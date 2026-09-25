package authz

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// CompanyRole is a user's roles within one company.
type CompanyRole struct {
	Roles                  []string `json:"roles"`
	HasGranularPermissions bool     `json:"has_granular_perms"`
}

// NewCompanyRole builds a CompanyRole, deriving HasGranularPermissions.
func NewCompanyRole(roles []string) CompanyRole {
	return CompanyRole{
		Roles:                  roles,
		HasGranularPermissions: HasGranularRole(roles),
	}
}

// HasGranularRole reports whether any role needs a resource-level check.
func HasGranularRole(roles []string) bool {
	for _, role := range roles {
		if role == models.CompanyRoleAdminSpecificStay || role == models.CompanyRoleAdminSpecificExperience {
			return true
		}
	}
	return false
}

// CompanyRoleSource returns a user's roles per company, keyed by company ID.
//
// It is how a service tells authz where its company memberships live — its own
// repository, another service, a cache. Authentication does not supply them:
// an identity provider says who the caller is, and this says what they may do.
type CompanyRoleSource interface {
	CompanyRoles(ctx context.Context, userID string) (map[string]CompanyRole, error)
}

// CompanyRoleSourceFunc adapts a function to CompanyRoleSource.
type CompanyRoleSourceFunc func(ctx context.Context, userID string) (map[string]CompanyRole, error)

func (f CompanyRoleSourceFunc) CompanyRoles(ctx context.Context, userID string) (map[string]CompanyRole, error) {
	return f(ctx, userID)
}

// The company-roles cache is written by one service (the owner of the user
// records, on a background warm) and read by another (whatever authorizes a
// request). Both halves live here so the wire format has exactly one definition.

// RolesCacheKey is the canonical Redis key for a user's company roles.
func RolesCacheKey(userID string) string {
	return fmt.Sprintf("user:%s:company-roles", userID)
}

// RolesCacheEntry is the cached value. Only CompanyRoles is load-bearing; the
// rest is there to make a cache dump legible and is not read back for authz.
type RolesCacheEntry struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email,omitempty"`
	IDPUserID    string                 `json:"idp_user_id,omitempty"`
	CompanyRoles map[string]CompanyRole `json:"company_roles"`
	CachedAt     int64                  `json:"cached_at"`
}

// CachedRoles wraps source with a Redis read-through cache at RolesCacheKey.
//
// With a nil source it is cache-only: a miss yields no company roles rather
// than an error, so the user is denied company access (fail closed) instead of
// the request failing. That suits a service that relies entirely on another
// service warming the cache.
func CachedRoles(source CompanyRoleSource, c *cache.RedisCache, ttl time.Duration) CompanyRoleSource {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &cachedRoles{source: source, cache: c, ttl: ttl}
}

type cachedRoles struct {
	source CompanyRoleSource
	cache  *cache.RedisCache
	ttl    time.Duration
}

func (r *cachedRoles) CompanyRoles(ctx context.Context, userID string) (map[string]CompanyRole, error) {
	var entry RolesCacheEntry
	if err := r.cache.Get(ctx, RolesCacheKey(userID), &entry); err == nil {
		return entry.CompanyRoles, nil
	}
	if r.source == nil {
		return nil, nil
	}

	roles, err := r.source.CompanyRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	entry = RolesCacheEntry{UserID: userID, CompanyRoles: roles, CachedAt: time.Now().Unix()}
	if uc, ok := principalFromContext(ctx); ok {
		entry.Email, entry.IDPUserID = uc.Email, uc.Subject
	}
	// A cache write failure must not fail the request.
	_ = r.cache.Set(ctx, RolesCacheKey(userID), entry, r.ttl)
	return roles, nil
}

// LoadCompanyRoles is middleware that fills UserContext.CompaniesRoles from
// source. Mount it after authentication and before any company guard or OPA
// tier.
//
// Requests without a principal (public routes) pass through untouched. If the
// source fails, the request is answered 503: the caller's credentials are fine,
// but access cannot be decided.
func LoadCompanyRoles(source CompanyRoleSource) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !ApplyCompanyRoles(c, source) {
			return
		}
		c.Next()
	}
}

// ApplyCompanyRoles does LoadCompanyRoles' work without calling c.Next, for
// middleware that composes it with other steps. It returns false if it
// aborted the request.
func ApplyCompanyRoles(c *gin.Context, source CompanyRoleSource) bool {
	uc, ok := models.GetUserContext(c)
	if !ok || uc == nil {
		return true
	}

	ctx, span := otel.Tracer("authz").Start(c.Request.Context(), "authz.load_company_roles")
	defer span.End()
	span.SetAttributes(attribute.String("user.id", uc.UserID))

	roles, err := source.CompanyRoles(withPrincipal(ctx, uc), uc.UserID)
	if err != nil {
		span.RecordError(err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, models.GetErrorResponse(
			"could not load permissions", http.StatusServiceUnavailable, "",
		))
		return false
	}

	// Nil, not an empty map, when the user belongs to no company, so
	// "roles were never loaded" and "no companies" look the same to guards.
	uc.CompaniesRoles = nil
	if len(roles) > 0 {
		perms := make(models.CompanyPermissionsForAuthUserMap, len(roles))
		for companyID, cr := range roles {
			perms[companyID] = cr.Roles
		}
		uc.CompaniesRoles = &perms
	}
	span.SetAttributes(attribute.Int("authz.company_count", len(roles)))
	return true
}

type principalKey struct{}

// withPrincipal lets a CompanyRoleSource (the cache) see who it is loading for,
// so cache entries stay legible without widening the interface.
func withPrincipal(ctx context.Context, uc *models.UserContext) context.Context {
	return context.WithValue(ctx, principalKey{}, uc)
}

func principalFromContext(ctx context.Context) (*models.UserContext, bool) {
	uc, ok := ctx.Value(principalKey{}).(*models.UserContext)
	return uc, ok
}
