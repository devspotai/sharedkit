package middleware

import (
	"github.com/devspotai/sharedkit/auth"
	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// RolesCacheConfig configures the RolesCacheMiddleware.
type RolesCacheConfig struct {
	Cache *cache.RedisCache
	// CacheKeyFunc builds the Redis key for a user's company roles.
	// Defaults to auth.RolesCacheKey, which is what writers use. Override only
	// if a service stores the entry somewhere else.
	CacheKeyFunc func(userID string) string
}

// RolesCacheMiddleware reads the authenticated user's company roles from Redis
// and populates UserContext.CompaniesRoles before OPA runs.
//
// Target middleware chain: JWT auth → RolesCacheMiddleware → OPA tier 1 → OPA tier 2
//
// On a cache miss it does not abort: CompaniesRoles stays nil, so
// HasCompanyAccess reports false and OPA denies. That is deliberate — an
// unreadable cache must not widen access.
//
// It reads auth.RolesCacheEntry from auth.RolesCacheKey. Both used to be wrong
// here, in ways that cancelled each other out into silence: the key was
// "user:<id>:company_roles" when every writer uses "user:<id>:company-roles",
// and the value was decoded into a bare map when the stored entry is an object
// carrying user_id, keycloak_id, company_roles and cached_at. Either alone
// lands on the miss branch, so the middleware ran on every authenticated
// request and enriched none of them.
//
// A service whose authentication already populates CompaniesRoles — middleware
// .ZitadelAuth does, from this same cache — does not need this as well.
func RolesCacheMiddleware(cfg RolesCacheConfig) gin.HandlerFunc {
	tracer := otel.Tracer("roles-cache")

	if cfg.CacheKeyFunc == nil {
		cfg.CacheKeyFunc = auth.RolesCacheKey
	}

	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), "roles_cache.enrich")
		defer span.End()

		userCtx, exists := models.GetUserContext(c)
		if !exists {
			c.Next()
			return
		}

		span.SetAttributes(attribute.String("user.id", userCtx.UserID))

		key := cfg.CacheKeyFunc(userCtx.UserID)
		span.SetAttributes(attribute.String("cache.key", key))

		var entry auth.RolesCacheEntry
		if err := cfg.Cache.Get(ctx, key, &entry); err != nil {
			span.SetAttributes(
				attribute.Bool("cache.hit", false),
				attribute.String("cache.miss_reason", err.Error()),
			)
			c.Next()
			return
		}

		roles := make(models.CompanyPermissionsForAuthUserMap, len(entry.CompanyRoles))
		for companyID, cr := range entry.CompanyRoles {
			roles[companyID] = cr.Roles
		}

		span.SetAttributes(
			attribute.Bool("cache.hit", true),
			attribute.Int("cache.companies_count", len(roles)),
		)
		userCtx.CompaniesRoles = &roles

		c.Next()
	}
}
