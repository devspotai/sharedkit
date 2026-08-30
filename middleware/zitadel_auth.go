package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/devspotai/sharedkit/auth"
	"github.com/devspotai/sharedkit/auth/zitadel"
	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
)

// ZitadelAuth authenticates a request directly from its Zitadel access token and
// puts a models.UserContext on the gin context.
//
// It replaces a Traefik forwardAuth sidecar that did the same work out of
// process and handed the result downstream as an X-Internal-JWT header. In one
// process there is no hop to carry identity across, so no internal token is
// minted — auth.InternalJWT remains for genuine service-to-service calls.
//
// Ordering: this is an alternative to InternalJWTAuth, not a companion. A router
// uses one or the other.
type ZitadelAuth struct {
	validator   TokenValidator
	users       UserProvider
	cache       *cache.RedisCache
	cacheTTL    time.Duration
	publicPaths map[string]bool
	tracer      trace.Tracer
}

// TokenValidator verifies an access token and returns its claims.
// *zitadel.Validator implements it; the interface exists so a router can be
// exercised without a live JWKS endpoint.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (*zitadel.Claims, error)
}

// UserProvider resolves an IdP subject to a local user and reads that user's
// company roles.
//
// It is an interface because the user records may or may not live in the calling
// process. A service that owns them implements this against its own repository;
// one that does not implements it over HTTP. Either way this middleware does not
// know which, so the caller cannot accidentally take a network hop it did not
// intend.
type UserProvider interface {
	// ResolveUserID maps an IdP subject to the local user id, provisioning the
	// user if this is their first sign-in. created reports whether it did.
	ResolveUserID(ctx context.Context, idpSubject string) (userID string, created bool, err error)

	// CompanyRoles returns the user's verified roles per company.
	CompanyRoles(ctx context.Context, userID string) (map[string]auth.CompanyRole, error)
}

// ErrTokenRefreshRequired is returned on first sign-in, when the access token
// does not yet carry the app_uid metadata claim. Provisioning writes that claim
// back to Zitadel out of band, so the token in hand can never gain it — the
// client has to fetch a new one and retry.
var ErrTokenRefreshRequired = errors.New("idp token refresh required")

// TokenRefreshRequiredHeader tells the client the retry is worth making. The
// gateway set this too, but listed it in neither authResponseHeaders entry, so
// Traefik stripped it and the browser never saw it.
const TokenRefreshRequiredHeader = "X-Token-Refresh-Required"

type ZitadelAuthConfig struct {
	// Validator verifies the access token. Required.
	Validator TokenValidator
	// Users resolves the subject to a local user. Required.
	Users UserProvider
	// Cache holds company roles between requests. Optional: without it every
	// request reads roles through Users.
	Cache *cache.RedisCache
	// CacheTTL defaults to 5m, matching the warmer that also writes these keys.
	CacheTTL time.Duration
	// PublicPaths skip authentication entirely.
	PublicPaths []string
}

func NewZitadelAuth(cfg ZitadelAuthConfig) (*ZitadelAuth, error) {
	if cfg.Validator == nil {
		return nil, errors.New("middleware: ZitadelAuthConfig.Validator is required")
	}
	if cfg.Users == nil {
		return nil, errors.New("middleware: ZitadelAuthConfig.Users is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	public := make(map[string]bool, len(cfg.PublicPaths))
	for _, p := range cfg.PublicPaths {
		public[p] = true
	}

	return &ZitadelAuth{
		validator:   cfg.Validator,
		users:       cfg.Users,
		cache:       cfg.Cache,
		cacheTTL:    cfg.CacheTTL,
		publicPaths: public,
		tracer:      otel.Tracer("zitadel-auth"),
	}, nil
}

// Middleware authenticates every request except those on a public path.
func (z *ZitadelAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if z.isPublicPath(c) {
			c.Next()
			return
		}
		z.authenticate(c)
	}
}

// MiddlewareRequired authenticates every request, public paths included.
func (z *ZitadelAuth) MiddlewareRequired() gin.HandlerFunc {
	return func(c *gin.Context) { z.authenticate(c) }
}

// isPublicPath matches the route pattern first, then the literal path.
//
// The pattern is what a caller configures — "/api/v1/destinations/:destination/facts"
// — and it is what gin exposes as FullPath once a route matches. Comparing only
// the request path means every parameterised public route fails the check and is
// treated as authenticated, because "/api/v1/destinations/PT/facts" is not in the
// list and never will be. The literal comparison is kept for routes registered
// without a pattern.
func (z *ZitadelAuth) isPublicPath(c *gin.Context) bool {
	if len(z.publicPaths) == 0 {
		return false
	}
	if pattern := c.FullPath(); pattern != "" && z.publicPaths[pattern] {
		return true
	}
	return z.publicPaths[c.Request.URL.Path]
}

func (z *ZitadelAuth) authenticate(c *gin.Context) {
	ctx, span := z.tracer.Start(c.Request.Context(), "zitadel_auth.authenticate")
	defer span.End()

	token, err := ExtractBearer(c.GetHeader("Authorization"))
	if err != nil {
		z.abort(c, span, http.StatusUnauthorized, "unauthorized", err)
		return
	}

	claims, err := z.validator.Validate(ctx, token)
	if err != nil {
		// A Zitadel outage is ours, not the caller's. The gateway returned 401
		// for this too, which made an outage look like a bad password.
		status := http.StatusUnauthorized
		if errors.Is(err, zitadel.ErrKeysUnavailable) {
			status = http.StatusServiceUnavailable
		}
		z.abort(c, span, status, "unauthorized", err)
		return
	}

	userID := claims.UserID
	if userID == "" {
		// First sign-in: provision, then make the client come back with a token
		// that carries the metadata this one lacks.
		if _, _, err := z.users.ResolveUserID(ctx, claims.Subject); err != nil {
			z.abort(c, span, http.StatusServiceUnavailable, "could not provision user", err)
			return
		}
		span.SetAttributes(attribute.Bool("auth.first_login", true))
		c.Header(TokenRefreshRequiredHeader, "true")
		c.AbortWithStatusJSON(http.StatusUnauthorized, models.GetErrorResponse(
			"token_refresh_required",
			http.StatusUnauthorized,
			"Your account has been created. Please refresh your token and retry.",
		))
		return
	}

	companyRoles, err := z.companyRoles(ctx, userID, claims)
	if err != nil {
		z.abort(c, span, http.StatusServiceUnavailable, "could not load permissions", err)
		return
	}

	var companiesRoles *models.CompanyPermissionsForAuthUserMap
	if len(companyRoles) > 0 {
		permMap := make(models.CompanyPermissionsForAuthUserMap, len(companyRoles))
		for companyID, cr := range companyRoles {
			permMap[companyID] = cr.Roles
		}
		companiesRoles = &permMap
	}

	userCtx := &models.UserContext{
		UserID:         userID,
		HostID:         claims.HostID,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Roles:          claims.ProjectRoles,
		CompaniesRoles: companiesRoles,
		Subject:        claims.Subject,
	}

	span.SetAttributes(
		attribute.String("auth.user_id", userID),
		attribute.Int("auth.company_count", len(companyRoles)),
		attribute.Bool("auth.valid", true),
	)

	c.Set(models.UserContextKey, userCtx)
	c.Request = c.Request.WithContext(ctx)
	c.Next()
}

// companyRoles reads the cache, falling back to the provider and warming the
// cache on a miss.
func (z *ZitadelAuth) companyRoles(ctx context.Context, userID string, claims *zitadel.Claims) (map[string]auth.CompanyRole, error) {
	if z.cache != nil {
		var entry auth.RolesCacheEntry
		if err := z.cache.Get(ctx, auth.RolesCacheKey(userID), &entry); err == nil {
			return entry.CompanyRoles, nil
		}
	}

	roles, err := z.users.CompanyRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("company roles for %s: %w", userID, err)
	}

	if z.cache != nil {
		entry := auth.RolesCacheEntry{
			UserID:       userID,
			Email:        claims.Email,
			KeycloakID:   claims.Subject,
			CompanyRoles: roles,
			CachedAt:     time.Now().Unix(),
		}
		// A cache write failure must not fail the request.
		_ = z.cache.Set(ctx, auth.RolesCacheKey(userID), entry, z.cacheTTL)
	}

	return roles, nil
}

func (z *ZitadelAuth) abort(c *gin.Context, span trace.Span, status int, message string, err error) {
	span.SetAttributes(
		attribute.Bool("auth.valid", false),
		attribute.Int("auth.status", status),
		attribute.String("auth.error", err.Error()),
	)
	// The detail is deliberately not err.Error(): it would leak whether a token
	// failed on signature, issuer or audience.
	c.AbortWithStatusJSON(status, models.GetErrorResponse(message, status, ""))
}

// ExtractBearer pulls the token out of an Authorization header, rejecting
// obviously malformed values before any cryptography is attempted.
func ExtractBearer(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing authorization header")
	}
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return "", errors.New("authorization header is not a bearer token")
	}
	// A JWT is normally 100-4000 bytes; 8KB is a generous ceiling that stops a
	// large body being fed to the parser.
	if len(token) > 8192 {
		return "", errors.New("bearer token too large")
	}
	if strings.Count(token, ".") != 2 {
		return "", errors.New("bearer token is not a three-part JWT")
	}
	return token, nil
}
