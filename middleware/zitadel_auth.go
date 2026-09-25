package middleware

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/devspotai/sharedkit/authn"
	"github.com/devspotai/sharedkit/authn/zitadel"
	"github.com/devspotai/sharedkit/authz"
	"github.com/devspotai/sharedkit/client/cache"
)

// ZitadelAuth authenticates a Zitadel bearer token and then loads the user's
// company roles, in one middleware.
//
// Deprecated: it bundles two separate concerns. Mount them separately:
//
//	a, _ := zitadel.NewAuthenticator(validator, users)
//	router.Use(authn.Middleware(a, authn.Options{PublicPaths: public}))
//	router.Use(authz.LoadCompanyRoles(authz.CachedRoles(users, redisCache, 5*time.Minute)))
//
// It is kept, built from exactly those pieces, so existing routers keep working.
type ZitadelAuth struct {
	authenticator *zitadel.Authenticator
	roles         authz.CompanyRoleSource
	public        authn.PathMatcher
}

// TokenValidator verifies an access token and returns its claims.
//
// Deprecated: use zitadel.TokenValidator from authn/zitadel.
type TokenValidator = zitadel.TokenValidator

// UserProvider resolves an IdP subject to a local user and reads that user's
// company roles.
//
// Deprecated: the two halves are now separate — zitadel.UserResolver for
// authentication and authz.CompanyRoleSource for authorization.
type UserProvider interface {
	zitadel.UserResolver
	authz.CompanyRoleSource
}

// Deprecated: use the authn/zitadel equivalents.
var ErrTokenRefreshRequired = zitadel.ErrTokenRefreshRequired

// Deprecated: use zitadel.TokenRefreshRequiredHeader.
const TokenRefreshRequiredHeader = zitadel.TokenRefreshRequiredHeader

// ZitadelAuthConfig configures ZitadelAuth.
//
// Deprecated: see ZitadelAuth.
type ZitadelAuthConfig struct {
	// Validator verifies the access token. Required.
	Validator TokenValidator
	// Users resolves the subject to a local user and supplies company roles.
	// Required.
	Users UserProvider
	// Cache holds company roles between requests. Optional: without it every
	// request reads roles through Users.
	Cache *cache.RedisCache
	// CacheTTL defaults to 5m, matching the warmer that also writes these keys.
	CacheTTL time.Duration
	// PublicPaths skip authentication entirely.
	PublicPaths []string
}

// NewZitadelAuth builds a ZitadelAuth.
//
// Deprecated: see ZitadelAuth.
func NewZitadelAuth(cfg ZitadelAuthConfig) (*ZitadelAuth, error) {
	if cfg.Validator == nil {
		return nil, errors.New("middleware: ZitadelAuthConfig.Validator is required")
	}
	if cfg.Users == nil {
		return nil, errors.New("middleware: ZitadelAuthConfig.Users is required")
	}
	a, err := zitadel.NewAuthenticator(cfg.Validator, cfg.Users)
	if err != nil {
		return nil, err
	}
	var roles authz.CompanyRoleSource = cfg.Users
	if cfg.Cache != nil {
		roles = authz.CachedRoles(cfg.Users, cfg.Cache, cfg.CacheTTL)
	}
	return &ZitadelAuth{
		authenticator: a,
		roles:         roles,
		public:        authn.NewPathMatcher(cfg.PublicPaths),
	}, nil
}

// Middleware authenticates every request except those on a public path.
func (z *ZitadelAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if z.public.Match(c) {
			c.Next()
			return
		}
		z.handle(c)
	}
}

// MiddlewareRequired authenticates every request, public paths included.
func (z *ZitadelAuth) MiddlewareRequired() gin.HandlerFunc {
	return z.handle
}

func (z *ZitadelAuth) handle(c *gin.Context) {
	if !authn.Authenticate(c, z.authenticator) {
		return
	}
	if !authz.ApplyCompanyRoles(c, z.roles) {
		return
	}
	c.Next()
}
