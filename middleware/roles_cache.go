package middleware

import (
	"fmt"

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
	// Default: "user:<userID>:company_roles"
	CacheKeyFunc func(userID string) string
}

// RolesCacheMiddleware reads the authenticated user's company-role map from
// Redis and populates UserContext.CompaniesRoles before OPA runs.
//
// Target middleware chain: JWT auth → RolesCacheMiddleware → OPA tier 1 → OPA tier 2
//
// On cache miss the middleware does NOT abort — CompaniesRoles stays nil so
// HasCompanyAccess() returns false and OPA returns 403 (fail closed).
func RolesCacheMiddleware(cfg RolesCacheConfig) gin.HandlerFunc {
	tracer := otel.Tracer("roles-cache")

	if cfg.CacheKeyFunc == nil {
		cfg.CacheKeyFunc = func(userID string) string {
			return fmt.Sprintf("user:%s:company_roles", userID)
		}
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

		var roles models.CompanyPermissionsForAuthUserMap
		if err := cfg.Cache.Get(ctx, key, &roles); err != nil {
			span.SetAttributes(attribute.Bool("cache.hit", false))
			span.SetAttributes(attribute.String("cache.miss_reason", err.Error()))
			c.Next()
			return
		}

		span.SetAttributes(
			attribute.Bool("cache.hit", true),
			attribute.Int("cache.companies_count", len(roles)),
		)
		userCtx.CompaniesRoles = &roles

		c.Next()
	}
}
