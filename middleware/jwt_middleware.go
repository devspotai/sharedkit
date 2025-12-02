package middleware

import (
	"fmt"

	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// JWTMiddleware handles JWT token validation and parsing
type JWTMiddleware struct {
	cachedClient  *cache.CachedAuthClient
	realm         string
	tracer        trace.Tracer
	keyRefreshTTL time.Duration
	publicKey     *rsa.PublicKey
	lastKeyFetch  time.Time
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(cachedClient *cache.CachedAuthClient, realm string) *JWTMiddleware {
	middleware := &JWTMiddleware{
		cachedClient:  cachedClient,
		realm:         realm,
		tracer:        otel.Tracer("jwt-middleware"),
		keyRefreshTTL: 1 * time.Hour,
	}

	// Fetch public key on initialization
	publicKey, err := cachedClient.GetPublicKey("test-kid")
	if err == nil {
		middleware.publicKey = publicKey.(*rsa.PublicKey)
		middleware.lastKeyFetch = time.Now()
	}

	if err != nil {
		// Log error but don't fail - will retry on first request
		fmt.Printf("Warning: Failed to fetch public key on init: %v\n", err)
	}

	return middleware
}

// Middleware returns the Gin middleware handler
func (m *JWTMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := m.tracer.Start(c.Request.Context(), "jwt.validate")
		defer span.End()

		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			span.RecordError(fmt.Errorf("missing authorization header"))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			c.Abort()
			return
		}

		// Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			span.RecordError(fmt.Errorf("invalid authorization header format"))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Refresh public key if needed
		if time.Since(m.lastKeyFetch) > m.keyRefreshTTL {
			publicKey, err := m.cachedClient.GetPublicKey("test-kid")
			if err == nil {
				m.publicKey = publicKey.(*rsa.PublicKey)
				m.lastKeyFetch = time.Now()
			} else {
				fmt.Printf("Warning: Failed to refresh public key: %v\n", err)
			}
		}

		// Parse and validate token
		userCtx, err := m.cachedClient.KeycloakClient.ParseToken(ctx, tokenString)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "details": err.Error()})
			c.Abort()
			return
		}

		// Add user context to Gin context
		c.Set("user", userCtx)
		c.Set("user_id", userCtx.UserID)
		c.Set("email", userCtx.Email)
		c.Set("roles", userCtx.Roles)
		c.Set("companies", userCtx.Companies)

		// Add user info to trace
		span.SetAttributes(
			attribute.String("user.id", userCtx.UserID),
			attribute.String("user.email", userCtx.Email),
			attribute.Bool("user.email_verified", userCtx.EmailVerified),
			attribute.StringSlice("user.roles", userCtx.Roles),
		)

		c.Next()
	}
}

// GetUserContext extracts user context from Gin context
func GetUserContext(c *gin.Context) (*models.UserContext, error) {
	user, exists := c.Get("user")
	if !exists {
		return nil, fmt.Errorf("user context not found")
	}

	userCtx, ok := user.(*models.UserContext)
	if !ok {
		return nil, fmt.Errorf("invalid user context type")
	}

	return userCtx, nil
}

// RequireRole middleware ensures user has at least one of the required roles
func RequireRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, err := GetUserContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range userCtx.Roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireEmailVerified ensures the user's email is verified
func RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, err := GetUserContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		if !userCtx.EmailVerified {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "email not verified",
				"message": "Please verify your email address to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// HasCompanyAccess checks if user has access to a specific company
func HasCompanyAccess(companyID string, requiredRoles ...string) bool {
	// This will be used in service layer, not as middleware
	return true // Implementation depends on business logic
}

// GetUserCompanyRole returns the user's role for a specific company
func GetUserCompanyRole(userCtx *models.UserContext, companyID string) (string, bool) {
	for _, company := range userCtx.Companies {
		if company.ID == companyID && company.Status == "VERIFIED" {
			return company.Role, true
		}
	}
	return "", false
}
