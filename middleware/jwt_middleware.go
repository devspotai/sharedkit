package middleware

import (
	"fmt"

	"net/http"
	"strings"

	"github.com/devspotai/sharedkit/client/auth"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// JWTMiddleware handles JWT token validation and parsing
type JWTMiddleware struct {
	authClient *auth.CachedAuthClient
	tracer     trace.Tracer
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(authClient *auth.CachedAuthClient) *JWTMiddleware {
	middleware := &JWTMiddleware{
		authClient: authClient,
		tracer:     otel.Tracer("jwt-middleware"),
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
			//No auth header - allow request to proceed without user context
			//Protected endpoints will check for user context
			c.Next()
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			span.RecordError(fmt.Errorf("invalid authorization header format"))
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format - must be 'Bearer <token>'",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Parse and validate token
		userCtx, tokenValid, err := m.authClient.ParseToken(ctx, tokenString)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token", "details": err.Error()})
			c.Abort()
			return
		}
		if !tokenValid {
			span.RecordError(fmt.Errorf("invalid token"))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Add user context to Gin context
		c.Set("user", userCtx)
		c.Set("user_id", userCtx.UserID)
		c.Set("host_id", userCtx.HostID)
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
