package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/devspotai/sharedkit/models"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// InternalJWTAuth middleware validates internal JWTs from the API gateway
type InternalJWTAuth struct {
	jwtSecret   []byte
	publicPaths map[string]bool
	tracer      trace.Tracer
}

// InternalJWTClaims represents the claims in the internal JWT from the gateway
type InternalJWTClaims struct {
	UserID              string                    `json:"user_id"`
	Email               string                    `json:"email"`
	KeycloakID          string                    `json:"keycloak_id"`
	CompanyRoles        map[string]CompanyRole    `json:"company_roles"`
	HasAnyCompanyAccess bool                      `json:"has_company_access"`
	ManagedCompanyIDs   []string                  `json:"managed_companies,omitempty"`
	jwt.RegisteredClaims
}

// CompanyRole represents a user's roles in a company
type CompanyRole struct {
	Roles                  []string `json:"roles"`
	HasGranularPermissions bool     `json:"has_granular_perms"`
}

// NewInternalJWTAuth creates a new internal JWT authentication middleware
func NewInternalJWTAuth(jwtSecret string, publicPaths []string) *InternalJWTAuth {
	if jwtSecret == "" {
		panic("internal JWT secret cannot be empty")
	}

	// Convert public paths slice to map for O(1) lookup
	publicPathsMap := make(map[string]bool)
	for _, path := range publicPaths {
		publicPathsMap[path] = true
	}

	return &InternalJWTAuth{
		jwtSecret:   []byte(jwtSecret),
		publicPaths: publicPathsMap,
		tracer:      otel.Tracer("internal-jwt-auth"),
	}
}

// Middleware returns the Gin middleware handler
func (m *InternalJWTAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.isPublicPath(c) {
			c.Next()
			return
		}

		if err := m.validateRequest(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// MiddlewareRequired always requires authentication (no public paths)
func (m *InternalJWTAuth) MiddlewareRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := m.validateRequest(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// MiddlewareOptional allows requests without authentication
// Sets user context if valid auth headers present, otherwise continues without
func (m *InternalJWTAuth) MiddlewareOptional() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to validate, but don't abort if validation fails
		_ = m.validateRequest(c)
		c.Next()
	}
}

// validateRequest validates the internal JWT and sets user context
func (m *InternalJWTAuth) validateRequest(c *gin.Context) error {
	ctx, span := m.tracer.Start(c.Request.Context(), "internal_jwt_auth.validate")
	defer span.End()

	// Get internal JWT from header
	tokenString := c.GetHeader("X-Internal-JWT")
	if tokenString == "" {
		err := fmt.Errorf("missing X-Internal-JWT header")
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("auth.valid", false))
		return err
	}

	// Parse and validate JWT
	claims, err := m.parseToken(tokenString)
	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("auth.valid", false))
		return fmt.Errorf("invalid token: %w", err)
	}

	span.SetAttributes(
		attribute.String("auth.user_id", claims.UserID),
		attribute.String("auth.email", claims.Email),
		attribute.Bool("auth.has_company_access", claims.HasAnyCompanyAccess),
	)

	// Convert CompanyRoles to CompanyPermissionsForAuthUserMap
	var companiesRoles *models.CompanyPermissionsForAuthUserMap
	if len(claims.CompanyRoles) > 0 {
		permMap := make(models.CompanyPermissionsForAuthUserMap)
		for companyID, cr := range claims.CompanyRoles {
			permMap[companyID] = cr.Roles
		}
		companiesRoles = &permMap
	}

	// Build UserContext
	userCtx := &models.UserContext{
		UserID:         claims.UserID,
		Email:          claims.Email,
		EmailVerified:  true, // Gateway only issues tokens for verified emails
		CompaniesRoles: companiesRoles,
		Subject:        claims.KeycloakID,
	}

	// Store in context
	c.Set(models.UserContextKey, userCtx)
	c.Request = c.Request.WithContext(ctx)

	span.SetAttributes(attribute.Bool("auth.valid", true))
	return nil
}

// parseToken parses and validates the internal JWT
func (m *InternalJWTAuth) parseToken(tokenString string) (*InternalJWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &InternalJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is invalid")
	}

	claims, ok := token.Claims.(*InternalJWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// isPublicPath checks if the current request path is public
func (m *InternalJWTAuth) isPublicPath(c *gin.Context) bool {
	if len(m.publicPaths) == 0 {
		return false
	}

	// Check full path (e.g., "/api/v1/health")
	fullPath := c.FullPath()
	if fullPath != "" && m.publicPaths[fullPath] {
		return true
	}

	// Check request path (for wildcard routes)
	requestPath := c.Request.URL.Path
	if m.publicPaths[requestPath] {
		return true
	}

	return false
}

// GetUserContext is a helper to retrieve user context from gin.Context
func GetUserContext(c *gin.Context) (*models.UserContext, bool) {
	return models.GetUserContext(c)
}

// MustGetUserContext retrieves user context or panics (use after RequireAuth)
func MustGetUserContext(c *gin.Context) *models.UserContext {
	return models.MustGetUserContext(c)
}
