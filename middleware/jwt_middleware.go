package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Company represents a company association in the JWT
type Company struct {
	ID     string `json:"id"`
	Role   string `json:"role"`   // OWNER, MANAGER, STAFF
	Status string `json:"status"` // VERIFIED, PENDING, SUSPENDED
}

// KeycloakClaims represents the custom claims in Keycloak JWT
type KeycloakClaims struct {
	jwt.RegisteredClaims
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
	Scope           string     `json:"scope"`
	SessionID       string     `json:"sid"`
	EmailVerified   bool       `json:"email_verified"`
	Name            string     `json:"name"`
	PreferredUser   string     `json:"preferred_username"`
	GivenName       string     `json:"given_name"`
	FamilyName      string     `json:"family_name"`
	Email           string     `json:"email"`
	UserID          string     `json:"user_id"`   // Custom claim
	Companies       []Company  `json:"companies"` // Custom claim
	SessionState    string     `json:"session_state"`
	ACR             string     `json:"acr"`
	AZP             string     `json:"azp"`
	Type            string     `json:"typ"`
}

// UserContext represents the authenticated user context
type UserContext struct {
	UserID        string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Roles         []string
	Companies     []Company
	SessionID     string
	Subject       string // Keycloak user ID
}

// JWTMiddleware handles JWT token validation and parsing
type JWTMiddleware struct {
	keycloakURL    string
	realm          string
	publicKey      *rsa.PublicKey
	publicKeyMutex sync.RWMutex
	tracer         trace.Tracer
	lastKeyFetch   time.Time
	keyRefreshTTL  time.Duration
}

// JWKS represents JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(keycloakURL, realm string) *JWTMiddleware {
	middleware := &JWTMiddleware{
		keycloakURL:   keycloakURL,
		realm:         realm,
		tracer:        otel.Tracer("jwt-middleware"),
		keyRefreshTTL: 1 * time.Hour,
	}

	// Fetch public key on initialization
	if err := middleware.fetchPublicKey(); err != nil {
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
			if err := m.fetchPublicKey(); err != nil {
				fmt.Printf("Warning: Failed to refresh public key: %v\n", err)
			}
		}

		// Parse and validate token
		userCtx, err := m.parseToken(ctx, tokenString)
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

// parseToken parses and validates the JWT token
func (m *JWTMiddleware) parseToken(ctx context.Context, tokenString string) (*UserContext, error) {
	m.publicKeyMutex.RLock()
	publicKey := m.publicKey
	m.publicKeyMutex.RUnlock()

	if publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenString, &KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*KeycloakClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Verify token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Build user context
	userCtx := &UserContext{
		UserID:        claims.UserID,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Roles:         claims.RealmAccess.Roles,
		Companies:     claims.Companies,
		SessionID:     claims.SessionID,
		Subject:       claims.Subject,
	}

	return userCtx, nil
}

// fetchPublicKey fetches the public key from Keycloak
func (m *JWTMiddleware) fetchPublicKey() error {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", m.keycloakURL, m.realm)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return fmt.Errorf("no keys found in JWKS")
	}

	// Use the first RSA key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			publicKey, err := m.parseRSAPublicKey(key)
			if err != nil {
				continue
			}

			m.publicKeyMutex.Lock()
			m.publicKey = publicKey
			m.lastKeyFetch = time.Now()
			m.publicKeyMutex.Unlock()

			return nil
		}
	}

	return fmt.Errorf("no suitable RSA key found")
}

// parseRSAPublicKey parses RSA public key from JWK
func (m *JWTMiddleware) parseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return publicKey, nil
}

// GetUserContext extracts user context from Gin context
func GetUserContext(c *gin.Context) (*UserContext, error) {
	user, exists := c.Get("user")
	if !exists {
		return nil, fmt.Errorf("user context not found")
	}

	userCtx, ok := user.(*UserContext)
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
func GetUserCompanyRole(userCtx *UserContext, companyID string) (string, bool) {
	for _, company := range userCtx.Companies {
		if company.ID == companyID && company.Status == "VERIFIED" {
			return company.Role, true
		}
	}
	return "", false
}
