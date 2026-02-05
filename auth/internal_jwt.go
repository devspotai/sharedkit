package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// InternalJWTClaims represents the claims in the internal JWT
type InternalJWTClaims struct {
	UserID              string                 `json:"user_id"`
	Email               string                 `json:"email"`
	KeycloakID          string                 `json:"keycloak_id"`
	CompanyRoles        map[string]CompanyRole `json:"company_roles"`
	HasAnyCompanyAccess bool                   `json:"has_company_access"`
	ManagedCompanyIDs   []string               `json:"managed_companies,omitempty"`
	jwt.RegisteredClaims
}

// CompanyRole represents a user's roles in a company
type CompanyRole struct {
	Roles                  []string `json:"roles"`
	HasGranularPermissions bool     `json:"has_granular_perms"`
}

// InternalJWTConfig holds configuration for internal JWT operations
type InternalJWTConfig struct {
	Secret   string
	Expiry   time.Duration
	Issuer   string
	Audience []string
}

// DefaultInternalJWTConfig returns default configuration
func DefaultInternalJWTConfig(secret string) InternalJWTConfig {
	return InternalJWTConfig{
		Secret:   secret,
		Expiry:   15 * time.Minute,
		Issuer:   "traefik-auth-enricher",
		Audience: []string{"internal-services"},
	}
}

// InternalJWT provides methods to create and parse internal JWTs
type InternalJWT struct {
	secret   []byte
	expiry   time.Duration
	issuer   string
	audience []string
}

// NewInternalJWT creates a new InternalJWT helper
func NewInternalJWT(cfg InternalJWTConfig) *InternalJWT {
	if cfg.Secret == "" {
		panic("internal JWT secret cannot be empty")
	}
	if cfg.Expiry == 0 {
		cfg.Expiry = 15 * time.Minute
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "traefik-auth-enricher"
	}
	if len(cfg.Audience) == 0 {
		cfg.Audience = []string{"internal-services"}
	}

	return &InternalJWT{
		secret:   []byte(cfg.Secret),
		expiry:   cfg.Expiry,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
	}
}

// CreateTokenInput holds the input for creating an internal JWT
type CreateTokenInput struct {
	UserID       string
	Email        string
	KeycloakID   string
	CompanyRoles map[string]CompanyRole
}

// CreateToken creates a signed internal JWT
func (j *InternalJWT) CreateToken(input CreateTokenInput) (string, error) {
	now := time.Now()

	// Generate unique JTI for replay attack prevention
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}

	// Build managed company IDs list
	managedCompanyIDs := make([]string, 0, len(input.CompanyRoles))
	for companyID := range input.CompanyRoles {
		managedCompanyIDs = append(managedCompanyIDs, companyID)
	}

	claims := InternalJWTClaims{
		UserID:              input.UserID,
		Email:               input.Email,
		KeycloakID:          input.KeycloakID,
		CompanyRoles:        input.CompanyRoles,
		HasAnyCompanyAccess: len(input.CompanyRoles) > 0,
		ManagedCompanyIDs:   managedCompanyIDs,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti, // Unique token ID for replay prevention
			ExpiresAt: jwt.NewNumericDate(now.Add(j.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings(j.audience),
			Subject:   input.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(j.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

// generateJTI generates a unique JWT ID
func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ParseToken parses and validates an internal JWT
func (j *InternalJWT) ParseToken(tokenString string) (*InternalJWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &InternalJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
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

// ParseTokenUnverified parses an internal JWT without verifying the signature
// Use only for debugging or logging purposes
func (j *InternalJWT) ParseTokenUnverified(tokenString string) (*InternalJWTClaims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &InternalJWTClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*InternalJWTClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return claims, nil
}

// GetTokenExpiry returns the configured token expiry duration
func (j *InternalJWT) GetTokenExpiry() time.Duration {
	return j.expiry
}

// HasGranularRole checks if any role in the list requires granular permissions
func HasGranularRole(roles []string) bool {
	for _, role := range roles {
		if role == "ADMIN_SPECIFIC_STAYS" || role == "ADMIN_SPECIFIC_EXPERIENCES" {
			return true
		}
	}
	return false
}

// NewCompanyRole is a helper to create a CompanyRole
func NewCompanyRole(roles []string) CompanyRole {
	return CompanyRole{
		Roles:                  roles,
		HasGranularPermissions: HasGranularRole(roles),
	}
}
