package models

import "time"

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

// Company represents a company association in the JWT
type Company struct {
	ID     string `json:"id"`
	Role   string `json:"role"`   // OWNER, MANAGER, STAFF
	Status string `json:"status"` // VERIFIED, PENDING, SUSPENDED
}

// ErrorResponse is a standard error response format
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Limit    int    `form:"limit" json:"limit"`
	Offset   int    `form:"offset" json:"offset"`
	OrderBy  string `form:"order_by" json:"order_by"`
	OrderDir string `form:"order_dir" json:"order_dir"`
}

// PaginationResponse represents a paginated response
type PaginationResponse struct {
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version,omitempty"`
}

// Constants for common values
const (
	// Roles
	RoleUser           = "USER"
	RoleHost           = "HOST"
	RoleAdmin          = "ADMIN"
	RoleProductCreator = "PRODUCT_CREATOR"

	// Company Roles
	CompanyRoleOwner   = "OWNER"
	CompanyRoleManager = "MANAGER"
	CompanyRoleStaff   = "STAFF"

	// Company Status
	CompanyStatusVerified  = "VERIFIED"
	CompanyStatusPending   = "PENDING"
	CompanyStatusSuspended = "SUSPENDED"

	// Pagination
	DefaultLimit    = 20
	MaxLimit        = 100
	DefaultOrderBy  = "created_at"
	DefaultOrderDir = "DESC"
)
