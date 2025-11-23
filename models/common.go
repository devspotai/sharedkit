package models

import "time"

// UserContext represents authenticated user information
// This is extracted from JWT and used across all services
type UserContext struct {
	UserID        string
	Email         string
	EmailVerified bool
	Name          string
	Roles         []string
	Companies     []CompanyContext
	SessionID     string
}

// CompanyContext represents a user's association with a company
type CompanyContext struct {
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
	Limit   int    `form:"limit" json:"limit"`
	Offset  int    `form:"offset" json:"offset"`
	OrderBy string `form:"order_by" json:"order_by"`
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
	DefaultLimit      = 20
	MaxLimit          = 100
	DefaultOrderBy    = "created_at"
	DefaultOrderDir   = "DESC"
)
