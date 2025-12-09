package models

import (
	"net/http"
	"time"
)

// UserContext represents the authenticated user context
type UserContext struct {
	UserID        string
	HostID        string
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

func (u *UserContext) HasMemberRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (u *UserContext) HasAnyOfMemberRoles(companyID string, roles []string) bool {
	for _, c := range u.Roles {
		for _, role := range roles {
			if c == role {
				return true
			}
		}
	}
	return false
}

func (u *UserContext) HasCompanyRole(companyID, role string) bool {
	for _, c := range u.Companies {
		if c.ID == companyID && c.Role == role {
			return true
		}
	}
	return false
}

func (u *UserContext) IsCompanyVerified(companyID string) bool {
	for _, c := range u.Companies {
		if c.ID == companyID && c.Status == CompanyStatusVerified {
			return true
		}
	}
	return false
}

func (u *UserContext) HasAnyOfVerifiedCompanyRoles(companyID string, roles []string) bool {
	for _, c := range u.Companies {
		if c.ID == companyID && c.Status == CompanyStatusVerified {
			for _, role := range roles {
				if c.Role == role {
					return true
				}
			}
		}
	}
	return false
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
	ID            string `json:"id"`
	Role          string `json:"role"` // OWNER, MANAGER, STAFF
	CoverImageURL string `json:"cover_image_url,omitempty"`
	Status        string `json:"status"` // VERIFIED, PENDING, SUSPENDED
}

// ErrorResponse is a standard error response format
type ErrorResponse struct {
	Message    string `json:"message,omitempty"`
	Details    string `json:"details,omitempty"` // Optional field for additional error details
	Code       string `json:"code,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
}

func GetErrorResponse(message string, statusCode int, details string) ErrorResponse {
	errorResponse := ErrorResponse{
		Message:    message,
		Details:    details,
		StatusCode: statusCode,
	}

	switch statusCode {
	case http.StatusBadRequest:
		errorResponse.Code = "BAD_REQUEST"
	case http.StatusUnauthorized:
		errorResponse.Code = "UNAUTHORIZED"
	case http.StatusForbidden:
		errorResponse.Code = "FORBIDDEN"
	case http.StatusNotFound:
		errorResponse.Code = "NOT_FOUND"
	case http.StatusInternalServerError:
		errorResponse.Code = "INTERNAL_SERVER_ERROR"
	case http.StatusConflict:
		errorResponse.Code = "CONFLICT"
	default:
		errorResponse.Code = "UNKNOWN_ERROR"
	}

	return errorResponse
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
