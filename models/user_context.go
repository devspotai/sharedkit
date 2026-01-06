package models

import (
	"github.com/gin-gonic/gin"
)

// ============================================================
// USER CONTEXT HELPERS
// ============================================================

// UserContextKey is the key used to store UserContext in gin.Context
const UserContextKey = "user_context"

// UserContext represents the authenticated user context
type UserContext struct {
	UserID         string
	HostID         string
	Email          string
	EmailVerified  bool
	Roles          []string
	CompaniesRoles []CompanyRole
	SessionID      string
	Subject        string // Keycloak user ID
}

func (u *UserContext) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (u *UserContext) HasAnyOfRoles(companyID string, roles ...string) bool {
	for _, required := range roles {
		if u.HasRole(required) {
			return true
		}
	}
	return false
}

// GetUserCompanyRole returns user's role for a specific company
func (u *UserContext) GetUserCompanyRole(companyID string) (string, bool) {
	for _, company := range u.CompaniesRoles {
		if company.ID == companyID && company.Status == CompanyStatusVerified {
			return company.Role, true
		}
	}
	return "", false
}

// HasCompanyAccess checks if user has access to a company with any role
func (u *UserContext) HasCompanyAccess(companyID string) bool {
	for _, company := range u.CompaniesRoles {
		if company.ID == companyID && company.Status == CompanyStatusVerified {
			return true
		}
	}
	return false
}

func (u *UserContext) HasCompanyRole(companyID, role string) bool {
	for _, c := range u.CompaniesRoles {
		if c.ID == companyID && c.Role == role && c.Status == CompanyStatusVerified {
			return true
		}
	}
	return false
}

func (u *UserContext) IsCompanyVerified(companyID string) bool {
	for _, c := range u.CompaniesRoles {
		if c.ID == companyID && c.Status == CompanyStatusVerified {
			return true
		}
	}
	return false
}

func (u *UserContext) HasAnyOfVerifiedCompanyRoles(companyID string, roles []string) bool {
	for _, c := range u.CompaniesRoles {
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

// GetUserContext retrieves user context from gin.Context
func GetUserContext(c *gin.Context) (*UserContext, bool) {
	value, exists := c.Get(UserContextKey)
	if !exists {
		return nil, false
	}

	userCtx, ok := value.(*UserContext)
	return userCtx, ok
}

// MustGetUserContext retrieves user context or panics (use after RequireAuth)
func MustGetUserContext(c *gin.Context) *UserContext {
	userCtx, exists := GetUserContext(c)
	if !exists {
		panic("user context not found - did you forget RequireAuth()?")
	}
	return userCtx
}

// GetUserCompanies returns all verified companies for the user
func (u *UserContext) GetUserCompanies() []CompanyRole {
	companies := make([]CompanyRole, 0)
	for _, company := range u.CompaniesRoles {
		if company.Status == CompanyStatusVerified {
			companies = append(companies, company)
		}
	}
	return companies
}

// GetCompanyRole returns user's role for a specific company
func (u *UserContext) GetCompanyRole(companyID string) (string, bool) {
	for _, company := range u.CompaniesRoles {
		if company.ID == companyID && company.Status == "VERIFIED" {
			return company.Role, true
		}
	}
	return "", false
}
