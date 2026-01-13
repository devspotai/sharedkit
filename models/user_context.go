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
	CompaniesRoles *[]CompanyRoles `json:"companies_roles,omitempty"`
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

// GetUserCompanyRoles returns user's roles for a specific company
func (u *UserContext) GetUserCompanyRoles(companyID string) (map[string]string, bool) {
	roles := make(map[string]string)
	if u.CompaniesRoles != nil {
		for _, company := range *u.CompaniesRoles {
			if company.CompanyID == companyID {
				for key, val := range company.Roles {
					if val == CompanyStatusVerified {
						roles[key] = val
					}
				}
			}
		}
	}
	return roles, len(roles) > 0
}

// HasCompanyAccess checks if user has access to a company with any role
func (u *UserContext) HasCompanyAccess(companyID string) bool {
	if u.CompaniesRoles != nil {
		for _, company := range *u.CompaniesRoles {
			if company.CompanyID == companyID {
				return true
			}
		}
	}
	return false
}

func (u *UserContext) HasCompanyRoleWithSpecificStatus(companyID, role, status string) bool {
	if u.CompaniesRoles != nil {
		for _, c := range *u.CompaniesRoles {
			if c.CompanyID == companyID {
				val, ok := c.Roles[role]
				if ok && val == status {
					return true
				}
			}
		}
	}
	return false
}

func (u *UserContext) HasAnyOfVerifiedCompanyRoles(companyID string, roles ...string) bool {
	if u.CompaniesRoles != nil {
		for _, c := range *u.CompaniesRoles {
			if c.CompanyID == companyID {
				for _, role := range roles {
					val, ok := c.Roles[role]
					if ok && val == CompanyStatusVerified {
						return true
					}
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
func (u *UserContext) GetUserCompanies() []CompanyRoles {
	companies := make([]CompanyRoles, 0)
	// copy companyroles
	if u.CompaniesRoles != nil {
		companies = append(companies, *u.CompaniesRoles...)
	}
	return companies
}

func (u *UserContext) GetCompanyRoles(companyID string) (map[string]string, bool) {
	if u.CompaniesRoles == nil {
		return nil, false
	}

	for _, company := range *u.CompaniesRoles {
		if company.CompanyID == companyID {
			roles := make(map[string]string, len(company.Roles))
			for k, v := range company.Roles {
				roles[k] = v
			}
			return roles, true
		}
	}

	return nil, false
}
