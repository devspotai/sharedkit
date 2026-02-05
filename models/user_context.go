package models

import (
	"slices"

	"github.com/gin-gonic/gin"
)

// ============================================================
// USER CONTEXT HELPERS
// ============================================================

// UserContextKey is the key used to store UserContext in gin.Context
const UserContextKey = "user_context"

type CompanyPermissionsForAuthUserMap map[string][]string

// UserContext represents the authenticated user context
type UserContext struct {
	UserID         string
	HostID         string
	Email          string
	EmailVerified  bool
	Roles          []string                          // REGISTERED_GUEST, REGISTERED_HOST, SYSTEM_ADMIN
	CompaniesRoles *CompanyPermissionsForAuthUserMap `json:"companies_roles,omitempty"`
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

func (u *UserContext) HasAnyOfRoles(roles ...string) bool {
	for _, required := range roles {
		if u.HasRole(required) {
			return true
		}
	}
	return false
}

// GetUserCompanyRoles returns user's roles for a specific company
func (u *UserContext) GetUserCompanyRoles(companyID string) ([]string, bool) {
	if u.CompaniesRoles != nil {
		if roles, exists := (*u.CompaniesRoles)[companyID]; exists {
			return roles, true
		}
	}
	return nil, false
}

// HasCompanyAccess checks if user has access to a company with any role
func (u *UserContext) HasCompanyAccess(companyID string) bool {
	if u.CompaniesRoles != nil {
		if _, exists := (*u.CompaniesRoles)[companyID]; exists {
			return true
		}
	}
	return false
}

func (u *UserContext) HasAnyOfCompanyRoles(companyID string, roles ...string) bool {
	var companyHasAnyOfRoles bool = false
	if u.CompaniesRoles != nil {
		if _, exists := (*u.CompaniesRoles)[companyID]; exists {
			for _, role := range roles {
				companyHasAnyOfRoles = slices.Contains((*u.CompaniesRoles)[companyID], role)
				if companyHasAnyOfRoles {
					return true
				}
			}
		}
	}
	return companyHasAnyOfRoles
}

// GetUserCompanies returns all verified companies for the user
func (u *UserContext) GetUserCompanies() []string {
	companies := make([]string, 0)
	// copy companyroles
	if u.CompaniesRoles != nil {
		for companyID := range *u.CompaniesRoles {
			companies = append(companies, companyID)
		}
	}
	return companies
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
