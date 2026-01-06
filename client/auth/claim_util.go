package auth

import (
	"github.com/devspotai/sharedkit/models"
	"github.com/golang-jwt/jwt/v5"
)

// ============================================================
// HELPER FUNCTIONS FOR JWT CLAIMS
// ============================================================

func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getBoolClaim(claims jwt.MapClaims, key string) bool {
	if val, ok := claims[key].(bool); ok {
		return val
	}
	return false
}

func extractRoles(claims jwt.MapClaims) []string {
	// Try realm_access.roles first (Keycloak standard)
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if rolesInterface, ok := realmAccess["roles"].([]interface{}); ok {
			roles := make([]string, 0, len(rolesInterface))
			for _, r := range rolesInterface {
				if role, ok := r.(string); ok {
					roles = append(roles, role)
				}
			}
			return roles
		}
	}

	// Fallback to direct roles claim
	if rolesInterface, ok := claims["roles"].([]interface{}); ok {
		roles := make([]string, 0, len(rolesInterface))
		for _, r := range rolesInterface {
			if role, ok := r.(string); ok {
				roles = append(roles, role)
			}
		}
		return roles
	}

	return []string{}
}

func extractCompanies(claims jwt.MapClaims) []models.CompanyRole {
	if companiesInterface, ok := claims["companies"].([]interface{}); ok {
		companies := make([]models.CompanyRole, 0, len(companiesInterface))
		for _, c := range companiesInterface {
			if companyMap, ok := c.(map[string]interface{}); ok {
				company := models.CompanyRole{
					ID:     getStringFromMap(companyMap, "id"),
					Role:   getStringFromMap(companyMap, "role"),
					Status: getStringFromMap(companyMap, "status"),
				}
				if company.ID != "" {
					companies = append(companies, company)
				}
			}
		}
		return companies
	}

	return []models.CompanyRole{}
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}
