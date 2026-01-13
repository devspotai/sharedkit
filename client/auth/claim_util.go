package auth

import (
	"fmt"

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

// GetCompanyRolesFromClaims finds the entry in the "company" claim with the given companyID
// and returns its "roles" as map[string]string.
//
// Expected claim shape:
//
// "company": [
//
//	{
//	  "companyId": "company-1",
//	  "roles": {
//	     "ADMIN_SPECIFIC_STAYS": "VERIFIED",
//	     "ADMIN_SPECIFIC_EXPERIENCES": "PENDING"
//	  }
//	},
//	...
//
// ]
func GetCompanyRolesFromClaims(claims jwt.MapClaims, companyID string) (map[string]string, bool, error) {
	if claims == nil {
		return nil, false, nil
	}

	rawCompaniesRoles, ok := claims["companies_roles"]
	if !ok || rawCompaniesRoles == nil {
		return nil, false, nil
	}

	companiesRolesSlice, ok := rawCompaniesRoles.([]any)
	if !ok {
		return nil, false, fmt.Errorf(`"companies_roles" claim has unexpected type %T (want []any)`, rawCompaniesRoles)
	}

	for i, rawCompanyRole := range companiesRolesSlice {
		obj, ok := rawCompanyRole.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf(`"company"[%d] has unexpected type %T (want map[string]any)`, i, rawCompanyRole)
		}

		// Accept "companyId" (as you specified) and also tolerate "companyID".
		id, err := readString(obj, "companyId", "companyID")
		if err != nil {
			return nil, false, fmt.Errorf(`"company"[%d]: %w`, i, err)
		}
		if id != companyID {
			continue
		}

		rolesRaw, exists := obj["roles"]
		if !exists || rolesRaw == nil {
			// company found but no roles present
			return map[string]string{}, true, nil
		}

		rolesAny, ok := rolesRaw.(map[string]any)
		if !ok {
			// Sometimes this could be map[string]string depending on how it was decoded upstream.
			if rolesStr, ok2 := rolesRaw.(map[string]string); ok2 {
				// Defensive copy so callers can’t mutate underlying state.
				out := make(map[string]string, len(rolesStr))
				for k, v := range rolesStr {
					out[k] = v
				}
				return out, true, nil
			}
			return nil, false, fmt.Errorf(`"company"[%d].roles has unexpected type %T (want map[string]any)`, i, rolesRaw)
		}

		out := make(map[string]string, len(rolesAny))
		for roleName, statusAny := range rolesAny {
			status, ok := statusAny.(string)
			if !ok {
				return nil, false, fmt.Errorf(`"company"[%d].roles[%q] has unexpected type %T (want string)`, i, roleName, statusAny)
			}
			out[roleName] = status
		}

		return out, true, nil
	}

	// No matching companyId in array
	return nil, false, nil
}

func readString(m map[string]any, keys ...string) (string, error) {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("%q has invalid type %T (want string)", k, v)
		}
		return s, nil
	}
	return "", fmt.Errorf("missing %q", keys[0])
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}
