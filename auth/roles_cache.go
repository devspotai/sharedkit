package auth

import "fmt"

// The company-roles cache is written by one service (the owner of the user
// records, on a background warm) and read by another (whatever authenticates a
// request). Both halves live here so the wire format has exactly one definition.
//
// Two key formats existed before this: the auth gateway and the user service
// wrote "user:<id>:company-roles" holding a RolesCacheEntry, while
// middleware.RolesCacheMiddleware read "user:<id>:company_roles" holding a bare
// role map. The hyphenated form wins because it is what production writers
// already emit; LegacyRolesCacheKey is kept so a reader can fall back during a
// rollout and is expected to be deleted once no writer emits it.

// RolesCacheKey is the canonical Redis key for a user's company roles.
func RolesCacheKey(userID string) string {
	return fmt.Sprintf("user:%s:company-roles", userID)
}

// RolesCacheEntry is the cached value. Only CompanyRoles is load-bearing; the
// rest is there to make a cache dump legible and is not read back for auth.
type RolesCacheEntry struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	KeycloakID   string                 `json:"keycloak_id"`
	CompanyRoles map[string]CompanyRole `json:"company_roles"`
	CachedAt     int64                  `json:"cached_at"`
}
