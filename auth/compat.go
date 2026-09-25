// Package auth is deprecated. Company roles and the roles cache moved to
// package authz; these aliases keep existing imports compiling.
package auth

import "github.com/devspotai/sharedkit/authz"

// Deprecated: use the authz types.
type (
	CompanyRole     = authz.CompanyRole
	RolesCacheEntry = authz.RolesCacheEntry
)

// Deprecated: use the authz functions.
var (
	NewCompanyRole  = authz.NewCompanyRole
	HasGranularRole = authz.HasGranularRole
	RolesCacheKey   = authz.RolesCacheKey
)
