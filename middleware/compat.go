package middleware

// Deprecated aliases. Authorization moved to package authz and the
// authentication contract to package authn; these keep existing imports
// compiling. New code should import authz and authn directly.

import (
	"github.com/devspotai/sharedkit/authn"
	"github.com/devspotai/sharedkit/authz"
	"github.com/devspotai/sharedkit/models"
)

// Context keys set by company-level authorization.
//
// Deprecated: use the authz constants.
const (
	OPACompanyAllowedKey      = authz.OPACompanyAllowedKey
	OPARequiresDomainCheckKey = authz.OPARequiresDomainCheckKey
	OPACompanyRolesKey        = authz.OPACompanyRolesKey
)

// Deprecated: use the authz types.
type (
	CompanyAuthorizer       = authz.CompanyAuthorizer
	CompanyAuthzConfig      = authz.CompanyAuthzConfig
	CompanyAuthzResult      = authz.CompanyAuthzResult
	CompanyOPAEngine        = authz.CompanyOPAEngine
	CompanyOPASidecar       = authz.CompanyOPASidecar
	CompanyOPASidecarConfig = authz.CompanyOPASidecarConfig
	DomainAuthorizer        = authz.DomainAuthorizer
	DomainOPAConfig         = authz.DomainOPAConfig
	DomainOPAEngine         = authz.DomainOPAEngine
	DomainOPASidecar        = authz.DomainOPASidecar
	DomainOPASidecarConfig  = authz.DomainOPASidecarConfig
	OPADecision             = authz.OPADecision
	OPAResult               = authz.OPAResult
)

// Deprecated: use the authz functions.
var (
	NewCompanyOPAEngine           = authz.NewCompanyOPAEngine
	NewCompanyOPAEngineWithPolicy = authz.NewCompanyOPAEngineWithPolicy
	NewCompanyOPASidecar          = authz.NewCompanyOPASidecar
	NewDomainOPAEngine            = authz.NewDomainOPAEngine
	NewDomainOPASidecar           = authz.NewDomainOPASidecar
	StaysDomainConfig             = authz.StaysDomainConfig
	ExperiencesDomainConfig       = authz.ExperiencesDomainConfig
	RequireAuth                   = authz.RequireAuth
	RequireRole                   = authz.RequireRole
	RequireAnyRole                = authz.RequireAnyRole
	RequireEmailVerified          = authz.RequireEmailVerified
	RequireCompanyAccess          = authz.RequireCompanyAccess
	RequireCompanyRole            = authz.RequireCompanyRole
	RequireCompanyRoles           = authz.RequireCompanyRoles
)

// ExtractBearer is kept for callers that parse Authorization headers.
//
// Deprecated: use authn.ExtractBearer.
var ExtractBearer = authn.ExtractBearer

// Deprecated: use models.GetUserContext and models.MustGetUserContext.
var (
	GetUserContext     = models.GetUserContext
	MustGetUserContext = models.MustGetUserContext
)
