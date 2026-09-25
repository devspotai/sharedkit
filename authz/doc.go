// Package authz decides what an authenticated caller may do. It never
// authenticates: it reads the *models.UserContext that an authn.Authenticator
// (or any middleware calling authn.SetPrincipal) placed on the request, and it
// works the same whichever identity provider produced it.
//
// The pieces, in mounting order:
//
//	LoadCompanyRoles          fill UserContext.CompaniesRoles from a
//	                          CompanyRoleSource (optionally CachedRoles)
//	RequireAuth, RequireRole, RequireAnyRole, RequireEmailVerified
//	                          global guards on identity and IdP roles
//	CompanyOPAEngine.AuthorizeCompanyAccess
//	                          tier 1: company-level policy (embedded Rego)
//	RequireCompanyRoles       per-route company role guard after tier 1
//	DomainOPAEngine.AuthorizeDomainResource
//	                          tier 2: the service's own resource-level Rego
//
// RequireCompanyAccess and RequireCompanyRole are standalone company guards
// for routes that do not use OPA.
package authz
