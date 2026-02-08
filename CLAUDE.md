# CLAUDE.md - SharedKit

## What is this?
Go shared library (`github.com/devspotai/sharedkit`) consumed by all devspotai microservices. Provides middleware, auth, caching, config, observability, and utility packages.

## Build & Test

```bash
go build ./...          # compile all packages
go test -race -cover ./...  # tests with race detector + coverage
go vet ./...            # static analysis
make test               # same as go test with coverage profile
make lint               # golangci-lint (if installed)
make tidy               # go mod tidy
```

## Project Structure

```
auth/           # Internal JWT, JTI tracking, request signing
client/auth/    # Keycloak auth client (token parsing, caching)
client/cache/   # Redis cache wrapper (Get/Set/Delete with OTel tracing)
config/         # Shared config structs (Redis, etc.)
events/         # Event definitions
middleware/     # Gin middleware (JWT, OPA, CORS, rate limit, roles cache)
models/         # Shared types (UserContext, responses, Keycloak models)
observability/  # OpenTelemetry tracer setup
ratelimit/      # Rate limiting
util/           # Array, JSONB, complex type helpers
```

## Key Conventions

- **Framework**: Gin for HTTP, OpenTelemetry for tracing (not zap/logrus)
- **Go version**: 1.25.3
- **OPA**: v1.13.1 with `github.com/open-policy-agent/opa/v1/rego` import path; Rego files use `import rego.v1`
- **Middleware pattern**: Return `gin.HandlerFunc`, start OTel span, use `models.GetUserContext(c)` for user info
- **Error responses**: Use `models.GetErrorResponse(message, statusCode, detail)`
- **User context**: Stored in `gin.Context` via `models.UserContextKey` ("user_context"); `GetUserContext()` returns `*UserContext`
- **No `go:embed` for policies**: Rego is a string constant (`companyAuthzPolicy`) because `go:embed` with paths outside the module root won't work for library consumers

## Authorization Architecture (Two-Tier OPA)

**Middleware chain**: JWT auth -> RolesCacheMiddleware -> OPA tier 1 -> OPA tier 2

### Tier 1 - Company-user level (`middleware/opa_embedded.go`)
- `CompanyOPAEngine` with embedded Rego policy compiled into binary
- `AuthorizeCompanyAccess(domainCfg)` middleware evaluates company roles
- Domain-agnostic: roles passed via `CompanyAuthzConfig` (FullAccessRoles, GranularRoles)
- Sets context keys: `opa_company_allowed`, `opa_requires_domain_check`, `opa_company_roles`
- `RequireCompanyRoles(allowed ...string)` adds per-endpoint role filtering after tier 1

### Tier 2 - Domain resource level (`middleware/opa_sidecar.go`)
- `OPAMiddleware` with `AuthorizeDomainResource()` queries external OPA sidecar
- Skips sidecar call if `requires_domain_check` is false

### Roles Cache (`middleware/roles_cache.go`)
- `RolesCacheMiddleware` reads `CompaniesRoles` from Redis before OPA runs
- Cache key default: `user:<userID>:company_roles`
- Cache miss = fail closed (CompaniesRoles stays nil, OPA denies)

## Company Roles
OWNER, MANAGER, ADMIN_ALL_STAYS, ADMIN_ALL_EXPERIENCES, ADMIN_SPECIFIC_STAYS, ADMIN_SPECIFIC_EXPERIENCES, STAFF

`CompaniesRoles` type is `*CompanyPermissionsForAuthUserMap` which is `map[string][]string` (companyID -> role names).

## Releasing

```bash
make release-patch   # runs tests + tidy, then tags vX.Y.(Z+1) and pushes
make release-minor   # vX.(Y+1).0
make release-major   # v(X+1).0.0
```
