# sharedkit — Developer Guide

## Overview

Private shared library (`github.com/devspotai/sharedkit`) consumed by all devspotai Go microservices. Provides Gin middleware (JWT auth, OPA authorization, rate limiting, CORS, roles cache), Redis caching, Keycloak integration, event pub/sub, observability, and utility packages.

## Module

```
Module: github.com/devspotai/sharedkit
Go version: 1.25.3
```

## Key Dependencies

| Package | Version |
|---------|---------|
| github.com/gin-gonic/gin | v1.11.0 |
| github.com/golang-jwt/jwt/v5 | v5.3.0 |
| github.com/open-policy-agent/opa | v1.13.1 |
| github.com/redis/go-redis/v9 | v9.17.1 |
| go.opentelemetry.io/otel | v1.39.0 |
| github.com/prometheus/client_golang | v1.23.2 |

**OPA import path**: `github.com/open-policy-agent/opa/v1/rego` — Rego files must use `import rego.v1`.

## Directory Structure

```
auth/
  internal_jwt.go           # InternalJWT, InternalJWTClaims, CompanyRole
  jti_tracker.go            # JTITracker — Redis-backed replay prevention
  request_signer.go         # RequestSigner — HMAC-SHA256 service-to-service auth
  request_signer_middleware.go # SignatureVerificationMiddleware (Gin)
client/
  auth/
    keycloak.go             # KeycloakClient — JWKS fetch, admin API
    cached_auth.go          # CachedAuthClient — keycloak + Redis caching
    claim_util.go           # GetCompanyRolesFromClaims helper
  cache/
    redis_cache.go          # NewRedisClientFromConfig, NewRedisCacheFromConfig, RedisCache
config/
  config.go                 # LoadRedisConfig, GetEnv, GetEnvAsInt, GetEnvAsBool
events/
  events.go                 # Event types, RedisEventPublisher, RedisEventSubscriber
middleware/
  internal_auth_middleware.go # InternalJWTAuth — validates X-Internal-JWT header
  middleware_auth_helper.go   # RequireAuth, RequireRole, RequireAnyRole, etc.
  opa_embedded.go             # CompanyOPAEngine, AuthorizeCompanyAccess
  roles_cache.go              # RolesCacheMiddleware
  cors.go                     # CORS(), CORSWithConfig()
models/
  user_context.go           # UserContext, CompanyPermissionsForAuthUserMap
  common.go                 # Role constants, GetErrorResponse, PaginationParams
  keycloak.go               # KeycloakClaims, CompanyRoles
  response.go               # (error/success response wrappers)
observability/
  observability.go          # InitObservability, TracingMiddleware, MetricsMiddleware
ratelimit/
  ratelimit.go              # Limiter, Allow, AllowN, FixedWindowAllow, TokenBucketAllow
  middleware.go             # PerIPMiddleware, PerUserMiddleware, PerEndpointMiddleware, Middleware
util/
  array_util.go             # Difference[T], Contains[T]
  jsonb_util.go             # JSONB type, ScanJSONSlice, ToRawMessage, FromRawMessage
  complex_types.go          # StringArray (PostgreSQL TEXT[] scanner/valuer)
```

## Build & Test

```bash
go build ./...
go test -race -cover ./...
make test       # same with coverage profile
make lint       # golangci-lint
make tidy       # go mod tidy

make release-patch  # tags vX.Y.(Z+1), pushes
make release-minor  # vX.(Y+1).0
make release-major  # v(X+1).0.0
```

## Config (`config/config.go`)

```go
cfg := config.LoadRedisConfig()  // reads env vars into *RedisConfig

// Env vars read:
// REDIS_URL (default "localhost:6379"), REDIS_PASSWORD, REDIS_DB,
// REDIS_MAX_RETRIES, REDIS_POOL_SIZE, REDIS_MIN_IDLE_CONNS,
// REDIS_TLS_ENABLED, REDIS_TLS_CA_CERT, REDIS_TLS_CLIENT_CERT, REDIS_TLS_CLIENT_KEY

config.GetEnv(key, defaultValue string) string
config.GetEnvAsInt(key string, defaultValue int) int
config.GetEnvAsBool(key string, defaultValue bool) bool  // EXISTS in sharedkit/config
```

## Redis Cache (`client/cache/redis_cache.go`)

```go
// Raw redis.Client — use for rate limiters, JTI trackers
client := cache.NewRedisClientFromConfig(cfg *config.RedisConfig) *redis.Client

// Structured wrapper — use for JSON marshal/unmarshal
rc := cache.NewRedisCacheFromConfig(cfg *config.RedisConfig) *cache.RedisCache

// RedisCache methods
rc.Set(ctx, key string, value any, expiration time.Duration) error
rc.SetNX(ctx, key string, value []byte, expiration) (bool, error)
rc.Get(ctx, key string, dest any) error           // JSON unmarshal into dest
rc.GetRaw(ctx, key string) ([]byte, error)        // no unmarshal
rc.Delete(ctx, key string) error
rc.DeletePattern(ctx, pattern string) error
rc.DeleteMany(ctx, keys ...string) error
rc.SetMany(ctx, ops []cache.SetOp) error
rc.HealthCheck(ctx) error
rc.WithPipeline(ctx, fn func(pipe redis.Pipeliner) error) error
rc.Close() error
```

Hot-reload for Redis TLS client cert: 5-minute cache via `GetClientCertificate` callback — TLS cert changes are picked up without restart.

## Internal JWT (`auth/internal_jwt.go`)

Issued by `auth-enricher` (Traefik sidecar), validated by backend services via `InternalJWTAuthMiddleware`. Backend services validate `X-Internal-JWT` header, NOT `Authorization`.

```go
type InternalJWTClaims struct {
    UserID              string                 `json:"user_id"`
    Email               string                 `json:"email"`
    KeycloakID          string                 `json:"keycloak_id"`
    CompanyRoles        map[string]CompanyRole `json:"company_roles"`
    HasAnyCompanyAccess bool                   `json:"has_company_access"`
    ManagedCompanyIDs   []string               `json:"managed_companies,omitempty"`
    jwt.RegisteredClaims  // includes JTI (unique, for replay prevention)
}

type CompanyRole struct {
    Roles                  []string `json:"roles"`
    HasGranularPermissions bool     `json:"has_granular_perms"`
}

cfg := auth.DefaultInternalJWTConfig(secret string) // Expiry=15min, Issuer="traefik-auth-enricher"
j := auth.NewInternalJWT(cfg)
token, err := j.CreateToken(auth.CreateTokenInput{UserID, Email, KeycloakID, CompanyRoles})
claims, err := j.ParseToken(tokenString string)
```

### JTI Tracker (`auth/jti_tracker.go`)

Redis-backed replay-attack prevention via SETNX:

```go
tracker := auth.NewJTITracker(client redis.Cmdable, auth.JTITrackerConfig{
    KeyPrefix:  "jti:",      // default
    DefaultTTL: 15*time.Minute, // should match JWT expiry
})

err := tracker.CheckAndMark(ctx, jti string, expiry time.Time) error // atomic SETNX
// returns auth.ErrTokenReplay if JTI already seen

tracker.Revoke(ctx, jti, extendedTTL)         // for logout
tracker.RevokeAllForUser(ctx, userID, ttl)    // stores "revoked after" timestamp
tracker.IsUserTokenRevoked(ctx, userID, issuedAt) (bool, error)
```

### Request Signer (`auth/request_signer.go`)

HMAC-SHA256 service-to-service signing. Adds `X-Signature-Timestamp`, `X-Signature-Nonce`, `X-Signature-Signature` headers.

```go
signer := auth.NewRequestSigner(auth.DefaultRequestSignerConfig(secret))
// Signs: method, path+query, host, timestamp, nonce, optional headers, body hash

err := signer.SignRequest(req *http.Request)
err = signer.VerifyRequest(req *http.Request)

// Gin middleware
router.Use(signer.SignatureVerificationMiddleware())   // required — 401 if invalid
router.Use(signer.OptionalSignatureVerificationMiddleware()) // optional — sets "request_signed" in ctx

// Auto-signing HTTP client
signedClient := auth.NewSignedHTTPClient(httpClient, signer)
resp, err := signedClient.Do(req)
resp, err = signedClient.Get(url)
resp, err = signedClient.Post(url, contentType, body)
```

## Internal Auth Middleware (`middleware/internal_auth_middleware.go`)

Validates `X-Internal-JWT` header. Sets `UserContext` in gin context on success.

```go
m := skmw.NewInternalJWTAuth(jwtSecret string, publicPaths []string) *skmw.InternalJWTAuth
// or with JTI tracking:
m = skmw.NewInternalJWTAuthWithConfig(skmw.InternalJWTAuthConfig{
    JWTSecret:   secret,
    PublicPaths: []string{"/health", "/api/v1/public/..."},
    JTITracker:  jtiTracker, // optional, nil = no replay protection
})

router.Use(m.Middleware())         // validates if path NOT in PublicPaths
router.Use(m.MiddlewareRequired()) // always validates
router.Use(m.MiddlewareOptional()) // validates if header present, skips if absent

// In handler:
uc, ok := skmw.GetUserContext(c)    // returns (*models.UserContext, bool)
uc = skmw.MustGetUserContext(c)     // panics if not set
```

`UserContext` populated from InternalJWT claims:

```go
type UserContext struct {
    UserID         string
    HostID         string
    Email          string
    EmailVerified  bool        // always true (enricher verified)
    Roles          []string
    CompaniesRoles *CompanyPermissionsForAuthUserMap  // map[companyID][]role
    SessionID      string
    Subject        string      // KeycloakID
}
```

## Auth Helpers (`middleware/middleware_auth_helper.go`)

```go
skmw.RequireAuth() gin.HandlerFunc              // 401 if no UserContext
skmw.RequireRole(role string)                   // 403 if user lacks role
skmw.RequireAnyRole(roles ...string)            // 403 if user lacks all roles
skmw.RequireEmailVerified()                     // 403 if not verified
skmw.RequireCompanyAccess()                     // 403 if CompaniesRoles is nil/empty
skmw.RequireCompanyRole(requiredRole string)    // 403 if user lacks role in company
```

## Role Constants (`models/common.go`)

```go
// Realm roles
models.RoleUser            = "USER"
models.RoleHost            = "HOST"
models.RoleAdmin           = "ADMIN"
models.RoleProductCreator  = "PRODUCT_CREATOR"

// Company roles
models.CompanyRoleOwner                    = "OWNER"
models.CompanyRoleManager                  = "MANAGER"
models.CompanyRoleAdminAllStays            = "ADMIN_ALL_STAYS"
models.CompanyRoleAdminAllExperiences      = "ADMIN_ALL_EXPERIENCES"
models.CompanyRoleAdminSpecificStay        = "ADMIN_SPECIFIC_STAYS"
models.CompanyRoleAdminSpecificExperience  = "ADMIN_SPECIFIC_EXPERIENCES"
models.CompanyRoleStaff                    = "STAFF"
```

## OPA Authorization (`middleware/opa_embedded.go`)

Two-tier authorization. Tier 1 (company-level) is embedded in sharedkit. Tier 2 (domain-level) is custom Rego in each service.

```go
// Tier 1: company-level OPA
engine, err := skmw.NewCompanyOPAEngine()

// Domain configs — use the real functions from sharedkit:
stays := skmw.StaysDomainConfig()          // FullAccessRoles: [ADMIN_ALL_STAYS], GranularRoles: [ADMIN_SPECIFIC_STAYS]
experiences := skmw.ExperiencesDomainConfig() // FullAccessRoles: [ADMIN_ALL_EXPERIENCES], GranularRoles: [ADMIN_SPECIFIC_EXPERIENCES]
// ProductsDomainConfig() does NOT exist in sharedkit — defined inline in sys-backend-product-n-services

router.Use(engine.AuthorizeCompanyAccess(domainCfg)) // sets context keys below
router.Use(skmw.RequireCompanyRoles("OWNER", "MANAGER")) // per-endpoint guard AFTER tier 1

// Context keys set by AuthorizeCompanyAccess:
// OPACompanyAllowedKey    ("opa_company_allowed")    bool
// OPARequiresDomainCheckKey ("opa_requires_domain_check") bool
// OPACompanyRolesKey      ("opa_company_roles")      []string
// "company_id"            string

// HTTP method → OPA action mapping:
// GET → "read", POST → "create", PUT/PATCH → "update", DELETE → "delete"
```

### CompanyAuthzConfig

```go
type CompanyAuthzConfig struct {
    Domain          string
    FullAccessRoles []string  // roles that bypass domain resource checks
    GranularRoles   []string  // roles that require tier-2 domain check
}
```

### OPA Sidecar (Tier 2)

```go
sidecar := skmw.NewCompanyOPASidecar(skmw.CompanyOPASidecarConfig{...})
// Same AuthorizeCompanyAccess interface — queries external OPA HTTP endpoint
// Skips the HTTP call if OPARequiresDomainCheckKey is false in context
```

## Roles Cache Middleware (`middleware/roles_cache.go`)

Reads `CompaniesRoles` from Redis before OPA evaluates. Must run after JWT auth, before OPA tier 1.

```go
skmw.RolesCacheMiddleware(skmw.RolesCacheConfig{
    Cache:       redisCache,
    CacheKeyFunc: func(userID string) string {
        return "user:" + userID + ":company_roles"  // default (underscore, not hyphen)
    },
})
```

**CRITICAL**: Default cache key uses underscore: `user:<userID>:company_roles`. The permission warmer in `sys-backend-user` writes `user:{id}:company-roles` (hyphen). These must match — if they don't, company roles will never load from cache. Check both sides when debugging auth failures.

On cache miss: does NOT abort — CompaniesRoles stays nil, OPA denies (fail-closed).

## CORS (`middleware/cors.go`)

```go
router.Use(skmw.CORS())   // allows all origins *, methods POST/OPTIONS/GET/PUT/DELETE/PATCH

router.Use(skmw.CORSWithConfig(skmw.CORSConfig{
    AllowOrigin:      []string{"https://app.example.com"},
    AllowMethods:     []string{"GET", "POST"},
    AllowHeaders:     []string{"Authorization"},
    AllowCredentials: true,
    MaxAge:           86400,
}))
```

## Rate Limiting (`ratelimit/`)

Sliding window via Redis sorted sets. Fixed-window and token-bucket also available.

```go
redisClient := cache.NewRedisClientFromConfig(redisCfg)
limiter := ratelimit.NewLimiter(redisClient, ratelimit.LimiterConfig{
    KeyPrefix: "ratelimit:my-service:",  // namespace all Redis keys
})

// Middleware variants
router.Use(limiter.PerIPMiddleware(100, time.Minute))        // 100 req/min per IP
router.Use(limiter.PerUserMiddleware(200, time.Minute))       // 200 req/min per user (falls back to IP)
router.Use(limiter.PerEndpointMiddleware(50, time.Minute))    // 50 req/min per method+path+IP
router.Use(limiter.Middleware(ratelimit.MiddlewareConfig{      // custom
    Limit:   50,
    Window:  time.Minute,
    KeyFunc: func(c *gin.Context) string { return "custom:" + c.GetHeader("X-Tenant-ID") },
    SkipFunc: func(c *gin.Context) bool { return c.FullPath() == "/health" },
}))

// Response headers set: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
// On exceeded: 429 + Retry-After + X-RateLimit-Reset
// On Redis error: allows request, sets X-RateLimit-Error: true (fail-open)

// Direct API
result, err := limiter.Allow(ctx, key string, limit int64, window time.Duration) (*ratelimit.Result, error)
result, err = limiter.AllowN(ctx, key, limit, window, n int64)
result, err = limiter.GetStatus(ctx, key, limit, window)
err = limiter.Reset(ctx, key)
```

## UserContext (`models/user_context.go`)

```go
type UserContext struct {
    UserID         string
    HostID         string
    Email          string
    EmailVerified  bool
    Roles          []string
    CompaniesRoles *CompanyPermissionsForAuthUserMap  // nil if not loaded from cache
    SessionID      string
    Subject        string
}

type CompanyPermissionsForAuthUserMap = map[string][]string  // companyID → []roleName

// Methods
uc.HasRole(role string) bool
uc.HasAnyOfRoles(roles ...string) bool
uc.GetUserCompanyRoles(companyID string) ([]string, bool)
uc.HasCompanyAccess(companyID string) bool
uc.HasAnyOfCompanyRoles(companyID string, roles ...string) bool
uc.GetUserCompanies() []string

// Retrieve from Gin context
uc, ok := models.GetUserContext(c *gin.Context) (*UserContext, bool)
uc = models.MustGetUserContext(c *gin.Context)  // panics: "user context not found - did you forget RequireAuth()?"

const models.UserContextKey = "user_context"
```

## Keycloak (`client/auth/`)

### KeycloakClient

```go
kc := auth.NewKeycloakClient(baseURL, jwksURL, realm, clientID, clientSecret string)
// jwksURL defaults to {baseURL}/realms/{realm}/protocol/openid-connect/certs if empty

kc.FetchPublicKey(ctx, kid string) ([]byte, *rsa.PublicKey, error)
kc.LogoutUser(ctx, keycloakUserID, adminToken string) error
kc.UpdateUserAttributes(ctx, keycloakUserID, adminToken string, attributes map[string][]string) error
kc.GetAdminToken(ctx) (string, error)  // client_credentials grant
```

### CachedAuthClient (recommended)

Wraps `KeycloakClient` with Redis caching (24h for JWKS, 4min for admin tokens):

```go
cachedAuth := auth.NewCachedAuthClient(kcClient, redisCache)
publicKey, err := cachedAuth.GetPublicKey(ctx, kid)     // memory → Redis → Keycloak
adminToken, err := cachedAuth.GetAdminToken(ctx)         // Redis → Keycloak
userCtx, err := cachedAuth.ParseToken(ctx, tokenString) // validates RSA JWT, returns UserContext
err = cachedAuth.UpdateUserAttributes(ctx, kcUserID, attributes, adminToken)
err = cachedAuth.FetchAndCachePublicKeys(kcUserID, suffix string) // preload JWKS into Redis
```

Cache keys used:
- `jwks:{realm}:{kid}` — JWKS public key JSON (24h)
- `keycloak:admin_token` — admin access token (4min)

## Keycloak Claims (`models/keycloak.go`)

```go
type KeycloakClaims struct {
    jwt.RegisteredClaims
    RealmAccess    struct{ Roles []string `json:"roles"` }  `json:"realm_access"`
    ResourceAccess map[string]struct{ Roles []string }      `json:"resource_access"`
    Email          string   `json:"email"`
    EmailVerified  bool     `json:"email_verified"`
    UserID         string   `json:"user_id"`          // custom claim added by auth-enricher
    HostID         string   `json:"host_id"`           // custom claim
    CompaniesRoles []CompanyRoles `json:"companies_roles"` // custom claim
    SessionID      string   `json:"sid"`
    // ...plus name, preferred_username, given_name, family_name, etc.
}
```

## Events (`events/events.go`)

Redis Pub/Sub-based domain event bus. Currently used for user/profile/host lifecycle events.

```go
publisher := events.NewRedisEventPublisher(redisClient, serviceName string)
err := publisher.Publish(ctx, &events.Event{
    Type:   events.EventUserCreated,  // "user.created"
    UserID: userID,
    Data:   map[string]any{"email": email},
})

// Pre-defined event types: EventUserCreated, EventUserUpdated, EventUserDeleted,
//                          EventProfileCreated, EventProfileUpdated, EventProfileDeleted,
//                          EventHostCreated, EventHostUpdated, EventHostDeleted

subscriber := events.NewRedisEventSubscriber(redisClient, serviceName)
err = subscriber.Subscribe(ctx, []events.EventType{events.EventUserCreated}, func(ctx context.Context, e *events.Event) error {
    // handle event
    return nil
})
subscriber.Close()

// Helper
e := events.NewEvent(eventType, userID, data map[string]any) *events.Event
```

Channels: `events:{type}` per event type, plus `events:all` for monitoring.

## Observability (`observability/observability.go`)

```go
// Initialize OTLP tracing (Grafana Cloud or local)
shutdown := observability.InitObservability(cfg *config.Config)
defer shutdown(ctx)

// Gin middleware
router.Use(observability.TracingMiddleware())   // OpenTelemetry span per request
router.Use(observability.MetricsMiddleware())   // Prometheus counters + histograms
router.Use(observability.LoggingMiddleware())   // stdlib log (prefer zap in services)

// Manual metrics
observability.RecordCacheHit("redis")
observability.RecordCacheMiss("redis")
observability.RecordDatabaseQuery("select", duration)
observability.SetActiveConnections(count)
```

`config.Config` fields needed: `ServiceName`, `ServiceVersion`, `Environment`, `EnableTracing`, `GrafanaCloudOTLPEndpoint`, `GrafanaCloudAPIKey`.

## Utility Packages

### `util/array_util.go`

```go
util.Difference[T comparable](x, y []T) []T  // elements in x not in y
util.Contains[T comparable](slice []T, v T) bool
```

### `util/jsonb_util.go`

```go
type JSONB map[string]any   // implements driver.Valuer + sql.Scanner for JSONB columns

util.ScanJSONSlice[S ~[]E, E any](src any, dest *S) error  // scan JSONB array into typed slice
util.ToRawMessage(v any) (json.RawMessage, error)
util.FromRawMessage[T any](rm json.RawMessage) (T, error)
```

### `util/complex_types.go`

```go
type StringArray []string   // implements driver.Valuer + sql.Scanner for TEXT[] columns
// Value(): formats as PostgreSQL {item1,item2} literal
// Scan(): JSON unmarshal from []byte or string
```

## Known Gotchas

- **`GetEnvAsBool` exists** in `sharedkit/config` — not in `arcusdata/util`. For arcusdata consumers: use `config.GetEnv("KEY","false") == "true"`.
- **OPA import path**: `github.com/open-policy-agent/opa/v1/rego` — the `/v1/` segment is required; Rego files need `import rego.v1`.
- **No `go:embed` for Rego policies**: The embedded company policy is a string constant in `opa_embedded.go` — `go:embed` doesn't work for library consumers with paths outside their module root.
- **`ProductsDomainConfig()` does not exist**: Only `StaysDomainConfig()` and `ExperiencesDomainConfig()` are in sharedkit. Other services define their own inline.
- **Roles cache key**: Default `user:<userID>:company_roles` (underscore). Must match what the permission warmer writes. Any mismatch means company auth always fails with nil CompaniesRoles.
- **JWT header**: Backend services read `X-Internal-JWT`, not `Authorization`. The Authorization header is stripped by Traefik.
