# sharedkit — Developer Guide

## Overview

Shared Go library (`github.com/devspotai/sharedkit`). Its main job is **authorization that any service can adopt regardless of how it authenticates**: company-level and domain-level OPA policies, role guards, and company-role loading. It also provides Redis caching, rate limiting, CORS, event pub/sub, observability and small utilities.

Live consumer: `serveyourstay-platform/sys-backend-services` (Zitadel, DigitalOcean App Platform, no gateway). Check its usage before changing any public API.

## Module

```
Module: github.com/devspotai/sharedkit
Go version: 1.27.0 (toolchain go1.27.1)
```

## Key Dependencies

| Package | Version |
|---------|---------|
| github.com/gin-gonic/gin | v1.12.0 |
| github.com/lestrrat-go/jwx/v3 | v3.3.0 |
| github.com/open-policy-agent/opa | v1.21.0 |
| github.com/redis/go-redis/v9 | v9.22.0 |
| go.opentelemetry.io/otel | v1.46.0 |
| github.com/prometheus/client_golang | v1.24.1 |

**OPA import path**: `github.com/open-policy-agent/opa/v1/rego` — Rego files must use `import rego.v1`.

## Directory Structure

```
authn/                      # authentication CONTRACT only
  authn.go                  # Authenticator, Middleware, Authenticate, SetPrincipal, Error, ErrUnavailable, ExtractBearer
  zitadel/                  # optional Zitadel implementation
    validator.go            # Validator — offline JWKS verification
    authenticator.go        # Authenticator, TokenValidator, UserResolver
    rediscache.go           # RedisKeyCache — JWKS survives restarts during IdP outages
authz/                      # authorization — IdP-agnostic
  company_roles.go          # CompanyRole, CompanyRoleSource, CachedRoles, LoadCompanyRoles, RolesCacheKey/Entry
  guards.go                 # RequireAuth, RequireRole, RequireAnyRole, RequireEmailVerified, RequireCompanyAccess, RequireCompanyRole
  company_opa.go            # tier 1: CompanyOPAEngine, CompanyOPASidecar, RequireCompanyRoles, Stays/ExperiencesDomainConfig
  domain_opa.go             # tier 2: DomainOPAEngine, DomainOPASidecar
  company_id.go             # resolveCompanyID — the single company-ID rule
middleware/
  cors.go                   # CORS(), CORSWithConfig()
  zitadel_auth.go           # DEPRECATED shim: NewZitadelAuth = authn/zitadel + authz.LoadCompanyRoles
  compat.go                 # DEPRECATED aliases for everything that moved to authz/authn
auth/, auth/zitadel/        # DEPRECATED alias packages (moved to authz and authn/zitadel)
client/cache/redis_cache.go # NewRedisClientFromConfig, NewRedisCacheFromConfig, RedisCache
config/config.go            # LoadRedisConfig, GetEnv, GetEnvAsInt, GetEnvAsBool
events/events.go            # Event types, RedisEventPublisher, RedisEventSubscriber
models/                     # UserContext (the principal), role constants, response wrappers
observability/              # InitObservability, TracingMiddleware, MetricsMiddleware
ratelimit/                  # Limiter, middleware variants
util/                       # Difference, Contains, JSONB, StringArray
```

Dependency direction: `authz` never imports `authn`. The only thing they share is `models.UserContext` on the gin context under `models.UserContextKey`.

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
// Raw redis.Client — use for rate limiters
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

## Authentication vs. authorization

Authentication is each service's own choice; authorization is what sharedkit standardises. The seam is one value: a `*models.UserContext` stored on the gin context.

```go
// 1. Authenticate — implement authn.Authenticator for your IdP (or use authn/zitadel)
type myAuth struct{}
func (myAuth) Authenticate(r *http.Request) (*models.UserContext, error) {
    // verify credentials; return identity + global roles only
    // wrap authn.ErrUnavailable for IdP outages (→ 503); other errors → 401;
    // return *authn.Error to control status, message and headers
}
router.Use(authn.Middleware(myAuth{}, authn.Options{PublicPaths: []string{"/health", "/facts/:country"}}))
// A service with its own auth middleware can call authn.SetPrincipal(c, uc) instead.

// 2. Load company roles — authorization data, never supplied by the IdP
router.Use(authz.LoadCompanyRoles(authz.CachedRoles(roleSource, redisCache, 5*time.Minute)))
// roleSource implements authz.CompanyRoleSource (or use authz.CompanyRoleSourceFunc).
// CachedRoles(nil, cache, ttl) is cache-only: a miss means no company access (fail closed).
// A source error answers 503.

// 3. Authorize
group.Use(engine.AuthorizeCompanyAccess(authz.StaysDomainConfig()))  // tier 1
group.GET("/x", authz.RequireCompanyRoles("OWNER"), handler)           // per-route guard after tier 1
```

### Zitadel (`authn/zitadel`)

```go
v, err := zitadel.New(zitadel.Config{JWKSURL, Issuer, Audience, KeyCache: zitadel.NewRedisKeyCache(rc)})
v.Start(ctx)                                  // background key rotation polling
a, err := zitadel.NewAuthenticator(v, users)  // users implements UserResolver (ResolveUserID)
router.Use(authn.Middleware(a, authn.Options{PublicPaths: public}))
```

First sign-in (token has no `app_uid` metadata yet): the user is provisioned via `ResolveUserID`, and the request gets 401 with `X-Token-Refresh-Required: true`. JWKS unavailable → 503.

`middleware.NewZitadelAuth` still exists as a deprecated shim built from exactly these pieces, so older routers keep working.

### Guards (`authz/guards.go`)

```go
authz.RequireAuth()                          // 401 if no UserContext
authz.RequireRole(role)                      // 403 if user lacks role
authz.RequireAnyRole(roles...)               // 403 if user lacks all roles
authz.RequireEmailVerified()                 // 403 if not verified
authz.RequireCompanyAccess()                 // 403 if user has no role in the request's company
authz.RequireCompanyRole(role)               // 403 if user lacks role in the request's company
```

Company ID resolution (`authz/company_id.go`), used by every company guard and both OPA tiers: path `:companyId`, then `:company_id`, then the `?companyId=` query **only when there is no path segment**. A request naming two different companies gets 400.

## Role Constants (`models/common.go`)

```go
// Global roles
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

## OPA Authorization (`authz/company_opa.go`, `authz/domain_opa.go`)

Two tiers. Tier 1 (company-level) is embedded in sharedkit. Tier 2 (domain-level) is each service's own Rego.

```go
engine, err := authz.NewCompanyOPAEngine()

stays := authz.StaysDomainConfig()             // FullAccessRoles: [ADMIN_ALL_STAYS], GranularRoles: [ADMIN_SPECIFIC_STAYS]
experiences := authz.ExperiencesDomainConfig() // FullAccessRoles: [ADMIN_ALL_EXPERIENCES], GranularRoles: [ADMIN_SPECIFIC_EXPERIENCES]
// Other domains define a CompanyAuthzConfig inline.

group.Use(engine.AuthorizeCompanyAccess(domainCfg))
group.Use(authz.RequireCompanyRoles("OWNER", "MANAGER"))

// Context keys set by AuthorizeCompanyAccess:
// OPACompanyAllowedKey      ("opa_company_allowed")       bool
// OPARequiresDomainCheckKey ("opa_requires_domain_check") bool
// OPACompanyRolesKey        ("opa_company_roles")         []string
// "company_id"              string — tier 2 evaluates this same company

// HTTP method → OPA action: GET → "read", POST → "create", PUT/PATCH → "update", DELETE → "delete"

domainEngine, err := authz.NewDomainOPAEngine(authz.DomainOPAConfig{...})
group.Use(domainEngine.AuthorizeDomainResource())  // tier 2; skipped unless tier 1 requires it
```

`CompanyOPASidecar` / `DomainOPASidecar` implement the same interfaces against an external OPA over HTTP.

## Company roles cache (`authz/company_roles.go`)

Key `user:<userID>:company-roles` (**hyphen**), value `authz.RolesCacheEntry` (`user_id`, `email`, `idp_user_id`, `company_roles`, `cached_at`). The platform's permission warmer writes the same format; only `company_roles` is read back. If you change either side, change both.

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
router.Use(limiter.PerIPMiddleware(100, time.Minute))        // 100 req/min per IP (gin ClientIP)
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
// DefaultKeyFunc uses gin's c.ClientIP(). Behind a proxy, configure gin
// (SetTrustedProxies or TrustedPlatform) or every client is keyed by the
// proxy's address or a spoofable header. On DO App Platform the client IP is
// in do-connecting-ip.

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
    CompaniesRoles *CompanyPermissionsForAuthUserMap  // set by authz.LoadCompanyRoles; nil = no companies
    SessionID      string
    Subject        string  // identity provider subject
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
- **No `go:embed` for Rego policies**: the embedded company policy is a string constant in `authz/company_opa.go` — `go:embed` doesn't work for library consumers with paths outside their module root.
- **`ProductsDomainConfig()` does not exist**: only `StaysDomainConfig()` and `ExperiencesDomainConfig()` are in sharedkit. Other domains define their own inline.
- **Mount order**: authentication → `authz.LoadCompanyRoles` → company guards / OPA tier 1 → tier 2. Guards that run before roles are loaded see nil `CompaniesRoles` and deny.
- **`authz` must not import `authn`** (or any IdP package). That independence is the point of the split.
- **Deprecated packages** (`middleware` auth aliases, `auth`, `auth/zitadel`) only forward to `authz`/`authn`. Don't add new code there.
