// Package zitadel validates Zitadel-issued OIDC access tokens offline against
// the instance's JWKS.
//
// It is the counterpart to client/auth, which does the same for Keycloak. Three
// things Keycloak put where a generic OIDC validator expects them, Zitadel does
// not:
//
//	sub       Keycloak issued a UUID; Zitadel issues a numeric snowflake
//	          (e.g. 378124744102248456). A UUID-shaped check rejects every token.
//	user_id   Keycloak carried custom attributes as top-level claims. Zitadel
//	          carries them under urn:zitadel:iam:user:metadata, as a map whose
//	          values are base64-encoded.
//	roles     realm_access.roles becomes urn:zitadel:iam:org:project:roles, a map
//	          of role key -> {orgID: orgDomain}.
//
// # Audience is mandatory
//
// A single Zitadel deployment hosts several tenants. Without an audience check a
// token minted for one app is accepted by another, so Config.Audience is
// required and New refuses to build a Validator without it.
//
// # Surviving an IdP outage
//
// New never fails because the JWKS could not be fetched. An identity provider is
// a shared dependency: if every service that verifies its tokens refuses to boot
// while it is down, a brief IdP outage becomes a total one the moment anything
// restarts or redeploys. Instead the validator starts empty, reports NotReady,
// and answers ErrKeysUnavailable (which callers surface as 503, not 401) until
// keys arrive. Supplying a KeyCache lets a restart reuse the last known key set,
// so an outage does not even cost that.
//
// # Algorithm pinning
//
// jwt.WithKeySet requires each JWKS key to carry an "alg" and resolves the key
// by "kid", deliberately ignoring the token's own header. That is what stops a
// caller swapping the algorithm, so jws.WithInferAlgorithmFromKey must stay off.
package zitadel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/sync/singleflight"
)

// Zitadel claim URNs.
const (
	claimUserMetadata = "urn:zitadel:iam:user:metadata"
	claimProjectRoles = "urn:zitadel:iam:org:project:roles"

	// metadataKeyUserID is the metadata key the owning service writes the
	// internal user id to after provisioning. Every app on the instance uses the
	// same key so their tokens read consistently.
	metadataKeyUserID = "app_uid"
	metadataKeyHostID = "host_id"
)

// Sentinel errors. Callers map these to status codes: ErrTokenInvalid and
// ErrWrongTenant are the caller's fault (401), ErrKeysUnavailable is ours (503).
// The gateway this replaced collapsed all three into 401, which made a Zitadel
// outage indistinguishable from a forged token.
var (
	ErrTokenInvalid    = errors.New("zitadel: token invalid")
	ErrWrongTenant     = errors.New("zitadel: token issued for a different issuer or audience")
	ErrKeysUnavailable = errors.New("zitadel: signing keys unavailable")
)

// Compiled once. These used to be built per call, which meant three regex
// compilations on every token validation.
var (
	zitadelIDPattern = regexp.MustCompile(`^[0-9]{1,32}$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	emailPattern     = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// KeyCache persists a fetched JWKS across restarts. Any shared store will do;
// NewRedisKeyCache adapts sharedkit's Redis client.
//
// A cache miss is never an error the validator reports upward — it just means
// falling back to the network.
type KeyCache interface {
	GetJWKS(ctx context.Context, key string) ([]byte, error)
	PutJWKS(ctx context.Context, key string, raw []byte, ttl time.Duration) error
}

// Config configures a Validator. JWKSURL, Issuer and Audience are required.
type Config struct {
	// JWKSURL is the instance's key endpoint, e.g.
	// https://auth.example.com/oauth/v2/keys
	JWKSURL string
	// Issuer must equal the token's iss claim exactly.
	Issuer string
	// Audience must appear in the token's aud claim. For Zitadel this is the API
	// application's client id; the frontend requests
	// urn:zitadel:iam:org:project:id:<project>:aud to get it there.
	Audience string

	// CACertPath appends a PEM CA to the system pool. Optional.
	CACertPath string
	// ClientCertPath/ClientKeyPath present a client certificate to the JWKS
	// endpoint. Zitadel does not ask for one; these exist for deployments that
	// front it with a mutually-authenticated proxy. Optional, but both or neither.
	ClientCertPath string
	ClientKeyPath  string

	// RefreshInterval is the background JWKS poll period. Default 15m.
	// A rotated key does not wait for this: an unknown kid triggers an immediate
	// refresh (see Validate).
	RefreshInterval time.Duration
	// HTTPTimeout bounds a single JWKS fetch. Default 10s.
	HTTPTimeout time.Duration
	// AcceptableSkew tolerates clock drift on exp/nbf/iat. Default 30s.
	AcceptableSkew time.Duration

	// KeyCache persists the key set so a restart during an IdP outage can still
	// verify tokens. Optional; without it a restart mid-outage starts with no
	// keys and rejects every request with ErrKeysUnavailable until the IdP
	// returns.
	KeyCache KeyCache
	// KeyCacheKey namespaces the cached entry. Defaults to the JWKS URL, which
	// keeps two instances of different tenants from sharing one entry.
	KeyCacheKey string
	// KeyCacheTTL bounds how long a cached key set may be served without a
	// successful refresh. Default 24h. Longer survives a longer outage but also
	// serves a retired signing key for longer.
	KeyCacheTTL time.Duration
}

func (c *Config) applyDefaults() {
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = 15 * time.Minute
	}
	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = 10 * time.Second
	}
	if c.AcceptableSkew <= 0 {
		c.AcceptableSkew = 30 * time.Second
	}
	if c.KeyCacheTTL <= 0 {
		c.KeyCacheTTL = 24 * time.Hour
	}
	if c.KeyCacheKey == "" {
		c.KeyCacheKey = "jwks:" + c.JWKSURL
	}
}

func (c Config) validate() error {
	switch {
	case c.JWKSURL == "":
		return errors.New("zitadel: Config.JWKSURL is required")
	case c.Issuer == "":
		return errors.New("zitadel: Config.Issuer is required")
	case c.Audience == "":
		// Deliberately not optional. See the package doc.
		return errors.New("zitadel: Config.Audience is required — without it this instance's other tenants' tokens are accepted")
	case (c.ClientCertPath == "") != (c.ClientKeyPath == ""):
		return errors.New("zitadel: Config.ClientCertPath and ClientKeyPath must be set together")
	}
	return nil
}

// Claims is the subset of a Zitadel token this package understands.
type Claims struct {
	// Subject is Zitadel's own user id, a numeric snowflake.
	Subject string
	// UserID is the owning service's user id, read from user metadata. Empty on
	// first login, before the metadata has been written.
	UserID string
	// HostID is read from user metadata when the user is a host.
	HostID string

	Email             string
	EmailVerified     bool
	PreferredUsername string

	// ProjectRoles are the role keys from the project-roles claim.
	ProjectRoles []string
	// RoleOrgs maps each role key to the org ids it was granted in. The gateway
	// discarded this; multi-tenant callers need it to tell which org a role
	// applies to.
	RoleOrgs map[string][]string
}

// Validator validates tokens against a cached JWKS.
type Validator struct {
	cfg        Config
	httpClient *http.Client

	mu     sync.RWMutex
	keySet jwk.Set

	// refresh collapses concurrent refreshes of the same key set. Without it a
	// rotation stampedes the JWKS endpoint with one fetch per in-flight request.
	refresh singleflight.Group
}

// New builds a Validator and tries to populate its key set.
//
// It returns an error only for a bad configuration. Failing to obtain keys is
// not fatal: the validator starts NotReady and every Validate call returns
// ErrKeysUnavailable until a refresh succeeds. See the package doc for why.
//
// Key sources are tried in order: a live fetch, then the KeyCache if one is
// configured.
func New(cfg Config) (*Validator, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.applyDefaults()

	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	v := &Validator{cfg: cfg, httpClient: httpClient}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.HTTPTimeout)
	defer cancel()

	fetchErr := v.refreshKeys(ctx)
	if fetchErr == nil {
		return v, nil
	}
	if cacheErr := v.loadFromCache(ctx); cacheErr == nil {
		return v, nil
	}
	// No keys anywhere. Ready() reports false so a health check can show the
	// degraded state, and Start's polling will pick keys up when the IdP returns.
	return v, nil
}

// Ready reports whether the validator holds a usable key set. A health endpoint
// should surface this: until it is true every authenticated request fails with
// a 503, and the cause is upstream rather than in this process.
func (v *Validator) Ready() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keySet != nil && v.keySet.Len() > 0
}

// Start runs the background refresh until ctx is cancelled. It returns
// immediately. The gateway's version leaked its ticker; this one stops.
func (v *Validator) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(v.cfg.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchCtx, cancel := context.WithTimeout(ctx, v.cfg.HTTPTimeout)
				// A failed poll is not fatal: the cached set stays in place and
				// an unknown kid still forces a refresh on demand.
				_ = v.refreshKeys(fetchCtx)
				cancel()
			}
		}
	}()
}

// Validate verifies a token's signature, issuer, audience and time claims, and
// returns the claims this package understands.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	// Resolve the key before parsing so a rotated kid refreshes immediately
	// rather than failing until the next poll.
	kid, err := signingKeyID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err)
	}
	if !v.Ready() {
		// Started, or restarted, while the IdP was unreachable and with nothing
		// cached. This is a dependency failure, not a bad token.
		if err := v.refreshOnce(ctx); err != nil {
			return nil, fmt.Errorf("%w: no signing keys held: %s", ErrKeysUnavailable, err)
		}
	}
	if !v.hasKey(kid) {
		if err := v.refreshOnce(ctx); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrKeysUnavailable, err)
		}
		if !v.hasKey(kid) {
			return nil, fmt.Errorf("%w: unknown signing key %q", ErrTokenInvalid, kid)
		}
	}

	v.mu.RLock()
	keySet := v.keySet
	v.mu.RUnlock()

	// Signature only. Claims are validated below so a wrong-tenant token is
	// distinguishable from a forged one.
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(false),
		jwt.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err)
	}

	// Time claims (exp/nbf/iat) are checked by jwx's default validators.
	if err := jwt.Validate(token, jwt.WithAcceptableSkew(v.cfg.AcceptableSkew)); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTokenInvalid, err)
	}
	if err := jwt.Validate(token,
		jwt.WithResetValidators(true),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
	); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrWrongTenant, err)
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: missing subject", ErrTokenInvalid)
	}
	// Zitadel subjects are decimal snowflakes, not UUIDs. Bounded so an absurdly
	// long value cannot be smuggled through as an id.
	if !zitadelIDPattern.MatchString(subject) {
		return nil, fmt.Errorf("%w: subject is not a Zitadel id", ErrTokenInvalid)
	}

	metadata := userMetadata(token)
	roleOrgs := projectRoles(token)

	claims := &Claims{
		Subject:           subject,
		UserID:            metadata[metadataKeyUserID],
		HostID:            metadata[metadataKeyHostID],
		Email:             stringClaim(token, "email"),
		EmailVerified:     boolClaim(token, "email_verified"),
		PreferredUsername: stringClaim(token, "preferred_username"),
		RoleOrgs:          roleOrgs,
		ProjectRoles:      make([]string, 0, len(roleOrgs)),
	}
	for role := range roleOrgs {
		claims.ProjectRoles = append(claims.ProjectRoles, role)
	}

	// UserID is absent on first login, before the metadata is written; the
	// caller detects the empty value and provisions. When present it is the
	// owning service's UUID, not a Zitadel id.
	if claims.UserID != "" && !uuidPattern.MatchString(claims.UserID) {
		return nil, fmt.Errorf("%w: user metadata %q is not a UUID", ErrTokenInvalid, metadataKeyUserID)
	}
	if claims.Email != "" && !emailPattern.MatchString(claims.Email) {
		return nil, fmt.Errorf("%w: malformed email claim", ErrTokenInvalid)
	}

	return claims, nil
}

func (v *Validator) hasKey(kid string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.keySet == nil {
		return false
	}
	_, ok := v.keySet.LookupKeyID(kid)
	return ok
}

// refreshOnce fetches the JWKS, collapsing concurrent callers onto one request.
func (v *Validator) refreshOnce(ctx context.Context) error {
	fetchCtx, cancel := context.WithTimeout(ctx, v.cfg.HTTPTimeout)
	defer cancel()
	_, err, _ := v.refresh.Do("jwks", func() (any, error) {
		return nil, v.refreshKeys(fetchCtx)
	})
	return err
}

func (v *Validator) refreshKeys(ctx context.Context) error {
	keySet, err := jwk.Fetch(ctx, v.cfg.JWKSURL, jwk.WithHTTPClient(v.httpClient))
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	v.mu.Lock()
	v.keySet = keySet
	v.mu.Unlock()

	// Best effort. A cache that will not accept the key set costs the next
	// restart its head start, nothing more, so it must not fail the refresh.
	if v.cfg.KeyCache != nil {
		if raw, marshalErr := json.Marshal(keySet); marshalErr == nil {
			_ = v.cfg.KeyCache.PutJWKS(ctx, v.cfg.KeyCacheKey, raw, v.cfg.KeyCacheTTL)
		}
	}
	return nil
}

// loadFromCache restores the last persisted key set. Used only when a live
// fetch has already failed, so a stale set beats no set.
func (v *Validator) loadFromCache(ctx context.Context) error {
	if v.cfg.KeyCache == nil {
		return errors.New("no key cache configured")
	}
	raw, err := v.cfg.KeyCache.GetJWKS(ctx, v.cfg.KeyCacheKey)
	if err != nil {
		return fmt.Errorf("read cached JWKS: %w", err)
	}
	if len(raw) == 0 {
		return errors.New("cached JWKS is empty")
	}
	keySet, err := jwk.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse cached JWKS: %w", err)
	}
	if keySet.Len() == 0 {
		return errors.New("cached JWKS holds no keys")
	}
	v.mu.Lock()
	v.keySet = keySet
	v.mu.Unlock()
	return nil
}

// signingKeyID reads the kid from the protected header without verifying
// anything. The value is used only to look up a key; an attacker controlling it
// can at worst cause a lookup miss.
func signingKeyID(tokenString string) (string, error) {
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return "", fmt.Errorf("parse JWS: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", errors.New("token carries no signature")
	}
	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok || kid == "" {
		return "", errors.New("token has no kid header")
	}
	return kid, nil
}

// userMetadata reads urn:zitadel:iam:user:metadata, whose values are
// base64-encoded. A value that will not decode is skipped rather than failing
// the token: the only consumer is the user-id mapping, and an unreadable one is
// indistinguishable from an absent one, which the caller already handles by
// re-provisioning.
func userMetadata(token jwt.Token) map[string]string {
	out := make(map[string]string)

	var raw any
	if token.Get(claimUserMetadata, &raw) != nil {
		return out
	}
	entries, ok := raw.(map[string]any)
	if !ok {
		return out
	}

	for key, value := range entries {
		encoded, ok := value.(string)
		if !ok {
			continue
		}
		// Zitadel uses standard base64. RawStdEncoding covers values written
		// without padding by an older client.
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
		}
		out[key] = string(decoded)
	}
	return out
}

// projectRoles reads urn:zitadel:iam:org:project:roles, a map of
// role key -> {orgID: orgDomain}, and keeps both halves.
func projectRoles(token jwt.Token) map[string][]string {
	var raw any
	if token.Get(claimProjectRoles, &raw) != nil {
		return nil
	}
	entries, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	out := make(map[string][]string, len(entries))
	for role, orgs := range entries {
		orgMap, ok := orgs.(map[string]any)
		if !ok {
			// A role with an unreadable org map is still a role.
			out[role] = nil
			continue
		}
		ids := make([]string, 0, len(orgMap))
		for orgID := range orgMap {
			ids = append(ids, orgID)
		}
		out[role] = ids
	}
	return out
}

func buildHTTPClient(cfg Config) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}

	if cfg.CACertPath != "" {
		pemBytes, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("zitadel: read CA cert %q: %w", cfg.CACertPath, err)
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("zitadel: no certificates found in %q", cfg.CACertPath)
		}
	}

	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	if cfg.ClientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("zitadel: load client cert %q/%q: %w", cfg.ClientCertPath, cfg.ClientKeyPath, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   cfg.HTTPTimeout,
	}, nil
}

func stringClaim(token jwt.Token, key string) string {
	var val any
	if token.Get(key, &val) == nil {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

func boolClaim(token jwt.Token, key string) bool {
	var val any
	if token.Get(key, &val) == nil {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}
