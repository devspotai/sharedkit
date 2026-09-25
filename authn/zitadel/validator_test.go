package zitadel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "serveyourstay-api"
	// The tenant that shares the instance. A token minted for this audience
	// must never validate against testAudience — that is the whole reason
	// Config.Audience is mandatory.
	otherTenantAudience = "devspot-api"
	testSubject         = "378124744102248456"
	testUserID          = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
)

// signer holds a keypair and serves its public half as a JWKS.
type signer struct {
	kid  string
	priv *rsa.PrivateKey
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &signer{kid: kid, priv: priv}
}

// publicJWK returns the public key with kid and alg set. jwt.WithKeySet
// resolves by kid and requires alg, so both must be present.
func (s *signer) publicJWK(t *testing.T) jwk.Key {
	t.Helper()
	key, err := jwk.Import(s.priv.PublicKey)
	if err != nil {
		t.Fatalf("import public key: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, s.kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		t.Fatalf("set alg: %v", err)
	}
	return key
}

type tokenOpts struct {
	issuer   string
	audience string
	subject  string
	expires  time.Time
	notFor   time.Duration // nbf offset into the future
	metadata map[string]string
	roles    map[string]any
	email    string
}

func (s *signer) mint(t *testing.T, o tokenOpts) string {
	t.Helper()

	if o.issuer == "" {
		o.issuer = testIssuer
	}
	if o.audience == "" {
		o.audience = testAudience
	}
	if o.subject == "" {
		o.subject = testSubject
	}
	if o.expires.IsZero() {
		o.expires = time.Now().Add(time.Hour)
	}

	b := jwt.NewBuilder().
		Issuer(o.issuer).
		Audience([]string{o.audience}).
		Subject(o.subject).
		IssuedAt(time.Now().Add(-time.Minute)).
		Expiration(o.expires)

	if o.notFor > 0 {
		b = b.NotBefore(time.Now().Add(o.notFor))
	}
	if o.email != "" {
		b = b.Claim("email", o.email).Claim("email_verified", true)
	}
	if o.metadata != nil {
		encoded := make(map[string]any, len(o.metadata))
		for k, v := range o.metadata {
			encoded[k] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		b = b.Claim(claimUserMetadata, encoded)
	}
	if o.roles != nil {
		b = b.Claim(claimProjectRoles, o.roles)
	}

	tok, err := b.Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, s.kid)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), s.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return string(signed)
}

// jwksServer serves the given signers' public keys. The key set it serves can
// be swapped at runtime to simulate rotation; fetches counts requests.
type jwksServer struct {
	*httptest.Server
	keys    atomic.Value // []jwk.Key
	fetches atomic.Int64
	down    atomic.Bool
}

func newJWKSServer(t *testing.T, signers ...*signer) *jwksServer {
	t.Helper()
	js := &jwksServer{}
	js.setKeys(t, signers...)

	js.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		js.fetches.Add(1)
		if js.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		set := jwk.NewSet()
		for _, k := range js.keys.Load().([]jwk.Key) {
			_ = set.AddKey(k)
		}
		w.Header().Set("Content-Type", "application/json")
		// No-store keeps jwx from caching across the rotation test.
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(js.Close)
	return js
}

func (js *jwksServer) setKeys(t *testing.T, signers ...*signer) {
	t.Helper()
	keys := make([]jwk.Key, 0, len(signers))
	for _, s := range signers {
		keys = append(keys, s.publicJWK(t))
	}
	js.keys.Store(keys)
}

func newTestValidator(t *testing.T, js *jwksServer) *Validator {
	t.Helper()
	v, err := New(Config{
		JWKSURL:  js.URL,
		Issuer:   testIssuer,
		Audience: testAudience,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestConfigRequiresAudience(t *testing.T) {
	// The gateway defaulted ZITADEL_AUDIENCE to "" and skipped the check, which
	// let another tenant's tokens through. This must not be constructible.
	_, err := New(Config{JWKSURL: "https://example.com/keys", Issuer: testIssuer})
	if err == nil {
		t.Fatal("expected New to reject an empty Audience")
	}
}

func TestConfigRequiresIssuerAndJWKSURL(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no jwks url": {Issuer: testIssuer, Audience: testAudience},
		"no issuer":   {JWKSURL: "https://example.com/keys", Audience: testAudience},
		"half mTLS":   {JWKSURL: "https://e/k", Issuer: testIssuer, Audience: testAudience, ClientCertPath: "/tmp/c.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("expected New to reject this config")
			}
		})
	}
}

func TestValidateAcceptsAValidToken(t *testing.T) {
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	token := s.mint(t, tokenOpts{
		email:    "traveller@example.com",
		metadata: map[string]string{metadataKeyUserID: testUserID, metadataKeyHostID: "host-9"},
		roles: map[string]any{
			"REGISTERED_HOST": map[string]any{"org-1": "example.com"},
		},
	})

	claims, err := v.Validate(context.Background(), token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != testSubject {
		t.Errorf("Subject = %q, want %q", claims.Subject, testSubject)
	}
	// The metadata claim is base64-encoded per value; this is the decoding.
	if claims.UserID != testUserID {
		t.Errorf("UserID = %q, want %q", claims.UserID, testUserID)
	}
	if claims.HostID != "host-9" {
		t.Errorf("HostID = %q, want %q", claims.HostID, "host-9")
	}
	if claims.Email != "traveller@example.com" || !claims.EmailVerified {
		t.Errorf("email claims not carried: %+v", claims)
	}
	// The org id used to be read and thrown away.
	if got := claims.RoleOrgs["REGISTERED_HOST"]; len(got) != 1 || got[0] != "org-1" {
		t.Errorf("RoleOrgs[REGISTERED_HOST] = %v, want [org-1]", got)
	}
	if len(claims.ProjectRoles) != 1 || claims.ProjectRoles[0] != "REGISTERED_HOST" {
		t.Errorf("ProjectRoles = %v", claims.ProjectRoles)
	}
}

func TestValidateRejectsAnotherTenantsAudience(t *testing.T) {
	// The instance is shared with DevSpot. A correctly-signed, unexpired token
	// for that tenant must not authenticate here.
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	token := s.mint(t, tokenOpts{audience: otherTenantAudience})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, ErrWrongTenant) {
		t.Fatalf("err = %v, want ErrWrongTenant", err)
	}
}

func TestValidateRejectsWrongIssuer(t *testing.T) {
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	token := s.mint(t, tokenOpts{issuer: "https://auth.attacker.example"})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, ErrWrongTenant) {
		t.Fatalf("err = %v, want ErrWrongTenant", err)
	}
}

func TestValidateRejectsExpiredAndNotYetValidTokens(t *testing.T) {
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	for name, opts := range map[string]tokenOpts{
		// Well outside the 30s default skew.
		"expired":       {expires: time.Now().Add(-10 * time.Minute)},
		"not yet valid": {notFor: 10 * time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), s.mint(t, opts))
			if !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("err = %v, want ErrTokenInvalid", err)
			}
		})
	}
}

func TestValidateRejectsForeignSignature(t *testing.T) {
	// Same kid, different private key: the signature must not verify.
	trusted := newSigner(t, "key-1")
	forger := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, trusted))

	_, err := v.Validate(context.Background(), forger.mint(t, tokenOpts{}))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestValidateRefreshesOnRotatedKey(t *testing.T) {
	// The gateway polled every 15 minutes and had no on-miss refresh, so a
	// rotation failed every request until the next tick.
	oldKey := newSigner(t, "key-1")
	js := newJWKSServer(t, oldKey)
	v := newTestValidator(t, js)

	newKey := newSigner(t, "key-2")
	js.setKeys(t, oldKey, newKey)

	before := js.fetches.Load()
	claims, err := v.Validate(context.Background(), newKey.mint(t, tokenOpts{}))
	if err != nil {
		t.Fatalf("Validate after rotation: %v", err)
	}
	if claims.Subject != testSubject {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if js.fetches.Load() <= before {
		t.Error("expected an on-demand JWKS refresh for the unknown kid")
	}
}

func TestValidateRejectsUnknownKeyAfterRefresh(t *testing.T) {
	trusted := newSigner(t, "key-1")
	stranger := newSigner(t, "key-unknown")
	v := newTestValidator(t, newJWKSServer(t, trusted))

	_, err := v.Validate(context.Background(), stranger.mint(t, tokenOpts{}))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestValidateRejectsNonZitadelSubject(t *testing.T) {
	// Zitadel subjects are decimal snowflakes; a UUID here means the token did
	// not come from where we think.
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	_, err := v.Validate(context.Background(), s.mint(t, tokenOpts{subject: testUserID}))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestValidateAllowsMissingUserMetadataOnFirstLogin(t *testing.T) {
	// Before provisioning writes app_uid the token is legitimate but carries no
	// user id. The caller detects the empty value and provisions.
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	claims, err := v.Validate(context.Background(), s.mint(t, tokenOpts{}))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.UserID != "" {
		t.Errorf("UserID = %q, want empty", claims.UserID)
	}
}

func TestValidateRejectsMalformedUserMetadata(t *testing.T) {
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	token := s.mint(t, tokenOpts{metadata: map[string]string{metadataKeyUserID: "not-a-uuid"}})

	_, err := v.Validate(context.Background(), token)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestValidateRejectsGarbage(t *testing.T) {
	s := newSigner(t, "key-1")
	v := newTestValidator(t, newJWKSServer(t, s))

	for name, tok := range map[string]string{
		"empty":     "",
		"not a jwt": "hello",
		"two parts": "aGVhZGVy.cGF5bG9hZA",
		"unsigned":  "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), tok); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// fakeKeyCache is an in-memory stand-in for Redis/Valkey.
type fakeKeyCache struct {
	mu    sync.Mutex
	items map[string][]byte
	puts  int
}

func newFakeKeyCache() *fakeKeyCache {
	return &fakeKeyCache{items: map[string][]byte{}}
}

func (f *fakeKeyCache) GetJWKS(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.items[key]
	if !ok {
		return nil, errors.New("miss")
	}
	return v, nil
}

func (f *fakeKeyCache) PutJWKS(_ context.Context, key string, raw []byte, _ time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[key] = raw
	f.puts++
	return nil
}

func TestNewSucceedsWhileTheIdPIsDown(t *testing.T) {
	// An identity provider is a shared dependency. If every service that
	// verifies its tokens refuses to boot while it is down, a brief IdP outage
	// becomes a total one as soon as anything restarts.
	js := newJWKSServer(t, newSigner(t, "key-1"))
	js.down.Store(true)

	v, err := New(Config{JWKSURL: js.URL, Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("New should not fail because the IdP is unreachable: %v", err)
	}
	if v.Ready() {
		t.Error("Ready() = true, want false with no keys")
	}
}

func TestValidateReportsDependencyFailureWhenNoKeysAreHeld(t *testing.T) {
	s := newSigner(t, "key-1")
	js := newJWKSServer(t, s)
	token := s.mint(t, tokenOpts{})
	js.down.Store(true)

	v, err := New(Config{JWKSURL: js.URL, Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Must be ErrKeysUnavailable, not ErrTokenInvalid: the token is fine, we
	// are not. Callers map this to 503 rather than 401.
	_, err = v.Validate(context.Background(), token)
	if !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("err = %v, want ErrKeysUnavailable", err)
	}
}

func TestKeyCacheLetsARestartSurviveAnOutage(t *testing.T) {
	s := newSigner(t, "key-1")
	js := newJWKSServer(t, s)
	kc := newFakeKeyCache()
	cfg := Config{JWKSURL: js.URL, Issuer: testIssuer, Audience: testAudience, KeyCache: kc}

	// First boot with the IdP up warms the cache.
	if _, err := New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
	if kc.puts == 0 {
		t.Fatal("a successful fetch should have been persisted")
	}

	// Now the IdP is down and the process restarts.
	js.down.Store(true)
	restarted, err := New(cfg)
	if err != nil {
		t.Fatalf("New after restart: %v", err)
	}
	if !restarted.Ready() {
		t.Fatal("Ready() = false; the cached key set should have been restored")
	}

	claims, err := restarted.Validate(context.Background(), s.mint(t, tokenOpts{}))
	if err != nil {
		t.Fatalf("Validate from cached keys: %v", err)
	}
	if claims.Subject != testSubject {
		t.Errorf("Subject = %q", claims.Subject)
	}
}

func TestValidatorRecoversWhenTheIdPReturns(t *testing.T) {
	s := newSigner(t, "key-1")
	js := newJWKSServer(t, s)
	js.down.Store(true)

	v, err := New(Config{JWKSURL: js.URL, Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if v.Ready() {
		t.Fatal("should not be ready yet")
	}

	js.down.Store(false)

	// No restart and no waiting for the poll: the next request refreshes.
	if _, err := v.Validate(context.Background(), s.mint(t, tokenOpts{})); err != nil {
		t.Fatalf("Validate after recovery: %v", err)
	}
	if !v.Ready() {
		t.Error("Ready() = false after a successful refresh")
	}
}

func TestCorruptCacheEntryIsIgnored(t *testing.T) {
	s := newSigner(t, "key-1")
	js := newJWKSServer(t, s)
	kc := newFakeKeyCache()
	cfg := Config{JWKSURL: js.URL, Issuer: testIssuer, Audience: testAudience, KeyCache: kc}
	_ = kc.PutJWKS(context.Background(), "jwks:"+js.URL, []byte("{not json"), time.Hour)

	js.down.Store(true)
	v, err := New(cfg)
	if err != nil {
		t.Fatalf("New should tolerate an unreadable cache entry: %v", err)
	}
	if v.Ready() {
		t.Error("Ready() = true from an unparseable cache entry")
	}
}
