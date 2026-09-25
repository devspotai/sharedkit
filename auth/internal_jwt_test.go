package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "test-secret-at-least-32-bytes-long!!"

func sign(t *testing.T, method jwt.SigningMethod, key any, claims jwt.RegisteredClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, InternalJWTClaims{UserID: "u1", RegisteredClaims: claims}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validClaims() jwt.RegisteredClaims {
	now := time.Now()
	return jwt.RegisteredClaims{
		ID:        "jti-1",
		Issuer:    "traefik-auth-enricher",
		Audience:  jwt.ClaimStrings{"internal-services"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
	}
}

func TestParseTokenAcceptsItsOwnTokens(t *testing.T) {
	j := NewInternalJWT(DefaultInternalJWTConfig(testSecret))
	tok, err := j.CreateToken(CreateTokenInput{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := j.ParseToken(tok)
	if err != nil {
		t.Fatalf("own token rejected: %v", err)
	}
	if claims.UserID != "u1" || claims.ID == "" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestParseTokenRejectsTokensOutsideItsTrustBoundary(t *testing.T) {
	// ParseToken only checked the signature, so tokens with no exp never
	// expired and tokens minted for another issuer or audience were accepted.
	j := NewInternalJWT(DefaultInternalJWTConfig(testSecret))
	cases := map[string]func(*jwt.RegisteredClaims){
		"no exp":         func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil },
		"expired":        func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) },
		"wrong issuer":   func(c *jwt.RegisteredClaims) { c.Issuer = "someone-else" },
		"no issuer":      func(c *jwt.RegisteredClaims) { c.Issuer = "" },
		"wrong audience": func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{"billing"} },
		"no audience":    func(c *jwt.RegisteredClaims) { c.Audience = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validClaims()
			mutate(&c)
			if _, err := j.ParseToken(sign(t, jwt.SigningMethodHS256, []byte(testSecret), c)); err == nil {
				t.Fatal("token accepted")
			}
		})
	}
}

func TestParseTokenRejectsOtherAlgorithms(t *testing.T) {
	j := NewInternalJWT(DefaultInternalJWTConfig(testSecret))
	if _, err := j.ParseToken(sign(t, jwt.SigningMethodHS512, []byte(testSecret), validClaims())); err == nil {
		t.Error("HS512 token accepted")
	}
	if _, err := j.ParseToken(sign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, validClaims())); err == nil {
		t.Error("alg=none token accepted")
	}
}

func TestParseTokenAcceptsAnyConfiguredAudience(t *testing.T) {
	cfg := DefaultInternalJWTConfig(testSecret)
	cfg.Audience = []string{"stays-experiences-service", "user-service"}
	j := NewInternalJWT(cfg)
	c := validClaims()
	c.Audience = jwt.ClaimStrings{"user-service"}
	if _, err := j.ParseToken(sign(t, jwt.SigningMethodHS256, []byte(testSecret), c)); err != nil {
		t.Errorf("token for a configured audience rejected: %v", err)
	}
}
