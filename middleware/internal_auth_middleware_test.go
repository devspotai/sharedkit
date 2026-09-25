package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devspotai/sharedkit/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

const internalSecret = "test-secret-at-least-32-bytes-long!!"

func TestInternalJWTAuthRejectsTokenWithoutExpInsteadOfPanicking(t *testing.T) {
	// With a JTI tracker configured, a validly signed token that had a jti but
	// no exp reached claims.ExpiresAt.Time and panicked on a nil pointer.
	gin.SetMode(gin.TestMode)
	// Nothing listens here: the token must be rejected before Redis is used.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })

	m := NewInternalJWTAuthWithConfig(InternalJWTAuthConfig{
		JWTSecret:  internalSecret,
		JTITracker: auth.NewJTITracker(rdb, auth.JTITrackerConfig{}),
	})
	r := gin.New()
	r.GET("/", m.MiddlewareRequired(), func(c *gin.Context) { c.Status(http.StatusOK) })

	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.InternalJWTClaims{
		UserID: "u1",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       "jti-1",
			Issuer:   "traefik-auth-enricher",
			Audience: jwt.ClaimStrings{"internal-services"},
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}).SignedString([]byte(internalSecret))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Internal-JWT", tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestInternalJWTAuthHonoursConfiguredAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	aud := []string{"user-service"}
	m := NewInternalJWTAuthWithConfig(InternalJWTAuthConfig{JWTSecret: internalSecret, Audience: aud})
	r := gin.New()
	r.GET("/", m.MiddlewareRequired(), func(c *gin.Context) { c.Status(http.StatusOK) })

	cfg := auth.DefaultInternalJWTConfig(internalSecret)
	cfg.Audience = aud
	tok, err := auth.NewInternalJWT(cfg).CreateToken(auth.CreateTokenInput{UserID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Internal-JWT", tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
