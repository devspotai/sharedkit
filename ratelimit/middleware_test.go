package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

// keyFor runs fn inside a gin engine configured to trust only 10.0.0.1, so
// ClientIP behaves as it does behind a correctly configured proxy.
func keyFor(t *testing.T, fn func(*gin.Context) string, prepare func(*gin.Context), remote string, headers map[string]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	if err := r.SetTrustedProxies([]string{"10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	var key string
	r.GET("/", func(c *gin.Context) {
		if prepare != nil {
			prepare(c)
		}
		key = fn(c)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote + ":1234"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	r.ServeHTTP(httptest.NewRecorder(), req)
	return key
}

func TestDefaultKeyIgnoresHeadersFromUntrustedClients(t *testing.T) {
	// The key used to be the raw X-Forwarded-For / X-Real-IP value, so a
	// client rotating the header got a fresh bucket on every request.
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP"} {
		got := keyFor(t, DefaultKeyFunc, nil, "203.0.113.7", map[string]string{h: "1.2.3.4"})
		if got != "ip:203.0.113.7" {
			t.Errorf("%s from a direct client: key = %q, want the socket address", h, got)
		}
	}
}

func TestDefaultKeyUsesForwardedIPFromTrustedProxy(t *testing.T) {
	got := keyFor(t, DefaultKeyFunc, nil, "10.0.0.1", map[string]string{"X-Forwarded-For": "1.2.3.4"})
	if got != "ip:1.2.3.4" {
		t.Errorf("key = %q, want the forwarded client IP", got)
	}
}

func TestDefaultKeyIgnoresSpoofedHopsBeforeTheProxy(t *testing.T) {
	// The proxy appends the real client; whatever the client sent sits to the left.
	got := keyFor(t, DefaultKeyFunc, nil, "10.0.0.1", map[string]string{"X-Forwarded-For": "6.6.6.6, 1.2.3.4"})
	if got != "ip:1.2.3.4" {
		t.Errorf("key = %q, want the hop the proxy appended", got)
	}
}

func TestUserKeyUsesTheAuthenticatedUser(t *testing.T) {
	// UserKeyFunc read c.Get("user_id"), which nothing sets, so "per user"
	// limits were always per (spoofable) IP.
	setUser := func(c *gin.Context) {
		c.Set(models.UserContextKey, &models.UserContext{UserID: "u-42"})
	}
	if got := keyFor(t, UserKeyFunc, setUser, "203.0.113.7", nil); got != "user:u-42" {
		t.Errorf("key = %q, want user:u-42", got)
	}
	if got := keyFor(t, UserKeyFunc, nil, "203.0.113.7", nil); got != "ip:203.0.113.7" {
		t.Errorf("anonymous key = %q, want the IP fallback", got)
	}
}
