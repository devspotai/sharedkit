package authn

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

func serve(t *testing.T, a Authenticator, opts Options, route, path string) (*httptest.ResponseRecorder, *models.UserContext) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var seen *models.UserContext
	r := gin.New()
	r.Use(Middleware(a, opts))
	r.GET(route, func(c *gin.Context) {
		seen, _ = models.GetUserContext(c)
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w, seen
}

func fails(err error) Authenticator {
	return AuthenticatorFunc(func(*http.Request) (*models.UserContext, error) { return nil, err })
}

func TestMiddlewareSetsThePrincipal(t *testing.T) {
	a := AuthenticatorFunc(func(*http.Request) (*models.UserContext, error) {
		return &models.UserContext{UserID: "u1"}, nil
	})
	w, uc := serve(t, a, Options{}, "/x", "/x")
	if w.Code != http.StatusOK || uc == nil || uc.UserID != "u1" {
		t.Fatalf("status %d, principal %+v", w.Code, uc)
	}
}

func TestMiddlewareMapsErrorsToStatus(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"bad credential":  {errors.New("bad signature"), http.StatusUnauthorized},
		"idp unavailable": {errors.Join(ErrUnavailable, errors.New("jwks down")), http.StatusServiceUnavailable},
		"custom":          {&Error{Status: http.StatusForbidden, Message: "blocked"}, http.StatusForbidden},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, uc := serve(t, fails(tc.err), Options{}, "/x", "/x")
			if w.Code != tc.want {
				t.Errorf("status = %d, want %d", w.Code, tc.want)
			}
			if uc != nil {
				t.Error("handler ran with a principal after a failed authentication")
			}
		})
	}
}

func TestMiddlewareDoesNotLeakTheFailureReason(t *testing.T) {
	w, _ := serve(t, fails(errors.New("issuer mismatch: secret-detail")), Options{}, "/x", "/x")
	if body := w.Body.String(); strings.Contains(body, "secret-detail") {
		t.Errorf("response leaks the validation error: %s", body)
	}
}

func TestCustomErrorSetsHeaders(t *testing.T) {
	err := &Error{Status: http.StatusUnauthorized, Message: "refresh", Headers: map[string]string{"X-Retry": "true"}}
	w, _ := serve(t, fails(err), Options{}, "/x", "/x")
	if w.Header().Get("X-Retry") != "true" {
		t.Error("custom header not set")
	}
}

func TestAuthenticatorReturningNoPrincipalIsRejected(t *testing.T) {
	a := AuthenticatorFunc(func(*http.Request) (*models.UserContext, error) { return nil, nil })
	if w, _ := serve(t, a, Options{}, "/x", "/x"); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestPublicPathsMatchRoutePatterns(t *testing.T) {
	opts := Options{PublicPaths: []string{"/facts/:country", "/health"}}
	for _, tc := range []struct{ route, path string }{
		{"/facts/:country", "/facts/PT"},
		{"/health", "/health"},
	} {
		if w, _ := serve(t, fails(errors.New("no token")), opts, tc.route, tc.path); w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tc.path, w.Code)
		}
	}
	if w, _ := serve(t, fails(errors.New("no token")), opts, "/private", "/private"); w.Code != http.StatusUnauthorized {
		t.Errorf("/private: status = %d, want 401", w.Code)
	}
}
