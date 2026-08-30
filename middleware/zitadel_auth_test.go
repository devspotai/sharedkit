package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/devspotai/sharedkit/auth"
	"github.com/devspotai/sharedkit/auth/zitadel"
	"github.com/devspotai/sharedkit/models"
)

func init() { gin.SetMode(gin.TestMode) }

type stubValidator struct {
	claims *zitadel.Claims
	err    error
}

func (s stubValidator) Validate(context.Context, string) (*zitadel.Claims, error) {
	return s.claims, s.err
}

type stubUsers struct {
	resolveID  string
	resolveErr error
	resolved   int

	roles    map[string]auth.CompanyRole
	rolesErr error
}

func (s *stubUsers) ResolveUserID(context.Context, string) (string, bool, error) {
	s.resolved++
	return s.resolveID, true, s.resolveErr
}

func (s *stubUsers) CompanyRoles(context.Context, string) (map[string]auth.CompanyRole, error) {
	return s.roles, s.rolesErr
}

const (
	bearer   = "Bearer aaaa.bbbb.cccc"
	testUser = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"
)

// run wires the middleware into a router and issues one GET, returning the
// recorder and whatever UserContext the handler saw.
func run(t *testing.T, cfg ZitadelAuthConfig, path, authHeader string) (*httptest.ResponseRecorder, *models.UserContext) {
	t.Helper()

	z, err := NewZitadelAuth(cfg)
	if err != nil {
		t.Fatalf("NewZitadelAuth: %v", err)
	}

	var seen *models.UserContext
	r := gin.New()
	r.Use(z.Middleware())
	r.GET(path, func(c *gin.Context) {
		if uc, ok := models.GetUserContext(c); ok {
			seen = uc
		}
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w, seen
}

func validClaims() *zitadel.Claims {
	return &zitadel.Claims{
		Subject:       "378124744102248456",
		UserID:        testUser,
		Email:         "traveller@example.com",
		EmailVerified: true,
		ProjectRoles:  []string{"REGISTERED_HOST"},
	}
}

func TestNewZitadelAuthRequiresValidatorAndUsers(t *testing.T) {
	if _, err := NewZitadelAuth(ZitadelAuthConfig{Users: &stubUsers{}}); err == nil {
		t.Error("expected an error without a Validator")
	}
	if _, err := NewZitadelAuth(ZitadelAuthConfig{Validator: stubValidator{}}); err == nil {
		t.Error("expected an error without a Users provider")
	}
}

func TestAuthenticatedRequestGetsUserContext(t *testing.T) {
	users := &stubUsers{roles: map[string]auth.CompanyRole{
		"company-1": auth.NewCompanyRole([]string{"OWNER"}),
	}}

	w, uc := run(t, ZitadelAuthConfig{
		Validator: stubValidator{claims: validClaims()},
		Users:     users,
	}, "/api/stays", bearer)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", w.Code, w.Body)
	}
	if uc == nil {
		t.Fatal("handler saw no UserContext")
	}
	if uc.UserID != testUser {
		t.Errorf("UserID = %q, want %q", uc.UserID, testUser)
	}
	if uc.Subject != "378124744102248456" {
		t.Errorf("Subject = %q", uc.Subject)
	}
	// The internal-JWT path hardcodes EmailVerified to true; this one carries
	// the real claim.
	if !uc.EmailVerified {
		t.Error("EmailVerified = false, want true")
	}
	// InternalJWTAuth leaves Roles empty, which quietly disables RequireRole.
	if len(uc.Roles) != 1 || uc.Roles[0] != "REGISTERED_HOST" {
		t.Errorf("Roles = %v, want [REGISTERED_HOST]", uc.Roles)
	}
	if uc.CompaniesRoles == nil {
		t.Fatal("CompaniesRoles is nil")
	}
	if got := (*uc.CompaniesRoles)["company-1"]; len(got) != 1 || got[0] != "OWNER" {
		t.Errorf("company-1 roles = %v, want [OWNER]", got)
	}
}

func TestFirstLoginProvisionsAndSignalsRefresh(t *testing.T) {
	// The claims carry no app_uid yet. The user must be provisioned and the
	// client told to fetch a fresh token — the old header never survived
	// Traefik, so the browser could not act on it.
	claims := validClaims()
	claims.UserID = ""
	users := &stubUsers{resolveID: testUser}

	w, uc := run(t, ZitadelAuthConfig{
		Validator: stubValidator{claims: claims},
		Users:     users,
	}, "/api/stays", bearer)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if got := w.Header().Get(TokenRefreshRequiredHeader); got != "true" {
		t.Errorf("%s = %q, want \"true\"", TokenRefreshRequiredHeader, got)
	}
	if users.resolved != 1 {
		t.Errorf("ResolveUserID called %d times, want 1", users.resolved)
	}
	if uc != nil {
		t.Error("handler should not have run")
	}
}

func TestPublicPathsSkipAuthentication(t *testing.T) {
	w, uc := run(t, ZitadelAuthConfig{
		Validator:   stubValidator{err: errors.New("must not be called")},
		Users:       &stubUsers{},
		PublicPaths: []string{"/health"},
	}, "/health", "")

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if uc != nil {
		t.Error("public path should not produce a UserContext")
	}
}

func TestParameterisedPublicPathsAreActuallyPublic(t *testing.T) {
	// Public paths are configured as route patterns. Matching only the request
	// path silently authenticates every parameterised public route, because
	// "/api/v1/destinations/PT/facts" is not in the list and never will be.
	z, err := NewZitadelAuth(ZitadelAuthConfig{
		Validator:   stubValidator{err: errors.New("must not be called for a public path")},
		Users:       &stubUsers{},
		PublicPaths: []string{"/api/v1/destinations/:destination/facts", "/api/v1/countries"},
	})
	if err != nil {
		t.Fatalf("NewZitadelAuth: %v", err)
	}

	r := gin.New()
	r.Use(z.Middleware())
	r.GET("/api/v1/destinations/:destination/facts", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/countries", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/v1/users/me", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/v1/destinations/PT/facts", http.StatusOK}, // the one that regressed
		{"/api/v1/countries", http.StatusOK},             // unparameterised, always worked
		{"/api/v1/users/me", http.StatusUnauthorized},    // not public, must still be guarded
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, w.Code, tc.want)
		}
	}
}

func TestMalformedAuthorizationHeaderIsRejected(t *testing.T) {
	for name, header := range map[string]string{
		"absent":     "",
		"not bearer": "Basic dXNlcjpwYXNz",
		"not a jwt":  "Bearer hello",
		"two parts":  "Bearer aaaa.bbbb",
	} {
		t.Run(name, func(t *testing.T) {
			w, _ := run(t, ZitadelAuthConfig{
				Validator: stubValidator{claims: validClaims()},
				Users:     &stubUsers{},
			}, "/api/stays", header)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", w.Code)
			}
		})
	}
}

func TestDependencyFailuresReturn503NotUnauthorized(t *testing.T) {
	// The gateway collapsed every failure into 401, so an IdP or database
	// outage was indistinguishable from a forged token.
	t.Run("jwks unavailable", func(t *testing.T) {
		w, _ := run(t, ZitadelAuthConfig{
			Validator: stubValidator{err: zitadel.ErrKeysUnavailable},
			Users:     &stubUsers{},
		}, "/api/stays", bearer)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
	})

	t.Run("roles lookup fails", func(t *testing.T) {
		w, _ := run(t, ZitadelAuthConfig{
			Validator: stubValidator{claims: validClaims()},
			Users:     &stubUsers{rolesErr: errors.New("database down")},
		}, "/api/stays", bearer)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
	})

	t.Run("provisioning fails", func(t *testing.T) {
		claims := validClaims()
		claims.UserID = ""
		w, _ := run(t, ZitadelAuthConfig{
			Validator: stubValidator{claims: claims},
			Users:     &stubUsers{resolveErr: errors.New("database down")},
		}, "/api/stays", bearer)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
	})
}

func TestInvalidTokenIsUnauthorized(t *testing.T) {
	w, _ := run(t, ZitadelAuthConfig{
		Validator: stubValidator{err: zitadel.ErrWrongTenant},
		Users:     &stubUsers{},
	}, "/api/stays", bearer)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	// The reason must not leak: a caller learning "wrong audience" learns the
	// token was otherwise valid.
	if body := w.Body.String(); strings.Contains(body, "tenant") || strings.Contains(body, "audience") {
		t.Errorf("response leaks the failure reason: %s", body)
	}
}

func TestUserWithNoCompaniesGetsNilCompaniesRoles(t *testing.T) {
	w, uc := run(t, ZitadelAuthConfig{
		Validator: stubValidator{claims: validClaims()},
		Users:     &stubUsers{roles: map[string]auth.CompanyRole{}},
	}, "/api/stays", bearer)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if uc.CompaniesRoles != nil {
		t.Errorf("CompaniesRoles = %v, want nil", *uc.CompaniesRoles)
	}
	if uc.HasCompanyAccess("company-1") {
		t.Error("HasCompanyAccess should be false")
	}
}

func TestExtractBearer(t *testing.T) {
	if _, err := ExtractBearer("Bearer aaaa.bbbb.cccc"); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	for name, header := range map[string]string{
		"empty":      "",
		"lowercase":  "bearer aaaa.bbbb.cccc",
		"no prefix":  "aaaa.bbbb.cccc",
		"four parts": "Bearer a.b.c.d",
		"oversized":  "Bearer " + strings.Repeat("a", 9000) + ".b.c",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExtractBearer(header); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
