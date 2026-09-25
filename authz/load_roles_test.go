package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/config"
	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

// loadRoles mounts LoadCompanyRoles after a stand-in authenticator (nil uc =
// unauthenticated) and returns the status and the principal the handler saw.
func loadRoles(t *testing.T, uc *models.UserContext, src CompanyRoleSource) (int, *models.UserContext) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var seen *models.UserContext
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if uc != nil {
			c.Set(models.UserContextKey, uc)
		}
	})
	r.Use(LoadCompanyRoles(src))
	r.GET("/", func(c *gin.Context) {
		seen, _ = models.GetUserContext(c)
		c.Status(http.StatusOK)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	return w.Code, seen
}

func staticRoles(roles map[string]CompanyRole, err error) CompanyRoleSource {
	return CompanyRoleSourceFunc(func(context.Context, string) (map[string]CompanyRole, error) { return roles, err })
}

func TestLoadCompanyRolesFillsThePrincipal(t *testing.T) {
	src := staticRoles(map[string]CompanyRole{"c1": NewCompanyRole([]string{"OWNER"})}, nil)
	code, uc := loadRoles(t, &models.UserContext{UserID: "u1"}, src)
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !uc.HasAnyOfCompanyRoles("c1", "OWNER") {
		t.Errorf("CompaniesRoles = %v, want c1: OWNER", uc.CompaniesRoles)
	}
}

func TestLoadCompanyRolesLeavesNilForNoCompanies(t *testing.T) {
	_, uc := loadRoles(t, &models.UserContext{UserID: "u1"}, staticRoles(nil, nil))
	if uc.CompaniesRoles != nil {
		t.Errorf("CompaniesRoles = %v, want nil", *uc.CompaniesRoles)
	}
}

func TestLoadCompanyRolesFailsClosedWith503(t *testing.T) {
	// A roles outage must not look like "no companies" and silently deny, nor
	// let the request through undecided.
	code, _ := loadRoles(t, &models.UserContext{UserID: "u1"}, staticRoles(nil, errors.New("db down")))
	if code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", code)
	}
}

func TestLoadCompanyRolesSkipsUnauthenticatedRequests(t *testing.T) {
	called := false
	src := CompanyRoleSourceFunc(func(context.Context, string) (map[string]CompanyRole, error) {
		called = true
		return nil, nil
	})
	if code, _ := loadRoles(t, nil, src); code != http.StatusOK {
		t.Errorf("status = %d, want 200", code)
	}
	if called {
		t.Error("source queried for a request with no principal")
	}
}

func unreachableCache() *cache.RedisCache {
	return cache.NewRedisCacheFromConfig(&config.RedisConfig{URL: "127.0.0.1:1", MaxRetries: -1})
}

func TestCachedRolesFallsBackToSourceOnMiss(t *testing.T) {
	src := staticRoles(map[string]CompanyRole{"c1": NewCompanyRole([]string{"STAFF"})}, nil)
	code, uc := loadRoles(t, &models.UserContext{UserID: "u1"}, CachedRoles(src, unreachableCache(), 0))
	if code != http.StatusOK || !uc.HasCompanyAccess("c1") {
		t.Errorf("status %d, CompaniesRoles %v", code, uc.CompaniesRoles)
	}
}

func TestCacheOnlyRolesDenyOnMiss(t *testing.T) {
	// With no source, a miss means no company access (fail closed), not an error.
	code, uc := loadRoles(t, &models.UserContext{UserID: "u1"}, CachedRoles(nil, unreachableCache(), 0))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if uc.CompaniesRoles != nil {
		t.Errorf("CompaniesRoles = %v, want nil", *uc.CompaniesRoles)
	}
}
