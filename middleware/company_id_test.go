package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

// companyRouter mounts guard on route for a user who belongs only to
// "mine". The handler reads :company_id, as a handler on such a route would.
func companyRouter(route string, guard gin.HandlerFunc) (*gin.Engine, *string) {
	gin.SetMode(gin.TestMode)
	acted := new(string)
	roles := models.CompanyPermissionsForAuthUserMap{"mine": {"OWNER"}}
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(models.UserContextKey, &models.UserContext{UserID: "u1", CompaniesRoles: &roles})
	})
	r.GET(route, guard, func(c *gin.Context) {
		*acted = c.Param("company_id")
		c.Status(http.StatusOK)
	})
	return r, acted
}

func TestCompanyGuardsRejectQueryOverridingThePath(t *testing.T) {
	// The guards read ?companyId= before :company_id, so a member of "mine"
	// passed the check while the handler acted on "victim".
	guards := map[string]gin.HandlerFunc{
		"RequireCompanyAccess": RequireCompanyAccess(),
		"RequireCompanyRole":   RequireCompanyRole("OWNER"),
	}
	for name, guard := range guards {
		t.Run(name, func(t *testing.T) {
			r, acted := companyRouter("/companies/:company_id/stays", guard)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/companies/victim/stays?companyId=mine", nil))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if *acted != "" {
				t.Fatalf("handler ran against company %q", *acted)
			}
		})
	}
}

func TestCompanyGuardsCheckThePathCompany(t *testing.T) {
	r, _ := companyRouter("/companies/:company_id/stays", RequireCompanyAccess())
	for path, want := range map[string]int{
		"/companies/mine/stays":                 http.StatusOK,
		"/companies/mine/stays?companyId=mine":  http.StatusOK,
		"/companies/victim/stays":               http.StatusForbidden,
		"/companies/victim/stays?companyId=bad": http.StatusBadRequest,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s: status = %d, want %d", path, w.Code, want)
		}
	}
}

func TestResolveCompanyIDUsesQueryOnlyWithoutAPathSegment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var got string
	var gotErr error
	r := gin.New()
	r.GET("/stays", func(c *gin.Context) { got, gotErr = resolveCompanyID(c) })

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/stays?companyId=mine", nil))
	if gotErr != nil || got != "mine" {
		t.Errorf("query fallback: got (%q, %v), want (\"mine\", nil)", got, gotErr)
	}

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/stays", nil))
	if gotErr != errCompanyIDMissing {
		t.Errorf("no company: err = %v, want errCompanyIDMissing", gotErr)
	}
}
