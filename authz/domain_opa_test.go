package authz

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

// A resource-scoped policy of the shape a consumer writes: a targeted request
// is allowed only for a listed stay; an untargeted read (a list) is allowed and
// left to the handler to filter.
const testStayPolicy = `
package test_stays_authz
import rego.v1
default allow := false
allow if { input.request.resource_id != ""; input.request.resource_id in input.company_resources.stay_ids }
allow if { input.request.action == "read"; input.request.resource_id == "" }
`

const (
	companyA = "company-a"
	companyB = "company-b"
	stay1    = "stay-1"
	stay2    = "stay-2"
	stayB    = "stay-b"
)

// specificUser holds ADMIN_SPECIFIC_STAYS in company A (stay-1 only) and in
// company B (stay-b only) — enough to tell a cross-company leak from a pass.
func specificUser() map[string]CompanyRole {
	return map[string]CompanyRole{
		companyA: {Roles: []string{models.CompanyRoleAdminSpecificStay}, HasGranularPermissions: true, StayIDs: []string{stay1}},
		companyB: {Roles: []string{models.CompanyRoleAdminSpecificStay}, HasGranularPermissions: true, StayIDs: []string{stayB}},
	}
}

func newTestEngine(t *testing.T) *DomainOPAEngine {
	t.Helper()
	e, err := NewDomainOPAEngine(DomainOPAConfig{
		Policy:          testStayPolicy,
		PackageName:     "test_stays_authz",
		ResourceIDParam: "id",
	})
	if err != nil {
		t.Fatalf("NewDomainOPAEngine: %v", err)
	}
	return e
}

// tier1 stands in for authentication, role loading and CompanyOPAEngine: it
// loads roles through ApplyCompanyRoles (the real path) and records what tier 1
// would — the authorised company and whether a domain check is required.
func tier1(roles map[string]CompanyRole, requiresCheck bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(models.UserContextKey, &models.UserContext{UserID: "u1"})
		if !ApplyCompanyRoles(c, staticRoles(roles, nil)) {
			return
		}
		c.Set("company_id", c.Param("companyId"))
		c.Set(OPARequiresDomainCheckKey, requiresCheck)
		c.Next()
	}
}

func serve(t *testing.T, roles map[string]CompanyRole, requiresCheck bool, method, path string) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/companies/:companyId/stays", tier1(roles, requiresCheck), newTestEngine(t).AuthorizeDomainResource())
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	g.GET("", ok)
	g.GET("/:id", ok)
	g.PUT("/:id", ok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

func TestDomainResource_SpecificUser(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"assigned stay, read", http.MethodGet, "/companies/company-a/stays/stay-1", http.StatusOK},
		{"assigned stay, update", http.MethodPut, "/companies/company-a/stays/stay-1", http.StatusOK},
		{"unassigned stay in same company", http.MethodGet, "/companies/company-a/stays/stay-2", http.StatusForbidden},
		{"unassigned stay, update", http.MethodPut, "/companies/company-a/stays/stay-2", http.StatusForbidden},
		// The grant on stay-b belongs to company B. Naming it under company A
		// must not borrow it: only the authorised company's resources count.
		{"another company's stay under this company", http.MethodGet, "/companies/company-a/stays/stay-b", http.StatusForbidden},
		{"list (no target) left to the handler", http.MethodGet, "/companies/company-a/stays", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serve(t, specificUser(), true, tc.method, tc.path); got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestDomainResource_NoResourcesMeansNone(t *testing.T) {
	// A granular role whose entry carries no ids — e.g. written before the
	// fields existed — grants nothing at resource level.
	roles := map[string]CompanyRole{
		companyA: {Roles: []string{models.CompanyRoleAdminSpecificStay}, HasGranularPermissions: true},
	}
	if got := serve(t, roles, true, http.MethodGet, "/companies/company-a/stays/stay-1"); got != http.StatusForbidden {
		t.Errorf("got %d, want 403", got)
	}
}

func TestDomainResource_SkippedWhenTier1DidNotFlag(t *testing.T) {
	owner := map[string]CompanyRole{companyA: {Roles: []string{models.CompanyRoleOwner}}}
	if got := serve(t, owner, false, http.MethodPut, "/companies/company-a/stays/stay-2"); got != http.StatusOK {
		t.Errorf("got %d, want 200 (no domain check for OWNER)", got)
	}
}

func TestAuthorizeResource(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newTestEngine(t)

	check := func(roles map[string]CompanyRole, requiresCheck bool, target string) (bool, error) {
		var allowed bool
		var err error
		r := gin.New()
		r.PUT("/companies/:companyId/packages/:id", tier1(roles, requiresCheck), func(c *gin.Context) {
			// The handler has loaded the package and resolved its stay.
			allowed, err = e.AuthorizeResource(c, target)
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/companies/company-a/packages/pkg-1", nil))
		return allowed, err
	}

	if ok, err := check(specificUser(), true, stay1); err != nil || !ok {
		t.Errorf("assigned stay: got %v, %v; want true", ok, err)
	}
	if ok, err := check(specificUser(), true, stay2); err != nil || ok {
		t.Errorf("unassigned stay: got %v, %v; want false", ok, err)
	}
	if ok, err := check(specificUser(), true, stayB); err != nil || ok {
		t.Errorf("another company's stay: got %v, %v; want false", ok, err)
	}
	owner := map[string]CompanyRole{companyA: {Roles: []string{models.CompanyRoleOwner}}}
	if ok, err := check(owner, false, stay2); err != nil || !ok {
		t.Errorf("unflagged request: got %v, %v; want true without evaluating", ok, err)
	}
}

func TestAuthorizeResource_NoUserIsDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newTestEngine(t)
	var allowed bool
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		c.Set(OPARequiresDomainCheckKey, true)
		allowed, _ = e.AuthorizeResource(c, stay1)
	})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	if allowed {
		t.Error("allowed without a user context")
	}
}

func TestRestrictedResources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	run := func(roles map[string]CompanyRole, requiresCheck bool) (models.CompanyResources, bool) {
		var res models.CompanyResources
		var restricted bool
		r := gin.New()
		r.GET("/companies/:companyId/stays", tier1(roles, requiresCheck), func(c *gin.Context) {
			res, restricted = RestrictedResources(c)
		})
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/companies/company-a/stays", nil))
		return res, restricted
	}

	res, restricted := run(specificUser(), true)
	if !restricted || !slices.Equal(res.StayIDs, []string{stay1}) {
		t.Errorf("specific user: got %v restricted=%v; want [stay-1] restricted", res.StayIDs, restricted)
	}
	owner := map[string]CompanyRole{companyA: {Roles: []string{models.CompanyRoleOwner}}}
	if _, restricted := run(owner, false); restricted {
		t.Error("owner reported as restricted")
	}
}

func TestCompanyRole_JSONCompatibility(t *testing.T) {
	// An entry written by a version without resource ids still decodes, and
	// decodes to "no resources".
	var old map[string]CompanyRole
	if err := json.Unmarshal([]byte(`{"company-a":{"roles":["ADMIN_SPECIFIC_STAYS"],"has_granular_perms":true}}`), &old); err != nil {
		t.Fatalf("decode old entry: %v", err)
	}
	if len(old[companyA].StayIDs) != 0 {
		t.Errorf("old entry decoded with stay ids: %v", old[companyA].StayIDs)
	}

	// New fields round-trip, and are omitted when empty so entries for
	// non-granular users do not grow.
	b, _ := json.Marshal(specificUser()[companyA])
	var back CompanyRole
	if err := json.Unmarshal(b, &back); err != nil || !slices.Equal(back.StayIDs, []string{stay1}) {
		t.Errorf("round trip: %s -> %+v (%v)", b, back, err)
	}
	if b, _ := json.Marshal(CompanyRole{Roles: []string{models.CompanyRoleOwner}}); string(b) != `{"roles":["OWNER"],"has_granular_perms":false}` {
		t.Errorf("empty resources not omitted: %s", b)
	}
}

func TestApplyCompanyRoles_Resources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	uc := &models.UserContext{
		UserID: "u1",
		// Stale resources from an earlier load must not survive a reload.
		CompaniesResources: map[string]models.CompanyResources{"stale": {StayIDs: []string{"old"}}},
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	c.Set(models.UserContextKey, uc)

	roles := specificUser()
	roles["company-c"] = CompanyRole{Roles: []string{models.CompanyRoleOwner}}
	if !ApplyCompanyRoles(c, staticRoles(roles, nil)) {
		t.Fatal("ApplyCompanyRoles aborted")
	}
	if _, ok := uc.CompaniesResources["stale"]; ok {
		t.Error("stale resources survived reload")
	}
	if got := uc.GetCompanyResources(companyA).StayIDs; !slices.Equal(got, []string{stay1}) {
		t.Errorf("company A stays = %v, want [stay-1]", got)
	}
	if _, ok := uc.CompaniesResources["company-c"]; ok {
		t.Error("company without resources got an entry")
	}
}
