package middleware

import (
	"encoding/json"
	"testing"

	"github.com/devspotai/sharedkit/auth"
	"github.com/devspotai/sharedkit/models"
)

// warmerOutput is byte-for-byte what the permission warmer writes to Redis. If
// this stops decoding, the middleware silently stops enriching — which is
// exactly how the previous version failed.
const warmerOutput = `{
  "user_id": "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b",
  "email": "traveller@example.com",
  "keycloak_id": "378124744102248456",
  "company_roles": {
    "company-1": {"roles": ["OWNER"], "has_granular_perms": false},
    "company-2": {"roles": ["ADMIN_SPECIFIC_STAYS"], "has_granular_perms": true}
  },
  "cached_at": 1756377600
}`

func TestDefaultKeyMatchesWhatWritersUse(t *testing.T) {
	// The middleware read "user:<id>:company_roles" while every writer used
	// "user:<id>:company-roles", so it never found anything.
	cfg := RolesCacheConfig{}
	if cfg.CacheKeyFunc == nil {
		cfg.CacheKeyFunc = auth.RolesCacheKey
	}
	got := cfg.CacheKeyFunc("abc")
	if want := auth.RolesCacheKey("abc"); got != want {
		t.Fatalf("default key = %q, want %q", got, want)
	}
	if got != "user:abc:company-roles" {
		t.Errorf("default key = %q, want the hyphenated form writers emit", got)
	}
}

func TestStoredEntryDecodes(t *testing.T) {
	// The middleware decoded into map[string][]string, so "user_id": "..." was
	// asked to become a []string and the whole entry failed.
	var entry auth.RolesCacheEntry
	if err := json.Unmarshal([]byte(warmerOutput), &entry); err != nil {
		t.Fatalf("the warmer's own output must decode: %v", err)
	}
	if entry.UserID != "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b" {
		t.Errorf("UserID = %q", entry.UserID)
	}
	if len(entry.CompanyRoles) != 2 {
		t.Fatalf("CompanyRoles = %v, want 2 companies", entry.CompanyRoles)
	}
	if !entry.CompanyRoles["company-2"].HasGranularPermissions {
		t.Error("company-2 should carry the granular flag, which decides whether a resource lookup is needed")
	}
}

func TestDecodingIntoTheOldShapeFails(t *testing.T) {
	// Guards the regression directly: the previous target type cannot hold this
	// entry, so anything reverting to it would silently miss again.
	var old models.CompanyPermissionsForAuthUserMap
	if err := json.Unmarshal([]byte(warmerOutput), &old); err == nil {
		t.Fatal("expected the bare role map to fail on the stored entry")
	}
}

func TestEntryConvertsToUserContextShape(t *testing.T) {
	var entry auth.RolesCacheEntry
	if err := json.Unmarshal([]byte(warmerOutput), &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	roles := make(models.CompanyPermissionsForAuthUserMap, len(entry.CompanyRoles))
	for companyID, cr := range entry.CompanyRoles {
		roles[companyID] = cr.Roles
	}

	uc := &models.UserContext{UserID: entry.UserID, CompaniesRoles: &roles}
	if !uc.HasCompanyAccess("company-1") {
		t.Error("HasCompanyAccess(company-1) = false")
	}
	if !uc.HasAnyOfCompanyRoles("company-1", "OWNER") {
		t.Error("company-1 should hold OWNER")
	}
	if uc.HasCompanyAccess("company-3") {
		t.Error("HasCompanyAccess(company-3) = true for a company not in the entry")
	}
}
