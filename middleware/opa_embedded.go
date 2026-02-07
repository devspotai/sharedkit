package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/v1/rego"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Context keys set by company-level OPA authorization.
// Domain-level middleware (AuthorizeDomainResource) reads these to decide whether to run.
const (
	OPACompanyAllowedKey      = "opa_company_allowed"
	OPARequiresDomainCheckKey = "opa_requires_domain_check"
	OPACompanyRolesKey        = "opa_company_roles"
)

// CompanyAuthorizer is the contract for tier-1 company-user authorization.
// Both CompanyOPAEngine (embedded) and CompanyOPASidecar (HTTP) satisfy this
// interface, so microservices can swap between them without changing routes.
type CompanyAuthorizer interface {
	AuthorizeCompanyAccess(domainCfg CompanyAuthzConfig) gin.HandlerFunc
}

// companyAuthzPolicy is the embedded Rego policy for company-user level authorization.
//
// Decision logic:
//
//	OWNER / MANAGER          → allow, no domain check needed
//	ADMIN_ALL_<DOMAIN>       → allow for matching domain, no domain check
//	ADMIN_SPECIFIC_<DOMAIN>  → allow at company level, requires_domain_check = true
//	STAFF                    → allow read-only, no domain check
//	SYSTEM ADMIN (global)    → allow everything
//
// The policy is domain-agnostic: full_access_roles and granular_roles are passed as
// input by the calling microservice via CompanyAuthzConfig.
const companyAuthzPolicy = `package company_authz

import rego.v1

default allow := false
default requires_domain_check := false

# ── Global system admin bypasses all company checks ──────────────
allow if {
	input.user.roles[_] == "ADMIN"
}

# ── Company OWNER: full access to every domain ──────────────────
allow if {
	input.user.company_roles[_] == "OWNER"
}

# ── Company MANAGER: full access to every domain ────────────────
allow if {
	input.user.company_roles[_] == "MANAGER"
}

# ── Domain full-access roles (e.g. ADMIN_ALL_STAYS) ─────────────
allow if {
	some role in input.full_access_roles
	input.user.company_roles[_] == role
}

# ── Domain granular roles (e.g. ADMIN_SPECIFIC_STAYS) ───────────
# Allowed at company level but the domain microservice OPA must
# verify which specific resources the user may access.
allow if {
	some role in input.granular_roles
	input.user.company_roles[_] == role
}

requires_domain_check if {
	some role in input.granular_roles
	input.user.company_roles[_] == role
	not has_full_access
}

# ── STAFF: read-only access ─────────────────────────────────────
allow if {
	input.user.company_roles[_] == "STAFF"
	input.action == "read"
}

# ── Helper: user already has unrestricted access ────────────────
has_full_access if {
	input.user.company_roles[_] == "OWNER"
}

has_full_access if {
	input.user.company_roles[_] == "MANAGER"
}

has_full_access if {
	some role in input.full_access_roles
	input.user.company_roles[_] == role
}

# ── Combined result document ────────────────────────────────────
result := {
	"allow": allow,
	"requires_domain_check": requires_domain_check,
}
`

// ============================================================
// DOMAIN CONFIGURATION
// ============================================================

// CompanyAuthzConfig tells the company OPA engine which company-level roles
// grant full vs granular access for a particular domain (microservice).
type CompanyAuthzConfig struct {
	// Domain identifier, e.g. "stays", "experiences".
	Domain string

	// FullAccessRoles are company roles granting unrestricted domain access.
	// Users with these roles will NOT trigger a domain-level OPA check.
	// Example: []string{"ADMIN_ALL_STAYS"}
	FullAccessRoles []string

	// GranularRoles are company roles that pass company-level auth but still
	// require the domain microservice's OPA to verify resource-level access.
	// Example: []string{"ADMIN_SPECIFIC_STAYS"}
	GranularRoles []string
}

// StaysDomainConfig returns the standard config for a stays microservice.
func StaysDomainConfig() CompanyAuthzConfig {
	return CompanyAuthzConfig{
		Domain:          "stays",
		FullAccessRoles: []string{models.CompanyRoleAdminAllStays},
		GranularRoles:   []string{models.CompanyRoleAdminSpecificStay},
	}
}

// ExperiencesDomainConfig returns the standard config for an experiences microservice.
func ExperiencesDomainConfig() CompanyAuthzConfig {
	return CompanyAuthzConfig{
		Domain:          "experiences",
		FullAccessRoles: []string{models.CompanyRoleAdminAllExperiences},
		GranularRoles:   []string{models.CompanyRoleAdminSpecificExperience},
	}
}

// ============================================================
// COMPANY OPA ENGINE
// ============================================================

// CompanyOPAEngine evaluates company-user level authorization using an
// embedded OPA policy compiled into the binary. Every microservice that
// imports sharedkit gets the same company-level policy enforcement.
type CompanyOPAEngine struct {
	query  rego.PreparedEvalQuery
	mu     sync.RWMutex
	tracer trace.Tracer
}

// CompanyAuthzResult holds the outcome of a company-level policy evaluation.
type CompanyAuthzResult struct {
	Allow               bool `json:"allow"`
	RequiresDomainCheck bool `json:"requires_domain_check"`
}

// NewCompanyOPAEngine creates a new engine with the built-in company
// authorization policy.
func NewCompanyOPAEngine() (*CompanyOPAEngine, error) {
	return NewCompanyOPAEngineWithPolicy(companyAuthzPolicy)
}

// NewCompanyOPAEngineWithPolicy creates a new engine with a custom Rego policy.
// The policy must define package "company_authz" with a "result" rule returning
// {"allow": bool, "requires_domain_check": bool}.
func NewCompanyOPAEngineWithPolicy(policy string) (*CompanyOPAEngine, error) {
	query, err := rego.New(
		rego.Query("data.company_authz.result"),
		rego.Module("company_authz.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile company OPA policy: %w", err)
	}

	return &CompanyOPAEngine{
		query:  query,
		tracer: otel.Tracer("opa-company-authz"),
	}, nil
}

// ============================================================
// EVALUATE
// ============================================================

// Evaluate runs the company-level policy for a given user, company, action,
// and domain configuration. Returns whether access is allowed and whether
// the domain microservice's own OPA must perform a follow-up check.
func (e *CompanyOPAEngine) Evaluate(
	ctx context.Context,
	userCtx *models.UserContext,
	companyID string,
	action string,
	domainCfg CompanyAuthzConfig,
) (*CompanyAuthzResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ctx, span := e.tracer.Start(ctx, "opa.company_authz.evaluate")
	defer span.End()

	companyRoles, _ := userCtx.GetUserCompanyRoles(companyID)

	span.SetAttributes(
		attribute.String("user.id", userCtx.UserID),
		attribute.String("company.id", companyID),
		attribute.String("opa.domain", domainCfg.Domain),
		attribute.String("opa.action", action),
	)

	inputMap := map[string]interface{}{
		"user": map[string]interface{}{
			"user_id":       userCtx.UserID,
			"roles":         userCtx.Roles,
			"company_roles": companyRoles,
		},
		"company_id":        companyID,
		"domain":            domainCfg.Domain,
		"action":            action,
		"full_access_roles": domainCfg.FullAccessRoles,
		"granular_roles":    domainCfg.GranularRoles,
	}

	results, err := e.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("company policy evaluation failed: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		span.SetAttributes(attribute.Bool("opa.decision", false))
		return &CompanyAuthzResult{Allow: false}, nil
	}

	resultMap, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected policy result type")
	}

	result := &CompanyAuthzResult{}
	if allow, ok := resultMap["allow"].(bool); ok {
		result.Allow = allow
	}
	if rd, ok := resultMap["requires_domain_check"].(bool); ok {
		result.RequiresDomainCheck = rd
	}

	span.SetAttributes(
		attribute.Bool("opa.decision", result.Allow),
		attribute.Bool("opa.requires_domain_check", result.RequiresDomainCheck),
	)

	return result, nil
}

// ============================================================
// GIN MIDDLEWARE
// ============================================================

// AuthorizeCompanyAccess returns Gin middleware that enforces company-user
// level authorization for a specific domain.
//
// It extracts the company ID from path params ("companyId" / "company_id")
// or query param ("companyId"), evaluates the embedded policy, and sets
// context keys for downstream domain-level middleware:
//
//   - OPACompanyAllowedKey      (bool)     – company access granted
//   - OPARequiresDomainCheckKey (bool)     – domain OPA must verify resource access
//   - OPACompanyRolesKey        ([]string) – user's roles for this company
//   - "company_id"              (string)   – resolved company ID
func (e *CompanyOPAEngine) AuthorizeCompanyAccess(domainCfg CompanyAuthzConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := e.tracer.Start(c.Request.Context(), "opa.company_authz.middleware")
		defer span.End()

		span.SetAttributes(
			attribute.String("opa.domain", domainCfg.Domain),
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		)

		// 1. Require authenticated user
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			span.RecordError(fmt.Errorf("no user context"))
			c.JSON(http.StatusUnauthorized, models.GetErrorResponse(
				"authentication required", http.StatusUnauthorized, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.String("user.id", userCtx.UserID))

		// 2. Resolve company ID from request
		companyID := extractCompanyID(c)
		if companyID == "" {
			c.JSON(http.StatusBadRequest, models.GetErrorResponse(
				"company_id required", http.StatusBadRequest, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.String("company.id", companyID))

		// 3. Quick check: does the user have ANY role in this company?
		if !userCtx.HasCompanyAccess(companyID) {
			span.SetAttributes(attribute.Bool("opa.decision", false))
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"no access to this company", http.StatusForbidden, companyID,
			))
			c.Abort()
			return
		}

		// 4. Evaluate company-level OPA policy
		action := mapMethodToAction(c.Request.Method)
		result, err := e.Evaluate(ctx, userCtx, companyID, action, domainCfg)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusInternalServerError, models.GetErrorResponse(
				"authorization check failed", http.StatusInternalServerError, "",
			))
			c.Abort()
			return
		}

		if !result.Allow {
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"insufficient company permissions", http.StatusForbidden,
				fmt.Sprintf("user does not have required %s permissions for company %s", domainCfg.Domain, companyID),
			))
			c.Abort()
			return
		}

		// 5. Set context for downstream domain middleware / handlers
		companyRoles, _ := userCtx.GetUserCompanyRoles(companyID)
		c.Set(OPACompanyAllowedKey, true)
		c.Set(OPARequiresDomainCheckKey, result.RequiresDomainCheck)
		c.Set(OPACompanyRolesKey, companyRoles)
		c.Set("company_id", companyID)

		c.Next()
	}
}

// ============================================================
// HOT RELOAD
// ============================================================

// ReloadPolicy replaces the running policy at runtime (e.g. for dev hot-reload).
func (e *CompanyOPAEngine) ReloadPolicy(policy string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	query, err := rego.New(
		rego.Query("data.company_authz.result"),
		rego.Module("company_authz.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to compile OPA policy: %w", err)
	}

	e.query = query
	return nil
}

// ============================================================
// COMPANY OPA SIDECAR (HTTP)
// ============================================================

// CompanyOPASidecarConfig configures the HTTP sidecar client for company-level
// authorization.
type CompanyOPASidecarConfig struct {
	// OPAEndpoint is the base URL (e.g., "http://localhost:8181").
	OPAEndpoint string

	// PolicyPath is the data path to query (e.g., "company_authz/result").
	PolicyPath string

	// Timeout for HTTP requests. Defaults to 100ms.
	Timeout time.Duration
}

// CompanyOPASidecar queries an external OPA sidecar over HTTP for company-level
// authorization. Use this when you need a dedicated OPA instance with bundle
// management, decision logging, etc.
//
// CompanyOPASidecar satisfies CompanyAuthorizer, so swapping from
// CompanyOPAEngine is a one-line change in route setup.
type CompanyOPASidecar struct {
	opaEndpoint string
	httpClient  *http.Client
	policyPath  string
	tracer      trace.Tracer
}

// NewCompanyOPASidecar creates a new HTTP sidecar client for company-level
// authorization.
func NewCompanyOPASidecar(config CompanyOPASidecarConfig) *CompanyOPASidecar {
	if config.Timeout == 0 {
		config.Timeout = 100 * time.Millisecond
	}
	return &CompanyOPASidecar{
		opaEndpoint: config.OPAEndpoint,
		httpClient:  &http.Client{Timeout: config.Timeout},
		policyPath:  config.PolicyPath,
		tracer:      otel.Tracer("opa-company-sidecar"),
	}
}

// AuthorizeCompanyAccess returns Gin middleware that enforces company-user
// level authorization by querying an external OPA sidecar.
//
// Same contract as CompanyOPAEngine.AuthorizeCompanyAccess — sets the same
// context keys for downstream domain-level middleware.
func (s *CompanyOPASidecar) AuthorizeCompanyAccess(domainCfg CompanyAuthzConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		_, span := s.tracer.Start(c.Request.Context(), "opa.company_authz.sidecar")
		defer span.End()

		span.SetAttributes(
			attribute.String("opa.domain", domainCfg.Domain),
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
			attribute.String("opa.policy_path", s.policyPath),
		)

		// 1. Require authenticated user
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			span.RecordError(fmt.Errorf("no user context"))
			c.JSON(http.StatusUnauthorized, models.GetErrorResponse(
				"authentication required", http.StatusUnauthorized, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.String("user.id", userCtx.UserID))

		// 2. Resolve company ID from request
		companyID := extractCompanyID(c)
		if companyID == "" {
			c.JSON(http.StatusBadRequest, models.GetErrorResponse(
				"company_id required", http.StatusBadRequest, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.String("company.id", companyID))

		// 3. Quick check: does the user have ANY role in this company?
		if !userCtx.HasCompanyAccess(companyID) {
			span.SetAttributes(attribute.Bool("opa.decision", false))
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"no access to this company", http.StatusForbidden, companyID,
			))
			c.Abort()
			return
		}

		// 4. Build OPA input (same shape as CompanyOPAEngine.Evaluate)
		action := mapMethodToAction(c.Request.Method)
		companyRoles, _ := userCtx.GetUserCompanyRoles(companyID)

		opaInput := map[string]interface{}{
			"user": map[string]interface{}{
				"user_id":       userCtx.UserID,
				"roles":         userCtx.Roles,
				"company_roles": companyRoles,
			},
			"company_id":        companyID,
			"domain":            domainCfg.Domain,
			"action":            action,
			"full_access_roles": domainCfg.FullAccessRoles,
			"granular_roles":    domainCfg.GranularRoles,
		}

		// 5. Query OPA sidecar
		result, err := s.queryCompanyOPA(c.Request.Context(), opaInput)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusInternalServerError, models.GetErrorResponse(
				"authorization check failed", http.StatusInternalServerError, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(
			attribute.Bool("opa.decision", result.Allow),
			attribute.Bool("opa.requires_domain_check", result.RequiresDomainCheck),
		)

		if !result.Allow {
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"insufficient company permissions", http.StatusForbidden,
				fmt.Sprintf("user does not have required %s permissions for company %s", domainCfg.Domain, companyID),
			))
			c.Abort()
			return
		}

		// 6. Set context for downstream domain middleware / handlers
		c.Set(OPACompanyAllowedKey, true)
		c.Set(OPARequiresDomainCheckKey, result.RequiresDomainCheck)
		c.Set(OPACompanyRolesKey, companyRoles)
		c.Set("company_id", companyID)

		c.Next()
	}
}

func (s *CompanyOPASidecar) queryCompanyOPA(ctx context.Context, input map[string]interface{}) (*CompanyAuthzResult, error) {
	ctx, span := s.tracer.Start(ctx, "opa.query_company_sidecar")
	defer span.End()

	span.SetAttributes(
		attribute.String("opa.endpoint", s.opaEndpoint),
		attribute.String("opa.policy_path", s.policyPath),
	)

	requestBody, err := json.Marshal(map[string]any{"input": input})
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/data/%s", s.opaEndpoint, s.policyPath)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(requestBody))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to query OPA: %w", err)
	}
	defer resp.Body.Close()

	span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))

	var opaResponse struct {
		Result CompanyAuthzResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResponse); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("opa.decision", opaResponse.Result.Allow),
		attribute.Bool("opa.requires_domain_check", opaResponse.Result.RequiresDomainCheck),
	)

	return &opaResponse.Result, nil
}

// ============================================================
// HELPERS
// ============================================================

func extractCompanyID(c *gin.Context) string {
	if id := c.Param("companyId"); id != "" {
		return id
	}
	if id := c.Param("company_id"); id != "" {
		return id
	}
	return c.Query("companyId")
}
