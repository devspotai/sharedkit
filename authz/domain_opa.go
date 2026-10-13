package authz

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

// ============================================================
// DOMAIN AUTHORIZER INTERFACE
// ============================================================

// DomainAuthorizer is the contract for tier-2 domain resource authorization.
// Both DomainOPAEngine (embedded) and DomainOPASidecar (HTTP) satisfy this
// interface, so microservices can swap between them without changing routes.
type DomainAuthorizer interface {
	AuthorizeDomainResource() gin.HandlerFunc
}

// ============================================================
// EMBEDDED DOMAIN OPA ENGINE
// ============================================================

// DomainOPAConfig configures an embedded domain OPA engine.
type DomainOPAConfig struct {
	// Policy is the Rego policy source code written by the microservice.
	// Must define a boolean "allow" rule inside the given PackageName.
	Policy string

	// PackageName is the Rego package name (e.g., "stays_authz").
	// The engine queries data.<PackageName>.allow.
	PackageName string

	// InputEnricher is called per-request to add domain-specific data to the
	// OPA input. Only called when a domain check is actually required
	// (ADMIN_SPECIFIC_* roles). Return nil to add nothing.
	//
	// Example: look up whether the user is assigned to a specific stay.
	//
	//   InputEnricher: func(c *gin.Context) (map[string]any, error) {
	//       stayID := c.Param("stayId")
	//       userID := models.MustGetUserContext(c).UserID
	//       assigned := stayRepo.IsAssigned(userID, stayID)
	//       return map[string]any{"is_assigned": assigned, "stay_id": stayID}, nil
	//   }
	InputEnricher func(c *gin.Context) (map[string]any, error)

	// ResourceIDParam names the path parameter holding the resource the
	// request targets (e.g. "id" for /stays/:id). Its value becomes
	// input.request.resource_id — empty on routes without it, such as lists
	// and creates. Leave unset if the policy does not check a target.
	ResourceIDParam string
}

// DomainOPAEngine evaluates domain-specific Rego policies in-process.
// Each microservice creates one with its own policy and optional InputEnricher.
//
// Every evaluation receives, besides the request and the user:
//
//	input.request.resource_id     the target resource (ResourceIDParam, or the
//	                              id passed to AuthorizeResource), "" if none
//	input.company_resources       the user's specific resources in the company
//	  .stay_ids / .experience_ids tier 1 authorised — always arrays, never null
//
// so a policy can decide "is this resource one of theirs" from the cached
// roles alone, with no query.
type DomainOPAEngine struct {
	query           rego.PreparedEvalQuery
	inputEnricher   func(c *gin.Context) (map[string]any, error)
	resourceIDParam string
	mu              sync.RWMutex
	tracer          trace.Tracer
}

// NewDomainOPAEngine compiles the domain policy and returns an embedded engine.
func NewDomainOPAEngine(config DomainOPAConfig) (*DomainOPAEngine, error) {
	queryStr := fmt.Sprintf("data.%s.allow", config.PackageName)

	query, err := rego.New(
		rego.Query(queryStr),
		rego.Module(config.PackageName+".rego", config.Policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to compile domain OPA policy %q: %w", config.PackageName, err)
	}

	return &DomainOPAEngine{
		query:           query,
		inputEnricher:   config.InputEnricher,
		resourceIDParam: config.ResourceIDParam,
		tracer:          otel.Tracer("opa-domain-authz"),
	}, nil
}

// requiresDomainCheck reports whether tier 1 flagged this request for a
// resource-level check (the caller holds only ADMIN_SPECIFIC_* roles here).
func requiresDomainCheck(c *gin.Context) bool {
	v, ok := c.Get(OPARequiresDomainCheckKey)
	required, _ := v.(bool)
	return ok && required
}

// companyResourcesInput returns the user's specific resources in the company
// tier 1 authorised, as non-nil slices so policies can use `in` safely.
func companyResourcesInput(c *gin.Context, uc *models.UserContext) map[string]any {
	res := uc.GetCompanyResources(sidecarCompanyID(c))
	stays, exps := res.StayIDs, res.ExperienceIDs
	if stays == nil {
		stays = []string{}
	}
	if exps == nil {
		exps = []string{}
	}
	return map[string]any{"stay_ids": stays, "experience_ids": exps}
}

// buildInput assembles the policy input shared by the middleware and
// AuthorizeResource, then applies the service's InputEnricher.
func (e *DomainOPAEngine) buildInput(c *gin.Context, uc *models.UserContext, resourceID string) (map[string]any, error) {
	input := map[string]any{
		"user": map[string]any{
			"user_id": uc.UserID,
			"email":   uc.Email,
			"roles":   uc.Roles,
			"host_id": uc.HostID,
		},
		"request": map[string]any{
			"method":      c.Request.Method,
			"path":        c.Request.URL.Path,
			"action":      mapMethodToAction(c.Request.Method),
			"company_id":  sidecarCompanyID(c),
			"resource_id": resourceID,
			"stay_id":     c.Param("stayId"),
			"user_id":     c.Param("userId"),
		},
		"company_resources": companyResourcesInput(c, uc),
	}

	if companyRoles, ok := c.Get(OPACompanyRolesKey); ok {
		input["company_roles"] = companyRoles
	}

	if e.inputEnricher != nil {
		enriched, err := e.inputEnricher(c)
		if err != nil {
			return nil, err
		}
		for k, v := range enriched {
			input[k] = v
		}
	}
	return input, nil
}

// AuthorizeResource evaluates the domain policy for a resource the handler
// resolved itself — for routes whose path names something other than the
// governed resource (a package, a service, a policy) and whose handler loads
// that row anyway. Pass the governed resource's id (e.g. the package's stay).
//
// It returns true without evaluating when tier 1 did not flag the request
// (OWNER / MANAGER / ADMIN_ALL_*), exactly like the middleware. It returns
// false, never an error, when the request has no authenticated user.
func (e *DomainOPAEngine) AuthorizeResource(c *gin.Context, resourceID string) (bool, error) {
	if !requiresDomainCheck(c) {
		return true, nil
	}
	uc, ok := models.GetUserContext(c)
	if !ok || uc == nil {
		return false, nil
	}
	input, err := e.buildInput(c, uc, resourceID)
	if err != nil {
		return false, fmt.Errorf("failed to load domain authorization data: %w", err)
	}
	return e.Evaluate(c.Request.Context(), input)
}

// RestrictedResources tells a handler whether the caller is limited to
// specific resources in the authorised company, and which. restricted is false
// for OWNER / MANAGER / ADMIN_ALL_* (no limit); when true, a list must be
// filtered to the returned ids and a create of a new resource refused — a new
// resource cannot be among them.
func RestrictedResources(c *gin.Context) (resources models.CompanyResources, restricted bool) {
	if !requiresDomainCheck(c) {
		return models.CompanyResources{}, false
	}
	uc, ok := models.GetUserContext(c)
	if !ok || uc == nil {
		return models.CompanyResources{}, true
	}
	return uc.GetCompanyResources(sidecarCompanyID(c)), true
}

// Evaluate runs the domain policy and returns whether access is allowed.
func (e *DomainOPAEngine) Evaluate(ctx context.Context, input map[string]any) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("domain policy evaluation failed: %w", err)
	}

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("unexpected domain policy result type")
	}

	return allowed, nil
}

// AuthorizeDomainResource returns middleware for domain-specific resource
// authorization, designed to run AFTER CompanyOPAEngine.AuthorizeCompanyAccess().
//
// Behavior:
//   - If OPARequiresDomainCheckKey is absent or false (user has OWNER / MANAGER /
//     ADMIN_ALL_*), the request passes through immediately — no evaluation.
//   - If OPARequiresDomainCheckKey is true (user has ADMIN_SPECIFIC_*), the
//     engine evaluates the domain policy to verify access to the specific resource.
//   - If an InputEnricher was provided, it is called to add domain-specific
//     data (e.g., resource assignments) to the policy input.
func (e *DomainOPAEngine) AuthorizeDomainResource() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := e.tracer.Start(c.Request.Context(), "opa.domain_authz.embedded")
		defer span.End()

		// If company OPA didn't flag for domain check, pass through.
		if !requiresDomainCheck(c) {
			span.SetAttributes(attribute.Bool("opa.domain_check_skipped", true))
			c.Next()
			return
		}

		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
		)

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

		var resourceID string
		if e.resourceIDParam != "" {
			resourceID = c.Param(e.resourceIDParam)
		}

		input, err := e.buildInput(c, userCtx, resourceID)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusInternalServerError, models.GetErrorResponse(
				"failed to load domain authorization data", http.StatusInternalServerError, "",
			))
			c.Abort()
			return
		}

		allowed, err := e.Evaluate(ctx, input)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusInternalServerError, models.GetErrorResponse(
				"domain authorization check failed", http.StatusInternalServerError, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.Bool("opa.domain_decision", allowed))

		if !allowed {
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"access denied to this resource", http.StatusForbidden, "",
			))
			c.Abort()
			return
		}

		c.Next()
	}
}

// ReloadPolicy hot-reloads the domain policy at runtime.
func (e *DomainOPAEngine) ReloadPolicy(policy string, packageName string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	queryStr := fmt.Sprintf("data.%s.allow", packageName)
	query, err := rego.New(
		rego.Query(queryStr),
		rego.Module(packageName+".rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("failed to compile domain OPA policy: %w", err)
	}

	e.query = query
	return nil
}

// ============================================================
// OPA SIDECAR (HTTP) — for future scaling
// ============================================================

// DomainOPASidecar queries an external OPA sidecar over HTTP.
// Use this when you outgrow the embedded engine and need a dedicated
// OPA instance with bundle management, decision logging, etc.
//
// DomainOPASidecar satisfies DomainAuthorizer, so swapping from
// DomainOPAEngine is a one-line change in route setup.
type DomainOPASidecar struct {
	opaEndpoint string
	httpClient  *http.Client
	policyPath  string
	tracer      trace.Tracer
}

// DomainOPASidecarConfig configures the HTTP sidecar client.
type DomainOPASidecarConfig struct {
	// OPAEndpoint is the base URL (e.g., "http://localhost:8181").
	OPAEndpoint string

	// PolicyPath is the data path to query (e.g., "stays_authz/allow").
	PolicyPath string

	// Timeout for HTTP requests. Defaults to 100ms.
	Timeout time.Duration
}

// OPADecision represents a policy decision from the OPA sidecar.
type OPADecision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// OPAResult is the raw response shape from the OPA REST API.
type OPAResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// NewDomainOPASidecar creates a new HTTP sidecar client.
func NewDomainOPASidecar(config DomainOPASidecarConfig) *DomainOPASidecar {
	if config.Timeout == 0 {
		config.Timeout = 100 * time.Millisecond
	}
	return &DomainOPASidecar{
		opaEndpoint: config.OPAEndpoint,
		httpClient:  &http.Client{Timeout: config.Timeout},
		policyPath:  config.PolicyPath,
		tracer:      otel.Tracer("opa-domain-sidecar"),
	}
}

// AuthorizeDomainResource returns middleware that queries the OPA sidecar.
// Same contract as DomainOPAEngine.AuthorizeDomainResource — reads
// OPARequiresDomainCheckKey and skips if no domain check is required.
func (s *DomainOPASidecar) AuthorizeDomainResource() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := s.tracer.Start(c.Request.Context(), "opa.domain_authz.sidecar")
		defer span.End()

		requiresDomainCheck, exists := c.Get(OPARequiresDomainCheckKey)
		if !exists || !requiresDomainCheck.(bool) {
			span.SetAttributes(attribute.Bool("opa.domain_check_skipped", true))
			c.Next()
			return
		}

		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
			attribute.String("opa.policy_path", s.policyPath),
		)

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

		opaInput := buildSidecarInput(c, userCtx)
		if companyRoles, ok := c.Get(OPACompanyRolesKey); ok {
			opaInput["company_roles"] = companyRoles
		}

		decision, err := s.queryOPA(ctx, opaInput)
		if err != nil {
			span.RecordError(err)
			c.JSON(http.StatusInternalServerError, models.GetErrorResponse(
				"domain authorization check failed", http.StatusInternalServerError, "",
			))
			c.Abort()
			return
		}

		span.SetAttributes(attribute.Bool("opa.domain_decision", decision.Allow))

		if !decision.Allow {
			c.JSON(http.StatusForbidden, models.GetErrorResponse(
				"access denied to this resource", http.StatusForbidden, decision.Reason,
			))
			c.Abort()
			return
		}

		c.Next()
	}
}

func buildSidecarInput(c *gin.Context, userCtx *models.UserContext) map[string]any {
	return map[string]any{
		"jwt": map[string]any{
			"user_id": userCtx.UserID,
			"email":   userCtx.Email,
			"roles":   userCtx.Roles,
			"host_id": userCtx.HostID,
		},
		"request": map[string]any{
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"action":     mapMethodToAction(c.Request.Method),
			"company_id": sidecarCompanyID(c),
			"stay_id":    c.Param("stayId"),
			"user_id":    c.Param("userId"),
			"query":      c.Request.URL.Query(),
		},
		// Same shape as the embedded engine's, so a policy can move between them.
		"company_resources": companyResourcesInput(c, userCtx),
	}
}

func (s *DomainOPASidecar) queryOPA(ctx context.Context, input map[string]any) (*OPADecision, error) {
	ctx, span := s.tracer.Start(ctx, "opa.query_sidecar")
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
		Result OPAResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&opaResponse); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	span.SetAttributes(attribute.Bool("opa.decision", opaResponse.Result.Allow))

	return &OPADecision{
		Allow:  opaResponse.Result.Allow,
		Reason: opaResponse.Result.Reason,
	}, nil
}

// ============================================================
// SHARED HELPERS
// ============================================================

func mapMethodToAction(method string) string {
	switch method {
	case "GET":
		return "read"
	case "POST":
		return "create"
	case "PUT", "PATCH":
		return "update"
	case "DELETE":
		return "delete"
	default:
		return "read"
	}
}

// sidecarCompanyID returns the company tier 1 authorised, so tier 2 always
// evaluates the same company. Falls back to the path parameter when tier 1
// has not run.
func sidecarCompanyID(c *gin.Context) string {
	if id := c.GetString("company_id"); id != "" {
		return id
	}
	return c.Param("companyId")
}
