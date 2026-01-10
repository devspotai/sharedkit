package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

type OPAMiddleware struct {
	OPAEndpoint string
	httpClient  *http.Client
	policyPath  string
}

type OPAConfig struct {
	PolicyPath  string
	OPAEndpoint string
	Timeout     time.Duration
}

func NewOPAMiddleware(config OPAConfig) *OPAMiddleware {
	if config.Timeout == 0 {
		config.Timeout = 100 * time.Millisecond
	}
	return &OPAMiddleware{
		OPAEndpoint: config.OPAEndpoint,
		httpClient:  &http.Client{Timeout: config.Timeout},
		policyPath:  config.PolicyPath,
	}
}

// ============================================================
// AUTHORIZE - Main middleware function
// ============================================================

func (m *OPAMiddleware) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		// 1. Get user context from JWT middleware
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized - no user context",
			})
			c.Abort()
			return
		}

		// 2. Build OPA input from request
		opaInput := m.buildOPAInput(c, userCtx)

		// 3. Query OPA for authorization decision
		decision, err := m.queryOPA(c.Request.Context(), opaInput)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "authorization check failed",
			})
			c.Abort()
			return
		}

		// 4. Check decision
		if !decision.Allow {
			c.JSON(http.StatusForbidden, gin.H{
				"error":  "access denied",
				"reason": decision.Reason,
			})
			c.Abort()
			return
		}

		// 5. Add decision metadata to context (optional)
		c.Set("opa_decision_time", time.Since(startTime))

		c.Next()
	}
}

// ============================================================
// BUILD OPA INPUT - Extract request details
// ============================================================

func (m *OPAMiddleware) buildOPAInput(c *gin.Context, userCtx *models.UserContext) map[string]interface{} {
	return map[string]interface{}{
		"jwt": map[string]interface{}{
			"user_id": userCtx.UserID,
			"email":   userCtx.Email,
			"roles":   userCtx.Roles,
			"host_id": userCtx.HostID,
		},
		"request": map[string]interface{}{
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"action": mapMethodToAction(c.Request.Method),
			// Extract path parameters
			"company_id": c.Param("companyId"),
			"stay_id":    c.Param("stayId"),
			"user_id":    c.Param("userId"),
			// Add query parameters if needed
			"query": c.Request.URL.Query(),
		},
	}
}

// ============================================================
// QUERY OPA - Make authorization request
// ============================================================

func (m *OPAMiddleware) queryOPA(ctx context.Context, input map[string]interface{}) (*OPADecision, error) {
	// Build OPA request
	opaRequest := map[string]interface{}{
		"input": input,
	}

	requestBody, err := json.Marshal(opaRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	// Build URL for policy evaluation
	url := fmt.Sprintf("%s/v1/data/%s", m.OPAEndpoint, m.policyPath)

	// Create HTTP request
	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		url,
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OPA: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var opaResponse struct {
		Result OPAResult `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&opaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode OPA response: %w", err)
	}

	return &OPADecision{
		Allow:  opaResponse.Result.Allow,
		Reason: opaResponse.Result.Reason,
	}, nil
}

// ============================================================
// HELPER FUNCTIONS
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

// ============================================================
// TYPES
// ============================================================

type OPADecision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

type OPAResult struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
}

// ============================================================
// ADVANCED: Resource-Specific Authorization
// ============================================================

// AuthorizeResource - For specific resource checks (company, stay, etc.)
func (m *OPAMiddleware) AuthorizeResource(resourceType, resourceID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// Build resource-specific input
		opaInput := map[string]interface{}{
			"jwt": map[string]interface{}{
				"user_id": userCtx.UserID,
				"roles":   userCtx.Roles,
				"host_id": userCtx.HostID,
			},
			"request": map[string]interface{}{
				"action":        mapMethodToAction(c.Request.Method),
				"resource_type": resourceType,
				"resource_id":   resourceID,
			},
		}

		decision, err := m.queryOPA(c.Request.Context(), opaInput)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization failed"})
			c.Abort()
			return
		}

		if !decision.Allow {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ============================================================
// REQUIRE ROLES - Simple role-based check
// ============================================================

// RequireRoles - Check if user has any of the specified roles
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "role unauthorized"})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		hasRole := false
		for _, requiredRole := range roles {
			for _, userRole := range userCtx.Roles {
				if userRole == requiredRole {
					hasRole = true
					break
				}
			}
			if hasRole {
				break
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{
				"error":          "insufficient permissions",
				"required_roles": roles,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ============================================================
// TWO-TIER AUTHORIZATION - Company + Resource
// ============================================================

type TwoTierAuthConfig struct {
	CompanyOPAURL      string // sys-backend-user OPA
	ResourceOPAURL     string // Local OPA sidecar
	CompanyPolicyPath  string // "company_authz/allow"
	ResourcePolicyPath string // "stay_authz/allow"
}

type TwoTierAuthMiddleware struct {
	companyMiddleware  *OPAMiddleware
	resourceMiddleware *OPAMiddleware
}

func NewTwoTierAuthMiddleware(config TwoTierAuthConfig) *TwoTierAuthMiddleware {
	return &TwoTierAuthMiddleware{
		companyMiddleware: NewOPAMiddleware(OPAConfig{
			OPAEndpoint: config.CompanyOPAURL,
			PolicyPath:  config.CompanyPolicyPath,
		}),
		resourceMiddleware: NewOPAMiddleware(OPAConfig{
			OPAEndpoint: config.ResourceOPAURL,
			PolicyPath:  config.ResourcePolicyPath,
		}),
	}
}

// Authorize - Two-tier check: company access + resource access
func (m *TwoTierAuthMiddleware) Authorize() gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		// TIER 1: Check company access
		companyInput := map[string]interface{}{
			"jwt": map[string]interface{}{
				"user_id": userCtx.UserID,
			},
			"request": map[string]interface{}{
				"company_id": c.Param("companyId"),
			},
		}

		companyDecision, err := m.companyMiddleware.queryOPA(c.Request.Context(), companyInput)
		if err != nil || !companyDecision.Allow {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "no company access",
			})
			c.Abort()
			return
		}

		// TIER 2: Check resource access
		resourceInput := map[string]interface{}{
			"jwt": map[string]interface{}{
				"user_id": userCtx.UserID,
			},
			"request": map[string]interface{}{
				"stay_id": c.Param("stayId"),
				"action":  mapMethodToAction(c.Request.Method),
			},
		}

		resourceDecision, err := m.resourceMiddleware.queryOPA(c.Request.Context(), resourceInput)
		if err != nil || !resourceDecision.Allow {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "no resource access",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
