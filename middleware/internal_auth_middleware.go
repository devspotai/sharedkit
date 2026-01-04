package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/sha3"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
)

// InternalServiceAuth middleware ensures only Traefik can call internal services
// This prevents malicious clients from injecting headers to bypass authentication
type InternalServiceAuth struct {
	sharedSecret  string
	cache         *cache.RedisCache
	nonceTTL      time.Duration
	allowedSkew   time.Duration
	publicPaths   map[string]bool
	includeMethod bool //Include HTTP method in HMAC signature
	includePath   bool //Include request path in HMAC signature
}

// NewInternalServiceAuth creates a new internal service authentication middleware
func NewInternalServiceAuth(sharedSecret string, cache *cache.RedisCache, nonceTtl time.Duration, allowedSkew time.Duration,
	publicPaths []string, includeMethod bool, includePath bool) *InternalServiceAuth {
	if sharedSecret == "" {
		panic("internal auth secret cannot be empty")
	}
	if cache == nil {
		panic("internal auth cache cannot be nil")
	}
	// Set defaults
	if nonceTtl == 0 {
		nonceTtl = 5 * time.Minute
	}
	if allowedSkew == 0 {
		allowedSkew = 30 * time.Second
	}
	// Convert public paths slice to map for O(1) lookup
	publicPathsMap := make(map[string]bool)
	for _, path := range publicPaths {
		publicPathsMap[path] = true
	}
	return &InternalServiceAuth{
		sharedSecret:  sharedSecret,
		cache:         cache,
		nonceTTL:      nonceTtl,
		allowedSkew:   allowedSkew,
		publicPaths:   publicPathsMap,
		includeMethod: includeMethod,
		includePath:   includePath,
	}
}

// Middleware returns the Gin middleware handler
// Middleware validates HMAC signature from API gateway
func (m *InternalServiceAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if m.isPublicPath(c) {
			c.Next()
			return
		}
		// Not a public path - require authentication
		if err := m.validateRequest(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// MiddlewareRequired always requires authentication (no public paths)
// Use this for route groups that should always be authenticated
func (m *InternalServiceAuth) MiddlewareRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := m.validateRequest(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// MiddlewareOptional allows requests without authentication
// Sets user context if valid auth headers present, otherwise continues without
// Use this for endpoints that work both authenticated and unauthenticated
func (m *InternalServiceAuth) MiddlewareOptional() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to validate, but don't abort if validation fails
		_ = m.validateRequest(c)
		c.Next()
	}
}

// MiddlewareWithPublicPaths creates middleware with specific public paths
// Use this when you want to override the configured public paths for a specific route group
func (m *InternalServiceAuth) MiddlewareWithPublicPaths(publicPaths ...string) gin.HandlerFunc {
	publicMap := make(map[string]bool)
	for _, path := range publicPaths {
		publicMap[path] = true
	}

	return func(c *gin.Context) {
		// Check against provided public paths
		fullPath := c.FullPath()
		if fullPath != "" && publicMap[fullPath] {
			c.Next()
			return
		}

		// Also check request path (for wildcards)
		requestPath := c.Request.URL.Path
		if publicMap[requestPath] {
			c.Next()
			return
		}

		// Not public - require authentication
		if err := m.validateRequest(c); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": err.Error(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// validateRequest performs full HMAC and nonce validation
func (m *InternalServiceAuth) validateRequest(c *gin.Context) error {
	// Get headers from gateway
	signature := c.GetHeader("X-Internal-Auth")
	nonce := c.GetHeader("X-Request-Nonce")
	userID := c.GetHeader("X-User-ID")
	hostID := c.GetHeader("X-Host-ID")
	email := c.GetHeader("X-User-Email")
	emailVerified := c.GetHeader("X-Email-Verified") == "true"
	rolesStr := c.GetHeader("X-User-Roles")
	companiesStr := c.GetHeader("X-Companies")
	timestampStr := c.GetHeader("X-Timestamp")

	// Validate required headers
	if signature == "" || userID == "" || nonce == "" || timestampStr == "" {
		return fmt.Errorf("missing required auth headers")
	}

	// Validate timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format")
	}

	now := time.Now()
	reqTime := time.Unix(timestamp, 0)

	// Check if request is from the future (clock skew protection)
	if reqTime.After(now.Add(m.allowedSkew)) {
		return fmt.Errorf("timestamp too far in future")
	}

	// Check if request is too old
	if now.Sub(reqTime) > m.nonceTTL {
		return fmt.Errorf("request expired")
	}

	// Validate nonce (prevent replay attacks)
	if err := m.validateNonce(c.Request.Context(), nonce, userID, timestamp); err != nil {
		return err
	}

	// Recompute HMAC signature
	message := m.buildHMACMessage(c, userID, hostID, rolesStr, companiesStr, timestampStr, nonce)
	mac := hmac.New(sha3.New256, []byte(m.sharedSecret))
	mac.Write([]byte(message))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return fmt.Errorf("invalid signature")
	}

	// Parse roles
	roles := []string{}
	if rolesStr != "" {
		roles = strings.Split(rolesStr, ",")
	}

	// Parse companies
	companies := []models.Company{}
	if companiesStr != "" {
		if err := json.Unmarshal([]byte(companiesStr), &companies); err != nil {
			return fmt.Errorf("invalid companies format in headers")
		}
	}

	// Store user context
	userCtx := &models.UserContext{
		UserID:        userID,
		Email:         email,
		EmailVerified: emailVerified,
		Roles:         roles,
		Companies:     companies,
	}

	c.Set(models.UserContextKey, userCtx)
	return nil
}

// buildHMACMessage constructs the message for HMAC computation
func (m *InternalServiceAuth) buildHMACMessage(c *gin.Context, userID, hostID, roles, companies, timestamp, nonce string) string {
	// Base message (always included)
	parts := []string{userID, hostID, roles, companies, timestamp, nonce}

	// Optionally include HTTP method (recommended for security)
	if m.includeMethod {
		parts = append([]string{c.Request.Method}, parts...)
	}

	// Optionally include request path (recommended for security)
	if m.includePath {
		path := c.Request.URL.Path
		if m.includeMethod {
			// Method already prepended, add path after it
			parts = append([]string{parts[0], path}, parts[1:]...)
		} else {
			// No method, prepend path
			parts = append([]string{path}, parts...)
		}
	}

	return strings.Join(parts, ":")
}

// isPublicPath checks if the current request path is public
func (m *InternalServiceAuth) isPublicPath(c *gin.Context) bool {
	if len(m.publicPaths) == 0 {
		return false
	}

	// Check full path (e.g., "/api/v1/health")
	fullPath := c.FullPath()
	if fullPath != "" && m.publicPaths[fullPath] {
		return true
	}

	// Check request path (for wildcard routes)
	requestPath := c.Request.URL.Path
	if m.publicPaths[requestPath] {
		return true
	}

	return false
}

// ============================================================
// NONCE VALIDATION (Replay Attack Prevention)
// ============================================================

// validateNonce checks if nonce has been used before
func (m *InternalServiceAuth) validateNonce(ctx context.Context, nonce, userID string, timestamp int64) error {
	// Validate nonce format (must be hex string, 32 characters minimum)
	if len(nonce) < 32 {
		return fmt.Errorf("nonce too short (minimum 32 characters)")
	}

	// Verify nonce is valid hex
	if _, err := hex.DecodeString(nonce); err != nil {
		return fmt.Errorf("nonce must be hex string")
	}

	// Nonce key scoped by userID to prevent cross-user replay
	nonceKey := m.getNonceKey(userID, nonce)

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Try to set nonce if not exists (atomic operation)
	// SetNX returns true if key was set, false if already exists
	wasSet, err := m.cache.SetNX(ctx, nonceKey, []byte("1"), m.nonceTTL)
	if err != nil {
		return fmt.Errorf("redis error checking nonce: %w", err)
	}

	if !wasSet {
		// Nonce already exists - replay attack detected!
		return fmt.Errorf("nonce already used - replay attack detected")
	}

	// Nonce is valid and has been recorded
	return nil
}

// getNonceKey returns Redis key for nonce tracking (scoped by userID)
func (m *InternalServiceAuth) getNonceKey(userID, nonce string) string {
	return fmt.Sprintf("nonce:%s:%s", userID, nonce)
}

// ForwardedUserHeaders represents user context forwarded from API gateway
type ForwardedUserHeaders struct {
	UserID        string
	HostID        string
	Email         string
	EmailVerified bool
	Roles         []string
	Companies     []models.Company
}

// ExtractForwardedUserContext extracts user context from headers set by Traefik
// Traefik middleware should forward these after JWT validation
func ExtractForwardedUserContext(c *gin.Context) (*ForwardedUserHeaders, error) {
	userID := c.GetHeader("X-User-ID")
	if userID == "" {
		return nil, fmt.Errorf("missing user ID header")
	}
	hostID := c.GetHeader("X-Host-ID")
	if hostID == "" {
		return nil, fmt.Errorf("missing host ID header")
	}

	email := c.GetHeader("X-User-Email")
	emailVerified := c.GetHeader("X-User-Email-Verified") == "true"

	// Parse roles from comma-separated string
	rolesStr := c.GetHeader("X-User-Roles")
	var roles []string
	if rolesStr != "" {
		roles = parseCommaSeparated(rolesStr)
	}

	// Parse companies from JSON header
	companiesStr := c.GetHeader("X-User-Companies")
	var companies []models.Company
	if companiesStr != "" {
		// In production, parse JSON. For simplicity, we'll leave it empty
		// json.Unmarshal([]byte(companiesStr), &companies)
	}

	return &ForwardedUserHeaders{
		UserID:        userID,
		HostID:        hostID,
		Email:         email,
		EmailVerified: emailVerified,
		Roles:         roles,
		Companies:     companies,
	}, nil
}

// parseCommaSeparated splits a comma-separated string into a slice
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}

	result := []string{}
	for _, part := range splitAndTrim(s, ",") {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// splitAndTrim splits and trims strings
func splitAndTrim(s, sep string) []string {
	parts := []string{}
	for _, part := range split(s, sep) {
		trimmed := trim(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func split(s, sep string) []string {
	// Simple split implementation
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trim(s string) string {
	start := 0
	end := len(s)

	// Trim leading spaces
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	// Trim trailing spaces
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

// CombinedAuth combines JWT validation with internal service authentication
// Use this for services that need both external (via API gateway) and internal access
func CombinedAuth(jwtMiddleware *JWTMiddleware, internalAuth *InternalServiceAuth) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request has internal auth headers
		internalAuthHeader := c.GetHeader("X-Internal-Auth")

		if internalAuthHeader != "" {
			// Internal service call - validate internal auth
			internalAuth.Middleware()(c)
			if c.IsAborted() {
				return
			}

			// Extract forwarded user context
			userContext, err := ExtractForwardedUserContext(c)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid forwarded user context"})
				c.Abort()
				return
			}

			// Set user context in Gin context
			c.Set("user_id", userContext.UserID)
			c.Set("host_id", userContext.HostID)
			c.Set("email", userContext.Email)
			c.Set("email_verified", userContext.EmailVerified)
			c.Set("roles", userContext.Roles)
			c.Set("companies", userContext.Companies)
		} else {
			// External call via API gateway - validate JWT
			jwtMiddleware.Middleware()(c)
			if c.IsAborted() {
				return
			}
		}

		c.Next()
	}
}

// RequireAuth ensures user context exists (user is authenticated)
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// GenerateNonce generates a cryptographically secure random nonce
func GenerateNonce() (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

// ComputeHMAC computes HMAC signature (for testing)
func ComputeHMAC(secret, method, path, userID, hostID, roles, companies string, timestamp int64, nonce string, includeMethod, includePath bool) string {
	parts := []string{userID, hostID, roles, companies, fmt.Sprintf("%d", timestamp), nonce}

	if includeMethod {
		parts = append([]string{method}, parts...)
	}

	if includePath {
		if includeMethod {
			parts = append([]string{parts[0], path}, parts[1:]...)
		} else {
			parts = append([]string{path}, parts...)
		}
	}

	message := strings.Join(parts, ":")
	mac := hmac.New(sha3.New256, []byte(secret))
	mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
