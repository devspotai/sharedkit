package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/devspotai/sharedkit/models"
)

// InternalServiceAuth middleware ensures only Traefik can call internal services
// This prevents malicious clients from injecting headers to bypass authentication
type InternalServiceAuth struct {
	sharedSecret string
	headerName   string
	timestampTTL time.Duration
}

// NewInternalServiceAuth creates a new internal service authentication middleware
func NewInternalServiceAuth(sharedSecret string) *InternalServiceAuth {
	return &InternalServiceAuth{
		sharedSecret: sharedSecret,
		headerName:   "X-Internal-Auth",
		timestampTTL: 5 * time.Minute, // Prevent replay attacks
	}
}

// Middleware returns the Gin middleware handler
func (i *InternalServiceAuth) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request comes from Traefik
		authHeader := c.GetHeader(i.headerName)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized: missing internal authentication header",
			})
			c.Abort()
			return
		}

		// Extract timestamp from header
		timestamp := c.GetHeader("X-Internal-Timestamp")
		if timestamp == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized: missing timestamp header",
			})
			c.Abort()
			return
		}

		// Verify timestamp to prevent replay attacks
		if !i.verifyTimestamp(timestamp) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized: timestamp expired or invalid",
			})
			c.Abort()
			return
		}

		// Verify HMAC signature
		if !i.verifySignature(authHeader, timestamp) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized: invalid signature",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// verifyTimestamp checks if the timestamp is within acceptable range
func (i *InternalServiceAuth) verifyTimestamp(timestamp string) bool {
	requestTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return false
	}

	now := time.Now()
	diff := now.Sub(requestTime)

	// Check if timestamp is within TTL and not in the future
	return diff >= 0 && diff <= i.timestampTTL
}

// verifySignature verifies the HMAC signature
func (i *InternalServiceAuth) verifySignature(signature, timestamp string) bool {
	expectedSignature := i.generateSignature(timestamp)
	return hmac.Equal([]byte(signature), []byte(expectedSignature))
}

// generateSignature generates HMAC signature for the timestamp
func (i *InternalServiceAuth) generateSignature(timestamp string) string {
	h := hmac.New(sha256.New, []byte(i.sharedSecret))
	h.Write([]byte(timestamp))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateAuthHeaders generates authentication headers for internal service calls
// This should only be used by Traefik
func (i *InternalServiceAuth) GenerateAuthHeaders() map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := i.generateSignature(timestamp)

	return map[string]string{
		i.headerName:           signature,
		"X-Internal-Timestamp": timestamp,
	}
}

// ForwardedUserHeaders represents user context forwarded from API gateway
type ForwardedUserHeaders struct {
	UserID        string
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
