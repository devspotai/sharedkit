package auth

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// SignatureVerificationMiddleware creates Gin middleware to verify request signatures
func (s *RequestSigner) SignatureVerificationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Read body for signature verification
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			// Restore body for later use
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		if err := s.VerifyRequest(c.Request); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "signature verification failed",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		// Restore body again after verification
		if bodyBytes != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		c.Next()
	}
}

// OptionalSignatureVerificationMiddleware verifies signature if present, but allows unsigned requests
func (s *RequestSigner) OptionalSignatureVerificationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if signature headers are present
		if c.GetHeader(s.headerPrefix+"Signature") == "" {
			// No signature - mark as unsigned and continue
			c.Set("request_signed", false)
			c.Next()
			return
		}

		// Read body for signature verification
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		if err := s.VerifyRequest(c.Request); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "signature verification failed",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		// Restore body and mark as signed
		if bodyBytes != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		c.Set("request_signed", true)

		c.Next()
	}
}

// IsRequestSigned checks if the current request was signed (after OptionalSignatureVerificationMiddleware)
func IsRequestSigned(c *gin.Context) bool {
	signed, exists := c.Get("request_signed")
	if !exists {
		return false
	}
	return signed.(bool)
}
