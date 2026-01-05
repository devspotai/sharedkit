// sys-backend-common/middleware/cors.go
package middleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// CORS returns a middleware that handles CORS headers with default configuration
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// CORSWithConfig returns a CORS middleware with custom configuration
func CORSWithConfig(config CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check if origin is allowed
		if config.AllowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", config.AllowOrigin)
		} else if len(config.AllowOrigins) > 0 {
			// Check if request origin is in allowed list
			for _, allowedOrigin := range config.AllowOrigins {
				if origin == allowedOrigin {
					c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
					break
				}
			}
		} else {
			// Default: allow all
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}

		if config.AllowCredentials {
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		// Set allowed headers
		if len(config.AllowHeaders) > 0 {
			headers := ""
			for i, h := range config.AllowHeaders {
				if i > 0 {
					headers += ", "
				}
				headers += h
			}
			c.Writer.Header().Set("Access-Control-Allow-Headers", headers)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}

		// Set allowed methods
		if len(config.AllowMethods) > 0 {
			methods := ""
			for i, m := range config.AllowMethods {
				if i > 0 {
					methods += ", "
				}
				methods += m
			}
			c.Writer.Header().Set("Access-Control-Allow-Methods", methods)
		} else {
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		}

		// Set max age
		if config.MaxAge > 0 {
			c.Writer.Header().Set("Access-Control-Max-Age", fmt.Sprintf("%d", config.MaxAge))
		}

		// Handle preflight
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// CORSConfig holds CORS configuration
type CORSConfig struct {
	AllowOrigin      string   // Single origin, or use AllowOrigins for multiple
	AllowOrigins     []string // Multiple allowed origins
	AllowMethods     []string // Allowed HTTP methods
	AllowHeaders     []string // Allowed headers
	AllowCredentials bool     // Allow credentials (cookies)
	MaxAge           int      // Preflight cache duration in seconds
}
