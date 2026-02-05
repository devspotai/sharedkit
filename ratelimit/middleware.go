package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// MiddlewareConfig holds configuration for rate limit middleware
type MiddlewareConfig struct {
	// Limit is the maximum number of requests allowed
	Limit int64
	// Window is the time window for the limit
	Window time.Duration
	// KeyFunc extracts the rate limit key from the request
	// Default: uses client IP
	KeyFunc func(*gin.Context) string
	// ErrorHandler is called when rate limit is exceeded
	// Default: returns 429 Too Many Requests
	ErrorHandler func(*gin.Context, *Result)
	// SkipFunc returns true to skip rate limiting for this request
	SkipFunc func(*gin.Context) bool
	// UseFixedWindow uses simpler fixed window algorithm (more efficient)
	UseFixedWindow bool
}

// DefaultKeyFunc returns the client IP as the rate limit key
func DefaultKeyFunc(c *gin.Context) string {
	// Check X-Forwarded-For first (for requests behind proxy)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		return "ip:" + xff
	}
	// Check X-Real-IP
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return "ip:" + xri
	}
	// Fall back to remote address
	return "ip:" + c.ClientIP()
}

// UserKeyFunc returns the user ID from context as the rate limit key
// Falls back to IP if user is not authenticated
func UserKeyFunc(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return "user:" + fmt.Sprintf("%v", userID)
	}
	return DefaultKeyFunc(c)
}

// EndpointKeyFunc returns a combination of method + path + IP
func EndpointKeyFunc(c *gin.Context) string {
	return fmt.Sprintf("endpoint:%s:%s:%s", c.Request.Method, c.FullPath(), c.ClientIP())
}

// DefaultErrorHandler returns a standard 429 response
func DefaultErrorHandler(c *gin.Context, result *Result) {
	c.Header("X-RateLimit-Remaining", "0")
	c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))
	if result.RetryAfter > 0 {
		c.Header("Retry-After", strconv.Itoa(int(result.RetryAfter.Seconds())))
	}

	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       "rate limit exceeded",
		"retry_after": int(result.RetryAfter.Seconds()),
		"reset_at":    result.ResetAt.Unix(),
	})
	c.Abort()
}

// Middleware creates a Gin middleware for rate limiting
func (l *Limiter) Middleware(cfg MiddlewareConfig) gin.HandlerFunc {
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultKeyFunc
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = DefaultErrorHandler
	}
	if cfg.Limit == 0 {
		cfg.Limit = 100
	}
	if cfg.Window == 0 {
		cfg.Window = time.Minute
	}

	return func(c *gin.Context) {
		// Check if we should skip rate limiting
		if cfg.SkipFunc != nil && cfg.SkipFunc(c) {
			c.Next()
			return
		}

		key := cfg.KeyFunc(c)

		var result *Result
		var err error

		if cfg.UseFixedWindow {
			result, err = l.FixedWindowAllow(c.Request.Context(), key, cfg.Limit, cfg.Window)
		} else {
			result, err = l.Allow(c.Request.Context(), key, cfg.Limit, cfg.Window)
		}

		if err != nil {
			// On Redis error, allow the request but log
			c.Header("X-RateLimit-Error", "true")
			c.Next()
			return
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.FormatInt(cfg.Limit, 10))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))

		if !result.Allowed {
			cfg.ErrorHandler(c, result)
			return
		}

		c.Next()
	}
}

// PerUserMiddleware creates rate limiting middleware keyed by user ID
func (l *Limiter) PerUserMiddleware(limit int64, window time.Duration) gin.HandlerFunc {
	return l.Middleware(MiddlewareConfig{
		Limit:   limit,
		Window:  window,
		KeyFunc: UserKeyFunc,
	})
}

// PerIPMiddleware creates rate limiting middleware keyed by client IP
func (l *Limiter) PerIPMiddleware(limit int64, window time.Duration) gin.HandlerFunc {
	return l.Middleware(MiddlewareConfig{
		Limit:   limit,
		Window:  window,
		KeyFunc: DefaultKeyFunc,
	})
}

// PerEndpointMiddleware creates rate limiting middleware keyed by endpoint + IP
func (l *Limiter) PerEndpointMiddleware(limit int64, window time.Duration) gin.HandlerFunc {
	return l.Middleware(MiddlewareConfig{
		Limit:   limit,
		Window:  window,
		KeyFunc: EndpointKeyFunc,
	})
}

// CombinedMiddleware applies multiple rate limits (user + IP + endpoint)
// All limits must pass for the request to be allowed
func (l *Limiter) CombinedMiddleware(configs ...MiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, cfg := range configs {
			if cfg.KeyFunc == nil {
				cfg.KeyFunc = DefaultKeyFunc
			}

			key := cfg.KeyFunc(c)
			result, err := l.Allow(c.Request.Context(), key, cfg.Limit, cfg.Window)
			if err != nil {
				continue // Skip on error
			}

			if !result.Allowed {
				handler := cfg.ErrorHandler
				if handler == nil {
					handler = DefaultErrorHandler
				}
				handler(c, result)
				return
			}
		}

		c.Next()
	}
}
