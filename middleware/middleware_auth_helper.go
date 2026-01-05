package middleware

import (
	"net/http"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

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

// RequireRole ensures user has specific role
func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		if !userCtx.HasRole(role) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "insufficient permissions",
				"required_role": role,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyRole ensures user has at least one of the specified roles
func RequireAnyRole(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		for _, role := range roles {
			if userCtx.HasRole(role) {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{
			"error":          "insufficient permissions",
			"required_roles": roles,
		})
		c.Abort()
	}
}

// RequireEmailVerified ensures user's email is verified
func RequireEmailVerified() gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		if !userCtx.EmailVerified {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "email verification required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireCompanyAccess ensures user has access to specific company
func RequireCompanyAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		// Get company ID from URL parameter or query
		companyID := c.Param("companyId")
		if companyID == "" {
			companyID = c.Query("companyId")
		}
		if companyID == "" {
			companyID = c.Param("company_id")
		}

		if companyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "company_id required",
			})
			c.Abort()
			return
		}

		if !userCtx.HasCompanyAccess(companyID) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":      "no access to this company",
				"company_id": companyID,
			})
			c.Abort()
			return
		}

		// Store company ID in context for handler use
		c.Set("company_id", companyID)
		c.Next()
	}
}

// RequireCompanyRole ensures user has specific role for a company
func RequireCompanyRole(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userCtx, exists := models.GetUserContext(c)
		if !exists || userCtx == nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "authentication required",
			})
			c.Abort()
			return
		}

		companyID := c.Param("companyId")
		if companyID == "" {
			companyID = c.Query("companyId")
		}
		if companyID == "" {
			companyID = c.Param("company_id")
		}

		if companyID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "company_id required",
			})
			c.Abort()
			return
		}

		if !userCtx.HasCompanyRole(companyID, requiredRole) {
			c.JSON(http.StatusForbidden, gin.H{
				"error":         "insufficient permissions for this company",
				"company_id":    companyID,
				"required_role": requiredRole,
			})
			c.Abort()
			return
		}

		c.Set("company_id", companyID)
		c.Next()
	}
}
