package authz

import (
	"errors"

	"github.com/gin-gonic/gin"
)

var (
	errCompanyIDMissing  = errors.New("company_id required")
	errCompanyIDConflict = errors.New("conflicting company_id in request")
)

// resolveCompanyID returns the company a request targets. Path parameters
// ("companyId", then "company_id") take precedence; the "companyId" query
// parameter is only used on routes that have no company path segment.
//
// Every company authorization check must use this so the company that was
// authorised is the one the handler acts on. Any request naming more than one
// distinct company (e.g. /companies/:company_id/x?companyId=other) is
// rejected rather than resolved, because handlers may read any of the sources.
func resolveCompanyID(c *gin.Context) (string, error) {
	var id string
	for _, candidate := range []string{
		c.Param("companyId"),
		c.Param("company_id"),
		c.Query("companyId"),
	} {
		if candidate == "" {
			continue
		}
		if id == "" {
			id = candidate
		} else if candidate != id {
			return "", errCompanyIDConflict
		}
	}
	if id == "" {
		return "", errCompanyIDMissing
	}
	return id, nil
}
