// Package authn is the seam between a service's authentication and sharedkit's
// authorization.
//
// Authentication is each service's own business: which identity provider it
// trusts, how tokens arrive, how users are provisioned. authz only needs the
// result — a *models.UserContext on the request. A service implements
// Authenticator for its IdP and mounts Middleware; everything in authz then
// works unchanged. authn/zitadel is one ready-made Authenticator.
//
// Typical chain:
//
//	router.Use(authn.Middleware(myAuthenticator, authn.Options{PublicPaths: public}))
//	router.Use(authz.LoadCompanyRoles(roleSource))
//	group.Use(engine.AuthorizeCompanyAccess(authz.StaysDomainConfig()))
package authn

import (
	"errors"
	"net/http"
	"strings"

	"github.com/devspotai/sharedkit/models"
	"github.com/gin-gonic/gin"
)

// Authenticator establishes who is calling. It returns the principal for a
// valid request, or an error saying why there is none.
//
// Errors map to responses as follows: an *Error controls the response itself;
// anything wrapping ErrUnavailable is a 503 (our dependency failed, not the
// caller); everything else is a 401.
//
// The principal carries identity and global roles only. Company roles are
// authorization data, loaded afterwards by authz.LoadCompanyRoles.
type Authenticator interface {
	Authenticate(r *http.Request) (*models.UserContext, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request) (*models.UserContext, error)

func (f AuthenticatorFunc) Authenticate(r *http.Request) (*models.UserContext, error) { return f(r) }

// ErrUnavailable marks a failure that is the service's fault, such as an
// unreachable identity provider. Wrap it so the caller gets 503, not 401 —
// an outage must not look like a bad credential.
var ErrUnavailable = errors.New("authn: authentication unavailable")

// Error lets an Authenticator shape the response, e.g. to tell a client to
// refresh its token.
type Error struct {
	Status  int
	Message string
	Details string
	Headers map[string]string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Options configures Middleware.
type Options struct {
	// PublicPaths skip authentication. Each entry is matched against the gin
	// route pattern (e.g. "/api/v1/destinations/:destination/facts") and the
	// literal request path.
	PublicPaths []string
}

// Middleware authenticates every request except those on a public path and
// stores the principal where authz and handlers read it.
func Middleware(a Authenticator, opts Options) gin.HandlerFunc {
	public := NewPathMatcher(opts.PublicPaths)
	return func(c *gin.Context) {
		if public.Match(c) {
			c.Next()
			return
		}
		if !Authenticate(c, a) {
			return
		}
		c.Next()
	}
}

// Authenticate runs a and either stores the principal or aborts the request.
// It does not call c.Next, so middleware can compose it with other steps. It
// returns false if it aborted.
func Authenticate(c *gin.Context, a Authenticator) bool {
	uc, err := a.Authenticate(c.Request)
	if err == nil && uc == nil {
		err = errors.New("authn: authenticator returned no principal")
	}
	if err != nil {
		abort(c, err)
		return false
	}
	SetPrincipal(c, uc)
	return true
}

// SetPrincipal stores the authenticated user on the request. Use it from a
// custom authentication middleware that does not go through Authenticate.
func SetPrincipal(c *gin.Context, uc *models.UserContext) {
	c.Set(models.UserContextKey, uc)
}

func abort(c *gin.Context, err error) {
	var ae *Error
	if errors.As(err, &ae) {
		for k, v := range ae.Headers {
			c.Header(k, v)
		}
		status := ae.Status
		if status == 0 {
			status = http.StatusUnauthorized
		}
		c.AbortWithStatusJSON(status, models.GetErrorResponse(ae.Message, status, ae.Details))
		return
	}
	status := http.StatusUnauthorized
	if errors.Is(err, ErrUnavailable) {
		status = http.StatusServiceUnavailable
	}
	// The detail is deliberately not err.Error(): it would tell a caller
	// whether its token failed on signature, issuer or audience.
	c.AbortWithStatusJSON(status, models.GetErrorResponse("unauthorized", status, ""))
}

// PathMatcher reports whether a request is on a configured path.
type PathMatcher struct{ paths map[string]bool }

// NewPathMatcher builds a PathMatcher for paths.
func NewPathMatcher(paths []string) PathMatcher {
	m := PathMatcher{paths: make(map[string]bool, len(paths))}
	for _, p := range paths {
		m.paths[p] = true
	}
	return m
}

// Match checks the route pattern first, then the literal path.
//
// The pattern is what callers configure and what gin exposes as FullPath once
// a route matches. Comparing only the request path would treat every
// parameterised public route as protected, because
// "/api/v1/destinations/PT/facts" is never in the list. The literal comparison
// covers routes registered without a pattern.
func (m PathMatcher) Match(c *gin.Context) bool {
	if len(m.paths) == 0 {
		return false
	}
	if pattern := c.FullPath(); pattern != "" && m.paths[pattern] {
		return true
	}
	return m.paths[c.Request.URL.Path]
}

// ExtractBearer pulls the token out of an Authorization header, rejecting
// obviously malformed values before any cryptography is attempted.
func ExtractBearer(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing authorization header")
	}
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return "", errors.New("authorization header is not a bearer token")
	}
	// A JWT is normally 100-4000 bytes; 8KB is a generous ceiling that stops a
	// large value being fed to the parser.
	if len(token) > 8192 {
		return "", errors.New("bearer token too large")
	}
	if strings.Count(token, ".") != 2 {
		return "", errors.New("bearer token is not a three-part JWT")
	}
	return token, nil
}
