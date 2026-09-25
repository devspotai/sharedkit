package zitadel

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/devspotai/sharedkit/authn"
	"github.com/devspotai/sharedkit/models"
)

// TokenValidator verifies an access token and returns its claims. *Validator
// implements it; the interface lets a router be exercised without a live JWKS
// endpoint.
type TokenValidator interface {
	Validate(ctx context.Context, token string) (*Claims, error)
}

// UserResolver maps a Zitadel subject to the service's own user, provisioning
// the user on first sign-in. created reports whether it did.
type UserResolver interface {
	ResolveUserID(ctx context.Context, idpSubject string) (userID string, created bool, err error)
}

// TokenRefreshRequiredHeader tells the client that retrying with a freshly
// issued token will succeed.
const TokenRefreshRequiredHeader = "X-Token-Refresh-Required"

// ErrTokenRefreshRequired is returned on first sign-in, when the access token
// does not yet carry the app_uid metadata claim. Provisioning writes that claim
// back to Zitadel out of band, so the token in hand can never gain it; the
// client has to fetch a new one and retry.
var ErrTokenRefreshRequired = errors.New("idp token refresh required")

// Authenticator is an authn.Authenticator for Zitadel bearer tokens.
type Authenticator struct {
	validator TokenValidator
	users     UserResolver
}

var _ authn.Authenticator = (*Authenticator)(nil)

// NewAuthenticator returns an Authenticator. Both arguments are required.
func NewAuthenticator(v TokenValidator, users UserResolver) (*Authenticator, error) {
	if v == nil {
		return nil, errors.New("zitadel: NewAuthenticator requires a TokenValidator")
	}
	if users == nil {
		return nil, errors.New("zitadel: NewAuthenticator requires a UserResolver")
	}
	return &Authenticator{validator: v, users: users}, nil
}

// Authenticate verifies the bearer token and returns the caller's identity and
// project roles. It does not load company roles; see authz.LoadCompanyRoles.
func (a *Authenticator) Authenticate(r *http.Request) (*models.UserContext, error) {
	ctx := r.Context()

	token, err := authn.ExtractBearer(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}

	claims, err := a.validator.Validate(ctx, token)
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return nil, fmt.Errorf("%w: %w", authn.ErrUnavailable, err)
		}
		return nil, err
	}

	if claims.UserID == "" {
		// First sign-in: provision, then make the client come back with a
		// token that carries the metadata this one lacks.
		if _, _, err := a.users.ResolveUserID(ctx, claims.Subject); err != nil {
			return nil, &authn.Error{
				Status:  http.StatusServiceUnavailable,
				Message: "could not provision user",
				Err:     err,
			}
		}
		return nil, &authn.Error{
			Status:  http.StatusUnauthorized,
			Message: "token_refresh_required",
			Details: "Your account has been created. Please refresh your token and retry.",
			Headers: map[string]string{TokenRefreshRequiredHeader: "true"},
			Err:     ErrTokenRefreshRequired,
		}
	}

	return &models.UserContext{
		UserID:        claims.UserID,
		HostID:        claims.HostID,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Roles:         claims.ProjectRoles,
		Subject:       claims.Subject,
	}, nil
}
