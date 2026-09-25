// Package zitadel is deprecated: it moved to authn/zitadel. These aliases keep
// existing imports compiling.
package zitadel

import zitadel "github.com/devspotai/sharedkit/authn/zitadel"

// Deprecated: use the authn/zitadel types.
type (
	Config        = zitadel.Config
	Claims        = zitadel.Claims
	Validator     = zitadel.Validator
	KeyCache      = zitadel.KeyCache
	RedisKeyCache = zitadel.RedisKeyCache
)

// Deprecated: use the authn/zitadel functions and errors.
var (
	New              = zitadel.New
	NewRedisKeyCache = zitadel.NewRedisKeyCache

	ErrTokenInvalid    = zitadel.ErrTokenInvalid
	ErrWrongTenant     = zitadel.ErrWrongTenant
	ErrKeysUnavailable = zitadel.ErrKeysUnavailable
)
