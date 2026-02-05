package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// JTITracker tracks JWT IDs to prevent replay attacks
// Each JWT should have a unique JTI claim that is checked against this tracker
type JTITracker struct {
	client    redis.Cmdable
	keyPrefix string
	// DefaultTTL is used when token expiry is not provided
	// Should match or slightly exceed your JWT expiry time
	DefaultTTL time.Duration
}

// JTITrackerConfig holds configuration for JTI tracking
type JTITrackerConfig struct {
	// KeyPrefix for Redis keys (default: "jti:")
	KeyPrefix string
	// DefaultTTL for tracking entries when expiry is not provided
	DefaultTTL time.Duration
}

// DefaultJTITrackerConfig returns sensible defaults
func DefaultJTITrackerConfig() JTITrackerConfig {
	return JTITrackerConfig{
		KeyPrefix:  "jti:",
		DefaultTTL: 15 * time.Minute,
	}
}

// NewJTITracker creates a new JTI tracker
func NewJTITracker(client redis.Cmdable, cfg JTITrackerConfig) *JTITracker {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "jti:"
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}

	return &JTITracker{
		client:     client,
		keyPrefix:  cfg.KeyPrefix,
		DefaultTTL: cfg.DefaultTTL,
	}
}

// CheckAndMark atomically checks if a JTI has been used and marks it as used
// Returns nil if the JTI is valid (not seen before)
// Returns ErrTokenReplay if the JTI has already been used
// This is the recommended method as it's atomic and race-condition safe
func (t *JTITracker) CheckAndMark(ctx context.Context, jti string, expiry time.Time) error {
	if jti == "" {
		return fmt.Errorf("empty JTI")
	}

	key := t.key(jti)
	ttl := t.calculateTTL(expiry)

	// SETNX returns true if key was set (JTI not seen before)
	// Returns false if key already exists (replay attack!)
	wasSet, err := t.client.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		return fmt.Errorf("redis error checking JTI: %w", err)
	}

	if !wasSet {
		return ErrTokenReplay
	}

	return nil
}

// IsUsed checks if a JTI has been used before (non-marking read)
// Use CheckAndMark for atomic check-and-mark operations
func (t *JTITracker) IsUsed(ctx context.Context, jti string) (bool, error) {
	if jti == "" {
		return false, fmt.Errorf("empty JTI")
	}

	key := t.key(jti)
	exists, err := t.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("redis error checking JTI: %w", err)
	}

	return exists > 0, nil
}

// MarkUsed marks a JTI as used without checking first
// Use this only if you've already verified the JTI hasn't been used
// Prefer CheckAndMark for atomic operations
func (t *JTITracker) MarkUsed(ctx context.Context, jti string, expiry time.Time) error {
	if jti == "" {
		return fmt.Errorf("empty JTI")
	}

	key := t.key(jti)
	ttl := t.calculateTTL(expiry)

	err := t.client.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("redis error marking JTI: %w", err)
	}

	return nil
}

// Revoke explicitly revokes a JTI (marks it as used with extended TTL)
// Use this for logout or token invalidation scenarios
func (t *JTITracker) Revoke(ctx context.Context, jti string, extendedTTL time.Duration) error {
	if jti == "" {
		return fmt.Errorf("empty JTI")
	}

	key := t.key(jti)
	if extendedTTL == 0 {
		extendedTTL = 24 * time.Hour // Default extended TTL for revocations
	}

	err := t.client.Set(ctx, key, "revoked", extendedTTL).Err()
	if err != nil {
		return fmt.Errorf("redis error revoking JTI: %w", err)
	}

	return nil
}

// RevokeAllForUser revokes all tokens for a user by storing a "revoked after" timestamp
// Tokens issued before this timestamp should be rejected
func (t *JTITracker) RevokeAllForUser(ctx context.Context, userID string, ttl time.Duration) error {
	if userID == "" {
		return fmt.Errorf("empty user ID")
	}

	key := t.keyPrefix + "user_revoked:" + userID
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	timestamp := time.Now().Unix()
	err := t.client.Set(ctx, key, timestamp, ttl).Err()
	if err != nil {
		return fmt.Errorf("redis error revoking user tokens: %w", err)
	}

	return nil
}

// IsUserTokenRevoked checks if a token issued at a given time is revoked for a user
// Returns true if the token was issued before the user's revocation timestamp
func (t *JTITracker) IsUserTokenRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	if userID == "" {
		return false, fmt.Errorf("empty user ID")
	}

	key := t.keyPrefix + "user_revoked:" + userID
	result, err := t.client.Get(ctx, key).Result()
	if err == redis.Nil {
		// No revocation record - token is valid
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("redis error checking user revocation: %w", err)
	}

	var revokedAfter int64
	if _, err := fmt.Sscanf(result, "%d", &revokedAfter); err != nil {
		return false, fmt.Errorf("invalid revocation timestamp: %w", err)
	}

	// Token is revoked if it was issued before the revocation timestamp
	return issuedAt.Unix() < revokedAfter, nil
}

func (t *JTITracker) key(jti string) string {
	return t.keyPrefix + jti
}

func (t *JTITracker) calculateTTL(expiry time.Time) time.Duration {
	if expiry.IsZero() {
		return t.DefaultTTL
	}

	ttl := time.Until(expiry)
	if ttl <= 0 {
		// Token already expired, use minimal TTL
		return time.Second
	}

	// Add small buffer to account for clock skew
	return ttl + 30*time.Second
}

// ErrTokenReplay indicates a replay attack was detected
var ErrTokenReplay = fmt.Errorf("token replay detected: JTI already used")
