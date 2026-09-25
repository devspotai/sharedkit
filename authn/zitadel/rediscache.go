package zitadel

import (
	"context"
	"time"

	"github.com/devspotai/sharedkit/client/cache"
)

// RedisKeyCache persists the JWKS in Redis or Valkey so a process that restarts
// while the identity provider is unreachable still has keys to verify with.
//
// The entry is shared by every replica, so the first one to fetch after a
// rotation warms it for the rest.
type RedisKeyCache struct {
	cache *cache.RedisCache
}

// NewRedisKeyCache adapts sharedkit's Redis client to the KeyCache interface.
// A nil client yields a nil cache, which Config.KeyCache treats as absent.
func NewRedisKeyCache(c *cache.RedisCache) *RedisKeyCache {
	if c == nil {
		return nil
	}
	return &RedisKeyCache{cache: c}
}

// GetJWKS returns the stored key set, or an error on a miss.
func (r *RedisKeyCache) GetJWKS(ctx context.Context, key string) ([]byte, error) {
	// Stored as a JSON string rather than raw bytes: RedisCache.Set marshals
	// whatever it is given, and a []byte would come back base64-encoded.
	var encoded string
	if err := r.cache.Get(ctx, key, &encoded); err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

func (r *RedisKeyCache) PutJWKS(ctx context.Context, key string, raw []byte, ttl time.Duration) error {
	return r.cache.Set(ctx, key, string(raw), ttl)
}

// compile-time check
var _ KeyCache = (*RedisKeyCache)(nil)
