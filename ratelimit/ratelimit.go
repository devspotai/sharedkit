package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter provides distributed rate limiting using Redis
// Implements sliding window rate limiting for accurate request counting
type Limiter struct {
	client    redis.Cmdable
	keyPrefix string
}

// LimiterConfig holds configuration for the rate limiter
type LimiterConfig struct {
	// KeyPrefix for Redis keys (default: "ratelimit:")
	KeyPrefix string
}

// NewLimiter creates a new distributed rate limiter
func NewLimiter(client redis.Cmdable, cfg LimiterConfig) *Limiter {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "ratelimit:"
	}

	return &Limiter{
		client:    client,
		keyPrefix: cfg.KeyPrefix,
	}
}

// Result contains rate limit check results
type Result struct {
	// Allowed indicates if the request should be allowed
	Allowed bool
	// Remaining is the number of requests remaining in the window
	Remaining int64
	// ResetAt is when the rate limit window resets
	ResetAt time.Time
	// RetryAfter is the duration to wait before retrying (if not allowed)
	RetryAfter time.Duration
}

// Allow checks if a request should be allowed under the rate limit
// key: unique identifier (e.g., "user:123", "ip:192.168.1.1")
// limit: maximum number of requests allowed
// window: time window for the limit
func (l *Limiter) Allow(ctx context.Context, key string, limit int64, window time.Duration) (*Result, error) {
	return l.AllowN(ctx, key, limit, window, 1)
}

// AllowN checks if N requests should be allowed (for batch operations)
func (l *Limiter) AllowN(ctx context.Context, key string, limit int64, window time.Duration, n int64) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window)
	resetAt := now.Add(window)

	redisKey := l.keyPrefix + key

	// Use sliding window log algorithm with sorted set
	// Score = timestamp, Member = unique request ID (timestamp with counter)
	pipe := l.client.Pipeline()

	// Remove old entries outside the window
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current entries in window
	countCmd := pipe.ZCard(ctx, redisKey)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline error: %w", err)
	}

	currentCount := countCmd.Val()
	remaining := limit - currentCount

	// Check if we can allow this request
	if remaining < n {
		// Rate limited - calculate retry after
		// Get the oldest entry to determine when space will be available
		oldestEntries, err := l.client.ZRangeWithScores(ctx, redisKey, 0, 0).Result()
		if err != nil {
			return nil, fmt.Errorf("redis error getting oldest entry: %w", err)
		}

		var retryAfter time.Duration
		if len(oldestEntries) > 0 {
			oldestTime := time.Unix(0, int64(oldestEntries[0].Score))
			retryAfter = oldestTime.Add(window).Sub(now)
			if retryAfter < 0 {
				retryAfter = 0
			}
		}

		return &Result{
			Allowed:    false,
			Remaining:  0,
			ResetAt:    resetAt,
			RetryAfter: retryAfter,
		}, nil
	}

	// Add new entries for this request
	members := make([]redis.Z, n)
	for i := int64(0); i < n; i++ {
		members[i] = redis.Z{
			Score:  float64(now.UnixNano() + i), // Unique timestamp for each
			Member: fmt.Sprintf("%d-%d", now.UnixNano(), i),
		}
	}

	pipe2 := l.client.Pipeline()
	pipe2.ZAdd(ctx, redisKey, members...)
	pipe2.Expire(ctx, redisKey, window+time.Second) // TTL slightly longer than window
	_, err = pipe2.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline error adding entries: %w", err)
	}

	return &Result{
		Allowed:   true,
		Remaining: remaining - n,
		ResetAt:   resetAt,
	}, nil
}

// GetStatus returns current rate limit status without consuming a request
func (l *Limiter) GetStatus(ctx context.Context, key string, limit int64, window time.Duration) (*Result, error) {
	now := time.Now()
	windowStart := now.Add(-window)
	resetAt := now.Add(window)

	redisKey := l.keyPrefix + key

	// Remove old entries and count current
	pipe := l.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", windowStart.UnixNano()))
	countCmd := pipe.ZCard(ctx, redisKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis pipeline error: %w", err)
	}

	currentCount := countCmd.Val()
	remaining := limit - currentCount
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:   remaining > 0,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}

// Reset clears the rate limit for a key
func (l *Limiter) Reset(ctx context.Context, key string) error {
	redisKey := l.keyPrefix + key
	return l.client.Del(ctx, redisKey).Err()
}

// FixedWindowAllow implements simpler fixed window rate limiting
// More efficient but less accurate at window boundaries
func (l *Limiter) FixedWindowAllow(ctx context.Context, key string, limit int64, window time.Duration) (*Result, error) {
	now := time.Now()
	windowKey := fmt.Sprintf("%s%s:%d", l.keyPrefix, key, now.Unix()/int64(window.Seconds()))
	resetAt := now.Truncate(window).Add(window)

	// Increment counter
	count, err := l.client.Incr(ctx, windowKey).Result()
	if err != nil {
		return nil, fmt.Errorf("redis error incrementing counter: %w", err)
	}

	// Set expiry on first request
	if count == 1 {
		l.client.Expire(ctx, windowKey, window+time.Second)
	}

	if count > limit {
		return &Result{
			Allowed:    false,
			Remaining:  0,
			ResetAt:    resetAt,
			RetryAfter: time.Until(resetAt),
		}, nil
	}

	return &Result{
		Allowed:   true,
		Remaining: limit - count,
		ResetAt:   resetAt,
	}, nil
}

// TokenBucketAllow implements token bucket rate limiting
// Allows bursting while maintaining average rate
func (l *Limiter) TokenBucketAllow(ctx context.Context, key string, bucketSize int64, refillRate float64) (*Result, error) {
	now := time.Now()
	redisKey := l.keyPrefix + "bucket:" + key

	// Lua script for atomic token bucket operation
	script := redis.NewScript(`
		local key = KEYS[1]
		local bucket_size = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		local requested = tonumber(ARGV[4])

		local bucket = redis.call('HMGET', key, 'tokens', 'last_update')
		local tokens = tonumber(bucket[1]) or bucket_size
		local last_update = tonumber(bucket[2]) or now

		-- Calculate tokens to add based on time elapsed
		local elapsed = now - last_update
		local tokens_to_add = elapsed * refill_rate
		tokens = math.min(bucket_size, tokens + tokens_to_add)

		-- Check if we have enough tokens
		if tokens < requested then
			-- Calculate wait time for enough tokens
			local needed = requested - tokens
			local wait_time = needed / refill_rate
			return {0, tokens, wait_time}
		end

		-- Consume tokens
		tokens = tokens - requested
		redis.call('HMSET', key, 'tokens', tokens, 'last_update', now)
		redis.call('EXPIRE', key, 3600)

		return {1, tokens, 0}
	`)

	result, err := script.Run(ctx, l.client, []string{redisKey},
		bucketSize, refillRate, float64(now.UnixNano())/1e9, 1).Slice()
	if err != nil {
		return nil, fmt.Errorf("redis script error: %w", err)
	}

	allowed := result[0].(int64) == 1
	remaining := int64(result[1].(int64))
	waitTime := result[2].(int64)

	return &Result{
		Allowed:    allowed,
		Remaining:  remaining,
		RetryAfter: time.Duration(waitTime) * time.Second,
	}, nil
}
