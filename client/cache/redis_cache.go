package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/devspotai/sharedkit/config"
	"github.com/redis/go-redis/v9"
)

var (
	ErrKeyNotFound             = fmt.Errorf("key not found")
	ErrRedisDown               = fmt.Errorf("redis is down")
	ErrFailedToConnect         = fmt.Errorf("failed to connect to redis")
	ErrRedisHealthCheckFailure = fmt.Errorf("redis health check failed")
	ErrUnmarshalCacheValue     = fmt.Errorf("failed to unmarshal cache value")
)

type RedisCache struct {
	client *redis.Client
	ttl    time.Duration
}

type SetOp struct {
	Key   string
	Value string
	TTL   time.Duration
}

type PipelineSetter func(key string, value any, ttl time.Duration)
type PipelineDeleter func(key string)

func NewRedisCache(addr, password string, db int) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToConnect, err)
	}

	return &RedisCache{client: client, ttl: 5 * time.Minute}, nil
}

func NewRedisCacheFromConfig(cfg *config.RedisConfig) *RedisCache {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.URL,
		Password:     cfg.Password,
		DB:           cfg.DB,
		MaxRetries:   cfg.MaxRetries,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
	})

	return &RedisCache{client: client, ttl: time.Duration(cfg.DefaultTTLSeconds) * time.Second}
}

func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, key, data, expiration).Err()
}

func (r *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return ErrKeyNotFound
	}
	if err != nil {
		return err
	}

	return fmt.Errorf("%w: %v", ErrUnmarshalCacheValue, json.Unmarshal([]byte(data), dest))
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisCache) DeletePattern(ctx context.Context, pattern string) error {
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		r.client.Del(ctx, iter.Val())
	}
	return iter.Err()
}

// HealthCheck performs a health check on the Redis connection
func (r *RedisCache) HealthCheck(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrRedisHealthCheckFailure, err)
	}
	return nil
}

func (c *RedisCache) WithPipeline(ctx context.Context,
	fn func(set PipelineSetter, del PipelineDeleter) error) error {

	pipe := c.client.TxPipeline()

	setter := func(key string, value any, ttl time.Duration) {
		pipe.Set(ctx, key, value, ttl)
	}

	deleter := func(key string) {
		pipe.Del(ctx, key)
	}

	// Let the caller queue ops
	if err := fn(setter, deleter); err != nil {
		// caller error before Exec
		return err
	}

	// Execute all at once
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("cache pipeline Exec failed: %w", err)
	}

	return nil
}

// DeleteMany removes multiple keys using a TxPipeline.
// The caller never sees redis.Pipeliner.
func (c *RedisCache) DeleteMany(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	pipe := c.client.TxPipeline()

	for _, k := range keys {
		pipe.Del(ctx, k)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("cache pipeline DEL failed: %w", err)
	}

	return nil
}

// SetMany sets multiple keys in a single Redis TxPipeline.
// The caller never sees redis.Pipeliner.
func (c *RedisCache) SetMany(ctx context.Context, ops []SetOp) error {
	if len(ops) == 0 {
		return nil
	}

	pipe := c.client.TxPipeline()

	for _, op := range ops {
		ttl := op.TTL
		if ttl == 0 {
			ttl = c.ttl
		}
		pipe.Set(ctx, op.Key, op.Value, ttl)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("cache pipeline Exec failed: %w", err)
	}

	return nil
}
