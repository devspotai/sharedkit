package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/devspotai/sharedkit/config"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	tracer trace.Tracer
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

	return &RedisCache{
		client: client,
		ttl:    5 * time.Minute,
		tracer: otel.Tracer("redis-cache"),
	}, nil
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

	return &RedisCache{
		client: client,
		ttl:    time.Duration(cfg.DefaultTTLSeconds) * time.Second,
		tracer: otel.Tracer("redis-cache"),
	}
}

func (r *RedisCache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	ctx, span := r.tracer.Start(ctx, "redis.set")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "SET"),
		attribute.String("cache.key", key),
	)

	data, err := json.Marshal(value)
	if err != nil {
		span.RecordError(err)
		return err
	}

	if err := r.client.Set(ctx, key, data, expiration).Err(); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

func (r *RedisCache) SetNX(ctx context.Context, key string, value []byte, expiration time.Duration) (bool, error) {
	ctx, span := r.tracer.Start(ctx, "redis.setnx")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "SETNX"),
		attribute.String("cache.key", key),
	)

	wasSet, err := r.client.SetNX(ctx, key, value, expiration).Result()
	if err != nil {
		span.RecordError(err)
		return false, err
	}

	span.SetAttributes(attribute.Bool("cache.key_set", wasSet))
	return wasSet, nil
}

func (r *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	ctx, span := r.tracer.Start(ctx, "redis.get")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "GET"),
		attribute.String("cache.key", key),
	)

	data, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return ErrKeyNotFound
	}
	if err != nil {
		span.RecordError(err)
		return err
	}

	span.SetAttributes(attribute.Bool("cache.hit", true))

	if err := json.Unmarshal([]byte(data), dest); err != nil {
		span.RecordError(err)
		return fmt.Errorf("%w: %v", ErrUnmarshalCacheValue, err)
	}
	return nil
}

func (r *RedisCache) GetRaw(ctx context.Context, key string) ([]byte, error) {
	ctx, span := r.tracer.Start(ctx, "redis.get_raw")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "GET"),
		attribute.String("cache.key", key),
	)

	data, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		span.SetAttributes(attribute.Bool("cache.hit", false))
		return nil, ErrKeyNotFound
	}
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	span.SetAttributes(attribute.Bool("cache.hit", true))
	return []byte(data), nil
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	ctx, span := r.tracer.Start(ctx, "redis.delete")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "DEL"),
		attribute.String("cache.key", key),
	)

	if err := r.client.Del(ctx, key).Err(); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

func (r *RedisCache) DeletePattern(ctx context.Context, pattern string) error {
	ctx, span := r.tracer.Start(ctx, "redis.delete_pattern")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "SCAN+DEL"),
		attribute.String("cache.pattern", pattern),
	)

	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	deletedCount := 0
	for iter.Next(ctx) {
		r.client.Del(ctx, iter.Val())
		deletedCount++
	}

	span.SetAttributes(attribute.Int("cache.deleted_count", deletedCount))

	if err := iter.Err(); err != nil {
		span.RecordError(err)
		return err
	}
	return nil
}

// HealthCheck performs a health check on the Redis connection
func (r *RedisCache) HealthCheck(ctx context.Context) error {
	ctx, span := r.tracer.Start(ctx, "redis.health_check")
	defer span.End()

	span.SetAttributes(attribute.String("db.system", "redis"))

	if err := r.client.Ping(ctx).Err(); err != nil {
		span.RecordError(err)
		return fmt.Errorf("%w: %v", ErrRedisHealthCheckFailure, err)
	}
	return nil
}

func (c *RedisCache) WithPipeline(ctx context.Context,
	fn func(set PipelineSetter, del PipelineDeleter) error) error {
	ctx, span := c.tracer.Start(ctx, "redis.pipeline")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "PIPELINE"),
	)

	pipe := c.client.TxPipeline()

	setter := func(key string, value any, ttl time.Duration) {
		pipe.Set(ctx, key, value, ttl)
	}

	deleter := func(key string) {
		pipe.Del(ctx, key)
	}

	// Let the caller queue ops
	if err := fn(setter, deleter); err != nil {
		span.RecordError(err)
		return err
	}

	// Execute all at once
	if _, err := pipe.Exec(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("cache pipeline Exec failed: %w", err)
	}

	return nil
}

// DeleteMany removes multiple keys using a TxPipeline.
// The caller never sees redis.Pipeliner.
func (c *RedisCache) DeleteMany(ctx context.Context, keys ...string) error {
	ctx, span := c.tracer.Start(ctx, "redis.delete_many")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "PIPELINE DEL"),
		attribute.Int("cache.keys_count", len(keys)),
	)

	if len(keys) == 0 {
		return nil
	}

	pipe := c.client.TxPipeline()

	for _, k := range keys {
		pipe.Del(ctx, k)
	}

	if _, err := pipe.Exec(ctx); err != nil {
		span.RecordError(err)
		return fmt.Errorf("cache pipeline DEL failed: %w", err)
	}

	return nil
}

// SetMany sets multiple keys in a single Redis TxPipeline.
// The caller never sees redis.Pipeliner.
func (c *RedisCache) SetMany(ctx context.Context, ops []SetOp) error {
	ctx, span := c.tracer.Start(ctx, "redis.set_many")
	defer span.End()

	span.SetAttributes(
		attribute.String("db.system", "redis"),
		attribute.String("db.operation", "PIPELINE SET"),
		attribute.Int("cache.keys_count", len(ops)),
	)

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
		span.RecordError(err)
		return fmt.Errorf("cache pipeline Exec failed: %w", err)
	}

	return nil
}

func (c *RedisCache) Close() error {
	return c.client.Close()
}
