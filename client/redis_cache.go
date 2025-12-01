package client

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
}

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

	return &RedisCache{client: client}, nil
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

	return &RedisCache{client: client}
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
