package client

import (
	"context"
	"fmt"
	"time"
)

type CachedClient struct {
	KeycloakClient *KeycloakClient
	cache          *RedisCache
}

func NewCachedClient(keycloakClient *KeycloakClient, cache *RedisCache) *CachedClient {
	return &CachedClient{
		KeycloakClient: keycloakClient,
		cache:          cache,
	}
}

// GetPublicKey with caching
func (c *CachedClient) GetPublicKey(kid string) (interface{}, error) {
	ctx := context.Background()
	cacheKey := fmt.Sprintf("keycloak:public_key:%s", kid)

	// Try cache first
	var cachedKey interface{}
	if err := c.cache.Get(ctx, cacheKey, &cachedKey); err == nil {
		return cachedKey, nil
	}

	// Cache miss - fetch from Keycloak
	publicKey, err := c.KeycloakClient.fetchPublicKey()
	if err != nil {
		return nil, err
	}

	// Cache for 24 hours (public keys rarely change)
	c.cache.Set(ctx, cacheKey, publicKey, 24*time.Hour)

	return publicKey, nil
}

// GetAdminToken with caching
func (c *CachedClient) GetAdminToken() (string, error) {
	ctx := context.Background()
	cacheKey := "keycloak:admin_token"

	// Try cache first
	var cachedToken string
	if err := c.cache.Get(ctx, cacheKey, &cachedToken); err == nil {
		return cachedToken, nil
	}

	// Cache miss - get new token
	token, err := c.KeycloakClient.GetAdminToken()
	if err != nil {
		return "", err
	}

	// Cache for 4 minutes (tokens expire in 5 minutes)
	c.cache.Set(ctx, cacheKey, token, 4*time.Minute)

	return token, nil
}

// UpdateUserAttributes with cache invalidation
func (c *CachedClient) UpdateUserAttributes(keycloakUserID string, attributes map[string][]string, adminToken string) error {
	ctx := context.Background()

	// Update in Keycloak
	if err := c.KeycloakClient.UpdateUserAttributes(keycloakUserID, adminToken, attributes); err != nil {
		return err
	}

	// Invalidate related caches
	c.cache.DeletePattern(ctx, fmt.Sprintf("user:*:%s:*", keycloakUserID))

	return nil
}
