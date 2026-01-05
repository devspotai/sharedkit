package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
	"github.com/golang-jwt/jwt/v5"
)

type CachedAuthClient struct {
	KeycloakClient *KeycloakClient
	cache          *cache.RedisCache
}

func NewCachedAuthClient(keycloakClient *KeycloakClient, cache *cache.RedisCache) *CachedAuthClient {
	return &CachedAuthClient{
		KeycloakClient: keycloakClient,
		cache:          cache,
	}
}

func (c *CachedAuthClient) getCacheKeyPrefix() string {
	return fmt.Sprintf("jwks:%s:", c.KeycloakClient.realm)
}

func (c *CachedAuthClient) getCacheKey(kid string) string {
	return c.getCacheKeyPrefix() + kid
}

func (c *CachedAuthClient) getCacheKeyPattern() string {
	return c.getCacheKeyPrefix() + "*"
}

func (c *CachedAuthClient) FetchAndCachePublicKeys(keycloakUserID, suffix string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Cache miss - fetch from Keycloak
	publicKeys, err := c.KeycloakClient.refreshKeysFromKeycloak(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch public keys from IDP: %w", err)
	}

	for kid, publicKey := range publicKeys {
		err := c.cache.Set(ctx, c.getCacheKey(kid), publicKey, 24*time.Hour)
		if err != nil {
			return fmt.Errorf("failed to cache public key for kid %s: %w", kid, err)
		}
	}

	return nil
}

// GetPublicKey with caching
func (c *CachedAuthClient) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	ctx := context.Background()
	cacheKey := c.getCacheKey(kid)

	// Try in-memory first
	if publicKey, err := c.KeycloakClient.GetInMemoryPublicKey(kid); err == nil {
		return publicKey, nil
	}

	// Try cache next
	if cachedPublicKeyJson, err := c.cache.GetRaw(ctx, cacheKey); err == nil {
		publicKey, err := c.KeycloakClient.parseRSAPublicKeyFromJWKJSON(cachedPublicKeyJson)
		if err == nil {
			c.KeycloakClient.publicKeyMutex.Lock()
			defer c.KeycloakClient.publicKeyMutex.Unlock()
			c.KeycloakClient.publicKeys[kid] = publicKey
			return publicKey, nil
		}
	}

	// Cache miss - fetch from Keycloak
	publicKeyJson, publicKey, err := c.KeycloakClient.FetchPublicKey(kid)
	if err != nil {
		return nil, err
	}

	// Cache for 24 hours (public keys rarely change)
	c.cache.Set(ctx, cacheKey, publicKeyJson, 24*time.Hour)

	return publicKey, nil
}

// GetAdminToken with caching
func (c *CachedAuthClient) GetAdminToken() (string, error) {
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

func (c *CachedAuthClient) DeletePublicKeyCache(kid string) error {
	ctx := context.Background()
	cacheKey := c.getCacheKey(kid)
	return c.cache.Delete(ctx, cacheKey)
}

func (c *CachedAuthClient) DeleteAllPublicKeyCache() error {
	ctx := context.Background()
	return c.cache.DeletePattern(ctx, c.getCacheKeyPattern())
}

func (c *CachedAuthClient) DeleteAllUserCache(keycloakUserID string) error {
	ctx := context.Background()
	return c.cache.DeletePattern(ctx, fmt.Sprintf("user:*:%s:*", keycloakUserID))
}

func (c *CachedAuthClient) GetOrCachePublicKeys(keycloakUserID string) error {
	ctx := context.Background()
	return c.cache.DeletePattern(ctx, fmt.Sprintf("user:*:%s:*", keycloakUserID))
}

// UpdateUserAttributes with cache invalidation
func (c *CachedAuthClient) UpdateUserAttributes(keycloakUserID string, attributes map[string][]string, adminToken string) error {
	ctx := context.Background()

	// Update in Keycloak
	if err := c.KeycloakClient.UpdateUserAttributes(keycloakUserID, adminToken, attributes); err != nil {
		return err
	}

	// Invalidate related caches
	c.cache.DeletePattern(ctx, fmt.Sprintf("user:*:%s:*", keycloakUserID))

	return nil
}

// ParseToken parses and validates the JWT token
func (c *CachedAuthClient) ParseToken(ctx context.Context, tokenString string) (*models.UserContext, bool, error) {

	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenString, &models.KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}
		publicKey, err := c.GetPublicKey(kid)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, false, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, token.Valid, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*models.KeycloakClaims)
	if !ok {
		return nil, token.Valid, fmt.Errorf("invalid claims type")
	}

	// Verify token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, token.Valid, fmt.Errorf("token expired")
	}

	// Build user context
	userCtx := &models.UserContext{
		UserID:        claims.UserID,
		HostID:        claims.HostID,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Roles:         claims.RealmAccess.Roles,
		Companies:     claims.Companies,
		SessionID:     claims.SessionID,
		Subject:       claims.Subject,
	}

	return userCtx, token.Valid, nil
}
