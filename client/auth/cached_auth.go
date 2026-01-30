package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/devspotai/sharedkit/client/cache"
	"github.com/devspotai/sharedkit/models"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type CachedAuthClient struct {
	KeycloakClient *KeycloakClient
	cache          *cache.RedisCache
	tracer         trace.Tracer
}

func NewCachedAuthClient(keycloakClient *KeycloakClient, cache *cache.RedisCache) *CachedAuthClient {
	return &CachedAuthClient{
		KeycloakClient: keycloakClient,
		cache:          cache,
		tracer:         otel.Tracer("cached-auth"),
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
func (c *CachedAuthClient) GetPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	ctx, span := c.tracer.Start(ctx, "cached_auth.get_public_key")
	defer span.End()

	span.SetAttributes(attribute.String("key.kid", kid))
	cacheKey := c.getCacheKey(kid)

	// Try in-memory first
	if publicKey, err := c.KeycloakClient.GetInMemoryPublicKey(kid); err == nil {
		span.SetAttributes(attribute.String("cache.source", "memory"))
		return publicKey, nil
	}

	// Try cache next
	if cachedPublicKeyJson, err := c.cache.GetRaw(ctx, cacheKey); err == nil {
		publicKey, err := c.KeycloakClient.parseRSAPublicKeyFromJWKJSON(cachedPublicKeyJson)
		if err == nil {
			c.KeycloakClient.publicKeyMutex.Lock()
			defer c.KeycloakClient.publicKeyMutex.Unlock()
			c.KeycloakClient.publicKeys[kid] = publicKey
			span.SetAttributes(attribute.String("cache.source", "redis"))
			return publicKey, nil
		}
	}

	// Cache miss - fetch from Keycloak
	span.SetAttributes(attribute.String("cache.source", "keycloak"))
	publicKeyJson, publicKey, err := c.KeycloakClient.FetchPublicKey(ctx, kid)
	if err != nil {
		span.RecordError(err)
		return nil, err
	}

	// Cache for 24 hours (public keys rarely change)
	c.cache.Set(ctx, cacheKey, publicKeyJson, 24*time.Hour)

	return publicKey, nil
}

// GetAdminToken with caching
func (c *CachedAuthClient) GetAdminToken(ctx context.Context) (string, error) {
	ctx, span := c.tracer.Start(ctx, "cached_auth.get_admin_token")
	defer span.End()

	cacheKey := "keycloak:admin_token"

	// Try cache first
	var cachedToken string
	if err := c.cache.Get(ctx, cacheKey, &cachedToken); err == nil {
		span.SetAttributes(attribute.Bool("cache.hit", true))
		return cachedToken, nil
	}

	span.SetAttributes(attribute.Bool("cache.hit", false))

	// Cache miss - get new token
	token, err := c.KeycloakClient.GetAdminToken(ctx)
	if err != nil {
		span.RecordError(err)
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

// UpdateUserAttributes with cache invalidation
func (c *CachedAuthClient) UpdateUserAttributes(ctx context.Context, keycloakUserID string, attributes map[string][]string, adminToken string) error {
	ctx, span := c.tracer.Start(ctx, "cached_auth.update_user_attributes")
	defer span.End()

	span.SetAttributes(attribute.String("keycloak.user_id", keycloakUserID))

	// Update in Keycloak
	if err := c.KeycloakClient.UpdateUserAttributes(ctx, keycloakUserID, adminToken, attributes); err != nil {
		span.RecordError(err)
		return err
	}

	// Invalidate related caches
	c.cache.DeletePattern(ctx, fmt.Sprintf("user:*:%s:*", keycloakUserID))

	return nil
}

// ParseToken parses and validates the JWT token
func (c *CachedAuthClient) ParseToken(ctx context.Context, tokenString string) (*models.UserContext, error) {
	ctx, span := c.tracer.Start(ctx, "cached_auth.parse_token")
	defer span.End()

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
		publicKey, err := c.GetPublicKey(ctx, kid)
		if err != nil {
			return nil, err
		}

		return publicKey, nil
	})

	//if token fails validation because public key in cache was old, retrieve public key from keycloack
	// If parsing failed, attempt to refresh the public key from Keycloak and retry once.
	// This handles the case where the cached public key is stale.
	if err != nil {
		// only attempt refresh if we have a parsed token header with a kid
		if token != nil && token.Header != nil {
			if kid, ok := token.Header["kid"].(string); ok && kid != "" {
				span.SetAttributes(attribute.String("cache.refresh.kid", kid))
				publicKeyJson, publicKey, fetchErr := c.KeycloakClient.FetchPublicKey(ctx, kid)
				if fetchErr == nil {
					// update cache (best-effort)
					_ = c.cache.Set(ctx, c.getCacheKey(kid), publicKeyJson, 24*time.Hour)

					// retry parse with the freshly fetched key
					token, err = jwt.ParseWithClaims(tokenString, &models.KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
						if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
							return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
						}
						return publicKey, nil
					})
					if err == nil {
						span.SetAttributes(attribute.Bool("cache.refreshed", true))
					} else {
						span.RecordError(err)
					}
				} else {
					span.RecordError(fetchErr)
				}
			}
		}
	}

	if err != nil {
		span.RecordError(err)
		span.SetAttributes(attribute.Bool("token.valid", false))
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		span.SetAttributes(attribute.Bool("token.valid", false))
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*models.KeycloakClaims)
	if !ok {
		span.SetAttributes(attribute.Bool("token.valid", false))
		return nil, fmt.Errorf("invalid claims type")
	}

	// Verify token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		span.SetAttributes(attribute.Bool("token.valid", false))
		return nil, fmt.Errorf("token expired")
	}

	span.SetAttributes(
		attribute.Bool("token.valid", true),
		attribute.String("user.id", claims.UserID),
	)

	// Build user context
	userCtx := &models.UserContext{
		UserID:         claims.UserID,
		HostID:         claims.HostID,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Roles:          claims.RealmAccess.Roles,
		CompaniesRoles: &claims.CompaniesRoles,
		SessionID:      claims.SessionID,
		Subject:        claims.Subject,
	}

	return userCtx, nil
}
