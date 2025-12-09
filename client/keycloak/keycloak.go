package keycloak

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devspotai/sharedkit/models"
	"github.com/golang-jwt/jwt/v5"
)

type KeycloakClient struct {
	baseURL        string
	realm          string
	clientID       string
	clientSecret   string
	publicKey      *rsa.PublicKey
	publicKeyMutex sync.RWMutex
	httpClient     *http.Client
	lastKeyFetch   time.Time
}

// LogoutUser logs out all user sessions (forces re-login)
func (c *KeycloakClient) LogoutUser(keycloakUserID, adminToken string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/logout", c.baseURL, c.realm, keycloakUserID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout failed: %s", string(body))
	}

	return nil
}

// InvalidateUserSessions invalidates all active sessions for a user
func (c *KeycloakClient) InvalidateUserSessions(keycloakUserID, adminToken string) error {
	// Get all sessions
	sessionsURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/sessions", c.baseURL, c.realm, keycloakUserID)

	req, _ := http.NewRequest("GET", sessionsURL, nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var sessions []struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&sessions)

	// Delete each session
	for _, session := range sessions {
		deleteURL := fmt.Sprintf("%s/admin/realms/%s/sessions/%s", c.baseURL, c.realm, session.ID)
		req, _ := http.NewRequest("DELETE", deleteURL, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		c.httpClient.Do(req)
	}

	return nil
}

// FetchPublicKey fetches the public key from Keycloak
func (c *KeycloakClient) FetchPublicKey() (*rsa.PublicKey, error) {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var jwks models.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no keys found in JWKS")
	}

	// Use the first RSA key
	for _, key := range jwks.Keys {
		if key.Kty == "RSA" && key.Use == "sig" {
			publicKey, err := c.parseRSAPublicKey(key)
			if err != nil {
				continue
			}

			c.publicKeyMutex.Lock()
			c.publicKey = publicKey
			c.lastKeyFetch = time.Now()
			c.publicKeyMutex.Unlock()

			return publicKey, nil
		}
	}

	return nil, fmt.Errorf("no suitable RSA key found")
}

// parseRSAPublicKey parses RSA public key from JWK
func (c *KeycloakClient) parseRSAPublicKey(jwk models.JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return publicKey, nil
}

func (c *KeycloakClient) GetAdminToken() (string, error) {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	data := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s",
		c.clientID, c.clientSecret)

	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get admin token: %s", string(body))
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (c *KeycloakClient) UpdateUserAttributes(keycloakUserID, adminToken string, attributes map[string][]string) error {
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s", c.baseURL, c.realm, keycloakUserID)

	// Prepare payload
	payload := map[string]interface{}{
		"attributes": attributes,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to update user attributes: %s", string(body))
	}

	return nil
}

// ParseToken parses and validates the JWT token
func (c *KeycloakClient) ParseToken(ctx context.Context, tokenString string) (*models.UserContext, error) {
	c.publicKeyMutex.RLock()
	publicKey := c.publicKey
	c.publicKeyMutex.RUnlock()

	if publicKey == nil {
		return nil, fmt.Errorf("public key not available")
	}

	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenString, &models.KeycloakClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*models.KeycloakClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Verify token expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Build user context
	userCtx := &models.UserContext{
		UserID:        claims.UserID,
		HostID:        claims.HostID,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Roles:         claims.RealmAccess.Roles,
		Companies:     claims.Companies,
		SessionID:     claims.SessionID,
		Subject:       claims.Subject,
	}

	return userCtx, nil
}
