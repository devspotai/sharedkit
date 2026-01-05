package auth

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/devspotai/sharedkit/models"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type KeycloakClient struct {
	baseURL           string
	jwksURL           string
	realm             string
	clientID          string
	clientSecret      string
	publicKeys        map[string]*rsa.PublicKey
	publicKeysToCache map[string]json.RawMessage
	publicKeyMutex    sync.RWMutex
	httpClient        *http.Client
	lastKeyFetch      time.Time
}

// NewKeycloakClient creates a new Keycloak client
func NewKeycloakClient(baseURL, jwksURL, realm, clientID, clientSecret string) *KeycloakClient {
	if baseURL == "" {
		panic("baseURL cannot be empty")
	}
	if realm == "" {
		panic("realm cannot be empty")
	}
	if jwksURL == "" {
		jwksURL = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", baseURL, realm)
	}

	m := &KeycloakClient{
		baseURL:      baseURL,
		jwksURL:      jwksURL,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		publicKeys:   make(map[string]*rsa.PublicKey),
	}

	return m
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

func (c *KeycloakClient) GetInMemoryPublicKey(kid string) (*rsa.PublicKey, error) {
	c.publicKeyMutex.RLock()
	defer c.publicKeyMutex.RUnlock()
	if publicKey, ok := c.publicKeys[kid]; ok {
		return publicKey, nil
	}
	return nil, fmt.Errorf("public key not found in memory for kid: %s", kid)
}

// FetchPublicKey fetches the public key from Keycloak
func (c *KeycloakClient) FetchPublicKey(kid string) ([]byte, *rsa.PublicKey, error) {
	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", c.baseURL, c.realm)

	jwksJsonResponse, err := c.fetchRawJsonResponse(url)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	var jwksJSON models.JWKSJSON
	if err := json.Unmarshal(jwksJsonResponse, &jwksJSON); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	if len(jwksJSON.Keys) == 0 {
		return nil, nil, fmt.Errorf("no keys found in JWKS")
	}

	// Use the first RSA key
	for _, keyJSON := range jwksJSON.Keys {
		var keyInfo models.JWK
		if err := json.Unmarshal(keyJSON, &keyInfo); err != nil {
			continue
		}
		if keyInfo.Kty != "RSA" || keyInfo.Use != "sig" || keyInfo.Kid != kid {
			continue
		}

		publicKey, err := c.parseRSAPublicKeyFromJWK(keyInfo.N, keyInfo.E)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing RSA public key: %w", err)
		}
		if publicKey != nil {
			c.publicKeys[kid] = publicKey
			return keyJSON, publicKey, nil
		}
	}
	return nil, nil, fmt.Errorf("no matching RSA key found in JWKS for kid: %s", kid)
}

func (c *KeycloakClient) fetchRawJsonResponse(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Fetch JWKS from Keycloak
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s endpoint returned status %d", url, resp.StatusCode)
	}

	// Read response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return responseBody, nil
}

// parseRSAPublicKey parses RSA public key from JWK
func (c *KeycloakClient) parseRSAPublicKeyFromJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	if nStr == "" || eStr == "" {
		return nil, fmt.Errorf("missing n/e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	// big-endian unsigned exponent
	e := 0
	for _, b := range eBytes {
		// avoid overflow on extremely large exponents
		if e > (int(^uint(0)>>1)-int(b))/256 {
			return nil, fmt.Errorf("exponent too large")
		}
		e = e*256 + int(b)
	}
	if e < 3 || e%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent: %d", e)
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}
	if pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA key too small: %d bits", pub.N.BitLen())
	}
	return pub, nil
}

func (c *KeycloakClient) parseRSAPublicKeyFromJWKJSON(jwkJSON []byte) (*rsa.PublicKey, error) {
	var pubKey rsa.PublicKey
	err := jwk.ParseRawKey(jwkJSON, &pubKey)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}

func (c *KeycloakClient) rsaPublicKeyFromPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
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

// GetLastFetchTime returns when keys were last fetched
func (c *KeycloakClient) GetLastFetchTime() time.Time {
	c.publicKeyMutex.RLock()
	defer c.publicKeyMutex.RUnlock()
	return c.lastKeyFetch
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

func (c *KeycloakClient) GetPublicKeysToCache() (map[string]json.RawMessage, error) {
	c.publicKeyMutex.RLock()
	defer c.publicKeyMutex.RUnlock()

	// Clone the public keys map to avoid concurrent map read/write
	publicKeys := make(map[string]json.RawMessage)
	for k, v := range c.publicKeysToCache {
		publicKeys[k] = v
	}
	return publicKeys, nil
}

// refreshKeysFromKeycloak fetches keys from Keycloak and caches them
func (c *KeycloakClient) refreshKeysFromKeycloak(ctx context.Context) (map[string]json.RawMessage, error) {

	// Fetch JWKS from Keycloak
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	// Read response body
	jwksData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	// Parse JWKS to get individual keys
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}

	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	// Build new maps WITHOUT holding lock
	newKeys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	newKeysToCache := make(map[string]json.RawMessage, len(jwks.Keys))
	for _, keyJSON := range jwks.Keys {
		// Parse key info to get kid
		var keyInfo struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
		}

		if err := json.Unmarshal(keyJSON, &keyInfo); err != nil {
			continue
		}

		// Only process RSA signing keys
		if keyInfo.Kty != "RSA" || (keyInfo.Use != "sig" && keyInfo.Use != "") {
			continue
		}

		// Parse JWK to RSA public key using library
		publicKey, err := c.parseRSAPublicKeyFromJWKJSON(keyJSON)
		if err != nil {
			fmt.Printf("Warning: failed to parse key %s: %v\n", keyInfo.Kid, err)
			continue
		}

		newKeys[keyInfo.Kid] = publicKey
		newKeysToCache[keyInfo.Kid] = keyJSON
	}

	if len(newKeys) == 0 {
		return nil, fmt.Errorf("no valid RSA keys found in JWKS")
	}

	// Swap atomically under lock
	c.publicKeyMutex.Lock()
	c.publicKeys = newKeys
	c.publicKeysToCache = newKeysToCache
	c.lastKeyFetch = time.Now()
	c.publicKeyMutex.Unlock()

	fmt.Printf("Loaded %d public keys from Keycloak\n", len(newKeys))

	return newKeysToCache, nil
}

// parseRSAPublicKeyFromJWK parses RSA public key from JWK format
func parseRSAPublicKeyFromJWK(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode base64url encoded modulus and exponent
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	return publicKey, nil
}
