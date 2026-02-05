package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RequestSigner signs HTTP requests for service-to-service authentication
// Uses HMAC-SHA256 with timestamp and nonce to prevent replay attacks
type RequestSigner struct {
	secret        []byte
	headerPrefix  string
	maxClockSkew  time.Duration
	includeBody   bool
	signedHeaders []string
}

// RequestSignerConfig holds configuration for request signing
type RequestSignerConfig struct {
	// Secret is the shared secret for HMAC signing
	Secret string
	// HeaderPrefix for signature headers (default: "X-Signature-")
	HeaderPrefix string
	// MaxClockSkew is the maximum allowed time difference (default: 5 minutes)
	MaxClockSkew time.Duration
	// IncludeBody includes request body in signature (default: true)
	IncludeBody bool
	// SignedHeaders are additional headers to include in signature
	SignedHeaders []string
}

// DefaultRequestSignerConfig returns sensible defaults
func DefaultRequestSignerConfig(secret string) RequestSignerConfig {
	return RequestSignerConfig{
		Secret:       secret,
		HeaderPrefix: "X-Signature-",
		MaxClockSkew: 5 * time.Minute,
		IncludeBody:  true,
		SignedHeaders: []string{
			"Content-Type",
			"X-Request-ID",
		},
	}
}

// NewRequestSigner creates a new request signer
func NewRequestSigner(cfg RequestSignerConfig) *RequestSigner {
	if cfg.Secret == "" {
		panic("request signer secret cannot be empty")
	}
	if cfg.HeaderPrefix == "" {
		cfg.HeaderPrefix = "X-Signature-"
	}
	if cfg.MaxClockSkew == 0 {
		cfg.MaxClockSkew = 5 * time.Minute
	}

	return &RequestSigner{
		secret:        []byte(cfg.Secret),
		headerPrefix:  cfg.HeaderPrefix,
		maxClockSkew:  cfg.MaxClockSkew,
		includeBody:   cfg.IncludeBody,
		signedHeaders: cfg.SignedHeaders,
	}
}

// SignRequest adds signature headers to an HTTP request
func (s *RequestSigner) SignRequest(req *http.Request) error {
	timestamp := time.Now().Unix()
	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Build canonical request
	canonicalRequest, err := s.buildCanonicalRequest(req, timestamp, nonce)
	if err != nil {
		return fmt.Errorf("failed to build canonical request: %w", err)
	}

	// Compute signature
	signature := s.computeSignature(canonicalRequest)

	// Set headers
	req.Header.Set(s.headerPrefix+"Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set(s.headerPrefix+"Nonce", nonce)
	req.Header.Set(s.headerPrefix+"Signature", signature)

	// Include list of signed headers for verification
	signedHeadersList := s.getSignedHeadersList(req)
	if len(signedHeadersList) > 0 {
		req.Header.Set(s.headerPrefix+"Signed-Headers", strings.Join(signedHeadersList, ","))
	}

	return nil
}

// VerifyRequest verifies the signature on an HTTP request
func (s *RequestSigner) VerifyRequest(req *http.Request) error {
	// Extract signature headers
	timestampStr := req.Header.Get(s.headerPrefix + "Timestamp")
	nonce := req.Header.Get(s.headerPrefix + "Nonce")
	signature := req.Header.Get(s.headerPrefix + "Signature")

	if timestampStr == "" || nonce == "" || signature == "" {
		return ErrMissingSignature
	}

	// Parse and validate timestamp
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	reqTime := time.Unix(timestamp, 0)
	now := time.Now()

	// Check for clock skew
	if reqTime.After(now.Add(s.maxClockSkew)) {
		return ErrTimestampTooFarInFuture
	}
	if now.Sub(reqTime) > s.maxClockSkew {
		return ErrTimestampTooOld
	}

	// Validate nonce format
	if len(nonce) < 16 {
		return ErrInvalidNonce
	}

	// Rebuild canonical request and compute expected signature
	canonicalRequest, err := s.buildCanonicalRequest(req, timestamp, nonce)
	if err != nil {
		return fmt.Errorf("failed to build canonical request: %w", err)
	}

	expectedSignature := s.computeSignature(canonicalRequest)

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return ErrInvalidSignature
	}

	return nil
}

// buildCanonicalRequest creates a canonical string representation of the request
func (s *RequestSigner) buildCanonicalRequest(req *http.Request, timestamp int64, nonce string) (string, error) {
	var parts []string

	// Method
	parts = append(parts, req.Method)

	// Path (with query string)
	path := req.URL.Path
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	parts = append(parts, path)

	// Host
	parts = append(parts, req.Host)

	// Timestamp
	parts = append(parts, strconv.FormatInt(timestamp, 10))

	// Nonce
	parts = append(parts, nonce)

	// Signed headers (sorted for consistency)
	signedHeaders := s.getSignedHeadersList(req)
	for _, header := range signedHeaders {
		value := req.Header.Get(header)
		parts = append(parts, fmt.Sprintf("%s:%s", strings.ToLower(header), value))
	}

	// Body hash (if enabled and body exists)
	if s.includeBody && req.Body != nil && req.ContentLength > 0 {
		bodyHash, err := s.hashBody(req)
		if err != nil {
			return "", err
		}
		parts = append(parts, bodyHash)
	}

	return strings.Join(parts, "\n"), nil
}

// getSignedHeadersList returns sorted list of headers that are present and should be signed
func (s *RequestSigner) getSignedHeadersList(req *http.Request) []string {
	var present []string
	for _, header := range s.signedHeaders {
		if req.Header.Get(header) != "" {
			present = append(present, header)
		}
	}
	sort.Strings(present)
	return present
}

// hashBody reads and hashes the request body, then restores it
func (s *RequestSigner) hashBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return "", nil
	}

	// Read body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read body: %w", err)
	}

	// Restore body for later use
	req.Body = io.NopCloser(bytes.NewReader(body))

	// Hash body
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:]), nil
}

// computeSignature computes HMAC-SHA256 signature
func (s *RequestSigner) computeSignature(canonicalRequest string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(canonicalRequest))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// generateNonce generates a cryptographically secure random nonce
func generateNonce() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Signature errors
var (
	ErrMissingSignature        = fmt.Errorf("missing signature headers")
	ErrInvalidSignature        = fmt.Errorf("invalid signature")
	ErrTimestampTooOld         = fmt.Errorf("request timestamp too old")
	ErrTimestampTooFarInFuture = fmt.Errorf("request timestamp too far in future")
	ErrInvalidNonce            = fmt.Errorf("invalid nonce")
)

// SignedHTTPClient wraps an http.Client to automatically sign requests
type SignedHTTPClient struct {
	client *http.Client
	signer *RequestSigner
}

// NewSignedHTTPClient creates an HTTP client that signs all requests
func NewSignedHTTPClient(client *http.Client, signer *RequestSigner) *SignedHTTPClient {
	if client == nil {
		client = http.DefaultClient
	}
	return &SignedHTTPClient{
		client: client,
		signer: signer,
	}
}

// Do executes the request after signing it
func (c *SignedHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.signer.SignRequest(req); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}
	return c.client.Do(req)
}

// Get performs a signed GET request
func (c *SignedHTTPClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post performs a signed POST request
func (c *SignedHTTPClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}
