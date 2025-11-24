package models

import (
	"github.com/golang-jwt/jwt/v5"
)

// KeycloakClaims represents the custom claims in Keycloak JWT
type KeycloakClaims struct {
	jwt.RegisteredClaims
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
	Scope         string    `json:"scope"`
	SessionID     string    `json:"sid"`
	EmailVerified bool      `json:"email_verified"`
	Name          string    `json:"name"`
	PreferredUser string    `json:"preferred_username"`
	GivenName     string    `json:"given_name"`
	FamilyName    string    `json:"family_name"`
	Email         string    `json:"email"`
	UserID        string    `json:"user_id"`   // Custom claim
	Companies     []Company `json:"companies"` // Custom claim
	SessionState  string    `json:"session_state"`
	ACR           string    `json:"acr"`
	AZP           string    `json:"azp"`
	Type          string    `json:"typ"`
}
