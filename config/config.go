package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all configuration for the application
type Config struct {
	// Server
	Port        int
	Environment string

	// Database
	DatabaseURL string
	
	// Redis
	RedisURL      string
	RedisPassword string
	RedisDB       int

	// Keycloak
	KeycloakURL   string
	KeycloakRealm string

	// Internal Service Authentication
	InternalSharedSecret string
	UseInternalAuth      bool

	// Observability
	GrafanaCloudInstanceID  string
	GrafanaCloudAPIKey      string
	GrafanaCloudOTLPEndpoint string
	ServiceName             string
	ServiceVersion          string

	// Feature Flags
	EnableTracing bool
	EnableMetrics bool
}

// ConnectionPoolConfig holds database connection pool configuration
type ConnectionPoolConfig struct {
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeInHours int
	ConnMaxIdleTimeInMin   int
	HealthCheckPeriodInSec int
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:                     getEnvAsInt("PORT", 8080),
		Environment:              getEnv("ENVIRONMENT", "development"),
		DatabaseURL:              getEnv("DATABASE_URL", ""),
		RedisURL:                 getEnv("REDIS_URL", "localhost:6379"),
		RedisPassword:            getEnv("REDIS_PASSWORD", ""),
		RedisDB:                  getEnvAsInt("REDIS_DB", 0),
		KeycloakURL:              getEnv("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm:            getEnv("KEYCLOAK_REALM", "travel-saas"),
		InternalSharedSecret:     getEnv("INTERNAL_SHARED_SECRET", ""),
		UseInternalAuth:          getEnvAsBool("USE_INTERNAL_AUTH", false),
		GrafanaCloudInstanceID:   getEnv("GRAFANA_CLOUD_INSTANCE_ID", ""),
		GrafanaCloudAPIKey:       getEnv("GRAFANA_CLOUD_API_KEY", ""),
		GrafanaCloudOTLPEndpoint: getEnv("GRAFANA_CLOUD_OTLP_ENDPOINT", ""),
		ServiceName:              getEnv("SERVICE_NAME", "sys-backend-user"),
		ServiceVersion:           getEnv("SERVICE_VERSION", "1.0.0"),
		EnableTracing:            getEnvAsBool("ENABLE_TRACING", true),
		EnableMetrics:            getEnvAsBool("ENABLE_METRICS", true),
	}

	// Validate required configuration
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	if cfg.UseInternalAuth && cfg.InternalSharedSecret == "" {
		return nil, fmt.Errorf("INTERNAL_SHARED_SECRET is required when USE_INTERNAL_AUTH is true")
	}

	return cfg, nil
}

// Helper functions

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}
