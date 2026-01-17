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
	GrafanaCloudInstanceID   string
	GrafanaCloudAPIKey       string
	GrafanaCloudOTLPEndpoint string
	ServiceName              string
	ServiceVersion           string

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

// RedisConfig holds Redis connection configuration
type RedisConfig struct {
	URL               string
	Username          string
	Password          string
	DB                int
	MaxRetries        int
	PoolSize          int
	MinIdleConns      int
	DefaultTTLSeconds int
}

// DefaultRedisConfig returns sensible defaults for Redis configuration
func DefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		URL:          "localhost:6379",
		Password:     "",
		DB:           0,
		MaxRetries:   3,
		PoolSize:     10,
		MinIdleConns: 2,
	}
}

func LoadRedisConfig() *RedisConfig {
	return &RedisConfig{
		URL:          GetEnv("REDIS_URL", "localhost:6379"),
		Password:     GetEnv("REDIS_PASSWORD", ""),
		DB:           GetEnvAsInt("REDIS_DB", 0),
		MaxRetries:   GetEnvAsInt("REDIS_MAX_RETRIES", 3),
		PoolSize:     GetEnvAsInt("REDIS_POOL_SIZE", 10),
		MinIdleConns: GetEnvAsInt("REDIS_MIN_IDLE_CONNS", 2),
	}
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:                     GetEnvAsInt("PORT", 8080),
		Environment:              GetEnv("ENVIRONMENT", "development"),
		DatabaseURL:              GetEnv("DATABASE_URL", ""),
		RedisURL:                 GetEnv("REDIS_URL", "localhost:6379"),
		RedisPassword:            GetEnv("REDIS_PASSWORD", ""),
		RedisDB:                  GetEnvAsInt("REDIS_DB", 0),
		KeycloakURL:              GetEnv("KEYCLOAK_URL", "http://localhost:8080"),
		KeycloakRealm:            GetEnv("KEYCLOAK_REALM", "travel-saas"),
		InternalSharedSecret:     GetEnv("INTERNAL_SHARED_SECRET", ""),
		UseInternalAuth:          GetEnvAsBool("USE_INTERNAL_AUTH", false),
		GrafanaCloudInstanceID:   GetEnv("GRAFANA_CLOUD_INSTANCE_ID", ""),
		GrafanaCloudAPIKey:       GetEnv("GRAFANA_CLOUD_API_KEY", ""),
		GrafanaCloudOTLPEndpoint: GetEnv("GRAFANA_CLOUD_OTLP_ENDPOINT", ""),
		ServiceName:              GetEnv("SERVICE_NAME", "sys-backend-user"),
		ServiceVersion:           GetEnv("SERVICE_VERSION", "1.0.0"),
		EnableTracing:            GetEnvAsBool("ENABLE_TRACING", true),
		EnableMetrics:            GetEnvAsBool("ENABLE_METRICS", true),
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

func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func GetEnvAsInt(key string, defaultValue int) int {
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

func GetEnvAsBool(key string, defaultValue bool) bool {
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
