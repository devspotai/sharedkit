package observability

import (
	"context"
	"fmt"
	"log"
	"time"

	"sys-backend-user/config"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	cacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_hits_total",
			Help: "Total number of cache hits",
		},
		[]string{"cache_type"},
	)

	cacheMissesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cache_misses_total",
			Help: "Total number of cache misses",
		},
		[]string{"cache_type"},
	)

	databaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation"},
	)

	activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "active_connections",
			Help: "Number of active connections",
		},
	)
)

// InitObservability initializes tracing and metrics exporters
func InitObservability(cfg *config.Config) func(context.Context) {
	if !cfg.EnableTracing {
		log.Println("Tracing is disabled")
		return func(context.Context) {}
	}

	// Initialize OpenTelemetry tracer
	tracerProvider, err := initTracer(cfg)
	if err != nil {
		log.Printf("Failed to initialize tracer: %v", err)
		return func(context.Context) {}
	}

	// Set global tracer provider
	otel.SetTracerProvider(tracerProvider)

	// Set global propagator for distributed tracing
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Println("Observability initialized successfully")

	// Return shutdown function
	return func(ctx context.Context) {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}
}

// initTracer initializes the OpenTelemetry tracer with Grafana Cloud
func initTracer(cfg *config.Config) (*sdktrace.TracerProvider, error) {
	// Create resource with service information
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Configure OTLP exporter for Grafana Cloud
	var exporter *otlptrace.Exporter
	if cfg.GrafanaCloudOTLPEndpoint != "" {
		exporter, err = otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpoint(cfg.GrafanaCloudOTLPEndpoint),
			otlptracehttp.WithHeaders(map[string]string{
				"Authorization": fmt.Sprintf("Basic %s", cfg.GrafanaCloudAPIKey),
			}),
		)
	} else {
		// Local development - use stdout exporter or skip
		log.Println("No Grafana Cloud endpoint configured, traces will be collected locally")
		exporter, err = otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpoint("localhost:4318"),
			otlptracehttp.WithInsecure(),
		)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
	}

	// Create tracer provider with batch span processor
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter,
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	return tracerProvider, nil
}

// TracingMiddleware adds OpenTelemetry tracing to Gin handlers
func TracingMiddleware() gin.HandlerFunc {
	tracer := otel.Tracer("gin-middleware")

	return func(c *gin.Context) {
		// Extract context from incoming request
		ctx := otel.GetTextMapPropagator().Extract(
			c.Request.Context(),
			propagation.HeaderCarrier(c.Request.Header),
		)

		// Start span
		ctx, span := tracer.Start(ctx, fmt.Sprintf("%s %s", c.Request.Method, c.FullPath()),
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.String()),
				attribute.String("http.scheme", c.Request.URL.Scheme),
				attribute.String("http.host", c.Request.Host),
				attribute.String("http.target", c.Request.URL.Path),
				attribute.String("http.user_agent", c.Request.UserAgent()),
			),
		)
		defer span.End()

		// Inject span context into Gin context
		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Record status code
		span.SetAttributes(
			attribute.Int("http.status_code", c.Writer.Status()),
		)

		// Record errors if any
		if len(c.Errors) > 0 {
			span.RecordError(c.Errors.Last().Err)
		}
	}
}

// MetricsMiddleware adds Prometheus metrics to Gin handlers
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start).Seconds()

		// Record metrics
		status := fmt.Sprintf("%d", c.Writer.Status())
		httpRequestsTotal.WithLabelValues(c.Request.Method, c.FullPath(), status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, c.FullPath(), status).Observe(duration)
	}
}

// LoggingMiddleware adds structured logging to Gin handlers
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start)

		// Log request details
		log.Printf(
			"[%s] %s %s | Status: %d | Duration: %v | IP: %s",
			c.Request.Method,
			c.Request.URL.Path,
			c.Request.Proto,
			c.Writer.Status(),
			duration,
			c.ClientIP(),
		)
	}
}

// RecordCacheHit records a cache hit metric
func RecordCacheHit(cacheType string) {
	cacheHitsTotal.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records a cache miss metric
func RecordCacheMiss(cacheType string) {
	cacheMissesTotal.WithLabelValues(cacheType).Inc()
}

// RecordDatabaseQuery records a database query duration
func RecordDatabaseQuery(operation string, duration time.Duration) {
	databaseQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// SetActiveConnections sets the number of active connections
func SetActiveConnections(count int) {
	activeConnections.Set(float64(count))
}
