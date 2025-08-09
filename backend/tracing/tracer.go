// iSECTECH Go OpenTelemetry Instrumentation
// Production-grade distributed tracing for Go backend services

package tracing

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	ServiceName      = "isectech-backend"
	ServiceNamespace = "isectech"
	DefaultVersion   = "1.0.0"
)

// TracingConfig holds the configuration for OpenTelemetry tracing
type TracingConfig struct {
	ServiceName     string
	ServiceVersion  string
	Environment     string
	OTLPEndpoint    string
	JaegerEndpoint  string
	SamplingRate    float64
	Debug           bool
	EnableJaeger    bool
	EnableOTLP      bool
}

// TracerProvider wraps the OpenTelemetry tracer provider
type TracerProvider struct {
	provider    *trace.TracerProvider
	tracer      oteltrace.Tracer
	config      *TracingConfig
	shutdown    func(context.Context) error
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

// NewTracingConfig creates a new tracing configuration from environment variables
func NewTracingConfig() *TracingConfig {
	config := &TracingConfig{
		ServiceName:     getEnvOrDefault("OTEL_SERVICE_NAME", ServiceName),
		ServiceVersion:  getEnvOrDefault("OTEL_SERVICE_VERSION", DefaultVersion),
		Environment:     getEnvOrDefault("OTEL_ENVIRONMENT", "development"),
		OTLPEndpoint:    getEnvOrDefault("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://localhost:4318/v1/traces"),
		JaegerEndpoint:  getEnvOrDefault("JAEGER_ENDPOINT", "http://localhost:14268/api/traces"),
		SamplingRate:    getEnvFloatOrDefault("OTEL_TRACES_SAMPLER_ARG", 0.1),
		Debug:           getEnvBoolOrDefault("OTEL_DEBUG", false),
		EnableJaeger:    getEnvBoolOrDefault("ENABLE_JAEGER_EXPORT", false),
		EnableOTLP:      getEnvBoolOrDefault("ENABLE_OTLP_EXPORT", true),
	}
	
	return config
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESOURCE CREATION
// ═══════════════════════════════════════════════════════════════════════════════

// createResource creates an OpenTelemetry resource with service and environment information
func createResource(config *TracingConfig) (*resource.Resource, error) {
	attributes := []attribute.KeyValue{
		semconv.ServiceNameKey.String(config.ServiceName),
		semconv.ServiceVersionKey.String(config.ServiceVersion),
		semconv.ServiceNamespaceKey.String(ServiceNamespace),
		semconv.DeploymentEnvironmentKey.String(config.Environment),
		semconv.ServiceInstanceIDKey.String(getEnvOrDefault("HOSTNAME", "unknown")),
		semconv.ContainerNameKey.String(getEnvOrDefault("CONTAINER_NAME", "backend")),
		semconv.ContainerIDKey.String(getEnvOrDefault("CONTAINER_ID", "unknown")),
		semconv.K8SPodNameKey.String(getEnvOrDefault("K8S_POD_NAME", "unknown")),
		semconv.K8SNamespaceNameKey.String(getEnvOrDefault("K8S_NAMESPACE", "default")),
		semconv.K8SClusterNameKey.String(getEnvOrDefault("K8S_CLUSTER_NAME", "isectech-cluster")),
		
		// Custom iSECTECH attributes
		attribute.String("isectech.component", "backend"),
		attribute.String("isectech.team", "backend-team"),
		attribute.String("isectech.environment.type", config.Environment),
		attribute.String("isectech.version", config.ServiceVersion),
	}

	return resource.NewWithAttributes(
		semconv.SchemaURL,
		attributes...,
	)
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTER CREATION
// ═══════════════════════════════════════════════════════════════════════════════

// createOTLPExporter creates an OTLP HTTP trace exporter
func createOTLPExporter(ctx context.Context, config *TracingConfig) (trace.SpanExporter, error) {
	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(config.OTLPEndpoint),
		otlptracehttp.WithInsecure(), // Use HTTPS in production
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	}

	// Add authentication headers if token is provided
	if token := os.Getenv("OTEL_AUTH_TOKEN"); token != "" {
		headers := map[string]string{
			"Authorization":    fmt.Sprintf("Bearer %s", token),
			"X-Service-Name":   config.ServiceName,
		}
		options = append(options, otlptracehttp.WithHeaders(headers))
	}

	return otlptracehttp.New(ctx, options...)
}

// createJaegerExporter creates a Jaeger trace exporter
func createJaegerExporter(config *TracingConfig) (trace.SpanExporter, error) {
	return jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(config.JaegerEndpoint),
	))
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLER CREATION
// ═══════════════════════════════════════════════════════════════════════════════

// createSampler creates a trace sampler based on environment and configuration
func createSampler(config *TracingConfig) trace.Sampler {
	if config.Environment == "development" || config.Debug {
		return trace.AlwaysSample()
	}

	// Production sampling with parent-based sampling
	return trace.ParentBased(trace.TraceIDRatioBased(config.SamplingRate))
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACER PROVIDER INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// NewTracerProvider creates and initializes a new OpenTelemetry tracer provider
func NewTracerProvider(ctx context.Context, config *TracingConfig) (*TracerProvider, error) {
	// Create resource
	res, err := createResource(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create span processors with exporters
	var spanProcessors []trace.SpanProcessor

	// OTLP Exporter
	if config.EnableOTLP {
		otlpExporter, err := createOTLPExporter(ctx, config)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
		spanProcessors = append(spanProcessors, trace.NewBatchSpanProcessor(otlpExporter,
			trace.WithBatchTimeout(5*time.Second),
			trace.WithMaxExportBatchSize(512),
			trace.WithMaxQueueSize(2048),
		))
	}

	// Jaeger Exporter
	if config.EnableJaeger {
		jaegerExporter, err := createJaegerExporter(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
		}
		spanProcessors = append(spanProcessors, trace.NewBatchSpanProcessor(jaegerExporter))
	}

	// Create tracer provider
	provider := trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithSampler(createSampler(config)),
	)

	// Add span processors
	for _, processor := range spanProcessors {
		provider.RegisterSpanProcessor(processor)
	}

	// Set global tracer provider
	otel.SetTracerProvider(provider)

	// Set global text map propagator for trace context propagation
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer
	tracer := provider.Tracer(
		config.ServiceName,
		oteltrace.WithInstrumentationVersion(config.ServiceVersion),
		oteltrace.WithSchemaURL(semconv.SchemaURL),
	)

	return &TracerProvider{
		provider: provider,
		tracer:   tracer,
		config:   config,
		shutdown: provider.Shutdown,
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACER PROVIDER METHODS
// ═══════════════════════════════════════════════════════════════════════════════

// Tracer returns the OpenTelemetry tracer
func (tp *TracerProvider) Tracer() oteltrace.Tracer {
	return tp.tracer
}

// Shutdown gracefully shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.shutdown != nil {
		return tp.shutdown(ctx)
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM SPAN UTILITIES FOR ISECTECH
// ═══════════════════════════════════════════════════════════════════════════════

// StartSecuritySpan starts a new span for security operations
func (tp *TracerProvider) StartSecuritySpan(ctx context.Context, name string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	opts = append(opts, oteltrace.WithAttributes(
		attribute.String("isectech.operation_type", "security"),
		attribute.String("isectech.component", "security"),
	))
	return tp.tracer.Start(ctx, name, opts...)
}

// StartBusinessSpan starts a new span for business operations
func (tp *TracerProvider) StartBusinessSpan(ctx context.Context, name string, userID string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	opts = append(opts, oteltrace.WithAttributes(
		attribute.String("isectech.operation_type", "business"),
		attribute.String("isectech.user_id", userID),
	))
	return tp.tracer.Start(ctx, name, opts...)
}

// StartDatabaseSpan starts a new span for database operations
func (tp *TracerProvider) StartDatabaseSpan(ctx context.Context, operation string, table string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	opts = append(opts, oteltrace.WithAttributes(
		attribute.String("isectech.operation_type", "database"),
		attribute.String("db.operation", operation),
		attribute.String("db.sql.table", table),
		attribute.String("isectech.component", "database"),
	))
	return tp.tracer.Start(ctx, fmt.Sprintf("db.%s %s", operation, table), opts...)
}

// StartHTTPSpan starts a new span for HTTP operations
func (tp *TracerProvider) StartHTTPSpan(ctx context.Context, method string, url string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	opts = append(opts, oteltrace.WithAttributes(
		attribute.String("isectech.operation_type", "http"),
		attribute.String("http.method", method),
		attribute.String("http.url", url),
		attribute.String("isectech.component", "http"),
	))
	return tp.tracer.Start(ctx, fmt.Sprintf("%s %s", method, url), opts...)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPAN UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

// AddSecurityEvent adds a security-related event to the current span
func AddSecurityEvent(ctx context.Context, eventType string, attributes map[string]interface{}) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() {
		attrs := []attribute.KeyValue{
			attribute.String("isectech.security.event_type", eventType),
		}
		for k, v := range attributes {
			switch val := v.(type) {
			case string:
				attrs = append(attrs, attribute.String(k, val))
			case int:
				attrs = append(attrs, attribute.Int(k, val))
			case bool:
				attrs = append(attrs, attribute.Bool(k, val))
			}
		}
		span.AddEvent("security.event", oteltrace.WithAttributes(attrs...))
	}
}

// AddErrorEvent adds an error event to the current span
func AddErrorEvent(ctx context.Context, err error, errorType string) {
	span := oteltrace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err, oteltrace.WithAttributes(
			attribute.String("isectech.error.type", errorType),
			attribute.Bool("isectech.error", true),
		))
		span.SetStatus(oteltrace.StatusCodeError, err.Error())
	}
}

// GetTraceID returns the trace ID from the current context
func GetTraceID(ctx context.Context) string {
	span := oteltrace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// GetSpanID returns the span ID from the current context
func GetSpanID(ctx context.Context) string {
	span := oteltrace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// getEnvOrDefault returns the environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvFloatOrDefault returns the environment variable as float64 or default if not set/invalid
func getEnvFloatOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvBoolOrDefault returns the environment variable as bool or default if not set/invalid
func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// ═══════════════════════════════════════════════════════════════════════════════
// GLOBAL TRACER PROVIDER
// ═══════════════════════════════════════════════════════════════════════════════

var globalTracerProvider *TracerProvider

// InitializeGlobalTracer initializes the global tracer provider
func InitializeGlobalTracer(ctx context.Context) error {
	config := NewTracingConfig()
	
	tp, err := NewTracerProvider(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to initialize tracer provider: %w", err)
	}
	
	globalTracerProvider = tp
	
	fmt.Printf("✅ OpenTelemetry tracing initialized for %s\n", config.ServiceName)
	fmt.Printf("   Service: %s v%s\n", config.ServiceName, config.ServiceVersion)
	fmt.Printf("   Environment: %s\n", config.Environment)
	fmt.Printf("   OTLP Endpoint: %s\n", config.OTLPEndpoint)
	fmt.Printf("   Sampling Rate: %.2f\n", config.SamplingRate)
	
	return nil
}

// GetGlobalTracer returns the global tracer
func GetGlobalTracer() oteltrace.Tracer {
	if globalTracerProvider != nil {
		return globalTracerProvider.Tracer()
	}
	return otel.Tracer(ServiceName)
}

// ShutdownGlobalTracer shuts down the global tracer provider
func ShutdownGlobalTracer(ctx context.Context) error {
	if globalTracerProvider != nil {
		return globalTracerProvider.Shutdown(ctx)
	}
	return nil
}