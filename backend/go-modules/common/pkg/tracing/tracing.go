package tracing

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
)

// Config represents tracing configuration
type Config struct {
	// Basic settings
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	ServiceName string `yaml:"service_name" json:"service_name"`
	Version     string `yaml:"version" json:"version"`
	Environment string `yaml:"environment" json:"environment"`
	
	// Jaeger settings
	Jaeger JaegerConfig `yaml:"jaeger" json:"jaeger"`
	
	// Sampling settings
	SamplingRatio float64 `yaml:"sampling_ratio" json:"sampling_ratio"`
	
	// Resource settings
	ResourceAttributes map[string]string `yaml:"resource_attributes" json:"resource_attributes"`
}

// JaegerConfig represents Jaeger configuration
type JaegerConfig struct {
	Endpoint string `yaml:"endpoint" json:"endpoint"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// Manager manages distributed tracing
type Manager struct {
	config   *Config
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	logger   *zap.Logger
}

// NewManager creates a new tracing manager
func NewManager(config *Config, logger *zap.Logger) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	if !config.Enabled {
		logger.Info("Tracing is disabled")
		return &Manager{
			config: config,
			tracer: trace.NewNoopTracerProvider().Tracer("noop"),
			logger: logger,
		}, nil
	}

	// Create resource
	res, err := createResource(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter
	exporter, err := createJaegerExporter(config.Jaeger)
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(config.SamplingRatio)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)
	
	// Set global text map propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer
	tracer := tp.Tracer(
		config.ServiceName,
		trace.WithInstrumentationVersion(config.Version),
	)

	m := &Manager{
		config:   config,
		tracer:   tracer,
		provider: tp,
		logger:   logger,
	}

	logger.Info("Tracing initialized",
		zap.String("service", config.ServiceName),
		zap.String("endpoint", config.Jaeger.Endpoint),
		zap.Float64("sampling_ratio", config.SamplingRatio),
	)

	return m, nil
}

// createResource creates an OpenTelemetry resource
func createResource(config *Config) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(config.ServiceName),
		semconv.ServiceVersionKey.String(config.Version),
		semconv.DeploymentEnvironmentKey.String(config.Environment),
	}

	// Add custom resource attributes
	for key, value := range config.ResourceAttributes {
		attrs = append(attrs, attribute.String(key, value))
	}

	return resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			attrs...,
		),
	)
}

// createJaegerExporter creates a Jaeger exporter
func createJaegerExporter(config JaegerConfig) (sdktrace.SpanExporter, error) {
	opts := []jaeger.EndpointOption{}

	if config.Username != "" && config.Password != "" {
		opts = append(opts, jaeger.WithUsername(config.Username))
		opts = append(opts, jaeger.WithPassword(config.Password))
	}

	endpoint := jaeger.WithEndpoint(config.Endpoint)

	return jaeger.New(endpoint)
}

// StartSpan starts a new span
func (m *Manager) StartSpan(ctx context.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return m.tracer.Start(ctx, operationName, opts...)
}

// GetTracer returns the tracer
func (m *Manager) GetTracer() trace.Tracer {
	return m.tracer
}

// Shutdown gracefully shuts down the tracing manager
func (m *Manager) Shutdown(ctx context.Context) error {
	if m.provider != nil {
		m.logger.Info("Shutting down tracing")
		return m.provider.Shutdown(ctx)
	}
	return nil
}

// SpanFromContext returns the span from context
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// TraceIDFromContext extracts trace ID from context
func TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts span ID from context
func SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}

// AddSpanTags adds tags to the current span
func AddSpanTags(ctx context.Context, tags map[string]interface{}) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}

	attrs := make([]attribute.KeyValue, 0, len(tags))
	for key, value := range tags {
		switch v := value.(type) {
		case string:
			attrs = append(attrs, attribute.String(key, v))
		case int:
			attrs = append(attrs, attribute.Int(key, v))
		case int64:
			attrs = append(attrs, attribute.Int64(key, v))
		case float64:
			attrs = append(attrs, attribute.Float64(key, v))
		case bool:
			attrs = append(attrs, attribute.Bool(key, v))
		default:
			attrs = append(attrs, attribute.String(key, fmt.Sprintf("%v", v)))
		}
	}
	
	span.SetAttributes(attrs...)
}

// AddSpanEvent adds an event to the current span
func AddSpanEvent(ctx context.Context, name string, attributes map[string]interface{}) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}

	attrs := make([]attribute.KeyValue, 0, len(attributes))
	for key, value := range attributes {
		switch v := value.(type) {
		case string:
			attrs = append(attrs, attribute.String(key, v))
		case int:
			attrs = append(attrs, attribute.Int(key, v))
		case int64:
			attrs = append(attrs, attribute.Int64(key, v))
		case float64:
			attrs = append(attrs, attribute.Float64(key, v))
		case bool:
			attrs = append(attrs, attribute.Bool(key, v))
		default:
			attrs = append(attrs, attribute.String(key, fmt.Sprintf("%v", v)))
		}
	}

	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordError records an error in the current span
func RecordError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}

	span.RecordError(err)
	span.SetStatus(trace.StatusError, err.Error())
}

// SetSpanStatus sets the status of the current span
func SetSpanStatus(ctx context.Context, code trace.StatusCode, description string) {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}

	span.SetStatus(code, description)
}

// GRPCServerInterceptors returns gRPC server interceptors for tracing
func GRPCServerInterceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return otelgrpc.UnaryServerInterceptor(), otelgrpc.StreamServerInterceptor()
}

// GRPCClientInterceptors returns gRPC client interceptors for tracing
func GRPCClientInterceptors() (grpc.UnaryClientInterceptor, grpc.StreamClientInterceptor) {
	return otelgrpc.UnaryClientInterceptor(), otelgrpc.StreamClientInterceptor()
}

// HTTPMiddleware returns HTTP middleware for tracing
func (m *Manager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := m.StartSpan(r.Context(), fmt.Sprintf("%s %s", r.Method, r.URL.Path),
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				semconv.HTTPMethodKey.String(r.Method),
				semconv.HTTPURLKey.String(r.URL.String()),
				semconv.HTTPUserAgentKey.String(r.UserAgent()),
				semconv.HTTPRemoteAddrKey.String(r.RemoteAddr),
			),
		)
		defer span.End()

		// Inject trace context into response headers
		propagator := otel.GetTextMapPropagator()
		propagator.Inject(ctx, propagation.HeaderCarrier(w.Header()))

		// Record response status
		defer func() {
			if w.Header().Get("Content-Length") != "" {
				span.SetAttributes(semconv.HTTPResponseContentLengthKey.String(w.Header().Get("Content-Length")))
			}
		}()

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InjectTraceContext injects trace context into gRPC metadata
func InjectTraceContext(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}

	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, &metadataCarrier{metadata: md})

	return metadata.NewOutgoingContext(ctx, md)
}

// ExtractTraceContext extracts trace context from gRPC metadata
func ExtractTraceContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}

	propagator := otel.GetTextMapPropagator()
	return propagator.Extract(ctx, &metadataCarrier{metadata: md})
}

// metadataCarrier implements TextMapCarrier for gRPC metadata
type metadataCarrier struct {
	metadata metadata.MD
}

func (c *metadataCarrier) Get(key string) string {
	values := c.metadata.Get(key)
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func (c *metadataCarrier) Set(key, value string) {
	c.metadata.Set(key, value)
}

func (c *metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(c.metadata))
	for key := range c.metadata {
		keys = append(keys, key)
	}
	return keys
}

// Tracer wraps common tracing operations
type Tracer struct {
	tracer trace.Tracer
	logger *zap.Logger
}

// NewTracer creates a new tracer wrapper
func NewTracer(name, version string, logger *zap.Logger) *Tracer {
	return &Tracer{
		tracer: otel.Tracer(name, trace.WithInstrumentationVersion(version)),
		logger: logger,
	}
}

// StartSpan starts a new span with common attributes
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// StartDBSpan starts a span for database operations
func (t *Tracer) StartDBSpan(ctx context.Context, operation, database, table string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, fmt.Sprintf("db.%s", operation),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.DBSystemKey.String(database),
			semconv.DBOperationKey.String(operation),
			semconv.DBNameKey.String(table),
		),
	)
}

// StartHTTPSpan starts a span for HTTP operations
func (t *Tracer) StartHTTPSpan(ctx context.Context, method, url string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, fmt.Sprintf("HTTP %s", method),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPMethodKey.String(method),
			semconv.HTTPURLKey.String(url),
		),
	)
}

// StartCacheSpan starts a span for cache operations
func (t *Tracer) StartCacheSpan(ctx context.Context, operation, key string) (context.Context, trace.Span) {
	return t.tracer.Start(ctx, fmt.Sprintf("cache.%s", operation),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("cache.operation", operation),
			attribute.String("cache.key", key),
		),
	)
}

// FinishSpan finishes a span with optional error
func (t *Tracer) FinishSpan(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(trace.StatusError, err.Error())
	} else {
		span.SetStatus(trace.StatusOK, "")
	}
	span.End()
}

// DefaultConfig returns a default tracing configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     true,
		ServiceName: "unknown",
		Version:     "unknown",
		Environment: "development",
		
		Jaeger: JaegerConfig{
			Endpoint: "http://localhost:14268/api/traces",
		},
		
		SamplingRatio: 1.0, // 100% sampling for development
		
		ResourceAttributes: map[string]string{},
	}
}

// GetServiceTracing creates a configured tracing manager for a service
func GetServiceTracing(serviceName, version, environment string) (*Manager, error) {
	config := DefaultConfig()
	config.ServiceName = serviceName
	config.Version = version
	config.Environment = environment
	
	// Adjust sampling based on environment
	if environment == "production" {
		config.SamplingRatio = 0.1 // 10% sampling for production
	}
	
	return NewManager(config, nil)
}