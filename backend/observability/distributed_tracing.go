package observability

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// DistributedTracing manages OpenTelemetry distributed tracing for the security pipeline
type DistributedTracing struct {
	logger        *zap.Logger
	config        *TracingConfig
	
	// OpenTelemetry components
	tracer        oteltrace.Tracer
	provider      *trace.TracerProvider
	propagator    propagation.TextMapPropagator
	
	// Custom span processors
	spanProcessors []trace.SpanProcessor
	
	// Pipeline-specific attributes
	serviceAttributes []attribute.KeyValue
	
	// Active spans tracking
	activeSpans   map[string]*SpanContext
	spansMutex    sync.RWMutex
	
	// Statistics
	stats         *TracingStats
	statsMutex    sync.RWMutex
}

// TracingConfig defines distributed tracing configuration
type TracingConfig struct {
	// Service identification
	ServiceName     string `json:"service_name"`
	ServiceVersion  string `json:"service_version"`
	Environment     string `json:"environment"`
	
	// Exporter configuration
	ExporterType    string `json:"exporter_type"` // jaeger, otlp, console
	JaegerEndpoint  string `json:"jaeger_endpoint"`
	OTLPEndpoint    string `json:"otlp_endpoint"`
	
	// Sampling configuration
	SamplingRatio   float64 `json:"sampling_ratio"`
	SamplingType    string  `json:"sampling_type"` // always_on, always_off, trace_id_ratio
	
	// Batch processing
	BatchTimeout    time.Duration `json:"batch_timeout"`
	ExportTimeout   time.Duration `json:"export_timeout"`
	MaxExportBatch  int           `json:"max_export_batch"`
	MaxQueueSize    int           `json:"max_queue_size"`
	
	// Security pipeline specific
	TraceEventProcessing   bool `json:"trace_event_processing"`
	TraceStreamProcessing  bool `json:"trace_stream_processing"`
	TraceQueryExecution    bool `json:"trace_query_execution"`
	TraceStorageOperations bool `json:"trace_storage_operations"`
	
	// Performance settings
	MaxSpanDuration        time.Duration `json:"max_span_duration"`
	SpanAttributeMaxLength int           `json:"span_attribute_max_length"`
	EnableMetrics          bool          `json:"enable_metrics"`
}

// SpanContext represents an active span context
type SpanContext struct {
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	Operation  string                 `json:"operation"`
	StartTime  time.Time              `json:"start_time"`
	Attributes map[string]interface{} `json:"attributes"`
	Tags       map[string]string      `json:"tags"`
	Events     []SpanEvent            `json:"events"`
}

// SpanEvent represents a span event
type SpanEvent struct {
	Name       string                 `json:"name"`
	Timestamp  time.Time              `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
}

// TracingStats tracks tracing statistics
type TracingStats struct {
	TotalSpans       int64         `json:"total_spans"`
	ActiveSpans      int64         `json:"active_spans"`
	CompletedSpans   int64         `json:"completed_spans"`
	ErrorSpans       int64         `json:"error_spans"`
	AverageSpanDuration time.Duration `json:"average_span_duration"`
	ExportedSpans    int64         `json:"exported_spans"`
	DroppedSpans     int64         `json:"dropped_spans"`
	LastExportTime   time.Time     `json:"last_export_time"`
}

// SecurityPipelineSpans defines span names for security pipeline operations
var SecurityPipelineSpans = struct {
	// Event ingestion
	EventIngestion    string
	EventValidation   string
	EventNormalization string
	EventEnrichment   string
	
	// Stream processing
	StreamProcessing  string
	EventCorrelation  string
	PatternMatching   string
	AnomalyDetection  string
	
	// Storage operations
	IndexingOperation string
	StorageWrite      string
	StorageRead       string
	QueryExecution    string
	
	// Analysis and reporting
	DashboardQuery    string
	ReportGeneration  string
	AlertProcessing   string
	NotificationSend  string
}{
	EventIngestion:    "event.ingestion",
	EventValidation:   "event.validation",
	EventNormalization: "event.normalization",
	EventEnrichment:   "event.enrichment",
	
	StreamProcessing:  "stream.processing",
	EventCorrelation:  "stream.correlation",
	PatternMatching:   "stream.pattern_matching",
	AnomalyDetection:  "stream.anomaly_detection",
	
	IndexingOperation: "storage.indexing",
	StorageWrite:      "storage.write",
	StorageRead:       "storage.read",
	QueryExecution:    "storage.query",
	
	DashboardQuery:    "analysis.dashboard_query",
	ReportGeneration:  "analysis.report_generation",
	AlertProcessing:   "analysis.alert_processing",
	NotificationSend:  "analysis.notification_send",
}

// SecurityPipelineAttributes defines common attributes for security pipeline spans
var SecurityPipelineAttributes = struct {
	// Event attributes
	EventType         attribute.Key
	EventSource       attribute.Key
	EventSeverity     attribute.Key
	EventCount        attribute.Key
	
	// Processing attributes
	ProcessingStage   attribute.Key
	ProcessingLatency attribute.Key
	BatchSize         attribute.Key
	
	// Storage attributes
	StorageBackend    attribute.Key
	IndexName         attribute.Key
	DocumentCount     attribute.Key
	QueryType         attribute.Key
	
	// Analysis attributes
	DashboardID       attribute.Key
	ReportType        attribute.Key
	AlertType         attribute.Key
	NotificationChannel attribute.Key
}{
	EventType:         attribute.Key("security.event.type"),
	EventSource:       attribute.Key("security.event.source"),
	EventSeverity:     attribute.Key("security.event.severity"),
	EventCount:        attribute.Key("security.event.count"),
	
	ProcessingStage:   attribute.Key("security.processing.stage"),
	ProcessingLatency: attribute.Key("security.processing.latency_ms"),
	BatchSize:         attribute.Key("security.processing.batch_size"),
	
	StorageBackend:    attribute.Key("security.storage.backend"),
	IndexName:         attribute.Key("security.storage.index"),
	DocumentCount:     attribute.Key("security.storage.document_count"),
	QueryType:         attribute.Key("security.storage.query_type"),
	
	DashboardID:       attribute.Key("security.analysis.dashboard_id"),
	ReportType:        attribute.Key("security.analysis.report_type"),
	AlertType:         attribute.Key("security.analysis.alert_type"),
	NotificationChannel: attribute.Key("security.analysis.notification_channel"),
}

// NewDistributedTracing creates a new distributed tracing manager
func NewDistributedTracing(logger *zap.Logger, config *TracingConfig) (*DistributedTracing, error) {
	if config == nil {
		return nil, fmt.Errorf("tracing configuration is required")
	}
	
	// Set defaults
	if err := setTracingDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	dt := &DistributedTracing{
		logger:            logger.With(zap.String("component", "distributed-tracing")),
		config:            config,
		activeSpans:       make(map[string]*SpanContext),
		stats:             &TracingStats{},
		serviceAttributes: []attribute.KeyValue{
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			semconv.DeploymentEnvironment(config.Environment),
		},
	}
	
	// Initialize OpenTelemetry
	if err := dt.initializeOpenTelemetry(); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}
	
	logger.Info("Distributed tracing initialized",
		zap.String("service_name", config.ServiceName),
		zap.String("exporter_type", config.ExporterType),
		zap.Float64("sampling_ratio", config.SamplingRatio),
	)
	
	return dt, nil
}

// setTracingDefaults sets configuration defaults
func setTracingDefaults(config *TracingConfig) error {
	if config.ServiceName == "" {
		config.ServiceName = "isectech-security-pipeline"
	}
	if config.ServiceVersion == "" {
		config.ServiceVersion = "1.0.0"
	}
	if config.Environment == "" {
		config.Environment = "production"
	}
	if config.ExporterType == "" {
		config.ExporterType = "jaeger"
	}
	if config.JaegerEndpoint == "" {
		config.JaegerEndpoint = "http://localhost:14268/api/traces"
	}
	if config.OTLPEndpoint == "" {
		config.OTLPEndpoint = "http://localhost:4318/v1/traces"
	}
	if config.SamplingRatio == 0 {
		config.SamplingRatio = 0.1 // 10% sampling by default
	}
	if config.SamplingType == "" {
		config.SamplingType = "trace_id_ratio"
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 5 * time.Second
	}
	if config.ExportTimeout == 0 {
		config.ExportTimeout = 30 * time.Second
	}
	if config.MaxExportBatch == 0 {
		config.MaxExportBatch = 512
	}
	if config.MaxQueueSize == 0 {
		config.MaxQueueSize = 2048
	}
	if config.MaxSpanDuration == 0 {
		config.MaxSpanDuration = 10 * time.Minute
	}
	if config.SpanAttributeMaxLength == 0 {
		config.SpanAttributeMaxLength = 1024
	}
	
	return nil
}

// initializeOpenTelemetry initializes OpenTelemetry components
func (dt *DistributedTracing) initializeOpenTelemetry() error {
	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(dt.serviceAttributes...),
		resource.WithFromEnv(),
		resource.WithProcessPID(),
		resource.WithProcessExecutableName(),
		resource.WithProcessExecutablePath(),
		resource.WithProcessOwner(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessRuntimeDescription(),
		resource.WithHost(),
		resource.WithOSType(),
		resource.WithOSDescription(),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}
	
	// Create exporter
	exporter, err := dt.createExporter()
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}
	
	// Create sampler
	sampler := dt.createSampler()
	
	// Create batch span processor
	batchProcessor := trace.NewBatchSpanProcessor(
		exporter,
		trace.WithBatchTimeout(dt.config.BatchTimeout),
		trace.WithExportTimeout(dt.config.ExportTimeout),
		trace.WithMaxExportBatchSize(dt.config.MaxExportBatch),
		trace.WithMaxQueueSize(dt.config.MaxQueueSize),
	)
	
	// Create custom span processor for statistics
	statsProcessor := dt.createStatsSpanProcessor()
	
	// Create tracer provider
	dt.provider = trace.NewTracerProvider(
		trace.WithResource(res),
		trace.WithSampler(sampler),
		trace.WithSpanProcessor(batchProcessor),
		trace.WithSpanProcessor(statsProcessor),
	)
	
	// Set global tracer provider
	otel.SetTracerProvider(dt.provider)
	
	// Create tracer
	dt.tracer = dt.provider.Tracer(
		dt.config.ServiceName,
		oteltrace.WithInstrumentationVersion(dt.config.ServiceVersion),
	)
	
	// Set up propagator
	dt.propagator = propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(dt.propagator)
	
	return nil
}

// createExporter creates the appropriate trace exporter
func (dt *DistributedTracing) createExporter() (trace.SpanExporter, error) {
	switch dt.config.ExporterType {
	case "jaeger":
		return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(dt.config.JaegerEndpoint)))
	case "otlp":
		return otlptracehttp.New(
			context.Background(),
			otlptracehttp.WithEndpoint(dt.config.OTLPEndpoint),
			otlptracehttp.WithInsecure(),
		)
	case "console":
		// For development/debugging
		return trace.NewNoopSpanExporter(), nil
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", dt.config.ExporterType)
	}
}

// createSampler creates the appropriate sampler
func (dt *DistributedTracing) createSampler() trace.Sampler {
	switch dt.config.SamplingType {
	case "always_on":
		return trace.AlwaysSample()
	case "always_off":
		return trace.NeverSample()
	case "trace_id_ratio":
		return trace.TraceIDRatioBased(dt.config.SamplingRatio)
	default:
		return trace.TraceIDRatioBased(dt.config.SamplingRatio)
	}
}

// createStatsSpanProcessor creates a custom span processor for statistics
func (dt *DistributedTracing) createStatsSpanProcessor() trace.SpanProcessor {
	return &statsSpanProcessor{
		tracer: dt,
	}
}

// statsSpanProcessor implements trace.SpanProcessor for collecting statistics
type statsSpanProcessor struct {
	tracer *DistributedTracing
}

func (ssp *statsSpanProcessor) OnStart(parent context.Context, s trace.ReadWriteSpan) {
	ssp.tracer.statsMutex.Lock()
	ssp.tracer.stats.TotalSpans++
	ssp.tracer.stats.ActiveSpans++
	ssp.tracer.statsMutex.Unlock()
}

func (ssp *statsSpanProcessor) OnEnd(s trace.ReadOnlySpan) {
	ssp.tracer.statsMutex.Lock()
	ssp.tracer.stats.ActiveSpans--
	ssp.tracer.stats.CompletedSpans++
	
	// Update average duration
	duration := s.EndTime().Sub(s.StartTime())
	if ssp.tracer.stats.AverageSpanDuration == 0 {
		ssp.tracer.stats.AverageSpanDuration = duration
	} else {
		ssp.tracer.stats.AverageSpanDuration = (ssp.tracer.stats.AverageSpanDuration + duration) / 2
	}
	
	// Check for errors
	if s.Status().Code == oteltrace.StatusCodeError {
		ssp.tracer.stats.ErrorSpans++
	}
	
	ssp.tracer.statsMutex.Unlock()
}

func (ssp *statsSpanProcessor) Shutdown(ctx context.Context) error {
	return nil
}

func (ssp *statsSpanProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

// StartSpan starts a new span for the security pipeline
func (dt *DistributedTracing) StartSpan(ctx context.Context, operationName string, opts ...oteltrace.SpanStartOption) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, operationName, opts...)
}

// StartEventIngestionSpan starts a span for event ingestion
func (dt *DistributedTracing) StartEventIngestionSpan(ctx context.Context, eventType, source string, eventCount int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.EventIngestion,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.EventType.String(eventType),
			SecurityPipelineAttributes.EventSource.String(source),
			SecurityPipelineAttributes.EventCount.Int(eventCount),
			SecurityPipelineAttributes.ProcessingStage.String("ingestion"),
		),
	)
}

// StartStreamProcessingSpan starts a span for stream processing
func (dt *DistributedTracing) StartStreamProcessingSpan(ctx context.Context, stage string, batchSize int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.StreamProcessing,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.ProcessingStage.String(stage),
			SecurityPipelineAttributes.BatchSize.Int(batchSize),
		),
	)
}

// StartStorageOperationSpan starts a span for storage operations
func (dt *DistributedTracing) StartStorageOperationSpan(ctx context.Context, operation, backend, index string, docCount int) (context.Context, oteltrace.Span) {
	var operationName string
	switch operation {
	case "write":
		operationName = SecurityPipelineSpans.StorageWrite
	case "read":
		operationName = SecurityPipelineSpans.StorageRead
	case "query":
		operationName = SecurityPipelineSpans.QueryExecution
	case "index":
		operationName = SecurityPipelineSpans.IndexingOperation
	default:
		operationName = "storage.operation"
	}
	
	return dt.tracer.Start(ctx, operationName,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.StorageBackend.String(backend),
			SecurityPipelineAttributes.IndexName.String(index),
			SecurityPipelineAttributes.DocumentCount.Int(docCount),
		),
	)
}

// StartQueryExecutionSpan starts a span for query execution
func (dt *DistributedTracing) StartQueryExecutionSpan(ctx context.Context, queryType, backend string) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.QueryExecution,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.QueryType.String(queryType),
			SecurityPipelineAttributes.StorageBackend.String(backend),
		),
	)
}

// StartDashboardQuerySpan starts a span for dashboard queries
func (dt *DistributedTracing) StartDashboardQuerySpan(ctx context.Context, dashboardID, queryType string) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.DashboardQuery,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.DashboardID.String(dashboardID),
			SecurityPipelineAttributes.QueryType.String(queryType),
		),
	)
}

// StartReportGenerationSpan starts a span for report generation
func (dt *DistributedTracing) StartReportGenerationSpan(ctx context.Context, reportType string) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.ReportGeneration,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.ReportType.String(reportType),
		),
	)
}

// StartAlertProcessingSpan starts a span for alert processing
func (dt *DistributedTracing) StartAlertProcessingSpan(ctx context.Context, alertType, severity string) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.AlertProcessing,
		oteltrace.WithAttributes(
			SecurityPipelineAttributes.AlertType.String(alertType),
			SecurityPipelineAttributes.EventSeverity.String(severity),
		),
	)
}

// AddSpanEvent adds an event to a span
func (dt *DistributedTracing) AddSpanEvent(span oteltrace.Span, name string, attributes ...attribute.KeyValue) {
	span.AddEvent(name, oteltrace.WithAttributes(attributes...))
}

// AddSpanError adds an error to a span
func (dt *DistributedTracing) AddSpanError(span oteltrace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(oteltrace.StatusCodeError, err.Error())
}

// SetSpanAttributes sets attributes on a span
func (dt *DistributedTracing) SetSpanAttributes(span oteltrace.Span, attributes ...attribute.KeyValue) {
	span.SetAttributes(attributes...)
}

// InjectTraceContext injects trace context into HTTP headers
func (dt *DistributedTracing) InjectTraceContext(ctx context.Context, headers http.Header) {
	dt.propagator.Inject(ctx, propagation.HeaderCarrier(headers))
}

// ExtractTraceContext extracts trace context from HTTP headers
func (dt *DistributedTracing) ExtractTraceContext(ctx context.Context, headers http.Header) context.Context {
	return dt.propagator.Extract(ctx, propagation.HeaderCarrier(headers))
}

// InjectTraceContextToMap injects trace context into a map
func (dt *DistributedTracing) InjectTraceContextToMap(ctx context.Context, carrier map[string]string) {
	dt.propagator.Inject(ctx, propagation.MapCarrier(carrier))
}

// ExtractTraceContextFromMap extracts trace context from a map
func (dt *DistributedTracing) ExtractTraceContextFromMap(ctx context.Context, carrier map[string]string) context.Context {
	return dt.propagator.Extract(ctx, propagation.MapCarrier(carrier))
}

// GetTraceID gets the trace ID from context
func (dt *DistributedTracing) GetTraceID(ctx context.Context) string {
	spanCtx := oteltrace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		return spanCtx.TraceID().String()
	}
	return ""
}

// GetSpanID gets the span ID from context
func (dt *DistributedTracing) GetSpanID(ctx context.Context) string {
	spanCtx := oteltrace.SpanContextFromContext(ctx)
	if spanCtx.IsValid() {
		return spanCtx.SpanID().String()
	}
	return ""
}

// WithTraceContext creates a new context with trace information
func (dt *DistributedTracing) WithTraceContext(ctx context.Context, traceID, spanID string) (context.Context, error) {
	// This would typically be used when reconstructing context from stored trace information
	// Implementation would depend on specific tracing needs
	return ctx, nil
}

// CreateChildSpan creates a child span from a parent context
func (dt *DistributedTracing) CreateChildSpan(parentCtx context.Context, operationName string, attributes ...attribute.KeyValue) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(parentCtx, operationName,
		oteltrace.WithAttributes(attributes...),
	)
}

// TraceEventProcessingPipeline creates a comprehensive trace for event processing
func (dt *DistributedTracing) TraceEventProcessingPipeline(ctx context.Context, eventID, eventType, source string) (context.Context, func()) {
	// Start root span for the entire pipeline
	ctx, rootSpan := dt.tracer.Start(ctx, "security.event.pipeline",
		oteltrace.WithAttributes(
			attribute.String("event.id", eventID),
			SecurityPipelineAttributes.EventType.String(eventType),
			SecurityPipelineAttributes.EventSource.String(source),
		),
	)
	
	// Track pipeline execution
	dt.spansMutex.Lock()
	dt.activeSpans[eventID] = &SpanContext{
		TraceID:   dt.GetTraceID(ctx),
		SpanID:    dt.GetSpanID(ctx),
		Operation: "security.event.pipeline",
		StartTime: time.Now(),
		Attributes: map[string]interface{}{
			"event.id":    eventID,
			"event.type":  eventType,
			"event.source": source,
		},
		Tags:   make(map[string]string),
		Events: []SpanEvent{},
	}
	dt.spansMutex.Unlock()
	
	// Return context and cleanup function
	return ctx, func() {
		rootSpan.End()
		
		dt.spansMutex.Lock()
		delete(dt.activeSpans, eventID)
		dt.spansMutex.Unlock()
	}
}

// TraceSecurityEventEnrichment traces event enrichment operations
func (dt *DistributedTracing) TraceSecurityEventEnrichment(ctx context.Context, enrichmentType string, sourceCount, enrichedCount int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.EventEnrichment,
		oteltrace.WithAttributes(
			attribute.String("enrichment.type", enrichmentType),
			attribute.Int("enrichment.source_count", sourceCount),
			attribute.Int("enrichment.enriched_count", enrichedCount),
		),
	)
}

// TraceCorrelationEngine traces event correlation operations
func (dt *DistributedTracing) TraceCorrelationEngine(ctx context.Context, correlationType string, windowSize time.Duration, eventCount int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.EventCorrelation,
		oteltrace.WithAttributes(
			attribute.String("correlation.type", correlationType),
			attribute.String("correlation.window", windowSize.String()),
			SecurityPipelineAttributes.EventCount.Int(eventCount),
		),
	)
}

// TracePatternMatching traces pattern matching operations
func (dt *DistributedTracing) TracePatternMatching(ctx context.Context, patternType string, ruleCount, matchCount int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.PatternMatching,
		oteltrace.WithAttributes(
			attribute.String("pattern.type", patternType),
			attribute.Int("pattern.rule_count", ruleCount),
			attribute.Int("pattern.match_count", matchCount),
		),
	)
}

// TraceAnomalyDetection traces anomaly detection operations
func (dt *DistributedTracing) TraceAnomalyDetection(ctx context.Context, detectionType string, modelVersion string, anomaliesFound int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, SecurityPipelineSpans.AnomalyDetection,
		oteltrace.WithAttributes(
			attribute.String("anomaly.type", detectionType),
			attribute.String("anomaly.model_version", modelVersion),
			attribute.Int("anomaly.found_count", anomaliesFound),
		),
	)
}

// GetActiveSpans returns currently active spans
func (dt *DistributedTracing) GetActiveSpans() map[string]*SpanContext {
	dt.spansMutex.RLock()
	defer dt.spansMutex.RUnlock()
	
	spans := make(map[string]*SpanContext)
	for k, v := range dt.activeSpans {
		spans[k] = v
	}
	return spans
}

// GetTracingStats returns tracing statistics
func (dt *DistributedTracing) GetTracingStats() *TracingStats {
	dt.statsMutex.RLock()
	defer dt.statsMutex.RUnlock()
	
	stats := *dt.stats
	return &stats
}

// FlushTraces forces immediate export of pending spans
func (dt *DistributedTracing) FlushTraces(ctx context.Context) error {
	return dt.provider.ForceFlush(ctx)
}

// IsHealthy returns the health status of the tracing system
func (dt *DistributedTracing) IsHealthy() bool {
	// Check if tracer provider is available and active spans are reasonable
	if dt.provider == nil || dt.tracer == nil {
		return false
	}
	
	dt.statsMutex.RLock()
	activeSpans := dt.stats.ActiveSpans
	dt.statsMutex.RUnlock()
	
	// Consider unhealthy if too many spans are active (potential memory leak)
	if activeSpans > 10000 {
		return false
	}
	
	return true
}

// Close gracefully shuts down the tracing system
func (dt *DistributedTracing) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Flush any pending spans
	if err := dt.provider.ForceFlush(ctx); err != nil {
		dt.logger.Warn("Failed to flush traces", zap.Error(err))
	}
	
	// Shutdown tracer provider
	if err := dt.provider.Shutdown(ctx); err != nil {
		dt.logger.Error("Failed to shutdown tracer provider", zap.Error(err))
		return err
	}
	
	dt.logger.Info("Distributed tracing system closed")
	return nil
}

// Utility functions for common tracing patterns

// TraceHTTPRequest traces an HTTP request
func (dt *DistributedTracing) TraceHTTPRequest(ctx context.Context, method, url string, statusCode int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, fmt.Sprintf("HTTP %s", method),
		oteltrace.WithAttributes(
			semconv.HTTPMethod(method),
			semconv.HTTPURL(url),
			semconv.HTTPStatusCode(statusCode),
		),
	)
}

// TraceDBOperation traces a database operation
func (dt *DistributedTracing) TraceDBOperation(ctx context.Context, operation, table string, affectedRows int) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, fmt.Sprintf("DB %s", operation),
		oteltrace.WithAttributes(
			semconv.DBOperation(operation),
			semconv.DBSQLTable(table),
			attribute.Int("db.affected_rows", affectedRows),
		),
	)
}

// TraceCacheOperation traces a cache operation
func (dt *DistributedTracing) TraceCacheOperation(ctx context.Context, operation, key string, hit bool) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, fmt.Sprintf("Cache %s", operation),
		oteltrace.WithAttributes(
			attribute.String("cache.operation", operation),
			attribute.String("cache.key", key),
			attribute.Bool("cache.hit", hit),
		),
	)
}

// TraceExternalAPICall traces external API calls
func (dt *DistributedTracing) TraceExternalAPICall(ctx context.Context, service, endpoint string, statusCode int, latency time.Duration) (context.Context, oteltrace.Span) {
	return dt.tracer.Start(ctx, fmt.Sprintf("External API %s", service),
		oteltrace.WithAttributes(
			attribute.String("external.service", service),
			attribute.String("external.endpoint", endpoint),
			attribute.Int("external.status_code", statusCode),
			attribute.Int64("external.latency_ms", latency.Milliseconds()),
		),
	)
}