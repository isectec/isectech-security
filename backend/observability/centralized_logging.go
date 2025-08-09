package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// CentralizedLogging manages centralized logging with security event correlation
type CentralizedLogging struct {
	logger      *zap.Logger
	config      *LoggingConfig
	
	// Log processors
	processors  map[string]LogProcessor
	procMutex   sync.RWMutex
	
	// Log correlation
	correlator  *LogCorrelator
	
	// Log storage
	storage     LogStorage
	
	// Log forwarding
	forwarders  []LogForwarder
	
	// Background processing
	ctx         context.Context
	cancel      context.CancelFunc
	
	// Statistics
	stats       *LoggingStats
	statsMutex  sync.RWMutex
}

// LoggingConfig defines centralized logging configuration
type LoggingConfig struct {
	// Service configuration
	ServiceName     string `json:"service_name"`
	Environment     string `json:"environment"`
	
	// Log levels
	DefaultLevel    string `json:"default_level"`
	ComponentLevels map[string]string `json:"component_levels"`
	
	// Storage configuration
	StorageType     string `json:"storage_type"` // elasticsearch, loki, file, syslog
	ElasticsearchConfig *ElasticsearchLogConfig `json:"elasticsearch_config"`
	LokiConfig      *LokiLogConfig `json:"loki_config"`
	FileConfig      *FileLogConfig `json:"file_config"`
	SyslogConfig    *SyslogLogConfig `json:"syslog_config"`
	
	// Correlation configuration
	CorrelationEnabled bool `json:"correlation_enabled"`
	CorrelationWindow  time.Duration `json:"correlation_window"`
	CorrelationRules   []CorrelationRule `json:"correlation_rules"`
	
	// Processing configuration
	BatchSize       int           `json:"batch_size"`
	FlushInterval   time.Duration `json:"flush_interval"`
	MaxRetries      int           `json:"max_retries"`
	RetryDelay      time.Duration `json:"retry_delay"`
	
	// Security configuration
	SensitiveFields []string      `json:"sensitive_fields"`
	MaskSensitive   bool          `json:"mask_sensitive"`
	EncryptLogs     bool          `json:"encrypt_logs"`
	EncryptionKey   string        `json:"encryption_key"`
	
	// Performance configuration
	BufferSize      int           `json:"buffer_size"`
	CompressLogs    bool          `json:"compress_logs"`
	EnableMetrics   bool          `json:"enable_metrics"`
}

// ElasticsearchLogConfig defines Elasticsearch logging configuration
type ElasticsearchLogConfig struct {
	URLs            []string `json:"urls"`
	Username        string   `json:"username"`
	Password        string   `json:"password"`
	IndexPattern    string   `json:"index_pattern"`
	IndexRotation   string   `json:"index_rotation"` // daily, weekly, monthly
	ShardCount      int      `json:"shard_count"`
	ReplicaCount    int      `json:"replica_count"`
}

// LokiLogConfig defines Loki logging configuration
type LokiLogConfig struct {
	URL         string            `json:"url"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	Labels      map[string]string `json:"labels"`
	BatchSize   int               `json:"batch_size"`
	BatchWait   time.Duration     `json:"batch_wait"`
}

// FileLogConfig defines file logging configuration
type FileLogConfig struct {
	Path            string `json:"path"`
	MaxSize         int    `json:"max_size_mb"`
	MaxBackups      int    `json:"max_backups"`
	MaxAge          int    `json:"max_age_days"`
	Compress        bool   `json:"compress"`
}

// SyslogLogConfig defines syslog configuration
type SyslogLogConfig struct {
	Network     string `json:"network"` // tcp, udp, unix
	Address     string `json:"address"`
	Priority    string `json:"priority"`
	Tag         string `json:"tag"`
	Facility    string `json:"facility"`
}

// LogProcessor processes logs before storage/forwarding
type LogProcessor interface {
	ProcessLog(ctx context.Context, entry *LogEntry) (*LogEntry, error)
	GetName() string
	IsEnabled() bool
}

// LogStorage stores logs
type LogStorage interface {
	StoreLogs(ctx context.Context, entries []*LogEntry) error
	QueryLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error)
	IsHealthy() bool
	Close() error
}

// LogForwarder forwards logs to external systems
type LogForwarder interface {
	ForwardLogs(ctx context.Context, entries []*LogEntry) error
	GetDestination() string
	IsHealthy() bool
	Close() error
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp       time.Time              `json:"timestamp"`
	Level           string                 `json:"level"`
	Message         string                 `json:"message"`
	Component       string                 `json:"component"`
	ServiceName     string                 `json:"service_name"`
	Environment     string                 `json:"environment"`
	
	// Tracing information
	TraceID         string                 `json:"trace_id,omitempty"`
	SpanID          string                 `json:"span_id,omitempty"`
	
	// Security context
	UserID          string                 `json:"user_id,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	RequestID       string                 `json:"request_id,omitempty"`
	SourceIP        string                 `json:"source_ip,omitempty"`
	
	// Event context
	EventType       string                 `json:"event_type,omitempty"`
	EventSource     string                 `json:"event_source,omitempty"`
	EventSeverity   string                 `json:"event_severity,omitempty"`
	EventID         string                 `json:"event_id,omitempty"`
	
	// Custom fields
	Fields          map[string]interface{} `json:"fields,omitempty"`
	
	// Metadata
	Host            string                 `json:"host"`
	ProcessID       int                    `json:"process_id"`
	ThreadID        string                 `json:"thread_id,omitempty"`
	
	// Correlation
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	ParentLogID     string                 `json:"parent_log_id,omitempty"`
	
	// Performance
	Duration        time.Duration          `json:"duration,omitempty"`
	
	// Error information
	Error           string                 `json:"error,omitempty"`
	ErrorStack      string                 `json:"error_stack,omitempty"`
}

// LogQuery represents a log query
type LogQuery struct {
	StartTime       time.Time              `json:"start_time"`
	EndTime         time.Time              `json:"end_time"`
	Levels          []string               `json:"levels"`
	Components      []string               `json:"components"`
	Services        []string               `json:"services"`
	TraceID         string                 `json:"trace_id,omitempty"`
	UserID          string                 `json:"user_id,omitempty"`
	EventType       string                 `json:"event_type,omitempty"`
	SearchText      string                 `json:"search_text,omitempty"`
	Fields          map[string]interface{} `json:"fields,omitempty"`
	Limit           int                    `json:"limit"`
	Offset          int                    `json:"offset"`
	SortBy          string                 `json:"sort_by"`
	SortOrder       string                 `json:"sort_order"`
}

// LogCorrelator correlates related log entries
type LogCorrelator struct {
	logger          *zap.Logger
	config          *LoggingConfig
	rules           []CorrelationRule
	correlationMap  map[string][]*LogEntry
	correlationMutex sync.RWMutex
	cleanupTicker   *time.Ticker
	ctx             context.Context
	cancel          context.CancelFunc
}

// CorrelationRule defines log correlation rules
type CorrelationRule struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Enabled         bool                   `json:"enabled"`
	
	// Matching criteria
	Components      []string               `json:"components"`
	EventTypes      []string               `json:"event_types"`
	Levels          []string               `json:"levels"`
	TimeWindow      time.Duration          `json:"time_window"`
	
	// Correlation fields
	CorrelationFields []string             `json:"correlation_fields"`
	
	// Actions
	Actions         []CorrelationAction    `json:"actions"`
	
	// Conditions
	MinEvents       int                    `json:"min_events"`
	MaxEvents       int                    `json:"max_events"`
	Pattern         string                 `json:"pattern,omitempty"`
}

// CorrelationAction defines actions to take when correlation matches
type CorrelationAction struct {
	Type            string                 `json:"type"` // alert, aggregate, forward, enrich
	Parameters      map[string]interface{} `json:"parameters"`
}

// LoggingStats tracks logging statistics
type LoggingStats struct {
	TotalLogs       int64         `json:"total_logs"`
	LogsByLevel     map[string]int64 `json:"logs_by_level"`
	LogsByComponent map[string]int64 `json:"logs_by_component"`
	ErrorCount      int64         `json:"error_count"`
	DroppedLogs     int64         `json:"dropped_logs"`
	CorrelatedLogs  int64         `json:"correlated_logs"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastLogTime     time.Time     `json:"last_log_time"`
}

// NewCentralizedLogging creates a new centralized logging system
func NewCentralizedLogging(logger *zap.Logger, config *LoggingConfig) (*CentralizedLogging, error) {
	if config == nil {
		return nil, fmt.Errorf("logging configuration is required")
	}
	
	// Set defaults
	if err := setLoggingDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cl := &CentralizedLogging{
		logger:     logger.With(zap.String("component", "centralized-logging")),
		config:     config,
		processors: make(map[string]LogProcessor),
		forwarders: make([]LogForwarder, 0),
		stats:      &LoggingStats{
			LogsByLevel:     make(map[string]int64),
			LogsByComponent: make(map[string]int64),
		},
		ctx:        ctx,
		cancel:     cancel,
	}
	
	// Initialize log storage
	if err := cl.initializeStorage(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize log storage: %w", err)
	}
	
	// Initialize log correlation
	if config.CorrelationEnabled {
		correlator, err := NewLogCorrelator(logger, config, ctx)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to initialize log correlator: %w", err)
		}
		cl.correlator = correlator
	}
	
	// Initialize default processors
	if err := cl.initializeProcessors(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize processors: %w", err)
	}
	
	// Initialize forwarders
	if err := cl.initializeForwarders(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize forwarders: %w", err)
	}
	
	logger.Info("Centralized logging initialized",
		zap.String("service_name", config.ServiceName),
		zap.String("storage_type", config.StorageType),
		zap.Bool("correlation_enabled", config.CorrelationEnabled),
	)
	
	return cl, nil
}

// setLoggingDefaults sets configuration defaults
func setLoggingDefaults(config *LoggingConfig) error {
	if config.ServiceName == "" {
		config.ServiceName = "isectech-security-pipeline"
	}
	if config.Environment == "" {
		config.Environment = "production"
	}
	if config.DefaultLevel == "" {
		config.DefaultLevel = "info"
	}
	if config.StorageType == "" {
		config.StorageType = "elasticsearch"
	}
	if config.CorrelationWindow == 0 {
		config.CorrelationWindow = 5 * time.Minute
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	
	// Set default sensitive fields
	if len(config.SensitiveFields) == 0 {
		config.SensitiveFields = []string{
			"password", "token", "secret", "key", "authorization",
			"cookie", "session", "credential", "private", "confidential",
		}
	}
	
	return nil
}

// initializeStorage initializes log storage based on configuration
func (cl *CentralizedLogging) initializeStorage() error {
	switch cl.config.StorageType {
	case "elasticsearch":
		if cl.config.ElasticsearchConfig == nil {
			return fmt.Errorf("elasticsearch configuration is required")
		}
		storage, err := NewElasticsearchLogStorage(cl.logger, cl.config.ElasticsearchConfig)
		if err != nil {
			return fmt.Errorf("failed to create elasticsearch storage: %w", err)
		}
		cl.storage = storage
	case "loki":
		if cl.config.LokiConfig == nil {
			return fmt.Errorf("loki configuration is required")
		}
		storage, err := NewLokiLogStorage(cl.logger, cl.config.LokiConfig)
		if err != nil {
			return fmt.Errorf("failed to create loki storage: %w", err)
		}
		cl.storage = storage
	case "file":
		if cl.config.FileConfig == nil {
			return fmt.Errorf("file configuration is required")
		}
		storage, err := NewFileLogStorage(cl.logger, cl.config.FileConfig)
		if err != nil {
			return fmt.Errorf("failed to create file storage: %w", err)
		}
		cl.storage = storage
	default:
		return fmt.Errorf("unsupported storage type: %s", cl.config.StorageType)
	}
	
	return nil
}

// initializeProcessors initializes default log processors
func (cl *CentralizedLogging) initializeProcessors() error {
	// Security processor - masks sensitive fields
	if cl.config.MaskSensitive {
		securityProcessor := NewSecurityLogProcessor(cl.config.SensitiveFields)
		cl.processors["security"] = securityProcessor
	}
	
	// Enrichment processor - adds metadata
	enrichmentProcessor := NewEnrichmentLogProcessor(cl.config.ServiceName, cl.config.Environment)
	cl.processors["enrichment"] = enrichmentProcessor
	
	// Formatting processor - ensures consistent format
	formattingProcessor := NewFormattingLogProcessor()
	cl.processors["formatting"] = formattingProcessor
	
	return nil
}

// initializeForwarders initializes log forwarders
func (cl *CentralizedLogging) initializeForwarders() error {
	// Syslog forwarder
	if cl.config.SyslogConfig != nil {
		forwarder, err := NewSyslogForwarder(cl.logger, cl.config.SyslogConfig)
		if err != nil {
			return fmt.Errorf("failed to create syslog forwarder: %w", err)
		}
		cl.forwarders = append(cl.forwarders, forwarder)
	}
	
	return nil
}

// LogEntry logs an entry through the centralized logging system
func (cl *CentralizedLogging) LogEntry(ctx context.Context, entry *LogEntry) error {
	start := time.Now()
	
	// Set default fields
	if entry.Timestamp.IsZero() {
		entry.Timestamp = start
	}
	if entry.ServiceName == "" {
		entry.ServiceName = cl.config.ServiceName
	}
	if entry.Environment == "" {
		entry.Environment = cl.config.Environment
	}
	
	// Extract trace context if available
	if traceID := GetTraceIDFromContext(ctx); traceID != "" {
		entry.TraceID = traceID
	}
	if spanID := GetSpanIDFromContext(ctx); spanID != "" {
		entry.SpanID = spanID
	}
	
	// Process through all processors
	processedEntry := entry
	cl.procMutex.RLock()
	for _, processor := range cl.processors {
		if processor.IsEnabled() {
			var err error
			processedEntry, err = processor.ProcessLog(ctx, processedEntry)
			if err != nil {
				cl.logger.Warn("Log processor failed",
					zap.String("processor", processor.GetName()),
					zap.Error(err),
				)
				continue
			}
		}
	}
	cl.procMutex.RUnlock()
	
	// Store log
	if cl.storage != nil {
		if err := cl.storage.StoreLogs(ctx, []*LogEntry{processedEntry}); err != nil {
			cl.statsMutex.Lock()
			cl.stats.ErrorCount++
			cl.statsMutex.Unlock()
			return fmt.Errorf("failed to store log: %w", err)
		}
	}
	
	// Forward to external systems
	for _, forwarder := range cl.forwarders {
		if err := forwarder.ForwardLogs(ctx, []*LogEntry{processedEntry}); err != nil {
			cl.logger.Warn("Log forwarding failed",
				zap.String("destination", forwarder.GetDestination()),
				zap.Error(err),
			)
		}
	}
	
	// Correlate logs if enabled
	if cl.correlator != nil {
		cl.correlator.CorrelateLog(processedEntry)
	}
	
	// Update statistics
	cl.updateStats(processedEntry, time.Since(start))
	
	return nil
}

// LogSecurityEvent logs a security event with enhanced context
func (cl *CentralizedLogging) LogSecurityEvent(ctx context.Context, eventType, source, severity, message string, fields map[string]interface{}) error {
	entry := &LogEntry{
		Level:         "info",
		Message:       message,
		Component:     "security",
		EventType:     eventType,
		EventSource:   source,
		EventSeverity: severity,
		Fields:        fields,
	}
	
	// Set log level based on severity
	switch severity {
	case "critical", "high":
		entry.Level = "error"
	case "medium":
		entry.Level = "warn"
	case "low", "info":
		entry.Level = "info"
	}
	
	return cl.LogEntry(ctx, entry)
}

// LogProcessingStage logs processing stage information
func (cl *CentralizedLogging) LogProcessingStage(ctx context.Context, stage, operation string, duration time.Duration, success bool, fields map[string]interface{}) error {
	level := "info"
	if !success {
		level = "error"
	}
	
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["processing_stage"] = stage
	fields["operation"] = operation
	fields["duration_ms"] = duration.Milliseconds()
	fields["success"] = success
	
	entry := &LogEntry{
		Level:     level,
		Message:   fmt.Sprintf("Processing stage: %s - %s", stage, operation),
		Component: "stream-processing",
		Duration:  duration,
		Fields:    fields,
	}
	
	return cl.LogEntry(ctx, entry)
}

// LogStorageOperation logs storage operations
func (cl *CentralizedLogging) LogStorageOperation(ctx context.Context, operation, backend, index string, docCount int, duration time.Duration, err error) error {
	level := "info"
	message := fmt.Sprintf("Storage operation: %s on %s.%s (%d docs)", operation, backend, index, docCount)
	
	fields := map[string]interface{}{
		"storage_operation": operation,
		"storage_backend":   backend,
		"storage_index":     index,
		"document_count":    docCount,
		"duration_ms":       duration.Milliseconds(),
	}
	
	if err != nil {
		level = "error"
		message += fmt.Sprintf(" - Error: %s", err.Error())
		fields["error"] = err.Error()
	}
	
	entry := &LogEntry{
		Level:     level,
		Message:   message,
		Component: "storage",
		Duration:  duration,
		Fields:    fields,
		Error:     getErrorString(err),
	}
	
	return cl.LogEntry(ctx, entry)
}

// LogQueryExecution logs query execution
func (cl *CentralizedLogging) LogQueryExecution(ctx context.Context, queryType, backend string, rowCount int, duration time.Duration, err error) error {
	level := "info"
	message := fmt.Sprintf("Query execution: %s on %s (%d rows)", queryType, backend, rowCount)
	
	fields := map[string]interface{}{
		"query_type":     queryType,
		"query_backend":  backend,
		"row_count":      rowCount,
		"duration_ms":    duration.Milliseconds(),
	}
	
	if err != nil {
		level = "error"
		message += fmt.Sprintf(" - Error: %s", err.Error())
		fields["error"] = err.Error()
	}
	
	entry := &LogEntry{
		Level:     level,
		Message:   message,
		Component: "query",
		Duration:  duration,
		Fields:    fields,
		Error:     getErrorString(err),
	}
	
	return cl.LogEntry(ctx, entry)
}

// QueryLogs queries stored logs
func (cl *CentralizedLogging) QueryLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error) {
	if cl.storage == nil {
		return nil, fmt.Errorf("log storage not configured")
	}
	
	return cl.storage.QueryLogs(ctx, query)
}

// GetCorrelatedLogs returns correlated log entries
func (cl *CentralizedLogging) GetCorrelatedLogs(correlationID string) ([]*LogEntry, error) {
	if cl.correlator == nil {
		return nil, fmt.Errorf("log correlation not enabled")
	}
	
	return cl.correlator.GetCorrelatedLogs(correlationID), nil
}

// AddLogProcessor adds a custom log processor
func (cl *CentralizedLogging) AddLogProcessor(name string, processor LogProcessor) {
	cl.procMutex.Lock()
	cl.processors[name] = processor
	cl.procMutex.Unlock()
	
	cl.logger.Info("Log processor added", zap.String("processor", name))
}

// RemoveLogProcessor removes a log processor
func (cl *CentralizedLogging) RemoveLogProcessor(name string) {
	cl.procMutex.Lock()
	delete(cl.processors, name)
	cl.procMutex.Unlock()
	
	cl.logger.Info("Log processor removed", zap.String("processor", name))
}

// AddLogForwarder adds a log forwarder
func (cl *CentralizedLogging) AddLogForwarder(forwarder LogForwarder) {
	cl.forwarders = append(cl.forwarders, forwarder)
	cl.logger.Info("Log forwarder added", zap.String("destination", forwarder.GetDestination()))
}

// updateStats updates logging statistics
func (cl *CentralizedLogging) updateStats(entry *LogEntry, latency time.Duration) {
	cl.statsMutex.Lock()
	defer cl.statsMutex.Unlock()
	
	cl.stats.TotalLogs++
	cl.stats.LogsByLevel[entry.Level]++
	cl.stats.LogsByComponent[entry.Component]++
	cl.stats.LastLogTime = entry.Timestamp
	
	// Update average latency
	if cl.stats.AverageLatency == 0 {
		cl.stats.AverageLatency = latency
	} else {
		cl.stats.AverageLatency = (cl.stats.AverageLatency + latency) / 2
	}
	
	if entry.Error != "" {
		cl.stats.ErrorCount++
	}
}

// GetLoggingStats returns logging statistics
func (cl *CentralizedLogging) GetLoggingStats() *LoggingStats {
	cl.statsMutex.RLock()
	defer cl.statsMutex.RUnlock()
	
	stats := *cl.stats
	return &stats
}

// IsHealthy returns the health status
func (cl *CentralizedLogging) IsHealthy() bool {
	if cl.storage != nil && !cl.storage.IsHealthy() {
		return false
	}
	
	for _, forwarder := range cl.forwarders {
		if !forwarder.IsHealthy() {
			return false
		}
	}
	
	return true
}

// Close closes the centralized logging system
func (cl *CentralizedLogging) Close() error {
	if cl.cancel != nil {
		cl.cancel()
	}
	
	// Close storage
	if cl.storage != nil {
		if err := cl.storage.Close(); err != nil {
			cl.logger.Warn("Failed to close log storage", zap.Error(err))
		}
	}
	
	// Close forwarders
	for _, forwarder := range cl.forwarders {
		if err := forwarder.Close(); err != nil {
			cl.logger.Warn("Failed to close log forwarder",
				zap.String("destination", forwarder.GetDestination()),
				zap.Error(err),
			)
		}
	}
	
	// Close correlator
	if cl.correlator != nil {
		cl.correlator.Close()
	}
	
	cl.logger.Info("Centralized logging system closed")
	return nil
}

// Utility functions

func getErrorString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func GetTraceIDFromContext(ctx context.Context) string {
	// Implementation would extract trace ID from context
	// This would integrate with the distributed tracing system
	return ""
}

func GetSpanIDFromContext(ctx context.Context) string {
	// Implementation would extract span ID from context
	// This would integrate with the distributed tracing system
	return ""
}

// Placeholder implementations for supporting components

func NewLogCorrelator(logger *zap.Logger, config *LoggingConfig, ctx context.Context) (*LogCorrelator, error) {
	correlatorCtx, cancel := context.WithCancel(ctx)
	
	correlator := &LogCorrelator{
		logger:         logger.With(zap.String("component", "log-correlator")),
		config:         config,
		rules:          config.CorrelationRules,
		correlationMap: make(map[string][]*LogEntry),
		ctx:            correlatorCtx,
		cancel:         cancel,
	}
	
	// Start cleanup process
	correlator.cleanupTicker = time.NewTicker(config.CorrelationWindow / 2)
	go correlator.runCleanup()
	
	return correlator, nil
}

func (lc *LogCorrelator) CorrelateLog(entry *LogEntry) {
	// Implementation would correlate logs based on rules
}

func (lc *LogCorrelator) GetCorrelatedLogs(correlationID string) []*LogEntry {
	lc.correlationMutex.RLock()
	defer lc.correlationMutex.RUnlock()
	
	if logs, exists := lc.correlationMap[correlationID]; exists {
		return logs
	}
	return nil
}

func (lc *LogCorrelator) runCleanup() {
	for {
		select {
		case <-lc.ctx.Done():
			return
		case <-lc.cleanupTicker.C:
			lc.cleanup()
		}
	}
}

func (lc *LogCorrelator) cleanup() {
	// Remove old correlation entries
	cutoff := time.Now().Add(-lc.config.CorrelationWindow)
	
	lc.correlationMutex.Lock()
	for correlationID, logs := range lc.correlationMap {
		if len(logs) > 0 && logs[0].Timestamp.Before(cutoff) {
			delete(lc.correlationMap, correlationID)
		}
	}
	lc.correlationMutex.Unlock()
}

func (lc *LogCorrelator) Close() {
	if lc.cancel != nil {
		lc.cancel()
	}
	if lc.cleanupTicker != nil {
		lc.cleanupTicker.Stop()
	}
}

// Log processor implementations

func NewSecurityLogProcessor(sensitiveFields []string) LogProcessor {
	return &SecurityLogProcessor{sensitiveFields: sensitiveFields}
}

type SecurityLogProcessor struct {
	sensitiveFields []string
}

func (slp *SecurityLogProcessor) ProcessLog(ctx context.Context, entry *LogEntry) (*LogEntry, error) {
	// Mask sensitive fields
	if entry.Fields != nil {
		for _, field := range slp.sensitiveFields {
			if _, exists := entry.Fields[field]; exists {
				entry.Fields[field] = "***MASKED***"
			}
		}
	}
	return entry, nil
}

func (slp *SecurityLogProcessor) GetName() string {
	return "security"
}

func (slp *SecurityLogProcessor) IsEnabled() bool {
	return true
}

func NewEnrichmentLogProcessor(serviceName, environment string) LogProcessor {
	return &EnrichmentLogProcessor{
		serviceName: serviceName,
		environment: environment,
	}
}

type EnrichmentLogProcessor struct {
	serviceName string
	environment string
}

func (elp *EnrichmentLogProcessor) ProcessLog(ctx context.Context, entry *LogEntry) (*LogEntry, error) {
	// Add metadata
	if entry.ServiceName == "" {
		entry.ServiceName = elp.serviceName
	}
	if entry.Environment == "" {
		entry.Environment = elp.environment
	}
	
	return entry, nil
}

func (elp *EnrichmentLogProcessor) GetName() string {
	return "enrichment"
}

func (elp *EnrichmentLogProcessor) IsEnabled() bool {
	return true
}

func NewFormattingLogProcessor() LogProcessor {
	return &FormattingLogProcessor{}
}

type FormattingLogProcessor struct{}

func (flp *FormattingLogProcessor) ProcessLog(ctx context.Context, entry *LogEntry) (*LogEntry, error) {
	// Ensure consistent formatting
	if entry.Level == "" {
		entry.Level = "info"
	}
	if entry.Component == "" {
		entry.Component = "unknown"
	}
	
	return entry, nil
}

func (flp *FormattingLogProcessor) GetName() string {
	return "formatting"
}

func (flp *FormattingLogProcessor) IsEnabled() bool {
	return true
}

// Storage implementations (placeholders)

func NewElasticsearchLogStorage(logger *zap.Logger, config *ElasticsearchLogConfig) (LogStorage, error) {
	return &ElasticsearchLogStorage{
		logger: logger,
		config: config,
	}, nil
}

type ElasticsearchLogStorage struct {
	logger *zap.Logger
	config *ElasticsearchLogConfig
}

func (els *ElasticsearchLogStorage) StoreLogs(ctx context.Context, entries []*LogEntry) error {
	// Implementation would store logs to Elasticsearch
	return nil
}

func (els *ElasticsearchLogStorage) QueryLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error) {
	// Implementation would query logs from Elasticsearch
	return nil, nil
}

func (els *ElasticsearchLogStorage) IsHealthy() bool {
	return true
}

func (els *ElasticsearchLogStorage) Close() error {
	return nil
}

func NewLokiLogStorage(logger *zap.Logger, config *LokiLogConfig) (LogStorage, error) {
	return &LokiLogStorage{
		logger: logger,
		config: config,
	}, nil
}

type LokiLogStorage struct {
	logger *zap.Logger
	config *LokiLogConfig
}

func (lls *LokiLogStorage) StoreLogs(ctx context.Context, entries []*LogEntry) error {
	return nil
}

func (lls *LokiLogStorage) QueryLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error) {
	return nil, nil
}

func (lls *LokiLogStorage) IsHealthy() bool {
	return true
}

func (lls *LokiLogStorage) Close() error {
	return nil
}

func NewFileLogStorage(logger *zap.Logger, config *FileLogConfig) (LogStorage, error) {
	return &FileLogStorage{
		logger: logger,
		config: config,
	}, nil
}

type FileLogStorage struct {
	logger *zap.Logger
	config *FileLogConfig
}

func (fls *FileLogStorage) StoreLogs(ctx context.Context, entries []*LogEntry) error {
	return nil
}

func (fls *FileLogStorage) QueryLogs(ctx context.Context, query *LogQuery) ([]*LogEntry, error) {
	return nil, nil
}

func (fls *FileLogStorage) IsHealthy() bool {
	return true
}

func (fls *FileLogStorage) Close() error {
	return nil
}

func NewSyslogForwarder(logger *zap.Logger, config *SyslogLogConfig) (LogForwarder, error) {
	return &SyslogForwarder{
		logger: logger,
		config: config,
	}, nil
}

type SyslogForwarder struct {
	logger *zap.Logger
	config *SyslogLogConfig
}

func (slf *SyslogForwarder) ForwardLogs(ctx context.Context, entries []*LogEntry) error {
	return nil
}

func (slf *SyslogForwarder) GetDestination() string {
	return fmt.Sprintf("%s://%s", slf.config.Network, slf.config.Address)
}

func (slf *SyslogForwarder) IsHealthy() bool {
	return true
}

func (slf *SyslogForwarder) Close() error {
	return nil
}