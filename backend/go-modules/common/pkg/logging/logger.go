package logging

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
)

// LogFormat represents the log output format
type LogFormat string

const (
	FormatJSON    LogFormat = "json"
	FormatConsole LogFormat = "console"
)

// Config represents logging configuration
type Config struct {
	// Basic settings
	Level  LogLevel  `yaml:"level" json:"level"`
	Format LogFormat `yaml:"format" json:"format"`
	
	// Output settings
	OutputPaths      []string `yaml:"output_paths" json:"output_paths"`
	ErrorOutputPaths []string `yaml:"error_output_paths" json:"error_output_paths"`
	
	// Service information
	ServiceName    string `yaml:"service_name" json:"service_name"`
	ServiceVersion string `yaml:"service_version" json:"service_version"`
	Environment    string `yaml:"environment" json:"environment"`
	
	// Structured logging settings
	EnableCaller     bool `yaml:"enable_caller" json:"enable_caller"`
	EnableStacktrace bool `yaml:"enable_stacktrace" json:"enable_stacktrace"`
	EnableSampling   bool `yaml:"enable_sampling" json:"enable_sampling"`
	
	// Correlation settings
	EnableCorrelationID bool   `yaml:"enable_correlation_id" json:"enable_correlation_id"`
	CorrelationIDHeader string `yaml:"correlation_id_header" json:"correlation_id_header"`
	
	// Performance settings
	BufferSize    int           `yaml:"buffer_size" json:"buffer_size"`
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`
}

// Logger represents an enhanced logger with correlation support
type Logger struct {
	*zap.Logger
	config *Config
	fields []zap.Field
}

// NewLogger creates a new logger with the given configuration
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Build zap config
	zapConfig := zap.Config{
		Level:       getZapLevel(config.Level),
		Development: config.Environment == "development",
		Encoding:    string(config.Format),
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "timestamp",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      config.OutputPaths,
		ErrorOutputPaths: config.ErrorOutputPaths,
		DisableCaller:    !config.EnableCaller,
		DisableStacktrace: !config.EnableStacktrace,
	}

	// Create base logger
	baseLogger, err := zapConfig.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Add service fields
	serviceFields := []zap.Field{
		zap.String("service", config.ServiceName),
		zap.String("version", config.ServiceVersion),
		zap.String("environment", config.Environment),
	}

	logger := &Logger{
		Logger: baseLogger.With(serviceFields...),
		config: config,
		fields: serviceFields,
	}

	return logger, nil
}

// getZapLevel converts LogLevel to zap.AtomicLevel
func getZapLevel(level LogLevel) zap.AtomicLevel {
	switch level {
	case LevelDebug:
		return zap.NewAtomicLevelAt(zap.DebugLevel)
	case LevelInfo:
		return zap.NewAtomicLevelAt(zap.InfoLevel)
	case LevelWarn:
		return zap.NewAtomicLevelAt(zap.WarnLevel)
	case LevelError:
		return zap.NewAtomicLevelAt(zap.ErrorLevel)
	case LevelFatal:
		return zap.NewAtomicLevelAt(zap.FatalLevel)
	default:
		return zap.NewAtomicLevelAt(zap.InfoLevel)
	}
}

// WithContext creates a logger with context-specific fields
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := l.extractContextFields(ctx)
	if len(fields) == 0 {
		return l
	}

	return &Logger{
		Logger: l.Logger.With(fields...),
		config: l.config,
		fields: append(l.fields, fields...),
	}
}

// WithCorrelationID creates a logger with a correlation ID
func (l *Logger) WithCorrelationID(correlationID string) *Logger {
	if correlationID == "" {
		return l
	}

	field := zap.String("correlation_id", correlationID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithTraceID creates a logger with a trace ID
func (l *Logger) WithTraceID(traceID string) *Logger {
	if traceID == "" {
		return l
	}

	field := zap.String("trace_id", traceID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithSpanID creates a logger with a span ID
func (l *Logger) WithSpanID(spanID string) *Logger {
	if spanID == "" {
		return l
	}

	field := zap.String("span_id", spanID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithUserID creates a logger with a user ID
func (l *Logger) WithUserID(userID string) *Logger {
	if userID == "" {
		return l
	}

	field := zap.String("user_id", userID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithTenantID creates a logger with a tenant ID
func (l *Logger) WithTenantID(tenantID string) *Logger {
	if tenantID == "" {
		return l
	}

	field := zap.String("tenant_id", tenantID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithRequestID creates a logger with a request ID
func (l *Logger) WithRequestID(requestID string) *Logger {
	if requestID == "" {
		return l
	}

	field := zap.String("request_id", requestID)
	return &Logger{
		Logger: l.Logger.With(field),
		config: l.config,
		fields: append(l.fields, field),
	}
}

// WithFields creates a logger with additional fields
func (l *Logger) WithFields(fields ...zap.Field) *Logger {
	return &Logger{
		Logger: l.Logger.With(fields...),
		config: l.config,
		fields: append(l.fields, fields...),
	}
}

// extractContextFields extracts logging fields from context
func (l *Logger) extractContextFields(ctx context.Context) []zap.Field {
	var fields []zap.Field

	// Extract correlation ID
	if l.config.EnableCorrelationID {
		if correlationID := GetCorrelationID(ctx); correlationID != "" {
			fields = append(fields, zap.String("correlation_id", correlationID))
		}
	}

	// Extract trace information
	if traceID := GetTraceID(ctx); traceID != "" {
		fields = append(fields, zap.String("trace_id", traceID))
	}

	if spanID := GetSpanID(ctx); spanID != "" {
		fields = append(fields, zap.String("span_id", spanID))
	}

	// Extract user information
	if userID := GetUserID(ctx); userID != "" {
		fields = append(fields, zap.String("user_id", userID))
	}

	if tenantID := GetTenantID(ctx); tenantID != "" {
		fields = append(fields, zap.String("tenant_id", tenantID))
	}

	// Extract request information
	if requestID := GetRequestID(ctx); requestID != "" {
		fields = append(fields, zap.String("request_id", requestID))
	}

	return fields
}

// LogEvent logs a structured event
func (l *Logger) LogEvent(level LogLevel, event string, fields ...zap.Field) {
	eventFields := append([]zap.Field{zap.String("event", event)}, fields...)
	
	switch level {
	case LevelDebug:
		l.Debug("Event occurred", eventFields...)
	case LevelInfo:
		l.Info("Event occurred", eventFields...)
	case LevelWarn:
		l.Warn("Event occurred", eventFields...)
	case LevelError:
		l.Error("Event occurred", eventFields...)
	case LevelFatal:
		l.Fatal("Event occurred", eventFields...)
	}
}

// LogError logs an error with full context
func (l *Logger) LogError(err error, message string, fields ...zap.Field) {
	errorFields := append([]zap.Field{zap.Error(err)}, fields...)
	l.Error(message, errorFields...)
}

// LogMetric logs a metric event
func (l *Logger) LogMetric(name string, value interface{}, unit string, fields ...zap.Field) {
	metricFields := append([]zap.Field{
		zap.String("metric_name", name),
		zap.Any("metric_value", value),
		zap.String("metric_unit", unit),
		zap.String("event_type", "metric"),
	}, fields...)
	
	l.Info("Metric recorded", metricFields...)
}

// LogAudit logs an audit event
func (l *Logger) LogAudit(action string, resource string, fields ...zap.Field) {
	auditFields := append([]zap.Field{
		zap.String("audit_action", action),
		zap.String("audit_resource", resource),
		zap.String("event_type", "audit"),
		zap.Time("timestamp", time.Now().UTC()),
	}, fields...)
	
	l.Info("Audit event", auditFields...)
}

// LogSecurity logs a security event
func (l *Logger) LogSecurity(eventType string, severity string, fields ...zap.Field) {
	securityFields := append([]zap.Field{
		zap.String("security_event_type", eventType),
		zap.String("security_severity", severity),
		zap.String("event_type", "security"),
		zap.Time("timestamp", time.Now().UTC()),
	}, fields...)
	
	l.Warn("Security event", securityFields...)
}

// LogPerformance logs a performance metric
func (l *Logger) LogPerformance(operation string, duration time.Duration, fields ...zap.Field) {
	perfFields := append([]zap.Field{
		zap.String("operation", operation),
		zap.Duration("duration", duration),
		zap.String("event_type", "performance"),
	}, fields...)
	
	l.Info("Performance metric", perfFields...)
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Clone creates a copy of the logger
func (l *Logger) Clone() *Logger {
	return &Logger{
		Logger: l.Logger,
		config: l.config,
		fields: append([]zap.Field{}, l.fields...),
	}
}

// DefaultConfig returns a default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		
		ServiceName:    "unknown",
		ServiceVersion: "unknown",
		Environment:    "development",
		
		EnableCaller:     true,
		EnableStacktrace: true,
		EnableSampling:   false,
		
		EnableCorrelationID: true,
		CorrelationIDHeader: "X-Correlation-ID",
		
		BufferSize:    256,
		FlushInterval: 30 * time.Second,
	}
}

// GetServiceLogger creates a configured logger for a service
func GetServiceLogger(serviceName, version, environment string) (*Logger, error) {
	config := DefaultConfig()
	config.ServiceName = serviceName
	config.ServiceVersion = version
	config.Environment = environment
	
	// Adjust config based on environment
	if environment == "production" {
		config.Level = LevelInfo
		config.EnableStacktrace = false
		config.EnableSampling = true
	} else if environment == "development" {
		config.Level = LevelDebug
		config.Format = FormatConsole
		config.EnableCaller = true
	}
	
	return NewLogger(config)
}

// InitGlobalLogger initializes a global logger (for backwards compatibility)
var globalLogger *Logger

func InitGlobalLogger(config *Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	
	globalLogger = logger
	
	// Replace global zap logger
	zap.ReplaceGlobals(logger.Logger)
	
	return nil
}

// GetGlobalLogger returns the global logger
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Create default logger if none exists
		logger, err := NewLogger(DefaultConfig())
		if err != nil {
			// Fallback to nop logger
			return &Logger{Logger: zap.NewNop(), config: DefaultConfig()}
		}
		globalLogger = logger
	}
	return globalLogger
}