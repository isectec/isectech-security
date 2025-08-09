package logging

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/isectech/platform/shared/types"
)

// Logger wraps zap.Logger with additional functionality
type Logger struct {
	*zap.Logger
	serviceName string
}

// Config represents logger configuration
type Config struct {
	Level       string `json:"level" yaml:"level"`
	Format      string `json:"format" yaml:"format"`
	Output      string `json:"output" yaml:"output"`
	ServiceName string `json:"service_name" yaml:"service_name"`
	Development bool   `json:"development" yaml:"development"`
}

// Field represents a log field
type Field = zapcore.Field

// NewLogger creates a new logger instance
func NewLogger(config Config) (*Logger, error) {
	level, err := zapcore.ParseLevel(config.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	var zapConfig zap.Config

	if config.Development {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		zapConfig = zap.NewProductionConfig()
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	zapConfig.Level = zap.NewAtomicLevelAt(level)

	// Configure output format
	switch strings.ToLower(config.Format) {
	case "json":
		zapConfig.Encoding = "json"
	case "console":
		zapConfig.Encoding = "console"
	default:
		zapConfig.Encoding = "json"
	}

	// Configure output destination
	switch strings.ToLower(config.Output) {
	case "stdout":
		zapConfig.OutputPaths = []string{"stdout"}
	case "stderr":
		zapConfig.OutputPaths = []string{"stderr"}
	case "":
		zapConfig.OutputPaths = []string{"stdout"}
	default:
		zapConfig.OutputPaths = []string{config.Output}
	}

	// Add service name field
	zapConfig.InitialFields = map[string]interface{}{
		"service": config.ServiceName,
	}

	zapLogger, err := zapConfig.Build(
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	return &Logger{
		Logger:      zapLogger,
		serviceName: config.ServiceName,
	}, nil
}

// NewDevelopmentLogger creates a development logger
func NewDevelopmentLogger(serviceName string) *Logger {
	config := Config{
		Level:       "debug",
		Format:      "console",
		Output:      "stdout",
		ServiceName: serviceName,
		Development: true,
	}

	logger, err := NewLogger(config)
	if err != nil {
		// Fallback to basic logger
		zapLogger := zap.NewExample()
		return &Logger{
			Logger:      zapLogger,
			serviceName: serviceName,
		}
	}

	return logger
}

// NewProductionLogger creates a production logger
func NewProductionLogger(serviceName string) *Logger {
	config := Config{
		Level:       "info",
		Format:      "json",
		Output:      "stdout",
		ServiceName: serviceName,
		Development: false,
	}

	logger, err := NewLogger(config)
	if err != nil {
		// Fallback to basic logger
		zapLogger := zap.NewExample()
		return &Logger{
			Logger:      zapLogger,
			serviceName: serviceName,
		}
	}

	return logger
}

// WithContext adds context information to logger
func (l *Logger) WithContext(ctx context.Context) *Logger {
	fields := extractContextFields(ctx)
	if len(fields) == 0 {
		return l
	}

	return &Logger{
		Logger:      l.Logger.With(fields...),
		serviceName: l.serviceName,
	}
}

// WithRequestContext adds request context information to logger
func (l *Logger) WithRequestContext(reqCtx *types.RequestContext) *Logger {
	if reqCtx == nil {
		return l
	}

	fields := []Field{
		zap.String("correlation_id", reqCtx.CorrelationID.String()),
		zap.String("tenant_id", reqCtx.TenantID.String()),
		zap.String("service_id", string(reqCtx.ServiceID)),
		zap.Time("request_timestamp", reqCtx.Timestamp),
	}

	if reqCtx.UserID != nil {
		fields = append(fields, zap.String("user_id", reqCtx.UserID.String()))
	}

	if reqCtx.TraceID != "" {
		fields = append(fields, zap.String("trace_id", reqCtx.TraceID))
	}

	if reqCtx.SpanID != "" {
		fields = append(fields, zap.String("span_id", reqCtx.SpanID))
	}

	if reqCtx.IPAddress != "" {
		fields = append(fields, zap.String("ip_address", reqCtx.IPAddress))
	}

	return &Logger{
		Logger:      l.Logger.With(fields...),
		serviceName: l.serviceName,
	}
}

// WithTenant adds tenant information to logger
func (l *Logger) WithTenant(tenantID types.TenantID) *Logger {
	return &Logger{
		Logger:      l.Logger.With(zap.String("tenant_id", tenantID.String())),
		serviceName: l.serviceName,
	}
}

// WithUser adds user information to logger
func (l *Logger) WithUser(userID types.UserID) *Logger {
	return &Logger{
		Logger:      l.Logger.With(zap.String("user_id", userID.String())),
		serviceName: l.serviceName,
	}
}

// WithComponent adds component information to logger
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger:      l.Logger.With(zap.String("component", component)),
		serviceName: l.serviceName,
	}
}

// WithError adds error information to logger
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger:      l.Logger.With(zap.Error(err)),
		serviceName: l.serviceName,
	}
}

// WithFields adds multiple fields to logger
func (l *Logger) WithFields(fields ...Field) *Logger {
	return &Logger{
		Logger:      l.Logger.With(fields...),
		serviceName: l.serviceName,
	}
}

// WithDuration adds duration field to logger
func (l *Logger) WithDuration(duration time.Duration) *Logger {
	return &Logger{
		Logger:      l.Logger.With(zap.Duration("duration", duration)),
		serviceName: l.serviceName,
	}
}

// Security logging methods

// LogSecurityEvent logs a security-related event
func (l *Logger) LogSecurityEvent(eventType, message string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "security"),
		zap.String("security_event_type", eventType),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Warn(message, allFields...)
}

// LogAuthenticationEvent logs authentication events
func (l *Logger) LogAuthenticationEvent(success bool, userID *types.UserID, message string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "authentication"),
		zap.Bool("success", success),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	if userID != nil {
		allFields = append(allFields, zap.String("user_id", userID.String()))
	}

	if success {
		l.Info(message, allFields...)
	} else {
		l.Warn(message, allFields...)
	}
}

// LogAuthorizationEvent logs authorization events
func (l *Logger) LogAuthorizationEvent(success bool, userID types.UserID, resource, action string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "authorization"),
		zap.Bool("success", success),
		zap.String("user_id", userID.String()),
		zap.String("resource", resource),
		zap.String("action", action),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	if success {
		l.Info("Authorization granted", allFields...)
	} else {
		l.Warn("Authorization denied", allFields...)
	}
}

// LogDataAccess logs data access events
func (l *Logger) LogDataAccess(userID types.UserID, operation, resource string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "data_access"),
		zap.String("user_id", userID.String()),
		zap.String("operation", operation),
		zap.String("resource", resource),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Info("Data access event", allFields...)
}

// LogThreatDetection logs threat detection events
func (l *Logger) LogThreatDetection(threatType, severity, description string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "threat_detection"),
		zap.String("threat_type", threatType),
		zap.String("severity", severity),
		zap.String("description", description),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	switch severity {
	case "critical", "high":
		l.Error("Threat detected", allFields...)
	case "medium":
		l.Warn("Threat detected", allFields...)
	default:
		l.Info("Threat detected", allFields...)
	}
}

// Performance logging methods

// LogPerformance logs performance metrics
func (l *Logger) LogPerformance(operation string, duration time.Duration, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "performance"),
		zap.String("operation", operation),
		zap.Duration("duration", duration),
		zap.Float64("duration_ms", float64(duration.Nanoseconds())/1000000),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Info("Performance metric", allFields...)
}

// LogSlowQuery logs slow database queries
func (l *Logger) LogSlowQuery(query string, duration time.Duration, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "slow_query"),
		zap.String("query", query),
		zap.Duration("duration", duration),
		zap.Float64("duration_ms", float64(duration.Nanoseconds())/1000000),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Warn("Slow query detected", allFields...)
}

// Business logging methods

// LogBusinessEvent logs business-related events
func (l *Logger) LogBusinessEvent(eventType, description string, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "business"),
		zap.String("business_event_type", eventType),
		zap.String("description", description),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Info("Business event", allFields...)
}

// LogAudit logs audit events
func (l *Logger) LogAudit(userID types.UserID, action, resource string, success bool, fields ...Field) {
	allFields := append([]Field{
		zap.String("event_type", "audit"),
		zap.String("user_id", userID.String()),
		zap.String("action", action),
		zap.String("resource", resource),
		zap.Bool("success", success),
		zap.Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	l.Info("Audit event", allFields...)
}

// Helper functions

// extractContextFields extracts logging fields from context
func extractContextFields(ctx context.Context) []Field {
	var fields []Field

	// Extract request context if available
	if reqCtx, ok := ctx.Value("request_context").(*types.RequestContext); ok {
		fields = append(fields,
			zap.String("correlation_id", reqCtx.CorrelationID.String()),
			zap.String("tenant_id", reqCtx.TenantID.String()),
		)

		if reqCtx.UserID != nil {
			fields = append(fields, zap.String("user_id", reqCtx.UserID.String()))
		}

		if reqCtx.TraceID != "" {
			fields = append(fields, zap.String("trace_id", reqCtx.TraceID))
		}
	}

	// Extract trace information if available
	if traceID, ok := ctx.Value("trace_id").(string); ok {
		fields = append(fields, zap.String("trace_id", traceID))
	}

	if spanID, ok := ctx.Value("span_id").(string); ok {
		fields = append(fields, zap.String("span_id", spanID))
	}

	return fields
}

// Global logger instance
var globalLogger *Logger

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() *Logger {
	if globalLogger == nil {
		// Fallback to development logger
		globalLogger = NewDevelopmentLogger("default")
	}
	return globalLogger
}

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger *Logger) {
	globalLogger = logger
}

// Convenience functions using global logger

// Debug logs a debug message
func Debug(msg string, fields ...Field) {
	GetGlobalLogger().Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...Field) {
	GetGlobalLogger().Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...Field) {
	GetGlobalLogger().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...Field) {
	GetGlobalLogger().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...Field) {
	GetGlobalLogger().Fatal(msg, fields...)
}

// Panic logs a panic message and panics
func Panic(msg string, fields ...Field) {
	GetGlobalLogger().Panic(msg, fields...)
}

// WithContext returns a logger with context
func WithContext(ctx context.Context) *Logger {
	return GetGlobalLogger().WithContext(ctx)
}

// WithRequestContext returns a logger with request context
func WithRequestContext(reqCtx *types.RequestContext) *Logger {
	return GetGlobalLogger().WithRequestContext(reqCtx)
}

// WithError returns a logger with error
func WithError(err error) *Logger {
	return GetGlobalLogger().WithError(err)
}

// Field creation functions

// String creates a string field
func String(key, value string) Field {
	return zap.String(key, value)
}

// Int creates an int field
func Int(key string, value int) Field {
	return zap.Int(key, value)
}

// Int64 creates an int64 field
func Int64(key string, value int64) Field {
	return zap.Int64(key, value)
}

// Float64 creates a float64 field
func Float64(key string, value float64) Field {
	return zap.Float64(key, value)
}

// Bool creates a bool field
func Bool(key string, value bool) Field {
	return zap.Bool(key, value)
}

// Time creates a time field
func Time(key string, value time.Time) Field {
	return zap.Time(key, value)
}

// Duration creates a duration field
func Duration(key string, value time.Duration) Field {
	return zap.Duration(key, value)
}

// Any creates a field with any value
func Any(key string, value interface{}) Field {
	return zap.Any(key, value)
}

// Cleanup closes the logger and flushes any buffered log entries
func (l *Logger) Cleanup() {
	if l.Logger != nil {
		l.Logger.Sync()
	}
}

// CleanupGlobal cleans up the global logger
func CleanupGlobal() {
	if globalLogger != nil {
		globalLogger.Cleanup()
	}
}