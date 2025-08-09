package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Context keys for various logging fields
type contextKey string

const (
	correlationIDKey contextKey = "correlation_id"
	traceIDKey       contextKey = "trace_id"
	spanIDKey        contextKey = "span_id"
	userIDKey        contextKey = "user_id"
	tenantIDKey      contextKey = "tenant_id"
	requestIDKey     contextKey = "request_id"
	sessionIDKey     contextKey = "session_id"
)

// WithCorrelationID adds a correlation ID to the context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey, correlationID)
}

// GetCorrelationID retrieves the correlation ID from the context
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}

// WithTraceID adds a trace ID to the context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey, traceID)
}

// GetTraceID retrieves the trace ID from the context
func GetTraceID(ctx context.Context) string {
	if id, ok := ctx.Value(traceIDKey).(string); ok {
		return id
	}
	return ""
}

// WithSpanID adds a span ID to the context
func WithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, spanIDKey, spanID)
}

// GetSpanID retrieves the span ID from the context
func GetSpanID(ctx context.Context) string {
	if id, ok := ctx.Value(spanIDKey).(string); ok {
		return id
	}
	return ""
}

// WithUserID adds a user ID to the context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUserID retrieves the user ID from the context
func GetUserID(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}

// WithTenantID adds a tenant ID to the context
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenantID retrieves the tenant ID from the context
func GetTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(tenantIDKey).(string); ok {
		return id
	}
	return ""
}

// WithRequestID adds a request ID to the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// GetRequestID retrieves the request ID from the context
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// WithSessionID adds a session ID to the context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// GetSessionID retrieves the session ID from the context
func GetSessionID(ctx context.Context) string {
	if id, ok := ctx.Value(sessionIDKey).(string); ok {
		return id
	}
	return ""
}

// NewCorrelationID generates a new correlation ID
func NewCorrelationID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("corr_%d", getTimestampNano())
	}
	return hex.EncodeToString(bytes)
}

// NewRequestID generates a new request ID
func NewRequestID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("req_%d", getTimestampNano())
	}
	return hex.EncodeToString(bytes)
}

// NewTraceID generates a new trace ID (compatible with OpenTelemetry)
func NewTraceID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%032x", getTimestampNano())
	}
	return hex.EncodeToString(bytes)
}

// NewSpanID generates a new span ID (compatible with OpenTelemetry)
func NewSpanID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%016x", getTimestampNano())
	}
	return hex.EncodeToString(bytes)
}

// EnsureCorrelationID ensures a correlation ID exists in the context, creating one if needed
func EnsureCorrelationID(ctx context.Context) (context.Context, string) {
	correlationID := GetCorrelationID(ctx)
	if correlationID == "" {
		correlationID = NewCorrelationID()
		ctx = WithCorrelationID(ctx, correlationID)
	}
	return ctx, correlationID
}

// EnsureRequestID ensures a request ID exists in the context, creating one if needed
func EnsureRequestID(ctx context.Context) (context.Context, string) {
	requestID := GetRequestID(ctx)
	if requestID == "" {
		requestID = NewRequestID()
		ctx = WithRequestID(ctx, requestID)
	}
	return ctx, requestID
}

// EnsureTraceContext ensures trace and span IDs exist in the context, creating them if needed
func EnsureTraceContext(ctx context.Context) (context.Context, string, string) {
	traceID := GetTraceID(ctx)
	spanID := GetSpanID(ctx)
	
	if traceID == "" {
		traceID = NewTraceID()
		ctx = WithTraceID(ctx, traceID)
	}
	
	if spanID == "" {
		spanID = NewSpanID()
		ctx = WithSpanID(ctx, spanID)
	}
	
	return ctx, traceID, spanID
}

// CopyTraceContext copies trace context from source to destination context
func CopyTraceContext(src, dst context.Context) context.Context {
	if traceID := GetTraceID(src); traceID != "" {
		dst = WithTraceID(dst, traceID)
	}
	
	if spanID := GetSpanID(src); spanID != "" {
		dst = WithSpanID(dst, spanID)
	}
	
	if correlationID := GetCorrelationID(src); correlationID != "" {
		dst = WithCorrelationID(dst, correlationID)
	}
	
	if requestID := GetRequestID(src); requestID != "" {
		dst = WithRequestID(dst, requestID)
	}
	
	if userID := GetUserID(src); userID != "" {
		dst = WithUserID(dst, userID)
	}
	
	if tenantID := GetTenantID(src); tenantID != "" {
		dst = WithTenantID(dst, tenantID)
	}
	
	if sessionID := GetSessionID(src); sessionID != "" {
		dst = WithSessionID(dst, sessionID)
	}
	
	return dst
}

// ExtractContextMap extracts all logging context values into a map
func ExtractContextMap(ctx context.Context) map[string]string {
	result := make(map[string]string)
	
	if correlationID := GetCorrelationID(ctx); correlationID != "" {
		result["correlation_id"] = correlationID
	}
	
	if traceID := GetTraceID(ctx); traceID != "" {
		result["trace_id"] = traceID
	}
	
	if spanID := GetSpanID(ctx); spanID != "" {
		result["span_id"] = spanID
	}
	
	if userID := GetUserID(ctx); userID != "" {
		result["user_id"] = userID
	}
	
	if tenantID := GetTenantID(ctx); tenantID != "" {
		result["tenant_id"] = tenantID
	}
	
	if requestID := GetRequestID(ctx); requestID != "" {
		result["request_id"] = requestID
	}
	
	if sessionID := GetSessionID(ctx); sessionID != "" {
		result["session_id"] = sessionID
	}
	
	return result
}

// CreateEnrichedContext creates a new context with common logging fields
func CreateEnrichedContext(ctx context.Context, userID, tenantID string) context.Context {
	// Ensure basic trace context
	ctx, _, _ = EnsureTraceContext(ctx)
	ctx, _ = EnsureCorrelationID(ctx)
	ctx, _ = EnsureRequestID(ctx)
	
	// Add user context if provided
	if userID != "" {
		ctx = WithUserID(ctx, userID)
	}
	
	if tenantID != "" {
		ctx = WithTenantID(ctx, tenantID)
	}
	
	return ctx
}

// getTimestampNano returns current timestamp in nanoseconds
func getTimestampNano() int64 {
	return getCurrentTimeNano()
}

// getCurrentTimeNano is a helper to get current time in nanoseconds
// This can be mocked for testing
var getCurrentTimeNano = func() int64 {
	return time.Now().UnixNano()
}

// For testing purposes
func setTimeFunc(fn func() int64) {
	getCurrentTimeNano = fn
}

// resetTimeFunc resets the time function to default
func resetTimeFunc() {
	getCurrentTimeNano = func() int64 {
		return time.Now().UnixNano()
	}
}