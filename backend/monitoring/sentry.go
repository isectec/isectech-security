// iSECTECH Go Sentry Integration
// Production-grade error tracking and performance monitoring for Go backend

package monitoring

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const (
	ServiceName = "isectech-backend"
	TeamName    = "backend-team"
)

// SentryConfig holds configuration for Sentry integration
type SentryConfig struct {
	DSN              string
	Environment      string
	Release          string
	SampleRate       float64
	TracesSampleRate float64
	Debug            bool
	AttachStacktrace bool
	SendDefaultPII   bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// NewSentryConfig creates a new Sentry configuration from environment variables
func NewSentryConfig() *SentryConfig {
	return &SentryConfig{
		DSN:              getEnvOrDefault("SENTRY_DSN", ""),
		Environment:      getEnvOrDefault("SENTRY_ENVIRONMENT", "development"),
		Release:          getEnvOrDefault("SENTRY_RELEASE", "1.0.0"),
		SampleRate:       getEnvFloatOrDefault("SENTRY_SAMPLE_RATE", 1.0),
		TracesSampleRate: getEnvFloatOrDefault("SENTRY_TRACES_SAMPLE_RATE", 0.1),
		Debug:            getEnvBoolOrDefault("SENTRY_DEBUG", false),
		AttachStacktrace: getEnvBoolOrDefault("SENTRY_ATTACH_STACKTRACE", true),
		SendDefaultPII:   getEnvBoolOrDefault("SENTRY_SEND_DEFAULT_PII", false),
	}
}

// InitializeSentry initializes Sentry with the provided configuration
func InitializeSentry(config *SentryConfig) error {
	if config.DSN == "" {
		log.Println("Sentry DSN not configured, error tracking disabled")
		return nil
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              config.DSN,
		Environment:      config.Environment,
		Release:          config.Release,
		SampleRate:       config.SampleRate,
		TracesSampleRate: config.TracesSampleRate,
		Debug:            config.Debug,
		AttachStacktrace: config.AttachStacktrace,
		SendDefaultPII:   config.SendDefaultPII,

		// Custom integrations and processors
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			return processSentryEvent(event, hint)
		},

		BeforeBreadcrumb: func(breadcrumb *sentry.Breadcrumb, hint *sentry.BreadcrumbHint) *sentry.Breadcrumb {
			return processBreadcrumb(breadcrumb, hint)
		},

		// Transport options
		Transport: sentry.NewHTTPSyncTransport(),

		// Server name
		ServerName: getHostname(),

		// Custom tags
		Tags: map[string]string{
			"component": "backend",
			"service":   ServiceName,
			"team":      TeamName,
			"runtime":   runtime.Version(),
		},

		// Ignored errors
		IgnoreErrors: []string{
			"context canceled",
			"connection reset by peer",
			"broken pipe",
			"EOF",
		},

		// Maximum breadcrumbs
		MaxBreadcrumbs: 100,
	})

	if err != nil {
		return fmt.Errorf("failed to initialize Sentry: %w", err)
	}

	// Configure initial scope
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetContext("runtime", map[string]interface{}{
			"name":    "go",
			"version": runtime.Version(),
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		})

		scope.SetContext("service", map[string]interface{}{
			"name":    ServiceName,
			"version": config.Release,
			"team":    TeamName,
		})
	})

	log.Printf("✅ Sentry initialized for %s (env: %s, release: %s)", 
		ServiceName, config.Environment, config.Release)

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVENT PROCESSING
// ═══════════════════════════════════════════════════════════════════════════════

// processSentryEvent processes Sentry events before sending
func processSentryEvent(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
	// Add iSECTECH specific context
	if event.Contexts == nil {
		event.Contexts = make(map[string]sentry.Context)
	}

	event.Contexts["isectech"] = sentry.Context{
		"environment": event.Environment,
		"service":     ServiceName,
		"timestamp":   time.Now().Format(time.RFC3339),
	}

	// Scrub sensitive data
	event = scrubSensitiveData(event)

	// Add request context if available
	if event.Request != nil {
		event.Request = scrubRequestData(event.Request)
	}

	// Filter out non-actionable errors in production
	if event.Environment == "production" {
		if shouldIgnoreError(event) {
			return nil
		}
	}

	return event
}

// processBreadcrumb processes breadcrumbs before adding to event
func processBreadcrumb(breadcrumb *sentry.Breadcrumb, hint *sentry.BreadcrumbHint) *sentry.Breadcrumb {
	// Filter out noisy breadcrumbs
	if breadcrumb.Category == "http" {
		// Skip health check requests
		if data, ok := breadcrumb.Data["url"].(string); ok {
			if strings.Contains(data, "/health") || strings.Contains(data, "/metrics") {
				return nil
			}
		}
	}

	// Scrub sensitive data from breadcrumbs
	if breadcrumb.Data != nil {
		breadcrumb.Data = scrubMapData(breadcrumb.Data)
	}

	return breadcrumb
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA SCRUBBING
// ═══════════════════════════════════════════════════════════════════════════════

var sensitiveKeys = []string{
	"password", "passwd", "secret", "api_key", "apikey", "token",
	"authorization", "auth", "session", "sessionid", "cookie",
	"email", "phone", "ssn", "credit_card", "card_number",
	"private_key", "privatekey", "credentials",
}

// scrubSensitiveData removes sensitive information from Sentry events
func scrubSensitiveData(event *sentry.Event) *sentry.Event {
	// Scrub extra data
	if event.Extra != nil {
		event.Extra = scrubMapData(event.Extra)
	}

	// Scrub breadcrumb data
	for i, breadcrumb := range event.Breadcrumbs {
		if breadcrumb.Data != nil {
			event.Breadcrumbs[i].Data = scrubMapData(breadcrumb.Data)
		}
	}

	return event
}

// scrubRequestData removes sensitive information from request data
func scrubRequestData(req *sentry.Request) *sentry.Request {
	// Scrub headers
	if req.Headers != nil {
		for key := range req.Headers {
			if isSensitiveKey(key) {
				req.Headers[key] = "[REDACTED]"
			}
		}
	}

	// Scrub form data
	if req.Data != nil {
		if formData, ok := req.Data.(map[string]interface{}); ok {
			req.Data = scrubMapData(formData)
		}
	}

	return req
}

// scrubMapData removes sensitive values from map data
func scrubMapData(data map[string]interface{}) map[string]interface{} {
	scrubbed := make(map[string]interface{})

	for key, value := range data {
		if isSensitiveKey(key) {
			scrubbed[key] = "[REDACTED]"
		} else {
			switch v := value.(type) {
			case map[string]interface{}:
				scrubbed[key] = scrubMapData(v)
			case string:
				// Check if the value looks like sensitive data
				if isSensitiveValue(v) {
					scrubbed[key] = "[REDACTED]"
				} else {
					scrubbed[key] = v
				}
			default:
				scrubbed[key] = v
			}
		}
	}

	return scrubbed
}

// isSensitiveKey checks if a key contains sensitive information
func isSensitiveKey(key string) bool {
	lowerKey := strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(lowerKey, sensitiveKey) {
			return true
		}
	}
	return false
}

// isSensitiveValue checks if a value looks like sensitive data
func isSensitiveValue(value string) bool {
	// Check for JWT tokens
	if strings.HasPrefix(value, "Bearer ") || strings.Count(value, ".") == 2 {
		return true
	}
	
	// Check for API keys (long alphanumeric strings)
	if len(value) > 20 && strings.ContainsAny(value, "0123456789") && strings.ContainsAny(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return true
	}
	
	return false
}

// shouldIgnoreError determines if an error should be ignored
func shouldIgnoreError(event *sentry.Event) bool {
	if len(event.Exception) == 0 {
		return false
	}

	errorMessage := event.Exception[0].Value
	
	// Ignore common network errors
	ignoredPatterns := []string{
		"connection reset by peer",
		"broken pipe",
		"context canceled",
		"EOF",
		"timeout",
	}

	for _, pattern := range ignoredPatterns {
		if strings.Contains(strings.ToLower(errorMessage), pattern) {
			return true
		}
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM ERROR TRACKING
// ═══════════════════════════════════════════════════════════════════════════════

// CaptureSecurityEvent captures a security-related event
func CaptureSecurityEvent(ctx context.Context, eventType string, details map[string]interface{}, level sentry.Level) {
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("event_type", "security")
		scope.SetTag("security_event_type", eventType)
		scope.SetLevel(level)
		scope.SetContext("security_details", details)

		// Add trace context if available
		if traceID := getTraceIDFromContext(ctx); traceID != "" {
			scope.SetTag("trace_id", traceID)
		}

		sentry.CaptureMessage(fmt.Sprintf("Security Event: %s", eventType))
	})
}

// CaptureBusinessEvent captures a business-related event
func CaptureBusinessEvent(ctx context.Context, eventType string, userID string, details map[string]interface{}) {
	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("event_type", "business")
		scope.SetTag("business_event_type", eventType)
		scope.SetUser(sentry.User{ID: userID})
		scope.SetContext("business_details", details)

		// Add trace context if available
		if traceID := getTraceIDFromContext(ctx); traceID != "" {
			scope.SetTag("trace_id", traceID)
		}

		sentry.CaptureMessage(fmt.Sprintf("Business Event: %s", eventType))
	})
}

// CaptureAPIError captures API-related errors
func CaptureAPIError(ctx context.Context, endpoint, method string, statusCode int, responseBody string) {
	level := sentry.LevelWarning
	if statusCode >= 500 {
		level = sentry.LevelError
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("event_type", "api_error")
		scope.SetTag("api_endpoint", endpoint)
		scope.SetTag("api_method", method)
		scope.SetTag("api_status_code", strconv.Itoa(statusCode))
		scope.SetLevel(level)
		scope.SetContext("api_details", map[string]interface{}{
			"endpoint":      endpoint,
			"method":        method,
			"status_code":   statusCode,
			"response_body": truncateString(responseBody, 1000),
		})

		// Add trace context if available
		if traceID := getTraceIDFromContext(ctx); traceID != "" {
			scope.SetTag("trace_id", traceID)
		}

		sentry.CaptureMessage(fmt.Sprintf("API Error: %s %s returned %d", method, endpoint, statusCode))
	})
}

// CapturePerformanceIssue captures performance-related issues
func CapturePerformanceIssue(ctx context.Context, operation string, duration, threshold time.Duration) {
	if duration <= threshold {
		return
	}

	sentry.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("event_type", "performance")
		scope.SetTag("performance_issue", "slow_operation")
		scope.SetLevel(sentry.LevelWarning)
		scope.SetContext("performance_details", map[string]interface{}{
			"operation":       operation,
			"duration_ms":     duration.Milliseconds(),
			"threshold_ms":    threshold.Milliseconds(),
			"slowness_factor": float64(duration) / float64(threshold),
		})

		// Add trace context if available
		if traceID := getTraceIDFromContext(ctx); traceID != "" {
			scope.SetTag("trace_id", traceID)
		}

		sentry.CaptureMessage(fmt.Sprintf("Slow Operation: %s took %v (threshold: %v)", operation, duration, threshold))
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// GIN MIDDLEWARE
// ═══════════════════════════════════════════════════════════════════════════════

// SentryGinMiddleware returns a Gin middleware for Sentry integration
func SentryGinMiddleware() gin.HandlerFunc {
	return sentrygin.New(sentrygin.Options{
		Repanic:         true,
		WaitForDelivery: false,
		Timeout:         5 * time.Second,
	})
}

// EnhancedSentryMiddleware provides additional context for API requests
func EnhancedSentryMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Configure Sentry scope for this request
		if hub := sentry.GetHubFromContext(c.Request.Context()); hub != nil {
			hub.ConfigureScope(func(scope *sentry.Scope) {
				// Add request context
				scope.SetTag("http_method", c.Request.Method)
				scope.SetTag("http_path", c.FullPath())
				scope.SetTag("http_route", c.Request.URL.Path)
				
				// Add user agent
				if userAgent := c.GetHeader("User-Agent"); userAgent != "" {
					scope.SetTag("user_agent", userAgent)
				}

				// Add request ID if available
				if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
					scope.SetTag("request_id", requestID)
				}

				// Add client IP
				scope.SetTag("client_ip", c.ClientIP())

				// Add additional context
				scope.SetContext("request", map[string]interface{}{
					"method":     c.Request.Method,
					"url":        c.Request.URL.String(),
					"user_agent": c.GetHeader("User-Agent"),
					"referer":    c.GetHeader("Referer"),
				})
			})
		}

		// Process request
		c.Next()

		// Capture API errors for non-success status codes
		if c.Writer.Status() >= 400 {
			CaptureAPIError(
				c.Request.Context(),
				c.FullPath(),
				c.Request.Method,
				c.Writer.Status(),
				"", // Response body not available in middleware
			)
		}
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERFORMANCE MONITORING
// ═══════════════════════════════════════════════════════════════════════════════

// CreateTransaction creates a new Sentry transaction
func CreateTransaction(ctx context.Context, name, operation string) *sentry.Span {
	return sentry.StartTransaction(ctx, name, sentry.WithOpName(operation))
}

// MeasureOperation measures the duration of an operation and reports slow operations
func MeasureOperation(ctx context.Context, operationName string, threshold time.Duration, fn func() error) error {
	start := time.Now()
	
	transaction := CreateTransaction(ctx, operationName, "operation")
	defer transaction.Finish()

	err := fn()
	duration := time.Since(start)

	if err != nil {
		transaction.Status = sentry.SpanStatusInternalError
		sentry.CaptureException(err)
	} else {
		transaction.Status = sentry.SpanStatusOK
	}

	// Report performance issues
	CapturePerformanceIssue(ctx, operationName, duration, threshold)

	return err
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// getTraceIDFromContext extracts trace ID from context (if using OpenTelemetry)
func getTraceIDFromContext(ctx context.Context) string {
	// This should be implemented based on your tracing setup
	// Example implementation for OpenTelemetry:
	// span := trace.SpanFromContext(ctx)
	// if span.SpanContext().IsValid() {
	//     return span.SpanContext().TraceID().String()
	// }
	return ""
}

// truncateString truncates a string to a maximum length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getHostname returns the hostname for server identification
func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

// getEnvOrDefault returns environment variable or default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvFloatOrDefault returns environment variable as float64 or default
func getEnvFloatOrDefault(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// getEnvBoolOrDefault returns environment variable as bool or default
func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLEANUP
// ═══════════════════════════════════════════════════════════════════════════════

// FlushSentry flushes all pending Sentry events
func FlushSentry(timeout time.Duration) {
	sentry.Flush(timeout)
}

// Shutdown gracefully shuts down Sentry
func Shutdown() {
	FlushSentry(5 * time.Second)
}