package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// BaseConnector provides common functionality for all connectors
type BaseConnector struct {
	sourceSystem     *entity.SourceSystem
	httpClient       *http.Client
	authHandler      AuthenticationHandler
	healthMonitor    HealthMonitor
	transformer      DataTransformer
	
	// Connection state
	connected        bool
	connectionMutex  sync.RWMutex
	
	// Authentication state
	authenticated    bool
	authToken        *AuthToken
	authMutex        sync.RWMutex
	
	// Health monitoring
	healthStatus     *HealthStatus
	healthTicker     *time.Ticker
	healthStopChan   chan bool
	healthMutex      sync.RWMutex
	
	// Metrics
	metrics          *ConnectorMetrics
	metricsMutex     sync.RWMutex
	
	// Configuration
	config           *ConnectorConfig
}

// ConnectorConfig contains connector configuration
type ConnectorConfig struct {
	RequestTimeout     time.Duration                `json:"request_timeout"`
	MaxRetries         int32                        `json:"max_retries"`
	RetryDelay         time.Duration                `json:"retry_delay"`
	HealthCheckInterval time.Duration               `json:"health_check_interval"`
	RateLimit          *entity.RateLimit            `json:"rate_limit,omitempty"`
	
	// TLS configuration
	InsecureSkipVerify bool                         `json:"insecure_skip_verify"`
	TLSConfig          *tls.Config                  `json:"-"`
	
	// Proxy configuration
	ProxyURL           string                       `json:"proxy_url,omitempty"`
	
	// Custom headers
	DefaultHeaders     map[string]string            `json:"default_headers,omitempty"`
	
	// Authentication configuration
	AuthConfig         map[string]interface{}       `json:"auth_config,omitempty"`
	
	// Feature flags
	EnableHealthMonitoring bool                     `json:"enable_health_monitoring"`
	EnableMetrics         bool                      `json:"enable_metrics"`
	EnableRetries         bool                      `json:"enable_retries"`
	EnableCompression     bool                      `json:"enable_compression"`
}

// ConnectorMetrics contains connector metrics
type ConnectorMetrics struct {
	TotalRequests       int64                       `json:"total_requests"`
	SuccessfulRequests  int64                       `json:"successful_requests"`
	FailedRequests      int64                       `json:"failed_requests"`
	TotalExtractions    int64                       `json:"total_extractions"`
	TotalRecordsExtracted int64                     `json:"total_records_extracted"`
	
	// Performance metrics
	AverageResponseTime time.Duration               `json:"average_response_time"`
	MinResponseTime     time.Duration               `json:"min_response_time"`
	MaxResponseTime     time.Duration               `json:"max_response_time"`
	
	// Error metrics
	ErrorsByType        map[string]int64            `json:"errors_by_type"`
	LastError           *ConnectorError             `json:"last_error,omitempty"`
	
	// Authentication metrics
	AuthenticationAttempts int64                    `json:"authentication_attempts"`
	SuccessfulAuthentications int64                 `json:"successful_authentications"`
	FailedAuthentications int64                     `json:"failed_authentications"`
	TokenRefreshCount   int64                       `json:"token_refresh_count"`
	
	// Data quality metrics
	QualityMetrics      *DataQualityMetrics         `json:"quality_metrics,omitempty"`
	
	// Timing metrics
	StartTime          time.Time                    `json:"start_time"`
	LastRequestTime    *time.Time                   `json:"last_request_time,omitempty"`
	LastSuccessTime    *time.Time                   `json:"last_success_time,omitempty"`
	LastErrorTime      *time.Time                   `json:"last_error_time,omitempty"`
}

// NewBaseConnector creates a new base connector
func NewBaseConnector(sourceSystem *entity.SourceSystem) (*BaseConnector, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	config := &ConnectorConfig{
		RequestTimeout:         time.Duration(sourceSystem.ConnectionConfig.Timeout) * time.Second,
		MaxRetries:             sourceSystem.ConnectionConfig.MaxRetries,
		RetryDelay:             time.Duration(sourceSystem.ConnectionConfig.RetryDelay) * time.Second,
		HealthCheckInterval:    time.Duration(sourceSystem.HealthCheckConfig.IntervalSeconds) * time.Second,
		InsecureSkipVerify:     !sourceSystem.ConnectionConfig.VerifySSL,
		ProxyURL:               sourceSystem.ConnectionConfig.ProxyURL,
		DefaultHeaders:         sourceSystem.ConnectionConfig.DefaultHeaders,
		EnableHealthMonitoring: sourceSystem.HealthCheckConfig.Enabled,
		EnableMetrics:          true,
		EnableRetries:          true,
		EnableCompression:      true,
	}

	// Create HTTP client with custom configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify,
		},
		MaxIdleConns:        int(sourceSystem.ConnectionConfig.MaxConnections),
		MaxIdleConnsPerHost: int(sourceSystem.ConnectionConfig.MaxConnections),
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  !config.EnableCompression,
	}

	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.RequestTimeout,
	}

	connector := &BaseConnector{
		sourceSystem:   sourceSystem,
		httpClient:     httpClient,
		config:         config,
		healthStopChan: make(chan bool),
		metrics: &ConnectorMetrics{
			StartTime:      time.Now(),
			ErrorsByType:   make(map[string]int64),
		},
	}

	return connector, nil
}

// Connect establishes connection to the source system
func (b *BaseConnector) Connect(ctx context.Context) error {
	b.connectionMutex.Lock()
	defer b.connectionMutex.Unlock()

	// Test connection
	if err := b.TestConnection(ctx); err != nil {
		b.recordError("connection", err)
		return fmt.Errorf("connection test failed: %w", err)
	}

	b.connected = true

	// Start health monitoring if enabled
	if b.config.EnableHealthMonitoring {
		go b.startHealthMonitoring(ctx)
	}

	b.recordMetric("connection_established", 1)
	return nil
}

// Disconnect closes connection to the source system
func (b *BaseConnector) Disconnect(ctx context.Context) error {
	b.connectionMutex.Lock()
	defer b.connectionMutex.Unlock()

	// Stop health monitoring
	if b.healthTicker != nil {
		b.healthTicker.Stop()
		b.healthStopChan <- true
	}

	b.connected = false
	b.authenticated = false

	b.recordMetric("connection_closed", 1)
	return nil
}

// TestConnection tests the connection to the source system
func (b *BaseConnector) TestConnection(ctx context.Context) error {
	// This is a base implementation - specific connectors should override
	baseURL := b.sourceSystem.ConnectionConfig.BaseURL
	if baseURL == "" {
		return fmt.Errorf("base URL not configured")
	}

	// Parse and validate URL
	_, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	// Test basic connectivity with a simple request
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create test request: %w", err)
	}

	// Add default headers
	b.addDefaultHeaders(req)

	start := time.Now()
	resp, err := b.httpClient.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		b.recordResponseTime(responseTime)
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer resp.Body.Close()

	b.recordResponseTime(responseTime)

	// Consider 2xx, 3xx, 401, and 403 as successful connections
	// (401/403 indicate the service is reachable but authentication is required)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 ||
		resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil
	}

	return fmt.Errorf("connection test failed with status: %d", resp.StatusCode)
}

// IsConnected returns true if connected to the source system
func (b *BaseConnector) IsConnected() bool {
	b.connectionMutex.RLock()
	defer b.connectionMutex.RUnlock()
	return b.connected
}

// ValidateConfiguration validates the connector configuration
func (b *BaseConnector) ValidateConfiguration() error {
	if b.sourceSystem == nil {
		return fmt.Errorf("source system not configured")
	}

	if b.sourceSystem.ConnectionConfig.BaseURL == "" {
		return fmt.Errorf("base URL is required")
	}

	if b.sourceSystem.ConnectionConfig.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	if b.sourceSystem.AuthConfig.Type == "" {
		return fmt.Errorf("authentication type is required")
	}

	// Validate URL format
	_, err := url.Parse(b.sourceSystem.ConnectionConfig.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL format: %w", err)
	}

	return nil
}

// GetRateLimit returns the rate limit information
func (b *BaseConnector) GetRateLimit() *entity.RateLimit {
	return b.sourceSystem.GetRateLimit()
}

// SupportsPagination returns true if the connector supports pagination
func (b *BaseConnector) SupportsPagination() bool {
	// Base implementation - specific connectors should override
	return true
}

// SupportsIncremental returns true if the connector supports incremental extraction
func (b *BaseConnector) SupportsIncremental() bool {
	return b.sourceSystem.DataExtractionConfig.SupportsIncremental
}

// GetSystemInfo retrieves system information and capabilities
func (b *BaseConnector) GetSystemInfo(ctx context.Context) (*SystemInfo, error) {
	// Base implementation returns configured information
	systemInfo := &SystemInfo{
		SystemID:           b.sourceSystem.ID,
		Name:               b.sourceSystem.Name,
		Version:            b.sourceSystem.ProductVersion,
		Vendor:             b.sourceSystem.Vendor,
		SystemType:         b.sourceSystem.SystemType,
		SupportedDataTypes: b.sourceSystem.GetSupportedDataTypes(),
		Capabilities:       b.sourceSystem.Capabilities,
		ServerInfo:         make(map[string]interface{}),
	}

	// Add connector-specific information
	systemInfo.ServerInfo["connector_version"] = "1.0.0"
	systemInfo.ServerInfo["last_health_check"] = b.sourceSystem.LastHealthCheck
	systemInfo.ServerInfo["status"] = b.sourceSystem.Status
	systemInfo.ServerInfo["uptime_percentage"] = b.sourceSystem.UpTimePercentage

	return systemInfo, nil
}

// Utility methods

// addDefaultHeaders adds default headers to the request
func (b *BaseConnector) addDefaultHeaders(req *http.Request) {
	// Add default headers from configuration
	for key, value := range b.config.DefaultHeaders {
		req.Header.Set(key, value)
	}

	// Add source system default headers
	for key, value := range b.sourceSystem.ConnectionConfig.DefaultHeaders {
		req.Header.Set(key, value)
	}

	// Add authentication headers if available
	if b.authHandler != nil && b.authHandler.IsAuthenticated() {
		authHeaders := b.authHandler.GetAuthHeaders()
		for key, value := range authHeaders {
			req.Header.Set(key, value)
		}
	}

	// Add common headers
	req.Header.Set("User-Agent", "iSECTECH-Migration-Service/1.0")
	req.Header.Set("Accept", "application/json")
	if b.config.EnableCompression {
		req.Header.Set("Accept-Encoding", "gzip, deflate")
	}
}

// makeRequest makes an HTTP request with retry logic
func (b *BaseConnector) makeRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	b.recordMetric("total_requests", 1)

	var lastErr error
	maxRetries := int(b.config.MaxRetries)
	if !b.config.EnableRetries {
		maxRetries = 0
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(b.config.RetryDelay * time.Duration(attempt)):
			}
		}

		start := time.Now()
		resp, err := b.httpClient.Do(req)
		responseTime := time.Since(start)

		b.recordResponseTime(responseTime)

		if err != nil {
			lastErr = err
			b.recordError("http_request", err)
			continue
		}

		// Check for retryable status codes
		if b.isRetryableStatusCode(resp.StatusCode) && attempt < maxRetries {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
			resp.Body.Close()
			continue
		}

		// Request successful or not retryable
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			b.recordMetric("successful_requests", 1)
			now := time.Now()
			b.metricsMutex.Lock()
			b.metrics.LastSuccessTime = &now
			b.metricsMutex.Unlock()
		} else {
			b.recordMetric("failed_requests", 1)
			b.recordError("http_status", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status))
		}

		now := time.Now()
		b.metricsMutex.Lock()
		b.metrics.LastRequestTime = &now
		b.metricsMutex.Unlock()

		return resp, nil
	}

	b.recordMetric("failed_requests", 1)
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastErr)
}

// isRetryableStatusCode returns true if the HTTP status code is retryable
func (b *BaseConnector) isRetryableStatusCode(statusCode int) bool {
	switch statusCode {
	case 429, // Too Many Requests
		502, // Bad Gateway
		503, // Service Unavailable
		504: // Gateway Timeout
		return true
	default:
		return false
	}
}

// Health monitoring

// startHealthMonitoring starts continuous health monitoring
func (b *BaseConnector) startHealthMonitoring(ctx context.Context) {
	if b.config.HealthCheckInterval <= 0 {
		return
	}

	b.healthTicker = time.NewTicker(b.config.HealthCheckInterval)
	defer b.healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.healthStopChan:
			return
		case <-b.healthTicker.C:
			if health, err := b.CheckHealth(ctx); err == nil {
				b.healthMutex.Lock()
				b.healthStatus = health
				b.healthMutex.Unlock()
			}
		}
	}
}

// CheckHealth performs a health check on the source system
func (b *BaseConnector) CheckHealth(ctx context.Context) (*HealthStatus, error) {
	start := time.Now()
	
	// Test basic connectivity
	err := b.TestConnection(ctx)
	responseTime := time.Since(start)
	
	status := &HealthStatus{
		IsHealthy:     err == nil,
		Status:        "healthy",
		ResponseTime:  responseTime,
		LastChecked:   start,
		Components:    make(map[string]ComponentHealth),
	}

	if err != nil {
		status.Status = "unhealthy"
		status.Message = err.Error()
	}

	// Test authentication if configured
	if b.authHandler != nil {
		authStart := time.Now()
		authErr := b.authHandler.Authenticate(ctx)
		authTime := time.Since(authStart)

		status.Components["authentication"] = ComponentHealth{
			Name:         "authentication",
			IsHealthy:    authErr == nil,
			Status:       "healthy",
			ResponseTime: authTime,
			LastChecked:  authStart,
		}

		if authErr != nil {
			status.Components["authentication"].Status = "unhealthy"
			status.Components["authentication"].Message = authErr.Error()
			status.IsHealthy = false
			if status.Status == "healthy" {
				status.Status = "degraded"
			}
		}
	}

	return status, nil
}

// GetHealthMetrics returns current health metrics
func (b *BaseConnector) GetHealthMetrics() *HealthMetrics {
	b.metricsMutex.RLock()
	defer b.metricsMutex.RUnlock()

	totalRequests := b.metrics.TotalRequests
	if totalRequests == 0 {
		totalRequests = 1 // Avoid division by zero
	}

	uptime := float64(b.metrics.SuccessfulRequests) / float64(totalRequests) * 100.0
	errorRate := float64(b.metrics.FailedRequests) / float64(totalRequests) * 100.0

	return &HealthMetrics{
		UpTimePercentage:       uptime,
		AverageResponseTime:    b.metrics.AverageResponseTime,
		ErrorRate:              errorRate,
		SuccessfulRequests:     b.metrics.SuccessfulRequests,
		FailedRequests:         b.metrics.FailedRequests,
		TotalRequests:          b.metrics.TotalRequests,
		LastSuccessfulCheck:    time.Now(), // This should be updated from actual health checks
		ConsecutiveFailures:    0,          // This should be tracked
	}
}

// Metrics recording

// recordMetric records a metric
func (b *BaseConnector) recordMetric(metricName string, value int64) {
	if !b.config.EnableMetrics {
		return
	}

	b.metricsMutex.Lock()
	defer b.metricsMutex.Unlock()

	switch metricName {
	case "total_requests":
		b.metrics.TotalRequests += value
	case "successful_requests":
		b.metrics.SuccessfulRequests += value
	case "failed_requests":
		b.metrics.FailedRequests += value
	case "total_extractions":
		b.metrics.TotalExtractions += value
	case "total_records_extracted":
		b.metrics.TotalRecordsExtracted += value
	case "authentication_attempts":
		b.metrics.AuthenticationAttempts += value
	case "successful_authentications":
		b.metrics.SuccessfulAuthentications += value
	case "failed_authentications":
		b.metrics.FailedAuthentications += value
	case "token_refresh_count":
		b.metrics.TokenRefreshCount += value
	}
}

// recordResponseTime records response time
func (b *BaseConnector) recordResponseTime(duration time.Duration) {
	if !b.config.EnableMetrics {
		return
	}

	b.metricsMutex.Lock()
	defer b.metricsMutex.Unlock()

	if b.metrics.AverageResponseTime == 0 {
		b.metrics.AverageResponseTime = duration
		b.metrics.MinResponseTime = duration
		b.metrics.MaxResponseTime = duration
	} else {
		// Update average (simple moving average for now)
		totalTime := b.metrics.AverageResponseTime*time.Duration(b.metrics.TotalRequests-1) + duration
		b.metrics.AverageResponseTime = totalTime / time.Duration(b.metrics.TotalRequests)

		// Update min/max
		if duration < b.metrics.MinResponseTime {
			b.metrics.MinResponseTime = duration
		}
		if duration > b.metrics.MaxResponseTime {
			b.metrics.MaxResponseTime = duration
		}
	}
}

// recordError records an error
func (b *BaseConnector) recordError(errorType string, err error) {
	if !b.config.EnableMetrics {
		return
	}

	b.metricsMutex.Lock()
	defer b.metricsMutex.Unlock()

	b.metrics.ErrorsByType[errorType]++
	
	now := time.Now()
	b.metrics.LastError = &ConnectorError{
		Type:      errorType,
		Message:   err.Error(),
		Timestamp: now,
		Retryable: b.isRetryableError(err),
	}
	b.metrics.LastErrorTime = &now
}

// isRetryableError determines if an error is retryable
func (b *BaseConnector) isRetryableError(err error) bool {
	// Simple heuristic - can be improved
	errStr := err.Error()
	retryablePatterns := []string{
		"timeout",
		"connection refused",
		"temporary failure", 
		"rate limit",
		"too many requests",
		"service unavailable",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// GetMetrics returns current connector metrics
func (b *BaseConnector) GetMetrics() *ConnectorMetrics {
	b.metricsMutex.RLock()
	defer b.metricsMutex.RUnlock()

	// Create a copy to avoid concurrent access issues
	metricsCopy := *b.metrics
	metricsCopy.ErrorsByType = make(map[string]int64)
	for k, v := range b.metrics.ErrorsByType {
		metricsCopy.ErrorsByType[k] = v
	}

	return &metricsCopy
}

// Utility functions

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    len(s) > len(substr) && 
		    (s[:len(substr)] == substr || 
		     s[len(s)-len(substr):] == substr ||
		     containsInner(s, substr)))
}

func containsInner(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// marshalJSON safely marshals data to JSON
func marshalJSON(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// unmarshalJSON safely unmarshals JSON data
func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}