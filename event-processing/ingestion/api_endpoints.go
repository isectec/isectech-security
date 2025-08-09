package ingestion

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// APIEndpointsHandler manages REST API endpoints for third-party event ingestion
type APIEndpointsHandler struct {
	config       *APIConfig
	logger       *zap.Logger
	ingestionSvc IngestionService
	authProvider AuthenticationProvider
	rateLimiter  *APIRateLimiter
	validator    *APIRequestValidator
	transformer  *EventTransformer

	// Server management
	server     *http.Server
	router     *gin.Engine
	middleware []gin.HandlerFunc

	// State management
	isRunning  bool
	shutdownCh chan struct{}
	mutex      sync.RWMutex

	// Metrics
	metrics    *APIMetrics
	lastReport time.Time
}

// APIConfig defines configuration for API endpoints
type APIConfig struct {
	// Server Configuration
	Host       string `json:"host" validate:"required"` // 0.0.0.0
	Port       int    `json:"port" validate:"required"` // 8080
	TLSEnabled bool   `json:"tls_enabled"`              // Default: true
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`

	// Security Configuration
	AuthRequired   bool     `json:"auth_required"` // Default: true
	JWTSecret      string   `json:"jwt_secret,omitempty"`
	APIKeyHeader   string   `json:"api_key_header"` // Default: X-API-Key
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	// Rate Limiting
	RateLimit *APIRateLimitConfig `json:"rate_limit,omitempty"`

	// Request/Response Settings
	MaxRequestSize int64         `json:"max_request_size"` // Default: 10MB
	ReadTimeout    time.Duration `json:"read_timeout"`     // Default: 30s
	WriteTimeout   time.Duration `json:"write_timeout"`    // Default: 30s
	IdleTimeout    time.Duration `json:"idle_timeout"`     // Default: 120s

	// Processing Settings
	BatchSize         int           `json:"batch_size"`         // Default: 1000
	BatchTimeout      time.Duration `json:"batch_timeout"`      // Default: 5s
	EnableCompression bool          `json:"enable_compression"` // Default: true

	// Monitoring
	MetricsEnabled  bool   `json:"metrics_enabled"`   // Default: true
	MetricsPath     string `json:"metrics_path"`      // Default: /metrics
	HealthCheckPath string `json:"health_check_path"` // Default: /health

	// Validation
	StrictValidation bool `json:"strict_validation"` // Default: true
	SchemaValidation bool `json:"schema_validation"` // Default: true

	// Transformation
	EnableTransformation bool                 `json:"enable_transformation"` // Default: true
	TransformationRules  []TransformationRule `json:"transformation_rules,omitempty"`
}

// APIRateLimitConfig defines API-specific rate limiting
type APIRateLimitConfig struct {
	RequestsPerSecond int64         `json:"requests_per_second"` // Default: 1000
	BurstSize         int64         `json:"burst_size"`          // Default: 100
	WindowSize        time.Duration `json:"window_size"`         // Default: 1m
	PerTenantLimit    bool          `json:"per_tenant_limit"`    // Default: true
	PerIPLimit        bool          `json:"per_ip_limit"`        // Default: true
	IPLimitRequests   int64         `json:"ip_limit_requests"`   // Default: 100
}

// TransformationRule defines event transformation rules
type TransformationRule struct {
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"` // JSONPath or expression
	Actions   []TransformationAction `json:"actions"`
	Priority  int                    `json:"priority"`
	Enabled   bool                   `json:"enabled"`
}

// TransformationAction defines transformation actions
type TransformationAction struct {
	Type       string                 `json:"type"` // map, filter, enrich, normalize
	Field      string                 `json:"field,omitempty"`
	Value      interface{}            `json:"value,omitempty"`
	Expression string                 `json:"expression,omitempty"`
	Mapping    map[string]interface{} `json:"mapping,omitempty"`
}

// APIMetrics tracks API performance and usage
type APIMetrics struct {
	TotalRequests      int64   `json:"total_requests"`
	SuccessfulRequests int64   `json:"successful_requests"`
	FailedRequests     int64   `json:"failed_requests"`
	RequestsPerSecond  float64 `json:"requests_per_second"`

	AvgResponseTime time.Duration `json:"avg_response_time"`
	P95ResponseTime time.Duration `json:"p95_response_time"`
	P99ResponseTime time.Duration `json:"p99_response_time"`

	EventsIngested   int64 `json:"events_ingested"`
	BatchesProcessed int64 `json:"batches_processed"`

	ErrorsByType       map[string]int64 `json:"errors_by_type"`
	RequestsByTenant   map[string]int64 `json:"requests_by_tenant"`
	RequestsByEndpoint map[string]int64 `json:"requests_by_endpoint"`

	RateLimitHits    int64 `json:"rate_limit_hits"`
	ValidationErrors int64 `json:"validation_errors"`

	mutex      sync.RWMutex
	lastUpdate time.Time
}

// AuthenticationProvider handles API authentication
type AuthenticationProvider interface {
	ValidateAPIKey(apiKey string) (*TenantInfo, error)
	ValidateJWT(token string) (*TenantInfo, error)
	GetTenantInfo(tenantID string) (*TenantInfo, error)
}

// TenantInfo contains tenant authentication and authorization information
type TenantInfo struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	APIKey      string            `json:"api_key"`
	Permissions []string          `json:"permissions"`
	RateLimit   int64             `json:"rate_limit"`
	Metadata    map[string]string `json:"metadata"`
	Active      bool              `json:"active"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// APIRateLimiter implements API-specific rate limiting
type APIRateLimiter struct {
	config         *APIRateLimitConfig
	globalLimiter  *TokenBucket
	tenantLimiters map[string]*TokenBucket
	ipLimiters     map[string]*TokenBucket
	mutex          sync.RWMutex
}

// APIRequestValidator validates incoming API requests
type APIRequestValidator struct {
	config          *APIConfig
	strictMode      bool
	schemaValidator SchemaValidator
}

// EventTransformer handles event transformation based on rules
type EventTransformer struct {
	rules []TransformationRule
	mutex sync.RWMutex
}

// SchemaValidator validates events against schemas
type SchemaValidator interface {
	ValidateEvent(event *SecurityEvent) error
	ValidateBatch(batch *EventBatch) error
}

// Request/Response structures

// IngestEventRequest represents a single event ingestion request
type IngestEventRequest struct {
	Event          *SecurityEvent         `json:"event" validate:"required"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
	TransformRules []string               `json:"transform_rules,omitempty"`
	SkipValidation bool                   `json:"skip_validation,omitempty"`
}

// IngestBatchRequest represents a batch event ingestion request
type IngestBatchRequest struct {
	Events         []*SecurityEvent       `json:"events" validate:"required"`
	BatchMetadata  map[string]interface{} `json:"batch_metadata,omitempty"`
	TransformRules []string               `json:"transform_rules,omitempty"`
	SkipValidation bool                   `json:"skip_validation,omitempty"`
}

// IngestResponse represents the response to ingestion requests
type IngestResponse struct {
	Success        bool                   `json:"success"`
	Message        string                 `json:"message,omitempty"`
	EventID        string                 `json:"event_id,omitempty"`
	BatchID        string                 `json:"batch_id,omitempty"`
	ProcessedCount int                    `json:"processed_count,omitempty"`
	FailedCount    int                    `json:"failed_count,omitempty"`
	Errors         []APIError             `json:"errors,omitempty"`
	ProcessingTime time.Duration          `json:"processing_time"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// APIError represents an API error
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
	Details string `json:"details,omitempty"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status     string            `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Version    string            `json:"version"`
	Uptime     time.Duration     `json:"uptime"`
	Components map[string]string `json:"components"`
	Metrics    *APIMetrics       `json:"metrics,omitempty"`
}

// NewAPIEndpointsHandler creates a new API endpoints handler
func NewAPIEndpointsHandler(config *APIConfig, ingestionSvc IngestionService, authProvider AuthenticationProvider, logger *zap.Logger) (*APIEndpointsHandler, error) {
	if err := validateAPIConfig(config); err != nil {
		return nil, fmt.Errorf("invalid API configuration: %w", err)
	}

	setAPIDefaults(config)

	handler := &APIEndpointsHandler{
		config:       config,
		logger:       logger,
		ingestionSvc: ingestionSvc,
		authProvider: authProvider,
		shutdownCh:   make(chan struct{}),
		metrics:      NewAPIMetrics(),
		lastReport:   time.Now(),
	}

	// Initialize rate limiter
	if config.RateLimit != nil {
		handler.rateLimiter = NewAPIRateLimiter(config.RateLimit)
	}

	// Initialize request validator
	handler.validator = NewAPIRequestValidator(config)

	// Initialize event transformer
	if config.EnableTransformation {
		handler.transformer = NewEventTransformer(config.TransformationRules)
	}

	// Setup router
	if err := handler.setupRouter(); err != nil {
		return nil, fmt.Errorf("failed to setup router: %w", err)
	}

	return handler, nil
}

// Start initializes and starts the API endpoints handler
func (h *APIEndpointsHandler) Start(ctx context.Context) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.isRunning {
		return fmt.Errorf("API endpoints handler is already running")
	}

	address := fmt.Sprintf("%s:%d", h.config.Host, h.config.Port)

	h.server = &http.Server{
		Addr:         address,
		Handler:      h.router,
		ReadTimeout:  h.config.ReadTimeout,
		WriteTimeout: h.config.WriteTimeout,
		IdleTimeout:  h.config.IdleTimeout,
	}

	h.logger.Info("Starting API endpoints handler",
		zap.String("address", address),
		zap.Bool("tls_enabled", h.config.TLSEnabled))

	go func() {
		var err error
		if h.config.TLSEnabled {
			err = h.server.ListenAndServeTLS(h.config.CertFile, h.config.KeyFile)
		} else {
			err = h.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			h.logger.Error("API server error", zap.Error(err))
		}
	}()

	h.isRunning = true
	h.logger.Info("API endpoints handler started successfully")
	return nil
}

// Stop gracefully shuts down the API endpoints handler
func (h *APIEndpointsHandler) Stop(ctx context.Context) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.isRunning {
		return fmt.Errorf("API endpoints handler is not running")
	}

	h.logger.Info("Stopping API endpoints handler")

	// Signal shutdown
	close(h.shutdownCh)

	// Shutdown server with context timeout
	if err := h.server.Shutdown(ctx); err != nil {
		h.logger.Warn("API server forced shutdown", zap.Error(err))
		return err
	}

	h.isRunning = false
	h.logger.Info("API endpoints handler stopped successfully")
	return nil
}

// GetMetrics returns current API metrics
func (h *APIEndpointsHandler) GetMetrics() *APIMetrics {
	h.metrics.mutex.RLock()
	defer h.metrics.mutex.RUnlock()

	// Create a copy
	metrics := *h.metrics
	metrics.ErrorsByType = make(map[string]int64)
	metrics.RequestsByTenant = make(map[string]int64)
	metrics.RequestsByEndpoint = make(map[string]int64)

	for errorType, count := range h.metrics.ErrorsByType {
		metrics.ErrorsByType[errorType] = count
	}
	for tenant, count := range h.metrics.RequestsByTenant {
		metrics.RequestsByTenant[tenant] = count
	}
	for endpoint, count := range h.metrics.RequestsByEndpoint {
		metrics.RequestsByEndpoint[endpoint] = count
	}

	return &metrics
}

// Private methods

func (h *APIEndpointsHandler) setupRouter() error {
	// Set Gin mode
	if h.logger.Core().Enabled(zap.DebugLevel) {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	h.router = gin.New()

	// Add middleware
	h.router.Use(h.loggingMiddleware())
	h.router.Use(h.recoveryMiddleware())
	h.router.Use(h.corsMiddleware())
	h.router.Use(h.securityMiddleware())
	h.router.Use(h.metricsMiddleware())

	if h.rateLimiter != nil {
		h.router.Use(h.rateLimitMiddleware())
	}

	if h.config.AuthRequired {
		h.router.Use(h.authenticationMiddleware())
	}

	// Health check endpoint (no auth required)
	h.router.GET(h.config.HealthCheckPath, h.healthCheck)

	// Metrics endpoint (no auth required)
	if h.config.MetricsEnabled {
		h.router.GET(h.config.MetricsPath, h.getMetrics)
	}

	// API versioning
	v1 := h.router.Group("/api/v1")
	{
		// Event ingestion endpoints
		v1.POST("/events", h.ingestEvent)
		v1.POST("/events/batch", h.ingestBatch)

		// Bulk operations
		v1.POST("/events/bulk", h.bulkIngest)

		// Async ingestion with webhook callbacks
		v1.POST("/events/async", h.asyncIngest)

		// Schema validation
		v1.POST("/events/validate", h.validateEvent)
		v1.POST("/events/batch/validate", h.validateBatch)

		// Transformation testing
		v1.POST("/events/transform", h.transformEvent)

		// Configuration management
		v1.GET("/config", h.getConfiguration)
		v1.PUT("/config", h.updateConfiguration)
	}

	return nil
}

// Middleware implementations

func (h *APIEndpointsHandler) loggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		h.logger.Info("API request",
			zap.String("method", param.Method),
			zap.String("path", param.Path),
			zap.Int("status", param.StatusCode),
			zap.Duration("latency", param.Latency),
			zap.String("client_ip", param.ClientIP),
			zap.String("user_agent", param.Request.UserAgent()))
		return ""
	})
}

func (h *APIEndpointsHandler) recoveryMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		h.logger.Error("API panic recovered",
			zap.Any("recovered", recovered),
			zap.String("path", c.Request.URL.Path))

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Internal server error",
		})
	})
}

func (h *APIEndpointsHandler) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Check allowed origins
		if len(h.config.AllowedOrigins) > 0 {
			allowed := false
			for _, allowedOrigin := range h.config.AllowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}
			if !allowed {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "Origin not allowed",
				})
				return
			}
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		c.Header("Access-Control-Max-Age", "3600")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (h *APIEndpointsHandler) securityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Check content length
		if c.Request.ContentLength > h.config.MaxRequestSize {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request too large",
			})
			return
		}

		c.Next()
	}
}

func (h *APIEndpointsHandler) metricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Process request
		c.Next()

		// Update metrics
		duration := time.Since(start)
		h.updateRequestMetrics(c.Request.Method, c.FullPath(), c.Writer.Status(), duration)
	}
}

func (h *APIEndpointsHandler) rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()
		tenantID := h.getTenantIDFromContext(c)

		// Check rate limits
		if !h.rateLimiter.AllowRequest(tenantID, clientIP) {
			h.updateMetric("rate_limit_hits", 1)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retry_after": "60",
			})
			return
		}

		c.Next()
	}
}

func (h *APIEndpointsHandler) authenticationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		var tenantInfo *TenantInfo
		var err error

		// Try API key authentication first
		apiKey := c.GetHeader(h.config.APIKeyHeader)
		if apiKey != "" {
			tenantInfo, err = h.authProvider.ValidateAPIKey(apiKey)
		} else {
			// Try JWT authentication
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				tenantInfo, err = h.authProvider.ValidateJWT(token)
			}
		}

		if err != nil || tenantInfo == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication failed",
			})
			return
		}

		// Check if tenant is active
		if !tenantInfo.Active {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Tenant account is inactive",
			})
			return
		}

		// Check expiration
		if tenantInfo.ExpiresAt != nil && time.Now().After(*tenantInfo.ExpiresAt) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Tenant account has expired",
			})
			return
		}

		// Store tenant info in context
		c.Set("tenant_info", tenantInfo)
		c.Set("tenant_id", tenantInfo.ID)

		c.Next()
	}
}

// Handler implementations

func (h *APIEndpointsHandler) healthCheck(c *gin.Context) {
	response := HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Uptime:    time.Since(h.lastReport),
		Components: map[string]string{
			"ingestion_service": "healthy",
			"rate_limiter":      "healthy",
			"transformer":       "healthy",
		},
	}

	if h.config.MetricsEnabled {
		response.Metrics = h.GetMetrics()
	}

	c.JSON(http.StatusOK, response)
}

func (h *APIEndpointsHandler) getMetrics(c *gin.Context) {
	metrics := h.GetMetrics()
	c.JSON(http.StatusOK, metrics)
}

func (h *APIEndpointsHandler) ingestEvent(c *gin.Context) {
	startTime := time.Now()

	var request IngestEventRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid_request", "Invalid request format", err.Error())
		return
	}

	// Get tenant info
	tenantInfo, _ := c.Get("tenant_info")
	if ti, ok := tenantInfo.(*TenantInfo); ok {
		request.Event.TenantID = ti.ID
	}

	// Validate event
	if !request.SkipValidation && h.validator != nil {
		if err := h.validator.ValidateEvent(request.Event); err != nil {
			h.updateMetric("validation_errors", 1)
			h.respondWithError(c, http.StatusBadRequest, "validation_error", "Event validation failed", err.Error())
			return
		}
	}

	// Transform event if enabled
	if h.transformer != nil && len(request.TransformRules) > 0 {
		if err := h.transformer.TransformEvent(request.Event, request.TransformRules); err != nil {
			h.respondWithError(c, http.StatusInternalServerError, "transformation_error", "Event transformation failed", err.Error())
			return
		}
	}

	// Ingest event
	if err := h.ingestionSvc.IngestEvent(c.Request.Context(), request.Event); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, "ingestion_error", "Event ingestion failed", err.Error())
		return
	}

	// Update metrics
	h.updateMetric("events_ingested", 1)

	response := IngestResponse{
		Success:        true,
		Message:        "Event ingested successfully",
		EventID:        request.Event.ID,
		ProcessedCount: 1,
		ProcessingTime: time.Since(startTime),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *APIEndpointsHandler) ingestBatch(c *gin.Context) {
	startTime := time.Now()

	var request IngestBatchRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid_request", "Invalid request format", err.Error())
		return
	}

	// Get tenant info
	tenantInfo, _ := c.Get("tenant_info")
	if ti, ok := tenantInfo.(*TenantInfo); ok {
		for _, event := range request.Events {
			event.TenantID = ti.ID
		}
	}

	// Create batch
	batch := NewEventBatch(h.getTenantIDFromContext(c), request.Events)

	// Validate batch
	if !request.SkipValidation && h.validator != nil {
		if err := h.validator.ValidateBatch(batch); err != nil {
			h.updateMetric("validation_errors", 1)
			h.respondWithError(c, http.StatusBadRequest, "validation_error", "Batch validation failed", err.Error())
			return
		}
	}

	// Transform events if enabled
	if h.transformer != nil && len(request.TransformRules) > 0 {
		for _, event := range batch.Events {
			if err := h.transformer.TransformEvent(event, request.TransformRules); err != nil {
				h.respondWithError(c, http.StatusInternalServerError, "transformation_error", "Event transformation failed", err.Error())
				return
			}
		}
	}

	// Ingest batch
	if err := h.ingestionSvc.IngestBatch(c.Request.Context(), batch); err != nil {
		h.respondWithError(c, http.StatusInternalServerError, "ingestion_error", "Batch ingestion failed", err.Error())
		return
	}

	// Update metrics
	h.updateMetric("events_ingested", int64(len(batch.Events)))
	h.updateMetric("batches_processed", 1)

	response := IngestResponse{
		Success:        true,
		Message:        "Batch ingested successfully",
		BatchID:        batch.ID,
		ProcessedCount: len(batch.Events),
		ProcessingTime: time.Since(startTime),
	}

	c.JSON(http.StatusCreated, response)
}

func (h *APIEndpointsHandler) bulkIngest(c *gin.Context) {
	// Implementation for bulk ingestion with streaming
	h.respondWithError(c, http.StatusNotImplemented, "not_implemented", "Bulk ingestion not yet implemented", "")
}

func (h *APIEndpointsHandler) asyncIngest(c *gin.Context) {
	// Implementation for asynchronous ingestion with webhooks
	h.respondWithError(c, http.StatusNotImplemented, "not_implemented", "Async ingestion not yet implemented", "")
}

func (h *APIEndpointsHandler) validateEvent(c *gin.Context) {
	var event SecurityEvent
	if err := c.ShouldBindJSON(&event); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid_request", "Invalid event format", err.Error())
		return
	}

	if h.validator == nil {
		h.respondWithError(c, http.StatusServiceUnavailable, "validator_unavailable", "Validation service not available", "")
		return
	}

	if err := h.validator.ValidateEvent(&event); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
	})
}

func (h *APIEndpointsHandler) validateBatch(c *gin.Context) {
	var batch EventBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "invalid_request", "Invalid batch format", err.Error())
		return
	}

	if h.validator == nil {
		h.respondWithError(c, http.StatusServiceUnavailable, "validator_unavailable", "Validation service not available", "")
		return
	}

	if err := h.validator.ValidateBatch(&batch); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":  false,
			"errors": []string{err.Error()},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
	})
}

func (h *APIEndpointsHandler) transformEvent(c *gin.Context) {
	// Implementation for event transformation testing
	h.respondWithError(c, http.StatusNotImplemented, "not_implemented", "Event transformation testing not yet implemented", "")
}

func (h *APIEndpointsHandler) getConfiguration(c *gin.Context) {
	// Return sanitized configuration (no secrets)
	config := map[string]interface{}{
		"rate_limit":           h.config.RateLimit,
		"max_request_size":     h.config.MaxRequestSize,
		"batch_size":           h.config.BatchSize,
		"batch_timeout":        h.config.BatchTimeout,
		"enable_compression":   h.config.EnableCompression,
		"transformation_rules": h.config.TransformationRules,
	}

	c.JSON(http.StatusOK, config)
}

func (h *APIEndpointsHandler) updateConfiguration(c *gin.Context) {
	// Implementation for configuration updates
	h.respondWithError(c, http.StatusNotImplemented, "not_implemented", "Configuration updates not yet implemented", "")
}

// Helper methods

func (h *APIEndpointsHandler) respondWithError(c *gin.Context, statusCode int, code, message, details string) {
	h.updateErrorMetric(code)

	apiError := APIError{
		Code:    code,
		Message: message,
		Details: details,
	}

	c.JSON(statusCode, IngestResponse{
		Success: false,
		Message: message,
		Errors:  []APIError{apiError},
	})
}

func (h *APIEndpointsHandler) getTenantIDFromContext(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		if tid, ok := tenantID.(string); ok {
			return tid
		}
	}
	return ""
}

func (h *APIEndpointsHandler) updateRequestMetrics(method, path string, status int, duration time.Duration) {
	h.metrics.mutex.Lock()
	defer h.metrics.mutex.Unlock()

	h.metrics.TotalRequests++
	if status >= 200 && status < 300 {
		h.metrics.SuccessfulRequests++
	} else {
		h.metrics.FailedRequests++
	}

	// Update endpoint-specific metrics
	endpoint := fmt.Sprintf("%s %s", method, path)
	if h.metrics.RequestsByEndpoint == nil {
		h.metrics.RequestsByEndpoint = make(map[string]int64)
	}
	h.metrics.RequestsByEndpoint[endpoint]++

	h.metrics.lastUpdate = time.Now()
}

func (h *APIEndpointsHandler) updateMetric(name string, value int64) {
	h.metrics.mutex.Lock()
	defer h.metrics.mutex.Unlock()

	switch name {
	case "events_ingested":
		h.metrics.EventsIngested += value
	case "batches_processed":
		h.metrics.BatchesProcessed += value
	case "rate_limit_hits":
		h.metrics.RateLimitHits += value
	case "validation_errors":
		h.metrics.ValidationErrors += value
	}
}

func (h *APIEndpointsHandler) updateErrorMetric(errorType string) {
	h.metrics.mutex.Lock()
	defer h.metrics.mutex.Unlock()

	if h.metrics.ErrorsByType == nil {
		h.metrics.ErrorsByType = make(map[string]int64)
	}
	h.metrics.ErrorsByType[errorType]++
}

// Utility functions

func validateAPIConfig(config *APIConfig) error {
	if config.Host == "" {
		return fmt.Errorf("host is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}
	if config.TLSEnabled && (config.CertFile == "" || config.KeyFile == "") {
		return fmt.Errorf("TLS certificate and key files are required when TLS is enabled")
	}
	return nil
}

func setAPIDefaults(config *APIConfig) {
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.APIKeyHeader == "" {
		config.APIKeyHeader = "X-API-Key"
	}
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 10 * 1024 * 1024 // 10MB
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 120 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 5 * time.Second
	}
	if config.HealthCheckPath == "" {
		config.HealthCheckPath = "/health"
	}
	if config.MetricsPath == "" {
		config.MetricsPath = "/metrics"
	}
}

func NewAPIMetrics() *APIMetrics {
	return &APIMetrics{
		ErrorsByType:       make(map[string]int64),
		RequestsByTenant:   make(map[string]int64),
		RequestsByEndpoint: make(map[string]int64),
		lastUpdate:         time.Now(),
	}
}

// Placeholder implementations

func NewAPIRateLimiter(config *APIRateLimitConfig) *APIRateLimiter {
	return &APIRateLimiter{
		config:         config,
		tenantLimiters: make(map[string]*TokenBucket),
		ipLimiters:     make(map[string]*TokenBucket),
	}
}

func (r *APIRateLimiter) AllowRequest(tenantID, clientIP string) bool {
	// Simplified implementation
	return true
}

func NewAPIRequestValidator(config *APIConfig) *APIRequestValidator {
	return &APIRequestValidator{
		config:     config,
		strictMode: config.StrictValidation,
	}
}

func (v *APIRequestValidator) ValidateEvent(event *SecurityEvent) error {
	return event.Validate()
}

func (v *APIRequestValidator) ValidateBatch(batch *EventBatch) error {
	for _, event := range batch.Events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func NewEventTransformer(rules []TransformationRule) *EventTransformer {
	return &EventTransformer{
		rules: rules,
	}
}

func (t *EventTransformer) TransformEvent(event *SecurityEvent, ruleNames []string) error {
	// Simplified implementation
	return nil
}
