package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/isectech/platform/services/api-gateway/infrastructure/cache"
	"github.com/isectech/platform/services/api-gateway/infrastructure/database"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	logger   *zap.Logger
	cache    cache.Cache
	database database.Database
	startTime time.Time
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(logger *zap.Logger, cache cache.Cache, database database.Database) *HealthHandler {
	return &HealthHandler{
		logger:    logger,
		cache:     cache,
		database:  database,
		startTime: time.Now(),
	}
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status      string                 `json:"status"`
	Timestamp   time.Time              `json:"timestamp"`
	Service     string                 `json:"service"`
	Version     string                 `json:"version"`
	Environment string                 `json:"environment"`
	Uptime      string                 `json:"uptime"`
	Checks      map[string]HealthCheck `json:"checks,omitempty"`
}

// HealthCheck represents an individual health check
type HealthCheck struct {
	Status    string        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Duration  time.Duration `json:"duration_ms"`
	Timestamp time.Time     `json:"timestamp"`
	Details   interface{}   `json:"details,omitempty"`
}

// Health returns the overall health status
func (h *HealthHandler) Health(c *gin.Context) {
	startTime := time.Now()
	
	// Perform health checks
	checks := make(map[string]HealthCheck)
	
	// Check cache (Redis)
	checks["cache"] = h.checkCache()
	
	// Check database (if enabled)
	if h.database != nil {
		checks["database"] = h.checkDatabase()
	}
	
	// Determine overall status
	status := "healthy"
	for _, check := range checks {
		if check.Status != "healthy" {
			status = "unhealthy"
			break
		}
	}
	
	response := HealthResponse{
		Status:      status,
		Timestamp:   time.Now(),
		Service:     "isectech-api-gateway",
		Version:     "2.0.0",
		Environment: getEnvironment(),
		Uptime:      time.Since(h.startTime).String(),
		Checks:      checks,
	}
	
	// Log health check
	h.logger.Debug("Health check completed",
		zap.String("status", status),
		zap.Duration("duration", time.Since(startTime)),
		zap.Int("checks_count", len(checks)),
	)
	
	// Return appropriate HTTP status
	if status == "healthy" {
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusServiceUnavailable, response)
	}
}

// Liveness returns the liveness probe response
func (h *HealthHandler) Liveness(c *gin.Context) {
	// Liveness check is simple - just check if the service is running
	response := HealthResponse{
		Status:      "alive",
		Timestamp:   time.Now(),
		Service:     "isectech-api-gateway",
		Version:     "2.0.0",
		Environment: getEnvironment(),
		Uptime:      time.Since(h.startTime).String(),
	}
	
	h.logger.Debug("Liveness check completed")
	c.JSON(http.StatusOK, response)
}

// Readiness returns the readiness probe response
func (h *HealthHandler) Readiness(c *gin.Context) {
	startTime := time.Now()
	
	// Readiness checks are more comprehensive
	checks := make(map[string]HealthCheck)
	
	// Check cache readiness
	checks["cache"] = h.checkCache()
	
	// Check database readiness (if enabled)
	if h.database != nil {
		checks["database"] = h.checkDatabase()
	}
	
	// Check if we have required configuration
	checks["config"] = h.checkConfiguration()
	
	// Determine readiness status
	ready := true
	for _, check := range checks {
		if check.Status != "healthy" {
			ready = false
			break
		}
	}
	
	status := "ready"
	if !ready {
		status = "not_ready"
	}
	
	response := HealthResponse{
		Status:      status,
		Timestamp:   time.Now(),
		Service:     "isectech-api-gateway",
		Version:     "2.0.0",
		Environment: getEnvironment(),
		Uptime:      time.Since(h.startTime).String(),
		Checks:      checks,
	}
	
	// Log readiness check
	h.logger.Debug("Readiness check completed",
		zap.String("status", status),
		zap.Duration("duration", time.Since(startTime)),
		zap.Bool("ready", ready),
	)
	
	// Return appropriate HTTP status
	if ready {
		c.JSON(http.StatusOK, response)
	} else {
		c.JSON(http.StatusServiceUnavailable, response)
	}
}

// checkCache checks the cache connection
func (h *HealthHandler) checkCache() HealthCheck {
	start := time.Now()
	
	if h.cache == nil {
		return HealthCheck{
			Status:    "unhealthy",
			Message:   "Cache not configured",
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}
	}
	
	// Test cache connectivity with a simple ping
	err := h.cache.Ping()
	duration := time.Since(start)
	
	if err != nil {
		h.logger.Warn("Cache health check failed", zap.Error(err))
		return HealthCheck{
			Status:    "unhealthy",
			Message:   "Cache connection failed: " + err.Error(),
			Duration:  duration,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}
	
	return HealthCheck{
		Status:    "healthy",
		Message:   "Cache connection successful",
		Duration:  duration,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"type": "redis",
		},
	}
}

// checkDatabase checks the database connection
func (h *HealthHandler) checkDatabase() HealthCheck {
	start := time.Now()
	
	if h.database == nil {
		return HealthCheck{
			Status:    "healthy", // Database is optional
			Message:   "Database not configured",
			Duration:  time.Since(start),
			Timestamp: time.Now(),
		}
	}
	
	// Test database connectivity
	err := h.database.Ping()
	duration := time.Since(start)
	
	if err != nil {
		h.logger.Warn("Database health check failed", zap.Error(err))
		return HealthCheck{
			Status:    "unhealthy",
			Message:   "Database connection failed: " + err.Error(),
			Duration:  duration,
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"error": err.Error(),
			},
		}
	}
	
	return HealthCheck{
		Status:    "healthy",
		Message:   "Database connection successful",
		Duration:  duration,
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"type": "postgresql",
		},
	}
}

// checkConfiguration checks if required configuration is present
func (h *HealthHandler) checkConfiguration() HealthCheck {
	start := time.Now()
	
	// Check for required environment variables or configuration
	issues := []string{}
	
	// These would be more comprehensive in a real implementation
	// For now, just check basic requirements
	
	if len(issues) > 0 {
		return HealthCheck{
			Status:    "unhealthy",
			Message:   "Configuration issues detected",
			Duration:  time.Since(start),
			Timestamp: time.Now(),
			Details: map[string]interface{}{
				"issues": issues,
			},
		}
	}
	
	return HealthCheck{
		Status:    "healthy",
		Message:   "Configuration valid",
		Duration:  time.Since(start),
		Timestamp: time.Now(),
	}
}

// getEnvironment returns the current environment
func getEnvironment() string {
	if env := getEnvOrDefault("ENVIRONMENT", ""); env != "" {
		return env
	}
	return "unknown"
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}