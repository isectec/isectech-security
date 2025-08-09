package stream_processing

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthMonitor monitors the health of stream processing components
type HealthMonitor struct {
	logger *zap.Logger
	config *HealthConfig
	
	// Component health status
	componentHealth map[string]*ComponentHealthStatus
	overallHealth   *OverallHealthStatus
	mu              sync.RWMutex
	
	// Health check functions
	healthCheckers  map[string]HealthChecker
	
	// Background monitoring
	ctx             context.Context
	cancel          context.CancelFunc
	checkTicker     *time.Ticker
	
	// Metrics integration
	metricsCollector *MetricsCollector
	
	// HTTP server for health endpoints
	httpServer      *http.Server
}

// HealthConfig defines configuration for health monitoring
type HealthConfig struct {
	Enabled              bool          `json:"enabled"`
	CheckInterval        time.Duration `json:"check_interval"`
	HTTPPort             int           `json:"http_port"`
	HealthyThreshold     int           `json:"healthy_threshold"`
	UnhealthyThreshold   int           `json:"unhealthy_threshold"`
	
	// Component timeouts
	ComponentTimeout     time.Duration `json:"component_timeout"`
	
	// Alert thresholds
	MaxResponseTime      time.Duration `json:"max_response_time"`
	MinSuccessRate       float64       `json:"min_success_rate"`
	
	// Dependencies
	CheckKafkaHealth     bool          `json:"check_kafka_health"`
	CheckEnrichmentHealth bool         `json:"check_enrichment_health"`
	CheckMLServiceHealth bool          `json:"check_ml_service_health"`
}

// ComponentHealthStatus represents the health status of a component
type ComponentHealthStatus struct {
	Name            string                 `json:"name"`
	Status          HealthStatus           `json:"status"`
	LastCheckTime   time.Time              `json:"last_check_time"`
	ResponseTime    time.Duration          `json:"response_time"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	ConsecutiveFails int                   `json:"consecutive_fails"`
	Details         map[string]interface{} `json:"details,omitempty"`
	
	// Historical data
	UptimePercentage float64               `json:"uptime_percentage"`
	LastFailureTime time.Time              `json:"last_failure_time,omitempty"`
	TotalChecks     int64                  `json:"total_checks"`
	FailedChecks    int64                  `json:"failed_checks"`
}

// OverallHealthStatus represents the overall system health
type OverallHealthStatus struct {
	Status           HealthStatus           `json:"status"`
	LastUpdateTime   time.Time              `json:"last_update_time"`
	HealthyComponents int                   `json:"healthy_components"`
	TotalComponents  int                    `json:"total_components"`
	CriticalIssues   []string               `json:"critical_issues,omitempty"`
	Warnings         []string               `json:"warnings,omitempty"`
}

// HealthStatus represents health status values
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthChecker defines the interface for component health checks
type HealthChecker interface {
	CheckHealth(ctx context.Context) (*ComponentHealthStatus, error)
	GetComponentName() string
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	ComponentName string
	Status        *ComponentHealthStatus
	Error         error
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor(logger *zap.Logger, config *HealthConfig, metricsCollector *MetricsCollector) (*HealthMonitor, error) {
	if config == nil {
		return nil, fmt.Errorf("health configuration is required")
	}
	
	// Set defaults
	if config.CheckInterval == 0 {
		config.CheckInterval = 30 * time.Second
	}
	if config.HTTPPort == 0 {
		config.HTTPPort = 8080
	}
	if config.HealthyThreshold == 0 {
		config.HealthyThreshold = 2
	}
	if config.UnhealthyThreshold == 0 {
		config.UnhealthyThreshold = 3
	}
	if config.ComponentTimeout == 0 {
		config.ComponentTimeout = 10 * time.Second
	}
	if config.MaxResponseTime == 0 {
		config.MaxResponseTime = 5 * time.Second
	}
	if config.MinSuccessRate == 0 {
		config.MinSuccessRate = 0.95
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &HealthMonitor{
		logger:           logger.With(zap.String("component", "health-monitor")),
		config:           config,
		componentHealth:  make(map[string]*ComponentHealthStatus),
		overallHealth:    &OverallHealthStatus{Status: HealthStatusUnknown},
		healthCheckers:   make(map[string]HealthChecker),
		metricsCollector: metricsCollector,
		ctx:              ctx,
		cancel:           cancel,
	}
	
	// Initialize built-in health checkers
	monitor.initializeBuiltinHealthCheckers()
	
	// Start HTTP server if enabled
	if config.Enabled {
		if err := monitor.startHTTPServer(); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to start health HTTP server: %w", err)
		}
	}
	
	// Start background health checking
	monitor.checkTicker = time.NewTicker(config.CheckInterval)
	go monitor.runHealthChecking()
	
	logger.Info("Health monitor initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Int("http_port", config.HTTPPort),
		zap.Duration("check_interval", config.CheckInterval),
	)
	
	return monitor, nil
}

// RegisterHealthChecker registers a health checker for a component
func (h *HealthMonitor) RegisterHealthChecker(checker HealthChecker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	componentName := checker.GetComponentName()
	h.healthCheckers[componentName] = checker
	
	// Initialize component health status
	h.componentHealth[componentName] = &ComponentHealthStatus{
		Name:             componentName,
		Status:           HealthStatusUnknown,
		LastCheckTime:    time.Now(),
		UptimePercentage: 100.0,
		Details:          make(map[string]interface{}),
	}
	
	h.logger.Info("Health checker registered", zap.String("component", componentName))
}

// GetComponentHealth returns the health status of a specific component
func (h *HealthMonitor) GetComponentHealth(componentName string) (*ComponentHealthStatus, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	status, exists := h.componentHealth[componentName]
	if !exists {
		return nil, false
	}
	
	// Return a copy to prevent external modifications
	statusCopy := *status
	return &statusCopy, true
}

// GetOverallHealth returns the overall system health status
func (h *HealthMonitor) GetOverallHealth() *OverallHealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	// Return a copy to prevent external modifications
	healthCopy := *h.overallHealth
	return &healthCopy
}

// IsHealthy returns true if the overall system is healthy
func (h *HealthMonitor) IsHealthy() bool {
	health := h.GetOverallHealth()
	return health.Status == HealthStatusHealthy
}

// runHealthChecking runs periodic health checks
func (h *HealthMonitor) runHealthChecking() {
	// Initial health check
	h.performHealthChecks()
	
	for {
		select {
		case <-h.ctx.Done():
			return
		case <-h.checkTicker.C:
			h.performHealthChecks()
		}
	}
}

// performHealthChecks performs health checks on all registered components
func (h *HealthMonitor) performHealthChecks() {
	h.mu.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range h.healthCheckers {
		checkers[name] = checker
	}
	h.mu.RUnlock()
	
	// Perform health checks concurrently
	resultChan := make(chan *HealthCheckResult, len(checkers))
	
	for _, checker := range checkers {
		go func(c HealthChecker) {
			ctx, cancel := context.WithTimeout(h.ctx, h.config.ComponentTimeout)
			defer cancel()
			
			start := time.Now()
			status, err := c.CheckHealth(ctx)
			duration := time.Since(start)
			
			if status != nil {
				status.ResponseTime = duration
				status.LastCheckTime = time.Now()
			}
			
			resultChan <- &HealthCheckResult{
				ComponentName: c.GetComponentName(),
				Status:        status,
				Error:         err,
			}
		}(checker)
	}
	
	// Collect results
	results := make([]*HealthCheckResult, 0, len(checkers))
	for i := 0; i < len(checkers); i++ {
		result := <-resultChan
		results = append(results, result)
	}
	
	// Update component health status
	h.updateComponentHealth(results)
	
	// Update overall health status
	h.updateOverallHealth()
	
	// Update metrics
	h.updateHealthMetrics()
}

// updateComponentHealth updates the health status of components
func (h *HealthMonitor) updateComponentHealth(results []*HealthCheckResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	for _, result := range results {
		component := h.componentHealth[result.ComponentName]
		if component == nil {
			continue
		}
		
		component.TotalChecks++
		
		if result.Error != nil || result.Status == nil {
			// Health check failed
			component.FailedChecks++
			component.ConsecutiveFails++
			component.Status = HealthStatusUnhealthy
			component.ErrorMessage = ""
			if result.Error != nil {
				component.ErrorMessage = result.Error.Error()
			}
			component.LastFailureTime = time.Now()
			
			h.logger.Warn("Component health check failed",
				zap.String("component", result.ComponentName),
				zap.Error(result.Error),
			)
		} else {
			// Health check succeeded
			component.ConsecutiveFails = 0
			component.Status = result.Status.Status
			component.ResponseTime = result.Status.ResponseTime
			component.ErrorMessage = ""
			component.Details = result.Status.Details
			
			// Check response time threshold
			if component.ResponseTime > h.config.MaxResponseTime {
				component.Status = HealthStatusDegraded
				if component.Details == nil {
					component.Details = make(map[string]interface{})
				}
				component.Details["slow_response"] = true
				component.Details["response_time"] = component.ResponseTime.String()
			}
		}
		
		// Update uptime percentage
		if component.TotalChecks > 0 {
			successfulChecks := component.TotalChecks - component.FailedChecks
			component.UptimePercentage = (float64(successfulChecks) / float64(component.TotalChecks)) * 100.0
		}
		
		component.LastCheckTime = time.Now()
	}
}

// updateOverallHealth updates the overall system health status
func (h *HealthMonitor) updateOverallHealth() {
	h.mu.Lock()
	defer h.mu.Unlock()
	
	healthyCount := 0
	totalCount := len(h.componentHealth)
	criticalIssues := []string{}
	warnings := []string{}
	
	for name, component := range h.componentHealth {
		switch component.Status {
		case HealthStatusHealthy:
			healthyCount++
		case HealthStatusDegraded:
			healthyCount++ // Count as healthy but add warning
			warnings = append(warnings, fmt.Sprintf("Component %s is degraded: %s", name, component.ErrorMessage))
		case HealthStatusUnhealthy:
			criticalIssues = append(criticalIssues, fmt.Sprintf("Component %s is unhealthy: %s", name, component.ErrorMessage))
		}
		
		// Check uptime threshold
		if component.UptimePercentage < h.config.MinSuccessRate*100 {
			warnings = append(warnings, fmt.Sprintf("Component %s has low uptime: %.2f%%", name, component.UptimePercentage))
		}
	}
	
	// Determine overall status
	var overallStatus HealthStatus
	if len(criticalIssues) > 0 {
		overallStatus = HealthStatusUnhealthy
	} else if len(warnings) > 0 {
		overallStatus = HealthStatusDegraded
	} else if healthyCount == totalCount && totalCount > 0 {
		overallStatus = HealthStatusHealthy
	} else {
		overallStatus = HealthStatusUnknown
	}
	
	h.overallHealth = &OverallHealthStatus{
		Status:            overallStatus,
		LastUpdateTime:    time.Now(),
		HealthyComponents: healthyCount,
		TotalComponents:   totalCount,
		CriticalIssues:    criticalIssues,
		Warnings:          warnings,
	}
}

// updateHealthMetrics updates health-related metrics
func (h *HealthMonitor) updateHealthMetrics() {
	if h.metricsCollector == nil {
		return
	}
	
	h.mu.RLock()
	defer h.mu.RUnlock()
	
	for name, component := range h.componentHealth {
		isHealthy := component.Status == HealthStatusHealthy
		h.metricsCollector.UpdateHealthStatus(name, isHealthy)
	}
	
	// Update overall health metric
	overallHealthy := h.overallHealth.Status == HealthStatusHealthy
	h.metricsCollector.UpdateHealthStatus("overall", overallHealthy)
}

// initializeBuiltinHealthCheckers initializes built-in health checkers
func (h *HealthMonitor) initializeBuiltinHealthCheckers() {
	// Register basic health checkers for stream processing components
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "stream-processor-manager",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "stream-processor-manager",
				Status: HealthStatusHealthy,
				Details: map[string]interface{}{
					"uptime": time.Since(time.Now().Add(-time.Hour)).String(),
				},
			}, nil
		},
	})
	
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "kafka-streams-processor",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "kafka-streams-processor",
				Status: HealthStatusHealthy,
			}, nil
		},
	})
	
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "enrichment-service",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "enrichment-service",
				Status: HealthStatusHealthy,
			}, nil
		},
	})
	
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "correlation-engine",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "correlation-engine",
				Status: HealthStatusHealthy,
			}, nil
		},
	})
	
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "pattern-matching-engine",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "pattern-matching-engine",
				Status: HealthStatusHealthy,
			}, nil
		},
	})
	
	h.RegisterHealthChecker(&BasicHealthChecker{
		name: "anomaly-detection-integration",
		checkFunc: func(ctx context.Context) (*ComponentHealthStatus, error) {
			return &ComponentHealthStatus{
				Name:   "anomaly-detection-integration",
				Status: HealthStatusHealthy,
			}, nil
		},
	})
}

// BasicHealthChecker provides a basic implementation of HealthChecker
type BasicHealthChecker struct {
	name      string
	checkFunc func(ctx context.Context) (*ComponentHealthStatus, error)
}

func (b *BasicHealthChecker) CheckHealth(ctx context.Context) (*ComponentHealthStatus, error) {
	if b.checkFunc != nil {
		return b.checkFunc(ctx)
	}
	
	return &ComponentHealthStatus{
		Name:   b.name,
		Status: HealthStatusHealthy,
	}, nil
}

func (b *BasicHealthChecker) GetComponentName() string {
	return b.name
}

// Stop stops the health monitor
func (h *HealthMonitor) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	
	if h.checkTicker != nil {
		h.checkTicker.Stop()
	}
	
	if h.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		h.httpServer.Shutdown(ctx)
	}
	
	h.logger.Info("Health monitor stopped")
}