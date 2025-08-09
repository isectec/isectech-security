package service

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// HealthChecker interface for health checking
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) error
}

// HealthManager manages health checks for various components
type HealthManager struct {
	checkers []HealthChecker
	logger   *zap.Logger
	interval time.Duration
	timeout  time.Duration
	mu       sync.RWMutex
	status   map[string]HealthStatus
	overall  OverallHealthStatus
}

// HealthStatus represents the status of a component
type HealthStatus struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"`
	LastCheck time.Time `json:"last_check"`
	Duration  string    `json:"duration"`
}

// OverallHealthStatus represents the overall system health
type OverallHealthStatus struct {
	Status       string                   `json:"status"`
	Components   map[string]HealthStatus  `json:"components"`
	LastUpdated  time.Time               `json:"last_updated"`
	Version      string                  `json:"version"`
	Environment  string                  `json:"environment"`
}

// NewHealthManager creates a new health manager
func NewHealthManager(logger *zap.Logger, interval, timeout time.Duration) *HealthManager {
	return &HealthManager{
		checkers: make([]HealthChecker, 0),
		logger:   logger,
		interval: interval,
		timeout:  timeout,
		status:   make(map[string]HealthStatus),
		overall: OverallHealthStatus{
			Components: make(map[string]HealthStatus),
		},
	}
}

// RegisterChecker registers a health checker
func (hm *HealthManager) RegisterChecker(checker HealthChecker) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.checkers = append(hm.checkers, checker)
	hm.status[checker.Name()] = HealthStatus{
		Name:      checker.Name(),
		Status:    "unknown",
		LastCheck: time.Time{},
	}
}

// Start starts the health monitoring
func (hm *HealthManager) Start(ctx context.Context) {
	ticker := time.NewTicker(hm.interval)
	defer ticker.Stop()

	// Initial health check
	hm.runHealthChecks(ctx)

	for {
		select {
		case <-ctx.Done():
			hm.logger.Info("Health manager stopping")
			return
		case <-ticker.C:
			hm.runHealthChecks(ctx)
		}
	}
}

// runHealthChecks runs all registered health checks
func (hm *HealthManager) runHealthChecks(ctx context.Context) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	overallHealthy := true
	
	for _, checker := range hm.checkers {
		status := hm.checkComponent(ctx, checker)
		hm.status[checker.Name()] = status
		hm.overall.Components[checker.Name()] = status
		
		if status.Status != "healthy" {
			overallHealthy = false
		}
	}

	// Update overall status
	if overallHealthy {
		hm.overall.Status = "healthy"
	} else {
		hm.overall.Status = "unhealthy"
	}
	hm.overall.LastUpdated = time.Now()
}

// checkComponent checks a single component
func (hm *HealthManager) checkComponent(ctx context.Context, checker HealthChecker) HealthStatus {
	start := time.Now()
	
	// Create context with timeout for the check
	checkCtx, cancel := context.WithTimeout(ctx, hm.timeout)
	defer cancel()

	status := HealthStatus{
		Name:      checker.Name(),
		LastCheck: start,
	}

	err := checker.Check(checkCtx)
	duration := time.Since(start)
	status.Duration = duration.String()

	if err != nil {
		status.Status = "unhealthy"
		status.Message = err.Error()
		hm.logger.Warn("Health check failed",
			zap.String("component", checker.Name()),
			zap.Error(err),
			zap.Duration("duration", duration),
		)
	} else {
		status.Status = "healthy"
		hm.logger.Debug("Health check passed",
			zap.String("component", checker.Name()),
			zap.Duration("duration", duration),
		)
	}

	return status
}

// GetOverallHealth returns the overall health status
func (hm *HealthManager) GetOverallHealth() OverallHealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	// Deep copy to avoid race conditions
	result := OverallHealthStatus{
		Status:      hm.overall.Status,
		Components:  make(map[string]HealthStatus),
		LastUpdated: hm.overall.LastUpdated,
		Version:     hm.overall.Version,
		Environment: hm.overall.Environment,
	}
	
	for name, status := range hm.overall.Components {
		result.Components[name] = status
	}
	
	return result
}

// GetComponentHealth returns the health status of a specific component
func (hm *HealthManager) GetComponentHealth(name string) (HealthStatus, bool) {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	status, exists := hm.status[name]
	return status, exists
}

// IsHealthy returns true if the overall system is healthy
func (hm *HealthManager) IsHealthy() bool {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	
	return hm.overall.Status == "healthy"
}

// SetVersion sets the version information
func (hm *HealthManager) SetVersion(version string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.overall.Version = version
}

// SetEnvironment sets the environment information
func (hm *HealthManager) SetEnvironment(environment string) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	hm.overall.Environment = environment
}

// DatabaseHealthChecker checks database health
type DatabaseHealthChecker struct {
	name string
	db   DatabaseHealth
}

// DatabaseHealth interface for database health checking
type DatabaseHealth interface {
	Ping(ctx context.Context) error
}

// NewDatabaseHealthChecker creates a new database health checker
func NewDatabaseHealthChecker(name string, db DatabaseHealth) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{
		name: name,
		db:   db,
	}
}

// Name returns the checker name
func (d *DatabaseHealthChecker) Name() string {
	return d.name
}

// Check performs the health check
func (d *DatabaseHealthChecker) Check(ctx context.Context) error {
	return d.db.Ping(ctx)
}

// CacheHealthChecker checks cache health
type CacheHealthChecker struct {
	name  string
	cache CacheHealth
}

// CacheHealth interface for cache health checking
type CacheHealth interface {
	Ping(ctx context.Context) error
}

// NewCacheHealthChecker creates a new cache health checker
func NewCacheHealthChecker(name string, cache CacheHealth) *CacheHealthChecker {
	return &CacheHealthChecker{
		name:  name,
		cache: cache,
	}
}

// Name returns the checker name
func (c *CacheHealthChecker) Name() string {
	return c.name
}

// Check performs the health check
func (c *CacheHealthChecker) Check(ctx context.Context) error {
	return c.cache.Ping(ctx)
}

// ExternalServiceHealthChecker checks external service health
type ExternalServiceHealthChecker struct {
	name    string
	service ExternalServiceHealth
}

// ExternalServiceHealth interface for external service health checking
type ExternalServiceHealth interface {
	HealthCheck(ctx context.Context) error
}

// NewExternalServiceHealthChecker creates a new external service health checker
func NewExternalServiceHealthChecker(name string, service ExternalServiceHealth) *ExternalServiceHealthChecker {
	return &ExternalServiceHealthChecker{
		name:    name,
		service: service,
	}
}

// Name returns the checker name
func (e *ExternalServiceHealthChecker) Name() string {
	return e.name
}

// Check performs the health check
func (e *ExternalServiceHealthChecker) Check(ctx context.Context) error {
	return e.service.HealthCheck(ctx)
}

// CustomHealthChecker allows for custom health checks
type CustomHealthChecker struct {
	name     string
	checkFn  func(ctx context.Context) error
}

// NewCustomHealthChecker creates a new custom health checker
func NewCustomHealthChecker(name string, checkFn func(ctx context.Context) error) *CustomHealthChecker {
	return &CustomHealthChecker{
		name:    name,
		checkFn: checkFn,
	}
}

// Name returns the checker name
func (c *CustomHealthChecker) Name() string {
	return c.name
}

// Check performs the health check
func (c *CustomHealthChecker) Check(ctx context.Context) error {
	return c.checkFn(ctx)
}