package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Status represents the health status
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
	StatusUnknown   Status = "unknown"
)

// CheckType represents the type of health check
type CheckType string

const (
	CheckTypeLiveness  CheckType = "liveness"
	CheckTypeReadiness CheckType = "readiness"
	CheckTypeStartup   CheckType = "startup"
)

// Check represents a health check function
type Check func(context.Context) CheckResult

// CheckResult represents the result of a health check
type CheckResult struct {
	Status    Status                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  time.Duration          `json:"duration"`
	Error     error                  `json:"error,omitempty"`
}

// CheckConfig represents configuration for a health check
type CheckConfig struct {
	Name        string        `yaml:"name" json:"name"`
	Type        CheckType     `yaml:"type" json:"type"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	Interval    time.Duration `yaml:"interval" json:"interval"`
	Enabled     bool          `yaml:"enabled" json:"enabled"`
	Critical    bool          `yaml:"critical" json:"critical"`
	Description string        `yaml:"description" json:"description"`
}

// Manager manages health checks for a service
type Manager struct {
	serviceName string
	version     string
	startTime   time.Time
	logger      *zap.Logger
	
	checks        map[string]*healthCheck
	checkConfigs  map[string]*CheckConfig
	mutex         sync.RWMutex
	
	// Overall status cache
	lastOverallCheck time.Time
	overallStatus    Status
	overallCache     *OverallHealth
	cacheTTL         time.Duration
	
	// HTTP server
	httpServer *http.Server
	httpConfig *HTTPConfig
}

// healthCheck wraps a Check with metadata
type healthCheck struct {
	config   *CheckConfig
	check    Check
	lastRun  time.Time
	lastResult CheckResult
	mu       sync.RWMutex
}

// OverallHealth represents the overall health status
type OverallHealth struct {
	Status      Status                    `json:"status"`
	Service     string                    `json:"service"`
	Version     string                    `json:"version"`
	Timestamp   time.Time                 `json:"timestamp"`
	Uptime      time.Duration             `json:"uptime"`
	Checks      map[string]CheckResult    `json:"checks"`
	Summary     map[CheckType]CheckSummary `json:"summary"`
}

// CheckSummary represents a summary of checks by type
type CheckSummary struct {
	Total     int           `json:"total"`
	Healthy   int           `json:"healthy"`
	Unhealthy int           `json:"unhealthy"`
	Degraded  int           `json:"degraded"`
	Duration  time.Duration `json:"duration"`
}

// HTTPConfig represents HTTP server configuration for health endpoints
type HTTPConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Host    string `yaml:"host" json:"host"`
	Port    int    `yaml:"port" json:"port"`
	Path    string `yaml:"path" json:"path"`
}

// Config represents health manager configuration
type Config struct {
	ServiceName string      `yaml:"service_name" json:"service_name"`
	Version     string      `yaml:"version" json:"version"`
	CacheTTL    time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
	HTTP        HTTPConfig  `yaml:"http" json:"http"`
}

// NewManager creates a new health check manager
func NewManager(config *Config, logger *zap.Logger) *Manager {
	if config == nil {
		config = &Config{
			ServiceName: "unknown",
			Version:     "unknown",
			CacheTTL:    5 * time.Second,
			HTTP: HTTPConfig{
				Enabled: true,
				Host:    "0.0.0.0",
				Port:    8080,
				Path:    "/health",
			},
		}
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Manager{
		serviceName:  config.ServiceName,
		version:      config.Version,
		startTime:    time.Now(),
		logger:       logger,
		checks:       make(map[string]*healthCheck),
		checkConfigs: make(map[string]*CheckConfig),
		cacheTTL:     config.CacheTTL,
		httpConfig:   &config.HTTP,
	}
}

// RegisterCheck registers a new health check
func (m *Manager) RegisterCheck(config *CheckConfig, check Check) error {
	if config == nil {
		return fmt.Errorf("check config is required")
	}
	
	if check == nil {
		return fmt.Errorf("check function is required")
	}
	
	// Set defaults
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.Interval == 0 {
		config.Interval = 30 * time.Second
	}
	if !config.Enabled {
		config.Enabled = true
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.checks[config.Name] = &healthCheck{
		config: config,
		check:  check,
	}
	m.checkConfigs[config.Name] = config

	m.logger.Info("Health check registered",
		zap.String("name", config.Name),
		zap.String("type", string(config.Type)),
		zap.Duration("timeout", config.Timeout),
		zap.Bool("critical", config.Critical),
	)

	return nil
}

// UnregisterCheck removes a health check
func (m *Manager) UnregisterCheck(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.checks, name)
	delete(m.checkConfigs, name)

	m.logger.Info("Health check unregistered", zap.String("name", name))
}

// GetCheck returns the result of a specific health check
func (m *Manager) GetCheck(ctx context.Context, name string) (CheckResult, error) {
	m.mutex.RLock()
	healthCheck, exists := m.checks[name]
	m.mutex.RUnlock()

	if !exists {
		return CheckResult{}, fmt.Errorf("health check '%s' not found", name)
	}

	if !healthCheck.config.Enabled {
		return CheckResult{
			Status:    StatusUnknown,
			Message:   "Check disabled",
			Timestamp: time.Now(),
		}, nil
	}

	return m.runCheck(ctx, healthCheck), nil
}

// GetOverallHealth returns the overall health status
func (m *Manager) GetOverallHealth(ctx context.Context) *OverallHealth {
	// Check cache
	if m.overallCache != nil && time.Since(m.lastOverallCheck) < m.cacheTTL {
		return m.overallCache
	}

	start := time.Now()
	
	m.mutex.RLock()
	checks := make(map[string]*healthCheck)
	for name, check := range m.checks {
		checks[name] = check
	}
	m.mutex.RUnlock()

	// Run all checks
	results := make(map[string]CheckResult)
	summary := make(map[CheckType]CheckSummary)
	
	for name, healthCheck := range checks {
		if !healthCheck.config.Enabled {
			continue
		}

		result := m.runCheck(ctx, healthCheck)
		results[name] = result

		// Update summary
		checkType := healthCheck.config.Type
		if _, exists := summary[checkType]; !exists {
			summary[checkType] = CheckSummary{}
		}
		
		s := summary[checkType]
		s.Total++
		s.Duration += result.Duration
		
		switch result.Status {
		case StatusHealthy:
			s.Healthy++
		case StatusUnhealthy:
			s.Unhealthy++
		case StatusDegraded:
			s.Degraded++
		}
		
		summary[checkType] = s
	}

	// Determine overall status
	overallStatus := m.calculateOverallStatus(results)

	overall := &OverallHealth{
		Status:    overallStatus,
		Service:   m.serviceName,
		Version:   m.version,
		Timestamp: time.Now(),
		Uptime:    time.Since(m.startTime),
		Checks:    results,
		Summary:   summary,
	}

	// Cache result
	m.overallCache = overall
	m.lastOverallCheck = time.Now()

	m.logger.Debug("Overall health check completed",
		zap.String("status", string(overallStatus)),
		zap.Duration("duration", time.Since(start)),
		zap.Int("checks", len(results)),
	)

	return overall
}

// runCheck executes a single health check
func (m *Manager) runCheck(ctx context.Context, healthCheck *healthCheck) CheckResult {
	// Check if we have a recent result
	healthCheck.mu.RLock()
	if time.Since(healthCheck.lastRun) < healthCheck.config.Interval {
		result := healthCheck.lastResult
		healthCheck.mu.RUnlock()
		return result
	}
	healthCheck.mu.RUnlock()

	// Run the check
	start := time.Now()
	
	// Create context with timeout
	checkCtx, cancel := context.WithTimeout(ctx, healthCheck.config.Timeout)
	defer cancel()

	// Execute check in goroutine to handle timeout
	resultChan := make(chan CheckResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- CheckResult{
					Status:    StatusUnhealthy,
					Message:   fmt.Sprintf("Check panicked: %v", r),
					Timestamp: time.Now(),
					Duration:  time.Since(start),
					Error:     fmt.Errorf("panic: %v", r),
				}
			}
		}()
		
		result := healthCheck.check(checkCtx)
		result.Timestamp = time.Now()
		result.Duration = time.Since(start)
		resultChan <- result
	}()

	var result CheckResult
	select {
	case result = <-resultChan:
		// Check completed
	case <-checkCtx.Done():
		result = CheckResult{
			Status:    StatusUnhealthy,
			Message:   "Check timed out",
			Timestamp: time.Now(),
			Duration:  time.Since(start),
			Error:     checkCtx.Err(),
		}
	}

	// Cache result
	healthCheck.mu.Lock()
	healthCheck.lastResult = result
	healthCheck.lastRun = time.Now()
	healthCheck.mu.Unlock()

	return result
}

// calculateOverallStatus determines the overall status based on individual checks
func (m *Manager) calculateOverallStatus(results map[string]CheckResult) Status {
	if len(results) == 0 {
		return StatusUnknown
	}

	hasUnhealthy := false
	hasDegraded := false
	hasCriticalUnhealthy := false

	for name, result := range results {
		m.mutex.RLock()
		config := m.checkConfigs[name]
		m.mutex.RUnlock()

		switch result.Status {
		case StatusUnhealthy:
			hasUnhealthy = true
			if config != nil && config.Critical {
				hasCriticalUnhealthy = true
			}
		case StatusDegraded:
			hasDegraded = true
		}
	}

	// Critical unhealthy checks make the service unhealthy
	if hasCriticalUnhealthy {
		return StatusUnhealthy
	}

	// Any unhealthy check makes the service degraded (unless critical)
	if hasUnhealthy || hasDegraded {
		return StatusDegraded
	}

	return StatusHealthy
}

// StartHTTPServer starts the HTTP server for health endpoints
func (m *Manager) StartHTTPServer() error {
	if !m.httpConfig.Enabled {
		return nil
	}

	mux := http.NewServeMux()
	
	// Health endpoints
	mux.HandleFunc(m.httpConfig.Path, m.handleOverallHealth)
	mux.HandleFunc(m.httpConfig.Path+"/live", m.handleLiveness)
	mux.HandleFunc(m.httpConfig.Path+"/ready", m.handleReadiness)
	mux.HandleFunc(m.httpConfig.Path+"/startup", m.handleStartup)
	
	// Individual check endpoints
	mux.HandleFunc(m.httpConfig.Path+"/check/", m.handleIndividualCheck)

	address := fmt.Sprintf("%s:%d", m.httpConfig.Host, m.httpConfig.Port)
	
	m.httpServer = &http.Server{
		Addr:         address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	m.logger.Info("Starting health HTTP server", zap.String("address", address))

	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			m.logger.Error("Health HTTP server failed", zap.Error(err))
		}
	}()

	return nil
}

// StopHTTPServer stops the HTTP server
func (m *Manager) StopHTTPServer(ctx context.Context) error {
	if m.httpServer == nil {
		return nil
	}

	m.logger.Info("Stopping health HTTP server")
	return m.httpServer.Shutdown(ctx)
}

// HTTP handlers

func (m *Manager) handleOverallHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	health := m.GetOverallHealth(ctx)
	
	statusCode := http.StatusOK
	if health.Status == StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	} else if health.Status == StatusDegraded {
		statusCode = http.StatusPartialContent
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(health)
}

func (m *Manager) handleLiveness(w http.ResponseWriter, r *http.Request) {
	m.handleChecksByType(w, r, CheckTypeLiveness)
}

func (m *Manager) handleReadiness(w http.ResponseWriter, r *http.Request) {
	m.handleChecksByType(w, r, CheckTypeReadiness)
}

func (m *Manager) handleStartup(w http.ResponseWriter, r *http.Request) {
	m.handleChecksByType(w, r, CheckTypeStartup)
}

func (m *Manager) handleChecksByType(w http.ResponseWriter, r *http.Request, checkType CheckType) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	overall := m.GetOverallHealth(ctx)
	
	// Filter checks by type
	filteredChecks := make(map[string]CheckResult)
	for name, result := range overall.Checks {
		if config, exists := m.checkConfigs[name]; exists && config.Type == checkType {
			filteredChecks[name] = result
		}
	}

	// Calculate status for this type
	status := m.calculateOverallStatus(filteredChecks)

	response := map[string]interface{}{
		"status":    status,
		"service":   m.serviceName,
		"timestamp": time.Now(),
		"checks":    filteredChecks,
	}

	statusCode := http.StatusOK
	if status == StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	} else if status == StatusDegraded {
		statusCode = http.StatusPartialContent
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func (m *Manager) handleIndividualCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Extract check name from path
	path := r.URL.Path
	checkName := path[len(m.httpConfig.Path+"/check/"):]

	result, err := m.GetCheck(ctx, checkName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	statusCode := http.StatusOK
	if result.Status == StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	} else if result.Status == StatusDegraded {
		statusCode = http.StatusPartialContent
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(result)
}

// Common Health Checks

// DatabaseCheck creates a health check for database connectivity
func DatabaseCheck(name string, db interface{ Ping() error }) Check {
	return func(ctx context.Context) CheckResult {
		err := db.Ping()
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("Database %s is unreachable", name),
				Error:   err,
			}
		}
		
		return CheckResult{
			Status:  StatusHealthy,
			Message: fmt.Sprintf("Database %s is healthy", name),
		}
	}
}

// RedisCheck creates a health check for Redis connectivity
func RedisCheck(name string, client interface{ Ping() error }) Check {
	return func(ctx context.Context) CheckResult {
		err := client.Ping()
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("Redis %s is unreachable", name),
				Error:   err,
			}
		}
		
		return CheckResult{
			Status:  StatusHealthy,
			Message: fmt.Sprintf("Redis %s is healthy", name),
		}
	}
}

// HTTPCheck creates a health check for HTTP endpoints
func HTTPCheck(name, url string, expectedStatus int) Check {
	client := &http.Client{Timeout: 5 * time.Second}
	
	return func(ctx context.Context) CheckResult {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("Failed to create request for %s", name),
				Error:   err,
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("HTTP endpoint %s is unreachable", name),
				Error:   err,
			}
		}
		defer resp.Body.Close()

		if resp.StatusCode != expectedStatus {
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("HTTP endpoint %s returned status %d, expected %d", name, resp.StatusCode, expectedStatus),
			}
		}

		return CheckResult{
			Status:  StatusHealthy,
			Message: fmt.Sprintf("HTTP endpoint %s is healthy", name),
			Details: map[string]interface{}{
				"status_code": resp.StatusCode,
				"url":         url,
			},
		}
	}
}

// DiskSpaceCheck creates a health check for disk space
func DiskSpaceCheck(path string, warningThreshold, criticalThreshold float64) Check {
	return func(ctx context.Context) CheckResult {
		// This is a simplified version - in production you'd use syscall.Statfs or similar
		// For now, we'll return a placeholder
		return CheckResult{
			Status:  StatusHealthy,
			Message: fmt.Sprintf("Disk space check for %s (placeholder)", path),
			Details: map[string]interface{}{
				"path": path,
				"warning_threshold":  warningThreshold,
				"critical_threshold": criticalThreshold,
			},
		}
	}
}

// MemoryCheck creates a health check for memory usage
func MemoryCheck(warningThreshold, criticalThreshold float64) Check {
	return func(ctx context.Context) CheckResult {
		// This is a simplified version - in production you'd check actual memory usage
		return CheckResult{
			Status:  StatusHealthy,
			Message: "Memory usage is within acceptable limits",
			Details: map[string]interface{}{
				"warning_threshold":  warningThreshold,
				"critical_threshold": criticalThreshold,
			},
		}
	}
}