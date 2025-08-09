package dal

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MonitorManager handles monitoring and observability for the Data Access Layer
type MonitorManager struct {
	config          MonitoringConfig
	logger          *zap.Logger
	metrics         *MetricsCollector
	operationBuffer []OperationMetrics
	bufferMu        sync.RWMutex
	closed          bool
	closeCh         chan struct{}
	wg              sync.WaitGroup
}

// MetricsCollector collects and aggregates metrics
type MetricsCollector struct {
	connectionPoolMetrics map[string]*ConnectionPoolMetrics
	queryMetrics         map[string]*QueryMetrics
	errorMetrics         map[string]*ErrorMetrics
	mu                   sync.RWMutex
}

// ConnectionPoolMetrics represents connection pool metrics for a database
type ConnectionPoolMetrics struct {
	Database        string    `json:"database"`
	ActiveConns     int       `json:"active_connections"`
	IdleConns       int       `json:"idle_connections"`
	MaxConns        int       `json:"max_connections"`
	TotalConns      int       `json:"total_connections"`
	AcquiredConns   int64     `json:"acquired_connections"`
	ReleasedConns   int64     `json:"released_connections"`
	FailedAcquires  int64     `json:"failed_acquires"`
	AcquireTime     time.Duration `json:"acquire_time"`
	LastUpdated     time.Time `json:"last_updated"`
}

// QueryMetrics represents query performance metrics
type QueryMetrics struct {
	Database         string        `json:"database"`
	TotalQueries     int64         `json:"total_queries"`
	SuccessfulQueries int64        `json:"successful_queries"`
	FailedQueries    int64         `json:"failed_queries"`
	AvgDuration      time.Duration `json:"average_duration"`
	MinDuration      time.Duration `json:"min_duration"`
	MaxDuration      time.Duration `json:"max_duration"`
	SlowQueries      int64         `json:"slow_queries"`
	LastUpdated      time.Time     `json:"last_updated"`
}

// ErrorMetrics represents error statistics
type ErrorMetrics struct {
	Database           string            `json:"database"`
	TotalErrors        int64             `json:"total_errors"`
	ErrorsByType       map[string]int64  `json:"errors_by_type"`
	ErrorRate          float64           `json:"error_rate"`
	LastError          string            `json:"last_error"`
	LastErrorTime      time.Time         `json:"last_error_time"`
	CircuitBreakerTrips int64            `json:"circuit_breaker_trips"`
	RetryAttempts      int64             `json:"retry_attempts"`
	LastUpdated        time.Time         `json:"last_updated"`
}

// SystemMetrics represents overall system health metrics
type SystemMetrics struct {
	Timestamp          time.Time                      `json:"timestamp"`
	ConnectionPools    map[string]*ConnectionPoolMetrics `json:"connection_pools"`
	Queries           map[string]*QueryMetrics        `json:"queries"`
	Errors            map[string]*ErrorMetrics        `json:"errors"`
	TotalOperations   int64                          `json:"total_operations"`
	OperationsPerSec  float64                        `json:"operations_per_second"`
	AvgResponseTime   time.Duration                  `json:"average_response_time"`
}

// AlertThreshold defines thresholds for monitoring alerts
type AlertThreshold struct {
	MetricName    string        `json:"metric_name"`
	Database      string        `json:"database"`
	Threshold     float64       `json:"threshold"`
	Operator      string        `json:"operator"` // >, <, >=, <=, ==
	Duration      time.Duration `json:"duration"` // How long threshold must be breached
	Severity      string        `json:"severity"` // critical, warning, info
	Description   string        `json:"description"`
}

// Alert represents a monitoring alert
type Alert struct {
	ID          string    `json:"id"`
	Threshold   AlertThreshold `json:"threshold"`
	TriggeredAt time.Time `json:"triggered_at"`
	CurrentValue float64  `json:"current_value"`
	Message     string    `json:"message"`
	Resolved    bool      `json:"resolved"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

// NewMonitorManager creates a new monitor manager
func NewMonitorManager(config MonitoringConfig, logger *zap.Logger) (*MonitorManager, error) {
	mm := &MonitorManager{
		config:          config,
		logger:          logger,
		operationBuffer: make([]OperationMetrics, 0, 1000),
		closeCh:         make(chan struct{}),
		metrics: &MetricsCollector{
			connectionPoolMetrics: make(map[string]*ConnectionPoolMetrics),
			queryMetrics:         make(map[string]*QueryMetrics),
			errorMetrics:         make(map[string]*ErrorMetrics),
		},
	}

	// Initialize metrics for each database
	databases := []string{"postgresql", "mongodb", "redis", "elasticsearch"}
	for _, db := range databases {
		mm.metrics.connectionPoolMetrics[db] = &ConnectionPoolMetrics{
			Database:    db,
			LastUpdated: time.Now(),
		}
		mm.metrics.queryMetrics[db] = &QueryMetrics{
			Database:    db,
			MinDuration: time.Hour, // Start with a high value
			LastUpdated: time.Now(),
		}
		mm.metrics.errorMetrics[db] = &ErrorMetrics{
			Database:     db,
			ErrorsByType: make(map[string]int64),
			LastUpdated:  time.Now(),
		}
	}

	// Start background processes if monitoring is enabled
	if config.Enabled {
		mm.startBackgroundProcesses()
	}

	logger.Info("Monitor manager initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Duration("metrics_interval", config.MetricsInterval))

	return mm, nil
}

// startBackgroundProcesses starts monitoring background processes
func (mm *MonitorManager) startBackgroundProcesses() {
	// Start metrics aggregation
	mm.wg.Add(1)
	go mm.metricsAggregationLoop()

	// Start buffer flush
	mm.wg.Add(1)
	go mm.bufferFlushLoop()
}

// RecordOperationMetrics records metrics for a database operation
func (mm *MonitorManager) RecordOperationMetrics(metrics OperationMetrics) {
	if !mm.config.Enabled {
		return
	}

	// Add to buffer
	mm.bufferMu.Lock()
	mm.operationBuffer = append(mm.operationBuffer, metrics)
	mm.bufferMu.Unlock()

	// Update query metrics immediately
	mm.updateQueryMetrics(metrics)

	// Update error metrics if there was an error
	if !metrics.Success {
		mm.updateErrorMetrics(metrics)
	}
}

// updateQueryMetrics updates query performance metrics
func (mm *MonitorManager) updateQueryMetrics(op OperationMetrics) {
	mm.metrics.mu.Lock()
	defer mm.metrics.mu.Unlock()

	queryMetrics, exists := mm.metrics.queryMetrics[op.Database]
	if !exists {
		return
	}

	queryMetrics.TotalQueries++
	if op.Success {
		queryMetrics.SuccessfulQueries++
	} else {
		queryMetrics.FailedQueries++
	}

	// Update duration statistics
	if queryMetrics.TotalQueries == 1 {
		queryMetrics.AvgDuration = op.Duration
		queryMetrics.MinDuration = op.Duration
		queryMetrics.MaxDuration = op.Duration
	} else {
		// Calculate running average
		totalDuration := time.Duration(float64(queryMetrics.AvgDuration) * float64(queryMetrics.TotalQueries-1))
		queryMetrics.AvgDuration = (totalDuration + op.Duration) / time.Duration(queryMetrics.TotalQueries)

		if op.Duration < queryMetrics.MinDuration {
			queryMetrics.MinDuration = op.Duration
		}
		if op.Duration > queryMetrics.MaxDuration {
			queryMetrics.MaxDuration = op.Duration
		}
	}

	// Check for slow queries
	if op.Duration > mm.config.SlowQueryThreshold {
		queryMetrics.SlowQueries++
		
		if mm.config.TraceSlowQueries {
			mm.logger.Warn("Slow query detected",
				zap.String("database", op.Database),
				zap.String("operation", op.Operation),
				zap.Duration("duration", op.Duration),
				zap.Int64("records_affected", op.RecordsAffected))
		}
	}

	queryMetrics.LastUpdated = time.Now()
}

// updateErrorMetrics updates error statistics
func (mm *MonitorManager) updateErrorMetrics(op OperationMetrics) {
	mm.metrics.mu.Lock()
	defer mm.metrics.mu.Unlock()

	errorMetrics, exists := mm.metrics.errorMetrics[op.Database]
	if !exists {
		return
	}

	errorMetrics.TotalErrors++
	errorMetrics.LastError = op.Error
	errorMetrics.LastErrorTime = op.Timestamp

	// Categorize error type
	errorType := mm.categorizeError(op.Error)
	errorMetrics.ErrorsByType[errorType]++

	// Update retry attempts
	if op.RetryCount > 0 {
		errorMetrics.RetryAttempts += int64(op.RetryCount)
	}

	// Calculate error rate
	queryMetrics := mm.metrics.queryMetrics[op.Database]
	if queryMetrics.TotalQueries > 0 {
		errorMetrics.ErrorRate = float64(errorMetrics.TotalErrors) / float64(queryMetrics.TotalQueries)
	}

	errorMetrics.LastUpdated = time.Now()
}

// categorizeError categorizes an error into a type
func (mm *MonitorManager) categorizeError(errorMsg string) string {
	errorLower := strings.ToLower(errorMsg)
	
	switch {
	case contains(errorLower, "connection"):
		return "connection"
	case contains(errorLower, "timeout"):
		return "timeout"
	case contains(errorLower, "authentication"):
		return "authentication"
	case contains(errorLower, "authorization"):
		return "authorization"
	case contains(errorLower, "syntax"):
		return "syntax"
	case contains(errorLower, "deadlock"):
		return "deadlock"
	case contains(errorLower, "constraint"):
		return "constraint"
	case contains(errorLower, "network"):
		return "network"
	default:
		return "unknown"
	}
}

// RecordConnectionPoolMetrics records connection pool metrics
func (mm *MonitorManager) RecordConnectionPoolMetrics(database string, active, idle, max, total int, acquired, released, failed int64, acquireTime time.Duration) {
	if !mm.config.Enabled || !mm.config.ConnectionPoolMetrics {
		return
	}

	mm.metrics.mu.Lock()
	defer mm.metrics.mu.Unlock()

	poolMetrics, exists := mm.metrics.connectionPoolMetrics[database]
	if !exists {
		return
	}

	poolMetrics.ActiveConns = active
	poolMetrics.IdleConns = idle
	poolMetrics.MaxConns = max
	poolMetrics.TotalConns = total
	poolMetrics.AcquiredConns = acquired
	poolMetrics.ReleasedConns = released
	poolMetrics.FailedAcquires = failed
	poolMetrics.AcquireTime = acquireTime
	poolMetrics.LastUpdated = time.Now()
}

// GetSystemMetrics returns current system metrics
func (mm *MonitorManager) GetSystemMetrics() *SystemMetrics {
	mm.metrics.mu.RLock()
	defer mm.metrics.mu.RUnlock()

	// Deep copy metrics to avoid race conditions
	connectionPools := make(map[string]*ConnectionPoolMetrics)
	for k, v := range mm.metrics.connectionPoolMetrics {
		connectionPools[k] = &ConnectionPoolMetrics{
			Database:       v.Database,
			ActiveConns:    v.ActiveConns,
			IdleConns:      v.IdleConns,
			MaxConns:       v.MaxConns,
			TotalConns:     v.TotalConns,
			AcquiredConns:  v.AcquiredConns,
			ReleasedConns:  v.ReleasedConns,
			FailedAcquires: v.FailedAcquires,
			AcquireTime:    v.AcquireTime,
			LastUpdated:    v.LastUpdated,
		}
	}

	queries := make(map[string]*QueryMetrics)
	for k, v := range mm.metrics.queryMetrics {
		queries[k] = &QueryMetrics{
			Database:          v.Database,
			TotalQueries:      v.TotalQueries,
			SuccessfulQueries: v.SuccessfulQueries,
			FailedQueries:     v.FailedQueries,
			AvgDuration:       v.AvgDuration,
			MinDuration:       v.MinDuration,
			MaxDuration:       v.MaxDuration,
			SlowQueries:       v.SlowQueries,
			LastUpdated:       v.LastUpdated,
		}
	}

	errors := make(map[string]*ErrorMetrics)
	for k, v := range mm.metrics.errorMetrics {
		errorsByType := make(map[string]int64)
		for ek, ev := range v.ErrorsByType {
			errorsByType[ek] = ev
		}
		errors[k] = &ErrorMetrics{
			Database:            v.Database,
			TotalErrors:         v.TotalErrors,
			ErrorsByType:        errorsByType,
			ErrorRate:           v.ErrorRate,
			LastError:           v.LastError,
			LastErrorTime:       v.LastErrorTime,
			CircuitBreakerTrips: v.CircuitBreakerTrips,
			RetryAttempts:       v.RetryAttempts,
			LastUpdated:         v.LastUpdated,
		}
	}

	// Calculate aggregate metrics
	var totalOperations int64
	var totalDuration time.Duration
	for _, q := range queries {
		totalOperations += q.TotalQueries
		totalDuration += time.Duration(float64(q.AvgDuration) * float64(q.TotalQueries))
	}

	var avgResponseTime time.Duration
	if totalOperations > 0 {
		avgResponseTime = totalDuration / time.Duration(totalOperations)
	}

	return &SystemMetrics{
		Timestamp:       time.Now(),
		ConnectionPools: connectionPools,
		Queries:         queries,
		Errors:          errors,
		TotalOperations: totalOperations,
		AvgResponseTime: avgResponseTime,
	}
}

// GetDatabaseMetrics returns metrics for a specific database
func (mm *MonitorManager) GetDatabaseMetrics(database string) map[string]interface{} {
	mm.metrics.mu.RLock()
	defer mm.metrics.mu.RUnlock()

	metrics := make(map[string]interface{})

	if poolMetrics, exists := mm.metrics.connectionPoolMetrics[database]; exists {
		metrics["connection_pool"] = poolMetrics
	}

	if queryMetrics, exists := mm.metrics.queryMetrics[database]; exists {
		metrics["queries"] = queryMetrics
	}

	if errorMetrics, exists := mm.metrics.errorMetrics[database]; exists {
		metrics["errors"] = errorMetrics
	}

	return metrics
}

// CollectMetrics performs metrics collection
func (mm *MonitorManager) CollectMetrics() {
	if !mm.config.Enabled {
		return
	}

	// This method can be called to trigger metrics collection
	// In a production system, this might push metrics to external systems
	systemMetrics := mm.GetSystemMetrics()

	mm.logger.Debug("Metrics collected",
		zap.Int64("total_operations", systemMetrics.TotalOperations),
		zap.Duration("avg_response_time", systemMetrics.AvgResponseTime))

	// TODO: Push metrics to monitoring systems (Prometheus, DataDog, etc.)
}

// metricsAggregationLoop runs metrics aggregation in the background
func (mm *MonitorManager) metricsAggregationLoop() {
	defer mm.wg.Done()

	ticker := time.NewTicker(mm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.CollectMetrics()
		case <-mm.closeCh:
			return
		}
	}
}

// bufferFlushLoop flushes the operation buffer periodically
func (mm *MonitorManager) bufferFlushLoop() {
	defer mm.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mm.flushBuffer()
		case <-mm.closeCh:
			mm.flushBuffer() // Final flush
			return
		}
	}
}

// flushBuffer processes buffered operations
func (mm *MonitorManager) flushBuffer() {
	mm.bufferMu.Lock()
	if len(mm.operationBuffer) == 0 {
		mm.bufferMu.Unlock()
		return
	}

	// Copy buffer and clear it
	operations := make([]OperationMetrics, len(mm.operationBuffer))
	copy(operations, mm.operationBuffer)
	mm.operationBuffer = mm.operationBuffer[:0]
	mm.bufferMu.Unlock()

	// Process operations
	mm.logger.Debug("Flushing operation buffer",
		zap.Int("operations", len(operations)))

	// TODO: Send operations to external analytics systems
}

// RecordCircuitBreakerTrip records a circuit breaker trip
func (mm *MonitorManager) RecordCircuitBreakerTrip(database string) {
	if !mm.config.Enabled {
		return
	}

	mm.metrics.mu.Lock()
	defer mm.metrics.mu.Unlock()

	if errorMetrics, exists := mm.metrics.errorMetrics[database]; exists {
		errorMetrics.CircuitBreakerTrips++
		errorMetrics.LastUpdated = time.Now()
	}

	mm.logger.Warn("Circuit breaker tripped",
		zap.String("database", database))
}

// IsHealthy returns whether the system is healthy based on metrics
func (mm *MonitorManager) IsHealthy() bool {
	if !mm.config.Enabled {
		return true // Assume healthy if monitoring is disabled
	}

	systemMetrics := mm.GetSystemMetrics()

	// Check error rates
	for database, errorMetrics := range systemMetrics.Errors {
		if errorMetrics.ErrorRate > 0.1 { // 10% error rate threshold
			mm.logger.Warn("High error rate detected",
				zap.String("database", database),
				zap.Float64("error_rate", errorMetrics.ErrorRate))
			return false
		}
	}

	// Check response times
	if systemMetrics.AvgResponseTime > 10*time.Second {
		mm.logger.Warn("High response time detected",
			zap.Duration("avg_response_time", systemMetrics.AvgResponseTime))
		return false
	}

	return true
}

// GetHealthStatus returns detailed health status
func (mm *MonitorManager) GetHealthStatus() map[string]interface{} {
	status := map[string]interface{}{
		"healthy":   mm.IsHealthy(),
		"timestamp": time.Now(),
	}

	if mm.config.Enabled {
		systemMetrics := mm.GetSystemMetrics()
		status["metrics"] = systemMetrics
	}

	return status
}

// Close closes the monitor manager
func (mm *MonitorManager) Close() error {
	if mm.closed {
		return nil
	}

	mm.closed = true
	close(mm.closeCh)

	// Wait for background processes to finish
	mm.wg.Wait()

	mm.logger.Info("Monitor manager closed")
	return nil
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		 findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}