package integration

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IntegrationMetrics collects and manages integration operation metrics
type IntegrationMetrics struct {
	logger *zap.Logger
	
	// Metrics data
	data *IntegrationMetricsData
	mu   sync.RWMutex
	
	// Event metrics
	eventMetrics *EventMetricsData
	
	// Sync metrics
	syncMetrics *SyncMetricsData
	
	// Consistency metrics
	consistencyMetrics *ConsistencyMetricsData
	
	// Performance metrics
	performanceMetrics *PerformanceMetricsData
}

// IntegrationMetricsData contains all integration metrics
type IntegrationMetricsData struct {
	// Overall statistics
	TotalOperations      int64                    `json:"total_operations"`
	SuccessfulOperations int64                    `json:"successful_operations"`
	FailedOperations     int64                    `json:"failed_operations"`
	
	// Event metrics
	EventsPublished      int64                    `json:"events_published"`
	EventsProcessed      int64                    `json:"events_processed"`
	EventsFailures       int64                    `json:"events_failures"`
	
	// Sync metrics
	SyncsCompleted       int64                    `json:"syncs_completed"`
	SyncsFailed          int64                    `json:"syncs_failed"`
	RecordsSynced        int64                    `json:"records_synced"`
	
	// Consistency metrics
	ConsistencyChecks    int64                    `json:"consistency_checks"`
	InconsistenciesFound int64                    `json:"inconsistencies_found"`
	AutoRepairsExecuted  int64                    `json:"auto_repairs_executed"`
	
	// Performance metrics
	AverageLatency       time.Duration            `json:"average_latency"`
	P95Latency           time.Duration            `json:"p95_latency"`
	P99Latency           time.Duration            `json:"p99_latency"`
	ThroughputOpsPerSec  float64                  `json:"throughput_ops_per_sec"`
	
	// Database-specific metrics
	DatabaseMetrics      map[string]*DatabaseIntegrationMetrics `json:"database_metrics"`
	
	// Error analytics
	ErrorsByType         map[string]int64         `json:"errors_by_type"`
	ErrorsByDatabase     map[string]int64         `json:"errors_by_database"`
	
	// Last update
	LastUpdate           time.Time                `json:"last_update"`
}

// EventMetricsData contains event system metrics
type EventMetricsData struct {
	EventsPublishedTotal     int64                    `json:"events_published_total"`
	EventsProcessedTotal     int64                    `json:"events_processed_total"`
	EventsFailedTotal        int64                    `json:"events_failed_total"`
	EventsDuplicateTotal     int64                    `json:"events_duplicate_total"`
	EventsByType             map[string]int64         `json:"events_by_type"`
	EventsBySource           map[string]int64         `json:"events_by_source"`
	EventsByTarget           map[string]int64         `json:"events_by_target"`
	EventProcessingLatency   map[string]time.Duration `json:"event_processing_latency"`
	DeadLetterQueueSize      int64                    `json:"dead_letter_queue_size"`
	EventHandlerPerformance  map[string]*HandlerMetrics `json:"event_handler_performance"`
}

// HandlerMetrics contains metrics for individual event handlers
type HandlerMetrics struct {
	HandlerName         string        `json:"handler_name"`
	EventsProcessed     int64         `json:"events_processed"`
	EventsFailed        int64         `json:"events_failed"`
	AverageLatency      time.Duration `json:"average_latency"`
	LastProcessedAt     time.Time     `json:"last_processed_at"`
	SuccessRate         float64       `json:"success_rate"`
}

// SyncMetricsData contains synchronization metrics
type SyncMetricsData struct {
	SyncOperationsTotal      int64                        `json:"sync_operations_total"`
	SyncOperationsSuccessful int64                        `json:"sync_operations_successful"`
	SyncOperationsFailed     int64                        `json:"sync_operations_failed"`
	RecordsSyncedTotal       int64                        `json:"records_synced_total"`
	SyncLatency              map[string]time.Duration     `json:"sync_latency"`
	SyncsByType              map[string]int64             `json:"syncs_by_type"`
	SyncsByDatabase          map[string]int64             `json:"syncs_by_database"`
	ConflictsDetected        int64                        `json:"conflicts_detected"`
	ConflictsResolved        int64                        `json:"conflicts_resolved"`
	SyncRulePerformance      map[string]*SyncRuleMetrics  `json:"sync_rule_performance"`
}

// SyncRuleMetrics contains metrics for individual sync rules
type SyncRuleMetrics struct {
	RuleName            string        `json:"rule_name"`
	ExecutionCount      int64         `json:"execution_count"`
	SuccessCount        int64         `json:"success_count"`
	FailureCount        int64         `json:"failure_count"`
	RecordsSynced       int64         `json:"records_synced"`
	AverageLatency      time.Duration `json:"average_latency"`
	LastExecutedAt      time.Time     `json:"last_executed_at"`
	SuccessRate         float64       `json:"success_rate"`
}

// ConsistencyMetricsData contains consistency checking metrics
type ConsistencyMetricsData struct {
	ConsistencyChecksTotal   int64                            `json:"consistency_checks_total"`
	InconsistenciesFound     int64                            `json:"inconsistencies_found"`
	ConsistencyRate          float64                          `json:"consistency_rate"`
	AutoRepairsAttempted     int64                            `json:"auto_repairs_attempted"`
	AutoRepairsSuccessful    int64                            `json:"auto_repairs_successful"`
	AutoRepairsFailed        int64                            `json:"auto_repairs_failed"`
	ChecksumValidations      int64                            `json:"checksum_validations"`
	ChecksumMismatches       int64                            `json:"checksum_mismatches"`
	ValidationRuleResults    map[string]*ValidationRuleMetrics `json:"validation_rule_results"`
	InconsistenciesByType    map[string]int64                 `json:"inconsistencies_by_type"`
	InconsistenciesBySeverity map[string]int64                `json:"inconsistencies_by_severity"`
}

// ValidationRuleMetrics contains metrics for validation rules
type ValidationRuleMetrics struct {
	RuleName        string        `json:"rule_name"`
	ExecutionCount  int64         `json:"execution_count"`
	ViolationCount  int64         `json:"violation_count"`
	PassRate        float64       `json:"pass_rate"`
	AverageLatency  time.Duration `json:"average_latency"`
	LastExecutedAt  time.Time     `json:"last_executed_at"`
}

// PerformanceMetricsData contains performance-related metrics
type PerformanceMetricsData struct {
	LatencyHistogram         map[string][]time.Duration `json:"latency_histogram"`
	ThroughputHistory        []ThroughputMeasurement    `json:"throughput_history"`
	ResourceUtilization      *ResourceUtilizationMetrics `json:"resource_utilization"`
	QueueSizes               map[string]int64           `json:"queue_sizes"`
	ConnectionPoolStats      map[string]*PoolStats      `json:"connection_pool_stats"`
	CircuitBreakerStats      map[string]*CircuitBreakerStats `json:"circuit_breaker_stats"`
}

// ThroughputMeasurement represents a throughput measurement at a point in time
type ThroughputMeasurement struct {
	Timestamp    time.Time `json:"timestamp"`
	OperationsPerSecond float64   `json:"operations_per_second"`
	Database     string    `json:"database"`
	Operation    string    `json:"operation"`
}

// ResourceUtilizationMetrics contains resource utilization metrics
type ResourceUtilizationMetrics struct {
	CPUUsage       float64 `json:"cpu_usage"`
	MemoryUsage    float64 `json:"memory_usage"`
	DiskUsage      float64 `json:"disk_usage"`
	NetworkIOBytes int64   `json:"network_io_bytes"`
	GoroutineCount int     `json:"goroutine_count"`
}

// PoolStats contains connection pool statistics
type PoolStats struct {
	ActiveConnections   int   `json:"active_connections"`
	IdleConnections     int   `json:"idle_connections"`
	MaxConnections      int   `json:"max_connections"`
	TotalConnections    int64 `json:"total_connections"`
	ConnectionsCreated  int64 `json:"connections_created"`
	ConnectionsDestroyed int64 `json:"connections_destroyed"`
	UtilizationRate     float64 `json:"utilization_rate"`
}

// CircuitBreakerStats contains circuit breaker statistics
type CircuitBreakerStats struct {
	State                string        `json:"state"`               // closed, open, half-open
	FailureCount         int64         `json:"failure_count"`
	SuccessCount         int64         `json:"success_count"`
	TimeoutCount         int64         `json:"timeout_count"`
	LastStateChange      time.Time     `json:"last_state_change"`
	NextRetry            time.Time     `json:"next_retry"`
	FailureRate          float64       `json:"failure_rate"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
}

// DatabaseIntegrationMetrics contains integration metrics for a specific database
type DatabaseIntegrationMetrics struct {
	Database             string        `json:"database"`
	EventsReceived       int64         `json:"events_received"`
	EventsProcessed      int64         `json:"events_processed"`
	EventsFailed         int64         `json:"events_failed"`
	SyncsCompleted       int64         `json:"syncs_completed"`
	SyncsFailed          int64         `json:"syncs_failed"`
	ConsistencyChecks    int64         `json:"consistency_checks"`
	InconsistenciesFound int64         `json:"inconsistencies_found"`
	AverageLatency       time.Duration `json:"average_latency"`
	ErrorRate            float64       `json:"error_rate"`
	LastOperationTime    time.Time     `json:"last_operation_time"`
	Health               string        `json:"health"`              // healthy, degraded, unhealthy
}

// NewIntegrationMetrics creates a new integration metrics collector
func NewIntegrationMetrics(logger *zap.Logger) *IntegrationMetrics {
	return &IntegrationMetrics{
		logger: logger,
		data: &IntegrationMetricsData{
			DatabaseMetrics: make(map[string]*DatabaseIntegrationMetrics),
			ErrorsByType:    make(map[string]int64),
			ErrorsByDatabase: make(map[string]int64),
		},
		eventMetrics: &EventMetricsData{
			EventsByType:             make(map[string]int64),
			EventsBySource:           make(map[string]int64),
			EventsByTarget:           make(map[string]int64),
			EventProcessingLatency:   make(map[string]time.Duration),
			EventHandlerPerformance:  make(map[string]*HandlerMetrics),
		},
		syncMetrics: &SyncMetricsData{
			SyncLatency:         make(map[string]time.Duration),
			SyncsByType:         make(map[string]int64),
			SyncsByDatabase:     make(map[string]int64),
			SyncRulePerformance: make(map[string]*SyncRuleMetrics),
		},
		consistencyMetrics: &ConsistencyMetricsData{
			ValidationRuleResults:     make(map[string]*ValidationRuleMetrics),
			InconsistenciesByType:     make(map[string]int64),
			InconsistenciesBySeverity: make(map[string]int64),
		},
		performanceMetrics: &PerformanceMetricsData{
			LatencyHistogram:    make(map[string][]time.Duration),
			ThroughputHistory:   make([]ThroughputMeasurement, 0),
			QueueSizes:          make(map[string]int64),
			ConnectionPoolStats: make(map[string]*PoolStats),
			CircuitBreakerStats: make(map[string]*CircuitBreakerStats),
			ResourceUtilization: &ResourceUtilizationMetrics{},
		},
	}
}

// Event metrics methods

func (im *IntegrationMetrics) RecordEventPublished(eventType, source string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.EventsPublished++
	im.eventMetrics.EventsPublishedTotal++
	im.eventMetrics.EventsByType[eventType]++
	im.eventMetrics.EventsBySource[source]++
	im.data.LastUpdate = time.Now()
	
	// Update database metrics
	if dbMetrics, exists := im.data.DatabaseMetrics[source]; exists {
		dbMetrics.EventsReceived++
		dbMetrics.LastOperationTime = time.Now()
	} else {
		im.data.DatabaseMetrics[source] = &DatabaseIntegrationMetrics{
			Database:          source,
			EventsReceived:    1,
			LastOperationTime: time.Now(),
			Health:            "healthy",
		}
	}
}

func (im *IntegrationMetrics) RecordEventProcessed(eventType, target string, latency time.Duration) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.EventsProcessed++
	im.eventMetrics.EventsProcessedTotal++
	im.eventMetrics.EventsByTarget[target]++
	im.eventMetrics.EventProcessingLatency[eventType] = latency
	im.data.LastUpdate = time.Now()
	
	// Update performance metrics
	im.updateLatencyMetrics("event_processing", latency)
	
	// Update database metrics
	if dbMetrics, exists := im.data.DatabaseMetrics[target]; exists {
		dbMetrics.EventsProcessed++
		dbMetrics.LastOperationTime = time.Now()
		im.updateDatabaseLatency(dbMetrics, latency)
	} else {
		im.data.DatabaseMetrics[target] = &DatabaseIntegrationMetrics{
			Database:          target,
			EventsProcessed:   1,
			AverageLatency:    latency,
			LastOperationTime: time.Now(),
			Health:            "healthy",
		}
	}
}

func (im *IntegrationMetrics) RecordEventPublishFailure(eventType string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.EventsFailures++
	im.eventMetrics.EventsFailedTotal++
	im.data.ErrorsByType["event_publish_failure"]++
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) RecordEventProcessingFailure(eventType, target, errorType string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.EventsFailures++
	im.eventMetrics.EventsFailedTotal++
	im.data.ErrorsByType[errorType]++
	im.data.ErrorsByDatabase[target]++
	im.data.LastUpdate = time.Now()
	
	// Update database metrics
	if dbMetrics, exists := im.data.DatabaseMetrics[target]; exists {
		dbMetrics.EventsFailed++
		dbMetrics.ErrorRate = float64(dbMetrics.EventsFailed) / float64(dbMetrics.EventsReceived)
		if dbMetrics.ErrorRate > 0.05 { // 5% error rate threshold
			dbMetrics.Health = "degraded"
		}
		if dbMetrics.ErrorRate > 0.15 { // 15% error rate threshold
			dbMetrics.Health = "unhealthy"
		}
	}
}

// Sync metrics methods

func (im *IntegrationMetrics) RecordSyncStarted(sourceDB, targetDB string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.TotalOperations++
	im.syncMetrics.SyncOperationsTotal++
	im.syncMetrics.SyncsByDatabase[sourceDB]++
	im.syncMetrics.SyncsByDatabase[targetDB]++
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) RecordSyncCompleted(sourceDB, targetDB string, recordsSynced int64, latency time.Duration) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.SuccessfulOperations++
	im.data.SyncsCompleted++
	im.data.RecordsSynced += recordsSynced
	im.syncMetrics.SyncOperationsSuccessful++
	im.syncMetrics.RecordsSyncedTotal += recordsSynced
	
	syncKey := fmt.Sprintf("%s_%s", sourceDB, targetDB)
	im.syncMetrics.SyncLatency[syncKey] = latency
	im.data.LastUpdate = time.Now()
	
	// Update performance metrics
	im.updateLatencyMetrics("sync_operation", latency)
	
	// Update database metrics
	for _, db := range []string{sourceDB, targetDB} {
		if dbMetrics, exists := im.data.DatabaseMetrics[db]; exists {
			dbMetrics.SyncsCompleted++
			dbMetrics.LastOperationTime = time.Now()
			im.updateDatabaseLatency(dbMetrics, latency)
		}
	}
}

func (im *IntegrationMetrics) RecordSyncFailure(sourceDB, targetDB string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.FailedOperations++
	im.data.SyncsFailed++
	im.syncMetrics.SyncOperationsFailed++
	im.data.ErrorsByType["sync_failure"]++
	im.data.ErrorsByDatabase[sourceDB]++
	im.data.ErrorsByDatabase[targetDB]++
	im.data.LastUpdate = time.Now()
	
	// Update database metrics
	for _, db := range []string{sourceDB, targetDB} {
		if dbMetrics, exists := im.data.DatabaseMetrics[db]; exists {
			dbMetrics.SyncsFailed++
			im.updateDatabaseErrorRate(dbMetrics)
		}
	}
}

// Consistency metrics methods

func (im *IntegrationMetrics) RecordConsistencyCheck(databases []string, table string, status ConsistencyStatus) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.ConsistencyChecks++
	im.consistencyMetrics.ConsistencyChecksTotal++
	
	if status == ConsistencyStatusInconsistent {
		im.data.InconsistenciesFound++
		im.consistencyMetrics.InconsistenciesFound++
	}
	
	// Update consistency rate
	if im.consistencyMetrics.ConsistencyChecksTotal > 0 {
		consistentChecks := im.consistencyMetrics.ConsistencyChecksTotal - im.consistencyMetrics.InconsistenciesFound
		im.consistencyMetrics.ConsistencyRate = float64(consistentChecks) / float64(im.consistencyMetrics.ConsistencyChecksTotal)
	}
	
	im.data.LastUpdate = time.Now()
	
	// Update database metrics
	for _, db := range databases {
		if dbMetrics, exists := im.data.DatabaseMetrics[db]; exists {
			dbMetrics.ConsistencyChecks++
			if status == ConsistencyStatusInconsistent {
				dbMetrics.InconsistenciesFound++
			}
		}
	}
}

func (im *IntegrationMetrics) RecordConsistencyCheckFailure(databases []string, table string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.ErrorsByType["consistency_check_failure"]++
	for _, db := range databases {
		im.data.ErrorsByDatabase[db]++
	}
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) RecordInconsistency(inconsistencyType, severity string) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.consistencyMetrics.InconsistenciesByType[inconsistencyType]++
	im.consistencyMetrics.InconsistenciesBySeverity[severity]++
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) RecordAutoRepair(success bool) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.data.AutoRepairsExecuted++
	im.consistencyMetrics.AutoRepairsAttempted++
	
	if success {
		im.consistencyMetrics.AutoRepairsSuccessful++
	} else {
		im.consistencyMetrics.AutoRepairsFailed++
	}
	
	im.data.LastUpdate = time.Now()
}

// Performance metrics methods

func (im *IntegrationMetrics) RecordLatency(operation string, latency time.Duration) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.updateLatencyMetrics(operation, latency)
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) RecordThroughput(database, operation string, opsPerSec float64) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	measurement := ThroughputMeasurement{
		Timestamp:           time.Now(),
		OperationsPerSecond: opsPerSec,
		Database:            database,
		Operation:           operation,
	}
	
	im.performanceMetrics.ThroughputHistory = append(im.performanceMetrics.ThroughputHistory, measurement)
	
	// Keep only last 1000 measurements
	if len(im.performanceMetrics.ThroughputHistory) > 1000 {
		im.performanceMetrics.ThroughputHistory = im.performanceMetrics.ThroughputHistory[1:]
	}
	
	// Update overall throughput
	im.data.ThroughputOpsPerSec = opsPerSec
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) UpdateQueueSize(queueName string, size int64) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.performanceMetrics.QueueSizes[queueName] = size
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) UpdateConnectionPoolStats(database string, stats *PoolStats) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.performanceMetrics.ConnectionPoolStats[database] = stats
	im.data.LastUpdate = time.Now()
}

func (im *IntegrationMetrics) UpdateCircuitBreakerStats(component string, stats *CircuitBreakerStats) {
	im.mu.Lock()
	defer im.mu.Unlock()
	
	im.performanceMetrics.CircuitBreakerStats[component] = stats
	im.data.LastUpdate = time.Now()
}

// GetMetrics returns the current metrics data
func (im *IntegrationMetrics) GetMetrics() *IntegrationMetricsData {
	im.mu.RLock()
	defer im.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	data := *im.data
	return &data
}

func (im *IntegrationMetrics) GetEventMetrics() *EventMetricsData {
	im.mu.RLock()
	defer im.mu.RUnlock()
	
	// Create a copy
	metrics := *im.eventMetrics
	return &metrics
}

func (im *IntegrationMetrics) GetSyncMetrics() *SyncMetricsData {
	im.mu.RLock()
	defer im.mu.RUnlock()
	
	// Create a copy
	metrics := *im.syncMetrics
	return &metrics
}

func (im *IntegrationMetrics) GetConsistencyMetrics() *ConsistencyMetricsData {
	im.mu.RLock()
	defer im.mu.RUnlock()
	
	// Create a copy
	metrics := *im.consistencyMetrics
	return &metrics
}

func (im *IntegrationMetrics) GetPerformanceMetrics() *PerformanceMetricsData {
	im.mu.RLock()
	defer im.mu.RUnlock()
	
	// Create a copy
	metrics := *im.performanceMetrics
	return &metrics
}

// Private helper methods

func (im *IntegrationMetrics) updateLatencyMetrics(operation string, latency time.Duration) {
	// Update latency histogram
	if _, exists := im.performanceMetrics.LatencyHistogram[operation]; !exists {
		im.performanceMetrics.LatencyHistogram[operation] = make([]time.Duration, 0)
	}
	
	im.performanceMetrics.LatencyHistogram[operation] = append(
		im.performanceMetrics.LatencyHistogram[operation], latency)
	
	// Keep only last 1000 measurements
	if len(im.performanceMetrics.LatencyHistogram[operation]) > 1000 {
		im.performanceMetrics.LatencyHistogram[operation] = 
			im.performanceMetrics.LatencyHistogram[operation][1:]
	}
	
	// Update percentiles (simplified calculation)
	latencies := im.performanceMetrics.LatencyHistogram[operation]
	if len(latencies) > 0 {
		// Calculate average
		total := time.Duration(0)
		for _, l := range latencies {
			total += l
		}
		im.data.AverageLatency = total / time.Duration(len(latencies))
		
		// Calculate P95 and P99 (simplified)
		if len(latencies) >= 20 {
			p95Index := int(float64(len(latencies)) * 0.95)
			p99Index := int(float64(len(latencies)) * 0.99)
			im.data.P95Latency = latencies[p95Index]
			im.data.P99Latency = latencies[p99Index]
		}
	}
}

func (im *IntegrationMetrics) updateDatabaseLatency(dbMetrics *DatabaseIntegrationMetrics, latency time.Duration) {
	// Simple running average
	if dbMetrics.AverageLatency == 0 {
		dbMetrics.AverageLatency = latency
	} else {
		// Weighted average with more weight on recent measurements
		dbMetrics.AverageLatency = time.Duration(
			(int64(dbMetrics.AverageLatency)*9 + int64(latency)) / 10)
	}
}

func (im *IntegrationMetrics) updateDatabaseErrorRate(dbMetrics *DatabaseIntegrationMetrics) {
	totalOps := dbMetrics.EventsReceived + dbMetrics.SyncsCompleted + dbMetrics.ConsistencyChecks
	totalErrors := dbMetrics.EventsFailed + dbMetrics.SyncsFailed
	
	if totalOps > 0 {
		dbMetrics.ErrorRate = float64(totalErrors) / float64(totalOps)
		
		// Update health status based on error rate
		if dbMetrics.ErrorRate <= 0.05 {
			dbMetrics.Health = "healthy"
		} else if dbMetrics.ErrorRate <= 0.15 {
			dbMetrics.Health = "degraded"
		} else {
			dbMetrics.Health = "unhealthy"
		}
	}
}

// IntegrationHealthMonitor monitors the health of the integration system
type IntegrationHealthMonitor struct {
	config  IntegrationMonitoringConfig
	metrics *IntegrationMetrics
	logger  *zap.Logger
	
	healthStatus *IntegrationHealthStatus
	mu           sync.RWMutex
}

// NewIntegrationHealthMonitor creates a new integration health monitor
func NewIntegrationHealthMonitor(
	config IntegrationMonitoringConfig,
	metrics *IntegrationMetrics,
	logger *zap.Logger,
) *IntegrationHealthMonitor {
	
	return &IntegrationHealthMonitor{
		config:  config,
		metrics: metrics,
		logger:  logger,
		healthStatus: &IntegrationHealthStatus{
			OverallStatus:       "unknown",
			LastCheck:           time.Now(),
			DatabaseConnections: make(map[string]ComponentHealth),
			Issues:              make([]HealthIssue, 0),
			Recommendations:     make([]string, 0),
		},
	}
}

// PerformHealthCheck performs a comprehensive health check
func (ihm *IntegrationHealthMonitor) PerformHealthCheck() {
	ihm.mu.Lock()
	defer ihm.mu.Unlock()
	
	ihm.healthStatus.LastCheck = time.Now()
	
	// Check event system health
	ihm.checkEventSystemHealth()
	
	// Check sync health
	ihm.checkSyncHealth()
	
	// Check consistency health
	ihm.checkConsistencyHealth()
	
	// Check data flow health
	ihm.checkDataFlowHealth()
	
	// Check database connections
	ihm.checkDatabaseConnections()
	
	// Calculate overall status
	ihm.calculateOverallHealth()
	
	// Generate recommendations
	ihm.generateHealthRecommendations()
	
	ihm.logger.Debug("Health check completed",
		zap.String("overall_status", ihm.healthStatus.OverallStatus),
		zap.Int("issues", len(ihm.healthStatus.Issues)),
	)
}

// GetHealthStatus returns the current health status
func (ihm *IntegrationHealthMonitor) GetHealthStatus() *IntegrationHealthStatus {
	ihm.mu.RLock()
	defer ihm.mu.RUnlock()
	
	// Return a copy
	status := *ihm.healthStatus
	return &status
}

// Close stops the health monitor
func (ihm *IntegrationHealthMonitor) Close() error {
	ihm.logger.Info("Integration health monitor closed")
	return nil
}

// Private health check methods

func (ihm *IntegrationHealthMonitor) checkEventSystemHealth() {
	eventMetrics := ihm.metrics.GetEventMetrics()
	
	// Calculate error rate
	totalEvents := eventMetrics.EventsPublishedTotal
	failedEvents := eventMetrics.EventsFailedTotal
	
	var errorRate float64
	if totalEvents > 0 {
		errorRate = float64(failedEvents) / float64(totalEvents)
	}
	
	status := "healthy"
	if errorRate > ihm.config.ErrorRateThreshold {
		status = "degraded"
	}
	if errorRate > ihm.config.ErrorRateThreshold*2 {
		status = "unhealthy"
	}
	
	ihm.healthStatus.EventSystemHealth = ComponentHealth{
		Status:       status,
		LastCheck:    time.Now(),
		ErrorRate:    errorRate,
		ResponseTime: 0, // Would be calculated from actual measurements
	}
	
	// Add issues if needed
	if status != "healthy" {
		ihm.addHealthIssue("warning", "event_system", "High Error Rate",
			fmt.Sprintf("Event system error rate is %.2f%%", errorRate*100))
	}
}

func (ihm *IntegrationHealthMonitor) checkSyncHealth() {
	syncMetrics := ihm.metrics.GetSyncMetrics()
	
	// Calculate sync success rate
	totalSyncs := syncMetrics.SyncOperationsTotal
	failedSyncs := syncMetrics.SyncOperationsFailed
	
	var successRate float64
	if totalSyncs > 0 {
		successRate = float64(totalSyncs-failedSyncs) / float64(totalSyncs)
	}
	
	status := "healthy"
	if successRate < 0.95 {
		status = "degraded"
	}
	if successRate < 0.85 {
		status = "unhealthy"
	}
	
	ihm.healthStatus.SyncHealth = ComponentHealth{
		Status:    status,
		LastCheck: time.Now(),
		ErrorRate: 1.0 - successRate,
	}
	
	if status != "healthy" {
		ihm.addHealthIssue("critical", "sync", "Low Sync Success Rate",
			fmt.Sprintf("Sync success rate is %.2f%%", successRate*100))
	}
}

func (ihm *IntegrationHealthMonitor) checkConsistencyHealth() {
	consistencyMetrics := ihm.metrics.GetConsistencyMetrics()
	
	status := "healthy"
	if consistencyMetrics.ConsistencyRate < 0.98 {
		status = "degraded"
	}
	if consistencyMetrics.ConsistencyRate < 0.95 {
		status = "unhealthy"
	}
	
	ihm.healthStatus.ConsistencyHealth = ComponentHealth{
		Status:    status,
		LastCheck: time.Now(),
		ErrorRate: 1.0 - consistencyMetrics.ConsistencyRate,
	}
	
	if status != "healthy" {
		ihm.addHealthIssue("warning", "consistency", "Low Consistency Rate",
			fmt.Sprintf("Data consistency rate is %.2f%%", consistencyMetrics.ConsistencyRate*100))
	}
}

func (ihm *IntegrationHealthMonitor) checkDataFlowHealth() {
	// Check queue sizes
	performanceMetrics := ihm.metrics.GetPerformanceMetrics()
	
	status := "healthy"
	for queueName, size := range performanceMetrics.QueueSizes {
		if size > int64(ihm.config.QueueSizeThreshold) {
			status = "degraded"
			ihm.addHealthIssue("warning", "data_flow", "Large Queue Size",
				fmt.Sprintf("Queue %s has %d items", queueName, size))
		}
	}
	
	ihm.healthStatus.DataFlowHealth = ComponentHealth{
		Status:    status,
		LastCheck: time.Now(),
	}
}

func (ihm *IntegrationHealthMonitor) checkDatabaseConnections() {
	metricsData := ihm.metrics.GetMetrics()
	
	for dbName, dbMetrics := range metricsData.DatabaseMetrics {
		status := dbMetrics.Health
		errorRate := dbMetrics.ErrorRate
		
		ihm.healthStatus.DatabaseConnections[dbName] = ComponentHealth{
			Status:       status,
			LastCheck:    time.Now(),
			ResponseTime: dbMetrics.AverageLatency,
			ErrorRate:    errorRate,
		}
		
		if status != "healthy" {
			severity := "warning"
			if status == "unhealthy" {
				severity = "critical"
			}
			ihm.addHealthIssue(severity, "database", fmt.Sprintf("Database %s Health", dbName),
				fmt.Sprintf("Database %s is %s with %.2f%% error rate", dbName, status, errorRate*100))
		}
	}
}

func (ihm *IntegrationHealthMonitor) calculateOverallHealth() {
	components := []ComponentHealth{
		ihm.healthStatus.EventSystemHealth,
		ihm.healthStatus.SyncHealth,
		ihm.healthStatus.ConsistencyHealth,
		ihm.healthStatus.DataFlowHealth,
	}
	
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	
	for _, component := range components {
		switch component.Status {
		case "healthy":
			healthyCount++
		case "degraded":
			degradedCount++
		case "unhealthy":
			unhealthyCount++
		}
	}
	
	// Add database health
	for _, dbHealth := range ihm.healthStatus.DatabaseConnections {
		switch dbHealth.Status {
		case "healthy":
			healthyCount++
		case "degraded":
			degradedCount++
		case "unhealthy":
			unhealthyCount++
		}
	}
	
	if unhealthyCount > 0 {
		ihm.healthStatus.OverallStatus = "unhealthy"
	} else if degradedCount > 0 {
		ihm.healthStatus.OverallStatus = "degraded"
	} else {
		ihm.healthStatus.OverallStatus = "healthy"
	}
}

func (ihm *IntegrationHealthMonitor) generateHealthRecommendations() {
	recommendations := make([]string, 0)
	
	if ihm.healthStatus.OverallStatus != "healthy" {
		recommendations = append(recommendations, "Review integration system configuration and performance")
	}
	
	if ihm.healthStatus.EventSystemHealth.Status != "healthy" {
		recommendations = append(recommendations, "Investigate event processing failures and optimize event handlers")
	}
	
	if ihm.healthStatus.SyncHealth.Status != "healthy" {
		recommendations = append(recommendations, "Review sync rules and increase sync frequency if needed")
	}
	
	if ihm.healthStatus.ConsistencyHealth.Status != "healthy" {
		recommendations = append(recommendations, "Enable auto-repair for consistency issues and review data synchronization")
	}
	
	ihm.healthStatus.Recommendations = recommendations
}

func (ihm *IntegrationHealthMonitor) addHealthIssue(severity, component, title, description string) {
	issue := HealthIssue{
		Severity:    severity,
		Component:   component,
		Title:       title,
		Description: description,
		DetectedAt:  time.Now(),
	}
	
	ihm.healthStatus.Issues = append(ihm.healthStatus.Issues, issue)
}

// Data flow manager placeholder (simplified)
type DataFlowManager struct {
	config DataFlowConfig
	logger *zap.Logger
	closed bool
}

func NewDataFlowManager(
	config DataFlowConfig,
	postgresql *postgres.Client,
	mongodb *mongodb.Client,
	redis *redis.Client,
	elasticsearch *elasticsearch.Client,
	logger *zap.Logger,
) (*DataFlowManager, error) {
	
	return &DataFlowManager{
		config: config,
		logger: logger,
	}, nil
}

func (dfm *DataFlowManager) Close() error {
	dfm.closed = true
	dfm.logger.Info("Data flow manager closed")
	return nil
}