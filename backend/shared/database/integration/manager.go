package integration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/redis"
	"github.com/isectech/platform/shared/database/elasticsearch"
)

// Manager orchestrates cross-database integration and data consistency
type Manager struct {
	config *Config
	logger *zap.Logger
	
	// Database clients
	postgresql    *postgres.Client
	mongodb       *mongodb.Client
	redis         *redis.Client
	elasticsearch *elasticsearch.Client
	
	// Integration components
	eventSystem      *EventSystem
	syncManager      *SynchronizationManager
	consistencyMgr   *ConsistencyManager
	dataFlowMgr      *DataFlowManager
	
	// Monitoring and metrics
	metrics          *IntegrationMetrics
	healthMonitor    *IntegrationHealthMonitor
	
	// State management
	mu               sync.RWMutex
	closed           bool
	shutdownCh       chan struct{}
	wg               sync.WaitGroup
}

// IntegrationEvent represents a cross-database integration event
type IntegrationEvent struct {
	ID             string                 `json:"id"`
	Type           string                 `json:"type"`
	Source         string                 `json:"source"`         // source database
	Target         []string               `json:"target"`         // target databases
	Timestamp      time.Time              `json:"timestamp"`
	TenantID       string                 `json:"tenant_id"`
	Classification string                 `json:"classification"` // security classification
	Data           map[string]interface{} `json:"data"`
	Metadata       map[string]interface{} `json:"metadata"`
	Priority       int                    `json:"priority"`
	TTL            time.Duration          `json:"ttl"`
}

// SyncOperation represents a data synchronization operation
type SyncOperation struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`            // full, incremental, delta
	SourceDatabase  string                 `json:"source_database"`
	TargetDatabase  string                 `json:"target_database"`
	Table           string                 `json:"table"`
	Status          SyncStatus             `json:"status"`
	StartTime       time.Time              `json:"start_time"`
	EndTime         *time.Time             `json:"end_time,omitempty"`
	RecordsProcessed int64                 `json:"records_processed"`
	RecordsSynced   int64                  `json:"records_synced"`
	Errors          []string               `json:"errors"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// SyncStatus represents the status of a sync operation
type SyncStatus string

const (
	SyncStatusPending    SyncStatus = "pending"
	SyncStatusRunning    SyncStatus = "running"
	SyncStatusCompleted  SyncStatus = "completed"
	SyncStatusFailed     SyncStatus = "failed"
	SyncStatusCancelled  SyncStatus = "cancelled"
)

// ConsistencyCheck represents a data consistency check result
type ConsistencyCheck struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`
	Databases       []string               `json:"databases"`
	Table           string                 `json:"table"`
	CheckTime       time.Time              `json:"check_time"`
	Status          ConsistencyStatus      `json:"status"`
	Inconsistencies []Inconsistency        `json:"inconsistencies"`
	Summary         ConsistencySummary     `json:"summary"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ConsistencyStatus represents the status of a consistency check
type ConsistencyStatus string

const (
	ConsistencyStatusConsistent   ConsistencyStatus = "consistent"
	ConsistencyStatusInconsistent ConsistencyStatus = "inconsistent"
	ConsistencyStatusError        ConsistencyStatus = "error"
)

// Inconsistency represents a data inconsistency
type Inconsistency struct {
	Type        string                 `json:"type"`        // missing, different, extra
	RecordID    string                 `json:"record_id"`
	Database    string                 `json:"database"`
	Table       string                 `json:"table"`
	Field       string                 `json:"field,omitempty"`
	Expected    interface{}            `json:"expected,omitempty"`
	Actual      interface{}            `json:"actual,omitempty"`
	Severity    string                 `json:"severity"`    // critical, warning, info
	Metadata    map[string]interface{} `json:"metadata"`
}

// ConsistencySummary provides a summary of consistency check results
type ConsistencySummary struct {
	TotalRecords       int64   `json:"total_records"`
	ConsistentRecords  int64   `json:"consistent_records"`
	InconsistentRecords int64  `json:"inconsistent_records"`
	ConsistencyRate    float64 `json:"consistency_rate"`
	CriticalIssues     int     `json:"critical_issues"`
	WarningIssues      int     `json:"warning_issues"`
	InfoIssues         int     `json:"info_issues"`
}

// NewManager creates a new integration manager
func NewManager(
	config *Config,
	logger *zap.Logger,
	postgresql *postgres.Client,
	mongodb *mongodb.Client,
	redis *redis.Client,
	elasticsearch *elasticsearch.Client,
) (*Manager, error) {
	
	// Initialize integration components
	eventSystem, err := NewEventSystem(config.EventSystem, redis, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize event system: %w", err)
	}
	
	syncManager, err := NewSynchronizationManager(config.Synchronization, postgresql, mongodb, redis, elasticsearch, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize sync manager: %w", err)
	}
	
	consistencyMgr, err := NewConsistencyManager(config.Consistency, postgresql, mongodb, redis, elasticsearch, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize consistency manager: %w", err)
	}
	
	dataFlowMgr, err := NewDataFlowManager(config.DataFlow, postgresql, mongodb, redis, elasticsearch, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize data flow manager: %w", err)
	}
	
	// Initialize monitoring components
	metrics := NewIntegrationMetrics(logger)
	healthMonitor := NewIntegrationHealthMonitor(config.Monitoring, metrics, logger)
	
	manager := &Manager{
		config:         config,
		logger:         logger,
		postgresql:     postgresql,
		mongodb:        mongodb,
		redis:          redis,
		elasticsearch:  elasticsearch,
		eventSystem:    eventSystem,
		syncManager:    syncManager,
		consistencyMgr: consistencyMgr,
		dataFlowMgr:    dataFlowMgr,
		metrics:        metrics,
		healthMonitor:  healthMonitor,
		shutdownCh:     make(chan struct{}),
	}
	
	// Start background processes
	manager.wg.Add(4)
	go manager.runEventProcessor()
	go manager.runSyncCoordinator()
	go manager.runConsistencyChecker()
	go manager.runHealthMonitor()
	
	logger.Info("Integration manager initialized successfully",
		zap.Bool("event_system_enabled", config.EventSystem.Enabled),
		zap.Bool("sync_enabled", config.Synchronization.Enabled),
		zap.Bool("consistency_enabled", config.Consistency.Enabled),
		zap.Bool("data_flow_enabled", config.DataFlow.Enabled),
	)
	
	return manager, nil
}

// PublishEvent publishes an integration event to the event system
func (m *Manager) PublishEvent(ctx context.Context, event *IntegrationEvent) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.closed {
		return fmt.Errorf("integration manager is closed")
	}
	
	// Validate event
	if err := m.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}
	
	// Enrich event with metadata
	event.Timestamp = time.Now()
	if event.ID == "" {
		event.ID = m.generateEventID()
	}
	
	// Publish to event system
	if err := m.eventSystem.PublishEvent(ctx, event); err != nil {
		m.metrics.RecordEventPublishFailure(event.Type)
		return fmt.Errorf("failed to publish event: %w", err)
	}
	
	m.metrics.RecordEventPublished(event.Type, event.Source)
	
	m.logger.Debug("Event published successfully",
		zap.String("event_id", event.ID),
		zap.String("type", event.Type),
		zap.String("source", event.Source),
		zap.Strings("targets", event.Target),
	)
	
	return nil
}

// TriggerSync triggers a data synchronization operation
func (m *Manager) TriggerSync(ctx context.Context, operation *SyncOperation) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.closed {
		return fmt.Errorf("integration manager is closed")
	}
	
	// Validate sync operation
	if err := m.validateSyncOperation(operation); err != nil {
		return fmt.Errorf("invalid sync operation: %w", err)
	}
	
	// Initialize operation
	operation.ID = m.generateSyncID()
	operation.Status = SyncStatusPending
	operation.StartTime = time.Now()
	
	// Submit to sync manager
	if err := m.syncManager.SubmitSyncOperation(ctx, operation); err != nil {
		m.metrics.RecordSyncFailure(operation.SourceDatabase, operation.TargetDatabase)
		return fmt.Errorf("failed to submit sync operation: %w", err)
	}
	
	m.metrics.RecordSyncStarted(operation.SourceDatabase, operation.TargetDatabase)
	
	m.logger.Info("Sync operation triggered",
		zap.String("operation_id", operation.ID),
		zap.String("type", operation.Type),
		zap.String("source", operation.SourceDatabase),
		zap.String("target", operation.TargetDatabase),
	)
	
	return nil
}

// CheckConsistency performs a consistency check across databases
func (m *Manager) CheckConsistency(ctx context.Context, databases []string, table string) (*ConsistencyCheck, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.closed {
		return nil, fmt.Errorf("integration manager is closed")
	}
	
	// Validate input
	if len(databases) < 2 {
		return nil, fmt.Errorf("consistency check requires at least 2 databases")
	}
	
	// Perform consistency check
	check, err := m.consistencyMgr.PerformConsistencyCheck(ctx, databases, table)
	if err != nil {
		m.metrics.RecordConsistencyCheckFailure(databases, table)
		return nil, fmt.Errorf("consistency check failed: %w", err)
	}
	
	m.metrics.RecordConsistencyCheck(databases, table, check.Status)
	
	m.logger.Info("Consistency check completed",
		zap.String("check_id", check.ID),
		zap.Strings("databases", databases),
		zap.String("table", table),
		zap.String("status", string(check.Status)),
		zap.Float64("consistency_rate", check.Summary.ConsistencyRate),
	)
	
	return check, nil
}

// GetSyncStatus returns the status of a sync operation
func (m *Manager) GetSyncStatus(operationID string) (*SyncOperation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.closed {
		return nil, fmt.Errorf("integration manager is closed")
	}
	
	return m.syncManager.GetSyncStatus(operationID)
}

// GetConsistencyReport returns a consistency report for the specified databases
func (m *Manager) GetConsistencyReport(databases []string, timeRange time.Duration) (*ConsistencyReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if m.closed {
		return nil, fmt.Errorf("integration manager is closed")
	}
	
	return m.consistencyMgr.GetConsistencyReport(databases, timeRange)
}

// GetIntegrationMetrics returns integration metrics
func (m *Manager) GetIntegrationMetrics() *IntegrationMetricsData {
	return m.metrics.GetMetrics()
}

// GetHealthStatus returns the health status of the integration system
func (m *Manager) GetHealthStatus() *IntegrationHealthStatus {
	return m.healthMonitor.GetHealthStatus()
}

// Close gracefully shuts down the integration manager
func (m *Manager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	m.mu.Unlock()
	
	close(m.shutdownCh)
	m.wg.Wait()
	
	// Close components
	if err := m.eventSystem.Close(); err != nil {
		m.logger.Error("Failed to close event system", zap.Error(err))
	}
	
	if err := m.syncManager.Close(); err != nil {
		m.logger.Error("Failed to close sync manager", zap.Error(err))
	}
	
	if err := m.consistencyMgr.Close(); err != nil {
		m.logger.Error("Failed to close consistency manager", zap.Error(err))
	}
	
	if err := m.dataFlowMgr.Close(); err != nil {
		m.logger.Error("Failed to close data flow manager", zap.Error(err))
	}
	
	if err := m.healthMonitor.Close(); err != nil {
		m.logger.Error("Failed to close health monitor", zap.Error(err))
	}
	
	m.logger.Info("Integration manager closed successfully")
	return nil
}

// Background processes

func (m *Manager) runEventProcessor() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.processEvents()
		case <-m.shutdownCh:
			return
		}
	}
}

func (m *Manager) runSyncCoordinator() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.Synchronization.BatchInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.coordinateSync()
		case <-m.shutdownCh:
			return
		}
	}
}

func (m *Manager) runConsistencyChecker() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.Consistency.CheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.performConsistencyChecks()
		case <-m.shutdownCh:
			return
		}
	}
}

func (m *Manager) runHealthMonitor() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.Monitoring.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.healthMonitor.PerformHealthCheck()
		case <-m.shutdownCh:
			return
		}
	}
}

// Private helper methods

func (m *Manager) processEvents() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Process pending events from the event system
	if err := m.eventSystem.ProcessPendingEvents(ctx); err != nil {
		m.logger.Error("Failed to process events", zap.Error(err))
	}
}

func (m *Manager) coordinateSync() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	// Coordinate automatic synchronization based on sync rules
	if err := m.syncManager.CoordinateSync(ctx); err != nil {
		m.logger.Error("Failed to coordinate sync", zap.Error(err))
	}
}

func (m *Manager) performConsistencyChecks() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	
	// Perform automatic consistency checks
	if err := m.consistencyMgr.PerformScheduledChecks(ctx); err != nil {
		m.logger.Error("Failed to perform consistency checks", zap.Error(err))
	}
}

func (m *Manager) validateEvent(event *IntegrationEvent) error {
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	
	if event.Source == "" {
		return fmt.Errorf("event source is required")
	}
	
	if len(event.Target) == 0 {
		return fmt.Errorf("event target is required")
	}
	
	if event.Data == nil {
		return fmt.Errorf("event data is required")
	}
	
	return nil
}

func (m *Manager) validateSyncOperation(operation *SyncOperation) error {
	if operation.Type == "" {
		return fmt.Errorf("sync operation type is required")
	}
	
	if operation.SourceDatabase == "" {
		return fmt.Errorf("source database is required")
	}
	
	if operation.TargetDatabase == "" {
		return fmt.Errorf("target database is required")
	}
	
	if operation.Table == "" {
		return fmt.Errorf("table is required")
	}
	
	return nil
}

func (m *Manager) generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

func (m *Manager) generateSyncID() string {
	return fmt.Sprintf("sync_%d", time.Now().UnixNano())
}

// Additional types and interfaces

// ConsistencyReport represents a comprehensive consistency report
type ConsistencyReport struct {
	GeneratedAt     time.Time            `json:"generated_at"`
	TimeRange       time.Duration        `json:"time_range"`
	Databases       []string             `json:"databases"`
	OverallStatus   ConsistencyStatus    `json:"overall_status"`
	Summary         ConsistencySummary   `json:"summary"`
	CheckResults    []ConsistencyCheck   `json:"check_results"`
	Recommendations []string             `json:"recommendations"`
	TrendAnalysis   *TrendAnalysis       `json:"trend_analysis,omitempty"`
}

// TrendAnalysis provides trend analysis for consistency over time
type TrendAnalysis struct {
	ConsistencyTrend    string    `json:"consistency_trend"`    // improving, stable, degrading
	ErrorTrend          string    `json:"error_trend"`          // increasing, stable, decreasing
	PeakInconsistency   time.Time `json:"peak_inconsistency"`
	AverageConsistency  float64   `json:"average_consistency"`
	PredictedIssues     []string  `json:"predicted_issues"`
}

// IntegrationHealthStatus represents the health status of the integration system
type IntegrationHealthStatus struct {
	OverallStatus       string                     `json:"overall_status"`
	LastCheck           time.Time                  `json:"last_check"`
	EventSystemHealth   ComponentHealth            `json:"event_system_health"`
	SyncHealth          ComponentHealth            `json:"sync_health"`
	ConsistencyHealth   ComponentHealth            `json:"consistency_health"`
	DataFlowHealth      ComponentHealth            `json:"data_flow_health"`
	DatabaseConnections map[string]ComponentHealth `json:"database_connections"`
	Issues              []HealthIssue              `json:"issues"`
	Recommendations     []string                   `json:"recommendations"`
}

// ComponentHealth represents the health of an individual component
type ComponentHealth struct {
	Status       string        `json:"status"`        // healthy, degraded, unhealthy
	LastCheck    time.Time     `json:"last_check"`
	ResponseTime time.Duration `json:"response_time"`
	ErrorRate    float64       `json:"error_rate"`
	Message      string        `json:"message,omitempty"`
}

// HealthIssue represents a health issue in the integration system
type HealthIssue struct {
	Severity    string    `json:"severity"`    // critical, warning, info
	Component   string    `json:"component"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	DetectedAt  time.Time `json:"detected_at"`
	Resolution  string    `json:"resolution,omitempty"`
}