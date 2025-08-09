package lifecycle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DataLifecycleManager manages data lifecycle across storage systems
type DataLifecycleManager struct {
	logger          *zap.Logger
	config          *LifecycleConfig
	
	// Storage backends
	timescaleManager *TimescaleLifecycleManager
	elasticManager   *ElasticsearchLifecycleManager
	archiveManager   *ArchiveManager
	
	// Lifecycle policies
	policies        map[string]*LifecyclePolicy
	policyMutex     sync.RWMutex
	
	// Background processing
	ctx             context.Context
	cancel          context.CancelFunc
	processTicker   *time.Ticker
	
	// Statistics
	stats           *LifecycleStats
	statsMutex      sync.RWMutex
}

// LifecycleConfig defines data lifecycle configuration
type LifecycleConfig struct {
	// Processing settings
	ProcessingInterval    time.Duration `json:"processing_interval"`
	BatchSize            int           `json:"batch_size"`
	MaxConcurrentOps     int           `json:"max_concurrent_ops"`
	
	// Default retention periods
	SecurityEventRetention time.Duration `json:"security_event_retention"`
	MetricsRetention      time.Duration `json:"metrics_retention"`
	LogRetention          time.Duration `json:"log_retention"`
	
	// Archival settings
	EnableArchival        bool          `json:"enable_archival"`
	ArchiveLocation       string        `json:"archive_location"`
	ArchiveCompression    string        `json:"archive_compression"`
	ArchiveEncryption     bool          `json:"archive_encryption"`
	ArchiveRetention      time.Duration `json:"archive_retention"`
	
	// Storage settings
	TimescaleConfig       *TimescaleLifecycleConfig       `json:"timescale_config"`
	ElasticsearchConfig   *ElasticsearchLifecycleConfig   `json:"elasticsearch_config"`
	ArchiveConfig         *ArchiveConfig                  `json:"archive_config"`
	
	// Monitoring settings
	MetricsEnabled        bool          `json:"metrics_enabled"`
	AlertingEnabled       bool          `json:"alerting_enabled"`
	HealthCheckInterval   time.Duration `json:"health_check_interval"`
}

// TimescaleLifecycleConfig defines TimescaleDB lifecycle settings
type TimescaleLifecycleConfig struct {
	CompressionAge        time.Duration `json:"compression_age"`
	RetentionAge          time.Duration `json:"retention_age"`
	ChunkTimeInterval     time.Duration `json:"chunk_time_interval"`
	EnableContinuousAgg   bool          `json:"enable_continuous_agg"`
	AggregationIntervals  []string      `json:"aggregation_intervals"`
}

// ElasticsearchLifecycleConfig defines Elasticsearch lifecycle settings
type ElasticsearchLifecycleConfig struct {
	HotPhaseSize          string        `json:"hot_phase_size"`
	HotPhaseAge           time.Duration `json:"hot_phase_age"`
	WarmPhaseAge          time.Duration `json:"warm_phase_age"`
	ColdPhaseAge          time.Duration `json:"cold_phase_age"`
	DeletePhaseAge        time.Duration `json:"delete_phase_age"`
	EnableShrinking       bool          `json:"enable_shrinking"`
	ShrinkShards          int           `json:"shrink_shards"`
	EnableForcemerge      bool          `json:"enable_forcemerge"`
	ForcemergeSegments    int           `json:"forcemerge_segments"`
}

// ArchiveConfig defines archive storage settings
type ArchiveConfig struct {
	StorageType           string        `json:"storage_type"` // s3, gcs, azure, filesystem
	Endpoint              string        `json:"endpoint"`
	Region                string        `json:"region"`
	Bucket                string        `json:"bucket"`
	AccessKey             string        `json:"access_key"`
	SecretKey             string        `json:"secret_key"`
	CompressionLevel      int           `json:"compression_level"`
	EncryptionKey         string        `json:"encryption_key"`
	ParallelUploads       int           `json:"parallel_uploads"`
	UploadTimeout         time.Duration `json:"upload_timeout"`
}

// LifecyclePolicy defines a data lifecycle policy
type LifecyclePolicy struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	Description           string                 `json:"description"`
	DataType              string                 `json:"data_type"` // security_events, metrics, logs
	
	// Retention phases
	HotPhase              *RetentionPhase        `json:"hot_phase"`
	WarmPhase             *RetentionPhase        `json:"warm_phase"`
	ColdPhase             *RetentionPhase        `json:"cold_phase"`
	ArchivePhase          *RetentionPhase        `json:"archive_phase"`
	DeletePhase           *RetentionPhase        `json:"delete_phase"`
	
	// Conditions
	Conditions            []PolicyCondition      `json:"conditions"`
	Priority              int                    `json:"priority"`
	Enabled               bool                   `json:"enabled"`
	
	// Metadata
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	LastExecuted          time.Time              `json:"last_executed"`
}

// RetentionPhase defines a lifecycle phase
type RetentionPhase struct {
	MinAge                time.Duration          `json:"min_age"`
	MaxAge                time.Duration          `json:"max_age"`
	MaxSize               string                 `json:"max_size"`
	MaxDocs               int64                  `json:"max_docs"`
	Actions               []PhaseAction          `json:"actions"`
	Priority              int                    `json:"priority"`
}

// PhaseAction defines an action to take in a phase
type PhaseAction struct {
	Type                  string                 `json:"type"` // compress, migrate, archive, delete
	Parameters            map[string]interface{} `json:"parameters"`
	ContinueOnFailure     bool                   `json:"continue_on_failure"`
}

// PolicyCondition defines conditions for policy application
type PolicyCondition struct {
	Field                 string                 `json:"field"`
	Operator              string                 `json:"operator"` // equals, contains, greater_than, less_than
	Value                 interface{}            `json:"value"`
}

// LifecycleStats tracks lifecycle management statistics
type LifecycleStats struct {
	ProcessedItems        int64                  `json:"processed_items"`
	CompressedItems       int64                  `json:"compressed_items"`
	ArchivedItems         int64                  `json:"archived_items"`
	DeletedItems          int64                  `json:"deleted_items"`
	BytesCompressed       int64                  `json:"bytes_compressed"`
	BytesArchived         int64                  `json:"bytes_archived"`
	BytesDeleted          int64                  `json:"bytes_deleted"`
	ErrorCount            int64                  `json:"error_count"`
	LastProcessingTime    time.Time              `json:"last_processing_time"`
	AverageProcessingTime time.Duration          `json:"average_processing_time"`
}

// LifecycleOperation represents a lifecycle operation
type LifecycleOperation struct {
	ID                    string                 `json:"id"`
	PolicyID              string                 `json:"policy_id"`
	DataType              string                 `json:"data_type"`
	Phase                 string                 `json:"phase"`
	Action                string                 `json:"action"`
	TargetIndex           string                 `json:"target_index"`
	SourceData            interface{}            `json:"source_data"`
	Status                string                 `json:"status"`
	StartTime             time.Time              `json:"start_time"`
	EndTime               time.Time              `json:"end_time"`
	Error                 string                 `json:"error,omitempty"`
	ItemsProcessed        int64                  `json:"items_processed"`
	BytesProcessed        int64                  `json:"bytes_processed"`
}

// NewDataLifecycleManager creates a new data lifecycle manager
func NewDataLifecycleManager(logger *zap.Logger, config *LifecycleConfig) (*DataLifecycleManager, error) {
	if config == nil {
		return nil, fmt.Errorf("lifecycle configuration is required")
	}
	
	// Set defaults
	if err := setLifecycleDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set configuration defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &DataLifecycleManager{
		logger:    logger.With(zap.String("component", "data-lifecycle-manager")),
		config:    config,
		policies:  make(map[string]*LifecyclePolicy),
		stats:     &LifecycleStats{},
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// Initialize storage managers
	if config.TimescaleConfig != nil {
		manager.timescaleManager = NewTimescaleLifecycleManager(logger, config.TimescaleConfig)
	}
	
	if config.ElasticsearchConfig != nil {
		manager.elasticManager = NewElasticsearchLifecycleManager(logger, config.ElasticsearchConfig)
	}
	
	if config.EnableArchival && config.ArchiveConfig != nil {
		archiveManager, err := NewArchiveManager(logger, config.ArchiveConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create archive manager: %w", err)
		}
		manager.archiveManager = archiveManager
	}
	
	// Create default policies
	if err := manager.createDefaultPolicies(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create default policies: %w", err)
	}
	
	// Start background processing
	manager.processTicker = time.NewTicker(config.ProcessingInterval)
	go manager.runLifecycleProcessing()
	
	logger.Info("Data lifecycle manager initialized",
		zap.Duration("processing_interval", config.ProcessingInterval),
		zap.Bool("archival_enabled", config.EnableArchival),
		zap.Int("policy_count", len(manager.policies)),
	)
	
	return manager, nil
}

// setLifecycleDefaults sets configuration defaults
func setLifecycleDefaults(config *LifecycleConfig) error {
	if config.ProcessingInterval == 0 {
		config.ProcessingInterval = 1 * time.Hour
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.MaxConcurrentOps == 0 {
		config.MaxConcurrentOps = 5
	}
	
	// Default retention periods
	if config.SecurityEventRetention == 0 {
		config.SecurityEventRetention = 365 * 24 * time.Hour // 1 year
	}
	if config.MetricsRetention == 0 {
		config.MetricsRetention = 90 * 24 * time.Hour // 90 days
	}
	if config.LogRetention == 0 {
		config.LogRetention = 30 * 24 * time.Hour // 30 days
	}
	
	// Archive settings
	if config.ArchiveLocation == "" {
		config.ArchiveLocation = "/data/archive"
	}
	if config.ArchiveCompression == "" {
		config.ArchiveCompression = "zstd"
	}
	if config.ArchiveRetention == 0 {
		config.ArchiveRetention = 2555 * 24 * time.Hour // 7 years
	}
	
	// Health check interval
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 5 * time.Minute
	}
	
	return nil
}

// createDefaultPolicies creates default lifecycle policies
func (dlm *DataLifecycleManager) createDefaultPolicies() error {
	// Security events policy
	securityPolicy := &LifecyclePolicy{
		ID:          "security-events-default",
		Name:        "Security Events Default Policy",
		Description: "Default lifecycle policy for security events",
		DataType:    "security_events",
		HotPhase: &RetentionPhase{
			MaxAge: 7 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "optimize", Parameters: map[string]interface{}{"refresh_interval": "5s"}},
			},
		},
		WarmPhase: &RetentionPhase{
			MinAge:  7 * 24 * time.Hour,
			MaxAge:  30 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "compress", Parameters: map[string]interface{}{"codec": "best_compression"}},
				{Type: "reduce_replicas", Parameters: map[string]interface{}{"replicas": 0}},
			},
		},
		ColdPhase: &RetentionPhase{
			MinAge:  30 * 24 * time.Hour,
			MaxAge:  90 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "freeze", Parameters: map[string]interface{}{}},
			},
		},
		ArchivePhase: &RetentionPhase{
			MinAge:  90 * 24 * time.Hour,
			MaxAge:  dlm.config.SecurityEventRetention,
			Actions: []PhaseAction{
				{Type: "archive", Parameters: map[string]interface{}{"compression": "zstd"}},
			},
		},
		DeletePhase: &RetentionPhase{
			MinAge: dlm.config.SecurityEventRetention,
			Actions: []PhaseAction{
				{Type: "delete", Parameters: map[string]interface{}{}},
			},
		},
		Priority:     100,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	// Metrics policy
	metricsPolicy := &LifecyclePolicy{
		ID:          "metrics-default",
		Name:        "Metrics Default Policy",
		Description: "Default lifecycle policy for metrics data",
		DataType:    "metrics",
		HotPhase: &RetentionPhase{
			MaxAge: 3 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "aggregate", Parameters: map[string]interface{}{"intervals": []string{"1m", "5m", "1h"}}},
			},
		},
		WarmPhase: &RetentionPhase{
			MinAge:  3 * 24 * time.Hour,
			MaxAge:  14 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "compress", Parameters: map[string]interface{}{"compression_after": "3d"}},
			},
		},
		ColdPhase: &RetentionPhase{
			MinAge:  14 * 24 * time.Hour,
			MaxAge:  dlm.config.MetricsRetention,
			Actions: []PhaseAction{
				{Type: "compress_heavy", Parameters: map[string]interface{}{}},
			},
		},
		DeletePhase: &RetentionPhase{
			MinAge: dlm.config.MetricsRetention,
			Actions: []PhaseAction{
				{Type: "delete", Parameters: map[string]interface{}{}},
			},
		},
		Priority:     90,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	// Logs policy
	logsPolicy := &LifecyclePolicy{
		ID:          "logs-default",
		Name:        "Logs Default Policy",
		Description: "Default lifecycle policy for application logs",
		DataType:    "logs",
		HotPhase: &RetentionPhase{
			MaxAge: 1 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "optimize", Parameters: map[string]interface{}{}},
			},
		},
		WarmPhase: &RetentionPhase{
			MinAge:  1 * 24 * time.Hour,
			MaxAge:  7 * 24 * time.Hour,
			Actions: []PhaseAction{
				{Type: "compress", Parameters: map[string]interface{}{}},
			},
		},
		DeletePhase: &RetentionPhase{
			MinAge: dlm.config.LogRetention,
			Actions: []PhaseAction{
				{Type: "delete", Parameters: map[string]interface{}{}},
			},
		},
		Priority:     80,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	
	// Store policies
	dlm.policyMutex.Lock()
	dlm.policies[securityPolicy.ID] = securityPolicy
	dlm.policies[metricsPolicy.ID] = metricsPolicy
	dlm.policies[logsPolicy.ID] = logsPolicy
	dlm.policyMutex.Unlock()
	
	dlm.logger.Info("Default lifecycle policies created",
		zap.Int("policy_count", 3),
	)
	
	return nil
}

// runLifecycleProcessing runs the main lifecycle processing loop
func (dlm *DataLifecycleManager) runLifecycleProcessing() {
	for {
		select {
		case <-dlm.ctx.Done():
			return
		case <-dlm.processTicker.C:
			dlm.processLifecyclePolicies()
		}
	}
}

// processLifecyclePolicies processes all enabled lifecycle policies
func (dlm *DataLifecycleManager) processLifecyclePolicies() {
	start := time.Now()
	
	dlm.policyMutex.RLock()
	policies := make([]*LifecyclePolicy, 0, len(dlm.policies))
	for _, policy := range dlm.policies {
		if policy.Enabled {
			policies = append(policies, policy)
		}
	}
	dlm.policyMutex.RUnlock()
	
	dlm.logger.Debug("Starting lifecycle policy processing",
		zap.Int("enabled_policies", len(policies)),
	)
	
	// Process policies concurrently with limit
	semaphore := make(chan struct{}, dlm.config.MaxConcurrentOps)
	var wg sync.WaitGroup
	
	for _, policy := range policies {
		wg.Add(1)
		go func(p *LifecyclePolicy) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			if err := dlm.processPolicy(p); err != nil {
				dlm.logger.Error("Failed to process lifecycle policy",
					zap.String("policy_id", p.ID),
					zap.Error(err),
				)
				dlm.statsMutex.Lock()
				dlm.stats.ErrorCount++
				dlm.statsMutex.Unlock()
			}
		}(policy)
	}
	
	wg.Wait()
	
	// Update statistics
	duration := time.Since(start)
	dlm.statsMutex.Lock()
	dlm.stats.LastProcessingTime = time.Now()
	dlm.stats.AverageProcessingTime = (dlm.stats.AverageProcessingTime + duration) / 2
	dlm.statsMutex.Unlock()
	
	dlm.logger.Debug("Lifecycle policy processing completed",
		zap.Duration("duration", duration),
		zap.Int("policies_processed", len(policies)),
	)
}

// processPolicy processes a single lifecycle policy
func (dlm *DataLifecycleManager) processPolicy(policy *LifecyclePolicy) error {
	ctx, cancel := context.WithTimeout(dlm.ctx, 30*time.Minute)
	defer cancel()
	
	dlm.logger.Debug("Processing lifecycle policy",
		zap.String("policy_id", policy.ID),
		zap.String("data_type", policy.DataType),
	)
	
	// Update last executed time
	dlm.policyMutex.Lock()
	policy.LastExecuted = time.Now()
	dlm.policyMutex.Unlock()
	
	// Process based on data type
	switch policy.DataType {
	case "security_events":
		return dlm.processSecurityEventsPolicy(ctx, policy)
	case "metrics":
		return dlm.processMetricsPolicy(ctx, policy)
	case "logs":
		return dlm.processLogsPolicy(ctx, policy)
	default:
		return fmt.Errorf("unknown data type: %s", policy.DataType)
	}
}

// processSecurityEventsPolicy processes security events lifecycle policy
func (dlm *DataLifecycleManager) processSecurityEventsPolicy(ctx context.Context, policy *LifecyclePolicy) error {
	if dlm.elasticManager == nil {
		return fmt.Errorf("elasticsearch manager not initialized")
	}
	
	// Get eligible indices for each phase
	if policy.WarmPhase != nil {
		if err := dlm.processPhase(ctx, policy, "warm", policy.WarmPhase); err != nil {
			dlm.logger.Error("Failed to process warm phase",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
		}
	}
	
	if policy.ColdPhase != nil {
		if err := dlm.processPhase(ctx, policy, "cold", policy.ColdPhase); err != nil {
			dlm.logger.Error("Failed to process cold phase",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
		}
	}
	
	if policy.ArchivePhase != nil && dlm.archiveManager != nil {
		if err := dlm.processPhase(ctx, policy, "archive", policy.ArchivePhase); err != nil {
			dlm.logger.Error("Failed to process archive phase",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
		}
	}
	
	if policy.DeletePhase != nil {
		if err := dlm.processPhase(ctx, policy, "delete", policy.DeletePhase); err != nil {
			dlm.logger.Error("Failed to process delete phase",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

// processMetricsPolicy processes metrics lifecycle policy
func (dlm *DataLifecycleManager) processMetricsPolicy(ctx context.Context, policy *LifecyclePolicy) error {
	if dlm.timescaleManager == nil {
		return fmt.Errorf("timescale manager not initialized")
	}
	
	// Process TimescaleDB-specific lifecycle operations
	return dlm.timescaleManager.ProcessPolicy(ctx, policy)
}

// processLogsPolicy processes logs lifecycle policy
func (dlm *DataLifecycleManager) processLogsPolicy(ctx context.Context, policy *LifecyclePolicy) error {
	if dlm.elasticManager == nil {
		return fmt.Errorf("elasticsearch manager not initialized")
	}
	
	// Similar to security events but with different index patterns
	return dlm.processSecurityEventsPolicy(ctx, policy)
}

// processPhase processes a specific lifecycle phase
func (dlm *DataLifecycleManager) processPhase(ctx context.Context, policy *LifecyclePolicy, phaseName string, phase *RetentionPhase) error {
	for _, action := range phase.Actions {
		operation := &LifecycleOperation{
			ID:       fmt.Sprintf("%s-%s-%s-%d", policy.ID, phaseName, action.Type, time.Now().Unix()),
			PolicyID: policy.ID,
			DataType: policy.DataType,
			Phase:    phaseName,
			Action:   action.Type,
			Status:   "running",
			StartTime: time.Now(),
		}
		
		if err := dlm.executeAction(ctx, operation, action); err != nil {
			operation.Status = "failed"
			operation.Error = err.Error()
			operation.EndTime = time.Now()
			
			if !action.ContinueOnFailure {
				return fmt.Errorf("action %s failed: %w", action.Type, err)
			}
			
			dlm.logger.Warn("Action failed but continuing",
				zap.String("action", action.Type),
				zap.Error(err),
			)
		} else {
			operation.Status = "completed"
			operation.EndTime = time.Now()
		}
		
		dlm.logger.Debug("Lifecycle action completed",
			zap.String("operation_id", operation.ID),
			zap.String("action", action.Type),
			zap.String("status", operation.Status),
		)
	}
	
	return nil
}

// executeAction executes a lifecycle action
func (dlm *DataLifecycleManager) executeAction(ctx context.Context, operation *LifecycleOperation, action PhaseAction) error {
	switch action.Type {
	case "compress":
		return dlm.executeCompressionAction(ctx, operation, action)
	case "archive":
		return dlm.executeArchiveAction(ctx, operation, action)
	case "delete":
		return dlm.executeDeleteAction(ctx, operation, action)
	case "migrate":
		return dlm.executeMigrationAction(ctx, operation, action)
	default:
		return fmt.Errorf("unknown action type: %s", action.Type)
	}
}

// executeCompressionAction executes compression action
func (dlm *DataLifecycleManager) executeCompressionAction(ctx context.Context, operation *LifecycleOperation, action PhaseAction) error {
	if dlm.elasticManager != nil {
		return dlm.elasticManager.CompressIndices(ctx, operation)
	}
	if dlm.timescaleManager != nil {
		return dlm.timescaleManager.CompressChunks(ctx, operation)
	}
	return fmt.Errorf("no compression backend available")
}

// executeArchiveAction executes archive action
func (dlm *DataLifecycleManager) executeArchiveAction(ctx context.Context, operation *LifecycleOperation, action PhaseAction) error {
	if dlm.archiveManager == nil {
		return fmt.Errorf("archive manager not initialized")
	}
	
	return dlm.archiveManager.ArchiveData(ctx, operation)
}

// executeDeleteAction executes delete action
func (dlm *DataLifecycleManager) executeDeleteAction(ctx context.Context, operation *LifecycleOperation, action PhaseAction) error {
	if dlm.elasticManager != nil {
		return dlm.elasticManager.DeleteIndices(ctx, operation)
	}
	if dlm.timescaleManager != nil {
		return dlm.timescaleManager.DeleteChunks(ctx, operation)
	}
	return fmt.Errorf("no delete backend available")
}

// executeMigrationAction executes migration action
func (dlm *DataLifecycleManager) executeMigrationAction(ctx context.Context, operation *LifecycleOperation, action PhaseAction) error {
	// Implementation would depend on specific migration requirements
	return fmt.Errorf("migration action not implemented")
}

// AddPolicy adds a new lifecycle policy
func (dlm *DataLifecycleManager) AddPolicy(policy *LifecyclePolicy) error {
	if policy.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	
	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()
	
	dlm.policyMutex.Lock()
	dlm.policies[policy.ID] = policy
	dlm.policyMutex.Unlock()
	
	dlm.logger.Info("Lifecycle policy added",
		zap.String("policy_id", policy.ID),
		zap.String("data_type", policy.DataType),
	)
	
	return nil
}

// RemovePolicy removes a lifecycle policy
func (dlm *DataLifecycleManager) RemovePolicy(policyID string) error {
	dlm.policyMutex.Lock()
	delete(dlm.policies, policyID)
	dlm.policyMutex.Unlock()
	
	dlm.logger.Info("Lifecycle policy removed", zap.String("policy_id", policyID))
	return nil
}

// GetPolicy returns a lifecycle policy
func (dlm *DataLifecycleManager) GetPolicy(policyID string) (*LifecyclePolicy, error) {
	dlm.policyMutex.RLock()
	policy, exists := dlm.policies[policyID]
	dlm.policyMutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}
	
	// Return copy to prevent external modifications
	policyCopy := *policy
	return &policyCopy, nil
}

// ListPolicies returns all lifecycle policies
func (dlm *DataLifecycleManager) ListPolicies() []*LifecyclePolicy {
	dlm.policyMutex.RLock()
	defer dlm.policyMutex.RUnlock()
	
	policies := make([]*LifecyclePolicy, 0, len(dlm.policies))
	for _, policy := range dlm.policies {
		policyCopy := *policy
		policies = append(policies, &policyCopy)
	}
	
	return policies
}

// GetStats returns lifecycle statistics
func (dlm *DataLifecycleManager) GetStats() *LifecycleStats {
	dlm.statsMutex.RLock()
	defer dlm.statsMutex.RUnlock()
	
	stats := *dlm.stats
	return &stats
}

// IsHealthy returns the health status
func (dlm *DataLifecycleManager) IsHealthy() bool {
	// Check if managers are healthy
	if dlm.timescaleManager != nil && !dlm.timescaleManager.IsHealthy() {
		return false
	}
	if dlm.elasticManager != nil && !dlm.elasticManager.IsHealthy() {
		return false
	}
	if dlm.archiveManager != nil && !dlm.archiveManager.IsHealthy() {
		return false
	}
	
	return true
}

// Close closes the data lifecycle manager
func (dlm *DataLifecycleManager) Close() error {
	if dlm.cancel != nil {
		dlm.cancel()
	}
	
	if dlm.processTicker != nil {
		dlm.processTicker.Stop()
	}
	
	if dlm.timescaleManager != nil {
		dlm.timescaleManager.Close()
	}
	
	if dlm.elasticManager != nil {
		dlm.elasticManager.Close()
	}
	
	if dlm.archiveManager != nil {
		dlm.archiveManager.Close()
	}
	
	dlm.logger.Info("Data lifecycle manager closed")
	return nil
}