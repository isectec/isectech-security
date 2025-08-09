package integration

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/redis"
	"github.com/isectech/platform/shared/database/elasticsearch"
)

// Initialize initializes the cross-database integration system
func Initialize(
	ctx context.Context,
	config *Config,
	logger *zap.Logger,
	pgClient *postgres.Client,
	mongoClient *mongodb.Client,
	redisClient *redis.Client,
	esClient *elasticsearch.Client,
) (*Manager, error) {
	
	logger.Info("Initializing cross-database integration system",
		zap.Bool("event_system_enabled", config.EventSystem.Enabled),
		zap.Bool("sync_enabled", config.Synchronization.Enabled),
		zap.Bool("consistency_enabled", config.Consistency.Enabled),
		zap.Bool("data_flow_enabled", config.DataFlow.Enabled),
	)
	
	// Validate configuration
	if errors := config.ValidateConfig(); len(errors) > 0 {
		for _, err := range errors {
			logger.Error("Integration configuration validation error", zap.Error(err))
		}
		return nil, fmt.Errorf("integration configuration validation failed: %d errors", len(errors))
	}
	
	// Create integration manager
	manager, err := NewManager(
		config,
		logger,
		pgClient,
		mongoClient,
		redisClient,
		esClient,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create integration manager: %w", err)
	}
	
	logger.Info("Cross-database integration system initialized successfully",
		zap.Duration("check_interval", config.Consistency.CheckInterval),
		zap.Duration("sync_interval", config.Synchronization.BatchInterval),
		zap.String("consistency_level", config.Consistency.ConsistencyLevel),
	)
	
	return manager, nil
}

// CreateDefaultConfig creates a default integration configuration for iSECTECH
func CreateDefaultConfig() *Config {
	return DefaultConfig()
}

// ValidateIntegrationInfrastructure validates that all integration infrastructure is accessible
func ValidateIntegrationInfrastructure(ctx context.Context, config *Config) error {
	// Validate event system configuration
	if config.EventSystem.Enabled {
		if err := validateEventSystemConfig(config.EventSystem); err != nil {
			return fmt.Errorf("event system validation failed: %w", err)
		}
	}
	
	// Validate synchronization configuration
	if config.Synchronization.Enabled {
		if err := validateSynchronizationConfig(config.Synchronization); err != nil {
			return fmt.Errorf("synchronization validation failed: %w", err)
		}
	}
	
	// Validate consistency configuration
	if config.Consistency.Enabled {
		if err := validateConsistencyConfig(config.Consistency); err != nil {
			return fmt.Errorf("consistency validation failed: %w", err)
		}
	}
	
	// Validate data flow configuration
	if config.DataFlow.Enabled {
		if err := validateDataFlowConfig(config.DataFlow); err != nil {
			return fmt.Errorf("data flow validation failed: %w", err)
		}
	}
	
	return nil
}

func validateEventSystemConfig(config EventSystemConfig) error {
	if config.EventStore.Type == "" {
		return fmt.Errorf("event store type is required")
	}
	
	if config.EventStore.Database == "" {
		return fmt.Errorf("event store database is required")
	}
	
	if config.EventStore.Stream == "" {
		return fmt.Errorf("event store stream is required")
	}
	
	if config.EventStore.Retention <= 0 {
		return fmt.Errorf("event store retention must be positive")
	}
	
	return nil
}

func validateSynchronizationConfig(config SynchronizationConfig) error {
	if config.Mode != "real_time" && config.Mode != "batch" && config.Mode != "hybrid" {
		return fmt.Errorf("invalid synchronization mode: %s", config.Mode)
	}
	
	if config.SyncBatchSize <= 0 {
		return fmt.Errorf("sync batch size must be positive")
	}
	
	if config.MaxSyncWorkers <= 0 {
		return fmt.Errorf("max sync workers must be positive")
	}
	
	if config.BatchInterval <= 0 {
		return fmt.Errorf("batch interval must be positive")
	}
	
	return nil
}

func validateConsistencyConfig(config ConsistencyConfig) error {
	if config.ConsistencyLevel != "eventual" && config.ConsistencyLevel != "strong" && config.ConsistencyLevel != "causal" {
		return fmt.Errorf("invalid consistency level: %s", config.ConsistencyLevel)
	}
	
	if config.CheckInterval <= 0 {
		return fmt.Errorf("consistency check interval must be positive")
	}
	
	if config.CheckBatchSize <= 0 {
		return fmt.Errorf("consistency check batch size must be positive")
	}
	
	if config.AlertThreshold < 0.0 || config.AlertThreshold > 1.0 {
		return fmt.Errorf("alert threshold must be between 0.0 and 1.0")
	}
	
	return nil
}

func validateDataFlowConfig(config DataFlowConfig) error {
	if config.RateLimiting.Enabled {
		if config.RateLimiting.GlobalLimit <= 0 {
			return fmt.Errorf("global rate limit must be positive")
		}
		
		if config.RateLimiting.PerDatabaseLimit <= 0 {
			return fmt.Errorf("per-database rate limit must be positive")
		}
		
		if config.RateLimiting.PerTenantLimit <= 0 {
			return fmt.Errorf("per-tenant rate limit must be positive")
		}
	}
	
	if config.BackPressure.Enabled {
		if config.BackPressure.QueueSize <= 0 {
			return fmt.Errorf("back pressure queue size must be positive")
		}
		
		if config.BackPressure.HighWatermark <= config.BackPressure.LowWatermark {
			return fmt.Errorf("high watermark must be greater than low watermark")
		}
	}
	
	return nil
}

// SetupDefaultSyncRules sets up default synchronization rules for iSECTECH platform
func SetupDefaultSyncRules() []SyncRuleConfig {
	return []SyncRuleConfig{
		{
			Name:           "asset_to_elasticsearch",
			SourceDatabase: "postgres",
			SourceTable:    "assets",
			TargetDatabase: "elasticsearch",
			TargetTable:    "assets",
			SyncType:       "incremental",
			Direction:      "one_way",
			FieldMappings: []FieldMapping{
				{SourceField: "id", TargetField: "id", DataType: "string", Required: true},
				{SourceField: "name", TargetField: "name", DataType: "string", Required: true},
				{SourceField: "asset_type", TargetField: "type", DataType: "string", Required: true},
				{SourceField: "ip_address", TargetField: "ip", DataType: "string", Required: false},
				{SourceField: "hostname", TargetField: "hostname", DataType: "string", Required: false},
				{SourceField: "classification", TargetField: "classification", DataType: "string", Required: true},
				{SourceField: "tenant_id", TargetField: "tenant_id", DataType: "string", Required: true},
				{SourceField: "updated_at", TargetField: "last_updated", DataType: "timestamp", Required: true},
			},
			Priority: 8,
			Enabled:  true,
		},
		{
			Name:           "security_events_to_postgres",
			SourceDatabase: "mongodb",
			SourceTable:    "security_events",
			TargetDatabase: "postgres",
			TargetTable:    "security_event_summaries",
			SyncType:       "incremental",
			Direction:      "one_way",
			FieldMappings: []FieldMapping{
				{SourceField: "_id", TargetField: "event_id", DataType: "string", Required: true},
				{SourceField: "event_type", TargetField: "event_type", DataType: "string", Required: true},
				{SourceField: "severity", TargetField: "severity", DataType: "string", Required: true},
				{SourceField: "source_ip", TargetField: "source_ip", DataType: "string", Required: false},
				{SourceField: "destination_ip", TargetField: "destination_ip", DataType: "string", Required: false},
				{SourceField: "tenant_id", TargetField: "tenant_id", DataType: "string", Required: true},
				{SourceField: "timestamp", TargetField: "occurred_at", DataType: "timestamp", Required: true},
			},
			Priority: 10,
			Enabled:  true,
		},
		{
			Name:           "security_events_to_elasticsearch",
			SourceDatabase: "mongodb",
			SourceTable:    "security_events",
			TargetDatabase: "elasticsearch",
			TargetTable:    "security-events",
			SyncType:       "incremental",
			Direction:      "one_way",
			FieldMappings: []FieldMapping{
				{SourceField: "_id", TargetField: "id", DataType: "string", Required: true},
				{SourceField: "event_type", TargetField: "event_type", DataType: "string", Required: true},
				{SourceField: "severity", TargetField: "severity", DataType: "string", Required: true},
				{SourceField: "description", TargetField: "description", DataType: "text", Required: false},
				{SourceField: "source_ip", TargetField: "source_ip", DataType: "ip", Required: false},
				{SourceField: "destination_ip", TargetField: "destination_ip", DataType: "ip", Required: false},
				{SourceField: "mitre_tactics", TargetField: "mitre_tactics", DataType: "array", Required: false},
				{SourceField: "mitre_techniques", TargetField: "mitre_techniques", DataType: "array", Required: false},
				{SourceField: "tenant_id", TargetField: "tenant_id", DataType: "string", Required: true},
				{SourceField: "classification", TargetField: "classification", DataType: "string", Required: true},
				{SourceField: "timestamp", TargetField: "timestamp", DataType: "date", Required: true},
			},
			Priority: 9,
			Enabled:  true,
		},
		{
			Name:           "compliance_data_sync",
			SourceDatabase: "postgres",
			SourceTable:    "compliance_assessments",
			TargetDatabase: "mongodb",
			TargetTable:    "compliance_data",
			SyncType:       "incremental",
			Direction:      "one_way",
			FieldMappings: []FieldMapping{
				{SourceField: "id", TargetField: "assessment_id", DataType: "string", Required: true},
				{SourceField: "framework_id", TargetField: "framework_id", DataType: "string", Required: true},
				{SourceField: "control_id", TargetField: "control_id", DataType: "string", Required: true},
				{SourceField: "status", TargetField: "status", DataType: "string", Required: true},
				{SourceField: "score", TargetField: "score", DataType: "number", Required: true},
				{SourceField: "evidence", TargetField: "evidence", DataType: "text", Required: false},
				{SourceField: "tenant_id", TargetField: "tenant_id", DataType: "string", Required: true},
				{SourceField: "assessed_at", TargetField: "assessed_at", DataType: "timestamp", Required: true},
			},
			Priority: 7,
			Enabled:  true,
		},
		{
			Name:           "user_sessions_cache",
			SourceDatabase: "postgres",
			SourceTable:    "user_sessions",
			TargetDatabase: "redis",
			TargetTable:    "sessions",
			SyncType:       "incremental",
			Direction:      "one_way",
			FieldMappings: []FieldMapping{
				{SourceField: "session_id", TargetField: "session_id", DataType: "string", Required: true},
				{SourceField: "user_id", TargetField: "user_id", DataType: "string", Required: true},
				{SourceField: "tenant_id", TargetField: "tenant_id", DataType: "string", Required: true},
				{SourceField: "expires_at", TargetField: "expires_at", DataType: "timestamp", Required: true},
				{SourceField: "last_activity", TargetField: "last_activity", DataType: "timestamp", Required: true},
			},
			Priority: 6,
			Enabled:  true,
		},
	}
}

// SetupDefaultValidationRules sets up default validation rules for consistency checking
func SetupDefaultValidationRules() []ValidationRuleConfig {
	return []ValidationRuleConfig{
		{
			Name:           "asset_referential_integrity",
			Type:           "referential",
			SourceDatabase: "postgres",
			TargetDatabase: "elasticsearch",
			Rule:           "assets.id exists in both databases",
			Parameters: map[string]interface{}{
				"source_table":      "assets",
				"target_index":      "assets",
				"key_field":         "id",
				"tenant_isolation":  true,
			},
			Severity: "critical",
			Enabled:  true,
		},
		{
			Name:           "security_event_data_integrity",
			Type:           "data",
			SourceDatabase: "mongodb",
			TargetDatabase: "elasticsearch",
			Rule:           "security_events data consistency check",
			Parameters: map[string]interface{}{
				"source_collection": "security_events",
				"target_index":      "security-events",
				"check_fields":      []string{"event_type", "severity", "tenant_id"},
				"tolerance":         0.99, // 99% consistency required
			},
			Severity: "high",
			Enabled:  true,
		},
		{
			Name:           "tenant_isolation_check",
			Type:           "business",
			SourceDatabase: "postgres",
			TargetDatabase: "mongodb",
			Rule:           "tenant data isolation validation",
			Parameters: map[string]interface{}{
				"check_tables":      []string{"assets", "users", "compliance_assessments"},
				"check_collections": []string{"security_events", "compliance_data"},
				"tenant_field":      "tenant_id",
				"isolation_level":   "strict",
			},
			Severity: "critical",
			Enabled:  true,
		},
		{
			Name:           "compliance_data_completeness",
			Type:           "data",
			SourceDatabase: "postgres",
			TargetDatabase: "mongodb",
			Rule:           "compliance data completeness validation",
			Parameters: map[string]interface{}{
				"source_table":      "compliance_assessments",
				"target_collection": "compliance_data",
				"required_fields":   []string{"framework_id", "control_id", "status", "tenant_id"},
				"completeness_threshold": 0.98, // 98% completeness required
			},
			Severity: "medium",
			Enabled:  true,
		},
		{
			Name:           "session_expiry_consistency",
			Type:           "business",
			SourceDatabase: "postgres",
			TargetDatabase: "redis",
			Rule:           "session expiry time consistency",
			Parameters: map[string]interface{}{
				"source_table":    "user_sessions",
				"target_keyspace": "sessions",
				"expiry_field":    "expires_at",
				"tolerance_minutes": 5, // 5 minute tolerance
			},
			Severity: "low",
			Enabled:  true,
		},
	}
}

// SetupDefaultETLPipelines sets up default ETL pipelines for data processing
func SetupDefaultETLPipelines() []ETLPipelineConfig {
	return []ETLPipelineConfig{
		{
			Name: "security_events_analytics",
			Type: "streaming",
			Extract: ExtractConfig{
				Sources: []DataSourceConfig{
					{
						Database: "mongodb",
						Table:    "security_events",
						Filters: []FilterConfig{
							{
								Type:     "field",
								Field:    "processed",
								Operator: "eq",
								Value:    false,
							},
						},
					},
				},
				Mode:        "incremental",
				WatermarkField: "timestamp",
				ChunkSize:   1000,
				Parallelism: 4,
			},
			Transform: []TransformConfig{
				{
					Type:      "enrichment",
					Operation: "mitre_mapping",
					Parameters: map[string]interface{}{
						"source_field": "event_type",
						"target_fields": []string{"mitre_tactics", "mitre_techniques"},
						"lookup_table":  "mitre_attack_mapping",
					},
				},
				{
					Type:      "aggregation",
					Operation: "threat_scoring",
					Parameters: map[string]interface{}{
						"score_fields": []string{"severity", "confidence", "impact"},
						"output_field": "threat_score",
						"algorithm":    "weighted_average",
					},
				},
			},
			Load: LoadConfig{
				Destinations: []DataDestConfig{
					{
						Database: "elasticsearch",
						Table:    "security-events-enriched",
						Mode:     "append",
					},
					{
						Database: "postgres",
						Table:    "threat_indicators",
						Mode:     "upsert",
					},
				},
				WriteBatchSize:   500,
				WriteParallelism: 2,
			},
			Schedule: "*/5 * * * *", // Every 5 minutes
			Resources: ResourceConfig{
				CPU:     "1000m",
				Memory:  "2Gi",
				Workers: 4,
				Timeout: 10 * time.Minute,
			},
			Monitoring: PipelineMonitoring{
				Enabled:        true,
				MetricsEnabled: true,
				AlertsEnabled:  true,
				SLAThresholds: SLAThresholds{
					ProcessingTime: 5 * time.Minute,
					ErrorRate:      0.01, // 1%
					Throughput:     1000,  // events per minute
					DataFreshness:  10 * time.Minute,
				},
			},
		},
		{
			Name: "compliance_reporting",
			Type: "batch",
			Extract: ExtractConfig{
				Sources: []DataSourceConfig{
					{
						Database: "postgres",
						Table:    "compliance_assessments",
					},
					{
						Database: "mongodb",
						Table:    "compliance_data",
					},
				},
				Mode:        "full",
				ChunkSize:   5000,
				Parallelism: 2,
			},
			Transform: []TransformConfig{
				{
					Type:      "aggregation",
					Operation: "compliance_scoring",
					Parameters: map[string]interface{}{
						"group_by":     []string{"framework_id", "tenant_id"},
						"score_field":  "score",
						"status_field": "status",
						"output_fields": []string{"overall_score", "compliance_percentage", "control_status_summary"},
					},
				},
			},
			Load: LoadConfig{
				Destinations: []DataDestConfig{
					{
						Database: "elasticsearch",
						Table:    "compliance-reports",
						Mode:     "overwrite",
					},
				},
				WriteBatchSize:   1000,
				WriteParallelism: 1,
			},
			Schedule: "0 6 * * *", // Daily at 6 AM
			Resources: ResourceConfig{
				CPU:     "2000m",
				Memory:  "4Gi",
				Workers: 2,
				Timeout: 30 * time.Minute,
			},
			Monitoring: PipelineMonitoring{
				Enabled:        true,
				MetricsEnabled: true,
				AlertsEnabled:  true,
				SLAThresholds: SLAThresholds{
					ProcessingTime: 20 * time.Minute,
					ErrorRate:      0.005, // 0.5%
					Throughput:     10000,  // records per run
					DataFreshness:  24 * time.Hour,
				},
			},
		},
	}
}