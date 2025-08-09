package backup

import (
	"fmt"
	"time"
)

// Config defines the comprehensive backup and disaster recovery configuration
type Config struct {
	// Global backup settings
	BackupRetention   BackupRetentionConfig   `yaml:"backup_retention" json:"backup_retention"`
	Security          BackupSecurityConfig    `yaml:"security" json:"security"`
	Storage           BackupStorageConfig     `yaml:"storage" json:"storage"`
	Monitoring        BackupMonitoringConfig  `yaml:"monitoring" json:"monitoring"`
	DisasterRecovery  DisasterRecoveryConfig  `yaml:"disaster_recovery" json:"disaster_recovery"`
	
	// Database-specific backup configurations
	PostgreSQL    PostgreSQLBackupConfig    `yaml:"postgresql" json:"postgresql"`
	MongoDB       MongoDBBackupConfig       `yaml:"mongodb" json:"mongodb"`
	Redis         RedisBackupConfig         `yaml:"redis" json:"redis"`
	Elasticsearch ElasticsearchBackupConfig `yaml:"elasticsearch" json:"elasticsearch"`
	
	// Operational settings
	ParallelBackups     int           `yaml:"parallel_backups" json:"parallel_backups"`
	CompressionLevel    int           `yaml:"compression_level" json:"compression_level"`
	VerificationEnabled bool          `yaml:"verification_enabled" json:"verification_enabled"`
	MaxRetries          int           `yaml:"max_retries" json:"max_retries"`
	RetryDelay          time.Duration `yaml:"retry_delay" json:"retry_delay"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
}

// BackupRetentionConfig defines data retention policies for compliance
type BackupRetentionConfig struct {
	// Cybersecurity-specific retention based on data classification
	TopSecretRetention    time.Duration `yaml:"top_secret_retention" json:"top_secret_retention"`       // 10 years
	SecretRetention       time.Duration `yaml:"secret_retention" json:"secret_retention"`               // 7 years
	ConfidentialRetention time.Duration `yaml:"confidential_retention" json:"confidential_retention"`   // 5 years
	UnclassifiedRetention time.Duration `yaml:"unclassified_retention" json:"unclassified_retention"`   // 3 years
	
	// Operational retention
	DailyBackupRetention   time.Duration `yaml:"daily_backup_retention" json:"daily_backup_retention"`     // 90 days
	WeeklyBackupRetention  time.Duration `yaml:"weekly_backup_retention" json:"weekly_backup_retention"`   // 1 year
	MonthlyBackupRetention time.Duration `yaml:"monthly_backup_retention" json:"monthly_backup_retention"` // 7 years
	
	// Archive settings
	ArchiveAfter    time.Duration `yaml:"archive_after" json:"archive_after"`
	ArchiveStorage  string        `yaml:"archive_storage" json:"archive_storage"`
	ArchiveCompress bool          `yaml:"archive_compress" json:"archive_compress"`
}

// BackupSecurityConfig defines encryption and security for backups
type BackupSecurityConfig struct {
	EncryptionEnabled    bool     `yaml:"encryption_enabled" json:"encryption_enabled"`
	EncryptionAlgorithm  string   `yaml:"encryption_algorithm" json:"encryption_algorithm"`   // AES-256-GCM
	KeyProvider          string   `yaml:"key_provider" json:"key_provider"`                   // vault, kms, local
	KeyRotationInterval  time.Duration `yaml:"key_rotation_interval" json:"key_rotation_interval"`
	
	// Access control
	AllowedUsers         []string `yaml:"allowed_users" json:"allowed_users"`
	RequireMultiAuth     bool     `yaml:"require_multi_auth" json:"require_multi_auth"`
	AuditAllOperations   bool     `yaml:"audit_all_operations" json:"audit_all_operations"`
	
	// Integrity verification
	ChecksumAlgorithm    string   `yaml:"checksum_algorithm" json:"checksum_algorithm"`       // SHA-256
	VerifyOnRestore      bool     `yaml:"verify_on_restore" json:"verify_on_restore"`
	VerifyAfterBackup    bool     `yaml:"verify_after_backup" json:"verify_after_backup"`
}

// BackupStorageConfig defines storage backends and locations
type BackupStorageConfig struct {
	Primary   StorageBackendConfig   `yaml:"primary" json:"primary"`
	Secondary []StorageBackendConfig `yaml:"secondary" json:"secondary"`
	Archive   StorageBackendConfig   `yaml:"archive" json:"archive"`
}

// StorageBackendConfig defines individual storage backend configuration
type StorageBackendConfig struct {
	Type        string            `yaml:"type" json:"type"`               // gcs, s3, azure, local, nfs
	Region      string            `yaml:"region" json:"region"`
	Bucket      string            `yaml:"bucket" json:"bucket"`
	Path        string            `yaml:"path" json:"path"`
	Credentials map[string]string `yaml:"credentials" json:"credentials"`
	
	// Performance settings
	MultipartThreshold int64         `yaml:"multipart_threshold" json:"multipart_threshold"`
	ChunkSize          int64         `yaml:"chunk_size" json:"chunk_size"`
	MaxConcurrency     int           `yaml:"max_concurrency" json:"max_concurrency"`
	Timeout            time.Duration `yaml:"timeout" json:"timeout"`
	
	// Encryption at storage level
	StorageEncryption  bool   `yaml:"storage_encryption" json:"storage_encryption"`
	KMSKeyID          string `yaml:"kms_key_id" json:"kms_key_id"`
}

// BackupMonitoringConfig defines monitoring and alerting for backup operations
type BackupMonitoringConfig struct {
	EnableMetrics       bool          `yaml:"enable_metrics" json:"enable_metrics"`
	MetricsEndpoint     string        `yaml:"metrics_endpoint" json:"metrics_endpoint"`
	AlertingEnabled     bool          `yaml:"alerting_enabled" json:"alerting_enabled"`
	AlertEndpoints      []string      `yaml:"alert_endpoints" json:"alert_endpoints"`
	
	// SLA monitoring
	BackupSLA           time.Duration `yaml:"backup_sla" json:"backup_sla"`              // Max backup time
	RestoreSLA          time.Duration `yaml:"restore_sla" json:"restore_sla"`            // Max restore time
	RPO                 time.Duration `yaml:"rpo" json:"rpo"`                            // Recovery Point Objective
	RTO                 time.Duration `yaml:"rto" json:"rto"`                            // Recovery Time Objective
	
	// Health monitoring
	HealthCheckEnabled  bool          `yaml:"health_check_enabled" json:"health_check_enabled"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
	MaxFailedChecks     int           `yaml:"max_failed_checks" json:"max_failed_checks"`
}

// DisasterRecoveryConfig defines disaster recovery procedures
type DisasterRecoveryConfig struct {
	Enabled             bool     `yaml:"enabled" json:"enabled"`
	SecondaryRegions    []string `yaml:"secondary_regions" json:"secondary_regions"`
	ReplicationMode     string   `yaml:"replication_mode" json:"replication_mode"`    // async, sync, semi-sync
	FailoverThreshold   time.Duration `yaml:"failover_threshold" json:"failover_threshold"`
	
	// Cross-region replication
	CrossRegionBackup   bool     `yaml:"cross_region_backup" json:"cross_region_backup"`
	CrossRegionInterval time.Duration `yaml:"cross_region_interval" json:"cross_region_interval"`
	
	// Automated failover
	AutoFailover        bool     `yaml:"auto_failover" json:"auto_failover"`
	FailoverDecisionTree map[string]interface{} `yaml:"failover_decision_tree" json:"failover_decision_tree"`
	
	// Recovery procedures
	RecoveryScripts     []string `yaml:"recovery_scripts" json:"recovery_scripts"`
	RecoveryValidation  []string `yaml:"recovery_validation" json:"recovery_validation"`
	WarmStandby         bool     `yaml:"warm_standby" json:"warm_standby"`
}

// Database-specific backup configurations

// PostgreSQLBackupConfig defines PostgreSQL-specific backup settings
type PostgreSQLBackupConfig struct {
	BackupMode          string        `yaml:"backup_mode" json:"backup_mode"`             // full, incremental, differential
	WALArchiving        bool          `yaml:"wal_archiving" json:"wal_archiving"`
	WALRetention        time.Duration `yaml:"wal_retention" json:"wal_retention"`
	PITREnabled         bool          `yaml:"pitr_enabled" json:"pitr_enabled"`           // Point-in-time recovery
	
	// Streaming replication
	StreamingReplicas   []ReplicaConfig `yaml:"streaming_replicas" json:"streaming_replicas"`
	ReplicationSlots    bool          `yaml:"replication_slots" json:"replication_slots"`
	SynchronousCommit   string        `yaml:"synchronous_commit" json:"synchronous_commit"` // on, off, remote_apply
	
	// Backup scheduling
	FullBackupSchedule  string        `yaml:"full_backup_schedule" json:"full_backup_schedule"`     // Cron expression
	IncrBackupSchedule  string        `yaml:"incr_backup_schedule" json:"incr_backup_schedule"`     // Cron expression
	
	// Compression and parallelism
	CompressionMethod   string        `yaml:"compression_method" json:"compression_method"`         // gzip, lz4, zstd
	ParallelJobs        int           `yaml:"parallel_jobs" json:"parallel_jobs"`
	ChecksumPages       bool          `yaml:"checksum_pages" json:"checksum_pages"`
}

// MongoDBBackupConfig defines MongoDB-specific backup settings
type MongoDBBackupConfig struct {
	BackupMethod        string        `yaml:"backup_method" json:"backup_method"`         // mongodump, filesystem, oplog
	OplogCapture        bool          `yaml:"oplog_capture" json:"oplog_capture"`
	OplogRetention      time.Duration `yaml:"oplog_retention" json:"oplog_retention"`
	
	// Sharded cluster support
	ShardedBackup       bool          `yaml:"sharded_backup" json:"sharded_backup"`
	ConfigServerBackup  bool          `yaml:"config_server_backup" json:"config_server_backup"`
	BalancerControl     bool          `yaml:"balancer_control" json:"balancer_control"`   // Stop balancer during backup
	
	// Replica set backup
	PreferSecondary     bool          `yaml:"prefer_secondary" json:"prefer_secondary"`
	ReadPreference      string        `yaml:"read_preference" json:"read_preference"`     // primary, secondary, nearest
	
	// Backup scheduling
	BackupSchedule      string        `yaml:"backup_schedule" json:"backup_schedule"`
	OplogSchedule       string        `yaml:"oplog_schedule" json:"oplog_schedule"`
	
	// Advanced options
	Archive             bool          `yaml:"archive" json:"archive"`
	Gzip                bool          `yaml:"gzip" json:"gzip"`
	NumParallelCollections int        `yaml:"num_parallel_collections" json:"num_parallel_collections"`
}

// RedisBackupConfig defines Redis-specific backup settings
type RedisBackupConfig struct {
	BackupMethod        string        `yaml:"backup_method" json:"backup_method"`         // rdb, aof, both
	RDBSchedule         string        `yaml:"rdb_schedule" json:"rdb_schedule"`
	AOFRewrite          bool          `yaml:"aof_rewrite" json:"aof_rewrite"`
	AOFRewriteSchedule  string        `yaml:"aof_rewrite_schedule" json:"aof_rewrite_schedule"`
	
	// Cluster backup
	ClusterBackup       bool          `yaml:"cluster_backup" json:"cluster_backup"`
	MasterOnly          bool          `yaml:"master_only" json:"master_only"`
	
	// Stream backup for real-time scenarios
	StreamBackup        bool          `yaml:"stream_backup" json:"stream_backup"`
	StreamRetention     time.Duration `yaml:"stream_retention" json:"stream_retention"`
	
	// Performance
	BackgroundSave      bool          `yaml:"background_save" json:"background_save"`
	CompressionEnabled  bool          `yaml:"compression_enabled" json:"compression_enabled"`
}

// ElasticsearchBackupConfig defines Elasticsearch-specific backup settings
type ElasticsearchBackupConfig struct {
	SnapshotRepository  string        `yaml:"snapshot_repository" json:"snapshot_repository"`
	SnapshotSchedule    string        `yaml:"snapshot_schedule" json:"snapshot_schedule"`
	IndexPattern        string        `yaml:"index_pattern" json:"index_pattern"`           // Indices to backup
	
	// Snapshot settings
	PartialSnapshots    bool          `yaml:"partial_snapshots" json:"partial_snapshots"`
	IncludeGlobalState  bool          `yaml:"include_global_state" json:"include_global_state"`
	IgnoreUnavailable   bool          `yaml:"ignore_unavailable" json:"ignore_unavailable"`
	
	// Cross-cluster replication for DR
	CCREnabled          bool          `yaml:"ccr_enabled" json:"ccr_enabled"`
	FollowerClusters    []string      `yaml:"follower_clusters" json:"follower_clusters"`
	ReplicationDelay    time.Duration `yaml:"replication_delay" json:"replication_delay"`
	
	// ILM integration
	ILMSnapshots        bool          `yaml:"ilm_snapshots" json:"ilm_snapshots"`
	SnapshotLifecycle   string        `yaml:"snapshot_lifecycle" json:"snapshot_lifecycle"`
}

// ReplicaConfig defines configuration for database replicas
type ReplicaConfig struct {
	Host                string        `yaml:"host" json:"host"`
	Port                int           `yaml:"port" json:"port"`
	Role                string        `yaml:"role" json:"role"`                     // sync, async, potential
	Priority            int           `yaml:"priority" json:"priority"`
	ReplicationDelay    time.Duration `yaml:"replication_delay" json:"replication_delay"`
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`
}

// DefaultConfig returns production-ready defaults for iSECTECH platform
func DefaultConfig() *Config {
	return &Config{
		BackupRetention: BackupRetentionConfig{
			TopSecretRetention:     10 * 365 * 24 * time.Hour, // 10 years
			SecretRetention:        7 * 365 * 24 * time.Hour,  // 7 years
			ConfidentialRetention:  5 * 365 * 24 * time.Hour,  // 5 years
			UnclassifiedRetention:  3 * 365 * 24 * time.Hour,  // 3 years
			DailyBackupRetention:   90 * 24 * time.Hour,       // 90 days
			WeeklyBackupRetention:  365 * 24 * time.Hour,      // 1 year
			MonthlyBackupRetention: 7 * 365 * 24 * time.Hour,  // 7 years
			ArchiveAfter:           365 * 24 * time.Hour,      // 1 year
			ArchiveStorage:         "glacier",
			ArchiveCompress:        true,
		},
		Security: BackupSecurityConfig{
			EncryptionEnabled:    true,
			EncryptionAlgorithm:  "AES-256-GCM",
			KeyProvider:          "vault",
			KeyRotationInterval:  90 * 24 * time.Hour, // 90 days
			RequireMultiAuth:     true,
			AuditAllOperations:   true,
			ChecksumAlgorithm:    "SHA-256",
			VerifyOnRestore:      true,
			VerifyAfterBackup:    true,
		},
		Storage: BackupStorageConfig{
			Primary: StorageBackendConfig{
				Type:               "gcs", // Google Cloud Storage preferred
				MultipartThreshold: 100 * 1024 * 1024, // 100MB
				ChunkSize:          50 * 1024 * 1024,   // 50MB
				MaxConcurrency:     10,
				Timeout:            30 * time.Minute,
				StorageEncryption:  true,
			},
		},
		Monitoring: BackupMonitoringConfig{
			EnableMetrics:       true,
			AlertingEnabled:     true,
			BackupSLA:          4 * time.Hour,    // Max 4 hours for backup
			RestoreSLA:         1 * time.Hour,    // Max 1 hour for restore
			RPO:                15 * time.Minute, // Max 15 min data loss
			RTO:                30 * time.Minute, // Max 30 min downtime
			HealthCheckEnabled: true,
			HealthCheckInterval: 5 * time.Minute,
			MaxFailedChecks:    3,
		},
		DisasterRecovery: DisasterRecoveryConfig{
			Enabled:             true,
			SecondaryRegions:    []string{"us-central1", "europe-west1"},
			ReplicationMode:     "async",
			FailoverThreshold:   5 * time.Minute,
			CrossRegionBackup:   true,
			CrossRegionInterval: 1 * time.Hour,
			AutoFailover:        false, // Manual approval for security
			WarmStandby:         true,
		},
		PostgreSQL: PostgreSQLBackupConfig{
			BackupMode:          "incremental",
			WALArchiving:        true,
			WALRetention:        7 * 24 * time.Hour, // 7 days
			PITREnabled:         true,
			ReplicationSlots:    true,
			SynchronousCommit:   "remote_apply",
			FullBackupSchedule:  "0 2 * * 0",   // Weekly at 2 AM Sunday
			IncrBackupSchedule:  "0 2 * * 1-6", // Daily at 2 AM Mon-Sat
			CompressionMethod:   "zstd",
			ParallelJobs:        4,
			ChecksumPages:       true,
		},
		MongoDB: MongoDBBackupConfig{
			BackupMethod:           "oplog",
			OplogCapture:           true,
			OplogRetention:         7 * 24 * time.Hour, // 7 days
			ShardedBackup:          true,
			ConfigServerBackup:     true,
			BalancerControl:        true,
			PreferSecondary:        true,
			ReadPreference:         "secondary",
			BackupSchedule:         "0 3 * * *", // Daily at 3 AM
			OplogSchedule:          "*/15 * * * *", // Every 15 minutes
			Archive:                true,
			Gzip:                   true,
			NumParallelCollections: 4,
		},
		Redis: RedisBackupConfig{
			BackupMethod:       "both",
			RDBSchedule:        "0 4 * * *", // Daily at 4 AM
			AOFRewrite:         true,
			AOFRewriteSchedule: "0 1 * * *", // Daily at 1 AM
			ClusterBackup:      true,
			MasterOnly:         false,
			StreamBackup:       true,
			StreamRetention:    24 * time.Hour, // 24 hours
			BackgroundSave:     true,
			CompressionEnabled: true,
		},
		Elasticsearch: ElasticsearchBackupConfig{
			SnapshotRepository:  "isectech-snapshots",
			SnapshotSchedule:    "0 5 * * *", // Daily at 5 AM
			IndexPattern:        "security-events-*,threat-intel-*,audit-*",
			PartialSnapshots:    false,
			IncludeGlobalState:  true,
			IgnoreUnavailable:   false,
			CCREnabled:          true,
			ReplicationDelay:    5 * time.Minute,
			ILMSnapshots:        true,
			SnapshotLifecycle:   "30d",
		},
		ParallelBackups:     3,
		CompressionLevel:    6, // Balanced compression
		VerificationEnabled: true,
		MaxRetries:          3,
		RetryDelay:          5 * time.Minute,
		HealthCheckInterval: 1 * time.Minute,
	}
}

// LoadConfig loads backup configuration from file with environment overrides
func LoadConfig(configPath string) (*Config, error) {
	// Implementation would load from YAML/JSON file
	// For now, return default config
	return DefaultConfig(), nil
}

// ValidateConfig validates the backup configuration for compliance and security
func (c *Config) ValidateConfig() []error {
	var errors []error
	
	// Validate encryption is enabled for cybersecurity platform
	if !c.Security.EncryptionEnabled {
		errors = append(errors, fmt.Errorf("encryption must be enabled for cybersecurity platform"))
	}
	
	// Validate retention meets compliance requirements
	if c.BackupRetention.TopSecretRetention < 7*365*24*time.Hour {
		errors = append(errors, fmt.Errorf("top secret data retention must be at least 7 years for compliance"))
	}
	
	// Validate RPO/RTO meet SLA requirements
	if c.Monitoring.RPO > 1*time.Hour {
		errors = append(errors, fmt.Errorf("RPO must be less than 1 hour for cybersecurity platform"))
	}
	
	if c.Monitoring.RTO > 4*time.Hour {
		errors = append(errors, fmt.Errorf("RTO must be less than 4 hours for cybersecurity platform"))
	}
	
	// Validate disaster recovery is enabled
	if !c.DisasterRecovery.Enabled {
		errors = append(errors, fmt.Errorf("disaster recovery must be enabled for production"))
	}
	
	return errors
}