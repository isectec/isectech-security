package backup

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/encryption"
	"github.com/isectech/platform/shared/database/postgres"
	"github.com/isectech/platform/shared/database/mongodb"
	"github.com/isectech/platform/shared/database/redis"
	"github.com/isectech/platform/shared/database/elasticsearch"
)

// Manager orchestrates backup and recovery operations across all databases
type Manager struct {
	config     *Config
	logger     *zap.Logger
	encryption *encryption.KeyManager
	
	// Database clients
	postgresql    *postgres.Client
	mongodb       *mongodb.Client
	redis         *redis.Client
	elasticsearch *elasticsearch.Client
	
	// Backup executors
	postgresBackup    *PostgreSQLBackup
	mongoBackup       *MongoDBBackup
	redisBackup       *RedisBackup
	elasticsearchBackup *ElasticsearchBackup
	
	// Storage backends
	storageManager    *StorageManager
	
	// Monitoring and metrics
	metrics           *BackupMetrics
	healthMonitor     *HealthMonitor
	
	// Coordination
	scheduler         *BackupScheduler
	recoveryManager   *RecoveryManager
	drManager         *DisasterRecoveryManager
	
	// State management
	activeBackups     map[string]*BackupOperation
	backupHistory     []*BackupRecord
	mu                sync.RWMutex
	closed            bool
	shutdownCh        chan struct{}
	wg                sync.WaitGroup
}

// BackupOperation represents an ongoing backup operation
type BackupOperation struct {
	ID            string                 `json:"id"`
	Database      string                 `json:"database"`
	Type          BackupType             `json:"type"`
	Status        BackupStatus           `json:"status"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Progress      float64                `json:"progress"`
	Size          int64                  `json:"size"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
	TenantContext *TenantContext         `json:"tenant_context,omitempty"`
	
	// Security context
	SecurityClassification string `json:"security_classification"`
	EncryptionKeyID        string `json:"encryption_key_id,omitempty"`
}

// BackupRecord represents a completed backup operation
type BackupRecord struct {
	Operation     *BackupOperation `json:"operation"`
	BackupPath    string          `json:"backup_path"`
	Checksum      string          `json:"checksum"`
	Compressed    bool            `json:"compressed"`
	Encrypted     bool            `json:"encrypted"`
	RetentionDate time.Time       `json:"retention_date"`
	Verified      bool            `json:"verified"`
	
	// Recovery information
	RecoveryProcedure string                 `json:"recovery_procedure"`
	Dependencies      []string               `json:"dependencies"`
	RecoveryMetadata  map[string]interface{} `json:"recovery_metadata"`
}

// TenantContext provides multi-tenant isolation for backups
type TenantContext struct {
	TenantID           string `json:"tenant_id"`
	SecurityClearance  string `json:"security_clearance"`
	DataClassification string `json:"data_classification"`
	ComplianceLevel    string `json:"compliance_level"`
}

// BackupType defines the type of backup operation
type BackupType string

const (
	BackupTypeFull        BackupType = "full"
	BackupTypeIncremental BackupType = "incremental"
	BackupTypeDifferential BackupType = "differential"
	BackupTypeSnapshot    BackupType = "snapshot"
	BackupTypeStreaming   BackupType = "streaming"
)

// BackupStatus defines the status of a backup operation
type BackupStatus string

const (
	BackupStatusPending    BackupStatus = "pending"
	BackupStatusRunning    BackupStatus = "running"
	BackupStatusCompleted  BackupStatus = "completed"
	BackupStatusFailed     BackupStatus = "failed"
	BackupStatusCancelled  BackupStatus = "cancelled"
	BackupStatusVerifying  BackupStatus = "verifying"
	BackupStatusArchiving  BackupStatus = "archiving"
)

// NewManager creates a new backup manager with all required components
func NewManager(
	config *Config,
	logger *zap.Logger,
	encryption *encryption.KeyManager,
	postgresql *postgres.Client,
	mongodb *mongodb.Client,
	redis *redis.Client,
	elasticsearch *elasticsearch.Client,
) (*Manager, error) {
	
	// Initialize storage manager
	storageManager, err := NewStorageManager(config.Storage, encryption, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage manager: %w", err)
	}
	
	// Initialize backup executors
	postgresBackup, err := NewPostgreSQLBackup(config.PostgreSQL, postgresql, storageManager, encryption, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PostgreSQL backup: %w", err)
	}
	
	mongoBackup, err := NewMongoDBBackup(config.MongoDB, mongodb, storageManager, encryption, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MongoDB backup: %w", err)
	}
	
	redisBackup, err := NewRedisBackup(config.Redis, redis, storageManager, encryption, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Redis backup: %w", err)
	}
	
	elasticsearchBackup, err := NewElasticsearchBackup(config.Elasticsearch, elasticsearch, storageManager, encryption, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Elasticsearch backup: %w", err)
	}
	
	// Initialize monitoring components
	metrics := NewBackupMetrics(logger)
	healthMonitor := NewHealthMonitor(config.Monitoring, metrics, logger)
	
	// Initialize coordination components
	scheduler := NewBackupScheduler(config, logger)
	recoveryManager := NewRecoveryManager(config, storageManager, encryption, logger)
	drManager := NewDisasterRecoveryManager(config.DisasterRecovery, logger)
	
	manager := &Manager{
		config:              config,
		logger:              logger,
		encryption:          encryption,
		postgresql:          postgresql,
		mongodb:             mongodb,
		redis:               redis,
		elasticsearch:       elasticsearch,
		postgresBackup:      postgresBackup,
		mongoBackup:         mongoBackup,
		redisBackup:         redisBackup,
		elasticsearchBackup: elasticsearchBackup,
		storageManager:      storageManager,
		metrics:             metrics,
		healthMonitor:       healthMonitor,
		scheduler:           scheduler,
		recoveryManager:     recoveryManager,
		drManager:           drManager,
		activeBackups:       make(map[string]*BackupOperation),
		backupHistory:       make([]*BackupRecord, 0),
		shutdownCh:          make(chan struct{}),
	}
	
	// Start background processes
	manager.wg.Add(3)
	go manager.runScheduler()
	go manager.runHealthMonitor()
	go manager.runMetricsCollector()
	
	logger.Info("Backup manager initialized successfully",
		zap.Bool("encryption_enabled", config.Security.EncryptionEnabled),
		zap.Bool("dr_enabled", config.DisasterRecovery.Enabled),
		zap.Duration("backup_sla", config.Monitoring.BackupSLA),
		zap.Duration("restore_sla", config.Monitoring.RestoreSLA),
	)
	
	return manager, nil
}

// BackupDatabase performs a backup of the specified database
func (m *Manager) BackupDatabase(ctx context.Context, database string, backupType BackupType, tenant *TenantContext) (*BackupOperation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.closed {
		return nil, fmt.Errorf("backup manager is closed")
	}
	
	// Generate backup operation ID
	operationID := fmt.Sprintf("%s-%s-%d", database, backupType, time.Now().Unix())
	
	// Create backup operation
	operation := &BackupOperation{
		ID:            operationID,
		Database:      database,
		Type:          backupType,
		Status:        BackupStatusPending,
		StartTime:     time.Now(),
		Progress:      0.0,
		Metadata:      make(map[string]interface{}),
		TenantContext: tenant,
	}
	
	// Set security classification based on tenant context
	if tenant != nil {
		operation.SecurityClassification = tenant.DataClassification
		
		// Generate encryption key for this backup
		if m.config.Security.EncryptionEnabled {
			keyID, err := m.encryption.GenerateKey(ctx, fmt.Sprintf("backup-%s", operationID), "data-encryption", tenant.TenantID)
			if err != nil {
				return nil, fmt.Errorf("failed to generate encryption key: %w", err)
			}
			operation.EncryptionKeyID = keyID
		}
	}
	
	// Store active backup operation
	m.activeBackups[operationID] = operation
	
	// Start backup operation asynchronously
	go m.executeBackup(ctx, operation)
	
	m.logger.Info("Started backup operation",
		zap.String("operation_id", operationID),
		zap.String("database", database),
		zap.String("type", string(backupType)),
		zap.String("tenant_id", func() string {
			if tenant != nil {
				return tenant.TenantID
			}
			return "system"
		}()),
	)
	
	return operation, nil
}

// executeBackup performs the actual backup operation
func (m *Manager) executeBackup(ctx context.Context, operation *BackupOperation) {
	defer func() {
		m.mu.Lock()
		delete(m.activeBackups, operation.ID)
		m.mu.Unlock()
	}()
	
	// Update operation status
	operation.Status = BackupStatusRunning
	
	// Record start metrics
	m.metrics.RecordBackupStart(operation.Database, string(operation.Type))
	
	var err error
	var backupPath string
	var checksum string
	
	// Execute database-specific backup
	switch operation.Database {
	case "postgresql":
		backupPath, checksum, err = m.postgresBackup.ExecuteBackup(ctx, operation)
	case "mongodb":
		backupPath, checksum, err = m.mongoBackup.ExecuteBackup(ctx, operation)
	case "redis":
		backupPath, checksum, err = m.redisBackup.ExecuteBackup(ctx, operation)
	case "elasticsearch":
		backupPath, checksum, err = m.elasticsearchBackup.ExecuteBackup(ctx, operation)
	default:
		err = fmt.Errorf("unsupported database: %s", operation.Database)
	}
	
	// Update operation status based on result
	now := time.Now()
	operation.EndTime = &now
	
	if err != nil {
		operation.Status = BackupStatusFailed
		operation.ErrorMessage = err.Error()
		m.metrics.RecordBackupFailure(operation.Database, string(operation.Type), err.Error())
		m.logger.Error("Backup operation failed",
			zap.String("operation_id", operation.ID),
			zap.String("database", operation.Database),
			zap.Error(err),
		)
		return
	}
	
	// Verify backup if enabled
	if m.config.Security.VerifyAfterBackup {
		operation.Status = BackupStatusVerifying
		if err := m.verifyBackup(ctx, backupPath, checksum); err != nil {
			operation.Status = BackupStatusFailed
			operation.ErrorMessage = fmt.Sprintf("backup verification failed: %v", err)
			m.metrics.RecordBackupFailure(operation.Database, string(operation.Type), "verification_failed")
			return
		}
	}
	
	operation.Status = BackupStatusCompleted
	operation.Progress = 100.0
	
	// Create backup record
	record := &BackupRecord{
		Operation:  operation,
		BackupPath: backupPath,
		Checksum:   checksum,
		Compressed: true, // Based on config
		Encrypted:  m.config.Security.EncryptionEnabled,
		Verified:   m.config.Security.VerifyAfterBackup,
	}
	
	// Set retention date based on security classification
	record.RetentionDate = m.calculateRetentionDate(operation.SecurityClassification)
	
	// Store backup record
	m.mu.Lock()
	m.backupHistory = append(m.backupHistory, record)
	m.mu.Unlock()
	
	// Record success metrics
	duration := operation.EndTime.Sub(operation.StartTime)
	m.metrics.RecordBackupSuccess(operation.Database, string(operation.Type), duration, operation.Size)
	
	m.logger.Info("Backup operation completed successfully",
		zap.String("operation_id", operation.ID),
		zap.String("database", operation.Database),
		zap.String("backup_path", backupPath),
		zap.Duration("duration", duration),
		zap.Int64("size_bytes", operation.Size),
	)
}

// RestoreDatabase restores a database from a backup
func (m *Manager) RestoreDatabase(ctx context.Context, database string, backupID string, targetTime *time.Time, tenant *TenantContext) error {
	return m.recoveryManager.RestoreDatabase(ctx, database, backupID, targetTime, tenant)
}

// ListBackups returns a list of available backups
func (m *Manager) ListBackups(database string, tenant *TenantContext) ([]*BackupRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var filtered []*BackupRecord
	
	for _, record := range m.backupHistory {
		// Filter by database
		if database != "" && record.Operation.Database != database {
			continue
		}
		
		// Filter by tenant context
		if tenant != nil && record.Operation.TenantContext != nil {
			if record.Operation.TenantContext.TenantID != tenant.TenantID {
				continue
			}
			
			// Security clearance check
			if !m.hasSecurityClearance(tenant.SecurityClearance, record.Operation.SecurityClassification) {
				continue
			}
		}
		
		filtered = append(filtered, record)
	}
	
	return filtered, nil
}

// GetActiveBackups returns currently running backup operations
func (m *Manager) GetActiveBackups() []*BackupOperation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	operations := make([]*BackupOperation, 0, len(m.activeBackups))
	for _, op := range m.activeBackups {
		operations = append(operations, op)
	}
	
	return operations
}

// GetHealthStatus returns the health status of the backup system
func (m *Manager) GetHealthStatus() *HealthStatus {
	return m.healthMonitor.GetHealthStatus()
}

// GetMetrics returns backup system metrics
func (m *Manager) GetMetrics() *BackupMetricsData {
	return m.metrics.GetMetrics()
}

// TriggerDisasterRecovery initiates disaster recovery procedures
func (m *Manager) TriggerDisasterRecovery(ctx context.Context, scenario string) error {
	return m.drManager.TriggerRecovery(ctx, scenario)
}

// Close gracefully shuts down the backup manager
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
	
	// Close all components
	if err := m.storageManager.Close(); err != nil {
		m.logger.Error("Failed to close storage manager", zap.Error(err))
	}
	
	if err := m.healthMonitor.Close(); err != nil {
		m.logger.Error("Failed to close health monitor", zap.Error(err))
	}
	
	m.logger.Info("Backup manager closed successfully")
	return nil
}

// Private helper methods

func (m *Manager) runScheduler() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.scheduler.CheckScheduledBackups(context.Background())
		case <-m.shutdownCh:
			return
		}
	}
}

func (m *Manager) runHealthMonitor() {
	defer m.wg.Done()
	m.healthMonitor.Start(m.shutdownCh)
}

func (m *Manager) runMetricsCollector() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			m.metrics.CollectSystemMetrics()
		case <-m.shutdownCh:
			return
		}
	}
}

func (m *Manager) verifyBackup(ctx context.Context, backupPath, expectedChecksum string) error {
	return m.storageManager.VerifyBackup(ctx, backupPath, expectedChecksum)
}

func (m *Manager) calculateRetentionDate(classification string) time.Time {
	now := time.Now()
	
	switch classification {
	case "TOP_SECRET":
		return now.Add(m.config.BackupRetention.TopSecretRetention)
	case "SECRET":
		return now.Add(m.config.BackupRetention.SecretRetention)
	case "CONFIDENTIAL":
		return now.Add(m.config.BackupRetention.ConfidentialRetention)
	default:
		return now.Add(m.config.BackupRetention.UnclassifiedRetention)
	}
}

func (m *Manager) hasSecurityClearance(userClearance, dataClassification string) bool {
	// Security clearance hierarchy
	clearanceLevel := map[string]int{
		"UNCLASSIFIED": 1,
		"CONFIDENTIAL": 2,
		"SECRET":       3,
		"TOP_SECRET":   4,
	}
	
	userLevel := clearanceLevel[userClearance]
	dataLevel := clearanceLevel[dataClassification]
	
	return userLevel >= dataLevel
}