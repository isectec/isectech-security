package backup

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/encryption"
	"github.com/isectech/platform/shared/database/postgres"
)

// PostgreSQLBackup handles PostgreSQL-specific backup operations
type PostgreSQLBackup struct {
	config         PostgreSQLBackupConfig
	client         *postgres.Client
	storageManager *StorageManager
	encryption     *encryption.KeyManager
	logger         *zap.Logger
}

// PostgreSQLBackupMetadata contains PostgreSQL-specific backup metadata
type PostgreSQLBackupMetadata struct {
	LSN            string            `json:"lsn"`              // Log Sequence Number
	WALFiles       []string          `json:"wal_files"`        // Required WAL files
	DatabaseSize   int64             `json:"database_size"`    // Database size in bytes
	StartTime      time.Time         `json:"start_time"`       // Backup start time
	EndTime        time.Time         `json:"end_time"`         // Backup end time
	CompressionMethod string         `json:"compression_method"`
	ShardInfo      map[string]string `json:"shard_info"`       // Shard-specific information
	ReplicaInfo    map[string]string `json:"replica_info"`     // Replica information
	BackupLabel    string            `json:"backup_label"`     // PostgreSQL backup label
	TimelineID     int               `json:"timeline_id"`      // Timeline ID for PITR
	CheckpointLSN  string            `json:"checkpoint_lsn"`   // Checkpoint LSN
}

// NewPostgreSQLBackup creates a new PostgreSQL backup handler
func NewPostgreSQLBackup(
	config PostgreSQLBackupConfig,
	client *postgres.Client,
	storageManager *StorageManager,
	encryption *encryption.KeyManager,
	logger *zap.Logger,
) (*PostgreSQLBackup, error) {
	
	return &PostgreSQLBackup{
		config:         config,
		client:         client,
		storageManager: storageManager,
		encryption:     encryption,
		logger:         logger,
	}, nil
}

// ExecuteBackup performs a PostgreSQL backup operation
func (p *PostgreSQLBackup) ExecuteBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	p.logger.Info("Starting PostgreSQL backup",
		zap.String("operation_id", operation.ID),
		zap.String("type", string(operation.Type)),
	)
	
	switch operation.Type {
	case BackupTypeFull:
		return p.executeFullBackup(ctx, operation)
	case BackupTypeIncremental:
		return p.executeIncrementalBackup(ctx, operation)
	case BackupTypeDifferential:
		return p.executeDifferentialBackup(ctx, operation)
	default:
		return "", "", fmt.Errorf("unsupported backup type: %s", operation.Type)
	}
}

// executeFullBackup performs a full PostgreSQL backup using pg_basebackup
func (p *PostgreSQLBackup) executeFullBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// Create backup directory
	backupDir := filepath.Join("backups", "postgresql", operation.ID)
	backupPath := filepath.Join(backupDir, "base.tar")
	
	// Prepare pg_basebackup command
	args := []string{
		"pg_basebackup",
		"-D", backupDir,
		"-F", "tar",
		"-z",                    // Enable compression
		"-P",                    // Show progress
		"-v",                    // Verbose output
		"-X", "stream",          // Include required WAL files
		"-l", operation.ID,      // Backup label
	}
	
	// Add compression method
	if p.config.CompressionMethod != "" {
		args = append(args, "--compress", p.config.CompressionMethod)
	}
	
	// Add parallel jobs
	if p.config.ParallelJobs > 1 {
		args = append(args, "-j", strconv.Itoa(p.config.ParallelJobs))
	}
	
	// Add checksum pages
	if p.config.ChecksumPages {
		args = append(args, "--checksum-pages")
	}
	
	// Execute backup command
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	
	// Set up environment variables for connection
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PGHOST=%s", p.client.GetHost()),
		fmt.Sprintf("PGPORT=%d", p.client.GetPort()),
		fmt.Sprintf("PGUSER=%s", p.client.GetUser()),
		fmt.Sprintf("PGDATABASE=%s", p.client.GetDatabase()),
	)
	
	// Execute with progress monitoring
	progressCh := make(chan float64, 100)
	go p.monitorProgress(progressCh, operation)
	
	output, err := cmd.CombinedOutput()
	close(progressCh)
	
	if err != nil {
		p.logger.Error("pg_basebackup failed",
			zap.String("operation_id", operation.ID),
			zap.ByteString("output", output),
			zap.Error(err),
		)
		return "", "", fmt.Errorf("pg_basebackup failed: %w", err)
	}
	
	// Collect backup metadata
	metadata, err := p.collectBackupMetadata(ctx, backupDir, operation)
	if err != nil {
		return "", "", fmt.Errorf("failed to collect backup metadata: %w", err)
	}
	
	operation.Metadata["postgresql"] = metadata
	operation.Size = metadata.DatabaseSize
	
	// Archive WAL files if configured
	if p.config.WALArchiving {
		if err := p.archiveWALFiles(ctx, metadata.WALFiles, backupDir); err != nil {
			p.logger.Warn("Failed to archive WAL files", zap.Error(err))
		}
	}
	
	// Encrypt backup if required
	if operation.EncryptionKeyID != "" {
		encryptedPath, err := p.encryptBackup(ctx, backupPath, operation.EncryptionKeyID)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		backupPath = encryptedPath
	}
	
	// Upload to storage
	storagePath, err := p.storageManager.Upload(ctx, backupPath, "postgresql", operation.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to upload backup: %w", err)
	}
	
	// Calculate checksum
	checksum, err := p.storageManager.CalculateChecksum(ctx, storagePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Clean up local backup files
	if err := os.RemoveAll(backupDir); err != nil {
		p.logger.Warn("Failed to clean up local backup files", zap.Error(err))
	}
	
	p.logger.Info("PostgreSQL full backup completed",
		zap.String("operation_id", operation.ID),
		zap.String("storage_path", storagePath),
		zap.String("checksum", checksum),
		zap.Int64("size", metadata.DatabaseSize),
	)
	
	return storagePath, checksum, nil
}

// executeIncrementalBackup performs an incremental backup using WAL files
func (p *PostgreSQLBackup) executeIncrementalBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// Get the last backup LSN for incremental backup
	lastBackupLSN, err := p.getLastBackupLSN(ctx, operation.TenantContext)
	if err != nil {
		return "", "", fmt.Errorf("failed to get last backup LSN: %w", err)
	}
	
	if lastBackupLSN == "" {
		// No previous backup, perform full backup instead
		p.logger.Info("No previous backup found, performing full backup instead",
			zap.String("operation_id", operation.ID),
		)
		return p.executeFullBackup(ctx, operation)
	}
	
	// Archive WAL files since last backup
	walFiles, err := p.getWALFilesSince(ctx, lastBackupLSN)
	if err != nil {
		return "", "", fmt.Errorf("failed to get WAL files: %w", err)
	}
	
	if len(walFiles) == 0 {
		return "", "", fmt.Errorf("no WAL files found since last backup")
	}
	
	// Create backup directory
	backupDir := filepath.Join("backups", "postgresql", operation.ID)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Archive WAL files
	walBackupPath := filepath.Join(backupDir, "wal-archive.tar")
	if err := p.createWALArchive(ctx, walFiles, walBackupPath); err != nil {
		return "", "", fmt.Errorf("failed to create WAL archive: %w", err)
	}
	
	// Collect metadata
	metadata := &PostgreSQLBackupMetadata{
		WALFiles:          walFiles,
		StartTime:         operation.StartTime,
		EndTime:           time.Now(),
		CompressionMethod: p.config.CompressionMethod,
		BackupLabel:       operation.ID,
	}
	
	// Get current LSN
	currentLSN, err := p.getCurrentLSN(ctx)
	if err != nil {
		p.logger.Warn("Failed to get current LSN", zap.Error(err))
	} else {
		metadata.LSN = currentLSN
	}
	
	operation.Metadata["postgresql"] = metadata
	
	// Get file size
	fileInfo, err := os.Stat(walBackupPath)
	if err == nil {
		operation.Size = fileInfo.Size()
	}
	
	// Encrypt backup if required
	if operation.EncryptionKeyID != "" {
		encryptedPath, err := p.encryptBackup(ctx, walBackupPath, operation.EncryptionKeyID)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		walBackupPath = encryptedPath
	}
	
	// Upload to storage
	storagePath, err := p.storageManager.Upload(ctx, walBackupPath, "postgresql", operation.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to upload backup: %w", err)
	}
	
	// Calculate checksum
	checksum, err := p.storageManager.CalculateChecksum(ctx, storagePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Clean up local files
	if err := os.RemoveAll(backupDir); err != nil {
		p.logger.Warn("Failed to clean up local backup files", zap.Error(err))
	}
	
	p.logger.Info("PostgreSQL incremental backup completed",
		zap.String("operation_id", operation.ID),
		zap.String("storage_path", storagePath),
		zap.String("last_lsn", lastBackupLSN),
		zap.String("current_lsn", currentLSN),
		zap.Int("wal_files", len(walFiles)),
	)
	
	return storagePath, checksum, nil
}

// executeDifferentialBackup performs a differential backup
func (p *PostgreSQLBackup) executeDifferentialBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// For PostgreSQL, differential backup is similar to incremental
	// but includes all changes since the last full backup
	return p.executeIncrementalBackup(ctx, operation)
}

// collectBackupMetadata collects metadata about the backup
func (p *PostgreSQLBackup) collectBackupMetadata(ctx context.Context, backupDir string, operation *BackupOperation) (*PostgreSQLBackupMetadata, error) {
	metadata := &PostgreSQLBackupMetadata{
		StartTime:         operation.StartTime,
		EndTime:           time.Now(),
		CompressionMethod: p.config.CompressionMethod,
		BackupLabel:       operation.ID,
		ShardInfo:         make(map[string]string),
		ReplicaInfo:       make(map[string]string),
	}
	
	// Get current LSN
	currentLSN, err := p.getCurrentLSN(ctx)
	if err != nil {
		p.logger.Warn("Failed to get current LSN", zap.Error(err))
	} else {
		metadata.LSN = currentLSN
	}
	
	// Get checkpoint LSN
	checkpointLSN, err := p.getCheckpointLSN(ctx)
	if err != nil {
		p.logger.Warn("Failed to get checkpoint LSN", zap.Error(err))
	} else {
		metadata.CheckpointLSN = checkpointLSN
	}
	
	// Get timeline ID
	timelineID, err := p.getTimelineID(ctx)
	if err != nil {
		p.logger.Warn("Failed to get timeline ID", zap.Error(err))
	} else {
		metadata.TimelineID = timelineID
	}
	
	// Calculate database size
	size, err := p.getDatabaseSize(ctx)
	if err != nil {
		p.logger.Warn("Failed to get database size", zap.Error(err))
	} else {
		metadata.DatabaseSize = size
	}
	
	// Read backup label file if it exists
	labelPath := filepath.Join(backupDir, "backup_label")
	if labelData, err := os.ReadFile(labelPath); err == nil {
		metadata.BackupLabel = string(labelData)
	}
	
	return metadata, nil
}

// Helper methods for PostgreSQL operations

func (p *PostgreSQLBackup) getCurrentLSN(ctx context.Context) (string, error) {
	rows, err := p.client.Query(ctx, "SELECT pg_current_wal_lsn()", nil, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	
	if rows.Next() {
		var lsn string
		if err := rows.Scan(&lsn); err != nil {
			return "", err
		}
		return lsn, nil
	}
	
	return "", fmt.Errorf("no LSN returned")
}

func (p *PostgreSQLBackup) getCheckpointLSN(ctx context.Context) (string, error) {
	rows, err := p.client.Query(ctx, "SELECT checkpoint_lsn FROM pg_control_checkpoint()", nil, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	
	if rows.Next() {
		var lsn string
		if err := rows.Scan(&lsn); err != nil {
			return "", err
		}
		return lsn, nil
	}
	
	return "", fmt.Errorf("no checkpoint LSN returned")
}

func (p *PostgreSQLBackup) getTimelineID(ctx context.Context) (int, error) {
	rows, err := p.client.Query(ctx, "SELECT timeline_id FROM pg_control_checkpoint()", nil, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	
	if rows.Next() {
		var timelineID int
		if err := rows.Scan(&timelineID); err != nil {
			return 0, err
		}
		return timelineID, nil
	}
	
	return 0, fmt.Errorf("no timeline ID returned")
}

func (p *PostgreSQLBackup) getDatabaseSize(ctx context.Context) (int64, error) {
	rows, err := p.client.Query(ctx, "SELECT pg_database_size(current_database())", nil, nil)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	
	if rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return 0, err
		}
		return size, nil
	}
	
	return 0, fmt.Errorf("no database size returned")
}

func (p *PostgreSQLBackup) getLastBackupLSN(ctx context.Context, tenant *TenantContext) (string, error) {
	// This would query a backup metadata table to get the last backup's LSN
	// For now, return empty string to indicate no previous backup
	return "", nil
}

func (p *PostgreSQLBackup) getWALFilesSince(ctx context.Context, lsn string) ([]string, error) {
	// Query to get WAL files since the given LSN
	query := `
		SELECT DISTINCT name
		FROM pg_ls_waldir()
		WHERE name ~ '^[0-9A-F]{24}$'
		AND name >= pg_walfile_name($1)
		ORDER BY name
	`
	
	rows, err := p.client.Query(ctx, query, []interface{}{lsn}, nil)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	var walFiles []string
	for rows.Next() {
		var fileName string
		if err := rows.Scan(&fileName); err != nil {
			return nil, err
		}
		walFiles = append(walFiles, fileName)
	}
	
	return walFiles, nil
}

func (p *PostgreSQLBackup) createWALArchive(ctx context.Context, walFiles []string, outputPath string) error {
	// Create tar archive of WAL files
	cmd := exec.CommandContext(ctx, "tar", append([]string{"-czf", outputPath}, walFiles...)...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create WAL archive: %w", err)
	}
	return nil
}

func (p *PostgreSQLBackup) archiveWALFiles(ctx context.Context, walFiles []string, backupDir string) error {
	walDir := filepath.Join(backupDir, "wal")
	if err := os.MkdirAll(walDir, 0755); err != nil {
		return err
	}
	
	for _, walFile := range walFiles {
		srcPath := filepath.Join(p.getWALDirectory(), walFile)
		dstPath := filepath.Join(walDir, walFile)
		
		if err := p.copyFile(srcPath, dstPath); err != nil {
			p.logger.Warn("Failed to archive WAL file",
				zap.String("file", walFile),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

func (p *PostgreSQLBackup) getWALDirectory() string {
	// This would typically be obtained from PostgreSQL configuration
	// For now, use default location
	return "/var/lib/postgresql/data/pg_wal"
}

func (p *PostgreSQLBackup) copyFile(src, dst string) error {
	cmd := exec.Command("cp", src, dst)
	return cmd.Run()
}

func (p *PostgreSQLBackup) encryptBackup(ctx context.Context, backupPath, keyID string) (string, error) {
	encryptedPath := backupPath + ".enc"
	
	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return "", err
	}
	
	// Encrypt data
	encryptedData, err := p.encryption.EncryptData(ctx, data, keyID, nil)
	if err != nil {
		return "", err
	}
	
	// Write encrypted data
	if err := os.WriteFile(encryptedPath, encryptedData, 0644); err != nil {
		return "", err
	}
	
	// Remove original file
	if err := os.Remove(backupPath); err != nil {
		p.logger.Warn("Failed to remove original backup file", zap.Error(err))
	}
	
	return encryptedPath, nil
}

func (p *PostgreSQLBackup) monitorProgress(progressCh <-chan float64, operation *BackupOperation) {
	for progress := range progressCh {
		operation.Progress = progress
	}
}

// RestoreBackup restores a PostgreSQL backup
func (p *PostgreSQLBackup) RestoreBackup(ctx context.Context, backupID string, targetTime *time.Time, tenant *TenantContext) error {
	p.logger.Info("Starting PostgreSQL restore",
		zap.String("backup_id", backupID),
		zap.Time("target_time", func() time.Time {
			if targetTime != nil {
				return *targetTime
			}
			return time.Time{}
		}()),
	)
	
	// Download backup from storage
	localPath, err := p.storageManager.Download(ctx, backupID, "postgresql")
	if err != nil {
		return fmt.Errorf("failed to download backup: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(localPath))
	
	// Decrypt if necessary
	if strings.HasSuffix(localPath, ".enc") {
		decryptedPath, err := p.decryptBackup(ctx, localPath, tenant)
		if err != nil {
			return fmt.Errorf("failed to decrypt backup: %w", err)
		}
		localPath = decryptedPath
	}
	
	// Stop PostgreSQL service
	if err := p.stopPostgreSQL(); err != nil {
		return fmt.Errorf("failed to stop PostgreSQL: %w", err)
	}
	
	// Extract backup
	dataDir := p.getDataDirectory()
	if err := p.extractBackup(localPath, dataDir); err != nil {
		return fmt.Errorf("failed to extract backup: %w", err)
	}
	
	// Configure recovery if PITR is enabled and target time is specified
	if targetTime != nil && p.config.PITREnabled {
		if err := p.configurePointInTimeRecovery(*targetTime); err != nil {
			return fmt.Errorf("failed to configure PITR: %w", err)
		}
	}
	
	// Start PostgreSQL service
	if err := p.startPostgreSQL(); err != nil {
		return fmt.Errorf("failed to start PostgreSQL: %w", err)
	}
	
	p.logger.Info("PostgreSQL restore completed successfully",
		zap.String("backup_id", backupID),
	)
	
	return nil
}

func (p *PostgreSQLBackup) decryptBackup(ctx context.Context, encryptedPath string, tenant *TenantContext) (string, error) {
	// Read encrypted data
	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return "", err
	}
	
	// Find appropriate key ID (this would be stored in backup metadata)
	keyID := "backup-key" // Placeholder
	
	// Decrypt data
	decryptedData, err := p.encryption.DecryptData(ctx, encryptedData, keyID, nil)
	if err != nil {
		return "", err
	}
	
	// Write decrypted data
	decryptedPath := strings.TrimSuffix(encryptedPath, ".enc")
	if err := os.WriteFile(decryptedPath, decryptedData, 0644); err != nil {
		return "", err
	}
	
	return decryptedPath, nil
}

func (p *PostgreSQLBackup) stopPostgreSQL() error {
	cmd := exec.Command("systemctl", "stop", "postgresql")
	return cmd.Run()
}

func (p *PostgreSQLBackup) startPostgreSQL() error {
	cmd := exec.Command("systemctl", "start", "postgresql")
	return cmd.Run()
}

func (p *PostgreSQLBackup) getDataDirectory() string {
	// This would typically be obtained from PostgreSQL configuration
	return "/var/lib/postgresql/data"
}

func (p *PostgreSQLBackup) extractBackup(backupPath, dataDir string) error {
	cmd := exec.Command("tar", "-xzf", backupPath, "-C", dataDir)
	return cmd.Run()
}

func (p *PostgreSQLBackup) configurePointInTimeRecovery(targetTime time.Time) error {
	// Create recovery configuration for PITR
	recoveryConf := fmt.Sprintf(`
restore_command = 'cp /path/to/wal/%%f "%%p"'
recovery_target_time = '%s'
recovery_target_action = 'promote'
`, targetTime.Format("2006-01-02 15:04:05"))
	
	confPath := filepath.Join(p.getDataDirectory(), "recovery.signal")
	return os.WriteFile(confPath, []byte(recoveryConf), 0644)
}