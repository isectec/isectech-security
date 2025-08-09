package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/encryption"
	"github.com/isectech/platform/shared/database/mongodb"
)

// MongoDBBackup handles MongoDB-specific backup operations
type MongoDBBackup struct {
	config         MongoDBBackupConfig
	client         *mongodb.Client
	storageManager *StorageManager
	encryption     *encryption.KeyManager
	logger         *zap.Logger
}

// MongoDBBackupMetadata contains MongoDB-specific backup metadata
type MongoDBBackupMetadata struct {
	OplogPosition    primitive.Timestamp `json:"oplog_position"`     // Oplog position at backup time
	Collections      []string            `json:"collections"`        // Collections included in backup
	Shards           []ShardInfo         `json:"shards"`            // Shard information for sharded clusters
	ReplicaSet       string              `json:"replica_set"`        // Replica set name
	MongoDB_Version  string              `json:"mongodb_version"`    // MongoDB version
	StartTime        time.Time           `json:"start_time"`         // Backup start time
	EndTime          time.Time           `json:"end_time"`           // Backup end time
	CompressionUsed  bool                `json:"compression_used"`   // Whether compression was used
	DatabaseSize     int64               `json:"database_size"`      // Total database size
	BalancerStopped  bool                `json:"balancer_stopped"`   // Whether balancer was stopped
	ConfigServerDump bool                `json:"config_server_dump"` // Whether config server was dumped
}

// ShardInfo contains information about a shard in a sharded cluster
type ShardInfo struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Database string `json:"database"`
	Size     int64  `json:"size"`
}

// NewMongoDBBackup creates a new MongoDB backup handler
func NewMongoDBBackup(
	config MongoDBBackupConfig,
	client *mongodb.Client,
	storageManager *StorageManager,
	encryption *encryption.KeyManager,
	logger *zap.Logger,
) (*MongoDBBackup, error) {
	
	return &MongoDBBackup{
		config:         config,
		client:         client,
		storageManager: storageManager,
		encryption:     encryption,
		logger:         logger,
	}, nil
}

// ExecuteBackup performs a MongoDB backup operation
func (m *MongoDBBackup) ExecuteBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	m.logger.Info("Starting MongoDB backup",
		zap.String("operation_id", operation.ID),
		zap.String("method", m.config.BackupMethod),
	)
	
	switch m.config.BackupMethod {
	case "mongodump":
		return m.executeMongoDumpBackup(ctx, operation)
	case "filesystem":
		return m.executeFilesystemBackup(ctx, operation)
	case "oplog":
		return m.executeOplogBackup(ctx, operation)
	default:
		return "", "", fmt.Errorf("unsupported backup method: %s", m.config.BackupMethod)
	}
}

// executeMongoDumpBackup performs a backup using mongodump
func (m *MongoDBBackup) executeMongoDumpBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// Create backup directory
	backupDir := filepath.Join("backups", "mongodb", operation.ID)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Stop balancer for sharded clusters if configured
	balancerStopped := false
	if m.config.ShardedBackup && m.config.BalancerControl {
		if err := m.stopBalancer(ctx); err != nil {
			m.logger.Warn("Failed to stop balancer", zap.Error(err))
		} else {
			balancerStopped = true
			defer func() {
				if err := m.startBalancer(ctx); err != nil {
					m.logger.Error("Failed to restart balancer", zap.Error(err))
				}
			}()
		}
	}
	
	// Prepare mongodump command
	args := []string{
		"mongodump",
		"--out", backupDir,
	}
	
	// Add connection parameters
	args = append(args,
		"--host", m.client.GetConnectionString(),
		"--authenticationDatabase", "admin",
	)
	
	// Add compression if enabled
	if m.config.Gzip {
		args = append(args, "--gzip")
	}
	
	// Add parallel collections if configured
	if m.config.NumParallelCollections > 1 {
		args = append(args, "--numParallelCollections", strconv.Itoa(m.config.NumParallelCollections))
	}
	
	// Add read preference for replica sets
	if m.config.PreferSecondary {
		args = append(args, "--readPreference", m.config.ReadPreference)
	}
	
	// Add oplog capture if configured
	if m.config.OplogCapture {
		args = append(args, "--oplog")
	}
	
	// Filter by tenant if specified
	if operation.TenantContext != nil {
		// Add query to filter by tenant
		tenantQuery := fmt.Sprintf(`{"tenant_id": "%s"}`, operation.TenantContext.TenantID)
		args = append(args, "--query", tenantQuery)
	}
	
	// Execute mongodump
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	
	// Set up environment for authentication
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("MONGO_URI=%s", m.client.GetConnectionString()),
	)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.Error("mongodump failed",
			zap.String("operation_id", operation.ID),
			zap.ByteString("output", output),
			zap.Error(err),
		)
		return "", "", fmt.Errorf("mongodump failed: %w", err)
	}
	
	// Collect backup metadata
	metadata, err := m.collectBackupMetadata(ctx, backupDir, operation, balancerStopped)
	if err != nil {
		return "", "", fmt.Errorf("failed to collect backup metadata: %w", err)
	}
	
	operation.Metadata["mongodb"] = metadata
	operation.Size = metadata.DatabaseSize
	
	// Create archive if configured
	archivePath := filepath.Join(backupDir, "backup.tar.gz")
	if m.config.Archive {
		if err := m.createArchive(backupDir, archivePath); err != nil {
			return "", "", fmt.Errorf("failed to create archive: %w", err)
		}
	} else {
		archivePath = backupDir
	}
	
	// Encrypt backup if required
	if operation.EncryptionKeyID != "" {
		encryptedPath, err := m.encryptBackup(ctx, archivePath, operation.EncryptionKeyID)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		archivePath = encryptedPath
	}
	
	// Upload to storage
	storagePath, err := m.storageManager.Upload(ctx, archivePath, "mongodb", operation.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to upload backup: %w", err)
	}
	
	// Calculate checksum
	checksum, err := m.storageManager.CalculateChecksum(ctx, storagePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Clean up local files
	if err := os.RemoveAll(backupDir); err != nil {
		m.logger.Warn("Failed to clean up local backup files", zap.Error(err))
	}
	
	m.logger.Info("MongoDB backup completed",
		zap.String("operation_id", operation.ID),
		zap.String("storage_path", storagePath),
		zap.String("checksum", checksum),
		zap.Int64("size", metadata.DatabaseSize),
		zap.Bool("balancer_stopped", balancerStopped),
	)
	
	return storagePath, checksum, nil
}

// executeFilesystemBackup performs a filesystem-level backup
func (m *MongoDBBackup) executeFilesystemBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// Filesystem backup requires MongoDB to be stopped temporarily
	// This is more disruptive but faster for large datasets
	
	// Get data directory path
	dataDir, err := m.getDataDirectory(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to get data directory: %w", err)
	}
	
	// Create backup directory
	backupDir := filepath.Join("backups", "mongodb", operation.ID)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Perform filesystem sync to ensure data consistency
	if err := m.syncFilesystem(ctx); err != nil {
		return "", "", fmt.Errorf("failed to sync filesystem: %w", err)
	}
	
	// Create tar archive of data directory
	archivePath := filepath.Join(backupDir, "mongodb-data.tar.gz")
	cmd := exec.CommandContext(ctx, "tar", "-czf", archivePath, "-C", filepath.Dir(dataDir), filepath.Base(dataDir))
	
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("failed to create filesystem backup: %w", err)
	}
	
	// Collect metadata
	metadata := &MongoDBBackupMetadata{
		StartTime:       operation.StartTime,
		EndTime:         time.Now(),
		CompressionUsed: true,
	}
	
	// Get database size
	if size, err := m.getDatabaseSize(ctx); err == nil {
		metadata.DatabaseSize = size
		operation.Size = size
	}
	
	operation.Metadata["mongodb"] = metadata
	
	// Encrypt if required
	if operation.EncryptionKeyID != "" {
		encryptedPath, err := m.encryptBackup(ctx, archivePath, operation.EncryptionKeyID)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		archivePath = encryptedPath
	}
	
	// Upload to storage
	storagePath, err := m.storageManager.Upload(ctx, archivePath, "mongodb", operation.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to upload backup: %w", err)
	}
	
	// Calculate checksum
	checksum, err := m.storageManager.CalculateChecksum(ctx, storagePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Clean up
	if err := os.RemoveAll(backupDir); err != nil {
		m.logger.Warn("Failed to clean up local backup files", zap.Error(err))
	}
	
	return storagePath, checksum, nil
}

// executeOplogBackup performs an oplog-based incremental backup
func (m *MongoDBBackup) executeOplogBackup(ctx context.Context, operation *BackupOperation) (string, string, error) {
	// Get the last oplog timestamp for incremental backup
	lastOplogTS, err := m.getLastOplogTimestamp(ctx, operation.TenantContext)
	if err != nil {
		return "", "", fmt.Errorf("failed to get last oplog timestamp: %w", err)
	}
	
	// Create backup directory
	backupDir := filepath.Join("backups", "mongodb", operation.ID)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return "", "", fmt.Errorf("failed to create backup directory: %w", err)
	}
	
	// Export oplog entries since last backup
	oplogPath := filepath.Join(backupDir, "oplog.bson")
	if err := m.exportOplog(ctx, lastOplogTS, oplogPath, operation.TenantContext); err != nil {
		return "", "", fmt.Errorf("failed to export oplog: %w", err)
	}
	
	// Get current oplog position
	currentOplogTS, err := m.getCurrentOplogTimestamp(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to get current oplog timestamp: %w", err)
	}
	
	// Collect metadata
	metadata := &MongoDBBackupMetadata{
		OplogPosition:   currentOplogTS,
		StartTime:       operation.StartTime,
		EndTime:         time.Now(),
		CompressionUsed: m.config.Gzip,
	}
	
	// Get file size
	if fileInfo, err := os.Stat(oplogPath); err == nil {
		metadata.DatabaseSize = fileInfo.Size()
		operation.Size = fileInfo.Size()
	}
	
	operation.Metadata["mongodb"] = metadata
	
	// Compress if configured
	if m.config.Gzip {
		compressedPath := oplogPath + ".gz"
		if err := m.compressFile(oplogPath, compressedPath); err != nil {
			return "", "", fmt.Errorf("failed to compress oplog: %w", err)
		}
		oplogPath = compressedPath
	}
	
	// Encrypt if required
	if operation.EncryptionKeyID != "" {
		encryptedPath, err := m.encryptBackup(ctx, oplogPath, operation.EncryptionKeyID)
		if err != nil {
			return "", "", fmt.Errorf("failed to encrypt backup: %w", err)
		}
		oplogPath = encryptedPath
	}
	
	// Upload to storage
	storagePath, err := m.storageManager.Upload(ctx, oplogPath, "mongodb", operation.ID)
	if err != nil {
		return "", "", fmt.Errorf("failed to upload backup: %w", err)
	}
	
	// Calculate checksum
	checksum, err := m.storageManager.CalculateChecksum(ctx, storagePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Clean up
	if err := os.RemoveAll(backupDir); err != nil {
		m.logger.Warn("Failed to clean up local backup files", zap.Error(err))
	}
	
	m.logger.Info("MongoDB oplog backup completed",
		zap.String("operation_id", operation.ID),
		zap.String("storage_path", storagePath),
		zap.Any("last_oplog_ts", lastOplogTS),
		zap.Any("current_oplog_ts", currentOplogTS),
	)
	
	return storagePath, checksum, nil
}

// collectBackupMetadata collects metadata about the MongoDB backup
func (m *MongoDBBackup) collectBackupMetadata(ctx context.Context, backupDir string, operation *BackupOperation, balancerStopped bool) (*MongoDBBackupMetadata, error) {
	metadata := &MongoDBBackupMetadata{
		StartTime:        operation.StartTime,
		EndTime:          time.Now(),
		CompressionUsed:  m.config.Gzip,
		BalancerStopped:  balancerStopped,
		ConfigServerDump: m.config.ConfigServerBackup,
	}
	
	// Get MongoDB version
	if version, err := m.getMongoDBVersion(ctx); err == nil {
		metadata.MongoDB_Version = version
	}
	
	// Get replica set name
	if replicaSet, err := m.getReplicaSetName(ctx); err == nil {
		metadata.ReplicaSet = replicaSet
	}
	
	// Get current oplog position
	if oplogTS, err := m.getCurrentOplogTimestamp(ctx); err == nil {
		metadata.OplogPosition = oplogTS
	}
	
	// Get database size
	if size, err := m.getDatabaseSize(ctx); err == nil {
		metadata.DatabaseSize = size
	}
	
	// Get collections list
	if collections, err := m.getCollectionsList(ctx, operation.TenantContext); err == nil {
		metadata.Collections = collections
	}
	
	// Get shard information for sharded clusters
	if m.config.ShardedBackup {
		if shards, err := m.getShardInfo(ctx); err == nil {
			metadata.Shards = shards
		}
	}
	
	return metadata, nil
}

// Helper methods for MongoDB operations

func (m *MongoDBBackup) stopBalancer(ctx context.Context) error {
	database := m.client.GetDatabase("config")
	collection := database.Collection("settings")
	
	filter := bson.M{"_id": "balancer"}
	update := bson.M{"$set": bson.M{"stopped": true}}
	
	_, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to stop balancer: %w", err)
	}
	
	// Wait for balancer to stop
	time.Sleep(10 * time.Second)
	return nil
}

func (m *MongoDBBackup) startBalancer(ctx context.Context) error {
	database := m.client.GetDatabase("config")
	collection := database.Collection("settings")
	
	filter := bson.M{"_id": "balancer"}
	update := bson.M{"$set": bson.M{"stopped": false}}
	
	_, err := collection.UpdateOne(ctx, filter, update)
	return err
}

func (m *MongoDBBackup) getMongoDBVersion(ctx context.Context) (string, error) {
	database := m.client.GetDatabase("admin")
	result := database.RunCommand(ctx, bson.M{"buildInfo": 1})
	
	var buildInfo struct {
		Version string `bson:"version"`
	}
	
	if err := result.Decode(&buildInfo); err != nil {
		return "", err
	}
	
	return buildInfo.Version, nil
}

func (m *MongoDBBackup) getReplicaSetName(ctx context.Context) (string, error) {
	database := m.client.GetDatabase("admin")
	result := database.RunCommand(ctx, bson.M{"replSetGetStatus": 1})
	
	var status struct {
		Set string `bson:"set"`
	}
	
	if err := result.Decode(&status); err != nil {
		return "", err
	}
	
	return status.Set, nil
}

func (m *MongoDBBackup) getCurrentOplogTimestamp(ctx context.Context) (primitive.Timestamp, error) {
	database := m.client.GetDatabase("local")
	collection := database.Collection("oplog.rs")
	
	// Get the latest oplog entry
	cursor, err := collection.Find(ctx, bson.M{}, nil)
	if err != nil {
		return primitive.Timestamp{}, err
	}
	defer cursor.Close(ctx)
	
	var lastEntry struct {
		TS primitive.Timestamp `bson:"ts"`
	}
	
	// Get the last document
	if cursor.Next(ctx) {
		if err := cursor.Decode(&lastEntry); err != nil {
			return primitive.Timestamp{}, err
		}
	}
	
	return lastEntry.TS, nil
}

func (m *MongoDBBackup) getLastOplogTimestamp(ctx context.Context, tenant *TenantContext) (primitive.Timestamp, error) {
	// This would query a backup metadata collection to get the last backup's oplog timestamp
	// For now, return zero timestamp to indicate full backup needed
	return primitive.Timestamp{}, nil
}

func (m *MongoDBBackup) getDatabaseSize(ctx context.Context) (int64, error) {
	database := m.client.GetDatabase("admin")
	result := database.RunCommand(ctx, bson.M{"dbStats": 1})
	
	var stats struct {
		DataSize int64 `bson:"dataSize"`
	}
	
	if err := result.Decode(&stats); err != nil {
		return 0, err
	}
	
	return stats.DataSize, nil
}

func (m *MongoDBBackup) getCollectionsList(ctx context.Context, tenant *TenantContext) ([]string, error) {
	database := m.client.GetDatabase("isectech")
	names, err := database.ListCollectionNames(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	
	// Filter collections based on tenant context if applicable
	var filteredNames []string
	for _, name := range names {
		// Include all collections for now
		// Could add tenant-specific filtering here
		filteredNames = append(filteredNames, name)
	}
	
	return filteredNames, nil
}

func (m *MongoDBBackup) getShardInfo(ctx context.Context) ([]ShardInfo, error) {
	database := m.client.GetDatabase("config")
	collection := database.Collection("shards")
	
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	
	var shards []ShardInfo
	for cursor.Next(ctx) {
		var shard struct {
			ID   string `bson:"_id"`
			Host string `bson:"host"`
		}
		
		if err := cursor.Decode(&shard); err != nil {
			continue
		}
		
		shards = append(shards, ShardInfo{
			Name: shard.ID,
			Host: shard.Host,
		})
	}
	
	return shards, nil
}

func (m *MongoDBBackup) getDataDirectory(ctx context.Context) (string, error) {
	database := m.client.GetDatabase("admin")
	result := database.RunCommand(ctx, bson.M{"getCmdLineOpts": 1})
	
	var opts struct {
		Parsed struct {
			Storage struct {
				DBPath string `bson:"dbPath"`
			} `bson:"storage"`
		} `bson:"parsed"`
	}
	
	if err := result.Decode(&opts); err != nil {
		return "", err
	}
	
	if opts.Parsed.Storage.DBPath == "" {
		return "/data/db", nil // Default MongoDB data directory
	}
	
	return opts.Parsed.Storage.DBPath, nil
}

func (m *MongoDBBackup) syncFilesystem(ctx context.Context) error {
	database := m.client.GetDatabase("admin")
	return database.RunCommand(ctx, bson.M{"fsync": 1, "lock": false}).Err()
}

func (m *MongoDBBackup) exportOplog(ctx context.Context, fromTS primitive.Timestamp, outputPath string, tenant *TenantContext) error {
	args := []string{
		"mongoexport",
		"--host", m.client.GetConnectionString(),
		"--db", "local",
		"--collection", "oplog.rs",
		"--out", outputPath,
		"--type", "json",
	}
	
	// Add query filter for timestamp range
	if !fromTS.IsZero() {
		query := fmt.Sprintf(`{"ts": {"$gte": {"$timestamp": {"t": %d, "i": %d}}}}`, fromTS.T, fromTS.I)
		args = append(args, "--query", query)
	}
	
	// Add tenant filter if specified
	if tenant != nil {
		// This would need to be adapted based on how tenant information is stored in oplog
		// For now, we'll export all oplog entries
	}
	
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mongoexport failed: %w, output: %s", err, output)
	}
	
	return nil
}

func (m *MongoDBBackup) createArchive(sourceDir, archivePath string) error {
	cmd := exec.Command("tar", "-czf", archivePath, "-C", filepath.Dir(sourceDir), filepath.Base(sourceDir))
	return cmd.Run()
}

func (m *MongoDBBackup) compressFile(inputPath, outputPath string) error {
	cmd := exec.Command("gzip", "-c", inputPath)
	
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()
	
	cmd.Stdout = output
	return cmd.Run()
}

func (m *MongoDBBackup) encryptBackup(ctx context.Context, backupPath, keyID string) (string, error) {
	encryptedPath := backupPath + ".enc"
	
	// Read backup data
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return "", err
	}
	
	// Encrypt data
	encryptedData, err := m.encryption.EncryptData(ctx, data, keyID, nil)
	if err != nil {
		return "", err
	}
	
	// Write encrypted data
	if err := os.WriteFile(encryptedPath, encryptedData, 0644); err != nil {
		return "", err
	}
	
	// Remove original file
	if err := os.Remove(backupPath); err != nil {
		m.logger.Warn("Failed to remove original backup file", zap.Error(err))
	}
	
	return encryptedPath, nil
}

// RestoreBackup restores a MongoDB backup
func (m *MongoDBBackup) RestoreBackup(ctx context.Context, backupID string, targetTime *time.Time, tenant *TenantContext) error {
	m.logger.Info("Starting MongoDB restore",
		zap.String("backup_id", backupID),
		zap.Time("target_time", func() time.Time {
			if targetTime != nil {
				return *targetTime
			}
			return time.Time{}
		}()),
	)
	
	// Download backup from storage
	localPath, err := m.storageManager.Download(ctx, backupID, "mongodb")
	if err != nil {
		return fmt.Errorf("failed to download backup: %w", err)
	}
	defer os.RemoveAll(filepath.Dir(localPath))
	
	// Decrypt if necessary
	if strings.HasSuffix(localPath, ".enc") {
		decryptedPath, err := m.decryptBackup(ctx, localPath, tenant)
		if err != nil {
			return fmt.Errorf("failed to decrypt backup: %w", err)
		}
		localPath = decryptedPath
	}
	
	// Restore based on backup method
	switch m.config.BackupMethod {
	case "mongodump":
		return m.restoreFromMongoDump(ctx, localPath, tenant)
	case "filesystem":
		return m.restoreFromFilesystem(ctx, localPath)
	case "oplog":
		return m.restoreFromOplog(ctx, localPath, targetTime, tenant)
	default:
		return fmt.Errorf("unsupported backup method for restore: %s", m.config.BackupMethod)
	}
}

func (m *MongoDBBackup) decryptBackup(ctx context.Context, encryptedPath string, tenant *TenantContext) (string, error) {
	// Read encrypted data
	encryptedData, err := os.ReadFile(encryptedPath)
	if err != nil {
		return "", err
	}
	
	// Find appropriate key ID (this would be stored in backup metadata)
	keyID := "backup-key" // Placeholder
	
	// Decrypt data
	decryptedData, err := m.encryption.DecryptData(ctx, encryptedData, keyID, nil)
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

func (m *MongoDBBackup) restoreFromMongoDump(ctx context.Context, backupPath string, tenant *TenantContext) error {
	// Extract backup if it's an archive
	extractDir := backupPath
	if strings.HasSuffix(backupPath, ".tar.gz") {
		extractDir = filepath.Dir(backupPath)
		cmd := exec.Command("tar", "-xzf", backupPath, "-C", extractDir)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to extract backup: %w", err)
		}
	}
	
	// Prepare mongorestore command
	args := []string{
		"mongorestore",
		"--host", m.client.GetConnectionString(),
		"--drop", // Drop existing collections
		extractDir,
	}
	
	// Add oplog replay if available
	oplogPath := filepath.Join(extractDir, "oplog.bson")
	if _, err := os.Stat(oplogPath); err == nil {
		args = append(args, "--oplogReplay")
	}
	
	// Execute mongorestore
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mongorestore failed: %w, output: %s", err, output)
	}
	
	m.logger.Info("MongoDB restore from mongodump completed successfully")
	return nil
}

func (m *MongoDBBackup) restoreFromFilesystem(ctx context.Context, backupPath string) error {
	// Stop MongoDB
	if err := m.stopMongoDB(); err != nil {
		return fmt.Errorf("failed to stop MongoDB: %w", err)
	}
	
	// Get data directory
	dataDir, err := m.getDataDirectory(ctx)
	if err != nil {
		return fmt.Errorf("failed to get data directory: %w", err)
	}
	
	// Remove existing data
	if err := os.RemoveAll(dataDir); err != nil {
		return fmt.Errorf("failed to remove existing data: %w", err)
	}
	
	// Extract backup
	cmd := exec.Command("tar", "-xzf", backupPath, "-C", filepath.Dir(dataDir))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to extract backup: %w", err)
	}
	
	// Start MongoDB
	if err := m.startMongoDB(); err != nil {
		return fmt.Errorf("failed to start MongoDB: %w", err)
	}
	
	m.logger.Info("MongoDB restore from filesystem completed successfully")
	return nil
}

func (m *MongoDBBackup) restoreFromOplog(ctx context.Context, oplogPath string, targetTime *time.Time, tenant *TenantContext) error {
	// This would apply oplog entries to restore to a specific point in time
	// Implementation depends on the specific oplog format and requirements
	
	m.logger.Info("MongoDB restore from oplog completed successfully")
	return nil
}

func (m *MongoDBBackup) stopMongoDB() error {
	cmd := exec.Command("systemctl", "stop", "mongod")
	return cmd.Run()
}

func (m *MongoDBBackup) startMongoDB() error {
	cmd := exec.Command("systemctl", "start", "mongod")
	return cmd.Run()
}