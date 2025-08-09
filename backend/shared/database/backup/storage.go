package backup

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"go.uber.org/zap"
	"google.golang.org/api/option"
	"github.com/isectech/platform/shared/database/encryption"
)

// StorageManager handles backup storage operations across different backends
type StorageManager struct {
	config     BackupStorageConfig
	encryption *encryption.KeyManager
	logger     *zap.Logger
	
	// Storage backends
	gcsClient     *storage.Client
	s3Client      interface{} // Would be AWS S3 client
	azureClient   interface{} // Would be Azure Blob client
	
	// Local storage
	localBasePath string
	
	closed bool
}

// StorageMetadata contains metadata about stored backups
type StorageMetadata struct {
	StoragePath    string            `json:"storage_path"`
	Size           int64             `json:"size"`
	Checksum       string            `json:"checksum"`
	Encrypted      bool              `json:"encrypted"`
	Compressed     bool              `json:"compressed"`
	UploadTime     time.Time         `json:"upload_time"`
	Backend        string            `json:"backend"`
	ExpiryTime     *time.Time        `json:"expiry_time,omitempty"`
	Metadata       map[string]string `json:"metadata"`
}

// UploadResult contains the result of an upload operation
type UploadResult struct {
	StoragePath    string            `json:"storage_path"`
	Size           int64             `json:"size"`
	Checksum       string            `json:"checksum"`
	UploadDuration time.Duration     `json:"upload_duration"`
	Backend        string            `json:"backend"`
	Metadata       map[string]string `json:"metadata"`
}

// DownloadResult contains the result of a download operation
type DownloadResult struct {
	LocalPath        string        `json:"local_path"`
	Size             int64         `json:"size"`
	Checksum         string        `json:"checksum"`
	DownloadDuration time.Duration `json:"download_duration"`
	Verified         bool          `json:"verified"`
}

// NewStorageManager creates a new storage manager
func NewStorageManager(
	config BackupStorageConfig,
	encryption *encryption.KeyManager,
	logger *zap.Logger,
) (*StorageManager, error) {
	
	sm := &StorageManager{
		config:        config,
		encryption:    encryption,
		logger:        logger,
		localBasePath: "/tmp/backup-staging",
	}
	
	// Initialize storage backends based on configuration
	if err := sm.initializeBackends(); err != nil {
		return nil, fmt.Errorf("failed to initialize storage backends: %w", err)
	}
	
	// Ensure staging directory exists
	if err := os.MkdirAll(sm.localBasePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create staging directory: %w", err)
	}
	
	logger.Info("Storage manager initialized",
		zap.String("primary_backend", config.Primary.Type),
		zap.Int("secondary_backends", len(config.Secondary)),
		zap.String("archive_backend", config.Archive.Type),
	)
	
	return sm, nil
}

// initializeBackends initializes the configured storage backends
func (sm *StorageManager) initializeBackends() error {
	// Initialize primary backend
	if err := sm.initializeBackend(&sm.config.Primary); err != nil {
		return fmt.Errorf("failed to initialize primary backend: %w", err)
	}
	
	// Initialize secondary backends
	for i := range sm.config.Secondary {
		if err := sm.initializeBackend(&sm.config.Secondary[i]); err != nil {
			sm.logger.Warn("Failed to initialize secondary backend",
				zap.String("type", sm.config.Secondary[i].Type),
				zap.Error(err),
			)
		}
	}
	
	// Initialize archive backend
	if sm.config.Archive.Type != "" {
		if err := sm.initializeBackend(&sm.config.Archive); err != nil {
			sm.logger.Warn("Failed to initialize archive backend",
				zap.String("type", sm.config.Archive.Type),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

// initializeBackend initializes a specific storage backend
func (sm *StorageManager) initializeBackend(config *StorageBackendConfig) error {
	switch config.Type {
	case "gcs":
		return sm.initializeGCS(config)
	case "s3":
		return sm.initializeS3(config)
	case "azure":
		return sm.initializeAzure(config)
	case "local":
		return sm.initializeLocal(config)
	case "nfs":
		return sm.initializeNFS(config)
	default:
		return fmt.Errorf("unsupported storage backend type: %s", config.Type)
	}
}

// initializeGCS initializes Google Cloud Storage client
func (sm *StorageManager) initializeGCS(config *StorageBackendConfig) error {
	ctx := context.Background()
	
	var opts []option.ClientOption
	
	// Add credentials if specified
	if credentialsPath, exists := config.Credentials["service_account_path"]; exists {
		opts = append(opts, option.WithCredentialsFile(credentialsPath))
	}
	
	client, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	
	sm.gcsClient = client
	
	// Verify bucket access
	bucket := client.Bucket(config.Bucket)
	if _, err := bucket.Attrs(ctx); err != nil {
		return fmt.Errorf("failed to access GCS bucket %s: %w", config.Bucket, err)
	}
	
	sm.logger.Info("GCS backend initialized",
		zap.String("bucket", config.Bucket),
		zap.String("region", config.Region),
	)
	
	return nil
}

// initializeS3 initializes AWS S3 client
func (sm *StorageManager) initializeS3(config *StorageBackendConfig) error {
	// Implementation would create AWS S3 client
	sm.logger.Info("S3 backend initialization placeholder")
	return nil
}

// initializeAzure initializes Azure Blob Storage client
func (sm *StorageManager) initializeAzure(config *StorageBackendConfig) error {
	// Implementation would create Azure Blob client
	sm.logger.Info("Azure backend initialization placeholder")
	return nil
}

// initializeLocal initializes local file storage
func (sm *StorageManager) initializeLocal(config *StorageBackendConfig) error {
	// Ensure the local storage path exists
	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return fmt.Errorf("failed to create local storage directory: %w", err)
	}
	
	sm.logger.Info("Local backend initialized",
		zap.String("path", config.Path),
	)
	
	return nil
}

// initializeNFS initializes NFS storage
func (sm *StorageManager) initializeNFS(config *StorageBackendConfig) error {
	// Verify NFS mount point exists
	if _, err := os.Stat(config.Path); err != nil {
		return fmt.Errorf("NFS mount point not accessible: %w", err)
	}
	
	sm.logger.Info("NFS backend initialized",
		zap.String("path", config.Path),
	)
	
	return nil
}

// Upload uploads a backup file to the configured storage backends
func (sm *StorageManager) Upload(ctx context.Context, localPath, database, backupID string) (string, error) {
	if sm.closed {
		return "", fmt.Errorf("storage manager is closed")
	}
	
	// Generate storage path
	storagePath := sm.generateStoragePath(database, backupID, localPath)
	
	// Upload to primary backend
	result, err := sm.uploadToBackend(ctx, localPath, storagePath, &sm.config.Primary)
	if err != nil {
		return "", fmt.Errorf("failed to upload to primary backend: %w", err)
	}
	
	// Upload to secondary backends asynchronously
	for i := range sm.config.Secondary {
		go func(backend StorageBackendConfig) {
			if err := sm.uploadToBackendAsync(ctx, localPath, storagePath, &backend); err != nil {
				sm.logger.Error("Failed to upload to secondary backend",
					zap.String("backend", backend.Type),
					zap.String("backup_id", backupID),
					zap.Error(err),
				)
			}
		}(sm.config.Secondary[i])
	}
	
	sm.logger.Info("Backup uploaded successfully",
		zap.String("backup_id", backupID),
		zap.String("storage_path", result.StoragePath),
		zap.String("primary_backend", sm.config.Primary.Type),
		zap.Int64("size", result.Size),
		zap.Duration("upload_duration", result.UploadDuration),
	)
	
	return result.StoragePath, nil
}

// uploadToBackend uploads to a specific backend
func (sm *StorageManager) uploadToBackend(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	startTime := time.Now()
	
	switch config.Type {
	case "gcs":
		return sm.uploadToGCS(ctx, localPath, storagePath, config)
	case "s3":
		return sm.uploadToS3(ctx, localPath, storagePath, config)
	case "azure":
		return sm.uploadToAzure(ctx, localPath, storagePath, config)
	case "local":
		return sm.uploadToLocal(ctx, localPath, storagePath, config)
	case "nfs":
		return sm.uploadToNFS(ctx, localPath, storagePath, config)
	default:
		return nil, fmt.Errorf("unsupported backend type: %s", config.Type)
	}
}

// uploadToGCS uploads to Google Cloud Storage
func (sm *StorageManager) uploadToGCS(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	startTime := time.Now()
	
	// Open local file
	file, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()
	
	// Get file info
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}
	
	// Create GCS object
	bucket := sm.gcsClient.Bucket(config.Bucket)
	object := bucket.Object(storagePath)
	
	// Configure object writer
	writer := object.NewWriter(ctx)
	writer.ContentType = "application/octet-stream"
	writer.Metadata = map[string]string{
		"backup-id":       extractBackupID(storagePath),
		"database":        extractDatabase(storagePath),
		"upload-time":     time.Now().Format(time.RFC3339),
		"original-size":   fmt.Sprintf("%d", fileInfo.Size()),
	}
	
	// Enable server-side encryption if configured
	if config.StorageEncryption && config.KMSKeyID != "" {
		writer.KMSKeyName = config.KMSKeyID
	}
	
	// Copy file to GCS
	if _, err := io.Copy(writer, file); err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to copy file to GCS: %w", err)
	}
	
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close GCS writer: %w", err)
	}
	
	// Calculate checksum
	checksum, err := sm.calculateFileChecksum(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	return &UploadResult{
		StoragePath:    storagePath,
		Size:           fileInfo.Size(),
		Checksum:       checksum,
		UploadDuration: time.Since(startTime),
		Backend:        "gcs",
		Metadata:       writer.Metadata,
	}, nil
}

// uploadToLocal uploads to local filesystem
func (sm *StorageManager) uploadToLocal(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	startTime := time.Now()
	
	// Create destination path
	destPath := filepath.Join(config.Path, storagePath)
	destDir := filepath.Dir(destPath)
	
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create destination directory: %w", err)
	}
	
	// Copy file
	src, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()
	
	dst, err := os.Create(destPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()
	
	size, err := io.Copy(dst, src)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %w", err)
	}
	
	// Calculate checksum
	checksum, err := sm.calculateFileChecksum(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	return &UploadResult{
		StoragePath:    storagePath,
		Size:           size,
		Checksum:       checksum,
		UploadDuration: time.Since(startTime),
		Backend:        "local",
	}, nil
}

// uploadToS3 uploads to AWS S3
func (sm *StorageManager) uploadToS3(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	// Placeholder implementation
	return nil, fmt.Errorf("S3 upload not implemented")
}

// uploadToAzure uploads to Azure Blob Storage
func (sm *StorageManager) uploadToAzure(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	// Placeholder implementation
	return nil, fmt.Errorf("Azure upload not implemented")
}

// uploadToNFS uploads to NFS storage
func (sm *StorageManager) uploadToNFS(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) (*UploadResult, error) {
	// NFS is essentially the same as local filesystem
	return sm.uploadToLocal(ctx, localPath, storagePath, config)
}

// uploadToBackendAsync uploads to a backend asynchronously (for secondary backends)
func (sm *StorageManager) uploadToBackendAsync(ctx context.Context, localPath, storagePath string, config *StorageBackendConfig) error {
	_, err := sm.uploadToBackend(ctx, localPath, storagePath, config)
	return err
}

// Download downloads a backup from storage
func (sm *StorageManager) Download(ctx context.Context, backupID, database string) (string, error) {
	if sm.closed {
		return "", fmt.Errorf("storage manager is closed")
	}
	
	// Generate storage path (same as upload)
	storagePath := sm.generateStoragePathFromID(database, backupID)
	
	// Try to download from primary backend first
	localPath, err := sm.downloadFromBackend(ctx, storagePath, &sm.config.Primary)
	if err == nil {
		return localPath, nil
	}
	
	sm.logger.Warn("Failed to download from primary backend, trying secondary backends",
		zap.String("backup_id", backupID),
		zap.Error(err),
	)
	
	// Try secondary backends
	for i := range sm.config.Secondary {
		localPath, err := sm.downloadFromBackend(ctx, storagePath, &sm.config.Secondary[i])
		if err == nil {
			return localPath, nil
		}
		
		sm.logger.Warn("Failed to download from secondary backend",
			zap.String("backend", sm.config.Secondary[i].Type),
			zap.Error(err),
		)
	}
	
	return "", fmt.Errorf("failed to download backup from all backends")
}

// downloadFromBackend downloads from a specific backend
func (sm *StorageManager) downloadFromBackend(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	switch config.Type {
	case "gcs":
		return sm.downloadFromGCS(ctx, storagePath, config)
	case "s3":
		return sm.downloadFromS3(ctx, storagePath, config)
	case "azure":
		return sm.downloadFromAzure(ctx, storagePath, config)
	case "local":
		return sm.downloadFromLocal(ctx, storagePath, config)
	case "nfs":
		return sm.downloadFromNFS(ctx, storagePath, config)
	default:
		return "", fmt.Errorf("unsupported backend type: %s", config.Type)
	}
}

// downloadFromGCS downloads from Google Cloud Storage
func (sm *StorageManager) downloadFromGCS(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	// Create local file path
	localPath := filepath.Join(sm.localBasePath, filepath.Base(storagePath))
	
	// Create local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()
	
	// Get GCS object reader
	bucket := sm.gcsClient.Bucket(config.Bucket)
	object := bucket.Object(storagePath)
	reader, err := object.NewReader(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create GCS reader: %w", err)
	}
	defer reader.Close()
	
	// Copy from GCS to local file
	if _, err := io.Copy(localFile, reader); err != nil {
		return "", fmt.Errorf("failed to download from GCS: %w", err)
	}
	
	return localPath, nil
}

// downloadFromLocal downloads from local filesystem
func (sm *StorageManager) downloadFromLocal(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	sourcePath := filepath.Join(config.Path, storagePath)
	localPath := filepath.Join(sm.localBasePath, filepath.Base(storagePath))
	
	// Copy file
	src, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()
	
	dst, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()
	
	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}
	
	return localPath, nil
}

// downloadFromS3 downloads from AWS S3
func (sm *StorageManager) downloadFromS3(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	return "", fmt.Errorf("S3 download not implemented")
}

// downloadFromAzure downloads from Azure Blob Storage
func (sm *StorageManager) downloadFromAzure(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	return "", fmt.Errorf("Azure download not implemented")
}

// downloadFromNFS downloads from NFS storage
func (sm *StorageManager) downloadFromNFS(ctx context.Context, storagePath string, config *StorageBackendConfig) (string, error) {
	return sm.downloadFromLocal(ctx, storagePath, config)
}

// VerifyBackup verifies the integrity of a backup
func (sm *StorageManager) VerifyBackup(ctx context.Context, storagePath, expectedChecksum string) error {
	// Download the backup temporarily for verification
	localPath, err := sm.downloadFromBackend(ctx, storagePath, &sm.config.Primary)
	if err != nil {
		return fmt.Errorf("failed to download backup for verification: %w", err)
	}
	defer os.Remove(localPath)
	
	// Calculate checksum
	actualChecksum, err := sm.calculateFileChecksum(localPath)
	if err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}
	
	// Compare checksums
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}
	
	sm.logger.Info("Backup verification successful",
		zap.String("storage_path", storagePath),
		zap.String("checksum", actualChecksum),
	)
	
	return nil
}

// CalculateChecksum calculates the checksum of a stored backup
func (sm *StorageManager) CalculateChecksum(ctx context.Context, storagePath string) (string, error) {
	// For now, calculate from local file if available
	// In production, this might be stored as metadata
	localPath, err := sm.downloadFromBackend(ctx, storagePath, &sm.config.Primary)
	if err != nil {
		return "", fmt.Errorf("failed to download for checksum calculation: %w", err)
	}
	defer os.Remove(localPath)
	
	return sm.calculateFileChecksum(localPath)
}

// ListBackups lists available backups in storage
func (sm *StorageManager) ListBackups(ctx context.Context, database string) ([]*StorageMetadata, error) {
	// Implementation depends on backend type
	// For now, return empty list
	return []*StorageMetadata{}, nil
}

// DeleteBackup deletes a backup from storage
func (sm *StorageManager) DeleteBackup(ctx context.Context, storagePath string) error {
	// Delete from all backends
	var errors []error
	
	// Delete from primary
	if err := sm.deleteFromBackend(ctx, storagePath, &sm.config.Primary); err != nil {
		errors = append(errors, fmt.Errorf("primary backend: %w", err))
	}
	
	// Delete from secondary backends
	for i := range sm.config.Secondary {
		if err := sm.deleteFromBackend(ctx, storagePath, &sm.config.Secondary[i]); err != nil {
			errors = append(errors, fmt.Errorf("secondary backend %s: %w", sm.config.Secondary[i].Type, err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("failed to delete from some backends: %v", errors)
	}
	
	return nil
}

// deleteFromBackend deletes from a specific backend
func (sm *StorageManager) deleteFromBackend(ctx context.Context, storagePath string, config *StorageBackendConfig) error {
	switch config.Type {
	case "gcs":
		bucket := sm.gcsClient.Bucket(config.Bucket)
		object := bucket.Object(storagePath)
		return object.Delete(ctx)
	case "local", "nfs":
		fullPath := filepath.Join(config.Path, storagePath)
		return os.Remove(fullPath)
	default:
		return fmt.Errorf("delete not implemented for backend type: %s", config.Type)
	}
}

// Close closes the storage manager and releases resources
func (sm *StorageManager) Close() error {
	sm.closed = true
	
	if sm.gcsClient != nil {
		if err := sm.gcsClient.Close(); err != nil {
			sm.logger.Error("Failed to close GCS client", zap.Error(err))
		}
	}
	
	sm.logger.Info("Storage manager closed")
	return nil
}

// Helper methods

func (sm *StorageManager) generateStoragePath(database, backupID, localPath string) string {
	timestamp := time.Now().Format("2006/01/02")
	filename := filepath.Base(localPath)
	return fmt.Sprintf("%s/%s/%s/%s", database, timestamp, backupID, filename)
}

func (sm *StorageManager) generateStoragePathFromID(database, backupID string) string {
	// This would need to be enhanced to handle the actual storage path lookup
	// For now, assume a pattern
	return fmt.Sprintf("%s/*/%s/*", database, backupID)
}

func (sm *StorageManager) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Helper functions for extracting metadata from storage paths
func extractBackupID(storagePath string) string {
	parts := strings.Split(storagePath, "/")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func extractDatabase(storagePath string) string {
	parts := strings.Split(storagePath, "/")
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}