package lifecycle

import (
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ArchiveManager manages data archival to external storage
type ArchiveManager struct {
	logger      *zap.Logger
	config      *ArchiveConfig
	storage     StorageBackend
	compressor  Compressor
	encryptor   Encryptor
	
	// Upload management
	uploadQueue chan *ArchiveJob
	workers     sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	
	// Statistics
	stats       *ArchiveStats
	statsMutex  sync.RWMutex
	
	// Health status
	isHealthy   bool
	healthMutex sync.RWMutex
}

// StorageBackend defines the interface for storage backends
type StorageBackend interface {
	Upload(ctx context.Context, key string, data io.Reader, metadata map[string]string) error
	Download(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
	IsHealthy() bool
	Close() error
}

// Compressor defines the interface for compression
type Compressor interface {
	Compress(data io.Reader) (io.Reader, error)
	Decompress(data io.Reader) (io.Reader, error)
	GetCompressionRatio() float64
}

// Encryptor defines the interface for encryption
type Encryptor interface {
	Encrypt(data io.Reader, key []byte) (io.Reader, error)
	Decrypt(data io.Reader, key []byte) (io.Reader, error)
}

// ArchiveJob represents an archive job
type ArchiveJob struct {
	ID            string                 `json:"id"`
	OperationID   string                 `json:"operation_id"`
	DataType      string                 `json:"data_type"`
	SourceIndex   string                 `json:"source_index"`
	TargetPath    string                 `json:"target_path"`
	Data          interface{}            `json:"data"`
	Metadata      map[string]string      `json:"metadata"`
	Priority      int                    `json:"priority"`
	CreatedAt     time.Time              `json:"created_at"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   time.Time              `json:"completed_at"`
	Status        string                 `json:"status"`
	Error         string                 `json:"error,omitempty"`
	BytesOriginal int64                  `json:"bytes_original"`
	BytesArchived int64                  `json:"bytes_archived"`
}

// ArchiveStats tracks archive statistics
type ArchiveStats struct {
	TotalJobs         int64         `json:"total_jobs"`
	CompletedJobs     int64         `json:"completed_jobs"`
	FailedJobs        int64         `json:"failed_jobs"`
	QueuedJobs        int64         `json:"queued_jobs"`
	BytesArchived     int64         `json:"bytes_archived"`
	BytesCompressed   int64         `json:"bytes_compressed"`
	CompressionRatio  float64       `json:"compression_ratio"`
	AverageUploadTime time.Duration `json:"average_upload_time"`
	LastArchiveTime   time.Time     `json:"last_archive_time"`
}

// NewArchiveManager creates a new archive manager
func NewArchiveManager(logger *zap.Logger, config *ArchiveConfig) (*ArchiveManager, error) {
	if config == nil {
		return nil, fmt.Errorf("archive configuration is required")
	}
	
	// Set defaults
	if config.ParallelUploads == 0 {
		config.ParallelUploads = 4
	}
	if config.UploadTimeout == 0 {
		config.UploadTimeout = 30 * time.Minute
	}
	if config.CompressionLevel == 0 {
		config.CompressionLevel = 6 // Default gzip compression level
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &ArchiveManager{
		logger:      logger.With(zap.String("component", "archive-manager")),
		config:      config,
		uploadQueue: make(chan *ArchiveJob, 1000), // Buffer for jobs
		stats:       &ArchiveStats{},
		ctx:         ctx,
		cancel:      cancel,
		isHealthy:   true,
	}
	
	// Initialize storage backend
	storage, err := createStorageBackend(config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}
	manager.storage = storage
	
	// Initialize compressor
	manager.compressor = &GzipCompressor{Level: config.CompressionLevel}
	
	// Initialize encryptor if encryption is enabled
	if config.EncryptionKey != "" {
		encryptor, err := NewAESEncryptor(config.EncryptionKey)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create encryptor: %w", err)
		}
		manager.encryptor = encryptor
	}
	
	// Start worker goroutines
	for i := 0; i < config.ParallelUploads; i++ {
		manager.workers.Add(1)
		go manager.archiveWorker()
	}
	
	logger.Info("Archive manager initialized",
		zap.String("storage_type", config.StorageType),
		zap.String("endpoint", config.Endpoint),
		zap.Int("parallel_uploads", config.ParallelUploads),
		zap.Bool("encryption_enabled", config.EncryptionKey != ""),
	)
	
	return manager, nil
}

// createStorageBackend creates the appropriate storage backend
func createStorageBackend(config *ArchiveConfig) (StorageBackend, error) {
	switch config.StorageType {
	case "s3":
		return NewS3Backend(config)
	case "gcs":
		return NewGCSBackend(config)
	case "azure":
		return NewAzureBackend(config)
	case "filesystem":
		return NewFilesystemBackend(config)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", config.StorageType)
	}
}

// ArchiveData archives data according to the lifecycle operation
func (am *ArchiveManager) ArchiveData(ctx context.Context, operation *LifecycleOperation) error {
	job := &ArchiveJob{
		ID:          fmt.Sprintf("archive-%d", time.Now().UnixNano()),
		OperationID: operation.ID,
		DataType:    operation.DataType,
		SourceIndex: operation.TargetIndex,
		TargetPath:  am.generateArchivePath(operation),
		Metadata:    map[string]string{
			"operation_id": operation.ID,
			"data_type":    operation.DataType,
			"archived_at":  time.Now().Format(time.RFC3339),
		},
		Priority:  1,
		CreatedAt: time.Now(),
		Status:    "queued",
	}
	
	// Update statistics
	am.statsMutex.Lock()
	am.stats.TotalJobs++
	am.stats.QueuedJobs++
	am.statsMutex.Unlock()
	
	// Queue the job
	select {
	case am.uploadQueue <- job:
		am.logger.Debug("Archive job queued",
			zap.String("job_id", job.ID),
			zap.String("target_path", job.TargetPath),
		)
		return nil
	case <-ctx.Done():
		am.statsMutex.Lock()
		am.stats.QueuedJobs--
		am.stats.FailedJobs++
		am.statsMutex.Unlock()
		return ctx.Err()
	}
}

// generateArchivePath generates the archive path for data
func (am *ArchiveManager) generateArchivePath(operation *LifecycleOperation) string {
	now := time.Now()
	return filepath.Join(
		operation.DataType,
		now.Format("2006"),
		now.Format("01"),
		now.Format("02"),
		fmt.Sprintf("%s-%s.archive", operation.TargetIndex, operation.ID),
	)
}

// archiveWorker processes archive jobs
func (am *ArchiveManager) archiveWorker() {
	defer am.workers.Done()
	
	for {
		select {
		case <-am.ctx.Done():
			return
		case job := <-am.uploadQueue:
			am.processArchiveJob(job)
		}
	}
}

// processArchiveJob processes a single archive job
func (am *ArchiveManager) processArchiveJob(job *ArchiveJob) {
	start := time.Now()
	job.StartedAt = start
	job.Status = "processing"
	
	// Update statistics
	am.statsMutex.Lock()
	am.stats.QueuedJobs--
	am.statsMutex.Unlock()
	
	ctx, cancel := context.WithTimeout(am.ctx, am.config.UploadTimeout)
	defer cancel()
	
	// Fetch data from source
	data, err := am.fetchSourceData(ctx, job)
	if err != nil {
		am.failJob(job, fmt.Errorf("failed to fetch source data: %w", err))
		return
	}
	
	// Compress data
	compressedData, err := am.compressor.Compress(data)
	if err != nil {
		am.failJob(job, fmt.Errorf("failed to compress data: %w", err))
		return
	}
	
	// Encrypt data if encryption is enabled
	var finalData io.Reader = compressedData
	if am.encryptor != nil {
		encryptedData, err := am.encryptor.Encrypt(compressedData, []byte(am.config.EncryptionKey))
		if err != nil {
			am.failJob(job, fmt.Errorf("failed to encrypt data: %w", err))
			return
		}
		finalData = encryptedData
	}
	
	// Upload to storage backend
	if err := am.storage.Upload(ctx, job.TargetPath, finalData, job.Metadata); err != nil {
		am.failJob(job, fmt.Errorf("failed to upload data: %w", err))
		return
	}
	
	// Complete job
	job.CompletedAt = time.Now()
	job.Status = "completed"
	
	duration := time.Since(start)
	
	// Update statistics
	am.statsMutex.Lock()
	am.stats.CompletedJobs++
	am.stats.BytesArchived += job.BytesArchived
	am.stats.BytesCompressed += job.BytesOriginal - job.BytesArchived
	am.stats.AverageUploadTime = (am.stats.AverageUploadTime + duration) / 2
	am.stats.LastArchiveTime = time.Now()
	if am.stats.BytesArchived > 0 {
		am.stats.CompressionRatio = float64(am.stats.BytesCompressed) / float64(am.stats.BytesArchived)
	}
	am.statsMutex.Unlock()
	
	am.logger.Info("Archive job completed",
		zap.String("job_id", job.ID),
		zap.String("target_path", job.TargetPath),
		zap.Duration("duration", duration),
		zap.Int64("bytes_original", job.BytesOriginal),
		zap.Int64("bytes_archived", job.BytesArchived),
	)
}

// fetchSourceData fetches data from the source system
func (am *ArchiveManager) fetchSourceData(ctx context.Context, job *ArchiveJob) (io.Reader, error) {
	// This would be implemented based on the specific source system
	// For now, return a placeholder implementation
	return nil, fmt.Errorf("fetchSourceData not implemented for data type: %s", job.DataType)
}

// failJob marks a job as failed
func (am *ArchiveManager) failJob(job *ArchiveJob, err error) {
	job.Status = "failed"
	job.Error = err.Error()
	job.CompletedAt = time.Now()
	
	am.statsMutex.Lock()
	am.stats.FailedJobs++
	am.statsMutex.Unlock()
	
	am.logger.Error("Archive job failed",
		zap.String("job_id", job.ID),
		zap.String("target_path", job.TargetPath),
		zap.Error(err),
	)
}

// GetStats returns archive statistics
func (am *ArchiveManager) GetStats() *ArchiveStats {
	am.statsMutex.RLock()
	defer am.statsMutex.RUnlock()
	
	stats := *am.stats
	return &stats
}

// IsHealthy returns the health status
func (am *ArchiveManager) IsHealthy() bool {
	am.healthMutex.RLock()
	defer am.healthMutex.RUnlock()
	
	return am.isHealthy && am.storage.IsHealthy()
}

// Close closes the archive manager
func (am *ArchiveManager) Close() error {
	if am.cancel != nil {
		am.cancel()
	}
	
	// Close upload queue
	close(am.uploadQueue)
	
	// Wait for workers to finish
	am.workers.Wait()
	
	// Close storage backend
	if am.storage != nil {
		am.storage.Close()
	}
	
	am.logger.Info("Archive manager closed")
	return nil
}

// GzipCompressor implements compression using gzip
type GzipCompressor struct {
	Level int
}

func (gc *GzipCompressor) Compress(data io.Reader) (io.Reader, error) {
	pr, pw := io.Pipe()
	
	go func() {
		defer pw.Close()
		
		writer, err := gzip.NewWriterLevel(pw, gc.Level)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		defer writer.Close()
		
		if _, err := io.Copy(writer, data); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()
	
	return pr, nil
}

func (gc *GzipCompressor) Decompress(data io.Reader) (io.Reader, error) {
	reader, err := gzip.NewReader(data)
	if err != nil {
		return nil, err
	}
	
	return reader, nil
}

func (gc *GzipCompressor) GetCompressionRatio() float64 {
	return 0.3 // Typical gzip compression ratio
}

// AESEncryptor implements AES encryption
type AESEncryptor struct {
	key []byte
}

func NewAESEncryptor(keyString string) (*AESEncryptor, error) {
	key := []byte(keyString)
	if len(key) != 32 { // AES-256 requires 32-byte key
		return nil, fmt.Errorf("encryption key must be 32 bytes long")
	}
	
	return &AESEncryptor{key: key}, nil
}

func (ae *AESEncryptor) Encrypt(data io.Reader, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(ae.key)
	if err != nil {
		return nil, err
	}
	
	pr, pw := io.Pipe()
	
	go func() {
		defer pw.Close()
		
		// Generate IV
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			pw.CloseWithError(err)
			return
		}
		
		// Write IV to output
		if _, err := pw.Write(iv); err != nil {
			pw.CloseWithError(err)
			return
		}
		
		// Create cipher stream
		stream := cipher.NewCFBEncrypter(block, iv)
		writer := &cipher.StreamWriter{S: stream, W: pw}
		
		// Encrypt data
		if _, err := io.Copy(writer, data); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()
	
	return pr, nil
}

func (ae *AESEncryptor) Decrypt(data io.Reader, key []byte) (io.Reader, error) {
	block, err := aes.NewCipher(ae.key)
	if err != nil {
		return nil, err
	}
	
	// Read IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(data, iv); err != nil {
		return nil, err
	}
	
	// Create cipher stream
	stream := cipher.NewCFBDecrypter(block, iv)
	reader := &cipher.StreamReader{S: stream, R: data}
	
	return reader, nil
}

// Filesystem backend implementation
type FilesystemBackend struct {
	basePath string
	logger   *zap.Logger
}

func NewFilesystemBackend(config *ArchiveConfig) (*FilesystemBackend, error) {
	return &FilesystemBackend{
		basePath: config.Endpoint,
		logger:   zap.L().With(zap.String("component", "filesystem-backend")),
	}, nil
}

func (fb *FilesystemBackend) Upload(ctx context.Context, key string, data io.Reader, metadata map[string]string) error {
	// Implementation would create directories and write files
	return fmt.Errorf("filesystem backend upload not implemented")
}

func (fb *FilesystemBackend) Download(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, fmt.Errorf("filesystem backend download not implemented")
}

func (fb *FilesystemBackend) Delete(ctx context.Context, key string) error {
	return fmt.Errorf("filesystem backend delete not implemented")
}

func (fb *FilesystemBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, fmt.Errorf("filesystem backend list not implemented")
}

func (fb *FilesystemBackend) IsHealthy() bool {
	return true
}

func (fb *FilesystemBackend) Close() error {
	return nil
}

// Placeholder implementations for other storage backends
func NewS3Backend(config *ArchiveConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("S3 backend not implemented")
}

func NewGCSBackend(config *ArchiveConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("GCS backend not implemented")
}

func NewAzureBackend(config *ArchiveConfig) (StorageBackend, error) {
	return nil, fmt.Errorf("Azure backend not implemented")
}