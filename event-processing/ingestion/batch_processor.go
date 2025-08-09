package ingestion

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// BatchProcessor manages efficient batch processing of security events for iSECTECH
type BatchProcessor struct {
	config       *BatchProcessorConfig
	logger       *zap.Logger
	ingestionSvc IngestionService

	// Processing queues and workers
	eventQueue chan *SecurityEvent
	batchQueue chan *EventBatch
	workerPool []*BatchWorker

	// Batch accumulation
	activeBatches map[string]*AccumulatingBatch
	batchMutex    sync.RWMutex

	// State management
	isRunning  int32
	shutdownCh chan struct{}
	wg         sync.WaitGroup

	// Metrics and monitoring
	metrics    *BatchProcessorMetrics
	lastReport time.Time

	// Performance optimization
	partitioner EventPartitioner
	compressor  BatchCompressor
	validator   BatchValidator
}

// BatchProcessorConfig defines configuration for batch processing
type BatchProcessorConfig struct {
	// Batch Settings
	DefaultBatchSize int           `json:"default_batch_size"` // Default: 1000
	MaxBatchSize     int           `json:"max_batch_size"`     // Default: 10000
	MinBatchSize     int           `json:"min_batch_size"`     // Default: 1
	BatchTimeout     time.Duration `json:"batch_timeout"`      // Default: 5s
	MaxBatchAge      time.Duration `json:"max_batch_age"`      // Default: 30s

	// Worker Pool Settings
	WorkerCount       int           `json:"worker_count"`        // Default: 10
	MaxWorkers        int           `json:"max_workers"`         // Default: 100
	WorkerIdleTimeout time.Duration `json:"worker_idle_timeout"` // Default: 60s

	// Queue Settings
	EventQueueSize       int  `json:"event_queue_size"`       // Default: 100000
	BatchQueueSize       int  `json:"batch_queue_size"`       // Default: 1000
	PriorityQueueEnabled bool `json:"priority_queue_enabled"` // Default: true

	// Partitioning Strategy
	PartitioningEnabled bool          `json:"partitioning_enabled"` // Default: true
	PartitionBy         []string      `json:"partition_by"`         // tenant_id, event_type, severity
	MaxPartitions       int           `json:"max_partitions"`       // Default: 100
	PartitionTimeout    time.Duration `json:"partition_timeout"`    // Default: 10s

	// Compression Settings
	CompressionEnabled   bool   `json:"compression_enabled"`   // Default: true
	CompressionLevel     int    `json:"compression_level"`     // Default: 6
	CompressionThreshold int    `json:"compression_threshold"` // Default: 1KB
	CompressionType      string `json:"compression_type"`      // gzip, zstd, snappy

	// Validation Settings
	ValidationEnabled    bool `json:"validation_enabled"`     // Default: true
	StrictValidation     bool `json:"strict_validation"`      // Default: false
	ValidateOnAccumulate bool `json:"validate_on_accumulate"` // Default: false

	// Retry and Error Handling
	MaxRetries        int           `json:"max_retries"`         // Default: 3
	RetryBackoff      time.Duration `json:"retry_backoff"`       // Default: 1s
	DeadLetterEnabled bool          `json:"dead_letter_enabled"` // Default: true

	// Performance Tuning
	MemoryLimit     int64         `json:"memory_limit"`     // Default: 1GB
	GCInterval      time.Duration `json:"gc_interval"`      // Default: 5m
	MetricsInterval time.Duration `json:"metrics_interval"` // Default: 30s

	// Persistence Settings
	PersistBatches bool   `json:"persist_batches"` // Default: false
	BatchStorage   string `json:"batch_storage"`   // memory, disk, database
	StoragePath    string `json:"storage_path,omitempty"`
}

// AccumulatingBatch represents a batch being built
type AccumulatingBatch struct {
	ID           string                 `json:"id"`
	PartitionKey string                 `json:"partition_key"`
	Events       []*SecurityEvent       `json:"events"`
	Size         int                    `json:"size"`
	CreatedAt    time.Time              `json:"created_at"`
	LastUpdated  time.Time              `json:"last_updated"`
	Priority     BatchPriority          `json:"priority"`
	Metadata     map[string]interface{} `json:"metadata"`

	// State tracking
	mutex        sync.RWMutex
	isSealed     bool
	expectedSize int
}

// BatchWorker processes batches in parallel
type BatchWorker struct {
	ID        int
	processor *BatchProcessor
	eventCh   chan *SecurityEvent
	batchCh   chan *EventBatch
	logger    *zap.Logger

	// State management
	isRunning      bool
	lastActivity   time.Time
	processedCount int64
	errorCount     int64

	// Performance tracking
	avgProcessTime   time.Duration
	totalProcessTime time.Duration

	mutex sync.RWMutex
}

// BatchProcessorMetrics tracks batch processing performance
type BatchProcessorMetrics struct {
	// Throughput metrics
	EventsProcessed  int64   `json:"events_processed"`
	BatchesCreated   int64   `json:"batches_created"`
	BatchesProcessed int64   `json:"batches_processed"`
	EventsPerSecond  float64 `json:"events_per_second"`
	BatchesPerSecond float64 `json:"batches_per_second"`

	// Size and timing metrics
	AvgBatchSize      float64       `json:"avg_batch_size"`
	MaxBatchSize      int           `json:"max_batch_size"`
	MinBatchSize      int           `json:"min_batch_size"`
	AvgBatchAge       time.Duration `json:"avg_batch_age"`
	AvgProcessingTime time.Duration `json:"avg_processing_time"`

	// Queue metrics
	EventQueueDepth  int     `json:"event_queue_depth"`
	BatchQueueDepth  int     `json:"batch_queue_depth"`
	ActiveBatches    int     `json:"active_batches"`
	QueueUtilization float64 `json:"queue_utilization"`

	// Worker metrics
	ActiveWorkers     int     `json:"active_workers"`
	IdleWorkers       int     `json:"idle_workers"`
	WorkerUtilization float64 `json:"worker_utilization"`

	// Error metrics
	ProcessingErrors int64 `json:"processing_errors"`
	ValidationErrors int64 `json:"validation_errors"`
	RetryCount       int64 `json:"retry_count"`
	DeadLetterCount  int64 `json:"dead_letter_count"`

	// Partition metrics
	PartitionCount int            `json:"partition_count"`
	PartitionSizes map[string]int `json:"partition_sizes"`
	HotPartitions  []string       `json:"hot_partitions"`

	// Resource metrics
	MemoryUsage      int64   `json:"memory_usage"`
	CompressionRatio float64 `json:"compression_ratio"`

	mutex      sync.RWMutex
	lastUpdate time.Time
}

// BatchPriority defines batch processing priority
type BatchPriority int

const (
	PriorityLow BatchPriority = iota
	PriorityNormal
	PriorityHigh
	PriorityCritical
)

// EventPartitioner handles event partitioning for optimal batching
type EventPartitioner interface {
	GetPartitionKey(event *SecurityEvent) string
	GetPartitionCount() int
	ShouldPartition(event *SecurityEvent) bool
}

// BatchCompressor handles batch compression
type BatchCompressor interface {
	Compress(batch *EventBatch) error
	Decompress(batch *EventBatch) error
	GetCompressionRatio() float64
}

// BatchValidator validates batches before processing
type BatchValidator interface {
	ValidateBatch(batch *EventBatch) error
	ValidateEvent(event *SecurityEvent) error
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(config *BatchProcessorConfig, ingestionSvc IngestionService, logger *zap.Logger) (*BatchProcessor, error) {
	if err := validateBatchProcessorConfig(config); err != nil {
		return nil, fmt.Errorf("invalid batch processor configuration: %w", err)
	}

	setBatchProcessorDefaults(config)

	processor := &BatchProcessor{
		config:        config,
		logger:        logger,
		ingestionSvc:  ingestionSvc,
		eventQueue:    make(chan *SecurityEvent, config.EventQueueSize),
		batchQueue:    make(chan *EventBatch, config.BatchQueueSize),
		activeBatches: make(map[string]*AccumulatingBatch),
		shutdownCh:    make(chan struct{}),
		metrics:       NewBatchProcessorMetrics(),
		lastReport:    time.Now(),
	}

	// Initialize components
	if config.PartitioningEnabled {
		processor.partitioner = NewEventPartitioner(config.PartitionBy, config.MaxPartitions)
	}

	if config.CompressionEnabled {
		processor.compressor = NewBatchCompressor(config.CompressionType, config.CompressionLevel)
	}

	if config.ValidationEnabled {
		processor.validator = NewBatchValidator(config.StrictValidation)
	}

	return processor, nil
}

// Start initializes and starts the batch processor
func (bp *BatchProcessor) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&bp.isRunning, 0, 1) {
		return fmt.Errorf("batch processor is already running")
	}

	bp.logger.Info("Starting batch processor",
		zap.Int("worker_count", bp.config.WorkerCount),
		zap.Int("default_batch_size", bp.config.DefaultBatchSize),
		zap.Duration("batch_timeout", bp.config.BatchTimeout))

	// Start worker pool
	bp.startWorkerPool()

	// Start background routines
	bp.wg.Add(4)
	go bp.batchAccumulator()
	go bp.batchFlusher()
	go bp.metricsReporter()
	go bp.memoryManager()

	bp.logger.Info("Batch processor started successfully")
	return nil
}

// Stop gracefully shuts down the batch processor
func (bp *BatchProcessor) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&bp.isRunning, 1, 0) {
		return fmt.Errorf("batch processor is not running")
	}

	bp.logger.Info("Stopping batch processor")

	// Signal shutdown
	close(bp.shutdownCh)

	// Flush remaining batches
	bp.flushAllBatches()

	// Stop workers
	bp.stopWorkerPool()

	// Wait for background routines
	done := make(chan struct{})
	go func() {
		bp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		bp.logger.Info("Batch processor stopped successfully")
		return nil
	case <-ctx.Done():
		bp.logger.Warn("Batch processor shutdown timed out")
		return ctx.Err()
	}
}

// ProcessEvent adds an event to the batch processing pipeline
func (bp *BatchProcessor) ProcessEvent(ctx context.Context, event *SecurityEvent) error {
	if atomic.LoadInt32(&bp.isRunning) == 0 {
		return fmt.Errorf("batch processor is not running")
	}

	select {
	case bp.eventQueue <- event:
		atomic.AddInt64(&bp.metrics.EventsProcessed, 1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-bp.shutdownCh:
		return fmt.Errorf("batch processor is shutting down")
	default:
		return fmt.Errorf("event queue is full")
	}
}

// ProcessBatch adds a pre-formed batch to the processing pipeline
func (bp *BatchProcessor) ProcessBatch(ctx context.Context, batch *EventBatch) error {
	if atomic.LoadInt32(&bp.isRunning) == 0 {
		return fmt.Errorf("batch processor is not running")
	}

	select {
	case bp.batchQueue <- batch:
		atomic.AddInt64(&bp.metrics.BatchesCreated, 1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-bp.shutdownCh:
		return fmt.Errorf("batch processor is shutting down")
	default:
		return fmt.Errorf("batch queue is full")
	}
}

// GetMetrics returns current batch processing metrics
func (bp *BatchProcessor) GetMetrics() *BatchProcessorMetrics {
	bp.metrics.mutex.RLock()
	defer bp.metrics.mutex.RUnlock()

	// Create a copy
	metrics := *bp.metrics
	metrics.PartitionSizes = make(map[string]int)

	for partition, size := range bp.metrics.PartitionSizes {
		metrics.PartitionSizes[partition] = size
	}

	metrics.HotPartitions = make([]string, len(bp.metrics.HotPartitions))
	copy(metrics.HotPartitions, bp.metrics.HotPartitions)

	return &metrics
}

// Private methods

func (bp *BatchProcessor) startWorkerPool() {
	bp.workerPool = make([]*BatchWorker, bp.config.WorkerCount)

	for i := 0; i < bp.config.WorkerCount; i++ {
		worker := &BatchWorker{
			ID:           i,
			processor:    bp,
			eventCh:      make(chan *SecurityEvent, 100),
			batchCh:      make(chan *EventBatch, 10),
			logger:       bp.logger.With(zap.Int("worker_id", i)),
			lastActivity: time.Now(),
		}

		bp.workerPool[i] = worker
		go worker.start()
	}

	bp.logger.Info("Worker pool started", zap.Int("workers", len(bp.workerPool)))
}

func (bp *BatchProcessor) stopWorkerPool() {
	for _, worker := range bp.workerPool {
		worker.stop()
	}
	bp.logger.Info("Worker pool stopped")
}

func (bp *BatchProcessor) batchAccumulator() {
	defer bp.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond) // Check every 100ms
	defer ticker.Stop()

	for {
		select {
		case event := <-bp.eventQueue:
			bp.accumulateEvent(event)

		case <-ticker.C:
			bp.checkBatchTimeouts()

		case <-bp.shutdownCh:
			return
		}
	}
}

func (bp *BatchProcessor) accumulateEvent(event *SecurityEvent) {
	// Determine partition key
	partitionKey := "default"
	if bp.partitioner != nil && bp.partitioner.ShouldPartition(event) {
		partitionKey = bp.partitioner.GetPartitionKey(event)
	}

	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()

	// Get or create accumulating batch
	batch, exists := bp.activeBatches[partitionKey]
	if !exists {
		batch = &AccumulatingBatch{
			ID:           generateBatchID(),
			PartitionKey: partitionKey,
			Events:       make([]*SecurityEvent, 0, bp.config.DefaultBatchSize),
			CreatedAt:    time.Now(),
			Priority:     bp.getEventPriority(event),
			Metadata:     make(map[string]interface{}),
		}
		bp.activeBatches[partitionKey] = batch
	}

	// Add event to batch
	batch.mutex.Lock()
	if !batch.isSealed {
		batch.Events = append(batch.Events, event)
		batch.Size = len(batch.Events)
		batch.LastUpdated = time.Now()

		// Check if batch should be flushed
		shouldFlush := false
		if batch.Size >= bp.config.MaxBatchSize {
			shouldFlush = true
		} else if batch.Size >= bp.config.DefaultBatchSize && bp.getEventPriority(event) >= PriorityHigh {
			shouldFlush = true
		}

		if shouldFlush {
			batch.isSealed = true
			bp.flushBatch(batch)
			delete(bp.activeBatches, partitionKey)
		}
	}
	batch.mutex.Unlock()
}

func (bp *BatchProcessor) checkBatchTimeouts() {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()

	now := time.Now()
	var expiredBatches []*AccumulatingBatch

	for partitionKey, batch := range bp.activeBatches {
		batch.mutex.RLock()
		isExpired := false

		// Check various timeout conditions
		if now.Sub(batch.CreatedAt) >= bp.config.MaxBatchAge {
			isExpired = true
		} else if now.Sub(batch.LastUpdated) >= bp.config.BatchTimeout && batch.Size >= bp.config.MinBatchSize {
			isExpired = true
		} else if batch.Priority >= PriorityHigh && now.Sub(batch.LastUpdated) >= bp.config.BatchTimeout/2 {
			isExpired = true
		}

		if isExpired && !batch.isSealed {
			batch.isSealed = true
			expiredBatches = append(expiredBatches, batch)
			delete(bp.activeBatches, partitionKey)
		}

		batch.mutex.RUnlock()
	}

	// Flush expired batches
	for _, batch := range expiredBatches {
		bp.flushBatch(batch)
	}
}

func (bp *BatchProcessor) flushBatch(accumBatch *AccumulatingBatch) {
	if len(accumBatch.Events) == 0 {
		return
	}

	// Create event batch
	batch := &EventBatch{
		ID:        accumBatch.ID,
		TenantID:  accumBatch.Events[0].TenantID, // Assume same tenant in partition
		Events:    accumBatch.Events,
		Size:      len(accumBatch.Events),
		CreatedAt: accumBatch.CreatedAt,
		Metadata:  accumBatch.Metadata,
	}

	// Apply compression if enabled
	if bp.compressor != nil && len(accumBatch.Events) > 10 {
		if err := bp.compressor.Compress(batch); err != nil {
			bp.logger.Warn("Failed to compress batch", zap.Error(err))
		}
	}

	// Validate batch if enabled
	if bp.validator != nil {
		if err := bp.validator.ValidateBatch(batch); err != nil {
			bp.logger.Error("Batch validation failed",
				zap.String("batch_id", batch.ID),
				zap.Error(err))
			atomic.AddInt64(&bp.metrics.ValidationErrors, 1)
			return
		}
	}

	// Send to processing queue
	select {
	case bp.batchQueue <- batch:
		atomic.AddInt64(&bp.metrics.BatchesCreated, 1)
		bp.updateBatchMetrics(batch)
	default:
		bp.logger.Warn("Batch queue full, dropping batch",
			zap.String("batch_id", batch.ID),
			zap.Int("size", batch.Size))
	}
}

func (bp *BatchProcessor) flushAllBatches() {
	bp.batchMutex.Lock()
	defer bp.batchMutex.Unlock()

	for partitionKey, batch := range bp.activeBatches {
		batch.mutex.Lock()
		if !batch.isSealed {
			batch.isSealed = true
			bp.flushBatch(batch)
		}
		batch.mutex.Unlock()
		delete(bp.activeBatches, partitionKey)
	}
}

func (bp *BatchProcessor) batchFlusher() {
	defer bp.wg.Done()

	for {
		select {
		case batch := <-bp.batchQueue:
			bp.processBatch(batch)

		case <-bp.shutdownCh:
			// Process remaining batches
			for {
				select {
				case batch := <-bp.batchQueue:
					bp.processBatch(batch)
				default:
					return
				}
			}
		}
	}
}

func (bp *BatchProcessor) processBatch(batch *EventBatch) {
	startTime := time.Now()

	// Select worker based on priority and load
	worker := bp.selectWorker(batch)
	if worker == nil {
		bp.logger.Warn("No available workers for batch",
			zap.String("batch_id", batch.ID))
		return
	}

	// Send batch to worker
	select {
	case worker.batchCh <- batch:
		// Success
	case <-time.After(time.Second):
		bp.logger.Warn("Worker timeout for batch",
			zap.String("batch_id", batch.ID),
			zap.Int("worker_id", worker.ID))
	}

	// Update metrics
	processingTime := time.Since(startTime)
	bp.updateProcessingMetrics(processingTime)
}

func (bp *BatchProcessor) selectWorker(batch *EventBatch) *BatchWorker {
	var selectedWorker *BatchWorker
	minLoad := int64(^uint64(0) >> 1) // Max int64

	for _, worker := range bp.workerPool {
		worker.mutex.RLock()
		if worker.isRunning {
			load := worker.processedCount + int64(len(worker.batchCh))
			if load < minLoad {
				minLoad = load
				selectedWorker = worker
			}
		}
		worker.mutex.RUnlock()
	}

	return selectedWorker
}

func (bp *BatchProcessor) getEventPriority(event *SecurityEvent) BatchPriority {
	switch event.Severity {
	case SeverityCritical:
		return PriorityCritical
	case SeverityHigh:
		return PriorityHigh
	case SeverityMedium:
		return PriorityNormal
	default:
		return PriorityLow
	}
}

func (bp *BatchProcessor) updateBatchMetrics(batch *EventBatch) {
	bp.metrics.mutex.Lock()
	defer bp.metrics.mutex.Unlock()

	// Update size metrics
	batchSize := len(batch.Events)
	if batchSize > bp.metrics.MaxBatchSize {
		bp.metrics.MaxBatchSize = batchSize
	}
	if bp.metrics.MinBatchSize == 0 || batchSize < bp.metrics.MinBatchSize {
		bp.metrics.MinBatchSize = batchSize
	}

	// Update average batch size
	totalBatches := bp.metrics.BatchesCreated
	if totalBatches > 0 {
		bp.metrics.AvgBatchSize = (bp.metrics.AvgBatchSize*float64(totalBatches-1) + float64(batchSize)) / float64(totalBatches)
	}

	// Update batch age
	batchAge := time.Since(batch.CreatedAt)
	if totalBatches > 0 {
		bp.metrics.AvgBatchAge = (bp.metrics.AvgBatchAge*time.Duration(totalBatches-1) + batchAge) / time.Duration(totalBatches)
	}
}

func (bp *BatchProcessor) updateProcessingMetrics(processingTime time.Duration) {
	bp.metrics.mutex.Lock()
	defer bp.metrics.mutex.Unlock()

	totalBatches := bp.metrics.BatchesProcessed + 1
	bp.metrics.AvgProcessingTime = (bp.metrics.AvgProcessingTime*time.Duration(totalBatches-1) + processingTime) / time.Duration(totalBatches)
	bp.metrics.BatchesProcessed = totalBatches
}

func (bp *BatchProcessor) metricsReporter() {
	defer bp.wg.Done()

	ticker := time.NewTicker(bp.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bp.reportMetrics()
		case <-bp.shutdownCh:
			return
		}
	}
}

func (bp *BatchProcessor) reportMetrics() {
	bp.metrics.mutex.Lock()
	defer bp.metrics.mutex.Unlock()

	now := time.Now()
	duration := now.Sub(bp.metrics.lastUpdate)

	// Calculate rates
	eventsDelta := bp.metrics.EventsProcessed
	batchesDelta := bp.metrics.BatchesProcessed

	bp.metrics.EventsPerSecond = float64(eventsDelta) / duration.Seconds()
	bp.metrics.BatchesPerSecond = float64(batchesDelta) / duration.Seconds()

	// Update queue metrics
	bp.metrics.EventQueueDepth = len(bp.eventQueue)
	bp.metrics.BatchQueueDepth = len(bp.batchQueue)
	bp.metrics.QueueUtilization = float64(bp.metrics.EventQueueDepth) / float64(bp.config.EventQueueSize)

	// Update active batches count
	bp.batchMutex.RLock()
	bp.metrics.ActiveBatches = len(bp.activeBatches)
	bp.batchMutex.RUnlock()

	// Update worker metrics
	activeWorkers := 0
	for _, worker := range bp.workerPool {
		worker.mutex.RLock()
		if worker.isRunning {
			activeWorkers++
		}
		worker.mutex.RUnlock()
	}
	bp.metrics.ActiveWorkers = activeWorkers
	bp.metrics.IdleWorkers = len(bp.workerPool) - activeWorkers
	bp.metrics.WorkerUtilization = float64(activeWorkers) / float64(len(bp.workerPool))

	bp.metrics.lastUpdate = now

	bp.logger.Debug("Batch processor metrics",
		zap.Float64("events_per_second", bp.metrics.EventsPerSecond),
		zap.Float64("batches_per_second", bp.metrics.BatchesPerSecond),
		zap.Float64("avg_batch_size", bp.metrics.AvgBatchSize),
		zap.Int("active_batches", bp.metrics.ActiveBatches))
}

func (bp *BatchProcessor) memoryManager() {
	defer bp.wg.Done()

	ticker := time.NewTicker(bp.config.GCInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bp.performMemoryCleanup()
		case <-bp.shutdownCh:
			return
		}
	}
}

func (bp *BatchProcessor) performMemoryCleanup() {
	// Force garbage collection if memory usage is high
	// Implementation would check memory usage and trigger GC
	bp.logger.Debug("Memory cleanup performed")
}

// BatchWorker implementation

func (worker *BatchWorker) start() {
	worker.mutex.Lock()
	worker.isRunning = true
	worker.lastActivity = time.Now()
	worker.mutex.Unlock()

	worker.logger.Debug("Worker started")

	for {
		select {
		case batch := <-worker.batchCh:
			worker.processBatch(batch)

		case <-worker.processor.shutdownCh:
			worker.logger.Debug("Worker stopping")
			return

		case <-time.After(worker.processor.config.WorkerIdleTimeout):
			worker.mutex.RLock()
			idle := time.Since(worker.lastActivity) > worker.processor.config.WorkerIdleTimeout
			worker.mutex.RUnlock()

			if idle {
				worker.logger.Debug("Worker idle timeout")
				return
			}
		}
	}
}

func (worker *BatchWorker) stop() {
	worker.mutex.Lock()
	defer worker.mutex.Unlock()

	worker.isRunning = false
	worker.logger.Debug("Worker stopped")
}

func (worker *BatchWorker) processBatch(batch *EventBatch) {
	startTime := time.Now()

	worker.mutex.Lock()
	worker.lastActivity = time.Now()
	worker.mutex.Unlock()

	// Process the batch
	retryCount := 0
	maxRetries := worker.processor.config.MaxRetries

	for retryCount <= maxRetries {
		err := worker.processor.ingestionSvc.IngestBatch(context.Background(), batch)
		if err == nil {
			// Success
			worker.updateMetrics(time.Since(startTime), false)
			atomic.AddInt64(&worker.processor.metrics.BatchesProcessed, 1)
			return
		}

		retryCount++
		if retryCount <= maxRetries {
			worker.logger.Warn("Batch processing failed, retrying",
				zap.String("batch_id", batch.ID),
				zap.Int("retry", retryCount),
				zap.Error(err))

			// Wait before retry
			time.Sleep(worker.processor.config.RetryBackoff * time.Duration(retryCount))
			atomic.AddInt64(&worker.processor.metrics.RetryCount, 1)
		} else {
			worker.logger.Error("Batch processing failed permanently",
				zap.String("batch_id", batch.ID),
				zap.Error(err))

			// Send to dead letter queue if enabled
			if worker.processor.config.DeadLetterEnabled {
				worker.sendToDeadLetter(batch, err)
			}

			worker.updateMetrics(time.Since(startTime), true)
			atomic.AddInt64(&worker.processor.metrics.ProcessingErrors, 1)
			return
		}
	}
}

func (worker *BatchWorker) updateMetrics(processingTime time.Duration, isError bool) {
	worker.mutex.Lock()
	defer worker.mutex.Unlock()

	if isError {
		worker.errorCount++
	} else {
		worker.processedCount++
	}

	worker.totalProcessTime += processingTime
	if worker.processedCount > 0 {
		worker.avgProcessTime = worker.totalProcessTime / time.Duration(worker.processedCount)
	}
}

func (worker *BatchWorker) sendToDeadLetter(batch *EventBatch, err error) {
	worker.logger.Info("Sending batch to dead letter queue",
		zap.String("batch_id", batch.ID),
		zap.Error(err))

	atomic.AddInt64(&worker.processor.metrics.DeadLetterCount, 1)
	// Implementation would send to dead letter storage
}

// Utility functions

func validateBatchProcessorConfig(config *BatchProcessorConfig) error {
	if config.DefaultBatchSize <= 0 {
		return fmt.Errorf("default batch size must be positive")
	}
	if config.MaxBatchSize < config.DefaultBatchSize {
		return fmt.Errorf("max batch size must be >= default batch size")
	}
	if config.WorkerCount <= 0 {
		return fmt.Errorf("worker count must be positive")
	}
	return nil
}

func setBatchProcessorDefaults(config *BatchProcessorConfig) {
	if config.DefaultBatchSize == 0 {
		config.DefaultBatchSize = 1000
	}
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = 10000
	}
	if config.MinBatchSize == 0 {
		config.MinBatchSize = 1
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 5 * time.Second
	}
	if config.MaxBatchAge == 0 {
		config.MaxBatchAge = 30 * time.Second
	}
	if config.WorkerCount == 0 {
		config.WorkerCount = 10
	}
	if config.MaxWorkers == 0 {
		config.MaxWorkers = 100
	}
	if config.WorkerIdleTimeout == 0 {
		config.WorkerIdleTimeout = 60 * time.Second
	}
	if config.EventQueueSize == 0 {
		config.EventQueueSize = 100000
	}
	if config.BatchQueueSize == 0 {
		config.BatchQueueSize = 1000
	}
	if config.MaxPartitions == 0 {
		config.MaxPartitions = 100
	}
	if config.PartitionTimeout == 0 {
		config.PartitionTimeout = 10 * time.Second
	}
	if config.CompressionLevel == 0 {
		config.CompressionLevel = 6
	}
	if config.CompressionThreshold == 0 {
		config.CompressionThreshold = 1024 // 1KB
	}
	if config.CompressionType == "" {
		config.CompressionType = "gzip"
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = time.Second
	}
	if config.MemoryLimit == 0 {
		config.MemoryLimit = 1024 * 1024 * 1024 // 1GB
	}
	if config.GCInterval == 0 {
		config.GCInterval = 5 * time.Minute
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 30 * time.Second
	}
}

func generateBatchID() string {
	return fmt.Sprintf("batch_%d", time.Now().UnixNano())
}

func NewBatchProcessorMetrics() *BatchProcessorMetrics {
	return &BatchProcessorMetrics{
		PartitionSizes: make(map[string]int),
		HotPartitions:  make([]string, 0),
		lastUpdate:     time.Now(),
	}
}

// Placeholder implementations

func NewEventPartitioner(partitionBy []string, maxPartitions int) EventPartitioner {
	return &DefaultEventPartitioner{
		partitionBy:   partitionBy,
		maxPartitions: maxPartitions,
	}
}

func NewBatchCompressor(compressionType string, level int) BatchCompressor {
	return &DefaultBatchCompressor{
		compressionType: compressionType,
		level:           level,
	}
}

func NewBatchValidator(strict bool) BatchValidator {
	return &DefaultBatchValidator{
		strict: strict,
	}
}

type DefaultEventPartitioner struct {
	partitionBy   []string
	maxPartitions int
}

func (p *DefaultEventPartitioner) GetPartitionKey(event *SecurityEvent) string {
	// Simplified implementation
	return event.TenantID
}

func (p *DefaultEventPartitioner) GetPartitionCount() int {
	return p.maxPartitions
}

func (p *DefaultEventPartitioner) ShouldPartition(event *SecurityEvent) bool {
	return len(p.partitionBy) > 0
}

type DefaultBatchCompressor struct {
	compressionType string
	level           int
}

func (c *DefaultBatchCompressor) Compress(batch *EventBatch) error {
	// Simplified implementation
	return nil
}

func (c *DefaultBatchCompressor) Decompress(batch *EventBatch) error {
	// Simplified implementation
	return nil
}

func (c *DefaultBatchCompressor) GetCompressionRatio() float64 {
	return 0.5 // Placeholder
}

type DefaultBatchValidator struct {
	strict bool
}

func (v *DefaultBatchValidator) ValidateBatch(batch *EventBatch) error {
	for _, event := range batch.Events {
		if err := v.ValidateEvent(event); err != nil {
			return err
		}
	}
	return nil
}

func (v *DefaultBatchValidator) ValidateEvent(event *SecurityEvent) error {
	return event.Validate()
}
