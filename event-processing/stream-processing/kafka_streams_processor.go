package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

// KafkaStreamsProcessor implements stream processing using Kafka
type KafkaStreamsProcessor struct {
	logger                 *zap.Logger
	config                 *KafkaStreamsConfig
	streamProcessorManager *StreamProcessorManager
	
	// Kafka components
	readers               []*kafka.Reader
	writers               map[string]*kafka.Writer
	
	// Processing workers
	workerPool            *WorkerPool
	
	// State management
	ctx                   context.Context
	cancel                context.CancelFunc
	wg                    sync.WaitGroup
	isRunning             bool
	mu                    sync.RWMutex
	
	// Metrics
	processedCount        int64
	errorCount            int64
	lastProcessedTime     time.Time
}

// KafkaStreamsConfig defines configuration for Kafka Streams processor
type KafkaStreamsConfig struct {
	Brokers         []string          `json:"brokers"`
	InputTopics     []string          `json:"input_topics"`
	OutputTopics    map[string]string `json:"output_topics"` // stage -> topic
	ConsumerGroupID string            `json:"consumer_group_id"`
	WorkerPoolSize  int               `json:"worker_pool_size"`
	BufferSize      int               `json:"buffer_size"`
	
	// Kafka consumer settings
	MinBytes          int           `json:"min_bytes"`
	MaxBytes          int           `json:"max_bytes"`
	MaxWait           time.Duration `json:"max_wait"`
	CommitInterval    time.Duration `json:"commit_interval"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	SessionTimeout    time.Duration `json:"session_timeout"`
	
	// Kafka producer settings
	BatchSize         int                `json:"batch_size"`
	BatchTimeout      time.Duration      `json:"batch_timeout"`
	RequiredAcks      kafka.RequiredAcks `json:"required_acks"`
	Compression       kafka.Compression  `json:"compression"`
	WriteTimeout      time.Duration      `json:"write_timeout"`
	ReadTimeout       time.Duration      `json:"read_timeout"`
	
	// Processing settings
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	MaxRetries        int           `json:"max_retries"`
	RetryDelay        time.Duration `json:"retry_delay"`
}

// WorkerPool manages a pool of stream processing workers
type WorkerPool struct {
	logger      *zap.Logger
	workerCount int
	workChan    chan *StreamProcessingTask
	workers     []*StreamWorker
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// StreamWorker processes streaming tasks
type StreamWorker struct {
	id                     int
	logger                 *zap.Logger
	workChan               chan *StreamProcessingTask
	streamProcessorManager *StreamProcessorManager
	ctx                    context.Context
}

// StreamProcessingTask represents a stream processing task
type StreamProcessingTask struct {
	Message     kafka.Message
	Topic       string
	Partition   int
	Offset      int64
	ProcessedAt time.Time
	Retries     int
}

// NewKafkaStreamsProcessor creates a new Kafka Streams processor
func NewKafkaStreamsProcessor(
	logger *zap.Logger,
	config *KafkaStreamsConfig,
	streamProcessorManager *StreamProcessorManager,
) (*KafkaStreamsProcessor, error) {
	if config == nil {
		return nil, fmt.Errorf("Kafka streams configuration is required")
	}
	
	// Set defaults
	if config.WorkerPoolSize == 0 {
		config.WorkerPoolSize = 10
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.MinBytes == 0 {
		config.MinBytes = 1
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = 10e6 // 10MB
	}
	if config.MaxWait == 0 {
		config.MaxWait = 500 * time.Millisecond
	}
	if config.CommitInterval == 0 {
		config.CommitInterval = 1 * time.Second
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 3 * time.Second
	}
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 30 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = 10 * time.Millisecond
	}
	if config.RequiredAcks == 0 {
		config.RequiredAcks = kafka.RequireAll
	}
	if config.Compression == 0 {
		config.Compression = kafka.Snappy
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.ProcessingTimeout == 0 {
		config.ProcessingTimeout = 30 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	
	processor := &KafkaStreamsProcessor{
		logger:                 logger.With(zap.String("component", "kafka-streams-processor")),
		config:                 config,
		streamProcessorManager: streamProcessorManager,
		writers:                make(map[string]*kafka.Writer),
	}
	
	return processor, nil
}

// Start starts the Kafka Streams processor
func (p *KafkaStreamsProcessor) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if p.isRunning {
		return fmt.Errorf("Kafka Streams processor is already running")
	}
	
	p.ctx, p.cancel = context.WithCancel(ctx)
	
	p.logger.Info("Starting Kafka Streams processor...")
	
	// Initialize Kafka readers for input topics
	p.readers = make([]*kafka.Reader, len(p.config.InputTopics))
	for i, topic := range p.config.InputTopics {
		reader := kafka.NewReader(kafka.ReaderConfig{
			Brokers:           p.config.Brokers,
			GroupID:           p.config.ConsumerGroupID,
			Topic:             topic,
			MinBytes:          p.config.MinBytes,
			MaxBytes:          p.config.MaxBytes,
			MaxWait:           p.config.MaxWait,
			CommitInterval:    p.config.CommitInterval,
			StartOffset:       kafka.LastOffset,
			HeartbeatInterval: p.config.HeartbeatInterval,
			SessionTimeout:    p.config.SessionTimeout,
			Logger:            kafka.LoggerFunc(p.logKafkaMessage),
			ErrorLogger:       kafka.LoggerFunc(p.logKafkaError),
		})
		
		p.readers[i] = reader
		
		p.logger.Info("Kafka reader created",
			zap.String("topic", topic),
			zap.String("group_id", p.config.ConsumerGroupID),
		)
	}
	
	// Initialize Kafka writers for output topics
	for stage, topic := range p.config.OutputTopics {
		writer := &kafka.Writer{
			Addr:         kafka.TCP(p.config.Brokers...),
			Topic:        topic,
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    p.config.BatchSize,
			BatchTimeout: p.config.BatchTimeout,
			RequiredAcks: p.config.RequiredAcks,
			Compression:  p.config.Compression,
			WriteTimeout: p.config.WriteTimeout,
			ReadTimeout:  p.config.ReadTimeout,
			Logger:       kafka.LoggerFunc(p.logKafkaMessage),
			ErrorLogger:  kafka.LoggerFunc(p.logKafkaError),
		}
		
		p.writers[stage] = writer
		
		p.logger.Info("Kafka writer created",
			zap.String("stage", stage),
			zap.String("topic", topic),
		)
	}
	
	// Initialize worker pool
	var err error
	p.workerPool, err = NewWorkerPool(
		p.logger,
		p.config.WorkerPoolSize,
		p.config.BufferSize,
		p.streamProcessorManager,
		p.ctx,
	)
	if err != nil {
		return fmt.Errorf("failed to create worker pool: %w", err)
	}
	
	// Start worker pool
	if err := p.workerPool.Start(); err != nil {
		return fmt.Errorf("failed to start worker pool: %w", err)
	}
	
	// Start consumer goroutines for each reader
	for i, reader := range p.readers {
		p.wg.Add(1)
		go p.runConsumer(reader, fmt.Sprintf("consumer-%d", i))
	}
	
	// Start metrics reporter
	p.wg.Add(1)
	go p.runMetricsReporter()
	
	p.isRunning = true
	
	p.logger.Info("Kafka Streams processor started",
		zap.Int("input_topics", len(p.config.InputTopics)),
		zap.Int("output_topics", len(p.config.OutputTopics)),
		zap.Int("worker_count", p.config.WorkerPoolSize),
	)
	
	return nil
}

// Stop stops the Kafka Streams processor
func (p *KafkaStreamsProcessor) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.isRunning {
		return nil
	}
	
	p.logger.Info("Stopping Kafka Streams processor...")
	
	// Cancel context to signal all goroutines to stop
	p.cancel()
	
	// Stop worker pool
	if p.workerPool != nil {
		p.workerPool.Stop()
	}
	
	// Close readers
	for _, reader := range p.readers {
		if err := reader.Close(); err != nil {
			p.logger.Error("Failed to close Kafka reader", zap.Error(err))
		}
	}
	
	// Close writers
	for stage, writer := range p.writers {
		if err := writer.Close(); err != nil {
			p.logger.Error("Failed to close Kafka writer",
				zap.String("stage", stage),
				zap.Error(err),
			)
		}
	}
	
	// Wait for all goroutines to finish
	p.wg.Wait()
	
	p.isRunning = false
	
	p.logger.Info("Kafka Streams processor stopped")
	return nil
}

// IsHealthy returns the health status of the processor
func (p *KafkaStreamsProcessor) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if !p.isRunning {
		return false
	}
	
	// Check if we've processed messages recently
	if time.Since(p.lastProcessedTime) > 5*time.Minute && p.processedCount > 0 {
		return false
	}
	
	// Check worker pool health
	if p.workerPool != nil && !p.workerPool.IsHealthy() {
		return false
	}
	
	return true
}

// runConsumer runs a Kafka consumer in a separate goroutine
func (p *KafkaStreamsProcessor) runConsumer(reader *kafka.Reader, consumerID string) {
	defer p.wg.Done()
	
	logger := p.logger.With(zap.String("consumer_id", consumerID))
	logger.Info("Consumer started")
	
	for {
		select {
		case <-p.ctx.Done():
			logger.Info("Consumer stopping due to context cancellation")
			return
		default:
			// Read message with timeout
			readCtx, cancel := context.WithTimeout(p.ctx, p.config.ProcessingTimeout)
			message, err := reader.FetchMessage(readCtx)
			cancel()
			
			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					continue
				}
				
				logger.Error("Failed to fetch message", zap.Error(err))
				p.errorCount++
				
				// Backoff before retrying
				time.Sleep(p.config.RetryDelay)
				continue
			}
			
			// Create processing task
			task := &StreamProcessingTask{
				Message:     message,
				Topic:       message.Topic,
				Partition:   message.Partition,
				Offset:      message.Offset,
				ProcessedAt: time.Now(),
				Retries:     0,
			}
			
			// Submit task to worker pool
			select {
			case p.workerPool.workChan <- task:
				// Task submitted successfully
			case <-p.ctx.Done():
				logger.Info("Consumer stopping, task not submitted")
				return
			default:
				// Worker pool is full, log warning
				logger.Warn("Worker pool is full, dropping message",
					zap.String("topic", message.Topic),
					zap.Int("partition", message.Partition),
					zap.Int64("offset", message.Offset),
				)
			}
			
			// Commit the message
			if err := reader.CommitMessages(p.ctx, message); err != nil {
				logger.Error("Failed to commit message", zap.Error(err))
			}
		}
	}
}

// runMetricsReporter runs the metrics reporter in a separate goroutine
func (p *KafkaStreamsProcessor) runMetricsReporter() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.reportMetrics()
		}
	}
}

// reportMetrics reports current processing metrics
func (p *KafkaStreamsProcessor) reportMetrics() {
	p.mu.RLock()
	processedCount := p.processedCount
	errorCount := p.errorCount
	lastProcessedTime := p.lastProcessedTime
	p.mu.RUnlock()
	
	p.logger.Info("Kafka Streams processor metrics",
		zap.Int64("processed_count", processedCount),
		zap.Int64("error_count", errorCount),
		zap.Time("last_processed_time", lastProcessedTime),
		zap.Bool("is_healthy", p.IsHealthy()),
	)
}

// logKafkaMessage logs Kafka informational messages
func (p *KafkaStreamsProcessor) logKafkaMessage(msg string, args ...interface{}) {
	p.logger.Debug(fmt.Sprintf("Kafka: "+msg, args...))
}

// logKafkaError logs Kafka error messages
func (p *KafkaStreamsProcessor) logKafkaError(msg string, args ...interface{}) {
	p.logger.Error(fmt.Sprintf("Kafka Error: "+msg, args...))
}