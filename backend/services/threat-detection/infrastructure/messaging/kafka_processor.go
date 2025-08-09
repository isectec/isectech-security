package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"

	"threat-detection/domain/service"
	"threat-detection/usecase"
)

// KafkaEventProcessor processes security events from Kafka
type KafkaEventProcessor struct {
	brokers              []string
	consumerGroup        string
	topicPrefix          string
	threatDetectionUC    *usecase.ThreatDetectionUseCase
	logger               *zap.Logger
	
	// Consumer management
	consumers            map[string]*kafka.Reader
	consumerMutex        sync.RWMutex
	
	// Processing configuration
	batchSize            int
	batchTimeout         time.Duration
	processingTimeout    time.Duration
	retryAttempts        int
	retryDelay           time.Duration
	
	// Control channels
	stopCh               chan struct{}
	doneCh               chan struct{}
	
	// Metrics
	totalProcessed       int64
	totalErrors          int64
	processingDuration   time.Duration
	lastProcessedTime    time.Time
	
	// Worker pool
	workerCount          int
	eventChan            chan *SecurityEventMessage
	batchChan            chan []*SecurityEventMessage
}

// SecurityEventMessage represents a security event message from Kafka
type SecurityEventMessage struct {
	Event     *service.SecurityEvent `json:"event"`
	Topic     string                 `json:"topic"`
	Partition int                    `json:"partition"`
	Offset    int64                  `json:"offset"`
	Timestamp time.Time              `json:"timestamp"`
}

// EventProcessingResult represents the result of event processing
type EventProcessingResult struct {
	ProcessedCount int                  `json:"processed_count"`
	ErrorCount     int                  `json:"error_count"`
	ThreatsDetected int                 `json:"threats_detected"`
	ProcessingTime time.Duration        `json:"processing_time"`
	Errors         []ProcessingError    `json:"errors,omitempty"`
}

// ProcessingError represents an error during event processing
type ProcessingError struct {
	EventID   string    `json:"event_id"`
	Topic     string    `json:"topic"`
	Offset    int64     `json:"offset"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// NewKafkaEventProcessor creates a new Kafka event processor
func NewKafkaEventProcessor(
	brokers []string,
	consumerGroup string,
	topicPrefix string,
	threatDetectionUC *usecase.ThreatDetectionUseCase,
	logger *zap.Logger,
) *KafkaEventProcessor {
	return &KafkaEventProcessor{
		brokers:              brokers,
		consumerGroup:        consumerGroup,
		topicPrefix:          topicPrefix,
		threatDetectionUC:    threatDetectionUC,
		logger:               logger,
		consumers:            make(map[string]*kafka.Reader),
		batchSize:            100,
		batchTimeout:         5 * time.Second,
		processingTimeout:    30 * time.Second,
		retryAttempts:        3,
		retryDelay:           time.Second,
		workerCount:          10,
		stopCh:               make(chan struct{}),
		doneCh:               make(chan struct{}),
		eventChan:            make(chan *SecurityEventMessage, 1000),
		batchChan:            make(chan []*SecurityEventMessage, 100),
	}
}

// Start starts the Kafka event processor
func (p *KafkaEventProcessor) Start(ctx context.Context, topics []string) error {
	p.logger.Info("Starting Kafka event processor",
		zap.Strings("brokers", p.brokers),
		zap.String("consumer_group", p.consumerGroup),
		zap.Strings("topics", topics),
		zap.Int("worker_count", p.workerCount),
		zap.Int("batch_size", p.batchSize),
	)

	// Create consumers for each topic
	for _, topic := range topics {
		if err := p.createConsumer(topic); err != nil {
			p.logger.Error("Failed to create consumer", 
				zap.String("topic", topic), 
				zap.Error(err))
			return fmt.Errorf("failed to create consumer for topic %s: %w", topic, err)
		}
	}

	// Start batch processor
	go p.batchProcessor(ctx)

	// Start worker pool
	for i := 0; i < p.workerCount; i++ {
		go p.worker(ctx, i)
	}

	// Start consumers
	for topic, consumer := range p.consumers {
		go p.consumeMessages(ctx, topic, consumer)
	}

	p.logger.Info("Kafka event processor started successfully")
	return nil
}

// Stop stops the Kafka event processor
func (p *KafkaEventProcessor) Stop() error {
	p.logger.Info("Stopping Kafka event processor")

	// Signal stop
	close(p.stopCh)

	// Close consumers
	p.consumerMutex.Lock()
	for topic, consumer := range p.consumers {
		p.logger.Debug("Closing consumer", zap.String("topic", topic))
		if err := consumer.Close(); err != nil {
			p.logger.Error("Failed to close consumer", 
				zap.String("topic", topic), 
				zap.Error(err))
		}
	}
	p.consumerMutex.Unlock()

	// Wait for completion
	select {
	case <-p.doneCh:
		p.logger.Info("Kafka event processor stopped gracefully")
	case <-time.After(30 * time.Second):
		p.logger.Warn("Kafka event processor stop timeout")
	}

	return nil
}

// createConsumer creates a Kafka consumer for a topic
func (p *KafkaEventProcessor) createConsumer(topic string) error {
	consumer := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        p.brokers,
		Topic:          topic,
		GroupID:        p.consumerGroup,
		StartOffset:    kafka.LastOffset,
		MinBytes:       1,
		MaxBytes:       10e6, // 10MB
		MaxWait:        1 * time.Second,
		CommitInterval: 1 * time.Second,
		Logger:         kafka.LoggerFunc(p.kafkaLogger),
		ErrorLogger:    kafka.LoggerFunc(p.kafkaErrorLogger),
	})

	p.consumerMutex.Lock()
	p.consumers[topic] = consumer
	p.consumerMutex.Unlock()

	p.logger.Info("Created Kafka consumer", zap.String("topic", topic))
	return nil
}

// consumeMessages consumes messages from a Kafka topic
func (p *KafkaEventProcessor) consumeMessages(ctx context.Context, topic string, consumer *kafka.Reader) {
	p.logger.Info("Starting message consumption", zap.String("topic", topic))

	for {
		select {
		case <-p.stopCh:
			p.logger.Info("Stopping message consumption", zap.String("topic", topic))
			return
		default:
			// Read message with timeout
			message, err := consumer.FetchMessage(ctx)
			if err != nil {
				if err == context.Canceled {
					return
				}
				p.logger.Error("Failed to fetch message", 
					zap.String("topic", topic), 
					zap.Error(err))
				time.Sleep(p.retryDelay)
				continue
			}

			// Parse security event
			securityEvent, err := p.parseSecurityEvent(message.Value)
			if err != nil {
				p.logger.Error("Failed to parse security event", 
					zap.String("topic", topic),
					zap.Int64("offset", message.Offset),
					zap.Error(err))
				
				// Commit the message even if parsing failed to avoid reprocessing
				if commitErr := consumer.CommitMessages(ctx, message); commitErr != nil {
					p.logger.Error("Failed to commit failed message", zap.Error(commitErr))
				}
				continue
			}

			// Create event message
			eventMessage := &SecurityEventMessage{
				Event:     securityEvent,
				Topic:     topic,
				Partition: message.Partition,
				Offset:    message.Offset,
				Timestamp: message.Time,
			}

			// Send to processing pipeline
			select {
			case p.eventChan <- eventMessage:
				// Commit the message after successful queueing
				if err := consumer.CommitMessages(ctx, message); err != nil {
					p.logger.Error("Failed to commit message", 
						zap.String("topic", topic),
						zap.Int64("offset", message.Offset),
						zap.Error(err))
				}
			case <-time.After(5 * time.Second):
				p.logger.Warn("Event processing queue full, dropping message",
					zap.String("topic", topic),
					zap.Int64("offset", message.Offset))
				
				// Still commit to avoid reprocessing
				if err := consumer.CommitMessages(ctx, message); err != nil {
					p.logger.Error("Failed to commit dropped message", zap.Error(err))
				}
			case <-p.stopCh:
				return
			}
		}
	}
}

// batchProcessor collects events into batches for efficient processing
func (p *KafkaEventProcessor) batchProcessor(ctx context.Context) {
	p.logger.Info("Starting batch processor")

	batch := make([]*SecurityEventMessage, 0, p.batchSize)
	ticker := time.NewTicker(p.batchTimeout)
	defer ticker.Stop()

	for {
		select {
		case event := <-p.eventChan:
			batch = append(batch, event)
			
			if len(batch) >= p.batchSize {
				p.sendBatch(batch)
				batch = make([]*SecurityEventMessage, 0, p.batchSize)
			}

		case <-ticker.C:
			if len(batch) > 0 {
				p.sendBatch(batch)
				batch = make([]*SecurityEventMessage, 0, p.batchSize)
			}

		case <-p.stopCh:
			// Process remaining batch
			if len(batch) > 0 {
				p.sendBatch(batch)
			}
			p.logger.Info("Batch processor stopped")
			return
		}
	}
}

// sendBatch sends a batch of events for processing
func (p *KafkaEventProcessor) sendBatch(batch []*SecurityEventMessage) {
	select {
	case p.batchChan <- batch:
		// Batch sent successfully
	case <-time.After(5 * time.Second):
		p.logger.Warn("Batch processing queue full, dropping batch",
			zap.Int("batch_size", len(batch)))
	case <-p.stopCh:
		return
	}
}

// worker processes batches of security events
func (p *KafkaEventProcessor) worker(ctx context.Context, workerID int) {
	p.logger.Debug("Starting worker", zap.Int("worker_id", workerID))

	for {
		select {
		case batch := <-p.batchChan:
			result := p.processBatch(ctx, batch)
			p.updateMetrics(result)
			p.logProcessingResult(workerID, result)

		case <-p.stopCh:
			p.logger.Debug("Worker stopped", zap.Int("worker_id", workerID))
			return
		}
	}
}

// processBatch processes a batch of security events
func (p *KafkaEventProcessor) processBatch(ctx context.Context, batch []*SecurityEventMessage) *EventProcessingResult {
	start := time.Now()
	
	result := &EventProcessingResult{
		ProcessedCount: 0,
		ErrorCount:     0,
		ThreatsDetected: 0,
		Errors:         make([]ProcessingError, 0),
	}

	// Extract events from messages
	events := make([]*service.SecurityEvent, len(batch))
	for i, msg := range batch {
		events[i] = msg.Event
	}

	// Process events in batch using the threat detection use case
	processCtx, cancel := context.WithTimeout(ctx, p.processingTimeout)
	defer cancel()

	threats, err := p.threatDetectionUC.ProcessSecurityEventsBatch(processCtx, events)
	if err != nil {
		p.logger.Error("Failed to process security events batch", zap.Error(err))
		
		// Record errors for all events in the batch
		for _, msg := range batch {
			result.Errors = append(result.Errors, ProcessingError{
				EventID:   msg.Event.ID.String(),
				Topic:     msg.Topic,
				Offset:    msg.Offset,
				Error:     err.Error(),
				Timestamp: time.Now(),
			})
		}
		result.ErrorCount = len(batch)
	} else {
		result.ProcessedCount = len(batch)
		result.ThreatsDetected = len(threats)
	}

	result.ProcessingTime = time.Since(start)
	return result
}

// parseSecurityEvent parses a security event from Kafka message
func (p *KafkaEventProcessor) parseSecurityEvent(data []byte) (*service.SecurityEvent, error) {
	var event service.SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal security event: %w", err)
	}

	// Validate event
	if err := p.validateSecurityEvent(&event); err != nil {
		return nil, fmt.Errorf("invalid security event: %w", err)
	}

	return &event, nil
}

// validateSecurityEvent validates a security event
func (p *KafkaEventProcessor) validateSecurityEvent(event *service.SecurityEvent) error {
	if event.ID.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("invalid event ID")
	}

	if event.TenantID.String() == "00000000-0000-0000-0000-000000000000" {
		return fmt.Errorf("invalid tenant ID")
	}

	if event.EventType == "" {
		return fmt.Errorf("event type is required")
	}

	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	return nil
}

// updateMetrics updates processing metrics
func (p *KafkaEventProcessor) updateMetrics(result *EventProcessingResult) {
	p.totalProcessed += int64(result.ProcessedCount)
	p.totalErrors += int64(result.ErrorCount)
	p.processingDuration += result.ProcessingTime
	p.lastProcessedTime = time.Now()
}

// logProcessingResult logs the processing result
func (p *KafkaEventProcessor) logProcessingResult(workerID int, result *EventProcessingResult) {
	if result.ErrorCount > 0 {
		p.logger.Warn("Batch processing completed with errors",
			zap.Int("worker_id", workerID),
			zap.Int("processed", result.ProcessedCount),
			zap.Int("errors", result.ErrorCount),
			zap.Int("threats_detected", result.ThreatsDetected),
			zap.Duration("processing_time", result.ProcessingTime),
		)
	} else {
		p.logger.Debug("Batch processing completed successfully",
			zap.Int("worker_id", workerID),
			zap.Int("processed", result.ProcessedCount),
			zap.Int("threats_detected", result.ThreatsDetected),
			zap.Duration("processing_time", result.ProcessingTime),
		)
	}
}

// GetMetrics returns processing metrics
func (p *KafkaEventProcessor) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"total_processed":       p.totalProcessed,
		"total_errors":          p.totalErrors,
		"last_processed_time":   p.lastProcessedTime,
		"average_processing_duration": p.processingDuration.Nanoseconds() / p.totalProcessed,
		"worker_count":          p.workerCount,
		"batch_size":            p.batchSize,
		"queue_length":          len(p.eventChan),
		"batch_queue_length":    len(p.batchChan),
	}
}

// SetBatchSize sets the batch size for processing
func (p *KafkaEventProcessor) SetBatchSize(size int) {
	p.batchSize = size
}

// SetBatchTimeout sets the batch timeout
func (p *KafkaEventProcessor) SetBatchTimeout(timeout time.Duration) {
	p.batchTimeout = timeout
}

// SetWorkerCount sets the number of workers
func (p *KafkaEventProcessor) SetWorkerCount(count int) {
	p.workerCount = count
}

// kafkaLogger logs Kafka messages
func (p *KafkaEventProcessor) kafkaLogger(msg string, a ...interface{}) {
	p.logger.Debug("Kafka: "+msg, zap.Any("args", a))
}

// kafkaErrorLogger logs Kafka errors
func (p *KafkaEventProcessor) kafkaErrorLogger(msg string, a ...interface{}) {
	p.logger.Error("Kafka Error: "+msg, zap.Any("args", a))
}

// ProcessSingleEvent processes a single security event (for testing)
func (p *KafkaEventProcessor) ProcessSingleEvent(ctx context.Context, event *service.SecurityEvent) error {
	p.logger.Debug("Processing single event", zap.String("event_id", event.ID.String()))

	threat, err := p.threatDetectionUC.ProcessSecurityEvent(ctx, event)
	if err != nil {
		p.logger.Error("Failed to process single event", zap.Error(err))
		return err
	}

	if threat != nil {
		p.logger.Info("Threat detected from single event",
			zap.String("threat_id", threat.ID.String()),
			zap.String("threat_type", string(threat.Type)),
		)
	}

	return nil
}

// HealthCheck checks the health of the Kafka processor
func (p *KafkaEventProcessor) HealthCheck() error {
	p.consumerMutex.RLock()
	defer p.consumerMutex.RUnlock()

	if len(p.consumers) == 0 {
		return fmt.Errorf("no consumers available")
	}

	// Check if we've processed events recently
	if time.Since(p.lastProcessedTime) > 5*time.Minute {
		return fmt.Errorf("no events processed in the last 5 minutes")
	}

	return nil
}

// RebalanceConsumers handles consumer group rebalancing
func (p *KafkaEventProcessor) RebalanceConsumers(ctx context.Context) error {
	p.logger.Info("Rebalancing Kafka consumers")

	p.consumerMutex.Lock()
	defer p.consumerMutex.Unlock()

	// Close existing consumers
	for topic, consumer := range p.consumers {
		if err := consumer.Close(); err != nil {
			p.logger.Error("Failed to close consumer during rebalance",
				zap.String("topic", topic),
				zap.Error(err))
		}
	}

	// Clear consumers map
	p.consumers = make(map[string]*kafka.Reader)

	// Recreate consumers
	for topic := range p.consumers {
		if err := p.createConsumer(topic); err != nil {
			p.logger.Error("Failed to recreate consumer during rebalance",
				zap.String("topic", topic),
				zap.Error(err))
			return err
		}
	}

	p.logger.Info("Kafka consumer rebalancing completed")
	return nil
}

// GetProcessingStats returns detailed processing statistics
func (p *KafkaEventProcessor) GetProcessingStats() map[string]interface{} {
	p.consumerMutex.RLock()
	defer p.consumerMutex.RUnlock()

	consumerStats := make(map[string]interface{})
	for topic, consumer := range p.consumers {
		stats := consumer.Stats()
		consumerStats[topic] = map[string]interface{}{
			"messages_read":    stats.Messages,
			"bytes_read":       stats.Bytes,
			"lag":              stats.Lag,
			"min_bytes":        stats.MinBytes,
			"max_bytes":        stats.MaxBytes,
			"max_wait":         stats.MaxWait,
			"queue_length":     stats.QueueLength,
			"queue_capacity":   stats.QueueCapacity,
		}
	}

	return map[string]interface{}{
		"total_processed":     p.totalProcessed,
		"total_errors":        p.totalErrors,
		"processing_duration": p.processingDuration,
		"last_processed":      p.lastProcessedTime,
		"worker_count":        p.workerCount,
		"batch_size":          p.batchSize,
		"batch_timeout":       p.batchTimeout,
		"event_queue_length":  len(p.eventChan),
		"batch_queue_length":  len(p.batchChan),
		"consumer_stats":      consumerStats,
	}
}