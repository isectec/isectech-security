package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// EventProducer defines the interface for producing events to message queues
type EventProducer interface {
	PublishEvent(ctx context.Context, event *entity.Event, topic string) error
	PublishEvents(ctx context.Context, events []*entity.Event, topic string) error
	PublishProcessedEvent(ctx context.Context, event *entity.Event, processingResult *ProcessingResult) error
	PublishError(ctx context.Context, originalEvent *entity.Event, processingError error) error
	Close(ctx context.Context) error
	GetStats() *ProducerStats
	IsHealthy() bool
}

// ProcessingResult represents the result of event processing
type ProcessingResult struct {
	EventID           types.EventID              `json:"event_id"`
	Status            entity.EventStatus         `json:"status"`
	ProcessedAt       time.Time                  `json:"processed_at"`
	Duration          time.Duration              `json:"duration"`
	RiskScore         float64                    `json:"risk_score,omitempty"`
	RiskFactors       []string                   `json:"risk_factors,omitempty"`
	CorrelatedEvents  []types.EventID            `json:"correlated_events,omitempty"`
	EnrichmentData    map[string]interface{}     `json:"enrichment_data,omitempty"`
	Warnings          []string                   `json:"warnings,omitempty"`
	ProcessingSteps   []ProcessingStepResult     `json:"processing_steps"`
}

// ProcessingStepResult represents the result of a processing step
type ProcessingStepResult struct {
	Step        string                 `json:"step"`
	Status      string                 `json:"status"`
	Duration    time.Duration          `json:"duration"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// ProducerStats represents producer statistics
type ProducerStats struct {
	MessagesSent       int64         `json:"messages_sent"`
	MessagesSucceeded  int64         `json:"messages_succeeded"`
	MessagesFailed     int64         `json:"messages_failed"`
	BytesSent          int64         `json:"bytes_sent"`
	AvgSendTime        time.Duration `json:"avg_send_time"`
	LastSendTime       time.Time     `json:"last_send_time"`
	IsConnected        bool          `json:"is_connected"`
	ErrorRate          float64       `json:"error_rate"`
	ThroughputPerSecond float64      `json:"throughput_per_second"`
	BatchesSent        int64         `json:"batches_sent"`
	AvgBatchSize       float64       `json:"avg_batch_size"`
}

// KafkaEventProducer implements EventProducer using Kafka
type KafkaEventProducer struct {
	writers map[string]*kafka.Writer
	logger  *logging.Logger
	metrics *metrics.Collector
	config  *KafkaProducerConfig
	
	// Statistics
	stats          *ProducerStats
	statsMu        sync.RWMutex
	lastStatsReset time.Time
	
	// State management
	mu        sync.RWMutex
	isRunning bool
}

// KafkaProducerConfig represents Kafka producer configuration
type KafkaProducerConfig struct {
	Brokers           []string      `json:"brokers"`
	ClientID          string        `json:"client_id"`
	
	// Topics
	ProcessedEventsTopic string `json:"processed_events_topic"`
	EnrichedEventsTopic  string `json:"enriched_events_topic"`
	AlertsTopic          string `json:"alerts_topic"`
	ErrorTopic           string `json:"error_topic"`
	
	// Performance settings
	BatchSize         int           `json:"batch_size"`
	BatchTimeout      time.Duration `json:"batch_timeout"`
	MaxRetries        int           `json:"max_retries"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	
	// Reliability settings
	RequiredAcks      kafka.RequiredAcks `json:"required_acks"`
	Compression       kafka.Compression  `json:"compression"`
	EnableIdempotent  bool               `json:"enable_idempotent"`
	
	// Error handling
	EnableDLQ         bool   `json:"enable_dlq"`
	RetryDelay        time.Duration `json:"retry_delay"`
	RetryBackoffMultiplier float64 `json:"retry_backoff_multiplier"`
	
	// Monitoring
	EnableMetrics     bool          `json:"enable_metrics"`
	StatsInterval     time.Duration `json:"stats_interval"`
}

// NewKafkaEventProducer creates a new Kafka event producer
func NewKafkaEventProducer(
	logger *logging.Logger,
	metrics *metrics.Collector,
	config *KafkaProducerConfig,
) *KafkaEventProducer {
	if config == nil {
		config = &KafkaProducerConfig{
			Brokers:              []string{"localhost:9092"},
			ClientID:             "event-processor-producer",
			ProcessedEventsTopic: "processed-events",
			EnrichedEventsTopic:  "enriched-events",
			AlertsTopic:          "security-alerts",
			ErrorTopic:           "event-processing-errors",
			BatchSize:            100,
			BatchTimeout:         10 * time.Millisecond,
			MaxRetries:           3,
			WriteTimeout:         30 * time.Second,
			ReadTimeout:          30 * time.Second,
			RequiredAcks:         kafka.RequireAll,
			Compression:          kafka.Snappy,
			EnableIdempotent:     true,
			EnableDLQ:            true,
			RetryDelay:           1 * time.Second,
			RetryBackoffMultiplier: 2.0,
			EnableMetrics:        true,
			StatsInterval:        30 * time.Second,
		}
	}

	producer := &KafkaEventProducer{
		writers: make(map[string]*kafka.Writer),
		logger:  logger,
		metrics: metrics,
		config:  config,
		stats: &ProducerStats{
			IsConnected: false,
		},
		lastStatsReset: time.Now(),
	}

	// Initialize writers for each topic
	producer.initializeWriters()

	return producer
}

// initializeWriters creates Kafka writers for each topic
func (p *KafkaEventProducer) initializeWriters() {
	topics := []string{
		p.config.ProcessedEventsTopic,
		p.config.EnrichedEventsTopic,
		p.config.AlertsTopic,
		p.config.ErrorTopic,
	}

	for _, topic := range topics {
		writer := &kafka.Writer{
			Addr:                   kafka.TCP(p.config.Brokers...),
			Topic:                  topic,
			Balancer:               &kafka.LeastBytes{},
			MaxAttempts:            p.config.MaxRetries,
			BatchSize:              p.config.BatchSize,
			BatchTimeout:           p.config.BatchTimeout,
			WriteTimeout:           p.config.WriteTimeout,
			ReadTimeout:            p.config.ReadTimeout,
			RequiredAcks:           p.config.RequiredAcks,
			Compression:            p.config.Compression,
			Logger:                 kafka.LoggerFunc(p.logKafkaMessage),
			ErrorLogger:            kafka.LoggerFunc(p.logKafkaError),
		}

		if p.config.EnableIdempotent {
			writer.AllowAutoTopicCreation = false
		}

		p.writers[topic] = writer
	}

	p.stats.IsConnected = true
	p.logger.Info("Kafka producers initialized", logging.Strings("topics", topics))
}

// PublishEvent publishes a single event to the specified topic
func (p *KafkaEventProducer) PublishEvent(ctx context.Context, event *entity.Event, topic string) error {
	start := time.Now()
	defer func() {
		p.updateStats(func(stats *ProducerStats) {
			duration := time.Since(start)
			stats.MessagesSent++
			stats.LastSendTime = time.Now()
			
			// Update average send time
			if stats.MessagesSucceeded > 0 {
				stats.AvgSendTime = time.Duration(
					(int64(stats.AvgSendTime) + int64(duration)) / 2,
				)
			} else {
				stats.AvgSendTime = duration
			}
		})
	}()

	writer, exists := p.writers[topic]
	if !exists {
		err := fmt.Errorf("no writer configured for topic: %s", topic)
		p.updateStats(func(stats *ProducerStats) {
			stats.MessagesFailed++
		})
		return common.WrapError(err, common.ErrCodeInvalidInput, "invalid topic")
	}

	// Marshal event to JSON
	eventData, err := json.Marshal(event)
	if err != nil {
		p.updateStats(func(stats *ProducerStats) {
			stats.MessagesFailed++
		})
		return common.WrapError(err, common.ErrCodeInternal, "failed to marshal event")
	}

	// Create Kafka message
	message := kafka.Message{
		Key:   []byte(event.ID.String()),
		Value: eventData,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(event.ID.String())},
			{Key: "tenant_id", Value: []byte(event.TenantID.String())},
			{Key: "event_type", Value: []byte(event.Type)},
			{Key: "source", Value: []byte(event.Source)},
			{Key: "severity", Value: []byte(event.Severity)},
			{Key: "produced_at", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
			{Key: "producer_id", Value: []byte(p.config.ClientID)},
		},
	}

	// Add correlation context if available
	if event.CorrelationID != (types.CorrelationID{}) {
		message.Headers = append(message.Headers, kafka.Header{
			Key:   "correlation_id",
			Value: []byte(event.CorrelationID.String()),
		})
	}

	// Send message
	err = writer.WriteMessages(ctx, message)
	if err != nil {
		p.updateStats(func(stats *ProducerStats) {
			stats.MessagesFailed++
		})
		
		p.logger.Error("Failed to publish event",
			logging.String("event_id", event.ID.String()),
			logging.String("topic", topic),
			logging.String("error", err.Error()),
		)
		
		if p.config.EnableMetrics {
			p.metrics.RecordError("kafka_publish_error", "event-processor")
			p.metrics.RecordMessageSent(topic, "failed")
		}
		
		return common.WrapError(err, common.ErrCodeExternalService, "failed to publish event")
	}

	p.updateStats(func(stats *ProducerStats) {
		stats.MessagesSucceeded++
		stats.BytesSent += int64(len(eventData))
	})

	if p.config.EnableMetrics {
		p.metrics.RecordMessageSent(topic, "success")
	}

	p.logger.Debug("Event published successfully",
		logging.String("event_id", event.ID.String()),
		logging.String("topic", topic),
		logging.Duration("duration", time.Since(start)),
	)

	return nil
}

// PublishEvents publishes multiple events in batch
func (p *KafkaEventProducer) PublishEvents(ctx context.Context, events []*entity.Event, topic string) error {
	if len(events) == 0 {
		return nil
	}

	start := time.Now()
	defer func() {
		p.updateStats(func(stats *ProducerStats) {
			stats.BatchesSent++
			if stats.BatchesSent > 0 {
				stats.AvgBatchSize = float64(stats.MessagesSent) / float64(stats.BatchesSent)
			}
		})
	}()

	writer, exists := p.writers[topic]
	if !exists {
		return common.WrapError(
			fmt.Errorf("no writer configured for topic: %s", topic),
			common.ErrCodeInvalidInput,
			"invalid topic",
		)
	}

	// Create batch messages
	messages := make([]kafka.Message, 0, len(events))
	var totalBytes int64

	for _, event := range events {
		eventData, err := json.Marshal(event)
		if err != nil {
			p.logger.Error("Failed to marshal event in batch",
				logging.String("event_id", event.ID.String()),
				logging.String("error", err.Error()),
			)
			continue
		}

		message := kafka.Message{
			Key:   []byte(event.ID.String()),
			Value: eventData,
			Headers: []kafka.Header{
				{Key: "event_id", Value: []byte(event.ID.String())},
				{Key: "tenant_id", Value: []byte(event.TenantID.String())},
				{Key: "event_type", Value: []byte(event.Type)},
				{Key: "batch_id", Value: []byte(fmt.Sprintf("batch-%d", time.Now().UnixNano()))},
				{Key: "batch_size", Value: []byte(fmt.Sprintf("%d", len(events)))},
				{Key: "produced_at", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
			},
		}

		messages = append(messages, message)
		totalBytes += int64(len(eventData))
	}

	// Send batch
	err := writer.WriteMessages(ctx, messages...)
	if err != nil {
		p.updateStats(func(stats *ProducerStats) {
			stats.MessagesFailed += int64(len(messages))
		})
		
		p.logger.Error("Failed to publish event batch",
			logging.String("topic", topic),
			logging.Int("batch_size", len(messages)),
			logging.String("error", err.Error()),
		)
		
		if p.config.EnableMetrics {
			p.metrics.RecordError("kafka_batch_publish_error", "event-processor")
		}
		
		return common.WrapError(err, common.ErrCodeExternalService, "failed to publish event batch")
	}

	p.updateStats(func(stats *ProducerStats) {
		stats.MessagesSent += int64(len(messages))
		stats.MessagesSucceeded += int64(len(messages))
		stats.BytesSent += totalBytes
		stats.LastSendTime = time.Now()
	})

	if p.config.EnableMetrics {
		for range messages {
			p.metrics.RecordMessageSent(topic, "success")
		}
	}

	p.logger.Info("Event batch published successfully",
		logging.String("topic", topic),
		logging.Int("batch_size", len(messages)),
		logging.Duration("duration", time.Since(start)),
	)

	return nil
}

// PublishProcessedEvent publishes a processed event with its processing result
func (p *KafkaEventProducer) PublishProcessedEvent(ctx context.Context, event *entity.Event, processingResult *ProcessingResult) error {
	// Create enriched event message
	enrichedEvent := struct {
		Event            *entity.Event      `json:"event"`
		ProcessingResult *ProcessingResult  `json:"processing_result"`
		PublishedAt      time.Time          `json:"published_at"`
	}{
		Event:            event,
		ProcessingResult: processingResult,
		PublishedAt:      time.Now().UTC(),
	}

	// Determine target topic based on event properties
	var targetTopic string
	if event.IsHighRisk() || event.Severity == types.SeverityCritical {
		targetTopic = p.config.AlertsTopic
	} else {
		targetTopic = p.config.EnrichedEventsTopic
	}

	// Marshal the enriched event
	enrichedData, err := json.Marshal(enrichedEvent)
	if err != nil {
		return common.WrapError(err, common.ErrCodeInternal, "failed to marshal enriched event")
	}

	writer, exists := p.writers[targetTopic]
	if !exists {
		return common.WrapError(
			fmt.Errorf("no writer configured for topic: %s", targetTopic),
			common.ErrCodeInvalidInput,
			"invalid topic",
		)
	}

	// Create message with enriched headers
	message := kafka.Message{
		Key:   []byte(event.ID.String()),
		Value: enrichedData,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(event.ID.String())},
			{Key: "tenant_id", Value: []byte(event.TenantID.String())},
			{Key: "event_type", Value: []byte(event.Type)},
			{Key: "severity", Value: []byte(event.Severity)},
			{Key: "status", Value: []byte(event.Status)},
			{Key: "risk_score", Value: []byte(fmt.Sprintf("%.2f", event.RiskScore))},
			{Key: "processing_duration", Value: []byte(processingResult.Duration.String())},
			{Key: "produced_at", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
			{Key: "message_type", Value: []byte("processed_event")},
		},
	}

	// Add correlation context
	if event.CorrelationID != (types.CorrelationID{}) {
		message.Headers = append(message.Headers, kafka.Header{
			Key:   "correlation_id",
			Value: []byte(event.CorrelationID.String()),
		})
	}

	// Send message
	err = writer.WriteMessages(ctx, message)
	if err != nil {
		p.logger.Error("Failed to publish processed event",
			logging.String("event_id", event.ID.String()),
			logging.String("topic", targetTopic),
			logging.String("error", err.Error()),
		)
		return common.WrapError(err, common.ErrCodeExternalService, "failed to publish processed event")
	}

	p.logger.Debug("Processed event published successfully",
		logging.String("event_id", event.ID.String()),
		logging.String("topic", targetTopic),
		logging.String("status", string(processingResult.Status)),
	)

	return nil
}

// PublishError publishes an error event
func (p *KafkaEventProducer) PublishError(ctx context.Context, originalEvent *entity.Event, processingError error) error {
	errorEvent := struct {
		OriginalEvent *entity.Event `json:"original_event"`
		Error         ErrorInfo     `json:"error"`
		Timestamp     time.Time     `json:"timestamp"`
	}{
		OriginalEvent: originalEvent,
		Error: ErrorInfo{
			Message:   processingError.Error(),
			Type:      "processing_error",
			Code:      "PROCESSING_FAILED",
			Retryable: true,
		},
		Timestamp: time.Now().UTC(),
	}

	// Marshal error event
	errorData, err := json.Marshal(errorEvent)
	if err != nil {
		return common.WrapError(err, common.ErrCodeInternal, "failed to marshal error event")
	}

	writer, exists := p.writers[p.config.ErrorTopic]
	if !exists {
		return common.WrapError(
			fmt.Errorf("no writer configured for error topic: %s", p.config.ErrorTopic),
			common.ErrCodeInvalidInput,
			"invalid error topic",
		)
	}

	// Create error message
	message := kafka.Message{
		Key:   []byte(originalEvent.ID.String()),
		Value: errorData,
		Headers: []kafka.Header{
			{Key: "event_id", Value: []byte(originalEvent.ID.String())},
			{Key: "tenant_id", Value: []byte(originalEvent.TenantID.String())},
			{Key: "error_type", Value: []byte("processing_error")},
			{Key: "original_event_type", Value: []byte(originalEvent.Type)},
			{Key: "error_timestamp", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
			{Key: "message_type", Value: []byte("error_event")},
		},
	}

	// Send error message
	err = writer.WriteMessages(ctx, message)
	if err != nil {
		p.logger.Error("Failed to publish error event",
			logging.String("event_id", originalEvent.ID.String()),
			logging.String("error", err.Error()),
		)
		return common.WrapError(err, common.ErrCodeExternalService, "failed to publish error event")
	}

	p.logger.Debug("Error event published successfully",
		logging.String("event_id", originalEvent.ID.String()),
		logging.String("error_topic", p.config.ErrorTopic),
	)

	return nil
}

// ErrorInfo represents error information
type ErrorInfo struct {
	Message   string `json:"message"`
	Type      string `json:"type"`
	Code      string `json:"code"`
	Retryable bool   `json:"retryable"`
}

// Close closes all Kafka writers
func (p *KafkaEventProducer) Close(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.logger.Info("Closing Kafka event producer...")

	var closeErrors []error
	for topic, writer := range p.writers {
		if err := writer.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("failed to close writer for topic %s: %w", topic, err))
			p.logger.Error("Failed to close Kafka writer",
				logging.String("topic", topic),
				logging.String("error", err.Error()),
			)
		}
	}

	p.stats.IsConnected = false
	p.isRunning = false

	if len(closeErrors) > 0 {
		return common.WrapError(
			fmt.Errorf("failed to close %d writers", len(closeErrors)),
			common.ErrCodeExternalService,
			"failed to close Kafka producers",
		)
	}

	p.logger.Info("Kafka event producer closed successfully")
	return nil
}

// GetStats returns producer statistics
func (p *KafkaEventProducer) GetStats() *ProducerStats {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()

	// Create a copy to avoid data races
	stats := *p.stats
	
	// Calculate derived statistics
	if stats.MessagesSent > 0 {
		stats.ErrorRate = float64(stats.MessagesFailed) / float64(stats.MessagesSent)
	}
	
	elapsed := time.Since(p.lastStatsReset)
	if elapsed > 0 {
		stats.ThroughputPerSecond = float64(stats.MessagesSucceeded) / elapsed.Seconds()
	}

	return &stats
}

// IsHealthy returns true if the producer is healthy
func (p *KafkaEventProducer) IsHealthy() bool {
	p.statsMu.RLock()
	defer p.statsMu.RUnlock()

	// Check connection status
	if !p.stats.IsConnected {
		return false
	}

	// Check error rate (should be less than 5%)
	if p.stats.ErrorRate > 0.05 {
		return false
	}

	return true
}

// updateStats safely updates producer statistics
func (p *KafkaEventProducer) updateStats(updateFunc func(*ProducerStats)) {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	updateFunc(p.stats)
}

// logKafkaMessage logs Kafka informational messages
func (p *KafkaEventProducer) logKafkaMessage(msg string, args ...interface{}) {
	p.logger.Debug(fmt.Sprintf("Kafka Producer: "+msg, args...))
}

// logKafkaError logs Kafka error messages
func (p *KafkaEventProducer) logKafkaError(msg string, args ...interface{}) {
	p.logger.Error(fmt.Sprintf("Kafka Producer Error: "+msg, args...))
}