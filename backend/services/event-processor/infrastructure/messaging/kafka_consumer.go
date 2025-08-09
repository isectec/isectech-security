package messaging

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/services/event-processor/usecase"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// EventConsumer defines the interface for consuming events from message queues
type EventConsumer interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Subscribe(topics []string) error
	GetStats() *ConsumerStats
	IsHealthy() bool
}

// ConsumerStats represents consumer statistics
type ConsumerStats struct {
	MessagesReceived   int64         `json:"messages_received"`
	MessagesProcessed  int64         `json:"messages_processed"`
	MessagesFailed     int64         `json:"messages_failed"`
	AvgProcessingTime  time.Duration `json:"avg_processing_time"`
	LastMessageTime    time.Time     `json:"last_message_time"`
	ConsumerLag        int64         `json:"consumer_lag"`
	PartitionCount     int           `json:"partition_count"`
	IsConnected        bool          `json:"is_connected"`
	ErrorRate          float64       `json:"error_rate"`
	ThroughputPerSecond float64      `json:"throughput_per_second"`
}

// KafkaEventConsumer implements EventConsumer using Kafka
type KafkaEventConsumer struct {
	readers             []*kafka.Reader
	processEventUseCase *usecase.ProcessEventUseCase
	logger              *logging.Logger
	metrics             *metrics.Collector
	config              *KafkaConsumerConfig
	
	// Processing state
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	isRunning      bool
	mu             sync.RWMutex
	
	// Statistics
	stats          *ConsumerStats
	statsMu        sync.RWMutex
	lastStatsReset time.Time
}

// KafkaConsumerConfig represents Kafka consumer configuration
type KafkaConsumerConfig struct {
	Brokers           []string      `json:"brokers"`
	GroupID           string        `json:"group_id"`
	Topics            []string      `json:"topics"`
	MinBytes          int           `json:"min_bytes"`
	MaxBytes          int           `json:"max_bytes"`
	MaxWait           time.Duration `json:"max_wait"`
	CommitInterval    time.Duration `json:"commit_interval"`
	StartOffset       int64         `json:"start_offset"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	SessionTimeout    time.Duration `json:"session_timeout"`
	
	// Processing configuration
	WorkerCount       int           `json:"worker_count"`
	BufferSize        int           `json:"buffer_size"`
	MaxRetries        int           `json:"max_retries"`
	RetryDelay        time.Duration `json:"retry_delay"`
	ProcessingTimeout time.Duration `json:"processing_timeout"`
	
	// Error handling
	EnableDLQ         bool   `json:"enable_dlq"`
	DLQTopic          string `json:"dlq_topic"`
	ErrorTopic        string `json:"error_topic"`
	
	// Performance settings
	EnableMetrics     bool `json:"enable_metrics"`
	StatsInterval     time.Duration `json:"stats_interval"`
}

// NewKafkaEventConsumer creates a new Kafka event consumer
func NewKafkaEventConsumer(
	processEventUseCase *usecase.ProcessEventUseCase,
	logger *logging.Logger,
	metrics *metrics.Collector,
	config *KafkaConsumerConfig,
) *KafkaEventConsumer {
	if config == nil {
		config = &KafkaConsumerConfig{
			Brokers:           []string{"localhost:9092"},
			GroupID:           "event-processor-group",
			Topics:            []string{"security-events"},
			MinBytes:          1,
			MaxBytes:          10e6, // 10MB
			MaxWait:           500 * time.Millisecond,
			CommitInterval:    1 * time.Second,
			StartOffset:       kafka.LastOffset,
			HeartbeatInterval: 3 * time.Second,
			SessionTimeout:    30 * time.Second,
			WorkerCount:       10,
			BufferSize:        1000,
			MaxRetries:        3,
			RetryDelay:        1 * time.Second,
			ProcessingTimeout: 30 * time.Second,
			EnableDLQ:         true,
			DLQTopic:          "event-processing-dlq",
			ErrorTopic:        "event-processing-errors",
			EnableMetrics:     true,
			StatsInterval:     30 * time.Second,
		}
	}

	consumer := &KafkaEventConsumer{
		processEventUseCase: processEventUseCase,
		logger:              logger,
		metrics:             metrics,
		config:              config,
		stats: &ConsumerStats{
			IsConnected: false,
		},
		lastStatsReset: time.Now(),
	}

	return consumer
}

// Start starts the Kafka consumer
func (c *KafkaEventConsumer) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return fmt.Errorf("consumer is already running")
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	
	// Create readers for each topic
	c.readers = make([]*kafka.Reader, len(c.config.Topics))
	for i, topic := range c.config.Topics {
		reader := kafka.NewReader(kafka.ReaderConfig{
			Brokers:           c.config.Brokers,
			GroupID:           c.config.GroupID,
			Topic:             topic,
			MinBytes:          c.config.MinBytes,
			MaxBytes:          c.config.MaxBytes,
			MaxWait:           c.config.MaxWait,
			CommitInterval:    c.config.CommitInterval,
			StartOffset:       c.config.StartOffset,
			HeartbeatInterval: c.config.HeartbeatInterval,
			SessionTimeout:    c.config.SessionTimeout,
			Logger:            kafka.LoggerFunc(c.logKafkaMessage),
			ErrorLogger:       kafka.LoggerFunc(c.logKafkaError),
		})
		
		c.readers[i] = reader
	}

	// Start worker goroutines for each reader
	for i, reader := range c.readers {
		for j := 0; j < c.config.WorkerCount; j++ {
			c.wg.Add(1)
			go c.consumerWorker(c.ctx, reader, fmt.Sprintf("worker-%d-%d", i, j))
		}
	}

	// Start statistics reporting
	if c.config.EnableMetrics {
		c.wg.Add(1)
		go c.statsReporter(c.ctx)
	}

	c.isRunning = true
	c.stats.IsConnected = true

	c.logger.Info("Kafka event consumer started",
		logging.Strings("topics", c.config.Topics),
		logging.String("group_id", c.config.GroupID),
		logging.Int("worker_count", c.config.WorkerCount * len(c.readers)),
	)

	return nil
}

// Stop stops the Kafka consumer
func (c *KafkaEventConsumer) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.isRunning {
		return nil
	}

	c.logger.Info("Stopping Kafka event consumer...")

	// Cancel context to signal workers to stop
	c.cancel()

	// Close readers
	for _, reader := range c.readers {
		if err := reader.Close(); err != nil {
			c.logger.Error("Failed to close Kafka reader", logging.String("error", err.Error()))
		}
	}

	// Wait for workers to finish or timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		c.logger.Info("All consumer workers stopped gracefully")
	case <-ctx.Done():
		c.logger.Warn("Consumer stop timeout exceeded")
	}

	c.isRunning = false
	c.stats.IsConnected = false

	c.logger.Info("Kafka event consumer stopped")
	return nil
}

// Subscribe subscribes to additional topics
func (c *KafkaEventConsumer) Subscribe(topics []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isRunning {
		return fmt.Errorf("cannot subscribe to topics while consumer is running")
	}

	c.config.Topics = append(c.config.Topics, topics...)
	c.logger.Info("Subscribed to additional topics", logging.Strings("topics", topics))
	
	return nil
}

// GetStats returns consumer statistics
func (c *KafkaEventConsumer) GetStats() *ConsumerStats {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	// Create a copy to avoid data races
	stats := *c.stats
	return &stats
}

// IsHealthy returns true if the consumer is healthy
func (c *KafkaEventConsumer) IsHealthy() bool {
	c.statsMu.RLock()
	defer c.statsMu.RUnlock()

	// Check if consumer is connected and processing messages
	if !c.stats.IsConnected {
		return false
	}

	// Check if we've received messages recently (within last 5 minutes)
	if time.Since(c.stats.LastMessageTime) > 5*time.Minute && c.stats.MessagesReceived > 0 {
		return false
	}

	// Check error rate (should be less than 10%)
	if c.stats.ErrorRate > 0.1 {
		return false
	}

	return true
}

// consumerWorker processes messages from a Kafka reader
func (c *KafkaEventConsumer) consumerWorker(ctx context.Context, reader *kafka.Reader, workerID string) {
	defer c.wg.Done()

	logger := c.logger.WithComponent(fmt.Sprintf("kafka-worker-%s", workerID))
	logger.Info("Consumer worker started")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Consumer worker stopping due to context cancellation")
			return
		default:
			// Read message with timeout
			readCtx, cancel := context.WithTimeout(ctx, c.config.ProcessingTimeout)
			message, err := reader.FetchMessage(readCtx)
			cancel()

			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					continue
				}
				
				logger.Error("Failed to fetch message", logging.String("error", err.Error()))
				c.updateStats(func(stats *ConsumerStats) {
					stats.MessagesFailed++
				})
				
				if c.config.EnableMetrics {
					c.metrics.RecordError("kafka_fetch_error", "event-processor")
				}
				
				// Backoff before retrying
				time.Sleep(c.config.RetryDelay)
				continue
			}

			// Update last message time
			c.updateStats(func(stats *ConsumerStats) {
				stats.MessagesReceived++
				stats.LastMessageTime = time.Now()
			})

			// Process the message
			if err := c.processMessage(ctx, &message, logger); err != nil {
				logger.Error("Failed to process message",
					logging.String("error", err.Error()),
					logging.String("topic", message.Topic),
					logging.Int("partition", message.Partition),
					logging.Int64("offset", message.Offset),
				)

				c.updateStats(func(stats *ConsumerStats) {
					stats.MessagesFailed++
				})

				// Send to DLQ if enabled
				if c.config.EnableDLQ {
					c.sendToDLQ(ctx, &message, err, logger)
				}
			} else {
				c.updateStats(func(stats *ConsumerStats) {
					stats.MessagesProcessed++
				})
			}

			// Commit the message
			if err := reader.CommitMessages(ctx, message); err != nil {
				logger.Error("Failed to commit message", logging.String("error", err.Error()))
			}

			if c.config.EnableMetrics {
				c.metrics.RecordMessageReceived(message.Topic, "success")
			}
		}
	}
}

// processMessage processes a single Kafka message
func (c *KafkaEventConsumer) processMessage(ctx context.Context, message *kafka.Message, logger *logging.Logger) error {
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		c.updateStats(func(stats *ConsumerStats) {
			// Update average processing time
			if stats.MessagesProcessed > 0 {
				stats.AvgProcessingTime = time.Duration(
					(int64(stats.AvgProcessingTime) + int64(duration)) / 2,
				)
			} else {
				stats.AvgProcessingTime = duration
			}
		})
	}()

	// Parse message headers for context
	requestContext := c.extractRequestContext(message)

	// Unmarshal the event
	var event entity.Event
	if err := json.Unmarshal(message.Value, &event); err != nil {
		return common.WrapError(err, common.ErrCodeInvalidInput, "failed to unmarshal event from message")
	}

	// Validate event
	if err := event.Validate(); err != nil {
		return common.WrapError(err, common.ErrCodeValidationFailed, "invalid event received from queue")
	}

	// Create processing request
	req := &usecase.ProcessEventRequest{
		Event:          &event,
		RequestContext: requestContext,
		ProcessingConfig: &usecase.ProcessingConfig{
			EnableValidation:     true,
			EnableNormalization:  true,
			EnableEnrichment:     true,
			EnableRiskAssessment: true,
			EnableCorrelation:    true,
			Timeout:             c.config.ProcessingTimeout,
			RetryAttempts:       c.config.MaxRetries,
		},
	}

	// Process the event
	response, err := c.processEventUseCase.Execute(ctx, req)
	if err != nil {
		return common.WrapError(err, common.ErrCodeInternal, "failed to process event")
	}

	logger.Debug("Event processed successfully",
		logging.String("event_id", response.EventID.String()),
		logging.String("status", string(response.Status)),
		logging.Duration("duration", response.Duration),
		logging.Float64("risk_score", response.RiskScore),
	)

	return nil
}

// extractRequestContext extracts request context from Kafka message headers
func (c *KafkaEventConsumer) extractRequestContext(message *kafka.Message) *types.RequestContext {
	reqCtx := &types.RequestContext{
		CorrelationID: types.NewCorrelationID(),
		ServiceID:     types.ServiceID("event-processor"),
		Timestamp:     time.Now().UTC(),
	}

	// Extract context from headers
	for _, header := range message.Headers {
		switch header.Key {
		case "correlation_id":
			if correlationID, err := types.CorrelationID(header.Value).String(), error(nil); err == nil {
				reqCtx.CorrelationID = types.CorrelationID(correlationID)
			}
		case "tenant_id":
			if tenantID, err := types.TenantID(header.Value).String(), error(nil); err == nil {
				reqCtx.TenantID = types.TenantID(tenantID)
			}
		case "user_id":
			if userID, err := types.UserID(header.Value).String(), error(nil); err == nil {
				userIDVal := types.UserID(userID)
				reqCtx.UserID = &userIDVal
			}
		case "trace_id":
			reqCtx.TraceID = string(header.Value)
		case "span_id":
			reqCtx.SpanID = string(header.Value)
		case "ip_address":
			reqCtx.IPAddress = string(header.Value)
		case "user_agent":
			reqCtx.UserAgent = string(header.Value)
		}
	}

	return reqCtx
}

// sendToDLQ sends a failed message to the dead letter queue
func (c *KafkaEventConsumer) sendToDLQ(ctx context.Context, message *kafka.Message, processingError error, logger *logging.Logger) {
	if c.config.DLQTopic == "" {
		return
	}

	// Create DLQ message with original message and error info
	dlqMessage := struct {
		OriginalTopic     string            `json:"original_topic"`
		OriginalPartition int               `json:"original_partition"`
		OriginalOffset    int64             `json:"original_offset"`
		OriginalMessage   []byte            `json:"original_message"`
		OriginalHeaders   []kafka.Header    `json:"original_headers"`
		Error             string            `json:"error"`
		FailedAt          time.Time         `json:"failed_at"`
		RetryCount        int               `json:"retry_count"`
	}{
		OriginalTopic:     message.Topic,
		OriginalPartition: message.Partition,
		OriginalOffset:    message.Offset,
		OriginalMessage:   message.Value,
		OriginalHeaders:   message.Headers,
		Error:             processingError.Error(),
		FailedAt:          time.Now().UTC(),
		RetryCount:        1, // TODO: Track actual retry count
	}

	dlqData, err := json.Marshal(dlqMessage)
	if err != nil {
		logger.Error("Failed to marshal DLQ message", logging.String("error", err.Error()))
		return
	}

	// Create DLQ producer (in a real implementation, this would be reused)
	writer := &kafka.Writer{
		Addr:     kafka.TCP(c.config.Brokers...),
		Topic:    c.config.DLQTopic,
		Balancer: &kafka.LeastBytes{},
	}
	defer writer.Close()

	// Send to DLQ
	err = writer.WriteMessages(ctx, kafka.Message{
		Value: dlqData,
		Headers: []kafka.Header{
			{Key: "dlq_reason", Value: []byte("processing_failed")},
			{Key: "original_topic", Value: []byte(message.Topic)},
			{Key: "failed_at", Value: []byte(time.Now().UTC().Format(time.RFC3339))},
		},
	})

	if err != nil {
		logger.Error("Failed to send message to DLQ", logging.String("error", err.Error()))
		if c.config.EnableMetrics {
			c.metrics.RecordError("dlq_send_error", "event-processor")
		}
	} else {
		logger.Info("Message sent to DLQ",
			logging.String("dlq_topic", c.config.DLQTopic),
			logging.String("original_topic", message.Topic),
			logging.Int64("original_offset", message.Offset),
		)
		if c.config.EnableMetrics {
			c.metrics.RecordMessageSent(c.config.DLQTopic, "dlq")
		}
	}
}

// updateStats safely updates consumer statistics
func (c *KafkaEventConsumer) updateStats(updateFunc func(*ConsumerStats)) {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	updateFunc(c.stats)
}

// statsReporter periodically reports statistics
func (c *KafkaEventConsumer) statsReporter(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reportStats()
		}
	}
}

// reportStats reports current statistics
func (c *KafkaEventConsumer) reportStats() {
	c.statsMu.Lock()
	stats := *c.stats
	
	// Calculate error rate
	if stats.MessagesReceived > 0 {
		stats.ErrorRate = float64(stats.MessagesFailed) / float64(stats.MessagesReceived)
	}
	
	// Calculate throughput
	elapsed := time.Since(c.lastStatsReset)
	if elapsed > 0 {
		stats.ThroughputPerSecond = float64(stats.MessagesProcessed) / elapsed.Seconds()
	}
	
	// Update stats
	c.stats.ErrorRate = stats.ErrorRate
	c.stats.ThroughputPerSecond = stats.ThroughputPerSecond
	c.statsMu.Unlock()

	// Log statistics
	c.logger.Info("Consumer statistics",
		logging.Int64("messages_received", stats.MessagesReceived),
		logging.Int64("messages_processed", stats.MessagesProcessed),
		logging.Int64("messages_failed", stats.MessagesFailed),
		logging.Float64("error_rate", stats.ErrorRate),
		logging.Float64("throughput_per_second", stats.ThroughputPerSecond),
		logging.Duration("avg_processing_time", stats.AvgProcessingTime),
	)

	// Record metrics
	if c.config.EnableMetrics {
		c.metrics.RecordBusinessOperation("message_processing", "kafka", "stats_report", 0)
		
		// Record individual metrics
		for _, topic := range c.config.Topics {
			c.metrics.RecordQueueDepth(topic, "0", float64(stats.ConsumerLag))
		}
	}
}

// logKafkaMessage logs Kafka informational messages
func (c *KafkaEventConsumer) logKafkaMessage(msg string, args ...interface{}) {
	c.logger.Debug(fmt.Sprintf("Kafka: "+msg, args...))
}

// logKafkaError logs Kafka error messages
func (c *KafkaEventConsumer) logKafkaError(msg string, args ...interface{}) {
	c.logger.Error(fmt.Sprintf("Kafka Error: "+msg, args...))
}