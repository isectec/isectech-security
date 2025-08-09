package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// StreamsManager manages Redis Streams for iSECTECH event processing
type StreamsManager struct {
	client         redis.Cmdable
	config         *Config
	logger         *zap.Logger
	consumers      map[string]*StreamConsumer
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	processingWg   sync.WaitGroup
}

// StreamConsumer represents a Redis Stream consumer
type StreamConsumer struct {
	name           string
	streamName     string
	groupName      string
	consumerName   string
	config         ConsumerGroupConfig
	client         redis.Cmdable
	logger         *zap.Logger
	handler        MessageHandler
	running        bool
	mu             sync.RWMutex
}

// MessageHandler defines the interface for processing stream messages
type MessageHandler interface {
	ProcessMessage(ctx context.Context, message *StreamMessage) error
	GetConsumerGroup() string
	GetStreamName() string
}

// SecurityEventHandler processes security events from streams
type SecurityEventHandler struct {
	logger    *zap.Logger
	tenantID  string
	processor SecurityEventProcessor
}

// SecurityEventProcessor defines the interface for processing security events
type SecurityEventProcessor interface {
	ProcessSecurityEvent(ctx context.Context, event *SecurityEvent) error
	EnrichEvent(ctx context.Context, event *SecurityEvent) error
	CorrelateEvent(ctx context.Context, event *SecurityEvent) ([]string, error)
	GenerateAlerts(ctx context.Context, event *SecurityEvent) error
}

// AuditEventHandler processes audit events from streams
type AuditEventHandler struct {
	logger    *zap.Logger
	tenantID  string
	processor AuditEventProcessor
}

// AuditEventProcessor defines the interface for processing audit events
type AuditEventProcessor interface {
	ProcessAuditEvent(ctx context.Context, event *AuditEvent) error
	StoreAuditEvent(ctx context.Context, event *AuditEvent) error
	TriggerComplianceChecks(ctx context.Context, event *AuditEvent) error
}

// ThreatIntelHandler processes threat intelligence updates from streams
type ThreatIntelHandler struct {
	logger    *zap.Logger
	tenantID  string
	processor ThreatIntelProcessor
}

// ThreatIntelProcessor defines the interface for processing threat intelligence
type ThreatIntelProcessor interface {
	ProcessThreatIntel(ctx context.Context, intel map[string]interface{}) error
	UpdateThreatDatabase(ctx context.Context, intel map[string]interface{}) error
	CorrelateWithEvents(ctx context.Context, intel map[string]interface{}) error
}

// NewStreamsManager creates a new streams manager
func NewStreamsManager(client redis.Cmdable, config *Config, logger *zap.Logger) (*StreamsManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	sm := &StreamsManager{
		client:    client,
		config:    config,
		logger:    logger,
		consumers: make(map[string]*StreamConsumer),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Initialize consumer groups
	if err := sm.initializeConsumerGroups(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize consumer groups: %w", err)
	}

	logger.Info("Redis streams manager initialized",
		zap.Int("consumer_groups", len(config.Streams.ConsumerGroups)))

	return sm, nil
}

// initializeConsumerGroups creates consumer groups if they don't exist
func (sm *StreamsManager) initializeConsumerGroups() error {
	for name, groupConfig := range sm.config.Streams.ConsumerGroups {
		// Create stream if it doesn't exist
		exists, err := sm.streamExists(groupConfig.StreamName)
		if err != nil {
			return fmt.Errorf("failed to check if stream exists: %w", err)
		}

		if !exists {
			// Create stream with a dummy message that will be deleted
			err = sm.client.XAdd(sm.ctx, &redis.XAddArgs{
				Stream: groupConfig.StreamName,
				ID:     "*",
				Values: map[string]interface{}{
					"init": "true",
				},
			}).Err()
			if err != nil {
				return fmt.Errorf("failed to create stream %s: %w", groupConfig.StreamName, err)
			}

			// Delete the dummy message
			sm.client.XTrim(sm.ctx, groupConfig.StreamName, 0)
		}

		// Create consumer group
		err = sm.client.XGroupCreate(sm.ctx, groupConfig.StreamName, groupConfig.GroupName, "0").Err()
		if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
			return fmt.Errorf("failed to create consumer group %s: %w", groupConfig.GroupName, err)
		}

		sm.logger.Info("Consumer group initialized",
			zap.String("group", name),
			zap.String("stream", groupConfig.StreamName),
			zap.String("group_name", groupConfig.GroupName))
	}

	return nil
}

// streamExists checks if a stream exists
func (sm *StreamsManager) streamExists(streamName string) (bool, error) {
	result, err := sm.client.Exists(sm.ctx, streamName).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// PublishMessage publishes a message to a Redis Stream
func (sm *StreamsManager) PublishMessage(ctx context.Context, message *StreamMessage) error {
	// Prepare stream data
	values := make(map[string]interface{})
	values["tenant_id"] = message.TenantID
	values["event_type"] = message.EventType
	values["timestamp"] = message.Timestamp.Format(time.RFC3339Nano)

	// Add data fields
	for key, value := range message.Data {
		// Serialize complex objects to JSON
		if valueBytes, err := json.Marshal(value); err == nil {
			values[fmt.Sprintf("data_%s", key)] = string(valueBytes)
		} else {
			values[fmt.Sprintf("data_%s", key)] = fmt.Sprintf("%v", value)
		}
	}

	// Add metadata fields
	for key, value := range message.Metadata {
		if valueBytes, err := json.Marshal(value); err == nil {
			values[fmt.Sprintf("meta_%s", key)] = string(valueBytes)
		} else {
			values[fmt.Sprintf("meta_%s", key)] = fmt.Sprintf("%v", value)
		}
	}

	// Publish to stream
	args := &redis.XAddArgs{
		Stream: message.Stream,
		ID:     "*",
		Values: values,
	}

	// Apply max length if configured
	if sm.config.Streams.MaxLength > 0 {
		args.MaxLen = sm.config.Streams.MaxLength
		args.Approx = sm.config.Streams.ApproxMaxLength
	}

	id, err := sm.client.XAdd(ctx, args).Result()
	if err != nil {
		return fmt.Errorf("failed to publish message to stream %s: %w", message.Stream, err)
	}

	message.ID = id

	sm.logger.Debug("Message published to stream",
		zap.String("stream", message.Stream),
		zap.String("id", id),
		zap.String("tenant_id", message.TenantID),
		zap.String("event_type", message.EventType))

	return nil
}

// StartConsumer starts a stream consumer
func (sm *StreamsManager) StartConsumer(consumerName string, handler MessageHandler) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	groupConfig, exists := sm.config.Streams.ConsumerGroups[consumerName]
	if !exists {
		return fmt.Errorf("consumer group configuration not found: %s", consumerName)
	}

	consumer := &StreamConsumer{
		name:         consumerName,
		streamName:   groupConfig.StreamName,
		groupName:    groupConfig.GroupName,
		consumerName: groupConfig.ConsumerName,
		config:       groupConfig,
		client:       sm.client,
		logger:       sm.logger.With(zap.String("consumer", consumerName)),
		handler:      handler,
	}

	sm.consumers[consumerName] = consumer

	// Start consumer in goroutine
	sm.processingWg.Add(1)
	go sm.runConsumer(consumer)

	sm.logger.Info("Stream consumer started",
		zap.String("consumer", consumerName),
		zap.String("stream", groupConfig.StreamName),
		zap.String("group", groupConfig.GroupName))

	return nil
}

// StopConsumer stops a stream consumer
func (sm *StreamsManager) StopConsumer(consumerName string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	consumer, exists := sm.consumers[consumerName]
	if !exists {
		return fmt.Errorf("consumer not found: %s", consumerName)
	}

	consumer.mu.Lock()
	consumer.running = false
	consumer.mu.Unlock()

	delete(sm.consumers, consumerName)

	sm.logger.Info("Stream consumer stopped",
		zap.String("consumer", consumerName))

	return nil
}

// runConsumer runs the consumer loop
func (sm *StreamsManager) runConsumer(consumer *StreamConsumer) {
	defer sm.processingWg.Done()

	consumer.mu.Lock()
	consumer.running = true
	consumer.mu.Unlock()

	for {
		consumer.mu.RLock()
		running := consumer.running
		consumer.mu.RUnlock()

		if !running {
			break
		}

		select {
		case <-sm.ctx.Done():
			return
		default:
			if err := sm.processConsumerBatch(consumer); err != nil {
				consumer.logger.Error("Error processing consumer batch",
					zap.Error(err))
				time.Sleep(consumer.config.RetryInterval)
			}
		}
	}
}

// processConsumerBatch processes a batch of messages for a consumer
func (sm *StreamsManager) processConsumerBatch(consumer *StreamConsumer) error {
	ctx, cancel := context.WithTimeout(sm.ctx, sm.config.Streams.ProcessingTimeout)
	defer cancel()

	// Read messages from the stream
	streams, err := consumer.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    consumer.groupName,
		Consumer: consumer.consumerName,
		Streams:  []string{consumer.streamName, ">"},
		Count:    consumer.config.BatchSize,
		Block:    sm.config.Streams.BlockingTimeout,
		NoAck:    false,
	}).Result()

	if err != nil {
		if err == redis.Nil {
			// No messages available
			return nil
		}
		return fmt.Errorf("failed to read from stream: %w", err)
	}

	// Process each stream
	for _, stream := range streams {
		for _, message := range stream.Messages {
			if err := sm.processStreamMessage(ctx, consumer, message); err != nil {
				consumer.logger.Error("Failed to process stream message",
					zap.String("message_id", message.ID),
					zap.Error(err))

				// Handle failed message
				if err := sm.handleFailedMessage(ctx, consumer, message, err); err != nil {
					consumer.logger.Error("Failed to handle failed message",
						zap.String("message_id", message.ID),
						zap.Error(err))
				}
			} else {
				// Acknowledge successful processing
				err = consumer.client.XAck(ctx, consumer.streamName, consumer.groupName, message.ID).Err()
				if err != nil {
					consumer.logger.Error("Failed to acknowledge message",
						zap.String("message_id", message.ID),
						zap.Error(err))
				}
			}
		}
	}

	return nil
}

// processStreamMessage processes a single stream message
func (sm *StreamsManager) processStreamMessage(ctx context.Context, consumer *StreamConsumer, redisMsg redis.XMessage) error {
	// Convert Redis message to StreamMessage
	streamMsg, err := sm.convertRedisMessage(redisMsg, consumer.streamName)
	if err != nil {
		return fmt.Errorf("failed to convert Redis message: %w", err)
	}

	// Process message with handler
	if err := consumer.handler.ProcessMessage(ctx, streamMsg); err != nil {
		return fmt.Errorf("handler failed to process message: %w", err)
	}

	consumer.logger.Debug("Stream message processed successfully",
		zap.String("message_id", redisMsg.ID),
		zap.String("tenant_id", streamMsg.TenantID),
		zap.String("event_type", streamMsg.EventType))

	return nil
}

// convertRedisMessage converts a Redis XMessage to a StreamMessage
func (sm *StreamsManager) convertRedisMessage(redisMsg redis.XMessage, streamName string) (*StreamMessage, error) {
	streamMsg := &StreamMessage{
		ID:       redisMsg.ID,
		Stream:   streamName,
		Data:     make(map[string]interface{}),
		Metadata: make(map[string]interface{}),
	}

	for key, value := range redisMsg.Values {
		strValue, ok := value.(string)
		if !ok {
			continue
		}

		switch {
		case key == "tenant_id":
			streamMsg.TenantID = strValue
		case key == "event_type":
			streamMsg.EventType = strValue
		case key == "timestamp":
			if ts, err := time.Parse(time.RFC3339Nano, strValue); err == nil {
				streamMsg.Timestamp = ts
			}
		case len(key) > 5 && key[:5] == "data_":
			dataKey := key[5:]
			var value interface{}
			if err := json.Unmarshal([]byte(strValue), &value); err != nil {
				value = strValue
			}
			streamMsg.Data[dataKey] = value
		case len(key) > 5 && key[:5] == "meta_":
			metaKey := key[5:]
			var value interface{}
			if err := json.Unmarshal([]byte(strValue), &value); err != nil {
				value = strValue
			}
			streamMsg.Metadata[metaKey] = value
		}
	}

	return streamMsg, nil
}

// handleFailedMessage handles messages that failed to process
func (sm *StreamsManager) handleFailedMessage(ctx context.Context, consumer *StreamConsumer, message redis.XMessage, processErr error) error {
	// Check retry count
	retryCount := 0
	if retryStr, exists := message.Values["retry_count"]; exists {
		if retryCountInt, ok := retryStr.(int); ok {
			retryCount = retryCountInt
		}
	}

	if retryCount >= consumer.config.MaxRetries {
		// Move to dead letter queue or log
		consumer.logger.Error("Message exceeded max retries",
			zap.String("message_id", message.ID),
			zap.Int("retry_count", retryCount),
			zap.Error(processErr))

		// Acknowledge to remove from pending
		return consumer.client.XAck(ctx, consumer.streamName, consumer.groupName, message.ID).Err()
	}

	// Increment retry count and re-queue
	retryCount++
	
	// Add message back to stream with retry count
	values := make(map[string]interface{})
	for k, v := range message.Values {
		values[k] = v
	}
	values["retry_count"] = retryCount
	values["last_error"] = processErr.Error()
	values["retry_at"] = time.Now().Add(consumer.config.RetryInterval).Format(time.RFC3339Nano)

	// Add to retry stream
	retryStream := fmt.Sprintf("%s:retry", consumer.streamName)
	err := consumer.client.XAdd(ctx, &redis.XAddArgs{
		Stream: retryStream,
		ID:     "*",
		Values: values,
	}).Err()

	if err != nil {
		return fmt.Errorf("failed to add message to retry stream: %w", err)
	}

	// Acknowledge original message
	return consumer.client.XAck(ctx, consumer.streamName, consumer.groupName, message.ID).Err()
}

// GetPendingMessages returns pending messages for a consumer group
func (sm *StreamsManager) GetPendingMessages(ctx context.Context, streamName, groupName string) (*redis.XPending, error) {
	return sm.client.XPending(ctx, streamName, groupName).Result()
}

// ClaimPendingMessages claims pending messages that have been idle
func (sm *StreamsManager) ClaimPendingMessages(ctx context.Context, streamName, groupName, consumerName string, minIdleTime time.Duration) ([]redis.XMessage, error) {
	// Get pending messages
	pending, err := sm.client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream: streamName,
		Group:  groupName,
		Start:  "-",
		End:    "+",
		Count:  100,
	}).Result()

	if err != nil {
		return nil, fmt.Errorf("failed to get pending messages: %w", err)
	}

	// Filter messages that have been idle too long
	var idleMsgIDs []string
	for _, msg := range pending {
		if msg.Idle >= minIdleTime {
			idleMsgIDs = append(idleMsgIDs, msg.ID)
		}
	}

	if len(idleMsgIDs) == 0 {
		return nil, nil
	}

	// Claim the idle messages
	return sm.client.XClaim(ctx, &redis.XClaimArgs{
		Stream:   streamName,
		Group:    groupName,
		Consumer: consumerName,
		MinIdle:  minIdleTime,
		Messages: idleMsgIDs,
	}).Result()
}

// Close stops all consumers and closes the streams manager
func (sm *StreamsManager) Close() error {
	sm.cancel()

	// Stop all consumers
	sm.mu.Lock()
	for name := range sm.consumers {
		sm.StopConsumer(name)
	}
	sm.mu.Unlock()

	// Wait for all processing to complete
	sm.processingWg.Wait()

	sm.logger.Info("Streams manager closed")
	return nil
}

// Implementation of message handlers

// ProcessMessage implements MessageHandler for SecurityEventHandler
func (h *SecurityEventHandler) ProcessMessage(ctx context.Context, message *StreamMessage) error {
	// Convert stream message to security event
	event, err := h.convertToSecurityEvent(message)
	if err != nil {
		return fmt.Errorf("failed to convert to security event: %w", err)
	}

	// Process the security event
	return h.processor.ProcessSecurityEvent(ctx, event)
}

func (h *SecurityEventHandler) GetConsumerGroup() string {
	return "security-events"
}

func (h *SecurityEventHandler) GetStreamName() string {
	return "security:events"
}

func (h *SecurityEventHandler) convertToSecurityEvent(message *StreamMessage) (*SecurityEvent, error) {
	event := &SecurityEvent{
		TenantID:  message.TenantID,
		Timestamp: message.Timestamp,
		Metadata:  message.Metadata,
	}

	// Extract fields from message data
	if id, ok := message.Data["id"].(string); ok {
		event.ID = id
	}
	if eventType, ok := message.Data["event_type"].(string); ok {
		event.EventType = eventType
	}
	if severity, ok := message.Data["severity"].(string); ok {
		event.Severity = severity
	}
	if description, ok := message.Data["description"].(string); ok {
		event.Description = description
	}
	if riskScore, ok := message.Data["risk_score"].(float64); ok {
		event.RiskScore = int(riskScore)
	}

	// Extract complex fields
	if source, ok := message.Data["source"].(map[string]interface{}); ok {
		event.Source = source
	}
	if target, ok := message.Data["target"].(map[string]interface{}); ok {
		event.Target = target
	}
	if tags, ok := message.Data["tags"].([]interface{}); ok {
		event.Tags = make([]string, len(tags))
		for i, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				event.Tags[i] = tagStr
			}
		}
	}

	return event, nil
}

// ProcessMessage implements MessageHandler for AuditEventHandler
func (h *AuditEventHandler) ProcessMessage(ctx context.Context, message *StreamMessage) error {
	// Convert stream message to audit event
	event, err := h.convertToAuditEvent(message)
	if err != nil {
		return fmt.Errorf("failed to convert to audit event: %w", err)
	}

	// Process the audit event
	return h.processor.ProcessAuditEvent(ctx, event)
}

func (h *AuditEventHandler) GetConsumerGroup() string {
	return "audit-events"
}

func (h *AuditEventHandler) GetStreamName() string {
	return "audit:events"
}

func (h *AuditEventHandler) convertToAuditEvent(message *StreamMessage) (*AuditEvent, error) {
	event := &AuditEvent{
		TenantID:  message.TenantID,
		Timestamp: message.Timestamp,
	}

	// Extract fields from message data
	if id, ok := message.Data["id"].(string); ok {
		event.ID = id
	}
	if userID, ok := message.Data["user_id"].(string); ok {
		event.UserID = userID
	}
	if action, ok := message.Data["action"].(string); ok {
		event.Action = action
	}
	if resourceType, ok := message.Data["resource_type"].(string); ok {
		event.ResourceType = resourceType
	}
	if resourceID, ok := message.Data["resource_id"].(string); ok {
		event.ResourceID = resourceID
	}
	if sourceIP, ok := message.Data["source_ip"].(string); ok {
		event.SourceIP = sourceIP
	}
	if userAgent, ok := message.Data["user_agent"].(string); ok {
		event.UserAgent = userAgent
	}
	if status, ok := message.Data["status"].(string); ok {
		event.Status = status
	}
	if errorMessage, ok := message.Data["error_message"].(string); ok {
		event.ErrorMessage = errorMessage
	}
	if details, ok := message.Data["details"].(map[string]interface{}); ok {
		event.Details = details
	}

	return event, nil
}