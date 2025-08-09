package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"github.com/isectech/platform/shared/database/redis"
)

// EventSystem manages event-driven integration across databases
type EventSystem struct {
	config EventSystemConfig
	redis  *redis.Client
	logger *zap.Logger
	
	// Event handlers
	handlers     map[string][]EventHandler
	handlersMu   sync.RWMutex
	
	// Event processing
	eventQueue   chan *IntegrationEvent
	deadLetterQueue chan *IntegrationEvent
	
	// State management
	closed       bool
	closeCh      chan struct{}
	wg           sync.WaitGroup
	
	// Metrics
	processedEvents   int64
	failedEvents      int64
	duplicateEvents   int64
}

// EventHandler defines the interface for event handlers
type EventHandler interface {
	HandleEvent(ctx context.Context, event *IntegrationEvent) error
	GetEventTypes() []string
	GetPriority() int
}

// DatabaseEventHandler handles database-specific events
type DatabaseEventHandler struct {
	name           string
	eventTypes     []string
	sourceDB       string
	targetDBs      []string
	priority       int
	processor      DatabaseEventProcessor
	logger         *zap.Logger
}

// DatabaseEventProcessor defines the interface for processing database events
type DatabaseEventProcessor interface {
	ProcessEvent(ctx context.Context, event *IntegrationEvent, targetDB string) error
}

// EventProcessingResult represents the result of event processing
type EventProcessingResult struct {
	Success     bool                   `json:"success"`
	EventID     string                 `json:"event_id"`
	ProcessedAt time.Time              `json:"processed_at"`
	Duration    time.Duration          `json:"duration"`
	TargetDB    string                 `json:"target_db"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewEventSystem creates a new event system
func NewEventSystem(
	config EventSystemConfig,
	redis *redis.Client,
	logger *zap.Logger,
) (*EventSystem, error) {
	
	es := &EventSystem{
		config:          config,
		redis:           redis,
		logger:          logger,
		handlers:        make(map[string][]EventHandler),
		eventQueue:      make(chan *IntegrationEvent, 10000),
		deadLetterQueue: make(chan *IntegrationEvent, 1000),
		closeCh:         make(chan struct{}),
	}
	
	// Initialize event store
	if err := es.initializeEventStore(); err != nil {
		return nil, fmt.Errorf("failed to initialize event store: %w", err)
	}
	
	// Start event processors
	es.startEventProcessors()
	
	// Register default event handlers
	if err := es.registerDefaultHandlers(); err != nil {
		return nil, fmt.Errorf("failed to register default handlers: %w", err)
	}
	
	logger.Info("Event system initialized",
		zap.Bool("enabled", config.Enabled),
		zap.String("event_store_type", config.EventStore.Type),
		zap.String("processing_mode", config.ProcessingMode),
	)
	
	return es, nil
}

// PublishEvent publishes an event to the event system
func (es *EventSystem) PublishEvent(ctx context.Context, event *IntegrationEvent) error {
	if !es.config.Enabled {
		return fmt.Errorf("event system is disabled")
	}
	
	if es.closed {
		return fmt.Errorf("event system is closed")
	}
	
	// Check for duplicates if enabled
	if es.config.DuplicateDetection {
		if isDuplicate, err := es.checkDuplicate(ctx, event); err != nil {
			es.logger.Warn("Failed to check for duplicate event", zap.Error(err))
		} else if isDuplicate {
			es.duplicateEvents++
			es.logger.Debug("Duplicate event detected, skipping",
				zap.String("event_id", event.ID),
				zap.String("type", event.Type),
			)
			return nil
		}
	}
	
	// Store event in event store
	if err := es.storeEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}
	
	// Publish to event bus based on processing mode
	switch es.config.ProcessingMode {
	case "async":
		select {
		case es.eventQueue <- event:
			return nil
		default:
			return fmt.Errorf("event queue is full")
		}
	case "sync":
		return es.processEventSync(ctx, event)
	case "hybrid":
		// Use async for non-critical events, sync for critical ones
		if event.Priority >= 5 {
			return es.processEventSync(ctx, event)
		} else {
			select {
			case es.eventQueue <- event:
				return nil
			default:
				return fmt.Errorf("event queue is full")
			}
		}
	default:
		return fmt.Errorf("unsupported processing mode: %s", es.config.ProcessingMode)
	}
}

// RegisterEventHandler registers an event handler
func (es *EventSystem) RegisterEventHandler(handler EventHandler) error {
	es.handlersMu.Lock()
	defer es.handlersMu.Unlock()
	
	for _, eventType := range handler.GetEventTypes() {
		if _, exists := es.handlers[eventType]; !exists {
			es.handlers[eventType] = make([]EventHandler, 0)
		}
		
		// Insert handler in priority order
		handlers := es.handlers[eventType]
		inserted := false
		for i, existingHandler := range handlers {
			if handler.GetPriority() > existingHandler.GetPriority() {
				es.handlers[eventType] = append(handlers[:i], 
					append([]EventHandler{handler}, handlers[i:]...)...)
				inserted = true
				break
			}
		}
		
		if !inserted {
			es.handlers[eventType] = append(handlers, handler)
		}
	}
	
	es.logger.Info("Event handler registered",
		zap.Strings("event_types", handler.GetEventTypes()),
		zap.Int("priority", handler.GetPriority()),
	)
	
	return nil
}

// ProcessPendingEvents processes pending events from the queue
func (es *EventSystem) ProcessPendingEvents(ctx context.Context) error {
	if !es.config.Enabled {
		return nil
	}
	
	// Process events from Redis streams if using stream-based event bus
	if es.config.EventBus.Type == "redis_streams" {
		return es.processRedisStreamEvents(ctx)
	}
	
	return nil
}

// Close stops the event system
func (es *EventSystem) Close() error {
	if es.closed {
		return nil
	}
	
	es.closed = true
	close(es.closeCh)
	es.wg.Wait()
	
	close(es.eventQueue)
	close(es.deadLetterQueue)
	
	es.logger.Info("Event system closed")
	return nil
}

// Private methods

func (es *EventSystem) initializeEventStore() error {
	switch es.config.EventStore.Type {
	case "redis":
		// Initialize Redis streams for event storage
		return es.initializeRedisEventStore()
	case "postgres":
		// Initialize PostgreSQL event store
		return es.initializePostgresEventStore()
	case "mongodb":
		// Initialize MongoDB event store
		return es.initializeMongoEventStore()
	default:
		return fmt.Errorf("unsupported event store type: %s", es.config.EventStore.Type)
	}
}

func (es *EventSystem) initializeRedisEventStore() error {
	// Create Redis stream for events
	streamName := es.config.EventStore.Stream
	
	// Check if stream exists, create if not
	ctx := context.Background()
	exists, err := es.redis.StreamExists(ctx, streamName)
	if err != nil {
		return fmt.Errorf("failed to check stream existence: %w", err)
	}
	
	if !exists {
		// Create stream with initial dummy entry
		if err := es.redis.StreamAdd(ctx, streamName, map[string]interface{}{
			"type": "system",
			"data": "stream_initialized",
		}); err != nil {
			return fmt.Errorf("failed to create stream: %w", err)
		}
	}
	
	// Create consumer groups for each topic
	for _, group := range es.config.EventBus.ConsumerGroups {
		if err := es.redis.StreamCreateConsumerGroup(ctx, streamName, group, "0"); err != nil {
			// Ignore error if group already exists
			es.logger.Debug("Consumer group may already exist",
				zap.String("group", group),
				zap.Error(err),
			)
		}
	}
	
	return nil
}

func (es *EventSystem) initializePostgresEventStore() error {
	// Implementation for PostgreSQL event store
	// This would create necessary tables and indexes
	return nil
}

func (es *EventSystem) initializeMongoEventStore() error {
	// Implementation for MongoDB event store
	// This would create necessary collections and indexes
	return nil
}

func (es *EventSystem) startEventProcessors() {
	// Start async event processors
	numProcessors := 4 // Configurable
	for i := 0; i < numProcessors; i++ {
		es.wg.Add(1)
		go es.eventProcessor()
	}
	
	// Start dead letter queue processor
	es.wg.Add(1)
	go es.deadLetterProcessor()
}

func (es *EventSystem) eventProcessor() {
	defer es.wg.Done()
	
	for {
		select {
		case event := <-es.eventQueue:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := es.processEventAsync(ctx, event); err != nil {
				es.logger.Error("Failed to process event",
					zap.String("event_id", event.ID),
					zap.Error(err),
				)
				es.failedEvents++
				
				// Send to dead letter queue if configured
				if es.config.DeadLetterQueue.Enabled {
					select {
					case es.deadLetterQueue <- event:
					default:
						es.logger.Error("Dead letter queue is full, dropping event",
							zap.String("event_id", event.ID),
						)
					}
				}
			} else {
				es.processedEvents++
			}
			cancel()
			
		case <-es.closeCh:
			return
		}
	}
}

func (es *EventSystem) deadLetterProcessor() {
	defer es.wg.Done()
	
	retryTicker := time.NewTicker(5 * time.Minute)
	defer retryTicker.Stop()
	
	deadLetterEvents := make([]*IntegrationEvent, 0)
	
	for {
		select {
		case event := <-es.deadLetterQueue:
			deadLetterEvents = append(deadLetterEvents, event)
			
		case <-retryTicker.C:
			if len(deadLetterEvents) > 0 {
				es.retryDeadLetterEvents(deadLetterEvents)
				deadLetterEvents = deadLetterEvents[:0] // Clear slice
			}
			
		case <-es.closeCh:
			return
		}
	}
}

func (es *EventSystem) processEventSync(ctx context.Context, event *IntegrationEvent) error {
	return es.processEvent(ctx, event)
}

func (es *EventSystem) processEventAsync(ctx context.Context, event *IntegrationEvent) error {
	return es.processEvent(ctx, event)
}

func (es *EventSystem) processEvent(ctx context.Context, event *IntegrationEvent) error {
	es.handlersMu.RLock()
	handlers, exists := es.handlers[event.Type]
	es.handlersMu.RUnlock()
	
	if !exists || len(handlers) == 0 {
		es.logger.Debug("No handlers registered for event type",
			zap.String("event_type", event.Type),
		)
		return nil
	}
	
	// Process event with all registered handlers
	var lastError error
	successCount := 0
	
	for _, handler := range handlers {
		if err := handler.HandleEvent(ctx, event); err != nil {
			es.logger.Error("Event handler failed",
				zap.String("event_id", event.ID),
				zap.String("event_type", event.Type),
				zap.Error(err),
			)
			lastError = err
		} else {
			successCount++
		}
	}
	
	if successCount == 0 && lastError != nil {
		return fmt.Errorf("all handlers failed, last error: %w", lastError)
	}
	
	return nil
}

func (es *EventSystem) processRedisStreamEvents(ctx context.Context) error {
	for _, group := range es.config.EventBus.ConsumerGroups {
		messages, err := es.redis.StreamReadGroup(ctx, es.config.EventStore.Stream, group, "consumer1", "10")
		if err != nil {
			es.logger.Error("Failed to read from stream",
				zap.String("group", group),
				zap.Error(err),
			)
			continue
		}
		
		for _, message := range messages {
			// Parse message into IntegrationEvent
			event, err := es.parseStreamMessage(message)
			if err != nil {
				es.logger.Error("Failed to parse stream message", zap.Error(err))
				continue
			}
			
			// Process event
			if err := es.processEvent(ctx, event); err != nil {
				es.logger.Error("Failed to process stream event", zap.Error(err))
			}
			
			// Acknowledge message
			if err := es.redis.StreamAck(ctx, es.config.EventStore.Stream, group, message.ID); err != nil {
				es.logger.Error("Failed to acknowledge stream message", zap.Error(err))
			}
		}
	}
	
	return nil
}

func (es *EventSystem) parseStreamMessage(message RedisStreamMessage) (*IntegrationEvent, error) {
	// Parse Redis stream message into IntegrationEvent
	eventData, exists := message.Values["event_data"]
	if !exists {
		return nil, fmt.Errorf("missing event_data in stream message")
	}
	
	var event IntegrationEvent
	if err := json.Unmarshal([]byte(eventData.(string)), &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event data: %w", err)
	}
	
	return &event, nil
}

func (es *EventSystem) storeEvent(ctx context.Context, event *IntegrationEvent) error {
	switch es.config.EventStore.Type {
	case "redis":
		return es.storeEventInRedis(ctx, event)
	case "postgres":
		return es.storeEventInPostgres(ctx, event)
	case "mongodb":
		return es.storeEventInMongo(ctx, event)
	default:
		return fmt.Errorf("unsupported event store type: %s", es.config.EventStore.Type)
	}
}

func (es *EventSystem) storeEventInRedis(ctx context.Context, event *IntegrationEvent) error {
	eventData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}
	
	fields := map[string]interface{}{
		"event_id":       event.ID,
		"event_type":     event.Type,
		"source":         event.Source,
		"tenant_id":      event.TenantID,
		"classification": event.Classification,
		"priority":       event.Priority,
		"event_data":     string(eventData),
		"timestamp":      event.Timestamp.Unix(),
	}
	
	// Add TTL if specified
	if event.TTL > 0 {
		fields["ttl"] = event.TTL.Seconds()
	}
	
	return es.redis.StreamAdd(ctx, es.config.EventStore.Stream, fields)
}

func (es *EventSystem) storeEventInPostgres(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for storing events in PostgreSQL
	return nil
}

func (es *EventSystem) storeEventInMongo(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for storing events in MongoDB
	return nil
}

func (es *EventSystem) checkDuplicate(ctx context.Context, event *IntegrationEvent) (bool, error) {
	// Simple duplicate detection based on event ID and timestamp
	// In production, this would be more sophisticated
	key := fmt.Sprintf("event_dedup:%s", event.ID)
	
	exists, err := es.redis.Exists(ctx, key)
	if err != nil {
		return false, err
	}
	
	if exists {
		return true, nil
	}
	
	// Store event ID with TTL for duplicate detection
	ttl := es.config.EventTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	
	return false, es.redis.Set(ctx, key, "1", ttl)
}

func (es *EventSystem) retryDeadLetterEvents(events []*IntegrationEvent) {
	for _, event := range events {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := es.processEvent(ctx, event); err != nil {
			es.logger.Error("Failed to retry dead letter event",
				zap.String("event_id", event.ID),
				zap.Error(err),
			)
		} else {
			es.logger.Info("Successfully retried dead letter event",
				zap.String("event_id", event.ID),
			)
		}
		cancel()
	}
}

func (es *EventSystem) registerDefaultHandlers() error {
	// Register default handlers for common event types
	
	// Security event handler
	securityHandler := &DatabaseEventHandler{
		name:       "security_event_handler",
		eventTypes: []string{"security_event_created", "security_event_updated"},
		sourceDB:   "mongodb",
		targetDBs:  []string{"elasticsearch", "postgres"},
		priority:   10,
		processor:  &SecurityEventProcessor{},
		logger:     es.logger,
	}
	
	if err := es.RegisterEventHandler(securityHandler); err != nil {
		return fmt.Errorf("failed to register security handler: %w", err)
	}
	
	// Asset event handler
	assetHandler := &DatabaseEventHandler{
		name:       "asset_event_handler",
		eventTypes: []string{"asset_created", "asset_updated", "asset_deleted"},
		sourceDB:   "postgres",
		targetDBs:  []string{"elasticsearch", "redis"},
		priority:   8,
		processor:  &AssetEventProcessor{},
		logger:     es.logger,
	}
	
	if err := es.RegisterEventHandler(assetHandler); err != nil {
		return fmt.Errorf("failed to register asset handler: %w", err)
	}
	
	// Compliance event handler
	complianceHandler := &DatabaseEventHandler{
		name:       "compliance_event_handler",
		eventTypes: []string{"compliance_assessment_completed", "compliance_status_changed"},
		sourceDB:   "postgres",
		targetDBs:  []string{"mongodb", "elasticsearch"},
		priority:   9,
		processor:  &ComplianceEventProcessor{},
		logger:     es.logger,
	}
	
	if err := es.RegisterEventHandler(complianceHandler); err != nil {
		return fmt.Errorf("failed to register compliance handler: %w", err)
	}
	
	return nil
}

// Event handler implementations

func (h *DatabaseEventHandler) HandleEvent(ctx context.Context, event *IntegrationEvent) error {
	for _, targetDB := range h.targetDBs {
		if err := h.processor.ProcessEvent(ctx, event, targetDB); err != nil {
			h.logger.Error("Failed to process event for target database",
				zap.String("event_id", event.ID),
				zap.String("target_db", targetDB),
				zap.Error(err),
			)
			return err
		}
	}
	return nil
}

func (h *DatabaseEventHandler) GetEventTypes() []string {
	return h.eventTypes
}

func (h *DatabaseEventHandler) GetPriority() int {
	return h.priority
}

// Event processor implementations

type SecurityEventProcessor struct{}

func (p *SecurityEventProcessor) ProcessEvent(ctx context.Context, event *IntegrationEvent, targetDB string) error {
	// Process security events for different target databases
	switch targetDB {
	case "elasticsearch":
		// Index security event in Elasticsearch for search and analytics
		return p.indexSecurityEvent(ctx, event)
	case "postgres":
		// Store security event summary in PostgreSQL for relational queries
		return p.storeSecurityEventSummary(ctx, event)
	default:
		return fmt.Errorf("unsupported target database for security events: %s", targetDB)
	}
}

func (p *SecurityEventProcessor) indexSecurityEvent(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for indexing security events in Elasticsearch
	return nil
}

func (p *SecurityEventProcessor) storeSecurityEventSummary(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for storing security event summaries in PostgreSQL
	return nil
}

type AssetEventProcessor struct{}

func (p *AssetEventProcessor) ProcessEvent(ctx context.Context, event *IntegrationEvent, targetDB string) error {
	// Process asset events for different target databases
	switch targetDB {
	case "elasticsearch":
		// Index asset information for search
		return p.indexAsset(ctx, event)
	case "redis":
		// Cache asset information for quick lookups
		return p.cacheAsset(ctx, event)
	default:
		return fmt.Errorf("unsupported target database for asset events: %s", targetDB)
	}
}

func (p *AssetEventProcessor) indexAsset(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for indexing assets in Elasticsearch
	return nil
}

func (p *AssetEventProcessor) cacheAsset(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for caching assets in Redis
	return nil
}

type ComplianceEventProcessor struct{}

func (p *ComplianceEventProcessor) ProcessEvent(ctx context.Context, event *IntegrationEvent, targetDB string) error {
	// Process compliance events for different target databases
	switch targetDB {
	case "mongodb":
		// Store detailed compliance data in MongoDB
		return p.storeComplianceData(ctx, event)
	case "elasticsearch":
		// Index compliance information for reporting
		return p.indexComplianceData(ctx, event)
	default:
		return fmt.Errorf("unsupported target database for compliance events: %s", targetDB)
	}
}

func (p *ComplianceEventProcessor) storeComplianceData(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for storing compliance data in MongoDB
	return nil
}

func (p *ComplianceEventProcessor) indexComplianceData(ctx context.Context, event *IntegrationEvent) error {
	// Implementation for indexing compliance data in Elasticsearch
	return nil
}

// Helper types

type RedisStreamMessage struct {
	ID     string
	Values map[string]interface{}
}