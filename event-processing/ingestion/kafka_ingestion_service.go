package ingestion

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IBM/sarama"
	"go.uber.org/zap"
)

// KafkaIngestionService provides high-performance event ingestion using Apache Kafka
type KafkaIngestionService struct {
	config        *KafkaConfig
	producer      sarama.AsyncProducer
	consumer      sarama.ConsumerGroup
	logger        *zap.Logger
	metrics       *IngestionMetrics
	rateLimiter   *RateLimiter
	backpressure  *BackpressureManager
	serializer    EventSerializer
	validator     EventValidator
	
	// State management
	isRunning     int32
	shutdownCh    chan struct{}
	wg            sync.WaitGroup
	errorHandler  ErrorHandler
	
	// Performance tracking
	lastMetricsReport time.Time
	eventCount        int64
	errorCount        int64
	bytesProcessed    int64
}

// KafkaConfig defines Kafka-specific configuration for iSECTECH
type KafkaConfig struct {
	// Connection Settings
	Brokers              []string      `json:"brokers" validate:"required"`
	ClientID             string        `json:"client_id" validate:"required"`
	GroupID              string        `json:"group_id" validate:"required"`
	
	// Security Configuration
	SecurityProtocol     string        `json:"security_protocol"` // PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL
	SASLMechanism        string        `json:"sasl_mechanism"`    // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, GSSAPI
	SASLUsername         string        `json:"sasl_username,omitempty"`
	SASLPassword         string        `json:"sasl_password,omitempty"`
	TLSConfig            *TLSConfig    `json:"tls_config,omitempty"`
	
	// Topic Configuration
	Topics               *TopicConfig  `json:"topics" validate:"required"`
	
	// Performance Settings
	BatchSize            int           `json:"batch_size"`            // Default: 16384
	LingerMs             int           `json:"linger_ms"`             // Default: 10
	CompressionType      string        `json:"compression_type"`      // none, gzip, snappy, lz4, zstd
	Acks                 string        `json:"acks"`                  // 0, 1, all
	Retries              int           `json:"retries"`               // Default: 3
	MaxInFlightRequests  int           `json:"max_in_flight_requests"` // Default: 5
	
	// Buffer and Queue Settings
	ChannelBufferSize    int           `json:"channel_buffer_size"`    // Default: 256
	FlushFrequency       time.Duration `json:"flush_frequency"`        // Default: 1s
	MaxMessageBytes      int           `json:"max_message_bytes"`      // Default: 1MB
	
	// Consumer Settings
	ConsumerTimeout      time.Duration `json:"consumer_timeout"`       // Default: 30s
	FetchMinBytes        int           `json:"fetch_min_bytes"`        // Default: 1
	FetchMaxBytes        int           `json:"fetch_max_bytes"`        // Default: 1MB
	FetchMaxWait         time.Duration `json:"fetch_max_wait"`         // Default: 500ms
	
	// Reliability Settings
	EnableIdempotent     bool          `json:"enable_idempotent"`      // Default: true
	TransactionTimeout   time.Duration `json:"transaction_timeout"`    // Default: 60s
	IsolationLevel       string        `json:"isolation_level"`        // read_uncommitted, read_committed
	
	// Monitoring and Metrics
	MetricsInterval      time.Duration `json:"metrics_interval"`       // Default: 30s
	EnableJMXReporter    bool          `json:"enable_jmx_reporter"`
	
	// Rate Limiting
	RateLimit            *RateLimitConfig `json:"rate_limit,omitempty"`
	
	// Backpressure Management
	Backpressure         *BackpressureConfig `json:"backpressure,omitempty"`
}

// TLSConfig defines TLS/SSL configuration
type TLSConfig struct {
	Enabled              bool   `json:"enabled"`
	CertFile             string `json:"cert_file,omitempty"`
	KeyFile              string `json:"key_file,omitempty"`
	CAFile               string `json:"ca_file,omitempty"`
	InsecureSkipVerify   bool   `json:"insecure_skip_verify"`
	ServerName           string `json:"server_name,omitempty"`
}

// TopicConfig defines topic configuration for different event types
type TopicConfig struct {
	// Primary Topics
	SecurityEvents       string `json:"security_events" validate:"required"`
	SystemEvents         string `json:"system_events" validate:"required"`
	AuditEvents          string `json:"audit_events" validate:"required"`
	
	// Priority Topics
	CriticalEvents       string `json:"critical_events" validate:"required"`
	HighPriorityEvents   string `json:"high_priority_events" validate:"required"`
	
	// Specialized Topics
	ThreatIntelligence   string `json:"threat_intelligence" validate:"required"`
	Vulnerabilities      string `json:"vulnerabilities" validate:"required"`
	Compliance           string `json:"compliance" validate:"required"`
	
	// Dead Letter Topics
	DeadLetterQueue      string `json:"dead_letter_queue" validate:"required"`
	RetryQueue           string `json:"retry_queue" validate:"required"`
	
	// Topic Settings
	Partitions           int    `json:"partitions"`           // Default: 12
	ReplicationFactor    int    `json:"replication_factor"`   // Default: 3
	RetentionHours       int    `json:"retention_hours"`      // Default: 168 (7 days)
	SegmentMs            int    `json:"segment_ms"`           // Default: 604800000 (7 days)
	CleanupPolicy        string `json:"cleanup_policy"`       // delete, compact
}

// RateLimitConfig defines rate limiting parameters
type RateLimitConfig struct {
	EventsPerSecond      int64         `json:"events_per_second"`      // Default: 1000000
	BurstSize            int64         `json:"burst_size"`             // Default: 10000
	WindowSize           time.Duration `json:"window_size"`            // Default: 1s
	EnablePerTenant      bool          `json:"enable_per_tenant"`      // Default: true
	TenantRateLimit      int64         `json:"tenant_rate_limit"`      // Default: 10000
}

// BackpressureConfig defines backpressure management
type BackpressureConfig struct {
	EnableBackpressure   bool          `json:"enable_backpressure"`    // Default: true
	HighWaterMark        int           `json:"high_water_mark"`        // Default: 100000
	LowWaterMark         int           `json:"low_water_mark"`         // Default: 50000
	BackoffMultiplier    float64       `json:"backoff_multiplier"`     // Default: 2.0
	MaxBackoffDuration   time.Duration `json:"max_backoff_duration"`   // Default: 30s
	CircuitBreakerThreshold int        `json:"circuit_breaker_threshold"` // Default: 1000
}

// IngestionMetrics tracks performance and operational metrics
type IngestionMetrics struct {
	// Throughput Metrics
	EventsIngested       int64   `json:"events_ingested"`
	EventsPerSecond      float64 `json:"events_per_second"`
	BytesPerSecond       float64 `json:"bytes_per_second"`
	
	// Latency Metrics
	AvgIngestLatency     time.Duration `json:"avg_ingest_latency"`
	P95IngestLatency     time.Duration `json:"p95_ingest_latency"`
	P99IngestLatency     time.Duration `json:"p99_ingest_latency"`
	
	// Error Metrics
	ErrorRate            float64 `json:"error_rate"`
	RetryCount           int64   `json:"retry_count"`
	DeadLetterCount      int64   `json:"dead_letter_count"`
	
	// Queue Metrics
	QueueDepth           int     `json:"queue_depth"`
	QueueUtilization     float64 `json:"queue_utilization"`
	
	// Resource Metrics
	CPUUsage             float64 `json:"cpu_usage"`
	MemoryUsage          float64 `json:"memory_usage"`
	NetworkBytesIn       int64   `json:"network_bytes_in"`
	NetworkBytesOut      int64   `json:"network_bytes_out"`
	
	// Connection Metrics
	ActiveConnections    int     `json:"active_connections"`
	ConnectionErrors     int64   `json:"connection_errors"`
	
	// Tenant Metrics
	TenantEventCounts    map[string]int64 `json:"tenant_event_counts"`
	TenantRateLimits     map[string]int64 `json:"tenant_rate_limits"`
	
	mutex                sync.RWMutex
	lastUpdate           time.Time
}

// EventSerializer handles event serialization for Kafka
type EventSerializer interface {
	Serialize(event *SecurityEvent) ([]byte, error)
	Deserialize(data []byte) (*SecurityEvent, error)
	GetContentType() string
}

// EventValidator validates events before ingestion
type EventValidator interface {
	Validate(event *SecurityEvent) error
	ValidateBatch(batch *EventBatch) error
}

// ErrorHandler handles ingestion errors
type ErrorHandler interface {
	HandleError(err error, event *SecurityEvent, context map[string]interface{})
	HandleBatchError(err error, batch *EventBatch, context map[string]interface{})
	GetErrorStats() map[string]int64
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	globalLimiter    *TokenBucket
	tenantLimiters   map[string]*TokenBucket
	config          *RateLimitConfig
	mutex           sync.RWMutex
}

// TokenBucket implements token bucket algorithm
type TokenBucket struct {
	capacity    int64
	tokens      int64
	refillRate  int64
	lastRefill  time.Time
	mutex       sync.Mutex
}

// BackpressureManager handles backpressure scenarios
type BackpressureManager struct {
	config          *BackpressureConfig
	currentDepth    int64
	isBackpressure  bool
	backoffDuration time.Duration
	circuitBreaker  *CircuitBreaker
	mutex           sync.RWMutex
}

// CircuitBreaker prevents cascade failures
type CircuitBreaker struct {
	failureCount    int64
	lastFailure     time.Time
	state          string // closed, open, half-open
	threshold      int
	timeout        time.Duration
	mutex          sync.RWMutex
}

// NewKafkaIngestionService creates a new Kafka ingestion service
func NewKafkaIngestionService(config *KafkaConfig, logger *zap.Logger) (*KafkaIngestionService, error) {
	// Validate configuration
	if err := validateKafkaConfig(config); err != nil {
		return nil, fmt.Errorf("invalid Kafka configuration: %w", err)
	}
	
	// Set defaults
	setKafkaDefaults(config)
	
	service := &KafkaIngestionService{
		config:            config,
		logger:            logger,
		metrics:           NewIngestionMetrics(),
		shutdownCh:        make(chan struct{}),
		lastMetricsReport: time.Now(),
		serializer:        NewJSONEventSerializer(),
		validator:         NewSecurityEventValidator(),
		errorHandler:      NewDefaultErrorHandler(logger),
	}
	
	// Initialize rate limiter if configured
	if config.RateLimit != nil {
		service.rateLimiter = NewRateLimiter(config.RateLimit)
	}
	
	// Initialize backpressure manager if configured
	if config.Backpressure != nil {
		service.backpressure = NewBackpressureManager(config.Backpressure)
	}
	
	return service, nil
}

// Start initializes and starts the Kafka ingestion service
func (k *KafkaIngestionService) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&k.isRunning, 0, 1) {
		return fmt.Errorf("ingestion service is already running")
	}
	
	k.logger.Info("Starting Kafka ingestion service",
		zap.Strings("brokers", k.config.Brokers),
		zap.String("client_id", k.config.ClientID))
	
	// Create Kafka configuration
	kafkaConfig, err := k.createKafkaConfig()
	if err != nil {
		return fmt.Errorf("failed to create Kafka configuration: %w", err)
	}
	
	// Create producer
	producer, err := sarama.NewAsyncProducer(k.config.Brokers, kafkaConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kafka producer: %w", err)
	}
	k.producer = producer
	
	// Create consumer group
	consumer, err := sarama.NewConsumerGroup(k.config.Brokers, k.config.GroupID, kafkaConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kafka consumer group: %w", err)
	}
	k.consumer = consumer
	
	// Start background routines
	k.wg.Add(3)
	go k.handleProducerErrors()
	go k.handleProducerSuccesses()
	go k.reportMetrics()
	
	k.logger.Info("Kafka ingestion service started successfully")
	return nil
}

// Stop gracefully shuts down the ingestion service
func (k *KafkaIngestionService) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&k.isRunning, 1, 0) {
		return fmt.Errorf("ingestion service is not running")
	}
	
	k.logger.Info("Stopping Kafka ingestion service")
	
	// Signal shutdown
	close(k.shutdownCh)
	
	// Close producer
	if k.producer != nil {
		if err := k.producer.Close(); err != nil {
			k.logger.Warn("Error closing Kafka producer", zap.Error(err))
		}
	}
	
	// Close consumer
	if k.consumer != nil {
		if err := k.consumer.Close(); err != nil {
			k.logger.Warn("Error closing Kafka consumer", zap.Error(err))
		}
	}
	
	// Wait for background routines to finish
	done := make(chan struct{})
	go func() {
		k.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		k.logger.Info("Kafka ingestion service stopped successfully")
		return nil
	case <-ctx.Done():
		k.logger.Warn("Kafka ingestion service shutdown timed out")
		return ctx.Err()
	}
}

// IngestEvent ingests a single security event
func (k *KafkaIngestionService) IngestEvent(ctx context.Context, event *SecurityEvent) error {
	if atomic.LoadInt32(&k.isRunning) == 0 {
		return fmt.Errorf("ingestion service is not running")
	}
	
	startTime := time.Now()
	
	// Rate limiting check
	if k.rateLimiter != nil {
		if !k.rateLimiter.Allow(event.TenantID) {
			atomic.AddInt64(&k.errorCount, 1)
			return NewIngestionError("rate_limit_exceeded", "rate limit exceeded for tenant", event.TenantID)
		}
	}
	
	// Backpressure check
	if k.backpressure != nil && k.backpressure.ShouldBackpressure() {
		atomic.AddInt64(&k.errorCount, 1)
		return NewIngestionError("backpressure", "system under backpressure", event.TenantID)
	}
	
	// Validate event
	if err := k.validator.Validate(event); err != nil {
		atomic.AddInt64(&k.errorCount, 1)
		k.errorHandler.HandleError(err, event, map[string]interface{}{
			"stage": "validation",
		})
		return fmt.Errorf("event validation failed: %w", err)
	}
	
	// Serialize event
	data, err := k.serializer.Serialize(event)
	if err != nil {
		atomic.AddInt64(&k.errorCount, 1)
		k.errorHandler.HandleError(err, event, map[string]interface{}{
			"stage": "serialization",
		})
		return fmt.Errorf("event serialization failed: %w", err)
	}
	
	// Determine topic based on event characteristics
	topic := k.selectTopic(event)
	
	// Create Kafka message
	message := &sarama.ProducerMessage{
		Topic:     topic,
		Key:       sarama.StringEncoder(event.TenantID), // Partition by tenant
		Value:     sarama.ByteEncoder(data),
		Timestamp: event.Timestamp,
		Headers: []sarama.RecordHeader{
			{Key: []byte("event_id"), Value: []byte(event.ID)},
			{Key: []byte("event_type"), Value: []byte(event.Type)},
			{Key: []byte("severity"), Value: []byte(event.Severity)},
			{Key: []byte("tenant_id"), Value: []byte(event.TenantID)},
			{Key: []byte("content_type"), Value: []byte(k.serializer.GetContentType())},
		},
	}
	
	// Add correlation headers if present
	if event.CorrelationID != "" {
		message.Headers = append(message.Headers, sarama.RecordHeader{
			Key: []byte("correlation_id"), Value: []byte(event.CorrelationID),
		})
	}
	
	// Send message asynchronously
	select {
	case k.producer.Input() <- message:
		// Update metrics
		atomic.AddInt64(&k.eventCount, 1)
		atomic.AddInt64(&k.bytesProcessed, int64(len(data)))
		
		// Update ingestion latency in event metrics
		if event.Metrics != nil {
			event.Metrics.IngestLatency = time.Since(startTime)
		}
		
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-k.shutdownCh:
		return fmt.Errorf("ingestion service is shutting down")
	default:
		// Producer channel is full, apply backpressure
		if k.backpressure != nil {
			k.backpressure.ApplyBackpressure()
		}
		return NewIngestionError("producer_full", "producer channel is full", event.TenantID)
	}
}

// IngestBatch ingests a batch of security events
func (k *KafkaIngestionService) IngestBatch(ctx context.Context, batch *EventBatch) error {
	if atomic.LoadInt32(&k.isRunning) == 0 {
		return fmt.Errorf("ingestion service is not running")
	}
	
	// Validate batch
	if err := k.validator.ValidateBatch(batch); err != nil {
		k.errorHandler.HandleBatchError(err, batch, map[string]interface{}{
			"stage": "validation",
		})
		return fmt.Errorf("batch validation failed: %w", err)
	}
	
	// Process events in parallel
	type result struct {
		index int
		err   error
	}
	
	results := make(chan result, len(batch.Events))
	semaphore := make(chan struct{}, 10) // Limit concurrency
	
	for i, event := range batch.Events {
		go func(index int, evt *SecurityEvent) {
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			err := k.IngestEvent(ctx, evt)
			results <- result{index: index, err: err}
		}(i, event)
	}
	
	// Collect results
	var errors []error
	for i := 0; i < len(batch.Events); i++ {
		result := <-results
		if result.err != nil {
			errors = append(errors, fmt.Errorf("event %d: %w", result.index, result.err))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("batch ingestion failed with %d errors: %v", len(errors), errors)
	}
	
	return nil
}

// GetMetrics returns current ingestion metrics
func (k *KafkaIngestionService) GetMetrics() *IngestionMetrics {
	k.metrics.mutex.RLock()
	defer k.metrics.mutex.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := *k.metrics
	metrics.TenantEventCounts = make(map[string]int64)
	metrics.TenantRateLimits = make(map[string]int64)
	
	for tenant, count := range k.metrics.TenantEventCounts {
		metrics.TenantEventCounts[tenant] = count
	}
	for tenant, limit := range k.metrics.TenantRateLimits {
		metrics.TenantRateLimits[tenant] = limit
	}
	
	return &metrics
}

// Helper methods

func (k *KafkaIngestionService) createKafkaConfig() (*sarama.Config, error) {
	config := sarama.NewConfig()
	
	// Client settings
	config.ClientID = k.config.ClientID
	config.Version = sarama.V3_5_0_0 // Kafka 3.5+
	
	// Producer settings
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Producer.RequiredAcks = sarama.WaitForAll // Acks = "all"
	config.Producer.Retry.Max = k.config.Retries
	config.Producer.Flush.Frequency = k.config.FlushFrequency
	config.Producer.Flush.Messages = k.config.BatchSize
	config.Producer.MaxMessageBytes = k.config.MaxMessageBytes
	config.Producer.Idempotent = k.config.EnableIdempotent
	
	// Compression
	switch k.config.CompressionType {
	case "gzip":
		config.Producer.Compression = sarama.CompressionGZIP
	case "snappy":
		config.Producer.Compression = sarama.CompressionSnappy
	case "lz4":
		config.Producer.Compression = sarama.CompressionLZ4
	case "zstd":
		config.Producer.Compression = sarama.CompressionZSTD
	default:
		config.Producer.Compression = sarama.CompressionNone
	}
	
	// Consumer settings
	config.Consumer.Return.Errors = true
	config.Consumer.Group.Rebalance.Strategy = sarama.BalanceStrategyRoundRobin
	config.Consumer.Offsets.Initial = sarama.OffsetNewest
	config.Consumer.Fetch.Min = int32(k.config.FetchMinBytes)
	config.Consumer.Fetch.Max = int32(k.config.FetchMaxBytes)
	config.Consumer.MaxWaitTime = k.config.FetchMaxWait
	
	// Security configuration
	if err := k.configureSecurity(config); err != nil {
		return nil, err
	}
	
	return config, nil
}

func (k *KafkaIngestionService) configureSecurity(config *sarama.Config) error {
	switch k.config.SecurityProtocol {
	case "SSL", "SASL_SSL":
		if k.config.TLSConfig != nil {
			tlsConfig := &tls.Config{
				ServerName:         k.config.TLSConfig.ServerName,
				InsecureSkipVerify: k.config.TLSConfig.InsecureSkipVerify,
			}
			
			// Load certificates if specified
			if k.config.TLSConfig.CertFile != "" && k.config.TLSConfig.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(k.config.TLSConfig.CertFile, k.config.TLSConfig.KeyFile)
				if err != nil {
					return fmt.Errorf("failed to load TLS certificates: %w", err)
				}
				tlsConfig.Certificates = []tls.Certificate{cert}
			}
			
			config.Net.TLS.Enable = true
			config.Net.TLS.Config = tlsConfig
		}
	}
	
	if k.config.SecurityProtocol == "SASL_PLAINTEXT" || k.config.SecurityProtocol == "SASL_SSL" {
		config.Net.SASL.Enable = true
		config.Net.SASL.User = k.config.SASLUsername
		config.Net.SASL.Password = k.config.SASLPassword
		
		switch k.config.SASLMechanism {
		case "PLAIN":
			config.Net.SASL.Mechanism = sarama.SASLTypePlaintext
		case "SCRAM-SHA-256":
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		case "SCRAM-SHA-512":
			config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		default:
			return fmt.Errorf("unsupported SASL mechanism: %s", k.config.SASLMechanism)
		}
	}
	
	return nil
}

func (k *KafkaIngestionService) selectTopic(event *SecurityEvent) string {
	// Route events to appropriate topics based on characteristics
	switch event.Severity {
	case SeverityCritical:
		return k.config.Topics.CriticalEvents
	case SeverityHigh:
		return k.config.Topics.HighPriorityEvents
	}
	
	switch event.Type {
	case EventTypeThreatIntelligence:
		return k.config.Topics.ThreatIntelligence
	case EventTypeVulnerability:
		return k.config.Topics.Vulnerabilities
	case EventTypeCompliance:
		return k.config.Topics.Compliance
	case EventTypeAudit:
		return k.config.Topics.AuditEvents
	case EventTypeSystem, EventTypeAgent, EventTypeHeartbeat, EventTypeConfiguration:
		return k.config.Topics.SystemEvents
	default:
		return k.config.Topics.SecurityEvents
	}
}

func (k *KafkaIngestionService) handleProducerErrors() {
	defer k.wg.Done()
	
	for {
		select {
		case err := <-k.producer.Errors():
			if err != nil {
				atomic.AddInt64(&k.errorCount, 1)
				k.logger.Error("Kafka producer error",
					zap.Error(err.Err),
					zap.String("topic", err.Msg.Topic),
					zap.Any("partition", err.Msg.Partition))
				
				// Handle specific error types
				k.handleProducerError(err)
			}
		case <-k.shutdownCh:
			return
		}
	}
}

func (k *KafkaIngestionService) handleProducerSuccesses() {
	defer k.wg.Done()
	
	for {
		select {
		case success := <-k.producer.Successes():
			if success != nil {
				// Update metrics for successful sends
				k.updateSuccessMetrics(success)
			}
		case <-k.shutdownCh:
			return
		}
	}
}

func (k *KafkaIngestionService) handleProducerError(err *sarama.ProducerError) {
	// Extract event information from headers
	var eventID, tenantID string
	for _, header := range err.Msg.Headers {
		switch string(header.Key) {
		case "event_id":
			eventID = string(header.Value)
		case "tenant_id":
			tenantID = string(header.Value)
		}
	}
	
	// Determine if error is retryable
	retryable := k.isRetryableError(err.Err)
	
	if retryable {
		// Send to retry queue
		k.sendToRetryQueue(err.Msg, err.Err)
	} else {
		// Send to dead letter queue
		k.sendToDeadLetterQueue(err.Msg, err.Err)
	}
	
	k.logger.Error("Producer error handled",
		zap.String("event_id", eventID),
		zap.String("tenant_id", tenantID),
		zap.Bool("retryable", retryable),
		zap.Error(err.Err))
}

func (k *KafkaIngestionService) updateSuccessMetrics(success *sarama.ProducerMessage) {
	k.metrics.mutex.Lock()
	defer k.metrics.mutex.Unlock()
	
	// Extract tenant ID from headers
	var tenantID string
	for _, header := range success.Headers {
		if string(header.Key) == "tenant_id" {
			tenantID = string(header.Value)
			break
		}
	}
	
	// Update tenant-specific metrics
	if tenantID != "" {
		if k.metrics.TenantEventCounts == nil {
			k.metrics.TenantEventCounts = make(map[string]int64)
		}
		k.metrics.TenantEventCounts[tenantID]++
	}
}

func (k *KafkaIngestionService) reportMetrics() {
	defer k.wg.Done()
	
	ticker := time.NewTicker(k.config.MetricsInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			k.calculateAndReportMetrics()
		case <-k.shutdownCh:
			return
		}
	}
}

func (k *KafkaIngestionService) calculateAndReportMetrics() {
	now := time.Now()
	duration := now.Sub(k.lastMetricsReport)
	
	eventCount := atomic.LoadInt64(&k.eventCount)
	errorCount := atomic.LoadInt64(&k.errorCount)
	bytesProcessed := atomic.LoadInt64(&k.bytesProcessed)
	
	k.metrics.mutex.Lock()
	defer k.metrics.mutex.Unlock()
	
	// Calculate rates
	k.metrics.EventsPerSecond = float64(eventCount) / duration.Seconds()
	k.metrics.BytesPerSecond = float64(bytesProcessed) / duration.Seconds()
	k.metrics.ErrorRate = float64(errorCount) / float64(eventCount+errorCount)
	
	// Reset counters
	atomic.StoreInt64(&k.eventCount, 0)
	atomic.StoreInt64(&k.errorCount, 0)
	atomic.StoreInt64(&k.bytesProcessed, 0)
	k.lastMetricsReport = now
	
	k.logger.Info("Ingestion metrics",
		zap.Float64("events_per_second", k.metrics.EventsPerSecond),
		zap.Float64("bytes_per_second", k.metrics.BytesPerSecond),
		zap.Float64("error_rate", k.metrics.ErrorRate))
}

func (k *KafkaIngestionService) isRetryableError(err error) bool {
	// Implement retry logic based on error type
	// This is a simplified version - production would have more sophisticated logic
	return err != nil // Placeholder
}

func (k *KafkaIngestionService) sendToRetryQueue(msg *sarama.ProducerMessage, err error) {
	// Implementation for retry queue
	k.logger.Debug("Sending message to retry queue", zap.Error(err))
}

func (k *KafkaIngestionService) sendToDeadLetterQueue(msg *sarama.ProducerMessage, err error) {
	// Implementation for dead letter queue
	k.logger.Debug("Sending message to dead letter queue", zap.Error(err))
}

// Utility functions

func validateKafkaConfig(config *KafkaConfig) error {
	if len(config.Brokers) == 0 {
		return fmt.Errorf("brokers list cannot be empty")
	}
	if config.ClientID == "" {
		return fmt.Errorf("client ID is required")
	}
	if config.GroupID == "" {
		return fmt.Errorf("group ID is required")
	}
	if config.Topics == nil {
		return fmt.Errorf("topic configuration is required")
	}
	return nil
}

func setKafkaDefaults(config *KafkaConfig) {
	if config.BatchSize == 0 {
		config.BatchSize = 16384
	}
	if config.LingerMs == 0 {
		config.LingerMs = 10
	}
	if config.CompressionType == "" {
		config.CompressionType = "snappy"
	}
	if config.Acks == "" {
		config.Acks = "all"
	}
	if config.Retries == 0 {
		config.Retries = 3
	}
	if config.MaxInFlightRequests == 0 {
		config.MaxInFlightRequests = 5
	}
	if config.ChannelBufferSize == 0 {
		config.ChannelBufferSize = 256
	}
	if config.FlushFrequency == 0 {
		config.FlushFrequency = time.Second
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = 1024 * 1024 // 1MB
	}
	if config.MetricsInterval == 0 {
		config.MetricsInterval = 30 * time.Second
	}
	
	// Topic defaults
	if config.Topics.Partitions == 0 {
		config.Topics.Partitions = 12
	}
	if config.Topics.ReplicationFactor == 0 {
		config.Topics.ReplicationFactor = 3
	}
	if config.Topics.RetentionHours == 0 {
		config.Topics.RetentionHours = 168 // 7 days
	}
}

// Error types

type IngestionError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	TenantID string `json:"tenant_id"`
}

func (e *IngestionError) Error() string {
	return fmt.Sprintf("ingestion error [%s]: %s (tenant: %s)", e.Code, e.Message, e.TenantID)
}

func NewIngestionError(code, message, tenantID string) *IngestionError {
	return &IngestionError{
		Code:     code,
		Message:  message,
		TenantID: tenantID,
	}
}

// Initialize metrics
func NewIngestionMetrics() *IngestionMetrics {
	return &IngestionMetrics{
		TenantEventCounts: make(map[string]int64),
		TenantRateLimits:  make(map[string]int64),
		lastUpdate:       time.Now(),
	}
}

// Placeholder implementations for interfaces
func NewJSONEventSerializer() EventSerializer {
	return &JSONEventSerializer{}
}

func NewSecurityEventValidator() EventValidator {
	return &SecurityEventValidator{}
}

func NewDefaultErrorHandler(logger *zap.Logger) ErrorHandler {
	return &DefaultErrorHandler{logger: logger}
}

func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	return &RateLimiter{config: config}
}

func NewBackpressureManager(config *BackpressureConfig) *BackpressureManager {
	return &BackpressureManager{config: config}
}

// Placeholder implementations - would be fully implemented in production

type JSONEventSerializer struct{}

func (j *JSONEventSerializer) Serialize(event *SecurityEvent) ([]byte, error) {
	return json.Marshal(event)
}

func (j *JSONEventSerializer) Deserialize(data []byte) (*SecurityEvent, error) {
	var event SecurityEvent
	err := json.Unmarshal(data, &event)
	return &event, err
}

func (j *JSONEventSerializer) GetContentType() string {
	return "application/json"
}

type SecurityEventValidator struct{}

func (s *SecurityEventValidator) Validate(event *SecurityEvent) error {
	return event.Validate()
}

func (s *SecurityEventValidator) ValidateBatch(batch *EventBatch) error {
	for _, event := range batch.Events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type DefaultErrorHandler struct {
	logger *zap.Logger
}

func (d *DefaultErrorHandler) HandleError(err error, event *SecurityEvent, context map[string]interface{}) {
	d.logger.Error("Event ingestion error", zap.Error(err), zap.Any("context", context))
}

func (d *DefaultErrorHandler) HandleBatchError(err error, batch *EventBatch, context map[string]interface{}) {
	d.logger.Error("Batch ingestion error", zap.Error(err), zap.Any("context", context))
}

func (d *DefaultErrorHandler) GetErrorStats() map[string]int64 {
	return make(map[string]int64)
}

func (r *RateLimiter) Allow(tenantID string) bool {
	// Simplified implementation
	return true
}

func (b *BackpressureManager) ShouldBackpressure() bool {
	// Simplified implementation
	return false
}

func (b *BackpressureManager) ApplyBackpressure() {
	// Simplified implementation
}