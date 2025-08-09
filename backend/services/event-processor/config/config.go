package config

import (
	"time"

	"github.com/isectech/platform/shared/common"
)

// Config represents the configuration for the event processor service
type Config struct {
	// Service configuration
	Service ServiceConfig `mapstructure:"service"`
	
	// Server configuration
	Server ServerConfig `mapstructure:"server"`
	
	// Database configurations
	Database DatabaseConfig `mapstructure:"database"`
	
	// Cache configuration
	Cache CacheConfig `mapstructure:"cache"`
	
	// Message queue configuration
	MessageQueue MessageQueueConfig `mapstructure:"messagequeue"`
	
	// Event processing configuration
	EventProcessing EventProcessingConfig `mapstructure:"event_processing"`
	
	// Risk assessment configuration
	RiskAssessment RiskAssessmentConfig `mapstructure:"risk_assessment"`
	
	// Enrichment configuration
	Enrichment EnrichmentConfig `mapstructure:"enrichment"`
	
	// Correlation configuration
	Correlation CorrelationConfig `mapstructure:"correlation"`
	
	// Logging configuration
	Logging common.LoggingConfig `mapstructure:"logging"`
	
	// Metrics configuration
	Metrics common.MetricsConfig `mapstructure:"metrics"`
	
	// Tracing configuration
	Tracing common.TracingConfig `mapstructure:"tracing"`
	
	// Security configuration
	Security common.SecurityConfig `mapstructure:"security"`
	
	// Service discovery configuration
	ServiceDiscovery common.ServiceDiscoveryConfig `mapstructure:"servicediscovery"`
}

// ServiceConfig contains service-specific configuration
type ServiceConfig struct {
	Name         string `mapstructure:"name"`
	Version      string `mapstructure:"version"`
	Environment  string `mapstructure:"environment"`
	BuildTime    string `mapstructure:"build_time"`
	GitCommit    string `mapstructure:"git_commit"`
	InstanceID   string `mapstructure:"instance_id"`
	WorkerCount  int    `mapstructure:"worker_count"`
	MaxConcurrency int  `mapstructure:"max_concurrency"`
}

// ServerConfig contains HTTP/gRPC server configuration
type ServerConfig struct {
	HTTP HTTPConfig `mapstructure:"http"`
	GRPC GRPCConfig `mapstructure:"grpc"`
}

// HTTPConfig contains HTTP server configuration
type HTTPConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	TLS          common.TLSConfig `mapstructure:"tls"`
}

// GRPCConfig contains gRPC server configuration
type GRPCConfig struct {
	Host               string        `mapstructure:"host"`
	Port               int           `mapstructure:"port"`
	MaxRecvMsgSize     int           `mapstructure:"max_recv_msg_size"`
	MaxSendMsgSize     int           `mapstructure:"max_send_msg_size"`
	ConnectionTimeout  time.Duration `mapstructure:"connection_timeout"`
	TLS                common.TLSConfig `mapstructure:"tls"`
}

// DatabaseConfig contains database configuration
type DatabaseConfig struct {
	MongoDB    common.MongoDBConfig    `mapstructure:"mongodb"`
	PostgreSQL common.PostgreSQLConfig `mapstructure:"postgresql"`
}

// CacheConfig contains cache configuration
type CacheConfig struct {
	Redis common.RedisConfig `mapstructure:"redis"`
}

// MessageQueueConfig contains message queue configuration
type MessageQueueConfig struct {
	Kafka KafkaConfig `mapstructure:"kafka"`
}

// KafkaConfig contains Kafka-specific configuration for event processor
type KafkaConfig struct {
	common.KafkaConfig `mapstructure:",squash"`
	
	// Consumer configuration
	ConsumerGroup         string        `mapstructure:"consumer_group"`
	AutoCommit            bool          `mapstructure:"auto_commit"`
	CommitInterval        time.Duration `mapstructure:"commit_interval"`
	FetchMinBytes         int           `mapstructure:"fetch_min_bytes"`
	FetchMaxBytes         int           `mapstructure:"fetch_max_bytes"`
	FetchMaxWait          time.Duration `mapstructure:"fetch_max_wait"`
	MaxProcessingTime     time.Duration `mapstructure:"max_processing_time"`
	
	// Producer configuration
	BatchSize         int           `mapstructure:"batch_size"`
	BatchTimeout      time.Duration `mapstructure:"batch_timeout"`
	Compression       string        `mapstructure:"compression"`
	Idempotent        bool          `mapstructure:"idempotent"`
	
	// Topics
	InputTopics  []string `mapstructure:"input_topics"`
	OutputTopics []string `mapstructure:"output_topics"`
	ErrorTopic   string   `mapstructure:"error_topic"`
	DeadLetterTopic string `mapstructure:"dead_letter_topic"`
}

// EventProcessingConfig contains event processing configuration
type EventProcessingConfig struct {
	// Processing limits
	MaxBatchSize           int           `mapstructure:"max_batch_size"`
	ProcessingTimeout      time.Duration `mapstructure:"processing_timeout"`
	MaxRetryAttempts       int           `mapstructure:"max_retry_attempts"`
	RetryBackoffMultiplier float64       `mapstructure:"retry_backoff_multiplier"`
	RetryMaxBackoff        time.Duration `mapstructure:"retry_max_backoff"`
	
	// Feature flags
	EnableValidation       bool `mapstructure:"enable_validation"`
	EnableNormalization    bool `mapstructure:"enable_normalization"`
	EnableEnrichment       bool `mapstructure:"enable_enrichment"`
	EnableRiskAssessment   bool `mapstructure:"enable_risk_assessment"`
	EnableCorrelation      bool `mapstructure:"enable_correlation"`
	EnablePatternDetection bool `mapstructure:"enable_pattern_detection"`
	EnableAnomalyDetection bool `mapstructure:"enable_anomaly_detection"`
	
	// Processing rules
	SkipInvalidEvents      bool     `mapstructure:"skip_invalid_events"`
	RequiredFields         []string `mapstructure:"required_fields"`
	AllowedEventTypes      []string `mapstructure:"allowed_event_types"`
	AllowedSources         []string `mapstructure:"allowed_sources"`
	
	// Performance settings
	ParallelProcessing     bool          `mapstructure:"parallel_processing"`
	WorkerPoolSize         int           `mapstructure:"worker_pool_size"`
	QueueSize              int           `mapstructure:"queue_size"`
	HealthCheckInterval    time.Duration `mapstructure:"health_check_interval"`
	MetricsReportInterval  time.Duration `mapstructure:"metrics_report_interval"`
	
	// Storage settings
	EnableEventStorage     bool          `mapstructure:"enable_event_storage"`
	StorageCompression     bool          `mapstructure:"storage_compression"`
	StorageEncryption      bool          `mapstructure:"storage_encryption"`
	RetentionPeriod        time.Duration `mapstructure:"retention_period"`
	ArchiveOldEvents       bool          `mapstructure:"archive_old_events"`
	ArchiveAfter           time.Duration `mapstructure:"archive_after"`
}

// RiskAssessmentConfig contains risk assessment configuration
type RiskAssessmentConfig struct {
	// Model configuration
	ModelType              string                 `mapstructure:"model_type"`
	ModelVersion           string                 `mapstructure:"model_version"`
	ModelUpdateInterval    time.Duration          `mapstructure:"model_update_interval"`
	UseMLModel             bool                   `mapstructure:"use_ml_model"`
	FallbackToRuleBased    bool                   `mapstructure:"fallback_to_rule_based"`
	
	// Scoring configuration
	DefaultRiskScore       float64                `mapstructure:"default_risk_score"`
	MinConfidenceThreshold float64                `mapstructure:"min_confidence_threshold"`
	RiskThresholds         RiskThresholds         `mapstructure:"risk_thresholds"`
	
	// Rule-based assessment
	RiskFactors            map[string]RiskFactor  `mapstructure:"risk_factors"`
	SeverityWeights        map[string]float64     `mapstructure:"severity_weights"`
	SourceWeights          map[string]float64     `mapstructure:"source_weights"`
	TypeWeights            map[string]float64     `mapstructure:"type_weights"`
	
	// Performance settings
	CacheResults           bool                   `mapstructure:"cache_results"`
	CacheTTL               time.Duration          `mapstructure:"cache_ttl"`
	BatchAssessment        bool                   `mapstructure:"batch_assessment"`
	AssessmentTimeout      time.Duration          `mapstructure:"assessment_timeout"`
}

// RiskThresholds defines risk score thresholds
type RiskThresholds struct {
	Low      float64 `mapstructure:"low"`
	Medium   float64 `mapstructure:"medium"`
	High     float64 `mapstructure:"high"`
	Critical float64 `mapstructure:"critical"`
}

// RiskFactor defines a risk factor configuration
type RiskFactor struct {
	Name        string  `mapstructure:"name"`
	Weight      float64 `mapstructure:"weight"`
	Enabled     bool    `mapstructure:"enabled"`
	Description string  `mapstructure:"description"`
}

// EnrichmentConfig contains enrichment configuration
type EnrichmentConfig struct {
	// Feature flags
	EnableAssetEnrichment           bool `mapstructure:"enable_asset_enrichment"`
	EnableUserEnrichment            bool `mapstructure:"enable_user_enrichment"`
	EnableGeoLocationEnrichment     bool `mapstructure:"enable_geo_location_enrichment"`
	EnableThreatIntelligenceEnrichment bool `mapstructure:"enable_threat_intelligence_enrichment"`
	EnableNetworkEnrichment         bool `mapstructure:"enable_network_enrichment"`
	
	// External services
	ThreatIntelligenceServices []ThreatIntelService `mapstructure:"threat_intelligence_services"`
	GeoLocationService         GeoLocationService   `mapstructure:"geo_location_service"`
	
	// Performance settings
	EnrichmentTimeout       time.Duration `mapstructure:"enrichment_timeout"`
	MaxConcurrentRequests   int           `mapstructure:"max_concurrent_requests"`
	CacheEnrichmentResults  bool          `mapstructure:"cache_enrichment_results"`
	CacheTTL                time.Duration `mapstructure:"cache_ttl"`
	
	// Retry settings
	MaxRetryAttempts        int           `mapstructure:"max_retry_attempts"`
	RetryBackoff            time.Duration `mapstructure:"retry_backoff"`
	CircuitBreakerEnabled   bool          `mapstructure:"circuit_breaker_enabled"`
	CircuitBreakerThreshold int           `mapstructure:"circuit_breaker_threshold"`
}

// ThreatIntelService defines a threat intelligence service configuration
type ThreatIntelService struct {
	Name     string `mapstructure:"name"`
	Type     string `mapstructure:"type"`
	Endpoint string `mapstructure:"endpoint"`
	APIKey   string `mapstructure:"api_key"`
	Enabled  bool   `mapstructure:"enabled"`
	Priority int    `mapstructure:"priority"`
}

// GeoLocationService defines a geo location service configuration
type GeoLocationService struct {
	Type     string `mapstructure:"type"`
	Endpoint string `mapstructure:"endpoint"`
	APIKey   string `mapstructure:"api_key"`
	Enabled  bool   `mapstructure:"enabled"`
}

// CorrelationConfig contains correlation configuration
type CorrelationConfig struct {
	// Feature flags
	EnableTimeBasedCorrelation   bool `mapstructure:"enable_time_based_correlation"`
	EnableAssetBasedCorrelation  bool `mapstructure:"enable_asset_based_correlation"`
	EnableUserBasedCorrelation   bool `mapstructure:"enable_user_based_correlation"`
	EnableIPBasedCorrelation     bool `mapstructure:"enable_ip_based_correlation"`
	EnablePatternBasedCorrelation bool `mapstructure:"enable_pattern_based_correlation"`
	
	// Time-based correlation
	TimeWindow              time.Duration `mapstructure:"time_window"`
	MaxEventsPerWindow      int           `mapstructure:"max_events_per_window"`
	MinEventsForCorrelation int           `mapstructure:"min_events_for_correlation"`
	
	// Similarity thresholds
	SimilarityThresholds    SimilarityThresholds `mapstructure:"similarity_thresholds"`
	
	// Performance settings
	CorrelationTimeout      time.Duration `mapstructure:"correlation_timeout"`
	MaxCorrelationDepth     int           `mapstructure:"max_correlation_depth"`
	CacheCorrelations       bool          `mapstructure:"cache_correlations"`
	CacheTTL                time.Duration `mapstructure:"cache_ttl"`
	
	// Storage settings
	StoreCorrelations       bool          `mapstructure:"store_correlations"`
	CorrelationRetention    time.Duration `mapstructure:"correlation_retention"`
}

// SimilarityThresholds defines similarity thresholds for correlation
type SimilarityThresholds struct {
	Asset    float64 `mapstructure:"asset"`
	User     float64 `mapstructure:"user"`
	IP       float64 `mapstructure:"ip"`
	Content  float64 `mapstructure:"content"`
	Pattern  float64 `mapstructure:"pattern"`
}

// LoadConfig loads the configuration for the event processor service
func LoadConfig(configPath string) (*Config, error) {
	config, err := common.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	
	// Convert to event processor config
	eventProcessorConfig := &Config{}
	
	// Copy common config fields
	eventProcessorConfig.Service = ServiceConfig{
		Name:        config.Service.Name,
		Version:     config.Service.Version,
		Environment: config.Service.Environment,
		BuildTime:   config.Service.BuildTime,
		GitCommit:   config.Service.GitCommit,
	}
	
	eventProcessorConfig.Database.MongoDB = config.Database.MongoDB
	eventProcessorConfig.Database.PostgreSQL = config.Database.PostgreSQL
	eventProcessorConfig.Cache.Redis = config.Cache.Redis
	eventProcessorConfig.Logging = config.Logging
	eventProcessorConfig.Metrics = config.Metrics
	eventProcessorConfig.Tracing = config.Tracing
	eventProcessorConfig.Security = config.Security
	eventProcessorConfig.ServiceDiscovery = config.ServiceDiscovery
	
	// Set event processor specific defaults
	setEventProcessorDefaults(eventProcessorConfig)
	
	return eventProcessorConfig, nil
}

// setEventProcessorDefaults sets default values for event processor configuration
func setEventProcessorDefaults(config *Config) {
	// Service defaults
	if config.Service.Name == "" {
		config.Service.Name = "event-processor"
	}
	if config.Service.WorkerCount == 0 {
		config.Service.WorkerCount = 10
	}
	if config.Service.MaxConcurrency == 0 {
		config.Service.MaxConcurrency = 1000
	}
	
	// Server defaults
	if config.Server.HTTP.Host == "" {
		config.Server.HTTP.Host = "0.0.0.0"
	}
	if config.Server.HTTP.Port == 0 {
		config.Server.HTTP.Port = 8001
	}
	if config.Server.GRPC.Host == "" {
		config.Server.GRPC.Host = "0.0.0.0"
	}
	if config.Server.GRPC.Port == 0 {
		config.Server.GRPC.Port = 9001
	}
	
	// Event processing defaults
	if config.EventProcessing.MaxBatchSize == 0 {
		config.EventProcessing.MaxBatchSize = 100
	}
	if config.EventProcessing.ProcessingTimeout == 0 {
		config.EventProcessing.ProcessingTimeout = 30 * time.Second
	}
	if config.EventProcessing.MaxRetryAttempts == 0 {
		config.EventProcessing.MaxRetryAttempts = 3
	}
	if config.EventProcessing.WorkerPoolSize == 0 {
		config.EventProcessing.WorkerPoolSize = 50
	}
	if config.EventProcessing.QueueSize == 0 {
		config.EventProcessing.QueueSize = 10000
	}
	
	// Risk assessment defaults
	if config.RiskAssessment.DefaultRiskScore == 0 {
		config.RiskAssessment.DefaultRiskScore = 5.0
	}
	if config.RiskAssessment.MinConfidenceThreshold == 0 {
		config.RiskAssessment.MinConfidenceThreshold = 0.7
	}
	if config.RiskAssessment.RiskThresholds.Low == 0 {
		config.RiskAssessment.RiskThresholds = RiskThresholds{
			Low:      3.0,
			Medium:   5.0,
			High:     7.0,
			Critical: 9.0,
		}
	}
	
	// Enrichment defaults
	if config.Enrichment.EnrichmentTimeout == 0 {
		config.Enrichment.EnrichmentTimeout = 10 * time.Second
	}
	if config.Enrichment.MaxConcurrentRequests == 0 {
		config.Enrichment.MaxConcurrentRequests = 10
	}
	
	// Correlation defaults
	if config.Correlation.TimeWindow == 0 {
		config.Correlation.TimeWindow = 5 * time.Minute
	}
	if config.Correlation.MaxEventsPerWindow == 0 {
		config.Correlation.MaxEventsPerWindow = 1000
	}
	if config.Correlation.MinEventsForCorrelation == 0 {
		config.Correlation.MinEventsForCorrelation = 2
	}
	
	// Kafka defaults
	if config.MessageQueue.Kafka.ConsumerGroup == "" {
		config.MessageQueue.Kafka.ConsumerGroup = "event-processor-group"
	}
	if len(config.MessageQueue.Kafka.InputTopics) == 0 {
		config.MessageQueue.Kafka.InputTopics = []string{"security-events", "raw-events"}
	}
	if len(config.MessageQueue.Kafka.OutputTopics) == 0 {
		config.MessageQueue.Kafka.OutputTopics = []string{"processed-events", "enriched-events"}
	}
	if config.MessageQueue.Kafka.ErrorTopic == "" {
		config.MessageQueue.Kafka.ErrorTopic = "event-processing-errors"
	}
	if config.MessageQueue.Kafka.DeadLetterTopic == "" {
		config.MessageQueue.Kafka.DeadLetterTopic = "event-processing-dead-letter"
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	
	if c.Server.HTTP.Port <= 0 || c.Server.HTTP.Port > 65535 {
		return fmt.Errorf("invalid HTTP port: %d", c.Server.HTTP.Port)
	}
	
	if c.Server.GRPC.Port <= 0 || c.Server.GRPC.Port > 65535 {
		return fmt.Errorf("invalid gRPC port: %d", c.Server.GRPC.Port)
	}
	
	if c.EventProcessing.MaxBatchSize <= 0 {
		return fmt.Errorf("max batch size must be positive")
	}
	
	if c.EventProcessing.ProcessingTimeout <= 0 {
		return fmt.Errorf("processing timeout must be positive")
	}
	
	if c.EventProcessing.WorkerPoolSize <= 0 {
		return fmt.Errorf("worker pool size must be positive")
	}
	
	if len(c.MessageQueue.Kafka.InputTopics) == 0 {
		return fmt.Errorf("at least one input topic is required")
	}
	
	return nil
}