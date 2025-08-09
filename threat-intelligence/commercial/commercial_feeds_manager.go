package commercial

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CommercialFeedsManager orchestrates all commercial threat intelligence feed integrations
type CommercialFeedsManager struct {
	logger     *zap.Logger
	config     *CommercialFeedsConfig
	
	// Feed providers
	recordedFuture    *RecordedFutureConnector
	digitalShadows    *DigitalShadowsConnector
	crowdStrike       *CrowdStrikeConnector
	fireeye           *FireEyeConnector
	
	// Feed management
	activeFeedSessions map[string]*FeedSession
	feedMutex         sync.RWMutex
	
	// Data processing
	stixProcessor     *STIXProcessor
	dataValidator     *CommercialDataValidator
	
	// Operational state
	ctx               context.Context
	cancel            context.CancelFunc
	healthChecker     *FeedHealthChecker
	metricsCollector  *CommercialFeedsMetrics
}

// CommercialFeedsConfig defines configuration for commercial threat intelligence feeds
type CommercialFeedsConfig struct {
	// Provider configurations
	RecordedFuture    *RecordedFutureConfig    `json:"recorded_future"`
	DigitalShadows    *DigitalShadowsConfig    `json:"digital_shadows"`
	CrowdStrike       *CrowdStrikeConfig       `json:"crowdstrike"`
	FireEye           *FireEyeConfig           `json:"fireeye"`
	
	// Global settings
	MaxConcurrentFeeds    int           `json:"max_concurrent_feeds"`
	FeedUpdateInterval    time.Duration `json:"feed_update_interval"`
	RetryAttempts         int           `json:"retry_attempts"`
	RetryBackoff          time.Duration `json:"retry_backoff"`
	
	// Data validation
	EnableDataValidation  bool          `json:"enable_data_validation"`
	MaxIndicatorAge       time.Duration `json:"max_indicator_age"`
	RequiredConfidence    float64       `json:"required_confidence"`
	
	// Security settings
	TLSConfig            *TLSConfig     `json:"tls_config"`
	APIRateLimit         int            `json:"api_rate_limit"`
	ConnectionTimeout    time.Duration  `json:"connection_timeout"`
	
	// Storage and processing
	EnableLocalCache     bool           `json:"enable_local_cache"`
	CacheRetentionPeriod time.Duration  `json:"cache_retention_period"`
	BatchSize            int            `json:"batch_size"`
	
	// Compliance and licensing
	LicenseValidation    bool           `json:"license_validation"`
	DataRetentionPolicy  string         `json:"data_retention_policy"`
	ExportRestrictions   []string       `json:"export_restrictions"`
}

// Provider-specific configurations
type RecordedFutureConfig struct {
	Enabled         bool              `json:"enabled"`
	APIToken        string            `json:"api_token"`
	BaseURL         string            `json:"base_url"`
	FeedTypes       []string          `json:"feed_types"`
	UpdateInterval  time.Duration     `json:"update_interval"`
	CustomQueries   map[string]string `json:"custom_queries"`
	RiskThreshold   int               `json:"risk_threshold"`
}

type DigitalShadowsConfig struct {
	Enabled         bool              `json:"enabled"`
	APIKey          string            `json:"api_key"`
	APISecret       string            `json:"api_secret"`
	BaseURL         string            `json:"base_url"`
	IncidentTypes   []string          `json:"incident_types"`
	UpdateInterval  time.Duration     `json:"update_interval"`
	SeverityFilter  []string          `json:"severity_filter"`
}

type CrowdStrikeConfig struct {
	Enabled         bool              `json:"enabled"`
	ClientID        string            `json:"client_id"`
	ClientSecret    string            `json:"client_secret"`
	BaseURL         string            `json:"base_url"`
	FeedCategories  []string          `json:"feed_categories"`
	UpdateInterval  time.Duration     `json:"update_interval"`
	ConfidenceLevel int               `json:"confidence_level"`
}

type FireEyeConfig struct {
	Enabled         bool              `json:"enabled"`
	APIKey          string            `json:"api_key"`
	BaseURL         string            `json:"base_url"`
	FeedCollections []string          `json:"feed_collections"`
	UpdateInterval  time.Duration     `json:"update_interval"`
	ThreatTypes     []string          `json:"threat_types"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	MinVersion         uint16 `json:"min_version"`
	CACertPath         string `json:"ca_cert_path"`
	ClientCertPath     string `json:"client_cert_path"`
	ClientKeyPath      string `json:"client_key_path"`
}

// FeedSession represents an active commercial feed ingestion session
type FeedSession struct {
	ID               string                    `json:"id"`
	Provider         string                    `json:"provider"`
	StartTime        time.Time                 `json:"start_time"`
	LastUpdate       time.Time                 `json:"last_update"`
	Status           FeedSessionStatus         `json:"status"`
	
	// Statistics
	IndicatorsProcessed int64                  `json:"indicators_processed"`
	IndicatorsValid     int64                  `json:"indicators_valid"`
	IndicatorsRejected  int64                  `json:"indicators_rejected"`
	DataVolume          int64                  `json:"data_volume"`
	
	// Configuration
	Config              *FeedSessionConfig     `json:"config"`
	
	// State management
	Context             context.Context        `json:"-"`
	CancelFunc          context.CancelFunc     `json:"-"`
	
	// Error tracking
	Errors              []FeedError            `json:"errors"`
	LastError           *FeedError             `json:"last_error"`
}

type FeedSessionStatus string

const (
	FeedSessionStatusInitializing FeedSessionStatus = "initializing"
	FeedSessionStatusActive       FeedSessionStatus = "active"
	FeedSessionStatusPaused       FeedSessionStatus = "paused"
	FeedSessionStatusError        FeedSessionStatus = "error"
	FeedSessionStatusCompleted    FeedSessionStatus = "completed"
)

type FeedSessionConfig struct {
	Provider           string            `json:"provider"`
	FeedType          string            `json:"feed_type"`
	UpdateFrequency   time.Duration     `json:"update_frequency"`
	DataFilters       map[string]string `json:"data_filters"`
	QualityThresholds *QualityThresholds `json:"quality_thresholds"`
}

type QualityThresholds struct {
	MinConfidence     float64 `json:"min_confidence"`
	MaxAge            time.Duration `json:"max_age"`
	RequiredFields    []string `json:"required_fields"`
	ValidationRules   []string `json:"validation_rules"`
}

type FeedError struct {
	Timestamp   time.Time `json:"timestamp"`
	ErrorType   string    `json:"error_type"`
	Message     string    `json:"message"`
	Context     string    `json:"context"`
	Severity    string    `json:"severity"`
	Recoverable bool      `json:"recoverable"`
}

// CommercialDataValidator validates commercial threat intelligence data
type CommercialDataValidator struct {
	logger         *zap.Logger
	config         *CommercialFeedsConfig
	
	// Validation rules
	stixValidator    *STIXValidator
	licenseChecker   *LicenseChecker
	qualityChecker   *DataQualityChecker
}

// FeedHealthChecker monitors health of commercial feeds
type FeedHealthChecker struct {
	logger         *zap.Logger
	config         *CommercialFeedsConfig
	
	// Health tracking
	feedHealth     map[string]*FeedHealthStatus
	healthMutex    sync.RWMutex
	
	// Monitoring
	healthTicker   *time.Ticker
	alertManager   *AlertManager
}

type FeedHealthStatus struct {
	Provider        string    `json:"provider"`
	IsHealthy       bool      `json:"is_healthy"`
	LastCheck       time.Time `json:"last_check"`
	LastSuccessful  time.Time `json:"last_successful"`
	ConsecutiveFailures int   `json:"consecutive_failures"`
	ResponseTime    time.Duration `json:"response_time"`
	ErrorRate       float64   `json:"error_rate"`
	DataFreshness   time.Duration `json:"data_freshness"`
}

// CommercialFeedsMetrics collects metrics for commercial feeds
type CommercialFeedsMetrics struct {
	logger         *zap.Logger
	
	// Metrics tracking
	FeedLatency         map[string]time.Duration
	IndicatorThroughput map[string]int64
	ErrorRates          map[string]float64
	DataQualityScores   map[string]float64
	
	// Prometheus integration
	PrometheusEnabled   bool
	MetricsRegistry     interface{}
}

// NewCommercialFeedsManager creates a new commercial feeds manager
func NewCommercialFeedsManager(logger *zap.Logger, config *CommercialFeedsConfig) (*CommercialFeedsManager, error) {
	if config == nil {
		return nil, fmt.Errorf("commercial feeds configuration is required")
	}
	
	// Set defaults
	if err := setCommercialFeedsDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set commercial feeds defaults: %w", err)
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	cfm := &CommercialFeedsManager{
		logger:             logger.With(zap.String("component", "commercial-feeds-manager")),
		config:             config,
		activeFeedSessions: make(map[string]*FeedSession),
		ctx:                ctx,
		cancel:             cancel,
	}
	
	// Initialize components
	if err := cfm.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize commercial feeds components: %w", err)
	}
	
	// Initialize feed connectors
	if err := cfm.initializeFeedConnectors(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize feed connectors: %w", err)
	}
	
	logger.Info("Commercial feeds manager initialized",
		zap.Bool("recorded_future_enabled", config.RecordedFuture != nil && config.RecordedFuture.Enabled),
		zap.Bool("digital_shadows_enabled", config.DigitalShadows != nil && config.DigitalShadows.Enabled),
		zap.Bool("crowdstrike_enabled", config.CrowdStrike != nil && config.CrowdStrike.Enabled),
		zap.Bool("fireeye_enabled", config.FireEye != nil && config.FireEye.Enabled),
	)
	
	return cfm, nil
}

func setCommercialFeedsDefaults(config *CommercialFeedsConfig) error {
	if config.MaxConcurrentFeeds == 0 {
		config.MaxConcurrentFeeds = 5
	}
	if config.FeedUpdateInterval == 0 {
		config.FeedUpdateInterval = 15 * time.Minute
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = 30 * time.Second
	}
	if config.RequiredConfidence == 0 {
		config.RequiredConfidence = 0.7 // 70% confidence threshold
	}
	if config.MaxIndicatorAge == 0 {
		config.MaxIndicatorAge = 30 * 24 * time.Hour // 30 days
	}
	if config.APIRateLimit == 0 {
		config.APIRateLimit = 100 // requests per minute
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 30 * time.Second
	}
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.CacheRetentionPeriod == 0 {
		config.CacheRetentionPeriod = 24 * time.Hour
	}
	
	return nil
}

func (cfm *CommercialFeedsManager) initializeComponents() error {
	var err error
	
	// Initialize STIX processor
	cfm.stixProcessor, err = NewSTIXProcessor(cfm.logger, cfm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize STIX processor: %w", err)
	}
	
	// Initialize data validator
	cfm.dataValidator, err = NewCommercialDataValidator(cfm.logger, cfm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize data validator: %w", err)
	}
	
	// Initialize health checker
	cfm.healthChecker, err = NewFeedHealthChecker(cfm.logger, cfm.config)
	if err != nil {
		return fmt.Errorf("failed to initialize health checker: %w", err)
	}
	
	// Initialize metrics collector
	cfm.metricsCollector, err = NewCommercialFeedsMetrics(cfm.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}
	
	return nil
}

func (cfm *CommercialFeedsManager) initializeFeedConnectors() error {
	var err error
	
	// Initialize Recorded Future connector
	if cfm.config.RecordedFuture != nil && cfm.config.RecordedFuture.Enabled {
		cfm.recordedFuture, err = NewRecordedFutureConnector(cfm.logger, cfm.config.RecordedFuture)
		if err != nil {
			return fmt.Errorf("failed to initialize Recorded Future connector: %w", err)
		}
	}
	
	// Initialize Digital Shadows connector
	if cfm.config.DigitalShadows != nil && cfm.config.DigitalShadows.Enabled {
		cfm.digitalShadows, err = NewDigitalShadowsConnector(cfm.logger, cfm.config.DigitalShadows)
		if err != nil {
			return fmt.Errorf("failed to initialize Digital Shadows connector: %w", err)
		}
	}
	
	// Initialize CrowdStrike connector
	if cfm.config.CrowdStrike != nil && cfm.config.CrowdStrike.Enabled {
		cfm.crowdStrike, err = NewCrowdStrikeConnector(cfm.logger, cfm.config.CrowdStrike)
		if err != nil {
			return fmt.Errorf("failed to initialize CrowdStrike connector: %w", err)
		}
	}
	
	// Initialize FireEye connector
	if cfm.config.FireEye != nil && cfm.config.FireEye.Enabled {
		cfm.fireeye, err = NewFireEyeConnector(cfm.logger, cfm.config.FireEye)
		if err != nil {
			return fmt.Errorf("failed to initialize FireEye connector: %w", err)
		}
	}
	
	return nil
}

// StartFeedIngestion starts ingestion from all configured commercial feeds
func (cfm *CommercialFeedsManager) StartFeedIngestion() error {
	cfm.logger.Info("Starting commercial feed ingestion")
	
	// Start health monitoring
	go cfm.healthChecker.StartMonitoring(cfm.ctx)
	
	// Start individual feed sessions
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	
	if cfm.recordedFuture != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfm.startFeedSession("recorded_future", cfm.recordedFuture); err != nil {
				errors <- fmt.Errorf("recorded future feed failed: %w", err)
			}
		}()
	}
	
	if cfm.digitalShadows != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfm.startFeedSession("digital_shadows", cfm.digitalShadows); err != nil {
				errors <- fmt.Errorf("digital shadows feed failed: %w", err)
			}
		}()
	}
	
	if cfm.crowdStrike != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfm.startFeedSession("crowdstrike", cfm.crowdStrike); err != nil {
				errors <- fmt.Errorf("crowdstrike feed failed: %w", err)
			}
		}()
	}
	
	if cfm.fireeye != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cfm.startFeedSession("fireeye", cfm.fireeye); err != nil {
				errors <- fmt.Errorf("fireeye feed failed: %w", err)
			}
		}()
	}
	
	// Wait for all feeds to start
	go func() {
		wg.Wait()
		close(errors)
	}()
	
	// Check for startup errors
	var startupErrors []error
	for err := range errors {
		if err != nil {
			startupErrors = append(startupErrors, err)
		}
	}
	
	if len(startupErrors) > 0 {
		cfm.logger.Warn("Some commercial feeds failed to start", zap.Int("failed_count", len(startupErrors)))
		for _, err := range startupErrors {
			cfm.logger.Error("Feed startup error", zap.Error(err))
		}
	}
	
	cfm.logger.Info("Commercial feed ingestion started", 
		zap.Int("active_feeds", len(cfm.activeFeedSessions)))
	
	return nil
}

func (cfm *CommercialFeedsManager) startFeedSession(provider string, connector FeedConnector) error {
	sessionID := fmt.Sprintf("%s-%d", provider, time.Now().UnixNano())
	
	ctx, cancel := context.WithCancel(cfm.ctx)
	
	session := &FeedSession{
		ID:         sessionID,
		Provider:   provider,
		StartTime:  time.Now(),
		Status:     FeedSessionStatusInitializing,
		Context:    ctx,
		CancelFunc: cancel,
		Config: &FeedSessionConfig{
			Provider:        provider,
			UpdateFrequency: cfm.config.FeedUpdateInterval,
		},
	}
	
	// Register session
	cfm.feedMutex.Lock()
	cfm.activeFeedSessions[sessionID] = session
	cfm.feedMutex.Unlock()
	
	// Start feed processing
	go cfm.processFeedSession(session, connector)
	
	return nil
}

func (cfm *CommercialFeedsManager) processFeedSession(session *FeedSession, connector FeedConnector) {
	defer func() {
		session.Status = FeedSessionStatusCompleted
		session.CancelFunc()
		
		// Remove from active sessions
		cfm.feedMutex.Lock()
		delete(cfm.activeFeedSessions, session.ID)
		cfm.feedMutex.Unlock()
		
		cfm.logger.Info("Feed session completed",
			zap.String("session_id", session.ID),
			zap.String("provider", session.Provider),
			zap.Int64("indicators_processed", session.IndicatorsProcessed),
		)
	}()
	
	session.Status = FeedSessionStatusActive
	ticker := time.NewTicker(session.Config.UpdateFrequency)
	defer ticker.Stop()
	
	for {
		select {
		case <-session.Context.Done():
			return
		case <-ticker.C:
			if err := cfm.ingestFeedData(session, connector); err != nil {
				session.LastError = &FeedError{
					Timestamp:   time.Now(),
					ErrorType:   "ingestion_error",
					Message:     err.Error(),
					Severity:    "error",
					Recoverable: true,
				}
				session.Errors = append(session.Errors, *session.LastError)
				
				cfm.logger.Error("Feed ingestion error",
					zap.String("session_id", session.ID),
					zap.String("provider", session.Provider),
					zap.Error(err),
				)
				
				// Update session status based on error type
				if cfm.isRecoverableError(err) {
					session.Status = FeedSessionStatusError
					time.Sleep(cfm.config.RetryBackoff)
				} else {
					cfm.logger.Error("Non-recoverable feed error, stopping session",
						zap.String("session_id", session.ID),
						zap.Error(err),
					)
					return
				}
			} else {
				session.LastUpdate = time.Now()
				session.Status = FeedSessionStatusActive
			}
		}
	}
}

func (cfm *CommercialFeedsManager) ingestFeedData(session *FeedSession, connector FeedConnector) error {
	// Fetch data from the connector
	data, err := connector.FetchLatestData(session.Context)
	if err != nil {
		return fmt.Errorf("failed to fetch data from %s: %w", session.Provider, err)
	}
	
	// Validate and process the data
	validatedData, err := cfm.dataValidator.ValidateIndicators(data)
	if err != nil {
		return fmt.Errorf("data validation failed for %s: %w", session.Provider, err)
	}
	
	// Convert to STIX format
	stixIndicators, err := cfm.stixProcessor.ConvertToSTIX(validatedData)
	if err != nil {
		return fmt.Errorf("STIX conversion failed for %s: %w", session.Provider, err)
	}
	
	// Update session statistics
	session.IndicatorsProcessed += int64(len(data))
	session.IndicatorsValid += int64(len(stixIndicators))
	session.IndicatorsRejected += int64(len(data) - len(stixIndicators))
	
	// Store processed indicators (this would integrate with the main threat intelligence storage)
	if err := cfm.storeIndicators(session.Provider, stixIndicators); err != nil {
		return fmt.Errorf("failed to store indicators for %s: %w", session.Provider, err)
	}
	
	cfm.logger.Debug("Feed data ingested successfully",
		zap.String("provider", session.Provider),
		zap.Int("indicators_fetched", len(data)),
		zap.Int("indicators_valid", len(stixIndicators)),
	)
	
	return nil
}

func (cfm *CommercialFeedsManager) isRecoverableError(err error) bool {
	// Implement logic to determine if an error is recoverable
	// For example, network timeouts are recoverable, but authentication errors are not
	return true // Simplified implementation
}

func (cfm *CommercialFeedsManager) storeIndicators(provider string, indicators []STIXIndicator) error {
	// This would integrate with the main threat intelligence storage system
	// For now, we'll just log that indicators were processed
	cfm.logger.Info("Storing indicators",
		zap.String("provider", provider),
		zap.Int("count", len(indicators)),
	)
	return nil
}

// GetFeedSessions returns information about active feed sessions
func (cfm *CommercialFeedsManager) GetFeedSessions() map[string]*FeedSession {
	cfm.feedMutex.RLock()
	defer cfm.feedMutex.RUnlock()
	
	sessions := make(map[string]*FeedSession)
	for id, session := range cfm.activeFeedSessions {
		sessions[id] = session
	}
	
	return sessions
}

// Close gracefully shuts down the commercial feeds manager
func (cfm *CommercialFeedsManager) Close() error {
	cfm.logger.Info("Shutting down commercial feeds manager")
	
	// Cancel all active sessions
	cfm.feedMutex.RLock()
	for _, session := range cfm.activeFeedSessions {
		session.CancelFunc()
	}
	cfm.feedMutex.RUnlock()
	
	// Cancel main context
	if cfm.cancel != nil {
		cfm.cancel()
	}
	
	// Close individual connectors
	if cfm.recordedFuture != nil {
		cfm.recordedFuture.Close()
	}
	if cfm.digitalShadows != nil {
		cfm.digitalShadows.Close()
	}
	if cfm.crowdStrike != nil {
		cfm.crowdStrike.Close()
	}
	if cfm.fireeye != nil {
		cfm.fireeye.Close()
	}
	
	cfm.logger.Info("Commercial feeds manager shut down complete")
	return nil
}

// FeedConnector interface for commercial feed providers
type FeedConnector interface {
	FetchLatestData(ctx context.Context) ([]RawIndicator, error)
	Close() error
}

// RawIndicator represents raw threat intelligence data from commercial feeds
type RawIndicator struct {
	Provider    string                 `json:"provider"`
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Confidence  float64                `json:"confidence"`
	Tags        []string               `json:"tags"`
	FirstSeen   time.Time              `json:"first_seen"`
	LastSeen    time.Time              `json:"last_seen"`
	Context     map[string]interface{} `json:"context"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// STIXIndicator represents a STIX 2.1 formatted indicator
type STIXIndicator struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Pattern     string                 `json:"pattern"`
	Labels      []string               `json:"labels"`
	Confidence  int                    `json:"confidence"`
	ValidFrom   time.Time              `json:"valid_from"`
	ValidUntil  time.Time              `json:"valid_until"`
	Metadata    map[string]interface{} `json:"metadata"`
}