package stream_processing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AnomalyDetectionIntegration integrates with AI/ML services for behavioral analysis
type AnomalyDetectionIntegration struct {
	logger      *zap.Logger
	config      *AnomalyDetectionConfig
	httpClient  *http.Client
	
	// Cache for recent anomaly results
	resultCache map[string]*CachedAnomalyResult
	cacheMu     sync.RWMutex
	
	// Health status
	isHealthy   bool
	mu          sync.RWMutex
	
	// Background cleanup
	ctx         context.Context
	cancel      context.CancelFunc
	cleanupTicker *time.Ticker
}

// AnomalyDetectionConfig defines configuration for anomaly detection integration
type AnomalyDetectionConfig struct {
	UserBehaviorServiceURL string        `json:"user_behavior_service_url"`
	NetworkBehaviorServiceURL string     `json:"network_behavior_service_url"`
	RequestTimeout         time.Duration `json:"request_timeout"`
	MaxRetries             int           `json:"max_retries"`
	RetryDelay             time.Duration `json:"retry_delay"`
	CacheSize              int           `json:"cache_size"`
	CacheTTL               time.Duration `json:"cache_ttl"`
	CleanupInterval        time.Duration `json:"cleanup_interval"`
	
	// Detection thresholds
	AnomalyThreshold       float64       `json:"anomaly_threshold"`
	HighRiskThreshold      float64       `json:"high_risk_threshold"`
	EnableUserAnalysis     bool          `json:"enable_user_analysis"`
	EnableNetworkAnalysis  bool          `json:"enable_network_analysis"`
	EnableProcessAnalysis  bool          `json:"enable_process_analysis"`
}

// CachedAnomalyResult represents a cached anomaly detection result
type CachedAnomalyResult struct {
	Result    *AnomalyDetectionResult `json:"result"`
	CachedAt  time.Time               `json:"cached_at"`
	ExpiresAt time.Time               `json:"expires_at"`
}

// AnomalyDetectionRequest represents a request to the anomaly detection service
type AnomalyDetectionRequest struct {
	EventData      map[string]interface{} `json:"event_data"`
	UserID         string                 `json:"user_id,omitempty"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	AssetID        string                 `json:"asset_id,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	AnalysisTypes  []string               `json:"analysis_types"`
	RequestContext map[string]interface{} `json:"request_context,omitempty"`
}

// UserBehaviorAnalysis represents user behavior analysis results
type UserBehaviorAnalysis struct {
	UserID             string                 `json:"user_id"`
	BaselineDeviation  float64                `json:"baseline_deviation"`
	AnomalousPatterns  []string               `json:"anomalous_patterns"`
	RiskFactors        []string               `json:"risk_factors"`
	BehaviorScore      float64                `json:"behavior_score"`
	TimeAnalysis       *TimeBasedAnalysis     `json:"time_analysis,omitempty"`
	LocationAnalysis   *LocationAnalysis      `json:"location_analysis,omitempty"`
	DeviceAnalysis     *DeviceAnalysis        `json:"device_analysis,omitempty"`
	ActivityAnalysis   *ActivityAnalysis      `json:"activity_analysis,omitempty"`
}

// NetworkBehaviorAnalysis represents network behavior analysis results
type NetworkBehaviorAnalysis struct {
	SourceIP           string              `json:"source_ip"`
	TrafficPatterns    []TrafficPattern    `json:"traffic_patterns"`
	AnomalousConnections []AnomalousConnection `json:"anomalous_connections"`
	GeoLocationRisk    float64             `json:"geo_location_risk"`
	ReputationScore    float64             `json:"reputation_score"`
	ThreatIntelMatch   bool                `json:"threat_intel_match"`
}

// ProcessBehaviorAnalysis represents process behavior analysis results
type ProcessBehaviorAnalysis struct {
	ProcessName        string              `json:"process_name"`
	ProcessPath        string              `json:"process_path"`
	ParentProcess      string              `json:"parent_process"`
	CommandLine        string              `json:"command_line"`
	BehaviorScore      float64             `json:"behavior_score"`
	AnomalousActions   []string            `json:"anomalous_actions"`
	SuspiciousIndicators []SuspiciousIndicator `json:"suspicious_indicators"`
}

// Supporting analysis structures
type TimeBasedAnalysis struct {
	IsOffHours         bool    `json:"is_off_hours"`
	UnusualTimePattern bool    `json:"unusual_time_pattern"`
	TimeRiskScore      float64 `json:"time_risk_score"`
}

type LocationAnalysis struct {
	IsNewLocation      bool    `json:"is_new_location"`
	GeoRiskScore       float64 `json:"geo_risk_score"`
	CountryRisk        string  `json:"country_risk"`
	VPNDetected        bool    `json:"vpn_detected"`
	TorDetected        bool    `json:"tor_detected"`
}

type DeviceAnalysis struct {
	IsNewDevice        bool    `json:"is_new_device"`
	DeviceRiskScore    float64 `json:"device_risk_score"`
	FingerprintMatch   bool    `json:"fingerprint_match"`
	SuspiciousAgent    bool    `json:"suspicious_agent"`
}

type ActivityAnalysis struct {
	AccessPatterns     []string `json:"access_patterns"`
	VolumeAnomaly      bool     `json:"volume_anomaly"`
	FrequencyAnomaly   bool     `json:"frequency_anomaly"`
	ActivityRiskScore  float64  `json:"activity_risk_score"`
}

type TrafficPattern struct {
	Pattern     string  `json:"pattern"`
	Frequency   int     `json:"frequency"`
	AnomalyScore float64 `json:"anomaly_score"`
}

type AnomalousConnection struct {
	DestinationIP   string  `json:"destination_ip"`
	DestinationPort int     `json:"destination_port"`
	Protocol        string  `json:"protocol"`
	AnomalyReason   string  `json:"anomaly_reason"`
	RiskScore       float64 `json:"risk_score"`
}

type SuspiciousIndicator struct {
	Indicator   string  `json:"indicator"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
}

// NewAnomalyDetectionIntegration creates a new anomaly detection integration
func NewAnomalyDetectionIntegration(logger *zap.Logger, config *AnomalyDetectionConfig) (*AnomalyDetectionIntegration, error) {
	if config == nil {
		return nil, fmt.Errorf("anomaly detection configuration is required")
	}
	
	// Set defaults
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.CacheSize == 0 {
		config.CacheSize = 1000
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	if config.AnomalyThreshold == 0 {
		config.AnomalyThreshold = 0.7
	}
	if config.HighRiskThreshold == 0 {
		config.HighRiskThreshold = 0.8
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	integration := &AnomalyDetectionIntegration{
		logger: logger.With(zap.String("component", "anomaly-detection-integration")),
		config: config,
		httpClient: &http.Client{
			Timeout: config.RequestTimeout,
		},
		resultCache: make(map[string]*CachedAnomalyResult),
		isHealthy:   true,
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Start cache cleanup
	integration.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go integration.runCacheCleanup()
	
	logger.Info("Anomaly detection integration initialized",
		zap.String("user_behavior_service", config.UserBehaviorServiceURL),
		zap.String("network_behavior_service", config.NetworkBehaviorServiceURL),
		zap.Duration("request_timeout", config.RequestTimeout),
		zap.Float64("anomaly_threshold", config.AnomalyThreshold),
	)
	
	return integration, nil
}

// DetectAnomalies performs anomaly detection on an event
func (a *AnomalyDetectionIntegration) DetectAnomalies(ctx context.Context, event map[string]interface{}) (*AnomalyDetectionResult, error) {
	start := time.Now()
	
	// Create cache key
	cacheKey := a.createCacheKey(event)
	
	// Check cache first
	if cached := a.getCachedResult(cacheKey); cached != nil {
		a.logger.Debug("Anomaly detection result from cache",
			zap.String("cache_key", cacheKey),
			zap.Float64("anomaly_score", cached.AnomalyScore),
		)
		return cached, nil
	}
	
	// Extract key fields for analysis
	userID := extractStringFromEvent(event, "user_id")
	sourceIP := extractStringFromEvent(event, "source_ip")
	assetID := extractStringFromEvent(event, "asset_id")
	timestamp := extractTimeFromEvent(event, "timestamp")
	
	// Determine analysis types
	analysisTypes := a.determineAnalysisTypes(event)
	
	// Create request
	request := &AnomalyDetectionRequest{
		EventData:     event,
		UserID:        userID,
		SourceIP:      sourceIP,
		AssetID:       assetID,
		Timestamp:     timestamp,
		AnalysisTypes: analysisTypes,
		RequestContext: map[string]interface{}{
			"request_id": cacheKey,
			"timestamp": time.Now(),
		},
	}
	
	// Perform anomaly detection
	result, err := a.performAnomalyDetection(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("anomaly detection failed: %w", err)
	}
	
	// Cache result
	a.cacheResult(cacheKey, result)
	
	duration := time.Since(start)
	
	a.logger.Debug("Anomaly detection completed",
		zap.String("user_id", userID),
		zap.String("source_ip", sourceIP),
		zap.Float64("anomaly_score", result.AnomalyScore),
		zap.Bool("is_anomalous", result.IsAnomalous),
		zap.Duration("duration", duration),
	)
	
	return result, nil
}

// performAnomalyDetection performs the actual anomaly detection
func (a *AnomalyDetectionIntegration) performAnomalyDetection(ctx context.Context, request *AnomalyDetectionRequest) (*AnomalyDetectionResult, error) {
	result := &AnomalyDetectionResult{
		AnomalyScore:   0.0,
		IsAnomalous:    false,
		AnomalyReasons: []string{},
	}
	
	var analysisResults []interface{}
	
	// Perform user behavior analysis
	if a.config.EnableUserAnalysis && request.UserID != "" {
		if userAnalysis, err := a.performUserBehaviorAnalysis(ctx, request); err == nil {
			analysisResults = append(analysisResults, userAnalysis)
			result.AnomalyScore += userAnalysis.BehaviorScore * 0.4 // 40% weight
			
			if len(userAnalysis.AnomalousPatterns) > 0 {
				result.AnomalyReasons = append(result.AnomalyReasons, userAnalysis.AnomalousPatterns...)
			}
		} else {
			a.logger.Warn("User behavior analysis failed", zap.Error(err))
		}
	}
	
	// Perform network behavior analysis
	if a.config.EnableNetworkAnalysis && request.SourceIP != "" {
		if networkAnalysis, err := a.performNetworkBehaviorAnalysis(ctx, request); err == nil {
			analysisResults = append(analysisResults, networkAnalysis)
			result.AnomalyScore += networkAnalysis.GeoLocationRisk * 0.3 // 30% weight
			
			if len(networkAnalysis.AnomalousConnections) > 0 {
				result.AnomalyReasons = append(result.AnomalyReasons, "anomalous network connections detected")
			}
		} else {
			a.logger.Warn("Network behavior analysis failed", zap.Error(err))
		}
	}
	
	// Perform process behavior analysis
	if a.config.EnableProcessAnalysis {
		if processAnalysis, err := a.performProcessBehaviorAnalysis(ctx, request); err == nil {
			analysisResults = append(analysisResults, processAnalysis)
			result.AnomalyScore += processAnalysis.BehaviorScore * 0.3 // 30% weight
			
			if len(processAnalysis.AnomalousActions) > 0 {
				result.AnomalyReasons = append(result.AnomalyReasons, processAnalysis.AnomalousActions...)
			}
		} else {
			a.logger.Warn("Process behavior analysis failed", zap.Error(err))
		}
	}
	
	// Normalize anomaly score (ensure it's between 0 and 1)
	if result.AnomalyScore > 1.0 {
		result.AnomalyScore = 1.0
	}
	
	// Determine if anomalous
	result.IsAnomalous = result.AnomalyScore >= a.config.AnomalyThreshold
	
	return result, nil
}

// IsHealthy returns the health status of the integration
func (a *AnomalyDetectionIntegration) IsHealthy() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.isHealthy
}