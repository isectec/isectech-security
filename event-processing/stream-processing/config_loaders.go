package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Configuration loading methods

// loadStreamProcessingConfig loads stream processing configuration
func (cm *ConfigManager) loadStreamProcessingConfig(filePath string) (*StreamProcessingConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var config StreamProcessingConfig
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &config)
	} else {
		err = json.Unmarshal(data, &config)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Validate and set defaults
	if err := cm.validateAndSetStreamProcessingDefaults(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// loadEnrichmentConfig loads enrichment service configuration
func (cm *ConfigManager) loadEnrichmentConfig(filePath string) (*EnrichmentServiceConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var config EnrichmentServiceConfig
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &config)
	} else {
		err = json.Unmarshal(data, &config)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Validate and set defaults
	if err := cm.validateAndSetEnrichmentDefaults(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// loadCorrelationConfig loads correlation engine configuration
func (cm *ConfigManager) loadCorrelationConfig(filePath string) (*CorrelationEngineConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var config CorrelationEngineConfig
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &config)
	} else {
		err = json.Unmarshal(data, &config)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Validate and set defaults
	if err := cm.validateAndSetCorrelationDefaults(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// loadPatternMatchingConfig loads pattern matching configuration
func (cm *ConfigManager) loadPatternMatchingConfig(filePath string) (*PatternMatchingConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var config PatternMatchingConfig
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &config)
	} else {
		err = json.Unmarshal(data, &config)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Validate and set defaults
	if err := cm.validateAndSetPatternMatchingDefaults(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// loadAnomalyDetectionConfig loads anomaly detection configuration
func (cm *ConfigManager) loadAnomalyDetectionConfig(filePath string) (*AnomalyDetectionConfig, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var config AnomalyDetectionConfig
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		err = yaml.Unmarshal(data, &config)
	} else {
		err = json.Unmarshal(data, &config)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Validate and set defaults
	if err := cm.validateAndSetAnomalyDetectionDefaults(&config); err != nil {
		return nil, err
	}
	
	return &config, nil
}

// Default configuration methods

// getDefaultStreamProcessingConfig returns default stream processing configuration
func (cm *ConfigManager) getDefaultStreamProcessingConfig() *StreamProcessingConfig {
	return &StreamProcessingConfig{
		KafkaBrokers:          []string{"localhost:9092"},
		InputTopics:           []string{"security-events"},
		OutputTopics: map[string]string{
			"enriched":    "enriched-events",
			"correlated":  "correlated-events",
			"alerts":      "security-alerts",
			"anomalies":   "anomaly-events",
		},
		ConsumerGroupID:        "stream-processor-group",
		EnableEnrichment:       true,
		EnableCorrelation:      true,
		EnablePatternMatching:  true,
		EnableAnomalyDetection: true,
		WorkerPoolSize:         10,
		ProcessingTimeout:      30 * time.Second,
		MaxProcessingRetries:   3,
		BufferSize:             1000,
		ThreatIntelSources:     []TISourceConfig{},
		AssetInventoryURL:      "",
		UserBehaviorServiceURL: "",
		GeolocationServiceURL:  "",
		PatternRulesPath:       "./rules/threat-patterns.json",
		CustomRulesPath:        "./rules/custom-patterns.json",
		RuleUpdateInterval:     5 * time.Minute,
		CorrelationWindowSize:  5 * time.Minute,
		MaxCorrelationDepth:    100,
		SessionTimeoutWindow:   30 * time.Minute,
		MetricsEnabled:         true,
		HealthCheckInterval:    30 * time.Second,
		AlertingEnabled:        true,
	}
}

// getDefaultEnrichmentConfig returns default enrichment configuration
func (cm *ConfigManager) getDefaultEnrichmentConfig() *EnrichmentServiceConfig {
	return &EnrichmentServiceConfig{
		ThreatIntelSources:     []TISourceConfig{},
		AssetInventoryURL:      "",
		UserBehaviorServiceURL: "",
		GeolocationServiceURL:  "",
		CacheSize:              10000,
		CacheTTL:               30 * time.Minute,
		RequestTimeout:         10 * time.Second,
		MaxRetries:             3,
		RetryDelay:             1 * time.Second,
		EnableThreatIntel:      true,
		EnableGeolocation:      true,
		EnableAssetInfo:        true,
		EnableUserBehavior:     true,
		EnableDNSResolution:    true,
	}
}

// getDefaultCorrelationConfig returns default correlation configuration
func (cm *ConfigManager) getDefaultCorrelationConfig() *CorrelationEngineConfig {
	return &CorrelationEngineConfig{
		WindowSize:           5 * time.Minute,
		MaxDepth:             100,
		SessionTimeoutWindow: 30 * time.Minute,
		CleanupInterval:      1 * time.Minute,
		MaxSessions:          10000,
		MaxEventsPerSession:  1000,
	}
}

// getDefaultPatternMatchingConfig returns default pattern matching configuration
func (cm *ConfigManager) getDefaultPatternMatchingConfig() *PatternMatchingConfig {
	return &PatternMatchingConfig{
		RulesPath:         "./rules/threat-patterns.json",
		CustomRulesPath:   "./rules/custom-patterns.json",
		UpdateInterval:    5 * time.Minute,
		CaseSensitive:     false,
		MaxRuleComplexity: 100,
		EnableCustomRules: true,
	}
}

// getDefaultAnomalyDetectionConfig returns default anomaly detection configuration
func (cm *ConfigManager) getDefaultAnomalyDetectionConfig() *AnomalyDetectionConfig {
	return &AnomalyDetectionConfig{
		UserBehaviorServiceURL:    "",
		NetworkBehaviorServiceURL: "",
		RequestTimeout:            10 * time.Second,
		MaxRetries:                3,
		RetryDelay:                1 * time.Second,
		CacheSize:                 1000,
		CacheTTL:                  5 * time.Minute,
		CleanupInterval:           1 * time.Minute,
		AnomalyThreshold:          0.7,
		HighRiskThreshold:         0.8,
		EnableUserAnalysis:        true,
		EnableNetworkAnalysis:     true,
		EnableProcessAnalysis:     true,
	}
}

// Validation methods

// validateAndSetStreamProcessingDefaults validates and sets defaults for stream processing config
func (cm *ConfigManager) validateAndSetStreamProcessingDefaults(config *StreamProcessingConfig) error {
	if len(config.KafkaBrokers) == 0 {
		config.KafkaBrokers = []string{"localhost:9092"}
	}
	
	if len(config.InputTopics) == 0 {
		config.InputTopics = []string{"security-events"}
	}
	
	if len(config.OutputTopics) == 0 {
		config.OutputTopics = map[string]string{
			"enriched":   "enriched-events",
			"correlated": "correlated-events",
			"alerts":     "security-alerts",
			"anomalies":  "anomaly-events",
		}
	}
	
	if config.ConsumerGroupID == "" {
		config.ConsumerGroupID = "stream-processor-group"
	}
	
	if config.WorkerPoolSize == 0 {
		config.WorkerPoolSize = 10
	}
	
	if config.ProcessingTimeout == 0 {
		config.ProcessingTimeout = 30 * time.Second
	}
	
	if config.MaxProcessingRetries == 0 {
		config.MaxProcessingRetries = 3
	}
	
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	
	if config.RuleUpdateInterval == 0 {
		config.RuleUpdateInterval = 5 * time.Minute
	}
	
	if config.CorrelationWindowSize == 0 {
		config.CorrelationWindowSize = 5 * time.Minute
	}
	
	if config.MaxCorrelationDepth == 0 {
		config.MaxCorrelationDepth = 100
	}
	
	if config.SessionTimeoutWindow == 0 {
		config.SessionTimeoutWindow = 30 * time.Minute
	}
	
	if config.HealthCheckInterval == 0 {
		config.HealthCheckInterval = 30 * time.Second
	}
	
	return nil
}

// validateAndSetEnrichmentDefaults validates and sets defaults for enrichment config
func (cm *ConfigManager) validateAndSetEnrichmentDefaults(config *EnrichmentServiceConfig) error {
	if config.CacheSize == 0 {
		config.CacheSize = 10000
	}
	
	if config.CacheTTL == 0 {
		config.CacheTTL = 30 * time.Minute
	}
	
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	
	return nil
}

// validateAndSetCorrelationDefaults validates and sets defaults for correlation config
func (cm *ConfigManager) validateAndSetCorrelationDefaults(config *CorrelationEngineConfig) error {
	if config.WindowSize == 0 {
		config.WindowSize = 5 * time.Minute
	}
	
	if config.MaxDepth == 0 {
		config.MaxDepth = 100
	}
	
	if config.SessionTimeoutWindow == 0 {
		config.SessionTimeoutWindow = 30 * time.Minute
	}
	
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	
	if config.MaxSessions == 0 {
		config.MaxSessions = 10000
	}
	
	if config.MaxEventsPerSession == 0 {
		config.MaxEventsPerSession = 1000
	}
	
	return nil
}

// validateAndSetPatternMatchingDefaults validates and sets defaults for pattern matching config
func (cm *ConfigManager) validateAndSetPatternMatchingDefaults(config *PatternMatchingConfig) error {
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 5 * time.Minute
	}
	
	if config.MaxRuleComplexity == 0 {
		config.MaxRuleComplexity = 100
	}
	
	if config.RulesPath == "" {
		config.RulesPath = "./rules/threat-patterns.json"
	}
	
	if config.CustomRulesPath == "" {
		config.CustomRulesPath = "./rules/custom-patterns.json"
	}
	
	return nil
}

// validateAndSetAnomalyDetectionDefaults validates and sets defaults for anomaly detection config
func (cm *ConfigManager) validateAndSetAnomalyDetectionDefaults(config *AnomalyDetectionConfig) error {
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
	
	return nil
}

// SaveDefaultConfiguration saves a default configuration to file
func (cm *ConfigManager) SaveDefaultConfiguration(configType, filePath string) error {
	var config interface{}
	
	switch configType {
	case "stream_processing":
		config = cm.getDefaultStreamProcessingConfig()
	case "enrichment":
		config = cm.getDefaultEnrichmentConfig()
	case "correlation":
		config = cm.getDefaultCorrelationConfig()
	case "pattern_matching":
		config = cm.getDefaultPatternMatchingConfig()
	case "anomaly_detection":
		config = cm.getDefaultAnomalyDetectionConfig()
	default:
		return fmt.Errorf("unknown configuration type: %s", configType)
	}
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	
	var data []byte
	var err error
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		data, err = yaml.Marshal(config)
	} else {
		data, err = json.MarshalIndent(config, "", "  ")
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	cm.logger.Info("Default configuration saved",
		zap.String("config_type", configType),
		zap.String("file_path", filePath),
	)
	
	return nil
}

// ExportConfiguration exports the current configuration to a file
func (cm *ConfigManager) ExportConfiguration(configType, filePath string) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	var config interface{}
	
	switch configType {
	case "stream_processing":
		config = cm.streamConfig
	case "enrichment":
		config = cm.enrichmentConfig
	case "correlation":
		config = cm.correlationConfig
	case "pattern_matching":
		config = cm.patternConfig
	case "anomaly_detection":
		config = cm.anomalyConfig
	default:
		return fmt.Errorf("unknown configuration type: %s", configType)
	}
	
	if config == nil {
		return fmt.Errorf("configuration not loaded: %s", configType)
	}
	
	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	
	var data []byte
	var err error
	
	if strings.HasSuffix(filePath, ".yaml") || strings.HasSuffix(filePath, ".yml") {
		data, err = yaml.Marshal(config)
	} else {
		data, err = json.MarshalIndent(config, "", "  ")
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	
	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	cm.logger.Info("Configuration exported",
		zap.String("config_type", configType),
		zap.String("file_path", filePath),
	)
	
	return nil
}