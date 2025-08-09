package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// ConfigManager manages configuration for stream processing components
type ConfigManager struct {
	logger           *zap.Logger
	configPaths      *ConfigPaths
	
	// Configuration watchers
	watchers         map[string]*ConfigWatcher
	callbacks        map[string][]ConfigUpdateCallback
	
	// Current configurations
	streamConfig     *StreamProcessingConfig
	enrichmentConfig *EnrichmentServiceConfig
	correlationConfig *CorrelationEngineConfig
	patternConfig    *PatternMatchingConfig
	anomalyConfig    *AnomalyDetectionConfig
	
	// Thread safety
	mu               sync.RWMutex
	
	// Background workers
	updateTicker     *time.Ticker
	ctx              context.Context
	cancel           context.CancelFunc
}

// ConfigPaths defines paths to configuration files
type ConfigPaths struct {
	StreamProcessing  string `json:"stream_processing"`
	Enrichment        string `json:"enrichment"`
	Correlation       string `json:"correlation"`
	PatternMatching   string `json:"pattern_matching"`
	AnomalyDetection  string `json:"anomaly_detection"`
	ThreatRules       string `json:"threat_rules"`
	CustomRules       string `json:"custom_rules"`
	CorrelationRules  string `json:"correlation_rules"`
	AttackPatterns    string `json:"attack_patterns"`
}

// ConfigWatcher monitors configuration file changes
type ConfigWatcher struct {
	FilePath     string
	LastModified time.Time
	FileSize     int64
	Checksum     string
}

// ConfigUpdateCallback defines callback function for configuration updates
type ConfigUpdateCallback func(configType string, newConfig interface{}) error

// DefaultStreamProcessingConfig provides default configuration
type DefaultStreamProcessingConfig struct {
	StreamProcessing  StreamProcessingConfig  `yaml:"stream_processing"`
	Enrichment        EnrichmentServiceConfig `yaml:"enrichment"`
	Correlation       CorrelationEngineConfig `yaml:"correlation"`
	PatternMatching   PatternMatchingConfig   `yaml:"pattern_matching"`
	AnomalyDetection  AnomalyDetectionConfig  `yaml:"anomaly_detection"`
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(logger *zap.Logger, configPaths *ConfigPaths) (*ConfigManager, error) {
	if configPaths == nil {
		return nil, fmt.Errorf("configuration paths are required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	manager := &ConfigManager{
		logger:      logger.With(zap.String("component", "config-manager")),
		configPaths: configPaths,
		watchers:    make(map[string]*ConfigWatcher),
		callbacks:   make(map[string][]ConfigUpdateCallback),
		ctx:         ctx,
		cancel:      cancel,
	}
	
	// Load initial configurations
	if err := manager.loadAllConfigurations(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load initial configurations: %w", err)
	}
	
	// Start configuration monitoring
	manager.updateTicker = time.NewTicker(30 * time.Second)
	go manager.runConfigurationMonitoring()
	
	logger.Info("Configuration manager initialized",
		zap.String("stream_processing_config", configPaths.StreamProcessing),
		zap.String("enrichment_config", configPaths.Enrichment),
		zap.String("correlation_config", configPaths.Correlation),
		zap.String("pattern_matching_config", configPaths.PatternMatching),
		zap.String("anomaly_detection_config", configPaths.AnomalyDetection),
	)
	
	return manager, nil
}

// GetStreamProcessingConfig returns the current stream processing configuration
func (cm *ConfigManager) GetStreamProcessingConfig() *StreamProcessingConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.streamConfig == nil {
		return cm.getDefaultStreamProcessingConfig()
	}
	
	// Return a copy to prevent external modifications
	config := *cm.streamConfig
	return &config
}

// GetEnrichmentConfig returns the current enrichment configuration
func (cm *ConfigManager) GetEnrichmentConfig() *EnrichmentServiceConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.enrichmentConfig == nil {
		return cm.getDefaultEnrichmentConfig()
	}
	
	config := *cm.enrichmentConfig
	return &config
}

// GetCorrelationConfig returns the current correlation configuration
func (cm *ConfigManager) GetCorrelationConfig() *CorrelationEngineConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.correlationConfig == nil {
		return cm.getDefaultCorrelationConfig()
	}
	
	config := *cm.correlationConfig
	return &config
}

// GetPatternMatchingConfig returns the current pattern matching configuration
func (cm *ConfigManager) GetPatternMatchingConfig() *PatternMatchingConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.patternConfig == nil {
		return cm.getDefaultPatternMatchingConfig()
	}
	
	config := *cm.patternConfig
	return &config
}

// GetAnomalyDetectionConfig returns the current anomaly detection configuration
func (cm *ConfigManager) GetAnomalyDetectionConfig() *AnomalyDetectionConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	
	if cm.anomalyConfig == nil {
		return cm.getDefaultAnomalyDetectionConfig()
	}
	
	config := *cm.anomalyConfig
	return &config
}

// RegisterConfigUpdateCallback registers a callback for configuration updates
func (cm *ConfigManager) RegisterConfigUpdateCallback(configType string, callback ConfigUpdateCallback) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	if cm.callbacks[configType] == nil {
		cm.callbacks[configType] = []ConfigUpdateCallback{}
	}
	
	cm.callbacks[configType] = append(cm.callbacks[configType], callback)
	
	cm.logger.Debug("Configuration update callback registered",
		zap.String("config_type", configType),
	)
}

// UpdateConfiguration manually updates a configuration
func (cm *ConfigManager) UpdateConfiguration(configType string, config interface{}) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	// Update the appropriate configuration
	switch configType {
	case "stream_processing":
		if cfg, ok := config.(*StreamProcessingConfig); ok {
			cm.streamConfig = cfg
		} else {
			return fmt.Errorf("invalid configuration type for stream_processing")
		}
	case "enrichment":
		if cfg, ok := config.(*EnrichmentServiceConfig); ok {
			cm.enrichmentConfig = cfg
		} else {
			return fmt.Errorf("invalid configuration type for enrichment")
		}
	case "correlation":
		if cfg, ok := config.(*CorrelationEngineConfig); ok {
			cm.correlationConfig = cfg
		} else {
			return fmt.Errorf("invalid configuration type for correlation")
		}
	case "pattern_matching":
		if cfg, ok := config.(*PatternMatchingConfig); ok {
			cm.patternConfig = cfg
		} else {
			return fmt.Errorf("invalid configuration type for pattern_matching")
		}
	case "anomaly_detection":
		if cfg, ok := config.(*AnomalyDetectionConfig); ok {
			cm.anomalyConfig = cfg
		} else {
			return fmt.Errorf("invalid configuration type for anomaly_detection")
		}
	default:
		return fmt.Errorf("unknown configuration type: %s", configType)
	}
	
	// Notify callbacks
	if callbacks, exists := cm.callbacks[configType]; exists {
		for _, callback := range callbacks {
			if err := callback(configType, config); err != nil {
				cm.logger.Error("Configuration update callback failed",
					zap.String("config_type", configType),
					zap.Error(err),
				)
			}
		}
	}
	
	cm.logger.Info("Configuration updated",
		zap.String("config_type", configType),
	)
	
	return nil
}

// loadAllConfigurations loads all configuration files
func (cm *ConfigManager) loadAllConfigurations() error {
	// Load stream processing configuration
	if cm.configPaths.StreamProcessing != "" {
		if config, err := cm.loadStreamProcessingConfig(cm.configPaths.StreamProcessing); err == nil {
			cm.streamConfig = config
			cm.addWatcher("stream_processing", cm.configPaths.StreamProcessing)
		} else {
			cm.logger.Warn("Failed to load stream processing config, using defaults", zap.Error(err))
		}
	}
	
	// Load enrichment configuration
	if cm.configPaths.Enrichment != "" {
		if config, err := cm.loadEnrichmentConfig(cm.configPaths.Enrichment); err == nil {
			cm.enrichmentConfig = config
			cm.addWatcher("enrichment", cm.configPaths.Enrichment)
		} else {
			cm.logger.Warn("Failed to load enrichment config, using defaults", zap.Error(err))
		}
	}
	
	// Load correlation configuration
	if cm.configPaths.Correlation != "" {
		if config, err := cm.loadCorrelationConfig(cm.configPaths.Correlation); err == nil {
			cm.correlationConfig = config
			cm.addWatcher("correlation", cm.configPaths.Correlation)
		} else {
			cm.logger.Warn("Failed to load correlation config, using defaults", zap.Error(err))
		}
	}
	
	// Load pattern matching configuration
	if cm.configPaths.PatternMatching != "" {
		if config, err := cm.loadPatternMatchingConfig(cm.configPaths.PatternMatching); err == nil {
			cm.patternConfig = config
			cm.addWatcher("pattern_matching", cm.configPaths.PatternMatching)
		} else {
			cm.logger.Warn("Failed to load pattern matching config, using defaults", zap.Error(err))
		}
	}
	
	// Load anomaly detection configuration
	if cm.configPaths.AnomalyDetection != "" {
		if config, err := cm.loadAnomalyDetectionConfig(cm.configPaths.AnomalyDetection); err == nil {
			cm.anomalyConfig = config
			cm.addWatcher("anomaly_detection", cm.configPaths.AnomalyDetection)
		} else {
			cm.logger.Warn("Failed to load anomaly detection config, using defaults", zap.Error(err))
		}
	}
	
	return nil
}

// addWatcher adds a file watcher for configuration changes
func (cm *ConfigManager) addWatcher(configType, filePath string) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		cm.logger.Warn("Failed to stat configuration file", 
			zap.String("config_type", configType),
			zap.String("file_path", filePath),
			zap.Error(err),
		)
		return
	}
	
	cm.watchers[configType] = &ConfigWatcher{
		FilePath:     filePath,
		LastModified: fileInfo.ModTime(),
		FileSize:     fileInfo.Size(),
	}
	
	cm.logger.Debug("Configuration file watcher added",
		zap.String("config_type", configType),
		zap.String("file_path", filePath),
	)
}

// runConfigurationMonitoring runs configuration file monitoring
func (cm *ConfigManager) runConfigurationMonitoring() {
	for {
		select {
		case <-cm.ctx.Done():
			return
		case <-cm.updateTicker.C:
			cm.checkForConfigurationUpdates()
		}
	}
}

// checkForConfigurationUpdates checks for configuration file changes
func (cm *ConfigManager) checkForConfigurationUpdates() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	for configType, watcher := range cm.watchers {
		if cm.hasFileChanged(watcher) {
			cm.logger.Info("Configuration file changed, reloading",
				zap.String("config_type", configType),
				zap.String("file_path", watcher.FilePath),
			)
			
			if err := cm.reloadConfiguration(configType, watcher.FilePath); err != nil {
				cm.logger.Error("Failed to reload configuration",
					zap.String("config_type", configType),
					zap.Error(err),
				)
			}
		}
	}
}

// hasFileChanged checks if a configuration file has changed
func (cm *ConfigManager) hasFileChanged(watcher *ConfigWatcher) bool {
	fileInfo, err := os.Stat(watcher.FilePath)
	if err != nil {
		return false
	}
	
	if fileInfo.ModTime().After(watcher.LastModified) || fileInfo.Size() != watcher.FileSize {
		watcher.LastModified = fileInfo.ModTime()
		watcher.FileSize = fileInfo.Size()
		return true
	}
	
	return false
}

// reloadConfiguration reloads a specific configuration
func (cm *ConfigManager) reloadConfiguration(configType, filePath string) error {
	switch configType {
	case "stream_processing":
		config, err := cm.loadStreamProcessingConfig(filePath)
		if err != nil {
			return err
		}
		cm.streamConfig = config
		
	case "enrichment":
		config, err := cm.loadEnrichmentConfig(filePath)
		if err != nil {
			return err
		}
		cm.enrichmentConfig = config
		
	case "correlation":
		config, err := cm.loadCorrelationConfig(filePath)
		if err != nil {
			return err
		}
		cm.correlationConfig = config
		
	case "pattern_matching":
		config, err := cm.loadPatternMatchingConfig(filePath)
		if err != nil {
			return err
		}
		cm.patternConfig = config
		
	case "anomaly_detection":
		config, err := cm.loadAnomalyDetectionConfig(filePath)
		if err != nil {
			return err
		}
		cm.anomalyConfig = config
		
	default:
		return fmt.Errorf("unknown configuration type: %s", configType)
	}
	
	// Notify callbacks
	if callbacks, exists := cm.callbacks[configType]; exists {
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
		}
		
		for _, callback := range callbacks {
			if err := callback(configType, config); err != nil {
				cm.logger.Error("Configuration update callback failed",
					zap.String("config_type", configType),
					zap.Error(err),
				)
			}
		}
	}
	
	return nil
}

// Stop stops the configuration manager
func (cm *ConfigManager) Stop() {
	if cm.cancel != nil {
		cm.cancel()
	}
	
	if cm.updateTicker != nil {
		cm.updateTicker.Stop()
	}
	
	cm.logger.Info("Configuration manager stopped")
}