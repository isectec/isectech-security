package utilization

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IntelligenceUtilizationManager orchestrates real-time and retrospective threat intelligence utilization
type IntelligenceUtilizationManager struct {
	logger     *zap.Logger
	config     *UtilizationConfig
	
	// Real-time components
	realTimeEngine     *RealTimeEngine
	alertingSystem     *AlertingSystem
	automationEngine   *AutomationEngine
	
	// Retrospective components
	huntingPlatform    *ThreatHuntingPlatform
	forensicsEngine    *ForensicsEngine
	historicalAnalyzer *HistoricalAnalyzer
	
	// Integration components
	siemConnector      *SIEMConnector
	soarConnector      *SOARConnector
	edrrConnector      *EDRConnector
	networkConnector   *NetworkSecurityConnector
	
	// Rule engines
	yaraRuleEngine     *YARARuleEngine
	sigmaRuleEngine    *SigmaRuleEngine
	customRuleEngine   *CustomRuleEngine
	
	// Operational state
	ctx               context.Context
	cancel            context.CancelFunc
	
	// Performance tracking
	metricsCollector  *UtilizationMetrics
}

// UtilizationConfig defines configuration for intelligence utilization
type UtilizationConfig struct {
	// Real-time settings
	RealTimeEnabled        bool          `json:"real_time_enabled"`
	AlertThreshold         float64       `json:"alert_threshold"`
	AutomationEnabled      bool          `json:"automation_enabled"`
	ResponseTimeTarget     time.Duration `json:"response_time_target"`
	
	// Retrospective settings
	HuntingEnabled         bool          `json:"hunting_enabled"`
	ForensicsEnabled       bool          `json:"forensics_enabled"`
	HistoricalRetention    time.Duration `json:"historical_retention"`
	AnalysisDepth          string        `json:"analysis_depth"`
	
	// Integration settings
	SIEM                   *SIEMConfig                   `json:"siem"`
	SOAR                   *SOARConfig                   `json:"soar"`
	EDR                    *EDRConfig                    `json:"edr"`
	NetworkSecurity        *NetworkSecurityConfig        `json:"network_security"`
	
	// Rule engine settings
	YARAConfig             *YARAConfig                   `json:"yara_config"`
	SigmaConfig            *SigmaConfig                  `json:"sigma_config"`
	CustomRulesConfig      *CustomRulesConfig            `json:"custom_rules_config"`
	
	// Performance settings
	MaxConcurrentOperations int           `json:"max_concurrent_operations"`
	OperationTimeout       time.Duration `json:"operation_timeout"`
	BatchSize              int           `json:"batch_size"`
}

// Integration configurations
type SIEMConfig struct {
	Enabled         bool              `json:"enabled"`
	Platform        string            `json:"platform"` // splunk, elastic, qradar, sentinel
	APIEndpoint     string            `json:"api_endpoint"`
	Authentication  *AuthConfig       `json:"authentication"`
	IndexMappings   map[string]string `json:"index_mappings"`
	QueryTemplates  map[string]string `json:"query_templates"`
	UpdateInterval  time.Duration     `json:"update_interval"`
}

type SOARConfig struct {
	Enabled         bool              `json:"enabled"`
	Platform        string            `json:"platform"` // phantom, demisto, resilient
	APIEndpoint     string            `json:"api_endpoint"`
	Authentication  *AuthConfig       `json:"authentication"`
	PlaybookMappings map[string]string `json:"playbook_mappings"`
	AutoExecution   bool              `json:"auto_execution"`
	EscalationRules []EscalationRule  `json:"escalation_rules"`
}

type EDRConfig struct {
	Enabled         bool              `json:"enabled"`
	Platform        string            `json:"platform"` // crowdstrike, sentinelone, carbon_black
	APIEndpoint     string            `json:"api_endpoint"`
	Authentication  *AuthConfig       `json:"authentication"`
	ResponseActions []string          `json:"response_actions"`
	AutoContainment bool              `json:"auto_containment"`
	QueryInterval   time.Duration     `json:"query_interval"`
}

type NetworkSecurityConfig struct {
	Enabled         bool              `json:"enabled"`
	Platforms       []NetworkPlatform `json:"platforms"`
	BlockingEnabled bool              `json:"blocking_enabled"`
	MonitoringOnly  bool              `json:"monitoring_only"`
	UpdateInterval  time.Duration     `json:"update_interval"`
}

type NetworkPlatform struct {
	Type           string            `json:"type"` // firewall, ids, proxy, dns
	Vendor         string            `json:"vendor"`
	APIEndpoint    string            `json:"api_endpoint"`
	Authentication *AuthConfig       `json:"authentication"`
	Capabilities   []string          `json:"capabilities"`
}

type AuthConfig struct {
	Type         string            `json:"type"` // api_key, oauth2, basic, token
	Credentials  map[string]string `json:"credentials"`
	TokenRefresh bool              `json:"token_refresh"`
	TLSConfig    *TLSConfig        `json:"tls_config"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CACertPath         string `json:"ca_cert_path"`
	ClientCertPath     string `json:"client_cert_path"`
	ClientKeyPath      string `json:"client_key_path"`
}

// Rule engine configurations
type YARAConfig struct {
	Enabled           bool              `json:"enabled"`
	RulesDirectory    string            `json:"rules_directory"`
	CustomRules       []string          `json:"custom_rules"`
	AutoGeneration    bool              `json:"auto_generation"`
	ScanTargets       []string          `json:"scan_targets"`
	UpdateInterval    time.Duration     `json:"update_interval"`
	PerformanceMode   string            `json:"performance_mode"`
}

type SigmaConfig struct {
	Enabled           bool              `json:"enabled"`
	RulesDirectory    string            `json:"rules_directory"`
	TargetPlatforms   []string          `json:"target_platforms"`
	CustomMappings    map[string]string `json:"custom_mappings"`
	AutoDeployment    bool              `json:"auto_deployment"`
	ValidationEnabled bool              `json:"validation_enabled"`
}

type CustomRulesConfig struct {
	Enabled           bool              `json:"enabled"`
	RuleFormats       []string          `json:"rule_formats"`
	ValidationRules   []string          `json:"validation_rules"`
	AutoTesting       bool              `json:"auto_testing"`
	VersionControl    bool              `json:"version_control"`
}

type EscalationRule struct {
	Name         string        `json:"name"`
	Condition    string        `json:"condition"`
	Severity     string        `json:"severity"`
	Delay        time.Duration `json:"delay"`
	Actions      []string      `json:"actions"`
	Destinations []string      `json:"destinations"`
}

// NewIntelligenceUtilizationManager creates a new intelligence utilization manager
func NewIntelligenceUtilizationManager(logger *zap.Logger, config *UtilizationConfig) (*IntelligenceUtilizationManager, error) {
	if config == nil {
		return nil, fmt.Errorf("utilization configuration is required")
	}
	
	// Set defaults
	setUtilizationDefaults(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	ium := &IntelligenceUtilizationManager{
		logger: logger.With(zap.String("component", "intelligence-utilization-manager")),
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	if err := ium.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	logger.Info("Intelligence utilization manager initialized",
		zap.Bool("real_time_enabled", config.RealTimeEnabled),
		zap.Bool("hunting_enabled", config.HuntingEnabled),
		zap.Bool("automation_enabled", config.AutomationEnabled),
	)
	
	return ium, nil
}

func setUtilizationDefaults(config *UtilizationConfig) {
	if config.ResponseTimeTarget == 0 {
		config.ResponseTimeTarget = 5 * time.Minute
	}
	if config.HistoricalRetention == 0 {
		config.HistoricalRetention = 90 * 24 * time.Hour // 90 days
	}
	if config.AlertThreshold == 0 {
		config.AlertThreshold = 0.8 // 80% confidence threshold
	}
	if config.MaxConcurrentOperations == 0 {
		config.MaxConcurrentOperations = 20
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = 30 * time.Minute
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.AnalysisDepth == "" {
		config.AnalysisDepth = "comprehensive"
	}
}

func (ium *IntelligenceUtilizationManager) initializeComponents() error {
	var err error
	
	// Initialize real-time components
	if ium.config.RealTimeEnabled {
		ium.realTimeEngine, err = NewRealTimeEngine(ium.logger, ium.config)
		if err != nil {
			return fmt.Errorf("failed to initialize real-time engine: %w", err)
		}
		
		ium.alertingSystem, err = NewAlertingSystem(ium.logger, ium.config)
		if err != nil {
			return fmt.Errorf("failed to initialize alerting system: %w", err)
		}
	}
	
	if ium.config.AutomationEnabled {
		ium.automationEngine, err = NewAutomationEngine(ium.logger, ium.config)
		if err != nil {
			return fmt.Errorf("failed to initialize automation engine: %w", err)
		}
	}
	
	// Initialize retrospective components
	if ium.config.HuntingEnabled {
		ium.huntingPlatform, err = NewThreatHuntingPlatform(ium.logger, ium.config)
		if err != nil {
			return fmt.Errorf("failed to initialize hunting platform: %w", err)
		}
	}
	
	if ium.config.ForensicsEnabled {
		ium.forensicsEngine, err = NewForensicsEngine(ium.logger, ium.config)
		if err != nil {
			return fmt.Errorf("failed to initialize forensics engine: %w", err)
		}
	}
	
	ium.historicalAnalyzer, err = NewHistoricalAnalyzer(ium.logger, ium.config)
	if err != nil {
		return fmt.Errorf("failed to initialize historical analyzer: %w", err)
	}
	
	// Initialize integration connectors
	if ium.config.SIEM != nil && ium.config.SIEM.Enabled {
		ium.siemConnector, err = NewSIEMConnector(ium.logger, ium.config.SIEM)
		if err != nil {
			return fmt.Errorf("failed to initialize SIEM connector: %w", err)
		}
	}
	
	if ium.config.SOAR != nil && ium.config.SOAR.Enabled {
		ium.soarConnector, err = NewSOARConnector(ium.logger, ium.config.SOAR)
		if err != nil {
			return fmt.Errorf("failed to initialize SOAR connector: %w", err)
		}
	}
	
	if ium.config.EDR != nil && ium.config.EDR.Enabled {
		ium.edrrConnector, err = NewEDRConnector(ium.logger, ium.config.EDR)
		if err != nil {
			return fmt.Errorf("failed to initialize EDR connector: %w", err)
		}
	}
	
	if ium.config.NetworkSecurity != nil && ium.config.NetworkSecurity.Enabled {
		ium.networkConnector, err = NewNetworkSecurityConnector(ium.logger, ium.config.NetworkSecurity)
		if err != nil {
			return fmt.Errorf("failed to initialize network security connector: %w", err)
		}
	}
	
	// Initialize rule engines
	if ium.config.YARAConfig != nil && ium.config.YARAConfig.Enabled {
		ium.yaraRuleEngine, err = NewYARARuleEngine(ium.logger, ium.config.YARAConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize YARA rule engine: %w", err)
		}
	}
	
	if ium.config.SigmaConfig != nil && ium.config.SigmaConfig.Enabled {
		ium.sigmaRuleEngine, err = NewSigmaRuleEngine(ium.logger, ium.config.SigmaConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize Sigma rule engine: %w", err)
		}
	}
	
	if ium.config.CustomRulesConfig != nil && ium.config.CustomRulesConfig.Enabled {
		ium.customRuleEngine, err = NewCustomRuleEngine(ium.logger, ium.config.CustomRulesConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize custom rule engine: %w", err)
		}
	}
	
	// Initialize metrics collector
	ium.metricsCollector, err = NewUtilizationMetrics(ium.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}
	
	return nil
}

// StartUtilization starts all utilization services
func (ium *IntelligenceUtilizationManager) StartUtilization() error {
	ium.logger.Info("Starting intelligence utilization services")
	
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	
	// Start real-time processing if enabled
	if ium.realTimeEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.realTimeEngine.StartProcessing(ium.ctx); err != nil {
				errors <- fmt.Errorf("real-time engine failed: %w", err)
			}
		}()
	}
	
	// Start alerting system if enabled
	if ium.alertingSystem != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.alertingSystem.StartAlerting(ium.ctx); err != nil {
				errors <- fmt.Errorf("alerting system failed: %w", err)
			}
		}()
	}
	
	// Start automation engine if enabled
	if ium.automationEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.automationEngine.StartAutomation(ium.ctx); err != nil {
				errors <- fmt.Errorf("automation engine failed: %w", err)
			}
		}()
	}
	
	// Start hunting platform if enabled
	if ium.huntingPlatform != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.huntingPlatform.StartHunting(ium.ctx); err != nil {
				errors <- fmt.Errorf("hunting platform failed: %w", err)
			}
		}()
	}
	
	// Start rule engines
	if ium.yaraRuleEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.yaraRuleEngine.StartEngine(ium.ctx); err != nil {
				errors <- fmt.Errorf("YARA rule engine failed: %w", err)
			}
		}()
	}
	
	if ium.sigmaRuleEngine != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ium.sigmaRuleEngine.StartEngine(ium.ctx); err != nil {
				errors <- fmt.Errorf("Sigma rule engine failed: %w", err)
			}
		}()
	}
	
	// Wait for startup completion
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
		ium.logger.Warn("Some utilization services failed to start", zap.Int("failed_count", len(startupErrors)))
		for _, err := range startupErrors {
			ium.logger.Error("Service startup error", zap.Error(err))
		}
	}
	
	ium.logger.Info("Intelligence utilization services started")
	return nil
}

// ProcessIntelligence processes new threat intelligence for both real-time and retrospective use
func (ium *IntelligenceUtilizationManager) ProcessIntelligence(intelligence []ThreatIntelligence) error {
	ium.logger.Info("Processing threat intelligence for utilization",
		zap.Int("intelligence_count", len(intelligence)))
	
	var wg sync.WaitGroup
	errors := make(chan error, len(intelligence))
	
	// Limit concurrent processing
	semaphore := make(chan struct{}, ium.config.MaxConcurrentOperations)
	
	for _, intel := range intelligence {
		wg.Add(1)
		go func(intel ThreatIntelligence) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			if err := ium.processIntelligenceItem(intel); err != nil {
				errors <- fmt.Errorf("failed to process intelligence %s: %w", intel.ID, err)
			}
		}(intel)
	}
	
	// Wait for completion
	go func() {
		wg.Wait()
		close(errors)
	}()
	
	// Collect errors
	var processingErrors []error
	for err := range errors {
		if err != nil {
			processingErrors = append(processingErrors, err)
		}
	}
	
	if len(processingErrors) > 0 {
		ium.logger.Warn("Some intelligence processing failed",
			zap.Int("error_count", len(processingErrors)))
		for _, err := range processingErrors {
			ium.logger.Error("Processing error", zap.Error(err))
		}
	}
	
	ium.logger.Info("Intelligence processing completed",
		zap.Int("processed_count", len(intelligence)-len(processingErrors)),
		zap.Int("error_count", len(processingErrors)))
	
	return nil
}

func (ium *IntelligenceUtilizationManager) processIntelligenceItem(intel ThreatIntelligence) error {
	startTime := time.Now()
	
	// Real-time processing
	if ium.realTimeEngine != nil && intel.OverallScore >= ium.config.AlertThreshold {
		if err := ium.realTimeEngine.ProcessIntelligence(intel); err != nil {
			ium.logger.Warn("Real-time processing failed", zap.Error(err))
		}
		
		// Generate alerts if needed
		if ium.alertingSystem != nil {
			if err := ium.alertingSystem.EvaluateForAlert(intel); err != nil {
				ium.logger.Warn("Alert evaluation failed", zap.Error(err))
			}
		}
		
		// Trigger automation if enabled
		if ium.automationEngine != nil {
			if err := ium.automationEngine.ProcessIntelligence(intel); err != nil {
				ium.logger.Warn("Automation processing failed", zap.Error(err))
			}
		}
	}
	
	// Generate detection rules
	if err := ium.generateDetectionRules(intel); err != nil {
		ium.logger.Warn("Rule generation failed", zap.Error(err))
	}
	
	// Update external systems
	if err := ium.updateExternalSystems(intel); err != nil {
		ium.logger.Warn("External system update failed", zap.Error(err))
	}
	
	// Store for retrospective analysis
	if ium.historicalAnalyzer != nil {
		if err := ium.historicalAnalyzer.StoreIntelligence(intel); err != nil {
			ium.logger.Warn("Historical storage failed", zap.Error(err))
		}
	}
	
	// Record processing metrics
	ium.metricsCollector.RecordProcessingOperation(time.Since(startTime), intel.OverallScore)
	
	return nil
}

func (ium *IntelligenceUtilizationManager) generateDetectionRules(intel ThreatIntelligence) error {
	// Generate YARA rules
	if ium.yaraRuleEngine != nil {
		if err := ium.yaraRuleEngine.GenerateRule(intel); err != nil {
			return fmt.Errorf("YARA rule generation failed: %w", err)
		}
	}
	
	// Generate Sigma rules
	if ium.sigmaRuleEngine != nil {
		if err := ium.sigmaRuleEngine.GenerateRule(intel); err != nil {
			return fmt.Errorf("Sigma rule generation failed: %w", err)
		}
	}
	
	// Generate custom rules
	if ium.customRuleEngine != nil {
		if err := ium.customRuleEngine.GenerateRule(intel); err != nil {
			return fmt.Errorf("Custom rule generation failed: %w", err)
		}
	}
	
	return nil
}

func (ium *IntelligenceUtilizationManager) updateExternalSystems(intel ThreatIntelligence) error {
	// Update SIEM
	if ium.siemConnector != nil {
		if err := ium.siemConnector.UpdateIntelligence(intel); err != nil {
			return fmt.Errorf("SIEM update failed: %w", err)
		}
	}
	
	// Update SOAR
	if ium.soarConnector != nil {
		if err := ium.soarConnector.CreateCase(intel); err != nil {
			return fmt.Errorf("SOAR case creation failed: %w", err)
		}
	}
	
	// Update EDR
	if ium.edrrConnector != nil {
		if err := ium.edrrConnector.UpdateIOCs(intel); err != nil {
			return fmt.Errorf("EDR IOC update failed: %w", err)
		}
	}
	
	// Update network security
	if ium.networkConnector != nil {
		if err := ium.networkConnector.UpdateBlocklist(intel); err != nil {
			return fmt.Errorf("Network security update failed: %w", err)
		}
	}
	
	return nil
}

// ExecuteHuntingQuery executes a threat hunting query using stored intelligence
func (ium *IntelligenceUtilizationManager) ExecuteHuntingQuery(query HuntingQuery) (*HuntingResult, error) {
	if ium.huntingPlatform == nil {
		return nil, fmt.Errorf("threat hunting platform not enabled")
	}
	
	return ium.huntingPlatform.ExecuteQuery(query)
}

// GetUtilizationMetrics returns utilization performance metrics
func (ium *IntelligenceUtilizationManager) GetUtilizationMetrics() map[string]interface{} {
	return ium.metricsCollector.GetMetrics()
}

// Close gracefully shuts down the intelligence utilization manager
func (ium *IntelligenceUtilizationManager) Close() error {
	ium.logger.Info("Shutting down intelligence utilization manager")
	
	if ium.cancel != nil {
		ium.cancel()
	}
	
	// Close all components
	if ium.realTimeEngine != nil {
		ium.realTimeEngine.Close()
	}
	if ium.alertingSystem != nil {
		ium.alertingSystem.Close()
	}
	if ium.automationEngine != nil {
		ium.automationEngine.Close()
	}
	if ium.huntingPlatform != nil {
		ium.huntingPlatform.Close()
	}
	if ium.yaraRuleEngine != nil {
		ium.yaraRuleEngine.Close()
	}
	if ium.sigmaRuleEngine != nil {
		ium.sigmaRuleEngine.Close()
	}
	
	return nil
}

// Supporting types
type ThreatIntelligence struct {
	ID             string                 `json:"id"`
	Source         string                 `json:"source"`
	Type           string                 `json:"type"`
	IOCs           []IOC                  `json:"iocs"`
	TTPs           []TTP                  `json:"ttps"`
	ConfidenceScore float64               `json:"confidence_score"`
	PriorityScore   float64               `json:"priority_score"`
	RiskScore       float64               `json:"risk_score"`
	OverallScore    float64               `json:"overall_score"`
	ProcessedAt     time.Time             `json:"processed_at"`
	Context         map[string]interface{} `json:"context"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type IOC struct {
	Type       string    `json:"type"`
	Value      string    `json:"value"`
	Confidence float64   `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type TTP struct {
	Name        string  `json:"name"`
	MITREId     string  `json:"mitre_id"`
	Confidence  float64 `json:"confidence"`
}

type HuntingQuery struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Query       string                 `json:"query"`
	DataSources []string               `json:"data_sources"`
	TimeRange   TimeRange              `json:"time_range"`
	Parameters  map[string]interface{} `json:"parameters"`
}

type HuntingResult struct {
	QueryID     string                 `json:"query_id"`
	ExecutedAt  time.Time              `json:"executed_at"`
	Results     []map[string]interface{} `json:"results"`
	ResultCount int                    `json:"result_count"`
	ExecutionTime time.Duration        `json:"execution_time"`
	Status      string                 `json:"status"`
}

type TimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}