package processing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// IntelligenceProcessor handles extraction, normalization, and correlation of threat intelligence
type IntelligenceProcessor struct {
	logger     *zap.Logger
	config     *ProcessingConfig
	
	// Processing components
	extractor      *IndicatorExtractor
	normalizer     *DataNormalizer
	correlator     *CorrelationEngine
	deduplicator   *Deduplicator
	
	// External integrations
	mitreMapper    *MITREMapper
	openCTI        *OpenCTIIntegration
	mispClient     *MISPClient
	
	// Processing pipeline
	processingPipeline *ProcessingPipeline
	
	// State management
	ctx           context.Context
	cancel        context.CancelFunc
	
	// Metrics and monitoring
	metricsCollector *ProcessingMetrics
}

// ProcessingConfig defines configuration for intelligence processing
type ProcessingConfig struct {
	// Extraction settings
	EnableIOCExtraction     bool     `json:"enable_ioc_extraction"`
	EnableTTPExtraction     bool     `json:"enable_ttp_extraction"`
	SupportedIOCTypes       []string `json:"supported_ioc_types"`
	ExtractionRules         []string `json:"extraction_rules"`
	
	// Normalization settings
	EnableNormalization     bool     `json:"enable_normalization"`
	NormalizationStandards  []string `json:"normalization_standards"`
	FieldMappings          map[string]string `json:"field_mappings"`
	
	// Correlation settings
	EnableCorrelation       bool          `json:"enable_correlation"`
	CorrelationWindow       time.Duration `json:"correlation_window"`
	CorrelationThreshold    float64       `json:"correlation_threshold"`
	
	// Deduplication settings
	EnableDeduplication     bool          `json:"enable_deduplication"`
	DeduplicationWindow     time.Duration `json:"deduplication_window"`
	SimilarityThreshold     float64       `json:"similarity_threshold"`
	
	// MITRE ATT&CK integration
	EnableMITREMapping      bool          `json:"enable_mitre_mapping"`
	MITREFrameworkVersion   string        `json:"mitre_framework_version"`
	
	// External system integration
	OpenCTIConfig          *OpenCTIConfig          `json:"opencti_config"`
	MISPConfig             *MISPIntegrationConfig  `json:"misp_config"`
	
	// Processing pipeline
	MaxConcurrentJobs      int           `json:"max_concurrent_jobs"`
	ProcessingTimeout      time.Duration `json:"processing_timeout"`
	BatchSize              int           `json:"batch_size"`
}

type OpenCTIConfig struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	VerifySSL bool   `json:"verify_ssl"`
}

type MISPIntegrationConfig struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"`
	AuthKey   string `json:"auth_key"`
	VerifySSL bool   `json:"verify_ssl"`
}

// ProcessingJob represents a single intelligence processing job
type ProcessingJob struct {
	ID            string                 `json:"id"`
	InputData     []RawIntelligence      `json:"input_data"`
	ProcessingSteps []ProcessingStep     `json:"processing_steps"`
	Status        ProcessingStatus       `json:"status"`
	Results       []ProcessedIntelligence `json:"results"`
	Errors        []ProcessingError      `json:"errors"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type ProcessingStatus string

const (
	ProcessingStatusPending    ProcessingStatus = "pending"
	ProcessingStatusProcessing ProcessingStatus = "processing"
	ProcessingStatusCompleted  ProcessingStatus = "completed"
	ProcessingStatusFailed     ProcessingStatus = "failed"
)

type ProcessingStep struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Duration    time.Duration          `json:"duration"`
	Input       interface{}            `json:"input"`
	Output      interface{}            `json:"output"`
	Errors      []string               `json:"errors"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type ProcessingError struct {
	Step        string    `json:"step"`
	Message     string    `json:"message"`
	Code        string    `json:"code"`
	Timestamp   time.Time `json:"timestamp"`
	Recoverable bool      `json:"recoverable"`
}

// RawIntelligence represents unprocessed intelligence data
type RawIntelligence struct {
	ID          string                 `json:"id"`
	Source      string                 `json:"source"`
	Type        string                 `json:"type"`
	Content     string                 `json:"content"`
	Format      string                 `json:"format"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
	Tags        []string               `json:"tags"`
}

// ProcessedIntelligence represents fully processed intelligence
type ProcessedIntelligence struct {
	ID             string                 `json:"id"`
	OriginalID     string                 `json:"original_id"`
	Source         string                 `json:"source"`
	Type           string                 `json:"type"`
	
	// Extracted indicators
	IOCs           []IOC                  `json:"iocs"`
	TTPs           []TTP                  `json:"ttps"`
	
	// Processing metadata
	ProcessedAt    time.Time              `json:"processed_at"`
	ProcessingJobs []string               `json:"processing_jobs"`
	Confidence     float64                `json:"confidence"`
	Quality        float64                `json:"quality"`
	
	// Correlation information
	RelatedIntel   []CorrelationLink      `json:"related_intel"`
	
	// MITRE mapping
	MITRETactics   []string               `json:"mitre_tactics"`
	MITRETechniques []string              `json:"mitre_techniques"`
	
	// Enrichment data
	Enrichments    map[string]interface{} `json:"enrichments"`
	
	// Standard fields
	Tags           []string               `json:"tags"`
	Metadata       map[string]interface{} `json:"metadata"`
}

type IOC struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Value      string                 `json:"value"`
	Pattern    string                 `json:"pattern"`
	Confidence float64                `json:"confidence"`
	Context    map[string]interface{} `json:"context"`
	FirstSeen  time.Time              `json:"first_seen"`
	LastSeen   time.Time              `json:"last_seen"`
	Tags       []string               `json:"tags"`
}

type TTP struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Tactic      string                 `json:"tactic"`
	Technique   string                 `json:"technique"`
	MITREID     string                 `json:"mitre_id"`
	Confidence  float64                `json:"confidence"`
	Context     map[string]interface{} `json:"context"`
	Evidence    []string               `json:"evidence"`
}

type CorrelationLink struct {
	RelatedID    string  `json:"related_id"`
	Relationship string  `json:"relationship"`
	Strength     float64 `json:"strength"`
	Evidence     []string `json:"evidence"`
}

// NewIntelligenceProcessor creates a new intelligence processor
func NewIntelligenceProcessor(logger *zap.Logger, config *ProcessingConfig) (*IntelligenceProcessor, error) {
	if config == nil {
		return nil, fmt.Errorf("processing configuration is required")
	}
	
	// Set defaults
	setProcessingDefaults(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	processor := &IntelligenceProcessor{
		logger: logger.With(zap.String("component", "intelligence-processor")),
		config: config,
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize components
	if err := processor.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	logger.Info("Intelligence processor initialized")
	return processor, nil
}

func setProcessingDefaults(config *ProcessingConfig) {
	if len(config.SupportedIOCTypes) == 0 {
		config.SupportedIOCTypes = []string{
			"ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr",
		}
	}
	if config.CorrelationWindow == 0 {
		config.CorrelationWindow = 24 * time.Hour
	}
	if config.CorrelationThreshold == 0 {
		config.CorrelationThreshold = 0.7
	}
	if config.DeduplicationWindow == 0 {
		config.DeduplicationWindow = 7 * 24 * time.Hour
	}
	if config.SimilarityThreshold == 0 {
		config.SimilarityThreshold = 0.8
	}
	if config.MaxConcurrentJobs == 0 {
		config.MaxConcurrentJobs = 10
	}
	if config.ProcessingTimeout == 0 {
		config.ProcessingTimeout = 30 * time.Minute
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
}

func (ip *IntelligenceProcessor) initializeComponents() error {
	var err error
	
	// Initialize extractor
	if ip.config.EnableIOCExtraction || ip.config.EnableTTPExtraction {
		ip.extractor, err = NewIndicatorExtractor(ip.logger, ip.config)
		if err != nil {
			return fmt.Errorf("failed to initialize extractor: %w", err)
		}
	}
	
	// Initialize normalizer
	if ip.config.EnableNormalization {
		ip.normalizer, err = NewDataNormalizer(ip.logger, ip.config)
		if err != nil {
			return fmt.Errorf("failed to initialize normalizer: %w", err)
		}
	}
	
	// Initialize correlator
	if ip.config.EnableCorrelation {
		ip.correlator, err = NewCorrelationEngine(ip.logger, ip.config)
		if err != nil {
			return fmt.Errorf("failed to initialize correlator: %w", err)
		}
	}
	
	// Initialize deduplicator
	if ip.config.EnableDeduplication {
		ip.deduplicator, err = NewDeduplicator(ip.logger, ip.config)
		if err != nil {
			return fmt.Errorf("failed to initialize deduplicator: %w", err)
		}
	}
	
	// Initialize MITRE mapper
	if ip.config.EnableMITREMapping {
		ip.mitreMapper, err = NewMITREMapper(ip.logger, ip.config)
		if err != nil {
			return fmt.Errorf("failed to initialize MITRE mapper: %w", err)
		}
	}
	
	// Initialize external integrations
	if ip.config.OpenCTIConfig != nil && ip.config.OpenCTIConfig.Enabled {
		ip.openCTI, err = NewOpenCTIIntegration(ip.logger, ip.config.OpenCTIConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize OpenCTI: %w", err)
		}
	}
	
	if ip.config.MISPConfig != nil && ip.config.MISPConfig.Enabled {
		ip.mispClient, err = NewMISPClient(ip.logger, ip.config.MISPConfig)
		if err != nil {
			return fmt.Errorf("failed to initialize MISP client: %w", err)
		}
	}
	
	// Initialize processing pipeline
	ip.processingPipeline, err = NewProcessingPipeline(ip.logger, ip.config)
	if err != nil {
		return fmt.Errorf("failed to initialize processing pipeline: %w", err)
	}
	
	// Initialize metrics collector
	ip.metricsCollector, err = NewProcessingMetrics(ip.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}
	
	return nil
}

// ProcessIntelligence processes raw intelligence through the complete pipeline
func (ip *IntelligenceProcessor) ProcessIntelligence(rawIntel []RawIntelligence) (*ProcessingJob, error) {
	job := &ProcessingJob{
		ID:          fmt.Sprintf("job-%d", time.Now().UnixNano()),
		InputData:   rawIntel,
		Status:      ProcessingStatusPending,
		StartTime:   time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	ip.logger.Info("Starting intelligence processing job",
		zap.String("job_id", job.ID),
		zap.Int("input_count", len(rawIntel)),
	)
	
	// Execute processing pipeline
	results, err := ip.processingPipeline.Execute(job)
	if err != nil {
		job.Status = ProcessingStatusFailed
		job.Errors = append(job.Errors, ProcessingError{
			Step:      "pipeline_execution",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
		return job, fmt.Errorf("processing pipeline failed: %w", err)
	}
	
	job.Results = results
	job.Status = ProcessingStatusCompleted
	job.EndTime = time.Now()
	
	// Update metrics
	ip.metricsCollector.RecordProcessingJob(job)
	
	ip.logger.Info("Intelligence processing job completed",
		zap.String("job_id", job.ID),
		zap.Int("results_count", len(results)),
		zap.Duration("duration", job.EndTime.Sub(job.StartTime)),
	)
	
	return job, nil
}

// GetProcessingStats returns processing statistics
func (ip *IntelligenceProcessor) GetProcessingStats() map[string]interface{} {
	return ip.metricsCollector.GetStats()
}

// Close gracefully shuts down the intelligence processor
func (ip *IntelligenceProcessor) Close() error {
	ip.logger.Info("Shutting down intelligence processor")
	
	if ip.cancel != nil {
		ip.cancel()
	}
	
	// Close external integrations
	if ip.openCTI != nil {
		ip.openCTI.Close()
	}
	if ip.mispClient != nil {
		ip.mispClient.Close()
	}
	
	return nil
}

// Component stubs for production implementation
type IndicatorExtractor struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type DataNormalizer struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type CorrelationEngine struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type Deduplicator struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type MITREMapper struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type OpenCTIIntegration struct {
	logger *zap.Logger
	config *OpenCTIConfig
}

type MISPClient struct {
	logger *zap.Logger
	config *MISPIntegrationConfig
}

type ProcessingPipeline struct {
	logger *zap.Logger
	config *ProcessingConfig
}

type ProcessingMetrics struct {
	logger *zap.Logger
	stats  map[string]interface{}
	mutex  sync.RWMutex
}

// Constructor stubs
func NewIndicatorExtractor(logger *zap.Logger, config *ProcessingConfig) (*IndicatorExtractor, error) {
	return &IndicatorExtractor{logger: logger, config: config}, nil
}

func NewDataNormalizer(logger *zap.Logger, config *ProcessingConfig) (*DataNormalizer, error) {
	return &DataNormalizer{logger: logger, config: config}, nil
}

func NewCorrelationEngine(logger *zap.Logger, config *ProcessingConfig) (*CorrelationEngine, error) {
	return &CorrelationEngine{logger: logger, config: config}, nil
}

func NewDeduplicator(logger *zap.Logger, config *ProcessingConfig) (*Deduplicator, error) {
	return &Deduplicator{logger: logger, config: config}, nil
}

func NewMITREMapper(logger *zap.Logger, config *ProcessingConfig) (*MITREMapper, error) {
	return &MITREMapper{logger: logger, config: config}, nil
}

func NewOpenCTIIntegration(logger *zap.Logger, config *OpenCTIConfig) (*OpenCTIIntegration, error) {
	return &OpenCTIIntegration{logger: logger, config: config}, nil
}

func NewMISPClient(logger *zap.Logger, config *MISPIntegrationConfig) (*MISPClient, error) {
	return &MISPClient{logger: logger, config: config}, nil
}

func NewProcessingPipeline(logger *zap.Logger, config *ProcessingConfig) (*ProcessingPipeline, error) {
	return &ProcessingPipeline{logger: logger, config: config}, nil
}

func NewProcessingMetrics(logger *zap.Logger) (*ProcessingMetrics, error) {
	return &ProcessingMetrics{
		logger: logger,
		stats:  make(map[string]interface{}),
	}, nil
}

// Method stubs
func (pp *ProcessingPipeline) Execute(job *ProcessingJob) ([]ProcessedIntelligence, error) {
	var results []ProcessedIntelligence
	
	// Simulate processing pipeline execution
	for i, rawIntel := range job.InputData {
		processed := ProcessedIntelligence{
			ID:           fmt.Sprintf("processed-%d-%d", time.Now().UnixNano(), i),
			OriginalID:   rawIntel.ID,
			Source:       rawIntel.Source,
			Type:         rawIntel.Type,
			ProcessedAt:  time.Now(),
			Confidence:   0.8,
			Quality:      0.9,
			Tags:         rawIntel.Tags,
			Metadata:     rawIntel.Metadata,
		}
		results = append(results, processed)
	}
	
	return results, nil
}

func (pm *ProcessingMetrics) RecordProcessingJob(job *ProcessingJob) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	
	pm.stats["total_jobs"] = pm.getStatValue("total_jobs") + 1
	pm.stats["total_processed"] = pm.getStatValue("total_processed") + len(job.Results)
	pm.stats["last_job_duration"] = job.EndTime.Sub(job.StartTime)
}

func (pm *ProcessingMetrics) GetStats() map[string]interface{} {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	for k, v := range pm.stats {
		stats[k] = v
	}
	return stats
}

func (pm *ProcessingMetrics) getStatValue(key string) int {
	if val, exists := pm.stats[key]; exists {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

// Close method stubs
func (oci *OpenCTIIntegration) Close() error { return nil }
func (mc *MISPClient) Close() error { return nil }