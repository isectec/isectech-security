package scoring

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ThreatIntelligenceScorer handles scoring, prioritization, and enrichment of threat intelligence
type ThreatIntelligenceScorer struct {
	logger     *zap.Logger
	config     *ScoringConfig
	
	// Scoring engines
	confidenceScorer   *ConfidenceScorer
	priorityEngine     *PriorityEngine
	enrichmentEngine   *EnrichmentEngine
	riskCalculator     *RiskCalculator
	
	// Context providers
	contextProviders   map[string]ContextProvider
	
	// Caching and optimization
	scoreCache         *ScoreCache
	
	// Operational state
	ctx               context.Context
	cancel            context.CancelFunc
	
	// Metrics
	metricsCollector  *ScoringMetrics
}

// ScoringConfig defines configuration for threat intelligence scoring
type ScoringConfig struct {
	// Confidence scoring
	ConfidenceWeights     map[string]float64 `json:"confidence_weights"`
	SourceReliability     map[string]float64 `json:"source_reliability"`
	AgeDecayFactor        float64            `json:"age_decay_factor"`
	
	// Priority scoring
	BusinessImpactWeights map[string]float64 `json:"business_impact_weights"`
	ThreatActorWeights    map[string]float64 `json:"threat_actor_weights"`
	AssetCriticalityWeights map[string]float64 `json:"asset_criticality_weights"`
	
	// Risk calculation
	CVSSWeights           map[string]float64 `json:"cvss_weights"`
	ExploitabilityWeights map[string]float64 `json:"exploitability_weights"`
	
	// Enrichment settings
	EnableEnrichment      bool               `json:"enable_enrichment"`
	EnrichmentSources     []string           `json:"enrichment_sources"`
	EnrichmentTimeout     time.Duration      `json:"enrichment_timeout"`
	
	// Caching
	EnableCaching         bool               `json:"enable_caching"`
	CacheTTL              time.Duration      `json:"cache_ttl"`
	MaxCacheEntries       int                `json:"max_cache_entries"`
	
	// Performance
	MaxConcurrentScoring  int                `json:"max_concurrent_scoring"`
	ScoringTimeout        time.Duration      `json:"scoring_timeout"`
}

// ScoredIntelligence represents intelligence with scoring information
type ScoredIntelligence struct {
	ID                string                 `json:"id"`
	OriginalIntel     ProcessedIntelligence  `json:"original_intel"`
	
	// Scoring results
	ConfidenceScore   float64                `json:"confidence_score"`
	PriorityScore     float64                `json:"priority_score"`
	RiskScore         float64                `json:"risk_score"`
	OverallScore      float64                `json:"overall_score"`
	
	// Scoring breakdown
	ScoreComponents   ScoreComponents        `json:"score_components"`
	
	// Enrichment data
	Enrichments       map[string]interface{} `json:"enrichments"`
	
	// Context information
	BusinessContext   BusinessContext        `json:"business_context"`
	ThreatContext     ThreatContext          `json:"threat_context"`
	
	// Metadata
	ScoredAt          time.Time              `json:"scored_at"`
	ScoringVersion    string                 `json:"scoring_version"`
	Metadata          map[string]interface{} `json:"metadata"`
}

type ScoreComponents struct {
	SourceReliability float64 `json:"source_reliability"`
	DataFreshness     float64 `json:"data_freshness"`
	CrossValidation   float64 `json:"cross_validation"`
	BusinessRelevance float64 `json:"business_relevance"`
	ThreatSeverity    float64 `json:"threat_severity"`
	Exploitability    float64 `json:"exploitability"`
	AssetExposure     float64 `json:"asset_exposure"`
}

type BusinessContext struct {
	AffectedAssets    []string               `json:"affected_assets"`
	BusinessUnits     []string               `json:"business_units"`
	CriticalityLevel  string                 `json:"criticality_level"`
	Compliance        []string               `json:"compliance"`
	Context           map[string]interface{} `json:"context"`
}

type ThreatContext struct {
	ThreatActors      []string               `json:"threat_actors"`
	Campaigns         []string               `json:"campaigns"`
	TTPs              []string               `json:"ttps"`
	Geolocation       []string               `json:"geolocation"`
	Industries        []string               `json:"industries"`
	Context           map[string]interface{} `json:"context"`
}

// ProcessedIntelligence placeholder (would come from processing package)
type ProcessedIntelligence struct {
	ID             string                 `json:"id"`
	Source         string                 `json:"source"`
	Type           string                 `json:"type"`
	IOCs           []IOC                  `json:"iocs"`
	TTPs           []TTP                  `json:"ttps"`
	ProcessedAt    time.Time              `json:"processed_at"`
	Confidence     float64                `json:"confidence"`
	Quality        float64                `json:"quality"`
	Tags           []string               `json:"tags"`
	Metadata       map[string]interface{} `json:"metadata"`
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
	MITREID     string  `json:"mitre_id"`
	Confidence  float64 `json:"confidence"`
}

// NewThreatIntelligenceScorer creates a new threat intelligence scorer
func NewThreatIntelligenceScorer(logger *zap.Logger, config *ScoringConfig) (*ThreatIntelligenceScorer, error) {
	if config == nil {
		return nil, fmt.Errorf("scoring configuration is required")
	}
	
	// Set defaults
	setScoringDefaults(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	scorer := &ThreatIntelligenceScorer{
		logger:           logger.With(zap.String("component", "threat-intelligence-scorer")),
		config:           config,
		ctx:              ctx,
		cancel:           cancel,
		contextProviders: make(map[string]ContextProvider),
	}
	
	// Initialize components
	if err := scorer.initializeComponents(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}
	
	logger.Info("Threat intelligence scorer initialized")
	return scorer, nil
}

func setScoringDefaults(config *ScoringConfig) {
	if config.AgeDecayFactor == 0 {
		config.AgeDecayFactor = 0.1 // 10% decay per day
	}
	if config.EnrichmentTimeout == 0 {
		config.EnrichmentTimeout = 30 * time.Second
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 1 * time.Hour
	}
	if config.MaxCacheEntries == 0 {
		config.MaxCacheEntries = 10000
	}
	if config.MaxConcurrentScoring == 0 {
		config.MaxConcurrentScoring = 50
	}
	if config.ScoringTimeout == 0 {
		config.ScoringTimeout = 5 * time.Minute
	}
	
	// Set default weights if not configured
	if len(config.ConfidenceWeights) == 0 {
		config.ConfidenceWeights = map[string]float64{
			"source_reliability": 0.3,
			"data_freshness":     0.2,
			"cross_validation":   0.3,
			"data_quality":       0.2,
		}
	}
	
	if len(config.SourceReliability) == 0 {
		config.SourceReliability = map[string]float64{
			"recorded_future":   0.95,
			"digital_shadows":   0.90,
			"crowdstrike":       0.95,
			"fireeye":           0.90,
			"otx":               0.75,
			"misp":              0.80,
			"cert":              0.85,
			"cisa":              0.90,
			"internal":          0.70,
		}
	}
}

func (tis *ThreatIntelligenceScorer) initializeComponents() error {
	var err error
	
	// Initialize confidence scorer
	tis.confidenceScorer, err = NewConfidenceScorer(tis.logger, tis.config)
	if err != nil {
		return fmt.Errorf("failed to initialize confidence scorer: %w", err)
	}
	
	// Initialize priority engine
	tis.priorityEngine, err = NewPriorityEngine(tis.logger, tis.config)
	if err != nil {
		return fmt.Errorf("failed to initialize priority engine: %w", err)
	}
	
	// Initialize enrichment engine
	if tis.config.EnableEnrichment {
		tis.enrichmentEngine, err = NewEnrichmentEngine(tis.logger, tis.config)
		if err != nil {
			return fmt.Errorf("failed to initialize enrichment engine: %w", err)
		}
	}
	
	// Initialize risk calculator
	tis.riskCalculator, err = NewRiskCalculator(tis.logger, tis.config)
	if err != nil {
		return fmt.Errorf("failed to initialize risk calculator: %w", err)
	}
	
	// Initialize score cache
	if tis.config.EnableCaching {
		tis.scoreCache, err = NewScoreCache(tis.logger, tis.config)
		if err != nil {
			return fmt.Errorf("failed to initialize score cache: %w", err)
		}
	}
	
	// Initialize metrics collector
	tis.metricsCollector, err = NewScoringMetrics(tis.logger)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics collector: %w", err)
	}
	
	return nil
}

// ScoreIntelligence scores and prioritizes threat intelligence
func (tis *ThreatIntelligenceScorer) ScoreIntelligence(intel []ProcessedIntelligence) ([]ScoredIntelligence, error) {
	tis.logger.Info("Starting intelligence scoring",
		zap.Int("input_count", len(intel)))
	
	var scoredIntel []ScoredIntelligence
	var wg sync.WaitGroup
	resultsChan := make(chan ScoredIntelligence, len(intel))
	errorsChan := make(chan error, len(intel))
	
	// Limit concurrent processing
	semaphore := make(chan struct{}, tis.config.MaxConcurrentScoring)
	
	for _, intelItem := range intel {
		wg.Add(1)
		go func(item ProcessedIntelligence) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			scored, err := tis.scoreIntelligenceItem(item)
			if err != nil {
				errorsChan <- fmt.Errorf("failed to score intelligence %s: %w", item.ID, err)
				return
			}
			
			resultsChan <- scored
		}(intelItem)
	}
	
	// Close channels when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()
	
	// Collect results
	for scored := range resultsChan {
		scoredIntel = append(scoredIntel, scored)
	}
	
	// Check for errors
	var errors []error
	for err := range errorsChan {
		errors = append(errors, err)
	}
	
	if len(errors) > 0 {
		tis.logger.Warn("Some intelligence scoring failed",
			zap.Int("error_count", len(errors)))
		for _, err := range errors {
			tis.logger.Error("Scoring error", zap.Error(err))
		}
	}
	
	tis.logger.Info("Intelligence scoring completed",
		zap.Int("scored_count", len(scoredIntel)),
		zap.Int("error_count", len(errors)))
	
	return scoredIntel, nil
}

func (tis *ThreatIntelligenceScorer) scoreIntelligenceItem(intel ProcessedIntelligence) (ScoredIntelligence, error) {
	startTime := time.Now()
	
	// Check cache first
	if tis.scoreCache != nil {
		if cached, found := tis.scoreCache.Get(intel.ID); found {
			tis.metricsCollector.RecordCacheHit()
			return cached, nil
		}
	}
	
	scored := ScoredIntelligence{
		ID:             fmt.Sprintf("scored-%s", intel.ID),
		OriginalIntel:  intel,
		ScoredAt:       time.Now(),
		ScoringVersion: "1.0",
		Metadata:       make(map[string]interface{}),
	}
	
	// Calculate confidence score
	confidenceScore, scoreComponents, err := tis.confidenceScorer.CalculateConfidence(intel)
	if err != nil {
		return scored, fmt.Errorf("confidence scoring failed: %w", err)
	}
	scored.ConfidenceScore = confidenceScore
	scored.ScoreComponents = scoreComponents
	
	// Calculate priority score
	priorityScore, businessContext, err := tis.priorityEngine.CalculatePriority(intel)
	if err != nil {
		return scored, fmt.Errorf("priority scoring failed: %w", err)
	}
	scored.PriorityScore = priorityScore
	scored.BusinessContext = businessContext
	
	// Calculate risk score
	riskScore, threatContext, err := tis.riskCalculator.CalculateRisk(intel)
	if err != nil {
		return scored, fmt.Errorf("risk calculation failed: %w", err)
	}
	scored.RiskScore = riskScore
	scored.ThreatContext = threatContext
	
	// Calculate overall score
	scored.OverallScore = tis.calculateOverallScore(confidenceScore, priorityScore, riskScore)
	
	// Enrich if enabled
	if tis.enrichmentEngine != nil {
		enrichments, err := tis.enrichmentEngine.EnrichIntelligence(intel)
		if err != nil {
			tis.logger.Warn("Intelligence enrichment failed", zap.Error(err))
		} else {
			scored.Enrichments = enrichments
		}
	}
	
	// Cache the result
	if tis.scoreCache != nil {
		tis.scoreCache.Set(intel.ID, scored)
	}
	
	// Record metrics
	tis.metricsCollector.RecordScoringOperation(time.Since(startTime), scored.OverallScore)
	
	return scored, nil
}

func (tis *ThreatIntelligenceScorer) calculateOverallScore(confidence, priority, risk float64) float64 {
	// Weighted combination of different scores
	// This could be made configurable
	weights := map[string]float64{
		"confidence": 0.3,
		"priority":   0.4,
		"risk":       0.3,
	}
	
	overallScore := (confidence * weights["confidence"]) +
		(priority * weights["priority"]) +
		(risk * weights["risk"])
	
	// Ensure score is between 0 and 1
	if overallScore > 1.0 {
		overallScore = 1.0
	}
	if overallScore < 0.0 {
		overallScore = 0.0
	}
	
	return overallScore
}

// GetScoringMetrics returns scoring performance metrics
func (tis *ThreatIntelligenceScorer) GetScoringMetrics() map[string]interface{} {
	return tis.metricsCollector.GetMetrics()
}

// Close gracefully shuts down the scorer
func (tis *ThreatIntelligenceScorer) Close() error {
	tis.logger.Info("Shutting down threat intelligence scorer")
	
	if tis.cancel != nil {
		tis.cancel()
	}
	
	if tis.enrichmentEngine != nil {
		tis.enrichmentEngine.Close()
	}
	
	return nil
}

// Component stubs for production implementation
type ConfidenceScorer struct {
	logger *zap.Logger
	config *ScoringConfig
}

type PriorityEngine struct {
	logger *zap.Logger
	config *ScoringConfig
}

type EnrichmentEngine struct {
	logger *zap.Logger
	config *ScoringConfig
}

type RiskCalculator struct {
	logger *zap.Logger
	config *ScoringConfig
}

type ScoreCache struct {
	logger *zap.Logger
	config *ScoringConfig
	cache  map[string]ScoredIntelligence
	mutex  sync.RWMutex
}

type ScoringMetrics struct {
	logger *zap.Logger
	stats  map[string]interface{}
	mutex  sync.RWMutex
}

type ContextProvider interface {
	GetContext(intel ProcessedIntelligence) (map[string]interface{}, error)
}

// Constructor stubs
func NewConfidenceScorer(logger *zap.Logger, config *ScoringConfig) (*ConfidenceScorer, error) {
	return &ConfidenceScorer{logger: logger, config: config}, nil
}

func NewPriorityEngine(logger *zap.Logger, config *ScoringConfig) (*PriorityEngine, error) {
	return &PriorityEngine{logger: logger, config: config}, nil
}

func NewEnrichmentEngine(logger *zap.Logger, config *ScoringConfig) (*EnrichmentEngine, error) {
	return &EnrichmentEngine{logger: logger, config: config}, nil
}

func NewRiskCalculator(logger *zap.Logger, config *ScoringConfig) (*RiskCalculator, error) {
	return &RiskCalculator{logger: logger, config: config}, nil
}

func NewScoreCache(logger *zap.Logger, config *ScoringConfig) (*ScoreCache, error) {
	return &ScoreCache{
		logger: logger,
		config: config,
		cache:  make(map[string]ScoredIntelligence),
	}, nil
}

func NewScoringMetrics(logger *zap.Logger) (*ScoringMetrics, error) {
	return &ScoringMetrics{
		logger: logger,
		stats:  make(map[string]interface{}),
	}, nil
}

// Method stubs
func (cs *ConfidenceScorer) CalculateConfidence(intel ProcessedIntelligence) (float64, ScoreComponents, error) {
	// Calculate confidence based on various factors
	sourceReliability := cs.config.SourceReliability[intel.Source]
	if sourceReliability == 0 {
		sourceReliability = 0.5 // Default reliability
	}
	
	// Calculate data freshness
	age := time.Since(intel.ProcessedAt)
	freshness := math.Exp(-cs.config.AgeDecayFactor * age.Hours() / 24)
	
	components := ScoreComponents{
		SourceReliability: sourceReliability,
		DataFreshness:     freshness,
		CrossValidation:   0.8, // Placeholder
		BusinessRelevance: 0.7, // Placeholder  
	}
	
	confidence := (sourceReliability * cs.config.ConfidenceWeights["source_reliability"]) +
		(freshness * cs.config.ConfidenceWeights["data_freshness"]) +
		(components.CrossValidation * cs.config.ConfidenceWeights["cross_validation"])
	
	return confidence, components, nil
}

func (pe *PriorityEngine) CalculatePriority(intel ProcessedIntelligence) (float64, BusinessContext, error) {
	priority := 0.7 // Placeholder calculation
	
	context := BusinessContext{
		AffectedAssets:   []string{"web-servers", "databases"},
		BusinessUnits:    []string{"finance", "operations"},
		CriticalityLevel: "high",
		Compliance:       []string{"pci-dss", "sox"},
	}
	
	return priority, context, nil
}

func (rc *RiskCalculator) CalculateRisk(intel ProcessedIntelligence) (float64, ThreatContext, error) {
	risk := 0.8 // Placeholder calculation
	
	context := ThreatContext{
		ThreatActors: []string{"apt1", "lazarus"},
		Campaigns:    []string{"operation-x"},
		TTPs:         []string{"t1055", "t1003"},
		Geolocation:  []string{"china", "north-korea"},
		Industries:   []string{"finance", "technology"},
	}
	
	return risk, context, nil
}

func (ee *EnrichmentEngine) EnrichIntelligence(intel ProcessedIntelligence) (map[string]interface{}, error) {
	enrichments := map[string]interface{}{
		"geolocation":    "US",
		"attribution":    "APT1",
		"malware_family": "Trojan.Generic",
	}
	return enrichments, nil
}

func (sc *ScoreCache) Get(key string) (ScoredIntelligence, bool) {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	
	scored, exists := sc.cache[key]
	return scored, exists
}

func (sc *ScoreCache) Set(key string, scored ScoredIntelligence) {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()
	
	sc.cache[key] = scored
}

func (sm *ScoringMetrics) RecordCacheHit() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	sm.stats["cache_hits"] = sm.getStatValue("cache_hits") + 1
}

func (sm *ScoringMetrics) RecordScoringOperation(duration time.Duration, score float64) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	sm.stats["total_operations"] = sm.getStatValue("total_operations") + 1
	sm.stats["last_operation_duration"] = duration
	sm.stats["average_score"] = (sm.getFloatStatValue("average_score") + score) / 2
}

func (sm *ScoringMetrics) GetMetrics() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	
	metrics := make(map[string]interface{})
	for k, v := range sm.stats {
		metrics[k] = v
	}
	return metrics
}

func (sm *ScoringMetrics) getStatValue(key string) int {
	if val, exists := sm.stats[key]; exists {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

func (sm *ScoringMetrics) getFloatStatValue(key string) float64 {
	if val, exists := sm.stats[key]; exists {
		if floatVal, ok := val.(float64); ok {
			return floatVal
		}
	}
	return 0.0
}

func (ee *EnrichmentEngine) Close() error { return nil }