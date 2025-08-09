package service

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/services/event-processor/domain/service"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// RiskAssessmentService implements service.RiskAssessmentService
type RiskAssessmentService struct {
	logger  *logging.Logger
	metrics *metrics.Collector
	config  *RiskAssessmentConfig
	
	// Risk assessment components
	riskFactors     map[string]RiskFactor
	severityWeights map[types.Severity]float64
	typeWeights     map[types.EventType]float64
	sourceWeights   map[string]float64
	
	// ML models (placeholder for future implementation)
	mlModelEnabled  bool
	mlModelEndpoint string
}

// RiskAssessmentConfig contains risk assessment configuration
type RiskAssessmentConfig struct {
	// Model configuration
	EnableMLModel              bool                       `json:"enable_ml_model"`
	MLModelEndpoint            string                     `json:"ml_model_endpoint"`
	FallbackToRuleBased        bool                       `json:"fallback_to_rule_based"`
	ModelTimeout               time.Duration              `json:"model_timeout"`
	
	// Scoring configuration
	DefaultRiskScore           float64                    `json:"default_risk_score"`
	MinConfidenceThreshold     float64                    `json:"min_confidence_threshold"`
	MaxRiskScore               float64                    `json:"max_risk_score"`
	
	// Risk thresholds
	LowRiskThreshold           float64                    `json:"low_risk_threshold"`
	MediumRiskThreshold        float64                    `json:"medium_risk_threshold"`
	HighRiskThreshold          float64                    `json:"high_risk_threshold"`
	CriticalRiskThreshold      float64                    `json:"critical_risk_threshold"`
	
	// Weighting factors
	SeverityWeight             float64                    `json:"severity_weight"`
	TypeWeight                 float64                    `json:"type_weight"`
	SourceWeight               float64                    `json:"source_weight"`
	TimeWeight                 float64                    `json:"time_weight"`
	FrequencyWeight            float64                    `json:"frequency_weight"`
	AssetCriticalityWeight     float64                    `json:"asset_criticality_weight"`
	ThreatIntelWeight          float64                    `json:"threat_intel_weight"`
	
	// Dynamic factors
	EnableTimeDecay            bool                       `json:"enable_time_decay"`
	TimeDecayHalfLife          time.Duration              `json:"time_decay_half_life"`
	EnableFrequencyAnalysis    bool                       `json:"enable_frequency_analysis"`
	FrequencyWindow            time.Duration              `json:"frequency_window"`
	EnableAssetContext         bool                       `json:"enable_asset_context"`
	EnableUserContext          bool                       `json:"enable_user_context"`
	
	// Risk factors
	CustomRiskFactors          map[string]RiskFactorConfig `json:"custom_risk_factors"`
	
	// Performance settings
	CacheResults               bool                       `json:"cache_results"`
	CacheTTL                   time.Duration              `json:"cache_ttl"`
	BatchAssessment            bool                       `json:"batch_assessment"`
	AssessmentTimeout          time.Duration              `json:"assessment_timeout"`
}

// RiskFactor represents a risk factor configuration
type RiskFactor struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Enabled     bool    `json:"enabled"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Evaluator   RiskFactorEvaluator
}

// RiskFactorConfig represents risk factor configuration
type RiskFactorConfig struct {
	Weight      float64 `json:"weight"`
	Enabled     bool    `json:"enabled"`
	Description string  `json:"description"`
	Category    string  `json:"category"`
	Conditions  map[string]interface{} `json:"conditions"`
}

// RiskFactorEvaluator evaluates a specific risk factor
type RiskFactorEvaluator func(ctx context.Context, event *entity.Event) (float64, bool)

// RiskAssessmentResult represents the result of risk assessment
type RiskAssessmentResult struct {
	Score              float64             `json:"score"`
	Level              string              `json:"level"`
	Confidence         float64             `json:"confidence"`
	Factors            []AssessedRiskFactor `json:"factors"`
	Reasoning          string              `json:"reasoning"`
	Recommendations    []string            `json:"recommendations"`
	AssessedAt         time.Time           `json:"assessed_at"`
	Method             string              `json:"method"`
}

// AssessedRiskFactor represents an assessed risk factor
type AssessedRiskFactor struct {
	Name         string  `json:"name"`
	Score        float64 `json:"score"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	Triggered    bool    `json:"triggered"`
	Description  string  `json:"description"`
	Category     string  `json:"category"`
}

// NewRiskAssessmentService creates a new risk assessment service
func NewRiskAssessmentService(
	logger *logging.Logger,
	metrics *metrics.Collector,
	config *RiskAssessmentConfig,
) service.RiskAssessmentService {
	if config == nil {
		config = &RiskAssessmentConfig{
			EnableMLModel:              false,
			FallbackToRuleBased:        true,
			ModelTimeout:               5 * time.Second,
			DefaultRiskScore:           3.0,
			MinConfidenceThreshold:     0.5,
			MaxRiskScore:               10.0,
			LowRiskThreshold:           3.0,
			MediumRiskThreshold:        5.0,
			HighRiskThreshold:          7.0,
			CriticalRiskThreshold:      9.0,
			SeverityWeight:             0.3,
			TypeWeight:                 0.2,
			SourceWeight:               0.1,
			TimeWeight:                 0.1,
			FrequencyWeight:            0.1,
			AssetCriticalityWeight:     0.1,
			ThreatIntelWeight:          0.1,
			EnableTimeDecay:            true,
			TimeDecayHalfLife:          24 * time.Hour,
			EnableFrequencyAnalysis:    true,
			FrequencyWindow:            1 * time.Hour,
			EnableAssetContext:         true,
			EnableUserContext:          true,
			CacheResults:               true,
			CacheTTL:                   10 * time.Minute,
			BatchAssessment:            false,
			AssessmentTimeout:          10 * time.Second,
		}
	}

	ras := &RiskAssessmentService{
		logger:  logger,
		metrics: metrics,
		config:  config,
		riskFactors: make(map[string]RiskFactor),
		mlModelEnabled: config.EnableMLModel,
		mlModelEndpoint: config.MLModelEndpoint,
	}

	// Initialize risk factors and weights
	ras.initializeRiskFactors()
	ras.initializeSeverityWeights()
	ras.initializeTypeWeights()
	ras.initializeSourceWeights()

	return ras
}

// CalculateRiskScore calculates the risk score for an event
func (ras *RiskAssessmentService) CalculateRiskScore(ctx context.Context, event *entity.Event) (*service.RiskAssessment, error) {
	start := time.Now()
	defer func() {
		ras.metrics.RecordBusinessOperation("risk_assessment", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Try ML model first if enabled
	if ras.mlModelEnabled && ras.mlModelEndpoint != "" {
		if result, err := ras.calculateMLRiskScore(ctx, event); err == nil {
			return ras.convertToRiskAssessment(result, "ml_model"), nil
		} else {
			ras.logger.Warn("ML model assessment failed, falling back to rule-based",
				logging.String("event_id", event.ID.String()),
				logging.String("error", err.Error()),
			)
		}
	}

	// Fall back to rule-based assessment
	result, err := ras.calculateRuleBasedRiskScore(ctx, event)
	if err != nil {
		return nil, common.WrapError(err, common.ErrCodeInternal, "risk assessment failed")
	}

	return ras.convertToRiskAssessment(result, "rule_based"), nil
}

// Rule-based risk assessment
func (ras *RiskAssessmentService) calculateRuleBasedRiskScore(ctx context.Context, event *entity.Event) (*RiskAssessmentResult, error) {
	var assessedFactors []AssessedRiskFactor
	var totalScore float64
	var totalWeight float64

	// Evaluate base factors
	baseScore, baseFactors := ras.evaluateBaseFactors(event)
	assessedFactors = append(assessedFactors, baseFactors...)
	totalScore += baseScore
	totalWeight += 1.0

	// Evaluate enrichment-based factors
	enrichmentScore, enrichmentFactors := ras.evaluateEnrichmentFactors(event)
	assessedFactors = append(assessedFactors, enrichmentFactors...)
	totalScore += enrichmentScore * ras.config.ThreatIntelWeight
	totalWeight += ras.config.ThreatIntelWeight

	// Evaluate contextual factors
	contextScore, contextFactors := ras.evaluateContextualFactors(ctx, event)
	assessedFactors = append(assessedFactors, contextFactors...)
	totalScore += contextScore * (ras.config.AssetCriticalityWeight + ras.config.FrequencyWeight)
	totalWeight += ras.config.AssetCriticalityWeight + ras.config.FrequencyWeight

	// Evaluate time-based factors
	timeScore, timeFactors := ras.evaluateTimeBasedFactors(event)
	assessedFactors = append(assessedFactors, timeFactors...)
	totalScore += timeScore * ras.config.TimeWeight
	totalWeight += ras.config.TimeWeight

	// Calculate final score
	finalScore := totalScore / totalWeight
	
	// Apply bounds
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > ras.config.MaxRiskScore {
		finalScore = ras.config.MaxRiskScore
	}

	// Determine risk level
	riskLevel := ras.determineRiskLevel(finalScore)

	// Calculate confidence
	confidence := ras.calculateConfidence(assessedFactors)

	// Generate reasoning and recommendations
	reasoning := ras.generateReasoning(assessedFactors, finalScore)
	recommendations := ras.generateRecommendations(event, assessedFactors, finalScore)

	result := &RiskAssessmentResult{
		Score:           finalScore,
		Level:           riskLevel,
		Confidence:      confidence,
		Factors:         assessedFactors,
		Reasoning:       reasoning,
		Recommendations: recommendations,
		AssessedAt:      time.Now().UTC(),
		Method:          "rule_based",
	}

	ras.logger.Debug("Risk assessment completed",
		logging.String("event_id", event.ID.String()),
		logging.Float64("score", finalScore),
		logging.String("level", riskLevel),
		logging.Float64("confidence", confidence),
		logging.Int("factors", len(assessedFactors)),
	)

	return result, nil
}

// Evaluate base factors (severity, type, source)
func (ras *RiskAssessmentService) evaluateBaseFactors(event *entity.Event) (float64, []AssessedRiskFactor) {
	var factors []AssessedRiskFactor
	var totalScore float64

	// Severity factor
	severityScore := ras.evaluateSeverityFactor(event)
	factors = append(factors, AssessedRiskFactor{
		Name:         "severity",
		Score:        severityScore,
		Weight:       ras.config.SeverityWeight,
		Contribution: severityScore * ras.config.SeverityWeight,
		Triggered:    severityScore > 5.0,
		Description:  fmt.Sprintf("Event severity: %s", event.Severity),
		Category:     "base",
	})
	totalScore += severityScore * ras.config.SeverityWeight

	// Event type factor
	typeScore := ras.evaluateTypeFactor(event)
	factors = append(factors, AssessedRiskFactor{
		Name:         "event_type",
		Score:        typeScore,
		Weight:       ras.config.TypeWeight,
		Contribution: typeScore * ras.config.TypeWeight,
		Triggered:    typeScore > 5.0,
		Description:  fmt.Sprintf("Event type: %s", event.Type),
		Category:     "base",
	})
	totalScore += typeScore * ras.config.TypeWeight

	// Source factor
	sourceScore := ras.evaluateSourceFactor(event)
	factors = append(factors, AssessedRiskFactor{
		Name:         "source",
		Score:        sourceScore,
		Weight:       ras.config.SourceWeight,
		Contribution: sourceScore * ras.config.SourceWeight,
		Triggered:    sourceScore > 5.0,
		Description:  fmt.Sprintf("Event source: %s", event.Source),
		Category:     "base",
	})
	totalScore += sourceScore * ras.config.SourceWeight

	return totalScore, factors
}

// Evaluate enrichment-based factors
func (ras *RiskAssessmentService) evaluateEnrichmentFactors(event *entity.Event) (float64, []AssessedRiskFactor) {
	var factors []AssessedRiskFactor
	var totalScore float64

	// Threat intelligence factor
	threatScore, hasThreatIntel := ras.evaluateThreatIntelFactor(event)
	if hasThreatIntel {
		factors = append(factors, AssessedRiskFactor{
			Name:         "threat_intelligence",
			Score:        threatScore,
			Weight:       1.0,
			Contribution: threatScore,
			Triggered:    threatScore > 7.0,
			Description:  "Threat intelligence indicates malicious activity",
			Category:     "enrichment",
		})
		totalScore += threatScore
	}

	// Geo location factor
	geoScore, hasGeoRisk := ras.evaluateGeoLocationFactor(event)
	if hasGeoRisk {
		factors = append(factors, AssessedRiskFactor{
			Name:         "geo_location",
			Score:        geoScore,
			Weight:       0.3,
			Contribution: geoScore * 0.3,
			Triggered:    geoScore > 6.0,
			Description:  "Geographic location indicates elevated risk",
			Category:     "enrichment",
		})
		totalScore += geoScore * 0.3
	}

	return totalScore, factors
}

// Evaluate contextual factors
func (ras *RiskAssessmentService) evaluateContextualFactors(ctx context.Context, event *entity.Event) (float64, []AssessedRiskFactor) {
	var factors []AssessedRiskFactor
	var totalScore float64

	// Asset criticality factor
	if ras.config.EnableAssetContext {
		assetScore, hasAssetContext := ras.evaluateAssetCriticalityFactor(event)
		if hasAssetContext {
			factors = append(factors, AssessedRiskFactor{
				Name:         "asset_criticality",
				Score:        assetScore,
				Weight:       ras.config.AssetCriticalityWeight,
				Contribution: assetScore * ras.config.AssetCriticalityWeight,
				Triggered:    assetScore > 7.0,
				Description:  "High-criticality asset involved",
				Category:     "context",
			})
			totalScore += assetScore * ras.config.AssetCriticalityWeight
		}
	}

	// User context factor
	if ras.config.EnableUserContext {
		userScore, hasUserContext := ras.evaluateUserContextFactor(event)
		if hasUserContext {
			factors = append(factors, AssessedRiskFactor{
				Name:         "user_context",
				Score:        userScore,
				Weight:       0.2,
				Contribution: userScore * 0.2,
				Triggered:    userScore > 6.0,
				Description:  "User context indicates elevated risk",
				Category:     "context",
			})
			totalScore += userScore * 0.2
		}
	}

	// Frequency analysis factor
	if ras.config.EnableFrequencyAnalysis {
		freqScore, hasFreqRisk := ras.evaluateFrequencyFactor(ctx, event)
		if hasFreqRisk {
			factors = append(factors, AssessedRiskFactor{
				Name:         "frequency_analysis",
				Score:        freqScore,
				Weight:       ras.config.FrequencyWeight,
				Contribution: freqScore * ras.config.FrequencyWeight,
				Triggered:    freqScore > 6.0,
				Description:  "Unusual frequency pattern detected",
				Category:     "context",
			})
			totalScore += freqScore * ras.config.FrequencyWeight
		}
	}

	return totalScore, factors
}

// Evaluate time-based factors
func (ras *RiskAssessmentService) evaluateTimeBasedFactors(event *entity.Event) (float64, []AssessedRiskFactor) {
	var factors []AssessedRiskFactor
	var totalScore float64

	// Time-based anomaly factor
	timeScore, hasTimeAnomaly := ras.evaluateTimeAnomalyFactor(event)
	if hasTimeAnomaly {
		factors = append(factors, AssessedRiskFactor{
			Name:         "time_anomaly",
			Score:        timeScore,
			Weight:       ras.config.TimeWeight,
			Contribution: timeScore * ras.config.TimeWeight,
			Triggered:    timeScore > 5.0,
			Description:  "Event occurred at unusual time",
			Category:     "temporal",
		})
		totalScore += timeScore * ras.config.TimeWeight
	}

	// Time decay factor
	if ras.config.EnableTimeDecay {
		decayFactor := ras.calculateTimeDecayFactor(event)
		if decayFactor < 1.0 {
			factors = append(factors, AssessedRiskFactor{
				Name:         "time_decay",
				Score:        (1.0 - decayFactor) * 10.0,
				Weight:       0.1,
				Contribution: (1.0 - decayFactor),
				Triggered:    decayFactor < 0.5,
				Description:  "Event freshness factor",
				Category:     "temporal",
			})
			totalScore *= decayFactor // Apply as multiplier rather than additive
		}
	}

	return totalScore, factors
}

// Individual factor evaluation methods

func (ras *RiskAssessmentService) evaluateSeverityFactor(event *entity.Event) float64 {
	if weight, exists := ras.severityWeights[event.Severity]; exists {
		return weight
	}
	return ras.config.DefaultRiskScore
}

func (ras *RiskAssessmentService) evaluateTypeFactor(event *entity.Event) float64 {
	if weight, exists := ras.typeWeights[event.Type]; exists {
		return weight
	}
	return ras.config.DefaultRiskScore
}

func (ras *RiskAssessmentService) evaluateSourceFactor(event *entity.Event) float64 {
	if weight, exists := ras.sourceWeights[event.Source]; exists {
		return weight
	}
	return ras.config.DefaultRiskScore
}

func (ras *RiskAssessmentService) evaluateThreatIntelFactor(event *entity.Event) (float64, bool) {
	if event.Metadata == nil {
		return 0, false
	}

	// Check for threat intelligence indicators
	if sourceIntel, exists := event.Metadata["source_threat_intel"]; exists {
		if intel, ok := sourceIntel.(map[string]interface{}); ok {
			if isMalicious, ok := intel["is_malicious"].(bool); ok && isMalicious {
				confidence := 0.8 // Default confidence
				if conf, ok := intel["confidence"].(float64); ok {
					confidence = conf
				}
				return 9.0 * confidence, true
			}
		}
	}

	if destIntel, exists := event.Metadata["destination_threat_intel"]; exists {
		if intel, ok := destIntel.(map[string]interface{}); ok {
			if isMalicious, ok := intel["is_malicious"].(bool); ok && isMalicious {
				confidence := 0.8
				if conf, ok := intel["confidence"].(float64); ok {
					confidence = conf
				}
				return 8.0 * confidence, true
			}
		}
	}

	return 0, false
}

func (ras *RiskAssessmentService) evaluateGeoLocationFactor(event *entity.Event) (float64, bool) {
	if event.Metadata == nil {
		return 0, false
	}

	// Check for high-risk countries
	highRiskCountries := []string{"CN", "RU", "KP", "IR"}
	
	if sourceGeo, exists := event.Metadata["source_geo"]; exists {
		if geo, ok := sourceGeo.(map[string]interface{}); ok {
			if countryCode, ok := geo["country_code"].(string); ok {
				for _, riskCountry := range highRiskCountries {
					if countryCode == riskCountry {
						return 7.0, true
					}
				}
			}
		}
	}

	return 0, false
}

func (ras *RiskAssessmentService) evaluateAssetCriticalityFactor(event *entity.Event) (float64, bool) {
	if event.Metadata == nil {
		return 0, false
	}

	if assetEnrichment, exists := event.Metadata["asset_enrichment"]; exists {
		if asset, ok := assetEnrichment.(map[string]interface{}); ok {
			if criticality, ok := asset["criticality"].(string); ok {
				switch strings.ToLower(criticality) {
				case "critical":
					return 9.0, true
				case "high":
					return 7.0, true
				case "medium":
					return 5.0, true
				case "low":
					return 3.0, true
				}
			}
		}
	}

	return 0, false
}

func (ras *RiskAssessmentService) evaluateUserContextFactor(event *entity.Event) (float64, bool) {
	if event.Metadata == nil {
		return 0, false
	}

	if userEnrichment, exists := event.Metadata["user_enrichment"]; exists {
		if user, ok := userEnrichment.(map[string]interface{}); ok {
			// Check for privileged users
			if roles, ok := user["roles"].([]string); ok {
				for _, role := range roles {
					if strings.Contains(strings.ToLower(role), "admin") ||
					   strings.Contains(strings.ToLower(role), "privileged") {
						return 7.0, true
					}
				}
			}
			
			// Check user status
			if status, ok := user["status"].(string); ok {
				if strings.ToLower(status) == "suspended" || strings.ToLower(status) == "disabled" {
					return 8.0, true
				}
			}
		}
	}

	return 0, false
}

func (ras *RiskAssessmentService) evaluateFrequencyFactor(ctx context.Context, event *entity.Event) (float64, bool) {
	// This would require access to historical data - simplified for now
	// In practice, would query repository for similar events in time window
	return 0, false
}

func (ras *RiskAssessmentService) evaluateTimeAnomalyFactor(event *entity.Event) (float64, bool) {
	// Check if event occurred outside business hours
	hour := event.OccurredAt.Hour()
	if hour < 6 || hour > 22 { // Outside 6 AM - 10 PM
		return 6.0, true
	}

	// Check if event occurred on weekend
	weekday := event.OccurredAt.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return 5.0, true
	}

	return 0, false
}

func (ras *RiskAssessmentService) calculateTimeDecayFactor(event *entity.Event) float64 {
	if !ras.config.EnableTimeDecay {
		return 1.0
	}

	elapsed := time.Since(event.OccurredAt)
	halfLife := ras.config.TimeDecayHalfLife
	
	// Exponential decay: factor = 0.5^(elapsed/halfLife)
	decayFactor := math.Pow(0.5, elapsed.Seconds()/halfLife.Seconds())
	
	// Ensure minimum factor
	if decayFactor < 0.1 {
		decayFactor = 0.1
	}
	
	return decayFactor
}

func (ras *RiskAssessmentService) determineRiskLevel(score float64) string {
	if score >= ras.config.CriticalRiskThreshold {
		return "critical"
	} else if score >= ras.config.HighRiskThreshold {
		return "high"
	} else if score >= ras.config.MediumRiskThreshold {
		return "medium"
	} else if score >= ras.config.LowRiskThreshold {
		return "low"
	}
	return "info"
}

func (ras *RiskAssessmentService) calculateConfidence(factors []AssessedRiskFactor) float64 {
	if len(factors) == 0 {
		return ras.config.MinConfidenceThreshold
	}

	// Base confidence on number and quality of factors
	baseConfidence := 0.5
	
	// Increase confidence based on number of triggered factors
	triggeredCount := 0
	for _, factor := range factors {
		if factor.Triggered {
			triggeredCount++
		}
	}
	
	confidenceBoost := float64(triggeredCount) * 0.1
	finalConfidence := baseConfidence + confidenceBoost
	
	if finalConfidence > 1.0 {
		finalConfidence = 1.0
	}
	
	return finalConfidence
}

func (ras *RiskAssessmentService) generateReasoning(factors []AssessedRiskFactor, score float64) string {
	var reasons []string
	
	for _, factor := range factors {
		if factor.Triggered && factor.Contribution > 1.0 {
			reasons = append(reasons, factor.Description)
		}
	}
	
	if len(reasons) == 0 {
		return fmt.Sprintf("Risk score %.2f based on standard factors", score)
	}
	
	return fmt.Sprintf("Risk score %.2f due to: %s", score, strings.Join(reasons, "; "))
}

func (ras *RiskAssessmentService) generateRecommendations(event *entity.Event, factors []AssessedRiskFactor, score float64) []string {
	var recommendations []string
	
	if score >= ras.config.CriticalRiskThreshold {
		recommendations = append(recommendations, "Immediate investigation required")
		recommendations = append(recommendations, "Consider isolating affected assets")
		recommendations = append(recommendations, "Escalate to security team")
	} else if score >= ras.config.HighRiskThreshold {
		recommendations = append(recommendations, "Priority investigation recommended")
		recommendations = append(recommendations, "Review related events")
	} else if score >= ras.config.MediumRiskThreshold {
		recommendations = append(recommendations, "Monitor for related activity")
		recommendations = append(recommendations, "Review security controls")
	}
	
	// Factor-specific recommendations
	for _, factor := range factors {
		if factor.Triggered {
			switch factor.Name {
			case "threat_intelligence":
				recommendations = append(recommendations, "Block malicious indicators")
			case "asset_criticality":
				recommendations = append(recommendations, "Verify asset security posture")
			case "user_context":
				recommendations = append(recommendations, "Review user access and behavior")
			case "geo_location":
				recommendations = append(recommendations, "Consider geo-blocking")
			}
		}
	}
	
	return recommendations
}

// ML model assessment (placeholder)
func (ras *RiskAssessmentService) calculateMLRiskScore(ctx context.Context, event *entity.Event) (*RiskAssessmentResult, error) {
	// This would call an ML model endpoint
	// For now, return an error to fall back to rule-based
	return nil, fmt.Errorf("ML model not implemented")
}

func (ras *RiskAssessmentService) convertToRiskAssessment(result *RiskAssessmentResult, method string) *service.RiskAssessment {
	factors := make([]service.RiskFactor, len(result.Factors))
	for i, factor := range result.Factors {
		factors[i] = service.RiskFactor{
			Name:         factor.Name,
			Score:        factor.Score,
			Weight:       factor.Weight,
			Contribution: factor.Contribution,
		}
	}

	return &service.RiskAssessment{
		Score:      result.Score,
		Level:      result.Level,
		Confidence: result.Confidence,
		Factors:    factors,
		Method:     method,
		AssessedAt: result.AssessedAt,
	}
}

// Initialize methods

func (ras *RiskAssessmentService) initializeRiskFactors() {
	ras.riskFactors["severity"] = RiskFactor{
		Name:        "severity",
		Weight:      ras.config.SeverityWeight,
		Enabled:     true,
		Description: "Event severity level",
		Category:    "base",
		Evaluator:   func(ctx context.Context, event *entity.Event) (float64, bool) {
			return ras.evaluateSeverityFactor(event), true
		},
	}
	
	// Add more risk factors as needed
}

func (ras *RiskAssessmentService) initializeSeverityWeights() {
	ras.severityWeights = map[types.Severity]float64{
		types.SeverityInfo:     1.0,
		types.SeverityLow:      3.0,
		types.SeverityMedium:   5.0,
		types.SeverityHigh:     7.0,
		types.SeverityCritical: 9.0,
	}
}

func (ras *RiskAssessmentService) initializeTypeWeights() {
	ras.typeWeights = map[types.EventType]float64{
		types.EventTypeAuthentication:  6.0,
		types.EventTypeAuthorization:   5.0,
		types.EventTypeNetworkAccess:   4.0,
		types.EventTypeThreatDetection: 8.0,
		types.EventTypeVulnerability:   7.0,
		types.EventTypeCompliance:      3.0,
		types.EventTypeAssetDiscovery:  2.0,
		types.EventTypeSystemHealth:    2.0,
		types.EventTypeUserActivity:    4.0,
		types.EventTypeDataAccess:      6.0,
	}
}

func (ras *RiskAssessmentService) initializeSourceWeights() {
	ras.sourceWeights = map[string]float64{
		"firewall":        5.0,
		"ids":            7.0,
		"antivirus":      6.0,
		"siem":           4.0,
		"endpoint":       5.0,
		"network":        4.0,
		"application":    3.0,
		"database":       6.0,
		"authentication": 7.0,
		"web_proxy":      4.0,
	}
}