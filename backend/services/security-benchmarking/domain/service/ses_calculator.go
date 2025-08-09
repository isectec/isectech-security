package service

import (
	"context"
	"fmt"
	"math"
	"time"
	"log/slog"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-benchmarking/domain/entity"
)

// SESCalculatorService handles Security Effectiveness Score calculations
type SESCalculatorService struct {
	logger          *slog.Logger
	metricCollector MetricCollector
	predictionModel PredictionModel
	targetAnalyzer  TargetAnalyzer
}

// MetricCollector interface for collecting security metrics
type MetricCollector interface {
	CollectThreatMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*ThreatMetrics, error)
	CollectIncidentMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*IncidentMetrics, error)
	CollectResponseMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*ResponseMetrics, error)
	CollectPreventionMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (*PreventionMetrics, error)
	CollectComponentMetrics(ctx context.Context, tenantID uuid.UUID, timeWindow time.Duration) (map[string]*ComponentMetrics, error)
}

// PredictionModel interface for predictive analytics
type PredictionModel interface {
	PredictScore(ctx context.Context, historicalScores []float64, features map[string]interface{}) (*entity.ScorePrediction, error)
	AnalyzeTrends(ctx context.Context, scores []entity.ScoreHistory) (entity.TrendDirection, error)
	CalculateConfidence(ctx context.Context, prediction float64, historicalData []float64) (float64, error)
}

// TargetAnalyzer interface for target analysis
type TargetAnalyzer interface {
	AnalyzeTargetAchievability(ctx context.Context, currentScore, targetScore float64, timeframe time.Duration) (*TargetAnalysis, error)
	RecommendActions(ctx context.Context, currentScore, targetScore float64, componentScores map[string]float64) ([]string, error)
	EstimateTimeToTarget(ctx context.Context, currentScore, targetScore float64, improvementRate float64) (time.Duration, error)
}

// Metric structures
type ThreatMetrics struct {
	TotalThreats      int64   `json:"total_threats"`
	BlockedThreats    int64   `json:"blocked_threats"`
	MissedThreats     int64   `json:"missed_threats"`
	FalsePositives    int64   `json:"false_positives"`
	BlockingRate      float64 `json:"blocking_rate"`
	AccuracyRate      float64 `json:"accuracy_rate"`
	AverageResponseTime time.Duration `json:"average_response_time"`
}

type IncidentMetrics struct {
	TotalIncidents       int64         `json:"total_incidents"`
	ResolvedIncidents    int64         `json:"resolved_incidents"`
	CriticalIncidents    int64         `json:"critical_incidents"`
	AverageResolutionTime time.Duration `json:"average_resolution_time"`
	AverageImpactScore   float64       `json:"average_impact_score"`
	RecurringIncidents   int64         `json:"recurring_incidents"`
}

type ResponseMetrics struct {
	AverageDetectionTime   time.Duration `json:"average_detection_time"`
	AverageContainmentTime time.Duration `json:"average_containment_time"`
	AverageRecoveryTime    time.Duration `json:"average_recovery_time"`
	AlertVolumeReduction   float64       `json:"alert_volume_reduction"`
	AutomationRate         float64       `json:"automation_rate"`
}

type PreventionMetrics struct {
	VulnerabilitiesFound    int64   `json:"vulnerabilities_found"`
	VulnerabilitiesPatched  int64   `json:"vulnerabilities_patched"`
	PatchingRate            float64 `json:"patching_rate"`
	MeanTimeToRemediation   time.Duration `json:"mean_time_to_remediation"`
	PreventedAttacks        int64   `json:"prevented_attacks"`
	PreventionEffectiveness float64 `json:"prevention_effectiveness"`
}

type ComponentMetrics struct {
	ComponentType   entity.ComponentType `json:"component_type"`
	AvailabilityRate float64             `json:"availability_rate"`
	PerformanceScore float64             `json:"performance_score"`
	EffectivenessRate float64            `json:"effectiveness_rate"`
	ConfigurationScore float64           `json:"configuration_score"`
	UpdateStatus     string              `json:"update_status"`
}

type TargetAnalysis struct {
	IsAchievable        bool          `json:"is_achievable"`
	Reason              string        `json:"reason"`
	RequiredImprovement float64       `json:"required_improvement"`
	EstimatedTimeframe  time.Duration `json:"estimated_timeframe"`
	RecommendedActions  []string      `json:"recommended_actions"`
	RiskFactors         []entity.RiskFactor `json:"risk_factors"`
}

// NewSESCalculatorService creates a new SES calculator service
func NewSESCalculatorService(logger *slog.Logger, collector MetricCollector, model PredictionModel, analyzer TargetAnalyzer) *SESCalculatorService {
	return &SESCalculatorService{
		logger:          logger,
		metricCollector: collector,
		predictionModel: model,
		targetAnalyzer:  analyzer,
	}
}

// CalculateSecurityEffectivenessScore calculates the comprehensive SES
func (s *SESCalculatorService) CalculateSecurityEffectivenessScore(ctx context.Context, tenantID, organizationID uuid.UUID, timeWindow time.Duration) (*entity.SecurityEffectivenessScore, error) {
	s.logger.Info("Starting SES calculation", 
		"tenant_id", tenantID, 
		"organization_id", organizationID,
		"time_window", timeWindow)

	score := entity.NewSecurityEffectivenessScore(tenantID, organizationID)
	score.TimeWindow = timeWindow

	// Collect all metrics
	threatMetrics, err := s.metricCollector.CollectThreatMetrics(ctx, tenantID, timeWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to collect threat metrics: %w", err)
	}

	incidentMetrics, err := s.metricCollector.CollectIncidentMetrics(ctx, tenantID, timeWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to collect incident metrics: %w", err)
	}

	responseMetrics, err := s.metricCollector.CollectResponseMetrics(ctx, tenantID, timeWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to collect response metrics: %w", err)
	}

	preventionMetrics, err := s.metricCollector.CollectPreventionMetrics(ctx, tenantID, timeWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to collect prevention metrics: %w", err)
	}

	componentMetrics, err := s.metricCollector.CollectComponentMetrics(ctx, tenantID, timeWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to collect component metrics: %w", err)
	}

	// Calculate individual component scores
	score.ThreatBlockingScore = s.calculateThreatBlockingScore(threatMetrics)
	score.IncidentImpactScore = s.calculateIncidentImpactScore(incidentMetrics)
	score.ResponseEfficiency = s.calculateResponseEfficiencyScore(responseMetrics)
	score.PreventionEffectiveness = s.calculatePreventionEffectivenessScore(preventionMetrics)

	// Calculate component scores
	score.ComponentScores = s.calculateComponentScores(componentMetrics)

	// Calculate overall score
	score.OverallScore = s.calculateOverallScore(score)

	// Calculate confidence level
	score.ConfidenceLevel = s.calculateConfidenceLevel(threatMetrics, incidentMetrics, responseMetrics, preventionMetrics)

	// Perform predictive analytics
	if err := s.performPredictiveAnalysis(ctx, score); err != nil {
		s.logger.Warn("Failed to perform predictive analysis", "error", err)
	}

	// Analyze targets
	if err := s.analyzeTargets(ctx, score); err != nil {
		s.logger.Warn("Failed to analyze targets", "error", err)
	}

	s.logger.Info("SES calculation completed", 
		"overall_score", score.OverallScore,
		"confidence_level", score.ConfidenceLevel)

	return score, nil
}

// calculateThreatBlockingScore calculates the threat blocking effectiveness score
func (s *SESCalculatorService) calculateThreatBlockingScore(metrics *ThreatMetrics) float64 {
	if metrics.TotalThreats == 0 {
		return 100.0 // No threats detected, perfect score
	}

	// Calculate basic blocking rate (0-60 points)
	blockingScore := metrics.BlockingRate * 60

	// Add accuracy bonus (0-25 points)
	accuracyBonus := metrics.AccuracyRate * 25

	// Add response time bonus (0-15 points)
	responseTimeBonus := s.calculateResponseTimeBonus(metrics.AverageResponseTime)

	totalScore := blockingScore + accuracyBonus + responseTimeBonus

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}

	return math.Round(totalScore*100) / 100
}

// calculateIncidentImpactScore calculates the incident impact score
func (s *SESCalculatorService) calculateIncidentImpactScore(metrics *IncidentMetrics) float64 {
	if metrics.TotalIncidents == 0 {
		return 100.0 // No incidents, perfect score
	}

	// Base score starts at 100 and decreases based on incidents
	baseScore := 100.0

	// Deduct points for critical incidents (up to -40 points)
	criticalPenalty := float64(metrics.CriticalIncidents) / float64(metrics.TotalIncidents) * 40

	// Deduct points for resolution time (up to -30 points)
	resolutionPenalty := s.calculateResolutionTimePenalty(metrics.AverageResolutionTime)

	// Deduct points for impact severity (up to -20 points)
	impactPenalty := (metrics.AverageImpactScore / 10.0) * 20

	// Deduct points for recurring incidents (up to -10 points)
	recurringPenalty := float64(metrics.RecurringIncidents) / float64(metrics.TotalIncidents) * 10

	totalScore := baseScore - criticalPenalty - resolutionPenalty - impactPenalty - recurringPenalty

	// Ensure minimum score of 0
	if totalScore < 0 {
		totalScore = 0
	}

	return math.Round(totalScore*100) / 100
}

// calculateResponseEfficiencyScore calculates the response efficiency score
func (s *SESCalculatorService) calculateResponseEfficiencyScore(metrics *ResponseMetrics) float64 {
	// Detection speed (0-30 points)
	detectionScore := s.calculateTimeScore(metrics.AverageDetectionTime, 30*time.Minute, 30)

	// Containment speed (0-30 points)
	containmentScore := s.calculateTimeScore(metrics.AverageContainmentTime, 2*time.Hour, 30)

	// Recovery speed (0-25 points)
	recoveryScore := s.calculateTimeScore(metrics.AverageRecoveryTime, 24*time.Hour, 25)

	// Automation rate (0-15 points)
	automationScore := metrics.AutomationRate * 15

	totalScore := detectionScore + containmentScore + recoveryScore + automationScore

	return math.Round(totalScore*100) / 100
}

// calculatePreventionEffectivenessScore calculates the prevention effectiveness score
func (s *SESCalculatorService) calculatePreventionEffectivenessScore(metrics *PreventionMetrics) float64 {
	// Patching rate (0-40 points)
	patchingScore := metrics.PatchingRate * 40

	// Prevention effectiveness (0-30 points)
	preventionScore := metrics.PreventionEffectiveness * 30

	// Time to remediation (0-20 points)
	remediationScore := s.calculateTimeScore(metrics.MeanTimeToRemediation, 7*24*time.Hour, 20)

	// Prevented attacks bonus (0-10 points)
	preventedBonus := math.Min(float64(metrics.PreventedAttacks)/10.0, 1.0) * 10

	totalScore := patchingScore + preventionScore + remediationScore + preventedBonus

	return math.Round(totalScore*100) / 100
}

// calculateComponentScores calculates individual component scores
func (s *SESCalculatorService) calculateComponentScores(componentMetrics map[string]*ComponentMetrics) map[string]float64 {
	scores := make(map[string]float64)

	for componentName, metrics := range componentMetrics {
		// Availability (25%)
		availabilityScore := metrics.AvailabilityRate * 25

		// Performance (25%)
		performanceScore := metrics.PerformanceScore * 25

		// Effectiveness (30%)
		effectivenessScore := metrics.EffectivenessRate * 30

		// Configuration (20%)
		configScore := metrics.ConfigurationScore * 20

		totalScore := availabilityScore + performanceScore + effectivenessScore + configScore
		scores[componentName] = math.Round(totalScore*100) / 100
	}

	return scores
}

// calculateOverallScore calculates the weighted overall score
func (s *SESCalculatorService) calculateOverallScore(score *entity.SecurityEffectivenessScore) float64 {
	weightedSum := 0.0
	totalWeight := 0.0

	// Core component weights
	coreWeights := map[string]float64{
		"threat_blocking":        0.25,
		"incident_impact":        0.20,
		"response_efficiency":    0.20,
		"prevention_effectiveness": 0.15,
	}

	// Add core component scores
	weightedSum += score.ThreatBlockingScore * coreWeights["threat_blocking"]
	weightedSum += score.IncidentImpactScore * coreWeights["incident_impact"]
	weightedSum += score.ResponseEfficiency * coreWeights["response_efficiency"]
	weightedSum += score.PreventionEffectiveness * coreWeights["prevention_effectiveness"]

	totalWeight += coreWeights["threat_blocking"] + coreWeights["incident_impact"] + 
		coreWeights["response_efficiency"] + coreWeights["prevention_effectiveness"]

	// Add individual component scores with remaining weight
	remainingWeight := 1.0 - totalWeight
	if len(score.ComponentScores) > 0 {
		componentWeight := remainingWeight / float64(len(score.ComponentScores))
		for _, componentScore := range score.ComponentScores {
			weightedSum += componentScore * componentWeight
		}
	}

	return math.Round(weightedSum*100) / 100
}

// calculateConfidenceLevel calculates the confidence level for the score
func (s *SESCalculatorService) calculateConfidenceLevel(threatMetrics *ThreatMetrics, incidentMetrics *IncidentMetrics, responseMetrics *ResponseMetrics, preventionMetrics *PreventionMetrics) float64 {
	confidence := 1.0

	// Reduce confidence based on data volume (more data = higher confidence)
	if threatMetrics.TotalThreats < 100 {
		confidence *= 0.8
	}
	if incidentMetrics.TotalIncidents < 10 {
		confidence *= 0.9
	}

	// Reduce confidence based on data quality indicators
	if threatMetrics.FalsePositives > threatMetrics.BlockedThreats/10 {
		confidence *= 0.85 // High false positive rate reduces confidence
	}

	// Adjust based on metric completeness
	metricCompleteness := s.calculateMetricCompleteness(threatMetrics, incidentMetrics, responseMetrics, preventionMetrics)
	confidence *= metricCompleteness

	return math.Round(confidence*100) / 100
}

// Helper methods

func (s *SESCalculatorService) calculateResponseTimeBonus(responseTime time.Duration) float64 {
	// Perfect response time (< 1 minute) = 15 points
	// Good response time (< 5 minutes) = 10 points
	// Acceptable response time (< 15 minutes) = 5 points
	// Poor response time (> 15 minutes) = 0 points

	if responseTime < time.Minute {
		return 15.0
	} else if responseTime < 5*time.Minute {
		return 10.0
	} else if responseTime < 15*time.Minute {
		return 5.0
	}
	return 0.0
}

func (s *SESCalculatorService) calculateResolutionTimePenalty(resolutionTime time.Duration) float64 {
	// Penalties based on resolution time
	if resolutionTime > 7*24*time.Hour { // > 1 week
		return 30.0
	} else if resolutionTime > 24*time.Hour { // > 1 day
		return 20.0
	} else if resolutionTime > 4*time.Hour { // > 4 hours
		return 10.0
	}
	return 0.0
}

func (s *SESCalculatorService) calculateTimeScore(actualTime, targetTime time.Duration, maxPoints float64) float64 {
	if actualTime <= targetTime {
		return maxPoints
	}

	// Exponential decay for times over target
	ratio := float64(actualTime) / float64(targetTime)
	score := maxPoints * math.Exp(-ratio+1)

	return math.Round(score*100) / 100
}

func (s *SESCalculatorService) calculateMetricCompleteness(threatMetrics *ThreatMetrics, incidentMetrics *IncidentMetrics, responseMetrics *ResponseMetrics, preventionMetrics *PreventionMetrics) float64 {
	completeness := 0.0
	totalMetrics := 4.0

	if threatMetrics != nil && threatMetrics.TotalThreats > 0 {
		completeness += 1.0
	}
	if incidentMetrics != nil {
		completeness += 1.0
	}
	if responseMetrics != nil {
		completeness += 1.0
	}
	if preventionMetrics != nil {
		completeness += 1.0
	}

	return completeness / totalMetrics
}

// performPredictiveAnalysis performs predictive analytics on the score
func (s *SESCalculatorService) performPredictiveAnalysis(ctx context.Context, score *entity.SecurityEffectivenessScore) error {
	// This would integrate with ML models for predictions
	// For now, we'll implement basic trend analysis
	
	// Get historical scores (this would come from a repository)
	historicalScores := []float64{} // Placeholder
	
	if len(historicalScores) > 0 {
		features := map[string]interface{}{
			"current_score": score.OverallScore,
			"component_scores": score.ComponentScores,
			"time_window": score.TimeWindow.String(),
		}
		
		prediction, err := s.predictionModel.PredictScore(ctx, historicalScores, features)
		if err != nil {
			return fmt.Errorf("failed to predict score: %w", err)
		}
		
		score.PredictedScore = &prediction.PredictedScore
		score.PredictionHorizon = prediction.PredictionHorizon
		score.PredictionConfidence = prediction.ConfidenceInterval.Confidence
	}
	
	return nil
}

// analyzeTargets analyzes target achievability
func (s *SESCalculatorService) analyzeTargets(ctx context.Context, score *entity.SecurityEffectivenessScore) error {
	if score.TargetScore > 0 {
		analysis, err := s.targetAnalyzer.AnalyzeTargetAchievability(ctx, score.OverallScore, score.TargetScore, time.Until(*score.TargetDate))
		if err != nil {
			return fmt.Errorf("failed to analyze target achievability: %w", err)
		}
		
		score.IsTargetAchievable = analysis.IsAchievable
	}
	
	return nil
}