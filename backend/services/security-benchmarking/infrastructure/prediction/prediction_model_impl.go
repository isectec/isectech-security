package prediction

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-benchmarking/domain/entity"
)

// DefaultPredictionModel implements the PredictionModel interface
type DefaultPredictionModel struct {
	logger *slog.Logger
}

// NewDefaultPredictionModel creates a new default prediction model
func NewDefaultPredictionModel(logger *slog.Logger) *DefaultPredictionModel {
	return &DefaultPredictionModel{
		logger: logger,
	}
}

// PredictScore predicts future security effectiveness scores using historical data and features
func (m *DefaultPredictionModel) PredictScore(ctx context.Context, historicalScores []float64, features map[string]interface{}) (*entity.ScorePrediction, error) {
	m.logger.Info("Predicting security score", "historical_data_points", len(historicalScores))

	if len(historicalScores) < 3 {
		return nil, fmt.Errorf("insufficient historical data: need at least 3 data points, got %d", len(historicalScores))
	}

	prediction := &entity.ScorePrediction{
		ID:                  uuid.New(),
		PredictionTimestamp: time.Now(),
		PredictionHorizon:   30 * 24 * time.Hour, // 30 days default
		ModelType:           entity.ModelEnsemble,
		ModelVersion:        "v1.0.0",
		InputFeatures:       features,
		CreatedAt:           time.Now(),
	}

	// Apply multiple prediction methods and ensemble them
	predictions := make([]float64, 0, 4)
	confidences := make([]float64, 0, 4)

	// Method 1: Linear trend analysis
	if linearPrediction, confidence := m.predictLinearTrend(historicalScores); confidence > 0.3 {
		predictions = append(predictions, linearPrediction)
		confidences = append(confidences, confidence)
	}

	// Method 2: Exponential smoothing
	if expPrediction, confidence := m.predictExponentialSmoothing(historicalScores); confidence > 0.3 {
		predictions = append(predictions, expPrediction)
		confidences = append(confidences, confidence)
	}

	// Method 3: Moving average with trend
	if maPrediction, confidence := m.predictMovingAverageTrend(historicalScores); confidence > 0.3 {
		predictions = append(predictions, maPrediction)
		confidences = append(confidences, confidence)
	}

	// Method 4: Feature-based adjustment
	if featurePrediction, confidence := m.predictWithFeatures(historicalScores, features); confidence > 0.3 {
		predictions = append(predictions, featurePrediction)
		confidences = append(confidences, confidence)
	}

	if len(predictions) == 0 {
		return nil, fmt.Errorf("all prediction methods failed to generate reliable predictions")
	}

	// Ensemble prediction using weighted average
	prediction.PredictedScore = m.calculateWeightedAverage(predictions, confidences)
	
	// Calculate confidence interval
	prediction.ConfidenceInterval = m.calculateConfidenceInterval(predictions, confidences)

	// Generate risk factors
	prediction.RiskFactors = m.identifyRiskFactors(historicalScores, features)

	// Generate assumptions
	prediction.Assumptions = m.generateAssumptions(historicalScores, features)

	m.logger.Info("Score prediction completed", 
		"predicted_score", prediction.PredictedScore,
		"confidence", prediction.ConfidenceInterval.Confidence,
		"methods_used", len(predictions))

	return prediction, nil
}

// AnalyzeTrends analyzes historical score trends
func (m *DefaultPredictionModel) AnalyzeTrends(ctx context.Context, scores []entity.ScoreHistory) (entity.TrendDirection, error) {
	if len(scores) < 2 {
		return entity.TrendUnknown, fmt.Errorf("insufficient data for trend analysis: need at least 2 data points")
	}

	// Sort scores by timestamp
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Timestamp.Before(scores[j].Timestamp)
	})

	// Extract score values
	values := make([]float64, len(scores))
	for i, score := range scores {
		values[i] = score.HistoricalScore
	}

	// Calculate trend metrics
	trend := m.calculateTrendDirection(values)
	volatility := m.calculateVolatility(values)

	// Determine overall trend direction
	if volatility > 15.0 { // High volatility threshold
		return entity.TrendVolatile, nil
	}

	if math.Abs(trend) < 0.5 { // Stable threshold
		return entity.TrendStable, nil
	}

	if trend > 0 {
		return entity.TrendImproving, nil
	}

	return entity.TrendDeclining, nil
}

// CalculateConfidence calculates prediction confidence based on historical data quality
func (m *DefaultPredictionModel) CalculateConfidence(ctx context.Context, prediction float64, historicalData []float64) (float64, error) {
	if len(historicalData) == 0 {
		return 0.0, fmt.Errorf("no historical data provided")
	}

	confidence := 1.0

	// Factor 1: Data volume (more data = higher confidence)
	dataVolumeFactor := math.Min(float64(len(historicalData))/20.0, 1.0) // Max confidence at 20+ data points
	confidence *= 0.3 + (0.7 * dataVolumeFactor)

	// Factor 2: Data consistency (lower variance = higher confidence)
	variance := m.calculateVariance(historicalData)
	consistencyFactor := math.Exp(-variance / 100.0) // Exponential decay with variance
	confidence *= 0.5 + (0.5 * consistencyFactor)

	// Factor 3: Prediction reasonableness (prediction within reasonable bounds)
	mean := m.calculateMean(historicalData)
	stdDev := math.Sqrt(variance)
	deviationFromMean := math.Abs(prediction - mean)
	
	if deviationFromMean > 3*stdDev {
		confidence *= 0.5 // Significantly reduce confidence for outlier predictions
	} else if deviationFromMean > 2*stdDev {
		confidence *= 0.7
	}

	// Factor 4: Trend stability
	trendStability := m.calculateTrendStability(historicalData)
	confidence *= 0.6 + (0.4 * trendStability)

	// Ensure confidence is between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	} else if confidence < 0.1 {
		confidence = 0.1 // Minimum confidence
	}

	return confidence, nil
}

// Prediction methods

func (m *DefaultPredictionModel) predictLinearTrend(historicalScores []float64) (float64, float64) {
	n := len(historicalScores)
	if n < 2 {
		return 0, 0
	}

	// Simple linear regression
	var sumX, sumY, sumXY, sumXX float64
	for i, score := range historicalScores {
		x := float64(i)
		sumX += x
		sumY += score
		sumXY += x * score
		sumXX += x * x
	}

	// Calculate slope and intercept
	slope := (float64(n)*sumXY - sumX*sumY) / (float64(n)*sumXX - sumX*sumX)
	intercept := (sumY - slope*sumX) / float64(n)

	// Predict next value
	nextX := float64(n)
	prediction := slope*nextX + intercept

	// Calculate R-squared for confidence
	meanY := sumY / float64(n)
	var ssRes, ssTot float64
	for i, score := range historicalScores {
		predicted := slope*float64(i) + intercept
		ssRes += math.Pow(score-predicted, 2)
		ssTot += math.Pow(score-meanY, 2)
	}

	rSquared := 1 - (ssRes / ssTot)
	confidence := math.Max(0, rSquared) // R-squared as confidence measure

	// Ensure prediction is within reasonable bounds
	prediction = math.Max(0, math.Min(100, prediction))

	return prediction, confidence
}

func (m *DefaultPredictionModel) predictExponentialSmoothing(historicalScores []float64) (float64, float64) {
	if len(historicalScores) == 0 {
		return 0, 0
	}

	alpha := 0.3 // Smoothing parameter
	smoothed := historicalScores[0]

	// Apply exponential smoothing
	for i := 1; i < len(historicalScores); i++ {
		smoothed = alpha*historicalScores[i] + (1-alpha)*smoothed
	}

	// Calculate confidence based on how well smoothing fits the data
	var totalError float64
	smoothedValue := historicalScores[0]
	for i := 1; i < len(historicalScores); i++ {
		smoothedValue = alpha*historicalScores[i] + (1-alpha)*smoothedValue
		error := math.Abs(historicalScores[i] - smoothedValue)
		totalError += error
	}

	avgError := totalError / float64(len(historicalScores)-1)
	confidence := math.Exp(-avgError / 20.0) // Exponential decay with error

	return smoothed, confidence
}

func (m *DefaultPredictionModel) predictMovingAverageTrend(historicalScores []float64) (float64, float64) {
	n := len(historicalScores)
	if n < 3 {
		return 0, 0
	}

	// Use last 5 values or all available if less than 5
	window := 5
	if n < window {
		window = n
	}

	// Calculate moving average
	var sum float64
	for i := n - window; i < n; i++ {
		sum += historicalScores[i]
	}
	movingAvg := sum / float64(window)

	// Calculate trend from the moving average period
	if window < 2 {
		return movingAvg, 0.5
	}

	var trendSum float64
	for i := 1; i < window; i++ {
		idx := n - window + i
		trendSum += historicalScores[idx] - historicalScores[idx-1]
	}
	avgTrend := trendSum / float64(window-1)

	prediction := movingAvg + avgTrend

	// Calculate confidence based on trend consistency
	var trendVariance float64
	for i := 1; i < window; i++ {
		idx := n - window + i
		trend := historicalScores[idx] - historicalScores[idx-1]
		trendVariance += math.Pow(trend-avgTrend, 2)
	}
	trendVariance /= float64(window - 1)

	confidence := math.Exp(-trendVariance / 10.0)

	// Ensure prediction is within bounds
	prediction = math.Max(0, math.Min(100, prediction))

	return prediction, confidence
}

func (m *DefaultPredictionModel) predictWithFeatures(historicalScores []float64, features map[string]interface{}) (float64, float64) {
	if len(historicalScores) == 0 {
		return 0, 0
	}

	basePrediction := historicalScores[len(historicalScores)-1]
	adjustment := 0.0
	confidence := 0.5

	// Analyze component scores for feature-based adjustments
	if componentScores, ok := features["component_scores"].(map[string]float64); ok {
		var totalScore, count float64
		for _, score := range componentScores {
			totalScore += score
			count++
		}
		if count > 0 {
			avgComponentScore := totalScore / count
			// Adjust prediction based on component performance
			adjustment += (avgComponentScore - basePrediction) * 0.3
			confidence += 0.2
		}
	}

	// Consider threat landscape features
	if threatLevel, ok := features["threat_level"].(string); ok {
		switch threatLevel {
		case "high":
			adjustment -= 5.0
		case "critical":
			adjustment -= 10.0
		case "low":
			adjustment += 2.0
		}
		confidence += 0.1
	}

	// Consider compliance status
	if complianceScore, ok := features["compliance_score"].(float64); ok {
		complianceAdjustment := (complianceScore - 80.0) * 0.1 // Baseline at 80%
		adjustment += complianceAdjustment
		confidence += 0.15
	}

	prediction := basePrediction + adjustment

	// Ensure prediction is within bounds
	prediction = math.Max(0, math.Min(100, prediction))

	// Cap confidence
	confidence = math.Min(1.0, confidence)

	return prediction, confidence
}

// Helper methods

func (m *DefaultPredictionModel) calculateWeightedAverage(predictions, confidences []float64) float64 {
	if len(predictions) != len(confidences) || len(predictions) == 0 {
		return 0
	}

	var weightedSum, totalWeight float64
	for i, prediction := range predictions {
		weight := confidences[i]
		weightedSum += prediction * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return m.calculateMean(predictions)
	}

	return weightedSum / totalWeight
}

func (m *DefaultPredictionModel) calculateConfidenceInterval(predictions, confidences []float64) entity.ConfidenceInterval {
	if len(predictions) == 0 {
		return entity.ConfidenceInterval{Lower: 0, Upper: 0, Confidence: 0}
	}

	// Calculate weighted average confidence
	avgConfidence := m.calculateMean(confidences)

	// Calculate prediction variance
	mean := m.calculateMean(predictions)
	variance := m.calculateVariance(predictions)
	stdDev := math.Sqrt(variance)

	// Calculate confidence interval (95% confidence level)
	margin := 1.96 * stdDev // 95% confidence interval
	
	lower := math.Max(0, mean-margin)
	upper := math.Min(100, mean+margin)

	return entity.ConfidenceInterval{
		Lower:      lower,
		Upper:      upper,
		Confidence: avgConfidence,
	}
}

func (m *DefaultPredictionModel) identifyRiskFactors(historicalScores []float64, features map[string]interface{}) []entity.RiskFactor {
	riskFactors := []entity.RiskFactor{}

	// High volatility risk
	volatility := m.calculateVolatility(historicalScores)
	if volatility > 15.0 {
		riskFactors = append(riskFactors, entity.RiskFactor{
			Name:        "High Score Volatility",
			Category:    "performance",
			Impact:      -10.0,
			Probability: 0.7,
			Description: fmt.Sprintf("Score volatility is %.1f%%, indicating unstable security posture", volatility),
		})
	}

	// Declining trend risk
	trend := m.calculateTrendDirection(historicalScores)
	if trend < -1.0 {
		riskFactors = append(riskFactors, entity.RiskFactor{
			Name:        "Declining Security Trend",
			Category:    "trend",
			Impact:      -15.0,
			Probability: 0.8,
			Description: "Security effectiveness score is showing a declining trend",
		})
	}

	// Component performance risks
	if componentScores, ok := features["component_scores"].(map[string]float64); ok {
		for component, score := range componentScores {
			if score < 60.0 {
				riskFactors = append(riskFactors, entity.RiskFactor{
					Name:        fmt.Sprintf("Poor %s Performance", component),
					Category:    "component",
					Impact:      -8.0,
					Probability: 0.6,
					Description: fmt.Sprintf("%s component score is %.1f, below acceptable threshold", component, score),
				})
			}
		}
	}

	return riskFactors
}

func (m *DefaultPredictionModel) generateAssumptions(historicalScores []float64, features map[string]interface{}) []string {
	assumptions := []string{
		"Current security infrastructure remains stable",
		"No major security incidents or breaches occur",
		"Historical patterns continue to apply",
		"Resource allocation for security remains consistent",
	}

	// Add context-specific assumptions based on features
	if _, ok := features["threat_level"]; ok {
		assumptions = append(assumptions, "Current threat landscape conditions persist")
	}

	if _, ok := features["compliance_score"]; ok {
		assumptions = append(assumptions, "Regulatory requirements remain unchanged")
	}

	return assumptions
}

// Statistical helper methods

func (m *DefaultPredictionModel) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func (m *DefaultPredictionModel) calculateVariance(values []float64) float64 {
	if len(values) <= 1 {
		return 0
	}

	mean := m.calculateMean(values)
	var sum float64
	for _, value := range values {
		sum += math.Pow(value-mean, 2)
	}
	return sum / float64(len(values)-1)
}

func (m *DefaultPredictionModel) calculateVolatility(values []float64) float64 {
	if len(values) <= 1 {
		return 0
	}

	variance := m.calculateVariance(values)
	return math.Sqrt(variance)
}

func (m *DefaultPredictionModel) calculateTrendDirection(values []float64) float64 {
	n := len(values)
	if n < 2 {
		return 0
	}

	// Calculate average change per period
	var totalChange float64
	for i := 1; i < n; i++ {
		totalChange += values[i] - values[i-1]
	}
	return totalChange / float64(n-1)
}

func (m *DefaultPredictionModel) calculateTrendStability(values []float64) float64 {
	if len(values) < 3 {
		return 0.5
	}

	// Calculate period-to-period changes
	changes := make([]float64, len(values)-1)
	for i := 1; i < len(values); i++ {
		changes[i-1] = values[i] - values[i-1]
	}

	// Measure stability as inverse of change variance
	variance := m.calculateVariance(changes)
	stability := math.Exp(-variance / 25.0) // Exponential decay with variance

	return math.Min(1.0, stability)
}