package stream_processing

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// Processing pipeline stages implementation

// processEnrichmentStage processes events through the enrichment stage
func (m *StreamProcessorManager) processEnrichmentStage(ctx context.Context, processingCtx *ProcessingContext, result *ProcessingResult) {
	if !m.config.EnableEnrichment || m.enrichmentService == nil {
		return
	}
	
	stepStart := time.Now()
	step := ProcessingStep{
		Name:      "enrichment",
		Status:    "processing",
		Timestamp: stepStart,
	}
	
	// Perform enrichment
	enrichmentResult, err := m.enrichmentService.EnrichEvent(ctx, result.ProcessedEvent)
	if err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		result.Errors = append(result.Errors, ProcessingError{
			Stage:     "enrichment",
			Code:      "ENRICHMENT_FAILED",
			Message:   "Failed to enrich event",
			Details:   err.Error(),
			Timestamp: time.Now(),
			Retryable: true,
		})
		
		m.logger.Error("Enrichment failed",
			zap.String("event_id", processingCtx.EventID),
			zap.Error(err),
		)
	} else {
		step.Status = "success"
		step.Output = enrichmentResult
		
		// Merge enrichment data into result
		for k, v := range enrichmentResult {
			result.EnrichmentData[k] = v
		}
		
		// Add enriched fields to processed event
		if enrichedFields, ok := enrichmentResult["enriched_fields"].(map[string]interface{}); ok {
			for k, v := range enrichedFields {
				result.ProcessedEvent[k] = v
			}
		}
		
		m.logger.Debug("Event enriched successfully",
			zap.String("event_id", processingCtx.EventID),
			zap.Int("enriched_fields", len(enrichmentResult)),
		)
	}
	
	step.Duration = time.Since(stepStart)
	result.ProcessingSteps = append(result.ProcessingSteps, step)
}

// processCorrelationStage processes events through the correlation stage
func (m *StreamProcessorManager) processCorrelationStage(ctx context.Context, processingCtx *ProcessingContext, result *ProcessingResult) {
	if !m.config.EnableCorrelation || m.correlationEngine == nil {
		return
	}
	
	stepStart := time.Now()
	step := ProcessingStep{
		Name:      "correlation",
		Status:    "processing",
		Timestamp: stepStart,
	}
	
	// Perform correlation
	correlationResult, err := m.correlationEngine.CorrelateEvent(ctx, result.ProcessedEvent)
	if err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		result.Errors = append(result.Errors, ProcessingError{
			Stage:     "correlation",
			Code:      "CORRELATION_FAILED",
			Message:   "Failed to correlate event",
			Details:   err.Error(),
			Timestamp: time.Now(),
			Retryable: true,
		})
		
		m.logger.Error("Correlation failed",
			zap.String("event_id", processingCtx.EventID),
			zap.Error(err),
		)
	} else {
		step.Status = "success"
		step.Output = map[string]interface{}{
			"correlated_events": correlationResult.CorrelatedEventIDs,
			"correlation_score": correlationResult.CorrelationScore,
			"session_id":        correlationResult.SessionID,
		}
		
		// Add correlated events to result
		result.CorrelatedEvents = correlationResult.CorrelatedEventIDs
		
		// Add correlation metadata to processed event
		result.ProcessedEvent["correlation_id"] = correlationResult.CorrelationID
		result.ProcessedEvent["session_id"] = correlationResult.SessionID
		result.ProcessedEvent["correlation_score"] = correlationResult.CorrelationScore
		
		m.logger.Debug("Event correlated successfully",
			zap.String("event_id", processingCtx.EventID),
			zap.String("correlation_id", correlationResult.CorrelationID),
			zap.Int("correlated_events", len(correlationResult.CorrelatedEventIDs)),
		)
	}
	
	step.Duration = time.Since(stepStart)
	result.ProcessingSteps = append(result.ProcessingSteps, step)
}

// processPatternMatchingStage processes events through the pattern matching stage
func (m *StreamProcessorManager) processPatternMatchingStage(ctx context.Context, processingCtx *ProcessingContext, result *ProcessingResult) {
	if !m.config.EnablePatternMatching || m.patternMatcher == nil {
		return
	}
	
	stepStart := time.Now()
	step := ProcessingStep{
		Name:      "pattern_matching",
		Status:    "processing",
		Timestamp: stepStart,
	}
	
	// Perform pattern matching
	matches, err := m.patternMatcher.MatchPatterns(ctx, result.ProcessedEvent)
	if err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		result.Errors = append(result.Errors, ProcessingError{
			Stage:     "pattern_matching",
			Code:      "PATTERN_MATCHING_FAILED",
			Message:   "Failed to match patterns",
			Details:   err.Error(),
			Timestamp: time.Now(),
			Retryable: true,
		})
		
		m.logger.Error("Pattern matching failed",
			zap.String("event_id", processingCtx.EventID),
			zap.Error(err),
		)
	} else {
		step.Status = "success"
		step.Output = map[string]interface{}{
			"matched_patterns": matches,
			"match_count":      len(matches),
		}
		
		// Add matched patterns to result
		result.MatchedPatterns = matches
		
		// Add pattern matching metadata to processed event
		if len(matches) > 0 {
			result.ProcessedEvent["matched_patterns"] = matches
			result.ProcessedEvent["threat_detected"] = true
			
			// Calculate max severity from matched patterns
			maxSeverity := "low"
			for _, match := range matches {
				if match.Severity == "critical" {
					maxSeverity = "critical"
					break
				} else if match.Severity == "high" && maxSeverity != "critical" {
					maxSeverity = "high"
				} else if match.Severity == "medium" && maxSeverity != "critical" && maxSeverity != "high" {
					maxSeverity = "medium"
				}
			}
			result.ProcessedEvent["threat_severity"] = maxSeverity
		}
		
		m.logger.Debug("Pattern matching completed",
			zap.String("event_id", processingCtx.EventID),
			zap.Int("patterns_matched", len(matches)),
		)
	}
	
	step.Duration = time.Since(stepStart)
	result.ProcessingSteps = append(result.ProcessingSteps, step)
}

// processAnomalyDetectionStage processes events through the anomaly detection stage
func (m *StreamProcessorManager) processAnomalyDetectionStage(ctx context.Context, processingCtx *ProcessingContext, result *ProcessingResult) {
	if !m.config.EnableAnomalyDetection || m.anomalyDetector == nil {
		return
	}
	
	stepStart := time.Now()
	step := ProcessingStep{
		Name:      "anomaly_detection",
		Status:    "processing",
		Timestamp: stepStart,
	}
	
	// Perform anomaly detection
	anomalyResult, err := m.anomalyDetector.DetectAnomalies(ctx, result.ProcessedEvent)
	if err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		result.Errors = append(result.Errors, ProcessingError{
			Stage:     "anomaly_detection",
			Code:      "ANOMALY_DETECTION_FAILED",
			Message:   "Failed to detect anomalies",
			Details:   err.Error(),
			Timestamp: time.Now(),
			Retryable: true,
		})
		
		m.logger.Error("Anomaly detection failed",
			zap.String("event_id", processingCtx.EventID),
			zap.Error(err),
		)
	} else {
		step.Status = "success"
		step.Output = map[string]interface{}{
			"anomaly_score":   anomalyResult.AnomalyScore,
			"is_anomalous":    anomalyResult.IsAnomalous,
			"anomaly_reasons": anomalyResult.AnomalyReasons,
		}
		
		// Add anomaly detection results to result
		result.AnomalyScore = anomalyResult.AnomalyScore
		
		// Add anomaly metadata to processed event
		result.ProcessedEvent["anomaly_score"] = anomalyResult.AnomalyScore
		result.ProcessedEvent["is_anomalous"] = anomalyResult.IsAnomalous
		if len(anomalyResult.AnomalyReasons) > 0 {
			result.ProcessedEvent["anomaly_reasons"] = anomalyResult.AnomalyReasons
		}
		
		m.logger.Debug("Anomaly detection completed",
			zap.String("event_id", processingCtx.EventID),
			zap.Float64("anomaly_score", anomalyResult.AnomalyScore),
			zap.Bool("is_anomalous", anomalyResult.IsAnomalous),
		)
	}
	
	step.Duration = time.Since(stepStart)
	result.ProcessingSteps = append(result.ProcessingSteps, step)
}

// processAlertGeneration generates alerts based on processing results
func (m *StreamProcessorManager) processAlertGeneration(ctx context.Context, processingCtx *ProcessingContext, result *ProcessingResult) {
	stepStart := time.Now()
	step := ProcessingStep{
		Name:      "alert_generation",
		Status:    "processing",
		Timestamp: stepStart,
	}
	
	// Generate alerts based on pattern matches
	for _, pattern := range result.MatchedPatterns {
		if pattern.Severity == "critical" || pattern.Severity == "high" {
			alert := Alert{
				ID:          fmt.Sprintf("alert-%s-%s", processingCtx.EventID, pattern.RuleID),
				Type:        "threat_detection",
				Severity:    pattern.Severity,
				Title:       fmt.Sprintf("Threat Pattern Detected: %s", pattern.RuleName),
				Description: pattern.Description,
				Source:      "pattern_matcher",
				Timestamp:   time.Now(),
				Metadata: map[string]interface{}{
					"event_id":     processingCtx.EventID,
					"rule_id":      pattern.RuleID,
					"rule_name":    pattern.RuleName,
					"confidence":   pattern.Confidence,
					"category":     pattern.Category,
					"tenant_id":    processingCtx.TenantID,
					"original_event": result.ProcessedEvent,
				},
			}
			result.Alerts = append(result.Alerts, alert)
		}
	}
	
	// Generate alerts based on anomaly score
	if result.AnomalyScore > 0.8 { // High anomaly threshold
		alert := Alert{
			ID:          fmt.Sprintf("alert-%s-anomaly", processingCtx.EventID),
			Type:        "anomaly_detection",
			Severity:    "high",
			Title:       "High Anomaly Score Detected",
			Description: fmt.Sprintf("Event shows anomalous behavior with score %.2f", result.AnomalyScore),
			Source:      "anomaly_detector",
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"event_id":       processingCtx.EventID,
				"anomaly_score":  result.AnomalyScore,
				"tenant_id":      processingCtx.TenantID,
				"original_event": result.ProcessedEvent,
			},
		}
		result.Alerts = append(result.Alerts, alert)
	}
	
	// Generate alerts for correlated attack chains
	if len(result.CorrelatedEvents) > 3 { // Multiple correlated events might indicate an attack chain
		alert := Alert{
			ID:          fmt.Sprintf("alert-%s-correlation", processingCtx.EventID),
			Type:        "attack_chain",
			Severity:    "medium",
			Title:       "Potential Attack Chain Detected",
			Description: fmt.Sprintf("Event correlated with %d other events", len(result.CorrelatedEvents)),
			Source:      "correlation_engine",
			Timestamp:   time.Now(),
			Metadata: map[string]interface{}{
				"event_id":          processingCtx.EventID,
				"correlated_events": result.CorrelatedEvents,
				"tenant_id":         processingCtx.TenantID,
				"original_event":    result.ProcessedEvent,
			},
		}
		result.Alerts = append(result.Alerts, alert)
	}
	
	step.Status = "success"
	step.Output = map[string]interface{}{
		"alerts_generated": len(result.Alerts),
	}
	step.Duration = time.Since(stepStart)
	result.ProcessingSteps = append(result.ProcessingSteps, step)
	
	if len(result.Alerts) > 0 {
		m.logger.Info("Alerts generated",
			zap.String("event_id", processingCtx.EventID),
			zap.Int("alert_count", len(result.Alerts)),
		)
	}
}

// Helper structures for processing results

// EnrichmentResult represents the result of event enrichment
type EnrichmentResult map[string]interface{}

// CorrelationResult represents the result of event correlation
type CorrelationResult struct {
	CorrelationID      string   `json:"correlation_id"`
	SessionID          string   `json:"session_id"`
	CorrelatedEventIDs []string `json:"correlated_event_ids"`
	CorrelationScore   float64  `json:"correlation_score"`
}

// AnomalyDetectionResult represents the result of anomaly detection
type AnomalyDetectionResult struct {
	AnomalyScore   float64  `json:"anomaly_score"`
	IsAnomalous    bool     `json:"is_anomalous"`
	AnomalyReasons []string `json:"anomaly_reasons"`
}