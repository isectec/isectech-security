package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"threat-detection/domain/entity"
	"threat-detection/domain/repository"
	"threat-detection/domain/service"
)

// ThreatDetectionUseCase orchestrates threat detection operations
type ThreatDetectionUseCase struct {
	threatRepo              repository.ThreatRepository
	threatIntelRepo         repository.ThreatIntelligenceRepository
	threatDetectionService  service.ThreatDetectionService
	threatAnalysisService   service.ThreatAnalysisService
	threatScoringService    service.ThreatScoringService
	logger                  *zap.Logger
}

// NewThreatDetectionUseCase creates a new threat detection use case
func NewThreatDetectionUseCase(
	threatRepo repository.ThreatRepository,
	threatIntelRepo repository.ThreatIntelligenceRepository,
	threatDetectionService service.ThreatDetectionService,
	threatAnalysisService service.ThreatAnalysisService,
	threatScoringService service.ThreatScoringService,
	logger *zap.Logger,
) *ThreatDetectionUseCase {
	return &ThreatDetectionUseCase{
		threatRepo:              threatRepo,
		threatIntelRepo:         threatIntelRepo,
		threatDetectionService:  threatDetectionService,
		threatAnalysisService:   threatAnalysisService,
		threatScoringService:    threatScoringService,
		logger:                  logger,
	}
}

// ProcessSecurityEvent processes a security event for threat detection
func (uc *ThreatDetectionUseCase) ProcessSecurityEvent(ctx context.Context, event *service.SecurityEvent) (*entity.Threat, error) {
	uc.logger.Info("Processing security event for threat detection",
		zap.String("event_id", event.ID.String()),
		zap.String("event_type", event.EventType),
		zap.String("tenant_id", event.TenantID.String()),
	)

	// Analyze the event for threats
	analysisResult, err := uc.threatDetectionService.AnalyzeEvent(ctx, event)
	if err != nil {
		uc.logger.Error("Failed to analyze security event", zap.Error(err))
		return nil, fmt.Errorf("failed to analyze event: %w", err)
	}

	// If no threat detected, return nil
	if !analysisResult.IsThreateningP {
		uc.logger.Debug("No threat detected in security event", zap.String("event_id", event.ID.String()))
		return nil, nil
	}

	// Create threat entity from analysis result
	threat := uc.createThreatFromAnalysis(event, analysisResult)

	// Enrich threat with intelligence
	if err := uc.enrichThreatWithIntelligence(ctx, threat); err != nil {
		uc.logger.Warn("Failed to enrich threat with intelligence", zap.Error(err))
		// Continue processing even if enrichment fails
	}

	// Calculate risk score
	if err := uc.calculateThreatRiskScore(ctx, threat); err != nil {
		uc.logger.Warn("Failed to calculate threat risk score", zap.Error(err))
		// Continue processing even if scoring fails
	}

	// Map to MITRE ATT&CK framework
	if err := uc.mapThreatToMITRE(ctx, threat); err != nil {
		uc.logger.Warn("Failed to map threat to MITRE ATT&CK", zap.Error(err))
		// Continue processing even if MITRE mapping fails
	}

	// Save threat to repository
	if err := uc.threatRepo.Create(ctx, threat); err != nil {
		uc.logger.Error("Failed to save threat", zap.Error(err))
		return nil, fmt.Errorf("failed to save threat: %w", err)
	}

	// Perform additional analysis asynchronously
	go uc.performAsyncAnalysis(context.Background(), threat.ID)

	uc.logger.Info("Successfully processed security event and created threat",
		zap.String("threat_id", threat.ID.String()),
		zap.String("threat_type", string(threat.Type)),
		zap.String("severity", string(threat.Severity)),
		zap.Float64("risk_score", threat.RiskScore),
	)

	return threat, nil
}

// ProcessSecurityEventsBatch processes multiple security events in batch
func (uc *ThreatDetectionUseCase) ProcessSecurityEventsBatch(ctx context.Context, events []*service.SecurityEvent) ([]*entity.Threat, error) {
	uc.logger.Info("Processing security events batch",
		zap.Int("event_count", len(events)),
	)

	// Analyze events in batch
	analysisResults, err := uc.threatDetectionService.AnalyzeBatch(ctx, events)
	if err != nil {
		uc.logger.Error("Failed to analyze security events batch", zap.Error(err))
		return nil, fmt.Errorf("failed to analyze events batch: %w", err)
	}

	var threats []*entity.Threat
	var threatsToSave []*entity.Threat

	// Process each analysis result
	for i, result := range analysisResults {
		if !result.IsThreateningP {
			continue
		}

		event := events[i]
		threat := uc.createThreatFromAnalysis(event, result)

		// Enrich threat with intelligence
		if err := uc.enrichThreatWithIntelligence(ctx, threat); err != nil {
			uc.logger.Warn("Failed to enrich threat with intelligence",
				zap.String("threat_id", threat.ID.String()),
				zap.Error(err))
		}

		// Calculate risk score
		if err := uc.calculateThreatRiskScore(ctx, threat); err != nil {
			uc.logger.Warn("Failed to calculate threat risk score",
				zap.String("threat_id", threat.ID.String()),
				zap.Error(err))
		}

		// Map to MITRE ATT&CK framework
		if err := uc.mapThreatToMITRE(ctx, threat); err != nil {
			uc.logger.Warn("Failed to map threat to MITRE ATT&CK",
				zap.String("threat_id", threat.ID.String()),
				zap.Error(err))
		}

		threats = append(threats, threat)
		threatsToSave = append(threatsToSave, threat)
	}

	// Bulk save threats
	if len(threatsToSave) > 0 {
		if err := uc.threatRepo.BulkCreate(ctx, threatsToSave); err != nil {
			uc.logger.Error("Failed to bulk save threats", zap.Error(err))
			return nil, fmt.Errorf("failed to bulk save threats: %w", err)
		}
	}

	// Perform additional analysis asynchronously
	for _, threat := range threats {
		go uc.performAsyncAnalysis(context.Background(), threat.ID)
	}

	uc.logger.Info("Successfully processed security events batch",
		zap.Int("total_events", len(events)),
		zap.Int("threats_detected", len(threats)),
	)

	return threats, nil
}

// DetectAnomalies detects anomalies in security data
func (uc *ThreatDetectionUseCase) DetectAnomalies(ctx context.Context, request *service.AnomalyDetectionRequest) (*service.AnomalyDetectionResult, error) {
	uc.logger.Info("Detecting anomalies",
		zap.String("tenant_id", request.TenantID.String()),
		zap.Duration("time_window", request.TimeWindow),
	)

	// Perform anomaly detection
	result, err := uc.threatDetectionService.DetectAnomalies(ctx, request)
	if err != nil {
		uc.logger.Error("Failed to detect anomalies", zap.Error(err))
		return nil, fmt.Errorf("failed to detect anomalies: %w", err)
	}

	// If anomalies detected, create threat entities
	if result.HasAnomalies {
		for _, anomaly := range result.Anomalies {
			threat := uc.createThreatFromAnomaly(request.TenantID, anomaly)
			
			// Save threat asynchronously
			go func(t *entity.Threat) {
				ctx := context.Background()
				if err := uc.threatRepo.Create(ctx, t); err != nil {
					uc.logger.Error("Failed to save anomaly threat", zap.Error(err))
				}
			}(threat)
		}
	}

	uc.logger.Info("Anomaly detection completed",
		zap.Bool("has_anomalies", result.HasAnomalies),
		zap.Int("anomaly_count", result.AnomalyCount),
		zap.Float64("score", result.Score),
	)

	return result, nil
}

// HuntThreats performs threat hunting based on specified criteria
func (uc *ThreatDetectionUseCase) HuntThreats(ctx context.Context, request *service.ThreatHuntingRequest) (*service.ThreatHuntingResult, error) {
	uc.logger.Info("Starting threat hunting",
		zap.String("tenant_id", request.TenantID.String()),
	)

	// Perform threat hunting
	result, err := uc.threatDetectionService.HuntThreats(ctx, request)
	if err != nil {
		uc.logger.Error("Failed to hunt threats", zap.Error(err))
		return nil, fmt.Errorf("failed to hunt threats: %w", err)
	}

	uc.logger.Info("Threat hunting completed",
		zap.Int("threats_found", len(result.Threats)),
		zap.Int("indicators_found", len(result.Indicators)),
	)

	return result, nil
}

// AnalyzeThreatCampaign analyzes a threat campaign
func (uc *ThreatDetectionUseCase) AnalyzeThreatCampaign(ctx context.Context, campaignID uuid.UUID) (*service.CampaignAnalysisResult, error) {
	uc.logger.Info("Analyzing threat campaign", zap.String("campaign_id", campaignID.String()))

	// Get threats associated with the campaign
	filter := repository.ThreatFilter{
		// Add campaign filter when available
	}
	
	threats, err := uc.threatRepo.List(ctx, filter, nil, repository.PageRequest{Page: 1, PageSize: 1000})
	if err != nil {
		uc.logger.Error("Failed to get campaign threats", zap.Error(err))
		return nil, fmt.Errorf("failed to get campaign threats: %w", err)
	}

	// Perform campaign analysis
	result := &service.CampaignAnalysisResult{
		CampaignID:    campaignID,
		TotalThreats:  int64(len(threats.Threats)),
		AnalysisTime:  time.Now(),
		// Add more analysis results
	}

	uc.logger.Info("Campaign analysis completed", 
		zap.String("campaign_id", campaignID.String()),
		zap.Int64("total_threats", result.TotalThreats),
	)

	return result, nil
}

// GetThreatTimeline builds a timeline for a specific threat
func (uc *ThreatDetectionUseCase) GetThreatTimeline(ctx context.Context, threatID uuid.UUID) (*service.ThreatTimeline, error) {
	uc.logger.Info("Building threat timeline", zap.String("threat_id", threatID.String()))

	// Get threat details
	threat, err := uc.threatRepo.GetByID(ctx, threatID)
	if err != nil {
		uc.logger.Error("Failed to get threat", zap.Error(err))
		return nil, fmt.Errorf("failed to get threat: %w", err)
	}

	// Build timeline using analysis service
	timeline, err := uc.threatAnalysisService.BuildThreatTimeline(ctx, threatID)
	if err != nil {
		uc.logger.Error("Failed to build threat timeline", zap.Error(err))
		return nil, fmt.Errorf("failed to build timeline: %w", err)
	}

	uc.logger.Info("Threat timeline built successfully",
		zap.String("threat_id", threatID.String()),
		zap.Int("timeline_events", len(timeline.Events)),
	)

	return timeline, nil
}

// UpdateThreatStatus updates the status of a threat
func (uc *ThreatDetectionUseCase) UpdateThreatStatus(ctx context.Context, threatID uuid.UUID, status entity.ThreatStatus, actor, reason string) error {
	uc.logger.Info("Updating threat status",
		zap.String("threat_id", threatID.String()),
		zap.String("new_status", string(status)),
		zap.String("actor", actor),
	)

	// Get current threat
	threat, err := uc.threatRepo.GetByID(ctx, threatID)
	if err != nil {
		uc.logger.Error("Failed to get threat", zap.Error(err))
		return fmt.Errorf("failed to get threat: %w", err)
	}

	// Update status
	threat.UpdateStatus(status, actor, reason)

	// Save updated threat
	if err := uc.threatRepo.Update(ctx, threat); err != nil {
		uc.logger.Error("Failed to update threat", zap.Error(err))
		return fmt.Errorf("failed to update threat: %w", err)
	}

	uc.logger.Info("Threat status updated successfully",
		zap.String("threat_id", threatID.String()),
		zap.String("status", string(status)),
	)

	return nil
}

// Helper methods

// createThreatFromAnalysis creates a threat entity from analysis results
func (uc *ThreatDetectionUseCase) createThreatFromAnalysis(event *service.SecurityEvent, result *service.ThreatAnalysisResult) *entity.Threat {
	now := time.Now()
	
	threat := &entity.Threat{
		ID:          uuid.New(),
		TenantID:    event.TenantID,
		Name:        fmt.Sprintf("Threat detected from %s", event.EventType),
		Description: fmt.Sprintf("Threat detected in security event: %s", event.Message),
		Type:        result.ThreatType,
		Severity:    result.Severity,
		Status:      entity.ThreatStatusActive,
		Confidence:  uc.convertConfidence(result.Confidence),
		RiskScore:   result.RiskScore,
		
		DetectionEngine: "threat-detection-service",
		DetectionMethod: "real-time-analysis",
		DetectedAt:      now,
		FirstSeen:       event.Timestamp,
		LastSeen:        event.Timestamp,
		
		SourceInfo: &entity.ThreatSourceInfo{
			SourceIP: event.SourceIP,
		},
		TargetInfo: &entity.ThreatTargetInfo{
			TargetIP: event.TargetIP,
		},
		
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}

	// Add IOC matches
	for _, iocMatch := range result.IOCMatches {
		ioc := entity.IndicatorOfCompromise{
			ID:          uuid.New(),
			Type:        entity.IOCType(iocMatch.MatchType),
			Value:       iocMatch.MatchValue,
			Confidence:  iocMatch.Confidence,
			FirstSeen:   now,
			LastSeen:    now,
			Source:      iocMatch.Source,
		}
		threat.IOCs = append(threat.IOCs, ioc)
	}

	// Add evidence
	for _, evidence := range result.Evidence {
		threatEvidence := entity.ThreatEvidence{
			ID:          uuid.New(),
			Type:        entity.EvidenceType(evidence.Type),
			Description: evidence.Value,
			Value:       evidence.Value,
			Source:      evidence.Source,
			CollectedAt: evidence.Timestamp,
		}
		threat.Evidence = append(threat.Evidence, threatEvidence)
	}

	// Add MITRE mapping
	if result.MITREMapping != nil {
		threat.MITREAttack = &entity.MITREAttackInfo{
			TacticIDs:       result.MITREMapping.TacticIDs,
			TacticNames:     result.MITREMapping.TacticNames,
			TechniqueIDs:    result.MITREMapping.TechniqueIDs,
			TechniqueNames:  result.MITREMapping.TechniqueNames,
			SubTechniqueIDs: result.MITREMapping.SubTechniqueIDs,
			KillChainPhases: []string{result.MITREMapping.KillChainPhase},
		}
	}

	// Set fingerprint
	threat.Fingerprint = threat.GetFingerprint()

	return threat
}

// createThreatFromAnomaly creates a threat entity from anomaly detection
func (uc *ThreatDetectionUseCase) createThreatFromAnomaly(tenantID uuid.UUID, anomaly *service.AnomalyResult) *entity.Threat {
	now := time.Now()
	
	threat := &entity.Threat{
		ID:          uuid.New(),
		TenantID:    tenantID,
		Name:        fmt.Sprintf("Anomaly detected: %s", anomaly.Type),
		Description: anomaly.Description,
		Type:        entity.ThreatTypeAnomalousActivity,
		Severity:    uc.convertSeverity(anomaly.Severity),
		Status:      entity.ThreatStatusActive,
		Confidence:  uc.convertConfidence(anomaly.Confidence),
		RiskScore:   anomaly.Deviation,
		
		DetectionEngine: "anomaly-detection-engine",
		DetectionMethod: "statistical-analysis",
		DetectedAt:      now,
		FirstSeen:       anomaly.Timestamp,
		LastSeen:        anomaly.Timestamp,
		
		CreatedAt: now,
		UpdatedAt: now,
		Version:   1,
	}

	// Add anomaly evidence
	evidence := entity.ThreatEvidence{
		ID:          uuid.New(),
		Type:        entity.EvidenceTypeMetrics,
		Description: fmt.Sprintf("Anomaly detected with deviation: %f", anomaly.Deviation),
		Value:       fmt.Sprintf("Expected: %f, Actual: %f", anomaly.ExpectedValue, anomaly.Value),
		Source:      "anomaly-detector",
		CollectedAt: anomaly.Timestamp,
	}
	threat.Evidence = append(threat.Evidence, evidence)

	// Set fingerprint
	threat.Fingerprint = threat.GetFingerprint()

	return threat
}

// enrichThreatWithIntelligence enriches threat with threat intelligence
func (uc *ThreatDetectionUseCase) enrichThreatWithIntelligence(ctx context.Context, threat *entity.Threat) error {
	enrichmentResult, err := uc.threatDetectionService.EnrichWithIntelligence(ctx, threat)
	if err != nil {
		return err
	}

	// Update threat with enrichment data
	if enrichmentResult.Attribution != nil {
		// Add attribution information
		threat.Context["attribution"] = enrichmentResult.Attribution
	}

	if len(enrichmentResult.RelatedCampaigns) > 0 {
		// Add campaign information
		threat.Context["campaigns"] = enrichmentResult.RelatedCampaigns
	}

	if len(enrichmentResult.AdditionalIOCs) > 0 {
		// Add additional IOCs
		threat.IOCs = append(threat.IOCs, enrichmentResult.AdditionalIOCs...)
	}

	return nil
}

// calculateThreatRiskScore calculates and updates the threat risk score
func (uc *ThreatDetectionUseCase) calculateThreatRiskScore(ctx context.Context, threat *entity.Threat) error {
	riskScore, err := uc.threatScoringService.CalculateRiskScore(ctx, threat)
	if err != nil {
		return err
	}

	threat.RiskScore = riskScore.Score
	threat.ImpactScore = riskScore.ImpactScore
	threat.LikelihoodScore = riskScore.LikelihoodScore

	return nil
}

// mapThreatToMITRE maps threat to MITRE ATT&CK framework
func (uc *ThreatDetectionUseCase) mapThreatToMITRE(ctx context.Context, threat *entity.Threat) error {
	mitreMapping, err := uc.threatDetectionService.MapToMITRE(ctx, threat)
	if err != nil {
		return err
	}

	if threat.MITREAttack == nil {
		threat.MITREAttack = &entity.MITREAttackInfo{}
	}

	// Update MITRE mapping
	threat.MITREAttack.TacticIDs = mitreMapping.TacticIDs
	threat.MITREAttack.TacticNames = mitreMapping.TacticNames
	threat.MITREAttack.TechniqueIDs = mitreMapping.TechniqueIDs
	threat.MITREAttack.TechniqueNames = mitreMapping.TechniqueNames
	threat.MITREAttack.SubTechniqueIDs = mitreMapping.SubTechniqueIDs
	threat.MITREAttack.KillChainPhases = []string{mitreMapping.KillChainPhase}

	return nil
}

// performAsyncAnalysis performs additional analysis asynchronously
func (uc *ThreatDetectionUseCase) performAsyncAnalysis(ctx context.Context, threatID uuid.UUID) {
	uc.logger.Debug("Starting async analysis", zap.String("threat_id", threatID.String()))

	// Get threat
	threat, err := uc.threatRepo.GetByID(ctx, threatID)
	if err != nil {
		uc.logger.Error("Failed to get threat for async analysis", zap.Error(err))
		return
	}

	// Perform deep analysis
	deepResult, err := uc.threatAnalysisService.DeepAnalyze(ctx, threat)
	if err != nil {
		uc.logger.Warn("Deep analysis failed", zap.Error(err))
	} else {
		// Update threat with deep analysis results
		threat.Context["deep_analysis"] = deepResult
	}

	// Perform attribution analysis
	attributionResult, err := uc.threatAnalysisService.AnalyzeAttribution(ctx, threat)
	if err != nil {
		uc.logger.Warn("Attribution analysis failed", zap.Error(err))
	} else {
		// Update threat with attribution results
		threat.Context["attribution_analysis"] = attributionResult
	}

	// Save updated threat
	if err := uc.threatRepo.Update(ctx, threat); err != nil {
		uc.logger.Error("Failed to save async analysis results", zap.Error(err))
	}

	uc.logger.Debug("Async analysis completed", zap.String("threat_id", threatID.String()))
}

// Utility methods

func (uc *ThreatDetectionUseCase) convertConfidence(confidence float64) entity.ThreatConfidence {
	if confidence >= 0.8 {
		return entity.ThreatConfidenceHigh
	} else if confidence >= 0.5 {
		return entity.ThreatConfidenceMedium
	} else {
		return entity.ThreatConfidenceLow
	}
}

func (uc *ThreatDetectionUseCase) convertSeverity(severity string) entity.ThreatSeverity {
	switch severity {
	case "critical":
		return entity.ThreatSeverityCritical
	case "high":
		return entity.ThreatSeverityHigh
	case "medium":
		return entity.ThreatSeverityMedium
	case "low":
		return entity.ThreatSeverityLow
	default:
		return entity.ThreatSeverityInfo
	}
}