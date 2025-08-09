// iSECTECH Security Awareness Training Service - Risk-Based Assignment Engine
// Production-grade business logic for intelligent training assignment
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
	"github.com/isectech/backend/services/security-awareness-training/domain/repository"
	"github.com/isectech/backend/common/events"
	"github.com/isectech/backend/common/logger"
	"github.com/sirupsen/logrus"
)

// RiskBasedAssignmentService provides intelligent training assignment based on user risk profiles
type RiskBasedAssignmentService struct {
	userRiskRepo       repository.UserRiskProfileRepository
	assignmentRepo     repository.TrainingAssignmentRepository
	eventPublisher     events.Publisher
	logger             *logrus.Logger
	mlPredictor        MLRiskPredictor
	securityEventAPI   SecurityEventAPI
	complianceEngine   ComplianceEngine
}

// NewRiskBasedAssignmentService creates a new instance of the risk-based assignment service
func NewRiskBasedAssignmentService(
	userRiskRepo repository.UserRiskProfileRepository,
	assignmentRepo repository.TrainingAssignmentRepository,
	eventPublisher events.Publisher,
	mlPredictor MLRiskPredictor,
	securityEventAPI SecurityEventAPI,
	complianceEngine ComplianceEngine,
) *RiskBasedAssignmentService {
	return &RiskBasedAssignmentService{
		userRiskRepo:     userRiskRepo,
		assignmentRepo:   assignmentRepo,
		eventPublisher:   eventPublisher,
		logger:          logger.GetLogger("risk-assignment-service"),
		mlPredictor:     mlPredictor,
		securityEventAPI: securityEventAPI,
		complianceEngine: complianceEngine,
	}
}

// AssignmentRequest represents a request for risk-based training assignment
type AssignmentRequest struct {
	TenantID              uuid.UUID         `json:"tenant_id" validate:"required"`
	UserID                uuid.UUID         `json:"user_id" validate:"required"`
	TriggerEvent          *SecurityEvent    `json:"trigger_event,omitempty"`
	ForceReassessment     bool              `json:"force_reassessment"`
	ComplianceFrameworks  []string          `json:"compliance_frameworks,omitempty"`
	CustomPriority        *entity.TrainingPriority `json:"custom_priority,omitempty"`
	ScheduledStart        *time.Time        `json:"scheduled_start,omitempty"`
	AssignedBy            uuid.UUID         `json:"assigned_by" validate:"required"`
	AssignmentReason      string            `json:"assignment_reason"`
}

// AssignmentResult represents the result of a risk-based assignment operation
type AssignmentResult struct {
	Assignments         []*entity.TrainingAssignment `json:"assignments"`
	RiskProfileUpdated  bool                         `json:"risk_profile_updated"`
	RiskLevelChanged    bool                         `json:"risk_level_changed"`
	PreviousRiskLevel   entity.RiskLevel             `json:"previous_risk_level"`
	CurrentRiskLevel    entity.RiskLevel             `json:"current_risk_level"`
	AssignmentTriggers  []string                     `json:"assignment_triggers"`
	ComplianceIssues    []ComplianceIssue            `json:"compliance_issues"`
	Recommendations     []string                     `json:"recommendations"`
}

// SecurityEvent represents a security event that can trigger training
type SecurityEvent struct {
	EventID          uuid.UUID              `json:"event_id"`
	EventType        string                 `json:"event_type"`
	Severity         string                 `json:"severity"`
	UserID           uuid.UUID              `json:"user_id"`
	TenantID         uuid.UUID              `json:"tenant_id"`
	Timestamp        time.Time              `json:"timestamp"`
	EventData        map[string]interface{} `json:"event_data"`
	RiskScore        int                    `json:"risk_score"`
	RequiresTraining bool                   `json:"requires_training"`
}

// ComplianceIssue represents a compliance-related training requirement
type ComplianceIssue struct {
	Framework    string    `json:"framework"`
	Requirement  string    `json:"requirement"`
	Severity     string    `json:"severity"`
	DueDate      time.Time `json:"due_date"`
	TrainingType string    `json:"training_type"`
}

// ProcessRiskBasedAssignment performs intelligent training assignment based on user risk profile
func (s *RiskBasedAssignmentService) ProcessRiskBasedAssignment(ctx context.Context, req *AssignmentRequest) (*AssignmentResult, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id": req.TenantID,
		"user_id":   req.UserID,
		"trigger":   req.TriggerEvent != nil,
	}).Info("Processing risk-based training assignment")

	// 1. Get or create user risk profile
	riskProfile, err := s.getOrCreateRiskProfile(ctx, req.TenantID, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk profile: %w", err)
	}

	previousRiskLevel := riskProfile.GetRiskLevel()

	// 2. Update risk profile based on trigger event and security history
	if req.TriggerEvent != nil || req.ForceReassessment {
		if err := s.updateRiskProfileFromEvents(ctx, riskProfile, req.TriggerEvent); err != nil {
			s.logger.WithError(err).Warning("Failed to update risk profile from events")
		}
	}

	// 3. Apply machine learning predictions
	if err := s.applyMLPredictions(ctx, riskProfile); err != nil {
		s.logger.WithError(err).Warning("Failed to apply ML predictions")
	}

	// 4. Update risk scores
	riskProfile.UpdateRiskScore()
	currentRiskLevel := riskProfile.GetRiskLevel()
	riskLevelChanged := previousRiskLevel != currentRiskLevel

	// 5. Determine required training based on risk assessment
	trainingRequirements, err := s.determineTrainingRequirements(ctx, riskProfile, req)
	if err != nil {
		return nil, fmt.Errorf("failed to determine training requirements: %w", err)
	}

	// 6. Check compliance requirements
	complianceIssues, err := s.checkComplianceRequirements(ctx, riskProfile, req.ComplianceFrameworks)
	if err != nil {
		s.logger.WithError(err).Warning("Failed to check compliance requirements")
	}

	// 7. Create training assignments
	assignments := make([]*entity.TrainingAssignment, 0)
	assignmentTriggers := make([]string, 0)

	for _, requirement := range trainingRequirements {
		assignment, err := s.createTrainingAssignment(ctx, riskProfile, requirement, req)
		if err != nil {
			s.logger.WithError(err).Error("Failed to create training assignment")
			continue
		}
		
		assignments = append(assignments, assignment)
		assignmentTriggers = append(assignmentTriggers, requirement.Trigger)
	}

	// 8. Save risk profile updates
	riskProfileUpdated := false
	if err := s.userRiskRepo.Update(ctx, riskProfile); err != nil {
		s.logger.WithError(err).Error("Failed to update risk profile")
	} else {
		riskProfileUpdated = true
	}

	// 9. Save training assignments
	if len(assignments) > 0 {
		if err := s.assignmentRepo.CreateBatch(ctx, assignments); err != nil {
			return nil, fmt.Errorf("failed to create training assignments: %w", err)
		}
	}

	// 10. Generate recommendations
	recommendations := s.generateRecommendations(riskProfile, assignments, complianceIssues)

	// 11. Publish events
	s.publishAssignmentEvents(ctx, assignments, req.TriggerEvent)

	result := &AssignmentResult{
		Assignments:        assignments,
		RiskProfileUpdated: riskProfileUpdated,
		RiskLevelChanged:   riskLevelChanged,
		PreviousRiskLevel:  previousRiskLevel,
		CurrentRiskLevel:   currentRiskLevel,
		AssignmentTriggers: assignmentTriggers,
		ComplianceIssues:   complianceIssues,
		Recommendations:    recommendations,
	}

	s.logger.WithFields(logrus.Fields{
		"assignments_created": len(assignments),
		"risk_level_changed":  riskLevelChanged,
		"compliance_issues":   len(complianceIssues),
	}).Info("Risk-based assignment completed")

	return result, nil
}

// getOrCreateRiskProfile retrieves existing risk profile or creates a new one
func (s *RiskBasedAssignmentService) getOrCreateRiskProfile(ctx context.Context, tenantID, userID uuid.UUID) (*entity.UserRiskProfile, error) {
	profile, err := s.userRiskRepo.GetByUserID(ctx, tenantID, userID)
	if err == nil {
		return profile, nil
	}

	// Create new profile with baseline risk assessment
	profile = &entity.UserRiskProfile{
		ProfileID:             uuid.New(),
		UserID:                userID,
		TenantID:              tenantID,
		OverallRiskScore:      50, // Baseline score
		PhishingRiskScore:     50,
		DataHandlingRiskScore: 50,
		AccessRiskScore:       50,
		ComplianceRiskScore:   50,
		TrainingStatus:        "required",
		SecurityClearance:     "unclassified",
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		LastRiskUpdate:        time.Now(),
		IsActive:              true,
		ProfileVersion:        1,
	}

	if err := s.userRiskRepo.Create(ctx, profile); err != nil {
		return nil, fmt.Errorf("failed to create new risk profile: %w", err)
	}

	return profile, nil
}

// updateRiskProfileFromEvents updates risk profile based on security events
func (s *RiskBasedAssignmentService) updateRiskProfileFromEvents(ctx context.Context, profile *entity.UserRiskProfile, triggerEvent *SecurityEvent) error {
	// Get recent security events for the user
	events, err := s.securityEventAPI.GetUserEvents(ctx, profile.TenantID, profile.UserID, time.Now().AddDate(0, -1, 0))
	if err != nil {
		return fmt.Errorf("failed to get security events: %w", err)
	}

	// Include trigger event if provided
	if triggerEvent != nil {
		events = append(events, *triggerEvent)
	}

	// Analyze events and update risk factors
	incidentCount := 0
	phishingIssues := 0
	policyViolations := 0
	suspiciousActivities := 0
	loginAnomalies := 0

	for _, event := range events {
		switch event.EventType {
		case "security_incident":
			incidentCount++
		case "phishing_click", "phishing_reported":
			phishingIssues++
		case "policy_violation":
			policyViolations++
		case "suspicious_activity":
			suspiciousActivities++
		case "login_anomaly":
			loginAnomalies++
		}
	}

	// Update risk scores based on events
	profile.RecentSecurityIncidents = incidentCount
	profile.PolicyViolationCount = policyViolations
	profile.SuspiciousActivityCount = suspiciousActivities
	profile.LoginAnomalies = loginAnomalies

	// Calculate phishing click rate
	if phishingIssues > 0 {
		totalPhishingTests := s.getPhishingTestCount(ctx, profile.UserID)
		if totalPhishingTests > 0 {
			profile.PhishingClickRate = (float64(phishingIssues) / float64(totalPhishingTests)) * 100
		}
	}

	// Update individual risk scores
	s.updateIndividualRiskScores(profile)

	profile.LastRiskUpdate = time.Now()
	profile.UpdatedAt = time.Now()

	return nil
}

// updateIndividualRiskScores updates individual risk component scores
func (s *RiskBasedAssignmentService) updateIndividualRiskScores(profile *entity.UserRiskProfile) {
	// Phishing risk score (0-100)
	basePhishingScore := 20.0
	if profile.PhishingClickRate > 0 {
		basePhishingScore += profile.PhishingClickRate * 0.8
	}
	if profile.PhishingClickRate > 50 {
		basePhishingScore += 20 // Penalty for high click rate
	}
	profile.PhishingRiskScore = int(math.Min(100, basePhishingScore))

	// Data handling risk score
	baseDataScore := 30.0
	if profile.SuspiciousActivityCount > 0 {
		baseDataScore += float64(profile.SuspiciousActivityCount) * 10
	}
	profile.DataHandlingRiskScore = int(math.Min(100, baseDataScore))

	// Access risk score
	baseAccessScore := 25.0
	if profile.LoginAnomalies > 0 {
		baseAccessScore += float64(profile.LoginAnomalies) * 8
	}
	profile.AccessRiskScore = int(math.Min(100, baseAccessScore))

	// Compliance risk score
	baseComplianceScore := 20.0
	if profile.PolicyViolationCount > 0 {
		baseComplianceScore += float64(profile.PolicyViolationCount) * 15
	}
	if profile.IsTrainingOverdue() {
		baseComplianceScore += 30
	}
	profile.ComplianceRiskScore = int(math.Min(100, baseComplianceScore))
}

// TrainingRequirement represents a required training module
type TrainingRequirement struct {
	ModuleID         uuid.UUID                `json:"module_id"`
	ModuleName       string                   `json:"module_name"`
	TrainingType     string                   `json:"training_type"`
	TrainingCategory string                   `json:"training_category"`
	Priority         entity.TrainingPriority  `json:"priority"`
	DifficultyLevel  string                   `json:"difficulty_level"`
	DueDate          time.Time                `json:"due_date"`
	Trigger          string                   `json:"trigger"`
	Reason           string                   `json:"reason"`
}

// determineTrainingRequirements determines what training is needed based on risk profile
func (s *RiskBasedAssignmentService) determineTrainingRequirements(ctx context.Context, profile *entity.UserRiskProfile, req *AssignmentRequest) ([]TrainingRequirement, error) {
	requirements := make([]TrainingRequirement, 0)

	// Check if training should be triggered
	shouldTrigger, triggerReasons := profile.ShouldTriggerTraining()
	if !shouldTrigger && req.TriggerEvent == nil {
		return requirements, nil
	}

	// Determine priority
	priority := profile.GetTrainingPriority()
	if req.CustomPriority != nil {
		priority = *req.CustomPriority
	}

	// High phishing risk - assign phishing training
	if profile.PhishingRiskScore >= 60 || profile.PhishingClickRate > 25 {
		requirements = append(requirements, TrainingRequirement{
			ModuleID:         s.getPhishingTrainingModuleID(profile.SecurityClearance),
			ModuleName:       "Advanced Phishing Awareness",
			TrainingType:     "phishing_simulation",
			TrainingCategory: "mandatory",
			Priority:         priority,
			DifficultyLevel:  s.getDifficultyLevel(profile.PhishingRiskScore),
			DueDate:          s.calculateDueDate(priority),
			Trigger:          "high_phishing_risk",
			Reason:           "High phishing susceptibility detected",
		})
	}

	// Policy violations - assign compliance training
	if profile.PolicyViolationCount > 0 {
		requirements = append(requirements, TrainingRequirement{
			ModuleID:         s.getComplianceTrainingModuleID(profile.SecurityClearance),
			ModuleName:       "Security Policy Compliance",
			TrainingType:     "compliance_training",
			TrainingCategory: "mandatory",
			Priority:         entity.TrainingPriorityHigh,
			DifficultyLevel:  "intermediate",
			DueDate:          s.calculateDueDate(entity.TrainingPriorityHigh),
			Trigger:          "policy_violation",
			Reason:           "Policy violations require remedial training",
		})
	}

	// Security incidents - assign incident response training
	if profile.RecentSecurityIncidents > 0 {
		requirements = append(requirements, TrainingRequirement{
			ModuleID:         s.getIncidentResponseModuleID(profile.SecurityClearance),
			ModuleName:       "Security Incident Response",
			TrainingType:     "incident_response",
			TrainingCategory: "remedial",
			Priority:         entity.TrainingPriorityImmediate,
			DifficultyLevel:  "advanced",
			DueDate:          s.calculateDueDate(entity.TrainingPriorityImmediate),
			Trigger:          "security_incident",
			Reason:           "Recent security incident involvement",
		})
	}

	// General security awareness for high overall risk
	if profile.OverallRiskScore >= 70 {
		requirements = append(requirements, TrainingRequirement{
			ModuleID:         s.getSecurityAwarenessModuleID(profile.SecurityClearance),
			ModuleName:       "Comprehensive Security Awareness",
			TrainingType:     "awareness_training",
			TrainingCategory: "mandatory",
			Priority:         priority,
			DifficultyLevel:  s.getDifficultyLevel(profile.OverallRiskScore),
			DueDate:          s.calculateDueDate(priority),
			Trigger:          "high_overall_risk",
			Reason:           "Elevated overall security risk profile",
		})
	}

	return requirements, nil
}

// Helper methods for module selection and calculation
func (s *RiskBasedAssignmentService) getPhishingTrainingModuleID(clearance string) uuid.UUID {
	// Return appropriate module ID based on security clearance
	switch clearance {
	case "top_secret":
		return uuid.MustParse("11111111-1111-1111-1111-111111111111")
	case "secret":
		return uuid.MustParse("22222222-2222-2222-2222-222222222222")
	case "confidential":
		return uuid.MustParse("33333333-3333-3333-3333-333333333333")
	default:
		return uuid.MustParse("44444444-4444-4444-4444-444444444444")
	}
}

func (s *RiskBasedAssignmentService) getComplianceTrainingModuleID(clearance string) uuid.UUID {
	// Return compliance training module based on clearance
	switch clearance {
	case "top_secret":
		return uuid.MustParse("55555555-5555-5555-5555-555555555555")
	default:
		return uuid.MustParse("66666666-6666-6666-6666-666666666666")
	}
}

func (s *RiskBasedAssignmentService) getIncidentResponseModuleID(clearance string) uuid.UUID {
	return uuid.MustParse("77777777-7777-7777-7777-777777777777")
}

func (s *RiskBasedAssignmentService) getSecurityAwarenessModuleID(clearance string) uuid.UUID {
	return uuid.MustParse("88888888-8888-8888-8888-888888888888")
}

func (s *RiskBasedAssignmentService) getDifficultyLevel(score int) string {
	switch {
	case score >= 80:
		return "expert"
	case score >= 60:
		return "advanced"
	case score >= 40:
		return "intermediate"
	default:
		return "beginner"
	}
}

func (s *RiskBasedAssignmentService) calculateDueDate(priority entity.TrainingPriority) time.Time {
	now := time.Now()
	switch priority {
	case entity.TrainingPriorityImmediate:
		return now.AddDate(0, 0, 3) // 3 days
	case entity.TrainingPriorityHigh:
		return now.AddDate(0, 0, 7) // 1 week
	case entity.TrainingPriorityStandard:
		return now.AddDate(0, 0, 30) // 1 month
	default:
		return now.AddDate(0, 0, 90) // 3 months
	}
}

// Additional interface definitions that would be implemented elsewhere
type MLRiskPredictor interface {
	PredictRiskTrend(ctx context.Context, profile *entity.UserRiskProfile) (*MLPrediction, error)
}

type SecurityEventAPI interface {
	GetUserEvents(ctx context.Context, tenantID, userID uuid.UUID, since time.Time) ([]SecurityEvent, error)
}

type ComplianceEngine interface {
	CheckCompliance(ctx context.Context, profile *entity.UserRiskProfile, frameworks []string) ([]ComplianceIssue, error)
}

type MLPrediction struct {
	RiskTrend           string  `json:"risk_trend"`
	PredictionScore     float64 `json:"prediction_score"`
	ConfidenceLevel     float64 `json:"confidence_level"`
	ModelVersion        string  `json:"model_version"`
}

// Placeholder implementations for remaining methods
func (s *RiskBasedAssignmentService) applyMLPredictions(ctx context.Context, profile *entity.UserRiskProfile) error {
	prediction, err := s.mlPredictor.PredictRiskTrend(ctx, profile)
	if err != nil {
		return err
	}
	
	profile.PredictedRiskTrend = prediction.RiskTrend
	profile.RiskPredictionScore = prediction.PredictionScore
	profile.MLModelVersion = prediction.ModelVersion
	profile.LastMLPredictionDate = &[]time.Time{time.Now()}[0]
	
	return nil
}

func (s *RiskBasedAssignmentService) checkComplianceRequirements(ctx context.Context, profile *entity.UserRiskProfile, frameworks []string) ([]ComplianceIssue, error) {
	return s.complianceEngine.CheckCompliance(ctx, profile, frameworks)
}

func (s *RiskBasedAssignmentService) createTrainingAssignment(ctx context.Context, profile *entity.UserRiskProfile, req TrainingRequirement, assignReq *AssignmentRequest) (*entity.TrainingAssignment, error) {
	assignment := &entity.TrainingAssignment{
		AssignmentID:       uuid.New(),
		TenantID:           profile.TenantID,
		UserID:             profile.UserID,
		ProfileID:          profile.ProfileID,
		TrainingModuleID:   req.ModuleID,
		ModuleName:         req.ModuleName,
		TrainingType:       req.TrainingType,
		TrainingCategory:   req.TrainingCategory,
		DifficultyLevel:    req.DifficultyLevel,
		AssignmentReason:   req.Reason,
		Priority:           req.Priority,
		AssignedBy:         assignReq.AssignedBy,
		AssignedByType:     "system",
		AssignmentMethod:   "risk_based",
		AssignedAt:         time.Now(),
		ScheduledStart:     assignReq.ScheduledStart,
		DueDate:            req.DueDate,
		EstimatedDuration:  s.getEstimatedDuration(req.TrainingType),
		Status:             "assigned",
		Progress:           0,
		RequiresAssessment: s.requiresAssessment(req.TrainingType),
		PassingScore:       s.getPassingScore(req.TrainingType),
		MaxAttempts:        3,
		AllowedExtensions:  1,
		SecurityClearanceRequired: profile.SecurityClearance,
		DeliveryMethod:     "web_portal",
		LanguageCode:       "en",
		TimeZone:           "UTC",
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
		Version:            1,
		IsActive:           true,
	}
	
	// Add trigger event info if provided
	if assignReq.TriggerEvent != nil {
		assignment.TriggerEvent = assignReq.TriggerEvent.EventID.String()
	}
	
	return assignment, nil
}

func (s *RiskBasedAssignmentService) getEstimatedDuration(trainingType string) int {
	durations := map[string]int{
		"awareness_training":   45,
		"phishing_simulation":  30,
		"compliance_training":  60,
		"incident_response":    90,
		"assessment":          20,
	}
	if duration, exists := durations[trainingType]; exists {
		return duration
	}
	return 45 // Default duration
}

func (s *RiskBasedAssignmentService) requiresAssessment(trainingType string) bool {
	assessmentRequired := map[string]bool{
		"awareness_training":   true,
		"phishing_simulation":  true,
		"compliance_training":  true,
		"incident_response":    true,
		"assessment":          true,
	}
	return assessmentRequired[trainingType]
}

func (s *RiskBasedAssignmentService) getPassingScore(trainingType string) float64 {
	passingScores := map[string]float64{
		"awareness_training":   80.0,
		"phishing_simulation":  85.0,
		"compliance_training":  90.0,
		"incident_response":    85.0,
		"assessment":          75.0,
	}
	if score, exists := passingScores[trainingType]; exists {
		return score
	}
	return 80.0 // Default passing score
}

func (s *RiskBasedAssignmentService) getPhishingTestCount(ctx context.Context, userID uuid.UUID) int {
	// This would query the phishing simulation system
	// For now, return a placeholder
	return 10
}

func (s *RiskBasedAssignmentService) generateRecommendations(profile *entity.UserRiskProfile, assignments []*entity.TrainingAssignment, complianceIssues []ComplianceIssue) []string {
	recommendations := make([]string, 0)
	
	if profile.GetRiskLevel() == entity.RiskLevelCritical {
		recommendations = append(recommendations, "Consider immediate manager notification due to critical risk level")
	}
	
	if len(assignments) > 3 {
		recommendations = append(recommendations, "Spread training assignments over multiple weeks to avoid training fatigue")
	}
	
	if len(complianceIssues) > 0 {
		recommendations = append(recommendations, "Prioritize compliance training to meet regulatory requirements")
	}
	
	return recommendations
}

func (s *RiskBasedAssignmentService) publishAssignmentEvents(ctx context.Context, assignments []*entity.TrainingAssignment, triggerEvent *SecurityEvent) {
	for _, assignment := range assignments {
		event := map[string]interface{}{
			"event_type":      "training_assigned",
			"tenant_id":       assignment.TenantID,
			"user_id":         assignment.UserID,
			"assignment_id":   assignment.AssignmentID,
			"training_type":   assignment.TrainingType,
			"priority":        assignment.Priority,
			"due_date":        assignment.DueDate,
			"trigger_event":   triggerEvent != nil,
		}
		
		s.eventPublisher.Publish(ctx, "training.assignment.created", event)
	}
}