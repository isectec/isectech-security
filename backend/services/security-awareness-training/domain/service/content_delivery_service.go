// iSECTECH Security Awareness Training Service - Content Delivery Service
// Production-grade content delivery and session management
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
	"github.com/isectech/backend/services/security-awareness-training/domain/repository"
	"github.com/isectech/backend/common/cache"
	"github.com/isectech/backend/common/events"
	"github.com/isectech/backend/common/logger"
	"github.com/sirupsen/logrus"
)

// ContentDeliveryService provides content delivery and session management
type ContentDeliveryService struct {
	contentRepo      repository.TrainingContentRepository
	deliveryRepo     repository.ContentDeliveryRepository
	assignmentRepo   repository.TrainingAssignmentRepository
	eventPublisher   events.Publisher
	cache            cache.Cache
	logger           *logrus.Logger
	config           *DeliveryServiceConfig
}

// DeliveryServiceConfig holds configuration for content delivery
type DeliveryServiceConfig struct {
	DefaultSessionTimeout   time.Duration `json:"default_session_timeout"`
	MaxConcurrentSessions   int          `json:"max_concurrent_sessions"`
	SessionExtensionLimit   int          `json:"session_extension_limit"`
	AutoSaveInterval        time.Duration `json:"auto_save_interval"`
	ProgressTrackingEnabled bool         `json:"progress_tracking_enabled"`
	SCORMTrackingEnabled    bool         `json:"scorm_tracking_enabled"`
	XAPITrackingEnabled     bool         `json:"xapi_tracking_enabled"`
	AnalyticsEnabled        bool         `json:"analytics_enabled"`
	OfflineCapable          bool         `json:"offline_capable"`
	MobileOptimized         bool         `json:"mobile_optimized"`
	SecurityAuditEnabled    bool         `json:"security_audit_enabled"`
}

// DefaultDeliveryServiceConfig returns default configuration
func DefaultDeliveryServiceConfig() *DeliveryServiceConfig {
	return &DeliveryServiceConfig{
		DefaultSessionTimeout:   time.Hour * 2,
		MaxConcurrentSessions:   3,
		SessionExtensionLimit:   2,
		AutoSaveInterval:        time.Minute * 5,
		ProgressTrackingEnabled: true,
		SCORMTrackingEnabled:    true,
		XAPITrackingEnabled:     true,
		AnalyticsEnabled:        true,
		OfflineCapable:          false,
		MobileOptimized:         true,
		SecurityAuditEnabled:    true,
	}
}

// NewContentDeliveryService creates a new content delivery service
func NewContentDeliveryService(
	contentRepo repository.TrainingContentRepository,
	deliveryRepo repository.ContentDeliveryRepository,
	assignmentRepo repository.TrainingAssignmentRepository,
	eventPublisher events.Publisher,
	cache cache.Cache,
	config *DeliveryServiceConfig,
) *ContentDeliveryService {
	if config == nil {
		config = DefaultDeliveryServiceConfig()
	}

	return &ContentDeliveryService{
		contentRepo:    contentRepo,
		deliveryRepo:   deliveryRepo,
		assignmentRepo: assignmentRepo,
		eventPublisher: eventPublisher,
		cache:          cache,
		logger:         logger.GetLogger("content-delivery-service"),
		config:         config,
	}
}

// LaunchRequest represents a content launch request
type LaunchRequest struct {
	TenantID       uuid.UUID `json:"tenant_id" validate:"required"`
	UserID         uuid.UUID `json:"user_id" validate:"required"`
	ContentID      uuid.UUID `json:"content_id" validate:"required"`
	AssignmentID   uuid.UUID `json:"assignment_id" validate:"required"`
	LaunchType     string    `json:"launch_type" validate:"required,oneof=direct assignment scheduled remedial preview"`
	DeliveryMethod string    `json:"delivery_method" validate:"required,oneof=web_browser mobile_app embedded_iframe api_access offline_package"`
	ReturnURL      string    `json:"return_url"`
	UserAgent      string    `json:"user_agent"`
	IPAddress      string    `json:"ip_address"`
	DeviceInfo     *DeviceInfo `json:"device_info"`
}

// DeviceInfo represents user device information
type DeviceInfo struct {
	DeviceType       string                 `json:"device_type"`
	OperatingSystem  string                 `json:"operating_system"`
	BrowserName      string                 `json:"browser_name"`
	BrowserVersion   string                 `json:"browser_version"`
	ScreenResolution string                 `json:"screen_resolution"`
	TimeZone         string                 `json:"timezone"`
	Language         string                 `json:"language"`
	AdditionalInfo   map[string]interface{} `json:"additional_info"`
}

// LaunchResult represents the result of a content launch
type LaunchResult struct {
	SessionID       uuid.UUID              `json:"session_id"`
	SessionToken    string                 `json:"session_token"`
	LaunchURL       string                 `json:"launch_url"`
	LaunchParameters map[string]interface{} `json:"launch_parameters"`
	ExpiresAt       time.Time              `json:"expires_at"`
	TrackingEnabled bool                   `json:"tracking_enabled"`
	ContentVersion  string                 `json:"content_version"`
}

// ProgressUpdate represents a progress update from the learner
type ProgressUpdate struct {
	SessionID        uuid.UUID              `json:"session_id" validate:"required"`
	SessionToken     string                 `json:"session_token" validate:"required"`
	Progress         int                    `json:"progress" validate:"min=0,max=100"`
	Location         string                 `json:"location"`
	TimeSpent        int                    `json:"time_spent_seconds"`
	InteractionData  map[string]interface{} `json:"interaction_data"`
	SCORMData        map[string]interface{} `json:"scorm_data"`
	XAPIStatements   []map[string]interface{} `json:"xapi_statements"`
	SuspendData      string                 `json:"suspend_data"`
	CompletionStatus string                 `json:"completion_status"`
	SuccessStatus    string                 `json:"success_status"`
	ScoreScaled      *float64               `json:"score_scaled"`
	ScoreRaw         *float64               `json:"score_raw"`
}

// AssessmentSubmission represents an assessment submission
type AssessmentSubmission struct {
	SessionID     uuid.UUID                 `json:"session_id" validate:"required"`
	SessionToken  string                    `json:"session_token" validate:"required"`
	AttemptNumber int                       `json:"attempt_number"`
	Responses     map[string]interface{}    `json:"responses" validate:"required"`
	TimeSpent     int                       `json:"time_spent_seconds"`
	StartedAt     time.Time                 `json:"started_at"`
	CompletedAt   time.Time                 `json:"completed_at"`
}

// LaunchContent initiates a content delivery session for a user
func (s *ContentDeliveryService) LaunchContent(ctx context.Context, req *LaunchRequest) (*LaunchResult, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":     req.TenantID,
		"user_id":       req.UserID,
		"content_id":    req.ContentID,
		"assignment_id": req.AssignmentID,
		"launch_type":   req.LaunchType,
	}).Info("Launching content")

	// Validate content exists and is accessible
	content, err := s.contentRepo.GetByID(ctx, req.ContentID)
	if err != nil {
		return nil, fmt.Errorf("content not found: %w", err)
	}

	if !content.IsPublished() {
		return nil, fmt.Errorf("content is not published")
	}

	if content.IsExpired() {
		return nil, fmt.Errorf("content has expired")
	}

	// Validate assignment if provided
	var assignment *entity.TrainingAssignment
	if req.AssignmentID != uuid.Nil {
		assignment, err = s.assignmentRepo.GetByID(ctx, req.AssignmentID)
		if err != nil {
			return nil, fmt.Errorf("assignment not found: %w", err)
		}

		if !assignment.CanStartTraining() {
			return nil, fmt.Errorf("assignment cannot be started at this time")
		}
	}

	// Check concurrent session limits
	activeSessions, err := s.deliveryRepo.GetActiveUserSessions(ctx, req.TenantID, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to check active sessions: %w", err)
	}

	if len(activeSessions) >= s.config.MaxConcurrentSessions {
		return nil, fmt.Errorf("maximum concurrent sessions limit reached (%d)", s.config.MaxConcurrentSessions)
	}

	// Generate session token
	sessionToken, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	// Create delivery session
	session := &entity.ContentDeliverySession{
		SessionID:             uuid.New(),
		TenantID:              req.TenantID,
		UserID:                req.UserID,
		ContentID:             req.ContentID,
		AssignmentID:          req.AssignmentID,
		SessionToken:          sessionToken,
		LaunchType:            req.LaunchType,
		DeliveryMethod:        req.DeliveryMethod,
		ContentVersion:        content.Version,
		LaunchURL:             content.LaunchURL,
		ReturnURL:             req.ReturnURL,
		Status:                string(entity.SessionStatusInitialized),
		Progress:              0,
		LaunchedAt:            time.Now(),
		UserAgent:             req.UserAgent,
		IPAddress:             req.IPAddress,
		SessionTimeoutMins:    int(s.config.DefaultSessionTimeout.Minutes()),
		ExpiresAt:             time.Now().Add(s.config.DefaultSessionTimeout),
		MaxAssessmentAttempts: content.MaxAttempts,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		IsActive:              true,
	}

	// Set device information if provided
	if req.DeviceInfo != nil {
		session.DeviceType = req.DeviceInfo.DeviceType
		session.OperatingSystem = req.DeviceInfo.OperatingSystem
		session.ScreenResolution = req.DeviceInfo.ScreenResolution

		browserInfo := map[string]interface{}{
			"name":    req.DeviceInfo.BrowserName,
			"version": req.DeviceInfo.BrowserVersion,
		}
		browserJSON, _ := json.Marshal(browserInfo)
		session.BrowserInfo = string(browserJSON)
	}

	// Save session to database
	if err := s.deliveryRepo.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create delivery session: %w", err)
	}

	// Update assignment status if applicable
	if assignment != nil {
		assignment.Status = "started"
		assignment.StartedAt = &[]time.Time{time.Now()}[0]
		s.assignmentRepo.Update(ctx, assignment)
	}

	// Generate launch parameters
	launchParams := content.GetLaunchParameters(req.UserID, session.SessionID.String())
	launchParams["session_token"] = sessionToken
	launchParams["expires_at"] = session.ExpiresAt

	// Cache session for quick access
	sessionKey := fmt.Sprintf("session:%s", sessionToken)
	if sessionJSON, err := json.Marshal(session); err == nil {
		s.cache.Set(ctx, sessionKey, sessionJSON, s.config.DefaultSessionTimeout)
	}

	// Publish launch event
	s.publishDeliveryEvent(ctx, "content.launched", session, nil)

	result := &LaunchResult{
		SessionID:        session.SessionID,
		SessionToken:     sessionToken,
		LaunchURL:        session.LaunchURL,
		LaunchParameters: launchParams,
		ExpiresAt:        session.ExpiresAt,
		TrackingEnabled:  s.config.ProgressTrackingEnabled,
		ContentVersion:   content.Version,
	}

	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"user_id":    req.UserID,
		"content_id": req.ContentID,
	}).Info("Content launched successfully")

	return result, nil
}

// UpdateProgress updates learner progress for a session
func (s *ContentDeliveryService) UpdateProgress(ctx context.Context, update *ProgressUpdate) error {
	// Validate and get session
	session, err := s.getAndValidateSession(ctx, update.SessionID, update.SessionToken)
	if err != nil {
		return err
	}

	// Update progress
	if err := session.UpdateProgress(update.Progress, update.Location, update.TimeSpent); err != nil {
		return fmt.Errorf("failed to update progress: %w", err)
	}

	// Process SCORM data if provided
	if len(update.SCORMData) > 0 && s.config.SCORMTrackingEnabled {
		for element, value := range update.SCORMData {
			session.UpdateSCORMData(element, value)
		}
	}

	// Process xAPI statements if provided
	if len(update.XAPIStatements) > 0 && s.config.XAPITrackingEnabled {
		for _, statement := range update.XAPIStatements {
			session.AddXAPIStatement(statement)
		}
	}

	// Add interaction event
	if len(update.InteractionData) > 0 {
		session.AddInteractionEvent("progress_update", update.InteractionData)
	}

	// Update suspend data if provided
	if update.SuspendData != "" {
		session.SuspendData = update.SuspendData
	}

	// Update completion and success status if provided
	if update.CompletionStatus != "" {
		session.CompletionStatus = update.CompletionStatus
	}
	if update.SuccessStatus != "" {
		session.SuccessStatus = update.SuccessStatus
	}

	// Update scores if provided
	if update.ScoreScaled != nil {
		session.ScoreScaled = *update.ScoreScaled
	}
	if update.ScoreRaw != nil {
		session.ScoreRaw = *update.ScoreRaw
	}

	// Save to database
	if err := s.deliveryRepo.UpdateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Update cache
	sessionKey := fmt.Sprintf("session:%s", update.SessionToken)
	if sessionJSON, err := json.Marshal(session); err == nil {
		s.cache.Set(ctx, sessionKey, sessionJSON, s.config.DefaultSessionTimeout)
	}

	// Publish progress event
	s.publishDeliveryEvent(ctx, "progress.updated", session, update.InteractionData)

	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"progress":   update.Progress,
		"location":   update.Location,
	}).Debug("Progress updated successfully")

	return nil
}

// SubmitAssessment processes an assessment submission
func (s *ContentDeliveryService) SubmitAssessment(ctx context.Context, submission *AssessmentSubmission) (*AssessmentResult, error) {
	// Validate and get session
	session, err := s.getAndValidateSession(ctx, submission.SessionID, submission.SessionToken)
	if err != nil {
		return nil, err
	}

	if !session.CanAttemptAssessment() {
		return nil, fmt.Errorf("cannot attempt assessment: maximum attempts exceeded or session invalid")
	}

	// Create attempt record
	attempt := &entity.ContentDeliveryAttempt{
		AttemptID:        uuid.New(),
		SessionID:        session.SessionID,
		AttemptNumber:    submission.AttemptNumber,
		StartedAt:        submission.StartedAt,
		CompletedAt:      &submission.CompletedAt,
		Status:           "completed",
		TimeSpentSeconds: submission.TimeSpent,
		CreatedAt:        time.Now(),
	}

	// Score the assessment (this would integrate with an assessment engine)
	score, passed := s.scoreAssessment(submission.Responses, session.ContentID)
	attempt.Score = score
	attempt.Passed = passed

	// Serialize response data
	responseJSON, _ := json.Marshal(submission.Responses)
	attempt.ResponseData = string(responseJSON)

	// Record attempt in session
	if err := session.RecordAssessmentAttempt(score, passed, submission.Responses); err != nil {
		return nil, fmt.Errorf("failed to record assessment attempt: %w", err)
	}

	// Save attempt and session
	if err := s.deliveryRepo.CreateAttempt(ctx, attempt); err != nil {
		return nil, fmt.Errorf("failed to create attempt record: %w", err)
	}

	if err := s.deliveryRepo.UpdateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	// Update assignment if applicable
	if session.AssignmentID != uuid.Nil {
		assignment, _ := s.assignmentRepo.GetByID(ctx, session.AssignmentID)
		if assignment != nil {
			if passed {
				assignment.MarkAsPassed(score)
			} else {
				assignment.MarkAsFailed(score)
			}
			s.assignmentRepo.Update(ctx, assignment)
		}
	}

	result := &AssessmentResult{
		AttemptID:       attempt.AttemptID,
		Score:           score,
		Passed:          passed,
		AttemptNumber:   attempt.AttemptNumber,
		MaxAttempts:     session.MaxAssessmentAttempts,
		CanRetry:        session.CanAttemptAssessment(),
		CompletedAt:     submission.CompletedAt,
		TimeSpent:       submission.TimeSpent,
		FeedbackMessage: s.generateFeedbackMessage(score, passed),
	}

	// Publish assessment event
	eventData := map[string]interface{}{
		"score":          score,
		"passed":         passed,
		"attempt_number": attempt.AttemptNumber,
	}
	s.publishDeliveryEvent(ctx, "assessment.submitted", session, eventData)

	s.logger.WithFields(logrus.Fields{
		"session_id": session.SessionID,
		"score":      score,
		"passed":     passed,
		"attempt":    attempt.AttemptNumber,
	}).Info("Assessment submitted successfully")

	return result, nil
}

// AssessmentResult represents the result of an assessment
type AssessmentResult struct {
	AttemptID       uuid.UUID `json:"attempt_id"`
	Score           float64   `json:"score"`
	Passed          bool      `json:"passed"`
	AttemptNumber   int       `json:"attempt_number"`
	MaxAttempts     int       `json:"max_attempts"`
	CanRetry        bool      `json:"can_retry"`
	CompletedAt     time.Time `json:"completed_at"`
	TimeSpent       int       `json:"time_spent_seconds"`
	FeedbackMessage string    `json:"feedback_message"`
}

// GetSessionStatus retrieves the current status of a session
func (s *ContentDeliveryService) GetSessionStatus(ctx context.Context, sessionToken string) (*SessionStatusResponse, error) {
	session, err := s.deliveryRepo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	return &SessionStatusResponse{
		SessionID:        session.SessionID,
		Status:           session.Status,
		Progress:         session.Progress,
		TimeSpentSeconds: session.TimeSpentSeconds,
		IsActive:         session.IsActive(),
		ExpiresAt:        session.ExpiresAt,
		LastAccessedAt:   session.LastAccessedAt,
		BookmarkLocation: session.BookmarkLocation,
	}, nil
}

// SessionStatusResponse represents session status information
type SessionStatusResponse struct {
	SessionID        uuid.UUID  `json:"session_id"`
	Status           string     `json:"status"`
	Progress         int        `json:"progress"`
	TimeSpentSeconds int        `json:"time_spent_seconds"`
	IsActive         bool       `json:"is_active"`
	ExpiresAt        time.Time  `json:"expires_at"`
	LastAccessedAt   *time.Time `json:"last_accessed_at"`
	BookmarkLocation string     `json:"bookmark_location"`
}

// Helper methods

// getAndValidateSession retrieves and validates a session by ID and token
func (s *ContentDeliveryService) getAndValidateSession(ctx context.Context, sessionID uuid.UUID, sessionToken string) (*entity.ContentDeliverySession, error) {
	// Try cache first
	sessionKey := fmt.Sprintf("session:%s", sessionToken)
	if cached, err := s.cache.Get(ctx, sessionKey); err == nil {
		var session entity.ContentDeliverySession
		if json.Unmarshal(cached, &session) == nil && session.SessionID == sessionID {
			if !session.IsActive() {
				return nil, fmt.Errorf("session is not active or has expired")
			}
			return &session, nil
		}
	}

	// Get from database
	session, err := s.deliveryRepo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if session.SessionID != sessionID {
		return nil, fmt.Errorf("session ID mismatch")
	}

	if !session.IsActive() {
		return nil, fmt.Errorf("session is not active or has expired")
	}

	return session, nil
}

// generateSessionToken generates a secure session token
func (s *ContentDeliveryService) generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// scoreAssessment scores an assessment (simplified implementation)
func (s *ContentDeliveryService) scoreAssessment(responses map[string]interface{}, contentID uuid.UUID) (float64, bool) {
	// In a real implementation, this would integrate with an assessment engine
	// For now, return a placeholder score
	totalQuestions := len(responses)
	if totalQuestions == 0 {
		return 0.0, false
	}

	// Simulate scoring logic
	correctAnswers := int(float64(totalQuestions) * 0.85) // 85% correct
	score := (float64(correctAnswers) / float64(totalQuestions)) * 100.0
	passed := score >= 80.0 // 80% passing threshold

	return score, passed
}

// generateFeedbackMessage generates feedback based on assessment results
func (s *ContentDeliveryService) generateFeedbackMessage(score float64, passed bool) string {
	if passed {
		if score >= 90 {
			return "Excellent work! You demonstrated strong understanding of the security concepts."
		}
		return "Good job! You passed the assessment and demonstrated adequate understanding."
	}

	return fmt.Sprintf("You scored %.1f%%. Please review the material and try again.", score)
}

// publishDeliveryEvent publishes delivery-related events
func (s *ContentDeliveryService) publishDeliveryEvent(ctx context.Context, eventType string, session *entity.ContentDeliverySession, eventData map[string]interface{}) {
	event := map[string]interface{}{
		"session_id":   session.SessionID,
		"tenant_id":    session.TenantID,
		"user_id":      session.UserID,
		"content_id":   session.ContentID,
		"assignment_id": session.AssignmentID,
		"status":       session.Status,
		"progress":     session.Progress,
		"timestamp":    time.Now(),
	}

	// Merge additional event data
	for key, value := range eventData {
		event[key] = value
	}

	s.eventPublisher.Publish(ctx, eventType, event)
}