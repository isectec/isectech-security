// iSECTECH Security Awareness Training Service - Assignment Engine
// Production-grade orchestration engine for training assignments
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
	"github.com/isectech/backend/services/security-awareness-training/domain/repository"
	"github.com/isectech/backend/common/cache"
	"github.com/isectech/backend/common/events"
	"github.com/isectech/backend/common/logger"
	"github.com/sirupsen/logrus"
)

// AssignmentEngineService orchestrates all training assignment operations
type AssignmentEngineService struct {
	riskBasedService   *RiskBasedAssignmentService
	userRiskRepo       repository.UserRiskProfileRepository
	assignmentRepo     repository.TrainingAssignmentRepository
	eventPublisher     events.Publisher
	cache              cache.Cache
	logger             *logrus.Logger
	config             *EngineConfig
	mu                 sync.RWMutex
	activeJobs         map[uuid.UUID]*AssignmentJob
}

// EngineConfig holds configuration for the assignment engine
type EngineConfig struct {
	MaxConcurrentAssignments int           `json:"max_concurrent_assignments"`
	BatchSize                int           `json:"batch_size"`
	ProcessingTimeout        time.Duration `json:"processing_timeout"`
	RetryAttempts            int           `json:"retry_attempts"`
	RetryDelay              time.Duration `json:"retry_delay"`
	CacheExpiration         time.Duration `json:"cache_expiration"`
	NotificationEnabled     bool          `json:"notification_enabled"`
	AuditingEnabled         bool          `json:"auditing_enabled"`
}

// DefaultEngineConfig returns default configuration
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		MaxConcurrentAssignments: 100,
		BatchSize:                50,
		ProcessingTimeout:        time.Minute * 10,
		RetryAttempts:            3,
		RetryDelay:              time.Second * 5,
		CacheExpiration:         time.Minute * 15,
		NotificationEnabled:     true,
		AuditingEnabled:         true,
	}
}

// AssignmentJob represents a running assignment job
type AssignmentJob struct {
	JobID          uuid.UUID              `json:"job_id"`
	TenantID       uuid.UUID              `json:"tenant_id"`
	JobType        string                 `json:"job_type"`
	Status         string                 `json:"status"`
	StartedAt      time.Time              `json:"started_at"`
	CompletedAt    *time.Time             `json:"completed_at"`
	TotalUsers     int                    `json:"total_users"`
	ProcessedUsers int                    `json:"processed_users"`
	SuccessCount   int                    `json:"success_count"`
	ErrorCount     int                    `json:"error_count"`
	Errors         []string               `json:"errors"`
	Context        map[string]interface{} `json:"context"`
}

// NewAssignmentEngineService creates a new assignment engine service
func NewAssignmentEngineService(
	riskBasedService *RiskBasedAssignmentService,
	userRiskRepo repository.UserRiskProfileRepository,
	assignmentRepo repository.TrainingAssignmentRepository,
	eventPublisher events.Publisher,
	cache cache.Cache,
	config *EngineConfig,
) *AssignmentEngineService {
	if config == nil {
		config = DefaultEngineConfig()
	}

	return &AssignmentEngineService{
		riskBasedService: riskBasedService,
		userRiskRepo:     userRiskRepo,
		assignmentRepo:   assignmentRepo,
		eventPublisher:   eventPublisher,
		cache:            cache,
		logger:           logger.GetLogger("assignment-engine"),
		config:           config,
		activeJobs:       make(map[uuid.UUID]*AssignmentJob),
	}
}

// BulkAssignmentRequest represents a bulk training assignment request
type BulkAssignmentRequest struct {
	TenantID              uuid.UUID                `json:"tenant_id" validate:"required"`
	UserIDs               []uuid.UUID              `json:"user_ids,omitempty"`
	Filters               *UserFilterCriteria      `json:"filters,omitempty"`
	TrainingModuleID      uuid.UUID                `json:"training_module_id" validate:"required"`
	TrainingType          string                   `json:"training_type" validate:"required"`
	Priority              entity.TrainingPriority  `json:"priority"`
	DueDate               time.Time                `json:"due_date" validate:"required"`
	AssignedBy            uuid.UUID                `json:"assigned_by" validate:"required"`
	AssignmentReason      string                   `json:"assignment_reason" validate:"required"`
	ScheduledStart        *time.Time               `json:"scheduled_start,omitempty"`
	ComplianceFrameworks  []string                 `json:"compliance_frameworks,omitempty"`
	NotificationSettings  *NotificationSettings    `json:"notification_settings,omitempty"`
	CustomFields          map[string]interface{}   `json:"custom_fields,omitempty"`
}

// UserFilterCriteria defines criteria for filtering users for bulk assignments
type UserFilterCriteria struct {
	Departments         []string                 `json:"departments,omitempty"`
	JobTitles          []string                 `json:"job_titles,omitempty"`
	SecurityClearances []string                 `json:"security_clearances,omitempty"`
	RiskLevels         []entity.RiskLevel       `json:"risk_levels,omitempty"`
	MinRiskScore       *int                     `json:"min_risk_score,omitempty"`
	MaxRiskScore       *int                     `json:"max_risk_score,omitempty"`
	TrainingStatus     []string                 `json:"training_status,omitempty"`
	ComplianceFramework string                  `json:"compliance_framework,omitempty"`
	ExcludeUserIDs     []uuid.UUID              `json:"exclude_user_ids,omitempty"`
	IncludeInactive    bool                     `json:"include_inactive"`
}

// NotificationSettings defines notification preferences for assignments
type NotificationSettings struct {
	EmailEnabled           bool          `json:"email_enabled"`
	SMSEnabled             bool          `json:"sms_enabled"`
	InAppEnabled           bool          `json:"in_app_enabled"`
	ReminderDays           []int         `json:"reminder_days"`
	EscalationEnabled      bool          `json:"escalation_enabled"`
	EscalationDays         int           `json:"escalation_days"`
	ManagerNotification    bool          `json:"manager_notification"`
	CustomMessage          string        `json:"custom_message,omitempty"`
}

// ProcessBulkAssignment processes bulk training assignments
func (s *AssignmentEngineService) ProcessBulkAssignment(ctx context.Context, req *BulkAssignmentRequest) (*AssignmentJob, error) {
	s.logger.WithFields(logrus.Fields{
		"tenant_id":     req.TenantID,
		"training_type": req.TrainingType,
		"user_count":    len(req.UserIDs),
	}).Info("Starting bulk assignment processing")

	// Create assignment job
	job := &AssignmentJob{
		JobID:     uuid.New(),
		TenantID:  req.TenantID,
		JobType:   "bulk_assignment",
		Status:    "running",
		StartedAt: time.Now(),
		Context: map[string]interface{}{
			"training_type":   req.TrainingType,
			"training_module": req.TrainingModuleID,
			"priority":       req.Priority,
		},
	}

	// Register job
	s.mu.Lock()
	s.activeJobs[job.JobID] = job
	s.mu.Unlock()

	// Process in background
	go s.processBulkAssignmentJob(ctx, job, req)

	return job, nil
}

// processBulkAssignmentJob processes a bulk assignment job
func (s *AssignmentEngineService) processBulkAssignmentJob(ctx context.Context, job *AssignmentJob, req *BulkAssignmentRequest) {
	defer func() {
		job.CompletedAt = &[]time.Time{time.Now()}[0]
		job.Status = "completed"
		
		// Publish job completion event
		s.eventPublisher.Publish(ctx, "training.bulk_assignment.completed", job)
		
		// Remove from active jobs after delay
		time.AfterFunc(time.Hour, func() {
			s.mu.Lock()
			delete(s.activeJobs, job.JobID)
			s.mu.Unlock()
		})
	}()

	// Get target users
	users, err := s.getTargetUsers(ctx, req)
	if err != nil {
		job.Status = "failed"
		job.Errors = append(job.Errors, fmt.Sprintf("Failed to get target users: %v", err))
		return
	}

	job.TotalUsers = len(users)

	// Process users in batches
	sem := make(chan struct{}, s.config.MaxConcurrentAssignments)
	var wg sync.WaitGroup

	for i := 0; i < len(users); i += s.config.BatchSize {
		end := i + s.config.BatchSize
		if end > len(users) {
			end = len(users)
		}

		batch := users[i:end]

		sem <- struct{}{}
		wg.Add(1)

		go func(userBatch []*entity.UserRiskProfile) {
			defer func() {
				<-sem
				wg.Done()
			}()

			s.processBatch(ctx, job, req, userBatch)
		}(batch)
	}

	wg.Wait()

	s.logger.WithFields(logrus.Fields{
		"job_id":         job.JobID,
		"total_users":    job.TotalUsers,
		"processed":      job.ProcessedUsers,
		"success_count":  job.SuccessCount,
		"error_count":    job.ErrorCount,
	}).Info("Bulk assignment job completed")
}

// processBatch processes a batch of users for assignment
func (s *AssignmentEngineService) processBatch(ctx context.Context, job *AssignmentJob, req *BulkAssignmentRequest, users []*entity.UserRiskProfile) {
	assignments := make([]*entity.TrainingAssignment, 0, len(users))

	for _, user := range users {
		assignment := s.createBulkAssignment(user, req)
		if assignment != nil {
			assignments = append(assignments, assignment)
		}

		s.mu.Lock()
		job.ProcessedUsers++
		s.mu.Unlock()
	}

	// Save assignments in batch
	if len(assignments) > 0 {
		if err := s.assignmentRepo.CreateBatch(ctx, assignments); err != nil {
			s.mu.Lock()
			job.ErrorCount += len(assignments)
			job.Errors = append(job.Errors, fmt.Sprintf("Failed to create batch assignments: %v", err))
			s.mu.Unlock()
			return
		}

		s.mu.Lock()
		job.SuccessCount += len(assignments)
		s.mu.Unlock()

		// Send notifications if enabled
		if req.NotificationSettings != nil && s.config.NotificationEnabled {
			s.sendBulkNotifications(ctx, assignments, req.NotificationSettings)
		}
	}
}

// getTargetUsers gets the target users based on request criteria
func (s *AssignmentEngineService) getTargetUsers(ctx context.Context, req *BulkAssignmentRequest) ([]*entity.UserRiskProfile, error) {
	// If specific user IDs provided, use those
	if len(req.UserIDs) > 0 {
		users := make([]*entity.UserRiskProfile, 0, len(req.UserIDs))
		for _, userID := range req.UserIDs {
			user, err := s.userRiskRepo.GetByUserID(ctx, req.TenantID, userID)
			if err != nil {
				continue // Skip users not found
			}
			users = append(users, user)
		}
		return users, nil
	}

	// Use filters to get users
	return s.getUsersByFilters(ctx, req.TenantID, req.Filters)
}

// getUsersByFilters gets users based on filter criteria
func (s *AssignmentEngineService) getUsersByFilters(ctx context.Context, tenantID uuid.UUID, filters *UserFilterCriteria) ([]*entity.UserRiskProfile, error) {
	if filters == nil {
		// Get all users if no filters
		return s.userRiskRepo.GetByTenantID(ctx, tenantID, 10000, 0) // Large limit
	}

	var users []*entity.UserRiskProfile
	var err error

	// Apply filters sequentially - in a production system, this would be optimized
	// with a more sophisticated query builder

	if len(filters.Departments) > 0 {
		for _, dept := range filters.Departments {
			deptUsers, err := s.userRiskRepo.GetProfilesByDepartment(ctx, tenantID, dept)
			if err != nil {
				continue
			}
			users = append(users, deptUsers...)
		}
	} else if len(filters.SecurityClearances) > 0 {
		for _, clearance := range filters.SecurityClearances {
			clearanceUsers, err := s.userRiskRepo.GetProfilesBySecurityClearance(ctx, tenantID, clearance)
			if err != nil {
				continue
			}
			users = append(users, clearanceUsers...)
		}
	} else {
		// Get all users and filter in memory (not optimal for large datasets)
		users, err = s.userRiskRepo.GetByTenantID(ctx, tenantID, 10000, 0)
		if err != nil {
			return nil, err
		}
	}

	// Apply additional filters
	filteredUsers := make([]*entity.UserRiskProfile, 0)
	for _, user := range users {
		if s.matchesFilters(user, filters) {
			filteredUsers = append(filteredUsers, user)
		}
	}

	return filteredUsers, nil
}

// matchesFilters checks if a user matches the filter criteria
func (s *AssignmentEngineService) matchesFilters(user *entity.UserRiskProfile, filters *UserFilterCriteria) bool {
	if !filters.IncludeInactive && !user.IsActive {
		return false
	}

	// Check exclude list
	for _, excludeID := range filters.ExcludeUserIDs {
		if user.UserID == excludeID {
			return false
		}
	}

	// Check job titles
	if len(filters.JobTitles) > 0 {
		found := false
		for _, title := range filters.JobTitles {
			if user.JobTitle == title {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check risk score range
	if filters.MinRiskScore != nil && user.OverallRiskScore < *filters.MinRiskScore {
		return false
	}
	if filters.MaxRiskScore != nil && user.OverallRiskScore > *filters.MaxRiskScore {
		return false
	}

	// Check risk levels
	if len(filters.RiskLevels) > 0 {
		userRiskLevel := user.GetRiskLevel()
		found := false
		for _, level := range filters.RiskLevels {
			if userRiskLevel == level {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check training status
	if len(filters.TrainingStatus) > 0 {
		found := false
		for _, status := range filters.TrainingStatus {
			if user.TrainingStatus == status {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// createBulkAssignment creates a training assignment for bulk processing
func (s *AssignmentEngineService) createBulkAssignment(user *entity.UserRiskProfile, req *BulkAssignmentRequest) *entity.TrainingAssignment {
	assignment := &entity.TrainingAssignment{
		AssignmentID:       uuid.New(),
		TenantID:           req.TenantID,
		UserID:             user.UserID,
		ProfileID:          user.ProfileID,
		TrainingModuleID:   req.TrainingModuleID,
		TrainingType:       req.TrainingType,
		TrainingCategory:   "mandatory",
		DifficultyLevel:    s.getDifficultyForUser(user),
		AssignmentReason:   req.AssignmentReason,
		Priority:           req.Priority,
		AssignedBy:         req.AssignedBy,
		AssignedByType:     "administrator",
		AssignmentMethod:   "bulk_assignment",
		AssignedAt:         time.Now(),
		ScheduledStart:     req.ScheduledStart,
		DueDate:            req.DueDate,
		EstimatedDuration:  s.getEstimatedDurationForType(req.TrainingType),
		Status:             "assigned",
		Progress:           0,
		RequiresAssessment: true,
		PassingScore:       80.0,
		MaxAttempts:        3,
		AllowedExtensions:  1,
		SecurityClearanceRequired: user.SecurityClearance,
		ComplianceFrameworks: req.ComplianceFrameworks,
		DeliveryMethod:       "web_portal",
		LanguageCode:         user.LanguagePreference,
		TimeZone:            user.TimeZone,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		Version:             1,
		IsActive:            true,
	}

	// Add custom fields if provided
	if len(req.CustomFields) > 0 {
		customFieldsJSON, _ := json.Marshal(req.CustomFields)
		assignment.CustomFields = string(customFieldsJSON)
	}

	return assignment
}

// ProcessScheduledAssignments processes scheduled training assignments
func (s *AssignmentEngineService) ProcessScheduledAssignments(ctx context.Context, tenantID uuid.UUID) error {
	s.logger.WithField("tenant_id", tenantID).Info("Processing scheduled assignments")

	// Get users requiring training assessment
	users, err := s.userRiskRepo.GetProfilesRequiringImmediateTraining(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get users requiring training: %w", err)
	}

	processed := 0
	for _, user := range users {
		assignmentReq := &AssignmentRequest{
			TenantID:         tenantID,
			UserID:           user.UserID,
			AssignedBy:       uuid.MustParse("00000000-0000-0000-0000-000000000000"), // System user
			AssignmentReason: "Scheduled risk assessment",
		}

		if _, err := s.riskBasedService.ProcessRiskBasedAssignment(ctx, assignmentReq); err != nil {
			s.logger.WithError(err).WithField("user_id", user.UserID).Error("Failed to process scheduled assignment")
			continue
		}

		processed++
	}

	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"processed": processed,
		"total":     len(users),
	}).Info("Completed scheduled assignment processing")

	return nil
}

// GetJobStatus returns the status of an assignment job
func (s *AssignmentEngineService) GetJobStatus(jobID uuid.UUID) (*AssignmentJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, exists := s.activeJobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found")
	}

	return job, nil
}

// Helper methods
func (s *AssignmentEngineService) getDifficultyForUser(user *entity.UserRiskProfile) string {
	switch user.GetRiskLevel() {
	case entity.RiskLevelCritical:
		return "expert"
	case entity.RiskLevelHigh:
		return "advanced"
	case entity.RiskLevelModerate:
		return "intermediate"
	default:
		return "beginner"
	}
}

func (s *AssignmentEngineService) getEstimatedDurationForType(trainingType string) int {
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
	return 45
}

func (s *AssignmentEngineService) sendBulkNotifications(ctx context.Context, assignments []*entity.TrainingAssignment, settings *NotificationSettings) {
	// This would integrate with the notification service
	// For now, just log the intent
	s.logger.WithField("assignment_count", len(assignments)).Info("Sending bulk assignment notifications")
	
	for _, assignment := range assignments {
		notification := map[string]interface{}{
			"type":           "training_assignment",
			"user_id":        assignment.UserID,
			"assignment_id":  assignment.AssignmentID,
			"training_type":  assignment.TrainingType,
			"due_date":       assignment.DueDate,
			"email_enabled":  settings.EmailEnabled,
			"sms_enabled":    settings.SMSEnabled,
		}
		
		s.eventPublisher.Publish(ctx, "notification.training.assigned", notification)
	}
}