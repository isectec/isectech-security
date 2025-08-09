// iSECTECH Security Awareness Training Service - Training Assignment Entity
// Production-grade training assignment and lifecycle management
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package entity

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TrainingAssignment represents a specific training assigned to a user
// Integrates with iSECTECH's compliance and security clearance requirements
type TrainingAssignment struct {
	// Primary identifiers
	AssignmentID uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"assignment_id"`
	TenantID     uuid.UUID `gorm:"not null;index:idx_training_assignment_tenant" json:"tenant_id"`
	UserID       uuid.UUID `gorm:"not null;index:idx_training_assignment_user" json:"user_id"`
	ProfileID    uuid.UUID `gorm:"not null;index:idx_training_assignment_profile" json:"profile_id"`

	// Training information
	TrainingModuleID   uuid.UUID `gorm:"not null;index:idx_training_assignment_module" json:"training_module_id"`
	ModuleName         string    `gorm:"not null;size:255" json:"module_name"`
	ModuleVersion      string    `gorm:"not null;size:50" json:"module_version"`
	TrainingType       string    `gorm:"not null;size:100" json:"training_type" validate:"required,oneof=awareness_training phishing_simulation assessment compliance_training incident_response security_policy"`
	TrainingCategory   string    `gorm:"not null;size:100" json:"training_category" validate:"required,oneof=mandatory optional remedial refresher certification"`
	DifficultyLevel    string    `gorm:"not null;size:50" json:"difficulty_level" validate:"required,oneof=beginner intermediate advanced expert"`

	// Assignment details
	AssignmentReason   string         `gorm:"not null;size:500" json:"assignment_reason"`
	TriggerEvent       string         `gorm:"size:255" json:"trigger_event"` // Security incident ID, risk score change, etc.
	Priority           TrainingPriority `gorm:"not null;default:standard" json:"priority" validate:"required,oneof=low standard high immediate"`
	AssignedBy         uuid.UUID      `gorm:"not null" json:"assigned_by"`
	AssignedByType     string         `gorm:"not null;size:50" json:"assigned_by_type" validate:"required,oneof=system administrator manager compliance_officer"`
	AssignmentMethod   string         `gorm:"not null;size:50" json:"assignment_method" validate:"required,oneof=risk_based incident_triggered scheduled_refresh compliance_required manual"`

	// Scheduling and deadlines
	AssignedAt       time.Time  `gorm:"default:now()" json:"assigned_at"`
	ScheduledStart   *time.Time `json:"scheduled_start"`
	DueDate          time.Time  `gorm:"not null" json:"due_date"`
	EstimatedDuration int       `gorm:"not null" json:"estimated_duration_minutes"`
	AllowedExtensions int       `gorm:"not null;default:1" json:"allowed_extensions"`
	ExtensionsUsed   int        `gorm:"not null;default:0" json:"extensions_used"`

	// Status and progress
	Status            string    `gorm:"not null;default:assigned" json:"status" validate:"required,oneof=assigned notified started in_progress completed passed failed expired cancelled"`
	Progress          int       `gorm:"not null;default:0;check:progress BETWEEN 0 AND 100" json:"progress"`
	StartedAt         *time.Time `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	LastAccessedAt    *time.Time `json:"last_accessed_at"`
	TimeSpentMinutes  int       `gorm:"not null;default:0" json:"time_spent_minutes"`

	// Assessment and scoring
	RequiresAssessment bool    `gorm:"not null;default:false" json:"requires_assessment"`
	AssessmentScore    float64 `gorm:"check:assessment_score BETWEEN 0 AND 100" json:"assessment_score"`
	PassingScore       float64 `gorm:"not null;default:80" json:"passing_score"`
	AttemptCount       int     `gorm:"not null;default:0" json:"attempt_count"`
	MaxAttempts        int     `gorm:"not null;default:3" json:"max_attempts"`
	IsPassed           bool    `gorm:"not null;default:false" json:"is_passed"`

	// Security and compliance
	SecurityClearanceRequired string         `gorm:"size:50" json:"security_clearance_required" validate:"omitempty,oneof=unclassified confidential secret top_secret"`
	ComplianceFrameworks      pq.StringArray `gorm:"type:text[]" json:"compliance_frameworks"`
	RegulatoryRequirements    string         `gorm:"type:jsonb;default:'{}'" json:"regulatory_requirements"`
	AuditRequired             bool           `gorm:"not null;default:false" json:"audit_required"`
	AuditTrail                string         `gorm:"type:jsonb;default:'[]'" json:"audit_trail"`

	// Personalization and delivery
	DeliveryMethod       string         `gorm:"not null;size:50" json:"delivery_method" validate:"required,oneof=web_portal mobile_app email_link sms_link embedded_widget"`
	LanguageCode         string         `gorm:"not null;size:10;default:en" json:"language_code"`
	TimeZone             string         `gorm:"not null;size:50;default:UTC" json:"timezone"`
	PreferredTimeSlots   pq.StringArray `gorm:"type:text[]" json:"preferred_time_slots"`
	NotificationSettings string         `gorm:"type:jsonb;default:'{}'" json:"notification_settings"`
	PersonalizationData  string         `gorm:"type:jsonb;default:'{}'" json:"personalization_data"`

	// Performance tracking
	InteractionMetrics   string `gorm:"type:jsonb;default:'{}'" json:"interaction_metrics"`
	LearningPathPosition int    `gorm:"not null;default:1" json:"learning_path_position"`
	PreviousAttempts     string `gorm:"type:jsonb;default:'[]'" json:"previous_attempts"`
	PerformanceMetrics   string `gorm:"type:jsonb;default:'{}'" json:"performance_metrics"`

	// Notifications and reminders
	NotificationsSent    int            `gorm:"not null;default:0" json:"notifications_sent"`
	LastNotificationSent *time.Time     `json:"last_notification_sent"`
	ReminderSchedule     pq.StringArray `gorm:"type:text[]" json:"reminder_schedule"`
	EscalationLevel      int            `gorm:"not null;default:0" json:"escalation_level"`
	ManagerNotified      bool           `gorm:"not null;default:false" json:"manager_notified"`

	// Integration and external systems
	LMSAssignmentID   string `gorm:"size:255" json:"lms_assignment_id"`
	ExternalSystemID  string `gorm:"size:255" json:"external_system_id"`
	IntegrationData   string `gorm:"type:jsonb;default:'{}'" json:"integration_data"`
	SyncStatus        string `gorm:"size:50;default:synced" json:"sync_status" validate:"omitempty,oneof=synced pending failed"`
	LastSyncedAt      *time.Time `json:"last_synced_at"`

	// Metadata and lifecycle
	CreatedAt     time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt     time.Time  `gorm:"default:now()" json:"updated_at"`
	Version       int        `gorm:"not null;default:1" json:"version"`
	IsActive      bool       `gorm:"default:true" json:"is_active"`
	DeactivatedAt *time.Time `json:"deactivated_at"`
	ArchiveDate   *time.Time `json:"archive_date"`
	RetentionDate *time.Time `json:"retention_date"`

	// Analytics and reporting
	CompletionMetrics string         `gorm:"type:jsonb;default:'{}'" json:"completion_metrics"`
	FeedbackData      string         `gorm:"type:jsonb;default:'{}'" json:"feedback_data"`
	Tags              pq.StringArray `gorm:"type:text[]" json:"tags"`
	CustomFields      string         `gorm:"type:jsonb;default:'{}'" json:"custom_fields"`
	Notes             string         `gorm:"type:text" json:"notes"`
}

// AssignmentStatus represents the current status of a training assignment
type AssignmentStatus string

const (
	StatusAssigned    AssignmentStatus = "assigned"
	StatusNotified    AssignmentStatus = "notified"
	StatusStarted     AssignmentStatus = "started"
	StatusInProgress  AssignmentStatus = "in_progress"
	StatusCompleted   AssignmentStatus = "completed"
	StatusPassed      AssignmentStatus = "passed"
	StatusFailed      AssignmentStatus = "failed"
	StatusExpired     AssignmentStatus = "expired"
	StatusCancelled   AssignmentStatus = "cancelled"
)

// IsOverdue checks if the assignment is past its due date
func (ta *TrainingAssignment) IsOverdue() bool {
	return time.Now().After(ta.DueDate) && ta.Status != "completed" && ta.Status != "passed"
}

// GetDaysUntilDue calculates days remaining until due date
func (ta *TrainingAssignment) GetDaysUntilDue() int {
	duration := time.Until(ta.DueDate)
	return int(duration.Hours() / 24)
}

// CanStartTraining checks if user can start the training
func (ta *TrainingAssignment) CanStartTraining() bool {
	now := time.Now()
	
	// Check if assignment is active and not expired
	if !ta.IsActive || ta.Status == "completed" || ta.Status == "passed" || ta.Status == "cancelled" {
		return false
	}

	// Check if scheduled start time has passed
	if ta.ScheduledStart != nil && now.Before(*ta.ScheduledStart) {
		return false
	}

	// Check if not overdue (with grace period)
	gracePeriod := time.Hour * 24 // 1 day grace period
	if now.After(ta.DueDate.Add(gracePeriod)) {
		return false
	}

	return true
}

// UpdateProgress updates the training progress and timestamps
func (ta *TrainingAssignment) UpdateProgress(progress int) error {
	if progress < 0 || progress > 100 {
		return fmt.Errorf("progress must be between 0 and 100")
	}

	ta.Progress = progress
	ta.LastAccessedAt = &[]time.Time{time.Now()}[0]
	ta.UpdatedAt = time.Now()

	// Update status based on progress
	switch {
	case progress == 0 && ta.Status == "assigned":
		// Keep as assigned
	case progress > 0 && progress < 100:
		if ta.Status == "assigned" || ta.Status == "notified" {
			ta.Status = "started"
			ta.StartedAt = &[]time.Time{time.Now()}[0]
		} else if ta.Status == "started" {
			ta.Status = "in_progress"
		}
	case progress == 100:
		ta.Status = "completed"
		ta.CompletedAt = &[]time.Time{time.Now()}[0]
	}

	return nil
}

// MarkAsPassed marks the assignment as passed with score
func (ta *TrainingAssignment) MarkAsPassed(score float64) {
	ta.AssessmentScore = score
	ta.IsPassed = true
	ta.Status = "passed"
	ta.Progress = 100
	ta.CompletedAt = &[]time.Time{time.Now()}[0]
	ta.UpdatedAt = time.Now()
}

// MarkAsFailed marks the assignment as failed
func (ta *TrainingAssignment) MarkAsFailed(score float64) {
	ta.AssessmentScore = score
	ta.IsPassed = false
	ta.Status = "failed"
	ta.AttemptCount++
	ta.UpdatedAt = time.Now()
}

// CanRetry checks if user can retry the training
func (ta *TrainingAssignment) CanRetry() bool {
	return ta.Status == "failed" && ta.AttemptCount < ta.MaxAttempts && !ta.IsOverdue()
}

// RequestExtension attempts to extend the due date
func (ta *TrainingAssignment) RequestExtension(days int, reason string) error {
	if ta.ExtensionsUsed >= ta.AllowedExtensions {
		return fmt.Errorf("maximum extensions (%d) already used", ta.AllowedExtensions)
	}

	if days <= 0 || days > 30 {
		return fmt.Errorf("extension days must be between 1 and 30")
	}

	ta.DueDate = ta.DueDate.AddDate(0, 0, days)
	ta.ExtensionsUsed++
	ta.UpdatedAt = time.Now()

	// Add to audit trail
	auditEntry := map[string]interface{}{
		"action":    "extension_granted",
		"days":      days,
		"reason":    reason,
		"timestamp": time.Now(),
		"new_due_date": ta.DueDate,
	}
	ta.AddAuditEntry(auditEntry)

	return nil
}

// AddAuditEntry adds an entry to the audit trail
func (ta *TrainingAssignment) AddAuditEntry(entry map[string]interface{}) {
	var auditTrail []map[string]interface{}
	
	if ta.AuditTrail != "" && ta.AuditTrail != "[]" {
		json.Unmarshal([]byte(ta.AuditTrail), &auditTrail)
	}

	auditTrail = append(auditTrail, entry)
	
	// Limit audit trail to last 50 entries
	if len(auditTrail) > 50 {
		auditTrail = auditTrail[len(auditTrail)-50:]
	}

	auditData, _ := json.Marshal(auditTrail)
	ta.AuditTrail = string(auditData)
	ta.UpdatedAt = time.Now()
}

// GetComplianceRequirements returns compliance-specific requirements
func (ta *TrainingAssignment) GetComplianceRequirements() map[string]interface{} {
	var requirements map[string]interface{}
	if ta.RegulatoryRequirements != "" {
		json.Unmarshal([]byte(ta.RegulatoryRequirements), &requirements)
	}
	if requirements == nil {
		requirements = make(map[string]interface{})
	}
	return requirements
}

// GetNotificationSettings returns notification configuration
func (ta *TrainingAssignment) GetNotificationSettings() map[string]interface{} {
	var settings map[string]interface{}
	if ta.NotificationSettings != "" {
		json.Unmarshal([]byte(ta.NotificationSettings), &settings)
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}
	return settings
}

// ShouldSendReminder determines if a reminder should be sent
func (ta *TrainingAssignment) ShouldSendReminder() bool {
	if ta.Status == "completed" || ta.Status == "passed" || ta.Status == "cancelled" {
		return false
	}

	// Send reminder if due in 3 days or less and no recent notification
	daysUntilDue := ta.GetDaysUntilDue()
	if daysUntilDue <= 3 && daysUntilDue > 0 {
		if ta.LastNotificationSent == nil {
			return true
		}
		
		// Send reminder if last notification was more than 24 hours ago
		return time.Since(*ta.LastNotificationSent).Hours() >= 24
	}

	// Send overdue reminder
	if ta.IsOverdue() {
		if ta.LastNotificationSent == nil {
			return true
		}
		
		// Send overdue reminder every 48 hours
		return time.Since(*ta.LastNotificationSent).Hours() >= 48
	}

	return false
}

// GetEscalationLevel determines current escalation level
func (ta *TrainingAssignment) GetEscalationLevel() int {
	if ta.IsOverdue() {
		daysOverdue := -ta.GetDaysUntilDue()
		switch {
		case daysOverdue >= 14:
			return 3 // Executive escalation
		case daysOverdue >= 7:
			return 2 // Manager escalation
		case daysOverdue >= 3:
			return 1 // Supervisor escalation
		default:
			return 0 // No escalation
		}
	}
	return 0
}

// CalculateCompletionRate calculates completion rate for analytics
func (ta *TrainingAssignment) CalculateCompletionRate() float64 {
	if ta.EstimatedDuration == 0 {
		return 0
	}
	
	expectedTime := float64(ta.EstimatedDuration)
	actualTime := float64(ta.TimeSpentMinutes)
	
	if actualTime == 0 {
		return 0
	}
	
	// Rate of progress per minute
	progressRate := float64(ta.Progress) / actualTime
	
	// Expected completion rate
	expectedRate := 100.0 / expectedTime
	
	return (progressRate / expectedRate) * 100
}

// IsHighPriority checks if assignment is high priority
func (ta *TrainingAssignment) IsHighPriority() bool {
	return ta.Priority == TrainingPriorityHigh || ta.Priority == TrainingPriorityImmediate
}

// TableName sets the table name for GORM
func (TrainingAssignment) TableName() string {
	return "training_assignments"
}