// iSECTECH Security Awareness Training Service - Training Assignment Repository
// Production-grade data access layer with multi-tenant security
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
)

// TrainingAssignmentRepository defines the interface for training assignment data access
type TrainingAssignmentRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, assignment *entity.TrainingAssignment) error
	GetByID(ctx context.Context, assignmentID uuid.UUID) (*entity.TrainingAssignment, error)
	Update(ctx context.Context, assignment *entity.TrainingAssignment) error
	Delete(ctx context.Context, assignmentID uuid.UUID) error

	// Multi-tenant operations
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*entity.TrainingAssignment, error)
	CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int64, error)

	// User-specific queries
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetActiveAssignmentsByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetPendingAssignmentsByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetCompletedAssignmentsByUserID(ctx context.Context, tenantID, userID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Status-based queries
	GetByStatus(ctx context.Context, tenantID uuid.UUID, status string) ([]*entity.TrainingAssignment, error)
	GetAssignmentsRequiringAction(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetOverdueAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetExpiringAssignments(ctx context.Context, tenantID uuid.UUID, days int) ([]*entity.TrainingAssignment, error)

	// Priority and urgency queries
	GetHighPriorityAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetImmediateAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetAssignmentsByPriority(ctx context.Context, tenantID uuid.UUID, priority entity.TrainingPriority) ([]*entity.TrainingAssignment, error)

	// Training module and type queries
	GetByModuleID(ctx context.Context, tenantID, moduleID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetByTrainingType(ctx context.Context, tenantID uuid.UUID, trainingType string) ([]*entity.TrainingAssignment, error)
	GetByTrainingCategory(ctx context.Context, tenantID uuid.UUID, category string) ([]*entity.TrainingAssignment, error)

	// Assignment method and trigger queries
	GetByAssignmentMethod(ctx context.Context, tenantID uuid.UUID, method string) ([]*entity.TrainingAssignment, error)
	GetByTriggerEvent(ctx context.Context, tenantID uuid.UUID, triggerEvent string) ([]*entity.TrainingAssignment, error)
	GetRiskBasedAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetIncidentTriggeredAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Security clearance and compliance queries
	GetBySecurityClearance(ctx context.Context, tenantID uuid.UUID, clearance string) ([]*entity.TrainingAssignment, error)
	GetByComplianceFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.TrainingAssignment, error)
	GetRequiringAudit(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Progress and performance tracking
	GetInProgressAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetFailedAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetAssignmentsWithLowProgress(ctx context.Context, tenantID uuid.UUID, progressThreshold int) ([]*entity.TrainingAssignment, error)
	GetAssignmentsExceedingTimeLimit(ctx context.Context, tenantID uuid.UUID, timeThreshold int) ([]*entity.TrainingAssignment, error)

	// Notification and reminder queries
	GetAssignmentsNeedingReminders(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetAssignmentsForEscalation(ctx context.Context, tenantID uuid.UUID, escalationLevel int) ([]*entity.TrainingAssignment, error)
	GetUnnotifiedAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Assessment and scoring queries
	GetRequiringAssessment(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetFailedAssessments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetRetryableAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)
	GetAssignmentsByScoreRange(ctx context.Context, tenantID uuid.UUID, minScore, maxScore float64) ([]*entity.TrainingAssignment, error)

	// Time-based queries
	GetAssignmentsByDateRange(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) ([]*entity.TrainingAssignment, error)
	GetAssignmentsDueInDays(ctx context.Context, tenantID uuid.UUID, days int) ([]*entity.TrainingAssignment, error)
	GetAssignmentsCompletedInPeriod(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) ([]*entity.TrainingAssignment, error)

	// External system integration
	GetBySyncStatus(ctx context.Context, tenantID uuid.UUID, syncStatus string) ([]*entity.TrainingAssignment, error)
	GetByExternalSystemID(ctx context.Context, tenantID uuid.UUID, systemID string) (*entity.TrainingAssignment, error)
	GetPendingSyncAssignments(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Batch operations
	CreateBatch(ctx context.Context, assignments []*entity.TrainingAssignment) error
	UpdateBatch(ctx context.Context, assignments []*entity.TrainingAssignment) error
	UpdateProgressBatch(ctx context.Context, updates []ProgressUpdate) error
	UpdateStatusBatch(ctx context.Context, updates []StatusUpdate) error

	// Analytics and reporting operations
	GetCompletionStats(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) (*CompletionStats, error)
	GetAssignmentMetrics(ctx context.Context, tenantID uuid.UUID) (*AssignmentMetrics, error)
	GetPerformanceMetrics(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) (*PerformanceMetrics, error)
	GetComplianceMetrics(ctx context.Context, tenantID uuid.UUID) (*ComplianceMetrics, error)

	// Department and organizational queries
	GetByDepartment(ctx context.Context, tenantID uuid.UUID, department string) ([]*entity.TrainingAssignment, error)
	GetByJobTitle(ctx context.Context, tenantID uuid.UUID, jobTitle string) ([]*entity.TrainingAssignment, error)
	GetManagerAssignments(ctx context.Context, tenantID, managerID uuid.UUID) ([]*entity.TrainingAssignment, error)

	// Lifecycle and archival operations
	DeactivateAssignment(ctx context.Context, assignmentID uuid.UUID) error
	ArchiveCompletedAssignments(ctx context.Context, tenantID uuid.UUID, completionThreshold time.Time) (int64, error)
	GetAssignmentsForRetention(ctx context.Context, tenantID uuid.UUID, retentionDate time.Time) ([]*entity.TrainingAssignment, error)
	PurgeExpiredAssignments(ctx context.Context, tenantID uuid.UUID, expirationDate time.Time) (int64, error)
}

// ProgressUpdate represents a progress update for batch operations
type ProgressUpdate struct {
	AssignmentID     uuid.UUID `json:"assignment_id"`
	Progress         int       `json:"progress"`
	TimeSpentMinutes int       `json:"time_spent_minutes"`
	LastAccessedAt   time.Time `json:"last_accessed_at"`
}

// StatusUpdate represents a status update for batch operations
type StatusUpdate struct {
	AssignmentID uuid.UUID `json:"assignment_id"`
	Status       string    `json:"status"`
	UpdatedBy    uuid.UUID `json:"updated_by"`
	UpdateReason string    `json:"update_reason,omitempty"`
}

// CompletionStats represents training completion statistics
type CompletionStats struct {
	TenantID             uuid.UUID `json:"tenant_id"`
	Period               string    `json:"period"`
	TotalAssignments     int64     `json:"total_assignments"`
	CompletedAssignments int64     `json:"completed_assignments"`
	FailedAssignments    int64     `json:"failed_assignments"`
	OverdueAssignments   int64     `json:"overdue_assignments"`
	CompletionRate       float64   `json:"completion_rate"`
	AverageCompletionTime float64  `json:"average_completion_time_hours"`
	AverageScore         float64   `json:"average_score"`
}

// AssignmentMetrics represents overall assignment metrics
type AssignmentMetrics struct {
	TenantID                uuid.UUID                    `json:"tenant_id"`
	TotalAssignments        int64                        `json:"total_assignments"`
	ActiveAssignments       int64                        `json:"active_assignments"`
	CompletedAssignments    int64                        `json:"completed_assignments"`
	OverdueAssignments      int64                        `json:"overdue_assignments"`
	HighPriorityAssignments int64                        `json:"high_priority_assignments"`
	StatusDistribution      map[string]int64             `json:"status_distribution"`
	PriorityDistribution    map[string]int64             `json:"priority_distribution"`
	TypeDistribution        map[string]int64             `json:"type_distribution"`
	CompletionTrend         []CompletionTrendPoint       `json:"completion_trend"`
}

// PerformanceMetrics represents performance-related metrics
type PerformanceMetrics struct {
	TenantID                  uuid.UUID `json:"tenant_id"`
	Period                    string    `json:"period"`
	AverageCompletionTime     float64   `json:"average_completion_time_hours"`
	MedianCompletionTime      float64   `json:"median_completion_time_hours"`
	AverageScore              float64   `json:"average_score"`
	MedianScore               float64   `json:"median_score"`
	FirstAttemptPassRate      float64   `json:"first_attempt_pass_rate"`
	RetryRate                 float64   `json:"retry_rate"`
	AverageAttemptsToPass     float64   `json:"average_attempts_to_pass"`
	TimeToCompletionByModule  map[string]float64 `json:"time_to_completion_by_module"`
	ScoreDistributionByModule map[string]float64 `json:"score_distribution_by_module"`
}

// ComplianceMetrics represents compliance-related metrics
type ComplianceMetrics struct {
	TenantID                    uuid.UUID                `json:"tenant_id"`
	FrameworkCompliance         map[string]float64       `json:"framework_compliance"`
	SecurityClearanceCompliance map[string]float64       `json:"security_clearance_compliance"`
	AuditRequiredAssignments    int64                    `json:"audit_required_assignments"`
	AuditCompletedRate          float64                  `json:"audit_completed_rate"`
	RegulatoryCompliance        map[string]*ComplianceStat `json:"regulatory_compliance"`
	OverallComplianceScore      float64                  `json:"overall_compliance_score"`
}

// ComplianceStat represents compliance statistics for a specific regulation
type ComplianceStat struct {
	Regulation       string  `json:"regulation"`
	RequiredTraining int64   `json:"required_training"`
	CompletedTraining int64  `json:"completed_training"`
	ComplianceRate   float64 `json:"compliance_rate"`
	OverdueCount     int64   `json:"overdue_count"`
}

// CompletionTrendPoint represents a point in the completion trend
type CompletionTrendPoint struct {
	Date             time.Time `json:"date"`
	CompletedCount   int64     `json:"completed_count"`
	AssignedCount    int64     `json:"assigned_count"`
	CompletionRate   float64   `json:"completion_rate"`
	AverageScore     float64   `json:"average_score"`
}