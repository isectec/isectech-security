// iSECTECH Security Awareness Training Service - User Risk Profile Repository
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

// UserRiskProfileRepository defines the interface for user risk profile data access
type UserRiskProfileRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, profile *entity.UserRiskProfile) error
	GetByID(ctx context.Context, profileID uuid.UUID) (*entity.UserRiskProfile, error)
	GetByUserID(ctx context.Context, tenantID, userID uuid.UUID) (*entity.UserRiskProfile, error)
	Update(ctx context.Context, profile *entity.UserRiskProfile) error
	Delete(ctx context.Context, profileID uuid.UUID) error

	// Multi-tenant operations
	GetByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*entity.UserRiskProfile, error)
	CountByTenantID(ctx context.Context, tenantID uuid.UUID) (int64, error)

	// Risk-based queries
	GetHighRiskProfiles(ctx context.Context, tenantID uuid.UUID, riskThreshold int) ([]*entity.UserRiskProfile, error)
	GetProfilesByRiskLevel(ctx context.Context, tenantID uuid.UUID, riskLevel entity.RiskLevel) ([]*entity.UserRiskProfile, error)
	GetProfilesRequiringImmediateTraining(ctx context.Context, tenantID uuid.UUID) ([]*entity.UserRiskProfile, error)
	GetOverdueTrainingProfiles(ctx context.Context, tenantID uuid.UUID) ([]*entity.UserRiskProfile, error)

	// Security clearance operations
	GetProfilesBySecurityClearance(ctx context.Context, tenantID uuid.UUID, clearance string) ([]*entity.UserRiskProfile, error)

	// Compliance operations
	GetProfilesByComplianceFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.UserRiskProfile, error)
	GetProfilesWithAuditFlags(ctx context.Context, tenantID uuid.UUID) ([]*entity.UserRiskProfile, error)

	// Risk trend analysis
	GetProfilesWithRiskTrend(ctx context.Context, tenantID uuid.UUID, trend string) ([]*entity.UserRiskProfile, error)
	GetProfilesUpdatedSince(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]*entity.UserRiskProfile, error)

	// Department and role-based queries
	GetProfilesByDepartment(ctx context.Context, tenantID uuid.UUID, department string) ([]*entity.UserRiskProfile, error)
	GetProfilesByJobTitle(ctx context.Context, tenantID uuid.UUID, jobTitle string) ([]*entity.UserRiskProfile, error)

	// Risk factor analysis
	GetProfilesWithRiskFactors(ctx context.Context, tenantID uuid.UUID, riskFactors []string) ([]*entity.UserRiskProfile, error)
	GetProfilesWithSecurityIncidents(ctx context.Context, tenantID uuid.UUID, incidentThreshold int) ([]*entity.UserRiskProfile, error)
	GetProfilesWithPhishingIssues(ctx context.Context, tenantID uuid.UUID, clickRateThreshold float64) ([]*entity.UserRiskProfile, error)

	// Machine learning and prediction support
	GetProfilesForMLTraining(ctx context.Context, tenantID uuid.UUID, limit int) ([]*entity.UserRiskProfile, error)
	UpdateMLPredictions(ctx context.Context, predictions []MLPredictionUpdate) error

	// Batch operations
	CreateBatch(ctx context.Context, profiles []*entity.UserRiskProfile) error
	UpdateBatch(ctx context.Context, profiles []*entity.UserRiskProfile) error
	UpdateRiskScoresBatch(ctx context.Context, updates []RiskScoreUpdate) error

	// Analytics and reporting
	GetRiskDistribution(ctx context.Context, tenantID uuid.UUID) (*RiskDistribution, error)
	GetTrainingCompletionStats(ctx context.Context, tenantID uuid.UUID) (*TrainingStats, error)
	GetComplianceStats(ctx context.Context, tenantID uuid.UUID) (*ComplianceStats, error)

	// Lifecycle management
	DeactivateProfile(ctx context.Context, profileID uuid.UUID, reason string) error
	ArchiveOldProfiles(ctx context.Context, tenantID uuid.UUID, archiveDate time.Time) (int64, error)
	GetProfilesForRetention(ctx context.Context, tenantID uuid.UUID, retentionDate time.Time) ([]*entity.UserRiskProfile, error)
}

// MLPredictionUpdate represents a machine learning prediction update
type MLPredictionUpdate struct {
	ProfileID           uuid.UUID `json:"profile_id"`
	PredictedRiskTrend  string    `json:"predicted_risk_trend"`
	RiskPredictionScore float64   `json:"risk_prediction_score"`
	MLModelVersion      string    `json:"ml_model_version"`
}

// RiskScoreUpdate represents a risk score update for batch operations
type RiskScoreUpdate struct {
	ProfileID            uuid.UUID `json:"profile_id"`
	OverallRiskScore     *int      `json:"overall_risk_score,omitempty"`
	PhishingRiskScore    *int      `json:"phishing_risk_score,omitempty"`
	DataHandlingRiskScore *int     `json:"data_handling_risk_score,omitempty"`
	AccessRiskScore      *int      `json:"access_risk_score,omitempty"`
	ComplianceRiskScore  *int      `json:"compliance_risk_score,omitempty"`
	TrendScore           *float64  `json:"trend_score,omitempty"`
}

// RiskDistribution represents risk level distribution statistics
type RiskDistribution struct {
	TenantID      uuid.UUID `json:"tenant_id"`
	LowRisk       int64     `json:"low_risk"`
	ModerateRisk  int64     `json:"moderate_risk"`
	HighRisk      int64     `json:"high_risk"`
	CriticalRisk  int64     `json:"critical_risk"`
	TotalProfiles int64     `json:"total_profiles"`
}

// TrainingStats represents training completion statistics
type TrainingStats struct {
	TenantID                uuid.UUID `json:"tenant_id"`
	TotalUsers              int64     `json:"total_users"`
	CurrentUsers            int64     `json:"current_users"`
	OverdueUsers            int64     `json:"overdue_users"`
	RequiredUsers           int64     `json:"required_users"`
	ExemptUsers             int64     `json:"exempt_users"`
	AverageCompletionCount  float64   `json:"average_completion_count"`
	AverageFailedAssessments float64  `json:"average_failed_assessments"`
}

// ComplianceStats represents compliance framework statistics
type ComplianceStats struct {
	TenantID           uuid.UUID                    `json:"tenant_id"`
	FrameworkStats     map[string]*FrameworkStat    `json:"framework_stats"`
	SecurityClearance  map[string]int64             `json:"security_clearance"`
	AuditFlaggedUsers  int64                        `json:"audit_flagged_users"`
	TotalCompliantUsers int64                       `json:"total_compliant_users"`
}

// FrameworkStat represents statistics for a specific compliance framework
type FrameworkStat struct {
	Framework     string `json:"framework"`
	TotalUsers    int64  `json:"total_users"`
	CompliantUsers int64 `json:"compliant_users"`
	ComplianceRate float64 `json:"compliance_rate"`
}