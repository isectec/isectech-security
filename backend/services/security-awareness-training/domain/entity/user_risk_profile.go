// iSECTECH Security Awareness Training Service - User Risk Profile Entity
// Production-grade risk assessment and training assignment system
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserRiskProfile represents a user's security risk assessment and training requirements
// Integrates with iSECTECH's security event system for dynamic risk calculation
type UserRiskProfile struct {
	// Primary identifiers
	ProfileID uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"profile_id"`
	UserID    uuid.UUID `gorm:"not null;index:idx_user_risk_profile_user" json:"user_id"`
	TenantID  uuid.UUID `gorm:"not null;index:idx_user_risk_profile_tenant" json:"tenant_id"`

	// User information
	Email             string `gorm:"not null;size:255" json:"email"`
	FirstName         string `gorm:"not null;size:100" json:"first_name"`
	LastName          string `gorm:"not null;size:100" json:"last_name"`
	JobTitle          string `gorm:"size:150" json:"job_title"`
	Department        string `gorm:"size:100" json:"department"`
	SecurityClearance string `gorm:"not null;default:unclassified" json:"security_clearance" validate:"oneof=unclassified confidential secret top_secret"`

	// Risk assessment scores (0-100)
	OverallRiskScore      int     `gorm:"not null;default:50;check:overall_risk_score BETWEEN 0 AND 100" json:"overall_risk_score"`
	PhishingRiskScore     int     `gorm:"not null;default:50;check:phishing_risk_score BETWEEN 0 AND 100" json:"phishing_risk_score"`
	DataHandlingRiskScore int     `gorm:"not null;default:50;check:data_handling_risk_score BETWEEN 0 AND 100" json:"data_handling_risk_score"`
	AccessRiskScore       int     `gorm:"not null;default:50;check:access_risk_score BETWEEN 0 AND 100" json:"access_risk_score"`
	ComplianceRiskScore   int     `gorm:"not null;default:50;check:compliance_risk_score BETWEEN 0 AND 100" json:"compliance_risk_score"`
	TrendScore            float64 `gorm:"not null;default:0" json:"trend_score"` // Positive = improving, negative = degrading

	// Training status and history
	TrainingStatus         string    `gorm:"not null;default:required" json:"training_status" validate:"oneof=current overdue required exempt"`
	LastTrainingDate       *time.Time `json:"last_training_date"`
	NextRequiredTraining   *time.Time `json:"next_required_training"`
	CompletedTrainingCount int       `gorm:"not null;default:0" json:"completed_training_count"`
	FailedAssessmentCount  int       `gorm:"not null;default:0" json:"failed_assessment_count"`

	// Risk factors and incidents
	RecentSecurityIncidents int            `gorm:"not null;default:0" json:"recent_security_incidents"`
	PhishingClickRate       float64        `gorm:"not null;default:0;check:phishing_click_rate BETWEEN 0 AND 100" json:"phishing_click_rate"`
	PolicyViolationCount    int            `gorm:"not null;default:0" json:"policy_violation_count"`
	SuspiciousActivityCount int            `gorm:"not null;default:0" json:"suspicious_activity_count"`
	RiskFactors             pq.StringArray `gorm:"type:text[]" json:"risk_factors"` // e.g., ["high_privilege_access", "external_email", "frequent_travel"]

	// Behavioral analytics
	LoginAnomalies         int     `gorm:"not null;default:0" json:"login_anomalies"`
	DataAccessPatterns     string  `gorm:"type:jsonb;default:'{}'" json:"data_access_patterns"`
	GeographicRiskFactors  string  `gorm:"type:jsonb;default:'{}'" json:"geographic_risk_factors"`
	DeviceRiskFactors      string  `gorm:"type:jsonb;default:'{}'" json:"device_risk_factors"`
	TimeBasedRiskFactors   string  `gorm:"type:jsonb;default:'{}'" json:"time_based_risk_factors"`

	// Compliance and regulatory requirements
	ComplianceFrameworks   pq.StringArray `gorm:"type:text[]" json:"compliance_frameworks"` // SOC2, ISO27001, HIPAA, etc.
	RegulatoryRequirements string         `gorm:"type:jsonb;default:'{}'" json:"regulatory_requirements"`
	AuditFlags             pq.StringArray `gorm:"type:text[]" json:"audit_flags"`

	// Machine learning predictions
	PredictedRiskTrend    string  `gorm:"size:50" json:"predicted_risk_trend" validate:"omitempty,oneof=improving stable degrading"`
	RiskPredictionScore   float64 `gorm:"check:risk_prediction_score BETWEEN 0 AND 100" json:"risk_prediction_score"`
	MLModelVersion        string  `gorm:"size:50" json:"ml_model_version"`
	LastMLPredictionDate  *time.Time `json:"last_ml_prediction_date"`

	// Training personalization
	PreferredLearningStyle string         `gorm:"size:50" json:"preferred_learning_style" validate:"omitempty,oneof=visual auditory kinesthetic reading"`
	LanguagePreference     string         `gorm:"size:10;default:en" json:"language_preference"`
	TimeZone              string         `gorm:"size:50;default:UTC" json:"timezone"`
	TrainingSchedule      string         `gorm:"type:jsonb;default:'{}'" json:"training_schedule"`
	PersonalizationData   string         `gorm:"type:jsonb;default:'{}'" json:"personalization_data"`

	// Audit and lifecycle management
	CreatedAt          time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt          time.Time  `gorm:"default:now()" json:"updated_at"`
	LastRiskUpdate     time.Time  `gorm:"default:now()" json:"last_risk_update"`
	LastActivityDate   *time.Time `json:"last_activity_date"`
	ProfileVersion     int        `gorm:"not null;default:1" json:"profile_version"`
	IsActive           bool       `gorm:"default:true" json:"is_active"`
	DeactivatedAt      *time.Time `json:"deactivated_at"`
	DeactivationReason string     `gorm:"size:500" json:"deactivation_reason"`

	// Metadata and integration
	SourceSystem       string    `gorm:"size:100" json:"source_system"`
	ExternalUserID     string    `gorm:"size:255" json:"external_user_id"`
	HRSystemID         string    `gorm:"size:255" json:"hr_system_id"`
	ADGroupMemberships pq.StringArray `gorm:"type:text[]" json:"ad_group_memberships"`
	CustomFields       string    `gorm:"type:jsonb;default:'{}'" json:"custom_fields"`
	Tags               pq.StringArray `gorm:"type:text[]" json:"tags"`
	Notes              string    `gorm:"type:text" json:"notes"`
}

// RiskLevel represents the categorized risk level based on scores
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelModerate RiskLevel = "moderate"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// TrainingPriority represents the urgency of training assignment
type TrainingPriority string

const (
	TrainingPriorityLow       TrainingPriority = "low"
	TrainingPriorityStandard  TrainingPriority = "standard"
	TrainingPriorityHigh      TrainingPriority = "high"
	TrainingPriorityImmediate TrainingPriority = "immediate"
)

// GetRiskLevel categorizes the overall risk score into levels
func (urp *UserRiskProfile) GetRiskLevel() RiskLevel {
	score := urp.OverallRiskScore
	switch {
	case score >= 80:
		return RiskLevelCritical
	case score >= 60:
		return RiskLevelHigh
	case score >= 40:
		return RiskLevelModerate
	default:
		return RiskLevelLow
	}
}

// GetTrainingPriority determines training priority based on risk factors
func (urp *UserRiskProfile) GetTrainingPriority() TrainingPriority {
	// Critical factors that require immediate training
	if urp.RecentSecurityIncidents > 2 || 
	   urp.PolicyViolationCount > 1 || 
	   urp.OverallRiskScore >= 90 ||
	   urp.PhishingClickRate > 75 {
		return TrainingPriorityImmediate
	}

	// High priority factors
	if urp.OverallRiskScore >= 70 ||
	   urp.PhishingClickRate > 50 ||
	   urp.SuspiciousActivityCount > 3 ||
	   urp.FailedAssessmentCount > 2 {
		return TrainingPriorityHigh
	}

	// Standard priority factors
	if urp.OverallRiskScore >= 50 ||
	   urp.TrainingStatus == "overdue" ||
	   time.Since(urp.LastRiskUpdate).Hours() > 168 { // 1 week
		return TrainingPriorityStandard
	}

	return TrainingPriorityLow
}

// IsTrainingOverdue checks if user's training is overdue
func (urp *UserRiskProfile) IsTrainingOverdue() bool {
	if urp.NextRequiredTraining == nil {
		return false
	}
	return time.Now().After(*urp.NextRequiredTraining)
}

// RequiresImmediateTraining determines if immediate training is needed
func (urp *UserRiskProfile) RequiresImmediateTraining() bool {
	return urp.GetTrainingPriority() == TrainingPriorityImmediate
}

// GetComplianceRequirements returns compliance-specific training requirements
func (urp *UserRiskProfile) GetComplianceRequirements() map[string]interface{} {
	var requirements map[string]interface{}
	if urp.RegulatoryRequirements != "" {
		json.Unmarshal([]byte(urp.RegulatoryRequirements), &requirements)
	}
	if requirements == nil {
		requirements = make(map[string]interface{})
	}
	return requirements
}

// UpdateRiskScore updates the overall risk score based on individual scores
func (urp *UserRiskProfile) UpdateRiskScore() {
	// Weighted average of risk components
	weights := map[string]float64{
		"phishing":     0.30,
		"data":         0.25,
		"access":       0.20,
		"compliance":   0.15,
		"behavioral":   0.10,
	}

	behavioralScore := urp.calculateBehavioralScore()
	
	weighted := float64(urp.PhishingRiskScore)*weights["phishing"] +
		float64(urp.DataHandlingRiskScore)*weights["data"] +
		float64(urp.AccessRiskScore)*weights["access"] +
		float64(urp.ComplianceRiskScore)*weights["compliance"] +
		behavioralScore*weights["behavioral"]

	urp.OverallRiskScore = int(weighted)
	urp.LastRiskUpdate = time.Now()
	urp.UpdatedAt = time.Now()
}

// calculateBehavioralScore calculates behavioral risk based on activities
func (urp *UserRiskProfile) calculateBehavioralScore() float64 {
	score := 50.0 // Base score

	// Increase score for risk factors
	score += float64(urp.LoginAnomalies * 5)
	score += float64(urp.SuspiciousActivityCount * 8)
	score += float64(urp.PolicyViolationCount * 15)

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// GetPersonalizationPreferences returns user's training personalization data
func (urp *UserRiskProfile) GetPersonalizationPreferences() map[string]interface{} {
	var prefs map[string]interface{}
	if urp.PersonalizationData != "" {
		json.Unmarshal([]byte(urp.PersonalizationData), &prefs)
	}
	if prefs == nil {
		prefs = make(map[string]interface{})
	}
	return prefs
}

// ShouldTriggerTraining determines if training should be triggered based on current state
func (urp *UserRiskProfile) ShouldTriggerTraining() (bool, string) {
	reasons := []string{}

	if urp.IsTrainingOverdue() {
		reasons = append(reasons, "training_overdue")
	}

	if urp.RecentSecurityIncidents > 0 {
		reasons = append(reasons, "security_incident")
	}

	if urp.PhishingClickRate > 25 {
		reasons = append(reasons, "phishing_susceptibility")
	}

	if urp.PolicyViolationCount > 0 {
		reasons = append(reasons, "policy_violation")
	}

	if urp.OverallRiskScore >= 60 {
		reasons = append(reasons, "high_risk_score")
	}

	shouldTrigger := len(reasons) > 0
	var reasonStr string
	if shouldTrigger {
		reasonsJSON, _ := json.Marshal(reasons)
		reasonStr = string(reasonsJSON)
	}

	return shouldTrigger, reasonStr
}

// TableName sets the table name for GORM
func (UserRiskProfile) TableName() string {
	return "user_risk_profiles"
}