package entity

import (
	"time"
	"github.com/google/uuid"
)

// SecurityEffectivenessScore represents the composite security effectiveness score
type SecurityEffectivenessScore struct {
	ID                    uuid.UUID                 `json:"id" db:"id"`
	TenantID              uuid.UUID                 `json:"tenant_id" db:"tenant_id"`
	OrganizationID        uuid.UUID                 `json:"organization_id" db:"organization_id"`
	TimeWindow            time.Duration             `json:"time_window" db:"time_window"`
	CalculationTimestamp  time.Time                 `json:"calculation_timestamp" db:"calculation_timestamp"`
	
	// Core SES Components
	OverallScore          float64                   `json:"overall_score" db:"overall_score"`           // 0-100
	ThreatBlockingScore   float64                   `json:"threat_blocking_score" db:"threat_blocking_score"`   // 0-100
	IncidentImpactScore   float64                   `json:"incident_impact_score" db:"incident_impact_score"`   // 0-100
	ResponseEfficiency    float64                   `json:"response_efficiency" db:"response_efficiency"`       // 0-100
	PreventionEffectiveness float64                 `json:"prevention_effectiveness" db:"prevention_effectiveness"` // 0-100
	
	// Detailed Metrics
	ComponentScores       map[string]float64        `json:"component_scores" db:"component_scores"`
	WeightingFactors      map[string]float64        `json:"weighting_factors" db:"weighting_factors"`
	ConfidenceLevel       float64                   `json:"confidence_level" db:"confidence_level"`     // 0-1
	
	// Historical Context
	PreviousScore         *float64                  `json:"previous_score,omitempty" db:"previous_score"`
	TrendDirection        TrendDirection            `json:"trend_direction" db:"trend_direction"`
	ChangePercent         float64                   `json:"change_percent" db:"change_percent"`
	
	// Predictive Analytics
	PredictedScore        *float64                  `json:"predicted_score,omitempty" db:"predicted_score"`
	PredictionHorizon     time.Duration             `json:"prediction_horizon" db:"prediction_horizon"`
	PredictionConfidence  float64                   `json:"prediction_confidence" db:"prediction_confidence"`
	
	// Target and Goals
	TargetScore           float64                   `json:"target_score" db:"target_score"`
	TargetDate            *time.Time                `json:"target_date,omitempty" db:"target_date"`
	IsTargetAchievable    bool                      `json:"is_target_achievable" db:"is_target_achievable"`
	
	// Security Clearance and Compliance
	SecurityClearance     SecurityClearanceLevel    `json:"security_clearance" db:"security_clearance"`
	ComplianceFrameworks  []ComplianceFramework     `json:"compliance_frameworks" db:"compliance_frameworks"`
	ClassificationLevel   DataClassificationLevel   `json:"classification_level" db:"classification_level"`
	
	// Metadata
	CreatedAt             time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at" db:"updated_at"`
	CreatedBy             uuid.UUID                 `json:"created_by" db:"created_by"`
	Version               int                       `json:"version" db:"version"`
	Tags                  []string                  `json:"tags" db:"tags"`
	Metadata              map[string]interface{}    `json:"metadata" db:"metadata"`
}

// TrendDirection represents the direction of score change
type TrendDirection string

const (
	TrendImproving  TrendDirection = "improving"
	TrendDeclining  TrendDirection = "declining"
	TrendStable     TrendDirection = "stable"
	TrendVolatile   TrendDirection = "volatile"
	TrendUnknown    TrendDirection = "unknown"
)

// SecurityClearanceLevel represents different security clearance levels
type SecurityClearanceLevel string

const (
	SecurityClearanceUnclassified SecurityClearanceLevel = "unclassified"
	SecurityClearanceConfidential SecurityClearanceLevel = "confidential"
	SecurityClearanceSecret       SecurityClearanceLevel = "secret"
	SecurityClearanceTopSecret    SecurityClearanceLevel = "top_secret"
)

// ComplianceFramework represents different compliance frameworks
type ComplianceFramework string

const (
	ComplianceSOC2     ComplianceFramework = "soc2"
	ComplianceISO27001 ComplianceFramework = "iso27001"
	ComplianceHIPAA    ComplianceFramework = "hipaa"
	ComplianceGDPR     ComplianceFramework = "gdpr"
	ComplianceFedRAMP  ComplianceFramework = "fedramp"
	ComplianceFISMA    ComplianceFramework = "fisma"
	ComplianceNIST     ComplianceFramework = "nist"
	CompliancePCI      ComplianceFramework = "pci"
)

// DataClassificationLevel represents data classification levels
type DataClassificationLevel string

const (
	DataClassificationPublic     DataClassificationLevel = "public"
	DataClassificationInternal   DataClassificationLevel = "internal"
	DataClassificationRestricted DataClassificationLevel = "restricted"
	DataClassificationSecret     DataClassificationLevel = "secret"
)

// ScoreComponent represents individual components that contribute to the overall score
type ScoreComponent struct {
	ID                uuid.UUID                 `json:"id" db:"id"`
	ScoreID           uuid.UUID                 `json:"score_id" db:"score_id"`
	ComponentType     ComponentType             `json:"component_type" db:"component_type"`
	ComponentName     string                    `json:"component_name" db:"component_name"`
	ComponentScore    float64                   `json:"component_score" db:"component_score"`
	Weight            float64                   `json:"weight" db:"weight"`
	ContributionScore float64                   `json:"contribution_score" db:"contribution_score"`
	
	// Component Metrics
	TotalEvents       int64                     `json:"total_events" db:"total_events"`
	BlockedEvents     int64                     `json:"blocked_events" db:"blocked_events"`
	AllowedEvents     int64                     `json:"allowed_events" db:"allowed_events"`
	FalsePositives    int64                     `json:"false_positives" db:"false_positives"`
	FalseNegatives    int64                     `json:"false_negatives" db:"false_negatives"`
	
	// Performance Metrics
	ResponseTime      time.Duration             `json:"response_time" db:"response_time"`
	Availability      float64                   `json:"availability" db:"availability"`
	Throughput        float64                   `json:"throughput" db:"throughput"`
	
	// Context
	TimeWindow        time.Duration             `json:"time_window" db:"time_window"`
	CreatedAt         time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at" db:"updated_at"`
}

// ComponentType represents different types of security components
type ComponentType string

const (
	ComponentFirewall          ComponentType = "firewall"
	ComponentIDS               ComponentType = "ids"
	ComponentIPS               ComponentType = "ips"
	ComponentAntivirus         ComponentType = "antivirus"
	ComponentEmailSecurity     ComponentType = "email_security"
	ComponentWebSecurity       ComponentType = "web_security"
	ComponentEndpointProtection ComponentType = "endpoint_protection"
	ComponentSIEM              ComponentType = "siem"
	ComponentSOAR              ComponentType = "soar"
	ComponentDLP               ComponentType = "dlp"
	ComponentIdentityAccess    ComponentType = "identity_access"
	ComponentVulnerability     ComponentType = "vulnerability"
	ComponentThreatIntel       ComponentType = "threat_intel"
	ComponentIncidentResponse  ComponentType = "incident_response"
)

// ScoreHistory represents historical score data for trending
type ScoreHistory struct {
	ID                    uuid.UUID   `json:"id" db:"id"`
	ScoreID               uuid.UUID   `json:"score_id" db:"score_id"`
	TenantID              uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	HistoricalScore       float64     `json:"historical_score" db:"historical_score"`
	Timestamp             time.Time   `json:"timestamp" db:"timestamp"`
	Period                string      `json:"period" db:"period"` // daily, weekly, monthly
	ChangeFromPrevious    float64     `json:"change_from_previous" db:"change_from_previous"`
	SignificantEvents     []string    `json:"significant_events" db:"significant_events"`
	CreatedAt             time.Time   `json:"created_at" db:"created_at"`
}

// ScorePrediction represents predictive analytics for future scores
type ScorePrediction struct {
	ID                    uuid.UUID               `json:"id" db:"id"`
	ScoreID               uuid.UUID               `json:"score_id" db:"score_id"`
	TenantID              uuid.UUID               `json:"tenant_id" db:"tenant_id"`
	PredictionTimestamp   time.Time               `json:"prediction_timestamp" db:"prediction_timestamp"`
	PredictionHorizon     time.Duration           `json:"prediction_horizon" db:"prediction_horizon"`
	PredictedScore        float64                 `json:"predicted_score" db:"predicted_score"`
	ConfidenceInterval    ConfidenceInterval      `json:"confidence_interval" db:"confidence_interval"`
	ModelType             PredictionModelType     `json:"model_type" db:"model_type"`
	ModelVersion          string                  `json:"model_version" db:"model_version"`
	InputFeatures         map[string]interface{}  `json:"input_features" db:"input_features"`
	Assumptions           []string                `json:"assumptions" db:"assumptions"`
	RiskFactors           []RiskFactor            `json:"risk_factors" db:"risk_factors"`
	CreatedAt             time.Time               `json:"created_at" db:"created_at"`
}

// ConfidenceInterval represents the confidence interval for predictions
type ConfidenceInterval struct {
	Lower      float64 `json:"lower" db:"lower"`
	Upper      float64 `json:"upper" db:"upper"`
	Confidence float64 `json:"confidence" db:"confidence"` // e.g., 0.95 for 95%
}

// PredictionModelType represents different types of prediction models
type PredictionModelType string

const (
	ModelLinearRegression    PredictionModelType = "linear_regression"
	ModelTimeSeriesARIMA     PredictionModelType = "time_series_arima"
	ModelMachineLearning     PredictionModelType = "machine_learning"
	ModelEnsemble            PredictionModelType = "ensemble"
	ModelNeuralNetwork       PredictionModelType = "neural_network"
	ModelBayesian            PredictionModelType = "bayesian"
)

// RiskFactor represents factors that could impact future scores
type RiskFactor struct {
	Name        string  `json:"name" db:"name"`
	Category    string  `json:"category" db:"category"`
	Impact      float64 `json:"impact" db:"impact"`        // -100 to +100
	Probability float64 `json:"probability" db:"probability"` // 0 to 1
	Description string  `json:"description" db:"description"`
}

// ScoreTarget represents target score settings and goals
type ScoreTarget struct {
	ID                    uuid.UUID     `json:"id" db:"id"`
	ScoreID               uuid.UUID     `json:"score_id" db:"score_id"`
	TenantID              uuid.UUID     `json:"tenant_id" db:"tenant_id"`
	TargetScore           float64       `json:"target_score" db:"target_score"`
	TargetDate            time.Time     `json:"target_date" db:"target_date"`
	CurrentScore          float64       `json:"current_score" db:"current_score"`
	RequiredImprovement   float64       `json:"required_improvement" db:"required_improvement"`
	IsAchievable          bool          `json:"is_achievable" db:"is_achievable"`
	AchievabilityReason   string        `json:"achievability_reason" db:"achievability_reason"`
	RecommendedActions    []string      `json:"recommended_actions" db:"recommended_actions"`
	EstimatedTimeToTarget time.Duration `json:"estimated_time_to_target" db:"estimated_time_to_target"`
	CreatedAt             time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time     `json:"updated_at" db:"updated_at"`
	CreatedBy             uuid.UUID     `json:"created_by" db:"created_by"`
}

// Business Methods

// IsImproving returns true if the score is showing improvement
func (ses *SecurityEffectivenessScore) IsImproving() bool {
	return ses.TrendDirection == TrendImproving
}

// IsTargetMet returns true if the current score meets or exceeds the target
func (ses *SecurityEffectivenessScore) IsTargetMet() bool {
	return ses.OverallScore >= ses.TargetScore
}

// GetScoreGrade returns a letter grade based on the overall score
func (ses *SecurityEffectivenessScore) GetScoreGrade() string {
	switch {
	case ses.OverallScore >= 90:
		return "A"
	case ses.OverallScore >= 80:
		return "B"
	case ses.OverallScore >= 70:
		return "C"
	case ses.OverallScore >= 60:
		return "D"
	default:
		return "F"
	}
}

// GetRiskLevel returns the risk level based on the score
func (ses *SecurityEffectivenessScore) GetRiskLevel() string {
	switch {
	case ses.OverallScore >= 80:
		return "Low"
	case ses.OverallScore >= 60:
		return "Medium"
	case ses.OverallScore >= 40:
		return "High"
	default:
		return "Critical"
	}
}

// CalculateComponentContribution calculates how much each component contributes to the overall score
func (ses *SecurityEffectivenessScore) CalculateComponentContribution() map[string]float64 {
	contributions := make(map[string]float64)
	
	for component, score := range ses.ComponentScores {
		if weight, exists := ses.WeightingFactors[component]; exists {
			contributions[component] = score * weight
		}
	}
	
	return contributions
}

// GetImprovementRecommendations returns recommendations for improving the score
func (ses *SecurityEffectivenessScore) GetImprovementRecommendations() []string {
	recommendations := []string{}
	
	// Analyze component scores and suggest improvements
	for component, score := range ses.ComponentScores {
		if score < 70 {
			switch component {
			case "threat_blocking":
				recommendations = append(recommendations, "Enhance threat detection rules and signatures")
			case "incident_response":
				recommendations = append(recommendations, "Improve incident response time and procedures")
			case "vulnerability_management":
				recommendations = append(recommendations, "Increase vulnerability scan frequency and remediation speed")
			case "endpoint_protection":
				recommendations = append(recommendations, "Deploy advanced endpoint protection and monitoring")
			case "email_security":
				recommendations = append(recommendations, "Strengthen email security filters and user training")
			}
		}
	}
	
	return recommendations
}

// Validation methods

// Validate performs comprehensive validation of the SecurityEffectivenessScore
func (ses *SecurityEffectivenessScore) Validate() error {
	if ses.TenantID == uuid.Nil {
		return NewValidationError("tenant_id is required")
	}
	
	if ses.OrganizationID == uuid.Nil {
		return NewValidationError("organization_id is required")
	}
	
	if ses.OverallScore < 0 || ses.OverallScore > 100 {
		return NewValidationError("overall_score must be between 0 and 100")
	}
	
	if ses.ThreatBlockingScore < 0 || ses.ThreatBlockingScore > 100 {
		return NewValidationError("threat_blocking_score must be between 0 and 100")
	}
	
	if ses.ConfidenceLevel < 0 || ses.ConfidenceLevel > 1 {
		return NewValidationError("confidence_level must be between 0 and 1")
	}
	
	return nil
}

// NewSecurityEffectivenessScore creates a new SecurityEffectivenessScore with defaults
func NewSecurityEffectivenessScore(tenantID, organizationID uuid.UUID) *SecurityEffectivenessScore {
	return &SecurityEffectivenessScore{
		ID:                    uuid.New(),
		TenantID:              tenantID,
		OrganizationID:        organizationID,
		CalculationTimestamp:  time.Now(),
		ComponentScores:       make(map[string]float64),
		WeightingFactors:      getDefaultWeightingFactors(),
		TrendDirection:        TrendUnknown,
		SecurityClearance:     SecurityClearanceUnclassified,
		ComplianceFrameworks:  []ComplianceFramework{},
		ClassificationLevel:   DataClassificationInternal,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		Version:               1,
		Tags:                  []string{},
		Metadata:              make(map[string]interface{}),
	}
}

// getDefaultWeightingFactors returns default weighting factors for score components
func getDefaultWeightingFactors() map[string]float64 {
	return map[string]float64{
		"threat_blocking":        0.25,
		"incident_response":      0.20,
		"vulnerability_mgmt":     0.20,
		"endpoint_protection":    0.15,
		"email_security":         0.10,
		"identity_access":        0.10,
	}
}