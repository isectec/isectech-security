// iSECTECH Security Awareness Training Service - Training Analytics Entity
// Production-grade analytics and reporting data models
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package entity

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TrainingAnalyticsReport represents a comprehensive analytics report
type TrainingAnalyticsReport struct {
	// Primary identifiers
	ReportID  uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"report_id"`
	TenantID  uuid.UUID `gorm:"not null;index:idx_analytics_report_tenant" json:"tenant_id"`

	// Report metadata
	ReportName        string    `gorm:"not null;size:255" json:"report_name"`
	ReportType        string    `gorm:"not null;size:100" json:"report_type" validate:"required,oneof=compliance risk_assessment performance engagement completion trend executive_summary department_breakdown"`
	ReportCategory    string    `gorm:"not null;size:100" json:"report_category" validate:"required,oneof=scheduled ad_hoc regulatory executive operational security"`
	ReportDescription string    `gorm:"type:text" json:"report_description"`
	ReportFormat      string    `gorm:"not null;size:50" json:"report_format" validate:"required,oneof=json csv xlsx pdf html dashboard"`

	// Time period and scope
	PeriodStart       time.Time  `gorm:"not null" json:"period_start"`
	PeriodEnd         time.Time  `gorm:"not null" json:"period_end"`
	GeneratedAt       time.Time  `gorm:"default:now()" json:"generated_at"`
	ValidUntil        *time.Time `json:"valid_until"`
	RefreshInterval   *int       `json:"refresh_interval_hours"`

	// Scope and filters
	ScopeType         string         `gorm:"not null;size:50" json:"scope_type" validate:"required,oneof=tenant department user_group content_type security_clearance"`
	ScopeIdentifiers  pq.StringArray `gorm:"type:text[]" json:"scope_identifiers"`
	FilterCriteria    string         `gorm:"type:jsonb;default:'{}'" json:"filter_criteria"`
	IncludedUsers     pq.StringArray `gorm:"type:text[]" json:"included_users"`
	ExcludedUsers     pq.StringArray `gorm:"type:text[]" json:"excluded_users"`

	// Report data and metrics
	SummaryMetrics    string `gorm:"type:jsonb;default:'{}'" json:"summary_metrics"`
	DetailedData      string `gorm:"type:jsonb;default:'{}'" json:"detailed_data"`
	TrendAnalysis     string `gorm:"type:jsonb;default:'{}'" json:"trend_analysis"`
	ComplianceData    string `gorm:"type:jsonb;default:'{}'" json:"compliance_data"`
	RiskAssessmentData string `gorm:"type:jsonb;default:'{}'" json:"risk_assessment_data"`
	PerformanceMetrics string `gorm:"type:jsonb;default:'{}'" json:"performance_metrics"`

	// Report status and lifecycle
	Status            string    `gorm:"not null;default:generating" json:"status" validate:"required,oneof=generating completed failed expired archived"`
	ProcessingProgress int      `gorm:"not null;default:0;check:processing_progress BETWEEN 0 AND 100" json:"processing_progress"`
	ErrorMessage      string    `gorm:"type:text" json:"error_message"`
	GenerationTime    float64   `json:"generation_time_seconds"`
	DataRows          int64     `json:"data_rows"`
	ReportSize        int64     `json:"report_size_bytes"`

	// Access control and security
	AccessLevel       string         `gorm:"not null;size:50" json:"access_level" validate:"required,oneof=public restricted confidential secret top_secret"`
	AuthorizedUsers   pq.StringArray `gorm:"type:text[]" json:"authorized_users"`
	AuthorizedRoles   pq.StringArray `gorm:"type:text[]" json:"authorized_roles"`
	SecurityTags      pq.StringArray `gorm:"type:text[]" json:"security_tags"`
	DataClassification string        `gorm:"not null;size:50" json:"data_classification" validate:"required,oneof=public internal restricted confidential"`

	// Distribution and delivery
	DeliveryMethods   pq.StringArray `gorm:"type:text[]" json:"delivery_methods"`
	Recipients        string         `gorm:"type:jsonb;default:'[]'" json:"recipients"`
	DeliverySchedule  string         `gorm:"type:jsonb;default:'{}'" json:"delivery_schedule"`
	AutoDistribution  bool           `gorm:"not null;default:false" json:"auto_distribution"`
	NotificationSent  bool           `gorm:"not null;default:false" json:"notification_sent"`

	// File and storage information
	StorageLocation   string    `gorm:"size:500" json:"storage_location"`
	DownloadURL       string    `gorm:"size:1000" json:"download_url"`
	FileHash          string    `gorm:"size:64" json:"file_hash"`
	CompressionUsed   bool      `gorm:"not null;default:false" json:"compression_used"`
	EncryptionUsed    bool      `gorm:"not null;default:false" json:"encryption_used"`

	// Compliance and regulatory tracking
	ComplianceFrameworks pq.StringArray `gorm:"type:text[]" json:"compliance_frameworks"`
	RegulatoryRequirements string       `gorm:"type:jsonb;default:'{}'" json:"regulatory_requirements"`
	AuditTrail          string          `gorm:"type:jsonb;default:'[]'" json:"audit_trail"`
	RetentionPolicy     string          `gorm:"type:jsonb;default:'{}'" json:"retention_policy"`
	DataLineage         string          `gorm:"type:jsonb;default:'{}'" json:"data_lineage"`

	// Metadata and lifecycle management
	CreatedBy         uuid.UUID  `gorm:"not null" json:"created_by"`
	RequestedBy       uuid.UUID  `json:"requested_by"`
	ApprovedBy        uuid.UUID  `json:"approved_by"`
	ReviewedBy        uuid.UUID  `json:"reviewed_by"`
	Tags              pq.StringArray `gorm:"type:text[]" json:"tags"`
	CustomMetadata    string     `gorm:"type:jsonb;default:'{}'" json:"custom_metadata"`
	CreatedAt         time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"default:now()" json:"updated_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	ArchivedAt        *time.Time `json:"archived_at"`
	IsActive          bool       `gorm:"default:true" json:"is_active"`
}

// ComplianceReport represents a compliance-specific report
type ComplianceReport struct {
	// Primary identifiers
	ComplianceReportID uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"compliance_report_id"`
	TenantID           uuid.UUID `gorm:"not null;index:idx_compliance_report_tenant" json:"tenant_id"`
	AnalyticsReportID  uuid.UUID `gorm:"index:idx_compliance_analytics" json:"analytics_report_id"`

	// Compliance framework information
	FrameworkName     string    `gorm:"not null;size:100" json:"framework_name" validate:"required,oneof=SOC2 ISO27001 HIPAA GDPR PCI_DSS NIST_CSF FedRAMP FISMA COBIT"`
	FrameworkVersion  string    `gorm:"size:50" json:"framework_version"`
	ComplianceStandard string   `gorm:"not null;size:100" json:"compliance_standard"`
	AssessmentPeriod  string    `gorm:"not null;size:100" json:"assessment_period"`
	ReportingPeriod   string    `gorm:"not null;size:100" json:"reporting_period"`

	// Compliance status and metrics
	OverallComplianceScore    float64 `gorm:"not null;check:overall_compliance_score BETWEEN 0 AND 100" json:"overall_compliance_score"`
	ComplianceStatus          string  `gorm:"not null;size:50" json:"compliance_status" validate:"required,oneof=compliant non_compliant partially_compliant under_review"`
	RequiredTrainingModules   int     `gorm:"not null" json:"required_training_modules"`
	CompletedTrainingModules  int     `gorm:"not null" json:"completed_training_modules"`
	OverdueTrainingModules    int     `gorm:"not null" json:"overdue_training_modules"`
	TrainingComplianceRate    float64 `gorm:"check:training_compliance_rate BETWEEN 0 AND 100" json:"training_compliance_rate"`

	// User compliance breakdown
	TotalUsers              int     `gorm:"not null" json:"total_users"`
	CompliantUsers          int     `gorm:"not null" json:"compliant_users"`
	NonCompliantUsers       int     `gorm:"not null" json:"non_compliant_users"`
	UsersInGracePeriod      int     `gorm:"not null" json:"users_in_grace_period"`
	UserComplianceRate      float64 `gorm:"check:user_compliance_rate BETWEEN 0 AND 100" json:"user_compliance_rate"`

	// Risk and gap analysis
	IdentifiedGaps          string `gorm:"type:jsonb;default:'[]'" json:"identified_gaps"`
	RiskAssessment          string `gorm:"type:jsonb;default:'{}'" json:"risk_assessment"`
	RemediationActions      string `gorm:"type:jsonb;default:'[]'" json:"remediation_actions"`
	ControlEffectiveness    string `gorm:"type:jsonb;default:'{}'" json:"control_effectiveness"`
	ComplianceGapAnalysis   string `gorm:"type:jsonb;default:'{}'" json:"compliance_gap_analysis"`

	// Detailed compliance data
	ControlAssessments      string `gorm:"type:jsonb;default:'[]'" json:"control_assessments"`
	EvidenceCollection      string `gorm:"type:jsonb;default:'[]'" json:"evidence_collection"`
	NonComplianceIssues     string `gorm:"type:jsonb;default:'[]'" json:"non_compliance_issues"`
	ComplianceMetrics       string `gorm:"type:jsonb;default:'{}'" json:"compliance_metrics"`
	TrendAnalysis           string `gorm:"type:jsonb;default:'{}'" json:"trend_analysis"`

	// Certification and attestation
	CertificationStatus     string     `gorm:"size:50" json:"certification_status"`
	CertificationDate       *time.Time `json:"certification_date"`
	CertificationExpiry     *time.Time `json:"certification_expiry"`
	AttestationRequired     bool       `gorm:"not null;default:false" json:"attestation_required"`
	AttestationCompleted    bool       `gorm:"not null;default:false" json:"attestation_completed"`
	AttestedBy              uuid.UUID  `json:"attested_by"`
	AttestationDate         *time.Time `json:"attestation_date"`

	// Regulatory and audit information
	RegulatoryRequirements  string         `gorm:"type:jsonb;default:'{}'" json:"regulatory_requirements"`
	AuditFindings           string         `gorm:"type:jsonb;default:'[]'" json:"audit_findings"`
	AuditRecommendations    string         `gorm:"type:jsonb;default:'[]'" json:"audit_recommendations"`
	ExternalAuditorNotes    string         `gorm:"type:text" json:"external_auditor_notes"`
	InternalAuditorNotes    string         `gorm:"type:text" json:"internal_auditor_notes"`

	// Lifecycle and metadata
	GeneratedAt       time.Time  `gorm:"default:now()" json:"generated_at"`
	ValidFrom         time.Time  `gorm:"not null" json:"valid_from"`
	ValidUntil        time.Time  `gorm:"not null" json:"valid_until"`
	NextReviewDate    time.Time  `json:"next_review_date"`
	CreatedBy         uuid.UUID  `gorm:"not null" json:"created_by"`
	ReviewedBy        uuid.UUID  `json:"reviewed_by"`
	ApprovedBy        uuid.UUID  `json:"approved_by"`
	CreatedAt         time.Time  `gorm:"default:now()" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"default:now()" json:"updated_at"`
	IsActive          bool       `gorm:"default:true" json:"is_active"`
}

// PerformanceMetric represents detailed performance analytics
type PerformanceMetric struct {
	// Primary identifiers
	MetricID          uuid.UUID `gorm:"primarykey;type:uuid;default:uuid_generate_v4()" json:"metric_id"`
	TenantID          uuid.UUID `gorm:"not null;index:idx_performance_metric_tenant" json:"tenant_id"`
	AnalyticsReportID uuid.UUID `gorm:"index:idx_performance_analytics" json:"analytics_report_id"`

	// Metric identification
	MetricName        string    `gorm:"not null;size:255" json:"metric_name"`
	MetricType        string    `gorm:"not null;size:100" json:"metric_type" validate:"required,oneof=completion_rate engagement_score learning_velocity risk_reduction time_to_proficiency assessment_performance retention_rate"`
	MetricCategory    string    `gorm:"not null;size:100" json:"metric_category" validate:"required,oneof=learning_outcomes business_impact operational_efficiency risk_management user_experience"`
	MetricDescription string    `gorm:"type:text" json:"metric_description"`

	// Scope and context
	ScopeType         string         `gorm:"not null;size:50" json:"scope_type" validate:"required,oneof=individual department organization content_type training_program"`
	ScopeIdentifier   string         `gorm:"not null;size:255" json:"scope_identifier"`
	ContentType       string         `gorm:"size:100" json:"content_type"`
	TrainingCategory  string         `gorm:"size:100" json:"training_category"`
	SecurityClearance string         `gorm:"size:50" json:"security_clearance"`

	// Metric values and statistics
	CurrentValue      float64   `gorm:"not null" json:"current_value"`
	PreviousValue     float64   `json:"previous_value"`
	TargetValue       float64   `json:"target_value"`
	BenchmarkValue    float64   `json:"benchmark_value"`
	PercentChange     float64   `json:"percent_change"`
	TrendDirection    string    `gorm:"size:50" json:"trend_direction" validate:"omitempty,oneof=improving stable declining"`
	StatisticalData   string    `gorm:"type:jsonb;default:'{}'" json:"statistical_data"`

	// Time period and measurement
	MeasurementPeriod string    `gorm:"not null;size:100" json:"measurement_period"`
	PeriodStart       time.Time `gorm:"not null" json:"period_start"`
	PeriodEnd         time.Time `gorm:"not null" json:"period_end"`
	MeasuredAt        time.Time `gorm:"default:now()" json:"measured_at"`
	DataPoints        int       `gorm:"not null" json:"data_points"`
	SampleSize        int       `json:"sample_size"`

	// Quality and confidence indicators
	DataQuality       string  `gorm:"size:50" json:"data_quality" validate:"omitempty,oneof=high medium low uncertain"`
	ConfidenceLevel   float64 `gorm:"check:confidence_level BETWEEN 0 AND 100" json:"confidence_level"`
	MarginOfError     float64 `json:"margin_of_error"`
	StatisticalSignificance bool `json:"statistical_significance"`

	// Analysis and insights
	PerformanceRating string `gorm:"size:50" json:"performance_rating" validate:"omitempty,oneof=excellent good satisfactory needs_improvement poor"`
	KeyInsights       string `gorm:"type:jsonb;default:'[]'" json:"key_insights"`
	Recommendations   string `gorm:"type:jsonb;default:'[]'" json:"recommendations"`
	ActionItems       string `gorm:"type:jsonb;default:'[]'" json:"action_items"`
	RiskIndicators    string `gorm:"type:jsonb;default:'[]'" json:"risk_indicators"`

	// Metadata and lifecycle
	CreatedBy         uuid.UUID `gorm:"not null" json:"created_by"`
	DataSource        string    `gorm:"size:255" json:"data_source"`
	CalculationMethod string    `gorm:"type:text" json:"calculation_method"`
	Tags              pq.StringArray `gorm:"type:text[]" json:"tags"`
	CustomAttributes  string    `gorm:"type:jsonb;default:'{}'" json:"custom_attributes"`
	CreatedAt         time.Time `gorm:"default:now()" json:"created_at"`
	UpdatedAt         time.Time `gorm:"default:now()" json:"updated_at"`
	IsActive          bool      `gorm:"default:true" json:"is_active"`
}

// ReportStatus represents the status of a report
type ReportStatus string

const (
	ReportStatusGenerating ReportStatus = "generating"
	ReportStatusCompleted  ReportStatus = "completed"
	ReportStatusFailed     ReportStatus = "failed"
	ReportStatusExpired    ReportStatus = "expired"
	ReportStatusArchived   ReportStatus = "archived"
)

// IsCompleted checks if the report has been completed
func (tar *TrainingAnalyticsReport) IsCompleted() bool {
	return tar.Status == string(ReportStatusCompleted) && tar.CompletedAt != nil
}

// IsFailed checks if the report generation failed
func (tar *TrainingAnalyticsReport) IsFailed() bool {
	return tar.Status == string(ReportStatusFailed)
}

// IsExpired checks if the report has expired
func (tar *TrainingAnalyticsReport) IsExpired() bool {
	return tar.ValidUntil != nil && time.Now().After(*tar.ValidUntil)
}

// GetSummaryMetrics returns the summary metrics as a map
func (tar *TrainingAnalyticsReport) GetSummaryMetrics() map[string]interface{} {
	var metrics map[string]interface{}
	if tar.SummaryMetrics != "" {
		json.Unmarshal([]byte(tar.SummaryMetrics), &metrics)
	}
	if metrics == nil {
		metrics = make(map[string]interface{})
	}
	return metrics
}

// AddAuditEntry adds an entry to the audit trail
func (tar *TrainingAnalyticsReport) AddAuditEntry(action string, performedBy uuid.UUID, details map[string]interface{}) {
	var auditTrail []map[string]interface{}
	if tar.AuditTrail != "" {
		json.Unmarshal([]byte(tar.AuditTrail), &auditTrail)
	}

	entry := map[string]interface{}{
		"action":       action,
		"performed_by": performedBy,
		"timestamp":    time.Now(),
		"details":      details,
	}

	auditTrail = append(auditTrail, entry)
	auditData, _ := json.Marshal(auditTrail)
	tar.AuditTrail = string(auditData)
	tar.UpdatedAt = time.Now()
}

// MarkCompleted marks the report as completed
func (tar *TrainingAnalyticsReport) MarkCompleted(generationTime float64) {
	tar.Status = string(ReportStatusCompleted)
	tar.ProcessingProgress = 100
	tar.GenerationTime = generationTime
	tar.CompletedAt = &[]time.Time{time.Now()}[0]
	tar.UpdatedAt = time.Now()
}

// MarkFailed marks the report as failed with error message
func (tar *TrainingAnalyticsReport) MarkFailed(errorMessage string) {
	tar.Status = string(ReportStatusFailed)
	tar.ErrorMessage = errorMessage
	tar.UpdatedAt = time.Now()
}

// GetComplianceScore returns the overall compliance score
func (cr *ComplianceReport) GetComplianceScore() float64 {
	return cr.OverallComplianceScore
}

// IsCompliant checks if the organization is compliant
func (cr *ComplianceReport) IsCompliant() bool {
	return cr.ComplianceStatus == "compliant"
}

// GetComplianceRate returns the training compliance rate
func (cr *ComplianceReport) GetComplianceRate() float64 {
	if cr.TotalUsers == 0 {
		return 0.0
	}
	return (float64(cr.CompliantUsers) / float64(cr.TotalUsers)) * 100.0
}

// NeedsAttestation checks if attestation is required and not completed
func (cr *ComplianceReport) NeedsAttestation() bool {
	return cr.AttestationRequired && !cr.AttestationCompleted
}

// GetTrendDirection returns the performance trend direction
func (pm *PerformanceMetric) GetTrendDirection() string {
	if pm.PreviousValue == 0 {
		return "unknown"
	}

	change := ((pm.CurrentValue - pm.PreviousValue) / pm.PreviousValue) * 100
	
	if change > 5 {
		return "improving"
	} else if change < -5 {
		return "declining"
	}
	
	return "stable"
}

// GetPerformanceLevel returns a qualitative assessment of performance
func (pm *PerformanceMetric) GetPerformanceLevel() string {
	if pm.TargetValue == 0 {
		return "unknown"
	}

	achievementRate := (pm.CurrentValue / pm.TargetValue) * 100

	switch {
	case achievementRate >= 110:
		return "excellent"
	case achievementRate >= 100:
		return "good"
	case achievementRate >= 90:
		return "satisfactory"
	case achievementRate >= 70:
		return "needs_improvement"
	default:
		return "poor"
	}
}

// TableName sets the table name for GORM
func (TrainingAnalyticsReport) TableName() string {
	return "training_analytics_reports"
}

// TableName sets the table name for GORM
func (ComplianceReport) TableName() string {
	return "compliance_reports"
}

// TableName sets the table name for GORM
func (PerformanceMetric) TableName() string {
	return "performance_metrics"
}