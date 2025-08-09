// iSECTECH Security Awareness Training Service - Analytics Repository
// Production-grade data access layer for analytics and compliance reporting
// Author: Claude Code - iSECTECH Security Team
// Version: 1.0.0

package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-awareness-training/domain/entity"
)

// AnalyticsRepository defines the interface for analytics and reporting data access
type AnalyticsRepository interface {
	// Analytics Report CRUD operations
	CreateAnalyticsReport(ctx context.Context, report *entity.TrainingAnalyticsReport) error
	GetAnalyticsReport(ctx context.Context, reportID uuid.UUID) (*entity.TrainingAnalyticsReport, error)
	UpdateAnalyticsReport(ctx context.Context, report *entity.TrainingAnalyticsReport) error
	DeleteAnalyticsReport(ctx context.Context, reportID uuid.UUID) error

	// Report discovery and listing
	GetReportsByTenant(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*entity.TrainingAnalyticsReport, error)
	GetReportsByType(ctx context.Context, tenantID uuid.UUID, reportType string) ([]*entity.TrainingAnalyticsReport, error)
	GetReportsByStatus(ctx context.Context, tenantID uuid.UUID, status string) ([]*entity.TrainingAnalyticsReport, error)
	GetReportsByDateRange(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) ([]*entity.TrainingAnalyticsReport, error)
	GetScheduledReports(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAnalyticsReport, error)

	// Report lifecycle management
	GetExpiredReports(ctx context.Context, tenantID uuid.UUID) ([]*entity.TrainingAnalyticsReport, error)
	GetReportsForArchival(ctx context.Context, tenantID uuid.UUID, archiveAfter time.Time) ([]*entity.TrainingAnalyticsReport, error)
	GetReportsForCleanup(ctx context.Context, tenantID uuid.UUID, cleanupAfter time.Time) ([]*entity.TrainingAnalyticsReport, error)
	ArchiveReports(ctx context.Context, reportIDs []uuid.UUID) error

	// Compliance Report operations
	CreateComplianceReport(ctx context.Context, report *entity.ComplianceReport) error
	GetComplianceReport(ctx context.Context, reportID uuid.UUID) (*entity.ComplianceReport, error)
	UpdateComplianceReport(ctx context.Context, report *entity.ComplianceReport) error
	GetComplianceReportsByFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.ComplianceReport, error)
	GetComplianceReportsByPeriod(ctx context.Context, tenantID uuid.UUID, startDate, endDate time.Time) ([]*entity.ComplianceReport, error)
	GetLatestComplianceReport(ctx context.Context, tenantID uuid.UUID, framework string) (*entity.ComplianceReport, error)

	// Performance Metric operations
	CreatePerformanceMetric(ctx context.Context, metric *entity.PerformanceMetric) error
	GetPerformanceMetric(ctx context.Context, metricID uuid.UUID) (*entity.PerformanceMetric, error)
	UpdatePerformanceMetric(ctx context.Context, metric *entity.PerformanceMetric) error
	GetMetricsByReport(ctx context.Context, reportID uuid.UUID) ([]*entity.PerformanceMetric, error)
	GetMetricsByType(ctx context.Context, tenantID uuid.UUID, metricType string) ([]*entity.PerformanceMetric, error)
	GetMetricsByScope(ctx context.Context, tenantID uuid.UUID, scopeType, scopeIdentifier string) ([]*entity.PerformanceMetric, error)

	// Aggregated analytics queries
	GetTrainingCompletionStats(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*TrainingCompletionStats, error)
	GetUserEngagementAnalytics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*UserEngagementAnalytics, error)
	GetRiskReductionMetrics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*RiskReductionMetrics, error)
	GetContentEffectivenessMetrics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) ([]*ContentEffectivenessMetric, error)

	// Compliance analytics
	GetComplianceStatusOverview(ctx context.Context, tenantID uuid.UUID) (*ComplianceStatusOverview, error)
	GetComplianceGapAnalysis(ctx context.Context, tenantID uuid.UUID, framework string) (*ComplianceGapAnalysis, error)
	GetComplianceTrends(ctx context.Context, tenantID uuid.UUID, framework string, months int) ([]*ComplianceTrendPoint, error)
	GetRegulatoryComplianceStatus(ctx context.Context, tenantID uuid.UUID) ([]*RegulatoryComplianceStatus, error)

	// Real-time analytics
	GetRealTimeMetrics(ctx context.Context, tenantID uuid.UUID) (*RealTimeMetrics, error)
	GetActiveLearnerStats(ctx context.Context, tenantID uuid.UUID) (*ActiveLearnerStats, error)
	GetCurrentTrainingLoad(ctx context.Context, tenantID uuid.UUID) (*TrainingLoadMetrics, error)

	// Departmental and organizational analytics
	GetDepartmentAnalytics(ctx context.Context, tenantID uuid.UUID, department string, timeRange TimeRange) (*DepartmentAnalytics, error)
	GetOrganizationalMetrics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*OrganizationalMetrics, error)
	GetSecurityClearanceAnalytics(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) ([]*SecurityClearanceAnalytics, error)

	// Trend analysis
	GetCompletionTrends(ctx context.Context, tenantID uuid.UUID, period string, count int) ([]*CompletionTrendPoint, error)
	GetEngagementTrends(ctx context.Context, tenantID uuid.UUID, period string, count int) ([]*EngagementTrendPoint, error)
	GetRiskTrends(ctx context.Context, tenantID uuid.UUID, period string, count int) ([]*RiskTrendPoint, error)

	// Executive reporting
	GetExecutiveDashboard(ctx context.Context, tenantID uuid.UUID) (*ExecutiveDashboard, error)
	GetExecutiveSummary(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*ExecutiveSummary, error)
	GetKPIDashboard(ctx context.Context, tenantID uuid.UUID) (*KPIDashboard, error)

	// Benchmarking and comparisons
	GetIndustryBenchmarks(ctx context.Context, tenantID uuid.UUID, industry string) (*IndustryBenchmarks, error)
	GetPeerComparison(ctx context.Context, tenantID uuid.UUID, peerGroup string) (*PeerComparison, error)
	GetHistoricalComparison(ctx context.Context, tenantID uuid.UUID, comparisonPeriod string) (*HistoricalComparison, error)

	// Data export and reporting
	ExportAnalyticsData(ctx context.Context, tenantID uuid.UUID, exportRequest *DataExportRequest) (*DataExportResult, error)
	GenerateCustomReport(ctx context.Context, tenantID uuid.UUID, reportSpec *CustomReportSpec) (*CustomReportResult, error)

	// Batch operations
	CreateMetricsBatch(ctx context.Context, metrics []*entity.PerformanceMetric) error
	UpdateReportsBatch(ctx context.Context, reports []*entity.TrainingAnalyticsReport) error
}

// Data structures for analytics responses

// TrainingCompletionStats represents overall completion statistics
type TrainingCompletionStats struct {
	TenantID              uuid.UUID `json:"tenant_id"`
	TimeRange             TimeRange `json:"time_range"`
	TotalAssignments      int64     `json:"total_assignments"`
	CompletedAssignments  int64     `json:"completed_assignments"`
	InProgressAssignments int64     `json:"in_progress_assignments"`
	OverdueAssignments    int64     `json:"overdue_assignments"`
	CompletionRate        float64   `json:"completion_rate"`
	AverageCompletionTime float64   `json:"average_completion_time_days"`
	OnTimeCompletionRate  float64   `json:"on_time_completion_rate"`
	PassRate              float64   `json:"pass_rate"`
	RetryRate             float64   `json:"retry_rate"`
	ByContentType         map[string]*CompletionStat `json:"by_content_type"`
	ByDepartment          map[string]*CompletionStat `json:"by_department"`
	BySecurityClearance   map[string]*CompletionStat `json:"by_security_clearance"`
}

// CompletionStat represents completion statistics for a specific category
type CompletionStat struct {
	Category        string  `json:"category"`
	TotalItems      int64   `json:"total_items"`
	CompletedItems  int64   `json:"completed_items"`
	CompletionRate  float64 `json:"completion_rate"`
	AverageScore    float64 `json:"average_score"`
	PassRate        float64 `json:"pass_rate"`
}

// UserEngagementAnalytics represents user engagement metrics
type UserEngagementAnalytics struct {
	TenantID              uuid.UUID `json:"tenant_id"`
	TimeRange             TimeRange `json:"time_range"`
	TotalUsers            int64     `json:"total_users"`
	ActiveUsers           int64     `json:"active_users"`
	EngagementRate        float64   `json:"engagement_rate"`
	AverageSessionTime    float64   `json:"average_session_time_minutes"`
	AverageInteractionsPerSession float64 `json:"average_interactions_per_session"`
	UserRetentionRate     float64   `json:"user_retention_rate"`
	EngagementTrend       string    `json:"engagement_trend"`
	TopEngagingContent    []*ContentEngagementMetric `json:"top_engaging_content"`
	EngagementByDevice    map[string]*EngagementStat `json:"engagement_by_device"`
	EngagementByTimeOfDay map[string]*EngagementStat `json:"engagement_by_time_of_day"`
}

// ContentEngagementMetric represents engagement metrics for specific content
type ContentEngagementMetric struct {
	ContentID         uuid.UUID `json:"content_id"`
	ContentName       string    `json:"content_name"`
	LaunchCount       int64     `json:"launch_count"`
	AvgTimeSpent      float64   `json:"avg_time_spent_minutes"`
	EngagementScore   float64   `json:"engagement_score"`
	CompletionRate    float64   `json:"completion_rate"`
	UserRating        float64   `json:"user_rating"`
}

// EngagementStat represents engagement statistics for a category
type EngagementStat struct {
	Category          string  `json:"category"`
	SessionCount      int64   `json:"session_count"`
	AvgEngagementTime float64 `json:"avg_engagement_time_minutes"`
	EngagementScore   float64 `json:"engagement_score"`
}

// RiskReductionMetrics represents risk reduction analytics
type RiskReductionMetrics struct {
	TenantID                uuid.UUID `json:"tenant_id"`
	TimeRange               TimeRange `json:"time_range"`
	BaselineRiskScore       float64   `json:"baseline_risk_score"`
	CurrentRiskScore        float64   `json:"current_risk_score"`
	RiskReductionPercentage float64   `json:"risk_reduction_percentage"`
	UsersAtHighRisk         int64     `json:"users_at_high_risk"`
	UsersAtLowRisk          int64     `json:"users_at_low_risk"`
	PhishingClickReduction  float64   `json:"phishing_click_reduction"`
	SecurityIncidentReduction float64 `json:"security_incident_reduction"`
	RiskByDepartment        map[string]*RiskStat `json:"risk_by_department"`
	RiskTrendData           []*RiskTrendPoint    `json:"risk_trend_data"`
}

// RiskStat represents risk statistics for a category
type RiskStat struct {
	Category      string  `json:"category"`
	UserCount     int64   `json:"user_count"`
	AvgRiskScore  float64 `json:"avg_risk_score"`
	RiskReduction float64 `json:"risk_reduction"`
	TrendDirection string `json:"trend_direction"`
}

// ContentEffectivenessMetric represents content effectiveness analytics
type ContentEffectivenessMetric struct {
	ContentID           uuid.UUID `json:"content_id"`
	ContentName         string    `json:"content_name"`
	ContentType         string    `json:"content_type"`
	LearnerCount        int64     `json:"learner_count"`
	CompletionRate      float64   `json:"completion_rate"`
	AverageScore        float64   `json:"average_score"`
	EffectivenessScore  float64   `json:"effectiveness_score"`
	RiskReductionImpact float64   `json:"risk_reduction_impact"`
	LearnerSatisfaction float64   `json:"learner_satisfaction"`
	RetentionRate       float64   `json:"retention_rate"`
	ROIScore            float64   `json:"roi_score"`
}

// ComplianceStatusOverview represents overall compliance status
type ComplianceStatusOverview struct {
	TenantID              uuid.UUID                               `json:"tenant_id"`
	GeneratedAt           time.Time                               `json:"generated_at"`
	OverallComplianceRate float64                                 `json:"overall_compliance_rate"`
	FrameworkCompliance   map[string]*ComplianceFrameworkStatus   `json:"framework_compliance"`
	CriticalGapCount      int                                     `json:"critical_gap_count"`
	UpcomingDeadlines     []*ComplianceDeadline                   `json:"upcoming_deadlines"`
	ComplianceRisk        string                                  `json:"compliance_risk"`
	TrendDirection        string                                  `json:"trend_direction"`
}

// ComplianceDeadline represents an upcoming compliance deadline
type ComplianceDeadline struct {
	Framework       string    `json:"framework"`
	Requirement     string    `json:"requirement"`
	DueDate         time.Time `json:"due_date"`
	DaysRemaining   int       `json:"days_remaining"`
	CompletionRate  float64   `json:"completion_rate"`
	Risk            string    `json:"risk"`
}

// ComplianceGapAnalysis represents compliance gap analysis
type ComplianceGapAnalysis struct {
	TenantID        uuid.UUID               `json:"tenant_id"`
	Framework       string                  `json:"framework"`
	AnalysisDate    time.Time               `json:"analysis_date"`
	OverallGapScore float64                 `json:"overall_gap_score"`
	IdentifiedGaps  []*ComplianceGap        `json:"identified_gaps"`
	PriorityAreas   []*PriorityArea         `json:"priority_areas"`
	RemediationPlan []*RemediationAction    `json:"remediation_plan"`
	EstimatedEffort string                  `json:"estimated_effort"`
	RiskAssessment  *ComplianceRiskAssessment `json:"risk_assessment"`
}

// ComplianceGap represents a specific compliance gap
type ComplianceGap struct {
	ControlID       string    `json:"control_id"`
	ControlName     string    `json:"control_name"`
	GapSeverity     string    `json:"gap_severity"`
	CurrentStatus   string    `json:"current_status"`
	RequiredStatus  string    `json:"required_status"`
	GapDescription  string    `json:"gap_description"`
	ImpactArea      []string  `json:"impact_area"`
	Deadline        time.Time `json:"deadline"`
}

// Additional data structures for comprehensive analytics...

// ExecutiveDashboard represents executive-level metrics
type ExecutiveDashboard struct {
	TenantID                uuid.UUID                    `json:"tenant_id"`
	GeneratedAt             time.Time                    `json:"generated_at"`
	OverallTrainingHealth   string                       `json:"overall_training_health"`
	ComplianceStatus        string                       `json:"compliance_status"`
	RiskPosture             string                       `json:"risk_posture"`
	KeyMetrics              *ExecutiveKeyMetrics         `json:"key_metrics"`
	CriticalIssues          []*CriticalIssue             `json:"critical_issues"`
	SuccessHighlights       []*SuccessHighlight          `json:"success_highlights"`
	UpcomingMilestones      []*Milestone                 `json:"upcoming_milestones"`
	ResourceUtilization     *ResourceUtilization         `json:"resource_utilization"`
	ROIMetrics              *ROIMetrics                  `json:"roi_metrics"`
}

// Supporting data structures...
type ExecutiveKeyMetrics struct {
	CompletionRate        float64 `json:"completion_rate"`
	ComplianceRate        float64 `json:"compliance_rate"`
	RiskReduction         float64 `json:"risk_reduction"`
	UserEngagement        float64 `json:"user_engagement"`
	TrainingEffectiveness float64 `json:"training_effectiveness"`
}

type CriticalIssue struct {
	IssueType    string    `json:"issue_type"`
	Description  string    `json:"description"`
	Severity     string    `json:"severity"`
	ImpactArea   []string  `json:"impact_area"`
	DueDate      time.Time `json:"due_date"`
	Owner        string    `json:"owner"`
}

type SuccessHighlight struct {
	Achievement string  `json:"achievement"`
	Metric      string  `json:"metric"`
	Value       float64 `json:"value"`
	Improvement string  `json:"improvement"`
	Impact      string  `json:"impact"`
}

type Milestone struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	DueDate     time.Time `json:"due_date"`
	Status      string    `json:"status"`
	Owner       string    `json:"owner"`
}

type ResourceUtilization struct {
	ContentLibraryUsage float64 `json:"content_library_usage"`
	InstructorUtilization float64 `json:"instructor_utilization"`
	SystemCapacityUsage float64 `json:"system_capacity_usage"`
	BudgetUtilization   float64 `json:"budget_utilization"`
}

type ROIMetrics struct {
	TrainingInvestment      float64 `json:"training_investment"`
	RiskMitigationValue     float64 `json:"risk_mitigation_value"`
	ProductivityGains       float64 `json:"productivity_gains"`
	ComplianceCostAvoidance float64 `json:"compliance_cost_avoidance"`
	NetROI                  float64 `json:"net_roi"`
}

// Data export and custom reporting structures
type DataExportRequest struct {
	ExportType   string                 `json:"export_type"`
	Format       string                 `json:"format"`
	TimeRange    TimeRange              `json:"time_range"`
	Filters      map[string]interface{} `json:"filters"`
	Columns      []string               `json:"columns"`
	Aggregations []string               `json:"aggregations"`
}

type DataExportResult struct {
	ExportID     uuid.UUID `json:"export_id"`
	DownloadURL  string    `json:"download_url"`
	FileSize     int64     `json:"file_size"`
	RecordCount  int64     `json:"record_count"`
	GeneratedAt  time.Time `json:"generated_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type CustomReportSpec struct {
	ReportName   string                 `json:"report_name"`
	ReportType   string                 `json:"report_type"`
	DataSources  []string               `json:"data_sources"`
	Metrics      []string               `json:"metrics"`
	Dimensions   []string               `json:"dimensions"`
	Filters      map[string]interface{} `json:"filters"`
	Aggregations map[string]string      `json:"aggregations"`
	Formatting   map[string]interface{} `json:"formatting"`
}

type CustomReportResult struct {
	ReportID    uuid.UUID              `json:"report_id"`
	ReportData  map[string]interface{} `json:"report_data"`
	GeneratedAt time.Time              `json:"generated_at"`
	Metadata    map[string]interface{} `json:"metadata"`
}