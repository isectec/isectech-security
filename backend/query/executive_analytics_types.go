package query

import (
	"time"
)

// Data structures for external API responses

// ThreatMetrics represents threat detection metrics from Task 69
type ThreatMetrics struct {
	RiskExposureIndex    float64       `json:"risk_exposure_index"`
	SeverityLevel        string        `json:"severity_level"`
	MTTD                 time.Duration `json:"mean_time_to_detection"`
	MTTR                 time.Duration `json:"mean_time_to_response"`
	ThreatCount          int64         `json:"threat_count"`
	HighSeverityThreats  int64         `json:"high_severity_threats"`
	ActiveThreats        int64         `json:"active_threats"`
	ResolvedThreats      int64         `json:"resolved_threats"`
	ThreatTrends         []ThreatTrend `json:"threat_trends"`
	LastUpdated          time.Time     `json:"last_updated"`
}

type ThreatTrend struct {
	Timestamp   time.Time `json:"timestamp"`
	ThreatCount int64     `json:"threat_count"`
	Severity    string    `json:"severity"`
}

// PredictiveThreatData represents predictive threat intelligence from Task 69
type PredictiveThreatData struct {
	ThirtyDayProbability  float64               `json:"thirty_day_probability"`
	NinetyDayProbability  float64               `json:"ninety_day_probability"`
	ConfidenceScore       float64               `json:"confidence_score"`
	PredictedThreatTypes  []PredictedThreatType `json:"predicted_threat_types"`
	RiskFactors           []string              `json:"risk_factors"`
	LastModelUpdate       time.Time             `json:"last_model_update"`
}

type PredictedThreatType struct {
	Type        string    `json:"type"`
	Probability float64   `json:"probability"`
	Impact      string    `json:"impact"`
	Timeline    time.Time `json:"timeline"`
}

// ThreatLandscapeData represents overall threat landscape from Task 69
type ThreatLandscapeData struct {
	GlobalThreatLevel     string                 `json:"global_threat_level"`
	IndustryThreatLevel   string                 `json:"industry_threat_level"`
	EmergingThreats       []EmergingThreat       `json:"emerging_threats"`
	ThreatActorActivity   []ThreatActorActivity  `json:"threat_actor_activity"`
	GeopoliticalFactors   []GeopoliticalFactor   `json:"geopolitical_factors"`
	LastIntelligenceSync  time.Time              `json:"last_intelligence_sync"`
}

type EmergingThreat struct {
	ThreatID    string    `json:"threat_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	FirstSeen   time.Time `json:"first_seen"`
	Indicators  []string  `json:"indicators"`
}

type ThreatActorActivity struct {
	ActorName       string    `json:"actor_name"`
	ActivityLevel   string    `json:"activity_level"`
	TargetSectors   []string  `json:"target_sectors"`
	RecentCampaigns []string  `json:"recent_campaigns"`
	LastActivity    time.Time `json:"last_activity"`
}

type GeopoliticalFactor struct {
	Factor      string    `json:"factor"`
	Impact      string    `json:"impact"`
	Probability float64   `json:"probability"`
	Timeline    time.Time `json:"timeline"`
}

// ComplianceScore represents compliance scoring from Task 36
type ComplianceScore struct {
	Framework       string                    `json:"framework"`
	Score           float64                   `json:"score"`
	MaxScore        float64                   `json:"max_score"`
	ControlsTotal   int                       `json:"controls_total"`
	ControlsPassed  int                       `json:"controls_passed"`
	ControlsFailed  int                       `json:"controls_failed"`
	ControlsPending int                       `json:"controls_pending"`
	LastAssessment  time.Time                 `json:"last_assessment"`
	TrendDirection  string                    `json:"trend_direction"`
	ControlDetails  []ComplianceControlDetail `json:"control_details"`
}

type ComplianceControlDetail struct {
	ControlID     string    `json:"control_id"`
	ControlName   string    `json:"control_name"`
	Status        string    `json:"status"` // passed, failed, pending, not_applicable
	Score         float64   `json:"score"`
	Evidence      []string  `json:"evidence"`
	Remediation   string    `json:"remediation"`
	DueDate       time.Time `json:"due_date"`
	Owner         string    `json:"owner"`
	LastAssessed  time.Time `json:"last_assessed"`
}

// ControlsStatus represents overall controls status from Task 36
type ControlsStatus struct {
	TotalControls       int                      `json:"total_controls"`
	ActiveControls      int                      `json:"active_controls"`
	InactiveControls    int                      `json:"inactive_controls"`
	PendingControls     int                      `json:"pending_controls"`
	ControlsByFramework map[string]int           `json:"controls_by_framework"`
	ControlsByStatus    map[string]int           `json:"controls_by_status"`
	CriticalControls    []ComplianceControlDetail `json:"critical_controls"`
	LastUpdate          time.Time                `json:"last_update"`
}

// AuditReadiness represents audit preparation status from Task 36
type AuditReadiness struct {
	ReadinessPercentage   float64                  `json:"readiness_percentage"`
	FrameworkReadiness    map[string]float64       `json:"framework_readiness"`
	EvidenceCompletion    float64                  `json:"evidence_completion"`
	DocumentationStatus   float64                  `json:"documentation_status"`
	GapCount              int                      `json:"gap_count"`
	CriticalGaps          []AuditGap               `json:"critical_gaps"`
	EstimatedPreparation  time.Duration            `json:"estimated_preparation"`
	NextAuditDate         time.Time                `json:"next_audit_date"`
	AuditorNotes          []string                 `json:"auditor_notes"`
}

type AuditGap struct {
	GapID         string    `json:"gap_id"`
	Description   string    `json:"description"`
	Framework     string    `json:"framework"`
	Severity      string    `json:"severity"`
	RequiredAction string   `json:"required_action"`
	Deadline      time.Time `json:"deadline"`
	Owner         string    `json:"owner"`
	Status        string    `json:"status"`
}

// SecurityPostureScore represents security posture from Task 42
type SecurityPostureScore struct {
	OverallScore         float64                    `json:"overall_score"`
	ConfidenceLevel      float64                    `json:"confidence_level"`
	ScoreBreakdown       map[string]float64         `json:"score_breakdown"`
	SecurityDomains      []SecurityDomainScore      `json:"security_domains"`
	ImprovementAreas     []ImprovementArea          `json:"improvement_areas"`
	TrendData            []SecurityPostureTrend     `json:"trend_data"`
	LastCalculation      time.Time                  `json:"last_calculation"`
	BenchmarkComparison  BenchmarkComparison        `json:"benchmark_comparison"`
}

type SecurityDomainScore struct {
	Domain      string    `json:"domain"`
	Score       float64   `json:"score"`
	MaxScore    float64   `json:"max_score"`
	Weight      float64   `json:"weight"`
	Status      string    `json:"status"`
	LastChecked time.Time `json:"last_checked"`
	Issues      []string  `json:"issues"`
}

type ImprovementArea struct {
	Area          string    `json:"area"`
	CurrentScore  float64   `json:"current_score"`
	PotentialGain float64   `json:"potential_gain"`
	Effort        string    `json:"effort"` // low, medium, high
	Priority      string    `json:"priority"`
	Recommendations []string `json:"recommendations"`
}

type SecurityPostureTrend struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Domain    string    `json:"domain"`
}

type BenchmarkComparison struct {
	IndustryAverage    float64 `json:"industry_average"`
	PeerComparison     string  `json:"peer_comparison"` // above, below, average
	BestPracticeScore  float64 `json:"best_practice_score"`
	PercentileRanking  int     `json:"percentile_ranking"`
}

// VulnerabilityMetrics represents vulnerability data from Task 42
type VulnerabilityMetrics struct {
	CurrentRiskScore      float64               `json:"current_risk_score"`
	ProjectedRiskScore    float64               `json:"projected_risk_score"`
	PeakRiskTiming        time.Time             `json:"peak_risk_timing"`
	ConfidenceInterval    [2]float64            `json:"confidence_interval"`
	KeyRiskFactors        []string              `json:"key_risk_factors"`
	VulnerabilityCount    VulnerabilityCount    `json:"vulnerability_count"`
	RemediationMetrics    RemediationMetrics    `json:"remediation_metrics"`
	ExposureMetrics       ExposureMetrics       `json:"exposure_metrics"`
	LastScanTime          time.Time             `json:"last_scan_time"`
}

type VulnerabilityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

type RemediationMetrics struct {
	AverageRemediationTime time.Duration `json:"average_remediation_time"`
	SLACompliance          float64       `json:"sla_compliance"`
	OverdueVulnerabilities int           `json:"overdue_vulnerabilities"`
	PatchingEffectiveness  float64       `json:"patching_effectiveness"`
}

type ExposureMetrics struct {
	InternetFacingAssets   int     `json:"internet_facing_assets"`
	ExposedCriticalAssets  int     `json:"exposed_critical_assets"`
	NetworkExposureScore   float64 `json:"network_exposure_score"`
	DataExposureRisk       float64 `json:"data_exposure_risk"`
}

// AssetSecurityStatus represents asset security status from Task 42
type AssetSecurityStatus struct {
	TotalAssets           int                     `json:"total_assets"`
	SecureAssets          int                     `json:"secure_assets"`
	VulnerableAssets      int                     `json:"vulnerable_assets"`
	CriticalAssets        int                     `json:"critical_assets"`
	AssetsByType          map[string]int          `json:"assets_by_type"`
	AssetsByRisk          map[string]int          `json:"assets_by_risk"`
	ComplianceStatus      map[string]int          `json:"compliance_status"`
	AssetInventoryHealth  AssetInventoryHealth    `json:"asset_inventory_health"`
	SecurityCoverage      SecurityCoverage        `json:"security_coverage"`
	LastInventoryUpdate   time.Time               `json:"last_inventory_update"`
}

type AssetInventoryHealth struct {
	DiscoveryAccuracy     float64   `json:"discovery_accuracy"`
	InventoryCompleteness float64   `json:"inventory_completeness"`
	DataQualityScore      float64   `json:"data_quality_score"`
	StaleRecords          int       `json:"stale_records"`
	LastDiscoveryScan     time.Time `json:"last_discovery_scan"`
}

type SecurityCoverage struct {
	MonitoredAssets       int     `json:"monitored_assets"`
	UnmonitoredAssets     int     `json:"unmonitored_assets"`
	CoveragePercentage    float64 `json:"coverage_percentage"`
	AgentDeployment       float64 `json:"agent_deployment"`
	ScanningCoverage      float64 `json:"scanning_coverage"`
}

// ExecutiveMetrics represents executive-level metrics from Task 46
type ExecutiveMetrics struct {
	BusinessDisruptionEvents int     `json:"business_disruption_events"`
	CustomerTrustIndex       float64 `json:"customer_trust_index"`
	RevenueAtRisk            float64 `json:"revenue_at_risk"`
	BrandImpactScore         float64 `json:"brand_impact_score"`
	RegulatoryRisk           float64 `json:"regulatory_risk"`
	BusinessContinuityScore  float64 `json:"business_continuity_score"`
	LastCalculation          time.Time `json:"last_calculation"`
}

// ROIMetrics represents return on investment metrics from Task 46
type ROIMetrics struct {
	SecurityInvestmentROI    float64                    `json:"security_investment_roi"`
	TotalSecuritySpend       float64                    `json:"total_security_spend"`
	CostAvoidance            float64                    `json:"cost_avoidance"`
	IncidentCostSavings      float64                    `json:"incident_cost_savings"`
	ProductivityGains        float64                    `json:"productivity_gains"`
	ComplianceCostSavings    float64                    `json:"compliance_cost_savings"`
	ROIByCategory            map[string]float64         `json:"roi_by_category"`
	InvestmentBreakdown      map[string]float64         `json:"investment_breakdown"`
	ProjectedROI             ProjectedROI               `json:"projected_roi"`
	LastCalculation          time.Time                  `json:"last_calculation"`
}

type ProjectedROI struct {
	SixMonthROI      float64 `json:"six_month_roi"`
	OneYearROI       float64 `json:"one_year_roi"`
	ThreeYearROI     float64 `json:"three_year_roi"`
	BreakevenPeriod  time.Duration `json:"breakeven_period"`
	ConfidenceLevel  float64 `json:"confidence_level"`
}

// OperationalMetrics represents operational efficiency metrics from Task 46
type OperationalMetrics struct {
	TeamProductivityScore       float64                     `json:"team_productivity_score"`
	AutomationRatio             float64                     `json:"automation_ratio"`
	FalsePositiveRate           float64                     `json:"false_positive_rate"`
	VulnRemediationSLACompliance float64                    `json:"vulnerability_remediation_sla_compliance"`
	TrainingCompletionRate      float64                     `json:"training_completion_rate"`
	AlertFatigue                float64                     `json:"alert_fatigue"`
	IncidentResponseEfficiency  float64                     `json:"incident_response_efficiency"`
	ProcessMaturityScore        float64                     `json:"process_maturity_score"`
	ResourceUtilization         ResourceUtilization         `json:"resource_utilization"`
	OperationalTrends           []OperationalTrend          `json:"operational_trends"`
	LastUpdate                  time.Time                   `json:"last_update"`
}

type ResourceUtilization struct {
	StaffUtilization      float64 `json:"staff_utilization"`
	ToolUtilization       float64 `json:"tool_utilization"`
	BudgetUtilization     float64 `json:"budget_utilization"`
	InfrastructureUse     float64 `json:"infrastructure_utilization"`
}

type OperationalTrend struct {
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Change    float64   `json:"change"`
	Direction string    `json:"direction"` // up, down, stable
	Timestamp time.Time `json:"timestamp"`
}