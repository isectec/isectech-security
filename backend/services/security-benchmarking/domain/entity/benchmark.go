package entity

import (
	"time"
	"github.com/google/uuid"
)

// IndustryBenchmark represents industry-specific security benchmarks
type IndustryBenchmark struct {
	ID                    uuid.UUID                 `json:"id" db:"id"`
	Industry              IndustryType              `json:"industry" db:"industry"`
	IndustrySegment       string                    `json:"industry_segment" db:"industry_segment"`
	CompanySize           CompanySize               `json:"company_size" db:"company_size"`
	GeographicRegion      GeographicRegion          `json:"geographic_region" db:"geographic_region"`
	
	// Benchmark Metrics
	AverageScore          float64                   `json:"average_score" db:"average_score"`
	MedianScore           float64                   `json:"median_score" db:"median_score"`
	BestInClassScore      float64                   `json:"best_in_class_score" db:"best_in_class_score"`   // 90th percentile
	WorstInClassScore     float64                   `json:"worst_in_class_score" db:"worst_in_class_score"` // 10th percentile
	
	// Percentile Distribution
	Percentile25          float64                   `json:"percentile_25" db:"percentile_25"`
	Percentile50          float64                   `json:"percentile_50" db:"percentile_50"`
	Percentile75          float64                   `json:"percentile_75" db:"percentile_75"`
	Percentile90          float64                   `json:"percentile_90" db:"percentile_90"`
	Percentile95          float64                   `json:"percentile_95" db:"percentile_95"`
	
	// Component Benchmarks
	ComponentBenchmarks   map[string]ComponentBenchmark `json:"component_benchmarks" db:"component_benchmarks"`
	
	// Data Quality Metrics
	SampleSize            int64                     `json:"sample_size" db:"sample_size"`
	DataCollectionPeriod  time.Duration             `json:"data_collection_period" db:"data_collection_period"`
	ConfidenceLevel       float64                   `json:"confidence_level" db:"confidence_level"`
	MarginOfError         float64                   `json:"margin_of_error" db:"margin_of_error"`
	
	// Temporal Data
	BenchmarkPeriod       BenchmarkPeriod           `json:"benchmark_period" db:"benchmark_period"`
	LastUpdated           time.Time                 `json:"last_updated" db:"last_updated"`
	ValidUntil            time.Time                 `json:"valid_until" db:"valid_until"`
	
	// Security and Compliance
	SecurityClearance     SecurityClearanceLevel    `json:"security_clearance" db:"security_clearance"`
	ComplianceFrameworks  []ComplianceFramework     `json:"compliance_frameworks" db:"compliance_frameworks"`
	DataClassification    DataClassificationLevel   `json:"data_classification" db:"data_classification"`
	
	// Metadata
	CreatedAt             time.Time                 `json:"created_at" db:"created_at"`
	CreatedBy             uuid.UUID                 `json:"created_by" db:"created_by"`
	Version               int                       `json:"version" db:"version"`
	Tags                  []string                  `json:"tags" db:"tags"`
	Metadata              map[string]interface{}    `json:"metadata" db:"metadata"`
}

// IndustryType represents different industry sectors
type IndustryType string

const (
	IndustryFinancialServices IndustryType = "financial_services"
	IndustryHealthcare        IndustryType = "healthcare"
	IndustryGovernment        IndustryType = "government"
	IndustryEducation         IndustryType = "education"
	IndustryRetail            IndustryType = "retail"
	IndustryManufacturing     IndustryType = "manufacturing"
	IndustryTechnology        IndustryType = "technology"
	IndustryEnergy            IndustryType = "energy"
	IndustryTelecommunications IndustryType = "telecommunications"
	IndustryTransportation    IndustryType = "transportation"
	IndustryInsurance         IndustryType = "insurance"
	IndustryRealEstate        IndustryType = "real_estate"
	IndustryLegal             IndustryType = "legal"
	IndustryMedia             IndustryType = "media"
	IndustryNonProfit         IndustryType = "non_profit"
	IndustryOther             IndustryType = "other"
)

// CompanySize represents different company sizes
type CompanySize string

const (
	CompanySizeSmall      CompanySize = "small"      // < 100 employees
	CompanySizeMedium     CompanySize = "medium"     // 100-1000 employees
	CompanySizeLarge      CompanySize = "large"      // 1000-10000 employees
	CompanySizeEnterprise CompanySize = "enterprise" // > 10000 employees
)

// GeographicRegion represents different geographic regions
type GeographicRegion string

const (
	RegionNorthAmerica GeographicRegion = "north_america"
	RegionEurope       GeographicRegion = "europe"
	RegionAsiaPacific  GeographicRegion = "asia_pacific"
	RegionLatinAmerica GeographicRegion = "latin_america"
	RegionMiddleEast   GeographicRegion = "middle_east"
	RegionAfrica       GeographicRegion = "africa"
	RegionGlobal       GeographicRegion = "global"
)

// BenchmarkPeriod represents the time period for benchmark data
type BenchmarkPeriod string

const (
	PeriodQuarterly BenchmarkPeriod = "quarterly"
	PeriodAnnual    BenchmarkPeriod = "annual"
	PeriodBiannual  BenchmarkPeriod = "biannual"
)

// ComponentBenchmark represents benchmark data for individual security components
type ComponentBenchmark struct {
	ComponentType         ComponentType   `json:"component_type" db:"component_type"`
	AverageScore          float64         `json:"average_score" db:"average_score"`
	MedianScore           float64         `json:"median_score" db:"median_score"`
	BestInClassScore      float64         `json:"best_in_class_score" db:"best_in_class_score"`
	AdoptionRate          float64         `json:"adoption_rate" db:"adoption_rate"`          // % of companies using this component
	EffectivenessRating   float64         `json:"effectiveness_rating" db:"effectiveness_rating"` // Industry effectiveness rating
	CostEfficiencyScore   float64         `json:"cost_efficiency_score" db:"cost_efficiency_score"`
	RecommendationScore   float64         `json:"recommendation_score" db:"recommendation_score"` // How recommended this component is
}

// PeerComparison represents comparison with peer organizations
type PeerComparison struct {
	ID                    uuid.UUID                 `json:"id" db:"id"`
	TenantID              uuid.UUID                 `json:"tenant_id" db:"tenant_id"`
	OrganizationID        uuid.UUID                 `json:"organization_id" db:"organization_id"`
	ComparisonDate        time.Time                 `json:"comparison_date" db:"comparison_date"`
	
	// Peer Selection Criteria
	PeerCriteria          PeerSelectionCriteria     `json:"peer_criteria" db:"peer_criteria"`
	PeerCount             int                       `json:"peer_count" db:"peer_count"`
	
	// Comparison Results
	OrganizationScore     float64                   `json:"organization_score" db:"organization_score"`
	PeerAverageScore      float64                   `json:"peer_average_score" db:"peer_average_score"`
	PeerMedianScore       float64                   `json:"peer_median_score" db:"peer_median_score"`
	IndustryRanking       int                       `json:"industry_ranking" db:"industry_ranking"`      // Ranking within industry
	PeerRanking           int                       `json:"peer_ranking" db:"peer_ranking"`              // Ranking within peer group
	PercentileRanking     float64                   `json:"percentile_ranking" db:"percentile_ranking"`  // 0-100 percentile
	
	// Gap Analysis
	ScoreGap              float64                   `json:"score_gap" db:"score_gap"`                    // Difference from peer average
	ComponentGaps         map[string]float64        `json:"component_gaps" db:"component_gaps"`          // Gaps by component
	TopPerformerGap       float64                   `json:"top_performer_gap" db:"top_performer_gap"`    // Gap to top performer
	
	// Improvement Opportunities
	ImprovementAreas      []ImprovementArea         `json:"improvement_areas" db:"improvement_areas"`
	QuickWins             []QuickWin                `json:"quick_wins" db:"quick_wins"`
	StrategicInitiatives  []StrategicInitiative     `json:"strategic_initiatives" db:"strategic_initiatives"`
	
	// Security and Metadata
	SecurityClearance     SecurityClearanceLevel    `json:"security_clearance" db:"security_clearance"`
	CreatedAt             time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at" db:"updated_at"`
	Version               int                       `json:"version" db:"version"`
}

// PeerSelectionCriteria defines criteria for selecting peer organizations
type PeerSelectionCriteria struct {
	Industry              IndustryType              `json:"industry" db:"industry"`
	CompanySize           CompanySize               `json:"company_size" db:"company_size"`
	GeographicRegion      GeographicRegion          `json:"geographic_region" db:"geographic_region"`
	ComplianceFrameworks  []ComplianceFramework     `json:"compliance_frameworks" db:"compliance_frameworks"`
	ThreatProfile         ThreatProfile             `json:"threat_profile" db:"threat_profile"`
	SecurityMaturity      SecurityMaturityLevel     `json:"security_maturity" db:"security_maturity"`
	RevenueRange          RevenueRange              `json:"revenue_range" db:"revenue_range"`
}

// ThreatProfile represents the threat profile for an organization
type ThreatProfile string

const (
	ThreatProfileLow      ThreatProfile = "low"
	ThreatProfileMedium   ThreatProfile = "medium"
	ThreatProfileHigh     ThreatProfile = "high"
	ThreatProfileCritical ThreatProfile = "critical"
)

// SecurityMaturityLevel represents security maturity levels
type SecurityMaturityLevel string

const (
	MaturityInitial    SecurityMaturityLevel = "initial"
	MaturityManaged    SecurityMaturityLevel = "managed"
	MaturityDefined    SecurityMaturityLevel = "defined"
	MaturityQuantified SecurityMaturityLevel = "quantified"
	MaturityOptimized  SecurityMaturityLevel = "optimized"
)

// RevenueRange represents company revenue ranges
type RevenueRange string

const (
	RevenueLessThan10M    RevenueRange = "less_than_10m"
	Revenue10MTo100M      RevenueRange = "10m_to_100m"
	Revenue100MTo1B       RevenueRange = "100m_to_1b"
	RevenueGreaterThan1B  RevenueRange = "greater_than_1b"
)

// ImprovementArea represents an area for security improvement
type ImprovementArea struct {
	Area                  string                    `json:"area" db:"area"`
	CurrentScore          float64                   `json:"current_score" db:"current_score"`
	PeerAverageScore      float64                   `json:"peer_average_score" db:"peer_average_score"`
	BestInClassScore      float64                   `json:"best_in_class_score" db:"best_in_class_score"`
	ImprovementPotential  float64                   `json:"improvement_potential" db:"improvement_potential"`
	Priority              Priority                  `json:"priority" db:"priority"`
	EstimatedCost         EstimatedCost             `json:"estimated_cost" db:"estimated_cost"`
	EstimatedTimeframe    time.Duration             `json:"estimated_timeframe" db:"estimated_timeframe"`
	ExpectedROI           float64                   `json:"expected_roi" db:"expected_roi"`
	Dependencies          []string                  `json:"dependencies" db:"dependencies"`
	Recommendations       []string                  `json:"recommendations" db:"recommendations"`
}

// Priority represents improvement priority levels
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

// EstimatedCost represents cost estimation ranges
type EstimatedCost string

const (
	CostLow      EstimatedCost = "low"      // < $50K
	CostMedium   EstimatedCost = "medium"   // $50K - $250K
	CostHigh     EstimatedCost = "high"     // $250K - $1M
	CostVeryHigh EstimatedCost = "very_high" // > $1M
)

// QuickWin represents quick improvement opportunities
type QuickWin struct {
	Name                  string                    `json:"name" db:"name"`
	Description           string                    `json:"description" db:"description"`
	ExpectedImprovement   float64                   `json:"expected_improvement" db:"expected_improvement"`
	ImplementationTime    time.Duration             `json:"implementation_time" db:"implementation_time"`
	RequiredResources     []string                  `json:"required_resources" db:"required_resources"`
	EstimatedCost         EstimatedCost             `json:"estimated_cost" db:"estimated_cost"`
	RiskLevel             RiskLevel                 `json:"risk_level" db:"risk_level"`
	Success_Probability   float64                   `json:"success_probability" db:"success_probability"`
}

// StrategicInitiative represents long-term strategic improvements
type StrategicInitiative struct {
	Name                  string                    `json:"name" db:"name"`
	Description           string                    `json:"description" db:"description"`
	ExpectedImprovement   float64                   `json:"expected_improvement" db:"expected_improvement"`
	ImplementationTime    time.Duration             `json:"implementation_time" db:"implementation_time"`
	TotalCost             float64                   `json:"total_cost" db:"total_cost"`
	Phases                []InitiativePhase         `json:"phases" db:"phases"`
	KeyMilestones         []Milestone               `json:"key_milestones" db:"key_milestones"`
	ExpectedROI           float64                   `json:"expected_roi" db:"expected_roi"`
	RiskFactors           []string                  `json:"risk_factors" db:"risk_factors"`
	SuccessMetrics        []string                  `json:"success_metrics" db:"success_metrics"`
}

// RiskLevel represents risk levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// InitiativePhase represents phases of a strategic initiative
type InitiativePhase struct {
	PhaseNumber           int                       `json:"phase_number" db:"phase_number"`
	Name                  string                    `json:"name" db:"name"`
	Description           string                    `json:"description" db:"description"`
	Duration              time.Duration             `json:"duration" db:"duration"`
	EstimatedCost         float64                   `json:"estimated_cost" db:"estimated_cost"`
	Dependencies          []string                  `json:"dependencies" db:"dependencies"`
	Deliverables          []string                  `json:"deliverables" db:"deliverables"`
	SuccessCriteria       []string                  `json:"success_criteria" db:"success_criteria"`
}

// Milestone represents key milestones in strategic initiatives
type Milestone struct {
	Name                  string                    `json:"name" db:"name"`
	Description           string                    `json:"description" db:"description"`
	TargetDate            time.Time                 `json:"target_date" db:"target_date"`
	CompletionCriteria    []string                  `json:"completion_criteria" db:"completion_criteria"`
	ResponsibleParty      string                    `json:"responsible_party" db:"responsible_party"`
	IsComplete            bool                      `json:"is_complete" db:"is_complete"`
	CompletionDate        *time.Time                `json:"completion_date,omitempty" db:"completion_date"`
}

// MaturityAssessment represents security maturity assessment
type MaturityAssessment struct {
	ID                    uuid.UUID                 `json:"id" db:"id"`
	TenantID              uuid.UUID                 `json:"tenant_id" db:"tenant_id"`
	OrganizationID        uuid.UUID                 `json:"organization_id" db:"organization_id"`
	AssessmentDate        time.Time                 `json:"assessment_date" db:"assessment_date"`
	
	// Overall Maturity
	OverallMaturityLevel  SecurityMaturityLevel     `json:"overall_maturity_level" db:"overall_maturity_level"`
	MaturityScore         float64                   `json:"maturity_score" db:"maturity_score"`        // 0-100
	
	// Domain Maturity Levels
	DomainMaturity        map[string]DomainMaturity `json:"domain_maturity" db:"domain_maturity"`
	
	// Assessment Framework
	Framework             MaturityFramework         `json:"framework" db:"framework"`
	FrameworkVersion      string                    `json:"framework_version" db:"framework_version"`
	
	// Comparison Data
	IndustryBenchmark     float64                   `json:"industry_benchmark" db:"industry_benchmark"`
	PeerComparison        float64                   `json:"peer_comparison" db:"peer_comparison"`
	BestPracticeGap       float64                   `json:"best_practice_gap" db:"best_practice_gap"`
	
	// Recommendations
	ImprovementRoadmap    []MaturityImprovement     `json:"improvement_roadmap" db:"improvement_roadmap"`
	NextMaturityLevel     SecurityMaturityLevel     `json:"next_maturity_level" db:"next_maturity_level"`
	TimeToNextLevel       time.Duration             `json:"time_to_next_level" db:"time_to_next_level"`
	
	// Metadata
	AssessedBy            uuid.UUID                 `json:"assessed_by" db:"assessed_by"`
	ValidUntil            time.Time                 `json:"valid_until" db:"valid_until"`
	CreatedAt             time.Time                 `json:"created_at" db:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at" db:"updated_at"`
}

// DomainMaturity represents maturity for specific security domains
type DomainMaturity struct {
	Domain                string                    `json:"domain" db:"domain"`
	MaturityLevel         SecurityMaturityLevel     `json:"maturity_level" db:"maturity_level"`
	Score                 float64                   `json:"score" db:"score"`
	CapabilitiesAssessed  []CapabilityAssessment    `json:"capabilities_assessed" db:"capabilities_assessed"`
	Strengths             []string                  `json:"strengths" db:"strengths"`
	Weaknesses            []string                  `json:"weaknesses" db:"weaknesses"`
	ImprovementActions    []string                  `json:"improvement_actions" db:"improvement_actions"`
}

// CapabilityAssessment represents assessment of specific capabilities
type CapabilityAssessment struct {
	Capability            string                    `json:"capability" db:"capability"`
	CurrentLevel          int                       `json:"current_level" db:"current_level"`    // 1-5 scale
	TargetLevel           int                       `json:"target_level" db:"target_level"`      // 1-5 scale
	GapAnalysis           string                    `json:"gap_analysis" db:"gap_analysis"`
	Evidence              []string                  `json:"evidence" db:"evidence"`
	ImprovementActions    []string                  `json:"improvement_actions" db:"improvement_actions"`
}

// MaturityFramework represents different maturity frameworks
type MaturityFramework string

const (
	FrameworkNIST         MaturityFramework = "nist_cybersecurity_framework"
	FrameworkISO27001     MaturityFramework = "iso_27001"
	FrameworkCMMI         MaturityFramework = "cmmi_cybersecurity"
	FrameworkCOBIT        MaturityFramework = "cobit"
	FrameworkCustom       MaturityFramework = "custom_isectech"
)

// MaturityImprovement represents maturity improvement recommendations
type MaturityImprovement struct {
	Domain                string                    `json:"domain" db:"domain"`
	CurrentLevel          SecurityMaturityLevel     `json:"current_level" db:"current_level"`
	TargetLevel           SecurityMaturityLevel     `json:"target_level" db:"target_level"`
	ImprovementActions    []ImprovementAction       `json:"improvement_actions" db:"improvement_actions"`
	EstimatedTimeframe    time.Duration             `json:"estimated_timeframe" db:"estimated_timeframe"`
	EstimatedCost         EstimatedCost             `json:"estimated_cost" db:"estimated_cost"`
	ExpectedBenefit       string                    `json:"expected_benefit" db:"expected_benefit"`
	Priority              Priority                  `json:"priority" db:"priority"`
}

// ImprovementAction represents specific improvement actions
type ImprovementAction struct {
	Action                string                    `json:"action" db:"action"`
	Description           string                    `json:"description" db:"description"`
	Owner                 string                    `json:"owner" db:"owner"`
	Timeline              time.Duration             `json:"timeline" db:"timeline"`
	Dependencies          []string                  `json:"dependencies" db:"dependencies"`
	SuccessMetrics        []string                  `json:"success_metrics" db:"success_metrics"`
	EstimatedEffort       string                    `json:"estimated_effort" db:"estimated_effort"`
}

// Business Methods for IndustryBenchmark

// GetPercentileScore returns the score at a given percentile
func (ib *IndustryBenchmark) GetPercentileScore(percentile float64) float64 {
	switch {
	case percentile <= 25:
		return ib.Percentile25
	case percentile <= 50:
		return ib.Percentile50
	case percentile <= 75:
		return ib.Percentile75
	case percentile <= 90:
		return ib.Percentile90
	case percentile <= 95:
		return ib.Percentile95
	default:
		return ib.BestInClassScore
	}
}

// IsValid checks if the benchmark data is still valid
func (ib *IndustryBenchmark) IsValid() bool {
	return time.Now().Before(ib.ValidUntil)
}

// GetQualityRating returns a quality rating for the benchmark data
func (ib *IndustryBenchmark) GetQualityRating() string {
	if ib.SampleSize >= 1000 && ib.ConfidenceLevel >= 0.95 {
		return "Excellent"
	} else if ib.SampleSize >= 500 && ib.ConfidenceLevel >= 0.90 {
		return "Good"
	} else if ib.SampleSize >= 100 && ib.ConfidenceLevel >= 0.80 {
		return "Fair"
	}
	return "Limited"
}

// Business Methods for PeerComparison

// GetPerformanceCategory returns the performance category based on percentile ranking
func (pc *PeerComparison) GetPerformanceCategory() string {
	switch {
	case pc.PercentileRanking >= 90:
		return "Top Performer"
	case pc.PercentileRanking >= 75:
		return "Above Average"
	case pc.PercentileRanking >= 50:
		return "Average"
	case pc.PercentileRanking >= 25:
		return "Below Average"
	default:
		return "Needs Improvement"
	}
}

// GetImprovementPriority returns prioritized improvement areas
func (pc *PeerComparison) GetImprovementPriority() []ImprovementArea {
	// Sort improvement areas by priority and potential impact
	areas := make([]ImprovementArea, len(pc.ImprovementAreas))
	copy(areas, pc.ImprovementAreas)

	// Simple sorting by priority (Critical > High > Medium > Low)
	priorityOrder := map[Priority]int{
		PriorityCritical: 4,
		PriorityHigh:     3,
		PriorityMedium:   2,
		PriorityLow:      1,
	}

	for i := 0; i < len(areas); i++ {
		for j := i + 1; j < len(areas); j++ {
			iPriority := priorityOrder[areas[i].Priority]
			jPriority := priorityOrder[areas[j].Priority]
			if jPriority > iPriority || (jPriority == iPriority && areas[j].ImprovementPotential > areas[i].ImprovementPotential) {
				areas[i], areas[j] = areas[j], areas[i]
			}
		}
	}

	return areas
}

// NewIndustryBenchmark creates a new industry benchmark
func NewIndustryBenchmark(industry IndustryType, companySize CompanySize, region GeographicRegion) *IndustryBenchmark {
	return &IndustryBenchmark{
		ID:                   uuid.New(),
		Industry:             industry,
		CompanySize:          companySize,
		GeographicRegion:     region,
		ComponentBenchmarks:  make(map[string]ComponentBenchmark),
		SecurityClearance:    SecurityClearanceUnclassified,
		ComplianceFrameworks: []ComplianceFramework{},
		DataClassification:   DataClassificationInternal,
		CreatedAt:            time.Now(),
		Version:              1,
		Tags:                 []string{},
		Metadata:             make(map[string]interface{}),
	}
}

// NewPeerComparison creates a new peer comparison
func NewPeerComparison(tenantID, organizationID uuid.UUID, criteria PeerSelectionCriteria) *PeerComparison {
	return &PeerComparison{
		ID:                   uuid.New(),
		TenantID:             tenantID,
		OrganizationID:       organizationID,
		ComparisonDate:       time.Now(),
		PeerCriteria:         criteria,
		ComponentGaps:        make(map[string]float64),
		ImprovementAreas:     []ImprovementArea{},
		QuickWins:            []QuickWin{},
		StrategicInitiatives: []StrategicInitiative{},
		SecurityClearance:    SecurityClearanceUnclassified,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
		Version:              1,
	}
}