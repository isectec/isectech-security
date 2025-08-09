package service

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/backend/services/security-benchmarking/domain/entity"
)

// BenchmarkService provides benchmarking and comparison capabilities
type BenchmarkService struct {
	logger                *slog.Logger
	benchmarkRepository   BenchmarkRepository
	scoreRepository       ScoreRepository
	maturityService       MaturityService
	comparisonEngine      ComparisonEngine
}

// BenchmarkRepository interface for benchmark data persistence
type BenchmarkRepository interface {
	GetIndustryBenchmark(ctx context.Context, industry entity.IndustryType, companySize entity.CompanySize, region entity.GeographicRegion) (*entity.IndustryBenchmark, error)
	SaveIndustryBenchmark(ctx context.Context, benchmark *entity.IndustryBenchmark) error
	GetPeerComparison(ctx context.Context, tenantID uuid.UUID) (*entity.PeerComparison, error)
	SavePeerComparison(ctx context.Context, comparison *entity.PeerComparison) error
	GetMaturityAssessment(ctx context.Context, tenantID uuid.UUID) (*entity.MaturityAssessment, error)
	SaveMaturityAssessment(ctx context.Context, assessment *entity.MaturityAssessment) error
}

// ScoreRepository interface for accessing security scores
type ScoreRepository interface {
	GetLatestScore(ctx context.Context, tenantID uuid.UUID) (*entity.SecurityEffectivenessScore, error)
	GetScoreHistory(ctx context.Context, tenantID uuid.UUID, period time.Duration) ([]entity.ScoreHistory, error)
	GetPeerScores(ctx context.Context, criteria entity.PeerSelectionCriteria) ([]PeerScoreData, error)
}

// MaturityService interface for maturity assessments
type MaturityService interface {
	AssessMaturity(ctx context.Context, tenantID uuid.UUID, framework entity.MaturityFramework) (*entity.MaturityAssessment, error)
	CompareMaturityWithPeers(ctx context.Context, tenantID uuid.UUID, criteria entity.PeerSelectionCriteria) (*MaturityComparison, error)
	GenerateImprovementRoadmap(ctx context.Context, assessment *entity.MaturityAssessment) ([]entity.MaturityImprovement, error)
}

// ComparisonEngine interface for comparative analysis
type ComparisonEngine interface {
	PerformPeerComparison(ctx context.Context, organizationScore float64, peerScores []PeerScoreData, criteria entity.PeerSelectionCriteria) (*entity.PeerComparison, error)
	IdentifyImprovementOpportunities(ctx context.Context, comparison *entity.PeerComparison) ([]entity.ImprovementArea, error)
	GenerateQuickWins(ctx context.Context, comparison *entity.PeerComparison) ([]entity.QuickWin, error)
	GenerateStrategicInitiatives(ctx context.Context, comparison *entity.PeerComparison) ([]entity.StrategicInitiative, error)
}

// Supporting data structures
type PeerScoreData struct {
	TenantID        uuid.UUID                         `json:"tenant_id"`
	Score           float64                           `json:"score"`
	ComponentScores map[string]float64                `json:"component_scores"`
	Industry        entity.IndustryType               `json:"industry"`
	CompanySize     entity.CompanySize                `json:"company_size"`
	Region          entity.GeographicRegion           `json:"region"`
	MaturityLevel   entity.SecurityMaturityLevel      `json:"maturity_level"`
	Timestamp       time.Time                         `json:"timestamp"`
}

type MaturityComparison struct {
	OrganizationMaturity  entity.SecurityMaturityLevel      `json:"organization_maturity"`
	PeerAverageMaturity   entity.SecurityMaturityLevel      `json:"peer_average_maturity"`
	IndustryBenchmark     entity.SecurityMaturityLevel      `json:"industry_benchmark"`
	MaturityGap           int                               `json:"maturity_gap"` // Levels behind/ahead
	DomainGaps            map[string]int                    `json:"domain_gaps"`
	TopPerformerLevel     entity.SecurityMaturityLevel      `json:"top_performer_level"`
}

// NewBenchmarkService creates a new benchmark service
func NewBenchmarkService(
	logger *slog.Logger,
	benchmarkRepo BenchmarkRepository,
	scoreRepo ScoreRepository,
	maturityService MaturityService,
	comparisonEngine ComparisonEngine,
) *BenchmarkService {
	return &BenchmarkService{
		logger:                logger,
		benchmarkRepository:   benchmarkRepo,
		scoreRepository:       scoreRepo,
		maturityService:       maturityService,
		comparisonEngine:      comparisonEngine,
	}
}

// GetIndustryBenchmark retrieves industry benchmark data
func (s *BenchmarkService) GetIndustryBenchmark(ctx context.Context, industry entity.IndustryType, companySize entity.CompanySize, region entity.GeographicRegion) (*entity.IndustryBenchmark, error) {
	s.logger.Info("Retrieving industry benchmark", 
		"industry", industry, 
		"company_size", companySize,
		"region", region)

	benchmark, err := s.benchmarkRepository.GetIndustryBenchmark(ctx, industry, companySize, region)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve industry benchmark: %w", err)
	}

	// Check if benchmark is still valid
	if !benchmark.IsValid() {
		s.logger.Warn("Industry benchmark data is outdated", 
			"valid_until", benchmark.ValidUntil,
			"current_time", time.Now())
		// Could trigger a refresh process here
	}

	return benchmark, nil
}

// PerformPeerComparison performs comprehensive peer comparison analysis
func (s *BenchmarkService) PerformPeerComparison(ctx context.Context, tenantID, organizationID uuid.UUID, criteria entity.PeerSelectionCriteria) (*entity.PeerComparison, error) {
	s.logger.Info("Performing peer comparison", 
		"tenant_id", tenantID,
		"organization_id", organizationID,
		"criteria", criteria)

	// Get current organization score
	currentScore, err := s.scoreRepository.GetLatestScore(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current score: %w", err)
	}

	// Get peer scores based on criteria
	peerScores, err := s.scoreRepository.GetPeerScores(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer scores: %w", err)
	}

	if len(peerScores) < 3 {
		return nil, fmt.Errorf("insufficient peer data: need at least 3 peers, found %d", len(peerScores))
	}

	// Perform comparison analysis
	comparison, err := s.comparisonEngine.PerformPeerComparison(ctx, currentScore.OverallScore, peerScores, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to perform peer comparison: %w", err)
	}

	comparison.TenantID = tenantID
	comparison.OrganizationID = organizationID
	comparison.OrganizationScore = currentScore.OverallScore

	// Calculate component gaps
	comparison.ComponentGaps = s.calculateComponentGaps(currentScore.ComponentScores, peerScores)

	// Identify improvement opportunities
	improvementAreas, err := s.comparisonEngine.IdentifyImprovementOpportunities(ctx, comparison)
	if err != nil {
		s.logger.Warn("Failed to identify improvement opportunities", "error", err)
	} else {
		comparison.ImprovementAreas = improvementAreas
	}

	// Generate quick wins
	quickWins, err := s.comparisonEngine.GenerateQuickWins(ctx, comparison)
	if err != nil {
		s.logger.Warn("Failed to generate quick wins", "error", err)
	} else {
		comparison.QuickWins = quickWins
	}

	// Generate strategic initiatives
	strategicInitiatives, err := s.comparisonEngine.GenerateStrategicInitiatives(ctx, comparison)
	if err != nil {
		s.logger.Warn("Failed to generate strategic initiatives", "error", err)
	} else {
		comparison.StrategicInitiatives = strategicInitiatives
	}

	// Save comparison results
	if err := s.benchmarkRepository.SavePeerComparison(ctx, comparison); err != nil {
		s.logger.Warn("Failed to save peer comparison", "error", err)
	}

	s.logger.Info("Peer comparison completed", 
		"peer_count", comparison.PeerCount,
		"percentile_ranking", comparison.PercentileRanking,
		"improvement_areas", len(comparison.ImprovementAreas))

	return comparison, nil
}

// AssessSecurityMaturity performs security maturity assessment
func (s *BenchmarkService) AssessSecurityMaturity(ctx context.Context, tenantID uuid.UUID, framework entity.MaturityFramework) (*entity.MaturityAssessment, error) {
	s.logger.Info("Assessing security maturity", 
		"tenant_id", tenantID,
		"framework", framework)

	// Perform maturity assessment
	assessment, err := s.maturityService.AssessMaturity(ctx, tenantID, framework)
	if err != nil {
		return nil, fmt.Errorf("failed to assess maturity: %w", err)
	}

	// Get industry benchmark for maturity
	// This would typically come from the benchmark repository
	// For now, we'll set some default values
	assessment.IndustryBenchmark = s.getIndustryMaturityBenchmark(assessment.Framework)
	assessment.BestPracticeGap = s.calculateBestPracticeGap(assessment.MaturityScore)

	// Generate improvement roadmap
	roadmap, err := s.maturityService.GenerateImprovementRoadmap(ctx, assessment)
	if err != nil {
		s.logger.Warn("Failed to generate improvement roadmap", "error", err)
	} else {
		assessment.ImprovementRoadmap = roadmap
	}

	// Determine next maturity level and time estimate
	assessment.NextMaturityLevel = s.getNextMaturityLevel(assessment.OverallMaturityLevel)
	assessment.TimeToNextLevel = s.estimateTimeToNextLevel(assessment.OverallMaturityLevel, assessment.NextMaturityLevel)

	// Save assessment
	if err := s.benchmarkRepository.SaveMaturityAssessment(ctx, assessment); err != nil {
		s.logger.Warn("Failed to save maturity assessment", "error", err)
	}

	s.logger.Info("Security maturity assessment completed", 
		"overall_maturity", assessment.OverallMaturityLevel,
		"maturity_score", assessment.MaturityScore,
		"next_level", assessment.NextMaturityLevel)

	return assessment, nil
}

// GenerateComprehensiveBenchmarkReport generates a comprehensive benchmarking report
func (s *BenchmarkService) GenerateComprehensiveBenchmarkReport(ctx context.Context, tenantID, organizationID uuid.UUID, criteria entity.PeerSelectionCriteria) (*ComprehensiveBenchmarkReport, error) {
	s.logger.Info("Generating comprehensive benchmark report", 
		"tenant_id", tenantID,
		"organization_id", organizationID)

	report := &ComprehensiveBenchmarkReport{
		ID:             uuid.New(),
		TenantID:       tenantID,
		OrganizationID: organizationID,
		GeneratedAt:    time.Now(),
	}

	// Get current score
	currentScore, err := s.scoreRepository.GetLatestScore(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current score: %w", err)
	}
	report.CurrentScore = currentScore

	// Get industry benchmark
	industryBenchmark, err := s.GetIndustryBenchmark(ctx, criteria.Industry, criteria.CompanySize, criteria.GeographicRegion)
	if err != nil {
		s.logger.Warn("Failed to get industry benchmark", "error", err)
	} else {
		report.IndustryBenchmark = industryBenchmark
	}

	// Perform peer comparison
	peerComparison, err := s.PerformPeerComparison(ctx, tenantID, organizationID, criteria)
	if err != nil {
		s.logger.Warn("Failed to perform peer comparison", "error", err)
	} else {
		report.PeerComparison = peerComparison
	}

	// Assess maturity
	maturityAssessment, err := s.AssessSecurityMaturity(ctx, tenantID, entity.FrameworkNIST)
	if err != nil {
		s.logger.Warn("Failed to assess maturity", "error", err)
	} else {
		report.MaturityAssessment = maturityAssessment
	}

	// Generate executive summary
	report.ExecutiveSummary = s.generateExecutiveSummary(report)

	// Generate recommendations
	report.Recommendations = s.generateComprehensiveRecommendations(report)

	s.logger.Info("Comprehensive benchmark report generated", 
		"report_id", report.ID,
		"recommendations_count", len(report.Recommendations))

	return report, nil
}

// Helper methods

func (s *BenchmarkService) calculateComponentGaps(organizationComponents map[string]float64, peerScores []PeerScoreData) map[string]float64 {
	gaps := make(map[string]float64)

	// Calculate average peer scores for each component
	componentAverages := make(map[string]float64)
	componentCounts := make(map[string]int)

	for _, peer := range peerScores {
		for component, score := range peer.ComponentScores {
			componentAverages[component] += score
			componentCounts[component]++
		}
	}

	// Calculate averages and gaps
	for component, total := range componentAverages {
		if count := componentCounts[component]; count > 0 {
			average := total / float64(count)
			if orgScore, exists := organizationComponents[component]; exists {
				gaps[component] = orgScore - average // Positive = above average, Negative = below average
			}
		}
	}

	return gaps
}

func (s *BenchmarkService) getIndustryMaturityBenchmark(framework entity.MaturityFramework) float64 {
	// Default industry benchmarks by framework
	benchmarks := map[entity.MaturityFramework]float64{
		entity.FrameworkNIST:     65.0,
		entity.FrameworkISO27001: 68.0,
		entity.FrameworkCMMI:     62.0,
		entity.FrameworkCOBIT:    60.0,
		entity.FrameworkCustom:   65.0,
	}

	if benchmark, exists := benchmarks[framework]; exists {
		return benchmark
	}
	return 65.0 // Default
}

func (s *BenchmarkService) calculateBestPracticeGap(currentScore float64) float64 {
	bestPracticeScore := 90.0 // Assuming 90+ is best practice
	return bestPracticeScore - currentScore
}

func (s *BenchmarkService) getNextMaturityLevel(currentLevel entity.SecurityMaturityLevel) entity.SecurityMaturityLevel {
	levelProgression := map[entity.SecurityMaturityLevel]entity.SecurityMaturityLevel{
		entity.MaturityInitial:    entity.MaturityManaged,
		entity.MaturityManaged:    entity.MaturityDefined,
		entity.MaturityDefined:    entity.MaturityQuantified,
		entity.MaturityQuantified: entity.MaturityOptimized,
		entity.MaturityOptimized:  entity.MaturityOptimized, // Already at highest level
	}

	if nextLevel, exists := levelProgression[currentLevel]; exists {
		return nextLevel
	}
	return entity.MaturityManaged // Default fallback
}

func (s *BenchmarkService) estimateTimeToNextLevel(currentLevel, nextLevel entity.SecurityMaturityLevel) time.Duration {
	if currentLevel == nextLevel {
		return 0 // Already at target level
	}

	// Estimated time to advance one maturity level
	timeEstimates := map[entity.SecurityMaturityLevel]time.Duration{
		entity.MaturityInitial:    6 * 30 * 24 * time.Hour,  // 6 months
		entity.MaturityManaged:    9 * 30 * 24 * time.Hour,  // 9 months
		entity.MaturityDefined:    12 * 30 * 24 * time.Hour, // 12 months
		entity.MaturityQuantified: 18 * 30 * 24 * time.Hour, // 18 months
	}

	if duration, exists := timeEstimates[currentLevel]; exists {
		return duration
	}
	return 12 * 30 * 24 * time.Hour // Default 12 months
}

func (s *BenchmarkService) generateExecutiveSummary(report *ComprehensiveBenchmarkReport) *ExecutiveSummary {
	summary := &ExecutiveSummary{
		OverallPerformance: "Average", // Default
		KeyFindings:        []string{},
		CriticalActions:    []string{},
		BusinessImpact:     "Medium",
		InvestmentPriority: "Medium",
	}

	if report.CurrentScore != nil {
		// Determine overall performance category
		score := report.CurrentScore.OverallScore
		switch {
		case score >= 90:
			summary.OverallPerformance = "Excellent"
		case score >= 80:
			summary.OverallPerformance = "Good"
		case score >= 70:
			summary.OverallPerformance = "Average"
		case score >= 60:
			summary.OverallPerformance = "Below Average"
		default:
			summary.OverallPerformance = "Poor"
		}

		// Add key findings based on score
		if score < 70 {
			summary.KeyFindings = append(summary.KeyFindings, "Security effectiveness score below industry standards")
			summary.CriticalActions = append(summary.CriticalActions, "Immediate security improvements required")
			summary.BusinessImpact = "High"
			summary.InvestmentPriority = "High"
		}
	}

	if report.PeerComparison != nil {
		percentile := report.PeerComparison.PercentileRanking
		if percentile < 25 {
			summary.KeyFindings = append(summary.KeyFindings, "Performance significantly below peer average")
			summary.CriticalActions = append(summary.CriticalActions, "Benchmark against industry leaders")
		} else if percentile > 75 {
			summary.KeyFindings = append(summary.KeyFindings, "Performance above peer average")
		}
	}

	if report.MaturityAssessment != nil {
		if report.MaturityAssessment.OverallMaturityLevel == entity.MaturityInitial {
			summary.KeyFindings = append(summary.KeyFindings, "Security maturity at initial level")
			summary.CriticalActions = append(summary.CriticalActions, "Establish formal security processes")
		}
	}

	return summary
}

func (s *BenchmarkService) generateComprehensiveRecommendations(report *ComprehensiveBenchmarkReport) []*RecommendationItem {
	recommendations := []*RecommendationItem{}

	// Add recommendations based on peer comparison
	if report.PeerComparison != nil {
		for _, area := range report.PeerComparison.ImprovementAreas {
			rec := &RecommendationItem{
				Category:    "Peer Comparison",
				Title:       fmt.Sprintf("Improve %s Performance", area.Area),
				Description: fmt.Sprintf("Current score: %.1f, Peer average: %.1f", area.CurrentScore, area.PeerAverageScore),
				Priority:    string(area.Priority),
				Timeline:    area.EstimatedTimeframe,
				Impact:      "Medium",
			}
			recommendations = append(recommendations, rec)
		}
	}

	// Add recommendations based on maturity assessment
	if report.MaturityAssessment != nil {
		for _, improvement := range report.MaturityAssessment.ImprovementRoadmap {
			rec := &RecommendationItem{
				Category:    "Maturity Improvement",
				Title:       fmt.Sprintf("Advance %s Maturity", improvement.Domain),
				Description: improvement.ExpectedBenefit,
				Priority:    string(improvement.Priority),
				Timeline:    improvement.EstimatedTimeframe,
				Impact:      "High",
			}
			recommendations = append(recommendations, rec)
		}
	}

	// Sort recommendations by priority
	sort.Slice(recommendations, func(i, j int) bool {
		priorityOrder := map[string]int{"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
		return priorityOrder[recommendations[i].Priority] > priorityOrder[recommendations[j].Priority]
	})

	return recommendations
}

// Supporting structures for comprehensive reporting

type ComprehensiveBenchmarkReport struct {
	ID                 uuid.UUID                         `json:"id"`
	TenantID           uuid.UUID                         `json:"tenant_id"`
	OrganizationID     uuid.UUID                         `json:"organization_id"`
	GeneratedAt        time.Time                         `json:"generated_at"`
	CurrentScore       *entity.SecurityEffectivenessScore `json:"current_score"`
	IndustryBenchmark  *entity.IndustryBenchmark         `json:"industry_benchmark"`
	PeerComparison     *entity.PeerComparison            `json:"peer_comparison"`
	MaturityAssessment *entity.MaturityAssessment        `json:"maturity_assessment"`
	ExecutiveSummary   *ExecutiveSummary                 `json:"executive_summary"`
	Recommendations    []*RecommendationItem             `json:"recommendations"`
}

type ExecutiveSummary struct {
	OverallPerformance string   `json:"overall_performance"`
	KeyFindings        []string `json:"key_findings"`
	CriticalActions    []string `json:"critical_actions"`
	BusinessImpact     string   `json:"business_impact"`
	InvestmentPriority string   `json:"investment_priority"`
}

type RecommendationItem struct {
	Category    string        `json:"category"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Priority    string        `json:"priority"`
	Timeline    time.Duration `json:"timeline"`
	Impact      string        `json:"impact"`
}