package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"threat-detection/domain/entity"
)

// ThreatIntelligenceRepository defines the interface for threat intelligence data access
type ThreatIntelligenceRepository interface {
	// CRUD Operations
	Create(ctx context.Context, intel *entity.ThreatIntelligence) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.ThreatIntelligence, error)
	GetByTenantAndID(ctx context.Context, tenantID, id uuid.UUID) (*entity.ThreatIntelligence, error)
	Update(ctx context.Context, intel *entity.ThreatIntelligence) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error

	// Query Operations
	List(ctx context.Context, filter IntelFilter, sort []IntelSort, page PageRequest) (*IntelListResult, error)
	Search(ctx context.Context, tenantID uuid.UUID, query string, filter IntelFilter, page PageRequest) (*IntelListResult, error)
	
	// Tenant-specific Operations
	GetByTenant(ctx context.Context, tenantID uuid.UUID, filter IntelFilter, page PageRequest) (*IntelListResult, error)
	GetActiveIntelByTenant(ctx context.Context, tenantID uuid.UUID) ([]*entity.ThreatIntelligence, error)
	
	// Indicator Operations
	GetByIndicator(ctx context.Context, tenantID uuid.UUID, indicatorType entity.IOCType, value string) ([]*entity.ThreatIntelligence, error)
	GetByIndicators(ctx context.Context, tenantID uuid.UUID, indicators []entity.ThreatIndicator) ([]*entity.ThreatIntelligence, error)
	MatchIndicators(ctx context.Context, tenantID uuid.UUID, indicators []entity.IndicatorOfCompromise) ([]*IntelMatch, error)
	
	// Source and Feed Operations
	GetBySource(ctx context.Context, tenantID uuid.UUID, source string) ([]*entity.ThreatIntelligence, error)
	GetBySources(ctx context.Context, tenantID uuid.UUID, sources []string) ([]*entity.ThreatIntelligence, error)
	UpdateBySource(ctx context.Context, source string, intel []*entity.ThreatIntelligence) error
	
	// Quality and Confidence
	GetByConfidence(ctx context.Context, tenantID uuid.UUID, minConfidence entity.IntelConfidence) ([]*entity.ThreatIntelligence, error)
	GetByQuality(ctx context.Context, tenantID uuid.UUID, minQuality entity.IntelQuality) ([]*entity.ThreatIntelligence, error)
	GetByReliability(ctx context.Context, tenantID uuid.UUID, minReliability entity.IntelReliability) ([]*entity.ThreatIntelligence, error)
	GetHighQualityIntel(ctx context.Context, tenantID uuid.UUID, minScore float64) ([]*entity.ThreatIntelligence, error)
	
	// Classification and Sharing
	GetByTLP(ctx context.Context, tenantID uuid.UUID, tlp entity.TLPLevel) ([]*entity.ThreatIntelligence, error)
	GetByClassification(ctx context.Context, tenantID uuid.UUID, classification entity.Classification) ([]*entity.ThreatIntelligence, error)
	GetShareableIntel(ctx context.Context, tenantID uuid.UUID, sharingLevel entity.SharingLevel) ([]*entity.ThreatIntelligence, error)
	
	// Time-based Operations
	GetByTimeRange(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]*entity.ThreatIntelligence, error)
	GetRecentIntel(ctx context.Context, tenantID uuid.UUID, duration time.Duration) ([]*entity.ThreatIntelligence, error)
	GetExpiredIntel(ctx context.Context, tenantID uuid.UUID) ([]*entity.ThreatIntelligence, error)
	GetExpiringIntel(ctx context.Context, tenantID uuid.UUID, within time.Duration) ([]*entity.ThreatIntelligence, error)
	
	// Campaign and Actor Operations
	GetByCampaign(ctx context.Context, tenantID uuid.UUID, campaignID uuid.UUID) ([]*entity.ThreatIntelligence, error)
	GetByThreatActor(ctx context.Context, tenantID uuid.UUID, actorID uuid.UUID) ([]*entity.ThreatIntelligence, error)
	GetByTTP(ctx context.Context, tenantID uuid.UUID, ttpID uuid.UUID) ([]*entity.ThreatIntelligence, error)
	
	// MITRE ATT&CK Operations
	GetByMITRETactic(ctx context.Context, tenantID uuid.UUID, tacticID string) ([]*entity.ThreatIntelligence, error)
	GetByMITRETechnique(ctx context.Context, tenantID uuid.UUID, techniqueID string) ([]*entity.ThreatIntelligence, error)
	GetMITRECoverage(ctx context.Context, tenantID uuid.UUID) (*MITRECoverage, error)
	
	// Enrichment and Correlation
	EnrichThreat(ctx context.Context, threat *entity.Threat) ([]*entity.ThreatIntelligence, error)
	CorrelateWithIntel(ctx context.Context, tenantID uuid.UUID, threat *entity.Threat) ([]*IntelCorrelation, error)
	GetRelatedIntel(ctx context.Context, intelID uuid.UUID, limit int) ([]*entity.ThreatIntelligence, error)
	
	// Feed Management
	CreateFeed(ctx context.Context, feed *IntelFeed) error
	GetFeeds(ctx context.Context, tenantID uuid.UUID) ([]*IntelFeed, error)
	UpdateFeed(ctx context.Context, feed *IntelFeed) error
	DeleteFeed(ctx context.Context, feedID uuid.UUID) error
	GetFeedStatistics(ctx context.Context, feedID uuid.UUID) (*FeedStatistics, error)
	
	// Bulk Operations
	BulkCreate(ctx context.Context, intel []*entity.ThreatIntelligence) error
	BulkUpdate(ctx context.Context, intel []*entity.ThreatIntelligence) error
	BulkDelete(ctx context.Context, ids []uuid.UUID) error
	BulkDeactivate(ctx context.Context, filter IntelFilter) error
	
	// Analytics and Aggregation
	GetAggregation(ctx context.Context, tenantID uuid.UUID, filter IntelFilter) (*IntelAggregation, error)
	GetIntelTrends(ctx context.Context, tenantID uuid.UUID, duration time.Duration, interval string) (*IntelTrends, error)
	GetSourceQuality(ctx context.Context, tenantID uuid.UUID) ([]*SourceQuality, error)
	GetIntelCoverage(ctx context.Context, tenantID uuid.UUID) (*IntelCoverage, error)
	
	// Validation and Quality Control
	ValidateIntel(ctx context.Context, intel *entity.ThreatIntelligence) (*ValidationResult, error)
	CalculateQualityScore(ctx context.Context, intel *entity.ThreatIntelligence) (float64, error)
	IdentifyDuplicates(ctx context.Context, tenantID uuid.UUID, intel *entity.ThreatIntelligence) ([]*entity.ThreatIntelligence, error)
	MergeIntel(ctx context.Context, sourceID, targetID uuid.UUID) error
	
	// Lifecycle Management
	UpdateLastSeen(ctx context.Context, id uuid.UUID) error
	MarkExpired(ctx context.Context, ids []uuid.UUID) error
	CleanupExpired(ctx context.Context, tenantID uuid.UUID) (int64, error)
	RefreshValidity(ctx context.Context, tenantID uuid.UUID) error
	
	// Export and Import
	ExportIntel(ctx context.Context, tenantID uuid.UUID, format string, filter IntelFilter) ([]byte, error)
	ImportIntel(ctx context.Context, tenantID uuid.UUID, data []byte, format string) (*ImportResult, error)
	
	// Health and Monitoring
	HealthCheck(ctx context.Context) error
	GetMetrics(ctx context.Context) (*IntelRepositoryMetrics, error)
}

// IntelFilter represents filtering criteria for threat intelligence
type IntelFilter struct {
	TenantID        *uuid.UUID                 `json:"tenant_id,omitempty"`
	Types           []entity.IntelType         `json:"types,omitempty"`
	Categories      []entity.IntelCategory     `json:"categories,omitempty"`
	Sources         []string                   `json:"sources,omitempty"`
	Confidences     []entity.IntelConfidence   `json:"confidences,omitempty"`
	Reliabilities   []entity.IntelReliability  `json:"reliabilities,omitempty"`
	Qualities       []entity.IntelQuality      `json:"qualities,omitempty"`
	TLPLevels       []entity.TLPLevel          `json:"tlp_levels,omitempty"`
	Classifications []entity.Classification    `json:"classifications,omitempty"`
	SharingLevels   []entity.SharingLevel      `json:"sharing_levels,omitempty"`
	
	// Quality Filters
	MinRelevance    *float64 `json:"min_relevance,omitempty"`
	MaxRelevance    *float64 `json:"max_relevance,omitempty"`
	MinScore        *float64 `json:"min_score,omitempty"`
	MaxScore        *float64 `json:"max_score,omitempty"`
	
	// Time-based Filters
	PublishedAfter  *time.Time `json:"published_after,omitempty"`
	PublishedBefore *time.Time `json:"published_before,omitempty"`
	ValidAfter      *time.Time `json:"valid_after,omitempty"`
	ValidBefore     *time.Time `json:"valid_before,omitempty"`
	FirstSeenAfter  *time.Time `json:"first_seen_after,omitempty"`
	FirstSeenBefore *time.Time `json:"first_seen_before,omitempty"`
	LastSeenAfter   *time.Time `json:"last_seen_after,omitempty"`
	LastSeenBefore  *time.Time `json:"last_seen_before,omitempty"`
	
	// Indicator Filters
	IndicatorTypes  []entity.IOCType `json:"indicator_types,omitempty"`
	IndicatorValues []string         `json:"indicator_values,omitempty"`
	HasIndicators   *bool            `json:"has_indicators,omitempty"`
	
	// MITRE ATT&CK Filters
	MITRETactics    []string `json:"mitre_tactics,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
	
	// Campaign and Actor Filters
	CampaignIDs     []uuid.UUID `json:"campaign_ids,omitempty"`
	ThreatActorIDs  []uuid.UUID `json:"threat_actor_ids,omitempty"`
	TTPIDs          []uuid.UUID `json:"ttp_ids,omitempty"`
	
	// Vulnerability Filters
	CVEs            []string `json:"cves,omitempty"`
	MinCVSS         *float64 `json:"min_cvss,omitempty"`
	MaxCVSS         *float64 `json:"max_cvss,omitempty"`
	
	// Status Filters
	IsActive        *bool `json:"is_active,omitempty"`
	IsExpired       *bool `json:"is_expired,omitempty"`
	
	// Text Search
	Search          *string  `json:"search,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	
	// Feed Filters
	FeedIDs         []uuid.UUID `json:"feed_ids,omitempty"`
}

// IntelSort represents sorting criteria for threat intelligence
type IntelSort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// IntelListResult represents a paginated list of threat intelligence
type IntelListResult struct {
	Intelligence []*entity.ThreatIntelligence `json:"intelligence"`
	Pagination   PageResponse                 `json:"pagination"`
}

// IntelMatch represents a match between threat data and intelligence
type IntelMatch struct {
	IntelID      uuid.UUID                   `json:"intel_id"`
	Intelligence *entity.ThreatIntelligence  `json:"intelligence"`
	MatchType    string                      `json:"match_type"`
	Confidence   float64                     `json:"confidence"`
	MatchedField string                      `json:"matched_field"`
	MatchedValue string                      `json:"matched_value"`
	Context      map[string]interface{}      `json:"context,omitempty"`
}

// IntelCorrelation represents correlation between threat and intelligence
type IntelCorrelation struct {
	ThreatID     uuid.UUID                   `json:"threat_id"`
	IntelID      uuid.UUID                   `json:"intel_id"`
	Intelligence *entity.ThreatIntelligence  `json:"intelligence"`
	Score        float64                     `json:"score"`
	Factors      []CorrelationFactor         `json:"factors"`
	Confidence   float64                     `json:"confidence"`
	Context      map[string]interface{}      `json:"context,omitempty"`
}

// CorrelationFactor represents a factor in threat-intelligence correlation
type CorrelationFactor struct {
	Type        string  `json:"type"`
	Field       string  `json:"field"`
	Value       string  `json:"value"`
	Weight      float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
}

// MITRECoverage represents MITRE ATT&CK framework coverage
type MITRECoverage struct {
	TotalTactics         int                    `json:"total_tactics"`
	CoveredTactics       int                    `json:"covered_tactics"`
	TacticCoverage       float64                `json:"tactic_coverage"`
	TotalTechniques      int                    `json:"total_techniques"`
	CoveredTechniques    int                    `json:"covered_techniques"`
	TechniqueCoverage    float64                `json:"technique_coverage"`
	TacticDetails        []MITRECoverageDetail  `json:"tactic_details"`
	TechniqueDetails     []MITRECoverageDetail  `json:"technique_details"`
	GapAnalysis          []MITREGap             `json:"gap_analysis"`
}

// MITRECoverageDetail represents detailed coverage for a MITRE item
type MITRECoverageDetail struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	IsCovered      bool      `json:"is_covered"`
	IntelCount     int       `json:"intel_count"`
	LastUpdated    time.Time `json:"last_updated"`
	QualityScore   float64   `json:"quality_score"`
}

// MITREGap represents a gap in MITRE coverage
type MITREGap struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"` // "tactic" or "technique"
	Severity    string  `json:"severity"`
	Priority    int     `json:"priority"`
	Description string  `json:"description"`
}

// IntelFeed represents a threat intelligence feed
type IntelFeed struct {
	ID          uuid.UUID             `json:"id" bson:"_id"`
	TenantID    uuid.UUID             `json:"tenant_id" bson:"tenant_id"`
	Name        string                `json:"name" bson:"name"`
	Description string                `json:"description" bson:"description"`
	Source      string                `json:"source" bson:"source"`
	Type        string                `json:"type" bson:"type"` // "api", "file", "rss", etc.
	URL         string                `json:"url,omitempty" bson:"url,omitempty"`
	Format      string                `json:"format" bson:"format"` // "json", "xml", "csv", "stix", etc.
	
	// Feed Configuration
	UpdateInterval  time.Duration         `json:"update_interval" bson:"update_interval"`
	Enabled         bool                  `json:"enabled" bson:"enabled"`
	AutoProcess     bool                  `json:"auto_process" bson:"auto_process"`
	Quality         entity.IntelQuality   `json:"quality" bson:"quality"`
	Reliability     entity.IntelReliability `json:"reliability" bson:"reliability"`
	TLPLevel        entity.TLPLevel       `json:"tlp_level" bson:"tlp_level"`
	
	// Authentication
	AuthType        string                `json:"auth_type,omitempty" bson:"auth_type,omitempty"`
	AuthConfig      map[string]interface{} `json:"auth_config,omitempty" bson:"auth_config,omitempty"`
	
	// Processing Rules
	ProcessingRules []ProcessingRule      `json:"processing_rules,omitempty" bson:"processing_rules,omitempty"`
	TagRules        []TagRule            `json:"tag_rules,omitempty" bson:"tag_rules,omitempty"`
	
	// Status and Metrics
	LastUpdate      time.Time             `json:"last_update" bson:"last_update"`
	LastSuccess     time.Time             `json:"last_success" bson:"last_success"`
	LastError       string                `json:"last_error,omitempty" bson:"last_error,omitempty"`
	ErrorCount      int                   `json:"error_count" bson:"error_count"`
	SuccessCount    int64                 `json:"success_count" bson:"success_count"`
	TotalRecords    int64                 `json:"total_records" bson:"total_records"`
	
	// Metadata
	Tags            []string              `json:"tags,omitempty" bson:"tags,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
	
	// Timestamps
	CreatedAt       time.Time             `json:"created_at" bson:"created_at"`
	UpdatedAt       time.Time             `json:"updated_at" bson:"updated_at"`
}

// ProcessingRule represents a rule for processing feed data
type ProcessingRule struct {
	Name        string                 `json:"name" bson:"name"`
	Type        string                 `json:"type" bson:"type"` // "filter", "transform", "enrich"
	Condition   string                 `json:"condition" bson:"condition"`
	Action      string                 `json:"action" bson:"action"`
	Parameters  map[string]interface{} `json:"parameters,omitempty" bson:"parameters,omitempty"`
	Enabled     bool                   `json:"enabled" bson:"enabled"`
}

// TagRule represents a rule for auto-tagging intelligence
type TagRule struct {
	Name        string   `json:"name" bson:"name"`
	Condition   string   `json:"condition" bson:"condition"`
	Tags        []string `json:"tags" bson:"tags"`
	Enabled     bool     `json:"enabled" bson:"enabled"`
}

// FeedStatistics represents statistics for a threat intelligence feed
type FeedStatistics struct {
	FeedID           uuid.UUID                 `json:"feed_id"`
	TotalRecords     int64                     `json:"total_records"`
	ProcessedRecords int64                     `json:"processed_records"`
	FailedRecords    int64                     `json:"failed_records"`
	DuplicateRecords int64                     `json:"duplicate_records"`
	LastUpdate       time.Time                 `json:"last_update"`
	UpdateFrequency  time.Duration             `json:"update_frequency"`
	AverageQuality   float64                   `json:"average_quality"`
	RecordsByType    map[entity.IntelType]int64 `json:"records_by_type"`
	ErrorsByType     map[string]int64          `json:"errors_by_type"`
	ProcessingTime   time.Duration             `json:"processing_time"`
}

// IntelAggregation represents aggregated threat intelligence data
type IntelAggregation struct {
	TotalIntel          int64                                   `json:"total_intel"`
	IntelByType         map[entity.IntelType]int64              `json:"intel_by_type"`
	IntelByCategory     map[entity.IntelCategory]int64          `json:"intel_by_category"`
	IntelBySource       map[string]int64                        `json:"intel_by_source"`
	IntelByConfidence   map[entity.IntelConfidence]int64        `json:"intel_by_confidence"`
	IntelByReliability  map[entity.IntelReliability]int64       `json:"intel_by_reliability"`
	IntelByQuality      map[entity.IntelQuality]int64           `json:"intel_by_quality"`
	IntelByTLP          map[entity.TLPLevel]int64               `json:"intel_by_tlp"`
	ActiveIntel         int64                                   `json:"active_intel"`
	ExpiredIntel        int64                                   `json:"expired_intel"`
	AverageRelevance    float64                                 `json:"average_relevance"`
	AverageScore        float64                                 `json:"average_score"`
	TotalIndicators     int64                                   `json:"total_indicators"`
	IndicatorsByType    map[entity.IOCType]int64                `json:"indicators_by_type"`
	MITRECoverage       *MITRECoverage                          `json:"mitre_coverage,omitempty"`
	SourceQuality       map[string]float64                      `json:"source_quality"`
	FeedStatistics      map[uuid.UUID]*FeedStatistics           `json:"feed_statistics"`
}

// IntelTrends represents threat intelligence trend data over time
type IntelTrends struct {
	Period      string                   `json:"period"`
	Interval    string                   `json:"interval"`
	DataPoints  []IntelTrendDataPoint    `json:"data_points"`
	Summary     *IntelTrendSummary       `json:"summary"`
}

// IntelTrendDataPoint represents a single data point in intelligence trend analysis
type IntelTrendDataPoint struct {
	Timestamp       time.Time                           `json:"timestamp"`
	Count           int64                               `json:"count"`
	Type            map[entity.IntelType]int64          `json:"type"`
	Source          map[string]int64                    `json:"source"`
	Quality         map[entity.IntelQuality]int64       `json:"quality"`
	AverageScore    float64                             `json:"average_score"`
	IndicatorCount  int64                               `json:"indicator_count"`
}

// IntelTrendSummary represents summary of intelligence trend analysis
type IntelTrendSummary struct {
	TotalIntel       int64     `json:"total_intel"`
	AveragePerPeriod float64   `json:"average_per_period"`
	PeakCount        int64     `json:"peak_count"`
	PeakTimestamp    time.Time `json:"peak_timestamp"`
	TrendDirection   string    `json:"trend_direction"` // "increasing", "decreasing", "stable"
	GrowthRate       float64   `json:"growth_rate"`
	QualityTrend     string    `json:"quality_trend"`
	TopSources       []string  `json:"top_sources"`
}

// SourceQuality represents quality metrics for an intelligence source
type SourceQuality struct {
	Source          string                              `json:"source"`
	TotalRecords    int64                               `json:"total_records"`
	AverageQuality  float64                             `json:"average_quality"`
	Reliability     entity.IntelReliability             `json:"reliability"`
	Confidence      entity.IntelConfidence              `json:"confidence"`
	Accuracy        float64                             `json:"accuracy"`
	Timeliness      float64                             `json:"timeliness"`
	Completeness    float64                             `json:"completeness"`
	Relevance       float64                             `json:"relevance"`
	FalsePositives  int64                               `json:"false_positives"`
	TruePositives   int64                               `json:"true_positives"`
	RecordsByType   map[entity.IntelType]int64          `json:"records_by_type"`
	LastUpdate      time.Time                           `json:"last_update"`
	UpdateFrequency time.Duration                       `json:"update_frequency"`
}

// IntelCoverage represents coverage analysis for threat intelligence
type IntelCoverage struct {
	TotalCoverage      float64                         `json:"total_coverage"`
	TypeCoverage       map[entity.IntelType]float64    `json:"type_coverage"`
	ThreatCoverage     map[entity.ThreatType]float64   `json:"threat_coverage"`
	GeographicCoverage map[string]float64              `json:"geographic_coverage"`
	IndustryCoverage   map[string]float64              `json:"industry_coverage"`
	MITRECoverage      *MITRECoverage                  `json:"mitre_coverage"`
	GapAnalysis        []CoverageGap                   `json:"gap_analysis"`
	Recommendations    []CoverageRecommendation        `json:"recommendations"`
}

// CoverageGap represents a gap in threat intelligence coverage
type CoverageGap struct {
	Type        string  `json:"type"`
	Area        string  `json:"area"`
	Severity    string  `json:"severity"`
	Priority    int     `json:"priority"`
	Description string  `json:"description"`
	Impact      string  `json:"impact"`
}

// CoverageRecommendation represents a recommendation to improve coverage
type CoverageRecommendation struct {
	Type        string   `json:"type"`
	Priority    int      `json:"priority"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	Sources     []string `json:"recommended_sources"`
	Timeline    string   `json:"timeline"`
}

// ValidationResult represents the result of intelligence validation
type ValidationResult struct {
	IsValid      bool                   `json:"is_valid"`
	Score        float64                `json:"score"`
	Issues       []ValidationIssue      `json:"issues"`
	Warnings     []ValidationWarning    `json:"warnings"`
	Suggestions  []ValidationSuggestion `json:"suggestions"`
	Confidence   float64                `json:"confidence"`
}

// ValidationIssue represents a validation issue
type ValidationIssue struct {
	Type        string `json:"type"`
	Field       string `json:"field"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Type    string `json:"type"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationSuggestion represents a validation suggestion
type ValidationSuggestion struct {
	Type        string `json:"type"`
	Field       string `json:"field"`
	Message     string `json:"message"`
	Improvement string `json:"improvement"`
}

// ImportResult represents the result of intelligence import
type ImportResult struct {
	TotalRecords     int64    `json:"total_records"`
	ProcessedRecords int64    `json:"processed_records"`
	SuccessfulRecords int64   `json:"successful_records"`
	FailedRecords    int64    `json:"failed_records"`
	DuplicateRecords int64    `json:"duplicate_records"`
	Errors           []string `json:"errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
	ProcessingTime   time.Duration `json:"processing_time"`
}

// IntelRepositoryMetrics represents repository metrics for threat intelligence
type IntelRepositoryMetrics struct {
	QueriesPerSecond    float64           `json:"queries_per_second"`
	AverageQueryTime    time.Duration     `json:"average_query_time"`
	SlowQueries         int64             `json:"slow_queries"`
	CacheHitRatio       float64           `json:"cache_hit_ratio"`
	IndexUsage          map[string]float64 `json:"index_usage"`
	CollectionSize      int64             `json:"collection_size"`
	DocumentCount       int64             `json:"document_count"`
	AverageDocumentSize float64           `json:"average_document_size"`
	ErrorRate           float64           `json:"error_rate"`
	FeedProcessingTime  map[uuid.UUID]time.Duration `json:"feed_processing_time"`
}