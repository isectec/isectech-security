package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"threat-detection/domain/entity"
)

// ThreatRepository defines the interface for threat data access
type ThreatRepository interface {
	// CRUD Operations
	Create(ctx context.Context, threat *entity.Threat) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Threat, error)
	GetByTenantAndID(ctx context.Context, tenantID, id uuid.UUID) (*entity.Threat, error)
	Update(ctx context.Context, threat *entity.Threat) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error

	// Query Operations
	List(ctx context.Context, filter ThreatFilter, sort []ThreatSort, page PageRequest) (*ThreatListResult, error)
	Search(ctx context.Context, tenantID uuid.UUID, query string, filter ThreatFilter, page PageRequest) (*ThreatListResult, error)
	
	// Tenant-specific Operations
	GetByTenant(ctx context.Context, tenantID uuid.UUID, filter ThreatFilter, page PageRequest) (*ThreatListResult, error)
	GetActiveThreatsByTenant(ctx context.Context, tenantID uuid.UUID) ([]*entity.Threat, error)
	GetThreatsByTimeRange(ctx context.Context, tenantID uuid.UUID, start, end time.Time) ([]*entity.Threat, error)
	
	// Status and Lifecycle
	GetByStatus(ctx context.Context, tenantID uuid.UUID, status entity.ThreatStatus) ([]*entity.Threat, error)
	GetExpiredThreats(ctx context.Context, tenantID uuid.UUID) ([]*entity.Threat, error)
	GetStaleThreats(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) ([]*entity.Threat, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status entity.ThreatStatus) error
	BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status entity.ThreatStatus) error
	
	// Real-time and Streaming
	GetRecentThreats(ctx context.Context, tenantID uuid.UUID, duration time.Duration) ([]*entity.Threat, error)
	StreamThreats(ctx context.Context, tenantID uuid.UUID, since time.Time) (<-chan *entity.Threat, error)
	
	// IOC and Indicator Operations
	GetThreatsByIOC(ctx context.Context, tenantID uuid.UUID, iocType entity.IOCType, value string) ([]*entity.Threat, error)
	GetThreatsByIndicators(ctx context.Context, tenantID uuid.UUID, indicators []entity.IndicatorOfCompromise) ([]*entity.Threat, error)
	UpdateIOCs(ctx context.Context, threatID uuid.UUID, iocs []entity.IndicatorOfCompromise) error
	
	// MITRE ATT&CK Framework
	GetThreatsByMITRETactic(ctx context.Context, tenantID uuid.UUID, tacticID string) ([]*entity.Threat, error)
	GetThreatsByMITRETechnique(ctx context.Context, tenantID uuid.UUID, techniqueID string) ([]*entity.Threat, error)
	GetMITREStatistics(ctx context.Context, tenantID uuid.UUID) (*MITREStatistics, error)
	
	// Risk and Scoring
	GetThreatsByRiskScore(ctx context.Context, tenantID uuid.UUID, minScore, maxScore float64) ([]*entity.Threat, error)
	GetThreatsBySeverity(ctx context.Context, tenantID uuid.UUID, severity entity.ThreatSeverity) ([]*entity.Threat, error)
	UpdateRiskScore(ctx context.Context, threatID uuid.UUID, riskScore float64) error
	
	// Correlation and Relationships
	GetRelatedThreats(ctx context.Context, threatID uuid.UUID, limit int) ([]*entity.Threat, error)
	GetThreatsByAsset(ctx context.Context, tenantID uuid.UUID, assetID uuid.UUID) ([]*entity.Threat, error)
	GetThreatsBySource(ctx context.Context, tenantID uuid.UUID, sourceIP string) ([]*entity.Threat, error)
	GetThreatsByTarget(ctx context.Context, tenantID uuid.UUID, targetIP string) ([]*entity.Threat, error)
	LinkThreats(ctx context.Context, threatID1, threatID2 uuid.UUID, relationship string) error
	
	// Evidence and Timeline
	AddEvidence(ctx context.Context, threatID uuid.UUID, evidence entity.ThreatEvidence) error
	GetEvidence(ctx context.Context, threatID uuid.UUID) ([]entity.ThreatEvidence, error)
	AddTimelineEvent(ctx context.Context, threatID uuid.UUID, event entity.ThreatTimelineEvent) error
	GetTimeline(ctx context.Context, threatID uuid.UUID) ([]entity.ThreatTimelineEvent, error)
	
	// Response Actions
	AddResponseAction(ctx context.Context, threatID uuid.UUID, action entity.ResponseAction) error
	GetResponseActions(ctx context.Context, threatID uuid.UUID) ([]entity.ResponseAction, error)
	UpdateResponseAction(ctx context.Context, threatID uuid.UUID, actionID uuid.UUID, status entity.ResponseActionStatus) error
	
	// Analytics and Aggregation
	GetAggregation(ctx context.Context, tenantID uuid.UUID, filter ThreatFilter) (*ThreatAggregation, error)
	GetThreatTrends(ctx context.Context, tenantID uuid.UUID, duration time.Duration, interval string) (*ThreatTrends, error)
	GetThreatHeatmap(ctx context.Context, tenantID uuid.UUID, timeRange TimeRange) (*ThreatHeatmap, error)
	GetTopThreats(ctx context.Context, tenantID uuid.UUID, limit int, timeRange TimeRange) ([]*ThreatSummary, error)
	
	// Time-series Operations (MongoDB specific)
	GetTimeSeriesData(ctx context.Context, tenantID uuid.UUID, metricType string, timeRange TimeRange, granularity string) ([]*TimeSeriesPoint, error)
	InsertTimeSeriesPoint(ctx context.Context, point *TimeSeriesPoint) error
	AggregateTimeSeriesData(ctx context.Context, tenantID uuid.UUID, pipeline []interface{}) ([]interface{}, error)
	
	// Bulk Operations
	BulkCreate(ctx context.Context, threats []*entity.Threat) error
	BulkUpdate(ctx context.Context, threats []*entity.Threat) error
	BulkDelete(ctx context.Context, ids []uuid.UUID) error
	
	// Indexing and Performance
	CreateIndexes(ctx context.Context) error
	OptimizeQueries(ctx context.Context) error
	GetStatistics(ctx context.Context) (*RepositoryStatistics, error)
	
	// Health and Monitoring
	HealthCheck(ctx context.Context) error
	GetMetrics(ctx context.Context) (*RepositoryMetrics, error)
}

// ThreatFilter represents filtering criteria for threats
type ThreatFilter struct {
	TenantID        *uuid.UUID               `json:"tenant_id,omitempty"`
	Types           []entity.ThreatType      `json:"types,omitempty"`
	Severities      []entity.ThreatSeverity  `json:"severities,omitempty"`
	Statuses        []entity.ThreatStatus    `json:"statuses,omitempty"`
	Confidences     []entity.ThreatConfidence `json:"confidences,omitempty"`
	Sources         []string                 `json:"sources,omitempty"`
	DetectionEngines []string                `json:"detection_engines,omitempty"`
	
	// Risk and Scoring
	MinRiskScore    *float64 `json:"min_risk_score,omitempty"`
	MaxRiskScore    *float64 `json:"max_risk_score,omitempty"`
	MinImpactScore  *float64 `json:"min_impact_score,omitempty"`
	MaxImpactScore  *float64 `json:"max_impact_score,omitempty"`
	
	// Time-based Filters
	DetectedAfter   *time.Time `json:"detected_after,omitempty"`
	DetectedBefore  *time.Time `json:"detected_before,omitempty"`
	FirstSeenAfter  *time.Time `json:"first_seen_after,omitempty"`
	FirstSeenBefore *time.Time `json:"first_seen_before,omitempty"`
	LastSeenAfter   *time.Time `json:"last_seen_after,omitempty"`
	LastSeenBefore  *time.Time `json:"last_seen_before,omitempty"`
	
	// Network Filters
	SourceIPs       []string `json:"source_ips,omitempty"`
	TargetIPs       []string `json:"target_ips,omitempty"`
	SourcePorts     []int    `json:"source_ports,omitempty"`
	TargetPorts     []int    `json:"target_ports,omitempty"`
	Protocols       []string `json:"protocols,omitempty"`
	
	// MITRE ATT&CK Filters
	MITRETactics    []string `json:"mitre_tactics,omitempty"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
	
	// IOC Filters
	IOCTypes        []entity.IOCType `json:"ioc_types,omitempty"`
	IOCValues       []string         `json:"ioc_values,omitempty"`
	
	// Asset and User Filters
	AssetIDs        []uuid.UUID `json:"asset_ids,omitempty"`
	SourceUsers     []string    `json:"source_users,omitempty"`
	TargetUsers     []string    `json:"target_users,omitempty"`
	
	// Response Filters
	AssignedTo      *string                        `json:"assigned_to,omitempty"`
	IncidentID      *uuid.UUID                     `json:"incident_id,omitempty"`
	ResponseStatus  []entity.ResponseActionStatus  `json:"response_status,omitempty"`
	
	// Text Search
	Search          *string  `json:"search,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	
	// Advanced Filters
	HasEvidence     *bool    `json:"has_evidence,omitempty"`
	HasResponseActions *bool `json:"has_response_actions,omitempty"`
	IsActive        *bool    `json:"is_active,omitempty"`
}

// ThreatSort represents sorting criteria
type ThreatSort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // "asc" or "desc"
}

// PageRequest represents pagination parameters
type PageRequest struct {
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

// PageResponse represents pagination metadata
type PageResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
	TotalItems int64 `json:"total_items"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// ThreatListResult represents a paginated list of threats
type ThreatListResult struct {
	Threats    []*entity.Threat `json:"threats"`
	Pagination PageResponse     `json:"pagination"`
}

// ThreatAggregation represents aggregated threat data
type ThreatAggregation struct {
	TotalThreats         int64                               `json:"total_threats"`
	ThreatsByType        map[entity.ThreatType]int64         `json:"threats_by_type"`
	ThreatsBySeverity    map[entity.ThreatSeverity]int64     `json:"threats_by_severity"`
	ThreatsByStatus      map[entity.ThreatStatus]int64       `json:"threats_by_status"`
	ThreatsByConfidence  map[entity.ThreatConfidence]int64   `json:"threats_by_confidence"`
	ThreatsBySource      map[string]int64                    `json:"threats_by_source"`
	ThreatsByEngine      map[string]int64                    `json:"threats_by_engine"`
	AverageRiskScore     float64                             `json:"average_risk_score"`
	MaxRiskScore         float64                             `json:"max_risk_score"`
	MinRiskScore         float64                             `json:"min_risk_score"`
	TotalIOCs            int64                               `json:"total_iocs"`
	IOCsByType           map[entity.IOCType]int64            `json:"iocs_by_type"`
	MITREStatistics      *MITREStatistics                    `json:"mitre_statistics,omitempty"`
	NetworkStatistics    *NetworkThreatStatistics            `json:"network_statistics,omitempty"`
	ResponseStatistics   *ResponseStatistics                 `json:"response_statistics,omitempty"`
}

// MITREStatistics represents MITRE ATT&CK framework statistics
type MITREStatistics struct {
	TotalTactics         int                 `json:"total_tactics"`
	TotalTechniques      int                 `json:"total_techniques"`
	TotalSubTechniques   int                 `json:"total_sub_techniques"`
	TacticDistribution   map[string]int64    `json:"tactic_distribution"`
	TechniqueDistribution map[string]int64   `json:"technique_distribution"`
	KillChainCoverage    map[string]float64  `json:"kill_chain_coverage"`
	TopTactics           []MITREItem         `json:"top_tactics"`
	TopTechniques        []MITREItem         `json:"top_techniques"`
}

// MITREItem represents a MITRE tactic or technique with count
type MITREItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Count       int64  `json:"count"`
	Percentage  float64 `json:"percentage"`
}

// NetworkThreatStatistics represents network-related threat statistics
type NetworkThreatStatistics struct {
	TotalNetworkThreats  int64            `json:"total_network_threats"`
	UniqueSourceIPs      int64            `json:"unique_source_ips"`
	UniqueTargetIPs      int64            `json:"unique_target_ips"`
	TopSourceIPs         []IPStatistic    `json:"top_source_ips"`
	TopTargetIPs         []IPStatistic    `json:"top_target_ips"`
	ProtocolDistribution map[string]int64 `json:"protocol_distribution"`
	PortDistribution     map[int]int64    `json:"port_distribution"`
	BytesTransferred     int64            `json:"total_bytes_transferred"`
	PacketCount          int64            `json:"total_packet_count"`
}

// IPStatistic represents IP address statistics
type IPStatistic struct {
	IP         string  `json:"ip"`
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
	Country    string  `json:"country,omitempty"`
	ISP        string  `json:"isp,omitempty"`
}

// ResponseStatistics represents response action statistics
type ResponseStatistics struct {
	TotalResponseActions     int64                                      `json:"total_response_actions"`
	ActionsByType            map[entity.ResponseActionType]int64        `json:"actions_by_type"`
	ActionsByStatus          map[entity.ResponseActionStatus]int64      `json:"actions_by_status"`
	AverageResponseTime      time.Duration                              `json:"average_response_time"`
	SuccessfulActions        int64                                      `json:"successful_actions"`
	FailedActions            int64                                      `json:"failed_actions"`
	PendingActions           int64                                      `json:"pending_actions"`
	TopPerformers            []PerformerStatistic                       `json:"top_performers"`
}

// PerformerStatistic represents response performer statistics
type PerformerStatistic struct {
	Performer   string  `json:"performer"`
	Actions     int64   `json:"actions"`
	SuccessRate float64 `json:"success_rate"`
}

// ThreatTrends represents threat trend data over time
type ThreatTrends struct {
	Period      string             `json:"period"`
	Interval    string             `json:"interval"`
	DataPoints  []TrendDataPoint   `json:"data_points"`
	Summary     *TrendSummary      `json:"summary"`
}

// TrendDataPoint represents a single data point in trend analysis
type TrendDataPoint struct {
	Timestamp    time.Time                           `json:"timestamp"`
	Count        int64                               `json:"count"`
	Severity     map[entity.ThreatSeverity]int64     `json:"severity"`
	Type         map[entity.ThreatType]int64         `json:"type"`
	RiskScore    float64                             `json:"average_risk_score"`
}

// TrendSummary represents summary of trend analysis
type TrendSummary struct {
	TotalThreats     int64   `json:"total_threats"`
	AveragePerPeriod float64 `json:"average_per_period"`
	PeakCount        int64   `json:"peak_count"`
	PeakTimestamp    time.Time `json:"peak_timestamp"`
	TrendDirection   string  `json:"trend_direction"` // "increasing", "decreasing", "stable"
	GrowthRate       float64 `json:"growth_rate"`
}

// ThreatHeatmap represents threat activity heatmap data
type ThreatHeatmap struct {
	TimeRange   TimeRange           `json:"time_range"`
	GridData    [][]HeatmapCell     `json:"grid_data"`
	MaxValue    int64               `json:"max_value"`
	MinValue    int64               `json:"min_value"`
	Summary     *HeatmapSummary     `json:"summary"`
}

// HeatmapCell represents a single cell in the heatmap
type HeatmapCell struct {
	Timestamp   time.Time                       `json:"timestamp"`
	Value       int64                           `json:"value"`
	Severity    map[entity.ThreatSeverity]int64 `json:"severity"`
	Type        map[entity.ThreatType]int64     `json:"type"`
}

// HeatmapSummary represents summary of heatmap data
type HeatmapSummary struct {
	HottestPeriods  []time.Time `json:"hottest_periods"`
	QuietestPeriods []time.Time `json:"quietest_periods"`
	AverageActivity float64     `json:"average_activity"`
	PeakActivity    int64       `json:"peak_activity"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ThreatSummary represents a summary of threat information
type ThreatSummary struct {
	ID           uuid.UUID               `json:"id"`
	Name         string                  `json:"name"`
	Type         entity.ThreatType       `json:"type"`
	Severity     entity.ThreatSeverity   `json:"severity"`
	Status       entity.ThreatStatus     `json:"status"`
	RiskScore    float64                 `json:"risk_score"`
	DetectedAt   time.Time               `json:"detected_at"`
	IOCCount     int                     `json:"ioc_count"`
	EvidenceCount int                    `json:"evidence_count"`
	ResponseCount int                    `json:"response_count"`
}

// TimeSeriesPoint represents a time-series data point
type TimeSeriesPoint struct {
	Timestamp  time.Time              `json:"timestamp" bson:"timestamp"`
	TenantID   uuid.UUID              `json:"tenant_id" bson:"tenant_id"`
	MetricType string                 `json:"metric_type" bson:"metric_type"`
	Value      float64                `json:"value" bson:"value"`
	Tags       map[string]string      `json:"tags,omitempty" bson:"tags,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty" bson:"metadata,omitempty"`
}

// RepositoryStatistics represents repository performance statistics
type RepositoryStatistics struct {
	TotalDocuments    int64             `json:"total_documents"`
	IndexCount        int               `json:"index_count"`
	AverageDocSize    float64           `json:"average_doc_size"`
	CollectionSize    int64             `json:"collection_size"`
	QueryPerformance  map[string]float64 `json:"query_performance"`
	LastOptimization  time.Time         `json:"last_optimization"`
}

// RepositoryMetrics represents repository metrics
type RepositoryMetrics struct {
	QueriesPerSecond     float64           `json:"queries_per_second"`
	AverageQueryTime     time.Duration     `json:"average_query_time"`
	SlowQueries          int64             `json:"slow_queries"`
	CacheHitRatio        float64           `json:"cache_hit_ratio"`
	ConnectionPoolUsage  float64           `json:"connection_pool_usage"`
	IndexUsage           map[string]float64 `json:"index_usage"`
	ErrorRate            float64           `json:"error_rate"`
}