package repository

import (
	"context"
	"time"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/shared/types"
)

// EventRepository defines the interface for event persistence
type EventRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, event *entity.Event) error
	GetByID(ctx context.Context, tenantID types.TenantID, eventID types.EventID) (*entity.Event, error)
	Update(ctx context.Context, event *entity.Event) error
	Delete(ctx context.Context, tenantID types.TenantID, eventID types.EventID) error
	
	// Batch operations
	CreateBatch(ctx context.Context, events []*entity.Event) error
	UpdateBatch(ctx context.Context, events []*entity.Event) error
	
	// Query operations
	Find(ctx context.Context, filter *entity.EventFilter) ([]*entity.Event, error)
	FindWithPagination(ctx context.Context, filter *entity.EventFilter, limit, offset int) ([]*entity.Event, int64, error)
	Count(ctx context.Context, filter *entity.EventFilter) (int64, error)
	
	// Search operations
	Search(ctx context.Context, tenantID types.TenantID, query string, limit, offset int) ([]*entity.Event, int64, error)
	SearchByTimeRange(ctx context.Context, tenantID types.TenantID, from, to time.Time, limit, offset int) ([]*entity.Event, error)
	
	// Status operations
	GetByStatus(ctx context.Context, tenantID types.TenantID, status entity.EventStatus, limit, offset int) ([]*entity.Event, error)
	UpdateStatus(ctx context.Context, tenantID types.TenantID, eventID types.EventID, status entity.EventStatus) error
	UpdateStatusBatch(ctx context.Context, tenantID types.TenantID, eventIDs []types.EventID, status entity.EventStatus) error
	
	// Correlation operations
	GetByCorrelationID(ctx context.Context, tenantID types.TenantID, correlationID types.CorrelationID) ([]*entity.Event, error)
	GetRelatedEvents(ctx context.Context, tenantID types.TenantID, eventID types.EventID) ([]*entity.Event, error)
	GetEventChain(ctx context.Context, tenantID types.TenantID, rootEventID types.EventID) ([]*entity.Event, error)
	
	// Asset correlation operations
	GetByAssetID(ctx context.Context, tenantID types.TenantID, assetID types.AssetID, limit, offset int) ([]*entity.Event, error)
	GetByAssetType(ctx context.Context, tenantID types.TenantID, assetType string, limit, offset int) ([]*entity.Event, error)
	
	// User correlation operations
	GetByUserID(ctx context.Context, tenantID types.TenantID, userID types.UserID, limit, offset int) ([]*entity.Event, error)
	GetByUsername(ctx context.Context, tenantID types.TenantID, username string, limit, offset int) ([]*entity.Event, error)
	
	// Risk-based operations
	GetHighRiskEvents(ctx context.Context, tenantID types.TenantID, minRiskScore float64, limit, offset int) ([]*entity.Event, error)
	GetByRiskFactors(ctx context.Context, tenantID types.TenantID, riskFactors []string, limit, offset int) ([]*entity.Event, error)
	
	// Network-based operations
	GetBySourceIP(ctx context.Context, tenantID types.TenantID, sourceIP string, limit, offset int) ([]*entity.Event, error)
	GetByDestinationIP(ctx context.Context, tenantID types.TenantID, destinationIP string, limit, offset int) ([]*entity.Event, error)
	GetByIPRange(ctx context.Context, tenantID types.TenantID, ipRange string, limit, offset int) ([]*entity.Event, error)
	
	// Type and category operations
	GetByType(ctx context.Context, tenantID types.TenantID, eventType types.EventType, limit, offset int) ([]*entity.Event, error)
	GetByCategory(ctx context.Context, tenantID types.TenantID, category string, limit, offset int) ([]*entity.Event, error)
	GetBySeverity(ctx context.Context, tenantID types.TenantID, severity types.Severity, limit, offset int) ([]*entity.Event, error)
	
	// Source operations
	GetBySource(ctx context.Context, tenantID types.TenantID, source string, limit, offset int) ([]*entity.Event, error)
	GetSources(ctx context.Context, tenantID types.TenantID) ([]string, error)
	
	// Tag operations
	GetByTag(ctx context.Context, tenantID types.TenantID, tag string, limit, offset int) ([]*entity.Event, error)
	GetByTags(ctx context.Context, tenantID types.TenantID, tags []string, matchAll bool, limit, offset int) ([]*entity.Event, error)
	GetTags(ctx context.Context, tenantID types.TenantID) ([]string, error)
	
	// Processing operations
	GetPendingEvents(ctx context.Context, tenantID types.TenantID, limit int) ([]*entity.Event, error)
	GetFailedEvents(ctx context.Context, tenantID types.TenantID, limit, offset int) ([]*entity.Event, error)
	GetEventsForReprocessing(ctx context.Context, tenantID types.TenantID, limit int) ([]*entity.Event, error)
	
	// Aggregation operations
	GetEventStats(ctx context.Context, tenantID types.TenantID, from, to time.Time) (*EventStats, error)
	GetEventsByTimeWindow(ctx context.Context, tenantID types.TenantID, from, to time.Time, windowSize time.Duration) ([]*EventTimeWindow, error)
	GetTopSources(ctx context.Context, tenantID types.TenantID, from, to time.Time, limit int) ([]*SourceStats, error)
	GetTopEventTypes(ctx context.Context, tenantID types.TenantID, from, to time.Time, limit int) ([]*TypeStats, error)
	GetSeverityDistribution(ctx context.Context, tenantID types.TenantID, from, to time.Time) ([]*SeverityStats, error)
	
	// Compliance operations
	GetByComplianceFlag(ctx context.Context, tenantID types.TenantID, flag string, limit, offset int) ([]*entity.Event, error)
	GetEventsForRetention(ctx context.Context, tenantID types.TenantID, retentionPolicy string, olderThan time.Time) ([]*entity.Event, error)
	
	// Maintenance operations
	Archive(ctx context.Context, tenantID types.TenantID, eventIDs []types.EventID) error
	DeleteOldEvents(ctx context.Context, tenantID types.TenantID, olderThan time.Time) (int64, error)
	DeleteByFilter(ctx context.Context, filter *entity.EventFilter) (int64, error)
	
	// Health and monitoring
	GetRepositoryHealth(ctx context.Context) (*RepositoryHealth, error)
	GetStorageStats(ctx context.Context, tenantID types.TenantID) (*StorageStats, error)
}

// EventStats represents aggregated event statistics
type EventStats struct {
	TotalEvents    int64                    `json:"total_events"`
	ProcessedEvents int64                   `json:"processed_events"`
	FailedEvents   int64                    `json:"failed_events"`
	PendingEvents  int64                    `json:"pending_events"`
	SeverityBreakdown map[types.Severity]int64 `json:"severity_breakdown"`
	TypeBreakdown     map[types.EventType]int64 `json:"type_breakdown"`
	SourceBreakdown   map[string]int64         `json:"source_breakdown"`
	AvgProcessingTime time.Duration            `json:"avg_processing_time"`
	AvgRiskScore      float64                  `json:"avg_risk_score"`
	HighRiskEvents    int64                    `json:"high_risk_events"`
	From              time.Time                `json:"from"`
	To                time.Time                `json:"to"`
}

// EventTimeWindow represents events in a time window
type EventTimeWindow struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	EventCount  int64     `json:"event_count"`
	AvgRiskScore float64  `json:"avg_risk_score"`
	SeverityBreakdown map[types.Severity]int64 `json:"severity_breakdown"`
}

// SourceStats represents statistics for an event source
type SourceStats struct {
	Source      string        `json:"source"`
	EventCount  int64         `json:"event_count"`
	AvgRiskScore float64      `json:"avg_risk_score"`
	LastEventAt time.Time     `json:"last_event_at"`
	SeverityBreakdown map[types.Severity]int64 `json:"severity_breakdown"`
}

// TypeStats represents statistics for an event type
type TypeStats struct {
	EventType   types.EventType `json:"event_type"`
	EventCount  int64           `json:"event_count"`
	AvgRiskScore float64        `json:"avg_risk_score"`
	LastEventAt time.Time       `json:"last_event_at"`
	SeverityBreakdown map[types.Severity]int64 `json:"severity_breakdown"`
}

// SeverityStats represents statistics for a severity level
type SeverityStats struct {
	Severity    types.Severity `json:"severity"`
	EventCount  int64          `json:"event_count"`
	Percentage  float64        `json:"percentage"`
	AvgRiskScore float64       `json:"avg_risk_score"`
}

// RepositoryHealth represents the health status of the repository
type RepositoryHealth struct {
	IsHealthy         bool          `json:"is_healthy"`
	ConnectionStatus  string        `json:"connection_status"`
	ResponseTime      time.Duration `json:"response_time"`
	LastHealthCheck   time.Time     `json:"last_health_check"`
	ErrorCount        int64         `json:"error_count"`
	LastError         string        `json:"last_error,omitempty"`
	DatabaseVersion   string        `json:"database_version,omitempty"`
	ConnectionPool    *PoolStats    `json:"connection_pool,omitempty"`
}

// PoolStats represents connection pool statistics
type PoolStats struct {
	ActiveConnections int `json:"active_connections"`
	IdleConnections   int `json:"idle_connections"`
	MaxConnections    int `json:"max_connections"`
	TotalConnections  int `json:"total_connections"`
}

// StorageStats represents storage statistics for a tenant
type StorageStats struct {
	TenantID           types.TenantID `json:"tenant_id"`
	TotalEvents        int64          `json:"total_events"`
	StorageSize        int64          `json:"storage_size_bytes"`
	IndexSize          int64          `json:"index_size_bytes"`
	OldestEvent        *time.Time     `json:"oldest_event,omitempty"`
	NewestEvent        *time.Time     `json:"newest_event,omitempty"`
	AvgEventSize       int64          `json:"avg_event_size_bytes"`
	CompressedSize     int64          `json:"compressed_size_bytes,omitempty"`
	CompressionRatio   float64        `json:"compression_ratio,omitempty"`
}

// Query represents a complex query for events
type Query struct {
	Filter     *entity.EventFilter `json:"filter"`
	Sort       []SortField         `json:"sort"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset"`
	Aggregates []Aggregate         `json:"aggregates,omitempty"`
}

// SortField represents a field to sort by
type SortField struct {
	Field string `json:"field"`
	Order string `json:"order"` // "asc" or "desc"
}

// Aggregate represents an aggregation operation
type Aggregate struct {
	Function string `json:"function"` // "count", "sum", "avg", "min", "max"
	Field    string `json:"field"`
	GroupBy  string `json:"group_by,omitempty"`
}

// QueryResult represents the result of a complex query
type QueryResult struct {
	Events      []*entity.Event            `json:"events"`
	TotalCount  int64                      `json:"total_count"`
	Aggregates  map[string]interface{}     `json:"aggregates,omitempty"`
	GroupedResults map[string][]*entity.Event `json:"grouped_results,omitempty"`
}

// EventRepositoryOption represents options for repository configuration
type EventRepositoryOption func(*EventRepositoryConfig)

// EventRepositoryConfig represents repository configuration
type EventRepositoryConfig struct {
	BatchSize        int           `json:"batch_size"`
	QueryTimeout     time.Duration `json:"query_timeout"`
	ConnectionPool   *PoolConfig   `json:"connection_pool"`
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheTTL         time.Duration `json:"cache_ttl"`
	IndexingEnabled  bool          `json:"indexing_enabled"`
	CompressionEnabled bool        `json:"compression_enabled"`
	PartitioningEnabled bool       `json:"partitioning_enabled"`
	PartitionField   string        `json:"partition_field"`
	RetentionPolicy  string        `json:"retention_policy"`
}

// PoolConfig represents connection pool configuration
type PoolConfig struct {
	MaxConnections     int           `json:"max_connections"`
	MaxIdleConnections int           `json:"max_idle_connections"`
	ConnectionTimeout  time.Duration `json:"connection_timeout"`
	IdleTimeout        time.Duration `json:"idle_timeout"`
	MaxLifetime        time.Duration `json:"max_lifetime"`
}

// WithBatchSize sets the batch size for bulk operations
func WithBatchSize(size int) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.BatchSize = size
	}
}

// WithQueryTimeout sets the query timeout
func WithQueryTimeout(timeout time.Duration) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.QueryTimeout = timeout
	}
}

// WithCaching enables caching with the specified TTL
func WithCaching(enabled bool, ttl time.Duration) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.CacheEnabled = enabled
		config.CacheTTL = ttl
	}
}

// WithIndexing enables indexing
func WithIndexing(enabled bool) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.IndexingEnabled = enabled
	}
}

// WithCompression enables compression
func WithCompression(enabled bool) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.CompressionEnabled = enabled
	}
}

// WithPartitioning enables partitioning by the specified field
func WithPartitioning(enabled bool, field string) EventRepositoryOption {
	return func(config *EventRepositoryConfig) {
		config.PartitioningEnabled = enabled
		config.PartitionField = field
	}
}