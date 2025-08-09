// iSECTECH Asset Inventory - Asset Repository Interface
// Production-grade asset data persistence layer
// Copyright (c) 2024 iSECTECH. All rights reserved.

package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
)

// AssetRepository defines the interface for asset data persistence
type AssetRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, asset *entity.Asset) error
	GetByID(ctx context.Context, tenantID, assetID uuid.UUID) (*entity.Asset, error)
	Update(ctx context.Context, asset *entity.Asset) error
	Delete(ctx context.Context, tenantID, assetID uuid.UUID) error

	// Query operations
	List(ctx context.Context, tenantID uuid.UUID, filter AssetFilter) ([]*entity.Asset, error)
	Count(ctx context.Context, tenantID uuid.UUID, filter AssetFilter) (int64, error)
	Search(ctx context.Context, tenantID uuid.UUID, query AssetSearchQuery) ([]*entity.Asset, error)

	// Specialized queries
	FindByIPAddress(ctx context.Context, tenantID uuid.UUID, ipAddress string) ([]*entity.Asset, error)
	FindByHostname(ctx context.Context, tenantID uuid.UUID, hostname string) ([]*entity.Asset, error)
	FindByMACAddress(ctx context.Context, tenantID uuid.UUID, macAddress string) ([]*entity.Asset, error)
	FindByNetworkSegment(ctx context.Context, tenantID uuid.UUID, networkSegment string) ([]*entity.Asset, error)
	FindByAssetType(ctx context.Context, tenantID uuid.UUID, assetType entity.AssetType) ([]*entity.Asset, error)
	FindByCriticality(ctx context.Context, tenantID uuid.UUID, criticality entity.CriticalityLevel) ([]*entity.Asset, error)
	FindByOwner(ctx context.Context, tenantID uuid.UUID, owner string) ([]*entity.Asset, error)
	FindByBusinessFunction(ctx context.Context, tenantID uuid.UUID, businessFunction string) ([]*entity.Asset, error)
	FindByTags(ctx context.Context, tenantID uuid.UUID, tags map[string]string) ([]*entity.Asset, error)
	FindByComplianceFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error)

	// Discovery and inventory operations
	FindStaleAssets(ctx context.Context, tenantID uuid.UUID, threshold time.Duration) ([]*entity.Asset, error)
	FindAssetsNeedingScanning(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error)
	FindHighValueAssets(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error)
	FindAssetsWithVulnerabilities(ctx context.Context, tenantID uuid.UUID, minSeverity string) ([]*entity.Asset, error)

	// Deduplication support
	FindPotentialDuplicates(ctx context.Context, tenantID uuid.UUID, asset *entity.Asset) ([]*entity.Asset, error)
	FindByExternalID(ctx context.Context, tenantID uuid.UUID, system, externalID string) (*entity.Asset, error)

	// Bulk operations
	BulkCreate(ctx context.Context, assets []*entity.Asset) error
	BulkUpdate(ctx context.Context, assets []*entity.Asset) error
	BulkDelete(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) error
	BulkUpdateLastSeen(ctx context.Context, assetIDs []uuid.UUID, timestamp time.Time) error

	// Statistics and reporting
	GetAssetCounts(ctx context.Context, tenantID uuid.UUID) (*AssetCounts, error)
	GetAssetCountsByType(ctx context.Context, tenantID uuid.UUID) (map[entity.AssetType]int64, error)
	GetAssetCountsByCriticality(ctx context.Context, tenantID uuid.UUID) (map[entity.CriticalityLevel]int64, error)
	GetAssetCountsByStatus(ctx context.Context, tenantID uuid.UUID) (map[entity.AssetStatus]int64, error)
	GetNetworkSegmentDistribution(ctx context.Context, tenantID uuid.UUID) (map[string]int64, error)
	GetTopSoftware(ctx context.Context, tenantID uuid.UUID, limit int) ([]*SoftwareCount, error)
	GetTopVulnerabilities(ctx context.Context, tenantID uuid.UUID, limit int) ([]*VulnerabilityCount, error)

	// History and audit
	GetAssetHistory(ctx context.Context, tenantID, assetID uuid.UUID, limit int) ([]*entity.AssetChange, error)
	RecordAssetChange(ctx context.Context, tenantID, assetID uuid.UUID, change *entity.AssetChange) error

	// Relationships
	GetAssetRelationships(ctx context.Context, tenantID, assetID uuid.UUID) ([]*entity.AssetRelationship, error)
	CreateAssetRelationship(ctx context.Context, tenantID, assetID uuid.UUID, relationship *entity.AssetRelationship) error
	DeleteAssetRelationship(ctx context.Context, tenantID, assetID, relatedAssetID uuid.UUID) error

	// Compliance and governance
	GetComplianceAssets(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error)
	UpdateComplianceStatus(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, framework string, status string) error

	// Health and maintenance
	GetHealthStatus(ctx context.Context) (*RepositoryHealth, error)
	RunMaintenance(ctx context.Context) error
	OptimizeQueries(ctx context.Context) error
}

// AssetFilter defines filtering options for asset queries
type AssetFilter struct {
	// Basic filters
	AssetTypes      []entity.AssetType        `json:"asset_types,omitempty"`
	Criticalities   []entity.CriticalityLevel `json:"criticalities,omitempty"`
	Statuses        []entity.AssetStatus      `json:"statuses,omitempty"`
	ScanFrequencies []entity.ScanFrequency    `json:"scan_frequencies,omitempty"`

	// Location and network filters
	NetworkSegments []string `json:"network_segments,omitempty"`
	Datacenters     []string `json:"datacenters,omitempty"`
	Regions         []string `json:"regions,omitempty"`
	Countries       []string `json:"countries,omitempty"`

	// Business filters
	BusinessFunctions []string `json:"business_functions,omitempty"`
	Owners            []string `json:"owners,omitempty"`

	// Technical filters
	OperatingSystems []string `json:"operating_systems,omitempty"`
	Manufacturers    []string `json:"manufacturers,omitempty"`

	// Time-based filters
	CreatedAfter   *time.Time `json:"created_after,omitempty"`
	CreatedBefore  *time.Time `json:"created_before,omitempty"`
	UpdatedAfter   *time.Time `json:"updated_after,omitempty"`
	UpdatedBefore  *time.Time `json:"updated_before,omitempty"`
	LastSeenAfter  *time.Time `json:"last_seen_after,omitempty"`
	LastSeenBefore *time.Time `json:"last_seen_before,omitempty"`

	// Security filters
	HasVulnerabilities    *bool                       `json:"has_vulnerabilities,omitempty"`
	MinVulnerabilityCount *int                        `json:"min_vulnerability_count,omitempty"`
	EncryptionRequired    *bool                       `json:"encryption_required,omitempty"`
	ComplianceFrameworks  []string                    `json:"compliance_frameworks,omitempty"`
	DataClassifications   []entity.DataClassification `json:"data_classifications,omitempty"`

	// Tag filters
	Tags         map[string]string `json:"tags,omitempty"`
	TagsAny      map[string]string `json:"tags_any,omitempty"`
	RequiredTags []string          `json:"required_tags,omitempty"`
	ExcludedTags map[string]string `json:"excluded_tags,omitempty"`

	// Discovery filters
	DiscoveryMethods []string `json:"discovery_methods,omitempty"`
	ScanningEnabled  *bool    `json:"scanning_enabled,omitempty"`

	// Pagination and sorting
	Offset    int       `json:"offset,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	SortBy    string    `json:"sort_by,omitempty"`
	SortOrder SortOrder `json:"sort_order,omitempty"`

	// Advanced filters
	CustomFields    map[string]string `json:"custom_fields,omitempty"`
	ExternalSystems []string          `json:"external_systems,omitempty"`
}

// AssetSearchQuery defines full-text search parameters
type AssetSearchQuery struct {
	Query        string      `json:"query"`
	Fields       []string    `json:"fields,omitempty"`
	Fuzzy        bool        `json:"fuzzy,omitempty"`
	Highlight    bool        `json:"highlight,omitempty"`
	Filter       AssetFilter `json:"filter,omitempty"`
	Aggregations []string    `json:"aggregations,omitempty"`
}

// SortOrder defines sort direction
type SortOrder string

const (
	SortOrderAsc  SortOrder = "asc"
	SortOrderDesc SortOrder = "desc"
)

// AssetCounts represents asset statistics
type AssetCounts struct {
	Total               int64 `json:"total"`
	Active              int64 `json:"active"`
	Inactive            int64 `json:"inactive"`
	Critical            int64 `json:"critical"`
	High                int64 `json:"high"`
	Medium              int64 `json:"medium"`
	Low                 int64 `json:"low"`
	WithVulnerabilities int64 `json:"with_vulnerabilities"`
	ScanningEnabled     int64 `json:"scanning_enabled"`
	StaleAssets         int64 `json:"stale_assets"`
	UnownedAssets       int64 `json:"unowned_assets"`
	UnclassifiedAssets  int64 `json:"unclassified_assets"`
}

// SoftwareCount represents software installation statistics
type SoftwareCount struct {
	Name          string  `json:"name"`
	Vendor        string  `json:"vendor"`
	Version       string  `json:"version"`
	Count         int64   `json:"count"`
	Percentage    float64 `json:"percentage"`
	LatestVersion string  `json:"latest_version,omitempty"`
	CVECount      int     `json:"cve_count,omitempty"`
}

// VulnerabilityCount represents vulnerability statistics
type VulnerabilityCount struct {
	CVE           string    `json:"cve"`
	Title         string    `json:"title"`
	Severity      string    `json:"severity"`
	Score         float64   `json:"score"`
	AffectedCount int64     `json:"affected_count"`
	Percentage    float64   `json:"percentage"`
	PublishedDate time.Time `json:"published_date"`
}

// RepositoryHealth represents repository health status
type RepositoryHealth struct {
	Healthy             bool              `json:"healthy"`
	DatabaseConnected   bool              `json:"database_connected"`
	QueryPerformance    map[string]string `json:"query_performance"`
	IndexHealth         map[string]string `json:"index_health"`
	TableSizes          map[string]int64  `json:"table_sizes"`
	ConnectionPoolStats map[string]int    `json:"connection_pool_stats"`
	LastMaintenanceRun  time.Time         `json:"last_maintenance_run"`
	RecommendedActions  []string          `json:"recommended_actions"`
}

// AssetRepositoryError represents repository-specific errors
type AssetRepositoryError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Operation string                 `json:"operation"`
	AssetID   string                 `json:"asset_id,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (e AssetRepositoryError) Error() string {
	return e.Message
}

// Common repository errors
var (
	ErrAssetNotFound           = &AssetRepositoryError{Code: "ASSET_NOT_FOUND", Message: "Asset not found"}
	ErrAssetAlreadyExists      = &AssetRepositoryError{Code: "ASSET_ALREADY_EXISTS", Message: "Asset already exists"}
	ErrInvalidAssetData        = &AssetRepositoryError{Code: "INVALID_ASSET_DATA", Message: "Invalid asset data"}
	ErrDatabaseConnection      = &AssetRepositoryError{Code: "DATABASE_CONNECTION", Message: "Database connection error"}
	ErrQueryTimeout            = &AssetRepositoryError{Code: "QUERY_TIMEOUT", Message: "Query execution timeout"}
	ErrConcurrentModification  = &AssetRepositoryError{Code: "CONCURRENT_MODIFICATION", Message: "Concurrent modification detected"}
	ErrInsufficientPermissions = &AssetRepositoryError{Code: "INSUFFICIENT_PERMISSIONS", Message: "Insufficient permissions"}
)

// AssetQueryBuilder provides a fluent interface for building complex asset queries
type AssetQueryBuilder struct {
	filter AssetFilter
}

// NewAssetQueryBuilder creates a new query builder
func NewAssetQueryBuilder() *AssetQueryBuilder {
	return &AssetQueryBuilder{
		filter: AssetFilter{},
	}
}

// WithAssetTypes adds asset type filters
func (qb *AssetQueryBuilder) WithAssetTypes(types ...entity.AssetType) *AssetQueryBuilder {
	qb.filter.AssetTypes = append(qb.filter.AssetTypes, types...)
	return qb
}

// WithCriticalities adds criticality filters
func (qb *AssetQueryBuilder) WithCriticalities(criticalities ...entity.CriticalityLevel) *AssetQueryBuilder {
	qb.filter.Criticalities = append(qb.filter.Criticalities, criticalities...)
	return qb
}

// WithStatuses adds status filters
func (qb *AssetQueryBuilder) WithStatuses(statuses ...entity.AssetStatus) *AssetQueryBuilder {
	qb.filter.Statuses = append(qb.filter.Statuses, statuses...)
	return qb
}

// WithNetworkSegments adds network segment filters
func (qb *AssetQueryBuilder) WithNetworkSegments(segments ...string) *AssetQueryBuilder {
	qb.filter.NetworkSegments = append(qb.filter.NetworkSegments, segments...)
	return qb
}

// WithBusinessFunctions adds business function filters
func (qb *AssetQueryBuilder) WithBusinessFunctions(functions ...string) *AssetQueryBuilder {
	qb.filter.BusinessFunctions = append(qb.filter.BusinessFunctions, functions...)
	return qb
}

// WithOwners adds owner filters
func (qb *AssetQueryBuilder) WithOwners(owners ...string) *AssetQueryBuilder {
	qb.filter.Owners = append(qb.filter.Owners, owners...)
	return qb
}

// WithTags adds tag filters (all must match)
func (qb *AssetQueryBuilder) WithTags(tags map[string]string) *AssetQueryBuilder {
	if qb.filter.Tags == nil {
		qb.filter.Tags = make(map[string]string)
	}
	for k, v := range tags {
		qb.filter.Tags[k] = v
	}
	return qb
}

// WithAnyTags adds tag filters (any can match)
func (qb *AssetQueryBuilder) WithAnyTags(tags map[string]string) *AssetQueryBuilder {
	if qb.filter.TagsAny == nil {
		qb.filter.TagsAny = make(map[string]string)
	}
	for k, v := range tags {
		qb.filter.TagsAny[k] = v
	}
	return qb
}

// WithVulnerabilities filters assets with/without vulnerabilities
func (qb *AssetQueryBuilder) WithVulnerabilities(hasVulns bool) *AssetQueryBuilder {
	qb.filter.HasVulnerabilities = &hasVulns
	return qb
}

// WithMinVulnerabilityCount filters by minimum vulnerability count
func (qb *AssetQueryBuilder) WithMinVulnerabilityCount(count int) *AssetQueryBuilder {
	qb.filter.MinVulnerabilityCount = &count
	return qb
}

// WithTimeRange adds time-based filters
func (qb *AssetQueryBuilder) WithTimeRange(field string, after, before *time.Time) *AssetQueryBuilder {
	switch field {
	case "created":
		qb.filter.CreatedAfter = after
		qb.filter.CreatedBefore = before
	case "updated":
		qb.filter.UpdatedAfter = after
		qb.filter.UpdatedBefore = before
	case "last_seen":
		qb.filter.LastSeenAfter = after
		qb.filter.LastSeenBefore = before
	}
	return qb
}

// WithPagination adds pagination parameters
func (qb *AssetQueryBuilder) WithPagination(offset, limit int) *AssetQueryBuilder {
	qb.filter.Offset = offset
	qb.filter.Limit = limit
	return qb
}

// WithSorting adds sorting parameters
func (qb *AssetQueryBuilder) WithSorting(sortBy string, order SortOrder) *AssetQueryBuilder {
	qb.filter.SortBy = sortBy
	qb.filter.SortOrder = order
	return qb
}

// Build returns the constructed filter
func (qb *AssetQueryBuilder) Build() AssetFilter {
	return qb.filter
}

// AssetRepositoryConfiguration holds repository configuration
type AssetRepositoryConfiguration struct {
	MaxConnections      int           `json:"max_connections"`
	MaxIdleConnections  int           `json:"max_idle_connections"`
	ConnectionLifetime  time.Duration `json:"connection_lifetime"`
	QueryTimeout        time.Duration `json:"query_timeout"`
	EnableQueryLogging  bool          `json:"enable_query_logging"`
	EnableMetrics       bool          `json:"enable_metrics"`
	MaintenanceSchedule string        `json:"maintenance_schedule"`
	BackupSchedule      string        `json:"backup_schedule"`
	IndexOptimization   bool          `json:"index_optimization"`
	CacheSettings       struct {
		Enabled bool          `json:"enabled"`
		TTL     time.Duration `json:"ttl"`
		Size    int           `json:"size"`
	} `json:"cache_settings"`
}
