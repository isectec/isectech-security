package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"asset-discovery/domain/entity"
)

// AssetFilter represents filtering options for asset queries
type AssetFilter struct {
	TenantID     *uuid.UUID             `json:"tenant_id,omitempty"`
	AssetTypes   []entity.AssetType     `json:"asset_types,omitempty"`
	Statuses     []entity.AssetStatus   `json:"statuses,omitempty"`
	RiskLevels   []entity.AssetRiskLevel `json:"risk_levels,omitempty"`
	Environments []string               `json:"environments,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	IPRange      *string                `json:"ip_range,omitempty"`
	Hostname     *string                `json:"hostname,omitempty"`
	Owner        *string                `json:"owner,omitempty"`
	Department   *string                `json:"department,omitempty"`
	
	// Time-based filtering
	LastSeenAfter  *time.Time `json:"last_seen_after,omitempty"`
	LastSeenBefore *time.Time `json:"last_seen_before,omitempty"`
	DiscoveredAfter *time.Time `json:"discovered_after,omitempty"`
	DiscoveredBefore *time.Time `json:"discovered_before,omitempty"`
	
	// Vulnerability filtering
	HasVulnerabilities *bool   `json:"has_vulnerabilities,omitempty"`
	MinVulnScore      *float64 `json:"min_vuln_score,omitempty"`
	MaxVulnScore      *float64 `json:"max_vuln_score,omitempty"`
	
	// Network filtering
	HasOpenPorts *bool     `json:"has_open_ports,omitempty"`
	OpenPorts    []int     `json:"open_ports,omitempty"`
	NetworkZones []string  `json:"network_zones,omitempty"`
	
	// Text search
	Search *string `json:"search,omitempty"` // Full-text search across asset fields
	
	// Compliance filtering
	ComplianceFramework *string `json:"compliance_framework,omitempty"`
	ComplianceStatus    *string `json:"compliance_status,omitempty"`
}

// AssetSort represents sorting options
type AssetSort struct {
	Field     string `json:"field"`     // Field to sort by
	Direction string `json:"direction"` // "asc" or "desc"
}

// PageRequest represents pagination parameters
type PageRequest struct {
	Page     int `json:"page"`      // Page number (1-based)
	PageSize int `json:"page_size"` // Number of items per page
}

// PageResponse represents paginated response metadata
type PageResponse struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
	TotalItems int64 `json:"total_items"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// AssetListResponse represents a paginated list of assets
type AssetListResponse struct {
	Assets     []*entity.Asset `json:"assets"`
	Pagination PageResponse    `json:"pagination"`
}

// AssetAggregation represents aggregated asset statistics
type AssetAggregation struct {
	TotalAssets      int64                          `json:"total_assets"`
	AssetsByType     map[entity.AssetType]int64     `json:"assets_by_type"`
	AssetsByStatus   map[entity.AssetStatus]int64   `json:"assets_by_status"`
	AssetsByRisk     map[entity.AssetRiskLevel]int64 `json:"assets_by_risk"`
	AssetsByEnvironment map[string]int64            `json:"assets_by_environment"`
	VulnStats        VulnerabilityStats             `json:"vulnerability_stats"`
	ComplianceStats  ComplianceStats                `json:"compliance_stats"`
	NetworkStats     NetworkStats                   `json:"network_stats"`
}

// VulnerabilityStats represents vulnerability statistics
type VulnerabilityStats struct {
	TotalVulns      int64            `json:"total_vulnerabilities"`
	VulnsBySeverity map[string]int64 `json:"vulnerabilities_by_severity"`
	AssetsWithVulns int64            `json:"assets_with_vulnerabilities"`
	AvgVulnScore    float64          `json:"average_vulnerability_score"`
}

// ComplianceStats represents compliance statistics
type ComplianceStats struct {
	FrameworkStats map[string]ComplianceFrameworkStats `json:"framework_stats"`
	OverallScore   float64                             `json:"overall_compliance_score"`
}

// ComplianceFrameworkStats represents statistics for a specific compliance framework
type ComplianceFrameworkStats struct {
	Compliant    int64   `json:"compliant"`
	NonCompliant int64   `json:"non_compliant"`
	Unknown      int64   `json:"unknown"`
	Score        float64 `json:"compliance_score"`
}

// NetworkStats represents network-related statistics
type NetworkStats struct {
	TotalIPs       int64            `json:"total_ips"`
	UniqueNetworks int64            `json:"unique_networks"`
	OpenPortStats  map[int]int64    `json:"open_port_stats"`
	NetworkZones   map[string]int64 `json:"network_zones"`
}

// BulkUpdateRequest represents a bulk update operation
type BulkUpdateRequest struct {
	Filter      AssetFilter            `json:"filter"`
	Updates     map[string]interface{} `json:"updates"`
	DryRun      bool                   `json:"dry_run"`
}

// BulkUpdateResponse represents the result of a bulk update operation
type BulkUpdateResponse struct {
	UpdatedCount int64    `json:"updated_count"`
	Errors       []string `json:"errors,omitempty"`
	DryRun       bool     `json:"dry_run"`
}

// AssetRepository defines the interface for asset persistence operations
type AssetRepository interface {
	// Basic CRUD operations
	Create(ctx context.Context, asset *entity.Asset) error
	GetByID(ctx context.Context, id uuid.UUID) (*entity.Asset, error)
	GetByTenantAndID(ctx context.Context, tenantID, assetID uuid.UUID) (*entity.Asset, error)
	Update(ctx context.Context, asset *entity.Asset) error
	Delete(ctx context.Context, id uuid.UUID) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	
	// Batch operations
	CreateBatch(ctx context.Context, assets []*entity.Asset) error
	UpdateBatch(ctx context.Context, assets []*entity.Asset) error
	DeleteBatch(ctx context.Context, ids []uuid.UUID) error
	
	// Query operations
	List(ctx context.Context, filter AssetFilter, sort []AssetSort, page PageRequest) (*AssetListResponse, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filter AssetFilter, sort []AssetSort, page PageRequest) (*AssetListResponse, error)
	Count(ctx context.Context, filter AssetFilter) (int64, error)
	CountByTenant(ctx context.Context, tenantID uuid.UUID, filter AssetFilter) (int64, error)
	
	// Specialized queries
	FindByIP(ctx context.Context, tenantID uuid.UUID, ipAddress string) (*entity.Asset, error)
	FindByMAC(ctx context.Context, tenantID uuid.UUID, macAddress string) (*entity.Asset, error)
	FindByHostname(ctx context.Context, tenantID uuid.UUID, hostname string) (*entity.Asset, error)
	FindByFingerprint(ctx context.Context, tenantID uuid.UUID, fingerprint string) (*entity.Asset, error)
	FindDuplicates(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error)
	FindStaleAssets(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) ([]*entity.Asset, error)
	
	// Network-based queries
	FindByIPRange(ctx context.Context, tenantID uuid.UUID, cidr string) ([]*entity.Asset, error)
	FindByNetworkZone(ctx context.Context, tenantID uuid.UUID, zone string) ([]*entity.Asset, error)
	FindByOpenPort(ctx context.Context, tenantID uuid.UUID, port int) ([]*entity.Asset, error)
	FindWithOpenPorts(ctx context.Context, tenantID uuid.UUID, ports []int) ([]*entity.Asset, error)
	
	// Security-focused queries
	FindByVulnerabilityScore(ctx context.Context, tenantID uuid.UUID, minScore, maxScore float64) ([]*entity.Asset, error)
	FindByRiskLevel(ctx context.Context, tenantID uuid.UUID, riskLevels []entity.AssetRiskLevel) ([]*entity.Asset, error)
	FindWithVulnerabilities(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error)
	FindNonCompliant(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error)
	
	// Aggregation and analytics
	GetAggregation(ctx context.Context, tenantID uuid.UUID, filter AssetFilter) (*AssetAggregation, error)
	GetAssetTrends(ctx context.Context, tenantID uuid.UUID, timeRange time.Duration) (map[string]interface{}, error)
	GetNetworkTopology(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error)
	
	// Maintenance operations
	BulkUpdate(ctx context.Context, request BulkUpdateRequest) (*BulkUpdateResponse, error)
	MarkAsStale(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int64, error)
	CleanupStaleAssets(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int64, error)
	UpdateLastSeen(ctx context.Context, assetIDs []uuid.UUID) error
	RecalculateFingerprints(ctx context.Context, tenantID uuid.UUID) (int64, error)
	
	// Search operations
	Search(ctx context.Context, tenantID uuid.UUID, query string, filters AssetFilter, page PageRequest) (*AssetListResponse, error)
	SearchByTags(ctx context.Context, tenantID uuid.UUID, tags []string) ([]*entity.Asset, error)
	SearchByLabels(ctx context.Context, tenantID uuid.UUID, labels map[string]string) ([]*entity.Asset, error)
	
	// Index management
	CreateIndex(ctx context.Context, indexName string, fields []string) error
	DropIndex(ctx context.Context, indexName string) error
	ListIndexes(ctx context.Context) ([]string, error)
	OptimizeIndexes(ctx context.Context) error
	
	// Health and monitoring
	HealthCheck(ctx context.Context) error
	GetStats(ctx context.Context) (map[string]interface{}, error)
	GetConnectionPool() interface{}
	Close() error
}

// AssetRepositoryError represents repository-specific errors
type AssetRepositoryError struct {
	Operation string
	Error     error
	AssetID   *uuid.UUID
	Context   map[string]interface{}
}

func (e *AssetRepositoryError) Error() string {
	if e.AssetID != nil {
		return fmt.Sprintf("asset repository error during %s for asset %s: %v", e.Operation, e.AssetID.String(), e.Error)
	}
	return fmt.Sprintf("asset repository error during %s: %v", e.Operation, e.Error)
}

// Common error types
var (
	ErrAssetNotFound      = &AssetRepositoryError{Operation: "get", Error: errors.New("asset not found")}
	ErrAssetAlreadyExists = &AssetRepositoryError{Operation: "create", Error: errors.New("asset already exists")}
	ErrInvalidFilter      = &AssetRepositoryError{Operation: "filter", Error: errors.New("invalid filter criteria")}
	ErrInvalidSort        = &AssetRepositoryError{Operation: "sort", Error: errors.New("invalid sort criteria")}
	ErrInvalidPagination  = &AssetRepositoryError{Operation: "paginate", Error: errors.New("invalid pagination parameters")}
	ErrTenantMismatch     = &AssetRepositoryError{Operation: "access", Error: errors.New("tenant mismatch")}
)

package repository

import (
	"errors"
	"fmt"
)