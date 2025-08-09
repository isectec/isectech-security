package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"go.uber.org/zap"

	"asset-discovery/domain/entity"
	"asset-discovery/domain/repository"
)

// PostgreSQLAssetRepository implements the AssetRepository interface using PostgreSQL
type PostgreSQLAssetRepository struct {
	db     *sqlx.DB
	logger *zap.Logger
}

// NewPostgreSQLAssetRepository creates a new PostgreSQL asset repository
func NewPostgreSQLAssetRepository(db *sqlx.DB, logger *zap.Logger) *PostgreSQLAssetRepository {
	return &PostgreSQLAssetRepository{
		db:     db,
		logger: logger,
	}
}

// Create creates a new asset in the database
func (r *PostgreSQLAssetRepository) Create(ctx context.Context, asset *entity.Asset) error {
	query := `
		INSERT INTO assets (
			id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			owner, department, business_unit, environment, criticality, tags, labels,
			network_info, system_info, security_info,
			discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
		)`

	networkInfoJSON, _ := json.Marshal(asset.NetworkInfo)
	systemInfoJSON, _ := json.Marshal(asset.SystemInfo)
	securityInfoJSON, _ := json.Marshal(asset.SecurityInfo)
	tagsJSON, _ := json.Marshal(asset.Tags)
	labelsJSON, _ := json.Marshal(asset.Labels)

	_, err := r.db.ExecContext(ctx, query,
		asset.ID, asset.TenantID, asset.Name, asset.DisplayName, asset.Description,
		asset.AssetType, asset.Status, asset.RiskLevel,
		asset.Owner, asset.Department, asset.BusinessUnit, asset.Environment, asset.Criticality,
		tagsJSON, labelsJSON, networkInfoJSON, systemInfoJSON, securityInfoJSON,
		asset.DiscoveryMethod, asset.DiscoverySource, asset.FirstDiscovered, asset.LastSeen, asset.LastUpdated,
		asset.ScanFrequency, asset.NextScanTime, asset.Fingerprint, asset.Checksum,
		asset.CreatedAt, asset.UpdatedAt, asset.Version,
	)

	if err != nil {
		r.logger.Error("Failed to create asset", zap.String("asset_id", asset.ID.String()), zap.Error(err))
		return fmt.Errorf("failed to create asset: %w", err)
	}

	r.logger.Debug("Asset created successfully", zap.String("asset_id", asset.ID.String()))
	return nil
}

// GetByID retrieves an asset by its ID
func (r *PostgreSQLAssetRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets WHERE id = $1 AND deleted_at IS NULL`

	return r.scanAsset(ctx, query, id)
}

// GetByTenantAndID retrieves an asset by tenant ID and asset ID
func (r *PostgreSQLAssetRepository) GetByTenantAndID(ctx context.Context, tenantID, assetID uuid.UUID) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	return r.scanAsset(ctx, query, assetID, tenantID)
}

// Update updates an existing asset
func (r *PostgreSQLAssetRepository) Update(ctx context.Context, asset *entity.Asset) error {
	query := `
		UPDATE assets SET
			name = $2, display_name = $3, description = $4, asset_type = $5, status = $6, risk_level = $7,
			owner = $8, department = $9, business_unit = $10, environment = $11, criticality = $12,
			tags = $13, labels = $14, network_info = $15, system_info = $16, security_info = $17,
			discovery_method = $18, discovery_source = $19, last_seen = $20, last_updated = $21,
			scan_frequency = $22, next_scan_time = $23, fingerprint = $24, checksum = $25,
			updated_at = $26, version = $27
		WHERE id = $1 AND deleted_at IS NULL`

	networkInfoJSON, _ := json.Marshal(asset.NetworkInfo)
	systemInfoJSON, _ := json.Marshal(asset.SystemInfo)
	securityInfoJSON, _ := json.Marshal(asset.SecurityInfo)
	tagsJSON, _ := json.Marshal(asset.Tags)
	labelsJSON, _ := json.Marshal(asset.Labels)

	asset.UpdatedAt = time.Now()
	asset.Version++

	result, err := r.db.ExecContext(ctx, query,
		asset.ID, asset.Name, asset.DisplayName, asset.Description, asset.AssetType, asset.Status, asset.RiskLevel,
		asset.Owner, asset.Department, asset.BusinessUnit, asset.Environment, asset.Criticality,
		tagsJSON, labelsJSON, networkInfoJSON, systemInfoJSON, securityInfoJSON,
		asset.DiscoveryMethod, asset.DiscoverySource, asset.LastSeen, asset.LastUpdated,
		asset.ScanFrequency, asset.NextScanTime, asset.Fingerprint, asset.Checksum,
		asset.UpdatedAt, asset.Version,
	)

	if err != nil {
		r.logger.Error("Failed to update asset", zap.String("asset_id", asset.ID.String()), zap.Error(err))
		return fmt.Errorf("failed to update asset: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("asset not found: %s", asset.ID.String())
	}

	r.logger.Debug("Asset updated successfully", zap.String("asset_id", asset.ID.String()))
	return nil
}

// Delete permanently deletes an asset
func (r *PostgreSQLAssetRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM assets WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to delete asset", zap.String("asset_id", id.String()), zap.Error(err))
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("asset not found: %s", id.String())
	}

	r.logger.Debug("Asset deleted successfully", zap.String("asset_id", id.String()))
	return nil
}

// SoftDelete marks an asset as deleted without removing it from the database
func (r *PostgreSQLAssetRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE assets SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.Error("Failed to soft delete asset", zap.String("asset_id", id.String()), zap.Error(err))
		return fmt.Errorf("failed to soft delete asset: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("asset not found: %s", id.String())
	}

	r.logger.Debug("Asset soft deleted successfully", zap.String("asset_id", id.String()))
	return nil
}

// CreateBatch creates multiple assets in a single transaction
func (r *PostgreSQLAssetRepository) CreateBatch(ctx context.Context, assets []*entity.Asset) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PreparexContext(ctx, `
		INSERT INTO assets (
			id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			owner, department, business_unit, environment, criticality, tags, labels,
			network_info, system_info, security_info,
			discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, asset := range assets {
		networkInfoJSON, _ := json.Marshal(asset.NetworkInfo)
		systemInfoJSON, _ := json.Marshal(asset.SystemInfo)
		securityInfoJSON, _ := json.Marshal(asset.SecurityInfo)
		tagsJSON, _ := json.Marshal(asset.Tags)
		labelsJSON, _ := json.Marshal(asset.Labels)

		_, err = stmt.ExecContext(ctx,
			asset.ID, asset.TenantID, asset.Name, asset.DisplayName, asset.Description,
			asset.AssetType, asset.Status, asset.RiskLevel,
			asset.Owner, asset.Department, asset.BusinessUnit, asset.Environment, asset.Criticality,
			tagsJSON, labelsJSON, networkInfoJSON, systemInfoJSON, securityInfoJSON,
			asset.DiscoveryMethod, asset.DiscoverySource, asset.FirstDiscovered, asset.LastSeen, asset.LastUpdated,
			asset.ScanFrequency, asset.NextScanTime, asset.Fingerprint, asset.Checksum,
			asset.CreatedAt, asset.UpdatedAt, asset.Version,
		)
		if err != nil {
			r.logger.Error("Failed to insert asset in batch", zap.String("asset_id", asset.ID.String()), zap.Error(err))
			return fmt.Errorf("failed to insert asset %s: %w", asset.ID.String(), err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Batch created assets successfully", zap.Int("count", len(assets)))
	return nil
}

// UpdateBatch updates multiple assets in a single transaction
func (r *PostgreSQLAssetRepository) UpdateBatch(ctx context.Context, assets []*entity.Asset) error {
	tx, err := r.db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, asset := range assets {
		networkInfoJSON, _ := json.Marshal(asset.NetworkInfo)
		systemInfoJSON, _ := json.Marshal(asset.SystemInfo)
		securityInfoJSON, _ := json.Marshal(asset.SecurityInfo)
		tagsJSON, _ := json.Marshal(asset.Tags)
		labelsJSON, _ := json.Marshal(asset.Labels)

		asset.UpdatedAt = time.Now()
		asset.Version++

		_, err = tx.ExecContext(ctx, `
			UPDATE assets SET
				name = $2, display_name = $3, description = $4, asset_type = $5, status = $6, risk_level = $7,
				owner = $8, department = $9, business_unit = $10, environment = $11, criticality = $12,
				tags = $13, labels = $14, network_info = $15, system_info = $16, security_info = $17,
				discovery_method = $18, discovery_source = $19, last_seen = $20, last_updated = $21,
				scan_frequency = $22, next_scan_time = $23, fingerprint = $24, checksum = $25,
				updated_at = $26, version = $27
			WHERE id = $1 AND deleted_at IS NULL`,
			asset.ID, asset.Name, asset.DisplayName, asset.Description, asset.AssetType, asset.Status, asset.RiskLevel,
			asset.Owner, asset.Department, asset.BusinessUnit, asset.Environment, asset.Criticality,
			tagsJSON, labelsJSON, networkInfoJSON, systemInfoJSON, securityInfoJSON,
			asset.DiscoveryMethod, asset.DiscoverySource, asset.LastSeen, asset.LastUpdated,
			asset.ScanFrequency, asset.NextScanTime, asset.Fingerprint, asset.Checksum,
			asset.UpdatedAt, asset.Version,
		)
		if err != nil {
			r.logger.Error("Failed to update asset in batch", zap.String("asset_id", asset.ID.String()), zap.Error(err))
			return fmt.Errorf("failed to update asset %s: %w", asset.ID.String(), err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	r.logger.Info("Batch updated assets successfully", zap.Int("count", len(assets)))
	return nil
}

// DeleteBatch deletes multiple assets
func (r *PostgreSQLAssetRepository) DeleteBatch(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	query := `DELETE FROM assets WHERE id = ANY($1)`
	
	_, err := r.db.ExecContext(ctx, query, pq.Array(ids))
	if err != nil {
		r.logger.Error("Failed to delete assets in batch", zap.Int("count", len(ids)), zap.Error(err))
		return fmt.Errorf("failed to delete assets: %w", err)
	}

	r.logger.Info("Batch deleted assets successfully", zap.Int("count", len(ids)))
	return nil
}

// List retrieves assets with filtering, sorting, and pagination
func (r *PostgreSQLAssetRepository) List(ctx context.Context, filter repository.AssetFilter, sort []repository.AssetSort, page repository.PageRequest) (*repository.AssetListResponse, error) {
	// Build the query with filters
	whereClause, args := r.buildWhereClause(filter)
	orderClause := r.buildOrderClause(sort)
	
	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL %s", whereClause)
	var totalItems int64
	err := r.db.GetContext(ctx, &totalItems, countQuery, args...)
	if err != nil {
		r.logger.Error("Failed to get asset count", zap.Error(err))
		return nil, fmt.Errorf("failed to get asset count: %w", err)
	}

	// Calculate pagination
	offset := (page.Page - 1) * page.PageSize
	totalPages := int((totalItems + int64(page.PageSize) - 1) / int64(page.PageSize))

	// Get assets with pagination
	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets WHERE deleted_at IS NULL %s %s LIMIT $%d OFFSET $%d`,
		whereClause, orderClause, len(args)+1, len(args)+2)

	args = append(args, page.PageSize, offset)

	rows, err := r.db.QueryxContext(ctx, query, args...)
	if err != nil {
		r.logger.Error("Failed to list assets", zap.Error(err))
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	defer rows.Close()

	assets := make([]*entity.Asset, 0)
	for rows.Next() {
		asset, err := r.scanAssetFromRow(rows)
		if err != nil {
			r.logger.Error("Failed to scan asset", zap.Error(err))
			continue
		}
		assets = append(assets, asset)
	}

	return &repository.AssetListResponse{
		Assets: assets,
		Pagination: repository.PageResponse{
			Page:       page.Page,
			PageSize:   page.PageSize,
			TotalPages: totalPages,
			TotalItems: totalItems,
			HasNext:    page.Page < totalPages,
			HasPrev:    page.Page > 1,
		},
	}, nil
}

// ListByTenant retrieves assets for a specific tenant
func (r *PostgreSQLAssetRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter, sort []repository.AssetSort, page repository.PageRequest) (*repository.AssetListResponse, error) {
	// Add tenant filter
	filter.TenantID = &tenantID
	return r.List(ctx, filter, sort, page)
}

// Count returns the total number of assets matching the filter
func (r *PostgreSQLAssetRepository) Count(ctx context.Context, filter repository.AssetFilter) (int64, error) {
	whereClause, args := r.buildWhereClause(filter)
	query := fmt.Sprintf("SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL %s", whereClause)
	
	var count int64
	err := r.db.GetContext(ctx, &count, query, args...)
	if err != nil {
		r.logger.Error("Failed to count assets", zap.Error(err))
		return 0, fmt.Errorf("failed to count assets: %w", err)
	}

	return count, nil
}

// CountByTenant returns the total number of assets for a tenant
func (r *PostgreSQLAssetRepository) CountByTenant(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) (int64, error) {
	filter.TenantID = &tenantID
	return r.Count(ctx, filter)
}

// FindByIP finds an asset by IP address
func (r *PostgreSQLAssetRepository) FindByIP(ctx context.Context, tenantID uuid.UUID, ipAddress string) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND network_info->>'ip_address' = $2`

	return r.scanAsset(ctx, query, tenantID, ipAddress)
}

// FindByMAC finds an asset by MAC address
func (r *PostgreSQLAssetRepository) FindByMAC(ctx context.Context, tenantID uuid.UUID, macAddress string) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND network_info->>'mac_address' = $2`

	return r.scanAsset(ctx, query, tenantID, macAddress)
}

// FindByHostname finds an asset by hostname
func (r *PostgreSQLAssetRepository) FindByHostname(ctx context.Context, tenantID uuid.UUID, hostname string) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND (network_info->>'hostname' = $2 OR network_info->>'fqdn' = $2)`

	return r.scanAsset(ctx, query, tenantID, hostname)
}

// FindByFingerprint finds an asset by fingerprint
func (r *PostgreSQLAssetRepository) FindByFingerprint(ctx context.Context, tenantID uuid.UUID, fingerprint string) (*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND fingerprint = $2 AND deleted_at IS NULL`

	return r.scanAsset(ctx, query, tenantID, fingerprint)
}

// FindDuplicates finds potential duplicate assets
func (r *PostgreSQLAssetRepository) FindDuplicates(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error) {
	query := `
		SELECT DISTINCT a1.id, a1.tenant_id, a1.name, a1.display_name, a1.description, a1.asset_type, a1.status, a1.risk_level,
			   a1.owner, a1.department, a1.business_unit, a1.environment, a1.criticality, a1.tags, a1.labels,
			   a1.network_info, a1.system_info, a1.security_info,
			   a1.discovery_method, a1.discovery_source, a1.first_discovered, a1.last_seen, a1.last_updated,
			   a1.scan_frequency, a1.next_scan_time, a1.fingerprint, a1.checksum, a1.created_at, a1.updated_at, a1.version
		FROM assets a1
		INNER JOIN assets a2 ON a1.fingerprint = a2.fingerprint 
			AND a1.id != a2.id 
			AND a1.tenant_id = $1 
			AND a2.tenant_id = $1
		WHERE a1.deleted_at IS NULL AND a2.deleted_at IS NULL
		ORDER BY a1.created_at`

	return r.scanAssets(ctx, query, tenantID)
}

// FindStaleAssets finds assets that haven't been seen recently
func (r *PostgreSQLAssetRepository) FindStaleAssets(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) ([]*entity.Asset, error) {
	staleTime := time.Now().Add(-staleDuration)
	
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND last_seen < $2 AND deleted_at IS NULL
		ORDER BY last_seen ASC`

	return r.scanAssets(ctx, query, tenantID, staleTime)
}

// FindByIPRange finds assets within an IP range
func (r *PostgreSQLAssetRepository) FindByIPRange(ctx context.Context, tenantID uuid.UUID, cidr string) ([]*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND (network_info->>'ip_address')::inet << $2::cidr`

	return r.scanAssets(ctx, query, tenantID, cidr)
}

// FindByNetworkZone finds assets in a specific network zone
func (r *PostgreSQLAssetRepository) FindByNetworkZone(ctx context.Context, tenantID uuid.UUID, zone string) ([]*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND network_info->>'network_zone' = $2`

	return r.scanAssets(ctx, query, tenantID, zone)
}

// FindByOpenPort finds assets with a specific open port
func (r *PostgreSQLAssetRepository) FindByOpenPort(ctx context.Context, tenantID uuid.UUID, port int) ([]*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND network_info->'open_ports' @> $2::jsonb`

	portJSON := fmt.Sprintf(`[{"number": %d}]`, port)

	return r.scanAssets(ctx, query, tenantID, portJSON)
}

// FindWithOpenPorts finds assets with any of the specified open ports
func (r *PostgreSQLAssetRepository) FindWithOpenPorts(ctx context.Context, tenantID uuid.UUID, ports []int) ([]*entity.Asset, error) {
	if len(ports) == 0 {
		return []*entity.Asset{}, nil
	}

	portConditions := make([]string, len(ports))
	args := []interface{}{tenantID}
	
	for i, port := range ports {
		portConditions[i] = fmt.Sprintf("network_info->'open_ports' @> $%d::jsonb", i+2)
		args = append(args, fmt.Sprintf(`[{"number": %d}]`, port))
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND (%s)`, strings.Join(portConditions, " OR "))

	return r.scanAssets(ctx, query, args...)
}

// FindByVulnerabilityScore finds assets with vulnerability scores in the specified range
func (r *PostgreSQLAssetRepository) FindByVulnerabilityScore(ctx context.Context, tenantID uuid.UUID, minScore, maxScore float64) ([]*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND (
				COALESCE((security_info->'vuln_count'->>'critical')::int, 0) * 10 +
				COALESCE((security_info->'vuln_count'->>'high')::int, 0) * 7 +
				COALESCE((security_info->'vuln_count'->>'medium')::int, 0) * 4 +
				COALESCE((security_info->'vuln_count'->>'low')::int, 0) * 1
			) BETWEEN $2 AND $3`

	return r.scanAssets(ctx, query, tenantID, minScore, maxScore)
}

// FindByRiskLevel finds assets with specified risk levels
func (r *PostgreSQLAssetRepository) FindByRiskLevel(ctx context.Context, tenantID uuid.UUID, riskLevels []entity.AssetRiskLevel) ([]*entity.Asset, error) {
	if len(riskLevels) == 0 {
		return []*entity.Asset{}, nil
	}

	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND risk_level = ANY($2)`

	riskLevelStrings := make([]string, len(riskLevels))
	for i, level := range riskLevels {
		riskLevelStrings[i] = string(level)
	}

	return r.scanAssets(ctx, query, tenantID, pq.Array(riskLevelStrings))
}

// FindWithVulnerabilities finds assets that have vulnerabilities
func (r *PostgreSQLAssetRepository) FindWithVulnerabilities(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error) {
	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND COALESCE((security_info->'vuln_count'->>'total')::int, 0) > 0`

	return r.scanAssets(ctx, query, tenantID)
}

// FindNonCompliant finds assets that are not compliant with a specific framework
func (r *PostgreSQLAssetRepository) FindNonCompliant(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error) {
	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND security_info->'compliance_status'->>'%s' != 'compliant'`, framework)

	return r.scanAssets(ctx, query, tenantID)
}

// Helper methods for building queries

func (r *PostgreSQLAssetRepository) buildWhereClause(filter repository.AssetFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, *filter.TenantID)
		argIndex++
	}

	if len(filter.AssetTypes) > 0 {
		assetTypeStrings := make([]string, len(filter.AssetTypes))
		for i, t := range filter.AssetTypes {
			assetTypeStrings[i] = string(t)
		}
		conditions = append(conditions, fmt.Sprintf("asset_type = ANY($%d)", argIndex))
		args = append(args, pq.Array(assetTypeStrings))
		argIndex++
	}

	if len(filter.Statuses) > 0 {
		statusStrings := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			statusStrings[i] = string(s)
		}
		conditions = append(conditions, fmt.Sprintf("status = ANY($%d)", argIndex))
		args = append(args, pq.Array(statusStrings))
		argIndex++
	}

	if len(filter.RiskLevels) > 0 {
		riskLevelStrings := make([]string, len(filter.RiskLevels))
		for i, r := range filter.RiskLevels {
			riskLevelStrings[i] = string(r)
		}
		conditions = append(conditions, fmt.Sprintf("risk_level = ANY($%d)", argIndex))
		args = append(args, pq.Array(riskLevelStrings))
		argIndex++
	}

	if len(filter.Environments) > 0 {
		conditions = append(conditions, fmt.Sprintf("environment = ANY($%d)", argIndex))
		args = append(args, pq.Array(filter.Environments))
		argIndex++
	}

	if filter.IPRange != nil {
		conditions = append(conditions, fmt.Sprintf("(network_info->>'ip_address')::inet << $%d::cidr", argIndex))
		args = append(args, *filter.IPRange)
		argIndex++
	}

	if filter.Hostname != nil {
		conditions = append(conditions, fmt.Sprintf("(network_info->>'hostname' = $%d OR network_info->>'fqdn' = $%d)", argIndex, argIndex))
		args = append(args, *filter.Hostname)
		argIndex++
	}

	if filter.Owner != nil {
		conditions = append(conditions, fmt.Sprintf("owner = $%d", argIndex))
		args = append(args, *filter.Owner)
		argIndex++
	}

	if filter.Department != nil {
		conditions = append(conditions, fmt.Sprintf("department = $%d", argIndex))
		args = append(args, *filter.Department)
		argIndex++
	}

	if filter.LastSeenAfter != nil {
		conditions = append(conditions, fmt.Sprintf("last_seen > $%d", argIndex))
		args = append(args, *filter.LastSeenAfter)
		argIndex++
	}

	if filter.LastSeenBefore != nil {
		conditions = append(conditions, fmt.Sprintf("last_seen < $%d", argIndex))
		args = append(args, *filter.LastSeenBefore)
		argIndex++
	}

	if filter.Search != nil {
		searchPattern := "%" + *filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf(`(
			name ILIKE $%d OR 
			display_name ILIKE $%d OR 
			description ILIKE $%d OR
			network_info->>'hostname' ILIKE $%d OR
			network_info->>'ip_address' ILIKE $%d
		)`, argIndex, argIndex, argIndex, argIndex, argIndex))
		args = append(args, searchPattern)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "AND " + strings.Join(conditions, " AND ")
	}

	return whereClause, args
}

func (r *PostgreSQLAssetRepository) buildOrderClause(sort []repository.AssetSort) string {
	if len(sort) == 0 {
		return "ORDER BY created_at DESC"
	}

	var orderParts []string
	for _, s := range sort {
		direction := "ASC"
		if strings.ToUpper(s.Direction) == "DESC" {
			direction = "DESC"
		}
		orderParts = append(orderParts, fmt.Sprintf("%s %s", s.Field, direction))
	}

	return "ORDER BY " + strings.Join(orderParts, ", ")
}

// Helper methods for scanning results

func (r *PostgreSQLAssetRepository) scanAsset(ctx context.Context, query string, args ...interface{}) (*entity.Asset, error) {
	row := r.db.QueryRowxContext(ctx, query, args...)
	return r.scanAssetFromRow(row)
}

func (r *PostgreSQLAssetRepository) scanAssets(ctx context.Context, query string, args ...interface{}) ([]*entity.Asset, error) {
	rows, err := r.db.QueryxContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assets []*entity.Asset
	for rows.Next() {
		asset, err := r.scanAssetFromRow(rows)
		if err != nil {
			r.logger.Error("Failed to scan asset", zap.Error(err))
			continue
		}
		assets = append(assets, asset)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) scanAssetFromRow(row interface{}) (*entity.Asset, error) {
	var asset entity.Asset
	var networkInfoJSON, systemInfoJSON, securityInfoJSON, tagsJSON, labelsJSON []byte

	// Type assertion to handle both *sqlx.Row and *sqlx.Rows
	var err error
	switch r := row.(type) {
	case *sqlx.Row:
		err = r.Scan(
			&asset.ID, &asset.TenantID, &asset.Name, &asset.DisplayName, &asset.Description,
			&asset.AssetType, &asset.Status, &asset.RiskLevel,
			&asset.Owner, &asset.Department, &asset.BusinessUnit, &asset.Environment, &asset.Criticality,
			&tagsJSON, &labelsJSON, &networkInfoJSON, &systemInfoJSON, &securityInfoJSON,
			&asset.DiscoveryMethod, &asset.DiscoverySource, &asset.FirstDiscovered, &asset.LastSeen, &asset.LastUpdated,
			&asset.ScanFrequency, &asset.NextScanTime, &asset.Fingerprint, &asset.Checksum,
			&asset.CreatedAt, &asset.UpdatedAt, &asset.Version,
		)
	case *sqlx.Rows:
		err = r.Scan(
			&asset.ID, &asset.TenantID, &asset.Name, &asset.DisplayName, &asset.Description,
			&asset.AssetType, &asset.Status, &asset.RiskLevel,
			&asset.Owner, &asset.Department, &asset.BusinessUnit, &asset.Environment, &asset.Criticality,
			&tagsJSON, &labelsJSON, &networkInfoJSON, &systemInfoJSON, &securityInfoJSON,
			&asset.DiscoveryMethod, &asset.DiscoverySource, &asset.FirstDiscovered, &asset.LastSeen, &asset.LastUpdated,
			&asset.ScanFrequency, &asset.NextScanTime, &asset.Fingerprint, &asset.Checksum,
			&asset.CreatedAt, &asset.UpdatedAt, &asset.Version,
		)
	default:
		return nil, fmt.Errorf("unsupported row type")
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("asset not found")
		}
		return nil, fmt.Errorf("failed to scan asset: %w", err)
	}

	// Unmarshal JSON fields
	if len(networkInfoJSON) > 0 {
		var networkInfo entity.NetworkInfo
		if err := json.Unmarshal(networkInfoJSON, &networkInfo); err == nil {
			asset.NetworkInfo = &networkInfo
		}
	}

	if len(systemInfoJSON) > 0 {
		var systemInfo entity.SystemInfo
		if err := json.Unmarshal(systemInfoJSON, &systemInfo); err == nil {
			asset.SystemInfo = &systemInfo
		}
	}

	if len(securityInfoJSON) > 0 {
		var securityInfo entity.SecurityInfo
		if err := json.Unmarshal(securityInfoJSON, &securityInfo); err == nil {
			asset.SecurityInfo = &securityInfo
		}
	}

	if len(tagsJSON) > 0 {
		json.Unmarshal(tagsJSON, &asset.Tags)
	}

	if len(labelsJSON) > 0 {
		json.Unmarshal(labelsJSON, &asset.Labels)
	}

	return &asset, nil
}

// Remaining methods implementation would continue here...
// For brevity, I'm showing the core CRUD and query methods
// The complete implementation would include all remaining interface methods

// GetAggregation gets aggregated statistics
func (r *PostgreSQLAssetRepository) GetAggregation(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) (*repository.AssetAggregation, error) {
	// Implementation for aggregation queries
	return &repository.AssetAggregation{}, nil
}

// GetAssetTrends gets trend data
func (r *PostgreSQLAssetRepository) GetAssetTrends(ctx context.Context, tenantID uuid.UUID, timeRange time.Duration) (map[string]interface{}, error) {
	// Implementation for trend analysis
	return make(map[string]interface{}), nil
}

// GetNetworkTopology gets network topology data
func (r *PostgreSQLAssetRepository) GetNetworkTopology(ctx context.Context, tenantID uuid.UUID) (map[string]interface{}, error) {
	// Implementation for network topology
	return make(map[string]interface{}), nil
}

// BulkUpdate performs bulk updates
func (r *PostgreSQLAssetRepository) BulkUpdate(ctx context.Context, request repository.BulkUpdateRequest) (*repository.BulkUpdateResponse, error) {
	// Implementation for bulk updates
	return &repository.BulkUpdateResponse{}, nil
}

// MarkAsStale marks assets as stale
func (r *PostgreSQLAssetRepository) MarkAsStale(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int64, error) {
	staleTime := time.Now().Add(-staleDuration)
	
	query := `UPDATE assets SET status = 'inactive' WHERE tenant_id = $1 AND last_seen < $2 AND status = 'active' AND deleted_at IS NULL`
	
	result, err := r.db.ExecContext(ctx, query, tenantID, staleTime)
	if err != nil {
		return 0, fmt.Errorf("failed to mark assets as stale: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// CleanupStaleAssets removes very old stale assets
func (r *PostgreSQLAssetRepository) CleanupStaleAssets(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int64, error) {
	staleTime := time.Now().Add(-staleDuration)
	
	query := `UPDATE assets SET deleted_at = NOW() WHERE tenant_id = $1 AND last_seen < $2 AND deleted_at IS NULL`
	
	result, err := r.db.ExecContext(ctx, query, tenantID, staleTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale assets: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	return rowsAffected, nil
}

// UpdateLastSeen updates the last seen timestamp for multiple assets
func (r *PostgreSQLAssetRepository) UpdateLastSeen(ctx context.Context, assetIDs []uuid.UUID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	query := `UPDATE assets SET last_seen = NOW(), last_updated = NOW() WHERE id = ANY($1) AND deleted_at IS NULL`
	
	_, err := r.db.ExecContext(ctx, query, pq.Array(assetIDs))
	return err
}

// RecalculateFingerprints recalculates fingerprints for all assets
func (r *PostgreSQLAssetRepository) RecalculateFingerprints(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	// This would need to fetch assets and recalculate fingerprints
	// For now, return 0 as this is a complex operation
	return 0, nil
}

// Search performs full-text search
func (r *PostgreSQLAssetRepository) Search(ctx context.Context, tenantID uuid.UUID, query string, filters repository.AssetFilter, page repository.PageRequest) (*repository.AssetListResponse, error) {
	filters.TenantID = &tenantID
	filters.Search = &query
	return r.List(ctx, filters, []repository.AssetSort{}, page)
}

// SearchByTags searches assets by tags
func (r *PostgreSQLAssetRepository) SearchByTags(ctx context.Context, tenantID uuid.UUID, tags []string) ([]*entity.Asset, error) {
	if len(tags) == 0 {
		return []*entity.Asset{}, nil
	}

	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND tags @> $2::jsonb`

	tagsJSON, _ := json.Marshal(tags)
	return r.scanAssets(ctx, query, tenantID, tagsJSON)
}

// SearchByLabels searches assets by labels
func (r *PostgreSQLAssetRepository) SearchByLabels(ctx context.Context, tenantID uuid.UUID, labels map[string]string) ([]*entity.Asset, error) {
	if len(labels) == 0 {
		return []*entity.Asset{}, nil
	}

	query := `
		SELECT id, tenant_id, name, display_name, description, asset_type, status, risk_level,
			   owner, department, business_unit, environment, criticality, tags, labels,
			   network_info, system_info, security_info,
			   discovery_method, discovery_source, first_discovered, last_seen, last_updated,
			   scan_frequency, next_scan_time, fingerprint, checksum, created_at, updated_at, version
		FROM assets 
		WHERE tenant_id = $1 AND deleted_at IS NULL 
			AND labels @> $2::jsonb`

	labelsJSON, _ := json.Marshal(labels)
	return r.scanAssets(ctx, query, tenantID, labelsJSON)
}

// Index management methods
func (r *PostgreSQLAssetRepository) CreateIndex(ctx context.Context, indexName string, fields []string) error {
	query := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON assets (%s)", indexName, strings.Join(fields, ", "))
	_, err := r.db.ExecContext(ctx, query)
	return err
}

func (r *PostgreSQLAssetRepository) DropIndex(ctx context.Context, indexName string) error {
	query := fmt.Sprintf("DROP INDEX IF EXISTS %s", indexName)
	_, err := r.db.ExecContext(ctx, query)
	return err
}

func (r *PostgreSQLAssetRepository) ListIndexes(ctx context.Context) ([]string, error) {
	query := `
		SELECT indexname 
		FROM pg_indexes 
		WHERE tablename = 'assets' AND schemaname = 'public'`
	
	var indexes []string
	err := r.db.SelectContext(ctx, &indexes, query)
	return indexes, err
}

func (r *PostgreSQLAssetRepository) OptimizeIndexes(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "REINDEX TABLE assets")
	return err
}

// Health and monitoring methods
func (r *PostgreSQLAssetRepository) HealthCheck(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

func (r *PostgreSQLAssetRepository) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	var totalAssets int64
	r.db.GetContext(ctx, &totalAssets, "SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL")
	stats["total_assets"] = totalAssets
	
	var activeAssets int64
	r.db.GetContext(ctx, &activeAssets, "SELECT COUNT(*) FROM assets WHERE status = 'active' AND deleted_at IS NULL")
	stats["active_assets"] = activeAssets
	
	return stats, nil
}

func (r *PostgreSQLAssetRepository) GetConnectionPool() interface{} {
	return r.db.DB
}

func (r *PostgreSQLAssetRepository) Close() error {
	return r.db.Close()
}