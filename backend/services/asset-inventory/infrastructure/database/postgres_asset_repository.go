// iSECTECH Asset Inventory - PostgreSQL Asset Repository Implementation
// Production-grade PostgreSQL asset data persistence with optimized queries
// Copyright (c) 2024 iSECTECH. All rights reserved.

package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
	"github.com/isectech/backend/services/asset-inventory/domain/repository"
)

// PostgreSQLAssetRepository implements AssetRepository using PostgreSQL
type PostgreSQLAssetRepository struct {
	db     *gorm.DB
	logger *logrus.Logger
	config repository.AssetRepositoryConfiguration
}

// NewPostgreSQLAssetRepository creates a new PostgreSQL asset repository
func NewPostgreSQLAssetRepository(
	connectionString string,
	config repository.AssetRepositoryConfiguration,
	logger *logrus.Logger,
) (*PostgreSQLAssetRepository, error) {

	// Configure GORM logger
	gormLogger := logger.NewEntry(logger.Logger)
	var gormLogLevel logger.LogLevel
	if config.EnableQueryLogging {
		gormLogLevel = logger.Info
	} else {
		gormLogLevel = logger.Silent
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(connectionString), &gorm.Config{
		Logger: logger.New(
			gormLogger,
			logger.Config{
				SlowThreshold:             200 * time.Millisecond,
				LogLevel:                  gormLogLevel,
				IgnoreRecordNotFoundError: true,
				Colorful:                  false,
			},
		),
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	sqlDB.SetMaxOpenConns(config.MaxConnections)
	sqlDB.SetMaxIdleConns(config.MaxIdleConnections)
	sqlDB.SetConnMaxLifetime(config.ConnectionLifetime)

	repo := &PostgreSQLAssetRepository{
		db:     db,
		logger: logger,
		config: config,
	}

	// Auto-migrate schema
	if err := repo.autoMigrate(); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	// Create indexes
	if err := repo.createIndexes(); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"component":       "postgres_asset_repository",
		"max_connections": config.MaxConnections,
		"query_logging":   config.EnableQueryLogging,
	}).Info("PostgreSQL asset repository initialized")

	return repo, nil
}

// Core CRUD operations

func (r *PostgreSQLAssetRepository) Create(ctx context.Context, asset *entity.Asset) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "create",
		"asset_id":  asset.ID,
		"tenant_id": asset.TenantID,
	})

	if err := asset.Validate(); err != nil {
		logger.WithError(err).Error("Asset validation failed")
		return fmt.Errorf("validation failed: %w", err)
	}

	// Set timestamps
	now := time.Now().UTC()
	asset.CreatedAt = now
	asset.UpdatedAt = now

	if asset.FirstDiscovered.IsZero() {
		asset.FirstDiscovered = now
	}

	if asset.LastSeen.IsZero() {
		asset.LastSeen = now
	}

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	result := r.db.WithContext(ctx).Create(asset)
	if result.Error != nil {
		if isPrimaryKeyViolation(result.Error) {
			logger.WithError(result.Error).Warn("Asset already exists")
			return repository.ErrAssetAlreadyExists
		}
		logger.WithError(result.Error).Error("Failed to create asset")
		return fmt.Errorf("create failed: %w", result.Error)
	}

	logger.Debug("Asset created successfully")
	return nil
}

func (r *PostgreSQLAssetRepository) GetByID(ctx context.Context, tenantID, assetID uuid.UUID) (*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "get_by_id",
		"asset_id":  assetID,
		"tenant_id": tenantID,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var asset entity.Asset
	result := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", assetID, tenantID).
		First(&asset)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			logger.Debug("Asset not found")
			return nil, repository.ErrAssetNotFound
		}
		logger.WithError(result.Error).Error("Failed to get asset")
		return nil, fmt.Errorf("get failed: %w", result.Error)
	}

	logger.Debug("Asset retrieved successfully")
	return &asset, nil
}

func (r *PostgreSQLAssetRepository) Update(ctx context.Context, asset *entity.Asset) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "update",
		"asset_id":  asset.ID,
		"tenant_id": asset.TenantID,
	})

	if err := asset.Validate(); err != nil {
		logger.WithError(err).Error("Asset validation failed")
		return fmt.Errorf("validation failed: %w", err)
	}

	// Update timestamp
	asset.UpdatedAt = time.Now().UTC()

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	result := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", asset.ID, asset.TenantID).
		Updates(asset)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to update asset")
		return fmt.Errorf("update failed: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		logger.Warn("No rows affected during update")
		return repository.ErrAssetNotFound
	}

	logger.Debug("Asset updated successfully")
	return nil
}

func (r *PostgreSQLAssetRepository) Delete(ctx context.Context, tenantID, assetID uuid.UUID) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "delete",
		"asset_id":  assetID,
		"tenant_id": tenantID,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	result := r.db.WithContext(ctx).
		Where("id = ? AND tenant_id = ?", assetID, tenantID).
		Delete(&entity.Asset{})

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to delete asset")
		return fmt.Errorf("delete failed: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		logger.Warn("No rows affected during delete")
		return repository.ErrAssetNotFound
	}

	logger.Debug("Asset deleted successfully")
	return nil
}

// Query operations

func (r *PostgreSQLAssetRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) ([]*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "list",
		"tenant_id": tenantID,
		"filter":    fmt.Sprintf("%+v", filter),
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	query := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)
	query = r.applyAssetFilter(query, filter)

	var assets []*entity.Asset
	result := query.Find(&assets)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to list assets")
		return nil, fmt.Errorf("list failed: %w", result.Error)
	}

	logger.WithField("count", len(assets)).Debug("Assets listed successfully")
	return assets, nil
}

func (r *PostgreSQLAssetRepository) Count(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) (int64, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "count",
		"tenant_id": tenantID,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	query := r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ?", tenantID)
	query = r.applyAssetFilter(query, filter)

	var count int64
	result := query.Count(&count)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to count assets")
		return 0, fmt.Errorf("count failed: %w", result.Error)
	}

	logger.WithField("count", count).Debug("Assets counted successfully")
	return count, nil
}

func (r *PostgreSQLAssetRepository) Search(ctx context.Context, tenantID uuid.UUID, query repository.AssetSearchQuery) ([]*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "search",
		"tenant_id": tenantID,
		"query":     query.Query,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	// Build full-text search query
	db := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)

	if query.Query != "" {
		// Use PostgreSQL full-text search
		searchVector := "to_tsvector('english', " +
			"coalesce(name, '') || ' ' || " +
			"coalesce(display_name, '') || ' ' || " +
			"coalesce(description, '') || ' ' || " +
			"coalesce(owner, '') || ' ' || " +
			"coalesce(business_function, '') || ' ' || " +
			"array_to_string(ip_addresses, ' ') || ' ' || " +
			"array_to_string(host_names, ' ') || ' ' || " +
			"coalesce(os_name, '') || ' ' || " +
			"coalesce(hw_manufacturer, '') || ' ' || " +
			"coalesce(hw_model, '')" +
			")"

		searchQuery := "plainto_tsquery('english', ?)"
		if query.Fuzzy {
			// For fuzzy search, use similarity
			db = db.Where("similarity(name, ?) > 0.3 OR similarity(display_name, ?) > 0.3 OR similarity(description, ?) > 0.3",
				query.Query, query.Query, query.Query)
		} else {
			db = db.Where(searchVector+" @@ "+searchQuery, query.Query)
		}
	}

	// Apply additional filters
	db = r.applyAssetFilter(db, query.Filter)

	var assets []*entity.Asset
	result := db.Find(&assets)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to search assets")
		return nil, fmt.Errorf("search failed: %w", result.Error)
	}

	logger.WithField("count", len(assets)).Debug("Asset search completed")
	return assets, nil
}

// Specialized queries

func (r *PostgreSQLAssetRepository) FindByIPAddress(ctx context.Context, tenantID uuid.UUID, ipAddress string) ([]*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation":  "find_by_ip",
		"tenant_id":  tenantID,
		"ip_address": ipAddress,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND ip_addresses @> ?", tenantID, pq.Array([]string{ipAddress})).
		Find(&assets)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to find assets by IP address")
		return nil, fmt.Errorf("find by IP failed: %w", result.Error)
	}

	logger.WithField("count", len(assets)).Debug("Assets found by IP address")
	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByHostname(ctx context.Context, tenantID uuid.UUID, hostname string) ([]*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "find_by_hostname",
		"tenant_id": tenantID,
		"hostname":  hostname,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND (name ILIKE ? OR host_names @> ?)",
			tenantID, "%"+hostname+"%", pq.Array([]string{hostname})).
		Find(&assets)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to find assets by hostname")
		return nil, fmt.Errorf("find by hostname failed: %w", result.Error)
	}

	logger.WithField("count", len(assets)).Debug("Assets found by hostname")
	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByMACAddress(ctx context.Context, tenantID uuid.UUID, macAddress string) ([]*entity.Asset, error) {
	logger := r.logger.WithFields(logrus.Fields{
		"operation":   "find_by_mac",
		"tenant_id":   tenantID,
		"mac_address": macAddress,
	})

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND mac_addresses @> ?", tenantID, pq.Array([]string{macAddress})).
		Find(&assets)

	if result.Error != nil {
		logger.WithError(result.Error).Error("Failed to find assets by MAC address")
		return nil, fmt.Errorf("find by MAC failed: %w", result.Error)
	}

	logger.WithField("count", len(assets)).Debug("Assets found by MAC address")
	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByNetworkSegment(ctx context.Context, tenantID uuid.UUID, networkSegment string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND network_segment = ?", tenantID, networkSegment).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by network segment failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByAssetType(ctx context.Context, tenantID uuid.UUID, assetType entity.AssetType) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND asset_type = ?", tenantID, assetType).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by asset type failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByCriticality(ctx context.Context, tenantID uuid.UUID, criticality entity.CriticalityLevel) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND criticality = ?", tenantID, criticality).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by criticality failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByOwner(ctx context.Context, tenantID uuid.UUID, owner string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND owner ILIKE ?", tenantID, "%"+owner+"%").
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by owner failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByBusinessFunction(ctx context.Context, tenantID uuid.UUID, businessFunction string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND business_function = ?", tenantID, businessFunction).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by business function failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByTags(ctx context.Context, tenantID uuid.UUID, tags map[string]string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	query := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)

	for key, value := range tags {
		query = query.Where("tags @> ?", fmt.Sprintf(`[{"key":"%s","value":"%s"}]`, key, value))
	}

	var assets []*entity.Asset
	result := query.Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by tags failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindByComplianceFramework(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND compliance_frameworks @> ?", tenantID, pq.Array([]string{framework})).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find by compliance framework failed: %w", result.Error)
	}

	return assets, nil
}

// Discovery and inventory operations

func (r *PostgreSQLAssetRepository) FindStaleAssets(ctx context.Context, tenantID uuid.UUID, threshold time.Duration) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	cutoff := time.Now().UTC().Add(-threshold)

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND last_seen < ? AND status = ?", tenantID, cutoff, entity.AssetStatusActive).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find stale assets failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindAssetsNeedingScanning(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND scanning_enabled = true AND status = ?", tenantID, entity.AssetStatusActive).
		Where("last_scanned IS NULL OR last_scanned < ?", time.Now().UTC().Add(-24*time.Hour)).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find assets needing scanning failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindHighValueAssets(ctx context.Context, tenantID uuid.UUID) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND (criticality IN (?, ?) OR data_classification IN (?, ?))",
			tenantID,
			entity.CriticalityCritical, entity.CriticalityHigh,
			entity.DataClassificationRestricted, entity.DataClassificationConfidential).
		Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find high value assets failed: %w", result.Error)
	}

	return assets, nil
}

func (r *PostgreSQLAssetRepository) FindAssetsWithVulnerabilities(ctx context.Context, tenantID uuid.UUID, minSeverity string) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var assets []*entity.Asset
	query := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID)

	switch strings.ToLower(minSeverity) {
	case "critical":
		query = query.Where("vuln_critical > 0")
	case "high":
		query = query.Where("vuln_critical > 0 OR vuln_high > 0")
	case "medium":
		query = query.Where("vuln_critical > 0 OR vuln_high > 0 OR vuln_medium > 0")
	case "low":
		query = query.Where("vuln_total > 0")
	default:
		query = query.Where("vuln_total > 0")
	}

	result := query.Find(&assets)

	if result.Error != nil {
		return nil, fmt.Errorf("find assets with vulnerabilities failed: %w", result.Error)
	}

	return assets, nil
}

// Deduplication support

func (r *PostgreSQLAssetRepository) FindPotentialDuplicates(ctx context.Context, tenantID uuid.UUID, asset *entity.Asset) ([]*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var duplicates []*entity.Asset

	// Find by IP address overlap
	if len(asset.IPAddresses) > 0 {
		var ipDuplicates []*entity.Asset
		r.db.WithContext(ctx).
			Where("tenant_id = ? AND id != ? AND ip_addresses && ?",
				tenantID, asset.ID, pq.Array(asset.IPAddresses)).
			Find(&ipDuplicates)
		duplicates = append(duplicates, ipDuplicates...)
	}

	// Find by MAC address overlap
	if len(asset.MACAddresses) > 0 {
		var macDuplicates []*entity.Asset
		r.db.WithContext(ctx).
			Where("tenant_id = ? AND id != ? AND mac_addresses && ?",
				tenantID, asset.ID, pq.Array(asset.MACAddresses)).
			Find(&macDuplicates)
		duplicates = append(duplicates, macDuplicates...)
	}

	// Find by hostname similarity
	if asset.Name != "" {
		var hostDuplicates []*entity.Asset
		r.db.WithContext(ctx).
			Where("tenant_id = ? AND id != ? AND (name ILIKE ? OR host_names @> ?)",
				tenantID, asset.ID, "%"+asset.Name+"%", pq.Array([]string{asset.Name})).
			Find(&hostDuplicates)
		duplicates = append(duplicates, hostDuplicates...)
	}

	// Remove duplicates from result set
	seen := make(map[uuid.UUID]bool)
	var result []*entity.Asset
	for _, dup := range duplicates {
		if !seen[dup.ID] {
			seen[dup.ID] = true
			result = append(result, dup)
		}
	}

	return result, nil
}

func (r *PostgreSQLAssetRepository) FindByExternalID(ctx context.Context, tenantID uuid.UUID, system, externalID string) (*entity.Asset, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var asset entity.Asset
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND external_ids ->> ? = ?", tenantID, system, externalID).
		First(&asset)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, repository.ErrAssetNotFound
		}
		return nil, fmt.Errorf("find by external ID failed: %w", result.Error)
	}

	return &asset, nil
}

// Bulk operations

func (r *PostgreSQLAssetRepository) BulkCreate(ctx context.Context, assets []*entity.Asset) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "bulk_create",
		"count":     len(assets),
	})

	if len(assets) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout*2)
	defer cancel()

	// Set timestamps for all assets
	now := time.Now().UTC()
	for _, asset := range assets {
		if err := asset.Validate(); err != nil {
			return fmt.Errorf("validation failed for asset %s: %w", asset.ID, err)
		}
		asset.CreatedAt = now
		asset.UpdatedAt = now
		if asset.FirstDiscovered.IsZero() {
			asset.FirstDiscovered = now
		}
		if asset.LastSeen.IsZero() {
			asset.LastSeen = now
		}
	}

	// Use batch insert
	batchSize := r.config.CacheSettings.Size
	if batchSize <= 0 {
		batchSize = 100
	}

	result := r.db.WithContext(ctx).CreateInBatches(assets, batchSize)
	if result.Error != nil {
		logger.WithError(result.Error).Error("Bulk create failed")
		return fmt.Errorf("bulk create failed: %w", result.Error)
	}

	logger.WithField("rows_affected", result.RowsAffected).Debug("Bulk create completed")
	return nil
}

func (r *PostgreSQLAssetRepository) BulkUpdate(ctx context.Context, assets []*entity.Asset) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "bulk_update",
		"count":     len(assets),
	})

	if len(assets) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout*2)
	defer cancel()

	// Update timestamps
	now := time.Now().UTC()
	for _, asset := range assets {
		if err := asset.Validate(); err != nil {
			return fmt.Errorf("validation failed for asset %s: %w", asset.ID, err)
		}
		asset.UpdatedAt = now
	}

	// Use transaction for bulk update
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, asset := range assets {
			result := tx.Where("id = ? AND tenant_id = ?", asset.ID, asset.TenantID).Updates(asset)
			if result.Error != nil {
				return result.Error
			}
		}
		return nil
	})
}

func (r *PostgreSQLAssetRepository) BulkDelete(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	logger := r.logger.WithFields(logrus.Fields{
		"operation": "bulk_delete",
		"tenant_id": tenantID,
		"count":     len(assetIDs),
	})

	if len(assetIDs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND id IN ?", tenantID, assetIDs).
		Delete(&entity.Asset{})

	if result.Error != nil {
		logger.WithError(result.Error).Error("Bulk delete failed")
		return fmt.Errorf("bulk delete failed: %w", result.Error)
	}

	logger.WithField("rows_affected", result.RowsAffected).Debug("Bulk delete completed")
	return nil
}

func (r *PostgreSQLAssetRepository) BulkUpdateLastSeen(ctx context.Context, assetIDs []uuid.UUID, timestamp time.Time) error {
	if len(assetIDs) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	result := r.db.WithContext(ctx).
		Model(&entity.Asset{}).
		Where("id IN ?", assetIDs).
		Updates(map[string]interface{}{
			"last_seen":  timestamp,
			"updated_at": time.Now().UTC(),
		})

	if result.Error != nil {
		return fmt.Errorf("bulk update last seen failed: %w", result.Error)
	}

	return nil
}

// Statistics and reporting

func (r *PostgreSQLAssetRepository) GetAssetCounts(ctx context.Context, tenantID uuid.UUID) (*repository.AssetCounts, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	counts := &repository.AssetCounts{}

	// Total count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ?", tenantID).Count(&counts.Total)

	// Active count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND status = ?", tenantID, entity.AssetStatusActive).Count(&counts.Active)

	// Inactive count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND status = ?", tenantID, entity.AssetStatusInactive).Count(&counts.Inactive)

	// Critical count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND criticality = ?", tenantID, entity.CriticalityCritical).Count(&counts.Critical)

	// High count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND criticality = ?", tenantID, entity.CriticalityHigh).Count(&counts.High)

	// Medium count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND criticality = ?", tenantID, entity.CriticalityMedium).Count(&counts.Medium)

	// Low count
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND criticality = ?", tenantID, entity.CriticalityLow).Count(&counts.Low)

	// With vulnerabilities
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND vuln_total > 0", tenantID).Count(&counts.WithVulnerabilities)

	// Scanning enabled
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND scanning_enabled = true", tenantID).Count(&counts.ScanningEnabled)

	// Stale assets (not seen in 7 days)
	weekAgo := time.Now().UTC().Add(-7 * 24 * time.Hour)
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND last_seen < ?", tenantID, weekAgo).Count(&counts.StaleAssets)

	// Unowned assets
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND (owner = '' OR owner IS NULL)", tenantID).Count(&counts.UnownedAssets)

	// Unclassified assets
	r.db.WithContext(ctx).Model(&entity.Asset{}).Where("tenant_id = ? AND (business_function = '' OR business_function IS NULL)", tenantID).Count(&counts.UnclassifiedAssets)

	return counts, nil
}

func (r *PostgreSQLAssetRepository) GetAssetCountsByType(ctx context.Context, tenantID uuid.UUID) (map[entity.AssetType]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var results []struct {
		AssetType entity.AssetType `json:"asset_type"`
		Count     int64            `json:"count"`
	}

	err := r.db.WithContext(ctx).
		Model(&entity.Asset{}).
		Select("asset_type, count(*) as count").
		Where("tenant_id = ?", tenantID).
		Group("asset_type").
		Find(&results).Error

	if err != nil {
		return nil, fmt.Errorf("get asset counts by type failed: %w", err)
	}

	counts := make(map[entity.AssetType]int64)
	for _, result := range results {
		counts[result.AssetType] = result.Count
	}

	return counts, nil
}

func (r *PostgreSQLAssetRepository) GetAssetCountsByCriticality(ctx context.Context, tenantID uuid.UUID) (map[entity.CriticalityLevel]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var results []struct {
		Criticality entity.CriticalityLevel `json:"criticality"`
		Count       int64                   `json:"count"`
	}

	err := r.db.WithContext(ctx).
		Model(&entity.Asset{}).
		Select("criticality, count(*) as count").
		Where("tenant_id = ?", tenantID).
		Group("criticality").
		Find(&results).Error

	if err != nil {
		return nil, fmt.Errorf("get asset counts by criticality failed: %w", err)
	}

	counts := make(map[entity.CriticalityLevel]int64)
	for _, result := range results {
		counts[result.Criticality] = result.Count
	}

	return counts, nil
}

func (r *PostgreSQLAssetRepository) GetAssetCountsByStatus(ctx context.Context, tenantID uuid.UUID) (map[entity.AssetStatus]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var results []struct {
		Status entity.AssetStatus `json:"status"`
		Count  int64              `json:"count"`
	}

	err := r.db.WithContext(ctx).
		Model(&entity.Asset{}).
		Select("status, count(*) as count").
		Where("tenant_id = ?", tenantID).
		Group("status").
		Find(&results).Error

	if err != nil {
		return nil, fmt.Errorf("get asset counts by status failed: %w", err)
	}

	counts := make(map[entity.AssetStatus]int64)
	for _, result := range results {
		counts[result.Status] = result.Count
	}

	return counts, nil
}

func (r *PostgreSQLAssetRepository) GetNetworkSegmentDistribution(ctx context.Context, tenantID uuid.UUID) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, r.config.QueryTimeout)
	defer cancel()

	var results []struct {
		NetworkSegment string `json:"network_segment"`
		Count          int64  `json:"count"`
	}

	err := r.db.WithContext(ctx).
		Model(&entity.Asset{}).
		Select("network_segment, count(*) as count").
		Where("tenant_id = ? AND network_segment != ''", tenantID).
		Group("network_segment").
		Order("count DESC").
		Find(&results).Error

	if err != nil {
		return nil, fmt.Errorf("get network segment distribution failed: %w", err)
	}

	distribution := make(map[string]int64)
	for _, result := range results {
		distribution[result.NetworkSegment] = result.Count
	}

	return distribution, nil
}

func (r *PostgreSQLAssetRepository) GetTopSoftware(ctx context.Context, tenantID uuid.UUID, limit int) ([]*repository.SoftwareCount, error) {
	// This would require more complex JSON queries to aggregate software data
	// For now, return empty slice
	return []*repository.SoftwareCount{}, nil
}

func (r *PostgreSQLAssetRepository) GetTopVulnerabilities(ctx context.Context, tenantID uuid.UUID, limit int) ([]*repository.VulnerabilityCount, error) {
	// This would require vulnerability data integration
	// For now, return empty slice
	return []*repository.VulnerabilityCount{}, nil
}

// History and audit operations (simplified implementations)

func (r *PostgreSQLAssetRepository) GetAssetHistory(ctx context.Context, tenantID, assetID uuid.UUID, limit int) ([]*entity.AssetChange, error) {
	// Implementation would query asset history table
	return []*entity.AssetChange{}, nil
}

func (r *PostgreSQLAssetRepository) RecordAssetChange(ctx context.Context, tenantID, assetID uuid.UUID, change *entity.AssetChange) error {
	// Implementation would insert into asset history table
	return nil
}

// Additional methods (simplified implementations)

func (r *PostgreSQLAssetRepository) GetAssetRelationships(ctx context.Context, tenantID, assetID uuid.UUID) ([]*entity.AssetRelationship, error) {
	return []*entity.AssetRelationship{}, nil
}

func (r *PostgreSQLAssetRepository) CreateAssetRelationship(ctx context.Context, tenantID, assetID uuid.UUID, relationship *entity.AssetRelationship) error {
	return nil
}

func (r *PostgreSQLAssetRepository) DeleteAssetRelationship(ctx context.Context, tenantID, assetID, relatedAssetID uuid.UUID) error {
	return nil
}

func (r *PostgreSQLAssetRepository) GetComplianceAssets(ctx context.Context, tenantID uuid.UUID, framework string) ([]*entity.Asset, error) {
	return r.FindByComplianceFramework(ctx, tenantID, framework)
}

func (r *PostgreSQLAssetRepository) UpdateComplianceStatus(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID, framework string, status string) error {
	return nil
}

func (r *PostgreSQLAssetRepository) GetHealthStatus(ctx context.Context) (*repository.RepositoryHealth, error) {
	health := &repository.RepositoryHealth{
		Healthy:             true,
		DatabaseConnected:   true,
		QueryPerformance:    make(map[string]string),
		IndexHealth:         make(map[string]string),
		TableSizes:          make(map[string]int64),
		ConnectionPoolStats: make(map[string]int),
		LastMaintenanceRun:  time.Now().UTC(),
		RecommendedActions:  []string{},
	}

	sqlDB, err := r.db.DB()
	if err != nil {
		health.Healthy = false
		health.DatabaseConnected = false
		return health, nil
	}

	// Check database connection
	if err := sqlDB.Ping(); err != nil {
		health.Healthy = false
		health.DatabaseConnected = false
	}

	// Get connection pool stats
	stats := sqlDB.Stats()
	health.ConnectionPoolStats["open_connections"] = stats.OpenConnections
	health.ConnectionPoolStats["in_use"] = stats.InUse
	health.ConnectionPoolStats["idle"] = stats.Idle

	return health, nil
}

func (r *PostgreSQLAssetRepository) RunMaintenance(ctx context.Context) error {
	// Implementation would run database maintenance tasks
	return nil
}

func (r *PostgreSQLAssetRepository) OptimizeQueries(ctx context.Context) error {
	// Implementation would run query optimization
	return nil
}

// Private helper methods

func (r *PostgreSQLAssetRepository) applyAssetFilter(query *gorm.DB, filter repository.AssetFilter) *gorm.DB {
	// Asset types
	if len(filter.AssetTypes) > 0 {
		query = query.Where("asset_type IN ?", filter.AssetTypes)
	}

	// Criticalities
	if len(filter.Criticalities) > 0 {
		query = query.Where("criticality IN ?", filter.Criticalities)
	}

	// Statuses
	if len(filter.Statuses) > 0 {
		query = query.Where("status IN ?", filter.Statuses)
	}

	// Network segments
	if len(filter.NetworkSegments) > 0 {
		query = query.Where("network_segment IN ?", filter.NetworkSegments)
	}

	// Business functions
	if len(filter.BusinessFunctions) > 0 {
		query = query.Where("business_function IN ?", filter.BusinessFunctions)
	}

	// Owners
	if len(filter.Owners) > 0 {
		query = query.Where("owner IN ?", filter.Owners)
	}

	// Operating systems
	if len(filter.OperatingSystems) > 0 {
		query = query.Where("os_name IN ?", filter.OperatingSystems)
	}

	// Time filters
	if filter.CreatedAfter != nil {
		query = query.Where("created_at >= ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("created_at <= ?", *filter.CreatedBefore)
	}
	if filter.UpdatedAfter != nil {
		query = query.Where("updated_at >= ?", *filter.UpdatedAfter)
	}
	if filter.UpdatedBefore != nil {
		query = query.Where("updated_at <= ?", *filter.UpdatedBefore)
	}
	if filter.LastSeenAfter != nil {
		query = query.Where("last_seen >= ?", *filter.LastSeenAfter)
	}
	if filter.LastSeenBefore != nil {
		query = query.Where("last_seen <= ?", *filter.LastSeenBefore)
	}

	// Vulnerability filters
	if filter.HasVulnerabilities != nil {
		if *filter.HasVulnerabilities {
			query = query.Where("vuln_total > 0")
		} else {
			query = query.Where("vuln_total = 0")
		}
	}
	if filter.MinVulnerabilityCount != nil {
		query = query.Where("vuln_total >= ?", *filter.MinVulnerabilityCount)
	}

	// Scanning filters
	if filter.ScanningEnabled != nil {
		query = query.Where("scanning_enabled = ?", *filter.ScanningEnabled)
	}

	// Tag filters
	for key, value := range filter.Tags {
		query = query.Where("tags @> ?", fmt.Sprintf(`[{"key":"%s","value":"%s"}]`, key, value))
	}

	// Compliance frameworks
	if len(filter.ComplianceFrameworks) > 0 {
		for _, framework := range filter.ComplianceFrameworks {
			query = query.Where("compliance_frameworks @> ?", pq.Array([]string{framework}))
		}
	}

	// Sorting
	if filter.SortBy != "" {
		orderClause := filter.SortBy
		if filter.SortOrder == repository.SortOrderDesc {
			orderClause += " DESC"
		} else {
			orderClause += " ASC"
		}
		query = query.Order(orderClause)
	} else {
		query = query.Order("updated_at DESC")
	}

	// Pagination
	if filter.Offset > 0 {
		query = query.Offset(filter.Offset)
	}
	if filter.Limit > 0 {
		query = query.Limit(filter.Limit)
	}

	return query
}

func (r *PostgreSQLAssetRepository) autoMigrate() error {
	return r.db.AutoMigrate(&entity.Asset{})
}

func (r *PostgreSQLAssetRepository) createIndexes() error {
	// Create custom indexes for better query performance
	queries := []string{
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_asset_type ON assets(tenant_id, asset_type)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_criticality ON assets(tenant_id, criticality)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_status ON assets(tenant_id, status)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_last_seen ON assets(tenant_id, last_seen)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_network_segment ON assets(tenant_id, network_segment)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_owner ON assets(tenant_id, owner)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_business_function ON assets(tenant_id, business_function)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_ip_addresses_gin ON assets USING gin(ip_addresses)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_mac_addresses_gin ON assets USING gin(mac_addresses)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_host_names_gin ON assets USING gin(host_names)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tags_gin ON assets USING gin(tags)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_compliance_frameworks_gin ON assets USING gin(compliance_frameworks)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_external_ids_gin ON assets USING gin(external_ids)",
		// Full-text search index
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_search_vector ON assets USING gin(to_tsvector('english', coalesce(name, '') || ' ' || coalesce(display_name, '') || ' ' || coalesce(description, '')))",
		// Enable pg_trgm extension for fuzzy search
		"CREATE EXTENSION IF NOT EXISTS pg_trgm",
		// Create trigram indexes for fuzzy search
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_name_trgm ON assets USING gin(name gin_trgm_ops)",
		"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_display_name_trgm ON assets USING gin(display_name gin_trgm_ops)",
	}

	for _, query := range queries {
		if err := r.db.Exec(query).Error; err != nil {
			// Log warning but don't fail - indexes might already exist
			r.logger.WithError(err).WithField("query", query).Warn("Failed to create index")
		}
	}

	return nil
}

func isPrimaryKeyViolation(err error) bool {
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505" // unique_violation
	}
	return false
}
