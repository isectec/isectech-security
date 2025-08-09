// iSECTECH Asset Inventory - Asset Use Case
// Production-grade business logic orchestration for asset management
// Copyright (c) 2024 iSECTECH. All rights reserved.

package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
	"github.com/isectech/backend/services/asset-inventory/domain/repository"
	"github.com/isectech/backend/services/asset-inventory/domain/service"
)

// AssetUseCase orchestrates asset management business logic
type AssetUseCase struct {
	assetRepo             repository.AssetRepository
	classificationService *service.AssetClassificationService
	discoveryService      *service.AssetDiscoveryService
	logger                *logrus.Logger
}

// AssetCreationRequest represents a request to create a new asset
type AssetCreationRequest struct {
	TenantID             uuid.UUID                  `json:"tenant_id" validate:"required"`
	Name                 string                     `json:"name" validate:"required,min=1,max=255"`
	DisplayName          string                     `json:"display_name,omitempty"`
	Description          string                     `json:"description,omitempty"`
	AssetType            entity.AssetType           `json:"asset_type" validate:"required"`
	AssetSubtype         string                     `json:"asset_subtype,omitempty"`
	Criticality          entity.CriticalityLevel    `json:"criticality,omitempty"`
	BusinessFunction     string                     `json:"business_function,omitempty"`
	Owner                string                     `json:"owner,omitempty"`
	OwnerContact         string                     `json:"owner_contact,omitempty"`
	IPAddresses          []string                   `json:"ip_addresses,omitempty"`
	MACAddresses         []string                   `json:"mac_addresses,omitempty"`
	HostNames            []string                   `json:"host_names,omitempty"`
	FQDNs                []string                   `json:"fqdns,omitempty"`
	NetworkSegment       string                     `json:"network_segment,omitempty"`
	Location             entity.AssetLocation       `json:"location,omitempty"`
	OperatingSystem      entity.OperatingSystemInfo `json:"operating_system,omitempty"`
	Hardware             entity.HardwareInfo        `json:"hardware,omitempty"`
	DataClassification   entity.DataClassification  `json:"data_classification,omitempty"`
	ComplianceFrameworks []string                   `json:"compliance_frameworks,omitempty"`
	Tags                 []entity.AssetTag          `json:"tags,omitempty"`
	CustomFields         map[string]string          `json:"custom_fields,omitempty"`
	ExternalIDs          map[string]string          `json:"external_ids,omitempty"`
	DiscoveryMethod      string                     `json:"discovery_method,omitempty"`
	ScanningEnabled      bool                       `json:"scanning_enabled"`
	ScanFrequency        entity.ScanFrequency       `json:"scan_frequency,omitempty"`
	AutoClassify         bool                       `json:"auto_classify"`
	CreatedBy            string                     `json:"created_by,omitempty"`
}

// AssetUpdateRequest represents a request to update an existing asset
type AssetUpdateRequest struct {
	Name                 *string                     `json:"name,omitempty"`
	DisplayName          *string                     `json:"display_name,omitempty"`
	Description          *string                     `json:"description,omitempty"`
	AssetSubtype         *string                     `json:"asset_subtype,omitempty"`
	Criticality          *entity.CriticalityLevel    `json:"criticality,omitempty"`
	BusinessFunction     *string                     `json:"business_function,omitempty"`
	Owner                *string                     `json:"owner,omitempty"`
	OwnerContact         *string                     `json:"owner_contact,omitempty"`
	IPAddresses          []string                    `json:"ip_addresses,omitempty"`
	MACAddresses         []string                    `json:"mac_addresses,omitempty"`
	HostNames            []string                    `json:"host_names,omitempty"`
	FQDNs                []string                    `json:"fqdns,omitempty"`
	NetworkSegment       *string                     `json:"network_segment,omitempty"`
	Location             *entity.AssetLocation       `json:"location,omitempty"`
	OperatingSystem      *entity.OperatingSystemInfo `json:"operating_system,omitempty"`
	Hardware             *entity.HardwareInfo        `json:"hardware,omitempty"`
	Software             []entity.SoftwareComponent  `json:"software,omitempty"`
	Services             []entity.ServiceInfo        `json:"services,omitempty"`
	SecurityControls     []entity.SecurityControl    `json:"security_controls,omitempty"`
	DataClassification   *entity.DataClassification  `json:"data_classification,omitempty"`
	ComplianceFrameworks []string                    `json:"compliance_frameworks,omitempty"`
	ScanningEnabled      *bool                       `json:"scanning_enabled,omitempty"`
	ScanFrequency        *entity.ScanFrequency       `json:"scan_frequency,omitempty"`
	Status               *entity.AssetStatus         `json:"status,omitempty"`
	Tags                 []entity.AssetTag           `json:"tags,omitempty"`
	CustomFields         map[string]string           `json:"custom_fields,omitempty"`
	ExternalIDs          map[string]string           `json:"external_ids,omitempty"`
	UpdatedBy            string                      `json:"updated_by,omitempty"`
	Reason               string                      `json:"reason,omitempty"`
}

// AssetSearchRequest represents a search request for assets
type AssetSearchRequest struct {
	TenantID     uuid.UUID                    `json:"tenant_id" validate:"required"`
	Query        string                       `json:"query,omitempty"`
	Filter       repository.AssetFilter       `json:"filter,omitempty"`
	SearchQuery  *repository.AssetSearchQuery `json:"search_query,omitempty"`
	IncludeCount bool                         `json:"include_count"`
}

// AssetSearchResponse represents the response from asset search
type AssetSearchResponse struct {
	Assets     []*entity.Asset `json:"assets"`
	TotalCount int64           `json:"total_count,omitempty"`
	SearchTime time.Duration   `json:"search_time"`
	HasMore    bool            `json:"has_more"`
}

// AssetClassificationRequest represents a request to classify an asset
type AssetClassificationRequest struct {
	TenantID uuid.UUID `json:"tenant_id" validate:"required"`
	AssetID  uuid.UUID `json:"asset_id" validate:"required"`
	Force    bool      `json:"force"` // Force re-classification even if already classified
}

// AssetStatisticsRequest represents a request for asset statistics
type AssetStatisticsRequest struct {
	TenantID  uuid.UUID              `json:"tenant_id" validate:"required"`
	Groupings []string               `json:"groupings,omitempty"` // e.g., ["type", "criticality", "status"]
	TimeRange *TimeRange             `json:"time_range,omitempty"`
	Filter    repository.AssetFilter `json:"filter,omitempty"`
}

// TimeRange represents a time range filter
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AssetStatisticsResponse represents asset statistics
type AssetStatisticsResponse struct {
	Summary       *repository.AssetCounts           `json:"summary"`
	ByType        map[entity.AssetType]int64        `json:"by_type,omitempty"`
	ByCriticality map[entity.CriticalityLevel]int64 `json:"by_criticality,omitempty"`
	ByStatus      map[entity.AssetStatus]int64      `json:"by_status,omitempty"`
	ByNetwork     map[string]int64                  `json:"by_network,omitempty"`
	TopSoftware   []*repository.SoftwareCount       `json:"top_software,omitempty"`
	TopVulns      []*repository.VulnerabilityCount  `json:"top_vulnerabilities,omitempty"`
	Trends        map[string][]StatisticPoint       `json:"trends,omitempty"`
	GeneratedAt   time.Time                         `json:"generated_at"`
}

// StatisticPoint represents a point in time statistics
type StatisticPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     int64     `json:"value"`
}

// AssetBulkOperationRequest represents a bulk operation request
type AssetBulkOperationRequest struct {
	TenantID   uuid.UUID              `json:"tenant_id" validate:"required"`
	AssetIDs   []uuid.UUID            `json:"asset_ids" validate:"required,min=1"`
	Operation  string                 `json:"operation" validate:"required"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Reason     string                 `json:"reason,omitempty"`
	UpdatedBy  string                 `json:"updated_by,omitempty"`
}

// AssetBulkOperationResponse represents the response from a bulk operation
type AssetBulkOperationResponse struct {
	SuccessCount int                  `json:"success_count"`
	FailureCount int                  `json:"failure_count"`
	Errors       []BulkOperationError `json:"errors,omitempty"`
	ProcessedAt  time.Time            `json:"processed_at"`
}

// BulkOperationError represents an error during bulk operation
type BulkOperationError struct {
	AssetID uuid.UUID `json:"asset_id"`
	Error   string    `json:"error"`
	Code    string    `json:"code,omitempty"`
}

// NewAssetUseCase creates a new asset use case
func NewAssetUseCase(
	assetRepo repository.AssetRepository,
	classificationService *service.AssetClassificationService,
	discoveryService *service.AssetDiscoveryService,
	logger *logrus.Logger,
) *AssetUseCase {
	return &AssetUseCase{
		assetRepo:             assetRepo,
		classificationService: classificationService,
		discoveryService:      discoveryService,
		logger:                logger,
	}
}

// CreateAsset creates a new asset with optional auto-classification
func (uc *AssetUseCase) CreateAsset(ctx context.Context, req *AssetCreationRequest) (*entity.Asset, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":  "create_asset",
		"tenant_id":  req.TenantID,
		"asset_name": req.Name,
		"asset_type": req.AssetType,
	})

	logger.Info("Creating new asset")

	// Validate request
	if err := uc.validateAssetCreationRequest(req); err != nil {
		logger.WithError(err).Error("Asset creation request validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check for potential duplicates
	duplicates, err := uc.findPotentialDuplicates(ctx, req)
	if err != nil {
		logger.WithError(err).Warn("Failed to check for duplicates")
	} else if len(duplicates) > 0 {
		logger.WithField("duplicates_count", len(duplicates)).Warn("Potential duplicate assets found")
		// Could return an error or warning here based on business rules
	}

	// Create asset entity
	asset := uc.buildAssetFromCreationRequest(req)

	// Auto-classify if requested
	if req.AutoClassify {
		classificationResult, err := uc.classificationService.ClassifyAsset(ctx, asset)
		if err != nil {
			logger.WithError(err).Warn("Auto-classification failed, proceeding without classification")
		} else {
			uc.applyClassificationResult(asset, classificationResult)
			logger.WithField("confidence_score", classificationResult.ConfidenceScore).Info("Asset auto-classified")
		}
	}

	// Save asset
	if err := uc.assetRepo.Create(ctx, asset); err != nil {
		logger.WithError(err).Error("Failed to save asset")
		return nil, fmt.Errorf("failed to save asset: %w", err)
	}

	// Record audit trail
	change := &entity.AssetChange{
		Timestamp: time.Now().UTC(),
		User:      req.CreatedBy,
		Operation: "create",
		Reason:    "Asset created",
	}
	uc.assetRepo.RecordAssetChange(ctx, req.TenantID, asset.ID, change)

	logger.WithField("asset_id", asset.ID).Info("Asset created successfully")
	return asset, nil
}

// GetAsset retrieves an asset by ID
func (uc *AssetUseCase) GetAsset(ctx context.Context, tenantID, assetID uuid.UUID) (*entity.Asset, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "get_asset",
		"tenant_id": tenantID,
		"asset_id":  assetID,
	})

	logger.Debug("Retrieving asset")

	asset, err := uc.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve asset")
		return nil, fmt.Errorf("failed to retrieve asset: %w", err)
	}

	logger.Debug("Asset retrieved successfully")
	return asset, nil
}

// UpdateAsset updates an existing asset
func (uc *AssetUseCase) UpdateAsset(ctx context.Context, tenantID, assetID uuid.UUID, req *AssetUpdateRequest) (*entity.Asset, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "update_asset",
		"tenant_id": tenantID,
		"asset_id":  assetID,
	})

	logger.Info("Updating asset")

	// Get existing asset
	asset, err := uc.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve asset for update")
		return nil, fmt.Errorf("failed to retrieve asset: %w", err)
	}

	// Track changes for audit
	changes := uc.trackAssetChanges(asset, req)

	// Apply updates
	uc.applyAssetUpdates(asset, req)

	// Validate updated asset
	if err := asset.Validate(); err != nil {
		logger.WithError(err).Error("Updated asset validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Save updated asset
	if err := uc.assetRepo.Update(ctx, asset); err != nil {
		logger.WithError(err).Error("Failed to save updated asset")
		return nil, fmt.Errorf("failed to save asset: %w", err)
	}

	// Record audit trail
	if len(changes) > 0 {
		change := &entity.AssetChange{
			Timestamp: time.Now().UTC(),
			User:      req.UpdatedBy,
			Operation: "update",
			Reason:    req.Reason,
		}
		uc.assetRepo.RecordAssetChange(ctx, tenantID, assetID, change)
	}

	logger.WithField("changes_count", len(changes)).Info("Asset updated successfully")
	return asset, nil
}

// DeleteAsset deletes an asset
func (uc *AssetUseCase) DeleteAsset(ctx context.Context, tenantID, assetID uuid.UUID, deletedBy, reason string) error {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":  "delete_asset",
		"tenant_id":  tenantID,
		"asset_id":   assetID,
		"deleted_by": deletedBy,
	})

	logger.Info("Deleting asset")

	// Check if asset exists
	_, err := uc.assetRepo.GetByID(ctx, tenantID, assetID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve asset for deletion")
		return fmt.Errorf("failed to retrieve asset: %w", err)
	}

	// Record audit trail before deletion
	change := &entity.AssetChange{
		Timestamp: time.Now().UTC(),
		User:      deletedBy,
		Operation: "delete",
		Reason:    reason,
	}
	uc.assetRepo.RecordAssetChange(ctx, tenantID, assetID, change)

	// Delete asset
	if err := uc.assetRepo.Delete(ctx, tenantID, assetID); err != nil {
		logger.WithError(err).Error("Failed to delete asset")
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	logger.Info("Asset deleted successfully")
	return nil
}

// SearchAssets searches for assets based on criteria
func (uc *AssetUseCase) SearchAssets(ctx context.Context, req *AssetSearchRequest) (*AssetSearchResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":     "search_assets",
		"tenant_id":     req.TenantID,
		"query":         req.Query,
		"include_count": req.IncludeCount,
	})

	logger.Debug("Searching assets")
	startTime := time.Now()

	var assets []*entity.Asset
	var totalCount int64
	var err error

	if req.SearchQuery != nil {
		// Full-text search
		assets, err = uc.assetRepo.Search(ctx, req.TenantID, *req.SearchQuery)
	} else {
		// Filter-based search
		assets, err = uc.assetRepo.List(ctx, req.TenantID, req.Filter)
	}

	if err != nil {
		logger.WithError(err).Error("Asset search failed")
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Get total count if requested
	if req.IncludeCount {
		if req.SearchQuery != nil {
			// For full-text search, count would need special handling
			totalCount = int64(len(assets))
		} else {
			totalCount, err = uc.assetRepo.Count(ctx, req.TenantID, req.Filter)
			if err != nil {
				logger.WithError(err).Warn("Failed to get total count")
			}
		}
	}

	searchTime := time.Since(startTime)
	hasMore := false
	if req.Filter.Limit > 0 && len(assets) == req.Filter.Limit {
		hasMore = true
	}

	response := &AssetSearchResponse{
		Assets:     assets,
		TotalCount: totalCount,
		SearchTime: searchTime,
		HasMore:    hasMore,
	}

	logger.WithFields(logrus.Fields{
		"results_count":  len(assets),
		"total_count":    totalCount,
		"search_time_ms": searchTime.Milliseconds(),
	}).Debug("Asset search completed")

	return response, nil
}

// ClassifyAsset performs asset classification
func (uc *AssetUseCase) ClassifyAsset(ctx context.Context, req *AssetClassificationRequest) (*service.ClassificationResult, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "classify_asset",
		"tenant_id": req.TenantID,
		"asset_id":  req.AssetID,
		"force":     req.Force,
	})

	logger.Info("Classifying asset")

	// Get asset
	asset, err := uc.assetRepo.GetByID(ctx, req.TenantID, req.AssetID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve asset for classification")
		return nil, fmt.Errorf("failed to retrieve asset: %w", err)
	}

	// Perform classification
	result, err := uc.classificationService.ClassifyAsset(ctx, asset)
	if err != nil {
		logger.WithError(err).Error("Asset classification failed")
		return nil, fmt.Errorf("classification failed: %w", err)
	}

	// Apply classification results to asset
	if req.Force || asset.BusinessFunction == "" || asset.Criticality == "" {
		uc.applyClassificationResult(asset, result)

		// Save updated asset
		if err := uc.assetRepo.Update(ctx, asset); err != nil {
			logger.WithError(err).Warn("Failed to save classification results")
		} else {
			logger.Info("Classification results applied to asset")
		}
	}

	logger.WithFields(logrus.Fields{
		"applied_rules":         len(result.AppliedRules),
		"confidence_score":      result.ConfidenceScore,
		"suggested_criticality": result.SuggestedCriticality,
	}).Info("Asset classification completed")

	return result, nil
}

// GetAssetStatistics retrieves asset statistics
func (uc *AssetUseCase) GetAssetStatistics(ctx context.Context, req *AssetStatisticsRequest) (*AssetStatisticsResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "get_asset_statistics",
		"tenant_id": req.TenantID,
		"groupings": req.Groupings,
	})

	logger.Debug("Generating asset statistics")

	response := &AssetStatisticsResponse{
		GeneratedAt: time.Now().UTC(),
	}

	// Get summary counts
	summary, err := uc.assetRepo.GetAssetCounts(ctx, req.TenantID)
	if err != nil {
		logger.WithError(err).Error("Failed to get asset summary counts")
		return nil, fmt.Errorf("failed to get summary: %w", err)
	}
	response.Summary = summary

	// Get detailed breakdowns if requested
	for _, grouping := range req.Groupings {
		switch grouping {
		case "type":
			if counts, err := uc.assetRepo.GetAssetCountsByType(ctx, req.TenantID); err == nil {
				response.ByType = counts
			}
		case "criticality":
			if counts, err := uc.assetRepo.GetAssetCountsByCriticality(ctx, req.TenantID); err == nil {
				response.ByCriticality = counts
			}
		case "status":
			if counts, err := uc.assetRepo.GetAssetCountsByStatus(ctx, req.TenantID); err == nil {
				response.ByStatus = counts
			}
		case "network":
			if distribution, err := uc.assetRepo.GetNetworkSegmentDistribution(ctx, req.TenantID); err == nil {
				response.ByNetwork = distribution
			}
		case "software":
			if software, err := uc.assetRepo.GetTopSoftware(ctx, req.TenantID, 10); err == nil {
				response.TopSoftware = software
			}
		case "vulnerabilities":
			if vulns, err := uc.assetRepo.GetTopVulnerabilities(ctx, req.TenantID, 10); err == nil {
				response.TopVulns = vulns
			}
		}
	}

	logger.Debug("Asset statistics generated successfully")
	return response, nil
}

// PerformBulkOperation performs bulk operations on multiple assets
func (uc *AssetUseCase) PerformBulkOperation(ctx context.Context, req *AssetBulkOperationRequest) (*AssetBulkOperationResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":      "bulk_operation",
		"tenant_id":      req.TenantID,
		"operation_type": req.Operation,
		"asset_count":    len(req.AssetIDs),
	})

	logger.Info("Performing bulk operation")

	response := &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}

	switch req.Operation {
	case "delete":
		response = uc.performBulkDelete(ctx, req)
	case "update_status":
		response = uc.performBulkStatusUpdate(ctx, req)
	case "update_criticality":
		response = uc.performBulkCriticalityUpdate(ctx, req)
	case "add_tags":
		response = uc.performBulkTagAdd(ctx, req)
	case "remove_tags":
		response = uc.performBulkTagRemove(ctx, req)
	case "update_scanning":
		response = uc.performBulkScanningUpdate(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported bulk operation: %s", req.Operation)
	}

	logger.WithFields(logrus.Fields{
		"success_count": response.SuccessCount,
		"failure_count": response.FailureCount,
	}).Info("Bulk operation completed")

	return response, nil
}

// Private helper methods

func (uc *AssetUseCase) validateAssetCreationRequest(req *AssetCreationRequest) error {
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if req.Name == "" {
		return fmt.Errorf("asset name is required")
	}

	if req.AssetType == "" {
		return fmt.Errorf("asset type is required")
	}

	// Validate IP addresses
	for _, ip := range req.IPAddresses {
		if ip != "" && !isValidIPAddress(ip) {
			return fmt.Errorf("invalid IP address: %s", ip)
		}
	}

	return nil
}

func (uc *AssetUseCase) findPotentialDuplicates(ctx context.Context, req *AssetCreationRequest) ([]*entity.Asset, error) {
	// Create a temporary asset for duplicate checking
	tempAsset := &entity.Asset{
		TenantID:     req.TenantID,
		Name:         req.Name,
		IPAddresses:  req.IPAddresses,
		MACAddresses: req.MACAddresses,
		HostNames:    req.HostNames,
	}

	return uc.assetRepo.FindPotentialDuplicates(ctx, req.TenantID, tempAsset)
}

func (uc *AssetUseCase) buildAssetFromCreationRequest(req *AssetCreationRequest) *entity.Asset {
	now := time.Now().UTC()

	asset := &entity.Asset{
		ID:                   uuid.New(),
		TenantID:             req.TenantID,
		Name:                 req.Name,
		DisplayName:          req.DisplayName,
		Description:          req.Description,
		AssetType:            req.AssetType,
		AssetSubtype:         req.AssetSubtype,
		Criticality:          req.Criticality,
		BusinessFunction:     req.BusinessFunction,
		Owner:                req.Owner,
		OwnerContact:         req.OwnerContact,
		IPAddresses:          req.IPAddresses,
		MACAddresses:         req.MACAddresses,
		HostNames:            req.HostNames,
		FQDNs:                req.FQDNs,
		NetworkSegment:       req.NetworkSegment,
		Location:             req.Location,
		OperatingSystem:      req.OperatingSystem,
		Hardware:             req.Hardware,
		DataClassification:   req.DataClassification,
		ComplianceFrameworks: req.ComplianceFrameworks,
		Tags:                 req.Tags,
		CustomFields:         req.CustomFields,
		ExternalIDs:          req.ExternalIDs,
		Status:               entity.AssetStatusActive,
		DiscoveryMethod:      req.DiscoveryMethod,
		FirstDiscovered:      now,
		LastSeen:             now,
		LastUpdated:          now,
		ScanningEnabled:      req.ScanningEnabled,
		ScanFrequency:        req.ScanFrequency,
		CreatedAt:            now,
		UpdatedAt:            now,
		CreatedBy:            req.CreatedBy,
	}

	// Set defaults
	if asset.Criticality == "" {
		asset.Criticality = entity.CriticalityMedium
	}

	if asset.ScanFrequency == "" {
		asset.ScanFrequency = entity.ScanFrequencyWeekly
	}

	if asset.DataClassification == "" {
		asset.DataClassification = entity.DataClassificationInternal
	}

	if asset.Tags == nil {
		asset.Tags = []entity.AssetTag{}
	}

	if asset.CustomFields == nil {
		asset.CustomFields = make(map[string]string)
	}

	if asset.ExternalIDs == nil {
		asset.ExternalIDs = make(map[string]string)
	}

	return asset
}

func (uc *AssetUseCase) applyClassificationResult(asset *entity.Asset, result *service.ClassificationResult) {
	if result.SuggestedCriticality != "" {
		asset.Criticality = result.SuggestedCriticality
	}

	if result.BusinessFunction != "" {
		asset.BusinessFunction = result.BusinessFunction
	}

	// Add suggested tags
	for _, tag := range result.SuggestedTags {
		asset.AddTag(tag.Key, tag.Value, tag.Source)
	}

	// Update compliance frameworks
	if len(result.ComplianceFrameworks) > 0 {
		asset.ComplianceFrameworks = append(asset.ComplianceFrameworks, result.ComplianceFrameworks...)
	}
}

func (uc *AssetUseCase) trackAssetChanges(asset *entity.Asset, req *AssetUpdateRequest) []string {
	changes := []string{}

	if req.Name != nil && *req.Name != asset.Name {
		changes = append(changes, "name")
	}

	if req.Criticality != nil && *req.Criticality != asset.Criticality {
		changes = append(changes, "criticality")
	}

	if req.Owner != nil && *req.Owner != asset.Owner {
		changes = append(changes, "owner")
	}

	// Add more field comparisons as needed

	return changes
}

func (uc *AssetUseCase) applyAssetUpdates(asset *entity.Asset, req *AssetUpdateRequest) {
	if req.Name != nil {
		asset.Name = *req.Name
	}

	if req.DisplayName != nil {
		asset.DisplayName = *req.DisplayName
	}

	if req.Description != nil {
		asset.Description = *req.Description
	}

	if req.AssetSubtype != nil {
		asset.AssetSubtype = *req.AssetSubtype
	}

	if req.Criticality != nil {
		asset.Criticality = *req.Criticality
	}

	if req.BusinessFunction != nil {
		asset.BusinessFunction = *req.BusinessFunction
	}

	if req.Owner != nil {
		asset.Owner = *req.Owner
	}

	if req.OwnerContact != nil {
		asset.OwnerContact = *req.OwnerContact
	}

	if len(req.IPAddresses) > 0 {
		asset.IPAddresses = req.IPAddresses
	}

	if len(req.MACAddresses) > 0 {
		asset.MACAddresses = req.MACAddresses
	}

	if len(req.HostNames) > 0 {
		asset.HostNames = req.HostNames
	}

	if len(req.FQDNs) > 0 {
		asset.FQDNs = req.FQDNs
	}

	if req.NetworkSegment != nil {
		asset.NetworkSegment = *req.NetworkSegment
	}

	if req.Location != nil {
		asset.Location = *req.Location
	}

	if req.OperatingSystem != nil {
		asset.OperatingSystem = *req.OperatingSystem
	}

	if req.Hardware != nil {
		asset.Hardware = *req.Hardware
	}

	if len(req.Software) > 0 {
		asset.Software = req.Software
	}

	if len(req.Services) > 0 {
		asset.Services = req.Services
	}

	if len(req.SecurityControls) > 0 {
		asset.SecurityControls = req.SecurityControls
	}

	if req.DataClassification != nil {
		asset.DataClassification = *req.DataClassification
	}

	if len(req.ComplianceFrameworks) > 0 {
		asset.ComplianceFrameworks = req.ComplianceFrameworks
	}

	if req.ScanningEnabled != nil {
		asset.ScanningEnabled = *req.ScanningEnabled
	}

	if req.ScanFrequency != nil {
		asset.ScanFrequency = *req.ScanFrequency
	}

	if req.Status != nil {
		asset.Status = *req.Status
	}

	if len(req.Tags) > 0 {
		asset.Tags = req.Tags
	}

	if len(req.CustomFields) > 0 {
		if asset.CustomFields == nil {
			asset.CustomFields = make(map[string]string)
		}
		for k, v := range req.CustomFields {
			asset.CustomFields[k] = v
		}
	}

	if len(req.ExternalIDs) > 0 {
		if asset.ExternalIDs == nil {
			asset.ExternalIDs = make(map[string]string)
		}
		for k, v := range req.ExternalIDs {
			asset.ExternalIDs[k] = v
		}
	}

	asset.UpdatedBy = req.UpdatedBy
	asset.UpdatedAt = time.Now().UTC()
}

// Bulk operation implementations

func (uc *AssetUseCase) performBulkDelete(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	response := &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}

	err := uc.assetRepo.BulkDelete(ctx, req.TenantID, req.AssetIDs)
	if err != nil {
		response.FailureCount = len(req.AssetIDs)
		for _, assetID := range req.AssetIDs {
			response.Errors = append(response.Errors, BulkOperationError{
				AssetID: assetID,
				Error:   err.Error(),
				Code:    "BULK_DELETE_FAILED",
			})
		}
	} else {
		response.SuccessCount = len(req.AssetIDs)
	}

	return response
}

func (uc *AssetUseCase) performBulkStatusUpdate(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	// Implementation would update status for multiple assets
	return &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}
}

func (uc *AssetUseCase) performBulkCriticalityUpdate(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	// Implementation would update criticality for multiple assets
	return &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}
}

func (uc *AssetUseCase) performBulkTagAdd(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	// Implementation would add tags to multiple assets
	return &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}
}

func (uc *AssetUseCase) performBulkTagRemove(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	// Implementation would remove tags from multiple assets
	return &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}
}

func (uc *AssetUseCase) performBulkScanningUpdate(ctx context.Context, req *AssetBulkOperationRequest) *AssetBulkOperationResponse {
	// Implementation would update scanning settings for multiple assets
	return &AssetBulkOperationResponse{
		ProcessedAt: time.Now().UTC(),
		Errors:      []BulkOperationError{},
	}
}

// Utility functions

func isValidIPAddress(ip string) bool {
	// Basic IP validation - could be enhanced
	return ip != "" && len(ip) >= 7 && len(ip) <= 39
}
