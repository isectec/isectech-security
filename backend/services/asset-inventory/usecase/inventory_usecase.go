// iSECTECH Asset Inventory - Inventory Use Case
// Production-grade inventory management and reporting
// Copyright (c) 2024 iSECTECH. All rights reserved.

package usecase

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
	"github.com/isectech/backend/services/asset-inventory/domain/repository"
	"github.com/isectech/backend/services/asset-inventory/domain/service"
)

// InventoryUseCase handles inventory management operations
type InventoryUseCase struct {
	assetRepo        repository.AssetRepository
	discoveryService *service.AssetDiscoveryService
	logger           *logrus.Logger
}

// InventorySummaryRequest represents a request for inventory summary
type InventorySummaryRequest struct {
	TenantID     uuid.UUID              `json:"tenant_id" validate:"required"`
	TimeRange    *TimeRange             `json:"time_range,omitempty"`
	GroupBy      []string               `json:"group_by,omitempty"`
	Filter       repository.AssetFilter `json:"filter,omitempty"`
	IncludeEmpty bool                   `json:"include_empty"`
}

// InventorySummaryResponse represents inventory summary data
type InventorySummaryResponse struct {
	Summary         *repository.AssetCounts     `json:"summary"`
	Breakdown       map[string]map[string]int64 `json:"breakdown"`
	Trends          map[string][]StatisticPoint `json:"trends,omitempty"`
	HealthScore     float64                     `json:"health_score"`
	Recommendations []InventoryRecommendation   `json:"recommendations"`
	GeneratedAt     time.Time                   `json:"generated_at"`
	Coverage        InventoryCoverage           `json:"coverage"`
}

// InventoryRecommendation represents an inventory management recommendation
type InventoryRecommendation struct {
	Type        string    `json:"type"`
	Priority    string    `json:"priority"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Impact      string    `json:"impact"`
	Action      string    `json:"action"`
	AssetCount  int       `json:"asset_count,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// InventoryCoverage represents inventory coverage metrics
type InventoryCoverage struct {
	TotalExpected   int           `json:"total_expected"`
	TotalDiscovered int           `json:"total_discovered"`
	CoveragePercent float64       `json:"coverage_percent"`
	LastScanAge     time.Duration `json:"last_scan_age"`
	StaleAssetCount int           `json:"stale_asset_count"`
	OrphanedAssets  int           `json:"orphaned_assets"`
}

// InventoryReportRequest represents a request for inventory report
type InventoryReportRequest struct {
	TenantID       uuid.UUID              `json:"tenant_id" validate:"required"`
	ReportType     string                 `json:"report_type" validate:"required"`
	Format         string                 `json:"format" validate:"required"` // csv, json, xlsx
	Filter         repository.AssetFilter `json:"filter,omitempty"`
	Columns        []string               `json:"columns,omitempty"`
	GroupBy        []string               `json:"group_by,omitempty"`
	SortBy         string                 `json:"sort_by,omitempty"`
	IncludeDetails bool                   `json:"include_details"`
	Template       string                 `json:"template,omitempty"`
}

// InventoryReportResponse represents the response from report generation
type InventoryReportResponse struct {
	ReportID    uuid.UUID `json:"report_id"`
	ReportType  string    `json:"report_type"`
	Format      string    `json:"format"`
	Status      string    `json:"status"`
	DownloadURL string    `json:"download_url,omitempty"`
	FileSize    int64     `json:"file_size,omitempty"`
	RecordCount int       `json:"record_count"`
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// InventoryImportRequest represents a request to import asset data
type InventoryImportRequest struct {
	TenantID   uuid.UUID         `json:"tenant_id" validate:"required"`
	Source     string            `json:"source" validate:"required"`
	Format     string            `json:"format" validate:"required"` // csv, json, xlsx
	Data       io.Reader         `json:"-"`
	Mapping    map[string]string `json:"mapping,omitempty"`
	Options    ImportOptions     `json:"options"`
	ImportedBy string            `json:"imported_by,omitempty"`
}

// ImportOptions controls import behavior
type ImportOptions struct {
	SkipDuplicates bool `json:"skip_duplicates"`
	UpdateExisting bool `json:"update_existing"`
	AutoClassify   bool `json:"auto_classify"`
	ValidateOnly   bool `json:"validate_only"`
	BatchSize      int  `json:"batch_size"`
	MaxErrors      int  `json:"max_errors"`
}

// InventoryImportResponse represents the response from import operation
type InventoryImportResponse struct {
	ImportID      uuid.UUID       `json:"import_id"`
	Status        string          `json:"status"`
	TotalRecords  int             `json:"total_records"`
	ValidRecords  int             `json:"valid_records"`
	ErrorRecords  int             `json:"error_records"`
	CreatedAssets int             `json:"created_assets"`
	UpdatedAssets int             `json:"updated_assets"`
	SkippedAssets int             `json:"skipped_assets"`
	Errors        []ImportError   `json:"errors,omitempty"`
	Warnings      []ImportWarning `json:"warnings,omitempty"`
	ProcessedAt   time.Time       `json:"processed_at"`
}

// ImportError represents an error during import
type ImportError struct {
	Row   int    `json:"row"`
	Field string `json:"field,omitempty"`
	Value string `json:"value,omitempty"`
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// ImportWarning represents a warning during import
type ImportWarning struct {
	Row     int    `json:"row"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Action  string `json:"action,omitempty"`
}

// ComplianceReportRequest represents a request for compliance report
type ComplianceReportRequest struct {
	TenantID    uuid.UUID              `json:"tenant_id" validate:"required"`
	Framework   string                 `json:"framework" validate:"required"`
	Filter      repository.AssetFilter `json:"filter,omitempty"`
	IncludeGaps bool                   `json:"include_gaps"`
	DetailLevel string                 `json:"detail_level"` // summary, detailed, full
}

// ComplianceReportResponse represents compliance status
type ComplianceReportResponse struct {
	Framework       string                     `json:"framework"`
	TotalAssets     int                        `json:"total_assets"`
	CompliantAssets int                        `json:"compliant_assets"`
	ComplianceRate  float64                    `json:"compliance_rate"`
	Controls        []ComplianceControlStatus  `json:"controls"`
	Gaps            []ComplianceGap            `json:"gaps,omitempty"`
	Recommendations []ComplianceRecommendation `json:"recommendations"`
	GeneratedAt     time.Time                  `json:"generated_at"`
}

// ComplianceControlStatus represents the status of a compliance control
type ComplianceControlStatus struct {
	ControlID      string  `json:"control_id"`
	ControlName    string  `json:"control_name"`
	Required       bool    `json:"required"`
	Implemented    int     `json:"implemented"`
	Total          int     `json:"total"`
	ComplianceRate float64 `json:"compliance_rate"`
	Status         string  `json:"status"` // compliant, partial, non_compliant
}

// ComplianceGap represents a compliance gap
type ComplianceGap struct {
	ControlID   string    `json:"control_id"`
	ControlName string    `json:"control_name"`
	AssetID     uuid.UUID `json:"asset_id"`
	AssetName   string    `json:"asset_name"`
	GapType     string    `json:"gap_type"`
	Description string    `json:"description"`
	Risk        string    `json:"risk"`
	Remediation string    `json:"remediation"`
}

// ComplianceRecommendation represents a compliance recommendation
type ComplianceRecommendation struct {
	Priority    string `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`
	Timeline    string `json:"timeline"`
}

// NewInventoryUseCase creates a new inventory use case
func NewInventoryUseCase(
	assetRepo repository.AssetRepository,
	discoveryService *service.AssetDiscoveryService,
	logger *logrus.Logger,
) *InventoryUseCase {
	return &InventoryUseCase{
		assetRepo:        assetRepo,
		discoveryService: discoveryService,
		logger:           logger,
	}
}

// GetInventorySummary generates comprehensive inventory summary
func (uc *InventoryUseCase) GetInventorySummary(ctx context.Context, req *InventorySummaryRequest) (*InventorySummaryResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "get_inventory_summary",
		"tenant_id": req.TenantID,
		"group_by":  req.GroupBy,
	})

	logger.Info("Generating inventory summary")

	response := &InventorySummaryResponse{
		GeneratedAt: time.Now().UTC(),
		Breakdown:   make(map[string]map[string]int64),
	}

	// Get basic asset counts
	summary, err := uc.assetRepo.GetAssetCounts(ctx, req.TenantID)
	if err != nil {
		logger.WithError(err).Error("Failed to get asset summary")
		return nil, fmt.Errorf("failed to get asset summary: %w", err)
	}
	response.Summary = summary

	// Generate breakdowns by requested groupings
	for _, groupBy := range req.GroupBy {
		switch groupBy {
		case "type":
			if counts, err := uc.assetRepo.GetAssetCountsByType(ctx, req.TenantID); err == nil {
				typeBreakdown := make(map[string]int64)
				for assetType, count := range counts {
					typeBreakdown[string(assetType)] = count
				}
				response.Breakdown["type"] = typeBreakdown
			}
		case "criticality":
			if counts, err := uc.assetRepo.GetAssetCountsByCriticality(ctx, req.TenantID); err == nil {
				criticalityBreakdown := make(map[string]int64)
				for criticality, count := range counts {
					criticalityBreakdown[string(criticality)] = count
				}
				response.Breakdown["criticality"] = criticalityBreakdown
			}
		case "status":
			if counts, err := uc.assetRepo.GetAssetCountsByStatus(ctx, req.TenantID); err == nil {
				statusBreakdown := make(map[string]int64)
				for status, count := range counts {
					statusBreakdown[string(status)] = count
				}
				response.Breakdown["status"] = statusBreakdown
			}
		case "network":
			if distribution, err := uc.assetRepo.GetNetworkSegmentDistribution(ctx, req.TenantID); err == nil {
				response.Breakdown["network"] = distribution
			}
		}
	}

	// Calculate health score
	response.HealthScore = uc.calculateInventoryHealthScore(summary)

	// Generate coverage metrics
	response.Coverage = uc.calculateInventoryCoverage(ctx, req.TenantID, summary)

	// Generate recommendations
	response.Recommendations = uc.generateInventoryRecommendations(summary, response.Coverage)

	logger.WithFields(logrus.Fields{
		"total_assets":    summary.Total,
		"health_score":    response.HealthScore,
		"recommendations": len(response.Recommendations),
	}).Info("Inventory summary generated")

	return response, nil
}

// GenerateInventoryReport creates detailed inventory reports
func (uc *InventoryUseCase) GenerateInventoryReport(ctx context.Context, req *InventoryReportRequest) (*InventoryReportResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":   "generate_inventory_report",
		"tenant_id":   req.TenantID,
		"report_type": req.ReportType,
		"format":      req.Format,
	})

	logger.Info("Generating inventory report")

	// Generate unique report ID
	reportID := uuid.New()

	// Get assets based on filter
	assets, err := uc.assetRepo.List(ctx, req.TenantID, req.Filter)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve assets for report")
		return nil, fmt.Errorf("failed to retrieve assets: %w", err)
	}

	// Generate report content based on format
	var reportData []byte
	var fileSize int64

	switch strings.ToLower(req.Format) {
	case "csv":
		reportData, err = uc.generateCSVReport(assets, req)
	case "json":
		reportData, err = uc.generateJSONReport(assets, req)
	case "xlsx":
		// Would implement Excel generation
		return nil, fmt.Errorf("XLSX format not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported format: %s", req.Format)
	}

	if err != nil {
		logger.WithError(err).Error("Failed to generate report data")
		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	fileSize = int64(len(reportData))

	// In a real implementation, you would save the report to storage
	// and provide a download URL
	downloadURL := fmt.Sprintf("/api/v1/reports/%s/download", reportID)

	response := &InventoryReportResponse{
		ReportID:    reportID,
		ReportType:  req.ReportType,
		Format:      req.Format,
		Status:      "completed",
		DownloadURL: downloadURL,
		FileSize:    fileSize,
		RecordCount: len(assets),
		GeneratedAt: time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(24 * time.Hour),
	}

	logger.WithFields(logrus.Fields{
		"report_id":    reportID,
		"record_count": len(assets),
		"file_size":    fileSize,
	}).Info("Inventory report generated")

	return response, nil
}

// ImportAssets imports asset data from external sources
func (uc *InventoryUseCase) ImportAssets(ctx context.Context, req *InventoryImportRequest) (*InventoryImportResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "import_assets",
		"tenant_id": req.TenantID,
		"source":    req.Source,
		"format":    req.Format,
	})

	logger.Info("Starting asset import")

	// Generate unique import ID
	importID := uuid.New()

	response := &InventoryImportResponse{
		ImportID:    importID,
		Status:      "processing",
		Errors:      []ImportError{},
		Warnings:    []ImportWarning{},
		ProcessedAt: time.Now().UTC(),
	}

	// Parse input data based on format
	var records []map[string]interface{}
	var err error

	switch strings.ToLower(req.Format) {
	case "csv":
		records, err = uc.parseCSVData(req.Data)
	case "json":
		records, err = uc.parseJSONData(req.Data)
	case "xlsx":
		// Would implement Excel parsing
		return nil, fmt.Errorf("XLSX format not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported format: %s", req.Format)
	}

	if err != nil {
		logger.WithError(err).Error("Failed to parse import data")
		return nil, fmt.Errorf("failed to parse data: %w", err)
	}

	response.TotalRecords = len(records)

	// Process records
	for i, record := range records {
		if req.Options.MaxErrors > 0 && len(response.Errors) >= req.Options.MaxErrors {
			logger.Warn("Maximum error limit reached, stopping import")
			break
		}

		asset, err := uc.convertRecordToAsset(record, req, i+1)
		if err != nil {
			response.Errors = append(response.Errors, ImportError{
				Row:   i + 1,
				Error: err.Error(),
				Code:  "CONVERSION_FAILED",
			})
			response.ErrorRecords++
			continue
		}

		response.ValidRecords++

		// Skip validation-only mode
		if req.Options.ValidateOnly {
			continue
		}

		// Check for duplicates
		if req.Options.SkipDuplicates {
			duplicates, err := uc.assetRepo.FindPotentialDuplicates(ctx, req.TenantID, asset)
			if err == nil && len(duplicates) > 0 {
				response.SkippedAssets++
				response.Warnings = append(response.Warnings, ImportWarning{
					Row:     i + 1,
					Message: "Potential duplicate found, skipping",
					Action:  "skipped",
				})
				continue
			}
		}

		// Create or update asset
		if req.Options.UpdateExisting {
			// Try to find existing asset
			existing, err := uc.findExistingAsset(ctx, req.TenantID, asset)
			if err == nil && existing != nil {
				// Update existing asset
				uc.updateAssetFromImport(existing, asset)
				if err := uc.assetRepo.Update(ctx, existing); err != nil {
					response.Errors = append(response.Errors, ImportError{
						Row:   i + 1,
						Error: err.Error(),
						Code:  "UPDATE_FAILED",
					})
					response.ErrorRecords++
				} else {
					response.UpdatedAssets++
				}
				continue
			}
		}

		// Create new asset
		if err := uc.assetRepo.Create(ctx, asset); err != nil {
			response.Errors = append(response.Errors, ImportError{
				Row:   i + 1,
				Error: err.Error(),
				Code:  "CREATE_FAILED",
			})
			response.ErrorRecords++
		} else {
			response.CreatedAssets++
		}
	}

	// Set final status
	if response.ErrorRecords == 0 {
		response.Status = "completed"
	} else if response.ValidRecords > 0 {
		response.Status = "completed_with_errors"
	} else {
		response.Status = "failed"
	}

	logger.WithFields(logrus.Fields{
		"import_id":      importID,
		"total_records":  response.TotalRecords,
		"valid_records":  response.ValidRecords,
		"created_assets": response.CreatedAssets,
		"updated_assets": response.UpdatedAssets,
		"error_records":  response.ErrorRecords,
		"status":         response.Status,
	}).Info("Asset import completed")

	return response, nil
}

// GetComplianceReport generates compliance status reports
func (uc *InventoryUseCase) GetComplianceReport(ctx context.Context, req *ComplianceReportRequest) (*ComplianceReportResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "get_compliance_report",
		"tenant_id": req.TenantID,
		"framework": req.Framework,
	})

	logger.Info("Generating compliance report")

	// Get assets that should be compliant with the framework
	assets, err := uc.assetRepo.GetComplianceAssets(ctx, req.TenantID, req.Framework)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve compliance assets")
		return nil, fmt.Errorf("failed to retrieve assets: %w", err)
	}

	response := &ComplianceReportResponse{
		Framework:       req.Framework,
		TotalAssets:     len(assets),
		Controls:        []ComplianceControlStatus{},
		Gaps:            []ComplianceGap{},
		Recommendations: []ComplianceRecommendation{},
		GeneratedAt:     time.Now().UTC(),
	}

	// Calculate compliance metrics
	compliantCount := 0
	for _, asset := range assets {
		if uc.isAssetCompliant(asset, req.Framework) {
			compliantCount++
		}
	}

	response.CompliantAssets = compliantCount
	if response.TotalAssets > 0 {
		response.ComplianceRate = float64(compliantCount) / float64(response.TotalAssets) * 100
	}

	// Generate compliance controls status
	response.Controls = uc.generateComplianceControls(assets, req.Framework)

	// Generate compliance gaps if requested
	if req.IncludeGaps {
		response.Gaps = uc.generateComplianceGaps(assets, req.Framework)
	}

	// Generate compliance recommendations
	response.Recommendations = uc.generateComplianceRecommendations(response.Controls, response.ComplianceRate)

	logger.WithFields(logrus.Fields{
		"total_assets":     response.TotalAssets,
		"compliant_assets": response.CompliantAssets,
		"compliance_rate":  response.ComplianceRate,
		"gaps_count":       len(response.Gaps),
	}).Info("Compliance report generated")

	return response, nil
}

// Private helper methods

func (uc *InventoryUseCase) calculateInventoryHealthScore(summary *repository.AssetCounts) float64 {
	if summary.Total == 0 {
		return 0.0
	}

	score := 100.0

	// Deduct points for stale assets
	if summary.StaleAssets > 0 {
		stalePercent := float64(summary.StaleAssets) / float64(summary.Total) * 100
		score -= stalePercent * 0.5 // 0.5 points per percent of stale assets
	}

	// Deduct points for unowned assets
	if summary.UnownedAssets > 0 {
		unownedPercent := float64(summary.UnownedAssets) / float64(summary.Total) * 100
		score -= unownedPercent * 0.3 // 0.3 points per percent of unowned assets
	}

	// Deduct points for unclassified assets
	if summary.UnclassifiedAssets > 0 {
		unclassifiedPercent := float64(summary.UnclassifiedAssets) / float64(summary.Total) * 100
		score -= unclassifiedPercent * 0.2 // 0.2 points per percent of unclassified assets
	}

	// Bonus points for scanning enabled
	if summary.ScanningEnabled > 0 {
		scanningPercent := float64(summary.ScanningEnabled) / float64(summary.Total) * 100
		score += scanningPercent * 0.1 // 0.1 bonus points per percent with scanning enabled
	}

	// Ensure score doesn't go below 0 or above 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

func (uc *InventoryUseCase) calculateInventoryCoverage(ctx context.Context, tenantID uuid.UUID, summary *repository.AssetCounts) InventoryCoverage {
	// This would involve more complex calculations based on expected vs discovered assets
	// For now, provide basic metrics

	staleThreshold := 7 * 24 * time.Hour // 7 days
	staleAssets, _ := uc.assetRepo.FindStaleAssets(ctx, tenantID, staleThreshold)

	return InventoryCoverage{
		TotalExpected:   int(summary.Total), // In reality, this would be from a baseline
		TotalDiscovered: int(summary.Active),
		CoveragePercent: 85.0,      // This would be calculated based on expected vs discovered
		LastScanAge:     time.Hour, // This would be from actual scan data
		StaleAssetCount: len(staleAssets),
		OrphanedAssets:  int(summary.UnownedAssets),
	}
}

func (uc *InventoryUseCase) generateInventoryRecommendations(summary *repository.AssetCounts, coverage InventoryCoverage) []InventoryRecommendation {
	recommendations := []InventoryRecommendation{}

	// Stale assets recommendation
	if summary.StaleAssets > 0 {
		recommendations = append(recommendations, InventoryRecommendation{
			Type:        "cleanup",
			Priority:    "medium",
			Title:       "Address Stale Assets",
			Description: fmt.Sprintf("Found %d assets that haven't been seen recently", summary.StaleAssets),
			Impact:      "Improves inventory accuracy and reduces security blind spots",
			Action:      "Review and update asset discovery coverage or remove decommissioned assets",
			AssetCount:  int(summary.StaleAssets),
			CreatedAt:   time.Now().UTC(),
		})
	}

	// Unowned assets recommendation
	if summary.UnownedAssets > 0 {
		recommendations = append(recommendations, InventoryRecommendation{
			Type:        "governance",
			Priority:    "high",
			Title:       "Assign Asset Owners",
			Description: fmt.Sprintf("Found %d assets without assigned owners", summary.UnownedAssets),
			Impact:      "Improves accountability and incident response capabilities",
			Action:      "Identify and assign owners for all critical and high-value assets",
			AssetCount:  int(summary.UnownedAssets),
			CreatedAt:   time.Now().UTC(),
		})
	}

	// Scanning recommendation
	scanningRate := float64(summary.ScanningEnabled) / float64(summary.Total) * 100
	if scanningRate < 80.0 {
		recommendations = append(recommendations, InventoryRecommendation{
			Type:        "security",
			Priority:    "high",
			Title:       "Enable Vulnerability Scanning",
			Description: fmt.Sprintf("Only %.1f%% of assets have vulnerability scanning enabled", scanningRate),
			Impact:      "Improves security posture and vulnerability management coverage",
			Action:      "Enable scanning for critical and high-value assets",
			AssetCount:  int(summary.Total - summary.ScanningEnabled),
			CreatedAt:   time.Now().UTC(),
		})
	}

	// Coverage recommendation
	if coverage.CoveragePercent < 90.0 {
		recommendations = append(recommendations, InventoryRecommendation{
			Type:        "discovery",
			Priority:    "medium",
			Title:       "Improve Discovery Coverage",
			Description: fmt.Sprintf("Asset discovery coverage is %.1f%%", coverage.CoveragePercent),
			Impact:      "Reduces security blind spots and improves asset visibility",
			Action:      "Review discovery configurations and network coverage",
			CreatedAt:   time.Now().UTC(),
		})
	}

	return recommendations
}

func (uc *InventoryUseCase) generateCSVReport(assets []*entity.Asset, req *InventoryReportRequest) ([]byte, error) {
	var buffer strings.Builder
	writer := csv.NewWriter(&buffer)

	// Default columns if none specified
	columns := req.Columns
	if len(columns) == 0 {
		columns = []string{"id", "name", "type", "criticality", "status", "owner", "last_seen"}
	}

	// Write header
	if err := writer.Write(columns); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, asset := range assets {
		row := make([]string, len(columns))
		for i, column := range columns {
			row[i] = uc.getAssetFieldValue(asset, column)
		}
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return []byte(buffer.String()), nil
}

func (uc *InventoryUseCase) generateJSONReport(assets []*entity.Asset, req *InventoryReportRequest) ([]byte, error) {
	// Create a simplified view if specific columns are requested
	if len(req.Columns) > 0 {
		simplified := make([]map[string]interface{}, len(assets))
		for i, asset := range assets {
			simplified[i] = make(map[string]interface{})
			for _, column := range req.Columns {
				simplified[i][column] = uc.getAssetFieldValue(asset, column)
			}
		}
		return json.MarshalIndent(simplified, "", "  ")
	}

	// Full asset data
	return json.MarshalIndent(assets, "", "  ")
}

func (uc *InventoryUseCase) getAssetFieldValue(asset *entity.Asset, field string) string {
	switch field {
	case "id":
		return asset.ID.String()
	case "name":
		return asset.Name
	case "type":
		return string(asset.AssetType)
	case "criticality":
		return string(asset.Criticality)
	case "status":
		return string(asset.Status)
	case "owner":
		return asset.Owner
	case "last_seen":
		return asset.LastSeen.Format(time.RFC3339)
	case "network_segment":
		return asset.NetworkSegment
	case "business_function":
		return asset.BusinessFunction
	case "os_name":
		return asset.OperatingSystem.Name
	case "os_version":
		return asset.OperatingSystem.Version
	default:
		return ""
	}
}

func (uc *InventoryUseCase) parseCSVData(data io.Reader) ([]map[string]interface{}, error) {
	reader := csv.NewReader(data)

	// Read header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV header: %w", err)
	}

	var records []map[string]interface{}

	// Read data rows
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV row: %w", err)
		}

		record := make(map[string]interface{})
		for i, value := range row {
			if i < len(header) {
				record[header[i]] = value
			}
		}
		records = append(records, record)
	}

	return records, nil
}

func (uc *InventoryUseCase) parseJSONData(data io.Reader) ([]map[string]interface{}, error) {
	var records []map[string]interface{}

	decoder := json.NewDecoder(data)
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("failed to parse JSON data: %w", err)
	}

	return records, nil
}

func (uc *InventoryUseCase) convertRecordToAsset(record map[string]interface{}, req *InventoryImportRequest, row int) (*entity.Asset, error) {
	asset := &entity.Asset{
		ID:              uuid.New(),
		TenantID:        req.TenantID,
		Status:          entity.AssetStatusActive,
		DiscoveryMethod: "import",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		FirstDiscovered: time.Now().UTC(),
		LastSeen:        time.Now().UTC(),
		Tags:            []entity.AssetTag{},
		CustomFields:    make(map[string]string),
		ExternalIDs:     make(map[string]string),
	}

	// Map fields based on mapping configuration
	for sourceField, targetField := range req.Mapping {
		if value, exists := record[sourceField]; exists {
			if err := uc.setAssetField(asset, targetField, value); err != nil {
				return nil, fmt.Errorf("failed to set field %s: %w", targetField, err)
			}
		}
	}

	// Validate required fields
	if asset.Name == "" {
		return nil, fmt.Errorf("asset name is required")
	}

	if asset.AssetType == "" {
		asset.AssetType = entity.AssetTypeOther
	}

	if asset.Criticality == "" {
		asset.Criticality = entity.CriticalityMedium
	}

	return asset, nil
}

func (uc *InventoryUseCase) setAssetField(asset *entity.Asset, field string, value interface{}) error {
	strValue := fmt.Sprintf("%v", value)

	switch field {
	case "name":
		asset.Name = strValue
	case "asset_type":
		asset.AssetType = entity.AssetType(strValue)
	case "criticality":
		asset.Criticality = entity.CriticalityLevel(strValue)
	case "owner":
		asset.Owner = strValue
	case "business_function":
		asset.BusinessFunction = strValue
	case "network_segment":
		asset.NetworkSegment = strValue
	case "description":
		asset.Description = strValue
	default:
		// Store as custom field
		asset.CustomFields[field] = strValue
	}

	return nil
}

func (uc *InventoryUseCase) findExistingAsset(ctx context.Context, tenantID uuid.UUID, asset *entity.Asset) (*entity.Asset, error) {
	// Try to find by name first
	assets, err := uc.assetRepo.List(ctx, tenantID, repository.AssetFilter{
		Limit:     1,
		SortBy:    "created_at",
		SortOrder: repository.SortOrderDesc,
	})
	if err != nil {
		return nil, err
	}

	for _, existing := range assets {
		if existing.Name == asset.Name {
			return existing, nil
		}
	}

	return nil, nil
}

func (uc *InventoryUseCase) updateAssetFromImport(existing, imported *entity.Asset) {
	// Update selected fields from imported data
	if imported.Description != "" {
		existing.Description = imported.Description
	}
	if imported.Owner != "" {
		existing.Owner = imported.Owner
	}
	if imported.BusinessFunction != "" {
		existing.BusinessFunction = imported.BusinessFunction
	}
	if imported.NetworkSegment != "" {
		existing.NetworkSegment = imported.NetworkSegment
	}

	existing.UpdatedAt = time.Now().UTC()
	existing.LastSeen = time.Now().UTC()
}

func (uc *InventoryUseCase) isAssetCompliant(asset *entity.Asset, framework string) bool {
	// Check if asset has the required compliance framework
	for _, cf := range asset.ComplianceFrameworks {
		if cf == framework {
			return true
		}
	}
	return false
}

func (uc *InventoryUseCase) generateComplianceControls(assets []*entity.Asset, framework string) []ComplianceControlStatus {
	// This would be based on actual compliance control definitions
	// For now, return sample controls
	return []ComplianceControlStatus{
		{
			ControlID:      "CC-01",
			ControlName:    "Asset Inventory",
			Required:       true,
			Implemented:    len(assets),
			Total:          len(assets),
			ComplianceRate: 100.0,
			Status:         "compliant",
		},
		{
			ControlID:      "CC-02",
			ControlName:    "Asset Classification",
			Required:       true,
			Implemented:    len(assets) / 2, // Assume half are properly classified
			Total:          len(assets),
			ComplianceRate: 50.0,
			Status:         "partial",
		},
	}
}

func (uc *InventoryUseCase) generateComplianceGaps(assets []*entity.Asset, framework string) []ComplianceGap {
	gaps := []ComplianceGap{}

	for _, asset := range assets {
		if !uc.isAssetCompliant(asset, framework) {
			gaps = append(gaps, ComplianceGap{
				ControlID:   "CC-01",
				ControlName: "Asset Inventory",
				AssetID:     asset.ID,
				AssetName:   asset.Name,
				GapType:     "missing_framework",
				Description: fmt.Sprintf("Asset not tagged with %s framework", framework),
				Risk:        "medium",
				Remediation: "Add compliance framework tag to asset",
			})
		}
	}

	return gaps
}

func (uc *InventoryUseCase) generateComplianceRecommendations(controls []ComplianceControlStatus, overallRate float64) []ComplianceRecommendation {
	recommendations := []ComplianceRecommendation{}

	if overallRate < 90.0 {
		recommendations = append(recommendations, ComplianceRecommendation{
			Priority:    "high",
			Title:       "Improve Overall Compliance Rate",
			Description: fmt.Sprintf("Current compliance rate is %.1f%%, target is 90%%", overallRate),
			Impact:      "Reduces regulatory risk and improves security posture",
			Effort:      "medium",
			Timeline:    "30 days",
		})
	}

	for _, control := range controls {
		if control.ComplianceRate < 80.0 {
			recommendations = append(recommendations, ComplianceRecommendation{
				Priority:    "medium",
				Title:       fmt.Sprintf("Address %s Control Gaps", control.ControlName),
				Description: fmt.Sprintf("Control %s has %.1f%% compliance rate", control.ControlID, control.ComplianceRate),
				Impact:      "Improves specific control compliance",
				Effort:      "low",
				Timeline:    "14 days",
			})
		}
	}

	return recommendations
}
