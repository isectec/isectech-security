package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"asset-discovery/domain/entity"
	"asset-discovery/domain/repository"
	"asset-discovery/domain/service"
	"asset-discovery/usecase"
)

// AssetDiscoveryHTTPServer implements the HTTP REST API for Asset Discovery
type AssetDiscoveryHTTPServer struct {
	router           *gin.Engine
	assetDiscoveryUC *usecase.AssetDiscoveryUseCase
	assetRepo        repository.AssetRepository
	logger           *zap.Logger
	port             string
}

// NewAssetDiscoveryHTTPServer creates a new HTTP server
func NewAssetDiscoveryHTTPServer(
	assetDiscoveryUC *usecase.AssetDiscoveryUseCase,
	assetRepo repository.AssetRepository,
	logger *zap.Logger,
	port string,
) *AssetDiscoveryHTTPServer {
	server := &AssetDiscoveryHTTPServer{
		assetDiscoveryUC: assetDiscoveryUC,
		assetRepo:        assetRepo,
		logger:           logger,
		port:             port,
	}

	server.setupRoutes()
	return server
}

// setupRoutes configures all HTTP routes
func (s *AssetDiscoveryHTTPServer) setupRoutes() {
	s.router = gin.New()

	// Middleware
	s.router.Use(gin.Logger())
	s.router.Use(gin.Recovery())
	s.router.Use(s.corsMiddleware())
	s.router.Use(s.loggingMiddleware())

	// Health check
	s.router.GET("/health", s.healthCheck)

	// API v1 routes
	v1 := s.router.Group("/api/v1")
	{
		// Discovery endpoints
		discovery := v1.Group("/discovery")
		{
			discovery.POST("/start", s.startDiscovery)
			discovery.GET("/status/:requestId", s.getDiscoveryStatus)
			discovery.DELETE("/cancel/:requestId", s.cancelDiscovery)
		}

		// Asset endpoints
		assets := v1.Group("/assets")
		{
			assets.GET("", s.listAssets)
			assets.POST("", s.createAsset)
			assets.GET("/:id", s.getAsset)
			assets.PUT("/:id", s.updateAsset)
			assets.DELETE("/:id", s.deleteAsset)
			assets.GET("/search", s.searchAssets)
			assets.GET("/aggregation", s.getAssetAggregation)
			assets.GET("/topology", s.getNetworkTopology)
		}

		// Tenant-specific routes
		tenants := v1.Group("/tenants/:tenantId")
		{
			tenantAssets := tenants.Group("/assets")
			{
				tenantAssets.GET("", s.listTenantAssets)
				tenantAssets.GET("/search", s.searchTenantAssets)
				tenantAssets.GET("/aggregation", s.getTenantAssetAggregation)
				tenantAssets.GET("/topology", s.getTenantNetworkTopology)
			}
		}
	}
}

// HTTP Handlers

// healthCheck returns the health status of the service
func (s *AssetDiscoveryHTTPServer) healthCheck(c *gin.Context) {
	ctx := c.Request.Context()

	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "asset-discovery",
	}

	// Check repository health
	if err := s.assetRepo.HealthCheck(ctx); err != nil {
		health["status"] = "unhealthy"
		health["repository_error"] = err.Error()
		c.JSON(http.StatusServiceUnavailable, health)
		return
	}

	health["repository"] = "ok"
	c.JSON(http.StatusOK, health)
}

// startDiscovery initiates a new asset discovery operation
func (s *AssetDiscoveryHTTPServer) startDiscovery(c *gin.Context) {
	var req DiscoveryRequestDTO
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.Error("Invalid discovery request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format", "details": err.Error()})
		return
	}

	// Convert DTO to domain request
	discoveryReq, err := s.convertDiscoveryRequestDTO(&req)
	if err != nil {
		s.logger.Error("Failed to convert discovery request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid discovery request", "details": err.Error()})
		return
	}

	// Execute discovery
	ctx := c.Request.Context()
	result, err := s.assetDiscoveryUC.StartDiscovery(ctx, *discoveryReq)
	if err != nil {
		s.logger.Error("Failed to start discovery", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start discovery", "details": err.Error()})
		return
	}

	// Convert result to DTO
	resultDTO := s.convertDiscoveryResultToDTO(result)
	c.JSON(http.StatusAccepted, resultDTO)
}

// getDiscoveryStatus returns the status of an ongoing discovery operation
func (s *AssetDiscoveryHTTPServer) getDiscoveryStatus(c *gin.Context) {
	requestID, err := uuid.Parse(c.Param("requestId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request ID"})
		return
	}

	ctx := c.Request.Context()
	progress, err := s.assetDiscoveryUC.GetDiscoveryStatus(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to get discovery status", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Discovery not found", "details": err.Error()})
		return
	}

	progressDTO := s.convertScanProgressToDTO(progress)
	c.JSON(http.StatusOK, progressDTO)
}

// cancelDiscovery cancels an ongoing discovery operation
func (s *AssetDiscoveryHTTPServer) cancelDiscovery(c *gin.Context) {
	requestID, err := uuid.Parse(c.Param("requestId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request ID"})
		return
	}

	ctx := c.Request.Context()
	err = s.assetDiscoveryUC.CancelDiscovery(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to cancel discovery", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel discovery", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Discovery cancelled successfully"})
}

// listAssets retrieves a paginated list of assets
func (s *AssetDiscoveryHTTPServer) listAssets(c *gin.Context) {
	// Extract tenant ID from header or query parameter
	tenantID := s.extractTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	// Parse query parameters
	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID

	sort := s.parseAssetSort(c)
	page := s.parsePageRequest(c)

	ctx := c.Request.Context()
	result, err := s.assetRepo.List(ctx, filter, sort, page)
	if err != nil {
		s.logger.Error("Failed to list assets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list assets", "details": err.Error()})
		return
	}

	// Convert to DTOs
	response := AssetListResponseDTO{
		Assets:     s.convertAssetsToDTO(result.Assets),
		Pagination: s.convertPaginationToDTO(&result.Pagination),
	}

	c.JSON(http.StatusOK, response)
}

// listTenantAssets retrieves assets for a specific tenant
func (s *AssetDiscoveryHTTPServer) listTenantAssets(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID

	sort := s.parseAssetSort(c)
	page := s.parsePageRequest(c)

	ctx := c.Request.Context()
	result, err := s.assetRepo.List(ctx, filter, sort, page)
	if err != nil {
		s.logger.Error("Failed to list tenant assets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list assets", "details": err.Error()})
		return
	}

	response := AssetListResponseDTO{
		Assets:     s.convertAssetsToDTO(result.Assets),
		Pagination: s.convertPaginationToDTO(&result.Pagination),
	}

	c.JSON(http.StatusOK, response)
}

// getAsset retrieves a single asset by ID
func (s *AssetDiscoveryHTTPServer) getAsset(c *gin.Context) {
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	tenantID := s.extractTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	ctx := c.Request.Context()
	asset, err := s.assetRepo.GetByTenantAndID(ctx, tenantID, assetID)
	if err != nil {
		s.logger.Error("Failed to get asset", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	assetDTO := s.convertAssetToDTO(asset)
	c.JSON(http.StatusOK, assetDTO)
}

// createAsset creates a new asset
func (s *AssetDiscoveryHTTPServer) createAsset(c *gin.Context) {
	var assetDTO AssetDTO
	if err := c.ShouldBindJSON(&assetDTO); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset format", "details": err.Error()})
		return
	}

	// Convert DTO to domain entity
	asset, err := s.convertAssetDTOToEntity(&assetDTO)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset data", "details": err.Error()})
		return
	}

	// Ensure tenant ID is set
	tenantID := s.extractTenantID(c)
	if tenantID != uuid.Nil {
		asset.TenantID = tenantID
	}

	// Set timestamps
	now := time.Now()
	asset.CreatedAt = now
	asset.UpdatedAt = now
	asset.FirstDiscovered = now
	asset.LastSeen = now
	asset.LastUpdated = now

	ctx := c.Request.Context()
	err = s.assetRepo.Create(ctx, asset)
	if err != nil {
		s.logger.Error("Failed to create asset", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create asset", "details": err.Error()})
		return
	}

	resultDTO := s.convertAssetToDTO(asset)
	c.JSON(http.StatusCreated, resultDTO)
}

// updateAsset updates an existing asset
func (s *AssetDiscoveryHTTPServer) updateAsset(c *gin.Context) {
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	var assetDTO AssetDTO
	if err := c.ShouldBindJSON(&assetDTO); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset format", "details": err.Error()})
		return
	}

	// Convert DTO to domain entity
	asset, err := s.convertAssetDTOToEntity(&assetDTO)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset data", "details": err.Error()})
		return
	}

	// Ensure asset ID matches the URL parameter
	asset.ID = assetID

	// Ensure tenant ID is set
	tenantID := s.extractTenantID(c)
	if tenantID != uuid.Nil {
		asset.TenantID = tenantID
	}

	ctx := c.Request.Context()
	err = s.assetRepo.Update(ctx, asset)
	if err != nil {
		s.logger.Error("Failed to update asset", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset", "details": err.Error()})
		return
	}

	resultDTO := s.convertAssetToDTO(asset)
	c.JSON(http.StatusOK, resultDTO)
}

// deleteAsset deletes an asset
func (s *AssetDiscoveryHTTPServer) deleteAsset(c *gin.Context) {
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}

	ctx := c.Request.Context()
	err = s.assetRepo.SoftDelete(ctx, assetID)
	if err != nil {
		s.logger.Error("Failed to delete asset", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete asset", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Asset deleted successfully"})
}

// searchAssets performs a text search on assets
func (s *AssetDiscoveryHTTPServer) searchAssets(c *gin.Context) {
	tenantID := s.extractTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
		return
	}

	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID
	page := s.parsePageRequest(c)

	ctx := c.Request.Context()
	result, err := s.assetRepo.Search(ctx, tenantID, query, filter, page)
	if err != nil {
		s.logger.Error("Failed to search assets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search assets", "details": err.Error()})
		return
	}

	response := AssetListResponseDTO{
		Assets:     s.convertAssetsToDTO(result.Assets),
		Pagination: s.convertPaginationToDTO(&result.Pagination),
	}

	c.JSON(http.StatusOK, response)
}

// searchTenantAssets performs a search for a specific tenant
func (s *AssetDiscoveryHTTPServer) searchTenantAssets(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	query := c.Query("q")
	if query == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Search query is required"})
		return
	}

	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID
	page := s.parsePageRequest(c)

	ctx := c.Request.Context()
	result, err := s.assetRepo.Search(ctx, tenantID, query, filter, page)
	if err != nil {
		s.logger.Error("Failed to search tenant assets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search assets", "details": err.Error()})
		return
	}

	response := AssetListResponseDTO{
		Assets:     s.convertAssetsToDTO(result.Assets),
		Pagination: s.convertPaginationToDTO(&result.Pagination),
	}

	c.JSON(http.StatusOK, response)
}

// getAssetAggregation returns aggregated asset statistics
func (s *AssetDiscoveryHTTPServer) getAssetAggregation(c *gin.Context) {
	tenantID := s.extractTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID

	ctx := c.Request.Context()
	aggregation, err := s.assetRepo.GetAggregation(ctx, tenantID, filter)
	if err != nil {
		s.logger.Error("Failed to get asset aggregation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get aggregation", "details": err.Error()})
		return
	}

	aggregationDTO := s.convertAssetAggregationToDTO(aggregation)
	c.JSON(http.StatusOK, aggregationDTO)
}

// getTenantAssetAggregation returns aggregated statistics for a specific tenant
func (s *AssetDiscoveryHTTPServer) getTenantAssetAggregation(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	filter := s.parseAssetFilter(c)
	filter.TenantID = &tenantID

	ctx := c.Request.Context()
	aggregation, err := s.assetRepo.GetAggregation(ctx, tenantID, filter)
	if err != nil {
		s.logger.Error("Failed to get tenant asset aggregation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get aggregation", "details": err.Error()})
		return
	}

	aggregationDTO := s.convertAssetAggregationToDTO(aggregation)
	c.JSON(http.StatusOK, aggregationDTO)
}

// getNetworkTopology returns network topology information
func (s *AssetDiscoveryHTTPServer) getNetworkTopology(c *gin.Context) {
	tenantID := s.extractTenantID(c)
	if tenantID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
		return
	}

	ctx := c.Request.Context()
	topology, err := s.assetRepo.GetNetworkTopology(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get network topology", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get topology", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, topology)
}

// getTenantNetworkTopology returns network topology for a specific tenant
func (s *AssetDiscoveryHTTPServer) getTenantNetworkTopology(c *gin.Context) {
	tenantID, err := uuid.Parse(c.Param("tenantId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	ctx := c.Request.Context()
	topology, err := s.assetRepo.GetNetworkTopology(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get tenant network topology", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get topology", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, topology)
}

// Helper methods

// extractTenantID extracts tenant ID from headers or query parameters
func (s *AssetDiscoveryHTTPServer) extractTenantID(c *gin.Context) uuid.UUID {
	// Try header first
	tenantIDStr := c.GetHeader("X-Tenant-ID")
	if tenantIDStr == "" {
		// Try query parameter
		tenantIDStr = c.Query("tenant_id")
	}

	if tenantIDStr == "" {
		return uuid.Nil
	}

	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return uuid.Nil
	}

	return tenantID
}

// parseAssetFilter parses asset filter parameters from query string
func (s *AssetDiscoveryHTTPServer) parseAssetFilter(c *gin.Context) repository.AssetFilter {
	filter := repository.AssetFilter{}

	// Asset types
	if types := c.QueryArray("asset_type"); len(types) > 0 {
		for _, t := range types {
			filter.AssetTypes = append(filter.AssetTypes, entity.AssetType(t))
		}
	}

	// Statuses
	if statuses := c.QueryArray("status"); len(statuses) > 0 {
		for _, s := range statuses {
			filter.Statuses = append(filter.Statuses, entity.AssetStatus(s))
		}
	}

	// Risk levels
	if risks := c.QueryArray("risk_level"); len(risks) > 0 {
		for _, r := range risks {
			filter.RiskLevels = append(filter.RiskLevels, entity.AssetRiskLevel(r))
		}
	}

	// Environments
	filter.Environments = c.QueryArray("environment")

	// Tags
	filter.Tags = c.QueryArray("tag")

	// Network zones
	filter.NetworkZones = c.QueryArray("network_zone")

	// IP range
	if ipRange := c.Query("ip_range"); ipRange != "" {
		filter.IPRange = &ipRange
	}

	// Hostname
	if hostname := c.Query("hostname"); hostname != "" {
		filter.Hostname = &hostname
	}

	// Owner
	if owner := c.Query("owner"); owner != "" {
		filter.Owner = &owner
	}

	// Department
	if department := c.Query("department"); department != "" {
		filter.Department = &department
	}

	// Time filters
	if lastSeenAfter := c.Query("last_seen_after"); lastSeenAfter != "" {
		if t, err := time.Parse(time.RFC3339, lastSeenAfter); err == nil {
			filter.LastSeenAfter = &t
		}
	}

	if lastSeenBefore := c.Query("last_seen_before"); lastSeenBefore != "" {
		if t, err := time.Parse(time.RFC3339, lastSeenBefore); err == nil {
			filter.LastSeenBefore = &t
		}
	}

	// Search
	if search := c.Query("search"); search != "" {
		filter.Search = &search
	}

	return filter
}

// parseAssetSort parses sort parameters from query string
func (s *AssetDiscoveryHTTPServer) parseAssetSort(c *gin.Context) []repository.AssetSort {
	var sort []repository.AssetSort

	sortBy := c.Query("sort_by")
	if sortBy == "" {
		// Default sort
		return []repository.AssetSort{{Field: "created_at", Direction: "desc"}}
	}

	sortOrder := c.Query("sort_order")
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Handle multiple sort fields
	fields := strings.Split(sortBy, ",")
	orders := strings.Split(sortOrder, ",")

	for i, field := range fields {
		direction := "asc"
		if i < len(orders) {
			direction = orders[i]
		}

		sort = append(sort, repository.AssetSort{
			Field:     strings.TrimSpace(field),
			Direction: strings.TrimSpace(direction),
		})
	}

	return sort
}

// parsePageRequest parses pagination parameters from query string
func (s *AssetDiscoveryHTTPServer) parsePageRequest(c *gin.Context) repository.PageRequest {
	page := repository.PageRequest{
		Page:     1,
		PageSize: 50,
	}

	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page.Page = p
		}
	}

	if sizeStr := c.Query("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 1000 {
			page.PageSize = s
		}
	}

	return page
}

// Middleware

// corsMiddleware adds CORS headers
func (s *AssetDiscoveryHTTPServer) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin,Content-Type,Authorization,X-Tenant-ID")
		c.Header("Access-Control-Expose-Headers", "Content-Length")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// loggingMiddleware logs HTTP requests
func (s *AssetDiscoveryHTTPServer) loggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log after processing
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		s.logger.Info("HTTP Request",
			zap.String("client_ip", clientIP),
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status_code", statusCode),
			zap.Duration("latency", latency),
		)
	}
}

// Server management methods

// Start starts the HTTP server
func (s *AssetDiscoveryHTTPServer) Start() error {
	s.logger.Info("Starting Asset Discovery HTTP server", zap.String("port", s.port))
	return s.router.Run(":" + s.port)
}

// Shutdown gracefully shuts down the HTTP server
func (s *AssetDiscoveryHTTPServer) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down Asset Discovery HTTP server")
	// Gin doesn't have a built-in graceful shutdown, so we implement a basic one
	// In production, you might want to use http.Server directly for better control
	return nil
}

// GetRouter returns the gin router for testing purposes
func (s *AssetDiscoveryHTTPServer) GetRouter() *gin.Engine {
	return s.router
}

// Conversion methods (simplified implementations)

func (s *AssetDiscoveryHTTPServer) convertDiscoveryRequestDTO(dto *DiscoveryRequestDTO) (*service.DiscoveryRequest, error) {
	tenantID, err := uuid.Parse(dto.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Convert discovery methods
	methods := make([]service.DiscoveryMethod, len(dto.DiscoveryMethods))
	for i, method := range dto.DiscoveryMethods {
		methods[i] = service.DiscoveryMethod(method)
	}

	// Convert scan options
	scanOptions := service.ScanOptions{
		PortRanges:       dto.ScanOptions.PortRanges,
		ServiceDetection: dto.ScanOptions.ServiceDetection,
		VersionDetection: dto.ScanOptions.VersionDetection,
		OSDetection:      dto.ScanOptions.OSDetection,
		DeepInspection:   dto.ScanOptions.DeepInspection,
		MaxConcurrency:   dto.ScanOptions.MaxConcurrency,
		RateLimit:        dto.ScanOptions.RateLimit,
		RetryAttempts:    dto.ScanOptions.RetryAttempts,
	}

	if dto.ScanOptions.Timeout > 0 {
		scanOptions.Timeout = time.Duration(dto.ScanOptions.Timeout) * time.Second
	}

	return &service.DiscoveryRequest{
		TenantID: tenantID,
		TargetScope: service.DiscoveryScope{
			IPRanges:  dto.TargetScope.IPRanges,
			Hostnames: dto.TargetScope.Hostnames,
			Domains:   dto.TargetScope.Domains,
		},
		DiscoveryMethods: methods,
		ScanOptions:      scanOptions,
		Priority:         service.DiscoveryPriority(dto.Priority),
		ScheduleType:     service.ScheduleType(dto.ScheduleType),
		Metadata:         dto.Metadata,
	}, nil
}

func (s *AssetDiscoveryHTTPServer) convertDiscoveryResultToDTO(result *service.DiscoveryResult) *DiscoveryResultDTO {
	return &DiscoveryResultDTO{
		RequestID:      result.RequestID.String(),
		TenantID:       result.TenantID.String(),
		Status:         string(result.Status),
		StartTime:      result.StartTime.Format(time.RFC3339),
		Duration:       int64(result.Duration.Seconds()),
		AssetsFound:    result.AssetsFound,
		AssetsUpdated:  result.AssetsUpdated,
		AssetsNew:      result.AssetsNew,
		TargetsScanned: result.TargetsScanned,
		TargetsTotal:   result.TargetsTotal,
		SuccessRate:    result.SuccessRate,
		Assets:         s.convertAssetsToDTO(result.Assets),
	}
}

func (s *AssetDiscoveryHTTPServer) convertScanProgressToDTO(progress *service.ScanProgress) *ScanProgressDTO {
	return &ScanProgressDTO{
		RequestID:       progress.RequestID.String(),
		Status:          string(progress.Status),
		PercentComplete: progress.PercentComplete,
		CurrentTarget:   progress.CurrentTarget,
		TargetsCompleted: progress.TargetsCompleted,
		TargetsTotal:    progress.TargetsTotal,
		AssetsFound:     progress.AssetsFound,
		ElapsedTime:     int64(progress.ElapsedTime.Seconds()),
	}
}

func (s *AssetDiscoveryHTTPServer) convertAssetsToDTO(assets []*entity.Asset) []*AssetDTO {
	dtos := make([]*AssetDTO, len(assets))
	for i, asset := range assets {
		dtos[i] = s.convertAssetToDTO(asset)
	}
	return dtos
}

func (s *AssetDiscoveryHTTPServer) convertAssetToDTO(asset *entity.Asset) *AssetDTO {
	dto := &AssetDTO{
		ID:              asset.ID.String(),
		TenantID:        asset.TenantID.String(),
		Name:            asset.Name,
		DisplayName:     asset.DisplayName,
		Description:     asset.Description,
		AssetType:       string(asset.AssetType),
		Status:          string(asset.Status),
		RiskLevel:       string(asset.RiskLevel),
		Owner:           asset.Owner,
		Department:      asset.Department,
		BusinessUnit:    asset.BusinessUnit,
		Environment:     asset.Environment,
		Criticality:     asset.Criticality,
		Tags:            asset.Tags,
		Labels:          asset.Labels,
		DiscoveryMethod: asset.DiscoveryMethod,
		DiscoverySource: asset.DiscoverySource,
		FirstDiscovered: asset.FirstDiscovered.Format(time.RFC3339),
		LastSeen:        asset.LastSeen.Format(time.RFC3339),
		LastUpdated:     asset.LastUpdated.Format(time.RFC3339),
		Fingerprint:     asset.Fingerprint,
		Checksum:        asset.Checksum,
		CreatedAt:       asset.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       asset.UpdatedAt.Format(time.RFC3339),
		Version:         asset.Version,
	}

	// Convert network info
	if asset.NetworkInfo != nil {
		dto.NetworkInfo = &NetworkInfoDTO{
			IPAddress:   asset.NetworkInfo.IPAddress,
			IPVersion:   asset.NetworkInfo.IPVersion,
			MACAddress:  asset.NetworkInfo.MACAddress,
			Hostname:    asset.NetworkInfo.Hostname,
			FQDN:        asset.NetworkInfo.FQDN,
			DNSNames:    asset.NetworkInfo.DNSNames,
			NetworkZone: asset.NetworkInfo.NetworkZone,
			VLAN:        asset.NetworkInfo.VLAN,
			Subnet:      asset.NetworkInfo.Subnet,
			Gateway:     asset.NetworkInfo.Gateway,
			PublicIP:    asset.NetworkInfo.PublicIP,
		}

		// Convert ports
		for _, port := range asset.NetworkInfo.OpenPorts {
			dto.NetworkInfo.OpenPorts = append(dto.NetworkInfo.OpenPorts, PortDTO{
				Number:   port.Number,
				Protocol: port.Protocol,
				Service:  port.Service,
				Version:  port.Version,
				Banner:   port.Banner,
				State:    port.State,
			})
		}
	}

	return dto
}

func (s *AssetDiscoveryHTTPServer) convertAssetDTOToEntity(dto *AssetDTO) (*entity.Asset, error) {
	var assetID uuid.UUID
	var err error

	if dto.ID != "" {
		assetID, err = uuid.Parse(dto.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid asset ID: %w", err)
		}
	} else {
		assetID = uuid.New()
	}

	tenantID, err := uuid.Parse(dto.TenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	asset := &entity.Asset{
		ID:              assetID,
		TenantID:        tenantID,
		Name:            dto.Name,
		DisplayName:     dto.DisplayName,
		Description:     dto.Description,
		AssetType:       entity.AssetType(dto.AssetType),
		Status:          entity.AssetStatus(dto.Status),
		RiskLevel:       entity.AssetRiskLevel(dto.RiskLevel),
		Owner:           dto.Owner,
		Department:      dto.Department,
		BusinessUnit:    dto.BusinessUnit,
		Environment:     dto.Environment,
		Criticality:     dto.Criticality,
		Tags:            dto.Tags,
		Labels:          dto.Labels,
		DiscoveryMethod: dto.DiscoveryMethod,
		DiscoverySource: dto.DiscoverySource,
		Fingerprint:     dto.Fingerprint,
		Checksum:        dto.Checksum,
		Version:         dto.Version,
	}

	// Parse timestamps
	if dto.FirstDiscovered != "" {
		if t, err := time.Parse(time.RFC3339, dto.FirstDiscovered); err == nil {
			asset.FirstDiscovered = t
		}
	}
	if dto.LastSeen != "" {
		if t, err := time.Parse(time.RFC3339, dto.LastSeen); err == nil {
			asset.LastSeen = t
		}
	}
	if dto.LastUpdated != "" {
		if t, err := time.Parse(time.RFC3339, dto.LastUpdated); err == nil {
			asset.LastUpdated = t
		}
	}
	if dto.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, dto.CreatedAt); err == nil {
			asset.CreatedAt = t
		}
	}
	if dto.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, dto.UpdatedAt); err == nil {
			asset.UpdatedAt = t
		}
	}

	// Convert network info
	if dto.NetworkInfo != nil {
		networkInfo := &entity.NetworkInfo{
			IPAddress:   dto.NetworkInfo.IPAddress,
			IPVersion:   dto.NetworkInfo.IPVersion,
			MACAddress:  dto.NetworkInfo.MACAddress,
			Hostname:    dto.NetworkInfo.Hostname,
			FQDN:        dto.NetworkInfo.FQDN,
			DNSNames:    dto.NetworkInfo.DNSNames,
			NetworkZone: dto.NetworkInfo.NetworkZone,
			VLAN:        dto.NetworkInfo.VLAN,
			Subnet:      dto.NetworkInfo.Subnet,
			Gateway:     dto.NetworkInfo.Gateway,
			PublicIP:    dto.NetworkInfo.PublicIP,
		}

		// Convert ports
		for _, portDTO := range dto.NetworkInfo.OpenPorts {
			port := entity.Port{
				Number:   portDTO.Number,
				Protocol: portDTO.Protocol,
				Service:  portDTO.Service,
				Version:  portDTO.Version,
				Banner:   portDTO.Banner,
				State:    portDTO.State,
			}
			networkInfo.OpenPorts = append(networkInfo.OpenPorts, port)
		}

		asset.NetworkInfo = networkInfo
	}

	return asset, nil
}

func (s *AssetDiscoveryHTTPServer) convertPaginationToDTO(pagination *repository.PageResponse) *PaginationDTO {
	return &PaginationDTO{
		Page:       pagination.Page,
		PageSize:   pagination.PageSize,
		TotalPages: pagination.TotalPages,
		TotalItems: pagination.TotalItems,
		HasNext:    pagination.HasNext,
		HasPrev:    pagination.HasPrev,
	}
}

func (s *AssetDiscoveryHTTPServer) convertAssetAggregationToDTO(agg *repository.AssetAggregation) *AssetAggregationDTO {
	dto := &AssetAggregationDTO{
		TotalAssets:         agg.TotalAssets,
		AssetsByType:        make(map[string]int64),
		AssetsByStatus:      make(map[string]int64),
		AssetsByRisk:        make(map[string]int64),
		AssetsByEnvironment: agg.AssetsByEnvironment,
	}

	// Convert enum maps to string maps
	for assetType, count := range agg.AssetsByType {
		dto.AssetsByType[string(assetType)] = count
	}
	for status, count := range agg.AssetsByStatus {
		dto.AssetsByStatus[string(status)] = count
	}
	for risk, count := range agg.AssetsByRisk {
		dto.AssetsByRisk[string(risk)] = count
	}

	return dto
}