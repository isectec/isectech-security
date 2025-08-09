package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/durationpb"

	"asset-discovery/domain/entity"
	"asset-discovery/domain/repository"
	"asset-discovery/domain/service"
	pb "asset-discovery/delivery/grpc/pb"
	"asset-discovery/usecase"
)

// AssetDiscoveryServer implements the gRPC AssetDiscoveryService
type AssetDiscoveryServer struct {
	pb.UnimplementedAssetDiscoveryServiceServer
	assetDiscoveryUC *usecase.AssetDiscoveryUseCase
	assetRepo        repository.AssetRepository
	logger           *zap.Logger
}

// NewAssetDiscoveryServer creates a new gRPC server
func NewAssetDiscoveryServer(
	assetDiscoveryUC *usecase.AssetDiscoveryUseCase,
	assetRepo repository.AssetRepository,
	logger *zap.Logger,
) *AssetDiscoveryServer {
	return &AssetDiscoveryServer{
		assetDiscoveryUC: assetDiscoveryUC,
		assetRepo:        assetRepo,
		logger:           logger,
	}
}

// StartDiscovery initiates a new asset discovery operation
func (s *AssetDiscoveryServer) StartDiscovery(ctx context.Context, req *pb.StartDiscoveryRequest) (*pb.StartDiscoveryResponse, error) {
	s.logger.Info("StartDiscovery gRPC request received")

	// Convert protobuf request to domain request
	discoveryReq, err := s.convertDiscoveryRequest(req.Request)
	if err != nil {
		s.logger.Error("Failed to convert discovery request", zap.Error(err))
		return nil, status.Errorf(codes.InvalidArgument, "invalid discovery request: %v", err)
	}

	// Execute discovery
	result, err := s.assetDiscoveryUC.StartDiscovery(ctx, *discoveryReq)
	if err != nil {
		s.logger.Error("Failed to start discovery", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to start discovery: %v", err)
	}

	// Convert result to protobuf
	pbResult, err := s.convertDiscoveryResult(result)
	if err != nil {
		s.logger.Error("Failed to convert discovery result", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to convert result: %v", err)
	}

	return &pb.StartDiscoveryResponse{
		Result: pbResult,
	}, nil
}

// GetDiscoveryStatus returns the status of an ongoing discovery operation
func (s *AssetDiscoveryServer) GetDiscoveryStatus(ctx context.Context, req *pb.GetDiscoveryStatusRequest) (*pb.GetDiscoveryStatusResponse, error) {
	s.logger.Debug("GetDiscoveryStatus gRPC request received", zap.String("request_id", req.RequestId))

	requestID, err := uuid.Parse(req.RequestId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request ID: %v", err)
	}

	progress, err := s.assetDiscoveryUC.GetDiscoveryStatus(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to get discovery status", zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "discovery not found: %v", err)
	}

	pbProgress := s.convertScanProgress(progress)
	return &pb.GetDiscoveryStatusResponse{
		Progress: pbProgress,
	}, nil
}

// CancelDiscovery cancels an ongoing discovery operation
func (s *AssetDiscoveryServer) CancelDiscovery(ctx context.Context, req *pb.CancelDiscoveryRequest) (*pb.CancelDiscoveryResponse, error) {
	s.logger.Info("CancelDiscovery gRPC request received", zap.String("request_id", req.RequestId))

	requestID, err := uuid.Parse(req.RequestId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request ID: %v", err)
	}

	err = s.assetDiscoveryUC.CancelDiscovery(ctx, requestID)
	if err != nil {
		s.logger.Error("Failed to cancel discovery", zap.Error(err))
		return &pb.CancelDiscoveryResponse{
			Success: false,
			Message: fmt.Sprintf("failed to cancel discovery: %v", err),
		}, nil
	}

	return &pb.CancelDiscoveryResponse{
		Success: true,
		Message: "Discovery cancelled successfully",
	}, nil
}

// GetAsset retrieves a single asset by ID
func (s *AssetDiscoveryServer) GetAsset(ctx context.Context, req *pb.GetAssetRequest) (*pb.GetAssetResponse, error) {
	s.logger.Debug("GetAsset gRPC request received", zap.String("asset_id", req.AssetId))

	assetID, err := uuid.Parse(req.AssetId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid asset ID: %v", err)
	}

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	asset, err := s.assetRepo.GetByTenantAndID(ctx, tenantID, assetID)
	if err != nil {
		s.logger.Error("Failed to get asset", zap.Error(err))
		return nil, status.Errorf(codes.NotFound, "asset not found: %v", err)
	}

	pbAsset := s.convertAsset(asset)
	return &pb.GetAssetResponse{
		Asset: pbAsset,
	}, nil
}

// ListAssets retrieves a paginated list of assets
func (s *AssetDiscoveryServer) ListAssets(ctx context.Context, req *pb.ListAssetsRequest) (*pb.ListAssetsResponse, error) {
	s.logger.Debug("ListAssets gRPC request received", zap.String("tenant_id", req.TenantId))

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	// Convert protobuf filter to domain filter
	filter := s.convertAssetFilter(req.Filter)
	filter.TenantID = &tenantID

	// Convert sort options
	sort := s.convertAssetSort(req.Sort)

	// Convert pagination
	page := repository.PageRequest{
		Page:     int(req.Page.Page),
		PageSize: int(req.Page.PageSize),
	}

	// Default page size if not specified
	if page.PageSize == 0 {
		page.PageSize = 50
	}
	if page.Page == 0 {
		page.Page = 1
	}

	result, err := s.assetRepo.List(ctx, filter, sort, page)
	if err != nil {
		s.logger.Error("Failed to list assets", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to list assets: %v", err)
	}

	// Convert assets to protobuf
	pbAssets := make([]*pb.Asset, len(result.Assets))
	for i, asset := range result.Assets {
		pbAssets[i] = s.convertAsset(asset)
	}

	// Convert pagination response
	pbPagination := &pb.PageResponse{
		Page:       int32(result.Pagination.Page),
		PageSize:   int32(result.Pagination.PageSize),
		TotalPages: int32(result.Pagination.TotalPages),
		TotalItems: result.Pagination.TotalItems,
		HasNext:    result.Pagination.HasNext,
		HasPrev:    result.Pagination.HasPrev,
	}

	return &pb.ListAssetsResponse{
		Assets:     pbAssets,
		Pagination: pbPagination,
	}, nil
}

// UpdateAsset updates an existing asset
func (s *AssetDiscoveryServer) UpdateAsset(ctx context.Context, req *pb.UpdateAssetRequest) (*pb.UpdateAssetResponse, error) {
	s.logger.Debug("UpdateAsset gRPC request received", zap.String("asset_id", req.Asset.Id))

	// Convert protobuf asset to domain asset
	asset, err := s.convertPbAsset(req.Asset)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid asset: %v", err)
	}

	err = s.assetRepo.Update(ctx, asset)
	if err != nil {
		s.logger.Error("Failed to update asset", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to update asset: %v", err)
	}

	pbAsset := s.convertAsset(asset)
	return &pb.UpdateAssetResponse{
		Asset: pbAsset,
	}, nil
}

// DeleteAsset deletes an asset
func (s *AssetDiscoveryServer) DeleteAsset(ctx context.Context, req *pb.DeleteAssetRequest) (*pb.DeleteAssetResponse, error) {
	s.logger.Debug("DeleteAsset gRPC request received", zap.String("asset_id", req.AssetId))

	assetID, err := uuid.Parse(req.AssetId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid asset ID: %v", err)
	}

	err = s.assetRepo.SoftDelete(ctx, assetID)
	if err != nil {
		s.logger.Error("Failed to delete asset", zap.Error(err))
		return &pb.DeleteAssetResponse{
			Success: false,
			Message: fmt.Sprintf("failed to delete asset: %v", err),
		}, nil
	}

	return &pb.DeleteAssetResponse{
		Success: true,
		Message: "Asset deleted successfully",
	}, nil
}

// SearchAssets performs a text search on assets
func (s *AssetDiscoveryServer) SearchAssets(ctx context.Context, req *pb.SearchAssetsRequest) (*pb.SearchAssetsResponse, error) {
	s.logger.Debug("SearchAssets gRPC request received", 
		zap.String("tenant_id", req.TenantId), 
		zap.String("query", req.Query))

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	// Convert filter and pagination
	filter := s.convertAssetFilter(req.Filters)
	filter.TenantID = &tenantID
	filter.Search = &req.Query

	page := repository.PageRequest{
		Page:     int(req.Page.Page),
		PageSize: int(req.Page.PageSize),
	}

	if page.PageSize == 0 {
		page.PageSize = 50
	}
	if page.Page == 0 {
		page.Page = 1
	}

	result, err := s.assetRepo.Search(ctx, tenantID, req.Query, filter, page)
	if err != nil {
		s.logger.Error("Failed to search assets", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to search assets: %v", err)
	}

	// Convert results to protobuf
	pbAssets := make([]*pb.Asset, len(result.Assets))
	for i, asset := range result.Assets {
		pbAssets[i] = s.convertAsset(asset)
	}

	pbPagination := &pb.PageResponse{
		Page:       int32(result.Pagination.Page),
		PageSize:   int32(result.Pagination.PageSize),
		TotalPages: int32(result.Pagination.TotalPages),
		TotalItems: result.Pagination.TotalItems,
		HasNext:    result.Pagination.HasNext,
		HasPrev:    result.Pagination.HasPrev,
	}

	return &pb.SearchAssetsResponse{
		Assets:     pbAssets,
		Pagination: pbPagination,
	}, nil
}

// GetAssetsByFilter retrieves assets by filter criteria
func (s *AssetDiscoveryServer) GetAssetsByFilter(ctx context.Context, req *pb.GetAssetsByFilterRequest) (*pb.GetAssetsByFilterResponse, error) {
	s.logger.Debug("GetAssetsByFilter gRPC request received", zap.String("tenant_id", req.TenantId))

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	// Convert filter, sort, and pagination
	filter := s.convertAssetFilter(req.Filter)
	filter.TenantID = &tenantID
	sort := s.convertAssetSort(req.Sort)

	page := repository.PageRequest{
		Page:     int(req.Page.Page),
		PageSize: int(req.Page.PageSize),
	}

	if page.PageSize == 0 {
		page.PageSize = 50
	}
	if page.Page == 0 {
		page.Page = 1
	}

	result, err := s.assetRepo.List(ctx, filter, sort, page)
	if err != nil {
		s.logger.Error("Failed to get assets by filter", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get assets: %v", err)
	}

	// Convert results
	pbAssets := make([]*pb.Asset, len(result.Assets))
	for i, asset := range result.Assets {
		pbAssets[i] = s.convertAsset(asset)
	}

	pbPagination := &pb.PageResponse{
		Page:       int32(result.Pagination.Page),
		PageSize:   int32(result.Pagination.PageSize),
		TotalPages: int32(result.Pagination.TotalPages),
		TotalItems: result.Pagination.TotalItems,
		HasNext:    result.Pagination.HasNext,
		HasPrev:    result.Pagination.HasPrev,
	}

	return &pb.GetAssetsByFilterResponse{
		Assets:     pbAssets,
		Pagination: pbPagination,
	}, nil
}

// GetAssetAggregation returns aggregated asset statistics
func (s *AssetDiscoveryServer) GetAssetAggregation(ctx context.Context, req *pb.GetAssetAggregationRequest) (*pb.GetAssetAggregationResponse, error) {
	s.logger.Debug("GetAssetAggregation gRPC request received", zap.String("tenant_id", req.TenantId))

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	filter := s.convertAssetFilter(req.Filter)
	filter.TenantID = &tenantID

	aggregation, err := s.assetRepo.GetAggregation(ctx, tenantID, filter)
	if err != nil {
		s.logger.Error("Failed to get asset aggregation", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get aggregation: %v", err)
	}

	pbAggregation := s.convertAssetAggregation(aggregation)
	return &pb.GetAssetAggregationResponse{
		Aggregation: pbAggregation,
	}, nil
}

// GetNetworkTopology returns network topology information
func (s *AssetDiscoveryServer) GetNetworkTopology(ctx context.Context, req *pb.GetNetworkTopologyRequest) (*pb.GetNetworkTopologyResponse, error) {
	s.logger.Debug("GetNetworkTopology gRPC request received", zap.String("tenant_id", req.TenantId))

	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tenant ID: %v", err)
	}

	topology, err := s.assetRepo.GetNetworkTopology(ctx, tenantID)
	if err != nil {
		s.logger.Error("Failed to get network topology", zap.Error(err))
		return nil, status.Errorf(codes.Internal, "failed to get topology: %v", err)
	}

	// Convert to string map for protobuf
	pbTopology := make(map[string]string)
	for key, value := range topology {
		pbTopology[key] = fmt.Sprintf("%v", value)
	}

	return &pb.GetNetworkTopologyResponse{
		Topology: pbTopology,
	}, nil
}

// HealthCheck returns the health status of the service
func (s *AssetDiscoveryServer) HealthCheck(ctx context.Context, req *emptypb.Empty) (*pb.HealthCheckResponse, error) {
	// Check repository health
	if err := s.assetRepo.HealthCheck(ctx); err != nil {
		return &pb.HealthCheckResponse{
			Healthy: false,
			Status:  "unhealthy",
			Details: map[string]string{
				"repository": err.Error(),
			},
		}, nil
	}

	return &pb.HealthCheckResponse{
		Healthy: true,
		Status:  "healthy",
		Details: map[string]string{
			"repository": "ok",
			"timestamp":  time.Now().Format(time.RFC3339),
		},
	}, nil
}

// Conversion helper methods

func (s *AssetDiscoveryServer) convertDiscoveryRequest(pbReq *pb.DiscoveryRequest) (*service.DiscoveryRequest, error) {
	tenantID, err := uuid.Parse(pbReq.TenantId)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	// Convert discovery methods
	methods := make([]service.DiscoveryMethod, len(pbReq.DiscoveryMethods))
	for i, method := range pbReq.DiscoveryMethods {
		methods[i] = s.convertDiscoveryMethod(method)
	}

	// Convert credentials
	credentials := make([]service.Credential, len(pbReq.Credentials))
	for i, cred := range pbReq.Credentials {
		credentials[i] = s.convertCredential(cred)
	}

	return &service.DiscoveryRequest{
		TenantID:        tenantID,
		TargetScope:     s.convertDiscoveryScope(pbReq.TargetScope),
		DiscoveryMethods: methods,
		ScanOptions:     s.convertScanOptions(pbReq.ScanOptions),
		Credentials:     credentials,
		Priority:        s.convertDiscoveryPriority(pbReq.Priority),
		ScheduleType:    s.convertScheduleType(pbReq.ScheduleType),
		Metadata:        pbReq.Metadata,
	}, nil
}

func (s *AssetDiscoveryServer) convertDiscoveryScope(pbScope *pb.DiscoveryScope) service.DiscoveryScope {
	if pbScope == nil {
		return service.DiscoveryScope{}
	}

	return service.DiscoveryScope{
		IPRanges:      pbScope.IpRanges,
		Hostnames:     pbScope.Hostnames,
		Domains:       pbScope.Domains,
		CloudAccounts: pbScope.CloudAccounts,
		Subnets:       pbScope.Subnets,
		NetworkZones:  pbScope.NetworkZones,
		ExcludeRanges: pbScope.ExcludeRanges,
	}
}

func (s *AssetDiscoveryServer) convertDiscoveryMethod(pbMethod pb.DiscoveryMethod) service.DiscoveryMethod {
	switch pbMethod {
	case pb.DiscoveryMethod_DISCOVERY_METHOD_PING:
		return service.DiscoveryMethodPing
	case pb.DiscoveryMethod_DISCOVERY_METHOD_PORT_SCAN:
		return service.DiscoveryMethodPortScan
	case pb.DiscoveryMethod_DISCOVERY_METHOD_SERVICE_SCAN:
		return service.DiscoveryMethodServiceScan
	case pb.DiscoveryMethod_DISCOVERY_METHOD_SNMP:
		return service.DiscoveryMethodSNMP
	case pb.DiscoveryMethod_DISCOVERY_METHOD_WMI:
		return service.DiscoveryMethodWMI
	case pb.DiscoveryMethod_DISCOVERY_METHOD_SSH:
		return service.DiscoveryMethodSSH
	case pb.DiscoveryMethod_DISCOVERY_METHOD_DNS:
		return service.DiscoveryMethodDNS
	case pb.DiscoveryMethod_DISCOVERY_METHOD_CLOUD:
		return service.DiscoveryMethodCloud
	case pb.DiscoveryMethod_DISCOVERY_METHOD_AGENT:
		return service.DiscoveryMethodAgent
	case pb.DiscoveryMethod_DISCOVERY_METHOD_PASSIVE:
		return service.DiscoveryMethodPassive
	case pb.DiscoveryMethod_DISCOVERY_METHOD_VULN_SCAN:
		return service.DiscoveryMethodVulnScan
	case pb.DiscoveryMethod_DISCOVERY_METHOD_ASSET_IMPORT:
		return service.DiscoveryMethodAssetImport
	default:
		return service.DiscoveryMethodPing
	}
}

func (s *AssetDiscoveryServer) convertScanOptions(pbOptions *pb.ScanOptions) service.ScanOptions {
	if pbOptions == nil {
		return service.ScanOptions{}
	}

	options := service.ScanOptions{
		PortRanges:         pbOptions.PortRanges,
		ScanTechnique:      pbOptions.ScanTechnique,
		ServiceDetection:   pbOptions.ServiceDetection,
		VersionDetection:   pbOptions.VersionDetection,
		OSDetection:        pbOptions.OsDetection,
		DeepInspection:     pbOptions.DeepInspection,
		GatherSoftware:     pbOptions.GatherSoftware,
		GatherProcesses:    pbOptions.GatherProcesses,
		GatherServices:     pbOptions.GatherServices,
		GatherCertificates: pbOptions.GatherCertificates,
		GatherVulns:        pbOptions.GatherVulns,
		CloudRegions:       pbOptions.CloudRegions,
		CloudServices:      pbOptions.CloudServices,
		MaxConcurrency:     int(pbOptions.MaxConcurrency),
		RateLimit:          int(pbOptions.RateLimit),
		RetryAttempts:      int(pbOptions.RetryAttempts),
	}

	if pbOptions.Timeout != nil {
		options.Timeout = pbOptions.Timeout.AsDuration()
	}
	if pbOptions.RetryDelay != nil {
		options.RetryDelay = pbOptions.RetryDelay.AsDuration()
	}

	// Convert custom scripts
	for _, script := range pbOptions.CustomScripts {
		customScript := service.CustomScript{
			Name:       script.Name,
			Type:       script.Type,
			Script:     script.Script,
			Parameters: script.Parameters,
		}
		if script.Timeout != nil {
			customScript.Timeout = script.Timeout.AsDuration()
		}
		options.CustomScripts = append(options.CustomScripts, customScript)
	}

	return options
}

func (s *AssetDiscoveryServer) convertCredential(pbCred *pb.Credential) service.Credential {
	if pbCred == nil {
		return service.Credential{}
	}

	return service.Credential{
		Type:        s.convertCredentialType(pbCred.Type),
		Username:    pbCred.Username,
		Password:    pbCred.Password,
		PrivateKey:  pbCred.PrivateKey,
		Certificate: pbCred.Certificate,
		Token:       pbCred.Token,
		APIKey:      pbCred.ApiKey,
		SecretKey:   pbCred.SecretKey,
		Domain:      pbCred.Domain,
		Metadata:    pbCred.Metadata,
	}
}

func (s *AssetDiscoveryServer) convertCredentialType(pbType pb.CredentialType) service.CredentialType {
	switch pbType {
	case pb.CredentialType_CREDENTIAL_TYPE_PASSWORD:
		return service.CredentialTypePassword
	case pb.CredentialType_CREDENTIAL_TYPE_SSH_KEY:
		return service.CredentialTypeSSHKey
	case pb.CredentialType_CREDENTIAL_TYPE_CERTIFICATE:
		return service.CredentialTypeCertificate
	case pb.CredentialType_CREDENTIAL_TYPE_TOKEN:
		return service.CredentialTypeToken
	case pb.CredentialType_CREDENTIAL_TYPE_API_KEY:
		return service.CredentialTypeAPIKey
	case pb.CredentialType_CREDENTIAL_TYPE_AWS:
		return service.CredentialTypeAWS
	case pb.CredentialType_CREDENTIAL_TYPE_AZURE:
		return service.CredentialTypeAzure
	case pb.CredentialType_CREDENTIAL_TYPE_GCP:
		return service.CredentialTypeGCP
	case pb.CredentialType_CREDENTIAL_TYPE_SNMP:
		return service.CredentialTypeSNMP
	case pb.CredentialType_CREDENTIAL_TYPE_WMI:
		return service.CredentialTypeWMI
	default:
		return service.CredentialTypePassword
	}
}

func (s *AssetDiscoveryServer) convertDiscoveryPriority(pbPriority pb.DiscoveryPriority) service.DiscoveryPriority {
	switch pbPriority {
	case pb.DiscoveryPriority_DISCOVERY_PRIORITY_LOW:
		return service.DiscoveryPriorityLow
	case pb.DiscoveryPriority_DISCOVERY_PRIORITY_MEDIUM:
		return service.DiscoveryPriorityMedium
	case pb.DiscoveryPriority_DISCOVERY_PRIORITY_HIGH:
		return service.DiscoveryPriorityHigh
	case pb.DiscoveryPriority_DISCOVERY_PRIORITY_CRITICAL:
		return service.DiscoveryPriorityCritical
	default:
		return service.DiscoveryPriorityMedium
	}
}

func (s *AssetDiscoveryServer) convertScheduleType(pbSchedule pb.ScheduleType) service.ScheduleType {
	switch pbSchedule {
	case pb.ScheduleType_SCHEDULE_TYPE_IMMEDIATE:
		return service.ScheduleTypeImmediate
	case pb.ScheduleType_SCHEDULE_TYPE_SCHEDULED:
		return service.ScheduleTypeScheduled
	case pb.ScheduleType_SCHEDULE_TYPE_RECURRING:
		return service.ScheduleTypeRecurring
	case pb.ScheduleType_SCHEDULE_TYPE_ON_DEMAND:
		return service.ScheduleTypeOnDemand
	default:
		return service.ScheduleTypeImmediate
	}
}

func (s *AssetDiscoveryServer) convertDiscoveryResult(result *service.DiscoveryResult) (*pb.DiscoveryResult, error) {
	if result == nil {
		return nil, fmt.Errorf("result is nil")
	}

	pbResult := &pb.DiscoveryResult{
		RequestId:      result.RequestID.String(),
		TenantId:       result.TenantID.String(),
		Status:         s.convertDiscoveryStatus(result.Status),
		StartTime:      timestamppb.New(result.StartTime),
		AssetsFound:    int32(result.AssetsFound),
		AssetsUpdated:  int32(result.AssetsUpdated),
		AssetsNew:      int32(result.AssetsNew),
		TargetsScanned: int32(result.TargetsScanned),
		TargetsTotal:   int32(result.TargetsTotal),
		SuccessRate:    result.SuccessRate,
		Duration:       durationpb.New(result.Duration),
		Metadata:       make(map[string]string),
	}

	if result.EndTime != nil {
		pbResult.EndTime = timestamppb.New(*result.EndTime)
	}

	// Convert assets
	for _, asset := range result.Assets {
		pbResult.Assets = append(pbResult.Assets, s.convertAsset(asset))
	}

	// Convert errors
	for _, err := range result.Errors {
		pbError := &pb.DiscoveryError{
			Target:      err.Target,
			Method:      err.Method,
			Error:       err.Error,
			Timestamp:   timestamppb.New(err.Timestamp),
			Severity:    err.Severity,
			Recoverable: err.Recoverable,
		}
		pbResult.Errors = append(pbResult.Errors, pbError)
	}

	// Convert warnings
	for _, warning := range result.Warnings {
		pbWarning := &pb.DiscoveryWarning{
			Target:    warning.Target,
			Method:    warning.Method,
			Message:   warning.Message,
			Timestamp: timestamppb.New(warning.Timestamp),
		}
		pbResult.Warnings = append(pbResult.Warnings, pbWarning)
	}

	// Convert statistics
	pbResult.Statistics = s.convertDiscoveryStatistics(&result.Statistics)

	// Convert metadata
	for key, value := range result.Metadata {
		pbResult.Metadata[key] = fmt.Sprintf("%v", value)
	}

	return pbResult, nil
}

func (s *AssetDiscoveryServer) convertDiscoveryStatus(status service.DiscoveryStatus) pb.DiscoveryStatus {
	switch status {
	case service.DiscoveryStatusPending:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_PENDING
	case service.DiscoveryStatusRunning:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_RUNNING
	case service.DiscoveryStatusCompleted:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_COMPLETED
	case service.DiscoveryStatusFailed:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_FAILED
	case service.DiscoveryStatusCancelled:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_CANCELLED
	case service.DiscoveryStatusPartial:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_PARTIAL
	default:
		return pb.DiscoveryStatus_DISCOVERY_STATUS_UNSPECIFIED
	}
}

func (s *AssetDiscoveryServer) convertDiscoveryStatistics(stats *service.DiscoveryStatistics) *pb.DiscoveryStatistics {
	if stats == nil {
		return &pb.DiscoveryStatistics{}
	}

	pbStats := &pb.DiscoveryStatistics{
		MethodStats:    make(map[string]*pb.MethodStatistics),
		AssetTypeStats: make(map[string]int32),
	}

	// Convert method stats
	for method, methodStats := range stats.MethodStats {
		pbMethodStats := &pb.MethodStatistics{
			TargetsScanned:  int32(methodStats.TargetsScanned),
			AssetsFound:     int32(methodStats.AssetsFound),
			Errors:          int32(methodStats.Errors),
			AvgResponseTime: durationpb.New(methodStats.AvgResponseTime),
			SuccessRate:     methodStats.SuccessRate,
		}
		pbStats.MethodStats[method] = pbMethodStats
	}

	// Convert asset type stats
	for assetType, count := range stats.AssetTypeStats {
		pbStats.AssetTypeStats[assetType] = int32(count)
	}

	// Convert network stats
	pbStats.NetworkStats = &pb.NetworkDiscoveryStats{
		IpsScanned:       int32(stats.NetworkStats.IPsScanned),
		ResponsiveIps:    int32(stats.NetworkStats.ResponsiveIPs),
		PortsScanned:     int32(stats.NetworkStats.PortsScanned),
		OpenPorts:        int32(stats.NetworkStats.OpenPorts),
		ServicesDetected: int32(stats.NetworkStats.ServicesDetected),
		PortDistribution: make(map[int32]int32),
	}

	for port, count := range stats.NetworkStats.PortDistribution {
		pbStats.NetworkStats.PortDistribution[int32(port)] = int32(count)
	}

	// Convert performance stats
	pbStats.PerformanceStats = &pb.PerformanceStats{
		TotalRequests:     stats.PerformanceStats.TotalRequests,
		RequestsPerSecond: stats.PerformanceStats.RequestsPerSecond,
		AvgResponseTime:   durationpb.New(stats.PerformanceStats.AvgResponseTime),
		MaxResponseTime:   durationpb.New(stats.PerformanceStats.MaxResponseTime),
		MinResponseTime:   durationpb.New(stats.PerformanceStats.MinResponseTime),
		Timeouts:          int32(stats.PerformanceStats.Timeouts),
		Retries:           int32(stats.PerformanceStats.Retries),
	}

	return pbStats
}

func (s *AssetDiscoveryServer) convertScanProgress(progress *service.ScanProgress) *pb.ScanProgress {
	if progress == nil {
		return &pb.ScanProgress{}
	}

	return &pb.ScanProgress{
		RequestId:          progress.RequestID.String(),
		Status:             s.convertDiscoveryStatus(progress.Status),
		PercentComplete:    progress.PercentComplete,
		CurrentTarget:      progress.CurrentTarget,
		TargetsCompleted:   int32(progress.TargetsCompleted),
		TargetsTotal:       int32(progress.TargetsTotal),
		AssetsFound:        int32(progress.AssetsFound),
		ElapsedTime:        durationpb.New(progress.ElapsedTime),
		EstimatedRemaining: durationpb.New(progress.EstimatedRemaining),
	}
}

func (s *AssetDiscoveryServer) convertAsset(asset *entity.Asset) *pb.Asset {
	if asset == nil {
		return &pb.Asset{}
	}

	pbAsset := &pb.Asset{
		Id:              asset.ID.String(),
		TenantId:        asset.TenantID.String(),
		Name:            asset.Name,
		DisplayName:     asset.DisplayName,
		Description:     asset.Description,
		AssetType:       s.convertAssetTypeToPb(asset.AssetType),
		Status:          s.convertAssetStatusToPb(asset.Status),
		RiskLevel:       s.convertAssetRiskLevelToPb(asset.RiskLevel),
		Owner:           asset.Owner,
		Department:      asset.Department,
		BusinessUnit:    asset.BusinessUnit,
		Environment:     asset.Environment,
		Criticality:     asset.Criticality,
		Tags:            asset.Tags,
		Labels:          asset.Labels,
		DiscoveryMethod: asset.DiscoveryMethod,
		DiscoverySource: asset.DiscoverySource,
		FirstDiscovered: timestamppb.New(asset.FirstDiscovered),
		LastSeen:        timestamppb.New(asset.LastSeen),
		LastUpdated:     timestamppb.New(asset.LastUpdated),
		ScanFrequency:   asset.ScanFrequency,
		Fingerprint:     asset.Fingerprint,
		Checksum:        asset.Checksum,
		CreatedAt:       timestamppb.New(asset.CreatedAt),
		UpdatedAt:       timestamppb.New(asset.UpdatedAt),
		Version:         int32(asset.Version),
	}

	if asset.NextScanTime != nil {
		pbAsset.NextScanTime = timestamppb.New(*asset.NextScanTime)
	}

	// Convert network info
	if asset.NetworkInfo != nil {
		pbAsset.NetworkInfo = s.convertNetworkInfo(asset.NetworkInfo)
	}

	// Convert system info
	if asset.SystemInfo != nil {
		pbAsset.SystemInfo = s.convertSystemInfo(asset.SystemInfo)
	}

	// Convert security info
	if asset.SecurityInfo != nil {
		pbAsset.SecurityInfo = s.convertSecurityInfo(asset.SecurityInfo)
	}

	return pbAsset
}

func (s *AssetDiscoveryServer) convertPbAsset(pbAsset *pb.Asset) (*entity.Asset, error) {
	if pbAsset == nil {
		return nil, fmt.Errorf("asset is nil")
	}

	assetID, err := uuid.Parse(pbAsset.Id)
	if err != nil {
		return nil, fmt.Errorf("invalid asset ID: %w", err)
	}

	tenantID, err := uuid.Parse(pbAsset.TenantId)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", err)
	}

	asset := &entity.Asset{
		ID:              assetID,
		TenantID:        tenantID,
		Name:            pbAsset.Name,
		DisplayName:     pbAsset.DisplayName,
		Description:     pbAsset.Description,
		AssetType:       s.convertAssetTypeFromPb(pbAsset.AssetType),
		Status:          s.convertAssetStatusFromPb(pbAsset.Status),
		RiskLevel:       s.convertAssetRiskLevelFromPb(pbAsset.RiskLevel),
		Owner:           pbAsset.Owner,
		Department:      pbAsset.Department,
		BusinessUnit:    pbAsset.BusinessUnit,
		Environment:     pbAsset.Environment,
		Criticality:     pbAsset.Criticality,
		Tags:            pbAsset.Tags,
		Labels:          pbAsset.Labels,
		DiscoveryMethod: pbAsset.DiscoveryMethod,
		DiscoverySource: pbAsset.DiscoverySource,
		ScanFrequency:   pbAsset.ScanFrequency,
		Fingerprint:     pbAsset.Fingerprint,
		Checksum:        pbAsset.Checksum,
		Version:         int(pbAsset.Version),
	}

	if pbAsset.FirstDiscovered != nil {
		asset.FirstDiscovered = pbAsset.FirstDiscovered.AsTime()
	}
	if pbAsset.LastSeen != nil {
		asset.LastSeen = pbAsset.LastSeen.AsTime()
	}
	if pbAsset.LastUpdated != nil {
		asset.LastUpdated = pbAsset.LastUpdated.AsTime()
	}
	if pbAsset.NextScanTime != nil {
		nextScanTime := pbAsset.NextScanTime.AsTime()
		asset.NextScanTime = &nextScanTime
	}
	if pbAsset.CreatedAt != nil {
		asset.CreatedAt = pbAsset.CreatedAt.AsTime()
	}
	if pbAsset.UpdatedAt != nil {
		asset.UpdatedAt = pbAsset.UpdatedAt.AsTime()
	}

	// Convert network info
	if pbAsset.NetworkInfo != nil {
		asset.NetworkInfo = s.convertNetworkInfoFromPb(pbAsset.NetworkInfo)
	}

	// Convert system info
	if pbAsset.SystemInfo != nil {
		asset.SystemInfo = s.convertSystemInfoFromPb(pbAsset.SystemInfo)
	}

	// Convert security info
	if pbAsset.SecurityInfo != nil {
		asset.SecurityInfo = s.convertSecurityInfoFromPb(pbAsset.SecurityInfo)
	}

	return asset, nil
}

// Additional conversion helper methods would continue here...
// For brevity, I'm showing the key conversion patterns
// The complete implementation would include all field conversions

func (s *AssetDiscoveryServer) convertAssetTypeToPb(assetType entity.AssetType) pb.AssetType {
	switch assetType {
	case entity.AssetTypeEndpoint:
		return pb.AssetType_ASSET_TYPE_ENDPOINT
	case entity.AssetTypeServer:
		return pb.AssetType_ASSET_TYPE_SERVER
	case entity.AssetTypeNetworkDevice:
		return pb.AssetType_ASSET_TYPE_NETWORK_DEVICE
	case entity.AssetTypeCloudResource:
		return pb.AssetType_ASSET_TYPE_CLOUD_RESOURCE
	case entity.AssetTypeContainer:
		return pb.AssetType_ASSET_TYPE_CONTAINER
	case entity.AssetTypeApplication:
		return pb.AssetType_ASSET_TYPE_APPLICATION
	case entity.AssetTypeDatabase:
		return pb.AssetType_ASSET_TYPE_DATABASE
	case entity.AssetTypeIoTDevice:
		return pb.AssetType_ASSET_TYPE_IOT_DEVICE
	case entity.AssetTypeUnknown:
		return pb.AssetType_ASSET_TYPE_UNKNOWN
	default:
		return pb.AssetType_ASSET_TYPE_UNSPECIFIED
	}
}

func (s *AssetDiscoveryServer) convertAssetTypeFromPb(pbType pb.AssetType) entity.AssetType {
	switch pbType {
	case pb.AssetType_ASSET_TYPE_ENDPOINT:
		return entity.AssetTypeEndpoint
	case pb.AssetType_ASSET_TYPE_SERVER:
		return entity.AssetTypeServer
	case pb.AssetType_ASSET_TYPE_NETWORK_DEVICE:
		return entity.AssetTypeNetworkDevice
	case pb.AssetType_ASSET_TYPE_CLOUD_RESOURCE:
		return entity.AssetTypeCloudResource
	case pb.AssetType_ASSET_TYPE_CONTAINER:
		return entity.AssetTypeContainer
	case pb.AssetType_ASSET_TYPE_APPLICATION:
		return entity.AssetTypeApplication
	case pb.AssetType_ASSET_TYPE_DATABASE:
		return entity.AssetTypeDatabase
	case pb.AssetType_ASSET_TYPE_IOT_DEVICE:
		return entity.AssetTypeIoTDevice
	case pb.AssetType_ASSET_TYPE_UNKNOWN:
		return entity.AssetTypeUnknown
	default:
		return entity.AssetTypeUnknown
	}
}

func (s *AssetDiscoveryServer) convertAssetStatusToPb(status entity.AssetStatus) pb.AssetStatus {
	switch status {
	case entity.AssetStatusActive:
		return pb.AssetStatus_ASSET_STATUS_ACTIVE
	case entity.AssetStatusInactive:
		return pb.AssetStatus_ASSET_STATUS_INACTIVE
	case entity.AssetStatusUnknown:
		return pb.AssetStatus_ASSET_STATUS_UNKNOWN
	case entity.AssetStatusMaintenance:
		return pb.AssetStatus_ASSET_STATUS_MAINTENANCE
	case entity.AssetStatusRetired:
		return pb.AssetStatus_ASSET_STATUS_RETIRED
	default:
		return pb.AssetStatus_ASSET_STATUS_UNSPECIFIED
	}
}

func (s *AssetDiscoveryServer) convertAssetStatusFromPb(pbStatus pb.AssetStatus) entity.AssetStatus {
	switch pbStatus {
	case pb.AssetStatus_ASSET_STATUS_ACTIVE:
		return entity.AssetStatusActive
	case pb.AssetStatus_ASSET_STATUS_INACTIVE:
		return entity.AssetStatusInactive
	case pb.AssetStatus_ASSET_STATUS_UNKNOWN:
		return entity.AssetStatusUnknown
	case pb.AssetStatus_ASSET_STATUS_MAINTENANCE:
		return entity.AssetStatusMaintenance
	case pb.AssetStatus_ASSET_STATUS_RETIRED:
		return entity.AssetStatusRetired
	default:
		return entity.AssetStatusUnknown
	}
}

func (s *AssetDiscoveryServer) convertAssetRiskLevelToPb(level entity.AssetRiskLevel) pb.AssetRiskLevel {
	switch level {
	case entity.AssetRiskCritical:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_CRITICAL
	case entity.AssetRiskHigh:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_HIGH
	case entity.AssetRiskMedium:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_MEDIUM
	case entity.AssetRiskLow:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_LOW
	case entity.AssetRiskUnknown:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_UNKNOWN
	default:
		return pb.AssetRiskLevel_ASSET_RISK_LEVEL_UNSPECIFIED
	}
}

func (s *AssetDiscoveryServer) convertAssetRiskLevelFromPb(pbLevel pb.AssetRiskLevel) entity.AssetRiskLevel {
	switch pbLevel {
	case pb.AssetRiskLevel_ASSET_RISK_LEVEL_CRITICAL:
		return entity.AssetRiskCritical
	case pb.AssetRiskLevel_ASSET_RISK_LEVEL_HIGH:
		return entity.AssetRiskHigh
	case pb.AssetRiskLevel_ASSET_RISK_LEVEL_MEDIUM:
		return entity.AssetRiskMedium
	case pb.AssetRiskLevel_ASSET_RISK_LEVEL_LOW:
		return entity.AssetRiskLow
	case pb.AssetRiskLevel_ASSET_RISK_LEVEL_UNKNOWN:
		return entity.AssetRiskUnknown
	default:
		return entity.AssetRiskUnknown
	}
}

// Simplified conversion methods (full implementation would include all fields)

func (s *AssetDiscoveryServer) convertNetworkInfo(info *entity.NetworkInfo) *pb.NetworkInfo {
	if info == nil {
		return nil
	}

	pbInfo := &pb.NetworkInfo{
		IpAddress:   info.IPAddress,
		IpVersion:   info.IPVersion,
		MacAddress:  info.MACAddress,
		Hostname:    info.Hostname,
		Fqdn:        info.FQDN,
		DnsNames:    info.DNSNames,
		NetworkZone: info.NetworkZone,
		Vlan:        info.VLAN,
		Subnet:      info.Subnet,
		Gateway:     info.Gateway,
		PublicIp:    info.PublicIP,
	}

	// Convert ports
	for _, port := range info.OpenPorts {
		pbPort := &pb.Port{
			Number:   int32(port.Number),
			Protocol: port.Protocol,
			Service:  port.Service,
			Version:  port.Version,
			Banner:   port.Banner,
			State:    port.State,
		}
		pbInfo.OpenPorts = append(pbInfo.OpenPorts, pbPort)
	}

	// Convert geo info
	if info.GeoLocation != nil {
		pbInfo.GeoLocation = &pb.GeoInfo{
			Country:   info.GeoLocation.Country,
			Region:    info.GeoLocation.Region,
			City:      info.GeoLocation.City,
			Latitude:  info.GeoLocation.Latitude,
			Longitude: info.GeoLocation.Longitude,
			Isp:       info.GeoLocation.ISP,
			Asn:       info.GeoLocation.ASN,
		}
	}

	return pbInfo
}

func (s *AssetDiscoveryServer) convertNetworkInfoFromPb(pbInfo *pb.NetworkInfo) *entity.NetworkInfo {
	if pbInfo == nil {
		return nil
	}

	info := &entity.NetworkInfo{
		IPAddress:   pbInfo.IpAddress,
		IPVersion:   pbInfo.IpVersion,
		MACAddress:  pbInfo.MacAddress,
		Hostname:    pbInfo.Hostname,
		FQDN:        pbInfo.Fqdn,
		DNSNames:    pbInfo.DnsNames,
		NetworkZone: pbInfo.NetworkZone,
		VLAN:        pbInfo.Vlan,
		Subnet:      pbInfo.Subnet,
		Gateway:     pbInfo.Gateway,
		PublicIP:    pbInfo.PublicIp,
	}

	// Convert ports
	for _, pbPort := range pbInfo.OpenPorts {
		port := entity.Port{
			Number:   int(pbPort.Number),
			Protocol: pbPort.Protocol,
			Service:  pbPort.Service,
			Version:  pbPort.Version,
			Banner:   pbPort.Banner,
			State:    pbPort.State,
		}
		info.OpenPorts = append(info.OpenPorts, port)
	}

	// Convert geo info
	if pbInfo.GeoLocation != nil {
		info.GeoLocation = &entity.GeoInfo{
			Country:   pbInfo.GeoLocation.Country,
			Region:    pbInfo.GeoLocation.Region,
			City:      pbInfo.GeoLocation.City,
			Latitude:  pbInfo.GeoLocation.Latitude,
			Longitude: pbInfo.GeoLocation.Longitude,
			ISP:       pbInfo.GeoLocation.Isp,
			ASN:       pbInfo.GeoLocation.Asn,
		}
	}

	return info
}

// Placeholder implementations for remaining conversion methods
func (s *AssetDiscoveryServer) convertSystemInfo(info *entity.SystemInfo) *pb.SystemInfo {
	// Implementation would convert all SystemInfo fields
	return &pb.SystemInfo{}
}

func (s *AssetDiscoveryServer) convertSystemInfoFromPb(pbInfo *pb.SystemInfo) *entity.SystemInfo {
	// Implementation would convert all SystemInfo fields
	return &entity.SystemInfo{}
}

func (s *AssetDiscoveryServer) convertSecurityInfo(info *entity.SecurityInfo) *pb.SecurityInfo {
	// Implementation would convert all SecurityInfo fields
	return &pb.SecurityInfo{}
}

func (s *AssetDiscoveryServer) convertSecurityInfoFromPb(pbInfo *pb.SecurityInfo) *entity.SecurityInfo {
	// Implementation would convert all SecurityInfo fields
	return &entity.SecurityInfo{}
}

func (s *AssetDiscoveryServer) convertAssetFilter(pbFilter *pb.AssetFilter) repository.AssetFilter {
	if pbFilter == nil {
		return repository.AssetFilter{}
	}

	filter := repository.AssetFilter{
		Environments:  pbFilter.Environments,
		Tags:          pbFilter.Tags,
		Owner:         &pbFilter.Owner,
		Department:    &pbFilter.Department,
		NetworkZones:  pbFilter.NetworkZones,
		Search:        &pbFilter.Search,
	}

	if pbFilter.IpRange != "" {
		filter.IPRange = &pbFilter.IpRange
	}
	if pbFilter.Hostname != "" {
		filter.Hostname = &pbFilter.Hostname
	}

	// Convert timestamps
	if pbFilter.LastSeenAfter != nil {
		t := pbFilter.LastSeenAfter.AsTime()
		filter.LastSeenAfter = &t
	}
	if pbFilter.LastSeenBefore != nil {
		t := pbFilter.LastSeenBefore.AsTime()
		filter.LastSeenBefore = &t
	}

	// Convert enums
	for _, pbType := range pbFilter.AssetTypes {
		filter.AssetTypes = append(filter.AssetTypes, s.convertAssetTypeFromPb(pbType))
	}
	for _, pbStatus := range pbFilter.Statuses {
		filter.Statuses = append(filter.Statuses, s.convertAssetStatusFromPb(pbStatus))
	}
	for _, pbLevel := range pbFilter.RiskLevels {
		filter.RiskLevels = append(filter.RiskLevels, s.convertAssetRiskLevelFromPb(pbLevel))
	}

	return filter
}

func (s *AssetDiscoveryServer) convertAssetSort(pbSort []*pb.AssetSort) []repository.AssetSort {
	var sort []repository.AssetSort
	for _, pbS := range pbSort {
		sort = append(sort, repository.AssetSort{
			Field:     pbS.Field,
			Direction: pbS.Direction,
		})
	}
	return sort
}

func (s *AssetDiscoveryServer) convertAssetAggregation(agg *repository.AssetAggregation) *pb.AssetAggregation {
	if agg == nil {
		return &pb.AssetAggregation{}
	}

	pbAgg := &pb.AssetAggregation{
		TotalAssets:         agg.TotalAssets,
		AssetsByType:        make(map[string]int64),
		AssetsByStatus:      make(map[string]int64),
		AssetsByRisk:        make(map[string]int64),
		AssetsByEnvironment: agg.AssetsByEnvironment,
	}

	// Convert asset type aggregations
	for assetType, count := range agg.AssetsByType {
		pbAgg.AssetsByType[string(assetType)] = count
	}

	// Convert status aggregations
	for status, count := range agg.AssetsByStatus {
		pbAgg.AssetsByStatus[string(status)] = count
	}

	// Convert risk level aggregations
	for risk, count := range agg.AssetsByRisk {
		pbAgg.AssetsByRisk[string(risk)] = count
	}

	// Convert vulnerability stats
	pbAgg.VulnStats = &pb.VulnerabilityStats{
		TotalVulns:      agg.VulnStats.TotalVulns,
		VulnsBySeverity: agg.VulnStats.VulnsBySeverity,
		AssetsWithVulns: agg.VulnStats.AssetsWithVulns,
		AvgVulnScore:    agg.VulnStats.AvgVulnScore,
	}

	// Convert compliance stats
	pbAgg.ComplianceStats = &pb.ComplianceStats{
		FrameworkStats: make(map[string]*pb.ComplianceFrameworkStats),
		OverallScore:   agg.ComplianceStats.OverallScore,
	}

	for framework, stats := range agg.ComplianceStats.FrameworkStats {
		pbAgg.ComplianceStats.FrameworkStats[framework] = &pb.ComplianceFrameworkStats{
			Compliant:    stats.Compliant,
			NonCompliant: stats.NonCompliant,
			Unknown:      stats.Unknown,
			Score:        stats.Score,
		}
	}

	// Convert network stats
	pbAgg.NetworkStats = &pb.NetworkStats{
		TotalIps:       agg.NetworkStats.TotalIPs,
		UniqueNetworks: agg.NetworkStats.UniqueNetworks,
		OpenPortStats:  make(map[int32]int64),
		NetworkZones:   agg.NetworkStats.NetworkZones,
	}

	for port, count := range agg.NetworkStats.OpenPortStats {
		pbAgg.NetworkStats.OpenPortStats[int32(port)] = count
	}

	return pbAgg
}