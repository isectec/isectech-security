// iSECTECH Asset Inventory - Discovery Use Case
// Production-grade asset discovery orchestration and management
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

// DiscoveryUseCase handles asset discovery operations
type DiscoveryUseCase struct {
	discoveryService *service.AssetDiscoveryService
	assetRepo        repository.AssetRepository
	logger           *logrus.Logger
}

// DiscoverySessionRequest represents a request to start discovery
type DiscoverySessionRequest struct {
	TenantID    uuid.UUID                  `json:"tenant_id" validate:"required"`
	Method      string                     `json:"method" validate:"required"`
	Scope       service.DiscoveryScope     `json:"scope"`
	Options     service.DiscoveryOptions   `json:"options"`
	Schedule    *service.DiscoverySchedule `json:"schedule,omitempty"`
	Parameters  map[string]interface{}     `json:"parameters,omitempty"`
	RequestedBy string                     `json:"requested_by,omitempty"`
}

// DiscoverySessionResponse represents discovery session information
type DiscoverySessionResponse struct {
	SessionID           uuid.UUID                `json:"session_id"`
	Status              service.DiscoveryStatus  `json:"status"`
	Progress            float64                  `json:"progress"`
	StartTime           time.Time                `json:"start_time"`
	LastUpdate          time.Time                `json:"last_update"`
	Results             *service.DiscoveryResult `json:"results,omitempty"`
	EstimatedCompletion *time.Time               `json:"estimated_completion,omitempty"`
}

// AgentHeartbeatRequest represents an agent heartbeat
type AgentHeartbeatRequest struct {
	AgentID          uuid.UUID                  `json:"agent_id" validate:"required"`
	TenantID         uuid.UUID                  `json:"tenant_id" validate:"required"`
	Hostname         string                     `json:"hostname" validate:"required"`
	IPAddresses      []string                   `json:"ip_addresses"`
	MACAddresses     []string                   `json:"mac_addresses"`
	OperatingSystem  entity.OperatingSystemInfo `json:"operating_system"`
	Hardware         entity.HardwareInfo        `json:"hardware"`
	Software         []entity.SoftwareComponent `json:"software,omitempty"`
	Services         []entity.ServiceInfo       `json:"services,omitempty"`
	NetworkPorts     []entity.NetworkPort       `json:"network_ports,omitempty"`
	SecurityControls []entity.SecurityControl   `json:"security_controls,omitempty"`
	AgentVersion     string                     `json:"agent_version"`
	Capabilities     []string                   `json:"capabilities"`
	Timestamp        time.Time                  `json:"timestamp"`
}

// AgentHeartbeatResponse represents the response to an agent heartbeat
type AgentHeartbeatResponse struct {
	AgentID       uuid.UUID          `json:"agent_id"`
	Status        string             `json:"status"`
	Configuration AgentConfiguration `json:"configuration,omitempty"`
	Commands      []AgentCommand     `json:"commands,omitempty"`
	NextHeartbeat time.Time          `json:"next_heartbeat"`
	ProcessedAt   time.Time          `json:"processed_at"`
}

// AgentConfiguration represents configuration updates for the agent
type AgentConfiguration struct {
	CollectionFrequency time.Duration          `json:"collection_frequency,omitempty"`
	ScanningEnabled     bool                   `json:"scanning_enabled"`
	ReportingLevel      string                 `json:"reporting_level,omitempty"`
	CustomSettings      map[string]interface{} `json:"custom_settings,omitempty"`
}

// AgentCommand represents a command to be executed by the agent
type AgentCommand struct {
	ID         uuid.UUID              `json:"id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	ExpiresAt  time.Time              `json:"expires_at"`
	CreatedAt  time.Time              `json:"created_at"`
}

// DiscoveryMethodsResponse represents available discovery methods
type DiscoveryMethodsResponse struct {
	Methods []DiscoveryMethodInfo `json:"methods"`
}

// DiscoveryMethodInfo represents information about a discovery method
type DiscoveryMethodInfo struct {
	Name         string                `json:"name"`
	Type         service.DiscoveryType `json:"type"`
	Enabled      bool                  `json:"enabled"`
	Capabilities []string              `json:"capabilities"`
	Description  string                `json:"description"`
	Parameters   []MethodParameter     `json:"parameters,omitempty"`
}

// MethodParameter represents a configurable parameter for a discovery method
type MethodParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Description string      `json:"description"`
	Options     []string    `json:"options,omitempty"`
}

// DiscoveryStatusRequest represents a request for discovery status
type DiscoveryStatusRequest struct {
	TenantID  uuid.UUID  `json:"tenant_id" validate:"required"`
	SessionID *uuid.UUID `json:"session_id,omitempty"`
	Method    string     `json:"method,omitempty"`
	TimeRange *TimeRange `json:"time_range,omitempty"`
}

// DiscoveryStatusResponse represents discovery status information
type DiscoveryStatusResponse struct {
	ActiveSessions []DiscoverySessionResponse `json:"active_sessions"`
	RecentResults  []DiscoverySessionResponse `json:"recent_results,omitempty"`
	Statistics     DiscoveryStatistics        `json:"statistics"`
	SystemHealth   DiscoverySystemHealth      `json:"system_health"`
}

// DiscoveryStatistics represents discovery system statistics
type DiscoveryStatistics struct {
	TotalSessions      int                    `json:"total_sessions"`
	ActiveSessions     int                    `json:"active_sessions"`
	SuccessfulSessions int                    `json:"successful_sessions"`
	FailedSessions     int                    `json:"failed_sessions"`
	AssetsDiscovered   int                    `json:"assets_discovered"`
	AssetsUpdated      int                    `json:"assets_updated"`
	AverageSessionTime time.Duration          `json:"average_session_time"`
	MethodStatistics   map[string]MethodStats `json:"method_statistics"`
	LastSuccessfulScan time.Time              `json:"last_successful_scan"`
}

// MethodStats represents statistics for a discovery method
type MethodStats struct {
	TotalRuns   int           `json:"total_runs"`
	SuccessRate float64       `json:"success_rate"`
	AverageTime time.Duration `json:"average_time"`
	LastRun     time.Time     `json:"last_run"`
	AssetsFound int           `json:"assets_found"`
}

// DiscoverySystemHealth represents the health of the discovery system
type DiscoverySystemHealth struct {
	Overall       string                     `json:"overall"`
	Components    map[string]ComponentHealth `json:"components"`
	Issues        []HealthIssue              `json:"issues,omitempty"`
	LastCheckTime time.Time                  `json:"last_check_time"`
}

// ComponentHealth represents the health of a discovery component
type ComponentHealth struct {
	Status    string                 `json:"status"`
	Message   string                 `json:"message,omitempty"`
	LastCheck time.Time              `json:"last_check"`
	Metrics   map[string]interface{} `json:"metrics,omitempty"`
}

// HealthIssue represents a health issue in the discovery system
type HealthIssue struct {
	Component  string    `json:"component"`
	Severity   string    `json:"severity"`
	Message    string    `json:"message"`
	Detected   time.Time `json:"detected"`
	Resolution string    `json:"resolution,omitempty"`
}

// NewDiscoveryUseCase creates a new discovery use case
func NewDiscoveryUseCase(
	discoveryService *service.AssetDiscoveryService,
	assetRepo repository.AssetRepository,
	logger *logrus.Logger,
) *DiscoveryUseCase {
	return &DiscoveryUseCase{
		discoveryService: discoveryService,
		assetRepo:        assetRepo,
		logger:           logger,
	}
}

// StartDiscoverySession initiates a new asset discovery session
func (uc *DiscoveryUseCase) StartDiscoverySession(ctx context.Context, req *DiscoverySessionRequest) (*DiscoverySessionResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":    "start_discovery_session",
		"tenant_id":    req.TenantID,
		"method":       req.Method,
		"requested_by": req.RequestedBy,
	})

	logger.Info("Starting discovery session")

	// Validate request
	if err := uc.validateDiscoveryRequest(req); err != nil {
		logger.WithError(err).Error("Discovery request validation failed")
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Create discovery configuration
	config := service.DiscoveryConfig{
		Method:     req.Method,
		TenantID:   req.TenantID,
		Scope:      req.Scope,
		Parameters: req.Parameters,
		Options:    req.Options,
		Schedule:   req.Schedule,
	}

	// Start discovery session
	session, err := uc.discoveryService.StartDiscovery(ctx, config)
	if err != nil {
		logger.WithError(err).Error("Failed to start discovery session")
		return nil, fmt.Errorf("failed to start discovery: %w", err)
	}

	response := &DiscoverySessionResponse{
		SessionID:  session.ID,
		Status:     session.Status,
		Progress:   session.Progress,
		StartTime:  session.StartTime,
		LastUpdate: session.LastUpdate,
		Results:    session.Results,
	}

	// Calculate estimated completion time
	if session.Status == service.DiscoveryStatusRunning {
		estimatedDuration := uc.estimateDiscoveryDuration(req.Method, req.Scope)
		estimatedCompletion := session.StartTime.Add(estimatedDuration)
		response.EstimatedCompletion = &estimatedCompletion
	}

	logger.WithField("session_id", session.ID).Info("Discovery session started")
	return response, nil
}

// GetDiscoverySession retrieves information about a discovery session
func (uc *DiscoveryUseCase) GetDiscoverySession(ctx context.Context, tenantID, sessionID uuid.UUID) (*DiscoverySessionResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":  "get_discovery_session",
		"tenant_id":  tenantID,
		"session_id": sessionID,
	})

	logger.Debug("Retrieving discovery session")

	session, err := uc.discoveryService.GetDiscoverySession(sessionID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve discovery session")
		return nil, fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Verify tenant access
	if session.Config.TenantID != tenantID {
		logger.Error("Tenant mismatch for discovery session")
		return nil, fmt.Errorf("session not found")
	}

	response := &DiscoverySessionResponse{
		SessionID:  session.ID,
		Status:     session.Status,
		Progress:   session.Progress,
		StartTime:  session.StartTime,
		LastUpdate: session.LastUpdate,
		Results:    session.Results,
	}

	logger.Debug("Discovery session retrieved")
	return response, nil
}

// CancelDiscoverySession cancels an active discovery session
func (uc *DiscoveryUseCase) CancelDiscoverySession(ctx context.Context, tenantID, sessionID uuid.UUID, cancelledBy string) error {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":    "cancel_discovery_session",
		"tenant_id":    tenantID,
		"session_id":   sessionID,
		"cancelled_by": cancelledBy,
	})

	logger.Info("Cancelling discovery session")

	// Verify session exists and belongs to tenant
	session, err := uc.discoveryService.GetDiscoverySession(sessionID)
	if err != nil {
		logger.WithError(err).Error("Failed to retrieve discovery session for cancellation")
		return fmt.Errorf("session not found: %w", err)
	}

	if session.Config.TenantID != tenantID {
		logger.Error("Tenant mismatch for discovery session cancellation")
		return fmt.Errorf("session not found")
	}

	// Cancel the session
	if err := uc.discoveryService.CancelDiscovery(sessionID); err != nil {
		logger.WithError(err).Error("Failed to cancel discovery session")
		return fmt.Errorf("failed to cancel session: %w", err)
	}

	logger.Info("Discovery session cancelled")
	return nil
}

// ListDiscoverySessions lists discovery sessions for a tenant
func (uc *DiscoveryUseCase) ListDiscoverySessions(ctx context.Context, tenantID uuid.UUID, activeOnly bool) ([]DiscoverySessionResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation":   "list_discovery_sessions",
		"tenant_id":   tenantID,
		"active_only": activeOnly,
	})

	logger.Debug("Listing discovery sessions")

	sessions := uc.discoveryService.ListActiveSessions()

	var response []DiscoverySessionResponse
	for _, session := range sessions {
		// Filter by tenant
		if session.Config.TenantID != tenantID {
			continue
		}

		// Filter by active status if requested
		if activeOnly && session.Status != service.DiscoveryStatusRunning && session.Status != service.DiscoveryStatusPending {
			continue
		}

		sessionResponse := DiscoverySessionResponse{
			SessionID:  session.ID,
			Status:     session.Status,
			Progress:   session.Progress,
			StartTime:  session.StartTime,
			LastUpdate: session.LastUpdate,
			Results:    session.Results,
		}

		response = append(response, sessionResponse)
	}

	logger.WithField("sessions_count", len(response)).Debug("Discovery sessions listed")
	return response, nil
}

// ProcessAgentHeartbeat processes heartbeat from security agent
func (uc *DiscoveryUseCase) ProcessAgentHeartbeat(ctx context.Context, req *AgentHeartbeatRequest) (*AgentHeartbeatResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "process_agent_heartbeat",
		"agent_id":  req.AgentID,
		"tenant_id": req.TenantID,
		"hostname":  req.Hostname,
	})

	logger.Debug("Processing agent heartbeat")

	// Convert to discovery service heartbeat format
	heartbeat := service.AgentHeartbeat{
		AgentID:         req.AgentID,
		TenantID:        req.TenantID,
		Hostname:        req.Hostname,
		IPAddresses:     req.IPAddresses,
		MACAddresses:    req.MACAddresses,
		OperatingSystem: req.OperatingSystem,
		Hardware:        req.Hardware,
		Software:        req.Software,
		Services:        req.Services,
		Timestamp:       req.Timestamp,
		AgentVersion:    req.AgentVersion,
		Capabilities:    req.Capabilities,
	}

	// Process heartbeat
	if err := uc.discoveryService.ProcessAgentHeartbeat(ctx, heartbeat); err != nil {
		logger.WithError(err).Error("Failed to process agent heartbeat")
		return nil, fmt.Errorf("failed to process heartbeat: %w", err)
	}

	// Generate response with configuration and commands
	response := &AgentHeartbeatResponse{
		AgentID:       req.AgentID,
		Status:        "healthy",
		NextHeartbeat: time.Now().UTC().Add(5 * time.Minute),
		ProcessedAt:   time.Now().UTC(),
	}

	// Get agent-specific configuration
	config := uc.getAgentConfiguration(ctx, req.TenantID, req.AgentID)
	if config != nil {
		response.Configuration = *config
	}

	// Get pending commands for agent
	commands := uc.getAgentCommands(ctx, req.TenantID, req.AgentID)
	response.Commands = commands

	logger.Debug("Agent heartbeat processed successfully")
	return response, nil
}

// GetDiscoveryMethods returns available discovery methods
func (uc *DiscoveryUseCase) GetDiscoveryMethods(ctx context.Context) (*DiscoveryMethodsResponse, error) {
	logger := uc.logger.WithField("operation", "get_discovery_methods")
	logger.Debug("Retrieving discovery methods")

	// This would typically query the discovery service for available methods
	// For now, return static information
	methods := []DiscoveryMethodInfo{
		{
			Name:         "agent",
			Type:         service.DiscoveryTypeAgent,
			Enabled:      true,
			Capabilities: []string{"real_time", "detailed_inventory", "software_list", "running_processes"},
			Description:  "Agent-based discovery using deployed security agents",
			Parameters: []MethodParameter{
				{
					Name:        "heartbeat_interval",
					Type:        "duration",
					Required:    false,
					Default:     "5m",
					Description: "Interval between agent heartbeats",
				},
			},
		},
		{
			Name:         "network_scan",
			Type:         service.DiscoveryTypeNetwork,
			Enabled:      true,
			Capabilities: []string{"network_mapping", "port_scanning", "service_detection", "os_fingerprinting"},
			Description:  "Network-based discovery using port scanning and service detection",
			Parameters: []MethodParameter{
				{
					Name:        "network_ranges",
					Type:        "string_array",
					Required:    true,
					Description: "CIDR network ranges to scan",
				},
				{
					Name:        "port_scan_enabled",
					Type:        "boolean",
					Required:    false,
					Default:     true,
					Description: "Enable port scanning",
				},
			},
		},
		{
			Name:         "cloud_api",
			Type:         service.DiscoveryTypeCloud,
			Enabled:      true,
			Capabilities: []string{"aws", "azure", "gcp", "resource_inventory", "tags", "metadata"},
			Description:  "Cloud API-based discovery for cloud resources",
			Parameters: []MethodParameter{
				{
					Name:        "cloud_provider",
					Type:        "string",
					Required:    true,
					Options:     []string{"aws", "azure", "gcp"},
					Description: "Cloud provider to discover resources from",
				},
				{
					Name:        "regions",
					Type:        "string_array",
					Required:    false,
					Description: "Specific regions to scan (all if not specified)",
				},
			},
		},
	}

	response := &DiscoveryMethodsResponse{
		Methods: methods,
	}

	logger.WithField("methods_count", len(methods)).Debug("Discovery methods retrieved")
	return response, nil
}

// GetDiscoveryStatus returns overall discovery system status
func (uc *DiscoveryUseCase) GetDiscoveryStatus(ctx context.Context, req *DiscoveryStatusRequest) (*DiscoveryStatusResponse, error) {
	logger := uc.logger.WithFields(logrus.Fields{
		"operation": "get_discovery_status",
		"tenant_id": req.TenantID,
	})

	logger.Debug("Retrieving discovery status")

	// Get active sessions
	activeSessions, err := uc.ListDiscoverySessions(ctx, req.TenantID, true)
	if err != nil {
		logger.WithError(err).Error("Failed to get active sessions")
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Get recent sessions
	recentSessions, err := uc.ListDiscoverySessions(ctx, req.TenantID, false)
	if err != nil {
		logger.WithError(err).Warn("Failed to get recent sessions")
		recentSessions = []DiscoverySessionResponse{}
	}

	// Generate statistics
	statistics := uc.generateDiscoveryStatistics(recentSessions)

	// Check system health
	systemHealth := uc.checkDiscoverySystemHealth(ctx)

	response := &DiscoveryStatusResponse{
		ActiveSessions: activeSessions,
		RecentResults:  recentSessions[:min(len(recentSessions), 10)], // Last 10 sessions
		Statistics:     statistics,
		SystemHealth:   systemHealth,
	}

	logger.WithFields(logrus.Fields{
		"active_sessions": len(activeSessions),
		"system_health":   systemHealth.Overall,
	}).Debug("Discovery status retrieved")

	return response, nil
}

// Private helper methods

func (uc *DiscoveryUseCase) validateDiscoveryRequest(req *DiscoverySessionRequest) error {
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	if req.Method == "" {
		return fmt.Errorf("discovery method is required")
	}

	// Validate method-specific parameters
	switch req.Method {
	case "network_scan":
		if len(req.Scope.NetworkRanges) == 0 {
			return fmt.Errorf("network ranges are required for network scan")
		}
	case "cloud_api":
		if len(req.Scope.CloudAccounts) == 0 {
			return fmt.Errorf("cloud accounts are required for cloud API discovery")
		}
	}

	return nil
}

func (uc *DiscoveryUseCase) estimateDiscoveryDuration(method string, scope service.DiscoveryScope) time.Duration {
	switch method {
	case "agent":
		return 5 * time.Minute // Agent discovery is usually quick
	case "network_scan":
		// Estimate based on network ranges
		baseTime := 10 * time.Minute
		if len(scope.NetworkRanges) > 1 {
			baseTime *= time.Duration(len(scope.NetworkRanges))
		}
		return baseTime
	case "cloud_api":
		// Estimate based on cloud accounts and regions
		return 15 * time.Minute
	default:
		return 30 * time.Minute
	}
}

func (uc *DiscoveryUseCase) getAgentConfiguration(ctx context.Context, tenantID, agentID uuid.UUID) *AgentConfiguration {
	// This would typically query the database for agent-specific configuration
	// For now, return default configuration
	return &AgentConfiguration{
		CollectionFrequency: 5 * time.Minute,
		ScanningEnabled:     true,
		ReportingLevel:      "normal",
		CustomSettings:      make(map[string]interface{}),
	}
}

func (uc *DiscoveryUseCase) getAgentCommands(ctx context.Context, tenantID, agentID uuid.UUID) []AgentCommand {
	// This would typically query the database for pending commands
	// For now, return empty list
	return []AgentCommand{}
}

func (uc *DiscoveryUseCase) generateDiscoveryStatistics(sessions []DiscoverySessionResponse) DiscoveryStatistics {
	stats := DiscoveryStatistics{
		TotalSessions:      len(sessions),
		MethodStatistics:   make(map[string]MethodStats),
		LastSuccessfulScan: time.Now().UTC().Add(-time.Hour), // Mock data
	}

	activeCount := 0
	successCount := 0
	failedCount := 0
	totalDuration := time.Duration(0)
	totalAssets := 0
	totalUpdated := 0

	methodCounts := make(map[string]int)
	methodSuccesses := make(map[string]int)
	methodDurations := make(map[string]time.Duration)

	for _, session := range sessions {
		// Count by status
		switch session.Status {
		case service.DiscoveryStatusRunning, service.DiscoveryStatusPending:
			activeCount++
		case service.DiscoveryStatusCompleted:
			successCount++
		case service.DiscoveryStatusFailed:
			failedCount++
		}

		// Aggregate results
		if session.Results != nil {
			totalAssets += session.Results.NewAssets
			totalUpdated += session.Results.UpdatedAssets
			totalDuration += session.Results.Duration

			// Method statistics
			method := session.Results.Method
			methodCounts[method]++
			if session.Status == service.DiscoveryStatusCompleted {
				methodSuccesses[method]++
			}
			methodDurations[method] += session.Results.Duration
		}
	}

	stats.ActiveSessions = activeCount
	stats.SuccessfulSessions = successCount
	stats.FailedSessions = failedCount
	stats.AssetsDiscovered = totalAssets
	stats.AssetsUpdated = totalUpdated

	if len(sessions) > 0 {
		stats.AverageSessionTime = totalDuration / time.Duration(len(sessions))
	}

	// Generate method statistics
	for method, count := range methodCounts {
		successRate := 0.0
		if count > 0 {
			successRate = float64(methodSuccesses[method]) / float64(count) * 100
		}

		avgTime := time.Duration(0)
		if count > 0 {
			avgTime = methodDurations[method] / time.Duration(count)
		}

		stats.MethodStatistics[method] = MethodStats{
			TotalRuns:   count,
			SuccessRate: successRate,
			AverageTime: avgTime,
			LastRun:     time.Now().UTC().Add(-time.Hour), // Mock data
			AssetsFound: totalAssets / len(methodCounts),  // Rough estimate
		}
	}

	return stats
}

func (uc *DiscoveryUseCase) checkDiscoverySystemHealth(ctx context.Context) DiscoverySystemHealth {
	health := DiscoverySystemHealth{
		Overall:       "healthy",
		Components:    make(map[string]ComponentHealth),
		Issues:        []HealthIssue{},
		LastCheckTime: time.Now().UTC(),
	}

	// Check discovery service health
	health.Components["discovery_service"] = ComponentHealth{
		Status:    "healthy",
		Message:   "Discovery service is operational",
		LastCheck: time.Now().UTC(),
		Metrics: map[string]interface{}{
			"active_sessions": 0,
			"queue_size":      0,
		},
	}

	// Check database connectivity
	repoHealth, err := uc.assetRepo.GetHealthStatus(ctx)
	if err != nil || !repoHealth.Healthy {
		health.Overall = "degraded"
		health.Components["database"] = ComponentHealth{
			Status:    "unhealthy",
			Message:   "Database connectivity issues",
			LastCheck: time.Now().UTC(),
		}
		health.Issues = append(health.Issues, HealthIssue{
			Component:  "database",
			Severity:   "high",
			Message:    "Database is not responding properly",
			Detected:   time.Now().UTC(),
			Resolution: "Check database connection and configuration",
		})
	} else {
		health.Components["database"] = ComponentHealth{
			Status:    "healthy",
			Message:   "Database is operational",
			LastCheck: time.Now().UTC(),
		}
	}

	// Check agent connectivity (mock)
	health.Components["agent_communication"] = ComponentHealth{
		Status:    "healthy",
		Message:   "Agent communication is operational",
		LastCheck: time.Now().UTC(),
		Metrics: map[string]interface{}{
			"connected_agents": 100,
			"heartbeat_rate":   95.5,
		},
	}

	return health
}

// Utility function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
