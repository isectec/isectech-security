// iSECTECH Asset Inventory - Discovery Service
// Production-grade asset discovery and inventory management
// Copyright (c) 2024 iSECTECH. All rights reserved.

package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
)

// AssetDiscoveryService handles automatic and manual asset discovery
type AssetDiscoveryService struct {
	logger              *logrus.Logger
	discoveryMethods    map[string]DiscoveryMethod
	discoveryConfig     DiscoveryConfiguration
	deduplicationEngine *DeduplicationEngine
	mutex               sync.RWMutex
	activeDiscoveries   map[string]*DiscoverySession
}

// DiscoveryMethod defines interface for different discovery mechanisms
type DiscoveryMethod interface {
	GetName() string
	GetType() DiscoveryType
	IsEnabled() bool
	Discover(ctx context.Context, config DiscoveryConfig) (*DiscoveryResult, error)
	Validate(config DiscoveryConfig) error
	GetCapabilities() []string
}

// DiscoveryType represents different types of discovery methods
type DiscoveryType string

const (
	DiscoveryTypeAgent     DiscoveryType = "agent"
	DiscoveryTypeNetwork   DiscoveryType = "network"
	DiscoveryTypeCloud     DiscoveryType = "cloud"
	DiscoveryTypeDatabase  DiscoveryType = "database"
	DiscoveryTypeDirectory DiscoveryType = "directory"
	DiscoveryTypeAPI       DiscoveryType = "api"
	DiscoveryTypeManual    DiscoveryType = "manual"
	DiscoveryTypeImport    DiscoveryType = "import"
)

// DiscoveryConfiguration holds global discovery settings
type DiscoveryConfiguration struct {
	EnabledMethods       []string                       `json:"enabled_methods"`
	DiscoverySchedule    map[string]string              `json:"discovery_schedule"`
	NetworkRanges        []string                       `json:"network_ranges"`
	ExcludedRanges       []string                       `json:"excluded_ranges"`
	CloudProviders       map[string]CloudProviderConfig `json:"cloud_providers"`
	AgentConfiguration   AgentDiscoveryConfig           `json:"agent_configuration"`
	DeduplicationRules   []DeduplicationRule            `json:"deduplication_rules"`
	PerformanceSettings  PerformanceSettings            `json:"performance_settings"`
	NotificationSettings NotificationSettings           `json:"notification_settings"`
}

// CloudProviderConfig holds cloud provider specific settings
type CloudProviderConfig struct {
	Enabled       bool              `json:"enabled"`
	Credentials   map[string]string `json:"credentials"`
	Regions       []string          `json:"regions"`
	ResourceTypes []string          `json:"resource_types"`
	Tags          map[string]string `json:"tags"`
}

// AgentDiscoveryConfig holds agent-based discovery settings
type AgentDiscoveryConfig struct {
	HeartbeatInterval    time.Duration `json:"heartbeat_interval"`
	OfflineThreshold     time.Duration `json:"offline_threshold"`
	RequiredCapabilities []string      `json:"required_capabilities"`
	CollectionFrequency  time.Duration `json:"collection_frequency"`
}

// PerformanceSettings controls discovery performance
type PerformanceSettings struct {
	MaxConcurrentScans int           `json:"max_concurrent_scans"`
	ScanTimeout        time.Duration `json:"scan_timeout"`
	PortScanTimeout    time.Duration `json:"port_scan_timeout"`
	MaxPortsPerHost    int           `json:"max_ports_per_host"`
	RateLimitRPS       int           `json:"rate_limit_rps"`
	BatchSize          int           `json:"batch_size"`
}

// NotificationSettings controls discovery notifications
type NotificationSettings struct {
	EnableNewAssetAlerts     bool           `json:"enable_new_asset_alerts"`
	EnableMissingAssetAlerts bool           `json:"enable_missing_asset_alerts"`
	AlertRecipients          []string       `json:"alert_recipients"`
	AlertThresholds          map[string]int `json:"alert_thresholds"`
}

// DiscoveryConfig holds configuration for a specific discovery run
type DiscoveryConfig struct {
	Method     string                 `json:"method"`
	TenantID   uuid.UUID              `json:"tenant_id"`
	Scope      DiscoveryScope         `json:"scope"`
	Parameters map[string]interface{} `json:"parameters"`
	Options    DiscoveryOptions       `json:"options"`
	Schedule   *DiscoverySchedule     `json:"schedule,omitempty"`
}

// DiscoveryScope defines what should be discovered
type DiscoveryScope struct {
	NetworkRanges  []string           `json:"network_ranges,omitempty"`
	CloudAccounts  []string           `json:"cloud_accounts,omitempty"`
	Datacenters    []string           `json:"datacenters,omitempty"`
	BusinessUnits  []string           `json:"business_units,omitempty"`
	AssetTypes     []entity.AssetType `json:"asset_types,omitempty"`
	IncludeFilters map[string]string  `json:"include_filters,omitempty"`
	ExcludeFilters map[string]string  `json:"exclude_filters,omitempty"`
}

// DiscoveryOptions controls discovery behavior
type DiscoveryOptions struct {
	DeepScan           bool          `json:"deep_scan"`
	PortScan           bool          `json:"port_scan"`
	ServiceDetection   bool          `json:"service_detection"`
	OSDetection        bool          `json:"os_detection"`
	SoftwareInventory  bool          `json:"software_inventory"`
	VulnerabilityCheck bool          `json:"vulnerability_check"`
	Timeout            time.Duration `json:"timeout"`
	MaxConcurrency     int           `json:"max_concurrency"`
	ForceRefresh       bool          `json:"force_refresh"`
}

// DiscoverySchedule defines when discovery should run
type DiscoverySchedule struct {
	Enabled  bool      `json:"enabled"`
	CronExpr string    `json:"cron_expr"`
	NextRun  time.Time `json:"next_run"`
	LastRun  time.Time `json:"last_run"`
	Timezone string    `json:"timezone"`
}

// DiscoveryResult holds the results of a discovery operation
type DiscoveryResult struct {
	SessionID        uuid.UUID              `json:"session_id"`
	Method           string                 `json:"method"`
	TenantID         uuid.UUID              `json:"tenant_id"`
	StartTime        time.Time              `json:"start_time"`
	EndTime          time.Time              `json:"end_time"`
	Duration         time.Duration          `json:"duration"`
	Status           DiscoveryStatus        `json:"status"`
	AssetsDiscovered []entity.Asset         `json:"assets_discovered"`
	AssetsUpdated    []entity.Asset         `json:"assets_updated"`
	NewAssets        int                    `json:"new_assets"`
	UpdatedAssets    int                    `json:"updated_assets"`
	DeadAssets       []uuid.UUID            `json:"dead_assets"`
	Errors           []DiscoveryError       `json:"errors"`
	Warnings         []string               `json:"warnings"`
	Statistics       DiscoveryStatistics    `json:"statistics"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// DiscoveryStatus represents the status of a discovery operation
type DiscoveryStatus string

const (
	DiscoveryStatusPending   DiscoveryStatus = "pending"
	DiscoveryStatusRunning   DiscoveryStatus = "running"
	DiscoveryStatusCompleted DiscoveryStatus = "completed"
	DiscoveryStatusFailed    DiscoveryStatus = "failed"
	DiscoveryStatusCancelled DiscoveryStatus = "cancelled"
	DiscoveryStatusPartial   DiscoveryStatus = "partial"
)

// DiscoveryError represents an error during discovery
type DiscoveryError struct {
	Code      string                 `json:"code"`
	Message   string                 `json:"message"`
	Source    string                 `json:"source"`
	Target    string                 `json:"target,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Severity  string                 `json:"severity"`
}

// DiscoveryStatistics holds discovery metrics
type DiscoveryStatistics struct {
	ScanRate             float64 `json:"scan_rate"`
	SuccessRate          float64 `json:"success_rate"`
	ErrorRate            float64 `json:"error_rate"`
	HostsScanned         int     `json:"hosts_scanned"`
	HostsResponding      int     `json:"hosts_responding"`
	PortsScanned         int     `json:"ports_scanned"`
	ServicesDetected     int     `json:"services_detected"`
	SoftwareDetected     int     `json:"software_detected"`
	OSDetected           int     `json:"os_detected"`
	VulnerabilitiesFound int     `json:"vulnerabilities_found"`
}

// DiscoverySession represents an active discovery session
type DiscoverySession struct {
	ID         uuid.UUID          `json:"id"`
	Config     DiscoveryConfig    `json:"config"`
	Status     DiscoveryStatus    `json:"status"`
	Progress   float64            `json:"progress"`
	StartTime  time.Time          `json:"start_time"`
	LastUpdate time.Time          `json:"last_update"`
	Cancel     context.CancelFunc `json:"-"`
	Results    *DiscoveryResult   `json:"results,omitempty"`
}

// DeduplicationEngine handles asset deduplication
type DeduplicationEngine struct {
	rules  []DeduplicationRule
	logger *logrus.Logger
}

// DeduplicationRule defines how to identify duplicate assets
type DeduplicationRule struct {
	Name       string                   `json:"name"`
	Priority   int                      `json:"priority"`
	Conditions []DeduplicationCondition `json:"conditions"`
	Action     DeduplicationAction      `json:"action"`
	Confidence float64                  `json:"confidence"`
}

// DeduplicationCondition defines matching criteria
type DeduplicationCondition struct {
	Field     string  `json:"field"`
	Weight    float64 `json:"weight"`
	Exact     bool    `json:"exact"`
	Tolerance float64 `json:"tolerance,omitempty"`
}

// DeduplicationAction defines what to do with duplicates
type DeduplicationAction string

const (
	DeduplicationActionMerge   DeduplicationAction = "merge"
	DeduplicationActionReplace DeduplicationAction = "replace"
	DeduplicationActionFlag    DeduplicationAction = "flag"
	DeduplicationActionIgnore  DeduplicationAction = "ignore"
)

// NewAssetDiscoveryService creates a new discovery service
func NewAssetDiscoveryService(logger *logrus.Logger) *AssetDiscoveryService {
	service := &AssetDiscoveryService{
		logger:              logger,
		discoveryMethods:    make(map[string]DiscoveryMethod),
		discoveryConfig:     createDefaultDiscoveryConfiguration(),
		deduplicationEngine: NewDeduplicationEngine(logger),
		activeDiscoveries:   make(map[string]*DiscoverySession),
	}

	// Register default discovery methods
	service.registerDefaultMethods()

	logger.WithFields(logrus.Fields{
		"component":       "asset_discovery",
		"methods_count":   len(service.discoveryMethods),
		"enabled_methods": service.discoveryConfig.EnabledMethods,
	}).Info("Asset discovery service initialized")

	return service
}

// RegisterDiscoveryMethod registers a new discovery method
func (s *AssetDiscoveryService) RegisterDiscoveryMethod(method DiscoveryMethod) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	name := method.GetName()
	if _, exists := s.discoveryMethods[name]; exists {
		return fmt.Errorf("discovery method %s already registered", name)
	}

	s.discoveryMethods[name] = method
	s.logger.WithFields(logrus.Fields{
		"method":       name,
		"type":         method.GetType(),
		"capabilities": method.GetCapabilities(),
	}).Info("Discovery method registered")

	return nil
}

// StartDiscovery initiates a new asset discovery session
func (s *AssetDiscoveryService) StartDiscovery(ctx context.Context, config DiscoveryConfig) (*DiscoverySession, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"method":    config.Method,
		"tenant_id": config.TenantID,
		"scope":     config.Scope,
	})

	logger.Info("Starting asset discovery")

	// Validate configuration
	if err := s.validateDiscoveryConfig(config); err != nil {
		logger.WithError(err).Error("Invalid discovery configuration")
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Get discovery method
	method, exists := s.discoveryMethods[config.Method]
	if !exists {
		return nil, fmt.Errorf("discovery method %s not found", config.Method)
	}

	if !method.IsEnabled() {
		return nil, fmt.Errorf("discovery method %s is disabled", config.Method)
	}

	// Create discovery session
	sessionCtx, cancel := context.WithCancel(ctx)
	session := &DiscoverySession{
		ID:         uuid.New(),
		Config:     config,
		Status:     DiscoveryStatusPending,
		Progress:   0.0,
		StartTime:  time.Now().UTC(),
		LastUpdate: time.Now().UTC(),
		Cancel:     cancel,
	}

	// Store active session
	s.mutex.Lock()
	s.activeDiscoveries[session.ID.String()] = session
	s.mutex.Unlock()

	// Start discovery in background
	go s.runDiscovery(sessionCtx, session, method)

	logger.WithField("session_id", session.ID).Info("Discovery session started")
	return session, nil
}

// GetDiscoverySession returns information about a discovery session
func (s *AssetDiscoveryService) GetDiscoverySession(sessionID uuid.UUID) (*DiscoverySession, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, exists := s.activeDiscoveries[sessionID.String()]
	if !exists {
		return nil, fmt.Errorf("discovery session %s not found", sessionID)
	}

	return session, nil
}

// CancelDiscovery cancels an active discovery session
func (s *AssetDiscoveryService) CancelDiscovery(sessionID uuid.UUID) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	session, exists := s.activeDiscoveries[sessionID.String()]
	if !exists {
		return fmt.Errorf("discovery session %s not found", sessionID)
	}

	if session.Cancel != nil {
		session.Cancel()
	}

	session.Status = DiscoveryStatusCancelled
	session.LastUpdate = time.Now().UTC()

	s.logger.WithField("session_id", sessionID).Info("Discovery session cancelled")
	return nil
}

// ListActiveSessions returns all active discovery sessions
func (s *AssetDiscoveryService) ListActiveSessions() []*DiscoverySession {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	sessions := make([]*DiscoverySession, 0, len(s.activeDiscoveries))
	for _, session := range s.activeDiscoveries {
		sessions = append(sessions, session)
	}

	// Sort by start time (newest first)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartTime.After(sessions[j].StartTime)
	})

	return sessions
}

// ProcessAgentHeartbeat processes heartbeat from security agent
func (s *AssetDiscoveryService) ProcessAgentHeartbeat(ctx context.Context, heartbeat AgentHeartbeat) error {
	logger := s.logger.WithFields(logrus.Fields{
		"agent_id":  heartbeat.AgentID,
		"tenant_id": heartbeat.TenantID,
		"hostname":  heartbeat.Hostname,
	})

	logger.Debug("Processing agent heartbeat")

	// Convert heartbeat to asset
	asset, err := s.convertHeartbeatToAsset(heartbeat)
	if err != nil {
		logger.WithError(err).Error("Failed to convert heartbeat to asset")
		return fmt.Errorf("heartbeat conversion failed: %w", err)
	}

	// Apply deduplication
	duplicates, err := s.deduplicationEngine.FindDuplicates(ctx, *asset)
	if err != nil {
		logger.WithError(err).Warn("Deduplication check failed")
	}

	if len(duplicates) > 0 {
		logger.WithField("duplicates_count", len(duplicates)).Debug("Found duplicate assets")
		// Handle deduplication based on rules
		asset, err = s.deduplicationEngine.HandleDuplicates(ctx, *asset, duplicates)
		if err != nil {
			logger.WithError(err).Error("Failed to handle duplicates")
			return fmt.Errorf("deduplication failed: %w", err)
		}
	}

	logger.Debug("Agent heartbeat processed successfully")
	return nil
}

// Private methods

func (s *AssetDiscoveryService) runDiscovery(ctx context.Context, session *DiscoverySession, method DiscoveryMethod) {
	logger := s.logger.WithFields(logrus.Fields{
		"session_id": session.ID,
		"method":     session.Config.Method,
	})

	logger.Info("Running discovery")

	// Update session status
	session.Status = DiscoveryStatusRunning
	session.LastUpdate = time.Now().UTC()

	// Create result structure
	result := &DiscoveryResult{
		SessionID:        session.ID,
		Method:           session.Config.Method,
		TenantID:         session.Config.TenantID,
		StartTime:        session.StartTime,
		Status:           DiscoveryStatusRunning,
		AssetsDiscovered: []entity.Asset{},
		AssetsUpdated:    []entity.Asset{},
		DeadAssets:       []uuid.UUID{},
		Errors:           []DiscoveryError{},
		Warnings:         []string{},
		Metadata:         make(map[string]interface{}),
	}

	session.Results = result

	// Run discovery
	discoveryResult, err := method.Discover(ctx, session.Config)
	if err != nil {
		logger.WithError(err).Error("Discovery failed")
		result.Status = DiscoveryStatusFailed
		result.Errors = append(result.Errors, DiscoveryError{
			Code:      "DISCOVERY_FAILED",
			Message:   err.Error(),
			Source:    session.Config.Method,
			Timestamp: time.Now().UTC(),
			Severity:  "error",
		})
	} else {
		// Merge results
		if discoveryResult != nil {
			result.AssetsDiscovered = discoveryResult.AssetsDiscovered
			result.AssetsUpdated = discoveryResult.AssetsUpdated
			result.NewAssets = discoveryResult.NewAssets
			result.UpdatedAssets = discoveryResult.UpdatedAssets
			result.DeadAssets = discoveryResult.DeadAssets
			result.Errors = append(result.Errors, discoveryResult.Errors...)
			result.Warnings = append(result.Warnings, discoveryResult.Warnings...)
			result.Statistics = discoveryResult.Statistics

			// Merge metadata
			for k, v := range discoveryResult.Metadata {
				result.Metadata[k] = v
			}
		}

		if len(result.Errors) == 0 {
			result.Status = DiscoveryStatusCompleted
		} else {
			result.Status = DiscoveryStatusPartial
		}
	}

	// Update session
	result.EndTime = time.Now().UTC()
	result.Duration = result.EndTime.Sub(result.StartTime)
	session.Status = result.Status
	session.Progress = 100.0
	session.LastUpdate = time.Now().UTC()

	// Clean up session after some time
	go func() {
		time.Sleep(24 * time.Hour) // Keep session for 24 hours
		s.mutex.Lock()
		delete(s.activeDiscoveries, session.ID.String())
		s.mutex.Unlock()
	}()

	logger.WithFields(logrus.Fields{
		"status":         result.Status,
		"duration":       result.Duration,
		"new_assets":     result.NewAssets,
		"updated_assets": result.UpdatedAssets,
		"errors":         len(result.Errors),
	}).Info("Discovery completed")
}

func (s *AssetDiscoveryService) validateDiscoveryConfig(config DiscoveryConfig) error {
	if config.Method == "" {
		return fmt.Errorf("discovery method is required")
	}

	if config.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	// Validate method-specific configuration
	method, exists := s.discoveryMethods[config.Method]
	if !exists {
		return fmt.Errorf("discovery method %s not found", config.Method)
	}

	return method.Validate(config)
}

func (s *AssetDiscoveryService) registerDefaultMethods() {
	// Register built-in discovery methods
	// These would be implemented as separate structures implementing DiscoveryMethod interface

	// Agent-based discovery
	agentMethod := &AgentDiscoveryMethod{
		name:         "agent",
		enabled:      true,
		capabilities: []string{"real_time", "detailed_inventory", "software_list", "running_processes"},
	}
	s.discoveryMethods["agent"] = agentMethod

	// Network discovery
	networkMethod := &NetworkDiscoveryMethod{
		name:         "network_scan",
		enabled:      true,
		capabilities: []string{"network_mapping", "port_scanning", "service_detection", "os_fingerprinting"},
	}
	s.discoveryMethods["network_scan"] = networkMethod

	// Cloud discovery
	cloudMethod := &CloudDiscoveryMethod{
		name:         "cloud_api",
		enabled:      true,
		capabilities: []string{"aws", "azure", "gcp", "resource_inventory", "tags", "metadata"},
	}
	s.discoveryMethods["cloud_api"] = cloudMethod
}

func (s *AssetDiscoveryService) convertHeartbeatToAsset(heartbeat AgentHeartbeat) (*entity.Asset, error) {
	asset := &entity.Asset{
		ID:              heartbeat.AgentID,
		TenantID:        heartbeat.TenantID,
		Name:            heartbeat.Hostname,
		DisplayName:     heartbeat.Hostname,
		AssetType:       s.determineAssetType(heartbeat),
		Criticality:     entity.CriticalityMedium, // Default, will be classified
		IPAddresses:     heartbeat.IPAddresses,
		MACAddresses:    heartbeat.MACAddresses,
		HostNames:       []string{heartbeat.Hostname},
		OperatingSystem: heartbeat.OperatingSystem,
		Hardware:        heartbeat.Hardware,
		Software:        heartbeat.Software,
		Services:        heartbeat.Services,
		Status:          entity.AssetStatusActive,
		DiscoveryMethod: "agent",
		FirstDiscovered: time.Now().UTC(),
		LastSeen:        heartbeat.Timestamp,
		LastUpdated:     time.Now().UTC(),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		Tags:            []entity.AssetTag{},
		CustomFields:    make(map[string]string),
		ExternalIDs:     make(map[string]string),
	}

	// Set external ID for agent tracking
	asset.ExternalIDs["agent_id"] = heartbeat.AgentID.String()

	return asset, nil
}

func (s *AssetDiscoveryService) determineAssetType(heartbeat AgentHeartbeat) entity.AssetType {
	// Basic asset type determination based on OS and characteristics
	switch strings.ToLower(heartbeat.OperatingSystem.Name) {
	case "windows":
		// Check if it's a server or workstation
		if strings.Contains(strings.ToLower(heartbeat.OperatingSystem.Edition), "server") {
			return entity.AssetTypeServer
		}
		return entity.AssetTypeEndpoint
	case "linux":
		// Most Linux systems in enterprise are servers
		return entity.AssetTypeServer
	case "macos":
		return entity.AssetTypeEndpoint
	case "ios":
		return entity.AssetTypeMobile
	case "android":
		return entity.AssetTypeMobile
	default:
		return entity.AssetTypeEndpoint
	}
}

// AgentHeartbeat represents data from security agent
type AgentHeartbeat struct {
	AgentID         uuid.UUID                  `json:"agent_id"`
	TenantID        uuid.UUID                  `json:"tenant_id"`
	Hostname        string                     `json:"hostname"`
	IPAddresses     []string                   `json:"ip_addresses"`
	MACAddresses    []string                   `json:"mac_addresses"`
	OperatingSystem entity.OperatingSystemInfo `json:"operating_system"`
	Hardware        entity.HardwareInfo        `json:"hardware"`
	Software        []entity.SoftwareComponent `json:"software"`
	Services        []entity.ServiceInfo       `json:"services"`
	Timestamp       time.Time                  `json:"timestamp"`
	AgentVersion    string                     `json:"agent_version"`
	Capabilities    []string                   `json:"capabilities"`
}

// NewDeduplicationEngine creates a new deduplication engine
func NewDeduplicationEngine(logger *logrus.Logger) *DeduplicationEngine {
	return &DeduplicationEngine{
		rules:  createDefaultDeduplicationRules(),
		logger: logger,
	}
}

// FindDuplicates finds potential duplicate assets
func (e *DeduplicationEngine) FindDuplicates(ctx context.Context, asset entity.Asset) ([]entity.Asset, error) {
	// This would query the database for potential duplicates
	// For now, return empty slice
	return []entity.Asset{}, nil
}

// HandleDuplicates handles duplicate assets based on rules
func (e *DeduplicationEngine) HandleDuplicates(ctx context.Context, asset entity.Asset, duplicates []entity.Asset) (*entity.Asset, error) {
	// This would implement deduplication logic
	// For now, return original asset
	return &asset, nil
}

// Default configurations and stub implementations

func createDefaultDiscoveryConfiguration() DiscoveryConfiguration {
	return DiscoveryConfiguration{
		EnabledMethods: []string{"agent", "network_scan", "cloud_api"},
		DiscoverySchedule: map[string]string{
			"agent":        "@every 5m",
			"network_scan": "0 2 * * *", // Daily at 2 AM
			"cloud_api":    "0 1 * * *", // Daily at 1 AM
		},
		NetworkRanges: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		ExcludedRanges: []string{
			"127.0.0.0/8",
			"169.254.0.0/16",
			"224.0.0.0/4",
		},
		AgentConfiguration: AgentDiscoveryConfig{
			HeartbeatInterval:    5 * time.Minute,
			OfflineThreshold:     15 * time.Minute,
			RequiredCapabilities: []string{"process_monitoring", "network_monitoring"},
			CollectionFrequency:  time.Hour,
		},
		PerformanceSettings: PerformanceSettings{
			MaxConcurrentScans: 10,
			ScanTimeout:        30 * time.Minute,
			PortScanTimeout:    5 * time.Second,
			MaxPortsPerHost:    1000,
			RateLimitRPS:       100,
			BatchSize:          100,
		},
		NotificationSettings: NotificationSettings{
			EnableNewAssetAlerts:     true,
			EnableMissingAssetAlerts: true,
			AlertRecipients:          []string{"security@isectech.com"},
			AlertThresholds: map[string]int{
				"new_assets_per_hour":     50,
				"missing_assets_per_hour": 10,
			},
		},
	}
}

func createDefaultDeduplicationRules() []DeduplicationRule {
	return []DeduplicationRule{
		{
			Name:     "IP Address Match",
			Priority: 100,
			Conditions: []DeduplicationCondition{
				{Field: "ip_addresses", Weight: 0.8, Exact: true},
			},
			Action:     DeduplicationActionMerge,
			Confidence: 0.9,
		},
		{
			Name:     "MAC Address Match",
			Priority: 95,
			Conditions: []DeduplicationCondition{
				{Field: "mac_addresses", Weight: 0.9, Exact: true},
			},
			Action:     DeduplicationActionMerge,
			Confidence: 0.95,
		},
		{
			Name:     "Hostname Match",
			Priority: 85,
			Conditions: []DeduplicationCondition{
				{Field: "host_names", Weight: 0.7, Exact: false},
			},
			Action:     DeduplicationActionFlag,
			Confidence: 0.8,
		},
	}
}

// Stub implementations for discovery methods

type AgentDiscoveryMethod struct {
	name         string
	enabled      bool
	capabilities []string
}

func (m *AgentDiscoveryMethod) GetName() string           { return m.name }
func (m *AgentDiscoveryMethod) GetType() DiscoveryType    { return DiscoveryTypeAgent }
func (m *AgentDiscoveryMethod) IsEnabled() bool           { return m.enabled }
func (m *AgentDiscoveryMethod) GetCapabilities() []string { return m.capabilities }

func (m *AgentDiscoveryMethod) Discover(ctx context.Context, config DiscoveryConfig) (*DiscoveryResult, error) {
	// Stub implementation
	return &DiscoveryResult{
		Status:           DiscoveryStatusCompleted,
		AssetsDiscovered: []entity.Asset{},
		Statistics:       DiscoveryStatistics{},
	}, nil
}

func (m *AgentDiscoveryMethod) Validate(config DiscoveryConfig) error {
	return nil
}

type NetworkDiscoveryMethod struct {
	name         string
	enabled      bool
	capabilities []string
}

func (m *NetworkDiscoveryMethod) GetName() string           { return m.name }
func (m *NetworkDiscoveryMethod) GetType() DiscoveryType    { return DiscoveryTypeNetwork }
func (m *NetworkDiscoveryMethod) IsEnabled() bool           { return m.enabled }
func (m *NetworkDiscoveryMethod) GetCapabilities() []string { return m.capabilities }

func (m *NetworkDiscoveryMethod) Discover(ctx context.Context, config DiscoveryConfig) (*DiscoveryResult, error) {
	// Stub implementation
	return &DiscoveryResult{
		Status:           DiscoveryStatusCompleted,
		AssetsDiscovered: []entity.Asset{},
		Statistics:       DiscoveryStatistics{},
	}, nil
}

func (m *NetworkDiscoveryMethod) Validate(config DiscoveryConfig) error {
	return nil
}

type CloudDiscoveryMethod struct {
	name         string
	enabled      bool
	capabilities []string
}

func (m *CloudDiscoveryMethod) GetName() string           { return m.name }
func (m *CloudDiscoveryMethod) GetType() DiscoveryType    { return DiscoveryTypeCloud }
func (m *CloudDiscoveryMethod) IsEnabled() bool           { return m.enabled }
func (m *CloudDiscoveryMethod) GetCapabilities() []string { return m.capabilities }

func (m *CloudDiscoveryMethod) Discover(ctx context.Context, config DiscoveryConfig) (*DiscoveryResult, error) {
	// Stub implementation
	return &DiscoveryResult{
		Status:           DiscoveryStatusCompleted,
		AssetsDiscovered: []entity.Asset{},
		Statistics:       DiscoveryStatistics{},
	}, nil
}

func (m *CloudDiscoveryMethod) Validate(config DiscoveryConfig) error {
	return nil
}
