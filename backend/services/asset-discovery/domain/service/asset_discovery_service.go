package service

import (
	"context"
	"net"
	"time"

	"github.com/google/uuid"
	"asset-discovery/domain/entity"
	"asset-discovery/domain/repository"
)

// DiscoveryRequest represents a request for asset discovery
type DiscoveryRequest struct {
	TenantID        uuid.UUID         `json:"tenant_id"`
	TargetScope     DiscoveryScope    `json:"target_scope"`
	DiscoveryMethods []DiscoveryMethod `json:"discovery_methods"`
	ScanOptions     ScanOptions       `json:"scan_options"`
	Credentials     []Credential      `json:"credentials,omitempty"`
	Priority        DiscoveryPriority `json:"priority"`
	ScheduleType    ScheduleType      `json:"schedule_type"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// DiscoveryScope defines the scope of discovery
type DiscoveryScope struct {
	IPRanges      []string  `json:"ip_ranges"`      // CIDR ranges to scan
	Hostnames     []string  `json:"hostnames"`      // Specific hostnames
	Domains       []string  `json:"domains"`        // Domain names for DNS discovery
	CloudAccounts []string  `json:"cloud_accounts"` // Cloud account IDs
	Subnets       []string  `json:"subnets"`        // Specific subnets
	NetworkZones  []string  `json:"network_zones"`  // Network zones/segments
	ExcludeRanges []string  `json:"exclude_ranges"` // IP ranges to exclude
}

// DiscoveryMethod represents different discovery approaches
type DiscoveryMethod string

const (
	DiscoveryMethodPing          DiscoveryMethod = "ping"
	DiscoveryMethodPortScan      DiscoveryMethod = "port_scan"
	DiscoveryMethodServiceScan   DiscoveryMethod = "service_scan"
	DiscoveryMethodSNMP          DiscoveryMethod = "snmp"
	DiscoveryMethodWMI           DiscoveryMethod = "wmi"
	DiscoveryMethodSSH           DiscoveryMethod = "ssh"
	DiscoveryMethodNetBIOS       DiscoveryMethod = "netbios"
	DiscoveryMethodDNS           DiscoveryMethod = "dns"
	DiscoveryMethodLDAP          DiscoveryMethod = "ldap"
	DiscoveryMethodAgent         DiscoveryMethod = "agent"
	DiscoveryMethodCloud         DiscoveryMethod = "cloud_api"
	DiscoveryMethodPassive       DiscoveryMethod = "passive"
	DiscoveryMethodVulnScan      DiscoveryMethod = "vulnerability_scan"
	DiscoveryMethodAssetImport   DiscoveryMethod = "asset_import"
)

// ScanOptions contains configuration for discovery scans
type ScanOptions struct {
	// Timing and performance
	Timeout           time.Duration `json:"timeout"`
	MaxConcurrency    int           `json:"max_concurrency"`
	RateLimit         int           `json:"rate_limit"` // requests per second
	RetryAttempts     int           `json:"retry_attempts"`
	RetryDelay        time.Duration `json:"retry_delay"`
	
	// Port scanning options
	PortRanges        []string      `json:"port_ranges"`    // e.g., "1-1000", "80,443,8080"
	ScanTechnique     string        `json:"scan_technique"` // "tcp_connect", "tcp_syn", "udp"
	ServiceDetection  bool          `json:"service_detection"`
	VersionDetection  bool          `json:"version_detection"`
	OSDetection       bool          `json:"os_detection"`
	
	// Discovery depth
	DeepInspection    bool          `json:"deep_inspection"`
	GatherSoftware    bool          `json:"gather_software"`
	GatherProcesses   bool          `json:"gather_processes"`
	GatherServices    bool          `json:"gather_services"`
	GatherCertificates bool         `json:"gather_certificates"`
	GatherVulns       bool          `json:"gather_vulnerabilities"`
	
	// Cloud-specific options
	CloudRegions      []string      `json:"cloud_regions"`
	CloudServices     []string      `json:"cloud_services"`
	
	// Custom scripts
	CustomScripts     []CustomScript `json:"custom_scripts"`
}

// CustomScript represents a custom discovery script
type CustomScript struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`        // "nmap", "powershell", "bash", "python"
	Script      string            `json:"script"`
	Parameters  map[string]string `json:"parameters"`
	Timeout     time.Duration     `json:"timeout"`
}

// Credential represents authentication credentials for discovery
type Credential struct {
	Type        CredentialType    `json:"type"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	PrivateKey  string            `json:"private_key,omitempty"`
	Certificate string            `json:"certificate,omitempty"`
	Token       string            `json:"token,omitempty"`
	APIKey      string            `json:"api_key,omitempty"`
	SecretKey   string            `json:"secret_key,omitempty"`
	Domain      string            `json:"domain,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CredentialType represents different credential types
type CredentialType string

const (
	CredentialTypePassword    CredentialType = "password"
	CredentialTypeSSHKey      CredentialType = "ssh_key"
	CredentialTypeCertificate CredentialType = "certificate"
	CredentialTypeToken       CredentialType = "token"
	CredentialTypeAPIKey      CredentialType = "api_key"
	CredentialTypeAWS         CredentialType = "aws"
	CredentialTypeAzure       CredentialType = "azure"
	CredentialTypeGCP         CredentialType = "gcp"
	CredentialTypeSNMP        CredentialType = "snmp"
	CredentialTypeWMI         CredentialType = "wmi"
)

// DiscoveryPriority represents the priority level of discovery
type DiscoveryPriority string

const (
	DiscoveryPriorityLow      DiscoveryPriority = "low"
	DiscoveryPriorityMedium   DiscoveryPriority = "medium"
	DiscoveryPriorityHigh     DiscoveryPriority = "high"
	DiscoveryPriorityCritical DiscoveryPriority = "critical"
)

// ScheduleType represents the scheduling type for discovery
type ScheduleType string

const (
	ScheduleTypeImmediate ScheduleType = "immediate"
	ScheduleTypeScheduled ScheduleType = "scheduled"
	ScheduleTypeRecurring ScheduleType = "recurring"
	ScheduleTypeOnDemand  ScheduleType = "on_demand"
)

// DiscoveryResult represents the result of a discovery operation
type DiscoveryResult struct {
	RequestID      uuid.UUID              `json:"request_id"`
	TenantID       uuid.UUID              `json:"tenant_id"`
	Status         DiscoveryStatus        `json:"status"`
	StartTime      time.Time              `json:"start_time"`
	EndTime        *time.Time             `json:"end_time,omitempty"`
	Duration       time.Duration          `json:"duration"`
	AssetsFound    int                    `json:"assets_found"`
	AssetsUpdated  int                    `json:"assets_updated"`
	AssetsNew      int                    `json:"assets_new"`
	TargetsScanned int                    `json:"targets_scanned"`
	TargetsTotal   int                    `json:"targets_total"`
	SuccessRate    float64                `json:"success_rate"`
	Assets         []*entity.Asset        `json:"assets"`
	Errors         []DiscoveryError       `json:"errors"`
	Warnings       []DiscoveryWarning     `json:"warnings"`
	Statistics     DiscoveryStatistics    `json:"statistics"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// DiscoveryStatus represents the status of a discovery operation
type DiscoveryStatus string

const (
	DiscoveryStatusPending    DiscoveryStatus = "pending"
	DiscoveryStatusRunning    DiscoveryStatus = "running"
	DiscoveryStatusCompleted  DiscoveryStatus = "completed"
	DiscoveryStatusFailed     DiscoveryStatus = "failed"
	DiscoveryStatusCancelled  DiscoveryStatus = "cancelled"
	DiscoveryStatusPartial    DiscoveryStatus = "partial"
)

// DiscoveryError represents an error during discovery
type DiscoveryError struct {
	Target      string    `json:"target"`
	Method      string    `json:"method"`
	Error       string    `json:"error"`
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	Recoverable bool      `json:"recoverable"`
}

// DiscoveryWarning represents a warning during discovery
type DiscoveryWarning struct {
	Target    string    `json:"target"`
	Method    string    `json:"method"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// DiscoveryStatistics contains detailed statistics about the discovery
type DiscoveryStatistics struct {
	MethodStats     map[string]MethodStatistics `json:"method_stats"`
	AssetTypeStats  map[string]int              `json:"asset_type_stats"`
	NetworkStats    NetworkDiscoveryStats       `json:"network_stats"`
	PerformanceStats PerformanceStats           `json:"performance_stats"`
}

// MethodStatistics contains statistics for a specific discovery method
type MethodStatistics struct {
	TargetsScanned int           `json:"targets_scanned"`
	AssetsFound    int           `json:"assets_found"`
	Errors         int           `json:"errors"`
	AvgResponseTime time.Duration `json:"avg_response_time"`
	SuccessRate    float64       `json:"success_rate"`
}

// NetworkDiscoveryStats contains network-specific discovery statistics
type NetworkDiscoveryStats struct {
	IPsScanned       int            `json:"ips_scanned"`
	ResponsiveIPs    int            `json:"responsive_ips"`
	PortsScanned     int            `json:"ports_scanned"`
	OpenPorts        int            `json:"open_ports"`
	ServicesDetected int            `json:"services_detected"`
	PortDistribution map[int]int    `json:"port_distribution"`
}

// PerformanceStats contains performance-related statistics
type PerformanceStats struct {
	TotalRequests     int64         `json:"total_requests"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	AvgResponseTime   time.Duration `json:"avg_response_time"`
	MaxResponseTime   time.Duration `json:"max_response_time"`
	MinResponseTime   time.Duration `json:"min_response_time"`
	Timeouts          int           `json:"timeouts"`
	Retries           int           `json:"retries"`
}

// ScanProgress represents the progress of an ongoing scan
type ScanProgress struct {
	RequestID        uuid.UUID `json:"request_id"`
	Status           DiscoveryStatus `json:"status"`
	PercentComplete  float64   `json:"percent_complete"`
	CurrentTarget    string    `json:"current_target"`
	TargetsCompleted int       `json:"targets_completed"`
	TargetsTotal     int       `json:"targets_total"`
	AssetsFound      int       `json:"assets_found"`
	ElapsedTime      time.Duration `json:"elapsed_time"`
	EstimatedRemaining time.Duration `json:"estimated_remaining"`
}

// AssetEnrichmentService defines methods for enriching asset information
type AssetEnrichmentService interface {
	// Enrich asset with additional information
	EnrichAsset(ctx context.Context, asset *entity.Asset) error
	
	// Gather system information
	GatherSystemInfo(ctx context.Context, asset *entity.Asset, creds []Credential) error
	
	// Gather security information
	GatherSecurityInfo(ctx context.Context, asset *entity.Asset) error
	
	// Perform vulnerability assessment
	PerformVulnerabilityAssessment(ctx context.Context, asset *entity.Asset) error
	
	// Check compliance status
	CheckCompliance(ctx context.Context, asset *entity.Asset, frameworks []string) error
	
	// Gather network information
	GatherNetworkInfo(ctx context.Context, asset *entity.Asset) error
	
	// Detect services and applications
	DetectServices(ctx context.Context, asset *entity.Asset) error
	
	// Fingerprint the asset
	FingerprintAsset(ctx context.Context, asset *entity.Asset) error
}

// NetworkScannerService defines methods for network-based asset discovery
type NetworkScannerService interface {
	// Perform ping scan
	PingScan(ctx context.Context, targets []string, options ScanOptions) ([]*entity.Asset, error)
	
	// Perform port scan
	PortScan(ctx context.Context, targets []string, options ScanOptions) ([]*entity.Asset, error)
	
	// Perform service detection
	ServiceScan(ctx context.Context, targets []string, options ScanOptions) ([]*entity.Asset, error)
	
	// Perform OS detection
	OSDetection(ctx context.Context, targets []string, options ScanOptions) ([]*entity.Asset, error)
	
	// Perform comprehensive scan
	ComprehensiveScan(ctx context.Context, targets []string, options ScanOptions) ([]*entity.Asset, error)
	
	// Validate target accessibility
	ValidateTargets(ctx context.Context, targets []string) ([]string, []string, error) // valid, invalid, error
}

// CloudDiscoveryService defines methods for cloud-based asset discovery
type CloudDiscoveryService interface {
	// Discover AWS assets
	DiscoverAWSAssets(ctx context.Context, tenantID uuid.UUID, creds Credential, regions []string) ([]*entity.Asset, error)
	
	// Discover Azure assets
	DiscoverAzureAssets(ctx context.Context, tenantID uuid.UUID, creds Credential, subscriptions []string) ([]*entity.Asset, error)
	
	// Discover GCP assets
	DiscoverGCPAssets(ctx context.Context, tenantID uuid.UUID, creds Credential, projects []string) ([]*entity.Asset, error)
	
	// Discover Kubernetes assets
	DiscoverKubernetesAssets(ctx context.Context, tenantID uuid.UUID, creds Credential, clusters []string) ([]*entity.Asset, error)
	
	// Discover Docker containers
	DiscoverDockerAssets(ctx context.Context, tenantID uuid.UUID, creds Credential, hosts []string) ([]*entity.Asset, error)
}

// AssetDiscoveryService defines the main interface for asset discovery operations
type AssetDiscoveryService interface {
	// Discovery operations
	StartDiscovery(ctx context.Context, request DiscoveryRequest) (*DiscoveryResult, error)
	GetDiscoveryStatus(ctx context.Context, requestID uuid.UUID) (*ScanProgress, error)
	CancelDiscovery(ctx context.Context, requestID uuid.UUID) error
	
	// Scheduled discovery
	ScheduleDiscovery(ctx context.Context, request DiscoveryRequest, schedule string) (uuid.UUID, error)
	UpdateScheduledDiscovery(ctx context.Context, scheduleID uuid.UUID, request DiscoveryRequest) error
	DeleteScheduledDiscovery(ctx context.Context, scheduleID uuid.UUID) error
	ListScheduledDiscoveries(ctx context.Context, tenantID uuid.UUID) ([]ScheduledDiscovery, error)
	
	// Asset management
	DiscoverSingleAsset(ctx context.Context, tenantID uuid.UUID, target string, methods []DiscoveryMethod) (*entity.Asset, error)
	RefreshAsset(ctx context.Context, assetID uuid.UUID) (*entity.Asset, error)
	RefreshAssetsByFilter(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) (int, error)
	
	// Asset enrichment
	EnrichAsset(ctx context.Context, assetID uuid.UUID) error
	EnrichAssetsByFilter(ctx context.Context, tenantID uuid.UUID, filter repository.AssetFilter) (int, error)
	
	// Asset correlation and deduplication
	DeduplicateAssets(ctx context.Context, tenantID uuid.UUID) (int, error)
	CorrelateAssets(ctx context.Context, tenantID uuid.UUID) error
	MergeAssets(ctx context.Context, primaryAssetID uuid.UUID, duplicateAssetIDs []uuid.UUID) error
	
	// Asset validation
	ValidateAssets(ctx context.Context, tenantID uuid.UUID) (*AssetValidationResult, error)
	ValidateAsset(ctx context.Context, assetID uuid.UUID) (*AssetValidationResult, error)
	
	// Asset lifecycle management
	MarkAssetsStale(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int, error)
	CleanupStaleAssets(ctx context.Context, tenantID uuid.UUID, staleDuration time.Duration) (int, error)
	ArchiveAssets(ctx context.Context, assetIDs []uuid.UUID) error
	RestoreAssets(ctx context.Context, assetIDs []uuid.UUID) error
	
	// Discovery history and analytics
	GetDiscoveryHistory(ctx context.Context, tenantID uuid.UUID, filter DiscoveryHistoryFilter) ([]DiscoveryResult, error)
	GetDiscoveryAnalytics(ctx context.Context, tenantID uuid.UUID, timeRange time.Duration) (*DiscoveryAnalytics, error)
	
	// Configuration and preferences
	GetDiscoveryConfig(ctx context.Context, tenantID uuid.UUID) (*DiscoveryConfig, error)
	UpdateDiscoveryConfig(ctx context.Context, tenantID uuid.UUID, config *DiscoveryConfig) error
	
	// Health and monitoring
	HealthCheck(ctx context.Context) error
	GetMetrics(ctx context.Context) (*DiscoveryMetrics, error)
	GetActiveScans(ctx context.Context) ([]ScanProgress, error)
}

// ScheduledDiscovery represents a scheduled discovery operation
type ScheduledDiscovery struct {
	ID           uuid.UUID        `json:"id"`
	TenantID     uuid.UUID        `json:"tenant_id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Request      DiscoveryRequest `json:"request"`
	Schedule     string           `json:"schedule"` // Cron expression
	Enabled      bool             `json:"enabled"`
	NextRun      *time.Time       `json:"next_run"`
	LastRun      *time.Time       `json:"last_run"`
	LastResult   *DiscoveryResult `json:"last_result,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// AssetValidationResult represents the result of asset validation
type AssetValidationResult struct {
	Valid           bool                  `json:"valid"`
	Errors          []ValidationError     `json:"errors"`
	Warnings        []ValidationWarning   `json:"warnings"`
	ValidatedAssets int                   `json:"validated_assets"`
	FixedAssets     int                   `json:"fixed_assets"`
}

// ValidationError represents a validation error
type ValidationError struct {
	AssetID uuid.UUID `json:"asset_id"`
	Field   string    `json:"field"`
	Error   string    `json:"error"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	AssetID uuid.UUID `json:"asset_id"`
	Field   string    `json:"field"`
	Warning string    `json:"warning"`
}

// DiscoveryHistoryFilter represents filtering options for discovery history
type DiscoveryHistoryFilter struct {
	StartTime *time.Time         `json:"start_time,omitempty"`
	EndTime   *time.Time         `json:"end_time,omitempty"`
	Status    []DiscoveryStatus  `json:"status,omitempty"`
	Methods   []DiscoveryMethod  `json:"methods,omitempty"`
	Limit     int                `json:"limit"`
	Offset    int                `json:"offset"`
}

// DiscoveryAnalytics represents analytics data for discovery operations
type DiscoveryAnalytics struct {
	TotalScans          int                    `json:"total_scans"`
	SuccessfulScans     int                    `json:"successful_scans"`
	FailedScans         int                    `json:"failed_scans"`
	AvgScanDuration     time.Duration          `json:"avg_scan_duration"`
	TotalAssetsFound    int                    `json:"total_assets_found"`
	NewAssetsFound      int                    `json:"new_assets_found"`
	AssetsUpdated       int                    `json:"assets_updated"`
	ScansByMethod       map[string]int         `json:"scans_by_method"`
	AssetsByType        map[string]int         `json:"assets_by_type"`
	ErrorsByType        map[string]int         `json:"errors_by_type"`
	PerformanceTrends   []PerformanceTrend     `json:"performance_trends"`
}

// PerformanceTrend represents performance trends over time
type PerformanceTrend struct {
	Timestamp       time.Time     `json:"timestamp"`
	ScanDuration    time.Duration `json:"scan_duration"`
	AssetsFound     int           `json:"assets_found"`
	RequestsPerSec  float64       `json:"requests_per_sec"`
	SuccessRate     float64       `json:"success_rate"`
}

// DiscoveryConfig represents configuration for discovery operations
type DiscoveryConfig struct {
	TenantID            uuid.UUID     `json:"tenant_id"`
	DefaultScanOptions  ScanOptions   `json:"default_scan_options"`
	DefaultCredentials  []Credential  `json:"default_credentials"`
	ExcludeRanges       []string      `json:"exclude_ranges"`
	IncludeRanges       []string      `json:"include_ranges"`
	ScanFrequency       time.Duration `json:"scan_frequency"`
	MaxConcurrentScans  int           `json:"max_concurrent_scans"`
	RetentionPeriod     time.Duration `json:"retention_period"`
	NotificationSettings NotificationSettings `json:"notification_settings"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// NotificationSettings represents notification preferences
type NotificationSettings struct {
	EnableEmail      bool     `json:"enable_email"`
	EmailAddresses   []string `json:"email_addresses"`
	EnableWebhook    bool     `json:"enable_webhook"`
	WebhookURL       string   `json:"webhook_url"`
	EnableSlack      bool     `json:"enable_slack"`
	SlackChannel     string   `json:"slack_channel"`
	NotifyOnComplete bool     `json:"notify_on_complete"`
	NotifyOnError    bool     `json:"notify_on_error"`
	NotifyOnHighRisk bool     `json:"notify_on_high_risk"`
}

// DiscoveryMetrics represents metrics for discovery operations
type DiscoveryMetrics struct {
	ActiveScans        int           `json:"active_scans"`
	QueuedScans        int           `json:"queued_scans"`
	CompletedScans24h  int           `json:"completed_scans_24h"`
	FailedScans24h     int           `json:"failed_scans_24h"`
	AvgScanDuration    time.Duration `json:"avg_scan_duration"`
	TotalAssetsManaged int64         `json:"total_assets_managed"`
	AssetsAddedToday   int           `json:"assets_added_today"`
	AssetsUpdatedToday int           `json:"assets_updated_today"`
	SystemLoad         float64       `json:"system_load"`
	MemoryUsage        float64       `json:"memory_usage"`
	CPUUsage           float64       `json:"cpu_usage"`
}