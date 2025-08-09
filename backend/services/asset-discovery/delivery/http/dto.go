package http

// DTOs for HTTP API requests and responses

// Discovery DTOs

type DiscoveryRequestDTO struct {
	TenantID         string                `json:"tenant_id" binding:"required"`
	TargetScope      DiscoveryScopeDTO     `json:"target_scope" binding:"required"`
	DiscoveryMethods []string              `json:"discovery_methods" binding:"required"`
	ScanOptions      ScanOptionsDTO        `json:"scan_options"`
	Credentials      []CredentialDTO       `json:"credentials,omitempty"`
	Priority         string                `json:"priority"`
	ScheduleType     string                `json:"schedule_type"`
	Metadata         map[string]string     `json:"metadata,omitempty"`
}

type DiscoveryScopeDTO struct {
	IPRanges      []string `json:"ip_ranges,omitempty"`
	Hostnames     []string `json:"hostnames,omitempty"`
	Domains       []string `json:"domains,omitempty"`
	CloudAccounts []string `json:"cloud_accounts,omitempty"`
	Subnets       []string `json:"subnets,omitempty"`
	NetworkZones  []string `json:"network_zones,omitempty"`
	ExcludeRanges []string `json:"exclude_ranges,omitempty"`
}

type ScanOptionsDTO struct {
	Timeout            int64             `json:"timeout,omitempty"`             // seconds
	MaxConcurrency     int               `json:"max_concurrency,omitempty"`
	RateLimit          int               `json:"rate_limit,omitempty"`          // requests per second
	RetryAttempts      int               `json:"retry_attempts,omitempty"`
	RetryDelay         int64             `json:"retry_delay,omitempty"`         // seconds
	PortRanges         []string          `json:"port_ranges,omitempty"`
	ScanTechnique      string            `json:"scan_technique,omitempty"`
	ServiceDetection   bool              `json:"service_detection,omitempty"`
	VersionDetection   bool              `json:"version_detection,omitempty"`
	OSDetection        bool              `json:"os_detection,omitempty"`
	DeepInspection     bool              `json:"deep_inspection,omitempty"`
	GatherSoftware     bool              `json:"gather_software,omitempty"`
	GatherProcesses    bool              `json:"gather_processes,omitempty"`
	GatherServices     bool              `json:"gather_services,omitempty"`
	GatherCertificates bool              `json:"gather_certificates,omitempty"`
	GatherVulns        bool              `json:"gather_vulns,omitempty"`
	CloudRegions       []string          `json:"cloud_regions,omitempty"`
	CloudServices      []string          `json:"cloud_services,omitempty"`
	CustomScripts      []CustomScriptDTO `json:"custom_scripts,omitempty"`
}

type CustomScriptDTO struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Script     string            `json:"script"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Timeout    int64             `json:"timeout,omitempty"` // seconds
}

type CredentialDTO struct {
	Type        string            `json:"type"`
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

type DiscoveryResultDTO struct {
	RequestID      string             `json:"request_id"`
	TenantID       string             `json:"tenant_id"`
	Status         string             `json:"status"`
	StartTime      string             `json:"start_time"`
	EndTime        string             `json:"end_time,omitempty"`
	Duration       int64              `json:"duration"` // seconds
	AssetsFound    int                `json:"assets_found"`
	AssetsUpdated  int                `json:"assets_updated"`
	AssetsNew      int                `json:"assets_new"`
	TargetsScanned int                `json:"targets_scanned"`
	TargetsTotal   int                `json:"targets_total"`
	SuccessRate    float64            `json:"success_rate"`
	Assets         []*AssetDTO        `json:"assets"`
	Errors         []DiscoveryErrorDTO `json:"errors,omitempty"`
	Warnings       []DiscoveryWarningDTO `json:"warnings,omitempty"`
	Statistics     *DiscoveryStatisticsDTO `json:"statistics,omitempty"`
	Metadata       map[string]string  `json:"metadata,omitempty"`
}

type DiscoveryErrorDTO struct {
	Target      string `json:"target"`
	Method      string `json:"method"`
	Error       string `json:"error"`
	Timestamp   string `json:"timestamp"`
	Severity    string `json:"severity"`
	Recoverable bool   `json:"recoverable"`
}

type DiscoveryWarningDTO struct {
	Target    string `json:"target"`
	Method    string `json:"method"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type DiscoveryStatisticsDTO struct {
	MethodStats      map[string]*MethodStatisticsDTO `json:"method_stats,omitempty"`
	AssetTypeStats   map[string]int                  `json:"asset_type_stats,omitempty"`
	NetworkStats     *NetworkDiscoveryStatsDTO       `json:"network_stats,omitempty"`
	PerformanceStats *PerformanceStatsDTO            `json:"performance_stats,omitempty"`
}

type MethodStatisticsDTO struct {
	TargetsScanned  int     `json:"targets_scanned"`
	AssetsFound     int     `json:"assets_found"`
	Errors          int     `json:"errors"`
	AvgResponseTime int64   `json:"avg_response_time"` // milliseconds
	SuccessRate     float64 `json:"success_rate"`
}

type NetworkDiscoveryStatsDTO struct {
	IPsScanned       int            `json:"ips_scanned"`
	ResponsiveIPs    int            `json:"responsive_ips"`
	PortsScanned     int            `json:"ports_scanned"`
	OpenPorts        int            `json:"open_ports"`
	ServicesDetected int            `json:"services_detected"`
	PortDistribution map[int]int    `json:"port_distribution,omitempty"`
}

type PerformanceStatsDTO struct {
	TotalRequests     int64   `json:"total_requests"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	AvgResponseTime   int64   `json:"avg_response_time"` // milliseconds
	MaxResponseTime   int64   `json:"max_response_time"` // milliseconds
	MinResponseTime   int64   `json:"min_response_time"` // milliseconds
	Timeouts          int     `json:"timeouts"`
	Retries           int     `json:"retries"`
}

type ScanProgressDTO struct {
	RequestID          string  `json:"request_id"`
	Status             string  `json:"status"`
	PercentComplete    float64 `json:"percent_complete"`
	CurrentTarget      string  `json:"current_target"`
	TargetsCompleted   int     `json:"targets_completed"`
	TargetsTotal       int     `json:"targets_total"`
	AssetsFound        int     `json:"assets_found"`
	ElapsedTime        int64   `json:"elapsed_time"`        // seconds
	EstimatedRemaining int64   `json:"estimated_remaining"` // seconds
}

// Asset DTOs

type AssetDTO struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	Name            string          `json:"name" binding:"required"`
	DisplayName     string          `json:"display_name"`
	Description     string          `json:"description"`
	AssetType       string          `json:"asset_type" binding:"required"`
	Status          string          `json:"status"`
	RiskLevel       string          `json:"risk_level"`
	Owner           string          `json:"owner"`
	Department      string          `json:"department"`
	BusinessUnit    string          `json:"business_unit"`
	Environment     string          `json:"environment"`
	Criticality     string          `json:"criticality"`
	Tags            []string        `json:"tags,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	NetworkInfo     *NetworkInfoDTO `json:"network_info,omitempty"`
	SystemInfo      *SystemInfoDTO  `json:"system_info,omitempty"`
	SecurityInfo    *SecurityInfoDTO `json:"security_info,omitempty"`
	DiscoveryMethod string          `json:"discovery_method"`
	DiscoverySource string          `json:"discovery_source"`
	FirstDiscovered string          `json:"first_discovered"`
	LastSeen        string          `json:"last_seen"`
	LastUpdated     string          `json:"last_updated"`
	ScanFrequency   string          `json:"scan_frequency"`
	NextScanTime    string          `json:"next_scan_time,omitempty"`
	Fingerprint     string          `json:"fingerprint"`
	Checksum        string          `json:"checksum"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
	Version         int             `json:"version"`
}

type NetworkInfoDTO struct {
	IPAddress     string     `json:"ip_address"`
	IPVersion     string     `json:"ip_version"`
	MACAddress    string     `json:"mac_address"`
	Hostname      string     `json:"hostname"`
	FQDN          string     `json:"fqdn"`
	DNSNames      []string   `json:"dns_names,omitempty"`
	OpenPorts     []PortDTO  `json:"open_ports,omitempty"`
	NetworkZone   string     `json:"network_zone"`
	VLAN          string     `json:"vlan"`
	Subnet        string     `json:"subnet"`
	Gateway       string     `json:"gateway"`
	PublicIP      string     `json:"public_ip"`
	GeoLocation   *GeoInfoDTO `json:"geo_location,omitempty"`
}

type PortDTO struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Banner   string `json:"banner"`
	State    string `json:"state"`
}

type GeoInfoDTO struct {
	Country   string  `json:"country"`
	Region    string  `json:"region"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
	ASN       string  `json:"asn"`
}

type SystemInfoDTO struct {
	OperatingSystem  string                 `json:"operating_system"`
	OSVersion        string                 `json:"os_version"`
	Architecture     string                 `json:"architecture"`
	Kernel           string                 `json:"kernel"`
	Uptime           int64                  `json:"uptime"` // seconds
	SystemTime       string                 `json:"system_time,omitempty"`
	TimeZone         string                 `json:"time_zone"`
	CPUInfo          *CPUInfoDTO            `json:"cpu_info,omitempty"`
	MemoryInfo       *MemoryInfoDTO         `json:"memory_info,omitempty"`
	DiskInfo         []DiskInfoDTO          `json:"disk_info,omitempty"`
	InstalledSoftware []SoftwarePackageDTO  `json:"installed_software,omitempty"`
	Processes        []ProcessInfoDTO       `json:"processes,omitempty"`
	Services         []ServiceInfoDTO       `json:"services,omitempty"`
}

type CPUInfoDTO struct {
	Model   string  `json:"model"`
	Cores   int     `json:"cores"`
	Threads int     `json:"threads"`
	Speed   string  `json:"speed"`
	Usage   float64 `json:"usage"`
}

type MemoryInfoDTO struct {
	Total     int64   `json:"total"`
	Available int64   `json:"available"`
	Used      int64   `json:"used"`
	Usage     float64 `json:"usage"`
}

type DiskInfoDTO struct {
	Device     string  `json:"device"`
	MountPoint string  `json:"mount_point"`
	FileSystem string  `json:"file_system"`
	Total      int64   `json:"total"`
	Used       int64   `json:"used"`
	Available  int64   `json:"available"`
	Usage      float64 `json:"usage"`
}

type SoftwarePackageDTO struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Vendor      string `json:"vendor"`
	InstallDate string `json:"install_date,omitempty"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type ProcessInfoDTO struct {
	PID         int     `json:"pid"`
	Name        string  `json:"name"`
	Command     string  `json:"command"`
	User        string  `json:"user"`
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage int64   `json:"memory_usage"`
}

type ServiceInfoDTO struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	User        string `json:"user"`
}

type SecurityInfoDTO struct {
	LastVulnScan     string                     `json:"last_vuln_scan,omitempty"`
	VulnCount        *VulnerabilityCountDTO     `json:"vuln_count,omitempty"`
	ComplianceStatus *ComplianceStatusDTO       `json:"compliance_status,omitempty"`
	SecurityTools    []SecurityToolDTO          `json:"security_tools,omitempty"`
	CertificateInfo  []CertificateInfoDTO       `json:"certificate_info,omitempty"`
	LastSecurityEvent string                    `json:"last_security_event,omitempty"`
	ThreatLevel      string                     `json:"threat_level"`
	Anomalies        []AnomalyInfoDTO           `json:"anomalies,omitempty"`
}

type VulnerabilityCountDTO struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

type ComplianceStatusDTO struct {
	SOC2            string `json:"soc2"`
	ISO27001        string `json:"iso27001"`
	NIST            string `json:"nist"`
	PCI             string `json:"pci"`
	HIPAA           string `json:"hipaa"`
	GDPR            string `json:"gdpr"`
	CustomFramework string `json:"custom_framework"`
}

type SecurityToolDTO struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Version       string `json:"version"`
	Status        string `json:"status"`
	LastUpdate    string `json:"last_update,omitempty"`
	Configuration string `json:"configuration"`
}

type CertificateInfoDTO struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
	Fingerprint  string `json:"fingerprint"`
	KeySize      int    `json:"key_size"`
	IsValid      bool   `json:"is_valid"`
	IsExpired    bool   `json:"is_expired"`
}

type AnomalyInfoDTO struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	DetectedAt  string  `json:"detected_at"`
	Confidence  float64 `json:"confidence"`
}

// Response DTOs

type AssetListResponseDTO struct {
	Assets     []*AssetDTO    `json:"assets"`
	Pagination *PaginationDTO `json:"pagination"`
}

type PaginationDTO struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	TotalPages int   `json:"total_pages"`
	TotalItems int64 `json:"total_items"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

type AssetAggregationDTO struct {
	TotalAssets         int64                         `json:"total_assets"`
	AssetsByType        map[string]int64              `json:"assets_by_type"`
	AssetsByStatus      map[string]int64              `json:"assets_by_status"`
	AssetsByRisk        map[string]int64              `json:"assets_by_risk"`
	AssetsByEnvironment map[string]int64              `json:"assets_by_environment"`
	VulnStats           *VulnerabilityStatsDTO        `json:"vulnerability_stats,omitempty"`
	ComplianceStats     *ComplianceStatsDTO           `json:"compliance_stats,omitempty"`
	NetworkStats        *NetworkStatsDTO              `json:"network_stats,omitempty"`
}

type VulnerabilityStatsDTO struct {
	TotalVulns      int64            `json:"total_vulnerabilities"`
	VulnsBySeverity map[string]int64 `json:"vulnerabilities_by_severity"`
	AssetsWithVulns int64            `json:"assets_with_vulnerabilities"`
	AvgVulnScore    float64          `json:"average_vulnerability_score"`
}

type ComplianceStatsDTO struct {
	FrameworkStats map[string]*ComplianceFrameworkStatsDTO `json:"framework_stats"`
	OverallScore   float64                                 `json:"overall_compliance_score"`
}

type ComplianceFrameworkStatsDTO struct {
	Compliant    int64   `json:"compliant"`
	NonCompliant int64   `json:"non_compliant"`
	Unknown      int64   `json:"unknown"`
	Score        float64 `json:"compliance_score"`
}

type NetworkStatsDTO struct {
	TotalIPs       int64            `json:"total_ips"`
	UniqueNetworks int64            `json:"unique_networks"`
	OpenPortStats  map[int]int64    `json:"open_port_stats"`
	NetworkZones   map[string]int64 `json:"network_zones"`
}

// Error response DTOs

type ErrorResponseDTO struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
	Code    string                 `json:"code,omitempty"`
}

type ValidationErrorDTO struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

type ValidationErrorResponseDTO struct {
	Error  string                `json:"error"`
	Errors []ValidationErrorDTO  `json:"validation_errors"`
}