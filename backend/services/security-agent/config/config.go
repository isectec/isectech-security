package config

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config represents the security agent configuration
type Config struct {
	Server        ServerConfig        `mapstructure:"server"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Security      SecurityConfig      `mapstructure:"security"`
	Communication CommunicationConfig `mapstructure:"communication"`
	Agent         AgentConfig         `mapstructure:"agent"`
	Monitoring    MonitoringConfig    `mapstructure:"monitoring"`
	Logging       LoggingConfig       `mapstructure:"logging"`
}

// ServerConfig contains HTTP/gRPC server configuration
type ServerConfig struct {
	HTTPPort        int           `mapstructure:"http_port"`
	GRPCPort        int           `mapstructure:"grpc_port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	MaxHeaderSize   int           `mapstructure:"max_header_size"`
	EnableTLS       bool          `mapstructure:"enable_tls"`
	TLSCertPath     string        `mapstructure:"tls_cert_path"`
	TLSKeyPath      string        `mapstructure:"tls_key_path"`
	EnableProfiling bool          `mapstructure:"enable_profiling"`
	EnableMetrics   bool          `mapstructure:"enable_metrics"`
}

// DatabaseConfig contains local SQLite configuration
type DatabaseConfig struct {
	Path              string        `mapstructure:"path"`
	MaxConnections    int           `mapstructure:"max_connections"`
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
	EnableEncryption  bool          `mapstructure:"enable_encryption"`
	EncryptionKey     string        `mapstructure:"encryption_key"`
	BackupInterval    time.Duration `mapstructure:"backup_interval"`
	BackupRetention   int           `mapstructure:"backup_retention"`
	VacuumInterval    time.Duration `mapstructure:"vacuum_interval"`
	EnableWAL         bool          `mapstructure:"enable_wal"`
	SynchronousMode   string        `mapstructure:"synchronous_mode"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	EnableTamperResistance bool                     `mapstructure:"enable_tamper_resistance"`
	EnableCodeSigning      bool                     `mapstructure:"enable_code_signing"`
	SigningCertPath        string                   `mapstructure:"signing_cert_path"`
	EnableAntiDebugging    bool                     `mapstructure:"enable_anti_debugging"`
	TrustedCertificates    []string                 `mapstructure:"trusted_certificates"`
	CertificatePinning     CertificatePinningConfig `mapstructure:"certificate_pinning"`
	EncryptionSettings     EncryptionConfig         `mapstructure:"encryption"`
	AuditLogSettings       AuditLogConfig           `mapstructure:"audit_log"`
}

// CertificatePinningConfig contains certificate pinning settings
type CertificatePinningConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	Pins              []string `mapstructure:"pins"`
	BackupPins        []string `mapstructure:"backup_pins"`
	MaxAge            int      `mapstructure:"max_age"`
	IncludeSubdomains bool     `mapstructure:"include_subdomains"`
}

// EncryptionConfig contains encryption settings
type EncryptionConfig struct {
	Algorithm        string        `mapstructure:"algorithm"`
	KeySize          int           `mapstructure:"key_size"`
	LocalKeyPath     string        `mapstructure:"local_key_path"`
	RotationInterval time.Duration `mapstructure:"rotation_interval"`
	EnableHSM        bool          `mapstructure:"enable_hsm"`
	HSMConfig        HSMConfig     `mapstructure:"hsm"`
}

// HSMConfig contains Hardware Security Module settings
type HSMConfig struct {
	Provider    string            `mapstructure:"provider"`
	LibraryPath string            `mapstructure:"library_path"`
	SlotID      int               `mapstructure:"slot_id"`
	Pin         string            `mapstructure:"pin"`
	KeyLabel    string            `mapstructure:"key_label"`
	Attributes  map[string]string `mapstructure:"attributes"`
}

// AuditLogConfig contains audit logging settings
type AuditLogConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Path           string        `mapstructure:"path"`
	MaxSize        int           `mapstructure:"max_size"`
	MaxBackups     int           `mapstructure:"max_backups"`
	MaxAge         int           `mapstructure:"max_age"`
	Compress       bool          `mapstructure:"compress"`
	LocalBuffer    bool          `mapstructure:"local_buffer"`
	BufferSize     int           `mapstructure:"buffer_size"`
	FlushInterval  time.Duration `mapstructure:"flush_interval"`
	SignEntries    bool          `mapstructure:"sign_entries"`
	EncryptEntries bool          `mapstructure:"encrypt_entries"`
}

// CommunicationConfig contains backend communication settings
type CommunicationConfig struct {
	BackendURL         string            `mapstructure:"backend_url"`
	EnableMTLS         bool              `mapstructure:"enable_mtls"`
	ClientCertPath     string            `mapstructure:"client_cert_path"`
	ClientKeyPath      string            `mapstructure:"client_key_path"`
	CACertPath         string            `mapstructure:"ca_cert_path"`
	TLSVersion         string            `mapstructure:"tls_version"`
	CipherSuites       []string          `mapstructure:"cipher_suites"`
	ConnectTimeout     time.Duration     `mapstructure:"connect_timeout"`
	RequestTimeout     time.Duration     `mapstructure:"request_timeout"`
	RetryPolicy        RetryPolicyConfig `mapstructure:"retry_policy"`
	CompressionEnabled bool              `mapstructure:"compression_enabled"`
	KeepAliveInterval  time.Duration     `mapstructure:"keep_alive_interval"`
	MaxIdleConnections int               `mapstructure:"max_idle_connections"`
	MaxConnections     int               `mapstructure:"max_connections"`
	EnableHeartbeat    bool              `mapstructure:"enable_heartbeat"`
	HeartbeatInterval  time.Duration     `mapstructure:"heartbeat_interval"`
}

// RetryPolicyConfig contains retry policy settings
type RetryPolicyConfig struct {
	MaxRetries      int           `mapstructure:"max_retries"`
	InitialInterval time.Duration `mapstructure:"initial_interval"`
	MaxInterval     time.Duration `mapstructure:"max_interval"`
	Multiplier      float64       `mapstructure:"multiplier"`
	RandomJitter    bool          `mapstructure:"random_jitter"`
}

// AgentConfig contains agent-specific settings
type AgentConfig struct {
	ID                string                  `mapstructure:"id"`
	Name              string                  `mapstructure:"name"`
	Version           string                  `mapstructure:"version"`
	Environment       string                  `mapstructure:"environment"`
	UpdateSettings    UpdateConfig            `mapstructure:"update"`
	ResourceLimits    ResourceLimitsConfig    `mapstructure:"resource_limits"`
	OfflineMode       OfflineModeConfig       `mapstructure:"offline_mode"`
	DataCollection    DataCollectionConfig    `mapstructure:"data_collection"`
	PolicyEnforcement PolicyEnforcementConfig `mapstructure:"policy_enforcement"`
	TelemetrySettings TelemetryConfig         `mapstructure:"telemetry"`
	PlatformSpecific  PlatformSpecificConfig  `mapstructure:"platform_specific"`
}

// UpdateConfig contains auto-update settings
type UpdateConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	CheckInterval    time.Duration `mapstructure:"check_interval"`
	UpdateChannel    string        `mapstructure:"update_channel"`
	UpdateURL        string        `mapstructure:"update_url"`
	EnableRollback   bool          `mapstructure:"enable_rollback"`
	RollbackTimeout  time.Duration `mapstructure:"rollback_timeout"`
	VerifySignatures bool          `mapstructure:"verify_signatures"`
	StagedRollout    bool          `mapstructure:"staged_rollout"`
	MaxDownloadSize  int64         `mapstructure:"max_download_size"`
	UpdateWindow     UpdateWindow  `mapstructure:"update_window"`
}

// UpdateWindow defines when updates can be installed
type UpdateWindow struct {
	Enabled   bool     `mapstructure:"enabled"`
	StartTime string   `mapstructure:"start_time"`
	EndTime   string   `mapstructure:"end_time"`
	Days      []string `mapstructure:"days"`
	Timezone  string   `mapstructure:"timezone"`
}

// ResourceLimitsConfig contains resource usage limits
type ResourceLimitsConfig struct {
	MaxCPUPercent   float64         `mapstructure:"max_cpu_percent"`
	MaxMemoryMB     int             `mapstructure:"max_memory_mb"`
	MaxDiskMB       int             `mapstructure:"max_disk_mb"`
	MaxNetworkKbps  int             `mapstructure:"max_network_kbps"`
	MonitorInterval time.Duration   `mapstructure:"monitor_interval"`
	EnforceLimits   bool            `mapstructure:"enforce_limits"`
	AlertThresholds AlertThresholds `mapstructure:"alert_thresholds"`
}

// AlertThresholds defines when to alert on resource usage
type AlertThresholds struct {
	CPUPercent     float64 `mapstructure:"cpu_percent"`
	MemoryPercent  float64 `mapstructure:"memory_percent"`
	DiskPercent    float64 `mapstructure:"disk_percent"`
	NetworkPercent float64 `mapstructure:"network_percent"`
}

// OfflineModeConfig contains offline operation settings
type OfflineModeConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	MaxOfflineHours    int           `mapstructure:"max_offline_hours"`
	LocalBufferSize    int           `mapstructure:"local_buffer_size"`
	CompressionEnabled bool          `mapstructure:"compression_enabled"`
	PriorityQueuing    bool          `mapstructure:"priority_queuing"`
	SyncInterval       time.Duration `mapstructure:"sync_interval"`
	ConflictResolution string        `mapstructure:"conflict_resolution"`
}

// DataCollectionConfig contains data collection settings
type DataCollectionConfig struct {
	ProcessMonitoring      ProcessMonitoringConfig      `mapstructure:"process_monitoring"`
	NetworkMonitoring      NetworkMonitoringConfig      `mapstructure:"network_monitoring"`
	FileSystemMonitoring   FileSystemMonitoringConfig   `mapstructure:"filesystem_monitoring"`
	RegistryMonitoring     RegistryMonitoringConfig     `mapstructure:"registry_monitoring"`
	UserActivityMonitoring UserActivityMonitoringConfig `mapstructure:"user_activity_monitoring"`
	ApplicationInventory   ApplicationInventoryConfig   `mapstructure:"application_inventory"`
	VulnerabilityScanning  VulnerabilityScanningConfig  `mapstructure:"vulnerability_scanning"`
}

// ProcessMonitoringConfig contains process monitoring settings
type ProcessMonitoringConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	SamplingRate       float64       `mapstructure:"sampling_rate"`
	CollectArguments   bool          `mapstructure:"collect_arguments"`
	CollectEnvironment bool          `mapstructure:"collect_environment"`
	CollectModules     bool          `mapstructure:"collect_modules"`
	CollectNetworks    bool          `mapstructure:"collect_networks"`
	MonitorChildren    bool          `mapstructure:"monitor_children"`
	ExcludeProcesses   []string      `mapstructure:"exclude_processes"`
	MaxProcessAge      time.Duration `mapstructure:"max_process_age"`
	HashExecutables    bool          `mapstructure:"hash_executables"`
}

// NetworkMonitoringConfig contains network monitoring settings
type NetworkMonitoringConfig struct {
	Enabled            bool     `mapstructure:"enabled"`
	MonitorDNS         bool     `mapstructure:"monitor_dns"`
	MonitorHTTP        bool     `mapstructure:"monitor_http"`
	MonitorTLS         bool     `mapstructure:"monitor_tls"`
	CapturePayloads    bool     `mapstructure:"capture_payloads"`
	MaxPayloadSize     int      `mapstructure:"max_payload_size"`
	ExcludeNetworks    []string `mapstructure:"exclude_networks"`
	ExcludePorts       []int    `mapstructure:"exclude_ports"`
	SamplingRate       float64  `mapstructure:"sampling_rate"`
	GeoLocationEnabled bool     `mapstructure:"geo_location_enabled"`
}

// FileSystemMonitoringConfig contains file system monitoring settings
type FileSystemMonitoringConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	MonitorReads        bool     `mapstructure:"monitor_reads"`
	MonitorWrites       bool     `mapstructure:"monitor_writes"`
	MonitorDeletes      bool     `mapstructure:"monitor_deletes"`
	MonitorPermissions  bool     `mapstructure:"monitor_permissions"`
	HashFiles           bool     `mapstructure:"hash_files"`
	MaxFileSize         int64    `mapstructure:"max_file_size"`
	ExcludePaths        []string `mapstructure:"exclude_paths"`
	ExcludeExtensions   []string `mapstructure:"exclude_extensions"`
	RecursiveMonitoring bool     `mapstructure:"recursive_monitoring"`
	MaxDepth            int      `mapstructure:"max_depth"`
}

// RegistryMonitoringConfig contains Windows registry monitoring settings
type RegistryMonitoringConfig struct {
	Enabled         bool     `mapstructure:"enabled"`
	MonitorKeys     []string `mapstructure:"monitor_keys"`
	ExcludeKeys     []string `mapstructure:"exclude_keys"`
	MonitorValues   bool     `mapstructure:"monitor_values"`
	MonitorSecurity bool     `mapstructure:"monitor_security"`
	SamplingRate    float64  `mapstructure:"sampling_rate"`
}

// UserActivityMonitoringConfig contains user activity monitoring settings
type UserActivityMonitoringConfig struct {
	Enabled                bool          `mapstructure:"enabled"`
	MonitorLogins          bool          `mapstructure:"monitor_logins"`
	MonitorLogouts         bool          `mapstructure:"monitor_logouts"`
	MonitorFailedAuth      bool          `mapstructure:"monitor_failed_auth"`
	MonitorPrivEsc         bool          `mapstructure:"monitor_priv_esc"`
	SessionTimeout         time.Duration `mapstructure:"session_timeout"`
	ExcludeUsers           []string      `mapstructure:"exclude_users"`
	ExcludeServiceAccounts bool          `mapstructure:"exclude_service_accounts"`
}

// ApplicationInventoryConfig contains application inventory settings
type ApplicationInventoryConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	ScanInterval      time.Duration `mapstructure:"scan_interval"`
	IncludeVersions   bool          `mapstructure:"include_versions"`
	IncludeSignatures bool          `mapstructure:"include_signatures"`
	IncludeHashes     bool          `mapstructure:"include_hashes"`
	ExcludePaths      []string      `mapstructure:"exclude_paths"`
	ScanDepth         int           `mapstructure:"scan_depth"`
}

// VulnerabilityScanningConfig contains vulnerability scanning settings
type VulnerabilityScanningConfig struct {
	Enabled          bool          `mapstructure:"enabled"`
	ScanInterval     time.Duration `mapstructure:"scan_interval"`
	ScanDepth        string        `mapstructure:"scan_depth"`
	IncludeOS        bool          `mapstructure:"include_os"`
	IncludeApps      bool          `mapstructure:"include_apps"`
	IncludeLibraries bool          `mapstructure:"include_libraries"`
	CVEDatabase      string        `mapstructure:"cve_database"`
	UpdateInterval   time.Duration `mapstructure:"update_interval"`
	RiskThreshold    string        `mapstructure:"risk_threshold"`
}

// PolicyEnforcementConfig contains policy enforcement settings
type PolicyEnforcementConfig struct {
	Enabled                bool                     `mapstructure:"enabled"`
	ProcessControl         ProcessControlConfig     `mapstructure:"process_control"`
	NetworkControl         NetworkControlConfig     `mapstructure:"network_control"`
	FileControl            FileControlConfig        `mapstructure:"file_control"`
	ApplicationControl     ApplicationControlConfig `mapstructure:"application_control"`
	UserSessionControl     UserSessionControlConfig `mapstructure:"user_session_control"`
	EnforcementMode        string                   `mapstructure:"enforcement_mode"`
	DryRunMode             bool                     `mapstructure:"dry_run_mode"`
	AlertBeforeEnforcement bool                     `mapstructure:"alert_before_enforcement"`
	EnforcementDelay       time.Duration            `mapstructure:"enforcement_delay"`
}

// ProcessControlConfig contains process control enforcement settings
type ProcessControlConfig struct {
	Enabled             bool     `mapstructure:"enabled"`
	AllowProcessKill    bool     `mapstructure:"allow_process_kill"`
	AllowProcessSuspend bool     `mapstructure:"allow_process_suspend"`
	WhitelistEnabled    bool     `mapstructure:"whitelist_enabled"`
	BlacklistEnabled    bool     `mapstructure:"blacklist_enabled"`
	WhitelistPaths      []string `mapstructure:"whitelist_paths"`
	BlacklistPaths      []string `mapstructure:"blacklist_paths"`
	RequireSignatures   bool     `mapstructure:"require_signatures"`
	TrustedSigners      []string `mapstructure:"trusted_signers"`
}

// NetworkControlConfig contains network control enforcement settings
type NetworkControlConfig struct {
	Enabled              bool     `mapstructure:"enabled"`
	AllowConnectionBlock bool     `mapstructure:"allow_connection_block"`
	AllowTrafficShape    bool     `mapstructure:"allow_traffic_shape"`
	AllowDNSRedirect     bool     `mapstructure:"allow_dns_redirect"`
	BlockedDomains       []string `mapstructure:"blocked_domains"`
	BlockedIPs           []string `mapstructure:"blocked_ips"`
	AllowedPorts         []int    `mapstructure:"allowed_ports"`
	BlockedPorts         []int    `mapstructure:"blocked_ports"`
}

// FileControlConfig contains file control enforcement settings
type FileControlConfig struct {
	Enabled               bool     `mapstructure:"enabled"`
	AllowQuarantine       bool     `mapstructure:"allow_quarantine"`
	AllowDelete           bool     `mapstructure:"allow_delete"`
	AllowPermissionChange bool     `mapstructure:"allow_permission_change"`
	QuarantinePath        string   `mapstructure:"quarantine_path"`
	ProtectedPaths        []string `mapstructure:"protected_paths"`
	RestrictedExtensions  []string `mapstructure:"restricted_extensions"`
	RequireEncryption     bool     `mapstructure:"require_encryption"`
}

// ApplicationControlConfig contains application control enforcement settings
type ApplicationControlConfig struct {
	Enabled              bool     `mapstructure:"enabled"`
	WhitelistMode        bool     `mapstructure:"whitelist_mode"`
	BlacklistMode        bool     `mapstructure:"blacklist_mode"`
	AllowedApplications  []string `mapstructure:"allowed_applications"`
	BlockedApplications  []string `mapstructure:"blocked_applications"`
	RequireSignatures    bool     `mapstructure:"require_signatures"`
	AllowScriptExecution bool     `mapstructure:"allow_script_execution"`
	ScriptWhitelist      []string `mapstructure:"script_whitelist"`
}

// UserSessionControlConfig contains user session control enforcement settings
type UserSessionControlConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	AllowSessionKill   bool          `mapstructure:"allow_session_kill"`
	AllowUserLock      bool          `mapstructure:"allow_user_lock"`
	MaxSessionDuration time.Duration `mapstructure:"max_session_duration"`
	IdleTimeout        time.Duration `mapstructure:"idle_timeout"`
	ConcurrentSessions int           `mapstructure:"concurrent_sessions"`
	RestrictedUsers    []string      `mapstructure:"restricted_users"`
	PrivilegedUsers    []string      `mapstructure:"privileged_users"`
}

// TelemetryConfig contains telemetry settings
type TelemetryConfig struct {
	Enabled              bool                `mapstructure:"enabled"`
	CollectionInterval   time.Duration       `mapstructure:"collection_interval"`
	TransmissionInterval time.Duration       `mapstructure:"transmission_interval"`
	BatchSize            int                 `mapstructure:"batch_size"`
	CompressionEnabled   bool                `mapstructure:"compression_enabled"`
	EncryptionEnabled    bool                `mapstructure:"encryption_enabled"`
	LocalBuffering       bool                `mapstructure:"local_buffering"`
	BufferSize           int                 `mapstructure:"buffer_size"`
	Anonymization        AnonymizationConfig `mapstructure:"anonymization"`
}

// AnonymizationConfig contains data anonymization settings
type AnonymizationConfig struct {
	Enabled        bool            `mapstructure:"enabled"`
	AnonymizeIPs   bool            `mapstructure:"anonymize_ips"`
	AnonymizeUsers bool            `mapstructure:"anonymize_users"`
	AnonymizePaths bool            `mapstructure:"anonymize_paths"`
	HashSalt       string          `mapstructure:"hash_salt"`
	ExcludeFields  []string        `mapstructure:"exclude_fields"`
	RedactionRules []RedactionRule `mapstructure:"redaction_rules"`
}

// RedactionRule defines a rule for data redaction
type RedactionRule struct {
	Field   string `mapstructure:"field"`
	Pattern string `mapstructure:"pattern"`
	Replace string `mapstructure:"replace"`
}

// PlatformSpecificConfig contains platform-specific settings
type PlatformSpecificConfig struct {
	Windows WindowsConfig `mapstructure:"windows"`
	MacOS   MacOSConfig   `mapstructure:"macos"`
	Linux   LinuxConfig   `mapstructure:"linux"`
	Mobile  MobileConfig  `mapstructure:"mobile"`
}

// WindowsConfig contains Windows-specific settings
type WindowsConfig struct {
	ETWSettings      ETWConfig      `mapstructure:"etw"`
	WMISettings      WMIConfig      `mapstructure:"wmi"`
	ServiceSettings  ServiceConfig  `mapstructure:"service"`
	RegistrySettings RegistryConfig `mapstructure:"registry"`
}

// ETWConfig contains Event Tracing for Windows settings
type ETWConfig struct {
	Enabled          bool     `mapstructure:"enabled"`
	SessionName      string   `mapstructure:"session_name"`
	BufferSize       int      `mapstructure:"buffer_size"`
	MaxBuffers       int      `mapstructure:"max_buffers"`
	FlushTimer       int      `mapstructure:"flush_timer"`
	EnabledProviders []string `mapstructure:"enabled_providers"`
	LogLevel         string   `mapstructure:"log_level"`
}

// WMIConfig contains Windows Management Instrumentation settings
type WMIConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Namespace      string        `mapstructure:"namespace"`
	QueryTimeout   time.Duration `mapstructure:"query_timeout"`
	MaxConnections int           `mapstructure:"max_connections"`
	EnabledClasses []string      `mapstructure:"enabled_classes"`
}

// ServiceConfig contains Windows service settings
type ServiceConfig struct {
	ServiceName     string   `mapstructure:"service_name"`
	DisplayName     string   `mapstructure:"display_name"`
	Description     string   `mapstructure:"description"`
	StartType       string   `mapstructure:"start_type"`
	Dependencies    []string `mapstructure:"dependencies"`
	RecoveryActions []string `mapstructure:"recovery_actions"`
}

// RegistryConfig contains Windows registry settings
type RegistryConfig struct {
	MonitorHives    []string `mapstructure:"monitor_hives"`
	ExcludeKeys     []string `mapstructure:"exclude_keys"`
	BackupKeys      []string `mapstructure:"backup_keys"`
	RestoreOnTamper bool     `mapstructure:"restore_on_tamper"`
}

// MacOSConfig contains macOS-specific settings
type MacOSConfig struct {
	EndpointSecuritySettings EndpointSecurityConfig `mapstructure:"endpoint_security"`
	FSEventsSettings         FSEventsConfig         `mapstructure:"fs_events"`
	LaunchDaemonSettings     LaunchDaemonConfig     `mapstructure:"launch_daemon"`
	KeychainSettings         KeychainConfig         `mapstructure:"keychain"`
}

// EndpointSecurityConfig contains macOS Endpoint Security framework settings
type EndpointSecurityConfig struct {
	Enabled            bool          `mapstructure:"enabled"`
	RequireEntitlement bool          `mapstructure:"require_entitlement"`
	EnabledEvents      []string      `mapstructure:"enabled_events"`
	MuteProcesses      []string      `mapstructure:"mute_processes"`
	AuthRequests       bool          `mapstructure:"auth_requests"`
	AuthTimeout        time.Duration `mapstructure:"auth_timeout"`
}

// FSEventsConfig contains macOS File System Events settings
type FSEventsConfig struct {
	Enabled      bool          `mapstructure:"enabled"`
	WatchPaths   []string      `mapstructure:"watch_paths"`
	ExcludePaths []string      `mapstructure:"exclude_paths"`
	Latency      time.Duration `mapstructure:"latency"`
	WatchRoot    bool          `mapstructure:"watch_root"`
	IgnoreSelf   bool          `mapstructure:"ignore_self"`
	FileEvents   bool          `mapstructure:"file_events"`
}

// LaunchDaemonConfig contains macOS Launch Daemon settings
type LaunchDaemonConfig struct {
	Label                string            `mapstructure:"label"`
	ProgramArguments     []string          `mapstructure:"program_arguments"`
	RunAtLoad            bool              `mapstructure:"run_at_load"`
	KeepAlive            bool              `mapstructure:"keep_alive"`
	EnvironmentVariables map[string]string `mapstructure:"environment_variables"`
}

// KeychainConfig contains macOS Keychain settings
type KeychainConfig struct {
	UseSystemKeychain bool   `mapstructure:"use_system_keychain"`
	KeychainPath      string `mapstructure:"keychain_path"`
	CertificateLabel  string `mapstructure:"certificate_label"`
	KeyLabel          string `mapstructure:"key_label"`
}

// LinuxConfig contains Linux-specific settings
type LinuxConfig struct {
	EBPFSettings    EBPFConfig    `mapstructure:"ebpf"`
	SystemdSettings SystemdConfig `mapstructure:"systemd"`
	AuditdSettings  AuditdConfig  `mapstructure:"auditd"`
	InotifySettings InotifyConfig `mapstructure:"inotify"`
}

// EBPFConfig contains eBPF settings
type EBPFConfig struct {
	Enabled           bool     `mapstructure:"enabled"`
	RequirePrivileged bool     `mapstructure:"require_privileged"`
	Programs          []string `mapstructure:"programs"`
	MapTypes          []string `mapstructure:"map_types"`
	AttachPoints      []string `mapstructure:"attach_points"`
	CompilerOptions   []string `mapstructure:"compiler_options"`
	VerifierLog       bool     `mapstructure:"verifier_log"`
}

// SystemdConfig contains systemd settings
type SystemdConfig struct {
	ServiceName           string            `mapstructure:"service_name"`
	ServiceType           string            `mapstructure:"service_type"`
	ExecStart             string            `mapstructure:"exec_start"`
	Restart               string            `mapstructure:"restart"`
	RestartSec            int               `mapstructure:"restart_sec"`
	Environment           map[string]string `mapstructure:"environment"`
	CapabilityBoundingSet []string          `mapstructure:"capability_bounding_set"`
}

// AuditdConfig contains Linux audit daemon settings
type AuditdConfig struct {
	Enabled        bool     `mapstructure:"enabled"`
	Rules          []string `mapstructure:"rules"`
	LogFormat      string   `mapstructure:"log_format"`
	MaxLogFile     int      `mapstructure:"max_log_file"`
	NumLogs        int      `mapstructure:"num_logs"`
	FlushMode      string   `mapstructure:"flush_mode"`
	DispatcherPath string   `mapstructure:"dispatcher_path"`
}

// InotifyConfig contains Linux inotify settings
type InotifyConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	WatchPaths   []string `mapstructure:"watch_paths"`
	ExcludePaths []string `mapstructure:"exclude_paths"`
	Events       []string `mapstructure:"events"`
	Recursive    bool     `mapstructure:"recursive"`
	MaxWatches   int      `mapstructure:"max_watches"`
}

// MobileConfig contains mobile platform settings
type MobileConfig struct {
	IOSSettings     IOSConfig     `mapstructure:"ios"`
	AndroidSettings AndroidConfig `mapstructure:"android"`
}

// IOSConfig contains iOS-specific settings
type IOSConfig struct {
	MDMIntegration   bool              `mapstructure:"mdm_integration"`
	KeychainAccess   bool              `mapstructure:"keychain_access"`
	NetworkExtension bool              `mapstructure:"network_extension"`
	AppGroups        []string          `mapstructure:"app_groups"`
	Entitlements     map[string]string `mapstructure:"entitlements"`
	PrivacyUsage     map[string]string `mapstructure:"privacy_usage"`
}

// AndroidConfig contains Android-specific settings
type AndroidConfig struct {
	AdminRights          bool     `mapstructure:"admin_rights"`
	VPNService           bool     `mapstructure:"vpn_service"`
	AccessibilityService bool     `mapstructure:"accessibility_service"`
	Permissions          []string `mapstructure:"permissions"`
	IntentFilters        []string `mapstructure:"intent_filters"`
	WorkProfile          bool     `mapstructure:"work_profile"`
}

// MonitoringConfig contains monitoring and metrics settings
type MonitoringConfig struct {
	Enabled          bool                 `mapstructure:"enabled"`
	MetricsPort      int                  `mapstructure:"metrics_port"`
	HealthCheckPort  int                  `mapstructure:"health_check_port"`
	ProfilingEnabled bool                 `mapstructure:"profiling_enabled"`
	TracingEnabled   bool                 `mapstructure:"tracing_enabled"`
	TracingEndpoint  string               `mapstructure:"tracing_endpoint"`
	MetricsPrefix    string               `mapstructure:"metrics_prefix"`
	CustomMetrics    []CustomMetricConfig `mapstructure:"custom_metrics"`
	AlertingEnabled  bool                 `mapstructure:"alerting_enabled"`
	AlertingEndpoint string               `mapstructure:"alerting_endpoint"`
}

// CustomMetricConfig defines a custom metric
type CustomMetricConfig struct {
	Name        string            `mapstructure:"name"`
	Type        string            `mapstructure:"type"`
	Description string            `mapstructure:"description"`
	Labels      map[string]string `mapstructure:"labels"`
	Interval    time.Duration     `mapstructure:"interval"`
}

// LoggingConfig contains logging configuration
type LoggingConfig struct {
	Level            string            `mapstructure:"level"`
	Format           string            `mapstructure:"format"`
	Output           []string          `mapstructure:"output"`
	FileSettings     LogFileConfig     `mapstructure:"file"`
	SyslogSettings   SyslogConfig      `mapstructure:"syslog"`
	RemoteSettings   RemoteLogConfig   `mapstructure:"remote"`
	StructuredLogs   bool              `mapstructure:"structured_logs"`
	EnableCaller     bool              `mapstructure:"enable_caller"`
	EnableStackTrace bool              `mapstructure:"enable_stack_trace"`
	SamplingEnabled  bool              `mapstructure:"sampling_enabled"`
	SamplingRate     float64           `mapstructure:"sampling_rate"`
	Fields           map[string]string `mapstructure:"fields"`
	Filters          []LogFilterConfig `mapstructure:"filters"`
}

// LogFileConfig contains file logging settings
type LogFileConfig struct {
	Path       string `mapstructure:"path"`
	MaxSize    int    `mapstructure:"max_size"`
	MaxBackups int    `mapstructure:"max_backups"`
	MaxAge     int    `mapstructure:"max_age"`
	Compress   bool   `mapstructure:"compress"`
	LocalTime  bool   `mapstructure:"local_time"`
}

// SyslogConfig contains syslog settings
type SyslogConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Network  string `mapstructure:"network"`
	Address  string `mapstructure:"address"`
	Priority string `mapstructure:"priority"`
	Tag      string `mapstructure:"tag"`
	Facility string `mapstructure:"facility"`
}

// RemoteLogConfig contains remote logging settings
type RemoteLogConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	Endpoint      string            `mapstructure:"endpoint"`
	Protocol      string            `mapstructure:"protocol"`
	AuthToken     string            `mapstructure:"auth_token"`
	Headers       map[string]string `mapstructure:"headers"`
	Timeout       time.Duration     `mapstructure:"timeout"`
	RetryPolicy   RetryPolicyConfig `mapstructure:"retry_policy"`
	BufferSize    int               `mapstructure:"buffer_size"`
	FlushInterval time.Duration     `mapstructure:"flush_interval"`
}

// LogFilterConfig defines a log filter
type LogFilterConfig struct {
	Level   string `mapstructure:"level"`
	Pattern string `mapstructure:"pattern"`
	Action  string `mapstructure:"action"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.SetConfigType("yaml")

	// Set default values
	setDefaults()

	// Enable environment variable support
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ISECTECH_AGENT")

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.http_port", 8080)
	viper.SetDefault("server.grpc_port", 9090)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.shutdown_timeout", "30s")
	viper.SetDefault("server.max_header_size", 1048576)
	viper.SetDefault("server.enable_tls", true)
	viper.SetDefault("server.enable_metrics", true)

	// Database defaults
	viper.SetDefault("database.path", "./data/agent.db")
	viper.SetDefault("database.max_connections", 10)
	viper.SetDefault("database.connection_timeout", "10s")
	viper.SetDefault("database.enable_encryption", true)
	viper.SetDefault("database.backup_interval", "24h")
	viper.SetDefault("database.backup_retention", 7)
	viper.SetDefault("database.vacuum_interval", "168h")
	viper.SetDefault("database.enable_wal", true)
	viper.SetDefault("database.synchronous_mode", "NORMAL")

	// Security defaults
	viper.SetDefault("security.enable_tamper_resistance", true)
	viper.SetDefault("security.enable_code_signing", true)
	viper.SetDefault("security.enable_anti_debugging", true)
	viper.SetDefault("security.certificate_pinning.enabled", true)
	viper.SetDefault("security.encryption.algorithm", "AES-256-GCM")
	viper.SetDefault("security.encryption.key_size", 256)
	viper.SetDefault("security.audit_log.enabled", true)
	viper.SetDefault("security.audit_log.sign_entries", true)
	viper.SetDefault("security.audit_log.encrypt_entries", true)

	// Communication defaults
	viper.SetDefault("communication.enable_mtls", true)
	viper.SetDefault("communication.tls_version", "1.3")
	viper.SetDefault("communication.connect_timeout", "10s")
	viper.SetDefault("communication.request_timeout", "30s")
	viper.SetDefault("communication.compression_enabled", true)
	viper.SetDefault("communication.enable_heartbeat", true)
	viper.SetDefault("communication.heartbeat_interval", "30s")

	// Agent defaults
	viper.SetDefault("agent.environment", "production")
	viper.SetDefault("agent.update.enabled", true)
	viper.SetDefault("agent.update.check_interval", "1h")
	viper.SetDefault("agent.update.verify_signatures", true)
	viper.SetDefault("agent.resource_limits.max_cpu_percent", 2.0)
	viper.SetDefault("agent.resource_limits.max_memory_mb", 100)
	viper.SetDefault("agent.resource_limits.enforce_limits", true)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("logging.structured_logs", true)
	viper.SetDefault("logging.enable_caller", true)
	viper.SetDefault("logging.file.max_size", 100)
	viper.SetDefault("logging.file.max_backups", 10)
	viper.SetDefault("logging.file.max_age", 30)
	viper.SetDefault("logging.file.compress", true)
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate TLS configuration
	if config.Server.EnableTLS {
		if config.Server.TLSCertPath == "" || config.Server.TLSKeyPath == "" {
			return fmt.Errorf("TLS enabled but certificate or key path not specified")
		}
	}

	// Validate mTLS configuration
	if config.Communication.EnableMTLS {
		if config.Communication.ClientCertPath == "" || config.Communication.ClientKeyPath == "" {
			return fmt.Errorf("mTLS enabled but client certificate or key path not specified")
		}
	}

	// Validate resource limits
	if config.Agent.ResourceLimits.MaxCPUPercent <= 0 || config.Agent.ResourceLimits.MaxCPUPercent > 100 {
		return fmt.Errorf("invalid CPU limit: must be between 0 and 100")
	}

	if config.Agent.ResourceLimits.MaxMemoryMB <= 0 {
		return fmt.Errorf("invalid memory limit: must be greater than 0")
	}

	// Validate TLS version
	validTLSVersions := []string{"1.2", "1.3"}
	tlsValid := false
	for _, version := range validTLSVersions {
		if config.Communication.TLSVersion == version {
			tlsValid = true
			break
		}
	}
	if !tlsValid {
		return fmt.Errorf("invalid TLS version: must be 1.2 or 1.3")
	}

	return nil
}

// GetTLSConfig returns a TLS configuration based on the config
func (c *Config) GetTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		InsecureSkipVerify:       false,
	}
}
