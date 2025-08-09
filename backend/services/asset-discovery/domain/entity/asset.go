package entity

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AssetType represents the type of discovered asset
type AssetType string

const (
	AssetTypeEndpoint       AssetType = "endpoint"
	AssetTypeServer         AssetType = "server"
	AssetTypeNetworkDevice  AssetType = "network_device"
	AssetTypeCloudResource  AssetType = "cloud_resource"
	AssetTypeContainer      AssetType = "container"
	AssetTypeApplication    AssetType = "application"
	AssetTypeDatabase       AssetType = "database"
	AssetTypeIoTDevice      AssetType = "iot_device"
	AssetTypeUnknown        AssetType = "unknown"
)

// AssetStatus represents the current operational status
type AssetStatus string

const (
	AssetStatusActive      AssetStatus = "active"
	AssetStatusInactive    AssetStatus = "inactive"
	AssetStatusUnknown     AssetStatus = "unknown"
	AssetStatusMaintenance AssetStatus = "maintenance"
	AssetStatusRetired     AssetStatus = "retired"
)

// AssetRiskLevel represents the risk level assigned to an asset
type AssetRiskLevel string

const (
	AssetRiskCritical AssetRiskLevel = "critical"
	AssetRiskHigh     AssetRiskLevel = "high"
	AssetRiskMedium   AssetRiskLevel = "medium"
	AssetRiskLow      AssetRiskLevel = "low"
	AssetRiskUnknown  AssetRiskLevel = "unknown"
)

// NetworkInfo contains network-related information about the asset
type NetworkInfo struct {
	IPAddress     string   `json:"ip_address" db:"ip_address"`
	IPVersion     string   `json:"ip_version" db:"ip_version"`
	MACAddress    string   `json:"mac_address" db:"mac_address"`
	Hostname      string   `json:"hostname" db:"hostname"`
	FQDN          string   `json:"fqdn" db:"fqdn"`
	DNSNames      []string `json:"dns_names" db:"dns_names"`
	OpenPorts     []Port   `json:"open_ports" db:"open_ports"`
	NetworkZone   string   `json:"network_zone" db:"network_zone"`
	VLAN          string   `json:"vlan" db:"vlan"`
	Subnet        string   `json:"subnet" db:"subnet"`
	Gateway       string   `json:"gateway" db:"gateway"`
	PublicIP      string   `json:"public_ip" db:"public_ip"`
	GeoLocation   *GeoInfo `json:"geo_location,omitempty" db:"geo_location"`
}

// Port represents an open port on the asset
type Port struct {
	Number   int    `json:"number" db:"number"`
	Protocol string `json:"protocol" db:"protocol"`
	Service  string `json:"service" db:"service"`
	Version  string `json:"version" db:"version"`
	Banner   string `json:"banner" db:"banner"`
	State    string `json:"state" db:"state"`
}

// GeoInfo contains geographical information
type GeoInfo struct {
	Country   string  `json:"country" db:"country"`
	Region    string  `json:"region" db:"region"`
	City      string  `json:"city" db:"city"`
	Latitude  float64 `json:"latitude" db:"latitude"`
	Longitude float64 `json:"longitude" db:"longitude"`
	ISP       string  `json:"isp" db:"isp"`
	ASN       string  `json:"asn" db:"asn"`
}

// SystemInfo contains system-level information about the asset
type SystemInfo struct {
	OperatingSystem  string            `json:"operating_system" db:"operating_system"`
	OSVersion        string            `json:"os_version" db:"os_version"`
	Architecture     string            `json:"architecture" db:"architecture"`
	Kernel           string            `json:"kernel" db:"kernel"`
	Uptime           time.Duration     `json:"uptime" db:"uptime"`
	SystemTime       *time.Time        `json:"system_time,omitempty" db:"system_time"`
	TimeZone         string            `json:"time_zone" db:"time_zone"`
	CPUInfo          *CPUInfo          `json:"cpu_info,omitempty" db:"cpu_info"`
	MemoryInfo       *MemoryInfo       `json:"memory_info,omitempty" db:"memory_info"`
	DiskInfo         []DiskInfo        `json:"disk_info" db:"disk_info"`
	InstalledSoftware []SoftwarePackage `json:"installed_software" db:"installed_software"`
	Processes        []ProcessInfo     `json:"processes" db:"processes"`
	Services         []ServiceInfo     `json:"services" db:"services"`
}

// CPUInfo contains CPU information
type CPUInfo struct {
	Model    string `json:"model" db:"model"`
	Cores    int    `json:"cores" db:"cores"`
	Threads  int    `json:"threads" db:"threads"`
	Speed    string `json:"speed" db:"speed"`
	Usage    float64 `json:"usage" db:"usage"`
}

// MemoryInfo contains memory information
type MemoryInfo struct {
	Total     int64   `json:"total" db:"total"`
	Available int64   `json:"available" db:"available"`
	Used      int64   `json:"used" db:"used"`
	Usage     float64 `json:"usage" db:"usage"`
}

// DiskInfo contains disk information
type DiskInfo struct {
	Device    string  `json:"device" db:"device"`
	MountPoint string `json:"mount_point" db:"mount_point"`
	FileSystem string `json:"file_system" db:"file_system"`
	Total     int64   `json:"total" db:"total"`
	Used      int64   `json:"used" db:"used"`
	Available int64   `json:"available" db:"available"`
	Usage     float64 `json:"usage" db:"usage"`
}

// SoftwarePackage represents installed software
type SoftwarePackage struct {
	Name        string    `json:"name" db:"name"`
	Version     string    `json:"version" db:"version"`
	Vendor      string    `json:"vendor" db:"vendor"`
	InstallDate *time.Time `json:"install_date,omitempty" db:"install_date"`
	Description string    `json:"description" db:"description"`
	Category    string    `json:"category" db:"category"`
}

// ProcessInfo represents running processes
type ProcessInfo struct {
	PID         int    `json:"pid" db:"pid"`
	Name        string `json:"name" db:"name"`
	Command     string `json:"command" db:"command"`
	User        string `json:"user" db:"user"`
	CPUUsage    float64 `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage int64  `json:"memory_usage" db:"memory_usage"`
}

// ServiceInfo represents system services
type ServiceInfo struct {
	Name        string `json:"name" db:"name"`
	DisplayName string `json:"display_name" db:"display_name"`
	Status      string `json:"status" db:"status"`
	StartType   string `json:"start_type" db:"start_type"`
	User        string `json:"user" db:"user"`
}

// SecurityInfo contains security-related information
type SecurityInfo struct {
	LastVulnScan    *time.Time        `json:"last_vuln_scan,omitempty" db:"last_vuln_scan"`
	VulnCount       VulnerabilityCount `json:"vuln_count" db:"vuln_count"`
	ComplianceStatus ComplianceStatus  `json:"compliance_status" db:"compliance_status"`
	SecurityTools   []SecurityTool    `json:"security_tools" db:"security_tools"`
	CertificateInfo []CertificateInfo `json:"certificate_info" db:"certificate_info"`
	LastSecurityEvent *time.Time      `json:"last_security_event,omitempty" db:"last_security_event"`
	ThreatLevel     AssetRiskLevel    `json:"threat_level" db:"threat_level"`
	Anomalies       []AnomalyInfo     `json:"anomalies" db:"anomalies"`
}

// VulnerabilityCount represents vulnerability counts by severity
type VulnerabilityCount struct {
	Critical int `json:"critical" db:"critical"`
	High     int `json:"high" db:"high"`
	Medium   int `json:"medium" db:"medium"`
	Low      int `json:"low" db:"low"`
	Total    int `json:"total" db:"total"`
}

// ComplianceStatus represents compliance with various frameworks
type ComplianceStatus struct {
	SOC2        string `json:"soc2" db:"soc2"`
	ISO27001    string `json:"iso27001" db:"iso27001"`
	NIST        string `json:"nist" db:"nist"`
	PCI         string `json:"pci" db:"pci"`
	HIPAA       string `json:"hipaa" db:"hipaa"`
	GDPR        string `json:"gdpr" db:"gdpr"`
	CustomFramework string `json:"custom_framework" db:"custom_framework"`
}

// SecurityTool represents installed security tools
type SecurityTool struct {
	Name         string    `json:"name" db:"name"`
	Type         string    `json:"type" db:"type"`
	Version      string    `json:"version" db:"version"`
	Status       string    `json:"status" db:"status"`
	LastUpdate   *time.Time `json:"last_update,omitempty" db:"last_update"`
	Configuration string    `json:"configuration" db:"configuration"`
}

// CertificateInfo represents SSL/TLS certificate information
type CertificateInfo struct {
	Subject      string     `json:"subject" db:"subject"`
	Issuer       string     `json:"issuer" db:"issuer"`
	NotBefore    time.Time  `json:"not_before" db:"not_before"`
	NotAfter     time.Time  `json:"not_after" db:"not_after"`
	SerialNumber string     `json:"serial_number" db:"serial_number"`
	Fingerprint  string     `json:"fingerprint" db:"fingerprint"`
	KeySize      int        `json:"key_size" db:"key_size"`
	IsValid      bool       `json:"is_valid" db:"is_valid"`
	IsExpired    bool       `json:"is_expired" db:"is_expired"`
}

// AnomalyInfo represents detected anomalies
type AnomalyInfo struct {
	Type        string    `json:"type" db:"type"`
	Description string    `json:"description" db:"description"`
	Severity    string    `json:"severity" db:"severity"`
	DetectedAt  time.Time `json:"detected_at" db:"detected_at"`
	Confidence  float64   `json:"confidence" db:"confidence"`
}

// Asset represents a discovered asset in the network
type Asset struct {
	// Core identification
	ID           uuid.UUID   `json:"id" db:"id"`
	TenantID     uuid.UUID   `json:"tenant_id" db:"tenant_id"`
	Name         string      `json:"name" db:"name"`
	DisplayName  string      `json:"display_name" db:"display_name"`
	Description  string      `json:"description" db:"description"`
	AssetType    AssetType   `json:"asset_type" db:"asset_type"`
	Status       AssetStatus `json:"status" db:"status"`
	RiskLevel    AssetRiskLevel `json:"risk_level" db:"risk_level"`
	
	// Asset metadata
	Owner           string            `json:"owner" db:"owner"`
	Department      string            `json:"department" db:"department"`
	BusinessUnit    string            `json:"business_unit" db:"business_unit"`
	Environment     string            `json:"environment" db:"environment"` // prod, staging, dev, test
	Criticality     string            `json:"criticality" db:"criticality"` // critical, high, medium, low
	Tags            []string          `json:"tags" db:"tags"`
	Labels          map[string]string `json:"labels" db:"labels"`
	
	// Network information
	NetworkInfo *NetworkInfo `json:"network_info,omitempty" db:"network_info"`
	
	// System information
	SystemInfo *SystemInfo `json:"system_info,omitempty" db:"system_info"`
	
	// Security information
	SecurityInfo *SecurityInfo `json:"security_info,omitempty" db:"security_info"`
	
	// Discovery information
	DiscoveryMethod   string     `json:"discovery_method" db:"discovery_method"`
	DiscoverySource   string     `json:"discovery_source" db:"discovery_source"`
	FirstDiscovered   time.Time  `json:"first_discovered" db:"first_discovered"`
	LastSeen          time.Time  `json:"last_seen" db:"last_seen"`
	LastUpdated       time.Time  `json:"last_updated" db:"last_updated"`
	ScanFrequency     string     `json:"scan_frequency" db:"scan_frequency"`
	NextScanTime      *time.Time `json:"next_scan_time,omitempty" db:"next_scan_time"`
	
	// Data integrity
	Fingerprint string    `json:"fingerprint" db:"fingerprint"`
	Checksum    string    `json:"checksum" db:"checksum"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
	Version     int       `json:"version" db:"version"`
}

// NewAsset creates a new asset with default values
func NewAsset(tenantID uuid.UUID, name string, assetType AssetType) *Asset {
	now := time.Now()
	return &Asset{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Name:             name,
		DisplayName:      name,
		AssetType:        assetType,
		Status:           AssetStatusUnknown,
		RiskLevel:        AssetRiskUnknown,
		FirstDiscovered:  now,
		LastSeen:         now,
		LastUpdated:      now,
		CreatedAt:        now,
		UpdatedAt:        now,
		Version:          1,
		Labels:           make(map[string]string),
		Tags:             make([]string, 0),
	}
}

// Validate validates the asset entity
func (a *Asset) Validate() error {
	if a.ID == uuid.Nil {
		return fmt.Errorf("asset ID is required")
	}
	
	if a.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}
	
	if strings.TrimSpace(a.Name) == "" {
		return fmt.Errorf("asset name is required")
	}
	
	if a.AssetType == "" {
		return fmt.Errorf("asset type is required")
	}
	
	// Validate network info if present
	if a.NetworkInfo != nil {
		if err := a.validateNetworkInfo(); err != nil {
			return fmt.Errorf("invalid network info: %w", err)
		}
	}
	
	return nil
}

// validateNetworkInfo validates network information
func (a *Asset) validateNetworkInfo() error {
	if a.NetworkInfo.IPAddress != "" {
		if ip := net.ParseIP(a.NetworkInfo.IPAddress); ip == nil {
			return fmt.Errorf("invalid IP address: %s", a.NetworkInfo.IPAddress)
		}
	}
	
	for _, port := range a.NetworkInfo.OpenPorts {
		if port.Number < 1 || port.Number > 65535 {
			return fmt.Errorf("invalid port number: %d", port.Number)
		}
	}
	
	return nil
}

// UpdateLastSeen updates the last seen timestamp
func (a *Asset) UpdateLastSeen() {
	a.LastSeen = time.Now()
	a.LastUpdated = time.Now()
	a.Version++
}

// MarkAsActive marks the asset as active
func (a *Asset) MarkAsActive() {
	a.Status = AssetStatusActive
	a.UpdateLastSeen()
}

// MarkAsInactive marks the asset as inactive
func (a *Asset) MarkAsInactive() {
	a.Status = AssetStatusInactive
	a.LastUpdated = time.Now()
	a.Version++
}

// UpdateRiskLevel updates the risk level
func (a *Asset) UpdateRiskLevel(level AssetRiskLevel) {
	a.RiskLevel = level
	a.LastUpdated = time.Now()
	a.Version++
}

// AddTag adds a tag to the asset
func (a *Asset) AddTag(tag string) {
	if tag = strings.TrimSpace(tag); tag != "" {
		for _, existing := range a.Tags {
			if existing == tag {
				return // Tag already exists
			}
		}
		a.Tags = append(a.Tags, tag)
		a.LastUpdated = time.Now()
		a.Version++
	}
}

// RemoveTag removes a tag from the asset
func (a *Asset) RemoveTag(tag string) {
	for i, existing := range a.Tags {
		if existing == tag {
			a.Tags = append(a.Tags[:i], a.Tags[i+1:]...)
			a.LastUpdated = time.Now()
			a.Version++
			break
		}
	}
}

// SetLabel sets a label on the asset
func (a *Asset) SetLabel(key, value string) {
	if a.Labels == nil {
		a.Labels = make(map[string]string)
	}
	a.Labels[key] = value
	a.LastUpdated = time.Now()
	a.Version++
}

// RemoveLabel removes a label from the asset
func (a *Asset) RemoveLabel(key string) {
	if a.Labels != nil {
		delete(a.Labels, key)
		a.LastUpdated = time.Now()
		a.Version++
	}
}

// CalculateFingerprint calculates a fingerprint for the asset
func (a *Asset) CalculateFingerprint() string {
	data := fmt.Sprintf("%s:%s:%s", a.Name, a.AssetType, a.TenantID.String())
	if a.NetworkInfo != nil && a.NetworkInfo.IPAddress != "" {
		data += ":" + a.NetworkInfo.IPAddress
	}
	if a.NetworkInfo != nil && a.NetworkInfo.MACAddress != "" {
		data += ":" + a.NetworkInfo.MACAddress
	}
	// In a real implementation, this would use a proper hash function
	return fmt.Sprintf("fp_%x", []byte(data))
}

// UpdateFingerprint updates the asset fingerprint
func (a *Asset) UpdateFingerprint() {
	a.Fingerprint = a.CalculateFingerprint()
	a.LastUpdated = time.Now()
	a.Version++
}

// IsStale checks if the asset is stale based on last seen time
func (a *Asset) IsStale(staleDuration time.Duration) bool {
	return time.Since(a.LastSeen) > staleDuration
}

// GetVulnerabilityScore calculates a vulnerability score
func (a *Asset) GetVulnerabilityScore() float64 {
	if a.SecurityInfo == nil {
		return 0.0
	}
	
	vuln := a.SecurityInfo.VulnCount
	score := float64(vuln.Critical*10 + vuln.High*7 + vuln.Medium*4 + vuln.Low*1)
	
	// Normalize to 0-100 scale
	if score > 100 {
		score = 100
	}
	
	return score
}

// ToMap converts the asset to a map for flexible storage/retrieval
func (a *Asset) ToMap() map[string]interface{} {
	data, _ := json.Marshal(a)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// String returns a string representation of the asset
func (a *Asset) String() string {
	return fmt.Sprintf("Asset{ID: %s, Name: %s, Type: %s, Status: %s, RiskLevel: %s}", 
		a.ID.String(), a.Name, a.AssetType, a.Status, a.RiskLevel)
}