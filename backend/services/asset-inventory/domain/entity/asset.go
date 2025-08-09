// iSECTECH Asset Inventory - Asset Domain Entity
// Production-grade asset tracking and classification for vulnerability management
// Copyright (c) 2024 iSECTECH. All rights reserved.

package entity

import (
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
)

// Asset represents a comprehensive organizational asset for vulnerability management
type Asset struct {
	// Core identification
	ID          uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	TenantID    uuid.UUID `json:"tenant_id" gorm:"type:uuid;not null;index"`
	Name        string    `json:"name" gorm:"type:varchar(255);not null"`
	DisplayName string    `json:"display_name" gorm:"type:varchar(255)"`
	Description string    `json:"description" gorm:"type:text"`

	// Asset classification
	AssetType        AssetType        `json:"asset_type" gorm:"type:varchar(50);not null;index"`
	AssetSubtype     string           `json:"asset_subtype" gorm:"type:varchar(100);index"`
	Criticality      CriticalityLevel `json:"criticality" gorm:"type:varchar(20);not null;index"`
	BusinessFunction string           `json:"business_function" gorm:"type:varchar(100);index"`
	Owner            string           `json:"owner" gorm:"type:varchar(100);index"`
	OwnerContact     string           `json:"owner_contact" gorm:"type:varchar(255)"`

	// Network and location information
	IPAddresses    []string      `json:"ip_addresses" gorm:"type:jsonb"`
	MACAddresses   []string      `json:"mac_addresses" gorm:"type:jsonb"`
	HostNames      []string      `json:"host_names" gorm:"type:jsonb"`
	FQDNs          []string      `json:"fqdns" gorm:"type:jsonb"`
	NetworkSegment string        `json:"network_segment" gorm:"type:varchar(100);index"`
	Location       AssetLocation `json:"location" gorm:"embedded;embeddedPrefix:location_"`
	NetworkPorts   []NetworkPort `json:"network_ports" gorm:"type:jsonb"`

	// Technical specifications
	OperatingSystem   OperatingSystemInfo `json:"operating_system" gorm:"embedded;embeddedPrefix:os_"`
	Hardware          HardwareInfo        `json:"hardware" gorm:"embedded;embeddedPrefix:hw_"`
	Software          []SoftwareComponent `json:"software" gorm:"type:jsonb"`
	Services          []ServiceInfo       `json:"services" gorm:"type:jsonb"`
	CloudMetadata     *CloudMetadata      `json:"cloud_metadata,omitempty" gorm:"type:jsonb"`
	ContainerMetadata *ContainerMetadata  `json:"container_metadata,omitempty" gorm:"type:jsonb"`

	// Security and compliance
	SecurityControls     []SecurityControl  `json:"security_controls" gorm:"type:jsonb"`
	ComplianceFrameworks []string           `json:"compliance_frameworks" gorm:"type:jsonb"`
	DataClassification   DataClassification `json:"data_classification" gorm:"type:varchar(50);index"`
	EncryptionStatus     EncryptionStatus   `json:"encryption_status" gorm:"embedded;embeddedPrefix:encryption_"`

	// Vulnerability management
	LastScanned        *time.Time            `json:"last_scanned,omitempty"`
	ScanningEnabled    bool                  `json:"scanning_enabled" gorm:"default:true"`
	ScanFrequency      ScanFrequency         `json:"scan_frequency" gorm:"type:varchar(20);default:'weekly'"`
	ExclusionReason    string                `json:"exclusion_reason,omitempty"`
	VulnerabilityCount VulnerabilityCounters `json:"vulnerability_count" gorm:"embedded;embeddedPrefix:vuln_"`

	// Asset lifecycle
	Status          AssetStatus `json:"status" gorm:"type:varchar(20);not null;index;default:'active'"`
	DiscoveryMethod string      `json:"discovery_method" gorm:"type:varchar(50);index"`
	FirstDiscovered time.Time   `json:"first_discovered" gorm:"not null"`
	LastSeen        time.Time   `json:"last_seen" gorm:"not null;index"`
	LastUpdated     time.Time   `json:"last_updated" gorm:"not null"`
	LifecycleStage  string      `json:"lifecycle_stage" gorm:"type:varchar(50);index"`
	RetirementDate  *time.Time  `json:"retirement_date,omitempty"`

	// Metadata and tagging
	Tags          []AssetTag          `json:"tags" gorm:"type:jsonb"`
	CustomFields  map[string]string   `json:"custom_fields" gorm:"type:jsonb"`
	ExternalIDs   map[string]string   `json:"external_ids" gorm:"type:jsonb"`
	Relationships []AssetRelationship `json:"relationships" gorm:"type:jsonb"`

	// Audit information
	CreatedAt     time.Time     `json:"created_at" gorm:"not null"`
	UpdatedAt     time.Time     `json:"updated_at" gorm:"not null"`
	CreatedBy     string        `json:"created_by" gorm:"type:varchar(100)"`
	UpdatedBy     string        `json:"updated_by" gorm:"type:varchar(100)"`
	ChangeHistory []AssetChange `json:"change_history" gorm:"type:jsonb"`
}

// AssetType represents the primary classification of an asset
type AssetType string

const (
	AssetTypeEndpoint      AssetType = "endpoint"
	AssetTypeServer        AssetType = "server"
	AssetTypeNetworkDevice AssetType = "network_device"
	AssetTypeApplication   AssetType = "application"
	AssetTypeDatabase      AssetType = "database"
	AssetTypeContainer     AssetType = "container"
	AssetTypeCloudResource AssetType = "cloud_resource"
	AssetTypeMobile        AssetType = "mobile"
	AssetTypeIoT           AssetType = "iot"
	AssetTypeVirtual       AssetType = "virtual"
	AssetTypeOther         AssetType = "other"
)

// CriticalityLevel represents the business criticality of an asset
type CriticalityLevel string

const (
	CriticalityLow      CriticalityLevel = "low"
	CriticalityMedium   CriticalityLevel = "medium"
	CriticalityHigh     CriticalityLevel = "high"
	CriticalityCritical CriticalityLevel = "critical"
)

// AssetStatus represents the operational status of an asset
type AssetStatus string

const (
	AssetStatusActive      AssetStatus = "active"
	AssetStatusInactive    AssetStatus = "inactive"
	AssetStatusMaintenance AssetStatus = "maintenance"
	AssetStatusRetired     AssetStatus = "retired"
	AssetStatusUnknown     AssetStatus = "unknown"
)

// ScanFrequency represents how often an asset should be scanned for vulnerabilities
type ScanFrequency string

const (
	ScanFrequencyDaily    ScanFrequency = "daily"
	ScanFrequencyWeekly   ScanFrequency = "weekly"
	ScanFrequencyMonthly  ScanFrequency = "monthly"
	ScanFrequencyOnDemand ScanFrequency = "on_demand"
	ScanFrequencyDisabled ScanFrequency = "disabled"
)

// DataClassification represents the sensitivity level of data on the asset
type DataClassification string

const (
	DataClassificationPublic       DataClassification = "public"
	DataClassificationInternal     DataClassification = "internal"
	DataClassificationConfidential DataClassification = "confidential"
	DataClassificationRestricted   DataClassification = "restricted"
)

// AssetLocation represents the physical and logical location of an asset
type AssetLocation struct {
	PhysicalLocation string  `json:"physical_location"`
	Building         string  `json:"building"`
	Floor            string  `json:"floor"`
	Room             string  `json:"room"`
	Rack             string  `json:"rack"`
	Datacenter       string  `json:"datacenter"`
	Region           string  `json:"region"`
	Country          string  `json:"country"`
	Latitude         float64 `json:"latitude,omitempty"`
	Longitude        float64 `json:"longitude,omitempty"`
}

// NetworkPort represents an open network port on an asset
type NetworkPort struct {
	Port     int       `json:"port"`
	Protocol string    `json:"protocol"`
	Service  string    `json:"service,omitempty"`
	Version  string    `json:"version,omitempty"`
	State    string    `json:"state"`
	Banner   string    `json:"banner,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// OperatingSystemInfo represents operating system details
type OperatingSystemInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
	Kernel       string `json:"kernel,omitempty"`
	Edition      string `json:"edition,omitempty"`
	ServicePack  string `json:"service_pack,omitempty"`
	Patch        string `json:"patch,omitempty"`
}

// HardwareInfo represents hardware specifications
type HardwareInfo struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
	CPUInfo      string `json:"cpu_info,omitempty"`
	MemoryGB     int    `json:"memory_gb,omitempty"`
	DiskGB       int    `json:"disk_gb,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

// SoftwareComponent represents installed software
type SoftwareComponent struct {
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Vendor      string     `json:"vendor"`
	InstallDate *time.Time `json:"install_date,omitempty"`
	LicenseType string     `json:"license_type,omitempty"`
	CPE         string     `json:"cpe,omitempty"`
	Path        string     `json:"path,omitempty"`
	Description string     `json:"description,omitempty"`
}

// ServiceInfo represents running services
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"`
	StartType   string `json:"start_type,omitempty"`
	Account     string `json:"account,omitempty"`
	Path        string `json:"path,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

// CloudMetadata represents cloud-specific information
type CloudMetadata struct {
	Provider         string            `json:"provider"`
	InstanceID       string            `json:"instance_id"`
	InstanceType     string            `json:"instance_type"`
	Region           string            `json:"region"`
	AvailabilityZone string            `json:"availability_zone,omitempty"`
	VPC              string            `json:"vpc,omitempty"`
	Subnet           string            `json:"subnet,omitempty"`
	SecurityGroups   []string          `json:"security_groups,omitempty"`
	Tags             map[string]string `json:"tags,omitempty"`
	LaunchTime       *time.Time        `json:"launch_time,omitempty"`
}

// ContainerMetadata represents container-specific information
type ContainerMetadata struct {
	ContainerID  string            `json:"container_id"`
	ImageName    string            `json:"image_name"`
	ImageTag     string            `json:"image_tag"`
	ImageDigest  string            `json:"image_digest,omitempty"`
	Runtime      string            `json:"runtime"`
	Orchestrator string            `json:"orchestrator,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	PodName      string            `json:"pod_name,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
}

// SecurityControl represents security controls implemented on the asset
type SecurityControl struct {
	Type          string                 `json:"type"`
	Name          string                 `json:"name"`
	Version       string                 `json:"version,omitempty"`
	Status        string                 `json:"status"`
	LastUpdated   time.Time              `json:"last_updated"`
	Configuration map[string]interface{} `json:"configuration,omitempty"`
}

// EncryptionStatus represents encryption configuration
type EncryptionStatus struct {
	DiskEncryption      bool   `json:"disk_encryption"`
	NetworkEncryption   bool   `json:"network_encryption"`
	DatabaseEncryption  bool   `json:"database_encryption"`
	BackupEncryption    bool   `json:"backup_encryption"`
	EncryptionAlgorithm string `json:"encryption_algorithm,omitempty"`
}

// VulnerabilityCounters represents vulnerability statistics
type VulnerabilityCounters struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// AssetTag represents metadata tags for classification and filtering
type AssetTag struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

// AssetRelationship represents relationships between assets
type AssetRelationship struct {
	RelatedAssetID uuid.UUID `json:"related_asset_id"`
	RelationType   string    `json:"relation_type"`
	Description    string    `json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// AssetChange represents audit trail of changes
type AssetChange struct {
	Timestamp time.Time   `json:"timestamp"`
	User      string      `json:"user"`
	Operation string      `json:"operation"`
	Field     string      `json:"field,omitempty"`
	OldValue  interface{} `json:"old_value,omitempty"`
	NewValue  interface{} `json:"new_value,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	IPAddress string      `json:"ip_address,omitempty"`
	UserAgent string      `json:"user_agent,omitempty"`
}

// TableName returns the database table name for Asset
func (Asset) TableName() string {
	return "assets"
}

// IsIPAddress checks if the asset has a specific IP address
func (a *Asset) IsIPAddress(ip string) bool {
	for _, addr := range a.IPAddresses {
		if addr == ip {
			return true
		}
	}
	return false
}

// IsInNetwork checks if the asset belongs to a specific network segment
func (a *Asset) IsInNetwork(network string) bool {
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return false
	}

	for _, ipStr := range a.IPAddresses {
		ip := net.ParseIP(ipStr)
		if ip != nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// HasTag checks if the asset has a specific tag
func (a *Asset) HasTag(key, value string) bool {
	for _, tag := range a.Tags {
		if tag.Key == key && tag.Value == value {
			return true
		}
	}
	return false
}

// GetCPEs returns all CPE identifiers for the asset's software
func (a *Asset) GetCPEs() []string {
	var cpes []string
	for _, software := range a.Software {
		if software.CPE != "" {
			cpes = append(cpes, software.CPE)
		}
	}
	return cpes
}

// UpdateLastSeen updates the last seen timestamp
func (a *Asset) UpdateLastSeen() {
	a.LastSeen = time.Now().UTC()
	a.LastUpdated = time.Now().UTC()
}

// AddTag adds a new tag to the asset
func (a *Asset) AddTag(key, value, source string) {
	// Remove existing tag with same key
	for i, tag := range a.Tags {
		if tag.Key == key {
			a.Tags = append(a.Tags[:i], a.Tags[i+1:]...)
			break
		}
	}

	// Add new tag
	a.Tags = append(a.Tags, AssetTag{
		Key:       key,
		Value:     value,
		Source:    source,
		CreatedAt: time.Now().UTC(),
	})
}

// RemoveTag removes a tag from the asset
func (a *Asset) RemoveTag(key string) {
	for i, tag := range a.Tags {
		if tag.Key == key {
			a.Tags = append(a.Tags[:i], a.Tags[i+1:]...)
			break
		}
	}
}

// IsHighValue determines if the asset is high-value based on criticality and data classification
func (a *Asset) IsHighValue() bool {
	return a.Criticality == CriticalityCritical ||
		a.Criticality == CriticalityHigh ||
		a.DataClassification == DataClassificationRestricted ||
		a.DataClassification == DataClassificationConfidential
}

// ShouldScan determines if the asset should be included in vulnerability scans
func (a *Asset) ShouldScan() bool {
	return a.ScanningEnabled &&
		a.Status == AssetStatusActive &&
		a.ScanFrequency != ScanFrequencyDisabled
}

// CalculateRiskScore calculates a risk score based on various factors
func (a *Asset) CalculateRiskScore() float64 {
	score := 0.0

	// Base score from criticality
	switch a.Criticality {
	case CriticalityCritical:
		score += 40.0
	case CriticalityHigh:
		score += 30.0
	case CriticalityMedium:
		score += 20.0
	case CriticalityLow:
		score += 10.0
	}

	// Data classification factor
	switch a.DataClassification {
	case DataClassificationRestricted:
		score += 30.0
	case DataClassificationConfidential:
		score += 20.0
	case DataClassificationInternal:
		score += 10.0
	}

	// Vulnerability count factor
	vulnScore := float64(a.VulnerabilityCount.Critical*10 +
		a.VulnerabilityCount.High*5 +
		a.VulnerabilityCount.Medium*2 +
		a.VulnerabilityCount.Low*1)
	if vulnScore > 30 {
		vulnScore = 30 // Cap vulnerability contribution
	}
	score += vulnScore

	return score
}

// Validate performs business logic validation on the asset
func (a *Asset) Validate() error {
	if a.Name == "" {
		return ErrAssetNameRequired
	}

	if a.TenantID == uuid.Nil {
		return ErrTenantIDRequired
	}

	if a.AssetType == "" {
		return ErrAssetTypeRequired
	}

	if a.Criticality == "" {
		return ErrCriticalityRequired
	}

	// Validate IP addresses
	for _, ip := range a.IPAddresses {
		if net.ParseIP(ip) == nil {
			return ErrInvalidIPAddress
		}
	}

	return nil
}

// Custom errors for asset validation
var (
	ErrAssetNameRequired   = AssetError{Code: "ASSET_NAME_REQUIRED", Message: "Asset name is required"}
	ErrTenantIDRequired    = AssetError{Code: "TENANT_ID_REQUIRED", Message: "Tenant ID is required"}
	ErrAssetTypeRequired   = AssetError{Code: "ASSET_TYPE_REQUIRED", Message: "Asset type is required"}
	ErrCriticalityRequired = AssetError{Code: "CRITICALITY_REQUIRED", Message: "Criticality level is required"}
	ErrInvalidIPAddress    = AssetError{Code: "INVALID_IP_ADDRESS", Message: "Invalid IP address format"}
)

// AssetError represents asset-specific errors
type AssetError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e AssetError) Error() string {
	return e.Message
}

// MarshalJSON implements custom JSON marshaling for Asset
func (a *Asset) MarshalJSON() ([]byte, error) {
	type Alias Asset
	return json.Marshal(&struct {
		*Alias
		RiskScore float64 `json:"risk_score"`
		HighValue bool    `json:"high_value"`
	}{
		Alias:     (*Alias)(a),
		RiskScore: a.CalculateRiskScore(),
		HighValue: a.IsHighValue(),
	})
}
