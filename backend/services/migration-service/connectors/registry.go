package connectors

import (
	"fmt"
	"sync"

	"github.com/isectech/migration-service/domain/entity"
)

// DefaultConnectorRegistry is the default connector registry instance
var DefaultConnectorRegistry = NewConnectorRegistry()

// connectorRegistry implements ConnectorRegistry interface
type connectorRegistry struct {
	factories map[entity.SourceSystemVendor]ConnectorFactory
	mutex     sync.RWMutex
}

// NewConnectorRegistry creates a new connector registry
func NewConnectorRegistry() ConnectorRegistry {
	registry := &connectorRegistry{
		factories: make(map[entity.SourceSystemVendor]ConnectorFactory),
	}

	// Register built-in connector factories
	registry.registerBuiltInFactories()

	return registry
}

// RegisterFactory registers a connector factory for a vendor
func (r *connectorRegistry) RegisterFactory(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	if factory == nil {
		return fmt.Errorf("factory cannot be nil")
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.factories[vendor] = factory
	return nil
}

// GetFactory returns a connector factory for the given vendor
func (r *connectorRegistry) GetFactory(vendor entity.SourceSystemVendor) (ConnectorFactory, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	factory, exists := r.factories[vendor]
	if !exists {
		return nil, fmt.Errorf("no factory registered for vendor: %s", vendor)
	}

	return factory, nil
}

// ListVendors returns all registered vendors
func (r *connectorRegistry) ListVendors() []entity.SourceSystemVendor {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	vendors := make([]entity.SourceSystemVendor, 0, len(r.factories))
	for vendor := range r.factories {
		vendors = append(vendors, vendor)
	}

	return vendors
}

// CreateConnector creates a connector for the given source system
func (r *connectorRegistry) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	factory, err := r.GetFactory(sourceSystem.Vendor)
	if err != nil {
		return nil, fmt.Errorf("failed to get factory for vendor %s: %w", sourceSystem.Vendor, err)
	}

	connector, err := factory.CreateConnector(sourceSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	return connector, nil
}

// registerBuiltInFactories registers built-in connector factories
func (r *connectorRegistry) registerBuiltInFactories() {
	// Register SIEM connector factories
	r.RegisterFactory(entity.VendorSplunk, NewSIEMConnectorFactory())
	r.RegisterFactory(entity.VendorIBMQRadar, NewSIEMConnectorFactory())
	r.RegisterFactory(entity.VendorArcSight, NewSIEMConnectorFactory())
	r.RegisterFactory(entity.VendorLogRhythm, NewSIEMConnectorFactory())
	r.RegisterFactory(entity.VendorElastic, NewSIEMConnectorFactory())
	r.RegisterFactory(entity.VendorSumoLogic, NewSIEMConnectorFactory())

	// Register Endpoint Protection connector factories
	r.RegisterFactory(entity.VendorCrowdStrike, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorSentinelOne, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorCarbonBlack, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorCylance, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorTrendMicro, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorSymantec, NewEndpointProtectionConnectorFactory())
	r.RegisterFactory(entity.VendorMcAfee, NewEndpointProtectionConnectorFactory())

	// Register Vulnerability Management connector factories
	r.RegisterFactory(entity.VendorTenable, NewVulnerabilityManagementConnectorFactory())
	r.RegisterFactory(entity.VendorQualys, NewVulnerabilityManagementConnectorFactory())
	r.RegisterFactory(entity.VendorRapid7, NewVulnerabilityManagementConnectorFactory())
	r.RegisterFactory(entity.VendorGreenbone, NewVulnerabilityManagementConnectorFactory())
	r.RegisterFactory(entity.VendorNessus, NewVulnerabilityManagementConnectorFactory())
	r.RegisterFactory(entity.VendorOpenVAS, NewVulnerabilityManagementConnectorFactory())

	// Register Network Security connector factories
	r.RegisterFactory(entity.VendorPaloAlto, NewNetworkSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorFortinet, NewNetworkSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorCisco, NewNetworkSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorCheckPoint, NewNetworkSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorJuniper, NewNetworkSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorSonicWall, NewNetworkSecurityConnectorFactory())

	// Register Cloud Security connector factories
	r.RegisterFactory(entity.VendorPrismaCloud, NewCloudSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorLacework, NewCloudSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorAWS, NewCloudSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorAzure, NewCloudSecurityConnectorFactory())
	r.RegisterFactory(entity.VendorGCP, NewCloudSecurityConnectorFactory())

	// Register Identity and Access Management connector factories
	r.RegisterFactory(entity.VendorOkta, NewIAMConnectorFactory())
	r.RegisterFactory(entity.VendorPingIdentity, NewIAMConnectorFactory())
	r.RegisterFactory(entity.VendorCyberArk, NewIAMConnectorFactory())
	r.RegisterFactory(entity.VendorSailPoint, NewIAMConnectorFactory())

	// Register custom connector factory
	r.RegisterFactory(entity.VendorCustom, NewCustomConnectorFactory())
	r.RegisterFactory(entity.VendorGeneric, NewGenericConnectorFactory())
}

// ConnectorFactoryManager provides helper methods for managing connector factories
type ConnectorFactoryManager struct {
	registry ConnectorRegistry
}

// NewConnectorFactoryManager creates a new connector factory manager
func NewConnectorFactoryManager(registry ConnectorRegistry) *ConnectorFactoryManager {
	if registry == nil {
		registry = DefaultConnectorRegistry
	}

	return &ConnectorFactoryManager{
		registry: registry,
	}
}

// GetSupportedVendors returns all supported vendors
func (m *ConnectorFactoryManager) GetSupportedVendors() []entity.SourceSystemVendor {
	return m.registry.ListVendors()
}

// IsVendorSupported checks if a vendor is supported
func (m *ConnectorFactoryManager) IsVendorSupported(vendor entity.SourceSystemVendor) bool {
	vendors := m.GetSupportedVendors()
	for _, v := range vendors {
		if v == vendor {
			return true
		}
	}
	return false
}

// GetVendorsBySystemType returns vendors that support a specific system type
func (m *ConnectorFactoryManager) GetVendorsBySystemType(systemType entity.SourceSystemType) ([]entity.SourceSystemVendor, error) {
	var supportedVendors []entity.SourceSystemVendor

	for _, vendor := range m.GetSupportedVendors() {
		factory, err := m.registry.GetFactory(vendor)
		if err != nil {
			continue
		}

		supportedSystemTypes := factory.GetSupportedSystemTypes()
		for _, st := range supportedSystemTypes {
			if st == systemType {
				supportedVendors = append(supportedVendors, vendor)
				break
			}
		}
	}

	return supportedVendors, nil
}

// ValidateSourceSystemConfiguration validates a source system configuration
func (m *ConnectorFactoryManager) ValidateSourceSystemConfiguration(sourceSystem *entity.SourceSystem) error {
	if sourceSystem == nil {
		return fmt.Errorf("source system cannot be nil")
	}

	// Check if vendor is supported
	if !m.IsVendorSupported(sourceSystem.Vendor) {
		return fmt.Errorf("vendor %s is not supported", sourceSystem.Vendor)
	}

	// Get factory and validate configuration
	factory, err := m.registry.GetFactory(sourceSystem.Vendor)
	if err != nil {
		return fmt.Errorf("failed to get factory: %w", err)
	}

	// Convert source system configuration to map for validation
	configMap := map[string]interface{}{
		"connection_config":      sourceSystem.ConnectionConfig,
		"auth_config":           sourceSystem.AuthConfig,
		"data_extraction_config": sourceSystem.DataExtractionConfig,
		"system_type":           sourceSystem.SystemType,
		"vendor":                sourceSystem.Vendor,
	}

	return factory.ValidateConfiguration(configMap)
}

// CreateAndTestConnector creates a connector and tests its connection
func (m *ConnectorFactoryManager) CreateAndTestConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// Validate configuration first
	if err := m.ValidateSourceSystemConfiguration(sourceSystem); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create connector
	connector, err := m.registry.CreateConnector(sourceSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}

	// Test connection
	ctx := context.Background()
	if err := connector.TestConnection(ctx); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	return connector, nil
}

// GetConnectorCapabilities returns the capabilities of a connector for a vendor
func (m *ConnectorFactoryManager) GetConnectorCapabilities(vendor entity.SourceSystemVendor) (*ConnectorCapabilities, error) {
	factory, err := m.registry.GetFactory(vendor)
	if err != nil {
		return nil, fmt.Errorf("failed to get factory: %w", err)
	}

	supportedVendors := factory.GetSupportedVendors()
	supportedSystemTypes := factory.GetSupportedSystemTypes()

	capabilities := &ConnectorCapabilities{
		Vendor:             vendor,
		SupportedVendors:   supportedVendors,
		SupportedSystemTypes: supportedSystemTypes,
		SupportedDataTypes: getSupportedDataTypes(supportedSystemTypes),
		Features:          getConnectorFeatures(vendor),
	}

	return capabilities, nil
}

// ConnectorCapabilities represents the capabilities of a connector
type ConnectorCapabilities struct {
	Vendor               entity.SourceSystemVendor   `json:"vendor"`
	SupportedVendors     []entity.SourceSystemVendor `json:"supported_vendors"`
	SupportedSystemTypes []entity.SourceSystemType   `json:"supported_system_types"`
	SupportedDataTypes   []entity.DataType           `json:"supported_data_types"`
	Features             ConnectorFeatures           `json:"features"`
}

// ConnectorFeatures represents the features supported by a connector
type ConnectorFeatures struct {
	SupportsAuthentication   bool                    `json:"supports_authentication"`
	SupportedAuthTypes       []entity.AuthenticationType `json:"supported_auth_types"`
	SupportsIncremental      bool                    `json:"supports_incremental"`
	SupportsPagination       bool                    `json:"supports_pagination"`
	SupportsFiltering        bool                    `json:"supports_filtering"`
	SupportsFieldSelection   bool                    `json:"supports_field_selection"`
	SupportsHealthCheck      bool                    `json:"supports_health_check"`
	SupportsMetrics          bool                    `json:"supports_metrics"`
	SupportsRetries          bool                    `json:"supports_retries"`
	SupportsRateLimit        bool                    `json:"supports_rate_limit"`
	MaxBatchSize             int32                   `json:"max_batch_size"`
	DefaultBatchSize         int32                   `json:"default_batch_size"`
	MaxParallelRequests      int32                   `json:"max_parallel_requests"`
}

// getSupportedDataTypes returns supported data types for system types
func getSupportedDataTypes(systemTypes []entity.SourceSystemType) []entity.DataType {
	dataTypeMap := make(map[entity.DataType]bool)

	for _, systemType := range systemTypes {
		switch systemType {
		case entity.SourceSystemTypeSIEM:
			dataTypeMap[entity.DataTypeAlerts] = true
			dataTypeMap[entity.DataTypeLogs] = true
			dataTypeMap[entity.DataTypeEvents] = true
			dataTypeMap[entity.DataTypeIncidents] = true
			dataTypeMap[entity.DataTypeThreats] = true
		case entity.SourceSystemTypeEndpointProtection:
			dataTypeMap[entity.DataTypeAlerts] = true
			dataTypeMap[entity.DataTypeThreats] = true
			dataTypeMap[entity.DataTypeAssets] = true
			dataTypeMap[entity.DataTypeEvents] = true
		case entity.SourceSystemTypeVulnerabilityMgmt:
			dataTypeMap[entity.DataTypeVulnerabilities] = true
			dataTypeMap[entity.DataTypeAssets] = true
			dataTypeMap[entity.DataTypeReports] = true
		case entity.SourceSystemTypeNetworkSecurity:
			dataTypeMap[entity.DataTypeAlerts] = true
			dataTypeMap[entity.DataTypeEvents] = true
			dataTypeMap[entity.DataTypeLogs] = true
		case entity.SourceSystemTypeCloudSecurity:
			dataTypeMap[entity.DataTypeAlerts] = true
			dataTypeMap[entity.DataTypeAssets] = true
			dataTypeMap[entity.DataTypePolicies] = true
		case entity.SourceSystemTypeIdentityAccessMgmt:
			dataTypeMap[entity.DataTypeUsers] = true
			dataTypeMap[entity.DataTypeEvents] = true
			dataTypeMap[entity.DataTypePolicies] = true
		}
	}

	// Convert map to slice
	var dataTypes []entity.DataType
	for dataType := range dataTypeMap {
		dataTypes = append(dataTypes, dataType)
	}

	return dataTypes
}

// getConnectorFeatures returns connector features for a vendor
func getConnectorFeatures(vendor entity.SourceSystemVendor) ConnectorFeatures {
	// Default features
	features := ConnectorFeatures{
		SupportsAuthentication:  true,
		SupportedAuthTypes:      []entity.AuthenticationType{entity.AuthTypeAPIKey, entity.AuthTypeBasicAuth},
		SupportsIncremental:     true,
		SupportsPagination:      true,
		SupportsFiltering:       true,
		SupportsFieldSelection:  false,
		SupportsHealthCheck:     true,
		SupportsMetrics:         true,
		SupportsRetries:         true,
		SupportsRateLimit:       true,
		MaxBatchSize:            10000,
		DefaultBatchSize:        1000,
		MaxParallelRequests:     5,
	}

	// Vendor-specific feature overrides
	switch vendor {
	case entity.VendorSplunk:
		features.SupportedAuthTypes = []entity.AuthenticationType{
			entity.AuthTypeBasicAuth, entity.AuthTypeAPIKey, entity.AuthTypeCertificate,
		}
		features.SupportsFieldSelection = true
		features.MaxBatchSize = 50000
		features.DefaultBatchSize = 10000

	case entity.VendorIBMQRadar:
		features.SupportedAuthTypes = []entity.AuthenticationType{
			entity.AuthTypeAPIKey, entity.AuthTypeBasicAuth, entity.AuthTypeCertificate, entity.AuthTypeSAML,
		}
		features.MaxBatchSize = 10000
		features.DefaultBatchSize = 1000

	case entity.VendorCrowdStrike:
		features.SupportedAuthTypes = []entity.AuthenticationType{entity.AuthTypeOAuth2}
		features.MaxBatchSize = 5000
		features.DefaultBatchSize = 2500
		features.MaxParallelRequests = 10

	case entity.VendorTenable:
		features.SupportedAuthTypes = []entity.AuthenticationType{entity.AuthTypeAPIKey}
		features.MaxBatchSize = 5000
		features.DefaultBatchSize = 1000

	case entity.VendorQualys:
		features.SupportedAuthTypes = []entity.AuthenticationType{entity.AuthTypeBasicAuth, entity.AuthTypeAPIKey}
		features.MaxBatchSize = 1000
		features.DefaultBatchSize = 500

	case entity.VendorAWS:
		features.SupportedAuthTypes = []entity.AuthenticationType{entity.AuthTypeAPIKey}
		features.SupportsIncremental = false // For some AWS services
		features.MaxBatchSize = 1000
		features.DefaultBatchSize = 100

	case entity.VendorOkta:
		features.SupportedAuthTypes = []entity.AuthenticationType{entity.AuthTypeAPIKey, entity.AuthTypeOAuth2}
		features.MaxBatchSize = 10000
		features.DefaultBatchSize = 200 // Okta has rate limits
		features.MaxParallelRequests = 1
	}

	return features
}

// Helper functions for easy registration of new connector factories

// RegisterSIEMConnector registers a SIEM connector factory
func RegisterSIEMConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterEndpointProtectionConnector registers an endpoint protection connector factory
func RegisterEndpointProtectionConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterVulnerabilityManagementConnector registers a vulnerability management connector factory
func RegisterVulnerabilityManagementConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterNetworkSecurityConnector registers a network security connector factory
func RegisterNetworkSecurityConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterCloudSecurityConnector registers a cloud security connector factory
func RegisterCloudSecurityConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterIAMConnector registers an IAM connector factory
func RegisterIAMConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}

// RegisterCustomConnector registers a custom connector factory
func RegisterCustomConnector(vendor entity.SourceSystemVendor, factory ConnectorFactory) error {
	return DefaultConnectorRegistry.RegisterFactory(vendor, factory)
}