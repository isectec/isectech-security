package connectors

import (
	"context"
	"fmt"

	"github.com/isectech/migration-service/connectors/siem"
	"github.com/isectech/migration-service/domain/entity"
)

// SIEMConnectorFactory creates SIEM connectors
type SIEMConnectorFactory struct{}

// NewSIEMConnectorFactory creates a new SIEM connector factory
func NewSIEMConnectorFactory() ConnectorFactory {
	return &SIEMConnectorFactory{}
}

// CreateConnector creates a SIEM connector based on the vendor
func (f *SIEMConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorSplunk:
		return siem.NewSplunkConnector(sourceSystem)
	case entity.VendorIBMQRadar:
		return siem.NewQRadarConnector(sourceSystem)
	case entity.VendorArcSight:
		return siem.NewArcSightConnector(sourceSystem)
	case entity.VendorLogRhythm:
		return siem.NewLogRhythmConnector(sourceSystem)
	case entity.VendorElastic:
		return siem.NewElasticConnector(sourceSystem)
	case entity.VendorSumoLogic:
		return siem.NewSumoLogicConnector(sourceSystem)
	case entity.VendorAlienVault:
		return siem.NewAlienVaultConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported SIEM vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *SIEMConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorSplunk,
		entity.VendorIBMQRadar,
		entity.VendorArcSight,
		entity.VendorLogRhythm,
		entity.VendorElastic,
		entity.VendorSumoLogic,
		entity.VendorAlienVault,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *SIEMConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeSIEM,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *SIEMConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	// Check if vendor is supported
	vendor, ok := config["vendor"].(entity.SourceSystemVendor)
	if !ok {
		return fmt.Errorf("vendor is required and must be a valid SourceSystemVendor")
	}

	supportedVendors := f.GetSupportedVendors()
	vendorSupported := false
	for _, v := range supportedVendors {
		if v == vendor {
			vendorSupported = true
			break
		}
	}

	if !vendorSupported {
		return fmt.Errorf("vendor %s is not supported by SIEM connector factory", vendor)
	}

	// Validate system type
	systemType, ok := config["system_type"].(entity.SourceSystemType)
	if !ok {
		return fmt.Errorf("system_type is required and must be a valid SourceSystemType")
	}

	if systemType != entity.SourceSystemTypeSIEM {
		return fmt.Errorf("system type %s is not supported by SIEM connector factory", systemType)
	}

	// Validate connection configuration
	if connectionConfig, exists := config["connection_config"]; exists {
		if connConfig, ok := connectionConfig.(entity.ConnectionConfig); ok {
			if connConfig.BaseURL == "" {
				return fmt.Errorf("base_url is required in connection configuration")
			}
		} else {
			return fmt.Errorf("invalid connection_config format")
		}
	} else {
		return fmt.Errorf("connection_config is required")
	}

	// Validate authentication configuration
	if authConfig, exists := config["auth_config"]; exists {
		if auth, ok := authConfig.(entity.AuthenticationConfig); ok {
			if auth.Type == "" {
				return fmt.Errorf("authentication type is required")
			}

			// Validate vendor-specific auth requirements
			switch vendor {
			case entity.VendorSplunk:
				if auth.Type != entity.AuthTypeBasicAuth && 
				   auth.Type != entity.AuthTypeAPIKey && 
				   auth.Type != entity.AuthTypeCertificate {
					return fmt.Errorf("Splunk supports only basic_auth, api_key, or certificate authentication")
				}
			case entity.VendorIBMQRadar:
				if auth.Type != entity.AuthTypeAPIKey && 
				   auth.Type != entity.AuthTypeBasicAuth && 
				   auth.Type != entity.AuthTypeCertificate && 
				   auth.Type != entity.AuthTypeSAML {
					return fmt.Errorf("QRadar supports only api_key, basic_auth, certificate, or saml authentication")
				}
			}
		} else {
			return fmt.Errorf("invalid auth_config format")
		}
	} else {
		return fmt.Errorf("auth_config is required")
	}

	return nil
}

// EndpointProtectionConnectorFactory creates endpoint protection connectors
type EndpointProtectionConnectorFactory struct{}

// NewEndpointProtectionConnectorFactory creates a new endpoint protection connector factory
func NewEndpointProtectionConnectorFactory() ConnectorFactory {
	return &EndpointProtectionConnectorFactory{}
}

// CreateConnector creates an endpoint protection connector based on the vendor
func (f *EndpointProtectionConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorCrowdStrike:
		return NewCrowdStrikeConnector(sourceSystem)
	case entity.VendorSentinelOne:
		return NewSentinelOneConnector(sourceSystem)
	case entity.VendorCarbonBlack:
		return NewCarbonBlackConnector(sourceSystem)
	case entity.VendorCylance:
		return NewCylanceConnector(sourceSystem)
	case entity.VendorTrendMicro:
		return NewTrendMicroConnector(sourceSystem)
	case entity.VendorSymantec:
		return NewSymantecConnector(sourceSystem)
	case entity.VendorMcAfee:
		return NewMcAfeeConnector(sourceSystem)
	case entity.VendorKaspersky:
		return NewKasperskyConnector(sourceSystem)
	case entity.VendorSophos:
		return NewSophosConnector(sourceSystem)
	case entity.VendorBitdefender:
		return NewBitdefenderConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported endpoint protection vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *EndpointProtectionConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorCrowdStrike,
		entity.VendorSentinelOne,
		entity.VendorCarbonBlack,
		entity.VendorCylance,
		entity.VendorTrendMicro,
		entity.VendorSymantec,
		entity.VendorMcAfee,
		entity.VendorKaspersky,
		entity.VendorSophos,
		entity.VendorBitdefender,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *EndpointProtectionConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeEndpointProtection,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *EndpointProtectionConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	// Check if vendor is supported
	vendor, ok := config["vendor"].(entity.SourceSystemVendor)
	if !ok {
		return fmt.Errorf("vendor is required and must be a valid SourceSystemVendor")
	}

	supportedVendors := f.GetSupportedVendors()
	vendorSupported := false
	for _, v := range supportedVendors {
		if v == vendor {
			vendorSupported = true
			break
		}
	}

	if !vendorSupported {
		return fmt.Errorf("vendor %s is not supported by endpoint protection connector factory", vendor)
	}

	// Validate system type
	systemType, ok := config["system_type"].(entity.SourceSystemType)
	if !ok {
		return fmt.Errorf("system_type is required and must be a valid SourceSystemType")
	}

	if systemType != entity.SourceSystemTypeEndpointProtection {
		return fmt.Errorf("system type %s is not supported by endpoint protection connector factory", systemType)
	}

	return f.validateCommonConfiguration(config, vendor)
}

// VulnerabilityManagementConnectorFactory creates vulnerability management connectors
type VulnerabilityManagementConnectorFactory struct{}

// NewVulnerabilityManagementConnectorFactory creates a new vulnerability management connector factory
func NewVulnerabilityManagementConnectorFactory() ConnectorFactory {
	return &VulnerabilityManagementConnectorFactory{}
}

// CreateConnector creates a vulnerability management connector based on the vendor
func (f *VulnerabilityManagementConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorTenable:
		return NewTenableConnector(sourceSystem)
	case entity.VendorQualys:
		return NewQualysConnector(sourceSystem)
	case entity.VendorRapid7:
		return NewRapid7Connector(sourceSystem)
	case entity.VendorGreenbone:
		return NewGreenboneConnector(sourceSystem)
	case entity.VendorNessus:
		return NewNessusConnector(sourceSystem)
	case entity.VendorOpenVAS:
		return NewOpenVASConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported vulnerability management vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *VulnerabilityManagementConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorTenable,
		entity.VendorQualys,
		entity.VendorRapid7,
		entity.VendorGreenbone,
		entity.VendorNessus,
		entity.VendorOpenVAS,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *VulnerabilityManagementConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeVulnerabilityMgmt,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *VulnerabilityManagementConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	// Check if vendor is supported
	vendor, ok := config["vendor"].(entity.SourceSystemVendor)
	if !ok {
		return fmt.Errorf("vendor is required and must be a valid SourceSystemVendor")
	}

	supportedVendors := f.GetSupportedVendors()
	vendorSupported := false
	for _, v := range supportedVendors {
		if v == vendor {
			vendorSupported = true
			break
		}
	}

	if !vendorSupported {
		return fmt.Errorf("vendor %s is not supported by vulnerability management connector factory", vendor)
	}

	// Validate system type
	systemType, ok := config["system_type"].(entity.SourceSystemType)
	if !ok {
		return fmt.Errorf("system_type is required and must be a valid SourceSystemType")
	}

	if systemType != entity.SourceSystemTypeVulnerabilityMgmt {
		return fmt.Errorf("system type %s is not supported by vulnerability management connector factory", systemType)
	}

	return f.validateCommonConfiguration(config, vendor)
}

// NetworkSecurityConnectorFactory creates network security connectors
type NetworkSecurityConnectorFactory struct{}

// NewNetworkSecurityConnectorFactory creates a new network security connector factory
func NewNetworkSecurityConnectorFactory() ConnectorFactory {
	return &NetworkSecurityConnectorFactory{}
}

// CreateConnector creates a network security connector based on the vendor
func (f *NetworkSecurityConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorPaloAlto:
		return NewPaloAltoConnector(sourceSystem)
	case entity.VendorFortinet:
		return NewFortinetConnector(sourceSystem)
	case entity.VendorCisco:
		return NewCiscoConnector(sourceSystem)
	case entity.VendorCheckPoint:
		return NewCheckPointConnector(sourceSystem)
	case entity.VendorJuniper:
		return NewJuniperConnector(sourceSystem)
	case entity.VendorSonicWall:
		return NewSonicWallConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported network security vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *NetworkSecurityConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorPaloAlto,
		entity.VendorFortinet,
		entity.VendorCisco,
		entity.VendorCheckPoint,
		entity.VendorJuniper,
		entity.VendorSonicWall,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *NetworkSecurityConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeNetworkSecurity,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *NetworkSecurityConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	return f.validateCommonConfiguration(config, config["vendor"].(entity.SourceSystemVendor))
}

// CloudSecurityConnectorFactory creates cloud security connectors
type CloudSecurityConnectorFactory struct{}

// NewCloudSecurityConnectorFactory creates a new cloud security connector factory
func NewCloudSecurityConnectorFactory() ConnectorFactory {
	return &CloudSecurityConnectorFactory{}
}

// CreateConnector creates a cloud security connector based on the vendor
func (f *CloudSecurityConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorPrismaCloud:
		return NewPrismaCloudConnector(sourceSystem)
	case entity.VendorLacework:
		return NewLaceworkConnector(sourceSystem)
	case entity.VendorCloudFlare:
		return NewCloudFlareConnector(sourceSystem)
	case entity.VendorAWS:
		return NewAWSConnector(sourceSystem)
	case entity.VendorAzure:
		return NewAzureConnector(sourceSystem)
	case entity.VendorGCP:
		return NewGCPConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported cloud security vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *CloudSecurityConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorPrismaCloud,
		entity.VendorLacework,
		entity.VendorCloudFlare,
		entity.VendorAWS,
		entity.VendorAzure,
		entity.VendorGCP,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *CloudSecurityConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeCloudSecurity,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *CloudSecurityConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	return f.validateCommonConfiguration(config, config["vendor"].(entity.SourceSystemVendor))
}

// IAMConnectorFactory creates IAM connectors
type IAMConnectorFactory struct{}

// NewIAMConnectorFactory creates a new IAM connector factory
func NewIAMConnectorFactory() ConnectorFactory {
	return &IAMConnectorFactory{}
}

// CreateConnector creates an IAM connector based on the vendor
func (f *IAMConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	if sourceSystem == nil {
		return nil, fmt.Errorf("source system cannot be nil")
	}

	switch sourceSystem.Vendor {
	case entity.VendorOkta:
		return NewOktaConnector(sourceSystem)
	case entity.VendorPingIdentity:
		return NewPingIdentityConnector(sourceSystem)
	case entity.VendorCyberArk:
		return NewCyberArkConnector(sourceSystem)
	case entity.VendorSailPoint:
		return NewSailPointConnector(sourceSystem)
	default:
		return nil, fmt.Errorf("unsupported IAM vendor: %s", sourceSystem.Vendor)
	}
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *IAMConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorOkta,
		entity.VendorPingIdentity,
		entity.VendorCyberArk,
		entity.VendorSailPoint,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *IAMConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeIdentityAccessMgmt,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *IAMConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	return f.validateCommonConfiguration(config, config["vendor"].(entity.SourceSystemVendor))
}

// CustomConnectorFactory creates custom connectors
type CustomConnectorFactory struct{}

// NewCustomConnectorFactory creates a new custom connector factory
func NewCustomConnectorFactory() ConnectorFactory {
	return &CustomConnectorFactory{}
}

// CreateConnector creates a custom connector
func (f *CustomConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return NewCustomConnector(sourceSystem)
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *CustomConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorCustom,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *CustomConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeCustom,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *CustomConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	return f.validateCommonConfiguration(config, entity.VendorCustom)
}

// GenericConnectorFactory creates generic connectors
type GenericConnectorFactory struct{}

// NewGenericConnectorFactory creates a new generic connector factory
func NewGenericConnectorFactory() ConnectorFactory {
	return &GenericConnectorFactory{}
}

// CreateConnector creates a generic connector
func (f *GenericConnectorFactory) CreateConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return NewGenericConnector(sourceSystem)
}

// GetSupportedVendors returns the vendors supported by this factory
func (f *GenericConnectorFactory) GetSupportedVendors() []entity.SourceSystemVendor {
	return []entity.SourceSystemVendor{
		entity.VendorGeneric,
	}
}

// GetSupportedSystemTypes returns the system types supported by this factory
func (f *GenericConnectorFactory) GetSupportedSystemTypes() []entity.SourceSystemType {
	return []entity.SourceSystemType{
		entity.SourceSystemTypeCustom,
	}
}

// ValidateConfiguration validates the connector configuration
func (f *GenericConnectorFactory) ValidateConfiguration(config map[string]interface{}) error {
	return f.validateCommonConfiguration(config, entity.VendorGeneric)
}

// Common validation methods

// validateCommonConfiguration validates common configuration elements
func (f *EndpointProtectionConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	// Validate connection configuration
	if connectionConfig, exists := config["connection_config"]; exists {
		if connConfig, ok := connectionConfig.(entity.ConnectionConfig); ok {
			if connConfig.BaseURL == "" {
				return fmt.Errorf("base_url is required in connection configuration")
			}
		} else {
			return fmt.Errorf("invalid connection_config format")
		}
	} else {
		return fmt.Errorf("connection_config is required")
	}

	// Validate authentication configuration
	if authConfig, exists := config["auth_config"]; exists {
		if auth, ok := authConfig.(entity.AuthenticationConfig); ok {
			if auth.Type == "" {
				return fmt.Errorf("authentication type is required")
			}
		} else {
			return fmt.Errorf("invalid auth_config format")
		}
	} else {
		return fmt.Errorf("auth_config is required")
	}

	return nil
}

func (f *VulnerabilityManagementConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

func (f *NetworkSecurityConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

func (f *CloudSecurityConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

func (f *IAMConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

func (f *CustomConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

func (f *GenericConnectorFactory) validateCommonConfiguration(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateCommonConfigBase(config, vendor)
}

// validateCommonConfigBase provides base validation logic
func (f *VulnerabilityManagementConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	// Validate connection configuration
	if connectionConfig, exists := config["connection_config"]; exists {
		if connConfig, ok := connectionConfig.(entity.ConnectionConfig); ok {
			if connConfig.BaseURL == "" {
				return fmt.Errorf("base_url is required in connection configuration")
			}
		} else {
			return fmt.Errorf("invalid connection_config format")
		}
	} else {
		return fmt.Errorf("connection_config is required")
	}

	// Validate authentication configuration
	if authConfig, exists := config["auth_config"]; exists {
		if auth, ok := authConfig.(entity.AuthenticationConfig); ok {
			if auth.Type == "" {
				return fmt.Errorf("authentication type is required")
			}
		} else {
			return fmt.Errorf("invalid auth_config format")
		}
	} else {
		return fmt.Errorf("auth_config is required")
	}

	return nil
}

func (f *NetworkSecurityConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateBaseConfig(config)
}

func (f *CloudSecurityConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateBaseConfig(config)
}

func (f *IAMConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateBaseConfig(config)
}

func (f *CustomConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateBaseConfig(config)
}

func (f *GenericConnectorFactory) validateCommonConfigBase(config map[string]interface{}, vendor entity.SourceSystemVendor) error {
	return f.validateBaseConfig(config)
}

func (f *NetworkSecurityConnectorFactory) validateBaseConfig(config map[string]interface{}) error {
	// Validate connection configuration
	if connectionConfig, exists := config["connection_config"]; exists {
		if connConfig, ok := connectionConfig.(entity.ConnectionConfig); ok {
			if connConfig.BaseURL == "" {
				return fmt.Errorf("base_url is required in connection configuration")
			}
		} else {
			return fmt.Errorf("invalid connection_config format")
		}
	} else {
		return fmt.Errorf("connection_config is required")
	}

	// Validate authentication configuration
	if authConfig, exists := config["auth_config"]; exists {
		if auth, ok := authConfig.(entity.AuthenticationConfig); ok {
			if auth.Type == "" {
				return fmt.Errorf("authentication type is required")
			}
		} else {
			return fmt.Errorf("invalid auth_config format")
		}
	} else {
		return fmt.Errorf("auth_config is required")
	}

	return nil
}

func (f *CloudSecurityConnectorFactory) validateBaseConfig(config map[string]interface{}) error {
	return validateConfigBase(config)
}

func (f *IAMConnectorFactory) validateBaseConfig(config map[string]interface{}) error {
	return validateConfigBase(config)
}

func (f *CustomConnectorFactory) validateBaseConfig(config map[string]interface{}) error {
	return validateConfigBase(config)
}

func (f *GenericConnectorFactory) validateBaseConfig(config map[string]interface{}) error {
	return validateConfigBase(config)
}

// validateConfigBase provides the most basic validation
func validateConfigBase(config map[string]interface{}) error {
	// Validate connection configuration
	if connectionConfig, exists := config["connection_config"]; exists {
		if connConfig, ok := connectionConfig.(entity.ConnectionConfig); ok {
			if connConfig.BaseURL == "" {
				return fmt.Errorf("base_url is required in connection configuration")
			}
		} else {
			return fmt.Errorf("invalid connection_config format")
		}
	} else {
		return fmt.Errorf("connection_config is required")
	}

	// Validate authentication configuration
	if authConfig, exists := config["auth_config"]; exists {
		if auth, ok := authConfig.(entity.AuthenticationConfig); ok {
			if auth.Type == "" {
				return fmt.Errorf("authentication type is required")
			}
		} else {
			return fmt.Errorf("invalid auth_config format")
		}
	} else {
		return fmt.Errorf("auth_config is required")
	}

	return nil
}

// Placeholder connector creation functions (these would be implemented in separate files)

// Endpoint Protection Connectors
func NewCrowdStrikeConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement CrowdStrike connector
	return nil, fmt.Errorf("CrowdStrike connector not yet implemented")
}

func NewSentinelOneConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement SentinelOne connector
	return nil, fmt.Errorf("SentinelOne connector not yet implemented")
}

func NewCarbonBlackConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Carbon Black connector
	return nil, fmt.Errorf("Carbon Black connector not yet implemented")
}

func NewCylanceConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Cylance connector
	return nil, fmt.Errorf("Cylance connector not yet implemented")
}

func NewTrendMicroConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Trend Micro connector
	return nil, fmt.Errorf("Trend Micro connector not yet implemented")
}

func NewSymantecConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Symantec connector
	return nil, fmt.Errorf("Symantec connector not yet implemented")
}

func NewMcAfeeConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement McAfee connector
	return nil, fmt.Errorf("McAfee connector not yet implemented")
}

func NewKasperskyConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Kaspersky connector
	return nil, fmt.Errorf("Kaspersky connector not yet implemented")
}

func NewSophosConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Sophos connector
	return nil, fmt.Errorf("Sophos connector not yet implemented")
}

func NewBitdefenderConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Bitdefender connector
	return nil, fmt.Errorf("Bitdefender connector not yet implemented")
}

// Vulnerability Management Connectors
func NewTenableConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Tenable connector
	return nil, fmt.Errorf("Tenable connector not yet implemented")
}

func NewQualysConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Qualys connector
	return nil, fmt.Errorf("Qualys connector not yet implemented")
}

func NewRapid7Connector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Rapid7 connector
	return nil, fmt.Errorf("Rapid7 connector not yet implemented")
}

func NewGreenboneConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Greenbone connector
	return nil, fmt.Errorf("Greenbone connector not yet implemented")
}

func NewNessusConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Nessus connector
	return nil, fmt.Errorf("Nessus connector not yet implemented")
}

func NewOpenVASConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement OpenVAS connector
	return nil, fmt.Errorf("OpenVAS connector not yet implemented")
}

// Additional SIEM Connectors
func NewArcSightConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement ArcSight connector
	return nil, fmt.Errorf("ArcSight connector not yet implemented")
}

func NewLogRhythmConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement LogRhythm connector
	return nil, fmt.Errorf("LogRhythm connector not yet implemented")
}

func NewElasticConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement Elastic connector
	return nil, fmt.Errorf("Elastic connector not yet implemented")
}

func NewSumoLogicConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement SumoLogic connector
	return nil, fmt.Errorf("SumoLogic connector not yet implemented")
}

func NewAlienVaultConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	// TODO: Implement AlienVault connector
	return nil, fmt.Errorf("AlienVault connector not yet implemented")
}

// Network Security, Cloud Security, IAM, and other connectors would follow similar patterns...
// These are placeholders for the full implementation

func NewPaloAltoConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Palo Alto connector not yet implemented")
}

func NewFortinetConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Fortinet connector not yet implemented")
}

func NewCiscoConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Cisco connector not yet implemented")
}

func NewCheckPointConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Check Point connector not yet implemented")
}

func NewJuniperConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Juniper connector not yet implemented")
}

func NewSonicWallConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("SonicWall connector not yet implemented")
}

func NewPrismaCloudConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Prisma Cloud connector not yet implemented")
}

func NewLaceworkConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Lacework connector not yet implemented")
}

func NewCloudFlareConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("CloudFlare connector not yet implemented")
}

func NewAWSConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("AWS connector not yet implemented")
}

func NewAzureConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Azure connector not yet implemented")
}

func NewGCPConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("GCP connector not yet implemented")
}

func NewOktaConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Okta connector not yet implemented")
}

func NewPingIdentityConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Ping Identity connector not yet implemented")
}

func NewCyberArkConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("CyberArk connector not yet implemented")
}

func NewSailPointConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("SailPoint connector not yet implemented")
}

func NewCustomConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Custom connector not yet implemented")
}

func NewGenericConnector(sourceSystem *entity.SourceSystem) (DataExtractor, error) {
	return nil, fmt.Errorf("Generic connector not yet implemented")
}