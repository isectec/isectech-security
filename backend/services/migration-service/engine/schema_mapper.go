package engine

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// DefaultSchemaMapper is the production implementation of SchemaMapper
type DefaultSchemaMapper struct {
	// Configuration
	config              *SchemaMapperConfig

	// Mapping cache
	mappingCache        map[string]*SchemaMapping
	mappingCacheMutex   sync.RWMutex

	// Built-in transformations
	transformationRules map[entity.SourceSystemVendor]map[entity.DataType]*TransformationRuleSet

	// Security and compliance
	securityValidator   *SecurityValidator
	complianceChecker   *ComplianceChecker
	auditLogger         *AuditLogger

	// Metrics
	metricsCollector    *SchemaMappingMetricsCollector
}

// SchemaMapperConfig contains configuration for the schema mapper
type SchemaMapperConfig struct {
	// Caching
	EnableCaching         bool          `json:"enable_caching"`
	CacheTTL              time.Duration `json:"cache_ttl"`
	MaxCacheSize          int32         `json:"max_cache_size"`

	// Mapping behavior
	AutoGenerateMappings  bool          `json:"auto_generate_mappings"`
	StrictTypeValidation  bool          `json:"strict_type_validation"`
	AllowNullableFields   bool          `json:"allow_nullable_fields"`
	PreserveSourceFields  bool          `json:"preserve_source_fields"`

	// Field mapping
	DefaultFieldMapping   map[string]string    `json:"default_field_mapping"`
	IgnoredFields         []string             `json:"ignored_fields"`
	RequiredFields        []string             `json:"required_fields"`

	// Data transformation
	EnableDataNormalization bool         `json:"enable_data_normalization"`
	DateTimeFormat          string       `json:"datetime_format"`
	TimeZone                string       `json:"timezone"`
	DefaultStringLength     int32        `json:"default_string_length"`

	// Security
	EncryptPIIFields      bool          `json:"encrypt_pii_fields"`
	PIIFieldPatterns      []string      `json:"pii_field_patterns"`
	SecurityClearance     string        `json:"security_clearance"`

	// Compliance
	ComplianceFrameworks  []string      `json:"compliance_frameworks"`
	DataClassification    string        `json:"data_classification"`
	RetentionPeriod       time.Duration `json:"retention_period"`
}

// TransformationRuleSet contains transformation rules for a specific vendor/data type combination
type TransformationRuleSet struct {
	Vendor             entity.SourceSystemVendor    `json:"vendor"`
	DataType           entity.DataType              `json:"data_type"`
	Version            string                       `json:"version"`
	
	// Field mappings
	FieldMappings      map[string]*FieldMapping     `json:"field_mappings"`
	
	// Data transformations
	DataTransformations []*DataTransformation       `json:"data_transformations"`
	
	// Validation rules
	ValidationRules    []*ValidationRule            `json:"validation_rules"`
	
	// Metadata
	CreatedAt          time.Time                    `json:"created_at"`
	UpdatedAt          time.Time                    `json:"updated_at"`
	CreatedBy          uuid.UUID                    `json:"created_by"`
}

// FieldMapping defines how a source field maps to target field(s)
type FieldMapping struct {
	SourceField        string                       `json:"source_field"`
	TargetField        string                       `json:"target_field"`
	DataType           entity.FieldDataType         `json:"data_type"`
	Required           bool                         `json:"required"`
	Nullable           bool                         `json:"nullable"`
	DefaultValue       interface{}                  `json:"default_value"`
	
	// Transformation
	TransformationType string                       `json:"transformation_type"`
	TransformationConfig map[string]interface{}     `json:"transformation_config"`
	
	// Validation
	ValidationRules    []*FieldValidationRule       `json:"validation_rules"`
	
	// Security
	EncryptField       bool                         `json:"encrypt_field"`
	PIIField           bool                         `json:"pii_field"`
	AccessLevel        string                       `json:"access_level"`
}

// DataTransformation defines a data transformation operation
type DataTransformation struct {
	ID                 uuid.UUID                    `json:"id"`
	Name               string                       `json:"name"`
	Description        string                       `json:"description"`
	Type               TransformationType           `json:"type"`
	Configuration      map[string]interface{}       `json:"configuration"`
	ApplyToFields      []string                     `json:"apply_to_fields"`
	Priority           int32                        `json:"priority"`
	Enabled            bool                         `json:"enabled"`
}

// FieldValidationRule defines validation for a field
type FieldValidationRule struct {
	RuleType           string                       `json:"rule_type"`
	RuleValue          interface{}                  `json:"rule_value"`
	ErrorMessage       string                       `json:"error_message"`
	Severity           string                       `json:"severity"`
}

// TransformationType represents the type of transformation
type TransformationType string

const (
	TransformationTypeNormalization TransformationType = "normalization"
	TransformationTypeFormatting    TransformationType = "formatting"
	TransformationTypeEnrichment    TransformationType = "enrichment"
	TransformationTypeFiltering     TransformationType = "filtering"
	TransformationTypeAggregation   TransformationType = "aggregation"
	TransformationTypeEncryption    TransformationType = "encryption"
	TransformationTypeRedaction     TransformationType = "redaction"
)

// NewDefaultSchemaMapper creates a new default schema mapper
func NewDefaultSchemaMapper(config *SchemaMapperConfig) *DefaultSchemaMapper {
	if config == nil {
		config = getDefaultSchemaMapperConfig()
	}

	mapper := &DefaultSchemaMapper{
		config:              config,
		mappingCache:        make(map[string]*SchemaMapping),
		transformationRules: make(map[entity.SourceSystemVendor]map[entity.DataType]*TransformationRuleSet),
		securityValidator:   NewSecurityValidator(config.SecurityClearance),
		complianceChecker:   NewComplianceChecker(config.ComplianceFrameworks),
		auditLogger:         NewAuditLogger(true),
		metricsCollector:    NewSchemaMappingMetricsCollector(),
	}

	// Initialize built-in transformation rules
	mapper.initializeBuiltInRules()

	return mapper
}

// CreateMapping creates a schema mapping for transforming data
func (m *DefaultSchemaMapper) CreateMapping(ctx context.Context, sourceSchema *entity.DataSchema, dataType entity.DataType) (*SchemaMapping, error) {
	if sourceSchema == nil {
		return nil, fmt.Errorf("source schema cannot be nil")
	}

	// Check cache first
	cacheKey := m.generateCacheKey(sourceSchema, dataType)
	if m.config.EnableCaching {
		if cached := m.getCachedMapping(cacheKey); cached != nil {
			return cached, nil
		}
	}

	// Perform security validation
	if err := m.securityValidator.ValidateSchema(ctx, sourceSchema); err != nil {
		return nil, fmt.Errorf("schema security validation failed: %w", err)
	}

	// Perform compliance validation
	if err := m.complianceChecker.ValidateSchema(ctx, sourceSchema); err != nil {
		return nil, fmt.Errorf("schema compliance validation failed: %w", err)
	}

	// Create target schema based on iSECTECH data model
	targetSchema, err := m.createTargetSchema(ctx, sourceSchema, dataType)
	if err != nil {
		return nil, fmt.Errorf("failed to create target schema: %w", err)
	}

	// Create field mappings
	fieldMappings, err := m.createFieldMappings(ctx, sourceSchema, targetSchema, dataType)
	if err != nil {
		return nil, fmt.Errorf("failed to create field mappings: %w", err)
	}

	// Get transformation rules for this vendor/data type
	transformationRules := m.getTransformationRules(sourceSchema.Vendor, dataType)

	// Create schema mapping
	mapping := &SchemaMapping{
		ID:                  uuid.New(),
		SourceSchema:        sourceSchema,
		TargetSchema:        targetSchema,
		DataType:            dataType,
		FieldMappings:       fieldMappings,
		TransformationRules: transformationRules,
		
		// Configuration
		StrictTypeValidation: m.config.StrictTypeValidation,
		PreserveSourceFields: m.config.PreserveSourceFields,
		
		// Security and compliance
		SecurityClearance:    m.config.SecurityClearance,
		ComplianceFrameworks: m.config.ComplianceFrameworks,
		DataClassification:   m.config.DataClassification,
		
		// Metadata
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		Version:             "1.0",
	}

	// Validate the mapping
	if err := m.validateMapping(ctx, mapping); err != nil {
		return nil, fmt.Errorf("mapping validation failed: %w", err)
	}

	// Cache the mapping
	if m.config.EnableCaching {
		m.cacheMapping(cacheKey, mapping)
	}

	// Log mapping creation
	m.auditLogger.LogJobEvent(ctx, uuid.Nil, "schema_mapping_created", map[string]interface{}{
		"mapping_id":        mapping.ID,
		"source_vendor":     sourceSchema.Vendor,
		"data_type":         dataType,
		"field_count":       len(fieldMappings),
		"transformation_count": len(transformationRules.DataTransformations),
	})

	return mapping, nil
}

// TransformData transforms data using the provided schema mapping
func (m *DefaultSchemaMapper) TransformData(ctx context.Context, data []map[string]interface{}, mapping *SchemaMapping) (*TransformationResult, error) {
	if mapping == nil {
		return nil, fmt.Errorf("schema mapping cannot be nil")
	}

	if len(data) == 0 {
		return &TransformationResult{
			TransformedData:     make([]map[string]interface{}, 0),
			TransformationLog:   make([]TransformationRecord, 0),
			QualityScore:        100.0,
			ProcessedRecords:    0,
			SuccessfulRecords:   0,
			FailedRecords:       0,
		}, nil
	}

	result := &TransformationResult{
		TransformedData:     make([]map[string]interface{}, 0, len(data)),
		TransformationLog:   make([]TransformationRecord, 0),
		ProcessedRecords:    int64(len(data)),
		SuccessfulRecords:   0,
		FailedRecords:       0,
	}

	// Transform each record
	for i, record := range data {
		transformedRecord, err := m.transformRecord(ctx, record, mapping, i)
		if err != nil {
			result.FailedRecords++
			
			// Log transformation error
			result.TransformationLog = append(result.TransformationLog, TransformationRecord{
				RecordIndex:        int32(i),
				TransformationType: "record_transformation",
				Status:             "failed",
				Error:              err.Error(),
				Timestamp:          time.Now(),
			})
			
			// Skip record if strict validation is enabled
			if mapping.StrictTypeValidation {
				continue
			}
		} else {
			result.SuccessfulRecords++
			result.TransformedData = append(result.TransformedData, transformedRecord)
		}
	}

	// Calculate quality score
	if result.ProcessedRecords > 0 {
		result.QualityScore = float64(result.SuccessfulRecords) / float64(result.ProcessedRecords) * 100.0
	}

	// Log transformation completion
	m.auditLogger.LogJobEvent(ctx, uuid.Nil, "data_transformation_completed", map[string]interface{}{
		"mapping_id":         mapping.ID,
		"processed_records":  result.ProcessedRecords,
		"successful_records": result.SuccessfulRecords,
		"failed_records":     result.FailedRecords,
		"quality_score":      result.QualityScore,
	})

	return result, nil
}

// ValidateMapping validates a schema mapping configuration
func (m *DefaultSchemaMapper) ValidateMapping(ctx context.Context, mapping *SchemaMapping) (*MappingValidationResult, error) {
	if mapping == nil {
		return nil, fmt.Errorf("schema mapping cannot be nil")
	}

	validationResult := &MappingValidationResult{
		IsValid:    true,
		Errors:     make([]MappingValidationError, 0),
		Warnings:   make([]MappingValidationWarning, 0),
		Score:      100.0,
	}

	// Validate source schema
	if mapping.SourceSchema == nil {
		validationResult.IsValid = false
		validationResult.addError("source_schema", "Source schema is required", "error")
	}

	// Validate target schema
	if mapping.TargetSchema == nil {
		validationResult.IsValid = false
		validationResult.addError("target_schema", "Target schema is required", "error")
	}

	// Validate field mappings
	if len(mapping.FieldMappings) == 0 {
		validationResult.IsValid = false
		validationResult.addError("field_mappings", "At least one field mapping is required", "error")
	}

	// Validate individual field mappings
	for fieldName, fieldMapping := range mapping.FieldMappings {
		if err := m.validateFieldMapping(fieldName, fieldMapping); err != nil {
			validationResult.addWarning("field_mapping", fmt.Sprintf("Field mapping validation warning for %s: %v", fieldName, err), "Review field mapping configuration")
			validationResult.Score -= 5.0
		}
	}

	// Validate required fields are mapped
	if mapping.TargetSchema != nil {
		for _, field := range mapping.TargetSchema.Fields {
			if field.Required {
				if _, exists := mapping.FieldMappings[field.Name]; !exists {
					validationResult.addWarning("required_field", fmt.Sprintf("Required field %s is not mapped", field.Name), "Add mapping for required field")
					validationResult.Score -= 10.0
				}
			}
		}
	}

	// Validate transformation rules
	if mapping.TransformationRules != nil {
		for _, transformation := range mapping.TransformationRules.DataTransformations {
			if err := m.validateTransformation(transformation); err != nil {
				validationResult.addWarning("transformation", fmt.Sprintf("Transformation validation warning: %v", err), "Review transformation configuration")
				validationResult.Score -= 3.0
			}
		}
	}

	// Calculate final score
	if validationResult.IsValid && len(validationResult.Warnings) == 0 {
		validationResult.Score = 100.0
	} else if !validationResult.IsValid {
		validationResult.Score = 0.0
	}

	return validationResult, nil
}

// GetSupportedTransformations returns available transformation types
func (m *DefaultSchemaMapper) GetSupportedTransformations() []TransformationType {
	return []TransformationType{
		TransformationTypeNormalization,
		TransformationTypeFormatting,
		TransformationTypeEnrichment,
		TransformationTypeFiltering,
		TransformationTypeAggregation,
		TransformationTypeEncryption,
		TransformationTypeRedaction,
	}
}

// Private helper methods

// createTargetSchema creates the target schema based on iSECTECH data model
func (m *DefaultSchemaMapper) createTargetSchema(ctx context.Context, sourceSchema *entity.DataSchema, dataType entity.DataType) (*entity.DataSchema, error) {
	targetSchema := &entity.DataSchema{
		ID:          uuid.New(),
		Name:        fmt.Sprintf("iSECTECH_%s_Schema", dataType),
		Description: fmt.Sprintf("Target schema for %s data type", dataType),
		Version:     "1.0",
		DataType:    dataType,
		Vendor:      "iSECTECH", // Internal vendor
		Fields:      make([]*entity.DataField, 0),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Add standard iSECTECH fields based on data type
	standardFields := m.getStandardFields(dataType)
	targetSchema.Fields = append(targetSchema.Fields, standardFields...)

	// Add security and compliance fields
	securityFields := m.getSecurityFields(m.config.SecurityClearance)
	targetSchema.Fields = append(targetSchema.Fields, securityFields...)

	complianceFields := m.getComplianceFields(m.config.ComplianceFrameworks)
	targetSchema.Fields = append(targetSchema.Fields, complianceFields...)

	return targetSchema, nil
}

// createFieldMappings creates field mappings between source and target schemas
func (m *DefaultSchemaMapper) createFieldMappings(ctx context.Context, sourceSchema, targetSchema *entity.DataSchema, dataType entity.DataType) (map[string]*FieldMapping, error) {
	fieldMappings := make(map[string]*FieldMapping)

	// Get transformation rules for this vendor/data type
	rules := m.getTransformationRules(sourceSchema.Vendor, dataType)

	// Create mappings for each target field
	for _, targetField := range targetSchema.Fields {
		// Check if there's a predefined mapping rule
		if rules != nil {
			if mapping, exists := rules.FieldMappings[targetField.Name]; exists {
				fieldMappings[targetField.Name] = mapping
				continue
			}
		}

		// Auto-generate mapping if enabled
		if m.config.AutoGenerateMappings {
			sourceField := m.findBestSourceFieldMatch(targetField, sourceSchema.Fields)
			if sourceField != nil {
				fieldMappings[targetField.Name] = &FieldMapping{
					SourceField:        sourceField.Name,
					TargetField:        targetField.Name,
					DataType:           targetField.DataType,
					Required:           targetField.Required,
					Nullable:           targetField.Nullable,
					TransformationType: "direct_copy",
					ValidationRules:    m.createValidationRules(targetField),
					EncryptField:       m.shouldEncryptField(targetField.Name),
					PIIField:           m.isPIIField(targetField.Name),
					AccessLevel:        m.determineAccessLevel(targetField.Name),
				}
			}
		}
	}

	return fieldMappings, nil
}

// transformRecord transforms a single record using the schema mapping
func (m *DefaultSchemaMapper) transformRecord(ctx context.Context, record map[string]interface{}, mapping *SchemaMapping, recordIndex int) (map[string]interface{}, error) {
	transformedRecord := make(map[string]interface{})

	// Apply field mappings
	for targetField, fieldMapping := range mapping.FieldMappings {
		value, exists := record[fieldMapping.SourceField]
		if !exists {
			if fieldMapping.Required {
				return nil, fmt.Errorf("required field %s not found in source record", fieldMapping.SourceField)
			}
			
			// Use default value if available
			if fieldMapping.DefaultValue != nil {
				value = fieldMapping.DefaultValue
			} else if fieldMapping.Nullable {
				value = nil
			} else {
				continue
			}
		}

		// Apply field transformations
		transformedValue, err := m.applyFieldTransformations(ctx, value, fieldMapping)
		if err != nil {
			if mapping.StrictTypeValidation {
				return nil, fmt.Errorf("field transformation failed for %s: %w", targetField, err)
			}
			// Log warning and use original value
			transformedValue = value
		}

		// Validate transformed value
		if err := m.validateFieldValue(transformedValue, fieldMapping); err != nil {
			if mapping.StrictTypeValidation {
				return nil, fmt.Errorf("field validation failed for %s: %w", targetField, err)
			}
		}

		transformedRecord[targetField] = transformedValue
	}

	// Add standard iSECTECH metadata fields
	transformedRecord["_migration_timestamp"] = time.Now()
	transformedRecord["_migration_id"] = mapping.ID
	transformedRecord["_source_vendor"] = mapping.SourceSchema.Vendor
	transformedRecord["_data_type"] = mapping.DataType
	transformedRecord["_record_index"] = recordIndex

	// Add security fields if configured
	if m.config.SecurityClearance != "" {
		transformedRecord["_security_clearance"] = m.config.SecurityClearance
	}

	// Add compliance fields if configured
	if len(m.config.ComplianceFrameworks) > 0 {
		transformedRecord["_compliance_frameworks"] = m.config.ComplianceFrameworks
	}

	return transformedRecord, nil
}

// applyFieldTransformations applies transformations to a field value
func (m *DefaultSchemaMapper) applyFieldTransformations(ctx context.Context, value interface{}, fieldMapping *FieldMapping) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	transformedValue := value

	// Apply transformation based on type
	switch fieldMapping.TransformationType {
	case "direct_copy":
		// No transformation needed
		
	case "type_conversion":
		var err error
		transformedValue, err = m.convertDataType(value, fieldMapping.DataType)
		if err != nil {
			return nil, fmt.Errorf("type conversion failed: %w", err)
		}
		
	case "normalization":
		transformedValue = m.normalizeValue(value, fieldMapping.TransformationConfig)
		
	case "formatting":
		transformedValue = m.formatValue(value, fieldMapping.TransformationConfig)
		
	case "encryption":
		if fieldMapping.EncryptField {
			var err error
			transformedValue, err = m.encryptValue(value)
			if err != nil {
				return nil, fmt.Errorf("encryption failed: %w", err)
			}
		}
		
	case "redaction":
		if fieldMapping.PIIField {
			transformedValue = m.redactPIIValue(value)
		}
		
	default:
		// Unknown transformation type - log warning
		return value, fmt.Errorf("unknown transformation type: %s", fieldMapping.TransformationType)
	}

	return transformedValue, nil
}

// Helper methods for data processing

func (m *DefaultSchemaMapper) convertDataType(value interface{}, targetType entity.FieldDataType) (interface{}, error) {
	if value == nil {
		return nil, nil
	}

	sourceValue := reflect.ValueOf(value)
	
	switch targetType {
	case entity.FieldDataTypeString:
		return fmt.Sprintf("%v", value), nil
	case entity.FieldDataTypeInteger:
		if sourceValue.Kind() == reflect.String {
			// Try to convert string to integer
			return fmt.Sprintf("%v", value), nil // Simplified
		}
		return value, nil
	case entity.FieldDataTypeFloat:
		return value, nil // Simplified conversion
	case entity.FieldDataTypeBool:
		if str, ok := value.(string); ok {
			return strings.ToLower(str) == "true" || str == "1", nil
		}
		return value, nil
	case entity.FieldDataTypeDateTime:
		if str, ok := value.(string); ok {
			// Parse datetime string
			if m.config.DateTimeFormat != "" {
				parsedTime, err := time.Parse(m.config.DateTimeFormat, str)
				if err == nil {
					return parsedTime, nil
				}
			}
			// Try common formats
			for _, format := range []string{time.RFC3339, time.RFC822, "2006-01-02 15:04:05"} {
				if parsedTime, err := time.Parse(format, str); err == nil {
					return parsedTime, nil
				}
			}
		}
		return value, nil
	default:
		return value, nil
	}
}

func (m *DefaultSchemaMapper) normalizeValue(value interface{}, config map[string]interface{}) interface{} {
	if str, ok := value.(string); ok {
		// Basic string normalization
		normalized := strings.TrimSpace(str)
		if toLower, exists := config["to_lower"]; exists && toLower.(bool) {
			normalized = strings.ToLower(normalized)
		}
		if toUpper, exists := config["to_upper"]; exists && toUpper.(bool) {
			normalized = strings.ToUpper(normalized)
		}
		return normalized
	}
	return value
}

func (m *DefaultSchemaMapper) formatValue(value interface{}, config map[string]interface{}) interface{} {
	if format, exists := config["format"]; exists {
		if formatStr, ok := format.(string); ok {
			return fmt.Sprintf(formatStr, value)
		}
	}
	return value
}

func (m *DefaultSchemaMapper) encryptValue(value interface{}) (interface{}, error) {
	// Placeholder implementation - would use proper encryption
	if str, ok := value.(string); ok {
		return fmt.Sprintf("ENCRYPTED[%s]", str), nil
	}
	return value, nil
}

func (m *DefaultSchemaMapper) redactPIIValue(value interface{}) interface{} {
	if str, ok := value.(string); ok {
		if len(str) > 4 {
			return str[:2] + "***" + str[len(str)-2:]
		}
		return "***"
	}
	return "***"
}

// Schema and field helper methods

func (m *DefaultSchemaMapper) getStandardFields(dataType entity.DataType) []*entity.DataField {
	commonFields := []*entity.DataField{
		{
			Name:        "id",
			DisplayName: "Unique Identifier",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Unique identifier for the record",
		},
		{
			Name:        "timestamp",
			DisplayName: "Timestamp",
			DataType:    entity.FieldDataTypeDateTime,
			Required:    true,
			Nullable:    false,
			Description: "Record timestamp",
		},
		{
			Name:        "source_system",
			DisplayName: "Source System",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Source system identifier",
		},
	}

	// Add data type specific fields
	switch dataType {
	case entity.DataTypeAlerts:
		return append(commonFields, []*entity.DataField{
			{Name: "severity", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "title", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "description", DataType: entity.FieldDataTypeString, Required: false},
			{Name: "status", DataType: entity.FieldDataTypeString, Required: true},
		}...)
	case entity.DataTypeIncidents:
		return append(commonFields, []*entity.DataField{
			{Name: "incident_id", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "priority", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "status", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "assigned_to", DataType: entity.FieldDataTypeString, Required: false},
		}...)
	case entity.DataTypeEvents:
		return append(commonFields, []*entity.DataField{
			{Name: "event_type", DataType: entity.FieldDataTypeString, Required: true},
			{Name: "source_ip", DataType: entity.FieldDataTypeString, Required: false},
			{Name: "destination_ip", DataType: entity.FieldDataTypeString, Required: false},
			{Name: "user_agent", DataType: entity.FieldDataTypeString, Required: false},
		}...)
	default:
		return commonFields
	}
}

func (m *DefaultSchemaMapper) getSecurityFields(securityClearance string) []*entity.DataField {
	return []*entity.DataField{
		{
			Name:        "_security_clearance",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Security clearance level",
		},
		{
			Name:        "_access_level",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Data access level",
		},
	}
}

func (m *DefaultSchemaMapper) getComplianceFields(frameworks []string) []*entity.DataField {
	return []*entity.DataField{
		{
			Name:        "_compliance_frameworks",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Applicable compliance frameworks",
		},
		{
			Name:        "_data_classification",
			DataType:    entity.FieldDataTypeString,
			Required:    true,
			Nullable:    false,
			Description: "Data classification level",
		},
	}
}

// Mapping validation and helper methods

func (m *DefaultSchemaMapper) findBestSourceFieldMatch(targetField *entity.DataField, sourceFields []*entity.DataField) *entity.DataField {
	// Direct name match
	for _, sourceField := range sourceFields {
		if sourceField.Name == targetField.Name {
			return sourceField
		}
	}

	// Case-insensitive match
	for _, sourceField := range sourceFields {
		if strings.EqualFold(sourceField.Name, targetField.Name) {
			return sourceField
		}
	}

	// Partial match with common patterns
	targetLower := strings.ToLower(targetField.Name)
	for _, sourceField := range sourceFields {
		sourceLower := strings.ToLower(sourceField.Name)
		
		// Check for common field name patterns
		if m.isFieldNameMatch(targetLower, sourceLower) {
			return sourceField
		}
	}

	return nil
}

func (m *DefaultSchemaMapper) isFieldNameMatch(target, source string) bool {
	// Common field name patterns
	patterns := map[string][]string{
		"timestamp": {"time", "date", "created", "modified", "updated"},
		"severity":  {"sev", "level", "priority", "criticality"},
		"title":     {"name", "summary", "subject", "header"},
		"description": {"desc", "details", "message", "content"},
		"source_ip": {"src_ip", "srcip", "source_address", "src_addr"},
		"destination_ip": {"dest_ip", "destip", "destination_address", "dest_addr"},
	}

	if synonyms, exists := patterns[target]; exists {
		for _, synonym := range synonyms {
			if strings.Contains(source, synonym) {
				return true
			}
		}
	}

	return false
}

func (m *DefaultSchemaMapper) shouldEncryptField(fieldName string) bool {
	encryptFields := []string{"password", "token", "key", "secret", "credential"}
	fieldLower := strings.ToLower(fieldName)
	
	for _, pattern := range encryptFields {
		if strings.Contains(fieldLower, pattern) {
			return true
		}
	}
	
	return false
}

func (m *DefaultSchemaMapper) isPIIField(fieldName string) bool {
	piiPatterns := m.config.PIIFieldPatterns
	if len(piiPatterns) == 0 {
		piiPatterns = []string{"email", "phone", "ssn", "address", "name", "username"}
	}
	
	fieldLower := strings.ToLower(fieldName)
	for _, pattern := range piiPatterns {
		if strings.Contains(fieldLower, pattern) {
			return true
		}
	}
	
	return false
}

func (m *DefaultSchemaMapper) determineAccessLevel(fieldName string) string {
	if m.isPIIField(fieldName) {
		return "restricted"
	}
	if m.shouldEncryptField(fieldName) {
		return "confidential"
	}
	return "internal"
}

// Cache management

func (m *DefaultSchemaMapper) generateCacheKey(sourceSchema *entity.DataSchema, dataType entity.DataType) string {
	return fmt.Sprintf("%s_%s_%s_%s", sourceSchema.Vendor, sourceSchema.Version, dataType, sourceSchema.ID)
}

func (m *DefaultSchemaMapper) getCachedMapping(key string) *SchemaMapping {
	m.mappingCacheMutex.RLock()
	defer m.mappingCacheMutex.RUnlock()
	
	if mapping, exists := m.mappingCache[key]; exists {
		// Check if mapping is still valid (TTL)
		if time.Since(mapping.CreatedAt) < m.config.CacheTTL {
			return mapping
		}
	}
	
	return nil
}

func (m *DefaultSchemaMapper) cacheMapping(key string, mapping *SchemaMapping) {
	m.mappingCacheMutex.Lock()
	defer m.mappingCacheMutex.Unlock()
	
	// Check cache size limit
	if int32(len(m.mappingCache)) >= m.config.MaxCacheSize {
		// Simple eviction: remove oldest entry
		var oldestKey string
		var oldestTime time.Time = time.Now()
		
		for k, v := range m.mappingCache {
			if v.CreatedAt.Before(oldestTime) {
				oldestTime = v.CreatedAt
				oldestKey = k
			}
		}
		
		if oldestKey != "" {
			delete(m.mappingCache, oldestKey)
		}
	}
	
	m.mappingCache[key] = mapping
}

// Validation methods

func (m *DefaultSchemaMapper) validateMapping(ctx context.Context, mapping *SchemaMapping) error {
	validationResult, err := m.ValidateMapping(ctx, mapping)
	if err != nil {
		return err
	}
	
	if !validationResult.IsValid {
		return fmt.Errorf("mapping validation failed with %d errors", len(validationResult.Errors))
	}
	
	return nil
}

func (m *DefaultSchemaMapper) validateFieldMapping(fieldName string, mapping *FieldMapping) error {
	if mapping.SourceField == "" {
		return fmt.Errorf("source field is required")
	}
	
	if mapping.TargetField == "" {
		return fmt.Errorf("target field is required")
	}
	
	return nil
}

func (m *DefaultSchemaMapper) validateTransformation(transformation *DataTransformation) error {
	if transformation.Name == "" {
		return fmt.Errorf("transformation name is required")
	}
	
	if transformation.Type == "" {
		return fmt.Errorf("transformation type is required")
	}
	
	return nil
}

func (m *DefaultSchemaMapper) validateFieldValue(value interface{}, fieldMapping *FieldMapping) error {
	if value == nil && !fieldMapping.Nullable {
		return fmt.Errorf("field cannot be null")
	}
	
	// Apply validation rules
	for _, rule := range fieldMapping.ValidationRules {
		if err := m.applyValidationRule(value, rule); err != nil {
			return err
		}
	}
	
	return nil
}

func (m *DefaultSchemaMapper) applyValidationRule(value interface{}, rule *FieldValidationRule) error {
	// Simplified validation rule application
	switch rule.RuleType {
	case "required":
		if value == nil {
			return fmt.Errorf(rule.ErrorMessage)
		}
	case "max_length":
		if str, ok := value.(string); ok {
			if maxLen, ok := rule.RuleValue.(int); ok {
				if len(str) > maxLen {
					return fmt.Errorf(rule.ErrorMessage)
				}
			}
		}
	case "min_length":
		if str, ok := value.(string); ok {
			if minLen, ok := rule.RuleValue.(int); ok {
				if len(str) < minLen {
					return fmt.Errorf(rule.ErrorMessage)
				}
			}
		}
	}
	
	return nil
}

func (m *DefaultSchemaMapper) createValidationRules(field *entity.DataField) []*FieldValidationRule {
	var rules []*FieldValidationRule
	
	if field.Required {
		rules = append(rules, &FieldValidationRule{
			RuleType:     "required",
			RuleValue:    true,
			ErrorMessage: fmt.Sprintf("Field %s is required", field.Name),
			Severity:     "error",
		})
	}
	
	if field.DataType == entity.FieldDataTypeString {
		if m.config.DefaultStringLength > 0 {
			rules = append(rules, &FieldValidationRule{
				RuleType:     "max_length",
				RuleValue:    m.config.DefaultStringLength,
				ErrorMessage: fmt.Sprintf("Field %s exceeds maximum length", field.Name),
				Severity:     "warning",
			})
		}
	}
	
	return rules
}

// Built-in transformation rules

func (m *DefaultSchemaMapper) initializeBuiltInRules() {
	// Initialize Splunk transformation rules
	m.initializeSplunkRules()
	
	// Initialize QRadar transformation rules
	m.initializeQRadarRules()
	
	// Add more vendor-specific rules as needed
}

func (m *DefaultSchemaMapper) initializeSplunkRules() {
	splunkRules := make(map[entity.DataType]*TransformationRuleSet)
	
	// Splunk alerts transformation rules
	splunkRules[entity.DataTypeAlerts] = &TransformationRuleSet{
		Vendor:   entity.VendorSplunk,
		DataType: entity.DataTypeAlerts,
		Version:  "1.0",
		FieldMappings: map[string]*FieldMapping{
			"id": {
				SourceField:        "_key",
				TargetField:        "id",
				DataType:           entity.FieldDataTypeString,
				Required:           true,
				TransformationType: "direct_copy",
			},
			"timestamp": {
				SourceField:        "_time",
				TargetField:        "timestamp",
				DataType:           entity.FieldDataTypeDateTime,
				Required:           true,
				TransformationType: "type_conversion",
			},
			"severity": {
				SourceField:        "urgency",
				TargetField:        "severity",
				DataType:           entity.FieldDataTypeString,
				Required:           true,
				TransformationType: "normalization",
				TransformationConfig: map[string]interface{}{
					"to_lower": true,
				},
			},
			"title": {
				SourceField:        "title",
				TargetField:        "title",
				DataType:           entity.FieldDataTypeString,
				Required:           true,
				TransformationType: "direct_copy",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	m.transformationRules[entity.VendorSplunk] = splunkRules
}

func (m *DefaultSchemaMapper) initializeQRadarRules() {
	qradarRules := make(map[entity.DataType]*TransformationRuleSet)
	
	// QRadar incidents (offenses) transformation rules
	qradarRules[entity.DataTypeIncidents] = &TransformationRuleSet{
		Vendor:   entity.VendorIBMQRadar,
		DataType: entity.DataTypeIncidents,
		Version:  "1.0",
		FieldMappings: map[string]*FieldMapping{
			"id": {
				SourceField:        "id",
				TargetField:        "incident_id",
				DataType:           entity.FieldDataTypeString,
				Required:           true,
				TransformationType: "direct_copy",
			},
			"timestamp": {
				SourceField:        "start_time",
				TargetField:        "timestamp",
				DataType:           entity.FieldDataTypeDateTime,
				Required:           true,
				TransformationType: "type_conversion",
			},
			"priority": {
				SourceField:        "magnitude",
				TargetField:        "priority",
				DataType:           entity.FieldDataTypeString,
				Required:           true,
				TransformationType: "normalization",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	
	m.transformationRules[entity.VendorIBMQRadar] = qradarRules
}

func (m *DefaultSchemaMapper) getTransformationRules(vendor entity.SourceSystemVendor, dataType entity.DataType) *TransformationRuleSet {
	if vendorRules, exists := m.transformationRules[vendor]; exists {
		if rules, exists := vendorRules[dataType]; exists {
			return rules
		}
	}
	return nil
}

// Validation result helper methods

func (result *MappingValidationResult) addError(errorType, message, severity string) {
	result.Errors = append(result.Errors, MappingValidationError{
		ErrorType: errorType,
		Message:   message,
		Severity:  severity,
	})
}

func (result *MappingValidationResult) addWarning(warningType, message, recommendation string) {
	result.Warnings = append(result.Warnings, MappingValidationWarning{
		WarningType:    warningType,
		Message:        message,
		Recommendation: recommendation,
	})
}

// Default configuration

func getDefaultSchemaMapperConfig() *SchemaMapperConfig {
	return &SchemaMapperConfig{
		EnableCaching:           true,
		CacheTTL:               time.Hour,
		MaxCacheSize:           1000,
		AutoGenerateMappings:   true,
		StrictTypeValidation:   false,
		AllowNullableFields:    true,
		PreserveSourceFields:   true,
		DefaultFieldMapping:    make(map[string]string),
		IgnoredFields:          []string{"_raw", "_internal"},
		RequiredFields:         []string{"id", "timestamp"},
		EnableDataNormalization: true,
		DateTimeFormat:         time.RFC3339,
		TimeZone:               "UTC",
		DefaultStringLength:    1000,
		EncryptPIIFields:       true,
		PIIFieldPatterns:       []string{"email", "phone", "ssn", "address", "name"},
		SecurityClearance:      "unclassified",
		ComplianceFrameworks:   []string{"SOC2", "ISO27001"},
		DataClassification:     "internal",
		RetentionPeriod:        time.Hour * 24 * 90, // 90 days
	}
}

// Placeholder for SchemaMappingMetricsCollector
type SchemaMappingMetricsCollector struct{}

func NewSchemaMappingMetricsCollector() *SchemaMappingMetricsCollector {
	return &SchemaMappingMetricsCollector{}
}