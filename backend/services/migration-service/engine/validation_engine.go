package engine

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// DefaultValidationEngine is the production implementation of ValidationEngine
type DefaultValidationEngine struct {
	// Core dependencies
	schemaMapper         SchemaMapper

	// Validation registry
	validators           map[string]DataValidator
	validatorMutex       sync.RWMutex

	// Rule registry
	validationRules      map[string]*ValidationRuleSet
	rulesMutex           sync.RWMutex

	// Configuration
	config               *ValidationEngineConfig

	// Monitoring and metrics
	metricsCollector     *ValidationMetricsCollector
	auditLogger          *AuditLogger

	// Security and compliance
	securityValidator    *SecurityValidator
	complianceChecker    *ComplianceChecker
}

// ValidationEngineConfig contains configuration for the validation engine
type ValidationEngineConfig struct {
	// Quality thresholds
	DefaultQualityThreshold    float64       `json:"default_quality_threshold"`
	MinimumQualityThreshold    float64       `json:"minimum_quality_threshold"`
	ComplianceThreshold        float64       `json:"compliance_threshold"`

	// Validation behavior
	StrictValidation           bool          `json:"strict_validation"`
	ContinueOnValidationError  bool          `json:"continue_on_validation_error"`
	EnableDetailedReporting    bool          `json:"enable_detailed_reporting"`
	
	// Performance
	MaxConcurrentValidations   int32         `json:"max_concurrent_validations"`
	ValidationTimeout          time.Duration `json:"validation_timeout"`
	BatchSize                  int32         `json:"batch_size"`
	
	// Caching
	EnableRuleCaching          bool          `json:"enable_rule_caching"`
	CacheTTL                   time.Duration `json:"cache_ttl"`
	MaxCacheSize               int32         `json:"max_cache_size"`

	// Security
	SecurityClearance          string        `json:"security_clearance"`
	ValidateSecurityFields     bool          `json:"validate_security_fields"`
	
	// Compliance
	ComplianceFrameworks       []string      `json:"compliance_frameworks"`
	DataClassification         string        `json:"data_classification"`
	ValidateComplianceFields   bool          `json:"validate_compliance_fields"`

	// Reporting
	GenerateDetailedReports    bool          `json:"generate_detailed_reports"`
	IncludeRecommendations     bool          `json:"include_recommendations"`
	AuditValidations           bool          `json:"audit_validations"`
}

// ValidationRuleSet contains validation rules for specific contexts
type ValidationRuleSet struct {
	ID                      uuid.UUID                     `json:"id"`
	Name                    string                        `json:"name"`
	Description             string                        `json:"description"`
	Version                 string                        `json:"version"`
	
	// Context
	DataType                entity.DataType               `json:"data_type"`
	Vendor                  entity.SourceSystemVendor    `json:"vendor"`
	SecurityClearance       string                        `json:"security_clearance"`
	ComplianceFrameworks    []string                      `json:"compliance_frameworks"`
	
	// Rules
	FieldValidationRules    map[string][]*FieldValidationRule `json:"field_validation_rules"`
	RecordValidationRules   []*RecordValidationRule       `json:"record_validation_rules"`
	QualityRules            []*QualityRule                `json:"quality_rules"`
	ComplianceRules         []*ComplianceRule             `json:"compliance_rules"`
	SecurityRules           []*SecurityRule               `json:"security_rules"`
	
	// Configuration
	QualityThreshold        float64                       `json:"quality_threshold"`
	ComplianceThreshold     float64                       `json:"compliance_threshold"`
	
	// Metadata
	CreatedAt               time.Time                     `json:"created_at"`
	UpdatedAt               time.Time                     `json:"updated_at"`
	CreatedBy               uuid.UUID                     `json:"created_by"`
}

// RecordValidationRule defines validation for entire records
type RecordValidationRule struct {
	ID                      uuid.UUID                     `json:"id"`
	Name                    string                        `json:"name"`
	Description             string                        `json:"description"`
	RuleType                string                        `json:"rule_type"`
	Expression              string                        `json:"expression"`
	ErrorMessage            string                        `json:"error_message"`
	Severity                ValidationSeverity            `json:"severity"`
	Enabled                 bool                          `json:"enabled"`
	Priority                int32                         `json:"priority"`
}

// QualityRule defines data quality validation
type QualityRule struct {
	ID                      uuid.UUID                     `json:"id"`
	Name                    string                        `json:"name"`
	Description             string                        `json:"description"`
	QualityDimension        QualityDimension              `json:"quality_dimension"`
	Threshold               float64                       `json:"threshold"`
	Measurement             string                        `json:"measurement"`
	ErrorMessage            string                        `json:"error_message"`
	Severity                ValidationSeverity            `json:"severity"`
	Enabled                 bool                          `json:"enabled"`
}

// ComplianceRule defines compliance validation
type ComplianceRule struct {
	ID                      uuid.UUID                     `json:"id"`
	Name                    string                        `json:"name"`
	Description             string                        `json:"description"`
	Framework               string                        `json:"framework"`
	Requirement             string                        `json:"requirement"`
	ValidationExpression    string                        `json:"validation_expression"`
	ErrorMessage            string                        `json:"error_message"`
	Severity                ValidationSeverity            `json:"severity"`
	Enabled                 bool                          `json:"enabled"`
}

// SecurityRule defines security validation
type SecurityRule struct {
	ID                      uuid.UUID                     `json:"id"`
	Name                    string                        `json:"name"`
	Description             string                        `json:"description"`
	SecurityDomain          string                        `json:"security_domain"`
	MinimumClearance        string                        `json:"minimum_clearance"`
	ValidationExpression    string                        `json:"validation_expression"`
	ErrorMessage            string                        `json:"error_message"`
	Severity                ValidationSeverity            `json:"severity"`
	Enabled                 bool                          `json:"enabled"`
}

// DataValidator interface for custom validators
type DataValidator interface {
	GetName() string
	GetDescription() string
	GetVersion() string
	GetSupportedDataTypes() []entity.DataType
	Validate(ctx context.Context, data []map[string]interface{}, rules *ValidationRuleSet) (*ValidationResult, error)
	ValidateRecord(ctx context.Context, record map[string]interface{}, rules *ValidationRuleSet) (*RecordValidationResult, error)
}

// ValidationSeverity represents the severity of validation issues
type ValidationSeverity string

const (
	ValidationSeverityInfo    ValidationSeverity = "info"
	ValidationSeverityWarning ValidationSeverity = "warning"
	ValidationSeverityError   ValidationSeverity = "error"
	ValidationSeverityCritical ValidationSeverity = "critical"
)

// QualityDimension represents different dimensions of data quality
type QualityDimension string

const (
	QualityDimensionCompleteness  QualityDimension = "completeness"
	QualityDimensionAccuracy      QualityDimension = "accuracy"
	QualityDimensionConsistency   QualityDimension = "consistency"
	QualityDimensionValidity      QualityDimension = "validity"
	QualityDimensionUniqueness    QualityDimension = "uniqueness"
	QualityDimensionTimeliness    QualityDimension = "timeliness"
)

// RecordValidationResult represents validation result for a single record
type RecordValidationResult struct {
	RecordIndex             int32                         `json:"record_index"`
	IsValid                 bool                          `json:"is_valid"`
	QualityScore            float64                       `json:"quality_score"`
	ComplianceScore         float64                       `json:"compliance_score"`
	SecurityScore           float64                       `json:"security_score"`
	Errors                  []*ValidationError            `json:"errors"`
	Warnings                []*ValidationWarning          `json:"warnings"`
	QualityMetrics          *RecordQualityMetrics         `json:"quality_metrics"`
	ProcessingTime          time.Duration                 `json:"processing_time"`
}

// RecordQualityMetrics contains quality metrics for a single record
type RecordQualityMetrics struct {
	CompletedFields         int32                         `json:"completed_fields"`
	TotalFields             int32                         `json:"total_fields"`
	CompletenessScore       float64                       `json:"completeness_score"`
	AccuracyScore           float64                       `json:"accuracy_score"`
	ConsistencyScore        float64                       `json:"consistency_score"`
	ValidityScore           float64                       `json:"validity_score"`
	UniquenessScore         float64                       `json:"uniqueness_score"`
	TimelinessScore         float64                       `json:"timeliness_score"`
}

// NewDefaultValidationEngine creates a new default validation engine
func NewDefaultValidationEngine(
	schemaMapper SchemaMapper,
	config *ValidationEngineConfig,
) *DefaultValidationEngine {
	if config == nil {
		config = getDefaultValidationEngineConfig()
	}

	engine := &DefaultValidationEngine{
		schemaMapper:        schemaMapper,
		validators:          make(map[string]DataValidator),
		validationRules:     make(map[string]*ValidationRuleSet),
		config:              config,
		metricsCollector:    NewValidationMetricsCollector(),
		auditLogger:         NewAuditLogger(config.AuditValidations),
		securityValidator:   NewSecurityValidator(config.SecurityClearance),
		complianceChecker:   NewComplianceChecker(config.ComplianceFrameworks),
	}

	// Register built-in validators
	engine.registerBuiltInValidators()

	// Initialize built-in validation rules
	engine.initializeBuiltInRules()

	return engine
}

// ValidateData validates data using the provided schema mapping
func (e *DefaultValidationEngine) ValidateData(ctx context.Context, data []map[string]interface{}, mapping *SchemaMapping) (*ValidationResult, error) {
	if mapping == nil {
		return nil, fmt.Errorf("schema mapping cannot be nil")
	}

	if len(data) == 0 {
		return &ValidationResult{
			IsValid:           true,
			QualityScore:      100.0,
			ComplianceScore:   100.0,
			SecurityScore:     100.0,
			ProcessedRecords:  0,
			ValidRecords:      0,
			InvalidRecords:    0,
			Errors:            make([]ValidationError, 0),
			Warnings:          make([]ValidationWarning, 0),
			QualityMetrics:    &QualityMetrics{},
			RecordResults:     make([]*RecordValidationResult, 0),
		}, nil
	}

	// Get validation rules for this mapping
	rules, err := e.getValidationRules(ctx, mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to get validation rules: %w", err)
	}

	// Get appropriate validator
	validator, err := e.getValidator(mapping.DataType)
	if err != nil {
		return nil, fmt.Errorf("failed to get validator: %w", err)
	}

	// Perform validation
	result, err := validator.Validate(ctx, data, rules)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Enhance result with additional analysis
	e.enhanceValidationResult(ctx, result, mapping, rules)

	// Log validation completion
	e.auditLogger.LogJobEvent(ctx, uuid.Nil, "data_validation_completed", map[string]interface{}{
		"mapping_id":        mapping.ID,
		"data_type":         mapping.DataType,
		"processed_records": result.ProcessedRecords,
		"valid_records":     result.ValidRecords,
		"invalid_records":   result.InvalidRecords,
		"quality_score":     result.QualityScore,
		"compliance_score":  result.ComplianceScore,
		"security_score":    result.SecurityScore,
	})

	return result, nil
}

// CreateValidationRules creates validation rules for a specific context
func (e *DefaultValidationEngine) CreateValidationRules(ctx context.Context, request *CreateValidationRulesRequest) (*ValidationRuleSet, error) {
	if request == nil {
		return nil, fmt.Errorf("create validation rules request cannot be nil")
	}

	// Validate the request
	if err := e.validateCreateRulesRequest(request); err != nil {
		return nil, fmt.Errorf("invalid create rules request: %w", err)
	}

	// Create rule set
	ruleSet := &ValidationRuleSet{
		ID:                      uuid.New(),
		Name:                    request.Name,
		Description:             request.Description,
		Version:                 "1.0",
		DataType:                request.DataType,
		Vendor:                  request.Vendor,
		SecurityClearance:       request.SecurityClearance,
		ComplianceFrameworks:    request.ComplianceFrameworks,
		FieldValidationRules:    make(map[string][]*FieldValidationRule),
		RecordValidationRules:   make([]*RecordValidationRule, 0),
		QualityRules:            make([]*QualityRule, 0),
		ComplianceRules:         make([]*ComplianceRule, 0),
		SecurityRules:           make([]*SecurityRule, 0),
		QualityThreshold:        request.QualityThreshold,
		ComplianceThreshold:     request.ComplianceThreshold,
		CreatedAt:               time.Now(),
		UpdatedAt:               time.Now(),
		CreatedBy:               request.CreatedBy,
	}

	// Generate rules based on schema if requested
	if request.AutoGenerateRules && request.Schema != nil {
		if err := e.generateRulesFromSchema(ctx, ruleSet, request.Schema); err != nil {
			return nil, fmt.Errorf("failed to generate rules from schema: %w", err)
		}
	}

	// Add custom rules
	if len(request.CustomRules) > 0 {
		if err := e.addCustomRules(ctx, ruleSet, request.CustomRules); err != nil {
			return nil, fmt.Errorf("failed to add custom rules: %w", err)
		}
	}

	// Store rule set
	ruleSetKey := e.getRuleSetKey(ruleSet.DataType, ruleSet.Vendor, ruleSet.SecurityClearance)
	e.rulesMutex.Lock()
	e.validationRules[ruleSetKey] = ruleSet
	e.rulesMutex.Unlock()

	// Log rule set creation
	e.auditLogger.LogJobEvent(ctx, uuid.Nil, "validation_rules_created", map[string]interface{}{
		"rule_set_id":         ruleSet.ID,
		"name":                ruleSet.Name,
		"data_type":           ruleSet.DataType,
		"vendor":              ruleSet.Vendor,
		"field_rules_count":   len(ruleSet.FieldValidationRules),
		"record_rules_count":  len(ruleSet.RecordValidationRules),
		"quality_rules_count": len(ruleSet.QualityRules),
	})

	return ruleSet, nil
}

// UpdateValidationRules updates existing validation rules
func (e *DefaultValidationEngine) UpdateValidationRules(ctx context.Context, ruleSetID uuid.UUID, updates *UpdateValidationRulesRequest) (*ValidationRuleSet, error) {
	// Find existing rule set
	var existingRuleSet *ValidationRuleSet
	e.rulesMutex.RLock()
	for _, ruleSet := range e.validationRules {
		if ruleSet.ID == ruleSetID {
			existingRuleSet = ruleSet
			break
		}
	}
	e.rulesMutex.RUnlock()

	if existingRuleSet == nil {
		return nil, fmt.Errorf("validation rule set %s not found", ruleSetID)
	}

	// Apply updates
	if updates.Name != "" {
		existingRuleSet.Name = updates.Name
	}
	if updates.Description != "" {
		existingRuleSet.Description = updates.Description
	}
	if updates.QualityThreshold > 0 {
		existingRuleSet.QualityThreshold = updates.QualityThreshold
	}
	if updates.ComplianceThreshold > 0 {
		existingRuleSet.ComplianceThreshold = updates.ComplianceThreshold
	}

	existingRuleSet.UpdatedAt = time.Now()
	existingRuleSet.Version = incrementVersion(existingRuleSet.Version)

	// Log rule set update
	e.auditLogger.LogJobEvent(ctx, uuid.Nil, "validation_rules_updated", map[string]interface{}{
		"rule_set_id": ruleSetID,
		"version":     existingRuleSet.Version,
	})

	return existingRuleSet, nil
}

// RegisterValidator registers a custom data validator
func (e *DefaultValidationEngine) RegisterValidator(validator DataValidator) error {
	if validator == nil {
		return fmt.Errorf("validator cannot be nil")
	}

	name := validator.GetName()
	if name == "" {
		return fmt.Errorf("validator name cannot be empty")
	}

	e.validatorMutex.Lock()
	defer e.validatorMutex.Unlock()

	e.validators[name] = validator

	return nil
}

// GetValidationRules retrieves validation rules for a specific context
func (e *DefaultValidationEngine) GetValidationRules(ctx context.Context, dataType entity.DataType, vendor entity.SourceSystemVendor, securityClearance string) (*ValidationRuleSet, error) {
	ruleSetKey := e.getRuleSetKey(dataType, vendor, securityClearance)
	
	e.rulesMutex.RLock()
	ruleSet, exists := e.validationRules[ruleSetKey]
	e.rulesMutex.RUnlock()

	if !exists {
		// Try to find a generic rule set
		genericKey := e.getRuleSetKey(dataType, "", securityClearance)
		e.rulesMutex.RLock()
		ruleSet, exists = e.validationRules[genericKey]
		e.rulesMutex.RUnlock()
		
		if !exists {
			return nil, fmt.Errorf("no validation rules found for data type %s, vendor %s, clearance %s", dataType, vendor, securityClearance)
		}
	}

	return ruleSet, nil
}

// Private helper methods

// getValidationRules gets validation rules for a schema mapping
func (e *DefaultValidationEngine) getValidationRules(ctx context.Context, mapping *SchemaMapping) (*ValidationRuleSet, error) {
	return e.GetValidationRules(ctx, mapping.DataType, mapping.SourceSchema.Vendor, mapping.SecurityClearance)
}

// getValidator gets appropriate validator for data type
func (e *DefaultValidationEngine) getValidator(dataType entity.DataType) (DataValidator, error) {
	validatorName := fmt.Sprintf("%s_validator", dataType)
	
	e.validatorMutex.RLock()
	validator, exists := e.validators[validatorName]
	e.validatorMutex.RUnlock()

	if !exists {
		// Fall back to generic validator
		e.validatorMutex.RLock()
		validator, exists = e.validators["generic_validator"]
		e.validatorMutex.RUnlock()
		
		if !exists {
			return nil, fmt.Errorf("no validator found for data type %s", dataType)
		}
	}

	return validator, nil
}

// enhanceValidationResult enhances validation result with additional analysis
func (e *DefaultValidationEngine) enhanceValidationResult(ctx context.Context, result *ValidationResult, mapping *SchemaMapping, rules *ValidationRuleSet) {
	// Add compliance analysis
	e.analyzeCompliance(result, mapping, rules)
	
	// Add security analysis
	e.analyzeSecurity(result, mapping, rules)
	
	// Add quality recommendations
	if e.config.IncludeRecommendations {
		e.addQualityRecommendations(result, rules)
	}
}

// analyzeCompliance performs compliance analysis
func (e *DefaultValidationEngine) analyzeCompliance(result *ValidationResult, mapping *SchemaMapping, rules *ValidationRuleSet) {
	if !e.config.ValidateComplianceFields {
		return
	}

	complianceScore := 100.0
	
	// Check compliance with each framework
	for _, framework := range mapping.ComplianceFrameworks {
		for _, rule := range rules.ComplianceRules {
			if rule.Framework == framework && rule.Enabled {
				// Simplified compliance check
				if result.QualityScore < rule.Threshold {
					complianceScore -= 10.0
					result.Warnings = append(result.Warnings, ValidationWarning{
						WarningType:    "compliance",
						Message:        fmt.Sprintf("Compliance rule '%s' failed for framework %s", rule.Name, framework),
						Recommendation: "Improve data quality to meet compliance requirements",
					})
				}
			}
		}
	}

	if complianceScore < 0 {
		complianceScore = 0
	}
	
	result.ComplianceScore = complianceScore
}

// analyzeSecurity performs security analysis  
func (e *DefaultValidationEngine) analyzeSecurity(result *ValidationResult, mapping *SchemaMapping, rules *ValidationRuleSet) {
	if !e.config.ValidateSecurityFields {
		return
	}

	securityScore := 100.0
	
	// Check security rules
	for _, rule := range rules.SecurityRules {
		if rule.Enabled {
			// Simplified security check
			if mapping.SecurityClearance == "" || mapping.SecurityClearance == "unclassified" {
				if rule.MinimumClearance != "unclassified" {
					securityScore -= 15.0
					result.Warnings = append(result.Warnings, ValidationWarning{
						WarningType:    "security",
						Message:        fmt.Sprintf("Security rule '%s' requires minimum clearance %s", rule.Name, rule.MinimumClearance),
						Recommendation: "Ensure proper security clearance for data access",
					})
				}
			}
		}
	}

	if securityScore < 0 {
		securityScore = 0
	}
	
	result.SecurityScore = securityScore
}

// addQualityRecommendations adds quality improvement recommendations
func (e *DefaultValidationEngine) addQualityRecommendations(result *ValidationResult, rules *ValidationRuleSet) {
	if result.QualityScore < rules.QualityThreshold {
		result.Recommendations = append(result.Recommendations, ValidationRecommendation{
			Type:        "quality_improvement",
			Priority:    "high",
			Title:       "Improve Data Quality",
			Description: fmt.Sprintf("Data quality score %.2f%% is below threshold %.2f%%", result.QualityScore, rules.QualityThreshold),
			Actions: []string{
				"Review data validation rules",
				"Improve data cleansing processes",
				"Implement additional quality checks",
			},
		})
	}

	// Add specific recommendations based on quality metrics
	if result.QualityMetrics != nil {
		if result.QualityMetrics.CompletenessScore < 90.0 {
			result.Recommendations = append(result.Recommendations, ValidationRecommendation{
				Type:        "completeness",
				Priority:    "medium",
				Title:       "Improve Data Completeness",
				Description: fmt.Sprintf("Data completeness score %.2f%% indicates missing fields", result.QualityMetrics.CompletenessScore),
				Actions: []string{
					"Review required field mappings",
					"Implement default value handling",
					"Improve data extraction processes",
				},
			})
		}
	}
}

// generateRulesFromSchema generates validation rules from schema
func (e *DefaultValidationEngine) generateRulesFromSchema(ctx context.Context, ruleSet *ValidationRuleSet, schema *entity.DataSchema) error {
	// Generate field validation rules
	for _, field := range schema.Fields {
		fieldRules := make([]*FieldValidationRule, 0)

		// Required field rule
		if field.Required {
			fieldRules = append(fieldRules, &FieldValidationRule{
				RuleType:     "required",
				RuleValue:    true,
				ErrorMessage: fmt.Sprintf("Field %s is required", field.Name),
				Severity:     "error",
			})
		}

		// Data type validation rule
		fieldRules = append(fieldRules, &FieldValidationRule{
			RuleType:     "data_type",
			RuleValue:    field.DataType,
			ErrorMessage: fmt.Sprintf("Field %s must be of type %s", field.Name, field.DataType),
			Severity:     "error",
		})

		// String length validation for string fields
		if field.DataType == entity.FieldDataTypeString && field.MaxLength > 0 {
			fieldRules = append(fieldRules, &FieldValidationRule{
				RuleType:     "max_length",
				RuleValue:    field.MaxLength,
				ErrorMessage: fmt.Sprintf("Field %s cannot exceed %d characters", field.Name, field.MaxLength),
				Severity:     "warning",
			})
		}

		ruleSet.FieldValidationRules[field.Name] = fieldRules
	}

	// Generate quality rules
	ruleSet.QualityRules = append(ruleSet.QualityRules, &QualityRule{
		ID:               uuid.New(),
		Name:             "Completeness Check",
		Description:      "Validates data completeness",
		QualityDimension: QualityDimensionCompleteness,
		Threshold:        90.0,
		Measurement:      "percentage_of_complete_fields",
		ErrorMessage:     "Data completeness below acceptable threshold",
		Severity:         ValidationSeverityWarning,
		Enabled:          true,
	})

	ruleSet.QualityRules = append(ruleSet.QualityRules, &QualityRule{
		ID:               uuid.New(),
		Name:             "Validity Check",
		Description:      "Validates data validity",
		QualityDimension: QualityDimensionValidity,
		Threshold:        95.0,
		Measurement:      "percentage_of_valid_fields",
		ErrorMessage:     "Data validity below acceptable threshold",
		Severity:         ValidationSeverityError,
		Enabled:          true,
	})

	return nil
}

// addCustomRules adds custom validation rules
func (e *DefaultValidationEngine) addCustomRules(ctx context.Context, ruleSet *ValidationRuleSet, customRules map[string]interface{}) error {
	// Simplified custom rule addition
	if fieldRules, exists := customRules["field_rules"]; exists {
		if fieldRulesMap, ok := fieldRules.(map[string]interface{}); ok {
			for fieldName, rules := range fieldRulesMap {
				// Convert and add field rules (simplified)
				ruleSet.FieldValidationRules[fieldName] = []*FieldValidationRule{
					{
						RuleType:     "custom",
						RuleValue:    rules,
						ErrorMessage: fmt.Sprintf("Custom validation failed for field %s", fieldName),
						Severity:     "warning",
					},
				}
			}
		}
	}

	return nil
}

// Built-in validators and rules

func (e *DefaultValidationEngine) registerBuiltInValidators() {
	// Register generic validator
	e.RegisterValidator(&GenericDataValidator{})
	
	// Register data type specific validators
	e.RegisterValidator(&AlertsDataValidator{})
	e.RegisterValidator(&EventsDataValidator{})
	e.RegisterValidator(&IncidentsDataValidator{})
}

func (e *DefaultValidationEngine) initializeBuiltInRules() {
	// Initialize generic rules
	e.initializeGenericRules()
	
	// Initialize vendor-specific rules
	e.initializeSplunkRules()
	e.initializeQRadarRules()
}

func (e *DefaultValidationEngine) initializeGenericRules() {
	// Generic alert validation rules
	alertRules := &ValidationRuleSet{
		ID:                   uuid.New(),
		Name:                 "Generic Alert Validation Rules",
		Description:          "Standard validation rules for alert data",
		Version:              "1.0",
		DataType:             entity.DataTypeAlerts,
		SecurityClearance:    "unclassified",
		ComplianceFrameworks: []string{"SOC2", "ISO27001"},
		FieldValidationRules: map[string][]*FieldValidationRule{
			"id": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "Alert ID is required", Severity: "error"},
				{RuleType: "data_type", RuleValue: "string", ErrorMessage: "Alert ID must be string", Severity: "error"},
			},
			"timestamp": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "Timestamp is required", Severity: "error"},
				{RuleType: "data_type", RuleValue: "datetime", ErrorMessage: "Timestamp must be datetime", Severity: "error"},
			},
			"severity": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "Severity is required", Severity: "error"},
				{RuleType: "enum", RuleValue: []string{"low", "medium", "high", "critical"}, ErrorMessage: "Invalid severity level", Severity: "error"},
			},
		},
		QualityThreshold:    90.0,
		ComplianceThreshold: 95.0,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	ruleSetKey := e.getRuleSetKey(entity.DataTypeAlerts, "", "unclassified")
	e.validationRules[ruleSetKey] = alertRules
}

func (e *DefaultValidationEngine) initializeSplunkRules() {
	// Splunk-specific alert validation rules
	splunkAlertRules := &ValidationRuleSet{
		ID:                   uuid.New(),
		Name:                 "Splunk Alert Validation Rules",
		Description:          "Validation rules for Splunk alert data",
		Version:              "1.0",
		DataType:             entity.DataTypeAlerts,
		Vendor:               entity.VendorSplunk,
		SecurityClearance:    "unclassified",
		ComplianceFrameworks: []string{"SOC2", "ISO27001"},
		FieldValidationRules: map[string][]*FieldValidationRule{
			"_key": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "Splunk _key is required", Severity: "error"},
			},
			"_time": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "Splunk _time is required", Severity: "error"},
				{RuleType: "format", RuleValue: "epoch", ErrorMessage: "Splunk _time must be epoch format", Severity: "error"},
			},
		},
		QualityThreshold:    95.0,
		ComplianceThreshold: 98.0,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	ruleSetKey := e.getRuleSetKey(entity.DataTypeAlerts, entity.VendorSplunk, "unclassified")
	e.validationRules[ruleSetKey] = splunkAlertRules
}

func (e *DefaultValidationEngine) initializeQRadarRules() {
	// QRadar-specific incident validation rules
	qradarIncidentRules := &ValidationRuleSet{
		ID:                   uuid.New(),
		Name:                 "QRadar Incident Validation Rules",
		Description:          "Validation rules for QRadar incident data",
		Version:              "1.0",
		DataType:             entity.DataTypeIncidents,
		Vendor:               entity.VendorIBMQRadar,
		SecurityClearance:    "unclassified",
		ComplianceFrameworks: []string{"SOC2", "ISO27001"},
		FieldValidationRules: map[string][]*FieldValidationRule{
			"id": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "QRadar offense ID is required", Severity: "error"},
				{RuleType: "data_type", RuleValue: "integer", ErrorMessage: "QRadar offense ID must be integer", Severity: "error"},
			},
			"magnitude": {
				{RuleType: "required", RuleValue: true, ErrorMessage: "QRadar magnitude is required", Severity: "error"},
				{RuleType: "range", RuleValue: map[string]int{"min": 0, "max": 10}, ErrorMessage: "QRadar magnitude must be 0-10", Severity: "error"},
			},
		},
		QualityThreshold:    92.0,
		ComplianceThreshold: 96.0,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}

	ruleSetKey := e.getRuleSetKey(entity.DataTypeIncidents, entity.VendorIBMQRadar, "unclassified")
	e.validationRules[ruleSetKey] = qradarIncidentRules
}

// Utility methods

func (e *DefaultValidationEngine) getRuleSetKey(dataType entity.DataType, vendor entity.SourceSystemVendor, securityClearance string) string {
	return fmt.Sprintf("%s_%s_%s", dataType, vendor, securityClearance)
}

func (e *DefaultValidationEngine) validateCreateRulesRequest(request *CreateValidationRulesRequest) error {
	if request.Name == "" {
		return fmt.Errorf("rule set name is required")
	}
	if request.DataType == "" {
		return fmt.Errorf("data type is required")
	}
	if request.QualityThreshold < 0 || request.QualityThreshold > 100 {
		return fmt.Errorf("quality threshold must be between 0 and 100")
	}
	return nil
}

func incrementVersion(version string) string {
	// Simplified version increment
	if version == "" {
		return "1.0"
	}
	return version + ".1"
}

// Built-in validator implementations

// GenericDataValidator provides generic data validation
type GenericDataValidator struct{}

func (v *GenericDataValidator) GetName() string { return "generic_validator" }
func (v *GenericDataValidator) GetDescription() string { return "Generic data validator for all data types" }
func (v *GenericDataValidator) GetVersion() string { return "1.0" }
func (v *GenericDataValidator) GetSupportedDataTypes() []entity.DataType {
	return []entity.DataType{entity.DataTypeAlerts, entity.DataTypeEvents, entity.DataTypeIncidents}
}

func (v *GenericDataValidator) Validate(ctx context.Context, data []map[string]interface{}, rules *ValidationRuleSet) (*ValidationResult, error) {
	result := &ValidationResult{
		ProcessedRecords: int64(len(data)),
		ValidRecords:     0,
		InvalidRecords:   0,
		Errors:           make([]ValidationError, 0),
		Warnings:         make([]ValidationWarning, 0),
		QualityMetrics:   &QualityMetrics{},
		RecordResults:    make([]*RecordValidationResult, 0),
		Recommendations:  make([]ValidationRecommendation, 0),
	}

	// Validate each record
	for i, record := range data {
		recordResult, err := v.ValidateRecord(ctx, record, rules)
		if err != nil {
			result.InvalidRecords++
			result.Errors = append(result.Errors, ValidationError{
				ErrorType: "validation_error",
				Message:   fmt.Sprintf("Record %d validation failed: %v", i, err),
				Severity:  "error",
			})
		} else {
			if recordResult.IsValid {
				result.ValidRecords++
			} else {
				result.InvalidRecords++
			}
			
			// Accumulate errors and warnings
			for _, err := range recordResult.Errors {
				result.Errors = append(result.Errors, ValidationError{
					ErrorType: err.ErrorType,
					Message:   fmt.Sprintf("Record %d: %s", i, err.Message),
					Severity:  err.Severity,
				})
			}
			
			for _, warn := range recordResult.Warnings {
				result.Warnings = append(result.Warnings, ValidationWarning{
					WarningType:    warn.WarningType,
					Message:        fmt.Sprintf("Record %d: %s", i, warn.Message),
					Recommendation: warn.Recommendation,
				})
			}
		}
		
		result.RecordResults = append(result.RecordResults, recordResult)
	}

	// Calculate overall scores
	if result.ProcessedRecords > 0 {
		result.QualityScore = float64(result.ValidRecords) / float64(result.ProcessedRecords) * 100.0
		result.ComplianceScore = result.QualityScore // Simplified
		result.SecurityScore = result.QualityScore   // Simplified
	}

	result.IsValid = result.QualityScore >= rules.QualityThreshold

	// Calculate quality metrics
	v.calculateQualityMetrics(result, data, rules)

	return result, nil
}

func (v *GenericDataValidator) ValidateRecord(ctx context.Context, record map[string]interface{}, rules *ValidationRuleSet) (*RecordValidationResult, error) {
	startTime := time.Now()
	
	recordResult := &RecordValidationResult{
		IsValid:         true,
		QualityScore:    100.0,
		ComplianceScore: 100.0,
		SecurityScore:   100.0,
		Errors:          make([]*ValidationError, 0),
		Warnings:        make([]*ValidationWarning, 0),
		QualityMetrics:  &RecordQualityMetrics{},
	}

	// Validate each field
	totalFields := 0
	completedFields := 0
	validFields := 0

	for fieldName, fieldRules := range rules.FieldValidationRules {
		totalFields++
		value, exists := record[fieldName]
		
		if exists && value != nil {
			completedFields++
		}

		// Apply field validation rules
		for _, rule := range fieldRules {
			if err := v.validateFieldRule(fieldName, value, exists, rule); err != nil {
				recordResult.IsValid = false
				recordResult.Errors = append(recordResult.Errors, &ValidationError{
					ErrorType: rule.RuleType,
					Message:   err.Error(),
					Severity:  rule.Severity,
				})
			} else {
				validFields++
			}
		}
	}

	// Calculate quality metrics
	if totalFields > 0 {
		recordResult.QualityMetrics.TotalFields = int32(totalFields)
		recordResult.QualityMetrics.CompletedFields = int32(completedFields)
		recordResult.QualityMetrics.CompletenessScore = float64(completedFields) / float64(totalFields) * 100.0
		recordResult.QualityMetrics.ValidityScore = float64(validFields) / float64(totalFields) * 100.0
		
		// Set overall quality score as average of completeness and validity
		recordResult.QualityScore = (recordResult.QualityMetrics.CompletenessScore + recordResult.QualityMetrics.ValidityScore) / 2.0
	}

	recordResult.ProcessingTime = time.Since(startTime)

	return recordResult, nil
}

func (v *GenericDataValidator) validateFieldRule(fieldName string, value interface{}, exists bool, rule *FieldValidationRule) error {
	switch rule.RuleType {
	case "required":
		if !exists || value == nil {
			return fmt.Errorf("required field %s is missing", fieldName)
		}
	case "data_type":
		expectedType := rule.RuleValue.(string)
		if !v.validateDataType(value, expectedType) {
			return fmt.Errorf("field %s has invalid data type, expected %s", fieldName, expectedType)
		}
	case "max_length":
		if str, ok := value.(string); ok {
			maxLen := rule.RuleValue.(int32)
			if int32(len(str)) > maxLen {
				return fmt.Errorf("field %s exceeds maximum length %d", fieldName, maxLen)
			}
		}
	case "enum":
		validValues := rule.RuleValue.([]string)
		if str, ok := value.(string); ok {
			valid := false
			for _, validValue := range validValues {
				if str == validValue {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("field %s has invalid value, must be one of %v", fieldName, validValues)
			}
		}
	case "format":
		expectedFormat := rule.RuleValue.(string)
		if !v.validateFormat(value, expectedFormat) {
			return fmt.Errorf("field %s has invalid format, expected %s", fieldName, expectedFormat)
		}
	case "range":
		rangeMap := rule.RuleValue.(map[string]int)
		if num, ok := value.(int); ok {
			if min, exists := rangeMap["min"]; exists && num < min {
				return fmt.Errorf("field %s value %d is below minimum %d", fieldName, num, min)
			}
			if max, exists := rangeMap["max"]; exists && num > max {
				return fmt.Errorf("field %s value %d is above maximum %d", fieldName, num, max)
			}
		}
	}
	
	return nil
}

func (v *GenericDataValidator) validateDataType(value interface{}, expectedType string) bool {
	if value == nil {
		return true // Null values are handled by required rule
	}

	switch expectedType {
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		_, ok := value.(int)
		if !ok {
			_, ok = value.(int32)
		}
		if !ok {
			_, ok = value.(int64)
		}
		return ok
	case "float":
		_, ok := value.(float64)
		if !ok {
			_, ok = value.(float32)
		}
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "datetime":
		_, ok := value.(time.Time)
		if !ok {
			// Try to parse string as datetime
			if str, isStr := value.(string); isStr {
				_, err := time.Parse(time.RFC3339, str)
				return err == nil
			}
		}
		return ok
	default:
		return true // Unknown type, pass validation
	}
}

func (v *GenericDataValidator) validateFormat(value interface{}, expectedFormat string) bool {
	if str, ok := value.(string); ok {
		switch expectedFormat {
		case "email":
			emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
			return emailRegex.MatchString(str)
		case "ip":
			// Simplified IP validation
			return strings.Count(str, ".") == 3
		case "epoch":
			// Check if string represents epoch timestamp
			return regexp.MustCompile(`^\d+$`).MatchString(str)
		default:
			return true // Unknown format, pass validation
		}
	}
	return false
}

func (v *GenericDataValidator) calculateQualityMetrics(result *ValidationResult, data []map[string]interface{}, rules *ValidationRuleSet) {
	if len(result.RecordResults) == 0 {
		return
	}

	var totalCompleteness, totalValidity float64
	for _, recordResult := range result.RecordResults {
		if recordResult.QualityMetrics != nil {
			totalCompleteness += recordResult.QualityMetrics.CompletenessScore
			totalValidity += recordResult.QualityMetrics.ValidityScore
		}
	}

	recordCount := float64(len(result.RecordResults))
	result.QualityMetrics.CompletenessScore = totalCompleteness / recordCount
	result.QualityMetrics.ValidityScore = totalValidity / recordCount
	result.QualityMetrics.AccuracyScore = result.QualityScore // Simplified
	result.QualityMetrics.ConsistencyScore = result.QualityScore // Simplified
	result.QualityMetrics.TimelinessScore = 100.0 // Simplified
	result.QualityMetrics.UniquenessScore = 100.0 // Simplified
}

// AlertsDataValidator provides specific validation for alerts
type AlertsDataValidator struct {
	*GenericDataValidator
}

func (v *AlertsDataValidator) GetName() string { return "alerts_validator" }
func (v *AlertsDataValidator) GetDescription() string { return "Specialized validator for alert data" }
func (v *AlertsDataValidator) GetSupportedDataTypes() []entity.DataType {
	return []entity.DataType{entity.DataTypeAlerts}
}

// EventsDataValidator provides specific validation for events
type EventsDataValidator struct {
	*GenericDataValidator
}

func (v *EventsDataValidator) GetName() string { return "events_validator" }
func (v *EventsDataValidator) GetDescription() string { return "Specialized validator for event data" }
func (v *EventsDataValidator) GetSupportedDataTypes() []entity.DataType {
	return []entity.DataType{entity.DataTypeEvents}
}

// IncidentsDataValidator provides specific validation for incidents
type IncidentsDataValidator struct {
	*GenericDataValidator
}

func (v *IncidentsDataValidator) GetName() string { return "incidents_validator" }
func (v *IncidentsDataValidator) GetDescription() string { return "Specialized validator for incident data" }
func (v *IncidentsDataValidator) GetSupportedDataTypes() []entity.DataType {
	return []entity.DataType{entity.DataTypeIncidents}
}

// Default configuration

func getDefaultValidationEngineConfig() *ValidationEngineConfig {
	return &ValidationEngineConfig{
		DefaultQualityThreshold:    90.0,
		MinimumQualityThreshold:    75.0,
		ComplianceThreshold:        95.0,
		StrictValidation:           false,
		ContinueOnValidationError:  true,
		EnableDetailedReporting:    true,
		MaxConcurrentValidations:   10,
		ValidationTimeout:          time.Minute * 30,
		BatchSize:                  1000,
		EnableRuleCaching:          true,
		CacheTTL:                   time.Hour,
		MaxCacheSize:               1000,
		SecurityClearance:          "unclassified",
		ComplianceFrameworks:       []string{"SOC2", "ISO27001"},
		DataClassification:         "internal",
		ValidateSecurityFields:     true,
		ValidateComplianceFields:   true,
		GenerateDetailedReports:    true,
		IncludeRecommendations:     true,
		AuditValidations:           true,
	}
}

// Placeholder for ValidationMetricsCollector
type ValidationMetricsCollector struct{}

func NewValidationMetricsCollector() *ValidationMetricsCollector {
	return &ValidationMetricsCollector{}
}