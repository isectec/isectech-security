package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/isectech/platform/services/event-processor/domain/entity"
	"github.com/isectech/platform/services/event-processor/domain/service"
	"github.com/isectech/platform/shared/common"
	"github.com/isectech/platform/shared/types"
	"github.com/isectech/platform/pkg/logging"
	"github.com/isectech/platform/pkg/metrics"
)

// ValidationServiceImpl implements service.EventValidationService
type ValidationServiceImpl struct {
	logger  *logging.Logger
	metrics *metrics.Collector
	config  *ValidationConfig
	
	// Validation rules
	fieldValidators    map[string]FieldValidator
	businessRules      []BusinessRule
	complianceRules    []ComplianceRule
	schemaValidators   map[types.EventType]*SchemaValidator
}

// ValidationConfig represents validation service configuration
type ValidationConfig struct {
	// Schema validation
	EnableSchemaValidation    bool                     `json:"enable_schema_validation"`
	SchemaRegistry           map[string]string        `json:"schema_registry"`
	StrictMode               bool                     `json:"strict_mode"`
	
	// Field validation
	RequiredFields           []string                 `json:"required_fields"`
	OptionalFields           []string                 `json:"optional_fields"`
	FieldValidationRules     map[string][]string      `json:"field_validation_rules"`
	CustomValidators         map[string]string        `json:"custom_validators"`
	
	// Business rules
	EnableBusinessRules      bool                     `json:"enable_business_rules"`
	BusinessRuleConfigs      []BusinessRuleConfig     `json:"business_rule_configs"`
	
	// Compliance validation
	EnableComplianceValidation bool                   `json:"enable_compliance_validation"`
	ComplianceFrameworks      []string                `json:"compliance_frameworks"`
	DataClassificationRules   map[string][]string     `json:"data_classification_rules"`
	
	// Performance settings
	ValidationTimeout        time.Duration            `json:"validation_timeout"`
	CacheValidationResults   bool                     `json:"cache_validation_results"`
	CacheTTL                 time.Duration            `json:"cache_ttl"`
	
	// Error handling
	StopOnFirstError         bool                     `json:"stop_on_first_error"`
	AllowPartialValidation   bool                     `json:"allow_partial_validation"`
}

// FieldValidator represents a field validation function
type FieldValidator func(value interface{}) error

// BusinessRule represents a business validation rule
type BusinessRule interface {
	Validate(ctx context.Context, event *entity.Event) error
	GetName() string
	GetDescription() string
	IsEnabled() bool
}

// ComplianceRule represents a compliance validation rule
type ComplianceRule interface {
	Validate(ctx context.Context, event *entity.Event) error
	GetFramework() string
	GetRuleID() string
	GetDescription() string
	IsRequired() bool
}

// SchemaValidator represents a schema validation configuration
type SchemaValidator struct {
	EventType    types.EventType        `json:"event_type"`
	Schema       map[string]interface{} `json:"schema"`
	Required     []string               `json:"required"`
	Optional     []string               `json:"optional"`
	Constraints  map[string]interface{} `json:"constraints"`
}

// BusinessRuleConfig represents business rule configuration
type BusinessRuleConfig struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Enabled     bool                   `json:"enabled"`
	Parameters  map[string]interface{} `json:"parameters"`
	Description string                 `json:"description"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field       string      `json:"field"`
	Value       interface{} `json:"value"`
	Rule        string      `json:"rule"`
	Message     string      `json:"message"`
	Severity    string      `json:"severity"`
	Code        string      `json:"code"`
}

// ValidationResult represents the result of validation
type ValidationResult struct {
	IsValid     bool               `json:"is_valid"`
	Errors      []ValidationError  `json:"errors"`
	Warnings    []ValidationError  `json:"warnings"`
	ValidatedAt time.Time          `json:"validated_at"`
	Duration    time.Duration      `json:"duration"`
}

// NewValidationService creates a new validation service
func NewValidationService(
	logger *logging.Logger,
	metrics *metrics.Collector,
	config *ValidationConfig,
) service.EventValidationService {
	if config == nil {
		config = &ValidationConfig{
			EnableSchemaValidation:     true,
			StrictMode:                false,
			RequiredFields:            []string{"id", "tenant_id", "type", "source", "occurred_at"},
			EnableBusinessRules:       true,
			EnableComplianceValidation: true,
			ValidationTimeout:         10 * time.Second,
			CacheValidationResults:    true,
			CacheTTL:                 5 * time.Minute,
			StopOnFirstError:         false,
			AllowPartialValidation:   true,
		}
	}

	vs := &ValidationServiceImpl{
		logger:           logger,
		metrics:          metrics,
		config:           config,
		fieldValidators:  make(map[string]FieldValidator),
		businessRules:    make([]BusinessRule, 0),
		complianceRules:  make([]ComplianceRule, 0),
		schemaValidators: make(map[types.EventType]*SchemaValidator),
	}

	// Initialize validators
	vs.initializeFieldValidators()
	vs.initializeBusinessRules()
	vs.initializeComplianceRules()
	vs.initializeSchemaValidators()

	return vs
}

// ValidateSchema validates event against its schema
func (vs *ValidationServiceImpl) ValidateSchema(ctx context.Context, event *entity.Event) error {
	if !vs.config.EnableSchemaValidation {
		return nil
	}

	start := time.Now()
	defer func() {
		vs.metrics.RecordBusinessOperation("schema_validation", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Get schema validator for event type
	schemaValidator, exists := vs.schemaValidators[event.Type]
	if !exists {
		if vs.config.StrictMode {
			return common.NewAppError(common.ErrCodeValidationFailed, 
				fmt.Sprintf("no schema defined for event type: %s", event.Type))
		}
		return nil // Allow unknown event types in non-strict mode
	}

	var validationErrors []ValidationError

	// Validate required fields
	for _, field := range schemaValidator.Required {
		if err := vs.validateRequiredField(event, field); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    field,
				Rule:     "required",
				Message:  err.Error(),
				Severity: "error",
				Code:     "FIELD_REQUIRED",
			})
			
			if vs.config.StopOnFirstError {
				break
			}
		}
	}

	// Validate field formats and constraints
	if len(validationErrors) == 0 || !vs.config.StopOnFirstError {
		constraintErrors := vs.validateConstraints(event, schemaValidator.Constraints)
		validationErrors = append(validationErrors, constraintErrors...)
	}

	if len(validationErrors) > 0 {
		return vs.createValidationError("schema validation failed", validationErrors)
	}

	vs.logger.Debug("Schema validation passed",
		logging.String("event_id", event.ID.String()),
		logging.String("event_type", string(event.Type)),
	)

	return nil
}

// ValidateBusinessRules validates event against business rules
func (vs *ValidationServiceImpl) ValidateBusinessRules(ctx context.Context, event *entity.Event) error {
	if !vs.config.EnableBusinessRules {
		return nil
	}

	start := time.Now()
	defer func() {
		vs.metrics.RecordBusinessOperation("business_rules_validation", event.TenantID.String(), "completed", time.Since(start))
	}()

	var validationErrors []ValidationError

	for _, rule := range vs.businessRules {
		if !rule.IsEnabled() {
			continue
		}

		if err := rule.Validate(ctx, event); err != nil {
			validationErrors = append(validationErrors, ValidationError{
				Field:    "business_rule",
				Rule:     rule.GetName(),
				Message:  err.Error(),
				Severity: "error",
				Code:     "BUSINESS_RULE_VIOLATION",
			})

			if vs.config.StopOnFirstError {
				break
			}
		}
	}

	if len(validationErrors) > 0 {
		return vs.createValidationError("business rules validation failed", validationErrors)
	}

	vs.logger.Debug("Business rules validation passed",
		logging.String("event_id", event.ID.String()),
		logging.Int("rules_checked", len(vs.businessRules)),
	)

	return nil
}

// ValidateDataIntegrity validates event data integrity
func (vs *ValidationServiceImpl) ValidateDataIntegrity(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		vs.metrics.RecordBusinessOperation("data_integrity_validation", event.TenantID.String(), "completed", time.Since(start))
	}()

	var validationErrors []ValidationError

	// Validate timestamps
	if err := vs.validateTimestamps(event); err != nil {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "timestamps",
			Rule:     "integrity",
			Message:  err.Error(),
			Severity: "error",
			Code:     "TIMESTAMP_INTEGRITY",
		})
	}

	// Validate IDs
	if err := vs.validateIDs(event); err != nil {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "ids",
			Rule:     "integrity",
			Message:  err.Error(),
			Severity: "error",
			Code:     "ID_INTEGRITY",
		})
	}

	// Validate IP addresses
	if err := vs.validateIPAddresses(event); err != nil {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "ip_addresses",
			Rule:     "integrity",
			Message:  err.Error(),
			Severity: "warning",
			Code:     "IP_INTEGRITY",
		})
	}

	// Validate JSON payloads
	if err := vs.validateJSONPayloads(event); err != nil {
		validationErrors = append(validationErrors, ValidationError{
			Field:    "payload",
			Rule:     "integrity",
			Message:  err.Error(),
			Severity: "error",
			Code:     "JSON_INTEGRITY",
		})
	}

	if len(validationErrors) > 0 {
		// Check if we have any errors (as opposed to just warnings)
		hasErrors := false
		for _, err := range validationErrors {
			if err.Severity == "error" {
				hasErrors = true
				break
			}
		}

		if hasErrors {
			return vs.createValidationError("data integrity validation failed", validationErrors)
		}
	}

	vs.logger.Debug("Data integrity validation passed",
		logging.String("event_id", event.ID.String()),
	)

	return nil
}

// ValidateCompliance validates event against compliance rules
func (vs *ValidationServiceImpl) ValidateCompliance(ctx context.Context, event *entity.Event) error {
	if !vs.config.EnableComplianceValidation {
		return nil
	}

	start := time.Time{}
	defer func() {
		vs.metrics.RecordBusinessOperation("compliance_validation", event.TenantID.String(), "completed", time.Since(start))
	}()

	var validationErrors []ValidationError

	for _, rule := range vs.complianceRules {
		if err := rule.Validate(ctx, event); err != nil {
			severity := "warning"
			if rule.IsRequired() {
				severity = "error"
			}

			validationErrors = append(validationErrors, ValidationError{
				Field:    "compliance",
				Rule:     fmt.Sprintf("%s_%s", rule.GetFramework(), rule.GetRuleID()),
				Message:  err.Error(),
				Severity: severity,
				Code:     "COMPLIANCE_VIOLATION",
			})

			if vs.config.StopOnFirstError && severity == "error" {
				break
			}
		}
	}

	// Check if we have any compliance errors
	hasErrors := false
	for _, err := range validationErrors {
		if err.Severity == "error" {
			hasErrors = true
			break
		}
	}

	if hasErrors {
		return vs.createValidationError("compliance validation failed", validationErrors)
	}

	vs.logger.Debug("Compliance validation passed",
		logging.String("event_id", event.ID.String()),
		logging.Int("rules_checked", len(vs.complianceRules)),
	)

	return nil
}

// Helper methods

// initializeFieldValidators sets up field validators
func (vs *ValidationServiceImpl) initializeFieldValidators() {
	vs.fieldValidators["email"] = vs.validateEmail
	vs.fieldValidators["ip_address"] = vs.validateIPAddress
	vs.fieldValidators["url"] = vs.validateURL
	vs.fieldValidators["uuid"] = vs.validateUUID
	vs.fieldValidators["severity"] = vs.validateSeverity
	vs.fieldValidators["event_type"] = vs.validateEventType
	vs.fieldValidators["timestamp"] = vs.validateTimestamp
	vs.fieldValidators["json"] = vs.validateJSON
	vs.fieldValidators["non_empty"] = vs.validateNonEmpty
	vs.fieldValidators["max_length"] = vs.validateMaxLength
}

// initializeBusinessRules sets up business rules
func (vs *ValidationServiceImpl) initializeBusinessRules() {
	for _, ruleConfig := range vs.config.BusinessRuleConfigs {
		if !ruleConfig.Enabled {
			continue
		}

		switch ruleConfig.Type {
		case "timeline_consistency":
			vs.businessRules = append(vs.businessRules, &TimelineConsistencyRule{
				name:        ruleConfig.Name,
				description: ruleConfig.Description,
				enabled:     ruleConfig.Enabled,
				parameters:  ruleConfig.Parameters,
			})
		case "severity_escalation":
			vs.businessRules = append(vs.businessRules, &SeverityEscalationRule{
				name:        ruleConfig.Name,
				description: ruleConfig.Description,
				enabled:     ruleConfig.Enabled,
				parameters:  ruleConfig.Parameters,
			})
		case "correlation_consistency":
			vs.businessRules = append(vs.businessRules, &CorrelationConsistencyRule{
				name:        ruleConfig.Name,
				description: ruleConfig.Description,
				enabled:     ruleConfig.Enabled,
				parameters:  ruleConfig.Parameters,
			})
		}
	}
}

// initializeComplianceRules sets up compliance rules
func (vs *ValidationServiceImpl) initializeComplianceRules() {
	for _, framework := range vs.config.ComplianceFrameworks {
		switch framework {
		case "gdpr":
			vs.complianceRules = append(vs.complianceRules, &GDPRComplianceRule{
				framework: "gdpr",
				ruleID:    "data_minimization",
				description: "Ensure data minimization principles",
				required:  true,
			})
		case "hipaa":
			vs.complianceRules = append(vs.complianceRules, &HIPAAComplianceRule{
				framework: "hipaa",
				ruleID:    "phi_protection",
				description: "Protect PHI data",
				required:  true,
			})
		case "pci_dss":
			vs.complianceRules = append(vs.complianceRules, &PCIDSSComplianceRule{
				framework: "pci_dss",
				ruleID:    "cardholder_data",
				description: "Protect cardholder data",
				required:  true,
			})
		}
	}
}

// initializeSchemaValidators sets up schema validators
func (vs *ValidationServiceImpl) initializeSchemaValidators() {
	// Authentication events schema
	vs.schemaValidators[types.EventTypeAuthentication] = &SchemaValidator{
		EventType: types.EventTypeAuthentication,
		Required:  []string{"id", "tenant_id", "type", "source", "occurred_at", "user_id"},
		Optional:  []string{"ip_address", "user_agent", "session_id"},
		Constraints: map[string]interface{}{
			"user_id": "uuid",
			"ip_address": "ip_address",
		},
	}

	// Threat detection events schema
	vs.schemaValidators[types.EventTypeThreatDetection] = &SchemaValidator{
		EventType: types.EventTypeThreatDetection,
		Required:  []string{"id", "tenant_id", "type", "source", "occurred_at", "severity"},
		Optional:  []string{"source_ip", "destination_ip", "asset_id"},
		Constraints: map[string]interface{}{
			"severity": "severity",
			"source_ip": "ip_address",
			"destination_ip": "ip_address",
		},
	}

	// Network access events schema
	vs.schemaValidators[types.EventTypeNetworkAccess] = &SchemaValidator{
		EventType: types.EventTypeNetworkAccess,
		Required:  []string{"id", "tenant_id", "type", "source", "occurred_at", "source_ip"},
		Optional:  []string{"destination_ip", "protocol", "source_port", "destination_port"},
		Constraints: map[string]interface{}{
			"source_ip": "ip_address",
			"destination_ip": "ip_address",
			"protocol": "non_empty",
		},
	}
}

// Field validation methods

func (vs *ValidationServiceImpl) validateEmail(value interface{}) error {
	email, ok := value.(string)
	if !ok {
		return fmt.Errorf("email must be a string")
	}
	
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateIPAddress(value interface{}) error {
	ip, ok := value.(string)
	if !ok {
		return fmt.Errorf("IP address must be a string")
	}
	
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateURL(value interface{}) error {
	url, ok := value.(string)
	if !ok {
		return fmt.Errorf("URL must be a string")
	}
	
	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	if !urlRegex.MatchString(url) {
		return fmt.Errorf("invalid URL format")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateUUID(value interface{}) error {
	uuid, ok := value.(string)
	if !ok {
		return fmt.Errorf("UUID must be a string")
	}
	
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	if !uuidRegex.MatchString(strings.ToLower(uuid)) {
		return fmt.Errorf("invalid UUID format")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateSeverity(value interface{}) error {
	severity, ok := value.(string)
	if !ok {
		return fmt.Errorf("severity must be a string")
	}
	
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	for _, valid := range validSeverities {
		if severity == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid severity: %s", severity)
}

func (vs *ValidationServiceImpl) validateEventType(value interface{}) error {
	eventType, ok := value.(string)
	if !ok {
		return fmt.Errorf("event type must be a string")
	}
	
	validTypes := []string{
		"authentication", "authorization", "network_access", "threat_detection",
		"vulnerability", "compliance", "asset_discovery", "system_health",
		"user_activity", "data_access",
	}
	
	for _, valid := range validTypes {
		if eventType == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid event type: %s", eventType)
}

func (vs *ValidationServiceImpl) validateTimestamp(value interface{}) error {
	timestamp, ok := value.(time.Time)
	if !ok {
		// Try to parse as string
		if timestampStr, ok := value.(string); ok {
			if _, err := time.Parse(time.RFC3339, timestampStr); err != nil {
				return fmt.Errorf("invalid timestamp format")
			}
			return nil
		}
		return fmt.Errorf("timestamp must be a time.Time or RFC3339 string")
	}
	
	if timestamp.IsZero() {
		return fmt.Errorf("timestamp cannot be zero")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateJSON(value interface{}) error {
	switch v := value.(type) {
	case string:
		var js json.RawMessage
		return json.Unmarshal([]byte(v), &js)
	case map[string]interface{}, []interface{}:
		// Already valid JSON structures
		return nil
	default:
		// Try to marshal and unmarshal
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("value is not JSON serializable")
		}
		var js json.RawMessage
		return json.Unmarshal(data, &js)
	}
}

func (vs *ValidationServiceImpl) validateNonEmpty(value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("value must be a string")
	}
	
	if strings.TrimSpace(str) == "" {
		return fmt.Errorf("value cannot be empty")
	}
	return nil
}

func (vs *ValidationServiceImpl) validateMaxLength(value interface{}) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("value must be a string")
	}
	
	maxLength := 255 // Default max length
	if len(str) > maxLength {
		return fmt.Errorf("value exceeds maximum length of %d", maxLength)
	}
	return nil
}

// Validation helper methods

func (vs *ValidationServiceImpl) validateRequiredField(event *entity.Event, field string) error {
	switch field {
	case "id":
		if event.ID == (types.EventID{}) {
			return fmt.Errorf("event ID is required")
		}
	case "tenant_id":
		if event.TenantID == (types.TenantID{}) {
			return fmt.Errorf("tenant ID is required")
		}
	case "type":
		if event.Type == "" {
			return fmt.Errorf("event type is required")
		}
	case "source":
		if event.Source == "" {
			return fmt.Errorf("event source is required")
		}
	case "occurred_at":
		if event.OccurredAt.IsZero() {
			return fmt.Errorf("occurred at timestamp is required")
		}
	case "user_id":
		if event.UserID == nil {
			return fmt.Errorf("user ID is required")
		}
	case "severity":
		if event.Severity == "" {
			return fmt.Errorf("severity is required")
		}
	case "source_ip":
		if event.SourceIP == "" {
			return fmt.Errorf("source IP is required")
		}
	}
	return nil
}

func (vs *ValidationServiceImpl) validateConstraints(event *entity.Event, constraints map[string]interface{}) []ValidationError {
	var errors []ValidationError

	for field, constraint := range constraints {
		var value interface{}
		
		// Extract field value from event
		switch field {
		case "user_id":
			if event.UserID != nil {
				value = event.UserID.String()
			}
		case "ip_address", "source_ip":
			value = event.SourceIP
		case "destination_ip":
			value = event.DestinationIP
		case "severity":
			value = string(event.Severity)
		case "protocol":
			value = event.Protocol
		}

		if value == nil {
			continue // Skip validation for nil values
		}

		// Apply constraint validation
		constraintStr, ok := constraint.(string)
		if !ok {
			continue
		}

		if validator, exists := vs.fieldValidators[constraintStr]; exists {
			if err := validator(value); err != nil {
				errors = append(errors, ValidationError{
					Field:    field,
					Value:    value,
					Rule:     constraintStr,
					Message:  err.Error(),
					Severity: "error",
					Code:     "CONSTRAINT_VIOLATION",
				})
			}
		}
	}

	return errors
}

func (vs *ValidationServiceImpl) validateTimestamps(event *entity.Event) error {
	now := time.Now()

	// Check if timestamps are in reasonable range
	if event.OccurredAt.After(now.Add(1 * time.Hour)) {
		return fmt.Errorf("occurred_at timestamp is too far in the future")
	}

	if event.ReceivedAt.Before(event.OccurredAt.Add(-1 * time.Hour)) {
		return fmt.Errorf("received_at timestamp is inconsistent with occurred_at")
	}

	if event.ProcessedAt != nil && event.ProcessedAt.Before(event.ReceivedAt) {
		return fmt.Errorf("processed_at timestamp cannot be before received_at")
	}

	return nil
}

func (vs *ValidationServiceImpl) validateIDs(event *entity.Event) error {
	// Validate event ID format
	if event.ID == (types.EventID{}) {
		return fmt.Errorf("event ID cannot be empty")
	}

	// Validate tenant ID format
	if event.TenantID == (types.TenantID{}) {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Validate correlation ID if present
	if event.CorrelationID == (types.CorrelationID{}) {
		return fmt.Errorf("correlation ID cannot be empty")
	}

	return nil
}

func (vs *ValidationServiceImpl) validateIPAddresses(event *entity.Event) error {
	if event.SourceIP != "" {
		if net.ParseIP(event.SourceIP) == nil {
			return fmt.Errorf("invalid source IP address: %s", event.SourceIP)
		}
	}

	if event.DestinationIP != "" {
		if net.ParseIP(event.DestinationIP) == nil {
			return fmt.Errorf("invalid destination IP address: %s", event.DestinationIP)
		}
	}

	return nil
}

func (vs *ValidationServiceImpl) validateJSONPayloads(event *entity.Event) error {
	// Validate payload JSON
	if event.Payload != nil {
		if _, err := json.Marshal(event.Payload); err != nil {
			return fmt.Errorf("invalid payload JSON: %w", err)
		}
	}

	// Validate metadata JSON
	if event.Metadata != nil {
		if _, err := json.Marshal(event.Metadata); err != nil {
			return fmt.Errorf("invalid metadata JSON: %w", err)
		}
	}

	return nil
}

func (vs *ValidationServiceImpl) createValidationError(message string, validationErrors []ValidationError) error {
	appErr := common.NewAppError(common.ErrCodeValidationFailed, message)
	appErr.WithContext("validation_errors", validationErrors)
	return appErr
}

// Business Rule implementations

// TimelineConsistencyRule validates event timeline consistency
type TimelineConsistencyRule struct {
	name        string
	description string
	enabled     bool
	parameters  map[string]interface{}
}

func (r *TimelineConsistencyRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check if event timestamps are logically consistent
	if event.ReceivedAt.Before(event.OccurredAt.Add(-1 * time.Minute)) {
		return fmt.Errorf("event received before it occurred (allowing 1-minute clock skew)")
	}
	return nil
}

func (r *TimelineConsistencyRule) GetName() string { return r.name }
func (r *TimelineConsistencyRule) GetDescription() string { return r.description }
func (r *TimelineConsistencyRule) IsEnabled() bool { return r.enabled }

// SeverityEscalationRule validates severity escalation logic
type SeverityEscalationRule struct {
	name        string
	description string
	enabled     bool
	parameters  map[string]interface{}
}

func (r *SeverityEscalationRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check if severity is appropriate for the event type
	if event.Type == types.EventTypeSystemHealth && event.Severity == types.SeverityCritical {
		// System health events should rarely be critical
		return fmt.Errorf("system health events should not typically be critical severity")
	}
	return nil
}

func (r *SeverityEscalationRule) GetName() string { return r.name }
func (r *SeverityEscalationRule) GetDescription() string { return r.description }
func (r *SeverityEscalationRule) IsEnabled() bool { return r.enabled }

// CorrelationConsistencyRule validates correlation consistency
type CorrelationConsistencyRule struct {
	name        string
	description string
	enabled     bool
	parameters  map[string]interface{}
}

func (r *CorrelationConsistencyRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check correlation ID consistency
	if event.ParentEventID != nil && event.CorrelationID == (types.CorrelationID{}) {
		return fmt.Errorf("events with parent events must have correlation IDs")
	}
	return nil
}

func (r *CorrelationConsistencyRule) GetName() string { return r.name }
func (r *CorrelationConsistencyRule) GetDescription() string { return r.description }
func (r *CorrelationConsistencyRule) IsEnabled() bool { return r.enabled }

// Compliance Rule implementations

// GDPRComplianceRule validates GDPR compliance
type GDPRComplianceRule struct {
	framework   string
	ruleID      string
	description string
	required    bool
}

func (r *GDPRComplianceRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check for PII data in event payload
	if event.Payload != nil {
		// Simplified PII detection - in practice would be more sophisticated
		for key := range event.Payload {
			key = strings.ToLower(key)
			if strings.Contains(key, "email") || strings.Contains(key, "phone") || 
			   strings.Contains(key, "ssn") || strings.Contains(key, "credit") {
				event.AddComplianceFlag("gdpr_pii_detected")
			}
		}
	}
	return nil
}

func (r *GDPRComplianceRule) GetFramework() string { return r.framework }
func (r *GDPRComplianceRule) GetRuleID() string { return r.ruleID }
func (r *GDPRComplianceRule) GetDescription() string { return r.description }
func (r *GDPRComplianceRule) IsRequired() bool { return r.required }

// HIPAAComplianceRule validates HIPAA compliance
type HIPAAComplianceRule struct {
	framework   string
	ruleID      string
	description string
	required    bool
}

func (r *HIPAAComplianceRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check for PHI data
	if event.Payload != nil {
		for key := range event.Payload {
			key = strings.ToLower(key)
			if strings.Contains(key, "medical") || strings.Contains(key, "health") || 
			   strings.Contains(key, "patient") || strings.Contains(key, "diagnosis") {
				event.AddComplianceFlag("hipaa_phi_detected")
			}
		}
	}
	return nil
}

func (r *HIPAAComplianceRule) GetFramework() string { return r.framework }
func (r *HIPAAComplianceRule) GetRuleID() string { return r.ruleID }
func (r *HIPAAComplianceRule) GetDescription() string { return r.description }
func (r *HIPAAComplianceRule) IsRequired() bool { return r.required }

// PCIDSSComplianceRule validates PCI DSS compliance
type PCIDSSComplianceRule struct {
	framework   string
	ruleID      string
	description string
	required    bool
}

func (r *PCIDSSComplianceRule) Validate(ctx context.Context, event *entity.Event) error {
	// Check for cardholder data
	if event.Payload != nil {
		for key := range event.Payload {
			key = strings.ToLower(key)
			if strings.Contains(key, "card") || strings.Contains(key, "payment") || 
			   strings.Contains(key, "cvv") || strings.Contains(key, "expiry") {
				event.AddComplianceFlag("pci_dss_cardholder_data_detected")
			}
		}
	}
	return nil
}

func (r *PCIDSSComplianceRule) GetFramework() string { return r.framework }
func (r *PCIDSSComplianceRule) GetRuleID() string { return r.ruleID }
func (r *PCIDSSComplianceRule) GetDescription() string { return r.description }
func (r *PCIDSSComplianceRule) IsRequired() bool { return r.required }