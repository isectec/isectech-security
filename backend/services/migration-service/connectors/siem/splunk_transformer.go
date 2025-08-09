package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/isectech/migration-service/connectors"
	"github.com/isectech/migration-service/domain/entity"
)

// NewSplunkTransformer creates a new Splunk data transformer
func NewSplunkTransformer() *SplunkTransformer {
	transformer := &SplunkTransformer{
		fieldMappings: make(map[entity.DataType]map[string]string),
	}

	// Initialize field mappings for different data types
	transformer.initializeFieldMappings()

	return transformer
}

// TransformRecord transforms a single record from Splunk format to iSECTECH format
func (s *SplunkTransformer) TransformRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*connectors.TransformedRecord, error) {
	if record == nil {
		return nil, fmt.Errorf("input record is nil")
	}

	// Create transformed record
	transformedData := make(map[string]interface{})
	transformationApplied := make([]string, 0)

	// Get field mappings for the data type
	fieldMappings := s.GetFieldMappings(dataType)

	// Apply field mappings
	for splunkField, isectechField := range fieldMappings {
		if value, exists := record[splunkField]; exists {
			transformedValue, transformation := s.transformFieldValue(splunkField, value, dataType)
			transformedData[isectechField] = transformedValue
			if transformation != "" {
				transformationApplied = append(transformationApplied, transformation)
			}
		}
	}

	// Apply data-type specific transformations
	if err := s.applyDataTypeTransformations(record, transformedData, dataType, &transformationApplied); err != nil {
		return nil, fmt.Errorf("failed to apply data type transformations: %w", err)
	}

	// Add metadata
	metadata := s.generateMetadata(record, dataType)

	// Validate the transformed record
	validationResult, err := s.ValidateRecord(ctx, transformedData, dataType)
	if err != nil {
		// Log validation error but don't fail the transformation
		validationResult = &connectors.ValidationResult{
			IsValid: false,
			Errors: []connectors.ValidationError{
				{
					ErrorType: "validation_failed",
					Message:   err.Error(),
					Severity:  "warning",
				},
			},
			Score: 0.0,
		}
	}

	return &connectors.TransformedRecord{
		OriginalData:          record,
		TransformedData:       transformedData,
		DataType:              dataType,
		TransformationApplied: transformationApplied,
		ValidationResult:      validationResult,
		Metadata:              metadata,
	}, nil
}

// TransformBatch transforms a batch of records
func (s *SplunkTransformer) TransformBatch(ctx context.Context, batch []map[string]interface{}, dataType entity.DataType) ([]*connectors.TransformedRecord, error) {
	if len(batch) == 0 {
		return make([]*connectors.TransformedRecord, 0), nil
	}

	transformedRecords := make([]*connectors.TransformedRecord, 0, len(batch))

	for i, record := range batch {
		transformedRecord, err := s.TransformRecord(ctx, record, dataType)
		if err != nil {
			// Log error but continue with next record
			continue
		}

		// Add batch metadata
		if transformedRecord.Metadata == nil {
			transformedRecord.Metadata = make(map[string]interface{})
		}
		transformedRecord.Metadata["batch_index"] = i
		transformedRecord.Metadata["batch_size"] = len(batch)

		transformedRecords = append(transformedRecords, transformedRecord)
	}

	return transformedRecords, nil
}

// GetFieldMappings returns field mappings for a data type
func (s *SplunkTransformer) GetFieldMappings(dataType entity.DataType) map[string]string {
	if mappings, exists := s.fieldMappings[dataType]; exists {
		return mappings
	}
	return s.fieldMappings[entity.DataTypeLogs] // Default to logs mapping
}

// ValidateRecord validates a record against the schema
func (s *SplunkTransformer) ValidateRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*connectors.ValidationResult, error) {
	result := &connectors.ValidationResult{
		IsValid:      true,
		Errors:       make([]connectors.ValidationError, 0),
		Warnings:     make([]connectors.ValidationWarning, 0),
		Score:        100.0,
		FieldResults: make(map[string]connectors.FieldValidation),
	}

	// Get required fields for the data type
	requiredFields := s.getRequiredFields(dataType)

	// Validate required fields
	for _, field := range requiredFields {
		fieldValidation := connectors.FieldValidation{
			IsValid:  true,
			Score:    100.0,
			Errors:   make([]connectors.ValidationError, 0),
			Warnings: make([]connectors.ValidationWarning, 0),
		}

		value, exists := record[field]
		if !exists {
			error := connectors.ValidationError{
				Field:     field,
				ErrorType: "required_field_missing",
				Message:   fmt.Sprintf("Required field '%s' is missing", field),
				Severity:  "error",
			}
			result.Errors = append(result.Errors, error)
			fieldValidation.Errors = append(fieldValidation.Errors, error)
			fieldValidation.IsValid = false
			fieldValidation.Score = 0.0
			result.IsValid = false
		} else if s.isEmptyValue(value) {
			warning := connectors.ValidationWarning{
				Field:       field,
				WarningType: "empty_required_field",
				Message:     fmt.Sprintf("Required field '%s' is empty", field),
				Recommendation: "Consider providing a default value or investigating data source",
			}
			result.Warnings = append(result.Warnings, warning)
			fieldValidation.Warnings = append(fieldValidation.Warnings, warning)
			fieldValidation.Score = 50.0
		}

		result.FieldResults[field] = fieldValidation
	}

	// Validate field formats
	for field, value := range record {
		if fieldValidation, exists := result.FieldResults[field]; exists {
			// Already validated as required field
			if !fieldValidation.IsValid {
				continue
			}
		}

		if err := s.validateFieldFormat(field, value, dataType); err != nil {
			error := connectors.ValidationError{
				Field:     field,
				ErrorType: "invalid_format",
				Message:   err.Error(),
				Value:     value,
				Severity:  "warning",
			}
			result.Warnings = append(result.Warnings, connectors.ValidationWarning{
				Field:       field,
				WarningType: "format_validation",
				Message:     err.Error(),
				Value:       value,
			})
		}
	}

	// Calculate overall score
	totalFields := len(result.FieldResults)
	if totalFields > 0 {
		totalScore := 0.0
		for _, fieldResult := range result.FieldResults {
			totalScore += fieldResult.Score
		}
		result.Score = totalScore / float64(totalFields)
	}

	// Adjust score based on errors and warnings
	if len(result.Errors) > 0 {
		result.Score = result.Score * 0.5 // Reduce score by 50% for errors
	}
	if len(result.Warnings) > 0 {
		result.Score = result.Score * 0.9 // Reduce score by 10% for warnings
	}

	return result, nil
}

// Helper methods

// initializeFieldMappings initializes field mappings for different data types
func (s *SplunkTransformer) initializeFieldMappings() {
	// Common fields mapping
	commonFields := map[string]string{
		"_time":      "timestamp",
		"source":     "source",
		"sourcetype": "source_type", 
		"host":       "host",
		"index":      "index",
		"_raw":       "raw_message",
	}

	// Alerts mapping
	s.fieldMappings[entity.DataTypeAlerts] = map[string]string{
		"_time":        "timestamp",
		"search_name":  "alert_name",
		"severity":     "severity",
		"trigger_time": "triggered_at",
		"owner":        "owner",
		"app":          "application",
		"sid":          "search_id",
		"result_count": "result_count",
		"source":       "source",
		"sourcetype":   "source_type",
		"host":         "host",
		"index":        "index",
	}

	// Logs mapping
	s.fieldMappings[entity.DataTypeLogs] = commonFields

	// Incidents mapping
	s.fieldMappings[entity.DataTypeIncidents] = map[string]string{
		"_time":        "timestamp",
		"incident_id":  "incident_id",
		"status":       "status",
		"priority":     "priority",
		"assignee":     "assignee",
		"title":        "title",
		"description":  "description",
		"category":     "category",
		"subcategory":  "subcategory",
		"source":       "source",
		"sourcetype":   "source_type",
		"host":         "host",
	}

	// Events mapping
	s.fieldMappings[entity.DataTypeEvents] = map[string]string{
		"_time":        "timestamp",
		"event_type":   "event_type",
		"event_id":     "event_id",
		"user":         "user",
		"action":       "action",
		"object":       "object",
		"result":       "result",
		"src_ip":       "source_ip",
		"dest_ip":      "destination_ip",
		"src_port":     "source_port",
		"dest_port":    "destination_port",
		"protocol":     "protocol",
		"source":       "source",
		"sourcetype":   "source_type",
		"host":         "host",
	}

	// Threats mapping
	s.fieldMappings[entity.DataTypeThreats] = map[string]string{
		"_time":           "timestamp",
		"threat_type":     "threat_type",
		"threat_name":     "threat_name",
		"threat_id":       "threat_id",
		"severity":        "severity",
		"confidence":      "confidence",
		"source_ip":       "source_ip",
		"destination_ip":  "destination_ip",
		"file_hash":       "file_hash",
		"file_name":       "file_name",
		"url":             "url",
		"domain":          "domain",
		"malware_family":  "malware_family",
		"signature_id":    "signature_id",
		"source":          "source",
		"sourcetype":      "source_type",
		"host":            "host",
	}
}

// transformFieldValue transforms a field value based on its type and context
func (s *SplunkTransformer) transformFieldValue(fieldName string, value interface{}, dataType entity.DataType) (interface{}, string) {
	if value == nil {
		return nil, ""
	}

	switch fieldName {
	case "_time", "trigger_time", "create_time", "modify_time":
		return s.transformTimestamp(value)
	case "severity", "priority":
		return s.transformSeverity(value)
	case "status":
		return s.transformStatus(value, dataType)
	case "src_ip", "dest_ip", "source_ip", "destination_ip":
		return s.transformIPAddress(value)
	case "src_port", "dest_port", "source_port", "destination_port":
		return s.transformPort(value)
	case "result_count", "event_count":
		return s.transformCount(value)
	default:
		// Default transformation - ensure string values are cleaned
		return s.transformString(value)
	}
}

// transformTimestamp transforms timestamp values
func (s *SplunkTransformer) transformTimestamp(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case string:
		// Try to parse as Unix timestamp first
		if timestamp, err := strconv.ParseFloat(v, 64); err == nil {
			t := time.Unix(int64(timestamp), int64((timestamp-float64(int64(timestamp)))*1e9))
			return t.Format(time.RFC3339), "unix_timestamp_conversion"
		}
		// Try to parse as ISO format
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Format(time.RFC3339), "iso_timestamp_normalization"
		}
		// Try other common formats
		formats := []string{
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"01/02/2006 15:04:05",
			"01-02-2006 15:04:05",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, v); err == nil {
				return t.Format(time.RFC3339), "timestamp_format_conversion"
			}
		}
		return v, "timestamp_passthrough"
	case float64:
		t := time.Unix(int64(v), int64((v-float64(int64(v)))*1e9))
		return t.Format(time.RFC3339), "unix_timestamp_conversion"
	case int64:
		t := time.Unix(v, 0)
		return t.Format(time.RFC3339), "unix_timestamp_conversion"
	default:
		return value, ""
	}
}

// transformSeverity transforms severity values to standardized format
func (s *SplunkTransformer) transformSeverity(value interface{}) (interface{}, string) {
	if str := s.toString(value); str != "" {
		normalized := strings.ToLower(strings.TrimSpace(str))
		switch normalized {
		case "critical", "crit", "emergency", "fatal", "5", "1":
			return "critical", "severity_normalization"
		case "high", "error", "err", "4", "2":
			return "high", "severity_normalization"
		case "medium", "med", "warning", "warn", "3":
			return "medium", "severity_normalization"
		case "low", "minor", "info", "informational", "2", "4":
			return "low", "severity_normalization"
		case "unknown", "none", "0":
			return "unknown", "severity_normalization"
		default:
			return normalized, "severity_lowercase"
		}
	}
	return value, ""
}

// transformStatus transforms status values based on data type
func (s *SplunkTransformer) transformStatus(value interface{}, dataType entity.DataType) (interface{}, string) {
	if str := s.toString(value); str != "" {
		normalized := strings.ToLower(strings.TrimSpace(str))
		
		switch dataType {
		case entity.DataTypeIncidents:
			switch normalized {
			case "new", "open", "created", "reported":
				return "open", "incident_status_normalization"
			case "in progress", "in_progress", "assigned", "investigating":
				return "in_progress", "incident_status_normalization"
			case "resolved", "closed", "fixed", "completed":
				return "resolved", "incident_status_normalization"
			case "canceled", "cancelled", "rejected":
				return "cancelled", "incident_status_normalization"
			default:
				return normalized, "status_lowercase"
			}
		case entity.DataTypeAlerts:
			switch normalized {
			case "triggered", "active", "firing":
				return "active", "alert_status_normalization"
			case "resolved", "cleared", "closed":
				return "resolved", "alert_status_normalization"
			case "suppressed", "muted", "disabled":
				return "suppressed", "alert_status_normalization"
			default:
				return normalized, "status_lowercase"
			}
		default:
			return normalized, "status_lowercase"
		}
	}
	return value, ""
}

// transformIPAddress transforms and validates IP addresses
func (s *SplunkTransformer) transformIPAddress(value interface{}) (interface{}, string) {
	if str := s.toString(value); str != "" {
		// Basic IP validation and normalization
		ip := strings.TrimSpace(str)
		// Remove common Splunk IP formatting
		if strings.Contains(ip, "::ffff:") {
			ip = strings.Replace(ip, "::ffff:", "", 1)
		}
		return ip, "ip_address_normalization"
	}
	return value, ""
}

// transformPort transforms port numbers
func (s *SplunkTransformer) transformPort(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case string:
		if port, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			if port >= 0 && port <= 65535 {
				return port, "port_string_to_int"
			}
		}
		return v, ""
	case float64:
		port := int(v)
		if port >= 0 && port <= 65535 {
			return port, "port_float_to_int"
		}
		return port, ""
	case int, int64:
		return v, ""
	default:
		return value, ""
	}
}

// transformCount transforms count values
func (s *SplunkTransformer) transformCount(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case string:
		if count, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return count, "count_string_to_int"
		}
		return v, ""
	case float64:
		return int64(v), "count_float_to_int"
	case int:
		return int64(v), "count_int_to_int64"
	case int64:
		return v, ""
	default:
		return value, ""
	}
}

// transformString transforms string values
func (s *SplunkTransformer) transformString(value interface{}) (interface{}, string) {
	if str := s.toString(value); str != "" {
		// Trim whitespace and normalize
		normalized := strings.TrimSpace(str)
		if normalized != str {
			return normalized, "string_normalization"
		}
		return str, ""
	}
	return value, ""
}

// applyDataTypeTransformations applies specific transformations based on data type
func (s *SplunkTransformer) applyDataTypeTransformations(original, transformed map[string]interface{}, dataType entity.DataType, transformations *[]string) error {
	switch dataType {
	case entity.DataTypeAlerts:
		return s.transformAlert(original, transformed, transformations)
	case entity.DataTypeIncidents:
		return s.transformIncident(original, transformed, transformations)
	case entity.DataTypeEvents:
		return s.transformEvent(original, transformed, transformations)
	case entity.DataTypeThreats:
		return s.transformThreat(original, transformed, transformations)
	case entity.DataTypeLogs:
		return s.transformLog(original, transformed, transformations)
	default:
		return nil
	}
}

// transformAlert applies alert-specific transformations
func (s *SplunkTransformer) transformAlert(original, transformed map[string]interface{}, transformations *[]string) error {
	// Ensure alert has required fields with defaults
	if _, exists := transformed["alert_id"]; !exists {
		if sid, exists := original["sid"]; exists {
			transformed["alert_id"] = sid
			*transformations = append(*transformations, "generated_alert_id_from_sid")
		} else {
			transformed["alert_id"] = fmt.Sprintf("splunk-alert-%d", time.Now().Unix())
			*transformations = append(*transformations, "generated_alert_id")
		}
	}

	// Set alert type if not present
	if _, exists := transformed["alert_type"]; !exists {
		transformed["alert_type"] = "splunk_saved_search"
		*transformations = append(*transformations, "set_default_alert_type")
	}

	return nil
}

// transformIncident applies incident-specific transformations
func (s *SplunkTransformer) transformIncident(original, transformed map[string]interface{}, transformations *[]string) error {
	// Generate incident ID if not present
	if _, exists := transformed["incident_id"]; !exists {
		transformed["incident_id"] = fmt.Sprintf("splunk-incident-%d", time.Now().Unix())
		*transformations = append(*transformations, "generated_incident_id")
	}

	// Set default priority if not present
	if _, exists := transformed["priority"]; !exists {
		transformed["priority"] = "medium"
		*transformations = append(*transformations, "set_default_priority")
	}

	return nil
}

// transformEvent applies event-specific transformations
func (s *SplunkTransformer) transformEvent(original, transformed map[string]interface{}, transformations *[]string) error {
	// Generate event ID if not present
	if _, exists := transformed["event_id"]; !exists {
		// Use timestamp and raw message hash as event ID
		if timestamp, exists := transformed["timestamp"]; exists {
			if raw, exists := original["_raw"]; exists {
				eventID := fmt.Sprintf("splunk-event-%s-%x", timestamp, []byte(s.toString(raw)))
				transformed["event_id"] = eventID
				*transformations = append(*transformations, "generated_event_id_from_timestamp_and_raw")
			} else {
				transformed["event_id"] = fmt.Sprintf("splunk-event-%d", time.Now().Unix())
				*transformations = append(*transformations, "generated_event_id")
			}
		}
	}

	return nil
}

// transformThreat applies threat-specific transformations
func (s *SplunkTransformer) transformThreat(original, transformed map[string]interface{}, transformations *[]string) error {
	// Generate threat ID if not present
	if _, exists := transformed["threat_id"]; !exists {
		transformed["threat_id"] = fmt.Sprintf("splunk-threat-%d", time.Now().Unix())
		*transformations = append(*transformations, "generated_threat_id")
	}

	// Set default confidence if not present
	if _, exists := transformed["confidence"]; !exists {
		transformed["confidence"] = 50 // Medium confidence
		*transformations = append(*transformations, "set_default_confidence")
	}

	return nil
}

// transformLog applies log-specific transformations
func (s *SplunkTransformer) transformLog(original, transformed map[string]interface{}, transformations *[]string) error {
	// Ensure log has a message field
	if _, exists := transformed["message"]; !exists {
		if raw, exists := original["_raw"]; exists {
			transformed["message"] = raw
			*transformations = append(*transformations, "set_message_from_raw")
		}
	}

	return nil
}

// generateMetadata generates metadata for the transformed record
func (s *SplunkTransformer) generateMetadata(original map[string]interface{}, dataType entity.DataType) map[string]interface{} {
	metadata := map[string]interface{}{
		"source_system": "splunk",
		"data_type":     dataType,
		"transform_timestamp": time.Now().Format(time.RFC3339),
		"original_field_count": len(original),
	}

	// Add Splunk-specific metadata
	if index, exists := original["index"]; exists {
		metadata["splunk_index"] = index
	}
	if sourcetype, exists := original["sourcetype"]; exists {
		metadata["splunk_sourcetype"] = sourcetype
	}
	if source, exists := original["source"]; exists {
		metadata["splunk_source"] = source
	}

	return metadata
}

// getRequiredFields returns required fields for a data type
func (s *SplunkTransformer) getRequiredFields(dataType entity.DataType) []string {
	switch dataType {
	case entity.DataTypeAlerts:
		return []string{"timestamp", "alert_name", "severity"}
	case entity.DataTypeIncidents:
		return []string{"timestamp", "incident_id", "status"}
	case entity.DataTypeEvents:
		return []string{"timestamp", "event_type"}
	case entity.DataTypeThreats:
		return []string{"timestamp", "threat_type", "threat_name"}
	case entity.DataTypeLogs:
		return []string{"timestamp", "message"}
	default:
		return []string{"timestamp"}
	}
}

// validateFieldFormat validates field format based on field name and data type
func (s *SplunkTransformer) validateFieldFormat(fieldName string, value interface{}, dataType entity.DataType) error {
	switch fieldName {
	case "timestamp":
		return s.validateTimestampFormat(value)
	case "source_ip", "destination_ip":
		return s.validateIPFormat(value)
	case "source_port", "destination_port":
		return s.validatePortFormat(value)
	case "severity":
		return s.validateSeverityFormat(value)
	default:
		return nil // No specific validation
	}
}

// validateTimestampFormat validates timestamp format
func (s *SplunkTransformer) validateTimestampFormat(value interface{}) error {
	str := s.toString(value)
	if str == "" {
		return fmt.Errorf("timestamp cannot be empty")
	}

	// Try to parse as RFC3339 (our standard format)
	if _, err := time.Parse(time.RFC3339, str); err == nil {
		return nil
	}

	return fmt.Errorf("invalid timestamp format: %s", str)
}

// validateIPFormat validates IP address format
func (s *SplunkTransformer) validateIPFormat(value interface{}) error {
	str := s.toString(value)
	if str == "" {
		return nil // Empty IP is allowed
	}

	// Basic IP validation (IPv4 and IPv6)
	parts := strings.Split(str, ".")
	if len(parts) == 4 {
		// IPv4 validation
		for _, part := range parts {
			if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
				return fmt.Errorf("invalid IPv4 address: %s", str)
			}
		}
		return nil
	}

	// IPv6 validation (basic)
	if strings.Contains(str, ":") && len(str) >= 2 {
		return nil // Basic IPv6 check
	}

	return fmt.Errorf("invalid IP address format: %s", str)
}

// validatePortFormat validates port number format
func (s *SplunkTransformer) validatePortFormat(value interface{}) error {
	switch v := value.(type) {
	case int, int64:
		port := s.toInt64(v)
		if port < 0 || port > 65535 {
			return fmt.Errorf("port number out of range: %d", port)
		}
	case string:
		if port, err := strconv.Atoi(v); err != nil {
			return fmt.Errorf("invalid port format: %s", v)
		} else if port < 0 || port > 65535 {
			return fmt.Errorf("port number out of range: %d", port)
		}
	}
	return nil
}

// validateSeverityFormat validates severity format
func (s *SplunkTransformer) validateSeverityFormat(value interface{}) error {
	str := strings.ToLower(s.toString(value))
	validSeverities := []string{"critical", "high", "medium", "low", "unknown"}
	
	for _, valid := range validSeverities {
		if str == valid {
			return nil
		}
	}

	return fmt.Errorf("invalid severity value: %s", str)
}

// Utility methods

// toString safely converts a value to string
func (s *SplunkTransformer) toString(value interface{}) string {
	if value == nil {
		return ""
	}
	
	switch v := value.(type) {
	case string:
		return v
	case int, int64, float64:
		return fmt.Sprintf("%v", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		// Try JSON marshaling for complex types
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
		return fmt.Sprintf("%v", v)
	}
}

// toInt64 safely converts a value to int64
func (s *SplunkTransformer) toInt64(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// isEmptyValue checks if a value is considered empty
func (s *SplunkTransformer) isEmptyValue(value interface{}) bool {
	if value == nil {
		return true
	}

	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case int, int64:
		return v == 0
	case float64:
		return v == 0.0
	case bool:
		return !v
	case []interface{}:
		return len(v) == 0
	case map[string]interface{}:
		return len(v) == 0
	default:
		return false
	}
}