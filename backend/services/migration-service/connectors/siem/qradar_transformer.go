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

// NewQRadarTransformer creates a new QRadar data transformer
func NewQRadarTransformer() *QRadarTransformer {
	transformer := &QRadarTransformer{
		fieldMappings: make(map[entity.DataType]map[string]string),
	}

	// Initialize field mappings for different data types
	transformer.initializeFieldMappings()

	return transformer
}

// TransformRecord transforms a single record from QRadar format to iSECTECH format
func (q *QRadarTransformer) TransformRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*connectors.TransformedRecord, error) {
	if record == nil {
		return nil, fmt.Errorf("input record is nil")
	}

	// Create transformed record
	transformedData := make(map[string]interface{})
	transformationApplied := make([]string, 0)

	// Get field mappings for the data type
	fieldMappings := q.GetFieldMappings(dataType)

	// Apply field mappings
	for qradarField, isectechField := range fieldMappings {
		if value, exists := record[qradarField]; exists {
			transformedValue, transformation := q.transformFieldValue(qradarField, value, dataType)
			transformedData[isectechField] = transformedValue
			if transformation != "" {
				transformationApplied = append(transformationApplied, transformation)
			}
		}
	}

	// Apply data-type specific transformations
	if err := q.applyDataTypeTransformations(record, transformedData, dataType, &transformationApplied); err != nil {
		return nil, fmt.Errorf("failed to apply data type transformations: %w", err)
	}

	// Add metadata
	metadata := q.generateMetadata(record, dataType)

	// Validate the transformed record
	validationResult, err := q.ValidateRecord(ctx, transformedData, dataType)
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
func (q *QRadarTransformer) TransformBatch(ctx context.Context, batch []map[string]interface{}, dataType entity.DataType) ([]*connectors.TransformedRecord, error) {
	if len(batch) == 0 {
		return make([]*connectors.TransformedRecord, 0), nil
	}

	transformedRecords := make([]*connectors.TransformedRecord, 0, len(batch))

	for i, record := range batch {
		transformedRecord, err := q.TransformRecord(ctx, record, dataType)
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
func (q *QRadarTransformer) GetFieldMappings(dataType entity.DataType) map[string]string {
	if mappings, exists := q.fieldMappings[dataType]; exists {
		return mappings
	}
	return q.fieldMappings[entity.DataTypeEvents] // Default to events mapping
}

// ValidateRecord validates a record against the schema
func (q *QRadarTransformer) ValidateRecord(ctx context.Context, record map[string]interface{}, dataType entity.DataType) (*connectors.ValidationResult, error) {
	result := &connectors.ValidationResult{
		IsValid:      true,
		Errors:       make([]connectors.ValidationError, 0),
		Warnings:     make([]connectors.ValidationWarning, 0),
		Score:        100.0,
		FieldResults: make(map[string]connectors.FieldValidation),
	}

	// Get required fields for the data type
	requiredFields := q.getRequiredFields(dataType)

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
		} else if q.isEmptyValue(value) {
			warning := connectors.ValidationWarning{
				Field:          field,
				WarningType:    "empty_required_field",
				Message:        fmt.Sprintf("Required field '%s' is empty", field),
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

		if err := q.validateFieldFormat(field, value, dataType); err != nil {
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
func (q *QRadarTransformer) initializeFieldMappings() {
	// Events mapping
	q.fieldMappings[entity.DataTypeEvents] = map[string]string{
		"id":              "event_id",
		"starttime":       "timestamp",
		"eventcount":      "event_count",
		"eventid":         "original_event_id",
		"qid":             "rule_id",
		"severity":        "severity",
		"category":        "category",
		"highlevelcategory": "high_level_category",
		"relevance":       "relevance",
		"credibilityrating": "credibility",
		"logsourceid":     "log_source_id",
		"sourceip":        "source_ip",
		"destinationip":   "destination_ip",
		"sourceport":      "source_port",
		"destinationport": "destination_port",
		"protocol":        "protocol",
		"username":        "username",
		"eventdirection":  "direction",
		"sourcenetwork":   "source_network",
		"destinationnetwork": "destination_network",
		"lastupdatedtime": "last_updated",
		"status":          "status",
		"assignedto":      "assigned_to",
		"followup":        "follow_up",
		"protected":       "protected",
	}

	// Incidents/Offenses mapping
	q.fieldMappings[entity.DataTypeIncidents] = map[string]string{
		"id":                   "incident_id",
		"description":          "title",
		"start_time":           "timestamp",
		"last_updated_time":    "last_updated",
		"status":               "status",
		"magnitude":            "magnitude",
		"credibility":          "credibility",
		"relevance":            "relevance",
		"severity":             "severity",
		"assigned_to":          "assigned_to",
		"closing_user":         "closed_by",
		"closing_reason":       "close_reason",
		"close_time":           "closed_at",
		"follow_up":            "follow_up",
		"protected":            "protected",
		"offense_type":         "offense_type",
		"category_count":       "category_count",
		"policy_category_count": "policy_category_count",
		"security_category_count": "security_category_count",
		"source_count":         "source_count",
		"local_destination_count": "local_destination_count",
		"remote_destination_count": "remote_destination_count",
		"event_count":          "event_count",
		"flow_count":           "flow_count",
		"inactive_reason":      "inactive_reason",
	}

	// Alerts mapping (same as incidents for QRadar)
	q.fieldMappings[entity.DataTypeAlerts] = q.fieldMappings[entity.DataTypeIncidents]

	// Assets mapping
	q.fieldMappings[entity.DataTypeAssets] = map[string]string{
		"id":             "asset_id",
		"interfaces":     "interfaces",
		"properties":     "properties",
		"vulnerabilities": "vulnerabilities",
		"domain_id":      "domain_id",
		"hostnames":      "hostnames",
		"products":       "products",
		"risk_score_sum": "risk_score",
		"vulnerability_count": "vulnerability_count",
	}
}

// transformFieldValue transforms a field value based on its type and context
func (q *QRadarTransformer) transformFieldValue(fieldName string, value interface{}, dataType entity.DataType) (interface{}, string) {
	if value == nil {
		return nil, ""
	}

	switch fieldName {
	case "starttime", "start_time", "last_updated_time", "lastupdatedtime", "close_time", "closetime":
		return q.transformTimestamp(value)
	case "severity":
		return q.transformSeverity(value)
	case "status":
		return q.transformStatus(value, dataType)
	case "sourceip", "destinationip", "source_ip", "destination_ip":
		return q.transformIPAddress(value)
	case "sourceport", "destinationport", "source_port", "destination_port":
		return q.transformPort(value)
	case "protocol":
		return q.transformProtocol(value)
	case "eventcount", "event_count", "category_count", "source_count":
		return q.transformCount(value)
	case "magnitude":
		return q.transformMagnitude(value)
	case "credibility", "credibilityrating", "relevance":
		return q.transformScore(value)
	case "followup", "follow_up", "protected":
		return q.transformBoolean(value)
	default:
		// Default transformation - ensure string values are cleaned
		return q.transformString(value)
	}
}

// transformTimestamp transforms QRadar timestamp values (milliseconds since epoch)
func (q *QRadarTransformer) transformTimestamp(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case int64:
		// QRadar uses milliseconds since epoch
		t := time.Unix(v/1000, (v%1000)*1000000)
		return t.Format(time.RFC3339), "qradar_timestamp_conversion"
	case float64:
		// Convert to int64 first
		timestamp := int64(v)
		t := time.Unix(timestamp/1000, (timestamp%1000)*1000000)
		return t.Format(time.RFC3339), "qradar_timestamp_conversion"
	case string:
		// Try to parse as timestamp
		if timestamp, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.Unix(timestamp/1000, (timestamp%1000)*1000000)
			return t.Format(time.RFC3339), "qradar_timestamp_string_conversion"
		}
		// Try to parse as ISO format
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Format(time.RFC3339), "timestamp_normalization"
		}
		return v, "timestamp_passthrough"
	default:
		return value, ""
	}
}

// transformSeverity transforms QRadar severity values (1-10 scale) to standardized format
func (q *QRadarTransformer) transformSeverity(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case int, int64:
		severity := q.toInt64(v)
		switch {
		case severity >= 8:
			return "critical", "qradar_severity_normalization"
		case severity >= 6:
			return "high", "qradar_severity_normalization"
		case severity >= 4:
			return "medium", "qradar_severity_normalization"
		case severity >= 1:
			return "low", "qradar_severity_normalization"
		default:
			return "unknown", "qradar_severity_normalization"
		}
	case float64:
		return q.transformSeverity(int64(v))
	case string:
		if severity, err := strconv.ParseInt(v, 10, 64); err == nil {
			return q.transformSeverity(severity)
		}
		// Handle string severities
		normalized := strings.ToLower(strings.TrimSpace(v))
		switch normalized {
		case "critical", "fatal", "emergency":
			return "critical", "severity_normalization"
		case "high", "error":
			return "high", "severity_normalization"
		case "medium", "warning", "warn":
			return "medium", "severity_normalization"
		case "low", "info", "informational":
			return "low", "severity_normalization"
		default:
			return "unknown", "severity_normalization"
		}
	default:
		return "unknown", "severity_default"
	}
}

// transformStatus transforms status values based on data type
func (q *QRadarTransformer) transformStatus(value interface{}, dataType entity.DataType) (interface{}, string) {
	if str := q.toString(value); str != "" {
		normalized := strings.ToUpper(strings.TrimSpace(str))
		
		switch dataType {
		case entity.DataTypeIncidents, entity.DataTypeAlerts:
			switch normalized {
			case "OPEN":
				return "open", "qradar_status_normalization"
			case "HIDDEN":
				return "suppressed", "qradar_status_normalization"
			case "CLOSED":
				return "resolved", "qradar_status_normalization"
			default:
				return strings.ToLower(normalized), "status_lowercase"
			}
		case entity.DataTypeEvents:
			switch normalized {
			case "OPEN":
				return "active", "qradar_event_status_normalization"
			case "CLOSED":
				return "resolved", "qradar_event_status_normalization"
			default:
				return strings.ToLower(normalized), "status_lowercase"
			}
		default:
			return strings.ToLower(normalized), "status_lowercase"
		}
	}
	return value, ""
}

// transformIPAddress transforms and validates IP addresses
func (q *QRadarTransformer) transformIPAddress(value interface{}) (interface{}, string) {
	if str := q.toString(value); str != "" {
		// Basic IP validation and normalization
		ip := strings.TrimSpace(str)
		// Handle QRadar IP formatting
		if ip == "0" || ip == "0.0.0.0" {
			return "", "empty_ip_normalization"
		}
		return ip, "ip_address_normalization"
	}
	return value, ""
}

// transformPort transforms port numbers
func (q *QRadarTransformer) transformPort(value interface{}) (interface{}, string) {
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
		port := q.toInt64(v)
		if port >= 0 && port <= 65535 {
			return int(port), "port_normalization"
		}
		return int(port), ""
	default:
		return value, ""
	}
}

// transformProtocol transforms protocol numbers to names where possible
func (q *QRadarTransformer) transformProtocol(value interface{}) (interface{}, string) {
	protocolMap := map[int]string{
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		50:  "ESP",
		51:  "AH",
		89:  "OSPF",
		132: "SCTP",
	}

	switch v := value.(type) {
	case int, int64:
		protocol := int(q.toInt64(v))
		if name, exists := protocolMap[protocol]; exists {
			return name, "protocol_number_to_name"
		}
		return protocol, ""
	case float64:
		return q.transformProtocol(int(v))
	case string:
		if protocol, err := strconv.Atoi(v); err == nil {
			return q.transformProtocol(protocol)
		}
		return strings.ToUpper(v), "protocol_uppercase"
	default:
		return value, ""
	}
}

// transformCount transforms count values
func (q *QRadarTransformer) transformCount(value interface{}) (interface{}, string) {
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

// transformMagnitude transforms QRadar magnitude values
func (q *QRadarTransformer) transformMagnitude(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case float64:
		// Keep as float but normalize to reasonable precision
		return fmt.Sprintf("%.2f", v), "magnitude_precision_normalization"
	case int, int64:
		return float64(q.toInt64(v)), "magnitude_int_to_float"
	case string:
		if magnitude, err := strconv.ParseFloat(v, 64); err == nil {
			return fmt.Sprintf("%.2f", magnitude), "magnitude_string_to_float"
		}
		return v, ""
	default:
		return value, ""
	}
}

// transformScore transforms QRadar score values (credibility, relevance)
func (q *QRadarTransformer) transformScore(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case int, int64:
		score := q.toInt64(v)
		// QRadar scores are typically 1-10, normalize to 0-100
		normalizedScore := (score - 1) * 100 / 9
		if normalizedScore < 0 {
			normalizedScore = 0
		}
		if normalizedScore > 100 {
			normalizedScore = 100
		}
		return int(normalizedScore), "qradar_score_normalization"
	case float64:
		return q.transformScore(int64(v))
	case string:
		if score, err := strconv.ParseInt(v, 10, 64); err == nil {
			return q.transformScore(score)
		}
		return v, ""
	default:
		return value, ""
	}
}

// transformBoolean transforms boolean values
func (q *QRadarTransformer) transformBoolean(value interface{}) (interface{}, string) {
	switch v := value.(type) {
	case bool:
		return v, ""
	case string:
		normalized := strings.ToLower(strings.TrimSpace(v))
		switch normalized {
		case "true", "yes", "1", "on", "enabled":
			return true, "boolean_string_to_bool"
		case "false", "no", "0", "off", "disabled":
			return false, "boolean_string_to_bool"
		default:
			return v, ""
		}
	case int, int64:
		return q.toInt64(v) != 0, "boolean_int_to_bool"
	case float64:
		return v != 0.0, "boolean_float_to_bool"
	default:
		return value, ""
	}
}

// transformString transforms string values
func (q *QRadarTransformer) transformString(value interface{}) (interface{}, string) {
	if str := q.toString(value); str != "" {
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
func (q *QRadarTransformer) applyDataTypeTransformations(original, transformed map[string]interface{}, dataType entity.DataType, transformations *[]string) error {
	switch dataType {
	case entity.DataTypeEvents:
		return q.transformEvent(original, transformed, transformations)
	case entity.DataTypeIncidents:
		return q.transformIncident(original, transformed, transformations)
	case entity.DataTypeAlerts:
		return q.transformAlert(original, transformed, transformations)
	case entity.DataTypeAssets:
		return q.transformAsset(original, transformed, transformations)
	default:
		return nil
	}
}

// transformEvent applies event-specific transformations
func (q *QRadarTransformer) transformEvent(original, transformed map[string]interface{}, transformations *[]string) error {
	// Ensure event has required fields with defaults
	if _, exists := transformed["event_type"]; !exists {
		if category, exists := original["category"]; exists {
			transformed["event_type"] = fmt.Sprintf("qradar_category_%v", category)
			*transformations = append(*transformations, "generated_event_type_from_category")
		} else {
			transformed["event_type"] = "qradar_event"
			*transformations = append(*transformations, "set_default_event_type")
		}
	}

	// Add event classification
	if qid, exists := original["qid"]; exists {
		transformed["rule_name"] = fmt.Sprintf("QRadar Rule %v", qid)
		*transformations = append(*transformations, "generated_rule_name_from_qid")
	}

	return nil
}

// transformIncident applies incident-specific transformations
func (q *QRadarTransformer) transformIncident(original, transformed map[string]interface{}, transformations *[]string) error {
	// Set priority based on magnitude and severity
	if _, exists := transformed["priority"]; !exists {
		priority := "medium" // default
		
		if magnitude, exists := original["magnitude"]; exists {
			if mag, ok := magnitude.(float64); ok {
				if mag >= 8 {
					priority = "critical"
				} else if mag >= 5 {
					priority = "high"
				} else if mag >= 2 {
					priority = "medium"
				} else {
					priority = "low"
				}
			}
		}
		
		transformed["priority"] = priority
		*transformations = append(*transformations, "calculated_priority_from_magnitude")
	}

	// Add incident type
	if _, exists := transformed["incident_type"]; !exists {
		transformed["incident_type"] = "qradar_offense"
		*transformations = append(*transformations, "set_default_incident_type")
	}

	return nil
}

// transformAlert applies alert-specific transformations
func (q *QRadarTransformer) transformAlert(original, transformed map[string]interface{}, transformations *[]string) error {
	// Apply same transformations as incidents for QRadar
	return q.transformIncident(original, transformed, transformations)
}

// transformAsset applies asset-specific transformations
func (q *QRadarTransformer) transformAsset(original, transformed map[string]interface{}, transformations *[]string) error {
	// Extract IP addresses from interfaces
	if interfaces, exists := original["interfaces"]; exists {
		if interfaceList, ok := interfaces.([]interface{}); ok {
			var ipAddresses []string
			for _, iface := range interfaceList {
				if ifaceMap, ok := iface.(map[string]interface{}); ok {
					if ip, exists := ifaceMap["ip_address"]; exists {
						if ipStr := q.toString(ip); ipStr != "" {
							ipAddresses = append(ipAddresses, ipStr)
						}
					}
				}
			}
			if len(ipAddresses) > 0 {
				transformed["ip_addresses"] = ipAddresses
				*transformations = append(*transformations, "extracted_ip_addresses_from_interfaces")
			}
		}
	}

	// Set asset type
	if _, exists := transformed["asset_type"]; !exists {
		transformed["asset_type"] = "network_device"
		*transformations = append(*transformations, "set_default_asset_type")
	}

	return nil
}

// generateMetadata generates metadata for the transformed record
func (q *QRadarTransformer) generateMetadata(original map[string]interface{}, dataType entity.DataType) map[string]interface{} {
	metadata := map[string]interface{}{
		"source_system":        "qradar",
		"data_type":            dataType,
		"transform_timestamp":  time.Now().Format(time.RFC3339),
		"original_field_count": len(original),
	}

	// Add QRadar-specific metadata
	if domainID, exists := original["domain_id"]; exists {
		metadata["qradar_domain_id"] = domainID
	}
	if logSourceID, exists := original["logsourceid"]; exists {
		metadata["qradar_log_source_id"] = logSourceID
	}
	if qid, exists := original["qid"]; exists {
		metadata["qradar_qid"] = qid
	}

	return metadata
}

// getRequiredFields returns required fields for a data type
func (q *QRadarTransformer) getRequiredFields(dataType entity.DataType) []string {
	switch dataType {
	case entity.DataTypeEvents:
		return []string{"event_id", "timestamp", "rule_id"}
	case entity.DataTypeIncidents:
		return []string{"incident_id", "title", "timestamp", "status"}
	case entity.DataTypeAlerts:
		return []string{"incident_id", "title", "severity"}
	case entity.DataTypeAssets:
		return []string{"asset_id", "interfaces"}
	default:
		return []string{"timestamp"}
	}
}

// validateFieldFormat validates field format based on field name and data type
func (q *QRadarTransformer) validateFieldFormat(fieldName string, value interface{}, dataType entity.DataType) error {
	switch fieldName {
	case "timestamp":
		return q.validateTimestampFormat(value)
	case "source_ip", "destination_ip":
		return q.validateIPFormat(value)
	case "source_port", "destination_port":
		return q.validatePortFormat(value)
	case "severity":
		return q.validateSeverityFormat(value)
	default:
		return nil // No specific validation
	}
}

// validateTimestampFormat validates timestamp format
func (q *QRadarTransformer) validateTimestampFormat(value interface{}) error {
	str := q.toString(value)
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
func (q *QRadarTransformer) validateIPFormat(value interface{}) error {
	str := q.toString(value)
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
func (q *QRadarTransformer) validatePortFormat(value interface{}) error {
	switch v := value.(type) {
	case int, int64:
		port := q.toInt64(v)
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
func (q *QRadarTransformer) validateSeverityFormat(value interface{}) error {
	str := strings.ToLower(q.toString(value))
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
func (q *QRadarTransformer) toString(value interface{}) string {
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
func (q *QRadarTransformer) toInt64(value interface{}) int64 {
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
func (q *QRadarTransformer) isEmptyValue(value interface{}) bool {
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