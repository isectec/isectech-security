package service

import (
	"context"
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

// NormalizationService implements service.EventNormalizationService
type NormalizationService struct {
	logger  *logging.Logger
	metrics *metrics.Collector
	config  *NormalizationConfig
	
	// Field mappers
	fieldMappers    map[string]FieldMapper
	valueNormalizers map[string]ValueNormalizer
	timestampParsers []TimestampParser
}

// NormalizationConfig contains normalization configuration
type NormalizationConfig struct {
	// Timestamp normalization
	TimestampFormats      []string          `json:"timestamp_formats"`
	TimezoneHandling      string            `json:"timezone_handling"` // "utc", "preserve", "detect"
	
	// IP normalization
	NormalizeIPAddresses  bool              `json:"normalize_ip_addresses"`
	IPAllowPrivate        bool              `json:"ip_allow_private"`
	IPAllowLoopback       bool              `json:"ip_allow_loopback"`
	
	// Field normalization
	FieldMappings         map[string]string `json:"field_mappings"`
	FieldTransforms       map[string]string `json:"field_transforms"`
	CaseNormalization     string            `json:"case_normalization"` // "lower", "upper", "preserve"
	
	// Value normalization
	TrimWhitespace        bool              `json:"trim_whitespace"`
	NormalizeURLs         bool              `json:"normalize_urls"`
	NormalizeEmails       bool              `json:"normalize_emails"`
	NormalizeDomains      bool              `json:"normalize_domains"`
	
	// Custom normalizers
	CustomNormalizers     map[string]string `json:"custom_normalizers"`
	
	// Performance settings
	CacheNormalizations   bool              `json:"cache_normalizations"`
	CacheTTL              time.Duration     `json:"cache_ttl"`
	NormalizationTimeout  time.Duration     `json:"normalization_timeout"`
}

// FieldMapper maps field names
type FieldMapper func(fieldName string) string

// ValueNormalizer normalizes field values
type ValueNormalizer func(value interface{}) (interface{}, error)

// TimestampParser parses timestamps from strings
type TimestampParser struct {
	Format   string
	Layout   string
	Priority int
}

// NewNormalizationService creates a new normalization service
func NewNormalizationService(
	logger *logging.Logger,
	metrics *metrics.Collector,
	config *NormalizationConfig,
) service.EventNormalizationService {
	if config == nil {
		config = &NormalizationConfig{
			TimestampFormats: []string{
				time.RFC3339,
				time.RFC3339Nano,
				"2006-01-02T15:04:05Z",
				"2006-01-02 15:04:05",
				"Jan 2 15:04:05 2006",
			},
			TimezoneHandling:      "utc",
			NormalizeIPAddresses:  true,
			IPAllowPrivate:        true,
			IPAllowLoopback:       true,
			CaseNormalization:     "lower",
			TrimWhitespace:        true,
			NormalizeURLs:         true,
			NormalizeEmails:       true,
			NormalizeDomains:      true,
			CacheNormalizations:   true,
			CacheTTL:             5 * time.Minute,
			NormalizationTimeout: 5 * time.Second,
		}
	}

	ns := &NormalizationService{
		logger:           logger,
		metrics:          metrics,
		config:           config,
		fieldMappers:     make(map[string]FieldMapper),
		valueNormalizers: make(map[string]ValueNormalizer),
	}

	// Initialize normalizers
	ns.initializeFieldMappers()
	ns.initializeValueNormalizers()
	ns.initializeTimestampParsers()

	return ns
}

// NormalizeTimestamps normalizes timestamp fields
func (ns *NormalizationService) NormalizeTimestamps(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		ns.metrics.RecordBusinessOperation("timestamp_normalization", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Normalize OccurredAt if it's zero
	if event.OccurredAt.IsZero() && event.Payload != nil {
		if timestamp, found := ns.extractTimestampFromPayload(event.Payload); found {
			event.OccurredAt = timestamp
		}
	}

	// Ensure timestamps are in UTC
	if ns.config.TimezoneHandling == "utc" {
		event.OccurredAt = event.OccurredAt.UTC()
		event.ReceivedAt = event.ReceivedAt.UTC()
		event.CreatedAt = event.CreatedAt.UTC()
		event.UpdatedAt = event.UpdatedAt.UTC()
		if event.ProcessedAt != nil {
			utc := event.ProcessedAt.UTC()
			event.ProcessedAt = &utc
		}
	}

	// Validate timestamp consistency
	if err := ns.validateTimestampConsistency(event); err != nil {
		ns.logger.Warn("Timestamp inconsistency detected",
			logging.String("event_id", event.ID.String()),
			logging.String("error", err.Error()),
		)
		// Don't fail normalization for timestamp inconsistencies, just log
	}

	ns.logger.Debug("Timestamps normalized",
		logging.String("event_id", event.ID.String()),
		logging.Time("occurred_at", event.OccurredAt),
	)

	return nil
}

// NormalizeIPAddresses normalizes IP address fields
func (ns *NormalizationService) NormalizeIPAddresses(ctx context.Context, event *entity.Event) error {
	if !ns.config.NormalizeIPAddresses {
		return nil
	}

	start := time.Now()
	defer func() {
		ns.metrics.RecordBusinessOperation("ip_normalization", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Normalize source IP
	if event.SourceIP != "" {
		normalizedIP, err := ns.normalizeIP(event.SourceIP)
		if err != nil {
			ns.logger.Warn("Failed to normalize source IP",
				logging.String("event_id", event.ID.String()),
				logging.String("original_ip", event.SourceIP),
				logging.String("error", err.Error()),
			)
		} else {
			event.SourceIP = normalizedIP
		}
	}

	// Normalize destination IP
	if event.DestinationIP != "" {
		normalizedIP, err := ns.normalizeIP(event.DestinationIP)
		if err != nil {
			ns.logger.Warn("Failed to normalize destination IP",
				logging.String("event_id", event.ID.String()),
				logging.String("original_ip", event.DestinationIP),
				logging.String("error", err.Error()),
			)
		} else {
			event.DestinationIP = normalizedIP
		}
	}

	// Normalize IPs in payload
	if event.Payload != nil {
		ns.normalizeIPsInMap(event.Payload)
	}

	ns.logger.Debug("IP addresses normalized",
		logging.String("event_id", event.ID.String()),
		logging.String("source_ip", event.SourceIP),
		logging.String("destination_ip", event.DestinationIP),
	)

	return nil
}

// NormalizeFieldNames normalizes field names in the event
func (ns *NormalizationService) NormalizeFieldNames(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		ns.metrics.RecordBusinessOperation("field_name_normalization", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Normalize payload field names
	if event.Payload != nil {
		normalizedPayload := make(map[string]interface{})
		for key, value := range event.Payload {
			normalizedKey := ns.normalizeFieldName(key)
			normalizedPayload[normalizedKey] = value
		}
		event.Payload = normalizedPayload
	}

	// Normalize metadata field names
	if event.Metadata != nil {
		normalizedMetadata := make(map[string]interface{})
		for key, value := range event.Metadata {
			normalizedKey := ns.normalizeFieldName(key)
			normalizedMetadata[normalizedKey] = value
		}
		event.Metadata = normalizedMetadata
	}

	// Apply field mappings from configuration
	if event.Payload != nil {
		for oldKey, newKey := range ns.config.FieldMappings {
			if value, exists := event.Payload[oldKey]; exists {
				delete(event.Payload, oldKey)
				event.Payload[newKey] = value
			}
		}
	}

	ns.logger.Debug("Field names normalized",
		logging.String("event_id", event.ID.String()),
	)

	return nil
}

// NormalizeValues normalizes field values
func (ns *NormalizationService) NormalizeValues(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		ns.metrics.RecordBusinessOperation("value_normalization", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Normalize core field values
	event.Source = ns.normalizeStringValue(event.Source)
	event.Category = ns.normalizeStringValue(event.Category)
	event.Title = ns.normalizeStringValue(event.Title)
	event.Description = ns.normalizeStringValue(event.Description)
	event.Protocol = ns.normalizeStringValue(event.Protocol)
	event.AssetType = ns.normalizeStringValue(event.AssetType)
	event.AssetName = ns.normalizeStringValue(event.AssetName)
	event.Username = ns.normalizeStringValue(event.Username)
	event.UserAgent = ns.normalizeStringValue(event.UserAgent)

	// Normalize severity to lowercase
	if event.Severity != "" {
		event.Severity = types.Severity(strings.ToLower(string(event.Severity)))
	}

	// Normalize tags
	normalizedTags := make([]string, len(event.Tags))
	for i, tag := range event.Tags {
		normalizedTags[i] = ns.normalizeStringValue(tag)
	}
	event.Tags = normalizedTags

	// Normalize payload values
	if event.Payload != nil {
		ns.normalizeValuesInMap(event.Payload)
	}

	// Normalize metadata values
	if event.Metadata != nil {
		ns.normalizeValuesInMap(event.Metadata)
	}

	ns.logger.Debug("Values normalized",
		logging.String("event_id", event.ID.String()),
	)

	return nil
}

// ApplyFieldMappings applies custom field mappings
func (ns *NormalizationService) ApplyFieldMappings(ctx context.Context, event *entity.Event) error {
	start := time.Now()
	defer func() {
		ns.metrics.RecordBusinessOperation("field_mapping", event.TenantID.String(), "completed", time.Since(start))
	}()

	// Apply source-specific field mappings
	mappings := ns.getSourceSpecificMappings(event.Source)
	
	if event.Payload != nil {
		for sourceField, targetField := range mappings {
			if value, exists := event.Payload[sourceField]; exists {
				// Remove old field
				delete(event.Payload, sourceField)
				
				// Add mapped field
				event.Payload[targetField] = value
				
				ns.logger.Debug("Applied field mapping",
					logging.String("event_id", event.ID.String()),
					logging.String("source_field", sourceField),
					logging.String("target_field", targetField),
				)
			}
		}
	}

	// Apply event type-specific mappings
	eventTypeMappings := ns.getEventTypeSpecificMappings(event.Type)
	
	if event.Payload != nil {
		for sourceField, targetField := range eventTypeMappings {
			if value, exists := event.Payload[sourceField]; exists {
				delete(event.Payload, sourceField)
				event.Payload[targetField] = value
			}
		}
	}

	ns.logger.Debug("Field mappings applied",
		logging.String("event_id", event.ID.String()),
		logging.Int("mappings_applied", len(mappings)+len(eventTypeMappings)),
	)

	return nil
}

// Helper methods

func (ns *NormalizationService) initializeFieldMappers() {
	// Standard field mappers
	ns.fieldMappers["camelCase"] = func(fieldName string) string {
		// Convert snake_case to camelCase
		parts := strings.Split(fieldName, "_")
		if len(parts) == 1 {
			return strings.ToLower(parts[0])
		}
		
		result := strings.ToLower(parts[0])
		for i := 1; i < len(parts); i++ {
			if len(parts[i]) > 0 {
				result += strings.ToUpper(parts[i][:1]) + strings.ToLower(parts[i][1:])
			}
		}
		return result
	}

	ns.fieldMappers["snake_case"] = func(fieldName string) string {
		// Convert camelCase to snake_case
		re := regexp.MustCompile(`([a-z0-9])([A-Z])`)
		return strings.ToLower(re.ReplaceAllString(fieldName, "${1}_${2}"))
	}

	ns.fieldMappers["lowercase"] = func(fieldName string) string {
		return strings.ToLower(fieldName)
	}
}

func (ns *NormalizationService) initializeValueNormalizers() {
	// String normalizer
	ns.valueNormalizers["string"] = func(value interface{}) (interface{}, error) {
		if str, ok := value.(string); ok {
			return ns.normalizeStringValue(str), nil
		}
		return value, nil
	}

	// Email normalizer
	ns.valueNormalizers["email"] = func(value interface{}) (interface{}, error) {
		if str, ok := value.(string); ok {
			return ns.normalizeEmail(str), nil
		}
		return value, nil
	}

	// URL normalizer
	ns.valueNormalizers["url"] = func(value interface{}) (interface{}, error) {
		if str, ok := value.(string); ok {
			return ns.normalizeURL(str), nil
		}
		return value, nil
	}

	// Domain normalizer
	ns.valueNormalizers["domain"] = func(value interface{}) (interface{}, error) {
		if str, ok := value.(string); ok {
			return ns.normalizeDomain(str), nil
		}
		return value, nil
	}
}

func (ns *NormalizationService) initializeTimestampParsers() {
	ns.timestampParsers = []TimestampParser{
		{Format: "rfc3339", Layout: time.RFC3339, Priority: 1},
		{Format: "rfc3339nano", Layout: time.RFC3339Nano, Priority: 2},
		{Format: "iso8601", Layout: "2006-01-02T15:04:05Z", Priority: 3},
		{Format: "datetime", Layout: "2006-01-02 15:04:05", Priority: 4},
		{Format: "syslog", Layout: "Jan 2 15:04:05 2006", Priority: 5},
		{Format: "apache", Layout: "02/Jan/2006:15:04:05 -0700", Priority: 6},
		{Format: "nginx", Layout: "2006/01/02 15:04:05", Priority: 7},
	}
}

func (ns *NormalizationService) normalizeFieldName(fieldName string) string {
	// Apply case normalization
	switch ns.config.CaseNormalization {
	case "lower":
		fieldName = strings.ToLower(fieldName)
	case "upper":
		fieldName = strings.ToUpper(fieldName)
	}

	// Remove special characters and normalize to snake_case
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	fieldName = re.ReplaceAllString(fieldName, "_")
	
	// Remove multiple underscores
	re = regexp.MustCompile(`_+`)
	fieldName = re.ReplaceAllString(fieldName, "_")
	
	// Trim leading/trailing underscores
	fieldName = strings.Trim(fieldName, "_")

	return fieldName
}

func (ns *NormalizationService) normalizeStringValue(value string) string {
	if ns.config.TrimWhitespace {
		value = strings.TrimSpace(value)
	}

	// Apply case normalization
	switch ns.config.CaseNormalization {
	case "lower":
		value = strings.ToLower(value)
	case "upper":
		value = strings.ToUpper(value)
	}

	return value
}

func (ns *NormalizationService) normalizeIP(ip string) (string, error) {
	// Parse IP address
	parsedIP := net.ParseIP(strings.TrimSpace(ip))
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if private IP addresses are allowed
	if !ns.config.IPAllowPrivate && ns.isPrivateIP(parsedIP) {
		return "", fmt.Errorf("private IP address not allowed: %s", ip)
	}

	// Check if loopback addresses are allowed
	if !ns.config.IPAllowLoopback && parsedIP.IsLoopback() {
		return "", fmt.Errorf("loopback IP address not allowed: %s", ip)
	}

	// Convert to string representation
	return parsedIP.String(), nil
}

func (ns *NormalizationService) normalizeEmail(email string) string {
	if !ns.config.NormalizeEmails {
		return email
	}

	email = strings.TrimSpace(strings.ToLower(email))
	
	// Basic email validation and normalization
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email // Invalid email, return as-is
	}

	localPart := parts[0]
	domain := ns.normalizeDomain(parts[1])

	// Remove dots from Gmail addresses (common normalization)
	if domain == "gmail.com" || domain == "googlemail.com" {
		localPart = strings.ReplaceAll(localPart, ".", "")
		// Remove plus addressing
		if plusIndex := strings.Index(localPart, "+"); plusIndex != -1 {
			localPart = localPart[:plusIndex]
		}
	}

	return localPart + "@" + domain
}

func (ns *NormalizationService) normalizeURL(url string) string {
	if !ns.config.NormalizeURLs {
		return url
	}

	url = strings.TrimSpace(strings.ToLower(url))
	
	// Remove trailing slash
	if strings.HasSuffix(url, "/") && len(url) > 1 {
		url = strings.TrimSuffix(url, "/")
	}

	// Normalize protocol
	if strings.HasPrefix(url, "https://") {
		return url
	} else if strings.HasPrefix(url, "http://") {
		return url
	} else if !strings.Contains(url, "://") {
		// Assume https for domain-only URLs
		return "https://" + url
	}

	return url
}

func (ns *NormalizationService) normalizeDomain(domain string) string {
	if !ns.config.NormalizeDomains {
		return domain
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")
	
	// Convert internationalized domain names to ASCII
	// This would require punycode implementation in a real system
	
	return domain
}

func (ns *NormalizationService) normalizeIPsInMap(data map[string]interface{}) {
	for key, value := range data {
		switch v := value.(type) {
		case string:
			if ns.looksLikeIP(v) {
				if normalizedIP, err := ns.normalizeIP(v); err == nil {
					data[key] = normalizedIP
				}
			}
		case map[string]interface{}:
			ns.normalizeIPsInMap(v)
		case []interface{}:
			for i, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					ns.normalizeIPsInMap(itemMap)
				} else if itemStr, ok := item.(string); ok && ns.looksLikeIP(itemStr) {
					if normalizedIP, err := ns.normalizeIP(itemStr); err == nil {
						v[i] = normalizedIP
					}
				}
			}
		}
	}
}

func (ns *NormalizationService) normalizeValuesInMap(data map[string]interface{}) {
	for key, value := range data {
		switch v := value.(type) {
		case string:
			// Apply value-specific normalizations
			if strings.Contains(strings.ToLower(key), "email") {
				data[key] = ns.normalizeEmail(v)
			} else if strings.Contains(strings.ToLower(key), "url") {
				data[key] = ns.normalizeURL(v)
			} else if strings.Contains(strings.ToLower(key), "domain") {
				data[key] = ns.normalizeDomain(v)
			} else {
				data[key] = ns.normalizeStringValue(v)
			}
		case map[string]interface{}:
			ns.normalizeValuesInMap(v)
		case []interface{}:
			for i, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					ns.normalizeValuesInMap(itemMap)
				} else if itemStr, ok := item.(string); ok {
					v[i] = ns.normalizeStringValue(itemStr)
				}
			}
		}
	}
}

func (ns *NormalizationService) extractTimestampFromPayload(payload map[string]interface{}) (time.Time, bool) {
	// Common timestamp field names
	timestampFields := []string{
		"timestamp", "time", "event_time", "occurred_at", "created_at",
		"datetime", "date_time", "@timestamp", "eventTime", "logTime",
	}

	for _, field := range timestampFields {
		if value, exists := payload[field]; exists {
			if timestamp, ok := ns.parseTimestamp(value); ok {
				return timestamp, true
			}
		}
	}

	return time.Time{}, false
}

func (ns *NormalizationService) parseTimestamp(value interface{}) (time.Time, bool) {
	switch v := value.(type) {
	case string:
		// Try each timestamp format
		for _, parser := range ns.timestampParsers {
			if timestamp, err := time.Parse(parser.Layout, v); err == nil {
				return timestamp, true
			}
		}
	case int64:
		// Unix timestamp
		if v > 1000000000 && v < 10000000000 { // Reasonable range for Unix timestamps
			return time.Unix(v, 0), true
		}
		// Unix timestamp in milliseconds
		if v > 1000000000000 && v < 10000000000000 {
			return time.Unix(v/1000, (v%1000)*1000000), true
		}
	case float64:
		// Unix timestamp as float
		if v > 1000000000 && v < 10000000000 {
			return time.Unix(int64(v), 0), true
		}
	}

	return time.Time{}, false
}

func (ns *NormalizationService) validateTimestampConsistency(event *entity.Event) error {
	now := time.Now()

	// Event should not be too far in the future
	if event.OccurredAt.After(now.Add(1 * time.Hour)) {
		return fmt.Errorf("event occurred_at is too far in the future")
	}

	// Received time should be after occurred time (allowing for clock skew)
	if !event.ReceivedAt.IsZero() && event.ReceivedAt.Before(event.OccurredAt.Add(-5*time.Minute)) {
		return fmt.Errorf("received_at is before occurred_at")
	}

	return nil
}

func (ns *NormalizationService) isPrivateIP(ip net.IP) bool {
	// IPv4 private ranges
	if ip.To4() != nil {
		return ip.IsPrivate()
	}
	
	// IPv6 unique local addresses
	if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
		return true
	}

	return false
}

func (ns *NormalizationService) looksLikeIP(value string) bool {
	// Simple heuristic to check if a string looks like an IP address
	return net.ParseIP(value) != nil
}

func (ns *NormalizationService) getSourceSpecificMappings(source string) map[string]string {
	mappings := make(map[string]string)

	// Source-specific field mappings
	switch strings.ToLower(source) {
	case "apache", "nginx":
		mappings["remote_addr"] = "source_ip"
		mappings["request_uri"] = "url"
		mappings["user_agent"] = "user_agent"
		mappings["status"] = "http_status"
	case "firewall", "pfsense", "iptables":
		mappings["src"] = "source_ip"
		mappings["dst"] = "destination_ip"
		mappings["sport"] = "source_port"
		mappings["dport"] = "destination_port"
		mappings["proto"] = "protocol"
	case "windows", "sysmon":
		mappings["EventID"] = "event_id"
		mappings["ProcessName"] = "process_name"
		mappings["CommandLine"] = "command_line"
		mappings["User"] = "username"
	case "syslog", "rsyslog":
		mappings["facility"] = "syslog_facility"
		mappings["priority"] = "syslog_priority"
		mappings["program"] = "process_name"
	}

	return mappings
}

func (ns *NormalizationService) getEventTypeSpecificMappings(eventType types.EventType) map[string]string {
	mappings := make(map[string]string)

	// Event type-specific field mappings
	switch eventType {
	case types.EventTypeAuthentication:
		mappings["login"] = "username"
		mappings["user"] = "username"
		mappings["account"] = "username"
		mappings["client_ip"] = "source_ip"
		mappings["remote_ip"] = "source_ip"
	case types.EventTypeNetworkAccess:
		mappings["src_ip"] = "source_ip"
		mappings["dst_ip"] = "destination_ip"
		mappings["src_port"] = "source_port"
		mappings["dst_port"] = "destination_port"
	case types.EventTypeThreatDetection:
		mappings["threat_name"] = "threat_type"
		mappings["malware_name"] = "threat_type"
		mappings["signature"] = "rule_name"
		mappings["rule"] = "rule_name"
	}

	return mappings
}