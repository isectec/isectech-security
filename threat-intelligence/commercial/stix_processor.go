package commercial

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// STIXProcessor handles conversion of raw indicators to STIX 2.1 format
type STIXProcessor struct {
	logger *zap.Logger
	config *CommercialFeedsConfig
	
	// STIX configuration
	stixVersion      string
	specVersion      string
	identityID       string
	organizationName string
}

// STIX 2.1 objects
type STIXBundle struct {
	Type         string      `json:"type"`
	ID           string      `json:"id"`
	SpecVersion  string      `json:"spec_version"`
	Objects      []STIXObject `json:"objects"`
	CreatedAt    time.Time   `json:"created"`
	ModifiedAt   time.Time   `json:"modified"`
}

type STIXObject interface {
	GetType() string
	GetID() string
}

type STIXIndicatorObject struct {
	Type              string                 `json:"type"`
	SpecVersion       string                 `json:"spec_version"`
	ID                string                 `json:"id"`
	CreatedBy         string                 `json:"created_by_ref"`
	Created           time.Time              `json:"created"`
	Modified          time.Time              `json:"modified"`
	Pattern           string                 `json:"pattern"`
	PatternType       string                 `json:"pattern_type"`
	PatternVersion    string                 `json:"pattern_version,omitempty"`
	ValidFrom         time.Time              `json:"valid_from"`
	ValidUntil        time.Time              `json:"valid_until,omitempty"`
	Labels            []string               `json:"labels"`
	Confidence        int                    `json:"confidence,omitempty"`
	Lang              string                 `json:"lang,omitempty"`
	ExternalReferences []STIXExternalReference `json:"external_references,omitempty"`
	ObjectMarkingRefs []string               `json:"object_marking_refs,omitempty"`
	GranularMarkings  []STIXGranularMarking  `json:"granular_markings,omitempty"`
	CustomProperties  map[string]interface{} `json:"x_isectech_properties,omitempty"`
}

type STIXIdentityObject struct {
	Type         string    `json:"type"`
	SpecVersion  string    `json:"spec_version"`
	ID           string    `json:"id"`
	Created      time.Time `json:"created"`
	Modified     time.Time `json:"modified"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	IdentityClass string   `json:"identity_class"`
	Sectors      []string  `json:"sectors,omitempty"`
	ContactInfo  string    `json:"contact_information,omitempty"`
}

type STIXExternalReference struct {
	SourceName  string `json:"source_name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

type STIXGranularMarking struct {
	Lang       string   `json:"lang,omitempty"`
	MarkingRef string   `json:"marking_ref,omitempty"`
	Selectors  []string `json:"selectors"`
}

func (s *STIXIndicatorObject) GetType() string { return s.Type }
func (s *STIXIndicatorObject) GetID() string   { return s.ID }
func (s *STIXIdentityObject) GetType() string  { return s.Type }
func (s *STIXIdentityObject) GetID() string    { return s.ID }

// NewSTIXProcessor creates a new STIX processor
func NewSTIXProcessor(logger *zap.Logger, config *CommercialFeedsConfig) (*STIXProcessor, error) {
	processor := &STIXProcessor{
		logger:           logger.With(zap.String("component", "stix-processor")),
		config:           config,
		stixVersion:      "2.1",
		specVersion:      "2.1",
		identityID:       "identity--" + generateUUID(),
		organizationName: "iSECTECH Threat Intelligence",
	}
	
	logger.Info("STIX processor initialized",
		zap.String("stix_version", processor.stixVersion),
		zap.String("spec_version", processor.specVersion),
		zap.String("identity_id", processor.identityID),
	)
	
	return processor, nil
}

// ConvertToSTIX converts raw indicators to STIX 2.1 format
func (sp *STIXProcessor) ConvertToSTIX(rawIndicators []RawIndicator) ([]STIXIndicator, error) {
	var stixIndicators []STIXIndicator
	
	for _, rawIndicator := range rawIndicators {
		stixIndicator, err := sp.convertRawIndicatorToSTIX(rawIndicator)
		if err != nil {
			sp.logger.Warn("Failed to convert indicator to STIX",
				zap.String("provider", rawIndicator.Provider),
				zap.String("type", rawIndicator.Type),
				zap.String("value", rawIndicator.Value),
				zap.Error(err),
			)
			continue
		}
		
		stixIndicators = append(stixIndicators, stixIndicator)
	}
	
	sp.logger.Debug("Converted indicators to STIX format",
		zap.Int("input_count", len(rawIndicators)),
		zap.Int("output_count", len(stixIndicators)),
	)
	
	return stixIndicators, nil
}

func (sp *STIXProcessor) convertRawIndicatorToSTIX(raw RawIndicator) (STIXIndicator, error) {
	// Generate STIX pattern based on indicator type
	pattern, err := sp.generateSTIXPattern(raw.Type, raw.Value)
	if err != nil {
		return STIXIndicator{}, fmt.Errorf("failed to generate STIX pattern: %w", err)
	}
	
	// Convert confidence to integer scale (0-100)
	confidence := int(raw.Confidence * 100)
	if confidence > 100 {
		confidence = 100
	}
	
	// Determine valid until time (default to 30 days from last seen)
	validUntil := raw.LastSeen.Add(30 * 24 * time.Hour)
	if sp.config.MaxIndicatorAge > 0 {
		validUntil = raw.LastSeen.Add(sp.config.MaxIndicatorAge)
	}
	
	// Generate STIX labels from tags
	labels := sp.generateSTIXLabels(raw.Tags, raw.Type)
	
	// Generate external references
	externalRefs := sp.generateExternalReferences(raw)
	
	// Build custom properties for iSECTECH specific data
	customProps := map[string]interface{}{
		"provider":      raw.Provider,
		"original_type": raw.Type,
		"raw_tags":      raw.Tags,
		"context":       raw.Context,
		"metadata":      raw.Metadata,
		"first_seen":    raw.FirstSeen,
		"last_seen":     raw.LastSeen,
	}
	
	// Create STIX indicator object
	stixObject := &STIXIndicatorObject{
		Type:               "indicator",
		SpecVersion:        sp.specVersion,
		ID:                 sp.generateIndicatorID(raw),
		CreatedBy:          sp.identityID,
		Created:            raw.FirstSeen,
		Modified:           raw.LastSeen,
		Pattern:            pattern,
		PatternType:        "stix",
		PatternVersion:     "2.1",
		ValidFrom:          raw.FirstSeen,
		ValidUntil:         validUntil,
		Labels:             labels,
		Confidence:         confidence,
		ExternalReferences: externalRefs,
		CustomProperties:   customProps,
	}
	
	// Convert to STIXIndicator format for our system
	stixIndicator := STIXIndicator{
		ID:         stixObject.ID,
		Type:       "indicator",
		Pattern:    pattern,
		Labels:     labels,
		Confidence: confidence,
		ValidFrom:  raw.FirstSeen,
		ValidUntil: validUntil,
		Metadata:   sp.buildSTIXMetadata(raw, stixObject),
	}
	
	return stixIndicator, nil
}

func (sp *STIXProcessor) generateSTIXPattern(indicatorType, value string) (string, error) {
	// Generate STIX patterns based on indicator type
	switch strings.ToLower(indicatorType) {
	case "ipv4-addr", "ip":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", value), nil
	case "ipv6-addr":
		return fmt.Sprintf("[ipv6-addr:value = '%s']", value), nil
	case "domain-name", "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", value), nil
	case "url":
		return fmt.Sprintf("[url:value = '%s']", value), nil
	case "file":
		if sp.isHash(value) {
			hashType := sp.detectHashType(value)
			return fmt.Sprintf("[file:hashes.'%s' = '%s']", hashType, strings.ToLower(value)), nil
		}
		return fmt.Sprintf("[file:name = '%s']", value), nil
	case "email-addr", "email":
		return fmt.Sprintf("[email-addr:value = '%s']", value), nil
	case "windows-registry-key":
		return fmt.Sprintf("[windows-registry-key:key = '%s']", value), nil
	case "x509-certificate":
		return fmt.Sprintf("[x509-certificate:serial_number = '%s']", value), nil
	case "vulnerability":
		return fmt.Sprintf("[vulnerability:name = '%s']", value), nil
	default:
		// Generic pattern for unknown types
		return fmt.Sprintf("[x-isectech-custom-indicator:value = '%s' AND x-isectech-custom-indicator:type = '%s']", value, indicatorType), nil
	}
}

func (sp *STIXProcessor) isHash(value string) bool {
	// Check if value looks like a hash based on length and character set
	value = strings.ToLower(strings.TrimSpace(value))
	
	// Check for common hash formats
	switch len(value) {
	case 32: // MD5
		return sp.isHexString(value)
	case 40: // SHA1
		return sp.isHexString(value)
	case 64: // SHA256
		return sp.isHexString(value)
	case 128: // SHA512
		return sp.isHexString(value)
	default:
		return false
	}
}

func (sp *STIXProcessor) isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (sp *STIXProcessor) detectHashType(hash string) string {
	switch len(strings.TrimSpace(hash)) {
	case 32:
		return "MD5"
	case 40:
		return "SHA-1"
	case 64:
		return "SHA-256"
	case 128:
		return "SHA-512"
	default:
		return "Unknown"
	}
}

func (sp *STIXProcessor) generateSTIXLabels(tags []string, indicatorType string) []string {
	labelSet := make(map[string]bool)
	
	// Always include the indicator type as a label
	labelSet["indicator"] = true
	
	// Add type-specific labels
	switch strings.ToLower(indicatorType) {
	case "ipv4-addr", "ipv6-addr", "ip":
		labelSet["malicious-activity"] = true
	case "domain-name", "domain":
		labelSet["malicious-activity"] = true
	case "url":
		labelSet["malicious-activity"] = true
	case "file":
		labelSet["malicious-activity"] = true
	case "email-addr", "email":
		labelSet["malicious-activity"] = true
	}
	
	// Convert relevant tags to STIX labels
	for _, tag := range tags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		
		// Map common tags to STIX labels
		switch {
		case strings.Contains(tag, "malware"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "apt"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "trojan"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "botnet"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "phishing"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "c2") || strings.Contains(tag, "command"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "exploit"):
			labelSet["malicious-activity"] = true
		case strings.Contains(tag, "suspicious"):
			labelSet["anomalous-activity"] = true
		case strings.Contains(tag, "benign"):
			labelSet["benign"] = true
		}
	}
	
	// Convert set to slice
	var labels []string
	for label := range labelSet {
		labels = append(labels, label)
	}
	
	// Ensure we have at least one label
	if len(labels) == 0 {
		labels = []string{"malicious-activity"}
	}
	
	return labels
}

func (sp *STIXProcessor) generateExternalReferences(raw RawIndicator) []STIXExternalReference {
	var refs []STIXExternalReference
	
	// Add provider-specific reference
	switch raw.Provider {
	case "recorded_future":
		refs = append(refs, STIXExternalReference{
			SourceName:  "Recorded Future",
			Description: "Commercial threat intelligence from Recorded Future",
			URL:         "https://www.recordedfuture.com",
		})
	case "digital_shadows":
		refs = append(refs, STIXExternalReference{
			SourceName:  "Digital Shadows SearchLight",
			Description: "Commercial threat intelligence from Digital Shadows",
			URL:         "https://searchlight.digitalshadows.com",
		})
	case "crowdstrike":
		refs = append(refs, STIXExternalReference{
			SourceName:  "CrowdStrike Falcon Intelligence",
			Description: "Commercial threat intelligence from CrowdStrike",
			URL:         "https://www.crowdstrike.com",
		})
	case "fireeye":
		refs = append(refs, STIXExternalReference{
			SourceName:  "FireEye Threat Intelligence",
			Description: "Commercial threat intelligence from FireEye",
			URL:         "https://www.fireeye.com",
		})
	}
	
	// Add external references from metadata if available
	if portalURL, ok := raw.Metadata["portal_url"].(string); ok && portalURL != "" {
		refs = append(refs, STIXExternalReference{
			SourceName:  raw.Provider + "_portal",
			Description: fmt.Sprintf("Direct link to %s portal", raw.Provider),
			URL:         portalURL,
		})
	}
	
	return refs
}

func (sp *STIXProcessor) generateIndicatorID(raw RawIndicator) string {
	// Generate deterministic ID based on provider, type, and value
	data := fmt.Sprintf("%s:%s:%s", raw.Provider, raw.Type, raw.Value)
	hash := sha256.Sum256([]byte(data))
	return "indicator--" + hex.EncodeToString(hash[:16]) // Use first 16 bytes for UUID-like format
}

func (sp *STIXProcessor) buildSTIXMetadata(raw RawIndicator, stixObj *STIXIndicatorObject) map[string]interface{} {
	metadata := make(map[string]interface{})
	
	// Copy original metadata
	for k, v := range raw.Metadata {
		metadata[k] = v
	}
	
	// Add STIX-specific metadata
	metadata["stix_id"] = stixObj.ID
	metadata["stix_version"] = sp.stixVersion
	metadata["spec_version"] = sp.specVersion
	metadata["created_by"] = sp.identityID
	metadata["pattern_type"] = stixObj.PatternType
	
	// Add processing metadata
	metadata["processed_at"] = time.Now()
	metadata["processor_version"] = "1.0"
	
	return metadata
}

// CreateSTIXBundle creates a STIX 2.1 bundle from indicators
func (sp *STIXProcessor) CreateSTIXBundle(indicators []STIXIndicator) (*STIXBundle, error) {
	objects := make([]STIXObject, 0, len(indicators)+1)
	
	// Add identity object
	identity := &STIXIdentityObject{
		Type:          "identity",
		SpecVersion:   sp.specVersion,
		ID:            sp.identityID,
		Created:       time.Now(),
		Modified:      time.Now(),
		Name:          sp.organizationName,
		Description:   "iSECTECH Threat Intelligence Platform",
		IdentityClass: "organization",
		Sectors:       []string{"technology"},
	}
	objects = append(objects, identity)
	
	// Add indicator objects
	for _, indicator := range indicators {
		stixObj := &STIXIndicatorObject{
			Type:        indicator.Type,
			SpecVersion: sp.specVersion,
			ID:          indicator.ID,
			CreatedBy:   sp.identityID,
			Pattern:     indicator.Pattern,
			Labels:      indicator.Labels,
			Confidence:  indicator.Confidence,
			ValidFrom:   indicator.ValidFrom,
			ValidUntil:  indicator.ValidUntil,
		}
		
		// Add metadata if available
		if metadata, ok := indicator.Metadata["custom_properties"].(map[string]interface{}); ok {
			stixObj.CustomProperties = metadata
		}
		
		objects = append(objects, stixObj)
	}
	
	// Create bundle
	bundle := &STIXBundle{
		Type:        "bundle",
		ID:          "bundle--" + generateUUID(),
		SpecVersion: sp.specVersion,
		Objects:     objects,
		CreatedAt:   time.Now(),
		ModifiedAt:  time.Now(),
	}
	
	return bundle, nil
}

// ExportSTIXBundle exports a STIX bundle as JSON
func (sp *STIXProcessor) ExportSTIXBundle(bundle *STIXBundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", "  ")
}

// ValidateSTIXPattern validates a STIX pattern syntax
func (sp *STIXProcessor) ValidateSTIXPattern(pattern string) error {
	// Basic validation - check for required brackets and structure
	if !strings.HasPrefix(pattern, "[") || !strings.HasSuffix(pattern, "]") {
		return fmt.Errorf("STIX pattern must be enclosed in square brackets")
	}
	
	// Check for basic pattern structure
	content := strings.TrimSpace(pattern[1 : len(pattern)-1])
	if content == "" {
		return fmt.Errorf("STIX pattern cannot be empty")
	}
	
	// More comprehensive validation would be implemented here
	// For now, we'll accept any non-empty bracketed pattern
	
	return nil
}

// generateUUID generates a simple UUID-like string
func generateUUID() string {
	// Simple UUID generation - in production, use a proper UUID library
	timestamp := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		hash[0:4], hash[4:6], hash[6:8], hash[8:10], hash[10:16])
}