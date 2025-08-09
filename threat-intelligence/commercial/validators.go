package commercial

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// CommercialDataValidator validates commercial threat intelligence data
type CommercialDataValidator struct {
	logger         *zap.Logger
	config         *CommercialFeedsConfig
	
	// Validation components
	stixValidator    *STIXValidator
	licenseChecker   *LicenseChecker
	qualityChecker   *DataQualityChecker
	
	// Validation rules and patterns
	validationRules  map[string]*ValidationRule
	compiledPatterns map[string]*regexp.Regexp
}

// ValidationRule defines a validation rule for threat intelligence data
type ValidationRule struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Pattern     string                 `json:"pattern,omitempty"`
	Required    bool                   `json:"required"`
	MinLength   int                    `json:"min_length,omitempty"`
	MaxLength   int                    `json:"max_length,omitempty"`
	AllowedValues []string             `json:"allowed_values,omitempty"`
	CustomCheck func(interface{}) bool `json:"-"`
}

// ValidationResult contains the result of data validation
type ValidationResult struct {
	Valid        bool                   `json:"valid"`
	Errors       []ValidationError      `json:"errors"`
	Warnings     []ValidationWarning    `json:"warnings"`
	Score        float64                `json:"score"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type ValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Rule        string `json:"rule"`
	Value       string `json:"value,omitempty"`
}

type ValidationWarning struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion,omitempty"`
	Rule        string `json:"rule"`
}

// STIXValidator validates STIX 2.1 format compliance
type STIXValidator struct {
	logger      *zap.Logger
	
	// STIX validation rules
	requiredFields    map[string][]string
	patternValidators map[string]*regexp.Regexp
}

// LicenseChecker validates licensing and usage compliance
type LicenseChecker struct {
	logger      *zap.Logger
	config      *CommercialFeedsConfig
	
	// License tracking
	providerLicenses map[string]*ProviderLicense
	usageTracker     *UsageTracker
}

type ProviderLicense struct {
	Provider        string    `json:"provider"`
	LicenseType     string    `json:"license_type"`
	MaxIndicators   int64     `json:"max_indicators"`
	MaxAPIRequests  int64     `json:"max_api_requests"`
	ExpirationDate  time.Time `json:"expiration_date"`
	Restrictions    []string  `json:"restrictions"`
	AllowedUses     []string  `json:"allowed_uses"`
}

type UsageTracker struct {
	IndicatorsUsed map[string]int64 `json:"indicators_used"`
	APIRequestsUsed map[string]int64 `json:"api_requests_used"`
	LastReset      time.Time         `json:"last_reset"`
}

// DataQualityChecker assesses the quality of threat intelligence data
type DataQualityChecker struct {
	logger      *zap.Logger
	config      *CommercialFeedsConfig
	
	// Quality metrics
	qualityWeights map[string]float64
	qualityRules   map[string]QualityRule
}

type QualityRule struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Threshold   float64 `json:"threshold"`
	CheckFunc   func(RawIndicator) float64 `json:"-"`
}

// NewCommercialDataValidator creates a new commercial data validator
func NewCommercialDataValidator(logger *zap.Logger, config *CommercialFeedsConfig) (*CommercialDataValidator, error) {
	validator := &CommercialDataValidator{
		logger:           logger.With(zap.String("component", "commercial-data-validator")),
		config:           config,
		validationRules:  make(map[string]*ValidationRule),
		compiledPatterns: make(map[string]*regexp.Regexp),
	}
	
	// Initialize sub-validators
	var err error
	validator.stixValidator, err = NewSTIXValidator(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize STIX validator: %w", err)
	}
	
	validator.licenseChecker, err = NewLicenseChecker(logger, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize license checker: %w", err)
	}
	
	validator.qualityChecker, err = NewDataQualityChecker(logger, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize quality checker: %w", err)
	}
	
	// Initialize validation rules
	if err := validator.initializeValidationRules(); err != nil {
		return nil, fmt.Errorf("failed to initialize validation rules: %w", err)
	}
	
	logger.Info("Commercial data validator initialized")
	return validator, nil
}

func (cdv *CommercialDataValidator) initializeValidationRules() error {
	// Define validation rules for different indicator types
	rules := map[string]*ValidationRule{
		"ipv4": {
			Name:     "IPv4 Address Validation",
			Type:     "format",
			Required: true,
			CustomCheck: func(value interface{}) bool {
				if str, ok := value.(string); ok {
					return net.ParseIP(str) != nil && strings.Contains(str, ".")
				}
				return false
			},
		},
		"ipv6": {
			Name:     "IPv6 Address Validation",
			Type:     "format",
			Required: true,
			CustomCheck: func(value interface{}) bool {
				if str, ok := value.(string); ok {
					return net.ParseIP(str) != nil && strings.Contains(str, ":")
				}
				return false
			},
		},
		"domain": {
			Name:      "Domain Name Validation",
			Type:      "format",
			Required:  true,
			MinLength: 3,
			MaxLength: 253,
			Pattern:   `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`,
		},
		"url": {
			Name:     "URL Validation",
			Type:     "format",
			Required: true,
			CustomCheck: func(value interface{}) bool {
				if str, ok := value.(string); ok {
					_, err := url.Parse(str)
					return err == nil
				}
				return false
			},
		},
		"hash_md5": {
			Name:      "MD5 Hash Validation",
			Type:      "format",
			Required:  true,
			MinLength: 32,
			MaxLength: 32,
			Pattern:   `^[a-fA-F0-9]{32}$`,
		},
		"hash_sha1": {
			Name:      "SHA1 Hash Validation",
			Type:      "format",
			Required:  true,
			MinLength: 40,
			MaxLength: 40,
			Pattern:   `^[a-fA-F0-9]{40}$`,
		},
		"hash_sha256": {
			Name:      "SHA256 Hash Validation",
			Type:      "format",
			Required:  true,
			MinLength: 64,
			MaxLength: 64,
			Pattern:   `^[a-fA-F0-9]{64}$`,
		},
		"email": {
			Name:    "Email Address Validation",
			Type:    "format",
			Required: true,
			Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
		},
		"confidence": {
			Name:     "Confidence Score Validation",
			Type:     "range",
			Required: true,
			CustomCheck: func(value interface{}) bool {
				if f, ok := value.(float64); ok {
					return f >= 0.0 && f <= 1.0
				}
				return false
			},
		},
	}
	
	// Compile regex patterns
	for name, rule := range rules {
		cdv.validationRules[name] = rule
		if rule.Pattern != "" {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return fmt.Errorf("failed to compile pattern for rule %s: %w", name, err)
			}
			cdv.compiledPatterns[name] = compiled
		}
	}
	
	return nil
}

// ValidateIndicators validates a batch of raw indicators
func (cdv *CommercialDataValidator) ValidateIndicators(indicators []RawIndicator) ([]RawIndicator, error) {
	var validIndicators []RawIndicator
	var validationErrors []error
	
	for i, indicator := range indicators {
		result := cdv.ValidateIndicator(indicator)
		
		if result.Valid {
			validIndicators = append(validIndicators, indicator)
		} else {
			cdv.logger.Debug("Indicator validation failed",
				zap.Int("index", i),
				zap.String("provider", indicator.Provider),
				zap.String("type", indicator.Type),
				zap.String("value", indicator.Value),
				zap.Int("error_count", len(result.Errors)),
			)
			
			// Collect validation errors
			for _, err := range result.Errors {
				validationErrors = append(validationErrors, fmt.Errorf("indicator %d: %s", i, err.Message))
			}
		}
	}
	
	cdv.logger.Info("Indicator validation completed",
		zap.Int("total_indicators", len(indicators)),
		zap.Int("valid_indicators", len(validIndicators)),
		zap.Int("validation_errors", len(validationErrors)),
	)
	
	return validIndicators, nil
}

// ValidateIndicator validates a single raw indicator
func (cdv *CommercialDataValidator) ValidateIndicator(indicator RawIndicator) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Score:    1.0,
		Metadata: make(map[string]interface{}),
	}
	
	// Validate basic required fields
	cdv.validateRequiredFields(indicator, result)
	
	// Validate indicator format based on type
	cdv.validateIndicatorFormat(indicator, result)
	
	// Validate confidence score
	cdv.validateConfidence(indicator, result)
	
	// Validate timestamps
	cdv.validateTimestamps(indicator, result)
	
	// Check license compliance
	cdv.licenseChecker.ValidateLicenseCompliance(indicator, result)
	
	// Assess data quality
	qualityScore := cdv.qualityChecker.AssessQuality(indicator)
	result.Metadata["quality_score"] = qualityScore
	
	// Calculate overall validation score
	result.Score = cdv.calculateValidationScore(result, qualityScore)
	
	// Determine if indicator is valid based on errors and score
	result.Valid = len(result.Errors) == 0 && result.Score >= cdv.config.RequiredConfidence
	
	return result
}

func (cdv *CommercialDataValidator) validateRequiredFields(indicator RawIndicator, result *ValidationResult) {
	if indicator.Provider == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "provider",
			Message:  "Provider is required",
			Severity: "error",
			Rule:     "required_fields",
		})
	}
	
	if indicator.Type == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "type",
			Message:  "Indicator type is required",
			Severity: "error",
			Rule:     "required_fields",
		})
	}
	
	if indicator.Value == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "value",
			Message:  "Indicator value is required",
			Severity: "error",
			Rule:     "required_fields",
		})
	}
}

func (cdv *CommercialDataValidator) validateIndicatorFormat(indicator RawIndicator, result *ValidationResult) {
	indicatorType := strings.ToLower(indicator.Type)
	value := strings.TrimSpace(indicator.Value)
	
	switch indicatorType {
	case "ipv4-addr", "ip":
		if rule, exists := cdv.validationRules["ipv4"]; exists {
			if !rule.CustomCheck(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid IPv4 address format",
					Severity: "error",
					Rule:     "ipv4_format",
					Value:    value,
				})
			}
		}
	case "ipv6-addr":
		if rule, exists := cdv.validationRules["ipv6"]; exists {
			if !rule.CustomCheck(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid IPv6 address format",
					Severity: "error",
					Rule:     "ipv6_format",
					Value:    value,
				})
			}
		}
	case "domain-name", "domain":
		if pattern, exists := cdv.compiledPatterns["domain"]; exists {
			if !pattern.MatchString(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid domain name format",
					Severity: "error",
					Rule:     "domain_format",
					Value:    value,
				})
			}
		}
	case "url":
		if rule, exists := cdv.validationRules["url"]; exists {
			if !rule.CustomCheck(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid URL format",
					Severity: "error",
					Rule:     "url_format",
					Value:    value,
				})
			}
		}
	case "file":
		// Validate hash formats
		cdv.validateHashFormat(value, result)
	case "email-addr", "email":
		if pattern, exists := cdv.compiledPatterns["email"]; exists {
			if !pattern.MatchString(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid email address format",
					Severity: "error",
					Rule:     "email_format",
					Value:    value,
				})
			}
		}
	}
}

func (cdv *CommercialDataValidator) validateHashFormat(value string, result *ValidationResult) {
	value = strings.ToLower(strings.TrimSpace(value))
	
	switch len(value) {
	case 32:
		if pattern, exists := cdv.compiledPatterns["hash_md5"]; exists {
			if !pattern.MatchString(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid MD5 hash format",
					Severity: "error",
					Rule:     "hash_md5_format",
					Value:    value,
				})
			}
		}
	case 40:
		if pattern, exists := cdv.compiledPatterns["hash_sha1"]; exists {
			if !pattern.MatchString(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid SHA1 hash format",
					Severity: "error",
					Rule:     "hash_sha1_format",
					Value:    value,
				})
			}
		}
	case 64:
		if pattern, exists := cdv.compiledPatterns["hash_sha256"]; exists {
			if !pattern.MatchString(value) {
				result.Errors = append(result.Errors, ValidationError{
					Field:    "value",
					Message:  "Invalid SHA256 hash format",
					Severity: "error",
					Rule:     "hash_sha256_format",
					Value:    value,
				})
			}
		}
	default:
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "value",
			Message:    "Hash length does not match common formats (MD5/SHA1/SHA256)",
			Suggestion: "Verify hash type and format",
			Rule:       "hash_length_check",
		})
	}
}

func (cdv *CommercialDataValidator) validateConfidence(indicator RawIndicator, result *ValidationResult) {
	if rule, exists := cdv.validationRules["confidence"]; exists {
		if !rule.CustomCheck(indicator.Confidence) {
			result.Errors = append(result.Errors, ValidationError{
				Field:    "confidence",
				Message:  "Confidence must be between 0.0 and 1.0",
				Severity: "error",
				Rule:     "confidence_range",
				Value:    fmt.Sprintf("%.2f", indicator.Confidence),
			})
		}
	}
	
	// Warning for low confidence indicators
	if indicator.Confidence < 0.5 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "confidence",
			Message:    "Low confidence indicator",
			Suggestion: "Consider additional validation or filtering",
			Rule:       "confidence_threshold",
		})
	}
}

func (cdv *CommercialDataValidator) validateTimestamps(indicator RawIndicator, result *ValidationResult) {
	now := time.Now()
	
	// Check if FirstSeen is not in the future
	if indicator.FirstSeen.After(now) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "first_seen",
			Message:  "FirstSeen timestamp cannot be in the future",
			Severity: "error",
			Rule:     "timestamp_validation",
			Value:    indicator.FirstSeen.Format(time.RFC3339),
		})
	}
	
	// Check if LastSeen is not in the future
	if indicator.LastSeen.After(now) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "last_seen",
			Message:  "LastSeen timestamp cannot be in the future",
			Severity: "error",
			Rule:     "timestamp_validation",
			Value:    indicator.LastSeen.Format(time.RFC3339),
		})
	}
	
	// Check if LastSeen is after FirstSeen
	if indicator.LastSeen.Before(indicator.FirstSeen) {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "last_seen",
			Message:  "LastSeen must be after or equal to FirstSeen",
			Severity: "error",
			Rule:     "timestamp_ordering",
		})
	}
	
	// Warning for very old indicators
	if cdv.config.MaxIndicatorAge > 0 && now.Sub(indicator.LastSeen) > cdv.config.MaxIndicatorAge {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:      "last_seen",
			Message:    "Indicator is older than maximum allowed age",
			Suggestion: "Consider filtering or marking as stale",
			Rule:       "indicator_age",
		})
	}
}

func (cdv *CommercialDataValidator) calculateValidationScore(result *ValidationResult, qualityScore float64) float64 {
	baseScore := 1.0
	
	// Reduce score for each error
	errorPenalty := float64(len(result.Errors)) * 0.2
	baseScore -= errorPenalty
	
	// Small reduction for warnings
	warningPenalty := float64(len(result.Warnings)) * 0.05
	baseScore -= warningPenalty
	
	// Factor in quality score (weighted at 30%)
	finalScore := (baseScore * 0.7) + (qualityScore * 0.3)
	
	// Ensure score is between 0 and 1
	if finalScore < 0 {
		finalScore = 0
	}
	if finalScore > 1 {
		finalScore = 1
	}
	
	return finalScore
}

// NewSTIXValidator creates a new STIX validator
func NewSTIXValidator(logger *zap.Logger) (*STIXValidator, error) {
	validator := &STIXValidator{
		logger:            logger.With(zap.String("component", "stix-validator")),
		requiredFields:    make(map[string][]string),
		patternValidators: make(map[string]*regexp.Regexp),
	}
	
	// Initialize STIX validation rules
	validator.requiredFields["indicator"] = []string{"type", "pattern", "labels"}
	
	return validator, nil
}

// NewLicenseChecker creates a new license checker
func NewLicenseChecker(logger *zap.Logger, config *CommercialFeedsConfig) (*LicenseChecker, error) {
	checker := &LicenseChecker{
		logger:           logger.With(zap.String("component", "license-checker")),
		config:           config,
		providerLicenses: make(map[string]*ProviderLicense),
		usageTracker: &UsageTracker{
			IndicatorsUsed:  make(map[string]int64),
			APIRequestsUsed: make(map[string]int64),
			LastReset:       time.Now(),
		},
	}
	
	return checker, nil
}

func (lc *LicenseChecker) ValidateLicenseCompliance(indicator RawIndicator, result *ValidationResult) {
	// This is a placeholder for license validation logic
	// In a real implementation, this would check against actual license terms
	result.Metadata["license_compliant"] = true
}

// NewDataQualityChecker creates a new data quality checker
func NewDataQualityChecker(logger *zap.Logger, config *CommercialFeedsConfig) (*DataQualityChecker, error) {
	checker := &DataQualityChecker{
		logger:         logger.With(zap.String("component", "data-quality-checker")),
		config:         config,
		qualityWeights: make(map[string]float64),
		qualityRules:   make(map[string]QualityRule),
	}
	
	// Initialize quality rules
	checker.initializeQualityRules()
	
	return checker, nil
}

func (dqc *DataQualityChecker) initializeQualityRules() {
	dqc.qualityRules["confidence"] = QualityRule{
		Name:      "Confidence Score",
		Weight:    0.3,
		Threshold: 0.7,
		CheckFunc: func(indicator RawIndicator) float64 {
			return indicator.Confidence
		},
	}
	
	dqc.qualityRules["freshness"] = QualityRule{
		Name:      "Data Freshness",
		Weight:    0.2,
		Threshold: 0.8,
		CheckFunc: func(indicator RawIndicator) float64 {
			age := time.Since(indicator.LastSeen)
			if age < 24*time.Hour {
				return 1.0
			} else if age < 7*24*time.Hour {
				return 0.8
			} else if age < 30*24*time.Hour {
				return 0.6
			} else {
				return 0.3
			}
		},
	}
	
	dqc.qualityRules["context_richness"] = QualityRule{
		Name:      "Context Richness",
		Weight:    0.2,
		Threshold: 0.5,
		CheckFunc: func(indicator RawIndicator) float64 {
			score := 0.0
			if len(indicator.Tags) > 0 {
				score += 0.3
			}
			if len(indicator.Context) > 0 {
				score += 0.4
			}
			if len(indicator.Metadata) > 0 {
				score += 0.3
			}
			return score
		},
	}
}

func (dqc *DataQualityChecker) AssessQuality(indicator RawIndicator) float64 {
	totalScore := 0.0
	totalWeight := 0.0
	
	for _, rule := range dqc.qualityRules {
		score := rule.CheckFunc(indicator)
		totalScore += score * rule.Weight
		totalWeight += rule.Weight
	}
	
	if totalWeight == 0 {
		return 0.5 // Default score
	}
	
	return totalScore / totalWeight
}