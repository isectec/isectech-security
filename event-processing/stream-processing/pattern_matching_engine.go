package stream_processing

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// PatternMatchingEngine performs threat pattern matching using rules
type PatternMatchingEngine struct {
	logger           *zap.Logger
	config           *PatternMatchingConfig
	
	// Pattern rules
	threatRules      []*ThreatRule
	customRules      []*ThreatRule
	compiledPatterns map[string]*CompiledPattern
	
	// Rule management
	ruleUpdateTicker *time.Ticker
	lastRuleUpdate   time.Time
	
	// Health and metrics
	isHealthy        bool
	mu               sync.RWMutex
	
	// Background workers
	ctx              context.Context
	cancel           context.CancelFunc
}

// PatternMatchingConfig defines configuration for pattern matching
type PatternMatchingConfig struct {
	RulesPath          string        `json:"rules_path"`
	CustomRulesPath    string        `json:"custom_rules_path"`
	UpdateInterval     time.Duration `json:"update_interval"`
	CaseSensitive      bool          `json:"case_sensitive"`
	MaxRuleComplexity  int           `json:"max_rule_complexity"`
	EnableCustomRules  bool          `json:"enable_custom_rules"`
}

// ThreatRule defines a threat detection rule
type ThreatRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	MITRE       []string               `json:"mitre_tactics,omitempty"`
	Conditions  []RuleCondition        `json:"conditions"`
	Actions     []RuleAction           `json:"actions"`
	Metadata    map[string]interface{} `json:"metadata"`
	Enabled     bool                   `json:"enabled"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Author      string                 `json:"author,omitempty"`
	Version     string                 `json:"version,omitempty"`
}

// RuleCondition defines a condition in a threat rule
type RuleCondition struct {
	Field       string      `json:"field"`
	Operator    string      `json:"operator"` // equals, contains, matches, regex, gt, lt, in, not_in
	Value       interface{} `json:"value"`
	CaseSensitive bool      `json:"case_sensitive,omitempty"`
	Weight      float64     `json:"weight"`
	Negate      bool        `json:"negate,omitempty"`
}

// RuleAction defines an action to take when a rule matches
type RuleAction struct {
	Type       string                 `json:"type"` // alert, log, block, quarantine
	Severity   string                 `json:"severity,omitempty"`
	Message    string                 `json:"message,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// CompiledPattern represents a compiled threat pattern for efficient matching
type CompiledPattern struct {
	Rule            *ThreatRule
	CompiledRegexes map[string]*regexp.Regexp
	FieldExtractors map[string]FieldExtractor
	LastUsed        time.Time
}

// FieldExtractor defines how to extract values from events
type FieldExtractor struct {
	JSONPath    string `json:"json_path,omitempty"`
	RegexGroup  int    `json:"regex_group,omitempty"`
	Transform   string `json:"transform,omitempty"` // lowercase, uppercase, trim
	DefaultValue string `json:"default_value,omitempty"`
}

// NewPatternMatchingEngine creates a new pattern matching engine
func NewPatternMatchingEngine(logger *zap.Logger, config *PatternMatchingConfig) (*PatternMatchingEngine, error) {
	if config == nil {
		return nil, fmt.Errorf("pattern matching configuration is required")
	}
	
	// Set defaults
	if config.UpdateInterval == 0 {
		config.UpdateInterval = 5 * time.Minute
	}
	if config.MaxRuleComplexity == 0 {
		config.MaxRuleComplexity = 100
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	engine := &PatternMatchingEngine{
		logger:           logger.With(zap.String("component", "pattern-matching-engine")),
		config:           config,
		threatRules:      []*ThreatRule{},
		customRules:      []*ThreatRule{},
		compiledPatterns: make(map[string]*CompiledPattern),
		isHealthy:        true,
		ctx:              ctx,
		cancel:           cancel,
	}
	
	// Load initial rules
	if err := engine.loadRules(); err != nil {
		logger.Warn("Failed to load initial rules", zap.Error(err))
	}
	
	// Start rule update ticker
	if config.UpdateInterval > 0 {
		engine.ruleUpdateTicker = time.NewTicker(config.UpdateInterval)
		go engine.runRuleUpdates()
	}
	
	logger.Info("Pattern matching engine initialized",
		zap.String("rules_path", config.RulesPath),
		zap.String("custom_rules_path", config.CustomRulesPath),
		zap.Duration("update_interval", config.UpdateInterval),
		zap.Int("loaded_rules", len(engine.threatRules)+len(engine.customRules)),
	)
	
	return engine, nil
}

// MatchPatterns matches an event against all loaded threat patterns
func (e *PatternMatchingEngine) MatchPatterns(ctx context.Context, event map[string]interface{}) ([]PatternMatch, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	
	start := time.Now()
	var matches []PatternMatch
	
	// Match against threat rules
	for _, rule := range e.threatRules {
		if !rule.Enabled {
			continue
		}
		
		if match := e.matchRule(rule, event); match != nil {
			matches = append(matches, *match)
		}
	}
	
	// Match against custom rules if enabled
	if e.config.EnableCustomRules {
		for _, rule := range e.customRules {
			if !rule.Enabled {
				continue
			}
			
			if match := e.matchRule(rule, event); match != nil {
				matches = append(matches, *match)
			}
		}
	}
	
	duration := time.Since(start)
	
	e.logger.Debug("Pattern matching completed",
		zap.Int("total_rules", len(e.threatRules)+len(e.customRules)),
		zap.Int("matches", len(matches)),
		zap.Duration("duration", duration),
	)
	
	return matches, nil
}

// matchRule matches an event against a specific rule
func (e *PatternMatchingEngine) matchRule(rule *ThreatRule, event map[string]interface{}) *PatternMatch {
	// Get or compile pattern
	pattern := e.getCompiledPattern(rule)
	if pattern == nil {
		return nil
	}
	
	// Evaluate all conditions
	conditionResults := make([]bool, len(rule.Conditions))
	totalWeight := 0.0
	matchedWeight := 0.0
	
	for i, condition := range rule.Conditions {
		result := e.evaluateCondition(condition, event, pattern)
		conditionResults[i] = result
		totalWeight += condition.Weight
		
		if result {
			matchedWeight += condition.Weight
		}
	}
	
	// Determine if rule matches
	var isMatch bool
	if totalWeight > 0 {
		// Weighted matching - need at least 70% of weight to match
		isMatch = (matchedWeight / totalWeight) >= 0.7
	} else {
		// All conditions must match if no weights specified
		isMatch = true
		for _, result := range conditionResults {
			if !result {
				isMatch = false
				break
			}
		}
	}
	
	if !isMatch {
		return nil
	}
	
	// Update pattern usage
	pattern.LastUsed = time.Now()
	
	// Create pattern match
	match := &PatternMatch{
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		Confidence:  rule.Confidence,
		Severity:    rule.Severity,
		Category:    rule.Category,
		Description: rule.Description,
		Metadata: map[string]interface{}{
			"rule_version":      rule.Version,
			"rule_author":       rule.Author,
			"mitre_tactics":     rule.MITRE,
			"matched_conditions": conditionResults,
			"match_score":       matchedWeight / totalWeight,
			"rule_metadata":     rule.Metadata,
		},
	}
	
	return match
}

// evaluateCondition evaluates a single rule condition against an event
func (e *PatternMatchingEngine) evaluateCondition(condition RuleCondition, event map[string]interface{}, pattern *CompiledPattern) bool {
	// Extract field value
	fieldValue := e.extractFieldValue(condition.Field, event, pattern)
	if fieldValue == nil && condition.Value != nil {
		return condition.Negate // If field doesn't exist, only match if we're negating
	}
	
	// Convert values to strings for comparison
	fieldStr := fmt.Sprintf("%v", fieldValue)
	valueStr := fmt.Sprintf("%v", condition.Value)
	
	// Apply case sensitivity
	if !condition.CaseSensitive && !e.config.CaseSensitive {
		fieldStr = strings.ToLower(fieldStr)
		valueStr = strings.ToLower(valueStr)
	}
	
	var result bool
	
	// Evaluate based on operator
	switch condition.Operator {
	case "equals":
		result = fieldStr == valueStr
	case "contains":
		result = strings.Contains(fieldStr, valueStr)
	case "matches":
		result = e.matchesPattern(fieldStr, valueStr)
	case "regex":
		result = e.matchesRegex(fieldStr, valueStr, pattern, condition.Field)
	case "gt":
		result = e.compareNumbers(fieldValue, condition.Value, ">")
	case "lt":
		result = e.compareNumbers(fieldValue, condition.Value, "<")
	case "gte":
		result = e.compareNumbers(fieldValue, condition.Value, ">=")
	case "lte":
		result = e.compareNumbers(fieldValue, condition.Value, "<=")
	case "in":
		result = e.valueInList(fieldStr, condition.Value)
	case "not_in":
		result = !e.valueInList(fieldStr, condition.Value)
	case "exists":
		result = fieldValue != nil
	case "not_exists":
		result = fieldValue == nil
	default:
		e.logger.Warn("Unknown operator in rule condition",
			zap.String("operator", condition.Operator),
			zap.String("field", condition.Field),
		)
		result = false
	}
	
	// Apply negation if specified
	if condition.Negate {
		result = !result
	}
	
	return result
}

// extractFieldValue extracts a field value from an event
func (e *PatternMatchingEngine) extractFieldValue(field string, event map[string]interface{}, pattern *CompiledPattern) interface{} {
	// Check if we have a custom field extractor
	if extractor, exists := pattern.FieldExtractors[field]; exists {
		return e.applyFieldExtractor(extractor, event)
	}
	
	// Simple field extraction
	if value, exists := event[field]; exists {
		return value
	}
	
	// Nested field extraction using dot notation
	if strings.Contains(field, ".") {
		return e.extractNestedField(field, event)
	}
	
	return nil
}

// extractNestedField extracts nested field values using dot notation
func (e *PatternMatchingEngine) extractNestedField(field string, event map[string]interface{}) interface{} {
	parts := strings.Split(field, ".")
	current := event
	
	for i, part := range parts {
		if value, exists := current[part]; exists {
			if i == len(parts)-1 {
				// Last part, return the value
				return value
			} else {
				// Continue traversing
				if nestedMap, ok := value.(map[string]interface{}); ok {
					current = nestedMap
				} else {
					return nil
				}
			}
		} else {
			return nil
		}
	}
	
	return nil
}

// applyFieldExtractor applies a custom field extractor
func (e *PatternMatchingEngine) applyFieldExtractor(extractor FieldExtractor, event map[string]interface{}) interface{} {
	var value interface{}
	
	// Extract value using JSONPath or regular field access
	if extractor.JSONPath != "" {
		// Simple JSONPath implementation (could be enhanced)
		value = e.extractNestedField(extractor.JSONPath, event)
	}
	
	if value == nil {
		return extractor.DefaultValue
	}
	
	// Apply transforms
	if strValue, ok := value.(string); ok {
		switch extractor.Transform {
		case "lowercase":
			return strings.ToLower(strValue)
		case "uppercase":
			return strings.ToUpper(strValue)
		case "trim":
			return strings.TrimSpace(strValue)
		}
	}
	
	return value
}

// getCompiledPattern gets or compiles a pattern for a rule
func (e *PatternMatchingEngine) getCompiledPattern(rule *ThreatRule) *CompiledPattern {
	// Check if pattern is already compiled
	if pattern, exists := e.compiledPatterns[rule.ID]; exists {
		return pattern
	}
	
	// Compile new pattern
	pattern := &CompiledPattern{
		Rule:            rule,
		CompiledRegexes: make(map[string]*regexp.Regexp),
		FieldExtractors: make(map[string]FieldExtractor),
		LastUsed:        time.Now(),
	}
	
	// Compile regex patterns
	for _, condition := range rule.Conditions {
		if condition.Operator == "regex" {
			if regexStr, ok := condition.Value.(string); ok {
				if compiled, err := regexp.Compile(regexStr); err == nil {
					pattern.CompiledRegexes[condition.Field] = compiled
				} else {
					e.logger.Warn("Failed to compile regex pattern",
						zap.String("rule_id", rule.ID),
						zap.String("field", condition.Field),
						zap.String("pattern", regexStr),
						zap.Error(err),
					)
				}
			}
		}
	}
	
	// Store compiled pattern
	e.compiledPatterns[rule.ID] = pattern
	
	return pattern
}

// IsHealthy returns the health status of the pattern matching engine
func (e *PatternMatchingEngine) IsHealthy() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isHealthy
}