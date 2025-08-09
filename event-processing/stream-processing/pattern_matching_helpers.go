package stream_processing

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Helper methods for pattern matching engine

// matchesPattern performs simple pattern matching
func (e *PatternMatchingEngine) matchesPattern(fieldValue, pattern string) bool {
	// Simple wildcard pattern matching
	if strings.Contains(pattern, "*") {
		// Convert wildcard pattern to regex
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		regexPattern = "^" + regexPattern + "$"
		
		if matched, err := regexp.MatchString(regexPattern, fieldValue); err == nil {
			return matched
		}
	}
	
	return strings.Contains(fieldValue, pattern)
}

// matchesRegex performs regex matching using compiled patterns
func (e *PatternMatchingEngine) matchesRegex(fieldValue, pattern string, compiledPattern *CompiledPattern, field string) bool {
	// Use compiled regex if available
	if compiled, exists := compiledPattern.CompiledRegexes[field]; exists {
		return compiled.MatchString(fieldValue)
	}
	
	// Fallback to runtime compilation
	if matched, err := regexp.MatchString(pattern, fieldValue); err == nil {
		return matched
	}
	
	return false
}

// compareNumbers compares numeric values
func (e *PatternMatchingEngine) compareNumbers(fieldValue, conditionValue interface{}, operator string) bool {
	// Convert to float64 for comparison
	fieldFloat, err1 := e.toFloat64(fieldValue)
	conditionFloat, err2 := e.toFloat64(conditionValue)
	
	if err1 != nil || err2 != nil {
		return false
	}
	
	switch operator {
	case ">":
		return fieldFloat > conditionFloat
	case "<":
		return fieldFloat < conditionFloat
	case ">=":
		return fieldFloat >= conditionFloat
	case "<=":
		return fieldFloat <= conditionFloat
	default:
		return false
	}
}

// toFloat64 converts various types to float64
func (e *PatternMatchingEngine) toFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

// valueInList checks if a value exists in a list
func (e *PatternMatchingEngine) valueInList(fieldValue string, listValue interface{}) bool {
	switch list := listValue.(type) {
	case []string:
		for _, item := range list {
			if fieldValue == item {
				return true
			}
		}
	case []interface{}:
		for _, item := range list {
			if fieldValue == fmt.Sprintf("%v", item) {
				return true
			}
		}
	case string:
		// Comma-separated list
		items := strings.Split(list, ",")
		for _, item := range items {
			if fieldValue == strings.TrimSpace(item) {
				return true
			}
		}
	}
	
	return false
}

// loadRules loads threat rules from files
func (e *PatternMatchingEngine) loadRules() error {
	var totalRules int
	
	// Load main threat rules
	if e.config.RulesPath != "" {
		rules, err := e.loadRulesFromPath(e.config.RulesPath)
		if err != nil {
			e.logger.Error("Failed to load threat rules", zap.Error(err))
		} else {
			e.threatRules = rules
			totalRules += len(rules)
		}
	}
	
	// Load custom rules if enabled
	if e.config.EnableCustomRules && e.config.CustomRulesPath != "" {
		rules, err := e.loadRulesFromPath(e.config.CustomRulesPath)
		if err != nil {
			e.logger.Error("Failed to load custom rules", zap.Error(err))
		} else {
			e.customRules = rules
			totalRules += len(rules)
		}
	}
	
	// Initialize default rules if no rules were loaded
	if totalRules == 0 {
		e.initializeDefaultRules()
		totalRules = len(e.threatRules)
	}
	
	// Clear compiled patterns to force recompilation
	e.compiledPatterns = make(map[string]*CompiledPattern)
	
	e.lastRuleUpdate = time.Now()
	
	e.logger.Info("Rules loaded successfully",
		zap.Int("threat_rules", len(e.threatRules)),
		zap.Int("custom_rules", len(e.customRules)),
		zap.Int("total_rules", totalRules),
	)
	
	return nil
}

// loadRulesFromPath loads rules from a file or directory
func (e *PatternMatchingEngine) loadRulesFromPath(path string) ([]*ThreatRule, error) {
	var rules []*ThreatRule
	
	// Check if path exists
	if _, err := ioutil.ReadDir(path); err != nil {
		// Try as a single file
		rule, err := e.loadRuleFromFile(path)
		if err != nil {
			return nil, err
		}
		if rule != nil {
			rules = append(rules, rule)
		}
		return rules, nil
	}
	
	// Load from directory
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		
		// Only process JSON files
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		filePath := filepath.Join(path, file.Name())
		rule, err := e.loadRuleFromFile(filePath)
		if err != nil {
			e.logger.Warn("Failed to load rule file",
				zap.String("file", filePath),
				zap.Error(err),
			)
			continue
		}
		
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	
	return rules, nil
}

// loadRuleFromFile loads a single rule from a file
func (e *PatternMatchingEngine) loadRuleFromFile(filePath string) (*ThreatRule, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var rule ThreatRule
	if err := json.Unmarshal(data, &rule); err != nil {
		return nil, err
	}
	
	// Validate rule
	if err := e.validateRule(&rule); err != nil {
		return nil, fmt.Errorf("rule validation failed: %w", err)
	}
	
	return &rule, nil
}

// validateRule validates a threat rule
func (e *PatternMatchingEngine) validateRule(rule *ThreatRule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	
	if len(rule.Conditions) == 0 {
		return fmt.Errorf("rule must have at least one condition")
	}
	
	// Check rule complexity
	if len(rule.Conditions) > e.config.MaxRuleComplexity {
		return fmt.Errorf("rule exceeds maximum complexity limit")
	}
	
	// Validate conditions
	for i, condition := range rule.Conditions {
		if condition.Field == "" {
			return fmt.Errorf("condition %d: field is required", i)
		}
		
		if condition.Operator == "" {
			return fmt.Errorf("condition %d: operator is required", i)
		}
		
		// Validate regex patterns
		if condition.Operator == "regex" {
			if regexStr, ok := condition.Value.(string); ok {
				if _, err := regexp.Compile(regexStr); err != nil {
					return fmt.Errorf("condition %d: invalid regex pattern: %w", i, err)
				}
			}
		}
	}
	
	return nil
}

// runRuleUpdates runs periodic rule updates
func (e *PatternMatchingEngine) runRuleUpdates() {
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.ruleUpdateTicker.C:
			if err := e.loadRules(); err != nil {
				e.logger.Error("Failed to update rules", zap.Error(err))
				e.mu.Lock()
				e.isHealthy = false
				e.mu.Unlock()
			} else {
				e.mu.Lock()
				e.isHealthy = true
				e.mu.Unlock()
			}
		}
	}
}

// initializeDefaultRules initializes a basic set of threat detection rules
func (e *PatternMatchingEngine) initializeDefaultRules() {
	// SQL Injection detection rule
	sqlInjectionRule := &ThreatRule{
		ID:          "sql_injection_detection",
		Name:        "SQL Injection Detection",
		Description: "Detects potential SQL injection attempts",
		Category:    "injection_attack",
		Severity:    "high",
		Confidence:  0.8,
		MITRE:       []string{"T1190"},
		Conditions: []RuleCondition{
			{
				Field:    "request_body",
				Operator: "regex",
				Value:    `(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|exec\s*\(|script\s*>)`,
				Weight:   1.0,
			},
			{
				Field:    "user_agent",
				Operator: "contains",
				Value:    "sqlmap",
				Weight:   0.5,
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "high",
				Message:  "Potential SQL injection attack detected",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "iSECTECH",
		Version:   "1.0",
	}
	
	// XSS detection rule
	xssRule := &ThreatRule{
		ID:          "xss_detection",
		Name:        "Cross-Site Scripting Detection",
		Description: "Detects potential XSS attempts",
		Category:    "injection_attack",
		Severity:    "medium",
		Confidence:  0.7,
		MITRE:       []string{"T1189"},
		Conditions: []RuleCondition{
			{
				Field:    "request_params",
				Operator: "regex",
				Value:    `(?i)(<script|javascript:|vbscript:|onload=|onerror=|onclick=)`,
				Weight:   1.0,
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "medium",
				Message:  "Potential XSS attack detected",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "iSECTECH",
		Version:   "1.0",
	}
	
	// Brute force detection rule
	bruteForceRule := &ThreatRule{
		ID:          "brute_force_detection",
		Name:        "Brute Force Attack Detection",
		Description: "Detects potential brute force authentication attempts",
		Category:    "credential_access",
		Severity:    "high",
		Confidence:  0.9,
		MITRE:       []string{"T1110"},
		Conditions: []RuleCondition{
			{
				Field:    "event_type",
				Operator: "equals",
				Value:    "authentication_failed",
				Weight:   1.0,
			},
			{
				Field:    "failure_count",
				Operator: "gt",
				Value:    5,
				Weight:   0.8,
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "high",
				Message:  "Potential brute force attack detected",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "iSECTECH",
		Version:   "1.0",
	}
	
	// Malware command and control detection
	c2Rule := &ThreatRule{
		ID:          "c2_communication_detection",
		Name:        "Command and Control Communication",
		Description: "Detects potential C2 communication patterns",
		Category:    "command_and_control",
		Severity:    "critical",
		Confidence:  0.85,
		MITRE:       []string{"T1095", "T1571"},
		Conditions: []RuleCondition{
			{
				Field:    "destination_port",
				Operator: "in",
				Value:    []int{4444, 5555, 6666, 7777, 8080, 9999},
				Weight:   0.6,
			},
			{
				Field:    "process_name",
				Operator: "regex",
				Value:    `(?i)(powershell|cmd|bash|nc|netcat)`,
				Weight:   0.4,
			},
			{
				Field:    "network_bytes",
				Operator: "gt",
				Value:    10000,
				Weight:   0.3,
			},
		},
		Actions: []RuleAction{
			{
				Type:     "alert",
				Severity: "critical",
				Message:  "Potential C2 communication detected",
			},
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    "iSECTECH",
		Version:   "1.0",
	}
	
	e.threatRules = []*ThreatRule{
		sqlInjectionRule,
		xssRule,
		bruteForceRule,
		c2Rule,
	}
	
	e.logger.Info("Default threat rules initialized", zap.Int("rule_count", len(e.threatRules)))
}