// iSECTECH Asset Inventory - Classification Service
// Production-grade asset classification and tagging engine
// Copyright (c) 2024 iSECTECH. All rights reserved.

package service

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/isectech/backend/services/asset-inventory/domain/entity"
)

// AssetClassificationService handles automatic and manual asset classification
type AssetClassificationService struct {
	logger               *logrus.Logger
	classificationRules  []ClassificationRule
	criticality          CriticalityMatrix
	businessFunctions    []BusinessFunction
	complianceFrameworks []ComplianceFramework
}

// ClassificationRule defines automatic classification logic
type ClassificationRule struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Priority    int                       `json:"priority"`
	Conditions  []ClassificationCondition `json:"conditions"`
	Actions     []ClassificationAction    `json:"actions"`
	Enabled     bool                      `json:"enabled"`
	CreatedBy   string                    `json:"created_by"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// ClassificationCondition defines when a rule should be applied
type ClassificationCondition struct {
	Field         string      `json:"field"`
	Operator      string      `json:"operator"`
	Value         interface{} `json:"value"`
	CaseSensitive bool        `json:"case_sensitive"`
}

// ClassificationAction defines what to do when a rule matches
type ClassificationAction struct {
	Action string      `json:"action"`
	Field  string      `json:"field"`
	Value  interface{} `json:"value"`
	Reason string      `json:"reason"`
}

// CriticalityMatrix defines criticality assessment rules
type CriticalityMatrix struct {
	DataClassificationWeights map[entity.DataClassification]int `json:"data_classification_weights"`
	AssetTypeWeights          map[entity.AssetType]int          `json:"asset_type_weights"`
	BusinessFunctionWeights   map[string]int                    `json:"business_function_weights"`
	NetworkSegmentWeights     map[string]int                    `json:"network_segment_weights"`
	ServiceWeights            map[string]int                    `json:"service_weights"`
	ThresholdCritical         int                               `json:"threshold_critical"`
	ThresholdHigh             int                               `json:"threshold_high"`
	ThresholdMedium           int                               `json:"threshold_medium"`
}

// BusinessFunction represents organizational business functions
type BusinessFunction struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Criticality entity.CriticalityLevel `json:"criticality"`
	Owner       string                  `json:"owner"`
	Keywords    []string                `json:"keywords"`
}

// ComplianceFramework represents compliance requirements
type ComplianceFramework struct {
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	Requirements []string           `json:"requirements"`
	AssetTypes   []entity.AssetType `json:"asset_types"`
	Keywords     []string           `json:"keywords"`
}

// ClassificationResult represents the outcome of asset classification
type ClassificationResult struct {
	AssetID              uuid.UUID               `json:"asset_id"`
	AppliedRules         []string                `json:"applied_rules"`
	SuggestedCriticality entity.CriticalityLevel `json:"suggested_criticality"`
	SuggestedTags        []entity.AssetTag       `json:"suggested_tags"`
	BusinessFunction     string                  `json:"business_function"`
	ComplianceFrameworks []string                `json:"compliance_frameworks"`
	ConfidenceScore      float64                 `json:"confidence_score"`
	Recommendations      []string                `json:"recommendations"`
}

// NewAssetClassificationService creates a new classification service
func NewAssetClassificationService(logger *logrus.Logger) *AssetClassificationService {
	service := &AssetClassificationService{
		logger:               logger,
		classificationRules:  createDefaultClassificationRules(),
		criticality:          createDefaultCriticalityMatrix(),
		businessFunctions:    createDefaultBusinessFunctions(),
		complianceFrameworks: createDefaultComplianceFrameworks(),
	}

	logger.WithFields(logrus.Fields{
		"component":             "asset_classification",
		"rules_count":           len(service.classificationRules),
		"business_functions":    len(service.businessFunctions),
		"compliance_frameworks": len(service.complianceFrameworks),
	}).Info("Asset classification service initialized")

	return service
}

// ClassifyAsset performs comprehensive asset classification
func (s *AssetClassificationService) ClassifyAsset(ctx context.Context, asset *entity.Asset) (*ClassificationResult, error) {
	logger := s.logger.WithFields(logrus.Fields{
		"asset_id":   asset.ID,
		"asset_name": asset.Name,
		"asset_type": asset.AssetType,
	})

	logger.Debug("Starting asset classification")

	result := &ClassificationResult{
		AssetID:              asset.ID,
		AppliedRules:         []string{},
		SuggestedTags:        []entity.AssetTag{},
		ComplianceFrameworks: []string{},
		Recommendations:      []string{},
	}

	// Apply classification rules
	if err := s.applyClassificationRules(asset, result); err != nil {
		logger.WithError(err).Error("Failed to apply classification rules")
		return nil, fmt.Errorf("classification rules failed: %w", err)
	}

	// Assess criticality
	s.assessCriticality(asset, result)

	// Identify business function
	s.identifyBusinessFunction(asset, result)

	// Check compliance requirements
	s.checkComplianceRequirements(asset, result)

	// Calculate confidence score
	result.ConfidenceScore = s.calculateConfidenceScore(asset, result)

	// Generate recommendations
	s.generateRecommendations(asset, result)

	logger.WithFields(logrus.Fields{
		"applied_rules":         len(result.AppliedRules),
		"suggested_criticality": result.SuggestedCriticality,
		"confidence_score":      result.ConfidenceScore,
		"business_function":     result.BusinessFunction,
	}).Info("Asset classification completed")

	return result, nil
}

// applyClassificationRules applies automatic classification rules
func (s *AssetClassificationService) applyClassificationRules(asset *entity.Asset, result *ClassificationResult) error {
	for _, rule := range s.classificationRules {
		if !rule.Enabled {
			continue
		}

		if s.evaluateRuleConditions(asset, rule.Conditions) {
			s.logger.WithFields(logrus.Fields{
				"asset_id":  asset.ID,
				"rule_id":   rule.ID,
				"rule_name": rule.Name,
			}).Debug("Classification rule matched")

			result.AppliedRules = append(result.AppliedRules, rule.ID)

			// Apply rule actions
			for _, action := range rule.Actions {
				if err := s.applyClassificationAction(asset, action, result); err != nil {
					s.logger.WithError(err).WithFields(logrus.Fields{
						"rule_id": rule.ID,
						"action":  action.Action,
					}).Warn("Failed to apply classification action")
				}
			}
		}
	}

	return nil
}

// evaluateRuleConditions checks if all conditions for a rule are met
func (s *AssetClassificationService) evaluateRuleConditions(asset *entity.Asset, conditions []ClassificationCondition) bool {
	for _, condition := range conditions {
		if !s.evaluateCondition(asset, condition) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single classification condition
func (s *AssetClassificationService) evaluateCondition(asset *entity.Asset, condition ClassificationCondition) bool {
	fieldValue := s.getFieldValue(asset, condition.Field)
	if fieldValue == nil {
		return false
	}

	switch condition.Operator {
	case "equals":
		return s.compareValues(fieldValue, condition.Value, condition.CaseSensitive, "equals")
	case "contains":
		return s.compareValues(fieldValue, condition.Value, condition.CaseSensitive, "contains")
	case "starts_with":
		return s.compareValues(fieldValue, condition.Value, condition.CaseSensitive, "starts_with")
	case "ends_with":
		return s.compareValues(fieldValue, condition.Value, condition.CaseSensitive, "ends_with")
	case "regex":
		return s.matchRegex(fieldValue, condition.Value)
	case "in_network":
		return s.isInNetwork(fieldValue, condition.Value)
	case "has_port":
		return s.hasPort(asset, condition.Value)
	case "has_service":
		return s.hasService(asset, condition.Value)
	case "has_software":
		return s.hasSoftware(asset, condition.Value)
	default:
		s.logger.WithField("operator", condition.Operator).Warn("Unknown classification operator")
		return false
	}
}

// getFieldValue extracts field value from asset using dot notation
func (s *AssetClassificationService) getFieldValue(asset *entity.Asset, field string) interface{} {
	switch field {
	case "name":
		return asset.Name
	case "asset_type":
		return string(asset.AssetType)
	case "os.name":
		return asset.OperatingSystem.Name
	case "os.version":
		return asset.OperatingSystem.Version
	case "network_segment":
		return asset.NetworkSegment
	case "ip_addresses":
		return asset.IPAddresses
	case "host_names":
		return asset.HostNames
	case "location.datacenter":
		return asset.Location.Datacenter
	case "location.region":
		return asset.Location.Region
	case "business_function":
		return asset.BusinessFunction
	case "owner":
		return asset.Owner
	default:
		// Check custom fields
		if value, exists := asset.CustomFields[field]; exists {
			return value
		}
		return nil
	}
}

// compareValues compares two values based on operator and case sensitivity
func (s *AssetClassificationService) compareValues(fieldValue, conditionValue interface{}, caseSensitive bool, operator string) bool {
	field := fmt.Sprintf("%v", fieldValue)
	condition := fmt.Sprintf("%v", conditionValue)

	if !caseSensitive {
		field = strings.ToLower(field)
		condition = strings.ToLower(condition)
	}

	switch operator {
	case "equals":
		return field == condition
	case "contains":
		return strings.Contains(field, condition)
	case "starts_with":
		return strings.HasPrefix(field, condition)
	case "ends_with":
		return strings.HasSuffix(field, condition)
	default:
		return false
	}
}

// matchRegex performs regex matching
func (s *AssetClassificationService) matchRegex(fieldValue, pattern interface{}) bool {
	field := fmt.Sprintf("%v", fieldValue)
	regex := fmt.Sprintf("%v", pattern)

	matched, err := regexp.MatchString(regex, field)
	if err != nil {
		s.logger.WithError(err).WithField("pattern", regex).Warn("Invalid regex pattern")
		return false
	}

	return matched
}

// isInNetwork checks if an IP address is in a specific network
func (s *AssetClassificationService) isInNetwork(fieldValue, networkValue interface{}) bool {
	network := fmt.Sprintf("%v", networkValue)
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return false
	}

	// Handle both single IP and IP list
	switch v := fieldValue.(type) {
	case string:
		ip := net.ParseIP(v)
		return ip != nil && cidr.Contains(ip)
	case []string:
		for _, ipStr := range v {
			ip := net.ParseIP(ipStr)
			if ip != nil && cidr.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// hasPort checks if asset has a specific port open
func (s *AssetClassificationService) hasPort(asset *entity.Asset, portValue interface{}) bool {
	port := fmt.Sprintf("%v", portValue)

	for _, networkPort := range asset.NetworkPorts {
		if fmt.Sprintf("%d", networkPort.Port) == port {
			return true
		}
	}

	return false
}

// hasService checks if asset has a specific service running
func (s *AssetClassificationService) hasService(asset *entity.Asset, serviceValue interface{}) bool {
	service := strings.ToLower(fmt.Sprintf("%v", serviceValue))

	for _, svc := range asset.Services {
		if strings.Contains(strings.ToLower(svc.Name), service) ||
			strings.Contains(strings.ToLower(svc.DisplayName), service) {
			return true
		}
	}

	// Check network ports for service
	for _, port := range asset.NetworkPorts {
		if strings.Contains(strings.ToLower(port.Service), service) {
			return true
		}
	}

	return false
}

// hasSoftware checks if asset has specific software installed
func (s *AssetClassificationService) hasSoftware(asset *entity.Asset, softwareValue interface{}) bool {
	software := strings.ToLower(fmt.Sprintf("%v", softwareValue))

	for _, sw := range asset.Software {
		if strings.Contains(strings.ToLower(sw.Name), software) ||
			strings.Contains(strings.ToLower(sw.Vendor), software) {
			return true
		}
	}

	return false
}

// applyClassificationAction applies a classification action to the asset
func (s *AssetClassificationService) applyClassificationAction(asset *entity.Asset, action ClassificationAction, result *ClassificationResult) error {
	switch action.Action {
	case "set_criticality":
		if criticality, ok := action.Value.(string); ok {
			result.SuggestedCriticality = entity.CriticalityLevel(criticality)
		}
	case "add_tag":
		if tagValue, ok := action.Value.(string); ok {
			tag := entity.AssetTag{
				Key:       action.Field,
				Value:     tagValue,
				Source:    "classification_rule",
				CreatedAt: time.Now().UTC(),
			}
			result.SuggestedTags = append(result.SuggestedTags, tag)
		}
	case "set_business_function":
		if function, ok := action.Value.(string); ok {
			result.BusinessFunction = function
		}
	case "add_compliance_framework":
		if framework, ok := action.Value.(string); ok {
			result.ComplianceFrameworks = append(result.ComplianceFrameworks, framework)
		}
	case "set_scan_frequency":
		if frequency, ok := action.Value.(string); ok {
			// This would be applied to the asset after classification
			result.Recommendations = append(result.Recommendations,
				fmt.Sprintf("Set scan frequency to %s: %s", frequency, action.Reason))
		}
	}

	return nil
}

// assessCriticality calculates asset criticality based on multiple factors
func (s *AssetClassificationService) assessCriticality(asset *entity.Asset, result *ClassificationResult) {
	if result.SuggestedCriticality != "" {
		return // Already set by rules
	}

	score := 0

	// Data classification weight
	if weight, exists := s.criticality.DataClassificationWeights[asset.DataClassification]; exists {
		score += weight
	}

	// Asset type weight
	if weight, exists := s.criticality.AssetTypeWeights[asset.AssetType]; exists {
		score += weight
	}

	// Business function weight
	if weight, exists := s.criticality.BusinessFunctionWeights[asset.BusinessFunction]; exists {
		score += weight
	}

	// Network segment weight
	if weight, exists := s.criticality.NetworkSegmentWeights[asset.NetworkSegment]; exists {
		score += weight
	}

	// Service weight
	for _, service := range asset.Services {
		if weight, exists := s.criticality.ServiceWeights[strings.ToLower(service.Name)]; exists {
			score += weight
		}
	}

	// Determine criticality level
	switch {
	case score >= s.criticality.ThresholdCritical:
		result.SuggestedCriticality = entity.CriticalityCritical
	case score >= s.criticality.ThresholdHigh:
		result.SuggestedCriticality = entity.CriticalityHigh
	case score >= s.criticality.ThresholdMedium:
		result.SuggestedCriticality = entity.CriticalityMedium
	default:
		result.SuggestedCriticality = entity.CriticalityLow
	}
}

// identifyBusinessFunction identifies the business function based on asset characteristics
func (s *AssetClassificationService) identifyBusinessFunction(asset *entity.Asset, result *ClassificationResult) {
	if result.BusinessFunction != "" {
		return // Already set by rules
	}

	for _, function := range s.businessFunctions {
		for _, keyword := range function.Keywords {
			if strings.Contains(strings.ToLower(asset.Name), strings.ToLower(keyword)) ||
				strings.Contains(strings.ToLower(asset.Description), strings.ToLower(keyword)) ||
				strings.Contains(strings.ToLower(asset.NetworkSegment), strings.ToLower(keyword)) {
				result.BusinessFunction = function.Name
				return
			}
		}
	}
}

// checkComplianceRequirements identifies applicable compliance frameworks
func (s *AssetClassificationService) checkComplianceRequirements(asset *entity.Asset, result *ClassificationResult) {
	for _, framework := range s.complianceFrameworks {
		// Check if asset type is covered
		for _, assetType := range framework.AssetTypes {
			if asset.AssetType == assetType {
				result.ComplianceFrameworks = append(result.ComplianceFrameworks, framework.Name)
				break
			}
		}

		// Check keywords
		for _, keyword := range framework.Keywords {
			if strings.Contains(strings.ToLower(asset.Name), strings.ToLower(keyword)) ||
				strings.Contains(strings.ToLower(asset.Description), strings.ToLower(keyword)) ||
				strings.Contains(strings.ToLower(asset.BusinessFunction), strings.ToLower(keyword)) {
				if !contains(result.ComplianceFrameworks, framework.Name) {
					result.ComplianceFrameworks = append(result.ComplianceFrameworks, framework.Name)
				}
				break
			}
		}
	}
}

// calculateConfidenceScore calculates confidence in classification results
func (s *AssetClassificationService) calculateConfidenceScore(asset *entity.Asset, result *ClassificationResult) float64 {
	score := 0.0
	maxScore := 100.0

	// Rules applied (40% weight)
	if len(result.AppliedRules) > 0 {
		score += 40.0
	}

	// Asset information completeness (30% weight)
	completeness := 0.0
	if asset.OperatingSystem.Name != "" {
		completeness += 5.0
	}
	if len(asset.IPAddresses) > 0 {
		completeness += 5.0
	}
	if len(asset.Services) > 0 {
		completeness += 5.0
	}
	if len(asset.Software) > 0 {
		completeness += 5.0
	}
	if asset.NetworkSegment != "" {
		completeness += 5.0
	}
	if asset.Owner != "" {
		completeness += 5.0
	}
	score += completeness

	// Business context (20% weight)
	if result.BusinessFunction != "" {
		score += 10.0
	}
	if len(result.ComplianceFrameworks) > 0 {
		score += 10.0
	}

	// Discovery method reliability (10% weight)
	switch asset.DiscoveryMethod {
	case "agent":
		score += 10.0
	case "network_scan":
		score += 8.0
	case "manual":
		score += 6.0
	case "import":
		score += 4.0
	default:
		score += 2.0
	}

	return (score / maxScore) * 100.0
}

// generateRecommendations generates classification recommendations
func (s *AssetClassificationService) generateRecommendations(asset *entity.Asset, result *ClassificationResult) {
	// Scan frequency recommendations
	if asset.ScanFrequency == "" || asset.ScanFrequency == entity.ScanFrequencyWeekly {
		switch result.SuggestedCriticality {
		case entity.CriticalityCritical:
			result.Recommendations = append(result.Recommendations, "Recommend daily vulnerability scanning for critical asset")
		case entity.CriticalityHigh:
			result.Recommendations = append(result.Recommendations, "Recommend bi-weekly vulnerability scanning for high-criticality asset")
		}
	}

	// Missing information recommendations
	if asset.Owner == "" {
		result.Recommendations = append(result.Recommendations, "Asset owner should be specified for accountability")
	}

	if asset.BusinessFunction == "" && result.BusinessFunction == "" {
		result.Recommendations = append(result.Recommendations, "Business function should be identified for better risk assessment")
	}

	if len(asset.ComplianceFrameworks) == 0 && len(result.ComplianceFrameworks) > 0 {
		result.Recommendations = append(result.Recommendations, "Asset should be tagged with applicable compliance frameworks")
	}

	// Security recommendations based on asset type
	switch asset.AssetType {
	case entity.AssetTypeServer:
		if !asset.EncryptionStatus.DiskEncryption {
			result.Recommendations = append(result.Recommendations, "Disk encryption should be enabled for server assets")
		}
	case entity.AssetTypeEndpoint:
		if asset.LastSeen.Before(time.Now().Add(-7 * 24 * time.Hour)) {
			result.Recommendations = append(result.Recommendations, "Endpoint has not been seen recently - verify connectivity")
		}
	case entity.AssetTypeDatabase:
		if !asset.EncryptionStatus.DatabaseEncryption {
			result.Recommendations = append(result.Recommendations, "Database encryption should be enabled for data protection")
		}
	}
}

// Helper function to check if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// createDefaultClassificationRules creates built-in classification rules for iSECTECH
func createDefaultClassificationRules() []ClassificationRule {
	return []ClassificationRule{
		{
			ID:          "rule_001",
			Name:        "Critical Infrastructure Servers",
			Description: "Classify domain controllers and critical infrastructure servers as critical",
			Priority:    100,
			Enabled:     true,
			Conditions: []ClassificationCondition{
				{Field: "asset_type", Operator: "equals", Value: "server"},
				{Field: "services", Operator: "has_service", Value: "Active Directory"},
			},
			Actions: []ClassificationAction{
				{Action: "set_criticality", Value: "critical", Reason: "Domain controller critical for infrastructure"},
				{Action: "add_tag", Field: "role", Value: "domain_controller", Reason: "Identified as domain controller"},
				{Action: "set_scan_frequency", Value: "daily", Reason: "Critical infrastructure requires frequent scanning"},
			},
		},
		{
			ID:          "rule_002",
			Name:        "Database Servers",
			Description: "Classify database servers with appropriate criticality",
			Priority:    90,
			Enabled:     true,
			Conditions: []ClassificationCondition{
				{Field: "asset_type", Operator: "equals", Value: "database"},
			},
			Actions: []ClassificationAction{
				{Action: "set_criticality", Value: "high", Reason: "Database contains critical business data"},
				{Action: "add_tag", Field: "data_store", Value: "true", Reason: "Asset stores data"},
				{Action: "add_compliance_framework", Value: "SOX", Reason: "Database may contain financial data"},
			},
		},
		{
			ID:          "rule_003",
			Name:        "Web Servers",
			Description: "Classify public-facing web servers",
			Priority:    80,
			Enabled:     true,
			Conditions: []ClassificationCondition{
				{Field: "network_ports", Operator: "has_port", Value: "80"},
				{Field: "network_ports", Operator: "has_port", Value: "443"},
			},
			Actions: []ClassificationAction{
				{Action: "add_tag", Field: "exposure", Value: "public", Reason: "Web server likely public-facing"},
				{Action: "set_criticality", Value: "high", Reason: "Public exposure increases risk"},
				{Action: "add_compliance_framework", Value: "PCI-DSS", Reason: "Web servers may process payments"},
			},
		},
		{
			ID:          "rule_004",
			Name:        "Executive Endpoints",
			Description: "Classify executive and VIP user endpoints",
			Priority:    85,
			Enabled:     true,
			Conditions: []ClassificationCondition{
				{Field: "owner", Operator: "contains", Value: "ceo", CaseSensitive: false},
				{Field: "owner", Operator: "contains", Value: "cto", CaseSensitive: false},
				{Field: "owner", Operator: "contains", Value: "cfo", CaseSensitive: false},
			},
			Actions: []ClassificationAction{
				{Action: "set_criticality", Value: "critical", Reason: "Executive asset requires enhanced protection"},
				{Action: "add_tag", Field: "vip", Value: "true", Reason: "VIP user asset"},
				{Action: "set_scan_frequency", Value: "daily", Reason: "VIP assets require frequent monitoring"},
			},
		},
		{
			ID:          "rule_005",
			Name:        "Development Environment",
			Description: "Classify development and testing environments",
			Priority:    60,
			Enabled:     true,
			Conditions: []ClassificationCondition{
				{Field: "network_segment", Operator: "contains", Value: "dev", CaseSensitive: false},
				{Field: "network_segment", Operator: "contains", Value: "test", CaseSensitive: false},
				{Field: "name", Operator: "contains", Value: "dev", CaseSensitive: false},
			},
			Actions: []ClassificationAction{
				{Action: "set_criticality", Value: "low", Reason: "Development environment"},
				{Action: "add_tag", Field: "environment", Value: "development", Reason: "Identified as development asset"},
				{Action: "set_business_function", Value: "Software Development", Reason: "Development asset"},
			},
		},
	}
}

// createDefaultCriticalityMatrix creates the default criticality assessment matrix
func createDefaultCriticalityMatrix() CriticalityMatrix {
	return CriticalityMatrix{
		DataClassificationWeights: map[entity.DataClassification]int{
			entity.DataClassificationRestricted:   40,
			entity.DataClassificationConfidential: 30,
			entity.DataClassificationInternal:     10,
			entity.DataClassificationPublic:       0,
		},
		AssetTypeWeights: map[entity.AssetType]int{
			entity.AssetTypeDatabase:      30,
			entity.AssetTypeServer:        25,
			entity.AssetTypeApplication:   20,
			entity.AssetTypeNetworkDevice: 20,
			entity.AssetTypeEndpoint:      10,
			entity.AssetTypeContainer:     15,
			entity.AssetTypeCloudResource: 20,
		},
		BusinessFunctionWeights: map[string]int{
			"Finance":              30,
			"Human Resources":      25,
			"Legal":                25,
			"Executive":            40,
			"IT Operations":        20,
			"Software Development": 15,
			"Marketing":            10,
		},
		NetworkSegmentWeights: map[string]int{
			"dmz":         30,
			"production":  25,
			"staging":     15,
			"development": 5,
			"guest":       0,
		},
		ServiceWeights: map[string]int{
			"domain controller": 40,
			"database":          30,
			"web server":        25,
			"file server":       20,
			"mail server":       25,
			"dns":               20,
			"dhcp":              15,
		},
		ThresholdCritical: 80,
		ThresholdHigh:     60,
		ThresholdMedium:   40,
	}
}

// createDefaultBusinessFunctions creates default business function definitions
func createDefaultBusinessFunctions() []BusinessFunction {
	return []BusinessFunction{
		{
			Name:        "Finance",
			Description: "Financial operations and accounting",
			Criticality: entity.CriticalityHigh,
			Keywords:    []string{"finance", "accounting", "payroll", "billing", "sap", "erp"},
		},
		{
			Name:        "Human Resources",
			Description: "Human resources and personnel management",
			Criticality: entity.CriticalityHigh,
			Keywords:    []string{"hr", "personnel", "employee", "workday", "adp"},
		},
		{
			Name:        "Executive",
			Description: "Executive and senior management",
			Criticality: entity.CriticalityCritical,
			Keywords:    []string{"executive", "ceo", "cto", "cfo", "president", "vp"},
		},
		{
			Name:        "IT Operations",
			Description: "Information technology operations",
			Criticality: entity.CriticalityHigh,
			Keywords:    []string{"datacenter", "server", "infrastructure", "monitoring"},
		},
		{
			Name:        "Software Development",
			Description: "Software development and engineering",
			Criticality: entity.CriticalityMedium,
			Keywords:    []string{"dev", "development", "engineering", "git", "jenkins"},
		},
		{
			Name:        "Sales",
			Description: "Sales and customer relationship management",
			Criticality: entity.CriticalityMedium,
			Keywords:    []string{"sales", "crm", "salesforce", "customer"},
		},
		{
			Name:        "Marketing",
			Description: "Marketing and communications",
			Criticality: entity.CriticalityLow,
			Keywords:    []string{"marketing", "website", "social", "campaign"},
		},
	}
}

// createDefaultComplianceFrameworks creates default compliance framework definitions
func createDefaultComplianceFrameworks() []ComplianceFramework {
	return []ComplianceFramework{
		{
			Name:        "PCI-DSS",
			Description: "Payment Card Industry Data Security Standard",
			AssetTypes:  []entity.AssetType{entity.AssetTypeApplication, entity.AssetTypeServer, entity.AssetTypeDatabase},
			Keywords:    []string{"payment", "credit", "card", "pos", "ecommerce"},
		},
		{
			Name:        "SOX",
			Description: "Sarbanes-Oxley Act",
			AssetTypes:  []entity.AssetType{entity.AssetTypeDatabase, entity.AssetTypeApplication, entity.AssetTypeServer},
			Keywords:    []string{"financial", "accounting", "finance", "sox", "audit"},
		},
		{
			Name:        "HIPAA",
			Description: "Health Insurance Portability and Accountability Act",
			AssetTypes:  []entity.AssetType{entity.AssetTypeDatabase, entity.AssetTypeApplication, entity.AssetTypeServer},
			Keywords:    []string{"health", "medical", "patient", "phi", "healthcare"},
		},
		{
			Name:        "ISO 27001",
			Description: "Information Security Management System",
			AssetTypes:  []entity.AssetType{entity.AssetTypeServer, entity.AssetTypeNetworkDevice, entity.AssetTypeDatabase},
			Keywords:    []string{"security", "iso", "isms"},
		},
		{
			Name:        "GDPR",
			Description: "General Data Protection Regulation",
			AssetTypes:  []entity.AssetType{entity.AssetTypeDatabase, entity.AssetTypeApplication, entity.AssetTypeServer},
			Keywords:    []string{"personal", "gdpr", "privacy", "customer", "eu"},
		},
	}
}
