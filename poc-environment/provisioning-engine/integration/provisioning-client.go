// iSECTECH POC Provisioning Engine - Client Integration
// Production-Grade Go Client for Backend-to-Provisioning Communication
// Version: 1.0
// Author: Claude Code Implementation

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Client configuration
type ProvisioningClientConfig struct {
	BaseURL        string
	Timeout        time.Duration
	RetryAttempts  int
	RetryDelay     time.Duration
	EnableLogging  bool
}

// Default configuration
var DefaultConfig = ProvisioningClientConfig{
	BaseURL:       "http://poc-provisioning-service.poc-provisioning.svc.cluster.local/api/v1",
	Timeout:       60 * time.Second,
	RetryAttempts: 3,
	RetryDelay:    2 * time.Second,
	EnableLogging: true,
}

// Provisioning client
type ProvisioningClient struct {
	config     ProvisioningClientConfig
	httpClient *http.Client
}

// Provisioning request structures
type CompanyInfo struct {
	CompanyName         string `json:"company_name"`
	IndustryVertical    string `json:"industry_vertical"`
	CompanySize         string `json:"company_size"`
	HeadquartersCountry string `json:"headquarters_country"`
	ContactEmail        string `json:"contact_email"`
	ContactName         string `json:"contact_name"`
}

type POCConfig struct {
	POCTier             string                 `json:"poc_tier"`
	POCDurationDays     int                    `json:"poc_duration_days"`
	ExpiresAt           time.Time              `json:"expires_at"`
	EnabledFeatures     []string               `json:"enabled_features"`
	ResourceAllocation  map[string]interface{} `json:"resource_allocation"`
}

type SecurityConfig struct {
	SecurityClearance     string   `json:"security_clearance"`
	DataResidencyRegion   string   `json:"data_residency_region"`
	ComplianceFrameworks  []string `json:"compliance_frameworks"`
	NetworkIsolationLevel string   `json:"network_isolation_level"`
	EncryptionRequired    bool     `json:"encryption_required"`
}

type IntegrationConfig struct {
	MainPlatformIntegration bool     `json:"main_platform_integration"`
	AllowedDataConnectors   []string `json:"allowed_data_connectors"`
	CRMIntegrationEnabled   bool     `json:"crm_integration_enabled"`
}

type MonitoringConfig struct {
	Enabled            bool `json:"enabled"`
	DetailedMonitoring bool `json:"detailed_monitoring"`
	AlertingEnabled    bool `json:"alerting_enabled"`
	RetentionDays      int  `json:"retention_days"`
}

type ProvisioningRequest struct {
	TenantID          uuid.UUID         `json:"tenant_id"`
	TenantSlug        string            `json:"tenant_slug"`
	CompanyInfo       CompanyInfo       `json:"company_info"`
	POCConfig         POCConfig         `json:"poc_config"`
	SecurityConfig    SecurityConfig    `json:"security_config"`
	IntegrationConfig IntegrationConfig `json:"integration_config"`
	MonitoringConfig  MonitoringConfig  `json:"monitoring_config"`
	RequestID         string            `json:"request_id"`
	RequestedBy       uuid.UUID         `json:"requested_by"`
	Priority          string            `json:"priority"`
}

type ProvisioningResponse struct {
	Success              bool                   `json:"success"`
	Message              string                 `json:"message"`
	JobID                uuid.UUID              `json:"job_id"`
	Status               string                 `json:"status"`
	EstimatedDuration    string                 `json:"estimated_duration"`
	ProgressTrackingURL  string                 `json:"progress_tracking_url"`
	ProvisionedResources map[string]interface{} `json:"provisioned_resources,omitempty"`
	ServiceEndpoints     map[string]interface{} `json:"service_endpoints,omitempty"`
	ErrorMessage         string                 `json:"error_message,omitempty"`
}

// Create new provisioning client
func NewProvisioningClient(config *ProvisioningClientConfig) *ProvisioningClient {
	if config == nil {
		config = &DefaultConfig
	}

	return &ProvisioningClient{
		config: *config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// Submit provisioning request
func (c *ProvisioningClient) SubmitProvisioningRequest(ctx context.Context, request *ProvisioningRequest) (*ProvisioningResponse, error) {
	// Generate request ID if not provided
	if request.RequestID == "" {
		request.RequestID = uuid.New().String()
	}

	// Set default priority if not provided
	if request.Priority == "" {
		request.Priority = "standard"
	}

	if c.config.EnableLogging {
		fmt.Printf("Submitting provisioning request for tenant %s (ID: %s)\n", 
			request.TenantSlug, request.RequestID)
	}

	// Marshal request to JSON
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := c.config.BaseURL + "/provisioning/provision"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Request-ID", request.RequestID)

	// Execute request with retry logic
	var response *ProvisioningResponse
	var lastErr error

	for attempt := 1; attempt <= c.config.RetryAttempts; attempt++ {
		if c.config.EnableLogging {
			fmt.Printf("Provisioning request attempt %d/%d for tenant %s\n", 
				attempt, c.config.RetryAttempts, request.TenantSlug)
		}

		response, lastErr = c.executeRequest(httpReq)
		if lastErr == nil {
			break
		}

		if attempt < c.config.RetryAttempts {
			if c.config.EnableLogging {
				fmt.Printf("Provisioning request failed (attempt %d), retrying in %v: %v\n", 
					attempt, c.config.RetryDelay, lastErr)
			}
			
			// Wait before retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.config.RetryDelay):
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all provisioning request attempts failed: %w", lastErr)
	}

	if c.config.EnableLogging {
		fmt.Printf("Provisioning request submitted successfully for tenant %s (Job ID: %s)\n", 
			request.TenantSlug, response.JobID)
	}

	return response, nil
}

// Execute HTTP request
func (c *ProvisioningClient) executeRequest(req *http.Request) (*ProvisioningResponse, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var response ProvisioningResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &response, nil
}

// Get provisioning status
func (c *ProvisioningClient) GetProvisioningStatus(ctx context.Context, jobID uuid.UUID) (*ProvisioningResponse, error) {
	url := fmt.Sprintf("%s/provisioning/status/%s", c.config.BaseURL, jobID.String())
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	return c.executeRequest(req)
}

// Check provisioning service health
func (c *ProvisioningClient) CheckHealth(ctx context.Context) (map[string]interface{}, error) {
	url := c.config.BaseURL + "/health"
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, fmt.Errorf("failed to unmarshal health response: %w", err)
	}

	return health, nil
}

// Convert POC signup data to provisioning request
func ConvertSignupToProvisioningRequest(signupData map[string]interface{}, tenantID uuid.UUID, tenantSlug string) *ProvisioningRequest {
	// Extract company information
	companyInfo := CompanyInfo{
		CompanyName:         getString(signupData, "company_name"),
		IndustryVertical:    getString(signupData, "industry_vertical"),
		CompanySize:         getString(signupData, "company_size"),
		HeadquartersCountry: getString(signupData, "headquarters_country"),
		ContactEmail:        getString(signupData, "contact_email"),
		ContactName:         getString(signupData, "contact_name"),
	}

	// Extract POC configuration
	pocTier := getString(signupData, "poc_tier")
	pocDurationDays := getInt(signupData, "poc_duration_days")
	expiresAt := time.Now().UTC().AddDate(0, 0, pocDurationDays)
	
	pocConfig := POCConfig{
		POCTier:         pocTier,
		POCDurationDays: pocDurationDays,
		ExpiresAt:       expiresAt,
		EnabledFeatures: getFeaturesByTier(pocTier),
		ResourceAllocation: getResourceAllocationByTier(pocTier),
	}

	// Extract security configuration
	securityConfig := SecurityConfig{
		SecurityClearance:     getString(signupData, "security_clearance"),
		DataResidencyRegion:   getString(signupData, "data_residency_region"),
		ComplianceFrameworks:  getStringArray(signupData, "compliance_frameworks"),
		NetworkIsolationLevel: "high",
		EncryptionRequired:    true,
	}

	// Integration configuration
	integrationConfig := IntegrationConfig{
		MainPlatformIntegration: true,
		AllowedDataConnectors:   getStringArray(signupData, "allowed_data_connectors"),
		CRMIntegrationEnabled:   true,
	}

	// Monitoring configuration
	monitoringConfig := MonitoringConfig{
		Enabled:            true,
		DetailedMonitoring: pocTier != "standard",
		AlertingEnabled:    true,
		RetentionDays:      getRetentionDaysByTier(pocTier),
	}

	return &ProvisioningRequest{
		TenantID:          tenantID,
		TenantSlug:        tenantSlug,
		CompanyInfo:       companyInfo,
		POCConfig:         pocConfig,
		SecurityConfig:    securityConfig,
		IntegrationConfig: integrationConfig,
		MonitoringConfig:  monitoringConfig,
		RequestID:         uuid.New().String(),
		Priority:          getPriorityByTier(pocTier),
	}
}

// Helper functions
func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		if num, ok := val.(float64); ok {
			return int(num)
		}
		if num, ok := val.(int); ok {
			return num
		}
	}
	return 0
}

func getStringArray(data map[string]interface{}, key string) []string {
	if val, ok := data[key]; ok {
		if arr, ok := val.([]interface{}); ok {
			result := make([]string, len(arr))
			for i, item := range arr {
				if str, ok := item.(string); ok {
					result[i] = str
				}
			}
			return result
		}
	}
	return []string{}
}

func getFeaturesByTier(tier string) []string {
	baseFeatures := []string{
		"threat_detection",
		"vulnerability_management", 
		"compliance_reporting",
		"siem_analytics",
		"dashboards_reporting",
	}

	if tier == "enterprise" || tier == "premium" {
		baseFeatures = append(baseFeatures,
			"email_security",
			"network_monitoring",
			"identity_analytics",
			"incident_response",
		)
	}

	if tier == "premium" {
		baseFeatures = append(baseFeatures,
			"soar_automation",
			"ai_ml_analytics",
			"custom_integrations",
			"advanced_reporting",
			"api_access",
		)
	}

	return baseFeatures
}

func getResourceAllocationByTier(tier string) map[string]interface{} {
	switch tier {
	case "standard":
		return map[string]interface{}{
			"cpu_cores":  8,
			"memory_gb":  32,
			"storage_gb": 500,
			"max_users":  25,
		}
	case "enterprise":
		return map[string]interface{}{
			"cpu_cores":  16,
			"memory_gb":  64,
			"storage_gb": 1000,
			"max_users":  100,
		}
	case "premium":
		return map[string]interface{}{
			"cpu_cores":  32,
			"memory_gb":  128,
			"storage_gb": 2000,
			"max_users":  500,
		}
	default:
		return map[string]interface{}{
			"cpu_cores":  8,
			"memory_gb":  32,
			"storage_gb": 500,
			"max_users":  25,
		}
	}
}

func getRetentionDaysByTier(tier string) int {
	switch tier {
	case "standard":
		return 30
	case "enterprise":
		return 90
	case "premium":
		return 365
	default:
		return 30
	}
}

func getPriorityByTier(tier string) string {
	switch tier {
	case "premium":
		return "high"
	case "enterprise":
		return "standard"
	case "standard":
		return "standard"
	default:
		return "standard"
	}
}