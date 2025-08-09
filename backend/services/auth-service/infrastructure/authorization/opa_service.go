package authorization

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"isectech/auth-service/domain/service"
)

// OPAServiceImpl implements the OPA service interface
type OPAServiceImpl struct {
	client    *http.Client
	baseURL   string
	timeout   time.Duration
	apiToken  string
	namespace string
}

// OPAConfig holds OPA service configuration
type OPAConfig struct {
	BaseURL    string        `yaml:"base_url" default:"http://localhost:8181"`
	Timeout    time.Duration `yaml:"timeout" default:"5s"`
	APIToken   string        `yaml:"api_token"`
	Namespace  string        `yaml:"namespace" default:"isectech"`
	RetryCount int           `yaml:"retry_count" default:"3"`
	RetryDelay time.Duration `yaml:"retry_delay" default:"1s"`
}

// NewOPAService creates a new OPA service implementation
func NewOPAService(config *OPAConfig) *OPAServiceImpl {
	client := &http.Client{
		Timeout: config.Timeout,
	}

	return &OPAServiceImpl{
		client:    client,
		baseURL:   strings.TrimSuffix(config.BaseURL, "/"),
		timeout:   config.Timeout,
		apiToken:  config.APIToken,
		namespace: config.Namespace,
	}
}

// Policy Management

func (s *OPAServiceImpl) DeployPolicy(ctx context.Context, policyID string, policyContent string) error {
	// Prepare policy document
	policyDoc := map[string]interface{}{
		"id":      policyID,
		"content": policyContent,
	}

	// Convert to JSON
	payload, err := json.Marshal(policyDoc)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	// Create request
	url := fmt.Sprintf("%s/v1/policies/%s", s.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "text/plain")
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to deploy policy: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy deployment failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *OPAServiceImpl) RemovePolicy(ctx context.Context, policyID string) error {
	// Create request
	url := fmt.Sprintf("%s/v1/policies/%s", s.baseURL, policyID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to remove policy: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("policy removal failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Data Management

func (s *OPAServiceImpl) SetData(ctx context.Context, path string, data interface{}) error {
	// Convert data to JSON
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create request
	url := fmt.Sprintf("%s/v1/data/%s", s.baseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to set data: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("data setting failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

func (s *OPAServiceImpl) GetData(ctx context.Context, path string) (interface{}, error) {
	// Create request
	url := fmt.Sprintf("%s/v1/data/%s", s.baseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get data: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("data retrieval failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract result from OPA response format
	if resultData, exists := result["result"]; exists {
		return resultData, nil
	}

	return result, nil
}

func (s *OPAServiceImpl) DeleteData(ctx context.Context, path string) error {
	// Create request
	url := fmt.Sprintf("%s/v1/data/%s", s.baseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete data: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("data deletion failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Query Evaluation

func (s *OPAServiceImpl) Query(ctx context.Context, query string, input interface{}) (*service.OPAQueryResult, error) {
	// Prepare query request
	queryReq := map[string]interface{}{
		"query": query,
	}

	if input != nil {
		queryReq["input"] = input
	}

	// Convert to JSON
	payload, err := json.Marshal(queryReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Create request
	url := fmt.Sprintf("%s/v1/query", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("query execution failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var opaResponse struct {
		Result   interface{}              `json:"result"`
		Bindings map[string]interface{}   `json:"bindings,omitempty"`
		Metrics  *service.OPAMetrics      `json:"metrics,omitempty"`
		Trace    []*service.OPATraceEvent `json:"trace,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&opaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &service.OPAQueryResult{
		Result:   opaResponse.Result,
		Bindings: opaResponse.Bindings,
		Metrics:  opaResponse.Metrics,
		Trace:    opaResponse.Trace,
	}, nil
}

func (s *OPAServiceImpl) QueryWithDecision(ctx context.Context, path string, input interface{}) (*service.OPADecisionResult, error) {
	// Prepare decision request
	decisionReq := map[string]interface{}{}

	if input != nil {
		decisionReq["input"] = input
	}

	// Convert to JSON
	payload, err := json.Marshal(decisionReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal decision request: %w", err)
	}

	// Create request URL - use data API with specific path
	url := fmt.Sprintf("%s/v1/data/%s", s.baseURL, strings.TrimPrefix(path, "/"))
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute decision query: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("decision query failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var opaResponse struct {
		DecisionID string                 `json:"decision_id,omitempty"`
		Result     interface{}            `json:"result"`
		Metadata   map[string]interface{} `json:"metadata,omitempty"`
		Metrics    *service.OPAMetrics    `json:"metrics,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&opaResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract boolean decision from result
	decision := false
	reason := ""

	switch result := opaResponse.Result.(type) {
	case bool:
		decision = result
	case map[string]interface{}:
		// Look for common decision patterns
		if allow, exists := result["allow"]; exists {
			if allowBool, ok := allow.(bool); ok {
				decision = allowBool
			}
		} else if permitted, exists := result["permitted"]; exists {
			if permittedBool, ok := permitted.(bool); ok {
				decision = permittedBool
			}
		}

		// Extract reason if available
		if reasonVal, exists := result["reason"]; exists {
			if reasonStr, ok := reasonVal.(string); ok {
				reason = reasonStr
			}
		}
	case []interface{}:
		// For array results, check if non-empty (assuming non-empty means allowed)
		decision = len(result) > 0
	default:
		// For other types, consider non-nil as true
		decision = result != nil
	}

	return &service.OPADecisionResult{
		DecisionID: opaResponse.DecisionID,
		Result:     decision,
		Reason:     reason,
		Metadata:   opaResponse.Metadata,
		Metrics:    opaResponse.Metrics,
	}, nil
}

// Health and Status

func (s *OPAServiceImpl) HealthCheck(ctx context.Context) (*service.OPAHealthStatus, error) {
	// Create request
	url := fmt.Sprintf("%s/health", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return &service.OPAHealthStatus{
			Healthy:   false,
			Timestamp: time.Now(),
		}, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var healthResponse struct {
		Healthy bool   `json:"healthy,omitempty"`
		Version string `json:"version,omitempty"`
		Uptime  string `json:"uptime,omitempty"`
	}

	healthy := resp.StatusCode >= 200 && resp.StatusCode < 300

	if healthy {
		json.NewDecoder(resp.Body).Decode(&healthResponse)
	}

	return &service.OPAHealthStatus{
		Healthy:   healthy,
		Version:   healthResponse.Version,
		Uptime:    healthResponse.Uptime,
		Timestamp: time.Now(),
	}, nil
}

func (s *OPAServiceImpl) GetPolicyStatus(ctx context.Context) (*service.OPAPolicyStatus, error) {
	// Get policies
	policiesUrl := fmt.Sprintf("%s/v1/policies", s.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", policiesUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy status: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var policiesResponse struct {
		Result map[string]interface{} `json:"result"`
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		json.NewDecoder(resp.Body).Decode(&policiesResponse)
	}

	// Extract policy names
	policies := make([]string, 0)
	if policiesResponse.Result != nil {
		for policyName := range policiesResponse.Result {
			policies = append(policies, policyName)
		}
	}

	// Get data status
	dataStatus := make(map[string]string)
	// This would involve checking various data endpoints

	return &service.OPAPolicyStatus{
		Policies:    policies,
		Data:        dataStatus,
		Bundles:     []string{}, // Would populate from bundle API if using bundles
		Health:      resp.StatusCode >= 200 && resp.StatusCode < 300,
		LastUpdated: time.Now(),
	}, nil
}

// Helper methods

func (s *OPAServiceImpl) buildURL(path string) string {
	return fmt.Sprintf("%s%s", s.baseURL, path)
}

func (s *OPAServiceImpl) addAuthHeader(req *http.Request) {
	if s.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.apiToken))
	}
}

func (s *OPAServiceImpl) handleErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errorResponse struct {
		Code    string `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
		Errors  []struct {
			Code     string `json:"code"`
			Message  string `json:"message"`
			Location struct {
				File string `json:"file"`
				Row  int    `json:"row"`
				Col  int    `json:"col"`
			} `json:"location,omitempty"`
		} `json:"errors,omitempty"`
	}

	if err := json.Unmarshal(body, &errorResponse); err == nil {
		if errorResponse.Message != "" {
			return fmt.Errorf("OPA error: %s", errorResponse.Message)
		}
		if len(errorResponse.Errors) > 0 {
			return fmt.Errorf("OPA error: %s", errorResponse.Errors[0].Message)
		}
	}

	return fmt.Errorf("OPA request failed with status %d: %s", resp.StatusCode, string(body))
}

// Batch operations for performance

func (s *OPAServiceImpl) SetDataBatch(ctx context.Context, dataMap map[string]interface{}) error {
	for path, data := range dataMap {
		if err := s.SetData(ctx, path, data); err != nil {
			return fmt.Errorf("failed to set data for path %s: %w", path, err)
		}
	}
	return nil
}

func (s *OPAServiceImpl) QueryBatch(ctx context.Context, queries []string, input interface{}) ([]*service.OPAQueryResult, error) {
	results := make([]*service.OPAQueryResult, 0, len(queries))

	for _, query := range queries {
		result, err := s.Query(ctx, query, input)
		if err != nil {
			return nil, fmt.Errorf("batch query failed for query '%s': %w", query, err)
		}
		results = append(results, result)
	}

	return results, nil
}
