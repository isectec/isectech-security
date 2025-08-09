package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"
)

// ILMManager handles Index Lifecycle Management for iSECTECH
type ILMManager struct {
	client *Client
	config *Config
	logger *zap.Logger
}

// ILMStatus represents the status of an ILM policy
type ILMStatus struct {
	PolicyName     string                 `json:"policy_name"`
	Version        int                    `json:"version"`
	ModifiedDate   time.Time              `json:"modified_date"`
	Policy         map[string]interface{} `json:"policy"`
	InUse          bool                   `json:"in_use"`
	LinkedIndices  []string               `json:"linked_indices"`
}

// IndexILMStatus represents the ILM status of an index
type IndexILMStatus struct {
	Index      string    `json:"index"`
	Policy     string    `json:"policy"`
	Phase      string    `json:"phase"`
	Action     string    `json:"action"`
	Step       string    `json:"step"`
	PhaseTime  time.Time `json:"phase_time"`
	ActionTime time.Time `json:"action_time"`
	StepTime   time.Time `json:"step_time"`
	Failed     bool      `json:"failed"`
	Error      string    `json:"error,omitempty"`
}

// NewILMManager creates a new ILM manager
func NewILMManager(client *Client, config *Config, logger *zap.Logger) (*ILMManager, error) {
	return &ILMManager{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// CreatePolicies creates all configured ILM policies
func (ilm *ILMManager) CreatePolicies(ctx context.Context) error {
	if !ilm.config.ILM.Enabled {
		ilm.logger.Info("ILM is disabled, skipping policy creation")
		return nil
	}

	ilm.logger.Info("Creating ILM policies")

	for policyName, policyConfig := range ilm.config.ILM.Policies {
		if err := ilm.CreatePolicy(ctx, policyName, policyConfig.Policy); err != nil {
			return fmt.Errorf("failed to create ILM policy %s: %w", policyName, err)
		}

		ilm.logger.Info("ILM policy created",
			zap.String("policy", policyName))
	}

	return nil
}

// CreatePolicy creates a single ILM policy
func (ilm *ILMManager) CreatePolicy(ctx context.Context, policyName string, policy map[string]interface{}) error {
	// Serialize policy
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	// Create policy request
	req := esapi.ILMPutLifecycleRequest{
		Policy: policyName,
		Body:   bytes.NewReader(policyBytes),
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to create ILM policy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create ILM policy failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// UpdatePolicy updates an existing ILM policy
func (ilm *ILMManager) UpdatePolicy(ctx context.Context, policyName string, policy map[string]interface{}) error {
	return ilm.CreatePolicy(ctx, policyName, policy) // PUT operation updates if exists
}

// DeletePolicy deletes an ILM policy
func (ilm *ILMManager) DeletePolicy(ctx context.Context, policyName string) error {
	req := esapi.ILMDeleteLifecycleRequest{
		Policy: policyName,
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to delete ILM policy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delete ILM policy failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// GetPolicy retrieves an ILM policy
func (ilm *ILMManager) GetPolicy(ctx context.Context, policyName string) (*ILMStatus, error) {
	req := esapi.ILMGetLifecycleRequest{
		Policy: policyName,
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get ILM policy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		if res.StatusCode == 404 {
			return nil, fmt.Errorf("ILM policy not found: %s", policyName)
		}
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get ILM policy failed with status %s: %s", res.Status(), string(body))
	}

	var response map[string]struct {
		Version      int                    `json:"version"`
		ModifiedDate string                 `json:"modified_date"`
		Policy       map[string]interface{} `json:"policy"`
		InUse        struct {
			Indices []string `json:"indices"`
		} `json:"in_use"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse ILM policy response: %w", err)
	}

	policyData, exists := response[policyName]
	if !exists {
		return nil, fmt.Errorf("policy not found in response: %s", policyName)
	}

	modifiedDate, _ := time.Parse(time.RFC3339, policyData.ModifiedDate)

	status := &ILMStatus{
		PolicyName:    policyName,
		Version:       policyData.Version,
		ModifiedDate:  modifiedDate,
		Policy:        policyData.Policy,
		InUse:         len(policyData.InUse.Indices) > 0,
		LinkedIndices: policyData.InUse.Indices,
	}

	return status, nil
}

// ListPolicies lists all ILM policies
func (ilm *ILMManager) ListPolicies(ctx context.Context) ([]ILMStatus, error) {
	req := esapi.ILMGetLifecycleRequest{}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to list ILM policies: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("list ILM policies failed with status %s: %s", res.Status(), string(body))
	}

	var response map[string]struct {
		Version      int                    `json:"version"`
		ModifiedDate string                 `json:"modified_date"`
		Policy       map[string]interface{} `json:"policy"`
		InUse        struct {
			Indices []string `json:"indices"`
		} `json:"in_use"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse ILM policies response: %w", err)
	}

	var policies []ILMStatus
	for policyName, policyData := range response {
		modifiedDate, _ := time.Parse(time.RFC3339, policyData.ModifiedDate)

		status := ILMStatus{
			PolicyName:    policyName,
			Version:       policyData.Version,
			ModifiedDate:  modifiedDate,
			Policy:        policyData.Policy,
			InUse:         len(policyData.InUse.Indices) > 0,
			LinkedIndices: policyData.InUse.Indices,
		}

		policies = append(policies, status)
	}

	return policies, nil
}

// GetIndexILMStatus gets the ILM status of indices
func (ilm *ILMManager) GetIndexILMStatus(ctx context.Context, indices ...string) ([]IndexILMStatus, error) {
	var indexNames []string
	if len(indices) > 0 {
		indexNames = indices
	} else {
		indexNames = []string{"*"}
	}

	req := esapi.ILMExplainLifecycleRequest{
		Index: indexNames,
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get index ILM status: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get index ILM status failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		Indices map[string]struct {
			Index           string `json:"index"`
			Managed         bool   `json:"managed"`
			Policy          string `json:"policy,omitempty"`
			Phase           string `json:"phase,omitempty"`
			Action          string `json:"action,omitempty"`
			Step            string `json:"step,omitempty"`
			PhaseTime       string `json:"phase_time,omitempty"`
			ActionTime      string `json:"action_time,omitempty"`
			StepTime        string `json:"step_time,omitempty"`
			Failed          bool   `json:"failed_step,omitempty"`
			StepInfo        map[string]interface{} `json:"step_info,omitempty"`
			PhaseExecution  map[string]interface{} `json:"phase_execution,omitempty"`
		} `json:"indices"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse index ILM status response: %w", err)
	}

	var statuses []IndexILMStatus
	for indexName, indexData := range response.Indices {
		if !indexData.Managed {
			continue // Skip unmanaged indices
		}

		phaseTime, _ := time.Parse(time.RFC3339, indexData.PhaseTime)
		actionTime, _ := time.Parse(time.RFC3339, indexData.ActionTime)
		stepTime, _ := time.Parse(time.RFC3339, indexData.StepTime)

		var errorMessage string
		if indexData.Failed && indexData.StepInfo != nil {
			if reason, ok := indexData.StepInfo["reason"].(string); ok {
				errorMessage = reason
			}
		}

		status := IndexILMStatus{
			Index:      indexName,
			Policy:     indexData.Policy,
			Phase:      indexData.Phase,
			Action:     indexData.Action,
			Step:       indexData.Step,
			PhaseTime:  phaseTime,
			ActionTime: actionTime,
			StepTime:   stepTime,
			Failed:     indexData.Failed,
			Error:      errorMessage,
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// MoveToStep moves an index to a specific ILM step
func (ilm *ILMManager) MoveToStep(ctx context.Context, index, currentStep, nextStep string) error {
	req := esapi.ILMMoveToStepRequest{
		Index: index,
		Body: bytes.NewReader([]byte(fmt.Sprintf(`{
			"current_step": {
				"phase": "hot",
				"action": "complete",
				"name": "%s"
			},
			"next_step": {
				"phase": "hot",
				"action": "complete",
				"name": "%s"
			}
		}`, currentStep, nextStep))),
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to move index to step: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("move to step failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// RetryPolicy retries failed ILM policy execution for an index
func (ilm *ILMManager) RetryPolicy(ctx context.Context, index string) error {
	req := esapi.ILMRetryRequest{
		Index: index,
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to retry ILM policy: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("retry ILM policy failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// GetILMStatus returns overall ILM status
func (ilm *ILMManager) GetILMStatus(ctx context.Context) (map[string]interface{}, error) {
	req := esapi.ILMGetStatusRequest{}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get ILM status: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get ILM status failed with status %s: %s", res.Status(), string(body))
	}

	var status map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to parse ILM status response: %w", err)
	}

	return status, nil
}

// StartILM starts the ILM service
func (ilm *ILMManager) StartILM(ctx context.Context) error {
	req := esapi.ILMStartRequest{}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to start ILM: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("start ILM failed with status %s: %s", res.Status(), string(body))
	}

	ilm.logger.Info("ILM service started")
	return nil
}

// StopILM stops the ILM service
func (ilm *ILMManager) StopILM(ctx context.Context) error {
	req := esapi.ILMStopRequest{}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to stop ILM: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("stop ILM failed with status %s: %s", res.Status(), string(body))
	}

	ilm.logger.Info("ILM service stopped")
	return nil
}

// MonitorPolicies monitors ILM policies and logs their status
func (ilm *ILMManager) MonitorPolicies(ctx context.Context) error {
	// Get all policies
	policies, err := ilm.ListPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}

	for _, policy := range policies {
		// Get index status for this policy
		indices, err := ilm.GetIndexILMStatus(ctx)
		if err != nil {
			ilm.logger.Error("Failed to get index ILM status",
				zap.String("policy", policy.PolicyName),
				zap.Error(err))
			continue
		}

		// Filter indices by policy
		var policyIndices []IndexILMStatus
		for _, index := range indices {
			if index.Policy == policy.PolicyName {
				policyIndices = append(policyIndices, index)
			}
		}

		// Log policy status
		failedCount := 0
		for _, index := range policyIndices {
			if index.Failed {
				failedCount++
			}
		}

		ilm.logger.Info("ILM policy status",
			zap.String("policy", policy.PolicyName),
			zap.Int("total_indices", len(policyIndices)),
			zap.Int("failed_indices", failedCount),
			zap.Bool("in_use", policy.InUse))

		// Log failed indices
		if failedCount > 0 {
			for _, index := range policyIndices {
				if index.Failed {
					ilm.logger.Error("ILM policy failed for index",
						zap.String("policy", policy.PolicyName),
						zap.String("index", index.Index),
						zap.String("phase", index.Phase),
						zap.String("action", index.Action),
						zap.String("step", index.Step),
						zap.String("error", index.Error))
				}
			}
		}
	}

	return nil
}

// ValidatePolicies validates all configured ILM policies
func (ilm *ILMManager) ValidatePolicies(ctx context.Context) error {
	ilm.logger.Info("Validating ILM policies")

	for policyName := range ilm.config.ILM.Policies {
		// Check if policy exists
		_, err := ilm.GetPolicy(ctx, policyName)
		if err != nil {
			return fmt.Errorf("policy validation failed for %s: %w", policyName, err)
		}

		ilm.logger.Info("ILM policy validated",
			zap.String("policy", policyName))
	}

	return nil
}

// CleanupFailedPolicies attempts to retry failed ILM policies
func (ilm *ILMManager) CleanupFailedPolicies(ctx context.Context) error {
	// Get all index ILM statuses
	statuses, err := ilm.GetIndexILMStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get index ILM statuses: %w", err)
	}

	retryCount := 0
	for _, status := range statuses {
		if status.Failed {
			ilm.logger.Info("Retrying failed ILM policy",
				zap.String("index", status.Index),
				zap.String("policy", status.Policy),
				zap.String("error", status.Error))

			if err := ilm.RetryPolicy(ctx, status.Index); err != nil {
				ilm.logger.Error("Failed to retry ILM policy",
					zap.String("index", status.Index),
					zap.Error(err))
			} else {
				retryCount++
			}
		}
	}

	ilm.logger.Info("ILM cleanup completed",
		zap.Int("retried_policies", retryCount))

	return nil
}

// SetPollInterval updates the ILM poll interval
func (ilm *ILMManager) SetPollInterval(ctx context.Context, interval time.Duration) error {
	settings := map[string]interface{}{
		"persistent": map[string]interface{}{
			"indices.lifecycle.poll_interval": interval.String(),
		},
	}

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to serialize settings: %w", err)
	}

	req := esapi.ClusterPutSettingsRequest{
		Body: bytes.NewReader(settingsBytes),
	}

	res, err := req.Do(ctx, ilm.client.client)
	if err != nil {
		return fmt.Errorf("failed to update ILM poll interval: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("update ILM poll interval failed with status %s: %s", res.Status(), string(body))
	}

	ilm.logger.Info("ILM poll interval updated",
		zap.Duration("interval", interval))

	return nil
}