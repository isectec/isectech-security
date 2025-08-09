package authorization

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
)

// ABACService implements Attribute-Based Access Control with OPA integration
type ABACService struct {
	opaService     service.OPAService
	policyRepo     PolicyRepository
	attributeStore AttributeStore
	auditLogger    AuthorizationAuditLogger
	config         *ABACConfig
}

// ABACConfig holds ABAC service configuration
type ABACConfig struct {
	OPAEndpoint           string        `yaml:"opa_endpoint" default:"http://localhost:8181"`
	OPATimeout            time.Duration `yaml:"opa_timeout" default:"5s"`
	PolicyCacheTimeout    time.Duration `yaml:"policy_cache_timeout" default:"300s"`
	AttributeCacheTimeout time.Duration `yaml:"attribute_cache_timeout" default:"60s"`
	EnablePolicyTracing   bool          `yaml:"enable_policy_tracing" default:"false"`
	EnableMetrics         bool          `yaml:"enable_metrics" default:"true"`
	MaxPolicySize         int           `yaml:"max_policy_size" default:"1048576"` // 1MB
	DefaultDecision       bool          `yaml:"default_decision" default:"false"`
	PolicyNamespace       string        `yaml:"policy_namespace" default:"isectech"`
}

// Repository interfaces
type PolicyRepository interface {
	Create(ctx context.Context, policy *service.Policy) error
	Update(ctx context.Context, policy *service.Policy) error
	Delete(ctx context.Context, policyID string, tenantID uuid.UUID) error
	GetByID(ctx context.Context, policyID string, tenantID uuid.UUID) (*service.Policy, error)
	GetByName(ctx context.Context, name string, tenantID uuid.UUID) (*service.Policy, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, filters *service.PolicyFilters) ([]*service.Policy, error)
	GetActivePolicies(ctx context.Context, tenantID uuid.UUID) ([]*service.Policy, error)
}

type AttributeStore interface {
	SetUserAttributes(ctx context.Context, userID uuid.UUID, attributes map[string]interface{}) error
	GetUserAttributes(ctx context.Context, userID uuid.UUID) (map[string]interface{}, error)
	SetResourceAttributes(ctx context.Context, resourceID string, attributes map[string]interface{}) error
	GetResourceAttributes(ctx context.Context, resourceID string) (map[string]interface{}, error)
	SetEnvironmentAttributes(ctx context.Context, attributes map[string]interface{}) error
	GetEnvironmentAttributes(ctx context.Context) (map[string]interface{}, error)
	DeleteUserAttributes(ctx context.Context, userID uuid.UUID) error
	DeleteResourceAttributes(ctx context.Context, resourceID string) error
}

// NewABACService creates a new ABAC service
func NewABACService(
	opaService service.OPAService,
	policyRepo PolicyRepository,
	attributeStore AttributeStore,
	auditLogger AuthorizationAuditLogger,
	config *ABACConfig,
) *ABACService {
	return &ABACService{
		opaService:     opaService,
		policyRepo:     policyRepo,
		attributeStore: attributeStore,
		auditLogger:    auditLogger,
		config:         config,
	}
}

// Policy Management

func (s *ABACService) CreatePolicy(ctx context.Context, req *service.CreatePolicyRequest) (*service.CreatePolicyResponse, error) {
	// Validate policy content
	validationResult, err := s.ValidatePolicy(ctx, req.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to validate policy: %w", err)
	}

	if !validationResult.Valid {
		return nil, fmt.Errorf("policy validation failed: %v", validationResult.Errors)
	}

	// Check for name conflicts
	existing, _ := s.policyRepo.GetByName(ctx, req.Name, req.TenantID)
	if existing != nil {
		return nil, fmt.Errorf("policy with name '%s' already exists", req.Name)
	}

	// Compile policy
	compiled, err := s.CompilePolicy(ctx, req.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to compile policy: %w", err)
	}

	// Create policy entity
	policy := &service.Policy{
		ID:          generatePolicyID(req.TenantID, req.Name),
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Version:     req.Version,
		Content:     req.Content,
		Compiled:    compiled,
		Metadata:    req.Metadata,
		IsActive:    true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedBy:   req.CreatedBy,
		UpdatedBy:   req.CreatedBy,
	}

	// Save policy to repository
	if err := s.policyRepo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	// Deploy policy to OPA
	if err := s.opaService.DeployPolicy(ctx, policy.ID, req.Content); err != nil {
		// Rollback policy creation
		s.policyRepo.Delete(ctx, policy.ID, req.TenantID)
		return nil, fmt.Errorf("failed to deploy policy to OPA: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "policy_created",
		UserID:    &req.CreatedBy,
		PolicyID:  &policy.ID,
		Success:   true,
		Context:   map[string]interface{}{"policy_name": policy.Name, "version": policy.Version},
		CreatedAt: time.Now(),
	})

	return &service.CreatePolicyResponse{
		PolicyID:  policy.ID,
		CreatedAt: policy.CreatedAt,
	}, nil
}

func (s *ABACService) UpdatePolicy(ctx context.Context, req *service.UpdatePolicyRequest) error {
	// Get existing policy
	policy, err := s.policyRepo.GetByID(ctx, req.PolicyID, req.TenantID)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	updated := false

	// Update fields
	if req.Name != "" && req.Name != policy.Name {
		// Check for name conflicts
		existing, _ := s.policyRepo.GetByName(ctx, req.Name, req.TenantID)
		if existing != nil && existing.ID != policy.ID {
			return fmt.Errorf("policy with name '%s' already exists", req.Name)
		}
		policy.Name = req.Name
		updated = true
	}

	if req.Description != "" && req.Description != policy.Description {
		policy.Description = req.Description
		updated = true
	}

	if req.Version != "" && req.Version != policy.Version {
		policy.Version = req.Version
		updated = true
	}

	if req.Content != "" && req.Content != policy.Content {
		// Validate new content
		validationResult, err := s.ValidatePolicy(ctx, req.Content)
		if err != nil {
			return fmt.Errorf("failed to validate policy: %w", err)
		}

		if !validationResult.Valid {
			return fmt.Errorf("policy validation failed: %v", validationResult.Errors)
		}

		// Compile new content
		compiled, err := s.CompilePolicy(ctx, req.Content)
		if err != nil {
			return fmt.Errorf("failed to compile policy: %w", err)
		}

		policy.Content = req.Content
		policy.Compiled = compiled
		updated = true

		// Deploy updated policy to OPA
		if err := s.opaService.DeployPolicy(ctx, policy.ID, req.Content); err != nil {
			return fmt.Errorf("failed to deploy updated policy to OPA: %w", err)
		}
	}

	if req.Metadata != nil {
		policy.Metadata = req.Metadata
		updated = true
	}

	if req.IsActive != nil && *req.IsActive != policy.IsActive {
		policy.IsActive = *req.IsActive
		updated = true

		// Handle policy activation/deactivation in OPA
		if !*req.IsActive {
			// Remove policy from OPA
			if err := s.opaService.RemovePolicy(ctx, policy.ID); err != nil {
				return fmt.Errorf("failed to remove policy from OPA: %w", err)
			}
		} else {
			// Re-deploy policy to OPA
			if err := s.opaService.DeployPolicy(ctx, policy.ID, policy.Content); err != nil {
				return fmt.Errorf("failed to re-deploy policy to OPA: %w", err)
			}
		}
	}

	if !updated {
		return nil // No changes
	}

	// Update metadata
	policy.UpdatedAt = time.Now()
	policy.UpdatedBy = req.UpdatedBy

	// Save policy
	if err := s.policyRepo.Update(ctx, policy); err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.TenantID,
		EventType: "policy_updated",
		UserID:    &req.UpdatedBy,
		PolicyID:  &policy.ID,
		Success:   true,
		Context:   map[string]interface{}{"policy_name": policy.Name, "version": policy.Version},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *ABACService) DeletePolicy(ctx context.Context, policyID string, tenantID uuid.UUID) error {
	// Get policy
	policy, err := s.policyRepo.GetByID(ctx, policyID, tenantID)
	if err != nil {
		return fmt.Errorf("policy not found: %w", err)
	}

	// Remove policy from OPA
	if err := s.opaService.RemovePolicy(ctx, policyID); err != nil {
		return fmt.Errorf("failed to remove policy from OPA: %w", err)
	}

	// Delete policy from repository
	if err := s.policyRepo.Delete(ctx, policyID, tenantID); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	// Audit log
	s.auditLogger.LogRoleEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  tenantID,
		EventType: "policy_deleted",
		PolicyID:  &policyID,
		Success:   true,
		Context:   map[string]interface{}{"policy_name": policy.Name},
		CreatedAt: time.Now(),
	})

	return nil
}

func (s *ABACService) GetPolicy(ctx context.Context, policyID string, tenantID uuid.UUID) (*service.Policy, error) {
	return s.policyRepo.GetByID(ctx, policyID, tenantID)
}

func (s *ABACService) ListPolicies(ctx context.Context, tenantID uuid.UUID, filters *service.PolicyFilters) ([]*service.Policy, error) {
	return s.policyRepo.ListByTenant(ctx, tenantID, filters)
}

// Policy Evaluation

func (s *ABACService) EvaluatePolicy(ctx context.Context, req *service.PolicyEvaluationRequest) (*service.PolicyEvaluationResponse, error) {
	startTime := time.Now()

	// Get policy
	policy, err := s.policyRepo.GetByID(ctx, req.PolicyID, req.Context.TenantID)
	if err != nil {
		return nil, fmt.Errorf("policy not found: %w", err)
	}

	if !policy.IsActive {
		return &service.PolicyEvaluationResponse{
			PolicyID:    req.PolicyID,
			Decision:    s.config.DefaultDecision,
			Result:      nil,
			Explanation: "policy is not active",
			EvaluatedAt: startTime,
			Duration:    time.Since(startTime),
		}, nil
	}

	// Prepare input for OPA
	input := s.prepareOPAInput(req.Input, req.Context)

	// Set query path if not provided
	query := req.Query
	if query == "" {
		query = fmt.Sprintf("data.%s.%s.allow", s.config.PolicyNamespace, policy.Name)
	}

	// Evaluate policy with OPA
	result, err := s.opaService.QueryWithDecision(ctx, query, input)
	if err != nil {
		// Audit log for evaluation failure
		s.auditLogger.LogAccessEvent(ctx, &service.AuthorizationAuditEvent{
			ID:        uuid.New(),
			TenantID:  req.Context.TenantID,
			EventType: "policy_evaluation_failed",
			UserID:    &req.Context.UserID,
			PolicyID:  &req.PolicyID,
			Success:   false,
			Reason:    err.Error(),
			IPAddress: req.Context.IPAddress,
			Context:   map[string]interface{}{"input": req.Input},
			CreatedAt: time.Now(),
		})

		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	// Prepare response
	response := &service.PolicyEvaluationResponse{
		PolicyID:    req.PolicyID,
		Decision:    result.Result,
		Result:      result.Metadata,
		Explanation: result.Reason,
		EvaluatedAt: startTime,
		Duration:    time.Since(startTime),
	}

	// Add trace if enabled
	if s.config.EnablePolicyTracing {
		// Convert OPA trace to our format if available
		if result.Metrics != nil {
			response.Trace = s.convertOPATrace(result.Metadata)
		}
	}

	// Audit log for evaluation
	s.auditLogger.LogAccessEvent(ctx, &service.AuthorizationAuditEvent{
		ID:        uuid.New(),
		TenantID:  req.Context.TenantID,
		EventType: "policy_evaluated",
		UserID:    &req.Context.UserID,
		PolicyID:  &req.PolicyID,
		Success:   true,
		IPAddress: req.Context.IPAddress,
		Context: map[string]interface{}{
			"input":    req.Input,
			"decision": result.Result,
			"duration": response.Duration.String(),
		},
		CreatedAt: time.Now(),
	})

	return response, nil
}

func (s *ABACService) EvaluateMultiplePolicies(ctx context.Context, req *service.MultipleEvaluationRequest) (*service.MultipleEvaluationResponse, error) {
	startTime := time.Now()
	results := make([]*service.PolicyEvaluationResponse, 0, len(req.PolicyIDs))
	overallResult := true

	for _, policyID := range req.PolicyIDs {
		evalReq := &service.PolicyEvaluationRequest{
			PolicyID: policyID,
			Input:    req.Input,
			Context:  req.Context,
		}

		result, err := s.EvaluatePolicy(ctx, evalReq)
		if err != nil {
			// Log error but continue with other policies
			result = &service.PolicyEvaluationResponse{
				PolicyID:    policyID,
				Decision:    false,
				Explanation: fmt.Sprintf("evaluation error: %v", err),
				EvaluatedAt: time.Now(),
			}
		}

		results = append(results, result)

		// Overall result is true only if all policies allow
		if !result.Decision {
			overallResult = false
		}
	}

	return &service.MultipleEvaluationResponse{
		Results:       results,
		OverallResult: overallResult,
		EvaluatedAt:   startTime,
	}, nil
}

// Attribute Management

func (s *ABACService) SetUserAttributes(ctx context.Context, userID uuid.UUID, attributes map[string]interface{}) error {
	if err := s.attributeStore.SetUserAttributes(ctx, userID, attributes); err != nil {
		return fmt.Errorf("failed to set user attributes: %w", err)
	}

	// Update OPA data
	path := fmt.Sprintf("users/%s/attributes", userID.String())
	if err := s.opaService.SetData(ctx, path, attributes); err != nil {
		return fmt.Errorf("failed to update OPA user attributes: %w", err)
	}

	return nil
}

func (s *ABACService) GetUserAttributes(ctx context.Context, userID uuid.UUID) (map[string]interface{}, error) {
	return s.attributeStore.GetUserAttributes(ctx, userID)
}

func (s *ABACService) SetResourceAttributes(ctx context.Context, resourceID string, attributes map[string]interface{}) error {
	if err := s.attributeStore.SetResourceAttributes(ctx, resourceID, attributes); err != nil {
		return fmt.Errorf("failed to set resource attributes: %w", err)
	}

	// Update OPA data
	path := fmt.Sprintf("resources/%s/attributes", resourceID)
	if err := s.opaService.SetData(ctx, path, attributes); err != nil {
		return fmt.Errorf("failed to update OPA resource attributes: %w", err)
	}

	return nil
}

func (s *ABACService) GetResourceAttributes(ctx context.Context, resourceID string) (map[string]interface{}, error) {
	return s.attributeStore.GetResourceAttributes(ctx, resourceID)
}

// Policy compilation and validation

func (s *ABACService) ValidatePolicy(ctx context.Context, policyContent string) (*service.PolicyValidationResult, error) {
	// Basic syntax validation
	if policyContent == "" {
		return &service.PolicyValidationResult{
			Valid:  false,
			Errors: []string{"policy content cannot be empty"},
		}, nil
	}

	if len(policyContent) > s.config.MaxPolicySize {
		return &service.PolicyValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("policy size exceeds maximum limit (%d bytes)", s.config.MaxPolicySize)},
		}, nil
	}

	// Try to parse as Rego policy
	// This is a simplified validation - in practice, you would use OPA's AST parser
	if !s.isValidRego(policyContent) {
		return &service.PolicyValidationResult{
			Valid:  false,
			Errors: []string{"invalid Rego syntax"},
		}, nil
	}

	// Additional semantic validation can be added here
	warnings := make([]string, 0)

	// Check for common patterns that might be problematic
	if !s.containsDecisionRule(policyContent) {
		warnings = append(warnings, "policy does not contain a clear decision rule")
	}

	return &service.PolicyValidationResult{
		Valid:    true,
		Errors:   nil,
		Warnings: warnings,
	}, nil
}

func (s *ABACService) CompilePolicy(ctx context.Context, policyContent string) (*service.CompiledPolicy, error) {
	// Parse policy content to extract metadata
	modules := s.extractModules(policyContent)
	functions := s.extractFunctions(policyContent)
	rules := s.extractRules(policyContent)
	dependencies := s.extractDependencies(policyContent)

	compiled := &service.CompiledPolicy{
		Content:      policyContent,
		Modules:      modules,
		Functions:    functions,
		Rules:        rules,
		Dependencies: dependencies,
		Metadata: map[string]interface{}{
			"module_count":   len(modules),
			"function_count": len(functions),
			"rule_count":     len(rules),
		},
		CompiledAt: time.Now(),
	}

	return compiled, nil
}

// Helper methods

func (s *ABACService) prepareOPAInput(input map[string]interface{}, context *entity.PermissionContext) map[string]interface{} {
	opaInput := make(map[string]interface{})

	// Copy original input
	for k, v := range input {
		opaInput[k] = v
	}

	// Add context information
	if context != nil {
		opaInput["user"] = map[string]interface{}{
			"id":                 context.UserID.String(),
			"security_clearance": context.SecurityClearance,
			"roles":              context.Roles,
			"attributes":         context.Attributes,
		}

		opaInput["environment"] = map[string]interface{}{
			"ip_address":   context.IPAddress,
			"location":     context.Location,
			"request_time": context.RequestTime.Unix(),
			"session_info": context.SessionInfo,
		}

		opaInput["request"] = map[string]interface{}{
			"tenant_id": context.TenantID.String(),
			"context":   context.RequestContext,
		}
	}

	return opaInput
}

func (s *ABACService) convertOPATrace(metadata map[string]interface{}) []*service.PolicyTraceEvent {
	// Convert OPA trace format to our trace format
	// This is a simplified implementation
	trace := make([]*service.PolicyTraceEvent, 0)

	if traceData, exists := metadata["trace"]; exists {
		// Parse trace data and convert
		_ = traceData // Implementation would parse actual OPA trace
	}

	return trace
}

func (s *ABACService) isValidRego(content string) bool {
	// Simplified Rego validation
	// In practice, you would use OPA's AST parser
	return len(content) > 0 &&
		(contains(content, "package ") || contains(content, "default ") || contains(content, "allow"))
}

func (s *ABACService) containsDecisionRule(content string) bool {
	return contains(content, "allow") || contains(content, "deny")
}

func (s *ABACService) extractModules(content string) []string {
	// Extract module names from policy content
	modules := make([]string, 0)
	// Implementation would parse the content for module declarations
	return modules
}

func (s *ABACService) extractFunctions(content string) []string {
	// Extract function names from policy content
	functions := make([]string, 0)
	// Implementation would parse the content for function definitions
	return functions
}

func (s *ABACService) extractRules(content string) []string {
	// Extract rule names from policy content
	rules := make([]string, 0)
	// Implementation would parse the content for rule definitions
	return rules
}

func (s *ABACService) extractDependencies(content string) []string {
	// Extract dependencies from policy content
	dependencies := make([]string, 0)
	// Implementation would parse the content for import statements
	return dependencies
}

func generatePolicyID(tenantID uuid.UUID, name string) string {
	return fmt.Sprintf("%s_%s", tenantID.String()[:8], name)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
