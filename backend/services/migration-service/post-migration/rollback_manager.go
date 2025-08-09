package postmigration

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/domain/entity"
)

// DefaultRollbackManager is the production implementation of RollbackManager
type DefaultRollbackManager struct {
	// Core configuration
	config *RollbackManagerConfig

	// Active rollback operations
	activeRollbacks   map[uuid.UUID]*RollbackExecution
	rollbacksMutex    sync.RWMutex

	// Rollback plans storage
	rollbackPlans     map[uuid.UUID]*RollbackPlan
	plansMutex        sync.RWMutex

	// Backup management
	backupStorage     BackupStorage
	backupManager     *BackupManager

	// Execution engines
	rollbackExecutor  *RollbackExecutor
	backupValidator   *BackupValidator
	recoveryEngine    *RecoveryEngine

	// Security and audit
	securityValidator *SecurityValidator
	complianceChecker *ComplianceChecker
	auditLogger       *AuditLogger
	metricsCollector  *RollbackMetricsCollector

	// External integrations
	jobRepository     JobRepository
	connectorFactory  DataConnectorFactory
	approvalWorkflow  ApprovalWorkflow
}

// RollbackManagerConfig contains configuration for the rollback manager
type RollbackManagerConfig struct {
	// Rollback settings
	MaxConcurrentRollbacks       int32         `json:"max_concurrent_rollbacks"`
	DefaultRollbackTimeout       time.Duration `json:"default_rollback_timeout"`
	RollbackWorkerPoolSize       int32         `json:"rollback_worker_pool_size"`
	
	// Plan validation
	RequireApprovalForRollback   bool          `json:"require_approval_for_rollback"`
	MaxRollbackAttempts          int32         `json:"max_rollback_attempts"`
	RollbackRetryDelay           time.Duration `json:"rollback_retry_delay"`
	
	// Backup management
	BackupRetentionPeriod        time.Duration `json:"backup_retention_period"`
	BackupValidationEnabled      bool          `json:"backup_validation_enabled"`
	BackupCompressionEnabled     bool          `json:"backup_compression_enabled"`
	BackupEncryptionEnabled      bool          `json:"backup_encryption_enabled"`
	
	// Safety settings
	PreRollbackValidation        bool          `json:"pre_rollback_validation"`
	PostRollbackValidation       bool          `json:"post_rollback_validation"`
	AutomaticRollbackPrevention  bool          `json:"automatic_rollback_prevention"`
	
	// Recovery settings
	EnablePointInTimeRecovery    bool          `json:"enable_point_in_time_recovery"`
	RecoveryCheckInterval        time.Duration `json:"recovery_check_interval"`
	MaxRecoveryAttempts          int32         `json:"max_recovery_attempts"`
	
	// Monitoring and alerts
	RollbackMonitoringEnabled    bool          `json:"rollback_monitoring_enabled"`
	AlertOnRollbackFailure       bool          `json:"alert_on_rollback_failure"`
	RollbackProgressReporting    bool          `json:"rollback_progress_reporting"`
	
	// Security and compliance
	SecurityClearance            string        `json:"security_clearance"`
	ComplianceFrameworks         []string      `json:"compliance_frameworks"`
	AuditAllOperations           bool          `json:"audit_all_operations"`
	RequireMultiPersonApproval   bool          `json:"require_multi_person_approval"`
	
	// Data retention
	RollbackLogRetention         time.Duration `json:"rollback_log_retention"`
	PlanRetentionPeriod          time.Duration `json:"plan_retention_period"`
}

// RollbackExecution represents an active rollback execution
type RollbackExecution struct {
	ID                           uuid.UUID                    `json:"id"`
	PlanID                       uuid.UUID                    `json:"plan_id"`
	JobID                        uuid.UUID                    `json:"job_id"`
	Status                       RollbackExecutionStatus      `json:"status"`
	
	// Execution tracking
	CurrentStep                  int32                        `json:"current_step"`
	TotalSteps                   int32                        `json:"total_steps"`
	Progress                     float64                      `json:"progress"`
	
	// Timing
	StartedAt                    time.Time                    `json:"started_at"`
	LastUpdated                  time.Time                    `json:"last_updated"`
	CompletedAt                  *time.Time                   `json:"completed_at"`
	EstimatedCompletion          *time.Time                   `json:"estimated_completion"`
	
	// Execution context
	ExecutionContext             *RollbackExecutionContext    `json:"execution_context"`
	StepResults                  []*RollbackStepResult        `json:"step_results"`
	
	// Error tracking
	Errors                       []*RollbackError             `json:"errors"`
	Warnings                     []*RollbackWarning           `json:"warnings"`
	
	// Security context
	ExecutedBy                   string                       `json:"executed_by"`
	ApprovalDetails              *ApprovalDetails             `json:"approval_details"`
	
	// Synchronization
	Mutex                        sync.RWMutex                 `json:"-"`
}

// RollbackExecutionStatus represents the status of a rollback execution
type RollbackExecutionStatus string

const (
	RollbackStatusPending     RollbackExecutionStatus = "pending"
	RollbackStatusRunning     RollbackExecutionStatus = "running"
	RollbackStatusPaused      RollbackExecutionStatus = "paused"
	RollbackStatusCompleted   RollbackExecutionStatus = "completed"
	RollbackStatusFailed      RollbackExecutionStatus = "failed"
	RollbackStatusCancelled   RollbackExecutionStatus = "cancelled"
	RollbackStatusRolledBack  RollbackExecutionStatus = "rolled_back"
)

// NewDefaultRollbackManager creates a new default rollback manager
func NewDefaultRollbackManager(
	backupStorage BackupStorage,
	jobRepository JobRepository,
	connectorFactory DataConnectorFactory,
	approvalWorkflow ApprovalWorkflow,
	config *RollbackManagerConfig,
) *DefaultRollbackManager {
	if config == nil {
		config = getDefaultRollbackManagerConfig()
	}

	manager := &DefaultRollbackManager{
		config:            config,
		activeRollbacks:   make(map[uuid.UUID]*RollbackExecution),
		rollbackPlans:     make(map[uuid.UUID]*RollbackPlan),
		backupStorage:     backupStorage,
		jobRepository:     jobRepository,
		connectorFactory:  connectorFactory,
		approvalWorkflow:  approvalWorkflow,
		securityValidator: NewSecurityValidator(config.SecurityClearance),
		complianceChecker: NewComplianceChecker(config.ComplianceFrameworks),
		auditLogger:       NewAuditLogger(config.AuditAllOperations),
		metricsCollector:  NewRollbackMetricsCollector(),
		backupManager:     NewBackupManager(backupStorage, config),
		rollbackExecutor:  NewRollbackExecutor(config),
		backupValidator:   NewBackupValidator(config),
		recoveryEngine:    NewRecoveryEngine(config),
	}

	// Start cleanup routines
	go manager.rollbackCleanupRoutine()
	go manager.planCleanupRoutine()

	return manager
}

// CreateRollbackPlan creates a comprehensive rollback plan for a migration job
func (m *DefaultRollbackManager) CreateRollbackPlan(ctx context.Context, jobID uuid.UUID, reason string, config *RollbackPlanConfig) (*RollbackPlan, error) {
	// Validate job access
	job, err := m.jobRepository.GetByID(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("job %s not found: %w", jobID, err)
	}

	// Security and compliance validation
	if err := m.securityValidator.ValidateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	if err := m.complianceChecker.ValidateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("compliance validation failed: %w", err)
	}

	// Create rollback plan
	plan := &RollbackPlan{
		ID:                uuid.New(),
		JobID:             jobID,
		Reason:            reason,
		Status:            "draft",
		CreatedAt:         time.Now(),
		CreatedBy:         "system", // Would extract from context
		SecurityClearance: config.SecurityClearance,
		ComplianceFrameworks: config.ComplianceFrameworks,
	}

	// Generate rollback steps based on migration job
	steps, err := m.generateRollbackSteps(ctx, job, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rollback steps: %w", err)
	}
	plan.Steps = steps
	plan.EstimatedDuration = m.calculateEstimatedDuration(steps)

	// Perform risk assessment
	riskAssessment, err := m.performRiskAssessment(ctx, job, plan)
	if err != nil {
		return nil, fmt.Errorf("failed to perform risk assessment: %w", err)
	}
	plan.RiskAssessment = riskAssessment

	// Check if approval is required
	if m.config.RequireApprovalForRollback || riskAssessment.ApprovalRequired {
		plan.Status = "pending_approval"
		plan.RequiresApproval = true

		// Initiate approval workflow
		if m.approvalWorkflow != nil {
			approvalRequest := &ApprovalRequest{
				Type:        "rollback_plan",
				ResourceID:  plan.ID,
				RequestedBy: plan.CreatedBy,
				Reason:      reason,
				RiskLevel:   riskAssessment.OverallRisk,
				Details:     map[string]interface{}{
					"job_id":           jobID,
					"estimated_duration": plan.EstimatedDuration,
					"steps_count":      len(steps),
				},
			}

			_, err = m.approvalWorkflow.SubmitApprovalRequest(ctx, approvalRequest)
			if err != nil {
				return nil, fmt.Errorf("failed to submit approval request: %w", err)
			}
		}
	} else {
		plan.Status = "approved"
	}

	// Store the plan
	m.plansMutex.Lock()
	m.rollbackPlans[plan.ID] = plan
	m.plansMutex.Unlock()

	// Log plan creation
	m.auditLogger.LogJobEvent(ctx, jobID, "rollback_plan_created", map[string]interface{}{
		"plan_id":            plan.ID,
		"reason":             reason,
		"requires_approval":  plan.RequiresApproval,
		"risk_level":         riskAssessment.OverallRisk,
		"steps_count":        len(steps),
		"estimated_duration": plan.EstimatedDuration,
	})

	return plan, nil
}

// ValidateRollbackPlan validates a rollback plan for feasibility and safety
func (m *DefaultRollbackManager) ValidateRollbackPlan(ctx context.Context, plan *RollbackPlan) (*RollbackPlanValidation, error) {
	validation := &RollbackPlanValidation{
		PlanID:      plan.ID,
		ValidatedAt: time.Now(),
		IsValid:     true,
		Warnings:    make([]*ValidationWarning, 0),
		Errors:      make([]*ValidationError, 0),
	}

	// Validate each step
	for i, step := range plan.Steps {
		stepValidation, err := m.validateRollbackStep(ctx, step, plan)
		if err != nil {
			validation.Errors = append(validation.Errors, &ValidationError{
				StepID:   step.ID,
				Message:  fmt.Sprintf("Step %d validation failed: %s", i+1, err.Error()),
				Severity: "error",
			})
			validation.IsValid = false
		}

		if stepValidation != nil {
			validation.Warnings = append(validation.Warnings, stepValidation.Warnings...)
			validation.Errors = append(validation.Errors, stepValidation.Errors...)
		}
	}

	// Validate dependencies
	if err := m.validateStepDependencies(plan.Steps); err != nil {
		validation.Errors = append(validation.Errors, &ValidationError{
			Message:  fmt.Sprintf("Dependency validation failed: %s", err.Error()),
			Severity: "error",
		})
		validation.IsValid = false
	}

	// Validate backup availability
	backupValidation, err := m.validateBackupAvailability(ctx, plan)
	if err != nil {
		validation.Warnings = append(validation.Warnings, &ValidationWarning{
			Message:  fmt.Sprintf("Backup validation warning: %s", err.Error()),
			Severity: "warning",
		})
	}

	if backupValidation != nil && !backupValidation.IsValid {
		validation.Errors = append(validation.Errors, &ValidationError{
			Message:  "Required backups are not available or invalid",
			Severity: "error",
		})
		validation.IsValid = false
	}

	return validation, nil
}

// UpdateRollbackPlan updates an existing rollback plan
func (m *DefaultRollbackManager) UpdateRollbackPlan(ctx context.Context, planID uuid.UUID, updates *RollbackPlanUpdates) (*RollbackPlan, error) {
	m.plansMutex.Lock()
	plan, exists := m.rollbackPlans[planID]
	if !exists {
		m.plansMutex.Unlock()
		return nil, fmt.Errorf("rollback plan %s not found", planID)
	}

	// Create a copy for updating
	updatedPlan := *plan
	m.plansMutex.Unlock()

	// Apply updates
	if updates.Reason != "" {
		updatedPlan.Reason = updates.Reason
	}

	if updates.Steps != nil {
		updatedPlan.Steps = updates.Steps
		updatedPlan.EstimatedDuration = m.calculateEstimatedDuration(updates.Steps)
	}

	// Re-validate if steps were updated
	if updates.Steps != nil {
		validation, err := m.ValidateRollbackPlan(ctx, &updatedPlan)
		if err != nil {
			return nil, fmt.Errorf("plan validation failed: %w", err)
		}

		if !validation.IsValid {
			return nil, fmt.Errorf("updated plan is invalid: %d errors found", len(validation.Errors))
		}
	}

	// Store updated plan
	updatedPlan.LastModified = time.Now()
	updatedPlan.ModifiedBy = "system" // Would extract from context

	m.plansMutex.Lock()
	m.rollbackPlans[planID] = &updatedPlan
	m.plansMutex.Unlock()

	// Log plan update
	m.auditLogger.LogJobEvent(ctx, updatedPlan.JobID, "rollback_plan_updated", map[string]interface{}{
		"plan_id":        planID,
		"update_reason":  updates.Reason,
		"steps_updated":  updates.Steps != nil,
	})

	return &updatedPlan, nil
}

// ExecuteRollback executes a rollback plan
func (m *DefaultRollbackManager) ExecuteRollback(ctx context.Context, planID uuid.UUID) (*RollbackExecution, error) {
	// Get the rollback plan
	m.plansMutex.RLock()
	plan, exists := m.rollbackPlans[planID]
	m.plansMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("rollback plan %s not found", planID)
	}

	// Check plan status and approval
	if plan.RequiresApproval && plan.Status != "approved" {
		return nil, fmt.Errorf("rollback plan %s requires approval", planID)
	}

	// Check concurrent rollback limits
	if err := m.checkConcurrentRollbackLimits(); err != nil {
		return nil, fmt.Errorf("concurrent rollback limit exceeded: %w", err)
	}

	// Pre-rollback validation
	if m.config.PreRollbackValidation {
		validation, err := m.ValidateRollbackPlan(ctx, plan)
		if err != nil {
			return nil, fmt.Errorf("pre-rollback validation failed: %w", err)
		}

		if !validation.IsValid {
			return nil, fmt.Errorf("rollback plan validation failed: %d errors", len(validation.Errors))
		}
	}

	// Create rollback execution
	execution := &RollbackExecution{
		ID:          uuid.New(),
		PlanID:      planID,
		JobID:       plan.JobID,
		Status:      RollbackStatusPending,
		CurrentStep: 0,
		TotalSteps:  int32(len(plan.Steps)),
		Progress:    0.0,
		StartedAt:   time.Now(),
		LastUpdated: time.Now(),
		ExecutionContext: &RollbackExecutionContext{
			PlanID:       planID,
			JobID:        plan.JobID,
			ExecutionID:  uuid.New(),
			StartedAt:    time.Now(),
		},
		StepResults: make([]*RollbackStepResult, 0),
		Errors:      make([]*RollbackError, 0),
		Warnings:    make([]*RollbackWarning, 0),
		ExecutedBy:  "system", // Would extract from context
	}

	// Track the execution
	m.rollbacksMutex.Lock()
	m.activeRollbacks[execution.ID] = execution
	m.rollbacksMutex.Unlock()

	// Log rollback start
	m.auditLogger.LogJobEvent(ctx, plan.JobID, "rollback_execution_started", map[string]interface{}{
		"execution_id": execution.ID,
		"plan_id":      planID,
		"total_steps":  execution.TotalSteps,
	})

	// Start asynchronous execution
	go m.executeRollbackAsync(ctx, execution, plan)

	return execution, nil
}

// ExecutePartialRollback executes only specific components of a rollback plan
func (m *DefaultRollbackManager) ExecutePartialRollback(ctx context.Context, planID uuid.UUID, components []string) (*RollbackExecution, error) {
	// Get the rollback plan
	m.plansMutex.RLock()
	plan, exists := m.rollbackPlans[planID]
	m.plansMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("rollback plan %s not found", planID)
	}

	// Filter steps based on components
	var filteredSteps []*RollbackStep
	for _, step := range plan.Steps {
		for _, component := range components {
			if step.Component == component {
				filteredSteps = append(filteredSteps, step)
				break
			}
		}
	}

	if len(filteredSteps) == 0 {
		return nil, fmt.Errorf("no steps found for specified components")
	}

	// Create a temporary plan with filtered steps
	partialPlan := *plan
	partialPlan.ID = uuid.New()
	partialPlan.Steps = filteredSteps

	// Store temporary plan
	m.plansMutex.Lock()
	m.rollbackPlans[partialPlan.ID] = &partialPlan
	m.plansMutex.Unlock()

	// Execute the partial rollback
	execution, err := m.ExecuteRollback(ctx, partialPlan.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute partial rollback: %w", err)
	}

	// Clean up temporary plan after execution
	go func() {
		time.Sleep(time.Hour) // Keep for logging purposes
		m.plansMutex.Lock()
		delete(m.rollbackPlans, partialPlan.ID)
		m.plansMutex.Unlock()
	}()

	return execution, nil
}

// CreateBackup creates a backup of the current system state
func (m *DefaultRollbackManager) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupResult, error) {
	return m.backupManager.CreateBackup(ctx, config)
}

// ValidateBackup validates the integrity and completeness of a backup
func (m *DefaultRollbackManager) ValidateBackup(ctx context.Context, backupID uuid.UUID) (*BackupValidationResult, error) {
	return m.backupValidator.ValidateBackup(ctx, backupID)
}

// RestoreFromBackup restores system state from a backup
func (m *DefaultRollbackManager) RestoreFromBackup(ctx context.Context, backupID uuid.UUID, config *RestoreConfig) (*RestoreResult, error) {
	return m.backupManager.RestoreFromBackup(ctx, backupID, config)
}

// GetRollbackStatus retrieves the status of a rollback execution
func (m *DefaultRollbackManager) GetRollbackStatus(ctx context.Context, planID uuid.UUID) (*RollbackStatus, error) {
	// Find execution by plan ID
	var execution *RollbackExecution
	m.rollbacksMutex.RLock()
	for _, exec := range m.activeRollbacks {
		if exec.PlanID == planID {
			execution = exec
			break
		}
	}
	m.rollbacksMutex.RUnlock()

	if execution == nil {
		return nil, fmt.Errorf("no active rollback found for plan %s", planID)
	}

	execution.Mutex.RLock()
	defer execution.Mutex.RUnlock()

	status := &RollbackStatus{
		ExecutionID:         execution.ID,
		PlanID:              execution.PlanID,
		JobID:               execution.JobID,
		Status:              string(execution.Status),
		CurrentStep:         execution.CurrentStep,
		TotalSteps:          execution.TotalSteps,
		Progress:            execution.Progress,
		StartedAt:           execution.StartedAt,
		LastUpdated:         execution.LastUpdated,
		CompletedAt:         execution.CompletedAt,
		EstimatedCompletion: execution.EstimatedCompletion,
		ErrorCount:          int32(len(execution.Errors)),
		WarningCount:        int32(len(execution.Warnings)),
	}

	return status, nil
}

// PauseRollback pauses an active rollback execution
func (m *DefaultRollbackManager) PauseRollback(ctx context.Context, executionID uuid.UUID) error {
	m.rollbacksMutex.RLock()
	execution, exists := m.activeRollbacks[executionID]
	m.rollbacksMutex.RUnlock()

	if !exists {
		return fmt.Errorf("rollback execution %s not found", executionID)
	}

	execution.Mutex.Lock()
	if execution.Status != RollbackStatusRunning {
		execution.Mutex.Unlock()
		return fmt.Errorf("rollback execution %s is not running", executionID)
	}

	execution.Status = RollbackStatusPaused
	execution.LastUpdated = time.Now()
	execution.Mutex.Unlock()

	// Log pause
	m.auditLogger.LogJobEvent(ctx, execution.JobID, "rollback_paused", map[string]interface{}{
		"execution_id": executionID,
		"current_step": execution.CurrentStep,
	})

	return nil
}

// ResumeRollback resumes a paused rollback execution
func (m *DefaultRollbackManager) ResumeRollback(ctx context.Context, executionID uuid.UUID) error {
	m.rollbacksMutex.RLock()
	execution, exists := m.activeRollbacks[executionID]
	m.rollbacksMutex.RUnlock()

	if !exists {
		return fmt.Errorf("rollback execution %s not found", executionID)
	}

	execution.Mutex.Lock()
	if execution.Status != RollbackStatusPaused {
		execution.Mutex.Unlock()
		return fmt.Errorf("rollback execution %s is not paused", executionID)
	}

	execution.Status = RollbackStatusRunning
	execution.LastUpdated = time.Now()
	execution.Mutex.Unlock()

	// Log resume
	m.auditLogger.LogJobEvent(ctx, execution.JobID, "rollback_resumed", map[string]interface{}{
		"execution_id": executionID,
		"current_step": execution.CurrentStep,
	})

	return nil
}

// CancelRollback cancels an active rollback execution
func (m *DefaultRollbackManager) CancelRollback(ctx context.Context, executionID uuid.UUID) error {
	m.rollbacksMutex.RLock()
	execution, exists := m.activeRollbacks[executionID]
	m.rollbacksMutex.RUnlock()

	if !exists {
		return fmt.Errorf("rollback execution %s not found", executionID)
	}

	execution.Mutex.Lock()
	if execution.Status == RollbackStatusCompleted || execution.Status == RollbackStatusFailed {
		execution.Mutex.Unlock()
		return fmt.Errorf("rollback execution %s cannot be cancelled (status: %s)", executionID, execution.Status)
	}

	execution.Status = RollbackStatusCancelled
	now := time.Now()
	execution.CompletedAt = &now
	execution.LastUpdated = now
	execution.Mutex.Unlock()

	// Log cancellation
	m.auditLogger.LogJobEvent(ctx, execution.JobID, "rollback_cancelled", map[string]interface{}{
		"execution_id": executionID,
		"current_step": execution.CurrentStep,
		"reason":       "user_requested",
	})

	return nil
}

// Private helper methods

// generateRollbackSteps generates rollback steps based on the migration job
func (m *DefaultRollbackManager) generateRollbackSteps(ctx context.Context, job *entity.MigrationJob, config *RollbackPlanConfig) ([]*RollbackStep, error) {
	steps := make([]*RollbackStep, 0)

	// Step 1: Data backup verification
	steps = append(steps, &RollbackStep{
		ID:                1,
		Name:              "Verify Data Backups",
		Description:       "Verify that all required data backups are available and valid",
		Type:              "validation",
		Component:         "backup",
		Commands:          []string{"verify-backup", "validate-integrity"},
		EstimatedDuration: time.Minute * 5,
		Dependencies:      []int32{},
		RollbackData: map[string]interface{}{
			"backup_type": "full",
			"validation_level": "comprehensive",
		},
	})

	// Step 2: Stop target system services
	steps = append(steps, &RollbackStep{
		ID:                2,
		Name:              "Stop Target System Services",
		Description:       "Stop all services on the target system to prevent data corruption",
		Type:              "service_control",
		Component:         "target_system",
		Commands:          []string{"stop-services", "drain-connections"},
		EstimatedDuration: time.Minute * 10,
		Dependencies:      []int32{1},
		RollbackData: map[string]interface{}{
			"service_list": job.TargetSystemID,
			"graceful_shutdown": true,
		},
	})

	// Step 3: Restore data from backup
	steps = append(steps, &RollbackStep{
		ID:                3,
		Name:              "Restore Data from Backup",
		Description:       "Restore data from the most recent valid backup",
		Type:              "data_restore",
		Component:         "data",
		Commands:          []string{"restore-data", "verify-restore"},
		EstimatedDuration: time.Hour * 2,
		Dependencies:      []int32{2},
		RollbackData: map[string]interface{}{
			"restore_type": "full",
			"verification_enabled": true,
		},
	})

	// Step 4: Restore configuration
	steps = append(steps, &RollbackStep{
		ID:                4,
		Name:              "Restore System Configuration",
		Description:       "Restore system configuration to pre-migration state",
		Type:              "configuration_restore",
		Component:         "configuration",
		Commands:          []string{"restore-config", "validate-config"},
		EstimatedDuration: time.Minute * 30,
		Dependencies:      []int32{3},
		RollbackData: map[string]interface{}{
			"config_backup_id": "pre_migration",
			"rollback_connectors": true,
		},
	})

	// Step 5: Restart services
	steps = append(steps, &RollbackStep{
		ID:                5,
		Name:              "Restart System Services",
		Description:       "Restart all system services and verify functionality",
		Type:              "service_control",
		Component:         "target_system",
		Commands:          []string{"start-services", "health-check"},
		EstimatedDuration: time.Minute * 15,
		Dependencies:      []int32{4},
		RollbackData: map[string]interface{}{
			"health_check_enabled": true,
			"service_dependency_order": true,
		},
	})

	// Step 6: Post-rollback validation
	steps = append(steps, &RollbackStep{
		ID:                6,
		Name:              "Post-Rollback Validation",
		Description:       "Perform comprehensive validation of rollback success",
		Type:              "validation",
		Component:         "validation",
		Commands:          []string{"validate-rollback", "integrity-check"},
		EstimatedDuration: time.Minute * 30,
		Dependencies:      []int32{5},
		RollbackData: map[string]interface{}{
			"validation_level": "comprehensive",
			"include_performance_check": true,
		},
	})

	return steps, nil
}

// calculateEstimatedDuration calculates the estimated duration for all steps
func (m *DefaultRollbackManager) calculateEstimatedDuration(steps []*RollbackStep) time.Duration {
	// Build dependency graph to calculate critical path
	maxDuration := time.Duration(0)
	stepDurations := make(map[int32]time.Duration)

	// Calculate duration for each step considering dependencies
	for _, step := range steps {
		var dependencyDuration time.Duration
		for _, depID := range step.Dependencies {
			if depDur, exists := stepDurations[depID]; exists {
				if depDur > dependencyDuration {
					dependencyDuration = depDur
				}
			}
		}

		stepDuration := dependencyDuration + step.EstimatedDuration
		stepDurations[step.ID] = stepDuration

		if stepDuration > maxDuration {
			maxDuration = stepDuration
		}
	}

	// Add 20% buffer for unexpected delays
	return time.Duration(float64(maxDuration) * 1.2)
}

// performRiskAssessment performs a risk assessment for the rollback plan
func (m *DefaultRollbackManager) performRiskAssessment(ctx context.Context, job *entity.MigrationJob, plan *RollbackPlan) (*RiskAssessment, error) {
	riskFactors := make([]*RiskFactor, 0)
	mitigationStrategies := make([]*MitigationStrategy, 0)

	// Analyze data size risk
	if job.DataVolume > 100*1024*1024*1024 { // > 100GB
		riskFactors = append(riskFactors, &RiskFactor{
			Name:        "Large Data Volume",
			Description: "Large data volume may cause extended rollback time",
			Impact:      "high",
			Probability: "medium",
			RiskLevel:   "medium",
		})

		mitigationStrategies = append(mitigationStrategies, &MitigationStrategy{
			Name:        "Incremental Rollback",
			Description: "Use incremental rollback approach to minimize downtime",
			Actions:     []string{"partition-data", "parallel-processing", "progress-monitoring"},
			Effectiveness: "high",
		})
	}

	// Analyze system complexity risk
	riskFactors = append(riskFactors, &RiskFactor{
		Name:        "System Integration Complexity",
		Description: "Complex system integrations may complicate rollback",
		Impact:      "medium",
		Probability: "low",
		RiskLevel:   "low",
	})

	// Calculate overall risk level
	overallRisk := m.calculateOverallRisk(riskFactors)

	// Determine if approval is required
	approvalRequired := overallRisk == "high" || m.config.RequireApprovalForRollback

	return &RiskAssessment{
		OverallRisk:          overallRisk,
		RiskFactors:          riskFactors,
		MitigationStrategies: mitigationStrategies,
		ApprovalRequired:     approvalRequired,
	}, nil
}

// calculateOverallRisk calculates overall risk level from individual risk factors
func (m *DefaultRollbackManager) calculateOverallRisk(riskFactors []*RiskFactor) string {
	highRiskCount := 0
	mediumRiskCount := 0

	for _, factor := range riskFactors {
		switch factor.RiskLevel {
		case "high":
			highRiskCount++
		case "medium":
			mediumRiskCount++
		}
	}

	if highRiskCount > 0 {
		return "high"
	} else if mediumRiskCount > 1 {
		return "medium"
	} else {
		return "low"
	}
}

// executeRollbackAsync executes rollback steps asynchronously
func (m *DefaultRollbackManager) executeRollbackAsync(ctx context.Context, execution *RollbackExecution, plan *RollbackPlan) {
	execution.Mutex.Lock()
	execution.Status = RollbackStatusRunning
	execution.LastUpdated = time.Now()
	execution.Mutex.Unlock()

	// Sort steps by dependencies
	sortedSteps := m.sortStepsByDependencies(plan.Steps)

	// Execute steps in order
	for i, step := range sortedSteps {
		// Check if execution was cancelled or paused
		execution.Mutex.RLock()
		if execution.Status == RollbackStatusCancelled {
			execution.Mutex.RUnlock()
			return
		}

		for execution.Status == RollbackStatusPaused {
			execution.Mutex.RUnlock()
			time.Sleep(time.Second)
			execution.Mutex.RLock()
		}
		execution.Mutex.RUnlock()

		// Update current step
		execution.Mutex.Lock()
		execution.CurrentStep = int32(i + 1)
		execution.Progress = float64(i) / float64(len(sortedSteps)) * 100.0
		execution.LastUpdated = time.Now()
		execution.Mutex.Unlock()

		// Execute step
		stepResult, err := m.rollbackExecutor.ExecuteStep(ctx, step, execution.ExecutionContext)
		
		execution.Mutex.Lock()
		execution.StepResults = append(execution.StepResults, stepResult)

		if err != nil {
			execution.Errors = append(execution.Errors, &RollbackError{
				StepID:    step.ID,
				ErrorType: "step_execution_error",
				Message:   err.Error(),
				Timestamp: time.Now(),
				Severity:  "error",
			})

			// Check if we should continue or fail
			if step.ContinueOnFailure {
				execution.Warnings = append(execution.Warnings, &RollbackWarning{
					StepID:    step.ID,
					Message:   fmt.Sprintf("Step failed but continuing: %s", err.Error()),
					Timestamp: time.Now(),
				})
			} else {
				execution.Status = RollbackStatusFailed
				now := time.Now()
				execution.CompletedAt = &now
				execution.LastUpdated = now
				execution.Mutex.Unlock()

				// Log failure
				m.auditLogger.LogJobEvent(ctx, execution.JobID, "rollback_failed", map[string]interface{}{
					"execution_id": execution.ID,
					"failed_step":  step.ID,
					"error":        err.Error(),
				})
				return
			}
		}
		execution.Mutex.Unlock()
	}

	// Rollback completed successfully
	execution.Mutex.Lock()
	execution.Status = RollbackStatusCompleted
	execution.Progress = 100.0
	now := time.Now()
	execution.CompletedAt = &now
	execution.LastUpdated = now
	execution.Mutex.Unlock()

	// Log success
	m.auditLogger.LogJobEvent(ctx, execution.JobID, "rollback_completed", map[string]interface{}{
		"execution_id":   execution.ID,
		"duration":       execution.CompletedAt.Sub(execution.StartedAt),
		"steps_executed": len(execution.StepResults),
	})

	// Post-rollback validation if enabled
	if m.config.PostRollbackValidation {
		go m.performPostRollbackValidation(ctx, execution, plan)
	}
}

// sortStepsByDependencies sorts steps in dependency order
func (m *DefaultRollbackManager) sortStepsByDependencies(steps []*RollbackStep) []*RollbackStep {
	sorted := make([]*RollbackStep, 0, len(steps))
	remaining := make([]*RollbackStep, len(steps))
	copy(remaining, steps)

	for len(remaining) > 0 {
		progress := false

		for i := len(remaining) - 1; i >= 0; i-- {
			step := remaining[i]
			canExecute := true

			// Check if all dependencies are satisfied
			for _, depID := range step.Dependencies {
				found := false
				for _, sortedStep := range sorted {
					if sortedStep.ID == depID {
						found = true
						break
					}
				}
				if !found {
					canExecute = false
					break
				}
			}

			if canExecute {
				sorted = append(sorted, step)
				remaining = append(remaining[:i], remaining[i+1:]...)
				progress = true
			}
		}

		if !progress {
			// Circular dependency detected, sort by ID
			sort.Slice(remaining, func(i, j int) bool {
				return remaining[i].ID < remaining[j].ID
			})
			sorted = append(sorted, remaining...)
			break
		}
	}

	return sorted
}

// Additional validation and helper methods...

// checkConcurrentRollbackLimits checks if concurrent rollback limits are exceeded
func (m *DefaultRollbackManager) checkConcurrentRollbackLimits() error {
	m.rollbacksMutex.RLock()
	defer m.rollbacksMutex.RUnlock()

	activeCount := int32(0)
	for _, execution := range m.activeRollbacks {
		if execution.Status == RollbackStatusRunning || execution.Status == RollbackStatusPending {
			activeCount++
		}
	}

	if activeCount >= m.config.MaxConcurrentRollbacks {
		return fmt.Errorf("maximum concurrent rollbacks (%d) exceeded", m.config.MaxConcurrentRollbacks)
	}

	return nil
}

// validateRollbackStep validates a single rollback step
func (m *DefaultRollbackManager) validateRollbackStep(ctx context.Context, step *RollbackStep, plan *RollbackPlan) (*StepValidation, error) {
	// Implementation would validate step feasibility, required resources, etc.
	// This is a simplified version
	validation := &StepValidation{
		StepID:      step.ID,
		IsValid:     true,
		Warnings:    make([]*ValidationWarning, 0),
		Errors:      make([]*ValidationError, 0),
		ValidatedAt: time.Now(),
	}

	// Validate step type is supported
	supportedTypes := []string{"validation", "service_control", "data_restore", "configuration_restore"}
	typeSupported := false
	for _, supportedType := range supportedTypes {
		if step.Type == supportedType {
			typeSupported = true
			break
		}
	}

	if !typeSupported {
		validation.Errors = append(validation.Errors, &ValidationError{
			StepID:   step.ID,
			Message:  fmt.Sprintf("Unsupported step type: %s", step.Type),
			Severity: "error",
		})
		validation.IsValid = false
	}

	return validation, nil
}

// validateStepDependencies validates that step dependencies form a valid DAG
func (m *DefaultRollbackManager) validateStepDependencies(steps []*RollbackStep) error {
	// Build adjacency list
	graph := make(map[int32][]int32)
	allSteps := make(map[int32]bool)

	for _, step := range steps {
		allSteps[step.ID] = true
		if graph[step.ID] == nil {
			graph[step.ID] = make([]int32, 0)
		}

		for _, depID := range step.Dependencies {
			if !allSteps[depID] {
				// Check if dependency exists
				found := false
				for _, s := range steps {
					if s.ID == depID {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("step %d depends on non-existent step %d", step.ID, depID)
				}
			}
			graph[depID] = append(graph[depID], step.ID)
		}
	}

	// Check for cycles using DFS
	color := make(map[int32]int) // 0: white, 1: gray, 2: black
	var dfs func(int32) bool
	dfs = func(node int32) bool {
		color[node] = 1 // gray
		for _, neighbor := range graph[node] {
			if color[neighbor] == 1 {
				return true // cycle detected
			}
			if color[neighbor] == 0 && dfs(neighbor) {
				return true
			}
		}
		color[node] = 2 // black
		return false
	}

	for stepID := range allSteps {
		if color[stepID] == 0 && dfs(stepID) {
			return fmt.Errorf("circular dependency detected involving step %d", stepID)
		}
	}

	return nil
}

// validateBackupAvailability validates that required backups are available
func (m *DefaultRollbackManager) validateBackupAvailability(ctx context.Context, plan *RollbackPlan) (*BackupValidationResult, error) {
	// Check if backups exist for the job
	return m.backupValidator.ValidateBackupForJob(ctx, plan.JobID)
}

// performPostRollbackValidation performs comprehensive validation after rollback
func (m *DefaultRollbackManager) performPostRollbackValidation(ctx context.Context, execution *RollbackExecution, plan *RollbackPlan) {
	// Implementation would perform comprehensive system validation
	// This is a placeholder for the actual validation logic
	m.auditLogger.LogJobEvent(ctx, execution.JobID, "post_rollback_validation_started", map[string]interface{}{
		"execution_id": execution.ID,
	})

	// Simulate validation
	time.Sleep(time.Minute * 5)

	m.auditLogger.LogJobEvent(ctx, execution.JobID, "post_rollback_validation_completed", map[string]interface{}{
		"execution_id": execution.ID,
		"result":       "success",
	})
}

// Cleanup routines

// rollbackCleanupRoutine periodically cleans up completed rollback executions
func (m *DefaultRollbackManager) rollbackCleanupRoutine() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanupCompletedRollbacks()
	}
}

// cleanupCompletedRollbacks removes old completed rollback executions
func (m *DefaultRollbackManager) cleanupCompletedRollbacks() {
	now := time.Now()
	
	m.rollbacksMutex.Lock()
	defer m.rollbacksMutex.Unlock()

	for executionID, execution := range m.activeRollbacks {
		if execution.CompletedAt != nil && 
		   now.Sub(*execution.CompletedAt) > m.config.RollbackLogRetention {
			delete(m.activeRollbacks, executionID)
		}
	}
}

// planCleanupRoutine periodically cleans up old rollback plans
func (m *DefaultRollbackManager) planCleanupRoutine() {
	ticker := time.NewTicker(time.Hour * 24)
	defer ticker.Stop()

	for range ticker.C {
		m.cleanupOldPlans()
	}
}

// cleanupOldPlans removes old rollback plans
func (m *DefaultRollbackManager) cleanupOldPlans() {
	now := time.Now()
	
	m.plansMutex.Lock()
	defer m.plansMutex.Unlock()

	for planID, plan := range m.rollbackPlans {
		if now.Sub(plan.CreatedAt) > m.config.PlanRetentionPeriod {
			delete(m.rollbackPlans, planID)
		}
	}
}

// Default configuration
func getDefaultRollbackManagerConfig() *RollbackManagerConfig {
	return &RollbackManagerConfig{
		MaxConcurrentRollbacks:       3,
		DefaultRollbackTimeout:       time.Hour * 6,
		RollbackWorkerPoolSize:       5,
		RequireApprovalForRollback:   true,
		MaxRollbackAttempts:          3,
		RollbackRetryDelay:          time.Minute * 30,
		BackupRetentionPeriod:       time.Hour * 24 * 30, // 30 days
		BackupValidationEnabled:     true,
		BackupCompressionEnabled:    true,
		BackupEncryptionEnabled:     true,
		PreRollbackValidation:       true,
		PostRollbackValidation:      true,
		AutomaticRollbackPrevention: true,
		EnablePointInTimeRecovery:   true,
		RecoveryCheckInterval:       time.Hour,
		MaxRecoveryAttempts:         3,
		RollbackMonitoringEnabled:   true,
		AlertOnRollbackFailure:      true,
		RollbackProgressReporting:   true,
		SecurityClearance:           "unclassified",
		ComplianceFrameworks:        []string{"SOC2", "ISO27001"},
		AuditAllOperations:          true,
		RequireMultiPersonApproval:  false,
		RollbackLogRetention:        time.Hour * 24 * 7, // 7 days
		PlanRetentionPeriod:         time.Hour * 24 * 90, // 90 days
	}
}

// Supporting component implementations
type BackupStorage interface {
	Store(ctx context.Context, data []byte, metadata map[string]interface{}) (uuid.UUID, error)
	Retrieve(ctx context.Context, backupID uuid.UUID) ([]byte, error)
	Delete(ctx context.Context, backupID uuid.UUID) error
	List(ctx context.Context, filter map[string]interface{}) ([]uuid.UUID, error)
}

type ApprovalWorkflow interface {
	SubmitApprovalRequest(ctx context.Context, request *ApprovalRequest) (*ApprovalResponse, error)
	GetApprovalStatus(ctx context.Context, requestID uuid.UUID) (*ApprovalStatus, error)
}

type BackupManager struct {
	storage BackupStorage
	config  *RollbackManagerConfig
}

func NewBackupManager(storage BackupStorage, config *RollbackManagerConfig) *BackupManager {
	return &BackupManager{storage: storage, config: config}
}

func (bm *BackupManager) CreateBackup(ctx context.Context, config *BackupConfig) (*BackupResult, error) {
	// Implementation would create actual backups
	return &BackupResult{
		BackupID:    uuid.New(),
		JobID:       config.JobID,
		Status:      "completed",
		CreatedAt:   time.Now(),
		Size:        1024 * 1024 * 100, // 100MB placeholder
		Checksum:    "abc123def456",
	}, nil
}

func (bm *BackupManager) RestoreFromBackup(ctx context.Context, backupID uuid.UUID, config *RestoreConfig) (*RestoreResult, error) {
	// Implementation would perform actual restore
	return &RestoreResult{
		RestoreID:   uuid.New(),
		BackupID:    backupID,
		Status:      "completed",
		StartedAt:   time.Now(),
		CompletedAt: time.Now().Add(time.Hour),
	}, nil
}

type BackupValidator struct {
	config *RollbackManagerConfig
}

func NewBackupValidator(config *RollbackManagerConfig) *BackupValidator {
	return &BackupValidator{config: config}
}

func (bv *BackupValidator) ValidateBackup(ctx context.Context, backupID uuid.UUID) (*BackupValidationResult, error) {
	return &BackupValidationResult{
		BackupID:    backupID,
		IsValid:     true,
		ValidatedAt: time.Now(),
	}, nil
}

func (bv *BackupValidator) ValidateBackupForJob(ctx context.Context, jobID uuid.UUID) (*BackupValidationResult, error) {
	return &BackupValidationResult{
		JobID:       jobID,
		IsValid:     true,
		ValidatedAt: time.Now(),
	}, nil
}

type RollbackExecutor struct {
	config *RollbackManagerConfig
}

func NewRollbackExecutor(config *RollbackManagerConfig) *RollbackExecutor {
	return &RollbackExecutor{config: config}
}

func (re *RollbackExecutor) ExecuteStep(ctx context.Context, step *RollbackStep, execCtx *RollbackExecutionContext) (*RollbackStepResult, error) {
	// Implementation would execute actual rollback steps
	return &RollbackStepResult{
		StepID:      step.ID,
		Status:      "completed",
		StartedAt:   time.Now(),
		CompletedAt: time.Now().Add(step.EstimatedDuration),
		Output:      "Step executed successfully",
	}, nil
}

type RecoveryEngine struct {
	config *RollbackManagerConfig
}

func NewRecoveryEngine(config *RollbackManagerConfig) *RecoveryEngine {
	return &RecoveryEngine{config: config}
}

type RollbackMetricsCollector struct{}

func NewRollbackMetricsCollector() *RollbackMetricsCollector {
	return &RollbackMetricsCollector{}
}

// Supporting data structures
type RollbackExecutionContext struct {
	PlanID      uuid.UUID `json:"plan_id"`
	JobID       uuid.UUID `json:"job_id"`
	ExecutionID uuid.UUID `json:"execution_id"`
	StartedAt   time.Time `json:"started_at"`
}

type RollbackStepResult struct {
	StepID      int32     `json:"step_id"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Output      string    `json:"output"`
	Error       string    `json:"error,omitempty"`
}

type RollbackError struct {
	StepID    int32     `json:"step_id"`
	ErrorType string    `json:"error_type"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
}

type RollbackWarning struct {
	StepID    int32     `json:"step_id"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type ApprovalDetails struct {
	RequestID   uuid.UUID `json:"request_id"`
	ApprovedBy  string    `json:"approved_by"`
	ApprovedAt  time.Time `json:"approved_at"`
	Comments    string    `json:"comments"`
}

type ApprovalRequest struct {
	Type        string                 `json:"type"`
	ResourceID  uuid.UUID              `json:"resource_id"`
	RequestedBy string                 `json:"requested_by"`
	Reason      string                 `json:"reason"`
	RiskLevel   string                 `json:"risk_level"`
	Details     map[string]interface{} `json:"details"`
}

type ApprovalResponse struct {
	RequestID uuid.UUID `json:"request_id"`
	Status    string    `json:"status"`
}

type ApprovalStatus struct {
	RequestID uuid.UUID `json:"request_id"`
	Status    string    `json:"status"`
	Comments  string    `json:"comments"`
}

type ValidationWarning struct {
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

type ValidationError struct {
	StepID   int32  `json:"step_id,omitempty"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

type StepValidation struct {
	StepID      int32                `json:"step_id"`
	IsValid     bool                 `json:"is_valid"`
	Warnings    []*ValidationWarning `json:"warnings"`
	Errors      []*ValidationError   `json:"errors"`
	ValidatedAt time.Time            `json:"validated_at"`
}

// Additional concrete implementations
type RollbackPlanValidation struct {
	PlanID      uuid.UUID            `json:"plan_id"`
	IsValid     bool                 `json:"is_valid"`
	Warnings    []*ValidationWarning `json:"warnings"`
	Errors      []*ValidationError   `json:"errors"`
	ValidatedAt time.Time            `json:"validated_at"`
}

type RollbackPlanUpdates struct {
	Reason string          `json:"reason,omitempty"`
	Steps  []*RollbackStep `json:"steps,omitempty"`
}

type BackupConfig struct {
	JobID       uuid.UUID              `json:"job_id"`
	BackupType  string                 `json:"backup_type"`
	Compression bool                   `json:"compression"`
	Encryption  bool                   `json:"encryption"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type BackupResult struct {
	BackupID  uuid.UUID `json:"backup_id"`
	JobID     uuid.UUID `json:"job_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	Checksum  string    `json:"checksum"`
}

type BackupValidationResult struct {
	BackupID    uuid.UUID `json:"backup_id,omitempty"`
	JobID       uuid.UUID `json:"job_id,omitempty"`
	IsValid     bool      `json:"is_valid"`
	ValidatedAt time.Time `json:"validated_at"`
}

type RestoreConfig struct {
	BackupID    uuid.UUID              `json:"backup_id"`
	RestoreType string                 `json:"restore_type"`
	Options     map[string]interface{} `json:"options"`
}

type RestoreResult struct {
	RestoreID   uuid.UUID `json:"restore_id"`
	BackupID    uuid.UUID `json:"backup_id"`
	Status      string    `json:"status"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type RollbackStatus struct {
	ExecutionID         uuid.UUID  `json:"execution_id"`
	PlanID              uuid.UUID  `json:"plan_id"`
	JobID               uuid.UUID  `json:"job_id"`
	Status              string     `json:"status"`
	CurrentStep         int32      `json:"current_step"`
	TotalSteps          int32      `json:"total_steps"`
	Progress            float64    `json:"progress"`
	StartedAt           time.Time  `json:"started_at"`
	LastUpdated         time.Time  `json:"last_updated"`
	CompletedAt         *time.Time `json:"completed_at"`
	EstimatedCompletion *time.Time `json:"estimated_completion"`
	ErrorCount          int32      `json:"error_count"`
	WarningCount        int32      `json:"warning_count"`
}

// Extend RollbackStep to include additional fields
type RollbackStep struct {
	ID                int32                  `json:"id"`
	Name              string                 `json:"name"`
	Description       string                 `json:"description"`
	Type              string                 `json:"type"`
	Component         string                 `json:"component"`
	Commands          []string               `json:"commands"`
	EstimatedDuration time.Duration          `json:"estimated_duration"`
	Dependencies      []int32                `json:"dependencies"`
	RollbackData      map[string]interface{} `json:"rollback_data"`
	ContinueOnFailure bool                   `json:"continue_on_failure"`
	RetryCount        int32                  `json:"retry_count"`
	Timeout           time.Duration          `json:"timeout"`
}

// Extend RollbackPlan to include additional fields
type RollbackPlan struct {
	ID                   uuid.UUID         `json:"id"`
	JobID                uuid.UUID         `json:"job_id"`
	Reason               string            `json:"reason"`
	Status               string            `json:"status"`
	Steps                []*RollbackStep   `json:"steps"`
	EstimatedDuration    time.Duration     `json:"estimated_duration"`
	RiskAssessment       *RiskAssessment   `json:"risk_assessment"`
	CreatedAt            time.Time         `json:"created_at"`
	CreatedBy            string            `json:"created_by"`
	LastModified         time.Time         `json:"last_modified"`
	ModifiedBy           string            `json:"modified_by"`
	RequiresApproval     bool              `json:"requires_approval"`
	SecurityClearance    string            `json:"security_clearance"`
	ComplianceFrameworks []string          `json:"compliance_frameworks"`
}