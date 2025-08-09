/**
 * Custom Business Rule Validators
 * Advanced validation logic that goes beyond OpenAPI schema capabilities
 * 
 * Task: 83.5 - Implement custom business rule validators
 */

import { NextRequest } from 'next/server';
import { createClient } from 'redis';
import { Pool } from 'pg';
import { TenantContext } from './tenant-context-service';

// Base interfaces for validation
export interface BusinessRuleValidationRequest {
  userId: string;
  tenantId: string;
  endpoint: string;
  method: string;
  requestBody?: any;
  queryParams?: Record<string, string>;
  pathParams?: Record<string, string>;
  headers?: Record<string, string>;
  tenantContext?: TenantContext;
  timestamp: Date;
}

export interface BusinessRuleValidationResult {
  isValid: boolean;
  violations: ValidationViolation[];
  warnings: ValidationWarning[];
  metadata?: Record<string, any>;
  evaluationTimeMs: number;
}

export interface ValidationViolation {
  ruleId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  field?: string;
  currentValue?: any;
  expectedValue?: any;
  remediation?: string;
}

export interface ValidationWarning {
  ruleId: string;
  message: string;
  field?: string;
  suggestion?: string;
}

// Transaction limit validation
export interface TransactionLimitRule {
  tenantTier: string;
  dailyLimit: number;
  hourlyLimit: number;
  transactionValueLimit: number;
  aggregateMonthlyLimit: number;
  requiresApprovalThreshold?: number;
}

export interface TimeBasedAccessRule {
  allowedDays: number[]; // 0-6 (Sunday-Saturday)
  allowedHours: { start: number; end: number }; // 24-hour format
  timezone: string;
  emergencyOverride: boolean;
  blackoutPeriods?: Array<{ start: Date; end: Date; reason: string }>;
}

export interface ResourceConsistencyRule {
  resourceType: string;
  requiredFields: string[];
  dependentResources: Array<{
    resourceType: string;
    relationshipType: 'parent' | 'child' | 'reference';
    validationQuery: string;
  }>;
  immutableFields?: string[];
}

export interface WorkflowStateRule {
  currentState: string;
  allowedTransitions: string[];
  requiredFields: Record<string, any>;
  preConditions: Array<{
    condition: string;
    errorMessage: string;
  }>;
  postConditions: Array<{
    condition: string;
    errorMessage: string;
  }>;
}

export interface TenantDataIsolationRule {
  resourcePath: string;
  isolationLevel: 'strict' | 'cross_tenant_allowed' | 'global';
  tenantFieldName: string;
  allowedCrossTenantRoles?: string[];
  auditRequired: boolean;
}

export class BusinessRuleValidator {
  private redisClient: ReturnType<typeof createClient>;
  private pgPool: Pool;
  private transactionLimitRules: Map<string, TransactionLimitRule>;
  private timeBasedAccessRules: Map<string, TimeBasedAccessRule>;
  private resourceConsistencyRules: Map<string, ResourceConsistencyRule>;
  private workflowStateRules: Map<string, Map<string, WorkflowStateRule>>;
  private tenantIsolationRules: Map<string, TenantDataIsolationRule>;

  constructor(
    redisClient: ReturnType<typeof createClient>,
    pgPool: Pool
  ) {
    this.redisClient = redisClient;
    this.pgPool = pgPool;
    this.transactionLimitRules = new Map();
    this.timeBasedAccessRules = new Map();
    this.resourceConsistencyRules = new Map();
    this.workflowStateRules = new Map();
    this.tenantIsolationRules = new Map();
    
    this.initializeRules();
  }

  /**
   * Main validation entry point
   */
  async validateBusinessRules(
    request: BusinessRuleValidationRequest
  ): Promise<BusinessRuleValidationResult> {
    const startTime = Date.now();
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];
    const metadata: Record<string, any> = {};

    try {
      // Execute all validation rules in parallel where possible
      const validationResults = await Promise.allSettled([
        this.validateTransactionLimits(request),
        this.validateTimeBasedAccess(request),
        this.validateResourceConsistency(request),
        this.validateWorkflowStates(request),
        this.validateTenantDataIsolation(request)
      ]);

      // Collect results from all validators
      validationResults.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          violations.push(...result.value.violations);
          warnings.push(...result.value.warnings);
          if (result.value.metadata) {
            Object.assign(metadata, result.value.metadata);
          }
        } else if (result.status === 'rejected') {
          violations.push({
            ruleId: `validator_error_${index}`,
            severity: 'high',
            message: `Business rule validation failed: ${result.reason}`,
            remediation: 'Contact system administrator'
          });
        }
      });

      return {
        isValid: violations.filter(v => v.severity === 'critical' || v.severity === 'high').length === 0,
        violations,
        warnings,
        metadata,
        evaluationTimeMs: Date.now() - startTime
      };

    } catch (error) {
      console.error('Business rule validation error:', error);
      return {
        isValid: false,
        violations: [{
          ruleId: 'validation_system_error',
          severity: 'critical',
          message: 'Business rule validation system error',
          remediation: 'Contact system administrator'
        }],
        warnings: [],
        evaluationTimeMs: Date.now() - startTime
      };
    }
  }

  /**
   * Validate transaction limits based on user tier and historical data
   */
  private async validateTransactionLimits(
    request: BusinessRuleValidationRequest
  ): Promise<{ violations: ValidationViolation[]; warnings: ValidationWarning[]; metadata?: Record<string, any> }> {
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];
    const metadata: Record<string, any> = {};

    // Only validate transaction-related endpoints
    if (!this.isTransactionEndpoint(request.endpoint, request.method)) {
      return { violations, warnings };
    }

    const tenantTier = request.tenantContext?.tenantTier || 'basic';
    const rule = this.transactionLimitRules.get(tenantTier);
    
    if (!rule) {
      violations.push({
        ruleId: 'unknown_tenant_tier',
        severity: 'high',
        message: `Unknown tenant tier: ${tenantTier}`,
        remediation: 'Update tenant configuration'
      });
      return { violations, warnings };
    }

    try {
      // Get current usage statistics from cache/database
      const [dailyUsage, hourlyUsage, monthlyUsage] = await Promise.all([
        this.getDailyTransactionUsage(request.userId, request.tenantId),
        this.getHourlyTransactionUsage(request.userId, request.tenantId),
        this.getMonthlyTransactionUsage(request.userId, request.tenantId)
      ]);

      metadata.currentUsage = { dailyUsage, hourlyUsage, monthlyUsage };
      metadata.limits = rule;

      // Check daily limits
      if (dailyUsage.count >= rule.dailyLimit) {
        violations.push({
          ruleId: 'daily_transaction_limit_exceeded',
          severity: 'critical',
          message: `Daily transaction limit exceeded (${dailyUsage.count}/${rule.dailyLimit})`,
          currentValue: dailyUsage.count,
          expectedValue: rule.dailyLimit,
          remediation: 'Wait until tomorrow or upgrade tenant tier'
        });
      } else if (dailyUsage.count >= rule.dailyLimit * 0.8) {
        warnings.push({
          ruleId: 'daily_transaction_limit_warning',
          message: `Approaching daily transaction limit (${dailyUsage.count}/${rule.dailyLimit})`,
          suggestion: 'Consider monitoring usage or upgrading tier'
        });
      }

      // Check hourly limits
      if (hourlyUsage.count >= rule.hourlyLimit) {
        violations.push({
          ruleId: 'hourly_transaction_limit_exceeded',
          severity: 'high',
          message: `Hourly transaction limit exceeded (${hourlyUsage.count}/${rule.hourlyLimit})`,
          currentValue: hourlyUsage.count,
          expectedValue: rule.hourlyLimit,
          remediation: 'Wait for the next hour or upgrade tenant tier'
        });
      }

      // Check transaction value limits
      const transactionValue = this.extractTransactionValue(request.requestBody);
      if (transactionValue && transactionValue > rule.transactionValueLimit) {
        violations.push({
          ruleId: 'transaction_value_limit_exceeded',
          severity: 'critical',
          message: `Transaction value exceeds limit ($${transactionValue} > $${rule.transactionValueLimit})`,
          currentValue: transactionValue,
          expectedValue: rule.transactionValueLimit,
          remediation: 'Reduce transaction value or request approval'
        });
      }

      // Check monthly aggregate limits
      if (monthlyUsage.totalValue >= rule.aggregateMonthlyLimit) {
        violations.push({
          ruleId: 'monthly_aggregate_limit_exceeded',
          severity: 'critical',
          message: `Monthly aggregate limit exceeded ($${monthlyUsage.totalValue}/$${rule.aggregateMonthlyLimit})`,
          currentValue: monthlyUsage.totalValue,
          expectedValue: rule.aggregateMonthlyLimit,
          remediation: 'Wait until next month or upgrade tenant tier'
        });
      }

      // Check approval requirements
      if (rule.requiresApprovalThreshold && 
          transactionValue && 
          transactionValue > rule.requiresApprovalThreshold) {
        const hasApproval = await this.checkTransactionApproval(request.requestBody);
        if (!hasApproval) {
          violations.push({
            ruleId: 'transaction_approval_required',
            severity: 'high',
            message: `Transaction requires approval (value: $${transactionValue})`,
            remediation: 'Obtain approval before proceeding'
          });
        }
      }

    } catch (error) {
      violations.push({
        ruleId: 'transaction_limit_validation_error',
        severity: 'medium',
        message: 'Failed to validate transaction limits',
        remediation: 'Check system logs'
      });
    }

    return { violations, warnings, metadata };
  }

  /**
   * Validate time-based access restrictions
   */
  private async validateTimeBasedAccess(
    request: BusinessRuleValidationRequest
  ): Promise<{ violations: ValidationViolation[]; warnings: ValidationWarning[]; metadata?: Record<string, any> }> {
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];
    
    // Get time-based rules for this endpoint
    const ruleKey = this.getTimeBasedRuleKey(request.endpoint, request.method);
    const rule = this.timeBasedAccessRules.get(ruleKey);
    
    if (!rule) {
      return { violations, warnings }; // No time restrictions
    }

    const now = new Date();
    const currentDay = now.getDay();
    const currentHour = now.getHours();

    // Check allowed days
    if (!rule.allowedDays.includes(currentDay)) {
      const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
      const allowedDayNames = rule.allowedDays.map(d => dayNames[d]).join(', ');
      
      violations.push({
        ruleId: 'access_not_allowed_today',
        severity: 'high',
        message: `Access not allowed on ${dayNames[currentDay]}. Allowed days: ${allowedDayNames}`,
        remediation: rule.emergencyOverride ? 'Request emergency access override' : 'Access only during allowed days'
      });
    }

    // Check allowed hours
    if (currentHour < rule.allowedHours.start || currentHour >= rule.allowedHours.end) {
      violations.push({
        ruleId: 'access_outside_allowed_hours',
        severity: 'high',
        message: `Access not allowed at ${currentHour}:00. Allowed hours: ${rule.allowedHours.start}:00-${rule.allowedHours.end}:00`,
        remediation: rule.emergencyOverride ? 'Request emergency access override' : 'Access only during allowed hours'
      });
    }

    // Check blackout periods
    if (rule.blackoutPeriods) {
      for (const period of rule.blackoutPeriods) {
        if (now >= period.start && now <= period.end) {
          violations.push({
            ruleId: 'access_during_blackout_period',
            severity: 'critical',
            message: `Access not allowed during blackout period: ${period.reason}`,
            remediation: 'Wait until blackout period ends'
          });
        }
      }
    }

    return { violations, warnings };
  }

  /**
   * Validate cross-resource consistency
   */
  private async validateResourceConsistency(
    request: BusinessRuleValidationRequest
  ): Promise<{ violations: ValidationViolation[]; warnings: ValidationWarning[]; metadata?: Record<string, any> }> {
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];

    // Only validate resource modification endpoints
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
      return { violations, warnings };
    }

    const resourceType = this.extractResourceType(request.endpoint);
    if (!resourceType) {
      return { violations, warnings };
    }

    const rule = this.resourceConsistencyRules.get(resourceType);
    if (!rule) {
      return { violations, warnings };
    }

    try {
      // Check required fields
      if (request.requestBody && rule.requiredFields) {
        for (const field of rule.requiredFields) {
          if (!(field in request.requestBody) || request.requestBody[field] == null) {
            violations.push({
              ruleId: 'required_field_missing',
              severity: 'critical',
              message: `Required field '${field}' is missing for ${resourceType}`,
              field,
              remediation: `Provide value for '${field}' field`
            });
          }
        }
      }

      // Check immutable fields (for updates)
      if (['PUT', 'PATCH'].includes(request.method) && 
          request.requestBody && 
          rule.immutableFields) {
        for (const field of rule.immutableFields) {
          if (field in request.requestBody) {
            violations.push({
              ruleId: 'immutable_field_modification',
              severity: 'high',
              message: `Immutable field '${field}' cannot be modified`,
              field,
              remediation: `Remove '${field}' from request body`
            });
          }
        }
      }

      // Check dependent resource consistency
      if (rule.dependentResources) {
        for (const dependency of rule.dependentResources) {
          const isValid = await this.validateResourceDependency(
            request.requestBody,
            request.tenantId,
            dependency
          );
          
          if (!isValid) {
            violations.push({
              ruleId: 'resource_dependency_violation',
              severity: 'high',
              message: `${dependency.relationshipType} ${dependency.resourceType} validation failed`,
              remediation: `Ensure ${dependency.resourceType} exists and is accessible`
            });
          }
        }
      }

    } catch (error) {
      violations.push({
        ruleId: 'resource_consistency_validation_error',
        severity: 'medium',
        message: 'Failed to validate resource consistency',
        remediation: 'Check system logs'
      });
    }

    return { violations, warnings };
  }

  /**
   * Validate business workflow state transitions
   */
  private async validateWorkflowStates(
    request: BusinessRuleValidationRequest
  ): Promise<{ violations: ValidationViolation[]; warnings: ValidationWarning[]; metadata?: Record<string, any> }> {
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];

    // Only validate state transition endpoints
    if (!this.isStateTransitionEndpoint(request.endpoint, request.method)) {
      return { violations, warnings };
    }

    const resourceType = this.extractResourceType(request.endpoint);
    if (!resourceType || !this.workflowStateRules.has(resourceType)) {
      return { violations, warnings };
    }

    try {
      const currentState = await this.getCurrentWorkflowState(
        resourceType,
        request.pathParams,
        request.tenantId
      );

      if (!currentState) {
        violations.push({
          ruleId: 'resource_state_not_found',
          severity: 'high',
          message: `Cannot determine current state for ${resourceType}`,
          remediation: 'Ensure resource exists'
        });
        return { violations, warnings };
      }

      const stateRules = this.workflowStateRules.get(resourceType);
      const rule = stateRules?.get(currentState);
      
      if (!rule) {
        violations.push({
          ruleId: 'unknown_workflow_state',
          severity: 'medium',
          message: `No workflow rules defined for state: ${currentState}`,
          remediation: 'Update workflow configuration'
        });
        return { violations, warnings };
      }

      // Get target state from request
      const targetState = this.extractTargetState(request.requestBody, request.endpoint);
      
      // Check if transition is allowed
      if (targetState && !rule.allowedTransitions.includes(targetState)) {
        violations.push({
          ruleId: 'invalid_state_transition',
          severity: 'critical',
          message: `Invalid state transition from '${currentState}' to '${targetState}'`,
          currentValue: currentState,
          expectedValue: rule.allowedTransitions,
          remediation: `Valid transitions: ${rule.allowedTransitions.join(', ')}`
        });
      }

      // Check required fields for the transition
      if (request.requestBody && rule.requiredFields) {
        for (const [field, expectedValue] of Object.entries(rule.requiredFields)) {
          const actualValue = request.requestBody[field];
          if (actualValue !== expectedValue) {
            violations.push({
              ruleId: 'workflow_required_field_mismatch',
              severity: 'high',
              message: `Field '${field}' does not meet workflow requirements`,
              field,
              currentValue: actualValue,
              expectedValue,
              remediation: `Set '${field}' to '${expectedValue}'`
            });
          }
        }
      }

      // Check pre-conditions
      for (const preCondition of rule.preConditions) {
        const conditionMet = await this.evaluateWorkflowCondition(
          preCondition.condition,
          resourceType,
          request.pathParams,
          request.tenantId
        );

        if (!conditionMet) {
          violations.push({
            ruleId: 'workflow_precondition_failed',
            severity: 'critical',
            message: preCondition.errorMessage,
            remediation: 'Ensure all pre-conditions are met'
          });
        }
      }

    } catch (error) {
      violations.push({
        ruleId: 'workflow_validation_error',
        severity: 'medium',
        message: 'Failed to validate workflow state',
        remediation: 'Check system logs'
      });
    }

    return { violations, warnings };
  }

  /**
   * Validate tenant data isolation
   */
  private async validateTenantDataIsolation(
    request: BusinessRuleValidationRequest
  ): Promise<{ violations: ValidationViolation[]; warnings: ValidationWarning[]; metadata?: Record<string, any> }> {
    const violations: ValidationViolation[] = [];
    const warnings: ValidationWarning[] = [];

    const rule = this.tenantIsolationRules.get(request.endpoint);
    if (!rule) {
      return { violations, warnings }; // No isolation rules for this endpoint
    }

    try {
      // Check isolation level
      if (rule.isolationLevel === 'strict') {
        // For strict isolation, ensure all data access is tenant-scoped
        if (request.requestBody && rule.tenantFieldName) {
          const resourceTenantId = request.requestBody[rule.tenantFieldName];
          
          if (resourceTenantId && resourceTenantId !== request.tenantId) {
            violations.push({
              ruleId: 'tenant_isolation_violation',
              severity: 'critical',
              message: 'Attempt to access data from different tenant',
              field: rule.tenantFieldName,
              currentValue: resourceTenantId,
              expectedValue: request.tenantId,
              remediation: 'Ensure resource belongs to current tenant'
            });
          }
        }

        // Check for cross-tenant resource access in path/query params
        await this.validateTenantScopedAccess(request, rule, violations);

      } else if (rule.isolationLevel === 'cross_tenant_allowed') {
        // Cross-tenant access allowed for specific roles
        const userRoles = await this.getUserRoles(request.userId, request.tenantId);
        const hasAllowedRole = rule.allowedCrossTenantRoles?.some(role => 
          userRoles.includes(role)
        );

        if (!hasAllowedRole) {
          violations.push({
            ruleId: 'insufficient_cross_tenant_permissions',
            severity: 'high',
            message: 'Insufficient permissions for cross-tenant access',
            remediation: `Required roles: ${rule.allowedCrossTenantRoles?.join(', ')}`
          });
        } else {
          // Log cross-tenant access for audit
          if (rule.auditRequired) {
            await this.auditCrossTenantAccess(request, rule);
          }
        }
      }

    } catch (error) {
      violations.push({
        ruleId: 'tenant_isolation_validation_error',
        severity: 'medium',
        message: 'Failed to validate tenant isolation',
        remediation: 'Check system logs'
      });
    }

    return { violations, warnings };
  }

  // Helper methods for rule initialization and utilities

  private initializeRules(): void {
    this.initializeTransactionLimitRules();
    this.initializeTimeBasedAccessRules();
    this.initializeResourceConsistencyRules();
    this.initializeWorkflowStateRules();
    this.initializeTenantIsolationRules();
  }

  private initializeTransactionLimitRules(): void {
    // Basic tier limits
    this.transactionLimitRules.set('basic', {
      tenantTier: 'basic',
      dailyLimit: 100,
      hourlyLimit: 20,
      transactionValueLimit: 1000,
      aggregateMonthlyLimit: 25000
    });

    // Premium tier limits
    this.transactionLimitRules.set('premium', {
      tenantTier: 'premium',
      dailyLimit: 500,
      hourlyLimit: 100,
      transactionValueLimit: 10000,
      aggregateMonthlyLimit: 250000,
      requiresApprovalThreshold: 5000
    });

    // Enterprise tier limits
    this.transactionLimitRules.set('enterprise', {
      tenantTier: 'enterprise',
      dailyLimit: 2000,
      hourlyLimit: 500,
      transactionValueLimit: 100000,
      aggregateMonthlyLimit: 2500000,
      requiresApprovalThreshold: 25000
    });
  }

  private initializeTimeBasedAccessRules(): void {
    // Sensitive financial operations - business hours only
    this.timeBasedAccessRules.set('POST:/api/v1/financial/transactions', {
      allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
      allowedHours: { start: 9, end: 17 }, // 9 AM - 5 PM
      timezone: 'America/New_York',
      emergencyOverride: true
    });

    // System maintenance operations - off-hours only
    this.timeBasedAccessRules.set('POST:/api/v1/admin/system/maintenance', {
      allowedDays: [0, 6], // Weekend only
      allowedHours: { start: 22, end: 6 }, // 10 PM - 6 AM
      timezone: 'UTC',
      emergencyOverride: false
    });

    // Security audit exports - restricted hours
    this.timeBasedAccessRules.set('GET:/api/v1/security/audit/export', {
      allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
      allowedHours: { start: 8, end: 18 }, // 8 AM - 6 PM
      timezone: 'America/New_York',
      emergencyOverride: true
    });
  }

  private initializeResourceConsistencyRules(): void {
    // User resource consistency
    this.resourceConsistencyRules.set('users', {
      resourceType: 'users',
      requiredFields: ['email', 'tenant_id', 'role'],
      immutableFields: ['id', 'created_at', 'tenant_id'],
      dependentResources: [{
        resourceType: 'tenants',
        relationshipType: 'reference',
        validationQuery: 'SELECT 1 FROM tenants WHERE id = $1 AND status = \'active\''
      }]
    });

    // Asset resource consistency
    this.resourceConsistencyRules.set('assets', {
      resourceType: 'assets',
      requiredFields: ['name', 'type', 'tenant_id', 'owner_id'],
      immutableFields: ['id', 'tenant_id', 'created_at'],
      dependentResources: [{
        resourceType: 'users',
        relationshipType: 'reference',
        validationQuery: 'SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2'
      }]
    });

    // Security incident consistency
    this.resourceConsistencyRules.set('incidents', {
      resourceType: 'incidents',
      requiredFields: ['title', 'severity', 'status', 'assigned_to'],
      immutableFields: ['id', 'created_at'],
      dependentResources: [{
        resourceType: 'users',
        relationshipType: 'reference',
        validationQuery: 'SELECT 1 FROM users WHERE id = $1 AND status = \'active\''
      }]
    });
  }

  private initializeWorkflowStateRules(): void {
    // Security incident workflow
    const incidentStates = new Map<string, WorkflowStateRule>();
    
    incidentStates.set('new', {
      currentState: 'new',
      allowedTransitions: ['assigned', 'closed'],
      requiredFields: { status: 'new' },
      preConditions: [],
      postConditions: []
    });

    incidentStates.set('assigned', {
      currentState: 'assigned',
      allowedTransitions: ['in_progress', 'escalated', 'closed'],
      requiredFields: { assigned_to: 'required' },
      preConditions: [{
        condition: 'assigned_user_active',
        errorMessage: 'Assigned user must be active'
      }],
      postConditions: []
    });

    incidentStates.set('in_progress', {
      currentState: 'in_progress',
      allowedTransitions: ['resolved', 'escalated'],
      requiredFields: {},
      preConditions: [],
      postConditions: []
    });

    incidentStates.set('resolved', {
      currentState: 'resolved',
      allowedTransitions: ['closed', 'reopened'],
      requiredFields: { resolution_notes: 'required' },
      preConditions: [],
      postConditions: []
    });

    this.workflowStateRules.set('incidents', incidentStates);

    // Asset lifecycle workflow
    const assetStates = new Map<string, WorkflowStateRule>();
    
    assetStates.set('pending', {
      currentState: 'pending',
      allowedTransitions: ['active', 'rejected'],
      requiredFields: {},
      preConditions: [],
      postConditions: []
    });

    assetStates.set('active', {
      currentState: 'active',
      allowedTransitions: ['maintenance', 'decommissioned'],
      requiredFields: {},
      preConditions: [{
        condition: 'asset_validated',
        errorMessage: 'Asset must be validated before activation'
      }],
      postConditions: []
    });

    this.workflowStateRules.set('assets', assetStates);
  }

  private initializeTenantIsolationRules(): void {
    // Strict tenant isolation for user data
    this.tenantIsolationRules.set('/api/v1/users', {
      resourcePath: '/api/v1/users',
      isolationLevel: 'strict',
      tenantFieldName: 'tenant_id',
      auditRequired: true
    });

    // Cross-tenant allowed for admin operations
    this.tenantIsolationRules.set('/api/v1/admin/users', {
      resourcePath: '/api/v1/admin/users',
      isolationLevel: 'cross_tenant_allowed',
      tenantFieldName: 'tenant_id',
      allowedCrossTenantRoles: ['admin', 'system_admin'],
      auditRequired: true
    });

    // Global access for system health
    this.tenantIsolationRules.set('/api/v1/system/health', {
      resourcePath: '/api/v1/system/health',
      isolationLevel: 'global',
      tenantFieldName: '',
      auditRequired: false
    });
  }

  // Utility helper methods (implementation details omitted for brevity)
  private isTransactionEndpoint(endpoint: string, method: string): boolean {
    return endpoint.includes('/financial/') || 
           endpoint.includes('/billing/') || 
           endpoint.includes('/payment/');
  }

  private getTimeBasedRuleKey(endpoint: string, method: string): string {
    return `${method}:${endpoint}`;
  }

  private extractResourceType(endpoint: string): string | null {
    const match = endpoint.match(/\/api\/v\d+\/(\w+)/);
    return match ? match[1] : null;
  }

  private isStateTransitionEndpoint(endpoint: string, method: string): boolean {
    return method === 'PUT' || method === 'PATCH' || 
           endpoint.includes('/status') || 
           endpoint.includes('/transition');
  }

  private extractTransactionValue(requestBody: any): number | null {
    return requestBody?.amount || requestBody?.value || requestBody?.total || null;
  }

  private async getDailyTransactionUsage(userId: string, tenantId: string): Promise<{ count: number; totalValue: number }> {
    // Implementation would query Redis/database for daily usage
    return { count: 0, totalValue: 0 };
  }

  private async getHourlyTransactionUsage(userId: string, tenantId: string): Promise<{ count: number; totalValue: number }> {
    // Implementation would query Redis/database for hourly usage
    return { count: 0, totalValue: 0 };
  }

  private async getMonthlyTransactionUsage(userId: string, tenantId: string): Promise<{ count: number; totalValue: number }> {
    // Implementation would query Redis/database for monthly usage
    return { count: 0, totalValue: 0 };
  }

  private async checkTransactionApproval(requestBody: any): Promise<boolean> {
    // Implementation would check for approval in the request or database
    return requestBody?.approval_id != null;
  }

  private async validateResourceDependency(
    requestBody: any,
    tenantId: string,
    dependency: any
  ): Promise<boolean> {
    // Implementation would execute dependency validation query
    return true;
  }

  private async getCurrentWorkflowState(
    resourceType: string,
    pathParams: Record<string, string> | undefined,
    tenantId: string
  ): Promise<string | null> {
    // Implementation would query database for current state
    return 'new';
  }

  private extractTargetState(requestBody: any, endpoint: string): string | null {
    return requestBody?.status || requestBody?.state || null;
  }

  private async evaluateWorkflowCondition(
    condition: string,
    resourceType: string,
    pathParams: Record<string, string> | undefined,
    tenantId: string
  ): Promise<boolean> {
    // Implementation would evaluate workflow conditions
    return true;
  }

  private async validateTenantScopedAccess(
    request: BusinessRuleValidationRequest,
    rule: TenantDataIsolationRule,
    violations: ValidationViolation[]
  ): Promise<void> {
    // Implementation would validate tenant-scoped access
  }

  private async getUserRoles(userId: string, tenantId: string): Promise<string[]> {
    // Implementation would query user roles from database
    return ['user'];
  }

  private async auditCrossTenantAccess(
    request: BusinessRuleValidationRequest,
    rule: TenantDataIsolationRule
  ): Promise<void> {
    // Implementation would log cross-tenant access for audit
  }
}

// Factory function
export function createBusinessRuleValidator(): BusinessRuleValidator {
  const redisClient = createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    password: process.env.REDIS_PASSWORD
  });

  const pgPool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB || 'isectech',
    user: process.env.POSTGRES_USER || 'postgres',
    password: process.env.POSTGRES_PASSWORD || 'postgres',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
  });

  return new BusinessRuleValidator(redisClient, pgPool);
}

// Export singleton instance
export const businessRuleValidator = createBusinessRuleValidator();