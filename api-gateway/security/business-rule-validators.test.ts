/**
 * Test Suite for Business Rule Validators
 * Comprehensive testing of custom business rule validation logic
 * 
 * Task: 83.5 - Testing framework for business rule validators
 */

import { jest } from '@jest/globals';
import { 
  BusinessRuleValidator,
  BusinessRuleValidationRequest,
  ValidationViolation,
  ValidationWarning
} from './business-rule-validators';
import { TenantContext } from './tenant-context-service';
import { createClient } from 'redis';
import { Pool } from 'pg';

// Mock dependencies
jest.mock('redis');
jest.mock('pg');

describe('BusinessRuleValidator', () => {
  let validator: BusinessRuleValidator;
  let mockRedisClient: jest.Mocked<ReturnType<typeof createClient>>;
  let mockPgPool: jest.Mocked<Pool>;

  beforeEach(() => {
    // Setup mocks
    mockRedisClient = {
      get: jest.fn(),
      set: jest.fn(),
      setex: jest.fn(),
      del: jest.fn(),
      connect: jest.fn(),
      disconnect: jest.fn()
    } as any;

    mockPgPool = {
      connect: jest.fn(),
      query: jest.fn(),
      end: jest.fn()
    } as any;

    // Create validator instance
    validator = new BusinessRuleValidator(mockRedisClient, mockPgPool);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Transaction Limit Validation', () => {
    const createTransactionRequest = (
      tenantTier: string = 'basic',
      transactionValue: number = 500
    ): BusinessRuleValidationRequest => ({
      userId: 'user-123',
      tenantId: 'tenant-456',
      endpoint: '/api/v1/financial/transactions',
      method: 'POST',
      requestBody: {
        amount: transactionValue,
        currency: 'USD',
        recipient: 'user-789'
      },
      tenantContext: {
        tenantId: 'tenant-456',
        tenantName: 'Test Tenant',
        tenantType: 'standard',
        tenantTier: tenantTier as any,
        status: 'active',
        features: ['transactions'],
        complianceFrameworks: ['SOC2']
      } as TenantContext,
      timestamp: new Date()
    });

    it('should pass validation for transaction within limits', async () => {
      // Mock usage data showing user is within limits
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 5,
        totalValue: 1000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 1,
        totalValue: 500
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 50,
        totalValue: 10000
      });

      const request = createTransactionRequest('basic', 500);
      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it('should fail validation when daily limit exceeded', async () => {
      // Mock usage data showing daily limit exceeded
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 100, // Basic tier daily limit
        totalValue: 25000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 5,
        totalValue: 500
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 100,
        totalValue: 25000
      });

      const request = createTransactionRequest('basic', 500);
      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe('daily_transaction_limit_exceeded');
      expect(result.violations[0].severity).toBe('critical');
    });

    it('should fail validation when transaction value exceeds limit', async () => {
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 5,
        totalValue: 1000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 1,
        totalValue: 2000
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 5,
        totalValue: 2000
      });

      const request = createTransactionRequest('basic', 2000); // Exceeds basic tier limit of 1000
      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].ruleId).toBe('transaction_value_limit_exceeded');
      expect(result.violations[0].severity).toBe('critical');
    });

    it('should generate warnings when approaching limits', async () => {
      // Mock usage showing 85% of daily limit used
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 85, // 85% of 100 (basic tier daily limit)
        totalValue: 20000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 5,
        totalValue: 500
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 85,
        totalValue: 20000
      });

      const request = createTransactionRequest('basic', 500);
      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(true);
      expect(result.warnings).toHaveLength(1);
      expect(result.warnings[0].ruleId).toBe('daily_transaction_limit_warning');
    });

    it('should handle different tenant tiers correctly', async () => {
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 200, // Would exceed basic but not premium
        totalValue: 50000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 50,
        totalValue: 50000
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 200,
        totalValue: 50000
      });

      const premiumRequest = createTransactionRequest('premium', 5000);
      const result = await validator.validateBusinessRules(premiumRequest);

      expect(result.isValid).toBe(true);
    });

    it('should validate approval requirements for high-value transactions', async () => {
      jest.spyOn(validator as any, 'getDailyTransactionUsage').mockResolvedValue({
        count: 10,
        totalValue: 20000
      });
      jest.spyOn(validator as any, 'getHourlyTransactionUsage').mockResolvedValue({
        count: 2,
        totalValue: 7000
      });
      jest.spyOn(validator as any, 'getMonthlyTransactionUsage').mockResolvedValue({
        count: 50,
        totalValue: 100000
      });
      jest.spyOn(validator as any, 'checkTransactionApproval').mockResolvedValue(false);

      const request = createTransactionRequest('premium', 7000); // Exceeds approval threshold of 5000
      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.some(v => v.ruleId === 'transaction_approval_required')).toBe(true);
    });
  });

  describe('Time-Based Access Validation', () => {
    const createTimeBasedRequest = (
      endpoint: string = '/api/v1/financial/transactions',
      method: string = 'POST'
    ): BusinessRuleValidationRequest => ({
      userId: 'user-123',
      tenantId: 'tenant-456',
      endpoint,
      method,
      requestBody: {},
      timestamp: new Date('2024-01-15T14:30:00Z') // Monday at 2:30 PM UTC
    });

    it('should allow access during allowed hours and days', async () => {
      const request = createTimeBasedRequest();
      const result = await validator.validateBusinessRules(request);

      // Note: This test assumes the request time falls within allowed hours
      // The actual validation would depend on the timezone conversion
      expect(result.violations.filter(v => v.ruleId.includes('time_based')).length).toBe(0);
    });

    it('should block access outside allowed hours', async () => {
      // Mock a request made outside business hours
      const request: BusinessRuleValidationRequest = {
        ...createTimeBasedRequest(),
        timestamp: new Date('2024-01-15T22:30:00Z') // Monday at 10:30 PM UTC (outside 9-5 NY time)
      };

      // Mock the time validation to simulate outside hours
      jest.spyOn(validator as any, 'validateTimeBasedAccess').mockResolvedValue({
        violations: [{
          ruleId: 'access_outside_allowed_hours',
          severity: 'high',
          message: 'Access not allowed at 22:00. Allowed hours: 9:00-17:00',
          remediation: 'Access only during allowed hours'
        }],
        warnings: []
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.some(v => v.ruleId === 'access_outside_allowed_hours')).toBe(true);
    });

    it('should block access on weekends for business-day-only endpoints', async () => {
      const request: BusinessRuleValidationRequest = {
        ...createTimeBasedRequest(),
        timestamp: new Date('2024-01-14T14:30:00Z') // Sunday at 2:30 PM UTC
      };

      // Mock weekend restriction
      jest.spyOn(validator as any, 'validateTimeBasedAccess').mockResolvedValue({
        violations: [{
          ruleId: 'access_not_allowed_today',
          severity: 'high',
          message: 'Access not allowed on Sunday. Allowed days: Monday, Tuesday, Wednesday, Thursday, Friday',
          remediation: 'Access only during allowed days'
        }],
        warnings: []
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.some(v => v.ruleId === 'access_not_allowed_today')).toBe(true);
    });

    it('should handle blackout periods', async () => {
      const request = createTimeBasedRequest();

      // Mock blackout period violation
      jest.spyOn(validator as any, 'validateTimeBasedAccess').mockResolvedValue({
        violations: [{
          ruleId: 'access_during_blackout_period',
          severity: 'critical',
          message: 'Access not allowed during blackout period: System maintenance',
          remediation: 'Wait until blackout period ends'
        }],
        warnings: []
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.some(v => v.ruleId === 'access_during_blackout_period')).toBe(true);
    });
  });

  describe('Resource Consistency Validation', () => {
    const createResourceRequest = (
      endpoint: string = '/api/v1/users',
      method: string = 'POST',
      requestBody: any = {}
    ): BusinessRuleValidationRequest => ({
      userId: 'user-123',
      tenantId: 'tenant-456',
      endpoint,
      method,
      requestBody,
      timestamp: new Date()
    });

    it('should pass validation when all required fields are present', async () => {
      const request = createResourceRequest('/api/v1/users', 'POST', {
        email: 'test@example.com',
        tenant_id: 'tenant-456',
        role: 'user',
        name: 'Test User'
      });

      // Mock successful dependency validation
      jest.spyOn(validator as any, 'validateResourceDependency').mockResolvedValue(true);

      const result = await validator.validateBusinessRules(request);

      // Filter for only resource consistency violations
      const resourceViolations = result.violations.filter(v => 
        v.ruleId.includes('required_field') || v.ruleId.includes('resource_consistency')
      );
      
      expect(resourceViolations).toHaveLength(0);
    });

    it('should fail validation when required fields are missing', async () => {
      const request = createResourceRequest('/api/v1/users', 'POST', {
        email: 'test@example.com',
        // missing tenant_id and role
      });

      const result = await validator.validateBusinessRules(request);

      const requiredFieldViolations = result.violations.filter(v => v.ruleId === 'required_field_missing');
      expect(requiredFieldViolations.length).toBeGreaterThan(0);
      expect(requiredFieldViolations.some(v => v.field === 'tenant_id')).toBe(true);
      expect(requiredFieldViolations.some(v => v.field === 'role')).toBe(true);
    });

    it('should fail validation when immutable fields are modified', async () => {
      const request = createResourceRequest('/api/v1/users', 'PUT', {
        id: 'user-123',
        email: 'updated@example.com',
        tenant_id: 'different-tenant', // Immutable field being modified
        created_at: '2024-01-01T00:00:00Z' // Immutable field being modified
      });

      const result = await validator.validateBusinessRules(request);

      const immutableViolations = result.violations.filter(v => v.ruleId === 'immutable_field_modification');
      expect(immutableViolations.length).toBeGreaterThan(0);
      expect(immutableViolations.some(v => v.field === 'tenant_id')).toBe(true);
      expect(immutableViolations.some(v => v.field === 'created_at')).toBe(true);
    });

    it('should validate dependent resource relationships', async () => {
      const request = createResourceRequest('/api/v1/assets', 'POST', {
        name: 'Test Asset',
        type: 'server',
        tenant_id: 'tenant-456',
        owner_id: 'nonexistent-user'
      });

      // Mock failed dependency validation
      jest.spyOn(validator as any, 'validateResourceDependency').mockResolvedValue(false);

      const result = await validator.validateBusinessRules(request);

      const dependencyViolations = result.violations.filter(v => v.ruleId === 'resource_dependency_violation');
      expect(dependencyViolations.length).toBeGreaterThan(0);
    });
  });

  describe('Workflow State Validation', () => {
    const createWorkflowRequest = (
      currentState: string = 'new',
      targetState: string = 'assigned',
      resourceId: string = 'incident-123'
    ): BusinessRuleValidationRequest => ({
      userId: 'user-123',
      tenantId: 'tenant-456',
      endpoint: '/api/v1/incidents/transition',
      method: 'PUT',
      requestBody: {
        status: targetState,
        assigned_to: 'user-456'
      },
      pathParams: {
        id: resourceId
      },
      timestamp: new Date()
    });

    it('should allow valid state transitions', async () => {
      // Mock current state lookup
      jest.spyOn(validator as any, 'getCurrentWorkflowState').mockResolvedValue('new');
      jest.spyOn(validator as any, 'evaluateWorkflowCondition').mockResolvedValue(true);

      const request = createWorkflowRequest('new', 'assigned');
      const result = await validator.validateBusinessRules(request);

      const workflowViolations = result.violations.filter(v => 
        v.ruleId.includes('workflow') || v.ruleId.includes('state_transition')
      );
      
      expect(workflowViolations).toHaveLength(0);
    });

    it('should block invalid state transitions', async () => {
      // Mock current state lookup
      jest.spyOn(validator as any, 'getCurrentWorkflowState').mockResolvedValue('new');

      const request = createWorkflowRequest('new', 'resolved'); // Invalid transition
      const result = await validator.validateBusinessRules(request);

      const transitionViolations = result.violations.filter(v => v.ruleId === 'invalid_state_transition');
      expect(transitionViolations.length).toBeGreaterThan(0);
    });

    it('should validate required fields for state transitions', async () => {
      jest.spyOn(validator as any, 'getCurrentWorkflowState').mockResolvedValue('in_progress');
      
      const request: BusinessRuleValidationRequest = {
        ...createWorkflowRequest('in_progress', 'resolved'),
        requestBody: {
          status: 'resolved'
          // missing resolution_notes which is required for 'resolved' state
        }
      };

      const result = await validator.validateBusinessRules(request);

      const fieldViolations = result.violations.filter(v => v.ruleId === 'workflow_required_field_mismatch');
      expect(fieldViolations.length).toBeGreaterThan(0);
    });

    it('should validate pre-conditions', async () => {
      jest.spyOn(validator as any, 'getCurrentWorkflowState').mockResolvedValue('assigned');
      jest.spyOn(validator as any, 'evaluateWorkflowCondition').mockResolvedValue(false);

      const request = createWorkflowRequest('assigned', 'in_progress');
      const result = await validator.validateBusinessRules(request);

      const preconditionViolations = result.violations.filter(v => v.ruleId === 'workflow_precondition_failed');
      expect(preconditionViolations.length).toBeGreaterThan(0);
    });
  });

  describe('Tenant Data Isolation Validation', () => {
    const createIsolationRequest = (
      endpoint: string = '/api/v1/users',
      tenantId: string = 'tenant-456',
      resourceTenantId?: string
    ): BusinessRuleValidationRequest => ({
      userId: 'user-123',
      tenantId,
      endpoint,
      method: 'GET',
      requestBody: resourceTenantId ? { tenant_id: resourceTenantId } : undefined,
      timestamp: new Date()
    });

    it('should allow access to same-tenant resources', async () => {
      const request = createIsolationRequest('/api/v1/users', 'tenant-456', 'tenant-456');
      const result = await validator.validateBusinessRules(request);

      const isolationViolations = result.violations.filter(v => v.ruleId.includes('tenant_isolation'));
      expect(isolationViolations).toHaveLength(0);
    });

    it('should block cross-tenant access in strict mode', async () => {
      const request = createIsolationRequest('/api/v1/users', 'tenant-456', 'different-tenant');
      const result = await validator.validateBusinessRules(request);

      const isolationViolations = result.violations.filter(v => v.ruleId === 'tenant_isolation_violation');
      expect(isolationViolations.length).toBeGreaterThan(0);
    });

    it('should allow cross-tenant access for authorized roles', async () => {
      // Mock user with admin role
      jest.spyOn(validator as any, 'getUserRoles').mockResolvedValue(['admin']);
      jest.spyOn(validator as any, 'auditCrossTenantAccess').mockResolvedValue(undefined);

      const request = createIsolationRequest('/api/v1/admin/users', 'tenant-456', 'different-tenant');
      const result = await validator.validateBusinessRules(request);

      const isolationViolations = result.violations.filter(v => v.ruleId.includes('tenant_isolation'));
      expect(isolationViolations).toHaveLength(0);
    });

    it('should block cross-tenant access for unauthorized roles', async () => {
      // Mock user with regular user role
      jest.spyOn(validator as any, 'getUserRoles').mockResolvedValue(['user']);

      const request = createIsolationRequest('/api/v1/admin/users', 'tenant-456', 'different-tenant');
      const result = await validator.validateBusinessRules(request);

      const permissionViolations = result.violations.filter(v => v.ruleId === 'insufficient_cross_tenant_permissions');
      expect(permissionViolations.length).toBeGreaterThan(0);
    });
  });

  describe('Performance and Error Handling', () => {
    it('should complete validation within reasonable time', async () => {
      const request: BusinessRuleValidationRequest = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        endpoint: '/api/v1/test',
        method: 'POST',
        timestamp: new Date()
      };

      const startTime = Date.now();
      const result = await validator.validateBusinessRules(request);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(5000); // Should complete in under 5 seconds
      expect(result.evaluationTimeMs).toBeGreaterThan(0);
    });

    it('should handle validation errors gracefully', async () => {
      // Mock a validation method that throws an error
      jest.spyOn(validator as any, 'validateTransactionLimits').mockRejectedValue(new Error('Database connection failed'));

      const request: BusinessRuleValidationRequest = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        endpoint: '/api/v1/financial/transactions',
        method: 'POST',
        timestamp: new Date()
      };

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
      expect(result.violations.some(v => v.message.includes('validation failed'))).toBe(true);
    });

    it('should return appropriate metadata', async () => {
      const request: BusinessRuleValidationRequest = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        endpoint: '/api/v1/financial/transactions',
        method: 'POST',
        requestBody: { amount: 100 },
        tenantContext: {
          tenantTier: 'basic'
        } as TenantContext,
        timestamp: new Date()
      };

      // Mock transaction validation to return metadata
      jest.spyOn(validator as any, 'validateTransactionLimits').mockResolvedValue({
        violations: [],
        warnings: [],
        metadata: {
          currentUsage: { dailyUsage: { count: 5, totalValue: 500 } },
          limits: { dailyLimit: 100 }
        }
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.metadata).toBeDefined();
      expect(result.metadata?.currentUsage).toBeDefined();
    });
  });

  describe('Integration with Multiple Rules', () => {
    it('should validate multiple business rules simultaneously', async () => {
      const request: BusinessRuleValidationRequest = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        endpoint: '/api/v1/financial/transactions',
        method: 'POST',
        requestBody: {
          amount: 2000, // Exceeds basic tier limit
          recipient: 'user-789'
        },
        tenantContext: {
          tenantTier: 'basic'
        } as TenantContext,
        timestamp: new Date('2024-01-14T14:30:00Z') // Sunday (weekend)
      };

      // Mock violations from multiple validators
      jest.spyOn(validator as any, 'validateTransactionLimits').mockResolvedValue({
        violations: [{
          ruleId: 'transaction_value_limit_exceeded',
          severity: 'critical',
          message: 'Transaction value exceeds limit'
        }],
        warnings: []
      });

      jest.spyOn(validator as any, 'validateTimeBasedAccess').mockResolvedValue({
        violations: [{
          ruleId: 'access_not_allowed_today',
          severity: 'high',
          message: 'Access not allowed on Sunday'
        }],
        warnings: []
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(false);
      expect(result.violations.length).toBeGreaterThanOrEqual(2);
      expect(result.violations.some(v => v.ruleId === 'transaction_value_limit_exceeded')).toBe(true);
      expect(result.violations.some(v => v.ruleId === 'access_not_allowed_today')).toBe(true);
    });

    it('should aggregate warnings from all validators', async () => {
      const request: BusinessRuleValidationRequest = {
        userId: 'user-123',
        tenantId: 'tenant-456',
        endpoint: '/api/v1/assets',
        method: 'POST',
        requestBody: {
          name: 'Test Asset',
          type: 'server',
          tenant_id: 'tenant-456'
        },
        timestamp: new Date()
      };

      // Mock warnings from multiple validators
      jest.spyOn(validator as any, 'validateTransactionLimits').mockResolvedValue({
        violations: [],
        warnings: [{
          ruleId: 'approaching_daily_limit',
          message: 'Approaching daily transaction limit'
        }]
      });

      jest.spyOn(validator as any, 'validateResourceConsistency').mockResolvedValue({
        violations: [],
        warnings: [{
          ruleId: 'missing_optional_field',
          message: 'Optional field description not provided'
        }]
      });

      const result = await validator.validateBusinessRules(request);

      expect(result.isValid).toBe(true);
      expect(result.warnings.length).toBeGreaterThanOrEqual(2);
    });
  });
});