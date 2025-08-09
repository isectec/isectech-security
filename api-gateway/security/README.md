# Custom Business Rule Validators

This module implements advanced business rule validation that goes beyond standard OpenAPI schema validation. It provides a comprehensive framework for enforcing complex business logic, compliance requirements, and security policies across the iSECTECH platform.

## Overview

The Custom Business Rule Validators system consists of several key components:

- **BusinessRuleValidator**: Core validation engine that executes business rules
- **EnhancedValidationMiddleware**: Integration layer combining schema and business rule validation
- **BusinessRuleConfigManager**: Configuration management for all business rules
- **Validation Pipeline**: Complete validation workflow from request to response

## Key Features

### 1. Transaction Limit Validation
Enforces financial transaction limits based on tenant tiers and usage patterns.

```typescript
// Automatic enforcement of tenant-based limits
const limits = {
  basic: { dailyLimit: 100, transactionValueLimit: 1000 },
  premium: { dailyLimit: 500, transactionValueLimit: 10000 },
  enterprise: { dailyLimit: 2000, transactionValueLimit: 100000 }
};
```

**Validation Rules:**
- Daily transaction count limits
- Hourly burst protection
- Single transaction value limits
- Monthly aggregate spending limits
- High-value transaction approval requirements

### 2. Time-Based Access Control
Restricts access to sensitive operations based on time windows and business schedules.

```typescript
// Financial operations restricted to business hours
{
  endpoint: '/api/v1/financial/transactions',
  method: 'POST',
  allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
  allowedHours: { start: 9, end: 17 }, // 9 AM - 5 PM
  timezone: 'America/New_York',
  emergencyOverride: true
}
```

**Features:**
- Business hours enforcement
- Timezone-aware validation
- Weekend/holiday restrictions
- Blackout period support
- Emergency override capabilities

### 3. Cross-Resource Consistency
Ensures data integrity across related resources and validates complex relationships.

```typescript
// User creation requires valid tenant reference
{
  resourceType: 'users',
  requiredFields: ['email', 'tenant_id', 'role'],
  immutableFields: ['id', 'created_at', 'tenant_id'],
  dependentResources: [{
    resourceType: 'tenants',
    relationshipType: 'reference',
    validationQuery: 'SELECT 1 FROM tenants WHERE id = $1 AND status = \'active\''
  }]
}
```

**Validation Types:**
- Required field validation
- Immutable field protection
- Cross-resource dependency checks
- Referential integrity enforcement
- Custom validation logic

### 4. Business Workflow State Management
Validates state transitions in business processes and workflows.

```typescript
// Security incident lifecycle management
{
  currentState: 'assigned',
  allowedTransitions: ['in_progress', 'escalated', 'closed'],
  requiredFields: { assigned_to: 'required' },
  preConditions: [{
    condition: 'assigned_user_active',
    errorMessage: 'Assigned user must be active'
  }]
}
```

**Features:**
- State transition validation
- Required field enforcement per state
- Pre/post-condition checks
- Workflow rule enforcement
- Automated notifications

### 5. Multi-Tenant Data Isolation
Enforces strict tenant data isolation with role-based cross-tenant access controls.

```typescript
// Strict tenant isolation for user data
{
  resourcePath: '/api/v1/users',
  isolationLevel: 'strict',
  tenantFieldName: 'tenant_id',
  auditRequired: true
}

// Controlled cross-tenant access for admin operations
{
  resourcePath: '/api/v1/admin/users',
  isolationLevel: 'cross_tenant_allowed',
  allowedCrossTenantRoles: ['admin', 'system_admin'],
  auditRequired: true
}
```

**Isolation Levels:**
- **Strict**: No cross-tenant access allowed
- **Cross-tenant allowed**: Role-based cross-tenant access
- **Global**: System-wide access (health checks, etc.)

## Integration with Existing Systems

### Schema Validation Integration
The business rule validators integrate seamlessly with the existing OpenAPI schema validation:

```typescript
// Create complete validation pipeline
const validationPipeline = createValidationPipeline({
  enableSchemaValidation: true,      // OpenAPI schema validation
  enableBusinessRuleValidation: true, // Custom business rules
  failFast: false                    // Run both validations
});

// Use in Next.js middleware
export async function middleware(request: NextRequest) {
  const validationResponse = await validationPipeline.validateRequest(request);
  if (validationResponse) {
    return validationResponse; // Validation failed
  }
  // Continue to next middleware or handler
}
```

### Error Response Format
Validation errors are returned in a standardized format:

```json
{
  "success": false,
  "error": "validation_failed",
  "error_code": "BUSINESS_RULE_VALIDATION_FAILED",
  "details": {
    "schema_errors": [...],
    "business_rule_violations": [
      {
        "rule_id": "daily_transaction_limit_exceeded",
        "severity": "critical",
        "message": "Daily transaction limit exceeded (100/100)",
        "field": "amount",
        "remediation": "Wait until tomorrow or upgrade tenant tier"
      }
    ],
    "warnings": [...]
  },
  "validation_metadata": {
    "schema_validation_time_ms": 15,
    "business_rule_validation_time_ms": 45,
    "total_validation_time_ms": 60
  },
  "request_id": "val_1704123456789_abc123",
  "timestamp": "2024-01-08T10:30:00Z"
}
```

## Configuration Management

### Environment-Based Configuration
Business rules can be configured through environment variables:

```bash
# Enable/disable business rule validation
BUSINESS_RULES_ENABLED=true
BUSINESS_RULES_STRICT_MODE=true
BUSINESS_RULES_MAX_VALIDATION_TIME_MS=10000

# Database and cache connections
POSTGRES_HOST=localhost
POSTGRES_DB=isectech
REDIS_URL=redis://localhost:6379

# Security settings
JWT_SECRET=your-jwt-secret-key
SECURITY_WEBHOOK_URL=https://api.example.com/security-alerts
```

### Runtime Configuration Updates
Configuration can be updated at runtime:

```typescript
import { businessRuleConfigManager } from './business-rules-config';

// Update transaction limits for a specific tenant tier
businessRuleConfigManager.updateConfig({
  transactionLimits: {
    tiers: {
      premium: {
        dailyLimit: 750,        // Increased from 500
        hourlyLimit: 150,       // Increased from 100
        transactionValueLimit: 15000, // Increased from 10000
        aggregateMonthlyLimit: 375000
      }
    }
  }
});
```

## Performance and Scalability

### Caching Strategy
The system implements multiple levels of caching:

- **Usage Tracking Cache**: Redis-based caching for transaction usage data
- **Validation Result Cache**: Caches successful validation results
- **Configuration Cache**: Caches business rule configurations
- **Database Query Cache**: Caches frequently accessed validation data

### Performance Metrics
- **Target Validation Time**: < 100ms for simple rules, < 500ms for complex workflows
- **Cache Hit Ratio**: > 80% for repeated validations
- **Database Query Optimization**: Prepared statements and connection pooling
- **Concurrent Validation**: Parallel execution of independent rule checks

### Monitoring and Alerting
Built-in monitoring for validation performance and rule violations:

```typescript
// Built-in performance monitoring
{
  alertThresholds: {
    validationTimeMs: 5000,        // Alert if validation takes > 5s
    violationRatePerHour: 100,     // Alert if > 100 violations/hour
    systemErrorRate: 0.1          // Alert if > 10% system errors
  }
}
```

## Security Considerations

### Threat Detection
The system includes built-in threat detection patterns:

```typescript
{
  suspiciousPatterns: [
    {
      pattern: 'rapid_failed_validations',
      severity: 'high',
      action: 'block'
    },
    {
      pattern: 'cross_tenant_access_attempt',
      severity: 'medium',
      action: 'warn'
    },
    {
      pattern: 'off_hours_sensitive_access',
      severity: 'medium',
      action: 'escalate'
    }
  ]
}
```

### Audit Logging
All business rule validations are audited:

- Successful validations (configurable)
- Failed validations (always logged)
- Cross-tenant access attempts
- Configuration changes
- System errors and exceptions

### Rate Limiting Integration
Failed business rule validations can trigger enhanced rate limiting:

```typescript
{
  rateLimitingIntegration: {
    enabled: true,
    penaltyMultiplier: 2.0  // Double the rate limiting for violators
  }
}
```

## Testing Framework

### Unit Tests
Comprehensive test coverage for all business rule validators:

```bash
npm test -- business-rule-validators.test.ts
```

### Integration Tests
End-to-end testing of the complete validation pipeline:

```typescript
// Example integration test
it('should validate complete transaction workflow', async () => {
  const request = createTransactionRequest({
    amount: 500,
    tenantTier: 'basic',
    timestamp: businessHours
  });
  
  const result = await validationPipeline.validateRequest(request);
  expect(result).toBeNull(); // Validation passed
});
```

### Load Testing
Performance testing under realistic load conditions:

```bash
# Run load tests
npm run test:load
```

## Development Guidelines

### Adding New Business Rules

1. **Define Rule Configuration**: Add rule configuration to `business-rules-config.ts`
2. **Implement Validation Logic**: Add validation method to `BusinessRuleValidator`
3. **Write Tests**: Create comprehensive test cases
4. **Update Documentation**: Document the new rule behavior

Example of adding a new rule:

```typescript
// 1. Add configuration
export interface CustomRule {
  enabled: boolean;
  threshold: number;
  message: string;
}

// 2. Implement validation
private async validateCustomRule(request: BusinessRuleValidationRequest): Promise<ValidationResult> {
  // Implementation logic
}

// 3. Integrate into main validator
const validationResults = await Promise.allSettled([
  this.validateTransactionLimits(request),
  this.validateTimeBasedAccess(request),
  this.validateCustomRule(request), // New rule
  // ... other rules
]);
```

### Best Practices

1. **Performance First**: Design rules for sub-second validation times
2. **Fail Gracefully**: Handle errors without breaking the validation pipeline
3. **Audit Everything**: Log all business rule decisions for compliance
4. **Cache Aggressively**: Cache validation results and frequently accessed data
5. **Monitor Continuously**: Track validation performance and rule effectiveness

## API Reference

### Core Classes

#### BusinessRuleValidator
Main validation engine that executes all business rule checks.

```typescript
class BusinessRuleValidator {
  async validateBusinessRules(request: BusinessRuleValidationRequest): Promise<BusinessRuleValidationResult>
}
```

#### EnhancedValidationMiddleware
Integration middleware that combines schema and business rule validation.

```typescript
class EnhancedValidationMiddleware {
  async validateRequest(request: NextRequest): Promise<NextResponse | null>
  createMiddlewareFunction(): (request: NextRequest) => Promise<NextResponse | null>
}
```

#### BusinessRuleConfigManager
Configuration management for all business rules.

```typescript
class BusinessRuleConfigManager {
  getConfig(): BusinessRuleConfig
  updateConfig(updates: Partial<BusinessRuleConfig>): void
  validateConfig(): { isValid: boolean; errors: string[] }
}
```

### Utility Functions

```typescript
// Create complete validation pipeline
function createValidationPipeline(config?: ValidationPipelineConfig): EnhancedValidationMiddleware

// Standalone business rule validation
async function validateBusinessRulesStandalone(request: BusinessRuleValidationRequest): Promise<BusinessRuleValidationResult>

// Check if endpoint requires validation
function requiresValidation(pathname: string, method: string): boolean

// Validate security configuration
function validateSecurityConfiguration(): { isValid: boolean; errors: string[]; warnings: string[] }

// Health check for security components
async function performSecurityHealthCheck(): Promise<HealthCheckResult>
```

## Compliance and Audit

The business rule validation system is designed to support various compliance frameworks:

- **SOC 2**: Comprehensive audit logging and access controls
- **GDPR**: Data protection and privacy controls
- **ISO 27001**: Information security management
- **PCI DSS**: Payment card industry security standards

### Audit Trail
All validation activities are logged with:
- Request details and validation results
- User and tenant context
- Timestamp and request tracing
- Rule-specific metadata
- Performance metrics

### Compliance Reporting
Built-in reporting for compliance audits:
- Validation failure rates
- Rule effectiveness metrics
- Access pattern analysis
- Security violation trends

## Troubleshooting

### Common Issues

#### High Validation Latency
- Check database connection pool size
- Review Redis cache hit rates
- Examine business rule complexity
- Consider rule-specific optimizations

#### False Positive Violations
- Review rule configuration accuracy
- Validate tenant tier assignments
- Check time zone configurations
- Verify resource dependency mappings

#### Configuration Errors
- Use `validateSecurityConfiguration()` to check setup
- Review environment variable configuration
- Validate JSON configuration syntax
- Check database schema compatibility

### Debug Mode
Enable debug logging for detailed validation information:

```bash
DEBUG=business-rule-validators:* npm start
```

### Performance Profiling
Built-in performance profiling for rule optimization:

```typescript
// Enable detailed performance metrics
const config = {
  enableMetrics: true,
  detailedProfiling: true
};
```

## Support and Maintenance

For questions, issues, or feature requests related to the Custom Business Rule Validators:

1. Check the troubleshooting guide above
2. Review the test suite for usage examples
3. Consult the API documentation for detailed method signatures
4. Submit issues through the project's issue tracking system

The system is actively maintained and regularly updated to support new business requirements and compliance standards.