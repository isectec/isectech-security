# RBAC Context Management Integration Guide

## Overview

This guide documents the integration of Task 80.3 context management functions with the existing RBAC system. The implementation provides simple wrapper functions that meet the task requirements while leveraging the comprehensive security features of the existing RBAC implementation.

## Task Requirements vs Implementation

### Required Functions (Task 80.3)
- ✅ `set_current_tenant_id(tenant_id)` - Set tenant context
- ✅ `set_current_user_id(user_id)` - Set user context  
- ✅ `current_tenant_id()` - Get current tenant
- ✅ `current_user_id()` - Get current user

### Enhanced Functions (Additional)
- ✅ `set_session_context(tenant_id, user_id)` - Set both contexts atomically
- ✅ `get_session_context()` - Get complete context information
- ✅ `clear_session_context()` - Clear all context

## Architecture Overview

```
Application Layer
      ↓
Context Management Functions (Task 80.3)
├── set_current_tenant_id()     ├── current_tenant_id()
├── set_current_user_id()       ├── current_user_id() 
├── set_session_context()       ├── get_session_context()
└── clear_session_context()     └── (Enhanced functions)
      ↓
PostgreSQL Session Variables
├── app.current_tenant_id
├── app.current_user_id
└── Session context validation
      ↓
Row-Level Security (RLS) Policies
├── tenant_isolation_*
├── Audit logging
└── Cross-tenant access prevention
```

## Function Relationships

### Core Context Functions
```sql
-- Existing RBAC functions (comprehensive, secure)
rbac_set_tenant_context(tenant_id, user_id)  -- Full validation + audit
rbac_get_current_tenant_id()                 -- Enhanced validation
rbac_get_current_user_id()                   -- Enhanced validation
rbac_clear_context()                         -- Context clearing

-- Task 80.3 functions (simple interface)
set_current_tenant_id(tenant_id)             -- Simple tenant setter
set_current_user_id(user_id)                 -- Simple user setter
current_tenant_id()                          -- Simple tenant getter
current_user_id()                            -- Simple user getter
```

## Usage Patterns

### Basic Usage (Task Requirements)

```sql
-- 1. Set tenant context
SELECT set_current_tenant_id('123e4567-e89b-12d3-a456-426614174000');

-- 2. Set user context
SELECT set_current_user_id('234e5678-e89b-12d3-a456-426614174001');

-- 3. Get current contexts
SELECT current_tenant_id(), current_user_id();

-- 4. Use with RLS-protected queries
SELECT * FROM roles;  -- Only shows roles for current tenant
SELECT * FROM user_roles WHERE user_id = current_user_id();
```

### Enhanced Usage (Production Recommended)

```sql
-- 1. Set complete session context atomically
SELECT set_session_context(
    '123e4567-e89b-12d3-a456-426614174000',  -- tenant_id
    '234e5678-e89b-12d3-a456-426614174001'   -- user_id
);

-- 2. Get complete context information
SELECT get_session_context();

-- 3. Clear context when done
SELECT clear_session_context();
```

## Integration with RLS Policies

The context functions integrate seamlessly with existing RLS policies:

### Tenant Isolation
```sql
-- RLS policies automatically use session context
CREATE POLICY tenant_isolation_roles ON roles
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Context functions set the session variables used by policies
SELECT set_current_tenant_id('tenant-uuid');  -- Sets app.current_tenant_id
SELECT * FROM roles;  -- RLS automatically filters by tenant
```

### Cross-Tenant Access Prevention
```sql
-- Attempting cross-tenant access triggers audit logging
SELECT set_current_tenant_id('tenant-1-uuid');
SELECT * FROM roles WHERE tenant_id = 'tenant-2-uuid';  -- Blocked + logged
```

## Security Features

### Input Validation
- All tenant IDs validated against `tenants` table
- All user IDs validated against `users` table  
- User-tenant association verified through `user_roles`
- Invalid contexts rejected with descriptive errors

### Audit Logging
- Context setting logged to `security_audit_log`
- Cross-tenant access attempts logged and blocked
- Real-time notifications via PostgreSQL `pg_notify`

### Error Handling
- Fail-safe design: errors clear context
- Descriptive error messages for troubleshooting
- Exception handling prevents privilege escalation

## Testing and Validation

### Comprehensive Test Suite
Located: `backend/security/test_context_management_functions.sql`

Test categories:
1. **Basic Tenant Functions** - Validate tenant context setting/getting
2. **Basic User Functions** - Validate user context setting/getting  
3. **Enhanced Context Functions** - Test session management
4. **RLS Integration** - Verify tenant isolation works
5. **Error Handling** - Validate security error cases

### Running Tests
```sql
-- Run all tests and display results
\i backend/security/test_context_management_functions.sql

-- Or run specific test function
SELECT * FROM run_context_management_tests();
SELECT display_test_results();
```

## Production Deployment

### File Locations
```
backend/security/
├── rbac_schema.sql                          # Core RBAC schema
├── rbac_rls_policies.sql                    # Comprehensive RLS policies  
├── tenant-context-schema.sql                # Extended tenant metadata
├── context_management_functions.sql         # Task 80.3 functions
├── test_context_management_functions.sql    # Test suite
└── rbac_context_integration_guide.md        # This document
```

### Deployment Order
1. Ensure `rbac_schema.sql` is deployed
2. Ensure `rbac_rls_policies.sql` is deployed
3. Deploy `context_management_functions.sql`
4. Run `test_context_management_functions.sql` to validate
5. Grant appropriate permissions to application roles

### Required Grants
```sql
GRANT EXECUTE ON FUNCTION set_current_tenant_id(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION set_current_user_id(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION current_tenant_id() TO application_role;
GRANT EXECUTE ON FUNCTION current_user_id() TO application_role;
GRANT EXECUTE ON FUNCTION set_session_context(UUID, UUID) TO application_role;
GRANT EXECUTE ON FUNCTION get_session_context() TO application_role;
GRANT EXECUTE ON FUNCTION clear_session_context() TO application_role;
```

## Application Integration Examples

### Go Backend Integration
```go
// Set session context at request start
func setUserContext(db *sql.DB, tenantID, userID string) error {
    query := `SELECT set_session_context($1::UUID, $2::UUID)`
    var result json.RawMessage
    err := db.QueryRow(query, tenantID, userID).Scan(&result)
    
    if err != nil {
        return fmt.Errorf("failed to set context: %w", err)
    }
    
    var ctxResult map[string]interface{}
    json.Unmarshal(result, &ctxResult)
    
    if !ctxResult["success"].(bool) {
        return fmt.Errorf("context validation failed: %s", ctxResult["error"])
    }
    
    return nil
}

// Clear context at request end
func clearUserContext(db *sql.DB) error {
    _, err := db.Exec(`SELECT clear_session_context()`)
    return err
}
```

### Next.js API Route Integration
```typescript
// API middleware for context management
export async function withTenantContext(
    req: NextRequest,
    handler: (req: NextRequest) => Promise<Response>
) {
    const tenantId = req.headers.get('x-tenant-id');
    const userId = req.headers.get('x-user-id');
    
    if (!tenantId || !userId) {
        return new Response('Missing tenant or user context', { status: 401 });
    }
    
    // Set context
    const result = await db.query(
        'SELECT set_session_context($1::UUID, $2::UUID)',
        [tenantId, userId]
    );
    
    if (!result.rows[0].set_session_context.success) {
        return new Response('Invalid context', { status: 403 });
    }
    
    try {
        return await handler(req);
    } finally {
        // Clear context
        await db.query('SELECT clear_session_context()');
    }
}
```

## Performance Considerations

### Session Variable Performance
- Session variables are per-connection, very fast access
- No database round-trips for context retrieval within queries  
- RLS policies use session variables directly in WHERE clauses

### Connection Pooling
- Context must be set per connection/transaction
- Use connection-scoped context setting in pooled environments
- Clear context when returning connections to pool

### Caching Strategies
- Context validation results can be cached briefly
- Session context changes require cache invalidation
- Consider connection-local caching for repeated validations

## Monitoring and Observability

### Context Usage Metrics
- Monitor context setting frequency via audit logs
- Track validation failures and reasons
- Alert on unusual cross-tenant access attempts

### Performance Metrics  
- Context function execution times
- RLS policy evaluation performance
- Session variable access patterns

### Security Monitoring
- Failed context validations
- Cross-tenant access attempts  
- Context manipulation attempts
- Audit log analysis

## Best Practices

### Development
1. Always set tenant context before user context
2. Use `set_session_context()` for atomic context setting
3. Implement proper error handling for context failures
4. Clear context in finally blocks or defer statements

### Production
1. Use connection pooling with proper context management
2. Implement request-scoped context setting/clearing
3. Monitor audit logs for security violations
4. Regular testing of RLS policy effectiveness

### Security
1. Never trust client-provided context without validation
2. Always validate user-tenant associations
3. Implement proper session management
4. Use audit logging for compliance and security monitoring

## Troubleshooting

### Common Issues
1. **"Tenant context not set"** - Call `set_current_tenant_id()` first
2. **"User not authorized for tenant"** - Verify user has role in tenant
3. **"Cross-tenant access blocked"** - Check tenant context is correct
4. **"RLS policy violation"** - Review audit logs for details

### Debugging Commands
```sql
-- Check current context
SELECT get_session_context();

-- Verify RLS is working
SELECT * FROM test_rbac_rls_enforcement();

-- Check audit logs for violations
SELECT * FROM rbac_security_violations;

-- Test context functions
SELECT * FROM run_context_management_tests();
```

## Conclusion

The Task 80.3 implementation provides the exact interface specified while leveraging the comprehensive security features of the existing RBAC system. The functions are production-ready with:

- ✅ Complete input validation
- ✅ Comprehensive audit logging  
- ✅ RLS integration
- ✅ Error handling
- ✅ Performance optimization
- ✅ Extensive testing
- ✅ Production deployment guide

This ensures tenant isolation, security compliance, and operational excellence for the iSECTECH platform's multi-tenant RBAC system.