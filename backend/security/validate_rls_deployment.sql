-- RBAC RLS Deployment Validation Script
-- Quick validation to ensure RLS policies are properly deployed and working

-- Check if basic schema exists
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenants') THEN
        RAISE EXCEPTION 'RBAC schema not found. Please run rbac_schema.sql first.';
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.routines WHERE routine_name = 'rbac_get_current_tenant_id') THEN
        RAISE EXCEPTION 'RLS functions not found. Please run rbac_rls_policies.sql first.';
    END IF;
    
    RAISE NOTICE 'Schema and functions verified successfully.';
END;
$$;

-- Validation Results Table
CREATE TEMP TABLE IF NOT EXISTS validation_results (
    check_name TEXT,
    status TEXT,
    details TEXT
);

-- Check 1: RLS enabled on all RBAC tables
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'RLS_ENABLED_STATUS',
    CASE WHEN COUNT(*) = 8 THEN 'PASS' ELSE 'FAIL' END,
    format('RLS enabled on %s out of 8 RBAC tables', COUNT(*))
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema()
AND c.relname IN ('tenants', 'users', 'roles', 'role_hierarchy', 
                  'permissions', 'role_permissions', 'user_roles', 'permission_attributes')
AND c.relrowsecurity = true;

-- Check 2: RLS policies count
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'RLS_POLICIES_COUNT',
    CASE WHEN COUNT(*) >= 10 THEN 'PASS' ELSE 'FAIL' END,
    format('%s RLS policies found (expected 10+)', COUNT(*))
FROM pg_policy p
JOIN pg_class c ON p.polrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE n.nspname = current_schema()
AND c.relname IN ('tenants', 'users', 'roles', 'role_hierarchy', 
                  'permissions', 'role_permissions', 'user_roles', 'permission_attributes');

-- Check 3: Security functions exist
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'SECURITY_FUNCTIONS_EXIST',
    CASE WHEN COUNT(*) >= 6 THEN 'PASS' ELSE 'FAIL' END,
    format('%s security functions found (expected 6+)', COUNT(*))
FROM information_schema.routines
WHERE routine_schema = current_schema()
AND routine_name IN ('rbac_get_current_tenant_id', 'rbac_get_current_user_id', 
                     'rbac_set_tenant_context', 'rbac_clear_context',
                     'audit_rbac_violation', 'test_rbac_rls_enforcement');

-- Check 4: Security views exist
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'SECURITY_VIEWS_EXIST',
    CASE WHEN COUNT(*) >= 2 THEN 'PASS' ELSE 'FAIL' END,
    format('%s security views found (expected 2+)', COUNT(*))
FROM information_schema.views
WHERE table_schema = current_schema()
AND table_name IN ('v_effective_roles_secure', 'rbac_security_violations');

-- Check 5: Test basic context functionality
DO $$
DECLARE
    test_tenant_id UUID := 'ffffffff-ffff-ffff-ffff-ffffffffffff';
    context_test_passed BOOLEAN := FALSE;
BEGIN
    -- Insert a test tenant
    INSERT INTO tenants (id, name) VALUES (test_tenant_id, 'validation_test_tenant')
    ON CONFLICT (id) DO NOTHING;
    
    -- Test context setting
    BEGIN
        PERFORM rbac_set_tenant_context(test_tenant_id);
        IF rbac_get_current_tenant_id() = test_tenant_id THEN
            context_test_passed := TRUE;
        END IF;
        
        -- Clear context
        PERFORM rbac_clear_context();
    EXCEPTION
        WHEN others THEN
            context_test_passed := FALSE;
    END;
    
    -- Record result
    INSERT INTO validation_results (check_name, status, details) VALUES (
        'CONTEXT_FUNCTIONS_TEST',
        CASE WHEN context_test_passed THEN 'PASS' ELSE 'FAIL' END,
        CASE WHEN context_test_passed 
             THEN 'Context functions working correctly' 
             ELSE 'Context functions failed' END
    );
    
    -- Cleanup
    DELETE FROM tenants WHERE id = test_tenant_id;
END;
$$;

-- Check 6: Audit system readiness
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'AUDIT_SYSTEM_READY',
    CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'security_audit_log')
         THEN 'PASS' ELSE 'FAIL' END,
    CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'security_audit_log')
         THEN 'Audit table exists and ready' 
         ELSE 'Audit table missing - run emergency-rls-policies.sql first' END;

-- Check 7: Performance indexes
INSERT INTO validation_results (check_name, status, details)
SELECT 
    'PERFORMANCE_INDEXES',
    CASE WHEN COUNT(*) >= 5 THEN 'PASS' ELSE 'WARN' END,
    format('%s performance indexes found', COUNT(*))
FROM pg_indexes
WHERE schemaname = current_schema()
AND indexname LIKE 'idx_%tenant%' OR indexname LIKE 'idx_%rbac%' OR indexname LIKE 'idx_%security%';

-- Display validation results
SELECT 
    check_name as "Check Name",
    status as "Status",
    details as "Details"
FROM validation_results
ORDER BY 
    CASE status 
        WHEN 'FAIL' THEN 1 
        WHEN 'WARN' THEN 2 
        WHEN 'PASS' THEN 3 
    END,
    check_name;

-- Summary
SELECT 
    COUNT(*) as total_checks,
    COUNT(CASE WHEN status = 'PASS' THEN 1 END) as passed,
    COUNT(CASE WHEN status = 'WARN' THEN 1 END) as warnings,
    COUNT(CASE WHEN status = 'FAIL' THEN 1 END) as failed,
    ROUND(
        (COUNT(CASE WHEN status = 'PASS' THEN 1 END) * 100.0) / COUNT(*), 
        1
    ) as pass_percentage
FROM validation_results;

-- Final validation message
DO $$
DECLARE
    summary RECORD;
    deployment_status TEXT;
BEGIN
    SELECT 
        COUNT(*) as total_checks,
        COUNT(CASE WHEN status = 'PASS' THEN 1 END) as passed,
        COUNT(CASE WHEN status = 'FAIL' THEN 1 END) as failed
    INTO summary
    FROM validation_results;
    
    IF summary.failed = 0 THEN
        deployment_status := 'SUCCESS';
    ELSIF summary.failed <= 1 THEN
        deployment_status := 'PARTIAL - NEEDS ATTENTION';
    ELSE
        deployment_status := 'FAILED - REQUIRES FIXES';
    END IF;
    
    RAISE NOTICE '============================================';
    RAISE NOTICE 'RBAC RLS DEPLOYMENT VALIDATION COMPLETE';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Total Checks: %', summary.total_checks;
    RAISE NOTICE 'Passed: %', summary.passed;
    RAISE NOTICE 'Failed: %', summary.failed;
    RAISE NOTICE 'Status: %', deployment_status;
    RAISE NOTICE '============================================';
    
    IF summary.failed = 0 THEN
        RAISE NOTICE 'RLS DEPLOYMENT: READY FOR PRODUCTION';
        RAISE NOTICE 'Next steps:';
        RAISE NOTICE '1. Update application to use rbac_set_tenant_context()';
        RAISE NOTICE '2. Test application functionality thoroughly';
        RAISE NOTICE '3. Monitor rbac_security_violations view';
        RAISE NOTICE '4. Run comprehensive tests when ready';
    ELSE
        RAISE NOTICE 'RLS DEPLOYMENT: REQUIRES FIXES BEFORE PRODUCTION';
        RAISE NOTICE 'Please address failed checks above';
    END IF;
    
    RAISE NOTICE '============================================';
END;
$$;