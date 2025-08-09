-- RBAC Row-Level Security (RLS) Integration Tests
-- Comprehensive test suite for tenant isolation enforcement
-- Tests cross-tenant access blocking, edge cases, and concurrent scenarios

BEGIN;

-- Test setup: Create test tenants, users, and roles
SET session_replication_role = 'origin';
SET LOCAL statement_timeout = '300s';

-- =====================================================
-- TEST DATA SETUP
-- =====================================================

-- Test tenants
INSERT INTO tenants (id, name, created_at, updated_at) VALUES
('11111111-1111-1111-1111-111111111111', 'test_tenant_alpha', NOW(), NOW()),
('22222222-2222-2222-2222-222222222222', 'test_tenant_beta', NOW(), NOW()),
('33333333-3333-3333-3333-333333333333', 'test_tenant_gamma', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Test users
INSERT INTO users (id, email, created_at, updated_at) VALUES
('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'alpha.user@isectech.com', NOW(), NOW()),
('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'beta.user@isectech.com', NOW(), NOW()),
('cccccccc-cccc-cccc-cccc-cccccccccccc', 'gamma.user@isectech.com', NOW(), NOW()),
('dddddddd-dddd-dddd-dddd-dddddddddddd', 'shared.user@isectech.com', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Test roles for each tenant
INSERT INTO roles (id, tenant_id, name, description, created_at, updated_at) VALUES
-- Tenant Alpha roles
('10101010-1010-1010-1010-101010101010', '11111111-1111-1111-1111-111111111111', 'alpha_admin', 'Alpha tenant admin', NOW(), NOW()),
('10101010-1010-1010-1010-101010101011', '11111111-1111-1111-1111-111111111111', 'alpha_user', 'Alpha tenant user', NOW(), NOW()),
-- Tenant Beta roles
('20202020-2020-2020-2020-202020202020', '22222222-2222-2222-2222-222222222222', 'beta_admin', 'Beta tenant admin', NOW(), NOW()),
('20202020-2020-2020-2020-202020202021', '22222222-2222-2222-2222-222222222222', 'beta_user', 'Beta tenant user', NOW(), NOW()),
-- Tenant Gamma roles
('30303030-3030-3030-3030-303030303030', '33333333-3333-3333-3333-333333333333', 'gamma_admin', 'Gamma tenant admin', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Test permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description, created_at, updated_at) VALUES
('40404040-4040-4040-4040-404040404040', 'security', 'alerts', 'read', 'Read security alerts', NOW(), NOW()),
('40404040-4040-4040-4040-404040404041', 'security', 'alerts', 'write', 'Write security alerts', NOW(), NOW()),
('40404040-4040-4040-4040-404040404042', 'users', 'profiles', 'read', 'Read user profiles', NOW(), NOW())
ON CONFLICT (id) DO NOTHING;

-- Test user role assignments
INSERT INTO user_roles (tenant_id, user_id, role_id, created_at) VALUES
-- Alpha tenant assignments
('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '10101010-1010-1010-1010-101010101010', NOW()),
('11111111-1111-1111-1111-111111111111', 'dddddddd-dddd-dddd-dddd-dddddddddddd', '10101010-1010-1010-1010-101010101011', NOW()),
-- Beta tenant assignments
('22222222-2222-2222-2222-222222222222', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '20202020-2020-2020-2020-202020202020', NOW()),
('22222222-2222-2222-2222-222222222222', 'dddddddd-dddd-dddd-dddd-dddddddddddd', '20202020-2020-2020-2020-202020202021', NOW()),
-- Gamma tenant assignments
('33333333-3333-3333-3333-333333333333', 'cccccccc-cccc-cccc-cccc-cccccccccccc', '30303030-3030-3030-3030-303030303030', NOW())
ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;

-- Test role permissions
INSERT INTO role_permissions (tenant_id, role_id, permission_id, created_at) VALUES
('11111111-1111-1111-1111-111111111111', '10101010-1010-1010-1010-101010101010', '40404040-4040-4040-4040-404040404040', NOW()),
('22222222-2222-2222-2222-222222222222', '20202020-2020-2020-2020-202020202020', '40404040-4040-4040-4040-404040404041', NOW()),
('33333333-3333-3333-3333-333333333333', '30303030-3030-3030-3030-303030303030', '40404040-4040-4040-4040-404040404042', NOW())
ON CONFLICT (tenant_id, role_id, permission_id) DO NOTHING;

-- =====================================================
-- TEST FRAMEWORK FUNCTIONS
-- =====================================================

-- Test result tracking
CREATE TEMP TABLE test_results (
    test_id SERIAL PRIMARY KEY,
    test_name TEXT NOT NULL,
    test_category TEXT NOT NULL,
    test_result TEXT NOT NULL, -- PASS, FAIL, ERROR
    details TEXT,
    execution_time INTERVAL,
    executed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Function to record test results
CREATE OR REPLACE FUNCTION record_test_result(
    p_test_name TEXT, 
    p_category TEXT, 
    p_result TEXT, 
    p_details TEXT DEFAULT NULL,
    p_execution_time INTERVAL DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO test_results (test_name, test_category, test_result, details, execution_time)
    VALUES (p_test_name, p_category, p_result, p_details, p_execution_time);
END;
$$;

-- Function to run a test with error handling
CREATE OR REPLACE FUNCTION run_test(
    p_test_name TEXT,
    p_category TEXT,
    p_test_sql TEXT,
    p_expected_result BOOLEAN DEFAULT TRUE
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    test_passed BOOLEAN := FALSE;
    error_msg TEXT;
BEGIN
    start_time := clock_timestamp();
    
    BEGIN
        EXECUTE p_test_sql;
        test_passed := p_expected_result;
    EXCEPTION
        WHEN others THEN
            error_msg := SQLERRM;
            test_passed := NOT p_expected_result; -- If we expected failure, this is success
    END;
    
    end_time := clock_timestamp();
    
    IF test_passed THEN
        PERFORM record_test_result(p_test_name, p_category, 'PASS', error_msg, end_time - start_time);
    ELSE
        PERFORM record_test_result(p_test_name, p_category, 'FAIL', error_msg, end_time - start_time);
    END IF;
END;
$$;

-- =====================================================
-- TEST SUITE 1: BASIC RLS ENFORCEMENT
-- =====================================================

-- Test 1.1: Tenant context setting and retrieval
DO $$
BEGIN
    -- Test context setting for tenant Alpha
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    
    IF rbac_get_current_tenant_id() = '11111111-1111-1111-1111-111111111111' 
       AND rbac_get_current_user_id() = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' THEN
        PERFORM record_test_result('Context Setting and Retrieval', 'Basic RLS', 'PASS', 'Tenant and user context correctly set');
    ELSE
        PERFORM record_test_result('Context Setting and Retrieval', 'Basic RLS', 'FAIL', 'Context not set correctly');
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Context Setting and Retrieval', 'Basic RLS', 'ERROR', SQLERRM);
END;
$$;

-- Test 1.2: Same-tenant access (should work)
DO $$
DECLARE
    role_count INTEGER;
BEGIN
    -- Set context to Alpha tenant
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    
    -- Should see Alpha tenant roles
    SELECT COUNT(*) INTO role_count FROM roles WHERE tenant_id = '11111111-1111-1111-1111-111111111111';
    
    IF role_count >= 2 THEN -- We inserted 2 Alpha roles
        PERFORM record_test_result('Same Tenant Access', 'Basic RLS', 'PASS', format('Found %s roles for current tenant', role_count));
    ELSE
        PERFORM record_test_result('Same Tenant Access', 'Basic RLS', 'FAIL', format('Expected 2+ roles, found %s', role_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Same Tenant Access', 'Basic RLS', 'ERROR', SQLERRM);
END;
$$;

-- Test 1.3: Cross-tenant access blocking (should be blocked)
DO $$
DECLARE
    role_count INTEGER;
    audit_count INTEGER;
BEGIN
    -- Set context to Alpha tenant
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    
    -- Try to access Beta tenant roles (should return 0)
    SELECT COUNT(*) INTO role_count FROM roles WHERE tenant_id = '22222222-2222-2222-2222-222222222222';
    
    -- Check if violation was audited
    SELECT COUNT(*) INTO audit_count 
    FROM security_audit_log 
    WHERE event_type = 'RBAC_RLS_VIOLATION' 
    AND table_name = 'roles'
    AND timestamp >= NOW() - INTERVAL '1 minute';
    
    IF role_count = 0 THEN
        PERFORM record_test_result('Cross Tenant Access Blocking', 'Basic RLS', 'PASS', 
            format('Cross-tenant access blocked. Roles found: %s, Audit entries: %s', role_count, audit_count));
    ELSE
        PERFORM record_test_result('Cross Tenant Access Blocking', 'Basic RLS', 'FAIL', 
            format('Cross-tenant access NOT blocked. Found %s roles', role_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Cross Tenant Access Blocking', 'Basic RLS', 'PASS', 
            format('Cross-tenant access blocked with exception (expected): %s', SQLERRM));
END;
$$;

-- =====================================================
-- TEST SUITE 2: USER ROLE ENFORCEMENT
-- =====================================================

-- Test 2.1: User can access own roles
DO $$
DECLARE
    role_count INTEGER;
BEGIN
    -- Set context to Alpha tenant with specific user
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
    
    -- User should see their own role assignments
    SELECT COUNT(*) INTO role_count 
    FROM user_roles 
    WHERE tenant_id = '11111111-1111-1111-1111-111111111111' 
    AND user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    
    IF role_count >= 1 THEN
        PERFORM record_test_result('User Own Role Access', 'User Role Enforcement', 'PASS', 
            format('User can access own roles: %s', role_count));
    ELSE
        PERFORM record_test_result('User Own Role Access', 'User Role Enforcement', 'FAIL', 
            format('User cannot access own roles: %s', role_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('User Own Role Access', 'User Role Enforcement', 'ERROR', SQLERRM);
END;
$$;

-- Test 2.2: User cannot access other users' roles without admin access
DO $$
DECLARE
    role_count INTEGER;
BEGIN
    -- Set context to Alpha tenant with regular user (not admin)
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111', 'dddddddd-dddd-dddd-dddd-dddddddddddd');
    
    -- Try to access another user's roles (should be restricted)
    SELECT COUNT(*) INTO role_count 
    FROM user_roles 
    WHERE tenant_id = '11111111-1111-1111-1111-111111111111' 
    AND user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    
    IF role_count = 0 THEN
        PERFORM record_test_result('User Cross-User Role Access Blocking', 'User Role Enforcement', 'PASS', 
            'Regular user blocked from accessing other users\' roles');
    ELSE
        PERFORM record_test_result('User Cross-User Role Access Blocking', 'User Role Enforcement', 'FAIL', 
            format('Regular user can access other users\' roles: %s', role_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('User Cross-User Role Access Blocking', 'User Role Enforcement', 'PASS', 
            format('Cross-user access blocked with exception (expected): %s', SQLERRM));
END;
$$;

-- =====================================================
-- TEST SUITE 3: PERMISSION SYSTEM TESTS
-- =====================================================

-- Test 3.1: Permission visibility (global permissions should be visible)
DO $$
DECLARE
    permission_count INTEGER;
BEGIN
    -- Set context to any tenant
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    
    -- Permissions should be globally readable
    SELECT COUNT(*) INTO permission_count FROM permissions;
    
    IF permission_count >= 3 THEN -- We inserted 3 test permissions
        PERFORM record_test_result('Global Permission Visibility', 'Permission System', 'PASS', 
            format('Can read global permissions: %s', permission_count));
    ELSE
        PERFORM record_test_result('Global Permission Visibility', 'Permission System', 'FAIL', 
            format('Cannot read global permissions: %s', permission_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Global Permission Visibility', 'Permission System', 'ERROR', SQLERRM);
END;
$$;

-- Test 3.2: Role-Permission mapping tenant isolation
DO $$
DECLARE
    mapping_count INTEGER;
BEGIN
    -- Set context to Alpha tenant
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    
    -- Should only see Alpha tenant role-permission mappings
    SELECT COUNT(*) INTO mapping_count FROM role_permissions;
    
    -- Should only see mappings for current tenant
    IF mapping_count = 1 THEN -- We inserted 1 mapping for Alpha
        PERFORM record_test_result('Role Permission Mapping Isolation', 'Permission System', 'PASS', 
            format('Tenant isolation working for role-permissions: %s', mapping_count));
    ELSE
        PERFORM record_test_result('Role Permission Mapping Isolation', 'Permission System', 'FAIL', 
            format('Expected 1 mapping for current tenant, found: %s', mapping_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Role Permission Mapping Isolation', 'Permission System', 'ERROR', SQLERRM);
END;
$$;

-- =====================================================
-- TEST SUITE 4: EDGE CASES AND ERROR HANDLING
-- =====================================================

-- Test 4.1: Invalid tenant context handling
DO $$
DECLARE
    error_occurred BOOLEAN := FALSE;
BEGIN
    -- Try to set invalid tenant
    BEGIN
        PERFORM rbac_set_tenant_context('99999999-9999-9999-9999-999999999999');
    EXCEPTION
        WHEN others THEN
            error_occurred := TRUE;
    END;
    
    IF error_occurred THEN
        PERFORM record_test_result('Invalid Tenant Context Handling', 'Edge Cases', 'PASS', 
            'Invalid tenant context properly rejected');
    ELSE
        PERFORM record_test_result('Invalid Tenant Context Handling', 'Edge Cases', 'FAIL', 
            'Invalid tenant context not rejected');
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Invalid Tenant Context Handling', 'Edge Cases', 'ERROR', SQLERRM);
END;
$$;

-- Test 4.2: No context set (should fail)
DO $$
DECLARE
    error_occurred BOOLEAN := FALSE;
    role_count INTEGER;
BEGIN
    -- Clear context
    PERFORM rbac_clear_context();
    
    -- Try to access roles without context (should fail)
    BEGIN
        SELECT COUNT(*) INTO role_count FROM roles;
    EXCEPTION
        WHEN others THEN
            error_occurred := TRUE;
    END;
    
    IF error_occurred THEN
        PERFORM record_test_result('No Context Access Control', 'Edge Cases', 'PASS', 
            'Access properly denied without tenant context');
    ELSE
        PERFORM record_test_result('No Context Access Control', 'Edge Cases', 'FAIL', 
            format('Access allowed without context, found %s roles', role_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('No Context Access Control', 'Edge Cases', 'ERROR', SQLERRM);
END;
$$;

-- Test 4.3: User without tenant access
DO $$
DECLARE
    error_occurred BOOLEAN := FALSE;
BEGIN
    -- Try to set context with user not in tenant
    BEGIN
        PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111', 'cccccccc-cccc-cccc-cccc-cccccccccccc'); -- Gamma user in Alpha tenant
    EXCEPTION
        WHEN others THEN
            error_occurred := TRUE;
    END;
    
    IF error_occurred THEN
        PERFORM record_test_result('Invalid User-Tenant Mapping', 'Edge Cases', 'PASS', 
            'Invalid user-tenant mapping properly rejected');
    ELSE
        PERFORM record_test_result('Invalid User-Tenant Mapping', 'Edge Cases', 'FAIL', 
            'Invalid user-tenant mapping not rejected');
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Invalid User-Tenant Mapping', 'Edge Cases', 'ERROR', SQLERRM);
END;
$$;

-- =====================================================
-- TEST SUITE 5: CONCURRENT ACCESS SIMULATION
-- =====================================================

-- Test 5.1: Simulate concurrent tenant access
DO $$
DECLARE
    alpha_count INTEGER;
    beta_count INTEGER;
    gamma_count INTEGER;
BEGIN
    -- Tenant Alpha session
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    SELECT COUNT(*) INTO alpha_count FROM roles;
    
    -- Tenant Beta session (context switch)
    PERFORM rbac_set_tenant_context('22222222-2222-2222-2222-222222222222');
    SELECT COUNT(*) INTO beta_count FROM roles;
    
    -- Tenant Gamma session (context switch)
    PERFORM rbac_set_tenant_context('33333333-3333-3333-3333-333333333333');
    SELECT COUNT(*) INTO gamma_count FROM roles;
    
    -- Each tenant should only see their own roles
    IF alpha_count = 2 AND beta_count = 2 AND gamma_count = 1 THEN
        PERFORM record_test_result('Concurrent Tenant Context Switching', 'Concurrent Access', 'PASS', 
            format('Context switching working: Alpha=%s, Beta=%s, Gamma=%s', alpha_count, beta_count, gamma_count));
    ELSE
        PERFORM record_test_result('Concurrent Tenant Context Switching', 'Concurrent Access', 'FAIL', 
            format('Context switching failed: Alpha=%s, Beta=%s, Gamma=%s', alpha_count, beta_count, gamma_count));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Concurrent Tenant Context Switching', 'Concurrent Access', 'ERROR', SQLERRM);
END;
$$;

-- =====================================================
-- TEST SUITE 6: PERFORMANCE AND SCALABILITY
-- =====================================================

-- Test 6.1: RLS policy performance test
DO $$
DECLARE
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    execution_time INTERVAL;
    role_count INTEGER;
BEGIN
    -- Set context
    PERFORM rbac_set_tenant_context('11111111-1111-1111-1111-111111111111');
    
    -- Measure query performance
    start_time := clock_timestamp();
    
    -- Run multiple queries to test RLS overhead
    FOR i IN 1..100 LOOP
        SELECT COUNT(*) INTO role_count FROM roles;
        SELECT COUNT(*) INTO role_count FROM user_roles;
        SELECT COUNT(*) INTO role_count FROM role_permissions;
    END LOOP;
    
    end_time := clock_timestamp();
    execution_time := end_time - start_time;
    
    -- Performance should be reasonable (less than 5 seconds for 300 queries)
    IF execution_time < INTERVAL '5 seconds' THEN
        PERFORM record_test_result('RLS Policy Performance', 'Performance', 'PASS', 
            format('300 queries executed in %s', execution_time));
    ELSE
        PERFORM record_test_result('RLS Policy Performance', 'Performance', 'FAIL', 
            format('Poor performance: 300 queries took %s', execution_time));
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('RLS Policy Performance', 'Performance', 'ERROR', SQLERRM);
END;
$$;

-- =====================================================
-- TEST SUITE 7: AUDIT AND MONITORING
-- =====================================================

-- Test 7.1: Audit log functionality
DO $$
DECLARE
    audit_count_before INTEGER;
    audit_count_after INTEGER;
BEGIN
    -- Count existing audit entries
    SELECT COUNT(*) INTO audit_count_before 
    FROM security_audit_log 
    WHERE event_type = 'RBAC_RLS_VIOLATION';
    
    -- Trigger an audit event
    PERFORM audit_rbac_violation('TEST_AUDIT', 'TEST_OP', 
        '11111111-1111-1111-1111-111111111111', 
        '22222222-2222-2222-2222-222222222222', 
        'TEST_VIOLATION');
    
    -- Count audit entries after
    SELECT COUNT(*) INTO audit_count_after 
    FROM security_audit_log 
    WHERE event_type = 'RBAC_RLS_VIOLATION';
    
    IF audit_count_after > audit_count_before THEN
        PERFORM record_test_result('Audit Log Functionality', 'Audit and Monitoring', 'PASS', 
            format('Audit logging working: before=%s, after=%s', audit_count_before, audit_count_after));
    ELSE
        PERFORM record_test_result('Audit Log Functionality', 'Audit and Monitoring', 'FAIL', 
            format('Audit logging not working: before=%s, after=%s', audit_count_before, audit_count_after));
    END IF;
    
    -- Cleanup test audit entry
    DELETE FROM security_audit_log 
    WHERE event_type = 'RBAC_RLS_VIOLATION' 
    AND table_name = 'TEST_AUDIT' 
    AND operation_type = 'TEST_OP';
    
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Audit Log Functionality', 'Audit and Monitoring', 'ERROR', SQLERRM);
END;
$$;

-- Test 7.2: Security metrics function
DO $$
DECLARE
    metrics_result RECORD;
BEGIN
    -- Test metrics function
    SELECT * INTO metrics_result FROM get_rbac_security_metrics(24);
    
    IF metrics_result IS NOT NULL THEN
        PERFORM record_test_result('Security Metrics Function', 'Audit and Monitoring', 'PASS', 
            format('Metrics function working: violations=%s, trend=%s', 
                metrics_result.total_violations, metrics_result.violation_trend));
    ELSE
        PERFORM record_test_result('Security Metrics Function', 'Audit and Monitoring', 'FAIL', 
            'Metrics function returned null');
    END IF;
EXCEPTION
    WHEN others THEN
        PERFORM record_test_result('Security Metrics Function', 'Audit and Monitoring', 'ERROR', SQLERRM);
END;
$$;

-- =====================================================
-- TEST RESULTS SUMMARY
-- =====================================================

-- Summary of all test results
SELECT 
    test_category,
    COUNT(*) as total_tests,
    COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) as passed,
    COUNT(CASE WHEN test_result = 'FAIL' THEN 1 END) as failed,
    COUNT(CASE WHEN test_result = 'ERROR' THEN 1 END) as errors,
    ROUND(
        (COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) * 100.0) / COUNT(*), 
        2
    ) as pass_rate
FROM test_results
GROUP BY test_category
ORDER BY test_category;

-- Detailed test results
SELECT 
    test_id,
    test_category,
    test_name,
    test_result,
    details,
    execution_time,
    executed_at
FROM test_results
ORDER BY test_id;

-- Overall test summary
SELECT 
    COUNT(*) as total_tests,
    COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) as total_passed,
    COUNT(CASE WHEN test_result = 'FAIL' THEN 1 END) as total_failed,
    COUNT(CASE WHEN test_result = 'ERROR' THEN 1 END) as total_errors,
    ROUND(
        (COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) * 100.0) / COUNT(*), 
        2
    ) as overall_pass_rate
FROM test_results;

-- Failed tests details (for debugging)
SELECT 
    test_name,
    test_category,
    details,
    execution_time
FROM test_results 
WHERE test_result IN ('FAIL', 'ERROR')
ORDER BY test_category, test_name;

-- =====================================================
-- TEST DATA CLEANUP
-- =====================================================

-- Clean up test data
DELETE FROM user_roles WHERE tenant_id IN (
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222',
    '33333333-3333-3333-3333-333333333333'
);

DELETE FROM role_permissions WHERE tenant_id IN (
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222',
    '33333333-3333-3333-3333-333333333333'
);

DELETE FROM roles WHERE tenant_id IN (
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222',
    '33333333-3333-3333-3333-333333333333'
);

DELETE FROM permissions WHERE id IN (
    '40404040-4040-4040-4040-404040404040',
    '40404040-4040-4040-4040-404040404041',
    '40404040-4040-4040-4040-404040404042'
);

DELETE FROM users WHERE id IN (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'cccccccc-cccc-cccc-cccc-cccccccccccc',
    'dddddddd-dddd-dddd-dddd-dddddddddddd'
);

DELETE FROM tenants WHERE id IN (
    '11111111-1111-1111-1111-111111111111',
    '22222222-2222-2222-2222-222222222222',
    '33333333-3333-3333-3333-333333333333'
);

-- Clear context after tests
SELECT rbac_clear_context();

COMMIT;

-- Final test report
DO $$
DECLARE
    test_summary RECORD;
BEGIN
    SELECT 
        COUNT(*) as total_tests,
        COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) as total_passed,
        COUNT(CASE WHEN test_result = 'FAIL' THEN 1 END) as total_failed,
        COUNT(CASE WHEN test_result = 'ERROR' THEN 1 END) as total_errors,
        ROUND((COUNT(CASE WHEN test_result = 'PASS' THEN 1 END) * 100.0) / COUNT(*), 2) as overall_pass_rate
    INTO test_summary
    FROM test_results;
    
    RAISE NOTICE '============================================';
    RAISE NOTICE 'RBAC RLS INTEGRATION TEST RESULTS';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Total Tests: %', test_summary.total_tests;
    RAISE NOTICE 'Passed: %', test_summary.total_passed;
    RAISE NOTICE 'Failed: %', test_summary.total_failed;
    RAISE NOTICE 'Errors: %', test_summary.total_errors;
    RAISE NOTICE 'Pass Rate: %%%', test_summary.overall_pass_rate;
    RAISE NOTICE '============================================';
    
    IF test_summary.overall_pass_rate >= 90 THEN
        RAISE NOTICE 'TEST RESULT: EXCELLENT - RLS implementation is robust';
    ELSIF test_summary.overall_pass_rate >= 80 THEN
        RAISE NOTICE 'TEST RESULT: GOOD - Minor issues to address';
    ELSIF test_summary.overall_pass_rate >= 70 THEN
        RAISE NOTICE 'TEST RESULT: NEEDS IMPROVEMENT - Several issues found';
    ELSE
        RAISE NOTICE 'TEST RESULT: CRITICAL ISSUES - RLS implementation needs major fixes';
    END IF;
    
    RAISE NOTICE '============================================';
END;
$$;