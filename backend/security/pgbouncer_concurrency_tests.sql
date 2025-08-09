-- ========================================
-- PgBouncer Concurrency and Session Isolation Tests
-- Task 80.10: Testing session context isolation between connections
-- ========================================

-- Test Setup: Create test tenants and users
BEGIN;

-- Test tenants
INSERT INTO tenants (id, name) VALUES 
  ('11111111-1111-1111-1111-111111111111', 'tenant_a'),
  ('22222222-2222-2222-2222-222222222222', 'tenant_b'),
  ('33333333-3333-3333-3333-333333333333', 'tenant_c')
ON CONFLICT (name) DO NOTHING;

-- Test users
INSERT INTO users (id, email) VALUES 
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'user_a@tenant-a.com'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'user_b@tenant-b.com'),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', 'user_c@tenant-c.com')
ON CONFLICT (email) DO NOTHING;

-- Test roles for each tenant
INSERT INTO roles (id, tenant_id, name, description) VALUES 
  ('a1111111-1111-1111-1111-111111111111', '11111111-1111-1111-1111-111111111111', 'admin', 'Tenant A Admin'),
  ('b1111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', 'admin', 'Tenant B Admin'),
  ('c1111111-1111-1111-1111-111111111111', '33333333-3333-3333-3333-333333333333', 'admin', 'Tenant C Admin')
ON CONFLICT (tenant_id, name) DO NOTHING;

-- User role assignments
INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES 
  ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'a1111111-1111-1111-1111-111111111111'),
  ('22222222-2222-2222-2222-222222222222', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'b1111111-1111-1111-1111-111111111111'),
  ('33333333-3333-3333-3333-333333333333', 'cccccccc-cccc-cccc-cccc-cccccccccccc', 'c1111111-1111-1111-1111-111111111111')
ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;

COMMIT;

-- ========================================
-- TEST 1: Basic Session Context Isolation
-- ========================================

DO $$
DECLARE
    test_result JSONB;
    tenant_a_id UUID := '11111111-1111-1111-1111-111111111111';
    user_a_id UUID := 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    retrieved_tenant UUID;
    retrieved_user UUID;
BEGIN
    -- Test session context setting and retrieval
    RAISE NOTICE '========================================';
    RAISE NOTICE 'TEST 1: Basic Session Context Isolation';
    RAISE NOTICE '========================================';
    
    -- Clear any existing context
    PERFORM clear_session_context();
    
    -- Set context for Tenant A
    SELECT set_session_context(tenant_a_id, user_a_id) INTO test_result;
    RAISE NOTICE 'Set context result: %', test_result;
    
    -- Verify context is correctly set
    SELECT current_tenant_id(), current_user_id() INTO retrieved_tenant, retrieved_user;
    
    IF retrieved_tenant = tenant_a_id AND retrieved_user = user_a_id THEN
        RAISE NOTICE 'PASS: Context correctly set for tenant A, user A';
    ELSE
        RAISE NOTICE 'FAIL: Context not correctly set. Expected: %, % Got: %, %',
            tenant_a_id, user_a_id, retrieved_tenant, retrieved_user;
    END IF;
    
    -- Test context retrieval function
    SELECT get_session_context() INTO test_result;
    RAISE NOTICE 'Session context: %', test_result;
    
    -- Clear context
    PERFORM clear_session_context();
    RAISE NOTICE 'Context cleared successfully';
    
    -- Verify context is cleared
    BEGIN
        SELECT current_tenant_id() INTO retrieved_tenant;
        RAISE NOTICE 'FAIL: Context should be cleared but still retrievable';
    EXCEPTION
        WHEN others THEN
            RAISE NOTICE 'PASS: Context correctly cleared';
    END;
END;
$$;

-- ========================================
-- TEST 2: Cross-Tenant Access Prevention
-- ========================================

DO $$
DECLARE
    test_result JSONB;
    tenant_a_id UUID := '11111111-1111-1111-1111-111111111111';
    tenant_b_id UUID := '22222222-2222-2222-2222-222222222222';
    user_a_id UUID := 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    user_b_id UUID := 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    roles_count INTEGER;
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'TEST 2: Cross-Tenant Access Prevention';
    RAISE NOTICE '========================================';
    
    -- Set context for Tenant A
    PERFORM set_session_context(tenant_a_id, user_a_id);
    RAISE NOTICE 'Set context to Tenant A';
    
    -- Try to access Tenant B roles (should be blocked by RLS)
    SELECT COUNT(*) FROM roles WHERE tenant_id = tenant_b_id INTO roles_count;
    
    IF roles_count = 0 THEN
        RAISE NOTICE 'PASS: RLS correctly blocks access to Tenant B roles';
    ELSE
        RAISE NOTICE 'FAIL: RLS not working - can see % roles from Tenant B', roles_count;
    END IF;
    
    -- Switch to Tenant B
    PERFORM set_session_context(tenant_b_id, user_b_id);
    RAISE NOTICE 'Switched context to Tenant B';
    
    -- Now try to access Tenant B roles (should work)
    SELECT COUNT(*) FROM roles WHERE tenant_id = tenant_b_id INTO roles_count;
    
    IF roles_count > 0 THEN
        RAISE NOTICE 'PASS: Can access Tenant B roles with correct context';
    ELSE
        RAISE NOTICE 'FAIL: Cannot access own tenant roles';
    END IF;
    
    -- Try to access Tenant A roles (should be blocked)
    SELECT COUNT(*) FROM roles WHERE tenant_id = tenant_a_id INTO roles_count;
    
    IF roles_count = 0 THEN
        RAISE NOTICE 'PASS: RLS correctly blocks access to Tenant A roles from Tenant B context';
    ELSE
        RAISE NOTICE 'FAIL: RLS not working - can see % roles from Tenant A', roles_count;
    END IF;
    
    PERFORM clear_session_context();
END;
$$;

-- ========================================
-- TEST 3: Permission Checking with Context
-- ========================================

DO $$
DECLARE
    tenant_a_id UUID := '11111111-1111-1111-1111-111111111111';
    tenant_b_id UUID := '22222222-2222-2222-2222-222222222222';
    user_a_id UUID := 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    user_b_id UUID := 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    has_perm BOOLEAN;
BEGIN
    RAISE NOTICE '========================================';
    RAISE NOTICE 'TEST 3: Permission Checking with Context';
    RAISE NOTICE '========================================';
    
    -- Set context for Tenant A, User A
    PERFORM set_session_context(tenant_a_id, user_a_id);
    
    -- Test permission check (this would typically be set up with actual permissions)
    SELECT has_permission(tenant_a_id, user_a_id, 'security', 'rbac', 'read') INTO has_perm;
    RAISE NOTICE 'User A permission check result: %', has_perm;
    
    -- Cross-tenant permission check (should fail)
    SELECT has_permission(tenant_b_id, user_b_id, 'security', 'rbac', 'read') INTO has_perm;
    RAISE NOTICE 'Cross-tenant permission check (should be false): %', has_perm;
    
    PERFORM clear_session_context();
END;
$$;

-- ========================================
-- Test Data Cleanup Functions
-- ========================================

CREATE OR REPLACE FUNCTION setup_concurrency_test_data()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    -- Create test data that can be safely used in concurrent tests
    INSERT INTO tenants (id, name) VALUES 
      ('test-tenant-1', 'Test Tenant 1'),
      ('test-tenant-2', 'Test Tenant 2'),
      ('test-tenant-3', 'Test Tenant 3')
    ON CONFLICT (name) DO NOTHING;
    
    INSERT INTO users (id, email) VALUES 
      ('test-user-1', 'testuser1@example.com'),
      ('test-user-2', 'testuser2@example.com'),
      ('test-user-3', 'testuser3@example.com')
    ON CONFLICT (email) DO NOTHING;
    
    INSERT INTO roles (id, tenant_id, name, description) VALUES 
      ('test-role-1', 'test-tenant-1', 'test_role', 'Test Role 1'),
      ('test-role-2', 'test-tenant-2', 'test_role', 'Test Role 2'),
      ('test-role-3', 'test-tenant-3', 'test_role', 'Test Role 3')
    ON CONFLICT (tenant_id, name) DO NOTHING;
    
    INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES 
      ('test-tenant-1', 'test-user-1', 'test-role-1'),
      ('test-tenant-2', 'test-user-2', 'test-role-2'),
      ('test-tenant-3', 'test-user-3', 'test-role-3')
    ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;
    
    RAISE NOTICE 'Concurrency test data setup complete';
END;
$$;

CREATE OR REPLACE FUNCTION cleanup_concurrency_test_data()
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM user_roles WHERE tenant_id IN ('test-tenant-1', 'test-tenant-2', 'test-tenant-3');
    DELETE FROM roles WHERE tenant_id IN ('test-tenant-1', 'test-tenant-2', 'test-tenant-3');
    DELETE FROM users WHERE id IN ('test-user-1', 'test-user-2', 'test-user-3');
    DELETE FROM tenants WHERE id IN ('test-tenant-1', 'test-tenant-2', 'test-tenant-3');
    
    RAISE NOTICE 'Concurrency test data cleanup complete';
END;
$$;

-- ========================================
-- Concurrent Session Simulation Function
-- ========================================

CREATE OR REPLACE FUNCTION simulate_concurrent_session(
    p_session_id TEXT,
    p_tenant_id UUID,
    p_user_id UUID,
    p_operations_count INTEGER DEFAULT 10
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    result JSONB;
    operation_results JSONB[] := '{}';
    i INTEGER;
    start_time TIMESTAMPTZ;
    end_time TIMESTAMPTZ;
    current_tenant UUID;
    current_user UUID;
    roles_visible INTEGER;
BEGIN
    start_time := NOW();
    
    -- Set session context
    PERFORM set_session_context(p_tenant_id, p_user_id);
    
    -- Perform multiple operations to test session persistence
    FOR i IN 1..p_operations_count LOOP
        -- Verify context is still correct
        SELECT current_tenant_id(), current_user_id() INTO current_tenant, current_user;
        
        -- Count visible roles (should only see own tenant)
        SELECT COUNT(*) FROM roles INTO roles_visible;
        
        -- Record operation result
        operation_results := operation_results || jsonb_build_object(
            'operation', i,
            'session_id', p_session_id,
            'tenant_correct', current_tenant = p_tenant_id,
            'user_correct', current_user = p_user_id,
            'roles_visible', roles_visible,
            'timestamp', NOW()
        );
        
        -- Small delay to simulate work
        PERFORM pg_sleep(0.001);
    END LOOP;
    
    end_time := NOW();
    
    -- Clear context
    PERFORM clear_session_context();
    
    -- Return results
    result := jsonb_build_object(
        'session_id', p_session_id,
        'tenant_id', p_tenant_id,
        'user_id', p_user_id,
        'operations_count', p_operations_count,
        'start_time', start_time,
        'end_time', end_time,
        'duration_ms', EXTRACT(epoch FROM (end_time - start_time)) * 1000,
        'operations', operation_results,
        'success', true
    );
    
    RETURN result;
EXCEPTION
    WHEN others THEN
        RETURN jsonb_build_object(
            'session_id', p_session_id,
            'error', SQLERRM,
            'success', false
        );
END;
$$;

-- Grant permissions
GRANT EXECUTE ON FUNCTION setup_concurrency_test_data() TO application_role;
GRANT EXECUTE ON FUNCTION cleanup_concurrency_test_data() TO application_role;
GRANT EXECUTE ON FUNCTION simulate_concurrent_session(TEXT, UUID, UUID, INTEGER) TO application_role;

-- Display completion message
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'PGBOUNCER CONCURRENCY TESTS READY';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Test functions available:';
    RAISE NOTICE '  • setup_concurrency_test_data()';
    RAISE NOTICE '  • cleanup_concurrency_test_data()';
    RAISE NOTICE '  • simulate_concurrent_session(session_id, tenant_id, user_id, operations_count)';
    RAISE NOTICE '';
    RAISE NOTICE 'Run basic tests with: \\i pgbouncer_concurrency_tests.sql';
    RAISE NOTICE 'Setup test data: SELECT setup_concurrency_test_data();';
    RAISE NOTICE 'Cleanup test data: SELECT cleanup_concurrency_test_data();';
    RAISE NOTICE '========================================';
END;
$$;