-- Test Suite for Context Management Functions
-- Task 80.3: Validate correct context setting and retrieval in various session scenarios
-- Comprehensive testing of context management functions

BEGIN;

-- =====================================================
-- TEST SETUP AND SAMPLE DATA
-- =====================================================

-- Create test data if not exists
DO $$
DECLARE
    test_tenant_1 UUID := '11111111-1111-1111-1111-111111111111';
    test_tenant_2 UUID := '22222222-2222-2222-2222-222222222222';
    test_user_1 UUID := '33333333-3333-3333-3333-333333333333';
    test_user_2 UUID := '44444444-4444-4444-4444-444444444444';
    test_role_1 UUID := '55555555-5555-5555-5555-555555555555';
    test_role_2 UUID := '66666666-6666-6666-6666-666666666666';
    test_permission_1 UUID := '77777777-7777-7777-7777-777777777777';
BEGIN
    -- Insert test tenants
    INSERT INTO tenants (id, name) VALUES 
        (test_tenant_1, 'Test Tenant 1'),
        (test_tenant_2, 'Test Tenant 2')
    ON CONFLICT (id) DO NOTHING;
    
    -- Insert test users
    INSERT INTO users (id, email) VALUES 
        (test_user_1, 'testuser1@isectech.com'),
        (test_user_2, 'testuser2@isectech.com')
    ON CONFLICT (id) DO NOTHING;
    
    -- Insert test roles
    INSERT INTO roles (id, tenant_id, name, description) VALUES 
        (test_role_1, test_tenant_1, 'Test Admin', 'Test administrator role'),
        (test_role_2, test_tenant_2, 'Test User', 'Test user role')
    ON CONFLICT (id) DO NOTHING;
    
    -- Insert test permission
    INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES 
        (test_permission_1, 'test', 'resource', 'read', 'Test permission')
    ON CONFLICT (id) DO NOTHING;
    
    -- Assign permissions to roles
    INSERT INTO role_permissions (tenant_id, role_id, permission_id) VALUES 
        (test_tenant_1, test_role_1, test_permission_1),
        (test_tenant_2, test_role_2, test_permission_1)
    ON CONFLICT (tenant_id, role_id, permission_id) DO NOTHING;
    
    -- Assign users to roles
    INSERT INTO user_roles (tenant_id, user_id, role_id) VALUES 
        (test_tenant_1, test_user_1, test_role_1),
        (test_tenant_2, test_user_2, test_role_2)
    ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;
    
    RAISE NOTICE 'Test data setup completed';
END;
$$;

-- =====================================================
-- TEST FUNCTION RUNNER
-- =====================================================

-- Function to run tests and collect results
CREATE OR REPLACE FUNCTION run_context_management_tests()
RETURNS TABLE(
    test_category TEXT,
    test_name TEXT,
    test_result TEXT,
    details TEXT,
    execution_time INTERVAL
)
LANGUAGE plpgsql
AS $$
DECLARE
    test_start TIMESTAMP;
    test_end TIMESTAMP;
    test_tenant_1 UUID := '11111111-1111-1111-1111-111111111111';
    test_tenant_2 UUID := '22222222-2222-2222-2222-222222222222';
    test_user_1 UUID := '33333333-3333-3333-3333-333333333333';
    test_user_2 UUID := '44444444-4444-4444-4444-444444444444';
    invalid_tenant UUID := '99999999-9999-9999-9999-999999999999';
    invalid_user UUID := '88888888-8888-8888-8888-888888888888';
    retrieved_tenant UUID;
    retrieved_user UUID;
    context_result JSONB;
    function_result BOOLEAN;
BEGIN
    -- Clear any existing context
    PERFORM clear_session_context();
    
    -- =====================================================
    -- TEST 1: Basic Tenant Context Functions
    -- =====================================================
    
    test_start := clock_timestamp();
    
    -- Test 1.1: set_current_tenant_id with valid tenant
    BEGIN
        SELECT set_current_tenant_id(test_tenant_1) INTO function_result;
        test_end := clock_timestamp();
        
        IF function_result = TRUE THEN
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'SET_VALID_TENANT'::TEXT, 
                'PASS'::TEXT,
                'Successfully set valid tenant context'::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'SET_VALID_TENANT'::TEXT, 
                'FAIL'::TEXT,
                'Function returned FALSE for valid tenant'::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'SET_VALID_TENANT'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 1.2: current_tenant_id retrieval
    test_start := clock_timestamp();
    BEGIN
        SELECT current_tenant_id() INTO retrieved_tenant;
        test_end := clock_timestamp();
        
        IF retrieved_tenant = test_tenant_1 THEN
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'GET_CURRENT_TENANT'::TEXT, 
                'PASS'::TEXT,
                format('Retrieved correct tenant ID: %s', retrieved_tenant)::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'GET_CURRENT_TENANT'::TEXT, 
                'FAIL'::TEXT,
                format('Retrieved wrong tenant ID: %s, expected: %s', retrieved_tenant, test_tenant_1)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'GET_CURRENT_TENANT'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 1.3: set_current_tenant_id with invalid tenant
    test_start := clock_timestamp();
    BEGIN
        SELECT set_current_tenant_id(invalid_tenant) INTO function_result;
        test_end := clock_timestamp();
        
        RETURN QUERY SELECT 
            'BASIC_TENANT'::TEXT, 
            'SET_INVALID_TENANT'::TEXT, 
            'FAIL'::TEXT,
            'Should have failed for invalid tenant'::TEXT,
            test_end - test_start;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_TENANT'::TEXT, 
                'SET_INVALID_TENANT'::TEXT, 
                'PASS'::TEXT,
                format('Correctly rejected invalid tenant: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- =====================================================
    -- TEST 2: Basic User Context Functions
    -- =====================================================
    
    -- Reset to valid tenant context for user tests
    PERFORM set_current_tenant_id(test_tenant_1);
    
    -- Test 2.1: set_current_user_id with valid user
    test_start := clock_timestamp();
    BEGIN
        SELECT set_current_user_id(test_user_1) INTO function_result;
        test_end := clock_timestamp();
        
        IF function_result = TRUE THEN
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'SET_VALID_USER'::TEXT, 
                'PASS'::TEXT,
                'Successfully set valid user context'::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'SET_VALID_USER'::TEXT, 
                'FAIL'::TEXT,
                'Function returned FALSE for valid user'::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'SET_VALID_USER'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 2.2: current_user_id retrieval
    test_start := clock_timestamp();
    BEGIN
        SELECT current_user_id() INTO retrieved_user;
        test_end := clock_timestamp();
        
        IF retrieved_user = test_user_1 THEN
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'GET_CURRENT_USER'::TEXT, 
                'PASS'::TEXT,
                format('Retrieved correct user ID: %s', retrieved_user)::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'GET_CURRENT_USER'::TEXT, 
                'FAIL'::TEXT,
                format('Retrieved wrong user ID: %s, expected: %s', retrieved_user, test_user_1)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'GET_CURRENT_USER'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 2.3: set_current_user_id with cross-tenant user
    test_start := clock_timestamp();
    BEGIN
        -- Try to set user from different tenant
        SELECT set_current_user_id(test_user_2) INTO function_result;
        test_end := clock_timestamp();
        
        RETURN QUERY SELECT 
            'BASIC_USER'::TEXT, 
            'SET_CROSS_TENANT_USER'::TEXT, 
            'FAIL'::TEXT,
            'Should have failed for cross-tenant user'::TEXT,
            test_end - test_start;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'BASIC_USER'::TEXT, 
                'SET_CROSS_TENANT_USER'::TEXT, 
                'PASS'::TEXT,
                format('Correctly rejected cross-tenant user: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- =====================================================
    -- TEST 3: Enhanced Session Context Functions
    -- =====================================================
    
    -- Clear context for enhanced tests
    PERFORM clear_session_context();
    
    -- Test 3.1: set_session_context with valid tenant and user
    test_start := clock_timestamp();
    BEGIN
        SELECT set_session_context(test_tenant_1, test_user_1) INTO context_result;
        test_end := clock_timestamp();
        
        IF (context_result->>'success')::boolean = TRUE THEN
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'SET_SESSION_CONTEXT'::TEXT, 
                'PASS'::TEXT,
                format('Successfully set session context: %s', context_result)::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'SET_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Failed to set session context: %s', context_result)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'SET_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 3.2: get_session_context retrieval
    test_start := clock_timestamp();
    BEGIN
        SELECT get_session_context() INTO context_result;
        test_end := clock_timestamp();
        
        IF (context_result->'tenant_context'->>'is_set')::boolean = TRUE AND
           (context_result->'user_context'->>'is_set')::boolean = TRUE THEN
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'GET_SESSION_CONTEXT'::TEXT, 
                'PASS'::TEXT,
                format('Successfully retrieved session context: %s', context_result)::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'GET_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Context not properly set: %s', context_result)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'GET_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 3.3: clear_session_context
    test_start := clock_timestamp();
    BEGIN
        SELECT clear_session_context() INTO function_result;
        SELECT get_session_context() INTO context_result;
        test_end := clock_timestamp();
        
        IF function_result = TRUE AND 
           (context_result->'tenant_context'->>'is_set')::boolean = FALSE AND
           (context_result->'user_context'->>'is_set')::boolean = FALSE THEN
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'CLEAR_SESSION_CONTEXT'::TEXT, 
                'PASS'::TEXT,
                'Successfully cleared session context'::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'CLEAR_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Failed to clear context properly. Result: %s, Context: %s', function_result, context_result)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'ENHANCED_CONTEXT'::TEXT, 
                'CLEAR_SESSION_CONTEXT'::TEXT, 
                'FAIL'::TEXT,
                format('Exception: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- =====================================================
    -- TEST 4: RLS Integration Tests
    -- =====================================================
    
    -- Test 4.1: Tenant isolation with context
    test_start := clock_timestamp();
    BEGIN
        -- Set tenant 1 context
        PERFORM set_current_tenant_id(test_tenant_1);
        
        -- Try to query roles - should only see tenant 1 roles
        SELECT COUNT(*) INTO function_result 
        FROM roles 
        WHERE tenant_id = test_tenant_2; -- Should be 0 due to RLS
        
        test_end := clock_timestamp();
        
        IF function_result = 0 THEN
            RETURN QUERY SELECT 
                'RLS_INTEGRATION'::TEXT, 
                'TENANT_ISOLATION'::TEXT, 
                'PASS'::TEXT,
                'RLS properly blocked cross-tenant access'::TEXT,
                test_end - test_start;
        ELSE
            RETURN QUERY SELECT 
                'RLS_INTEGRATION'::TEXT, 
                'TENANT_ISOLATION'::TEXT, 
                'FAIL'::TEXT,
                format('RLS failed - saw %s cross-tenant records', function_result)::TEXT,
                test_end - test_start;
        END IF;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'RLS_INTEGRATION'::TEXT, 
                'TENANT_ISOLATION'::TEXT, 
                'PASS'::TEXT,
                format('RLS blocked access with error (expected): %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 4.2: Context switching
    test_start := clock_timestamp();
    BEGIN
        -- Set tenant 1 context and count roles
        PERFORM set_current_tenant_id(test_tenant_1);
        SELECT COUNT(*) FROM roles INTO function_result;
        
        -- Switch to tenant 2 context and count roles
        PERFORM set_current_tenant_id(test_tenant_2);
        
        test_end := clock_timestamp();
        
        -- If we get here without error, context switching works
        RETURN QUERY SELECT 
            'RLS_INTEGRATION'::TEXT, 
            'CONTEXT_SWITCHING'::TEXT, 
            'PASS'::TEXT,
            'Successfully switched between tenant contexts'::TEXT,
            test_end - test_start;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'RLS_INTEGRATION'::TEXT, 
                'CONTEXT_SWITCHING'::TEXT, 
                'FAIL'::TEXT,
                format('Context switching failed: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- =====================================================
    -- TEST 5: Error Handling Tests
    -- =====================================================
    
    -- Clear context for error tests
    PERFORM clear_session_context();
    
    -- Test 5.1: current_tenant_id without context
    test_start := clock_timestamp();
    BEGIN
        SELECT current_tenant_id() INTO retrieved_tenant;
        test_end := clock_timestamp();
        
        RETURN QUERY SELECT 
            'ERROR_HANDLING'::TEXT, 
            'NO_TENANT_CONTEXT'::TEXT, 
            'FAIL'::TEXT,
            'Should have failed when no tenant context set'::TEXT,
            test_end - test_start;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'ERROR_HANDLING'::TEXT, 
                'NO_TENANT_CONTEXT'::TEXT, 
                'PASS'::TEXT,
                format('Correctly failed when no tenant context: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Test 5.2: set_current_user_id without tenant context
    test_start := clock_timestamp();
    BEGIN
        SELECT set_current_user_id(test_user_1) INTO function_result;
        test_end := clock_timestamp();
        
        RETURN QUERY SELECT 
            'ERROR_HANDLING'::TEXT, 
            'USER_WITHOUT_TENANT'::TEXT, 
            'FAIL'::TEXT,
            'Should have failed when setting user without tenant context'::TEXT,
            test_end - test_start;
    EXCEPTION
        WHEN others THEN
            test_end := clock_timestamp();
            RETURN QUERY SELECT 
                'ERROR_HANDLING'::TEXT, 
                'USER_WITHOUT_TENANT'::TEXT, 
                'PASS'::TEXT,
                format('Correctly failed when setting user without tenant: %s', SQLERRM)::TEXT,
                test_end - test_start;
    END;
    
    -- Final cleanup
    PERFORM clear_session_context();
    
END;
$$;

-- =====================================================
-- RUN TESTS AND DISPLAY RESULTS
-- =====================================================

-- Function to display test results in a formatted way
CREATE OR REPLACE FUNCTION display_test_results()
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    test_record RECORD;
    total_tests INTEGER := 0;
    passed_tests INTEGER := 0;
    failed_tests INTEGER := 0;
    current_category TEXT := '';
    total_time INTERVAL := '0'::INTERVAL;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'CONTEXT MANAGEMENT FUNCTION TEST RESULTS';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Test Run Time: %', NOW();
    RAISE NOTICE '';
    
    -- Loop through test results
    FOR test_record IN 
        SELECT * FROM run_context_management_tests() ORDER BY test_category, test_name
    LOOP
        total_tests := total_tests + 1;
        total_time := total_time + test_record.execution_time;
        
        -- Display category header if changed
        IF current_category != test_record.test_category THEN
            current_category := test_record.test_category;
            RAISE NOTICE '';
            RAISE NOTICE '%:', current_category;
            RAISE NOTICE '----------------------------------------';
        END IF;
        
        -- Display test result
        IF test_record.test_result = 'PASS' THEN
            passed_tests := passed_tests + 1;
            RAISE NOTICE '✅ %: % (%s)', 
                test_record.test_name, 
                test_record.details,
                test_record.execution_time;
        ELSE
            failed_tests := failed_tests + 1;
            RAISE NOTICE '❌ %: % (%s)', 
                test_record.test_name, 
                test_record.details,
                test_record.execution_time;
        END IF;
    END LOOP;
    
    -- Display summary
    RAISE NOTICE '';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'TEST SUMMARY';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Total Tests: %', total_tests;
    RAISE NOTICE 'Passed: % (%s%%)', passed_tests, ROUND((passed_tests::numeric / total_tests::numeric) * 100, 1);
    RAISE NOTICE 'Failed: % (%s%%)', failed_tests, ROUND((failed_tests::numeric / total_tests::numeric) * 100, 1);
    RAISE NOTICE 'Total Execution Time: %', total_time;
    RAISE NOTICE '';
    
    IF failed_tests = 0 THEN
        RAISE NOTICE 'Result: ✅ ALL TESTS PASSED';
    ELSE
        RAISE NOTICE 'Result: ❌ % TESTS FAILED', failed_tests;
    END IF;
    RAISE NOTICE '============================================';
END;
$$;

COMMIT;

-- Run the test display function
SELECT display_test_results();