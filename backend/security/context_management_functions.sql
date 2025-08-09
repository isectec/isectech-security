-- iSECTECH Context Management Functions
-- Task 80.3: Develop Functions for Tenant and User Context Management
-- Simple wrapper functions that provide exact interface specified in task requirements
-- Leverages existing secure RBAC implementation

BEGIN;

-- =====================================================
-- SIMPLE CONTEXT SETTER FUNCTIONS
-- =====================================================

-- Function: set_current_tenant_id
-- Sets the current tenant ID using session variables
-- Usage: SELECT set_current_tenant_id('123e4567-e89b-12d3-a456-426614174000');
CREATE OR REPLACE FUNCTION set_current_tenant_id(p_tenant_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    is_valid BOOLEAN := FALSE;
BEGIN
    -- Validate tenant exists before setting
    SELECT EXISTS (
        SELECT 1 FROM tenants WHERE id = p_tenant_id
    ) INTO is_valid;
    
    IF NOT is_valid THEN
        RAISE EXCEPTION 'Invalid tenant ID: % - tenant does not exist', p_tenant_id;
    END IF;
    
    -- Set tenant context using PostgreSQL session variables
    PERFORM set_config('app.current_tenant_id', p_tenant_id::text, true);
    
    RETURN TRUE;
EXCEPTION
    WHEN others THEN
        RAISE EXCEPTION 'Failed to set tenant context: %', SQLERRM;
END;
$$;

-- Function: set_current_user_id
-- Sets the current user ID using session variables
-- Usage: SELECT set_current_user_id('234e5678-e89b-12d3-a456-426614174001');
CREATE OR REPLACE FUNCTION set_current_user_id(p_user_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    is_valid BOOLEAN := FALSE;
    current_tenant UUID;
BEGIN
    -- Get current tenant context (must be set first)
    BEGIN
        current_tenant := current_setting('app.current_tenant_id')::UUID;
    EXCEPTION
        WHEN others THEN
            RAISE EXCEPTION 'Tenant context must be set before setting user context';
    END;
    
    -- Validate user exists and has access to current tenant
    SELECT EXISTS (
        SELECT 1 FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        WHERE u.id = p_user_id 
        AND ur.tenant_id = current_tenant
    ) INTO is_valid;
    
    IF NOT is_valid THEN
        RAISE EXCEPTION 'Invalid user ID: % - user does not exist or not authorized for current tenant %', 
            p_user_id, current_tenant;
    END IF;
    
    -- Set user context using PostgreSQL session variables
    PERFORM set_config('app.current_user_id', p_user_id::text, true);
    
    RETURN TRUE;
EXCEPTION
    WHEN others THEN
        RAISE EXCEPTION 'Failed to set user context: %', SQLERRM;
END;
$$;

-- =====================================================
-- SIMPLE CONTEXT GETTER FUNCTIONS
-- =====================================================

-- Function: current_tenant_id()
-- Returns the current tenant ID from session variables
-- Usage: SELECT current_tenant_id();
CREATE OR REPLACE FUNCTION current_tenant_id()
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    tenant_id UUID;
BEGIN
    BEGIN
        tenant_id := current_setting('app.current_tenant_id')::UUID;
        
        IF tenant_id IS NULL THEN
            RAISE EXCEPTION 'Tenant context not set';
        END IF;
        
        RETURN tenant_id;
    EXCEPTION
        WHEN undefined_object THEN
            RAISE EXCEPTION 'Tenant context not set - call set_current_tenant_id() first';
        WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'Invalid tenant context value - call set_current_tenant_id() with valid UUID';
        WHEN others THEN
            RAISE EXCEPTION 'Failed to retrieve tenant context: %', SQLERRM;
    END;
END;
$$;

-- Function: current_user_id()
-- Returns the current user ID from session variables
-- Usage: SELECT current_user_id();
CREATE OR REPLACE FUNCTION current_user_id()
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    user_id UUID;
BEGIN
    BEGIN
        user_id := current_setting('app.current_user_id')::UUID;
        
        IF user_id IS NULL THEN
            RAISE EXCEPTION 'User context not set';
        END IF;
        
        RETURN user_id;
    EXCEPTION
        WHEN undefined_object THEN
            RAISE EXCEPTION 'User context not set - call set_current_user_id() first';
        WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'Invalid user context value - call set_current_user_id() with valid UUID';
        WHEN others THEN
            RAISE EXCEPTION 'Failed to retrieve user context: %', SQLERRM;
    END;
END;
$$;

-- =====================================================
-- ENHANCED CONTEXT MANAGEMENT FUNCTIONS
-- =====================================================

-- Function: set_session_context
-- Combined function to set both tenant and user context in one call
-- Usage: SELECT set_session_context(tenant_id, user_id);
CREATE OR REPLACE FUNCTION set_session_context(
    p_tenant_id UUID,
    p_user_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    result JSONB;
    tenant_valid BOOLEAN := FALSE;
    user_valid BOOLEAN := TRUE;
    tenant_name TEXT;
    user_email TEXT;
BEGIN
    -- Validate and set tenant context
    SELECT EXISTS (
        SELECT 1 FROM tenants WHERE id = p_tenant_id
    ), name INTO tenant_valid, tenant_name
    FROM tenants WHERE id = p_tenant_id;
    
    IF NOT tenant_valid THEN
        RETURN jsonb_build_object(
            'success', false,
            'error', 'INVALID_TENANT',
            'message', format('Tenant %s does not exist', p_tenant_id)
        );
    END IF;
    
    -- Set tenant context
    PERFORM set_config('app.current_tenant_id', p_tenant_id::text, true);
    
    -- Validate and set user context if provided
    IF p_user_id IS NOT NULL THEN
        SELECT EXISTS (
            SELECT 1 FROM users u
            JOIN user_roles ur ON u.id = ur.user_id
            WHERE u.id = p_user_id 
            AND ur.tenant_id = p_tenant_id
        ), u.email INTO user_valid, user_email
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        WHERE u.id = p_user_id 
        AND ur.tenant_id = p_tenant_id
        LIMIT 1;
        
        IF NOT user_valid THEN
            -- Clear tenant context on user validation failure
            PERFORM set_config('app.current_tenant_id', NULL, true);
            RETURN jsonb_build_object(
                'success', false,
                'error', 'INVALID_USER_TENANT',
                'message', format('User %s is not authorized for tenant %s', p_user_id, p_tenant_id)
            );
        END IF;
        
        -- Set user context
        PERFORM set_config('app.current_user_id', p_user_id::text, true);
    END IF;
    
    -- Log context setting for audit
    INSERT INTO security_audit_log (
        event_type, severity, table_name, operation_type,
        user_tenant_id, resource_tenant_id, violation_context,
        timestamp, session_id, application_user
    ) VALUES (
        'CONTEXT_SET', 'INFO', 'session_context', 'SET_CONTEXT',
        p_tenant_id::text, p_tenant_id::text,
        jsonb_build_object(
            'tenant_id', p_tenant_id,
            'user_id', COALESCE(p_user_id::text, 'NULL'),
            'function', 'set_session_context'
        ),
        NOW(), current_setting('tenant.session_id', true),
        current_setting('tenant.application_user', true)
    );
    
    -- Build success response
    result := jsonb_build_object(
        'success', true,
        'context', jsonb_build_object(
            'tenant_id', p_tenant_id,
            'tenant_name', tenant_name,
            'user_id', p_user_id,
            'user_email', user_email,
            'set_at', NOW()
        )
    );
    
    RETURN result;
EXCEPTION
    WHEN others THEN
        -- Clear context on any error
        PERFORM set_config('app.current_tenant_id', NULL, true);
        PERFORM set_config('app.current_user_id', NULL, true);
        
        RETURN jsonb_build_object(
            'success', false,
            'error', 'CONTEXT_SET_FAILED',
            'message', SQLERRM
        );
END;
$$;

-- Function: get_session_context
-- Returns current session context information
-- Usage: SELECT get_session_context();
CREATE OR REPLACE FUNCTION get_session_context()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    result JSONB;
    tenant_id UUID;
    user_id UUID;
    tenant_name TEXT;
    user_email TEXT;
BEGIN
    -- Get tenant context
    BEGIN
        tenant_id := current_setting('app.current_tenant_id')::UUID;
        SELECT name INTO tenant_name FROM tenants WHERE id = tenant_id;
    EXCEPTION
        WHEN others THEN
            tenant_id := NULL;
            tenant_name := NULL;
    END;
    
    -- Get user context
    BEGIN
        user_id := current_setting('app.current_user_id')::UUID;
        SELECT email INTO user_email FROM users WHERE id = user_id;
    EXCEPTION
        WHEN others THEN
            user_id := NULL;
            user_email := NULL;
    END;
    
    -- Build context response
    result := jsonb_build_object(
        'tenant_context', jsonb_build_object(
            'tenant_id', tenant_id,
            'tenant_name', tenant_name,
            'is_set', tenant_id IS NOT NULL
        ),
        'user_context', jsonb_build_object(
            'user_id', user_id,
            'user_email', user_email,
            'is_set', user_id IS NOT NULL
        ),
        'session_info', jsonb_build_object(
            'database_user', current_user,
            'application_name', current_setting('application_name', true),
            'client_ip', inet_client_addr()::text,
            'retrieved_at', NOW()
        )
    );
    
    RETURN result;
END;
$$;

-- Function: clear_session_context
-- Clears all session context variables
-- Usage: SELECT clear_session_context();
CREATE OR REPLACE FUNCTION clear_session_context()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Clear both tenant and user context
    PERFORM set_config('app.current_tenant_id', NULL, true);
    PERFORM set_config('app.current_user_id', NULL, true);
    
    -- Log context clearing for audit
    INSERT INTO security_audit_log (
        event_type, severity, table_name, operation_type,
        user_tenant_id, resource_tenant_id, violation_context,
        timestamp, session_id, application_user
    ) VALUES (
        'CONTEXT_CLEARED', 'INFO', 'session_context', 'CLEAR_CONTEXT',
        'CLEARED', 'CLEARED',
        jsonb_build_object('function', 'clear_session_context'),
        NOW(), current_setting('tenant.session_id', true),
        current_setting('tenant.application_user', true)
    );
    
    RETURN TRUE;
EXCEPTION
    WHEN others THEN
        RETURN FALSE;
END;
$$;

-- =====================================================
-- GRANTS AND PERMISSIONS
-- =====================================================

-- Grant execution permissions for context management functions
GRANT EXECUTE ON FUNCTION set_current_tenant_id(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION set_current_user_id(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION current_tenant_id() TO application_role;
GRANT EXECUTE ON FUNCTION current_user_id() TO application_role;
GRANT EXECUTE ON FUNCTION set_session_context(UUID, UUID) TO application_role;
GRANT EXECUTE ON FUNCTION get_session_context() TO application_role;
GRANT EXECUTE ON FUNCTION clear_session_context() TO application_role;

COMMIT;

-- =====================================================
-- DOCUMENTATION AND EXAMPLES
-- =====================================================

-- Add helpful comments
COMMENT ON FUNCTION set_current_tenant_id(UUID) IS 'Sets current tenant context using session variables';
COMMENT ON FUNCTION set_current_user_id(UUID) IS 'Sets current user context using session variables (requires tenant context)';
COMMENT ON FUNCTION current_tenant_id() IS 'Returns current tenant ID from session variables';
COMMENT ON FUNCTION current_user_id() IS 'Returns current user ID from session variables';
COMMENT ON FUNCTION set_session_context(UUID, UUID) IS 'Sets both tenant and user context with validation and audit logging';
COMMENT ON FUNCTION get_session_context() IS 'Returns complete session context information';
COMMENT ON FUNCTION clear_session_context() IS 'Clears all session context variables';

-- Display usage examples
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'CONTEXT MANAGEMENT FUNCTIONS DEPLOYED';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Deployment Time: %', NOW();
    RAISE NOTICE '';
    RAISE NOTICE 'Available Functions:';
    RAISE NOTICE '  • set_current_tenant_id(tenant_id)';
    RAISE NOTICE '  • set_current_user_id(user_id)';
    RAISE NOTICE '  • current_tenant_id()';
    RAISE NOTICE '  • current_user_id()';
    RAISE NOTICE '  • set_session_context(tenant_id, user_id)';
    RAISE NOTICE '  • get_session_context()';
    RAISE NOTICE '  • clear_session_context()';
    RAISE NOTICE '';
    RAISE NOTICE 'Usage Examples:';
    RAISE NOTICE '  -- Set tenant context';
    RAISE NOTICE '  SELECT set_current_tenant_id(''123e4567-e89b-12d3-a456-426614174000'');';
    RAISE NOTICE '';
    RAISE NOTICE '  -- Set user context';
    RAISE NOTICE '  SELECT set_current_user_id(''234e5678-e89b-12d3-a456-426614174001'');';
    RAISE NOTICE '';
    RAISE NOTICE '  -- Get current contexts';
    RAISE NOTICE '  SELECT current_tenant_id(), current_user_id();';
    RAISE NOTICE '';
    RAISE NOTICE '  -- Set both contexts at once';
    RAISE NOTICE '  SELECT set_session_context(';
    RAISE NOTICE '    ''123e4567-e89b-12d3-a456-426614174000'',';
    RAISE NOTICE '    ''234e5678-e89b-12d3-a456-426614174001''';
    RAISE NOTICE '  );';
    RAISE NOTICE '';
    RAISE NOTICE '  -- View complete context';
    RAISE NOTICE '  SELECT get_session_context();';
    RAISE NOTICE '';
    RAISE NOTICE '  -- Clear context';
    RAISE NOTICE '  SELECT clear_session_context();';
    RAISE NOTICE '============================================';
END;
$$;