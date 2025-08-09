-- Create current_tenant_id() function for PostgreSQL RLS
-- This function returns the tenant ID from the current session context

-- Enable the required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create security clearance level enum if it doesn't exist
DO $$ BEGIN
    CREATE TYPE security_clearance_level AS ENUM (
        'unclassified',
        'cui',
        'confidential', 
        'secret',
        'top_secret'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create application role for RLS policies
DO $$ BEGIN
    CREATE ROLE application_role;
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Grant necessary permissions to application role
GRANT CONNECT ON DATABASE postgres TO application_role;
GRANT USAGE ON SCHEMA public TO application_role;

-- Create session variables table for tenant context
CREATE TABLE IF NOT EXISTS session_context (
    session_id TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id UUID,
    security_clearance security_clearance_level DEFAULT 'unclassified',
    permissions TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() + INTERVAL '24 hours'
);

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_session_context_tenant_id ON session_context(tenant_id);
CREATE INDEX IF NOT EXISTS idx_session_context_expires_at ON session_context(expires_at);

-- Function to set tenant context for current session
CREATE OR REPLACE FUNCTION set_tenant_context(
    p_tenant_id UUID,
    p_user_id UUID DEFAULT NULL,
    p_security_clearance security_clearance_level DEFAULT 'unclassified',
    p_permissions TEXT[] DEFAULT ARRAY[]::TEXT[]
) RETURNS VOID AS $$
DECLARE
    session_key TEXT;
BEGIN
    -- Generate session key from connection info
    session_key := COALESCE(
        current_setting('app.session_id', true),
        current_setting('application_name', true),
        'default'
    );
    
    -- Insert or update session context
    INSERT INTO session_context (
        session_id, 
        tenant_id, 
        user_id, 
        security_clearance, 
        permissions
    ) VALUES (
        session_key, 
        p_tenant_id, 
        p_user_id, 
        p_security_clearance, 
        p_permissions
    )
    ON CONFLICT (session_id) 
    DO UPDATE SET
        tenant_id = EXCLUDED.tenant_id,
        user_id = EXCLUDED.user_id,
        security_clearance = EXCLUDED.security_clearance,
        permissions = EXCLUDED.permissions,
        expires_at = NOW() + INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get current tenant ID from session context
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
DECLARE
    session_key TEXT;
    tenant_id UUID;
BEGIN
    -- Get session key
    session_key := COALESCE(
        current_setting('app.session_id', true),
        current_setting('application_name', true),
        'default'
    );
    
    -- Get tenant ID from session context
    SELECT sc.tenant_id INTO tenant_id
    FROM session_context sc
    WHERE sc.session_id = session_key
      AND sc.expires_at > NOW();
    
    -- Return tenant ID or NULL if not found
    RETURN tenant_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get current user ID from session context
CREATE OR REPLACE FUNCTION current_user_id() RETURNS UUID AS $$
DECLARE
    session_key TEXT;
    user_id UUID;
BEGIN
    session_key := COALESCE(
        current_setting('app.session_id', true),
        current_setting('application_name', true),
        'default'
    );
    
    SELECT sc.user_id INTO user_id
    FROM session_context sc
    WHERE sc.session_id = session_key
      AND sc.expires_at > NOW();
    
    RETURN user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get current security clearance from session context
CREATE OR REPLACE FUNCTION current_security_clearance() RETURNS security_clearance_level AS $$
DECLARE
    session_key TEXT;
    clearance security_clearance_level;
BEGIN
    session_key := COALESCE(
        current_setting('app.session_id', true),
        current_setting('application_name', true),
        'default'
    );
    
    SELECT sc.security_clearance INTO clearance
    FROM session_context sc
    WHERE sc.session_id = session_key
      AND sc.expires_at > NOW();
    
    RETURN COALESCE(clearance, 'unclassified'::security_clearance_level);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to check if current user has permission
CREATE OR REPLACE FUNCTION has_permission(permission_name TEXT) RETURNS BOOLEAN AS $$
DECLARE
    session_key TEXT;
    user_permissions TEXT[];
BEGIN
    session_key := COALESCE(
        current_setting('app.session_id', true),
        current_setting('application_name', true),
        'default'
    );
    
    SELECT sc.permissions INTO user_permissions
    FROM session_context sc
    WHERE sc.session_id = session_key
      AND sc.expires_at > NOW();
    
    -- Check if user has the specific permission or wildcard permissions
    RETURN (
        permission_name = ANY(user_permissions) OR
        '*:*' = ANY(user_permissions) OR
        (permission_name LIKE '%:%' AND 
         (split_part(permission_name, ':', 1) || ':*') = ANY(user_permissions))
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions() RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM session_context
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permissions to application role
GRANT EXECUTE ON FUNCTION set_tenant_context(UUID, UUID, security_clearance_level, TEXT[]) TO application_role;
GRANT EXECUTE ON FUNCTION current_tenant_id() TO application_role;
GRANT EXECUTE ON FUNCTION current_user_id() TO application_role;
GRANT EXECUTE ON FUNCTION current_security_clearance() TO application_role;
GRANT EXECUTE ON FUNCTION has_permission(TEXT) TO application_role;
GRANT EXECUTE ON FUNCTION cleanup_expired_sessions() TO application_role;
GRANT EXECUTE ON FUNCTION update_updated_at_column() TO application_role;

-- Grant table permissions to application role
GRANT SELECT ON session_context TO application_role;
GRANT INSERT, UPDATE, DELETE ON session_context TO application_role;

-- Create scheduled job to cleanup expired sessions (requires pg_cron extension)
-- This would typically be set up separately in production
-- SELECT cron.schedule('cleanup-expired-sessions', '*/15 * * * *', 'SELECT cleanup_expired_sessions();');

-- Comments for documentation
COMMENT ON FUNCTION set_tenant_context IS 'Sets the tenant context for the current database session';
COMMENT ON FUNCTION current_tenant_id IS 'Returns the tenant ID for the current session';
COMMENT ON FUNCTION current_user_id IS 'Returns the user ID for the current session';
COMMENT ON FUNCTION current_security_clearance IS 'Returns the security clearance level for the current session';
COMMENT ON FUNCTION has_permission IS 'Checks if the current user has a specific permission';
COMMENT ON TABLE session_context IS 'Stores tenant context information for database sessions';