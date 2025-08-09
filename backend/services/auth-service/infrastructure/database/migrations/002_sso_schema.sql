-- SSO (Single Sign-On) Schema Migration
-- This migration adds support for SAML 2.0, OIDC, and social login providers

-- Identity Provider Types enum
CREATE TYPE identity_provider_type AS ENUM (
    'saml',
    'oidc', 
    'google',
    'microsoft',
    'github',
    'okta',
    'auth0',
    'azure_ad',
    'adfs',
    'ping_identity'
);

-- Identity Provider Status enum
CREATE TYPE identity_provider_status AS ENUM (
    'active',
    'inactive',
    'testing',
    'deprecated',
    'error'
);

-- Identity Providers table
CREATE TABLE identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    type identity_provider_type NOT NULL,
    status identity_provider_status NOT NULL DEFAULT 'testing',
    
    -- Provider configuration (JSON)
    configuration JSONB NOT NULL DEFAULT '{}',
    
    -- Metadata and certificates
    metadata JSONB DEFAULT '{}',
    certificate TEXT,
    private_key TEXT, -- Encrypted
    
    -- Endpoints
    login_url TEXT NOT NULL,
    logout_url TEXT,
    callback_url TEXT NOT NULL,
    metadata_url TEXT,
    
    -- Settings
    is_default BOOLEAN NOT NULL DEFAULT false,
    priority INTEGER NOT NULL DEFAULT 1,
    enable_jit BOOLEAN NOT NULL DEFAULT false, -- Just-In-Time provisioning
    
    -- Attribute mapping (JSON)
    attribute_mapping JSONB DEFAULT '{}',
    
    -- Security settings
    require_secure_cert BOOLEAN NOT NULL DEFAULT true,
    validate_signature BOOLEAN NOT NULL DEFAULT true,
    encrypt_assertions BOOLEAN NOT NULL DEFAULT false,
    
    -- Session management
    session_timeout INTERVAL NOT NULL DEFAULT '8 hours',
    force_logout BOOLEAN NOT NULL DEFAULT false,
    
    -- Audit and monitoring
    last_used_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    last_error TEXT,
    usage_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps and audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    
    -- Constraints
    CONSTRAINT identity_providers_tenant_name_unique UNIQUE(tenant_id, name),
    CONSTRAINT identity_providers_valid_priority CHECK (priority > 0),
    CONSTRAINT identity_providers_valid_session_timeout CHECK (session_timeout > INTERVAL '0'),
    CONSTRAINT identity_providers_one_default_per_tenant EXCLUDE USING btree (
        tenant_id WITH =, 
        type WITH =
    ) WHERE (is_default = true)
);

-- Federated Users table
CREATE TABLE federated_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    
    -- External identity information
    external_id VARCHAR(255) NOT NULL,
    external_username VARCHAR(255),
    external_email VARCHAR(255),
    
    -- Claims and attributes from the provider
    claims JSONB DEFAULT '{}',
    attributes JSONB DEFAULT '{}',
    
    -- Session information
    last_login_at TIMESTAMPTZ,
    last_token_at TIMESTAMPTZ,
    token_expiration TIMESTAMPTZ,
    
    -- Mapping information
    mapped_roles TEXT[] DEFAULT '{}',
    mapped_clearance security_clearance_level NOT NULL DEFAULT 'unclassified',
    
    -- Status and audit
    is_active BOOLEAN NOT NULL DEFAULT true,
    login_count BIGINT NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT federated_users_provider_external_unique UNIQUE(provider_id, external_id),
    CONSTRAINT federated_users_tenant_user_provider_unique UNIQUE(tenant_id, user_id, provider_id)
);

-- SSO Sessions table
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    
    -- External session information
    external_session_id VARCHAR(255),
    saml_session_index VARCHAR(255),
    oidc_id_token TEXT, -- Encrypted
    
    -- Session metadata
    login_method identity_provider_type NOT NULL,
    auth_context JSONB DEFAULT '{}',
    
    -- Security context
    ip_address INET,
    user_agent TEXT,
    location VARCHAR(255),
    
    -- Session lifecycle
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT sso_sessions_valid_expiry CHECK (expires_at > created_at),
    CONSTRAINT sso_sessions_valid_activity CHECK (last_activity_at >= created_at)
);

-- Attribute Mappings table
CREATE TABLE attribute_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- Mapping configuration
    external_attribute VARCHAR(255) NOT NULL,
    internal_attribute VARCHAR(255) NOT NULL,
    attribute_type VARCHAR(50) NOT NULL, -- user, role, clearance, etc.
    
    -- Transformation rules
    transform_rule TEXT,
    default_value TEXT,
    required BOOLEAN NOT NULL DEFAULT false,
    
    -- Validation
    validation_regex TEXT,
    allowed_values TEXT[],
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT attribute_mappings_provider_external_unique UNIQUE(provider_id, external_attribute),
    CONSTRAINT attribute_mappings_valid_type CHECK (attribute_type IN ('user', 'role', 'clearance', 'group', 'permission', 'custom'))
);

-- SSO Audit Events table
CREATE TABLE sso_audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL,
    provider_id UUID REFERENCES identity_providers(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id VARCHAR(255),
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    
    -- Event details
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance

-- Identity Providers indexes
CREATE INDEX idx_identity_providers_tenant_type ON identity_providers(tenant_id, type);
CREATE INDEX idx_identity_providers_tenant_status ON identity_providers(tenant_id, status);
CREATE INDEX idx_identity_providers_tenant_active ON identity_providers(tenant_id) WHERE status = 'active';
CREATE INDEX idx_identity_providers_last_used ON identity_providers(last_used_at) WHERE last_used_at IS NOT NULL;
CREATE INDEX idx_identity_providers_usage_count ON identity_providers(usage_count);

-- Federated Users indexes
CREATE INDEX idx_federated_users_user_tenant ON federated_users(user_id, tenant_id);
CREATE INDEX idx_federated_users_provider_external ON federated_users(provider_id, external_id);
CREATE INDEX idx_federated_users_external_email ON federated_users(external_email) WHERE external_email IS NOT NULL;
CREATE INDEX idx_federated_users_last_login ON federated_users(last_login_at) WHERE last_login_at IS NOT NULL;
CREATE INDEX idx_federated_users_active ON federated_users(tenant_id) WHERE is_active = true;

-- SSO Sessions indexes
CREATE INDEX idx_sso_sessions_user_tenant ON sso_sessions(user_id, tenant_id);
CREATE INDEX idx_sso_sessions_provider ON sso_sessions(provider_id);
CREATE INDEX idx_sso_sessions_session_id ON sso_sessions(session_id);
CREATE INDEX idx_sso_sessions_external_session ON sso_sessions(external_session_id) WHERE external_session_id IS NOT NULL;
CREATE INDEX idx_sso_sessions_active ON sso_sessions(tenant_id) WHERE is_active = true;
CREATE INDEX idx_sso_sessions_expires_at ON sso_sessions(expires_at);
CREATE INDEX idx_sso_sessions_last_activity ON sso_sessions(last_activity_at);

-- Attribute Mappings indexes
CREATE INDEX idx_attribute_mappings_provider ON attribute_mappings(provider_id);
CREATE INDEX idx_attribute_mappings_provider_type ON attribute_mappings(provider_id, attribute_type);

-- SSO Audit Events indexes
CREATE INDEX idx_sso_audit_events_tenant_type ON sso_audit_events(tenant_id, event_type);
CREATE INDEX idx_sso_audit_events_provider ON sso_audit_events(provider_id) WHERE provider_id IS NOT NULL;
CREATE INDEX idx_sso_audit_events_user ON sso_audit_events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_sso_audit_events_created_at ON sso_audit_events(created_at);
CREATE INDEX idx_sso_audit_events_success ON sso_audit_events(tenant_id, success);
CREATE INDEX idx_sso_audit_events_session ON sso_audit_events(session_id) WHERE session_id IS NOT NULL;

-- Functions and Triggers

-- Update timestamp trigger for identity_providers
CREATE OR REPLACE FUNCTION update_identity_providers_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_identity_providers_updated_at
    BEFORE UPDATE ON identity_providers
    FOR EACH ROW
    EXECUTE FUNCTION update_identity_providers_updated_at();

-- Update timestamp trigger for federated_users
CREATE OR REPLACE FUNCTION update_federated_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_federated_users_updated_at
    BEFORE UPDATE ON federated_users
    FOR EACH ROW
    EXECUTE FUNCTION update_federated_users_updated_at();

-- Update timestamp trigger for sso_sessions
CREATE OR REPLACE FUNCTION update_sso_sessions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_sso_sessions_updated_at
    BEFORE UPDATE ON sso_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_sso_sessions_updated_at();

-- Update timestamp trigger for attribute_mappings
CREATE OR REPLACE FUNCTION update_attribute_mappings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_attribute_mappings_updated_at
    BEFORE UPDATE ON attribute_mappings
    FOR EACH ROW
    EXECUTE FUNCTION update_attribute_mappings_updated_at();

-- Auto-increment usage counter for identity providers on login
CREATE OR REPLACE FUNCTION increment_provider_usage()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE identity_providers 
    SET 
        usage_count = usage_count + 1,
        last_used_at = NOW()
    WHERE id = NEW.provider_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_increment_provider_usage
    AFTER INSERT ON sso_sessions
    FOR EACH ROW
    EXECUTE FUNCTION increment_provider_usage();

-- Cleanup function for expired SSO sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sso_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sso_sessions 
    WHERE expires_at < NOW() - INTERVAL '1 day';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup activity
    INSERT INTO sso_audit_events (
        event_type,
        tenant_id,
        success,
        metadata,
        created_at
    ) VALUES (
        'session_cleanup',
        '00000000-0000-0000-0000-000000000000', -- System tenant
        true,
        jsonb_build_object('deleted_sessions', deleted_count),
        NOW()
    );
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get provider statistics
CREATE OR REPLACE FUNCTION get_provider_stats(p_tenant_id UUID, p_provider_id UUID DEFAULT NULL)
RETURNS TABLE (
    provider_id UUID,
    provider_name VARCHAR,
    provider_type identity_provider_type,
    total_users BIGINT,
    active_sessions BIGINT,
    total_logins BIGINT,
    last_login TIMESTAMPTZ,
    error_rate NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ip.id,
        ip.name,
        ip.type,
        COUNT(DISTINCT fu.user_id)::BIGINT AS total_users,
        COUNT(DISTINCT ss.id) FILTER (WHERE ss.is_active = true AND ss.expires_at > NOW())::BIGINT AS active_sessions,
        COALESCE(ip.usage_count, 0) AS total_logins,
        ip.last_used_at AS last_login,
        CASE 
            WHEN ip.usage_count > 0 THEN 
                ROUND((ip.error_count::NUMERIC / ip.usage_count::NUMERIC) * 100, 2)
            ELSE 0
        END AS error_rate
    FROM identity_providers ip
    LEFT JOIN federated_users fu ON ip.id = fu.provider_id AND fu.is_active = true
    LEFT JOIN sso_sessions ss ON ip.id = ss.provider_id
    WHERE ip.tenant_id = p_tenant_id
    AND (p_provider_id IS NULL OR ip.id = p_provider_id)
    GROUP BY ip.id, ip.name, ip.type, ip.usage_count, ip.error_count, ip.last_used_at
    ORDER BY ip.usage_count DESC;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions (adjust based on your security model)
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers TO isectech;
GRANT SELECT, INSERT, UPDATE, DELETE ON federated_users TO isectech;
GRANT SELECT, INSERT, UPDATE, DELETE ON sso_sessions TO isectech;
GRANT SELECT, INSERT, UPDATE, DELETE ON attribute_mappings TO isectech;
GRANT SELECT, INSERT, UPDATE, DELETE ON sso_audit_events TO isectech;

GRANT USAGE ON SEQUENCE identity_providers_id_seq TO isectech;
GRANT USAGE ON SEQUENCE federated_users_id_seq TO isectech;
GRANT USAGE ON SEQUENCE sso_sessions_id_seq TO isectech;
GRANT USAGE ON SEQUENCE attribute_mappings_id_seq TO isectech;
GRANT USAGE ON SEQUENCE sso_audit_events_id_seq TO isectech;

-- Comments for documentation
COMMENT ON TABLE identity_providers IS 'External identity providers for SSO (SAML, OIDC, social login)';
COMMENT ON TABLE federated_users IS 'Links between internal users and external identity provider accounts';
COMMENT ON TABLE sso_sessions IS 'Active SSO sessions and their metadata';
COMMENT ON TABLE attribute_mappings IS 'Mappings between external provider attributes and internal user properties';
COMMENT ON TABLE sso_audit_events IS 'Audit log for all SSO-related events';

COMMENT ON COLUMN identity_providers.configuration IS 'Provider-specific configuration (client_id, endpoints, etc.) stored as JSON';
COMMENT ON COLUMN identity_providers.metadata IS 'Provider metadata (SAML metadata, OIDC discovery) stored as JSON';
COMMENT ON COLUMN identity_providers.private_key IS 'Encrypted private key for SAML signing/encryption';
COMMENT ON COLUMN identity_providers.enable_jit IS 'Enable Just-In-Time user provisioning';
COMMENT ON COLUMN federated_users.claims IS 'Claims from the identity provider stored as JSON';
COMMENT ON COLUMN federated_users.attributes IS 'User attributes from the provider stored as JSON';
COMMENT ON COLUMN sso_sessions.oidc_id_token IS 'Encrypted OIDC ID token for session validation';
COMMENT ON COLUMN attribute_mappings.transform_rule IS 'Transformation rule for converting external to internal values';