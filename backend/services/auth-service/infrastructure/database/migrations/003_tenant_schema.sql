-- iSECTECH Multi-Tenant Database Schema
-- Production-grade tenant management with security clearance integration
-- File: 003_tenant_schema.sql

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create enum types for tenant management
CREATE TYPE tenant_type AS ENUM (
    'enterprise',
    'government', 
    'defense',
    'critical_infra',
    'financial',
    'healthcare',
    'msp',
    'startup'
);

CREATE TYPE tenant_tier AS ENUM (
    'essential',
    'advanced',
    'enterprise',
    'government'
);

CREATE TYPE tenant_status AS ENUM (
    'active',
    'suspended',
    'disabled',
    'provisioning',
    'migrating',
    'decommissioning'
);

CREATE TYPE compliance_framework AS ENUM (
    'soc2',
    'iso27001',
    'nist',
    'fedramp',
    'hipaa',
    'pci',
    'gdpr',
    'ccpa',
    'fisma'
);

-- Main tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    description TEXT,
    type tenant_type NOT NULL,
    tier tenant_tier NOT NULL,
    status tenant_status NOT NULL DEFAULT 'provisioning',
    
    -- Organization details
    domain VARCHAR(255) NOT NULL UNIQUE,
    additional_domains TEXT[], -- Array of additional verified domains
    industry VARCHAR(100),
    country VARCHAR(2), -- ISO 3166-1 alpha-2
    timezone VARCHAR(50) DEFAULT 'UTC',
    
    -- Security classification and clearance
    max_security_clearance security_clearance_level NOT NULL DEFAULT 'unclassified',
    default_clearance security_clearance_level NOT NULL DEFAULT 'unclassified',
    
    -- Compliance and regulatory requirements
    compliance_frameworks compliance_framework[],
    data_residency_regions TEXT[], -- Array of allowed regions
    
    -- Network and access controls
    allowed_ip_ranges TEXT[], -- Array of CIDR blocks
    blocked_ip_ranges TEXT[], -- Array of blocked CIDR blocks
    require_vpn BOOLEAN DEFAULT FALSE,
    allowed_countries TEXT[], -- Array of ISO country codes
    
    -- Billing and subscription
    subscription_id VARCHAR(100),
    billing_email VARCHAR(255) NOT NULL,
    contract_start_date TIMESTAMP WITH TIME ZONE NOT NULL,
    contract_end_date TIMESTAMP WITH TIME ZONE,
    
    -- Hierarchical relationships
    parent_tenant_id UUID REFERENCES tenants(id),
    is_sub_organization BOOLEAN DEFAULT FALSE,
    
    -- Audit and lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    activated_at TIMESTAMP WITH TIME ZONE,
    suspended_at TIMESTAMP WITH TIME ZONE,
    deactivated_at TIMESTAMP WITH TIME ZONE,
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    version INTEGER DEFAULT 1,
    
    -- Constraints
    CONSTRAINT valid_clearance_hierarchy CHECK (max_security_clearance >= default_clearance),
    CONSTRAINT valid_contract_dates CHECK (contract_end_date IS NULL OR contract_end_date > contract_start_date),
    CONSTRAINT no_self_parent CHECK (parent_tenant_id != id),
    CONSTRAINT valid_status_transitions CHECK (
        (status = 'active' AND activated_at IS NOT NULL) OR
        (status = 'suspended' AND suspended_at IS NOT NULL) OR
        (status = 'disabled' AND deactivated_at IS NOT NULL) OR
        status IN ('provisioning', 'migrating', 'decommissioning')
    )
);

-- Tenant security context table
CREATE TABLE tenant_security_contexts (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    threat_intelligence_level VARCHAR(20) DEFAULT 'basic', -- basic, advanced, premium
    incident_response_tier VARCHAR(20) DEFAULT 'standard', -- standard, priority, critical
    risk_tolerance VARCHAR(10) DEFAULT 'medium', -- low, medium, high
    auto_response_enabled BOOLEAN DEFAULT FALSE,
    threat_hunting_enabled BOOLEAN DEFAULT FALSE,
    forensics_retention INTERVAL DEFAULT '90 days',
    
    -- JSON fields for flexible configuration
    security_policies JSONB DEFAULT '{}',
    alert_thresholds JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant retention policies table
CREATE TABLE tenant_retention_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    audit_logs INTERVAL DEFAULT '90 days',
    security_events INTERVAL DEFAULT '365 days',
    threat_data INTERVAL DEFAULT '180 days',
    incident_data INTERVAL DEFAULT '730 days',
    forensics_data INTERVAL DEFAULT '365 days',
    backup_retention INTERVAL DEFAULT '30 days',
    archive_policy VARCHAR(20) DEFAULT 'cloud', -- local, cloud, hybrid
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant encryption requirements table
CREATE TABLE tenant_encryption_requirements (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    encryption_at_rest VARCHAR(50) DEFAULT 'AES-256',
    encryption_in_transit VARCHAR(50) DEFAULT 'TLS 1.3',
    key_management VARCHAR(20) DEFAULT 'KMS', -- HSM, KMS, local
    certificate_authority VARCHAR(20) DEFAULT 'public', -- internal, public
    hardware_security_module BOOLEAN DEFAULT FALSE,
    fips_compliance BOOLEAN DEFAULT FALSE,
    quantum_resistant BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant resource quotas table
CREATE TABLE tenant_resource_quotas (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    max_users INTEGER DEFAULT 100,
    max_devices INTEGER DEFAULT 1000,
    max_alerts INTEGER DEFAULT 10000,
    max_incidents INTEGER DEFAULT 1000,
    storage_quota_gb BIGINT DEFAULT 100,
    bandwidth_quota_gb BIGINT DEFAULT 1000,
    compute_units INTEGER DEFAULT 10,
    threat_intel_feeds INTEGER DEFAULT 5,
    custom_rules INTEGER DEFAULT 50,
    api_calls_per_minute INTEGER DEFAULT 1000,
    concurrent_sessions INTEGER DEFAULT 100,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant API rate limits table
CREATE TABLE tenant_api_rate_limits (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    requests_per_minute INTEGER DEFAULT 1000,
    requests_per_hour INTEGER DEFAULT 10000,
    requests_per_day INTEGER DEFAULT 100000,
    burst_limit INTEGER DEFAULT 500,
    concurrent_requests INTEGER DEFAULT 50,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant branding configuration table
CREATE TABLE tenant_branding_configs (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    logo_url TEXT,
    favicon_url TEXT,
    primary_color VARCHAR(7), -- Hex color code
    secondary_color VARCHAR(7), -- Hex color code
    custom_css TEXT,
    custom_domain VARCHAR(255),
    white_labeling BOOLEAN DEFAULT FALSE,
    
    -- JSON field for custom email templates
    custom_email_templates JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant feature flags table
CREATE TABLE tenant_feature_flags (
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    flag_name VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (tenant_id, flag_name)
);

-- Tenant maintenance windows table
CREATE TABLE tenant_maintenance_windows (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    day_of_week INTEGER CHECK (day_of_week >= 0 AND day_of_week <= 6), -- 0 = Sunday
    start_time TIME NOT NULL,
    end_time TIME NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    duration INTERVAL,
    enabled BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_time_window CHECK (end_time > start_time)
);

-- Emergency contacts table
CREATE TABLE tenant_emergency_contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    title VARCHAR(100),
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    alternate_phone VARCHAR(20),
    is_primary BOOLEAN DEFAULT FALSE,
    contact_type VARCHAR(20) DEFAULT 'technical', -- technical, business, legal
    available_24x7 BOOLEAN DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
);

-- Tenant integration settings table
CREATE TABLE tenant_integration_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    
    -- SIEM integration
    siem_enabled BOOLEAN DEFAULT FALSE,
    siem_platform VARCHAR(50),
    siem_endpoint TEXT,
    siem_api_key_encrypted TEXT, -- Encrypted API key
    siem_settings JSONB DEFAULT '{}',
    
    -- SOAR integration
    soar_enabled BOOLEAN DEFAULT FALSE,
    soar_platform VARCHAR(50),
    soar_endpoint TEXT,
    soar_credentials_encrypted TEXT, -- Encrypted credentials
    soar_playbook_mappings JSONB DEFAULT '{}',
    soar_auto_execution BOOLEAN DEFAULT FALSE,
    
    -- Ticketing integration
    ticketing_enabled BOOLEAN DEFAULT FALSE,
    ticketing_platform VARCHAR(50),
    ticketing_endpoint TEXT,
    ticketing_credentials_encrypted TEXT, -- Encrypted credentials
    ticketing_project_key VARCHAR(50),
    ticketing_issue_mapping JSONB DEFAULT '{}',
    ticketing_auto_creation BOOLEAN DEFAULT FALSE,
    
    -- Notification settings
    email_notifications BOOLEAN DEFAULT TRUE,
    sms_notifications BOOLEAN DEFAULT FALSE,
    push_notifications BOOLEAN DEFAULT TRUE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Webhook endpoints table
CREATE TABLE tenant_webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    secret_encrypted TEXT, -- Encrypted webhook secret
    events TEXT[] NOT NULL, -- Array of event types
    headers JSONB DEFAULT '{}', -- Custom headers
    enabled BOOLEAN DEFAULT TRUE,
    max_retries INTEGER DEFAULT 3,
    retry_delay INTERVAL DEFAULT '5 minutes',
    backoff_multiplier DECIMAL(3,2) DEFAULT 2.0,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_url CHECK (url ~* '^https?://'),
    CONSTRAINT valid_backoff CHECK (backoff_multiplier >= 1.0)
);

-- Tenant resource usage tracking table
CREATE TABLE tenant_resource_usage (
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    resource_type VARCHAR(50) NOT NULL,
    usage_amount BIGINT NOT NULL DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    reset_at TIMESTAMP WITH TIME ZONE, -- For periodic quotas
    
    PRIMARY KEY (tenant_id, resource_type)
);

-- Tenant audit events table
CREATE TABLE tenant_audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    user_id UUID, -- Optional, may reference users table
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    operation VARCHAR(50) NOT NULL,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    ip_address INET,
    user_agent TEXT,
    
    -- JSON field for flexible context storage
    context JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes for performance
    INDEX idx_tenant_audit_tenant_id (tenant_id),
    INDEX idx_tenant_audit_event_type (event_type),
    INDEX idx_tenant_audit_created_at (created_at),
    INDEX idx_tenant_audit_user_id (user_id),
    INDEX idx_tenant_audit_operation (operation)
);

-- Tenant health checks table
CREATE TABLE tenant_health_checks (
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    check_name VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'unknown', -- healthy, degraded, unhealthy, unknown
    message TEXT,
    details JSONB DEFAULT '{}',
    last_checked TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    PRIMARY KEY (tenant_id, check_name)
);

-- Create indexes for performance
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_type ON tenants(type);
CREATE INDEX idx_tenants_tier ON tenants(tier);
CREATE INDEX idx_tenants_domain ON tenants(domain);
CREATE INDEX idx_tenants_parent_id ON tenants(parent_tenant_id);
CREATE INDEX idx_tenants_created_at ON tenants(created_at);
CREATE INDEX idx_tenants_clearance ON tenants(max_security_clearance);

-- Composite indexes for common queries
CREATE INDEX idx_tenants_status_type ON tenants(status, type);
CREATE INDEX idx_tenants_tier_clearance ON tenants(tier, max_security_clearance);

-- Partial indexes for active tenants (most common queries)
CREATE INDEX idx_tenants_active_created ON tenants(created_at) WHERE status = 'active';
CREATE INDEX idx_tenants_active_domain ON tenants(domain) WHERE status = 'active';

-- GIN indexes for array and JSONB columns
CREATE INDEX idx_tenants_compliance_frameworks ON tenants USING GIN(compliance_frameworks);
CREATE INDEX idx_tenants_allowed_ip_ranges ON tenants USING GIN(allowed_ip_ranges);
CREATE INDEX idx_tenant_security_policies ON tenant_security_contexts USING GIN(security_policies);
CREATE INDEX idx_tenant_alert_thresholds ON tenant_security_contexts USING GIN(alert_thresholds);

-- Full-text search indexes
CREATE INDEX idx_tenants_search ON tenants USING GIN(to_tsvector('english', name || ' ' || display_name || ' ' || COALESCE(description, '')));

-- Enable Row Level Security (RLS) for tenant isolation
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_security_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_encryption_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_resource_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_api_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_branding_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_feature_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_maintenance_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_emergency_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_integration_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_resource_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_health_checks ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for tenant isolation
-- Note: These policies assume a current_tenant_id() function is available
-- This function should be set by the application based on the user's tenant context

-- Main tenants table policy
CREATE POLICY tenant_isolation_policy ON tenants
    FOR ALL
    TO application_role
    USING (id = current_tenant_id() OR parent_tenant_id = current_tenant_id());

-- Security contexts policy
CREATE POLICY tenant_security_context_policy ON tenant_security_contexts
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Retention policies policy
CREATE POLICY tenant_retention_policy ON tenant_retention_policies
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Encryption requirements policy
CREATE POLICY tenant_encryption_policy ON tenant_encryption_requirements
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Resource quotas policy
CREATE POLICY tenant_quotas_policy ON tenant_resource_quotas
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- API rate limits policy
CREATE POLICY tenant_rate_limits_policy ON tenant_api_rate_limits
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Branding configs policy
CREATE POLICY tenant_branding_policy ON tenant_branding_configs
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Feature flags policy
CREATE POLICY tenant_feature_flags_policy ON tenant_feature_flags
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Maintenance windows policy
CREATE POLICY tenant_maintenance_policy ON tenant_maintenance_windows
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Emergency contacts policy
CREATE POLICY tenant_contacts_policy ON tenant_emergency_contacts
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Integration settings policy
CREATE POLICY tenant_integrations_policy ON tenant_integration_settings
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Webhook endpoints policy
CREATE POLICY tenant_webhooks_policy ON tenant_webhook_endpoints
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Resource usage policy
CREATE POLICY tenant_usage_policy ON tenant_resource_usage
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Audit events policy (read-only for tenants)
CREATE POLICY tenant_audit_policy ON tenant_audit_events
    FOR SELECT
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Health checks policy
CREATE POLICY tenant_health_policy ON tenant_health_checks
    FOR ALL
    TO application_role
    USING (tenant_id = current_tenant_id());

-- Create triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_tenant_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply timestamp triggers to all tenant tables
CREATE TRIGGER update_tenants_timestamp
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_tenant_timestamp();

CREATE TRIGGER update_tenant_security_contexts_timestamp
    BEFORE UPDATE ON tenant_security_contexts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_retention_policies_timestamp
    BEFORE UPDATE ON tenant_retention_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_encryption_requirements_timestamp
    BEFORE UPDATE ON tenant_encryption_requirements
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_resource_quotas_timestamp
    BEFORE UPDATE ON tenant_resource_quotas
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_api_rate_limits_timestamp
    BEFORE UPDATE ON tenant_api_rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_branding_configs_timestamp
    BEFORE UPDATE ON tenant_branding_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_feature_flags_timestamp
    BEFORE UPDATE ON tenant_feature_flags
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_maintenance_windows_timestamp
    BEFORE UPDATE ON tenant_maintenance_windows
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_emergency_contacts_timestamp
    BEFORE UPDATE ON tenant_emergency_contacts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_integration_settings_timestamp
    BEFORE UPDATE ON tenant_integration_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenant_webhook_endpoints_timestamp
    BEFORE UPDATE ON tenant_webhook_endpoints
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create function for tenant statistics
CREATE OR REPLACE FUNCTION get_tenant_statistics(p_tenant_id UUID)
RETURNS TABLE (
    user_count BIGINT,
    device_count BIGINT,
    alert_count BIGINT,
    incident_count BIGINT,
    storage_used_gb BIGINT,
    api_calls_today BIGINT
) AS $$
BEGIN
    -- This function would calculate real statistics
    -- For now, return sample data
    RETURN QUERY
    SELECT 
        0::BIGINT as user_count,
        0::BIGINT as device_count,
        0::BIGINT as alert_count,
        0::BIGINT as incident_count,
        0::BIGINT as storage_used_gb,
        0::BIGINT as api_calls_today;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function for tenant compliance validation
CREATE OR REPLACE FUNCTION validate_tenant_compliance(p_tenant_id UUID)
RETURNS TABLE (
    framework compliance_framework,
    compliant BOOLEAN,
    violations TEXT[]
) AS $$
BEGIN
    -- This function would perform actual compliance validation
    -- For now, return sample data
    RETURN QUERY
    SELECT 
        'soc2'::compliance_framework as framework,
        true as compliant,
        ARRAY[]::TEXT[] as violations;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to cleanup expired data
CREATE OR REPLACE FUNCTION cleanup_tenant_expired_data(p_tenant_id UUID)
RETURNS INTEGER AS $$
DECLARE
    retention_policy RECORD;
    deleted_count INTEGER := 0;
BEGIN
    -- Get tenant retention policy
    SELECT * INTO retention_policy
    FROM tenant_retention_policies
    WHERE tenant_id = p_tenant_id;
    
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    
    -- Cleanup audit events older than retention period
    DELETE FROM tenant_audit_events
    WHERE tenant_id = p_tenant_id
      AND created_at < NOW() - retention_policy.audit_logs;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create materialized view for tenant metrics
CREATE MATERIALIZED VIEW tenant_metrics AS
SELECT 
    t.id as tenant_id,
    t.name,
    t.type,
    t.tier,
    t.status,
    t.created_at,
    COALESCE(u.user_count, 0) as user_count,
    COALESCE(r.total_usage, 0) as total_resource_usage,
    COALESCE(a.event_count, 0) as audit_event_count
FROM tenants t
LEFT JOIN (
    SELECT tenant_id, COUNT(*) as user_count
    FROM users
    GROUP BY tenant_id
) u ON t.id = u.tenant_id
LEFT JOIN (
    SELECT tenant_id, SUM(usage_amount) as total_usage
    FROM tenant_resource_usage
    GROUP BY tenant_id
) r ON t.id = r.tenant_id
LEFT JOIN (
    SELECT tenant_id, COUNT(*) as event_count
    FROM tenant_audit_events
    WHERE created_at >= NOW() - INTERVAL '30 days'
    GROUP BY tenant_id
) a ON t.id = a.tenant_id;

-- Create index on materialized view
CREATE INDEX idx_tenant_metrics_tenant_id ON tenant_metrics(tenant_id);
CREATE INDEX idx_tenant_metrics_type_tier ON tenant_metrics(type, tier);

-- Create function to refresh tenant metrics
CREATE OR REPLACE FUNCTION refresh_tenant_metrics()
RETURNS VOID AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY tenant_metrics;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant appropriate permissions
GRANT SELECT ON tenant_metrics TO application_role;
GRANT EXECUTE ON FUNCTION get_tenant_statistics(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION validate_tenant_compliance(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION cleanup_tenant_expired_data(UUID) TO application_role;
GRANT EXECUTE ON FUNCTION refresh_tenant_metrics() TO application_role;

-- Insert default system tenant (for system operations)
INSERT INTO tenants (
    id,
    name,
    display_name,
    description,
    type,
    tier,
    status,
    domain,
    industry,
    country,
    max_security_clearance,
    default_clearance,
    compliance_frameworks,
    billing_email,
    contract_start_date,
    created_by,
    updated_by
) VALUES (
    '00000000-0000-0000-0000-000000000000',
    'system',
    'System Tenant',
    'Internal system tenant for platform operations',
    'enterprise',
    'enterprise',
    'active',
    'system.isectech.internal',
    'Technology',
    'US',
    'top_secret',
    'unclassified',
    ARRAY['soc2', 'iso27001', 'fedramp']::compliance_framework[],
    'system@isectech.com',
    NOW(),
    '00000000-0000-0000-0000-000000000000',
    '00000000-0000-0000-0000-000000000000'
) ON CONFLICT (id) DO NOTHING;

-- Insert default security context for system tenant
INSERT INTO tenant_security_contexts (
    tenant_id,
    threat_intelligence_level,
    incident_response_tier,
    risk_tolerance,
    auto_response_enabled,
    threat_hunting_enabled,
    forensics_retention,
    security_policies,
    alert_thresholds
) VALUES (
    '00000000-0000-0000-0000-000000000000',
    'premium',
    'critical',
    'low',
    true,
    true,
    '7 years',
    '{"encryption_required": true, "audit_all_access": true, "require_mfa": true}',
    '{"critical_severity": 0.9, "high_severity": 0.8, "failed_login_rate": 0.05}'
) ON CONFLICT (tenant_id) DO NOTHING;

-- Comments for documentation
COMMENT ON TABLE tenants IS 'Main tenants table for multi-tenant iSECTECH platform with security clearance integration';
COMMENT ON COLUMN tenants.max_security_clearance IS 'Maximum security clearance level allowed for this tenant';
COMMENT ON COLUMN tenants.compliance_frameworks IS 'Array of compliance frameworks the tenant must adhere to';
COMMENT ON TABLE tenant_security_contexts IS 'Security-specific configuration for each tenant';
COMMENT ON TABLE tenant_audit_events IS 'Comprehensive audit log for all tenant operations';
COMMENT ON MATERIALIZED VIEW tenant_metrics IS 'Aggregated metrics for tenant monitoring and reporting';

-- Enable table statistics for query optimization
ANALYZE tenants;
ANALYZE tenant_audit_events;
ANALYZE tenant_resource_usage;