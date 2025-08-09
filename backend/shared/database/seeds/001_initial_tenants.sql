-- Initial tenant seed data for iSECTECH Multi-Tenant Platform
-- This file creates sample tenants for development and testing

-- First ensure our functions are available
DO $$ 
BEGIN
    -- Test if current_tenant_id function exists
    PERFORM current_tenant_id();
EXCEPTION
    WHEN undefined_function THEN
        RAISE EXCEPTION 'current_tenant_id() function not found. Please run 001_create_current_tenant_function.sql first';
END $$;

-- Create initial tenants
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
    compliance_frameworks,
    max_security_clearance,
    billing_email,
    contract_start_date,
    contract_end_date,
    resource_quotas,
    network_config,
    encryption_config,
    backup_config,
    monitoring_config,
    created_at,
    updated_at
) VALUES 
(
    '123e4567-e89b-12d3-a456-426614174000',
    'acme-corp',
    'ACME Corporation',
    'Enterprise security monitoring for ACME Corporation',
    'enterprise',
    'enterprise',
    'active',
    'acme.com',
    'Manufacturing',
    'US',
    ARRAY['soc2', 'iso27001', 'nist'],
    'confidential',
    'billing@acme.com',
    '2024-01-01 00:00:00+00',
    '2025-01-01 00:00:00+00',
    jsonb_build_object(
        'max_users', 500,
        'max_devices', 5000,
        'max_alerts_per_month', 100000,
        'storage_quota_gb', 1000,
        'api_calls_per_minute', 10000,
        'retention_days', 365
    ),
    jsonb_build_object(
        'allowed_ip_ranges', ARRAY['192.168.0.0/16', '10.0.0.0/8'],
        'require_vpn', false,
        'allowed_countries', ARRAY['US', 'CA']
    ),
    jsonb_build_object(
        'encryption_at_rest', true,
        'encryption_in_transit', true,
        'key_rotation_days', 90,
        'customer_managed_keys', false
    ),
    jsonb_build_object(
        'enabled', true,
        'frequency_hours', 24,
        'retention_days', 30,
        'cross_region', false
    ),
    jsonb_build_object(
        'sla_uptime_percent', 99.9,
        'response_time_ms', 500,
        'alert_channels', ARRAY['email', 'slack'],
        'custom_dashboards', true
    ),
    NOW(),
    NOW()
),
(
    '234e5678-e89b-12d3-a456-426614174001',
    'defense-agency',
    'Federal Defense Agency',
    'Government security monitoring with classified data handling',
    'government',
    'government',
    'active',
    'defense.gov',
    'Government',
    'US',
    ARRAY['fisma', 'fedramp_high', 'dod_8570'],
    'secret',
    'contracts@defense.gov',
    '2024-01-01 00:00:00+00',
    '2026-01-01 00:00:00+00',
    jsonb_build_object(
        'max_users', 1000,
        'max_devices', 20000,
        'max_alerts_per_month', 500000,
        'storage_quota_gb', 5000,
        'api_calls_per_minute', 50000,
        'retention_days', 2555
    ),
    jsonb_build_object(
        'allowed_ip_ranges', ARRAY['172.16.0.0/12'],
        'require_vpn', true,
        'allowed_countries', ARRAY['US'],
        'require_cac_auth', true
    ),
    jsonb_build_object(
        'encryption_at_rest', true,
        'encryption_in_transit', true,
        'key_rotation_days', 30,
        'customer_managed_keys', true,
        'fips_140_2_level', 3
    ),
    jsonb_build_object(
        'enabled', true,
        'frequency_hours', 6,
        'retention_days', 90,
        'cross_region', true,
        'classification_level', 'secret'
    ),
    jsonb_build_object(
        'sla_uptime_percent', 99.95,
        'response_time_ms', 200,
        'alert_channels', ARRAY['secure_email', 'phone'],
        'custom_dashboards', true,
        'classification_banners', true
    ),
    NOW(),
    NOW()
),
(
    '345e6789-e89b-12d3-a456-426614174002',
    'security-msp',
    'CyberGuard MSP',
    'Managed Security Service Provider serving multiple clients',
    'msp',
    'enterprise',
    'active',
    'cyberguard-msp.com',
    'Cybersecurity Services',
    'US',
    ARRAY['soc2', 'iso27001', 'nist', 'cis'],
    'confidential',
    'billing@cyberguard-msp.com',
    '2024-01-01 00:00:00+00',
    '2025-12-31 00:00:00+00',
    jsonb_build_object(
        'max_users', 100,
        'max_devices', 50000,
        'max_alerts_per_month', 1000000,
        'storage_quota_gb', 10000,
        'api_calls_per_minute', 100000,
        'retention_days', 1095,
        'max_child_tenants', 50
    ),
    jsonb_build_object(
        'allowed_ip_ranges', ARRAY['0.0.0.0/0'],
        'require_vpn', false,
        'allowed_countries', ARRAY['US', 'CA', 'GB', 'AU']
    ),
    jsonb_build_object(
        'encryption_at_rest', true,
        'encryption_in_transit', true,
        'key_rotation_days', 60,
        'customer_managed_keys', true
    ),
    jsonb_build_object(
        'enabled', true,
        'frequency_hours', 12,
        'retention_days', 60,
        'cross_region', true
    ),
    jsonb_build_object(
        'sla_uptime_percent', 99.99,
        'response_time_ms', 300,
        'alert_channels', ARRAY['email', 'slack', 'webhook', 'sms'],
        'custom_dashboards', true,
        'white_label', true
    ),
    NOW(),
    NOW()
),
(
    '456e789a-e89b-12d3-a456-426614174003',
    'fintech-startup',
    'SecureFinance Inc',
    'Financial technology startup requiring compliance monitoring',
    'startup',
    'advanced',
    'active',
    'securefinance.io',
    'Financial Technology',
    'US',
    ARRAY['pci_dss', 'sox', 'ffiec'],
    'confidential',
    'compliance@securefinance.io',
    '2024-03-01 00:00:00+00',
    '2025-03-01 00:00:00+00',
    jsonb_build_object(
        'max_users', 100,
        'max_devices', 1000,
        'max_alerts_per_month', 10000,
        'storage_quota_gb', 100,
        'api_calls_per_minute', 1000,
        'retention_days', 2555
    ),
    jsonb_build_object(
        'allowed_ip_ranges', ARRAY['203.0.113.0/24'],
        'require_vpn', true,
        'allowed_countries', ARRAY['US']
    ),
    jsonb_build_object(
        'encryption_at_rest', true,
        'encryption_in_transit', true,
        'key_rotation_days', 90,
        'customer_managed_keys', false
    ),
    jsonb_build_object(
        'enabled', true,
        'frequency_hours', 24,
        'retention_days', 30,
        'cross_region', false
    ),
    jsonb_build_object(
        'sla_uptime_percent', 99.5,
        'response_time_ms', 1000,
        'alert_channels', ARRAY['email', 'slack'],
        'custom_dashboards', false
    ),
    NOW(),
    NOW()
);

-- Create MSP tenant relationships (CyberGuard MSP manages ACME Corp)
INSERT INTO tenant_relationships (
    parent_tenant_id,
    child_tenant_id,
    relationship_type,
    permissions,
    status,
    created_at
) VALUES (
    '345e6789-e89b-12d3-a456-426614174002', -- CyberGuard MSP
    '123e4567-e89b-12d3-a456-426614174000', -- ACME Corp
    'msp_manages',
    ARRAY['read:alerts', 'read:devices', 'read:users', 'write:alerts', 'manage:security'],
    'active',
    NOW()
);

-- Create initial users for each tenant
INSERT INTO tenant_users (
    id,
    tenant_id,
    email,
    role,
    security_clearance,
    permissions,
    status,
    created_at,
    updated_at
) VALUES 
-- ACME Corp Admin
(
    '111e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-12d3-a456-426614174000',
    'admin@acme.com',
    'tenant_admin',
    'confidential',
    ARRAY['*:*'],
    'active',
    NOW(),
    NOW()
),
-- Defense Agency Admin
(
    '222e5678-e89b-12d3-a456-426614174001',
    '234e5678-e89b-12d3-a456-426614174001',
    'admin@defense.gov',
    'tenant_admin',
    'secret',
    ARRAY['*:*'],
    'active',
    NOW(),
    NOW()
),
-- MSP Super Admin
(
    '333e6789-e89b-12d3-a456-426614174002',
    '345e6789-e89b-12d3-a456-426614174002',
    'admin@cyberguard-msp.com',
    'msp_admin',
    'confidential',
    ARRAY['*:*', 'manage:tenants', 'manage:users'],
    'active',
    NOW(),
    NOW()
),
-- FinTech Startup Admin
(
    '444e789a-e89b-12d3-a456-426614174003',
    '456e789a-e89b-12d3-a456-426614174003',
    'admin@securefinance.io',
    'tenant_admin',
    'confidential',
    ARRAY['*:*'],
    'active',
    NOW(),
    NOW()
);

-- Create some sample devices for testing
INSERT INTO devices (
    id,
    tenant_id,
    name,
    type,
    ip_address,
    security_classification,
    status,
    created_at,
    updated_at
) VALUES 
-- ACME Corp devices
(
    'dev-123e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-12d3-a456-426614174000',
    'ACME-DC-01',
    'server',
    '192.168.1.10',
    'confidential',
    'active',
    NOW(),
    NOW()
),
(
    'dev-123e4567-e89b-12d3-a456-426614174001',
    '123e4567-e89b-12d3-a456-426614174000',
    'ACME-WS-01',
    'workstation',
    '192.168.1.100',
    'unclassified',
    'active',
    NOW(),
    NOW()
),
-- Defense Agency devices
(
    'dev-234e5678-e89b-12d3-a456-426614174000',
    '234e5678-e89b-12d3-a456-426614174001',
    'DOD-SERVER-01',
    'server',
    '172.16.1.10',
    'secret',
    'active',
    NOW(),
    NOW()
);

-- Create sample alerts for testing
INSERT INTO alerts (
    id,
    tenant_id,
    device_id,
    title,
    description,
    severity,
    security_classification,
    status,
    created_at,
    updated_at
) VALUES 
-- ACME Corp alert
(
    'alert-123e4567-e89b-12d3-a456-426614174000',
    '123e4567-e89b-12d3-a456-426614174000',
    'dev-123e4567-e89b-12d3-a456-426614174000',
    'Suspicious Network Activity',
    'Unusual outbound connections detected from server ACME-DC-01',
    'medium',
    'confidential',
    'open',
    NOW(),
    NOW()
),
-- Defense Agency alert
(
    'alert-234e5678-e89b-12d3-a456-426614174000',
    '234e5678-e89b-12d3-a456-426614174001',
    'dev-234e5678-e89b-12d3-a456-426614174000',
    'Classified Data Access Attempt',
    'Unauthorized access attempt to classified systems detected',
    'high',
    'secret',
    'open',
    NOW(),
    NOW()
);

-- Initialize session contexts for the seed users
-- ACME Corp Admin Session
SELECT set_tenant_context(
    '123e4567-e89b-12d3-a456-426614174000'::UUID,
    '111e4567-e89b-12d3-a456-426614174000'::UUID,
    'confidential'::security_clearance_level,
    ARRAY['*:*']
);

-- Defense Agency Admin Session  
SELECT set_tenant_context(
    '234e5678-e89b-12d3-a456-426614174001'::UUID,
    '222e5678-e89b-12d3-a456-426614174001'::UUID,
    'secret'::security_clearance_level,
    ARRAY['*:*']
);

-- MSP Admin Session
SELECT set_tenant_context(
    '345e6789-e89b-12d3-a456-426614174002'::UUID,
    '333e6789-e89b-12d3-a456-426614174002'::UUID,
    'confidential'::security_clearance_level,
    ARRAY['*:*', 'manage:tenants', 'manage:users']
);

-- Create audit logs for the initial setup
INSERT INTO audit_logs (
    id,
    tenant_id,
    user_id,
    action,
    resource_type,
    resource_id,
    details,
    security_classification,
    ip_address,
    user_agent,
    created_at
) VALUES 
(
    'audit-' || gen_random_uuid(),
    '123e4567-e89b-12d3-a456-426614174000',
    '111e4567-e89b-12d3-a456-426614174000',
    'tenant_initialized',
    'tenant',
    '123e4567-e89b-12d3-a456-426614174000',
    jsonb_build_object('event', 'Initial tenant setup completed', 'method', 'seed_data'),
    'unclassified',
    '127.0.0.1',
    'Database Seed Script',
    NOW()
),
(
    'audit-' || gen_random_uuid(),
    '234e5678-e89b-12d3-a456-426614174001',
    '222e5678-e89b-12d3-a456-426614174001',
    'tenant_initialized',
    'tenant',
    '234e5678-e89b-12d3-a456-426614174001',
    jsonb_build_object('event', 'Initial government tenant setup completed', 'method', 'seed_data'),
    'unclassified',
    '127.0.0.1',
    'Database Seed Script',
    NOW()
);

-- Verify RLS is working by testing cross-tenant access
DO $$
DECLARE
    acme_alert_count INTEGER;
    defense_alert_count INTEGER;
BEGIN
    -- Set ACME Corp context and count alerts
    PERFORM set_tenant_context(
        '123e4567-e89b-12d3-a456-426614174000'::UUID,
        '111e4567-e89b-12d3-a456-426614174000'::UUID,
        'confidential'::security_clearance_level,
        ARRAY['*:*']
    );
    
    SELECT COUNT(*) INTO acme_alert_count FROM alerts;
    
    -- Set Defense Agency context and count alerts
    PERFORM set_tenant_context(
        '234e5678-e89b-12d3-a456-426614174001'::UUID,
        '222e5678-e89b-12d3-a456-426614174001'::UUID,
        'secret'::security_clearance_level,
        ARRAY['*:*']
    );
    
    SELECT COUNT(*) INTO defense_alert_count FROM alerts;
    
    -- Log verification results
    RAISE NOTICE 'RLS Verification: ACME Corp sees % alerts, Defense Agency sees % alerts', 
        acme_alert_count, defense_alert_count;
    
    -- Each tenant should only see their own alert
    IF acme_alert_count != 1 OR defense_alert_count != 1 THEN
        RAISE EXCEPTION 'RLS verification failed: Cross-tenant data access detected';
    END IF;
    
    RAISE NOTICE 'RLS verification passed: Tenants are properly isolated';
END $$;

-- Create helpful views for development
CREATE OR REPLACE VIEW tenant_summary AS
SELECT 
    t.id,
    t.name,
    t.display_name,
    t.type,
    t.tier,
    t.status,
    t.max_security_clearance,
    (t.resource_quotas->>'max_users')::INTEGER as max_users,
    COUNT(DISTINCT u.id) as current_users,
    COUNT(DISTINCT d.id) as current_devices,
    COUNT(DISTINCT a.id) as open_alerts,
    t.created_at
FROM tenants t
LEFT JOIN tenant_users u ON t.id = u.tenant_id AND u.status = 'active'
LEFT JOIN devices d ON t.id = d.tenant_id AND d.status = 'active'
LEFT JOIN alerts a ON t.id = a.tenant_id AND a.status = 'open'
GROUP BY t.id, t.name, t.display_name, t.type, t.tier, t.status, 
         t.max_security_clearance, t.resource_quotas, t.created_at
ORDER BY t.created_at;

COMMENT ON VIEW tenant_summary IS 'Summary view of tenant statistics for development and monitoring';

-- Grant permissions to application role
GRANT SELECT ON tenant_summary TO application_role;

RAISE NOTICE 'Seed data creation completed successfully!';
RAISE NOTICE 'Created tenants: ACME Corp, Defense Agency, CyberGuard MSP, SecureFinance Inc';
RAISE NOTICE 'Use tenant_summary view to see tenant statistics';