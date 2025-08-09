-- Tenant Context and Access Logging Schema
-- Extends the RBAC schema for tenant context validation and access tracking

BEGIN;

-- Table to store tenant metadata and configuration
CREATE TABLE IF NOT EXISTS tenant_metadata (
  tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  tenant_type TEXT NOT NULL DEFAULT 'standard' CHECK (tenant_type IN ('enterprise', 'standard', 'trial')),
  tenant_tier TEXT NOT NULL DEFAULT 'basic' CHECK (tenant_tier IN ('basic', 'premium', 'enterprise')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'trial_expired')),
  max_users INTEGER,
  features JSONB NOT NULL DEFAULT '[]'::JSONB,
  data_residency TEXT, -- e.g., 'us-east-1', 'eu-west-1'
  compliance_frameworks TEXT[] DEFAULT '{}', -- e.g., GDPR, HIPAA, SOC2
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Table to track user access patterns for audit and analytics
CREATE TABLE IF NOT EXISTS user_access_log (
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
  first_access_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_access_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  access_count BIGINT NOT NULL DEFAULT 1,
  last_ip_address INET,
  last_user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, tenant_id)
);

-- Table to store detailed access events for security monitoring
CREATE TABLE IF NOT EXISTS tenant_access_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL CHECK (event_type IN ('login', 'access', 'logout', 'denied', 'suspended')),
  endpoint_path TEXT,
  http_method TEXT,
  ip_address INET NOT NULL,
  user_agent TEXT,
  success BOOLEAN NOT NULL DEFAULT true,
  error_code TEXT,
  error_message TEXT,
  session_id TEXT,
  request_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_tenant_metadata_status ON tenant_metadata(status);
CREATE INDEX IF NOT EXISTS idx_tenant_metadata_type ON tenant_metadata(tenant_type);

CREATE INDEX IF NOT EXISTS idx_user_access_log_tenant ON user_access_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_access_log_user ON user_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_user_access_log_last_access ON user_access_log(last_access_at);
CREATE INDEX IF NOT EXISTS idx_user_access_log_status ON user_access_log(status);

CREATE INDEX IF NOT EXISTS idx_tenant_access_events_user_tenant ON tenant_access_events(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_access_events_created_at ON tenant_access_events(created_at);
CREATE INDEX IF NOT EXISTS idx_tenant_access_events_event_type ON tenant_access_events(event_type);
CREATE INDEX IF NOT EXISTS idx_tenant_access_events_success ON tenant_access_events(success);

-- Enable RLS on new tables
ALTER TABLE tenant_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_access_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_access_events ENABLE ROW LEVEL SECURITY;

-- RLS Policies for tenant isolation
CREATE POLICY tenant_metadata_isolation ON tenant_metadata
  USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY user_access_log_isolation ON user_access_log
  USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_access_events_isolation ON tenant_access_events
  USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Function to update last access time efficiently
CREATE OR REPLACE FUNCTION update_user_access(
  p_user_id UUID,
  p_tenant_id UUID,
  p_ip_address INET DEFAULT NULL,
  p_user_agent TEXT DEFAULT NULL
) RETURNS VOID AS $$
BEGIN
  INSERT INTO user_access_log (
    user_id, tenant_id, last_access_at, access_count, 
    last_ip_address, last_user_agent, updated_at
  )
  VALUES (
    p_user_id, p_tenant_id, NOW(), 1,
    p_ip_address, p_user_agent, NOW()
  )
  ON CONFLICT (user_id, tenant_id) DO UPDATE SET
    last_access_at = NOW(),
    access_count = user_access_log.access_count + 1,
    last_ip_address = COALESCE(p_ip_address, user_access_log.last_ip_address),
    last_user_agent = COALESCE(p_user_agent, user_access_log.last_user_agent),
    updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to log tenant access events
CREATE OR REPLACE FUNCTION log_tenant_access_event(
  p_user_id UUID,
  p_tenant_id UUID,
  p_event_type TEXT,
  p_endpoint_path TEXT DEFAULT NULL,
  p_http_method TEXT DEFAULT NULL,
  p_ip_address INET DEFAULT NULL,
  p_user_agent TEXT DEFAULT NULL,
  p_success BOOLEAN DEFAULT true,
  p_error_code TEXT DEFAULT NULL,
  p_error_message TEXT DEFAULT NULL,
  p_session_id TEXT DEFAULT NULL,
  p_request_id TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
  event_id UUID;
BEGIN
  INSERT INTO tenant_access_events (
    user_id, tenant_id, event_type, endpoint_path, http_method,
    ip_address, user_agent, success, error_code, error_message,
    session_id, request_id
  )
  VALUES (
    p_user_id, p_tenant_id, p_event_type, p_endpoint_path, p_http_method,
    p_ip_address, p_user_agent, p_success, p_error_code, p_error_message,
    p_session_id, p_request_id
  )
  RETURNING id INTO event_id;
  
  RETURN event_id;
END;
$$ LANGUAGE plpgsql;

-- Function to check tenant access with enhanced validation
CREATE OR REPLACE FUNCTION validate_tenant_access(
  p_user_id UUID,
  p_tenant_id UUID
) RETURNS JSONB AS $$
DECLARE
  result JSONB;
  tenant_info RECORD;
  user_association RECORD;
BEGIN
  -- Get tenant information
  SELECT 
    t.id, t.name, 
    tm.tenant_type, tm.tenant_tier, tm.status,
    tm.max_users, tm.features, tm.data_residency,
    tm.compliance_frameworks
  INTO tenant_info
  FROM tenants t
  LEFT JOIN tenant_metadata tm ON t.id = tm.tenant_id
  WHERE t.id = p_tenant_id;

  -- Check if tenant exists and is active
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'success', false,
      'error_code', 'TENANT_NOT_FOUND',
      'error_message', 'Tenant not found or inactive'
    );
  END IF;

  IF tenant_info.status != 'active' THEN
    RETURN jsonb_build_object(
      'success', false,
      'error_code', 'TENANT_SUSPENDED',
      'error_message', 'Tenant is suspended or inactive'
    );
  END IF;

  -- Get user-tenant association with permissions
  SELECT 
    ur.user_id, ur.tenant_id, ur.created_at as joined_at,
    r.name as role,
    array_agg(DISTINCT p.resource_namespace || ':' || p.resource || ':' || p.action) as permissions,
    COALESCE(ual.status, 'active') as access_status,
    ual.last_access_at
  INTO user_association
  FROM user_roles ur
  JOIN roles r ON ur.role_id = r.id
  JOIN role_permissions rp ON r.id = rp.role_id AND rp.tenant_id = p_tenant_id
  JOIN permissions p ON rp.permission_id = p.id
  LEFT JOIN user_access_log ual ON ur.user_id = ual.user_id AND ur.tenant_id = ual.tenant_id
  WHERE ur.user_id = p_user_id AND ur.tenant_id = p_tenant_id
  GROUP BY ur.user_id, ur.tenant_id, ur.created_at, r.name, ual.status, ual.last_access_at;

  -- Check if user has access to tenant
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'success', false,
      'error_code', 'TENANT_ACCESS_DENIED',
      'error_message', 'User not authorized to access this tenant'
    );
  END IF;

  -- Check if user access is suspended
  IF user_association.access_status = 'suspended' THEN
    RETURN jsonb_build_object(
      'success', false,
      'error_code', 'USER_ACCESS_SUSPENDED',
      'error_message', 'User access to tenant is suspended'
    );
  END IF;

  -- Build successful response
  result := jsonb_build_object(
    'success', true,
    'tenant_context', jsonb_build_object(
      'tenant_id', tenant_info.id,
      'tenant_name', tenant_info.name,
      'tenant_type', COALESCE(tenant_info.tenant_type, 'standard'),
      'tenant_tier', COALESCE(tenant_info.tenant_tier, 'basic'),
      'status', COALESCE(tenant_info.status, 'active'),
      'max_users', tenant_info.max_users,
      'features', COALESCE(tenant_info.features, '[]'::jsonb),
      'data_residency', tenant_info.data_residency,
      'compliance_frameworks', COALESCE(tenant_info.compliance_frameworks, '{}')
    ),
    'user_association', jsonb_build_object(
      'user_id', user_association.user_id,
      'tenant_id', user_association.tenant_id,
      'role', user_association.role,
      'permissions', user_association.permissions,
      'status', user_association.access_status,
      'joined_at', user_association.joined_at,
      'last_access_at', user_association.last_access_at
    )
  );

  RETURN result;
END;
$$ LANGUAGE plpgsql STABLE;

-- Trigger to automatically update updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_tenant_metadata_updated_at
  BEFORE UPDATE ON tenant_metadata
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_access_log_updated_at
  BEFORE UPDATE ON user_access_log
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Seed some initial tenant metadata
INSERT INTO tenant_metadata (tenant_id, tenant_type, tenant_tier, status, features, compliance_frameworks)
SELECT 
  t.id,
  'enterprise',
  'premium', 
  'active',
  '["advanced_analytics", "custom_policies", "multi_region", "soc_automation"]'::jsonb,
  ARRAY['SOC2', 'GDPR', 'HIPAA']
FROM tenants t
WHERE NOT EXISTS (
  SELECT 1 FROM tenant_metadata tm WHERE tm.tenant_id = t.id
);

COMMIT;

-- Add helpful comments
COMMENT ON TABLE tenant_metadata IS 'Extended tenant configuration and metadata';
COMMENT ON TABLE user_access_log IS 'Tracks user access patterns for each tenant';
COMMENT ON TABLE tenant_access_events IS 'Detailed security event log for tenant access';

COMMENT ON FUNCTION update_user_access(UUID, UUID, INET, TEXT) IS 'Efficiently updates user access tracking';
COMMENT ON FUNCTION log_tenant_access_event IS 'Logs detailed tenant access events for security monitoring';
COMMENT ON FUNCTION validate_tenant_access(UUID, UUID) IS 'Comprehensive tenant access validation with context';