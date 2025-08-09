-- iSECTECH API Authorization Matrix - Permissions Seed Data
-- This script populates the permissions table with all defined permissions
-- from the authorization matrix

BEGIN;

-- Clear existing permissions (be careful in production!)
-- DELETE FROM role_permissions;
-- DELETE FROM permissions;

-- Authentication permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'auth', 'login', 'execute', 'User authentication with tenant context'),
  (gen_random_uuid(), 'auth', 'logout', 'execute', 'Secure session cleanup'),
  (gen_random_uuid(), 'auth', 'verify', 'execute', 'Session validation'),
  (gen_random_uuid(), 'auth', 'token', 'refresh', 'Token refresh'),
  (gen_random_uuid(), 'auth', 'session', 'validate', 'Session validation'),
  (gen_random_uuid(), 'auth', 'password', 'reset:request', 'Password reset request'),
  (gen_random_uuid(), 'auth', 'password', 'reset:complete', 'Complete password reset'),
  (gen_random_uuid(), 'auth', 'password', 'validate', 'Password strength validation'),
  (gen_random_uuid(), 'auth', 'password', 'change', 'Change user password'),
  (gen_random_uuid(), 'auth', 'profile', 'read', 'Get user profile information'),
  (gen_random_uuid(), 'auth', 'sessions', 'read', 'List user sessions'),
  (gen_random_uuid(), 'auth', 'sessions', 'delete', 'Terminate user sessions'),
  (gen_random_uuid(), 'auth', 'mfa', 'verify', 'MFA verification'),
  (gen_random_uuid(), 'auth', 'mfa:devices', 'read', 'List MFA devices'),
  (gen_random_uuid(), 'auth', 'mfa:devices', 'create', 'Enroll MFA device');

-- Tenant management permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'tenants', 'tenants', 'list', 'List accessible tenants'),
  (gen_random_uuid(), 'tenants', 'tenants', 'create', 'Create new tenant'),
  (gen_random_uuid(), 'tenants', 'tenants', 'read', 'Get tenant details'),
  (gen_random_uuid(), 'tenants', 'tenants', 'update', 'Update tenant information'),
  (gen_random_uuid(), 'tenants', 'tenants', 'delete', 'Delete tenant');

-- System metrics permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'metrics', 'metrics', 'read', 'Access system metrics');

-- Notification permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'notifications', 'notifications', 'read', 'List notifications'),
  (gen_random_uuid(), 'notifications', 'notifications', 'create', 'Create notification'),
  (gen_random_uuid(), 'notifications', 'notifications', 'update', 'Update notification'),
  (gen_random_uuid(), 'notifications', 'notifications', 'delete', 'Delete notification'),
  (gen_random_uuid(), 'notifications', 'notifications', 'subscribe', 'Subscribe to notifications'),
  (gen_random_uuid(), 'notifications', 'notifications', 'unsubscribe', 'Unsubscribe from notifications'),
  (gen_random_uuid(), 'notifications', 'preferences', 'read', 'Get notification preferences'),
  (gen_random_uuid(), 'notifications', 'preferences', 'update', 'Update notification preferences'),
  (gen_random_uuid(), 'notifications', 'templates', 'read', 'List notification templates'),
  (gen_random_uuid(), 'notifications', 'templates', 'create', 'Create notification template'),
  (gen_random_uuid(), 'notifications', 'templates', 'render', 'Render notification template'),
  (gen_random_uuid(), 'notifications', 'analytics', 'read', 'Notification analytics'),
  (gen_random_uuid(), 'notifications', 'schedule', 'read', 'Get scheduled notifications'),
  (gen_random_uuid(), 'notifications', 'schedule', 'create', 'Schedule notification'),
  (gen_random_uuid(), 'notifications', 'webhooks', 'manage', 'Webhook management'),
  (gen_random_uuid(), 'notifications', 'notifications', 'test', 'Test notification delivery');

-- Trust score permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'trust-score', 'trust-score', 'read', 'Get trust score'),
  (gen_random_uuid(), 'trust-score', 'trust-score', 'update', 'Update trust score'),
  (gen_random_uuid(), 'trust-score', 'analytics', 'read', 'Trust score analytics'),
  (gen_random_uuid(), 'trust-score', 'websocket', 'connect', 'WebSocket connection for real-time trust scores');

-- Compliance permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'compliance', 'status', 'read', 'Get compliance status'),
  (gen_random_uuid(), 'compliance', 'violations', 'read', 'List compliance violations'),
  (gen_random_uuid(), 'compliance', 'violations', 'create', 'Create violation record'),
  (gen_random_uuid(), 'compliance', 'violations', 'resolve', 'Resolve compliance violation'),
  (gen_random_uuid(), 'compliance', 'audit', 'read', 'Access audit trail'),
  (gen_random_uuid(), 'compliance', 'assessments', 'read', 'List compliance assessments'),
  (gen_random_uuid(), 'compliance', 'assessments', 'create', 'Create compliance assessment');

-- Onboarding permissions  
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'onboarding', 'onboarding', 'read', 'List onboarding flows'),
  (gen_random_uuid(), 'onboarding', 'onboarding', 'create', 'Create onboarding flow'),
  (gen_random_uuid(), 'onboarding', 'onboarding', 'update', 'Update onboarding flow'),
  (gen_random_uuid(), 'onboarding', 'analytics', 'read', 'Onboarding analytics');

-- Policy engine permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'policy', 'policy', 'evaluate', 'Evaluate policy decision'),
  (gen_random_uuid(), 'policy', 'policy', 'health', 'Policy service health check'),
  (gen_random_uuid(), 'policy', 'evaluate', 'batch', 'Batch policy evaluation'),
  (gen_random_uuid(), 'policy', 'logs', 'read', 'Access policy evaluation logs'),
  (gen_random_uuid(), 'policy', 'bundles', 'read', 'List policy bundles'),
  (gen_random_uuid(), 'policy', 'bundles', 'create', 'Create policy bundle'),
  (gen_random_uuid(), 'policy', 'bundles', 'activate', 'Activate policy bundle'),
  (gen_random_uuid(), 'policy', 'bundles', 'rollback', 'Rollback policy bundle');

-- Analytics permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'analytics', 'performance', 'read', 'Performance metrics'),
  (gen_random_uuid(), 'analytics', 'performance', 'write', 'Record performance data');

-- Administrative user management permissions  
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'users', 'admin', 'list', 'List all users'),
  (gen_random_uuid(), 'users', 'admin', 'create', 'Create user'),
  (gen_random_uuid(), 'users', 'admin', 'read', 'Get user details'),
  (gen_random_uuid(), 'users', 'admin', 'update', 'Update user'),
  (gen_random_uuid(), 'users', 'admin', 'delete', 'Delete user'),
  (gen_random_uuid(), 'users', 'admin', 'lock', 'Lock user account'),
  (gen_random_uuid(), 'users', 'admin', 'unlock', 'Unlock user account'),
  (gen_random_uuid(), 'users', 'admin:mfa', 'reset', 'Reset user MFA');

-- Administrative session management permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'sessions', 'admin', 'list', 'List all sessions'),
  (gen_random_uuid(), 'sessions', 'admin', 'delete', 'Terminate any session'),
  (gen_random_uuid(), 'sessions', 'admin:delete', 'user', 'Terminate all user sessions');

-- Administrative audit permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'audit', 'admin', 'read', 'Access audit events'),
  (gen_random_uuid(), 'audit', 'admin', 'metrics', 'Audit metrics');

-- System administration permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'system', 'admin', 'health', 'System health status'),
  (gen_random_uuid(), 'system', 'admin', 'maintenance', 'Trigger maintenance mode');

-- Security officer permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'security', 'alerts', 'read', 'Security alerts'),
  (gen_random_uuid(), 'security', 'threats', 'read', 'Threat intelligence'),
  (gen_random_uuid(), 'security', 'incidents', 'create', 'Create security incident'),
  (gen_random_uuid(), 'security', 'audit', 'export', 'Export audit logs'),
  (gen_random_uuid(), 'security', 'compliance', 'report', 'Generate compliance report');

-- Asset discovery and management permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'assets', 'discovery', 'start', 'Start asset discovery operation'),
  (gen_random_uuid(), 'assets', 'discovery', 'read', 'Get discovery status'),
  (gen_random_uuid(), 'assets', 'discovery', 'cancel', 'Cancel discovery operation'),
  (gen_random_uuid(), 'assets', 'assets', 'read', 'List and view assets'),
  (gen_random_uuid(), 'assets', 'assets', 'create', 'Create asset'),
  (gen_random_uuid(), 'assets', 'assets', 'update', 'Update asset'),
  (gen_random_uuid(), 'assets', 'assets', 'delete', 'Delete asset'),
  (gen_random_uuid(), 'assets', 'assets', 'search', 'Search assets'),
  (gen_random_uuid(), 'assets', 'aggregation', 'read', 'Asset aggregation statistics'),
  (gen_random_uuid(), 'assets', 'topology', 'read', 'Network topology');

-- Event processing permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'events', 'events', 'process', 'Process security events'),
  (gen_random_uuid(), 'events', 'events', 'read', 'List and view security events');

-- Threat detection permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'threats', 'threats', 'analyze', 'Analyze threat data'),
  (gen_random_uuid(), 'threats', 'threats', 'read', 'List and view threats'),
  (gen_random_uuid(), 'threats', 'threats', 'mitigate', 'Mitigate threats');

-- Mobile notification permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'mobile', 'notifications', 'send', 'Send mobile notification'),
  (gen_random_uuid(), 'mobile', 'notifications', 'read', 'List mobile notifications'),
  (gen_random_uuid(), 'mobile', 'notifications', 'batch', 'Batch send notifications'),
  (gen_random_uuid(), 'mobile', 'notifications', 'status', 'Check delivery status');

-- Vulnerability scanning permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'vulnerabilities', 'scan', 'start', 'Start vulnerability scan'),
  (gen_random_uuid(), 'vulnerabilities', 'scan', 'read', 'Get scan results'),
  (gen_random_uuid(), 'vulnerabilities', 'vulnerabilities', 'read', 'List vulnerabilities'),
  (gen_random_uuid(), 'vulnerabilities', 'vulnerabilities', 'remediate', 'Remediate vulnerability');

-- Security agent permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'agents', 'agents', 'register', 'Register security agent'),
  (gen_random_uuid(), 'agents', 'agents', 'read', 'List security agents'),
  (gen_random_uuid(), 'agents', 'agents', 'command', 'Send agent commands'),
  (gen_random_uuid(), 'agents', 'telemetry', 'read', 'Get agent telemetry');

-- Billing permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'billing', 'invoices', 'read', 'List invoices'),
  (gen_random_uuid(), 'billing', 'subscriptions', 'read', 'Get subscriptions'),
  (gen_random_uuid(), 'billing', 'payment-methods', 'create', 'Add payment method'),
  (gen_random_uuid(), 'billing', 'usage', 'read', 'Get usage metrics');

-- Kong API Gateway permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'kong', 'admin', 'status', 'Kong status'),
  (gen_random_uuid(), 'kong', 'admin:services', 'read', 'List Kong services'),
  (gen_random_uuid(), 'kong', 'admin:services', 'create', 'Create Kong service'),
  (gen_random_uuid(), 'kong', 'admin:routes', 'read', 'List Kong routes'),
  (gen_random_uuid(), 'kong', 'admin:routes', 'create', 'Create Kong route'),
  (gen_random_uuid(), 'kong', 'admin:plugins', 'read', 'List Kong plugins'),
  (gen_random_uuid(), 'kong', 'admin:plugins', 'create', 'Create Kong plugin');

-- Traffic management permissions
INSERT INTO permissions (id, resource_namespace, resource, action, description) VALUES
  (gen_random_uuid(), 'traffic', 'status', 'read', 'Traffic status'),
  (gen_random_uuid(), 'traffic', 'throttle', 'apply', 'Apply throttling'),
  (gen_random_uuid(), 'rate-limiting', 'status', 'read', 'Rate limiting status');

COMMIT;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_permissions_lookup ON permissions(resource_namespace, resource, action);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_namespace ON permissions(resource_namespace);

-- Add comments for documentation
COMMENT ON TABLE permissions IS 'Defines all available permissions in the iSECTECH authorization system';
COMMENT ON COLUMN permissions.resource_namespace IS 'High-level permission category (e.g., auth, assets, notifications)';
COMMENT ON COLUMN permissions.resource IS 'Specific resource within the namespace';
COMMENT ON COLUMN permissions.action IS 'Action that can be performed on the resource';

-- Verify the data was inserted correctly
DO $$
DECLARE
    permission_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO permission_count FROM permissions;
    RAISE NOTICE 'Inserted % permissions into the permissions table', permission_count;
    
    -- Log count by namespace
    FOR permission_count IN 
        SELECT resource_namespace, COUNT(*) as cnt 
        FROM permissions 
        GROUP BY resource_namespace 
        ORDER BY resource_namespace
    LOOP
        RAISE NOTICE 'Namespace: %, Count: %', permission_count.resource_namespace, permission_count.cnt;
    END LOOP;
END $$;