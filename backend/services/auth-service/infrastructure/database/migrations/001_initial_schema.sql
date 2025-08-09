-- Migration: 001_initial_schema.sql
-- Description: Initial database schema for iSECTECH Authentication Service
-- Created: 2025-01-01

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom types for security clearance levels
DO $$ BEGIN
    CREATE TYPE security_clearance_level AS ENUM (
        'UNCLASSIFIED',
        'CONFIDENTIAL', 
        'SECRET',
        'TOP_SECRET'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for user status
DO $$ BEGIN
    CREATE TYPE user_status AS ENUM (
        'ACTIVE',
        'INACTIVE',
        'SUSPENDED',
        'LOCKED',
        'PENDING'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for session status
DO $$ BEGIN
    CREATE TYPE session_status AS ENUM (
        'ACTIVE',
        'EXPIRED',
        'REVOKED',
        'SUSPENDED'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for session type
DO $$ BEGIN
    CREATE TYPE session_type AS ENUM (
        'WEB',
        'MOBILE',
        'API',
        'DESKTOP',
        'SSO'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for MFA device type
DO $$ BEGIN
    CREATE TYPE mfa_device_type AS ENUM (
        'TOTP',
        'SMS',
        'WEBAUTHN',
        'EMAIL',
        'BACKUP'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for MFA device status
DO $$ BEGIN
    CREATE TYPE mfa_device_status AS ENUM (
        'ACTIVE',
        'INACTIVE',
        'REVOKED',
        'PENDING'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for role type
DO $$ BEGIN
    CREATE TYPE role_type AS ENUM (
        'SYSTEM',
        'CUSTOM',
        'TEMPORARY'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create custom types for role scope
DO $$ BEGIN
    CREATE TYPE role_scope AS ENUM (
        'GLOBAL',
        'TENANT',
        'RESOURCE',
        'OPERATION'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    status user_status NOT NULL DEFAULT 'PENDING',
    security_clearance security_clearance_level NOT NULL DEFAULT 'UNCLASSIFIED',
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enforced BOOLEAN NOT NULL DEFAULT FALSE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_attempt TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    
    -- Constraints
    CONSTRAINT users_username_tenant_unique UNIQUE (username, tenant_id),
    CONSTRAINT users_email_tenant_unique UNIQUE (email, tenant_id),
    CONSTRAINT users_failed_attempts_check CHECK (failed_attempts >= 0),
    CONSTRAINT users_password_changed_check CHECK (password_changed_at <= NOW())
);

-- Create indexes for users table
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_security_clearance ON users(security_clearance);
CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);

-- MFA devices table
CREATE TABLE IF NOT EXISTS mfa_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    device_type mfa_device_type NOT NULL,
    device_name VARCHAR(255) NOT NULL,
    status mfa_device_status NOT NULL DEFAULT 'PENDING',
    is_primary BOOLEAN NOT NULL DEFAULT FALSE,
    is_backup BOOLEAN NOT NULL DEFAULT FALSE,
    secret TEXT, -- Encrypted TOTP secret
    public_key BYTEA, -- WebAuthn public key
    credential_id BYTEA, -- WebAuthn credential ID
    counter INTEGER DEFAULT 0, -- WebAuthn counter
    phone_number VARCHAR(20), -- SMS phone number
    email_address VARCHAR(255), -- Email address
    backup_codes JSONB, -- Encrypted backup codes
    used_backup_codes JSONB, -- Used backup codes
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT mfa_devices_failed_attempts_check CHECK (failed_attempts >= 0),
    CONSTRAINT mfa_devices_counter_check CHECK (counter >= 0),
    CONSTRAINT mfa_devices_user_name_unique UNIQUE (user_id, device_name, tenant_id)
);

-- Create indexes for mfa_devices table
CREATE INDEX IF NOT EXISTS idx_mfa_devices_user_id ON mfa_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_tenant_id ON mfa_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_device_type ON mfa_devices(device_type);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_status ON mfa_devices(status);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_is_primary ON mfa_devices(is_primary);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_expires_at ON mfa_devices(expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_devices_created_at ON mfa_devices(created_at);

-- Roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    description TEXT,
    role_type role_type NOT NULL DEFAULT 'CUSTOM',
    scope role_scope NOT NULL DEFAULT 'TENANT',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    required_clearance security_clearance_level NOT NULL DEFAULT 'UNCLASSIFIED',
    max_session_duration INTERVAL,
    allow_concurrent_sessions BOOLEAN NOT NULL DEFAULT TRUE,
    ip_restrictions JSONB DEFAULT '[]',
    time_restrictions JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    updated_by UUID NOT NULL,
    expires_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT roles_name_tenant_unique UNIQUE (name, tenant_id)
);

-- Create indexes for roles table
CREATE INDEX IF NOT EXISTS idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_role_type ON roles(role_type);
CREATE INDEX IF NOT EXISTS idx_roles_scope ON roles(scope);
CREATE INDEX IF NOT EXISTS idx_roles_is_active ON roles(is_active);
CREATE INDEX IF NOT EXISTS idx_roles_required_clearance ON roles(required_clearance);

-- Permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    scope VARCHAR(255) NOT NULL DEFAULT 'tenant',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT permissions_resource_action_unique UNIQUE (resource, action, scope)
);

-- Create indexes for permissions table
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);
CREATE INDEX IF NOT EXISTS idx_permissions_action ON permissions(action);
CREATE INDEX IF NOT EXISTS idx_permissions_scope ON permissions(scope);

-- Role permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (role_id, permission_id)
);

-- User roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    assigned_by UUID NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT user_roles_user_role_unique UNIQUE (user_id, role_id, tenant_id)
);

-- Create indexes for user_roles table
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_id ON user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_expires_at ON user_roles(expires_at);
CREATE INDEX IF NOT EXISTS idx_user_roles_is_active ON user_roles(is_active);

-- Sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    refresh_token VARCHAR(255) NOT NULL UNIQUE,
    status session_status NOT NULL DEFAULT 'ACTIVE',
    session_type session_type NOT NULL DEFAULT 'WEB',
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    location VARCHAR(255),
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_verified_at TIMESTAMPTZ,
    security_clearance security_clearance_level NOT NULL DEFAULT 'UNCLASSIFIED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    max_inactivity_minutes INTEGER DEFAULT 30,
    require_mfa_reauth BOOLEAN NOT NULL DEFAULT FALSE,
    allowed_resources JSONB DEFAULT '[]',
    denied_resources JSONB DEFAULT '[]',
    session_data JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT sessions_max_inactivity_check CHECK (max_inactivity_minutes >= 0)
);

-- Create indexes for sessions table
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_session_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token ON sessions(refresh_token);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity_at ON sessions(last_activity_at);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_address ON sessions(ip_address);

-- Authentication attempts audit table
CREATE TABLE IF NOT EXISTS authentication_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    tenant_id UUID NOT NULL,
    username VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    user_agent TEXT,
    attempt_type VARCHAR(50) NOT NULL, -- LOGIN, MFA, PASSWORD_RESET
    success BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason TEXT,
    mfa_required BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    security_events JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score DOUBLE PRECISION DEFAULT 0.0,
    risk_factors JSONB DEFAULT '[]',
    requires_review BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT auth_attempts_risk_score_check CHECK (risk_score >= 0.0 AND risk_score <= 10.0)
);

-- Create indexes for authentication_attempts table
CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_id ON authentication_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_tenant_id ON authentication_attempts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_username ON authentication_attempts(username);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_address ON authentication_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_attempt_type ON authentication_attempts(attempt_type);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_success ON authentication_attempts(success);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_created_at ON authentication_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_requires_review ON authentication_attempts(requires_review);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_risk_score ON authentication_attempts(risk_score);

-- MFA audit events table
CREATE TABLE IF NOT EXISTS mfa_audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    device_id UUID,
    device_type mfa_device_type NOT NULL,
    action VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason TEXT,
    ip_address INET,
    user_agent TEXT,
    risk VARCHAR(20) DEFAULT 'LOW',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'
);

-- Create indexes for mfa_audit_events table
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_user_id ON mfa_audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_tenant_id ON mfa_audit_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_device_id ON mfa_audit_events(device_id);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_device_type ON mfa_audit_events(device_type);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_action ON mfa_audit_events(action);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_success ON mfa_audit_events(success);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_created_at ON mfa_audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_mfa_audit_events_risk ON mfa_audit_events(risk);

-- Security events table
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'LOW',
    description TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    risk_score DOUBLE PRECISION DEFAULT 0.0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT security_events_risk_score_check CHECK (risk_score >= 0.0 AND risk_score <= 10.0),
    CONSTRAINT security_events_severity_check CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
);

-- Create indexes for security_events table
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_id ON security_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_risk_score ON security_events(risk_score);

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT password_reset_tokens_expires_check CHECK (expires_at > created_at)
);

-- Create indexes for password_reset_tokens table
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token ON password_reset_tokens(token);
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);

-- Email verification tokens table
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    ip_address INET NOT NULL,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT email_verification_tokens_expires_check CHECK (expires_at > created_at)
);

-- Create indexes for email_verification_tokens table
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_token ON email_verification_tokens(token);
CREATE INDEX IF NOT EXISTS idx_email_verification_tokens_expires_at ON email_verification_tokens(expires_at);

-- Add foreign key constraints
ALTER TABLE mfa_devices 
ADD CONSTRAINT fk_mfa_devices_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE user_roles 
ADD CONSTRAINT fk_user_roles_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE sessions 
ADD CONSTRAINT fk_sessions_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE authentication_attempts 
ADD CONSTRAINT fk_auth_attempts_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE mfa_audit_events 
ADD CONSTRAINT fk_mfa_audit_events_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE mfa_audit_events 
ADD CONSTRAINT fk_mfa_audit_events_device_id 
FOREIGN KEY (device_id) REFERENCES mfa_devices(id) ON DELETE SET NULL;

ALTER TABLE security_events 
ADD CONSTRAINT fk_security_events_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE password_reset_tokens 
ADD CONSTRAINT fk_password_reset_tokens_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE email_verification_tokens 
ADD CONSTRAINT fk_email_verification_tokens_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Create functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_mfa_devices_updated_at BEFORE UPDATE ON mfa_devices 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_roles_updated_at BEFORE UPDATE ON user_roles 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sessions_updated_at BEFORE UPDATE ON sessions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default system permissions
INSERT INTO permissions (id, name, description, resource, action, scope) VALUES 
    ('00000000-0000-0000-0000-000000000001', 'system:admin', 'Full system administration', '*', '*', 'global'),
    ('00000000-0000-0000-0000-000000000002', 'tenant:admin', 'Full tenant administration', '*', '*', 'tenant'),
    ('00000000-0000-0000-0000-000000000003', 'user:read', 'Read user information', 'user', 'read', 'tenant'),
    ('00000000-0000-0000-0000-000000000004', 'user:write', 'Create and update users', 'user', 'write', 'tenant'),
    ('00000000-0000-0000-0000-000000000005', 'user:delete', 'Delete users', 'user', 'delete', 'tenant'),
    ('00000000-0000-0000-0000-000000000006', 'mfa:read', 'Read MFA devices', 'mfa', 'read', 'tenant'),
    ('00000000-0000-0000-0000-000000000007', 'mfa:write', 'Manage MFA devices', 'mfa', 'write', 'tenant'),
    ('00000000-0000-0000-0000-000000000008', 'role:read', 'Read roles and permissions', 'role', 'read', 'tenant'),
    ('00000000-0000-0000-0000-000000000009', 'role:write', 'Create and update roles', 'role', 'write', 'tenant'),
    ('00000000-0000-0000-0000-00000000000A', 'audit:read', 'Read audit logs', 'audit', 'read', 'tenant'),
    ('00000000-0000-0000-0000-00000000000B', 'session:read', 'Read session information', 'session', 'read', 'tenant'),
    ('00000000-0000-0000-0000-00000000000C', 'session:write', 'Manage user sessions', 'session', 'write', 'tenant'),
    ('00000000-0000-0000-0000-00000000000D', 'security:monitor', 'Monitor security events', 'security', 'monitor', 'tenant'),
    ('00000000-0000-0000-0000-00000000000E', 'security:respond', 'Respond to security incidents', 'security', 'respond', 'tenant'),
    ('00000000-0000-0000-0000-00000000000F', 'dashboard:view', 'View security dashboards', 'dashboard', 'view', 'tenant')
ON CONFLICT (id) DO NOTHING;

-- Insert default system roles
INSERT INTO roles (id, tenant_id, name, display_name, description, role_type, scope, required_clearance, created_by, updated_by) VALUES 
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000000', 'system:super-admin', 'Super Administrator', 'Full system access with all permissions', 'SYSTEM', 'GLOBAL', 'TOP_SECRET', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000000', 'system:tenant-admin', 'Tenant Administrator', 'Full administrative access within tenant', 'SYSTEM', 'TENANT', 'SECRET', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000000', 'system:security-analyst', 'Security Analyst', 'Access to security monitoring and analysis tools', 'SYSTEM', 'TENANT', 'CONFIDENTIAL', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000000', 'system:incident-responder', 'Incident Responder', 'Access to incident response and remediation tools', 'SYSTEM', 'TENANT', 'CONFIDENTIAL', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000000', 'system:readonly-user', 'Read-Only User', 'Read-only access to security dashboards and reports', 'SYSTEM', 'TENANT', 'UNCLASSIFIED', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000'),
    ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000000', 'system:api-user', 'API User', 'Programmatic access to iSECTECH APIs', 'SYSTEM', 'RESOURCE', 'UNCLASSIFIED', '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000000')
ON CONFLICT (id) DO NOTHING;

-- Assign permissions to system roles
INSERT INTO role_permissions (role_id, permission_id) VALUES 
    -- Super Admin gets all permissions
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001'),
    
    -- Tenant Admin gets tenant-level permissions
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000003'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000004'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000005'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000006'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000007'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000008'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000009'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000A'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000B'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000C'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000D'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000E'),
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-00000000000F'),
    
    -- Security Analyst gets monitoring and read permissions
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000003'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000006'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-000000000008'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000A'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000B'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000D'),
    ('00000000-0000-0000-0000-000000000003', '00000000-0000-0000-0000-00000000000F'),
    
    -- Incident Responder gets response permissions
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000003'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000006'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000008'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000A'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000B'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000C'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000D'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000E'),
    ('00000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-00000000000F'),
    
    -- Read-Only User gets read permissions only
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000003'),
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000006'),
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-000000000008'),
    ('00000000-0000-0000-0000-000000000005', '00000000-0000-0000-0000-00000000000F'),
    
    -- API User gets minimal permissions
    ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000003'),
    ('00000000-0000-0000-0000-000000000006', '00000000-0000-0000-0000-000000000006')
ON CONFLICT DO NOTHING;

-- Create a function to clean up expired sessions and tokens
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    temp_count INTEGER;
BEGIN
    -- Clean up expired sessions
    DELETE FROM sessions WHERE expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean up expired password reset tokens
    DELETE FROM password_reset_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean up expired email verification tokens
    DELETE FROM email_verification_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean up expired MFA devices
    DELETE FROM mfa_devices WHERE expires_at IS NOT NULL AND expires_at < NOW();
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Migration completed successfully
SELECT 'Migration 001_initial_schema.sql completed successfully' AS status;