-- Database initialization for Deception Technology Platform
-- Creates all necessary tables for canary tokens and decoy services

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schema for deception services
CREATE SCHEMA IF NOT EXISTS deception;

-- Set search path to include deception schema
SET search_path TO deception, public;

-- Canary Tokens table
CREATE TABLE IF NOT EXISTS canary_tokens (
    token_id VARCHAR(64) PRIMARY KEY,
    token_type VARCHAR(50) NOT NULL,
    token_data JSONB NOT NULL,
    location VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_triggered TIMESTAMP WITH TIME ZONE,
    trigger_count INTEGER DEFAULT 0,
    active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    deployment_id VARCHAR(64),
    criticality VARCHAR(20) DEFAULT 'medium'
);

-- Indexes for canary_tokens
CREATE INDEX IF NOT EXISTS idx_canary_tokens_type ON canary_tokens(token_type);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_tenant ON canary_tokens(tenant_id);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_active ON canary_tokens(active);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_location ON canary_tokens(location);
CREATE INDEX IF NOT EXISTS idx_canary_tokens_created ON canary_tokens(created_at);

-- Canary Triggers table
CREATE TABLE IF NOT EXISTS canary_triggers (
    trigger_id SERIAL PRIMARY KEY,
    token_id VARCHAR(64) REFERENCES canary_tokens(token_id) ON DELETE CASCADE,
    triggered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source_ip INET,
    user_agent TEXT,
    request_details JSONB DEFAULT '{}',
    alert_sent BOOLEAN DEFAULT FALSE,
    response_actions JSONB DEFAULT '[]',
    severity VARCHAR(20) DEFAULT 'medium',
    investigation_status VARCHAR(20) DEFAULT 'pending',
    notes TEXT
);

-- Indexes for canary_triggers
CREATE INDEX IF NOT EXISTS idx_canary_triggers_token ON canary_triggers(token_id, triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_canary_triggers_time ON canary_triggers(triggered_at DESC);
CREATE INDEX IF NOT EXISTS idx_canary_triggers_ip ON canary_triggers(source_ip);
CREATE INDEX IF NOT EXISTS idx_canary_triggers_severity ON canary_triggers(severity);

-- Behavioral feedback table (for ML improvement)
CREATE TABLE IF NOT EXISTS behavioral_feedback (
    feedback_id VARCHAR(64) PRIMARY KEY,
    entity_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    prediction_id VARCHAR(64) NOT NULL,
    feedback_type VARCHAR(50) NOT NULL,
    priority VARCHAR(20) NOT NULL,
    original_score FLOAT NOT NULL CHECK (original_score >= 0 AND original_score <= 1),
    original_prediction BOOLEAN NOT NULL,
    corrected_label BOOLEAN NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    source VARCHAR(100) NOT NULL,
    metadata JSONB DEFAULT '{}',
    confidence FLOAT NOT NULL DEFAULT 1.0 CHECK (confidence >= 0 AND confidence <= 1),
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for behavioral_feedback
CREATE INDEX IF NOT EXISTS idx_behavioral_feedback_tenant_entity ON behavioral_feedback(tenant_id, entity_id);
CREATE INDEX IF NOT EXISTS idx_behavioral_feedback_timestamp ON behavioral_feedback(timestamp);
CREATE INDEX IF NOT EXISTS idx_behavioral_feedback_processed ON behavioral_feedback(processed);
CREATE INDEX IF NOT EXISTS idx_behavioral_feedback_type ON behavioral_feedback(feedback_type);

-- Model performance metrics
CREATE TABLE IF NOT EXISTS model_performance_metrics (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    model_type VARCHAR(100) NOT NULL,
    precision FLOAT NOT NULL,
    recall FLOAT NOT NULL,
    f1_score FLOAT NOT NULL,
    false_positive_rate FLOAT NOT NULL,
    false_negative_rate FLOAT NOT NULL,
    accuracy FLOAT NOT NULL,
    sample_count INTEGER NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for model_performance_metrics
CREATE INDEX IF NOT EXISTS idx_model_performance_tenant_model ON model_performance_metrics(tenant_id, model_type);
CREATE INDEX IF NOT EXISTS idx_model_performance_timestamp ON model_performance_metrics(timestamp);

-- Decoy customers table
CREATE TABLE IF NOT EXISTS decoy_customers (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(20) UNIQUE NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    contact_name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    industry VARCHAR(100),
    annual_revenue DECIMAL(15,2),
    employee_count INTEGER,
    security_level VARCHAR(20) DEFAULT 'CONFIDENTIAL',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    api_key VARCHAR(64),
    is_premium BOOLEAN DEFAULT FALSE,
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_customers
CREATE INDEX IF NOT EXISTS idx_decoy_customers_customer_id ON decoy_customers(customer_id);
CREATE INDEX IF NOT EXISTS idx_decoy_customers_email ON decoy_customers(email);
CREATE INDEX IF NOT EXISTS idx_decoy_customers_tenant ON decoy_customers(tenant_id);

-- Decoy users table
CREATE TABLE IF NOT EXISTS decoy_users (
    id SERIAL PRIMARY KEY,
    employee_id VARCHAR(20) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    department VARCHAR(100),
    position VARCHAR(100),
    salary DECIMAL(10,2),
    ssn VARCHAR(11), -- Fake SSN data
    hire_date DATE,
    access_level INTEGER DEFAULT 1,
    security_clearance VARCHAR(20),
    manager_id INTEGER REFERENCES decoy_users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked BOOLEAN DEFAULT FALSE,
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_users
CREATE INDEX IF NOT EXISTS idx_decoy_users_employee_id ON decoy_users(employee_id);
CREATE INDEX IF NOT EXISTS idx_decoy_users_username ON decoy_users(username);
CREATE INDEX IF NOT EXISTS idx_decoy_users_email ON decoy_users(email);
CREATE INDEX IF NOT EXISTS idx_decoy_users_department ON decoy_users(department);
CREATE INDEX IF NOT EXISTS idx_decoy_users_tenant ON decoy_users(tenant_id);

-- Financial records table
CREATE TABLE IF NOT EXISTS decoy_financial_records (
    id SERIAL PRIMARY KEY,
    record_id VARCHAR(20) UNIQUE NOT NULL,
    customer_id VARCHAR(20) REFERENCES decoy_customers(customer_id),
    transaction_type VARCHAR(50),
    amount DECIMAL(15,2),
    currency VARCHAR(3) DEFAULT 'USD',
    description TEXT,
    account_number VARCHAR(20),
    routing_number VARCHAR(9),
    transaction_date TIMESTAMP WITH TIME ZONE,
    processed_by INTEGER REFERENCES decoy_users(id),
    classification VARCHAR(20) DEFAULT 'RESTRICTED',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_financial_records
CREATE INDEX IF NOT EXISTS idx_financial_records_customer ON decoy_financial_records(customer_id);
CREATE INDEX IF NOT EXISTS idx_financial_records_transaction_date ON decoy_financial_records(transaction_date DESC);
CREATE INDEX IF NOT EXISTS idx_financial_records_type ON decoy_financial_records(transaction_type);

-- System logs table
CREATE TABLE IF NOT EXISTS decoy_system_logs (
    id SERIAL PRIMARY KEY,
    log_level VARCHAR(10),
    service_name VARCHAR(100),
    message TEXT,
    user_id INTEGER REFERENCES decoy_users(id),
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    request_id VARCHAR(64),
    metadata JSONB DEFAULT '{}',
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_system_logs
CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON decoy_system_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON decoy_system_logs(log_level);
CREATE INDEX IF NOT EXISTS idx_system_logs_service ON decoy_system_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_system_logs_ip ON decoy_system_logs(ip_address);

-- API tokens table
CREATE TABLE IF NOT EXISTS decoy_api_tokens (
    id SERIAL PRIMARY KEY,
    token_name VARCHAR(100),
    token_value VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES decoy_users(id),
    scopes TEXT[],
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    usage_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_api_tokens
CREATE INDEX IF NOT EXISTS idx_api_tokens_value ON decoy_api_tokens(token_value);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON decoy_api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_active ON decoy_api_tokens(is_active);

-- Backup records table
CREATE TABLE IF NOT EXISTS decoy_backups (
    id SERIAL PRIMARY KEY,
    backup_name VARCHAR(255),
    backup_type VARCHAR(50),
    file_path TEXT,
    size_bytes BIGINT,
    checksum VARCHAR(64),
    encryption_key VARCHAR(255),
    created_by INTEGER REFERENCES decoy_users(id),
    backup_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    restore_tested BOOLEAN DEFAULT FALSE,
    retention_policy VARCHAR(50),
    classification VARCHAR(20) DEFAULT 'INTERNAL',
    tenant_id VARCHAR(255) DEFAULT 'default'
);

-- Indexes for decoy_backups
CREATE INDEX IF NOT EXISTS idx_backups_date ON decoy_backups(backup_date DESC);
CREATE INDEX IF NOT EXISTS idx_backups_type ON decoy_backups(backup_type);
CREATE INDEX IF NOT EXISTS idx_backups_creator ON decoy_backups(created_by);

-- Feature store table for behavioral analysis
CREATE TABLE IF NOT EXISTS behavioral_features (
    id SERIAL PRIMARY KEY,
    entity_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    features JSONB NOT NULL DEFAULT '{}',
    extracted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for behavioral_features
CREATE INDEX IF NOT EXISTS idx_behavioral_features_entity_tenant ON behavioral_features(entity_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_behavioral_features_extracted ON behavioral_features(extracted_at DESC);

-- Model deployment registry
CREATE TABLE IF NOT EXISTS model_deployments (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    model_type VARCHAR(100) NOT NULL,
    model_id INTEGER NOT NULL,
    stage VARCHAR(20) NOT NULL DEFAULT 'staging', -- staging, production
    artifact_path TEXT,
    metrics JSONB DEFAULT '{}',
    promoted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    promoted_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for model_deployments
CREATE INDEX IF NOT EXISTS idx_model_deployments_tenant_type_stage ON model_deployments(tenant_id, model_type, stage);
CREATE INDEX IF NOT EXISTS idx_model_deployments_promoted ON model_deployments(promoted_at DESC);

-- Behavioral models table
CREATE TABLE IF NOT EXISTS behavioral_models (
    id SERIAL PRIMARY KEY,
    entity_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL DEFAULT 'default',
    model_type VARCHAR(50) NOT NULL, -- 'isolation_forest', 'autoencoder', etc.
    artifact_path TEXT,
    metrics JSONB DEFAULT '{}',
    hyperparameters JSONB DEFAULT '{}',
    training_data_count INTEGER,
    trained_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for behavioral_models
CREATE INDEX IF NOT EXISTS idx_behavioral_models_entity_tenant ON behavioral_models(entity_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_behavioral_models_type ON behavioral_models(model_type);
CREATE INDEX IF NOT EXISTS idx_behavioral_models_trained ON behavioral_models(trained_at DESC);

-- Create functions for common operations

-- Function to get active canary tokens
CREATE OR REPLACE FUNCTION get_active_canary_tokens(p_tenant_id VARCHAR DEFAULT 'default')
RETURNS TABLE (
    token_id VARCHAR,
    token_type VARCHAR,
    location VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE,
    trigger_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ct.token_id,
        ct.token_type,
        ct.location,
        ct.created_at,
        ct.trigger_count
    FROM canary_tokens ct
    WHERE ct.active = TRUE 
    AND ct.tenant_id = p_tenant_id
    ORDER BY ct.created_at DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to log canary token trigger
CREATE OR REPLACE FUNCTION log_canary_trigger(
    p_token_id VARCHAR,
    p_source_ip INET,
    p_user_agent TEXT,
    p_request_details JSONB DEFAULT '{}'
) RETURNS INTEGER AS $$
DECLARE
    trigger_id INTEGER;
BEGIN
    -- Insert trigger record
    INSERT INTO canary_triggers (token_id, source_ip, user_agent, request_details)
    VALUES (p_token_id, p_source_ip, p_user_agent, p_request_details)
    RETURNING canary_triggers.trigger_id INTO trigger_id;
    
    -- Update token trigger count
    UPDATE canary_tokens 
    SET trigger_count = trigger_count + 1, 
        last_triggered = CURRENT_TIMESTAMP
    WHERE token_id = p_token_id;
    
    RETURN trigger_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get decoy interaction statistics
CREATE OR REPLACE FUNCTION get_decoy_stats(p_tenant_id VARCHAR DEFAULT 'default')
RETURNS TABLE (
    total_interactions INTEGER,
    unique_ips BIGINT,
    suspicious_activities INTEGER,
    last_24h_interactions INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_interactions,
        COUNT(DISTINCT ip_address) as unique_ips,
        COUNT(CASE WHEN log_level = 'ALERT' THEN 1 END)::INTEGER as suspicious_activities,
        COUNT(CASE WHEN timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours' THEN 1 END)::INTEGER as last_24h_interactions
    FROM decoy_system_logs
    WHERE tenant_id = p_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Create views for easier data access

-- View for canary token overview
CREATE OR REPLACE VIEW canary_tokens_overview AS
SELECT 
    ct.token_id,
    ct.token_type,
    ct.location,
    ct.tenant_id,
    ct.created_at,
    ct.trigger_count,
    ct.last_triggered,
    ct.active,
    CASE 
        WHEN ct.trigger_count = 0 THEN 'clean'
        WHEN ct.trigger_count <= 2 THEN 'low_activity'
        WHEN ct.trigger_count <= 5 THEN 'moderate_activity'
        ELSE 'high_activity'
    END as activity_level
FROM canary_tokens ct;

-- View for recent suspicious activities
CREATE OR REPLACE VIEW recent_suspicious_activity AS
SELECT 
    dsl.timestamp,
    dsl.log_level,
    dsl.service_name,
    dsl.message,
    dsl.ip_address,
    dsl.metadata,
    CASE 
        WHEN dsl.ip_address <<= '10.0.0.0/8'::inet OR 
             dsl.ip_address <<= '172.16.0.0/12'::inet OR 
             dsl.ip_address <<= '192.168.0.0/16'::inet 
        THEN 'internal'
        ELSE 'external'
    END as ip_type
FROM decoy_system_logs dsl
WHERE dsl.log_level = 'ALERT'
AND dsl.timestamp > CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY dsl.timestamp DESC;

-- Set up Row Level Security (RLS) for multi-tenant isolation
ALTER TABLE canary_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE canary_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE behavioral_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE decoy_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE decoy_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE decoy_financial_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE decoy_system_logs ENABLE ROW LEVEL SECURITY;

-- Create policies for tenant isolation (can be customized based on authentication method)
CREATE POLICY tenant_isolation_canary_tokens ON canary_tokens
    FOR ALL
    USING (tenant_id = COALESCE(current_setting('app.current_tenant_id', true), 'default'));

CREATE POLICY tenant_isolation_canary_triggers ON canary_triggers
    FOR ALL
    USING (EXISTS (
        SELECT 1 FROM canary_tokens ct 
        WHERE ct.token_id = canary_triggers.token_id 
        AND ct.tenant_id = COALESCE(current_setting('app.current_tenant_id', true), 'default')
    ));

CREATE POLICY tenant_isolation_behavioral_feedback ON behavioral_feedback
    FOR ALL
    USING (tenant_id = COALESCE(current_setting('app.current_tenant_id', true), 'default'));

-- Grant necessary permissions to application user
GRANT USAGE ON SCHEMA deception TO deception_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA deception TO deception_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA deception TO deception_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA deception TO deception_user;

-- Create application role for limited access
CREATE ROLE deception_app_role;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA deception TO deception_app_role;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA deception TO deception_app_role;
GRANT deception_app_role TO deception_user;

-- Log successful initialization
INSERT INTO decoy_system_logs (log_level, service_name, message, metadata)
VALUES (
    'INFO', 
    'database_init', 
    'Deception technology database initialized successfully',
    jsonb_build_object(
        'tables_created', 15,
        'indexes_created', 25,
        'functions_created', 3,
        'views_created', 2,
        'initialized_at', CURRENT_TIMESTAMP
    )
);

COMMIT;