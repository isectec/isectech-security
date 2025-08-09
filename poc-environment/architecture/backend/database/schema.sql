-- iSECTECH POC Environment Database Schema
-- Production-Grade Multi-Tenant POC Management System
-- Version: 1.0
-- Database: PostgreSQL 15+
-- Author: Claude Code Implementation

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Custom types and enums
CREATE TYPE poc_tier_enum AS ENUM ('standard', 'enterprise', 'premium');
CREATE TYPE poc_status_enum AS ENUM ('provisioning', 'active', 'suspended', 'expired', 'terminated');
CREATE TYPE poc_user_role_enum AS ENUM ('poc_admin', 'poc_user', 'poc_viewer', 'poc_evaluator', 'poc_guest');
CREATE TYPE security_clearance_enum AS ENUM ('unclassified', 'confidential', 'secret', 'top_secret');
CREATE TYPE company_size_enum AS ENUM ('startup', 'small', 'medium', 'large', 'enterprise');
CREATE TYPE environment_type_enum AS ENUM ('evaluation', 'demo', 'pilot', 'training', 'development');
CREATE TYPE environment_status_enum AS ENUM ('provisioning', 'ready', 'suspended', 'terminating', 'terminated');
CREATE TYPE evaluation_category_enum AS ENUM ('security_effectiveness', 'user_experience', 'integration_success', 'performance', 'cost_efficiency');
CREATE TYPE data_classification_enum AS ENUM ('public', 'internal', 'confidential', 'restricted');
CREATE TYPE compliance_framework_enum AS ENUM ('soc2', 'iso27001', 'hipaa', 'gdpr', 'fedramp', 'fisma', 'pci_dss', 'ccpa', 'nist', 'cis');

-- Core POC tenant management table
CREATE TABLE poc_tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_slug VARCHAR(63) UNIQUE NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    contact_email citext NOT NULL,
    contact_name VARCHAR(200) NOT NULL,
    contact_phone VARCHAR(50),
    website_url VARCHAR(500),
    
    -- Company information
    industry_vertical VARCHAR(100) NOT NULL,
    company_size company_size_enum NOT NULL,
    headquarters_country CHAR(2) NOT NULL, -- ISO 3166-1 alpha-2
    employee_count INTEGER,
    annual_revenue BIGINT,
    
    -- POC configuration
    poc_tier poc_tier_enum NOT NULL DEFAULT 'standard',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    activated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    status poc_status_enum NOT NULL DEFAULT 'provisioning',
    
    -- Resource allocation (JSONB for flexibility)
    resource_allocation JSONB NOT NULL DEFAULT '{}',
    feature_flags JSONB NOT NULL DEFAULT '{}',
    
    -- Security and compliance
    security_clearance security_clearance_enum NOT NULL DEFAULT 'unclassified',
    data_residency_region VARCHAR(10) NOT NULL DEFAULT 'us',
    compliance_frameworks compliance_framework_enum[] NOT NULL DEFAULT ARRAY['soc2']::compliance_framework_enum[],
    
    -- Cybersecurity-specific profile
    current_security_tools JSONB DEFAULT '{}',
    security_maturity_level INTEGER CHECK (security_maturity_level BETWEEN 1 AND 5),
    primary_security_challenges TEXT[],
    evaluation_objectives TEXT[],
    success_criteria JSONB DEFAULT '{}',
    
    -- Business context
    decision_makers JSONB DEFAULT '[]',
    budget_range VARCHAR(50),
    timeline_to_decision VARCHAR(50),
    competitive_alternatives TEXT[],
    
    -- Technical requirements
    integration_requirements JSONB DEFAULT '{}',
    compliance_requirements JSONB DEFAULT '{}',
    scalability_requirements JSONB DEFAULT '{}',
    
    -- Lifecycle management
    auto_cleanup_enabled BOOLEAN DEFAULT TRUE,
    cleanup_scheduled_at TIMESTAMP WITH TIME ZONE,
    extension_requests INTEGER DEFAULT 0,
    max_extensions INTEGER DEFAULT 2,
    
    -- Tracking and analytics
    source_campaign VARCHAR(100),
    lead_score INTEGER CHECK (lead_score BETWEEN 0 AND 100),
    conversion_probability DECIMAL(5,2) CHECK (conversion_probability BETWEEN 0 AND 100),
    
    -- Audit fields
    created_by UUID,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID,
    
    -- Constraints
    CONSTRAINT valid_expiration CHECK (expires_at > created_at),
    CONSTRAINT valid_email CHECK (contact_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_employee_count CHECK (employee_count > 0),
    CONSTRAINT valid_revenue CHECK (annual_revenue > 0)
);

-- POC users table with role-based access
CREATE TABLE poc_users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    email citext NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP WITH TIME ZONE,
    
    -- User profile
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    job_title VARCHAR(150),
    department VARCHAR(100),
    phone VARCHAR(50),
    
    -- Authentication
    password_hash VARCHAR(255), -- For local auth if needed
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Role and permissions
    role poc_user_role_enum NOT NULL DEFAULT 'poc_user',
    permissions JSONB DEFAULT '{}',
    security_clearance security_clearance_enum DEFAULT 'unclassified',
    
    -- Access control
    is_active BOOLEAN DEFAULT TRUE,
    is_primary_contact BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE,
    last_password_change TIMESTAMP WITH TIME ZONE,
    
    -- MFA settings
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(32),
    mfa_backup_codes TEXT[],
    
    -- Preferences and settings
    timezone VARCHAR(50) DEFAULT 'UTC',
    language_preference VARCHAR(10) DEFAULT 'en',
    notification_preferences JSONB DEFAULT '{"email": true, "in_app": true, "sms": false}',
    ui_preferences JSONB DEFAULT '{}',
    
    -- Tracking
    signup_source VARCHAR(100),
    onboarding_completed BOOLEAN DEFAULT FALSE,
    onboarding_completed_at TIMESTAMP WITH TIME ZONE,
    terms_accepted_at TIMESTAMP WITH TIME ZONE,
    privacy_policy_accepted_at TIMESTAMP WITH TIME ZONE,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID,
    updated_by UUID,
    
    -- Constraints
    UNIQUE(tenant_id, email),
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_failed_attempts CHECK (failed_login_attempts >= 0 AND failed_login_attempts <= 10)
);

-- POC environments (infrastructure instances)
CREATE TABLE poc_environments (
    environment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    environment_name VARCHAR(100) NOT NULL,
    environment_slug VARCHAR(63) NOT NULL,
    environment_type environment_type_enum NOT NULL DEFAULT 'evaluation',
    
    -- Infrastructure details
    kubernetes_namespace VARCHAR(100) NOT NULL,
    kubernetes_cluster_name VARCHAR(100) NOT NULL,
    database_instance_id VARCHAR(255) NOT NULL,
    database_name VARCHAR(100) NOT NULL,
    vpc_id VARCHAR(255) NOT NULL,
    region VARCHAR(50) NOT NULL,
    
    -- Resource allocation tracking
    allocated_cpu_cores INTEGER NOT NULL,
    allocated_memory_gb INTEGER NOT NULL,
    allocated_storage_gb INTEGER NOT NULL,
    allocated_network_bandwidth_mbps INTEGER DEFAULT 1000,
    
    -- Current resource usage
    current_cpu_usage DECIMAL(5,2) DEFAULT 0,
    current_memory_usage DECIMAL(5,2) DEFAULT 0,
    current_storage_usage_gb INTEGER DEFAULT 0,
    current_active_users INTEGER DEFAULT 0,
    
    -- Status and lifecycle
    status environment_status_enum NOT NULL DEFAULT 'provisioning',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    provisioning_started_at TIMESTAMP WITH TIME ZONE,
    ready_at TIMESTAMP WITH TIME ZONE,
    last_health_check TIMESTAMP WITH TIME ZONE,
    health_status VARCHAR(20) DEFAULT 'unknown',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    terminated_at TIMESTAMP WITH TIME ZONE,
    
    -- Configuration
    configuration JSONB NOT NULL DEFAULT '{}',
    environment_variables JSONB DEFAULT '{}',
    feature_toggles JSONB DEFAULT '{}',
    
    -- Networking and security
    ingress_endpoints JSONB DEFAULT '[]',
    ssl_certificate_arn VARCHAR(255),
    custom_domain VARCHAR(255),
    network_policies JSONB DEFAULT '{}',
    firewall_rules JSONB DEFAULT '[]',
    
    -- Monitoring and alerting
    monitoring_enabled BOOLEAN DEFAULT TRUE,
    alerting_rules JSONB DEFAULT '{}',
    notification_channels JSONB DEFAULT '[]',
    
    -- Cost tracking
    estimated_hourly_cost DECIMAL(10,4) DEFAULT 0,
    actual_cost_to_date DECIMAL(10,2) DEFAULT 0.00,
    budget_limit DECIMAL(10,2),
    budget_alerts_enabled BOOLEAN DEFAULT TRUE,
    
    -- Backup and disaster recovery
    backup_enabled BOOLEAN DEFAULT TRUE,
    backup_schedule VARCHAR(50) DEFAULT '0 2 * * *',
    last_backup_at TIMESTAMP WITH TIME ZONE,
    backup_retention_days INTEGER DEFAULT 7,
    disaster_recovery_enabled BOOLEAN DEFAULT FALSE,
    
    -- Audit fields
    created_by UUID,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID,
    
    -- Constraints
    UNIQUE(tenant_id, environment_slug),
    CONSTRAINT valid_resources CHECK (
        allocated_cpu_cores > 0 AND 
        allocated_memory_gb > 0 AND 
        allocated_storage_gb > 0
    ),
    CONSTRAINT valid_usage CHECK (
        current_cpu_usage >= 0 AND current_cpu_usage <= 100 AND
        current_memory_usage >= 0 AND current_memory_usage <= 100
    )
);

-- Sample data configurations for POC environments
CREATE TABLE poc_sample_data_sets (
    dataset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dataset_name VARCHAR(100) NOT NULL UNIQUE,
    dataset_description TEXT,
    dataset_category VARCHAR(50) NOT NULL,
    
    -- Data characteristics
    industry_focus VARCHAR(100),
    company_size_target company_size_enum,
    security_scenario VARCHAR(200),
    data_volume_description VARCHAR(200),
    
    -- Data structure
    data_schema JSONB NOT NULL,
    data_generation_rules JSONB NOT NULL,
    data_relationships JSONB DEFAULT '{}',
    
    -- Anonymization and privacy
    anonymization_applied BOOLEAN DEFAULT TRUE,
    privacy_level VARCHAR(20) DEFAULT 'high',
    contains_pii BOOLEAN DEFAULT FALSE,
    gdpr_compliant BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version VARCHAR(20) DEFAULT '1.0',
    tags TEXT[] DEFAULT '{}',
    
    -- Quality metrics
    data_quality_score INTEGER CHECK (data_quality_score BETWEEN 0 AND 100),
    realism_score INTEGER CHECK (realism_score BETWEEN 0 AND 100),
    educational_value INTEGER CHECK (educational_value BETWEEN 0 AND 100)
);

-- Environment sample data assignments
CREATE TABLE poc_environment_sample_data (
    assignment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    environment_id UUID NOT NULL REFERENCES poc_environments(environment_id) ON DELETE CASCADE,
    dataset_id UUID NOT NULL REFERENCES poc_sample_data_sets(dataset_id),
    
    -- Assignment details
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assignment_status VARCHAR(20) DEFAULT 'pending',
    data_volume_actual BIGINT,
    generation_completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Customization
    customization_parameters JSONB DEFAULT '{}',
    custom_scenarios JSONB DEFAULT '[]',
    
    UNIQUE(environment_id, dataset_id)
);

-- Feature usage tracking for POC evaluation
CREATE TABLE poc_feature_usage (
    usage_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES poc_environments(environment_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES poc_users(user_id) ON DELETE CASCADE,
    
    -- Feature identification
    feature_name VARCHAR(100) NOT NULL,
    feature_category VARCHAR(50) NOT NULL,
    feature_version VARCHAR(20),
    
    -- Usage details
    usage_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    session_id UUID NOT NULL,
    duration_seconds INTEGER,
    interaction_count INTEGER DEFAULT 1,
    
    -- Context
    user_agent TEXT,
    ip_address INET,
    geographic_location JSONB,
    device_info JSONB,
    
    -- Detailed interaction data
    interaction_details JSONB DEFAULT '{}',
    input_parameters JSONB DEFAULT '{}',
    output_results JSONB DEFAULT '{}',
    error_encountered BOOLEAN DEFAULT FALSE,
    error_details TEXT,
    
    -- Value demonstration metrics
    business_value_demonstrated DECIMAL(10,2),
    user_satisfaction_score INTEGER CHECK (user_satisfaction_score BETWEEN 1 AND 5),
    feature_completeness_score INTEGER CHECK (feature_completeness_score BETWEEN 0 AND 100),
    learning_objective_met BOOLEAN,
    
    -- Performance metrics
    response_time_ms INTEGER,
    data_processed_mb DECIMAL(10,2),
    cpu_usage_percent DECIMAL(5,2),
    memory_usage_mb INTEGER,
    
    -- Indexes for performance
    INDEX idx_feature_usage_tenant (tenant_id, usage_timestamp),
    INDEX idx_feature_usage_feature (feature_name, usage_timestamp),
    INDEX idx_feature_usage_session (session_id),
    INDEX idx_feature_usage_user (user_id, usage_timestamp)
);

-- POC evaluation metrics and success criteria tracking
CREATE TABLE poc_evaluation_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES poc_environments(environment_id) ON DELETE CASCADE,
    
    -- Metric identification
    metric_name VARCHAR(100) NOT NULL,
    metric_category evaluation_category_enum NOT NULL,
    metric_description TEXT,
    
    -- Measurement details
    target_value DECIMAL(15,4),
    current_value DECIMAL(15,4),
    previous_value DECIMAL(15,4),
    unit_of_measurement VARCHAR(50),
    measurement_method VARCHAR(100),
    
    -- Timing
    measured_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    measurement_period_start TIMESTAMP WITH TIME ZONE,
    measurement_period_end TIMESTAMP WITH TIME ZONE,
    
    -- Business impact calculation
    cost_savings_potential DECIMAL(12,2),
    efficiency_improvement_percent DECIMAL(5,2),
    risk_reduction_score INTEGER CHECK (risk_reduction_score BETWEEN 0 AND 100),
    productivity_gain_percent DECIMAL(5,2),
    
    -- ROI calculation fields
    investment_required DECIMAL(12,2),
    annual_benefit DECIMAL(12,2),
    payback_period_months INTEGER,
    net_present_value DECIMAL(12,2),
    
    -- Success criteria evaluation
    success_threshold DECIMAL(15,4),
    is_success_criteria_met BOOLEAN DEFAULT FALSE,
    confidence_level DECIMAL(5,2) CHECK (confidence_level BETWEEN 0 AND 100),
    
    -- Data quality and reliability
    data_points_count INTEGER DEFAULT 1,
    measurement_accuracy DECIMAL(5,2),
    statistical_significance DECIMAL(5,2),
    
    -- Context and metadata
    measurement_context JSONB DEFAULT '{}',
    external_factors JSONB DEFAULT '{}',
    assumptions JSONB DEFAULT '{}',
    
    -- Trending and comparison
    trend_direction VARCHAR(20), -- 'improving', 'declining', 'stable', 'volatile'
    benchmark_comparison DECIMAL(15,4),
    peer_comparison DECIMAL(15,4),
    industry_standard DECIMAL(15,4),
    
    UNIQUE(tenant_id, metric_name, measured_at)
);

-- User engagement and behavior tracking
CREATE TABLE poc_user_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES poc_users(user_id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES poc_environments(environment_id) ON DELETE CASCADE,
    
    -- Session details
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Technical details
    ip_address INET,
    user_agent TEXT,
    device_type VARCHAR(50),
    browser_info JSONB,
    screen_resolution VARCHAR(20),
    
    -- Geographic and network info
    country_code CHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    timezone VARCHAR(50),
    connection_type VARCHAR(50),
    
    -- Engagement metrics
    pages_visited INTEGER DEFAULT 0,
    actions_performed INTEGER DEFAULT 0,
    features_used TEXT[] DEFAULT '{}',
    time_on_features JSONB DEFAULT '{}',
    
    -- Quality metrics
    bounce_rate DECIMAL(5,2),
    engagement_score INTEGER CHECK (engagement_score BETWEEN 0 AND 100),
    satisfaction_indicators JSONB DEFAULT '{}',
    
    -- Technical performance
    average_page_load_time INTEGER,
    error_count INTEGER DEFAULT 0,
    api_calls_made INTEGER DEFAULT 0,
    data_downloaded_mb DECIMAL(10,2) DEFAULT 0,
    
    INDEX idx_user_sessions_tenant (tenant_id, started_at),
    INDEX idx_user_sessions_user (user_id, started_at),
    INDEX idx_user_sessions_active (is_active, started_at)
);

-- Integration configurations and external data sources
CREATE TABLE poc_integrations (
    integration_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    environment_id UUID NOT NULL REFERENCES poc_environments(environment_id) ON DELETE CASCADE,
    
    -- Integration details
    integration_name VARCHAR(100) NOT NULL,
    integration_type VARCHAR(50) NOT NULL,
    vendor_name VARCHAR(100),
    product_name VARCHAR(100),
    version VARCHAR(50),
    
    -- Configuration
    configuration JSONB NOT NULL DEFAULT '{}',
    credentials_secret_name VARCHAR(255),
    api_endpoint VARCHAR(500),
    authentication_method VARCHAR(50),
    
    -- Status and health
    status VARCHAR(20) DEFAULT 'inactive',
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_successful_sync_at TIMESTAMP WITH TIME ZONE,
    sync_frequency VARCHAR(50) DEFAULT 'hourly',
    health_check_status VARCHAR(20) DEFAULT 'unknown',
    
    -- Data flow metrics
    records_imported_count BIGINT DEFAULT 0,
    records_exported_count BIGINT DEFAULT 0,
    data_volume_imported_mb DECIMAL(12,2) DEFAULT 0,
    sync_error_count INTEGER DEFAULT 0,
    last_error_message TEXT,
    
    -- Security and compliance
    data_classification data_classification_enum DEFAULT 'internal',
    encryption_enabled BOOLEAN DEFAULT TRUE,
    audit_logging_enabled BOOLEAN DEFAULT TRUE,
    
    -- Timing and lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    activated_at TIMESTAMP WITH TIME ZONE,
    deactivated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE, -- For time-limited integrations
    
    UNIQUE(tenant_id, integration_name)
);

-- CRM and sales pipeline integration
CREATE TABLE poc_sales_pipeline (
    pipeline_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES poc_tenants(tenant_id) ON DELETE CASCADE,
    
    -- Sales context
    opportunity_id VARCHAR(100), -- External CRM opportunity ID
    sales_rep_email citext,
    sales_rep_name VARCHAR(200),
    account_executive_email citext,
    account_executive_name VARCHAR(200),
    
    -- Pipeline stage tracking
    current_stage VARCHAR(50) NOT NULL DEFAULT 'poc_initiated',
    stage_entered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    previous_stage VARCHAR(50),
    stage_progression JSONB DEFAULT '[]',
    
    -- Qualification and scoring
    qualification_score INTEGER CHECK (qualification_score BETWEEN 0 AND 100),
    engagement_score INTEGER CHECK (engagement_score BETWEEN 0 AND 100),
    technical_fit_score INTEGER CHECK (technical_fit_score BETWEEN 0 AND 100),
    commercial_fit_score INTEGER CHECK (commercial_fit_score BETWEEN 0 AND 100),
    
    -- Forecasting
    conversion_probability DECIMAL(5,2) CHECK (conversion_probability BETWEEN 0 AND 100),
    forecasted_close_date DATE,
    deal_value DECIMAL(12,2),
    deal_currency CHAR(3) DEFAULT 'USD',
    
    -- Key stakeholders and decision process
    decision_makers JSONB DEFAULT '[]',
    influencers JSONB DEFAULT '[]',
    champions JSONB DEFAULT '[]',
    decision_criteria JSONB DEFAULT '{}',
    competitive_situation JSONB DEFAULT '{}',
    
    -- Next steps and follow-up
    next_steps TEXT,
    next_meeting_scheduled TIMESTAMP WITH TIME ZONE,
    follow_up_tasks JSONB DEFAULT '[]',
    
    -- Outcome tracking
    outcome VARCHAR(50), -- 'won', 'lost', 'no_decision', 'delayed'
    outcome_reason TEXT,
    outcome_date DATE,
    lessons_learned TEXT,
    
    -- Integration with CRM
    crm_system VARCHAR(50),
    crm_record_id VARCHAR(100),
    last_crm_sync TIMESTAMP WITH TIME ZONE,
    crm_sync_status VARCHAR(20) DEFAULT 'pending',
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID,
    updated_by UUID
);

-- Event log for audit and analytics
CREATE TABLE poc_event_log (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES poc_tenants(tenant_id),
    user_id UUID REFERENCES poc_users(user_id),
    environment_id UUID REFERENCES poc_environments(environment_id),
    
    -- Event identification
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    event_name VARCHAR(200) NOT NULL,
    
    -- Event details
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    event_data JSONB DEFAULT '{}',
    event_metadata JSONB DEFAULT '{}',
    
    -- Source information
    source_ip INET,
    source_user_agent TEXT,
    source_service VARCHAR(100),
    source_component VARCHAR(100),
    
    -- Security context
    security_context JSONB DEFAULT '{}',
    risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    requires_investigation BOOLEAN DEFAULT FALSE,
    
    -- Correlation
    correlation_id UUID,
    parent_event_id UUID REFERENCES poc_event_log(event_id),
    trace_id VARCHAR(100),
    
    -- Processing status
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMP WITH TIME ZONE,
    processing_result JSONB,
    
    -- Retention and archival
    retention_policy VARCHAR(50) DEFAULT 'standard',
    archived BOOLEAN DEFAULT FALSE,
    archived_at TIMESTAMP WITH TIME ZONE,
    
    -- Indexes for performance
    INDEX idx_event_log_tenant_time (tenant_id, event_timestamp),
    INDEX idx_event_log_type_time (event_type, event_timestamp),
    INDEX idx_event_log_user_time (user_id, event_timestamp),
    INDEX idx_event_log_correlation (correlation_id),
    INDEX idx_event_log_risk (risk_score DESC, event_timestamp)
);

-- Automated triggers and audit functions
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers to relevant tables
CREATE TRIGGER update_poc_tenants_updated_at BEFORE UPDATE ON poc_tenants FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_poc_users_updated_at BEFORE UPDATE ON poc_users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_poc_environments_updated_at BEFORE UPDATE ON poc_environments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_poc_sales_pipeline_updated_at BEFORE UPDATE ON poc_sales_pipeline FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Row Level Security (RLS) for multi-tenancy
ALTER TABLE poc_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_feature_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_evaluation_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_integrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_sales_pipeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE poc_event_log ENABLE ROW LEVEL SECURITY;

-- Create RLS policies (examples - adjust based on application roles)
CREATE POLICY tenant_isolation_policy ON poc_tenants FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY user_tenant_policy ON poc_users FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY environment_tenant_policy ON poc_environments FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY feature_usage_tenant_policy ON poc_feature_usage FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY evaluation_metrics_tenant_policy ON poc_evaluation_metrics FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY user_sessions_tenant_policy ON poc_user_sessions FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY integrations_tenant_policy ON poc_integrations FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY sales_pipeline_tenant_policy ON poc_sales_pipeline FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY event_log_tenant_policy ON poc_event_log FOR ALL USING (tenant_id = current_setting('app.current_tenant_id')::uuid);

-- Performance indexes
CREATE INDEX CONCURRENTLY idx_poc_tenants_status_expires ON poc_tenants(status, expires_at);
CREATE INDEX CONCURRENTLY idx_poc_tenants_tier_region ON poc_tenants(poc_tier, data_residency_region);
CREATE INDEX CONCURRENTLY idx_poc_users_tenant_active ON poc_users(tenant_id, is_active);
CREATE INDEX CONCURRENTLY idx_poc_users_email_verification ON poc_users(email_verified, email_verification_expires_at);
CREATE INDEX CONCURRENTLY idx_poc_environments_status_health ON poc_environments(status, health_status);
CREATE INDEX CONCURRENTLY idx_poc_environments_tenant_type ON poc_environments(tenant_id, environment_type);
CREATE INDEX CONCURRENTLY idx_feature_usage_analytics ON poc_feature_usage(tenant_id, feature_category, usage_timestamp);
CREATE INDEX CONCURRENTLY idx_evaluation_metrics_tracking ON poc_evaluation_metrics(tenant_id, metric_category, measured_at);
CREATE INDEX CONCURRENTLY idx_user_sessions_engagement ON poc_user_sessions(tenant_id, engagement_score, started_at);
CREATE INDEX CONCURRENTLY idx_sales_pipeline_stage ON poc_sales_pipeline(current_stage, stage_entered_at);

-- Full-text search indexes
CREATE INDEX CONCURRENTLY idx_poc_tenants_search ON poc_tenants USING gin(to_tsvector('english', company_name || ' ' || COALESCE(industry_vertical, '')));
CREATE INDEX CONCURRENTLY idx_event_log_search ON poc_event_log USING gin(to_tsvector('english', event_name || ' ' || COALESCE(event_data::text, '')));

-- Partial indexes for common queries
CREATE INDEX CONCURRENTLY idx_poc_tenants_active ON poc_tenants(tenant_id) WHERE status = 'active';
CREATE INDEX CONCURRENTLY idx_poc_environments_ready ON poc_environments(environment_id, tenant_id) WHERE status = 'ready';
CREATE INDEX CONCURRENTLY idx_poc_users_active ON poc_users(user_id, tenant_id) WHERE is_active = TRUE;

-- Database maintenance and monitoring views
CREATE VIEW poc_tenant_summary AS
SELECT 
    t.tenant_id,
    t.tenant_slug,
    t.company_name,
    t.poc_tier,
    t.status,
    t.created_at,
    t.expires_at,
    CASE 
        WHEN t.expires_at < NOW() THEN 'expired'
        WHEN t.expires_at < NOW() + INTERVAL '7 days' THEN 'expiring_soon'
        ELSE 'active'
    END as expiration_status,
    COUNT(DISTINCT e.environment_id) as environment_count,
    COUNT(DISTINCT u.user_id) as user_count,
    COUNT(DISTINCT fu.usage_id) as feature_usage_count,
    MAX(s.started_at) as last_user_activity
FROM poc_tenants t
LEFT JOIN poc_environments e ON t.tenant_id = e.tenant_id
LEFT JOIN poc_users u ON t.tenant_id = u.tenant_id AND u.is_active = TRUE
LEFT JOIN poc_feature_usage fu ON t.tenant_id = fu.tenant_id
LEFT JOIN poc_user_sessions s ON t.tenant_id = s.tenant_id
GROUP BY t.tenant_id, t.tenant_slug, t.company_name, t.poc_tier, t.status, t.created_at, t.expires_at;

-- Performance monitoring view
CREATE VIEW poc_environment_health AS
SELECT 
    e.environment_id,
    e.tenant_id,
    e.environment_name,
    e.status,
    e.health_status,
    e.current_cpu_usage,
    e.current_memory_usage,
    e.current_storage_usage_gb,
    e.current_active_users,
    e.allocated_cpu_cores,
    e.allocated_memory_gb,
    e.allocated_storage_gb,
    ROUND((e.current_cpu_usage / e.allocated_cpu_cores) * 100, 2) as cpu_utilization_percent,
    ROUND((e.current_memory_usage / e.allocated_memory_gb) * 100, 2) as memory_utilization_percent,
    ROUND((e.current_storage_usage_gb::decimal / e.allocated_storage_gb) * 100, 2) as storage_utilization_percent,
    e.actual_cost_to_date,
    e.estimated_hourly_cost,
    e.last_health_check,
    CASE 
        WHEN e.last_health_check < NOW() - INTERVAL '5 minutes' THEN 'stale'
        WHEN e.health_status = 'healthy' THEN 'healthy'
        WHEN e.health_status = 'warning' THEN 'warning'
        ELSE 'unhealthy'
    END as overall_health_status
FROM poc_environments e;

-- Grant permissions (adjust based on application roles)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO poc_application_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO poc_application_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO poc_readonly_role;

-- Comments for documentation
COMMENT ON TABLE poc_tenants IS 'Core table for POC tenant management with comprehensive business and technical context';
COMMENT ON TABLE poc_users IS 'POC users with role-based access control and security features';
COMMENT ON TABLE poc_environments IS 'Infrastructure environments for POC instances with resource tracking';
COMMENT ON TABLE poc_feature_usage IS 'Detailed feature usage tracking for POC evaluation and analytics';
COMMENT ON TABLE poc_evaluation_metrics IS 'Business metrics and success criteria tracking for POC ROI analysis';
COMMENT ON TABLE poc_user_sessions IS 'User engagement and behavior analytics for POC optimization';
COMMENT ON TABLE poc_integrations IS 'External system integrations and data connector configurations';
COMMENT ON TABLE poc_sales_pipeline IS 'CRM integration and sales pipeline tracking for POC conversion';
COMMENT ON TABLE poc_event_log IS 'Comprehensive audit log and event tracking for security and analytics';

-- Schema version tracking
CREATE TABLE schema_version (
    version VARCHAR(20) PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    applied_by VARCHAR(100),
    description TEXT
);

INSERT INTO schema_version (version, applied_by, description) 
VALUES ('1.0.0', 'automated_deployment', 'Initial POC environment schema with multi-tenant architecture');

COMMIT;