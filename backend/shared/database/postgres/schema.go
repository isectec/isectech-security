package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// SchemaManager manages database schema operations for iSECTECH
type SchemaManager struct {
	client *Client
	logger *zap.Logger
}

// NewSchemaManager creates a new schema manager
func NewSchemaManager(client *Client, logger *zap.Logger) *SchemaManager {
	return &SchemaManager{
		client: client,
		logger: logger,
	}
}

// CreateSchema creates all necessary tables and indexes for iSECTECH
func (sm *SchemaManager) CreateSchema(ctx context.Context) error {
	schemas := []string{
		sm.createTenantsSchema(),
		sm.createUsersSchema(),
		sm.createAssetSchema(),
		sm.createThreatSchema(),
		sm.createEventSchema(),
		sm.createAlertSchema(),
		sm.createComplianceSchema(),
		sm.createAuditSchema(),
	}

	// Execute schema creation for each shard
	for _, schema := range schemas {
		if err := sm.executeOnAllShards(ctx, schema); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}
	}

	// Create indexes
	if err := sm.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Enable row-level security policies
	if err := sm.enableRLSPolicies(ctx); err != nil {
		return fmt.Errorf("failed to enable RLS policies: %w", err)
	}

	sm.logger.Info("Database schema created successfully")
	return nil
}

// createTenantsSchema creates the tenants table
func (sm *SchemaManager) createTenantsSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name VARCHAR(255) NOT NULL,
			domain VARCHAR(255) UNIQUE NOT NULL,
			plan VARCHAR(50) NOT NULL DEFAULT 'basic',
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			settings JSONB NOT NULL DEFAULT '{}',
			security_config JSONB NOT NULL DEFAULT '{}',
			compliance_requirements TEXT[] DEFAULT '{}',
			max_users INTEGER DEFAULT 100,
			max_assets INTEGER DEFAULT 1000,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID,
			updated_by UUID
		);

		-- Enable RLS
		ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
	`
}

// createUsersSchema creates the users table
func (sm *SchemaManager) createUsersSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			email VARCHAR(255) UNIQUE NOT NULL,
			username VARCHAR(100) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			first_name VARCHAR(100),
			last_name VARCHAR(100),
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			security_clearance VARCHAR(50) NOT NULL DEFAULT 'UNCLASSIFIED',
			permissions JSONB NOT NULL DEFAULT '[]',
			preferences JSONB NOT NULL DEFAULT '{}',
			last_login_at TIMESTAMP WITH TIME ZONE,
			failed_login_attempts INTEGER DEFAULT 0,
			locked_until TIMESTAMP WITH TIME ZONE,
			mfa_enabled BOOLEAN DEFAULT false,
			mfa_secret VARCHAR(255),
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID,
			updated_by UUID
		);

		-- Enable RLS
		ALTER TABLE users ENABLE ROW LEVEL SECURITY;
	`
}

// createAssetSchema creates the assets table
func (sm *SchemaManager) createAssetSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS assets (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(100) NOT NULL,
			category VARCHAR(100) NOT NULL,
			ip_addresses INET[] DEFAULT '{}',
			mac_addresses MACADDR[] DEFAULT '{}',
			hostnames TEXT[] DEFAULT '{}',
			ports JSONB DEFAULT '[]',
			services JSONB DEFAULT '[]',
			operating_system VARCHAR(255),
			os_version VARCHAR(100),
			manufacturer VARCHAR(255),
			model VARCHAR(255),
			serial_number VARCHAR(255),
			asset_tag VARCHAR(100),
			location VARCHAR(255),
			owner VARCHAR(255),
			business_unit VARCHAR(255),
			criticality VARCHAR(50) NOT NULL DEFAULT 'medium',
			security_classification VARCHAR(50) NOT NULL DEFAULT 'INTERNAL',
			compliance_tags TEXT[] DEFAULT '{}',
			vulnerabilities JSONB DEFAULT '[]',
			security_controls JSONB DEFAULT '[]',
			metadata JSONB DEFAULT '{}',
			last_scan_at TIMESTAMP WITH TIME ZONE,
			last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID,
			updated_by UUID
		);

		-- Enable RLS
		ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
		
		-- Add sharding info
		CREATE INDEX IF NOT EXISTS assets_tenant_id_idx ON assets(tenant_id);
	`
}

// createThreatSchema creates the threats table
func (sm *SchemaManager) createThreatSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS threats (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			type VARCHAR(100) NOT NULL,
			category VARCHAR(100) NOT NULL,
			severity VARCHAR(50) NOT NULL,
			confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
			description TEXT,
			indicators JSONB DEFAULT '[]',
			ttps JSONB DEFAULT '[]', -- Tactics, Techniques, and Procedures
			mitre_attack_ids TEXT[] DEFAULT '{}',
			affected_assets UUID[] DEFAULT '{}',
			source VARCHAR(255),
			external_references JSONB DEFAULT '[]',
			tags TEXT[] DEFAULT '{}',
			security_classification VARCHAR(50) NOT NULL DEFAULT 'CONFIDENTIAL',
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID,
			updated_by UUID
		);

		-- Enable RLS
		ALTER TABLE threats ENABLE ROW LEVEL SECURITY;
		
		-- Add sharding info
		CREATE INDEX IF NOT EXISTS threats_tenant_id_idx ON threats(tenant_id);
	`
}

// createEventSchema creates the security events table
func (sm *SchemaManager) createEventSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS security_events (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			event_type VARCHAR(100) NOT NULL,
			severity VARCHAR(50) NOT NULL,
			source_asset_id UUID REFERENCES assets(id),
			target_asset_id UUID REFERENCES assets(id),
			threat_id UUID REFERENCES threats(id),
			title VARCHAR(500) NOT NULL,
			description TEXT,
			raw_event JSONB NOT NULL,
			normalized_event JSONB NOT NULL,
			indicators JSONB DEFAULT '[]',
			tags TEXT[] DEFAULT '{}',
			source_ip INET,
			source_port INTEGER,
			destination_ip INET,
			destination_port INTEGER,
			protocol VARCHAR(20),
			user_id UUID REFERENCES users(id),
			session_id VARCHAR(255),
			process_name VARCHAR(255),
			process_id INTEGER,
			parent_process_id INTEGER,
			command_line TEXT,
			file_path TEXT,
			file_hash VARCHAR(255),
			network_traffic JSONB,
			mitre_attack_techniques TEXT[] DEFAULT '{}',
			risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
			security_classification VARCHAR(50) NOT NULL DEFAULT 'RESTRICTED',
			status VARCHAR(50) NOT NULL DEFAULT 'new',
			acknowledged_at TIMESTAMP WITH TIME ZONE,
			acknowledged_by UUID REFERENCES users(id),
			resolved_at TIMESTAMP WITH TIME ZONE,
			resolved_by UUID REFERENCES users(id),
			occurred_at TIMESTAMP WITH TIME ZONE NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Enable RLS
		ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
		
		-- Partition by month for performance
		CREATE INDEX IF NOT EXISTS security_events_tenant_occurred_at_idx 
			ON security_events(tenant_id, occurred_at DESC);
	`
}

// createAlertSchema creates the alerts table
func (sm *SchemaManager) createAlertSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS alerts (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			title VARCHAR(500) NOT NULL,
			description TEXT,
			severity VARCHAR(50) NOT NULL,
			category VARCHAR(100) NOT NULL,
			rule_id VARCHAR(255),
			rule_name VARCHAR(255),
			event_ids UUID[] DEFAULT '{}',
			asset_ids UUID[] DEFAULT '{}',
			threat_ids UUID[] DEFAULT '{}',
			indicators JSONB DEFAULT '[]',
			recommendations TEXT,
			false_positive BOOLEAN DEFAULT false,
			risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
			security_classification VARCHAR(50) NOT NULL DEFAULT 'RESTRICTED',
			status VARCHAR(50) NOT NULL DEFAULT 'open',
			assigned_to UUID REFERENCES users(id),
			escalated_to UUID REFERENCES users(id),
			escalated_at TIMESTAMP WITH TIME ZONE,
			acknowledged_at TIMESTAMP WITH TIME ZONE,
			acknowledged_by UUID REFERENCES users(id),
			resolved_at TIMESTAMP WITH TIME ZONE,
			resolved_by UUID REFERENCES users(id),
			resolution_notes TEXT,
			tags TEXT[] DEFAULT '{}',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Enable RLS
		ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
		
		-- Add sharding info
		CREATE INDEX IF NOT EXISTS alerts_tenant_id_idx ON alerts(tenant_id);
	`
}

// createComplianceSchema creates compliance-related tables
func (sm *SchemaManager) createComplianceSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS compliance_frameworks (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			version VARCHAR(50),
			description TEXT,
			requirements JSONB NOT NULL DEFAULT '[]',
			status VARCHAR(50) NOT NULL DEFAULT 'active',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS compliance_assessments (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			framework_id UUID NOT NULL REFERENCES compliance_frameworks(id),
			asset_id UUID REFERENCES assets(id),
			requirement_id VARCHAR(255) NOT NULL,
			status VARCHAR(50) NOT NULL DEFAULT 'pending',
			score INTEGER CHECK (score >= 0 AND score <= 100),
			findings JSONB DEFAULT '[]',
			evidence JSONB DEFAULT '[]',
			remediation_actions JSONB DEFAULT '[]',
			assessed_by UUID REFERENCES users(id),
			assessed_at TIMESTAMP WITH TIME ZONE,
			next_assessment_due TIMESTAMP WITH TIME ZONE,
			security_classification VARCHAR(50) NOT NULL DEFAULT 'CONFIDENTIAL',
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Enable RLS
		ALTER TABLE compliance_frameworks ENABLE ROW LEVEL SECURITY;
		ALTER TABLE compliance_assessments ENABLE ROW LEVEL SECURITY;
	`
}

// createAuditSchema creates audit logging tables
func (sm *SchemaManager) createAuditSchema() string {
	return `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id),
			action VARCHAR(100) NOT NULL,
			resource_type VARCHAR(100) NOT NULL,
			resource_id UUID,
			source_ip INET,
			user_agent TEXT,
			session_id VARCHAR(255),
			details JSONB DEFAULT '{}',
			old_values JSONB,
			new_values JSONB,
			status VARCHAR(50) NOT NULL DEFAULT 'success',
			error_message TEXT,
			security_classification VARCHAR(50) NOT NULL DEFAULT 'RESTRICTED',
			occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);

		-- Enable RLS
		ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
		
		-- Partition by month for performance
		CREATE INDEX IF NOT EXISTS audit_logs_tenant_occurred_at_idx 
			ON audit_logs(tenant_id, occurred_at DESC);
	`
}

// createIndexes creates performance indexes
func (sm *SchemaManager) createIndexes(ctx context.Context) error {
	indexes := []string{
		// User indexes
		"CREATE INDEX IF NOT EXISTS users_tenant_email_idx ON users(tenant_id, email);",
		"CREATE INDEX IF NOT EXISTS users_tenant_username_idx ON users(tenant_id, username);",
		"CREATE INDEX IF NOT EXISTS users_role_idx ON users(role);",
		"CREATE INDEX IF NOT EXISTS users_security_clearance_idx ON users(security_clearance);",

		// Asset indexes
		"CREATE INDEX IF NOT EXISTS assets_type_idx ON assets(type);",
		"CREATE INDEX IF NOT EXISTS assets_criticality_idx ON assets(criticality);",
		"CREATE INDEX IF NOT EXISTS assets_security_classification_idx ON assets(security_classification);",
		"CREATE INDEX IF NOT EXISTS assets_ip_addresses_idx ON assets USING GIN(ip_addresses);",
		"CREATE INDEX IF NOT EXISTS assets_compliance_tags_idx ON assets USING GIN(compliance_tags);",

		// Threat indexes
		"CREATE INDEX IF NOT EXISTS threats_type_severity_idx ON threats(type, severity);",
		"CREATE INDEX IF NOT EXISTS threats_mitre_attack_ids_idx ON threats USING GIN(mitre_attack_ids);",
		"CREATE INDEX IF NOT EXISTS threats_security_classification_idx ON threats(security_classification);",

		// Security event indexes
		"CREATE INDEX IF NOT EXISTS security_events_event_type_idx ON security_events(event_type);",
		"CREATE INDEX IF NOT EXISTS security_events_severity_idx ON security_events(severity);",
		"CREATE INDEX IF NOT EXISTS security_events_source_ip_idx ON security_events(source_ip);",
		"CREATE INDEX IF NOT EXISTS security_events_destination_ip_idx ON security_events(destination_ip);",
		"CREATE INDEX IF NOT EXISTS security_events_mitre_attack_idx ON security_events USING GIN(mitre_attack_techniques);",
		"CREATE INDEX IF NOT EXISTS security_events_tags_idx ON security_events USING GIN(tags);",
		"CREATE INDEX IF NOT EXISTS security_events_risk_score_idx ON security_events(risk_score);",

		// Alert indexes
		"CREATE INDEX IF NOT EXISTS alerts_severity_status_idx ON alerts(severity, status);",
		"CREATE INDEX IF NOT EXISTS alerts_assigned_to_idx ON alerts(assigned_to);",
		"CREATE INDEX IF NOT EXISTS alerts_category_idx ON alerts(category);",

		// Compliance indexes
		"CREATE INDEX IF NOT EXISTS compliance_assessments_framework_id_idx ON compliance_assessments(framework_id);",
		"CREATE INDEX IF NOT EXISTS compliance_assessments_status_idx ON compliance_assessments(status);",
		"CREATE INDEX IF NOT EXISTS compliance_assessments_next_due_idx ON compliance_assessments(next_assessment_due);",

		// Audit indexes
		"CREATE INDEX IF NOT EXISTS audit_logs_user_action_idx ON audit_logs(user_id, action);",
		"CREATE INDEX IF NOT EXISTS audit_logs_resource_type_idx ON audit_logs(resource_type, resource_id);",
	}

	for _, index := range indexes {
		if err := sm.executeOnAllShards(ctx, index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// enableRLSPolicies creates row-level security policies
func (sm *SchemaManager) enableRLSPolicies(ctx context.Context) error {
	policies := []string{
		// Tenant policies
		`CREATE POLICY tenant_isolation ON tenants 
			FOR ALL TO PUBLIC 
			USING (id = app.current_tenant_id()::UUID);`,

		// User policies
		`CREATE POLICY user_tenant_isolation ON users 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID);`,

		// Asset policies
		`CREATE POLICY asset_tenant_isolation ON assets 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,

		// Threat policies
		`CREATE POLICY threat_tenant_isolation ON threats 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,

		// Security event policies
		`CREATE POLICY security_event_tenant_isolation ON security_events 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,

		// Alert policies
		`CREATE POLICY alert_tenant_isolation ON alerts 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,

		// Compliance policies
		`CREATE POLICY compliance_framework_tenant_isolation ON compliance_frameworks 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID);`,

		`CREATE POLICY compliance_assessment_tenant_isolation ON compliance_assessments 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,

		// Audit log policies
		`CREATE POLICY audit_log_tenant_isolation ON audit_logs 
			FOR ALL TO PUBLIC 
			USING (tenant_id = app.current_tenant_id()::UUID 
				AND app.validate_security_clearance(security_classification));`,
	}

	for _, policy := range policies {
		if err := sm.executeOnAllShards(ctx, policy); err != nil {
			// Skip if policy already exists
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			return fmt.Errorf("failed to create RLS policy: %w", err)
		}
	}

	return nil
}

// executeOnAllShards executes SQL on all shards
func (sm *SchemaManager) executeOnAllShards(ctx context.Context, sql string) error {
	for shardName := range sm.client.shards {
		shard := sm.client.shards[shardName]
		_, err := shard.primary.ExecContext(ctx, sql)
		if err != nil {
			return fmt.Errorf("failed to execute on shard %s: %w", shardName, err)
		}
	}
	return nil
}

// DropSchema drops all tables (use with caution)
func (sm *SchemaManager) DropSchema(ctx context.Context) error {
	dropSQL := `
		DROP TABLE IF EXISTS audit_logs CASCADE;
		DROP TABLE IF EXISTS compliance_assessments CASCADE;
		DROP TABLE IF EXISTS compliance_frameworks CASCADE;
		DROP TABLE IF EXISTS alerts CASCADE;
		DROP TABLE IF EXISTS security_events CASCADE;
		DROP TABLE IF EXISTS threats CASCADE;
		DROP TABLE IF EXISTS assets CASCADE;
		DROP TABLE IF EXISTS users CASCADE;
		DROP TABLE IF EXISTS tenants CASCADE;
		DROP SCHEMA IF EXISTS app CASCADE;
	`

	return sm.executeOnAllShards(ctx, dropSQL)
}