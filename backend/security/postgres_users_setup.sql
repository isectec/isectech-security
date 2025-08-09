-- PostgreSQL Users Setup for PgBouncer Integration
-- Creates the necessary database users and roles for connection pooling

-- Create application role for RBAC functions
CREATE ROLE IF NOT EXISTS application_role;

-- Create pool users for PgBouncer
CREATE USER IF NOT EXISTS isectech_pool WITH PASSWORD 'pool_password';
CREATE USER IF NOT EXISTS isectech_analytics_pool WITH PASSWORD 'analytics_pool_password';
CREATE USER IF NOT EXISTS isectech_test_pool WITH PASSWORD 'test_pool_password';

-- Grant necessary privileges to pool users
GRANT CONNECT ON DATABASE isectech TO isectech_pool;
GRANT CONNECT ON DATABASE isectech TO isectech_analytics_pool;
GRANT CONNECT ON DATABASE isectech TO isectech_test_pool;

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO isectech_pool;
GRANT USAGE ON SCHEMA public TO isectech_analytics_pool;
GRANT USAGE ON SCHEMA public TO isectech_test_pool;

-- Grant table permissions for RBAC
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO isectech_pool;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO isectech_analytics_pool;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO isectech_test_pool;

-- Grant sequence permissions
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO isectech_pool;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO isectech_analytics_pool;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO isectech_test_pool;

-- Grant function execution permissions
GRANT application_role TO isectech_pool;
GRANT application_role TO isectech_analytics_pool;
GRANT application_role TO isectech_test_pool;

-- Allow setting session parameters (important for context management)
GRANT SET ON ALL TABLES IN SCHEMA public TO isectech_pool;
GRANT SET ON ALL TABLES IN SCHEMA public TO isectech_analytics_pool;
GRANT SET ON ALL TABLES IN SCHEMA public TO isectech_test_pool;

-- Create monitoring user for health checks
CREATE USER IF NOT EXISTS pgbouncer_monitor WITH PASSWORD 'monitor_password';
GRANT CONNECT ON DATABASE isectech TO pgbouncer_monitor;
GRANT USAGE ON SCHEMA public TO pgbouncer_monitor;
GRANT SELECT ON pg_stat_database TO pgbouncer_monitor;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO isectech_pool;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO isectech_pool;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO isectech_analytics_pool;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO isectech_analytics_pool;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO isectech_test_pool;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO isectech_test_pool;

-- Enable the users to create and drop temporary tables (required for some operations)
GRANT TEMPORARY ON DATABASE isectech TO isectech_pool;
GRANT TEMPORARY ON DATABASE isectech TO isectech_analytics_pool;
GRANT TEMPORARY ON DATABASE isectech TO isectech_test_pool;

-- Log the setup completion
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL users and roles setup completed successfully';
    RAISE NOTICE 'Pool users created: isectech_pool, isectech_analytics_pool, isectech_test_pool';
    RAISE NOTICE 'Monitor user created: pgbouncer_monitor';
    RAISE NOTICE 'All necessary permissions granted';
END $$;