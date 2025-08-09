-- Seed data for Deception Technology Platform
-- Creates sample canary tokens and decoy data for local demo

SET search_path TO deception, public;

-- Insert sample canary tokens
INSERT INTO canary_tokens (token_id, token_type, token_data, location, tenant_id, active, criticality) VALUES
('aws_key_001', 'aws_access_key', '{"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-east-1"}', 'Production AWS Console', 'demo_tenant', true, 'high'),
('ssh_key_002', 'ssh_private_key', '{"key_type": "rsa", "key_size": 2048, "fingerprint": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"}', 'Development Server /home/admin/.ssh/', 'demo_tenant', true, 'high'),
('api_token_003', 'api_key', '{"token": "sk_test_4eC39HqLyjWDarjtT1zdp7dc", "service": "payment_gateway", "permissions": ["read", "write"]}', 'Production API Gateway', 'demo_tenant', true, 'critical'),
('db_conn_004', 'database_record', '{"host": "prod-db.internal", "username": "admin", "password": "super_secret_123", "database": "customer_data"}', 'Customer Database Config', 'demo_tenant', true, 'critical'),
('email_005', 'email_trap', '{"email": "admin@isectech-internal.com", "name": "System Administrator", "department": "IT Security"}', 'Internal Email Directory', 'demo_tenant', true, 'medium'),
('file_006', 'sensitive_document', '{"filename": "quarterly_financials_2024.pdf", "classification": "confidential", "department": "finance"}', 'Finance Shared Drive', 'demo_tenant', true, 'high'),
('web_beacon_007', 'web_beacon', '{"url": "https://tracking.isectech.com/pixel.gif", "referrer_policy": "no-referrer-when-downgrade"}', 'Company Website Footer', 'demo_tenant', true, 'low'),
('dns_record_008', 'dns_canary', '{"domain": "internal-admin.isectech.com", "record_type": "A", "ip": "192.168.1.100"}', 'Internal DNS Records', 'demo_tenant', true, 'medium'),
('cert_009', 'ssl_certificate', '{"common_name": "*.internal.isectech.com", "issuer": "Internal CA", "expires": "2025-12-31"}', 'Certificate Store', 'demo_tenant', true, 'high'),
('token_010', 'bearer_token', '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example", "service": "internal_api", "scope": "admin"}', 'Internal API Documentation', 'demo_tenant', true, 'high');

-- Insert sample decoy services data
INSERT INTO decoy_services (service_id, service_name, service_type, port, endpoint_path, response_data, tenant_id, active) VALUES
('decoy_001', 'Customer Management Portal', 'web_application', 8080, '/customer-portal', '{"login_page": true, "fake_customers": 50}', 'demo_tenant', true),
('decoy_002', 'Internal API Gateway', 'api_service', 8081, '/api/v1', '{"endpoints": ["/users", "/orders", "/payments"]}', 'demo_tenant', true),
('decoy_003', 'Admin Dashboard', 'web_application', 8082, '/admin', '{"admin_users": 5, "fake_data": true}', 'demo_tenant', true),
('decoy_004', 'Database Console', 'database_interface', 8083, '/db-console', '{"connection_strings": true, "query_interface": true}', 'demo_tenant', true),
('decoy_005', 'File Share Manager', 'file_service', 8084, '/files', '{"directories": 15, "documents": 100}', 'demo_tenant', true),
('decoy_006', 'Monitoring Dashboard', 'monitoring', 8085, '/monitoring', '{"metrics": true, "alerts": true}', 'demo_tenant', true),
('decoy_007', 'Development Tools', 'development', 8086, '/dev-tools', '{"repositories": 20, "ci_cd": true}', 'demo_tenant', true);

-- Insert sample fake customer data for decoy services
INSERT INTO fake_customers (customer_id, name, email, company, phone, address, created_date, tenant_id) VALUES
('cust_001', 'John Smith', 'john.smith@techcorp.com', 'TechCorp Industries', '+1-555-0101', '123 Business Ave, Tech City, TC 12345', '2024-01-15', 'demo_tenant'),
('cust_002', 'Sarah Johnson', 'sarah.j@innovate.com', 'Innovate Solutions', '+1-555-0102', '456 Innovation Dr, Future Town, FT 67890', '2024-01-20', 'demo_tenant'),
('cust_003', 'Michael Brown', 'mbrown@globaltech.org', 'Global Technology', '+1-555-0103', '789 Global Plaza, Worldwide City, WC 11111', '2024-02-01', 'demo_tenant'),
('cust_004', 'Emily Davis', 'emily@startupx.io', 'StartupX', '+1-555-0104', '321 Startup Blvd, Venture Valley, VV 22222', '2024-02-15', 'demo_tenant'),
('cust_005', 'Robert Wilson', 'rwilson@enterprise.net', 'Enterprise Networks', '+1-555-0105', '654 Enterprise Way, Business Park, BP 33333', '2024-03-01', 'demo_tenant');

-- Insert sample employee data for HR decoy service
INSERT INTO fake_employees (employee_id, name, email, department, title, salary, hire_date, tenant_id) VALUES
('emp_001', 'Alex Thompson', 'athompson@isectech.com', 'Engineering', 'Senior Software Engineer', 95000, '2022-03-15', 'demo_tenant'),
('emp_002', 'Jennifer Liu', 'jliu@isectech.com', 'Security', 'Security Analyst', 85000, '2023-01-10', 'demo_tenant'),
('emp_003', 'David Rodriguez', 'drodriguez@isectech.com', 'DevOps', 'DevOps Engineer', 90000, '2022-11-20', 'demo_tenant'),
('emp_004', 'Lisa Chen', 'lchen@isectech.com', 'Product', 'Product Manager', 110000, '2021-08-05', 'demo_tenant'),
('emp_005', 'Mark Anderson', 'manderson@isectech.com', 'Finance', 'Financial Analyst', 75000, '2023-06-12', 'demo_tenant');

-- Insert sample financial records for finance decoy service
INSERT INTO fake_financial_records (record_id, account_name, amount, transaction_type, transaction_date, description, tenant_id) VALUES
('fin_001', 'Operating Revenue', 150000.00, 'credit', '2024-01-31', 'Q1 Software License Revenue', 'demo_tenant'),
('fin_002', 'R&D Expenses', -45000.00, 'debit', '2024-01-31', 'Q1 Research and Development Costs', 'demo_tenant'),
('fin_003', 'Marketing Budget', -25000.00, 'debit', '2024-01-31', 'Q1 Marketing Campaign Expenses', 'demo_tenant'),
('fin_004', 'Infrastructure Costs', -15000.00, 'debit', '2024-01-31', 'Q1 Cloud Infrastructure Costs', 'demo_tenant'),
('fin_005', 'Personnel Costs', -80000.00, 'debit', '2024-01-31', 'Q1 Employee Salaries and Benefits', 'demo_tenant');

-- Update statistics
ANALYZE canary_tokens;
ANALYZE canary_triggers;
ANALYZE decoy_services;
ANALYZE fake_customers;
ANALYZE fake_employees;
ANALYZE fake_financial_records;

-- Create a demo user for testing
INSERT INTO demo_users (user_id, username, password_hash, role, tenant_id, created_at) VALUES
('demo_user_001', 'demo@isectech.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj7/1KE.1234', 'admin', 'demo_tenant', CURRENT_TIMESTAMP);

COMMIT;