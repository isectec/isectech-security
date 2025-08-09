/**
 * Decoy Service Manager
 * 
 * Creates and manages realistic decoy services and databases with plausible
 * but non-sensitive data to engage attackers and gather intelligence.
 */

const express = require('express');
const { Pool } = require('pg');
const redis = require('redis');
const crypto = require('crypto');
const faker = require('@faker-js/faker');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const path = require('path');
const fs = require('fs').promises;

class DecoyServiceManager {
    constructor(config = {}) {
        this.config = {
            port: config.port || process.env.DECOY_PORT || 3001,
            dbUrl: config.dbUrl || process.env.DECOY_DATABASE_URL,
            redisUrl: config.redisUrl || process.env.REDIS_URL,
            alertWebhook: config.alertWebhook || process.env.DECEPTION_ALERT_WEBHOOK,
            jwtSecret: config.jwtSecret || 'decoy_secret_key_123',
            logLevel: config.logLevel || 'info',
            services: {
                customerPortal: true,
                internalApi: true,
                adminDashboard: true,
                fileServer: true,
                databaseApi: true,
                analyticsService: true,
                backupService: true,
                ...config.services
            },
            ...config
        };
        
        this.app = express();
        this.postgres = null;
        this.redis = null;
        this.logger = this.setupLogger();
        this.decoyData = new Map();
        this.interactionLog = [];
    }
    
    setupLogger() {
        return winston.createLogger({
            level: this.config.logLevel,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            transports: [
                new winston.transports.Console(),
                new winston.transports.File({ 
                    filename: path.join(__dirname, '..', 'logs', 'decoy-service.log')
                })
            ]
        });
    }
    
    async initialize() {
        // Initialize database connections
        if (this.config.dbUrl) {
            this.postgres = new Pool({ connectionString: this.config.dbUrl });
            await this.createDecoyDatabases();
        }
        
        if (this.config.redisUrl) {
            this.redis = redis.createClient({ url: this.config.redisUrl });
            await this.redis.connect();
        }
        
        // Generate decoy data
        await this.generateDecoyData();
        
        // Setup middleware
        this.setupMiddleware();
        
        // Setup decoy services
        if (this.config.services.customerPortal) this.setupCustomerPortal();
        if (this.config.services.internalApi) this.setupInternalApi();
        if (this.config.services.adminDashboard) this.setupAdminDashboard();
        if (this.config.services.fileServer) this.setupFileServer();
        if (this.config.services.databaseApi) this.setupDatabaseApi();
        if (this.config.services.analyticsService) this.setupAnalyticsService();
        if (this.config.services.backupService) this.setupBackupService();
        
        // Start server
        this.server = this.app.listen(this.config.port, () => {
            this.logger.info(`Decoy services running on port ${this.config.port}`);
        });
        
        this.logger.info('Decoy Service Manager initialized');
    }
    
    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        
        // Log all interactions
        this.app.use((req, res, next) => {
            const interaction = {
                timestamp: new Date().toISOString(),
                ip: req.ip || req.connection.remoteAddress,
                userAgent: req.get('User-Agent'),
                method: req.method,
                url: req.url,
                headers: req.headers,
                body: req.body,
                sessionId: crypto.randomUUID()
            };
            
            this.logInteraction(interaction);
            req.deceptionSession = interaction.sessionId;
            next();
        });
        
        // Add realistic response delays
        this.app.use((req, res, next) => {
            const delay = Math.random() * 200 + 100; // 100-300ms delay
            setTimeout(next, delay);
        });
    }
    
    async createDecoyDatabases() {
        const createTablesQuery = `
            -- Customers table with realistic fake data
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                api_key VARCHAR(64),
                is_premium BOOLEAN DEFAULT FALSE
            );
            
            -- Users table for employee records
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT FALSE
            );
            
            -- Financial records
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
                transaction_date TIMESTAMP,
                processed_by INTEGER REFERENCES decoy_users(id),
                classification VARCHAR(20) DEFAULT 'RESTRICTED',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- System logs (fake)
            CREATE TABLE IF NOT EXISTS decoy_system_logs (
                id SERIAL PRIMARY KEY,
                log_level VARCHAR(10),
                service_name VARCHAR(100),
                message TEXT,
                user_id INTEGER REFERENCES decoy_users(id),
                ip_address INET,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                request_id VARCHAR(64),
                metadata JSONB
            );
            
            -- API tokens
            CREATE TABLE IF NOT EXISTS decoy_api_tokens (
                id SERIAL PRIMARY KEY,
                token_name VARCHAR(100),
                token_value VARCHAR(255) UNIQUE NOT NULL,
                user_id INTEGER REFERENCES decoy_users(id),
                scopes TEXT[],
                expires_at TIMESTAMP,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            );
            
            -- Backup records
            CREATE TABLE IF NOT EXISTS decoy_backups (
                id SERIAL PRIMARY KEY,
                backup_name VARCHAR(255),
                backup_type VARCHAR(50),
                file_path TEXT,
                size_bytes BIGINT,
                checksum VARCHAR(64),
                encryption_key VARCHAR(255),
                created_by INTEGER REFERENCES decoy_users(id),
                backup_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                restore_tested BOOLEAN DEFAULT FALSE,
                retention_policy VARCHAR(50),
                classification VARCHAR(20) DEFAULT 'INTERNAL'
            );
        `;
        
        try {
            await this.postgres.query(createTablesQuery);
            this.logger.info('Decoy database tables created successfully');
        } catch (error) {
            this.logger.error('Error creating decoy tables:', error);
        }
    }
    
    async generateDecoyData() {
        this.logger.info('Generating realistic decoy data...');
        
        // Generate fake customer data
        const customers = [];
        for (let i = 0; i < 50; i++) {
            customers.push({
                customer_id: `CUST-${String(i + 1000).padStart(4, '0')}`,
                company_name: faker.company.name(),
                contact_name: faker.person.fullName(),
                email: faker.internet.email(),
                phone: faker.phone.number(),
                industry: faker.commerce.department(),
                annual_revenue: parseFloat((Math.random() * 10000000 + 100000).toFixed(2)),
                employee_count: Math.floor(Math.random() * 1000) + 10,
                last_login: faker.date.recent(),
                api_key: `api_${crypto.randomBytes(16).toString('hex')}`,
                is_premium: Math.random() < 0.3
            });
        }
        
        // Generate fake employee data
        const users = [];
        const departments = ['Engineering', 'Sales', 'Marketing', 'Finance', 'HR', 'Operations', 'Security'];
        const positions = ['Manager', 'Senior Developer', 'Analyst', 'Director', 'Specialist', 'Coordinator'];
        
        for (let i = 0; i < 25; i++) {
            const firstName = faker.person.firstName();
            const lastName = faker.person.lastName();
            users.push({
                employee_id: `EMP-${String(i + 1000).padStart(4, '0')}`,
                username: faker.internet.userName({ firstName, lastName }),
                email: faker.internet.email({ firstName, lastName }),
                password_hash: await bcrypt.hash('DefaultPass123!', 10),
                first_name: firstName,
                last_name: lastName,
                department: departments[Math.floor(Math.random() * departments.length)],
                position: positions[Math.floor(Math.random() * positions.length)],
                salary: parseFloat((Math.random() * 100000 + 50000).toFixed(2)),
                ssn: faker.phone.number('###-##-####'), // Fake SSN format
                hire_date: faker.date.past(),
                access_level: Math.floor(Math.random() * 5) + 1,
                security_clearance: ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'SECRET'][Math.floor(Math.random() * 4)],
                last_login: faker.date.recent()
            });
        }
        
        // Generate financial records
        const financialRecords = [];
        for (let i = 0; i < 100; i++) {
            financialRecords.push({
                record_id: `FIN-${String(i + 10000).padStart(5, '0')}`,
                customer_id: customers[Math.floor(Math.random() * customers.length)].customer_id,
                transaction_type: ['PAYMENT', 'REFUND', 'CHARGE', 'TRANSFER'][Math.floor(Math.random() * 4)],
                amount: parseFloat((Math.random() * 50000 + 100).toFixed(2)),
                description: faker.finance.transactionDescription(),
                account_number: faker.finance.accountNumber(),
                routing_number: faker.finance.routingNumber(),
                transaction_date: faker.date.recent(),
                processed_by: Math.floor(Math.random() * users.length) + 1
            });
        }
        
        // Store in PostgreSQL
        if (this.postgres) {
            try {
                // Insert customers
                for (const customer of customers) {
                    await this.postgres.query(
                        'INSERT INTO decoy_customers (customer_id, company_name, contact_name, email, phone, industry, annual_revenue, employee_count, last_login, api_key, is_premium) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (customer_id) DO NOTHING',
                        [customer.customer_id, customer.company_name, customer.contact_name, customer.email, customer.phone, customer.industry, customer.annual_revenue, customer.employee_count, customer.last_login, customer.api_key, customer.is_premium]
                    );
                }
                
                // Insert users
                for (const user of users) {
                    await this.postgres.query(
                        'INSERT INTO decoy_users (employee_id, username, email, password_hash, first_name, last_name, department, position, salary, ssn, hire_date, access_level, security_clearance, last_login) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) ON CONFLICT (employee_id) DO NOTHING',
                        [user.employee_id, user.username, user.email, user.password_hash, user.first_name, user.last_name, user.department, user.position, user.salary, user.ssn, user.hire_date, user.access_level, user.security_clearance, user.last_login]
                    );
                }
                
                // Insert financial records
                for (const record of financialRecords) {
                    await this.postgres.query(
                        'INSERT INTO decoy_financial_records (record_id, customer_id, transaction_type, amount, description, account_number, routing_number, transaction_date, processed_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (record_id) DO NOTHING',
                        [record.record_id, record.customer_id, record.transaction_type, record.amount, record.description, record.account_number, record.routing_number, record.transaction_date, record.processed_by]
                    );
                }
                
                this.logger.info(`Generated ${customers.length} customers, ${users.length} users, and ${financialRecords.length} financial records`);
            } catch (error) {
                this.logger.error('Error inserting decoy data:', error);
            }
        }
        
        // Store in memory for API responses
        this.decoyData.set('customers', customers);
        this.decoyData.set('users', users);
        this.decoyData.set('financialRecords', financialRecords);
    }
    
    setupCustomerPortal() {
        this.logger.info('Setting up Customer Portal decoy service');
        
        // Customer login page
        this.app.get('/customer/login', (req, res) => {
            this.sendHtmlResponse(req, res, `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>iSECTECH Customer Portal</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 50px; }
                        .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .logo { text-align: center; color: #1a73e8; font-size: 24px; font-weight: bold; margin-bottom: 30px; }
                        .form-group { margin-bottom: 20px; }
                        label { display: block; margin-bottom: 5px; font-weight: bold; }
                        input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; }
                        .btn { background: #1a73e8; color: white; padding: 12px 30px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; }
                        .btn:hover { background: #1557b0; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="logo">🔒 iSECTECH</div>
                        <h2>Customer Portal Login</h2>
                        <form action="/customer/authenticate" method="post">
                            <div class="form-group">
                                <label for="customer_id">Customer ID:</label>
                                <input type="text" id="customer_id" name="customer_id" placeholder="CUST-XXXX" required>
                            </div>
                            <div class="form-group">
                                <label for="api_key">API Key:</label>
                                <input type="password" id="api_key" name="api_key" placeholder="Enter your API key" required>
                            </div>
                            <button type="submit" class="btn">Access Portal</button>
                        </form>
                    </div>
                </body>
                </html>
            `);
        });
        
        // Customer authentication (always successful for decoy)
        this.app.post('/customer/authenticate', async (req, res) => {
            const { customer_id, api_key } = req.body;
            
            this.logSuspiciousActivity(req, 'CUSTOMER_LOGIN_ATTEMPT', {
                customer_id,
                api_key: api_key.substring(0, 8) + '...'
            });
            
            // Simulate authentication delay
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            const token = jwt.sign({ customer_id, type: 'customer' }, this.config.jwtSecret, { expiresIn: '1h' });
            
            res.json({
                success: true,
                token,
                message: 'Authentication successful',
                dashboard_url: '/customer/dashboard'
            });
        });
        
        // Customer dashboard
        this.app.get('/customer/dashboard', (req, res) => {
            const customers = this.decoyData.get('customers') || [];
            const sampleCustomer = customers[0] || { company_name: 'Sample Corp' };
            
            this.sendHtmlResponse(req, res, `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Customer Dashboard - iSECTECH</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; background: #f8f9fa; }
                        .header { background: #1a73e8; color: white; padding: 20px; }
                        .container { padding: 30px; }
                        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                        .stat { display: inline-block; margin-right: 30px; }
                        .stat-value { font-size: 24px; font-weight: bold; color: #1a73e8; }
                        .stat-label { color: #666; }
                        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                        th { background: #f5f5f5; font-weight: bold; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>📊 Customer Dashboard</h1>
                        <p>Welcome back, ${sampleCustomer.company_name}</p>
                    </div>
                    <div class="container">
                        <div class="card">
                            <h3>Account Overview</h3>
                            <div class="stat">
                                <div class="stat-value">$125,430</div>
                                <div class="stat-label">Current Balance</div>
                            </div>
                            <div class="stat">
                                <div class="stat-value">23</div>
                                <div class="stat-label">Active Services</div>
                            </div>
                            <div class="stat">
                                <div class="stat-value">98.9%</div>
                                <div class="stat-label">Uptime</div>
                            </div>
                        </div>
                        <div class="card">
                            <h3>🚨 Recent Security Alerts</h3>
                            <table>
                                <tr><th>Date</th><th>Alert</th><th>Status</th></tr>
                                <tr><td>2024-01-15</td><td>Suspicious login from new location</td><td>Resolved</td></tr>
                                <tr><td>2024-01-14</td><td>API rate limit exceeded</td><td>Investigating</td></tr>
                                <tr><td>2024-01-13</td><td>Unusual data access pattern</td><td>Resolved</td></tr>
                            </table>
                        </div>
                    </div>
                </body>
                </html>
            `);
        });
    }
    
    setupInternalApi() {
        this.logger.info('Setting up Internal API decoy service');
        
        // User listing endpoint
        this.app.get('/api/internal/users', async (req, res) => {
            this.logSuspiciousActivity(req, 'INTERNAL_API_ACCESS', { endpoint: '/users' });
            
            const users = await this.postgres.query(
                'SELECT employee_id, username, email, first_name, last_name, department, position, access_level FROM decoy_users LIMIT 10'
            );
            
            res.json({
                success: true,
                count: users.rowCount,
                data: users.rows,
                timestamp: new Date().toISOString()
            });
        });
        
        // Customer data endpoint  
        this.app.get('/api/internal/customers', async (req, res) => {
            this.logSuspiciousActivity(req, 'INTERNAL_API_ACCESS', { endpoint: '/customers' });
            
            const customers = await this.postgres.query(
                'SELECT customer_id, company_name, contact_name, email, industry, annual_revenue FROM decoy_customers LIMIT 10'
            );
            
            res.json({
                success: true,
                count: customers.rowCount,
                data: customers.rows,
                timestamp: new Date().toISOString()
            });
        });
        
        // Financial records endpoint
        this.app.get('/api/internal/financial', async (req, res) => {
            this.logSuspiciousActivity(req, 'FINANCIAL_DATA_ACCESS', { endpoint: '/financial', severity: 'HIGH' });
            
            const records = await this.postgres.query(
                'SELECT record_id, transaction_type, amount, currency, account_number, transaction_date FROM decoy_financial_records ORDER BY transaction_date DESC LIMIT 20'
            );
            
            res.json({
                success: true,
                count: records.rowCount,
                data: records.rows,
                classification: 'RESTRICTED',
                timestamp: new Date().toISOString()
            });
        });
        
        // System status endpoint
        this.app.get('/api/internal/status', (req, res) => {
            res.json({
                status: 'operational',
                services: {
                    database: 'healthy',
                    cache: 'healthy',
                    api_gateway: 'healthy',
                    authentication: 'healthy'
                },
                uptime: '99.97%',
                last_backup: '2024-01-15T02:00:00Z',
                version: '2.4.1',
                environment: 'production'
            });
        });
    }
    
    setupAdminDashboard() {
        this.logger.info('Setting up Admin Dashboard decoy service');
        
        // Admin login
        this.app.get('/admin', (req, res) => {
            this.sendHtmlResponse(req, res, `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Admin Dashboard - iSECTECH</title>
                    <style>
                        body { font-family: Arial, sans-serif; background: #1a1a1a; color: white; margin: 0; padding: 50px; }
                        .container { max-width: 500px; margin: 0 auto; background: #2d2d2d; padding: 40px; border-radius: 8px; border: 1px solid #444; }
                        .logo { text-align: center; color: #ff6b35; font-size: 28px; font-weight: bold; margin-bottom: 30px; }
                        .warning { background: #ff4444; color: white; padding: 15px; border-radius: 4px; margin-bottom: 30px; text-align: center; }
                        input { width: 100%; padding: 12px; margin-bottom: 15px; background: #444; border: 1px solid #666; color: white; border-radius: 4px; }
                        .btn { background: #ff6b35; color: white; padding: 15px 30px; border: none; border-radius: 4px; cursor: pointer; width: 100%; font-size: 16px; font-weight: bold; }
                        .btn:hover { background: #e55a2e; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="logo">⚡ ADMIN PORTAL</div>
                        <div class="warning">⚠️ RESTRICTED ACCESS - AUTHORIZED PERSONNEL ONLY</div>
                        <form action="/admin/authenticate" method="post">
                            <input type="text" name="username" placeholder="Administrator Username" required>
                            <input type="password" name="password" placeholder="Administrator Password" required>
                            <input type="text" name="security_code" placeholder="2FA Security Code" required>
                            <button type="submit" class="btn">🔓 ADMIN ACCESS</button>
                        </form>
                    </div>
                </body>
                </html>
            `);
        });
        
        // Admin authentication
        this.app.post('/admin/authenticate', async (req, res) => {
            const { username, password, security_code } = req.body;
            
            this.logSuspiciousActivity(req, 'ADMIN_LOGIN_ATTEMPT', {
                username,
                security_code,
                severity: 'CRITICAL'
            });
            
            // Always "authenticate" for honeypot effect
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            res.json({
                success: true,
                message: 'Admin authentication successful',
                redirect: '/admin/dashboard',
                session_token: crypto.randomBytes(32).toString('hex')
            });
        });
        
        // Admin dashboard
        this.app.get('/admin/dashboard', (req, res) => {
            this.logSuspiciousActivity(req, 'ADMIN_DASHBOARD_ACCESS', { severity: 'CRITICAL' });
            
            this.sendHtmlResponse(req, res, `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>System Administration - iSECTECH</title>
                    <style>
                        body { font-family: 'Courier New', monospace; background: #000; color: #00ff00; margin: 0; padding: 20px; }
                        .terminal { background: #111; padding: 20px; border: 1px solid #333; border-radius: 4px; }
                        .prompt { color: #00ff00; }
                        .command { color: #ffff00; }
                        .output { color: #ffffff; margin-left: 20px; }
                        .menu { margin: 20px 0; }
                        .menu a { color: #00ffff; text-decoration: none; margin-right: 20px; }
                        .menu a:hover { color: #ffffff; }
                        .critical { color: #ff0000; font-weight: bold; }
                    </style>
                </head>
                <body>
                    <div class="terminal">
                        <h1>🔧 SYSTEM ADMINISTRATION CONSOLE</h1>
                        <div class="menu">
                            <a href="/admin/users">👥 User Management</a>
                            <a href="/admin/logs">📋 System Logs</a>
                            <a href="/admin/backups">💾 Backup Management</a>
                            <a href="/admin/security">🛡️ Security Settings</a>
                        </div>
                        <div class="prompt">root@isectech-prod:~$ <span class="command">systemctl status --all</span></div>
                        <div class="output">
                            ● postgresql.service - PostgreSQL database server<br>
                            &nbsp;&nbsp;&nbsp;Loaded: loaded (/lib/systemd/system/postgresql.service; enabled)<br>
                            &nbsp;&nbsp;&nbsp;Active: active (running) since Mon 2024-01-15 08:30:22 UTC<br>
                            <br>
                            ● redis.service - Advanced key-value store<br>
                            &nbsp;&nbsp;&nbsp;Active: active (running)<br>
                            <br>
                            <span class="critical">● backup.service - CRITICAL: Last backup failed</span><br>
                            &nbsp;&nbsp;&nbsp;Active: failed (Result: exit-code)<br>
                        </div>
                        <div class="prompt">root@isectech-prod:~$ <span class="command">cat /etc/shadow | head -5</span></div>
                        <div class="output critical">
                            root:$6$salt$encrypted_hash_here:18000:0:99999:7:::<br>
                            admin:$6$salt$another_hash_here:18000:0:99999:7:::<br>
                            postgres:*:18000:0:99999:7:::<br>
                        </div>
                    </div>
                </body>
                </html>
            `);
        });
    }
    
    setupFileServer() {
        this.logger.info('Setting up File Server decoy service');
        
        // File browser
        this.app.get('/files', (req, res) => {
            this.sendHtmlResponse(req, res, `
                <!DOCTYPE html>
                <html>
                <head>
                    <title>iSECTECH File Server</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; background: #f0f0f0; }
                        .header { background: #2c3e50; color: white; padding: 20px; }
                        .breadcrumb { background: #ecf0f1; padding: 10px 20px; border-bottom: 1px solid #bdc3c7; }
                        .file-list { padding: 20px; }
                        .file-item { padding: 12px; border-bottom: 1px solid #eee; display: flex; align-items: center; }
                        .file-item:hover { background: #f8f9fa; }
                        .file-icon { margin-right: 15px; font-size: 20px; }
                        .file-name { flex: 1; }
                        .file-size { color: #666; margin-left: 20px; }
                        .file-date { color: #666; margin-left: 20px; }
                        .restricted { color: #e74c3c; font-weight: bold; }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>📁 iSECTECH File Server</h1>
                        <p>Internal document repository</p>
                    </div>
                    <div class="breadcrumb">
                        🏠 Home > Documents > Confidential
                    </div>
                    <div class="file-list">
                        <div class="file-item">
                            <div class="file-icon">📄</div>
                            <div class="file-name">Q4_Financial_Report_CONFIDENTIAL.pdf</div>
                            <div class="file-size">2.4 MB</div>
                            <div class="file-date">2024-01-10</div>
                        </div>
                        <div class="file-item">
                            <div class="file-icon">📊</div>
                            <div class="file-name">Customer_Database_Export.xlsx</div>
                            <div class="file-size">15.8 MB</div>
                            <div class="file-date">2024-01-08</div>
                        </div>
                        <div class="file-item">
                            <div class="file-icon">🔒</div>
                            <div class="file-name restricted">Security_Audit_Results_2024.docx</div>
                            <div class="file-size">892 KB</div>
                            <div class="file-date">2024-01-12</div>
                        </div>
                        <div class="file-item">
                            <div class="file-icon">💾</div>
                            <div class="file-name">backup_production_db_20240115.sql.gz</div>
                            <div class="file-size">234 MB</div>
                            <div class="file-date">2024-01-15</div>
                        </div>
                        <div class="file-item">
                            <div class="file-icon">🗝️</div>
                            <div class="file-name restricted">API_Keys_and_Secrets.txt</div>
                            <div class="file-size">1.2 KB</div>
                            <div class="file-date">2024-01-05</div>
                        </div>
                    </div>
                </body>
                </html>
            `);
        });
        
        // File download (triggers alert)
        this.app.get('/files/download/:filename', (req, res) => {
            const filename = req.params.filename;
            
            this.logSuspiciousActivity(req, 'FILE_DOWNLOAD_ATTEMPT', {
                filename,
                severity: filename.includes('CONFIDENTIAL') || filename.includes('secrets') ? 'CRITICAL' : 'HIGH'
            });
            
            // Generate fake file content
            const fakeContent = `CONFIDENTIAL DOCUMENT - ${filename}
            
This document contains sensitive information about iSECTECH operations.
            
Document ID: ${crypto.randomUUID()}
Classification: RESTRICTED
Generated: ${new Date().toISOString()}
            
[This is a decoy document used for security monitoring]
            `;
            
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.send(Buffer.from(fakeContent));
        });
    }
    
    setupDatabaseApi() {
        this.logger.info('Setting up Database API decoy service');
        
        // Database query endpoint
        this.app.post('/db/query', express.text(), async (req, res) => {
            const query = req.body;
            
            this.logSuspiciousActivity(req, 'DATABASE_QUERY_ATTEMPT', {
                query: query.substring(0, 200),
                severity: 'HIGH'
            });
            
            // Simulate database response
            if (query.toLowerCase().includes('select')) {
                res.json({
                    success: true,
                    rows: [
                        { id: 1, name: 'Sample Data', value: 'Confidential Info' },
                        { id: 2, name: 'Test Record', value: 'Restricted Access' }
                    ],
                    execution_time: '0.023s'
                });
            } else {
                res.json({
                    success: true,
                    message: 'Query executed successfully',
                    affected_rows: Math.floor(Math.random() * 10) + 1
                });
            }
        });
    }
    
    setupAnalyticsService() {
        this.logger.info('Setting up Analytics Service decoy service');
        
        this.app.get('/analytics/dashboard', (req, res) => {
            res.json({
                revenue: {
                    current_month: 1250000,
                    last_month: 1180000,
                    growth: 5.9
                },
                customers: {
                    total: 1247,
                    active: 1198,
                    churn_rate: 2.3
                },
                security_metrics: {
                    threats_detected: 23,
                    incidents_resolved: 19,
                    avg_response_time: '4.2 minutes'
                },
                classification: 'BUSINESS_CONFIDENTIAL'
            });
        });
    }
    
    setupBackupService() {
        this.logger.info('Setting up Backup Service decoy service');
        
        this.app.get('/backups/list', async (req, res) => {
            this.logSuspiciousActivity(req, 'BACKUP_ACCESS_ATTEMPT', { severity: 'HIGH' });
            
            const backups = await this.postgres.query(
                'SELECT backup_name, backup_type, size_bytes, backup_date, encryption_key FROM decoy_backups ORDER BY backup_date DESC LIMIT 10'
            );
            
            res.json({
                success: true,
                backups: backups.rows,
                storage_location: 's3://isectech-backups-confidential/',
                retention_policy: '7 years',
                encryption: 'AES-256'
            });
        });
    }
    
    logInteraction(interaction) {
        this.interactionLog.push(interaction);
        
        // Keep only last 1000 interactions in memory
        if (this.interactionLog.length > 1000) {
            this.interactionLog = this.interactionLog.slice(-1000);
        }
        
        this.logger.info('Decoy interaction logged', {
            sessionId: interaction.sessionId,
            method: interaction.method,
            url: interaction.url,
            ip: interaction.ip
        });
    }
    
    async logSuspiciousActivity(req, activityType, details = {}) {
        const alert = {
            timestamp: new Date().toISOString(),
            type: 'DECOY_SERVICE_ACCESS',
            activity: activityType,
            severity: details.severity || 'MEDIUM',
            source_ip: req.ip || req.connection.remoteAddress,
            user_agent: req.get('User-Agent'),
            url: req.url,
            method: req.method,
            session_id: req.deceptionSession,
            details,
            recommendations: this.getResponseRecommendations(activityType)
        };
        
        // Store in database
        if (this.postgres) {
            try {
                await this.postgres.query(
                    'INSERT INTO decoy_system_logs (log_level, service_name, message, ip_address, request_id, metadata) VALUES ($1, $2, $3, $4, $5, $6)',
                    ['ALERT', 'decoy_service', `${activityType}: ${JSON.stringify(details)}`, alert.source_ip, alert.session_id, JSON.stringify(alert)]
                );
            } catch (error) {
                this.logger.error('Error logging to database:', error);
            }
        }
        
        // Send webhook alert
        if (this.config.alertWebhook) {
            try {
                await fetch(this.config.alertWebhook, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(alert)
                });
            } catch (error) {
                this.logger.error('Error sending webhook alert:', error);
            }
        }
        
        this.logger.warn('Suspicious activity detected', alert);
    }
    
    getResponseRecommendations(activityType) {
        const recommendations = {
            'CUSTOMER_LOGIN_ATTEMPT': [
                'Verify customer identity through alternate channels',
                'Check if customer ID and API key are legitimate',
                'Monitor source IP for additional suspicious activity'
            ],
            'INTERNAL_API_ACCESS': [
                'Immediately investigate source of API access',
                'Review API authentication logs',
                'Check if accessing IP is from internal network',
                'Verify user permissions for accessed endpoints'
            ],
            'ADMIN_LOGIN_ATTEMPT': [
                'CRITICAL: Immediate investigation required',
                'Block source IP pending investigation',
                'Alert security team immediately',
                'Review all recent admin access attempts',
                'Check for credential compromise'
            ],
            'FINANCIAL_DATA_ACCESS': [
                'CRITICAL: Potential data breach',
                'Immediately audit financial data access',
                'Notify compliance team',
                'Review data loss prevention policies',
                'Consider temporary access restrictions'
            ],
            'FILE_DOWNLOAD_ATTEMPT': [
                'Monitor for data exfiltration attempts',
                'Review file access permissions',
                'Check if user has legitimate need for file',
                'Consider watermarking sensitive documents'
            ]
        };
        
        return recommendations[activityType] || [
            'Monitor source IP for additional activity',
            'Review access logs for patterns',
            'Consider additional security measures'
        ];
    }
    
    sendHtmlResponse(req, res, html) {
        // Log HTML page access
        this.logInteraction({
            timestamp: new Date().toISOString(),
            sessionId: req.deceptionSession,
            type: 'HTML_PAGE_ACCESS',
            url: req.url,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });
        
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('X-Powered-By', 'iSECTECH-Portal/2.1.0');
        res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
        res.send(html);
    }
    
    async getInteractionStats() {
        return {
            total_interactions: this.interactionLog.length,
            unique_ips: [...new Set(this.interactionLog.map(i => i.ip))].length,
            most_accessed_endpoints: this.getMostAccessedEndpoints(),
            suspicious_activities: await this.getSuspiciousActivityCount(),
            last_24_hours: this.interactionLog.filter(
                i => new Date(i.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
            ).length
        };
    }
    
    getMostAccessedEndpoints() {
        const endpoints = {};
        this.interactionLog.forEach(interaction => {
            const endpoint = interaction.url || 'unknown';
            endpoints[endpoint] = (endpoints[endpoint] || 0) + 1;
        });
        
        return Object.entries(endpoints)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .map(([endpoint, count]) => ({ endpoint, count }));
    }
    
    async getSuspiciousActivityCount() {
        if (!this.postgres) return 0;
        
        try {
            const result = await this.postgres.query(
                "SELECT COUNT(*) FROM decoy_system_logs WHERE log_level = 'ALERT' AND timestamp > NOW() - INTERVAL '24 hours'"
            );
            return parseInt(result.rows[0].count);
        } catch (error) {
            return 0;
        }
    }
    
    async shutdown() {
        if (this.server) {
            this.server.close();
        }
        if (this.postgres) {
            await this.postgres.end();
        }
        if (this.redis) {
            await this.redis.disconnect();
        }
        this.logger.info('Decoy Service Manager shutdown complete');
    }
}

module.exports = DecoyServiceManager;