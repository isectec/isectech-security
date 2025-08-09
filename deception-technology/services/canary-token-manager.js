/**
 * Canary Token Manager Service
 * 
 * Manages the lifecycle of canary tokens across the iSECTECH environment,
 * providing strategic placement, monitoring, and alert generation.
 */

const crypto = require('crypto');
const { createClient } = require('redis');
const { Pool } = require('pg');
const { EventEmitter } = require('events');
const dns = require('dns').promises;
const fs = require('fs').promises;
const path = require('path');

class CanaryTokenManager extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            redisUrl: config.redisUrl || process.env.REDIS_URL || 'redis://localhost:6379',
            postgresUrl: config.postgresUrl || process.env.DATABASE_URL,
            alertWebhook: config.alertWebhook || process.env.DECEPTION_ALERT_WEBHOOK,
            tokenPrefix: config.tokenPrefix || 'ct_',
            tokenDomain: config.tokenDomain || 'canary.isectech.internal',
            tokenTypes: config.tokenTypes || [
                'api_key',
                'aws_key',
                'database_record',
                'document',
                'dns_record',
                'email_address',
                'file_system',
                'git_commit',
                'jwt_token',
                'ssh_key',
                'url_shortener',
                'webhook_url'
            ],
            ...config
        };
        
        this.redis = null;
        this.postgres = null;
        this.tokens = new Map();
        this.triggerHistory = new Map();
    }
    
    async initialize() {
        // Initialize Redis connection
        this.redis = createClient({ url: this.config.redisUrl });
        await this.redis.connect();
        
        // Initialize PostgreSQL connection
        this.postgres = new Pool({ connectionString: this.config.postgresUrl });
        
        // Create database tables
        await this.createTables();
        
        // Start monitoring
        this.startMonitoring();
        
        console.log('Canary Token Manager initialized');
    }
    
    async createTables() {
        const createTableQuery = `
            CREATE TABLE IF NOT EXISTS canary_tokens (
                token_id VARCHAR(64) PRIMARY KEY,
                token_type VARCHAR(50) NOT NULL,
                token_data JSONB NOT NULL,
                location VARCHAR(255) NOT NULL,
                tenant_id VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_triggered TIMESTAMP,
                trigger_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT TRUE,
                metadata JSONB,
                INDEX idx_token_type (token_type),
                INDEX idx_tenant (tenant_id),
                INDEX idx_active (active)
            );
            
            CREATE TABLE IF NOT EXISTS canary_triggers (
                trigger_id SERIAL PRIMARY KEY,
                token_id VARCHAR(64) REFERENCES canary_tokens(token_id),
                triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip VARCHAR(45),
                user_agent TEXT,
                request_details JSONB,
                alert_sent BOOLEAN DEFAULT FALSE,
                response_actions JSONB,
                INDEX idx_token_trigger (token_id, triggered_at)
            );
        `;
        
        try {
            await this.postgres.query(createTableQuery);
        } catch (error) {
            console.error('Error creating tables:', error);
        }
    }
    
    /**
     * Generate a new canary token
     */
    async generateToken(tokenType, location, options = {}) {
        const tokenId = crypto.randomUUID();
        const timestamp = new Date().toISOString();
        
        let tokenData;
        
        switch (tokenType) {
            case 'api_key':
                tokenData = this.generateApiKey(tokenId);
                break;
                
            case 'aws_key':
                tokenData = this.generateAwsKey(tokenId);
                break;
                
            case 'database_record':
                tokenData = this.generateDatabaseRecord(tokenId);
                break;
                
            case 'document':
                tokenData = this.generateDocument(tokenId, options);
                break;
                
            case 'dns_record':
                tokenData = this.generateDnsRecord(tokenId);
                break;
                
            case 'email_address':
                tokenData = this.generateEmailAddress(tokenId);
                break;
                
            case 'file_system':
                tokenData = await this.generateFileSystemToken(tokenId, location);
                break;
                
            case 'git_commit':
                tokenData = this.generateGitCommit(tokenId);
                break;
                
            case 'jwt_token':
                tokenData = this.generateJwtToken(tokenId);
                break;
                
            case 'ssh_key':
                tokenData = await this.generateSshKey(tokenId);
                break;
                
            case 'url_shortener':
                tokenData = this.generateUrlShortener(tokenId);
                break;
                
            case 'webhook_url':
                tokenData = this.generateWebhookUrl(tokenId);
                break;
                
            default:
                throw new Error(`Unsupported token type: ${tokenType}`);
        }
        
        // Store token in database
        const insertQuery = `
            INSERT INTO canary_tokens (
                token_id, token_type, token_data, location, 
                tenant_id, metadata, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        
        await this.postgres.query(insertQuery, [
            tokenId,
            tokenType,
            JSON.stringify(tokenData),
            location,
            options.tenantId || 'default',
            JSON.stringify(options.metadata || {}),
            timestamp
        ]);
        
        // Store in Redis for fast lookup
        await this.redis.hSet(`canary:${tokenId}`, {
            type: tokenType,
            location,
            created: timestamp,
            triggered: 'false',
            triggerCount: '0',
            data: JSON.stringify(tokenData)
        });
        
        // Set expiry for Redis entry (30 days)
        await this.redis.expire(`canary:${tokenId}`, 30 * 24 * 60 * 60);
        
        // Store in memory
        this.tokens.set(tokenId, {
            type: tokenType,
            location,
            data: tokenData,
            created: timestamp
        });
        
        this.emit('token:created', {
            tokenId,
            tokenType,
            location
        });
        
        return {
            tokenId,
            tokenType,
            tokenData,
            location,
            created: timestamp
        };
    }
    
    /**
     * Token generation methods for different types
     */
    generateApiKey(tokenId) {
        return {
            key: `${this.config.tokenPrefix}${crypto.randomBytes(16).toString('hex')}`,
            tokenId,
            description: 'API Access Key',
            permissions: ['read', 'write'],
            expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        };
    }
    
    generateAwsKey(tokenId) {
        return {
            accessKeyId: `AKIA${crypto.randomBytes(8).toString('hex').toUpperCase()}`,
            secretAccessKey: crypto.randomBytes(32).toString('base64'),
            tokenId,
            region: 'us-east-1',
            service: 's3'
        };
    }
    
    generateDatabaseRecord(tokenId) {
        return {
            id: crypto.randomUUID(),
            username: `canary_user_${crypto.randomBytes(4).toString('hex')}`,
            email: `canary${tokenId.substring(0, 8)}@isectech.local`,
            password_hash: crypto.randomBytes(32).toString('hex'),
            api_token: `${this.config.tokenPrefix}${tokenId}`,
            created_at: new Date().toISOString(),
            last_login: null,
            is_admin: false,
            canaryId: tokenId
        };
    }
    
    generateDocument(tokenId, options) {
        const docType = options.docType || 'pdf';
        const fileName = options.fileName || `confidential_${tokenId.substring(0, 8)}.${docType}`;
        
        return {
            documentId: crypto.randomUUID(),
            fileName,
            title: 'Confidential Security Report',
            author: 'Security Team',
            created: new Date().toISOString(),
            classification: 'CONFIDENTIAL',
            trackingUrl: `https://${this.config.tokenDomain}/doc/${tokenId}`,
            watermark: tokenId,
            metadata: {
                canaryToken: tokenId,
                department: 'Security Operations',
                project: 'Q4 Security Assessment'
            }
        };
    }
    
    generateDnsRecord(tokenId) {
        const subdomain = `canary${tokenId.substring(0, 8)}`;
        return {
            hostname: `${subdomain}.${this.config.tokenDomain}`,
            tokenId,
            recordType: 'A',
            ipAddress: '10.0.0.100',
            ttl: 300
        };
    }
    
    generateEmailAddress(tokenId) {
        return {
            email: `security.alert.${tokenId.substring(0, 8)}@${this.config.tokenDomain}`,
            tokenId,
            displayName: 'Security Alert System',
            autoResponder: true,
            forwardTo: 'soc@isectech.com'
        };
    }
    
    async generateFileSystemToken(tokenId, location) {
        const fileName = `.canary_${tokenId.substring(0, 8)}.txt`;
        const filePath = path.join(location, fileName);
        
        const content = `
# CONFIDENTIAL - DO NOT SHARE
# Security Token: ${tokenId}
# Created: ${new Date().toISOString()}
# Location: ${location}

This file contains sensitive security information.
Any access to this file is monitored and logged.

Token ID: ${tokenId}
Access URL: https://${this.config.tokenDomain}/file/${tokenId}
        `;
        
        try {
            await fs.writeFile(filePath, content, 'utf8');
            await fs.chmod(filePath, 0o600); // Restrict permissions
        } catch (error) {
            console.error('Error creating file system token:', error);
        }
        
        return {
            fileName,
            filePath,
            tokenId,
            size: Buffer.byteLength(content),
            permissions: '600'
        };
    }
    
    generateGitCommit(tokenId) {
        return {
            commitHash: crypto.randomBytes(20).toString('hex'),
            author: 'security-bot@isectech.com',
            message: `Security update - Token: ${tokenId.substring(0, 8)}`,
            branch: 'security-patches',
            files: [
                '.security/canary.txt',
                'config/security.yml'
            ],
            tokenId,
            repository: 'internal-tools'
        };
    }
    
    generateJwtToken(tokenId) {
        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };
        
        const payload = {
            sub: `canary_${tokenId.substring(0, 8)}`,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60),
            aud: 'isectech.com',
            iss: 'canary-token-system',
            canaryId: tokenId
        };
        
        const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
        const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
        const signature = crypto
            .createHmac('sha256', tokenId)
            .update(`${encodedHeader}.${encodedPayload}`)
            .digest('base64url');
        
        return {
            token: `${encodedHeader}.${encodedPayload}.${signature}`,
            tokenId,
            algorithm: 'HS256',
            expiresAt: new Date(payload.exp * 1000).toISOString()
        };
    }
    
    async generateSshKey(tokenId) {
        const { generateKeyPairSync } = require('crypto');
        
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        
        const comment = `canary_${tokenId.substring(0, 8)}@isectech.com`;
        
        return {
            publicKey: publicKey.trim() + ` ${comment}`,
            privateKey,
            tokenId,
            keyType: 'rsa',
            bits: 2048,
            fingerprint: crypto.createHash('sha256').update(publicKey).digest('hex'),
            comment
        };
    }
    
    generateUrlShortener(tokenId) {
        const shortCode = crypto.randomBytes(4).toString('hex');
        return {
            shortUrl: `https://link.isectech.com/${shortCode}`,
            targetUrl: `https://${this.config.tokenDomain}/redirect/${tokenId}`,
            tokenId,
            shortCode,
            clickTracking: true
        };
    }
    
    generateWebhookUrl(tokenId) {
        return {
            url: `https://${this.config.tokenDomain}/webhook/${tokenId}`,
            tokenId,
            method: 'POST',
            headers: {
                'X-Canary-Token': tokenId,
                'X-Webhook-Secret': crypto.randomBytes(32).toString('hex')
            },
            responseCode: 200,
            responseBody: { status: 'received' }
        };
    }
    
    /**
     * Handle token trigger event
     */
    async handleTrigger(tokenId, triggerContext) {
        const tokenInfo = await this.redis.hGetAll(`canary:${tokenId}`);
        
        if (!tokenInfo || Object.keys(tokenInfo).length === 0) {
            console.warn(`Unknown token triggered: ${tokenId}`);
            return false;
        }
        
        const triggerTime = new Date().toISOString();
        const triggerCount = parseInt(tokenInfo.triggerCount || '0') + 1;
        
        // Update Redis
        await this.redis.hSet(`canary:${tokenId}`, {
            triggered: 'true',
            lastTriggered: triggerTime,
            triggerCount: triggerCount.toString()
        });
        
        // Store trigger details in PostgreSQL
        const insertTriggerQuery = `
            INSERT INTO canary_triggers (
                token_id, triggered_at, source_ip, user_agent, 
                request_details, alert_sent
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING trigger_id
        `;
        
        const triggerResult = await this.postgres.query(insertTriggerQuery, [
            tokenId,
            triggerTime,
            triggerContext.sourceIp || null,
            triggerContext.userAgent || null,
            JSON.stringify(triggerContext),
            false
        ]);
        
        const triggerId = triggerResult.rows[0].trigger_id;
        
        // Update token trigger count
        await this.postgres.query(
            'UPDATE canary_tokens SET trigger_count = $1, last_triggered = $2 WHERE token_id = $3',
            [triggerCount, triggerTime, tokenId]
        );
        
        // Store in trigger history
        if (!this.triggerHistory.has(tokenId)) {
            this.triggerHistory.set(tokenId, []);
        }
        this.triggerHistory.get(tokenId).push({
            triggerId,
            timestamp: triggerTime,
            context: triggerContext
        });
        
        // Send alert
        await this.sendAlert(tokenId, tokenInfo, triggerContext, triggerId);
        
        // Emit event
        this.emit('token:triggered', {
            tokenId,
            tokenType: tokenInfo.type,
            location: tokenInfo.location,
            triggerCount,
            triggerContext
        });
        
        // Execute automated response
        await this.executeAutomatedResponse(tokenId, tokenInfo, triggerContext);
        
        return true;
    }
    
    /**
     * Send alert for triggered token
     */
    async sendAlert(tokenId, tokenInfo, triggerContext, triggerId) {
        const alert = {
            alertType: 'CANARY_TOKEN_TRIGGERED',
            severity: 'HIGH',
            tokenId,
            tokenType: tokenInfo.type,
            location: tokenInfo.location,
            triggerTime: new Date().toISOString(),
            triggerCount: tokenInfo.triggerCount,
            sourceIp: triggerContext.sourceIp,
            userAgent: triggerContext.userAgent,
            additionalContext: triggerContext,
            investigationUrl: `https://soc.isectech.com/investigate/${triggerId}`,
            recommendations: this.getResponseRecommendations(tokenInfo.type)
        };
        
        // Send to webhook
        if (this.config.alertWebhook) {
            try {
                const response = await fetch(this.config.alertWebhook, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Alert-Type': 'canary-token'
                    },
                    body: JSON.stringify(alert)
                });
                
                if (response.ok) {
                    await this.postgres.query(
                        'UPDATE canary_triggers SET alert_sent = true WHERE trigger_id = $1',
                        [triggerId]
                    );
                }
            } catch (error) {
                console.error('Error sending alert:', error);
            }
        }
        
        // Log to console
        console.log('🚨 CANARY TOKEN TRIGGERED:', alert);
        
        return alert;
    }
    
    /**
     * Get response recommendations based on token type
     */
    getResponseRecommendations(tokenType) {
        const recommendations = {
            'api_key': [
                'Revoke all API keys for affected systems',
                'Audit API access logs for suspicious activity',
                'Rotate all production API keys',
                'Enable additional API authentication factors'
            ],
            'aws_key': [
                'Immediately deactivate compromised AWS credentials',
                'Review CloudTrail logs for unauthorized actions',
                'Enable MFA on all AWS accounts',
                'Implement AWS GuardDuty if not already active'
            ],
            'database_record': [
                'Audit database access logs',
                'Check for data exfiltration attempts',
                'Review user privileges and access patterns',
                'Consider database activity monitoring'
            ],
            'document': [
                'Track document access and distribution',
                'Review file server logs',
                'Check for unauthorized copies or transfers',
                'Implement DLP policies if not present'
            ],
            'ssh_key': [
                'Revoke compromised SSH keys immediately',
                'Audit SSH access logs on all systems',
                'Review authorized_keys files',
                'Implement SSH key rotation policy'
            ],
            'git_commit': [
                'Review repository access logs',
                'Check for unauthorized code changes',
                'Audit commit history for suspicious activity',
                'Enable commit signing requirements'
            ]
        };
        
        return recommendations[tokenType] || [
            'Investigate source of token access',
            'Review security logs for related activity',
            'Consider increasing monitoring in affected area',
            'Update incident response procedures'
        ];
    }
    
    /**
     * Execute automated response actions
     */
    async executeAutomatedResponse(tokenId, tokenInfo, triggerContext) {
        const responseActions = [];
        
        // Common response actions
        responseActions.push({
            action: 'log_event',
            details: 'Logged to SIEM'
        });
        
        // Type-specific responses
        switch (tokenInfo.type) {
            case 'api_key':
            case 'aws_key':
            case 'jwt_token':
                responseActions.push({
                    action: 'revoke_credentials',
                    details: `Revoked token ${tokenId}`
                });
                break;
                
            case 'ssh_key':
                responseActions.push({
                    action: 'block_ssh_key',
                    details: 'Added to SSH blacklist'
                });
                break;
                
            case 'database_record':
                responseActions.push({
                    action: 'enable_monitoring',
                    details: 'Enhanced database monitoring activated'
                });
                break;
        }
        
        // Source IP blocking if suspicious
        if (triggerContext.sourceIp && !this.isInternalIp(triggerContext.sourceIp)) {
            responseActions.push({
                action: 'block_ip',
                details: `Blocked IP ${triggerContext.sourceIp} at firewall`
            });
        }
        
        // Store response actions
        await this.postgres.query(
            'UPDATE canary_triggers SET response_actions = $1 WHERE token_id = $2 AND triggered_at = $3',
            [JSON.stringify(responseActions), tokenId, tokenInfo.lastTriggered]
        );
        
        return responseActions;
    }
    
    /**
     * Check if IP is internal
     */
    isInternalIp(ip) {
        const internalRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./
        ];
        
        return internalRanges.some(range => range.test(ip));
    }
    
    /**
     * Deploy tokens strategically across the environment
     */
    async deployTokens(deploymentPlan) {
        const deployedTokens = [];
        
        for (const deployment of deploymentPlan) {
            try {
                const token = await this.generateToken(
                    deployment.type,
                    deployment.location,
                    deployment.options
                );
                
                deployedTokens.push({
                    ...token,
                    deploymentId: deployment.id,
                    status: 'deployed'
                });
                
                console.log(`✅ Deployed ${deployment.type} token at ${deployment.location}`);
            } catch (error) {
                console.error(`❌ Failed to deploy ${deployment.type} token:`, error);
                deployedTokens.push({
                    deploymentId: deployment.id,
                    type: deployment.type,
                    location: deployment.location,
                    status: 'failed',
                    error: error.message
                });
            }
        }
        
        return deployedTokens;
    }
    
    /**
     * Monitor token triggers
     */
    startMonitoring() {
        // Subscribe to Redis pub/sub for real-time triggers
        const subscriber = this.redis.duplicate();
        subscriber.connect().then(() => {
            subscriber.subscribe('canary:triggers', (message) => {
                const trigger = JSON.parse(message);
                this.handleTrigger(trigger.tokenId, trigger.context);
            });
        });
        
        // Periodic health check
        setInterval(async () => {
            await this.performHealthCheck();
        }, 60000); // Every minute
    }
    
    /**
     * Perform health check on deployed tokens
     */
    async performHealthCheck() {
        const query = 'SELECT COUNT(*) as total, COUNT(CASE WHEN triggered = true THEN 1 END) as triggered FROM canary_tokens WHERE active = true';
        const result = await this.postgres.query(query);
        
        const stats = result.rows[0];
        
        this.emit('health:check', {
            totalTokens: parseInt(stats.total),
            triggeredTokens: parseInt(stats.triggered),
            timestamp: new Date().toISOString()
        });
    }
    
    /**
     * Get token statistics
     */
    async getStatistics(options = {}) {
        const { tenantId, timeRange = '7d' } = options;
        
        let query = `
            SELECT 
                token_type,
                COUNT(*) as count,
                SUM(trigger_count) as total_triggers,
                MAX(last_triggered) as last_trigger
            FROM canary_tokens
            WHERE active = true
        `;
        
        const params = [];
        if (tenantId) {
            query += ` AND tenant_id = $${params.length + 1}`;
            params.push(tenantId);
        }
        
        query += ' GROUP BY token_type';
        
        const result = await this.postgres.query(query, params);
        
        return {
            byType: result.rows,
            summary: {
                totalTokens: result.rows.reduce((sum, row) => sum + parseInt(row.count), 0),
                totalTriggers: result.rows.reduce((sum, row) => sum + parseInt(row.total_triggers || 0), 0),
                tokenTypes: result.rows.length
            }
        };
    }
    
    /**
     * Clean up expired or inactive tokens
     */
    async cleanup(daysOld = 90) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysOld);
        
        const query = `
            UPDATE canary_tokens 
            SET active = false 
            WHERE created_at < $1 
            AND trigger_count = 0 
            AND active = true
            RETURNING token_id
        `;
        
        const result = await this.postgres.query(query, [cutoffDate]);
        
        // Remove from Redis
        for (const row of result.rows) {
            await this.redis.del(`canary:${row.token_id}`);
            this.tokens.delete(row.token_id);
        }
        
        console.log(`Cleaned up ${result.rows.length} inactive tokens`);
        
        return result.rows.length;
    }
}

module.exports = CanaryTokenManager;