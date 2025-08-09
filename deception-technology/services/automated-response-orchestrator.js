/**
 * Automated Response Orchestrator
 * 
 * Coordinates and executes automated response actions when deception
 * technology triggers are activated, including isolation, blocking,
 * and forensic data collection.
 */

const EventEmitter = require('events');
const { exec } = require('child_process');
const { promisify } = require('util');
const axios = require('axios');
const winston = require('winston');
const crypto = require('crypto');

const execAsync = promisify(exec);

class AutomatedResponseOrchestrator extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            soarWebhook: config.soarWebhook || process.env.SOAR_WEBHOOK,
            siemEndpoint: config.siemEndpoint || process.env.SIEM_ENDPOINT,
            firewallApi: config.firewallApi || process.env.FIREWALL_API,
            edrApi: config.edrApi || process.env.EDR_API,
            ticketingApi: config.ticketingApi || process.env.TICKETING_API,
            slackWebhook: config.slackWebhook || process.env.SLACK_WEBHOOK,
            responseThresholds: {
                autoBlock: config.autoBlockThreshold || 2,
                escalate: config.escalateThreshold || 3,
                critical: config.criticalThreshold || 5
            },
            responseDelays: {
                immediate: 0,
                standard: 5000,
                cautious: 30000
            },
            ...config
        };
        
        this.logger = this.setupLogger();
        this.activeResponses = new Map();
        this.responseHistory = [];
        this.blockedIPs = new Set();
        this.isolatedSystems = new Set();
    }
    
    setupLogger() {
        return winston.createLogger({
            level: 'info',
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            transports: [
                new winston.transports.Console(),
                new winston.transports.File({ 
                    filename: 'logs/automated-response.log',
                    maxsize: 100000000, // 100MB
                    maxFiles: 10
                })
            ]
        });
    }
    
    /**
     * Process deception trigger and execute automated response
     */
    async processDeceptionTrigger(trigger) {
        const responseId = crypto.randomUUID();
        const startTime = Date.now();
        
        this.logger.info('Processing deception trigger', {
            responseId,
            trigger
        });
        
        // Create response plan
        const responsePlan = await this.createResponsePlan(trigger);
        
        // Store active response
        this.activeResponses.set(responseId, {
            trigger,
            plan: responsePlan,
            startTime,
            status: 'executing'
        });
        
        try {
            // Execute response actions
            const results = await this.executeResponsePlan(responsePlan, trigger);
            
            // Log response completion
            const response = {
                responseId,
                trigger,
                plan: responsePlan,
                results,
                executionTime: Date.now() - startTime,
                timestamp: new Date().toISOString()
            };
            
            this.responseHistory.push(response);
            this.activeResponses.delete(responseId);
            
            // Notify stakeholders
            await this.notifyStakeholders(response);
            
            this.emit('response:completed', response);
            
            return response;
            
        } catch (error) {
            this.logger.error('Response execution failed', {
                responseId,
                error: error.message,
                stack: error.stack
            });
            
            this.activeResponses.set(responseId, {
                ...this.activeResponses.get(responseId),
                status: 'failed',
                error: error.message
            });
            
            throw error;
        }
    }
    
    /**
     * Create automated response plan based on trigger
     */
    async createResponsePlan(trigger) {
        const plan = {
            id: crypto.randomUUID(),
            priority: this.determinePriority(trigger),
            actions: [],
            notifications: [],
            forensics: [],
            rollback: []
        };
        
        // Determine response actions based on trigger type and severity
        switch (trigger.type) {
            case 'CANARY_TOKEN_TRIGGERED':
                plan.actions.push(...this.getCanaryTokenActions(trigger));
                break;
                
            case 'DECOY_SERVICE_ACCESS':
                plan.actions.push(...this.getDecoyServiceActions(trigger));
                break;
                
            case 'HONEYPOT_INTERACTION':
                plan.actions.push(...this.getHoneypotActions(trigger));
                break;
                
            case 'ADMIN_LOGIN_ATTEMPT':
            case 'FINANCIAL_DATA_ACCESS':
                plan.actions.push(...this.getCriticalActions(trigger));
                plan.priority = 'critical';
                break;
                
            default:
                plan.actions.push(...this.getStandardActions(trigger));
        }
        
        // Add forensic collection
        plan.forensics = this.getForensicActions(trigger);
        
        // Add notifications
        plan.notifications = this.getNotificationActions(trigger, plan.priority);
        
        // Add rollback procedures
        plan.rollback = this.getRollbackActions(plan.actions);
        
        this.logger.info('Response plan created', {
            planId: plan.id,
            actionCount: plan.actions.length,
            priority: plan.priority
        });
        
        return plan;
    }
    
    /**
     * Execute response plan actions
     */
    async executeResponsePlan(plan, trigger) {
        const results = {
            successful: [],
            failed: [],
            skipped: []
        };
        
        // Execute actions based on priority
        const delay = this.getResponseDelay(plan.priority);
        if (delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
        }
        
        // Execute containment actions
        for (const action of plan.actions) {
            try {
                const result = await this.executeAction(action, trigger);
                results.successful.push({
                    action: action.type,
                    result,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                results.failed.push({
                    action: action.type,
                    error: error.message,
                    timestamp: new Date().toISOString()
                });
                
                // Continue with other actions unless critical
                if (action.critical) {
                    throw error;
                }
            }
        }
        
        // Execute forensic collection
        for (const forensic of plan.forensics) {
            try {
                await this.collectForensics(forensic, trigger);
                results.successful.push({
                    action: 'forensics',
                    type: forensic.type,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                this.logger.error('Forensics collection failed', {
                    type: forensic.type,
                    error: error.message
                });
            }
        }
        
        // Send notifications
        for (const notification of plan.notifications) {
            try {
                await this.sendNotification(notification, trigger, results);
            } catch (error) {
                this.logger.error('Notification failed', {
                    type: notification.type,
                    error: error.message
                });
            }
        }
        
        return results;
    }
    
    /**
     * Execute individual response action
     */
    async executeAction(action, trigger) {
        this.logger.info('Executing action', {
            type: action.type,
            target: action.target
        });
        
        switch (action.type) {
            case 'BLOCK_IP':
                return await this.blockIP(action.target, action.duration);
                
            case 'ISOLATE_SYSTEM':
                return await this.isolateSystem(action.target);
                
            case 'DISABLE_ACCOUNT':
                return await this.disableAccount(action.target);
                
            case 'REVOKE_CREDENTIALS':
                return await this.revokeCredentials(action.target);
                
            case 'QUARANTINE_FILE':
                return await this.quarantineFile(action.target);
                
            case 'KILL_PROCESS':
                return await this.killProcess(action.target);
                
            case 'NETWORK_SEGMENTATION':
                return await this.segmentNetwork(action.target);
                
            case 'ENABLE_MONITORING':
                return await this.enableEnhancedMonitoring(action.target);
                
            case 'SNAPSHOT_SYSTEM':
                return await this.createSystemSnapshot(action.target);
                
            case 'THREAT_HUNT':
                return await this.initiateThreatHunt(action.target, trigger);
                
            default:
                throw new Error(`Unknown action type: ${action.type}`);
        }
    }
    
    /**
     * Block IP address at firewall
     */
    async blockIP(ipAddress, duration = 3600) {
        // Check if already blocked
        if (this.blockedIPs.has(ipAddress)) {
            return { status: 'already_blocked', ip: ipAddress };
        }
        
        // Check if internal IP
        if (this.isInternalIP(ipAddress)) {
            this.logger.warn('Attempting to block internal IP', { ip: ipAddress });
            return { status: 'skipped', reason: 'internal_ip', ip: ipAddress };
        }
        
        try {
            // Call firewall API
            const response = await axios.post(`${this.config.firewallApi}/rules/block`, {
                source_ip: ipAddress,
                action: 'DROP',
                duration: duration,
                reason: 'deception_trigger',
                priority: 1
            }, {
                headers: {
                    'Authorization': `Bearer ${process.env.FIREWALL_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            // Add to blocked list
            this.blockedIPs.add(ipAddress);
            
            // Schedule unblock
            if (duration > 0) {
                setTimeout(() => {
                    this.unblockIP(ipAddress);
                }, duration * 1000);
            }
            
            this.logger.info('IP blocked successfully', {
                ip: ipAddress,
                duration,
                ruleId: response.data.ruleId
            });
            
            return {
                status: 'blocked',
                ip: ipAddress,
                duration,
                ruleId: response.data.ruleId
            };
            
        } catch (error) {
            // Fallback to iptables
            const command = `sudo iptables -A INPUT -s ${ipAddress} -j DROP`;
            await execAsync(command);
            
            this.blockedIPs.add(ipAddress);
            
            return {
                status: 'blocked_local',
                ip: ipAddress,
                method: 'iptables'
            };
        }
    }
    
    /**
     * Unblock IP address
     */
    async unblockIP(ipAddress) {
        try {
            await axios.delete(`${this.config.firewallApi}/rules/block/${ipAddress}`, {
                headers: {
                    'Authorization': `Bearer ${process.env.FIREWALL_API_KEY}`
                }
            });
            
            this.blockedIPs.delete(ipAddress);
            
            this.logger.info('IP unblocked', { ip: ipAddress });
            
        } catch (error) {
            // Fallback to iptables
            const command = `sudo iptables -D INPUT -s ${ipAddress} -j DROP`;
            await execAsync(command);
            
            this.blockedIPs.delete(ipAddress);
        }
    }
    
    /**
     * Isolate system from network
     */
    async isolateSystem(hostname) {
        if (this.isolatedSystems.has(hostname)) {
            return { status: 'already_isolated', hostname };
        }
        
        try {
            // Call EDR API for network isolation
            const response = await axios.post(`${this.config.edrApi}/endpoints/isolate`, {
                hostname,
                isolation_type: 'network',
                allow_local: true,
                reason: 'deception_trigger'
            }, {
                headers: {
                    'Authorization': `Bearer ${process.env.EDR_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            this.isolatedSystems.add(hostname);
            
            this.logger.info('System isolated', {
                hostname,
                isolationId: response.data.isolationId
            });
            
            return {
                status: 'isolated',
                hostname,
                isolationId: response.data.isolationId
            };
            
        } catch (error) {
            this.logger.error('System isolation failed', {
                hostname,
                error: error.message
            });
            throw error;
        }
    }
    
    /**
     * Disable user account
     */
    async disableAccount(username) {
        try {
            // Call identity management API
            const response = await axios.post(`${this.config.identityApi}/users/disable`, {
                username,
                reason: 'security_incident',
                automated: true
            }, {
                headers: {
                    'Authorization': `Bearer ${process.env.IDENTITY_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            this.logger.info('Account disabled', {
                username,
                status: response.data.status
            });
            
            return {
                status: 'disabled',
                username,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            // Fallback to local system
            const command = `sudo usermod -L ${username}`;
            await execAsync(command);
            
            return {
                status: 'disabled_local',
                username,
                method: 'usermod'
            };
        }
    }
    
    /**
     * Revoke credentials
     */
    async revokeCredentials(credentialId) {
        try {
            const response = await axios.post(`${this.config.vaultApi}/credentials/revoke`, {
                credential_id: credentialId,
                cascade: true,
                reason: 'compromised'
            }, {
                headers: {
                    'Authorization': `Bearer ${process.env.VAULT_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            this.logger.info('Credentials revoked', {
                credentialId,
                affected: response.data.affectedCount
            });
            
            return {
                status: 'revoked',
                credentialId,
                affectedCount: response.data.affectedCount
            };
            
        } catch (error) {
            this.logger.error('Credential revocation failed', {
                credentialId,
                error: error.message
            });
            throw error;
        }
    }
    
    /**
     * Collect forensic data
     */
    async collectForensics(forensic, trigger) {
        const forensicId = crypto.randomUUID();
        const timestamp = new Date().toISOString();
        
        switch (forensic.type) {
            case 'NETWORK_CAPTURE':
                await this.captureNetworkTraffic(trigger.sourceIp, forensicId);
                break;
                
            case 'MEMORY_DUMP':
                await this.captureMemoryDump(trigger.hostname, forensicId);
                break;
                
            case 'PROCESS_SNAPSHOT':
                await this.captureProcessSnapshot(trigger.hostname, forensicId);
                break;
                
            case 'FILE_ARTIFACTS':
                await this.collectFileArtifacts(trigger.path, forensicId);
                break;
                
            case 'LOG_COLLECTION':
                await this.collectLogs(trigger, forensicId);
                break;
                
            case 'REGISTRY_SNAPSHOT':
                await this.captureRegistrySnapshot(trigger.hostname, forensicId);
                break;
        }
        
        this.logger.info('Forensics collected', {
            forensicId,
            type: forensic.type,
            trigger: trigger.id
        });
        
        return { forensicId, type: forensic.type, timestamp };
    }
    
    /**
     * Capture network traffic
     */
    async captureNetworkTraffic(sourceIp, forensicId) {
        const pcapFile = `/forensics/network/${forensicId}.pcap`;
        const command = `sudo tcpdump -i any -w ${pcapFile} -c 10000 host ${sourceIp}`;
        
        // Start capture in background
        exec(command, (error) => {
            if (error) {
                this.logger.error('Network capture failed', {
                    forensicId,
                    error: error.message
                });
            }
        });
        
        // Stop capture after 60 seconds
        setTimeout(async () => {
            await execAsync('sudo pkill -f tcpdump');
        }, 60000);
        
        return { pcapFile, status: 'capturing' };
    }
    
    /**
     * Send notifications to stakeholders
     */
    async sendNotification(notification, trigger, results) {
        const message = this.formatNotificationMessage(notification, trigger, results);
        
        switch (notification.type) {
            case 'SLACK':
                await this.sendSlackNotification(message, notification.channel);
                break;
                
            case 'EMAIL':
                await this.sendEmailNotification(message, notification.recipients);
                break;
                
            case 'TICKET':
                await this.createIncidentTicket(message, trigger, notification.priority);
                break;
                
            case 'SOAR':
                await this.triggerSOARPlaybook(trigger, results);
                break;
                
            case 'SIEM':
                await this.logToSIEM(trigger, results);
                break;
        }
    }
    
    /**
     * Send Slack notification
     */
    async sendSlackNotification(message, channel = '#security-alerts') {
        try {
            await axios.post(this.config.slackWebhook, {
                channel,
                username: 'Security Bot',
                icon_emoji: ':shield:',
                attachments: [{
                    color: message.priority === 'critical' ? 'danger' : 'warning',
                    title: message.title,
                    text: message.text,
                    fields: message.fields,
                    footer: 'iSECTECH Security Platform',
                    ts: Math.floor(Date.now() / 1000)
                }]
            });
        } catch (error) {
            this.logger.error('Slack notification failed', { error: error.message });
        }
    }
    
    /**
     * Create incident ticket
     */
    async createIncidentTicket(message, trigger, priority) {
        try {
            const response = await axios.post(`${this.config.ticketingApi}/incidents`, {
                title: message.title,
                description: message.text,
                priority: priority,
                category: 'security_incident',
                source: 'automated_response',
                metadata: {
                    trigger,
                    automated_actions: message.actions
                }
            }, {
                headers: {
                    'Authorization': `Bearer ${process.env.TICKETING_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            });
            
            this.logger.info('Incident ticket created', {
                ticketId: response.data.ticketId,
                priority
            });
            
            return response.data.ticketId;
            
        } catch (error) {
            this.logger.error('Ticket creation failed', { error: error.message });
            throw error;
        }
    }
    
    /**
     * Trigger SOAR playbook
     */
    async triggerSOARPlaybook(trigger, results) {
        try {
            const response = await axios.post(this.config.soarWebhook, {
                playbook: this.selectPlaybook(trigger),
                trigger,
                automated_actions: results,
                timestamp: new Date().toISOString()
            }, {
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': process.env.SOAR_API_KEY
                }
            });
            
            this.logger.info('SOAR playbook triggered', {
                playbookId: response.data.playbookId,
                executionId: response.data.executionId
            });
            
        } catch (error) {
            this.logger.error('SOAR trigger failed', { error: error.message });
        }
    }
    
    /**
     * Helper functions
     */
    
    determinePriority(trigger) {
        if (trigger.severity === 'critical' || 
            trigger.type === 'ADMIN_LOGIN_ATTEMPT' ||
            trigger.type === 'FINANCIAL_DATA_ACCESS') {
            return 'critical';
        }
        
        if (trigger.severity === 'high' || trigger.triggerCount > 3) {
            return 'high';
        }
        
        if (trigger.severity === 'medium' || trigger.triggerCount > 1) {
            return 'medium';
        }
        
        return 'low';
    }
    
    getResponseDelay(priority) {
        switch (priority) {
            case 'critical':
                return this.config.responseDelays.immediate;
            case 'high':
                return this.config.responseDelays.standard;
            default:
                return this.config.responseDelays.cautious;
        }
    }
    
    getCanaryTokenActions(trigger) {
        const actions = [];
        
        // Always block source IP for canary tokens
        if (trigger.sourceIp && !this.isInternalIP(trigger.sourceIp)) {
            actions.push({
                type: 'BLOCK_IP',
                target: trigger.sourceIp,
                duration: 7200 // 2 hours
            });
        }
        
        // Token-specific actions
        switch (trigger.tokenType) {
            case 'ssh_key':
            case 'api_key':
            case 'aws_key':
                actions.push({
                    type: 'REVOKE_CREDENTIALS',
                    target: trigger.tokenId,
                    critical: true
                });
                break;
                
            case 'database_record':
                actions.push({
                    type: 'ENABLE_MONITORING',
                    target: 'database_access'
                });
                break;
        }
        
        return actions;
    }
    
    getDecoyServiceActions(trigger) {
        const actions = [];
        
        // Block external IPs accessing decoy services
        if (trigger.sourceIp && !this.isInternalIP(trigger.sourceIp)) {
            actions.push({
                type: 'BLOCK_IP',
                target: trigger.sourceIp,
                duration: 3600
            });
        }
        
        // Service-specific actions
        if (trigger.activity === 'ADMIN_LOGIN_ATTEMPT') {
            actions.push({
                type: 'SNAPSHOT_SYSTEM',
                target: trigger.hostname || 'decoy-server'
            });
            
            if (trigger.username) {
                actions.push({
                    type: 'DISABLE_ACCOUNT',
                    target: trigger.username
                });
            }
        }
        
        return actions;
    }
    
    getHoneypotActions(trigger) {
        const actions = [];
        
        // Network isolation for compromised systems
        if (trigger.hostname) {
            actions.push({
                type: 'ISOLATE_SYSTEM',
                target: trigger.hostname
            });
        }
        
        // Process termination for suspicious processes
        if (trigger.processId) {
            actions.push({
                type: 'KILL_PROCESS',
                target: trigger.processId
            });
        }
        
        return actions;
    }
    
    getCriticalActions(trigger) {
        const actions = [];
        
        // Immediate containment for critical triggers
        if (trigger.sourceIp) {
            actions.push({
                type: 'BLOCK_IP',
                target: trigger.sourceIp,
                duration: 0, // Permanent
                critical: true
            });
        }
        
        if (trigger.hostname) {
            actions.push({
                type: 'ISOLATE_SYSTEM',
                target: trigger.hostname,
                critical: true
            });
            
            actions.push({
                type: 'SNAPSHOT_SYSTEM',
                target: trigger.hostname
            });
        }
        
        if (trigger.username) {
            actions.push({
                type: 'DISABLE_ACCOUNT',
                target: trigger.username,
                critical: true
            });
        }
        
        // Initiate threat hunt
        actions.push({
            type: 'THREAT_HUNT',
            target: {
                scope: 'network_wide',
                indicators: trigger
            }
        });
        
        return actions;
    }
    
    getStandardActions(trigger) {
        const actions = [];
        
        // Basic containment
        if (trigger.sourceIp && !this.isInternalIP(trigger.sourceIp)) {
            actions.push({
                type: 'BLOCK_IP',
                target: trigger.sourceIp,
                duration: 1800 // 30 minutes
            });
        }
        
        // Enhanced monitoring
        actions.push({
            type: 'ENABLE_MONITORING',
            target: trigger.service || 'general'
        });
        
        return actions;
    }
    
    getForensicActions(trigger) {
        const forensics = [];
        
        // Always collect logs
        forensics.push({ type: 'LOG_COLLECTION' });
        
        // Network capture for external threats
        if (trigger.sourceIp && !this.isInternalIP(trigger.sourceIp)) {
            forensics.push({ type: 'NETWORK_CAPTURE' });
        }
        
        // System forensics for critical events
        if (trigger.severity === 'critical' || trigger.priority === 'critical') {
            if (trigger.hostname) {
                forensics.push({ type: 'MEMORY_DUMP' });
                forensics.push({ type: 'PROCESS_SNAPSHOT' });
            }
        }
        
        return forensics;
    }
    
    getNotificationActions(trigger, priority) {
        const notifications = [];
        
        // Always log to SIEM
        notifications.push({ type: 'SIEM' });
        
        // Priority-based notifications
        switch (priority) {
            case 'critical':
                notifications.push({
                    type: 'SLACK',
                    channel: '#security-critical'
                });
                notifications.push({
                    type: 'EMAIL',
                    recipients: ['security-team@isectech.com', 'ciso@isectech.com']
                });
                notifications.push({
                    type: 'TICKET',
                    priority: 'P1'
                });
                notifications.push({ type: 'SOAR' });
                break;
                
            case 'high':
                notifications.push({
                    type: 'SLACK',
                    channel: '#security-alerts'
                });
                notifications.push({
                    type: 'TICKET',
                    priority: 'P2'
                });
                notifications.push({ type: 'SOAR' });
                break;
                
            case 'medium':
                notifications.push({
                    type: 'SLACK',
                    channel: '#security-monitoring'
                });
                notifications.push({
                    type: 'TICKET',
                    priority: 'P3'
                });
                break;
                
            default:
                notifications.push({
                    type: 'SLACK',
                    channel: '#security-info'
                });
        }
        
        return notifications;
    }
    
    getRollbackActions(actions) {
        const rollback = [];
        
        for (const action of actions) {
            switch (action.type) {
                case 'BLOCK_IP':
                    rollback.push({
                        type: 'UNBLOCK_IP',
                        target: action.target,
                        condition: 'manual_review'
                    });
                    break;
                    
                case 'ISOLATE_SYSTEM':
                    rollback.push({
                        type: 'RESTORE_NETWORK',
                        target: action.target,
                        condition: 'incident_resolved'
                    });
                    break;
                    
                case 'DISABLE_ACCOUNT':
                    rollback.push({
                        type: 'ENABLE_ACCOUNT',
                        target: action.target,
                        condition: 'user_verified'
                    });
                    break;
            }
        }
        
        return rollback;
    }
    
    formatNotificationMessage(notification, trigger, results) {
        const successCount = results.successful.length;
        const failCount = results.failed.length;
        
        return {
            title: `🚨 Security Incident: ${trigger.type}`,
            text: `Automated response executed for ${trigger.type} trigger`,
            priority: trigger.priority || 'medium',
            fields: [
                {
                    title: 'Trigger Source',
                    value: trigger.sourceIp || 'Unknown',
                    short: true
                },
                {
                    title: 'Actions Taken',
                    value: `${successCount} successful, ${failCount} failed`,
                    short: true
                },
                {
                    title: 'Severity',
                    value: trigger.severity || 'Medium',
                    short: true
                },
                {
                    title: 'Response Time',
                    value: `${results.executionTime || 0}ms`,
                    short: true
                }
            ],
            actions: results.successful.map(r => r.action)
        };
    }
    
    selectPlaybook(trigger) {
        const playbookMap = {
            'CANARY_TOKEN_TRIGGERED': 'canary_token_response',
            'ADMIN_LOGIN_ATTEMPT': 'privileged_access_incident',
            'FINANCIAL_DATA_ACCESS': 'data_exfiltration_response',
            'DECOY_SERVICE_ACCESS': 'honeypot_interaction',
            'HONEYPOT_INTERACTION': 'attacker_engagement'
        };
        
        return playbookMap[trigger.type] || 'generic_security_incident';
    }
    
    isInternalIP(ip) {
        const internalRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[01])\./,
            /^192\.168\./,
            /^127\./
        ];
        
        return internalRanges.some(range => range.test(ip));
    }
    
    /**
     * Get response statistics
     */
    getStatistics() {
        const last24h = Date.now() - 24 * 60 * 60 * 1000;
        const recent = this.responseHistory.filter(r => 
            new Date(r.timestamp) > new Date(last24h)
        );
        
        return {
            total_responses: this.responseHistory.length,
            last_24h: recent.length,
            active_responses: this.activeResponses.size,
            blocked_ips: this.blockedIPs.size,
            isolated_systems: this.isolatedSystems.size,
            average_response_time: this.calculateAverageResponseTime(),
            success_rate: this.calculateSuccessRate()
        };
    }
    
    calculateAverageResponseTime() {
        if (this.responseHistory.length === 0) return 0;
        
        const total = this.responseHistory.reduce((sum, r) => 
            sum + (r.executionTime || 0), 0
        );
        
        return Math.round(total / this.responseHistory.length);
    }
    
    calculateSuccessRate() {
        if (this.responseHistory.length === 0) return 100;
        
        const successful = this.responseHistory.filter(r => 
            r.results && r.results.failed.length === 0
        ).length;
        
        return Math.round((successful / this.responseHistory.length) * 100);
    }
}

module.exports = AutomatedResponseOrchestrator;