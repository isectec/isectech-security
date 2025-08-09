#!/usr/bin/env node

/**
 * Canary Token Deployment Script
 * 
 * Strategically deploys canary tokens across the iSECTECH infrastructure
 * based on security priorities and threat modeling.
 */

const CanaryTokenManager = require('../services/canary-token-manager');
const path = require('path');
const fs = require('fs').promises;

// Deployment configuration
const DEPLOYMENT_PLAN = [
    // Critical Infrastructure Tokens
    {
        id: 'ct-001',
        type: 'aws_key',
        location: '/etc/isectech/config/',
        options: {
            tenantId: 'infrastructure',
            metadata: {
                criticality: 'high',
                description: 'AWS credentials honeypot in config directory'
            }
        }
    },
    {
        id: 'ct-002',
        type: 'api_key',
        location: 'production-api-gateway',
        options: {
            tenantId: 'api-gateway',
            metadata: {
                criticality: 'high',
                description: 'API key for production gateway monitoring'
            }
        }
    },
    
    // Database Canaries
    {
        id: 'ct-003',
        type: 'database_record',
        location: 'users_table',
        options: {
            tenantId: 'database',
            metadata: {
                table: 'users',
                database: 'production',
                description: 'Canary user record for insider threat detection'
            }
        }
    },
    {
        id: 'ct-004',
        type: 'database_record',
        location: 'customers_table',
        options: {
            tenantId: 'database',
            metadata: {
                table: 'customers',
                database: 'production',
                description: 'Canary customer record with fake PII'
            }
        }
    },
    
    // File System Tokens
    {
        id: 'ct-005',
        type: 'file_system',
        location: '/var/www/html/',
        options: {
            tenantId: 'web-server',
            metadata: {
                description: 'Web root canary file'
            }
        }
    },
    {
        id: 'ct-006',
        type: 'file_system',
        location: '/home/admin/',
        options: {
            tenantId: 'system',
            metadata: {
                description: 'Admin home directory canary'
            }
        }
    },
    {
        id: 'ct-007',
        type: 'file_system',
        location: '/opt/backups/',
        options: {
            tenantId: 'backup',
            metadata: {
                description: 'Backup directory canary token'
            }
        }
    },
    
    // Source Code Repository Tokens
    {
        id: 'ct-008',
        type: 'git_commit',
        location: 'main-repository',
        options: {
            tenantId: 'source-control',
            metadata: {
                repository: 'isectech-platform',
                branch: 'master',
                description: 'Git commit canary for code theft detection'
            }
        }
    },
    
    // SSH Keys
    {
        id: 'ct-009',
        type: 'ssh_key',
        location: '/home/deploy/.ssh/',
        options: {
            tenantId: 'ssh-access',
            metadata: {
                user: 'deploy',
                description: 'Deploy user SSH key canary'
            }
        }
    },
    {
        id: 'ct-010',
        type: 'ssh_key',
        location: '/root/.ssh/',
        options: {
            tenantId: 'ssh-access',
            metadata: {
                user: 'root',
                description: 'Root SSH key canary',
                criticality: 'critical'
            }
        }
    },
    
    // JWT Tokens
    {
        id: 'ct-011',
        type: 'jwt_token',
        location: 'session-storage',
        options: {
            tenantId: 'authentication',
            metadata: {
                description: 'JWT token for session hijacking detection'
            }
        }
    },
    
    // Document Canaries
    {
        id: 'ct-012',
        type: 'document',
        location: '/shared/documents/',
        options: {
            tenantId: 'file-share',
            docType: 'pdf',
            fileName: 'Q4_Financial_Report_CONFIDENTIAL.pdf',
            metadata: {
                description: 'Honeypot document for data exfiltration detection'
            }
        }
    },
    {
        id: 'ct-013',
        type: 'document',
        location: '/shared/documents/',
        options: {
            tenantId: 'file-share',
            docType: 'xlsx',
            fileName: 'Customer_Database_Export.xlsx',
            metadata: {
                description: 'Fake customer database export'
            }
        }
    },
    
    // DNS Records
    {
        id: 'ct-014',
        type: 'dns_record',
        location: 'internal-dns',
        options: {
            tenantId: 'network',
            metadata: {
                description: 'DNS canary for reconnaissance detection'
            }
        }
    },
    
    // Email Addresses
    {
        id: 'ct-015',
        type: 'email_address',
        location: 'email-system',
        options: {
            tenantId: 'email',
            metadata: {
                description: 'Canary email for phishing detection'
            }
        }
    },
    
    // Webhook URLs
    {
        id: 'ct-016',
        type: 'webhook_url',
        location: 'integration-configs',
        options: {
            tenantId: 'integrations',
            metadata: {
                description: 'Webhook canary for third-party integration monitoring'
            }
        }
    },
    
    // URL Shorteners
    {
        id: 'ct-017',
        type: 'url_shortener',
        location: 'marketing-campaigns',
        options: {
            tenantId: 'marketing',
            metadata: {
                description: 'URL shortener canary for link manipulation detection'
            }
        }
    },
    
    // Kubernetes Secrets (as file system tokens)
    {
        id: 'ct-018',
        type: 'file_system',
        location: '/var/run/secrets/kubernetes.io/',
        options: {
            tenantId: 'kubernetes',
            metadata: {
                description: 'Kubernetes secrets directory canary',
                criticality: 'high'
            }
        }
    },
    
    // Docker Registry Credentials
    {
        id: 'ct-019',
        type: 'file_system',
        location: '/root/.docker/',
        options: {
            tenantId: 'docker',
            metadata: {
                description: 'Docker registry credentials canary'
            }
        }
    },
    
    // Environment Variables File
    {
        id: 'ct-020',
        type: 'file_system',
        location: '/app/',
        options: {
            tenantId: 'application',
            metadata: {
                fileName: '.env.production',
                description: 'Production environment variables canary'
            }
        }
    }
];

/**
 * Main deployment function
 */
async function deployCanaryTokens() {
    console.log('🚀 Starting Canary Token Deployment');
    console.log('=====================================\n');
    
    // Initialize the Canary Token Manager
    const manager = new CanaryTokenManager({
        redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
        postgresUrl: process.env.DATABASE_URL,
        alertWebhook: process.env.DECEPTION_ALERT_WEBHOOK || 'https://soc.isectech.com/webhooks/deception-alert',
        tokenDomain: process.env.CANARY_DOMAIN || 'canary.isectech.internal'
    });
    
    try {
        // Initialize manager
        await manager.initialize();
        console.log('✅ Canary Token Manager initialized\n');
        
        // Deploy tokens according to plan
        console.log(`📋 Deploying ${DEPLOYMENT_PLAN.length} canary tokens...\n`);
        
        const results = await manager.deployTokens(DEPLOYMENT_PLAN);
        
        // Generate deployment report
        const report = {
            deploymentTime: new Date().toISOString(),
            totalTokens: DEPLOYMENT_PLAN.length,
            successful: results.filter(r => r.status === 'deployed').length,
            failed: results.filter(r => r.status === 'failed').length,
            tokens: results
        };
        
        // Save deployment report
        const reportPath = path.join(__dirname, '..', 'logs', `deployment-${Date.now()}.json`);
        await fs.mkdir(path.dirname(reportPath), { recursive: true });
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
        
        // Print summary
        console.log('\n📊 Deployment Summary:');
        console.log('=====================');
        console.log(`✅ Successful: ${report.successful}`);
        console.log(`❌ Failed: ${report.failed}`);
        console.log(`📁 Report saved to: ${reportPath}`);
        
        // Print token statistics by type
        const stats = await manager.getStatistics();
        console.log('\n📈 Token Distribution:');
        console.log('=====================');
        stats.byType.forEach(type => {
            console.log(`  ${type.token_type}: ${type.count} tokens`);
        });
        
        // Set up monitoring
        manager.on('token:triggered', (event) => {
            console.log('\n🚨 ALERT: Canary Token Triggered!');
            console.log(`  Token ID: ${event.tokenId}`);
            console.log(`  Type: ${event.tokenType}`);
            console.log(`  Location: ${event.location}`);
            console.log(`  Trigger Count: ${event.triggerCount}`);
        });
        
        // Set up periodic health checks
        manager.on('health:check', (health) => {
            console.log(`\n💓 Health Check: ${health.totalTokens} tokens deployed, ${health.triggeredTokens} triggered`);
        });
        
        console.log('\n✅ Canary token deployment complete!');
        console.log('🔍 Monitoring active - tokens are now protecting the environment');
        
        // Create integration documentation
        await createIntegrationDocs(results);
        
    } catch (error) {
        console.error('❌ Deployment failed:', error);
        process.exit(1);
    }
}

/**
 * Create integration documentation for deployed tokens
 */
async function createIntegrationDocs(deployedTokens) {
    const docs = `# Canary Token Integration Guide

## Deployed Tokens

This document contains integration information for deployed canary tokens.

### Token Locations and Usage

${deployedTokens.filter(t => t.status === 'deployed').map(token => `
#### ${token.deploymentId}: ${token.tokenType}
- **Location**: ${token.location}
- **Token ID**: ${token.tokenId}
- **Created**: ${token.created}
- **Integration**: ${getIntegrationInstructions(token)}
`).join('\n')}

### Monitoring and Alerts

All canary tokens are monitored 24/7. When triggered:

1. Alert sent to SOC webhook: ${process.env.DECEPTION_ALERT_WEBHOOK || 'https://soc.isectech.com/webhooks/deception-alert'}
2. Event logged to SIEM
3. Automated response actions executed based on token type
4. Incident ticket created in ticketing system

### Testing Tokens

To test a canary token:

1. Access the token using its specific trigger mechanism
2. Monitor the SOC dashboard for alerts
3. Verify automated responses are executed
4. Check SIEM for logged events

### Maintenance

- Tokens are automatically cleaned up after 90 days of inactivity
- Active tokens are refreshed monthly
- Token statistics available at: https://soc.isectech.com/deception/stats

## Security Considerations

⚠️ **NEVER** share actual token values in documentation or communications
⚠️ **NEVER** trigger tokens unless conducting authorized testing
⚠️ **ALWAYS** treat triggered tokens as potential security incidents

## Support

For questions or issues related to canary tokens:
- Email: soc@isectech.com
- Slack: #security-operations
- On-call: +1-555-SEC-RITY
`;
    
    const docPath = path.join(__dirname, '..', 'docs', 'integration-guide.md');
    await fs.mkdir(path.dirname(docPath), { recursive: true });
    await fs.writeFile(docPath, docs);
    
    console.log(`\n📚 Integration documentation created: ${docPath}`);
}

/**
 * Get integration instructions based on token type
 */
function getIntegrationInstructions(token) {
    const instructions = {
        'api_key': 'Place in API configuration files or environment variables',
        'aws_key': 'Add to AWS credentials file or IAM configuration',
        'database_record': 'Insert into database table with appropriate visibility',
        'document': 'Place in shared folders or document management systems',
        'dns_record': 'Configure in DNS server or hosts file',
        'email_address': 'Add to email distribution lists or contact directories',
        'file_system': 'File created at specified location with restricted permissions',
        'git_commit': 'Reference in code comments or documentation',
        'jwt_token': 'Store in session storage or configuration files',
        'ssh_key': 'Add public key to authorized_keys with comment',
        'url_shortener': 'Include in documentation or configuration files',
        'webhook_url': 'Add to integration configurations or webhook settings'
    };
    
    return instructions[token.tokenType] || 'Follow standard deployment procedures for this token type';
}

// Run deployment if executed directly
if (require.main === module) {
    deployCanaryTokens().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}

module.exports = { deployCanaryTokens, DEPLOYMENT_PLAN };