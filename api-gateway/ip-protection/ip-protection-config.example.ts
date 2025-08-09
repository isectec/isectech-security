/**
 * Example Configuration for iSECTECH IP Protection System
 * 
 * This file provides a comprehensive example configuration for the
 * Intelligent IP Protection System. Copy and modify as needed.
 */

import { IPProtectionManagerConfig } from './ip-protection-manager';

export const productionConfig: IPProtectionManagerConfig = {
  system: {
    enabled: true,
    mode: 'PRODUCTION',
    logLevel: 'INFO',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0'),
    keyPrefix: 'isectech:ip_protection:',
  },
  protection: {
    redis: {
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: parseInt(process.env.REDIS_DB || '0'),
      keyPrefix: 'isectech:ip_protection:',
    },
    geolocation: {
      enabled: true,
      defaultPolicy: 'ALLOW',
      database: 'maxmind',
    },
    reputation: {
      enabled: true,
      sources: [
        {
          name: 'VirusTotal',
          apiKey: process.env.VIRUSTOTAL_API_KEY || '',
          endpoint: 'https://www.virustotal.com/vtapi/v2/ip-address/report',
          weight: 0.4,
          cacheTtl: 3600,
        },
        {
          name: 'AbuseIPDB',
          apiKey: process.env.ABUSEIPDB_API_KEY || '',
          endpoint: 'https://api.abuseipdb.com/api/v2/check',
          weight: 0.3,
          cacheTtl: 3600,
        },
        {
          name: 'ThreatFox',
          apiKey: process.env.THREATFOX_API_KEY || '',
          endpoint: 'https://threatfox-api.abuse.ch/api/v1/',
          weight: 0.3,
          cacheTtl: 7200,
        },
      ],
      thresholds: {
        block: 80,
        suspicious: 60,
        clean: 20,
      },
      temporaryBan: {
        enabled: true,
        initialDuration: 300, // 5 minutes
        maxDuration: 86400, // 24 hours
        escalationFactor: 2,
      },
    },
    analytics: {
      enabled: true,
      retentionDays: 30,
      realTimeMetrics: true,
    },
    rateLimit: {
      checkRequests: 10000,
      checkWindow: 60,
      cacheSize: 100000,
    },
  },
  kong: {
    enabled: true,
    protection: {
      mode: 'ENFORCE',
      failOpen: false, // Fail closed in production
      responseHeaders: true,
      logLevel: 'INFO',
    },
    performance: {
      timeout: 100, // milliseconds
      cacheEnabled: true,
      cacheTtl: 300, // 5 minutes
      batchSize: 1000,
    },
    responses: {
      block: {
        status: 403,
        message: 'Access denied by security policy',
        headers: {
          'X-Protection-Policy': 'IP-BLOCKED',
          'X-Security-Reason': 'IP_REPUTATION_BLOCK',
          'Retry-After': '300',
        },
      },
      challenge: {
        status: 429,
        message: 'Additional verification required',
        headers: {
          'X-Protection-Policy': 'IP-CHALLENGE',
          'X-Challenge-Type': 'CAPTCHA',
          'X-Challenge-Timeout': '60',
        },
      },
    },
    monitoring: {
      metricsEnabled: true,
      detailedLogging: false, // Reduce log volume in production
      alertThresholds: {
        blockRate: 50, // blocks per minute (higher threshold for production)
        errorRate: 10, // errors per minute
      },
    },
  },
  dashboard: {
    realTime: {
      enabled: true,
      updateInterval: 5000, // 5 seconds
      maxDataPoints: 2000,
      geolocationEnabled: true,
    },
    forensics: {
      enabled: true,
      retentionDays: 90,
      maxIncidentHistory: 50000,
      autoInvestigation: true,
    },
    alerts: {
      enabled: true,
      thresholds: {
        suspiciousActivity: 25, // incidents per hour
        massiveTraffic: 5000, // requests per minute
        newThreatSource: 10, // new malicious IPs per hour
        reputationDrop: 30, // reputation score drop
      },
      channels: ['email', 'slack', 'webhook'],
    },
    reporting: {
      enabled: true,
      schedules: ['daily', 'weekly'],
      recipients: [
        'security@isectech.com',
        'devops@isectech.com',
      ],
    },
  },
  integration: {
    healthCheckInterval: 30000, // 30 seconds
    configSyncInterval: 300000, // 5 minutes
    metricsFlushInterval: 15000, // 15 seconds
    autoBackup: true,
  },
};

export const developmentConfig: IPProtectionManagerConfig = {
  system: {
    enabled: true,
    mode: 'DEVELOPMENT',
    logLevel: 'DEBUG',
  },
  redis: {
    host: 'localhost',
    port: 6379,
    db: 1, // Use different DB for development
    keyPrefix: 'dev:ip_protection:',
  },
  protection: {
    redis: {
      host: 'localhost',
      port: 6379,
      db: 1,
      keyPrefix: 'dev:ip_protection:',
    },
    geolocation: {
      enabled: true,
      defaultPolicy: 'ALLOW',
      database: 'maxmind',
    },
    reputation: {
      enabled: false, // Disable in development to avoid API costs
      sources: [],
      thresholds: {
        block: 90,
        suspicious: 70,
        clean: 30,
      },
      temporaryBan: {
        enabled: false,
        initialDuration: 60, // 1 minute for testing
        maxDuration: 300, // 5 minutes max
        escalationFactor: 1.5,
      },
    },
    analytics: {
      enabled: true,
      retentionDays: 7,
      realTimeMetrics: true,
    },
    rateLimit: {
      checkRequests: 1000,
      checkWindow: 60,
      cacheSize: 10000,
    },
  },
  kong: {
    enabled: true,
    protection: {
      mode: 'MONITOR', // Monitor mode for development
      failOpen: true, // Fail open in development
      responseHeaders: true,
      logLevel: 'DEBUG',
    },
    performance: {
      timeout: 500, // Longer timeout for debugging
      cacheEnabled: true,
      cacheTtl: 60, // Shorter cache for faster testing
      batchSize: 100,
    },
    responses: {
      block: {
        status: 403,
        message: 'Development: Access would be blocked in production',
        headers: {
          'X-Protection-Policy': 'IP-BLOCKED-DEV',
          'X-Development-Mode': 'true',
        },
      },
      challenge: {
        status: 200, // Allow through in development
        message: 'Development: Challenge would be required in production',
        headers: {
          'X-Protection-Policy': 'IP-CHALLENGE-DEV',
          'X-Development-Mode': 'true',
        },
      },
    },
    monitoring: {
      metricsEnabled: true,
      detailedLogging: true, // Detailed logging for debugging
      alertThresholds: {
        blockRate: 5, // Lower thresholds for testing
        errorRate: 2,
      },
    },
  },
  dashboard: {
    realTime: {
      enabled: true,
      updateInterval: 1000, // 1 second for development
      maxDataPoints: 500,
      geolocationEnabled: true,
    },
    forensics: {
      enabled: true,
      retentionDays: 7,
      maxIncidentHistory: 1000,
      autoInvestigation: false, // Manual investigation in development
    },
    alerts: {
      enabled: false, // Disable alerts in development
      thresholds: {
        suspiciousActivity: 100,
        massiveTraffic: 10000,
        newThreatSource: 50,
        reputationDrop: 50,
      },
      channels: [],
    },
    reporting: {
      enabled: false, // Disable scheduled reports in development
      schedules: [],
      recipients: [],
    },
  },
  integration: {
    healthCheckInterval: 10000, // 10 seconds
    configSyncInterval: 30000, // 30 seconds
    metricsFlushInterval: 5000, // 5 seconds
    autoBackup: false, // Disable automatic backups
  },
};

export const stagingConfig: IPProtectionManagerConfig = {
  ...productionConfig,
  system: {
    enabled: true,
    mode: 'STAGING',
    logLevel: 'INFO',
  },
  redis: {
    ...productionConfig.redis,
    keyPrefix: 'staging:ip_protection:',
  },
  protection: {
    ...productionConfig.protection,
    redis: {
      ...productionConfig.protection.redis,
      keyPrefix: 'staging:ip_protection:',
    },
    reputation: {
      ...productionConfig.protection.reputation,
      enabled: true, // Enable for staging testing
      temporaryBan: {
        enabled: true,
        initialDuration: 60, // Shorter bans for staging
        maxDuration: 3600, // 1 hour max
        escalationFactor: 1.5,
      },
    },
  },
  kong: {
    ...productionConfig.kong,
    protection: {
      ...productionConfig.kong.protection,
      mode: 'ENFORCE', // Full enforcement in staging
      failOpen: true, // Fail open to avoid staging issues
    },
    monitoring: {
      ...productionConfig.kong.monitoring,
      detailedLogging: true, // More detailed logging for staging
    },
  },
  dashboard: {
    ...productionConfig.dashboard,
    alerts: {
      ...productionConfig.dashboard.alerts,
      channels: ['slack'], // Only Slack alerts for staging
    },
    reporting: {
      enabled: false, // No scheduled reports for staging
      schedules: [],
      recipients: [],
    },
  },
};

// Default rule examples for initial setup
export const defaultIPRules = [
  {
    type: 'DENY' as const,
    cidr: '10.0.0.0/8',
    priority: 900,
    description: 'Block private IP ranges - RFC 1918',
    createdBy: 'system',
    tags: ['private', 'rfc1918'],
  },
  {
    type: 'DENY' as const,
    cidr: '172.16.0.0/12',
    priority: 900,
    description: 'Block private IP ranges - RFC 1918',
    createdBy: 'system',
    tags: ['private', 'rfc1918'],
  },
  {
    type: 'DENY' as const,
    cidr: '192.168.0.0/16',
    priority: 900,
    description: 'Block private IP ranges - RFC 1918',
    createdBy: 'system',
    tags: ['private', 'rfc1918'],
  },
  {
    type: 'DENY' as const,
    cidr: '127.0.0.0/8',
    priority: 950,
    description: 'Block localhost range',
    createdBy: 'system',
    tags: ['localhost', 'loopback'],
  },
  {
    type: 'ALLOW' as const,
    cidr: '8.8.8.0/24',
    priority: 100,
    description: 'Allow Google DNS range (example trusted source)',
    createdBy: 'system',
    tags: ['trusted', 'google'],
  },
];

// Default geolocation rules for high-risk countries
export const defaultGeolocationRules = [
  {
    type: 'DENY' as const,
    countries: ['CN', 'RU', 'KP', 'IR'],
    priority: 800,
    description: 'Block high-risk countries',
    isActive: false, // Start disabled, enable as needed
  },
  {
    type: 'ALLOW' as const,
    countries: ['US', 'CA', 'GB', 'DE', 'FR', 'AU', 'JP'],
    priority: 200,
    description: 'Explicitly allow trusted countries',
    isActive: true,
  },
];

// Environment-specific configuration selector
export function getConfigForEnvironment(env: string = process.env.NODE_ENV || 'development'): IPProtectionManagerConfig {
  switch (env.toLowerCase()) {
    case 'production':
      return productionConfig;
    case 'staging':
      return stagingConfig;
    case 'development':
    case 'dev':
    default:
      return developmentConfig;
  }
}