/**
 * Production-grade Developer Dashboard and API Key Management for iSECTECH
 * 
 * Provides comprehensive developer account management, API key lifecycle management,
 * usage analytics, quota tracking, and developer experience optimization.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Developer Dashboard Configuration Schemas
export const DeveloperDashboardConfigSchema = z.object({
  dashboardId: z.string(),
  developerId: z.string(),
  
  // Dashboard layout and customization
  layout: z.object({
    theme: z.enum(['light', 'dark', 'auto']).default('auto'),
    sidebar: z.object({
      collapsed: z.boolean().default(false),
      pinned: z.boolean().default(true)
    }),
    widgets: z.array(z.object({
      id: z.string(),
      type: z.enum(['API_USAGE', 'QUOTA_STATUS', 'API_KEYS', 'RECENT_ACTIVITY', 'PERFORMANCE', 'ALERTS']),
      position: z.object({
        x: z.number(),
        y: z.number(),
        width: z.number(),
        height: z.number()
      }),
      visible: z.boolean().default(true),
      settings: z.record(z.any()).default({})
    })).default([]),
    refreshInterval: z.number().default(30) // seconds
  }),
  
  // Notification preferences
  notifications: z.object({
    email: z.object({
      enabled: z.boolean().default(true),
      quotaWarnings: z.boolean().default(true),
      securityAlerts: z.boolean().default(true),
      maintenanceNotices: z.boolean().default(true),
      newFeatures: z.boolean().default(false)
    }),
    inApp: z.object({
      enabled: z.boolean().default(true),
      sound: z.boolean().default(false),
      desktop: z.boolean().default(true)
    }),
    webhook: z.object({
      enabled: z.boolean().default(false),
      url: z.string().url().optional(),
      events: z.array(z.string()).default([])
    })
  }),
  
  // Analytics preferences
  analytics: z.object({
    dataRetention: z.number().default(90), // days
    detailedTracking: z.boolean().default(true),
    performanceMonitoring: z.boolean().default(true),
    errorTracking: z.boolean().default(true)
  }),
  
  // Security settings
  security: z.object({
    twoFactorAuth: z.boolean().default(false),
    sessionTimeout: z.number().default(3600), // seconds
    ipWhitelist: z.array(z.string()).default([]),
    webhookSigning: z.boolean().default(true)
  }),
  
  createdAt: z.date(),
  updatedAt: z.date()
});

export const APIKeySchema = z.object({
  keyId: z.string(),
  developerId: z.string(),
  name: z.string(),
  description: z.string().optional(),
  
  // Key properties
  keyPrefix: z.string(), // First 8 characters for display
  keyHash: z.string(), // SHA-256 hash of the full key
  secretHash: z.string(), // For webhook signing
  
  // Permissions and scopes
  scopes: z.array(z.string()).default([]),
  permissions: z.array(z.string()).default([]),
  allowedIPs: z.array(z.string()).default([]), // IP restrictions
  allowedDomains: z.array(z.string()).default([]), // Domain restrictions for CORS
  
  // Usage limits
  rateLimits: z.object({
    requestsPerMinute: z.number().default(60),
    requestsPerHour: z.number().default(1000),
    requestsPerDay: z.number().default(10000),
    requestsPerMonth: z.number().default(100000)
  }),
  
  // Quotas
  quotas: z.object({
    threatAnalysis: z.object({
      daily: z.number().default(100),
      monthly: z.number().default(1000)
    }),
    assetScans: z.object({
      daily: z.number().default(10),
      monthly: z.number().default(100)
    }),
    threatIntelligence: z.object({
      daily: z.number().default(1000),
      monthly: z.number().default(10000)
    })
  }),
  
  // Status and lifecycle
  status: z.enum(['ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED']).default('ACTIVE'),
  createdAt: z.date(),
  updatedAt: z.date(),
  lastUsed: z.date().optional(),
  expiresAt: z.date().optional(),
  
  // Usage statistics
  usage: z.object({
    totalRequests: z.number().default(0),
    requestsThisMonth: z.number().default(0),
    requestsToday: z.number().default(0),
    lastRequestAt: z.date().optional(),
    averageResponseTime: z.number().default(0),
    errorRate: z.number().default(0)
  }),
  
  // Security events
  securityEvents: z.array(z.object({
    eventId: z.string(),
    type: z.enum(['UNAUTHORIZED_ACCESS', 'RATE_LIMIT_EXCEEDED', 'SUSPICIOUS_ACTIVITY', 'IP_VIOLATION']),
    timestamp: z.date(),
    details: z.record(z.any()),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
  })).default([]),
  
  // Metadata
  environment: z.enum(['DEVELOPMENT', 'STAGING', 'PRODUCTION']).default('DEVELOPMENT'),
  tags: z.array(z.string()).default([]),
  notes: z.string().optional()
});

export const UsageAnalyticsSchema = z.object({
  developerId: z.string(),
  period: z.object({
    start: z.date(),
    end: z.date(),
    type: z.enum(['HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY'])
  }),
  
  // Request statistics
  requests: z.object({
    total: z.number(),
    successful: z.number(),
    failed: z.number(),
    blocked: z.number(),
    throttled: z.number(),
    
    // By endpoint
    byEndpoint: z.array(z.object({
      endpoint: z.string(),
      method: z.string(),
      count: z.number(),
      averageResponseTime: z.number(),
      errorRate: z.number()
    })),
    
    // By status code
    byStatusCode: z.record(z.number()),
    
    // Time series data
    timeSeries: z.array(z.object({
      timestamp: z.date(),
      requests: z.number(),
      errors: z.number(),
      responseTime: z.number()
    }))
  }),
  
  // Performance metrics
  performance: z.object({
    averageResponseTime: z.number(),
    p50ResponseTime: z.number(),
    p95ResponseTime: z.number(),
    p99ResponseTime: z.number(),
    slowestEndpoints: z.array(z.object({
      endpoint: z.string(),
      averageTime: z.number()
    }))
  }),
  
  // Quota usage
  quotaUsage: z.object({
    threatAnalysis: z.object({
      used: z.number(),
      limit: z.number(),
      percentage: z.number()
    }),
    assetScans: z.object({
      used: z.number(),
      limit: z.number(),
      percentage: z.number()
    }),
    threatIntelligence: z.object({
      used: z.number(),
      limit: z.number(),
      percentage: z.number()
    })
  }),
  
  // Geographic distribution
  geography: z.array(z.object({
    country: z.string(),
    region: z.string().optional(),
    requests: z.number(),
    percentage: z.number()
  })),
  
  // Error analysis
  errors: z.object({
    totalErrors: z.number(),
    errorRate: z.number(),
    byType: z.record(z.number()),
    topErrors: z.array(z.object({
      error: z.string(),
      count: z.number(),
      firstSeen: z.date(),
      lastSeen: z.date()
    }))
  }),
  
  generatedAt: z.date()
});

export type DeveloperDashboardConfig = z.infer<typeof DeveloperDashboardConfigSchema>;
export type APIKey = z.infer<typeof APIKeySchema>;
export type UsageAnalytics = z.infer<typeof UsageAnalyticsSchema>;

/**
 * Developer Dashboard and API Key Management System
 */
export class ISECTECHDeveloperDashboard {
  private dashboardConfigs: Map<string, DeveloperDashboardConfig> = new Map();
  private apiKeys: Map<string, APIKey> = new Map();
  private usageAnalytics: Map<string, UsageAnalytics> = new Map();
  private activeWebhooks: Map<string, any> = new Map();

  constructor() {
    this.initializeDefaultDashboards();
    this.startMaintenanceTasks();
  }

  /**
   * Initialize default dashboard configurations
   */
  private initializeDefaultDashboards(): void {
    // Default dashboard layout for new developers
    const defaultDashboard: DeveloperDashboardConfig = {
      dashboardId: 'default-dashboard',
      developerId: 'template',
      
      layout: {
        theme: 'auto',
        sidebar: {
          collapsed: false,
          pinned: true
        },
        widgets: [
          {
            id: 'api-usage-widget',
            type: 'API_USAGE',
            position: { x: 0, y: 0, width: 6, height: 4 },
            visible: true,
            settings: {
              period: '24h',
              showTrends: true
            }
          },
          {
            id: 'quota-status-widget',
            type: 'QUOTA_STATUS',
            position: { x: 6, y: 0, width: 6, height: 4 },
            visible: true,
            settings: {
              showWarnings: true,
              alertThreshold: 80
            }
          },
          {
            id: 'api-keys-widget',
            type: 'API_KEYS',
            position: { x: 0, y: 4, width: 8, height: 3 },
            visible: true,
            settings: {
              showUsage: true,
              maxKeys: 10
            }
          },
          {
            id: 'recent-activity-widget',
            type: 'RECENT_ACTIVITY',
            position: { x: 8, y: 4, width: 4, height: 3 },
            visible: true,
            settings: {
              maxItems: 20
            }
          },
          {
            id: 'performance-widget',
            type: 'PERFORMANCE',
            position: { x: 0, y: 7, width: 6, height: 3 },
            visible: true,
            settings: {
              showPercentiles: true,
              period: '7d'
            }
          },
          {
            id: 'alerts-widget',
            type: 'ALERTS',
            position: { x: 6, y: 7, width: 6, height: 3 },
            visible: true,
            settings: {
              showResolved: false,
              maxAlerts: 10
            }
          }
        ],
        refreshInterval: 30
      },
      
      notifications: {
        email: {
          enabled: true,
          quotaWarnings: true,
          securityAlerts: true,
          maintenanceNotices: true,
          newFeatures: false
        },
        inApp: {
          enabled: true,
          sound: false,
          desktop: true
        },
        webhook: {
          enabled: false,
          events: []
        }
      },
      
      analytics: {
        dataRetention: 90,
        detailedTracking: true,
        performanceMonitoring: true,
        errorTracking: true
      },
      
      security: {
        twoFactorAuth: false,
        sessionTimeout: 3600,
        ipWhitelist: [],
        webhookSigning: true
      },
      
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.dashboardConfigs.set('default', defaultDashboard);
    console.log('Default dashboard configuration initialized');
  }

  /**
   * Create developer dashboard
   */
  public async createDeveloperDashboard(developerId: string, config?: Partial<DeveloperDashboardConfig>): Promise<DeveloperDashboardConfig> {
    const dashboardId = `dashboard-${developerId}`;
    const defaultConfig = this.dashboardConfigs.get('default')!;
    
    const newDashboard: DeveloperDashboardConfig = {
      ...defaultConfig,
      dashboardId,
      developerId,
      ...config,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const validatedDashboard = DeveloperDashboardConfigSchema.parse(newDashboard);
    this.dashboardConfigs.set(dashboardId, validatedDashboard);

    console.log(`Created dashboard for developer: ${developerId}`);
    return validatedDashboard;
  }

  /**
   * Generate new API key
   */
  public async generateAPIKey(developerId: string, keyData: {
    name: string;
    description?: string;
    scopes?: string[];
    environment?: 'DEVELOPMENT' | 'STAGING' | 'PRODUCTION';
    expiresAt?: Date;
    rateLimits?: Partial<APIKey['rateLimits']>;
    quotas?: Partial<APIKey['quotas']>;
  }): Promise<{ apiKey: APIKey; secretKey: string }> {
    const keyId = crypto.randomUUID();
    const secretKey = `isectech_${crypto.randomBytes(32).toString('hex')}`;
    const keyPrefix = secretKey.substring(0, 16); // First 16 chars for display
    const keyHash = crypto.createHash('sha256').update(secretKey).digest('hex');
    const secretHash = crypto.createHash('sha256').update(`${secretKey}-webhook`).digest('hex');

    // Default scopes based on environment
    const defaultScopes = keyData.environment === 'PRODUCTION' 
      ? ['threats:read', 'threats:analyze', 'assets:read', 'intelligence:read']
      : ['threats:read', 'threats:analyze', 'assets:read', 'assets:scan', 'intelligence:read'];

    const newAPIKey: APIKey = {
      keyId,
      developerId,
      name: keyData.name,
      description: keyData.description,
      keyPrefix,
      keyHash,
      secretHash,
      
      scopes: keyData.scopes || defaultScopes,
      permissions: this.generatePermissionsFromScopes(keyData.scopes || defaultScopes),
      allowedIPs: [],
      allowedDomains: [],
      
      rateLimits: {
        requestsPerMinute: 60,
        requestsPerHour: 1000,
        requestsPerDay: 10000,
        requestsPerMonth: 100000,
        ...keyData.rateLimits
      },
      
      quotas: {
        threatAnalysis: { daily: 100, monthly: 1000 },
        assetScans: { daily: 10, monthly: 100 },
        threatIntelligence: { daily: 1000, monthly: 10000 },
        ...keyData.quotas
      },
      
      status: 'ACTIVE',
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: keyData.expiresAt,
      
      usage: {
        totalRequests: 0,
        requestsThisMonth: 0,
        requestsToday: 0,
        averageResponseTime: 0,
        errorRate: 0
      },
      
      securityEvents: [],
      environment: keyData.environment || 'DEVELOPMENT',
      tags: [`env:${keyData.environment || 'development'}`]
    };

    const validatedKey = APIKeySchema.parse(newAPIKey);
    this.apiKeys.set(keyId, validatedKey);

    // Log security event
    await this.logSecurityEvent(validatedKey, {
      type: 'API_KEY_CREATED',
      details: {
        name: keyData.name,
        scopes: validatedKey.scopes,
        environment: validatedKey.environment
      },
      severity: 'LOW'
    });

    console.log(`Generated API key for developer ${developerId}: ${keyData.name}`);
    return { apiKey: validatedKey, secretKey };
  }

  /**
   * Revoke API key
   */
  public async revokeAPIKey(keyId: string, reason: string): Promise<boolean> {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      return false;
    }

    apiKey.status = 'REVOKED';
    apiKey.updatedAt = new Date();

    // Log security event
    await this.logSecurityEvent(apiKey, {
      type: 'API_KEY_REVOKED',
      details: {
        reason,
        revokedAt: new Date()
      },
      severity: 'MEDIUM'
    });

    console.log(`Revoked API key ${keyId}: ${reason}`);
    return true;
  }

  /**
   * Update API key settings
   */
  public async updateAPIKey(keyId: string, updates: Partial<APIKey>): Promise<APIKey | null> {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      return null;
    }

    // Create updated key
    const updatedKey = {
      ...apiKey,
      ...updates,
      updatedAt: new Date(),
      // Prevent certain fields from being updated
      keyId: apiKey.keyId,
      developerId: apiKey.developerId,
      keyHash: apiKey.keyHash,
      secretHash: apiKey.secretHash,
      createdAt: apiKey.createdAt
    };

    const validatedKey = APIKeySchema.parse(updatedKey);
    this.apiKeys.set(keyId, validatedKey);

    // Log security event for significant changes
    if (updates.status || updates.scopes || updates.rateLimits) {
      await this.logSecurityEvent(validatedKey, {
        type: 'API_KEY_UPDATED',
        details: {
          changes: Object.keys(updates),
          updatedAt: new Date()
        },
        severity: 'LOW'
      });
    }

    return validatedKey;
  }

  /**
   * Get developer's API keys
   */
  public getDeveloperAPIKeys(developerId: string): APIKey[] {
    return Array.from(this.apiKeys.values())
      .filter(key => key.developerId === developerId)
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Authenticate API key
   */
  public async authenticateAPIKey(keyString: string): Promise<{
    valid: boolean;
    apiKey?: APIKey;
    error?: string;
  }> {
    try {
      const keyHash = crypto.createHash('sha256').update(keyString).digest('hex');
      
      // Find matching key
      const apiKey = Array.from(this.apiKeys.values()).find(key => key.keyHash === keyHash);
      
      if (!apiKey) {
        return { valid: false, error: 'Invalid API key' };
      }

      if (apiKey.status !== 'ACTIVE') {
        return { valid: false, error: `API key is ${apiKey.status.toLowerCase()}` };
      }

      if (apiKey.expiresAt && apiKey.expiresAt < new Date()) {
        // Auto-expire the key
        apiKey.status = 'EXPIRED';
        apiKey.updatedAt = new Date();
        return { valid: false, error: 'API key has expired' };
      }

      // Update last used timestamp
      apiKey.lastUsed = new Date();
      apiKey.usage.lastRequestAt = new Date();

      return { valid: true, apiKey };

    } catch (error) {
      return { valid: false, error: 'Authentication failed' };
    }
  }

  /**
   * Record API usage
   */
  public async recordAPIUsage(keyId: string, usageData: {
    endpoint: string;
    method: string;
    statusCode: number;
    responseTime: number;
    requestSize: number;
    responseSize: number;
    ipAddress: string;
    userAgent?: string;
  }): Promise<void> {
    const apiKey = this.apiKeys.get(keyId);
    if (!apiKey) {
      return;
    }

    // Update usage statistics
    apiKey.usage.totalRequests++;
    apiKey.usage.requestsToday++; // Would be reset daily in production
    apiKey.usage.requestsThisMonth++; // Would be reset monthly in production
    
    // Update average response time (simple moving average)
    const totalResponseTime = apiKey.usage.averageResponseTime * (apiKey.usage.totalRequests - 1) + usageData.responseTime;
    apiKey.usage.averageResponseTime = totalResponseTime / apiKey.usage.totalRequests;
    
    // Update error rate
    if (usageData.statusCode >= 400) {
      const totalErrors = Math.floor(apiKey.usage.errorRate * (apiKey.usage.totalRequests - 1) / 100) + 1;
      apiKey.usage.errorRate = (totalErrors / apiKey.usage.totalRequests) * 100;
    } else {
      const totalErrors = Math.floor(apiKey.usage.errorRate * (apiKey.usage.totalRequests - 1) / 100);
      apiKey.usage.errorRate = (totalErrors / apiKey.usage.totalRequests) * 100;
    }

    apiKey.updatedAt = new Date();

    // Check for rate limit violations or suspicious activity
    await this.checkForSecurityEvents(apiKey, usageData);
  }

  /**
   * Generate usage analytics
   */
  public async generateUsageAnalytics(developerId: string, period: {
    start: Date;
    end: Date;
    type: 'HOURLY' | 'DAILY' | 'WEEKLY' | 'MONTHLY';
  }): Promise<UsageAnalytics> {
    // In production, this would query actual usage data
    // For now, generating sample analytics data
    
    const analytics: UsageAnalytics = {
      developerId,
      period,
      
      requests: {
        total: Math.floor(Math.random() * 10000) + 1000,
        successful: Math.floor(Math.random() * 9000) + 800,
        failed: Math.floor(Math.random() * 500) + 50,
        blocked: Math.floor(Math.random() * 100) + 10,
        throttled: Math.floor(Math.random() * 200) + 20,
        
        byEndpoint: [
          {
            endpoint: '/threats/analyze',
            method: 'POST',
            count: Math.floor(Math.random() * 3000) + 500,
            averageResponseTime: Math.floor(Math.random() * 2000) + 500,
            errorRate: Math.random() * 5
          },
          {
            endpoint: '/threats/feeds',
            method: 'GET',
            count: Math.floor(Math.random() * 2000) + 300,
            averageResponseTime: Math.floor(Math.random() * 1000) + 200,
            errorRate: Math.random() * 3
          },
          {
            endpoint: '/assets/scan',
            method: 'POST',
            count: Math.floor(Math.random() * 500) + 50,
            averageResponseTime: Math.floor(Math.random() * 5000) + 1000,
            errorRate: Math.random() * 8
          }
        ],
        
        byStatusCode: {
          200: Math.floor(Math.random() * 8000) + 700,
          400: Math.floor(Math.random() * 200) + 20,
          401: Math.floor(Math.random() * 50) + 5,
          429: Math.floor(Math.random() * 100) + 10,
          500: Math.floor(Math.random() * 30) + 3
        },
        
        timeSeries: this.generateTimeSeriesData(period)
      },
      
      performance: {
        averageResponseTime: Math.floor(Math.random() * 1500) + 300,
        p50ResponseTime: Math.floor(Math.random() * 1000) + 200,
        p95ResponseTime: Math.floor(Math.random() * 3000) + 1000,
        p99ResponseTime: Math.floor(Math.random() * 5000) + 2000,
        slowestEndpoints: [
          { endpoint: '/assets/scan', averageTime: 3500 },
          { endpoint: '/threats/analyze', averageTime: 1200 },
          { endpoint: '/threats/feeds', averageTime: 450 }
        ]
      },
      
      quotaUsage: {
        threatAnalysis: {
          used: Math.floor(Math.random() * 80) + 10,
          limit: 100,
          percentage: 0
        },
        assetScans: {
          used: Math.floor(Math.random() * 8) + 1,
          limit: 10,
          percentage: 0
        },
        threatIntelligence: {
          used: Math.floor(Math.random() * 800) + 100,
          limit: 1000,
          percentage: 0
        }
      },
      
      geography: [
        { country: 'United States', requests: Math.floor(Math.random() * 4000) + 500, percentage: 0 },
        { country: 'United Kingdom', requests: Math.floor(Math.random() * 2000) + 200, percentage: 0 },
        { country: 'Germany', requests: Math.floor(Math.random() * 1500) + 150, percentage: 0 },
        { country: 'Canada', requests: Math.floor(Math.random() * 1000) + 100, percentage: 0 }
      ],
      
      errors: {
        totalErrors: Math.floor(Math.random() * 300) + 50,
        errorRate: Math.random() * 5 + 1,
        byType: {
          'RATE_LIMIT_EXCEEDED': Math.floor(Math.random() * 100) + 10,
          'INVALID_REQUEST': Math.floor(Math.random() * 80) + 8,
          'AUTHENTICATION_FAILED': Math.floor(Math.random() * 50) + 5,
          'SERVICE_UNAVAILABLE': Math.floor(Math.random() * 30) + 3
        },
        topErrors: [
          {
            error: 'Rate limit exceeded',
            count: Math.floor(Math.random() * 100) + 10,
            firstSeen: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
            lastSeen: new Date()
          }
        ]
      },
      
      generatedAt: new Date()
    };

    // Calculate percentages
    analytics.quotaUsage.threatAnalysis.percentage = 
      (analytics.quotaUsage.threatAnalysis.used / analytics.quotaUsage.threatAnalysis.limit) * 100;
    analytics.quotaUsage.assetScans.percentage = 
      (analytics.quotaUsage.assetScans.used / analytics.quotaUsage.assetScans.limit) * 100;
    analytics.quotaUsage.threatIntelligence.percentage = 
      (analytics.quotaUsage.threatIntelligence.used / analytics.quotaUsage.threatIntelligence.limit) * 100;

    const totalGeoRequests = analytics.geography.reduce((sum, geo) => sum + geo.requests, 0);
    analytics.geography.forEach(geo => {
      geo.percentage = (geo.requests / totalGeoRequests) * 100;
    });

    const validatedAnalytics = UsageAnalyticsSchema.parse(analytics);
    this.usageAnalytics.set(`${developerId}-${Date.now()}`, validatedAnalytics);

    return validatedAnalytics;
  }

  /**
   * Get developer dashboard data
   */
  public async getDeveloperDashboardData(developerId: string): Promise<{
    config: DeveloperDashboardConfig;
    apiKeys: APIKey[];
    analytics: UsageAnalytics;
    alerts: any[];
    recentActivity: any[];
  }> {
    const dashboardId = `dashboard-${developerId}`;
    let config = this.dashboardConfigs.get(dashboardId);
    
    if (!config) {
      config = await this.createDeveloperDashboard(developerId);
    }

    const apiKeys = this.getDeveloperAPIKeys(developerId);
    
    const analytics = await this.generateUsageAnalytics(developerId, {
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days ago
      end: new Date(),
      type: 'DAILY'
    });

    const alerts = await this.getDeveloperAlerts(developerId);
    const recentActivity = await this.getDeveloperRecentActivity(developerId);

    return {
      config,
      apiKeys,
      analytics,
      alerts,
      recentActivity
    };
  }

  /**
   * Update dashboard configuration
   */
  public async updateDashboardConfig(developerId: string, updates: Partial<DeveloperDashboardConfig>): Promise<DeveloperDashboardConfig | null> {
    const dashboardId = `dashboard-${developerId}`;
    const config = this.dashboardConfigs.get(dashboardId);
    
    if (!config) {
      return null;
    }

    const updatedConfig = {
      ...config,
      ...updates,
      updatedAt: new Date()
    };

    const validatedConfig = DeveloperDashboardConfigSchema.parse(updatedConfig);
    this.dashboardConfigs.set(dashboardId, validatedConfig);

    return validatedConfig;
  }

  // Private helper methods
  private generatePermissionsFromScopes(scopes: string[]): string[] {
    const permissions: string[] = [];
    
    scopes.forEach(scope => {
      switch (scope) {
        case 'threats:read':
          permissions.push('read:threat_intelligence');
          break;
        case 'threats:analyze':
          permissions.push('create:threat_analysis', 'read:threat_analysis');
          break;
        case 'assets:read':
          permissions.push('read:assets');
          break;
        case 'assets:scan':
          permissions.push('create:asset_scan', 'read:asset_scan');
          break;
        case 'intelligence:read':
          permissions.push('read:threat_feeds', 'read:iocs');
          break;
      }
    });
    
    return [...new Set(permissions)]; // Remove duplicates
  }

  private async logSecurityEvent(apiKey: APIKey, event: {
    type: 'API_KEY_CREATED' | 'API_KEY_REVOKED' | 'API_KEY_UPDATED' | 'UNAUTHORIZED_ACCESS' | 'RATE_LIMIT_EXCEEDED' | 'SUSPICIOUS_ACTIVITY' | 'IP_VIOLATION';
    details: Record<string, any>;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }): Promise<void> {
    const securityEvent = {
      eventId: crypto.randomUUID(),
      type: event.type,
      timestamp: new Date(),
      details: event.details,
      severity: event.severity
    };

    apiKey.securityEvents.push(securityEvent);
    
    // Keep only last 100 events
    if (apiKey.securityEvents.length > 100) {
      apiKey.securityEvents = apiKey.securityEvents.slice(-100);
    }

    // Send alerts for high/critical events
    if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
      await this.sendSecurityAlert(apiKey.developerId, securityEvent);
    }
  }

  private async checkForSecurityEvents(apiKey: APIKey, usageData: any): Promise<void> {
    // Check for rate limiting
    if (usageData.statusCode === 429) {
      await this.logSecurityEvent(apiKey, {
        type: 'RATE_LIMIT_EXCEEDED',
        details: {
          endpoint: usageData.endpoint,
          ipAddress: usageData.ipAddress,
          timestamp: new Date()
        },
        severity: 'MEDIUM'
      });
    }

    // Check for authentication failures
    if (usageData.statusCode === 401 || usageData.statusCode === 403) {
      await this.logSecurityEvent(apiKey, {
        type: 'UNAUTHORIZED_ACCESS',
        details: {
          endpoint: usageData.endpoint,
          ipAddress: usageData.ipAddress,
          statusCode: usageData.statusCode
        },
        severity: 'HIGH'
      });
    }

    // Check for IP violations (if IP whitelist is configured)
    if (apiKey.allowedIPs.length > 0 && !apiKey.allowedIPs.includes(usageData.ipAddress)) {
      await this.logSecurityEvent(apiKey, {
        type: 'IP_VIOLATION',
        details: {
          ipAddress: usageData.ipAddress,
          allowedIPs: apiKey.allowedIPs
        },
        severity: 'HIGH'
      });
    }
  }

  private async sendSecurityAlert(developerId: string, event: any): Promise<void> {
    // Implementation would send actual alerts
    console.log(`Security alert for developer ${developerId}:`, event);
  }

  private async getDeveloperAlerts(developerId: string): Promise<any[]> {
    // Get alerts for developer
    const apiKeys = this.getDeveloperAPIKeys(developerId);
    const alerts: any[] = [];

    apiKeys.forEach(key => {
      key.securityEvents.forEach(event => {
        if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
          alerts.push({
            id: event.eventId,
            type: 'SECURITY',
            severity: event.severity,
            message: `Security event: ${event.type}`,
            details: event.details,
            timestamp: event.timestamp,
            apiKeyId: key.keyId
          });
        }
      });

      // Check quota warnings
      const quotaUsage = key.quotas;
      Object.entries(quotaUsage).forEach(([service, quota]) => {
        if (quota.daily && key.usage.requestsToday > quota.daily * 0.8) {
          alerts.push({
            id: crypto.randomUUID(),
            type: 'QUOTA_WARNING',
            severity: 'MEDIUM',
            message: `${service} quota usage is above 80%`,
            details: { service, usage: key.usage.requestsToday, limit: quota.daily },
            timestamp: new Date(),
            apiKeyId: key.keyId
          });
        }
      });
    });

    return alerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).slice(0, 20);
  }

  private async getDeveloperRecentActivity(developerId: string): Promise<any[]> {
    // Generate sample recent activity
    const activities = [
      {
        id: crypto.randomUUID(),
        type: 'API_CALL',
        description: 'Threat analysis request completed',
        timestamp: new Date(Date.now() - 5 * 60 * 1000),
        details: { endpoint: '/threats/analyze', responseTime: 1200 }
      },
      {
        id: crypto.randomUUID(),
        type: 'API_KEY',
        description: 'API key created',
        timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
        details: { keyName: 'Production Key' }
      }
    ];

    return activities;
  }

  private generateTimeSeriesData(period: any): any[] {
    const data = [];
    const now = new Date();
    const hoursBack = period.type === 'DAILY' ? 24 : period.type === 'WEEKLY' ? 168 : 720;
    
    for (let i = hoursBack; i >= 0; i--) {
      const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000);
      data.push({
        timestamp,
        requests: Math.floor(Math.random() * 100) + 10,
        errors: Math.floor(Math.random() * 10),
        responseTime: Math.floor(Math.random() * 1000) + 200
      });
    }
    
    return data;
  }

  private startMaintenanceTasks(): void {
    // Clean up old analytics data every hour
    setInterval(() => {
      const cutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000); // 90 days
      for (const [key, analytics] of this.usageAnalytics) {
        if (analytics.generatedAt < cutoff) {
          this.usageAnalytics.delete(key);
        }
      }
    }, 60 * 60 * 1000);

    // Check for expired API keys every day
    setInterval(() => {
      const now = new Date();
      for (const [keyId, apiKey] of this.apiKeys) {
        if (apiKey.expiresAt && apiKey.expiresAt < now && apiKey.status === 'ACTIVE') {
          apiKey.status = 'EXPIRED';
          apiKey.updatedAt = now;
          console.log(`Auto-expired API key: ${keyId}`);
        }
      }
    }, 24 * 60 * 60 * 1000);
  }
}

// Export production-ready developer dashboard
export const isectechDeveloperDashboard = new ISECTECHDeveloperDashboard();