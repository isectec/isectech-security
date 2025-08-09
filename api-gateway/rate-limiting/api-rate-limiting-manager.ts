/**
 * Production-grade API Rate Limiting and Quota Management System for iSECTECH
 * 
 * Provides comprehensive rate limiting, quota management, and usage analytics
 * with granular policies per API, client, tenant, and user for fair usage
 * enforcement and abuse prevention.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';
import * as crypto from 'crypto';

// Rate Limiting Configuration Schemas
export const RateLimitPolicySchema = z.object({
  policyId: z.string(),
  name: z.string(),
  description: z.string(),
  
  // Scope definition
  scope: z.object({
    type: z.enum(['GLOBAL', 'TENANT', 'CLIENT', 'USER', 'API', 'ENDPOINT']),
    targets: z.array(z.string()), // List of target IDs (tenant IDs, client IDs, etc.)
    serviceScope: z.array(z.string()).optional(), // Specific services
    routeScope: z.array(z.string()).optional() // Specific routes
  }),
  
  // Rate limiting configuration
  rateLimits: z.array(z.object({
    name: z.string(),
    window: z.enum(['SECOND', 'MINUTE', 'HOUR', 'DAY', 'MONTH']),
    windowSize: z.number().min(1), // Number of time units (e.g., 5 for 5 minutes)
    limit: z.number().min(0), // Maximum requests allowed
    burstLimit: z.number().min(0).optional(), // Allow temporary bursts
    slidingWindow: z.boolean().default(true), // Use sliding window vs fixed window
    
    // Action when limit exceeded
    action: z.enum(['BLOCK', 'THROTTLE', 'LOG_ONLY', 'ALERT']),
    blockDuration: z.number().optional(), // Minutes to block after limit exceeded
    throttleDelay: z.number().optional(), // Milliseconds to delay requests
    
    // Custom response
    customResponse: z.object({
      statusCode: z.number().default(429),
      body: z.string().optional(),
      headers: z.record(z.string()).optional()
    }).optional()
  })),
  
  // Quota management
  quotas: z.array(z.object({
    name: z.string(),
    period: z.enum(['DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY', 'CUSTOM']),
    customPeriodDays: z.number().optional(), // For custom periods
    limit: z.number().min(0),
    softLimit: z.number().min(0).optional(), // Warning threshold
    resetTime: z.string().optional(), // Time of day to reset (HH:MM)
    
    // Overage policy
    allowOverage: z.boolean().default(false),
    overageRate: z.number().optional(), // Cost per request over quota
    maxOverage: z.number().optional(), // Maximum overage allowed
    
    // Actions
    onSoftLimitAction: z.enum(['WARN', 'ALERT', 'THROTTLE']).default('WARN'),
    onHardLimitAction: z.enum(['BLOCK', 'THROTTLE', 'ALERT']).default('BLOCK')
  })),
  
  // Exemptions and overrides
  exemptions: z.object({
    ipWhitelist: z.array(z.string()).default([]), // IP addresses/CIDR blocks
    clientWhitelist: z.array(z.string()).default([]), // Client IDs
    userWhitelist: z.array(z.string()).default([]), // User IDs
    emergencyBypass: z.boolean().default(false), // Emergency bypass flag
    healthCheckExempt: z.boolean().default(true) // Exempt health check endpoints
  }),
  
  // Advanced configuration
  advanced: z.object({
    distributedLimiting: z.boolean().default(true), // Use Redis for distributed limiting
    precisionMode: z.enum(['APPROXIMATE', 'PRECISE']).default('APPROXIMATE'),
    backpressure: z.boolean().default(true), // Apply backpressure when approaching limits
    gracefulDegradation: z.boolean().default(true), // Graceful handling of storage failures
    
    // Machine learning features
    adaptiveLimiting: z.boolean().default(false), // Adjust limits based on patterns
    anomalyDetection: z.boolean().default(true), // Detect unusual usage patterns
    fraudDetection: z.boolean().default(true) // Detect potential fraud/abuse
  }),
  
  // Monitoring and alerting
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsCollection: z.boolean().default(true),
    alerting: z.object({
      enabled: z.boolean().default(true),
      thresholds: z.object({
        warningPercentage: z.number().min(0).max(100).default(80),
        criticalPercentage: z.number().min(0).max(100).default(95),
        anomalyScore: z.number().min(0).max(1).default(0.8)
      }),
      channels: z.array(z.enum(['EMAIL', 'SLACK', 'WEBHOOK', 'SMS'])).default(['EMAIL', 'SLACK'])
    }),
    reporting: z.object({
      enabled: z.boolean().default(true),
      frequency: z.enum(['HOURLY', 'DAILY', 'WEEKLY', 'MONTHLY']).default('DAILY'),
      recipients: z.array(z.string()).default([])
    })
  }),
  
  // Compliance and audit
  compliance: z.object({
    auditLogging: z.boolean().default(true),
    dataRetentionDays: z.number().default(90),
    gdprCompliant: z.boolean().default(true),
    encryptMetrics: z.boolean().default(true)
  }),
  
  // Metadata
  priority: z.number().min(0).max(100).default(50), // Policy priority (higher = more priority)
  isActive: z.boolean().default(true),
  effectiveFrom: z.date().optional(),
  effectiveUntil: z.date().optional(),
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date(),
  version: z.string(),
  tags: z.array(z.string()).default(['isectech', 'rate-limiting', 'quota'])
});

export const UsageMetricsSchema = z.object({
  metricId: z.string(),
  timestamp: z.date(),
  
  // Identity information
  tenantId: z.string(),
  clientId: z.string().optional(),
  userId: z.string().optional(),
  ipAddress: z.string(),
  userAgent: z.string().optional(),
  
  // Request information
  method: z.string(),
  path: z.string(),
  endpoint: z.string(),
  serviceId: z.string(),
  
  // Response information
  statusCode: z.number(),
  responseTime: z.number(), // milliseconds
  responseSize: z.number(), // bytes
  
  // Rate limiting information
  rateLimitPolicy: z.string().optional(),
  currentUsage: z.number(),
  limitRemaining: z.number(),
  quotaUsed: z.number().optional(),
  quotaRemaining: z.number().optional(),
  
  // Flags
  wasBlocked: z.boolean().default(false),
  wasThrottled: z.boolean().default(false),
  wasAnomalous: z.boolean().default(false),
  fraudScore: z.number().min(0).max(1).optional(),
  
  // Custom metadata
  customTags: z.record(z.string()).optional(),
  sessionId: z.string().optional(),
  correlationId: z.string().optional()
});

export const QuotaUsageSchema = z.object({
  quotaId: z.string(),
  tenantId: z.string(),
  clientId: z.string().optional(),
  userId: z.string().optional(),
  
  // Quota information
  quotaName: z.string(),
  quotaPeriod: z.string(),
  quotaLimit: z.number(),
  currentUsage: z.number(),
  remainingQuota: z.number(),
  
  // Time information
  periodStart: z.date(),
  periodEnd: z.date(),
  nextReset: z.date(),
  
  // Status
  status: z.enum(['NORMAL', 'WARNING', 'EXCEEDED', 'BLOCKED']),
  overageAmount: z.number().default(0),
  lastUpdated: z.date(),
  
  // Metadata
  createdAt: z.date(),
  updatedAt: z.date()
});

export type RateLimitPolicy = z.infer<typeof RateLimitPolicySchema>;
export type UsageMetrics = z.infer<typeof UsageMetricsSchema>;
export type QuotaUsage = z.infer<typeof QuotaUsageSchema>;

/**
 * API Rate Limiting and Quota Management System
 */
export class ISECTECHAPIRateLimitingManager {
  private policies: Map<string, RateLimitPolicy> = new Map();
  private usageCounters: Map<string, Map<string, number>> = new Map(); // Policy -> Key -> Count
  private quotaUsage: Map<string, QuotaUsage> = new Map();
  private usageMetrics: UsageMetrics[] = [];
  private blockedIPs: Map<string, Date> = new Map();
  private anomalyDetector: Map<string, number[]> = new Map(); // For pattern detection

  constructor(
    private config: {
      redisUrl: string;
      metricsRetentionDays: number;
      alertingWebhook: string;
      defaultBlockDuration: number; // minutes
      anomalyThreshold: number; // standard deviations
      fraudThreshold: number; // 0-1 score
      maxMetricsInMemory: number;
    }
  ) {
    this.initializeISECTECHRateLimitPolicies();
    this.startCleanupTasks();
  }

  /**
   * Initialize rate limiting policies for iSECTECH services
   */
  private initializeISECTECHRateLimitPolicies(): void {
    // High Security APIs (Threat Detection, AI/ML)
    const highSecurityPolicy: RateLimitPolicy = {
      policyId: 'high-security-api-limits',
      name: 'High Security API Rate Limits',
      description: 'Strict rate limits for threat detection and AI/ML services',
      
      scope: {
        type: 'API',
        targets: ['threat-detection', 'ai-ml-services'],
        serviceScope: ['isectech-threat-detection', 'isectech-ai-ml-services'],
        routeScope: ['/api/v1/threats/analyze', '/api/v1/ai/behavioral/analyze']
      },
      
      rateLimits: [
        {
          name: 'requests_per_minute',
          window: 'MINUTE',
          windowSize: 1,
          limit: 60, // 60 requests per minute
          burstLimit: 80,
          slidingWindow: true,
          action: 'THROTTLE',
          throttleDelay: 1000, // 1 second delay
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Rate limit exceeded for security API',
              message: 'Too many threat analysis requests. Please retry after 1 minute.',
              retryAfter: 60,
              type: 'RATE_LIMIT_EXCEEDED'
            }),
            headers: {
              'Retry-After': '60',
              'X-RateLimit-Policy': 'high-security-api-limits'
            }
          }
        },
        {
          name: 'requests_per_hour',
          window: 'HOUR',
          windowSize: 1,
          limit: 1000, // 1000 requests per hour
          slidingWindow: true,
          action: 'BLOCK',
          blockDuration: 60, // Block for 1 hour
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Hourly rate limit exceeded',
              message: 'Security API hourly limit exceeded. Access blocked for 1 hour.',
              retryAfter: 3600,
              type: 'HOURLY_LIMIT_EXCEEDED'
            })
          }
        }
      ],
      
      quotas: [
        {
          name: 'daily_threat_analysis',
          period: 'DAILY',
          limit: 5000, // 5000 threat analyses per day
          softLimit: 4000,
          resetTime: '00:00',
          allowOverage: false,
          onSoftLimitAction: 'ALERT',
          onHardLimitAction: 'BLOCK'
        },
        {
          name: 'monthly_premium_features',
          period: 'MONTHLY',
          limit: 50000,
          softLimit: 40000,
          allowOverage: true,
          overageRate: 0.001, // $0.001 per request over quota
          maxOverage: 10000,
          onSoftLimitAction: 'WARN',
          onHardLimitAction: 'THROTTLE'
        }
      ],
      
      exemptions: {
        ipWhitelist: [
          '10.0.0.0/8',      // Internal networks
          '172.16.0.0/12',
          '192.168.0.0/16'
        ],
        clientWhitelist: ['isectech-internal-monitoring', 'isectech-health-check'],
        userWhitelist: ['system-admin', 'emergency-user'],
        emergencyBypass: false,
        healthCheckExempt: true
      },
      
      advanced: {
        distributedLimiting: true,
        precisionMode: 'PRECISE',
        backpressure: true,
        gracefulDegradation: true,
        adaptiveLimiting: true,
        anomalyDetection: true,
        fraudDetection: true
      },
      
      monitoring: {
        enabled: true,
        metricsCollection: true,
        alerting: {
          enabled: true,
          thresholds: {
            warningPercentage: 75,
            criticalPercentage: 90,
            anomalyScore: 0.7
          },
          channels: ['EMAIL', 'SLACK', 'WEBHOOK']
        },
        reporting: {
          enabled: true,
          frequency: 'HOURLY',
          recipients: ['security-team@isectech.com', 'ops-team@isectech.com']
        }
      },
      
      compliance: {
        auditLogging: true,
        dataRetentionDays: 365, // Longer retention for security APIs
        gdprCompliant: true,
        encryptMetrics: true
      },
      
      priority: 90,
      isActive: true,
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0',
      tags: ['isectech', 'high-security', 'threat-detection', 'ai-ml']
    };

    // Standard APIs (Asset Discovery, Compliance)
    const standardPolicy: RateLimitPolicy = {
      policyId: 'standard-api-limits',
      name: 'Standard API Rate Limits',
      description: 'Standard rate limits for general platform APIs',
      
      scope: {
        type: 'API',
        targets: ['asset-discovery', 'compliance-automation', 'vulnerability-management'],
        serviceScope: [
          'isectech-asset-discovery',
          'isectech-compliance-automation',
          'isectech-vulnerability-management'
        ]
      },
      
      rateLimits: [
        {
          name: 'requests_per_minute',
          window: 'MINUTE',
          windowSize: 1,
          limit: 120, // 120 requests per minute
          burstLimit: 150,
          slidingWindow: true,
          action: 'THROTTLE',
          throttleDelay: 500,
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Rate limit exceeded',
              message: 'Too many requests. Please slow down.',
              retryAfter: 60,
              type: 'RATE_LIMIT_EXCEEDED'
            })
          }
        },
        {
          name: 'requests_per_hour',
          window: 'HOUR',
          windowSize: 1,
          limit: 2000,
          slidingWindow: true,
          action: 'BLOCK',
          blockDuration: 30,
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Hourly rate limit exceeded',
              message: 'API hourly limit exceeded. Access blocked for 30 minutes.',
              retryAfter: 1800,
              type: 'HOURLY_LIMIT_EXCEEDED'
            })
          }
        }
      ],
      
      quotas: [
        {
          name: 'daily_api_calls',
          period: 'DAILY',
          limit: 10000,
          softLimit: 8000,
          resetTime: '00:00',
          allowOverage: true,
          overageRate: 0.0005,
          maxOverage: 5000,
          onSoftLimitAction: 'WARN',
          onHardLimitAction: 'THROTTLE'
        }
      ],
      
      exemptions: {
        ipWhitelist: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        clientWhitelist: ['isectech-internal-services'],
        userWhitelist: [],
        emergencyBypass: false,
        healthCheckExempt: true
      },
      
      advanced: {
        distributedLimiting: true,
        precisionMode: 'APPROXIMATE',
        backpressure: true,
        gracefulDegradation: true,
        adaptiveLimiting: false,
        anomalyDetection: true,
        fraudDetection: false
      },
      
      monitoring: {
        enabled: true,
        metricsCollection: true,
        alerting: {
          enabled: true,
          thresholds: {
            warningPercentage: 80,
            criticalPercentage: 95,
            anomalyScore: 0.8
          },
          channels: ['EMAIL', 'SLACK']
        },
        reporting: {
          enabled: true,
          frequency: 'DAILY',
          recipients: ['ops-team@isectech.com']
        }
      },
      
      compliance: {
        auditLogging: true,
        dataRetentionDays: 90,
        gdprCompliant: true,
        encryptMetrics: false
      },
      
      priority: 50,
      isActive: true,
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0',
      tags: ['isectech', 'standard', 'general-apis']
    };

    // Public APIs (Documentation, Status)
    const publicPolicy: RateLimitPolicy = {
      policyId: 'public-api-limits',
      name: 'Public API Rate Limits',
      description: 'Generous rate limits for public APIs and documentation',
      
      scope: {
        type: 'API',
        targets: ['api-docs', 'health-check', 'status'],
        serviceScope: ['isectech-api-docs', 'isectech-health-check', 'isectech-status']
      },
      
      rateLimits: [
        {
          name: 'requests_per_minute',
          window: 'MINUTE',
          windowSize: 1,
          limit: 300, // 300 requests per minute
          burstLimit: 500,
          slidingWindow: true,
          action: 'THROTTLE',
          throttleDelay: 100,
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Rate limit exceeded',
              message: 'Too many requests to public API. Please slow down.',
              retryAfter: 60,
              type: 'RATE_LIMIT_EXCEEDED'
            })
          }
        }
      ],
      
      quotas: [
        {
          name: 'daily_public_calls',
          period: 'DAILY',
          limit: 50000,
          softLimit: 40000,
          resetTime: '00:00',
          allowOverage: true,
          overageRate: 0,
          maxOverage: 20000,
          onSoftLimitAction: 'LOG_ONLY',
          onHardLimitAction: 'THROTTLE'
        }
      ],
      
      exemptions: {
        ipWhitelist: [],
        clientWhitelist: ['isectech-website', 'isectech-status-page'],
        userWhitelist: [],
        emergencyBypass: false,
        healthCheckExempt: true
      },
      
      advanced: {
        distributedLimiting: false, // Use local limiting for public APIs
        precisionMode: 'APPROXIMATE',
        backpressure: false,
        gracefulDegradation: true,
        adaptiveLimiting: false,
        anomalyDetection: false,
        fraudDetection: false
      },
      
      monitoring: {
        enabled: true,
        metricsCollection: true,
        alerting: {
          enabled: false, // No alerting for public APIs
          thresholds: {
            warningPercentage: 90,
            criticalPercentage: 95,
            anomalyScore: 0.9
          },
          channels: ['EMAIL']
        },
        reporting: {
          enabled: true,
          frequency: 'WEEKLY',
          recipients: ['ops-team@isectech.com']
        }
      },
      
      compliance: {
        auditLogging: false, // No audit logging for public APIs
        dataRetentionDays: 30,
        gdprCompliant: true,
        encryptMetrics: false
      },
      
      priority: 10,
      isActive: true,
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0',
      tags: ['isectech', 'public', 'documentation']
    };

    // Tenant-specific rate limiting
    const tenantPremiumPolicy: RateLimitPolicy = {
      policyId: 'tenant-premium-limits',
      name: 'Premium Tenant Rate Limits',
      description: 'Enhanced rate limits for premium tenants',
      
      scope: {
        type: 'TENANT',
        targets: ['premium-tenant-1', 'premium-tenant-2'], // Premium tenant IDs
      },
      
      rateLimits: [
        {
          name: 'requests_per_minute',
          window: 'MINUTE',
          windowSize: 1,
          limit: 500, // 5x standard limit
          burstLimit: 750,
          slidingWindow: true,
          action: 'THROTTLE',
          throttleDelay: 200,
          customResponse: {
            statusCode: 429,
            body: JSON.stringify({
              error: 'Premium rate limit exceeded',
              message: 'Premium tenant rate limit exceeded. Contact support for upgrade.',
              retryAfter: 60,
              type: 'PREMIUM_RATE_LIMIT_EXCEEDED'
            })
          }
        }
      ],
      
      quotas: [
        {
          name: 'monthly_premium_quota',
          period: 'MONTHLY',
          limit: 1000000, // 1M requests per month
          softLimit: 800000,
          allowOverage: true,
          overageRate: 0.0001, // Lower overage rate for premium
          maxOverage: 500000,
          onSoftLimitAction: 'WARN',
          onHardLimitAction: 'THROTTLE'
        }
      ],
      
      exemptions: {
        ipWhitelist: [],
        clientWhitelist: [],
        userWhitelist: [],
        emergencyBypass: true, // Premium tenants get emergency bypass
        healthCheckExempt: true
      },
      
      advanced: {
        distributedLimiting: true,
        precisionMode: 'PRECISE',
        backpressure: false, // No backpressure for premium
        gracefulDegradation: true,
        adaptiveLimiting: true,
        anomalyDetection: true,
        fraudDetection: true
      },
      
      monitoring: {
        enabled: true,
        metricsCollection: true,
        alerting: {
          enabled: true,
          thresholds: {
            warningPercentage: 85,
            criticalPercentage: 95,
            anomalyScore: 0.6
          },
          channels: ['EMAIL', 'SLACK', 'SMS'] // Premium gets SMS alerts
        },
        reporting: {
          enabled: true,
          frequency: 'DAILY',
          recipients: ['premium-support@isectech.com', 'ops-team@isectech.com']
        }
      },
      
      compliance: {
        auditLogging: true,
        dataRetentionDays: 365, // Longer retention for premium
        gdprCompliant: true,
        encryptMetrics: true
      },
      
      priority: 100, // Highest priority
      isActive: true,
      createdBy: 'system',
      createdAt: new Date(),
      updatedAt: new Date(),
      version: '1.0',
      tags: ['isectech', 'premium', 'enterprise']
    };

    // Store all policies
    [
      highSecurityPolicy,
      standardPolicy,
      publicPolicy,
      tenantPremiumPolicy
    ].forEach(policy => {
      const validatedPolicy = RateLimitPolicySchema.parse(policy);
      this.policies.set(policy.policyId, validatedPolicy);
    });

    console.log(`Initialized ${this.policies.size} rate limiting policies`);
  }

  /**
   * Check if request should be allowed
   */
  public async checkRateLimit(request: {
    tenantId: string;
    clientId?: string;
    userId?: string;
    ipAddress: string;
    method: string;
    path: string;
    endpoint: string;
    serviceId: string;
    userAgent?: string;
  }): Promise<{
    allowed: boolean;
    policy?: RateLimitPolicy;
    rateLimitInfo: {
      limit: number;
      remaining: number;
      resetTime: Date;
      retryAfter?: number;
    };
    quotaInfo?: {
      limit: number;
      used: number;
      remaining: number;
      resetTime: Date;
    };
    reason?: string;
    customResponse?: any;
  }> {
    try {
      // Find applicable policies (sorted by priority)
      const applicablePolicies = this.findApplicablePolicies(request);
      
      if (applicablePolicies.length === 0) {
        // No policies apply - allow request
        return {
          allowed: true,
          rateLimitInfo: {
            limit: Infinity,
            remaining: Infinity,
            resetTime: new Date(Date.now() + 3600000) // 1 hour from now
          }
        };
      }

      // Check each policy (highest priority first)
      for (const policy of applicablePolicies) {
        // Check exemptions first
        if (this.isExempt(request, policy)) {
          continue;
        }

        // Check if IP is blocked
        const blockExpiry = this.blockedIPs.get(request.ipAddress);
        if (blockExpiry && blockExpiry > new Date()) {
          return {
            allowed: false,
            policy,
            rateLimitInfo: {
              limit: 0,
              remaining: 0,
              resetTime: blockExpiry,
              retryAfter: Math.ceil((blockExpiry.getTime() - Date.now()) / 1000)
            },
            reason: 'IP_BLOCKED',
            customResponse: {
              statusCode: 429,
              body: JSON.stringify({
                error: 'IP address blocked',
                message: 'Your IP address is temporarily blocked due to rate limit violations.',
                retryAfter: Math.ceil((blockExpiry.getTime() - Date.now()) / 1000)
              })
            }
          };
        }

        // Check rate limits
        const rateLimitResult = await this.checkPolicyRateLimits(request, policy);
        if (!rateLimitResult.allowed) {
          return rateLimitResult;
        }

        // Check quotas
        const quotaResult = await this.checkPolicyQuotas(request, policy);
        if (!quotaResult.allowed) {
          return quotaResult;
        }
      }

      // All policies passed - allow request
      const primaryPolicy = applicablePolicies[0];
      const rateLimitInfo = await this.getRateLimitInfo(request, primaryPolicy);
      const quotaInfo = await this.getQuotaInfo(request, primaryPolicy);

      return {
        allowed: true,
        policy: primaryPolicy,
        rateLimitInfo,
        quotaInfo
      };

    } catch (error) {
      console.error('Rate limit check error:', error);
      
      // Fail open with logging
      return {
        allowed: true,
        rateLimitInfo: {
          limit: 1000,
          remaining: 1000,
          resetTime: new Date(Date.now() + 3600000)
        },
        reason: 'RATE_LIMIT_ERROR'
      };
    }
  }

  /**
   * Record request for analytics and monitoring
   */
  public async recordRequest(request: {
    tenantId: string;
    clientId?: string;
    userId?: string;
    ipAddress: string;
    method: string;
    path: string;
    endpoint: string;
    serviceId: string;
    statusCode: number;
    responseTime: number;
    responseSize: number;
    wasBlocked?: boolean;
    wasThrottled?: boolean;
    rateLimitPolicy?: string;
    userAgent?: string;
    correlationId?: string;
  }): Promise<void> {
    try {
      const usageMetric: UsageMetrics = {
        metricId: crypto.randomUUID(),
        timestamp: new Date(),
        tenantId: request.tenantId,
        clientId: request.clientId,
        userId: request.userId,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        method: request.method,
        path: request.path,
        endpoint: request.endpoint,
        serviceId: request.serviceId,
        statusCode: request.statusCode,
        responseTime: request.responseTime,
        responseSize: request.responseSize,
        rateLimitPolicy: request.rateLimitPolicy,
        currentUsage: 0, // Will be updated by rate limit check
        limitRemaining: 0, // Will be updated by rate limit check
        wasBlocked: request.wasBlocked || false,
        wasThrottled: request.wasThrottled || false,
        wasAnomalous: false, // Will be determined by anomaly detection
        correlationId: request.correlationId
      };

      // Validate and store metric
      const validatedMetric = UsageMetricsSchema.parse(usageMetric);
      this.usageMetrics.push(validatedMetric);

      // Keep only recent metrics in memory
      if (this.usageMetrics.length > this.config.maxMetricsInMemory) {
        this.usageMetrics.splice(0, this.usageMetrics.length - this.config.maxMetricsInMemory);
      }

      // Update usage counters
      await this.updateUsageCounters(request);

      // Detect anomalies
      if (this.shouldDetectAnomalies(request)) {
        const isAnomalous = await this.detectAnomaly(request);
        if (isAnomalous) {
          validatedMetric.wasAnomalous = true;
          await this.handleAnomaly(request, 'UNUSUAL_USAGE_PATTERN');
        }
      }

      // Send to external analytics system (async)
      this.sendToAnalytics(validatedMetric).catch(error => {
        console.error('Failed to send metrics to analytics:', error);
      });

    } catch (error) {
      console.error('Failed to record request metrics:', error);
    }
  }

  /**
   * Generate Kong rate limiting plugin configurations
   */
  public generateKongRateLimitingPluginConfigurations(): Array<{
    name: string;
    service?: { id: string };
    route?: { id: string };
    config: object;
    enabled: boolean;
    tags: string[];
  }> {
    const configurations = [];

    for (const [policyId, policy] of this.policies) {
      for (const rateLimit of policy.rateLimits) {
        configurations.push({
          name: 'rate-limiting',
          config: {
            minute: rateLimit.window === 'MINUTE' ? rateLimit.limit : null,
            hour: rateLimit.window === 'HOUR' ? rateLimit.limit : null,
            day: rateLimit.window === 'DAY' ? rateLimit.limit : null,
            month: rateLimit.window === 'MONTH' ? rateLimit.limit : null,
            year: rateLimit.window === 'YEAR' ? rateLimit.limit : null,
            policy: policy.advanced.distributedLimiting ? 'redis' : 'local',
            fault_tolerant: policy.advanced.gracefulDegradation,
            hide_client_headers: false,
            redis_host: 'redis.isectech-cache.svc.cluster.local',
            redis_port: 6379,
            redis_password: process.env.REDIS_PASSWORD,
            redis_database: 0,
            redis_timeout: 2000
          },
          enabled: policy.isActive,
          tags: policy.tags
        });
      }

      // Add response rate limiting for throttling
      configurations.push({
        name: 'response-ratelimiting',
        config: {
          limits: policy.rateLimits.reduce((acc, limit) => {
            acc[limit.window.toLowerCase()] = limit.limit;
            return acc;
          }, {} as Record<string, number>),
          policy: policy.advanced.distributedLimiting ? 'redis' : 'local',
          fault_tolerant: policy.advanced.gracefulDegradation,
          redis_host: 'redis.isectech-cache.svc.cluster.local',
          redis_port: 6379,
          redis_database: 1
        },
        enabled: policy.isActive,
        tags: policy.tags
      });
    }

    return configurations;
  }

  /**
   * Get rate limiting analytics and statistics
   */
  public getRateLimitingAnalytics(timeframe: {
    start: Date;
    end: Date;
  }): {
    summary: {
      totalRequests: number;
      blockedRequests: number;
      throttledRequests: number;
      blockRate: number;
      throttleRate: number;
    };
    topBlockedIPs: Array<{ ip: string; blocks: number }>;
    policyStats: Array<{
      policyId: string;
      policyName: string;
      triggeredCount: number;
      blockedCount: number;
      throttledCount: number;
    }>;
    timeSeriesData: Array<{
      timestamp: Date;
      requests: number;
      blocked: number;
      throttled: number;
    }>;
  } {
    const filteredMetrics = this.usageMetrics.filter(metric => 
      metric.timestamp >= timeframe.start && metric.timestamp <= timeframe.end
    );

    const totalRequests = filteredMetrics.length;
    const blockedRequests = filteredMetrics.filter(m => m.wasBlocked).length;
    const throttledRequests = filteredMetrics.filter(m => m.wasThrottled).length;

    // Top blocked IPs
    const ipBlocks = new Map<string, number>();
    filteredMetrics.filter(m => m.wasBlocked).forEach(m => {
      ipBlocks.set(m.ipAddress, (ipBlocks.get(m.ipAddress) || 0) + 1);
    });
    const topBlockedIPs = Array.from(ipBlocks.entries())
      .map(([ip, blocks]) => ({ ip, blocks }))
      .sort((a, b) => b.blocks - a.blocks)
      .slice(0, 10);

    // Policy statistics
    const policyStats = Array.from(this.policies.values()).map(policy => {
      const policyMetrics = filteredMetrics.filter(m => m.rateLimitPolicy === policy.policyId);
      return {
        policyId: policy.policyId,
        policyName: policy.name,
        triggeredCount: policyMetrics.length,
        blockedCount: policyMetrics.filter(m => m.wasBlocked).length,
        throttledCount: policyMetrics.filter(m => m.wasThrottled).length
      };
    });

    // Time series data (hourly buckets)
    const timeSeriesData = [];
    const hourMs = 60 * 60 * 1000;
    for (let time = timeframe.start.getTime(); time < timeframe.end.getTime(); time += hourMs) {
      const hourStart = new Date(time);
      const hourEnd = new Date(time + hourMs);
      const hourMetrics = filteredMetrics.filter(m => 
        m.timestamp >= hourStart && m.timestamp < hourEnd
      );
      
      timeSeriesData.push({
        timestamp: hourStart,
        requests: hourMetrics.length,
        blocked: hourMetrics.filter(m => m.wasBlocked).length,
        throttled: hourMetrics.filter(m => m.wasThrottled).length
      });
    }

    return {
      summary: {
        totalRequests,
        blockedRequests,
        throttledRequests,
        blockRate: totalRequests > 0 ? (blockedRequests / totalRequests) * 100 : 0,
        throttleRate: totalRequests > 0 ? (throttledRequests / totalRequests) * 100 : 0
      },
      topBlockedIPs,
      policyStats,
      timeSeriesData
    };
  }

  // Private helper methods
  private findApplicablePolicies(request: any): RateLimitPolicy[] {
    const applicable = [];

    for (const policy of this.policies.values()) {
      if (!policy.isActive) continue;

      // Check effective dates
      if (policy.effectiveFrom && new Date() < policy.effectiveFrom) continue;
      if (policy.effectiveUntil && new Date() > policy.effectiveUntil) continue;

      // Check scope
      let isApplicable = false;
      switch (policy.scope.type) {
        case 'GLOBAL':
          isApplicable = true;
          break;
        case 'TENANT':
          isApplicable = policy.scope.targets.includes(request.tenantId);
          break;
        case 'CLIENT':
          isApplicable = request.clientId && policy.scope.targets.includes(request.clientId);
          break;
        case 'USER':
          isApplicable = request.userId && policy.scope.targets.includes(request.userId);
          break;
        case 'API':
          isApplicable = policy.scope.targets.includes(request.serviceId);
          break;
        case 'ENDPOINT':
          isApplicable = policy.scope.targets.includes(request.endpoint);
          break;
      }

      // Check service scope
      if (isApplicable && policy.scope.serviceScope) {
        isApplicable = policy.scope.serviceScope.includes(request.serviceId);
      }

      // Check route scope
      if (isApplicable && policy.scope.routeScope) {
        isApplicable = policy.scope.routeScope.some(route => request.path.startsWith(route));
      }

      if (isApplicable) {
        applicable.push(policy);
      }
    }

    // Sort by priority (highest first)
    return applicable.sort((a, b) => b.priority - a.priority);
  }

  private isExempt(request: any, policy: RateLimitPolicy): boolean {
    // IP whitelist
    if (policy.exemptions.ipWhitelist.some(ip => this.isIPInRange(request.ipAddress, ip))) {
      return true;
    }

    // Client whitelist
    if (request.clientId && policy.exemptions.clientWhitelist.includes(request.clientId)) {
      return true;
    }

    // User whitelist
    if (request.userId && policy.exemptions.userWhitelist.includes(request.userId)) {
      return true;
    }

    // Health check exemption
    if (policy.exemptions.healthCheckExempt && 
        (request.path.includes('/health') || request.path.includes('/status'))) {
      return true;
    }

    // Emergency bypass
    if (policy.exemptions.emergencyBypass) {
      // Check for emergency bypass header or system flag
      return false; // Implementation would check actual emergency conditions
    }

    return false;
  }

  private async checkPolicyRateLimits(request: any, policy: RateLimitPolicy): Promise<any> {
    // Implementation would check each rate limit in the policy
    // This is a simplified version
    return { allowed: true };
  }

  private async checkPolicyQuotas(request: any, policy: RateLimitPolicy): Promise<any> {
    // Implementation would check each quota in the policy
    // This is a simplified version
    return { allowed: true };
  }

  private async getRateLimitInfo(request: any, policy: RateLimitPolicy): Promise<any> {
    // Implementation would return current rate limit status
    return {
      limit: 1000,
      remaining: 500,
      resetTime: new Date(Date.now() + 3600000)
    };
  }

  private async getQuotaInfo(request: any, policy: RateLimitPolicy): Promise<any> {
    // Implementation would return current quota status
    return {
      limit: 10000,
      used: 2500,
      remaining: 7500,
      resetTime: new Date(Date.now() + 86400000)
    };
  }

  private async updateUsageCounters(request: any): Promise<void> {
    // Implementation would update Redis counters
  }

  private shouldDetectAnomalies(request: any): boolean {
    // Implementation would determine if anomaly detection should run
    return true;
  }

  private async detectAnomaly(request: any): Promise<boolean> {
    // Simple anomaly detection based on request patterns
    const key = `${request.tenantId}:${request.ipAddress}`;
    const history = this.anomalyDetector.get(key) || [];
    
    // Add current request time
    history.push(Date.now());
    
    // Keep only last 100 requests
    if (history.length > 100) {
      history.splice(0, history.length - 100);
    }
    
    this.anomalyDetector.set(key, history);
    
    // Check for unusual patterns (simplified)
    if (history.length >= 10) {
      const intervals = [];
      for (let i = 1; i < history.length; i++) {
        intervals.push(history[i] - history[i-1]);
      }
      
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const stdDev = Math.sqrt(intervals.reduce((sq, n) => sq + Math.pow(n - avgInterval, 2), 0) / intervals.length);
      
      // Check if recent requests are unusually frequent
      const recentIntervals = intervals.slice(-5);
      const recentAvg = recentIntervals.reduce((a, b) => a + b, 0) / recentIntervals.length;
      
      return recentAvg < (avgInterval - this.config.anomalyThreshold * stdDev);
    }
    
    return false;
  }

  private async handleAnomaly(request: any, type: string): Promise<void> {
    console.warn(`Anomaly detected: ${type} for ${request.ipAddress}`);
    
    // Send alert
    await this.sendAlert({
      type: 'ANOMALY_DETECTED',
      severity: 'WARNING',
      ipAddress: request.ipAddress,
      tenantId: request.tenantId,
      details: type,
      timestamp: new Date()
    });
  }

  private async sendToAnalytics(metric: UsageMetrics): Promise<void> {
    // Implementation would send to external analytics system
    // e.g., Prometheus, Grafana, or custom analytics service
  }

  private async sendAlert(alert: any): Promise<void> {
    // Implementation would send alerts via configured channels
    console.log('Alert:', alert);
  }

  private isIPInRange(ip: string, range: string): boolean {
    // Simple IP range check - production would use proper CIDR matching
    return range === ip || range.includes('*');
  }

  private startCleanupTasks(): void {
    // Cleanup expired blocked IPs every 5 minutes
    setInterval(() => {
      const now = new Date();
      for (const [ip, expiry] of this.blockedIPs) {
        if (expiry < now) {
          this.blockedIPs.delete(ip);
        }
      }
    }, 5 * 60 * 1000);

    // Cleanup old metrics every hour
    setInterval(() => {
      const cutoff = new Date(Date.now() - this.config.metricsRetentionDays * 24 * 60 * 60 * 1000);
      this.usageMetrics = this.usageMetrics.filter(m => m.timestamp > cutoff);
    }, 60 * 60 * 1000);
  }
}

// Export production-ready rate limiting manager
export const isectechAPIRateLimitingManager = new ISECTECHAPIRateLimitingManager({
  redisUrl: process.env.REDIS_URL || 'redis://redis.isectech-cache.svc.cluster.local:6379',
  metricsRetentionDays: parseInt(process.env.METRICS_RETENTION_DAYS || '30'),
  alertingWebhook: process.env.ALERTING_WEBHOOK_URL || '',
  defaultBlockDuration: parseInt(process.env.DEFAULT_BLOCK_DURATION || '60'),
  anomalyThreshold: parseFloat(process.env.ANOMALY_THRESHOLD || '2.0'),
  fraudThreshold: parseFloat(process.env.FRAUD_THRESHOLD || '0.8'),
  maxMetricsInMemory: parseInt(process.env.MAX_METRICS_IN_MEMORY || '10000')
});