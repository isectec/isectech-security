/**
 * Business Rules Configuration
 * Centralized configuration for all custom business rule validators
 * 
 * Task: 83.5 - Configuration management for business rule validators
 */

export interface BusinessRuleConfig {
  transactionLimits: {
    enabled: boolean;
    tiers: Record<string, {
      dailyLimit: number;
      hourlyLimit: number;
      transactionValueLimit: number;
      aggregateMonthlyLimit: number;
      requiresApprovalThreshold?: number;
    }>;
    cacheSettings: {
      usageTrackingTtl: number; // seconds
      approvalCacheTtl: number; // seconds
    };
  };

  timeBasedAccess: {
    enabled: boolean;
    rules: Array<{
      endpoint: string;
      method: string;
      allowedDays: number[]; // 0-6 (Sunday-Saturday)
      allowedHours: { start: number; end: number };
      timezone: string;
      emergencyOverride: boolean;
      blackoutPeriods?: Array<{
        start: string; // ISO datetime
        end: string; // ISO datetime
        reason: string;
      }>;
    }>;
    emergencyOverrideRoles: string[];
  };

  resourceConsistency: {
    enabled: boolean;
    resources: Record<string, {
      requiredFields: string[];
      immutableFields?: string[];
      dependentResources: Array<{
        resourceType: string;
        relationshipType: 'parent' | 'child' | 'reference';
        validationQuery: string;
        errorMessage?: string;
      }>;
      customValidators?: string[]; // Reference to custom validation functions
    }>;
  };

  workflowStates: {
    enabled: boolean;
    workflows: Record<string, {
      states: Record<string, {
        allowedTransitions: string[];
        requiredFields: Record<string, any>;
        preConditions: Array<{
          condition: string;
          errorMessage: string;
          queryTemplate?: string;
        }>;
        postConditions: Array<{
          condition: string;
          errorMessage: string;
          queryTemplate?: string;
        }>;
        notifications?: Array<{
          event: string;
          recipients: string[];
          template: string;
        }>;
      }>;
    }>;
  };

  tenantDataIsolation: {
    enabled: boolean;
    strictMode: boolean;
    rules: Record<string, {
      isolationLevel: 'strict' | 'cross_tenant_allowed' | 'global';
      tenantFieldName: string;
      allowedCrossTenantRoles?: string[];
      auditRequired: boolean;
      exemptMethods?: string[]; // Methods that bypass isolation
    }>;
    auditSettings: {
      logAllAccess: boolean;
      logCrossTenantOnly: boolean;
      retentionDays: number;
    };
  };

  performance: {
    maxValidationTimeMs: number;
    enableCaching: boolean;
    cacheSettings: {
      defaultTtl: number;
      maxCacheSize: number;
      enableDistributedCache: boolean;
    };
    enableMetrics: boolean;
    alertThresholds: {
      validationTimeMs: number;
      violationRatePerHour: number;
      systemErrorRate: number;
    };
  };

  compliance: {
    enabled: boolean;
    frameworks: string[]; // e.g., ['SOC2', 'GDPR', 'HIPAA']
    dataClassification: {
      enabled: boolean;
      levels: string[]; // e.g., ['public', 'internal', 'confidential', 'restricted']
      defaultLevel: string;
    };
    retentionPolicies: Array<{
      dataType: string;
      retentionDays: number;
      autoDelete: boolean;
    }>;
  };

  security: {
    sensitiveEndpoints: string[];
    rateLimitingIntegration: {
      enabled: boolean;
      penaltyMultiplier: number; // Apply extra rate limiting for violations
    };
    threatDetection: {
      enabled: boolean;
      suspiciousPatterns: Array<{
        pattern: string;
        severity: 'low' | 'medium' | 'high' | 'critical';
        action: 'log' | 'warn' | 'block' | 'escalate';
      }>;
    };
  };

  notifications: {
    enabled: boolean;
    channels: Array<{
      type: 'email' | 'slack' | 'webhook' | 'sms';
      config: Record<string, any>;
      severityThreshold: 'low' | 'medium' | 'high' | 'critical';
    }>;
    templates: Record<string, {
      subject: string;
      body: string;
      variables: string[];
    }>;
  };
}

// Default configuration
export const defaultBusinessRuleConfig: BusinessRuleConfig = {
  transactionLimits: {
    enabled: true,
    tiers: {
      basic: {
        dailyLimit: 100,
        hourlyLimit: 20,
        transactionValueLimit: 1000,
        aggregateMonthlyLimit: 25000
      },
      premium: {
        dailyLimit: 500,
        hourlyLimit: 100,
        transactionValueLimit: 10000,
        aggregateMonthlyLimit: 250000,
        requiresApprovalThreshold: 5000
      },
      enterprise: {
        dailyLimit: 2000,
        hourlyLimit: 500,
        transactionValueLimit: 100000,
        aggregateMonthlyLimit: 2500000,
        requiresApprovalThreshold: 25000
      }
    },
    cacheSettings: {
      usageTrackingTtl: 3600, // 1 hour
      approvalCacheTtl: 1800 // 30 minutes
    }
  },

  timeBasedAccess: {
    enabled: true,
    rules: [
      {
        endpoint: '/api/v1/financial/transactions',
        method: 'POST',
        allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
        allowedHours: { start: 9, end: 17 }, // 9 AM - 5 PM
        timezone: 'America/New_York',
        emergencyOverride: true
      },
      {
        endpoint: '/api/v1/admin/system/maintenance',
        method: 'POST',
        allowedDays: [0, 6], // Weekend only
        allowedHours: { start: 22, end: 6 }, // 10 PM - 6 AM
        timezone: 'UTC',
        emergencyOverride: false
      },
      {
        endpoint: '/api/v1/security/audit/export',
        method: 'GET',
        allowedDays: [1, 2, 3, 4, 5], // Monday-Friday
        allowedHours: { start: 8, end: 18 }, // 8 AM - 6 PM
        timezone: 'America/New_York',
        emergencyOverride: true
      }
    ],
    emergencyOverrideRoles: ['admin', 'security_officer', 'system_admin']
  },

  resourceConsistency: {
    enabled: true,
    resources: {
      users: {
        requiredFields: ['email', 'tenant_id', 'role'],
        immutableFields: ['id', 'created_at', 'tenant_id'],
        dependentResources: [{
          resourceType: 'tenants',
          relationshipType: 'reference',
          validationQuery: 'SELECT 1 FROM tenants WHERE id = $1 AND status = \'active\'',
          errorMessage: 'Referenced tenant must exist and be active'
        }]
      },
      assets: {
        requiredFields: ['name', 'type', 'tenant_id', 'owner_id'],
        immutableFields: ['id', 'tenant_id', 'created_at'],
        dependentResources: [{
          resourceType: 'users',
          relationshipType: 'reference',
          validationQuery: 'SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2 AND status = \'active\'',
          errorMessage: 'Asset owner must be an active user in the same tenant'
        }]
      },
      incidents: {
        requiredFields: ['title', 'severity', 'status', 'assigned_to'],
        immutableFields: ['id', 'created_at'],
        dependentResources: [{
          resourceType: 'users',
          relationshipType: 'reference',
          validationQuery: 'SELECT 1 FROM users WHERE id = $1 AND status = \'active\'',
          errorMessage: 'Incident must be assigned to an active user'
        }]
      }
    }
  },

  workflowStates: {
    enabled: true,
    workflows: {
      incidents: {
        states: {
          new: {
            allowedTransitions: ['assigned', 'closed'],
            requiredFields: { status: 'new' },
            preConditions: [],
            postConditions: [],
            notifications: [{
              event: 'incident_created',
              recipients: ['security_team'],
              template: 'incident_created_notification'
            }]
          },
          assigned: {
            allowedTransitions: ['in_progress', 'escalated', 'closed'],
            requiredFields: { assigned_to: 'required' },
            preConditions: [{
              condition: 'assigned_user_active',
              errorMessage: 'Assigned user must be active',
              queryTemplate: 'SELECT 1 FROM users WHERE id = $1 AND status = \'active\''
            }],
            postConditions: [],
            notifications: [{
              event: 'incident_assigned',
              recipients: ['assigned_user'],
              template: 'incident_assigned_notification'
            }]
          },
          in_progress: {
            allowedTransitions: ['resolved', 'escalated'],
            requiredFields: {},
            preConditions: [],
            postConditions: []
          },
          resolved: {
            allowedTransitions: ['closed', 'reopened'],
            requiredFields: { resolution_notes: 'required' },
            preConditions: [],
            postConditions: [],
            notifications: [{
              event: 'incident_resolved',
              recipients: ['reporter', 'assigned_user'],
              template: 'incident_resolved_notification'
            }]
          },
          closed: {
            allowedTransitions: ['reopened'],
            requiredFields: {},
            preConditions: [],
            postConditions: []
          }
        }
      },
      assets: {
        states: {
          pending: {
            allowedTransitions: ['active', 'rejected'],
            requiredFields: {},
            preConditions: [],
            postConditions: []
          },
          active: {
            allowedTransitions: ['maintenance', 'decommissioned'],
            requiredFields: {},
            preConditions: [{
              condition: 'asset_validated',
              errorMessage: 'Asset must be validated before activation',
              queryTemplate: 'SELECT 1 FROM asset_validations WHERE asset_id = $1 AND status = \'passed\''
            }],
            postConditions: []
          },
          maintenance: {
            allowedTransitions: ['active', 'decommissioned'],
            requiredFields: { maintenance_reason: 'required' },
            preConditions: [],
            postConditions: []
          },
          decommissioned: {
            allowedTransitions: [],
            requiredFields: { decommission_reason: 'required' },
            preConditions: [],
            postConditions: []
          }
        }
      }
    }
  },

  tenantDataIsolation: {
    enabled: true,
    strictMode: true,
    rules: {
      '/api/v1/users': {
        isolationLevel: 'strict',
        tenantFieldName: 'tenant_id',
        auditRequired: true
      },
      '/api/v1/assets': {
        isolationLevel: 'strict',
        tenantFieldName: 'tenant_id',
        auditRequired: true
      },
      '/api/v1/admin/users': {
        isolationLevel: 'cross_tenant_allowed',
        tenantFieldName: 'tenant_id',
        allowedCrossTenantRoles: ['admin', 'system_admin'],
        auditRequired: true
      },
      '/api/v1/system/health': {
        isolationLevel: 'global',
        tenantFieldName: '',
        auditRequired: false,
        exemptMethods: ['GET', 'OPTIONS']
      }
    },
    auditSettings: {
      logAllAccess: false,
      logCrossTenantOnly: true,
      retentionDays: 90
    }
  },

  performance: {
    maxValidationTimeMs: 10000,
    enableCaching: true,
    cacheSettings: {
      defaultTtl: 300, // 5 minutes
      maxCacheSize: 10000,
      enableDistributedCache: true
    },
    enableMetrics: true,
    alertThresholds: {
      validationTimeMs: 5000,
      violationRatePerHour: 100,
      systemErrorRate: 0.1 // 10%
    }
  },

  compliance: {
    enabled: true,
    frameworks: ['SOC2', 'GDPR', 'ISO27001'],
    dataClassification: {
      enabled: true,
      levels: ['public', 'internal', 'confidential', 'restricted'],
      defaultLevel: 'internal'
    },
    retentionPolicies: [
      {
        dataType: 'audit_logs',
        retentionDays: 2555, // 7 years
        autoDelete: false
      },
      {
        dataType: 'validation_logs',
        retentionDays: 90,
        autoDelete: true
      },
      {
        dataType: 'user_sessions',
        retentionDays: 30,
        autoDelete: true
      }
    ]
  },

  security: {
    sensitiveEndpoints: [
      '/api/v1/admin/',
      '/api/v1/security/',
      '/api/v1/financial/',
      '/api/v1/auth/admin'
    ],
    rateLimitingIntegration: {
      enabled: true,
      penaltyMultiplier: 2.0
    },
    threatDetection: {
      enabled: true,
      suspiciousPatterns: [
        {
          pattern: 'rapid_failed_validations',
          severity: 'high',
          action: 'block'
        },
        {
          pattern: 'cross_tenant_access_attempt',
          severity: 'medium',
          action: 'warn'
        },
        {
          pattern: 'off_hours_sensitive_access',
          severity: 'medium',
          action: 'escalate'
        }
      ]
    }
  },

  notifications: {
    enabled: true,
    channels: [
      {
        type: 'email',
        config: {
          smtp_host: process.env.SMTP_HOST,
          smtp_port: 587,
          from_address: 'security@isectech.com'
        },
        severityThreshold: 'high'
      },
      {
        type: 'slack',
        config: {
          webhook_url: process.env.SLACK_WEBHOOK_URL,
          channel: '#security-alerts'
        },
        severityThreshold: 'critical'
      },
      {
        type: 'webhook',
        config: {
          url: process.env.SECURITY_WEBHOOK_URL,
          headers: {
            'Authorization': 'Bearer ${WEBHOOK_TOKEN}',
            'Content-Type': 'application/json'
          }
        },
        severityThreshold: 'medium'
      }
    ],
    templates: {
      business_rule_violation: {
        subject: 'Business Rule Violation Alert - ${SEVERITY}',
        body: `
          A business rule violation has been detected:
          
          Rule ID: ${RULE_ID}
          Severity: ${SEVERITY}
          Message: ${MESSAGE}
          User: ${USER_ID}
          Tenant: ${TENANT_ID}
          Endpoint: ${ENDPOINT}
          Timestamp: ${TIMESTAMP}
          
          Remediation: ${REMEDIATION}
        `,
        variables: ['RULE_ID', 'SEVERITY', 'MESSAGE', 'USER_ID', 'TENANT_ID', 'ENDPOINT', 'TIMESTAMP', 'REMEDIATION']
      },
      transaction_limit_exceeded: {
        subject: 'Transaction Limit Exceeded - ${USER_ID}',
        body: `
          A user has exceeded their transaction limits:
          
          User: ${USER_ID}
          Tenant: ${TENANT_ID}
          Limit Type: ${LIMIT_TYPE}
          Current Value: ${CURRENT_VALUE}
          Limit: ${LIMIT_VALUE}
          Timestamp: ${TIMESTAMP}
        `,
        variables: ['USER_ID', 'TENANT_ID', 'LIMIT_TYPE', 'CURRENT_VALUE', 'LIMIT_VALUE', 'TIMESTAMP']
      }
    }
  }
};

// Configuration loader with environment-specific overrides
export class BusinessRuleConfigManager {
  private config: BusinessRuleConfig;

  constructor(baseConfig: BusinessRuleConfig = defaultBusinessRuleConfig) {
    this.config = this.loadConfiguration(baseConfig);
  }

  private loadConfiguration(baseConfig: BusinessRuleConfig): BusinessRuleConfig {
    // Load environment-specific overrides
    const envOverrides = this.loadEnvironmentOverrides();
    
    // Merge configurations
    return this.deepMerge(baseConfig, envOverrides);
  }

  private loadEnvironmentOverrides(): Partial<BusinessRuleConfig> {
    const overrides: Partial<BusinessRuleConfig> = {};

    // Load from environment variables
    if (process.env.BUSINESS_RULES_ENABLED === 'false') {
      overrides.transactionLimits = { ...defaultBusinessRuleConfig.transactionLimits, enabled: false };
      overrides.timeBasedAccess = { ...defaultBusinessRuleConfig.timeBasedAccess, enabled: false };
      overrides.resourceConsistency = { ...defaultBusinessRuleConfig.resourceConsistency, enabled: false };
      overrides.workflowStates = { ...defaultBusinessRuleConfig.workflowStates, enabled: false };
      overrides.tenantDataIsolation = { ...defaultBusinessRuleConfig.tenantDataIsolation, enabled: false };
    }

    if (process.env.BUSINESS_RULES_STRICT_MODE === 'false') {
      overrides.tenantDataIsolation = {
        ...defaultBusinessRuleConfig.tenantDataIsolation,
        strictMode: false
      };
    }

    if (process.env.BUSINESS_RULES_MAX_VALIDATION_TIME_MS) {
      overrides.performance = {
        ...defaultBusinessRuleConfig.performance,
        maxValidationTimeMs: parseInt(process.env.BUSINESS_RULES_MAX_VALIDATION_TIME_MS)
      };
    }

    return overrides;
  }

  private deepMerge(target: any, source: any): any {
    if (source === null || typeof source !== 'object') {
      return source;
    }

    if (Array.isArray(source)) {
      return source;
    }

    const result = { ...target };

    Object.keys(source).forEach(key => {
      if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        result[key] = this.deepMerge(target[key] || {}, source[key]);
      } else {
        result[key] = source[key];
      }
    });

    return result;
  }

  getConfig(): BusinessRuleConfig {
    return this.config;
  }

  getTransactionLimitsConfig() {
    return this.config.transactionLimits;
  }

  getTimeBasedAccessConfig() {
    return this.config.timeBasedAccess;
  }

  getResourceConsistencyConfig() {
    return this.config.resourceConsistency;
  }

  getWorkflowStatesConfig() {
    return this.config.workflowStates;
  }

  getTenantDataIsolationConfig() {
    return this.config.tenantDataIsolation;
  }

  getPerformanceConfig() {
    return this.config.performance;
  }

  getComplianceConfig() {
    return this.config.compliance;
  }

  getSecurityConfig() {
    return this.config.security;
  }

  getNotificationsConfig() {
    return this.config.notifications;
  }

  updateConfig(updates: Partial<BusinessRuleConfig>): void {
    this.config = this.deepMerge(this.config, updates);
  }

  validateConfig(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate transaction limits
    if (this.config.transactionLimits.enabled) {
      Object.entries(this.config.transactionLimits.tiers).forEach(([tier, limits]) => {
        if (limits.dailyLimit <= 0) {
          errors.push(`Invalid daily limit for tier ${tier}: must be greater than 0`);
        }
        if (limits.hourlyLimit <= 0) {
          errors.push(`Invalid hourly limit for tier ${tier}: must be greater than 0`);
        }
        if (limits.hourlyLimit > limits.dailyLimit) {
          errors.push(`Hourly limit cannot exceed daily limit for tier ${tier}`);
        }
      });
    }

    // Validate time-based access rules
    if (this.config.timeBasedAccess.enabled) {
      this.config.timeBasedAccess.rules.forEach((rule, index) => {
        if (rule.allowedHours.start >= rule.allowedHours.end && rule.allowedHours.end !== 0) {
          errors.push(`Invalid allowed hours for rule ${index}: start time must be before end time`);
        }
        if (!rule.allowedDays.every(day => day >= 0 && day <= 6)) {
          errors.push(`Invalid allowed days for rule ${index}: days must be 0-6`);
        }
      });
    }

    // Validate performance settings
    if (this.config.performance.maxValidationTimeMs <= 0) {
      errors.push('Max validation time must be greater than 0');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

// Export singleton instance
export const businessRuleConfigManager = new BusinessRuleConfigManager();