/**
 * Traffic Management Configuration for iSECTECH
 * 
 * Production-ready configuration examples for intelligent traffic management
 * including traffic segmentation, routing rules, A/B testing, and canary deployments.
 */

import { 
  TrafficManagerConfig, 
  TrafficSegment, 
  RoutingRule, 
  ABTestConfig, 
  CanaryDeployment,
  TrafficMirrorConfig 
} from './intelligent-traffic-manager';
import { KongTrafficPluginConfig } from './kong-traffic-management-plugin';

// Production configuration
export const productionTrafficConfig: TrafficManagerConfig = {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0'),
    keyPrefix: 'isectech:traffic:',
  },
  routing: {
    enabled: true,
    defaultUpstream: 'isectech-api-v1',
    healthCheckInterval: 30000, // 30 seconds
    cacheEnabled: true,
    cacheTtl: 60, // 1 minute
  },
  abTesting: {
    enabled: true,
    maxConcurrentTests: 5, // Conservative for production
    statisticalEngine: 'FREQUENTIST',
  },
  canary: {
    enabled: true,
    maxConcurrentDeployments: 2, // Limited for stability
    defaultStages: [5, 15, 30, 50, 100], // Gradual rollout
  },
  mirroring: {
    enabled: true,
    maxMirrorTargets: 2,
    bufferSize: 5000,
  },
  monitoring: {
    metricsEnabled: true,
    detailedLogging: false, // Reduce log volume in production
    alerting: {
      enabled: true,
      thresholds: {
        errorRate: 2, // 2% max error rate
        responseTime: 500, // 500ms max response time
      },
    },
  },
};

// Development configuration
export const developmentTrafficConfig: TrafficManagerConfig = {
  ...productionTrafficConfig,
  redis: {
    ...productionTrafficConfig.redis,
    keyPrefix: 'dev:traffic:',
    db: 1, // Different DB for development
  },
  routing: {
    ...productionTrafficConfig.routing,
    cacheTtl: 10, // Shorter cache for faster testing
  },
  abTesting: {
    enabled: true,
    maxConcurrentTests: 10, // More flexibility in development
    statisticalEngine: 'FREQUENTIST',
  },
  canary: {
    enabled: true,
    maxConcurrentDeployments: 5,
    defaultStages: [25, 50, 100], // Faster rollout for testing
  },
  monitoring: {
    metricsEnabled: true,
    detailedLogging: true, // Detailed logging for debugging
    alerting: {
      enabled: false, // No alerts in development
      thresholds: {
        errorRate: 10,
        responseTime: 2000,
      },
    },
  },
};

// Kong plugin configuration
export const kongTrafficPluginConfig: KongTrafficPluginConfig = {
  enabled: true,
  trafficManager: {
    timeout: 100, // 100ms timeout
    cacheEnabled: true,
    cacheTtl: 60,
  },
  routing: {
    headerPassthrough: true,
    upstreamHeaders: {
      segment: 'X-iSECTECH-Segment',
      abTest: 'X-iSECTECH-AB-Test',
      canary: 'X-iSECTECH-Canary',
      mirror: 'X-iSECTECH-Mirror',
    },
  },
  monitoring: {
    metricsEnabled: true,
    responseHeaders: true,
    detailedLogging: false,
  },
  fallback: {
    behavior: 'DEFAULT_UPSTREAM',
    defaultUpstream: 'isectech-api-v1',
  },
};

// Example traffic segments
export const defaultTrafficSegments: Omit<TrafficSegment, 'id' | 'createdAt' | 'updatedAt'>[] = [
  {
    name: 'enterprise_customers',
    description: 'Enterprise customers with premium SLA',
    criteria: {
      headers: {
        'x-customer-tier': 'enterprise',
      },
      userAgent: ['iSECTECH-Enterprise.*'],
    },
    priority: 900,
    isActive: true,
  },
  {
    name: 'mobile_users',
    description: 'Mobile application users',
    criteria: {
      userAgent: [
        'iSECTECH-Mobile.*',
        'Mozilla.*Mobile.*',
        'Mozilla.*Android.*',
        'Mozilla.*iPhone.*',
      ],
    },
    priority: 700,
    isActive: true,
  },
  {
    name: 'api_integrators',
    description: 'Third-party API integrators',
    criteria: {
      headers: {
        'user-agent': '.*API.*',
        'x-integration-type': 'api',
      },
    },
    priority: 800,
    isActive: true,
  },
  {
    name: 'beta_users',
    description: 'Users enrolled in beta program',
    criteria: {
      headers: {
        'x-beta-program': 'true',
      },
    },
    priority: 600,
    isActive: true,
  },
  {
    name: 'high_value_customers',
    description: 'High-value customers based on usage',
    criteria: {
      headers: {
        'x-customer-value': 'high',
      },
    },
    priority: 850,
    isActive: true,
  },
];

// Example routing rules
export const defaultRoutingRules: Omit<RoutingRule, 'id'>[] = [
  {
    name: 'enterprise_priority_routing',
    conditions: {
      segments: ['enterprise_customers'],
    },
    destinations: [
      {
        upstream: 'isectech-api-premium',
        weight: 100,
        priority: 1,
        healthCheck: true,
      },
    ],
    fallback: {
      upstream: 'isectech-api-v1',
      behavior: 'FAILOVER',
    },
    priority: 950,
    isActive: true,
  },
  {
    name: 'api_integrator_routing',
    conditions: {
      segments: ['api_integrators'],
      path: '/api/v[12]/.*',
    },
    destinations: [
      {
        upstream: 'isectech-api-v2',
        weight: 80,
        priority: 1,
        healthCheck: true,
      },
      {
        upstream: 'isectech-api-v1',
        weight: 20,
        priority: 2,
        healthCheck: true,
      },
    ],
    priority: 800,
    isActive: true,
  },
  {
    name: 'mobile_optimized_routing',
    conditions: {
      segments: ['mobile_users'],
    },
    destinations: [
      {
        upstream: 'isectech-mobile-api',
        weight: 100,
        priority: 1,
        healthCheck: true,
      },
    ],
    fallback: {
      upstream: 'isectech-api-v1',
      behavior: 'FAILOVER',
    },
    priority: 750,
    isActive: true,
  },
  {
    name: 'beta_features_routing',
    conditions: {
      segments: ['beta_users'],
      path: '/api/v2/beta/.*',
    },
    destinations: [
      {
        upstream: 'isectech-beta-api',
        weight: 100,
        priority: 1,
        healthCheck: true,
      },
    ],
    fallback: {
      upstream: 'isectech-api-v2',
      behavior: 'FAILOVER',
    },
    priority: 700,
    isActive: true,
  },
];

// Example A/B test configurations
export const exampleABTests: Omit<ABTestConfig, 'id' | 'status'>[] = [
  {
    name: 'new_dashboard_ui',
    description: 'Test new dashboard UI against current version',
    variants: [
      {
        id: 'control',
        name: 'Current Dashboard',
        upstream: 'isectech-dashboard-v1',
        allocation: 50,
      },
      {
        id: 'treatment',
        name: 'New Dashboard UI',
        upstream: 'isectech-dashboard-v2',
        allocation: 50,
      },
    ],
    targeting: {
      segments: ['enterprise_customers', 'high_value_customers'],
      percentage: 100,
    },
    metrics: {
      primaryMetric: 'conversion_rate',
      secondaryMetrics: ['session_duration', 'bounce_rate'],
      significanceLevel: 0.05,
      minSampleSize: 1000,
    },
    duration: {
      startDate: new Date('2025-08-07'),
      endDate: new Date('2025-09-07'),
      autoStop: true,
    },
  },
  {
    name: 'api_response_optimization',
    description: 'Test optimized API response format',
    variants: [
      {
        id: 'standard',
        name: 'Standard Response',
        upstream: 'isectech-api-v1',
        allocation: 30,
      },
      {
        id: 'optimized',
        name: 'Optimized Response',
        upstream: 'isectech-api-optimized',
        allocation: 70,
      },
    ],
    targeting: {
      segments: ['api_integrators'],
      percentage: 50, // Only 50% of API integrators
    },
    metrics: {
      primaryMetric: 'response_time',
      secondaryMetrics: ['error_rate', 'throughput'],
      significanceLevel: 0.01,
      minSampleSize: 5000,
    },
    duration: {
      startDate: new Date('2025-08-10'),
      endDate: new Date('2025-08-24'),
      autoStop: false,
    },
  },
];

// Example canary deployment configurations
export const exampleCanaryDeployments: Omit<CanaryDeployment, 'id' | 'status'>[] = [
  {
    name: 'api_v2_rollout',
    service: 'isectech-api',
    canaryUpstream: 'isectech-api-v2-canary',
    stableUpstream: 'isectech-api-v1',
    stages: [
      {
        stage: 1,
        trafficPercentage: 5,
        duration: 30, // 30 minutes
        successCriteria: {
          errorRate: 0.5, // Max 0.5% error rate
          responseTime: 300, // Max 300ms p99
          minRequests: 500,
        },
      },
      {
        stage: 2,
        trafficPercentage: 15,
        duration: 60, // 1 hour
        successCriteria: {
          errorRate: 1, // Max 1% error rate
          responseTime: 400, // Max 400ms p99
          minRequests: 1000,
        },
      },
      {
        stage: 3,
        trafficPercentage: 30,
        duration: 120, // 2 hours
        successCriteria: {
          errorRate: 1,
          responseTime: 400,
          minRequests: 2000,
        },
      },
      {
        stage: 4,
        trafficPercentage: 50,
        duration: 240, // 4 hours
        successCriteria: {
          errorRate: 1,
          responseTime: 500,
          minRequests: 5000,
        },
      },
      {
        stage: 5,
        trafficPercentage: 100,
        duration: 0, // Final stage
        successCriteria: {
          errorRate: 2,
          responseTime: 500,
          minRequests: 10000,
        },
      },
    ],
    rollbackTriggers: {
      errorRateThreshold: 3, // 3%
      responseTimeThreshold: 1000, // 1000ms
      manualRollback: true,
    },
  },
];

// Example traffic mirror configurations
export const exampleTrafficMirrors: Omit<TrafficMirrorConfig, 'id'>[] = [
  {
    name: 'api_testing_mirror',
    sourceUpstream: 'isectech-api-v1',
    mirrorUpstream: 'isectech-api-test',
    mirrorPercentage: 10, // Mirror 10% of traffic
    filters: {
      methods: ['GET', 'POST'],
      paths: ['/api/v1/.*'],
    },
    sampling: {
      enabled: true,
      rate: 0.1, // 10% sampling of the mirrored traffic
    },
    isActive: true,
  },
  {
    name: 'analytics_data_mirror',
    sourceUpstream: 'isectech-api-v1',
    mirrorUpstream: 'isectech-analytics-collector',
    mirrorPercentage: 100, // Mirror all analytics requests
    filters: {
      paths: ['/api/v1/analytics/.*', '/api/v1/events/.*'],
    },
    sampling: {
      enabled: false,
    },
    isActive: true,
  },
];

// Environment-specific configuration getter
export function getTrafficConfigForEnvironment(env: string = process.env.NODE_ENV || 'development'): TrafficManagerConfig {
  switch (env.toLowerCase()) {
    case 'production':
      return productionTrafficConfig;
    case 'staging':
      return {
        ...productionTrafficConfig,
        redis: {
          ...productionTrafficConfig.redis,
          keyPrefix: 'staging:traffic:',
        },
        monitoring: {
          ...productionTrafficConfig.monitoring,
          detailedLogging: true, // More logging in staging
        },
      };
    case 'development':
    default:
      return developmentTrafficConfig;
  }
}

// Utility functions for configuration management
export class TrafficConfigurationManager {
  /**
   * Validate traffic segment criteria
   */
  static validateSegmentCriteria(criteria: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!criteria || Object.keys(criteria).length === 0) {
      errors.push('Segment criteria cannot be empty');
    }

    if (criteria.userAgent) {
      for (const pattern of criteria.userAgent) {
        try {
          new RegExp(pattern);
        } catch {
          errors.push(`Invalid regex pattern in userAgent: ${pattern}`);
        }
      }
    }

    if (criteria.ipRanges) {
      for (const cidr of criteria.ipRanges) {
        if (!cidr.includes('/')) {
          errors.push(`Invalid CIDR format: ${cidr}`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate A/B test configuration
   */
  static validateABTestConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.variants || config.variants.length < 2) {
      errors.push('A/B test must have at least 2 variants');
    }

    if (config.variants) {
      const totalAllocation = config.variants.reduce((sum: number, v: any) => sum + v.allocation, 0);
      if (Math.abs(totalAllocation - 100) > 0.01) {
        errors.push('Variant allocations must sum to 100%');
      }

      const variantIds = new Set();
      for (const variant of config.variants) {
        if (variantIds.has(variant.id)) {
          errors.push(`Duplicate variant ID: ${variant.id}`);
        }
        variantIds.add(variant.id);
      }
    }

    if (config.duration) {
      const start = new Date(config.duration.startDate);
      const end = new Date(config.duration.endDate);
      if (start >= end) {
        errors.push('Start date must be before end date');
      }
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate canary deployment stages
   */
  static validateCanaryStages(stages: any[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!stages || stages.length === 0) {
      errors.push('Canary deployment must have at least one stage');
    }

    let lastPercentage = 0;
    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i];
      
      if (stage.trafficPercentage <= lastPercentage) {
        errors.push(`Stage ${i + 1} traffic percentage must be greater than previous stage`);
      }
      
      if (stage.trafficPercentage > 100) {
        errors.push(`Stage ${i + 1} traffic percentage cannot exceed 100%`);
      }
      
      lastPercentage = stage.trafficPercentage;
    }

    // Last stage should be 100%
    if (stages.length > 0 && stages[stages.length - 1].trafficPercentage !== 100) {
      errors.push('Final stage must have 100% traffic allocation');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Generate default upstream names based on service
   */
  static generateUpstreamNames(serviceName: string): {
    stable: string;
    canary: string;
    test: string;
    premium: string;
  } {
    return {
      stable: `${serviceName}-stable`,
      canary: `${serviceName}-canary`,
      test: `${serviceName}-test`,
      premium: `${serviceName}-premium`,
    };
  }
}

// Export all configurations and utilities
export {
  productionTrafficConfig,
  developmentTrafficConfig,
  kongTrafficPluginConfig,
  defaultTrafficSegments,
  defaultRoutingRules,
  exampleABTests,
  exampleCanaryDeployments,
  exampleTrafficMirrors,
};