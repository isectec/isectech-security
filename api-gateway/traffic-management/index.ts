/**
 * iSECTECH Traffic Management System - Main Export Module
 * 
 * Intelligent traffic management system providing:
 * - Dynamic traffic segmentation and routing
 * - A/B testing with statistical significance tracking
 * - Canary deployments with automated rollback
 * - Traffic mirroring for testing and analysis
 * - Kong Gateway integration
 * - Real-time analytics and monitoring
 */

// Core Traffic Management System
export {
  IntelligentTrafficManager,
  TrafficManagerConfigSchema,
  TrafficSegmentSchema,
  RoutingRuleSchema,
  ABTestConfigSchema,
  CanaryDeploymentSchema,
  TrafficMirrorConfigSchema,
} from './intelligent-traffic-manager';

export type {
  TrafficManagerConfig,
  TrafficSegment,
  RoutingRule,
  ABTestConfig,
  CanaryDeployment,
  TrafficMirrorConfig,
  RequestContext,
  RoutingDecision,
} from './intelligent-traffic-manager';

// Kong Plugin Integration
export {
  KongTrafficManagementPlugin,
  createKongTrafficManagementPlugin,
  KongTrafficPluginConfigSchema,
} from './kong-traffic-management-plugin';

export type {
  KongTrafficPluginConfig,
} from './kong-traffic-management-plugin';

// Configuration Management
export {
  productionTrafficConfig,
  developmentTrafficConfig,
  kongTrafficPluginConfig,
  defaultTrafficSegments,
  defaultRoutingRules,
  exampleABTests,
  exampleCanaryDeployments,
  exampleTrafficMirrors,
  getTrafficConfigForEnvironment,
  TrafficConfigurationManager,
} from './traffic-management-config';

/**
 * Quick Start Factory Function
 * 
 * Creates a fully configured traffic management system with sensible defaults
 */
import { Logger } from 'winston';
import { IntelligentTrafficManager } from './intelligent-traffic-manager';
import { getTrafficConfigForEnvironment } from './traffic-management-config';

export async function createTrafficManagementSystem(
  logger: Logger,
  environment?: string,
  configOverrides?: any
): Promise<IntelligentTrafficManager> {
  const baseConfig = getTrafficConfigForEnvironment(environment);
  const finalConfig = configOverrides 
    ? { ...baseConfig, ...configOverrides }
    : baseConfig;

  const trafficManager = new IntelligentTrafficManager(finalConfig, logger);
  
  logger.info('Traffic Management System created successfully', {
    component: 'TrafficManagementFactory',
    environment: environment || 'development',
    features: {
      routing: finalConfig.routing.enabled,
      abTesting: finalConfig.abTesting.enabled,
      canary: finalConfig.canary.enabled,
      mirroring: finalConfig.mirroring.enabled,
    },
  });

  return trafficManager;
}

/**
 * System Health Check Utility
 */
export async function performTrafficHealthCheck(manager: IntelligentTrafficManager): Promise<{
  healthy: boolean;
  details: any;
  recommendations: string[];
}> {
  try {
    const status = await manager.getSystemStatus();
    
    const recommendations = [];
    
    if (status.status !== 'healthy') {
      recommendations.push('Traffic management system is experiencing issues');
    }
    
    if (status.components.abTests > 10) {
      recommendations.push('High number of concurrent A/B tests may impact performance');
    }
    
    if (status.components.canaryDeployments > 5) {
      recommendations.push('Multiple canary deployments may increase complexity');
    }

    return {
      healthy: status.status === 'healthy',
      details: status,
      recommendations,
    };
  } catch (error) {
    return {
      healthy: false,
      details: { error: error.message },
      recommendations: ['Health check failed - system may be offline'],
    };
  }
}

/**
 * Traffic Analysis Utilities
 */
export const trafficUtils = {
  /**
   * Calculate statistical significance for A/B tests
   */
  calculateStatisticalSignificance: (
    controlConversions: number,
    controlSamples: number,
    treatmentConversions: number,
    treatmentSamples: number,
    significanceLevel: number = 0.05
  ): {
    significant: boolean;
    pValue: number;
    confidenceLevel: number;
    powerAnalysis: {
      effectSize: number;
      power: number;
    };
  } => {
    // Simplified statistical calculation
    // Real implementation would use proper statistical libraries
    
    const controlRate = controlConversions / controlSamples;
    const treatmentRate = treatmentConversions / treatmentSamples;
    const effectSize = Math.abs(treatmentRate - controlRate);
    
    // Mock p-value calculation
    const pValue = effectSize > 0.01 ? 0.03 : 0.8;
    const significant = pValue < significanceLevel;
    
    return {
      significant,
      pValue,
      confidenceLevel: (1 - significanceLevel) * 100,
      powerAnalysis: {
        effectSize,
        power: significant ? 0.8 : 0.3,
      },
    };
  },

  /**
   * Generate traffic segment recommendations based on patterns
   */
  generateSegmentRecommendations: (
    trafficData: Array<{ ip: string; userAgent: string; path: string; responseTime: number }>
  ): Array<{ name: string; criteria: any; reasoning: string }> => {
    const recommendations = [];
    
    // Analyze user agents
    const mobileAgents = trafficData.filter(t => 
      /mobile|android|iphone|ipad/i.test(t.userAgent)
    ).length;
    
    if (mobileAgents > trafficData.length * 0.3) {
      recommendations.push({
        name: 'mobile_users',
        criteria: {
          userAgent: ['.*[Mm]obile.*', '.*[Aa]ndroid.*', '.*iPhone.*', '.*iPad.*'],
        },
        reasoning: 'High mobile traffic detected (>30% of requests)',
      });
    }
    
    // Analyze API usage patterns
    const apiRequests = trafficData.filter(t => 
      t.path.startsWith('/api/')
    ).length;
    
    if (apiRequests > trafficData.length * 0.4) {
      recommendations.push({
        name: 'api_users',
        criteria: {
          headers: {
            'content-type': '.*application/json.*',
          },
          userAgent: ['.*API.*', '.*SDK.*', '.*Client.*'],
        },
        reasoning: 'High API usage detected (>40% of requests)',
      });
    }
    
    return recommendations;
  },

  /**
   * Calculate canary deployment risk score
   */
  calculateCanaryRisk: (
    deployment: any,
    metrics: { errorRate: number; responseTime: number; throughput: number }
  ): {
    riskScore: number; // 0-100
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    factors: Array<{ factor: string; impact: number; description: string }>;
  } => {
    const factors = [];
    let riskScore = 0;
    
    // Error rate risk
    if (metrics.errorRate > 5) {
      factors.push({
        factor: 'High Error Rate',
        impact: 30,
        description: `Error rate ${metrics.errorRate}% exceeds safe threshold`,
      });
      riskScore += 30;
    } else if (metrics.errorRate > 2) {
      factors.push({
        factor: 'Elevated Error Rate',
        impact: 15,
        description: `Error rate ${metrics.errorRate}% above normal baseline`,
      });
      riskScore += 15;
    }
    
    // Response time risk
    if (metrics.responseTime > 1000) {
      factors.push({
        factor: 'High Response Time',
        impact: 20,
        description: `Response time ${metrics.responseTime}ms exceeds threshold`,
      });
      riskScore += 20;
    }
    
    // Throughput risk
    if (metrics.throughput < 100) {
      factors.push({
        factor: 'Low Throughput',
        impact: 10,
        description: `Low request volume may affect statistical validity`,
      });
      riskScore += 10;
    }
    
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    if (riskScore >= 50) riskLevel = 'CRITICAL';
    else if (riskScore >= 30) riskLevel = 'HIGH';
    else if (riskScore >= 15) riskLevel = 'MEDIUM';
    else riskLevel = 'LOW';
    
    return { riskScore, riskLevel, factors };
  },
};

/**
 * Testing Utilities
 */
export const testingUtils = {
  /**
   * Create test traffic segments
   */
  createTestSegments: () => [
    {
      name: 'test_mobile',
      description: 'Test mobile traffic segment',
      criteria: {
        userAgent: ['TestMobileAgent.*'],
        headers: { 'x-test-segment': 'mobile' },
      },
      priority: 100,
      isActive: true,
    },
    {
      name: 'test_api',
      description: 'Test API traffic segment',
      criteria: {
        userAgent: ['TestAPIClient.*'],
        headers: { 'x-test-segment': 'api' },
      },
      priority: 200,
      isActive: true,
    },
  ],

  /**
   * Generate mock traffic data
   */
  generateMockTraffic: (count: number = 1000) => {
    const paths = ['/api/v1/users', '/api/v1/data', '/dashboard', '/login'];
    const userAgents = [
      'Mozilla/5.0 (Mobile; Android)',
      'iSECTECH-API-Client/1.0',
      'Mozilla/5.0 (Windows NT 10.0)',
      'iSECTECH-Mobile/2.1',
    ];
    const countries = ['US', 'GB', 'DE', 'CA', 'AU'];

    return Array.from({ length: count }, (_, i) => ({
      ip: `192.0.2.${(i % 254) + 1}`,
      method: Math.random() > 0.8 ? 'POST' : 'GET',
      path: paths[i % paths.length],
      headers: {
        'user-agent': userAgents[i % userAgents.length],
        'x-forwarded-for': `192.0.2.${(i % 254) + 1}`,
      },
      queryParams: {},
      userAgent: userAgents[i % userAgents.length],
      country: countries[i % countries.length],
      userId: `user_${i % 100}`,
      sessionId: `session_${i % 200}`,
    }));
  },

  /**
   * Mock A/B test scenarios
   */
  mockABTestScenarios: {
    // High-converting variant
    highConversion: {
      control: { conversions: 45, samples: 1000 },
      treatment: { conversions: 72, samples: 1000 },
    },
    // No significant difference
    noChange: {
      control: { conversions: 48, samples: 1000 },
      treatment: { conversions: 52, samples: 1000 },
    },
    // Negative impact
    negativeImpact: {
      control: { conversions: 60, samples: 1000 },
      treatment: { conversions: 35, samples: 1000 },
    },
  },
};

/**
 * Monitoring Integration Helper
 */
export function getTrafficPrometheusMetrics(status: any): string {
  const metrics = [
    `# HELP traffic_routing_decisions_total Total number of routing decisions`,
    `# TYPE traffic_routing_decisions_total counter`,
    `traffic_routing_decisions_total ${status.metrics.total_requests || 0}`,
    
    `# HELP traffic_ab_tests_active Number of active A/B tests`,
    `# TYPE traffic_ab_tests_active gauge`,
    `traffic_ab_tests_active ${status.components.abTests || 0}`,
    
    `# HELP traffic_canary_deployments_active Number of active canary deployments`,
    `# TYPE traffic_canary_deployments_active gauge`,
    `traffic_canary_deployments_active ${status.components.canaryDeployments || 0}`,
    
    `# HELP traffic_cache_hit_ratio Cache hit ratio for routing decisions`,
    `# TYPE traffic_cache_hit_ratio gauge`,
    `traffic_cache_hit_ratio ${calculateCacheHitRatio(status.metrics)}`,
    
    `# HELP traffic_system_health Traffic management system health (1=healthy, 0=unhealthy)`,
    `# TYPE traffic_system_health gauge`,
    `traffic_system_health ${status.status === 'healthy' ? 1 : 0}`,
  ];
  
  return metrics.join('\n') + '\n';
}

function calculateCacheHitRatio(metrics: any): number {
  const hits = parseInt(metrics.cache_hits || '0');
  const misses = parseInt(metrics.cache_misses || '0');
  const total = hits + misses;
  return total > 0 ? hits / total : 0;
}

// Version and compatibility information
export const VERSION = '1.0.0';
export const SUPPORTED_KONG_VERSIONS = ['2.8.x', '3.0.x', '3.1.x', '3.2.x'];
export const SUPPORTED_REDIS_VERSIONS = ['6.x', '7.x'];

// Component identifiers
export const COMPONENTS = {
  TRAFFIC_MANAGER: 'IntelligentTrafficManager',
  KONG_PLUGIN: 'KongTrafficManagementPlugin',
  CONFIG_MANAGER: 'TrafficConfigurationManager',
} as const;