/**
 * iSECTECH IP Protection System - Main Export Module
 * 
 * Comprehensive IP-based protection system for API gateways providing:
 * - Intelligent threat detection and blocking
 * - Geolocation-based filtering
 * - IP reputation scoring with threat intelligence
 * - Real-time analytics and forensic capabilities
 * - Kong Gateway integration
 * - Dynamic configuration management
 */

// Core IP Protection System
export {
  IntelligentIPProtectionSystem,
  IPProtectionConfigSchema,
  IPRuleSchema,
  GeolocationRuleSchema,
} from './intelligent-ip-protection-system';

export type {
  IPProtectionConfig,
  IPRule,
  GeolocationRule,
  ProtectionDecision,
  IPAnalytics,
} from './intelligent-ip-protection-system';

// Kong Plugin Integration
export {
  KongIPProtectionPlugin,
  createKongIPProtectionPlugin,
  KongIPProtectionConfigSchema,
} from './kong-ip-protection-plugin';

export type {
  KongIPProtectionConfig,
} from './kong-ip-protection-plugin';

// Analytics Dashboard
export {
  IPAnalyticsDashboard,
  DashboardConfigSchema,
} from './ip-analytics-dashboard';

export type {
  DashboardConfig,
  TrafficMetrics,
  ThreatIntelligence,
  IncidentDetails,
  GeolocationData,
} from './ip-analytics-dashboard';

// Protection Manager (Main Controller)
export {
  IPProtectionManager,
  IPProtectionManagerConfigSchema,
} from './ip-protection-manager';

export type {
  IPProtectionManagerConfig,
  SystemStatus,
  ConfigurationBackup,
} from './ip-protection-manager';

// Configuration Examples and Utilities
export {
  productionConfig,
  developmentConfig,
  stagingConfig,
  defaultIPRules,
  defaultGeolocationRules,
  getConfigForEnvironment,
} from './ip-protection-config.example';

/**
 * Quick Start Factory Function
 * 
 * Creates a fully configured IP Protection system with sensible defaults
 */
import { Logger } from 'winston';
import { IPProtectionManager } from './ip-protection-manager';
import { getConfigForEnvironment } from './ip-protection-config.example';

export async function createIPProtectionSystem(
  logger: Logger,
  environment?: string,
  configOverrides?: any
): Promise<IPProtectionManager> {
  const baseConfig = getConfigForEnvironment(environment);
  const finalConfig = configOverrides 
    ? { ...baseConfig, ...configOverrides }
    : baseConfig;

  const manager = new IPProtectionManager(finalConfig, logger);
  
  logger.info('IP Protection System created successfully', {
    component: 'IPProtectionFactory',
    environment: environment || 'development',
    mode: finalConfig.system.mode,
  });

  return manager;
}

/**
 * Health Check Utility
 * 
 * Performs comprehensive health check of the IP Protection system
 */
export async function performHealthCheck(manager: IPProtectionManager): Promise<{
  healthy: boolean;
  details: any;
  recommendations: string[];
}> {
  try {
    const status = await manager.getSystemStatus();
    const managerStatus = manager.getManagerStatus();
    
    const recommendations = [];
    
    if (status.overall === 'degraded') {
      recommendations.push('System is degraded - check component health');
    }
    
    if (status.overall === 'critical') {
      recommendations.push('System is critical - immediate attention required');
    }
    
    if (status.performance.errorRate > 5) {
      recommendations.push('High error rate detected - review logs and configurations');
    }
    
    if (status.performance.blockRate > 50) {
      recommendations.push('High block rate - verify rule effectiveness');
    }

    return {
      healthy: status.overall === 'healthy' && managerStatus.healthy,
      details: {
        system: status,
        manager: managerStatus,
      },
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
 * Migration Utility
 * 
 * Helps migrate from legacy IP protection systems
 */
export interface LegacyIPRule {
  ip?: string;
  cidr?: string;
  action: 'allow' | 'deny' | 'block';
  reason?: string;
  priority?: number;
}

export function migrateLegacyRules(legacyRules: LegacyIPRule[]) {
  return legacyRules.map((rule, index) => ({
    type: rule.action.toUpperCase() === 'ALLOW' ? 'ALLOW' as const : 'DENY' as const,
    cidr: rule.cidr || `${rule.ip}/32`,
    priority: rule.priority || (1000 - index), // Reverse order for priority
    description: rule.reason || 'Migrated from legacy system',
    createdBy: 'migration',
    tags: ['migrated'],
  }));
}

/**
 * Monitoring Integration Helper
 * 
 * Provides Prometheus-compatible metrics
 */
export function getPrometheusMetrics(status: any): string {
  const metrics = [
    `# HELP ip_protection_requests_total Total number of IP protection evaluations`,
    `# TYPE ip_protection_requests_total counter`,
    `ip_protection_requests_total{action="allow"} ${status.performance.requestsPerSecond * 60}`,
    
    `# HELP ip_protection_blocks_total Total number of blocked requests`,
    `# TYPE ip_protection_blocks_total counter`, 
    `ip_protection_blocks_total ${status.performance.blockRate * 60}`,
    
    `# HELP ip_protection_response_time_seconds Average response time`,
    `# TYPE ip_protection_response_time_seconds gauge`,
    `ip_protection_response_time_seconds ${status.performance.averageResponseTime / 1000}`,
    
    `# HELP ip_protection_system_health System health status (1=healthy, 0=degraded/critical)`,
    `# TYPE ip_protection_system_health gauge`,
    `ip_protection_system_health ${status.overall === 'healthy' ? 1 : 0}`,
  ];
  
  return metrics.join('\n') + '\n';
}

/**
 * Testing Utilities
 */
export const testUtils = {
  /**
   * Create test IP rules for development/testing
   */
  createTestRules: () => [
    {
      type: 'DENY' as const,
      cidr: '192.0.2.0/24', // RFC 5737 test network
      priority: 999,
      description: 'Test block rule',
      createdBy: 'test',
      tags: ['test'],
    },
    {
      type: 'ALLOW' as const, 
      cidr: '203.0.113.0/24', // RFC 5737 test network
      priority: 100,
      description: 'Test allow rule',
      createdBy: 'test',
      tags: ['test'],
    },
  ],

  /**
   * Generate test traffic data
   */
  generateTestTraffic: (count: number = 1000) => {
    const testIPs = [
      '192.0.2.1',  // Test block
      '203.0.113.1', // Test allow
      '8.8.8.8',     // Google DNS
      '1.1.1.1',     // Cloudflare DNS
    ];

    return Array.from({ length: count }, (_, i) => ({
      ip: testIPs[i % testIPs.length],
      timestamp: Date.now() - (Math.random() * 86400000), // Last 24 hours
      action: Math.random() > 0.1 ? 'ALLOW' : 'DENY',
      userAgent: `TestAgent/${Math.floor(Math.random() * 10)}`,
    }));
  },

  /**
   * Mock threat intelligence responses
   */
  mockThreatIntelligence: {
    benign: {
      score: 0,
      categories: [],
      confidence: 95,
      source: 'mock',
    },
    suspicious: {
      score: 65,
      categories: ['suspicious'],
      confidence: 80,
      source: 'mock',
    },
    malicious: {
      score: 95,
      categories: ['malware', 'botnet'],
      confidence: 90,
      source: 'mock',
    },
  },
};

// Version information
export const VERSION = '1.0.0';
export const SUPPORTED_KONG_VERSIONS = ['2.8.x', '3.0.x', '3.1.x', '3.2.x'];
export const SUPPORTED_REDIS_VERSIONS = ['6.x', '7.x'];

// Component status
export const COMPONENTS = {
  PROTECTION_ENGINE: 'IntelligentIPProtectionSystem',
  KONG_PLUGIN: 'KongIPProtectionPlugin', 
  ANALYTICS_DASHBOARD: 'IPAnalyticsDashboard',
  PROTECTION_MANAGER: 'IPProtectionManager',
} as const;