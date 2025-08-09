/**
 * IP Protection Manager for iSECTECH API Gateway
 * 
 * Central coordination system that integrates all IP protection components:
 * - Intelligent IP Protection System (core engine)
 * - Kong Plugin Integration (gateway integration)  
 * - Analytics Dashboard (monitoring and forensics)
 * - Configuration Management (dynamic updates)
 * 
 * Provides unified API for managing IP protection across the entire system.
 */

import { IntelligentIPProtectionSystem, IPProtectionConfig, IPRule, GeolocationRule } from './intelligent-ip-protection-system';
import { KongIPProtectionPlugin, KongIPProtectionConfig } from './kong-ip-protection-plugin';
import { IPAnalyticsDashboard, DashboardConfig } from './ip-analytics-dashboard';
import { Redis } from 'ioredis';
import { Logger } from 'winston';
import { z } from 'zod';

// Manager configuration schema
const IPProtectionManagerConfigSchema = z.object({
  system: z.object({
    enabled: z.boolean().default(true),
    mode: z.enum(['DEVELOPMENT', 'STAGING', 'PRODUCTION']).default('PRODUCTION'),
    logLevel: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR']).default('INFO'),
  }),
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(0),
    keyPrefix: z.string().default('ip_protection:'),
  }),
  protection: IPProtectionConfig,
  kong: KongIPProtectionConfig,
  dashboard: DashboardConfig,
  integration: z.object({
    healthCheckInterval: z.number().default(30000), // 30 seconds
    configSyncInterval: z.number().default(60000), // 1 minute
    metricsFlushInterval: z.number().default(10000), // 10 seconds
    autoBackup: z.boolean().default(true),
  }),
});

type IPProtectionManagerConfig = z.infer<typeof IPProtectionManagerConfigSchema>;

interface SystemStatus {
  overall: 'healthy' | 'degraded' | 'critical';
  components: {
    protection: { status: string; details: any };
    kong: { status: string; details: any };
    dashboard: { status: string; details: any };
    redis: { status: string; details: any };
  };
  performance: {
    averageResponseTime: number;
    requestsPerSecond: number;
    blockRate: number;
    errorRate: number;
  };
  timestamp: number;
}

interface ConfigurationBackup {
  timestamp: number;
  version: string;
  rules: {
    ipRules: IPRule[];
    geolocationRules: GeolocationRule[];
  };
  settings: {
    protection: any;
    kong: any;
    dashboard: any;
  };
}

/**
 * Centralized IP Protection Management System
 */
export class IPProtectionManager {
  private protectionSystem: IntelligentIPProtectionSystem;
  private kongPlugin: KongIPProtectionPlugin;
  private dashboard: IPAnalyticsDashboard;
  private redis: Redis;
  private logger: Logger;
  private config: IPProtectionManagerConfig;
  private healthCheckTimer?: NodeJS.Timeout;
  private configSyncTimer?: NodeJS.Timeout;
  private metricsFlushTimer?: NodeJS.Timeout;
  private isHealthy: boolean = true;

  constructor(config: IPProtectionManagerConfig, logger: Logger) {
    this.config = IPProtectionManagerConfigSchema.parse(config);
    this.logger = logger;

    // Initialize Redis connection
    this.redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      password: this.config.redis.password,
      db: this.config.redis.db,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
    });

    this.initializeSystem();
  }

  /**
   * Initialize all IP protection components
   */
  private async initializeSystem(): Promise<void> {
    try {
      this.logger.info('Initializing IP Protection Management System', {
        component: 'IPProtectionManager',
        mode: this.config.system.mode,
      });

      // Initialize core protection system
      this.protectionSystem = new IntelligentIPProtectionSystem(
        this.config.protection,
        this.logger
      );

      // Initialize Kong plugin
      this.kongPlugin = new KongIPProtectionPlugin(
        this.protectionSystem,
        this.config.kong,
        this.logger
      );

      // Initialize analytics dashboard
      this.dashboard = new IPAnalyticsDashboard(
        this.protectionSystem,
        this.redis,
        this.config.dashboard,
        this.logger
      );

      // Start monitoring services
      this.startHealthChecks();
      this.startConfigSync();
      this.startMetricsFlush();

      // Create initial configuration backup
      if (this.config.integration.autoBackup) {
        await this.createConfigurationBackup();
      }

      this.logger.info('IP Protection Management System initialized successfully', {
        component: 'IPProtectionManager',
        features: {
          protection: true,
          kong: true,
          dashboard: true,
          monitoring: true,
        },
      });

    } catch (error) {
      this.logger.error('Failed to initialize IP Protection Management System', {
        component: 'IPProtectionManager',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Add IP rule with validation and synchronization
   */
  async addIPRule(rule: Omit<IPRule, 'id'>): Promise<{
    success: boolean;
    ruleId?: string;
    error?: string;
  }> {
    try {
      // Validate rule before adding
      const validationResult = await this.validateIPRule(rule);
      if (!validationResult.valid) {
        return {
          success: false,
          error: `Rule validation failed: ${validationResult.errors.join(', ')}`,
        };
      }

      // Add rule to protection system
      const ruleId = await this.protectionSystem.addIPRule(rule);

      // Create configuration backup
      if (this.config.integration.autoBackup) {
        await this.createConfigurationBackup();
      }

      // Log the addition
      this.logger.info('IP rule added successfully', {
        component: 'IPProtectionManager',
        ruleId,
        type: rule.type,
        cidr: rule.cidr,
        priority: rule.priority,
      });

      return { success: true, ruleId };

    } catch (error) {
      this.logger.error('Error adding IP rule', {
        component: 'IPProtectionManager',
        rule,
        error: error.message,
      });

      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Add geolocation rule with validation
   */
  async addGeolocationRule(rule: Omit<GeolocationRule, 'id'>): Promise<{
    success: boolean;
    ruleId?: string;
    error?: string;
  }> {
    try {
      // Validate geolocation rule
      const validationResult = await this.validateGeolocationRule(rule);
      if (!validationResult.valid) {
        return {
          success: false,
          error: `Rule validation failed: ${validationResult.errors.join(', ')}`,
        };
      }

      // Add rule to protection system
      const ruleId = await this.protectionSystem.addGeolocationRule(rule);

      // Create configuration backup
      if (this.config.integration.autoBackup) {
        await this.createConfigurationBackup();
      }

      this.logger.info('Geolocation rule added successfully', {
        component: 'IPProtectionManager',
        ruleId,
        type: rule.type,
        countries: rule.countries,
      });

      return { success: true, ruleId };

    } catch (error) {
      this.logger.error('Error adding geolocation rule', {
        component: 'IPProtectionManager',
        rule,
        error: error.message,
      });

      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Get comprehensive system status
   */
  async getSystemStatus(): Promise<SystemStatus> {
    try {
      // Get component statuses
      const protectionStatus = await this.protectionSystem.getSystemStatus();
      const kongStatus = this.kongPlugin.getStatus();
      const dashboardStatus = this.dashboard.getStatus();

      // Check Redis connectivity
      const redisStatus = await this.checkRedisHealth();

      // Calculate performance metrics
      const performance = await this.calculatePerformanceMetrics();

      // Determine overall health
      const componentStatuses = [
        protectionStatus.status === 'healthy',
        kongStatus.enabled,
        dashboardStatus.status === 'active',
        redisStatus.status === 'healthy',
      ];

      let overallStatus: 'healthy' | 'degraded' | 'critical';
      const healthyComponents = componentStatuses.filter(Boolean).length;
      
      if (healthyComponents === componentStatuses.length) {
        overallStatus = 'healthy';
      } else if (healthyComponents >= componentStatuses.length / 2) {
        overallStatus = 'degraded';
      } else {
        overallStatus = 'critical';
      }

      return {
        overall: overallStatus,
        components: {
          protection: { status: protectionStatus.status, details: protectionStatus },
          kong: { status: kongStatus.enabled ? 'active' : 'disabled', details: kongStatus },
          dashboard: { status: dashboardStatus.status, details: dashboardStatus },
          redis: { status: redisStatus.status, details: redisStatus },
        },
        performance,
        timestamp: Date.now(),
      };

    } catch (error) {
      this.logger.error('Error getting system status', {
        component: 'IPProtectionManager',
        error: error.message,
      });

      return {
        overall: 'critical',
        components: {
          protection: { status: 'error', details: {} },
          kong: { status: 'error', details: {} },
          dashboard: { status: 'error', details: {} },
          redis: { status: 'error', details: {} },
        },
        performance: {
          averageResponseTime: 0,
          requestsPerSecond: 0,
          blockRate: 0,
          errorRate: 0,
        },
        timestamp: Date.now(),
      };
    }
  }

  /**
   * Perform emergency shutdown of IP protection
   */
  async emergencyShutdown(reason: string): Promise<void> {
    this.logger.warn('Emergency shutdown initiated', {
      component: 'IPProtectionManager',
      reason,
    });

    try {
      // Stop all timers
      if (this.healthCheckTimer) clearInterval(this.healthCheckTimer);
      if (this.configSyncTimer) clearInterval(this.configSyncTimer);
      if (this.metricsFlushTimer) clearInterval(this.metricsFlushTimer);

      // Shutdown components
      await Promise.all([
        this.protectionSystem.shutdown(),
        this.dashboard.shutdown(),
      ]);

      this.kongPlugin.shutdown();

      // Close Redis connection
      await this.redis.quit();

      this.logger.info('Emergency shutdown completed', {
        component: 'IPProtectionManager',
        reason,
      });

    } catch (error) {
      this.logger.error('Error during emergency shutdown', {
        component: 'IPProtectionManager',
        reason,
        error: error.message,
      });
    }
  }

  /**
   * Export system configuration for backup
   */
  async exportConfiguration(): Promise<ConfigurationBackup> {
    try {
      const backup: ConfigurationBackup = {
        timestamp: Date.now(),
        version: '1.0.0',
        rules: {
          ipRules: [], // Would be populated from actual system
          geolocationRules: [], // Would be populated from actual system
        },
        settings: {
          protection: this.config.protection,
          kong: this.config.kong,
          dashboard: this.config.dashboard,
        },
      };

      return backup;
    } catch (error) {
      this.logger.error('Error exporting configuration', {
        component: 'IPProtectionManager',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Import system configuration from backup
   */
  async importConfiguration(backup: ConfigurationBackup): Promise<{
    success: boolean;
    error?: string;
  }> {
    try {
      this.logger.info('Importing configuration from backup', {
        component: 'IPProtectionManager',
        backupTimestamp: backup.timestamp,
        version: backup.version,
      });

      // Validate backup integrity
      if (!backup.timestamp || !backup.rules || !backup.settings) {
        return {
          success: false,
          error: 'Invalid backup format',
        };
      }

      // Create pre-import backup
      await this.createConfigurationBackup();

      // Import IP rules
      for (const rule of backup.rules.ipRules) {
        await this.protectionSystem.addIPRule(rule);
      }

      // Import geolocation rules
      for (const rule of backup.rules.geolocationRules) {
        await this.protectionSystem.addGeolocationRule(rule);
      }

      this.logger.info('Configuration imported successfully', {
        component: 'IPProtectionManager',
        ipRules: backup.rules.ipRules.length,
        geolocationRules: backup.rules.geolocationRules.length,
      });

      return { success: true };

    } catch (error) {
      this.logger.error('Error importing configuration', {
        component: 'IPProtectionManager',
        error: error.message,
      });

      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * Validate IP rule before adding
   */
  private async validateIPRule(rule: Omit<IPRule, 'id'>): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors = [];

    // Validate CIDR format
    try {
      // Basic CIDR validation would go here
      if (!rule.cidr || !rule.cidr.includes('/')) {
        errors.push('Invalid CIDR format');
      }
    } catch (error) {
      errors.push('Invalid CIDR format');
    }

    // Validate priority
    if (rule.priority < 1 || rule.priority > 1000) {
      errors.push('Priority must be between 1 and 1000');
    }

    // Check for conflicting rules
    // Implementation would check against existing rules

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate geolocation rule before adding
   */
  private async validateGeolocationRule(rule: Omit<GeolocationRule, 'id'>): Promise<{
    valid: boolean;
    errors: string[];
  }> {
    const errors = [];

    // Validate country codes
    if (rule.countries) {
      for (const country of rule.countries) {
        if (country.length !== 2) {
          errors.push(`Invalid country code: ${country}`);
        }
      }
    }

    // Validate priority
    if (rule.priority < 1 || rule.priority > 1000) {
      errors.push('Priority must be between 1 and 1000');
    }

    // Must have at least one filter criteria
    if (!rule.countries && !rule.regions && !rule.asns) {
      errors.push('Rule must specify at least one filtering criteria');
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Check Redis health
   */
  private async checkRedisHealth(): Promise<{ status: string; details: any }> {
    try {
      const ping = await this.redis.ping();
      const info = await this.redis.info('memory');
      
      return {
        status: ping === 'PONG' ? 'healthy' : 'degraded',
        details: {
          ping,
          memory: info,
          connections: await this.redis.client('list'),
        },
      };
    } catch (error) {
      return {
        status: 'error',
        details: { error: error.message },
      };
    }
  }

  /**
   * Calculate performance metrics
   */
  private async calculatePerformanceMetrics(): Promise<{
    averageResponseTime: number;
    requestsPerSecond: number;
    blockRate: number;
    errorRate: number;
  }> {
    try {
      // Get metrics from Redis
      const metricsData = await this.redis.hgetall('metrics:performance');
      
      return {
        averageResponseTime: parseFloat(metricsData.avg_response_time || '0'),
        requestsPerSecond: parseFloat(metricsData.requests_per_second || '0'),
        blockRate: parseFloat(metricsData.block_rate || '0'),
        errorRate: parseFloat(metricsData.error_rate || '0'),
      };
    } catch (error) {
      return {
        averageResponseTime: 0,
        requestsPerSecond: 0,
        blockRate: 0,
        errorRate: 0,
      };
    }
  }

  /**
   * Start health check monitoring
   */
  private startHealthChecks(): void {
    this.healthCheckTimer = setInterval(async () => {
      try {
        const status = await this.getSystemStatus();
        this.isHealthy = status.overall === 'healthy';

        if (!this.isHealthy) {
          this.logger.warn('System health degraded', {
            component: 'IPProtectionManager',
            status: status.overall,
            components: status.components,
          });
        }
      } catch (error) {
        this.logger.error('Health check failed', {
          component: 'IPProtectionManager',
          error: error.message,
        });
        this.isHealthy = false;
      }
    }, this.config.integration.healthCheckInterval);
  }

  /**
   * Start configuration synchronization
   */
  private startConfigSync(): void {
    this.configSyncTimer = setInterval(async () => {
      try {
        // Sync configurations between components
        // Implementation would handle dynamic config updates
      } catch (error) {
        this.logger.error('Configuration sync failed', {
          component: 'IPProtectionManager',
          error: error.message,
        });
      }
    }, this.config.integration.configSyncInterval);
  }

  /**
   * Start metrics flushing
   */
  private startMetricsFlush(): void {
    this.metricsFlushTimer = setInterval(async () => {
      try {
        // Flush metrics to persistent storage
        await this.flushMetrics();
      } catch (error) {
        this.logger.error('Metrics flush failed', {
          component: 'IPProtectionManager',
          error: error.message,
        });
      }
    }, this.config.integration.metricsFlushInterval);
  }

  /**
   * Create configuration backup
   */
  private async createConfigurationBackup(): Promise<void> {
    try {
      const backup = await this.exportConfiguration();
      const backupKey = `backup:config:${backup.timestamp}`;
      
      await this.redis.set(backupKey, JSON.stringify(backup));
      await this.redis.expire(backupKey, 30 * 24 * 60 * 60); // 30 days
      
      // Keep only last 10 backups
      const backupKeys = await this.redis.keys('backup:config:*');
      if (backupKeys.length > 10) {
        const sortedKeys = backupKeys.sort();
        const toDelete = sortedKeys.slice(0, sortedKeys.length - 10);
        await this.redis.del(...toDelete);
      }
      
    } catch (error) {
      this.logger.error('Error creating configuration backup', {
        component: 'IPProtectionManager',
        error: error.message,
      });
    }
  }

  /**
   * Flush metrics to persistent storage
   */
  private async flushMetrics(): Promise<void> {
    // Implementation would flush in-memory metrics to Redis/database
  }

  /**
   * Get manager status
   */
  getManagerStatus(): {
    status: string;
    uptime: number;
    healthy: boolean;
    lastHealthCheck: number;
  } {
    return {
      status: 'running',
      uptime: Date.now(),
      healthy: this.isHealthy,
      lastHealthCheck: Date.now(),
    };
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    try {
      // Stop timers
      if (this.healthCheckTimer) clearInterval(this.healthCheckTimer);
      if (this.configSyncTimer) clearInterval(this.configSyncTimer);
      if (this.metricsFlushTimer) clearInterval(this.metricsFlushTimer);

      // Shutdown components
      await this.protectionSystem.shutdown();
      await this.dashboard.shutdown();
      this.kongPlugin.shutdown();

      // Close Redis
      await this.redis.quit();

      this.logger.info('IP Protection Manager shutdown completed');
    } catch (error) {
      this.logger.error('Error during shutdown', {
        component: 'IPProtectionManager',
        error: error.message,
      });
    }
  }
}

// Export configuration schema and types
export { IPProtectionManagerConfigSchema };
export type { IPProtectionManagerConfig, SystemStatus, ConfigurationBackup };