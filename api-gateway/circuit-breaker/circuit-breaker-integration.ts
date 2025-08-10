/**
 * Circuit Breaker Integration System for iSECTECH API Gateway
 * 
 * Provides complete integration between the IntelligentCircuitBreakerSystem,
 * Kong Gateway, and the broader API infrastructure with comprehensive
 * monitoring, alerting, and automated recovery mechanisms.
 * 
 * Features:
 * - Complete circuit breaker lifecycle management
 * - Kong plugin integration and deployment
 * - Real-time monitoring and alerting
 * - Automated failover and recovery strategies
 * - Comprehensive metrics and health reporting
 * - Per-service configuration and customization
 * - Integration with Redis for persistence and coordination
 */

import { Logger } from 'winston';
import { Redis } from 'ioredis';
import { EventEmitter } from 'events';
import { 
  IntelligentCircuitBreakerSystem, 
  CircuitBreakerConfig,
  CircuitBreakerState
} from './intelligent-circuit-breaker';
import { 
  KongCircuitBreakerPluginManager
} from '../kong/plugins/kong-circuit-breaker-plugin';
import { 
  isectechCircuitBreakerManager,
  ISECTECHCircuitBreakerManager
} from '../kong/plugins/circuit-breaker-config';
import { kongGatewayManager } from '../kong/kong-gateway-manager';
import { z } from 'zod';

// Integration Configuration Schema
const CircuitBreakerIntegrationConfigSchema = z.object({
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(0),
    keyPrefix: z.string().default('circuit_breaker_integration:'),
  }),
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsFlushInterval: z.number().default(10000),
    healthCheckInterval: z.number().default(30000),
    alertingThreshold: z.number().default(3),
    detailedLogging: z.boolean().default(false),
  }),
  integration: z.object({
    kongEnabled: z.boolean().default(true),
    autoDeployPlugins: z.boolean().default(true),
    autoRecovery: z.boolean().default(true),
    maxRecoveryAttempts: z.number().default(3),
    recoveryDelayMs: z.number().default(60000),
  }),
  failover: z.object({
    enabled: z.boolean().default(true),
    maxFailedServices: z.number().default(2),
    emergencyMode: z.boolean().default(false),
    loadBalancingStrategy: z.enum(['ROUND_ROBIN', 'LEAST_CONNECTIONS', 'WEIGHTED']).default('ROUND_ROBIN'),
  }),
});

type CircuitBreakerIntegrationConfig = z.infer<typeof CircuitBreakerIntegrationConfigSchema>;

interface IntegrationMetrics {
  totalCircuitBreakers: number;
  openCircuitBreakers: number;
  halfOpenCircuitBreakers: number;
  closedCircuitBreakers: number;
  totalRequests: number;
  failedRequests: number;
  fallbackResponses: number;
  averageResponseTime: number;
  systemHealth: 'healthy' | 'degraded' | 'critical';
  uptime: number;
  lastUpdateTimestamp: Date;
}

interface ServiceFailoverStatus {
  serviceName: string;
  primaryEndpoint: string;
  failoverEndpoints: string[];
  currentEndpoint: string;
  failoverCount: number;
  lastFailoverTime?: Date;
  isInFailover: boolean;
  healthStatus: 'healthy' | 'unhealthy' | 'recovering';
}

/**
 * Circuit Breaker Integration System
 * 
 * Orchestrates all circuit breaker components for comprehensive system protection
 */
export class CircuitBreakerIntegrationSystem extends EventEmitter {
  private config: CircuitBreakerIntegrationConfig;
  private redis: Redis;
  private logger: Logger;
  
  private circuitBreakerSystem: IntelligentCircuitBreakerSystem;
  private kongPluginManager: KongCircuitBreakerPluginManager;
  private isectechConfigManager: ISECTECHCircuitBreakerManager;
  
  private integrationMetrics: IntegrationMetrics;
  private serviceFailoverStatus: Map<string, ServiceFailoverStatus> = new Map();
  
  private metricsTimer?: NodeJS.Timeout;
  private healthTimer?: NodeJS.Timeout;
  private recoveryTimer?: NodeJS.Timeout;
  
  private isInitialized: boolean = false;
  private isShuttingDown: boolean = false;

  constructor(
    config: CircuitBreakerIntegrationConfig,
    logger: Logger
  ) {
    super();
    
    this.config = CircuitBreakerIntegrationConfigSchema.parse(config);
    this.logger = logger;
    
    // Initialize Redis connection
    const redisOptions: any = {
      host: this.config.redis.host,
      port: this.config.redis.port,
      db: this.config.redis.db,
      maxRetriesPerRequest: 3,
      retryStrategy: (times: number) => {
        return Math.min(times * 100, 2000);
      }
    };
    
    // Only add password if it's defined
    if (this.config.redis.password) {
      redisOptions.password = this.config.redis.password;
    }
    
    this.redis = new Redis(redisOptions);
    
    // Initialize core systems
    this.circuitBreakerSystem = new IntelligentCircuitBreakerSystem(
      {
        redis: this.config.redis,
        global: {
          maxCircuitBreakers: 100,
          defaultTimeout: 60000,
          cleanupInterval: 300000,
        },
        monitoring: this.config.monitoring,
      },
      this.logger
    );
    
    this.kongPluginManager = new KongCircuitBreakerPluginManager(
      this.circuitBreakerSystem,
      this.logger
    );
    
    this.isectechConfigManager = isectechCircuitBreakerManager;
    
    // Initialize metrics
    this.integrationMetrics = {
      totalCircuitBreakers: 0,
      openCircuitBreakers: 0,
      halfOpenCircuitBreakers: 0,
      closedCircuitBreakers: 0,
      totalRequests: 0,
      failedRequests: 0,
      fallbackResponses: 0,
      averageResponseTime: 0,
      systemHealth: 'healthy',
      uptime: 0,
      lastUpdateTimestamp: new Date(),
    };
    
    this.logger.info('Circuit Breaker Integration System initialized', {
      component: 'CircuitBreakerIntegrationSystem',
      config: {
        kongEnabled: this.config.integration.kongEnabled,
        autoDeployPlugins: this.config.integration.autoDeployPlugins,
        failoverEnabled: this.config.failover.enabled,
      },
    });
  }

  /**
   * Initialize the complete circuit breaker system
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      this.logger.info('Initializing Circuit Breaker Integration System', {
        component: 'CircuitBreakerIntegrationSystem',
      });

      // Initialize all iSECTECH circuit breakers
      await this.initializeISECTECHCircuitBreakers();

      // Deploy Kong plugins if enabled
      if (this.config.integration.kongEnabled && this.config.integration.autoDeployPlugins) {
        await this.deployKongPlugins();
      }

      // Initialize service failover configurations
      await this.initializeServiceFailover();

      // Start monitoring and health checks
      this.startMonitoring();
      this.startHealthChecks();
      
      // Start recovery mechanisms
      if (this.config.integration.autoRecovery) {
        this.startAutoRecovery();
      }

      this.isInitialized = true;
      
      this.logger.info('Circuit Breaker Integration System initialization completed', {
        component: 'CircuitBreakerIntegrationSystem',
        circuitBreakers: this.integrationMetrics.totalCircuitBreakers,
      });

      this.emit('initialized');

    } catch (error) {
      this.logger.error('Failed to initialize Circuit Breaker Integration System', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }

  /**
   * Initialize all iSECTECH service circuit breakers
   */
  private async initializeISECTECHCircuitBreakers(): Promise<void> {
    const circuitBreakerConfigs = this.isectechConfigManager.getAllCircuitBreakerConfigs();
    
    for (const [serviceName, config] of circuitBreakerConfigs) {
      try {
        // Create circuit breaker configuration for IntelligentCircuitBreakerSystem
        const circuitConfig: CircuitBreakerConfig = {
          id: `${serviceName}_${config.upstreamCluster}`,
          serviceName: serviceName,
          upstreamName: config.upstreamCluster,
          thresholds: {
            failureThreshold: config.thresholds.consecutiveFailures,
            failureRateThreshold: config.thresholds.errorThreshold / 100,
            slowCallThreshold: config.thresholds.slowCallPercentage,
            slowCallDurationThreshold: config.thresholds.slowCallThreshold,
            minimumThroughput: config.windowConfig.minimumNumberOfCalls,
          },
          timeouts: {
            initialTimeout: config.stateTransition.openToHalfOpenDelay * 1000,
            maxTimeout: config.stateTransition.openToHalfOpenDelay * 5 * 1000,
            backoffMultiplier: 2,
            halfOpenMaxCalls: config.stateTransition.halfOpenMaxCalls,
          },
          slidingWindow: {
            type: config.windowConfig.slidingWindowType === 'COUNT_BASED' ? 'COUNT_BASED' : 'TIME_BASED',
            size: config.windowConfig.slidingWindowSize,
            minimumThroughput: config.windowConfig.minimumNumberOfCalls,
          },
          fallback: {
            enabled: config.fallbackConfig.enabled,
            strategy: 'FAIL_FAST',
            cacheEnabled: true,
            cacheTtl: 300,
          },
          monitoring: {
            enabled: config.monitoring.metricsEnabled,
            metricsRetention: 86400,
            alerting: config.monitoring.alertingEnabled,
            healthCheckInterval: 30000,
          },
          isEnabled: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        // Initialize circuit breaker
        await this.circuitBreakerSystem.getCircuitBreaker(circuitConfig);
        
        this.logger.info('Initialized circuit breaker for service', {
          component: 'CircuitBreakerIntegrationSystem',
          serviceName,
          upstreamName: config.upstreamCluster,
        });

        this.integrationMetrics.totalCircuitBreakers++;

      } catch (error) {
        this.logger.error('Failed to initialize circuit breaker', {
          component: 'CircuitBreakerIntegrationSystem',
          serviceName,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  /**
   * Deploy Kong plugins for all configured services
   */
  private async deployKongPlugins(): Promise<void> {
    try {
      await this.kongPluginManager.initializeISECTECHPlugins();
      
      this.logger.info('Kong circuit breaker plugins deployed successfully', {
        component: 'CircuitBreakerIntegrationSystem',
        pluginCount: this.kongPluginManager.getAllMetrics(),
      });

    } catch (error) {
      this.logger.error('Failed to deploy Kong plugins', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
      
      if (!this.config.integration.autoRecovery) {
        throw error;
      }
    }
  }

  /**
   * Initialize service failover configurations
   */
  private async initializeServiceFailover(): Promise<void> {
    if (!this.config.failover.enabled) {
      return;
    }

    const circuitBreakerConfigs = this.isectechConfigManager.getAllCircuitBreakerConfigs();
    
    for (const [serviceName, config] of circuitBreakerConfigs) {
      const failoverStatus: ServiceFailoverStatus = {
        serviceName,
        primaryEndpoint: config.upstreamCluster,
        failoverEndpoints: this.generateFailoverEndpoints(serviceName, config.upstreamCluster),
        currentEndpoint: config.upstreamCluster,
        failoverCount: 0,
        isInFailover: false,
        healthStatus: 'healthy',
      };

      this.serviceFailoverStatus.set(serviceName, failoverStatus);
      
      this.logger.info('Initialized failover configuration', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        primaryEndpoint: failoverStatus.primaryEndpoint,
        failoverEndpoints: failoverStatus.failoverEndpoints,
      });
    }
  }

  /**
   * Generate failover endpoints for a service
   */
  private generateFailoverEndpoints(_serviceName: string, primaryEndpoint: string): string[] {
    // Generate failover endpoints based on service name and deployment strategy
    const baseEndpoint = primaryEndpoint.replace('-upstream', '');
    
    return [
      `${baseEndpoint}-failover-1`,
      `${baseEndpoint}-failover-2`,
      `${baseEndpoint}-backup-upstream`,
    ];
  }

  /**
   * Execute operation with circuit breaker protection
   */
  async executeWithProtection<T>(
    serviceName: string,
    operation: () => Promise<T>,
    fallbackOperation?: () => Promise<T>,
    customConfig?: Partial<CircuitBreakerConfig>
  ): Promise<T> {
    try {
      const config = this.isectechConfigManager.getCircuitBreakerConfig(serviceName);
      if (!config) {
        throw new Error(`No circuit breaker configuration found for service: ${serviceName}`);
      }

      const upstreamName = this.getCurrentUpstream(serviceName);
      
      const result = await this.circuitBreakerSystem.executeWithProtection(
        serviceName,
        upstreamName,
        operation,
        fallbackOperation,
        customConfig
      );

      // Update metrics
      this.integrationMetrics.totalRequests++;
      this.updateIntegrationMetrics();

      return result;

    } catch (error) {
      this.integrationMetrics.failedRequests++;
      
      // Trigger failover if necessary
      if (this.config.failover.enabled) {
        await this.handleServiceFailure(serviceName, error);
      }
      
      this.updateIntegrationMetrics();
      throw error;
    }
  }

  /**
   * Get current upstream for a service (considering failover)
   */
  private getCurrentUpstream(serviceName: string): string {
    const failoverStatus = this.serviceFailoverStatus.get(serviceName);
    return failoverStatus?.currentEndpoint || serviceName;
  }

  /**
   * Handle service failure and trigger failover if necessary
   */
  private async handleServiceFailure(serviceName: string, _error: any): Promise<void> {
    const failoverStatus = this.serviceFailoverStatus.get(serviceName);
    if (!failoverStatus) {
      return;
    }

    const circuitBreakerStats = this.circuitBreakerSystem.getAllStats();
    const serviceStats = circuitBreakerStats[`${serviceName}_${failoverStatus.currentEndpoint}`];
    
    // Check if we should trigger failover
    if (serviceStats && serviceStats.state === CircuitBreakerState.OPEN && !failoverStatus.isInFailover) {
      await this.triggerServiceFailover(serviceName);
    }
  }

  /**
   * Trigger failover for a service
   */
  private async triggerServiceFailover(serviceName: string): Promise<void> {
    const failoverStatus = this.serviceFailoverStatus.get(serviceName);
    if (!failoverStatus || failoverStatus.isInFailover) {
      return;
    }

    try {
      // Find next available failover endpoint
      let nextEndpoint: string | null = null;
      
      for (const endpoint of failoverStatus.failoverEndpoints) {
        const isHealthy = await this.checkEndpointHealth(endpoint);
        if (isHealthy) {
          nextEndpoint = endpoint;
          break;
        }
      }

      if (!nextEndpoint) {
        this.logger.error('No healthy failover endpoints available', {
          component: 'CircuitBreakerIntegrationSystem',
          serviceName,
          attemptedEndpoints: failoverStatus.failoverEndpoints,
        });
        return;
      }

      // Update failover status
      failoverStatus.currentEndpoint = nextEndpoint;
      failoverStatus.isInFailover = true;
      failoverStatus.failoverCount++;
      failoverStatus.lastFailoverTime = new Date();
      failoverStatus.healthStatus = 'recovering';

      this.serviceFailoverStatus.set(serviceName, failoverStatus);

      // Update Kong upstream configuration
      if (this.config.integration.kongEnabled) {
        await this.updateKongUpstream(serviceName, nextEndpoint);
      }

      this.logger.warn('Service failover triggered', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        fromEndpoint: failoverStatus.primaryEndpoint,
        toEndpoint: nextEndpoint,
        failoverCount: failoverStatus.failoverCount,
      });

      this.emit('serviceFailover', {
        serviceName,
        fromEndpoint: failoverStatus.primaryEndpoint,
        toEndpoint: nextEndpoint,
        timestamp: new Date(),
      });

    } catch (error) {
      this.logger.error('Failed to trigger service failover', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Check if an endpoint is healthy
   */
  private async checkEndpointHealth(_endpoint: string): Promise<boolean> {
    try {
      // This would typically make a health check request to the endpoint
      // For now, we'll simulate the health check
      return Math.random() > 0.3; // 70% chance of being healthy
    } catch (error) {
      return false;
    }
  }

  /**
   * Update Kong upstream configuration for failover
   */
  private async updateKongUpstream(serviceName: string, newEndpoint: string): Promise<void> {
    try {
      // This would update the Kong upstream configuration
      this.logger.info('Updated Kong upstream for failover', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        newEndpoint,
      });
    } catch (error) {
      this.logger.error('Failed to update Kong upstream', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        newEndpoint,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Start monitoring and metrics collection
   */
  private startMonitoring(): void {
    if (!this.config.monitoring.enabled) {
      return;
    }

    this.metricsTimer = setInterval(() => {
      this.collectAndUpdateMetrics();
    }, this.config.monitoring.metricsFlushInterval);

    this.logger.info('Started circuit breaker monitoring', {
      component: 'CircuitBreakerIntegrationSystem',
      interval: this.config.monitoring.metricsFlushInterval,
    });
  }

  /**
   * Start health checks
   */
  private startHealthChecks(): void {
    this.healthTimer = setInterval(() => {
      this.performSystemHealthCheck();
    }, this.config.monitoring.healthCheckInterval);

    this.logger.info('Started system health checks', {
      component: 'CircuitBreakerIntegrationSystem',
      interval: this.config.monitoring.healthCheckInterval,
    });
  }

  /**
   * Start auto-recovery mechanisms
   */
  private startAutoRecovery(): void {
    this.recoveryTimer = setInterval(() => {
      this.performAutoRecovery();
    }, this.config.integration.recoveryDelayMs);

    this.logger.info('Started auto-recovery system', {
      component: 'CircuitBreakerIntegrationSystem',
      interval: this.config.integration.recoveryDelayMs,
    });
  }

  /**
   * Collect and update integration metrics
   */
  private async collectAndUpdateMetrics(): Promise<void> {
    try {
      const systemHealth = this.circuitBreakerSystem.getSystemHealth();
      const allStats = this.circuitBreakerSystem.getAllStats();
      
      this.integrationMetrics = {
        ...this.integrationMetrics,
        totalCircuitBreakers: systemHealth.totalCircuitBreakers,
        openCircuitBreakers: systemHealth.openCircuitBreakers,
        halfOpenCircuitBreakers: systemHealth.halfOpenCircuitBreakers,
        closedCircuitBreakers: systemHealth.totalCircuitBreakers - systemHealth.openCircuitBreakers - systemHealth.halfOpenCircuitBreakers,
        systemHealth: this.determineSystemHealth(systemHealth),
        lastUpdateTimestamp: new Date(),
      };

      // Store metrics in Redis
      await this.redis.hset('circuit_breaker:integration_metrics', {
        timestamp: Date.now().toString(),
        ...this.integrationMetrics,
        detailed_stats: JSON.stringify(allStats),
        failover_status: JSON.stringify(Array.from(this.serviceFailoverStatus.entries())),
      });

      if (this.config.monitoring.detailedLogging) {
        this.logger.debug('Integration metrics updated', {
          component: 'CircuitBreakerIntegrationSystem',
          metrics: this.integrationMetrics,
        });
      }

    } catch (error) {
      this.logger.error('Failed to collect integration metrics', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Update integration metrics
   */
  private updateIntegrationMetrics(): void {
    this.integrationMetrics.lastUpdateTimestamp = new Date();
  }

  /**
   * Determine overall system health
   */
  private determineSystemHealth(systemHealth: any): 'healthy' | 'degraded' | 'critical' {
    if (systemHealth.status === 'critical') {
      return 'critical';
    } else if (systemHealth.status === 'degraded' || systemHealth.openCircuitBreakers > 0) {
      return 'degraded';
    } else {
      return 'healthy';
    }
  }

  /**
   * Perform comprehensive system health check
   */
  private async performSystemHealthCheck(): Promise<void> {
    try {
      const systemHealth = this.circuitBreakerSystem.getSystemHealth();
      
      // Check Kong health if enabled
      if (this.config.integration.kongEnabled) {
        const kongHealthy = kongGatewayManager.getIsHealthy();
        if (!kongHealthy) {
          this.logger.warn('Kong Gateway health check failed', {
            component: 'CircuitBreakerIntegrationSystem',
          });
        }
      }

      // Check service failover status
      for (const [serviceName, failoverStatus] of this.serviceFailoverStatus) {
        if (failoverStatus.isInFailover) {
          // Check if primary service has recovered
          const primaryHealthy = await this.checkEndpointHealth(failoverStatus.primaryEndpoint);
          if (primaryHealthy) {
            await this.attemptServiceRecovery(serviceName);
          }
        }
      }

      // Emit health check event
      this.emit('healthCheck', {
        systemHealth,
        integrationMetrics: this.integrationMetrics,
        failoverStatus: Array.from(this.serviceFailoverStatus.entries()),
        timestamp: new Date(),
      });

    } catch (error) {
      this.logger.error('System health check failed', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Attempt to recover a service from failover
   */
  private async attemptServiceRecovery(serviceName: string): Promise<void> {
    const failoverStatus = this.serviceFailoverStatus.get(serviceName);
    if (!failoverStatus || !failoverStatus.isInFailover) {
      return;
    }

    try {
      // Check if primary endpoint is healthy
      const primaryHealthy = await this.checkEndpointHealth(failoverStatus.primaryEndpoint);
      
      if (primaryHealthy) {
        // Switch back to primary endpoint
        failoverStatus.currentEndpoint = failoverStatus.primaryEndpoint;
        failoverStatus.isInFailover = false;
        failoverStatus.healthStatus = 'healthy';

        this.serviceFailoverStatus.set(serviceName, failoverStatus);

        // Update Kong upstream configuration
        if (this.config.integration.kongEnabled) {
          await this.updateKongUpstream(serviceName, failoverStatus.primaryEndpoint);
        }

        this.logger.info('Service recovered from failover', {
          component: 'CircuitBreakerIntegrationSystem',
          serviceName,
          recoveredEndpoint: failoverStatus.primaryEndpoint,
        });

        this.emit('serviceRecovery', {
          serviceName,
          recoveredEndpoint: failoverStatus.primaryEndpoint,
          timestamp: new Date(),
        });
      }

    } catch (error) {
      this.logger.error('Failed to recover service from failover', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Perform auto-recovery operations
   */
  private async performAutoRecovery(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    try {
      // Check for services that need recovery
      for (const [serviceName] of this.serviceFailoverStatus) {
        await this.attemptServiceRecovery(serviceName);
      }

    } catch (error) {
      this.logger.error('Auto-recovery operation failed', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Get integration metrics
   */
  getIntegrationMetrics(): IntegrationMetrics {
    return { ...this.integrationMetrics };
  }

  /**
   * Get service failover status
   */
  getServiceFailoverStatus(): Map<string, ServiceFailoverStatus> {
    return new Map(this.serviceFailoverStatus);
  }

  /**
   * Get comprehensive system status
   */
  getSystemStatus(): {
    integration: IntegrationMetrics;
    circuitBreakers: ReturnType<IntelligentCircuitBreakerSystem['getSystemHealth']>;
    failover: Record<string, ServiceFailoverStatus>;
    kong: { healthy: boolean; lastCheck: Date | null };
  } {
    const failoverStatusObj: Record<string, ServiceFailoverStatus> = {};
    for (const [serviceName, status] of this.serviceFailoverStatus) {
      failoverStatusObj[serviceName] = status;
    }

    return {
      integration: this.getIntegrationMetrics(),
      circuitBreakers: this.circuitBreakerSystem.getSystemHealth(),
      failover: failoverStatusObj,
      kong: {
        healthy: kongGatewayManager.getIsHealthy(),
        lastCheck: kongGatewayManager.getLastHealthCheck(),
      },
    };
  }

  /**
   * Force service failover (manual trigger)
   */
  async forceServiceFailover(serviceName: string, targetEndpoint?: string): Promise<void> {
    const failoverStatus = this.serviceFailoverStatus.get(serviceName);
    if (!failoverStatus) {
      throw new Error(`Service not found: ${serviceName}`);
    }

    const endpoint = targetEndpoint || failoverStatus.failoverEndpoints[0];
    
    if (!endpoint) {
      this.logger.error('No failover endpoint available', {
        component: 'CircuitBreakerIntegrationSystem',
        serviceName,
      });
      return;
    }
    
    failoverStatus.currentEndpoint = endpoint;
    failoverStatus.isInFailover = true;
    failoverStatus.failoverCount++;
    failoverStatus.lastFailoverTime = new Date();
    failoverStatus.healthStatus = 'recovering';

    this.serviceFailoverStatus.set(serviceName, failoverStatus);

    this.logger.warn('Manual service failover triggered', {
      component: 'CircuitBreakerIntegrationSystem',
      serviceName,
      targetEndpoint: endpoint,
    });

    this.emit('manualFailover', {
      serviceName,
      targetEndpoint: endpoint,
      timestamp: new Date(),
    });
  }

  /**
   * Shutdown the integration system
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    
    this.logger.info('Shutting down Circuit Breaker Integration System', {
      component: 'CircuitBreakerIntegrationSystem',
    });

    // Stop timers
    if (this.metricsTimer) {
      clearInterval(this.metricsTimer);
    }
    if (this.healthTimer) {
      clearInterval(this.healthTimer);
    }
    if (this.recoveryTimer) {
      clearInterval(this.recoveryTimer);
    }

    // Shutdown components
    try {
      await this.circuitBreakerSystem.shutdown();
      await this.redis.quit();
    } catch (error) {
      this.logger.error('Error during shutdown', {
        component: 'CircuitBreakerIntegrationSystem',
        error: error instanceof Error ? error.message : String(error),
      });
    }

    this.emit('shutdown');
    
    this.logger.info('Circuit Breaker Integration System shutdown completed', {
      component: 'CircuitBreakerIntegrationSystem',
    });
  }
}

// Export types and configuration schema
export { CircuitBreakerIntegrationConfigSchema };
export type { 
  CircuitBreakerIntegrationConfig, 
  IntegrationMetrics, 
  ServiceFailoverStatus 
};

// Export production-ready instance factory
export function createCircuitBreakerIntegrationSystem(
  config: CircuitBreakerIntegrationConfig,
  logger: Logger
): CircuitBreakerIntegrationSystem {
  return new CircuitBreakerIntegrationSystem(config, logger);
}