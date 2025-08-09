/**
 * Kong Circuit Breaker Plugin Integration for iSECTECH API Gateway
 * 
 * Integrates the IntelligentCircuitBreakerSystem with Kong Gateway for production-ready
 * circuit breaker functionality with three states (closed, open, half-open), failure
 * thresholds, recovery timeouts, and comprehensive fallback mechanisms.
 * 
 * Features:
 * - Seamless integration with Kong's plugin architecture
 * - Per-service circuit breaker configurations
 * - Real-time metrics collection and monitoring
 * - Automatic failover and recovery mechanisms
 * - Custom fallback strategies with response caching
 * - Prometheus metrics integration
 * - Health check integration
 */

import { z } from 'zod';
import { Logger } from 'winston';
import { IntelligentCircuitBreakerSystem, CircuitBreakerConfig, CircuitBreakerState } from '../circuit-breaker/intelligent-circuit-breaker';
import { isectechCircuitBreakerManager } from './circuit-breaker-config';

// Kong Plugin Configuration Schema
const KongCircuitBreakerPluginConfigSchema = z.object({
  // Plugin identification
  name: z.literal('isectech-circuit-breaker'),
  service: z.object({
    id: z.string(),
    name: z.string().optional(),
  }),
  route: z.object({
    id: z.string(),
    name: z.string().optional(),
  }).optional(),
  consumer: z.object({
    id: z.string(),
    username: z.string().optional(),
  }).optional(),
  
  // Circuit breaker configuration
  config: z.object({
    // Service identification
    serviceName: z.string(),
    upstreamName: z.string(),
    
    // Failure thresholds
    failureThreshold: z.number().min(1).max(100).default(5),
    failureRateThreshold: z.number().min(0).max(1).default(0.5),
    slowCallThreshold: z.number().min(1).default(10),
    slowCallDurationThreshold: z.number().min(100).default(5000),
    minimumThroughput: z.number().min(1).default(10),
    
    // Timing configuration
    initialTimeout: z.number().min(1000).default(60000),
    maxTimeout: z.number().min(60000).default(300000),
    backoffMultiplier: z.number().min(1).default(2),
    halfOpenMaxCalls: z.number().min(1).default(3),
    
    // Sliding window configuration
    slidingWindowType: z.enum(['TIME_BASED', 'COUNT_BASED']).default('TIME_BASED'),
    slidingWindowSize: z.number().min(10).default(60),
    
    // Fallback configuration
    fallbackEnabled: z.boolean().default(true),
    fallbackStrategy: z.enum(['CACHE', 'MOCK', 'ALTERNATE_SERVICE', 'FAIL_FAST', 'CUSTOM']).default('FAIL_FAST'),
    cacheEnabled: z.boolean().default(true),
    cacheTtl: z.number().default(300),
    alternateService: z.string().optional(),
    mockResponse: z.record(z.any()).optional(),
    
    // Response configuration
    fallbackStatusCode: z.number().default(503),
    fallbackBody: z.string().optional(),
    fallbackHeaders: z.record(z.string()).default({
      'Content-Type': 'application/json',
      'Retry-After': '30',
      'X-Circuit-Breaker': 'OPEN',
    }),
    
    // Monitoring
    metricsEnabled: z.boolean().default(true),
    alertingEnabled: z.boolean().default(true),
    healthCheckInterval: z.number().default(30000),
  }),
  
  // Plugin metadata
  enabled: z.boolean().default(true),
  tags: z.array(z.string()).default(['isectech', 'circuit-breaker']),
});

type KongCircuitBreakerPluginConfig = z.infer<typeof KongCircuitBreakerPluginConfigSchema>;

interface KongRequestContext {
  request: {
    get_method(): string;
    get_path(): string;
    get_headers(): Record<string, string>;
    get_query(): Record<string, string>;
  };
  response: {
    set_status(status: number): void;
    set_header(name: string, value: string): void;
    set_body(body: string): void;
  };
  service: {
    request: {
      set_header(name: string, value: string): void;
    };
  };
  ctx: {
    shared: Record<string, any>;
  };
}

interface KongUpstreamResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Kong Circuit Breaker Plugin for iSECTECH
 */
export class KongCircuitBreakerPlugin {
  private circuitBreakerSystem: IntelligentCircuitBreakerSystem;
  private logger: Logger;
  private config: KongCircuitBreakerPluginConfig['config'];
  private metrics: Map<string, any> = new Map();

  constructor(
    circuitBreakerSystem: IntelligentCircuitBreakerSystem,
    logger: Logger,
    config: KongCircuitBreakerPluginConfig['config']
  ) {
    this.circuitBreakerSystem = circuitBreakerSystem;
    this.logger = logger;
    this.config = config;
    
    this.initializeMetrics();
  }

  /**
   * Kong plugin access phase - executed before upstream request
   */
  async access(kong: KongRequestContext): Promise<void> {
    try {
      const startTime = Date.now();
      const requestId = this.generateRequestId();
      
      // Store request metadata in Kong context
      kong.ctx.shared.circuit_breaker = {
        requestId,
        startTime,
        serviceName: this.config.serviceName,
        upstreamName: this.config.upstreamName,
      };

      // Add circuit breaker headers to upstream request
      kong.service.request.set_header('X-Circuit-Breaker-Request-ID', requestId);
      kong.service.request.set_header('X-Circuit-Breaker-Service', this.config.serviceName);
      
      this.logger.debug('Circuit breaker access phase completed', {
        component: 'KongCircuitBreakerPlugin',
        service: this.config.serviceName,
        requestId,
        method: kong.request.get_method(),
        path: kong.request.get_path(),
      });

    } catch (error) {
      this.logger.error('Error in circuit breaker access phase', {
        component: 'KongCircuitBreakerPlugin',
        service: this.config.serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Kong plugin response phase - executed after upstream response
   */
  async response(kong: KongRequestContext, upstreamResponse: KongUpstreamResponse): Promise<void> {
    try {
      const circuitBreakerData = kong.ctx.shared.circuit_breaker;
      if (!circuitBreakerData) {
        return;
      }

      const duration = Date.now() - circuitBreakerData.startTime;
      const success = this.isSuccessfulResponse(upstreamResponse.status);

      // Execute circuit breaker logic
      const result = await this.executeCircuitBreakerLogic(
        upstreamResponse,
        duration,
        success,
        circuitBreakerData
      );

      if (result.useFallback) {
        // Apply fallback response
        kong.response.set_status(result.fallbackResponse.status);
        
        Object.entries(result.fallbackResponse.headers).forEach(([name, value]) => {
          kong.response.set_header(name, value);
        });
        
        if (result.fallbackResponse.body) {
          kong.response.set_body(result.fallbackResponse.body);
        }
      } else {
        // Add circuit breaker headers to successful response
        kong.response.set_header('X-Circuit-Breaker-State', result.circuitState);
        kong.response.set_header('X-Circuit-Breaker-Service', this.config.serviceName);
      }

      // Update metrics
      this.updateMetrics(result.circuitState, success, duration);

      this.logger.debug('Circuit breaker response phase completed', {
        component: 'KongCircuitBreakerPlugin',
        service: this.config.serviceName,
        requestId: circuitBreakerData.requestId,
        duration,
        success,
        circuitState: result.circuitState,
        useFallback: result.useFallback,
      });

    } catch (error) {
      this.logger.error('Error in circuit breaker response phase', {
        component: 'KongCircuitBreakerPlugin',
        service: this.config.serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Execute circuit breaker logic with upstream response
   */
  private async executeCircuitBreakerLogic(
    upstreamResponse: KongUpstreamResponse,
    duration: number,
    success: boolean,
    requestData: any
  ): Promise<{
    circuitState: string;
    useFallback: boolean;
    fallbackResponse?: {
      status: number;
      headers: Record<string, string>;
      body?: string;
    };
  }> {
    // Create circuit breaker configuration
    const circuitConfig: CircuitBreakerConfig = {
      id: `${this.config.serviceName}_${this.config.upstreamName}`,
      serviceName: this.config.serviceName,
      upstreamName: this.config.upstreamName,
      thresholds: {
        failureThreshold: this.config.failureThreshold,
        failureRateThreshold: this.config.failureRateThreshold,
        slowCallThreshold: this.config.slowCallThreshold,
        slowCallDurationThreshold: this.config.slowCallDurationThreshold,
        minimumThroughput: this.config.minimumThroughput,
      },
      timeouts: {
        initialTimeout: this.config.initialTimeout,
        maxTimeout: this.config.maxTimeout,
        backoffMultiplier: this.config.backoffMultiplier,
        halfOpenMaxCalls: this.config.halfOpenMaxCalls,
      },
      slidingWindow: {
        type: this.config.slidingWindowType,
        size: this.config.slidingWindowSize,
        minimumThroughput: this.config.minimumThroughput,
      },
      fallback: {
        enabled: this.config.fallbackEnabled,
        strategy: this.config.fallbackStrategy,
        cacheEnabled: this.config.cacheEnabled,
        cacheTtl: this.config.cacheTtl,
        alternateService: this.config.alternateService,
        mockResponse: this.config.mockResponse,
      },
      monitoring: {
        enabled: this.config.metricsEnabled,
        metricsRetention: 86400,
        alerting: this.config.alertingEnabled,
        healthCheckInterval: this.config.healthCheckInterval,
      },
      isEnabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    try {
      // Execute through circuit breaker system
      const circuitBreaker = await this.circuitBreakerSystem.getCircuitBreaker(circuitConfig);
      const stats = circuitBreaker.getStats();
      
      // Simulate the operation result for circuit breaker tracking
      const operationResult = await circuitBreaker.execute(
        async () => {
          if (!success) {
            const error = new Error(`Upstream failed with status ${upstreamResponse.status}`);
            (error as any).statusCode = upstreamResponse.status;
            throw error;
          }
          return upstreamResponse;
        },
        // Fallback operation
        async () => {
          return this.generateFallbackResponse();
        }
      );

      // Determine if we should use fallback
      const shouldUseFallback = stats.state === CircuitBreakerState.OPEN || 
                               (stats.state === CircuitBreakerState.HALF_OPEN && !success);

      if (shouldUseFallback) {
        const fallbackResponse = this.generateFallbackResponse();
        return {
          circuitState: stats.state,
          useFallback: true,
          fallbackResponse: {
            status: fallbackResponse.status,
            headers: fallbackResponse.headers,
            body: fallbackResponse.body,
          },
        };
      }

      return {
        circuitState: stats.state,
        useFallback: false,
      };

    } catch (error) {
      this.logger.error('Circuit breaker execution failed', {
        component: 'KongCircuitBreakerPlugin',
        service: this.config.serviceName,
        error: error.message,
      });

      // Default fallback on error
      if (this.config.fallbackEnabled) {
        const fallbackResponse = this.generateFallbackResponse();
        return {
          circuitState: CircuitBreakerState.OPEN,
          useFallback: true,
          fallbackResponse: {
            status: fallbackResponse.status,
            headers: fallbackResponse.headers,
            body: fallbackResponse.body,
          },
        };
      }

      throw error;
    }
  }

  /**
   * Generate fallback response based on configuration
   */
  private generateFallbackResponse(): {
    status: number;
    headers: Record<string, string>;
    body: string;
  } {
    const fallbackBody = this.config.fallbackBody || JSON.stringify({
      error: `Service ${this.config.serviceName} is temporarily unavailable`,
      message: 'Circuit breaker is protecting the service. Please try again later.',
      service: this.config.serviceName,
      timestamp: new Date().toISOString(),
      retry_after: Math.floor(this.config.initialTimeout / 1000),
    });

    return {
      status: this.config.fallbackStatusCode,
      headers: {
        ...this.config.fallbackHeaders,
        'X-Circuit-Breaker-Service': this.config.serviceName,
        'X-Circuit-Breaker-Timestamp': new Date().toISOString(),
      },
      body: fallbackBody,
    };
  }

  /**
   * Determine if response status indicates success
   */
  private isSuccessfulResponse(status: number): boolean {
    return status >= 200 && status < 400;
  }

  /**
   * Initialize metrics collection
   */
  private initializeMetrics(): void {
    this.metrics.set('total_requests', 0);
    this.metrics.set('successful_requests', 0);
    this.metrics.set('failed_requests', 0);
    this.metrics.set('circuit_breaker_open_count', 0);
    this.metrics.set('circuit_breaker_half_open_count', 0);
    this.metrics.set('fallback_responses', 0);
    this.metrics.set('average_response_time', 0);
  }

  /**
   * Update metrics with request result
   */
  private updateMetrics(circuitState: string, success: boolean, duration: number): void {
    const totalRequests = this.metrics.get('total_requests') + 1;
    this.metrics.set('total_requests', totalRequests);

    if (success) {
      this.metrics.set('successful_requests', this.metrics.get('successful_requests') + 1);
    } else {
      this.metrics.set('failed_requests', this.metrics.get('failed_requests') + 1);
    }

    if (circuitState === CircuitBreakerState.OPEN) {
      this.metrics.set('circuit_breaker_open_count', this.metrics.get('circuit_breaker_open_count') + 1);
    } else if (circuitState === CircuitBreakerState.HALF_OPEN) {
      this.metrics.set('circuit_breaker_half_open_count', this.metrics.get('circuit_breaker_half_open_count') + 1);
    }

    // Update average response time
    const currentAvg = this.metrics.get('average_response_time');
    const newAvg = ((currentAvg * (totalRequests - 1)) + duration) / totalRequests;
    this.metrics.set('average_response_time', newAvg);
  }

  /**
   * Generate unique request ID
   */
  private generateRequestId(): string {
    return `cb_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get plugin metrics for monitoring
   */
  getMetrics(): Record<string, any> {
    const metricsObj: Record<string, any> = {};
    for (const [key, value] of this.metrics.entries()) {
      metricsObj[key] = value;
    }
    return {
      service: this.config.serviceName,
      upstream: this.config.upstreamName,
      metrics: metricsObj,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Health check for circuit breaker plugin
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    status: string;
    details: Record<string, any>;
  }> {
    try {
      // Check circuit breaker system health
      const systemHealth = this.circuitBreakerSystem.getSystemHealth();
      
      const isHealthy = systemHealth.status !== 'critical';
      
      return {
        healthy: isHealthy,
        status: systemHealth.status,
        details: {
          service: this.config.serviceName,
          upstream: this.config.upstreamName,
          systemHealth,
          metrics: this.getMetrics(),
          timestamp: new Date().toISOString(),
        },
      };
    } catch (error) {
      return {
        healthy: false,
        status: 'error',
        details: {
          service: this.config.serviceName,
          upstream: this.config.upstreamName,
          error: error.message,
          timestamp: new Date().toISOString(),
        },
      };
    }
  }
}

/**
 * Kong Circuit Breaker Plugin Manager
 */
export class KongCircuitBreakerPluginManager {
  private circuitBreakerSystem: IntelligentCircuitBreakerSystem;
  private logger: Logger;
  private plugins: Map<string, KongCircuitBreakerPlugin> = new Map();

  constructor(circuitBreakerSystem: IntelligentCircuitBreakerSystem, logger: Logger) {
    this.circuitBreakerSystem = circuitBreakerSystem;
    this.logger = logger;
  }

  /**
   * Create Kong circuit breaker plugin for service
   */
  async createPlugin(config: KongCircuitBreakerPluginConfig): Promise<KongCircuitBreakerPlugin> {
    const validatedConfig = KongCircuitBreakerPluginConfigSchema.parse(config);
    const pluginKey = `${validatedConfig.service.id}_${validatedConfig.config.serviceName}`;

    const plugin = new KongCircuitBreakerPlugin(
      this.circuitBreakerSystem,
      this.logger,
      validatedConfig.config
    );

    this.plugins.set(pluginKey, plugin);

    this.logger.info('Kong circuit breaker plugin created', {
      component: 'KongCircuitBreakerPluginManager',
      service: validatedConfig.config.serviceName,
      upstream: validatedConfig.config.upstreamName,
      pluginKey,
    });

    return plugin;
  }

  /**
   * Get plugin by service
   */
  getPlugin(serviceId: string, serviceName: string): KongCircuitBreakerPlugin | undefined {
    const pluginKey = `${serviceId}_${serviceName}`;
    return this.plugins.get(pluginKey);
  }

  /**
   * Remove plugin
   */
  async removePlugin(serviceId: string, serviceName: string): Promise<boolean> {
    const pluginKey = `${serviceId}_${serviceName}`;
    const removed = this.plugins.delete(pluginKey);

    if (removed) {
      this.logger.info('Kong circuit breaker plugin removed', {
        component: 'KongCircuitBreakerPluginManager',
        service: serviceName,
        pluginKey,
      });
    }

    return removed;
  }

  /**
   * Get all plugin metrics
   */
  getAllMetrics(): Record<string, any> {
    const allMetrics: Record<string, any> = {};
    
    for (const [pluginKey, plugin] of this.plugins.entries()) {
      allMetrics[pluginKey] = plugin.getMetrics();
    }

    return allMetrics;
  }

  /**
   * Perform health check on all plugins
   */
  async healthCheckAll(): Promise<Record<string, any>> {
    const healthChecks: Record<string, any> = {};
    
    for (const [pluginKey, plugin] of this.plugins.entries()) {
      healthChecks[pluginKey] = await plugin.healthCheck();
    }

    return healthChecks;
  }

  /**
   * Initialize plugins for iSECTECH services
   */
  async initializeISECTECHPlugins(): Promise<void> {
    const circuitBreakerConfigs = isectechCircuitBreakerManager.getAllCircuitBreakerConfigs();

    for (const [serviceName, config] of circuitBreakerConfigs) {
      const pluginConfig: KongCircuitBreakerPluginConfig = {
        name: 'isectech-circuit-breaker',
        service: {
          id: config.serviceName,
          name: config.serviceName,
        },
        config: {
          serviceName: config.serviceName,
          upstreamName: config.upstreamCluster,
          failureThreshold: config.thresholds.consecutiveFailures,
          failureRateThreshold: config.thresholds.errorThreshold / 100,
          slowCallThreshold: config.thresholds.slowCallPercentage,
          slowCallDurationThreshold: config.thresholds.slowCallThreshold,
          minimumThroughput: config.windowConfig.minimumNumberOfCalls,
          initialTimeout: config.stateTransition.openToHalfOpenDelay * 1000,
          maxTimeout: config.stateTransition.openToHalfOpenDelay * 5 * 1000,
          backoffMultiplier: 2,
          halfOpenMaxCalls: config.stateTransition.halfOpenMaxCalls,
          slidingWindowType: config.windowConfig.slidingWindowType === 'COUNT_BASED' ? 'COUNT_BASED' : 'TIME_BASED',
          slidingWindowSize: config.windowConfig.slidingWindowSize,
          fallbackEnabled: config.fallbackConfig.enabled,
          fallbackStrategy: 'FAIL_FAST',
          cacheEnabled: true,
          cacheTtl: 300,
          fallbackStatusCode: config.fallbackConfig.fallbackResponse.statusCode,
          fallbackBody: config.fallbackConfig.fallbackResponse.body,
          fallbackHeaders: config.fallbackConfig.fallbackResponse.headers,
          metricsEnabled: config.monitoring.metricsEnabled,
          alertingEnabled: config.monitoring.alertingEnabled,
          healthCheckInterval: 30000,
        },
        enabled: true,
        tags: config.tags,
      };

      await this.createPlugin(pluginConfig);
    }

    this.logger.info('All iSECTECH circuit breaker plugins initialized', {
      component: 'KongCircuitBreakerPluginManager',
      pluginCount: this.plugins.size,
    });
  }
}

// Export types and schemas
export { KongCircuitBreakerPluginConfigSchema };
export type { KongCircuitBreakerPluginConfig, KongRequestContext, KongUpstreamResponse };