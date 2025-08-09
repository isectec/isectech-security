/**
 * Kong Traffic Management Plugin for iSECTECH
 * 
 * Kong plugin integration for intelligent traffic management system providing
 * real-time routing decisions, A/B testing, canary deployments, and traffic mirroring.
 */

import { IntelligentTrafficManager, RequestContext, RoutingDecision } from './intelligent-traffic-manager';
import { Logger } from 'winston';
import { z } from 'zod';

const KongTrafficPluginConfigSchema = z.object({
  enabled: z.boolean().default(true),
  trafficManager: z.object({
    timeout: z.number().default(50), // milliseconds
    cacheEnabled: z.boolean().default(true),
    cacheTtl: z.number().default(60), // seconds
  }),
  routing: z.object({
    headerPassthrough: z.boolean().default(true),
    upstreamHeaders: z.object({
      segment: z.string().default('X-Traffic-Segment'),
      abTest: z.string().default('X-AB-Test'),
      canary: z.string().default('X-Canary-Deployment'),
      mirror: z.string().default('X-Traffic-Mirror'),
    }),
  }),
  monitoring: z.object({
    metricsEnabled: z.boolean().default(true),
    responseHeaders: z.boolean().default(true),
    detailedLogging: z.boolean().default(false),
  }),
  fallback: z.object({
    behavior: z.enum(['CONTINUE', 'ERROR', 'DEFAULT_UPSTREAM']).default('DEFAULT_UPSTREAM'),
    defaultUpstream: z.string().default('default'),
  }),
});

type KongTrafficPluginConfig = z.infer<typeof KongTrafficPluginConfigSchema>;

interface KongRequest {
  get_ip(): string;
  get_method(): string;
  get_path(): string;
  get_header(name: string): string | null;
  get_headers(): Record<string, string>;
  get_query(): Record<string, string>;
}

interface KongResponse {
  set_header(name: string, value: string): void;
  exit(status: number, body?: string, headers?: Record<string, string>): void;
}

interface KongUpstream {
  set_target(host: string, port?: number): void;
  set_upstream(upstream: string): void;
}

interface KongContext {
  request: KongRequest;
  response: KongResponse;
  upstream: KongUpstream;
  log: {
    debug(message: string): void;
    info(message: string): void;
    warn(message: string): void;
    err(message: string): void;
  };
  shared: {
    get(key: string): any;
    set(key: string, value: any): void;
  };
  ctx: {
    set(key: string, value: any): void;
    get(key: string): any;
  };
}

/**
 * Kong Traffic Management Plugin
 */
export class KongTrafficManagementPlugin {
  private trafficManager: IntelligentTrafficManager;
  private config: KongTrafficPluginConfig;
  private logger: Logger;
  private performanceMetrics: Map<string, number> = new Map();
  private lastMetricsReset: number = Date.now();

  constructor(
    trafficManager: IntelligentTrafficManager,
    config: KongTrafficPluginConfig,
    logger: Logger
  ) {
    this.trafficManager = trafficManager;
    this.config = KongTrafficPluginConfigSchema.parse(config);
    this.logger = logger;

    this.startMetricsCollection();
  }

  /**
   * Kong access phase handler
   */
  async access(kong: KongContext): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    const startTime = Date.now();
    
    try {
      // Extract request context
      const context = this.extractRequestContext(kong);
      
      // Get routing decision from traffic manager
      const decision = await this.getRoutingDecision(kong, context);
      
      // Apply routing decision
      await this.applyRoutingDecision(kong, decision);
      
      // Set response headers if enabled
      if (this.config.monitoring.responseHeaders) {
        this.setResponseHeaders(kong, decision);
      }

      // Record metrics
      const duration = Date.now() - startTime;
      this.recordMetric('routing_decisions', 1);
      this.recordMetric('processing_time', duration);
      
      if (this.config.monitoring.detailedLogging) {
        this.logger.debug('Traffic routing completed', {
          component: 'KongTrafficManagementPlugin',
          ip: context.ip,
          path: context.path,
          upstream: decision.upstream,
          reason: decision.reason,
          processingTime: duration,
        });
      }

    } catch (error) {
      const duration = Date.now() - startTime;
      this.recordMetric('routing_errors', 1);
      this.recordMetric('error_processing_time', duration);
      
      kong.log.err(`Traffic management error: ${error.message}`);
      
      // Handle fallback behavior
      await this.handleRoutingError(kong, error);
    }
  }

  /**
   * Kong rewrite phase handler for upstream modifications
   */
  async rewrite(kong: KongContext): Promise<void> {
    try {
      const routingDecision = kong.ctx.get('traffic_routing_decision');
      if (!routingDecision) return;

      // Set upstream based on routing decision
      if (routingDecision.upstream !== 'default') {
        kong.upstream.set_upstream(routingDecision.upstream);
      }

      // Handle traffic mirroring if needed
      if (routingDecision.mirror && routingDecision.metadata?.mirrorTargets) {
        // Store mirror targets for header phase processing
        kong.ctx.set('mirror_targets', routingDecision.metadata.mirrorTargets);
      }

    } catch (error) {
      kong.log.err(`Error in rewrite phase: ${error.message}`);
    }
  }

  /**
   * Kong header_filter phase handler
   */
  async headerFilter(kong: KongContext): Promise<void> {
    try {
      const routingDecision = kong.ctx.get('traffic_routing_decision');
      if (!routingDecision) return;

      // Pass through traffic management headers to upstream
      if (this.config.routing.headerPassthrough) {
        const headers = this.config.routing.upstreamHeaders;
        
        if (routingDecision.segment) {
          kong.response.set_header(headers.segment, routingDecision.segment);
        }
        
        if (routingDecision.abTest) {
          kong.response.set_header(headers.abTest, routingDecision.abTest);
        }
        
        if (routingDecision.canary) {
          kong.response.set_header(headers.canary, 'true');
        }
        
        if (routingDecision.mirror) {
          kong.response.set_header(headers.mirror, 'true');
        }
      }

    } catch (error) {
      kong.log.err(`Error in header_filter phase: ${error.message}`);
    }
  }

  /**
   * Kong log phase handler for analytics
   */
  async log(kong: KongContext): Promise<void> {
    try {
      const routingDecision = kong.ctx.get('traffic_routing_decision');
      if (!routingDecision) return;

      // Record analytics data
      const context = this.extractRequestContext(kong);
      const responseTime = kong.ctx.get('response_time') || 0;
      const statusCode = kong.ctx.get('status_code') || 200;

      // Send to traffic manager for analytics
      await this.recordRoutingAnalytics(context, routingDecision, responseTime, statusCode);

    } catch (error) {
      kong.log.err(`Error in log phase: ${error.message}`);
    }
  }

  /**
   * Extract request context from Kong
   */
  private extractRequestContext(kong: KongContext): RequestContext {
    const headers = kong.request.get_headers();
    const queryParams = kong.request.get_query();

    return {
      ip: this.extractClientIP(kong),
      method: kong.request.get_method(),
      path: kong.request.get_path(),
      headers: headers,
      queryParams: queryParams,
      userAgent: headers['user-agent'],
      userId: headers['x-user-id'] || headers['authorization']?.split(' ')[1], // JWT or custom
      sessionId: headers['x-session-id'] || headers['cookie']?.match(/session_id=([^;]+)/)?.[1],
      country: headers['cf-ipcountry'] || headers['x-country'], // Cloudflare or custom
    };
  }

  /**
   * Get routing decision with caching and error handling
   */
  private async getRoutingDecision(kong: KongContext, context: RequestContext): Promise<RoutingDecision> {
    // Check cache first
    const cacheKey = this.generateCacheKey(context);
    
    if (this.config.trafficManager.cacheEnabled) {
      const cached = kong.shared.get(cacheKey);
      if (cached) {
        this.recordMetric('cache_hits', 1);
        return JSON.parse(cached);
      }
    }

    // Get decision with timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error('Traffic manager timeout')), 
        this.config.trafficManager.timeout);
    });

    const routingPromise = this.trafficManager.routeRequest(context);
    
    try {
      const decision = await Promise.race([routingPromise, timeoutPromise]);
      
      // Cache the decision
      if (this.config.trafficManager.cacheEnabled) {
        kong.shared.set(cacheKey, JSON.stringify(decision));
        // Set expiry (Kong shared dict doesn't support TTL directly)
        setTimeout(() => kong.shared.set(cacheKey, null), 
          this.config.trafficManager.cacheTtl * 1000);
      }
      
      this.recordMetric('cache_misses', 1);
      return decision;
      
    } catch (error) {
      if (error.message === 'Traffic manager timeout') {
        this.recordMetric('timeouts', 1);
      }
      throw error;
    }
  }

  /**
   * Apply routing decision to Kong context
   */
  private async applyRoutingDecision(kong: KongContext, decision: RoutingDecision): Promise<void> {
    // Store decision in context for later phases
    kong.ctx.set('traffic_routing_decision', decision);
    
    // Set upstream if not default
    if (decision.upstream && decision.upstream !== 'default') {
      // The actual upstream setting happens in rewrite phase
      kong.ctx.set('target_upstream', decision.upstream);
    }

    // Handle A/B test tracking
    if (decision.abTest) {
      kong.ctx.set('ab_test_id', decision.abTest);
      
      // Set cookie for consistent assignment (if not already set)
      const existingCookie = kong.request.get_header('cookie');
      if (!existingCookie?.includes(`ab_test_${decision.abTest}`)) {
        kong.response.set_header('Set-Cookie', 
          `ab_test_${decision.abTest}=1; Path=/; HttpOnly; SameSite=Strict`);
      }
    }

    // Handle canary deployment tracking
    if (decision.canary) {
      kong.ctx.set('canary_deployment', true);
      kong.response.set_header('X-Deployment-Type', 'canary');
    }
  }

  /**
   * Set response headers for monitoring and debugging
   */
  private setResponseHeaders(kong: KongContext, decision: RoutingDecision): void {
    kong.response.set_header('X-Traffic-Manager', 'active');
    kong.response.set_header('X-Upstream-Target', decision.upstream);
    kong.response.set_header('X-Routing-Reason', decision.reason);
    
    if (decision.segment) {
      kong.response.set_header('X-Traffic-Segment', decision.segment);
    }
    
    if (decision.abTest) {
      kong.response.set_header('X-AB-Test-Active', decision.abTest);
    }
    
    if (decision.canary) {
      kong.response.set_header('X-Canary-Active', 'true');
    }
    
    if (decision.mirror) {
      kong.response.set_header('X-Traffic-Mirrored', 'true');
    }
    
    if (decision.metadata?.processingTime) {
      kong.response.set_header('X-Routing-Time', decision.metadata.processingTime.toString());
    }
  }

  /**
   * Handle routing errors with fallback behavior
   */
  private async handleRoutingError(kong: KongContext, error: Error): Promise<void> {
    switch (this.config.fallback.behavior) {
      case 'CONTINUE':
        // Continue with default Kong behavior
        this.logger.warn('Traffic management error, continuing with default behavior', {
          component: 'KongTrafficManagementPlugin',
          error: error.message,
        });
        break;
        
      case 'ERROR':
        // Return error to client
        kong.response.exit(500, 'Traffic management service unavailable', {
          'X-Traffic-Manager-Error': error.message,
          'Retry-After': '5',
        });
        break;
        
      case 'DEFAULT_UPSTREAM':
      default:
        // Route to default upstream
        kong.ctx.set('traffic_routing_decision', {
          upstream: this.config.fallback.defaultUpstream,
          reason: `Fallback due to error: ${error.message}`,
          metadata: { fallback: true, error: error.message },
        });
        break;
    }
  }

  /**
   * Record routing analytics
   */
  private async recordRoutingAnalytics(
    context: RequestContext,
    decision: RoutingDecision,
    responseTime: number,
    statusCode: number
  ): Promise<void> {
    try {
      // This would typically send data to analytics system
      const analyticsData = {
        timestamp: Date.now(),
        context,
        decision,
        responseTime,
        statusCode,
        success: statusCode < 400,
      };

      // Log for external analytics systems
      if (this.config.monitoring.detailedLogging) {
        this.logger.info('Traffic routing analytics', {
          component: 'KongTrafficManagementPlugin',
          analytics: analyticsData,
        });
      }

    } catch (error) {
      this.logger.error('Error recording routing analytics', {
        component: 'KongTrafficManagementPlugin',
        error: error.message,
      });
    }
  }

  /**
   * Extract client IP handling proxies
   */
  private extractClientIP(kong: KongContext): string {
    const proxyHeaders = [
      'CF-Connecting-IP',
      'X-Forwarded-For',
      'X-Real-IP',
      'X-Client-IP',
    ];

    for (const header of proxyHeaders) {
      const value = kong.request.get_header(header);
      if (value) {
        return value.split(',')[0].trim();
      }
    }

    return kong.request.get_ip();
  }

  /**
   * Generate cache key for routing decisions
   */
  private generateCacheKey(context: RequestContext): string {
    // Simple cache key based on request characteristics
    return `traffic_routing:${context.method}:${context.path}:${context.ip}:${context.userId || 'anonymous'}`;
  }

  /**
   * Record performance metrics
   */
  private recordMetric(metric: string, value: number): void {
    if (!this.config.monitoring.metricsEnabled) return;
    
    const current = this.performanceMetrics.get(metric) || 0;
    this.performanceMetrics.set(metric, current + value);
  }

  /**
   * Start metrics collection and reporting
   */
  private startMetricsCollection(): void {
    if (!this.config.monitoring.metricsEnabled) return;

    setInterval(() => {
      this.collectAndReportMetrics();
    }, 60000); // Every minute
  }

  /**
   * Collect and report metrics
   */
  private collectAndReportMetrics(): void {
    try {
      const now = Date.now();
      const timeSinceReset = (now - this.lastMetricsReset) / 1000; // seconds

      const metrics = {
        timestamp: now,
        period: timeSinceReset,
        routing: {
          decisions: this.performanceMetrics.get('routing_decisions') || 0,
          errors: this.performanceMetrics.get('routing_errors') || 0,
          timeouts: this.performanceMetrics.get('timeouts') || 0,
        },
        cache: {
          hits: this.performanceMetrics.get('cache_hits') || 0,
          misses: this.performanceMetrics.get('cache_misses') || 0,
        },
        performance: {
          avgProcessingTime: this.performanceMetrics.get('processing_time') || 0,
          avgErrorTime: this.performanceMetrics.get('error_processing_time') || 0,
        },
      };

      // Calculate rates
      const decisionRate = (metrics.routing.decisions / timeSinceReset) * 60; // per minute
      const errorRate = (metrics.routing.errors / timeSinceReset) * 60; // per minute
      const cacheHitRate = metrics.cache.hits / (metrics.cache.hits + metrics.cache.misses) * 100;

      this.logger.info('Traffic Management Plugin Metrics', {
        component: 'KongTrafficManagementPlugin',
        metrics,
        rates: { decisionRate, errorRate, cacheHitRate },
      });

      // Check alert thresholds
      if (errorRate > 10) { // More than 10 errors per minute
        this.logger.warn('High traffic management error rate', {
          component: 'KongTrafficManagementPlugin',
          errorRate,
          threshold: 10,
        });
      }

      // Reset metrics
      this.performanceMetrics.clear();
      this.lastMetricsReset = now;

    } catch (error) {
      this.logger.error('Error collecting traffic management metrics', {
        component: 'KongTrafficManagementPlugin',
        error: error.message,
      });
    }
  }

  /**
   * Get plugin status
   */
  getStatus(): {
    enabled: boolean;
    metrics: Record<string, number>;
    lastReset: number;
    config: any;
  } {
    return {
      enabled: this.config.enabled,
      metrics: Object.fromEntries(this.performanceMetrics),
      lastReset: this.lastMetricsReset,
      config: {
        cacheEnabled: this.config.trafficManager.cacheEnabled,
        timeout: this.config.trafficManager.timeout,
        fallbackBehavior: this.config.fallback.behavior,
      },
    };
  }

  /**
   * Update plugin configuration
   */
  updateConfig(newConfig: Partial<KongTrafficPluginConfig>): void {
    this.config = KongTrafficPluginConfigSchema.parse({
      ...this.config,
      ...newConfig,
    });

    this.logger.info('Traffic Management Plugin configuration updated', {
      component: 'KongTrafficManagementPlugin',
      config: newConfig,
    });
  }

  /**
   * Shutdown plugin
   */
  shutdown(): void {
    this.performanceMetrics.clear();
    this.logger.info('Kong Traffic Management Plugin shutdown completed');
  }
}

// Factory function for creating plugin instances
export function createKongTrafficManagementPlugin(
  trafficManager: IntelligentTrafficManager,
  config: KongTrafficPluginConfig,
  logger: Logger
): KongTrafficManagementPlugin {
  return new KongTrafficManagementPlugin(trafficManager, config, logger);
}

export { KongTrafficPluginConfigSchema };
export type { KongTrafficPluginConfig };