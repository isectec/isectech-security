/**
 * Kong IP Protection Plugin Integration for iSECTECH
 * 
 * Custom Kong plugin that integrates with the Intelligent IP Protection System
 * to provide comprehensive IP-based security controls at the gateway level.
 * 
 * Features:
 * - Real-time IP evaluation with sub-millisecond response times
 * - Seamless Kong integration with proper error handling
 * - Configurable protection levels and response strategies
 * - Advanced logging and monitoring integration
 */

import { IntelligentIPProtectionSystem, IPProtectionConfig } from './intelligent-ip-protection-system';
import { Logger } from 'winston';
import { z } from 'zod';

// Kong plugin configuration schema
const KongIPProtectionConfigSchema = z.object({
  enabled: z.boolean().default(true),
  protection: z.object({
    mode: z.enum(['MONITOR', 'ENFORCE']).default('ENFORCE'),
    failOpen: z.boolean().default(true),
    responseHeaders: z.boolean().default(true),
    logLevel: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR']).default('INFO'),
  }),
  performance: z.object({
    timeout: z.number().default(100), // milliseconds
    cacheEnabled: z.boolean().default(true),
    cacheTtl: z.number().default(300), // seconds
    batchSize: z.number().default(1000),
  }),
  responses: z.object({
    block: z.object({
      status: z.number().default(403),
      message: z.string().default('Access denied by IP protection'),
      headers: z.record(z.string()).default({
        'X-Protection-Policy': 'IP-BLOCKED',
        'Retry-After': '300',
      }),
    }),
    challenge: z.object({
      status: z.number().default(429),
      message: z.string().default('Additional verification required'),
      headers: z.record(z.string()).default({
        'X-Protection-Policy': 'IP-CHALLENGE',
        'X-Challenge-Type': 'CAPTCHA',
      }),
    }),
  }),
  monitoring: z.object({
    metricsEnabled: z.boolean().default(true),
    detailedLogging: z.boolean().default(false),
    alertThresholds: z.object({
      blockRate: z.number().default(10), // blocks per minute
      errorRate: z.number().default(5), // errors per minute
    }),
  }),
});

type KongIPProtectionConfig = z.infer<typeof KongIPProtectionConfigSchema>;

interface KongRequest {
  get_ip(): string;
  get_header(name: string): string | null;
  get_headers(): Record<string, string>;
  get_uri(): string;
  get_method(): string;
}

interface KongResponse {
  exit(status: number, body?: string, headers?: Record<string, string>): void;
  set_header(name: string, value: string): void;
}

interface KongContext {
  request: KongRequest;
  response: KongResponse;
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
}

/**
 * Kong IP Protection Plugin for comprehensive IP-based security
 */
export class KongIPProtectionPlugin {
  private protectionSystem: IntelligentIPProtectionSystem;
  private config: KongIPProtectionConfig;
  private logger: Logger;
  private performanceMetrics: Map<string, number> = new Map();
  private lastMetricsReset: number = Date.now();

  constructor(
    protectionSystem: IntelligentIPProtectionSystem,
    config: KongIPProtectionConfig,
    logger: Logger
  ) {
    this.protectionSystem = protectionSystem;
    this.config = KongIPProtectionConfigSchema.parse(config);
    this.logger = logger;

    this.startMetricsCollection();
  }

  /**
   * Kong access phase handler - main entry point for IP protection
   */
  async access(kong: KongContext): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    const startTime = Date.now();
    const clientIP = this.extractClientIP(kong);
    
    if (!clientIP) {
      kong.log.warn('Unable to extract client IP address');
      return;
    }

    try {
      // Check cache first for performance
      const cacheKey = `ip_decision:${clientIP}`;
      let decision = null;

      if (this.config.performance.cacheEnabled) {
        decision = kong.shared.get(cacheKey);
      }

      // Evaluate IP protection if not cached
      if (!decision) {
        const timeout = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('IP protection timeout')), 
            this.config.performance.timeout);
        });

        const evaluationPromise = this.protectionSystem.evaluateIPProtection(
          clientIP,
          kong.request.get_header('User-Agent'),
          kong.request.get_headers()
        );

        decision = await Promise.race([evaluationPromise, timeout]);

        // Cache the decision
        if (this.config.performance.cacheEnabled) {
          kong.shared.set(cacheKey, decision);
          // Set expiry (Kong shared dict doesn't support TTL directly)
          setTimeout(() => kong.shared.set(cacheKey, null), 
            this.config.performance.cacheTtl * 1000);
        }
      }

      // Handle the decision
      await this.handleProtectionDecision(kong, clientIP, decision);

      // Record performance metrics
      const duration = Date.now() - startTime;
      this.recordPerformanceMetric('decision_time', duration);

    } catch (error) {
      const duration = Date.now() - startTime;
      this.recordPerformanceMetric('error_count', 1);
      
      kong.log.err(`IP protection error for ${clientIP}: ${error.message}`);

      if (this.config.protection.failOpen) {
        // Fail open - allow request to continue
        if (this.config.protection.responseHeaders) {
          kong.response.set_header('X-Protection-Status', 'ERROR');
          kong.response.set_header('X-Protection-Error', 'IP_PROTECTION_ERROR');
        }
        return;
      } else {
        // Fail closed - block request
        kong.response.exit(500, 'IP protection service unavailable', {
          'X-Protection-Status': 'ERROR',
          'Retry-After': '60',
        });
      }
    }
  }

  /**
   * Handle protection decision and respond appropriately
   */
  private async handleProtectionDecision(
    kong: KongContext, 
    clientIP: string, 
    decision: any
  ): Promise<void> {
    const action = decision.action;
    const timestamp = new Date().toISOString();

    // Set common response headers
    if (this.config.protection.responseHeaders) {
      kong.response.set_header('X-Protection-Status', action);
      kong.response.set_header('X-Protection-Score', decision.score.toString());
      kong.response.set_header('X-Protection-Timestamp', timestamp);
    }

    switch (action) {
      case 'DENY':
        this.recordPerformanceMetric('blocked_requests', 1);
        
        // Log the block
        kong.log.warn(`IP blocked: ${clientIP} - ${decision.reason}`);

        if (this.config.protection.mode === 'ENFORCE') {
          // Add additional headers for blocked requests
          const blockHeaders = {
            ...this.config.responses.block.headers,
            'X-Protection-Reason': decision.reason,
            'X-Protection-Rule': decision.ruleId || 'UNKNOWN',
            'X-Client-IP': clientIP,
          };

          kong.response.exit(
            this.config.responses.block.status,
            this.config.responses.block.message,
            blockHeaders
          );
        } else {
          // Monitor mode - log but allow
          kong.response.set_header('X-Protection-Mode', 'MONITOR');
          kong.response.set_header('X-Protection-Would-Block', 'true');
        }
        break;

      case 'CHALLENGE':
        this.recordPerformanceMetric('challenged_requests', 1);
        
        kong.log.info(`IP challenged: ${clientIP} - ${decision.reason}`);

        if (this.config.protection.mode === 'ENFORCE') {
          const challengeHeaders = {
            ...this.config.responses.challenge.headers,
            'X-Protection-Reason': decision.reason,
            'X-Protection-Score': decision.score.toString(),
            'X-Client-IP': clientIP,
          };

          kong.response.exit(
            this.config.responses.challenge.status,
            this.config.responses.challenge.message,
            challengeHeaders
          );
        } else {
          // Monitor mode - log but allow
          kong.response.set_header('X-Protection-Mode', 'MONITOR');
          kong.response.set_header('X-Protection-Would-Challenge', 'true');
        }
        break;

      case 'ALLOW':
      default:
        this.recordPerformanceMetric('allowed_requests', 1);
        
        if (this.config.monitoring.detailedLogging) {
          kong.log.debug(`IP allowed: ${clientIP} - ${decision.reason}`);
        }

        if (this.config.protection.responseHeaders) {
          kong.response.set_header('X-Protection-Reason', decision.reason);
        }
        break;
    }

    // Record metadata if available
    if (decision.metadata && this.config.protection.responseHeaders) {
      if (decision.metadata.country) {
        kong.response.set_header('X-Client-Country', decision.metadata.country);
      }
      if (decision.metadata.reputation !== undefined) {
        kong.response.set_header('X-Client-Reputation', decision.metadata.reputation.toString());
      }
      if (decision.metadata.temporaryBan) {
        kong.response.set_header('X-Protection-Temp-Ban', 'true');
      }
    }
  }

  /**
   * Extract client IP from request, handling proxies and load balancers
   */
  private extractClientIP(kong: KongContext): string | null {
    // Check for IP in standard proxy headers (ordered by preference)
    const proxyHeaders = [
      'CF-Connecting-IP',        // Cloudflare
      'X-Forwarded-For',         // Standard proxy header
      'X-Real-IP',               // Nginx proxy
      'X-Client-IP',             // Apache/IIS
      'X-Cluster-Client-IP',     // Cluster environments
      'Forwarded',               // RFC 7239
    ];

    for (const header of proxyHeaders) {
      const value = kong.request.get_header(header);
      if (value) {
        // Handle comma-separated IPs (X-Forwarded-For)
        const ip = value.split(',')[0].trim();
        if (this.isValidIP(ip)) {
          return ip;
        }
      }
    }

    // Fallback to Kong's native IP detection
    const directIP = kong.request.get_ip();
    return this.isValidIP(directIP) ? directIP : null;
  }

  /**
   * Validate IP address format
   */
  private isValidIP(ip: string): boolean {
    if (!ip) return false;

    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      return ip.split('.').every(octet => {
        const num = parseInt(octet, 10);
        return num >= 0 && num <= 255;
      });
    }

    // IPv6 validation (simplified)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv6Regex.test(ip);
  }

  /**
   * Record performance metrics
   */
  private recordPerformanceMetric(metric: string, value: number): void {
    if (!this.config.monitoring.metricsEnabled) return;

    const current = this.performanceMetrics.get(metric) || 0;
    this.performanceMetrics.set(metric, current + value);
  }

  /**
   * Start periodic metrics collection and alerting
   */
  private startMetricsCollection(): void {
    if (!this.config.monitoring.metricsEnabled) return;

    setInterval(() => {
      this.collectAndReportMetrics();
    }, 60000); // Every minute
  }

  /**
   * Collect and report metrics, trigger alerts if needed
   */
  private collectAndReportMetrics(): void {
    try {
      const now = Date.now();
      const timeSinceReset = (now - this.lastMetricsReset) / 1000; // seconds

      const metrics = {
        timestamp: now,
        period: timeSinceReset,
        requests: {
          allowed: this.performanceMetrics.get('allowed_requests') || 0,
          blocked: this.performanceMetrics.get('blocked_requests') || 0,
          challenged: this.performanceMetrics.get('challenged_requests') || 0,
        },
        performance: {
          averageDecisionTime: this.performanceMetrics.get('decision_time') || 0,
          errorCount: this.performanceMetrics.get('error_count') || 0,
        },
      };

      // Calculate rates
      const blockRate = (metrics.requests.blocked / timeSinceReset) * 60; // per minute
      const errorRate = (metrics.performance.errorCount / timeSinceReset) * 60; // per minute

      // Log metrics
      this.logger.info('IP Protection Plugin Metrics', {
        component: 'KongIPProtectionPlugin',
        metrics,
        rates: { blockRate, errorRate },
      });

      // Check alert thresholds
      if (blockRate > this.config.monitoring.alertThresholds.blockRate) {
        this.logger.warn('High IP block rate detected', {
          component: 'KongIPProtectionPlugin',
          blockRate,
          threshold: this.config.monitoring.alertThresholds.blockRate,
        });
      }

      if (errorRate > this.config.monitoring.alertThresholds.errorRate) {
        this.logger.error('High IP protection error rate detected', {
          component: 'KongIPProtectionPlugin',
          errorRate,
          threshold: this.config.monitoring.alertThresholds.errorRate,
        });
      }

      // Reset metrics
      this.performanceMetrics.clear();
      this.lastMetricsReset = now;

    } catch (error) {
      this.logger.error('Error collecting IP protection metrics', {
        component: 'KongIPProtectionPlugin',
        error: error.message,
      });
    }
  }

  /**
   * Get current plugin status and statistics
   */
  getStatus(): {
    enabled: boolean;
    mode: string;
    metrics: Record<string, number>;
    lastReset: number;
  } {
    return {
      enabled: this.config.enabled,
      mode: this.config.protection.mode,
      metrics: Object.fromEntries(this.performanceMetrics),
      lastReset: this.lastMetricsReset,
    };
  }

  /**
   * Update plugin configuration dynamically
   */
  updateConfig(newConfig: Partial<KongIPProtectionConfig>): void {
    this.config = KongIPProtectionConfigSchema.parse({
      ...this.config,
      ...newConfig,
    });

    this.logger.info('IP Protection Plugin configuration updated', {
      component: 'KongIPProtectionPlugin',
      config: newConfig,
    });
  }

  /**
   * Cleanup and shutdown
   */
  shutdown(): void {
    this.performanceMetrics.clear();
    this.logger.info('Kong IP Protection Plugin shutdown completed');
  }
}

// Kong plugin factory function
export function createKongIPProtectionPlugin(
  protectionSystem: IntelligentIPProtectionSystem,
  config: KongIPProtectionConfig,
  logger: Logger
): KongIPProtectionPlugin {
  return new KongIPProtectionPlugin(protectionSystem, config, logger);
}

// Export schemas
export { KongIPProtectionConfigSchema };
export type { KongIPProtectionConfig };