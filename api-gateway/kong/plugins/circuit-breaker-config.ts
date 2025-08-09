/**
 * Production-grade Circuit Breaker Configuration for iSECTECH Kong Gateway
 * 
 * Provides comprehensive circuit breaker capabilities to protect backend services
 * from cascading failures and improve overall system resilience.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';

// Circuit Breaker Configuration Schema
export const CircuitBreakerConfigSchema = z.object({
  serviceName: z.string(),
  upstreamCluster: z.string(),
  thresholds: z.object({
    errorThreshold: z.number().min(1).max(100).default(50), // Percentage of errors to trigger open state
    requestThreshold: z.number().min(1).default(10), // Minimum requests before evaluating
    timeoutThreshold: z.number().min(1).default(30), // Seconds to wait before half-open
    consecutiveFailures: z.number().min(1).default(5), // Consecutive failures to trip
    slowCallThreshold: z.number().min(1).default(5000), // Milliseconds to consider slow
    slowCallPercentage: z.number().min(1).max(100).default(50) // Percentage of slow calls to trigger
  }),
  windowConfig: z.object({
    slidingWindowSize: z.number().min(1).default(100), // Number of calls in sliding window
    minimumNumberOfCalls: z.number().min(1).default(10), // Minimum calls before calculation
    slidingWindowType: z.enum(['COUNT_BASED', 'TIME_BASED']).default('COUNT_BASED'),
    recordFailurePredicate: z.array(z.number()).default([500, 502, 503, 504]) // HTTP codes considered failures
  }),
  stateTransition: z.object({
    openToHalfOpenDelay: z.number().min(1).default(30), // Seconds to wait before half-open
    halfOpenMaxCalls: z.number().min(1).default(5), // Max calls allowed in half-open state
    halfOpenSuccessThreshold: z.number().min(1).default(3) // Successful calls to close circuit
  }),
  fallbackConfig: z.object({
    enabled: z.boolean().default(true),
    fallbackResponse: z.object({
      statusCode: z.number().default(503),
      body: z.string().default('{"error": "Service temporarily unavailable", "retry_after": 30}'),
      headers: z.record(z.string()).default({
        'Content-Type': 'application/json',
        'Retry-After': '30',
        'X-Circuit-Breaker': 'OPEN'
      })
    }),
    fallbackPath: z.string().optional() // Optional fallback service endpoint
  }),
  monitoring: z.object({
    metricsEnabled: z.boolean().default(true),
    alertingEnabled: z.boolean().default(true),
    healthCheckEndpoint: z.string().optional(),
    dashboardEnabled: z.boolean().default(true)
  }),
  tags: z.array(z.string()).default(['isectech', 'circuit-breaker', 'resilience'])
});

export type CircuitBreakerConfig = z.infer<typeof CircuitBreakerConfigSchema>;

/**
 * Circuit Breaker State Management
 */
export enum CircuitBreakerState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

export interface CircuitBreakerMetrics {
  state: CircuitBreakerState;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  timeoutRequests: number;
  slowRequests: number;
  errorRate: number;
  averageResponseTime: number;
  lastStateChange: Date;
  uptime: number;
  openCount: number;
  halfOpenCount: number;
}

/**
 * Circuit Breaker Manager for iSECTECH Services
 */
export class ISECTECHCircuitBreakerManager {
  private circuitBreakers: Map<string, CircuitBreakerConfig> = new Map();
  private metricsStore: Map<string, CircuitBreakerMetrics> = new Map();

  constructor() {
    this.initializeISECTECHCircuitBreakers();
  }

  /**
   * Initialize circuit breakers for iSECTECH services
   */
  private initializeISECTECHCircuitBreakers(): void {
    // Asset Discovery Service Circuit Breaker
    const assetDiscoveryCircuitBreaker: CircuitBreakerConfig = {
      serviceName: 'isectech-asset-discovery',
      upstreamCluster: 'isectech-asset-discovery-upstream',
      thresholds: {
        errorThreshold: 40, // Less strict for asset discovery
        requestThreshold: 15,
        timeoutThreshold: 45,
        consecutiveFailures: 5,
        slowCallThreshold: 10000, // 10 seconds for scanning operations
        slowCallPercentage: 60
      },
      windowConfig: {
        slidingWindowSize: 50,
        minimumNumberOfCalls: 10,
        slidingWindowType: 'COUNT_BASED',
        recordFailurePredicate: [500, 502, 503, 504, 408]
      },
      stateTransition: {
        openToHalfOpenDelay: 60, // Longer recovery time for scanning
        halfOpenMaxCalls: 5,
        halfOpenSuccessThreshold: 3
      },
      fallbackConfig: {
        enabled: true,
        fallbackResponse: {
          statusCode: 503,
          body: JSON.stringify({
            error: 'Asset discovery service temporarily unavailable',
            message: 'Please retry in 60 seconds',
            service: 'asset-discovery',
            timestamp: new Date().toISOString()
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '60',
            'X-Circuit-Breaker': 'OPEN',
            'X-Service': 'asset-discovery'
          }
        }
      },
      monitoring: {
        metricsEnabled: true,
        alertingEnabled: true,
        healthCheckEndpoint: '/health/asset-discovery',
        dashboardEnabled: true
      },
      tags: ['isectech', 'asset-discovery', 'circuit-breaker']
    };

    // Threat Detection Service Circuit Breaker (Critical ML Service)
    const threatDetectionCircuitBreaker: CircuitBreakerConfig = {
      serviceName: 'isectech-threat-detection',
      upstreamCluster: 'isectech-threat-detection-upstream',
      thresholds: {
        errorThreshold: 30, // Stricter for critical security service
        requestThreshold: 20,
        timeoutThreshold: 30,
        consecutiveFailures: 3,
        slowCallThreshold: 15000, // 15 seconds for ML processing
        slowCallPercentage: 40
      },
      windowConfig: {
        slidingWindowSize: 100,
        minimumNumberOfCalls: 15,
        slidingWindowType: 'COUNT_BASED',
        recordFailurePredicate: [500, 502, 503, 504, 408, 429]
      },
      stateTransition: {
        openToHalfOpenDelay: 45,
        halfOpenMaxCalls: 3,
        halfOpenSuccessThreshold: 2
      },
      fallbackConfig: {
        enabled: true,
        fallbackResponse: {
          statusCode: 503,
          body: JSON.stringify({
            error: 'Threat detection service temporarily unavailable',
            message: 'Threat analysis is temporarily degraded. Check back in 45 seconds.',
            service: 'threat-detection',
            impact: 'Security analysis may be delayed',
            timestamp: new Date().toISOString()
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '45',
            'X-Circuit-Breaker': 'OPEN',
            'X-Service': 'threat-detection',
            'X-Impact': 'SECURITY_DEGRADED'
          }
        }
      },
      monitoring: {
        metricsEnabled: true,
        alertingEnabled: true,
        healthCheckEndpoint: '/health/threat-detection',
        dashboardEnabled: true
      },
      tags: ['isectech', 'threat-detection', 'critical', 'ml', 'circuit-breaker']
    };

    // AI/ML Services Circuit Breaker (Resource-intensive)
    const aiMLCircuitBreaker: CircuitBreakerConfig = {
      serviceName: 'isectech-ai-ml-services',
      upstreamCluster: 'isectech-ai-ml-upstream',
      thresholds: {
        errorThreshold: 35,
        requestThreshold: 10,
        timeoutThreshold: 60, // Longer timeout for ML
        consecutiveFailures: 4,
        slowCallThreshold: 30000, // 30 seconds for complex ML operations
        slowCallPercentage: 50
      },
      windowConfig: {
        slidingWindowSize: 75,
        minimumNumberOfCalls: 8,
        slidingWindowType: 'COUNT_BASED',
        recordFailurePredicate: [500, 502, 503, 504, 408, 507]
      },
      stateTransition: {
        openToHalfOpenDelay: 90, // Longer recovery for resource-heavy service
        halfOpenMaxCalls: 3,
        halfOpenSuccessThreshold: 2
      },
      fallbackConfig: {
        enabled: true,
        fallbackResponse: {
          statusCode: 503,
          body: JSON.stringify({
            error: 'AI/ML services temporarily unavailable',
            message: 'Machine learning analysis is temporarily unavailable. Please retry in 90 seconds.',
            service: 'ai-ml-services',
            alternatives: ['Use rule-based detection', 'Check manual analysis tools'],
            timestamp: new Date().toISOString()
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '90',
            'X-Circuit-Breaker': 'OPEN',
            'X-Service': 'ai-ml-services',
            'X-Alternatives': 'rule-based-detection'
          }
        }
      },
      monitoring: {
        metricsEnabled: true,
        alertingEnabled: true,
        healthCheckEndpoint: '/health/ai-ml',
        dashboardEnabled: true
      },
      tags: ['isectech', 'ai-ml', 'resource-intensive', 'circuit-breaker']
    };

    // Event Processing Circuit Breaker (Real-time critical)
    const eventProcessingCircuitBreaker: CircuitBreakerConfig = {
      serviceName: 'isectech-event-processing',
      upstreamCluster: 'isectech-event-processing-upstream',
      thresholds: {
        errorThreshold: 25, // Very strict for real-time processing
        requestThreshold: 25,
        timeoutThreshold: 15, // Short timeout for real-time
        consecutiveFailures: 5,
        slowCallThreshold: 2000, // 2 seconds for real-time events
        slowCallPercentage: 30
      },
      windowConfig: {
        slidingWindowSize: 150,
        minimumNumberOfCalls: 20,
        slidingWindowType: 'COUNT_BASED',
        recordFailurePredicate: [500, 502, 503, 504, 408, 429]
      },
      stateTransition: {
        openToHalfOpenDelay: 20, // Fast recovery for real-time service
        halfOpenMaxCalls: 10,
        halfOpenSuccessThreshold: 7
      },
      fallbackConfig: {
        enabled: true,
        fallbackResponse: {
          statusCode: 503,
          body: JSON.stringify({
            error: 'Event processing temporarily unavailable',
            message: 'Real-time event processing is temporarily degraded. Events are being queued.',
            service: 'event-processing',
            status: 'DEGRADED',
            timestamp: new Date().toISOString()
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '20',
            'X-Circuit-Breaker': 'OPEN',
            'X-Service': 'event-processing',
            'X-Status': 'DEGRADED'
          }
        }
      },
      monitoring: {
        metricsEnabled: true,
        alertingEnabled: true,
        healthCheckEndpoint: '/health/event-processing',
        dashboardEnabled: true
      },
      tags: ['isectech', 'event-processing', 'real-time', 'critical', 'circuit-breaker']
    };

    // Compliance Services Circuit Breaker
    const complianceCircuitBreaker: CircuitBreakerConfig = {
      serviceName: 'isectech-compliance-automation',
      upstreamCluster: 'isectech-compliance-upstream',
      thresholds: {
        errorThreshold: 45, // More tolerance for reporting services
        requestThreshold: 12,
        timeoutThreshold: 120, // Long timeout for report generation
        consecutiveFailures: 6,
        slowCallThreshold: 60000, // 1 minute for complex reports
        slowCallPercentage: 70
      },
      windowConfig: {
        slidingWindowSize: 60,
        minimumNumberOfCalls: 8,
        slidingWindowType: 'COUNT_BASED',
        recordFailurePredicate: [500, 502, 503, 504]
      },
      stateTransition: {
        openToHalfOpenDelay: 120, // Longer recovery for report generation
        halfOpenMaxCalls: 3,
        halfOpenSuccessThreshold: 2
      },
      fallbackConfig: {
        enabled: true,
        fallbackResponse: {
          statusCode: 503,
          body: JSON.stringify({
            error: 'Compliance services temporarily unavailable',
            message: 'Report generation and compliance checking is temporarily unavailable.',
            service: 'compliance-automation',
            estimated_recovery: '2 minutes',
            timestamp: new Date().toISOString()
          }),
          headers: {
            'Content-Type': 'application/json',
            'Retry-After': '120',
            'X-Circuit-Breaker': 'OPEN',
            'X-Service': 'compliance-automation'
          }
        }
      },
      monitoring: {
        metricsEnabled: true,
        alertingEnabled: true,
        healthCheckEndpoint: '/health/compliance',
        dashboardEnabled: true
      },
      tags: ['isectech', 'compliance', 'reporting', 'circuit-breaker']
    };

    // Store all circuit breaker configurations
    [
      assetDiscoveryCircuitBreaker,
      threatDetectionCircuitBreaker,
      aiMLCircuitBreaker,
      eventProcessingCircuitBreaker,
      complianceCircuitBreaker
    ].forEach(config => {
      const validatedConfig = CircuitBreakerConfigSchema.parse(config);
      this.circuitBreakers.set(config.serviceName, validatedConfig);
      
      // Initialize metrics for each service
      this.metricsStore.set(config.serviceName, {
        state: CircuitBreakerState.CLOSED,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        timeoutRequests: 0,
        slowRequests: 0,
        errorRate: 0,
        averageResponseTime: 0,
        lastStateChange: new Date(),
        uptime: 100,
        openCount: 0,
        halfOpenCount: 0
      });
    });
  }

  /**
   * Get circuit breaker configuration for a service
   */
  public getCircuitBreakerConfig(serviceName: string): CircuitBreakerConfig | undefined {
    return this.circuitBreakers.get(serviceName);
  }

  /**
   * Get all circuit breaker configurations
   */
  public getAllCircuitBreakerConfigs(): Map<string, CircuitBreakerConfig> {
    return new Map(this.circuitBreakers);
  }

  /**
   * Update circuit breaker configuration
   */
  public updateCircuitBreakerConfig(serviceName: string, config: Partial<CircuitBreakerConfig>): void {
    const existingConfig = this.circuitBreakers.get(serviceName);
    if (existingConfig) {
      const updatedConfig = { ...existingConfig, ...config };
      const validatedConfig = CircuitBreakerConfigSchema.parse(updatedConfig);
      this.circuitBreakers.set(serviceName, validatedConfig);
      console.log(`Updated circuit breaker configuration for ${serviceName}`);
    } else {
      throw new Error(`Circuit breaker configuration not found for service: ${serviceName}`);
    }
  }

  /**
   * Get circuit breaker metrics
   */
  public getCircuitBreakerMetrics(serviceName: string): CircuitBreakerMetrics | undefined {
    return this.metricsStore.get(serviceName);
  }

  /**
   * Get all circuit breaker metrics
   */
  public getAllCircuitBreakerMetrics(): Map<string, CircuitBreakerMetrics> {
    return new Map(this.metricsStore);
  }

  /**
   * Generate Kong plugin configuration for circuit breakers
   */
  public generateKongPluginConfigurations(): Array<{
    name: string;
    service: { id: string };
    config: object;
    enabled: boolean;
    tags: string[];
  }> {
    const pluginConfigurations: Array<{
      name: string;
      service: { id: string };
      config: object;
      enabled: boolean;
      tags: string[];
    }> = [];

    for (const [serviceName, config] of this.circuitBreakers) {
      pluginConfigurations.push({
        name: 'circuit-breaker',
        service: { id: serviceName },
        config: {
          threshold: config.thresholds.requestThreshold,
          timeout: config.stateTransition.openToHalfOpenDelay,
          error_threshold: config.thresholds.errorThreshold,
          threshold_timeout: config.stateTransition.openToHalfOpenDelay,
          fallback_response: {
            status_code: config.fallbackConfig.fallbackResponse.statusCode,
            body: config.fallbackConfig.fallbackResponse.body,
            headers: config.fallbackConfig.fallbackResponse.headers
          }
        },
        enabled: true,
        tags: config.tags
      });
    }

    return pluginConfigurations;
  }

  /**
   * Generate circuit breaker health check configuration
   */
  public generateHealthCheckConfiguration(): object {
    const healthChecks: Record<string, any> = {};

    for (const [serviceName, config] of this.circuitBreakers) {
      if (config.monitoring.healthCheckEndpoint) {
        healthChecks[serviceName] = {
          endpoint: config.monitoring.healthCheckEndpoint,
          interval: '15s',
          timeout: '5s',
          unhealthy_threshold: 3,
          healthy_threshold: 2,
          tags: config.tags
        };
      }
    }

    return healthChecks;
  }

  /**
   * Generate monitoring alerts configuration
   */
  public generateAlertingConfiguration(): object {
    const alerts: Record<string, any> = {};

    for (const [serviceName, config] of this.circuitBreakers) {
      if (config.monitoring.alertingEnabled) {
        alerts[`${serviceName}-circuit-breaker-open`] = {
          condition: `circuit_breaker_state{service="${serviceName}"} == 1`,
          severity: 'warning',
          summary: `Circuit breaker is OPEN for ${serviceName}`,
          description: `The circuit breaker for ${serviceName} is in OPEN state, blocking requests`,
          runbook_url: `https://docs.isectech.com/runbooks/circuit-breaker-${serviceName}`,
          tags: config.tags
        };

        alerts[`${serviceName}-high-error-rate`] = {
          condition: `circuit_breaker_error_rate{service="${serviceName}"} > ${config.thresholds.errorThreshold}`,
          severity: 'critical',
          summary: `High error rate detected for ${serviceName}`,
          description: `Error rate for ${serviceName} is above ${config.thresholds.errorThreshold}%`,
          runbook_url: `https://docs.isectech.com/runbooks/high-error-rate-${serviceName}`,
          tags: config.tags
        };
      }
    }

    return alerts;
  }

  /**
   * Validate all circuit breaker configurations
   */
  public validateConfigurations(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const [serviceName, config] of this.circuitBreakers) {
      try {
        CircuitBreakerConfigSchema.parse(config);
      } catch (error) {
        errors.push(`Invalid configuration for ${serviceName}: ${error}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// Export production-ready circuit breaker manager
export const isectechCircuitBreakerManager = new ISECTECHCircuitBreakerManager();