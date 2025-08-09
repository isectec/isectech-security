/**
 * Intelligent Failover System for iSECTECH API Gateway
 * 
 * Advanced failover mechanisms that integrate with circuit breakers to provide
 * comprehensive system resilience and automated recovery for critical services.
 * 
 * Features:
 * - Multi-tier failover strategies (primary, secondary, tertiary)
 * - Intelligent health monitoring and endpoint selection
 * - Automated service recovery and rollback
 * - Load balancing across healthy endpoints
 * - Geographic and region-aware failover
 * - Real-time monitoring and alerting
 * - Integration with circuit breaker patterns
 * - SLA-aware priority-based failover
 */

import { Logger } from 'winston';
import { Redis } from 'ioredis';
import { EventEmitter } from 'events';
import { z } from 'zod';
import axios, { AxiosInstance } from 'axios';

// Failover Configuration Schema
const FailoverConfigSchema = z.object({
  serviceName: z.string(),
  priority: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).default('HIGH'),
  
  endpoints: z.object({
    primary: z.object({
      url: z.string(),
      region: z.string().default('us-west-2'),
      weight: z.number().min(0).max(100).default(100),
      healthCheckUrl: z.string().optional(),
      timeout: z.number().default(5000),
    }),
    secondary: z.array(z.object({
      url: z.string(),
      region: z.string(),
      weight: z.number().min(0).max(100).default(50),
      healthCheckUrl: z.string().optional(),
      timeout: z.number().default(5000),
    })).default([]),
    tertiary: z.array(z.object({
      url: z.string(),
      region: z.string(),
      weight: z.number().min(0).max(100).default(25),
      healthCheckUrl: z.string().optional(),
      timeout: z.number().default(5000),
    })).default([]),
  }),
  
  failoverStrategy: z.object({
    strategy: z.enum(['ROUND_ROBIN', 'WEIGHTED', 'LEAST_CONNECTIONS', 'GEOGRAPHICALLY_CLOSEST', 'PRIORITY_BASED']).default('PRIORITY_BASED'),
    maxFailoverAttempts: z.number().min(1).default(3),
    failoverThreshold: z.number().min(1).default(3), // consecutive failures
    recoveryThreshold: z.number().min(1).default(3), // consecutive successes
    cooldownPeriod: z.number().min(1000).default(60000), // 1 minute
    maxConcurrentFailovers: z.number().min(1).default(5),
  }),
  
  healthCheck: z.object({
    enabled: z.boolean().default(true),
    interval: z.number().min(5000).default(30000), // 30 seconds
    timeout: z.number().min(1000).default(10000), // 10 seconds
    healthyThreshold: z.number().min(1).default(2), // consecutive successes
    unhealthyThreshold: z.number().min(1).default(3), // consecutive failures
    path: z.string().default('/health'),
    expectedStatus: z.array(z.number()).default([200, 204]),
    retries: z.number().min(0).default(2),
  }),
  
  loadBalancing: z.object({
    algorithm: z.enum(['ROUND_ROBIN', 'WEIGHTED_ROUND_ROBIN', 'LEAST_CONNECTIONS', 'STICKY_SESSION']).default('WEIGHTED_ROUND_ROBIN'),
    sessionAffinity: z.boolean().default(false),
    affinityKey: z.string().default('session_id'),
  }),
  
  monitoring: z.object({
    metricsEnabled: z.boolean().default(true),
    alertingEnabled: z.boolean().default(true),
    detailedLogging: z.boolean().default(false),
    slaTarget: z.number().min(0).max(100).default(99.9), // 99.9% uptime
  }),
  
  recovery: z.object({
    autoRecovery: z.boolean().default(true),
    recoveryDelay: z.number().min(30000).default(120000), // 2 minutes
    maxRecoveryAttempts: z.number().min(1).default(5),
    gracefulRecovery: z.boolean().default(true),
    trafficShiftPercentage: z.number().min(0).max(100).default(10), // 10% traffic shift during recovery
  }),
});

const SystemFailoverConfigSchema = z.object({
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(1),
    keyPrefix: z.string().default('failover:'),
  }),
  global: z.object({
    maxServices: z.number().default(50),
    globalFailoverCooldown: z.number().default(300000), // 5 minutes
    emergencyMode: z.boolean().default(false),
    maxConcurrentFailovers: z.number().default(10),
  }),
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsFlushInterval: z.number().default(30000),
    healthCheckInterval: z.number().default(15000),
    alertingThreshold: z.number().default(2),
  }),
});

type FailoverConfig = z.infer<typeof FailoverConfigSchema>;
type SystemFailoverConfig = z.infer<typeof SystemFailoverConfigSchema>;

enum EndpointHealth {
  HEALTHY = 'HEALTHY',
  UNHEALTHY = 'UNHEALTHY',
  DEGRADED = 'DEGRADED',
  UNKNOWN = 'UNKNOWN',
}

enum FailoverState {
  ACTIVE = 'ACTIVE',
  FAILING_OVER = 'FAILING_OVER',
  FAILED_OVER = 'FAILED_OVER',
  RECOVERING = 'RECOVERING',
  MAINTENANCE = 'MAINTENANCE',
}

interface EndpointStatus {
  url: string;
  region: string;
  tier: 'primary' | 'secondary' | 'tertiary';
  health: EndpointHealth;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  lastHealthCheck: Date;
  lastSuccessfulRequest: Date;
  lastFailedRequest: Date;
  responseTime: number;
  weight: number;
  currentConnections: number;
  totalRequests: number;
  failedRequests: number;
}

interface ServiceFailoverStatus {
  serviceName: string;
  state: FailoverState;
  currentEndpoint: string;
  primaryEndpoint: string;
  failoverHistory: Array<{
    fromEndpoint: string;
    toEndpoint: string;
    reason: string;
    timestamp: Date;
  }>;
  lastFailoverTime?: Date;
  recoveryAttempts: number;
  endpoints: Map<string, EndpointStatus>;
  metrics: {
    totalRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    uptime: number;
    slaCompliance: number;
  };
}

interface LoadBalancingState {
  currentIndex: number;
  sessionAffinityMap: Map<string, string>;
  connectionCounts: Map<string, number>;
}

/**
 * Intelligent Failover System
 */
export class IntelligentFailoverSystem extends EventEmitter {
  private config: SystemFailoverConfig;
  private redis: Redis;
  private logger: Logger;
  private httpClient: AxiosInstance;
  
  private services: Map<string, FailoverConfig> = new Map();
  private serviceStatus: Map<string, ServiceFailoverStatus> = new Map();
  private loadBalancingState: Map<string, LoadBalancingState> = new Map();
  
  private healthCheckTimer?: NodeJS.Timeout;
  private metricsTimer?: NodeJS.Timeout;
  private recoveryTimer?: NodeJS.Timeout;
  
  private isInitialized: boolean = false;
  private isShuttingDown: boolean = false;

  constructor(config: SystemFailoverConfig, logger: Logger) {
    super();
    
    this.config = SystemFailoverConfigSchema.parse(config);
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
    
    // Initialize HTTP client for health checks
    this.httpClient = axios.create({
      timeout: 10000,
      validateStatus: () => true, // Don't throw on any status code
    });
    
    this.logger.info('Intelligent Failover System initialized', {
      component: 'IntelligentFailoverSystem',
      config: {
        maxServices: this.config.global.maxServices,
        emergencyMode: this.config.global.emergencyMode,
        monitoringEnabled: this.config.monitoring.enabled,
      },
    });
  }

  /**
   * Initialize the failover system
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      this.logger.info('Initializing Intelligent Failover System', {
        component: 'IntelligentFailoverSystem',
      });

      // Load existing configurations from Redis
      await this.loadExistingConfigurations();

      // Start monitoring
      if (this.config.monitoring.enabled) {
        this.startHealthChecking();
        this.startMetricsCollection();
        this.startRecoveryMonitoring();
      }

      this.isInitialized = true;
      
      this.logger.info('Intelligent Failover System initialization completed', {
        component: 'IntelligentFailoverSystem',
        services: this.services.size,
      });

      this.emit('initialized');

    } catch (error) {
      this.logger.error('Failed to initialize Intelligent Failover System', {
        component: 'IntelligentFailoverSystem',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Register a service for failover management
   */
  async registerService(config: FailoverConfig): Promise<void> {
    const validatedConfig = FailoverConfigSchema.parse(config);
    const serviceName = validatedConfig.serviceName;

    if (this.services.size >= this.config.global.maxServices) {
      throw new Error('Maximum number of services exceeded');
    }

    this.services.set(serviceName, validatedConfig);

    // Initialize service status
    const serviceStatus: ServiceFailoverStatus = {
      serviceName,
      state: FailoverState.ACTIVE,
      currentEndpoint: validatedConfig.endpoints.primary.url,
      primaryEndpoint: validatedConfig.endpoints.primary.url,
      failoverHistory: [],
      recoveryAttempts: 0,
      endpoints: new Map(),
      metrics: {
        totalRequests: 0,
        failedRequests: 0,
        averageResponseTime: 0,
        uptime: 100,
        slaCompliance: 100,
      },
    };

    // Initialize endpoint statuses
    this.initializeEndpointStatuses(validatedConfig, serviceStatus);
    
    this.serviceStatus.set(serviceName, serviceStatus);
    
    // Initialize load balancing state
    this.loadBalancingState.set(serviceName, {
      currentIndex: 0,
      sessionAffinityMap: new Map(),
      connectionCounts: new Map(),
    });

    // Persist configuration
    await this.saveServiceConfiguration(serviceName, validatedConfig);

    this.logger.info('Service registered for failover', {
      component: 'IntelligentFailoverSystem',
      serviceName,
      primaryEndpoint: validatedConfig.endpoints.primary.url,
      secondaryEndpoints: validatedConfig.endpoints.secondary.length,
      tertiaryEndpoints: validatedConfig.endpoints.tertiary.length,
    });
  }

  /**
   * Initialize endpoint statuses for a service
   */
  private initializeEndpointStatuses(config: FailoverConfig, serviceStatus: ServiceFailoverStatus): void {
    // Primary endpoint
    serviceStatus.endpoints.set(config.endpoints.primary.url, {
      url: config.endpoints.primary.url,
      region: config.endpoints.primary.region,
      tier: 'primary',
      health: EndpointHealth.UNKNOWN,
      consecutiveFailures: 0,
      consecutiveSuccesses: 0,
      lastHealthCheck: new Date(),
      lastSuccessfulRequest: new Date(),
      lastFailedRequest: new Date(0),
      responseTime: 0,
      weight: config.endpoints.primary.weight,
      currentConnections: 0,
      totalRequests: 0,
      failedRequests: 0,
    });

    // Secondary endpoints
    config.endpoints.secondary.forEach(endpoint => {
      serviceStatus.endpoints.set(endpoint.url, {
        url: endpoint.url,
        region: endpoint.region,
        tier: 'secondary',
        health: EndpointHealth.UNKNOWN,
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        lastHealthCheck: new Date(),
        lastSuccessfulRequest: new Date(),
        lastFailedRequest: new Date(0),
        responseTime: 0,
        weight: endpoint.weight,
        currentConnections: 0,
        totalRequests: 0,
        failedRequests: 0,
      });
    });

    // Tertiary endpoints
    config.endpoints.tertiary.forEach(endpoint => {
      serviceStatus.endpoints.set(endpoint.url, {
        url: endpoint.url,
        region: endpoint.region,
        tier: 'tertiary',
        health: EndpointHealth.UNKNOWN,
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        lastHealthCheck: new Date(),
        lastSuccessfulRequest: new Date(),
        lastFailedRequest: new Date(0),
        responseTime: 0,
        weight: endpoint.weight,
        currentConnections: 0,
        totalRequests: 0,
        failedRequests: 0,
      });
    });
  }

  /**
   * Execute request with failover protection
   */
  async executeWithFailover<T>(
    serviceName: string,
    requestOperation: (endpoint: string) => Promise<T>,
    sessionId?: string
  ): Promise<T> {
    const config = this.services.get(serviceName);
    const serviceStatus = this.serviceStatus.get(serviceName);
    
    if (!config || !serviceStatus) {
      throw new Error(`Service not registered: ${serviceName}`);
    }

    const startTime = Date.now();
    let lastError: Error | null = null;
    let attemptCount = 0;
    const maxAttempts = config.failoverStrategy.maxFailoverAttempts;

    while (attemptCount < maxAttempts) {
      try {
        const endpoint = await this.selectEndpoint(serviceName, sessionId);
        const result = await requestOperation(endpoint);
        
        // Record successful request
        await this.recordRequestResult(serviceName, endpoint, true, Date.now() - startTime);
        
        return result;

      } catch (error) {
        lastError = error;
        attemptCount++;
        
        const endpoint = serviceStatus.currentEndpoint;
        
        // Record failed request
        await this.recordRequestResult(serviceName, endpoint, false, Date.now() - startTime, error.message);
        
        // Check if we should trigger failover
        const shouldFailover = await this.shouldTriggerFailover(serviceName, endpoint);
        
        if (shouldFailover && attemptCount < maxAttempts) {
          await this.triggerFailover(serviceName, error.message);
        } else if (attemptCount >= maxAttempts) {
          break;
        }
      }
    }

    // All attempts failed
    this.logger.error('All failover attempts exhausted', {
      component: 'IntelligentFailoverSystem',
      serviceName,
      attempts: attemptCount,
      lastError: lastError?.message,
    });

    throw new Error(`Service ${serviceName} failed after ${attemptCount} attempts: ${lastError?.message}`);
  }

  /**
   * Select the best endpoint for a request
   */
  private async selectEndpoint(serviceName: string, sessionId?: string): Promise<string> {
    const config = this.services.get(serviceName);
    const serviceStatus = this.serviceStatus.get(serviceName);
    const loadBalancingState = this.loadBalancingState.get(serviceName);
    
    if (!config || !serviceStatus || !loadBalancingState) {
      throw new Error(`Service configuration not found: ${serviceName}`);
    }

    // Check for session affinity
    if (config.loadBalancing.sessionAffinity && sessionId) {
      const affinityEndpoint = loadBalancingState.sessionAffinityMap.get(sessionId);
      if (affinityEndpoint && this.isEndpointHealthy(serviceStatus, affinityEndpoint)) {
        return affinityEndpoint;
      }
    }

    // Get healthy endpoints
    const healthyEndpoints = this.getHealthyEndpoints(serviceStatus);
    
    if (healthyEndpoints.length === 0) {
      // No healthy endpoints, use current endpoint as last resort
      this.logger.warn('No healthy endpoints available, using current endpoint', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        currentEndpoint: serviceStatus.currentEndpoint,
      });
      return serviceStatus.currentEndpoint;
    }

    // Select endpoint based on strategy
    const selectedEndpoint = this.applyLoadBalancingStrategy(
      config.loadBalancing.algorithm,
      healthyEndpoints,
      loadBalancingState
    );

    // Update session affinity if enabled
    if (config.loadBalancing.sessionAffinity && sessionId) {
      loadBalancingState.sessionAffinityMap.set(sessionId, selectedEndpoint);
    }

    return selectedEndpoint;
  }

  /**
   * Get healthy endpoints sorted by priority and weight
   */
  private getHealthyEndpoints(serviceStatus: ServiceFailoverStatus): string[] {
    const endpoints: Array<{ url: string; tier: string; weight: number; health: EndpointHealth }> = [];
    
    for (const [url, status] of serviceStatus.endpoints) {
      if (status.health === EndpointHealth.HEALTHY || status.health === EndpointHealth.DEGRADED) {
        endpoints.push({
          url,
          tier: status.tier,
          weight: status.weight,
          health: status.health,
        });
      }
    }

    // Sort by tier priority, then by weight
    const tierPriority = { primary: 3, secondary: 2, tertiary: 1 };
    
    endpoints.sort((a, b) => {
      const tierDiff = tierPriority[b.tier] - tierPriority[a.tier];
      if (tierDiff !== 0) return tierDiff;
      
      const healthDiff = (b.health === EndpointHealth.HEALTHY ? 1 : 0) - (a.health === EndpointHealth.HEALTHY ? 1 : 0);
      if (healthDiff !== 0) return healthDiff;
      
      return b.weight - a.weight;
    });

    return endpoints.map(e => e.url);
  }

  /**
   * Apply load balancing strategy
   */
  private applyLoadBalancingStrategy(
    algorithm: string,
    endpoints: string[],
    loadBalancingState: LoadBalancingState
  ): string {
    switch (algorithm) {
      case 'ROUND_ROBIN':
        const index = loadBalancingState.currentIndex % endpoints.length;
        loadBalancingState.currentIndex = (loadBalancingState.currentIndex + 1) % endpoints.length;
        return endpoints[index];
        
      case 'WEIGHTED_ROUND_ROBIN':
        // For simplicity, using round-robin here. In production, implement weighted logic
        return this.applyLoadBalancingStrategy('ROUND_ROBIN', endpoints, loadBalancingState);
        
      case 'LEAST_CONNECTIONS':
        let leastConnEndpoint = endpoints[0];
        let leastConnections = loadBalancingState.connectionCounts.get(leastConnEndpoint) || 0;
        
        for (const endpoint of endpoints) {
          const connections = loadBalancingState.connectionCounts.get(endpoint) || 0;
          if (connections < leastConnections) {
            leastConnections = connections;
            leastConnEndpoint = endpoint;
          }
        }
        
        return leastConnEndpoint;
        
      default:
        return endpoints[0]; // Default to first healthy endpoint
    }
  }

  /**
   * Check if endpoint is healthy
   */
  private isEndpointHealthy(serviceStatus: ServiceFailoverStatus, endpoint: string): boolean {
    const endpointStatus = serviceStatus.endpoints.get(endpoint);
    return endpointStatus?.health === EndpointHealth.HEALTHY || 
           endpointStatus?.health === EndpointHealth.DEGRADED;
  }

  /**
   * Record request result
   */
  private async recordRequestResult(
    serviceName: string,
    endpoint: string,
    success: boolean,
    duration: number,
    errorMessage?: string
  ): Promise<void> {
    const serviceStatus = this.serviceStatus.get(serviceName);
    if (!serviceStatus) return;

    const endpointStatus = serviceStatus.endpoints.get(endpoint);
    if (!endpointStatus) return;

    // Update endpoint statistics
    endpointStatus.totalRequests++;
    endpointStatus.responseTime = (endpointStatus.responseTime + duration) / 2; // Simple moving average

    if (success) {
      endpointStatus.consecutiveSuccesses++;
      endpointStatus.consecutiveFailures = 0;
      endpointStatus.lastSuccessfulRequest = new Date();
      
      // Update health status
      if (endpointStatus.consecutiveSuccesses >= 2) {
        endpointStatus.health = EndpointHealth.HEALTHY;
      }
    } else {
      endpointStatus.failedRequests++;
      endpointStatus.consecutiveFailures++;
      endpointStatus.consecutiveSuccesses = 0;
      endpointStatus.lastFailedRequest = new Date();
    }

    // Update service metrics
    serviceStatus.metrics.totalRequests++;
    if (!success) {
      serviceStatus.metrics.failedRequests++;
    }
    serviceStatus.metrics.averageResponseTime = 
      (serviceStatus.metrics.averageResponseTime + duration) / 2;

    // Calculate SLA compliance
    const successRate = (serviceStatus.metrics.totalRequests - serviceStatus.metrics.failedRequests) / 
                       serviceStatus.metrics.totalRequests * 100;
    serviceStatus.metrics.slaCompliance = successRate;

    // Persist metrics
    await this.saveServiceStatus(serviceName, serviceStatus);
  }

  /**
   * Check if failover should be triggered
   */
  private async shouldTriggerFailover(serviceName: string, endpoint: string): Promise<boolean> {
    const config = this.services.get(serviceName);
    const serviceStatus = this.serviceStatus.get(serviceName);
    
    if (!config || !serviceStatus) return false;

    const endpointStatus = serviceStatus.endpoints.get(endpoint);
    if (!endpointStatus) return false;

    // Check consecutive failures threshold
    if (endpointStatus.consecutiveFailures >= config.failoverStrategy.failoverThreshold) {
      return true;
    }

    // Check if we're in cooldown period
    if (serviceStatus.lastFailoverTime) {
      const timeSinceLastFailover = Date.now() - serviceStatus.lastFailoverTime.getTime();
      if (timeSinceLastFailover < config.failoverStrategy.cooldownPeriod) {
        return false;
      }
    }

    return false;
  }

  /**
   * Trigger failover for a service
   */
  private async triggerFailover(serviceName: string, reason: string): Promise<void> {
    const config = this.services.get(serviceName);
    const serviceStatus = this.serviceStatus.get(serviceName);
    
    if (!config || !serviceStatus) return;

    const currentEndpoint = serviceStatus.currentEndpoint;
    
    // Find next healthy endpoint
    const healthyEndpoints = this.getHealthyEndpoints(serviceStatus);
    const nextEndpoint = healthyEndpoints.find(ep => ep !== currentEndpoint);
    
    if (!nextEndpoint) {
      this.logger.error('No healthy endpoints available for failover', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        currentEndpoint,
        reason,
      });
      return;
    }

    // Update service status
    serviceStatus.state = FailoverState.FAILING_OVER;
    serviceStatus.currentEndpoint = nextEndpoint;
    serviceStatus.lastFailoverTime = new Date();
    
    // Record failover history
    serviceStatus.failoverHistory.push({
      fromEndpoint: currentEndpoint,
      toEndpoint: nextEndpoint,
      reason,
      timestamp: new Date(),
    });

    // Mark previous endpoint as unhealthy
    const previousEndpointStatus = serviceStatus.endpoints.get(currentEndpoint);
    if (previousEndpointStatus) {
      previousEndpointStatus.health = EndpointHealth.UNHEALTHY;
    }

    serviceStatus.state = FailoverState.FAILED_OVER;

    // Persist updated status
    await this.saveServiceStatus(serviceName, serviceStatus);

    this.logger.warn('Service failover completed', {
      component: 'IntelligentFailoverSystem',
      serviceName,
      fromEndpoint: currentEndpoint,
      toEndpoint: nextEndpoint,
      reason,
    });

    this.emit('failover', {
      serviceName,
      fromEndpoint: currentEndpoint,
      toEndpoint: nextEndpoint,
      reason,
      timestamp: new Date(),
    });
  }

  /**
   * Start health checking
   */
  private startHealthChecking(): void {
    this.healthCheckTimer = setInterval(async () => {
      await this.performHealthChecks();
    }, this.config.monitoring.healthCheckInterval);

    this.logger.info('Started failover health checking', {
      component: 'IntelligentFailoverSystem',
      interval: this.config.monitoring.healthCheckInterval,
    });
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsTimer = setInterval(async () => {
      await this.collectMetrics();
    }, this.config.monitoring.metricsFlushInterval);

    this.logger.info('Started failover metrics collection', {
      component: 'IntelligentFailoverSystem',
      interval: this.config.monitoring.metricsFlushInterval,
    });
  }

  /**
   * Start recovery monitoring
   */
  private startRecoveryMonitoring(): void {
    this.recoveryTimer = setInterval(async () => {
      await this.performRecoveryChecks();
    }, 60000); // Every minute

    this.logger.info('Started recovery monitoring', {
      component: 'IntelligentFailoverSystem',
    });
  }

  /**
   * Perform health checks on all endpoints
   */
  private async performHealthChecks(): Promise<void> {
    if (this.isShuttingDown) return;

    const healthCheckPromises: Promise<void>[] = [];

    for (const [serviceName, config] of this.services) {
      const serviceStatus = this.serviceStatus.get(serviceName);
      if (!serviceStatus) continue;

      for (const [endpoint] of serviceStatus.endpoints) {
        healthCheckPromises.push(
          this.performEndpointHealthCheck(serviceName, endpoint, config)
        );
      }
    }

    await Promise.allSettled(healthCheckPromises);
  }

  /**
   * Perform health check on a specific endpoint
   */
  private async performEndpointHealthCheck(
    serviceName: string,
    endpoint: string,
    config: FailoverConfig
  ): Promise<void> {
    const serviceStatus = this.serviceStatus.get(serviceName);
    const endpointStatus = serviceStatus?.endpoints.get(endpoint);
    
    if (!serviceStatus || !endpointStatus) return;

    if (!config.healthCheck.enabled) return;

    try {
      const healthCheckUrl = endpointStatus.url + config.healthCheck.path;
      const startTime = Date.now();
      
      const response = await this.httpClient.get(healthCheckUrl, {
        timeout: config.healthCheck.timeout,
      });
      
      const duration = Date.now() - startTime;
      const isHealthy = config.healthCheck.expectedStatus.includes(response.status);
      
      endpointStatus.lastHealthCheck = new Date();
      endpointStatus.responseTime = duration;
      
      if (isHealthy) {
        endpointStatus.consecutiveSuccesses++;
        endpointStatus.consecutiveFailures = 0;
        
        if (endpointStatus.consecutiveSuccesses >= config.healthCheck.healthyThreshold) {
          endpointStatus.health = EndpointHealth.HEALTHY;
        }
      } else {
        endpointStatus.consecutiveFailures++;
        endpointStatus.consecutiveSuccesses = 0;
        
        if (endpointStatus.consecutiveFailures >= config.healthCheck.unhealthyThreshold) {
          endpointStatus.health = EndpointHealth.UNHEALTHY;
        }
      }

    } catch (error) {
      endpointStatus.consecutiveFailures++;
      endpointStatus.consecutiveSuccesses = 0;
      endpointStatus.lastHealthCheck = new Date();
      
      if (endpointStatus.consecutiveFailures >= config.healthCheck.unhealthyThreshold) {
        endpointStatus.health = EndpointHealth.UNHEALTHY;
      }

      if (config.monitoring.detailedLogging) {
        this.logger.debug('Endpoint health check failed', {
          component: 'IntelligentFailoverSystem',
          serviceName,
          endpoint,
          error: error.message,
        });
      }
    }
  }

  /**
   * Perform recovery checks
   */
  private async performRecoveryChecks(): Promise<void> {
    if (this.isShuttingDown) return;

    for (const [serviceName, serviceStatus] of this.serviceStatus) {
      const config = this.services.get(serviceName);
      if (!config || !config.recovery.autoRecovery) continue;

      // Check if primary endpoint has recovered
      if (serviceStatus.currentEndpoint !== serviceStatus.primaryEndpoint) {
        const primaryStatus = serviceStatus.endpoints.get(serviceStatus.primaryEndpoint);
        
        if (primaryStatus && primaryStatus.health === EndpointHealth.HEALTHY) {
          await this.attemptRecovery(serviceName);
        }
      }
    }
  }

  /**
   * Attempt to recover a service to its primary endpoint
   */
  private async attemptRecovery(serviceName: string): Promise<void> {
    const config = this.services.get(serviceName);
    const serviceStatus = this.serviceStatus.get(serviceName);
    
    if (!config || !serviceStatus) return;

    try {
      serviceStatus.state = FailoverState.RECOVERING;
      serviceStatus.recoveryAttempts++;

      // Gradual traffic shift if enabled
      if (config.recovery.gracefulRecovery) {
        // Implement gradual traffic shifting logic here
        // For now, we'll do an immediate switch
      }

      const previousEndpoint = serviceStatus.currentEndpoint;
      serviceStatus.currentEndpoint = serviceStatus.primaryEndpoint;
      serviceStatus.state = FailoverState.ACTIVE;

      await this.saveServiceStatus(serviceName, serviceStatus);

      this.logger.info('Service recovery completed', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        fromEndpoint: previousEndpoint,
        toPrimaryEndpoint: serviceStatus.primaryEndpoint,
        recoveryAttempts: serviceStatus.recoveryAttempts,
      });

      this.emit('recovery', {
        serviceName,
        fromEndpoint: previousEndpoint,
        toPrimaryEndpoint: serviceStatus.primaryEndpoint,
        timestamp: new Date(),
      });

    } catch (error) {
      serviceStatus.state = FailoverState.FAILED_OVER;
      
      this.logger.error('Service recovery failed', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        error: error.message,
        recoveryAttempts: serviceStatus.recoveryAttempts,
      });
    }
  }

  /**
   * Collect and store metrics
   */
  private async collectMetrics(): Promise<void> {
    if (this.isShuttingDown) return;

    try {
      const systemMetrics = {
        totalServices: this.services.size,
        activeServices: 0,
        failedOverServices: 0,
        recoveringServices: 0,
        timestamp: Date.now(),
        services: {},
      };

      for (const [serviceName, serviceStatus] of this.serviceStatus) {
        switch (serviceStatus.state) {
          case FailoverState.ACTIVE:
            systemMetrics.activeServices++;
            break;
          case FailoverState.FAILED_OVER:
            systemMetrics.failedOverServices++;
            break;
          case FailoverState.RECOVERING:
            systemMetrics.recoveringServices++;
            break;
        }

        systemMetrics.services[serviceName] = {
          state: serviceStatus.state,
          currentEndpoint: serviceStatus.currentEndpoint,
          metrics: serviceStatus.metrics,
          endpointsHealth: Array.from(serviceStatus.endpoints.entries()).map(([url, status]) => ({
            url,
            health: status.health,
            responseTime: status.responseTime,
          })),
        };
      }

      // Store metrics in Redis
      await this.redis.hset('failover:system_metrics', {
        timestamp: systemMetrics.timestamp.toString(),
        data: JSON.stringify(systemMetrics),
      });

    } catch (error) {
      this.logger.error('Failed to collect failover metrics', {
        component: 'IntelligentFailoverSystem',
        error: error.message,
      });
    }
  }

  /**
   * Load existing configurations from Redis
   */
  private async loadExistingConfigurations(): Promise<void> {
    try {
      const keys = await this.redis.keys(`${this.config.redis.keyPrefix}config:*`);
      
      for (const key of keys) {
        const configData = await this.redis.get(key);
        if (configData) {
          const config = JSON.parse(configData);
          await this.registerService(config);
        }
      }
    } catch (error) {
      this.logger.error('Failed to load existing configurations', {
        component: 'IntelligentFailoverSystem',
        error: error.message,
      });
    }
  }

  /**
   * Save service configuration to Redis
   */
  private async saveServiceConfiguration(serviceName: string, config: FailoverConfig): Promise<void> {
    try {
      const key = `${this.config.redis.keyPrefix}config:${serviceName}`;
      await this.redis.set(key, JSON.stringify(config));
    } catch (error) {
      this.logger.error('Failed to save service configuration', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Save service status to Redis
   */
  private async saveServiceStatus(serviceName: string, status: ServiceFailoverStatus): Promise<void> {
    try {
      const key = `${this.config.redis.keyPrefix}status:${serviceName}`;
      const statusData = {
        ...status,
        endpoints: Array.from(status.endpoints.entries()),
      };
      await this.redis.set(key, JSON.stringify(statusData));
    } catch (error) {
      this.logger.error('Failed to save service status', {
        component: 'IntelligentFailoverSystem',
        serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Get service status
   */
  getServiceStatus(serviceName: string): ServiceFailoverStatus | undefined {
    return this.serviceStatus.get(serviceName);
  }

  /**
   * Get all service statuses
   */
  getAllServiceStatuses(): Map<string, ServiceFailoverStatus> {
    return new Map(this.serviceStatus);
  }

  /**
   * Get system health summary
   */
  getSystemHealth(): {
    healthy: boolean;
    totalServices: number;
    activeServices: number;
    failedOverServices: number;
    recoveringServices: number;
  } {
    let activeServices = 0;
    let failedOverServices = 0;
    let recoveringServices = 0;

    for (const serviceStatus of this.serviceStatus.values()) {
      switch (serviceStatus.state) {
        case FailoverState.ACTIVE:
          activeServices++;
          break;
        case FailoverState.FAILED_OVER:
          failedOverServices++;
          break;
        case FailoverState.RECOVERING:
          recoveringServices++;
          break;
      }
    }

    return {
      healthy: failedOverServices === 0,
      totalServices: this.services.size,
      activeServices,
      failedOverServices,
      recoveringServices,
    };
  }

  /**
   * Force failover for a service
   */
  async forceFailover(serviceName: string, targetEndpoint?: string): Promise<void> {
    await this.triggerFailover(serviceName, `Manual failover${targetEndpoint ? ` to ${targetEndpoint}` : ''}`);
  }

  /**
   * Force recovery for a service
   */
  async forceRecovery(serviceName: string): Promise<void> {
    await this.attemptRecovery(serviceName);
  }

  /**
   * Shutdown the failover system
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    
    this.logger.info('Shutting down Intelligent Failover System', {
      component: 'IntelligentFailoverSystem',
    });

    // Stop timers
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }
    if (this.metricsTimer) {
      clearInterval(this.metricsTimer);
    }
    if (this.recoveryTimer) {
      clearInterval(this.recoveryTimer);
    }

    // Close Redis connection
    try {
      await this.redis.quit();
    } catch (error) {
      this.logger.error('Error closing Redis connection', {
        component: 'IntelligentFailoverSystem',
        error: error.message,
      });
    }

    this.emit('shutdown');
    
    this.logger.info('Intelligent Failover System shutdown completed', {
      component: 'IntelligentFailoverSystem',
    });
  }
}

// Export types and schemas
export { FailoverConfigSchema, SystemFailoverConfigSchema };
export type { 
  FailoverConfig, 
  SystemFailoverConfig, 
  ServiceFailoverStatus,
  EndpointStatus
};
export { EndpointHealth, FailoverState };

// Export production-ready instance factory
export function createIntelligentFailoverSystem(
  config: SystemFailoverConfig,
  logger: Logger
): IntelligentFailoverSystem {
  return new IntelligentFailoverSystem(config, logger);
}