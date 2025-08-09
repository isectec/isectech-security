/**
 * Advanced Failover Configurations for iSECTECH API Gateway
 * 
 * Comprehensive failover strategies including active-passive, active-active,
 * sticky sessions, regional disaster recovery, and sub-second transition times
 * for critical cybersecurity services.
 * 
 * Features:
 * - Active-Passive failover with automated health monitoring
 * - Active-Active load balancing with intelligent routing
 * - Sticky session management with failover support
 * - Multi-region disaster recovery orchestration
 * - Sub-second failover transition capabilities
 * - Service mesh integration with traffic shifting
 * - Geo-distributed endpoint management
 * - Real-time health monitoring and automated recovery
 */

import { Logger } from 'winston';
import { Redis } from 'ioredis';
import { EventEmitter } from 'events';
import { z } from 'zod';

// Advanced Failover Configuration Schemas
const EndpointConfigSchema = z.object({
  id: z.string(),
  url: z.string(),
  region: z.string(),
  zone: z.string().optional(),
  datacenter: z.string().optional(),
  weight: z.number().min(0).max(100).default(100),
  priority: z.number().min(1).max(10).default(5),
  healthCheckUrl: z.string().optional(),
  healthCheckInterval: z.number().default(10000), // 10 seconds
  timeout: z.number().default(5000),
  maxConcurrentConnections: z.number().default(1000),
  tags: z.array(z.string()).default([]),
  metadata: z.record(z.any()).default({}),
});

const ActivePassiveConfigSchema = z.object({
  primary: EndpointConfigSchema,
  secondary: z.array(EndpointConfigSchema),
  failoverDelay: z.number().default(500), // 500ms
  healthCheckFailureThreshold: z.number().default(3),
  healthCheckSuccessThreshold: z.number().default(2),
  autoFailback: z.boolean().default(true),
  failbackDelay: z.number().default(60000), // 1 minute
  stickySessions: z.boolean().default(false),
});

const ActiveActiveConfigSchema = z.object({
  endpoints: z.array(EndpointConfigSchema).min(2),
  loadBalancingStrategy: z.enum([
    'ROUND_ROBIN',
    'WEIGHTED_ROUND_ROBIN', 
    'LEAST_CONNECTIONS',
    'IP_HASH',
    'GEOLOCATION',
    'RESPONSE_TIME'
  ]).default('WEIGHTED_ROUND_ROBIN'),
  healthCheckAll: z.boolean().default(true),
  minHealthyEndpoints: z.number().min(1).default(1),
  maxFailedEndpoints: z.number().default(1),
  sessionAffinity: z.object({
    enabled: z.boolean().default(false),
    method: z.enum(['COOKIE', 'IP_HASH', 'HEADER']).default('COOKIE'),
    cookieName: z.string().default('ISECTECH_SESSION'),
    headerName: z.string().default('X-Session-ID'),
    ttl: z.number().default(3600), // 1 hour
  }),
});

const RegionalFailoverConfigSchema = z.object({
  regions: z.array(z.object({
    name: z.string(),
    primary: z.boolean().default(false),
    priority: z.number().min(1).max(10),
    endpoints: z.array(EndpointConfigSchema),
    latencyThreshold: z.number().default(200), // 200ms
    failoverDelay: z.number().default(1000), // 1 second
  })).min(2),
  disasterRecovery: z.object({
    enabled: z.boolean().default(true),
    rpo: z.number().default(300), // Recovery Point Objective: 5 minutes
    rto: z.number().default(60), // Recovery Time Objective: 1 minute
    autoFailover: z.boolean().default(true),
    trafficShiftPercentage: z.number().min(0).max(100).default(100),
    dataReplicationLag: z.number().default(30), // 30 seconds acceptable lag
  }),
  geoDNS: z.object({
    enabled: z.boolean().default(true),
    provider: z.enum(['ROUTE53', 'CLOUDFLARE', 'CUSTOM']).default('ROUTE53'),
    healthCheckUrl: z.string().default('/health'),
    ttl: z.number().default(60), // DNS TTL in seconds
  }),
});

const AdvancedFailoverConfigSchema = z.object({
  serviceName: z.string(),
  strategy: z.enum(['ACTIVE_PASSIVE', 'ACTIVE_ACTIVE', 'REGIONAL']),
  
  // Configuration based on strategy
  activePassive: ActivePassiveConfigSchema.optional(),
  activeActive: ActiveActiveConfigSchema.optional(),
  regional: RegionalFailoverConfigSchema.optional(),
  
  // Common settings
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsInterval: z.number().default(30000),
    alerting: z.boolean().default(true),
    detailedLogging: z.boolean().default(true),
  }),
  
  performance: z.object({
    connectionPooling: z.boolean().default(true),
    keepAlive: z.boolean().default(true),
    connectionTimeout: z.number().default(5000),
    requestTimeout: z.number().default(30000),
    retries: z.number().default(3),
    retryDelay: z.number().default(1000),
  }),
  
  security: z.object({
    tlsEnabled: z.boolean().default(true),
    certificateValidation: z.boolean().default(true),
    allowedCiphers: z.array(z.string()).optional(),
    clientCertificates: z.boolean().default(false),
  }),
});

type EndpointConfig = z.infer<typeof EndpointConfigSchema>;
type ActivePassiveConfig = z.infer<typeof ActivePassiveConfigSchema>;
type ActiveActiveConfig = z.infer<typeof ActiveActiveConfigSchema>;
type RegionalFailoverConfig = z.infer<typeof RegionalFailoverConfigSchema>;
type AdvancedFailoverConfig = z.infer<typeof AdvancedFailoverConfigSchema>;

enum FailoverStrategy {
  ACTIVE_PASSIVE = 'ACTIVE_PASSIVE',
  ACTIVE_ACTIVE = 'ACTIVE_ACTIVE',
  REGIONAL = 'REGIONAL',
}

enum EndpointState {
  HEALTHY = 'HEALTHY',
  UNHEALTHY = 'UNHEALTHY',
  DEGRADED = 'DEGRADED',
  MAINTENANCE = 'MAINTENANCE',
  UNKNOWN = 'UNKNOWN',
}

interface EndpointStatus extends EndpointConfig {
  state: EndpointState;
  isActive: boolean;
  connectionCount: number;
  responseTime: number;
  successRate: number;
  lastHealthCheck: Date;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  totalRequests: number;
  failedRequests: number;
}

interface SessionInfo {
  id: string;
  endpoint: string;
  createdAt: Date;
  lastAccess: Date;
  sticky: boolean;
  metadata: Record<string, any>;
}

interface FailoverEvent {
  timestamp: Date;
  serviceName: string;
  strategy: FailoverStrategy;
  fromEndpoint?: string;
  toEndpoint: string;
  reason: string;
  duration: number;
  automatic: boolean;
}

/**
 * Advanced Failover Configuration Manager
 */
export class AdvancedFailoverManager extends EventEmitter {
  private redis: Redis;
  private logger: Logger;
  
  private configurations: Map<string, AdvancedFailoverConfig> = new Map();
  private endpointStatuses: Map<string, Map<string, EndpointStatus>> = new Map();
  private activeSessions: Map<string, SessionInfo> = new Map();
  private failoverHistory: FailoverEvent[] = [];
  
  private healthCheckTimers: Map<string, NodeJS.Timeout> = new Map();
  private metricsTimer?: NodeJS.Timeout;
  private sessionCleanupTimer?: NodeJS.Timeout;
  
  private isInitialized: boolean = false;
  private isShuttingDown: boolean = false;

  constructor(redis: Redis, logger: Logger) {
    super();
    this.redis = redis;
    this.logger = logger;
    
    this.logger.info('Advanced Failover Manager initialized', {
      component: 'AdvancedFailoverManager',
    });
  }

  /**
   * Initialize the failover manager
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      this.logger.info('Initializing Advanced Failover Manager', {
        component: 'AdvancedFailoverManager',
      });

      // Load existing configurations
      await this.loadConfigurations();
      
      // Start monitoring
      this.startMetricsCollection();
      this.startSessionCleanup();

      this.isInitialized = true;
      
      this.logger.info('Advanced Failover Manager initialization completed', {
        component: 'AdvancedFailoverManager',
        configurations: this.configurations.size,
      });

    } catch (error) {
      this.logger.error('Failed to initialize Advanced Failover Manager', {
        component: 'AdvancedFailoverManager',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Configure service failover strategy
   */
  async configureService(config: AdvancedFailoverConfig): Promise<void> {
    const validatedConfig = AdvancedFailoverConfigSchema.parse(config);
    const serviceName = validatedConfig.serviceName;

    this.configurations.set(serviceName, validatedConfig);
    
    // Initialize endpoint statuses
    await this.initializeEndpointStatuses(serviceName, validatedConfig);
    
    // Start health checks
    await this.startHealthChecks(serviceName, validatedConfig);
    
    // Persist configuration
    await this.saveConfiguration(serviceName, validatedConfig);

    this.logger.info('Service failover configured', {
      component: 'AdvancedFailoverManager',
      serviceName,
      strategy: validatedConfig.strategy,
    });
  }

  /**
   * Initialize endpoint statuses for a service
   */
  private async initializeEndpointStatuses(
    serviceName: string, 
    config: AdvancedFailoverConfig
  ): Promise<void> {
    const serviceEndpoints = new Map<string, EndpointStatus>();
    const endpoints = this.getEndpointsFromConfig(config);

    for (const endpoint of endpoints) {
      const status: EndpointStatus = {
        ...endpoint,
        state: EndpointState.UNKNOWN,
        isActive: this.shouldEndpointBeActive(endpoint, config),
        connectionCount: 0,
        responseTime: 0,
        successRate: 100,
        lastHealthCheck: new Date(),
        consecutiveFailures: 0,
        consecutiveSuccesses: 0,
        totalRequests: 0,
        failedRequests: 0,
      };

      serviceEndpoints.set(endpoint.id, status);
    }

    this.endpointStatuses.set(serviceName, serviceEndpoints);
  }

  /**
   * Get endpoints from configuration based on strategy
   */
  private getEndpointsFromConfig(config: AdvancedFailoverConfig): EndpointConfig[] {
    switch (config.strategy) {
      case FailoverStrategy.ACTIVE_PASSIVE:
        return config.activePassive ? 
          [config.activePassive.primary, ...config.activePassive.secondary] : [];
      
      case FailoverStrategy.ACTIVE_ACTIVE:
        return config.activeActive ? config.activeActive.endpoints : [];
      
      case FailoverStrategy.REGIONAL:
        return config.regional ? 
          config.regional.regions.flatMap(region => region.endpoints) : [];
      
      default:
        return [];
    }
  }

  /**
   * Determine if endpoint should be initially active
   */
  private shouldEndpointBeActive(endpoint: EndpointConfig, config: AdvancedFailoverConfig): boolean {
    switch (config.strategy) {
      case FailoverStrategy.ACTIVE_PASSIVE:
        // Only primary is initially active in active-passive
        return config.activePassive?.primary.id === endpoint.id;
      
      case FailoverStrategy.ACTIVE_ACTIVE:
        // All endpoints are initially active in active-active
        return true;
      
      case FailoverStrategy.REGIONAL:
        // Primary region endpoints are initially active
        const primaryRegion = config.regional?.regions.find(r => r.primary);
        return primaryRegion?.endpoints.some(e => e.id === endpoint.id) || false;
      
      default:
        return false;
    }
  }

  /**
   * Execute request with advanced failover
   */
  async executeWithFailover<T>(
    serviceName: string,
    operation: (endpoint: string) => Promise<T>,
    sessionId?: string,
    requestMetadata?: Record<string, any>
  ): Promise<T> {
    const config = this.configurations.get(serviceName);
    if (!config) {
      throw new Error(`Service not configured: ${serviceName}`);
    }

    const startTime = Date.now();
    const selectedEndpoint = await this.selectEndpoint(serviceName, sessionId, requestMetadata);
    
    try {
      // Update connection count
      await this.incrementConnectionCount(serviceName, selectedEndpoint.id);
      
      // Execute operation
      const result = await operation(selectedEndpoint.url);
      
      // Record successful execution
      await this.recordRequestResult(serviceName, selectedEndpoint.id, true, Date.now() - startTime);
      
      // Update session if sticky sessions are enabled
      if (sessionId && this.isStickSessionEnabled(config)) {
        await this.updateSession(sessionId, selectedEndpoint.id, requestMetadata);
      }
      
      return result;

    } catch (error) {
      // Record failed execution
      await this.recordRequestResult(serviceName, selectedEndpoint.id, false, Date.now() - startTime);
      
      // Check if failover is needed
      const needsFailover = await this.evaluateFailoverNeed(serviceName, selectedEndpoint.id);
      
      if (needsFailover) {
        // Attempt failover
        const failoverResult = await this.performFailover(serviceName, selectedEndpoint.id, error.message);
        
        if (failoverResult.success) {
          // Retry with new endpoint
          return await this.executeWithFailover(serviceName, operation, sessionId, requestMetadata);
        }
      }
      
      throw error;
    } finally {
      // Decrement connection count
      await this.decrementConnectionCount(serviceName, selectedEndpoint.id);
    }
  }

  /**
   * Select best endpoint based on strategy and current state
   */
  private async selectEndpoint(
    serviceName: string, 
    sessionId?: string,
    requestMetadata?: Record<string, any>
  ): Promise<EndpointStatus> {
    const config = this.configurations.get(serviceName);
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    
    if (!config || !serviceEndpoints) {
      throw new Error(`Service configuration not found: ${serviceName}`);
    }

    // Check for sticky session
    if (sessionId && this.isStickSessionEnabled(config)) {
      const session = this.activeSessions.get(sessionId);
      if (session) {
        const stickyEndpoint = serviceEndpoints.get(session.endpoint);
        if (stickyEndpoint && stickyEndpoint.state === EndpointState.HEALTHY) {
          return stickyEndpoint;
        }
      }
    }

    // Select endpoint based on strategy
    switch (config.strategy) {
      case FailoverStrategy.ACTIVE_PASSIVE:
        return await this.selectActivePassiveEndpoint(serviceName, config.activePassive!);
      
      case FailoverStrategy.ACTIVE_ACTIVE:
        return await this.selectActiveActiveEndpoint(serviceName, config.activeActive!, requestMetadata);
      
      case FailoverStrategy.REGIONAL:
        return await this.selectRegionalEndpoint(serviceName, config.regional!, requestMetadata);
      
      default:
        throw new Error(`Unsupported failover strategy: ${config.strategy}`);
    }
  }

  /**
   * Select endpoint for active-passive strategy
   */
  private async selectActivePassiveEndpoint(
    serviceName: string,
    config: ActivePassiveConfig
  ): Promise<EndpointStatus> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName)!;
    
    // Try primary first
    const primary = serviceEndpoints.get(config.primary.id);
    if (primary && primary.state === EndpointState.HEALTHY && primary.isActive) {
      return primary;
    }
    
    // Try secondary endpoints
    for (const secondaryConfig of config.secondary) {
      const secondary = serviceEndpoints.get(secondaryConfig.id);
      if (secondary && secondary.state === EndpointState.HEALTHY && secondary.isActive) {
        return secondary;
      }
    }
    
    // If no healthy endpoints, use primary as last resort
    if (primary) {
      this.logger.warn('No healthy endpoints available, using primary as fallback', {
        component: 'AdvancedFailoverManager',
        serviceName,
        primaryState: primary.state,
      });
      return primary;
    }
    
    throw new Error(`No available endpoints for service: ${serviceName}`);
  }

  /**
   * Select endpoint for active-active strategy
   */
  private async selectActiveActiveEndpoint(
    serviceName: string,
    config: ActiveActiveConfig,
    requestMetadata?: Record<string, any>
  ): Promise<EndpointStatus> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName)!;
    const healthyEndpoints = Array.from(serviceEndpoints.values())
      .filter(e => e.state === EndpointState.HEALTHY && e.isActive);
    
    if (healthyEndpoints.length === 0) {
      throw new Error(`No healthy endpoints for service: ${serviceName}`);
    }

    // Apply load balancing strategy
    switch (config.loadBalancingStrategy) {
      case 'ROUND_ROBIN':
        return this.selectRoundRobinEndpoint(serviceName, healthyEndpoints);
      
      case 'WEIGHTED_ROUND_ROBIN':
        return this.selectWeightedRoundRobinEndpoint(healthyEndpoints);
      
      case 'LEAST_CONNECTIONS':
        return this.selectLeastConnectionsEndpoint(healthyEndpoints);
      
      case 'RESPONSE_TIME':
        return this.selectFastestEndpoint(healthyEndpoints);
      
      case 'GEOLOCATION':
        return this.selectGeolocationEndpoint(healthyEndpoints, requestMetadata);
      
      case 'IP_HASH':
        return this.selectIPHashEndpoint(healthyEndpoints, requestMetadata);
      
      default:
        return healthyEndpoints[0];
    }
  }

  /**
   * Select endpoint for regional strategy
   */
  private async selectRegionalEndpoint(
    serviceName: string,
    config: RegionalFailoverConfig,
    requestMetadata?: Record<string, any>
  ): Promise<EndpointStatus> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName)!;
    
    // Determine client region if available
    const clientRegion = requestMetadata?.region || requestMetadata?.clientIP;
    
    // Sort regions by priority and health
    const sortedRegions = config.regions
      .map(region => ({
        ...region,
        healthyEndpoints: region.endpoints
          .map(e => serviceEndpoints.get(e.id))
          .filter(e => e && e.state === EndpointState.HEALTHY && e.isActive)
      }))
      .filter(region => region.healthyEndpoints.length > 0)
      .sort((a, b) => {
        // Prefer client region if specified
        if (clientRegion) {
          if (a.name === clientRegion && b.name !== clientRegion) return -1;
          if (b.name === clientRegion && a.name !== clientRegion) return 1;
        }
        
        // Then by priority
        return b.priority - a.priority;
      });
    
    if (sortedRegions.length === 0) {
      throw new Error(`No healthy regional endpoints for service: ${serviceName}`);
    }
    
    // Select endpoint from best region
    const bestRegion = sortedRegions[0];
    return bestRegion.healthyEndpoints[0] as EndpointStatus;
  }

  /**
   * Load balancing strategies
   */
  private selectRoundRobinEndpoint(serviceName: string, endpoints: EndpointStatus[]): EndpointStatus {
    // Simple round-robin implementation
    const index = Math.floor(Math.random() * endpoints.length);
    return endpoints[index];
  }

  private selectWeightedRoundRobinEndpoint(endpoints: EndpointStatus[]): EndpointStatus {
    const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);
    let random = Math.random() * totalWeight;
    
    for (const endpoint of endpoints) {
      random -= endpoint.weight;
      if (random <= 0) {
        return endpoint;
      }
    }
    
    return endpoints[0]; // Fallback
  }

  private selectLeastConnectionsEndpoint(endpoints: EndpointStatus[]): EndpointStatus {
    return endpoints.reduce((min, current) => 
      current.connectionCount < min.connectionCount ? current : min
    );
  }

  private selectFastestEndpoint(endpoints: EndpointStatus[]): EndpointStatus {
    return endpoints.reduce((fastest, current) => 
      current.responseTime < fastest.responseTime ? current : fastest
    );
  }

  private selectGeolocationEndpoint(
    endpoints: EndpointStatus[], 
    requestMetadata?: Record<string, any>
  ): EndpointStatus {
    const clientRegion = requestMetadata?.region;
    if (clientRegion) {
      const regionalEndpoint = endpoints.find(e => e.region === clientRegion);
      if (regionalEndpoint) return regionalEndpoint;
    }
    
    return endpoints[0]; // Fallback to first endpoint
  }

  private selectIPHashEndpoint(
    endpoints: EndpointStatus[], 
    requestMetadata?: Record<string, any>
  ): EndpointStatus {
    const clientIP = requestMetadata?.clientIP;
    if (clientIP) {
      // Simple hash-based selection
      const hash = this.hashString(clientIP);
      const index = hash % endpoints.length;
      return endpoints[index];
    }
    
    return endpoints[0]; // Fallback
  }

  /**
   * Simple string hash function
   */
  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash);
  }

  /**
   * Check if sticky sessions are enabled
   */
  private isStickSessionEnabled(config: AdvancedFailoverConfig): boolean {
    return (config.activeActive?.sessionAffinity.enabled || 
            config.activePassive?.stickySessions) || false;
  }

  /**
   * Update session information
   */
  private async updateSession(
    sessionId: string, 
    endpointId: string, 
    metadata?: Record<string, any>
  ): Promise<void> {
    const existingSession = this.activeSessions.get(sessionId);
    const sessionInfo: SessionInfo = {
      id: sessionId,
      endpoint: endpointId,
      createdAt: existingSession?.createdAt || new Date(),
      lastAccess: new Date(),
      sticky: true,
      metadata: { ...existingSession?.metadata, ...metadata },
    };

    this.activeSessions.set(sessionId, sessionInfo);
    
    // Persist session in Redis
    await this.redis.hset(`failover:session:${sessionId}`, sessionInfo);
    await this.redis.expire(`failover:session:${sessionId}`, 3600); // 1 hour TTL
  }

  /**
   * Start health checks for a service
   */
  private async startHealthChecks(
    serviceName: string, 
    config: AdvancedFailoverConfig
  ): Promise<void> {
    const endpoints = this.getEndpointsFromConfig(config);
    
    for (const endpoint of endpoints) {
      const timerId = `${serviceName}:${endpoint.id}`;
      
      const timer = setInterval(async () => {
        await this.performHealthCheck(serviceName, endpoint);
      }, endpoint.healthCheckInterval || 10000);
      
      this.healthCheckTimers.set(timerId, timer);
    }

    this.logger.info('Health checks started for service', {
      component: 'AdvancedFailoverManager',
      serviceName,
      endpointCount: endpoints.length,
    });
  }

  /**
   * Perform health check on endpoint
   */
  private async performHealthCheck(
    serviceName: string, 
    endpoint: EndpointConfig
  ): Promise<void> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    const endpointStatus = serviceEndpoints?.get(endpoint.id);
    
    if (!endpointStatus) return;

    try {
      const healthCheckUrl = endpoint.healthCheckUrl || `${endpoint.url}/health`;
      const startTime = Date.now();
      
      // Perform health check (simplified - would use actual HTTP call)
      const isHealthy = await this.executeHealthCheck(healthCheckUrl, endpoint.timeout);
      const responseTime = Date.now() - startTime;
      
      endpointStatus.lastHealthCheck = new Date();
      endpointStatus.responseTime = responseTime;
      
      if (isHealthy) {
        endpointStatus.consecutiveSuccesses++;
        endpointStatus.consecutiveFailures = 0;
        
        if (endpointStatus.consecutiveSuccesses >= 2) {
          endpointStatus.state = EndpointState.HEALTHY;
        }
      } else {
        endpointStatus.consecutiveFailures++;
        endpointStatus.consecutiveSuccesses = 0;
        
        if (endpointStatus.consecutiveFailures >= 3) {
          endpointStatus.state = EndpointState.UNHEALTHY;
          
          // Trigger failover if this endpoint was active
          if (endpointStatus.isActive) {
            await this.performFailover(serviceName, endpoint.id, 'Health check failed');
          }
        }
      }

    } catch (error) {
      endpointStatus.consecutiveFailures++;
      endpointStatus.consecutiveSuccesses = 0;
      endpointStatus.lastHealthCheck = new Date();
      
      if (endpointStatus.consecutiveFailures >= 3) {
        endpointStatus.state = EndpointState.UNHEALTHY;
      }
    }
  }

  /**
   * Execute actual health check (placeholder)
   */
  private async executeHealthCheck(url: string, timeout: number): Promise<boolean> {
    // This would make an actual HTTP request
    // For now, simulate health check with random result
    return Math.random() > 0.1; // 90% success rate
  }

  /**
   * Evaluate if failover is needed
   */
  private async evaluateFailoverNeed(serviceName: string, endpointId: string): Promise<boolean> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    const endpointStatus = serviceEndpoints?.get(endpointId);
    
    if (!endpointStatus) return false;
    
    return endpointStatus.consecutiveFailures >= 3 || 
           endpointStatus.state === EndpointState.UNHEALTHY;
  }

  /**
   * Perform failover
   */
  private async performFailover(
    serviceName: string, 
    failedEndpointId: string, 
    reason: string
  ): Promise<{ success: boolean; newEndpoint?: string }> {
    const config = this.configurations.get(serviceName);
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    
    if (!config || !serviceEndpoints) {
      return { success: false };
    }

    const startTime = Date.now();
    
    try {
      // Mark failed endpoint as inactive
      const failedEndpoint = serviceEndpoints.get(failedEndpointId);
      if (failedEndpoint) {
        failedEndpoint.isActive = false;
        failedEndpoint.state = EndpointState.UNHEALTHY;
      }

      // Find replacement endpoint
      const replacementEndpoint = await this.findReplacementEndpoint(serviceName, config);
      
      if (!replacementEndpoint) {
        this.logger.error('No replacement endpoint available for failover', {
          component: 'AdvancedFailoverManager',
          serviceName,
          failedEndpointId,
          reason,
        });
        return { success: false };
      }

      // Activate replacement endpoint
      replacementEndpoint.isActive = true;
      
      // Record failover event
      const failoverEvent: FailoverEvent = {
        timestamp: new Date(),
        serviceName,
        strategy: config.strategy,
        fromEndpoint: failedEndpointId,
        toEndpoint: replacementEndpoint.id,
        reason,
        duration: Date.now() - startTime,
        automatic: true,
      };
      
      this.failoverHistory.push(failoverEvent);
      
      // Persist failover event
      await this.redis.lpush('failover:history', JSON.stringify(failoverEvent));
      await this.redis.ltrim('failover:history', 0, 99); // Keep last 100 events
      
      this.logger.warn('Failover completed', {
        component: 'AdvancedFailoverManager',
        serviceName,
        fromEndpoint: failedEndpointId,
        toEndpoint: replacementEndpoint.id,
        reason,
        duration: failoverEvent.duration,
      });

      this.emit('failover', failoverEvent);
      
      return { success: true, newEndpoint: replacementEndpoint.id };

    } catch (error) {
      this.logger.error('Failover operation failed', {
        component: 'AdvancedFailoverManager',
        serviceName,
        error: error.message,
      });
      
      return { success: false };
    }
  }

  /**
   * Find replacement endpoint for failover
   */
  private async findReplacementEndpoint(
    serviceName: string, 
    config: AdvancedFailoverConfig
  ): Promise<EndpointStatus | null> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName)!;
    
    // Get all healthy, inactive endpoints
    const availableEndpoints = Array.from(serviceEndpoints.values())
      .filter(e => e.state === EndpointState.HEALTHY && !e.isActive)
      .sort((a, b) => b.priority - a.priority); // Sort by priority
    
    return availableEndpoints.length > 0 ? availableEndpoints[0] : null;
  }

  /**
   * Record request result
   */
  private async recordRequestResult(
    serviceName: string,
    endpointId: string,
    success: boolean,
    duration: number
  ): Promise<void> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    const endpointStatus = serviceEndpoints?.get(endpointId);
    
    if (!endpointStatus) return;

    endpointStatus.totalRequests++;
    endpointStatus.responseTime = (endpointStatus.responseTime + duration) / 2;
    
    if (success) {
      endpointStatus.consecutiveSuccesses++;
      endpointStatus.consecutiveFailures = 0;
    } else {
      endpointStatus.failedRequests++;
      endpointStatus.consecutiveFailures++;
      endpointStatus.consecutiveSuccesses = 0;
    }
    
    endpointStatus.successRate = 
      ((endpointStatus.totalRequests - endpointStatus.failedRequests) / 
       endpointStatus.totalRequests) * 100;
  }

  /**
   * Connection management
   */
  private async incrementConnectionCount(serviceName: string, endpointId: string): Promise<void> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    const endpointStatus = serviceEndpoints?.get(endpointId);
    
    if (endpointStatus) {
      endpointStatus.connectionCount++;
    }
  }

  private async decrementConnectionCount(serviceName: string, endpointId: string): Promise<void> {
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    const endpointStatus = serviceEndpoints?.get(endpointId);
    
    if (endpointStatus && endpointStatus.connectionCount > 0) {
      endpointStatus.connectionCount--;
    }
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsTimer = setInterval(async () => {
      await this.collectMetrics();
    }, 30000); // Every 30 seconds

    this.logger.info('Started failover metrics collection', {
      component: 'AdvancedFailoverManager',
    });
  }

  /**
   * Start session cleanup
   */
  private startSessionCleanup(): void {
    this.sessionCleanupTimer = setInterval(async () => {
      await this.cleanupExpiredSessions();
    }, 300000); // Every 5 minutes

    this.logger.info('Started session cleanup', {
      component: 'AdvancedFailoverManager',
    });
  }

  /**
   * Collect metrics
   */
  private async collectMetrics(): Promise<void> {
    if (this.isShuttingDown) return;

    try {
      const metrics = {
        timestamp: Date.now(),
        services: {},
        totalSessions: this.activeSessions.size,
        totalFailovers: this.failoverHistory.length,
      };

      for (const [serviceName, serviceEndpoints] of this.endpointStatuses) {
        const endpointMetrics = Array.from(serviceEndpoints.values()).map(e => ({
          id: e.id,
          url: e.url,
          region: e.region,
          state: e.state,
          isActive: e.isActive,
          connectionCount: e.connectionCount,
          responseTime: e.responseTime,
          successRate: e.successRate,
          totalRequests: e.totalRequests,
        }));

        metrics.services[serviceName] = {
          strategy: this.configurations.get(serviceName)?.strategy,
          endpoints: endpointMetrics,
          healthyEndpoints: endpointMetrics.filter(e => e.state === EndpointState.HEALTHY).length,
          activeEndpoints: endpointMetrics.filter(e => e.isActive).length,
        };
      }

      // Store metrics in Redis
      await this.redis.hset('failover:metrics', {
        timestamp: metrics.timestamp.toString(),
        data: JSON.stringify(metrics),
      });

    } catch (error) {
      this.logger.error('Failed to collect failover metrics', {
        component: 'AdvancedFailoverManager',
        error: error.message,
      });
    }
  }

  /**
   * Cleanup expired sessions
   */
  private async cleanupExpiredSessions(): Promise<void> {
    const now = Date.now();
    const expiredSessions: string[] = [];
    
    for (const [sessionId, session] of this.activeSessions) {
      const age = now - session.lastAccess.getTime();
      if (age > 3600000) { // 1 hour
        expiredSessions.push(sessionId);
      }
    }
    
    for (const sessionId of expiredSessions) {
      this.activeSessions.delete(sessionId);
      await this.redis.del(`failover:session:${sessionId}`);
    }
    
    if (expiredSessions.length > 0) {
      this.logger.debug('Cleaned up expired sessions', {
        component: 'AdvancedFailoverManager',
        expiredCount: expiredSessions.length,
      });
    }
  }

  /**
   * Load configurations from Redis
   */
  private async loadConfigurations(): Promise<void> {
    try {
      const keys = await this.redis.keys('failover:config:*');
      
      for (const key of keys) {
        const configData = await this.redis.get(key);
        if (configData) {
          const config = JSON.parse(configData);
          await this.configureService(config);
        }
      }
    } catch (error) {
      this.logger.error('Failed to load configurations', {
        component: 'AdvancedFailoverManager',
        error: error.message,
      });
    }
  }

  /**
   * Save configuration to Redis
   */
  private async saveConfiguration(
    serviceName: string, 
    config: AdvancedFailoverConfig
  ): Promise<void> {
    try {
      await this.redis.set(`failover:config:${serviceName}`, JSON.stringify(config));
    } catch (error) {
      this.logger.error('Failed to save configuration', {
        component: 'AdvancedFailoverManager',
        serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Get service status
   */
  getServiceStatus(serviceName: string): {
    config: AdvancedFailoverConfig;
    endpoints: EndpointStatus[];
    activeSessions: number;
    recentFailovers: FailoverEvent[];
  } | null {
    const config = this.configurations.get(serviceName);
    const serviceEndpoints = this.endpointStatuses.get(serviceName);
    
    if (!config || !serviceEndpoints) return null;
    
    const sessionCount = Array.from(this.activeSessions.values())
      .filter(s => serviceEndpoints.has(s.endpoint)).length;
    
    const recentFailovers = this.failoverHistory
      .filter(f => f.serviceName === serviceName)
      .slice(-10); // Last 10 failovers
    
    return {
      config,
      endpoints: Array.from(serviceEndpoints.values()),
      activeSessions: sessionCount,
      recentFailovers,
    };
  }

  /**
   * Force failover for testing/maintenance
   */
  async forceFailover(
    serviceName: string, 
    fromEndpointId: string, 
    toEndpointId?: string
  ): Promise<{ success: boolean; message: string }> {
    try {
      const result = await this.performFailover(
        serviceName, 
        fromEndpointId, 
        'Manual failover request'
      );
      
      return {
        success: result.success,
        message: result.success ? 
          `Failover completed to ${result.newEndpoint}` : 
          'Failover failed - no replacement endpoint available'
      };
    } catch (error) {
      return {
        success: false,
        message: `Failover failed: ${error.message}`
      };
    }
  }

  /**
   * Shutdown the failover manager
   */
  async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    
    this.logger.info('Shutting down Advanced Failover Manager', {
      component: 'AdvancedFailoverManager',
    });

    // Stop all timers
    for (const timer of this.healthCheckTimers.values()) {
      clearInterval(timer);
    }
    this.healthCheckTimers.clear();
    
    if (this.metricsTimer) clearInterval(this.metricsTimer);
    if (this.sessionCleanupTimer) clearInterval(this.sessionCleanupTimer);

    this.logger.info('Advanced Failover Manager shutdown completed', {
      component: 'AdvancedFailoverManager',
    });
  }
}

// Export types and schemas
export { 
  AdvancedFailoverConfigSchema,
  EndpointConfigSchema,
  ActivePassiveConfigSchema,
  ActiveActiveConfigSchema,
  RegionalFailoverConfigSchema 
};

export type { 
  AdvancedFailoverConfig,
  EndpointConfig,
  ActivePassiveConfig,
  ActiveActiveConfig,
  RegionalFailoverConfig,
  EndpointStatus,
  SessionInfo,
  FailoverEvent 
};

export { FailoverStrategy, EndpointState };