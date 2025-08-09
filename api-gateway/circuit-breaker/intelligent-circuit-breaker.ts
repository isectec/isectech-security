/**
 * Intelligent Circuit Breaker System for iSECTECH API Gateway
 * 
 * Advanced circuit breaker implementation with three states (closed, open, half-open),
 * custom failure thresholds, recovery timeouts, fallback mechanisms, and comprehensive
 * monitoring for preventing cascading failures and improving system resilience.
 * 
 * Features:
 * - Three-state circuit breaker pattern (closed, open, half-open)
 * - Per-service circuit breakers with custom configurations
 * - Failure threshold detection with sliding windows
 * - Adaptive recovery timeouts with exponential backoff
 * - Multiple fallback strategies (cache, mock, alternate service)
 * - Real-time metrics and health monitoring
 * - Integration with Kong gateway and service mesh
 */

import { Redis } from 'ioredis';
import { z } from 'zod';
import { Logger } from 'winston';
import { EventEmitter } from 'events';

// Circuit breaker state enum
export enum CircuitBreakerState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN',
}

// Configuration schemas
const CircuitBreakerConfigSchema = z.object({
  id: z.string(),
  serviceName: z.string(),
  upstreamName: z.string(),
  thresholds: z.object({
    failureThreshold: z.number().min(1).default(5), // number of failures
    failureRateThreshold: z.number().min(0).max(1).default(0.5), // 50% failure rate
    slowCallThreshold: z.number().min(1).default(10), // slow calls count
    slowCallDurationThreshold: z.number().min(100).default(5000), // 5 seconds
    minimumThroughput: z.number().min(1).default(10), // minimum calls to evaluate
  }),
  timeouts: z.object({
    initialTimeout: z.number().min(1000).default(60000), // 1 minute
    maxTimeout: z.number().min(60000).default(300000), // 5 minutes
    backoffMultiplier: z.number().min(1).default(2),
    halfOpenMaxCalls: z.number().min(1).default(3), // calls allowed in half-open
  }),
  slidingWindow: z.object({
    type: z.enum(['TIME_BASED', 'COUNT_BASED']).default('TIME_BASED'),
    size: z.number().min(10).default(60), // 60 seconds or 60 calls
    minimumThroughput: z.number().min(1).default(10),
  }),
  fallback: z.object({
    enabled: z.boolean().default(true),
    strategy: z.enum(['CACHE', 'MOCK', 'ALTERNATE_SERVICE', 'FAIL_FAST', 'CUSTOM']).default('FAIL_FAST'),
    cacheEnabled: z.boolean().default(true),
    cacheTtl: z.number().default(300), // 5 minutes
    alternateService: z.string().optional(),
    mockResponse: z.record(z.any()).optional(),
  }),
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsRetention: z.number().default(86400), // 24 hours
    alerting: z.boolean().default(true),
    healthCheckInterval: z.number().default(30000), // 30 seconds
  }),
  isEnabled: z.boolean().default(true),
  createdAt: z.date().default(() => new Date()),
  updatedAt: z.date().default(() => new Date()),
});

const SystemConfigSchema = z.object({
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(0),
    keyPrefix: z.string().default('circuit_breaker:'),
  }),
  global: z.object({
    maxCircuitBreakers: z.number().default(100),
    defaultTimeout: z.number().default(60000),
    cleanupInterval: z.number().default(300000), // 5 minutes
  }),
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsFlushInterval: z.number().default(10000), // 10 seconds
    detailedLogging: z.boolean().default(false),
  }),
});

type CircuitBreakerConfig = z.infer<typeof CircuitBreakerConfigSchema>;
type SystemConfig = z.infer<typeof SystemConfigSchema>;

interface CallResult {
  success: boolean;
  duration: number;
  timestamp: number;
  error?: string;
  statusCode?: number;
}

interface CircuitBreakerStats {
  state: CircuitBreakerState;
  failureCount: number;
  successCount: number;
  totalCalls: number;
  failureRate: number;
  slowCallCount: number;
  lastFailureTime: number;
  lastSuccessTime: number;
  stateChangedAt: number;
  nextRetryTime: number;
  halfOpenCallCount: number;
}

interface FallbackResult {
  success: boolean;
  data?: any;
  source: 'CACHE' | 'MOCK' | 'ALTERNATE_SERVICE' | 'CUSTOM';
  cached: boolean;
}

/**
 * Individual Circuit Breaker Implementation
 */
class CircuitBreaker extends EventEmitter {
  private config: CircuitBreakerConfig;
  private redis: Redis;
  private logger: Logger;
  private state: CircuitBreakerState = CircuitBreakerState.CLOSED;
  private stats: CircuitBreakerStats;
  private callHistory: CallResult[] = [];
  private stateChangedAt: number = Date.now();
  private nextRetryTime: number = 0;
  private currentTimeout: number;

  constructor(config: CircuitBreakerConfig, redis: Redis, logger: Logger) {
    super();
    this.config = CircuitBreakerConfigSchema.parse(config);
    this.redis = redis;
    this.logger = logger;
    this.currentTimeout = this.config.timeouts.initialTimeout;
    
    this.stats = {
      state: CircuitBreakerState.CLOSED,
      failureCount: 0,
      successCount: 0,
      totalCalls: 0,
      failureRate: 0,
      slowCallCount: 0,
      lastFailureTime: 0,
      lastSuccessTime: 0,
      stateChangedAt: Date.now(),
      nextRetryTime: 0,
      halfOpenCallCount: 0,
    };

    this.loadStateFromRedis();
    this.startHealthMonitoring();
  }

  /**
   * Execute a call through the circuit breaker
   */
  async execute<T>(
    operation: () => Promise<T>,
    fallbackOperation?: () => Promise<T>
  ): Promise<T> {
    if (!this.config.isEnabled) {
      return await operation();
    }

    const startTime = Date.now();

    // Check if circuit is open
    if (this.state === CircuitBreakerState.OPEN) {
      if (Date.now() < this.nextRetryTime) {
        this.logger.debug('Circuit breaker is OPEN, executing fallback', {
          component: 'CircuitBreaker',
          service: this.config.serviceName,
          nextRetry: new Date(this.nextRetryTime),
        });
        
        return await this.executeFallback(fallbackOperation);
      } else {
        // Transition to half-open
        await this.transitionToHalfOpen();
      }
    }

    // Check if we're in half-open state and have exceeded max calls
    if (this.state === CircuitBreakerState.HALF_OPEN && 
        this.stats.halfOpenCallCount >= this.config.timeouts.halfOpenMaxCalls) {
      return await this.executeFallback(fallbackOperation);
    }

    try {
      // Execute the operation
      const result = await operation();
      const duration = Date.now() - startTime;
      
      // Record successful call
      await this.recordCall({
        success: true,
        duration,
        timestamp: Date.now(),
      });

      return result;

    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Record failed call
      await this.recordCall({
        success: false,
        duration,
        timestamp: Date.now(),
        error: error.message,
        statusCode: error.statusCode,
      });

      // Execute fallback or rethrow
      if (this.config.fallback.enabled) {
        return await this.executeFallback(fallbackOperation);
      } else {
        throw error;
      }
    }
  }

  /**
   * Record call result and update circuit breaker state
   */
  private async recordCall(result: CallResult): Promise<void> {
    this.callHistory.push(result);
    this.cleanupHistory();
    
    // Update statistics
    this.stats.totalCalls++;
    
    if (result.success) {
      this.stats.successCount++;
      this.stats.lastSuccessTime = result.timestamp;
      
      // Handle half-open state
      if (this.state === CircuitBreakerState.HALF_OPEN) {
        this.stats.halfOpenCallCount++;
        
        // Check if we have enough successful calls to close the circuit
        if (this.stats.halfOpenCallCount >= this.config.timeouts.halfOpenMaxCalls) {
          await this.transitionToClosed();
        }
      }
    } else {
      this.stats.failureCount++;
      this.stats.lastFailureTime = result.timestamp;
      
      // Check for slow calls
      if (result.duration > this.config.thresholds.slowCallDurationThreshold) {
        this.stats.slowCallCount++;
      }
      
      // Transition to open if thresholds are exceeded
      if (this.shouldOpenCircuit()) {
        await this.transitionToOpen();
      }
    }
    
    // Update failure rate
    this.updateFailureRate();
    
    // Persist state
    await this.saveStateToRedis();
    
    // Emit metrics
    this.emit('callRecorded', {
      service: this.config.serviceName,
      result,
      stats: this.stats,
    });
  }

  /**
   * Determine if circuit should be opened based on failure thresholds
   */
  private shouldOpenCircuit(): boolean {
    const recentCalls = this.getRecentCalls();
    
    if (recentCalls.length < this.config.thresholds.minimumThroughput) {
      return false; // Not enough data to make a decision
    }

    const failures = recentCalls.filter(call => !call.success).length;
    const failureRate = failures / recentCalls.length;
    const slowCalls = recentCalls.filter(call => 
      call.duration > this.config.thresholds.slowCallDurationThreshold
    ).length;

    // Check failure threshold
    if (failures >= this.config.thresholds.failureThreshold) {
      return true;
    }

    // Check failure rate threshold
    if (failureRate >= this.config.thresholds.failureRateThreshold) {
      return true;
    }

    // Check slow call threshold
    if (slowCalls >= this.config.thresholds.slowCallThreshold) {
      return true;
    }

    return false;
  }

  /**
   * Get recent calls based on sliding window configuration
   */
  private getRecentCalls(): CallResult[] {
    const now = Date.now();
    
    if (this.config.slidingWindow.type === 'TIME_BASED') {
      const windowStart = now - (this.config.slidingWindow.size * 1000);
      return this.callHistory.filter(call => call.timestamp >= windowStart);
    } else {
      // COUNT_BASED
      return this.callHistory.slice(-this.config.slidingWindow.size);
    }
  }

  /**
   * Transition circuit breaker to OPEN state
   */
  private async transitionToOpen(): Promise<void> {
    const previousState = this.state;
    this.state = CircuitBreakerState.OPEN;
    this.stateChangedAt = Date.now();
    this.nextRetryTime = Date.now() + this.currentTimeout;
    this.stats.stateChangedAt = this.stateChangedAt;
    this.stats.nextRetryTime = this.nextRetryTime;
    
    // Increase timeout for next time (exponential backoff)
    this.currentTimeout = Math.min(
      this.currentTimeout * this.config.timeouts.backoffMultiplier,
      this.config.timeouts.maxTimeout
    );

    this.logger.warn('Circuit breaker transitioned to OPEN', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
      previousState,
      timeout: this.currentTimeout,
      nextRetry: new Date(this.nextRetryTime),
      stats: this.stats,
    });

    this.emit('stateChanged', {
      service: this.config.serviceName,
      previousState,
      currentState: this.state,
      timestamp: this.stateChangedAt,
    });

    await this.saveStateToRedis();
  }

  /**
   * Transition circuit breaker to HALF_OPEN state
   */
  private async transitionToHalfOpen(): Promise<void> {
    const previousState = this.state;
    this.state = CircuitBreakerState.HALF_OPEN;
    this.stateChangedAt = Date.now();
    this.stats.stateChangedAt = this.stateChangedAt;
    this.stats.halfOpenCallCount = 0;

    this.logger.info('Circuit breaker transitioned to HALF_OPEN', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
      previousState,
      maxCalls: this.config.timeouts.halfOpenMaxCalls,
    });

    this.emit('stateChanged', {
      service: this.config.serviceName,
      previousState,
      currentState: this.state,
      timestamp: this.stateChangedAt,
    });

    await this.saveStateToRedis();
  }

  /**
   * Transition circuit breaker to CLOSED state
   */
  private async transitionToClosed(): Promise<void> {
    const previousState = this.state;
    this.state = CircuitBreakerState.CLOSED;
    this.stateChangedAt = Date.now();
    this.stats.stateChangedAt = this.stateChangedAt;
    this.stats.halfOpenCallCount = 0;
    
    // Reset timeout to initial value
    this.currentTimeout = this.config.timeouts.initialTimeout;

    this.logger.info('Circuit breaker transitioned to CLOSED', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
      previousState,
    });

    this.emit('stateChanged', {
      service: this.config.serviceName,
      previousState,
      currentState: this.state,
      timestamp: this.stateChangedAt,
    });

    await this.saveStateToRedis();
  }

  /**
   * Execute fallback strategy
   */
  private async executeFallback<T>(fallbackOperation?: () => Promise<T>): Promise<T> {
    if (fallbackOperation) {
      try {
        return await fallbackOperation();
      } catch (error) {
        this.logger.error('Fallback operation failed', {
          component: 'CircuitBreaker',
          service: this.config.serviceName,
          error: error.message,
        });
        throw error;
      }
    }

    // Use configured fallback strategy
    const fallbackResult = await this.executeConfiguredFallback();
    
    if (fallbackResult.success) {
      return fallbackResult.data as T;
    } else {
      throw new Error('Circuit breaker is OPEN and no fallback available');
    }
  }

  /**
   * Execute configured fallback strategy
   */
  private async executeConfiguredFallback(): Promise<FallbackResult> {
    switch (this.config.fallback.strategy) {
      case 'CACHE':
        return await this.executeCacheFallback();
      
      case 'MOCK':
        return await this.executeMockFallback();
      
      case 'ALTERNATE_SERVICE':
        return await this.executeAlternateServiceFallback();
      
      case 'FAIL_FAST':
      default:
        return {
          success: false,
          source: 'CUSTOM',
          cached: false,
        };
    }
  }

  /**
   * Execute cache-based fallback
   */
  private async executeCacheFallback(): Promise<FallbackResult> {
    if (!this.config.fallback.cacheEnabled) {
      return { success: false, source: 'CACHE', cached: false };
    }

    try {
      const cacheKey = `fallback:${this.config.serviceName}:last_success`;
      const cachedData = await this.redis.get(cacheKey);
      
      if (cachedData) {
        return {
          success: true,
          data: JSON.parse(cachedData),
          source: 'CACHE',
          cached: true,
        };
      }
    } catch (error) {
      this.logger.error('Cache fallback failed', {
        component: 'CircuitBreaker',
        service: this.config.serviceName,
        error: error.message,
      });
    }

    return { success: false, source: 'CACHE', cached: false };
  }

  /**
   * Execute mock response fallback
   */
  private async executeMockFallback(): Promise<FallbackResult> {
    if (!this.config.fallback.mockResponse) {
      return { success: false, source: 'MOCK', cached: false };
    }

    return {
      success: true,
      data: this.config.fallback.mockResponse,
      source: 'MOCK',
      cached: false,
    };
  }

  /**
   * Execute alternate service fallback
   */
  private async executeAlternateServiceFallback(): Promise<FallbackResult> {
    if (!this.config.fallback.alternateService) {
      return { success: false, source: 'ALTERNATE_SERVICE', cached: false };
    }

    // This would typically make a call to an alternate service
    // Implementation depends on the specific service architecture
    return { success: false, source: 'ALTERNATE_SERVICE', cached: false };
  }

  /**
   * Cache successful response for fallback
   */
  async cacheSuccessfulResponse(data: any): Promise<void> {
    if (!this.config.fallback.cacheEnabled) {
      return;
    }

    try {
      const cacheKey = `fallback:${this.config.serviceName}:last_success`;
      await this.redis.setex(
        cacheKey, 
        this.config.fallback.cacheTtl, 
        JSON.stringify(data)
      );
    } catch (error) {
      this.logger.error('Failed to cache successful response', {
        component: 'CircuitBreaker',
        service: this.config.serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Update failure rate calculation
   */
  private updateFailureRate(): void {
    const recentCalls = this.getRecentCalls();
    if (recentCalls.length === 0) {
      this.stats.failureRate = 0;
      return;
    }

    const failures = recentCalls.filter(call => !call.success).length;
    this.stats.failureRate = failures / recentCalls.length;
  }

  /**
   * Clean up old call history
   */
  private cleanupHistory(): void {
    const maxHistorySize = Math.max(this.config.slidingWindow.size * 2, 1000);
    if (this.callHistory.length > maxHistorySize) {
      this.callHistory = this.callHistory.slice(-maxHistorySize);
    }
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    if (!this.config.monitoring.enabled) {
      return;
    }

    setInterval(() => {
      this.performHealthCheck();
    }, this.config.monitoring.healthCheckInterval);
  }

  /**
   * Perform health check and emit metrics
   */
  private performHealthCheck(): void {
    const healthData = {
      service: this.config.serviceName,
      state: this.state,
      stats: this.stats,
      timestamp: Date.now(),
    };

    this.emit('healthCheck', healthData);

    if (this.config.monitoring.alerting && this.state === CircuitBreakerState.OPEN) {
      this.emit('alert', {
        severity: 'WARNING',
        message: `Circuit breaker for ${this.config.serviceName} is OPEN`,
        service: this.config.serviceName,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Get current statistics
   */
  getStats(): CircuitBreakerStats {
    return { ...this.stats, state: this.state };
  }

  /**
   * Get current configuration
   */
  getConfig(): CircuitBreakerConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  async updateConfig(updates: Partial<CircuitBreakerConfig>): Promise<void> {
    this.config = CircuitBreakerConfigSchema.parse({
      ...this.config,
      ...updates,
      updatedAt: new Date(),
    });

    await this.saveStateToRedis();
    
    this.logger.info('Circuit breaker configuration updated', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
      updates,
    });
  }

  /**
   * Force state change (for testing/manual intervention)
   */
  async forceState(newState: CircuitBreakerState): Promise<void> {
    const previousState = this.state;
    
    switch (newState) {
      case CircuitBreakerState.CLOSED:
        await this.transitionToClosed();
        break;
      case CircuitBreakerState.OPEN:
        await this.transitionToOpen();
        break;
      case CircuitBreakerState.HALF_OPEN:
        await this.transitionToHalfOpen();
        break;
    }

    this.logger.warn('Circuit breaker state force changed', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
      previousState,
      newState,
      forced: true,
    });
  }

  /**
   * Reset circuit breaker statistics
   */
  async reset(): Promise<void> {
    this.callHistory = [];
    this.stats = {
      state: CircuitBreakerState.CLOSED,
      failureCount: 0,
      successCount: 0,
      totalCalls: 0,
      failureRate: 0,
      slowCallCount: 0,
      lastFailureTime: 0,
      lastSuccessTime: 0,
      stateChangedAt: Date.now(),
      nextRetryTime: 0,
      halfOpenCallCount: 0,
    };
    
    this.state = CircuitBreakerState.CLOSED;
    this.currentTimeout = this.config.timeouts.initialTimeout;
    
    await this.saveStateToRedis();
    
    this.logger.info('Circuit breaker reset', {
      component: 'CircuitBreaker',
      service: this.config.serviceName,
    });
  }

  /**
   * Save state to Redis for persistence
   */
  private async saveStateToRedis(): Promise<void> {
    try {
      const stateData = {
        config: this.config,
        state: this.state,
        stats: this.stats,
        currentTimeout: this.currentTimeout,
        stateChangedAt: this.stateChangedAt,
        nextRetryTime: this.nextRetryTime,
      };

      const key = `circuit_breaker:${this.config.serviceName}`;
      await this.redis.set(key, JSON.stringify(stateData));
      await this.redis.expire(key, 86400); // 24 hours
    } catch (error) {
      this.logger.error('Failed to save circuit breaker state to Redis', {
        component: 'CircuitBreaker',
        service: this.config.serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Load state from Redis
   */
  private async loadStateFromRedis(): Promise<void> {
    try {
      const key = `circuit_breaker:${this.config.serviceName}`;
      const stateData = await this.redis.get(key);
      
      if (stateData) {
        const parsed = JSON.parse(stateData);
        this.state = parsed.state || CircuitBreakerState.CLOSED;
        this.stats = { ...this.stats, ...parsed.stats };
        this.currentTimeout = parsed.currentTimeout || this.config.timeouts.initialTimeout;
        this.stateChangedAt = parsed.stateChangedAt || Date.now();
        this.nextRetryTime = parsed.nextRetryTime || 0;
      }
    } catch (error) {
      this.logger.error('Failed to load circuit breaker state from Redis', {
        component: 'CircuitBreaker',
        service: this.config.serviceName,
        error: error.message,
      });
    }
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    this.removeAllListeners();
    await this.saveStateToRedis();
  }
}

/**
 * Circuit Breaker Manager - manages multiple circuit breakers
 */
export class IntelligentCircuitBreakerSystem {
  private redis: Redis;
  private logger: Logger;
  private config: SystemConfig;
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private metricsTimer?: NodeJS.Timeout;
  private cleanupTimer?: NodeJS.Timeout;

  constructor(config: SystemConfig, logger: Logger) {
    this.config = SystemConfigSchema.parse(config);
    this.logger = logger;
    
    this.redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      password: this.config.redis.password,
      db: this.config.redis.db,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
    });

    this.initialize();
  }

  /**
   * Initialize the circuit breaker system
   */
  private async initialize(): Promise<void> {
    try {
      await this.loadExistingCircuitBreakers();
      this.startMetricsCollection();
      this.startCleanupTasks();
      
      this.logger.info('Circuit Breaker System initialized', {
        component: 'IntelligentCircuitBreakerSystem',
        circuitBreakers: this.circuitBreakers.size,
      });
    } catch (error) {
      this.logger.error('Failed to initialize Circuit Breaker System', {
        component: 'IntelligentCircuitBreakerSystem',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Create or get circuit breaker for a service
   */
  async getCircuitBreaker(config: CircuitBreakerConfig): Promise<CircuitBreaker> {
    const key = `${config.serviceName}_${config.upstreamName}`;
    
    if (this.circuitBreakers.has(key)) {
      return this.circuitBreakers.get(key)!;
    }

    if (this.circuitBreakers.size >= this.config.global.maxCircuitBreakers) {
      throw new Error('Maximum number of circuit breakers exceeded');
    }

    const circuitBreaker = new CircuitBreaker(config, this.redis, this.logger);
    this.circuitBreakers.set(key, circuitBreaker);

    // Set up event listeners
    this.setupCircuitBreakerListeners(circuitBreaker);

    this.logger.info('Circuit breaker created', {
      component: 'IntelligentCircuitBreakerSystem',
      service: config.serviceName,
      upstream: config.upstreamName,
    });

    return circuitBreaker;
  }

  /**
   * Execute operation with circuit breaker protection
   */
  async executeWithProtection<T>(
    serviceName: string,
    upstreamName: string,
    operation: () => Promise<T>,
    fallbackOperation?: () => Promise<T>,
    circuitBreakerConfig?: Partial<CircuitBreakerConfig>
  ): Promise<T> {
    const config: CircuitBreakerConfig = {
      id: `${serviceName}_${upstreamName}`,
      serviceName,
      upstreamName,
      ...circuitBreakerConfig,
      thresholds: {
        failureThreshold: 5,
        failureRateThreshold: 0.5,
        slowCallThreshold: 10,
        slowCallDurationThreshold: 5000,
        minimumThroughput: 10,
        ...circuitBreakerConfig?.thresholds,
      },
      timeouts: {
        initialTimeout: 60000,
        maxTimeout: 300000,
        backoffMultiplier: 2,
        halfOpenMaxCalls: 3,
        ...circuitBreakerConfig?.timeouts,
      },
      slidingWindow: {
        type: 'TIME_BASED' as const,
        size: 60,
        minimumThroughput: 10,
        ...circuitBreakerConfig?.slidingWindow,
      },
      fallback: {
        enabled: true,
        strategy: 'FAIL_FAST' as const,
        cacheEnabled: true,
        cacheTtl: 300,
        ...circuitBreakerConfig?.fallback,
      },
      monitoring: {
        enabled: true,
        metricsRetention: 86400,
        alerting: true,
        healthCheckInterval: 30000,
        ...circuitBreakerConfig?.monitoring,
      },
      isEnabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
      ...circuitBreakerConfig,
    };

    const circuitBreaker = await this.getCircuitBreaker(config);
    
    try {
      const result = await circuitBreaker.execute(operation, fallbackOperation);
      
      // Cache successful result if caching is enabled
      if (config.fallback.cacheEnabled) {
        await circuitBreaker.cacheSuccessfulResponse(result);
      }
      
      return result;
    } catch (error) {
      this.logger.error('Circuit breaker protected operation failed', {
        component: 'IntelligentCircuitBreakerSystem',
        service: serviceName,
        upstream: upstreamName,
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Get all circuit breaker statistics
   */
  getAllStats(): Record<string, CircuitBreakerStats> {
    const stats: Record<string, CircuitBreakerStats> = {};
    
    for (const [key, circuitBreaker] of this.circuitBreakers) {
      stats[key] = circuitBreaker.getStats();
    }
    
    return stats;
  }

  /**
   * Get system health summary
   */
  getSystemHealth(): {
    status: string;
    totalCircuitBreakers: number;
    openCircuitBreakers: number;
    halfOpenCircuitBreakers: number;
    alertCount: number;
  } {
    const stats = this.getAllStats();
    const values = Object.values(stats);
    
    const openCount = values.filter(s => s.state === CircuitBreakerState.OPEN).length;
    const halfOpenCount = values.filter(s => s.state === CircuitBreakerState.HALF_OPEN).length;
    
    let status = 'healthy';
    if (openCount > values.length * 0.5) {
      status = 'critical';
    } else if (openCount > 0 || halfOpenCount > 0) {
      status = 'degraded';
    }

    return {
      status,
      totalCircuitBreakers: values.length,
      openCircuitBreakers: openCount,
      halfOpenCircuitBreakers: halfOpenCount,
      alertCount: openCount + halfOpenCount,
    };
  }

  /**
   * Remove circuit breaker
   */
  async removeCircuitBreaker(serviceName: string, upstreamName: string): Promise<boolean> {
    const key = `${serviceName}_${upstreamName}`;
    const circuitBreaker = this.circuitBreakers.get(key);
    
    if (circuitBreaker) {
      await circuitBreaker.shutdown();
      this.circuitBreakers.delete(key);
      
      this.logger.info('Circuit breaker removed', {
        component: 'IntelligentCircuitBreakerSystem',
        service: serviceName,
        upstream: upstreamName,
      });
      
      return true;
    }
    
    return false;
  }

  /**
   * Load existing circuit breakers from Redis
   */
  private async loadExistingCircuitBreakers(): Promise<void> {
    try {
      const keys = await this.redis.keys('circuit_breaker:*');
      
      for (const key of keys) {
        const stateData = await this.redis.get(key);
        if (stateData) {
          const parsed = JSON.parse(stateData);
          const circuitBreaker = new CircuitBreaker(parsed.config, this.redis, this.logger);
          const cbKey = `${parsed.config.serviceName}_${parsed.config.upstreamName}`;
          this.circuitBreakers.set(cbKey, circuitBreaker);
          this.setupCircuitBreakerListeners(circuitBreaker);
        }
      }
    } catch (error) {
      this.logger.error('Failed to load existing circuit breakers', {
        component: 'IntelligentCircuitBreakerSystem',
        error: error.message,
      });
    }
  }

  /**
   * Set up event listeners for circuit breaker
   */
  private setupCircuitBreakerListeners(circuitBreaker: CircuitBreaker): void {
    circuitBreaker.on('stateChanged', (data) => {
      this.logger.info('Circuit breaker state changed', {
        component: 'IntelligentCircuitBreakerSystem',
        ...data,
      });
    });

    circuitBreaker.on('alert', (data) => {
      this.logger.warn('Circuit breaker alert', {
        component: 'IntelligentCircuitBreakerSystem',
        ...data,
      });
    });

    if (this.config.monitoring.enabled) {
      circuitBreaker.on('callRecorded', (data) => {
        if (this.config.monitoring.detailedLogging) {
          this.logger.debug('Circuit breaker call recorded', {
            component: 'IntelligentCircuitBreakerSystem',
            ...data,
          });
        }
      });

      circuitBreaker.on('healthCheck', (data) => {
        // Aggregate health data for system monitoring
      });
    }
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollection(): void {
    if (!this.config.monitoring.enabled) {
      return;
    }

    this.metricsTimer = setInterval(async () => {
      try {
        const systemHealth = this.getSystemHealth();
        const allStats = this.getAllStats();
        
        // Store metrics in Redis
        await this.redis.hset('circuit_breaker:system_metrics', {
          timestamp: Date.now().toString(),
          ...systemHealth,
          detailed_stats: JSON.stringify(allStats),
        });

        // Metrics retention
        await this.redis.expire('circuit_breaker:system_metrics', this.config.monitoring.metricsFlushInterval * 24);

      } catch (error) {
        this.logger.error('Error collecting circuit breaker metrics', {
          component: 'IntelligentCircuitBreakerSystem',
          error: error.message,
        });
      }
    }, this.config.monitoring.metricsFlushInterval);
  }

  /**
   * Start cleanup tasks
   */
  private startCleanupTasks(): void {
    this.cleanupTimer = setInterval(async () => {
      try {
        // Clean up unused circuit breakers
        // Implementation would check for inactive circuit breakers and remove them
      } catch (error) {
        this.logger.error('Error in cleanup tasks', {
          component: 'IntelligentCircuitBreakerSystem',
          error: error.message,
        });
      }
    }, this.config.global.cleanupInterval);
  }

  /**
   * Shutdown the system
   */
  async shutdown(): Promise<void> {
    try {
      // Stop timers
      if (this.metricsTimer) {
        clearInterval(this.metricsTimer);
      }
      if (this.cleanupTimer) {
        clearInterval(this.cleanupTimer);
      }

      // Shutdown all circuit breakers
      for (const circuitBreaker of this.circuitBreakers.values()) {
        await circuitBreaker.shutdown();
      }

      // Close Redis connection
      await this.redis.quit();

      this.logger.info('Circuit Breaker System shutdown completed');
    } catch (error) {
      this.logger.error('Error during Circuit Breaker System shutdown', {
        component: 'IntelligentCircuitBreakerSystem',
        error: error.message,
      });
    }
  }
}

// Export types and schemas
export { CircuitBreakerConfigSchema, SystemConfigSchema };
export type { CircuitBreakerConfig, SystemConfig, CallResult, CircuitBreakerStats, FallbackResult };