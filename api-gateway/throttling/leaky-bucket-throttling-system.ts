/**
 * Leaky Bucket Request Throttling System for iSECTECH
 * 
 * Provides sophisticated request throttling using leaky bucket algorithm with
 * backpressure mechanisms, adaptive controls, and seamless integration with
 * the token bucket rate limiting system for smooth traffic shaping.
 * 
 * Features:
 * - Pure leaky bucket algorithm for consistent request processing
 * - Adaptive bucket capacity based on system load
 * - Backpressure mechanisms with retry-after headers
 * - Request queuing with priority levels
 * - Integration with circuit breakers
 * - Real-time monitoring and metrics
 * - Graceful degradation under load
 * 
 * Performance Requirements:
 * - <2ms processing overhead per request
 * - Support for 50,000+ concurrent requests
 * - 99.9% request ordering accuracy
 * - Sub-second failover for backend failures
 */

import { z } from 'zod';
import * as Redis from 'ioredis';
import * as crypto from 'crypto';
import { EventEmitter } from 'events';

// Leaky Bucket Configuration Schema
export const LeakyBucketConfigSchema = z.object({
  // Basic configuration
  bucketId: z.string(),
  capacity: z.number().min(1), // Maximum number of requests in bucket
  leakRate: z.number().min(0), // Requests processed per second
  
  // Request processing
  processing: z.object({
    batchSize: z.number().min(1).default(1), // Process N requests at once
    processingInterval: z.number().min(10).default(100), // Milliseconds between processing
    maxWaitTime: z.number().min(100).default(30000), // Maximum time to wait in queue
    priorityLevels: z.number().min(1).max(10).default(3) // Number of priority levels
  }),
  
  // Adaptive behavior
  adaptive: z.object({
    enabled: z.boolean().default(true),
    loadThreshold: z.number().min(0).max(1).default(0.8), // Trigger adaptation at 80% capacity
    adjustmentFactor: z.number().min(0.1).max(2.0).default(1.2),
    evaluationInterval: z.number().min(1000).default(5000), // Milliseconds
    
    // Capacity scaling
    minCapacity: z.number().min(1).default(10),
    maxCapacity: z.number().min(1).default(1000),
    
    // Rate scaling
    minLeakRate: z.number().min(0.1).default(1),
    maxLeakRate: z.number().min(1).default(100)
  }),
  
  // Backpressure configuration
  backpressure: z.object({
    enabled: z.boolean().default(true),
    strategy: z.enum(['REJECT', 'DELAY', 'QUEUE', 'CIRCUIT_BREAKER']).default('QUEUE'),
    
    // Queue configuration
    queueCapacity: z.number().min(0).default(1000),
    queueTimeout: z.number().min(100).default(10000), // Milliseconds
    
    // Rejection configuration
    rejectionThreshold: z.number().min(0).max(1).default(0.95), // Reject at 95% capacity
    rejectionStatusCode: z.number().min(400).max(599).default(503),
    rejectionMessage: z.string().default('Service temporarily unavailable due to high load'),
    
    // Circuit breaker integration
    circuitBreakerThreshold: z.number().min(1).default(10), // Failures before opening
    circuitBreakerTimeout: z.number().min(1000).default(30000), // Milliseconds
    
    // Headers
    retryAfterHeader: z.boolean().default(true),
    queuePositionHeader: z.boolean().default(true),
    estimatedWaitTimeHeader: z.boolean().default(true)
  }),
  
  // Health and monitoring
  monitoring: z.object({
    enabled: z.boolean().default(true),
    metricsCollection: z.boolean().default(true),
    detailedLogging: z.boolean().default(false),
    
    // Performance tracking
    trackProcessingTime: z.boolean().default(true),
    trackQueueTime: z.boolean().default(true),
    trackThroughput: z.boolean().default(true),
    
    // Alerting
    alertOnHighLoad: z.boolean().default(true),
    alertThreshold: z.number().min(0).max(1).default(0.9),
    
    // Metrics retention
    metricsRetentionMinutes: z.number().min(1).default(60)
  }),
  
  // Integration settings
  integration: z.object({
    // Token bucket integration
    tokenBucketIntegration: z.boolean().default(true),
    tokenBucketId: z.string().optional(),
    
    // Circuit breaker integration
    circuitBreakerIntegration: z.boolean().default(true),
    
    // External queuing system
    externalQueue: z.object({
      enabled: z.boolean().default(false),
      type: z.enum(['REDIS', 'RABBITMQ', 'KAFKA']).default('REDIS'),
      connectionString: z.string().optional()
    }),
    
    // Load balancer integration
    loadBalancerIntegration: z.boolean().default(false),
    healthCheckEndpoint: z.string().default('/health')
  }),
  
  // Metadata
  name: z.string(),
  description: z.string().optional(),
  tags: z.array(z.string()).default([]),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const ThrottleRequestSchema = z.object({
  id: z.string(),
  timestamp: z.date(),
  priority: z.number().min(0).max(10).default(5),
  
  // Request information
  clientId: z.string().optional(),
  userId: z.string().optional(),
  ipAddress: z.string(),
  endpoint: z.string(),
  method: z.string(),
  
  // Processing requirements
  estimatedProcessingTime: z.number().min(0).default(100), // Milliseconds
  maxWaitTime: z.number().min(0).optional(),
  
  // Callback information
  callbackUrl: z.string().optional(),
  callbackHeaders: z.record(z.string()).optional(),
  
  // Context
  correlationId: z.string().optional(),
  userAgent: z.string().optional(),
  sessionId: z.string().optional()
});

export const ThrottleResultSchema = z.object({
  requestId: z.string(),
  allowed: z.boolean(),
  action: z.enum(['PROCESS_NOW', 'QUEUED', 'REJECTED', 'CIRCUIT_BREAKER_OPEN']),
  
  // Queue information
  queuePosition: z.number().optional(),
  estimatedWaitTime: z.number().optional(), // Milliseconds
  retryAfter: z.number().optional(), // Seconds
  
  // Processing information
  processingStarted: z.boolean().default(false),
  processingTime: z.number().optional(),
  
  // Headers for client
  headers: z.record(z.string()),
  
  // Status information
  bucketStatus: z.object({
    currentLoad: z.number().min(0).max(1),
    capacity: z.number(),
    leakRate: z.number(),
    queueLength: z.number(),
    processingCount: z.number()
  }),
  
  // Debug information
  debug: z.object({
    bucketId: z.string(),
    processingLatency: z.number(),
    adaptiveAdjustments: z.record(z.any()).optional(),
    circuitBreakerState: z.enum(['CLOSED', 'OPEN', 'HALF_OPEN']).optional()
  }).optional()
});

export type LeakyBucketConfig = z.infer<typeof LeakyBucketConfigSchema>;
export type ThrottleRequest = z.infer<typeof ThrottleRequestSchema>;
export type ThrottleResult = z.infer<typeof ThrottleResultSchema>;

/**
 * Request Priority Queue
 */
class PriorityRequestQueue {
  private queues: Map<number, ThrottleRequest[]> = new Map();
  private maxCapacity: number;
  private currentSize: number = 0;

  constructor(maxCapacity: number, priorityLevels: number) {
    this.maxCapacity = maxCapacity;
    
    // Initialize priority queues
    for (let i = 0; i < priorityLevels; i++) {
      this.queues.set(i, []);
    }
  }

  public enqueue(request: ThrottleRequest): boolean {
    if (this.currentSize >= this.maxCapacity) {
      return false; // Queue full
    }

    const priority = Math.min(Math.max(request.priority, 0), this.queues.size - 1);
    const queue = this.queues.get(priority)!;
    
    queue.push(request);
    this.currentSize++;
    
    return true;
  }

  public dequeue(): ThrottleRequest | null {
    // Process highest priority first
    for (let priority = this.queues.size - 1; priority >= 0; priority--) {
      const queue = this.queues.get(priority)!;
      if (queue.length > 0) {
        const request = queue.shift()!;
        this.currentSize--;
        return request;
      }
    }
    
    return null;
  }

  public peek(): ThrottleRequest | null {
    for (let priority = this.queues.size - 1; priority >= 0; priority--) {
      const queue = this.queues.get(priority)!;
      if (queue.length > 0) {
        return queue[0];
      }
    }
    
    return null;
  }

  public getPosition(requestId: string): number {
    let position = 1;
    
    for (let priority = this.queues.size - 1; priority >= 0; priority--) {
      const queue = this.queues.get(priority)!;
      const index = queue.findIndex(req => req.id === requestId);
      
      if (index !== -1) {
        return position + index;
      }
      
      position += queue.length;
    }
    
    return -1; // Not found
  }

  public remove(requestId: string): boolean {
    for (const queue of this.queues.values()) {
      const index = queue.findIndex(req => req.id === requestId);
      if (index !== -1) {
        queue.splice(index, 1);
        this.currentSize--;
        return true;
      }
    }
    
    return false;
  }

  public size(): number {
    return this.currentSize;
  }

  public isEmpty(): boolean {
    return this.currentSize === 0;
  }

  public getStats(): any {
    const stats: any = { totalSize: this.currentSize, byPriority: {} };
    
    for (const [priority, queue] of this.queues) {
      stats.byPriority[priority] = queue.length;
    }
    
    return stats;
  }
}

/**
 * Circuit Breaker for Throttling System
 */
class ThrottlingCircuitBreaker {
  private state: 'CLOSED' | 'OPEN' | 'HALF_OPEN' = 'CLOSED';
  private failures: number = 0;
  private lastFailureTime: Date = new Date(0);
  private successCount: number = 0;

  constructor(
    private threshold: number,
    private timeout: number
  ) {}

  public canProcess(): boolean {
    switch (this.state) {
      case 'CLOSED':
        return true;
        
      case 'OPEN':
        if (Date.now() - this.lastFailureTime.getTime() > this.timeout) {
          this.state = 'HALF_OPEN';
          this.successCount = 0;
          return true;
        }
        return false;
        
      case 'HALF_OPEN':
        return true;
        
      default:
        return false;
    }
  }

  public onSuccess(): void {
    this.failures = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= 3) { // Need 3 successes to close
        this.state = 'CLOSED';
      }
    }
  }

  public onFailure(): void {
    this.failures++;
    this.lastFailureTime = new Date();
    
    if (this.failures >= this.threshold) {
      this.state = 'OPEN';
    }
  }

  public getState(): 'CLOSED' | 'OPEN' | 'HALF_OPEN' {
    return this.state;
  }

  public getStats(): any {
    return {
      state: this.state,
      failures: this.failures,
      lastFailureTime: this.lastFailureTime,
      successCount: this.successCount
    };
  }
}

/**
 * Leaky Bucket Request Throttling System
 */
export class LeakyBucketThrottlingSystem extends EventEmitter {
  private config: LeakyBucketConfig;
  private redis: Redis.Redis;
  private requestQueue: PriorityRequestQueue;
  private processing: Map<string, { request: ThrottleRequest; startTime: Date }> = new Map();
  private circuitBreaker: ThrottlingCircuitBreaker;
  private metrics: Map<string, any[]> = new Map();
  private processingTimer: NodeJS.Timeout | null = null;
  private adaptiveTimer: NodeJS.Timeout | null = null;

  // Current bucket state
  private currentCapacity: number;
  private currentLeakRate: number;
  private lastLeakTime: Date = new Date();
  private currentLoad: number = 0;

  constructor(config: LeakyBucketConfig, redisClient?: Redis.Redis) {
    super();
    
    this.config = LeakyBucketConfigSchema.parse(config);
    this.currentCapacity = this.config.capacity;
    this.currentLeakRate = this.config.leakRate;
    
    // Initialize Redis client
    this.redis = redisClient || new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });
    
    // Initialize components
    this.requestQueue = new PriorityRequestQueue(
      this.config.backpressure.queueCapacity,
      this.config.processing.priorityLevels
    );
    
    this.circuitBreaker = new ThrottlingCircuitBreaker(
      this.config.backpressure.circuitBreakerThreshold,
      this.config.backpressure.circuitBreakerTimeout
    );
    
    // Start processing loop
    this.startProcessingLoop();
    
    // Start adaptive adjustment if enabled
    if (this.config.adaptive.enabled) {
      this.startAdaptiveAdjustment();
    }
    
    console.log(`Leaky bucket throttling system initialized: ${this.config.bucketId}`);
  }

  /**
   * Submit a request for throttling
   */
  public async throttleRequest(request: ThrottleRequest): Promise<ThrottleResult> {
    const startTime = Date.now();
    
    try {
      // Validate request
      const validatedRequest = ThrottleRequestSchema.parse(request);
      
      // Check circuit breaker
      if (!this.circuitBreaker.canProcess()) {
        return this.createRejectionResult(
          validatedRequest,
          'CIRCUIT_BREAKER_OPEN',
          'Service temporarily unavailable - circuit breaker open',
          startTime
        );
      }
      
      // Check if we can process immediately
      if (this.canProcessImmediately()) {
        await this.startProcessing(validatedRequest);
        
        return {
          requestId: validatedRequest.id,
          allowed: true,
          action: 'PROCESS_NOW',
          processingStarted: true,
          headers: this.generateHeaders(validatedRequest, 0, 0),
          bucketStatus: this.getBucketStatus(),
          debug: {
            bucketId: this.config.bucketId,
            processingLatency: Date.now() - startTime,
            circuitBreakerState: this.circuitBreaker.getState()
          }
        };
      }
      
      // Check backpressure strategy
      switch (this.config.backpressure.strategy) {
        case 'REJECT':
          return this.handleRejection(validatedRequest, startTime);
          
        case 'QUEUE':
          return this.handleQueueing(validatedRequest, startTime);
          
        case 'DELAY':
          return this.handleDelay(validatedRequest, startTime);
          
        case 'CIRCUIT_BREAKER':
          this.circuitBreaker.onFailure();
          return this.createRejectionResult(
            validatedRequest,
            'CIRCUIT_BREAKER_OPEN',
            'Service capacity exceeded - circuit breaker activated',
            startTime
          );
          
        default:
          return this.handleQueueing(validatedRequest, startTime);
      }
      
    } catch (error) {
      console.error('Error in throttleRequest:', error);
      this.circuitBreaker.onFailure();
      
      // Fail-open: allow request in case of system errors
      return {
        requestId: request.id,
        allowed: true,
        action: 'PROCESS_NOW',
        processingStarted: false,
        headers: { 'X-Throttle-Error': 'true' },
        bucketStatus: this.getBucketStatus(),
        debug: {
          bucketId: this.config.bucketId,
          processingLatency: Date.now() - startTime,
          circuitBreakerState: this.circuitBreaker.getState()
        }
      };
    }
  }

  /**
   * Complete processing of a request
   */
  public async completeProcessing(requestId: string, success: boolean = true): Promise<void> {
    const processingInfo = this.processing.get(requestId);
    if (!processingInfo) {
      console.warn(`Request ${requestId} not found in processing map`);
      return;
    }
    
    const processingTime = Date.now() - processingInfo.startTime.getTime();
    this.processing.delete(requestId);
    
    // Update metrics
    if (this.config.monitoring.trackProcessingTime) {
      this.recordMetric('processing_time', processingTime);
    }
    
    // Update circuit breaker
    if (success) {
      this.circuitBreaker.onSuccess();
    } else {
      this.circuitBreaker.onFailure();
    }
    
    // Emit completion event
    this.emit('requestCompleted', {
      requestId,
      success,
      processingTime,
      bucketLoad: this.getCurrentLoad()
    });
    
    console.debug(`Request ${requestId} completed in ${processingTime}ms (success: ${success})`);
  }

  /**
   * Get current throttling status
   */
  public getStatus(): any {
    return {
      bucketId: this.config.bucketId,
      configuration: {
        capacity: this.currentCapacity,
        leakRate: this.currentLeakRate,
        adaptive: this.config.adaptive.enabled
      },
      currentState: {
        load: this.getCurrentLoad(),
        queueLength: this.requestQueue.size(),
        processingCount: this.processing.size,
        lastLeakTime: this.lastLeakTime
      },
      circuitBreaker: this.circuitBreaker.getStats(),
      queue: this.requestQueue.getStats(),
      metrics: this.getMetricsSummary()
    };
  }

  // Private methods

  private canProcessImmediately(): boolean {
    const currentTime = new Date();
    
    // Perform leak calculation
    this.performLeak(currentTime);
    
    // Check if we have capacity
    return this.getCurrentLoad() < 1.0 && this.processing.size < this.currentCapacity;
  }

  private performLeak(currentTime: Date): void {
    const timeDiff = (currentTime.getTime() - this.lastLeakTime.getTime()) / 1000; // Convert to seconds
    
    if (timeDiff > 0) {
      const leaksToProcess = Math.floor(this.currentLeakRate * timeDiff);
      
      if (leaksToProcess > 0) {
        // Process requests from queue
        for (let i = 0; i < leaksToProcess && !this.requestQueue.isEmpty(); i++) {
          const request = this.requestQueue.dequeue();
          if (request) {
            this.startProcessing(request).catch(error => {
              console.error(`Error starting processing for request ${request.id}:`, error);
            });
          }
        }
        
        this.lastLeakTime = currentTime;
      }
    }
  }

  private async startProcessing(request: ThrottleRequest): Promise<void> {
    this.processing.set(request.id, {
      request,
      startTime: new Date()
    });
    
    // Emit processing started event
    this.emit('processingStarted', {
      requestId: request.id,
      queueTime: Date.now() - request.timestamp.getTime(),
      bucketLoad: this.getCurrentLoad()
    });
    
    console.debug(`Started processing request ${request.id}`);
  }

  private handleRejection(request: ThrottleRequest, startTime: number): ThrottleResult {
    const retryAfter = this.calculateRetryAfter();
    
    return this.createRejectionResult(
      request,
      'REJECTED',
      this.config.backpressure.rejectionMessage,
      startTime,
      retryAfter
    );
  }

  private handleQueueing(request: ThrottleRequest, startTime: number): ThrottleResult {
    const queued = this.requestQueue.enqueue(request);
    
    if (!queued) {
      return this.createRejectionResult(
        request,
        'REJECTED',
        'Queue capacity exceeded',
        startTime,
        this.calculateRetryAfter()
      );
    }
    
    const position = this.requestQueue.getPosition(request.id);
    const estimatedWaitTime = this.calculateEstimatedWaitTime(position);
    
    // Set up timeout for request
    setTimeout(() => {
      if (this.requestQueue.remove(request.id)) {
        this.emit('requestTimeout', {
          requestId: request.id,
          waitTime: Date.now() - startTime
        });
      }
    }, request.maxWaitTime || this.config.backpressure.queueTimeout);
    
    return {
      requestId: request.id,
      allowed: false,
      action: 'QUEUED',
      queuePosition: position,
      estimatedWaitTime,
      headers: this.generateHeaders(request, position, estimatedWaitTime),
      bucketStatus: this.getBucketStatus(),
      debug: {
        bucketId: this.config.bucketId,
        processingLatency: Date.now() - startTime,
        circuitBreakerState: this.circuitBreaker.getState()
      }
    };
  }

  private handleDelay(request: ThrottleRequest, startTime: number): ThrottleResult {
    const retryAfter = this.calculateRetryAfter();
    
    return {
      requestId: request.id,
      allowed: false,
      action: 'QUEUED',
      retryAfter,
      headers: this.generateHeaders(request, 0, retryAfter * 1000),
      bucketStatus: this.getBucketStatus(),
      debug: {
        bucketId: this.config.bucketId,
        processingLatency: Date.now() - startTime,
        circuitBreakerState: this.circuitBreaker.getState()
      }
    };
  }

  private createRejectionResult(
    request: ThrottleRequest,
    action: 'REJECTED' | 'CIRCUIT_BREAKER_OPEN',
    message: string,
    startTime: number,
    retryAfter?: number
  ): ThrottleResult {
    return {
      requestId: request.id,
      allowed: false,
      action,
      retryAfter,
      headers: {
        ...this.generateHeaders(request, 0, 0),
        'X-Throttle-Rejection-Reason': message,
        ...(retryAfter ? { 'Retry-After': retryAfter.toString() } : {})
      },
      bucketStatus: this.getBucketStatus(),
      debug: {
        bucketId: this.config.bucketId,
        processingLatency: Date.now() - startTime,
        circuitBreakerState: this.circuitBreaker.getState()
      }
    };
  }

  private generateHeaders(request: ThrottleRequest, position: number, waitTime: number): Record<string, string> {
    const headers: Record<string, string> = {
      'X-Throttle-Bucket-Id': this.config.bucketId,
      'X-Throttle-Bucket-Capacity': this.currentCapacity.toString(),
      'X-Throttle-Leak-Rate': this.currentLeakRate.toString(),
      'X-Throttle-Current-Load': this.getCurrentLoad().toFixed(3)
    };
    
    if (this.config.backpressure.queuePositionHeader && position > 0) {
      headers['X-Throttle-Queue-Position'] = position.toString();
    }
    
    if (this.config.backpressure.estimatedWaitTimeHeader && waitTime > 0) {
      headers['X-Throttle-Estimated-Wait-Time'] = Math.ceil(waitTime / 1000).toString();
    }
    
    if (this.config.backpressure.retryAfterHeader) {
      const retryAfter = this.calculateRetryAfter();
      headers['Retry-After'] = retryAfter.toString();
    }
    
    // Add iSECTECH specific headers
    headers['X-iSECTECH-Throttle-Algorithm'] = 'leaky-bucket';
    headers['X-iSECTECH-Throttle-Version'] = '2.0';
    
    return headers;
  }

  private getCurrentLoad(): number {
    const queueLoad = this.requestQueue.size() / this.config.backpressure.queueCapacity;
    const processingLoad = this.processing.size / this.currentCapacity;
    
    return Math.max(queueLoad, processingLoad);
  }

  private calculateRetryAfter(): number {
    const load = this.getCurrentLoad();
    const baseRetryTime = 60; // 1 minute base
    
    return Math.ceil(baseRetryTime * (1 + load));
  }

  private calculateEstimatedWaitTime(position: number): number {
    if (position <= 0 || this.currentLeakRate === 0) {
      return 0;
    }
    
    // Estimate based on current leak rate and position
    return Math.ceil((position / this.currentLeakRate) * 1000); // Convert to milliseconds
  }

  private getBucketStatus(): any {
    return {
      currentLoad: this.getCurrentLoad(),
      capacity: this.currentCapacity,
      leakRate: this.currentLeakRate,
      queueLength: this.requestQueue.size(),
      processingCount: this.processing.size
    };
  }

  private startProcessingLoop(): void {
    this.processingTimer = setInterval(() => {
      const currentTime = new Date();
      this.performLeak(currentTime);
    }, this.config.processing.processingInterval);
  }

  private startAdaptiveAdjustment(): void {
    this.adaptiveTimer = setInterval(() => {
      this.performAdaptiveAdjustment();
    }, this.config.adaptive.evaluationInterval);
  }

  private performAdaptiveAdjustment(): void {
    const currentLoad = this.getCurrentLoad();
    
    if (currentLoad > this.config.adaptive.loadThreshold) {
      // System under load - increase capacity and/or leak rate
      const adjustment = this.config.adaptive.adjustmentFactor;
      
      // Increase leak rate first
      const newLeakRate = Math.min(
        this.currentLeakRate * adjustment,
        this.config.adaptive.maxLeakRate
      );
      
      // If leak rate is at max, increase capacity
      if (newLeakRate >= this.config.adaptive.maxLeakRate && 
          this.currentCapacity < this.config.adaptive.maxCapacity) {
        this.currentCapacity = Math.min(
          Math.ceil(this.currentCapacity * adjustment),
          this.config.adaptive.maxCapacity
        );
      }
      
      this.currentLeakRate = newLeakRate;
      
      console.log(`Adaptive adjustment: Load ${currentLoad.toFixed(3)}, ` +
        `LeakRate ${this.currentLeakRate}, Capacity ${this.currentCapacity}`);
      
      // Emit adjustment event
      this.emit('adaptiveAdjustment', {
        bucketId: this.config.bucketId,
        trigger: 'HIGH_LOAD',
        adjustments: {
          leakRate: this.currentLeakRate,
          capacity: this.currentCapacity
        },
        metrics: {
          load: currentLoad,
          queueLength: this.requestQueue.size(),
          processingCount: this.processing.size
        }
      });
    } else if (currentLoad < this.config.adaptive.loadThreshold * 0.5) {
      // System under-utilized - reduce capacity and/or leak rate to save resources
      const adjustment = 1 / this.config.adaptive.adjustmentFactor;
      
      // Reduce capacity first
      if (this.currentCapacity > this.config.adaptive.minCapacity) {
        this.currentCapacity = Math.max(
          Math.floor(this.currentCapacity * adjustment),
          this.config.adaptive.minCapacity
        );
      }
      
      // Then reduce leak rate if needed
      this.currentLeakRate = Math.max(
        this.currentLeakRate * adjustment,
        this.config.adaptive.minLeakRate
      );
      
      console.debug(`Adaptive reduction: Load ${currentLoad.toFixed(3)}, ` +
        `LeakRate ${this.currentLeakRate}, Capacity ${this.currentCapacity}`);
    }
  }

  private recordMetric(type: string, value: number): void {
    if (!this.config.monitoring.metricsCollection) {
      return;
    }
    
    const metrics = this.metrics.get(type) || [];
    const timestamp = Date.now();
    
    metrics.push({ timestamp, value });
    
    // Keep only recent metrics
    const cutoff = timestamp - (this.config.monitoring.metricsRetentionMinutes * 60 * 1000);
    const recentMetrics = metrics.filter(m => m.timestamp > cutoff);
    
    this.metrics.set(type, recentMetrics);
  }

  private getMetricsSummary(): any {
    const summary: any = {};
    
    for (const [type, metrics] of this.metrics) {
      if (metrics.length === 0) {
        summary[type] = { count: 0 };
        continue;
      }
      
      const values = metrics.map(m => m.value);
      summary[type] = {
        count: values.length,
        avg: values.reduce((sum, val) => sum + val, 0) / values.length,
        min: Math.min(...values),
        max: Math.max(...values),
        recent: values.slice(-10) // Last 10 values
      };
    }
    
    return summary;
  }

  /**
   * Shutdown the throttling system
   */
  public async shutdown(): Promise<void> {
    console.log(`Shutting down leaky bucket throttling system: ${this.config.bucketId}`);
    
    // Stop timers
    if (this.processingTimer) {
      clearInterval(this.processingTimer);
    }
    
    if (this.adaptiveTimer) {
      clearInterval(this.adaptiveTimer);
    }
    
    // Process remaining queue
    let processed = 0;
    while (!this.requestQueue.isEmpty() && processed < 100) { // Process up to 100 remaining
      const request = this.requestQueue.dequeue();
      if (request) {
        await this.startProcessing(request);
        processed++;
      }
    }
    
    // Close Redis connection
    try {
      await this.redis.quit();
    } catch (error) {
      console.error('Error closing Redis connection:', error);
    }
    
    console.log(`Throttling system shutdown complete (processed ${processed} remaining requests)`);
  }
}

// Export configured instances for different iSECTECH service tiers

export const isectechHighSecurityThrottler = new LeakyBucketThrottlingSystem({
  bucketId: 'isectech-high-security-throttler',
  name: 'High Security Services Throttler',
  capacity: 50, // Lower capacity for security services
  leakRate: 2, // Process 2 requests per second
  
  processing: {
    batchSize: 1,
    processingInterval: 500, // More frequent processing
    maxWaitTime: 30000, // 30 seconds max wait
    priorityLevels: 5 // More priority levels for security
  },
  
  adaptive: {
    enabled: true,
    loadThreshold: 0.7, // Lower threshold for security services
    adjustmentFactor: 1.1, // Conservative adjustments
    evaluationInterval: 3000, // More frequent evaluation
    minCapacity: 20,
    maxCapacity: 100,
    minLeakRate: 1,
    maxLeakRate: 10
  },
  
  backpressure: {
    enabled: true,
    strategy: 'QUEUE',
    queueCapacity: 200,
    queueTimeout: 20000, // Shorter timeout for security
    rejectionThreshold: 0.9,
    rejectionStatusCode: 429,
    rejectionMessage: 'High-security service temporarily at capacity',
    circuitBreakerThreshold: 5,
    circuitBreakerTimeout: 60000,
    retryAfterHeader: true,
    queuePositionHeader: true,
    estimatedWaitTimeHeader: true
  },
  
  monitoring: {
    enabled: true,
    metricsCollection: true,
    detailedLogging: true, // Detailed logging for security services
    trackProcessingTime: true,
    trackQueueTime: true,
    trackThroughput: true,
    alertOnHighLoad: true,
    alertThreshold: 0.8,
    metricsRetentionMinutes: 120 // Longer retention for security
  },
  
  integration: {
    tokenBucketIntegration: true,
    tokenBucketId: 'isectech-high-security-global',
    circuitBreakerIntegration: true,
    externalQueue: { enabled: false, type: 'REDIS' },
    loadBalancerIntegration: true,
    healthCheckEndpoint: '/health'
  },
  
  tags: ['isectech', 'high-security', 'throttling', 'production'],
  createdAt: new Date(),
  updatedAt: new Date()
});

export const isectechStandardThrottler = new LeakyBucketThrottlingSystem({
  bucketId: 'isectech-standard-throttler',
  name: 'Standard Services Throttler',
  capacity: 200,
  leakRate: 10, // Process 10 requests per second
  
  processing: {
    batchSize: 2, // Process 2 at once for efficiency
    processingInterval: 100, // More frequent
    maxWaitTime: 60000, // 1 minute max wait
    priorityLevels: 3
  },
  
  adaptive: {
    enabled: true,
    loadThreshold: 0.8,
    adjustmentFactor: 1.3, // More aggressive adjustments
    evaluationInterval: 5000,
    minCapacity: 50,
    maxCapacity: 500,
    minLeakRate: 5,
    maxLeakRate: 50
  },
  
  backpressure: {
    enabled: true,
    strategy: 'QUEUE',
    queueCapacity: 1000,
    queueTimeout: 30000,
    rejectionThreshold: 0.95,
    rejectionStatusCode: 503,
    rejectionMessage: 'Service temporarily at capacity',
    circuitBreakerThreshold: 10,
    circuitBreakerTimeout: 30000,
    retryAfterHeader: true,
    queuePositionHeader: true,
    estimatedWaitTimeHeader: true
  },
  
  monitoring: {
    enabled: true,
    metricsCollection: true,
    detailedLogging: false, // Basic logging for standard services
    trackProcessingTime: true,
    trackQueueTime: true,
    trackThroughput: true,
    alertOnHighLoad: true,
    alertThreshold: 0.9,
    metricsRetentionMinutes: 60
  },
  
  integration: {
    tokenBucketIntegration: true,
    tokenBucketId: 'isectech-standard-global',
    circuitBreakerIntegration: true,
    externalQueue: { enabled: false, type: 'REDIS' },
    loadBalancerIntegration: true,
    healthCheckEndpoint: '/health'
  },
  
  tags: ['isectech', 'standard', 'throttling', 'production'],
  createdAt: new Date(),
  updatedAt: new Date()
});

export const isectechEventProcessingThrottler = new LeakyBucketThrottlingSystem({
  bucketId: 'isectech-event-processing-throttler',
  name: 'Event Processing Throttler',
  capacity: 1000, // Large capacity for events
  leakRate: 50, // Process 50 events per second
  
  processing: {
    batchSize: 10, // Process 10 events at once
    processingInterval: 50, // Very frequent processing
    maxWaitTime: 10000, // Short wait for events
    priorityLevels: 3
  },
  
  adaptive: {
    enabled: true,
    loadThreshold: 0.9, // Higher threshold for events
    adjustmentFactor: 2.0, // Aggressive scaling for events
    evaluationInterval: 1000, // Very frequent evaluation
    minCapacity: 100,
    maxCapacity: 5000,
    minLeakRate: 10,
    maxLeakRate: 500
  },
  
  backpressure: {
    enabled: true,
    strategy: 'QUEUE',
    queueCapacity: 5000, // Large queue for events
    queueTimeout: 5000, // Short timeout for real-time events
    rejectionThreshold: 0.98,
    rejectionStatusCode: 503,
    rejectionMessage: 'Event processing system at capacity',
    circuitBreakerThreshold: 20,
    circuitBreakerTimeout: 10000,
    retryAfterHeader: true,
    queuePositionHeader: false, // Don't need position for events
    estimatedWaitTimeHeader: true
  },
  
  monitoring: {
    enabled: true,
    metricsCollection: true,
    detailedLogging: false,
    trackProcessingTime: true,
    trackQueueTime: true,
    trackThroughput: true,
    alertOnHighLoad: true,
    alertThreshold: 0.95,
    metricsRetentionMinutes: 30 // Shorter retention for high-volume events
  },
  
  integration: {
    tokenBucketIntegration: false, // Events don't need token bucket
    circuitBreakerIntegration: true,
    externalQueue: { enabled: true, type: 'REDIS' }, // Use external queue for events
    loadBalancerIntegration: true,
    healthCheckEndpoint: '/health'
  },
  
  tags: ['isectech', 'event-processing', 'real-time', 'throttling'],
  createdAt: new Date(),
  updatedAt: new Date()
});