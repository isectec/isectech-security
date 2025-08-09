/**
 * Advanced Token Bucket and Leaky Bucket Rate Limiting Implementation for iSECTECH
 * 
 * Provides production-grade token bucket algorithm with leaky bucket integration,
 * adaptive rate limiting, burst control, and comprehensive monitoring for
 * multi-tenant cybersecurity platform with high-performance requirements.
 * 
 * Features:
 * - Hybrid Token Bucket + Leaky Bucket algorithm
 * - Adaptive rate limiting based on server load and traffic patterns
 * - Sub-millisecond precision with Redis Lua scripts
 * - Comprehensive rate limit headers (X-RateLimit-*)
 * - Circuit breaker integration for graceful degradation
 * - Real-time monitoring and alerting
 * 
 * Performance Requirements:
 * - <1ms latency overhead
 * - 100,000+ requests per second
 * - 99.99% accuracy in rate limiting
 * - Sub-second failover for Redis outages
 */

import { z } from 'zod';
import * as Redis from 'ioredis';
import * as crypto from 'crypto';

// Advanced Token Bucket Configuration Schema
export const TokenBucketConfigSchema = z.object({
  // Core bucket parameters
  bucketId: z.string(),
  capacity: z.number().min(1), // Maximum tokens in bucket
  refillRate: z.number().min(0), // Tokens added per second
  initialTokens: z.number().min(0).optional(), // Initial token count
  
  // Leaky bucket integration
  leakyBucket: z.object({
    enabled: z.boolean().default(false),
    leakRate: z.number().min(0), // Tokens leaked per second
    smoothing: z.boolean().default(true), // Smooth token consumption
    queueCapacity: z.number().min(0).default(0) // Request queue size
  }).optional(),
  
  // Burst control
  burstControl: z.object({
    enabled: z.boolean().default(true),
    burstCapacity: z.number().min(0).optional(), // Max burst tokens
    burstRefillRate: z.number().min(0).optional(), // Burst refill rate
    cooldownPeriod: z.number().min(0).default(60) // Seconds to cool down after burst
  }).optional(),
  
  // Adaptive control
  adaptive: z.object({
    enabled: z.boolean().default(false),
    serverLoadThreshold: z.number().min(0).max(1).default(0.8),
    trafficPattern: z.enum(['STEADY', 'BURSTY', 'SEASONAL', 'AUTO']).default('AUTO'),
    adjustmentFactor: z.number().min(0.1).max(2.0).default(1.0),
    evaluationInterval: z.number().min(1).default(60) // Seconds
  }).optional(),
  
  // Precision and performance
  precision: z.object({
    timestampPrecision: z.enum(['SECOND', 'MILLISECOND', 'MICROSECOND']).default('MILLISECOND'),
    algorithmMode: z.enum(['STANDARD', 'HIGH_PRECISION', 'LOW_LATENCY']).default('STANDARD'),
    batchProcessing: z.boolean().default(false),
    precomputation: z.boolean().default(true)
  }).optional(),
  
  // Metadata
  name: z.string(),
  description: z.string().optional(),
  tags: z.array(z.string()).default([]),
  priority: z.number().min(0).max(100).default(50),
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

export const RateLimitResultSchema = z.object({
  allowed: z.boolean(),
  tokensConsumed: z.number(),
  tokensRemaining: z.number(),
  bucketCapacity: z.number(),
  refillRate: z.number(),
  nextRefillTime: z.date(),
  retryAfter: z.number().optional(), // Seconds until tokens available
  
  // Headers for client
  headers: z.record(z.string()),
  
  // Debugging information
  debug: z.object({
    bucketState: z.any().optional(),
    processingTime: z.number(), // Milliseconds
    redisLatency: z.number().optional(),
    adaptiveAdjustment: z.number().optional(),
    circuitBreakerState: z.enum(['CLOSED', 'OPEN', 'HALF_OPEN']).optional()
  }).optional(),
  
  // Monitoring data
  metrics: z.object({
    timestamp: z.date(),
    bucketId: z.string(),
    requestId: z.string().optional(),
    clientId: z.string().optional(),
    endpoint: z.string().optional()
  })
});

export type TokenBucketConfig = z.infer<typeof TokenBucketConfigSchema>;
export type RateLimitResult = z.infer<typeof RateLimitResultSchema>;

/**
 * Redis Lua Scripts for Atomic Token Bucket Operations
 */
const LUA_SCRIPTS = {
  // Token bucket with leaky bucket integration
  tokenBucketConsume: `
    local bucket_key = KEYS[1]
    local config_key = KEYS[2]
    local tokens_requested = tonumber(ARGV[1])
    local current_time = tonumber(ARGV[2])
    local precision_multiplier = tonumber(ARGV[3]) or 1000
    
    -- Get bucket state
    local bucket_data = redis.call('HMGET', bucket_key, 
      'tokens', 'last_refill', 'capacity', 'refill_rate', 
      'burst_tokens', 'cooldown_until', 'leaky_rate')
    
    local tokens = tonumber(bucket_data[1]) or 0
    local last_refill = tonumber(bucket_data[2]) or current_time
    local capacity = tonumber(bucket_data[3]) or 100
    local refill_rate = tonumber(bucket_data[4]) or 10
    local burst_tokens = tonumber(bucket_data[5]) or 0
    local cooldown_until = tonumber(bucket_data[6]) or 0
    local leaky_rate = tonumber(bucket_data[7]) or 0
    
    -- Calculate time elapsed
    local time_elapsed = (current_time - last_refill) / precision_multiplier
    
    -- Apply leaky bucket (continuous token leak)
    if leaky_rate > 0 and time_elapsed > 0 then
      local leaked_tokens = leaky_rate * time_elapsed
      tokens = math.max(0, tokens - leaked_tokens)
    end
    
    -- Refill tokens
    local new_tokens = refill_rate * time_elapsed
    tokens = math.min(capacity, tokens + new_tokens)
    
    -- Handle burst tokens (if not in cooldown)
    local burst_available = 0
    if current_time > cooldown_until and burst_tokens > 0 then
      burst_available = burst_tokens
      tokens = math.min(capacity + burst_available, tokens + burst_available)
    end
    
    -- Check if request can be satisfied
    local can_consume = tokens >= tokens_requested
    local retry_after = 0
    
    if can_consume then
      tokens = tokens - tokens_requested
      
      -- Start cooldown if burst tokens were used
      if tokens < capacity then
        cooldown_until = current_time + (60 * precision_multiplier) -- 60 second cooldown
      end
    else
      -- Calculate retry after time
      local tokens_needed = tokens_requested - tokens
      retry_after = math.ceil(tokens_needed / refill_rate)
    end
    
    -- Update bucket state
    redis.call('HMSET', bucket_key,
      'tokens', tokens,
      'last_refill', current_time,
      'capacity', capacity,
      'refill_rate', refill_rate,
      'burst_tokens', burst_available,
      'cooldown_until', cooldown_until,
      'leaky_rate', leaky_rate
    )
    
    -- Set expiration (TTL = 2 * max(capacity/refill_rate, 3600))
    local ttl = math.max(2 * math.ceil(capacity / refill_rate), 3600)
    redis.call('EXPIRE', bucket_key, ttl)
    
    -- Return result
    return {
      can_consume and 1 or 0,
      tokens_requested,
      math.floor(tokens),
      capacity,
      refill_rate,
      retry_after,
      current_time + (tokens_needed and (tokens_needed / refill_rate * precision_multiplier) or 0),
      burst_available
    }
  `,

  // Adaptive rate adjustment based on system load
  adaptiveAdjustment: `
    local bucket_key = KEYS[1]
    local metrics_key = KEYS[2]
    local server_load = tonumber(ARGV[1])
    local traffic_score = tonumber(ARGV[2])
    local adjustment_factor = tonumber(ARGV[3]) or 1.0
    local current_time = tonumber(ARGV[4])
    
    -- Get current configuration
    local bucket_data = redis.call('HMGET', bucket_key, 'refill_rate', 'capacity')
    local base_refill_rate = tonumber(bucket_data[1]) or 10
    local base_capacity = tonumber(bucket_data[2]) or 100
    
    -- Calculate adaptive adjustment
    local load_factor = 1.0
    if server_load > 0.8 then
      load_factor = 0.5  -- Reduce rate by 50% under high load
    elseif server_load > 0.6 then
      load_factor = 0.75 -- Reduce rate by 25% under medium load
    elseif server_load < 0.3 then
      load_factor = 1.25 -- Increase rate by 25% under low load
    end
    
    -- Apply traffic pattern adjustment
    local traffic_factor = 1.0
    if traffic_score > 2.0 then
      traffic_factor = 0.8 -- Reduce for unusual traffic
    elseif traffic_score < 0.5 then
      traffic_factor = 1.1 -- Slightly increase for normal traffic
    end
    
    -- Calculate new rates
    local new_refill_rate = base_refill_rate * load_factor * traffic_factor * adjustment_factor
    local new_capacity = base_capacity * math.sqrt(load_factor * traffic_factor)
    
    -- Update bucket configuration
    redis.call('HMSET', bucket_key,
      'refill_rate', new_refill_rate,
      'capacity', new_capacity,
      'last_adjustment', current_time,
      'load_factor', load_factor,
      'traffic_factor', traffic_factor
    )
    
    -- Store metrics
    redis.call('ZADD', metrics_key, current_time, 
      string.format('load=%.2f;traffic=%.2f;refill=%.2f;capacity=%.2f', 
        server_load, traffic_score, new_refill_rate, new_capacity))
    redis.call('ZREMRANGEBYSCORE', metrics_key, 0, current_time - 86400) -- Keep 24h of metrics
    
    return {new_refill_rate, new_capacity, load_factor, traffic_factor}
  `,

  // Batch token consumption for high-throughput scenarios
  batchTokenConsume: `
    local bucket_key = KEYS[1]
    local batch_size = tonumber(ARGV[1])
    local tokens_per_request = tonumber(ARGV[2])
    local current_time = tonumber(ARGV[3])
    local precision_multiplier = tonumber(ARGV[4]) or 1000
    
    local results = {}
    local total_tokens_needed = batch_size * tokens_per_request
    
    -- Get bucket state once
    local bucket_data = redis.call('HMGET', bucket_key, 'tokens', 'last_refill', 'capacity', 'refill_rate')
    local tokens = tonumber(bucket_data[1]) or 0
    local last_refill = tonumber(bucket_data[2]) or current_time
    local capacity = tonumber(bucket_data[3]) or 100
    local refill_rate = tonumber(bucket_data[4]) or 10
    
    -- Refill tokens
    local time_elapsed = (current_time - last_refill) / precision_multiplier
    local new_tokens = refill_rate * time_elapsed
    tokens = math.min(capacity, tokens + new_tokens)
    
    -- Process batch
    local successful_requests = 0
    while successful_requests < batch_size and tokens >= tokens_per_request do
      tokens = tokens - tokens_per_request
      successful_requests = successful_requests + 1
    end
    
    -- Update bucket
    redis.call('HMSET', bucket_key,
      'tokens', tokens,
      'last_refill', current_time
    )
    
    return {successful_requests, batch_size - successful_requests, tokens}
  `
};

/**
 * Advanced Token Bucket Rate Limiter
 */
export class AdvancedTokenBucketRateLimiter {
  private redis: Redis.Redis;
  private buckets: Map<string, TokenBucketConfig> = new Map();
  private luaScripts: Map<string, string> = new Map();
  private circuitBreaker: Map<string, { state: string; failures: number; lastFailure: Date }> = new Map();
  private metricsCollector: Map<string, any[]> = new Map();

  constructor(
    private config: {
      redisUrl: string;
      redisCluster?: string[];
      defaultPrecision: 'SECOND' | 'MILLISECOND' | 'MICROSECOND';
      circuitBreakerThreshold: number;
      metricsRetention: number; // minutes
      adaptiveEvaluation: number; // seconds
      enableBatchProcessing: boolean;
      enablePrecomputation: boolean;
    }
  ) {
    this.initializeRedis();
    this.loadLuaScripts();
    this.startPeriodicTasks();
  }

  private initializeRedis(): void {
    if (this.config.redisCluster) {
      this.redis = new Redis.Cluster(
        this.config.redisCluster.map(url => {
          const parsed = new URL(url);
          return { host: parsed.hostname, port: parseInt(parsed.port) || 6379 };
        }),
        {
          redisOptions: {
            password: process.env.REDIS_PASSWORD,
            connectTimeout: 5000,
            lazyConnect: true,
            maxRetriesPerRequest: 3,
            retryDelayOnFailover: 100
          },
          clusterRetryDelayOnFailover: 100,
          clusterRetryDelayOnClusterDown: 300,
          clusterMaxRedirections: 16,
          clusterRetryDelayOnMoved: 50,
          scaleReads: 'slave'
        }
      );
    } else {
      this.redis = new Redis(this.config.redisUrl, {
        password: process.env.REDIS_PASSWORD,
        connectTimeout: 5000,
        lazyConnect: true,
        maxRetriesPerRequest: 3,
        retryDelayOnFailover: 100,
        enableReadyCheck: true,
        showFriendlyErrorStack: true
      });
    }

    // Error handling
    this.redis.on('error', (error) => {
      console.error('Redis connection error:', error);
      this.handleCircuitBreaker('redis', false);
    });

    this.redis.on('connect', () => {
      console.log('Connected to Redis');
      this.handleCircuitBreaker('redis', true);
    });
  }

  private loadLuaScripts(): void {
    Object.entries(LUA_SCRIPTS).forEach(([name, script]) => {
      this.luaScripts.set(name, script);
    });
  }

  /**
   * Create or update a token bucket configuration
   */
  public async createTokenBucket(config: TokenBucketConfig): Promise<void> {
    try {
      const validatedConfig = TokenBucketConfigSchema.parse(config);
      this.buckets.set(validatedConfig.bucketId, validatedConfig);

      // Initialize bucket in Redis
      const bucketKey = `rate_limit:bucket:${validatedConfig.bucketId}`;
      const initialTokens = validatedConfig.initialTokens ?? validatedConfig.capacity;

      await this.redis.hmset(bucketKey, {
        tokens: initialTokens,
        last_refill: Date.now(),
        capacity: validatedConfig.capacity,
        refill_rate: validatedConfig.refillRate,
        burst_tokens: validatedConfig.burstControl?.burstCapacity || 0,
        cooldown_until: 0,
        leaky_rate: validatedConfig.leakyBucket?.leakRate || 0
      });

      // Set TTL
      const ttl = Math.max(2 * Math.ceil(validatedConfig.capacity / validatedConfig.refillRate), 3600);
      await this.redis.expire(bucketKey, ttl);

      console.log(`Token bucket created: ${validatedConfig.bucketId}`);
    } catch (error) {
      console.error(`Failed to create token bucket ${config.bucketId}:`, error);
      throw error;
    }
  }

  /**
   * Consume tokens from bucket with advanced features
   */
  public async consumeTokens(
    bucketId: string,
    tokensRequested: number = 1,
    options: {
      clientId?: string;
      endpoint?: string;
      requestId?: string;
      bypassCircuitBreaker?: boolean;
      enableAdaptive?: boolean;
      serverLoad?: number;
    } = {}
  ): Promise<RateLimitResult> {
    const startTime = Date.now();
    const bucketConfig = this.buckets.get(bucketId);

    if (!bucketConfig) {
      throw new Error(`Token bucket not found: ${bucketId}`);
    }

    try {
      // Check circuit breaker
      if (!options.bypassCircuitBreaker && !this.isCircuitBreakerClosed('redis')) {
        return this.createFailOpenResult(bucketId, tokensRequested, startTime, options);
      }

      // Apply adaptive rate limiting if enabled and configured
      if (options.enableAdaptive && bucketConfig.adaptive?.enabled && options.serverLoad !== undefined) {
        await this.applyAdaptiveRateAdjustment(bucketId, options.serverLoad);
      }

      const bucketKey = `rate_limit:bucket:${bucketId}`;
      const configKey = `rate_limit:config:${bucketId}`;
      const currentTime = this.getCurrentTimestamp();
      const precisionMultiplier = this.getPrecisionMultiplier(bucketConfig);

      // Execute Lua script for atomic token consumption
      const result = await this.redis.eval(
        this.luaScripts.get('tokenBucketConsume')!,
        2,
        bucketKey,
        configKey,
        tokensRequested,
        currentTime,
        precisionMultiplier
      ) as number[];

      const [canConsume, tokensConsumed, tokensRemaining, capacity, refillRate, retryAfter, nextRefillTime, burstAvailable] = result;

      // Create result object
      const rateLimitResult: RateLimitResult = {
        allowed: canConsume === 1,
        tokensConsumed: tokensConsumed,
        tokensRemaining: tokensRemaining,
        bucketCapacity: capacity,
        refillRate: refillRate,
        nextRefillTime: new Date(nextRefillTime),
        retryAfter: retryAfter > 0 ? retryAfter : undefined,
        headers: this.generateRateLimitHeaders({
          limit: capacity,
          remaining: tokensRemaining,
          resetTime: new Date(nextRefillTime),
          retryAfter: retryAfter,
          policy: bucketId,
          burstAvailable: burstAvailable
        }),
        debug: {
          processingTime: Date.now() - startTime,
          redisLatency: 0, // Would be measured in production
          bucketState: {
            tokensRemaining,
            capacity,
            refillRate,
            burstAvailable
          },
          circuitBreakerState: this.getCircuitBreakerState('redis')
        },
        metrics: {
          timestamp: new Date(),
          bucketId,
          requestId: options.requestId,
          clientId: options.clientId,
          endpoint: options.endpoint
        }
      };

      // Collect metrics
      this.collectMetrics(bucketId, rateLimitResult);

      // Handle circuit breaker success
      this.handleCircuitBreaker('redis', true);

      return RateLimitResultSchema.parse(rateLimitResult);

    } catch (error) {
      console.error(`Token consumption failed for bucket ${bucketId}:`, error);
      
      // Handle circuit breaker failure
      this.handleCircuitBreaker('redis', false);

      // Return fail-open result in case of Redis failure
      if (bucketConfig.adaptive?.enabled) {
        return this.createFailOpenResult(bucketId, tokensRequested, startTime, options);
      }

      throw error;
    }
  }

  /**
   * Batch token consumption for high-throughput scenarios
   */
  public async consumeTokensBatch(
    bucketId: string,
    batchSize: number,
    tokensPerRequest: number = 1
  ): Promise<{
    successful: number;
    failed: number;
    remainingTokens: number;
    processingTime: number;
  }> {
    const startTime = Date.now();
    const bucketKey = `rate_limit:bucket:${bucketId}`;

    try {
      const result = await this.redis.eval(
        this.luaScripts.get('batchTokenConsume')!,
        1,
        bucketKey,
        batchSize,
        tokensPerRequest,
        this.getCurrentTimestamp(),
        this.getPrecisionMultiplier()
      ) as number[];

      const [successful, failed, remainingTokens] = result;

      return {
        successful,
        failed,
        remainingTokens,
        processingTime: Date.now() - startTime
      };

    } catch (error) {
      console.error(`Batch token consumption failed for bucket ${bucketId}:`, error);
      throw error;
    }
  }

  /**
   * Get current bucket status
   */
  public async getBucketStatus(bucketId: string): Promise<{
    tokens: number;
    capacity: number;
    refillRate: number;
    lastRefill: Date;
    cooldownUntil?: Date;
    leakyRate?: number;
    isHealthy: boolean;
  }> {
    const bucketKey = `rate_limit:bucket:${bucketId}`;

    try {
      const data = await this.redis.hmget(
        bucketKey,
        'tokens', 'capacity', 'refill_rate', 'last_refill', 'cooldown_until', 'leaky_rate'
      );

      return {
        tokens: parseInt(data[0] || '0'),
        capacity: parseInt(data[1] || '100'),
        refillRate: parseFloat(data[2] || '10'),
        lastRefill: new Date(parseInt(data[3] || '0')),
        cooldownUntil: data[4] && parseInt(data[4]) > 0 ? new Date(parseInt(data[4])) : undefined,
        leakyRate: data[5] ? parseFloat(data[5]) : undefined,
        isHealthy: this.isCircuitBreakerClosed('redis')
      };

    } catch (error) {
      console.error(`Failed to get bucket status for ${bucketId}:`, error);
      throw error;
    }
  }

  // Private helper methods

  private getCurrentTimestamp(): number {
    switch (this.config.defaultPrecision) {
      case 'MICROSECOND':
        return Date.now() * 1000 + (process.hrtime()[1] / 1000);
      case 'MILLISECOND':
        return Date.now();
      case 'SECOND':
      default:
        return Math.floor(Date.now() / 1000);
    }
  }

  private getPrecisionMultiplier(config?: TokenBucketConfig): number {
    const precision = config?.precision?.timestampPrecision || this.config.defaultPrecision;
    switch (precision) {
      case 'MICROSECOND': return 1000000;
      case 'MILLISECOND': return 1000;
      case 'SECOND': default: return 1;
    }
  }

  private generateRateLimitHeaders(params: {
    limit: number;
    remaining: number;
    resetTime: Date;
    retryAfter?: number;
    policy: string;
    burstAvailable?: number;
  }): Record<string, string> {
    const headers: Record<string, string> = {
      'X-RateLimit-Limit': params.limit.toString(),
      'X-RateLimit-Remaining': params.remaining.toString(),
      'X-RateLimit-Reset': Math.floor(params.resetTime.getTime() / 1000).toString(),
      'X-RateLimit-Policy': params.policy,
      'X-RateLimit-Precision': this.config.defaultPrecision.toLowerCase(),
    };

    if (params.retryAfter !== undefined && params.retryAfter > 0) {
      headers['Retry-After'] = params.retryAfter.toString();
      headers['X-RateLimit-Retry-After'] = params.retryAfter.toString();
    }

    if (params.burstAvailable !== undefined && params.burstAvailable > 0) {
      headers['X-RateLimit-Burst-Available'] = params.burstAvailable.toString();
    }

    // Add custom iSECTECH headers
    headers['X-iSECTECH-RateLimit-Version'] = '2.0';
    headers['X-iSECTECH-RateLimit-Algorithm'] = 'token-bucket-leaky-bucket-hybrid';

    return headers;
  }

  private async applyAdaptiveRateAdjustment(bucketId: string, serverLoad: number): Promise<void> {
    const bucketKey = `rate_limit:bucket:${bucketId}`;
    const metricsKey = `rate_limit:metrics:${bucketId}`;
    
    // Calculate traffic score based on recent metrics
    const trafficScore = await this.calculateTrafficScore(bucketId);
    
    const bucketConfig = this.buckets.get(bucketId);
    const adjustmentFactor = bucketConfig?.adaptive?.adjustmentFactor || 1.0;

    try {
      await this.redis.eval(
        this.luaScripts.get('adaptiveAdjustment')!,
        2,
        bucketKey,
        metricsKey,
        serverLoad,
        trafficScore,
        adjustmentFactor,
        this.getCurrentTimestamp()
      );
    } catch (error) {
      console.error(`Adaptive rate adjustment failed for bucket ${bucketId}:`, error);
    }
  }

  private async calculateTrafficScore(bucketId: string): Promise<number> {
    // Simple traffic score calculation - would be more sophisticated in production
    const metricsKey = `rate_limit:metrics:${bucketId}`;
    const recentMetrics = await this.redis.zrange(metricsKey, -60, -1); // Last 60 data points
    
    if (recentMetrics.length < 10) {
      return 1.0; // Default score for insufficient data
    }

    // Analyze request patterns (simplified)
    const requestCounts = recentMetrics.map(metric => {
      const match = metric.match(/requests=(\d+)/);
      return match ? parseInt(match[1]) : 0;
    });

    const avg = requestCounts.reduce((sum, count) => sum + count, 0) / requestCounts.length;
    const variance = requestCounts.reduce((sum, count) => sum + Math.pow(count - avg, 2), 0) / requestCounts.length;
    const coefficient = variance > 0 ? Math.sqrt(variance) / avg : 0;

    return Math.max(0.1, Math.min(3.0, coefficient)); // Score between 0.1 and 3.0
  }

  private handleCircuitBreaker(service: string, success: boolean): void {
    const key = service;
    const breaker = this.circuitBreaker.get(key) || { state: 'CLOSED', failures: 0, lastFailure: new Date() };

    if (success) {
      if (breaker.state === 'HALF_OPEN') {
        breaker.state = 'CLOSED';
        breaker.failures = 0;
      } else if (breaker.state === 'CLOSED') {
        breaker.failures = Math.max(0, breaker.failures - 1);
      }
    } else {
      breaker.failures++;
      breaker.lastFailure = new Date();

      if (breaker.failures >= this.config.circuitBreakerThreshold) {
        breaker.state = 'OPEN';
      }
    }

    this.circuitBreaker.set(key, breaker);

    // Auto-transition from OPEN to HALF_OPEN after 60 seconds
    if (breaker.state === 'OPEN' && Date.now() - breaker.lastFailure.getTime() > 60000) {
      breaker.state = 'HALF_OPEN';
      this.circuitBreaker.set(key, breaker);
    }
  }

  private isCircuitBreakerClosed(service: string): boolean {
    const breaker = this.circuitBreaker.get(service);
    return !breaker || breaker.state === 'CLOSED' || breaker.state === 'HALF_OPEN';
  }

  private getCircuitBreakerState(service: string): 'CLOSED' | 'OPEN' | 'HALF_OPEN' {
    const breaker = this.circuitBreaker.get(service);
    return breaker?.state as 'CLOSED' | 'OPEN' | 'HALF_OPEN' || 'CLOSED';
  }

  private createFailOpenResult(
    bucketId: string,
    tokensRequested: number,
    startTime: number,
    options: any
  ): RateLimitResult {
    // Fail-open policy: allow request but log the failure
    console.warn(`Failing open for bucket ${bucketId} due to circuit breaker`);

    return {
      allowed: true,
      tokensConsumed: tokensRequested,
      tokensRemaining: 1000, // Fallback value
      bucketCapacity: 1000,
      refillRate: 100,
      nextRefillTime: new Date(Date.now() + 60000),
      headers: {
        'X-RateLimit-Limit': '1000',
        'X-RateLimit-Remaining': '1000',
        'X-RateLimit-Reset': Math.floor((Date.now() + 60000) / 1000).toString(),
        'X-RateLimit-Policy': bucketId,
        'X-iSECTECH-RateLimit-Fallback': 'true',
        'X-iSECTECH-RateLimit-Circuit-Breaker': 'OPEN'
      },
      debug: {
        processingTime: Date.now() - startTime,
        circuitBreakerState: 'OPEN'
      },
      metrics: {
        timestamp: new Date(),
        bucketId,
        requestId: options.requestId,
        clientId: options.clientId,
        endpoint: options.endpoint
      }
    };
  }

  private collectMetrics(bucketId: string, result: RateLimitResult): void {
    const metrics = this.metricsCollector.get(bucketId) || [];
    metrics.push({
      timestamp: result.metrics.timestamp,
      allowed: result.allowed,
      tokensConsumed: result.tokensConsumed,
      tokensRemaining: result.tokensRemaining,
      processingTime: result.debug?.processingTime
    });

    // Keep only recent metrics
    const cutoff = Date.now() - (this.config.metricsRetention * 60 * 1000);
    this.metricsCollector.set(
      bucketId,
      metrics.filter(m => m.timestamp.getTime() > cutoff)
    );
  }

  private startPeriodicTasks(): void {
    // Circuit breaker maintenance
    setInterval(() => {
      for (const [service, breaker] of this.circuitBreaker) {
        if (breaker.state === 'OPEN' && Date.now() - breaker.lastFailure.getTime() > 60000) {
          breaker.state = 'HALF_OPEN';
          this.circuitBreaker.set(service, breaker);
        }
      }
    }, 30000); // Check every 30 seconds

    // Adaptive rate limiting evaluation
    if (this.config.adaptiveEvaluation > 0) {
      setInterval(() => {
        this.evaluateAdaptiveRateLimiting().catch(error => {
          console.error('Adaptive rate limiting evaluation failed:', error);
        });
      }, this.config.adaptiveEvaluation * 1000);
    }

    // Metrics cleanup
    setInterval(() => {
      const cutoff = Date.now() - (this.config.metricsRetention * 60 * 1000);
      for (const [bucketId, metrics] of this.metricsCollector) {
        this.metricsCollector.set(
          bucketId,
          metrics.filter(m => m.timestamp.getTime() > cutoff)
        );
      }
    }, 300000); // Clean up every 5 minutes
  }

  private async evaluateAdaptiveRateLimiting(): Promise<void> {
    // Implementation would evaluate system-wide metrics and adjust rate limits
    // This is a placeholder for the actual adaptive logic
    console.debug('Evaluating adaptive rate limiting adjustments...');
  }

  /**
   * Get comprehensive rate limiting statistics
   */
  public getRateLimitingStatistics(bucketId?: string): any {
    if (bucketId) {
      const metrics = this.metricsCollector.get(bucketId) || [];
      const recentMetrics = metrics.filter(m => m.timestamp.getTime() > Date.now() - 3600000); // Last hour

      return {
        bucketId,
        totalRequests: recentMetrics.length,
        allowedRequests: recentMetrics.filter(m => m.allowed).length,
        blockedRequests: recentMetrics.filter(m => !m.allowed).length,
        averageProcessingTime: recentMetrics.reduce((sum, m) => sum + (m.processingTime || 0), 0) / recentMetrics.length,
        tokensConsumed: recentMetrics.reduce((sum, m) => sum + m.tokensConsumed, 0)
      };
    } else {
      // Return system-wide statistics
      const allMetrics = Array.from(this.metricsCollector.values()).flat();
      const recentMetrics = allMetrics.filter(m => m.timestamp.getTime() > Date.now() - 3600000);

      return {
        systemWide: true,
        totalBuckets: this.buckets.size,
        totalRequests: recentMetrics.length,
        allowedRequests: recentMetrics.filter(m => m.allowed).length,
        blockedRequests: recentMetrics.filter(m => !m.allowed).length,
        averageProcessingTime: recentMetrics.reduce((sum, m) => sum + (m.processingTime || 0), 0) / recentMetrics.length,
        circuitBreakerStates: Array.from(this.circuitBreaker.entries()).map(([service, breaker]) => ({
          service,
          state: breaker.state,
          failures: breaker.failures
        }))
      };
    }
  }

  /**
   * Cleanup and shutdown
   */
  public async shutdown(): Promise<void> {
    console.log('Shutting down Advanced Token Bucket Rate Limiter...');
    
    try {
      await this.redis.quit();
      console.log('Redis connection closed');
    } catch (error) {
      console.error('Error during Redis shutdown:', error);
    }
  }
}

// Export configured instance for iSECTECH
export const isectechAdvancedRateLimiter = new AdvancedTokenBucketRateLimiter({
  redisUrl: process.env.REDIS_URL || 'redis://redis.isectech-cache.svc.cluster.local:6379',
  redisCluster: process.env.REDIS_CLUSTER_URLS ? process.env.REDIS_CLUSTER_URLS.split(',') : undefined,
  defaultPrecision: (process.env.RATE_LIMIT_PRECISION as any) || 'MILLISECOND',
  circuitBreakerThreshold: parseInt(process.env.CIRCUIT_BREAKER_THRESHOLD || '5'),
  metricsRetention: parseInt(process.env.RATE_LIMIT_METRICS_RETENTION || '60'),
  adaptiveEvaluation: parseInt(process.env.ADAPTIVE_EVALUATION_INTERVAL || '60'),
  enableBatchProcessing: process.env.ENABLE_BATCH_PROCESSING === 'true',
  enablePrecomputation: process.env.ENABLE_PRECOMPUTATION !== 'false'
});