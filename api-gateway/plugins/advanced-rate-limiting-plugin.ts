/**
 * Kong Advanced Rate Limiting Plugin Integration for iSECTECH
 * 
 * Integrates the Advanced Token Bucket Rate Limiter with Kong Gateway,
 * providing seamless rate limiting with adaptive controls, DDoS protection,
 * and comprehensive monitoring for the iSECTECH cybersecurity platform.
 * 
 * Features:
 * - Kong plugin configuration generation
 * - Custom Lua script integration
 * - Rate limiting middleware with token bucket algorithm
 * - DDoS protection with intelligent traffic analysis
 * - Adaptive rate limiting based on system metrics
 * - Comprehensive client feedback headers
 */

import { z } from 'zod';
import { 
  isectechAdvancedRateLimiter, 
  TokenBucketConfig,
  RateLimitResult 
} from '../rate-limiting/advanced-token-bucket-rate-limiter';

// Kong Plugin Configuration Schema
export const KongRateLimitingPluginConfigSchema = z.object({
  name: z.literal('advanced-rate-limiting'),
  service: z.object({ id: z.string() }).optional(),
  route: z.object({ id: z.string() }).optional(),
  consumer: z.object({ id: z.string() }).optional(),
  
  config: z.object({
    // Token bucket configuration
    bucket_capacity: z.number().min(1).default(100),
    refill_rate: z.number().min(0).default(10),
    tokens_per_request: z.number().min(1).default(1),
    
    // Rate limiting policies
    policies: z.array(z.object({
      limit: z.number().min(1),
      window_size: z.number().min(1),
      window_type: z.enum(['second', 'minute', 'hour', 'day', 'month']),
      identifier: z.enum(['ip', 'consumer', 'credential', 'service', 'header']).default('ip'),
      header_name: z.string().optional()
    })).default([]),
    
    // Leaky bucket integration
    leaky_bucket_enabled: z.boolean().default(false),
    leak_rate: z.number().min(0).default(0),
    queue_capacity: z.number().min(0).default(0),
    
    // Burst control
    burst_capacity: z.number().min(0).optional(),
    burst_refill_rate: z.number().min(0).optional(),
    cooldown_period: z.number().min(0).default(60),
    
    // Adaptive features
    adaptive_enabled: z.boolean().default(false),
    server_load_threshold: z.number().min(0).max(1).default(0.8),
    adjustment_factor: z.number().min(0.1).max(2.0).default(1.0),
    evaluation_interval: z.number().min(1).default(60),
    
    // DDoS protection
    ddos_protection: z.object({
      enabled: z.boolean().default(true),
      baseline_window: z.number().min(60).default(300), // 5 minutes
      anomaly_threshold: z.number().min(1).default(5), // 5x baseline
      block_duration: z.number().min(60).default(3600), // 1 hour
      challenge_mode: z.boolean().default(false)
    }).optional(),
    
    // Storage and persistence
    policy: z.enum(['local', 'cluster', 'redis']).default('redis'),
    redis_host: z.string().optional(),
    redis_port: z.number().min(1).max(65535).optional(),
    redis_database: z.number().min(0).default(0),
    redis_timeout: z.number().min(100).default(2000),
    
    // Response configuration
    limit_by: z.enum(['ip', 'consumer', 'credential', 'service']).default('ip'),
    fault_tolerant: z.boolean().default(true),
    hide_client_headers: z.boolean().default(false),
    
    // Custom responses
    error_code: z.number().min(400).max(599).default(429),
    error_message: z.string().default('Rate limit exceeded'),
    
    // Monitoring and logging
    enable_detailed_logging: z.boolean().default(true),
    metrics_collection: z.boolean().default(true),
    
    // Advanced features
    precision: z.enum(['second', 'millisecond', 'microsecond']).default('millisecond'),
    circuit_breaker_enabled: z.boolean().default(true),
    circuit_breaker_threshold: z.number().min(1).default(5),
    
    // Custom headers
    custom_headers: z.record(z.string()).optional()
  }),
  
  protocols: z.array(z.enum(['grpc', 'grpcs', 'http', 'https'])).optional(),
  enabled: z.boolean().default(true),
  tags: z.array(z.string()).optional(),
  
  ordering: z.object({
    before: z.record(z.array(z.string())).optional(),
    after: z.record(z.array(z.string())).optional()
  }).optional()
});

export type KongRateLimitingPluginConfig = z.infer<typeof KongRateLimitingPluginConfigSchema>;

/**
 * Kong Advanced Rate Limiting Plugin Manager
 */
export class KongAdvancedRateLimitingPlugin {
  private tokenBuckets: Map<string, string> = new Map(); // Route/Service ID -> Bucket ID mapping
  private ddosBaselines: Map<string, number[]> = new Map(); // IP -> Request timestamps
  private adaptiveMetrics: Map<string, any> = new Map();

  constructor(
    private config: {
      defaultBucketCapacity: number;
      defaultRefillRate: number;
      redisKeyPrefix: string;
      enableGlobalDDoSProtection: boolean;
      metricsCollectionInterval: number;
    }
  ) {
    this.initializeDefaultBuckets();
    this.startPeriodicTasks();
  }

  /**
   * Generate Kong plugin configurations for iSECTECH services
   */
  public generateISECTECHPluginConfigurations(): KongRateLimitingPluginConfig[] {
    const configurations: KongRateLimitingPluginConfig[] = [];

    // High Security APIs (Threat Detection, AI/ML) - Strict Limits
    configurations.push({
      name: 'advanced-rate-limiting',
      service: { id: 'isectech-threat-detection' },
      config: {
        bucket_capacity: 60,
        refill_rate: 1, // 1 token per second = 60 requests per minute
        tokens_per_request: 1,
        policies: [
          {
            limit: 60,
            window_size: 1,
            window_type: 'minute',
            identifier: 'ip'
          },
          {
            limit: 1000,
            window_size: 1,
            window_type: 'hour',
            identifier: 'ip'
          },
          {
            limit: 5000,
            window_size: 1,
            window_type: 'day',
            identifier: 'consumer'
          }
        ],
        leaky_bucket_enabled: true,
        leak_rate: 0.1, // Smooth out bursty traffic
        queue_capacity: 10,
        burst_capacity: 20, // Allow short bursts
        burst_refill_rate: 2,
        cooldown_period: 60,
        adaptive_enabled: true,
        server_load_threshold: 0.7,
        adjustment_factor: 0.8,
        evaluation_interval: 30,
        ddos_protection: {
          enabled: true,
          baseline_window: 300,
          anomaly_threshold: 8,
          block_duration: 3600,
          challenge_mode: false
        },
        policy: 'redis',
        redis_host: 'redis.isectech-cache.svc.cluster.local',
        redis_port: 6379,
        redis_database: 1,
        redis_timeout: 2000,
        limit_by: 'ip',
        fault_tolerant: true,
        hide_client_headers: false,
        error_code: 429,
        error_message: 'Security API rate limit exceeded. Please reduce request frequency.',
        enable_detailed_logging: true,
        metrics_collection: true,
        precision: 'millisecond',
        circuit_breaker_enabled: true,
        circuit_breaker_threshold: 3,
        custom_headers: {
          'X-iSECTECH-Security-Policy': 'high-security-api',
          'X-iSECTECH-Service-Tier': 'premium'
        }
      },
      protocols: ['https'],
      enabled: true,
      tags: ['isectech', 'high-security', 'threat-detection', 'rate-limiting'],
      ordering: {
        before: {
          'cors': ['*'],
          'jwt': ['*']
        },
        after: {
          'ip-restriction': ['*']
        }
      }
    });

    // AI/ML Services - Specialized Configuration
    configurations.push({
      name: 'advanced-rate-limiting',
      service: { id: 'isectech-ai-ml-services' },
      config: {
        bucket_capacity: 30,
        refill_rate: 0.5, // 0.5 tokens per second = 30 requests per minute
        tokens_per_request: 1,
        policies: [
          {
            limit: 30,
            window_size: 1,
            window_type: 'minute',
            identifier: 'consumer'
          },
          {
            limit: 500,
            window_size: 1,
            window_type: 'hour',
            identifier: 'consumer'
          }
        ],
        leaky_bucket_enabled: true,
        leak_rate: 0.05, // Very smooth for ML workloads
        queue_capacity: 5,
        burst_capacity: 10,
        burst_refill_rate: 1,
        cooldown_period: 120, // Longer cooldown for ML
        adaptive_enabled: true,
        server_load_threshold: 0.6, // Lower threshold for ML services
        adjustment_factor: 0.5, // More aggressive adjustment
        evaluation_interval: 45,
        ddos_protection: {
          enabled: true,
          baseline_window: 600,
          anomaly_threshold: 10,
          block_duration: 7200,
          challenge_mode: true
        },
        policy: 'redis',
        redis_host: 'redis.isectech-cache.svc.cluster.local',
        redis_port: 6379,
        redis_database: 2,
        error_code: 429,
        error_message: 'AI/ML service capacity exceeded. ML processing requires significant resources.',
        custom_headers: {
          'X-iSECTECH-ML-Queue-Position': 'dynamic',
          'X-iSECTECH-Processing-Time-Estimate': 'dynamic'
        }
      },
      protocols: ['https'],
      enabled: true,
      tags: ['isectech', 'ai-ml', 'machine-learning', 'rate-limiting']
    });

    // Standard APIs - Balanced Configuration
    configurations.push({
      name: 'advanced-rate-limiting',
      service: { id: 'isectech-asset-discovery' },
      config: {
        bucket_capacity: 120,
        refill_rate: 2, // 2 tokens per second = 120 requests per minute
        tokens_per_request: 1,
        policies: [
          {
            limit: 120,
            window_size: 1,
            window_type: 'minute',
            identifier: 'ip'
          },
          {
            limit: 2000,
            window_size: 1,
            window_type: 'hour',
            identifier: 'consumer'
          }
        ],
        leaky_bucket_enabled: false, // Standard APIs don't need smoothing
        burst_capacity: 50,
        burst_refill_rate: 5,
        cooldown_period: 60,
        adaptive_enabled: true,
        server_load_threshold: 0.8,
        adjustment_factor: 1.2,
        evaluation_interval: 60,
        ddos_protection: {
          enabled: true,
          baseline_window: 300,
          anomaly_threshold: 5,
          block_duration: 1800,
          challenge_mode: false
        },
        policy: 'redis',
        redis_host: 'redis.isectech-cache.svc.cluster.local',
        redis_port: 6379,
        redis_database: 3,
        error_message: 'Asset discovery API rate limit exceeded.',
        custom_headers: {
          'X-iSECTECH-Service-Type': 'asset-discovery'
        }
      },
      protocols: ['https'],
      enabled: true,
      tags: ['isectech', 'standard', 'asset-discovery', 'rate-limiting']
    });

    // Compliance Automation - Document Upload Friendly
    configurations.push({
      name: 'advanced-rate-limiting',
      service: { id: 'isectech-compliance-automation' },
      config: {
        bucket_capacity: 200,
        refill_rate: 3, // Higher rate for document processing
        tokens_per_request: 1,
        policies: [
          {
            limit: 200,
            window_size: 1,
            window_type: 'minute',
            identifier: 'consumer'
          },
          {
            limit: 5000,
            window_size: 1,
            window_type: 'day',
            identifier: 'consumer'
          }
        ],
        leaky_bucket_enabled: true,
        leak_rate: 0.2,
        queue_capacity: 20,
        burst_capacity: 100, // Large bursts for document uploads
        burst_refill_rate: 10,
        cooldown_period: 30,
        adaptive_enabled: true,
        server_load_threshold: 0.85,
        adjustment_factor: 1.5,
        ddos_protection: {
          enabled: true,
          baseline_window: 300,
          anomaly_threshold: 4,
          block_duration: 1200,
          challenge_mode: false
        },
        policy: 'redis',
        redis_database: 4,
        error_message: 'Compliance API rate limit exceeded. Large document uploads may require premium tier.',
        custom_headers: {
          'X-iSECTECH-Upload-Limit': 'dynamic',
          'X-iSECTECH-Queue-Depth': 'dynamic'
        }
      },
      protocols: ['https'],
      enabled: true,
      tags: ['isectech', 'compliance', 'document-upload', 'rate-limiting']
    });

    // Event Processing - Real-time Friendly
    configurations.push({
      name: 'advanced-rate-limiting',
      service: { id: 'isectech-event-processing' },
      config: {
        bucket_capacity: 500,
        refill_rate: 8, // High rate for real-time events
        tokens_per_request: 1,
        policies: [
          {
            limit: 500,
            window_size: 1,
            window_type: 'minute',
            identifier: 'consumer'
          },
          {
            limit: 10000,
            window_size: 1,
            window_type: 'hour',
            identifier: 'consumer'
          }
        ],
        leaky_bucket_enabled: true,
        leak_rate: 1, // Smooth out event spikes
        queue_capacity: 50,
        burst_capacity: 200,
        burst_refill_rate: 20,
        cooldown_period: 15, // Short cooldown for real-time
        adaptive_enabled: true,
        server_load_threshold: 0.9, // Higher threshold for event processing
        adjustment_factor: 2.0, // Aggressive scaling
        evaluation_interval: 15,
        ddos_protection: {
          enabled: true,
          baseline_window: 60, // Shorter baseline for events
          anomaly_threshold: 15,
          block_duration: 600,
          challenge_mode: false
        },
        policy: 'redis',
        redis_database: 5,
        precision: 'microsecond', // High precision for events
        error_message: 'Event processing capacity exceeded. Consider batching events.',
        custom_headers: {
          'X-iSECTECH-Event-Queue-Depth': 'dynamic',
          'X-iSECTECH-Processing-Latency': 'dynamic'
        }
      },
      protocols: ['https'],
      enabled: true,
      tags: ['isectech', 'event-processing', 'real-time', 'rate-limiting']
    });

    // Public APIs - Generous Limits
    configurations.push({
      name: 'advanced-rate-limiting',
      route: { id: 'isectech-public-docs' },
      config: {
        bucket_capacity: 1000,
        refill_rate: 16, // Very generous for public APIs
        tokens_per_request: 1,
        policies: [
          {
            limit: 1000,
            window_size: 1,
            window_type: 'minute',
            identifier: 'ip'
          }
        ],
        leaky_bucket_enabled: false,
        burst_capacity: 500,
        burst_refill_rate: 50,
        cooldown_period: 10,
        adaptive_enabled: false, // No adaptive for public APIs
        ddos_protection: {
          enabled: true,
          baseline_window: 300,
          anomaly_threshold: 20, // Higher threshold
          block_duration: 300, // Shorter block
          challenge_mode: false
        },
        policy: 'local', // Local for public APIs
        fault_tolerant: true,
        error_message: 'Public API rate limit exceeded. Please distribute your requests over time.',
        enable_detailed_logging: false, // Reduce logging for public APIs
        custom_headers: {
          'X-iSECTECH-API-Tier': 'public',
          'X-iSECTECH-Upgrade-Available': 'true'
        }
      },
      protocols: ['http', 'https'],
      enabled: true,
      tags: ['isectech', 'public', 'documentation', 'rate-limiting']
    });

    // Global DDoS Protection - Applied to all services
    configurations.push({
      name: 'advanced-rate-limiting',
      config: {
        bucket_capacity: 10000, // Very large bucket for DDoS detection
        refill_rate: 100,
        tokens_per_request: 1,
        policies: [
          {
            limit: 10000,
            window_size: 1,
            window_type: 'minute',
            identifier: 'ip'
          }
        ],
        ddos_protection: {
          enabled: true,
          baseline_window: 60,
          anomaly_threshold: 50,
          block_duration: 3600,
          challenge_mode: true
        },
        policy: 'redis',
        redis_database: 0, // Global DDoS uses main database
        limit_by: 'ip',
        error_code: 429,
        error_message: 'Potential DDoS detected. Your IP has been temporarily blocked.',
        enable_detailed_logging: true,
        precision: 'millisecond',
        custom_headers: {
          'X-iSECTECH-DDoS-Protection': 'active',
          'X-iSECTECH-Security-Level': 'maximum'
        }
      },
      protocols: ['http', 'https'],
      enabled: true,
      tags: ['isectech', 'global', 'ddos-protection', 'security'],
      ordering: {
        before: {
          '*': ['*'] // Execute before all other plugins
        }
      }
    });

    return configurations;
  }

  /**
   * Custom Kong Lua script for advanced rate limiting
   */
  public getKongLuaScript(): string {
    return `
      -- Advanced Rate Limiting Plugin for Kong Gateway
      -- Integrates with iSECTECH Advanced Token Bucket Rate Limiter
      
      local plugin = {
        PRIORITY = 1000,
        VERSION = "2.0.0",
      }
      
      local redis = require "resty.redis"
      local cjson = require "cjson"
      local ngx_time = ngx.time
      local ngx_now = ngx.now
      local string_format = string.format
      local math_floor = math.floor
      local math_ceil = math.ceil
      local math_min = math.min
      local math_max = math.max
      
      -- Advanced Token Bucket Implementation
      local function consume_tokens(conf, identifier, tokens_requested)
        local red = redis:new()
        red:set_timeout(conf.redis_timeout)
        
        local ok, err = red:connect(conf.redis_host, conf.redis_port)
        if not ok then
          if conf.fault_tolerant then
            return { allowed = true, fallback = true }
          else
            return { allowed = false, error = "Redis connection failed" }
          end
        end
        
        if conf.redis_database > 0 then
          red:select(conf.redis_database)
        end
        
        local bucket_key = "rate_limit:bucket:" .. identifier
        local current_time = math_floor(ngx_now() * 1000) -- millisecond precision
        
        -- Execute token bucket Lua script
        local script = [[
          local bucket_key = KEYS[1]
          local tokens_requested = tonumber(ARGV[1])
          local current_time = tonumber(ARGV[2])
          local capacity = tonumber(ARGV[3])
          local refill_rate = tonumber(ARGV[4])
          local leak_rate = tonumber(ARGV[5])
          local burst_capacity = tonumber(ARGV[6]) or 0
          local cooldown_period = tonumber(ARGV[7]) or 60000
          
          -- Get bucket state
          local bucket_data = redis.call('HMGET', bucket_key, 
            'tokens', 'last_refill', 'burst_tokens', 'cooldown_until', 'request_count')
          
          local tokens = tonumber(bucket_data[1]) or capacity
          local last_refill = tonumber(bucket_data[2]) or current_time
          local burst_tokens = tonumber(bucket_data[3]) or 0
          local cooldown_until = tonumber(bucket_data[4]) or 0
          local request_count = tonumber(bucket_data[5]) or 0
          
          -- Calculate time elapsed (in milliseconds)
          local time_elapsed = current_time - last_refill
          
          -- Apply leaky bucket (continuous token leak)
          if leak_rate > 0 and time_elapsed > 0 then
            local leaked_tokens = (leak_rate * time_elapsed) / 1000
            tokens = math.max(0, tokens - leaked_tokens)
          end
          
          -- Refill tokens
          if time_elapsed > 0 then
            local new_tokens = (refill_rate * time_elapsed) / 1000
            tokens = math.min(capacity, tokens + new_tokens)
          end
          
          -- Handle burst tokens
          local total_capacity = capacity
          if current_time > cooldown_until and burst_capacity > 0 then
            total_capacity = capacity + burst_capacity
            tokens = math.min(total_capacity, tokens + burst_capacity)
          end
          
          -- Check if request can be satisfied
          local can_consume = tokens >= tokens_requested
          local retry_after = 0
          
          if can_consume then
            tokens = tokens - tokens_requested
            request_count = request_count + 1
            
            -- Start cooldown if burst tokens were used
            if tokens < capacity then
              cooldown_until = current_time + cooldown_period
            end
          else
            local tokens_needed = tokens_requested - tokens
            retry_after = math_ceil((tokens_needed / refill_rate) * 1000) / 1000
          end
          
          -- Update bucket state
          redis.call('HMSET', bucket_key,
            'tokens', tokens,
            'last_refill', current_time,
            'burst_tokens', burst_capacity,
            'cooldown_until', cooldown_until,
            'request_count', request_count
          )
          
          -- Set TTL
          redis.call('EXPIRE', bucket_key, math.max(3600, math.ceil(capacity / refill_rate * 2)))
          
          return {
            can_consume and 1 or 0,
            math_floor(tokens),
            capacity,
            total_capacity,
            refill_rate,
            retry_after,
            request_count
          }
        ]]
        
        local result, err = red:eval(script, 1, bucket_key,
          tokens_requested,
          current_time,
          conf.bucket_capacity,
          conf.refill_rate,
          conf.leak_rate or 0,
          conf.burst_capacity or 0,
          (conf.cooldown_period or 60) * 1000
        )
        
        red:set_keepalive(10000, 100)
        
        if not result then
          if conf.fault_tolerant then
            return { allowed = true, fallback = true }
          else
            return { allowed = false, error = err }
          end
        end
        
        return {
          allowed = result[1] == 1,
          tokens_remaining = result[2],
          bucket_capacity = result[3],
          total_capacity = result[4],
          refill_rate = result[5],
          retry_after = result[6],
          request_count = result[7]
        }
      end
      
      -- DDoS Detection
      local function check_ddos_protection(conf, identifier, request_count)
        if not conf.ddos_protection or not conf.ddos_protection.enabled then
          return { blocked = false }
        end
        
        local red = redis:new()
        red:set_timeout(conf.redis_timeout)
        
        local ok, err = red:connect(conf.redis_host, conf.redis_port)
        if not ok then
          return { blocked = false, error = "Redis connection failed" }
        end
        
        local ddos_key = "ddos:baseline:" .. identifier
        local current_time = ngx_time()
        local window = conf.ddos_protection.baseline_window or 300
        
        -- Update request timeline
        red:zadd(ddos_key, current_time, current_time)
        red:zremrangebyscore(ddos_key, 0, current_time - window)
        red:expire(ddos_key, window * 2)
        
        -- Calculate baseline
        local baseline_requests = red:zcard(ddos_key)
        local baseline_rate = baseline_requests / window
        
        -- Check for anomaly
        local current_rate = request_count / 60 -- requests per minute
        local threshold = conf.ddos_protection.anomaly_threshold or 5
        
        if current_rate > (baseline_rate * threshold) and baseline_rate > 0 then
          -- Block IP
          local block_key = "ddos:blocked:" .. identifier
          local block_duration = conf.ddos_protection.block_duration or 3600
          red:setex(block_key, block_duration, current_time)
          
          red:set_keepalive(10000, 100)
          return { 
            blocked = true, 
            reason = "DDoS detected",
            baseline_rate = baseline_rate,
            current_rate = current_rate,
            block_duration = block_duration
          }
        end
        
        -- Check if already blocked
        local blocked = red:get("ddos:blocked:" .. identifier)
        red:set_keepalive(10000, 100)
        
        return { 
          blocked = blocked ~= ngx.null,
          baseline_rate = baseline_rate,
          current_rate = current_rate
        }
      end
      
      -- Get identifier based on configuration
      local function get_identifier(conf)
        if conf.limit_by == "consumer" then
          return kong.client.get_consumer() and kong.client.get_consumer().id or kong.client.get_ip()
        elseif conf.limit_by == "credential" then
          return kong.client.get_credential() and kong.client.get_credential().id or kong.client.get_ip()
        elseif conf.limit_by == "service" then
          return kong.router.get_service() and kong.router.get_service().id or "unknown"
        else
          return kong.client.get_ip()
        end
      end
      
      -- Generate rate limit headers
      local function set_rate_limit_headers(result, conf)
        if conf.hide_client_headers then
          return
        end
        
        kong.response.set_header("X-RateLimit-Limit", result.bucket_capacity)
        kong.response.set_header("X-RateLimit-Remaining", result.tokens_remaining)
        kong.response.set_header("X-RateLimit-Reset", math_floor(ngx_time() + (result.bucket_capacity - result.tokens_remaining) / result.refill_rate))
        
        if result.retry_after and result.retry_after > 0 then
          kong.response.set_header("Retry-After", math_ceil(result.retry_after))
        end
        
        if result.total_capacity > result.bucket_capacity then
          kong.response.set_header("X-RateLimit-Burst-Available", result.total_capacity - result.bucket_capacity)
        end
        
        -- iSECTECH specific headers
        kong.response.set_header("X-iSECTECH-RateLimit-Policy", "advanced-token-bucket")
        kong.response.set_header("X-iSECTECH-RateLimit-Precision", conf.precision or "millisecond")
        kong.response.set_header("X-iSECTECH-RateLimit-Algorithm", "hybrid-token-leaky-bucket")
        
        if conf.custom_headers then
          for header, value in pairs(conf.custom_headers) do
            kong.response.set_header(header, value)
          end
        end
      end
      
      function plugin:access(conf)
        local identifier = get_identifier(conf)
        local tokens_requested = conf.tokens_per_request or 1
        
        -- Check DDoS protection first
        local ddos_result = check_ddos_protection(conf, identifier, 1)
        if ddos_result.blocked then
          kong.log.warn("DDoS protection triggered for ", identifier, ": ", ddos_result.reason)
          return kong.response.exit(429, {
            error = "DDoS protection activated",
            message = "Your IP has been temporarily blocked due to suspicious activity",
            retry_after = ddos_result.block_duration,
            blocked_at = ngx.time(),
            type = "DDOS_PROTECTION"
          })
        end
        
        -- Consume tokens from bucket
        local result = consume_tokens(conf, identifier, tokens_requested)
        
        if result.fallback then
          kong.log.warn("Rate limiting fallback mode activated for ", identifier)
          kong.response.set_header("X-iSECTECH-RateLimit-Fallback", "true")
          return
        end
        
        if result.error then
          kong.log.err("Rate limiting error for ", identifier, ": ", result.error)
          if conf.fault_tolerant then
            kong.response.set_header("X-iSECTECH-RateLimit-Error", "true")
            return
          else
            return kong.response.exit(500, {
              error = "Rate limiting service unavailable",
              message = "Please try again later"
            })
          end
        end
        
        -- Set rate limit headers
        set_rate_limit_headers(result, conf)
        
        -- Check if request should be blocked
        if not result.allowed then
          kong.log.info("Rate limit exceeded for ", identifier, 
            " (", result.tokens_remaining, "/", result.bucket_capacity, " tokens)")
          
          local error_response = {
            error = conf.error_message or "Rate limit exceeded",
            message = "You have exceeded the rate limit. Please slow down your requests.",
            retry_after = result.retry_after,
            limit = result.bucket_capacity,
            remaining = result.tokens_remaining,
            reset_time = math_floor(ngx_time() + result.retry_after),
            type = "RATE_LIMIT_EXCEEDED"
          }
          
          return kong.response.exit(conf.error_code or 429, error_response)
        end
        
        -- Log successful request if detailed logging is enabled
        if conf.enable_detailed_logging then
          kong.log.info("Rate limit passed for ", identifier, 
            " (", result.tokens_remaining, "/", result.bucket_capacity, " tokens remaining)")
        end
      end
      
      return plugin
    `;
  }

  /**
   * Initialize default token buckets for iSECTECH services
   */
  private async initializeDefaultBuckets(): Promise<void> {
    const defaultBuckets: TokenBucketConfig[] = [
      {
        bucketId: 'isectech-high-security-global',
        name: 'High Security Global Bucket',
        capacity: 100,
        refillRate: 2,
        leakyBucket: {
          enabled: true,
          leakRate: 0.1,
          smoothing: true,
          queueCapacity: 10
        },
        burstControl: {
          enabled: true,
          burstCapacity: 25,
          burstRefillRate: 5,
          cooldownPeriod: 60
        },
        adaptive: {
          enabled: true,
          serverLoadThreshold: 0.7,
          trafficPattern: 'AUTO',
          adjustmentFactor: 0.8,
          evaluationInterval: 30
        },
        createdAt: new Date(),
        updatedAt: new Date()
      },
      {
        bucketId: 'isectech-standard-global',
        name: 'Standard Services Global Bucket',
        capacity: 200,
        refillRate: 4,
        burstControl: {
          enabled: true,
          burstCapacity: 50,
          burstRefillRate: 10,
          cooldownPeriod: 60
        },
        adaptive: {
          enabled: true,
          serverLoadThreshold: 0.8,
          trafficPattern: 'AUTO',
          adjustmentFactor: 1.2,
          evaluationInterval: 60
        },
        createdAt: new Date(),
        updatedAt: new Date()
      }
    ];

    for (const bucket of defaultBuckets) {
      try {
        await isectechAdvancedRateLimiter.createTokenBucket(bucket);
        console.log(`Created default bucket: ${bucket.bucketId}`);
      } catch (error) {
        console.error(`Failed to create default bucket ${bucket.bucketId}:`, error);
      }
    }
  }

  private startPeriodicTasks(): void {
    // DDoS baseline cleanup
    setInterval(() => {
      this.cleanupDDoSBaselines();
    }, 300000); // Every 5 minutes

    // Adaptive metrics collection
    setInterval(() => {
      this.collectAdaptiveMetrics();
    }, this.config.metricsCollectionInterval * 1000);
  }

  private cleanupDDoSBaselines(): void {
    const now = Date.now();
    for (const [ip, timestamps] of this.ddosBaselines) {
      const recentTimestamps = timestamps.filter(ts => now - ts < 600000); // Keep 10 minutes
      if (recentTimestamps.length === 0) {
        this.ddosBaselines.delete(ip);
      } else {
        this.ddosBaselines.set(ip, recentTimestamps);
      }
    }
  }

  private collectAdaptiveMetrics(): void {
    // Collect system metrics for adaptive rate limiting
    // This would integrate with system monitoring in production
    const metrics = {
      timestamp: new Date(),
      serverLoad: Math.random(), // Mock data - would be real metrics
      memoryUsage: Math.random(),
      responseTime: Math.random() * 100
    };

    const key = Math.floor(Date.now() / (60 * 1000)); // Per minute
    this.adaptiveMetrics.set(key.toString(), metrics);

    // Keep only last hour
    const cutoff = key - 60;
    for (const [k, v] of this.adaptiveMetrics) {
      if (parseInt(k) < cutoff) {
        this.adaptiveMetrics.delete(k);
      }
    }
  }

  /**
   * Get Kong plugin schema definition
   */
  public getKongPluginSchema(): any {
    return {
      name: "advanced-rate-limiting",
      fields: [
        { protocols: { type: "set", elements: { type: "string", one_of: ["grpc", "grpcs", "http", "https"] }, default: ["grpc", "grpcs", "http", "https"] } },
        { config: {
          type: "record",
          fields: [
            { bucket_capacity: { type: "integer", default: 100, gt: 0 } },
            { refill_rate: { type: "number", default: 10, gte: 0 } },
            { tokens_per_request: { type: "integer", default: 1, gt: 0 } },
            { leaky_bucket_enabled: { type: "boolean", default: false } },
            { leak_rate: { type: "number", default: 0, gte: 0 } },
            { queue_capacity: { type: "integer", default: 0, gte: 0 } },
            { burst_capacity: { type: "integer", gte: 0 } },
            { burst_refill_rate: { type: "number", gte: 0 } },
            { cooldown_period: { type: "integer", default: 60, gt: 0 } },
            { adaptive_enabled: { type: "boolean", default: false } },
            { server_load_threshold: { type: "number", default: 0.8, between: [0, 1] } },
            { adjustment_factor: { type: "number", default: 1.0, between: [0.1, 2.0] } },
            { evaluation_interval: { type: "integer", default: 60, gt: 0 } },
            { ddos_protection: {
              type: "record",
              fields: [
                { enabled: { type: "boolean", default: true } },
                { baseline_window: { type: "integer", default: 300, gte: 60 } },
                { anomaly_threshold: { type: "number", default: 5, gt: 1 } },
                { block_duration: { type: "integer", default: 3600, gt: 0 } },
                { challenge_mode: { type: "boolean", default: false } }
              ]
            }},
            { policy: { type: "string", default: "redis", one_of: ["local", "cluster", "redis"] } },
            { redis_host: { type: "string" } },
            { redis_port: { type: "integer", between: [1, 65535] } },
            { redis_database: { type: "integer", default: 0, gte: 0 } },
            { redis_timeout: { type: "integer", default: 2000, gt: 0 } },
            { limit_by: { type: "string", default: "ip", one_of: ["ip", "consumer", "credential", "service"] } },
            { fault_tolerant: { type: "boolean", default: true } },
            { hide_client_headers: { type = "boolean", default = false } },
            { error_code: { type: "integer", default = 429, between = [400, 599] } },
            { error_message: { type: "string", default = "Rate limit exceeded" } },
            { enable_detailed_logging: { type = "boolean", default = true } },
            { metrics_collection: { type = "boolean", default = true } },
            { precision: { type = "string", default = "millisecond", one_of = ["second", "millisecond", "microsecond"] } },
            { circuit_breaker_enabled: { type = "boolean", default = true } },
            { circuit_breaker_threshold: { type = "integer", default = 5, gt = 0 } },
            { custom_headers: { type: "map", keys: { type = "string" }, values: { type = "string" } } }
          ]
        }}
      ]
    };
  }
}

// Export configured plugin manager for iSECTECH
export const isectechKongRateLimitingPlugin = new KongAdvancedRateLimitingPlugin({
  defaultBucketCapacity: 100,
  defaultRefillRate: 10,
  redisKeyPrefix: 'isectech:rate_limit:',
  enableGlobalDDoSProtection: true,
  metricsCollectionInterval: 60
});