/**
 * Production-grade Caching Configuration for iSECTECH Kong Gateway
 * 
 * Provides comprehensive caching strategies for different types of API endpoints
 * to improve performance, reduce backend load, and enhance user experience.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import { z } from 'zod';

// Caching Configuration Schemas
export const CacheConfigSchema = z.object({
  serviceName: z.string(),
  routeName: z.string(),
  cacheStrategy: z.enum([
    'AGGRESSIVE_CACHE',
    'MODERATE_CACHE', 
    'CONSERVATIVE_CACHE',
    'NO_CACHE',
    'CONDITIONAL_CACHE'
  ]),
  cacheTTL: z.object({
    default: z.number().min(0), // seconds
    min: z.number().min(0),
    max: z.number().min(0),
    vary_by_headers: z.array(z.string()).optional()
  }),
  cacheKey: z.object({
    includeHeaders: z.array(z.string()).default(['Host', 'Accept', 'Accept-Language']),
    includeQueryParams: z.array(z.string()).optional(),
    excludeQueryParams: z.array(z.string()).optional(),
    includeConsumer: z.boolean().default(false),
    includeTenant: z.boolean().default(true),
    customKeyTemplate: z.string().optional()
  }),
  storage: z.object({
    type: z.enum(['memory', 'redis', 'hybrid']).default('redis'),
    memory: z.object({
      dictionary_name: z.string().default('kong_cache'),
      max_size: z.string().default('256m')
    }).optional(),
    redis: z.object({
      host: z.string().default('redis.isectech-cache.svc.cluster.local'),
      port: z.number().default(6379),
      password: z.string().optional(),
      database: z.number().default(0),
      ssl: z.boolean().default(true),
      ssl_verify: z.boolean().default(true),
      timeout: z.number().default(2000)
    }).optional()
  }),
  conditions: z.object({
    request_method: z.array(z.string()).default(['GET', 'HEAD']),
    response_code: z.array(z.number()).default([200, 203, 300, 301, 404, 410]),
    content_type: z.array(z.string()).optional(),
    max_response_size: z.number().default(1048576), // 1MB
    cache_control_respect: z.boolean().default(true)
  }),
  invalidation: z.object({
    enabled: z.boolean().default(true),
    surrogate_keys: z.array(z.string()).optional(),
    webhook_endpoints: z.array(z.string()).optional(),
    auto_invalidate_patterns: z.array(z.string()).optional()
  }),
  security: z.object({
    tenant_isolation: z.boolean().default(true),
    encrypt_cached_data: z.boolean().default(true),
    pii_detection: z.boolean().default(true),
    cache_poisoning_protection: z.boolean().default(true)
  }),
  monitoring: z.object({
    hit_rate_tracking: z.boolean().default(true),
    performance_metrics: z.boolean().default(true),
    cache_size_monitoring: z.boolean().default(true),
    alerting_enabled: z.boolean().default(true)
  }),
  tags: z.array(z.string()).default(['isectech', 'caching', 'performance'])
});

export type CacheConfig = z.infer<typeof CacheConfigSchema>;

export interface CacheMetrics {
  serviceName: string;
  routeName: string;
  hitRate: number;
  missRate: number;
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  averageResponseTime: number;
  cacheSize: number;
  evictions: number;
  lastUpdated: Date;
}

/**
 * Intelligent Caching Manager for iSECTECH Services
 */
export class ISECTECHCachingManager {
  private cacheConfigs: Map<string, CacheConfig> = new Map();
  private metricsStore: Map<string, CacheMetrics> = new Map();

  constructor() {
    this.initializeISECTECHCacheConfigurations();
  }

  /**
   * Initialize caching configurations for iSECTECH services
   */
  private initializeISECTECHCacheConfigurations(): void {
    // Asset Discovery Inventory Cache (Static-ish data)
    const assetInventoryCache: CacheConfig = {
      serviceName: 'isectech-asset-discovery',
      routeName: 'isectech-asset-discovery-inventory',
      cacheStrategy: 'AGGRESSIVE_CACHE',
      cacheTTL: {
        default: 300, // 5 minutes
        min: 60,
        max: 900,
        vary_by_headers: ['X-Tenant-ID', 'Accept']
      },
      cacheKey: {
        includeHeaders: ['Host', 'Accept', 'X-Tenant-ID', 'Authorization'],
        includeQueryParams: ['filter', 'sort', 'limit', 'offset'],
        excludeQueryParams: ['timestamp', '_t'],
        includeConsumer: true,
        includeTenant: true,
        customKeyTemplate: 'asset-inventory:{tenant}:{user}:{query_hash}'
      },
      storage: {
        type: 'redis',
        redis: {
          host: 'redis.isectech-cache.svc.cluster.local',
          port: 6379,
          database: 1, // Dedicated DB for asset cache
          ssl: true,
          ssl_verify: true,
          timeout: 2000
        }
      },
      conditions: {
        request_method: ['GET', 'HEAD'],
        response_code: [200, 203, 300],
        content_type: ['application/json', 'application/vnd.api+json'],
        max_response_size: 2097152, // 2MB for asset lists
        cache_control_respect: true
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['asset-inventory', 'asset-discovery'],
        webhook_endpoints: ['/cache/invalidate/assets'],
        auto_invalidate_patterns: ['/api/v1/assets/scan']
      },
      security: {
        tenant_isolation: true,
        encrypt_cached_data: true,
        pii_detection: true,
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'asset-discovery', 'inventory', 'caching']
    };

    // Threat Intelligence Cache (Moderate frequency updates)
    const threatIntelCache: CacheConfig = {
      serviceName: 'isectech-threat-detection',
      routeName: 'isectech-threat-intelligence',
      cacheStrategy: 'MODERATE_CACHE',
      cacheTTL: {
        default: 120, // 2 minutes
        min: 30,
        max: 300,
        vary_by_headers: ['X-Tenant-ID', 'X-Threat-Level']
      },
      cacheKey: {
        includeHeaders: ['Host', 'Accept', 'X-Tenant-ID', 'X-Threat-Level'],
        includeQueryParams: ['ioc_type', 'threat_family', 'confidence'],
        excludeQueryParams: ['timestamp', 'request_id'],
        includeConsumer: true,
        includeTenant: true,
        customKeyTemplate: 'threat-intel:{tenant}:{threat_level}:{ioc_hash}'
      },
      storage: {
        type: 'redis',
        redis: {
          host: 'redis.isectech-cache.svc.cluster.local',
          port: 6379,
          database: 2, // Dedicated DB for threat intel
          ssl: true,
          ssl_verify: true,
          timeout: 1500
        }
      },
      conditions: {
        request_method: ['GET', 'HEAD'],
        response_code: [200, 203],
        content_type: ['application/json'],
        max_response_size: 1048576, // 1MB
        cache_control_respect: true
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['threat-intel', 'threat-detection'],
        webhook_endpoints: ['/cache/invalidate/threats'],
        auto_invalidate_patterns: ['/api/v1/threats/update', '/api/v1/threats/feed']
      },
      security: {
        tenant_isolation: true,
        encrypt_cached_data: true,
        pii_detection: false, // No PII in threat intel
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'threat-detection', 'intelligence', 'caching']
    };

    // Compliance Reports Cache (Long-lived reports)
    const complianceReportsCache: CacheConfig = {
      serviceName: 'isectech-compliance-automation',
      routeName: 'isectech-compliance-reports',
      cacheStrategy: 'AGGRESSIVE_CACHE',
      cacheTTL: {
        default: 1800, // 30 minutes
        min: 600,
        max: 3600,
        vary_by_headers: ['X-Tenant-ID', 'Accept']
      },
      cacheKey: {
        includeHeaders: ['Host', 'Accept', 'X-Tenant-ID'],
        includeQueryParams: ['framework', 'period', 'format'],
        excludeQueryParams: ['download_token', 'timestamp'],
        includeConsumer: true,
        includeTenant: true,
        customKeyTemplate: 'compliance-report:{tenant}:{framework}:{period}:{format}'
      },
      storage: {
        type: 'redis',
        redis: {
          host: 'redis.isectech-cache.svc.cluster.local',
          port: 6379,
          database: 3, // Dedicated DB for compliance cache
          ssl: true,
          ssl_verify: true,
          timeout: 3000
        }
      },
      conditions: {
        request_method: ['GET', 'HEAD'],
        response_code: [200, 203],
        content_type: ['application/json', 'application/pdf', 'text/csv'],
        max_response_size: 10485760, // 10MB for large reports
        cache_control_respect: true
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['compliance-reports', 'compliance-automation'],
        webhook_endpoints: ['/cache/invalidate/compliance'],
        auto_invalidate_patterns: ['/api/v1/compliance/generate', '/api/v1/compliance/controls/update']
      },
      security: {
        tenant_isolation: true,
        encrypt_cached_data: true,
        pii_detection: true,
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'compliance', 'reports', 'caching']
    };

    // Real-time Events Cache (Very short-lived)
    const eventsCache: CacheConfig = {
      serviceName: 'isectech-event-processing',
      routeName: 'isectech-events-aggregate',
      cacheStrategy: 'CONSERVATIVE_CACHE',
      cacheTTL: {
        default: 30, // 30 seconds
        min: 10,
        max: 60,
        vary_by_headers: ['X-Tenant-ID']
      },
      cacheKey: {
        includeHeaders: ['Host', 'X-Tenant-ID'],
        includeQueryParams: ['time_range', 'event_type', 'severity'],
        excludeQueryParams: ['real_time', 'stream_id'],
        includeConsumer: false,
        includeTenant: true,
        customKeyTemplate: 'events-agg:{tenant}:{time_range}:{event_type}'
      },
      storage: {
        type: 'memory', // Fast memory cache for real-time data
        memory: {
          dictionary_name: 'kong_events_cache',
          max_size: '128m'
        }
      },
      conditions: {
        request_method: ['GET'],
        response_code: [200],
        content_type: ['application/json'],
        max_response_size: 524288, // 512KB
        cache_control_respect: false // Ignore cache-control for real-time data
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['events-aggregate'],
        webhook_endpoints: ['/cache/invalidate/events'],
        auto_invalidate_patterns: ['/api/v1/events/process', '/api/v1/events/ingest']
      },
      security: {
        tenant_isolation: true,
        encrypt_cached_data: false, // Skip encryption for performance
        pii_detection: true,
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'event-processing', 'real-time', 'caching']
    };

    // User Profile Cache (Medium-term cache)
    const userProfileCache: CacheConfig = {
      serviceName: 'isectech-user-management',
      routeName: 'isectech-user-profiles',
      cacheStrategy: 'MODERATE_CACHE',
      cacheTTL: {
        default: 600, // 10 minutes
        min: 300,
        max: 1800,
        vary_by_headers: ['X-Tenant-ID', 'Authorization']
      },
      cacheKey: {
        includeHeaders: ['Host', 'X-Tenant-ID', 'Authorization'],
        includeQueryParams: ['include_permissions', 'include_roles'],
        excludeQueryParams: ['last_login', 'session_id'],
        includeConsumer: true,
        includeTenant: true,
        customKeyTemplate: 'user-profile:{tenant}:{user_id}:{permissions}'
      },
      storage: {
        type: 'redis',
        redis: {
          host: 'redis.isectech-cache.svc.cluster.local',
          port: 6379,
          database: 4, // Dedicated DB for user cache
          ssl: true,
          ssl_verify: true,
          timeout: 2000
        }
      },
      conditions: {
        request_method: ['GET', 'HEAD'],
        response_code: [200, 203],
        content_type: ['application/json'],
        max_response_size: 262144, // 256KB
        cache_control_respect: true
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['user-profiles', 'user-management'],
        webhook_endpoints: ['/cache/invalidate/users'],
        auto_invalidate_patterns: ['/api/v1/users/update', '/api/v1/users/permissions']
      },
      security: {
        tenant_isolation: true,
        encrypt_cached_data: true,
        pii_detection: true,
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'user-management', 'profiles', 'caching']
    };

    // API Documentation Cache (Very long-lived)
    const apiDocsCache: CacheConfig = {
      serviceName: 'isectech-api-docs',
      routeName: 'isectech-api-documentation',
      cacheStrategy: 'AGGRESSIVE_CACHE',
      cacheTTL: {
        default: 3600, // 1 hour
        min: 1800,
        max: 7200,
        vary_by_headers: ['Accept', 'Accept-Language']
      },
      cacheKey: {
        includeHeaders: ['Host', 'Accept', 'Accept-Language'],
        includeQueryParams: ['version', 'format'],
        excludeQueryParams: ['timestamp', 'user_id'],
        includeConsumer: false,
        includeTenant: false,
        customKeyTemplate: 'api-docs:{version}:{format}:{lang}'
      },
      storage: {
        type: 'hybrid',
        memory: {
          dictionary_name: 'kong_docs_cache',
          max_size: '64m'
        },
        redis: {
          host: 'redis.isectech-cache.svc.cluster.local',
          port: 6379,
          database: 5, // Dedicated DB for docs cache
          ssl: true,
          ssl_verify: true,
          timeout: 2000
        }
      },
      conditions: {
        request_method: ['GET', 'HEAD'],
        response_code: [200, 203, 300, 301],
        content_type: ['text/html', 'application/json', 'text/yaml'],
        max_response_size: 5242880, // 5MB for large docs
        cache_control_respect: true
      },
      invalidation: {
        enabled: true,
        surrogate_keys: ['api-docs', 'documentation'],
        webhook_endpoints: ['/cache/invalidate/docs'],
        auto_invalidate_patterns: ['/api/docs/update', '/api/docs/publish']
      },
      security: {
        tenant_isolation: false, // Public docs
        encrypt_cached_data: false,
        pii_detection: false,
        cache_poisoning_protection: true
      },
      monitoring: {
        hit_rate_tracking: true,
        performance_metrics: true,
        cache_size_monitoring: true,
        alerting_enabled: true
      },
      tags: ['isectech', 'documentation', 'api-docs', 'caching']
    };

    // Store all cache configurations
    [
      assetInventoryCache,
      threatIntelCache,
      complianceReportsCache,
      eventsCache,
      userProfileCache,
      apiDocsCache
    ].forEach(config => {
      const validatedConfig = CacheConfigSchema.parse(config);
      const key = `${config.serviceName}:${config.routeName}`;
      this.cacheConfigs.set(key, validatedConfig);
      
      // Initialize metrics for each cache
      this.metricsStore.set(key, {
        serviceName: config.serviceName,
        routeName: config.routeName,
        hitRate: 0,
        missRate: 0,
        totalRequests: 0,
        cacheHits: 0,
        cacheMisses: 0,
        averageResponseTime: 0,
        cacheSize: 0,
        evictions: 0,
        lastUpdated: new Date()
      });
    });
  }

  /**
   * Get cache configuration for a service/route
   */
  public getCacheConfig(serviceName: string, routeName: string): CacheConfig | undefined {
    return this.cacheConfigs.get(`${serviceName}:${routeName}`);
  }

  /**
   * Get all cache configurations
   */
  public getAllCacheConfigs(): Map<string, CacheConfig> {
    return new Map(this.cacheConfigs);
  }

  /**
   * Update cache configuration
   */
  public updateCacheConfig(serviceName: string, routeName: string, config: Partial<CacheConfig>): void {
    const key = `${serviceName}:${routeName}`;
    const existingConfig = this.cacheConfigs.get(key);
    if (existingConfig) {
      const updatedConfig = { ...existingConfig, ...config };
      const validatedConfig = CacheConfigSchema.parse(updatedConfig);
      this.cacheConfigs.set(key, validatedConfig);
      console.log(`Updated cache configuration for ${serviceName}:${routeName}`);
    } else {
      throw new Error(`Cache configuration not found for: ${serviceName}:${routeName}`);
    }
  }

  /**
   * Get cache metrics
   */
  public getCacheMetrics(serviceName: string, routeName: string): CacheMetrics | undefined {
    return this.metricsStore.get(`${serviceName}:${routeName}`);
  }

  /**
   * Get all cache metrics
   */
  public getAllCacheMetrics(): Map<string, CacheMetrics> {
    return new Map(this.metricsStore);
  }

  /**
   * Generate Kong proxy-cache plugin configurations
   */
  public generateKongCachePluginConfigurations(): Array<{
    name: string;
    route: { id: string };
    config: object;
    enabled: boolean;
    tags: string[];
  }> {
    const pluginConfigurations: Array<{
      name: string;
      route: { id: string };
      config: object;
      enabled: boolean;
      tags: string[];
    }> = [];

    for (const [key, config] of this.cacheConfigs) {
      if (config.cacheStrategy !== 'NO_CACHE') {
        pluginConfigurations.push({
          name: 'proxy-cache',
          route: { id: config.routeName },
          config: {
            response_code: config.conditions.response_code,
            request_method: config.conditions.request_method,
            content_type: config.conditions.content_type || ['text/plain', 'application/json'],
            cache_ttl: config.cacheTTL.default,
            cache_control: config.conditions.cache_control_respect,
            strategy: config.storage.type,
            ...(config.storage.redis && {
              redis: {
                host: config.storage.redis.host,
                port: config.storage.redis.port,
                password: config.storage.redis.password,
                database: config.storage.redis.database,
                ssl: config.storage.redis.ssl,
                ssl_verify: config.storage.redis.ssl_verify,
                timeout: config.storage.redis.timeout
              }
            }),
            ...(config.storage.memory && {
              memory: {
                dictionary_name: config.storage.memory.dictionary_name
              }
            }),
            vary_headers: config.cacheKey.includeHeaders,
            vary_query_params: config.cacheKey.includeQueryParams,
            ignore_query_params: config.cacheKey.excludeQueryParams
          },
          enabled: true,
          tags: config.tags
        });
      }
    }

    return pluginConfigurations;
  }

  /**
   * Generate cache invalidation webhook configuration
   */
  public generateCacheInvalidationConfig(): object {
    const invalidationConfig: Record<string, any> = {};

    for (const [key, config] of this.cacheConfigs) {
      if (config.invalidation.enabled && config.invalidation.webhook_endpoints) {
        invalidationConfig[key] = {
          surrogate_keys: config.invalidation.surrogate_keys,
          webhook_endpoints: config.invalidation.webhook_endpoints,
          auto_invalidate_patterns: config.invalidation.auto_invalidate_patterns,
          tags: config.tags
        };
      }
    }

    return invalidationConfig;
  }

  /**
   * Generate cache monitoring configuration
   */
  public generateCacheMonitoringConfig(): object {
    const monitoringConfig: Record<string, any> = {};

    for (const [key, config] of this.cacheConfigs) {
      if (config.monitoring.alerting_enabled) {
        monitoringConfig[`${key}-low-hit-rate`] = {
          condition: `cache_hit_rate{service="${config.serviceName}",route="${config.routeName}"} < 0.7`,
          severity: 'warning',
          summary: `Low cache hit rate for ${config.serviceName}:${config.routeName}`,
          description: `Cache hit rate is below 70% for ${config.serviceName}:${config.routeName}`,
          tags: config.tags
        };

        monitoringConfig[`${key}-high-cache-size`] = {
          condition: `cache_size_bytes{service="${config.serviceName}",route="${config.routeName}"} > 1073741824`, // 1GB
          severity: 'warning',
          summary: `High cache size for ${config.serviceName}:${config.routeName}`,
          description: `Cache size is above 1GB for ${config.serviceName}:${config.routeName}`,
          tags: config.tags
        };
      }
    }

    return monitoringConfig;
  }

  /**
   * Validate all cache configurations
   */
  public validateConfigurations(): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const [key, config] of this.cacheConfigs) {
      try {
        CacheConfigSchema.parse(config);
        
        // Additional business logic validation
        if (config.cacheTTL.min > config.cacheTTL.max) {
          errors.push(`Invalid TTL configuration for ${key}: min TTL cannot be greater than max TTL`);
        }
        
        if (config.cacheTTL.default < config.cacheTTL.min || config.cacheTTL.default > config.cacheTTL.max) {
          errors.push(`Invalid TTL configuration for ${key}: default TTL must be between min and max TTL`);
        }
      } catch (error) {
        errors.push(`Invalid configuration for ${key}: ${error}`);
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Optimize cache configurations based on metrics
   */
  public optimizeCacheConfigurations(): { optimizations: string[]; recommendations: string[] } {
    const optimizations: string[] = [];
    const recommendations: string[] = [];

    for (const [key, metrics] of this.metricsStore) {
      const config = this.cacheConfigs.get(key);
      if (!config) continue;

      // Low hit rate optimization
      if (metrics.hitRate < 0.5) {
        recommendations.push(`Consider increasing TTL for ${key} (current hit rate: ${(metrics.hitRate * 100).toFixed(1)}%)`);
        
        if (config.cacheTTL.default < config.cacheTTL.max * 0.7) {
          const newTTL = Math.min(config.cacheTTL.default * 1.5, config.cacheTTL.max);
          this.updateCacheConfig(config.serviceName, config.routeName, {
            cacheTTL: { ...config.cacheTTL, default: newTTL }
          });
          optimizations.push(`Increased TTL for ${key} from ${config.cacheTTL.default}s to ${newTTL}s`);
        }
      }

      // High eviction rate optimization
      if (metrics.evictions > metrics.totalRequests * 0.1) {
        recommendations.push(`High eviction rate for ${key}. Consider increasing cache size or reducing TTL`);
      }

      // Performance optimization
      if (metrics.averageResponseTime > 1000 && config.storage.type === 'redis') {
        recommendations.push(`Consider switching ${key} to memory cache for better performance`);
      }
    }

    return { optimizations, recommendations };
  }
}

// Export production-ready caching manager
export const isectechCachingManager = new ISECTECHCachingManager();