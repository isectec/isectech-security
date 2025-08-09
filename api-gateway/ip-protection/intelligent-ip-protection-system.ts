/**
 * Intelligent IP-Based Protection System for iSECTECH API Gateway
 * 
 * Comprehensive IP protection with allow/deny lists, geolocation filtering,
 * reputation-based blocking, and dynamic threat intelligence integration.
 * 
 * Features:
 * - CIDR-based allow/deny lists with hierarchical rules
 * - Geolocation filtering with country/region granularity
 * - IP reputation scoring with threat intelligence feeds
 * - Dynamic temporary banning with escalation policies
 * - Real-time analytics and forensic capabilities
 */

import { Redis } from 'ioredis';
import { z } from 'zod';
import { Logger } from 'winston';
import axios from 'axios';
import geoip from 'geoip-lite';
import { Parser as NetMask } from 'netmask';

// Configuration schemas
const IPRuleSchema = z.object({
  id: z.string(),
  type: z.enum(['ALLOW', 'DENY']),
  cidr: z.string(),
  priority: z.number().min(1).max(1000),
  description: z.string(),
  expiresAt: z.date().optional(),
  createdBy: z.string(),
  tags: z.array(z.string()).default([]),
});

const GeolocationRuleSchema = z.object({
  id: z.string(),
  type: z.enum(['ALLOW', 'DENY']),
  countries: z.array(z.string()).optional(),
  regions: z.array(z.string()).optional(),
  asns: z.array(z.number()).optional(),
  priority: z.number().min(1).max(1000),
  description: z.string(),
  isActive: z.boolean().default(true),
});

const ReputationConfigSchema = z.object({
  enabled: z.boolean().default(true),
  sources: z.array(z.object({
    name: z.string(),
    apiKey: z.string(),
    endpoint: z.string(),
    weight: z.number().min(0).max(1),
    cacheTtl: z.number().default(3600),
  })),
  thresholds: z.object({
    block: z.number().min(0).max(100).default(80),
    suspicious: z.number().min(0).max(100).default(60),
    clean: z.number().min(0).max(100).default(20),
  }),
  temporaryBan: z.object({
    enabled: z.boolean().default(true),
    initialDuration: z.number().default(300), // 5 minutes
    maxDuration: z.number().default(86400), // 24 hours
    escalationFactor: z.number().default(2),
  }),
});

const IPProtectionConfigSchema = z.object({
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(0),
    keyPrefix: z.string().default('ip_protection:'),
  }),
  geolocation: z.object({
    enabled: z.boolean().default(true),
    defaultPolicy: z.enum(['ALLOW', 'DENY']).default('ALLOW'),
    database: z.string().default('maxmind'),
  }),
  reputation: ReputationConfigSchema,
  analytics: z.object({
    enabled: z.boolean().default(true),
    retentionDays: z.number().default(30),
    realTimeMetrics: z.boolean().default(true),
  }),
  rateLimit: z.object({
    checkRequests: z.number().default(10000),
    checkWindow: z.number().default(60),
    cacheSize: z.number().default(100000),
  }),
});

type IPRule = z.infer<typeof IPRuleSchema>;
type GeolocationRule = z.infer<typeof GeolocationRuleSchema>;
type ReputationConfig = z.infer<typeof ReputationConfigSchema>;
type IPProtectionConfig = z.infer<typeof IPProtectionConfigSchema>;

interface IPAnalytics {
  ip: string;
  country?: string;
  asn?: number;
  reputationScore: number;
  totalRequests: number;
  blockedRequests: number;
  lastSeen: Date;
  riskFactors: string[];
}

interface ProtectionDecision {
  action: 'ALLOW' | 'DENY' | 'CHALLENGE';
  reason: string;
  ruleId?: string;
  score: number;
  metadata: {
    country?: string;
    asn?: number;
    reputation?: number;
    temporaryBan?: boolean;
    escalationLevel?: number;
  };
}

interface ThreatIntelligenceResponse {
  score: number;
  categories: string[];
  lastSeen?: Date;
  confidence: number;
  source: string;
}

/**
 * Comprehensive IP-based protection system with intelligent threat detection
 */
export class IntelligentIPProtectionSystem {
  private redis: Redis;
  private logger: Logger;
  private config: IPProtectionConfig;
  private ipRules: Map<string, IPRule> = new Map();
  private geoRules: Map<string, GeolocationRule> = new Map();
  private reputationCache: Map<string, { score: number; expiry: number }> = new Map();
  private networkCache: Map<string, NetMask> = new Map();
  private metricsCache: Map<string, number> = new Map();

  constructor(config: IPProtectionConfig, logger: Logger) {
    this.config = IPProtectionConfigSchema.parse(config);
    this.logger = logger;
    
    this.redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      password: this.config.redis.password,
      db: this.config.redis.db,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
    });

    this.initializeSystem();
  }

  /**
   * Initialize the IP protection system
   */
  private async initializeSystem(): Promise<void> {
    try {
      await this.loadIPRules();
      await this.loadGeolocationRules();
      this.startMetricsCollection();
      this.startCacheCleanup();
      
      this.logger.info('IP Protection System initialized successfully', {
        component: 'IntelligentIPProtectionSystem',
        ipRules: this.ipRules.size,
        geoRules: this.geoRules.size,
      });
    } catch (error) {
      this.logger.error('Failed to initialize IP Protection System', {
        component: 'IntelligentIPProtectionSystem',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Main method to evaluate IP protection for incoming requests
   */
  async evaluateIPProtection(
    ip: string,
    userAgent?: string,
    headers?: Record<string, string>
  ): Promise<ProtectionDecision> {
    const startTime = Date.now();
    
    try {
      // Check for temporary bans first
      const tempBan = await this.checkTemporaryBan(ip);
      if (tempBan.isBanned) {
        await this.recordMetrics(ip, 'DENY', 'temporary_ban');
        return {
          action: 'DENY',
          reason: `Temporarily banned: ${tempBan.reason}`,
          score: 100,
          metadata: {
            temporaryBan: true,
            escalationLevel: tempBan.escalationLevel,
          },
        };
      }

      // Check explicit IP rules (highest priority)
      const ipRuleDecision = await this.evaluateIPRules(ip);
      if (ipRuleDecision) {
        await this.recordMetrics(ip, ipRuleDecision.action, 'ip_rule');
        return ipRuleDecision;
      }

      // Check geolocation rules
      const geoDecision = await this.evaluateGeolocationRules(ip);
      if (geoDecision) {
        await this.recordMetrics(ip, geoDecision.action, 'geolocation');
        return geoDecision;
      }

      // Check IP reputation
      const reputationDecision = await this.evaluateReputationRules(ip);
      if (reputationDecision) {
        await this.recordMetrics(ip, reputationDecision.action, 'reputation');
        return reputationDecision;
      }

      // Default allow with analytics
      await this.recordMetrics(ip, 'ALLOW', 'default');
      await this.updateIPAnalytics(ip, {
        action: 'ALLOW',
        userAgent,
        headers,
      });

      return {
        action: 'ALLOW',
        reason: 'No blocking rules matched',
        score: 0,
        metadata: {},
      };

    } catch (error) {
      this.logger.error('Error evaluating IP protection', {
        component: 'IntelligentIPProtectionSystem',
        ip,
        error: error.message,
      });

      // Fail open on errors to maintain availability
      return {
        action: 'ALLOW',
        reason: 'Protection system error - fail open',
        score: 0,
        metadata: {},
      };
    } finally {
      const duration = Date.now() - startTime;
      await this.redis.hset('metrics:performance', 'avg_decision_time', duration);
    }
  }

  /**
   * Evaluate explicit IP rules (allow/deny lists with CIDR support)
   */
  private async evaluateIPRules(ip: string): Promise<ProtectionDecision | null> {
    const sortedRules = Array.from(this.ipRules.values())
      .filter(rule => !rule.expiresAt || rule.expiresAt > new Date())
      .sort((a, b) => b.priority - a.priority);

    for (const rule of sortedRules) {
      if (await this.ipMatchesCIDR(ip, rule.cidr)) {
        const decision: ProtectionDecision = {
          action: rule.type,
          reason: `Matched IP rule: ${rule.description}`,
          ruleId: rule.id,
          score: rule.type === 'DENY' ? 100 : 0,
          metadata: {},
        };

        this.logger.info('IP rule matched', {
          component: 'IntelligentIPProtectionSystem',
          ip,
          ruleId: rule.id,
          action: rule.type,
        });

        return decision;
      }
    }

    return null;
  }

  /**
   * Evaluate geolocation-based rules
   */
  private async evaluateGeolocationRules(ip: string): Promise<ProtectionDecision | null> {
    if (!this.config.geolocation.enabled) {
      return null;
    }

    const geoData = geoip.lookup(ip);
    if (!geoData) {
      return null;
    }

    const sortedRules = Array.from(this.geoRules.values())
      .filter(rule => rule.isActive)
      .sort((a, b) => b.priority - a.priority);

    for (const rule of sortedRules) {
      let matches = false;

      if (rule.countries && rule.countries.includes(geoData.country)) {
        matches = true;
      }

      if (rule.regions && rule.regions.includes(geoData.region)) {
        matches = true;
      }

      // ASN matching would require additional GeoIP database
      // Placeholder for ASN-based rules

      if (matches) {
        const decision: ProtectionDecision = {
          action: rule.type,
          reason: `Geolocation rule: ${rule.description}`,
          ruleId: rule.id,
          score: rule.type === 'DENY' ? 80 : 0,
          metadata: {
            country: geoData.country,
          },
        };

        this.logger.info('Geolocation rule matched', {
          component: 'IntelligentIPProtectionSystem',
          ip,
          country: geoData.country,
          ruleId: rule.id,
          action: rule.type,
        });

        return decision;
      }
    }

    return null;
  }

  /**
   * Evaluate reputation-based rules with threat intelligence
   */
  private async evaluateReputationRules(ip: string): Promise<ProtectionDecision | null> {
    if (!this.config.reputation.enabled) {
      return null;
    }

    const reputationScore = await this.getIPReputationScore(ip);
    
    if (reputationScore >= this.config.reputation.thresholds.block) {
      // Consider temporary ban for high-risk IPs
      await this.applyTemporaryBan(ip, 'High reputation risk score', reputationScore);
      
      return {
        action: 'DENY',
        reason: `High risk reputation score: ${reputationScore}`,
        score: reputationScore,
        metadata: {
          reputation: reputationScore,
        },
      };
    }

    if (reputationScore >= this.config.reputation.thresholds.suspicious) {
      return {
        action: 'CHALLENGE',
        reason: `Suspicious reputation score: ${reputationScore}`,
        score: reputationScore,
        metadata: {
          reputation: reputationScore,
        },
      };
    }

    return null;
  }

  /**
   * Get comprehensive IP reputation score from multiple sources
   */
  private async getIPReputationScore(ip: string): Promise<number> {
    const cacheKey = `reputation:${ip}`;
    const cached = this.reputationCache.get(cacheKey);
    
    if (cached && cached.expiry > Date.now()) {
      return cached.score;
    }

    try {
      const scores: number[] = [];
      const weights: number[] = [];

      for (const source of this.config.reputation.sources) {
        try {
          const intel = await this.queryThreatIntelligence(ip, source);
          scores.push(intel.score);
          weights.push(source.weight);
        } catch (error) {
          this.logger.warn('Threat intelligence source failed', {
            component: 'IntelligentIPProtectionSystem',
            source: source.name,
            ip,
            error: error.message,
          });
        }
      }

      if (scores.length === 0) {
        return 0; // No data available
      }

      // Calculate weighted average
      const weightedSum = scores.reduce((sum, score, index) => sum + score * weights[index], 0);
      const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
      const finalScore = Math.round(weightedSum / totalWeight);

      // Cache the result
      this.reputationCache.set(cacheKey, {
        score: finalScore,
        expiry: Date.now() + (this.config.reputation.sources[0]?.cacheTtl ?? 3600) * 1000,
      });

      // Store in Redis for persistence
      await this.redis.setex(`${this.config.redis.keyPrefix}${cacheKey}`, 
        this.config.reputation.sources[0]?.cacheTtl ?? 3600, finalScore);

      return finalScore;
    } catch (error) {
      this.logger.error('Error calculating reputation score', {
        component: 'IntelligentIPProtectionSystem',
        ip,
        error: error.message,
      });
      return 0;
    }
  }

  /**
   * Query threat intelligence sources for IP reputation
   */
  private async queryThreatIntelligence(
    ip: string, 
    source: any
  ): Promise<ThreatIntelligenceResponse> {
    const response = await axios.get(source.endpoint, {
      params: { ip },
      headers: {
        'Authorization': `Bearer ${source.apiKey}`,
        'User-Agent': 'iSECTECH-IP-Protection/1.0',
      },
      timeout: 5000,
    });

    // Normalize response based on source
    // This is a simplified example - real implementations would handle
    // specific API formats for VirusTotal, AbuseIPDB, etc.
    return {
      score: response.data.score || 0,
      categories: response.data.categories || [],
      confidence: response.data.confidence || 50,
      source: source.name,
    };
  }

  /**
   * Check if IP is under temporary ban
   */
  private async checkTemporaryBan(ip: string): Promise<{
    isBanned: boolean;
    reason?: string;
    expiresAt?: Date;
    escalationLevel?: number;
  }> {
    const banKey = `temp_ban:${ip}`;
    const banData = await this.redis.hgetall(banKey);

    if (!banData || !banData.expiresAt) {
      return { isBanned: false };
    }

    const expiresAt = new Date(parseInt(banData.expiresAt));
    if (expiresAt <= new Date()) {
      await this.redis.del(banKey);
      return { isBanned: false };
    }

    return {
      isBanned: true,
      reason: banData.reason,
      expiresAt,
      escalationLevel: parseInt(banData.escalationLevel || '1'),
    };
  }

  /**
   * Apply temporary ban with escalation
   */
  private async applyTemporaryBan(ip: string, reason: string, score: number): Promise<void> {
    if (!this.config.reputation.temporaryBan.enabled) {
      return;
    }

    const banKey = `temp_ban:${ip}`;
    const existingBan = await this.redis.hgetall(banKey);
    
    let escalationLevel = 1;
    let duration = this.config.reputation.temporaryBan.initialDuration;

    if (existingBan && existingBan.escalationLevel) {
      escalationLevel = Math.min(
        parseInt(existingBan.escalationLevel) + 1,
        10 // Max escalation level
      );
      duration = Math.min(
        this.config.reputation.temporaryBan.initialDuration * 
        Math.pow(this.config.reputation.temporaryBan.escalationFactor, escalationLevel - 1),
        this.config.reputation.temporaryBan.maxDuration
      );
    }

    const expiresAt = new Date(Date.now() + duration * 1000);

    await this.redis.hset(banKey, {
      reason,
      score: score.toString(),
      escalationLevel: escalationLevel.toString(),
      expiresAt: expiresAt.getTime().toString(),
      appliedAt: Date.now().toString(),
    });

    await this.redis.expire(banKey, duration);

    this.logger.warn('Temporary ban applied', {
      component: 'IntelligentIPProtectionSystem',
      ip,
      reason,
      duration: duration,
      escalationLevel,
      expiresAt,
    });
  }

  /**
   * Check if IP matches CIDR block
   */
  private async ipMatchesCIDR(ip: string, cidr: string): Promise<boolean> {
    try {
      let block = this.networkCache.get(cidr);
      if (!block) {
        block = new NetMask(cidr);
        this.networkCache.set(cidr, block);
      }
      return block.contains(ip);
    } catch (error) {
      this.logger.error('Error matching CIDR', {
        component: 'IntelligentIPProtectionSystem',
        ip,
        cidr,
        error: error.message,
      });
      return false;
    }
  }

  /**
   * Load IP rules from storage
   */
  private async loadIPRules(): Promise<void> {
    try {
      const rulesData = await this.redis.get(`${this.config.redis.keyPrefix}ip_rules`);
      if (rulesData) {
        const rules = JSON.parse(rulesData);
        for (const rule of rules) {
          this.ipRules.set(rule.id, {
            ...rule,
            expiresAt: rule.expiresAt ? new Date(rule.expiresAt) : undefined,
          });
        }
      }
    } catch (error) {
      this.logger.error('Error loading IP rules', {
        component: 'IntelligentIPProtectionSystem',
        error: error.message,
      });
    }
  }

  /**
   * Load geolocation rules from storage
   */
  private async loadGeolocationRules(): Promise<void> {
    try {
      const rulesData = await this.redis.get(`${this.config.redis.keyPrefix}geo_rules`);
      if (rulesData) {
        const rules = JSON.parse(rulesData);
        for (const rule of rules) {
          this.geoRules.set(rule.id, rule);
        }
      }
    } catch (error) {
      this.logger.error('Error loading geolocation rules', {
        component: 'IntelligentIPProtectionSystem',
        error: error.message,
      });
    }
  }

  /**
   * Record metrics for analytics and monitoring
   */
  private async recordMetrics(ip: string, action: string, reason: string): Promise<void> {
    if (!this.config.analytics.enabled) return;

    const timestamp = Date.now();
    const dailyKey = `metrics:daily:${new Date().toISOString().split('T')[0]}`;
    const hourlyKey = `metrics:hourly:${Math.floor(timestamp / 3600000)}`;

    await Promise.all([
      this.redis.hincrby(dailyKey, `${action}_${reason}`, 1),
      this.redis.hincrby(hourlyKey, `${action}_${reason}`, 1),
      this.redis.hincrby('metrics:total', `${action}_${reason}`, 1),
      this.redis.expire(dailyKey, 86400 * this.config.analytics.retentionDays),
      this.redis.expire(hourlyKey, 86400),
    ]);
  }

  /**
   * Update IP analytics for forensic analysis
   */
  private async updateIPAnalytics(ip: string, data: any): Promise<void> {
    const key = `analytics:ip:${ip}`;
    const geoData = geoip.lookup(ip);
    
    await this.redis.hset(key, {
      lastSeen: Date.now().toString(),
      country: geoData?.country || 'Unknown',
      asn: geoData?.asn || 0,
      totalRequests: await this.redis.hincrby(key, 'totalRequests', 1),
      action: data.action,
    });

    await this.redis.expire(key, 86400 * this.config.analytics.retentionDays);
  }

  /**
   * Start periodic metrics collection
   */
  private startMetricsCollection(): void {
    setInterval(async () => {
      try {
        const stats = {
          timestamp: Date.now(),
          active_rules: this.ipRules.size + this.geoRules.size,
          cache_size: this.reputationCache.size,
          temp_bans: await this.redis.scard('temp_ban:*'),
        };

        await this.redis.hset('metrics:system', stats);
      } catch (error) {
        this.logger.error('Error collecting metrics', {
          component: 'IntelligentIPProtectionSystem',
          error: error.message,
        });
      }
    }, 60000); // Every minute
  }

  /**
   * Start periodic cache cleanup
   */
  private startCacheCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      
      // Clean reputation cache
      for (const [key, value] of this.reputationCache.entries()) {
        if (value.expiry <= now) {
          this.reputationCache.delete(key);
        }
      }

      // Limit network cache size
      if (this.networkCache.size > this.config.rateLimit.cacheSize) {
        const keys = Array.from(this.networkCache.keys());
        const toDelete = keys.slice(0, keys.length - this.config.rateLimit.cacheSize);
        toDelete.forEach(key => this.networkCache.delete(key));
      }
    }, 300000); // Every 5 minutes
  }

  /**
   * Add new IP rule
   */
  async addIPRule(rule: Omit<IPRule, 'id'>): Promise<string> {
    const id = `ip_rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newRule: IPRule = { ...rule, id };
    
    this.ipRules.set(id, newRule);
    await this.saveIPRules();
    
    this.logger.info('IP rule added', {
      component: 'IntelligentIPProtectionSystem',
      ruleId: id,
      type: rule.type,
      cidr: rule.cidr,
    });

    return id;
  }

  /**
   * Add new geolocation rule
   */
  async addGeolocationRule(rule: Omit<GeolocationRule, 'id'>): Promise<string> {
    const id = `geo_rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newRule: GeolocationRule = { ...rule, id };
    
    this.geoRules.set(id, newRule);
    await this.saveGeolocationRules();
    
    this.logger.info('Geolocation rule added', {
      component: 'IntelligentIPProtectionSystem',
      ruleId: id,
      type: rule.type,
      countries: rule.countries,
    });

    return id;
  }

  /**
   * Get IP analytics for forensic analysis
   */
  async getIPAnalytics(ip: string): Promise<IPAnalytics | null> {
    try {
      const key = `analytics:ip:${ip}`;
      const data = await this.redis.hgetall(key);
      
      if (!data || Object.keys(data).length === 0) {
        return null;
      }

      return {
        ip,
        country: data.country,
        asn: parseInt(data.asn) || undefined,
        reputationScore: await this.getIPReputationScore(ip),
        totalRequests: parseInt(data.totalRequests) || 0,
        blockedRequests: parseInt(data.blockedRequests) || 0,
        lastSeen: new Date(parseInt(data.lastSeen)),
        riskFactors: JSON.parse(data.riskFactors || '[]'),
      };
    } catch (error) {
      this.logger.error('Error getting IP analytics', {
        component: 'IntelligentIPProtectionSystem',
        ip,
        error: error.message,
      });
      return null;
    }
  }

  /**
   * Save IP rules to persistent storage
   */
  private async saveIPRules(): Promise<void> {
    const rules = Array.from(this.ipRules.values());
    await this.redis.set(
      `${this.config.redis.keyPrefix}ip_rules`,
      JSON.stringify(rules)
    );
  }

  /**
   * Save geolocation rules to persistent storage
   */
  private async saveGeolocationRules(): Promise<void> {
    const rules = Array.from(this.geoRules.values());
    await this.redis.set(
      `${this.config.redis.keyPrefix}geo_rules`,
      JSON.stringify(rules)
    );
  }

  /**
   * Get system status and statistics
   */
  async getSystemStatus(): Promise<{
    status: string;
    rules: { ip: number; geo: number };
    metrics: any;
    performance: any;
  }> {
    try {
      const metrics = await this.redis.hgetall('metrics:total');
      const performance = await this.redis.hgetall('metrics:performance');
      const systemMetrics = await this.redis.hgetall('metrics:system');

      return {
        status: 'healthy',
        rules: {
          ip: this.ipRules.size,
          geo: this.geoRules.size,
        },
        metrics: {
          total: metrics,
          system: systemMetrics,
        },
        performance: performance,
      };
    } catch (error) {
      this.logger.error('Error getting system status', {
        component: 'IntelligentIPProtectionSystem',
        error: error.message,
      });
      
      return {
        status: 'error',
        rules: { ip: 0, geo: 0 },
        metrics: {},
        performance: {},
      };
    }
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    try {
      await this.redis.quit();
      this.logger.info('IP Protection System shutdown completed');
    } catch (error) {
      this.logger.error('Error during shutdown', {
        component: 'IntelligentIPProtectionSystem',
        error: error.message,
      });
    }
  }
}

// Export configuration schemas for external use
export { IPProtectionConfigSchema, IPRuleSchema, GeolocationRuleSchema };
export type { IPProtectionConfig, IPRule, GeolocationRule, ProtectionDecision, IPAnalytics };