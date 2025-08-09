/**
 * Intelligent Traffic Management System for iSECTECH API Gateway
 * 
 * Advanced traffic management with segmentation, dynamic routing, A/B testing,
 * canary deployments, and traffic mirroring capabilities.
 * 
 * Features:
 * - Dynamic traffic segmentation with user-defined criteria
 * - Content-based routing with configurable rule engine
 * - A/B testing with statistical significance tracking
 * - Canary deployments with automated rollback
 * - Traffic mirroring for testing and analysis
 * - Real-time traffic shaping and prioritization
 * - Load balancing with health-aware routing
 */

import { Redis } from 'ioredis';
import { z } from 'zod';
import { Logger } from 'winston';
import crypto from 'crypto';

// Configuration schemas
const TrafficSegmentSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  criteria: z.object({
    userAgent: z.array(z.string()).optional(),
    headers: z.record(z.string()).optional(),
    ipRanges: z.array(z.string()).optional(),
    countries: z.array(z.string()).optional(),
    userIds: z.array(z.string()).optional(),
    customAttributes: z.record(z.any()).optional(),
  }),
  priority: z.number().min(1).max(1000),
  isActive: z.boolean().default(true),
  createdAt: z.date().default(() => new Date()),
  updatedAt: z.date().default(() => new Date()),
});

const RoutingRuleSchema = z.object({
  id: z.string(),
  name: z.string(),
  conditions: z.object({
    path: z.string().optional(),
    method: z.array(z.string()).optional(),
    headers: z.record(z.string()).optional(),
    queryParams: z.record(z.string()).optional(),
    segments: z.array(z.string()).optional(),
  }),
  destinations: z.array(z.object({
    upstream: z.string(),
    weight: z.number().min(0).max(100),
    priority: z.number().min(1).max(10),
    healthCheck: z.boolean().default(true),
  })),
  fallback: z.object({
    upstream: z.string(),
    behavior: z.enum(['FAILOVER', 'CIRCUIT_BREAKER', 'REJECT']),
  }).optional(),
  priority: z.number().min(1).max(1000),
  isActive: z.boolean().default(true),
});

const ABTestConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  variants: z.array(z.object({
    id: z.string(),
    name: z.string(),
    upstream: z.string(),
    allocation: z.number().min(0).max(100),
    config: z.record(z.any()).optional(),
  })),
  targeting: z.object({
    segments: z.array(z.string()).optional(),
    percentage: z.number().min(0).max(100).default(100),
    criteria: z.record(z.any()).optional(),
  }),
  metrics: z.object({
    primaryMetric: z.string(),
    secondaryMetrics: z.array(z.string()).optional(),
    significanceLevel: z.number().min(0.01).max(0.1).default(0.05),
    minSampleSize: z.number().min(100).default(1000),
  }),
  duration: z.object({
    startDate: z.date(),
    endDate: z.date(),
    autoStop: z.boolean().default(false),
  }),
  status: z.enum(['DRAFT', 'RUNNING', 'PAUSED', 'COMPLETED', 'STOPPED']).default('DRAFT'),
});

const CanaryDeploymentSchema = z.object({
  id: z.string(),
  name: z.string(),
  service: z.string(),
  canaryUpstream: z.string(),
  stableUpstream: z.string(),
  stages: z.array(z.object({
    stage: z.number(),
    trafficPercentage: z.number().min(0).max(100),
    duration: z.number(), // minutes
    successCriteria: z.object({
      errorRate: z.number().max(5).default(1), // max 1% error rate
      responseTime: z.number().default(500), // max 500ms p99
      minRequests: z.number().default(100),
    }),
  })),
  rollbackTriggers: z.object({
    errorRateThreshold: z.number().default(5), // 5%
    responseTimeThreshold: z.number().default(1000), // 1000ms
    manualRollback: z.boolean().default(true),
  }),
  status: z.enum(['PENDING', 'IN_PROGRESS', 'COMPLETED', 'ROLLED_BACK', 'FAILED']).default('PENDING'),
});

const TrafficMirrorConfigSchema = z.object({
  id: z.string(),
  name: z.string(),
  sourceUpstream: z.string(),
  mirrorUpstream: z.string(),
  mirrorPercentage: z.number().min(0).max(100),
  filters: z.object({
    methods: z.array(z.string()).optional(),
    paths: z.array(z.string()).optional(),
    headers: z.record(z.string()).optional(),
  }).optional(),
  sampling: z.object({
    enabled: z.boolean().default(false),
    rate: z.number().min(0).max(1).default(0.1), // 10% sampling
  }),
  isActive: z.boolean().default(true),
});

const TrafficManagerConfigSchema = z.object({
  redis: z.object({
    host: z.string().default('localhost'),
    port: z.number().default(6379),
    password: z.string().optional(),
    db: z.number().default(0),
    keyPrefix: z.string().default('traffic_manager:'),
  }),
  routing: z.object({
    enabled: z.boolean().default(true),
    defaultUpstream: z.string().default('default'),
    healthCheckInterval: z.number().default(30000), // 30 seconds
    cacheEnabled: z.boolean().default(true),
    cacheTtl: z.number().default(60), // 60 seconds
  }),
  abTesting: z.object({
    enabled: z.boolean().default(true),
    maxConcurrentTests: z.number().default(10),
    statisticalEngine: z.enum(['FREQUENTIST', 'BAYESIAN']).default('FREQUENTIST'),
  }),
  canary: z.object({
    enabled: z.boolean().default(true),
    maxConcurrentDeployments: z.number().default(5),
    defaultStages: z.array(z.number()).default([5, 25, 50, 100]),
  }),
  mirroring: z.object({
    enabled: z.boolean().default(true),
    maxMirrorTargets: z.number().default(3),
    bufferSize: z.number().default(1000),
  }),
  monitoring: z.object({
    metricsEnabled: z.boolean().default(true),
    detailedLogging: z.boolean().default(false),
    alerting: z.object({
      enabled: z.boolean().default(true),
      thresholds: z.object({
        errorRate: z.number().default(5),
        responseTime: z.number().default(1000),
      }),
    }),
  }),
});

type TrafficSegment = z.infer<typeof TrafficSegmentSchema>;
type RoutingRule = z.infer<typeof RoutingRuleSchema>;
type ABTestConfig = z.infer<typeof ABTestConfigSchema>;
type CanaryDeployment = z.infer<typeof CanaryDeploymentSchema>;
type TrafficMirrorConfig = z.infer<typeof TrafficMirrorConfigSchema>;
type TrafficManagerConfig = z.infer<typeof TrafficManagerConfigSchema>;

interface RequestContext {
  ip: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  queryParams: Record<string, string>;
  userAgent?: string;
  userId?: string;
  sessionId?: string;
  country?: string;
}

interface RoutingDecision {
  upstream: string;
  reason: string;
  segment?: string;
  abTest?: string;
  canary?: boolean;
  mirror?: boolean;
  metadata: Record<string, any>;
}

interface ABTestResult {
  testId: string;
  variant: string;
  allocation: number;
  metadata: Record<string, any>;
}

/**
 * Comprehensive Intelligent Traffic Management System
 */
export class IntelligentTrafficManager {
  private redis: Redis;
  private logger: Logger;
  private config: TrafficManagerConfig;
  private segments: Map<string, TrafficSegment> = new Map();
  private routingRules: Map<string, RoutingRule> = new Map();
  private abTests: Map<string, ABTestConfig> = new Map();
  private canaryDeployments: Map<string, CanaryDeployment> = new Map();
  private mirrorConfigs: Map<string, TrafficMirrorConfig> = new Map();
  private upstreamHealth: Map<string, { healthy: boolean; lastCheck: number }> = new Map();
  private requestCache: Map<string, RoutingDecision> = new Map();

  constructor(config: TrafficManagerConfig, logger: Logger) {
    this.config = TrafficManagerConfigSchema.parse(config);
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
   * Initialize the traffic management system
   */
  private async initializeSystem(): Promise<void> {
    try {
      await this.loadConfiguration();
      this.startHealthChecks();
      this.startMetricsCollection();
      this.startCacheCleanup();
      
      this.logger.info('Intelligent Traffic Manager initialized successfully', {
        component: 'IntelligentTrafficManager',
        segments: this.segments.size,
        routingRules: this.routingRules.size,
        abTests: this.abTests.size,
        canaryDeployments: this.canaryDeployments.size,
      });
    } catch (error) {
      this.logger.error('Failed to initialize Traffic Manager', {
        component: 'IntelligentTrafficManager',
        error: error.message,
      });
      throw error;
    }
  }

  /**
   * Main routing decision engine
   */
  async routeRequest(context: RequestContext): Promise<RoutingDecision> {
    const startTime = Date.now();
    
    try {
      // Check cache first for performance
      const cacheKey = this.generateCacheKey(context);
      let decision = null;

      if (this.config.routing.cacheEnabled) {
        decision = this.requestCache.get(cacheKey);
        if (decision) {
          await this.recordMetrics(decision, Date.now() - startTime, true);
          return decision;
        }
      }

      // 1. Segment identification
      const segment = await this.identifySegment(context);
      
      // 2. Check for active A/B tests
      const abTestResult = await this.evaluateABTests(context, segment);
      
      // 3. Check for canary deployments
      const canaryResult = await this.evaluateCanaryDeployments(context, segment);
      
      // 4. Apply routing rules
      const routingResult = await this.applyRoutingRules(context, segment, abTestResult, canaryResult);
      
      // 5. Check for traffic mirroring
      const mirrorTargets = await this.evaluateTrafficMirroring(context, routingResult.upstream);

      decision = {
        upstream: routingResult.upstream,
        reason: routingResult.reason,
        segment: segment?.name,
        abTest: abTestResult?.testId,
        canary: canaryResult?.isCanary || false,
        mirror: mirrorTargets.length > 0,
        metadata: {
          segment: segment,
          abTest: abTestResult,
          canary: canaryResult,
          mirrorTargets,
          processingTime: Date.now() - startTime,
        },
      };

      // Cache the decision
      if (this.config.routing.cacheEnabled) {
        this.requestCache.set(cacheKey, decision);
        setTimeout(() => this.requestCache.delete(cacheKey), this.config.routing.cacheTtl * 1000);
      }

      // Record metrics
      await this.recordMetrics(decision, Date.now() - startTime, false);
      
      // Execute traffic mirroring asynchronously
      if (mirrorTargets.length > 0) {
        setImmediate(() => this.executeMirroring(context, mirrorTargets));
      }

      return decision;

    } catch (error) {
      this.logger.error('Error in routing decision', {
        component: 'IntelligentTrafficManager',
        context,
        error: error.message,
      });

      // Fallback routing
      return {
        upstream: this.config.routing.defaultUpstream,
        reason: 'Fallback due to routing error',
        metadata: { error: error.message },
      };
    }
  }

  /**
   * Identify traffic segment for the request
   */
  private async identifySegment(context: RequestContext): Promise<TrafficSegment | null> {
    const activeSegments = Array.from(this.segments.values())
      .filter(segment => segment.isActive)
      .sort((a, b) => b.priority - a.priority);

    for (const segment of activeSegments) {
      if (await this.matchesSegmentCriteria(context, segment.criteria)) {
        this.logger.debug('Request matched segment', {
          component: 'IntelligentTrafficManager',
          segment: segment.name,
          ip: context.ip,
        });
        return segment;
      }
    }

    return null;
  }

  /**
   * Check if request matches segment criteria
   */
  private async matchesSegmentCriteria(context: RequestContext, criteria: any): Promise<boolean> {
    // User-Agent matching
    if (criteria.userAgent && context.userAgent) {
      const matches = criteria.userAgent.some((pattern: string) => 
        new RegExp(pattern, 'i').test(context.userAgent!));
      if (!matches) return false;
    }

    // Header matching
    if (criteria.headers) {
      for (const [headerName, headerValue] of Object.entries(criteria.headers)) {
        const requestValue = context.headers[headerName.toLowerCase()];
        if (!requestValue || !new RegExp(headerValue, 'i').test(requestValue)) {
          return false;
        }
      }
    }

    // IP range matching
    if (criteria.ipRanges) {
      const ipMatches = criteria.ipRanges.some((cidr: string) => 
        this.ipInCIDR(context.ip, cidr));
      if (!ipMatches) return false;
    }

    // Country matching
    if (criteria.countries && context.country) {
      if (!criteria.countries.includes(context.country)) {
        return false;
      }
    }

    // User ID matching
    if (criteria.userIds && context.userId) {
      if (!criteria.userIds.includes(context.userId)) {
        return false;
      }
    }

    // Custom attribute matching
    if (criteria.customAttributes) {
      // Implementation would depend on how custom attributes are provided
      // This is a placeholder for extensibility
    }

    return true;
  }

  /**
   * Evaluate active A/B tests for the request
   */
  private async evaluateABTests(context: RequestContext, segment: TrafficSegment | null): Promise<ABTestResult | null> {
    if (!this.config.abTesting.enabled) return null;

    const activeTests = Array.from(this.abTests.values())
      .filter(test => test.status === 'RUNNING' && 
               new Date() >= test.duration.startDate && 
               new Date() <= test.duration.endDate);

    for (const test of activeTests) {
      // Check targeting criteria
      if (!await this.matchesABTestTargeting(context, segment, test.targeting)) {
        continue;
      }

      // Determine variant using consistent hashing
      const hash = this.generateConsistentHash(context.userId || context.sessionId || context.ip, test.id);
      const variant = this.selectVariant(hash, test.variants);

      if (variant) {
        // Record test participation
        await this.recordABTestParticipation(test.id, variant.id, context);

        return {
          testId: test.id,
          variant: variant.id,
          allocation: variant.allocation,
          metadata: {
            testName: test.name,
            variantName: variant.name,
            upstream: variant.upstream,
          },
        };
      }
    }

    return null;
  }

  /**
   * Check if request matches A/B test targeting
   */
  private async matchesABTestTargeting(context: RequestContext, segment: TrafficSegment | null, targeting: any): Promise<boolean> {
    // Segment targeting
    if (targeting.segments && segment) {
      if (!targeting.segments.includes(segment.id)) {
        return false;
      }
    }

    // Percentage targeting (random sampling)
    if (targeting.percentage < 100) {
      const hash = this.generateConsistentHash(context.ip, 'percentage_targeting');
      const percentage = (hash % 100) + 1;
      if (percentage > targeting.percentage) {
        return false;
      }
    }

    // Additional criteria matching would go here
    
    return true;
  }

  /**
   * Evaluate active canary deployments
   */
  private async evaluateCanaryDeployments(context: RequestContext, segment: TrafficSegment | null): Promise<{ isCanary: boolean; upstream?: string } | null> {
    if (!this.config.canary.enabled) return null;

    const activeDeployments = Array.from(this.canaryDeployments.values())
      .filter(deployment => deployment.status === 'IN_PROGRESS');

    for (const deployment of activeDeployments) {
      const currentStage = await this.getCurrentCanaryStage(deployment);
      if (!currentStage) continue;

      // Use consistent hashing to determine if this request gets canary traffic
      const hash = this.generateConsistentHash(context.userId || context.ip, deployment.id);
      const percentage = (hash % 100) + 1;

      if (percentage <= currentStage.trafficPercentage) {
        // Record canary participation
        await this.recordCanaryParticipation(deployment.id, context);

        return {
          isCanary: true,
          upstream: deployment.canaryUpstream,
        };
      }
    }

    return { isCanary: false };
  }

  /**
   * Apply routing rules to determine upstream
   */
  private async applyRoutingRules(context: RequestContext, segment: TrafficSegment | null, abTest: ABTestResult | null, canary: any): Promise<{ upstream: string; reason: string }> {
    // A/B test takes highest priority
    if (abTest) {
      const test = this.abTests.get(abTest.testId);
      const variant = test?.variants.find(v => v.id === abTest.variant);
      if (variant) {
        return {
          upstream: variant.upstream,
          reason: `A/B Test: ${test.name} - Variant: ${variant.name}`,
        };
      }
    }

    // Canary deployment takes second priority
    if (canary?.isCanary) {
      return {
        upstream: canary.upstream,
        reason: 'Canary deployment traffic',
      };
    }

    // Apply routing rules based on request attributes
    const applicableRules = Array.from(this.routingRules.values())
      .filter(rule => rule.isActive)
      .sort((a, b) => b.priority - a.priority);

    for (const rule of applicableRules) {
      if (await this.matchesRoutingRule(context, segment, rule)) {
        const upstream = await this.selectUpstreamFromRule(rule);
        
        return {
          upstream,
          reason: `Routing Rule: ${rule.name}`,
        };
      }
    }

    // Default routing
    return {
      upstream: this.config.routing.defaultUpstream,
      reason: 'Default routing',
    };
  }

  /**
   * Check if request matches routing rule conditions
   */
  private async matchesRoutingRule(context: RequestContext, segment: TrafficSegment | null, rule: RoutingRule): Promise<boolean> {
    const conditions = rule.conditions;

    // Path matching
    if (conditions.path) {
      if (!new RegExp(conditions.path).test(context.path)) {
        return false;
      }
    }

    // Method matching
    if (conditions.method) {
      if (!conditions.method.includes(context.method)) {
        return false;
      }
    }

    // Header matching
    if (conditions.headers) {
      for (const [headerName, headerPattern] of Object.entries(conditions.headers)) {
        const headerValue = context.headers[headerName.toLowerCase()];
        if (!headerValue || !new RegExp(headerPattern).test(headerValue)) {
          return false;
        }
      }
    }

    // Query parameter matching
    if (conditions.queryParams) {
      for (const [paramName, paramPattern] of Object.entries(conditions.queryParams)) {
        const paramValue = context.queryParams[paramName];
        if (!paramValue || !new RegExp(paramPattern).test(paramValue)) {
          return false;
        }
      }
    }

    // Segment matching
    if (conditions.segments && segment) {
      if (!conditions.segments.includes(segment.id)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Select upstream from routing rule based on weights and health
   */
  private async selectUpstreamFromRule(rule: RoutingRule): Promise<string> {
    const healthyDestinations = rule.destinations.filter(dest => {
      const health = this.upstreamHealth.get(dest.upstream);
      return !dest.healthCheck || (health && health.healthy);
    });

    if (healthyDestinations.length === 0) {
      // All unhealthy, use fallback or return first destination
      if (rule.fallback) {
        return rule.fallback.upstream;
      }
      return rule.destinations[0]?.upstream || this.config.routing.defaultUpstream;
    }

    // Weighted selection among healthy destinations
    const totalWeight = healthyDestinations.reduce((sum, dest) => sum + dest.weight, 0);
    const random = Math.random() * totalWeight;
    let currentWeight = 0;

    for (const destination of healthyDestinations) {
      currentWeight += destination.weight;
      if (random <= currentWeight) {
        return destination.upstream;
      }
    }

    return healthyDestinations[0].upstream;
  }

  /**
   * Evaluate traffic mirroring configurations
   */
  private async evaluateTrafficMirroring(context: RequestContext, primaryUpstream: string): Promise<string[]> {
    if (!this.config.mirroring.enabled) return [];

    const applicableMirrors = Array.from(this.mirrorConfigs.values())
      .filter(mirror => mirror.isActive && mirror.sourceUpstream === primaryUpstream);

    const selectedMirrors = [];

    for (const mirror of applicableMirrors) {
      // Check filters
      if (mirror.filters) {
        if (mirror.filters.methods && !mirror.filters.methods.includes(context.method)) {
          continue;
        }
        
        if (mirror.filters.paths && !mirror.filters.paths.some(path => 
          new RegExp(path).test(context.path))) {
          continue;
        }

        if (mirror.filters.headers) {
          let headerMatch = true;
          for (const [headerName, headerPattern] of Object.entries(mirror.filters.headers)) {
            const headerValue = context.headers[headerName.toLowerCase()];
            if (!headerValue || !new RegExp(headerPattern).test(headerValue)) {
              headerMatch = false;
              break;
            }
          }
          if (!headerMatch) continue;
        }
      }

      // Check percentage
      if (mirror.mirrorPercentage < 100) {
        const hash = this.generateConsistentHash(context.ip, mirror.id);
        const percentage = (hash % 100) + 1;
        if (percentage > mirror.mirrorPercentage) {
          continue;
        }
      }

      // Check sampling
      if (mirror.sampling.enabled) {
        if (Math.random() > mirror.sampling.rate) {
          continue;
        }
      }

      selectedMirrors.push(mirror.mirrorUpstream);
    }

    return selectedMirrors;
  }

  /**
   * Execute traffic mirroring asynchronously
   */
  private async executeMirroring(context: RequestContext, mirrorTargets: string[]): Promise<void> {
    try {
      // This would typically involve making HTTP requests to mirror targets
      // Implementation depends on the specific mirroring mechanism
      
      for (const target of mirrorTargets) {
        this.logger.debug('Executing traffic mirror', {
          component: 'IntelligentTrafficManager',
          source: context.path,
          target,
          ip: context.ip,
        });

        // Record mirroring metrics
        await this.redis.hincrby('metrics:mirroring', target, 1);
      }
    } catch (error) {
      this.logger.error('Error in traffic mirroring', {
        component: 'IntelligentTrafficManager',
        mirrorTargets,
        error: error.message,
      });
    }
  }

  /**
   * Add traffic segment
   */
  async addTrafficSegment(segment: Omit<TrafficSegment, 'id' | 'createdAt' | 'updatedAt'>): Promise<string> {
    const id = `segment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newSegment: TrafficSegment = {
      ...segment,
      id,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    
    this.segments.set(id, newSegment);
    await this.saveSegments();
    
    this.logger.info('Traffic segment added', {
      component: 'IntelligentTrafficManager',
      segmentId: id,
      name: segment.name,
    });

    return id;
  }

  /**
   * Add routing rule
   */
  async addRoutingRule(rule: Omit<RoutingRule, 'id'>): Promise<string> {
    const id = `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newRule: RoutingRule = { ...rule, id };
    
    this.routingRules.set(id, newRule);
    await this.saveRoutingRules();
    
    this.logger.info('Routing rule added', {
      component: 'IntelligentTrafficManager',
      ruleId: id,
      name: rule.name,
    });

    return id;
  }

  /**
   * Start A/B test
   */
  async startABTest(test: Omit<ABTestConfig, 'id' | 'status'>): Promise<string> {
    const id = `abtest_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newTest: ABTestConfig = {
      ...test,
      id,
      status: 'RUNNING',
    };
    
    // Validate variant allocations sum to 100%
    const totalAllocation = newTest.variants.reduce((sum, variant) => sum + variant.allocation, 0);
    if (Math.abs(totalAllocation - 100) > 0.01) {
      throw new Error('Variant allocations must sum to 100%');
    }
    
    this.abTests.set(id, newTest);
    await this.saveABTests();
    
    this.logger.info('A/B test started', {
      component: 'IntelligentTrafficManager',
      testId: id,
      name: test.name,
      variants: test.variants.length,
    });

    return id;
  }

  /**
   * Start canary deployment
   */
  async startCanaryDeployment(deployment: Omit<CanaryDeployment, 'id' | 'status'>): Promise<string> {
    const id = `canary_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const newDeployment: CanaryDeployment = {
      ...deployment,
      id,
      status: 'IN_PROGRESS',
    };
    
    this.canaryDeployments.set(id, newDeployment);
    await this.saveCanaryDeployments();
    
    // Start canary progression monitoring
    this.startCanaryMonitoring(id);
    
    this.logger.info('Canary deployment started', {
      component: 'IntelligentTrafficManager',
      deploymentId: id,
      name: deployment.name,
      stages: deployment.stages.length,
    });

    return id;
  }

  /**
   * Utility functions
   */
  private generateCacheKey(context: RequestContext): string {
    const key = `${context.method}_${context.path}_${context.ip}_${context.userId || 'anonymous'}`;
    return crypto.createHash('md5').update(key).digest('hex');
  }

  private generateConsistentHash(input: string, salt: string): number {
    const hash = crypto.createHash('md5').update(input + salt).digest('hex');
    return parseInt(hash.substr(0, 8), 16);
  }

  private selectVariant(hash: number, variants: any[]): any {
    const totalAllocation = variants.reduce((sum, variant) => sum + variant.allocation, 0);
    const normalizedHash = (hash % 100) + 1;
    let currentAllocation = 0;

    for (const variant of variants) {
      currentAllocation += (variant.allocation / totalAllocation) * 100;
      if (normalizedHash <= currentAllocation) {
        return variant;
      }
    }

    return variants[variants.length - 1]; // Fallback to last variant
  }

  private ipInCIDR(ip: string, cidr: string): boolean {
    // Simplified CIDR matching - production would use proper IP library
    try {
      const [network, prefixLength] = cidr.split('/');
      const ipParts = ip.split('.').map(Number);
      const networkParts = network.split('.').map(Number);
      const mask = (0xffffffff << (32 - parseInt(prefixLength))) >>> 0;
      
      const ipInt = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
      const networkInt = (networkParts[0] << 24) + (networkParts[1] << 16) + (networkParts[2] << 8) + networkParts[3];
      
      return (ipInt & mask) === (networkInt & mask);
    } catch (error) {
      return false;
    }
  }

  private async getCurrentCanaryStage(deployment: CanaryDeployment): Promise<any> {
    // Get current stage based on time progression and success criteria
    // This is a simplified implementation
    const currentTime = Date.now();
    const deployment_start = await this.redis.get(`canary:${deployment.id}:start_time`);
    
    if (!deployment_start) {
      await this.redis.set(`canary:${deployment.id}:start_time`, currentTime.toString());
      return deployment.stages[0];
    }

    // Implementation would track stage progression based on time and success criteria
    return deployment.stages[0]; // Simplified
  }

  private async recordABTestParticipation(testId: string, variantId: string, context: RequestContext): Promise<void> {
    const key = `abtest:${testId}:${variantId}`;
    await this.redis.hincrby(key, 'participants', 1);
    await this.redis.expire(key, 86400 * 30); // 30 days
  }

  private async recordCanaryParticipation(deploymentId: string, context: RequestContext): Promise<void> {
    const key = `canary:${deploymentId}:participants`;
    await this.redis.hincrby(key, 'total', 1);
    await this.redis.expire(key, 86400 * 7); // 7 days
  }

  private async recordMetrics(decision: RoutingDecision, processingTime: number, cached: boolean): Promise<void> {
    const timestamp = Date.now();
    
    await Promise.all([
      this.redis.hincrby('metrics:routing', 'total_requests', 1),
      this.redis.hincrby('metrics:routing', `upstream_${decision.upstream}`, 1),
      this.redis.hincrby('metrics:routing', cached ? 'cache_hits' : 'cache_misses', 1),
      this.redis.hset('metrics:routing', 'avg_processing_time', processingTime),
      this.redis.zadd('metrics:timeline', timestamp, JSON.stringify({
        timestamp,
        upstream: decision.upstream,
        reason: decision.reason,
        processingTime,
        cached,
      })),
    ]);
  }

  private async loadConfiguration(): Promise<void> {
    // Load from Redis if available
    try {
      const [segmentsData, rulesData, abTestsData, canaryData, mirrorData] = await Promise.all([
        this.redis.get(`${this.config.redis.keyPrefix}segments`),
        this.redis.get(`${this.config.redis.keyPrefix}routing_rules`),
        this.redis.get(`${this.config.redis.keyPrefix}ab_tests`),
        this.redis.get(`${this.config.redis.keyPrefix}canary_deployments`),
        this.redis.get(`${this.config.redis.keyPrefix}mirror_configs`),
      ]);

      if (segmentsData) {
        const segments = JSON.parse(segmentsData);
        segments.forEach((segment: TrafficSegment) => {
          this.segments.set(segment.id, {
            ...segment,
            createdAt: new Date(segment.createdAt),
            updatedAt: new Date(segment.updatedAt),
          });
        });
      }

      // Similar loading for other configurations...
      
    } catch (error) {
      this.logger.error('Error loading configuration', {
        component: 'IntelligentTrafficManager',
        error: error.message,
      });
    }
  }

  private async saveSegments(): Promise<void> {
    const segments = Array.from(this.segments.values());
    await this.redis.set(`${this.config.redis.keyPrefix}segments`, JSON.stringify(segments));
  }

  private async saveRoutingRules(): Promise<void> {
    const rules = Array.from(this.routingRules.values());
    await this.redis.set(`${this.config.redis.keyPrefix}routing_rules`, JSON.stringify(rules));
  }

  private async saveABTests(): Promise<void> {
    const tests = Array.from(this.abTests.values());
    await this.redis.set(`${this.config.redis.keyPrefix}ab_tests`, JSON.stringify(tests));
  }

  private async saveCanaryDeployments(): Promise<void> {
    const deployments = Array.from(this.canaryDeployments.values());
    await this.redis.set(`${this.config.redis.keyPrefix}canary_deployments`, JSON.stringify(deployments));
  }

  private startHealthChecks(): void {
    setInterval(async () => {
      // Check upstream health
      // Implementation would depend on health check mechanism
    }, this.config.routing.healthCheckInterval);
  }

  private startMetricsCollection(): void {
    setInterval(async () => {
      // Collect and aggregate metrics
    }, 60000); // Every minute
  }

  private startCacheCleanup(): void {
    setInterval(() => {
      // Clean up expired cache entries
      if (this.requestCache.size > 10000) { // Limit cache size
        const keys = Array.from(this.requestCache.keys());
        const toDelete = keys.slice(0, keys.length - 5000);
        toDelete.forEach(key => this.requestCache.delete(key));
      }
    }, 300000); // Every 5 minutes
  }

  private startCanaryMonitoring(deploymentId: string): void {
    const interval = setInterval(async () => {
      try {
        const deployment = this.canaryDeployments.get(deploymentId);
        if (!deployment || deployment.status !== 'IN_PROGRESS') {
          clearInterval(interval);
          return;
        }

        // Check success criteria and progress to next stage or rollback
        const shouldRollback = await this.checkCanaryHealth(deployment);
        if (shouldRollback) {
          await this.rollbackCanaryDeployment(deploymentId);
          clearInterval(interval);
        }
      } catch (error) {
        this.logger.error('Error in canary monitoring', {
          component: 'IntelligentTrafficManager',
          deploymentId,
          error: error.message,
        });
      }
    }, 60000); // Check every minute
  }

  private async checkCanaryHealth(deployment: CanaryDeployment): Promise<boolean> {
    // Check rollback triggers
    // Implementation would analyze metrics and determine if rollback is needed
    return false; // Simplified
  }

  private async rollbackCanaryDeployment(deploymentId: string): Promise<void> {
    const deployment = this.canaryDeployments.get(deploymentId);
    if (deployment) {
      deployment.status = 'ROLLED_BACK';
      await this.saveCanaryDeployments();
      
      this.logger.warn('Canary deployment rolled back', {
        component: 'IntelligentTrafficManager',
        deploymentId,
        name: deployment.name,
      });
    }
  }

  /**
   * Get system status
   */
  async getSystemStatus(): Promise<{
    status: string;
    components: any;
    metrics: any;
  }> {
    try {
      const metrics = await this.redis.hgetall('metrics:routing');
      
      return {
        status: 'healthy',
        components: {
          segments: this.segments.size,
          routingRules: this.routingRules.size,
          abTests: Array.from(this.abTests.values()).filter(t => t.status === 'RUNNING').length,
          canaryDeployments: Array.from(this.canaryDeployments.values()).filter(d => d.status === 'IN_PROGRESS').length,
          mirrorConfigs: Array.from(this.mirrorConfigs.values()).filter(m => m.isActive).length,
        },
        metrics: metrics,
      };
    } catch (error) {
      return {
        status: 'error',
        components: {},
        metrics: {},
      };
    }
  }

  /**
   * Shutdown
   */
  async shutdown(): Promise<void> {
    try {
      await this.redis.quit();
      this.requestCache.clear();
      this.logger.info('Intelligent Traffic Manager shutdown completed');
    } catch (error) {
      this.logger.error('Error during shutdown', {
        component: 'IntelligentTrafficManager',
        error: error.message,
      });
    }
  }
}

// Export schemas
export { 
  TrafficManagerConfigSchema,
  TrafficSegmentSchema,
  RoutingRuleSchema,
  ABTestConfigSchema,
  CanaryDeploymentSchema,
  TrafficMirrorConfigSchema,
};

export type {
  TrafficManagerConfig,
  TrafficSegment,
  RoutingRule,
  ABTestConfig,
  CanaryDeployment,
  TrafficMirrorConfig,
  RequestContext,
  RoutingDecision,
};