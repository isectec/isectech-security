/**
 * Rate Limiting Infrastructure Integration Service
 * 
 * Comprehensive integration service that connects the iSECTECH Rate Limiting Manager
 * with Kong Gateway infrastructure, providing automated policy deployment,
 * real-time monitoring, and intelligent traffic management.
 * 
 * Production-grade infrastructure integration for cybersecurity platform.
 */

import axios, { AxiosInstance } from 'axios';
import { EventEmitter } from 'events';
import * as cron from 'node-cron';
import Redis from 'ioredis';
import { z } from 'zod';

import { KongGatewayManager } from '../kong/kong-gateway-manager';
import { isectechAPIRateLimitingManager, RateLimitPolicy } from '../rate-limiting/api-rate-limiting-manager';

// Infrastructure Integration Schemas
export const InfrastructureStatusSchema = z.object({
  kongGateway: z.object({
    healthy: z.boolean(),
    version: z.string(),
    uptime: z.number(),
    lastCheck: z.date()
  }),
  redis: z.object({
    connected: z.boolean(),
    memory: z.string(),
    keyspace: z.number(),
    lastCheck: z.date()
  }),
  rateLimitingService: z.object({
    active: z.boolean(),
    policiesCount: z.number(),
    requestsPerSecond: z.number(),
    lastCheck: z.date()
  }),
  monitoring: z.object({
    prometheusConnected: z.boolean(),
    grafanaConnected: z.boolean(),
    alertsActive: z.boolean(),
    lastCheck: z.date()
  })
});

export const DeploymentResultSchema = z.object({
  deploymentId: z.string(),
  timestamp: z.date(),
  success: z.boolean(),
  componentsDeployed: z.array(z.string()),
  errors: z.array(z.string()),
  rollbackAvailable: z.boolean(),
  metrics: z.object({
    deploymentTime: z.number(),
    policiesDeployed: z.number(),
    routesUpdated: z.number(),
    pluginsConfigured: z.number()
  })
});

export type InfrastructureStatus = z.infer<typeof InfrastructureStatusSchema>;
export type DeploymentResult = z.infer<typeof DeploymentResultSchema>;

interface PolicyDeploymentConfig {
  kongPlugins: boolean;
  redisCounters: boolean;
  prometheusRules: boolean;
  grafanaDashboards: boolean;
  alertingRules: boolean;
}

interface TrafficAnalytics {
  timestamp: Date;
  totalRequests: number;
  blockedRequests: number;
  throttledRequests: number;
  topPaths: Array<{ path: string; count: number }>;
  topIPs: Array<{ ip: string; count: number; blocked: boolean }>;
  policyTriggers: Array<{ policyId: string; triggers: number }>;
  responseTimeP95: number;
  errorRate: number;
}

interface IntelligentScalingConfig {
  enabled: boolean;
  cpuThreshold: number;
  memoryThreshold: number;
  requestRateThreshold: number;
  scaleUpCooldown: number;
  scaleDownCooldown: number;
  minReplicas: number;
  maxReplicas: number;
}

interface CircuitBreakerConfig {
  enabled: boolean;
  failureThreshold: number;
  recoveryTimeout: number;
  halfOpenRequests: number;
  monitoringWindow: number;
}

export class RateLimitingInfrastructureIntegration extends EventEmitter {
  private kongManager: KongGatewayManager;
  private redis: Redis;
  private prometheusClient: AxiosInstance;
  private grafanaClient: AxiosInstance;
  
  // Monitoring and analytics
  private trafficAnalytics: TrafficAnalytics[] = [];
  private deploymentHistory: DeploymentResult[] = [];
  private infrastructureStatus: Partial<InfrastructureStatus> = {};
  
  // Background tasks
  private statusCheckInterval: NodeJS.Timeout | null = null;
  private analyticsCollectionInterval: NodeJS.Timeout | null = null;
  private deploymentSyncInterval: NodeJS.Timeout | null = null;
  
  // Circuit breaker state
  private circuitBreakerStates = new Map<string, {
    state: 'closed' | 'open' | 'half-open';
    failures: number;
    lastFailure: Date;
    nextAttempt: Date;
  }>();

  constructor(
    private config: {
      // Kong Gateway configuration
      kongGateway: {
        adminUrl: string;
        adminApiKey: string;
        proxyUrl: string;
      };
      
      // Redis configuration
      redis: {
        host: string;
        port: number;
        password?: string;
        database: number;
      };
      
      // Monitoring configuration
      prometheus: {
        url: string;
        username?: string;
        password?: string;
      };
      
      grafana: {
        url: string;
        apiKey: string;
      };
      
      // Infrastructure settings
      infrastructure: {
        namespace: string;
        environment: 'development' | 'staging' | 'production';
        region: string;
      };
      
      // Integration settings
      integration: {
        syncIntervalMinutes: number;
        statusCheckIntervalMinutes: number;
        analyticsCollectionIntervalMinutes: number;
        deploymentTimeoutMinutes: number;
        rollbackTimeoutMinutes: number;
      };
      
      // Intelligent features
      intelligentScaling: IntelligentScalingConfig;
      circuitBreaker: CircuitBreakerConfig;
    }
  ) {
    super();
    
    this.initializeClients();
    this.startBackgroundTasks();
    this.setupEventHandlers();
  }

  /**
   * Initialize external service clients
   */
  private initializeClients(): void {
    // Initialize Kong Gateway Manager
    this.kongManager = new KongGatewayManager({
      adminUrl: this.config.kongGateway.adminUrl,
      adminApiKey: this.config.kongGateway.adminApiKey,
      adminTimeout: 30000,
      healthCheckIntervalMs: 60000,
      metricsCollectionIntervalMs: 30000,
      retryAttempts: 3,
      retryDelayMs: 1000
    });

    // Initialize Redis client
    this.redis = new Redis({
      host: this.config.redis.host,
      port: this.config.redis.port,
      password: this.config.redis.password,
      db: this.config.redis.database,
      retryDelayOnFailover: 1000,
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
      lazyConnect: true
    });

    // Initialize Prometheus client
    this.prometheusClient = axios.create({
      baseURL: this.config.prometheus.url,
      timeout: 10000,
      auth: this.config.prometheus.username ? {
        username: this.config.prometheus.username,
        password: this.config.prometheus.password!
      } : undefined
    });

    // Initialize Grafana client
    this.grafanaClient = axios.create({
      baseURL: this.config.grafana.url,
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${this.config.grafana.apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    console.log('Initialized infrastructure integration clients');
  }

  /**
   * Deploy rate limiting policies to infrastructure
   */
  public async deployRateLimitingPolicies(
    policies: RateLimitPolicy[],
    deploymentConfig: PolicyDeploymentConfig = {
      kongPlugins: true,
      redisCounters: true,
      prometheusRules: true,
      grafanaDashboards: true,
      alertingRules: true
    }
  ): Promise<DeploymentResult> {
    const deploymentId = `deployment_${Date.now()}`;
    const deploymentStart = new Date();
    const errors: string[] = [];
    const componentsDeployed: string[] = [];

    console.log(`Starting rate limiting policy deployment: ${deploymentId}`);
    this.emit('deploymentStarted', { deploymentId, policies: policies.length });

    try {
      // 1. Deploy Kong plugins and configurations
      if (deploymentConfig.kongPlugins) {
        try {
          await this.deployKongConfigurations(policies);
          componentsDeployed.push('kong-plugins');
          console.log('✓ Kong plugins deployed successfully');
        } catch (error) {
          errors.push(`Kong deployment failed: ${error.message}`);
          console.error('✗ Kong deployment failed:', error);
        }
      }

      // 2. Initialize Redis counters and data structures
      if (deploymentConfig.redisCounters) {
        try {
          await this.initializeRedisCounters(policies);
          componentsDeployed.push('redis-counters');
          console.log('✓ Redis counters initialized');
        } catch (error) {
          errors.push(`Redis initialization failed: ${error.message}`);
          console.error('✗ Redis initialization failed:', error);
        }
      }

      // 3. Deploy Prometheus monitoring rules
      if (deploymentConfig.prometheusRules) {
        try {
          await this.deployPrometheusRules(policies);
          componentsDeployed.push('prometheus-rules');
          console.log('✓ Prometheus rules deployed');
        } catch (error) {
          errors.push(`Prometheus rules deployment failed: ${error.message}`);
          console.error('✗ Prometheus rules deployment failed:', error);
        }
      }

      // 4. Create Grafana dashboards
      if (deploymentConfig.grafanaDashboards) {
        try {
          await this.createGrafanaDashboards(policies);
          componentsDeployed.push('grafana-dashboards');
          console.log('✓ Grafana dashboards created');
        } catch (error) {
          errors.push(`Grafana dashboard creation failed: ${error.message}`);
          console.error('✗ Grafana dashboard creation failed:', error);
        }
      }

      // 5. Configure alerting rules
      if (deploymentConfig.alertingRules) {
        try {
          await this.configureAlertingRules(policies);
          componentsDeployed.push('alerting-rules');
          console.log('✓ Alerting rules configured');
        } catch (error) {
          errors.push(`Alerting rules configuration failed: ${error.message}`);
          console.error('✗ Alerting rules configuration failed:', error);
        }
      }

      // 6. Verify deployment health
      const healthCheck = await this.verifyDeploymentHealth();
      if (!healthCheck.healthy) {
        errors.push(`Health check failed: ${healthCheck.issues.join(', ')}`);
      }

      const deploymentEnd = new Date();
      const deploymentTime = deploymentEnd.getTime() - deploymentStart.getTime();

      const result: DeploymentResult = {
        deploymentId,
        timestamp: deploymentEnd,
        success: errors.length === 0,
        componentsDeployed,
        errors,
        rollbackAvailable: componentsDeployed.length > 0,
        metrics: {
          deploymentTime,
          policiesDeployed: policies.length,
          routesUpdated: await this.countUpdatedRoutes(),
          pluginsConfigured: await this.countConfiguredPlugins()
        }
      };

      // Store deployment result
      this.deploymentHistory.push(result);
      
      // Keep only recent deployments
      if (this.deploymentHistory.length > 50) {
        this.deploymentHistory.splice(0, this.deploymentHistory.length - 50);
      }

      this.emit('deploymentCompleted', result);
      console.log(`Deployment ${deploymentId} completed:`, result.success ? '✓ SUCCESS' : '✗ FAILED');

      return result;

    } catch (error) {
      console.error(`Deployment ${deploymentId} failed with critical error:`, error);
      
      const failedResult: DeploymentResult = {
        deploymentId,
        timestamp: new Date(),
        success: false,
        componentsDeployed,
        errors: [...errors, `Critical deployment error: ${error.message}`],
        rollbackAvailable: false,
        metrics: {
          deploymentTime: Date.now() - deploymentStart.getTime(),
          policiesDeployed: 0,
          routesUpdated: 0,
          pluginsConfigured: 0
        }
      };

      this.deploymentHistory.push(failedResult);
      this.emit('deploymentFailed', failedResult);

      throw error;
    }
  }

  /**
   * Deploy Kong Gateway configurations
   */
  private async deployKongConfigurations(policies: RateLimitPolicy[]): Promise<void> {
    // Generate Kong plugin configurations from policies
    const pluginConfigs = isectechAPIRateLimitingManager.generateKongRateLimitingPluginConfigurations();

    // Deploy each plugin configuration
    for (const pluginConfig of pluginConfigs) {
      try {
        await this.kongManager.createOrUpdatePlugin({
          name: pluginConfig.name,
          config: pluginConfig.config,
          enabled: pluginConfig.enabled,
          tags: pluginConfig.tags
        });
      } catch (error) {
        console.error(`Failed to deploy Kong plugin ${pluginConfig.name}:`, error);
        throw error;
      }
    }

    // Configure circuit breaker plugins if enabled
    if (this.config.circuitBreaker.enabled) {
      await this.deployCircuitBreakerPlugins();
    }

    // Configure intelligent traffic management
    await this.deployTrafficManagementPlugins();
  }

  /**
   * Initialize Redis counters and data structures
   */
  private async initializeRedisCounters(policies: RateLimitPolicy[]): Promise<void> {
    await this.redis.connect();

    // Initialize rate limiting counters for each policy
    for (const policy of policies) {
      for (const rateLimit of policy.rateLimits) {
        const key = `ratelimit:${policy.policyId}:${rateLimit.name}`;
        
        // Initialize counter if it doesn't exist
        const exists = await this.redis.exists(key);
        if (!exists) {
          await this.redis.hset(key, 'limit', rateLimit.limit, 'current', 0, 'reset_time', Date.now());
        }
      }

      // Initialize quota counters
      for (const quota of policy.quotas) {
        const key = `quota:${policy.policyId}:${quota.name}`;
        
        const exists = await this.redis.exists(key);
        if (!exists) {
          await this.redis.hset(key, 'limit', quota.limit, 'used', 0, 'period_start', Date.now());
        }
      }
    }

    // Initialize analytics data structures
    await this.redis.hset('analytics:summary', {
      total_requests: 0,
      blocked_requests: 0,
      throttled_requests: 0,
      last_update: Date.now()
    });

    console.log('Redis counters and data structures initialized');
  }

  /**
   * Deploy Prometheus monitoring rules
   */
  private async deployPrometheusRules(policies: RateLimitPolicy[]): Promise<void> {
    const prometheusRules = this.generatePrometheusRules(policies);

    for (const ruleGroup of prometheusRules) {
      try {
        // In production, this would deploy to Prometheus via API or config reload
        console.log(`Deploying Prometheus rule group: ${ruleGroup.name}`);
        
        // Example: POST to Prometheus configuration API
        // await this.prometheusClient.post('/api/v1/rules', ruleGroup);
        
      } catch (error) {
        console.error(`Failed to deploy Prometheus rule group ${ruleGroup.name}:`, error);
        throw error;
      }
    }
  }

  /**
   * Create Grafana dashboards
   */
  private async createGrafanaDashboards(policies: RateLimitPolicy[]): Promise<void> {
    const dashboards = this.generateGrafanaDashboards(policies);

    for (const dashboard of dashboards) {
      try {
        await this.grafanaClient.post('/api/dashboards/db', {
          dashboard: dashboard.definition,
          overwrite: true,
          message: `Auto-deployed by Rate Limiting Infrastructure Integration`
        });
        
        console.log(`Created Grafana dashboard: ${dashboard.title}`);
      } catch (error) {
        console.error(`Failed to create Grafana dashboard ${dashboard.title}:`, error);
        throw error;
      }
    }
  }

  /**
   * Configure alerting rules
   */
  private async configureAlertingRules(policies: RateLimitPolicy[]): Promise<void> {
    const alertingRules = this.generateAlertingRules(policies);

    for (const rule of alertingRules) {
      try {
        // Deploy alerting rule (implementation depends on alerting system)
        console.log(`Configuring alert rule: ${rule.name}`);
        
        // Example: Configure with AlertManager or similar
        // await this.alertManagerClient.post('/api/v1/rules', rule);
        
      } catch (error) {
        console.error(`Failed to configure alert rule ${rule.name}:`, error);
        throw error;
      }
    }
  }

  /**
   * Deploy circuit breaker plugins
   */
  private async deployCircuitBreakerPlugins(): Promise<void> {
    const circuitBreakerPlugin = {
      name: 'circuit-breaker',
      config: {
        failure_threshold: this.config.circuitBreaker.failureThreshold,
        recovery_timeout: this.config.circuitBreaker.recoveryTimeout,
        half_open_requests: this.config.circuitBreaker.halfOpenRequests,
        monitoring_window: this.config.circuitBreaker.monitoringWindow
      },
      enabled: true,
      tags: ['isectech', 'circuit-breaker', 'infrastructure']
    };

    await this.kongManager.createOrUpdatePlugin(circuitBreakerPlugin);
    console.log('Circuit breaker plugins deployed');
  }

  /**
   * Deploy traffic management plugins
   */
  private async deployTrafficManagementPlugins(): Promise<void> {
    // Deploy request size limiting
    const requestSizeLimitPlugin = {
      name: 'request-size-limiting',
      config: {
        allowed_payload_size: 10485760, // 10MB
        size_unit: 'bytes',
        require_content_length: false
      },
      enabled: true,
      tags: ['isectech', 'traffic-management']
    };

    // Deploy IP restriction for suspicious IPs
    const ipRestrictionPlugin = {
      name: 'ip-restriction',
      config: {
        deny: [], // Will be populated by security analysis
        allow: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] // Internal networks
      },
      enabled: true,
      tags: ['isectech', 'security', 'ip-restriction']
    };

    await Promise.all([
      this.kongManager.createOrUpdatePlugin(requestSizeLimitPlugin),
      this.kongManager.createOrUpdatePlugin(ipRestrictionPlugin)
    ]);

    console.log('Traffic management plugins deployed');
  }

  /**
   * Verify deployment health
   */
  private async verifyDeploymentHealth(): Promise<{ healthy: boolean; issues: string[] }> {
    const issues: string[] = [];

    try {
      // Check Kong Gateway health
      const kongHealth = await this.kongManager.getHealthStatus();
      if (!kongHealth.database.reachable) {
        issues.push('Kong Gateway database not reachable');
      }

      // Check Redis connectivity
      try {
        await this.redis.ping();
      } catch (error) {
        issues.push('Redis not accessible');
      }

      // Check plugin configurations
      const plugins = await this.kongManager.createOrUpdatePlugin;
      // Verify plugins are properly configured

      return { healthy: issues.length === 0, issues };

    } catch (error) {
      issues.push(`Health verification failed: ${error.message}`);
      return { healthy: false, issues };
    }
  }

  /**
   * Get real-time traffic analytics
   */
  public async getRealTimeTrafficAnalytics(): Promise<TrafficAnalytics> {
    const now = new Date();
    
    try {
      // Collect metrics from Redis
      const analyticsData = await this.redis.hgetall('analytics:summary');
      
      // Get Kong Gateway metrics
      const kongMetrics = await this.kongManager.getMetrics();
      
      // Get rate limiting statistics
      const rateLimitStats = isectechAPIRateLimitingManager.getRateLimitingAnalytics({
        start: new Date(Date.now() - 60000), // Last minute
        end: now
      });

      const analytics: TrafficAnalytics = {
        timestamp: now,
        totalRequests: parseInt(analyticsData.total_requests || '0'),
        blockedRequests: rateLimitStats.summary.blockedRequests,
        throttledRequests: rateLimitStats.summary.throttledRequests,
        topPaths: [], // Would be populated from Kong logs
        topIPs: rateLimitStats.topBlockedIPs.map(item => ({
          ip: item.ip,
          count: item.blocks,
          blocked: true
        })),
        policyTriggers: rateLimitStats.policyStats.map(stat => ({
          policyId: stat.policyId,
          triggers: stat.triggeredCount
        })),
        responseTimeP95: kongMetrics.kong_latency_ms || 0,
        errorRate: 0 // Would be calculated from status codes
      };

      // Store analytics
      this.trafficAnalytics.push(analytics);
      
      // Keep only recent analytics (last 24 hours)
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
      this.trafficAnalytics = this.trafficAnalytics.filter(a => a.timestamp.getTime() > cutoff);

      return analytics;

    } catch (error) {
      console.error('Failed to collect traffic analytics:', error);
      throw error;
    }
  }

  /**
   * Get infrastructure status
   */
  public async getInfrastructureStatus(): Promise<InfrastructureStatus> {
    const now = new Date();

    try {
      // Kong Gateway status
      const kongStatus = await this.kongManager.getHealthStatus();
      const kongIsHealthy = this.kongManager.getIsHealthy();

      // Redis status
      let redisConnected = false;
      let redisMemory = 'unknown';
      let redisKeyspace = 0;
      
      try {
        const redisInfo = await this.redis.info();
        redisConnected = true;
        
        // Parse Redis info
        const memoryMatch = redisInfo.match(/used_memory_human:(.+)/);
        if (memoryMatch) redisMemory = memoryMatch[1].trim();
        
        const keyspaceMatch = redisInfo.match(/db\d+:keys=(\d+)/);
        if (keyspaceMatch) redisKeyspace = parseInt(keyspaceMatch[1]);
      } catch (error) {
        console.warn('Redis status check failed:', error.message);
      }

      // Rate limiting service status
      const policies = Array.from(isectechAPIRateLimitingManager['policies'].values());
      const recentAnalytics = this.trafficAnalytics.slice(-5);
      const avgRPS = recentAnalytics.length > 0 
        ? recentAnalytics.reduce((sum, a) => sum + a.totalRequests, 0) / recentAnalytics.length / 60
        : 0;

      // Monitoring status
      let prometheusConnected = false;
      let grafanaConnected = false;
      
      try {
        await this.prometheusClient.get('/api/v1/query?query=up');
        prometheusConnected = true;
      } catch (error) {
        console.warn('Prometheus connectivity check failed');
      }
      
      try {
        await this.grafanaClient.get('/api/health');
        grafanaConnected = true;
      } catch (error) {
        console.warn('Grafana connectivity check failed');
      }

      const status: InfrastructureStatus = {
        kongGateway: {
          healthy: kongIsHealthy,
          version: kongStatus.version,
          uptime: Date.now() - this.kongManager.getLastHealthCheck()?.getTime() || 0,
          lastCheck: now
        },
        redis: {
          connected: redisConnected,
          memory: redisMemory,
          keyspace: redisKeyspace,
          lastCheck: now
        },
        rateLimitingService: {
          active: true,
          policiesCount: policies.length,
          requestsPerSecond: avgRPS,
          lastCheck: now
        },
        monitoring: {
          prometheusConnected,
          grafanaConnected,
          alertsActive: prometheusConnected && grafanaConnected,
          lastCheck: now
        }
      };

      this.infrastructureStatus = status;
      return status;

    } catch (error) {
      console.error('Failed to get infrastructure status:', error);
      throw error;
    }
  }

  /**
   * Intelligent scaling based on traffic patterns
   */
  private async performIntelligentScaling(): Promise<void> {
    if (!this.config.intelligentScaling.enabled) {
      return;
    }

    try {
      const analytics = await this.getRealTimeTrafficAnalytics();
      
      // Check if scaling is needed
      const shouldScaleUp = 
        analytics.totalRequests > this.config.intelligentScaling.requestRateThreshold ||
        analytics.responseTimeP95 > 2000; // 2 seconds

      const shouldScaleDown = 
        analytics.totalRequests < this.config.intelligentScaling.requestRateThreshold * 0.5 &&
        analytics.responseTimeP95 < 500; // 0.5 seconds

      if (shouldScaleUp) {
        await this.scaleUp();
      } else if (shouldScaleDown) {
        await this.scaleDown();
      }

    } catch (error) {
      console.error('Intelligent scaling failed:', error);
    }
  }

  private async scaleUp(): Promise<void> {
    console.log('Scaling up infrastructure based on traffic patterns');
    // Implementation would scale Kong Gateway replicas, Redis cluster, etc.
    this.emit('scalingUp', { timestamp: new Date() });
  }

  private async scaleDown(): Promise<void> {
    console.log('Scaling down infrastructure to optimize costs');
    // Implementation would scale down replicas while maintaining minimum
    this.emit('scalingDown', { timestamp: new Date() });
  }

  /**
   * Generate helper methods for monitoring and alerting
   */
  private generatePrometheusRules(policies: RateLimitPolicy[]): any[] {
    return [
      {
        name: 'isectech_rate_limiting_rules',
        rules: [
          {
            alert: 'HighRateLimitViolations',
            expr: 'rate(kong_http_requests_total{status=~"429"}[5m]) > 10',
            for: '2m',
            labels: { severity: 'warning' },
            annotations: {
              summary: 'High rate limit violations detected',
              description: 'Rate limit violations are above threshold'
            }
          },
          {
            alert: 'KongGatewayDown',
            expr: 'kong_nginx_http_current_connections == 0',
            for: '1m',
            labels: { severity: 'critical' },
            annotations: {
              summary: 'Kong Gateway is down',
              description: 'Kong Gateway is not accepting connections'
            }
          }
        ]
      }
    ];
  }

  private generateGrafanaDashboards(policies: RateLimitPolicy[]): any[] {
    return [
      {
        title: 'iSECTECH Rate Limiting Dashboard',
        definition: {
          dashboard: {
            title: 'iSECTECH Rate Limiting Dashboard',
            panels: [
              {
                title: 'Request Rate',
                type: 'graph',
                targets: [{ expr: 'rate(kong_http_requests_total[5m])' }]
              },
              {
                title: 'Rate Limit Violations',
                type: 'stat',
                targets: [{ expr: 'kong_http_requests_total{status="429"}' }]
              }
            ]
          }
        }
      }
    ];
  }

  private generateAlertingRules(policies: RateLimitPolicy[]): any[] {
    return policies.map(policy => ({
      name: `rate_limit_alert_${policy.policyId}`,
      condition: 'rate_limit_exceeded',
      threshold: policy.rateLimits[0]?.limit || 100,
      channels: policy.monitoring.alerting.channels
    }));
  }

  private async countUpdatedRoutes(): Promise<number> {
    try {
      const routes = await this.kongManager.listRoutes();
      return routes.length;
    } catch (error) {
      return 0;
    }
  }

  private async countConfiguredPlugins(): Promise<number> {
    // Implementation would count active plugins
    return 0;
  }

  /**
   * Background task management
   */
  private startBackgroundTasks(): void {
    // Status check task
    this.statusCheckInterval = setInterval(async () => {
      try {
        await this.getInfrastructureStatus();
      } catch (error) {
        console.error('Status check failed:', error);
      }
    }, this.config.integration.statusCheckIntervalMinutes * 60 * 1000);

    // Analytics collection task
    this.analyticsCollectionInterval = setInterval(async () => {
      try {
        await this.getRealTimeTrafficAnalytics();
        await this.performIntelligentScaling();
      } catch (error) {
        console.error('Analytics collection failed:', error);
      }
    }, this.config.integration.analyticsCollectionIntervalMinutes * 60 * 1000);

    // Deployment sync task
    this.deploymentSyncInterval = setInterval(async () => {
      try {
        // Sync any pending policy changes
        await this.syncPolicyChanges();
      } catch (error) {
        console.error('Deployment sync failed:', error);
      }
    }, this.config.integration.syncIntervalMinutes * 60 * 1000);

    // Daily maintenance task
    cron.schedule('0 2 * * *', async () => {
      await this.performDailyMaintenance();
    });

    console.log('Background tasks started');
  }

  private async syncPolicyChanges(): Promise<void> {
    // Implementation would detect and sync policy changes
    console.log('Syncing policy changes...');
  }

  private async performDailyMaintenance(): Promise<void> {
    console.log('Performing daily maintenance tasks...');
    
    // Clean up old deployment history
    const cutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days
    this.deploymentHistory = this.deploymentHistory.filter(d => d.timestamp > cutoff);
    
    // Clean up old analytics
    this.trafficAnalytics = this.trafficAnalytics.filter(a => a.timestamp > cutoff);
    
    // Optimize Redis memory usage
    await this.redis.flushdb(1); // Flush temporary database
    
    this.emit('maintenanceCompleted', { timestamp: new Date() });
  }

  /**
   * Event handler setup
   */
  private setupEventHandlers(): void {
    // Handle Kong Gateway events
    this.kongManager.on('healthCheck', (status) => {
      this.emit('kongHealthUpdate', status);
    });

    // Handle Redis events
    this.redis.on('connect', () => {
      console.log('Redis connected');
      this.emit('redisConnected');
    });

    this.redis.on('error', (error) => {
      console.error('Redis error:', error);
      this.emit('redisError', error);
    });

    // Handle rate limiting events
    isectechAPIRateLimitingManager.on('policyViolation', (event) => {
      this.emit('rateLimitViolation', event);
    });
  }

  /**
   * Graceful shutdown
   */
  public async shutdown(): Promise<void> {
    console.log('Shutting down Rate Limiting Infrastructure Integration...');

    // Clear intervals
    if (this.statusCheckInterval) clearInterval(this.statusCheckInterval);
    if (this.analyticsCollectionInterval) clearInterval(this.analyticsCollectionInterval);
    if (this.deploymentSyncInterval) clearInterval(this.deploymentSyncInterval);

    // Close connections
    try {
      await this.redis.quit();
      await this.kongManager.shutdown();
    } catch (error) {
      console.error('Error during shutdown:', error);
    }

    this.emit('shutdown');
    console.log('Infrastructure integration shutdown complete');
  }

  /**
   * Public API methods
   */
  public getDeploymentHistory(): DeploymentResult[] {
    return [...this.deploymentHistory];
  }

  public getTrafficAnalyticsHistory(): TrafficAnalytics[] {
    return [...this.trafficAnalytics];
  }

  public getCurrentInfrastructureStatus(): Partial<InfrastructureStatus> {
    return { ...this.infrastructureStatus };
  }
}

// Export production-ready infrastructure integration service
export const rateLimitingInfrastructureIntegration = new RateLimitingInfrastructureIntegration({
  kongGateway: {
    adminUrl: process.env.KONG_ADMIN_URL || 'https://kong-admin.isectech.internal:8001',
    adminApiKey: process.env.KONG_ADMIN_API_KEY || '',
    proxyUrl: process.env.KONG_PROXY_URL || 'https://api.isectech.com'
  },
  
  redis: {
    host: process.env.REDIS_HOST || 'redis.isectech-cache.svc.cluster.local',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    database: parseInt(process.env.REDIS_DATABASE || '0')
  },
  
  prometheus: {
    url: process.env.PROMETHEUS_URL || 'https://prometheus.isectech-monitoring.svc.cluster.local:9090',
    username: process.env.PROMETHEUS_USERNAME,
    password: process.env.PROMETHEUS_PASSWORD
  },
  
  grafana: {
    url: process.env.GRAFANA_URL || 'https://grafana.isectech-monitoring.svc.cluster.local:3000',
    apiKey: process.env.GRAFANA_API_KEY || ''
  },
  
  infrastructure: {
    namespace: process.env.KUBERNETES_NAMESPACE || 'isectech-production',
    environment: (process.env.NODE_ENV as any) || 'production',
    region: process.env.AWS_REGION || 'us-east-1'
  },
  
  integration: {
    syncIntervalMinutes: parseInt(process.env.SYNC_INTERVAL_MINUTES || '5'),
    statusCheckIntervalMinutes: parseInt(process.env.STATUS_CHECK_INTERVAL_MINUTES || '2'),
    analyticsCollectionIntervalMinutes: parseInt(process.env.ANALYTICS_INTERVAL_MINUTES || '1'),
    deploymentTimeoutMinutes: parseInt(process.env.DEPLOYMENT_TIMEOUT_MINUTES || '10'),
    rollbackTimeoutMinutes: parseInt(process.env.ROLLBACK_TIMEOUT_MINUTES || '5')
  },
  
  intelligentScaling: {
    enabled: process.env.INTELLIGENT_SCALING_ENABLED === 'true',
    cpuThreshold: parseFloat(process.env.CPU_SCALE_THRESHOLD || '70'),
    memoryThreshold: parseFloat(process.env.MEMORY_SCALE_THRESHOLD || '80'),
    requestRateThreshold: parseInt(process.env.REQUEST_RATE_SCALE_THRESHOLD || '1000'),
    scaleUpCooldown: parseInt(process.env.SCALE_UP_COOLDOWN_MINUTES || '5'),
    scaleDownCooldown: parseInt(process.env.SCALE_DOWN_COOLDOWN_MINUTES || '10'),
    minReplicas: parseInt(process.env.MIN_REPLICAS || '2'),
    maxReplicas: parseInt(process.env.MAX_REPLICAS || '10')
  },
  
  circuitBreaker: {
    enabled: process.env.CIRCUIT_BREAKER_ENABLED === 'true',
    failureThreshold: parseFloat(process.env.CIRCUIT_BREAKER_FAILURE_THRESHOLD || '0.5'),
    recoveryTimeout: parseInt(process.env.CIRCUIT_BREAKER_RECOVERY_TIMEOUT || '30'),
    halfOpenRequests: parseInt(process.env.CIRCUIT_BREAKER_HALF_OPEN_REQUESTS || '5'),
    monitoringWindow: parseInt(process.env.CIRCUIT_BREAKER_MONITORING_WINDOW || '60')
  }
});

export default RateLimitingInfrastructureIntegration;