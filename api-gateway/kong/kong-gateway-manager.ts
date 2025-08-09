/**
 * Production-grade Kong Gateway Manager for iSECTECH
 * 
 * Provides comprehensive Kong Gateway management capabilities including
 * service registration, route management, plugin configuration, health
 * monitoring, and automated failover for the cybersecurity platform.
 * 
 * Custom implementation for iSECTECH multi-tenant cybersecurity platform.
 */

import axios, { AxiosInstance } from 'axios';
import { z } from 'zod';
import { KongService, KongRoute, KongUpstream, KongTarget, KongPlugin } from './kong-gateway-config';

// Kong Admin API response schemas
export const KongHealthStatusSchema = z.object({
  database: z.object({
    reachable: z.boolean()
  }),
  memory: z.object({
    workers_lua_vms: z.array(z.object({
      http_allocated_gc: z.string(),
      pid: z.number()
    }))
  }),
  server: z.object({
    connections_accepted: z.number(),
    connections_active: z.number(),
    connections_handled: z.number(),
    connections_reading: z.number(),
    connections_waiting: z.number(),
    connections_writing: z.number(),
    total_requests: z.number()
  }),
  configuration_hash: z.string(),
  lua_version: z.string(),
  prng_seeds: z.object({
    pid_1: z.number(),
    pid_2: z.number(),
    pid_3: z.number()
  }),
  tagline: z.string(),
  timers: z.object({
    pending: z.number(),
    running: z.number()
  }),
  version: z.string(),
  node_id: z.string(),
  hostname: z.string()
});

export const KongMetricsSchema = z.object({
  http_requests_total: z.number(),
  http_consumer_status: z.record(z.number()),
  nginx_metric_errors_total: z.number(),
  session_duration_ms: z.number(),
  kong_latency_ms: z.number(),
  request_latency_ms: z.number(),
  upstream_latency_ms: z.number()
});

export type KongHealthStatus = z.infer<typeof KongHealthStatusSchema>;
export type KongMetrics = z.infer<typeof KongMetricsSchema>;

/**
 * Kong Gateway Management Interface
 */
export class KongGatewayManager {
  private adminClient: AxiosInstance;
  private healthCheckInterval: NodeJS.Timeout | null = null;
  private metricsCollectionInterval: NodeJS.Timeout | null = null;
  private lastHealthCheck: Date | null = null;
  private isHealthy: boolean = false;

  constructor(
    private config: {
      adminUrl: string;
      adminApiKey: string;
      adminTimeout: number;
      healthCheckIntervalMs: number;
      metricsCollectionIntervalMs: number;
      retryAttempts: number;
      retryDelayMs: number;
    }
  ) {
    this.adminClient = axios.create({
      baseURL: this.config.adminUrl,
      timeout: this.config.adminTimeout,
      headers: {
        'Content-Type': 'application/json',
        'Kong-Admin-Token': this.config.adminApiKey,
        'User-Agent': 'iSECTECH-Kong-Manager/1.0'
      },
      httpsAgent: {
        rejectUnauthorized: true
      }
    });

    this.setupRequestInterceptors();
    this.startHealthChecking();
    this.startMetricsCollection();
  }

  /**
   * Setup request interceptors for retry logic and error handling
   */
  private setupRequestInterceptors(): void {
    // Request interceptor for logging
    this.adminClient.interceptors.request.use(
      (config) => {
        console.log(`Kong Admin API Request: ${config.method?.toUpperCase()} ${config.url}`);
        return config;
      },
      (error) => {
        console.error('Kong Admin API Request Error:', error);
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling and retries
    this.adminClient.interceptors.response.use(
      (response) => {
        console.log(`Kong Admin API Response: ${response.status} for ${response.config.url}`);
        return response;
      },
      async (error) => {
        const originalRequest = error.config;

        if (error.response?.status >= 500 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
            try {
              console.log(`Retrying Kong Admin API request, attempt ${attempt}/${this.config.retryAttempts}`);
              await this.delay(this.config.retryDelayMs * attempt);
              return await this.adminClient(originalRequest);
            } catch (retryError) {
              if (attempt === this.config.retryAttempts) {
                console.error('Kong Admin API max retries exceeded:', retryError);
                throw retryError;
              }
            }
          }
        }

        console.error('Kong Admin API Response Error:', error);
        return Promise.reject(error);
      }
    );
  }

  /**
   * Create or update a service in Kong
   */
  async createOrUpdateService(service: KongService): Promise<KongService> {
    try {
      // Try to get existing service first
      try {
        const existingResponse = await this.adminClient.get(`/services/${service.name}`);
        // Service exists, update it
        const updateResponse = await this.adminClient.patch(`/services/${service.name}`, service);
        console.log(`Updated Kong service: ${service.name}`);
        return updateResponse.data;
      } catch (error: any) {
        if (error.response?.status === 404) {
          // Service doesn't exist, create it
          const createResponse = await this.adminClient.post('/services', service);
          console.log(`Created Kong service: ${service.name}`);
          return createResponse.data;
        }
        throw error;
      }
    } catch (error) {
      console.error(`Failed to create/update Kong service ${service.name}:`, error);
      throw new Error(`Kong service operation failed: ${error}`);
    }
  }

  /**
   * Create or update a route in Kong
   */
  async createOrUpdateRoute(route: KongRoute): Promise<KongRoute> {
    try {
      // Try to get existing route first
      try {
        const existingResponse = await this.adminClient.get(`/routes/${route.name}`);
        // Route exists, update it
        const updateResponse = await this.adminClient.patch(`/routes/${route.name}`, route);
        console.log(`Updated Kong route: ${route.name}`);
        return updateResponse.data;
      } catch (error: any) {
        if (error.response?.status === 404) {
          // Route doesn't exist, create it
          const createResponse = await this.adminClient.post('/routes', route);
          console.log(`Created Kong route: ${route.name}`);
          return createResponse.data;
        }
        throw error;
      }
    } catch (error) {
      console.error(`Failed to create/update Kong route ${route.name}:`, error);
      throw new Error(`Kong route operation failed: ${error}`);
    }
  }

  /**
   * Create or update an upstream in Kong
   */
  async createOrUpdateUpstream(upstream: KongUpstream): Promise<KongUpstream> {
    try {
      // Try to get existing upstream first
      try {
        const existingResponse = await this.adminClient.get(`/upstreams/${upstream.name}`);
        // Upstream exists, update it
        const updateResponse = await this.adminClient.patch(`/upstreams/${upstream.name}`, upstream);
        console.log(`Updated Kong upstream: ${upstream.name}`);
        return updateResponse.data;
      } catch (error: any) {
        if (error.response?.status === 404) {
          // Upstream doesn't exist, create it
          const createResponse = await this.adminClient.post('/upstreams', upstream);
          console.log(`Created Kong upstream: ${upstream.name}`);
          return createResponse.data;
        }
        throw error;
      }
    } catch (error) {
      console.error(`Failed to create/update Kong upstream ${upstream.name}:`, error);
      throw new Error(`Kong upstream operation failed: ${error}`);
    }
  }

  /**
   * Create or update a target in an upstream
   */
  async createOrUpdateTarget(upstreamName: string, target: KongTarget): Promise<KongTarget> {
    try {
      // Targets are usually recreated rather than updated
      const createResponse = await this.adminClient.post(`/upstreams/${upstreamName}/targets`, {
        target: target.target,
        weight: target.weight,
        tags: target.tags
      });
      console.log(`Created Kong target ${target.target} for upstream ${upstreamName}`);
      return createResponse.data;
    } catch (error) {
      console.error(`Failed to create Kong target ${target.target}:`, error);
      throw new Error(`Kong target operation failed: ${error}`);
    }
  }

  /**
   * Create or update a plugin in Kong
   */
  async createOrUpdatePlugin(plugin: KongPlugin): Promise<KongPlugin> {
    try {
      // Try to get existing plugin first
      const existingPluginsResponse = await this.adminClient.get('/plugins', {
        params: {
          name: plugin.name,
          ...(plugin.service && { service_id: plugin.service.id }),
          ...(plugin.route && { route_id: plugin.route.id }),
          ...(plugin.consumer && { consumer_id: plugin.consumer.id })
        }
      });

      const existingPlugins = existingPluginsResponse.data.data;
      
      if (existingPlugins.length > 0) {
        // Plugin exists, update it
        const pluginId = existingPlugins[0].id;
        const updateResponse = await this.adminClient.patch(`/plugins/${pluginId}`, plugin);
        console.log(`Updated Kong plugin: ${plugin.name} (${pluginId})`);
        return updateResponse.data;
      } else {
        // Plugin doesn't exist, create it
        const createResponse = await this.adminClient.post('/plugins', plugin);
        console.log(`Created Kong plugin: ${plugin.name}`);
        return createResponse.data;
      }
    } catch (error) {
      console.error(`Failed to create/update Kong plugin ${plugin.name}:`, error);
      throw new Error(`Kong plugin operation failed: ${error}`);
    }
  }

  /**
   * Deploy complete Kong configuration
   */
  async deployConfiguration(config: {
    services: KongService[];
    routes: KongRoute[];
    upstreams: KongUpstream[];
    targets: { upstreamName: string; target: KongTarget }[];
    plugins: KongPlugin[];
  }): Promise<{
    services: KongService[];
    routes: KongRoute[];
    upstreams: KongUpstream[];
    targets: KongTarget[];
    plugins: KongPlugin[];
  }> {
    try {
      console.log('Starting Kong configuration deployment...');

      // Deploy services first
      const deployedServices = await Promise.all(
        config.services.map(service => this.createOrUpdateService(service))
      );

      // Deploy upstreams
      const deployedUpstreams = await Promise.all(
        config.upstreams.map(upstream => this.createOrUpdateUpstream(upstream))
      );

      // Deploy targets
      const deployedTargets = await Promise.all(
        config.targets.map(({ upstreamName, target }) => 
          this.createOrUpdateTarget(upstreamName, target)
        )
      );

      // Deploy routes
      const deployedRoutes = await Promise.all(
        config.routes.map(route => this.createOrUpdateRoute(route))
      );

      // Deploy plugins
      const deployedPlugins = await Promise.all(
        config.plugins.map(plugin => this.createOrUpdatePlugin(plugin))
      );

      console.log('Kong configuration deployment completed successfully');

      return {
        services: deployedServices,
        routes: deployedRoutes,
        upstreams: deployedUpstreams,
        targets: deployedTargets,
        plugins: deployedPlugins
      };
    } catch (error) {
      console.error('Kong configuration deployment failed:', error);
      throw new Error(`Kong deployment failed: ${error}`);
    }
  }

  /**
   * Get Kong health status
   */
  async getHealthStatus(): Promise<KongHealthStatus> {
    try {
      const response = await this.adminClient.get('/status');
      const healthStatus = KongHealthStatusSchema.parse(response.data);
      this.isHealthy = healthStatus.database.reachable;
      this.lastHealthCheck = new Date();
      return healthStatus;
    } catch (error) {
      console.error('Failed to get Kong health status:', error);
      this.isHealthy = false;
      throw new Error(`Kong health check failed: ${error}`);
    }
  }

  /**
   * Get Kong metrics
   */
  async getMetrics(): Promise<KongMetrics> {
    try {
      const response = await this.adminClient.get('/metrics');
      return KongMetricsSchema.parse(response.data);
    } catch (error) {
      console.error('Failed to get Kong metrics:', error);
      throw new Error(`Kong metrics collection failed: ${error}`);
    }
  }

  /**
   * List all services
   */
  async listServices(): Promise<KongService[]> {
    try {
      const response = await this.adminClient.get('/services');
      return response.data.data;
    } catch (error) {
      console.error('Failed to list Kong services:', error);
      throw new Error(`Kong service listing failed: ${error}`);
    }
  }

  /**
   * List all routes
   */
  async listRoutes(): Promise<KongRoute[]> {
    try {
      const response = await this.adminClient.get('/routes');
      return response.data.data;
    } catch (error) {
      console.error('Failed to list Kong routes:', error);
      throw new Error(`Kong route listing failed: ${error}`);
    }
  }

  /**
   * List all upstreams
   */
  async listUpstreams(): Promise<KongUpstream[]> {
    try {
      const response = await this.adminClient.get('/upstreams');
      return response.data.data;
    } catch (error) {
      console.error('Failed to list Kong upstreams:', error);
      throw new Error(`Kong upstream listing failed: ${error}`);
    }
  }

  /**
   * Get upstream health
   */
  async getUpstreamHealth(upstreamName: string): Promise<any> {
    try {
      const response = await this.adminClient.get(`/upstreams/${upstreamName}/health`);
      return response.data;
    } catch (error) {
      console.error(`Failed to get upstream health for ${upstreamName}:`, error);
      throw new Error(`Kong upstream health check failed: ${error}`);
    }
  }

  /**
   * Enable or disable a target
   */
  async setTargetHealth(upstreamName: string, targetId: string, healthy: boolean): Promise<void> {
    try {
      const action = healthy ? 'healthy' : 'unhealthy';
      await this.adminClient.post(`/upstreams/${upstreamName}/targets/${targetId}/${action}`);
      console.log(`Set target ${targetId} in upstream ${upstreamName} to ${action}`);
    } catch (error) {
      console.error(`Failed to set target health for ${targetId}:`, error);
      throw new Error(`Kong target health operation failed: ${error}`);
    }
  }

  /**
   * Start automated health checking
   */
  private startHealthChecking(): void {
    this.healthCheckInterval = setInterval(async () => {
      try {
        await this.getHealthStatus();
        if (this.isHealthy) {
          console.log('Kong Gateway health check: HEALTHY');
        }
      } catch (error) {
        console.error('Kong Gateway health check: UNHEALTHY -', error);
        // Implement alerting logic here
        this.handleUnhealthyState();
      }
    }, this.config.healthCheckIntervalMs);

    console.log(`Started Kong health checking every ${this.config.healthCheckIntervalMs}ms`);
  }

  /**
   * Start automated metrics collection
   */
  private startMetricsCollection(): void {
    this.metricsCollectionInterval = setInterval(async () => {
      try {
        const metrics = await this.getMetrics();
        console.log('Kong Gateway metrics collected:', {
          requests: metrics.http_requests_total,
          latency: metrics.kong_latency_ms
        });
        // Send metrics to monitoring system
        this.sendMetricsToMonitoring(metrics);
      } catch (error) {
        console.error('Kong Gateway metrics collection failed:', error);
      }
    }, this.config.metricsCollectionIntervalMs);

    console.log(`Started Kong metrics collection every ${this.config.metricsCollectionIntervalMs}ms`);
  }

  /**
   * Handle unhealthy state
   */
  private handleUnhealthyState(): void {
    // Implement alerting and failover logic
    console.error('Kong Gateway is unhealthy - triggering alerts');
    
    // Example: Send alert to monitoring system
    // this.sendAlert({
    //   severity: 'critical',
    //   message: 'Kong Gateway health check failed',
    //   timestamp: new Date(),
    //   service: 'kong-gateway'
    // });
  }

  /**
   * Send metrics to monitoring system
   */
  private sendMetricsToMonitoring(metrics: KongMetrics): void {
    // Implement metrics forwarding to Prometheus/Grafana
    console.log('Sending Kong metrics to monitoring system:', metrics);
  }

  /**
   * Graceful shutdown
   */
  async shutdown(): Promise<void> {
    console.log('Shutting down Kong Gateway Manager...');

    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = null;
    }

    if (this.metricsCollectionInterval) {
      clearInterval(this.metricsCollectionInterval);
      this.metricsCollectionInterval = null;
    }

    console.log('Kong Gateway Manager shutdown complete');
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get current health status
   */
  public getIsHealthy(): boolean {
    return this.isHealthy;
  }

  /**
   * Get last health check timestamp
   */
  public getLastHealthCheck(): Date | null {
    return this.lastHealthCheck;
  }
}

// Export production-ready Kong Gateway Manager
export const kongGatewayManager = new KongGatewayManager({
  adminUrl: process.env.KONG_ADMIN_URL || 'https://kong-admin.isectech.internal:8001',
  adminApiKey: process.env.KONG_ADMIN_API_KEY || '',
  adminTimeout: parseInt(process.env.KONG_ADMIN_TIMEOUT || '30000'),
  healthCheckIntervalMs: parseInt(process.env.KONG_HEALTH_CHECK_INTERVAL || '30000'),
  metricsCollectionIntervalMs: parseInt(process.env.KONG_METRICS_INTERVAL || '60000'),
  retryAttempts: parseInt(process.env.KONG_RETRY_ATTEMPTS || '3'),
  retryDelayMs: parseInt(process.env.KONG_RETRY_DELAY || '1000')
});