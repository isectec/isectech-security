// iSECTECH Health Check Monitor
// Production-grade health monitoring system for all services

import { EventEmitter } from 'events';
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { createHash } from 'crypto';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface HealthCheckConfig {
  name: string;
  url: string;
  method?: 'GET' | 'POST' | 'HEAD';
  headers?: Record<string, string>;
  body?: any;
  timeout?: number;
  interval?: number;
  retries?: number;
  expectedStatus?: number[];
  expectedResponse?: string | RegExp;
  tags?: string[];
  critical?: boolean;
  description?: string;
}

export interface HealthCheckResult {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  responseTime: number;
  statusCode?: number;
  message?: string;
  timestamp: Date;
  details?: any;
  error?: string;
}

export interface ServiceHealth {
  service: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  checks: HealthCheckResult[];
  lastUpdated: Date;
  uptime: number;
  responseTime: number;
}

export interface SystemHealth {
  status: 'healthy' | 'unhealthy' | 'degraded';
  services: Record<string, ServiceHealth>;
  timestamp: Date;
  version: string;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK MONITOR CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class HealthCheckMonitor extends EventEmitter {
  private checks: Map<string, HealthCheckConfig> = new Map();
  private results: Map<string, HealthCheckResult[]> = new Map();
  private timers: Map<string, NodeJS.Timeout> = new Map();
  private httpClient: AxiosInstance;
  private isRunning = false;

  constructor() {
    super();
    
    this.httpClient = axios.create({
      timeout: 30000,
      headers: {
        'User-Agent': 'iSECTECH-HealthMonitor/1.0',
        'Accept': 'application/json',
      },
    });

    // Add request interceptor for timing
    this.httpClient.interceptors.request.use((config: any) => {
      config.metadata = { startTime: Date.now() };
      return config;
    });

    // Add response interceptor for timing
    this.httpClient.interceptors.response.use(
      (response: any) => {
        const endTime = Date.now();
        const startTime = response.config.metadata?.startTime || endTime;
        response.responseTime = endTime - startTime;
        return response;
      },
      (error: any) => {
        const endTime = Date.now();
        const startTime = error.config?.metadata?.startTime || endTime;
        error.responseTime = endTime - startTime;
        return Promise.reject(error);
      }
    );
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // CHECK MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Add a health check configuration
   */
  addCheck(config: HealthCheckConfig): void {
    const checkId = this.generateCheckId(config);
    
    // Set defaults
    const fullConfig: HealthCheckConfig = {
      method: 'GET',
      timeout: 30000,
      interval: 60000, // 1 minute
      retries: 3,
      expectedStatus: [200],
      critical: true,
      tags: [],
      ...config,
    };

    this.checks.set(checkId, fullConfig);
    this.results.set(checkId, []);

    this.emit('check:added', { checkId, config: fullConfig });

    // Start monitoring if already running
    if (this.isRunning) {
      this.startCheckMonitoring(checkId, fullConfig);
    }
  }

  /**
   * Remove a health check
   */
  removeCheck(name: string): void {
    const checkId = this.findCheckId(name);
    if (!checkId) return;

    this.stopCheckMonitoring(checkId);
    this.checks.delete(checkId);
    this.results.delete(checkId);

    this.emit('check:removed', { checkId, name });
  }

  /**
   * Update a health check configuration
   */
  updateCheck(name: string, updates: Partial<HealthCheckConfig>): void {
    const checkId = this.findCheckId(name);
    if (!checkId) return;

    const currentConfig = this.checks.get(checkId)!;
    const updatedConfig = { ...currentConfig, ...updates };

    this.checks.set(checkId, updatedConfig);

    // Restart monitoring with new config
    if (this.isRunning) {
      this.stopCheckMonitoring(checkId);
      this.startCheckMonitoring(checkId, updatedConfig);
    }

    this.emit('check:updated', { checkId, config: updatedConfig });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // MONITORING CONTROL
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Start monitoring all health checks
   */
  start(): void {
    if (this.isRunning) return;

    this.isRunning = true;

    for (const [checkId, config] of this.checks.entries()) {
      this.startCheckMonitoring(checkId, config);
    }

    this.emit('monitor:started');
  }

  /**
   * Stop monitoring all health checks
   */
  stop(): void {
    if (!this.isRunning) return;

    this.isRunning = false;

    for (const checkId of this.checks.keys()) {
      this.stopCheckMonitoring(checkId);
    }

    this.emit('monitor:stopped');
  }

  /**
   * Start monitoring a specific check
   */
  private startCheckMonitoring(checkId: string, config: HealthCheckConfig): void {
    // Perform initial check
    this.performCheck(checkId, config);

    // Schedule recurring checks
    const timer = setInterval(() => {
      this.performCheck(checkId, config);
    }, config.interval!);

    this.timers.set(checkId, timer);
  }

  /**
   * Stop monitoring a specific check
   */
  private stopCheckMonitoring(checkId: string): void {
    const timer = this.timers.get(checkId);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(checkId);
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // HEALTH CHECK EXECUTION
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Perform a health check
   */
  private async performCheck(checkId: string, config: HealthCheckConfig): Promise<void> {
    let attempt = 0;
    let lastError: any = null;

    while (attempt <= config.retries!) {
      try {
        const result = await this.executeCheck(config);
        this.recordResult(checkId, result);
        
        this.emit('check:success', { checkId, result });
        return;
      } catch (error) {
        lastError = error;
        attempt++;
        
        if (attempt <= config.retries!) {
          // Wait before retry with exponential backoff
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
          await this.sleep(delay);
        }
      }
    }

    // All retries failed
    const failureResult: HealthCheckResult = {
      name: config.name,
      status: 'unhealthy',
      responseTime: lastError?.responseTime || 0,
      statusCode: lastError?.response?.status,
      message: `Failed after ${config.retries} retries`,
      timestamp: new Date(),
      error: lastError?.message || 'Unknown error',
    };

    this.recordResult(checkId, failureResult);
    this.emit('check:failure', { checkId, result: failureResult, error: lastError });
  }

  /**
   * Execute a single health check attempt
   */
  private async executeCheck(config: HealthCheckConfig): Promise<HealthCheckResult> {
    const requestConfig: AxiosRequestConfig = {
      method: config.method!,
      url: config.url,
      headers: config.headers,
      data: config.body,
      timeout: config.timeout!,
      validateStatus: () => true, // Don't throw on any status code
    };

    const response = await this.httpClient.request(requestConfig);
    const responseTime = (response as any).responseTime || 0;

    // Check status code
    const statusOk = config.expectedStatus!.includes(response.status);
    
    // Check response content if expected
    let contentOk = true;
    if (config.expectedResponse) {
      const responseText = typeof response.data === 'string' 
        ? response.data 
        : JSON.stringify(response.data);
      
      if (config.expectedResponse instanceof RegExp) {
        contentOk = config.expectedResponse.test(responseText);
      } else {
        contentOk = responseText.includes(config.expectedResponse);
      }
    }

    const isHealthy = statusOk && contentOk;
    const status = isHealthy ? 'healthy' : 'unhealthy';

    return {
      name: config.name,
      status,
      responseTime,
      statusCode: response.status,
      message: isHealthy ? 'OK' : 'Health check failed',
      timestamp: new Date(),
      details: {
        headers: response.headers,
        data: response.data,
      },
    };
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // RESULT MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  /**
   * Record a health check result
   */
  private recordResult(checkId: string, result: HealthCheckResult): void {
    const results = this.results.get(checkId) || [];
    
    // Keep last 100 results
    results.push(result);
    if (results.length > 100) {
      results.shift();
    }
    
    this.results.set(checkId, results);
  }

  /**
   * Get results for a specific check
   */
  getCheckResults(name: string, limit = 10): HealthCheckResult[] {
    const checkId = this.findCheckId(name);
    if (!checkId) return [];

    const results = this.results.get(checkId) || [];
    return results.slice(-limit).reverse();
  }

  /**
   * Get the latest result for a specific check
   */
  getLatestResult(name: string): HealthCheckResult | null {
    const results = this.getCheckResults(name, 1);
    return results[0] || null;
  }

  /**
   * Get overall system health
   */
  getSystemHealth(): SystemHealth {
    const services: Record<string, ServiceHealth> = {};
    let overallStatus: 'healthy' | 'unhealthy' | 'degraded' = 'healthy';

    for (const [checkId, config] of this.checks.entries()) {
      const results = this.results.get(checkId) || [];
      const latestResult = results[results.length - 1];
      
      if (!latestResult) continue;

      const serviceName = this.extractServiceName(config.name);
      
      if (!services[serviceName]) {
        services[serviceName] = {
          service: serviceName,
          status: 'healthy',
          checks: [],
          lastUpdated: new Date(),
          uptime: 0,
          responseTime: 0,
        };
      }

      services[serviceName].checks.push(latestResult);
      services[serviceName].lastUpdated = latestResult.timestamp;

      // Calculate uptime and average response time
      const recentResults = results.slice(-10);
      const healthyResults = recentResults.filter(r => r.status === 'healthy');
      services[serviceName].uptime = (healthyResults.length / recentResults.length) * 100;
      services[serviceName].responseTime = recentResults.reduce((sum, r) => sum + r.responseTime, 0) / recentResults.length;

      // Determine service status
      if (latestResult.status === 'unhealthy' && config.critical) {
        services[serviceName].status = 'unhealthy';
        overallStatus = 'unhealthy';
      } else if (latestResult.status === 'unhealthy' && !config.critical) {
        if (services[serviceName].status === 'healthy') {
          services[serviceName].status = 'degraded';
        }
        if (overallStatus === 'healthy') {
          overallStatus = 'degraded';
        }
      }
    }

    return {
      status: overallStatus,
      services,
      timestamp: new Date(),
      version: process.env.npm_package_version || '1.0.0',
    };
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private generateCheckId(config: HealthCheckConfig): string {
    const data = `${config.name}:${config.url}:${config.method}`;
    return createHash('md5').update(data).digest('hex').substring(0, 8);
  }

  private findCheckId(name: string): string | null {
    for (const [checkId, config] of this.checks.entries()) {
      if (config.name === name) {
        return checkId;
      }
    }
    return null;
  }

  private extractServiceName(checkName: string): string {
    // Extract service name from check name (e.g., "api-auth" -> "api")
    return checkName.split('-')[0] || checkName;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDEFINED HEALTH CHECKS FOR ISECTECH
// ═══════════════════════════════════════════════════════════════════════════════

export const createISECTECHHealthChecks = (): HealthCheckConfig[] => [
  // Frontend health checks
  {
    name: 'frontend-app',
    url: 'https://isectech.com/api/health',
    description: 'Main application frontend',
    critical: true,
    tags: ['frontend', 'critical'],
    interval: 30000, // 30 seconds
  },
  
  // Backend API health checks
  {
    name: 'api-auth',
    url: 'https://api.isectech.com/auth/health',
    description: 'Authentication service',
    critical: true,
    tags: ['api', 'auth', 'critical'],
  },
  
  {
    name: 'api-user',
    url: 'https://api.isectech.com/users/health',
    description: 'User management service',
    critical: true,
    tags: ['api', 'users', 'critical'],
  },
  
  {
    name: 'api-security',
    url: 'https://api.isectech.com/security/health',
    description: 'Security monitoring service',
    critical: true,
    tags: ['api', 'security', 'critical'],
  },
  
  // AI Services health checks
  {
    name: 'ai-threat-detection',
    url: 'https://ai.isectech.com/threat-detection/health',
    description: 'AI threat detection service',
    critical: false,
    tags: ['ai', 'threat-detection'],
    interval: 60000, // 1 minute
  },
  
  {
    name: 'ai-anomaly-detection',
    url: 'https://ai.isectech.com/anomaly-detection/health',
    description: 'AI anomaly detection service',
    critical: false,
    tags: ['ai', 'anomaly-detection'],
    interval: 60000,
  },
  
  // Infrastructure health checks
  {
    name: 'database-postgres',
    url: 'http://postgres:5432',
    method: 'HEAD',
    description: 'PostgreSQL database',
    critical: true,
    tags: ['database', 'postgres', 'critical'],
    timeout: 5000,
  },
  
  {
    name: 'cache-redis',
    url: 'http://redis:6379',
    method: 'HEAD',
    description: 'Redis cache',
    critical: false,
    tags: ['cache', 'redis'],
    timeout: 5000,
  },
  
  // Monitoring infrastructure
  {
    name: 'monitoring-prometheus',
    url: 'http://prometheus:9090/api/v1/query?query=up',
    description: 'Prometheus monitoring',
    critical: false,
    tags: ['monitoring', 'prometheus'],
    expectedResponse: /success/,
  },
  
  {
    name: 'monitoring-grafana',
    url: 'http://grafana:3000/api/health',
    description: 'Grafana dashboards',
    critical: false,
    tags: ['monitoring', 'grafana'],
  },
  
  // External dependencies
  {
    name: 'external-threat-intel',
    url: 'https://api.threatintel.com/status',
    description: 'External threat intelligence feed',
    critical: false,
    tags: ['external', 'threat-intel'],
    interval: 300000, // 5 minutes
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// HEALTH CHECK SERVER
// ═══════════════════════════════════════════════════════════════════════════════

export class HealthCheckServer {
  private monitor: HealthCheckMonitor;
  
  constructor(monitor: HealthCheckMonitor) {
    this.monitor = monitor;
  }
  
  /**
   * Express route handler for health check endpoint
   */
  getHealthHandler() {
    return (req: any, res: any) => {
      const systemHealth = this.monitor.getSystemHealth();
      
      const statusCode = systemHealth.status === 'healthy' ? 200 : 
                        systemHealth.status === 'degraded' ? 200 : 503;
      
      res.status(statusCode).json(systemHealth);
    };
  }
  
  /**
   * Express route handler for detailed health check
   */
  getDetailedHealthHandler() {
    return (req: any, res: any) => {
      const systemHealth = this.monitor.getSystemHealth();
      const detailed = {
        ...systemHealth,
        checks: Object.values(systemHealth.services).flatMap(service => 
          service.checks.map(check => ({
            ...check,
            history: this.monitor.getCheckResults(check.name, 10)
          }))
        )
      };
      
      res.json(detailed);
    };
  }
}

// Export singleton instance
export const healthMonitor = new HealthCheckMonitor();