/**
 * API Validation Monitoring System
 * 
 * Provides comprehensive monitoring, logging, and alerting for API validation failures
 * across schema, business rules, compliance, and data integrity validation.
 * 
 * Task 83.4: Set Up Monitoring and Logging for Validation Failures
 */

import { Logger } from 'winston';
import { Registry, Counter, Histogram, Gauge, collectDefaultMetrics } from 'prom-client';
import { EventEmitter } from 'events';

interface ValidationMetrics {
  // Counter metrics for different types of validation failures
  validationFailuresTotal: Counter<string>;
  validationSuccessTotal: Counter<string>;
  
  // Histogram for validation duration
  validationDuration: Histogram<string>;
  
  // Gauge for current validation error rates
  validationErrorRate: Gauge<string>;
  
  // Counters for specific error types
  schemaValidationErrors: Counter<string>;
  businessRuleViolations: Counter<string>;
  complianceViolations: Counter<string>;
  dataIntegrityErrors: Counter<string>;
  
  // Performance metrics
  validationQueueDepth: Gauge<string>;
  validationThroughput: Counter<string>;
}

interface ValidationError {
  field: string;
  value: any;
  rule: string;
  message: string;
  severity: 'error' | 'warning' | 'critical';
  code: string;
  timestamp: Date;
  tenantId?: string;
  eventId?: string;
  eventType?: string;
  source?: string;
}

interface ValidationAlert {
  alertId: string;
  type: 'rate_threshold' | 'error_spike' | 'compliance_violation' | 'system_health';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  metadata: Record<string, any>;
  timestamp: Date;
  tenantId?: string;
}

interface AlertingConfig {
  // Rate-based alerting
  errorRateThresholds: {
    warning: number;    // e.g., 5% error rate
    critical: number;   // e.g., 15% error rate
  };
  
  // Spike detection
  spikeDetection: {
    enabled: boolean;
    windowMinutes: number;     // e.g., 5 minutes
    spikeMultiplier: number;   // e.g., 3x normal rate
    minimumEvents: number;     // e.g., 10 events minimum
  };
  
  // Compliance alerting
  complianceAlerting: {
    immediateAlerts: string[];  // Rule types that trigger immediate alerts
    batchingEnabled: boolean;   // Batch non-critical compliance alerts
    batchIntervalMinutes: number;
  };
  
  // Alert destinations
  destinations: {
    webhook?: {
      url: string;
      headers?: Record<string, string>;
    };
    slack?: {
      webhook: string;
      channel: string;
    };
    pagerduty?: {
      integrationKey: string;
    };
    email?: {
      recipients: string[];
      smtpConfig: any;
    };
  };
}

interface MonitoringConfig {
  // Logging configuration
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    structured: boolean;
    includeStackTrace: boolean;
    rotateFiles: boolean;
  };
  
  // Metrics configuration
  metrics: {
    enabled: boolean;
    port: number;
    path: string;
    defaultLabels: Record<string, string>;
  };
  
  // Alerting configuration
  alerting: AlertingConfig;
  
  // Performance settings
  performance: {
    bufferSize: number;
    flushIntervalMs: number;
    enableSampling: boolean;
    samplingRate: number;
  };
}

/**
 * API Validation Monitoring Service
 * 
 * Comprehensive monitoring solution for API validation failures with:
 * - Prometheus metrics collection
 * - Structured logging with correlation IDs
 * - Intelligent alerting with rate limiting
 * - Tenant-aware monitoring and isolation
 * - Performance optimization with buffering
 */
export class APIValidationMonitor extends EventEmitter {
  private metrics: ValidationMetrics;
  private logger: Logger;
  private config: MonitoringConfig;
  private registry: Registry;
  private alertBuffer: ValidationAlert[] = [];
  private errorRateWindow: Map<string, number[]> = new Map();
  private lastFlush: number = Date.now();

  constructor(logger: Logger, config: MonitoringConfig) {
    super();
    this.logger = logger;
    this.config = config;
    this.registry = new Registry();
    
    this.initializeMetrics();
    this.startPeriodicFlush();
    
    // Enable default metrics collection
    if (config.metrics.enabled) {
      collectDefaultMetrics({ 
        register: this.registry,
        labels: config.metrics.defaultLabels 
      });
    }

    this.logger.info('API Validation Monitor initialized', {
      component: 'APIValidationMonitor',
      metricsEnabled: config.metrics.enabled,
      alertingEnabled: !!config.alerting,
    });
  }

  /**
   * Initialize Prometheus metrics
   */
  private initializeMetrics(): void {
    this.metrics = {
      validationFailuresTotal: new Counter({
        name: 'api_validation_failures_total',
        help: 'Total number of API validation failures',
        labelNames: ['tenant_id', 'validation_type', 'error_code', 'severity', 'event_type'],
        registers: [this.registry],
      }),

      validationSuccessTotal: new Counter({
        name: 'api_validation_success_total', 
        help: 'Total number of successful API validations',
        labelNames: ['tenant_id', 'validation_type', 'event_type'],
        registers: [this.registry],
      }),

      validationDuration: new Histogram({
        name: 'api_validation_duration_seconds',
        help: 'Duration of API validation operations',
        labelNames: ['tenant_id', 'validation_type', 'event_type'],
        buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5],
        registers: [this.registry],
      }),

      validationErrorRate: new Gauge({
        name: 'api_validation_error_rate',
        help: 'Current API validation error rate (errors per minute)',
        labelNames: ['tenant_id', 'validation_type'],
        registers: [this.registry],
      }),

      schemaValidationErrors: new Counter({
        name: 'api_schema_validation_errors_total',
        help: 'Total number of schema validation errors',
        labelNames: ['tenant_id', 'event_type', 'field', 'error_code'],
        registers: [this.registry],
      }),

      businessRuleViolations: new Counter({
        name: 'api_business_rule_violations_total',
        help: 'Total number of business rule violations',
        labelNames: ['tenant_id', 'rule_name', 'event_type'],
        registers: [this.registry],
      }),

      complianceViolations: new Counter({
        name: 'api_compliance_violations_total',
        help: 'Total number of compliance violations',
        labelNames: ['tenant_id', 'framework', 'rule_id', 'severity'],
        registers: [this.registry],
      }),

      dataIntegrityErrors: new Counter({
        name: 'api_data_integrity_errors_total',
        help: 'Total number of data integrity errors',
        labelNames: ['tenant_id', 'error_type', 'field'],
        registers: [this.registry],
      }),

      validationQueueDepth: new Gauge({
        name: 'api_validation_queue_depth',
        help: 'Current depth of validation processing queue',
        labelNames: ['tenant_id'],
        registers: [this.registry],
      }),

      validationThroughput: new Counter({
        name: 'api_validation_throughput_total',
        help: 'Total number of validations processed',
        labelNames: ['tenant_id', 'status'],
        registers: [this.registry],
      }),
    };
  }

  /**
   * Record a validation failure with comprehensive context
   */
  public recordValidationFailure(
    validationType: 'schema' | 'business_rule' | 'compliance' | 'data_integrity',
    error: ValidationError,
    duration?: number
  ): void {
    const labels = {
      tenant_id: error.tenantId || 'unknown',
      validation_type: validationType,
      error_code: error.code,
      severity: error.severity,
      event_type: error.eventType || 'unknown',
    };

    // Record metrics
    this.metrics.validationFailuresTotal.inc(labels);
    
    if (duration) {
      this.metrics.validationDuration.observe(
        { ...labels, validation_type: validationType },
        duration / 1000 // Convert to seconds
      );
    }

    // Record specific validation type metrics
    switch (validationType) {
      case 'schema':
        this.metrics.schemaValidationErrors.inc({
          tenant_id: error.tenantId || 'unknown',
          event_type: error.eventType || 'unknown',
          field: error.field,
          error_code: error.code,
        });
        break;

      case 'business_rule':
        this.metrics.businessRuleViolations.inc({
          tenant_id: error.tenantId || 'unknown',
          rule_name: error.rule,
          event_type: error.eventType || 'unknown',
        });
        break;

      case 'compliance':
        const [framework, ruleId] = error.rule.split('_', 2);
        this.metrics.complianceViolations.inc({
          tenant_id: error.tenantId || 'unknown',
          framework: framework || 'unknown',
          rule_id: ruleId || 'unknown',
          severity: error.severity,
        });
        break;

      case 'data_integrity':
        this.metrics.dataIntegrityErrors.inc({
          tenant_id: error.tenantId || 'unknown',
          error_type: error.code,
          field: error.field,
        });
        break;
    }

    // Structured logging
    this.logger.error('API validation failure', {
      component: 'APIValidationMonitor',
      validationType,
      error: {
        field: error.field,
        rule: error.rule,
        message: error.message,
        severity: error.severity,
        code: error.code,
        value: this.config.logging.level === 'debug' ? error.value : '[REDACTED]',
      },
      context: {
        tenantId: error.tenantId,
        eventId: error.eventId,
        eventType: error.eventType,
        source: error.source,
        timestamp: error.timestamp.toISOString(),
      },
      performance: {
        durationMs: duration,
      },
      ...(this.config.logging.includeStackTrace && { stack: new Error().stack }),
    });

    // Update error rate tracking
    this.updateErrorRateTracking(error.tenantId || 'global', validationType);

    // Check alerting conditions
    this.checkAlertingConditions(validationType, error);

    // Emit event for external listeners
    this.emit('validation-failure', {
      type: validationType,
      error,
      duration,
    });
  }

  /**
   * Record a successful validation
   */
  public recordValidationSuccess(
    validationType: 'schema' | 'business_rule' | 'compliance' | 'data_integrity',
    tenantId?: string,
    eventType?: string,
    duration?: number
  ): void {
    const labels = {
      tenant_id: tenantId || 'unknown',
      validation_type: validationType,
      event_type: eventType || 'unknown',
    };

    this.metrics.validationSuccessTotal.inc(labels);
    this.metrics.validationThroughput.inc({
      tenant_id: tenantId || 'unknown',
      status: 'success',
    });

    if (duration) {
      this.metrics.validationDuration.observe(labels, duration / 1000);
    }

    this.logger.debug('API validation success', {
      component: 'APIValidationMonitor',
      validationType,
      tenantId,
      eventType,
      durationMs: duration,
    });
  }

  /**
   * Update queue depth metric
   */
  public updateQueueDepth(tenantId: string, depth: number): void {
    this.metrics.validationQueueDepth.set({ tenant_id: tenantId }, depth);
  }

  /**
   * Track error rate for alerting
   */
  private updateErrorRateTracking(tenantId: string, validationType: string): void {
    const key = `${tenantId}:${validationType}`;
    const now = Date.now();
    const windowMs = 5 * 60 * 1000; // 5-minute window

    if (!this.errorRateWindow.has(key)) {
      this.errorRateWindow.set(key, []);
    }

    const timestamps = this.errorRateWindow.get(key)!;
    timestamps.push(now);

    // Remove timestamps outside the window
    const cutoff = now - windowMs;
    const filtered = timestamps.filter(ts => ts > cutoff);
    this.errorRateWindow.set(key, filtered);

    // Update error rate gauge
    const errorsPerMinute = (filtered.length / 5); // 5-minute window
    this.metrics.validationErrorRate.set(
      { tenant_id: tenantId, validation_type: validationType },
      errorsPerMinute
    );
  }

  /**
   * Check alerting conditions and generate alerts
   */
  private checkAlertingConditions(validationType: string, error: ValidationError): void {
    if (!this.config.alerting) return;

    const tenantId = error.tenantId || 'global';
    const key = `${tenantId}:${validationType}`;
    const errorRate = this.getCurrentErrorRate(key);

    // Rate-based alerting
    if (errorRate >= this.config.alerting.errorRateThresholds.critical) {
      this.createAlert({
        alertId: `rate_critical_${tenantId}_${validationType}_${Date.now()}`,
        type: 'rate_threshold',
        severity: 'critical',
        message: `Critical error rate detected: ${errorRate.toFixed(2)} errors/min in ${validationType} validation`,
        metadata: {
          tenantId,
          validationType,
          errorRate,
          threshold: this.config.alerting.errorRateThresholds.critical,
        },
        timestamp: new Date(),
        tenantId,
      });
    } else if (errorRate >= this.config.alerting.errorRateThresholds.warning) {
      this.createAlert({
        alertId: `rate_warning_${tenantId}_${validationType}_${Date.now()}`,
        type: 'rate_threshold', 
        severity: 'medium',
        message: `Warning error rate detected: ${errorRate.toFixed(2)} errors/min in ${validationType} validation`,
        metadata: {
          tenantId,
          validationType,
          errorRate,
          threshold: this.config.alerting.errorRateThresholds.warning,
        },
        timestamp: new Date(),
        tenantId,
      });
    }

    // Compliance-specific alerting
    if (validationType === 'compliance' && this.config.alerting.complianceAlerting.immediateAlerts.includes(error.code)) {
      this.createAlert({
        alertId: `compliance_${error.code}_${tenantId}_${Date.now()}`,
        type: 'compliance_violation',
        severity: error.severity === 'critical' ? 'critical' : 'high',
        message: `Immediate compliance violation detected: ${error.message}`,
        metadata: {
          tenantId,
          rule: error.rule,
          code: error.code,
          field: error.field,
          eventType: error.eventType,
        },
        timestamp: new Date(),
        tenantId,
      });
    }

    // Spike detection
    if (this.config.alerting.spikeDetection.enabled) {
      this.checkSpikeDetection(tenantId, validationType);
    }
  }

  /**
   * Get current error rate for a tenant/validation type
   */
  private getCurrentErrorRate(key: string): number {
    const timestamps = this.errorRateWindow.get(key) || [];
    return timestamps.length / 5; // 5-minute window = errors per minute
  }

  /**
   * Check for error spikes
   */
  private checkSpikeDetection(tenantId: string, validationType: string): void {
    const key = `${tenantId}:${validationType}`;
    const timestamps = this.errorRateWindow.get(key) || [];
    
    if (timestamps.length < this.config.alerting.spikeDetection.minimumEvents) {
      return;
    }

    // Calculate recent rate vs historical average
    const windowMs = this.config.alerting.spikeDetection.windowMinutes * 60 * 1000;
    const now = Date.now();
    const recentWindow = now - windowMs;
    const historicalWindow = now - (windowMs * 6); // 6x the recent window for baseline

    const recentErrors = timestamps.filter(ts => ts > recentWindow).length;
    const historicalErrors = timestamps.filter(ts => ts > historicalWindow && ts <= recentWindow).length;

    const recentRate = recentErrors / this.config.alerting.spikeDetection.windowMinutes;
    const historicalRate = historicalErrors / (this.config.alerting.spikeDetection.windowMinutes * 5);

    if (recentRate >= historicalRate * this.config.alerting.spikeDetection.spikeMultiplier) {
      this.createAlert({
        alertId: `spike_${tenantId}_${validationType}_${Date.now()}`,
        type: 'error_spike',
        severity: 'high',
        message: `Error spike detected: ${recentRate.toFixed(2)} errors/min (${this.config.alerting.spikeDetection.spikeMultiplier}x normal rate)`,
        metadata: {
          tenantId,
          validationType,
          recentRate,
          historicalRate,
          spikeMultiplier: this.config.alerting.spikeDetection.spikeMultiplier,
        },
        timestamp: new Date(),
        tenantId,
      });
    }
  }

  /**
   * Create and buffer alert for sending
   */
  private createAlert(alert: ValidationAlert): void {
    this.alertBuffer.push(alert);
    
    this.logger.warn('Validation alert generated', {
      component: 'APIValidationMonitor',
      alert: {
        id: alert.alertId,
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        tenantId: alert.tenantId,
      },
    });

    // Immediate delivery for critical alerts
    if (alert.severity === 'critical') {
      this.sendAlert(alert);
      this.alertBuffer = this.alertBuffer.filter(a => a.alertId !== alert.alertId);
    }

    this.emit('alert-generated', alert);
  }

  /**
   * Send alert to configured destinations
   */
  private async sendAlert(alert: ValidationAlert): Promise<void> {
    const destinations = this.config.alerting.destinations;

    try {
      // Webhook delivery
      if (destinations.webhook) {
        await this.sendWebhookAlert(destinations.webhook, alert);
      }

      // Slack delivery
      if (destinations.slack) {
        await this.sendSlackAlert(destinations.slack, alert);
      }

      // PagerDuty delivery
      if (destinations.pagerduty) {
        await this.sendPagerDutyAlert(destinations.pagerduty, alert);
      }

      // Email delivery
      if (destinations.email) {
        await this.sendEmailAlert(destinations.email, alert);
      }

      this.logger.info('Alert sent successfully', {
        component: 'APIValidationMonitor',
        alertId: alert.alertId,
        severity: alert.severity,
      });

    } catch (error) {
      this.logger.error('Failed to send alert', {
        component: 'APIValidationMonitor',
        alertId: alert.alertId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  /**
   * Send webhook alert
   */
  private async sendWebhookAlert(webhook: { url: string; headers?: Record<string, string> }, alert: ValidationAlert): Promise<void> {
    const fetch = (await import('node-fetch')).default;
    
    const response = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...webhook.headers,
      },
      body: JSON.stringify({
        alert_id: alert.alertId,
        type: alert.type,
        severity: alert.severity,
        message: alert.message,
        metadata: alert.metadata,
        timestamp: alert.timestamp,
        tenant_id: alert.tenantId,
        source: 'isectech-api-validation-monitor',
      }),
    });

    if (!response.ok) {
      throw new Error(`Webhook delivery failed: ${response.statusText}`);
    }
  }

  /**
   * Send Slack alert
   */
  private async sendSlackAlert(slack: { webhook: string; channel: string }, alert: ValidationAlert): Promise<void> {
    const fetch = (await import('node-fetch')).default;
    
    const color = alert.severity === 'critical' ? 'danger' : 
                  alert.severity === 'high' ? 'warning' : 'good';

    const response = await fetch(slack.webhook, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        channel: slack.channel,
        username: 'iSECTECH API Monitor',
        icon_emoji: ':warning:',
        attachments: [{
          color,
          title: `API Validation Alert - ${alert.severity.toUpperCase()}`,
          text: alert.message,
          fields: [
            { title: 'Alert ID', value: alert.alertId, short: true },
            { title: 'Type', value: alert.type, short: true },
            { title: 'Tenant ID', value: alert.tenantId || 'N/A', short: true },
            { title: 'Timestamp', value: alert.timestamp.toISOString(), short: true },
          ],
          footer: 'iSECTECH API Validation Monitor',
          ts: Math.floor(alert.timestamp.getTime() / 1000),
        }],
      }),
    });

    if (!response.ok) {
      throw new Error(`Slack delivery failed: ${response.statusText}`);
    }
  }

  /**
   * Send PagerDuty alert
   */
  private async sendPagerDutyAlert(pagerduty: { integrationKey: string }, alert: ValidationAlert): Promise<void> {
    const fetch = (await import('node-fetch')).default;
    
    const response = await fetch('https://events.pagerduty.com/v2/enqueue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        routing_key: pagerduty.integrationKey,
        event_action: 'trigger',
        dedup_key: `validation-${alert.type}-${alert.tenantId}`,
        payload: {
          summary: alert.message,
          severity: alert.severity,
          source: 'isectech-api-validation-monitor',
          component: 'API Validation',
          group: alert.tenantId,
          class: alert.type,
          custom_details: alert.metadata,
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`PagerDuty delivery failed: ${response.statusText}`);
    }
  }

  /**
   * Send email alert
   */
  private async sendEmailAlert(email: { recipients: string[]; smtpConfig: any }, alert: ValidationAlert): Promise<void> {
    // Email implementation would use nodemailer or similar
    // Placeholder for now
    this.logger.info('Email alert would be sent', {
      component: 'APIValidationMonitor',
      recipients: email.recipients,
      alertId: alert.alertId,
    });
  }

  /**
   * Start periodic flush of buffered alerts
   */
  private startPeriodicFlush(): void {
    setInterval(() => {
      this.flushAlerts();
    }, this.config.performance.flushIntervalMs);
  }

  /**
   * Flush buffered alerts
   */
  private flushAlerts(): void {
    if (this.alertBuffer.length === 0) return;

    const alertsToSend = this.alertBuffer.splice(0);
    
    this.logger.info('Flushing buffered alerts', {
      component: 'APIValidationMonitor',
      count: alertsToSend.length,
    });

    // Group and batch non-critical alerts
    const batchedAlerts = new Map<string, ValidationAlert[]>();
    
    for (const alert of alertsToSend) {
      if (alert.severity === 'critical') {
        // Send critical alerts immediately
        this.sendAlert(alert);
        continue;
      }

      const batchKey = `${alert.tenantId || 'global'}-${alert.type}`;
      if (!batchedAlerts.has(batchKey)) {
        batchedAlerts.set(batchKey, []);
      }
      batchedAlerts.get(batchKey)!.push(alert);
    }

    // Send batched alerts
    for (const [batchKey, alerts] of batchedAlerts) {
      this.sendBatchedAlerts(batchKey, alerts);
    }

    this.lastFlush = Date.now();
  }

  /**
   * Send batched alerts
   */
  private sendBatchedAlerts(batchKey: string, alerts: ValidationAlert[]): void {
    const batchAlert: ValidationAlert = {
      alertId: `batch_${batchKey}_${Date.now()}`,
      type: alerts[0].type,
      severity: this.calculateBatchSeverity(alerts),
      message: `Batched validation alerts: ${alerts.length} alerts of type ${alerts[0].type}`,
      metadata: {
        batchKey,
        alertCount: alerts.length,
        alerts: alerts.map(a => ({
          id: a.alertId,
          message: a.message,
          timestamp: a.timestamp,
        })),
      },
      timestamp: new Date(),
      tenantId: alerts[0].tenantId,
    };

    this.sendAlert(batchAlert);
  }

  /**
   * Calculate severity for batched alerts
   */
  private calculateBatchSeverity(alerts: ValidationAlert[]): 'low' | 'medium' | 'high' | 'critical' {
    const severities = alerts.map(a => a.severity);
    if (severities.includes('critical')) return 'critical';
    if (severities.includes('high')) return 'high';
    if (severities.includes('medium')) return 'medium';
    return 'low';
  }

  /**
   * Get metrics registry for Prometheus scraping
   */
  public getMetricsRegistry(): Registry {
    return this.registry;
  }

  /**
   * Get current metrics as text
   */
  public async getMetrics(): Promise<string> {
    return await this.registry.metrics();
  }

  /**
   * Health check method
   */
  public getHealth(): { status: 'healthy' | 'unhealthy'; details: Record<string, any> } {
    const now = Date.now();
    const timeSinceLastFlush = now - this.lastFlush;
    
    return {
      status: timeSinceLastFlush < this.config.performance.flushIntervalMs * 2 ? 'healthy' : 'unhealthy',
      details: {
        bufferedAlerts: this.alertBuffer.length,
        errorRateWindows: this.errorRateWindow.size,
        timeSinceLastFlush: timeSinceLastFlush,
        metricsEnabled: this.config.metrics.enabled,
        alertingEnabled: !!this.config.alerting,
      },
    };
  }

  /**
   * Graceful shutdown
   */
  public async shutdown(): Promise<void> {
    this.logger.info('Shutting down API validation monitor');
    
    // Flush any remaining alerts
    this.flushAlerts();
    
    // Clear intervals and cleanup
    this.removeAllListeners();
    this.errorRateWindow.clear();
    this.alertBuffer.length = 0;
    
    this.logger.info('API validation monitor shutdown complete');
  }
}

/**
 * Factory function to create APIValidationMonitor with default configuration
 */
export function createAPIValidationMonitor(
  logger: Logger,
  overrides: Partial<MonitoringConfig> = {}
): APIValidationMonitor {
  const defaultConfig: MonitoringConfig = {
    logging: {
      level: 'info',
      structured: true,
      includeStackTrace: false,
      rotateFiles: true,
    },
    metrics: {
      enabled: true,
      port: 9090,
      path: '/metrics',
      defaultLabels: {
        service: 'api-validation',
        environment: process.env.NODE_ENV || 'development',
      },
    },
    alerting: {
      errorRateThresholds: {
        warning: 5.0,  // 5 errors per minute
        critical: 15.0, // 15 errors per minute
      },
      spikeDetection: {
        enabled: true,
        windowMinutes: 5,
        spikeMultiplier: 3,
        minimumEvents: 10,
      },
      complianceAlerting: {
        immediateAlerts: ['GDPR_VIOLATION', 'HIPAA_PHI_DETECTED', 'PCI_DSS_CARDHOLDER_DATA_DETECTED'],
        batchingEnabled: true,
        batchIntervalMinutes: 15,
      },
      destinations: {
        // Configure based on environment
      },
    },
    performance: {
      bufferSize: 1000,
      flushIntervalMs: 30000, // 30 seconds
      enableSampling: false,
      samplingRate: 1.0,
    },
  };

  const config = { ...defaultConfig, ...overrides };
  return new APIValidationMonitor(logger, config);
}

export { ValidationError, ValidationAlert, MonitoringConfig, AlertingConfig };