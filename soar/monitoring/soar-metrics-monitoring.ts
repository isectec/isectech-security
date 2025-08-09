/**
 * iSECTECH SOAR Metrics, Reporting, and Monitoring System
 * 
 * Comprehensive monitoring and analytics platform for SOAR operations with
 * real-time dashboards, performance metrics, compliance reporting, and
 * intelligent alerting for security operations centers.
 * 
 * Features:
 * - Real-time metrics collection from all SOAR components
 * - Custom dashboards for SOC teams and management
 * - Automated reporting with customizable schedules
 * - Performance analytics and trend analysis
 * - Health monitoring and alerting
 * - Compliance tracking and audit reporting
 * - Business intelligence and KPI tracking
 */

import { z } from 'zod';
import { EventEmitter } from 'events';

// Core Monitoring Schemas
const MetricTypeSchema = z.enum(['counter', 'gauge', 'histogram', 'summary', 'timer']);
const AlertSeveritySchema = z.enum(['info', 'warning', 'critical', 'emergency']);
const ReportTypeSchema = z.enum(['operational', 'compliance', 'performance', 'security', 'executive', 'custom']);
const DashboardTypeSchema = z.enum(['soc_overview', 'case_management', 'incident_response', 'threat_intelligence', 'compliance', 'executive']);

const ISECTECHMetricSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: MetricTypeSchema,
  value: z.number(),
  unit: z.string().optional(),
  tags: z.record(z.string()),
  timestamp: z.date(),
  source: z.string(),
  description: z.string().optional(),
  metadata: z.record(z.any()).optional()
});

const ISECTECHAlertSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string(),
  severity: AlertSeveritySchema,
  status: z.enum(['active', 'acknowledged', 'resolved', 'suppressed']),
  
  // Triggering conditions
  metricName: z.string(),
  threshold: z.number(),
  condition: z.enum(['greater_than', 'less_than', 'equals', 'not_equals', 'contains']),
  evaluationWindow: z.number(), // minutes
  
  // Alert details
  triggeredAt: z.date().optional(),
  acknowledgedAt: z.date().optional(),
  acknowledgedBy: z.string().optional(),
  resolvedAt: z.date().optional(),
  resolvedBy: z.string().optional(),
  
  // Notification settings
  notificationChannels: z.array(z.string()),
  escalationRules: z.array(z.object({
    level: z.number(),
    delayMinutes: z.number(),
    recipients: z.array(z.string())
  })),
  
  // Suppression settings
  suppressionRules: z.array(z.object({
    condition: z.string(),
    duration: z.number(), // minutes
    reason: z.string()
  })),
  
  // History
  triggerHistory: z.array(z.object({
    triggeredAt: z.date(),
    value: z.number(),
    resolvedAt: z.date().optional(),
    duration: z.number().optional() // minutes
  })),
  
  isActive: z.boolean().default(true),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHDashboardSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: DashboardTypeSchema,
  description: z.string(),
  
  // Layout and widgets
  layout: z.object({
    rows: z.number(),
    columns: z.number()
  }),
  widgets: z.array(z.object({
    id: z.string(),
    type: z.enum(['metric_chart', 'alert_list', 'case_overview', 'threat_map', 'kpi_card', 'log_viewer']),
    title: z.string(),
    position: z.object({
      x: z.number(),
      y: z.number(),
      width: z.number(),
      height: z.number()
    }),
    config: z.record(z.any()),
    dataSource: z.string(),
    refreshInterval: z.number().optional() // seconds
  })),
  
  // Access control
  permissions: z.object({
    viewUsers: z.array(z.string()),
    editUsers: z.array(z.string()),
    isPublic: z.boolean().default(false)
  }),
  
  // Settings
  autoRefresh: z.boolean().default(true),
  refreshInterval: z.number().default(30), // seconds
  timeRange: z.object({
    start: z.string(), // relative time like "-1h" or absolute timestamp
    end: z.string()
  }),
  
  // Metadata
  tags: z.array(z.string()),
  category: z.string().optional(),
  
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date()
});

const ISECTECHReportSchema = z.object({
  id: z.string(),
  name: z.string(),
  type: ReportTypeSchema,
  description: z.string(),
  
  // Report configuration
  template: z.string(),
  parameters: z.record(z.any()),
  dataSource: z.array(z.string()),
  
  // Scheduling
  schedule: z.object({
    enabled: z.boolean(),
    frequency: z.enum(['hourly', 'daily', 'weekly', 'monthly', 'quarterly', 'yearly']),
    time: z.string(), // HH:MM format
    dayOfWeek: z.number().optional(), // 0-6, Sunday = 0
    dayOfMonth: z.number().optional(), // 1-31
    timezone: z.string().default('UTC')
  }),
  
  // Distribution
  recipients: z.array(z.object({
    email: z.string(),
    role: z.string(),
    deliveryMethod: z.enum(['email', 'slack', 'teams', 'webhook'])
  })),
  
  // Report content
  sections: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(['summary', 'metrics', 'charts', 'tables', 'narrative']),
    config: z.record(z.any()),
    order: z.number()
  })),
  
  // Generation history
  executions: z.array(z.object({
    id: z.string(),
    startedAt: z.date(),
    completedAt: z.date().optional(),
    status: z.enum(['running', 'completed', 'failed', 'cancelled']),
    fileUrl: z.string().optional(),
    error: z.string().optional(),
    metrics: z.object({
      processingTime: z.number(),
      dataPoints: z.number(),
      fileSize: z.number().optional()
    }).optional()
  })),
  
  // Settings
  format: z.enum(['pdf', 'html', 'csv', 'json', 'xlsx']),
  retentionDays: z.number().default(90),
  isActive: z.boolean().default(true),
  
  createdBy: z.string(),
  createdAt: z.date(),
  updatedAt: z.date()
});

type ISECTECHMetric = z.infer<typeof ISECTECHMetricSchema>;
type ISECTECHAlert = z.infer<typeof ISECTECHAlertSchema>;
type ISECTECHDashboard = z.infer<typeof ISECTECHDashboardSchema>;
type ISECTECHReport = z.infer<typeof ISECTECHReportSchema>;

interface SOARMetricsConfig {
  retentionDays: number;
  aggregationIntervals: number[]; // minutes
  enableRealTimeUpdates: boolean;
  maxMetricsPerBatch: number;
  alertEvaluationInterval: number; // seconds
  dashboardRefreshInterval: number; // seconds
  reportGenerationTimeout: number; // minutes
  enableAnomalyDetection: boolean;
  complianceStandards: string[];
}

interface HealthCheckResult {
  component: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  responseTime: number;
  lastCheck: Date;
  details: any;
  uptime: number;
}

export class ISECTECHSOARMetricsMonitoring extends EventEmitter {
  private metrics = new Map<string, ISECTECHMetric[]>();
  private alerts = new Map<string, ISECTECHAlert>();
  private dashboards = new Map<string, ISECTECHDashboard>();
  private reports = new Map<string, ISECTECHReport>();
  private config: SOARMetricsConfig;
  
  // Health monitoring
  private healthChecks = new Map<string, HealthCheckResult>();
  private componentStatus = new Map<string, any>();
  
  // Performance tracking
  private performanceMetrics = new Map<string, any>();
  private anomalyDetector = new Map<string, any>();
  
  // Alerting system
  private alertQueue = new Array<any>();
  private alertEvaluationTimer: NodeJS.Timeout | null = null;
  
  // Reporting system
  private reportQueue = new Array<any>();
  private scheduledReports = new Map<string, NodeJS.Timeout>();
  
  // Circuit breakers and rate limiting
  private circuitBreaker = {
    isOpen: false,
    failureCount: 0,
    lastFailureTime: 0,
    resetTimeout: 60000
  };

  constructor(config: SOARMetricsConfig) {
    super();
    this.config = config;
    this.initializeDefaultDashboards();
    this.initializeDefaultAlerts();
    this.initializeDefaultReports();
    this.startMetricsCollection();
    this.startAlertEvaluation();
    this.startHealthMonitoring();
  }

  // Metrics Collection
  async recordMetric(metric: Partial<ISECTECHMetric>): Promise<void> {
    try {
      const metricId = `${metric.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const fullMetric: ISECTECHMetric = {
        id: metricId,
        name: metric.name || 'unnamed_metric',
        type: metric.type || 'gauge',
        value: metric.value || 0,
        unit: metric.unit,
        tags: metric.tags || {},
        timestamp: metric.timestamp || new Date(),
        source: metric.source || 'unknown',
        description: metric.description,
        metadata: metric.metadata
      };

      const metricsArray = this.metrics.get(fullMetric.name) || [];
      metricsArray.push(fullMetric);
      
      // Keep only recent metrics based on retention policy
      const cutoffTime = new Date(Date.now() - (this.config.retentionDays * 24 * 60 * 60 * 1000));
      const filteredMetrics = metricsArray.filter(m => m.timestamp >= cutoffTime);
      
      this.metrics.set(fullMetric.name, filteredMetrics);

      // Emit event for real-time updates
      if (this.config.enableRealTimeUpdates) {
        this.emit('metricRecorded', fullMetric);
      }

      // Check if metric triggers any alerts
      await this.evaluateAlertsForMetric(fullMetric);

    } catch (error) {
      this.handleError('recordMetric', error as Error);
      throw error;
    }
  }

  async recordBatchMetrics(metrics: Partial<ISECTECHMetric>[]): Promise<void> {
    try {
      if (metrics.length > this.config.maxMetricsPerBatch) {
        throw new Error(`Batch size ${metrics.length} exceeds maximum ${this.config.maxMetricsPerBatch}`);
      }

      const promises = metrics.map(metric => this.recordMetric(metric));
      await Promise.all(promises);

      this.emit('batchMetricsRecorded', { count: metrics.length });

    } catch (error) {
      this.handleError('recordBatchMetrics', error as Error);
      throw error;
    }
  }

  // SOAR-specific metrics
  async recordSOARMetrics(): Promise<void> {
    try {
      const timestamp = new Date();
      
      // Case management metrics
      await this.recordMetric({
        name: 'soar.cases.total',
        type: 'gauge',
        value: this.getCaseCount(),
        tags: { component: 'case_management' },
        timestamp,
        source: 'case_manager'
      });

      await this.recordMetric({
        name: 'soar.cases.open',
        type: 'gauge',
        value: this.getOpenCaseCount(),
        tags: { component: 'case_management' },
        timestamp,
        source: 'case_manager'
      });

      await this.recordMetric({
        name: 'soar.cases.average_resolution_time',
        type: 'gauge',
        value: this.getAverageResolutionTime(),
        unit: 'minutes',
        tags: { component: 'case_management' },
        timestamp,
        source: 'case_manager'
      });

      // Playbook execution metrics
      await this.recordMetric({
        name: 'soar.playbooks.executions',
        type: 'counter',
        value: this.getPlaybookExecutionCount(),
        tags: { component: 'playbook_engine' },
        timestamp,
        source: 'playbook_engine'
      });

      await this.recordMetric({
        name: 'soar.playbooks.success_rate',
        type: 'gauge',
        value: this.getPlaybookSuccessRate(),
        unit: 'percentage',
        tags: { component: 'playbook_engine' },
        timestamp,
        source: 'playbook_engine'
      });

      // Integration metrics
      await this.recordMetric({
        name: 'soar.integrations.active',
        type: 'gauge',
        value: this.getActiveIntegrationCount(),
        tags: { component: 'integration_framework' },
        timestamp,
        source: 'integration_manager'
      });

      await this.recordMetric({
        name: 'soar.integrations.api_calls',
        type: 'counter',
        value: this.getIntegrationAPICallCount(),
        tags: { component: 'integration_framework' },
        timestamp,
        source: 'integration_manager'
      });

      // Threat intelligence metrics
      await this.recordMetric({
        name: 'soar.threats.detected',
        type: 'counter',
        value: this.getThreatDetectionCount(),
        tags: { component: 'threat_intelligence' },
        timestamp,
        source: 'threat_detector'
      });

      await this.recordMetric({
        name: 'soar.threats.mitigated',
        type: 'counter',
        value: this.getThreatMitigationCount(),
        tags: { component: 'threat_intelligence' },
        timestamp,
        source: 'threat_detector'
      });

    } catch (error) {
      this.handleError('recordSOARMetrics', error as Error);
    }
  }

  // Alert Management
  async createAlert(alertData: Partial<ISECTECHAlert>): Promise<ISECTECHAlert> {
    try {
      const alertId = `ALERT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const alert: ISECTECHAlert = {
        id: alertId,
        name: alertData.name || 'Unnamed Alert',
        description: alertData.description || 'No description provided',
        severity: alertData.severity || 'warning',
        status: 'active',
        
        metricName: alertData.metricName || '',
        threshold: alertData.threshold || 0,
        condition: alertData.condition || 'greater_than',
        evaluationWindow: alertData.evaluationWindow || 5,
        
        notificationChannels: alertData.notificationChannels || [],
        escalationRules: alertData.escalationRules || [],
        suppressionRules: alertData.suppressionRules || [],
        
        triggerHistory: [],
        
        isActive: alertData.isActive !== false,
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.alerts.set(alertId, alert);
      this.emit('alertCreated', alert);
      
      return alert;

    } catch (error) {
      this.handleError('createAlert', error as Error);
      throw error;
    }
  }

  async acknowledgeAlert(alertId: string, userId: string): Promise<void> {
    try {
      const alert = this.alerts.get(alertId);
      if (!alert) {
        throw new Error(`Alert ${alertId} not found`);
      }

      alert.status = 'acknowledged';
      alert.acknowledgedAt = new Date();
      alert.acknowledgedBy = userId;
      alert.updatedAt = new Date();

      this.emit('alertAcknowledged', { alert, userId });

    } catch (error) {
      this.handleError('acknowledgeAlert', error as Error);
      throw error;
    }
  }

  async resolveAlert(alertId: string, userId: string): Promise<void> {
    try {
      const alert = this.alerts.get(alertId);
      if (!alert) {
        throw new Error(`Alert ${alertId} not found`);
      }

      alert.status = 'resolved';
      alert.resolvedAt = new Date();
      alert.resolvedBy = userId;
      alert.updatedAt = new Date();

      this.emit('alertResolved', { alert, userId });

    } catch (error) {
      this.handleError('resolveAlert', error as Error);
      throw error;
    }
  }

  // Dashboard Management
  async createDashboard(dashboardData: Partial<ISECTECHDashboard>): Promise<ISECTECHDashboard> {
    try {
      const dashboardId = `DASHBOARD-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const dashboard: ISECTECHDashboard = {
        id: dashboardId,
        name: dashboardData.name || 'Unnamed Dashboard',
        type: dashboardData.type || 'soc_overview',
        description: dashboardData.description || 'No description provided',
        
        layout: dashboardData.layout || { rows: 4, columns: 6 },
        widgets: dashboardData.widgets || [],
        
        permissions: dashboardData.permissions || {
          viewUsers: [],
          editUsers: [],
          isPublic: false
        },
        
        autoRefresh: dashboardData.autoRefresh !== false,
        refreshInterval: dashboardData.refreshInterval || this.config.dashboardRefreshInterval,
        timeRange: dashboardData.timeRange || {
          start: '-1h',
          end: 'now'
        },
        
        tags: dashboardData.tags || [],
        category: dashboardData.category,
        
        createdBy: dashboardData.createdBy || 'system',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.dashboards.set(dashboardId, dashboard);
      this.emit('dashboardCreated', dashboard);
      
      return dashboard;

    } catch (error) {
      this.handleError('createDashboard', error as Error);
      throw error;
    }
  }

  async getDashboardData(dashboardId: string, timeRange?: { start: string; end: string }): Promise<any> {
    try {
      const dashboard = this.dashboards.get(dashboardId);
      if (!dashboard) {
        throw new Error(`Dashboard ${dashboardId} not found`);
      }

      const data: any = {
        dashboard,
        widgets: {},
        lastUpdated: new Date()
      };

      // Generate data for each widget
      for (const widget of dashboard.widgets) {
        data.widgets[widget.id] = await this.generateWidgetData(widget, timeRange || dashboard.timeRange);
      }

      return data;

    } catch (error) {
      this.handleError('getDashboardData', error as Error);
      throw error;
    }
  }

  // Report Management
  async createReport(reportData: Partial<ISECTECHReport>): Promise<ISECTECHReport> {
    try {
      const reportId = `REPORT-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      const report: ISECTECHReport = {
        id: reportId,
        name: reportData.name || 'Unnamed Report',
        type: reportData.type || 'operational',
        description: reportData.description || 'No description provided',
        
        template: reportData.template || 'default',
        parameters: reportData.parameters || {},
        dataSource: reportData.dataSource || [],
        
        schedule: reportData.schedule || {
          enabled: false,
          frequency: 'daily',
          time: '08:00',
          timezone: 'UTC'
        },
        
        recipients: reportData.recipients || [],
        sections: reportData.sections || [],
        executions: [],
        
        format: reportData.format || 'pdf',
        retentionDays: reportData.retentionDays || 90,
        isActive: reportData.isActive !== false,
        
        createdBy: reportData.createdBy || 'system',
        createdAt: new Date(),
        updatedAt: new Date()
      };

      this.reports.set(reportId, report);
      
      // Schedule if enabled
      if (report.schedule.enabled) {
        this.scheduleReport(report);
      }

      this.emit('reportCreated', report);
      return report;

    } catch (error) {
      this.handleError('createReport', error as Error);
      throw error;
    }
  }

  async generateReport(reportId: string, parameters?: any): Promise<string> {
    try {
      const report = this.reports.get(reportId);
      if (!report) {
        throw new Error(`Report ${reportId} not found`);
      }

      const executionId = `EXEC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const execution = {
        id: executionId,
        startedAt: new Date(),
        status: 'running' as const,
        metrics: {
          processingTime: 0,
          dataPoints: 0
        }
      };

      report.executions.push(execution);

      try {
        const startTime = Date.now();
        const reportData = await this.generateReportData(report, parameters);
        const fileUrl = await this.renderReport(report, reportData);
        
        execution.completedAt = new Date();
        execution.status = 'completed';
        execution.fileUrl = fileUrl;
        execution.metrics = {
          processingTime: Date.now() - startTime,
          dataPoints: reportData.totalDataPoints || 0,
          fileSize: reportData.fileSize || 0
        };

        this.emit('reportGenerated', { report, execution });
        return fileUrl;

      } catch (error) {
        execution.status = 'failed';
        execution.error = (error as Error).message;
        throw error;
      }

    } catch (error) {
      this.handleError('generateReport', error as Error);
      throw error;
    }
  }

  // Health Monitoring
  async performHealthCheck(component: string): Promise<HealthCheckResult> {
    try {
      const startTime = Date.now();
      let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
      let details: any = {};

      switch (component) {
        case 'case_management':
          details = await this.checkCaseManagementHealth();
          break;
        case 'playbook_engine':
          details = await this.checkPlaybookEngineHealth();
          break;
        case 'integration_framework':
          details = await this.checkIntegrationFrameworkHealth();
          break;
        case 'threat_intelligence':
          details = await this.checkThreatIntelligenceHealth();
          break;
        default:
          details = { error: 'Unknown component' };
          status = 'unhealthy';
      }

      // Determine status based on details
      if (details.error || details.failureRate > 0.1) {
        status = 'unhealthy';
      } else if (details.responseTime > 5000 || details.warnings?.length > 0) {
        status = 'degraded';
      }

      const responseTime = Date.now() - startTime;
      const result: HealthCheckResult = {
        component,
        status,
        responseTime,
        lastCheck: new Date(),
        details,
        uptime: details.uptime || this.calculateUptime(component)
      };

      this.healthChecks.set(component, result);
      this.emit('healthCheckCompleted', result);

      return result;

    } catch (error) {
      const result: HealthCheckResult = {
        component,
        status: 'unhealthy',
        responseTime: 0,
        lastCheck: new Date(),
        details: { error: (error as Error).message },
        uptime: 0
      };

      this.healthChecks.set(component, result);
      this.handleError('performHealthCheck', error as Error);
      
      return result;
    }
  }

  async getSystemOverview(): Promise<any> {
    const components = ['case_management', 'playbook_engine', 'integration_framework', 'threat_intelligence'];
    const healthChecks = await Promise.all(
      components.map(component => this.performHealthCheck(component))
    );

    const overallStatus = healthChecks.every(hc => hc.status === 'healthy') ? 'healthy' :
                         healthChecks.some(hc => hc.status === 'unhealthy') ? 'unhealthy' : 'degraded';

    return {
      overallStatus,
      components: healthChecks,
      metrics: {
        totalMetrics: Array.from(this.metrics.values()).reduce((sum, arr) => sum + arr.length, 0),
        activeAlerts: Array.from(this.alerts.values()).filter(a => a.status === 'active').length,
        totalDashboards: this.dashboards.size,
        scheduledReports: this.scheduledReports.size
      },
      uptime: this.calculateSystemUptime(),
      lastUpdated: new Date()
    };
  }

  // Private helper methods
  private initializeDefaultDashboards(): void {
    const defaultDashboards = [
      {
        name: 'SOC Overview Dashboard',
        type: 'soc_overview' as const,
        description: 'Main dashboard for SOC team with key metrics and alerts',
        layout: { rows: 6, columns: 8 },
        widgets: [
          {
            id: 'cases-overview',
            type: 'kpi_card' as const,
            title: 'Open Cases',
            position: { x: 0, y: 0, width: 2, height: 2 },
            config: { metric: 'soar.cases.open', color: 'blue' },
            dataSource: 'metrics',
            refreshInterval: 30
          },
          {
            id: 'threat-map',
            type: 'threat_map' as const,
            title: 'Threat Intelligence Map',
            position: { x: 2, y: 0, width: 4, height: 3 },
            config: { showDetails: true, timeRange: '-24h' },
            dataSource: 'threat_intelligence'
          },
          {
            id: 'active-alerts',
            type: 'alert_list' as const,
            title: 'Active Alerts',
            position: { x: 6, y: 0, width: 2, height: 4 },
            config: { maxItems: 10, severityFilter: ['critical', 'warning'] },
            dataSource: 'alerts'
          },
          {
            id: 'case-resolution-chart',
            type: 'metric_chart' as const,
            title: 'Case Resolution Trends',
            position: { x: 0, y: 2, width: 6, height: 2 },
            config: { 
              metrics: ['soar.cases.resolved', 'soar.cases.average_resolution_time'],
              chartType: 'line',
              timeRange: '-7d'
            },
            dataSource: 'metrics'
          }
        ],
        permissions: { viewUsers: ['soc_team'], editUsers: ['soc_admin'], isPublic: true },
        tags: ['soc', 'overview', 'default']
      },
      {
        name: 'Executive Dashboard',
        type: 'executive' as const,
        description: 'High-level view for executives and management',
        layout: { rows: 4, columns: 6 },
        widgets: [
          {
            id: 'security-posture',
            type: 'kpi_card' as const,
            title: 'Security Posture Score',
            position: { x: 0, y: 0, width: 2, height: 2 },
            config: { metric: 'soar.security.posture_score', color: 'green' },
            dataSource: 'metrics'
          },
          {
            id: 'incident-trends',
            type: 'metric_chart' as const,
            title: 'Incident Trends (Monthly)',
            position: { x: 2, y: 0, width: 4, height: 2 },
            config: { 
              metrics: ['soar.incidents.total', 'soar.incidents.resolved'],
              chartType: 'bar',
              timeRange: '-3M',
              aggregation: 'monthly'
            },
            dataSource: 'metrics'
          }
        ],
        permissions: { viewUsers: ['executives'], editUsers: ['admin'], isPublic: false },
        tags: ['executive', 'management', 'kpi']
      }
    ];

    defaultDashboards.forEach(async dashboard => {
      await this.createDashboard(dashboard);
    });
  }

  private initializeDefaultAlerts(): void {
    const defaultAlerts = [
      {
        name: 'High Case Volume Alert',
        description: 'Triggered when open cases exceed threshold',
        severity: 'warning' as const,
        metricName: 'soar.cases.open',
        threshold: 50,
        condition: 'greater_than' as const,
        evaluationWindow: 5,
        notificationChannels: ['slack-soc', 'email-soc-manager'],
        escalationRules: [
          { level: 1, delayMinutes: 15, recipients: ['soc-manager@isectech.com'] },
          { level: 2, delayMinutes: 30, recipients: ['ciso@isectech.com'] }
        ]
      },
      {
        name: 'Critical Threat Detection',
        description: 'Immediate alert for critical threats detected',
        severity: 'critical' as const,
        metricName: 'soar.threats.critical',
        threshold: 1,
        condition: 'greater_than' as const,
        evaluationWindow: 1,
        notificationChannels: ['pagerduty', 'slack-incident', 'sms-oncall'],
        escalationRules: [
          { level: 1, delayMinutes: 0, recipients: ['incident-commander@isectech.com'] }
        ]
      },
      {
        name: 'Integration Health Alert',
        description: 'Alert when critical integrations are failing',
        severity: 'warning' as const,
        metricName: 'soar.integrations.failure_rate',
        threshold: 0.1,
        condition: 'greater_than' as const,
        evaluationWindow: 10,
        notificationChannels: ['slack-engineering'],
        suppressionRules: [
          { condition: 'maintenance_window_active', duration: 60, reason: 'Planned maintenance' }
        ]
      }
    ];

    defaultAlerts.forEach(async alert => {
      await this.createAlert(alert);
    });
  }

  private initializeDefaultReports(): void {
    const defaultReports = [
      {
        name: 'Daily SOC Operations Report',
        type: 'operational' as const,
        description: 'Daily summary of SOC activities and metrics',
        template: 'daily_operations',
        schedule: {
          enabled: true,
          frequency: 'daily' as const,
          time: '09:00',
          timezone: 'America/New_York'
        },
        recipients: [
          { email: 'soc-team@isectech.com', role: 'soc_analyst', deliveryMethod: 'email' as const },
          { email: 'soc-manager@isectech.com', role: 'soc_manager', deliveryMethod: 'email' as const }
        ],
        sections: [
          { id: 'summary', name: 'Executive Summary', type: 'summary' as const, config: {}, order: 1 },
          { id: 'metrics', name: 'Key Metrics', type: 'metrics' as const, config: { timeRange: '-24h' }, order: 2 },
          { id: 'incidents', name: 'Incident Summary', type: 'tables' as const, config: { source: 'cases' }, order: 3 },
          { id: 'alerts', name: 'Alert Activity', type: 'charts' as const, config: { chartType: 'timeline' }, order: 4 }
        ]
      },
      {
        name: 'Monthly Security Report',
        type: 'executive' as const,
        description: 'Monthly security posture and trend analysis',
        template: 'monthly_security',
        schedule: {
          enabled: true,
          frequency: 'monthly' as const,
          time: '08:00',
          dayOfMonth: 1,
          timezone: 'UTC'
        },
        recipients: [
          { email: 'ciso@isectech.com', role: 'ciso', deliveryMethod: 'email' as const },
          { email: 'executives@isectech.com', role: 'executive', deliveryMethod: 'email' as const }
        ]
      }
    ];

    defaultReports.forEach(async report => {
      await this.createReport(report);
    });
  }

  private startMetricsCollection(): void {
    setInterval(async () => {
      try {
        await this.recordSOARMetrics();
      } catch (error) {
        this.handleError('metricsCollection', error as Error);
      }
    }, 60000); // Every minute
  }

  private startAlertEvaluation(): void {
    this.alertEvaluationTimer = setInterval(async () => {
      try {
        for (const alert of this.alerts.values()) {
          if (alert.isActive && alert.status === 'active') {
            await this.evaluateAlert(alert);
          }
        }
      } catch (error) {
        this.handleError('alertEvaluation', error as Error);
      }
    }, this.config.alertEvaluationInterval * 1000);
  }

  private startHealthMonitoring(): void {
    const components = ['case_management', 'playbook_engine', 'integration_framework', 'threat_intelligence'];
    
    setInterval(async () => {
      try {
        await Promise.all(components.map(component => this.performHealthCheck(component)));
      } catch (error) {
        this.handleError('healthMonitoring', error as Error);
      }
    }, 300000); // Every 5 minutes
  }

  private async evaluateAlertsForMetric(metric: ISECTECHMetric): Promise<void> {
    for (const alert of this.alerts.values()) {
      if (alert.metricName === metric.name && alert.isActive) {
        await this.evaluateAlert(alert, metric);
      }
    }
  }

  private async evaluateAlert(alert: ISECTECHAlert, triggeringMetric?: ISECTECHMetric): Promise<void> {
    try {
      const metrics = this.metrics.get(alert.metricName) || [];
      const windowStart = new Date(Date.now() - (alert.evaluationWindow * 60 * 1000));
      const recentMetrics = metrics.filter(m => m.timestamp >= windowStart);

      if (recentMetrics.length === 0) return;

      const latestMetric = triggeringMetric || recentMetrics[recentMetrics.length - 1];
      let shouldTrigger = false;

      switch (alert.condition) {
        case 'greater_than':
          shouldTrigger = latestMetric.value > alert.threshold;
          break;
        case 'less_than':
          shouldTrigger = latestMetric.value < alert.threshold;
          break;
        case 'equals':
          shouldTrigger = latestMetric.value === alert.threshold;
          break;
        case 'not_equals':
          shouldTrigger = latestMetric.value !== alert.threshold;
          break;
      }

      if (shouldTrigger && alert.status === 'active') {
        await this.triggerAlert(alert, latestMetric);
      }

    } catch (error) {
      this.handleError('evaluateAlert', error as Error);
    }
  }

  private async triggerAlert(alert: ISECTECHAlert, metric: ISECTECHMetric): Promise<void> {
    const trigger = {
      triggeredAt: new Date(),
      value: metric.value,
      resolvedAt: undefined,
      duration: undefined
    };

    alert.triggerHistory.push(trigger);
    alert.triggeredAt = trigger.triggeredAt;

    // Send notifications
    for (const channel of alert.notificationChannels) {
      await this.sendNotification(channel, alert, metric);
    }

    this.emit('alertTriggered', { alert, metric });
  }

  private async sendNotification(channel: string, alert: ISECTECHAlert, metric: ISECTECHMetric): Promise<void> {
    // Implementation would integrate with actual notification services
    console.log(`[NOTIFICATION] ${channel}: ${alert.name} - ${alert.description} (Value: ${metric.value})`);
  }

  private async generateWidgetData(widget: any, timeRange: any): Promise<any> {
    switch (widget.type) {
      case 'kpi_card':
        return this.generateKPIData(widget.config);
      case 'metric_chart':
        return this.generateChartData(widget.config, timeRange);
      case 'alert_list':
        return this.generateAlertData(widget.config);
      case 'threat_map':
        return this.generateThreatMapData(widget.config);
      default:
        return { error: 'Unknown widget type' };
    }
  }

  private async generateKPIData(config: any): Promise<any> {
    const metrics = this.metrics.get(config.metric) || [];
    const latestMetric = metrics[metrics.length - 1];
    
    return {
      value: latestMetric?.value || 0,
      unit: latestMetric?.unit,
      trend: this.calculateTrend(metrics),
      lastUpdated: latestMetric?.timestamp || new Date()
    };
  }

  private async generateChartData(config: any, timeRange: any): Promise<any> {
    const data: any = {
      series: [],
      timeRange,
      lastUpdated: new Date()
    };

    for (const metricName of config.metrics) {
      const metrics = this.metrics.get(metricName) || [];
      const filteredMetrics = this.filterMetricsByTimeRange(metrics, timeRange);
      
      data.series.push({
        name: metricName,
        data: filteredMetrics.map(m => ({ x: m.timestamp, y: m.value }))
      });
    }

    return data;
  }

  private async generateAlertData(config: any): Promise<any> {
    const alerts = Array.from(this.alerts.values())
      .filter(a => a.status === 'active')
      .filter(a => !config.severityFilter || config.severityFilter.includes(a.severity))
      .sort((a, b) => (b.triggeredAt?.getTime() || 0) - (a.triggeredAt?.getTime() || 0))
      .slice(0, config.maxItems || 10);

    return {
      alerts,
      total: alerts.length,
      lastUpdated: new Date()
    };
  }

  private async generateThreatMapData(config: any): Promise<any> {
    // Mock threat intelligence data
    return {
      threats: [
        { id: '1', type: 'malware', severity: 'high', location: 'US', count: 15 },
        { id: '2', type: 'phishing', severity: 'medium', location: 'EU', count: 8 },
        { id: '3', type: 'ddos', severity: 'critical', location: 'APAC', count: 3 }
      ],
      lastUpdated: new Date()
    };
  }

  private calculateTrend(metrics: ISECTECHMetric[]): string {
    if (metrics.length < 2) return 'stable';
    
    const recent = metrics.slice(-5);
    const avg = recent.reduce((sum, m) => sum + m.value, 0) / recent.length;
    const previous = metrics.slice(-10, -5);
    const prevAvg = previous.reduce((sum, m) => sum + m.value, 0) / previous.length;
    
    if (avg > prevAvg * 1.1) return 'increasing';
    if (avg < prevAvg * 0.9) return 'decreasing';
    return 'stable';
  }

  private filterMetricsByTimeRange(metrics: ISECTECHMetric[], timeRange: any): ISECTECHMetric[] {
    const now = new Date();
    let startTime: Date;
    
    if (timeRange.start.startsWith('-')) {
      const duration = timeRange.start.substring(1);
      const hours = duration.includes('h') ? parseInt(duration) : 
                   duration.includes('d') ? parseInt(duration) * 24 : 1;
      startTime = new Date(now.getTime() - (hours * 60 * 60 * 1000));
    } else {
      startTime = new Date(timeRange.start);
    }
    
    return metrics.filter(m => m.timestamp >= startTime);
  }

  private scheduleReport(report: ISECTECHReport): void {
    // Implementation would use a proper job scheduler
    // For now, simplified scheduling
    const intervalMs = this.getScheduleInterval(report.schedule.frequency);
    
    const timer = setInterval(async () => {
      try {
        await this.generateReport(report.id);
      } catch (error) {
        this.handleError('scheduledReport', error as Error);
      }
    }, intervalMs);
    
    this.scheduledReports.set(report.id, timer);
  }

  private getScheduleInterval(frequency: string): number {
    switch (frequency) {
      case 'hourly': return 60 * 60 * 1000;
      case 'daily': return 24 * 60 * 60 * 1000;
      case 'weekly': return 7 * 24 * 60 * 60 * 1000;
      case 'monthly': return 30 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }

  private async generateReportData(report: ISECTECHReport, parameters?: any): Promise<any> {
    // Mock report data generation
    return {
      reportId: report.id,
      generatedAt: new Date(),
      totalDataPoints: 1000,
      sections: report.sections.map(section => ({
        ...section,
        data: this.generateSectionData(section)
      }))
    };
  }

  private generateSectionData(section: any): any {
    switch (section.type) {
      case 'summary':
        return { summary: 'This is a summary section' };
      case 'metrics':
        return { metrics: [{ name: 'test', value: 100 }] };
      case 'charts':
        return { charts: [{ type: 'line', data: [] }] };
      default:
        return {};
    }
  }

  private async renderReport(report: ISECTECHReport, data: any): Promise<string> {
    // Mock report rendering
    const fileUrl = `/reports/${report.id}-${Date.now()}.${report.format}`;
    return fileUrl;
  }

  // Health check implementations
  private async checkCaseManagementHealth(): Promise<any> {
    return {
      status: 'healthy',
      responseTime: Math.random() * 100,
      activeCases: this.getCaseCount(),
      failureRate: 0
    };
  }

  private async checkPlaybookEngineHealth(): Promise<any> {
    return {
      status: 'healthy',
      responseTime: Math.random() * 200,
      activePlaybooks: 5,
      successRate: 0.95
    };
  }

  private async checkIntegrationFrameworkHealth(): Promise<any> {
    return {
      status: 'healthy',
      responseTime: Math.random() * 150,
      activeConnections: this.getActiveIntegrationCount(),
      failureRate: 0.02
    };
  }

  private async checkThreatIntelligenceHealth(): Promise<any> {
    return {
      status: 'healthy',
      responseTime: Math.random() * 300,
      feedsActive: 10,
      lastUpdate: new Date()
    };
  }

  private calculateUptime(component: string): number {
    // Mock uptime calculation
    return Math.random() * 0.1 + 0.9; // 90-100% uptime
  }

  private calculateSystemUptime(): number {
    return Math.random() * 0.05 + 0.95; // 95-100% uptime
  }

  // Mock data getters (would integrate with actual SOAR components)
  private getCaseCount(): number {
    return Math.floor(Math.random() * 100) + 50;
  }

  private getOpenCaseCount(): number {
    return Math.floor(Math.random() * 30) + 10;
  }

  private getAverageResolutionTime(): number {
    return Math.floor(Math.random() * 300) + 120; // 2-7 hours
  }

  private getPlaybookExecutionCount(): number {
    return Math.floor(Math.random() * 500) + 100;
  }

  private getPlaybookSuccessRate(): number {
    return Math.random() * 0.1 + 0.9; // 90-100%
  }

  private getActiveIntegrationCount(): number {
    return Math.floor(Math.random() * 10) + 15;
  }

  private getIntegrationAPICallCount(): number {
    return Math.floor(Math.random() * 10000) + 5000;
  }

  private getThreatDetectionCount(): number {
    return Math.floor(Math.random() * 50) + 20;
  }

  private getThreatMitigationCount(): number {
    return Math.floor(Math.random() * 40) + 15;
  }

  private handleError(operation: string, error: Error): void {
    console.error(`[ISECTECHSOARMetricsMonitoring] Error in ${operation}:`, error);
    
    this.circuitBreaker.failureCount++;
    this.circuitBreaker.lastFailureTime = Date.now();
    
    if (this.circuitBreaker.failureCount >= 5) {
      this.circuitBreaker.isOpen = true;
      setTimeout(() => {
        this.circuitBreaker.isOpen = false;
        this.circuitBreaker.failureCount = 0;
      }, this.circuitBreaker.resetTimeout);
    }
    
    this.emit('error', { operation, error });
  }

  // Public getters for external access
  getMetrics(metricName?: string): ISECTECHMetric[] {
    if (metricName) {
      return this.metrics.get(metricName) || [];
    }
    return Array.from(this.metrics.values()).flat();
  }

  getAlerts(status?: string): ISECTECHAlert[] {
    const alerts = Array.from(this.alerts.values());
    return status ? alerts.filter(a => a.status === status) : alerts;
  }

  getDashboards(): ISECTECHDashboard[] {
    return Array.from(this.dashboards.values());
  }

  getReports(): ISECTECHReport[] {
    return Array.from(this.reports.values());
  }

  getHealthStatus(): Map<string, HealthCheckResult> {
    return new Map(this.healthChecks);
  }

  getSystemMetrics(): any {
    return {
      totalMetrics: Array.from(this.metrics.values()).reduce((sum, arr) => sum + arr.length, 0),
      activeAlerts: Array.from(this.alerts.values()).filter(a => a.status === 'active').length,
      totalDashboards: this.dashboards.size,
      scheduledReports: this.scheduledReports.size,
      circuitBreakerStatus: this.circuitBreaker.isOpen ? 'open' : 'closed',
      lastUpdated: new Date()
    };
  }
}