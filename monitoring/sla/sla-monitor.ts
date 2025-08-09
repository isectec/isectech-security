// iSECTECH SLA Monitoring and Tracking System
// Production-grade SLA monitoring with automated reporting and alerting

import { EventEmitter } from 'events';
import axios from 'axios';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface SLATarget {
  name: string;
  description: string;
  type: 'availability' | 'performance' | 'error_rate' | 'throughput';
  target: number; // Target value (e.g., 99.9 for 99.9% uptime)
  unit: 'percentage' | 'milliseconds' | 'requests_per_second';
  service: string;
  environment: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  alertThreshold: number; // Alert when SLA drops below this
  warningThreshold?: number; // Warning when SLA drops below this
  measurement: SLAMeasurement;
  tags?: string[];
}

export interface SLAMeasurement {
  query: string; // Prometheus query
  datasource: 'prometheus' | 'elasticsearch';
  evaluationWindow: string; // e.g., '5m', '1h', '24h'
  evaluationInterval: string; // e.g., '1m', '5m'
  aggregation?: 'avg' | 'sum' | 'max' | 'min' | 'p95' | 'p99';
}

export interface SLAStatus {
  target: SLATarget;
  currentValue: number;
  status: 'met' | 'at_risk' | 'violated';
  lastUpdated: Date;
  trend: 'improving' | 'stable' | 'degrading';
  errorBudget: number; // Remaining error budget (percentage)
  errorBudgetBurnRate: number; // Rate of error budget consumption
  history: SLADataPoint[];
}

export interface SLADataPoint {
  timestamp: Date;
  value: number;
  status: 'met' | 'at_risk' | 'violated';
}

export interface SLAReport {
  period: 'hourly' | 'daily' | 'weekly' | 'monthly';
  startTime: Date;
  endTime: Date;
  targets: SLAReportTarget[];
  summary: SLASummary;
  incidents: SLAIncident[];
  generatedAt: Date;
}

export interface SLAReportTarget {
  target: SLATarget;
  actualValue: number;
  slaAchieved: boolean;
  uptimePercentage: number;
  downtimeMinutes: number;
  violationCount: number;
  mttr: number; // Mean Time To Recovery in minutes
  mtbf: number; // Mean Time Between Failures in minutes
}

export interface SLASummary {
  totalTargets: number;
  targetsAchieved: number;
  targetsViolated: number;
  overallSLAPercentage: number;
  totalDowntime: number;
  worstPerformingService: string;
  bestPerformingService: string;
}

export interface SLAIncident {
  id: string;
  target: string;
  service: string;
  startTime: Date;
  endTime?: Date;
  duration?: number; // in minutes
  severity: 'critical' | 'high' | 'medium' | 'low';
  impact: string;
  rootCause?: string;
  resolution?: string;
  status: 'open' | 'investigating' | 'resolved';
}

export interface SLAConfig {
  prometheus: {
    url: string;
    timeout?: number;
  };
  elasticsearch?: {
    url: string;
    timeout?: number;
  };
  notification: {
    slack?: {
      webhookUrl: string;
      channel: string;
    };
    email?: {
      recipients: string[];
      smtpConfig: any;
    };
  };
  reporting: {
    schedule: string; // Cron expression
    recipients: string[];
    formats: ('json' | 'html' | 'pdf')[];
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SLA MONITOR CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class SLAMonitor extends EventEmitter {
  private targets: Map<string, SLATarget> = new Map();
  private statuses: Map<string, SLAStatus> = new Map();
  private incidents: Map<string, SLAIncident> = new Map();
  private timers: Map<string, NodeJS.Timeout> = new Map();
  private config: SLAConfig;
  private isRunning = false;

  constructor(config: SLAConfig) {
    super();
    this.config = config;
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // TARGET MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  addTarget(target: SLATarget): void {
    const targetId = this.generateTargetId(target);
    this.targets.set(targetId, target);
    
    // Initialize status
    this.statuses.set(targetId, {
      target,
      currentValue: 0,
      status: 'met',
      lastUpdated: new Date(),
      trend: 'stable',
      errorBudget: 100,
      errorBudgetBurnRate: 0,
      history: [],
    });

    this.emit('target:added', { targetId, target });

    // Start monitoring if running
    if (this.isRunning) {
      this.startTargetMonitoring(targetId, target);
    }
  }

  removeTarget(targetId: string): void {
    const target = this.targets.get(targetId);
    if (target) {
      this.stopTargetMonitoring(targetId);
      this.targets.delete(targetId);
      this.statuses.delete(targetId);
      this.emit('target:removed', { targetId, target });
    }
  }

  getTargets(): SLATarget[] {
    return Array.from(this.targets.values());
  }

  getTargetStatus(targetId: string): SLAStatus | null {
    return this.statuses.get(targetId) || null;
  }

  getAllStatuses(): Map<string, SLAStatus> {
    return new Map(this.statuses);
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // MONITORING CONTROL
  // ═════════════════════════════════════════════════════════════════════════════

  start(): void {
    if (this.isRunning) return;

    this.isRunning = true;

    for (const [targetId, target] of this.targets.entries()) {
      this.startTargetMonitoring(targetId, target);
    }

    this.emit('monitor:started');
  }

  stop(): void {
    if (!this.isRunning) return;

    this.isRunning = false;

    for (const targetId of this.targets.keys()) {
      this.stopTargetMonitoring(targetId);
    }

    this.emit('monitor:stopped');
  }

  private startTargetMonitoring(targetId: string, target: SLATarget): void {
    const interval = this.parseInterval(target.measurement.evaluationInterval);
    
    // Perform initial evaluation
    this.evaluateTarget(targetId, target);

    // Schedule recurring evaluations
    const timer = setInterval(() => {
      this.evaluateTarget(targetId, target);
    }, interval);

    this.timers.set(targetId, timer);
  }

  private stopTargetMonitoring(targetId: string): void {
    const timer = this.timers.get(targetId);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(targetId);
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // SLA EVALUATION
  // ═════════════════════════════════════════════════════════════════════════════

  private async evaluateTarget(targetId: string, target: SLATarget): Promise<void> {
    try {
      const value = await this.executeQuery(target.measurement);
      const status = this.statuses.get(targetId)!;
      
      // Update status
      const previousValue = status.currentValue;
      status.currentValue = value;
      status.lastUpdated = new Date();
      
      // Determine SLA status
      const newStatus = this.determineSLAStatus(value, target);
      const statusChanged = status.status !== newStatus;
      status.status = newStatus;
      
      // Calculate trend
      status.trend = this.calculateTrend(status.history, value);
      
      // Calculate error budget
      this.calculateErrorBudget(status, target);
      
      // Add to history
      status.history.push({
        timestamp: new Date(),
        value,
        status: newStatus,
      });
      
      // Keep last 1440 data points (24 hours at 1-minute intervals)
      if (status.history.length > 1440) {
        status.history.shift();
      }
      
      // Handle status changes
      if (statusChanged) {
        await this.handleStatusChange(targetId, target, status, newStatus);
      }
      
      this.emit('target:evaluated', { targetId, target, status, previousValue });
      
    } catch (error) {
      this.emit('target:evaluation_failed', { targetId, target, error });
    }
  }

  private async executeQuery(measurement: SLAMeasurement): Promise<number> {
    if (measurement.datasource === 'prometheus') {
      return this.executePrometheusQuery(measurement.query);
    } else if (measurement.datasource === 'elasticsearch') {
      return this.executeElasticsearchQuery(measurement.query);
    }
    throw new Error(`Unsupported datasource: ${measurement.datasource}`);
  }

  private async executePrometheusQuery(query: string): Promise<number> {
    const response = await axios.get(`${this.config.prometheus.url}/api/v1/query`, {
      params: { query },
      timeout: this.config.prometheus.timeout || 30000,
    });

    const result = response.data.data.result;
    if (result.length === 0) {
      throw new Error('No data returned from Prometheus query');
    }

    const value = parseFloat(result[0].value[1]);
    if (isNaN(value)) {
      throw new Error('Invalid numeric value returned from Prometheus');
    }

    return value;
  }

  private async executeElasticsearchQuery(query: string): Promise<number> {
    // Implementation for Elasticsearch queries
    // This would depend on the specific Elasticsearch query format
    throw new Error('Elasticsearch queries not yet implemented');
  }

  private determineSLAStatus(value: number, target: SLATarget): 'met' | 'at_risk' | 'violated' {
    if (value >= target.target) {
      return 'met';
    } else if (target.warningThreshold && value >= target.warningThreshold) {
      return 'at_risk';
    } else if (value < target.alertThreshold) {
      return 'violated';
    }
    return 'at_risk';
  }

  private calculateTrend(history: SLADataPoint[], currentValue: number): 'improving' | 'stable' | 'degrading' {
    if (history.length < 5) return 'stable';
    
    const recent = history.slice(-5);
    const average = recent.reduce((sum, point) => sum + point.value, 0) / recent.length;
    
    const tolerance = 0.01; // 1% tolerance for "stable"
    if (currentValue > average * (1 + tolerance)) return 'improving';
    if (currentValue < average * (1 - tolerance)) return 'degrading';
    return 'stable';
  }

  private calculateErrorBudget(status: SLAStatus, target: SLATarget): void {
    // Calculate error budget based on target type
    if (target.type === 'availability') {
      const uptimeTarget = target.target / 100; // Convert percentage to decimal
      const currentUptime = status.currentValue / 100;
      const errorBudget = (1 - uptimeTarget) * 100; // Available error budget
      const currentError = (1 - currentUptime) * 100;
      
      status.errorBudget = Math.max(0, ((errorBudget - currentError) / errorBudget) * 100);
      
      // Calculate burn rate (error budget consumed per hour)
      if (status.history.length >= 2) {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const historicalPoint = status.history.find(point => 
          Math.abs(point.timestamp.getTime() - oneHourAgo.getTime()) < 5 * 60 * 1000
        );
        
        if (historicalPoint) {
          const budgetChange = historicalPoint.value - status.currentValue;
          status.errorBudgetBurnRate = Math.max(0, budgetChange);
        }
      }
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // INCIDENT MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  private async handleStatusChange(
    targetId: string,
    target: SLATarget,
    status: SLAStatus,
    newStatus: 'met' | 'at_risk' | 'violated'
  ): Promise<void> {
    if (newStatus === 'violated') {
      await this.createIncident(targetId, target, status);
    } else if (newStatus === 'met') {
      await this.resolveIncident(targetId, target);
    }

    // Send notifications
    await this.sendStatusChangeNotification(targetId, target, status, newStatus);
    
    this.emit('status:changed', { targetId, target, status, newStatus });
  }

  private async createIncident(targetId: string, target: SLATarget, status: SLAStatus): Promise<void> {
    const incidentId = `${targetId}-${Date.now()}`;
    
    const incident: SLAIncident = {
      id: incidentId,
      target: target.name,
      service: target.service,
      startTime: new Date(),
      severity: target.severity,
      impact: `SLA violation: ${target.name} is ${status.currentValue}${target.unit}, below target of ${target.target}${target.unit}`,
      status: 'open',
    };

    this.incidents.set(incidentId, incident);
    this.emit('incident:created', incident);
  }

  private async resolveIncident(targetId: string, target: SLATarget): Promise<void> {
    // Find open incidents for this target
    for (const [incidentId, incident] of this.incidents.entries()) {
      if (incident.target === target.name && incident.status === 'open') {
        incident.endTime = new Date();
        incident.duration = Math.round((incident.endTime.getTime() - incident.startTime.getTime()) / (1000 * 60));
        incident.status = 'resolved';
        incident.resolution = 'SLA target restored automatically';
        
        this.emit('incident:resolved', incident);
      }
    }
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // NOTIFICATIONS
  // ═════════════════════════════════════════════════════════════════════════════

  private async sendStatusChangeNotification(
    targetId: string,
    target: SLATarget,
    status: SLAStatus,
    newStatus: 'met' | 'at_risk' | 'violated'
  ): Promise<void> {
    const message = this.buildNotificationMessage(target, status, newStatus);
    
    // Send Slack notification
    if (this.config.notification.slack) {
      await this.sendSlackNotification(message, newStatus);
    }
    
    // Send email notification for violations
    if (newStatus === 'violated' && this.config.notification.email) {
      await this.sendEmailNotification(message, target);
    }
  }

  private buildNotificationMessage(
    target: SLATarget,
    status: SLAStatus,
    newStatus: 'met' | 'at_risk' | 'violated'
  ): string {
    const emoji = newStatus === 'met' ? '✅' : newStatus === 'at_risk' ? '⚠️' : '🔥';
    const statusText = newStatus.replace('_', ' ').toUpperCase();
    
    return `${emoji} SLA ${statusText}: ${target.name}
Service: ${target.service}
Current Value: ${status.currentValue}${target.unit}
Target: ${target.target}${target.unit}
Error Budget: ${status.errorBudget.toFixed(1)}%
Trend: ${status.trend}`;
  }

  private async sendSlackNotification(message: string, status: string): Promise<void> {
    if (!this.config.notification.slack) return;

    const color = status === 'met' ? 'good' : status === 'at_risk' ? 'warning' : 'danger';
    
    await axios.post(this.config.notification.slack.webhookUrl, {
      channel: this.config.notification.slack.channel,
      text: message,
      attachments: [{
        color,
        text: message,
      }],
    });
  }

  private async sendEmailNotification(message: string, target: SLATarget): Promise<void> {
    // Email implementation would go here
    // Using nodemailer or similar library
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // REPORTING
  // ═════════════════════════════════════════════════════════════════════════════

  async generateReport(
    period: 'hourly' | 'daily' | 'weekly' | 'monthly',
    startTime?: Date,
    endTime?: Date
  ): Promise<SLAReport> {
    const now = new Date();
    const { start, end } = this.calculateReportPeriod(period, startTime, endTime, now);
    
    const targetReports: SLAReportTarget[] = [];
    
    for (const [targetId, target] of this.targets.entries()) {
      const status = this.statuses.get(targetId)!;
      const targetReport = await this.generateTargetReport(target, status, start, end);
      targetReports.push(targetReport);
    }
    
    const summary = this.generateSummary(targetReports);
    const incidents = this.getIncidentsInPeriod(start, end);
    
    return {
      period,
      startTime: start,
      endTime: end,
      targets: targetReports,
      summary,
      incidents,
      generatedAt: new Date(),
    };
  }

  private async generateTargetReport(
    target: SLATarget,
    status: SLAStatus,
    startTime: Date,
    endTime: Date
  ): Promise<SLAReportTarget> {
    // Filter history for the report period
    const periodData = status.history.filter(
      point => point.timestamp >= startTime && point.timestamp <= endTime
    );
    
    if (periodData.length === 0) {
      return {
        target,
        actualValue: status.currentValue,
        slaAchieved: status.currentValue >= target.target,
        uptimePercentage: 0,
        downtimeMinutes: 0,
        violationCount: 0,
        mttr: 0,
        mtbf: 0,
      };
    }
    
    // Calculate metrics
    const totalPoints = periodData.length;
    const violatedPoints = periodData.filter(point => point.status === 'violated').length;
    const uptimePercentage = ((totalPoints - violatedPoints) / totalPoints) * 100;
    
    // Calculate downtime (assuming 1-minute intervals)
    const downtimeMinutes = violatedPoints;
    
    // Count violations (consecutive violated points count as one violation)
    let violationCount = 0;
    let inViolation = false;
    
    for (const point of periodData) {
      if (point.status === 'violated' && !inViolation) {
        violationCount++;
        inViolation = true;
      } else if (point.status !== 'violated') {
        inViolation = false;
      }
    }
    
    // Calculate MTTR and MTBF
    const incidents = this.getIncidentsForTarget(target.name, startTime, endTime);
    const resolvedIncidents = incidents.filter(inc => inc.status === 'resolved' && inc.duration);
    
    const mttr = resolvedIncidents.length > 0
      ? resolvedIncidents.reduce((sum, inc) => sum + (inc.duration || 0), 0) / resolvedIncidents.length
      : 0;
    
    const totalPeriodMinutes = Math.round((endTime.getTime() - startTime.getTime()) / (1000 * 60));
    const mtbf = violationCount > 0 ? (totalPeriodMinutes - downtimeMinutes) / violationCount : totalPeriodMinutes;
    
    const avgValue = periodData.reduce((sum, point) => sum + point.value, 0) / periodData.length;
    
    return {
      target,
      actualValue: avgValue,
      slaAchieved: avgValue >= target.target,
      uptimePercentage,
      downtimeMinutes,
      violationCount,
      mttr,
      mtbf,
    };
  }

  private generateSummary(targetReports: SLAReportTarget[]): SLASummary {
    const totalTargets = targetReports.length;
    const targetsAchieved = targetReports.filter(report => report.slaAchieved).length;
    const targetsViolated = totalTargets - targetsAchieved;
    const overallSLAPercentage = (targetsAchieved / totalTargets) * 100;
    const totalDowntime = targetReports.reduce((sum, report) => sum + report.downtimeMinutes, 0);
    
    const worstPerforming = targetReports.reduce((worst, current) => 
      current.uptimePercentage < worst.uptimePercentage ? current : worst
    );
    
    const bestPerforming = targetReports.reduce((best, current) => 
      current.uptimePercentage > best.uptimePercentage ? current : best
    );
    
    return {
      totalTargets,
      targetsAchieved,
      targetsViolated,
      overallSLAPercentage,
      totalDowntime,
      worstPerformingService: worstPerforming.target.service,
      bestPerformingService: bestPerforming.target.service,
    };
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private generateTargetId(target: SLATarget): string {
    return `${target.service}-${target.name}`.replace(/[^a-zA-Z0-9-]/g, '-').toLowerCase();
  }

  private parseInterval(interval: string): number {
    const unit = interval.slice(-1);
    const value = parseInt(interval.slice(0, -1));
    
    switch (unit) {
      case 's': return value * 1000;
      case 'm': return value * 60 * 1000;
      case 'h': return value * 60 * 60 * 1000;
      default: throw new Error(`Invalid interval: ${interval}`);
    }
  }

  private calculateReportPeriod(
    period: 'hourly' | 'daily' | 'weekly' | 'monthly',
    startTime?: Date,
    endTime?: Date,
    now: Date = new Date()
  ): { start: Date; end: Date } {
    if (startTime && endTime) {
      return { start: startTime, end: endTime };
    }
    
    const end = endTime || now;
    let start: Date;
    
    switch (period) {
      case 'hourly':
        start = new Date(end.getTime() - 60 * 60 * 1000);
        break;
      case 'daily':
        start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
        break;
      case 'weekly':
        start = new Date(end.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case 'monthly':
        start = new Date(end.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
    }
    
    return { start, end };
  }

  private getIncidentsInPeriod(startTime: Date, endTime: Date): SLAIncident[] {
    return Array.from(this.incidents.values()).filter(
      incident => incident.startTime >= startTime && incident.startTime <= endTime
    );
  }

  private getIncidentsForTarget(targetName: string, startTime: Date, endTime: Date): SLAIncident[] {
    return this.getIncidentsInPeriod(startTime, endTime).filter(
      incident => incident.target === targetName
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREDEFINED SLA TARGETS FOR ISECTECH
// ═══════════════════════════════════════════════════════════════════════════════

export const createISECTECHSLATargets = (): SLATarget[] => [
  // Frontend Availability SLA
  {
    name: 'Frontend Availability',
    description: 'Main application frontend uptime',
    type: 'availability',
    target: 99.9, // 99.9% uptime
    unit: 'percentage',
    service: 'frontend',
    environment: 'production',
    severity: 'critical',
    alertThreshold: 99.0,
    warningThreshold: 99.5,
    measurement: {
      query: 'avg_over_time(up{job="isectech-frontend"}[5m]) * 100',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['user-facing', 'critical'],
  },
  
  // API Response Time SLA
  {
    name: 'API Response Time',
    description: 'Backend API p95 response time',
    type: 'performance',
    target: 200, // 200ms p95 response time
    unit: 'milliseconds',
    service: 'backend-api',
    environment: 'production',
    severity: 'high',
    alertThreshold: 500,
    warningThreshold: 300,
    measurement: {
      query: 'histogram_quantile(0.95, sum by (le) (rate(http_request_duration_seconds_bucket{job="isectech-backend"}[5m]))) * 1000',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['performance', 'user-experience'],
  },
  
  // Database Availability SLA
  {
    name: 'Database Availability',
    description: 'PostgreSQL database uptime',
    type: 'availability',
    target: 99.95, // 99.95% uptime
    unit: 'percentage',
    service: 'database',
    environment: 'production',
    severity: 'critical',
    alertThreshold: 99.0,
    warningThreshold: 99.9,
    measurement: {
      query: 'avg_over_time(up{job="postgres-exporter"}[5m]) * 100',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['infrastructure', 'critical'],
  },
  
  // API Error Rate SLA
  {
    name: 'API Error Rate',
    description: 'Backend API error rate (5xx responses)',
    type: 'error_rate',
    target: 0.1, // 0.1% error rate
    unit: 'percentage',
    service: 'backend-api',
    environment: 'production',
    severity: 'high',
    alertThreshold: 1.0,
    warningThreshold: 0.5,
    measurement: {
      query: '(sum(rate(http_requests_total{job="isectech-backend",status=~"5.."}[5m])) / sum(rate(http_requests_total{job="isectech-backend"}[5m]))) * 100',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['reliability', 'error-tracking'],
  },
  
  // Security Service Availability SLA
  {
    name: 'Security Service Availability',
    description: 'Security monitoring service uptime',
    type: 'availability',
    target: 99.8, // 99.8% uptime
    unit: 'percentage',
    service: 'security-service',
    environment: 'production',
    severity: 'critical',
    alertThreshold: 98.0,
    warningThreshold: 99.0,
    measurement: {
      query: 'avg_over_time(up{job="isectech-security"}[5m]) * 100',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['security', 'compliance'],
  },
  
  // AI Service Performance SLA
  {
    name: 'AI Service Response Time',
    description: 'AI threat detection p95 response time',
    type: 'performance',
    target: 1000, // 1 second p95 response time
    unit: 'milliseconds',
    service: 'ai-services',
    environment: 'production',
    severity: 'medium',
    alertThreshold: 3000,
    warningThreshold: 2000,
    measurement: {
      query: 'histogram_quantile(0.95, sum by (le) (rate(ai_request_duration_seconds_bucket{job="isectech-ai"}[5m]))) * 1000',
      datasource: 'prometheus',
      evaluationWindow: '5m',
      evaluationInterval: '1m',
    },
    tags: ['ai', 'performance'],
  },
];

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createSLAMonitor(config: SLAConfig): SLAMonitor {
  return new SLAMonitor(config);
}

// Export default configuration
export const defaultSLAConfig: SLAConfig = {
  prometheus: {
    url: process.env.PROMETHEUS_URL || 'http://localhost:9090',
    timeout: 30000,
  },
  notification: {
    slack: {
      webhookUrl: process.env.SLACK_SLA_WEBHOOK_URL || '',
      channel: '#sla-monitoring',
    },
    email: {
      recipients: (process.env.SLA_EMAIL_RECIPIENTS || 'ops-team@isectech.com').split(','),
      smtpConfig: {
        host: process.env.SMTP_HOST || 'smtp.isectech.com',
        port: parseInt(process.env.SMTP_PORT || '587'),
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER || 'alerts@isectech.com',
          pass: process.env.SMTP_PASSWORD || '',
        },
      },
    },
  },
  reporting: {
    schedule: '0 9 * * *', // Daily at 9 AM
    recipients: (process.env.SLA_REPORT_RECIPIENTS || 'management@isectech.com').split(','),
    formats: ['json', 'html'],
  },
};