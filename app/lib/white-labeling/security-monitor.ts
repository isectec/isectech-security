/**
 * Security Monitoring and Alerting System for Multi-Tenant Isolation
 * Production-grade monitoring, alerting, and incident response system
 */

import crypto from 'crypto';
import type {
  IsolationValidationReport,
  TenantVulnerability,
  SecurityMetrics,
} from '@/lib/white-labeling/tenant-isolation-validator';
import type { BrandingAuditLog } from '@/types/white-labeling';

export interface SecurityAlert {
  id: string;
  type: 'VULNERABILITY_DETECTED' | 'SECURITY_SCORE_DROP' | 'COMPLIANCE_FAILURE' | 
        'UNAUTHORIZED_ACCESS' | 'DATA_BREACH_RISK' | 'SYSTEM_ANOMALY';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  tenantId: string;
  triggeredBy: string;
  triggeredAt: Date;
  evidence: any;
  recommendations: string[];
  status: 'ACTIVE' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  assignedTo?: string;
  resolvedAt?: Date;
  resolutionNotes?: string;
  relatedAlerts?: string[];
  escalationLevel: number;
  lastEscalationAt?: Date;
}

export interface SecurityIncident {
  id: string;
  title: string;
  description: string;
  severity: SecurityAlert['severity'];
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  tenantId: string;
  affectedTenants: string[];
  detectedAt: Date;
  containedAt?: Date;
  resolvedAt?: Date;
  assignedTo?: string;
  relatedAlerts: string[];
  impactAssessment: {
    dataExposure: boolean;
    configurationCompromise: boolean;
    serviceDisruption: boolean;
    complianceImpact: boolean;
    estimatedUsers: number;
  };
  timeline: SecurityIncidentEvent[];
  remediationSteps: string[];
  lessonsLearned?: string[];
}

export interface SecurityIncidentEvent {
  id: string;
  timestamp: Date;
  type: 'DETECTED' | 'ESCALATED' | 'MITIGATED' | 'RESOLVED' | 'NOTE_ADDED';
  description: string;
  performedBy: string;
  evidence?: any;
}

export interface MonitoringRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  ruleType: 'THRESHOLD' | 'ANOMALY' | 'PATTERN' | 'COMPLIANCE';
  conditions: MonitoringCondition[];
  alertSeverity: SecurityAlert['severity'];
  escalationPlan: EscalationPlan;
  cooldownPeriod: number; // minutes
  lastTriggered?: Date;
  triggerCount: number;
}

export interface MonitoringCondition {
  metric: 'SECURITY_SCORE' | 'VULNERABILITY_COUNT' | 'FAILED_TESTS' | 'CROSS_TENANT_ATTEMPTS';
  operator: 'GT' | 'LT' | 'EQ' | 'GTE' | 'LTE';
  threshold: number;
  timeWindow: number; // minutes
}

export interface EscalationPlan {
  levels: EscalationLevel[];
  maxLevel: number;
  autoEscalationEnabled: boolean;
}

export interface EscalationLevel {
  level: number;
  delayMinutes: number;
  notificationChannels: NotificationChannel[];
  assignees: string[];
  actions: string[];
}

export interface NotificationChannel {
  type: 'EMAIL' | 'SMS' | 'SLACK' | 'WEBHOOK' | 'PAGER_DUTY';
  target: string;
  template?: string;
}

export interface SecurityDashboardMetrics {
  currentSecurityScore: number;
  activeAlerts: number;
  openIncidents: number;
  lastValidationTime: Date;
  vulnerabilityTrend: Array<{ date: Date; count: number; severity: string }>;
  complianceScore: number;
  tenantRiskDistribution: Record<string, number>;
  mttr: number; // Mean Time To Resolution in hours
  alertVelocity: number; // Alerts per day
}

export class SecurityMonitor {
  private static instance: SecurityMonitor;
  private alerts = new Map<string, SecurityAlert>();
  private incidents = new Map<string, SecurityIncident>();
  private rules = new Map<string, MonitoringRule>();
  private metrics: SecurityDashboardMetrics;
  private monitoringInterval?: NodeJS.Timeout;
  private eventQueue: Array<() => Promise<void>> = [];
  
  private constructor() {
    this.metrics = this.initializeMetrics();
    this.initializeDefaultRules();
    this.startEventProcessor();
  }

  public static getInstance(): SecurityMonitor {
    if (!SecurityMonitor.instance) {
      SecurityMonitor.instance = new SecurityMonitor();
    }
    return SecurityMonitor.instance;
  }

  /**
   * Process validation report and trigger alerts if needed
   */
  public async processValidationReport(
    report: IsolationValidationReport,
    executedBy: string
  ): Promise<SecurityAlert[]> {
    const triggeredAlerts: SecurityAlert[] = [];

    // Check security score threshold
    if (report.overallSecurityScore < 70) {
      const alert = await this.createAlert({
        type: 'SECURITY_SCORE_DROP',
        severity: report.overallSecurityScore < 50 ? 'CRITICAL' : 'HIGH',
        title: `Security Score Drop Detected`,
        description: `Security score dropped to ${report.overallSecurityScore}/100 for tenant ${report.tenantId}`,
        tenantId: report.tenantId,
        triggeredBy: 'automated-monitoring',
        evidence: {
          report: report.id,
          score: report.overallSecurityScore,
          riskLevel: report.riskLevel,
          failedTests: report.failedTests,
        },
        recommendations: report.recommendations,
      });
      triggeredAlerts.push(alert);
    }

    // Check for vulnerabilities
    for (const vulnerability of report.vulnerabilities) {
      const alert = await this.createAlert({
        type: 'VULNERABILITY_DETECTED',
        severity: vulnerability.severity,
        title: `${vulnerability.type.replace(/_/g, ' ')} Vulnerability Detected`,
        description: vulnerability.description,
        tenantId: report.tenantId,
        triggeredBy: 'automated-monitoring',
        evidence: {
          vulnerability: vulnerability.id,
          type: vulnerability.type,
          evidence: vulnerability.evidence,
          report: report.id,
        },
        recommendations: [vulnerability.remediation],
      });
      triggeredAlerts.push(alert);
    }

    // Check compliance failures
    const failedCompliance = Object.entries(report.complianceStatus)
      .filter(([_, compliant]) => !compliant)
      .map(([standard, _]) => standard);

    if (failedCompliance.length > 0) {
      const alert = await this.createAlert({
        type: 'COMPLIANCE_FAILURE',
        severity: 'HIGH',
        title: `Compliance Failure Detected`,
        description: `Failed compliance checks: ${failedCompliance.join(', ')}`,
        tenantId: report.tenantId,
        triggeredBy: 'automated-monitoring',
        evidence: {
          failedStandards: failedCompliance,
          complianceStatus: report.complianceStatus,
          report: report.id,
        },
        recommendations: [
          'Review and address security vulnerabilities',
          'Implement additional security controls',
          'Schedule compliance audit',
        ],
      });
      triggeredAlerts.push(alert);
    }

    // Update metrics
    await this.updateMetrics(report);

    // Check monitoring rules
    const ruleTriggeredAlerts = await this.checkMonitoringRules(report);
    triggeredAlerts.push(...ruleTriggeredAlerts);

    return triggeredAlerts;
  }

  /**
   * Process suspicious activity log
   */
  public async processSuspiciousActivity(
    auditLog: BrandingAuditLog,
    activityType: 'CROSS_TENANT_ATTEMPT' | 'PRIVILEGE_ESCALATION' | 'UNUSUAL_PATTERN'
  ): Promise<SecurityAlert | null> {
    let severity: SecurityAlert['severity'] = 'MEDIUM';
    let alertType: SecurityAlert['type'] = 'UNAUTHORIZED_ACCESS';

    if (activityType === 'CROSS_TENANT_ATTEMPT') {
      severity = 'HIGH';
      alertType = 'DATA_BREACH_RISK';
    }

    const alert = await this.createAlert({
      type: alertType,
      severity,
      title: `Suspicious Activity Detected: ${activityType.replace(/_/g, ' ')}`,
      description: `Suspicious activity detected for user ${auditLog.userEmail} in tenant ${auditLog.tenantId}`,
      tenantId: auditLog.tenantId,
      triggeredBy: 'audit-monitoring',
      evidence: {
        auditLogId: auditLog.id,
        userId: auditLog.userId,
        action: auditLog.action,
        resourceType: auditLog.resourceType,
        resourceId: auditLog.resourceId,
        timestamp: auditLog.createdAt,
        ipAddress: auditLog.ipAddress,
        userAgent: auditLog.userAgent,
      },
      recommendations: [
        'Investigate user activity patterns',
        'Verify user authorization',
        'Check for compromised credentials',
        'Consider temporary access restriction',
      ],
    });

    return alert;
  }

  /**
   * Create security incident from alerts
   */
  public async createIncident(
    alertIds: string[],
    title: string,
    description: string,
    assignedTo: string
  ): Promise<SecurityIncident> {
    const alerts = alertIds.map(id => this.alerts.get(id)!).filter(Boolean);
    const maxSeverity = this.getMaxSeverity(alerts.map(a => a.severity));
    const affectedTenants = [...new Set(alerts.map(a => a.tenantId))];

    const incident: SecurityIncident = {
      id: this.generateId('incident'),
      title,
      description,
      severity: maxSeverity,
      status: 'OPEN',
      tenantId: affectedTenants[0],
      affectedTenants,
      detectedAt: new Date(),
      assignedTo,
      relatedAlerts: alertIds,
      impactAssessment: {
        dataExposure: alerts.some(a => a.type === 'DATA_BREACH_RISK'),
        configurationCompromise: alerts.some(a => a.type === 'VULNERABILITY_DETECTED'),
        serviceDisruption: false,
        complianceImpact: alerts.some(a => a.type === 'COMPLIANCE_FAILURE'),
        estimatedUsers: 0,
      },
      timeline: [{
        id: this.generateId('event'),
        timestamp: new Date(),
        type: 'DETECTED',
        description: 'Security incident created',
        performedBy: assignedTo,
      }],
      remediationSteps: [],
    };

    this.incidents.set(incident.id, incident);

    // Update related alerts
    alertIds.forEach(alertId => {
      const alert = this.alerts.get(alertId);
      if (alert) {
        alert.status = 'INVESTIGATING';
        alert.assignedTo = assignedTo;
      }
    });

    await this.sendNotifications([{
      type: 'EMAIL',
      target: 'security-team@isectech.com',
      template: 'security-incident-created',
    }], {
      incident,
      alerts,
    });

    return incident;
  }

  /**
   * Start real-time monitoring
   */
  public startRealTimeMonitoring(intervalMinutes: number = 5): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
    }

    this.monitoringInterval = setInterval(async () => {
      try {
        await this.performHealthCheck();
        await this.checkEscalations();
        await this.updateDashboardMetrics();
      } catch (error) {
        console.error('Real-time monitoring error:', error);
      }
    }, intervalMinutes * 60 * 1000);

    console.log(`Real-time security monitoring started (interval: ${intervalMinutes}m)`);
  }

  /**
   * Stop monitoring
   */
  public stopRealTimeMonitoring(): void {
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
    }
  }

  /**
   * Get current security dashboard metrics
   */
  public getDashboardMetrics(): SecurityDashboardMetrics {
    return { ...this.metrics };
  }

  /**
   * Get active alerts
   */
  public getActiveAlerts(tenantId?: string): SecurityAlert[] {
    const alerts = Array.from(this.alerts.values());
    return tenantId 
      ? alerts.filter(a => a.tenantId === tenantId && a.status === 'ACTIVE')
      : alerts.filter(a => a.status === 'ACTIVE');
  }

  /**
   * Get open incidents
   */
  public getOpenIncidents(tenantId?: string): SecurityIncident[] {
    const incidents = Array.from(this.incidents.values());
    return tenantId
      ? incidents.filter(i => i.affectedTenants.includes(tenantId) && i.status !== 'CLOSED')
      : incidents.filter(i => i.status !== 'CLOSED');
  }

  /**
   * Acknowledge alert
   */
  public async acknowledgeAlert(alertId: string, acknowledgedBy: string): Promise<void> {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.status = 'ACKNOWLEDGED';
      alert.assignedTo = acknowledgedBy;
      await this.logAlertAction(alertId, 'acknowledged', acknowledgedBy);
    }
  }

  /**
   * Resolve alert
   */
  public async resolveAlert(
    alertId: string, 
    resolvedBy: string, 
    resolutionNotes: string
  ): Promise<void> {
    const alert = this.alerts.get(alertId);
    if (alert) {
      alert.status = 'RESOLVED';
      alert.resolvedAt = new Date();
      alert.resolutionNotes = resolutionNotes;
      await this.logAlertAction(alertId, 'resolved', resolvedBy);
    }
  }

  // Private helper methods

  private async createAlert(alertData: Omit<SecurityAlert, 'id' | 'triggeredAt' | 'status' | 'escalationLevel'>): Promise<SecurityAlert> {
    const alert: SecurityAlert = {
      ...alertData,
      id: this.generateId('alert'),
      triggeredAt: new Date(),
      status: 'ACTIVE',
      escalationLevel: 0,
    };

    this.alerts.set(alert.id, alert);

    // Queue immediate notification
    this.eventQueue.push(async () => {
      await this.sendAlertNotifications(alert);
    });

    return alert;
  }

  private async checkMonitoringRules(report: IsolationValidationReport): Promise<SecurityAlert[]> {
    const triggeredAlerts: SecurityAlert[] = [];

    for (const rule of this.rules.values()) {
      if (!rule.enabled) continue;

      // Check cooldown period
      if (rule.lastTriggered) {
        const cooldownEnd = new Date(rule.lastTriggered.getTime() + rule.cooldownPeriod * 60 * 1000);
        if (new Date() < cooldownEnd) continue;
      }

      let ruleTriggered = false;
      
      for (const condition of rule.conditions) {
        const value = this.getMetricValue(condition.metric, report);
        const threshold = condition.threshold;

        const conditionMet = this.evaluateCondition(value, condition.operator, threshold);
        
        if (conditionMet) {
          ruleTriggered = true;
          break;
        }
      }

      if (ruleTriggered) {
        const alert = await this.createAlert({
          type: 'SYSTEM_ANOMALY',
          severity: rule.alertSeverity,
          title: `Monitoring Rule Triggered: ${rule.name}`,
          description: rule.description,
          tenantId: report.tenantId,
          triggeredBy: 'monitoring-rule',
          evidence: {
            ruleId: rule.id,
            ruleName: rule.name,
            report: report.id,
            conditions: rule.conditions,
          },
          recommendations: [`Review monitoring rule: ${rule.name}`],
        });

        triggeredAlerts.push(alert);
        rule.lastTriggered = new Date();
        rule.triggerCount++;
      }
    }

    return triggeredAlerts;
  }

  private getMetricValue(metric: MonitoringCondition['metric'], report: IsolationValidationReport): number {
    switch (metric) {
      case 'SECURITY_SCORE': return report.overallSecurityScore;
      case 'VULNERABILITY_COUNT': return report.vulnerabilities.length;
      case 'FAILED_TESTS': return report.failedTests;
      case 'CROSS_TENANT_ATTEMPTS': return 0; // Would be calculated from audit logs
      default: return 0;
    }
  }

  private evaluateCondition(value: number, operator: MonitoringCondition['operator'], threshold: number): boolean {
    switch (operator) {
      case 'GT': return value > threshold;
      case 'LT': return value < threshold;
      case 'EQ': return value === threshold;
      case 'GTE': return value >= threshold;
      case 'LTE': return value <= threshold;
      default: return false;
    }
  }

  private async performHealthCheck(): Promise<void> {
    // Mock health check implementation
    console.log('Performing security health check...');
  }

  private async checkEscalations(): Promise<void> {
    const now = new Date();
    
    for (const alert of this.alerts.values()) {
      if (alert.status !== 'ACTIVE' && alert.status !== 'ACKNOWLEDGED') continue;

      const escalationPlan = this.getEscalationPlan(alert);
      if (!escalationPlan.autoEscalationEnabled) continue;

      const nextLevel = alert.escalationLevel + 1;
      if (nextLevel >= escalationPlan.levels.length) continue;

      const levelConfig = escalationPlan.levels[nextLevel];
      const escalationTime = new Date(alert.triggeredAt.getTime() + levelConfig.delayMinutes * 60 * 1000);

      if (now >= escalationTime) {
        await this.escalateAlert(alert, nextLevel);
      }
    }
  }

  private async escalateAlert(alert: SecurityAlert, level: number): Promise<void> {
    alert.escalationLevel = level;
    alert.lastEscalationAt = new Date();

    const escalationPlan = this.getEscalationPlan(alert);
    const levelConfig = escalationPlan.levels[level];

    await this.sendNotifications(levelConfig.notificationChannels, {
      alert,
      escalationLevel: level,
      message: `Security alert has been escalated to level ${level}`,
    });

    await this.logAlertAction(alert.id, 'escalated', 'system');
  }

  private getEscalationPlan(alert: SecurityAlert): EscalationPlan {
    // Return default escalation plan or rule-specific plan
    return {
      levels: [
        {
          level: 0,
          delayMinutes: 0,
          notificationChannels: [{ type: 'EMAIL', target: 'security-team@isectech.com' }],
          assignees: ['security-admin'],
          actions: [],
        },
        {
          level: 1,
          delayMinutes: 15,
          notificationChannels: [
            { type: 'EMAIL', target: 'security-manager@isectech.com' },
            { type: 'SLACK', target: '#security-alerts' },
          ],
          assignees: ['security-manager'],
          actions: ['notify-management'],
        },
      ],
      maxLevel: 2,
      autoEscalationEnabled: true,
    };
  }

  private async updateMetrics(report: IsolationValidationReport): Promise<void> {
    this.metrics.currentSecurityScore = report.overallSecurityScore;
    this.metrics.lastValidationTime = report.executedAt;
    this.metrics.activeAlerts = this.getActiveAlerts().length;
    this.metrics.openIncidents = this.getOpenIncidents().length;
    
    // Update vulnerability trend
    this.metrics.vulnerabilityTrend.push({
      date: new Date(),
      count: report.vulnerabilities.length,
      severity: report.riskLevel,
    });

    // Keep only last 30 days of trend data
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    this.metrics.vulnerabilityTrend = this.metrics.vulnerabilityTrend
      .filter(trend => trend.date >= thirtyDaysAgo);
  }

  private async updateDashboardMetrics(): Promise<void> {
    // Update real-time metrics
    this.metrics.activeAlerts = this.getActiveAlerts().length;
    this.metrics.openIncidents = this.getOpenIncidents().length;
    this.metrics.alertVelocity = this.calculateAlertVelocity();
    this.metrics.mttr = this.calculateMTTR();
  }

  private calculateAlertVelocity(): number {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentAlerts = Array.from(this.alerts.values())
      .filter(alert => alert.triggeredAt >= oneDayAgo);
    return recentAlerts.length;
  }

  private calculateMTTR(): number {
    const resolvedAlerts = Array.from(this.alerts.values())
      .filter(alert => alert.status === 'RESOLVED' && alert.resolvedAt);

    if (resolvedAlerts.length === 0) return 0;

    const totalResolutionTime = resolvedAlerts.reduce((sum, alert) => {
      const resolutionTime = alert.resolvedAt!.getTime() - alert.triggeredAt.getTime();
      return sum + resolutionTime;
    }, 0);

    return totalResolutionTime / resolvedAlerts.length / (1000 * 60 * 60); // Hours
  }

  private async sendAlertNotifications(alert: SecurityAlert): Promise<void> {
    const channels: NotificationChannel[] = [
      { type: 'EMAIL', target: 'security-team@isectech.com' },
    ];

    if (alert.severity === 'CRITICAL') {
      channels.push({ type: 'SLACK', target: '#security-critical' });
    }

    await this.sendNotifications(channels, { alert });
  }

  private async sendNotifications(channels: NotificationChannel[], data: any): Promise<void> {
    for (const channel of channels) {
      try {
        await this.sendNotification(channel, data);
      } catch (error) {
        console.error(`Failed to send notification to ${channel.type}:`, error);
      }
    }
  }

  private async sendNotification(channel: NotificationChannel, data: any): Promise<void> {
    // Mock notification sending
    console.log(`Sending ${channel.type} notification to ${channel.target}:`, {
      alert: data.alert?.title || 'Security notification',
      severity: data.alert?.severity || 'INFO',
    });
  }

  private async logAlertAction(alertId: string, action: string, performedBy: string): Promise<void> {
    console.log(`Alert ${alertId} - ${action} by ${performedBy}`);
  }

  private getMaxSeverity(severities: SecurityAlert['severity'][]): SecurityAlert['severity'] {
    const order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    return severities.reduce((max, current) => 
      order.indexOf(current) > order.indexOf(max) ? current : max
    );
  }

  private startEventProcessor(): void {
    setInterval(async () => {
      while (this.eventQueue.length > 0) {
        const event = this.eventQueue.shift();
        if (event) {
          try {
            await event();
          } catch (error) {
            console.error('Event processing error:', error);
          }
        }
      }
    }, 1000);
  }

  private initializeMetrics(): SecurityDashboardMetrics {
    return {
      currentSecurityScore: 0,
      activeAlerts: 0,
      openIncidents: 0,
      lastValidationTime: new Date(),
      vulnerabilityTrend: [],
      complianceScore: 0,
      tenantRiskDistribution: {},
      mttr: 0,
      alertVelocity: 0,
    };
  }

  private initializeDefaultRules(): void {
    // Critical security score threshold
    this.rules.set('security-score-critical', {
      id: 'security-score-critical',
      name: 'Critical Security Score',
      description: 'Triggers when security score drops below 50',
      enabled: true,
      ruleType: 'THRESHOLD',
      conditions: [{
        metric: 'SECURITY_SCORE',
        operator: 'LT',
        threshold: 50,
        timeWindow: 5,
      }],
      alertSeverity: 'CRITICAL',
      escalationPlan: {
        levels: [],
        maxLevel: 2,
        autoEscalationEnabled: true,
      },
      cooldownPeriod: 30,
      triggerCount: 0,
    });

    // High vulnerability count
    this.rules.set('high-vulnerability-count', {
      id: 'high-vulnerability-count',
      name: 'High Vulnerability Count',
      description: 'Triggers when vulnerability count exceeds threshold',
      enabled: true,
      ruleType: 'THRESHOLD',
      conditions: [{
        metric: 'VULNERABILITY_COUNT',
        operator: 'GT',
        threshold: 5,
        timeWindow: 10,
      }],
      alertSeverity: 'HIGH',
      escalationPlan: {
        levels: [],
        maxLevel: 1,
        autoEscalationEnabled: true,
      },
      cooldownPeriod: 60,
      triggerCount: 0,
    });
  }

  private generateId(type: string): string {
    return `${type}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}`;
  }
}

// Export singleton instance
export const securityMonitor = SecurityMonitor.getInstance();