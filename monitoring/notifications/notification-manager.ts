// iSECTECH Notification Manager
// Centralized notification routing and management system

import { EventEmitter } from 'events';
import { SlackNotificationManager, AlertMessage, SlackConfig } from './slack-integration';
import nodemailer from 'nodemailer';
import axios from 'axios';

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES AND INTERFACES
// ═══════════════════════════════════════════════════════════════════════════════

export interface NotificationConfig {
  slack?: SlackConfig;
  email?: EmailConfig;
  pagerDuty?: PagerDutyConfig;
  webhook?: WebhookConfig[];
  sms?: SMSConfig;
}

export interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
  from: string;
  defaultRecipients: string[];
}

export interface PagerDutyConfig {
  apiUrl: string;
  integrationKeys: {
    critical: string;
    warning: string;
    info: string;
  };
  userToken?: string;
}

export interface WebhookConfig {
  name: string;
  url: string;
  headers?: Record<string, string>;
  method?: 'POST' | 'PUT' | 'PATCH';
  retries?: number;
  timeout?: number;
}

export interface SMSConfig {
  provider: 'twilio' | 'aws-sns';
  credentials: any;
  defaultNumbers: string[];
}

export interface NotificationRule {
  id: string;
  name: string;
  conditions: NotificationCondition[];
  actions: NotificationAction[];
  enabled: boolean;
  priority: 'low' | 'medium' | 'high' | 'critical';
  cooldown?: number; // minutes
  description?: string;
}

export interface NotificationCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater' | 'less';
  value: any;
  negate?: boolean;
}

export interface NotificationAction {
  type: 'slack' | 'email' | 'pagerduty' | 'webhook' | 'sms';
  target: string;
  template?: string;
  escalate?: boolean;
  delay?: number; // seconds
}

export interface NotificationEvent {
  id: string;
  timestamp: Date;
  type: 'alert' | 'incident' | 'maintenance' | 'custom';
  severity: 'critical' | 'warning' | 'info';
  title: string;
  message: string;
  source: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  resolved?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOTIFICATION MANAGER CLASS
// ═══════════════════════════════════════════════════════════════════════════════

export class NotificationManager extends EventEmitter {
  private config: NotificationConfig;
  private slackManager?: SlackNotificationManager;
  private emailTransporter?: nodemailer.Transporter;
  private rules: Map<string, NotificationRule> = new Map();
  private cooldowns: Map<string, Date> = new Map();
  private notificationHistory: NotificationEvent[] = [];

  constructor(config: NotificationConfig) {
    super();
    this.config = config;
    this.initialize();
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // INITIALIZATION
  // ═════════════════════════════════════════════════════════════════════════════

  private initialize(): void {
    // Initialize Slack manager
    if (this.config.slack) {
      this.slackManager = new SlackNotificationManager(this.config.slack);
    }

    // Initialize email transporter
    if (this.config.email) {
      this.emailTransporter = nodemailer.createTransporter({
        host: this.config.email.host,
        port: this.config.email.port,
        secure: this.config.email.secure,
        auth: this.config.email.auth,
      });
    }

    // Setup default notification rules
    this.setupDefaultRules();
  }

  private setupDefaultRules(): void {
    // Critical alert rule
    this.addRule({
      id: 'critical-alerts',
      name: 'Critical Alert Notifications',
      conditions: [
        { field: 'severity', operator: 'equals', value: 'critical' }
      ],
      actions: [
        { type: 'slack', target: '#alerts-critical', escalate: true },
        { type: 'pagerduty', target: 'critical' },
        { type: 'email', target: 'critical-alerts@isectech.com' }
      ],
      enabled: true,
      priority: 'critical',
      cooldown: 5, // 5 minutes
      description: 'Immediate notification for critical alerts'
    });

    // Security incident rule
    this.addRule({
      id: 'security-incidents',
      name: 'Security Incident Notifications',
      conditions: [
        { field: 'labels.category', operator: 'equals', value: 'security' }
      ],
      actions: [
        { type: 'slack', target: '#alerts-security' },
        { type: 'email', target: 'security-team@isectech.com' },
        { type: 'webhook', target: 'security-webhook' }
      ],
      enabled: true,
      priority: 'high',
      description: 'Security team notifications'
    });

    // Performance warning rule
    this.addRule({
      id: 'performance-warnings',
      name: 'Performance Warning Notifications',
      conditions: [
        { field: 'labels.category', operator: 'equals', value: 'performance' },
        { field: 'severity', operator: 'equals', value: 'warning' }
      ],
      actions: [
        { type: 'slack', target: '#team-performance', delay: 60 }
      ],
      enabled: true,
      priority: 'medium',
      cooldown: 30,
      description: 'Performance team notifications with delay'
    });

    // Business hours rule
    this.addRule({
      id: 'business-hours-only',
      name: 'Business Hours Notifications',
      conditions: [
        { field: 'severity', operator: 'equals', value: 'info' }
      ],
      actions: [
        { type: 'email', target: 'business-team@isectech.com' }
      ],
      enabled: true,
      priority: 'low',
      cooldown: 60,
      description: 'Non-urgent notifications during business hours'
    });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // RULE MANAGEMENT
  // ═════════════════════════════════════════════════════════════════════════════

  addRule(rule: NotificationRule): void {
    this.rules.set(rule.id, rule);
    this.emit('rule:added', rule);
  }

  removeRule(ruleId: string): void {
    const rule = this.rules.get(ruleId);
    if (rule) {
      this.rules.delete(ruleId);
      this.emit('rule:removed', rule);
    }
  }

  updateRule(ruleId: string, updates: Partial<NotificationRule>): void {
    const rule = this.rules.get(ruleId);
    if (rule) {
      const updatedRule = { ...rule, ...updates };
      this.rules.set(ruleId, updatedRule);
      this.emit('rule:updated', updatedRule);
    }
  }

  enableRule(ruleId: string): void {
    this.updateRule(ruleId, { enabled: true });
  }

  disableRule(ruleId: string): void {
    this.updateRule(ruleId, { enabled: false });
  }

  getRules(): NotificationRule[] {
    return Array.from(this.rules.values());
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // NOTIFICATION PROCESSING
  // ═════════════════════════════════════════════════════════════════════════════

  async sendNotification(event: NotificationEvent): Promise<void> {
    // Record event
    this.notificationHistory.push(event);
    this.emit('notification:received', event);

    // Find matching rules
    const matchingRules = this.findMatchingRules(event);

    for (const rule of matchingRules) {
      if (!rule.enabled) continue;

      // Check cooldown
      if (this.isInCooldown(rule.id, event)) {
        this.emit('notification:cooldown', { rule, event });
        continue;
      }

      // Execute rule actions
      await this.executeRuleActions(rule, event);

      // Set cooldown
      if (rule.cooldown) {
        const cooldownUntil = new Date(Date.now() + rule.cooldown * 60 * 1000);
        this.cooldowns.set(`${rule.id}:${event.source}`, cooldownUntil);
      }
    }
  }

  private findMatchingRules(event: NotificationEvent): NotificationRule[] {
    const matchingRules: NotificationRule[] = [];

    for (const rule of this.rules.values()) {
      if (this.evaluateConditions(rule.conditions, event)) {
        matchingRules.push(rule);
      }
    }

    // Sort by priority
    return matchingRules.sort((a, b) => {
      const priorities = { critical: 4, high: 3, medium: 2, low: 1 };
      return priorities[b.priority] - priorities[a.priority];
    });
  }

  private evaluateConditions(conditions: NotificationCondition[], event: NotificationEvent): boolean {
    return conditions.every(condition => this.evaluateCondition(condition, event));
  }

  private evaluateCondition(condition: NotificationCondition, event: NotificationEvent): boolean {
    const fieldValue = this.getFieldValue(condition.field, event);
    let result = false;

    switch (condition.operator) {
      case 'equals':
        result = fieldValue === condition.value;
        break;
      case 'contains':
        result = String(fieldValue).includes(String(condition.value));
        break;
      case 'regex':
        result = new RegExp(condition.value).test(String(fieldValue));
        break;
      case 'greater':
        result = Number(fieldValue) > Number(condition.value);
        break;
      case 'less':
        result = Number(fieldValue) < Number(condition.value);
        break;
    }

    return condition.negate ? !result : result;
  }

  private getFieldValue(field: string, event: NotificationEvent): any {
    // Support dot notation for nested fields
    const parts = field.split('.');
    let value: any = event;

    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  private async executeRuleActions(rule: NotificationRule, event: NotificationEvent): Promise<void> {
    for (const action of rule.actions) {
      try {
        // Apply delay if specified
        if (action.delay) {
          setTimeout(() => this.executeAction(action, event, rule), action.delay * 1000);
        } else {
          await this.executeAction(action, event, rule);
        }
      } catch (error) {
        this.emit('notification:error', { rule, action, event, error });
      }
    }
  }

  private async executeAction(action: NotificationAction, event: NotificationEvent, rule: NotificationRule): Promise<void> {
    switch (action.type) {
      case 'slack':
        await this.sendSlackNotification(action, event);
        break;
      case 'email':
        await this.sendEmailNotification(action, event);
        break;
      case 'pagerduty':
        await this.sendPagerDutyNotification(action, event);
        break;
      case 'webhook':
        await this.sendWebhookNotification(action, event);
        break;
      case 'sms':
        await this.sendSMSNotification(action, event);
        break;
    }

    this.emit('notification:sent', { action, event, rule });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // NOTIFICATION METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private async sendSlackNotification(action: NotificationAction, event: NotificationEvent): Promise<void> {
    if (!this.slackManager) return;

    const alertMessage: AlertMessage = {
      alertName: event.title,
      status: event.resolved ? 'resolved' : 'firing',
      severity: event.severity,
      summary: event.message,
      description: event.annotations.description || event.message,
      service: event.labels.service,
      environment: event.labels.environment,
      instance: event.labels.instance,
      timestamp: event.timestamp,
      labels: event.labels,
      annotations: event.annotations,
    };

    if (event.severity === 'critical') {
      await this.slackManager.sendCriticalAlert(alertMessage, { channel: action.target });
    } else if (event.labels.category === 'security') {
      await this.slackManager.sendSecurityAlert(alertMessage, { channel: action.target });
    } else {
      await this.slackManager.sendAlert(alertMessage, { channel: action.target });
    }
  }

  private async sendEmailNotification(action: NotificationAction, event: NotificationEvent): Promise<void> {
    if (!this.emailTransporter || !this.config.email) return;

    const recipients = action.target.includes('@') 
      ? [action.target] 
      : this.config.email.defaultRecipients;

    const subject = `[${event.severity.toUpperCase()}] ${event.title}`;
    const body = this.buildEmailBody(event);

    await this.emailTransporter.sendMail({
      from: this.config.email.from,
      to: recipients.join(', '),
      subject,
      html: body,
    });
  }

  private async sendPagerDutyNotification(action: NotificationAction, event: NotificationEvent): Promise<void> {
    if (!this.config.pagerDuty) return;

    const integrationKey = this.config.pagerDuty.integrationKeys[action.target as keyof typeof this.config.pagerDuty.integrationKeys];
    if (!integrationKey) return;

    const payload = {
      routing_key: integrationKey,
      event_action: event.resolved ? 'resolve' : 'trigger',
      dedup_key: `${event.source}-${event.id}`,
      payload: {
        summary: event.message,
        severity: event.severity,
        source: event.source,
        timestamp: event.timestamp.toISOString(),
        custom_details: {
          labels: event.labels,
          annotations: event.annotations,
        },
      },
    };

    await axios.post(this.config.pagerDuty.apiUrl, payload);
  }

  private async sendWebhookNotification(action: NotificationAction, event: NotificationEvent): Promise<void> {
    const webhook = this.config.webhook?.find(w => w.name === action.target);
    if (!webhook) return;

    const payload = {
      event,
      timestamp: new Date().toISOString(),
      source: 'isectech-notification-manager',
    };

    const config = {
      method: webhook.method || 'POST',
      url: webhook.url,
      headers: webhook.headers || { 'Content-Type': 'application/json' },
      data: payload,
      timeout: webhook.timeout || 10000,
    };

    let attempt = 0;
    const maxRetries = webhook.retries || 3;

    while (attempt <= maxRetries) {
      try {
        await axios(config);
        break;
      } catch (error) {
        attempt++;
        if (attempt > maxRetries) throw error;
        await this.sleep(1000 * Math.pow(2, attempt - 1)); // Exponential backoff
      }
    }
  }

  private async sendSMSNotification(action: NotificationAction, event: NotificationEvent): Promise<void> {
    // SMS implementation would depend on the configured provider
    // This is a placeholder for SMS functionality
    this.emit('notification:sms', { action, event, message: 'SMS not implemented' });
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // UTILITY METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  private isInCooldown(ruleId: string, event: NotificationEvent): boolean {
    const cooldownKey = `${ruleId}:${event.source}`;
    const cooldownUntil = this.cooldowns.get(cooldownKey);
    
    if (!cooldownUntil) return false;
    
    const now = new Date();
    if (now > cooldownUntil) {
      this.cooldowns.delete(cooldownKey);
      return false;
    }
    
    return true;
  }

  private buildEmailBody(event: NotificationEvent): string {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>iSECTECH Notification</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
          .container { max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .header { background-color: ${event.severity === 'critical' ? '#d32f2f' : event.severity === 'warning' ? '#ff8f00' : '#1976d2'}; color: white; padding: 20px; text-align: center; }
          .content { padding: 20px; }
          .label { background-color: #e0e0e0; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin: 2px; display: inline-block; }
          .timestamp { color: #666; font-size: 12px; margin-top: 15px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${event.severity.toUpperCase()} Notification</h1>
            <h2>${event.title}</h2>
          </div>
          <div class="content">
            <p><strong>Message:</strong> ${event.message}</p>
            <p><strong>Source:</strong> ${event.source}</p>
            <p><strong>Severity:</strong> ${event.severity}</p>
            ${Object.entries(event.labels).map(([key, value]) => 
              `<span class="label">${key}: ${value}</span>`
            ).join('')}
            <div class="timestamp">
              <strong>Timestamp:</strong> ${event.timestamp.toLocaleString()}
            </div>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // ═════════════════════════════════════════════════════════════════════════════
  // PUBLIC METHODS
  // ═════════════════════════════════════════════════════════════════════════════

  getNotificationHistory(limit = 100): NotificationEvent[] {
    return this.notificationHistory.slice(-limit).reverse();
  }

  getActiveCooldowns(): Array<{ ruleId: string, source: string, until: Date }> {
    const active: Array<{ ruleId: string, source: string, until: Date }> = [];
    
    for (const [key, until] of this.cooldowns.entries()) {
      if (new Date() < until) {
        const [ruleId, source] = key.split(':');
        active.push({ ruleId, source, until });
      }
    }
    
    return active;
  }

  clearCooldown(ruleId: string, source?: string): void {
    if (source) {
      this.cooldowns.delete(`${ruleId}:${source}`);
    } else {
      // Clear all cooldowns for this rule
      for (const key of this.cooldowns.keys()) {
        if (key.startsWith(`${ruleId}:`)) {
          this.cooldowns.delete(key);
        }
      }
    }
  }

  testRule(ruleId: string, event: NotificationEvent): boolean {
    const rule = this.rules.get(ruleId);
    if (!rule) return false;
    
    return this.evaluateConditions(rule.conditions, event);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FACTORY FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

export function createNotificationManager(config: NotificationConfig): NotificationManager {
  return new NotificationManager(config);
}

// Export default instance
export const notificationManager = createNotificationManager({
  slack: {
    token: process.env.SLACK_BOT_TOKEN || '',
    webhookUrl: process.env.SLACK_WEBHOOK_URL,
    defaultChannel: process.env.SLACK_DEFAULT_CHANNEL || '#alerts-general',
    signingSecret: process.env.SLACK_SIGNING_SECRET,
  },
  email: {
    host: process.env.SMTP_HOST || 'smtp.isectech.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || 'alerts@isectech.com',
      pass: process.env.SMTP_PASSWORD || '',
    },
    from: process.env.SMTP_FROM || 'alerts@isectech.com',
    defaultRecipients: (process.env.EMAIL_DEFAULT_RECIPIENTS || 'ops-team@isectech.com').split(','),
  },
  pagerDuty: {
    apiUrl: 'https://events.pagerduty.com/v2/enqueue',
    integrationKeys: {
      critical: process.env.PAGERDUTY_CRITICAL_KEY || '',
      warning: process.env.PAGERDUTY_WARNING_KEY || '',
      info: process.env.PAGERDUTY_INFO_KEY || '',
    },
    userToken: process.env.PAGERDUTY_USER_TOKEN,
  },
  webhook: [
    {
      name: 'security-webhook',
      url: process.env.SECURITY_WEBHOOK_URL || 'https://api.isectech.com/webhooks/security',
      headers: {
        'Authorization': `Bearer ${process.env.SECURITY_WEBHOOK_TOKEN}`,
        'Content-Type': 'application/json',
      },
      retries: 3,
      timeout: 10000,
    },
  ],
});