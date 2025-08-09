/**
 * Mobile Fallback Service
 * Backend implementation for notification fallback mechanisms
 * Supports SMS, Email, and Webhook delivery with retry logic
 */

import { EventEmitter } from 'events';

interface NotificationPayload {
  id: string;
  title: string;
  message?: string;
  type: 'success' | 'error' | 'warning' | 'info';
  timestamp: Date;
  priority: 'low' | 'medium' | 'high' | 'critical';
  userId: string;
  metadata?: Record<string, any>;
}

interface FallbackConfig {
  enabled: boolean;
  priority: number;
  retryAttempts: number;
  retryDelayMs: number;
  timeout: number;
  conditions: FallbackCondition[];
}

interface FallbackCondition {
  type: 'delivery_failure' | 'user_offline' | 'device_unavailable' | 'schedule_based' | 'priority_threshold';
  enabled: boolean;
  config: Record<string, any>;
}

interface SMSConfig extends FallbackConfig {
  provider: {
    type: 'twilio' | 'aws_sns' | 'messagebird';
    credentials: Record<string, string>;
  };
  phoneNumber: string;
  maxLength: number;
  templates: {
    alert: string;
    critical: string;
    info: string;
  };
}

interface EmailConfig extends FallbackConfig {
  provider: {
    type: 'sendgrid' | 'ses' | 'mailgun';
    credentials: Record<string, string>;
  };
  to: string[];
  from: string;
  templates: {
    subject: string;
    html: string;
    text: string;
  };
  attachments: {
    includeLogs: boolean;
    includeScreenshots: boolean;
    includeReports: boolean;
  };
}

interface WebhookConfig extends FallbackConfig {
  url: string;
  method: 'POST' | 'PUT' | 'PATCH';
  headers: Record<string, string>;
  authentication: {
    type: 'none' | 'bearer' | 'basic' | 'api_key' | 'oauth2';
    credentials: Record<string, string>;
  };
  payloadTemplate: string;
  expectedStatusCodes: number[];
}

interface FallbackAttempt {
  id: string;
  notificationId: string;
  method: 'sms' | 'email' | 'webhook';
  status: 'pending' | 'success' | 'failed' | 'timeout' | 'retrying';
  attempts: number;
  maxAttempts: number;
  lastAttempt: Date;
  nextRetry?: Date;
  error?: string;
  responseTime?: number;
  response?: any;
  metadata: Record<string, any>;
}

interface DeliveryReport {
  notificationId: string;
  totalAttempts: number;
  successfulMethods: string[];
  failedMethods: string[];
  totalDeliveryTime: number;
  fallbacksUsed: boolean;
  primaryDeliveryFailed: boolean;
  finalStatus: 'delivered' | 'failed' | 'partial';
}

class MobileFallbackService extends EventEmitter {
  private smsConfig: SMSConfig | null = null;
  private emailConfig: EmailConfig | null = null;
  private webhookConfig: WebhookConfig | null = null;
  
  private activeAttempts = new Map<string, FallbackAttempt>();
  private deliveryQueue: NotificationPayload[] = [];
  private retryTimers = new Map<string, NodeJS.Timeout>();
  private isProcessing = false;
  
  // External service clients (would be real implementations in production)
  private smsClients = new Map();
  private emailClients = new Map();
  private httpClient: any;

  constructor() {
    super();
    this.startQueueProcessor();
    this.initializeClients();
  }

  /**
   * Initialize external service clients
   */
  private initializeClients() {
    // Initialize HTTP client for webhooks
    this.httpClient = {
      request: async (config: any) => {
        // Simulate HTTP request
        return new Promise((resolve, reject) => {
          const delay = Math.random() * 1000 + 200; // 200ms to 1.2s
          setTimeout(() => {
            if (Math.random() > 0.1) { // 90% success rate
              resolve({
                status: config.expectedStatusCodes?.[0] || 200,
                data: { success: true, timestamp: new Date().toISOString() },
                headers: { 'content-type': 'application/json' }
              });
            } else {
              reject(new Error('HTTP request failed'));
            }
          }, delay);
        });
      }
    };

    // Initialize SMS clients (would be real SDK clients)
    this.smsClients.set('twilio', {
      send: async (to: string, message: string) => {
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            if (Math.random() > 0.05) { // 95% success rate
              resolve({ sid: `SM${Date.now()}`, status: 'queued' });
            } else {
              reject(new Error('SMS delivery failed'));
            }
          }, 500 + Math.random() * 1000);
        });
      }
    });

    // Initialize email clients (would be real SDK clients)
    this.emailClients.set('sendgrid', {
      send: async (email: any) => {
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            if (Math.random() > 0.03) { // 97% success rate
              resolve({ messageId: `msg_${Date.now()}`, status: 'accepted' });
            } else {
              reject(new Error('Email delivery failed'));
            }
          }, 300 + Math.random() * 700);
        });
      }
    });
  }

  /**
   * Configure SMS fallback
   */
  public configureSMS(config: SMSConfig): void {
    this.smsConfig = config;
    this.emit('configUpdated', { type: 'sms', enabled: config.enabled });
  }

  /**
   * Configure Email fallback
   */
  public configureEmail(config: EmailConfig): void {
    this.emailConfig = config;
    this.emit('configUpdated', { type: 'email', enabled: config.enabled });
  }

  /**
   * Configure Webhook fallback
   */
  public configureWebhook(config: WebhookConfig): void {
    this.webhookConfig = config;
    this.emit('configUpdated', { type: 'webhook', enabled: config.enabled });
  }

  /**
   * Queue notification for fallback processing
   */
  public async queueNotification(notification: NotificationPayload): Promise<string> {
    const processId = `${notification.id}_${Date.now()}`;
    
    this.deliveryQueue.push(notification);
    
    this.emit('notificationQueued', {
      notificationId: notification.id,
      processId,
      queueLength: this.deliveryQueue.length
    });

    return processId;
  }

  /**
   * Process delivery queue
   */
  private async startQueueProcessor(): Promise<void> {
    setInterval(async () => {
      if (!this.isProcessing && this.deliveryQueue.length > 0) {
        await this.processQueue();
      }
    }, 1000);
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing) return;
    
    this.isProcessing = true;
    
    try {
      while (this.deliveryQueue.length > 0) {
        const notification = this.deliveryQueue.shift();
        if (notification) {
          await this.processNotification(notification);
        }
      }
    } catch (error) {
      console.error('Queue processing error:', error);
    } finally {
      this.isProcessing = false;
    }
  }

  /**
   * Process individual notification through fallback methods
   */
  private async processNotification(notification: NotificationPayload): Promise<void> {
    const startTime = Date.now();
    const methods = this.getApplicableMethods(notification);
    
    if (methods.length === 0) {
      this.emit('noMethodsAvailable', { notificationId: notification.id });
      return;
    }

    // Sort methods by priority
    methods.sort((a, b) => a.config.priority - b.config.priority);

    const deliveryReport: Partial<DeliveryReport> = {
      notificationId: notification.id,
      totalAttempts: 0,
      successfulMethods: [],
      failedMethods: [],
      fallbacksUsed: methods.length > 1,
      primaryDeliveryFailed: true, // Assume primary failed if we're here
    };

    // Execute fallback methods
    for (const method of methods) {
      try {
        const success = await this.executeMethod(notification, method);
        deliveryReport.totalAttempts! += 1;
        
        if (success) {
          deliveryReport.successfulMethods!.push(method.type);
          // If we have one successful delivery, we can consider it delivered
          break;
        } else {
          deliveryReport.failedMethods!.push(method.type);
        }
      } catch (error) {
        console.error(`Method ${method.type} failed:`, error);
        deliveryReport.failedMethods!.push(method.type);
      }
    }

    // Complete delivery report
    deliveryReport.totalDeliveryTime = Date.now() - startTime;
    deliveryReport.finalStatus = deliveryReport.successfulMethods!.length > 0 ? 'delivered' : 'failed';

    this.emit('deliveryCompleted', deliveryReport);
  }

  /**
   * Get applicable fallback methods for a notification
   */
  private getApplicableMethods(notification: NotificationPayload): Array<{type: string, config: FallbackConfig}> {
    const methods: Array<{type: string, config: FallbackConfig}> = [];

    if (this.smsConfig?.enabled && this.shouldUseFallback(this.smsConfig, notification)) {
      methods.push({ type: 'sms', config: this.smsConfig });
    }

    if (this.emailConfig?.enabled && this.shouldUseFallback(this.emailConfig, notification)) {
      methods.push({ type: 'email', config: this.emailConfig });
    }

    if (this.webhookConfig?.enabled && this.shouldUseFallback(this.webhookConfig, notification)) {
      methods.push({ type: 'webhook', config: this.webhookConfig });
    }

    return methods;
  }

  /**
   * Check if fallback method should be used for this notification
   */
  private shouldUseFallback(config: FallbackConfig, notification: NotificationPayload): boolean {
    return config.conditions.some(condition => {
      if (!condition.enabled) return false;

      switch (condition.type) {
        case 'priority_threshold':
          const priorityMap = { low: 1, medium: 2, high: 3, critical: 4 };
          const notificationPriority = priorityMap[notification.priority] || 1;
          const thresholdPriority = priorityMap[condition.config.minPriority] || 1;
          return notificationPriority >= thresholdPriority;

        case 'delivery_failure':
          // Always true if we're processing fallback
          return true;

        case 'user_offline':
          // Would check user's online status
          return condition.config.assumeOffline || false;

        case 'device_unavailable':
          // Would check device connectivity
          return condition.config.assumeUnavailable || false;

        case 'schedule_based':
          // Would implement cron-like scheduling
          const now = new Date();
          const hour = now.getHours();
          const schedule = condition.config.activeHours || [0, 23];
          return hour >= schedule[0] && hour <= schedule[1];

        default:
          return false;
      }
    });
  }

  /**
   * Execute a specific fallback method
   */
  private async executeMethod(
    notification: NotificationPayload,
    method: {type: string, config: FallbackConfig}
  ): Promise<boolean> {
    const attempt: FallbackAttempt = {
      id: `${notification.id}_${method.type}_${Date.now()}`,
      notificationId: notification.id,
      method: method.type as any,
      status: 'pending',
      attempts: 1,
      maxAttempts: method.config.retryAttempts + 1,
      lastAttempt: new Date(),
      metadata: {},
    };

    this.activeAttempts.set(attempt.id, attempt);
    this.emit('attemptStarted', attempt);

    try {
      const result = await this.deliverViaMethod(notification, method);
      
      attempt.status = 'success';
      attempt.responseTime = Date.now() - attempt.lastAttempt.getTime();
      attempt.response = result;
      
      this.emit('attemptSucceeded', attempt);
      return true;

    } catch (error) {
      attempt.status = 'failed';
      attempt.error = error.message;
      
      this.emit('attemptFailed', attempt);

      // Schedule retry if attempts remaining
      if (attempt.attempts < attempt.maxAttempts) {
        this.scheduleRetry(notification, method, attempt);
      }

      return false;
    } finally {
      this.activeAttempts.set(attempt.id, attempt);
    }
  }

  /**
   * Deliver notification via specific method
   */
  private async deliverViaMethod(
    notification: NotificationPayload,
    method: {type: string, config: FallbackConfig}
  ): Promise<any> {
    switch (method.type) {
      case 'sms':
        return this.deliverViaSMS(notification, this.smsConfig!);
      
      case 'email':
        return this.deliverViaEmail(notification, this.emailConfig!);
      
      case 'webhook':
        return this.deliverViaWebhook(notification, this.webhookConfig!);
      
      default:
        throw new Error(`Unknown delivery method: ${method.type}`);
    }
  }

  /**
   * Deliver notification via SMS
   */
  private async deliverViaSMS(notification: NotificationPayload, config: SMSConfig): Promise<any> {
    const client = this.smsClients.get(config.provider.type);
    if (!client) {
      throw new Error(`SMS client not configured for provider: ${config.provider.type}`);
    }

    // Select appropriate template based on notification type
    let template = config.templates.alert;
    if (notification.priority === 'critical') {
      template = config.templates.critical;
    } else if (notification.type === 'info') {
      template = config.templates.info;
    }

    // Build message from template
    const message = this.renderTemplate(template, {
      title: notification.title,
      message: notification.message || '',
      type: notification.type,
      timestamp: notification.timestamp.toISOString(),
    }).substring(0, config.maxLength);

    return await client.send(config.phoneNumber, message);
  }

  /**
   * Deliver notification via Email
   */
  private async deliverViaEmail(notification: NotificationPayload, config: EmailConfig): Promise<any> {
    const client = this.emailClients.get(config.provider.type);
    if (!client) {
      throw new Error(`Email client not configured for provider: ${config.provider.type}`);
    }

    const templateData = {
      title: notification.title,
      message: notification.message || '',
      type: notification.type,
      priority: notification.priority,
      timestamp: notification.timestamp.toISOString(),
      userId: notification.userId,
    };

    const emailData = {
      to: config.to,
      from: config.from,
      subject: this.renderTemplate(config.templates.subject, templateData),
      html: this.renderTemplate(config.templates.html, templateData),
      text: this.renderTemplate(config.templates.text, templateData),
      attachments: await this.prepareEmailAttachments(notification, config),
    };

    return await client.send(emailData);
  }

  /**
   * Deliver notification via Webhook
   */
  private async deliverViaWebhook(notification: NotificationPayload, config: WebhookConfig): Promise<any> {
    // Prepare payload from template
    const payload = JSON.parse(this.renderTemplate(config.payloadTemplate, {
      notification: JSON.stringify(notification),
      title: notification.title,
      message: notification.message || '',
      type: notification.type,
      priority: notification.priority,
      timestamp: notification.timestamp.toISOString(),
      userId: notification.userId,
    }));

    // Prepare headers
    const headers = { ...config.headers };
    
    // Add authentication
    switch (config.authentication.type) {
      case 'bearer':
        headers['Authorization'] = `Bearer ${config.authentication.credentials.token}`;
        break;
      case 'basic':
        const auth = Buffer.from(
          `${config.authentication.credentials.username}:${config.authentication.credentials.password}`
        ).toString('base64');
        headers['Authorization'] = `Basic ${auth}`;
        break;
      case 'api_key':
        const headerName = config.authentication.credentials.headerName || 'X-API-Key';
        headers[headerName] = config.authentication.credentials.apiKey;
        break;
    }

    // Make HTTP request
    const response = await this.httpClient.request({
      method: config.method,
      url: config.url,
      headers,
      data: payload,
      timeout: config.timeout || 10000,
      expectedStatusCodes: config.expectedStatusCodes,
    });

    return response;
  }

  /**
   * Schedule retry for failed attempt
   */
  private scheduleRetry(
    notification: NotificationPayload,
    method: {type: string, config: FallbackConfig},
    attempt: FallbackAttempt
  ): void {
    const delay = method.config.retryDelayMs * Math.pow(2, attempt.attempts - 1); // Exponential backoff
    const retryTime = new Date(Date.now() + delay);
    
    attempt.nextRetry = retryTime;
    attempt.status = 'retrying';
    
    const timer = setTimeout(async () => {
      this.retryTimers.delete(attempt.id);
      
      attempt.attempts += 1;
      attempt.lastAttempt = new Date();
      attempt.status = 'pending';
      
      try {
        const success = await this.executeMethod(notification, method);
        if (!success && attempt.attempts < attempt.maxAttempts) {
          this.scheduleRetry(notification, method, attempt);
        }
      } catch (error) {
        console.error(`Retry failed for attempt ${attempt.id}:`, error);
      }
    }, delay);

    this.retryTimers.set(attempt.id, timer);
    this.emit('retryScheduled', attempt);
  }

  /**
   * Prepare email attachments
   */
  private async prepareEmailAttachments(
    notification: NotificationPayload,
    config: EmailConfig
  ): Promise<any[]> {
    const attachments: any[] = [];

    if (config.attachments.includeLogs) {
      // Would generate/fetch relevant logs
      attachments.push({
        filename: `logs_${notification.id}.txt`,
        content: Buffer.from(`Log entries related to notification ${notification.id}\n...`),
        contentType: 'text/plain',
      });
    }

    if (config.attachments.includeScreenshots) {
      // Would capture or fetch screenshots
      attachments.push({
        filename: `screenshot_${notification.id}.png`,
        content: Buffer.from(''), // Would be actual image data
        contentType: 'image/png',
      });
    }

    if (config.attachments.includeReports) {
      // Would generate relevant reports
      attachments.push({
        filename: `report_${notification.id}.pdf`,
        content: Buffer.from(''), // Would be actual PDF data
        contentType: 'application/pdf',
      });
    }

    return attachments;
  }

  /**
   * Render template with variables
   */
  private renderTemplate(template: string, variables: Record<string, any>): string {
    let rendered = template;
    
    for (const [key, value] of Object.entries(variables)) {
      const regex = new RegExp(`{{${key}}}`, 'g');
      rendered = rendered.replace(regex, String(value));
    }

    return rendered;
  }

  /**
   * Get status of all active attempts
   */
  public getActiveAttempts(): FallbackAttempt[] {
    return Array.from(this.activeAttempts.values());
  }

  /**
   * Get attempt by ID
   */
  public getAttempt(attemptId: string): FallbackAttempt | undefined {
    return this.activeAttempts.get(attemptId);
  }

  /**
   * Cancel retry timers and cleanup
   */
  public async shutdown(): Promise<void> {
    // Clear all retry timers
    for (const [id, timer] of this.retryTimers) {
      clearTimeout(timer);
    }
    this.retryTimers.clear();
    
    // Clear queues
    this.deliveryQueue.length = 0;
    this.activeAttempts.clear();
    
    this.emit('shutdown');
  }

  /**
   * Test a specific fallback method
   */
  public async testMethod(methodType: 'sms' | 'email' | 'webhook'): Promise<boolean> {
    const testNotification: NotificationPayload = {
      id: `test_${Date.now()}`,
      title: 'iSECTECH Fallback Test',
      message: 'This is a test of the notification fallback system.',
      type: 'info',
      priority: 'medium',
      timestamp: new Date(),
      userId: 'test_user',
      metadata: { test: true },
    };

    try {
      const method = { type: methodType, config: this.getConfigForMethod(methodType) };
      return await this.executeMethod(testNotification, method);
    } catch (error) {
      console.error(`Test failed for ${methodType}:`, error);
      return false;
    }
  }

  private getConfigForMethod(methodType: string): FallbackConfig {
    switch (methodType) {
      case 'sms':
        return this.smsConfig!;
      case 'email':
        return this.emailConfig!;
      case 'webhook':
        return this.webhookConfig!;
      default:
        throw new Error(`Unknown method type: ${methodType}`);
    }
  }
}

// Export singleton instance
export const mobileFallbackService = new MobileFallbackService();

// Export types for use in other modules
export type {
  NotificationPayload,
  FallbackConfig,
  SMSConfig,
  EmailConfig,
  WebhookConfig,
  FallbackAttempt,
  DeliveryReport,
};

export default MobileFallbackService;