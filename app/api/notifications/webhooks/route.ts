/**
 * Webhook Integration API
 * Manages webhook endpoints for notification integrations with external systems
 */

import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { rateLimit } from '@/lib/middleware/rate-limiting';
import { authenticate, authorize } from '@/lib/middleware/auth';
import { validateTenant } from '@/lib/middleware/tenant-validation';
import { auditLog } from '@/lib/middleware/audit-logging';
import { sanitizeInput } from '@/lib/utils/input-sanitization';
import { metrics } from '@/lib/monitoring/metrics';
import { logger } from '@/lib/utils/logger';
import { createHmac } from 'crypto';

// Validation schemas
const webhookSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  url: z.string().url(),
  method: z.enum(['POST', 'PUT', 'PATCH']).default('POST'),
  headers: z.record(z.string()).optional(),
  authentication: z.object({
    type: z.enum(['none', 'bearer', 'basic', 'api_key', 'hmac']),
    credentials: z.record(z.string()).optional(),
    hmacSecret: z.string().optional(),
    hmacAlgorithm: z.enum(['sha256', 'sha512']).default('sha256'),
  }).optional(),
  eventTypes: z.array(z.enum([
    'notification.sent',
    'notification.delivered', 
    'notification.read',
    'notification.clicked',
    'notification.failed',
    'schedule.created',
    'schedule.executed',
    'template.updated',
    'user.preferences_changed'
  ])),
  filters: z.object({
    types: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])).optional(),
    priorities: z.array(z.enum(['low', 'medium', 'high', 'critical'])).optional(),
    channels: z.array(z.enum(['push', 'email', 'sms', 'webhook'])).optional(),
    userSegments: z.array(z.string()).optional(),
  }).optional(),
  retryPolicy: z.object({
    enabled: z.boolean().default(true),
    maxRetries: z.number().min(0).max(10).default(3),
    retryDelay: z.number().min(1000).max(300000).default(5000), // 5s default
    backoffMultiplier: z.number().min(1).max(5).default(2),
    retryOn: z.array(z.number()).default([408, 429, 500, 502, 503, 504]),
  }).optional(),
  rateLimiting: z.object({
    enabled: z.boolean().default(false),
    requestsPerSecond: z.number().min(1).max(1000).optional(),
    burstSize: z.number().min(1).max(10000).optional(),
  }).optional(),
  isActive: z.boolean().default(true),
  metadata: z.record(z.any()).optional(),
});

const webhookQuerySchema = z.object({
  isActive: z.boolean().optional(),
  eventType: z.enum([
    'notification.sent', 'notification.delivered', 'notification.read',
    'notification.clicked', 'notification.failed', 'schedule.created',
    'schedule.executed', 'template.updated', 'user.preferences_changed'
  ]).optional(),
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
});

const webhookTestSchema = z.object({
  webhookId: z.string(),
  eventType: z.enum([
    'notification.sent', 'notification.delivered', 'notification.read',
    'notification.clicked', 'notification.failed', 'schedule.created',
    'schedule.executed', 'template.updated', 'user.preferences_changed'
  ]),
  testPayload: z.record(z.any()).optional(),
});

interface WebhookService {
  createWebhook(webhook: any): Promise<any>;
  getWebhooks(query: any): Promise<any>;
  getWebhook(id: string): Promise<any>;
  updateWebhook(id: string, updates: any): Promise<any>;
  deleteWebhook(id: string): Promise<boolean>;
  testWebhook(id: string, eventType: string, testPayload?: any): Promise<any>;
  getWebhookLogs(id: string, params: any): Promise<any>;
  executeWebhook(webhook: any, event: any): Promise<any>;
  validateWebhookSignature(webhook: any, payload: string, signature: string): boolean;
}

// Mock webhook service
class MockWebhookService implements WebhookService {
  private webhooks: Map<string, any> = new Map();
  private webhookLogs: Map<string, any[]> = new Map();
  private nextId = 1;

  constructor() {
    this.seedWebhooks();
  }

  private seedWebhooks() {
    const sampleWebhooks = [
      {
        id: '1',
        name: 'Slack Integration',
        description: 'Send notifications to Slack channels',
        url: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
        method: 'POST',
        eventTypes: ['notification.sent', 'notification.failed'],
        isActive: true,
        createdAt: new Date().toISOString(),
        lastTriggered: new Date(Date.now() - 3600000).toISOString(), // 1 hour ago
        successCount: 245,
        failureCount: 3,
      },
      {
        id: '2',
        name: 'External SIEM',
        description: 'Forward security events to external SIEM system',
        url: 'https://api.siem-system.com/webhooks/isectech',
        method: 'POST',
        eventTypes: ['notification.sent'],
        filters: {
          types: ['security', 'error'],
          priorities: ['high', 'critical'],
        },
        authentication: {
          type: 'api_key',
          credentials: { 'X-API-Key': 'redacted' },
        },
        isActive: true,
        createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days ago
        lastTriggered: new Date(Date.now() - 300000).toISOString(), // 5 minutes ago
        successCount: 1052,
        failureCount: 12,
      },
    ];

    sampleWebhooks.forEach(webhook => {
      this.webhooks.set(webhook.id, webhook);
      this.webhookLogs.set(webhook.id, []);
      this.nextId = Math.max(this.nextId, parseInt(webhook.id) + 1);
    });
  }

  async createWebhook(webhook: any) {
    const newWebhook = {
      id: (this.nextId++).toString(),
      ...webhook,
      successCount: 0,
      failureCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.webhooks.set(newWebhook.id, newWebhook);
    this.webhookLogs.set(newWebhook.id, []);

    return newWebhook;
  }

  async getWebhooks(query: any) {
    const { limit, offset, isActive, eventType } = query;
    
    let filtered = Array.from(this.webhooks.values()).filter(webhook => {
      if (typeof isActive === 'boolean' && webhook.isActive !== isActive) return false;
      if (eventType && !webhook.eventTypes.includes(eventType)) return false;
      return true;
    });

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return {
      webhooks: paginated,
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    };
  }

  async getWebhook(id: string) {
    const webhook = this.webhooks.get(id);
    if (!webhook) {
      throw new Error('Webhook not found');
    }
    return webhook;
  }

  async updateWebhook(id: string, updates: any) {
    const webhook = this.webhooks.get(id);
    if (!webhook) {
      throw new Error('Webhook not found');
    }

    const updatedWebhook = {
      ...webhook,
      ...updates,
      id, // Preserve ID
      createdAt: webhook.createdAt, // Preserve creation date
      updatedAt: new Date().toISOString(),
    };

    this.webhooks.set(id, updatedWebhook);
    return updatedWebhook;
  }

  async deleteWebhook(id: string) {
    const deleted = this.webhooks.delete(id);
    if (deleted) {
      this.webhookLogs.delete(id);
    }
    return deleted;
  }

  async testWebhook(id: string, eventType: string, testPayload?: any) {
    const webhook = await this.getWebhook(id);
    
    const defaultPayload = {
      eventType,
      timestamp: new Date().toISOString(),
      tenantId: 'test-tenant',
      data: {
        notificationId: 'test-notification-001',
        type: 'info',
        priority: 'medium',
        title: 'Test Notification',
        message: 'This is a test webhook notification',
        recipients: [{ userId: 'test-user', channel: 'push' }],
      },
      metadata: {
        source: 'webhook-test',
        requestId: `test-${Date.now()}`,
      },
    };

    const payload = testPayload || defaultPayload;
    
    // Simulate webhook execution
    const executionResult = await this.executeWebhook(webhook, payload);
    
    // Log the test execution
    const logEntry = {
      id: `log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      eventType,
      payload,
      response: executionResult,
      status: executionResult.success ? 'success' : 'failed',
      duration: executionResult.duration,
      isTest: true,
    };

    const logs = this.webhookLogs.get(id) || [];
    logs.unshift(logEntry);
    this.webhookLogs.set(id, logs.slice(0, 1000)); // Keep last 1000 logs

    return {
      success: executionResult.success,
      testResult: logEntry,
      webhook: {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
      },
    };
  }

  async getWebhookLogs(id: string, params: any) {
    const logs = this.webhookLogs.get(id) || [];
    const { limit = 50, offset = 0, status, eventType } = params;
    
    let filtered = logs.filter(log => {
      if (status && log.status !== status) return false;
      if (eventType && log.eventType !== eventType) return false;
      return true;
    });

    const paginated = filtered.slice(offset, offset + limit);
    
    return {
      logs: paginated,
      total: filtered.length,
      limit,
      offset,
      hasMore: offset + limit < filtered.length,
      summary: {
        totalRequests: logs.length,
        successRate: logs.length > 0 ? (logs.filter(l => l.status === 'success').length / logs.length) * 100 : 0,
        averageLatency: logs.length > 0 ? logs.reduce((sum, l) => sum + (l.duration || 0), 0) / logs.length : 0,
      },
    };
  }

  async executeWebhook(webhook: any, event: any) {
    const startTime = Date.now();
    
    try {
      // Simulate HTTP request execution
      const delay = Math.random() * 500 + 100; // 100-600ms
      await new Promise(resolve => setTimeout(resolve, delay));
      
      // Simulate occasional failures
      const shouldFail = Math.random() < 0.05; // 5% failure rate
      
      if (shouldFail) {
        throw new Error('Simulated webhook failure');
      }

      // Update success count
      const updatedWebhook = await this.updateWebhook(webhook.id, {
        successCount: webhook.successCount + 1,
        lastTriggered: new Date().toISOString(),
      });

      return {
        success: true,
        statusCode: 200,
        duration: Date.now() - startTime,
        response: { message: 'Webhook executed successfully' },
      };

    } catch (error: any) {
      // Update failure count
      await this.updateWebhook(webhook.id, {
        failureCount: webhook.failureCount + 1,
        lastTriggered: new Date().toISOString(),
      });

      return {
        success: false,
        statusCode: 500,
        duration: Date.now() - startTime,
        error: error.message,
      };
    }
  }

  validateWebhookSignature(webhook: any, payload: string, signature: string): boolean {
    if (!webhook.authentication?.hmacSecret) {
      return true; // No signature validation required
    }

    const algorithm = webhook.authentication.hmacAlgorithm || 'sha256';
    const expectedSignature = createHmac(algorithm, webhook.authentication.hmacSecret)
      .update(payload)
      .digest('hex');
    
    const providedSignature = signature.replace('sha256=', '').replace('sha512=', '');
    
    return expectedSignature === providedSignature;
  }
}

const webhookService = new MockWebhookService();

// GET /api/notifications/webhooks - Get webhooks
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 200,
      keyGenerator: (req) => `webhooks:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const hasPermission = await authorize(user, 'notifications:webhooks:read');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse query parameters
    const { searchParams } = new URL(request.url);
    const queryParams = Object.fromEntries(searchParams);
    
    const validationResult = webhookQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Handle special endpoints
    const webhookId = searchParams.get('id');
    const endpoint = searchParams.get('endpoint');
    
    if (webhookId && endpoint === 'logs') {
      const logs = await webhookService.getWebhookLogs(webhookId, {
        limit: parseInt(searchParams.get('limit') || '50'),
        offset: parseInt(searchParams.get('offset') || '0'),
        status: searchParams.get('status'),
        eventType: searchParams.get('eventType'),
      });
      
      return NextResponse.json({
        success: true,
        data: logs,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    // Get webhooks
    const result = await webhookService.getWebhooks(validationResult.data);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'webhooks.list',
      resource: 'notification_webhooks',
      metadata: { query: validationResult.data },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('webhooks.api.get.success', {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: result,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Webhooks API GET error:', error);
    
    metrics.increment('webhooks.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get webhooks',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/notifications/webhooks - Create webhook or test webhook
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 50,
      keyGenerator: (req) => `webhooks:create:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication & Authorization
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse and validate request body
    const body = await request.json();
    const sanitizedBody = sanitizeInput(body);
    
    // Check if this is a test request
    if (sanitizedBody.action === 'test') {
      const hasTestPermission = await authorize(user, 'notifications:webhooks:test');
      if (!hasTestPermission) {
        return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
      }

      const testValidation = webhookTestSchema.safeParse(sanitizedBody);
      if (!testValidation.success) {
        return NextResponse.json(
          { error: 'Invalid test data', details: testValidation.error.issues },
          { status: 400 }
        );
      }

      const { webhookId, eventType, testPayload } = testValidation.data;
      
      // Test webhook
      const testResult = await webhookService.testWebhook(webhookId, eventType, testPayload);

      // Audit logging
      await auditLog({
        userId: user.id,
        tenantId: tenantValidation.tenantId,
        action: 'webhooks.test',
        resource: 'notification_webhooks',
        resourceId: webhookId,
        metadata: { eventType, success: testResult.success },
        timestamp: new Date(),
      });

      // Metrics
      metrics.increment('webhooks.api.test.success', {
        tenantId: tenantValidation.tenantId,
        eventType,
        success: testResult.success.toString(),
      });

      return NextResponse.json({
        success: true,
        data: testResult,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    // Create webhook
    const hasCreatePermission = await authorize(user, 'notifications:webhooks:create');
    if (!hasCreatePermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    const validationResult = webhookSchema.safeParse(sanitizedBody);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid webhook data', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Create webhook
    const webhook = await webhookService.createWebhook({
      ...validationResult.data,
      tenantId: tenantValidation.tenantId,
      createdBy: user.id,
    });

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'webhooks.create',
      resource: 'notification_webhooks',
      resourceId: webhook.id,
      metadata: { webhook: { id: webhook.id, name: webhook.name, url: webhook.url } },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('webhooks.api.post.success', {
      tenantId: tenantValidation.tenantId,
      eventTypesCount: webhook.eventTypes.length.toString(),
    });

    return NextResponse.json({
      success: true,
      data: webhook,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Webhooks API POST error:', error);
    
    metrics.increment('webhooks.api.post.error', {
      errorType: error.name,
    });

    const statusCode = error.message === 'Webhook not found' ? 404 : 500;

    return NextResponse.json(
      { 
        error: statusCode === 404 ? 'Webhook not found' : 'Failed to process webhook request',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: statusCode }
    );
  }
}