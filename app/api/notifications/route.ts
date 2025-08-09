/**
 * Notification Management API Routes
 * Production-grade REST API for mobile notification system
 * Supports push notifications, preferences, templating, and analytics
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

// Validation schemas
const notificationQuerySchema = z.object({
  userId: z.string().optional(),
  tenantId: z.string().optional(),
  status: z.enum(['sent', 'delivered', 'read', 'failed']).optional(),
  type: z.enum(['security', 'alert', 'info', 'warning', 'error']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(1000).default(50),
  offset: z.coerce.number().min(0).default(0),
  sortBy: z.enum(['timestamp', 'priority', 'status']).default('timestamp'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

const notificationCreateSchema = z.object({
  title: z.string().min(1).max(200),
  message: z.string().min(1).max(2000),
  type: z.enum(['security', 'alert', 'info', 'warning', 'error']),
  priority: z.enum(['low', 'medium', 'high', 'critical']),
  recipients: z.array(z.object({
    userId: z.string(),
    channel: z.enum(['push', 'email', 'sms', 'webhook']),
    metadata: z.record(z.any()).optional(),
  })),
  templateId: z.string().optional(),
  templateData: z.record(z.any()).optional(),
  scheduledFor: z.string().datetime().optional(),
  expiresAt: z.string().datetime().optional(),
  actions: z.array(z.object({
    label: z.string(),
    action: z.string(),
    url: z.string().url().optional(),
    metadata: z.record(z.any()).optional(),
  })).optional(),
  metadata: z.record(z.any()).optional(),
});

interface NotificationService {
  getNotifications(query: any): Promise<any>;
  createNotification(data: any): Promise<any>;
  updateNotificationStatus(id: string, status: string, metadata?: any): Promise<any>;
  deleteNotification(id: string): Promise<boolean>;
  getNotificationAnalytics(tenantId: string, params: any): Promise<any>;
}

// Mock notification service - replace with actual implementation
class MockNotificationService implements NotificationService {
  private notifications: any[] = [];
  private nextId = 1;

  async getNotifications(query: any) {
    const { limit, offset, sortBy, sortOrder, ...filters } = query;
    
    let filtered = this.notifications.filter((notification) => {
      if (filters.userId && notification.userId !== filters.userId) return false;
      if (filters.tenantId && notification.tenantId !== filters.tenantId) return false;
      if (filters.status && notification.status !== filters.status) return false;
      if (filters.type && notification.type !== filters.type) return false;
      if (filters.priority && notification.priority !== filters.priority) return false;
      if (filters.startDate && notification.createdAt < filters.startDate) return false;
      if (filters.endDate && notification.createdAt > filters.endDate) return false;
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      const aVal = a[sortBy] || 0;
      const bVal = b[sortBy] || 0;
      return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
    });

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return {
      notifications: paginated,
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    };
  }

  async createNotification(data: any) {
    const notification = {
      id: (this.nextId++).toString(),
      ...data,
      status: 'sent',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      deliveryAttempts: 0,
      deliveryResults: [],
    };

    this.notifications.push(notification);
    
    // Simulate notification sending
    setTimeout(async () => {
      await this.updateNotificationStatus(notification.id, 'delivered', {
        deliveredAt: new Date().toISOString(),
        channel: 'push',
      });
    }, 1000);

    return notification;
  }

  async updateNotificationStatus(id: string, status: string, metadata: any = {}) {
    const notification = this.notifications.find(n => n.id === id);
    if (!notification) {
      throw new Error('Notification not found');
    }

    notification.status = status;
    notification.updatedAt = new Date().toISOString();
    notification.deliveryResults.push({
      status,
      timestamp: new Date().toISOString(),
      ...metadata,
    });

    return notification;
  }

  async deleteNotification(id: string) {
    const index = this.notifications.findIndex(n => n.id === id);
    if (index === -1) return false;
    
    this.notifications.splice(index, 1);
    return true;
  }

  async getNotificationAnalytics(tenantId: string, params: any) {
    const tenantNotifications = this.notifications.filter(n => n.tenantId === tenantId);
    
    const analytics = {
      totalNotifications: tenantNotifications.length,
      byStatus: {},
      byType: {},
      byPriority: {},
      deliveryRate: 0,
      averageDeliveryTime: 0,
      trendsData: [],
    };

    // Calculate analytics
    tenantNotifications.forEach(n => {
      analytics.byStatus[n.status] = (analytics.byStatus[n.status] || 0) + 1;
      analytics.byType[n.type] = (analytics.byType[n.type] || 0) + 1;
      analytics.byPriority[n.priority] = (analytics.byPriority[n.priority] || 0) + 1;
    });

    const deliveredCount = analytics.byStatus['delivered'] || 0;
    analytics.deliveryRate = tenantNotifications.length > 0 
      ? (deliveredCount / tenantNotifications.length) * 100 
      : 0;

    return analytics;
  }
}

const notificationService = new MockNotificationService();

// GET /api/notifications - Retrieve notifications with filtering and pagination
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000, // 1 minute
      max: 1000, // 1000 requests per minute
      keyGenerator: (req) => `notifications:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:read');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse and validate query parameters
    const { searchParams } = new URL(request.url);
    const queryParams = Object.fromEntries(searchParams);
    
    const validationResult = notificationQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    const query = {
      ...validationResult.data,
      tenantId: tenantValidation.tenantId,
      userId: validationResult.data.userId || user.id,
    };

    // Fetch notifications
    const result = await notificationService.getNotifications(query);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'notifications.list',
      resource: 'notifications',
      metadata: { query },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('notifications.api.get.success', {
      tenantId: tenantValidation.tenantId,
      userId: user.id,
    });

    metrics.histogram('notifications.api.get.duration', Date.now() - startTime, {
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
    logger.error('Notification API GET error:', error);
    
    metrics.increment('notifications.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Internal server error',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/notifications - Create new notification
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting - more restrictive for create operations
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000, // 1 minute
      max: 100, // 100 creates per minute
      keyGenerator: (req) => `notifications:create:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:create');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Parse and validate request body
    const body = await request.json();
    const sanitizedBody = sanitizeInput(body);
    
    const validationResult = notificationCreateSchema.safeParse(sanitizedBody);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid request data', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    const notificationData = {
      ...validationResult.data,
      tenantId: tenantValidation.tenantId,
      createdBy: user.id,
    };

    // Create notification
    const notification = await notificationService.createNotification(notificationData);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'notifications.create',
      resource: 'notifications',
      resourceId: notification.id,
      metadata: { notification: { id: notification.id, type: notification.type } },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('notifications.api.post.success', {
      tenantId: tenantValidation.tenantId,
      type: notification.type,
      priority: notification.priority,
    });

    metrics.histogram('notifications.api.post.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: notification,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Notification API POST error:', error);
    
    metrics.increment('notifications.api.post.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to create notification',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// PUT /api/notifications - Bulk update notifications
export async function PUT(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 50, // More restrictive for bulk operations
      keyGenerator: (req) => `notifications:bulk:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:update');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    const body = await request.json();
    const { notificationIds, updates } = sanitizeInput(body);

    if (!Array.isArray(notificationIds) || notificationIds.length === 0) {
      return NextResponse.json(
        { error: 'notificationIds array is required and cannot be empty' },
        { status: 400 }
      );
    }

    if (notificationIds.length > 100) {
      return NextResponse.json(
        { error: 'Cannot update more than 100 notifications at once' },
        { status: 400 }
      );
    }

    // Process bulk updates
    const results = [];
    for (const id of notificationIds) {
      try {
        const result = await notificationService.updateNotificationStatus(
          id, 
          updates.status, 
          updates.metadata
        );
        results.push({ id, success: true, notification: result });
      } catch (error: any) {
        results.push({ id, success: false, error: error.message });
      }
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.length - successCount;

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'notifications.bulk_update',
      resource: 'notifications',
      metadata: { 
        updated: successCount, 
        failed: failureCount, 
        updates 
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('notifications.api.bulk_update.success', {
      tenantId: tenantValidation.tenantId,
    });

    metrics.histogram('notifications.api.bulk_update.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: {
        results,
        summary: {
          total: results.length,
          successful: successCount,
          failed: failureCount,
        },
      },
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Notification API PUT error:', error);
    
    metrics.increment('notifications.api.bulk_update.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to update notifications',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// DELETE /api/notifications - Bulk delete notifications
export async function DELETE(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 20, // Very restrictive for delete operations
      keyGenerator: (req) => `notifications:delete:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:delete');
    if (!hasPermission) {
      return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    const body = await request.json();
    const { notificationIds } = sanitizeInput(body);

    if (!Array.isArray(notificationIds) || notificationIds.length === 0) {
      return NextResponse.json(
        { error: 'notificationIds array is required and cannot be empty' },
        { status: 400 }
      );
    }

    if (notificationIds.length > 50) {
      return NextResponse.json(
        { error: 'Cannot delete more than 50 notifications at once' },
        { status: 400 }
      );
    }

    // Process bulk deletes
    const results = [];
    for (const id of notificationIds) {
      try {
        const success = await notificationService.deleteNotification(id);
        results.push({ id, success, deleted: success });
      } catch (error: any) {
        results.push({ id, success: false, error: error.message });
      }
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.length - successCount;

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'notifications.bulk_delete',
      resource: 'notifications',
      metadata: { 
        deleted: successCount, 
        failed: failureCount,
        notificationIds 
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('notifications.api.bulk_delete.success', {
      tenantId: tenantValidation.tenantId,
    });

    metrics.histogram('notifications.api.bulk_delete.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: {
        results,
        summary: {
          total: results.length,
          deleted: successCount,
          failed: failureCount,
        },
      },
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Notification API DELETE error:', error);
    
    metrics.increment('notifications.api.bulk_delete.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to delete notifications',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}