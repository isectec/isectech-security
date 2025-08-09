/**
 * Notification Scheduling API
 * Manages scheduled notifications and batching operations
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
const scheduleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  templateId: z.string(),
  templateVariables: z.record(z.any()).optional(),
  recipients: z.array(z.object({
    userId: z.string(),
    channel: z.enum(['push', 'email', 'sms', 'webhook']),
    personalizedVariables: z.record(z.any()).optional(),
  })),
  schedule: z.object({
    type: z.enum(['immediate', 'delayed', 'recurring', 'conditional']),
    scheduledFor: z.string().datetime().optional(),
    timezone: z.string().default('UTC'),
    recurrence: z.object({
      pattern: z.enum(['daily', 'weekly', 'monthly', 'yearly', 'custom']),
      interval: z.number().min(1).max(365).optional(),
      daysOfWeek: z.array(z.number().min(0).max(6)).optional(),
      daysOfMonth: z.array(z.number().min(1).max(31)).optional(),
      endDate: z.string().datetime().optional(),
      maxOccurrences: z.number().min(1).max(1000).optional(),
    }).optional(),
    conditions: z.array(z.object({
      type: z.enum(['user_activity', 'system_event', 'time_based', 'data_threshold']),
      operator: z.enum(['equals', 'not_equals', 'greater_than', 'less_than', 'contains']),
      value: z.any(),
      metadata: z.record(z.any()).optional(),
    })).optional(),
  }),
  batching: z.object({
    enabled: z.boolean().default(false),
    batchSize: z.number().min(1).max(10000).optional(),
    batchInterval: z.number().min(60).max(86400).optional(), // seconds
    strategy: z.enum(['size_based', 'time_based', 'hybrid']).optional(),
  }).optional(),
  preferences: z.object({
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    respectQuietHours: z.boolean().default(true),
    allowDuplicates: z.boolean().default(false),
    retryPolicy: z.object({
      maxRetries: z.number().min(0).max(10).default(3),
      retryDelay: z.number().min(1000).max(3600000).default(60000), // 1min default
      backoffMultiplier: z.number().min(1).max(10).default(2),
    }).optional(),
  }).optional(),
  metadata: z.record(z.any()).optional(),
  isActive: z.boolean().default(true),
});

const scheduleQuerySchema = z.object({
  status: z.enum(['active', 'paused', 'completed', 'failed']).optional(),
  type: z.enum(['immediate', 'delayed', 'recurring', 'conditional']).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
  sortBy: z.enum(['created', 'scheduled', 'name', 'priority']).default('created'),
  sortOrder: z.enum(['asc', 'desc']).default('desc'),
});

interface SchedulingService {
  createSchedule(schedule: any): Promise<any>;
  getSchedules(query: any): Promise<any>;
  getSchedule(id: string): Promise<any>;
  updateSchedule(id: string, updates: any): Promise<any>;
  deleteSchedule(id: string): Promise<boolean>;
  pauseSchedule(id: string): Promise<any>;
  resumeSchedule(id: string): Promise<any>;
  getScheduleHistory(id: string, params: any): Promise<any>;
  getBatchingStatus(params: any): Promise<any>;
  processPendingSchedules(): Promise<any>;
}

// Mock scheduling service
class MockSchedulingService implements SchedulingService {
  private schedules: Map<string, any> = new Map();
  private scheduleHistory: Map<string, any[]> = new Map();
  private nextId = 1;

  constructor() {
    this.seedSchedules();
  }

  private seedSchedules() {
    const sampleSchedules = [
      {
        id: '1',
        name: 'Daily Security Digest',
        description: 'Daily security summary for all users',
        templateId: '1',
        recipients: [
          { userId: 'user1', channel: 'email' },
          { userId: 'user2', channel: 'email' },
        ],
        schedule: {
          type: 'recurring',
          scheduledFor: '2025-01-08T08:00:00Z',
          timezone: 'UTC',
          recurrence: {
            pattern: 'daily',
            interval: 1,
          },
        },
        status: 'active',
        nextRun: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        lastRun: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
        runCount: 45,
        createdAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: '2',
        name: 'Critical Alert Batch',
        description: 'Batched critical alerts for management team',
        templateId: '2',
        recipients: [
          { userId: 'admin1', channel: 'push' },
          { userId: 'admin2', channel: 'sms' },
        ],
        schedule: {
          type: 'conditional',
          conditions: [
            {
              type: 'data_threshold',
              operator: 'greater_than',
              value: 5,
              metadata: { metric: 'critical_alerts_count' },
            },
          ],
        },
        batching: {
          enabled: true,
          batchSize: 10,
          strategy: 'hybrid',
        },
        status: 'active',
        runCount: 12,
        createdAt: new Date(Date.now() - 15 * 24 * 60 * 60 * 1000).toISOString(),
      },
    ];

    sampleSchedules.forEach(schedule => {
      this.schedules.set(schedule.id, schedule);
      this.scheduleHistory.set(schedule.id, []);
      this.nextId = Math.max(this.nextId, parseInt(schedule.id) + 1);
    });
  }

  async createSchedule(schedule: any) {
    const newSchedule = {
      id: (this.nextId++).toString(),
      ...schedule,
      status: 'active',
      runCount: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Calculate next run time
    if (schedule.schedule.type === 'delayed' || schedule.schedule.type === 'recurring') {
      newSchedule.nextRun = schedule.schedule.scheduledFor;
    } else if (schedule.schedule.type === 'immediate') {
      newSchedule.nextRun = new Date().toISOString();
    }

    this.schedules.set(newSchedule.id, newSchedule);
    this.scheduleHistory.set(newSchedule.id, []);

    return newSchedule;
  }

  async getSchedules(query: any) {
    const { limit, offset, sortBy, sortOrder, status, type, startDate, endDate } = query;
    
    let filtered = Array.from(this.schedules.values()).filter(schedule => {
      if (status && schedule.status !== status) return false;
      if (type && schedule.schedule.type !== type) return false;
      if (startDate && schedule.createdAt < startDate) return false;
      if (endDate && schedule.createdAt > endDate) return false;
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let aVal, bVal;
      switch (sortBy) {
        case 'created':
          aVal = new Date(a.createdAt).getTime();
          bVal = new Date(b.createdAt).getTime();
          break;
        case 'scheduled':
          aVal = new Date(a.nextRun || 0).getTime();
          bVal = new Date(b.nextRun || 0).getTime();
          break;
        case 'name':
          aVal = a.name;
          bVal = b.name;
          break;
        case 'priority':
          const priorities = { low: 1, medium: 2, high: 3, critical: 4 };
          aVal = priorities[a.preferences?.priority] || 2;
          bVal = priorities[b.preferences?.priority] || 2;
          break;
        default:
          aVal = 0;
          bVal = 0;
      }
      
      return sortOrder === 'asc' ? (aVal > bVal ? 1 : -1) : (aVal < bVal ? 1 : -1);
    });

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return {
      schedules: paginated,
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    };
  }

  async getSchedule(id: string) {
    const schedule = this.schedules.get(id);
    if (!schedule) {
      throw new Error('Schedule not found');
    }
    return schedule;
  }

  async updateSchedule(id: string, updates: any) {
    const schedule = this.schedules.get(id);
    if (!schedule) {
      throw new Error('Schedule not found');
    }

    const updatedSchedule = {
      ...schedule,
      ...updates,
      id, // Preserve ID
      createdAt: schedule.createdAt, // Preserve creation date
      updatedAt: new Date().toISOString(),
    };

    this.schedules.set(id, updatedSchedule);
    return updatedSchedule;
  }

  async deleteSchedule(id: string) {
    const deleted = this.schedules.delete(id);
    if (deleted) {
      this.scheduleHistory.delete(id);
    }
    return deleted;
  }

  async pauseSchedule(id: string) {
    const schedule = await this.getSchedule(id);
    return this.updateSchedule(id, { status: 'paused' });
  }

  async resumeSchedule(id: string) {
    const schedule = await this.getSchedule(id);
    return this.updateSchedule(id, { status: 'active' });
  }

  async getScheduleHistory(id: string, params: any) {
    const history = this.scheduleHistory.get(id) || [];
    const { limit = 50, offset = 0 } = params;
    
    // Mock history data
    const mockHistory = Array.from({ length: Math.min(100, limit + offset) }, (_, i) => ({
      id: `${id}-run-${i + 1}`,
      scheduleId: id,
      executedAt: new Date(Date.now() - (i + 1) * 24 * 60 * 60 * 1000).toISOString(),
      status: Math.random() > 0.05 ? 'completed' : 'failed',
      recipientCount: Math.floor(Math.random() * 100) + 10,
      deliveredCount: Math.floor(Math.random() * 90) + 5,
      duration: Math.floor(Math.random() * 5000) + 100, // ms
      errors: Math.random() > 0.9 ? [{ message: 'Rate limit exceeded' }] : [],
    }));

    const paginated = mockHistory.slice(offset, offset + limit);
    
    return {
      history: paginated,
      total: mockHistory.length,
      limit,
      offset,
      hasMore: offset + limit < mockHistory.length,
    };
  }

  async getBatchingStatus(params: any) {
    return {
      overview: {
        totalBatches: 45,
        activeBatches: 3,
        queuedNotifications: 1250,
        processedToday: 12450,
      },
      activeBatches: [
        {
          id: 'batch-001',
          scheduleId: '2',
          size: 150,
          targetSize: 200,
          strategy: 'hybrid',
          startedAt: new Date(Date.now() - 300000).toISOString(), // 5 min ago
          estimatedCompletion: new Date(Date.now() + 180000).toISOString(), // 3 min from now
        },
      ],
      queueStats: {
        totalQueued: 1250,
        byPriority: {
          critical: 25,
          high: 150,
          medium: 800,
          low: 275,
        },
        byChannel: {
          push: 750,
          email: 400,
          sms: 75,
          webhook: 25,
        },
        averageWaitTime: 45, // seconds
      },
      performance: {
        throughput: {
          current: 850, // notifications per minute
          peak: 1200,
          average: 650,
        },
        efficiency: {
          batchingReduction: 35.2, // percentage
          costSavings: 28.5, // percentage
        },
      },
    };
  }

  async processPendingSchedules() {
    const now = new Date();
    const pendingSchedules = Array.from(this.schedules.values())
      .filter(schedule => 
        schedule.status === 'active' && 
        schedule.nextRun && 
        new Date(schedule.nextRun) <= now
      );

    const processed = [];
    for (const schedule of pendingSchedules) {
      // Simulate processing
      const result = {
        scheduleId: schedule.id,
        executedAt: now.toISOString(),
        recipientCount: schedule.recipients.length,
        status: Math.random() > 0.02 ? 'completed' : 'failed',
        duration: Math.floor(Math.random() * 3000) + 500,
      };

      // Update schedule for next run (if recurring)
      if (schedule.schedule.type === 'recurring') {
        const nextRun = new Date(schedule.nextRun);
        switch (schedule.schedule.recurrence?.pattern) {
          case 'daily':
            nextRun.setDate(nextRun.getDate() + (schedule.schedule.recurrence.interval || 1));
            break;
          case 'weekly':
            nextRun.setDate(nextRun.getDate() + 7 * (schedule.schedule.recurrence.interval || 1));
            break;
          case 'monthly':
            nextRun.setMonth(nextRun.getMonth() + (schedule.schedule.recurrence.interval || 1));
            break;
        }
        
        await this.updateSchedule(schedule.id, {
          nextRun: nextRun.toISOString(),
          lastRun: now.toISOString(),
          runCount: schedule.runCount + 1,
        });
      } else {
        // One-time schedules are marked as completed
        await this.updateSchedule(schedule.id, {
          status: 'completed',
          lastRun: now.toISOString(),
          runCount: schedule.runCount + 1,
        });
      }

      processed.push(result);
    }

    return {
      processedCount: processed.length,
      results: processed,
      nextProcessTime: new Date(Date.now() + 60000).toISOString(), // Next minute
    };
  }
}

const schedulingService = new MockSchedulingService();

// GET /api/notifications/schedule - Get scheduled notifications
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 200,
      keyGenerator: (req) => `schedule:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:schedule:read');
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
    
    const validationResult = scheduleQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Handle special endpoints
    const endpoint = searchParams.get('endpoint');
    
    if (endpoint === 'batching') {
      const batchingStatus = await schedulingService.getBatchingStatus(validationResult.data);
      
      return NextResponse.json({
        success: true,
        data: batchingStatus,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

    // Get schedules
    const result = await schedulingService.getSchedules(validationResult.data);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'schedule.list',
      resource: 'notification_schedules',
      metadata: { query: validationResult.data },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('schedule.api.get.success', {
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
    logger.error('Schedule API GET error:', error);
    
    metrics.increment('schedule.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get schedules',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/notifications/schedule - Create new schedule
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 50,
      keyGenerator: (req) => `schedule:create:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:schedule:create');
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
    
    const validationResult = scheduleSchema.safeParse(sanitizedBody);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid schedule data', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Create schedule
    const schedule = await schedulingService.createSchedule({
      ...validationResult.data,
      tenantId: tenantValidation.tenantId,
      createdBy: user.id,
    });

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'schedule.create',
      resource: 'notification_schedules',
      resourceId: schedule.id,
      metadata: { 
        schedule: { 
          id: schedule.id, 
          name: schedule.name, 
          type: schedule.schedule.type 
        } 
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('schedule.api.post.success', {
      tenantId: tenantValidation.tenantId,
      scheduleType: schedule.schedule.type,
    });

    return NextResponse.json({
      success: true,
      data: schedule,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Schedule API POST error:', error);
    
    metrics.increment('schedule.api.post.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to create schedule',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}