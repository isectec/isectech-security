/**
 * Notification Preferences API
 * Manages user notification preferences and delivery settings
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
const channelPreferencesSchema = z.object({
  push: z.object({
    enabled: z.boolean(),
    quietHours: z.object({
      enabled: z.boolean(),
      startTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).optional(),
      endTime: z.string().regex(/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/).optional(),
      timezone: z.string().optional(),
    }).optional(),
    categories: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])),
    priorities: z.array(z.enum(['low', 'medium', 'high', 'critical'])),
    deviceTypes: z.array(z.enum(['mobile', 'desktop', 'web'])),
  }),
  email: z.object({
    enabled: z.boolean(),
    frequency: z.enum(['immediate', 'hourly', 'daily', 'weekly']),
    categories: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])),
    priorities: z.array(z.enum(['low', 'medium', 'high', 'critical'])),
    digest: z.boolean().optional(),
  }),
  sms: z.object({
    enabled: z.boolean(),
    emergencyOnly: z.boolean(),
    categories: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])),
    priorities: z.array(z.enum(['low', 'medium', 'high', 'critical'])),
  }),
  webhook: z.object({
    enabled: z.boolean(),
    url: z.string().url().optional(),
    headers: z.record(z.string()).optional(),
    categories: z.array(z.enum(['security', 'alert', 'info', 'warning', 'error'])),
    priorities: z.array(z.enum(['low', 'medium', 'high', 'critical'])),
    retryPolicy: z.object({
      maxRetries: z.number().min(0).max(10),
      retryDelay: z.number().min(1000).max(300000), // 1s to 5min
      backoffMultiplier: z.number().min(1).max(5),
    }).optional(),
  }),
});

const preferencesUpdateSchema = z.object({
  channels: channelPreferencesSchema.partial(),
  globalSettings: z.object({
    doNotDisturb: z.boolean().optional(),
    language: z.enum(['en', 'es', 'fr', 'de', 'ja', 'zh']).optional(),
    timezone: z.string().optional(),
    groupNotifications: z.boolean().optional(),
    soundEnabled: z.boolean().optional(),
    vibrationEnabled: z.boolean().optional(),
  }).optional(),
  smartFiltering: z.object({
    enabled: z.boolean().optional(),
    duplicateDetection: z.boolean().optional(),
    priorityBoost: z.boolean().optional(),
    intelligentScheduling: z.boolean().optional(),
  }).optional(),
});

interface PreferencesService {
  getUserPreferences(userId: string, tenantId: string): Promise<any>;
  updateUserPreferences(userId: string, tenantId: string, preferences: any): Promise<any>;
  resetUserPreferences(userId: string, tenantId: string): Promise<any>;
  getDefaultPreferences(tenantId: string): Promise<any>;
  validatePreferences(preferences: any): Promise<{ isValid: boolean; errors?: any[] }>;
}

// Mock preferences service
class MockPreferencesService implements PreferencesService {
  private preferences: Map<string, any> = new Map();

  private getKey(userId: string, tenantId: string): string {
    return `${tenantId}:${userId}`;
  }

  private getDefaultPreferences(): any {
    return {
      channels: {
        push: {
          enabled: true,
          quietHours: {
            enabled: true,
            startTime: '22:00',
            endTime: '07:00',
            timezone: 'UTC',
          },
          categories: ['security', 'alert', 'error'],
          priorities: ['medium', 'high', 'critical'],
          deviceTypes: ['mobile', 'desktop', 'web'],
        },
        email: {
          enabled: true,
          frequency: 'daily',
          categories: ['security', 'alert', 'info', 'warning', 'error'],
          priorities: ['high', 'critical'],
          digest: true,
        },
        sms: {
          enabled: false,
          emergencyOnly: true,
          categories: ['security', 'error'],
          priorities: ['critical'],
        },
        webhook: {
          enabled: false,
          categories: [],
          priorities: [],
        },
      },
      globalSettings: {
        doNotDisturb: false,
        language: 'en',
        timezone: 'UTC',
        groupNotifications: true,
        soundEnabled: true,
        vibrationEnabled: true,
      },
      smartFiltering: {
        enabled: true,
        duplicateDetection: true,
        priorityBoost: true,
        intelligentScheduling: false,
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  async getUserPreferences(userId: string, tenantId: string) {
    const key = this.getKey(userId, tenantId);
    return this.preferences.get(key) || this.getDefaultPreferences();
  }

  async updateUserPreferences(userId: string, tenantId: string, preferences: any) {
    const key = this.getKey(userId, tenantId);
    const existing = this.preferences.get(key) || this.getDefaultPreferences();
    
    const updated = {
      ...existing,
      ...preferences,
      channels: {
        ...existing.channels,
        ...preferences.channels,
      },
      globalSettings: {
        ...existing.globalSettings,
        ...preferences.globalSettings,
      },
      smartFiltering: {
        ...existing.smartFiltering,
        ...preferences.smartFiltering,
      },
      updatedAt: new Date().toISOString(),
    };

    this.preferences.set(key, updated);
    return updated;
  }

  async resetUserPreferences(userId: string, tenantId: string) {
    const key = this.getKey(userId, tenantId);
    const defaults = this.getDefaultPreferences();
    this.preferences.set(key, defaults);
    return defaults;
  }

  async getDefaultPreferences(tenantId: string) {
    return this.getDefaultPreferences();
  }

  async validatePreferences(preferences: any) {
    const validationResult = preferencesUpdateSchema.safeParse(preferences);
    if (!validationResult.success) {
      return {
        isValid: false,
        errors: validationResult.error.issues,
      };
    }

    // Additional business logic validation
    const errors = [];

    // Validate quiet hours
    if (preferences.channels?.push?.quietHours?.enabled) {
      const { startTime, endTime } = preferences.channels.push.quietHours;
      if (startTime && endTime && startTime === endTime) {
        errors.push({
          path: ['channels', 'push', 'quietHours'],
          message: 'Start time and end time cannot be the same',
        });
      }
    }

    // Validate webhook URL if webhook is enabled
    if (preferences.channels?.webhook?.enabled && !preferences.channels?.webhook?.url) {
      errors.push({
        path: ['channels', 'webhook', 'url'],
        message: 'Webhook URL is required when webhook channel is enabled',
      });
    }

    return {
      isValid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }
}

const preferencesService = new MockPreferencesService();

// GET /api/notifications/preferences - Get user preferences
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 200,
      keyGenerator: (req) => `preferences:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Get user ID from query or use authenticated user
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId') || user.id;

    // Authorization check for accessing other users' preferences
    if (userId !== user.id) {
      const hasPermission = await authorize(user, 'notifications:preferences:read:others');
      if (!hasPermission) {
        return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
      }
    }

    // Get preferences
    const preferences = await preferencesService.getUserPreferences(userId, tenantValidation.tenantId);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'preferences.read',
      resource: 'notification_preferences',
      resourceId: userId,
      metadata: { targetUserId: userId },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('preferences.api.get.success', {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: preferences,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Preferences API GET error:', error);
    
    metrics.increment('preferences.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get preferences',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// PUT /api/notifications/preferences - Update user preferences
export async function PUT(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 50, // More restrictive for updates
      keyGenerator: (req) => `preferences:update:${req.headers.get('x-forwarded-for') || 'unknown'}`,
    });

    if (!rateLimitResult.success) {
      return NextResponse.json(
        { error: 'Rate limit exceeded', retryAfter: rateLimitResult.retryAfter },
        { status: 429, headers: { 'Retry-After': rateLimitResult.retryAfter?.toString() || '60' } }
      );
    }

    // Authentication
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
    
    const { userId: targetUserId, preferences } = sanitizedBody;
    const userId = targetUserId || user.id;

    // Authorization check for updating other users' preferences
    if (userId !== user.id) {
      const hasPermission = await authorize(user, 'notifications:preferences:update:others');
      if (!hasPermission) {
        return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
      }
    }

    // Validate preferences
    const validation = await preferencesService.validatePreferences(preferences);
    if (!validation.isValid) {
      return NextResponse.json(
        { error: 'Invalid preferences', details: validation.errors },
        { status: 400 }
      );
    }

    // Update preferences
    const updatedPreferences = await preferencesService.updateUserPreferences(
      userId, 
      tenantValidation.tenantId, 
      preferences
    );

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'preferences.update',
      resource: 'notification_preferences',
      resourceId: userId,
      metadata: { 
        targetUserId: userId,
        updatedFields: Object.keys(preferences),
      },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('preferences.api.put.success', {
      tenantId: tenantValidation.tenantId,
    });

    metrics.histogram('preferences.api.put.duration', Date.now() - startTime, {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: updatedPreferences,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Preferences API PUT error:', error);
    
    metrics.increment('preferences.api.put.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to update preferences',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// DELETE /api/notifications/preferences - Reset to default preferences
export async function DELETE(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Authentication
    const user = await authenticate(request);
    if (!user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Tenant validation
    const tenantValidation = await validateTenant(request, user);
    if (!tenantValidation.isValid) {
      return NextResponse.json({ error: 'Invalid tenant' }, { status: 400 });
    }

    // Get user ID from query or use authenticated user
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId') || user.id;

    // Authorization check
    if (userId !== user.id) {
      const hasPermission = await authorize(user, 'notifications:preferences:delete:others');
      if (!hasPermission) {
        return NextResponse.json({ error: 'Insufficient permissions' }, { status: 403 });
      }
    }

    // Reset to defaults
    const defaultPreferences = await preferencesService.resetUserPreferences(
      userId,
      tenantValidation.tenantId
    );

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'preferences.reset',
      resource: 'notification_preferences',
      resourceId: userId,
      metadata: { targetUserId: userId },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('preferences.api.delete.success', {
      tenantId: tenantValidation.tenantId,
    });

    return NextResponse.json({
      success: true,
      data: defaultPreferences,
      message: 'Preferences reset to default values',
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    });

  } catch (error: any) {
    logger.error('Preferences API DELETE error:', error);
    
    metrics.increment('preferences.api.delete.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to reset preferences',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}