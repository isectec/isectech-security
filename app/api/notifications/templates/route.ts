/**
 * Notification Templates API
 * Manages notification templates and personalization engine
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
const templateSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  category: z.enum(['security', 'alert', 'info', 'warning', 'error', 'system']),
  type: z.enum(['push', 'email', 'sms', 'webhook']),
  subject: z.string().min(1).max(200).optional(), // For email templates
  title: z.string().min(1).max(200),
  body: z.string().min(1).max(5000),
  variables: z.array(z.object({
    name: z.string().min(1).max(50),
    type: z.enum(['string', 'number', 'date', 'boolean', 'object', 'array']),
    required: z.boolean(),
    defaultValue: z.any().optional(),
    description: z.string().max(200).optional(),
    validation: z.object({
      minLength: z.number().min(0).optional(),
      maxLength: z.number().min(0).optional(),
      pattern: z.string().optional(),
      options: z.array(z.any()).optional(),
    }).optional(),
  })),
  localization: z.record(z.object({
    subject: z.string().optional(),
    title: z.string(),
    body: z.string(),
  })).optional(),
  metadata: z.record(z.any()).optional(),
  isActive: z.boolean().default(true),
  version: z.string().default('1.0.0'),
});

const templateQuerySchema = z.object({
  category: z.enum(['security', 'alert', 'info', 'warning', 'error', 'system']).optional(),
  type: z.enum(['push', 'email', 'sms', 'webhook']).optional(),
  isActive: z.boolean().optional(),
  search: z.string().max(100).optional(),
  limit: z.coerce.number().min(1).max(100).default(20),
  offset: z.coerce.number().min(0).default(0),
});

const renderSchema = z.object({
  templateId: z.string(),
  variables: z.record(z.any()),
  language: z.string().default('en'),
  personalizeFor: z.object({
    userId: z.string(),
    deviceType: z.enum(['mobile', 'desktop', 'tablet']).optional(),
    preferences: z.record(z.any()).optional(),
  }).optional(),
});

interface TemplateService {
  getTemplates(query: any): Promise<any>;
  getTemplate(id: string): Promise<any>;
  createTemplate(template: any): Promise<any>;
  updateTemplate(id: string, updates: any): Promise<any>;
  deleteTemplate(id: string): Promise<boolean>;
  renderTemplate(templateId: string, variables: any, options: any): Promise<any>;
  validateTemplate(template: any): Promise<{ isValid: boolean; errors?: any[] }>;
  duplicateTemplate(id: string, newName: string): Promise<any>;
}

// Mock template service
class MockTemplateService implements TemplateService {
  private templates: Map<string, any> = new Map();
  private nextId = 1;

  constructor() {
    this.seedTemplates();
  }

  private seedTemplates() {
    const defaultTemplates = [
      {
        id: '1',
        name: 'Security Alert',
        description: 'Template for security-related alerts',
        category: 'security',
        type: 'push',
        title: 'Security Alert: {{alertType}}',
        body: 'A {{severity}} security event has been detected: {{description}}. Please review immediately.',
        variables: [
          { name: 'alertType', type: 'string', required: true, description: 'Type of security alert' },
          { name: 'severity', type: 'string', required: true, description: 'Alert severity level' },
          { name: 'description', type: 'string', required: true, description: 'Alert description' },
          { name: 'timestamp', type: 'date', required: false, defaultValue: new Date().toISOString() },
        ],
        localization: {
          es: {
            title: 'Alerta de Seguridad: {{alertType}}',
            body: 'Se ha detectado un evento de seguridad {{severity}}: {{description}}. Por favor, revise inmediatamente.',
          },
        },
        isActive: true,
        version: '1.0.0',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
      {
        id: '2',
        name: 'System Notification',
        description: 'General system notification template',
        category: 'system',
        type: 'email',
        subject: 'System Update: {{updateType}}',
        title: 'System Update',
        body: 'Dear {{userName}},\n\nA system update has been completed: {{updateDetails}}\n\nBest regards,\nThe iSECTECH Team',
        variables: [
          { name: 'userName', type: 'string', required: true, description: 'User name' },
          { name: 'updateType', type: 'string', required: true, description: 'Type of update' },
          { name: 'updateDetails', type: 'string', required: true, description: 'Update details' },
        ],
        isActive: true,
        version: '1.0.0',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ];

    defaultTemplates.forEach(template => {
      this.templates.set(template.id, template);
      this.nextId = Math.max(this.nextId, parseInt(template.id) + 1);
    });
  }

  async getTemplates(query: any) {
    const { limit, offset, category, type, isActive, search } = query;
    
    let filtered = Array.from(this.templates.values()).filter(template => {
      if (category && template.category !== category) return false;
      if (type && template.type !== type) return false;
      if (typeof isActive === 'boolean' && template.isActive !== isActive) return false;
      if (search) {
        const searchLower = search.toLowerCase();
        return template.name.toLowerCase().includes(searchLower) ||
               template.description?.toLowerCase().includes(searchLower);
      }
      return true;
    });

    const total = filtered.length;
    const paginated = filtered.slice(offset, offset + limit);

    return {
      templates: paginated,
      total,
      limit,
      offset,
      hasMore: offset + limit < total,
    };
  }

  async getTemplate(id: string) {
    const template = this.templates.get(id);
    if (!template) {
      throw new Error('Template not found');
    }
    return template;
  }

  async createTemplate(template: any) {
    const newTemplate = {
      id: (this.nextId++).toString(),
      ...template,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    this.templates.set(newTemplate.id, newTemplate);
    return newTemplate;
  }

  async updateTemplate(id: string, updates: any) {
    const template = this.templates.get(id);
    if (!template) {
      throw new Error('Template not found');
    }

    const updatedTemplate = {
      ...template,
      ...updates,
      id, // Preserve ID
      createdAt: template.createdAt, // Preserve creation date
      updatedAt: new Date().toISOString(),
    };

    this.templates.set(id, updatedTemplate);
    return updatedTemplate;
  }

  async deleteTemplate(id: string) {
    return this.templates.delete(id);
  }

  async renderTemplate(templateId: string, variables: any, options: any = {}) {
    const template = await this.getTemplate(templateId);
    const { language = 'en', personalizeFor } = options;

    // Get localized content
    let content = template;
    if (language !== 'en' && template.localization?.[language]) {
      content = {
        ...template,
        ...template.localization[language],
      };
    }

    // Simple template rendering (replace {{variable}} with values)
    const renderText = (text: string, vars: any): string => {
      return text.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
        return vars[varName] !== undefined ? String(vars[varName]) : match;
      });
    };

    // Apply personalization if provided
    let finalVariables = { ...variables };
    if (personalizeFor) {
      // Add personalization logic here
      finalVariables = {
        ...finalVariables,
        userName: finalVariables.userName || 'User',
        deviceType: personalizeFor.deviceType || 'desktop',
      };
    }

    const rendered = {
      id: template.id,
      name: template.name,
      category: template.category,
      type: template.type,
      subject: content.subject ? renderText(content.subject, finalVariables) : undefined,
      title: renderText(content.title, finalVariables),
      body: renderText(content.body, finalVariables),
      language,
      variables: finalVariables,
      renderedAt: new Date().toISOString(),
    };

    return rendered;
  }

  async validateTemplate(template: any) {
    const validation = templateSchema.safeParse(template);
    if (!validation.success) {
      return {
        isValid: false,
        errors: validation.error.issues,
      };
    }

    // Additional validation
    const errors = [];

    // Check for circular variable references
    const { title, body, subject } = template;
    const allText = `${title} ${body} ${subject || ''}`;
    const variableNames = template.variables.map((v: any) => v.name);
    
    for (const varName of variableNames) {
      const pattern = new RegExp(`\\{\\{${varName}\\}\\}`, 'g');
      const matches = allText.match(pattern);
      if (matches && matches.length > 10) {
        errors.push({
          path: ['variables', varName],
          message: `Variable ${varName} appears too many times, possible circular reference`,
        });
      }
    }

    // Validate required variables are used
    const requiredVars = template.variables.filter((v: any) => v.required);
    for (const reqVar of requiredVars) {
      if (!allText.includes(`{{${reqVar.name}}}`)) {
        errors.push({
          path: ['variables', reqVar.name],
          message: `Required variable ${reqVar.name} is not used in template`,
        });
      }
    }

    return {
      isValid: errors.length === 0,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async duplicateTemplate(id: string, newName: string) {
    const original = await this.getTemplate(id);
    const duplicate = {
      ...original,
      name: newName,
      version: '1.0.0',
    };
    
    // Remove ID and timestamps to create new template
    delete duplicate.id;
    delete duplicate.createdAt;
    delete duplicate.updatedAt;

    return this.createTemplate(duplicate);
  }
}

const templateService = new MockTemplateService();

// GET /api/notifications/templates - Get templates with filtering
export async function GET(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 200,
      keyGenerator: (req) => `templates:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:templates:read');
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
    
    const validationResult = templateQuerySchema.safeParse(queryParams);
    if (!validationResult.success) {
      return NextResponse.json(
        { error: 'Invalid query parameters', details: validationResult.error.issues },
        { status: 400 }
      );
    }

    // Get templates
    const result = await templateService.getTemplates(validationResult.data);

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'templates.list',
      resource: 'notification_templates',
      metadata: { query: validationResult.data },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('templates.api.get.success', {
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
    logger.error('Templates API GET error:', error);
    
    metrics.increment('templates.api.get.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to get templates',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}

// POST /api/notifications/templates - Create new template
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 50,
      keyGenerator: (req) => `templates:create:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:templates:create');
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

    // Validate template
    const validation = await templateService.validateTemplate(sanitizedBody);
    if (!validation.isValid) {
      return NextResponse.json(
        { error: 'Invalid template', details: validation.errors },
        { status: 400 }
      );
    }

    // Create template
    const template = await templateService.createTemplate({
      ...sanitizedBody,
      tenantId: tenantValidation.tenantId,
      createdBy: user.id,
    });

    // Audit logging
    await auditLog({
      userId: user.id,
      tenantId: tenantValidation.tenantId,
      action: 'templates.create',
      resource: 'notification_templates',
      resourceId: template.id,
      metadata: { template: { id: template.id, name: template.name } },
      timestamp: new Date(),
    });

    // Metrics
    metrics.increment('templates.api.post.success', {
      tenantId: tenantValidation.tenantId,
      category: template.category,
      type: template.type,
    });

    return NextResponse.json({
      success: true,
      data: template,
      metadata: {
        requestId: request.headers.get('x-request-id'),
        timestamp: new Date().toISOString(),
        processingTime: Date.now() - startTime,
      },
    }, { status: 201 });

  } catch (error: any) {
    logger.error('Templates API POST error:', error);
    
    metrics.increment('templates.api.post.error', {
      errorType: error.name,
    });

    return NextResponse.json(
      { 
        error: 'Failed to create template',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: 500 }
    );
  }
}