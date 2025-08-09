/**
 * Template Rendering API
 * Renders notification templates with personalization
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

const renderSchema = z.object({
  templateId: z.string(),
  variables: z.record(z.any()),
  language: z.string().default('en'),
  personalizeFor: z.object({
    userId: z.string(),
    deviceType: z.enum(['mobile', 'desktop', 'tablet']).optional(),
    preferences: z.record(z.any()).optional(),
  }).optional(),
  preview: z.boolean().default(false),
});

// Mock template service instance
class TemplateRenderingService {
  async renderTemplate(templateId: string, variables: any, options: any = {}) {
    // This would integrate with the template service from the main templates route
    // For now, using a simplified mock implementation
    
    const mockTemplates: Record<string, any> = {
      '1': {
        id: '1',
        name: 'Security Alert',
        category: 'security',
        type: 'push',
        title: 'Security Alert: {{alertType}}',
        body: 'A {{severity}} security event has been detected: {{description}}. Please review immediately.',
        variables: [
          { name: 'alertType', type: 'string', required: true },
          { name: 'severity', type: 'string', required: true },
          { name: 'description', type: 'string', required: true },
        ],
        localization: {
          es: {
            title: 'Alerta de Seguridad: {{alertType}}',
            body: 'Se ha detectado un evento de seguridad {{severity}}: {{description}}. Por favor, revise inmediatamente.',
          },
        },
      },
      '2': {
        id: '2',
        name: 'System Notification',
        category: 'system', 
        type: 'email',
        subject: 'System Update: {{updateType}}',
        title: 'System Update',
        body: 'Dear {{userName}},\n\nA system update has been completed: {{updateDetails}}\n\nBest regards,\nThe iSECTECH Team',
        variables: [
          { name: 'userName', type: 'string', required: true },
          { name: 'updateType', type: 'string', required: true },
          { name: 'updateDetails', type: 'string', required: true },
        ],
      },
    };

    const template = mockTemplates[templateId];
    if (!template) {
      throw new Error('Template not found');
    }

    const { language = 'en', personalizeFor } = options;

    // Get localized content
    let content = template;
    if (language !== 'en' && template.localization?.[language]) {
      content = {
        ...template,
        ...template.localization[language],
      };
    }

    // Enhanced template rendering with personalization
    const renderText = (text: string, vars: any, personalization: any = {}): string => {
      let rendered = text;

      // Apply personalization enhancements
      if (personalization.deviceType === 'mobile') {
        // Shorten content for mobile
        rendered = rendered.replace(/Please review immediately\./g, 'Review now.');
        rendered = rendered.replace(/A system update has been completed/g, 'System updated');
      }

      // Apply variable substitution
      rendered = rendered.replace(/\{\{(\w+)\}\}/g, (match, varName) => {
        return vars[varName] !== undefined ? String(vars[varName]) : match;
      });

      return rendered;
    };

    // Apply personalization
    let finalVariables = { ...variables };
    if (personalizeFor) {
      // Add personalization based on user preferences
      finalVariables = {
        ...finalVariables,
        userName: finalVariables.userName || 'User',
        deviceType: personalizeFor.deviceType || 'desktop',
      };

      // Apply preference-based personalization
      if (personalizeFor.preferences?.shortFormNotifications) {
        // Use shorter versions of messages
      }
      
      if (personalizeFor.preferences?.includeActionButtons) {
        finalVariables.actionButtons = true;
      }
    }

    // Generate action buttons based on template type and personalization
    const generateActions = (template: any, personalization: any) => {
      const actions = [];
      
      if (template.category === 'security') {
        actions.push({ label: 'View Details', action: 'view', priority: 'high' });
        actions.push({ label: 'Acknowledge', action: 'acknowledge', priority: 'medium' });
      }
      
      if (template.category === 'system') {
        actions.push({ label: 'View Changes', action: 'view', priority: 'medium' });
      }

      // Personalize actions based on device type
      if (personalization?.deviceType === 'mobile') {
        actions.forEach(action => {
          action.label = action.label.replace('View Details', 'View');
          action.label = action.label.replace('View Changes', 'Changes');
        });
      }

      return actions;
    };

    const rendered = {
      id: template.id,
      name: template.name,
      category: template.category,
      type: template.type,
      subject: content.subject ? renderText(content.subject, finalVariables, personalizeFor) : undefined,
      title: renderText(content.title, finalVariables, personalizeFor),
      body: renderText(content.body, finalVariables, personalizeFor),
      actions: generateActions(template, personalizeFor),
      language,
      personalizedFor: personalizeFor,
      variables: finalVariables,
      renderedAt: new Date().toISOString(),
      wordCount: renderText(content.body, finalVariables, personalizeFor).split(' ').length,
      estimatedReadTime: Math.ceil(renderText(content.body, finalVariables, personalizeFor).split(' ').length / 200), // words per minute
    };

    return rendered;
  }

  async batchRender(requests: any[]) {
    const results = [];
    
    for (const request of requests) {
      try {
        const rendered = await this.renderTemplate(
          request.templateId,
          request.variables,
          {
            language: request.language,
            personalizeFor: request.personalizeFor,
          }
        );
        results.push({ success: true, data: rendered, requestId: request.id });
      } catch (error: any) {
        results.push({ 
          success: false, 
          error: error.message, 
          requestId: request.id 
        });
      }
    }

    return results;
  }

  async validateVariables(templateId: string, variables: any) {
    // Mock template variable validation
    const mockTemplates: Record<string, any> = {
      '1': {
        variables: [
          { name: 'alertType', type: 'string', required: true },
          { name: 'severity', type: 'string', required: true },
          { name: 'description', type: 'string', required: true },
        ],
      },
      '2': {
        variables: [
          { name: 'userName', type: 'string', required: true },
          { name: 'updateType', type: 'string', required: true },
          { name: 'updateDetails', type: 'string', required: true },
        ],
      },
    };

    const template = mockTemplates[templateId];
    if (!template) {
      throw new Error('Template not found');
    }

    const errors = [];
    const warnings = [];

    for (const variable of template.variables) {
      if (variable.required && !(variable.name in variables)) {
        errors.push({
          variable: variable.name,
          message: `Required variable '${variable.name}' is missing`,
        });
      }

      if (variable.name in variables) {
        const value = variables[variable.name];
        
        // Type validation
        if (variable.type === 'string' && typeof value !== 'string') {
          warnings.push({
            variable: variable.name,
            message: `Variable '${variable.name}' should be a string, got ${typeof value}`,
          });
        }

        if (variable.type === 'number' && typeof value !== 'number') {
          warnings.push({
            variable: variable.name,
            message: `Variable '${variable.name}' should be a number, got ${typeof value}`,
          });
        }

        // Length validation for strings
        if (variable.type === 'string' && typeof value === 'string') {
          if (value.length > 1000) {
            warnings.push({
              variable: variable.name,
              message: `Variable '${variable.name}' is very long (${value.length} characters), consider shortening`,
            });
          }
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }
}

const renderingService = new TemplateRenderingService();

// POST /api/notifications/templates/render - Render template with variables
export async function POST(request: NextRequest) {
  const startTime = Date.now();
  
  try {
    // Rate limiting
    const rateLimitResult = await rateLimit(request, {
      windowMs: 60 * 1000,
      max: 500, // High limit for rendering operations
      keyGenerator: (req) => `template:render:${req.headers.get('x-forwarded-for') || 'unknown'}`,
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

    const hasPermission = await authorize(user, 'notifications:templates:render');
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

    // Handle both single and batch rendering
    const isBatch = Array.isArray(sanitizedBody);
    
    if (isBatch) {
      // Batch rendering
      if (sanitizedBody.length > 50) {
        return NextResponse.json(
          { error: 'Cannot render more than 50 templates at once' },
          { status: 400 }
        );
      }

      // Validate each request in the batch
      for (const [index, item] of sanitizedBody.entries()) {
        const validationResult = renderSchema.safeParse(item);
        if (!validationResult.success) {
          return NextResponse.json(
            { 
              error: `Invalid request at index ${index}`, 
              details: validationResult.error.issues 
            },
            { status: 400 }
          );
        }
      }

      // Process batch rendering
      const results = await renderingService.batchRender(sanitizedBody.map((item, index) => ({
        ...item,
        id: item.id || index.toString(),
      })));

      const successCount = results.filter(r => r.success).length;
      const failureCount = results.length - successCount;

      // Audit logging for batch
      await auditLog({
        userId: user.id,
        tenantId: tenantValidation.tenantId,
        action: 'templates.batch_render',
        resource: 'notification_templates',
        metadata: { 
          batchSize: sanitizedBody.length,
          successful: successCount,
          failed: failureCount,
        },
        timestamp: new Date(),
      });

      // Metrics
      metrics.increment('templates.api.batch_render.success', {
        tenantId: tenantValidation.tenantId,
        batchSize: sanitizedBody.length.toString(),
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

    } else {
      // Single template rendering
      const validationResult = renderSchema.safeParse(sanitizedBody);
      if (!validationResult.success) {
        return NextResponse.json(
          { error: 'Invalid request data', details: validationResult.error.issues },
          { status: 400 }
        );
      }

      const { templateId, variables, language, personalizeFor, preview } = validationResult.data;

      // Validate variables if not in preview mode
      if (!preview) {
        const variableValidation = await renderingService.validateVariables(templateId, variables);
        if (!variableValidation.isValid) {
          return NextResponse.json(
            { 
              error: 'Invalid template variables', 
              details: variableValidation.errors,
              warnings: variableValidation.warnings,
            },
            { status: 400 }
          );
        }
      }

      // Render template
      const rendered = await renderingService.renderTemplate(templateId, variables, {
        language,
        personalizeFor,
        preview,
      });

      // Audit logging
      await auditLog({
        userId: user.id,
        tenantId: tenantValidation.tenantId,
        action: 'templates.render',
        resource: 'notification_templates',
        resourceId: templateId,
        metadata: { 
          templateId,
          language,
          personalized: !!personalizeFor,
          preview,
        },
        timestamp: new Date(),
      });

      // Metrics
      metrics.increment('templates.api.render.success', {
        tenantId: tenantValidation.tenantId,
        templateId,
        language,
        personalized: personalizeFor ? 'true' : 'false',
      });

      metrics.histogram('templates.api.render.duration', Date.now() - startTime, {
        tenantId: tenantValidation.tenantId,
      });

      return NextResponse.json({
        success: true,
        data: rendered,
        metadata: {
          requestId: request.headers.get('x-request-id'),
          timestamp: new Date().toISOString(),
          processingTime: Date.now() - startTime,
        },
      });
    }

  } catch (error: any) {
    logger.error('Template Render API error:', error);
    
    metrics.increment('templates.api.render.error', {
      errorType: error.name,
    });

    const statusCode = error.message === 'Template not found' ? 404 : 500;

    return NextResponse.json(
      { 
        error: statusCode === 404 ? 'Template not found' : 'Failed to render template',
        requestId: request.headers.get('x-request-id'),
        details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      },
      { status: statusCode }
    );
  }
}