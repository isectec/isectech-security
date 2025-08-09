/**
 * Email Template Manager for iSECTECH Protect White-Labeling
 * Production-grade email template management with customization and variable processing
 */

import type { 
  EmailTemplate,
  EmailType,
  BrandAsset
} from '@/types/white-labeling';

export interface EmailVariables {
  [key: string]: string | number | Date;
  userName?: string;
  userEmail?: string;
  companyName?: string;
  platformName?: string;
  supportEmail?: string;
  currentYear?: number;
  resetLink?: string;
  activationLink?: string;
  alertSummary?: string;
  reportName?: string;
  reportLink?: string;
}

export interface EmailRenderResult {
  subject: string;
  htmlContent: string;
  textContent: string;
  attachments?: {
    filename: string;
    content: Buffer | string;
    contentType: string;
  }[];
}

export interface EmailValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  suggestions: string[];
}

export interface EmailPreviewOptions {
  variables: EmailVariables;
  assets?: Record<string, BrandAsset>;
  baseUrl?: string;
}

export class EmailTemplateManager {
  private static instance: EmailTemplateManager;
  private templateCache = new Map<string, EmailTemplate>();
  private renderedCache = new Map<string, { content: EmailRenderResult; timestamp: number }>();
  private readonly CACHE_TTL = 600000; // 10 minutes
  
  private constructor() {}

  public static getInstance(): EmailTemplateManager {
    if (!EmailTemplateManager.instance) {
      EmailTemplateManager.instance = new EmailTemplateManager();
    }
    return EmailTemplateManager.instance;
  }

  /**
   * Create or update email template
   */
  public async createEmailTemplate(
    tenantId: string,
    templateData: {
      type: EmailType;
      name: string;
      subject: string;
      htmlContent: string;
      textContent: string;
      previewData?: Record<string, string>;
    },
    userId: string
  ): Promise<EmailTemplate> {
    // Validate template content
    const validation = this.validateTemplate(templateData);
    if (!validation.isValid) {
      throw new Error(`Template validation failed: ${validation.errors.join(', ')}`);
    }

    // Extract variables from template content
    const variables = this.extractVariables([
      templateData.subject,
      templateData.htmlContent,
      templateData.textContent
    ]);

    const template: EmailTemplate = {
      id: this.generateId(),
      type: templateData.type,
      name: templateData.name,
      subject: templateData.subject,
      htmlContent: templateData.htmlContent,
      textContent: templateData.textContent,
      variables,
      previewData: templateData.previewData,
      isDefault: false,
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    // Save template
    await this.saveEmailTemplate(template);

    // Clear cache
    this.clearTemplateCache(tenantId, templateData.type);

    return template;
  }

  /**
   * Update existing email template
   */
  public async updateEmailTemplate(
    templateId: string,
    tenantId: string,
    updates: Partial<{
      name: string;
      subject: string;
      htmlContent: string;
      textContent: string;
      previewData: Record<string, string>;
    }>,
    userId: string
  ): Promise<EmailTemplate> {
    const template = await this.getEmailTemplate(templateId, tenantId);
    if (!template) {
      throw new Error('Email template not found');
    }

    // Apply updates
    Object.assign(template, updates, {
      updatedAt: new Date(),
      updatedBy: userId,
    });

    // Re-extract variables if content changed
    if (updates.subject || updates.htmlContent || updates.textContent) {
      template.variables = this.extractVariables([
        template.subject,
        template.htmlContent,
        template.textContent
      ]);
    }

    // Validate updated template
    const validation = this.validateTemplate(template);
    if (!validation.isValid) {
      throw new Error(`Template validation failed: ${validation.errors.join(', ')}`);
    }

    // Save updated template
    await this.saveEmailTemplate(template);

    // Clear cache
    this.clearTemplateCache(tenantId, template.type);

    return template;
  }

  /**
   * Get email template by type
   */
  public async getEmailTemplateByType(
    type: EmailType,
    tenantId: string
  ): Promise<EmailTemplate | null> {
    const cacheKey = `${tenantId}:${type}`;
    
    if (this.templateCache.has(cacheKey)) {
      return this.templateCache.get(cacheKey)!;
    }

    // Try to get tenant-specific template first
    let template = await this.fetchTemplateFromDatabase(type, tenantId);
    
    // Fall back to default template if none exists
    if (!template) {
      template = await this.getDefaultTemplate(type);
      if (template) {
        // Customize for tenant
        template = { ...template, tenantId };
      }
    }

    if (template) {
      this.templateCache.set(cacheKey, template);
    }

    return template;
  }

  /**
   * Get email template by ID
   */
  public async getEmailTemplate(
    templateId: string,
    tenantId: string
  ): Promise<EmailTemplate | null> {
    return this.fetchTemplateById(templateId, tenantId);
  }

  /**
   * Render email template with variables
   */
  public async renderEmailTemplate(
    type: EmailType,
    tenantId: string,
    variables: EmailVariables,
    options: {
      assets?: Record<string, BrandAsset>;
      baseUrl?: string;
    } = {}
  ): Promise<EmailRenderResult> {
    const cacheKey = `${tenantId}:${type}:${JSON.stringify(variables)}`;
    
    // Check cache first
    const cached = this.renderedCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.content;
    }

    const template = await this.getEmailTemplateByType(type, tenantId);
    if (!template) {
      throw new Error(`Email template not found for type: ${type}`);
    }

    // Add default variables
    const allVariables: EmailVariables = {
      currentYear: new Date().getFullYear(),
      platformName: 'iSECTECH Protect',
      supportEmail: 'support@isectech.com',
      ...variables,
    };

    // Render template components
    const subject = this.processVariables(template.subject, allVariables);
    const htmlContent = await this.processHtmlTemplate(template.htmlContent, allVariables, options);
    const textContent = this.processVariables(template.textContent, allVariables);

    const result: EmailRenderResult = {
      subject,
      htmlContent,
      textContent,
    };

    // Cache the result
    this.renderedCache.set(cacheKey, {
      content: result,
      timestamp: Date.now(),
    });

    return result;
  }

  /**
   * Preview email template
   */
  public async previewEmailTemplate(
    templateId: string,
    tenantId: string,
    options: EmailPreviewOptions
  ): Promise<EmailRenderResult> {
    const template = await this.getEmailTemplate(templateId, tenantId);
    if (!template) {
      throw new Error('Email template not found');
    }

    // Use preview data if no variables provided
    const variables = {
      ...template.previewData,
      ...options.variables,
      currentYear: new Date().getFullYear(),
    };

    // Render with provided options
    const subject = this.processVariables(template.subject, variables);
    const htmlContent = await this.processHtmlTemplate(template.htmlContent, variables, options);
    const textContent = this.processVariables(template.textContent, variables);

    return {
      subject,
      htmlContent,
      textContent,
    };
  }

  /**
   * Validate email template
   */
  public validateTemplate(template: Partial<EmailTemplate>): EmailValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];

    // Required fields
    if (!template.subject?.trim()) {
      errors.push('Subject is required');
    }

    if (!template.htmlContent?.trim()) {
      errors.push('HTML content is required');
    }

    if (!template.textContent?.trim()) {
      errors.push('Text content is required');
    }

    // Subject validation
    if (template.subject) {
      if (template.subject.length > 78) {
        warnings.push('Subject line longer than 78 characters may be truncated in some email clients');
      }
      
      if (template.subject.includes('{{') && !template.subject.includes('}}')) {
        errors.push('Subject contains incomplete variable syntax');
      }
    }

    // HTML content validation
    if (template.htmlContent) {
      const htmlValidation = this.validateHtmlContent(template.htmlContent);
      errors.push(...htmlValidation.errors);
      warnings.push(...htmlValidation.warnings);
    }

    // Text content validation
    if (template.textContent) {
      if (template.textContent.includes('<') || template.textContent.includes('>')) {
        warnings.push('Text content appears to contain HTML tags');
      }
    }

    // Variable consistency check
    if (template.htmlContent && template.textContent) {
      const htmlVars = this.extractVariables([template.htmlContent]);
      const textVars = this.extractVariables([template.textContent]);
      
      const missingInText = htmlVars.filter(v => !textVars.includes(v));
      const missingInHtml = textVars.filter(v => !htmlVars.includes(v));
      
      if (missingInText.length > 0) {
        warnings.push(`Variables missing in text version: ${missingInText.join(', ')}`);
      }
      
      if (missingInHtml.length > 0) {
        warnings.push(`Variables missing in HTML version: ${missingInHtml.join(', ')}`);
      }
    }

    // Accessibility suggestions
    if (template.htmlContent && !template.htmlContent.includes('alt=')) {
      suggestions.push('Consider adding alt text to images for accessibility');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
    };
  }

  /**
   * Get all templates for tenant
   */
  public async getTemplatesForTenant(tenantId: string): Promise<EmailTemplate[]> {
    return this.fetchTemplatesForTenant(tenantId);
  }

  /**
   * Copy template from another tenant or default
   */
  public async copyEmailTemplate(
    sourceTemplateId: string,
    sourceTenantId: string,
    targetTenantId: string,
    userId: string,
    customizations?: Partial<EmailTemplate>
  ): Promise<EmailTemplate> {
    const sourceTemplate = await this.getEmailTemplate(sourceTemplateId, sourceTenantId);
    if (!sourceTemplate) {
      throw new Error('Source template not found');
    }

    const newTemplate: EmailTemplate = {
      ...sourceTemplate,
      id: this.generateId(),
      tenantId: targetTenantId,
      isDefault: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
      ...customizations,
    };

    await this.saveEmailTemplate(newTemplate);
    return newTemplate;
  }

  /**
   * Delete email template
   */
  public async deleteEmailTemplate(
    templateId: string,
    tenantId: string,
    userId: string
  ): Promise<void> {
    const template = await this.getEmailTemplate(templateId, tenantId);
    if (!template) {
      throw new Error('Email template not found');
    }

    if (template.isDefault) {
      throw new Error('Cannot delete default template');
    }

    await this.deleteTemplateFromDatabase(templateId, tenantId);
    
    // Clear cache
    this.clearTemplateCache(tenantId, template.type);
  }

  /**
   * Test email template sending
   */
  public async sendTestEmail(
    templateId: string,
    tenantId: string,
    recipientEmail: string,
    variables: EmailVariables,
    options?: {
      assets?: Record<string, BrandAsset>;
      baseUrl?: string;
    }
  ): Promise<{ messageId: string; success: boolean }> {
    const template = await this.getEmailTemplate(templateId, tenantId);
    if (!template) {
      throw new Error('Email template not found');
    }

    // Render the template
    const rendered = await this.renderEmailTemplate(
      template.type,
      tenantId,
      variables,
      options
    );

    // Send email (mock implementation - would integrate with email service)
    const messageId = await this.sendEmail({
      to: recipientEmail,
      subject: `[TEST] ${rendered.subject}`,
      html: rendered.htmlContent,
      text: rendered.textContent,
    });

    return { messageId, success: true };
  }

  // Private helper methods

  private processVariables(content: string, variables: EmailVariables): string {
    let processed = content;
    
    Object.entries(variables).forEach(([key, value]) => {
      const regex = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'g');
      processed = processed.replace(regex, String(value));
    });

    return processed;
  }

  private async processHtmlTemplate(
    htmlContent: string,
    variables: EmailVariables,
    options: {
      assets?: Record<string, BrandAsset>;
      baseUrl?: string;
    }
  ): Promise<string> {
    let processed = this.processVariables(htmlContent, variables);

    // Process asset URLs
    if (options.assets) {
      Object.entries(options.assets).forEach(([key, asset]) => {
        if (asset) {
          const assetRegex = new RegExp(`\\{\\{\\s*${key}\\.url\\s*\\}\\}`, 'g');
          processed = processed.replace(assetRegex, asset.url);
        }
      });
    }

    // Process base URL
    if (options.baseUrl) {
      processed = processed.replace(/\{\{\s*baseUrl\s*\}\}/g, options.baseUrl);
    }

    // Add email-specific CSS inlining and mobile optimization
    processed = this.optimizeForEmail(processed);

    return processed;
  }

  private optimizeForEmail(htmlContent: string): string {
    // Basic email optimization - would use more sophisticated tools in production
    let optimized = htmlContent;

    // Ensure table-based layout for better email client support
    if (!optimized.includes('<table')) {
      optimized = `
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          <tr>
            <td>
              ${optimized}
            </td>
          </tr>
        </table>
      `;
    }

    // Add mobile-friendly meta tags and CSS
    if (!optimized.includes('viewport')) {
      const mobileOptimization = `
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style type="text/css">
          @media screen and (max-width: 600px) {
            .mobile-full-width { width: 100% !important; }
            .mobile-center { text-align: center !important; }
            .mobile-padding { padding: 10px !important; }
          }
        </style>
      `;
      
      optimized = optimized.replace(/<\/head>/, `${mobileOptimization}</head>`);
    }

    return optimized;
  }

  private validateHtmlContent(html: string): { errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Check for balanced tags
    const openTags = html.match(/<[^\/][^>]*>/g) || [];
    const closeTags = html.match(/<\/[^>]*>/g) || [];
    
    if (openTags.length !== closeTags.length) {
      errors.push('HTML tags are not properly balanced');
    }

    // Check for email-unsafe elements
    const unsafeElements = ['script', 'link', 'meta', 'form', 'input'];
    unsafeElements.forEach(element => {
      if (html.toLowerCase().includes(`<${element}`)) {
        warnings.push(`${element} elements may not be supported in all email clients`);
      }
    });

    // Check for external resources
    if (html.includes('http://') && !html.includes('https://')) {
      warnings.push('Consider using HTTPS for all external resources');
    }

    return { errors, warnings };
  }

  private extractVariables(contents: string[]): string[] {
    const variables = new Set<string>();
    
    contents.forEach(content => {
      const matches = content.match(/\{\{\s*([^}]+)\s*\}\}/g) || [];
      matches.forEach(match => {
        const variable = match.replace(/[{}]/g, '').trim();
        // Handle nested properties like asset.url
        const baseVariable = variable.split('.')[0];
        variables.add(baseVariable);
      });
    });

    return Array.from(variables);
  }

  private async getDefaultTemplate(type: EmailType): Promise<EmailTemplate | null> {
    // Default templates based on type
    const defaultTemplates: Record<EmailType, Partial<EmailTemplate>> = {
      welcome: {
        subject: 'Welcome to {{platformName}}!',
        htmlContent: `
          <h1>Welcome {{userName}}!</h1>
          <p>Thank you for joining {{platformName}}. We're excited to have you on board.</p>
          <p>Get started by logging into your account and exploring our security features.</p>
          <p>If you have any questions, please don't hesitate to contact us at {{supportEmail}}.</p>
        `,
        textContent: `
          Welcome {{userName}}!
          
          Thank you for joining {{platformName}}. We're excited to have you on board.
          
          Get started by logging into your account and exploring our security features.
          
          If you have any questions, please don't hesitate to contact us at {{supportEmail}}.
        `,
      },
      'password-reset': {
        subject: 'Reset your {{platformName}} password',
        htmlContent: `
          <h1>Password Reset Request</h1>
          <p>Hello {{userName}},</p>
          <p>We received a request to reset your password for your {{platformName}} account.</p>
          <p><a href="{{resetLink}}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
          <p>If you didn't request this, please ignore this email. Your password won't be changed.</p>
          <p>This link will expire in 24 hours for your security.</p>
        `,
        textContent: `
          Password Reset Request
          
          Hello {{userName}},
          
          We received a request to reset your password for your {{platformName}} account.
          
          Reset your password: {{resetLink}}
          
          If you didn't request this, please ignore this email. Your password won't be changed.
          
          This link will expire in 24 hours for your security.
        `,
      },
      'alert-notification': {
        subject: 'Security Alert: {{alertSummary}}',
        htmlContent: `
          <h1>Security Alert</h1>
          <p>A security alert has been triggered in your {{platformName}} environment.</p>
          <div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545;">
            {{alertSummary}}
          </div>
          <p>Please log in to review the full details and take appropriate action.</p>
          <p>If you have questions, contact our security team at {{supportEmail}}.</p>
        `,
        textContent: `
          Security Alert
          
          A security alert has been triggered in your {{platformName}} environment.
          
          Alert: {{alertSummary}}
          
          Please log in to review the full details and take appropriate action.
          
          If you have questions, contact our security team at {{supportEmail}}.
        `,
      },
      'report-delivery': {
        subject: 'Your {{reportName}} is ready',
        htmlContent: `
          <h1>Report Ready</h1>
          <p>Your {{reportName}} report has been generated and is ready for review.</p>
          <p><a href="{{reportLink}}" style="background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Report</a></p>
          <p>This report will be available for 30 days.</p>
        `,
        textContent: `
          Report Ready
          
          Your {{reportName}} report has been generated and is ready for review.
          
          View Report: {{reportLink}}
          
          This report will be available for 30 days.
        `,
      },
      'system-notification': {
        subject: '{{platformName}} System Notification',
        htmlContent: `
          <h1>System Notification</h1>
          <p>This is a system notification from {{platformName}}.</p>
          <p>{{notificationContent}}</p>
        `,
        textContent: `
          System Notification
          
          This is a system notification from {{platformName}}.
          
          {{notificationContent}}
        `,
      },
      invitation: {
        subject: 'You\'ve been invited to join {{companyName}} on {{platformName}}',
        htmlContent: `
          <h1>You're Invited!</h1>
          <p>{{userName}} has invited you to join {{companyName}} on {{platformName}}.</p>
          <p><a href="{{activationLink}}" style="background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Accept Invitation</a></p>
          <p>This invitation will expire in 7 days.</p>
        `,
        textContent: `
          You're Invited!
          
          {{userName}} has invited you to join {{companyName}} on {{platformName}}.
          
          Accept Invitation: {{activationLink}}
          
          This invitation will expire in 7 days.
        `,
      },
      reminder: {
        subject: 'Reminder from {{platformName}}',
        htmlContent: `
          <h1>Reminder</h1>
          <p>This is a friendly reminder from {{platformName}}.</p>
          <p>{{reminderContent}}</p>
        `,
        textContent: `
          Reminder
          
          This is a friendly reminder from {{platformName}}.
          
          {{reminderContent}}
        `,
      },
    };

    const templateData = defaultTemplates[type];
    if (!templateData) return null;

    return {
      id: `default_${type}`,
      type,
      name: `Default ${type} Template`,
      subject: templateData.subject!,
      htmlContent: templateData.htmlContent!,
      textContent: templateData.textContent!,
      variables: this.extractVariables([
        templateData.subject!,
        templateData.htmlContent!,
        templateData.textContent!
      ]),
      isDefault: true,
      tenantId: '',
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'system',
      updatedBy: 'system',
    };
  }

  private clearTemplateCache(tenantId: string, type?: EmailType): void {
    if (type) {
      this.templateCache.delete(`${tenantId}:${type}`);
    } else {
      // Clear all templates for tenant
      for (const key of this.templateCache.keys()) {
        if (key.startsWith(`${tenantId}:`)) {
          this.templateCache.delete(key);
        }
      }
    }
    
    // Clear rendered cache
    for (const key of this.renderedCache.keys()) {
      if (key.startsWith(`${tenantId}:`)) {
        this.renderedCache.delete(key);
      }
    }
  }

  private generateId(): string {
    return `email_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Mock database and email service operations

  private async fetchTemplateFromDatabase(type: EmailType, tenantId: string): Promise<EmailTemplate | null> {
    // Mock implementation
    return null;
  }

  private async fetchTemplateById(templateId: string, tenantId: string): Promise<EmailTemplate | null> {
    // Mock implementation
    return null;
  }

  private async fetchTemplatesForTenant(tenantId: string): Promise<EmailTemplate[]> {
    // Mock implementation
    return [];
  }

  private async saveEmailTemplate(template: EmailTemplate): Promise<void> {
    // Mock implementation
    console.log('Saving email template:', template);
  }

  private async deleteTemplateFromDatabase(templateId: string, tenantId: string): Promise<void> {
    // Mock implementation
    console.log(`Deleting template ${templateId} for tenant ${tenantId}`);
  }

  private async sendEmail(emailData: {
    to: string;
    subject: string;
    html: string;
    text: string;
  }): Promise<string> {
    // Mock implementation - would integrate with SendGrid, AWS SES, etc.
    console.log('Sending email to:', emailData.to);
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Export singleton instance
export const emailTemplateManager = EmailTemplateManager.getInstance();