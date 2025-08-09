/**
 * Content Manager for iSECTECH Protect White-Labeling
 * Production-grade content customization system with terminology replacement,
 * template management, and legal document handling
 */

import type { 
  ContentTemplate, 
  TerminologyMapping,
  ContentType,
  WhiteLabelConfiguration
} from '@/types/white-labeling';

export interface ContentReplacementContext {
  tenantId: string;
  userId?: string;
  userRole?: string;
  locale?: string;
  variables?: Record<string, string>;
}

export interface TerminologyRule {
  id: string;
  pattern: string | RegExp;
  replacement: string;
  context: string[];
  caseSensitive: boolean;
  wholeWord: boolean;
  priority: number;
}

export interface ContentValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  suggestions: string[];
}

interface ContentCacheEntry {
  content: string;
  timestamp: number;
  version: string;
  expiresAt: number;
}

export class ContentManager {
  private static instance: ContentManager;
  private terminologyCache = new Map<string, TerminologyRule[]>();
  private contentCache = new Map<string, ContentCacheEntry>();
  private templateCache = new Map<string, ContentTemplate>();
  private readonly CACHE_TTL = 300000; // 5 minutes
  
  private constructor() {}

  public static getInstance(): ContentManager {
    if (!ContentManager.instance) {
      ContentManager.instance = new ContentManager();
    }
    return ContentManager.instance;
  }

  /**
   * Replace terminology in content based on tenant configuration
   */
  public async applyTerminologyReplacements(
    content: string,
    context: ContentReplacementContext
  ): Promise<string> {
    const cacheKey = `terminology:${context.tenantId}`;
    let rules = this.terminologyCache.get(cacheKey);

    if (!rules) {
      rules = await this.loadTerminologyRules(context.tenantId);
      this.terminologyCache.set(cacheKey, rules);
    }

    let processedContent = content;

    // Sort rules by priority (higher priority first)
    const sortedRules = rules.sort((a, b) => b.priority - a.priority);

    for (const rule of sortedRules) {
      // Check if rule applies to current context
      if (rule.context.length > 0 && !this.matchesContext(rule.context, context)) {
        continue;
      }

      processedContent = this.applyTerminologyRule(processedContent, rule);
    }

    return processedContent;
  }

  /**
   * Get customized content template
   */
  public async getCustomContent(
    type: ContentType,
    key: string,
    context: ContentReplacementContext,
    variables?: Record<string, string>
  ): Promise<string> {
    const cacheKey = `content:${context.tenantId}:${type}:${key}`;
    
    // Check cache first
    const cached = this.contentCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return this.processVariables(cached.content, variables);
    }

    // Load template from database
    const template = await this.loadContentTemplate(type, key, context.tenantId);
    if (!template) {
      throw new Error(`Content template not found: ${type}:${key}`);
    }

    // Use custom content if available, otherwise fall back to default
    let content = template.customContent || template.defaultContent;

    // Apply terminology replacements
    content = await this.applyTerminologyReplacements(content, context);

    // Cache the processed content
    this.contentCache.set(cacheKey, {
      content,
      timestamp: Date.now(),
      version: template.updatedAt.toISOString(),
      expiresAt: Date.now() + this.CACHE_TTL,
    });

    // Process variables if provided
    return this.processVariables(content, variables);
  }

  /**
   * Update custom content template
   */
  public async updateContentTemplate(
    tenantId: string,
    type: ContentType,
    key: string,
    customContent: string,
    userId: string
  ): Promise<ContentTemplate> {
    // Validate content
    const validation = this.validateContent(customContent, type);
    if (!validation.isValid) {
      throw new Error(`Content validation failed: ${validation.errors.join(', ')}`);
    }

    // Load existing template or create new one
    let template = await this.loadContentTemplate(type, key, tenantId);
    
    if (!template) {
      template = await this.createContentTemplate(type, key, tenantId, customContent, userId);
    } else {
      template.customContent = customContent;
      template.updatedAt = new Date();
      template.updatedBy = userId;
      await this.saveContentTemplate(template);
    }

    // Clear cache
    this.clearContentCache(tenantId, type, key);

    return template;
  }

  /**
   * Create terminology mapping
   */
  public async createTerminologyMapping(
    tenantId: string,
    originalTerm: string,
    customTerm: string,
    context: string[],
    options: {
      caseSensitive?: boolean;
      wholeWord?: boolean;
      priority?: number;
    } = {}
  ): Promise<TerminologyMapping> {
    const mapping: TerminologyMapping = {
      id: this.generateId(),
      originalTerm,
      customTerm,
      context,
      caseSensitive: options.caseSensitive ?? false,
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await this.saveTerminologyMapping(mapping);

    // Clear terminology cache
    this.terminologyCache.delete(`terminology:${tenantId}`);

    return mapping;
  }

  /**
   * Bulk update terminology mappings
   */
  public async bulkUpdateTerminology(
    tenantId: string,
    mappings: {
      originalTerm: string;
      customTerm: string;
      context?: string[];
      caseSensitive?: boolean;
    }[],
    userId: string
  ): Promise<{ successful: TerminologyMapping[]; failed: { mapping: any; error: string }[] }> {
    const successful: TerminologyMapping[] = [];
    const failed: { mapping: any; error: string }[] = [];

    for (const mapping of mappings) {
      try {
        const result = await this.createTerminologyMapping(
          tenantId,
          mapping.originalTerm,
          mapping.customTerm,
          mapping.context || [],
          {
            caseSensitive: mapping.caseSensitive,
            priority: 1,
          }
        );
        successful.push(result);
      } catch (error) {
        failed.push({
          mapping,
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }
    }

    return { successful, failed };
  }

  /**
   * Get all terminology mappings for a tenant
   */
  public async getTerminologyMappings(tenantId: string): Promise<TerminologyMapping[]> {
    return this.loadTerminologyMappings(tenantId);
  }

  /**
   * Legal document management
   */
  public async updateLegalDocument(
    tenantId: string,
    documentType: 'privacyPolicy' | 'termsOfService' | 'cookiePolicy' | 'dataProcessingAgreement' | 'complianceStatement',
    content: string,
    userId: string
  ): Promise<void> {
    // Validate legal document content
    const validation = this.validateLegalDocument(content, documentType);
    if (!validation.isValid) {
      throw new Error(`Legal document validation failed: ${validation.errors.join(', ')}`);
    }

    // Save legal document
    await this.saveLegalDocument(tenantId, documentType, content, userId);

    // Clear related content cache
    this.clearLegalDocumentCache(tenantId, documentType);
  }

  /**
   * Get legal document with customizations applied
   */
  public async getLegalDocument(
    tenantId: string,
    documentType: 'privacyPolicy' | 'termsOfService' | 'cookiePolicy' | 'dataProcessingAgreement' | 'complianceStatement',
    context: ContentReplacementContext
  ): Promise<string> {
    const content = await this.loadLegalDocument(tenantId, documentType);
    if (!content) {
      throw new Error(`Legal document not found: ${documentType}`);
    }

    // Apply terminology replacements
    return this.applyTerminologyReplacements(content, context);
  }

  /**
   * Multi-language content support
   */
  public async getLocalizedContent(
    type: ContentType,
    key: string,
    locale: string,
    context: ContentReplacementContext,
    variables?: Record<string, string>
  ): Promise<string> {
    // Try to get localized version first
    try {
      const localizedKey = `${key}.${locale}`;
      return await this.getCustomContent(type, localizedKey, context, variables);
    } catch (error) {
      // Fall back to default locale
      return this.getCustomContent(type, key, context, variables);
    }
  }

  /**
   * Content preview with changes applied
   */
  public async previewContent(
    tenantId: string,
    changes: {
      terminology?: Array<{ originalTerm: string; customTerm: string; context?: string[] }>;
      templates?: Array<{ type: ContentType; key: string; content: string }>;
    },
    sampleContent: string,
    context: ContentReplacementContext
  ): Promise<{ original: string; preview: string; changes: string[] }> {
    const changesApplied: string[] = [];
    let previewContent = sampleContent;

    // Apply terminology changes
    if (changes.terminology) {
      for (const termChange of changes.terminology) {
        const rule: TerminologyRule = {
          id: 'preview',
          pattern: termChange.originalTerm,
          replacement: termChange.customTerm,
          context: termChange.context || [],
          caseSensitive: false,
          wholeWord: true,
          priority: 1,
        };

        const beforeChange = previewContent;
        previewContent = this.applyTerminologyRule(previewContent, rule);
        
        if (beforeChange !== previewContent) {
          changesApplied.push(`Terminology: "${termChange.originalTerm}" → "${termChange.customTerm}"`);
        }
      }
    }

    return {
      original: sampleContent,
      preview: previewContent,
      changes: changesApplied,
    };
  }

  /**
   * Export all customizations for a tenant
   */
  public async exportCustomizations(tenantId: string): Promise<{
    terminology: TerminologyMapping[];
    templates: ContentTemplate[];
    legalDocuments: Record<string, string>;
    exportedAt: Date;
  }> {
    const [terminology, templates, legalDocuments] = await Promise.all([
      this.loadTerminologyMappings(tenantId),
      this.loadAllContentTemplates(tenantId),
      this.loadAllLegalDocuments(tenantId),
    ]);

    return {
      terminology,
      templates,
      legalDocuments,
      exportedAt: new Date(),
    };
  }

  /**
   * Import customizations for a tenant
   */
  public async importCustomizations(
    tenantId: string,
    data: {
      terminology?: TerminologyMapping[];
      templates?: ContentTemplate[];
      legalDocuments?: Record<string, string>;
    },
    userId: string,
    options: { overwrite?: boolean } = {}
  ): Promise<{
    imported: { terminology: number; templates: number; legalDocuments: number };
    errors: string[];
  }> {
    const imported = { terminology: 0, templates: 0, legalDocuments: 0 };
    const errors: string[] = [];

    // Import terminology mappings
    if (data.terminology) {
      for (const mapping of data.terminology) {
        try {
          await this.createTerminologyMapping(
            tenantId,
            mapping.originalTerm,
            mapping.customTerm,
            mapping.context,
            { caseSensitive: mapping.caseSensitive }
          );
          imported.terminology++;
        } catch (error) {
          errors.push(`Terminology mapping failed: ${mapping.originalTerm} - ${error}`);
        }
      }
    }

    // Import content templates
    if (data.templates) {
      for (const template of data.templates) {
        try {
          await this.updateContentTemplate(
            tenantId,
            template.type,
            template.key,
            template.customContent || template.defaultContent,
            userId
          );
          imported.templates++;
        } catch (error) {
          errors.push(`Template import failed: ${template.type}:${template.key} - ${error}`);
        }
      }
    }

    // Import legal documents
    if (data.legalDocuments) {
      for (const [docType, content] of Object.entries(data.legalDocuments)) {
        try {
          await this.updateLegalDocument(
            tenantId,
            docType as any,
            content,
            userId
          );
          imported.legalDocuments++;
        } catch (error) {
          errors.push(`Legal document import failed: ${docType} - ${error}`);
        }
      }
    }

    return { imported, errors };
  }

  // Private helper methods

  private applyTerminologyRule(content: string, rule: TerminologyRule): string {
    let pattern: RegExp;

    if (rule.pattern instanceof RegExp) {
      pattern = rule.pattern;
    } else {
      const flags = rule.caseSensitive ? 'g' : 'gi';
      const escapedPattern = rule.pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const wordBoundary = rule.wholeWord ? '\\b' : '';
      pattern = new RegExp(`${wordBoundary}${escapedPattern}${wordBoundary}`, flags);
    }

    return content.replace(pattern, rule.replacement);
  }

  private matchesContext(ruleContext: string[], context: ContentReplacementContext): boolean {
    // Simple context matching - can be extended for more complex rules
    const contextStrings = [
      context.userRole,
      context.locale,
      'all', // Always include 'all' context
    ].filter(Boolean);

    return ruleContext.some(ctx => contextStrings.includes(ctx));
  }

  private processVariables(content: string, variables?: Record<string, string>): string {
    if (!variables) return content;

    let processedContent = content;
    
    Object.entries(variables).forEach(([key, value]) => {
      const pattern = new RegExp(`\\{\\{\\s*${key}\\s*\\}\\}`, 'g');
      processedContent = processedContent.replace(pattern, value);
    });

    return processedContent;
  }

  private validateContent(content: string, type: ContentType): ContentValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];

    // Basic validation
    if (!content.trim()) {
      errors.push('Content cannot be empty');
    }

    // Type-specific validation
    switch (type) {
      case 'welcome-message':
        if (content.length > 500) {
          warnings.push('Welcome message is quite long. Consider keeping it under 500 characters.');
        }
        if (!content.includes('{{')) {
          suggestions.push('Consider using variables like {{userName}} for personalization');
        }
        break;

      case 'error-message':
        if (!content.includes('error') && !content.includes('problem')) {
          warnings.push('Error messages should clearly indicate there is an issue');
        }
        if (content.length > 200) {
          warnings.push('Error messages should be concise');
        }
        break;

      case 'legal-document':
        if (content.length < 100) {
          warnings.push('Legal document seems too short to be comprehensive');
        }
        break;
    }

    // HTML validation for HTML content
    if (content.includes('<')) {
      const htmlValidation = this.validateHtml(content);
      errors.push(...htmlValidation.errors);
      warnings.push(...htmlValidation.warnings);
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
    };
  }

  private validateLegalDocument(content: string, documentType: string): ContentValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];
    const suggestions: string[] = [];

    // Minimum length requirements
    const minLengths = {
      privacyPolicy: 500,
      termsOfService: 300,
      cookiePolicy: 200,
      dataProcessingAgreement: 400,
      complianceStatement: 100,
    };

    const minLength = minLengths[documentType as keyof typeof minLengths] || 100;
    if (content.length < minLength) {
      warnings.push(`${documentType} should be at least ${minLength} characters long`);
    }

    // Required sections for privacy policy
    if (documentType === 'privacyPolicy') {
      const requiredSections = ['data collection', 'data use', 'data sharing', 'contact'];
      const missingSection = requiredSections.find(section => 
        !content.toLowerCase().includes(section.replace(' ', ''))
      );
      if (missingSection) {
        warnings.push(`Privacy policy should include section about ${missingSection}`);
      }
    }

    // Date validation
    const currentYear = new Date().getFullYear();
    if (!content.includes(currentYear.toString())) {
      suggestions.push(`Consider including the current year (${currentYear}) in the document`);
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      suggestions,
    };
  }

  private validateHtml(html: string): { errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic HTML validation
    const openTags = html.match(/<[^\/][^>]*>/g) || [];
    const closeTags = html.match(/<\/[^>]*>/g) || [];

    if (openTags.length !== closeTags.length) {
      errors.push('HTML tags are not properly balanced');
    }

    // Check for dangerous HTML
    const dangerousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /on\w+\s*=\s*["'][^"']*["']/gi,
      /javascript:/gi,
    ];

    if (dangerousPatterns.some(pattern => pattern.test(html))) {
      errors.push('HTML contains potentially dangerous content (scripts, event handlers)');
    }

    return { errors, warnings };
  }

  private clearContentCache(tenantId: string, type?: ContentType, key?: string): void {
    if (type && key) {
      this.contentCache.delete(`content:${tenantId}:${type}:${key}`);
    } else {
      // Clear all content cache for tenant
      for (const cacheKey of this.contentCache.keys()) {
        if (cacheKey.startsWith(`content:${tenantId}:`)) {
          this.contentCache.delete(cacheKey);
        }
      }
    }
  }

  private clearLegalDocumentCache(tenantId: string, documentType: string): void {
    this.contentCache.delete(`legal:${tenantId}:${documentType}`);
  }

  private generateId(): string {
    return `content_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Mock database operations - would be replaced with actual database calls

  private async loadTerminologyRules(tenantId: string): Promise<TerminologyRule[]> {
    const mappings = await this.loadTerminologyMappings(tenantId);
    return mappings.map((mapping, index) => ({
      id: mapping.id,
      pattern: mapping.originalTerm,
      replacement: mapping.customTerm,
      context: mapping.context,
      caseSensitive: mapping.caseSensitive,
      wholeWord: true,
      priority: 1,
    }));
  }

  private async loadTerminologyMappings(tenantId: string): Promise<TerminologyMapping[]> {
    // Mock implementation
    return [];
  }

  private async saveTerminologyMapping(mapping: TerminologyMapping): Promise<void> {
    // Mock implementation
    console.log('Saving terminology mapping:', mapping);
  }

  private async loadContentTemplate(type: ContentType, key: string, tenantId: string): Promise<ContentTemplate | null> {
    // Mock implementation
    return null;
  }

  private async createContentTemplate(
    type: ContentType,
    key: string,
    tenantId: string,
    content: string,
    userId: string
  ): Promise<ContentTemplate> {
    const template: ContentTemplate = {
      id: this.generateId(),
      type,
      key,
      defaultContent: content,
      customContent: content,
      variables: this.extractVariables(content),
      isHtml: content.includes('<'),
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    await this.saveContentTemplate(template);
    return template;
  }

  private async saveContentTemplate(template: ContentTemplate): Promise<void> {
    // Mock implementation
    console.log('Saving content template:', template);
  }

  private async loadAllContentTemplates(tenantId: string): Promise<ContentTemplate[]> {
    // Mock implementation
    return [];
  }

  private async saveLegalDocument(
    tenantId: string,
    documentType: string,
    content: string,
    userId: string
  ): Promise<void> {
    // Mock implementation
    console.log(`Saving legal document ${documentType} for tenant ${tenantId}`);
  }

  private async loadLegalDocument(tenantId: string, documentType: string): Promise<string | null> {
    // Mock implementation
    return null;
  }

  private async loadAllLegalDocuments(tenantId: string): Promise<Record<string, string>> {
    // Mock implementation
    return {};
  }

  private extractVariables(content: string): string[] {
    const matches = content.match(/\{\{\s*([^}]+)\s*\}\}/g) || [];
    return matches.map(match => match.replace(/[{}]/g, '').trim());
  }
}

// Export singleton instance
export const contentManager = ContentManager.getInstance();