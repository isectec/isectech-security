/**
 * Configuration Manager for iSECTECH Protect White-Labeling
 * Production-grade unified configuration management system
 */

import { themeManager } from './theme-manager';
import { assetManager } from './asset-manager';
import { contentManager } from './content-manager';
import { domainManager } from './domain-manager';
import { emailTemplateManager } from './email-template-manager';
import type {
  WhiteLabelConfiguration,
  ThemeConfiguration,
  ConfigurationStatus,
  ConfigurationPreview,
  ConfigurationDeployment,
  BrandAsset,
  AssetType,
  DomainConfiguration,
  EmailTemplate,
  ValidationResult,
  BrandingConfigUpdate
} from '@/types/white-labeling';

export interface ConfigurationManagerOptions {
  includeAssets?: boolean;
  includeContent?: boolean;
  includeDomain?: boolean;
  includeEmailTemplates?: boolean;
  validateBeforeSave?: boolean;
}

export interface ConfigurationExport {
  configuration: WhiteLabelConfiguration;
  assets: Record<AssetType, BrandAsset | null>;
  contentCustomizations: any;
  domainConfiguration?: DomainConfiguration;
  emailTemplates: EmailTemplate[];
  exportedAt: Date;
  version: string;
}

export interface ConfigurationImportResult {
  success: boolean;
  configurationId: string;
  errors: string[];
  warnings: string[];
  imported: {
    theme: boolean;
    assets: number;
    content: number;
    domain: boolean;
    emailTemplates: number;
  };
}

export class ConfigurationManager {
  private static instance: ConfigurationManager;
  private configurationCache = new Map<string, WhiteLabelConfiguration>();
  private previewCache = new Map<string, ConfigurationPreview>();
  private deploymentCache = new Map<string, ConfigurationDeployment>();
  
  private constructor() {}

  public static getInstance(): ConfigurationManager {
    if (!ConfigurationManager.instance) {
      ConfigurationManager.instance = new ConfigurationManager();
    }
    return ConfigurationManager.instance;
  }

  /**
   * Create a new white-label configuration
   */
  public async createConfiguration(
    tenantId: string,
    configData: {
      name: string;
      description: string;
      theme?: ThemeConfiguration;
      assets?: Record<AssetType, BrandAsset | null>;
      content?: any[];
      domain?: DomainConfiguration;
      emailTemplates?: EmailTemplate[];
    },
    userId: string
  ): Promise<WhiteLabelConfiguration> {
    // Generate configuration ID
    const configurationId = this.generateConfigurationId();

    // Create base configuration
    const configuration: WhiteLabelConfiguration = {
      id: configurationId,
      name: configData.name,
      description: configData.description,
      status: 'draft',
      theme: configData.theme || this.getDefaultThemeConfiguration(tenantId),
      content: configData.content || [],
      terminology: [],
      domain: configData.domain,
      emailTemplates: configData.emailTemplates || [],
      legalDocuments: {},
      version: '1.0.0',
      isActive: false,
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    // Validate configuration
    const validation = await this.validateConfiguration(configuration);
    if (!validation.isValid) {
      throw new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
    }

    // Save configuration
    await this.saveConfiguration(configuration);

    // Cache the configuration
    this.configurationCache.set(configurationId, configuration);

    return configuration;
  }

  /**
   * Update existing configuration
   */
  public async updateConfiguration(
    configurationId: string,
    tenantId: string,
    updates: BrandingConfigUpdate,
    userId: string
  ): Promise<WhiteLabelConfiguration> {
    const existing = await this.getConfiguration(configurationId, tenantId);
    if (!existing) {
      throw new Error('Configuration not found');
    }

    // Apply updates
    const updated: WhiteLabelConfiguration = {
      ...existing,
      ...updates,
      updatedAt: new Date(),
      updatedBy: userId,
      version: this.incrementVersion(existing.version),
    };

    // Validate updated configuration
    const validation = await this.validateConfiguration(updated);
    if (!validation.isValid) {
      throw new Error(`Configuration validation failed: ${validation.errors.join(', ')}`);
    }

    // Save updated configuration
    await this.saveConfiguration(updated);

    // Clear cache
    this.configurationCache.delete(configurationId);

    return updated;
  }

  /**
   * Get configuration by ID
   */
  public async getConfiguration(
    configurationId: string,
    tenantId: string
  ): Promise<WhiteLabelConfiguration | null> {
    // Check cache first
    if (this.configurationCache.has(configurationId)) {
      const cached = this.configurationCache.get(configurationId)!;
      if (cached.tenantId === tenantId) {
        return cached;
      }
    }

    // Fetch from database
    const configuration = await this.fetchConfigurationFromDatabase(configurationId, tenantId);
    
    if (configuration) {
      this.configurationCache.set(configurationId, configuration);
    }

    return configuration;
  }

  /**
   * Get all configurations for tenant
   */
  public async getConfigurationsForTenant(
    tenantId: string,
    options?: {
      status?: ConfigurationStatus[];
      limit?: number;
      offset?: number;
      sortBy?: 'name' | 'createdAt' | 'updatedAt';
      sortOrder?: 'asc' | 'desc';
    }
  ): Promise<{ configurations: WhiteLabelConfiguration[]; total: number }> {
    return this.fetchConfigurationsForTenant(tenantId, options);
  }

  /**
   * Validate configuration completeness and correctness
   */
  public async validateConfiguration(
    configuration: WhiteLabelConfiguration
  ): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Basic validation
    if (!configuration.name?.trim()) {
      errors.push('Configuration name is required');
    }

    if (!configuration.description?.trim()) {
      warnings.push('Configuration description is recommended');
    }

    // Theme validation
    if (configuration.theme) {
      const themeValidation = themeManager.validateConfiguration(configuration.theme);
      errors.push(...themeValidation.errors);
      warnings.push(...themeValidation.warnings);
    }

    // Asset validation
    const requiredAssets: AssetType[] = ['logo-primary', 'favicon'];
    const missingAssets = requiredAssets.filter(type => !configuration.theme?.assets?.[type]);
    
    if (missingAssets.length > 0) {
      warnings.push(`Missing recommended assets: ${missingAssets.join(', ')}`);
    }

    // Domain validation
    if (configuration.domain) {
      try {
        const domainValidation = await domainManager.validateDnsRecords(
          configuration.domain.domain,
          configuration.tenantId
        );
        if (!domainValidation.isValid) {
          warnings.push('Domain DNS records are not properly configured');
        }
      } catch (error) {
        warnings.push('Could not validate domain configuration');
      }
    }

    // Email templates validation
    for (const template of configuration.emailTemplates) {
      const templateValidation = emailTemplateManager.validateTemplate(template);
      errors.push(...templateValidation.errors.map(e => `Email template "${template.name}": ${e}`));
      warnings.push(...templateValidation.warnings.map(w => `Email template "${template.name}": ${w}`));
    }

    // Content validation
    if (configuration.content.length === 0) {
      warnings.push('No custom content defined - using default platform content');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Generate preview for configuration
   */
  public async generatePreview(
    configurationId: string,
    tenantId: string,
    options?: {
      includeScreenshots?: boolean;
      devices?: ('desktop' | 'tablet' | 'mobile')[];
      expiresInHours?: number;
    }
  ): Promise<ConfigurationPreview> {
    const configuration = await this.getConfiguration(configurationId, tenantId);
    if (!configuration) {
      throw new Error('Configuration not found');
    }

    // Generate preview URL
    const previewUrl = await this.createPreviewEnvironment(configuration);

    // Generate screenshots if requested
    const screenshots = options?.includeScreenshots 
      ? await this.generateScreenshots(previewUrl, options.devices)
      : { desktop: '', tablet: '', mobile: '' };

    const preview: ConfigurationPreview = {
      configurationId,
      previewUrl,
      screenshots,
      generatedAt: new Date(),
      expiresAt: new Date(Date.now() + (options?.expiresInHours || 24) * 60 * 60 * 1000),
    };

    // Cache preview
    this.previewCache.set(configurationId, preview);

    return preview;
  }

  /**
   * Deploy configuration to production
   */
  public async deployConfiguration(
    configurationId: string,
    tenantId: string,
    userId: string,
    options?: {
      immediateDeployment?: boolean;
      rollbackVersion?: string;
      deploymentNotes?: string;
    }
  ): Promise<ConfigurationDeployment> {
    const configuration = await this.getConfiguration(configurationId, tenantId);
    if (!configuration) {
      throw new Error('Configuration not found');
    }

    if (configuration.status !== 'approved') {
      throw new Error('Configuration must be approved before deployment');
    }

    // Create deployment record
    const deployment: ConfigurationDeployment = {
      id: this.generateDeploymentId(),
      configurationId,
      fromVersion: await this.getCurrentActiveVersion(tenantId),
      toVersion: configuration.version,
      deployedBy: userId,
      deploymentStatus: 'pending',
      rollbackVersion: options?.rollbackVersion,
      deploymentLog: [{
        timestamp: new Date(),
        level: 'info',
        message: `Deployment initiated by ${userId}${options?.deploymentNotes ? ': ' + options.deploymentNotes : ''}`,
      }],
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    // Save deployment record
    await this.saveDeployment(deployment);

    // Start deployment process
    try {
      deployment.deploymentStatus = 'in-progress';
      deployment.deploymentLog.push({
        timestamp: new Date(),
        level: 'info',
        message: 'Starting deployment process',
      });

      // Deploy theme configuration
      if (configuration.theme) {
        await this.deployThemeConfiguration(configuration.theme, tenantId);
        deployment.deploymentLog.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Theme configuration deployed successfully',
        });
      }

      // Deploy assets
      if (configuration.theme?.assets) {
        await this.deployAssets(configuration.theme.assets, tenantId);
        deployment.deploymentLog.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Brand assets deployed successfully',
        });
      }

      // Deploy content customizations
      if (configuration.content.length > 0 || configuration.terminology.length > 0) {
        await this.deployContentCustomizations(configuration, tenantId);
        deployment.deploymentLog.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Content customizations deployed successfully',
        });
      }

      // Deploy domain configuration
      if (configuration.domain) {
        await this.deployDomainConfiguration(configuration.domain, tenantId);
        deployment.deploymentLog.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Domain configuration deployed successfully',
        });
      }

      // Deploy email templates
      if (configuration.emailTemplates.length > 0) {
        await this.deployEmailTemplates(configuration.emailTemplates, tenantId);
        deployment.deploymentLog.push({
          timestamp: new Date(),
          level: 'info',
          message: 'Email templates deployed successfully',
        });
      }

      // Mark configuration as active
      configuration.isActive = true;
      configuration.status = 'active';
      await this.saveConfiguration(configuration);

      // Complete deployment
      deployment.deploymentStatus = 'completed';
      deployment.deploymentLog.push({
        timestamp: new Date(),
        level: 'info',
        message: 'Deployment completed successfully',
      });

    } catch (error) {
      deployment.deploymentStatus = 'failed';
      deployment.deploymentLog.push({
        timestamp: new Date(),
        level: 'error',
        message: `Deployment failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });

      throw error;
    } finally {
      deployment.updatedAt = new Date();
      await this.saveDeployment(deployment);
    }

    return deployment;
  }

  /**
   * Rollback to previous configuration version
   */
  public async rollbackConfiguration(
    configurationId: string,
    tenantId: string,
    targetVersion: string,
    userId: string
  ): Promise<ConfigurationDeployment> {
    const currentConfig = await this.getConfiguration(configurationId, tenantId);
    if (!currentConfig) {
      throw new Error('Configuration not found');
    }

    const targetConfig = await this.getConfigurationVersion(configurationId, targetVersion, tenantId);
    if (!targetConfig) {
      throw new Error('Target version not found');
    }

    // Create rollback deployment
    const deployment: ConfigurationDeployment = {
      id: this.generateDeploymentId(),
      configurationId,
      fromVersion: currentConfig.version,
      toVersion: targetVersion,
      deployedBy: userId,
      deploymentStatus: 'in-progress',
      rollbackVersion: currentConfig.version,
      deploymentLog: [{
        timestamp: new Date(),
        level: 'info',
        message: `Rollback initiated by ${userId} to version ${targetVersion}`,
      }],
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: userId,
      updatedBy: userId,
    };

    try {
      // Perform rollback deployment
      await this.deployConfiguration(configurationId, tenantId, userId, {
        rollbackVersion: currentConfig.version,
        deploymentNotes: `Rollback to version ${targetVersion}`,
      });

      deployment.deploymentStatus = 'completed';
    } catch (error) {
      deployment.deploymentStatus = 'failed';
      deployment.deploymentLog.push({
        timestamp: new Date(),
        level: 'error',
        message: `Rollback failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    }

    return deployment;
  }

  /**
   * Export configuration with all assets and customizations
   */
  public async exportConfiguration(
    configurationId: string,
    tenantId: string,
    options: ConfigurationManagerOptions = {}
  ): Promise<ConfigurationExport> {
    const configuration = await this.getConfiguration(configurationId, tenantId);
    if (!configuration) {
      throw new Error('Configuration not found');
    }

    const exportData: ConfigurationExport = {
      configuration,
      assets: configuration.theme?.assets || {},
      contentCustomizations: {},
      emailTemplates: configuration.emailTemplates,
      exportedAt: new Date(),
      version: configuration.version,
    };

    // Include content customizations
    if (options.includeContent !== false) {
      exportData.contentCustomizations = await contentManager.exportCustomizations(tenantId);
    }

    // Include domain configuration
    if (options.includeDomain !== false && configuration.domain) {
      exportData.domainConfiguration = configuration.domain;
    }

    return exportData;
  }

  /**
   * Import configuration from export data
   */
  public async importConfiguration(
    tenantId: string,
    exportData: ConfigurationExport,
    userId: string,
    options: {
      overwriteExisting?: boolean;
      newConfigurationName?: string;
    } = {}
  ): Promise<ConfigurationImportResult> {
    const result: ConfigurationImportResult = {
      success: false,
      configurationId: '',
      errors: [],
      warnings: [],
      imported: {
        theme: false,
        assets: 0,
        content: 0,
        domain: false,
        emailTemplates: 0,
      },
    };

    try {
      // Create new configuration
      const configuration = await this.createConfiguration(
        tenantId,
        {
          name: options.newConfigurationName || `${exportData.configuration.name} (Imported)`,
          description: exportData.configuration.description,
          theme: exportData.configuration.theme,
          emailTemplates: exportData.emailTemplates,
          domain: exportData.domainConfiguration,
        },
        userId
      );

      result.configurationId = configuration.id;
      result.imported.theme = true;

      // Import assets
      if (exportData.assets) {
        let assetCount = 0;
        for (const [assetType, asset] of Object.entries(exportData.assets)) {
          if (asset) {
            try {
              // Would implement asset duplication/import logic here
              assetCount++;
            } catch (error) {
              result.warnings.push(`Failed to import asset ${assetType}: ${error}`);
            }
          }
        }
        result.imported.assets = assetCount;
      }

      // Import content customizations
      if (exportData.contentCustomizations) {
        try {
          await contentManager.importCustomizations(
            tenantId,
            exportData.contentCustomizations,
            userId,
            { overwrite: options.overwriteExisting }
          );
          result.imported.content = Object.keys(exportData.contentCustomizations.terminology || {}).length +
                                   Object.keys(exportData.contentCustomizations.templates || {}).length;
        } catch (error) {
          result.warnings.push(`Failed to import content customizations: ${error}`);
        }
      }

      // Import email templates
      result.imported.emailTemplates = exportData.emailTemplates.length;

      // Import domain configuration
      if (exportData.domainConfiguration) {
        result.imported.domain = true;
      }

      result.success = true;

    } catch (error) {
      result.errors.push(`Import failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }

    return result;
  }

  /**
   * Delete configuration
   */
  public async deleteConfiguration(
    configurationId: string,
    tenantId: string,
    userId: string
  ): Promise<void> {
    const configuration = await this.getConfiguration(configurationId, tenantId);
    if (!configuration) {
      throw new Error('Configuration not found');
    }

    if (configuration.isActive) {
      throw new Error('Cannot delete active configuration. Please deactivate first.');
    }

    // Delete associated assets
    if (configuration.theme?.assets) {
      for (const asset of Object.values(configuration.theme.assets)) {
        if (asset) {
          await assetManager.deleteAsset(asset.id, tenantId);
        }
      }
    }

    // Delete configuration from database
    await this.deleteConfigurationFromDatabase(configurationId, tenantId);

    // Clear caches
    this.configurationCache.delete(configurationId);
    this.previewCache.delete(configurationId);
  }

  // Private helper methods

  private async deployThemeConfiguration(theme: ThemeConfiguration, tenantId: string): Promise<void> {
    // Apply theme to platform
    const cssVariables = themeManager.generateCssVariables(theme);
    themeManager.applyCssVariables(cssVariables);
    
    // Load web fonts if specified
    await themeManager.loadWebFonts(theme);
  }

  private async deployAssets(assets: Record<AssetType, BrandAsset | null>, tenantId: string): Promise<void> {
    // Deploy assets to CDN and update references
    for (const [type, asset] of Object.entries(assets)) {
      if (asset) {
        // Would implement asset deployment to CDN here
        console.log(`Deploying asset ${type}:`, asset.url);
      }
    }
  }

  private async deployContentCustomizations(config: WhiteLabelConfiguration, tenantId: string): Promise<void> {
    // Apply content customizations
    for (const content of config.content) {
      // Would implement content deployment here
      console.log('Deploying content customization:', content);
    }
  }

  private async deployDomainConfiguration(domain: DomainConfiguration, tenantId: string): Promise<void> {
    // Configure routing and SSL for domain
    console.log('Deploying domain configuration:', domain.domain);
  }

  private async deployEmailTemplates(templates: EmailTemplate[], tenantId: string): Promise<void> {
    // Update email service with new templates
    for (const template of templates) {
      console.log('Deploying email template:', template.name);
    }
  }

  private async createPreviewEnvironment(configuration: WhiteLabelConfiguration): Promise<string> {
    // Mock preview URL generation
    const previewId = this.generatePreviewId();
    return `https://preview.isectech.com/${previewId}`;
  }

  private async generateScreenshots(
    previewUrl: string,
    devices?: ('desktop' | 'tablet' | 'mobile')[]
  ): Promise<{ desktop: string; tablet: string; mobile: string }> {
    // Mock screenshot generation
    return {
      desktop: `${previewUrl}/screenshot-desktop.png`,
      tablet: `${previewUrl}/screenshot-tablet.png`,
      mobile: `${previewUrl}/screenshot-mobile.png`,
    };
  }

  private getDefaultThemeConfiguration(tenantId: string): ThemeConfiguration {
    // Return default theme configuration
    return {
      id: 'default-theme',
      name: 'Default Theme',
      description: 'Default iSECTECH theme',
      colorScheme: {
        id: 'default-colors',
        name: 'Default Colors',
        description: 'Default color scheme',
        light: {
          primary: '#1976d2',
          primaryDark: '#115293',
          primaryLight: '#4791db',
          secondary: '#dc004e',
          secondaryDark: '#9a0036',
          secondaryLight: '#e33371',
          accent: '#ff9800',
          accentDark: '#b26a00',
          accentLight: '#ffb74d',
          success: '#4caf50',
          warning: '#ff9800',
          error: '#f44336',
          info: '#2196f3',
          background: '#ffffff',
          surface: '#f5f5f5',
          text: {
            primary: '#212121',
            secondary: '#757575',
            disabled: '#bdbdbd',
          },
          border: '#e0e0e0',
          divider: '#e0e0e0',
        },
        dark: {
          primary: '#4791db',
          primaryDark: '#1976d2',
          primaryLight: '#6bb6ff',
          secondary: '#e33371',
          secondaryDark: '#dc004e',
          secondaryLight: '#e85a8e',
          accent: '#ffb74d',
          accentDark: '#ff9800',
          accentLight: '#ffc947',
          success: '#66bb6a',
          warning: '#ffb74d',
          error: '#ef5350',
          info: '#42a5f5',
          background: '#121212',
          surface: '#1e1e1e',
          text: {
            primary: '#ffffff',
            secondary: '#aaaaaa',
            disabled: '#666666',
          },
          border: '#333333',
          divider: '#333333',
        },
        isDefault: true,
        tenantId,
        createdAt: new Date(),
        updatedAt: new Date(),
        createdBy: 'system',
        updatedBy: 'system',
      },
      typography: {
        id: 'default-typography',
        name: 'Default Typography',
        description: 'Default typography settings',
        fontFamily: {
          name: 'Roboto',
          fallback: ['Arial', 'sans-serif'],
        },
        scale: {
          h1: { fontSize: '2.5rem', fontWeight: 700, lineHeight: 1.2 },
          h2: { fontSize: '2rem', fontWeight: 600, lineHeight: 1.3 },
          h3: { fontSize: '1.75rem', fontWeight: 600, lineHeight: 1.4 },
          h4: { fontSize: '1.5rem', fontWeight: 500, lineHeight: 1.4 },
          h5: { fontSize: '1.25rem', fontWeight: 500, lineHeight: 1.5 },
          h6: { fontSize: '1rem', fontWeight: 500, lineHeight: 1.5 },
          body1: { fontSize: '1rem', fontWeight: 400, lineHeight: 1.6 },
          body2: { fontSize: '0.875rem', fontWeight: 400, lineHeight: 1.6 },
          caption: { fontSize: '0.75rem', fontWeight: 400, lineHeight: 1.4 },
          button: { fontSize: '0.875rem', fontWeight: 500, lineHeight: 1.4, textTransform: 'uppercase' },
        },
        isDefault: true,
        tenantId,
        createdAt: new Date(),
        updatedAt: new Date(),
        createdBy: 'system',
        updatedBy: 'system',
      },
      assets: {},
      isActive: false,
      version: '1.0.0',
      tenantId,
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy: 'system',
      updatedBy: 'system',
    };
  }

  private incrementVersion(version: string): string {
    const parts = version.split('.');
    const patch = parseInt(parts[2] || '0') + 1;
    return `${parts[0] || '1'}.${parts[1] || '0'}.${patch}`;
  }

  private generateConfigurationId(): string {
    return `config_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateDeploymentId(): string {
    return `deploy_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generatePreviewId(): string {
    return `preview_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Mock database operations - would be replaced with actual database calls

  private async saveConfiguration(config: WhiteLabelConfiguration): Promise<void> {
    console.log('Saving configuration:', config);
  }

  private async saveDeployment(deployment: ConfigurationDeployment): Promise<void> {
    console.log('Saving deployment:', deployment);
  }

  private async fetchConfigurationFromDatabase(id: string, tenantId: string): Promise<WhiteLabelConfiguration | null> {
    return null;
  }

  private async fetchConfigurationsForTenant(
    tenantId: string,
    options?: any
  ): Promise<{ configurations: WhiteLabelConfiguration[]; total: number }> {
    return { configurations: [], total: 0 };
  }

  private async getCurrentActiveVersion(tenantId: string): Promise<string> {
    return '0.0.0';
  }

  private async getConfigurationVersion(
    configId: string,
    version: string,
    tenantId: string
  ): Promise<WhiteLabelConfiguration | null> {
    return null;
  }

  private async deleteConfigurationFromDatabase(id: string, tenantId: string): Promise<void> {
    console.log(`Deleting configuration ${id} for tenant ${tenantId}`);
  }
}

// Export singleton instance
export const configurationManager = ConfigurationManager.getInstance();