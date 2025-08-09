#!/usr/bin/env ts-node

/**
 * CI/CD Integration for API Documentation
 * 
 * Integrates documentation generation with CI/CD pipelines
 * Provides automated validation, generation, and deployment
 */

import { promises as fs } from 'fs';
import { execSync } from 'child_process';
import path from 'path';
import { DocumentationGenerator } from './generate-docs';
import { validateOpenAPISpec } from './utils/doc-utils';

interface CICDConfig {
  validation: {
    enabled: boolean;
    breakOnErrors: boolean;
    tools: string[];
  };
  generation: {
    enabled: boolean;
    formats: string[];
    versioning: boolean;
  };
  deployment: {
    enabled: boolean;
    targets: Array<{
      name: string;
      type: 'gcs' | 's3' | 'github-pages' | 'netlify' | 'vercel';
      config: Record<string, any>;
    }>;
  };
  notifications: {
    enabled: boolean;
    channels: Array<{
      type: 'slack' | 'teams' | 'email';
      config: Record<string, any>;
    }>;
  };
}

class CICDIntegration {
  private config: CICDConfig;
  private buildId: string;
  private commitHash: string;
  private branch: string;

  constructor(configPath?: string) {
    this.config = this.loadConfig(configPath);
    this.buildId = process.env.BUILD_ID || `build-${Date.now()}`;
    this.commitHash = this.getCommitHash();
    this.branch = this.getBranch();
    
    console.log(`🚀 Starting CI/CD Documentation Pipeline`);
    console.log(`Build ID: ${this.buildId}`);
    console.log(`Commit: ${this.commitHash}`);
    console.log(`Branch: ${this.branch}`);
  }

  private loadConfig(configPath?: string): CICDConfig {
    const defaultConfig: CICDConfig = {
      validation: {
        enabled: true,
        breakOnErrors: true,
        tools: ['swagger-validator', 'redocly', 'spectral']
      },
      generation: {
        enabled: true,
        formats: ['html', 'pdf'],
        versioning: true
      },
      deployment: {
        enabled: process.env.DEPLOY_DOCS === 'true',
        targets: []
      },
      notifications: {
        enabled: process.env.NOTIFY_ON_DOCS === 'true',
        channels: []
      }
    };

    if (configPath && require('fs').existsSync(configPath)) {
      const customConfig = JSON.parse(require('fs').readFileSync(configPath, 'utf8'));
      return { ...defaultConfig, ...customConfig };
    }

    return defaultConfig;
  }

  private getCommitHash(): string {
    try {
      return execSync('git rev-parse HEAD').toString().trim().substring(0, 8);
    } catch {
      return 'unknown';
    }
  }

  private getBranch(): string {
    try {
      return execSync('git rev-parse --abbrev-ref HEAD').toString().trim();
    } catch {
      return 'unknown';
    }
  }

  async run(): Promise<void> {
    const startTime = Date.now();
    
    try {
      // Step 1: Validation
      if (this.config.validation.enabled) {
        console.log('\\n📋 Step 1: Validating OpenAPI specifications...');
        await this.validateSpecifications();
      }

      // Step 2: Generation
      if (this.config.generation.enabled) {
        console.log('\\n🏗️  Step 2: Generating documentation...');
        await this.generateDocumentation();
      }

      // Step 3: Deployment
      if (this.config.deployment.enabled) {
        console.log('\\n🚀 Step 3: Deploying documentation...');
        await this.deployDocumentation();
      }

      // Step 4: Notifications
      if (this.config.notifications.enabled) {
        console.log('\\n📢 Step 4: Sending notifications...');
        await this.sendNotifications('success');
      }

      const duration = Math.round((Date.now() - startTime) / 1000);
      console.log(`\\n✅ Documentation pipeline completed successfully in ${duration}s`);

    } catch (error) {
      console.error(`\\n❌ Documentation pipeline failed:`, error.message);
      
      if (this.config.notifications.enabled) {
        await this.sendNotifications('failure', error.message);
      }
      
      process.exit(1);
    }
  }

  private async validateSpecifications(): Promise<void> {
    const specFiles = [
      'app/api/openapi-complete.json',
      'backend/openapi-backend-services.json',
      'app/api/openapi-extended-apis.json'
    ];

    const validationResults = [];

    for (const specFile of specFiles) {
      console.log(`  🔍 Validating ${specFile}...`);
      
      if (!(await fs.stat(specFile).catch(() => false))) {
        throw new Error(`Specification file not found: ${specFile}`);
      }

      // Basic validation
      const isValid = await validateOpenAPISpec(specFile);
      if (!isValid && this.config.validation.breakOnErrors) {
        throw new Error(`Validation failed for ${specFile}`);
      }

      // Advanced validation with external tools
      for (const tool of this.config.validation.tools) {
        await this.runValidationTool(tool, specFile);
      }

      validationResults.push({
        file: specFile,
        valid: isValid,
        timestamp: new Date().toISOString()
      });
    }

    // Save validation report
    const validationReport = {
      buildId: this.buildId,
      commit: this.commitHash,
      branch: this.branch,
      timestamp: new Date().toISOString(),
      results: validationResults,
      tools: this.config.validation.tools
    };

    await fs.mkdir('docs/api/generated/reports', { recursive: true });
    await fs.writeFile(
      'docs/api/generated/reports/validation-report.json',
      JSON.stringify(validationReport, null, 2)
    );

    console.log('  ✅ All specifications validated successfully');
  }

  private async runValidationTool(tool: string, specFile: string): Promise<void> {
    try {
      switch (tool) {
        case 'swagger-validator':
          await this.runSwaggerValidator(specFile);
          break;
        case 'redocly':
          await this.runRedoclyLint(specFile);
          break;
        case 'spectral':
          await this.runSpectral(specFile);
          break;
        default:
          console.warn(`    ⚠️  Unknown validation tool: ${tool}`);
      }
    } catch (error) {
      if (this.config.validation.breakOnErrors) {
        throw error;
      } else {
        console.warn(`    ⚠️  ${tool} validation failed: ${error.message}`);
      }
    }
  }

  private async runSwaggerValidator(specFile: string): Promise<void> {
    try {
      execSync(`swagger-validator validate ${specFile}`, { stdio: 'pipe' });
      console.log(`    ✅ swagger-validator: ${specFile} is valid`);
    } catch (error) {
      throw new Error(`swagger-validator failed for ${specFile}: ${error.message}`);
    }
  }

  private async runRedoclyLint(specFile: string): Promise<void> {
    try {
      execSync(`redocly lint ${specFile}`, { stdio: 'pipe' });
      console.log(`    ✅ redocly: ${specFile} passed linting`);
    } catch (error) {
      throw new Error(`redocly lint failed for ${specFile}: ${error.message}`);
    }
  }

  private async runSpectral(specFile: string): Promise<void> {
    try {
      execSync(`spectral lint ${specFile}`, { stdio: 'pipe' });
      console.log(`    ✅ spectral: ${specFile} passed linting`);
    } catch (error) {
      throw new Error(`spectral lint failed for ${specFile}: ${error.message}`);
    }
  }

  private async generateDocumentation(): Promise<void> {
    const generator = new DocumentationGenerator();
    await generator.generate();

    // Create deployment manifest
    const deploymentManifest = {
      buildId: this.buildId,
      commit: this.commitHash,
      branch: this.branch,
      timestamp: new Date().toISOString(),
      formats: this.config.generation.formats,
      files: await this.getGeneratedFiles()
    };

    await fs.writeFile(
      'docs/api/generated/deployment-manifest.json',
      JSON.stringify(deploymentManifest, null, 2)
    );

    console.log('  ✅ Documentation generated successfully');
  }

  private async getGeneratedFiles(): Promise<string[]> {
    const generatedDir = 'docs/api/generated';
    const files: string[] = [];

    const addFiles = async (dir: string, basePath: string = '') => {
      const items = await fs.readdir(path.join(generatedDir, dir), { withFileTypes: true });
      
      for (const item of items) {
        const relativePath = path.join(basePath, item.name);
        
        if (item.isDirectory()) {
          await addFiles(path.join(dir, item.name), relativePath);
        } else {
          files.push(relativePath);
        }
      }
    };

    try {
      await addFiles('');
    } catch (error) {
      console.warn('Could not list generated files:', error.message);
    }

    return files;
  }

  private async deployDocumentation(): Promise<void> {
    for (const target of this.config.deployment.targets) {
      console.log(`  🚀 Deploying to ${target.name} (${target.type})...`);
      
      try {
        switch (target.type) {
          case 'gcs':
            await this.deployToGCS(target.config);
            break;
          case 's3':
            await this.deployToS3(target.config);
            break;
          case 'github-pages':
            await this.deployToGitHubPages(target.config);
            break;
          case 'netlify':
            await this.deployToNetlify(target.config);
            break;
          case 'vercel':
            await this.deployToVercel(target.config);
            break;
          default:
            throw new Error(`Unknown deployment target type: ${target.type}`);
        }
        
        console.log(`    ✅ Deployed to ${target.name} successfully`);
      } catch (error) {
        console.error(`    ❌ Deployment to ${target.name} failed:`, error.message);
        throw error;
      }
    }
  }

  private async deployToGCS(config: any): Promise<void> {
    const bucket = config.bucket;
    const prefix = config.prefix || 'docs/';
    
    execSync(`gsutil -m rsync -r -d docs/api/generated/ gs://${bucket}/${prefix}`, {
      stdio: 'inherit'
    });
  }

  private async deployToS3(config: any): Promise<void> {
    const bucket = config.bucket;
    const prefix = config.prefix || 'docs/';
    
    execSync(`aws s3 sync docs/api/generated/ s3://${bucket}/${prefix} --delete`, {
      stdio: 'inherit'
    });
  }

  private async deployToGitHubPages(config: any): Promise<void> {
    const repoUrl = config.repository;
    const branch = config.branch || 'gh-pages';
    
    // Clone or update gh-pages branch
    const tempDir = `temp-gh-pages-${this.buildId}`;
    
    try {
      execSync(`git clone --single-branch --branch ${branch} ${repoUrl} ${tempDir}`, {
        stdio: 'inherit'
      });
      
      // Copy generated docs
      execSync(`cp -r docs/api/generated/* ${tempDir}/`, {
        stdio: 'inherit'
      });
      
      // Commit and push
      execSync('git add .', { cwd: tempDir, stdio: 'inherit' });
      execSync(`git commit -m "Update documentation (${this.buildId})"`, {
        cwd: tempDir,
        stdio: 'inherit'
      });
      execSync(`git push origin ${branch}`, { cwd: tempDir, stdio: 'inherit' });
      
    } finally {
      // Cleanup
      execSync(`rm -rf ${tempDir}`, { stdio: 'inherit' });
    }
  }

  private async deployToNetlify(config: any): Promise<void> {
    const siteId = config.siteId;
    const accessToken = config.accessToken || process.env.NETLIFY_ACCESS_TOKEN;
    
    if (!accessToken) {
      throw new Error('Netlify access token not found');
    }
    
    execSync(`netlify deploy --prod --dir=docs/api/generated --site=${siteId} --auth=${accessToken}`, {
      stdio: 'inherit'
    });
  }

  private async deployToVercel(config: any): Promise<void> {
    const projectId = config.projectId;
    const token = config.token || process.env.VERCEL_TOKEN;
    
    if (!token) {
      throw new Error('Vercel token not found');
    }
    
    execSync(`vercel --prod --yes --token=${token} docs/api/generated`, {
      stdio: 'inherit'
    });
  }

  private async sendNotifications(status: 'success' | 'failure', error?: string): Promise<void> {
    for (const channel of this.config.notifications.channels) {
      try {
        switch (channel.type) {
          case 'slack':
            await this.sendSlackNotification(channel.config, status, error);
            break;
          case 'teams':
            await this.sendTeamsNotification(channel.config, status, error);
            break;
          case 'email':
            await this.sendEmailNotification(channel.config, status, error);
            break;
          default:
            console.warn(`  ⚠️  Unknown notification channel: ${channel.type}`);
        }
      } catch (notificationError) {
        console.warn(`  ⚠️  Failed to send ${channel.type} notification:`, notificationError.message);
      }
    }
  }

  private async sendSlackNotification(config: any, status: 'success' | 'failure', error?: string): Promise<void> {
    const webhookUrl = config.webhookUrl;
    const channel = config.channel;
    
    const color = status === 'success' ? '#36a64f' : '#ff0000';
    const emoji = status === 'success' ? ':white_check_mark:' : ':x:';
    
    const payload = {
      channel,
      username: 'API Documentation Bot',
      icon_emoji: ':books:',
      attachments: [
        {
          color,
          title: `${emoji} API Documentation ${status === 'success' ? 'Generated' : 'Failed'}`,
          fields: [
            { title: 'Build ID', value: this.buildId, short: true },
            { title: 'Branch', value: this.branch, short: true },
            { title: 'Commit', value: this.commitHash, short: true },
            { title: 'Timestamp', value: new Date().toISOString(), short: true }
          ],
          ...(error && { text: `Error: ${error}` })
        }
      ]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Slack notification failed: ${response.statusText}`);
    }
  }

  private async sendTeamsNotification(config: any, status: 'success' | 'failure', error?: string): Promise<void> {
    const webhookUrl = config.webhookUrl;
    
    const themeColor = status === 'success' ? '00FF00' : 'FF0000';
    const title = `API Documentation ${status === 'success' ? 'Generated Successfully' : 'Generation Failed'}`;
    
    const payload = {
      '@type': 'MessageCard',
      '@context': 'https://schema.org/extensions',
      summary: title,
      themeColor,
      sections: [
        {
          activityTitle: title,
          activitySubtitle: `Build ${this.buildId}`,
          facts: [
            { name: 'Branch', value: this.branch },
            { name: 'Commit', value: this.commitHash },
            { name: 'Timestamp', value: new Date().toISOString() },
            ...(error ? [{ name: 'Error', value: error }] : [])
          ]
        }
      ]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Teams notification failed: ${response.statusText}`);
    }
  }

  private async sendEmailNotification(config: any, status: 'success' | 'failure', error?: string): Promise<void> {
    // This would integrate with your email service (SendGrid, SES, etc.)
    console.log('📧 Email notification would be sent here');
    console.log(`   To: ${config.recipients?.join(', ')}`);
    console.log(`   Subject: API Documentation ${status === 'success' ? 'Generated' : 'Failed'} - Build ${this.buildId}`);
  }
}

// GitHub Actions integration
export function generateGitHubActionsWorkflow(): string {
  return `name: API Documentation

on:
  push:
    branches: [main, develop]
    paths:
      - 'app/api/*.json'
      - 'backend/*.json'
      - 'docs/api/**'
  pull_request:
    branches: [main]
    paths:
      - 'app/api/*.json'
      - 'backend/*.json'
      - 'docs/api/**'

jobs:
  validate-and-generate-docs:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Install documentation tools
      run: |
        npm install -g @redocly/cli@latest
        npm install -g @stoplight/spectral-cli@latest
        
    - name: Validate OpenAPI specifications
      run: npm run docs:validate
      
    - name: Generate documentation
      run: npm run docs:generate
      
    - name: Upload documentation artifacts
      uses: actions/upload-artifact@v3
      with:
        name: api-documentation-\${{ github.sha }}
        path: docs/api/generated/
        retention-days: 30
        
    - name: Deploy to GitHub Pages
      if: github.ref == 'refs/heads/main'
      uses: peaceiris/actions-gh-pages@v3
      with:
        github_token: \${{ secrets.GITHUB_TOKEN }}
        publish_dir: ./docs/api/generated
        destination_dir: api-docs
        
    - name: Notify Slack on success
      if: success() && github.ref == 'refs/heads/main'
      uses: 8398a7/action-slack@v3
      with:
        status: success
        text: 'API Documentation generated and deployed successfully'
      env:
        SLACK_WEBHOOK_URL: \${{ secrets.SLACK_WEBHOOK_URL }}
        
    - name: Notify Slack on failure
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        text: 'API Documentation generation failed'
      env:
        SLACK_WEBHOOK_URL: \${{ secrets.SLACK_WEBHOOK_URL }}
`;
}

// Main execution
async function main() {
  const integration = new CICDIntegration(process.argv[2]);
  await integration.run();
}

// Export for use as module
export { CICDIntegration, generateGitHubActionsWorkflow };

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}