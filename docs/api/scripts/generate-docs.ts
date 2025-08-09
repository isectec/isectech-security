#!/usr/bin/env ts-node

/**
 * API Documentation Generation Script
 * 
 * Automatically generates comprehensive API documentation from OpenAPI specifications
 * using Swagger UI, ReDoc, and custom templates.
 */

import { promises as fs } from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { validateOpenAPISpec, generateCodeExamples, createVersionedDocs } from './utils/doc-utils';

interface DocumentationConfig {
  specs: Array<{
    name: string;
    file: string;
    description: string;
    version: string;
    category: 'frontend' | 'backend' | 'extended';
  }>;
  output: {
    directory: string;
    formats: string[];
    versioning: boolean;
  };
  generators: {
    swagger: boolean;
    redoc: boolean;
    pdf: boolean;
    postman: boolean;
  };
  codeExamples: {
    languages: string[];
    includeAuth: boolean;
    includeErrorHandling: boolean;
  };
}

class DocumentationGenerator {
  private config: DocumentationConfig;
  private outputDir: string;
  private timestamp: string;

  constructor(configPath?: string) {
    this.config = this.loadConfig(configPath);
    this.outputDir = path.resolve(this.config.output.directory);
    this.timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    
    console.log(`📚 Starting API Documentation Generation`);
    console.log(`Output Directory: ${this.outputDir}`);
  }

  private loadConfig(configPath?: string): DocumentationConfig {
    const defaultConfig: DocumentationConfig = {
      specs: [
        {
          name: 'Complete Frontend API',
          file: 'app/api/openapi-complete.json',
          description: 'Main frontend API endpoints',
          version: '2.0.0',
          category: 'frontend'
        },
        {
          name: 'Backend Services API',
          file: 'backend/openapi-backend-services.json', 
          description: 'Backend microservices API',
          version: '1.0.0',
          category: 'backend'
        },
        {
          name: 'Extended APIs',
          file: 'app/api/openapi-extended-apis.json',
          description: 'Additional frontend API endpoints',
          version: '1.0.0',
          category: 'extended'
        }
      ],
      output: {
        directory: 'docs/api/generated',
        formats: ['html', 'pdf', 'json'],
        versioning: true
      },
      generators: {
        swagger: true,
        redoc: true,
        pdf: true,
        postman: true
      },
      codeExamples: {
        languages: ['javascript', 'python', 'go', 'curl', 'php'],
        includeAuth: true,
        includeErrorHandling: true
      }
    };

    if (configPath && require('fs').existsSync(configPath)) {
      const customConfig = JSON.parse(require('fs').readFileSync(configPath, 'utf8'));
      return { ...defaultConfig, ...customConfig };
    }

    return defaultConfig;
  }

  async generate(): Promise<void> {
    try {
      // Ensure output directory exists
      await this.ensureDirectories();

      // Validate all OpenAPI specifications
      await this.validateSpecifications();

      // Generate documentation for each specification
      for (const spec of this.config.specs) {
        console.log(`\n🔄 Processing ${spec.name}...`);
        await this.processSpecification(spec);
      }

      // Generate combined documentation
      await this.generateCombinedDocs();

      // Create version information
      await this.createVersionInfo();

      // Generate additional assets
      await this.generateAdditionalAssets();

      console.log(`\n✅ Documentation generation completed successfully!`);
      console.log(`📁 Output location: ${this.outputDir}`);

    } catch (error) {
      console.error('❌ Documentation generation failed:', error);
      process.exit(1);
    }
  }

  private async ensureDirectories(): Promise<void> {
    const dirs = [
      this.outputDir,
      path.join(this.outputDir, 'swagger'),
      path.join(this.outputDir, 'redoc'),
      path.join(this.outputDir, 'pdf'),
      path.join(this.outputDir, 'postman'),
      path.join(this.outputDir, 'code-examples'),
      path.join(this.outputDir, 'guides'),
      path.join(this.outputDir, 'assets')
    ];

    for (const dir of dirs) {
      await fs.mkdir(dir, { recursive: true });
    }
  }

  private async validateSpecifications(): Promise<void> {
    console.log('🔍 Validating OpenAPI specifications...');
    
    for (const spec of this.config.specs) {
      const specPath = path.resolve(spec.file);
      
      if (!(await fs.stat(specPath).catch(() => false))) {
        throw new Error(`Specification file not found: ${specPath}`);
      }

      const isValid = await validateOpenAPISpec(specPath);
      if (!isValid) {
        throw new Error(`Invalid OpenAPI specification: ${spec.name}`);
      }
      
      console.log(`  ✅ ${spec.name} - Valid`);
    }
  }

  private async processSpecification(spec: any): Promise<void> {
    const specPath = path.resolve(spec.file);
    const specContent = JSON.parse(await fs.readFile(specPath, 'utf8'));

    // Generate Swagger UI documentation
    if (this.config.generators.swagger) {
      await this.generateSwaggerUI(spec, specContent);
    }

    // Generate ReDoc documentation
    if (this.config.generators.redoc) {
      await this.generateRedoc(spec, specContent);
    }

    // Generate PDF documentation
    if (this.config.generators.pdf) {
      await this.generatePDF(spec, specContent);
    }

    // Generate Postman collection
    if (this.config.generators.postman) {
      await this.generatePostmanCollection(spec, specContent);
    }

    // Generate code examples
    await this.generateCodeExamples(spec, specContent);
  }

  private async generateSwaggerUI(spec: any, specContent: any): Promise<void> {
    const swaggerDir = path.join(this.outputDir, 'swagger', spec.category);
    await fs.mkdir(swaggerDir, { recursive: true });

    // Create custom Swagger UI with iSECTECH branding
    const swaggerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${spec.name} - iSECTECH API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui.css" />
    <link rel="icon" type="image/png" href="../../assets/favicon.png" sizes="32x32" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
        
        /* Custom iSECTECH branding */
        .topbar { background-color: #1a1a2e; border-bottom: 2px solid #16213e; }
        .topbar .topbar-wrapper .link { color: #ffffff; }
        .swagger-ui .info .title { color: #1a1a2e; }
        .swagger-ui .scheme-container { background: #1a1a2e; }
        .swagger-ui .btn.authorize { background-color: #0f4c75; border-color: #0f4c75; }
        .swagger-ui .btn.authorize:hover { background-color: #16213e; }
        
        /* Security badges */
        .security-badge { 
            display: inline-block; 
            background: #e74c3c; 
            color: white; 
            padding: 2px 8px; 
            border-radius: 3px; 
            font-size: 0.8em;
            margin-left: 8px;
        }
        
        /* Custom header */
        .custom-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .custom-header h1 { margin: 0; font-size: 2em; }
        .custom-header p { margin: 10px 0 0 0; opacity: 0.9; }
        
        /* Rate limiting information */
        .rate-limit-info {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            margin: 20px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="custom-header">
        <h1>${spec.name}</h1>
        <p>${spec.description}</p>
        <p><strong>Version:</strong> ${spec.version} | <strong>Category:</strong> ${spec.category.toUpperCase()}</p>
    </div>
    
    <div class="rate-limit-info">
        <strong>⚠️ Rate Limiting:</strong> This API implements intelligent rate limiting. 
        Please review the rate limit headers in responses and implement proper backoff strategies.
        <a href="../../guides/rate-limiting.html">Learn more about rate limits →</a>
    </div>
    
    <div id="swagger-ui"></div>
    
    <script src="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui-bundle.js" charset="UTF-8"> </script>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.5/swagger-ui-standalone-preset.js" charset="UTF-8"> </script>
    <script>
        window.onload = function() {
            // Configure Swagger UI with security-focused settings
            const ui = SwaggerUIBundle({
                url: '${spec.name.toLowerCase().replace(/\\s+/g, '-')}.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                requestInterceptor: function(request) {
                    // Add security headers for all requests
                    request.headers['X-API-Source'] = 'swagger-ui';
                    request.headers['X-Documentation-Version'] = '${spec.version}';
                    return request;
                },
                responseInterceptor: function(response) {
                    // Log security-relevant response headers
                    console.log('Security Headers:', {
                        'X-Rate-Limit': response.headers['x-rate-limit-remaining'],
                        'X-Request-ID': response.headers['x-request-id']
                    });
                    return response;
                },
                // Custom request/response handling for security APIs
                requestSnippetsEnabled: true,
                requestSnippets: {
                    generators: {
                        curl_bash: {
                            title: "cURL (bash)",
                            syntax: "bash"
                        },
                        curl_powershell: {
                            title: "cURL (PowerShell)", 
                            syntax: "powershell"
                        }
                    }
                }
            });

            // Add custom functionality for security API testing
            window.ui = ui;
        };
    </script>
</body>
</html>`;

    await fs.writeFile(path.join(swaggerDir, 'index.html'), swaggerHTML);
    await fs.writeFile(
      path.join(swaggerDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}.json`), 
      JSON.stringify(specContent, null, 2)
    );
  }

  private async generateRedoc(spec: any, specContent: any): Promise<void> {
    const redocDir = path.join(this.outputDir, 'redoc', spec.category);
    await fs.mkdir(redocDir, { recursive: true });

    // Create ReDoc HTML with custom theme
    const redocHTML = `<!DOCTYPE html>
<html>
<head>
    <title>${spec.name} - API Reference</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body { margin: 0; padding: 0; }
        
        /* Custom iSECTECH theme */
        redoc {
            --redoc-brand-color: #1a1a2e;
            --redoc-brand-color-dark: #16213e;
            --redoc-brand-color-light: #0f4c75;
            --redoc-font-family: 'Roboto', sans-serif;
            --redoc-headings-font-family: 'Montserrat', sans-serif;
        }
        
        /* Security-focused styling */
        .security-scheme {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 12px;
            margin: 16px 0;
        }
        
        .security-requirement {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .endpoint-security-info {
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 16px;
        }
        
        /* Rate limiting badges */
        .rate-limit-badge {
            background: #17a2b8;
            color: white;
            padding: 2px 6px;
            border-radius: 12px;
            font-size: 0.75em;
            margin-left: 8px;
        }
    </style>
</head>
<body>
    <div id="redoc-container"></div>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"> </script>
    <script>
        // Initialize ReDoc with security-focused configuration
        Redoc.init('${spec.name.toLowerCase().replace(/\\s+/g, '-')}.json', {
            scrollYOffset: 50,
            hideDownloadButton: false,
            hideLoading: false,
            expandResponses: "200,201",
            expandSingleSchemaField: true,
            showExtensions: true,
            sortPropsAlphabetically: true,
            menuToggle: true,
            theme: {
                colors: {
                    primary: {
                        main: '#1a1a2e'
                    },
                    success: {
                        main: '#28a745'
                    },
                    warning: {
                        main: '#ffc107'
                    },
                    error: {
                        main: '#dc3545'
                    }
                },
                typography: {
                    fontSize: '14px',
                    lineHeight: '1.5em',
                    code: {
                        backgroundColor: '#f8f9fa',
                        color: '#e83e8c'
                    }
                },
                sidebar: {
                    backgroundColor: '#f8f9fa',
                    width: '260px'
                },
                rightPanel: {
                    backgroundColor: '#1a1a2e',
                    width: '40%'
                }
            },
            // Custom options for security APIs
            pathInMiddlePanel: true,
            requiredPropsFirst: true,
            sortTagsAlphabetically: true,
            expandDefaultServerVariables: true,
            maxDisplayedEnumValues: 3,
            showObjectSchemaExamples: true
        }, document.getElementById('redoc-container'));
        
        // Add custom post-processing for security documentation
        setTimeout(() => {
            // Add security badges to endpoints
            document.querySelectorAll('[data-section-id*="operation/"]').forEach(el => {
                const securityInfo = el.querySelector('.security-requirement');
                if (securityInfo) {
                    const badge = document.createElement('span');
                    badge.className = 'security-requirement';
                    badge.textContent = '🔒 Authentication Required';
                    el.insertBefore(badge, el.firstChild);
                }
            });
        }, 1000);
    </script>
</body>
</html>`;

    await fs.writeFile(path.join(redocDir, 'index.html'), redocHTML);
    await fs.writeFile(
      path.join(redocDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}.json`),
      JSON.stringify(specContent, null, 2)
    );
  }

  private async generatePDF(spec: any, specContent: any): Promise<void> {
    const pdfDir = path.join(this.outputDir, 'pdf');
    
    try {
      // Use wkhtmltopdf or similar to generate PDF from HTML
      console.log(`  📄 Generating PDF for ${spec.name}...`);
      
      // Create a simplified HTML version for PDF generation
      const htmlContent = await this.createPDFTemplate(spec, specContent);
      const htmlFile = path.join(pdfDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}.html`);
      const pdfFile = path.join(pdfDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}.pdf`);
      
      await fs.writeFile(htmlFile, htmlContent);
      
      // Note: This requires wkhtmltopdf to be installed
      // For now, we'll create a placeholder and log the requirement
      console.log(`  ℹ️  PDF generation requires wkhtmltopdf. HTML template created: ${htmlFile}`);
      
    } catch (error) {
      console.warn(`  ⚠️  PDF generation failed for ${spec.name}:`, error.message);
    }
  }

  private async generatePostmanCollection(spec: any, specContent: any): Promise<void> {
    const postmanDir = path.join(this.outputDir, 'postman');
    
    try {
      console.log(`  📮 Generating Postman collection for ${spec.name}...`);
      
      // Convert OpenAPI to Postman collection format
      const collection = await this.convertToPostmanCollection(spec, specContent);
      const collectionFile = path.join(postmanDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}.postman_collection.json`);
      
      await fs.writeFile(collectionFile, JSON.stringify(collection, null, 2));
      
    } catch (error) {
      console.warn(`  ⚠️  Postman collection generation failed for ${spec.name}:`, error.message);
    }
  }

  private async generateCodeExamples(spec: any, specContent: any): Promise<void> {
    const examplesDir = path.join(this.outputDir, 'code-examples', spec.category);
    await fs.mkdir(examplesDir, { recursive: true });
    
    console.log(`  💻 Generating code examples for ${spec.name}...`);
    
    const examples = await generateCodeExamples(
      specContent,
      this.config.codeExamples.languages,
      this.config.codeExamples.includeAuth,
      this.config.codeExamples.includeErrorHandling
    );
    
    for (const [language, code] of Object.entries(examples)) {
      const langDir = path.join(examplesDir, language);
      await fs.mkdir(langDir, { recursive: true });
      
      await fs.writeFile(
        path.join(langDir, `${spec.name.toLowerCase().replace(/\\s+/g, '-')}-examples.${this.getFileExtension(language)}`),
        code as string
      );
    }
  }

  private async generateCombinedDocs(): Promise<void> {
    console.log('🔄 Generating combined documentation...');
    
    // Create unified index page
    const indexHTML = await this.createIndexPage();
    await fs.writeFile(path.join(this.outputDir, 'index.html'), indexHTML);
    
    // Create navigation structure
    const navigation = await this.createNavigationStructure();
    await fs.writeFile(path.join(this.outputDir, 'navigation.json'), JSON.stringify(navigation, null, 2));
  }

  private async createVersionInfo(): Promise<void> {
    const versionInfo = {
      generatedAt: new Date().toISOString(),
      generator: 'iSECTECH API Documentation Generator',
      version: '1.0.0',
      specifications: this.config.specs.map(spec => ({
        name: spec.name,
        version: spec.version,
        category: spec.category,
        lastModified: new Date().toISOString()
      })),
      formats: this.config.output.formats,
      codeExamples: this.config.codeExamples.languages
    };
    
    await fs.writeFile(
      path.join(this.outputDir, 'version-info.json'), 
      JSON.stringify(versionInfo, null, 2)
    );
  }

  private async generateAdditionalAssets(): Promise<void> {
    console.log('🎨 Generating additional assets...');
    
    // Copy favicon and logos
    const assetsDir = path.join(this.outputDir, 'assets');
    
    // Create CSS for consistent branding
    const brandingCSS = `
/* iSECTECH API Documentation Branding */
:root {
  --isectech-primary: #1a1a2e;
  --isectech-secondary: #16213e;
  --isectech-accent: #0f4c75;
  --isectech-success: #28a745;
  --isectech-warning: #ffc107;
  --isectech-danger: #dc3545;
  --isectech-info: #17a2b8;
}

.isectech-header {
  background: linear-gradient(135deg, var(--isectech-primary) 0%, var(--isectech-secondary) 100%);
  color: white;
  padding: 2rem;
  text-align: center;
  margin-bottom: 2rem;
}

.security-badge {
  background: var(--isectech-danger);
  color: white;
  padding: 0.25rem 0.5rem;
  border-radius: 0.25rem;
  font-size: 0.8em;
  margin-left: 0.5rem;
}

.rate-limit-info {
  background: #fff3cd;
  border: 1px solid #ffeaa7;
  padding: 1rem;
  margin: 1rem 0;
  border-radius: 0.25rem;
}
`;
    
    await fs.writeFile(path.join(assetsDir, 'branding.css'), brandingCSS);
    
    // Generate authentication guides
    await this.generateAuthenticationGuides();
    
    // Generate getting started guide
    await this.generateGettingStartedGuide();
  }

  // Helper methods
  private async createPDFTemplate(spec: any, specContent: any): Promise<string> {
    // Simplified HTML template for PDF generation
    return `<!DOCTYPE html>
<html>
<head>
    <title>${spec.name} - API Documentation</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; }
        h1, h2, h3 { color: #1a1a2e; }
        .endpoint { margin: 2rem 0; border: 1px solid #ddd; padding: 1rem; }
        .method { font-weight: bold; text-transform: uppercase; }
        .security { background: #fff3cd; padding: 0.5rem; border-radius: 0.25rem; }
        code { background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }
    </style>
</head>
<body>
    <h1>${spec.name}</h1>
    <p><strong>Version:</strong> ${spec.version}</p>
    <p><strong>Description:</strong> ${spec.description}</p>
    
    <!-- Content would be generated from OpenAPI spec -->
    <p><em>Full PDF content would be generated here from the OpenAPI specification.</em></p>
</body>
</html>`;
  }

  private async convertToPostmanCollection(spec: any, specContent: any): Promise<any> {
    // Convert OpenAPI spec to Postman collection format
    return {
      info: {
        name: spec.name,
        description: spec.description,
        version: spec.version,
        schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
      },
      auth: {
        type: "bearer",
        bearer: [
          {
            key: "token",
            value: "{{auth_token}}",
            type: "string"
          }
        ]
      },
      variable: [
        {
          key: "baseUrl",
          value: "https://api.isectech.com/v1",
          type: "string"
        },
        {
          key: "auth_token",
          value: "",
          type: "string"
        }
      ],
      item: [
        {
          name: "Authentication",
          description: "Authentication endpoints",
          item: []
        }
        // Additional items would be generated from OpenAPI paths
      ]
    };
  }

  private async createIndexPage(): Promise<string> {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH API Documentation</title>
    <link rel="stylesheet" href="assets/branding.css">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .docs-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem; margin: 2rem 0; }
        .docs-card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .docs-card h3 { color: var(--isectech-primary); margin-top: 0; }
        .format-links { display: flex; gap: 1rem; margin-top: 1rem; }
        .format-links a { padding: 0.5rem 1rem; background: var(--isectech-accent); color: white; text-decoration: none; border-radius: 4px; }
        .format-links a:hover { background: var(--isectech-secondary); }
        .quickstart { background: var(--isectech-primary); color: white; padding: 2rem; border-radius: 8px; margin: 2rem 0; }
    </style>
</head>
<body>
    <div class="isectech-header">
        <h1>iSECTECH API Documentation</h1>
        <p>Comprehensive documentation for the iSECTECH Security Platform APIs</p>
        <p><em>Generated on ${new Date().toISOString()}</em></p>
    </div>

    <div class="container">
        <div class="quickstart">
            <h2>🚀 Quick Start</h2>
            <p>New to our APIs? Start here:</p>
            <ul>
                <li><a href="guides/getting-started.html" style="color: #ffc107;">Getting Started Guide</a></li>
                <li><a href="guides/authentication.html" style="color: #ffc107;">Authentication Guide</a></li>
                <li><a href="guides/rate-limiting.html" style="color: #ffc107;">Rate Limiting Guide</a></li>
                <li><a href="code-examples/" style="color: #ffc107;">Code Examples</a></li>
            </ul>
        </div>

        <div class="docs-grid">
            ${this.config.specs.map(spec => `
            <div class="docs-card">
                <h3>${spec.name}</h3>
                <p>${spec.description}</p>
                <p><strong>Version:</strong> ${spec.version} | <strong>Category:</strong> ${spec.category.toUpperCase()}</p>
                <div class="format-links">
                    <a href="swagger/${spec.category}/index.html">📱 Interactive (Swagger)</a>
                    <a href="redoc/${spec.category}/index.html">📖 Static (ReDoc)</a>
                    <a href="pdf/${spec.name.toLowerCase().replace(/\\s+/g, '-')}.pdf">📄 PDF</a>
                    <a href="postman/${spec.name.toLowerCase().replace(/\\s+/g, '-')}.postman_collection.json">📮 Postman</a>
                </div>
            </div>
            `).join('')}
        </div>

        <div style="text-align: center; margin: 3rem 0; padding: 2rem; border-top: 1px solid #dee2e6;">
            <h3>Need Help?</h3>
            <p>
                📧 <a href="mailto:api@isectech.com">Contact API Team</a> | 
                📚 <a href="https://docs.isectech.com">Full Documentation</a> | 
                🐛 <a href="https://github.com/isectech/api-issues">Report Issues</a>
            </p>
            <p><small>Documentation generated by iSECTECH API Documentation Generator v1.0.0</small></p>
        </div>
    </div>
</body>
</html>`;
  }

  private async createNavigationStructure(): Promise<any> {
    return {
      title: "iSECTECH API Documentation",
      version: "1.0.0",
      sections: [
        {
          title: "Getting Started",
          items: [
            { title: "Introduction", path: "guides/getting-started.html" },
            { title: "Authentication", path: "guides/authentication.html" },
            { title: "Rate Limiting", path: "guides/rate-limiting.html" },
            { title: "Error Handling", path: "guides/error-handling.html" }
          ]
        },
        {
          title: "API References",
          items: this.config.specs.map(spec => ({
            title: spec.name,
            category: spec.category,
            formats: {
              interactive: `swagger/${spec.category}/index.html`,
              static: `redoc/${spec.category}/index.html`,
              pdf: `pdf/${spec.name.toLowerCase().replace(/\\s+/g, '-')}.pdf`,
              postman: `postman/${spec.name.toLowerCase().replace(/\\s+/g, '-')}.postman_collection.json`
            }
          }))
        },
        {
          title: "Code Examples",
          items: this.config.codeExamples.languages.map(lang => ({
            title: lang.charAt(0).toUpperCase() + lang.slice(1),
            path: `code-examples/${lang}/`
          }))
        }
      ]
    };
  }

  private async generateAuthenticationGuides(): Promise<void> {
    const guidesDir = path.join(this.outputDir, 'guides');
    
    const authGuide = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Guide - iSECTECH API</title>
    <link rel="stylesheet" href="../assets/branding.css">
    <style>
        body { font-family: 'Segoe UI', sans-serif; line-height: 1.6; margin: 0; background: #f8f9fa; }
        .container { max-width: 800px; margin: 0 auto; padding: 2rem; background: white; }
        code { background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }
        pre { background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 1rem; margin: 1rem 0; }
        .info { background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 1rem; margin: 1rem 0; }
    </style>
</head>
<body>
    <div class="isectech-header">
        <h1>Authentication Guide</h1>
        <p>Complete guide to authenticating with iSECTECH APIs</p>
    </div>

    <div class="container">
        <h2>Overview</h2>
        <p>The iSECTECH API uses JWT (JSON Web Tokens) for authentication. All API requests must include a valid JWT token in the Authorization header.</p>

        <div class="warning">
            <strong>⚠️ Security Notice:</strong> Never expose your API keys or tokens in client-side code, public repositories, or logs.
        </div>

        <h2>Authentication Methods</h2>
        
        <h3>1. Bearer Token Authentication</h3>
        <p>Include your JWT token in the Authorization header:</p>
        <pre><code>Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...</code></pre>

        <h3>2. API Key Authentication</h3>
        <p>For service-to-service authentication, use API keys:</p>
        <pre><code>X-API-Key: your-api-key-here</code></pre>

        <h2>Getting Your Token</h2>
        
        <h3>Step 1: Obtain Credentials</h3>
        <p>Contact your system administrator or visit the developer portal to get your credentials.</p>

        <h3>Step 2: Authenticate</h3>
        <p>Make a POST request to the authentication endpoint:</p>
        <pre><code>POST /auth/login
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password",
  "mfaCode": "123456"
}</code></pre>

        <h3>Step 3: Extract Token</h3>
        <p>The response will contain your JWT token:</p>
        <pre><code>{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 3600,
    "refreshToken": "refresh-token-here"
  }
}</code></pre>

        <h2>Token Refresh</h2>
        <p>Tokens expire after 1 hour. Use the refresh token to get a new access token:</p>
        <pre><code>POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}</code></pre>

        <h2>Multi-Factor Authentication (MFA)</h2>
        <p>MFA is required for all API access. Support methods include:</p>
        <ul>
            <li>TOTP (Time-based One-Time Password)</li>
            <li>SMS codes</li>
            <li>Hardware security keys</li>
        </ul>

        <div class="info">
            <strong>ℹ️ Best Practices:</strong>
            <ul>
                <li>Store tokens securely (e.g., encrypted storage, environment variables)</li>
                <li>Implement automatic token refresh</li>
                <li>Handle authentication errors gracefully</li>
                <li>Use HTTPS for all API requests</li>
                <li>Implement proper logout to invalidate tokens</li>
            </ul>
        </div>

        <h2>Code Examples</h2>
        
        <h3>JavaScript (Axios)</h3>
        <pre><code>const axios = require('axios');

const api = axios.create({
  baseURL: 'https://api.isectech.com/v1',
  headers: {
    'Authorization': \`Bearer \${token}\`,
    'Content-Type': 'application/json'
  }
});

// Automatic token refresh interceptor
api.interceptors.response.use(
  response => response,
  async error => {
    if (error.response.status === 401) {
      const newToken = await refreshToken();
      error.config.headers['Authorization'] = \`Bearer \${newToken}\`;
      return api.request(error.config);
    }
    return Promise.reject(error);
  }
);</code></pre>

        <h3>Python (requests)</h3>
        <pre><code>import requests
from datetime import datetime, timedelta

class ISECTECHClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = None
        self.token_expires = None
        self.refresh_token = None
        self.authenticate(username, password)
    
    def authenticate(self, username, password):
        response = requests.post(f"{self.base_url}/auth/login", json={
            "username": username,
            "password": password
        })
        
        if response.status_code == 200:
            data = response.json()['data']
            self.token = data['token']
            self.refresh_token = data['refreshToken']
            self.token_expires = datetime.now() + timedelta(seconds=data['expiresIn'])
    
    def get_headers(self):
        if self.token_expires and datetime.now() >= self.token_expires:
            self.refresh_access_token()
        
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }</code></pre>

        <h2>Error Handling</h2>
        <p>Handle authentication errors properly:</p>
        
        <ul>
            <li><strong>401 Unauthorized:</strong> Token is invalid or expired</li>
            <li><strong>403 Forbidden:</strong> Token is valid but lacks required permissions</li>
            <li><strong>429 Too Many Requests:</strong> Rate limit exceeded</li>
        </ul>

        <h2>Security Considerations</h2>
        
        <div class="warning">
            <strong>🔒 Security Checklist:</strong>
            <ul>
                <li>✅ Always use HTTPS in production</li>
                <li>✅ Store tokens securely (never in plain text)</li>
                <li>✅ Implement token rotation</li>
                <li>✅ Use strong passwords and enable MFA</li>
                <li>✅ Monitor for suspicious authentication patterns</li>
                <li>✅ Implement proper session timeout</li>
                <li>✅ Log authentication events</li>
            </ul>
        </div>

        <h2>Support</h2>
        <p>Need help with authentication? Contact us:</p>
        <ul>
            <li>📧 Email: <a href="mailto:support@isectech.com">support@isectech.com</a></li>
            <li>📚 Documentation: <a href="https://docs.isectech.com">https://docs.isectech.com</a></li>
            <li>🎫 Support Portal: <a href="https://support.isectech.com">https://support.isectech.com</a></li>
        </ul>
    </div>
</body>
</html>`;

    await fs.writeFile(path.join(guidesDir, 'authentication.html'), authGuide);
  }

  private async generateGettingStartedGuide(): Promise<void> {
    const guidesDir = path.join(this.outputDir, 'guides');
    
    const gettingStartedGuide = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Getting Started - iSECTECH API</title>
    <link rel="stylesheet" href="../assets/branding.css">
    <style>
        body { font-family: 'Segoe UI', sans-serif; line-height: 1.6; margin: 0; background: #f8f9fa; }
        .container { max-width: 800px; margin: 0 auto; padding: 2rem; background: white; }
        code { background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }
        pre { background: #f8f9fa; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
        .step { background: white; border-left: 4px solid var(--isectech-accent); padding: 1.5rem; margin: 1.5rem 0; border-radius: 0.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .step h3 { margin-top: 0; color: var(--isectech-primary); }
    </style>
</head>
<body>
    <div class="isectech-header">
        <h1>Getting Started with iSECTECH API</h1>
        <p>Your complete guide to integrating with our security platform</p>
    </div>

    <div class="container">
        <h2>Welcome to iSECTECH API</h2>
        <p>The iSECTECH API provides comprehensive access to our enterprise security platform, including threat detection, compliance monitoring, asset management, and more.</p>

        <div class="step">
            <h3>Step 1: Get API Access</h3>
            <p>To start using the API, you'll need:</p>
            <ul>
                <li>A valid iSECTECH account with API access permissions</li>
                <li>API credentials (provided by your administrator)</li>
                <li>MFA setup (required for security)</li>
            </ul>
            <p><a href="mailto:api@isectech.com">Request API access →</a></p>
        </div>

        <div class="step">
            <h3>Step 2: Authentication</h3>
            <p>All API requests require authentication using JWT tokens:</p>
            <pre><code>curl -X POST https://api.isectech.com/v1/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{
    "username": "your-username",
    "password": "your-password",
    "mfaCode": "123456"
  }'</code></pre>
            <p><a href="authentication.html">Complete authentication guide →</a></p>
        </div>

        <div class="step">
            <h3>Step 3: Make Your First Request</h3>
            <p>Try fetching your notifications:</p>
            <pre><code>curl -X GET https://api.isectech.com/v1/notifications \\
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
  -H "Content-Type: application/json"</code></pre>
        </div>

        <div class="step">
            <h3>Step 4: Explore the API</h3>
            <p>Browse our comprehensive API documentation:</p>
            <ul>
                <li><a href="../swagger/frontend/index.html">Frontend API (Interactive)</a></li>
                <li><a href="../swagger/backend/index.html">Backend Services API</a></li>
                <li><a href="../code-examples/">Code Examples</a></li>
            </ul>
        </div>

        <h2>Key Concepts</h2>
        
        <h3>Multi-Tenant Architecture</h3>
        <p>Our API supports multi-tenant operations. Each request is automatically scoped to your tenant context based on your authentication.</p>

        <h3>Rate Limiting</h3>
        <p>APIs are rate-limited to ensure fair usage:</p>
        <ul>
            <li><strong>Standard endpoints:</strong> 1000 requests/minute</li>
            <li><strong>Trust scoring:</strong> 5000 requests/minute</li>
            <li><strong>Bulk operations:</strong> 100 requests/minute</li>
        </ul>
        <p>Rate limit headers are included in all responses:</p>
        <pre><code>X-Rate-Limit-Remaining: 995
X-Rate-Limit-Reset: 1640995200
Retry-After: 60</code></pre>

        <h3>Error Handling</h3>
        <p>All errors follow a consistent format:</p>
        <pre><code>{
  "error": "Validation failed",
  "details": [
    {
      "path": ["userId"],
      "message": "User ID is required"
    }
  ],
  "requestId": "req_123456789"
}</code></pre>

        <h2>Common Use Cases</h2>
        
        <h3>Security Monitoring</h3>
        <pre><code>// Get security alerts
GET /notifications?type=security&priority=high

// Calculate trust scores
POST /trust-score
{
  "userId": "user_123",
  "context": {
    "location": { "country": "US" },
    "device": { "fingerprint": "device_abc" }
  }
}</code></pre>

        <h3>Compliance Reporting</h3>
        <pre><code>// Generate compliance report
POST /trust-score/analytics
{
  "reportType": "compliance",
  "timeframe": "30d",
  "format": "pdf"
}</code></pre>

        <h3>Asset Management</h3>
        <pre><code>// Discover network assets
GET /assets/discovery?scan_type=network

// Get asset inventory
GET /assets/inventory?classification=critical</code></pre>

        <h2>Best Practices</h2>
        
        <ul>
            <li><strong>Use pagination:</strong> Always handle paginated responses properly</li>
            <li><strong>Implement retry logic:</strong> Handle rate limits and temporary errors gracefully</li>
            <li><strong>Cache responses:</strong> Use ETags and cache headers when appropriate</li>
            <li><strong>Monitor usage:</strong> Track your API usage and set up alerts</li>
            <li><strong>Validate input:</strong> Always validate data before sending to the API</li>
            <li><strong>Handle errors:</strong> Implement proper error handling and logging</li>
        </ul>

        <h2>SDKs and Tools</h2>
        
        <h3>Official SDKs</h3>
        <ul>
            <li>JavaScript/TypeScript SDK (coming soon)</li>
            <li>Python SDK (coming soon)</li>
            <li>Go SDK (coming soon)</li>
        </ul>

        <h3>Development Tools</h3>
        <ul>
            <li><a href="../postman/">Postman Collections</a> - Pre-configured API requests</li>
            <li><a href="../swagger/frontend/index.html">API Explorer</a> - Interactive testing</li>
            <li>OpenAPI Specs - For code generation</li>
        </ul>

        <h2>Support and Resources</h2>
        
        <ul>
            <li>📧 <strong>Email Support:</strong> <a href="mailto:api@isectech.com">api@isectech.com</a></li>
            <li>📚 <strong>Documentation:</strong> <a href="https://docs.isectech.com">docs.isectech.com</a></li>
            <li>💬 <strong>Community Forum:</strong> <a href="https://community.isectech.com">community.isectech.com</a></li>
            <li>🐛 <strong>Bug Reports:</strong> <a href="https://github.com/isectech/api-issues">GitHub Issues</a></li>
            <li>📈 <strong>Status Page:</strong> <a href="https://status.isectech.com">status.isectech.com</a></li>
        </ul>

        <h2>What's Next?</h2>
        
        <p>Now that you understand the basics:</p>
        <ol>
            <li>Set up authentication in your application</li>
            <li>Explore the specific APIs you need</li>
            <li>Implement error handling and rate limiting</li>
            <li>Test in our staging environment</li>
            <li>Deploy to production</li>
        </ol>

        <p>Ready to dive deeper? Check out our <a href="../swagger/frontend/index.html">interactive API documentation</a> or browse <a href="../code-examples/">code examples</a> for your preferred programming language.</p>
    </div>
</body>
</html>`;

    await fs.writeFile(path.join(guidesDir, 'getting-started.html'), gettingStartedGuide);
  }

  private getFileExtension(language: string): string {
    const extensions: Record<string, string> = {
      javascript: 'js',
      python: 'py',
      go: 'go',
      curl: 'sh',
      php: 'php',
      java: 'java',
      csharp: 'cs'
    };
    return extensions[language] || 'txt';
  }
}

// Main execution
async function main() {
  const configPath = process.argv[2];
  const generator = new DocumentationGenerator(configPath);
  await generator.generate();
}

// Export for use as module
export { DocumentationGenerator };

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}