# iSECTECH API Documentation System

A comprehensive, automated API documentation generation system for the iSECTECH Security Platform. This system automatically generates interactive and static documentation from OpenAPI 3.1 specifications, ensuring documentation stays synchronized with API changes.

## Features

### 🚀 Multi-Format Documentation Generation
- **Interactive Documentation** - Swagger UI with custom iSECTECH branding
- **Static Documentation** - ReDoc with responsive design and search
- **PDF Documentation** - Printer-friendly versions for offline use
- **Postman Collections** - Ready-to-import API collections for testing

### 💻 Multi-Language Code Examples
Automatically generated code examples in:
- JavaScript/TypeScript (with error handling and rate limiting)
- Python (with comprehensive client class)
- Go (with proper error handling and structs)
- cURL (with authentication and retry logic)
- PHP (with session management)

### 🔧 Advanced Features
- **Automatic Versioning** - Maintains documentation for all API versions
- **CI/CD Integration** - GitHub Actions workflow for automated deployment
- **Comprehensive Validation** - Uses Redocly, Spectral, and custom validators
- **Security Focus** - Specialized templates and guides for security APIs
- **Performance Testing** - Lighthouse integration for documentation performance
- **Multi-format Export** - HTML, PDF, and JSON outputs

## Quick Start

### Prerequisites
- Node.js 18+ and npm
- TypeScript support (`ts-node`)
- OpenAPI 3.1 specifications in place

### Installation
```bash
# Install dependencies
npm install

# Install documentation tools
npm install -g @redocly/cli@latest
npm install -g @stoplight/spectral-cli@latest
```

### Generate Documentation
```bash
# Validate OpenAPI specifications
npm run docs:validate

# Generate all documentation formats
npm run docs:generate

# Serve documentation locally
npm run docs:serve

# Clean previous builds
npm run docs:clean
```

### Watch Mode for Development
```bash
# Auto-regenerate on OpenAPI spec changes
npm run docs:watch
```

## Directory Structure

```
docs/api/
├── README.md                    # This file
├── generated/                   # Auto-generated documentation (gitignored)
│   ├── index.html              # Main documentation portal
│   ├── swagger/                # Interactive Swagger UI docs
│   │   ├── frontend/           # Frontend API documentation
│   │   ├── backend/            # Backend services documentation
│   │   └── extended/           # Extended APIs documentation
│   ├── redoc/                  # Static ReDoc documentation
│   ├── pdf/                    # PDF versions
│   ├── postman/                # Postman collections
│   ├── code-examples/          # Multi-language code examples
│   └── guides/                 # Auto-generated from templates
├── scripts/                    # Generation and deployment scripts
│   ├── generate-docs.ts        # Main documentation generator
│   ├── ci-cd-integration.ts    # CI/CD pipeline integration
│   └── utils/
│       └── doc-utils.ts        # Utility functions
├── templates/                  # Documentation templates
├── guides/                     # Static guide files
│   ├── getting-started.html    # Getting started guide
│   ├── authentication.html     # Authentication guide
│   ├── rate-limiting.html      # Rate limiting guide
│   └── error-handling.html     # Error handling guide
└── assets/                     # Static assets and branding
    └── branding.css            # iSECTECH branding styles
```

## Configuration

### Package.json Scripts
The following npm scripts are available:

```json
{
  "docs:validate": "Validate OpenAPI specifications",
  "docs:generate": "Generate all documentation formats",
  "docs:serve": "Serve documentation locally on port 8080",
  "docs:deploy": "Deploy documentation (CI/CD)",
  "docs:ci": "Full CI/CD pipeline (validate + generate + deploy)",
  "docs:clean": "Clean generated documentation",
  "docs:watch": "Watch OpenAPI specs and auto-regenerate"
}
```

### Validation Configuration
Documentation validation uses multiple tools configured in:
- `.redocly.yaml` - Redocly linting rules and theme configuration
- `.spectral.yaml` - Spectral linting rules for OpenAPI validation
- `openapi-validation-config.yaml` - Custom validation rules and coverage requirements

### CI/CD Configuration
GitHub Actions workflow (`.github/workflows/api-documentation.yml`) provides:
- Automated validation on pull requests
- Documentation generation on main branch pushes
- Security scanning for sensitive information
- Performance testing with Lighthouse
- Deployment to GitHub Pages
- Slack notifications

## OpenAPI Specifications

The system processes these OpenAPI 3.1 specifications:

1. **Frontend API** (`app/api/openapi-complete.json`)
   - Complete frontend API endpoints
   - Authentication, notifications, trust scoring
   - Version 2.0.0

2. **Backend Services** (`backend/openapi-backend-services.json`)
   - Microservices API endpoints
   - Asset management, threat detection, vulnerability scanning
   - Version 1.0.0

3. **Extended APIs** (`app/api/openapi-extended-apis.json`)
   - Additional frontend functionality
   - WebSocket endpoints, advanced features
   - Version 1.0.0

## Customization

### Branding and Styling
The documentation uses custom iSECTECH branding defined in:
- `docs/api/assets/branding.css` - CSS variables and styles
- Swagger UI customization in generator scripts
- ReDoc theme configuration in `.redocly.yaml`

### Adding New Languages for Code Examples
To add support for additional programming languages:

1. Update `docs/api/scripts/utils/doc-utils.ts`
2. Add language-specific generation functions
3. Update the configuration to include the new language

### Custom Validation Rules
Add custom validation rules in:
- `.redocly.yaml` for Redocly-specific rules
- `.spectral.yaml` for Spectral-based validation
- `docs/api/scripts/utils/doc-utils.ts` for programmatic validation

## Security Considerations

The documentation system includes security-focused features:

- **Sensitive Information Scanning** - CI/CD pipeline scans for leaked credentials
- **Authentication Documentation** - Comprehensive security guides
- **Rate Limiting Information** - Built into all documentation
- **Security Headers** - Documented for all endpoints
- **Multi-Factor Authentication** - Complete implementation guides

## Performance

Documentation performance is optimized through:
- **Lazy Loading** - Large documentation loads efficiently
- **CDN Integration** - Static assets served from CDN
- **Compression** - Gzipped assets and responses
- **Lighthouse Testing** - Automated performance monitoring
- **Responsive Design** - Mobile-optimized documentation

## Deployment

### GitHub Pages (Automatic)
Documentation automatically deploys to GitHub Pages on main branch pushes.

### Manual Deployment
```bash
# Deploy to configured targets
npm run docs:deploy

# CI/CD pipeline with validation
npm run docs:ci
```

### Deployment Targets
Supports deployment to:
- GitHub Pages
- Google Cloud Storage
- AWS S3
- Netlify
- Vercel

## Monitoring and Maintenance

### Health Checks
The system includes monitoring for:
- Documentation generation success/failure
- Validation rule compliance
- Performance metrics
- User engagement analytics

### Maintenance Tasks
Regular maintenance includes:
- Updating validation rules for new OpenAPI features
- Refreshing code example templates
- Monitoring documentation performance
- Updating security guidelines

## Troubleshooting

### Common Issues

1. **Generation Fails**
   - Check OpenAPI spec validity
   - Verify all dependencies are installed
   - Review validation errors in CI/CD logs

2. **Missing Code Examples**
   - Ensure language is configured in generator
   - Check that OpenAPI specs have sufficient detail
   - Verify endpoint schemas are properly defined

3. **Styling Issues**
   - Check branding.css for conflicts
   - Verify CDN asset loading
   - Test with different browsers

4. **CI/CD Pipeline Failures**
   - Review GitHub Actions logs
   - Check validation tool configurations
   - Verify environment variables are set

### Getting Help
- 📧 **API Team:** api@isectech.com
- 📚 **Documentation:** https://docs.isectech.com
- 🎫 **Support Portal:** https://support.isectech.com
- 💬 **Community:** https://community.isectech.com

## Contributing

### Adding New Documentation Features
1. Fork the repository
2. Create a feature branch
3. Add/modify generation scripts in `docs/api/scripts/`
4. Test with `npm run docs:generate`
5. Submit a pull request

### Improving Validation Rules
1. Update `.redocly.yaml` or `.spectral.yaml`
2. Test validation with `npm run docs:validate`
3. Update documentation if needed
4. Submit pull request with test results

### Code Example Templates
1. Update language-specific functions in `doc-utils.ts`
2. Test generation with multiple API specs
3. Verify examples work correctly
4. Document any new language-specific requirements

## Architecture

The documentation system follows these principles:

- **Docs-as-Code** - All documentation versioned with source code
- **Automation First** - Minimize manual documentation maintenance
- **Developer Experience** - Clear, searchable, interactive documentation
- **Security Focus** - Specialized for cybersecurity API documentation
- **Multi-Format Support** - Various consumption preferences supported
- **Performance Optimized** - Fast loading and responsive design

## Version History

- **v1.0.0** - Initial implementation with Swagger UI and ReDoc
- **v1.1.0** - Added multi-language code examples
- **v1.2.0** - CI/CD integration and automated deployment
- **v1.3.0** - Performance optimization and monitoring
- **v1.4.0** - Enhanced security documentation and validation

---

This documentation system ensures that iSECTECH's APIs are thoroughly documented, always up-to-date, and provide an excellent developer experience for integration partners.