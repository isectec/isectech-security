# iSECTECH Enterprise Security Platform - Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the iSECTECH Enterprise Security Platform using the automated deployment script.

## Prerequisites

### Required Tools
- Google Cloud SDK (`gcloud`)
- Docker & Docker Compose
- Node.js (v18+) & npm
- Go (v1.21+)
- Python 3.9+
- Terraform (v1.5+)
- kubectl
- Git
- jq

### GCP Setup
1. Create a GCP project
2. Enable billing
3. Install and configure `gcloud` CLI
4. Authenticate: `gcloud auth login`
5. Set project: `gcloud config set project isectech-security-platform`

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/isectech/security-platform.git
cd security-platform
```

### 2. Configure Environment
```bash
# Copy example environment file
cp .env.production.example .env.production

# Edit with your values
nano .env.production
```

### 3. Run Deployment
```bash
# Standard deployment
./deploy-production.sh

# Canary deployment (10% traffic)
./deploy-production.sh canary production

# Blue-green deployment
./deploy-production.sh blue-green production

# Multi-region deployment
./deploy-production.sh multi-region production
```

## Deployment Modes

### Standard Deployment
Deploys all services directly to production:
```bash
./deploy-production.sh standard production
```

### Canary Deployment
Gradually rolls out changes to a percentage of users:
```bash
CANARY_PERCENTAGE=20 CANARY_DURATION=600 ./deploy-production.sh canary production
```

### Blue-Green Deployment
Maintains two production environments for zero-downtime deployments:
```bash
./deploy-production.sh blue-green production
```

### Multi-Region Deployment
Deploys to multiple regions for global availability:
```bash
./deploy-production.sh multi-region production
```

### Rollback
Reverts to the previous deployment:
```bash
./deploy-production.sh rollback production
```

## Configuration Options

### Environment Variables

```bash
# Core Configuration
export GCP_PROJECT_ID="isectech-security-platform"
export GCP_REGION="us-central1"
export ENVIRONMENT="production"

# Deployment Options
export SKIP_BUILD=false           # Skip building images
export SKIP_INFRASTRUCTURE=false  # Skip infrastructure setup
export RUN_TESTS=true             # Run tests before deployment
export RUN_SMOKE_TESTS=true       # Run smoke tests after deployment
export ROLLBACK_ON_ERROR=true     # Auto-rollback on failure

# Canary Configuration
export CANARY_PERCENTAGE=10       # Traffic percentage for canary
export CANARY_DURATION=300        # Duration in seconds

# Security
export RUN_SECURITY_CHECKS=true   # Run security validations
export BACKUP_DATABASE=true        # Backup database before deployment
export RESTORE_DATABASE=false      # Restore database on rollback

# Notifications
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
```

### Dry Run Mode
Test deployment without making changes:
```bash
DRY_RUN=true ./deploy-production.sh
```

## Step-by-Step Manual Deployment

If you prefer manual deployment or need to debug:

### 1. Setup Infrastructure
```bash
# Create VPC
./infrastructure/setup-vpc-networks.sh

# Setup Cloud KMS
./infrastructure/setup-cloud-kms.sh

# Configure secrets
./infrastructure/secrets/setup-secrets-manager.sh

# Setup load balancer
./infrastructure/setup-load-balancer.sh
```

### 2. Build Services
```bash
# Frontend
npm ci
npm run build
docker build -f Dockerfile.frontend.production -t frontend:latest .

# Backend
cd backend
go build ./...
docker build -f ../Dockerfile.backend -t backend:latest .

# AI Services
cd ../ai-services
docker build -f ../Dockerfile.ai -t ai-services:latest .
```

### 3. Push to Registry
```bash
# Configure Docker
gcloud auth configure-docker us-central1-docker.pkg.dev

# Tag and push
docker tag frontend:latest us-central1-docker.pkg.dev/isectech-security-platform/isectech-production/frontend:latest
docker push us-central1-docker.pkg.dev/isectech-security-platform/isectech-production/frontend:latest
```

### 4. Deploy to Cloud Run
```bash
gcloud run deploy isectech-frontend \
  --image=us-central1-docker.pkg.dev/isectech-security-platform/isectech-production/frontend:latest \
  --region=us-central1 \
  --platform=managed \
  --allow-unauthenticated
```

## Monitoring & Validation

### Health Checks
```bash
# Check frontend
curl https://protect.isectech.com/api/health

# Check backend
curl https://api.isectech.com/health

# Check all services
./scripts/health-check-all.sh
```

### View Logs
```bash
# Cloud Run logs
gcloud run logs read isectech-frontend --region=us-central1

# All logs
gcloud logging read "resource.type=cloud_run_revision" --limit=50
```

### Monitoring Dashboards
- [Cloud Console](https://console.cloud.google.com/monitoring)
- [Custom Dashboard](https://console.cloud.google.com/monitoring/dashboards/custom/isectech-production)
- [Uptime Checks](https://console.cloud.google.com/monitoring/uptime)

## Troubleshooting

### Common Issues

#### 1. Authentication Error
```bash
# Re-authenticate
gcloud auth login
gcloud auth application-default login
```

#### 2. Missing APIs
```bash
# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

#### 3. Build Failures
```bash
# Check Docker daemon
docker info

# Clean Docker cache
docker system prune -a

# Rebuild without cache
docker build --no-cache -f Dockerfile.frontend.production -t frontend:latest .
```

#### 4. Deployment Failures
```bash
# Check service status
gcloud run services describe isectech-frontend --region=us-central1

# View recent revisions
gcloud run revisions list --service=isectech-frontend --region=us-central1

# Check IAM permissions
gcloud projects get-iam-policy isectech-security-platform
```

### Manual Rollback
```bash
# List revisions
gcloud run revisions list --service=isectech-frontend --region=us-central1

# Route traffic to previous revision
gcloud run services update-traffic isectech-frontend \
  --to-revisions=isectech-frontend-00001-abc=100 \
  --region=us-central1
```

## Security Considerations

### Pre-deployment Checklist
- [ ] All secrets in Secret Manager
- [ ] No hardcoded credentials
- [ ] Security scans passed
- [ ] IAM permissions reviewed
- [ ] Network policies configured
- [ ] SSL certificates valid
- [ ] DDoS protection enabled
- [ ] Backup created

### Post-deployment Validation
- [ ] Health checks passing
- [ ] Security headers present
- [ ] Rate limiting active
- [ ] Monitoring alerts configured
- [ ] Audit logging enabled
- [ ] Penetration test scheduled

## Maintenance

### Regular Tasks
```bash
# Update dependencies
npm update
go get -u ./...

# Rotate secrets
./infrastructure/secrets/rotate-secrets.sh

# Clean old images
gcloud container images list-tags us-central1-docker.pkg.dev/isectech-security-platform/isectech-production/frontend \
  --filter='-tags:*' --format='get(digest)' | \
  xargs -I {} gcloud container images delete "us-central1-docker.pkg.dev/isectech-security-platform/isectech-production/frontend@{}" --quiet

# Database maintenance
gcloud sql instances patch isectech-postgres --maintenance-window-day=SAT --maintenance-window-hour=3
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Deploy to Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: google-github-actions/auth@v1
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - run: ./deploy-production.sh
```

### GitLab CI
```yaml
deploy:production:
  stage: deploy
  script:
    - ./deploy-production.sh
  only:
    - main
  environment:
    name: production
    url: https://protect.isectech.com
```

## Support

### Documentation
- [API Documentation](https://api.isectech.com/docs)
- [Architecture Guide](./docs/architecture.md)
- [Security Documentation](./docs/security.md)

### Contact
- **Support Email**: support@isectech.com
- **Security Issues**: security@isectech.com
- **Emergency Hotline**: +1-xxx-xxx-xxxx

### Logs Location
- **Deployment Logs**: `./logs/deployments/`
- **Application Logs**: Cloud Logging Console
- **Audit Logs**: `gs://isectech-audit-logs/`

## License

Copyright © 2024 iSECTECH. All rights reserved.