# iSECTECH Artifact Registry CI/CD Integration Guide

Comprehensive integration guide for iSECTECH security platform with Google Artifact Registry, including Cloud Build, GitHub Actions, and GitLab CI configurations.

## Overview

The iSECTECH Artifact Registry is configured with multiple repositories to support different environments and use cases:

- **Main Repository**: `isectech-docker` - Primary repository for all microservices
- **Environment Repositories**: Separate repositories for development, staging, and production
- **Security Tools Repository**: Dedicated repository for security scanning and monitoring tools

## Repository Structure

```
{region}-docker.pkg.dev/{project-id}/
├── isectech-docker/                 # Main repository
├── isectech-development/            # Development environment
├── isectech-staging/               # Staging environment  
├── isectech-production/            # Production environment
└── isectech-security-tools/        # Security tools
```

## Image Tagging Strategy

### Production-Grade Tagging Convention

```bash
# Format: {registry}/{repository}/{service}:{tag}
{region}-docker.pkg.dev/{project-id}/{repository}/{service}:{tag}

# Examples:
us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:v1.2.3
us-central1-docker.pkg.dev/isectech-prod/isectech-production/siem-engine:prod-v1.0.0
us-central1-docker.pkg.dev/isectech-prod/isectech-development/threat-detection:dev-feature-auth
```

### Tag Patterns by Environment

| Environment | Tag Pattern | Example |
|-------------|-------------|---------|
| Development | `dev-{feature/sha}` | `dev-latest`, `dev-feature-auth`, `dev-sha-abc123` |
| Staging | `staging-{version}` | `staging-latest`, `staging-v1.0.0`, `staging-rc1` |
| Production | `prod-{version}` | `prod-v1.0.0`, `prod-latest`, `prod-hotfix-1.0.1` |
| Main | `{version/sha}` | `latest`, `v1.0.0`, `sha-abc123` |

## Google Cloud Build Integration

### Cloud Build Configuration

```yaml
# cloudbuild.yaml
steps:
  # Build the Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: [
      'build',
      '-t', '${_REGISTRY_URL}/${_SERVICE_NAME}:${COMMIT_SHA}',
      '-t', '${_REGISTRY_URL}/${_SERVICE_NAME}:${_ENVIRONMENT}-latest',
      '-f', '${_DOCKERFILE_PATH}',
      '${_BUILD_CONTEXT}'
    ]
    id: 'build-image'

  # Run security scan
  - name: 'gcr.io/cloud-builders/gcloud'
    args: [
      'artifacts', 'docker', 'images', 'scan',
      '${_REGISTRY_URL}/${_SERVICE_NAME}:${COMMIT_SHA}',
      '--format=json'
    ]
    id: 'security-scan'
    waitFor: ['build-image']

  # Push the Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: [
      'push', '--all-tags',
      '${_REGISTRY_URL}/${_SERVICE_NAME}'
    ]
    id: 'push-image'
    waitFor: ['security-scan']

  # Deploy to Cloud Run (optional)
  - name: 'gcr.io/cloud-builders/gcloud'
    args: [
      'run', 'deploy', '${_SERVICE_NAME}',
      '--image', '${_REGISTRY_URL}/${_SERVICE_NAME}:${COMMIT_SHA}',
      '--region', '${_DEPLOY_REGION}',
      '--platform', 'managed',
      '--allow-unauthenticated'
    ]
    id: 'deploy-service'
    waitFor: ['push-image']

# Default substitutions
substitutions:
  _REGISTRY_REGION: 'us-central1'
  _PROJECT_ID: '${PROJECT_ID}'
  _REPOSITORY: 'isectech-docker'
  _SERVICE_NAME: 'api-gateway'
  _ENVIRONMENT: 'development'
  _DOCKERFILE_PATH: 'Dockerfile'
  _BUILD_CONTEXT: '.'
  _DEPLOY_REGION: 'us-central1'
  _REGISTRY_URL: '${_REGISTRY_REGION}-docker.pkg.dev/${_PROJECT_ID}/${_REPOSITORY}'

# Build options
options:
  logging: CLOUD_LOGGING_ONLY
  substitution_option: ALLOW_LOOSE
  dynamic_substitutions: true

# Build timeout
timeout: '1800s'  # 30 minutes

# Service account for build
serviceAccount: 'projects/${PROJECT_ID}/serviceAccounts/isectech-registry-cicd@${PROJECT_ID}.iam.gserviceaccount.com'
```

### Multi-Service Build Configuration

```yaml
# cloudbuild-multi-service.yaml
steps:
  # Build all iSECTECH services in parallel
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_URL}/api-gateway:${COMMIT_SHA}', './api-gateway']
    id: 'build-api-gateway'
  
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_URL}/auth-service:${COMMIT_SHA}', './auth-service']
    id: 'build-auth-service'
    
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_URL}/event-processor:${COMMIT_SHA}', './event-processor']
    id: 'build-event-processor'
    
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_URL}/threat-detection:${COMMIT_SHA}', './threat-detection']
    id: 'build-threat-detection'
    
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_URL}/siem-engine:${COMMIT_SHA}', './siem-engine']
    id: 'build-siem-engine'

  # Security scanning for all images
  - name: 'gcr.io/cloud-builders/gcloud'
    script: |
      #!/bin/bash
      set -e
      SERVICES=("api-gateway" "auth-service" "event-processor" "threat-detection" "siem-engine")
      for service in "${SERVICES[@]}"; do
        echo "Scanning $service..."
        gcloud artifacts docker images scan ${_REGISTRY_URL}/$service:${COMMIT_SHA} || true
      done
    id: 'security-scan-all'
    waitFor: ['build-api-gateway', 'build-auth-service', 'build-event-processor', 'build-threat-detection', 'build-siem-engine']

  # Push all images
  - name: 'gcr.io/cloud-builders/docker'
    script: |
      #!/bin/bash
      set -e
      SERVICES=("api-gateway" "auth-service" "event-processor" "threat-detection" "siem-engine")
      for service in "${SERVICES[@]}"; do
        echo "Pushing $service..."
        docker push ${_REGISTRY_URL}/$service:${COMMIT_SHA}
        docker tag ${_REGISTRY_URL}/$service:${COMMIT_SHA} ${_REGISTRY_URL}/$service:${_ENVIRONMENT}-latest
        docker push ${_REGISTRY_URL}/$service:${_ENVIRONMENT}-latest
      done
    id: 'push-all-images'
    waitFor: ['security-scan-all']

substitutions:
  _REGISTRY_REGION: 'us-central1'
  _PROJECT_ID: '${PROJECT_ID}'
  _REPOSITORY: 'isectech-${_ENVIRONMENT}'
  _ENVIRONMENT: 'development'
  _REGISTRY_URL: '${_REGISTRY_REGION}-docker.pkg.dev/${_PROJECT_ID}/${_REPOSITORY}'

options:
  logging: CLOUD_LOGGING_ONLY
  machineType: 'E2_HIGHCPU_8'  # High-performance build
  
timeout: '3600s'  # 1 hour for multi-service build
```

## GitHub Actions Integration

### Complete GitHub Actions Workflow

```yaml
# .github/workflows/build-and-deploy.yml
name: iSECTECH Build and Deploy

on:
  push:
    branches: [main, develop, 'feature/*']
  pull_request:
    branches: [main, develop]

env:
  PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
  REGISTRY_REGION: us-central1
  SERVICE_NAME: api-gateway

jobs:
  setup:
    runs-on: ubuntu-latest
    outputs:
      environment: ${{ steps.determine-env.outputs.environment }}
      repository: ${{ steps.determine-env.outputs.repository }}
      should-deploy: ${{ steps.determine-env.outputs.should-deploy }}
    steps:
      - name: Determine Environment
        id: determine-env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "environment=production" >> $GITHUB_OUTPUT
            echo "repository=isectech-production" >> $GITHUB_OUTPUT
            echo "should-deploy=true" >> $GITHUB_OUTPUT
          elif [[ "${{ github.ref }}" == "refs/heads/develop" ]]; then
            echo "environment=staging" >> $GITHUB_OUTPUT
            echo "repository=isectech-staging" >> $GITHUB_OUTPUT
            echo "should-deploy=true" >> $GITHUB_OUTPUT
          else
            echo "environment=development" >> $GITHUB_OUTPUT
            echo "repository=isectech-development" >> $GITHUB_OUTPUT
            echo "should-deploy=false" >> $GITHUB_OUTPUT
          fi

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'

  build-and-push:
    needs: [setup, security-scan]
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      security-events: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Authenticate to Google Cloud
        id: auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
          service_account: ${{ secrets.WIF_SERVICE_ACCOUNT }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2
        with:
          version: 'latest'

      - name: Configure Docker for Artifact Registry
        run: gcloud auth configure-docker ${{ env.REGISTRY_REGION }}-docker.pkg.dev

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY_REGION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/${{ needs.setup.outputs.repository }}/${{ env.SERVICE_NAME }}
          tags: |
            type=ref,event=branch,prefix=${{ needs.setup.outputs.environment }}-
            type=ref,event=pr,prefix=${{ needs.setup.outputs.environment }}-pr-
            type=sha,prefix=${{ needs.setup.outputs.environment }}-sha-
            type=raw,value=${{ needs.setup.outputs.environment }}-latest,enable={{is_default_branch}}

      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: false
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Scan image for vulnerabilities
        run: |
          # Extract the first tag for scanning
          IMAGE_TAG=$(echo "${{ steps.meta.outputs.tags }}" | head -n1)
          echo "Scanning image: $IMAGE_TAG"
          
          # Build image for scanning
          docker build -t $IMAGE_TAG .
          
          # Run vulnerability scan
          gcloud artifacts docker images scan $IMAGE_TAG --format=json > scan-results.json || true
          
          # Check for critical vulnerabilities
          CRITICAL_COUNT=$(jq '.vulnerabilities[] | select(.severity=="CRITICAL") | .severity' scan-results.json 2>/dev/null | wc -l || echo "0")
          echo "Critical vulnerabilities found: $CRITICAL_COUNT"
          
          if [ "$CRITICAL_COUNT" -gt 5 ] && [ "${{ needs.setup.outputs.environment }}" = "production" ]; then
            echo "Too many critical vulnerabilities for production deployment"
            exit 1
          fi

      - name: Push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          file: ./Dockerfile
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Generate deployment artifact
        run: |
          cat > deployment-config.json << EOF
          {
            "image": "$(echo "${{ steps.meta.outputs.tags }}" | head -n1)",
            "environment": "${{ needs.setup.outputs.environment }}",
            "service": "${{ env.SERVICE_NAME }}",
            "commit_sha": "${{ github.sha }}",
            "build_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          }
          EOF

      - name: Upload deployment artifact
        uses: actions/upload-artifact@v4
        with:
          name: deployment-config-${{ github.sha }}
          path: deployment-config.json

  deploy:
    needs: [setup, build-and-push]
    if: needs.setup.outputs.should-deploy == 'true'
    runs-on: ubuntu-latest
    environment: ${{ needs.setup.outputs.environment }}
    permissions:
      contents: read
      id-token: write

    steps:
      - name: Download deployment artifact
        uses: actions/download-artifact@v4
        with:
          name: deployment-config-${{ github.sha }}

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
          service_account: ${{ secrets.WIF_SERVICE_ACCOUNT }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Deploy to Cloud Run
        run: |
          IMAGE=$(jq -r '.image' deployment-config.json)
          ENV=$(jq -r '.environment' deployment-config.json)
          SERVICE=$(jq -r '.service' deployment-config.json)
          
          gcloud run deploy $SERVICE \
            --image $IMAGE \
            --region ${{ env.REGISTRY_REGION }} \
            --platform managed \
            --allow-unauthenticated \
            --set-env-vars "ENVIRONMENT=$ENV" \
            --max-instances 100 \
            --memory 512Mi \
            --cpu 1 \
            --timeout 300s

      - name: Verify deployment
        run: |
          SERVICE_URL=$(gcloud run services describe ${{ env.SERVICE_NAME }} --region ${{ env.REGISTRY_REGION }} --format 'value(status.url)')
          echo "Service deployed at: $SERVICE_URL"
          
          # Health check
          curl -f "$SERVICE_URL/health" || echo "Health check endpoint not available"
```

## GitLab CI Integration

### GitLab CI Configuration

```yaml
# .gitlab-ci.yml
stages:
  - validate
  - build
  - scan
  - push
  - deploy

variables:
  REGISTRY_REGION: "us-central1"
  PROJECT_ID: "$CI_PROJECT_NAMESPACE"
  DOCKER_DRIVER: overlay2
  DOCKER_TLS_CERTDIR: "/certs"

before_script:
  - echo $SERVICE_ACCOUNT_KEY | base64 -d > gcloud-service-key.json
  - gcloud auth activate-service-account --key-file gcloud-service-key.json
  - gcloud config set project $PROJECT_ID
  - gcloud auth configure-docker $REGISTRY_REGION-docker.pkg.dev

validate:
  stage: validate
  image: hadolint/hadolint:latest-debian
  script:
    - hadolint Dockerfile
  rules:
    - changes:
        - Dockerfile
        - "**/*.go"
        - "**/*.js"
        - "**/*.py"

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  script:
    - |
      if [ "$CI_COMMIT_REF_NAME" = "main" ]; then
        ENVIRONMENT="production"
        REPOSITORY="isectech-production"
      elif [ "$CI_COMMIT_REF_NAME" = "develop" ]; then
        ENVIRONMENT="staging"
        REPOSITORY="isectech-staging"
      else
        ENVIRONMENT="development"
        REPOSITORY="isectech-development"
      fi
      
      IMAGE_TAG="$REGISTRY_REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$CI_PROJECT_NAME:$CI_COMMIT_SHA"
      LATEST_TAG="$REGISTRY_REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/$CI_PROJECT_NAME:$ENVIRONMENT-latest"
      
      docker build -t $IMAGE_TAG -t $LATEST_TAG .
      
      echo "IMAGE_TAG=$IMAGE_TAG" >> build.env
      echo "LATEST_TAG=$LATEST_TAG" >> build.env
      echo "ENVIRONMENT=$ENVIRONMENT" >> build.env
  artifacts:
    reports:
      dotenv: build.env

security-scan:
  stage: scan
  image: google/cloud-sdk:latest
  dependencies:
    - build
  script:
    - |
      echo "Scanning image: $IMAGE_TAG"
      gcloud artifacts docker images scan $IMAGE_TAG --format=json > scan-results.json
      
      # Check critical vulnerabilities
      CRITICAL_COUNT=$(jq '.vulnerabilities[] | select(.severity=="CRITICAL") | .severity' scan-results.json 2>/dev/null | wc -l || echo "0")
      echo "Critical vulnerabilities: $CRITICAL_COUNT"
      
      if [ "$CRITICAL_COUNT" -gt 10 ] && [ "$ENVIRONMENT" = "production" ]; then
        echo "Too many critical vulnerabilities for production"
        exit 1
      fi
  artifacts:
    reports:
      junit: scan-results.json
    expire_in: 1 week

push:
  stage: push
  image: docker:latest
  services:
    - docker:dind
  dependencies:
    - build
    - security-scan
  script:
    - docker push $IMAGE_TAG
    - docker push $LATEST_TAG
  only:
    - main
    - develop
    - /^feature\/.*$/

deploy-staging:
  stage: deploy
  image: google/cloud-sdk:latest
  dependencies:
    - push
  script:
    - |
      gcloud run deploy $CI_PROJECT_NAME \
        --image $IMAGE_TAG \
        --region $REGISTRY_REGION \
        --platform managed \
        --allow-unauthenticated \
        --set-env-vars "ENVIRONMENT=staging"
  environment:
    name: staging
    url: https://$CI_PROJECT_NAME-staging-$PROJECT_ID.a.run.app
  only:
    - develop

deploy-production:
  stage: deploy
  image: google/cloud-sdk:latest
  dependencies:
    - push
  script:
    - |
      gcloud run deploy $CI_PROJECT_NAME \
        --image $IMAGE_TAG \
        --region $REGISTRY_REGION \
        --platform managed \
        --allow-unauthenticated \
        --set-env-vars "ENVIRONMENT=production" \
        --min-instances 1 \
        --max-instances 100
  environment:
    name: production
    url: https://$CI_PROJECT_NAME-$PROJECT_ID.a.run.app
  when: manual
  only:
    - main
```

## Security Scanning Integration

### Automated Vulnerability Scanning

```bash
#!/bin/bash
# vulnerability-scan.sh

set -euo pipefail

PROJECT_ID="$1"
REGISTRY_REGION="$2"
IMAGE_URL="$3"
MAX_CRITICAL="${4:-5}"
MAX_HIGH="${5:-20}"

echo "Scanning image: $IMAGE_URL"

# Run the scan
gcloud artifacts docker images scan "$IMAGE_URL" --format=json > scan-results.json

# Parse results
CRITICAL_COUNT=$(jq '.vulnerabilities[]? | select(.severity=="CRITICAL") | .severity' scan-results.json 2>/dev/null | wc -l || echo "0")
HIGH_COUNT=$(jq '.vulnerabilities[]? | select(.severity=="HIGH") | .severity' scan-results.json 2>/dev/null | wc -l || echo "0")

echo "Critical vulnerabilities: $CRITICAL_COUNT"
echo "High vulnerabilities: $HIGH_COUNT"

# Check thresholds
if [ "$CRITICAL_COUNT" -gt "$MAX_CRITICAL" ]; then
    echo "ERROR: Too many critical vulnerabilities ($CRITICAL_COUNT > $MAX_CRITICAL)"
    exit 1
fi

if [ "$HIGH_COUNT" -gt "$MAX_HIGH" ]; then
    echo "WARNING: High number of high-severity vulnerabilities ($HIGH_COUNT > $MAX_HIGH)"
fi

echo "Vulnerability scan passed"
```

## Environment-Specific Configurations

### Development Environment

```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  api-gateway:
    image: us-central1-docker.pkg.dev/isectech-dev/isectech-development/api-gateway:dev-latest
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=debug
    ports:
      - "8080:8080"
    
  auth-service:
    image: us-central1-docker.pkg.dev/isectech-dev/isectech-development/auth-service:dev-latest
    environment:
      - ENVIRONMENT=development
      - LOG_LEVEL=debug
```

### Production Environment

```yaml
# kubernetes/production/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: isectech-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      serviceAccountName: isectech-workload
      containers:
      - name: api-gateway
        image: us-central1-docker.pkg.dev/isectech-prod/isectech-production/api-gateway:prod-v1.0.0
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Monitoring and Alerting

### Container Registry Metrics

```sql
-- BigQuery query for registry usage
SELECT 
  repository_name,
  image_name,
  tag,
  size_bytes,
  upload_time,
  vulnerability_count
FROM `project.dataset.artifact_registry_usage`
WHERE DATE(upload_time) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
ORDER BY upload_time DESC;
```

### Alerting Policies

```yaml
# monitoring/registry-alerts.yaml
alerting_policies:
  - display_name: "High Vulnerability Count in Container Images"
    conditions:
      - display_name: "Critical vulnerabilities > 5"
        condition_threshold:
          filter: 'resource.type="artifact_registry"'
          comparison: COMPARISON_GREATER_THAN
          threshold_value: 5
    notification_channels:
      - projects/PROJECT_ID/notificationChannels/CHANNEL_ID

  - display_name: "Failed Container Image Pushes"
    conditions:
      - display_name: "Push failures > 3 in 5 minutes"
        condition_threshold:
          filter: 'resource.type="artifact_registry" AND metric.type="push_failures"'
          comparison: COMPARISON_GREATER_THAN
          threshold_value: 3
          duration: 300s
```

## Troubleshooting Guide

### Common Issues and Solutions

#### Authentication Errors

```bash
# Fix 1: Re-configure Docker authentication
gcloud auth configure-docker us-central1-docker.pkg.dev

# Fix 2: Check service account permissions
gcloud projects get-iam-policy PROJECT_ID --flatten="bindings[].members" --filter="bindings.role:artifactregistry"

# Fix 3: Verify project access
gcloud projects describe PROJECT_ID
```

#### Push/Pull Failures

```bash
# Check repository exists
gcloud artifacts repositories list --location=us-central1

# Verify image name format
# Correct: us-central1-docker.pkg.dev/project/repo/service:tag
# Incorrect: gcr.io/project/service:tag

# Test connectivity
docker pull hello-world
```

#### Vulnerability Scanning Issues

```bash
# Enable Container Analysis API
gcloud services enable containeranalysis.googleapis.com

# Manual scan trigger
gcloud artifacts docker images scan IMAGE_URL

# Check scan status
gcloud artifacts docker images list-vulnerabilities IMAGE_URL
```

## Best Practices

### Security Best Practices

1. **Use Multi-Stage Builds**: Minimize image size and attack surface
2. **Scan Early and Often**: Integrate vulnerability scanning in CI/CD
3. **Use Specific Tags**: Avoid using `latest` in production
4. **Implement RBAC**: Use least-privilege access controls
5. **Monitor Registry Usage**: Track image pulls and vulnerability trends

### Performance Best Practices

1. **Optimize Build Cache**: Use Docker layer caching
2. **Parallel Builds**: Build multiple services concurrently
3. **Regional Deployment**: Use closest registry region
4. **Cleanup Policies**: Implement automatic cleanup to reduce costs
5. **Image Optimization**: Use distroless or alpine base images

### Operational Best Practices

1. **Tag Consistently**: Follow established tagging conventions
2. **Document Changes**: Include clear commit messages and PR descriptions
3. **Test Thoroughly**: Validate images in non-production environments first
4. **Monitor Metrics**: Track build times, scan results, and deployment success rates
5. **Automate Everything**: Minimize manual intervention in CI/CD processes

## Support and Documentation

- **Internal Documentation**: `infrastructure/terraform/modules/artifact-registry/README.md`
- **Setup Script**: `infrastructure/scripts/setup-docker-auth.sh`
- **Terraform Module**: `infrastructure/terraform/modules/artifact-registry/`
- **Monitoring Dashboards**: Google Cloud Console > Artifact Registry
- **Support Channel**: #infrastructure Slack channel

---

*This document is maintained by the iSECTECH Infrastructure Team. Last updated: $(date)*