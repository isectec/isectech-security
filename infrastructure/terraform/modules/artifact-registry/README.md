# iSECTECH Artifact Registry Module

Production-grade Google Artifact Registry module specifically designed for iSECTECH security platform container image management with enhanced security, compliance, and multi-environment support.

## Features

### 🛡️ Security Features
- **Vulnerability Scanning**: Automatic container image vulnerability scanning with alerting
- **Binary Authorization**: Production image verification with attestation (production only)
- **IAM Security**: Least-privilege access controls with dedicated service accounts
- **Audit Logging**: Comprehensive audit trail for compliance requirements
- **Encryption**: Optional KMS encryption for container images

### 🏗️ Architecture Features
- **Multi-Environment Support**: Separate repositories for dev, staging, and production
- **Service-Specific Tagging**: Optimized for iSECTECH microservices architecture
- **Cost Optimization**: Intelligent cleanup policies to minimize storage costs
- **Monitoring Integration**: Built-in alerting for vulnerabilities and failed pushes

### 🔧 Operational Features
- **CI/CD Integration**: Ready-to-use configurations for Cloud Build and GitHub Actions
- **Compliance Ready**: SOC2, ISO27001, NIST compliance support
- **Performance Optimized**: Regional deployment for optimal performance
- **Disaster Recovery**: Cross-region replication support

## Usage

### Basic Usage

```hcl
module "artifact_registry" {
  source = "./modules/artifact-registry"
  
  project_id  = "isectech-prod-12345"
  region      = "us-central1"
  environment = "production"
  
  # Security configuration
  enable_vulnerability_scanning = true
  enable_binary_authorization  = true
  
  # Monitoring
  enable_monitoring      = true
  notification_channels  = ["projects/isectech-prod-12345/notificationChannels/1234567890"]
  
  labels = {
    project     = "isectech"
    environment = "production"
    managed-by  = "terraform"
  }
}
```

### Advanced Configuration

```hcl
module "artifact_registry" {
  source = "./modules/artifact-registry"
  
  project_id  = "isectech-prod-12345"
  region      = "us-central1"
  environment = "production"
  
  # Custom iSECTECH services
  isectech_services = [
    "api-gateway",
    "auth-service",
    "event-processor",
    "threat-detection",
    "siem-engine",
    "custom-security-tool"
  ]
  
  # Enhanced security
  enable_vulnerability_scanning = true
  enable_binary_authorization  = true
  attestor_public_key         = var.attestor_public_key
  
  # Cost optimization
  cleanup_policy_untagged_days   = 3
  cleanup_policy_keep_versions   = 15
  production_keep_versions       = 100
  development_keep_versions      = 20
  
  # Compliance
  compliance_frameworks = ["SOC2", "ISO27001", "NIST", "HIPAA"]
  enable_audit_logging = true
  
  # Integration
  workload_identity_sa = "isectech-workload@isectech-prod-12345.iam.gserviceaccount.com"
  ci_cd_service_accounts = [
    "isectech-cicd@isectech-prod-12345.iam.gserviceaccount.com"
  ]
  
  # Monitoring
  enable_monitoring         = true
  notification_channels     = var.notification_channels
  vulnerability_threshold   = 5
  failed_push_threshold    = 3
}
```

## Repositories Created

The module creates the following repositories:

### Main Repository
- **Name**: `isectech-docker`
- **Purpose**: Primary repository for all iSECTECH microservices
- **URL**: `{region}-docker.pkg.dev/{project-id}/isectech-docker`

### Environment Repositories
- **Development**: `isectech-development`
- **Staging**: `isectech-staging`
- **Production**: `isectech-production`

### Security Tools Repository
- **Name**: `isectech-security-tools`
- **Purpose**: Dedicated repository for security scanning and monitoring tools

## Image Tagging Strategy

### Recommended Tagging Convention

```bash
# Main repository
{region}-docker.pkg.dev/{project-id}/isectech-docker/{service}:{tag}

# Examples:
us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:latest
us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:v1.0.0
us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:sha-abc123def

# Environment-specific
{region}-docker.pkg.dev/{project-id}/isectech-{env}/{service}:{env}-{tag}

# Examples:
us-central1-docker.pkg.dev/isectech-prod/isectech-production/api-gateway:prod-v1.0.0
us-central1-docker.pkg.dev/isectech-prod/isectech-staging/api-gateway:staging-latest
us-central1-docker.pkg.dev/isectech-prod/isectech-development/api-gateway:dev-feature-123
```

### Tag Patterns
- **Latest**: `latest`, `{env}-latest`
- **Version**: `v{major}.{minor}.{patch}`, `{env}-v{major}.{minor}.{patch}`
- **Commit**: `sha-{short-sha}`, `{env}-sha-{short-sha}`
- **Feature**: `feature-{branch-name}`, `{env}-feature-{branch-name}`
- **PR**: `pr-{number}`, `{env}-pr-{number}`

## Docker Authentication

### Configure Docker Authentication

```bash
# Configure Docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Alternative: Login with access token
docker login -u _token -p "$(gcloud auth print-access-token)" https://us-central1-docker.pkg.dev
```

### Service Account Authentication (CI/CD)

```bash
# Authenticate with service account key
gcloud auth activate-service-account --key-file=path/to/service-account-key.json
gcloud auth configure-docker us-central1-docker.pkg.dev
```

## CI/CD Integration

### Cloud Build Integration

```yaml
# cloudbuild.yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', '${_REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/${_MAIN_REPO}/${_SERVICE_NAME}:${COMMIT_SHA}', '.']
  
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', '${_REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/${_MAIN_REPO}/${_SERVICE_NAME}:${COMMIT_SHA}']

substitutions:
  _SERVICE_NAME: 'api-gateway'
  _REGISTRY_REGION: 'us-central1'
  _MAIN_REPO: 'isectech-docker'

options:
  logging: CLOUD_LOGGING_ONLY
```

### GitHub Actions Integration

```yaml
name: Build and Push to Artifact Registry

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - uses: actions/checkout@v4
      
      - id: 'auth'
        uses: 'google-github-actions/auth@v2'
        with:
          workload_identity_provider: 'projects/123456789/locations/global/workloadIdentityPools/github-actions/providers/github-actions'
          service_account: 'isectech-registry-cicd@isectech-prod.iam.gserviceaccount.com'

      - name: 'Set up Cloud SDK'
        uses: 'google-github-actions/setup-gcloud@v2'

      - name: 'Configure Docker'
        run: gcloud auth configure-docker us-central1-docker.pkg.dev

      - name: 'Build and Push'
        run: |
          docker build -t us-central1-docker.pkg.dev/${{ env.PROJECT_ID }}/isectech-docker/api-gateway:${{ github.sha }} .
          docker push us-central1-docker.pkg.dev/${{ env.PROJECT_ID }}/isectech-docker/api-gateway:${{ github.sha }}
```

## Security Configuration

### Binary Authorization (Production)

For production environments, the module configures Binary Authorization to ensure only verified images are deployed:

```bash
# Generate attestor key pair
gpg --quick-generate-key isectech-security-attestor
gpg --armor --export isectech-security-attestor > attestor-public-key.asc

# Create attestation
gcloud container binauthz attestations sign-and-create \
  --project=isectech-prod \
  --artifact-url=us-central1-docker.pkg.dev/isectech-prod/isectech-production/api-gateway:v1.0.0 \
  --attestor=isectech-security-attestor \
  --keyversion=1
```

### Vulnerability Scanning

Automatic vulnerability scanning is enabled for all repositories:

```bash
# Manual vulnerability scan
gcloud artifacts docker images scan \
  us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:latest

# List vulnerabilities
gcloud artifacts docker images list-vulnerabilities \
  us-central1-docker.pkg.dev/isectech-prod/isectech-docker/api-gateway:latest
```

## Monitoring and Alerting

### Built-in Alerts
- **High Vulnerability Count**: Alerts when images have >10 vulnerabilities
- **Failed Image Pushes**: Alerts when >5 pushes fail within 5 minutes

### Custom Monitoring Queries

```sql
-- BigQuery: Top vulnerable images
SELECT 
  image_name,
  tag,
  vulnerability_count,
  severity_counts
FROM `project.dataset.container_vulnerabilities`
WHERE DATE(_PARTITIONTIME) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
ORDER BY vulnerability_count DESC
LIMIT 20;
```

## Cost Optimization

### Cleanup Policies
- **Untagged Images**: Deleted after 7 days (configurable)
- **Version Retention**: Keep 10-50 versions depending on environment
- **Age-based Cleanup**: Delete images older than 30 days (keeping minimum versions)

### Cost Monitoring
```bash
# Estimate repository costs
gcloud artifacts repositories describe isectech-docker \
  --location=us-central1 \
  --format="value(sizeBytes)"
```

## Troubleshooting

### Common Issues

#### Authentication Errors
```bash
# Re-configure Docker auth
gcloud auth configure-docker us-central1-docker.pkg.dev --quiet

# Check permissions
gcloud projects get-iam-policy PROJECT_ID \
  --flatten='bindings[].members' \
  --filter='bindings.role:artifactregistry'
```

#### Push Failures
```bash
# Check repository exists
gcloud artifacts repositories list --location=us-central1

# Validate image name format
# Correct: us-central1-docker.pkg.dev/project/repo/image:tag
# Incorrect: gcr.io/project/image:tag
```

#### Vulnerability Scanning Issues
```bash
# Check if Container Analysis API is enabled
gcloud services list --enabled --filter="name:containeranalysis.googleapis.com"

# Manual scan trigger
gcloud artifacts docker images scan IMAGE_URL
```

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.6.0 |
| google | ~> 5.10 |

## Providers

| Name | Version |
|------|---------|
| google | ~> 5.10 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| project_id | Google Cloud Project ID | `string` | n/a | yes |
| region | Google Cloud region | `string` | `"us-central1"` | no |
| environment | Environment name | `string` | n/a | yes |
| enable_vulnerability_scanning | Enable vulnerability scanning | `bool` | `true` | no |
| enable_binary_authorization | Enable Binary Authorization | `bool` | `true` | no |
| notification_channels | Notification channel IDs | `list(string)` | `[]` | no |

## Outputs

| Name | Description |
|------|-------------|
| main_repository_url | URL of the main Docker repository |
| environment_repositories | Map of environment repository information |
| ci_cd_service_account_email | Email of CI/CD service account |
| docker_config_commands | Docker configuration commands |
| image_tagging_strategy | Recommended tagging strategy |

## License

Internal use only - iSECTECH Security Platform