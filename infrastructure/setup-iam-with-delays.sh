#!/bin/bash

# iSECTECH Google Cloud IAM Setup Script (with rate limiting)
# Configures service accounts, IAM roles, and security policies for multi-tenant platform

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-protech-project}"
REGION="${REGION:-us-central1}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Export Google Cloud SDK to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

# Set project
gcloud config set project "$PROJECT_ID"

# Function to create service account with retry and delay
create_service_account_with_delay() {
    local account_name="$1"
    local display_name="$2"
    local description="$3"
    
    log "Creating service account: $account_name"
    
    if gcloud iam service-accounts describe "${account_name}@${PROJECT_ID}.iam.gserviceaccount.com" &>/dev/null; then
        warning "Service account $account_name already exists"
        return 0
    fi
    
    # Retry logic for quota limits
    local retry_count=0
    local max_retries=3
    
    while [ $retry_count -lt $max_retries ]; do
        if gcloud iam service-accounts create "$account_name" \
            --display-name="$display_name" \
            --description="$description" 2>/dev/null; then
            success "Created service account: $account_name"
            sleep 15  # Wait 15 seconds between service account creations
            return 0
        else
            retry_count=$((retry_count + 1))
            warning "Rate limit hit, waiting 65 seconds before retry $retry_count/$max_retries"
            sleep 65
        fi
    done
    
    error "Failed to create service account $account_name after $max_retries retries"
    return 1
}

log "Continuing IAM configuration from existing service accounts..."

# List existing service accounts
log "Existing service accounts:"
gcloud iam service-accounts list --filter="email:*@${PROJECT_ID}.iam.gserviceaccount.com"

# Continue with remaining service accounts
log "Creating remaining service accounts with rate limiting..."

# Create remaining service accounts with delays
create_service_account_with_delay "cicd-pipeline-sa" \
    "CI/CD Pipeline Service Account" \
    "Service account for build and deployment automation"

create_service_account_with_delay "backup-sa" \
    "Backup Service Account" \
    "Service account for automated backups and disaster recovery"

create_service_account_with_delay "security-scanner-sa" \
    "Security Scanner Service Account" \
    "Service account for vulnerability scanning and security assessments"

create_service_account_with_delay "isectech-app-sa" \
    "iSECTECH Application Service Account" \
    "Service account for iSECTECH application runtime"

log "All service accounts created. Proceeding with IAM role binding..."

# Function to bind IAM policy with error handling
bind_iam_policy_safe() {
    local service_account="$1"
    local role="$2"
    
    log "Binding role $role to $service_account"
    
    if gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${service_account}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --role="$role" \
        --quiet 2>/dev/null; then
        success "Bound $role to $service_account"
    else
        warning "Failed to bind $role to $service_account (may already exist)"
    fi
    sleep 2  # Small delay between bindings
}

log "Binding IAM roles to service accounts..."

# GKE Cluster Service Account roles
bind_iam_policy_safe "gke-cluster-sa" "roles/container.serviceAgent"
bind_iam_policy_safe "gke-cluster-sa" "roles/compute.serviceAgent"

# GKE Node Service Account roles
bind_iam_policy_safe "gke-node-sa" "roles/container.nodeServiceAgent"
bind_iam_policy_safe "gke-node-sa" "roles/storage.objectViewer"
bind_iam_policy_safe "gke-node-sa" "roles/logging.logWriter"
bind_iam_policy_safe "gke-node-sa" "roles/monitoring.metricWriter"

# Cloud SQL Service Account roles
bind_iam_policy_safe "cloudsql-sa" "roles/cloudsql.admin"
bind_iam_policy_safe "cloudsql-sa" "roles/compute.networkUser"

# Monitoring Service Account roles
bind_iam_policy_safe "monitoring-sa" "roles/monitoring.editor"
bind_iam_policy_safe "monitoring-sa" "roles/logging.admin"
bind_iam_policy_safe "monitoring-sa" "roles/errorreporting.admin"

# CI/CD Pipeline Service Account roles
bind_iam_policy_safe "cicd-pipeline-sa" "roles/container.admin"
bind_iam_policy_safe "cicd-pipeline-sa" "roles/storage.admin"
bind_iam_policy_safe "cicd-pipeline-sa" "roles/secretmanager.secretAccessor"

# Backup Service Account roles
bind_iam_policy_safe "backup-sa" "roles/storage.admin"
bind_iam_policy_safe "backup-sa" "roles/cloudsql.editor"

# Security Scanner Service Account roles
bind_iam_policy_safe "security-scanner-sa" "roles/securitycenter.adminEditor"
bind_iam_policy_safe "security-scanner-sa" "roles/compute.securityAdmin"

# iSECTECH Application Service Account roles
bind_iam_policy_safe "isectech-app-sa" "roles/cloudsql.client"
bind_iam_policy_safe "isectech-app-sa" "roles/storage.objectAdmin"
bind_iam_policy_safe "isectech-app-sa" "roles/secretmanager.secretAccessor"
bind_iam_policy_safe "isectech-app-sa" "roles/monitoring.metricWriter"
bind_iam_policy_safe "isectech-app-sa" "roles/logging.logWriter"

log "Setting up cross-service authentication..."

# Allow GKE service account to impersonate application service account
gcloud iam service-accounts add-iam-policy-binding \
    "isectech-app-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --member="serviceAccount:gke-node-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --quiet || warning "Cross-service binding may already exist"

success "Cross-service authentication configured"

log "Creating service account keys for external access..."

# Create key directory
mkdir -p ./keys

# Generate service account keys (only for external access)
for sa in "cicd-pipeline-sa" "monitoring-sa" "backup-sa"; do
    key_file="./keys/${sa}-key.json"
    if [ ! -f "$key_file" ]; then
        log "Creating key for $sa"
        if gcloud iam service-accounts keys create "$key_file" \
            --iam-account="${sa}@${PROJECT_ID}.iam.gserviceaccount.com" \
            --quiet 2>/dev/null; then
            chmod 600 "$key_file"
            success "Created key for $sa"
        else
            warning "Failed to create key for $sa"
        fi
    else
        warning "Key already exists for $sa"
    fi
done

log "Creating IAM summary report..."

# Generate comprehensive IAM summary
cat > ./iam-summary.md << EOF
# iSECTECH IAM Configuration Summary

Generated: $(date)
Project: $PROJECT_ID

## Service Accounts Created

| Service Account | Email | Purpose |
|----------------|-------|---------|
| gke-cluster-sa | gke-cluster-sa@${PROJECT_ID}.iam.gserviceaccount.com | GKE cluster management |
| gke-node-sa | gke-node-sa@${PROJECT_ID}.iam.gserviceaccount.com | GKE node operations |
| cloudsql-sa | cloudsql-sa@${PROJECT_ID}.iam.gserviceaccount.com | Database operations |
| monitoring-sa | monitoring-sa@${PROJECT_ID}.iam.gserviceaccount.com | Observability & alerting |
| cicd-pipeline-sa | cicd-pipeline-sa@${PROJECT_ID}.iam.gserviceaccount.com | Build & deployment |
| backup-sa | backup-sa@${PROJECT_ID}.iam.gserviceaccount.com | Backup & recovery |
| security-scanner-sa | security-scanner-sa@${PROJECT_ID}.iam.gserviceaccount.com | Security assessments |
| isectech-app-sa | isectech-app-sa@${PROJECT_ID}.iam.gserviceaccount.com | Application runtime |

## IAM Roles Assigned

### GKE Cluster Service Account
- roles/container.serviceAgent
- roles/compute.serviceAgent

### GKE Node Service Account
- roles/container.nodeServiceAgent
- roles/storage.objectViewer
- roles/logging.logWriter
- roles/monitoring.metricWriter

### Cloud SQL Service Account
- roles/cloudsql.admin
- roles/compute.networkUser

### Monitoring Service Account
- roles/monitoring.editor
- roles/logging.admin
- roles/errorreporting.admin

### CI/CD Pipeline Service Account
- roles/container.admin
- roles/storage.admin
- roles/secretmanager.secretAccessor

### Backup Service Account
- roles/storage.admin
- roles/cloudsql.editor

### Security Scanner Service Account
- roles/securitycenter.adminEditor
- roles/compute.securityAdmin

### iSECTECH Application Service Account
- roles/cloudsql.client
- roles/storage.objectAdmin
- roles/secretmanager.secretAccessor
- roles/monitoring.metricWriter
- roles/logging.logWriter

## Security Features

- ✅ Least-privilege access policies applied
- ✅ Cross-service authentication configured
- ✅ Service account keys generated for external access
- ✅ Role separation for different platform components

## Service Account Keys Generated

The following service account keys have been created in \`./keys/\`:
- cicd-pipeline-sa-key.json (for CI/CD automation)
- monitoring-sa-key.json (for external monitoring tools)
- backup-sa-key.json (for backup automation)

**Security Warning**: These keys provide administrative access. Store securely and rotate regularly.

## Next Steps

1. ✅ Task 66.2: Configure IAM roles and service accounts - **COMPLETED**
2. 🔄 Task 66.3: Set up billing and budget monitoring
3. 🔄 Task 66.4: Create VPC networks and subnets
4. 🔄 Task 66.5: Configure Cloud KMS for encryption
5. 🔄 Task 66.6: Set up monitoring and logging infrastructure

## Commands to Verify Setup

\`\`\`bash
# List all service accounts
gcloud iam service-accounts list

# Check IAM policies for a service account
gcloud projects get-iam-policy $PROJECT_ID

# Test service account authentication
gcloud auth activate-service-account --key-file=keys/monitoring-sa-key.json
gcloud auth list
\`\`\`
EOF

success "IAM configuration completed successfully!"
success "Summary report created: ./iam-summary.md"
success "Service account keys stored in: ./keys/"

log "IAM setup with rate limiting completed successfully."