#!/bin/bash

# iSECTECH Secret Manager IAM Configuration Script
# Configure service accounts and IAM bindings for secure secret access
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated with sufficient permissions
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable iam.googleapis.com
    gcloud services enable cloudresourcemanager.googleapis.com
    gcloud services enable secretmanager.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create service account with proper naming and labels
create_service_account() {
    local sa_name="$1"
    local display_name="$2"
    local description="$3"
    local service_type="$4"
    
    log_info "Creating service account: ${sa_name}"
    
    # Create service account
    gcloud iam service-accounts create "$sa_name" \
        --display-name="$display_name" \
        --description="$description" || {
        log_warning "Service account ${sa_name} may already exist"
    }
    
    # Add labels for better organization
    gcloud iam service-accounts update "${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com" \
        --update-labels="environment=${ENVIRONMENT},service-type=${service_type},managed-by=isectech-platform"
    
    log_success "Service account ${sa_name} configured"
}

# Grant secret access permissions with principle of least privilege
grant_secret_access() {
    local sa_email="$1"
    local secret_pattern="$2"
    local role="$3"
    local description="$4"
    
    log_info "Granting ${role} access to ${secret_pattern} for ${sa_email}"
    
    # Get all secrets matching the pattern
    local secrets
    secrets=$(gcloud secrets list --filter="name:${secret_pattern}" --format="value(name)")
    
    if [ -z "$secrets" ]; then
        log_warning "No secrets found matching pattern: ${secret_pattern}"
        return
    fi
    
    # Grant access to each matching secret
    while IFS= read -r secret_name; do
        if [ -n "$secret_name" ]; then
            gcloud secrets add-iam-policy-binding "$secret_name" \
                --member="serviceAccount:${sa_email}" \
                --role="$role" \
                --condition=None > /dev/null 2>&1 || {
                log_warning "Failed to grant access to ${secret_name}, may already exist"
            }
        fi
    done <<< "$secrets"
    
    log_success "Secret access granted for ${description}"
}

# Create frontend service account and permissions
setup_frontend_service_account() {
    log_info "Setting up frontend service account..."
    
    local sa_name="isectech-frontend-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH Frontend Service Account" \
        "Service account for iSECTECH React frontend application running on Cloud Run" \
        "frontend"
    
    # Frontend needs access to authentication and OAuth secrets
    grant_secret_access "$sa_email" "isectech-nextauth-*" "roles/secretmanager.secretAccessor" "NextAuth secrets"
    grant_secret_access "$sa_email" "isectech-*-oauth-*" "roles/secretmanager.secretAccessor" "OAuth provider secrets"
    grant_secret_access "$sa_email" "isectech-session-*" "roles/secretmanager.secretAccessor" "Session management secrets"
    grant_secret_access "$sa_email" "isectech-google-maps-*" "roles/secretmanager.secretAccessor" "Google Maps API"
    grant_secret_access "$sa_email" "isectech-mapbox-*" "roles/secretmanager.secretAccessor" "Mapbox API"
    
    # Grant Cloud Run invoker role
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/run.invoker"
    
    log_success "Frontend service account configured"
}

# Create API Gateway service account and permissions
setup_api_gateway_service_account() {
    log_info "Setting up API Gateway service account..."
    
    local sa_name="isectech-api-gateway-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH API Gateway Service Account" \
        "Service account for Kong API Gateway managing traffic routing and authentication" \
        "api-gateway"
    
    # API Gateway needs access to authentication, database, and service mesh secrets
    grant_secret_access "$sa_email" "isectech-jwt-*" "roles/secretmanager.secretAccessor" "JWT signing secrets"
    grant_secret_access "$sa_email" "isectech-service-api-key" "roles/secretmanager.secretAccessor" "Service API key"
    grant_secret_access "$sa_email" "isectech-kong-*" "roles/secretmanager.secretAccessor" "Kong configuration secrets"
    grant_secret_access "$sa_email" "isectech-postgres-*" "roles/secretmanager.secretAccessor" "PostgreSQL secrets for Kong"
    grant_secret_access "$sa_email" "isectech-consul-*" "roles/secretmanager.secretAccessor" "Service discovery secrets"
    
    # Grant necessary Cloud Run and load balancer permissions
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/run.invoker"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/compute.networkUser"
    
    log_success "API Gateway service account configured"
}

# Create backend services service account and permissions
setup_backend_services_service_account() {
    log_info "Setting up backend services service account..."
    
    local sa_name="isectech-backend-services-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH Backend Services Account" \
        "Service account for Go microservices (Auth, SIEM, SOAR, Threat Intel, etc.)" \
        "backend"
    
    # Backend services need comprehensive access to databases, APIs, and infrastructure
    grant_secret_access "$sa_email" "isectech-postgres-*" "roles/secretmanager.secretAccessor" "PostgreSQL database access"
    grant_secret_access "$sa_email" "isectech-mongodb-*" "roles/secretmanager.secretAccessor" "MongoDB database access"
    grant_secret_access "$sa_email" "isectech-redis-*" "roles/secretmanager.secretAccessor" "Redis cache access"
    grant_secret_access "$sa_email" "isectech-clickhouse-*" "roles/secretmanager.secretAccessor" "ClickHouse analytics access"
    grant_secret_access "$sa_email" "isectech-jwt-*" "roles/secretmanager.secretAccessor" "JWT authentication"
    grant_secret_access "$sa_email" "isectech-service-api-key" "roles/secretmanager.secretAccessor" "Inter-service authentication"
    grant_secret_access "$sa_email" "isectech-*-encryption-key" "roles/secretmanager.secretAccessor" "Data encryption keys"
    
    # External API access for threat intelligence and security tools
    grant_secret_access "$sa_email" "isectech-virustotal-*" "roles/secretmanager.secretAccessor" "VirusTotal API"
    grant_secret_access "$sa_email" "isectech-recorded-future-*" "roles/secretmanager.secretAccessor" "Recorded Future API"
    grant_secret_access "$sa_email" "isectech-misp-*" "roles/secretmanager.secretAccessor" "MISP API"
    grant_secret_access "$sa_email" "isectech-nessus-*" "roles/secretmanager.secretAccessor" "Nessus API"
    grant_secret_access "$sa_email" "isectech-openvas-*" "roles/secretmanager.secretAccessor" "OpenVAS API"
    grant_secret_access "$sa_email" "isectech-qualys-*" "roles/secretmanager.secretAccessor" "Qualys API"
    
    # SIEM/SOAR integration access
    grant_secret_access "$sa_email" "isectech-splunk-*" "roles/secretmanager.secretAccessor" "Splunk integration"
    grant_secret_access "$sa_email" "isectech-elastic-*" "roles/secretmanager.secretAccessor" "Elasticsearch integration"
    grant_secret_access "$sa_email" "isectech-phantom-*" "roles/secretmanager.secretAccessor" "Phantom SOAR"
    grant_secret_access "$sa_email" "isectech-demisto-*" "roles/secretmanager.secretAccessor" "Demisto SOAR"
    
    # Communication and notification access
    grant_secret_access "$sa_email" "isectech-smtp-*" "roles/secretmanager.secretAccessor" "Email notifications"
    grant_secret_access "$sa_email" "isectech-slack-*" "roles/secretmanager.secretAccessor" "Slack notifications"
    grant_secret_access "$sa_email" "isectech-twilio-*" "roles/secretmanager.secretAccessor" "SMS notifications"
    grant_secret_access "$sa_email" "isectech-pagerduty-*" "roles/secretmanager.secretAccessor" "PagerDuty alerts"
    
    # Infrastructure access
    grant_secret_access "$sa_email" "isectech-kafka-*" "roles/secretmanager.secretAccessor" "Kafka messaging"
    grant_secret_access "$sa_email" "isectech-consul-*" "roles/secretmanager.secretAccessor" "Service discovery"
    grant_secret_access "$sa_email" "isectech-backup-*" "roles/secretmanager.secretAccessor" "Backup encryption"
    
    # Grant necessary Cloud Run permissions
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/run.invoker"
    
    # Grant Cloud SQL client access (when using Cloud SQL)
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/cloudsql.client"
    
    # Grant Pub/Sub access for event streaming
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/pubsub.publisher"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/pubsub.subscriber"
    
    log_success "Backend services service account configured"
}

# Create monitoring service account and permissions
setup_monitoring_service_account() {
    log_info "Setting up monitoring service account..."
    
    local sa_name="isectech-monitoring-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH Monitoring Service Account" \
        "Service account for monitoring, logging, and observability services" \
        "monitoring"
    
    # Monitoring needs access to monitoring-related secrets
    grant_secret_access "$sa_email" "isectech-sentry-*" "roles/secretmanager.secretAccessor" "Error tracking"
    grant_secret_access "$sa_email" "isectech-newrelic-*" "roles/secretmanager.secretAccessor" "APM monitoring"
    grant_secret_access "$sa_email" "isectech-google-analytics-*" "roles/secretmanager.secretAccessor" "Analytics"
    grant_secret_access "$sa_email" "isectech-mixpanel-*" "roles/secretmanager.secretAccessor" "User analytics"
    
    # Grant monitoring and logging permissions
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/monitoring.metricWriter"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/logging.logWriter"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/cloudtrace.agent"
    
    log_success "Monitoring service account configured"
}

# Create deployment service account for CI/CD
setup_deployment_service_account() {
    log_info "Setting up deployment service account..."
    
    local sa_name="isectech-deployment-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH Deployment Service Account" \
        "Service account for CI/CD pipeline deployments and infrastructure management" \
        "deployment"
    
    # Deployment needs limited access to manage secrets and deployments
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/run.admin"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/storage.admin"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/secretmanager.admin"
    
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/iam.serviceAccountUser"
    
    log_success "Deployment service account configured"
}

# Set up secret rotation service account
setup_secret_rotation_service_account() {
    log_info "Setting up secret rotation service account..."
    
    local sa_name="isectech-secret-rotation-sa"
    local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
    
    create_service_account "$sa_name" \
        "iSECTECH Secret Rotation Service Account" \
        "Service account for automated secret rotation and management" \
        "security"
    
    # Secret rotation needs admin access to secrets but limited other permissions
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/secretmanager.admin"
    
    # Grant access to restart Cloud Run services after rotation
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/run.developer"
    
    # Grant access to Cloud Scheduler for automated rotation
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${sa_email}" \
        --role="roles/cloudscheduler.admin"
    
    log_success "Secret rotation service account configured"
}

# Create custom IAM roles for fine-grained access
create_custom_iam_roles() {
    log_info "Creating custom IAM roles..."
    
    # Custom role for secret readers with audit logging
    cat > /tmp/secret-reader-role.yaml << EOF
title: "iSECTECH Secret Reader"
description: "Custom role for reading secrets with audit requirements"
stage: "GA"
includedPermissions:
- secretmanager.secrets.get
- secretmanager.versions.get
- secretmanager.versions.access
- logging.logEntries.create
EOF
    
    gcloud iam roles create isectech.secretReader \
        --project="$PROJECT_ID" \
        --file=/tmp/secret-reader-role.yaml || {
        log_warning "Custom role may already exist"
    }
    
    # Custom role for service mesh communication
    cat > /tmp/service-mesh-role.yaml << EOF
title: "iSECTECH Service Mesh Actor"
description: "Custom role for service-to-service communication"
stage: "GA"
includedPermissions:
- run.services.get
- run.services.list
- run.services.invoke
- secretmanager.versions.access
- compute.networks.use
EOF
    
    gcloud iam roles create isectech.serviceMeshActor \
        --project="$PROJECT_ID" \
        --file=/tmp/service-mesh-role.yaml || {
        log_warning "Custom role may already exist"
    }
    
    # Clean up temporary files
    rm -f /tmp/secret-reader-role.yaml /tmp/service-mesh-role.yaml
    
    log_success "Custom IAM roles configured"
}

# Set up secret access monitoring and alerting
setup_secret_monitoring() {
    log_info "Setting up secret access monitoring..."
    
    # Create log sink for secret access
    gcloud logging sinks create isectech-secret-access-sink \
        bigquery.googleapis.com/projects/"$PROJECT_ID"/datasets/security_logs \
        --log-filter='protoPayload.serviceName="secretmanager.googleapis.com"' || {
        log_warning "Log sink may already exist"
    }
    
    # Create Cloud Function for anomaly detection (placeholder)
    log_info "Secret access monitoring requires additional Cloud Function deployment"
    log_info "Refer to monitoring setup documentation for complete configuration"
    
    log_success "Secret monitoring framework configured"
}

# Generate service account keys for local development (if needed)
generate_development_keys() {
    if [ "$ENVIRONMENT" != "development" ]; then
        log_info "Skipping development key generation for ${ENVIRONMENT} environment"
        return
    fi
    
    log_warning "Generating service account keys for development environment"
    
    local key_dir="./service-account-keys"
    mkdir -p "$key_dir"
    
    # Generate keys for each service account
    local service_accounts=(
        "isectech-frontend-sa"
        "isectech-api-gateway-sa"
        "isectech-backend-services-sa"
        "isectech-monitoring-sa"
    )
    
    for sa_name in "${service_accounts[@]}"; do
        local sa_email="${sa_name}@${PROJECT_ID}.iam.gserviceaccount.com"
        local key_file="${key_dir}/${sa_name}-key.json"
        
        gcloud iam service-accounts keys create "$key_file" \
            --iam-account="$sa_email" || {
            log_warning "Failed to generate key for ${sa_name}"
        }
    done
    
    log_warning "Development keys generated in ${key_dir}/"
    log_warning "NEVER commit these keys to version control!"
}

# Generate comprehensive IAM report
generate_iam_report() {
    log_info "Generating IAM configuration report..."
    
    local report_file="/tmp/isectech-iam-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH IAM Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}

==================================
SERVICE ACCOUNTS CREATED
==================================

EOF
    
    # List service accounts with labels
    gcloud iam service-accounts list \
        --filter="labels.managed-by=isectech-platform" \
        --format="table(
            displayName:label=SERVICE_ACCOUNT,
            email:label=EMAIL,
            labels.service-type:label=TYPE,
            description:label=DESCRIPTION
        )" >> "$report_file"
    
    cat >> "$report_file" << EOF

==================================
IAM POLICY BINDINGS
==================================

EOF
    
    # List project-level IAM bindings for our service accounts
    gcloud projects get-iam-policy "$PROJECT_ID" \
        --format="json" | jq -r '.bindings[] | select(.members[] | contains("isectech-")) | "\(.role): \(.members[])"' >> "$report_file"
    
    cat >> "$report_file" << EOF

==================================
SECRET ACCESS PERMISSIONS
==================================

EOF
    
    # Get secret access information
    local secrets
    secrets=$(gcloud secrets list --filter="labels.managed-by=isectech-platform" --format="value(name)")
    
    echo "Secrets with IAM bindings:" >> "$report_file"
    while IFS= read -r secret_name; do
        if [ -n "$secret_name" ]; then
            echo "  $secret_name:" >> "$report_file"
            gcloud secrets get-iam-policy "$secret_name" --format="json" 2>/dev/null | \
                jq -r '.bindings[]? | "    \(.role): \(.members[])"' >> "$report_file" 2>/dev/null || true
        fi
    done <<< "$secrets"
    
    cat >> "$report_file" << EOF

==================================
SECURITY RECOMMENDATIONS
==================================

1. Service Account Security:
   - Regularly rotate service account keys (if using key-based auth)
   - Enable service account key expiration policies
   - Monitor service account usage and disable unused accounts
   - Use workload identity for GKE deployments when possible

2. Secret Access Control:
   - Implement regular access reviews for secret permissions
   - Use conditions in IAM policies for time-based access
   - Enable audit logging for all secret access operations
   - Set up automated alerts for unusual secret access patterns

3. Principle of Least Privilege:
   - Review and minimize permissions regularly
   - Use custom roles instead of primitive roles where possible
   - Implement just-in-time access for administrative operations
   - Separate development and production service accounts

4. Monitoring and Compliance:
   - Enable Cloud Asset Inventory for IAM tracking
   - Set up regular compliance scans
   - Implement automated policy enforcement
   - Monitor for policy violations and drift

==================================
NEXT STEPS
==================================

1. Test service account permissions in staging environment
2. Implement secret rotation schedules
3. Set up monitoring and alerting for IAM changes
4. Configure workload identity for GKE if applicable
5. Implement emergency access procedures
6. Create runbooks for IAM incident response

EOF
    
    log_success "IAM report generated: $report_file"
    
    # Display summary
    local sa_count
    sa_count=$(gcloud iam service-accounts list --filter="labels.managed-by=isectech-platform" --format="value(email)" | wc -l)
    
    local secret_count
    secret_count=$(gcloud secrets list --filter="labels.managed-by=isectech-platform" --format="value(name)" | wc -l)
    
    log_info "Summary: ${sa_count} service accounts configured with access to ${secret_count} secrets"
}

# Main execution
main() {
    log_info "Starting iSECTECH IAM Secret Access configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    
    check_prerequisites
    
    create_custom_iam_roles
    
    setup_frontend_service_account
    setup_api_gateway_service_account
    setup_backend_services_service_account
    setup_monitoring_service_account
    setup_deployment_service_account
    setup_secret_rotation_service_account
    
    setup_secret_monitoring
    
    generate_development_keys
    generate_iam_report
    
    log_success "iSECTECH IAM Secret Access configuration completed successfully!"
    
    echo ""
    log_info "Service accounts are now configured with appropriate secret access permissions."
    log_info "Next steps:"
    log_info "1. Update Cloud Run service configurations with correct service account emails"
    log_info "2. Test secret access in staging environment"
    log_info "3. Set up secret rotation schedules"
    log_info "4. Configure monitoring and alerting"
}

# Execute main function
main "$@"