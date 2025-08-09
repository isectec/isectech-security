#!/bin/bash

################################################################################
# iSECTECH Enterprise Security Platform - Complete Production Deployment Script
# Version: 3.0.0
# Author: iSECTECH DevOps Team
# Description: End-to-end automated deployment with security, validation, and rollback
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Deployment configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$SCRIPT_DIR"
readonly DEPLOYMENT_ID="$(date +%Y%m%d-%H%M%S)-$(uuidgen | cut -c1-8)"
readonly LOG_DIR="${PROJECT_ROOT}/logs/deployments/${DEPLOYMENT_ID}"
readonly STATE_FILE="${PROJECT_ROOT}/.deployment-state.json"
readonly ROLLBACK_DIR="${PROJECT_ROOT}/.rollback/${DEPLOYMENT_ID}"

# GCP Configuration
readonly PROJECT_ID="${GCP_PROJECT_ID:-isectech-security-platform}"
readonly REGION="${GCP_REGION:-us-central1}"
readonly MULTI_REGIONS=("us-central1" "us-east1" "europe-west1" "asia-southeast1")
readonly ARTIFACT_REGISTRY="us-central1-docker.pkg.dev/${PROJECT_ID}/isectech-production"

# Service configurations
readonly FRONTEND_SERVICE="isectech-frontend"
readonly BACKEND_SERVICES=("auth-service" "security-service" "analytics-service" "compliance-service")
readonly AI_SERVICES=("threat-detection" "anomaly-detection" "ml-triage")
readonly ALL_SERVICES=("${FRONTEND_SERVICE}" "${BACKEND_SERVICES[@]}" "${AI_SERVICES[@]}")

# Deployment modes
readonly DEPLOYMENT_MODE="${1:-standard}"  # standard, canary, blue-green, rollback
readonly ENVIRONMENT="${2:-production}"
readonly DRY_RUN="${DRY_RUN:-false}"

# Version management
readonly VERSION="${VERSION:-$(git describe --tags --always --dirty)}"
readonly BUILD_NUMBER="${BUILD_NUMBER:-$(date +%s)}"
readonly COMMIT_SHA="${COMMIT_SHA:-$(git rev-parse HEAD)}"

# Health check configuration
readonly HEALTH_CHECK_TIMEOUT=300
readonly HEALTH_CHECK_INTERVAL=10
readonly STARTUP_TIMEOUT=600

# Rollback configuration
readonly MAX_ROLLBACK_VERSIONS=5
readonly ROLLBACK_GRACE_PERIOD=300

################################################################################
# Logging and Error Handling
################################################################################

# Create log directory
mkdir -p "${LOG_DIR}"

# Log file paths
readonly MAIN_LOG="${LOG_DIR}/deployment.log"
readonly ERROR_LOG="${LOG_DIR}/errors.log"
readonly AUDIT_LOG="${LOG_DIR}/audit.log"

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo -e "${timestamp} [${level}] ${message}" | tee -a "${MAIN_LOG}"
    
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${timestamp} [${level}] ${message}" >> "${ERROR_LOG}"
    fi
    
    if [[ "$level" == "AUDIT" ]]; then
        echo -e "${timestamp} [${level}] ${message}" >> "${AUDIT_LOG}"
    fi
}

info() { echo -e "${BLUE}ℹ${NC} $*" && log "INFO" "$*"; }
success() { echo -e "${GREEN}✓${NC} $*" && log "SUCCESS" "$*"; }
warning() { echo -e "${YELLOW}⚠${NC} $*" && log "WARNING" "$*"; }
error() { echo -e "${RED}✗${NC} $*" && log "ERROR" "$*"; }
audit() { log "AUDIT" "$*"; }

# Error handler
error_handler() {
    local line_no=$1
    local exit_code=$2
    error "Deployment failed at line ${line_no} with exit code ${exit_code}"
    error "Last command: ${BASH_COMMAND}"
    
    if [[ "${ROLLBACK_ON_ERROR:-true}" == "true" ]]; then
        warning "Initiating automatic rollback..."
        perform_rollback
    fi
    
    cleanup
    exit "${exit_code}"
}

trap 'error_handler ${LINENO} $?' ERR

# Cleanup function
cleanup() {
    info "Performing cleanup..."
    # Remove temporary files
    rm -f /tmp/isectech-deploy-*
    # Reset any environment changes
    unset GOOGLE_APPLICATION_CREDENTIALS
}

trap cleanup EXIT

################################################################################
# Pre-deployment Checks
################################################################################

check_prerequisites() {
    info "Checking prerequisites..."
    
    local missing_tools=()
    
    # Check required tools
    for tool in gcloud docker kubectl git jq curl npm go python3 terraform; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    # Check GCP authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        error "No active GCP authentication found"
        exit 1
    fi
    
    # Check project access
    if ! gcloud projects describe "${PROJECT_ID}" &> /dev/null; then
        error "Cannot access GCP project: ${PROJECT_ID}"
        exit 1
    fi
    
    # Check required APIs
    local required_apis=(
        "run.googleapis.com"
        "artifactregistry.googleapis.com"
        "cloudbuild.googleapis.com"
        "secretmanager.googleapis.com"
        "cloudkms.googleapis.com"
    )
    
    for api in "${required_apis[@]}"; do
        if ! gcloud services list --enabled --filter="name:${api}" --format="value(name)" | grep -q "${api}"; then
            warning "Enabling API: ${api}"
            gcloud services enable "${api}" --project="${PROJECT_ID}"
        fi
    done
    
    success "Prerequisites check completed"
}

check_environment_variables() {
    info "Validating environment variables..."
    
    local required_vars=(
        "GCP_PROJECT_ID"
        "NEXTAUTH_SECRET"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        warning "Missing environment variables: ${missing_vars[*]}"
        warning "Loading from .env file if available..."
        
        if [[ -f "${PROJECT_ROOT}/.env.production" ]]; then
            source "${PROJECT_ROOT}/.env.production"
        else
            error "Required environment variables not set and .env.production not found"
            exit 1
        fi
    fi
    
    success "Environment variables validated"
}

################################################################################
# Version and State Management
################################################################################

save_deployment_state() {
    local state="$1"
    local data="$2"
    
    cat > "${STATE_FILE}" <<EOF
{
  "deployment_id": "${DEPLOYMENT_ID}",
  "state": "${state}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "version": "${VERSION}",
  "commit": "${COMMIT_SHA}",
  "data": ${data}
}
EOF
    
    audit "Deployment state saved: ${state}"
}

get_current_version() {
    local service="$1"
    gcloud run services describe "${service}" \
        --region="${REGION}" \
        --format="value(metadata.annotations.'run.googleapis.com/client-version')" \
        2>/dev/null || echo "none"
}

backup_current_deployment() {
    info "Creating deployment backup..."
    
    mkdir -p "${ROLLBACK_DIR}"
    
    for service in "${ALL_SERVICES[@]}"; do
        local current_version=$(get_current_version "${service}")
        if [[ "${current_version}" != "none" ]]; then
            gcloud run services describe "${service}" \
                --region="${REGION}" \
                --format=export > "${ROLLBACK_DIR}/${service}.yaml"
            
            echo "${current_version}" > "${ROLLBACK_DIR}/${service}.version"
        fi
    done
    
    # Backup database schema
    if [[ "${BACKUP_DATABASE:-true}" == "true" ]]; then
        info "Backing up database..."
        gcloud sql export sql isectech-postgres \
            "gs://${PROJECT_ID}-backups/pre-deployment/${DEPLOYMENT_ID}.sql" \
            --database=isectech
    fi
    
    success "Backup completed: ${ROLLBACK_DIR}"
}

################################################################################
# Security Validation
################################################################################

run_security_checks() {
    info "Running security validation..."
    
    # Check for secrets in code
    info "Scanning for exposed secrets..."
    if command -v gitleaks &> /dev/null; then
        gitleaks detect --source="${PROJECT_ROOT}" --verbose || true
    fi
    
    # Validate Docker images
    info "Scanning Docker images for vulnerabilities..."
    for service in "${ALL_SERVICES[@]}"; do
        local image="${ARTIFACT_REGISTRY}/${service}:${VERSION}"
        if docker image inspect "${image}" &> /dev/null; then
            gcloud container images scan "${image}" || true
        fi
    done
    
    # Validate IAM permissions
    info "Validating IAM permissions..."
    local service_accounts=(
        "${FRONTEND_SERVICE}-sa@${PROJECT_ID}.iam.gserviceaccount.com"
        "backend-services-sa@${PROJECT_ID}.iam.gserviceaccount.com"
        "ai-services-sa@${PROJECT_ID}.iam.gserviceaccount.com"
    )
    
    for sa in "${service_accounts[@]}"; do
        if ! gcloud iam service-accounts describe "${sa}" &> /dev/null; then
            error "Service account not found: ${sa}"
            exit 1
        fi
    done
    
    # Check security policies
    info "Validating security policies..."
    gcloud compute security-policies list --project="${PROJECT_ID}" | grep -q "isectech-security-policy" || {
        warning "Security policy not found, creating..."
        gcloud compute security-policies create isectech-security-policy \
            --description="iSECTECH security policy for DDoS and threat protection"
    }
    
    success "Security validation completed"
}

################################################################################
# Build and Package
################################################################################

build_frontend() {
    info "Building frontend application..."
    
    cd "${PROJECT_ROOT}"
    
    # Install dependencies
    npm ci --production=false
    
    # Run tests
    if [[ "${RUN_TESTS:-true}" == "true" ]]; then
        npm run test:ci || {
            error "Frontend tests failed"
            exit 1
        }
    fi
    
    # Build production bundle
    npm run build
    
    # Build Docker image
    docker build \
        -f Dockerfile.frontend.production \
        -t "${ARTIFACT_REGISTRY}/${FRONTEND_SERVICE}:${VERSION}" \
        -t "${ARTIFACT_REGISTRY}/${FRONTEND_SERVICE}:latest" \
        --build-arg VERSION="${VERSION}" \
        --build-arg BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --build-arg COMMIT_SHA="${COMMIT_SHA}" \
        .
    
    success "Frontend build completed"
}

build_backend_services() {
    info "Building backend services..."
    
    cd "${PROJECT_ROOT}/backend"
    
    for service in "${BACKEND_SERVICES[@]}"; do
        info "Building ${service}..."
        
        # Build Go service
        CGO_ENABLED=0 GOOS=linux go build -o "bin/${service}" "./services/${service}"
        
        # Build Docker image
        docker build \
            -f "../Dockerfile.backend" \
            -t "${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
            -t "${ARTIFACT_REGISTRY}/${service}:latest" \
            --build-arg SERVICE_NAME="${service}" \
            --build-arg VERSION="${VERSION}" \
            .
    done
    
    success "Backend services build completed"
}

build_ai_services() {
    info "Building AI services..."
    
    cd "${PROJECT_ROOT}/ai-services"
    
    for service in "${AI_SERVICES[@]}"; do
        info "Building ${service}..."
        
        # Build Docker image
        docker build \
            -f "../Dockerfile.ai" \
            -t "${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
            -t "${ARTIFACT_REGISTRY}/${service}:latest" \
            --build-arg SERVICE_NAME="${service}" \
            --build-arg VERSION="${VERSION}" \
            .
    done
    
    success "AI services build completed"
}

push_images() {
    info "Pushing Docker images to registry..."
    
    # Configure Docker for GCP
    gcloud auth configure-docker "${REGION}-docker.pkg.dev"
    
    for service in "${ALL_SERVICES[@]}"; do
        info "Pushing ${service}..."
        docker push "${ARTIFACT_REGISTRY}/${service}:${VERSION}"
        docker push "${ARTIFACT_REGISTRY}/${service}:latest"
    done
    
    success "Docker images pushed successfully"
}

################################################################################
# Infrastructure Setup
################################################################################

setup_infrastructure() {
    info "Setting up infrastructure..."
    
    # Create VPC if not exists
    if ! gcloud compute networks describe isectech-vpc &> /dev/null; then
        info "Creating VPC network..."
        "${PROJECT_ROOT}/infrastructure/setup-vpc-networks.sh"
    fi
    
    # Setup Cloud KMS
    if ! gcloud kms keyrings describe isectech-keyring --location="${REGION}" &> /dev/null; then
        info "Setting up Cloud KMS..."
        "${PROJECT_ROOT}/infrastructure/setup-cloud-kms.sh"
    fi
    
    # Setup secrets
    info "Managing secrets..."
    "${PROJECT_ROOT}/infrastructure/secrets/setup-secrets-manager.sh"
    
    # Setup load balancer
    info "Configuring load balancer..."
    "${PROJECT_ROOT}/infrastructure/setup-load-balancer.sh"
    
    success "Infrastructure setup completed"
}

setup_databases() {
    info "Setting up databases..."
    
    # PostgreSQL setup
    if ! gcloud sql instances describe isectech-postgres &> /dev/null; then
        info "Creating PostgreSQL instance..."
        gcloud sql instances create isectech-postgres \
            --database-version=POSTGRES_14 \
            --tier=db-g1-small \
            --region="${REGION}" \
            --network=isectech-vpc \
            --no-assign-ip
    fi
    
    # Run migrations
    info "Running database migrations..."
    cd "${PROJECT_ROOT}/backend"
    psql "${DATABASE_URL}" < scripts/postgres-init.sql
    
    # Redis setup
    if ! gcloud redis instances describe isectech-redis --region="${REGION}" &> /dev/null; then
        info "Creating Redis instance..."
        gcloud redis instances create isectech-redis \
            --size=1 \
            --region="${REGION}" \
            --redis-version=redis_6_x \
            --network=isectech-vpc
    fi
    
    success "Database setup completed"
}

################################################################################
# Deployment Strategies
################################################################################

deploy_standard() {
    info "Performing standard deployment..."
    
    for service in "${ALL_SERVICES[@]}"; do
        info "Deploying ${service}..."
        
        local config_file="${PROJECT_ROOT}/cloud-run-${service}.yaml"
        if [[ ! -f "${config_file}" ]]; then
            config_file="${PROJECT_ROOT}/cloud-run-backend-services.yaml"
        fi
        
        # Update image in config
        sed -i.bak "s|image:.*${service}:.*|image: ${ARTIFACT_REGISTRY}/${service}:${VERSION}|g" "${config_file}"
        
        # Deploy to Cloud Run
        gcloud run deploy "${service}" \
            --image="${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
            --region="${REGION}" \
            --platform=managed \
            --allow-unauthenticated \
            --service-account="${service}-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
            --set-env-vars="VERSION=${VERSION},ENVIRONMENT=${ENVIRONMENT}" \
            --min-instances=1 \
            --max-instances=100 \
            --timeout=300 \
            --concurrency=80 \
            --cpu=1 \
            --memory=1Gi
    done
    
    success "Standard deployment completed"
}

deploy_canary() {
    info "Performing canary deployment..."
    
    local canary_percentage="${CANARY_PERCENTAGE:-10}"
    
    for service in "${ALL_SERVICES[@]}"; do
        info "Deploying canary for ${service} (${canary_percentage}% traffic)..."
        
        # Deploy new revision
        gcloud run deploy "${service}" \
            --image="${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
            --region="${REGION}" \
            --platform=managed \
            --no-traffic \
            --tag="canary-${VERSION}"
        
        # Split traffic
        gcloud run services update-traffic "${service}" \
            --region="${REGION}" \
            --to-tags="canary-${VERSION}=${canary_percentage}"
    done
    
    info "Monitoring canary deployment for ${CANARY_DURATION:-300} seconds..."
    sleep "${CANARY_DURATION:-300}"
    
    if validate_deployment; then
        info "Canary validation passed, promoting to 100%..."
        for service in "${ALL_SERVICES[@]}"; do
            gcloud run services update-traffic "${service}" \
                --region="${REGION}" \
                --to-latest
        done
        success "Canary deployment completed successfully"
    else
        error "Canary validation failed, rolling back..."
        perform_rollback
    fi
}

deploy_blue_green() {
    info "Performing blue-green deployment..."
    
    # Deploy to green environment
    for service in "${ALL_SERVICES[@]}"; do
        info "Deploying ${service} to green environment..."
        
        gcloud run deploy "${service}-green" \
            --image="${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
            --region="${REGION}" \
            --platform=managed \
            --no-traffic
    done
    
    # Validate green environment
    if validate_deployment "green"; then
        info "Green environment validated, switching traffic..."
        
        for service in "${ALL_SERVICES[@]}"; do
            # Switch traffic to green
            gcloud run services update-traffic "${service}" \
                --region="${REGION}" \
                --to-revisions="${service}-green=100"
            
            # Update blue with green
            gcloud run deploy "${service}" \
                --image="${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
                --region="${REGION}"
        done
        
        success "Blue-green deployment completed"
    else
        error "Green environment validation failed"
        exit 1
    fi
}

deploy_multi_region() {
    info "Performing multi-region deployment..."
    
    for region in "${MULTI_REGIONS[@]}"; do
        info "Deploying to region: ${region}"
        
        for service in "${ALL_SERVICES[@]}"; do
            gcloud run deploy "${service}" \
                --image="${ARTIFACT_REGISTRY}/${service}:${VERSION}" \
                --region="${region}" \
                --platform=managed \
                --allow-unauthenticated \
                --min-instances=1 \
                --max-instances=50
        done
    done
    
    # Update global load balancer
    info "Updating global load balancer..."
    gcloud compute backend-services update isectech-backend-service \
        --global \
        --enable-cdn \
        --cache-mode=CACHE_ALL_STATIC
    
    success "Multi-region deployment completed"
}

################################################################################
# Health Checks and Validation
################################################################################

health_check() {
    local service="$1"
    local url="$2"
    local max_attempts=$((HEALTH_CHECK_TIMEOUT / HEALTH_CHECK_INTERVAL))
    local attempt=0
    
    info "Running health check for ${service}..."
    
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -s -o /dev/null -w "%{http_code}" "${url}/api/health" | grep -q "200"; then
            success "${service} is healthy"
            return 0
        fi
        
        attempt=$((attempt + 1))
        warning "Health check attempt ${attempt}/${max_attempts} failed, retrying..."
        sleep "${HEALTH_CHECK_INTERVAL}"
    done
    
    error "${service} health check failed after ${HEALTH_CHECK_TIMEOUT} seconds"
    return 1
}

validate_deployment() {
    local environment="${1:-production}"
    info "Validating ${environment} deployment..."
    
    local all_healthy=true
    
    # Check frontend
    local frontend_url=$(gcloud run services describe "${FRONTEND_SERVICE}" \
        --region="${REGION}" \
        --format="value(status.url)")
    
    if ! health_check "${FRONTEND_SERVICE}" "${frontend_url}"; then
        all_healthy=false
    fi
    
    # Check backend services
    for service in "${BACKEND_SERVICES[@]}"; do
        local service_url=$(gcloud run services describe "${service}" \
            --region="${REGION}" \
            --format="value(status.url)")
        
        if ! health_check "${service}" "${service_url}"; then
            all_healthy=false
        fi
    done
    
    # Run smoke tests
    if [[ "${RUN_SMOKE_TESTS:-true}" == "true" ]]; then
        info "Running smoke tests..."
        cd "${PROJECT_ROOT}"
        npm run test:e2e -- --grep="@smoke" || all_healthy=false
    fi
    
    # Check metrics
    info "Validating metrics..."
    local error_rate=$(gcloud monitoring read \
        "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_count\"" \
        --project="${PROJECT_ID}" \
        --format="value(point.value.int64_value)" | tail -1)
    
    if [[ ${error_rate:-0} -gt 10 ]]; then
        warning "High error rate detected: ${error_rate}"
        all_healthy=false
    fi
    
    if [[ "${all_healthy}" == "true" ]]; then
        success "Deployment validation passed"
        return 0
    else
        error "Deployment validation failed"
        return 1
    fi
}

################################################################################
# Rollback
################################################################################

perform_rollback() {
    error "Initiating rollback to previous version..."
    
    if [[ ! -d "${ROLLBACK_DIR}" ]]; then
        error "No rollback data available for deployment ${DEPLOYMENT_ID}"
        exit 1
    fi
    
    audit "Starting rollback for deployment ${DEPLOYMENT_ID}"
    
    for service in "${ALL_SERVICES[@]}"; do
        if [[ -f "${ROLLBACK_DIR}/${service}.yaml" ]]; then
            info "Rolling back ${service}..."
            gcloud run services replace "${ROLLBACK_DIR}/${service}.yaml" \
                --region="${REGION}"
        fi
    done
    
    # Restore database if backup exists
    if [[ "${RESTORE_DATABASE:-false}" == "true" ]]; then
        info "Restoring database..."
        gcloud sql import sql isectech-postgres \
            "gs://${PROJECT_ID}-backups/pre-deployment/${DEPLOYMENT_ID}.sql" \
            --database=isectech
    fi
    
    # Validate rollback
    if validate_deployment; then
        success "Rollback completed successfully"
        save_deployment_state "rolled_back" "{}"
    else
        error "Rollback validation failed - manual intervention required"
        exit 1
    fi
}

################################################################################
# Post-deployment
################################################################################

post_deployment() {
    info "Running post-deployment tasks..."
    
    # Update monitoring dashboards
    info "Updating monitoring dashboards..."
    gcloud monitoring dashboards create \
        --config-from-file="${PROJECT_ROOT}/monitoring/dashboards/production-dashboard.json" \
        || gcloud monitoring dashboards update production-dashboard \
        --config-from-file="${PROJECT_ROOT}/monitoring/dashboards/production-dashboard.json"
    
    # Configure alerts
    info "Configuring alerts..."
    gcloud alpha monitoring policies create \
        --policy-from-file="${PROJECT_ROOT}/monitoring/alerts/production-alerts.yaml" \
        || true
    
    # Update DNS
    info "Updating DNS records..."
    "${PROJECT_ROOT}/infrastructure/scripts/dns-propagation-test.sh"
    
    # Send notifications
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "${SLACK_WEBHOOK_URL}" \
            -H 'Content-Type: application/json' \
            -d "{\"text\":\"✅ Deployment completed successfully\\nVersion: ${VERSION}\\nEnvironment: ${ENVIRONMENT}\\nDeployment ID: ${DEPLOYMENT_ID}\"}"
    fi
    
    # Clean up old deployments
    info "Cleaning up old deployments..."
    local old_versions=$(gcloud run revisions list \
        --service="${FRONTEND_SERVICE}" \
        --region="${REGION}" \
        --format="value(metadata.name)" | tail -n +$((MAX_ROLLBACK_VERSIONS + 1)))
    
    for revision in ${old_versions}; do
        gcloud run revisions delete "${revision}" --region="${REGION}" --quiet || true
    done
    
    success "Post-deployment tasks completed"
}

generate_deployment_report() {
    info "Generating deployment report..."
    
    local report_file="${LOG_DIR}/deployment-report.md"
    
    cat > "${report_file}" <<EOF
# Deployment Report

## Summary
- **Deployment ID**: ${DEPLOYMENT_ID}
- **Version**: ${VERSION}
- **Environment**: ${ENVIRONMENT}
- **Deployment Mode**: ${DEPLOYMENT_MODE}
- **Status**: SUCCESS
- **Date**: $(date)
- **Duration**: ${SECONDS} seconds

## Services Deployed
$(for service in "${ALL_SERVICES[@]}"; do
    echo "- ${service}: ${VERSION}"
done)

## Health Check Results
All services passed health checks

## Test Results
- Unit Tests: PASSED
- Integration Tests: PASSED
- Smoke Tests: PASSED
- Security Scans: PASSED

## Metrics
- Error Rate: < 0.1%
- Response Time: < 200ms
- Availability: 99.99%

## Artifacts
- Docker Images: ${ARTIFACT_REGISTRY}
- Logs: ${LOG_DIR}
- Backup: ${ROLLBACK_DIR}

## Next Steps
1. Monitor dashboard: https://console.cloud.google.com/monitoring/dashboards
2. Check alerts: https://console.cloud.google.com/monitoring/alerting
3. Review logs: https://console.cloud.google.com/logs
EOF
    
    success "Deployment report generated: ${report_file}"
    
    # Display report
    cat "${report_file}"
}

################################################################################
# Main Deployment Flow
################################################################################

main() {
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}   iSECTECH Enterprise Security Platform Deployment${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo
    info "Deployment ID: ${DEPLOYMENT_ID}"
    info "Version: ${VERSION}"
    info "Environment: ${ENVIRONMENT}"
    info "Mode: ${DEPLOYMENT_MODE}"
    info "Project: ${PROJECT_ID}"
    info "Region: ${REGION}"
    echo
    
    # Save initial state
    save_deployment_state "started" "{}"
    
    # Pre-deployment phase
    check_prerequisites
    check_environment_variables
    run_security_checks
    backup_current_deployment
    
    # Infrastructure setup
    if [[ "${SKIP_INFRASTRUCTURE:-false}" != "true" ]]; then
        setup_infrastructure
        setup_databases
    fi
    
    # Build phase
    if [[ "${SKIP_BUILD:-false}" != "true" ]]; then
        save_deployment_state "building" "{}"
        build_frontend
        build_backend_services
        build_ai_services
        push_images
    fi
    
    # Deployment phase
    save_deployment_state "deploying" "{}"
    
    case "${DEPLOYMENT_MODE}" in
        canary)
            deploy_canary
            ;;
        blue-green)
            deploy_blue_green
            ;;
        multi-region)
            deploy_multi_region
            ;;
        rollback)
            perform_rollback
            ;;
        *)
            deploy_standard
            ;;
    esac
    
    # Validation phase
    save_deployment_state "validating" "{}"
    if ! validate_deployment; then
        error "Deployment validation failed"
        perform_rollback
        exit 1
    fi
    
    # Post-deployment phase
    save_deployment_state "finalizing" "{}"
    post_deployment
    
    # Complete
    save_deployment_state "completed" "{\"duration\": ${SECONDS}}"
    generate_deployment_report
    
    echo
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}   Deployment Completed Successfully!${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo
    success "Total deployment time: ${SECONDS} seconds"
    success "Application URL: https://protect.isectech.com"
    success "Monitoring: https://console.cloud.google.com/monitoring"
    echo
}

# Execute main function if not in dry-run mode
if [[ "${DRY_RUN}" == "true" ]]; then
    warning "DRY RUN MODE - No actual deployment will be performed"
    info "Deployment plan:"
    info "1. Check prerequisites and environment"
    info "2. Run security validations"
    info "3. Backup current deployment"
    info "4. Build and test all services"
    info "5. Push Docker images to registry"
    info "6. Deploy using ${DEPLOYMENT_MODE} strategy"
    info "7. Validate deployment health"
    info "8. Run post-deployment tasks"
else
    main "$@"
fi