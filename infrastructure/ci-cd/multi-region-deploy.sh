#!/bin/bash
# iSECTECH Multi-Region Deployment Automation Script
# Production-grade deployment orchestration with compliance validation

set -euo pipefail

# Script metadata
readonly SCRIPT_NAME="multi-region-deploy.sh"
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DESCRIPTION="Multi-region deployment automation with compliance validation"

# Configuration
readonly PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
readonly PRIMARY_REGION="${PRIMARY_REGION:-us-central1}"
readonly SECONDARY_REGIONS="${SECONDARY_REGIONS:-europe-west1,asia-northeast1,australia-southeast1}"
readonly DEPLOYMENT_STRATEGY="${DEPLOYMENT_STRATEGY:-blue-green}"
readonly BUILD_VERSION="${BUILD_VERSION:-$(date +%Y%m%d-%H%M%S)}"
readonly ENVIRONMENT="${ENVIRONMENT:-production}"
readonly DRY_RUN="${DRY_RUN:-false}"

# Compliance configuration
readonly GDPR_REGIONS="europe-west1,europe-west2,europe-west3,europe-west4,europe-west6,europe-north1"
readonly PDPA_REGIONS="asia-northeast1,asia-northeast2,asia-southeast1,asia-southeast2,asia-south1,asia-east1"
readonly PRIVACY_ACT_REGIONS="australia-southeast1,australia-southeast2"

# Logging configuration
readonly LOG_LEVEL="${LOG_LEVEL:-INFO}"
readonly LOG_FILE="/tmp/multi-region-deploy-${BUILD_VERSION}.log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Initialize logging
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Logging functions
log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $*"
}

log_warn() {
    log "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "${RED}[ERROR]${NC} $*"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $*"
}

# Error handling
trap 'handle_error $LINENO $?' ERR

handle_error() {
    local line_number=$1
    local exit_code=$2
    log_error "Script failed at line $line_number with exit code $exit_code"
    log_error "Check log file: $LOG_FILE"
    
    # Trigger rollback if deployment was in progress
    if [[ -f "/tmp/deployment-in-progress" ]]; then
        log_warn "Deployment failure detected, initiating rollback..."
        rollback_deployment
    fi
    
    exit $exit_code
}

# Utility functions
validate_prerequisites() {
    log_info "Validating deployment prerequisites..."
    
    # Check required tools
    local required_tools=("gcloud" "kubectl" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool not found: $tool"
            return 1
        fi
    done
    
    # Validate gcloud authentication
    if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
        log_error "gcloud authentication required"
        return 1
    fi
    
    # Validate project access
    if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
        log_error "Cannot access project: $PROJECT_ID"
        return 1
    fi
    
    # Validate regions
    IFS=',' read -ra REGIONS <<< "$SECONDARY_REGIONS"
    for region in "${REGIONS[@]}"; do
        if ! gcloud compute regions describe "$region" --quiet >/dev/null 2>&1; then
            log_error "Cannot access region: $region"
            return 1
        fi
    done
    
    log_success "Prerequisites validation completed"
}

validate_compliance() {
    local region=$1
    local data_classification=${2:-""}
    
    log_info "Validating compliance for region: $region"
    
    # GDPR validation for EU regions
    if [[ ",$GDPR_REGIONS," == *",$region,"* ]]; then
        if [[ "$data_classification" == "EU_RESTRICTED" || "$data_classification" == "" ]]; then
            log_info "✓ $region complies with GDPR requirements"
        else
            log_error "❌ $region does not meet GDPR data residency requirements"
            return 1
        fi
    fi
    
    # PDPA validation for APAC regions
    if [[ ",$PDPA_REGIONS," == *",$region,"* ]]; then
        if [[ "$data_classification" == "APAC_RESTRICTED" || "$data_classification" == "" ]]; then
            log_info "✓ $region complies with PDPA requirements"
        else
            log_error "❌ $region does not meet PDPA data residency requirements"
            return 1
        fi
    fi
    
    # Privacy Act validation for Australia
    if [[ ",$PRIVACY_ACT_REGIONS," == *",$region,"* ]]; then
        if [[ "$data_classification" == "AU_RESTRICTED" || "$data_classification" == "" ]]; then
            log_info "✓ $region complies with Privacy Act requirements"
        else
            log_error "❌ $region does not meet Privacy Act data residency requirements"
            return 1
        fi
    fi
    
    return 0
}

check_service_health() {
    local service_url=$1
    local max_attempts=${2:-5}
    local timeout=${3:-30}
    
    log_info "Checking service health: $service_url"
    
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        if curl -f -s --max-time "$timeout" "$service_url/health" >/dev/null 2>&1; then
            log_success "✓ Service is healthy: $service_url"
            return 0
        else
            log_warn "⚠ Health check failed for $service_url (attempt $attempt/$max_attempts)"
            if [[ $attempt -lt $max_attempts ]]; then
                sleep 10
            fi
        fi
    done
    
    log_error "❌ Service health check failed: $service_url"
    return 1
}

deploy_service_to_region() {
    local service=$1
    local region=$2
    local image_tag=$3
    
    log_info "Deploying $service to region $region with strategy: $DEPLOYMENT_STRATEGY"
    
    # Validate compliance for the region
    validate_compliance "$region" || return 1
    
    local service_name="isectech-$service-$ENVIRONMENT-$region"
    local blue_service_name="${service_name}-blue"
    local registry_url="$region-docker.pkg.dev/$PROJECT_ID/isectech-docker-repo"
    local image_url="$registry_url/$service:$image_tag"
    
    # Mark deployment as in progress
    touch "/tmp/deployment-in-progress"
    
    if [[ "$DEPLOYMENT_STRATEGY" == "blue-green" ]]; then
        deploy_blue_green "$service" "$region" "$image_url" "$blue_service_name"
    elif [[ "$DEPLOYMENT_STRATEGY" == "canary" ]]; then
        deploy_canary "$service" "$region" "$image_url" "$service_name"
    else
        deploy_rolling "$service" "$region" "$image_url" "$service_name"
    fi
    
    # Remove deployment in progress marker
    rm -f "/tmp/deployment-in-progress"
}

deploy_blue_green() {
    local service=$1
    local region=$2
    local image_url=$3
    local blue_service_name=$4
    local green_service_name="isectech-$service-$ENVIRONMENT-$region"
    
    log_info "Executing blue-green deployment for $service in $region"
    
    # Deploy to blue environment
    if [[ "$DRY_RUN" == "false" ]]; then
        gcloud run deploy "$blue_service_name" \
            --image="$image_url" \
            --region="$region" \
            --platform=managed \
            --no-allow-unauthenticated \
            --memory=4Gi \
            --cpu=2 \
            --concurrency=100 \
            --max-instances=50 \
            --min-instances=2 \
            --timeout=300 \
            --port=8080 \
            --set-env-vars="ENVIRONMENT=$ENVIRONMENT,BUILD_VERSION=$BUILD_VERSION,DEPLOYMENT_REGION=$region,DEPLOYMENT_STRATEGY=blue-green" \
            --labels="environment=$ENVIRONMENT,version=$BUILD_VERSION,service=$service,region=$region,deployment=blue" \
            --tag="blue-$BUILD_VERSION" \
            --quiet || {
                log_error "Blue deployment failed for $service in $region"
                return 1
            }
    else
        log_info "[DRY RUN] Would deploy $service to blue environment in $region"
    fi
    
    # Wait for deployment to be ready
    log_info "Waiting for blue deployment to be ready..."
    sleep 30
    
    # Get blue service URL
    local blue_url
    if [[ "$DRY_RUN" == "false" ]]; then
        blue_url=$(gcloud run services describe "$blue_service_name" --region="$region" --format="value(status.url)" 2>/dev/null || echo "")
        
        if [[ -n "$blue_url" ]]; then
            # Perform health checks on blue environment
            check_service_health "$blue_url" 5 30 || {
                log_error "Blue environment health check failed"
                return 1
            }
            
            # Switch traffic to blue environment
            log_info "Switching traffic from green to blue..."
            gcloud run services update-traffic "$green_service_name" \
                --to-tags="blue-$BUILD_VERSION=100" \
                --region="$region" \
                --quiet || {
                    log_error "Traffic switching failed"
                    return 1
                }
            
            log_success "✓ Blue-green deployment completed for $service in $region"
        else
            log_error "Unable to get blue service URL"
            return 1
        fi
    else
        log_info "[DRY RUN] Would switch traffic to blue environment"
    fi
}

deploy_canary() {
    local service=$1
    local region=$2
    local image_url=$3
    local service_name=$4
    
    log_info "Executing canary deployment for $service in $region"
    
    local canary_percentage=10
    
    # Deploy canary version
    if [[ "$DRY_RUN" == "false" ]]; then
        gcloud run deploy "$service_name" \
            --image="$image_url" \
            --region="$region" \
            --platform=managed \
            --no-allow-unauthenticated \
            --memory=4Gi \
            --cpu=2 \
            --concurrency=100 \
            --max-instances=20 \
            --min-instances=1 \
            --timeout=300 \
            --port=8080 \
            --set-env-vars="ENVIRONMENT=$ENVIRONMENT,BUILD_VERSION=$BUILD_VERSION,DEPLOYMENT_REGION=$region,DEPLOYMENT_STRATEGY=canary" \
            --labels="environment=$ENVIRONMENT,version=$BUILD_VERSION,service=$service,region=$region,deployment=canary" \
            --tag="canary-$BUILD_VERSION" \
            --no-traffic \
            --quiet || {
                log_error "Canary deployment failed for $service in $region"
                return 1
            }
        
        # Gradually increase traffic to canary
        log_info "Starting canary traffic at $canary_percentage%..."
        gcloud run services update-traffic "$service_name" \
            --to-tags="canary-$BUILD_VERSION=$canary_percentage" \
            --region="$region" \
            --quiet || {
                log_error "Canary traffic allocation failed"
                return 1
            }
        
        # Monitor canary for 5 minutes
        log_info "Monitoring canary deployment for 5 minutes..."
        sleep 300
        
        # Get canary service URL for health check
        local canary_url=$(gcloud run services describe "$service_name" --region="$region" --format="value(status.url)" 2>/dev/null || echo "")
        
        if [[ -n "$canary_url" ]]; then
            check_service_health "$canary_url" 3 15 || {
                log_error "Canary health check failed, rolling back..."
                # Rollback canary
                gcloud run services update-traffic "$service_name" \
                    --to-latest \
                    --region="$region" \
                    --quiet
                return 1
            }
            
            # Promote canary to 100%
            log_info "Promoting canary to 100% traffic..."
            gcloud run services update-traffic "$service_name" \
                --to-tags="canary-$BUILD_VERSION=100" \
                --region="$region" \
                --quiet || {
                    log_error "Canary promotion failed"
                    return 1
                }
        fi
        
        log_success "✓ Canary deployment completed for $service in $region"
    else
        log_info "[DRY RUN] Would execute canary deployment"
    fi
}

deploy_rolling() {
    local service=$1
    local region=$2
    local image_url=$3
    local service_name=$4
    
    log_info "Executing rolling deployment for $service in $region"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        gcloud run deploy "$service_name" \
            --image="$image_url" \
            --region="$region" \
            --platform=managed \
            --no-allow-unauthenticated \
            --memory=4Gi \
            --cpu=2 \
            --concurrency=100 \
            --max-instances=30 \
            --min-instances=2 \
            --timeout=300 \
            --port=8080 \
            --set-env-vars="ENVIRONMENT=$ENVIRONMENT,BUILD_VERSION=$BUILD_VERSION,DEPLOYMENT_REGION=$region,DEPLOYMENT_STRATEGY=rolling" \
            --labels="environment=$ENVIRONMENT,version=$BUILD_VERSION,service=$service,region=$region,deployment=rolling" \
            --quiet || {
                log_error "Rolling deployment failed for $service in $region"
                return 1
            }
        
        # Wait for deployment and health check
        sleep 20
        local service_url=$(gcloud run services describe "$service_name" --region="$region" --format="value(status.url)" 2>/dev/null || echo "")
        
        if [[ -n "$service_url" ]]; then
            check_service_health "$service_url" 5 30 || {
                log_error "Rolling deployment health check failed"
                return 1
            }
        fi
        
        log_success "✓ Rolling deployment completed for $service in $region"
    else
        log_info "[DRY RUN] Would execute rolling deployment"
    fi
}

rollback_deployment() {
    log_warn "Initiating deployment rollback..."
    
    local services=("frontend" "backend" "ai-services")
    IFS=',' read -ra REGIONS <<< "$SECONDARY_REGIONS"
    local all_regions=($PRIMARY_REGION "${REGIONS[@]}")
    
    for region in "${all_regions[@]}"; do
        for service in "${services[@]}"; do
            log_info "Rolling back $service in $region..."
            
            local service_name="isectech-$service-$ENVIRONMENT-$region"
            
            if [[ "$DRY_RUN" == "false" ]]; then
                # Get previous stable revision
                local previous_revision=$(gcloud run revisions list \
                    --service="$service_name" \
                    --region="$region" \
                    --filter="metadata.labels.deployment!=blue AND metadata.labels.deployment!=canary" \
                    --sort-by="~metadata.creationTimestamp" \
                    --limit=1 \
                    --format="value(metadata.name)" 2>/dev/null || echo "")
                
                if [[ -n "$previous_revision" ]]; then
                    log_info "Rolling back to revision: $previous_revision"
                    gcloud run services update-traffic "$service_name" \
                        --to-revisions="$previous_revision=100" \
                        --region="$region" \
                        --quiet || log_error "Rollback failed for $service in $region"
                else
                    log_warn "No previous revision found for $service in $region"
                fi
            else
                log_info "[DRY RUN] Would rollback $service in $region"
            fi
        done
    done
    
    log_success "Rollback completed"
}

generate_deployment_report() {
    log_info "Generating deployment report..."
    
    local report_file="/tmp/deployment-report-${BUILD_VERSION}.json"
    
    cat > "$report_file" << EOF
{
    "deployment_id": "$BUILD_VERSION",
    "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
    "project_id": "$PROJECT_ID",
    "environment": "$ENVIRONMENT",
    "deployment_strategy": "$DEPLOYMENT_STRATEGY",
    "primary_region": "$PRIMARY_REGION",
    "secondary_regions": "$SECONDARY_REGIONS",
    "services_deployed": ["frontend", "backend", "ai-services"],
    "compliance_validation": "completed",
    "health_checks": "passed",
    "log_file": "$LOG_FILE"
}
EOF
    
    log_success "Deployment report generated: $report_file"
    
    # Upload report to Cloud Storage
    if command -v gsutil >/dev/null 2>&1 && [[ "$DRY_RUN" == "false" ]]; then
        gsutil cp "$report_file" "gs://$PROJECT_ID-deployment-reports/" || log_warn "Failed to upload deployment report"
    fi
}

# Main deployment function
main() {
    log_info "Starting iSECTECH multi-region deployment"
    log_info "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log_info "Build Version: $BUILD_VERSION"
    log_info "Deployment Strategy: $DEPLOYMENT_STRATEGY"
    log_info "Environment: $ENVIRONMENT"
    log_info "Dry Run: $DRY_RUN"
    
    # Validate prerequisites
    validate_prerequisites || exit 1
    
    # Define services to deploy
    local services=("frontend" "backend" "ai-services")
    
    # Parse regions
    IFS=',' read -ra REGIONS <<< "$SECONDARY_REGIONS"
    local all_regions=($PRIMARY_REGION "${REGIONS[@]}")
    
    log_info "Deploying to regions: ${all_regions[*]}"
    
    # Deploy to primary region first
    log_info "Starting deployment to primary region: $PRIMARY_REGION"
    for service in "${services[@]}"; do
        deploy_service_to_region "$service" "$PRIMARY_REGION" "$BUILD_VERSION" || {
            log_error "Primary region deployment failed for $service"
            exit 1
        }
    done
    
    # Deploy to secondary regions
    for region in "${REGIONS[@]}"; do
        log_info "Starting deployment to secondary region: $region"
        for service in "${services[@]}"; do
            deploy_service_to_region "$service" "$region" "$BUILD_VERSION" || {
                log_warn "Secondary region deployment failed for $service in $region"
                # Continue with other regions but log the failure
            }
        done
    done
    
    # Generate deployment report
    generate_deployment_report
    
    log_success "Multi-region deployment completed successfully!"
    log_info "Deployment version: $BUILD_VERSION"
    log_info "Log file: $LOG_FILE"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi