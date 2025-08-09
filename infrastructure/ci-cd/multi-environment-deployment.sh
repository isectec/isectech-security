#!/bin/bash

# iSECTECH Multi-Environment Deployment Manager
# Handles deployment promotion across development, staging, and production environments
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ARTIFACT_REGISTRY="${PROJECT_ID}-docker-repo"
BUILD_VERSION="${BUILD_VERSION:-latest}"
GIT_COMMIT="${GIT_COMMIT:-unknown}"

# Environment configurations
declare -A ENVIRONMENT_CONFIGS=(
    ["development"]="min-instances=0,max-instances=3,memory=1Gi,cpu=1,concurrency=10,timeout=60"
    ["staging"]="min-instances=1,max-instances=5,memory=2Gi,cpu=2,concurrency=50,timeout=300"
    ["production"]="min-instances=2,max-instances=20,memory=4Gi,cpu=4,concurrency=100,timeout=600"
)

# Service definitions with specific configurations
declare -A SERVICE_CONFIGS=(
    ["frontend"]="port=80,health=/health,memory_override=512Mi"
    ["api-gateway"]="port=8080,health=/health,cpu_override=2"
    ["auth-service"]="port=8080,health=/health,security=high"
    ["asset-discovery"]="port=8080,health=/ready,cpu_override=4"
    ["event-processor"]="port=8080,health=/health,memory_override=8Gi"
    ["threat-detection"]="port=8080,health=/health,cpu_override=4,memory_override=8Gi"
    ["behavioral-analysis"]="port=8000,health=/health,memory_override=4Gi"
    ["decision-engine"]="port=8000,health=/health,cpu_override=2"
    ["nlp-assistant"]="port=8000,health=/health,memory_override=6Gi"
)

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

# Parse service configuration
parse_service_config() {
    local service="$1"
    local config="${SERVICE_CONFIGS[$service]:-}"
    
    # Default values
    PORT="8080"
    HEALTH_PATH="/health"
    MEMORY_OVERRIDE=""
    CPU_OVERRIDE=""
    SECURITY_LEVEL="standard"
    
    # Parse configuration string
    IFS=',' read -ra CONFIG_PARTS <<< "$config"
    for part in "${CONFIG_PARTS[@]}"; do
        IFS='=' read -ra KV <<< "$part"
        case "${KV[0]}" in
            "port") PORT="${KV[1]}" ;;
            "health") HEALTH_PATH="${KV[1]}" ;;
            "memory_override") MEMORY_OVERRIDE="${KV[1]}" ;;
            "cpu_override") CPU_OVERRIDE="${KV[1]}" ;;
            "security") SECURITY_LEVEL="${KV[1]}" ;;
        esac
    done
}

# Parse environment configuration
parse_environment_config() {
    local environment="$1"
    local config="${ENVIRONMENT_CONFIGS[$environment]}"
    
    # Parse configuration string
    IFS=',' read -ra CONFIG_PARTS <<< "$config"
    for part in "${CONFIG_PARTS[@]}"; do
        IFS='=' read -ra KV <<< "$part"
        case "${KV[0]}" in
            "min-instances") MIN_INSTANCES="${KV[1]}" ;;
            "max-instances") MAX_INSTANCES="${KV[1]}" ;;
            "memory") DEFAULT_MEMORY="${KV[1]}" ;;
            "cpu") DEFAULT_CPU="${KV[1]}" ;;
            "concurrency") CONCURRENCY="${KV[1]}" ;;
            "timeout") TIMEOUT="${KV[1]}" ;;
        esac
    done
}

# Validate environment
validate_environment() {
    local environment="$1"
    
    if [[ ! "${!ENVIRONMENT_CONFIGS[@]}" =~ $environment ]]; then
        log_error "Invalid environment: $environment"
        log_error "Valid environments: ${!ENVIRONMENT_CONFIGS[*]}"
        exit 1
    fi
    
    log_info "Environment validated: $environment"
}

# Check if image exists in Artifact Registry
check_image_exists() {
    local service="$1"
    local version="$2"
    local image="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REGISTRY}/${service}:${version}"
    
    if gcloud container images describe "$image" --quiet >/dev/null 2>&1; then
        log_success "Image exists: $image"
        return 0
    else
        log_error "Image not found: $image"
        return 1
    fi
}

# Deploy service to Cloud Run
deploy_service() {
    local service="$1"
    local environment="$2"
    local version="$3"
    
    log_info "Deploying $service to $environment environment (version: $version)"
    
    # Parse configurations
    parse_service_config "$service"
    parse_environment_config "$environment"
    
    # Override with service-specific configurations
    MEMORY="${MEMORY_OVERRIDE:-$DEFAULT_MEMORY}"
    CPU="${CPU_OVERRIDE:-$DEFAULT_CPU}"
    
    # Construct service name
    SERVICE_NAME="isectech-${service}-${environment}"
    IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REGISTRY}/${service}:${version}"
    
    # Check if image exists
    if ! check_image_exists "$service" "$version"; then
        log_error "Cannot deploy $service: image not found"
        return 1
    fi
    
    # Prepare environment variables
    ENV_VARS="ENVIRONMENT=${environment},BUILD_VERSION=${version},GIT_COMMIT=${GIT_COMMIT},SERVICE_NAME=${service}"
    
    # Add environment-specific variables
    case "$environment" in
        "production")
            ENV_VARS="${ENV_VARS},LOG_LEVEL=info,METRICS_ENABLED=true,TRACING_ENABLED=true"
            ;;
        "staging")
            ENV_VARS="${ENV_VARS},LOG_LEVEL=debug,METRICS_ENABLED=true,TRACING_ENABLED=true"
            ;;
        "development")
            ENV_VARS="${ENV_VARS},LOG_LEVEL=debug,METRICS_ENABLED=false,TRACING_ENABLED=false"
            ;;
    esac
    
    # Security configurations
    ALLOW_UNAUTHENTICATED="--allow-unauthenticated"
    if [ "$SECURITY_LEVEL" = "high" ]; then
        ALLOW_UNAUTHENTICATED="--no-allow-unauthenticated"
    fi
    
    # Deploy to Cloud Run
    gcloud run deploy "$SERVICE_NAME" \
        --image="$IMAGE" \
        --region="$REGION" \
        --platform=managed \
        $ALLOW_UNAUTHENTICATED \
        --memory="$MEMORY" \
        --cpu="$CPU" \
        --concurrency="$CONCURRENCY" \
        --max-instances="$MAX_INSTANCES" \
        --min-instances="$MIN_INSTANCES" \
        --timeout="${TIMEOUT}s" \
        --port="$PORT" \
        --set-env-vars="$ENV_VARS" \
        --labels="environment=${environment},version=${version},service=${service},security=${SECURITY_LEVEL}" \
        --tag="version-${version}" \
        --revision-suffix="v${version//[^a-zA-Z0-9]/-}" \
        --execution-environment=gen2 \
        --cpu-boost \
        --session-affinity
    
    # Configure traffic allocation for production
    if [ "$environment" = "production" ]; then
        log_info "Configuring traffic allocation for production deployment"
        
        # Get current revision
        CURRENT_REVISION=$(gcloud run revisions list \
            --service="$SERVICE_NAME" \
            --region="$REGION" \
            --limit=1 \
            --format="value(metadata.name)")
        
        # Gradual traffic rollout (Blue/Green deployment)
        log_info "Starting gradual traffic rollout for $SERVICE_NAME"
        
        # Start with 10% traffic to new revision
        gcloud run services update-traffic "$SERVICE_NAME" \
            --to-revisions="$CURRENT_REVISION=10" \
            --region="$REGION"
        
        log_info "10% traffic allocated to new revision. Monitor for 5 minutes..."
        sleep 300
        
        # Check health and gradually increase traffic
        if validate_service_health "$SERVICE_NAME" "$environment"; then
            # Increase to 50%
            gcloud run services update-traffic "$SERVICE_NAME" \
                --to-revisions="$CURRENT_REVISION=50" \
                --region="$REGION"
            
            log_info "50% traffic allocated. Monitor for 3 minutes..."
            sleep 180
            
            if validate_service_health "$SERVICE_NAME" "$environment"; then
                # Full traffic
                gcloud run services update-traffic "$SERVICE_NAME" \
                    --to-latest \
                    --region="$REGION"
                
                log_success "100% traffic allocated to new revision"
            else
                log_error "Health check failed at 50% traffic. Initiating rollback..."
                rollback_service "$service" "$environment"
                return 1
            fi
        else
            log_error "Health check failed at 10% traffic. Initiating rollback..."
            rollback_service "$service" "$environment"
            return 1
        fi
    fi
    
    log_success "Successfully deployed $service to $environment"
    return 0
}

# Validate service health
validate_service_health() {
    local service_name="$1"
    local environment="$2"
    local max_attempts=5
    local attempt=1
    
    log_info "Validating health of $service_name"
    
    # Get service URL
    SERVICE_URL=$(gcloud run services describe "$service_name" \
        --region="$REGION" \
        --format="value(status.url)")
    
    if [ -z "$SERVICE_URL" ]; then
        log_error "Could not retrieve service URL for $service_name"
        return 1
    fi
    
    # Parse service config to get health path
    local service=${service_name#isectech-}
    service=${service%-*}
    parse_service_config "$service"
    
    # Health check with retries
    while [ $attempt -le $max_attempts ]; do
        log_info "Health check attempt $attempt/$max_attempts for $service_name"
        
        if curl -f -s --max-time 30 "${SERVICE_URL}${HEALTH_PATH}" >/dev/null; then
            log_success "Health check passed for $service_name"
            return 0
        else
            log_warning "Health check failed for $service_name (attempt $attempt/$max_attempts)"
            attempt=$((attempt + 1))
            sleep 10
        fi
    done
    
    log_error "Health check failed for $service_name after $max_attempts attempts"
    return 1
}

# Rollback service to previous version
rollback_service() {
    local service="$1"
    local environment="$2"
    
    local service_name="isectech-${service}-${environment}"
    
    log_warning "Initiating rollback for $service_name"
    
    # Get previous revision
    PREVIOUS_REVISION=$(gcloud run revisions list \
        --service="$service_name" \
        --region="$REGION" \
        --limit=2 \
        --format="value(metadata.name)" | tail -n 1)
    
    if [ -n "$PREVIOUS_REVISION" ]; then
        log_info "Rolling back to previous revision: $PREVIOUS_REVISION"
        
        # Immediate rollback to previous revision
        gcloud run services update-traffic "$service_name" \
            --to-revisions="$PREVIOUS_REVISION=100" \
            --region="$REGION"
        
        log_success "Rollback completed for $service_name"
        
        # Validate rollback
        if validate_service_health "$service_name" "$environment"; then
            log_success "Rollback validation successful"
        else
            log_error "Rollback validation failed - manual intervention required"
        fi
    else
        log_error "No previous revision found for rollback"
    fi
}

# Deploy all services to an environment
deploy_all_services() {
    local environment="$1"
    local version="$2"
    
    log_info "Deploying all services to $environment environment"
    
    # Define deployment order (dependencies first)
    local services=(
        "auth-service"
        "api-gateway"
        "asset-discovery"
        "event-processor"
        "threat-detection"
        "behavioral-analysis"
        "decision-engine"
        "nlp-assistant"
        "frontend"
    )
    
    local failed_services=()
    
    # Deploy services in order
    for service in "${services[@]}"; do
        if deploy_service "$service" "$environment" "$version"; then
            log_success "✓ $service deployed successfully"
        else
            log_error "✗ $service deployment failed"
            failed_services+=("$service")
        fi
        
        # Wait between deployments to avoid resource conflicts
        sleep 10
    done
    
    # Report results
    if [ ${#failed_services[@]} -eq 0 ]; then
        log_success "All services deployed successfully to $environment"
        return 0
    else
        log_error "The following services failed to deploy: ${failed_services[*]}"
        return 1
    fi
}

# Environment promotion workflow
promote_environment() {
    local from_env="$1"
    local to_env="$2"
    local version="$3"
    
    log_info "Promoting from $from_env to $to_env (version: $version)"
    
    # Validate source environment health
    log_info "Validating source environment health..."
    
    local services=(
        "auth-service"
        "api-gateway"
        "asset-discovery"
        "event-processor"
        "threat-detection"
        "behavioral-analysis"
        "decision-engine"
        "nlp-assistant"
        "frontend"
    )
    
    local unhealthy_services=()
    
    for service in "${services[@]}"; do
        local service_name="isectech-${service}-${from_env}"
        if ! validate_service_health "$service_name" "$from_env"; then
            unhealthy_services+=("$service")
        fi
    done
    
    if [ ${#unhealthy_services[@]} -gt 0 ]; then
        log_error "Cannot promote: unhealthy services in $from_env: ${unhealthy_services[*]}"
        return 1
    fi
    
    log_success "Source environment validation passed"
    
    # Perform promotion
    if deploy_all_services "$to_env" "$version"; then
        log_success "Environment promotion from $from_env to $to_env completed successfully"
        
        # Generate promotion report
        generate_promotion_report "$from_env" "$to_env" "$version"
        
        return 0
    else
        log_error "Environment promotion failed"
        return 1
    fi
}

# Generate promotion report
generate_promotion_report() {
    local from_env="$1"
    local to_env="$2"
    local version="$3"
    
    local report_file="/tmp/promotion-report-${to_env}-${version}-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$report_file" << EOF
{
  "promotion_id": "$(uuidgen)",
  "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "source_environment": "$from_env",
  "target_environment": "$to_env",
  "version": "$version",
  "git_commit": "$GIT_COMMIT",
  "project_id": "$PROJECT_ID",
  "region": "$REGION",
  "services": [
    "auth-service",
    "api-gateway",
    "asset-discovery",
    "event-processor",
    "threat-detection",
    "behavioral-analysis",
    "decision-engine",
    "nlp-assistant",
    "frontend"
  ],
  "deployment_strategy": "blue_green",
  "health_validation": "passed",
  "rollback_capability": "enabled"
}
EOF
    
    log_success "Promotion report generated: $report_file"
}

# Show help
show_help() {
    cat << EOF
iSECTECH Multi-Environment Deployment Manager

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    deploy SERVICE ENVIRONMENT VERSION     Deploy a specific service
    deploy-all ENVIRONMENT VERSION         Deploy all services to environment
    promote FROM_ENV TO_ENV VERSION        Promote deployment between environments
    rollback SERVICE ENVIRONMENT           Rollback service to previous version
    health SERVICE ENVIRONMENT             Check service health
    
Environments:
    development     Development environment (minimal resources)
    staging         Staging environment (production-like)
    production      Production environment (full resources)

Services:
    frontend, api-gateway, auth-service, asset-discovery,
    event-processor, threat-detection, behavioral-analysis,
    decision-engine, nlp-assistant

Examples:
    # Deploy single service
    $0 deploy auth-service staging v1.2.3
    
    # Deploy all services
    $0 deploy-all production v1.2.3
    
    # Promote from staging to production
    $0 promote staging production v1.2.3
    
    # Check service health
    $0 health api-gateway production
    
    # Rollback service
    $0 rollback frontend production

Environment Variables:
    PROJECT_ID              Google Cloud project ID
    REGION                 Google Cloud region
    BUILD_VERSION          Build version to deploy
    GIT_COMMIT             Git commit hash

EOF
}

# Main execution
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        "deploy")
            if [ $# -ne 3 ]; then
                log_error "Usage: $0 deploy SERVICE ENVIRONMENT VERSION"
                exit 1
            fi
            validate_environment "$2"
            deploy_service "$1" "$2" "$3"
            ;;
        "deploy-all")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 deploy-all ENVIRONMENT VERSION"
                exit 1
            fi
            validate_environment "$1"
            deploy_all_services "$1" "$2"
            ;;
        "promote")
            if [ $# -ne 3 ]; then
                log_error "Usage: $0 promote FROM_ENV TO_ENV VERSION"
                exit 1
            fi
            validate_environment "$1"
            validate_environment "$2"
            promote_environment "$1" "$2" "$3"
            ;;
        "rollback")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 rollback SERVICE ENVIRONMENT"
                exit 1
            fi
            validate_environment "$2"
            rollback_service "$1" "$2"
            ;;
        "health")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 health SERVICE ENVIRONMENT"
                exit 1
            fi
            validate_environment "$2"
            service_name="isectech-$1-$2"
            validate_service_health "$service_name" "$2"
            ;;
        "help")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"