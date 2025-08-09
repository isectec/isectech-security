#!/bin/bash

# iSECTECH API Gateway Build and Deploy Script
# Production-grade build and deployment automation
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

# Default configuration
PROJECT_ID=${PROJECT_ID:-""}
ENVIRONMENT=${ENVIRONMENT:-"development"}
REGION=${REGION:-"us-central1"}
SERVICE_NAME="api-gateway"
IMAGE_NAME="isectech-api-gateway"
VERSION=${VERSION:-"latest"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
}

# Banner function
print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    iSECTECH API Gateway Build & Deploy                       ║"
    echo "║                        Production-Grade Container Build                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Usage function
show_usage() {
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo ""
    echo "Commands:"
    echo "  build                        Build Docker image"
    echo "  push                         Push image to Artifact Registry"
    echo "  deploy                       Deploy to Cloud Run"
    echo "  build-push-deploy           Build, push, and deploy (full pipeline)"
    echo "  local                       Start local development environment"
    echo ""
    echo "Options:"
    echo "  -p, --project-id PROJECT_ID  Google Cloud Project ID (required)"
    echo "  -e, --environment ENV        Environment (development, staging, production)"
    echo "  -r, --region REGION          Google Cloud region (default: us-central1)"
    echo "  -v, --version VERSION        Image version tag (default: latest)"
    echo "  -h, --help                   Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  PROJECT_ID                   Google Cloud Project ID"
    echo "  ENVIRONMENT                  Environment name"
    echo "  REGION                       Google Cloud region"
    echo "  VERSION                      Image version tag"
    echo ""
    echo "Examples:"
    echo "  $0 -p isectech-prod -e production build"
    echo "  $0 --project-id isectech-dev --environment development build-push-deploy"
    echo "  export PROJECT_ID=isectech-staging && $0 deploy"
}

# Validation functions
validate_prerequisites() {
    log "Validating prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check gcloud CLI
    if ! command -v gcloud &> /dev/null; then
        error "Google Cloud CLI is not installed or not in PATH"
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -n1 | grep -q .; then
        error "Not authenticated with Google Cloud. Run: gcloud auth login"
        exit 1
    fi
    
    success "Prerequisites validation completed"
}

validate_configuration() {
    log "Validating configuration..."
    
    if [ -z "$PROJECT_ID" ]; then
        error "PROJECT_ID is required. Set via environment variable or use -p flag"
        show_usage
        exit 1
    fi
    
    # Validate project ID format
    if ! [[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
        error "Invalid PROJECT_ID format. Must be 6-30 characters, lowercase letters, numbers, and hyphens."
        exit 1
    fi
    
    # Validate environment
    if [[ ! "$ENVIRONMENT" =~ ^(development|staging|production)$ ]]; then
        error "Invalid ENVIRONMENT. Must be one of: development, staging, production"
        exit 1
    fi
    
    success "Configuration validation completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

build_image() {
    log "Building Docker image for $ENVIRONMENT environment..."
    
    local image_tag
    local registry_url
    
    # Determine repository based on environment
    case $ENVIRONMENT in
        "production")
            registry_url="$REGION-docker.pkg.dev/$PROJECT_ID/isectech-production"
            image_tag="prod-$VERSION"
            ;;
        "staging")
            registry_url="$REGION-docker.pkg.dev/$PROJECT_ID/isectech-staging"
            image_tag="staging-$VERSION"
            ;;
        "development")
            registry_url="$REGION-docker.pkg.dev/$PROJECT_ID/isectech-development"
            image_tag="dev-$VERSION"
            ;;
        *)
            registry_url="$REGION-docker.pkg.dev/$PROJECT_ID/isectech-docker"
            image_tag="$VERSION"
            ;;
    esac
    
    local full_image_name="$registry_url/$SERVICE_NAME:$image_tag"
    local latest_tag="$registry_url/$SERVICE_NAME:${ENVIRONMENT}-latest"
    
    log "Building image: $full_image_name"
    
    # Build with build args
    docker build \
        --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --build-arg BUILD_VERSION="$VERSION" \
        --build-arg BUILD_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo 'unknown')" \
        --target runtime \
        -t "$full_image_name" \
        -t "$latest_tag" \
        .
    
    success "Docker image built successfully: $full_image_name"
    
    # Export variables for other functions
    export FULL_IMAGE_NAME="$full_image_name"
    export LATEST_TAG="$latest_tag"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PUSH FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

push_image() {
    log "Pushing Docker image to Artifact Registry..."
    
    if [ -z "${FULL_IMAGE_NAME:-}" ]; then
        error "No image to push. Run build first."
        exit 1
    fi
    
    # Configure Docker authentication
    log "Configuring Docker authentication for Artifact Registry..."
    gcloud auth configure-docker "$REGION-docker.pkg.dev" --quiet
    
    # Push both tags
    log "Pushing image: $FULL_IMAGE_NAME"
    docker push "$FULL_IMAGE_NAME"
    
    log "Pushing latest tag: $LATEST_TAG"
    docker push "$LATEST_TAG"
    
    success "Docker image pushed successfully to Artifact Registry"
    
    # Run vulnerability scan (if in CI/CD environment)
    if [ "${CI:-false}" = "true" ]; then
        scan_vulnerability
    fi
}

scan_vulnerability() {
    log "Running vulnerability scan..."
    
    # Run vulnerability scan
    if gcloud artifacts docker images scan "$FULL_IMAGE_NAME" --format=json > scan-results.json; then
        # Check for critical vulnerabilities
        local critical_count
        critical_count=$(jq '.vulnerabilities[]? | select(.severity=="CRITICAL") | .severity' scan-results.json 2>/dev/null | wc -l || echo "0")
        
        log "Vulnerability scan completed. Critical vulnerabilities: $critical_count"
        
        # For production, fail if too many critical vulnerabilities
        if [ "$ENVIRONMENT" = "production" ] && [ "$critical_count" -gt 5 ]; then
            error "Too many critical vulnerabilities ($critical_count) for production deployment"
            exit 1
        fi
        
        success "Vulnerability scan passed"
    else
        warning "Vulnerability scan failed or not available"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

deploy_to_cloud_run() {
    log "Deploying to Cloud Run..."
    
    if [ -z "${FULL_IMAGE_NAME:-}" ]; then
        error "No image to deploy. Run build and push first."
        exit 1
    fi
    
    local service_name="isectech-api-gateway-${ENVIRONMENT}"
    local memory="1Gi"
    local cpu="1000m"
    local max_instances="100"
    local min_instances="1"
    
    # Environment-specific configuration
    case $ENVIRONMENT in
        "production")
            memory="2Gi"
            cpu="2000m"
            max_instances="100"
            min_instances="3"
            ;;
        "staging")
            memory="1Gi"
            cpu="1000m"
            max_instances="20"
            min_instances="1"
            ;;
        "development")
            memory="512Mi"
            cpu="500m"
            max_instances="5"
            min_instances="0"
            ;;
    esac
    
    log "Deploying Cloud Run service: $service_name"
    
    # Deploy to Cloud Run
    gcloud run deploy "$service_name" \
        --image "$FULL_IMAGE_NAME" \
        --region "$REGION" \
        --platform managed \
        --memory "$memory" \
        --cpu "$cpu" \
        --min-instances "$min_instances" \
        --max-instances "$max_instances" \
        --port 8080 \
        --allow-unauthenticated \
        --set-env-vars "ENVIRONMENT=$ENVIRONMENT" \
        --set-env-vars "LOG_LEVEL=info" \
        --set-env-vars "LOG_FORMAT=json" \
        --set-env-vars "MONITORING_ENABLED=true" \
        --service-account "isectech-api-gateway@$PROJECT_ID.iam.gserviceaccount.com" \
        --vpc-connector "isectech-vpc-connector" \
        --vpc-egress private-ranges-only \
        --execution-environment gen2 \
        --no-cpu-throttling \
        --timeout 300 \
        --quiet
    
    # Get service URL
    local service_url
    service_url=$(gcloud run services describe "$service_name" --region "$REGION" --format 'value(status.url)')
    
    success "Deployment completed successfully!"
    log "Service URL: $service_url"
    
    # Test deployment
    test_deployment "$service_url"
}

test_deployment() {
    local service_url="$1"
    
    log "Testing deployment..."
    
    # Wait for service to be ready
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f -s "$service_url/health" > /dev/null; then
            success "Service is healthy and responding"
            break
        else
            log "Attempt $attempt/$max_attempts: Service not ready yet, waiting..."
            sleep 10
            ((attempt++))
        fi
    done
    
    if [ $attempt -gt $max_attempts ]; then
        error "Service health check failed after $max_attempts attempts"
        exit 1
    fi
    
    # Test endpoints
    log "Testing service endpoints..."
    
    # Health check
    if curl -f -s "$service_url/health" | jq '.status' | grep -q "healthy"; then
        success "Health endpoint: OK"
    else
        warning "Health endpoint: Failed"
    fi
    
    # Metrics endpoint
    if curl -f -s "$service_url/metrics" > /dev/null; then
        success "Metrics endpoint: OK"
    else
        warning "Metrics endpoint: Failed"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL DEVELOPMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

start_local() {
    log "Starting local development environment..."
    
    # Check if Docker Compose is available
    if command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        error "Docker Compose is not available"
        exit 1
    fi
    
    # Start services
    log "Starting services with Docker Compose..."
    $COMPOSE_CMD up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 10
    
    # Check service health
    if curl -f -s "http://localhost:8080/health" > /dev/null; then
        success "Local development environment is ready!"
        echo ""
        echo "Services available at:"
        echo "  API Gateway: http://localhost:8080"
        echo "  Health Check: http://localhost:8080/health"
        echo "  Metrics: http://localhost:8080/metrics"
        echo "  Redis: localhost:6379"
        echo "  PostgreSQL: localhost:5432"
        echo ""
        echo "Use 'docker-compose logs -f api-gateway' to view logs"
        echo "Use 'docker-compose down' to stop services"
    else
        warning "Service may not be fully ready yet. Check logs with: docker-compose logs api-gateway"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    local command=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--project-id)
                PROJECT_ID="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -v|--version)
                VERSION="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            build|push|deploy|build-push-deploy|local)
                command="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check if command is provided
    if [ -z "$command" ]; then
        error "No command specified"
        show_usage
        exit 1
    fi
    
    # Print banner
    print_banner
    
    # Run validations (except for local command)
    if [ "$command" != "local" ]; then
        validate_prerequisites
        validate_configuration
    fi
    
    # Execute command
    case $command in
        "build")
            build_image
            ;;
        "push")
            push_image
            ;;
        "deploy")
            deploy_to_cloud_run
            ;;
        "build-push-deploy")
            build_image
            push_image
            deploy_to_cloud_run
            ;;
        "local")
            start_local
            ;;
        *)
            error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
    
    success "Operation completed successfully!"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi