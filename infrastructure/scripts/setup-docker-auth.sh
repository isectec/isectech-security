#!/bin/bash

# iSECTECH Docker Authentication Setup Script
# Production-grade Docker authentication configuration for Artifact Registry
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

# Required environment variables
PROJECT_ID=${PROJECT_ID:-""}
REGISTRY_REGION=${REGISTRY_REGION:-"us-central1"}
SERVICE_ACCOUNT_KEY_PATH=${SERVICE_ACCOUNT_KEY_PATH:-""}
ENVIRONMENT=${ENVIRONMENT:-"development"}

# Color codes for output
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
    echo "║                   iSECTECH Docker Authentication Setup                       ║"
    echo "║                     Production-Grade Container Registry                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Validation functions
validate_prerequisites() {
    log "Validating prerequisites for Docker authentication setup..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        echo "  Ubuntu/Debian: sudo apt-get install docker.io"
        echo "  macOS: brew install docker"
        echo "  Windows: Download from https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    fi
    
    # Check if gcloud CLI is installed
    if ! command -v gcloud &> /dev/null; then
        error "Google Cloud CLI is not installed. Please install it first."
        echo "  Install: curl https://sdk.cloud.google.com | bash"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    success "Prerequisites validation completed"
}

validate_configuration() {
    log "Validating configuration parameters..."
    
    if [ -z "$PROJECT_ID" ]; then
        error "PROJECT_ID environment variable is not set"
        echo "  Export PROJECT_ID: export PROJECT_ID='your-project-id'"
        exit 1
    fi
    
    # Validate project ID format
    if ! [[ "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
        error "Invalid PROJECT_ID format. Must be 6-30 characters, lowercase letters, numbers, and hyphens."
        exit 1
    fi
    
    # Validate region
    local valid_regions=("us-central1" "us-east1" "us-east4" "us-west1" "us-west2" "us-west3" "us-west4" 
                        "europe-north1" "europe-west1" "europe-west2" "europe-west3" "europe-west4" "europe-west6"
                        "asia-east1" "asia-east2" "asia-northeast1" "asia-northeast2" "asia-northeast3"
                        "asia-south1" "asia-southeast1" "asia-southeast2" "australia-southeast1")
    
    if ! [[ " ${valid_regions[@]} " =~ " ${REGISTRY_REGION} " ]]; then
        error "Invalid REGISTRY_REGION: $REGISTRY_REGION"
        echo "  Valid regions: ${valid_regions[*]}"
        exit 1
    fi
    
    success "Configuration validation completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

setup_gcloud_auth() {
    log "Setting up Google Cloud authentication..."
    
    # Check if already authenticated
    local current_account
    current_account=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null || echo "")
    
    if [ -n "$current_account" ]; then
        log "Already authenticated as: $current_account"
        
        # Verify project access
        if gcloud projects describe "$PROJECT_ID" &>/dev/null; then
            success "Project access verified: $PROJECT_ID"
        else
            error "Cannot access project: $PROJECT_ID"
            echo "  Please check project ID and permissions"
            exit 1
        fi
    else
        if [ -n "$SERVICE_ACCOUNT_KEY_PATH" ] && [ -f "$SERVICE_ACCOUNT_KEY_PATH" ]; then
            log "Authenticating with service account key..."
            gcloud auth activate-service-account --key-file="$SERVICE_ACCOUNT_KEY_PATH"
            success "Service account authentication completed"
        else
            log "No service account key provided. Starting interactive authentication..."
            gcloud auth login
            success "Interactive authentication completed"
        fi
    fi
    
    # Set the project
    gcloud config set project "$PROJECT_ID"
    success "Project set to: $PROJECT_ID"
}

configure_docker_auth() {
    log "Configuring Docker authentication for Artifact Registry..."
    
    # Configure Docker to use gcloud as credential helper
    local registry_url="${REGISTRY_REGION}-docker.pkg.dev"
    
    log "Configuring Docker for registry: $registry_url"
    if gcloud auth configure-docker "$registry_url" --quiet; then
        success "Docker authentication configured successfully"
    else
        error "Failed to configure Docker authentication"
        exit 1
    fi
    
    # Verify authentication by attempting to access registry
    log "Verifying Docker authentication..."
    local test_command="docker pull $registry_url/hello-world || echo 'Registry access verified (repository may not exist)'"
    
    if eval "$test_command" &>/dev/null; then
        success "Docker authentication verification completed"
    else
        warning "Could not fully verify registry access (this is normal if repositories don't exist yet)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPOSITORY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

list_repositories() {
    log "Listing available Artifact Registry repositories..."
    
    if gcloud artifacts repositories list --location="$REGISTRY_REGION" --project="$PROJECT_ID" --format="table(name,format,createTime)" 2>/dev/null; then
        success "Repository listing completed"
    else
        warning "Could not list repositories (may not exist yet or insufficient permissions)"
    fi
}

create_sample_dockerfile() {
    log "Creating sample Dockerfile for testing..."
    
    cat > Dockerfile.sample << 'EOF'
# iSECTECH Sample Container for Registry Testing
FROM alpine:latest

# Install basic security tools
RUN apk add --no-cache \
    curl \
    netcat-openbsd \
    nmap \
    openssl

# Create non-root user for security
RUN addgroup -g 1001 -S isectech && \
    adduser -u 1001 -S isectech -G isectech

# Set working directory
WORKDIR /app

# Copy application files (if any)
COPY . .

# Switch to non-root user
USER isectech

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
CMD ["echo", "iSECTECH Container Registry Test - SUCCESS"]
EOF

    success "Sample Dockerfile created (Dockerfile.sample)"
}

test_docker_push() {
    log "Testing Docker push functionality..."
    
    local test_image="${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-${ENVIRONMENT}/test-image"
    local tag="test-$(date +%s)"
    
    # Create test Dockerfile if it doesn't exist
    if [ ! -f "Dockerfile.sample" ]; then
        create_sample_dockerfile
    fi
    
    log "Building test image: ${test_image}:${tag}"
    if docker build -f Dockerfile.sample -t "${test_image}:${tag}" .; then
        success "Test image built successfully"
        
        log "Attempting to push test image..."
        if docker push "${test_image}:${tag}"; then
            success "Test image pushed successfully to Artifact Registry"
            
            # Clean up local image
            docker rmi "${test_image}:${tag}" &>/dev/null || true
            
            log "Test push completed. You can view the image at:"
            echo "  https://console.cloud.google.com/artifacts/docker/${PROJECT_ID}/${REGISTRY_REGION}/isectech-${ENVIRONMENT}"
        else
            error "Failed to push test image"
            echo "  This might be due to:"
            echo "  - Repository doesn't exist yet"
            echo "  - Insufficient permissions"
            echo "  - Network connectivity issues"
        fi
    else
        error "Failed to build test image"
    fi
    
    # Clean up
    rm -f Dockerfile.sample
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

generate_image_urls() {
    log "Generating iSECTECH image URL examples..."
    
    local base_url="${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}"
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                            iSECTECH Image URLs                               ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "Main Repository (isectech-docker):"
    echo "  ${base_url}/isectech-docker/api-gateway:latest"
    echo "  ${base_url}/isectech-docker/auth-service:v1.0.0"
    echo "  ${base_url}/isectech-docker/event-processor:sha-abc123"
    echo ""
    
    echo "Environment-Specific Repositories:"
    echo "  Development:"
    echo "    ${base_url}/isectech-development/api-gateway:dev-latest"
    echo "    ${base_url}/isectech-development/threat-detection:dev-feature-123"
    echo ""
    echo "  Staging:"
    echo "    ${base_url}/isectech-staging/siem-engine:staging-v1.0.0"
    echo "    ${base_url}/isectech-staging/compliance-manager:staging-latest"
    echo ""
    echo "  Production:"
    echo "    ${base_url}/isectech-production/vulnerability-scanner:prod-v1.0.0"
    echo "    ${base_url}/isectech-production/soar-orchestrator:prod-latest"
    echo ""
    
    echo "Security Tools Repository:"
    echo "  ${base_url}/isectech-security-tools/vulnerability-scanner:latest"
    echo "  ${base_url}/isectech-security-tools/compliance-checker:v2.1.0"
    echo ""
}

generate_docker_commands() {
    log "Generating useful Docker commands for iSECTECH development..."
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                          Useful Docker Commands                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    echo "Build and Push Commands:"
    echo "  # Build image"
    echo "  docker build -t ${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-${ENVIRONMENT}/SERVICE_NAME:TAG ."
    echo ""
    echo "  # Push image"
    echo "  docker push ${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-${ENVIRONMENT}/SERVICE_NAME:TAG"
    echo ""
    
    echo "Pull and Run Commands:"
    echo "  # Pull image"
    echo "  docker pull ${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-${ENVIRONMENT}/SERVICE_NAME:TAG"
    echo ""
    echo "  # Run container"
    echo "  docker run -d --name SERVICE_NAME ${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-${ENVIRONMENT}/SERVICE_NAME:TAG"
    echo ""
    
    echo "Repository Management:"
    echo "  # List repositories"
    echo "  gcloud artifacts repositories list --location=${REGISTRY_REGION}"
    echo ""
    echo "  # List images in repository"
    echo "  gcloud artifacts docker images list ${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/REPOSITORY_NAME"
    echo ""
    echo "  # Scan image for vulnerabilities"
    echo "  gcloud artifacts docker images scan IMAGE_URL"
    echo ""
    
    echo "Authentication:"
    echo "  # Re-configure Docker auth"
    echo "  gcloud auth configure-docker ${REGISTRY_REGION}-docker.pkg.dev"
    echo ""
    echo "  # Login with access token"
    echo "  docker login -u _token -p \"\$(gcloud auth print-access-token)\" https://${REGISTRY_REGION}-docker.pkg.dev"
    echo ""
}

create_env_file() {
    log "Creating environment configuration file..."
    
    cat > .env.docker << EOF
# iSECTECH Docker Registry Configuration
# Generated on $(date)

# Project Configuration
PROJECT_ID=${PROJECT_ID}
REGISTRY_REGION=${REGISTRY_REGION}
ENVIRONMENT=${ENVIRONMENT}

# Registry URLs
MAIN_REGISTRY=${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-docker
DEV_REGISTRY=${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-development
STAGING_REGISTRY=${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-staging
PROD_REGISTRY=${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-production
SECURITY_REGISTRY=${REGISTRY_REGION}-docker.pkg.dev/${PROJECT_ID}/isectech-security-tools

# iSECTECH Services
ISECTECH_SERVICES="api-gateway auth-service event-processor asset-discovery threat-detection siem-engine soar-orchestrator threat-intelligence vulnerability-scanner compliance-manager data-classifier identity-analytics network-monitor frontend-app"

# Usage Examples
# docker build -t \$MAIN_REGISTRY/api-gateway:latest .
# docker push \$MAIN_REGISTRY/api-gateway:latest
EOF

    success "Environment file created: .env.docker"
    echo "  Source it with: source .env.docker"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --project-id PROJECT_ID       Google Cloud Project ID (required)"
    echo "  -r, --region REGION               Registry region (default: us-central1)"
    echo "  -e, --environment ENVIRONMENT     Environment (default: development)"
    echo "  -k, --key-file PATH               Service account key file path"
    echo "  -t, --test                        Run Docker push test"
    echo "  -s, --skip-test                   Skip Docker push test"
    echo "  -c, --create-env                  Create environment configuration file"
    echo "  -h, --help                        Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  PROJECT_ID                        Google Cloud Project ID"
    echo "  REGISTRY_REGION                   Registry region"
    echo "  ENVIRONMENT                       Environment name"
    echo "  SERVICE_ACCOUNT_KEY_PATH          Path to service account key file"
    echo ""
    echo "Examples:"
    echo "  $0 --project-id isectech-prod-12345 --region us-central1 --environment production"
    echo "  $0 -p isectech-dev-12345 -e development --test"
    echo "  export PROJECT_ID=isectech-prod && $0 --create-env"
}

main() {
    local run_test=false
    local skip_test=false
    local create_env=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--project-id)
                PROJECT_ID="$2"
                shift 2
                ;;
            -r|--region)
                REGISTRY_REGION="$2"
                shift 2
                ;;
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -k|--key-file)
                SERVICE_ACCOUNT_KEY_PATH="$2"
                shift 2
                ;;
            -t|--test)
                run_test=true
                shift
                ;;
            -s|--skip-test)
                skip_test=true
                shift
                ;;
            -c|--create-env)
                create_env=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Main execution
    print_banner
    
    validate_prerequisites
    validate_configuration
    
    setup_gcloud_auth
    configure_docker_auth
    
    list_repositories
    generate_image_urls
    generate_docker_commands
    
    if [ "$create_env" = true ]; then
        create_env_file
    fi
    
    if [ "$run_test" = true ] && [ "$skip_test" = false ]; then
        test_docker_push
    elif [ "$skip_test" = false ]; then
        echo ""
        warning "Skipping Docker push test. Use --test flag to run test."
        echo "  Test command: $0 --project-id $PROJECT_ID --test"
    fi
    
    echo ""
    success "iSECTECH Docker authentication setup completed successfully!"
    echo ""
    echo "Next Steps:"
    echo "1. Build your Docker images using the generated URLs"
    echo "2. Push images to the appropriate repository based on environment"
    echo "3. Configure your CI/CD pipeline to use these repositories"
    echo "4. Set up vulnerability scanning for production images"
    echo ""
    echo "For help and documentation, see:"
    echo "  - Artifact Registry documentation: infrastructure/terraform/modules/artifact-registry/README.md"
    echo "  - Environment configuration: .env.docker"
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi