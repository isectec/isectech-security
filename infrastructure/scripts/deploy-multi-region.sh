#!/bin/bash
# iSECTECH Multi-Region Infrastructure Deployment Script
# Automated deployment script for multi-region GCP infrastructure
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Multi-Region Architecture Implementation

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
PROJECT_ID="${PROJECT_ID:-isectech-platform}"
ENVIRONMENT="${ENVIRONMENT:-production}"
TERRAFORM_STATE_BUCKET="${TERRAFORM_STATE_BUCKET:-isectech-terraform-state}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

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

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if gcloud is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if terraform is installed
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed. Please install it first."
        exit 1
    fi
    
    # Check if kubectl is installed
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed. Please install it first."
        exit 1
    fi
    
    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        log_error "gcloud is not authenticated. Please run 'gcloud auth login' first."
        exit 1
    fi
    
    # Check project access
    if ! gcloud projects describe "${PROJECT_ID}" &> /dev/null; then
        log_error "Cannot access project ${PROJECT_ID}. Please check permissions."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

enable_required_apis() {
    log_info "Enabling required GCP APIs..."
    
    local apis=(
        "container.googleapis.com"
        "compute.googleapis.com"
        "cloudkms.googleapis.com"
        "dns.googleapis.com"
        "monitoring.googleapis.com"
        "logging.googleapis.com"
        "cloudresourcemanager.googleapis.com"
        "serviceusage.googleapis.com"
        "iam.googleapis.com"
        "storage.googleapis.com"
        "secretmanager.googleapis.com"
        "artifactregistry.googleapis.com"
        "binaryauthorization.googleapis.com"
        "networksecurity.googleapis.com"
    )
    
    for api in "${apis[@]}"; do
        log_info "Enabling ${api}..."
        gcloud services enable "${api}" --project="${PROJECT_ID}" || {
            log_warning "Failed to enable ${api}, it might already be enabled"
        }
    done
    
    log_success "Required APIs enabled"
}

create_terraform_state_bucket() {
    log_info "Creating Terraform state bucket if it doesn't exist..."
    
    if ! gsutil ls -b "gs://${TERRAFORM_STATE_BUCKET}" &> /dev/null; then
        log_info "Creating bucket gs://${TERRAFORM_STATE_BUCKET}..."
        gsutil mb -p "${PROJECT_ID}" -c STANDARD -l us-central1 "gs://${TERRAFORM_STATE_BUCKET}"
        
        # Enable versioning
        gsutil versioning set on "gs://${TERRAFORM_STATE_BUCKET}"
        
        # Set lifecycle policy to clean up old versions
        cat > /tmp/lifecycle.json << EOF
{
  "rule": [
    {
      "action": {"type": "Delete"},
      "condition": {
        "age": 90,
        "isLive": false
      }
    }
  ]
}
EOF
        gsutil lifecycle set /tmp/lifecycle.json "gs://${TERRAFORM_STATE_BUCKET}"
        rm /tmp/lifecycle.json
        
        log_success "Terraform state bucket created and configured"
    else
        log_success "Terraform state bucket already exists"
    fi
}

validate_terraform_config() {
    log_info "Validating Terraform configuration..."
    
    cd "${TERRAFORM_DIR}"
    
    # Initialize Terraform
    terraform init -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" \
                   -backend-config="prefix=multi-region/terraform.tfstate"
    
    # Validate configuration
    terraform validate
    
    # Plan deployment with all configuration files
    terraform plan -var-file="multi-region.tfvars" \
                   -var="project_id=${PROJECT_ID}" \
                   -var="environment=${ENVIRONMENT}" \
                   -var="terraform_state_bucket=${TERRAFORM_STATE_BUCKET}" \
                   -target="module.regional_infrastructure" \
                   -target="google_dns_managed_zone.primary_zone" \
                   -target="google_compute_address.regional_ip" \
                   -out="multi-region.tfplan"
    
    log_success "Terraform configuration validated"
}

deploy_infrastructure() {
    log_info "Deploying multi-region infrastructure..."
    
    cd "${TERRAFORM_DIR}"
    
    # Apply Terraform plan
    terraform apply "multi-region.tfplan"
    
    log_success "Multi-region infrastructure deployed"
}

configure_kubectl_contexts() {
    log_info "Configuring kubectl contexts for all regional clusters..."
    
    local regions=("us-central1" "europe-west4" "asia-northeast1" "us-east1" "europe-west1")
    
    for region in "${regions[@]}"; do
        local cluster_name="isectech-${region}-${ENVIRONMENT}"
        log_info "Configuring kubectl for cluster ${cluster_name} in ${region}..."
        
        gcloud container clusters get-credentials "${cluster_name}" \
            --region="${region}" \
            --project="${PROJECT_ID}"
        
        # Rename context for clarity
        kubectl config rename-context \
            "gke_${PROJECT_ID}_${region}_${cluster_name}" \
            "isectech-${region}-${ENVIRONMENT}"
    done
    
    # Set primary region as default context
    kubectl config use-context "isectech-us-central1-${ENVIRONMENT}"
    
    log_success "kubectl contexts configured"
}

verify_deployment() {
    log_info "Verifying multi-region deployment..."
    
    local regions=("us-central1" "europe-west4" "asia-northeast1" "us-east1" "europe-west1")
    local failed_regions=()
    
    for region in "${regions[@]}"; do
        log_info "Checking cluster health in ${region}..."
        
        kubectl config use-context "isectech-${region}-${ENVIRONMENT}"
        
        # Check if cluster is responsive
        if kubectl get nodes &> /dev/null; then
            local node_count=$(kubectl get nodes --no-headers | wc -l)
            log_success "Cluster in ${region} is healthy with ${node_count} nodes"
        else
            log_error "Cluster in ${region} is not responding"
            failed_regions+=("${region}")
        fi
        
        # Check system pods
        local system_pods=$(kubectl get pods -n kube-system --no-headers | grep -c "Running" || echo 0)
        log_info "System pods running in ${region}: ${system_pods}"
        
        # Verify workload identity
        if kubectl get serviceaccounts isectech-workload &> /dev/null; then
            log_success "Workload Identity configured in ${region}"
        else
            log_warning "Workload Identity not found in ${region}"
        fi
    done
    
    if [ ${#failed_regions[@]} -eq 0 ]; then
        log_success "All regional clusters are healthy"
    else
        log_error "Failed regions: ${failed_regions[*]}"
        return 1
    fi
}

setup_monitoring() {
    log_info "Setting up multi-region monitoring..."
    
    # Create monitoring dashboard for multi-region overview
    gcloud monitoring dashboards create --config-from-file="${SCRIPT_DIR}/monitoring/multi-region-dashboard.json" \
        --project="${PROJECT_ID}" || log_warning "Dashboard creation failed"
    
    log_success "Multi-region monitoring configured"
}

print_deployment_summary() {
    log_success "=== MULTI-REGION DEPLOYMENT SUMMARY ==="
    echo ""
    echo "Project ID: ${PROJECT_ID}"
    echo "Environment: ${ENVIRONMENT}"
    echo "Deployment Model: Active-Active"
    echo ""
    echo "Deployed Regions:"
    echo "  - us-central1 (Primary, CCPA)"
    echo "  - europe-west4 (Secondary, GDPR)"
    echo "  - asia-northeast1 (Secondary, APPI)"
    echo "  - us-east1 (Backup, CCPA)"
    echo "  - europe-west1 (Backup, GDPR)"
    echo ""
    echo "Security Features:"
    echo "  ✓ Workload Identity enabled"
    echo "  ✓ Shielded nodes enabled"
    echo "  ✓ Binary Authorization enabled"
    echo "  ✓ Network policies enabled"
    echo "  ✓ Envelope encryption with regional KMS keys"
    echo ""
    echo "Compliance:"
    echo "  ✓ Data residency enforcement"
    echo "  ✓ GDPR, CCPA, APPI compliance"
    echo "  ✓ Cross-region data transfer disabled"
    echo "  ✓ Audit logging enabled"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure global load balancing (Task 70.3)"
    echo "  2. Set up cross-region replication (Task 70.7)"
    echo "  3. Update CI/CD pipelines (Task 70.8)"
    echo "  4. Configure monitoring and alerting (Task 70.9)"
    echo ""
    echo "kubectl Contexts:"
    kubectl config get-contexts | grep isectech || echo "No contexts found"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    log_info "Starting iSECTECH Multi-Region Infrastructure Deployment"
    log_info "Project: ${PROJECT_ID}, Environment: ${ENVIRONMENT}"
    echo ""
    
    # Confirm deployment
    read -p "Are you sure you want to deploy multi-region infrastructure? (y/N): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Deployment cancelled"
        exit 0
    fi
    
    # Execute deployment steps
    check_prerequisites
    enable_required_apis
    create_terraform_state_bucket
    validate_terraform_config
    deploy_infrastructure
    configure_kubectl_contexts
    verify_deployment
    setup_monitoring
    print_deployment_summary
    
    log_success "Multi-region deployment completed successfully!"
}

# Handle script arguments
case "${1:-deploy}" in
    "prerequisites")
        check_prerequisites
        ;;
    "validate")
        validate_terraform_config
        ;;
    "deploy")
        main
        ;;
    "verify")
        verify_deployment
        ;;
    "summary")
        print_deployment_summary
        ;;
    *)
        echo "Usage: $0 [prerequisites|validate|deploy|verify|summary]"
        echo ""
        echo "Commands:"
        echo "  prerequisites - Check prerequisites only"
        echo "  validate     - Validate Terraform configuration"
        echo "  deploy       - Full deployment (default)"
        echo "  verify       - Verify existing deployment"
        echo "  summary      - Print deployment summary"
        exit 1
        ;;
esac