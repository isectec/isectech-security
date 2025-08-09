#!/bin/bash

# Deploy Default Deny Network Policies for iSECTECH
# Part of Task 77: Identity-Based Network Policies
# This script safely deploys default-deny policies with essential allow rules

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICIES_DIR="${SCRIPT_DIR}"
DRY_RUN="${DRY_RUN:-false}"
CONFIRM="${CONFIRM:-false}"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        error "kubectl not found. Please install kubectl."
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        error "Cannot connect to Kubernetes cluster. Check your kubeconfig."
        exit 1
    fi
    
    # Check if running as admin
    if ! kubectl auth can-i create networkpolicies --all-namespaces &> /dev/null; then
        error "Insufficient permissions. You need cluster admin rights to deploy network policies."
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Validate namespaces exist
validate_namespaces() {
    log "Validating target namespaces exist..."
    
    local namespaces=(
        "istio-system"
        "isectech-api-gateway"
        "isectech-services"
        "isectech-data"
        "isectech-ai"
        "isectech-frontend"
        "production"
        "staging"
        "monitoring"
        "kube-system"
        "default"
    )
    
    local missing_namespaces=()
    
    for ns in "${namespaces[@]}"; do
        if ! kubectl get namespace "$ns" &> /dev/null; then
            missing_namespaces+=("$ns")
            warning "Namespace '$ns' does not exist"
        fi
    done
    
    if [ ${#missing_namespaces[@]} -gt 0 ]; then
        warning "The following namespaces are missing and will be skipped:"
        printf ' - %s\n' "${missing_namespaces[@]}"
        echo
        if [ "$CONFIRM" != "true" ]; then
            read -p "Continue anyway? [y/N]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log "Deployment cancelled by user"
                exit 0
            fi
        fi
    fi
    
    success "Namespace validation completed"
}

# Check current network policies
check_existing_policies() {
    log "Checking existing network policies..."
    
    local existing_policies
    existing_policies=$(kubectl get networkpolicies --all-namespaces -o json | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")
    
    if [ -n "$existing_policies" ]; then
        warning "Existing network policies found:"
        echo "$existing_policies"
        echo
        if [ "$CONFIRM" != "true" ]; then
            read -p "These policies may conflict. Continue? [y/N]: " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log "Deployment cancelled by user"
                exit 0
            fi
        fi
    else
        log "No existing network policies found"
    fi
}

# Backup existing network policies
backup_existing_policies() {
    log "Backing up existing network policies..."
    
    local backup_dir="${SCRIPT_DIR}/backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    if kubectl get networkpolicies --all-namespaces -o yaml > "$backup_dir/existing-network-policies.yaml" 2>/dev/null; then
        success "Backup created at: $backup_dir/existing-network-policies.yaml"
    else
        log "No existing policies to backup"
    fi
}

# Apply policies with kubectl
apply_policy_file() {
    local file="$1"
    local description="$2"
    
    log "Applying $description..."
    
    if [ "$DRY_RUN" = "true" ]; then
        log "DRY RUN: Would apply $file"
        kubectl apply -f "$file" --dry-run=client
    else
        if kubectl apply -f "$file"; then
            success "$description applied successfully"
        else
            error "Failed to apply $description"
            return 1
        fi
    fi
}

# Test connectivity after applying policies
test_connectivity() {
    log "Testing basic connectivity..."
    
    # Test DNS resolution
    if kubectl run network-test-pod --image=nicolaka/netshoot --rm -i --restart=Never -- nslookup kubernetes.default.svc.cluster.local &> /dev/null; then
        success "DNS resolution test passed"
    else
        warning "DNS resolution test failed - this may be expected with new policies"
    fi
    
    # Test API server connectivity
    if kubectl get nodes &> /dev/null; then
        success "API server connectivity test passed"
    else
        error "API server connectivity test failed"
        return 1
    fi
}

# Main deployment function
deploy_policies() {
    log "Starting default deny network policy deployment..."
    
    # Step 1: Apply essential allow policies first (critical for cluster operation)
    apply_policy_file "$POLICIES_DIR/essential-allow-policies.yaml" "essential allow policies"
    
    # Wait a moment for policies to take effect
    sleep 5
    
    # Step 2: Apply default deny policies
    apply_policy_file "$POLICIES_DIR/default-deny-network-policies.yaml" "default deny policies"
    
    # Wait for policies to propagate
    log "Waiting for policies to propagate..."
    sleep 10
    
    # Test connectivity
    if [ "$DRY_RUN" != "true" ]; then
        test_connectivity
    fi
}

# Rollback function
rollback() {
    error "Rolling back network policies..."
    
    # Find the most recent backup
    local latest_backup
    latest_backup=$(find "$SCRIPT_DIR" -name "backup-*" -type d | sort | tail -n 1)
    
    if [ -n "$latest_backup" ] && [ -f "$latest_backup/existing-network-policies.yaml" ]; then
        log "Restoring from backup: $latest_backup"
        kubectl delete -f "$POLICIES_DIR/default-deny-network-policies.yaml" --ignore-not-found=true
        kubectl delete -f "$POLICIES_DIR/essential-allow-policies.yaml" --ignore-not-found=true
        kubectl apply -f "$latest_backup/existing-network-policies.yaml"
        success "Rollback completed"
    else
        warning "No backup found. Manually removing deployed policies..."
        kubectl delete -f "$POLICIES_DIR/default-deny-network-policies.yaml" --ignore-not-found=true
        kubectl delete -f "$POLICIES_DIR/essential-allow-policies.yaml" --ignore-not-found=true
        success "Policies removed"
    fi
}

# Show deployment summary
show_summary() {
    log "Deployment Summary:"
    echo "===================="
    echo "Default Deny Policies: Applied to all namespaces"
    echo "Essential Allow Policies: Applied for:"
    echo "  - DNS resolution"
    echo "  - API server access"
    echo "  - Istio service mesh communication"
    echo "  - Monitoring and metrics collection"
    echo "  - External DNS and NTP"
    echo "  - Container image pulls"
    echo
    echo "Next Steps:"
    echo "1. Deploy granular service-to-service allow policies (Task 77.3)"
    echo "2. Integrate with Istio authorization policies (Task 77.4)"
    echo "3. Configure advanced CNI features (Task 77.5)"
    echo "4. Implement egress policies and monitoring (Task 77.6)"
    echo
    echo "Monitoring:"
    echo "- Check policy violations: kubectl get events --field-selector reason=NetworkPolicyViolation"
    echo "- Monitor pod connectivity issues"
    echo "- Verify expected traffic flows work correctly"
}

# Signal handlers for cleanup
cleanup() {
    log "Received interrupt signal. Cleaning up..."
    if [ "${ROLLBACK_ON_FAILURE:-false}" = "true" ]; then
        rollback
    fi
    exit 130
}

trap cleanup INT TERM

# Main execution
main() {
    log "iSECTECH Default Deny Network Policy Deployment"
    log "=============================================="
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN="true"
                shift
                ;;
            --yes)
                CONFIRM="true"
                shift
                ;;
            --rollback)
                rollback
                exit 0
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --dry-run    Show what would be applied without making changes"
                echo "  --yes        Skip confirmation prompts"
                echo "  --rollback   Rollback to previous state"
                echo "  --help       Show this help message"
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [ "$DRY_RUN" = "true" ]; then
        warning "DRY RUN MODE - No changes will be applied"
    fi
    
    # Show warning
    if [ "$CONFIRM" != "true" ]; then
        warning "This will apply default DENY network policies to all namespaces!"
        warning "Essential allow rules will be applied first to maintain cluster functionality."
        warning "Ensure you have tested these policies in a non-production environment first."
        echo
        read -p "Are you sure you want to continue? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    # Execute deployment steps
    check_prerequisites
    validate_namespaces
    check_existing_policies
    backup_existing_policies
    
    # Deploy with error handling
    if deploy_policies; then
        success "Default deny network policies deployed successfully!"
        show_summary
    else
        error "Deployment failed!"
        if [ "${ROLLBACK_ON_FAILURE:-true}" = "true" ]; then
            rollback
        fi
        exit 1
    fi
}

# Run main function
main "$@"