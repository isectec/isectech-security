#!/bin/bash
# Deploy Security Context Constraints and OPA Gatekeeper Policies
# This script deploys all security constraints and validates their proper functioning
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="${SCRIPT_DIR}/../infrastructure"
K8S_DIR="${INFRA_DIR}/kubernetes"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Please install kubectl."
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Unable to connect to Kubernetes cluster."
        exit 1
    fi

    # Check if user has admin privileges
    if ! kubectl auth can-i create clusterroles &> /dev/null; then
        log_error "Insufficient permissions. Cluster admin access required."
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Install OPA Gatekeeper if not present
install_gatekeeper() {
    log_info "Checking OPA Gatekeeper installation..."
    
    if kubectl get namespace gatekeeper-system &> /dev/null; then
        log_info "OPA Gatekeeper already installed"
        return 0
    fi

    log_info "Installing OPA Gatekeeper..."
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml

    log_info "Waiting for Gatekeeper to be ready..."
    kubectl wait --for=condition=Ready pods -n gatekeeper-system --all --timeout=300s

    log_success "OPA Gatekeeper installed successfully"
}

# Deploy Pod Security Standards admission controller configuration
deploy_pod_security_standards() {
    log_info "Deploying Pod Security Standards configuration..."
    
    # Apply PSS admission controller configuration
    kubectl apply -f "${K8S_DIR}/pod-security-standards-admission.yaml"
    
    # Apply namespace profiles
    kubectl apply -f "${K8S_DIR}/pod-security-namespace-profiles.yaml"
    
    log_success "Pod Security Standards configuration deployed"
}

# Deploy security context constraints and OPA policies
deploy_security_constraints() {
    log_info "Deploying security context constraints..."
    
    # Apply security context constraints
    kubectl apply -f "${K8S_DIR}/security-context-constraints.yaml"
    
    # Wait for Gatekeeper to process the constraint templates
    log_info "Waiting for constraint templates to be ready..."
    sleep 10
    
    # Check if constraint templates are ready
    while ! kubectl get constrainttemplates k8srequiresecuritycontext &> /dev/null; do
        log_info "Waiting for constraint templates to be available..."
        sleep 5
    done
    
    log_success "Security context constraints deployed"
}

# Update namespace labels for Pod Security Standards
update_namespace_labels() {
    log_info "Updating namespace labels for Pod Security Standards..."
    
    # Production namespaces - restricted profile
    for ns in isectech-api-gateway isectech-services isectech-data isectech-ai isectech-frontend production staging; do
        if kubectl get namespace "$ns" &> /dev/null; then
            kubectl label namespace "$ns" \
                pod-security.kubernetes.io/enforce=restricted \
                pod-security.kubernetes.io/audit=restricted \
                pod-security.kubernetes.io/warn=restricted \
                security.isectech.com/profile=restricted \
                --overwrite
            log_info "Labeled namespace $ns with restricted profile"
        fi
    done
    
    # Development and baseline namespaces
    for ns in development pss-test; do
        if kubectl get namespace "$ns" &> /dev/null; then
            kubectl label namespace "$ns" \
                pod-security.kubernetes.io/enforce=baseline \
                pod-security.kubernetes.io/audit=restricted \
                pod-security.kubernetes.io/warn=restricted \
                security.isectech.com/profile=baseline \
                --overwrite
            log_info "Labeled namespace $ns with baseline profile"
        fi
    done
    
    # Security monitoring namespaces
    for ns in security monitoring isectech-siem-agents; do
        if kubectl get namespace "$ns" &> /dev/null; then
            kubectl label namespace "$ns" \
                pod-security.kubernetes.io/enforce=baseline \
                pod-security.kubernetes.io/audit=baseline \
                pod-security.kubernetes.io/warn=baseline \
                security.isectech.com/tier=security \
                --overwrite
            log_info "Labeled namespace $ns with security monitoring profile"
        fi
    done
    
    log_success "Namespace labels updated"
}

# Validate deployment
validate_deployment() {
    log_info "Validating security constraints deployment..."
    
    # Check constraint templates
    log_info "Checking constraint templates..."
    if kubectl get constrainttemplates k8srequiresecuritycontext &> /dev/null; then
        log_success "Security context constraint template is available"
    else
        log_error "Security context constraint template not found"
        return 1
    fi
    
    if kubectl get constrainttemplates k8srequireresourcelimits &> /dev/null; then
        log_success "Resource limits constraint template is available"
    else
        log_error "Resource limits constraint template not found"
        return 1
    fi
    
    # Check constraints
    log_info "Checking constraints..."
    for constraint in security-context-restricted security-context-baseline security-context-monitoring require-resource-limits; do
        if kubectl get constraint "$constraint" &> /dev/null; then
            log_success "Constraint $constraint is deployed"
        else
            log_warning "Constraint $constraint not found"
        fi
    done
    
    # Check for violations
    log_info "Checking for existing violations..."
    violations=$(kubectl get constraints -o jsonpath='{range .items[*]}{.metadata.name}: {.status.totalViolations}{"\n"}{end}' 2>/dev/null || echo "")
    
    if [[ -n "$violations" ]]; then
        log_warning "Current policy violations:"
        echo "$violations" | grep -v ": 0" || log_info "No violations found"
    fi
    
    log_success "Deployment validation completed"
}

# Test security constraints with sample pods
test_security_constraints() {
    log_info "Testing security constraints with sample workloads..."
    
    # Create test namespace if it doesn't exist
    kubectl create namespace pss-test --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace pss-test \
        pod-security.kubernetes.io/enforce=baseline \
        pod-security.kubernetes.io/audit=restricted \
        pod-security.kubernetes.io/warn=restricted \
        security.isectech.com/profile=baseline \
        --overwrite
    
    # Test 1: Try to create a privileged pod (should fail)
    log_info "Test 1: Attempting to create privileged pod (should be blocked)..."
    cat << EOF | kubectl apply --dry-run=server -f - || log_success "Privileged pod correctly blocked"
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged-pod
  namespace: pss-test
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
EOF
    
    # Test 2: Try to create a pod without security context (should fail in restricted namespaces)
    log_info "Test 2: Attempting to create pod without security context..."
    cat << EOF | kubectl apply --dry-run=server -f - || log_success "Pod without security context correctly blocked"
apiVersion: v1
kind: Pod
metadata:
  name: test-insecure-pod
  namespace: pss-test
spec:
  containers:
  - name: test
    image: busybox:1.35
    command: ["sleep", "3600"]
EOF
    
    # Test 3: Create a compliant pod (should succeed)
    log_info "Test 3: Creating compliant pod (should succeed)..."
    cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: test-secure-pod
  namespace: pss-test
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: test
    image: busybox:1.35
    command: ["sleep", "60"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
    resources:
      limits:
        cpu: "100m"
        memory: "64Mi"
      requests:
        cpu: "50m"
        memory: "32Mi"
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
  restartPolicy: Never
EOF
    
    # Wait for pod to be ready and then clean up
    if kubectl wait --for=condition=Ready pod/test-secure-pod -n pss-test --timeout=60s; then
        log_success "Compliant pod created successfully"
        kubectl delete pod test-secure-pod -n pss-test
    else
        log_warning "Compliant pod did not become ready within timeout"
    fi
    
    log_success "Security constraints testing completed"
}

# Generate deployment report
generate_report() {
    log_info "Generating deployment report..."
    
    report_file="${SCRIPT_DIR}/../reports/security-constraints-deployment-$(date +%Y%m%d_%H%M%S).txt"
    mkdir -p "$(dirname "$report_file")"
    
    cat > "$report_file" << EOF
Security Context Constraints Deployment Report
============================================
Deployment Date: $(date)
Cluster: $(kubectl config current-context)
Kubernetes Version: $(kubectl version --short --client=false | grep 'Server Version' | cut -d' ' -f3 || echo 'unknown')

DEPLOYED COMPONENTS
==================
EOF
    
    # List constraint templates
    echo "Constraint Templates:" >> "$report_file"
    kubectl get constrainttemplates -o custom-columns=NAME:.metadata.name,AGE:.metadata.creationTimestamp >> "$report_file" 2>/dev/null || echo "None found" >> "$report_file"
    echo "" >> "$report_file"
    
    # List constraints
    echo "Constraints:" >> "$report_file"
    kubectl get constraints -o custom-columns=NAME:.metadata.name,VIOLATIONS:.status.totalViolations,AGE:.metadata.creationTimestamp >> "$report_file" 2>/dev/null || echo "None found" >> "$report_file"
    echo "" >> "$report_file"
    
    # List labeled namespaces
    echo "Pod Security Standards Namespace Labels:" >> "$report_file"
    kubectl get namespaces -o custom-columns=NAME:.metadata.name,ENFORCE:.metadata.labels.'pod-security\.kubernetes\.io/enforce',PROFILE:.metadata.labels.'security\.isectech\.com/profile' >> "$report_file" 2>/dev/null
    echo "" >> "$report_file"
    
    echo "NEXT STEPS" >> "$report_file"
    echo "==========" >> "$report_file"
    echo "1. Run security audit: ./scripts/audit-security-context.sh" >> "$report_file"
    echo "2. Review existing workloads for compliance" >> "$report_file"
    echo "3. Update non-compliant deployments" >> "$report_file"
    echo "4. Set up monitoring alerts for policy violations" >> "$report_file"
    echo "5. Schedule regular compliance audits" >> "$report_file"
    
    log_success "Deployment report generated: $report_file"
}

# Main execution
main() {
    log_info "Starting security context constraints deployment..."
    
    check_prerequisites
    install_gatekeeper
    deploy_pod_security_standards
    deploy_security_constraints
    update_namespace_labels
    validate_deployment
    test_security_constraints
    generate_report
    
    log_success "Security context constraints deployment completed successfully!"
    log_info ""
    log_info "IMPORTANT NEXT STEPS:"
    log_info "1. Run the security audit: ./scripts/audit-security-context.sh"
    log_info "2. Review and update existing non-compliant workloads"
    log_info "3. Configure monitoring alerts for policy violations"
    log_info "4. Train development teams on new security requirements"
    log_info ""
    log_info "For troubleshooting, see: infrastructure/security/POD-SECURITY-STANDARDS-IMPLEMENTATION-GUIDE.md"
}

# Execute main function
main "$@"