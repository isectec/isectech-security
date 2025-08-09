#!/bin/bash
# Security Context Compliance Audit Script for iSECTECH Kubernetes Clusters
# This script audits all running workloads for security context compliance
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${SCRIPT_DIR}/../reports/security-compliance"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="${REPORT_DIR}/security-context-audit-${TIMESTAMP}.json"
SUMMARY_FILE="${REPORT_DIR}/security-context-summary-${TIMESTAMP}.txt"

# Create reports directory
mkdir -p "${REPORT_DIR}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_PODS=0
COMPLIANT_PODS=0
VIOLATIONS=0

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

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    log_error "kubectl not found. Please install kubectl and ensure cluster access."
    exit 1
fi

# Check cluster connectivity
if ! kubectl cluster-info &> /dev/null; then
    log_error "Unable to connect to Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

log_info "Starting security context compliance audit..."
log_info "Report will be saved to: ${REPORT_FILE}"

# Initialize JSON report
cat > "${REPORT_FILE}" << EOF
{
  "audit_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "cluster_info": {
    "cluster_name": "$(kubectl config current-context)",
    "kubernetes_version": "$(kubectl version --short --client=false | grep 'Server Version' | cut -d' ' -f3 || echo 'unknown')"
  },
  "audit_results": {
    "summary": {
      "total_pods": 0,
      "compliant_pods": 0,
      "violation_count": 0,
      "compliance_percentage": 0
    },
    "namespace_results": [],
    "violations": [],
    "recommendations": []
  }
}
EOF

# Function to check pod security context
check_pod_security_context() {
    local namespace="$1"
    local pod="$2"
    local violations=()
    local pod_compliant=true

    # Get pod security context
    local pod_security_context=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext}' 2>/dev/null || echo '{}')
    
    # Check runAsNonRoot at pod level
    local run_as_non_root=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext.runAsNonRoot}' 2>/dev/null || echo 'null')
    if [[ "$run_as_non_root" != "true" ]] && [[ "$namespace" != "isectech-siem-agents" ]] && [[ "$namespace" != "falco-system" ]]; then
        violations+=("Pod runAsNonRoot not set to true")
        pod_compliant=false
    fi

    # Check seccomp profile at pod level
    local seccomp_type=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext.seccompProfile.type}' 2>/dev/null || echo 'null')
    if [[ "$seccomp_type" != "RuntimeDefault" ]]; then
        violations+=("Pod seccompProfile not set to RuntimeDefault")
        pod_compliant=false
    fi

    # Check fsGroup
    local fs_group=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext.fsGroup}' 2>/dev/null || echo 'null')
    if [[ "$fs_group" == "null" ]] || [[ -z "$fs_group" ]]; then
        violations+=("Pod fsGroup not configured")
        pod_compliant=false
    fi

    # Get container names
    local containers=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null || echo "")
    
    for container in $containers; do
        check_container_security_context "$namespace" "$pod" "$container" violations pod_compliant
    done

    # Add pod result to JSON report
    if [[ ${#violations[@]} -gt 0 ]]; then
        # Escape quotes for JSON
        local violations_json=""
        for violation in "${violations[@]}"; do
            violations_json+='"'${violation//\"/\\\"}'",'
        done
        violations_json=${violations_json%,}  # Remove trailing comma

        # Add to violations array in JSON
        jq --arg namespace "$namespace" \
           --arg pod "$pod" \
           --argjson violations "[$violations_json]" \
           '.audit_results.violations += [{
             "namespace": $namespace,
             "pod": $pod,
             "violations": $violations
           }]' "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
    fi

    if [[ "$pod_compliant" == "true" ]]; then
        ((COMPLIANT_PODS++))
    else
        ((VIOLATIONS++))
    fi
}

# Function to check container security context
check_container_security_context() {
    local namespace="$1"
    local pod="$2"
    local container="$3"
    local -n violations_ref=$4
    local -n compliant_ref=$5

    # Check allowPrivilegeEscalation
    local allow_priv_esc=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.allowPrivilegeEscalation}" 2>/dev/null || echo 'null')
    if [[ "$allow_priv_esc" != "false" ]]; then
        violations_ref+=("Container $container: allowPrivilegeEscalation not set to false")
        compliant_ref=false
    fi

    # Check capabilities
    local dropped_caps=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.capabilities.drop}" 2>/dev/null || echo '[]')
    if [[ "$dropped_caps" != *"ALL"* ]]; then
        violations_ref+=("Container $container: ALL capabilities not dropped")
        compliant_ref=false
    fi

    # Check for privileged mode
    local privileged=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.privileged}" 2>/dev/null || echo 'false')
    if [[ "$privileged" == "true" ]]; then
        violations_ref+=("Container $container: running in privileged mode")
        compliant_ref=false
    fi

    # Check readOnlyRootFilesystem
    local readonly_fs=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.readOnlyRootFilesystem}" 2>/dev/null || echo 'false')
    if [[ "$readonly_fs" != "true" ]] && [[ "$namespace" != "isectech-siem-agents" ]]; then
        violations_ref+=("Container $container: readOnlyRootFilesystem not set to true")
        compliant_ref=false
    fi

    # Check runAsNonRoot at container level
    local container_run_as_non_root=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.runAsNonRoot}" 2>/dev/null || echo 'null')
    if [[ "$container_run_as_non_root" != "true" ]] && [[ "$namespace" != "isectech-siem-agents" ]] && [[ "$namespace" != "falco-system" ]]; then
        violations_ref+=("Container $container: runAsNonRoot not set to true")
        compliant_ref=false
    fi

    # Check container seccomp profile
    local container_seccomp=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].securityContext.seccompProfile.type}" 2>/dev/null || echo 'null')
    if [[ "$container_seccomp" != "RuntimeDefault" ]] && [[ "$container_seccomp" == "null" ]]; then
        # Only flag if pod-level seccomp is also missing
        local pod_seccomp=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.securityContext.seccompProfile.type}' 2>/dev/null || echo 'null')
        if [[ "$pod_seccomp" != "RuntimeDefault" ]]; then
            violations_ref+=("Container $container: seccompProfile not configured")
            compliant_ref=false
        fi
    fi

    # Check resource limits
    local cpu_limit=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].resources.limits.cpu}" 2>/dev/null || echo 'null')
    local memory_limit=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath="{.spec.containers[?(@.name=='$container')].resources.limits.memory}" 2>/dev/null || echo 'null')
    
    if [[ "$cpu_limit" == "null" ]]; then
        violations_ref+=("Container $container: CPU limits not set")
        compliant_ref=false
    fi
    
    if [[ "$memory_limit" == "null" ]]; then
        violations_ref+=("Container $container: Memory limits not set")
        compliant_ref=false
    fi
}

# Get all namespaces (excluding system namespaces)
log_info "Discovering namespaces..."
namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | \
            grep -E '^(isectech-|production|staging|development|default|monitoring|security|kong-system)' || echo "")

if [[ -z "$namespaces" ]]; then
    log_warning "No application namespaces found matching patterns. Checking all non-system namespaces..."
    namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | \
                grep -vE '^(kube-|local-path-storage|gatekeeper-system|cert-manager)' || echo "")
fi

# Audit each namespace
for namespace in $namespaces; do
    log_info "Scanning namespace: $namespace"
    
    # Get pods in namespace
    pods=$(kubectl get pods -n "$namespace" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -z "$pods" ]]; then
        log_info "  No pods found in namespace $namespace"
        continue
    fi

    namespace_pod_count=0
    namespace_compliant_count=0
    
    for pod in $pods; do
        # Skip completed/failed pods
        phase=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        if [[ "$phase" == "Succeeded" ]] || [[ "$phase" == "Failed" ]]; then
            continue
        fi
        
        ((TOTAL_PODS++))
        ((namespace_pod_count++))
        
        pod_compliant_before=$COMPLIANT_PODS
        check_pod_security_context "$namespace" "$pod"
        
        if [[ $COMPLIANT_PODS -gt $pod_compliant_before ]]; then
            ((namespace_compliant_count++))
        fi
    done

    log_info "  Namespace $namespace: $namespace_compliant_count/$namespace_pod_count pods compliant"
    
    # Add namespace result to JSON
    jq --arg namespace "$namespace" \
       --arg pod_count "$namespace_pod_count" \
       --arg compliant_count "$namespace_compliant_count" \
       '.audit_results.namespace_results += [{
         "namespace": $namespace,
         "total_pods": ($pod_count | tonumber),
         "compliant_pods": ($compliant_count | tonumber),
         "compliance_percentage": (if ($pod_count | tonumber) > 0 then (($compliant_count | tonumber) / ($pod_count | tonumber) * 100) else 0 end)
       }]' "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
done

# Calculate compliance percentage
COMPLIANCE_PERCENTAGE=0
if [[ $TOTAL_PODS -gt 0 ]]; then
    COMPLIANCE_PERCENTAGE=$((COMPLIANT_PODS * 100 / TOTAL_PODS))
fi

# Update summary in JSON report
jq --arg total "$TOTAL_PODS" \
   --arg compliant "$COMPLIANT_PODS" \
   --arg violations "$VIOLATIONS" \
   --arg percentage "$COMPLIANCE_PERCENTAGE" \
   '.audit_results.summary.total_pods = ($total | tonumber) |
    .audit_results.summary.compliant_pods = ($compliant | tonumber) |
    .audit_results.summary.violation_count = ($violations | tonumber) |
    .audit_results.summary.compliance_percentage = ($percentage | tonumber)' \
   "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"

# Add recommendations to JSON report
recommendations=(
    "Enable Pod Security Standards admission controller with 'restricted' profile for production namespaces"
    "Deploy OPA Gatekeeper with security context constraint templates"
    "Implement automated remediation for non-compliant workloads"
    "Add security context validation to CI/CD pipelines"
    "Regular security context audits should be performed weekly"
    "Create exception handling process for legitimate privileged workloads"
    "Implement monitoring alerts for security context violations"
)

for rec in "${recommendations[@]}"; do
    jq --arg rec "$rec" \
       '.audit_results.recommendations += [$rec]' \
       "$REPORT_FILE" > "${REPORT_FILE}.tmp" && mv "${REPORT_FILE}.tmp" "$REPORT_FILE"
done

# Generate summary report
cat > "$SUMMARY_FILE" << EOF
================================
Security Context Compliance Audit
================================
Audit Date: $(date)
Cluster: $(kubectl config current-context)
Kubernetes Version: $(kubectl version --short --client=false | grep 'Server Version' | cut -d' ' -f3 || echo 'unknown')

SUMMARY
=======
Total Pods Audited: $TOTAL_PODS
Compliant Pods: $COMPLIANT_PODS
Pods with Violations: $VIOLATIONS
Overall Compliance: $COMPLIANCE_PERCENTAGE%

COMPLIANCE STATUS
================
EOF

if [[ $COMPLIANCE_PERCENTAGE -ge 90 ]]; then
    echo "Status: EXCELLENT (≥90%)" >> "$SUMMARY_FILE"
elif [[ $COMPLIANCE_PERCENTAGE -ge 75 ]]; then
    echo "Status: GOOD (≥75%)" >> "$SUMMARY_FILE"
elif [[ $COMPLIANCE_PERCENTAGE -ge 50 ]]; then
    echo "Status: NEEDS IMPROVEMENT (≥50%)" >> "$SUMMARY_FILE"
else
    echo "Status: CRITICAL (<50%)" >> "$SUMMARY_FILE"
fi

echo "" >> "$SUMMARY_FILE"
echo "RECOMMENDATIONS" >> "$SUMMARY_FILE"
echo "===============" >> "$SUMMARY_FILE"
for rec in "${recommendations[@]}"; do
    echo "- $rec" >> "$SUMMARY_FILE"
done

echo "" >> "$SUMMARY_FILE"
echo "DETAILED REPORTS" >> "$SUMMARY_FILE"
echo "===============" >> "$SUMMARY_FILE"
echo "JSON Report: $REPORT_FILE" >> "$SUMMARY_FILE"
echo "Summary Report: $SUMMARY_FILE" >> "$SUMMARY_FILE"

# Display results
echo ""
log_info "================================"
log_info "Security Context Audit Complete"
log_info "================================"
log_info "Total Pods Audited: $TOTAL_PODS"
log_info "Compliant Pods: $COMPLIANT_PODS"
log_info "Pods with Violations: $VIOLATIONS"

if [[ $COMPLIANCE_PERCENTAGE -ge 90 ]]; then
    log_success "Overall Compliance: $COMPLIANCE_PERCENTAGE% (EXCELLENT)"
elif [[ $COMPLIANCE_PERCENTAGE -ge 75 ]]; then
    log_success "Overall Compliance: $COMPLIANCE_PERCENTAGE% (GOOD)"
elif [[ $COMPLIANCE_PERCENTAGE -ge 50 ]]; then
    log_warning "Overall Compliance: $COMPLIANCE_PERCENTAGE% (NEEDS IMPROVEMENT)"
else
    log_error "Overall Compliance: $COMPLIANCE_PERCENTAGE% (CRITICAL)"
fi

log_info "Reports saved to:"
log_info "  JSON Report: $REPORT_FILE"
log_info "  Summary: $SUMMARY_FILE"

# Exit with appropriate code
if [[ $COMPLIANCE_PERCENTAGE -lt 75 ]]; then
    exit 1
else
    exit 0
fi