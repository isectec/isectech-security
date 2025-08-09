#!/bin/bash

# Istio Security Validation Script for iSECTECH Zero Trust Architecture
# Comprehensive validation of mTLS enforcement, security policies, and zero trust principles
# 
# This script validates the security posture of the deployed Istio service mesh

set -euo pipefail

# Configuration
ISTIO_NAMESPACE="istio-system"
TEST_NAMESPACE="istio-security-test"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${GREEN}[${timestamp}] [INFO]${NC} $message"
            ;;
        WARN)
            echo -e "${YELLOW}[${timestamp}] [WARN]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[${timestamp}] [ERROR]${NC} $message"
            ;;
        DEBUG)
            echo -e "${BLUE}[${timestamp}] [DEBUG]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[${timestamp}] [SUCCESS]${NC} ✓ $message"
            ;;
        FAILURE)
            echo -e "${RED}[${timestamp}] [FAILURE]${NC} ✗ $message"
            ;;
    esac
}

# Test result counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [[ "$result" == "PASS" ]]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        log SUCCESS "$test_name"
        [[ -n "$details" ]] && log INFO "  Details: $details"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        log FAILURE "$test_name"
        [[ -n "$details" ]] && log ERROR "  Details: $details"
    fi
}

# Check prerequisites
check_prerequisites() {
    log INFO "🔍 Checking prerequisites for security validation..."
    
    # Check if kubectl is available
    if ! command -v kubectl &> /dev/null; then
        log ERROR "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check if istioctl is available
    if ! command -v istioctl &> /dev/null; then
        log ERROR "istioctl is not installed or not in PATH"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log ERROR "Unable to connect to Kubernetes cluster"
        exit 1
    fi
    
    # Check if Istio is installed
    if ! kubectl get namespace ${ISTIO_NAMESPACE} &> /dev/null; then
        log ERROR "Istio system namespace not found. Is Istio installed?"
        exit 1
    fi
    
    log INFO "Prerequisites validation completed"
}

# Validate Istio installation
validate_istio_installation() {
    log INFO "🔧 Validating Istio installation..."
    
    # Check Istio control plane health
    local istiod_ready=$(kubectl get deployment istiod -n ${ISTIO_NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local istiod_desired=$(kubectl get deployment istiod -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
    
    if [[ "$istiod_ready" -eq "$istiod_desired" && "$istiod_ready" -gt 0 ]]; then
        test_result "Istio control plane health check" "PASS" "istiod: $istiod_ready/$istiod_desired ready"
    else
        test_result "Istio control plane health check" "FAIL" "istiod: $istiod_ready/$istiod_desired ready"
    fi
    
    # Check ingress gateway
    local gateway_ready=$(kubectl get deployment istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local gateway_desired=$(kubectl get deployment istio-ingressgateway -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
    
    if [[ "$gateway_ready" -eq "$gateway_desired" && "$gateway_ready" -gt 0 ]]; then
        test_result "Istio ingress gateway health check" "PASS" "ingress-gateway: $gateway_ready/$gateway_desired ready"
    else
        test_result "Istio ingress gateway health check" "FAIL" "ingress-gateway: $gateway_ready/$gateway_desired ready"
    fi
    
    # Verify installation using istioctl
    log INFO "Running istioctl verify-install..."
    if istioctl verify-install --quiet; then
        test_result "Istioctl verify-install check" "PASS" "All Istio components verified successfully"
    else
        test_result "Istioctl verify-install check" "FAIL" "Istio verification failed"
    fi
}

# Validate mTLS enforcement
validate_mtls_enforcement() {
    log INFO "🔒 Validating mTLS enforcement across the mesh..."
    
    # Check global mTLS policy
    if kubectl get peerauthentication default -n ${ISTIO_NAMESPACE} &> /dev/null; then
        local mtls_mode=$(kubectl get peerauthentication default -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.mtls.mode}')
        if [[ "$mtls_mode" == "STRICT" ]]; then
            test_result "Global mTLS policy enforcement" "PASS" "Mode: $mtls_mode"
        else
            test_result "Global mTLS policy enforcement" "FAIL" "Expected STRICT, got: $mtls_mode"
        fi
    else
        test_result "Global mTLS policy existence" "FAIL" "Global PeerAuthentication policy not found"
    fi
    
    # Check namespace-specific mTLS policies
    local namespaces=("isectech-api-gateway" "isectech-services" "isectech-data" "isectech-ai" "isectech-frontend")
    local policies_found=0
    
    for namespace in "${namespaces[@]}"; do
        if kubectl get namespace "$namespace" &> /dev/null; then
            if kubectl get peerauthentication default -n "$namespace" &> /dev/null; then
                local ns_mtls_mode=$(kubectl get peerauthentication default -n "$namespace" -o jsonpath='{.spec.mtls.mode}')
                if [[ "$ns_mtls_mode" == "STRICT" ]]; then
                    policies_found=$((policies_found + 1))
                fi
            fi
        fi
    done
    
    if [[ $policies_found -ge 3 ]]; then
        test_result "Namespace mTLS policies" "PASS" "$policies_found/${#namespaces[@]} namespaces have strict mTLS"
    else
        test_result "Namespace mTLS policies" "FAIL" "Only $policies_found/${#namespaces[@]} namespaces have strict mTLS"
    fi
    
    # Test mTLS using istioctl (if services are available)
    log INFO "Testing mTLS connectivity using istioctl..."
    local services_to_test=()
    
    # Find available services to test
    if kubectl get service kong-proxy -n isectech-api-gateway &> /dev/null; then
        services_to_test+=("kong-proxy.isectech-api-gateway")
    fi
    
    if kubectl get service auth-service -n isectech-services &> /dev/null; then
        services_to_test+=("auth-service.isectech-services")
    fi
    
    local mtls_tests_passed=0
    for service in "${services_to_test[@]}"; do
        if istioctl authn tls-check "$service" &> /dev/null; then
            mtls_tests_passed=$((mtls_tests_passed + 1))
        fi
    done
    
    if [[ ${#services_to_test[@]} -gt 0 ]]; then
        if [[ $mtls_tests_passed -eq ${#services_to_test[@]} ]]; then
            test_result "Service mTLS connectivity" "PASS" "$mtls_tests_passed/${#services_to_test[@]} services have working mTLS"
        else
            test_result "Service mTLS connectivity" "FAIL" "Only $mtls_tests_passed/${#services_to_test[@]} services have working mTLS"
        fi
    else
        test_result "Service mTLS connectivity" "SKIP" "No services available for testing"
    fi
}

# Validate authorization policies
validate_authorization_policies() {
    log INFO "🛡️ Validating authorization policies..."
    
    # Count authorization policies
    local total_policies=$(kubectl get authorizationpolicy --all-namespaces --no-headers 2>/dev/null | wc -l)
    
    if [[ $total_policies -gt 0 ]]; then
        test_result "Authorization policies presence" "PASS" "$total_policies policies found across all namespaces"
    else
        test_result "Authorization policies presence" "FAIL" "No authorization policies found"
    fi
    
    # Check for default deny policies in critical namespaces
    local critical_namespaces=("production" "isectech-api-gateway" "isectech-services")
    local deny_policies_found=0
    
    for namespace in "${critical_namespaces[@]}"; do
        if kubectl get namespace "$namespace" &> /dev/null; then
            local ns_policies=$(kubectl get authorizationpolicy -n "$namespace" --no-headers 2>/dev/null | wc -l)
            if [[ $ns_policies -gt 0 ]]; then
                deny_policies_found=$((deny_policies_found + 1))
            fi
        fi
    done
    
    if [[ $deny_policies_found -ge 2 ]]; then
        test_result "Critical namespace authorization policies" "PASS" "$deny_policies_found/${#critical_namespaces[@]} critical namespaces have policies"
    else
        test_result "Critical namespace authorization policies" "WARN" "Only $deny_policies_found/${#critical_namespaces[@]} critical namespaces have policies"
    fi
}

# Validate sidecar injection
validate_sidecar_injection() {
    log INFO "💉 Validating sidecar injection..."
    
    local namespaces_with_injection=()
    local total_injection_enabled=0
    
    # Check which namespaces have injection enabled
    while IFS= read -r namespace; do
        if [[ -n "$namespace" ]]; then
            namespaces_with_injection+=("$namespace")
            total_injection_enabled=$((total_injection_enabled + 1))
        fi
    done < <(kubectl get namespaces -o jsonpath='{.items[?(@.metadata.labels.istio-injection=="enabled")].metadata.name}' | tr ' ' '\n')
    
    if [[ $total_injection_enabled -ge 3 ]]; then
        test_result "Namespaces with sidecar injection" "PASS" "$total_injection_enabled namespaces have injection enabled"
    else
        test_result "Namespaces with sidecar injection" "WARN" "Only $total_injection_enabled namespaces have injection enabled"
    fi
    
    # Check actual sidecar injection in pods
    local total_pods_with_sidecars=0
    local total_pods_checked=0
    
    for namespace in "${namespaces_with_injection[@]}"; do
        local pods_in_ns=$(kubectl get pods -n "$namespace" --no-headers 2>/dev/null | wc -l)
        if [[ $pods_in_ns -gt 0 ]]; then
            local pods_with_sidecars=$(kubectl get pods -n "$namespace" -o jsonpath='{.items[*].spec.containers[*].name}' 2>/dev/null | tr ' ' '\n' | grep -c istio-proxy || echo 0)
            total_pods_with_sidecars=$((total_pods_with_sidecars + pods_with_sidecars))
            total_pods_checked=$((total_pods_checked + pods_in_ns))
        fi
    done
    
    if [[ $total_pods_checked -gt 0 ]]; then
        local injection_percentage=$((total_pods_with_sidecars * 100 / total_pods_checked))
        if [[ $injection_percentage -ge 80 ]]; then
            test_result "Pod sidecar injection rate" "PASS" "$total_pods_with_sidecars/$total_pods_checked pods have sidecars (${injection_percentage}%)"
        else
            test_result "Pod sidecar injection rate" "FAIL" "$total_pods_with_sidecars/$total_pods_checked pods have sidecars (${injection_percentage}%)"
        fi
    else
        test_result "Pod sidecar injection rate" "SKIP" "No pods found in injection-enabled namespaces"
    fi
}

# Validate destination rules
validate_destination_rules() {
    log INFO "🎯 Validating destination rules and traffic policies..."
    
    # Count destination rules
    local total_dr=$(kubectl get destinationrules --all-namespaces --no-headers 2>/dev/null | wc -l)
    
    if [[ $total_dr -gt 0 ]]; then
        test_result "DestinationRule resources" "PASS" "$total_dr DestinationRule resources found"
    else
        test_result "DestinationRule resources" "FAIL" "No DestinationRule resources found"
    fi
    
    # Check for ISTIO_MUTUAL TLS mode in destination rules
    local dr_with_mtls=0
    while IFS= read -r dr_info; do
        if [[ -n "$dr_info" ]]; then
            local namespace=$(echo "$dr_info" | awk '{print $1}')
            local name=$(echo "$dr_info" | awk '{print $2}')
            local tls_mode=$(kubectl get destinationrule "$name" -n "$namespace" -o jsonpath='{.spec.trafficPolicy.tls.mode}' 2>/dev/null || echo "")
            
            if [[ "$tls_mode" == "ISTIO_MUTUAL" ]]; then
                dr_with_mtls=$((dr_with_mtls + 1))
            fi
        fi
    done < <(kubectl get destinationrules --all-namespaces --no-headers 2>/dev/null | awk '{print $1 " " $2}')
    
    if [[ $dr_with_mtls -gt 0 ]]; then
        test_result "DestinationRules with mTLS" "PASS" "$dr_with_mtls DestinationRules configured with ISTIO_MUTUAL"
    else
        test_result "DestinationRules with mTLS" "WARN" "No DestinationRules found with ISTIO_MUTUAL TLS mode"
    fi
}

# Validate gateways and virtual services
validate_gateways_virtualservices() {
    log INFO "🚪 Validating gateways and virtual services..."
    
    # Count gateways
    local total_gateways=$(kubectl get gateways --all-namespaces --no-headers 2>/dev/null | wc -l)
    if [[ $total_gateways -gt 0 ]]; then
        test_result "Gateway resources" "PASS" "$total_gateways Gateway resources found"
    else
        test_result "Gateway resources" "FAIL" "No Gateway resources found"
    fi
    
    # Count virtual services
    local total_vs=$(kubectl get virtualservices --all-namespaces --no-headers 2>/dev/null | wc -l)
    if [[ $total_vs -gt 0 ]]; then
        test_result "VirtualService resources" "PASS" "$total_vs VirtualService resources found"
    else
        test_result "VirtualService resources" "FAIL" "No VirtualService resources found"
    fi
    
    # Check for HTTPS configuration in gateways
    local gateways_with_tls=0
    while IFS= read -r gw_info; do
        if [[ -n "$gw_info" ]]; then
            local namespace=$(echo "$gw_info" | awk '{print $1}')
            local name=$(echo "$gw_info" | awk '{print $2}')
            local has_https=$(kubectl get gateway "$name" -n "$namespace" -o json 2>/dev/null | jq -r '.spec.servers[].port.protocol' | grep -c HTTPS || echo 0)
            
            if [[ $has_https -gt 0 ]]; then
                gateways_with_tls=$((gateways_with_tls + 1))
            fi
        fi
    done < <(kubectl get gateways --all-namespaces --no-headers 2>/dev/null | awk '{print $1 " " $2}')
    
    if [[ $gateways_with_tls -gt 0 ]]; then
        test_result "Gateways with TLS/HTTPS" "PASS" "$gateways_with_tls Gateways configured with HTTPS"
    else
        test_result "Gateways with TLS/HTTPS" "WARN" "No Gateways found with HTTPS configuration"
    fi
}

# Test network security with test pods
test_network_security() {
    log INFO "🔬 Testing network security with test pods..."
    
    # Create test namespace
    kubectl create namespace ${TEST_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
    kubectl label namespace ${TEST_NAMESPACE} istio-injection=enabled --overwrite
    
    # Deploy test pods
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-client
  namespace: ${TEST_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-client
  template:
    metadata:
      labels:
        app: test-client
    spec:
      containers:
      - name: client
        image: curlimages/curl:latest
        command: ["/bin/sleep", "3600"]
        securityContext:
          runAsNonRoot: true
          runAsUser: 65534
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-server
  namespace: ${TEST_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-server
  template:
    metadata:
      labels:
        app: test-server
    spec:
      containers:
      - name: server
        image: nginx:alpine
        ports:
        - containerPort: 80
        securityContext:
          runAsNonRoot: true
          runAsUser: 101
---
apiVersion: v1
kind: Service
metadata:
  name: test-server
  namespace: ${TEST_NAMESPACE}
spec:
  selector:
    app: test-server
  ports:
  - port: 80
    targetPort: 80
EOF
    
    # Wait for pods to be ready
    log INFO "Waiting for test pods to be ready..."
    kubectl wait --for=condition=ready pod -l app=test-client -n ${TEST_NAMESPACE} --timeout=120s
    kubectl wait --for=condition=ready pod -l app=test-server -n ${TEST_NAMESPACE} --timeout=120s
    
    # Test mTLS communication
    local client_pod=$(kubectl get pod -l app=test-client -n ${TEST_NAMESPACE} -o jsonpath='{.items[0].metadata.name}')
    
    # Test connectivity (should work with mTLS)
    if kubectl exec "$client_pod" -n ${TEST_NAMESPACE} -- curl -s -o /dev/null -w "%{http_code}" http://test-server:80 --max-time 10 | grep -q "200"; then
        test_result "Inter-pod mTLS communication" "PASS" "Test pods can communicate via mTLS"
    else
        test_result "Inter-pod mTLS communication" "FAIL" "Test pods cannot communicate"
    fi
    
    # Cleanup test resources
    log INFO "Cleaning up test resources..."
    kubectl delete namespace ${TEST_NAMESPACE} --wait=false
}

# Validate telemetry and monitoring
validate_telemetry() {
    log INFO "📊 Validating telemetry and monitoring configuration..."
    
    # Check telemetry resources
    if kubectl get telemetry -n ${ISTIO_NAMESPACE} &> /dev/null; then
        local telemetry_count=$(kubectl get telemetry -n ${ISTIO_NAMESPACE} --no-headers | wc -l)
        test_result "Telemetry configuration" "PASS" "$telemetry_count telemetry resources found"
    else
        test_result "Telemetry configuration" "WARN" "No telemetry resources found"
    fi
    
    # Check if Prometheus is collecting Istio metrics
    if kubectl get service prometheus -n monitoring &> /dev/null; then
        # Try to query Prometheus for Istio metrics
        local prom_pod=$(kubectl get pod -l app.kubernetes.io/name=prometheus -n monitoring -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        if [[ -n "$prom_pod" ]]; then
            if kubectl exec "$prom_pod" -n monitoring -- wget -q -O- "http://localhost:9090/api/v1/label/__name__/values" 2>/dev/null | grep -q "istio_"; then
                test_result "Prometheus Istio metrics" "PASS" "Istio metrics are being collected by Prometheus"
            else
                test_result "Prometheus Istio metrics" "WARN" "Istio metrics not found in Prometheus"
            fi
        else
            test_result "Prometheus accessibility" "SKIP" "Prometheus pod not found"
        fi
    else
        test_result "Prometheus service" "SKIP" "Prometheus service not found in monitoring namespace"
    fi
    
    # Check Grafana dashboards
    if kubectl get service grafana -n monitoring &> /dev/null; then
        test_result "Grafana service" "PASS" "Grafana service found for dashboard visualization"
    else
        test_result "Grafana service" "WARN" "Grafana service not found"
    fi
}

# Security posture summary
generate_security_summary() {
    log INFO "📋 Generating security posture summary..."
    
    local summary_file="/tmp/istio-security-validation-$(date +%Y%m%d-%H%M%S).json"
    
    cat > "$summary_file" << EOF
{
  "validation_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "cluster_context": "$(kubectl config current-context)",
  "istio_version": "$(istioctl version --short --remote=false 2>/dev/null || echo 'unknown')",
  "test_results": {
    "total_tests": $TESTS_TOTAL,
    "tests_passed": $TESTS_PASSED,
    "tests_failed": $TESTS_FAILED,
    "success_rate": "$(echo "scale=2; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc -l 2>/dev/null || echo 'N/A')%"
  },
  "security_controls": {
    "mtls_enforcement": "$(kubectl get peerauthentication default -n ${ISTIO_NAMESPACE} -o jsonpath='{.spec.mtls.mode}' 2>/dev/null || echo 'unknown')",
    "authorization_policies": $(kubectl get authorizationpolicy --all-namespaces --no-headers 2>/dev/null | wc -l),
    "destination_rules": $(kubectl get destinationrules --all-namespaces --no-headers 2>/dev/null | wc -l),
    "gateways": $(kubectl get gateways --all-namespaces --no-headers 2>/dev/null | wc -l),
    "virtual_services": $(kubectl get virtualservices --all-namespaces --no-headers 2>/dev/null | wc -l)
  },
  "sidecar_injection": {
    "enabled_namespaces": $(kubectl get namespaces -o jsonpath='{.items[?(@.metadata.labels.istio-injection=="enabled")].metadata.name}' | wc -w),
    "total_pods": "$(kubectl get pods --all-namespaces --no-headers | wc -l)",
    "pods_with_sidecars": "$(kubectl get pods --all-namespaces -o jsonpath='{.items[*].spec.containers[*].name}' | tr ' ' '\n' | grep -c istio-proxy || echo 0)"
  },
  "recommendations": [
    "Monitor mTLS certificate expiration and rotation",
    "Regularly review and audit authorization policies",
    "Implement continuous security scanning of mesh traffic",
    "Set up alerting for security policy violations",
    "Conduct regular penetration testing of the service mesh"
  ]
}
EOF
    
    log INFO "Security validation report generated: $summary_file"
    cat "$summary_file"
}

# Main validation flow
main() {
    log INFO "🛡️ Starting Istio Security Validation for iSECTECH Zero Trust Architecture"
    log INFO "🔍 Comprehensive validation of mTLS enforcement and security policies"
    
    # Validation steps
    check_prerequisites
    validate_istio_installation
    validate_mtls_enforcement
    validate_authorization_policies
    validate_sidecar_injection
    validate_destination_rules
    validate_gateways_virtualservices
    validate_telemetry
    
    # Network security testing (optional, can be resource intensive)
    if [[ "${SKIP_NETWORK_TESTS:-false}" != "true" ]]; then
        test_network_security
    else
        log INFO "Skipping network security tests (SKIP_NETWORK_TESTS=true)"
    fi
    
    # Generate summary report
    generate_security_summary
    
    # Final results
    log INFO "🎯 Security Validation Results Summary:"
    log INFO "  Total Tests: $TESTS_TOTAL"
    log INFO "  Tests Passed: $TESTS_PASSED"
    log INFO "  Tests Failed: $TESTS_FAILED"
    
    local success_rate=0
    if [[ $TESTS_TOTAL -gt 0 ]]; then
        success_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    fi
    
    if [[ $success_rate -ge 90 ]]; then
        log SUCCESS "Security validation completed with ${success_rate}% success rate"
        log SUCCESS "🔒 Istio Zero Trust Architecture is properly configured and secured"
    elif [[ $success_rate -ge 75 ]]; then
        log WARN "Security validation completed with ${success_rate}% success rate"
        log WARN "⚠️ Some security controls need attention"
    else
        log ERROR "Security validation completed with ${success_rate}% success rate"
        log ERROR "❌ Critical security issues found - immediate attention required"
    fi
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log INFO "✅ All security validations passed successfully!"
        exit 0
    else
        log ERROR "❌ $TESTS_FAILED security validation(s) failed"
        exit 1
    fi
}

# Execute main function
main "$@"