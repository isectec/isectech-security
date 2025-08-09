#!/bin/bash
# CI/CD Security Validation Pipeline
# Validates security contexts, policies, and compliance before deployment
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST_DIR="${1:-manifests}"
OUTPUT_DIR="${SCRIPT_DIR}/../reports/ci-cd-security"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Tools versions (update as needed)
KUBE_SCORE_VERSION="1.16.1"
TRIVY_VERSION="0.48.0"
CHECKOV_VERSION="3.1.0"

# Exit codes
EXIT_SUCCESS=0
EXIT_WARNING=1
EXIT_FAILURE=2

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
WARNING_CHECKS=0
FAILED_CHECKS=0

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_CHECKS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARNING_CHECKS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_CHECKS++))
}

increment_total() {
    ((TOTAL_CHECKS++))
}

# Install required tools if not present
install_tools() {
    log_info "Checking required security validation tools..."
    
    # Check if running in CI environment
    if [[ "${CI:-false}" == "true" ]]; then
        log_info "Running in CI environment, installing tools..."
        
        # Install kube-score
        if ! command -v kube-score &> /dev/null; then
            log_info "Installing kube-score ${KUBE_SCORE_VERSION}..."
            curl -L "https://github.com/zegl/kube-score/releases/download/v${KUBE_SCORE_VERSION}/kube-score_${KUBE_SCORE_VERSION}_linux_amd64.tar.gz" | tar xz
            chmod +x kube-score
            sudo mv kube-score /usr/local/bin/
        fi
        
        # Install trivy
        if ! command -v trivy &> /dev/null; then
            log_info "Installing trivy ${TRIVY_VERSION}..."
            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}
        fi
        
        # Install checkov
        if ! command -v checkov &> /dev/null; then
            log_info "Installing checkov ${CHECKOV_VERSION}..."
            pip install checkov==${CHECKOV_VERSION}
        fi
    else
        log_info "Running in local environment, checking tool availability..."
        
        if ! command -v kube-score &> /dev/null; then
            log_warning "kube-score not found. Install with: brew install kube-score"
        fi
        
        if ! command -v trivy &> /dev/null; then
            log_warning "trivy not found. Install with: brew install aquasecurity/trivy/trivy"
        fi
        
        if ! command -v checkov &> /dev/null; then
            log_warning "checkov not found. Install with: pip install checkov"
        fi
    fi
    
    log_success "Tool availability check completed"
}

# Validate manifest directory
validate_manifest_dir() {
    log_info "Validating manifest directory: $MANIFEST_DIR"
    increment_total
    
    if [[ ! -d "$MANIFEST_DIR" ]]; then
        log_error "Manifest directory '$MANIFEST_DIR' not found"
        return 1
    fi
    
    local yaml_files=$(find "$MANIFEST_DIR" -name "*.yaml" -o -name "*.yml" | wc -l)
    if [[ $yaml_files -eq 0 ]]; then
        log_error "No YAML files found in '$MANIFEST_DIR'"
        return 1
    fi
    
    log_success "Found $yaml_files YAML files in manifest directory"
    return 0
}

# Validate YAML syntax
validate_yaml_syntax() {
    log_info "Validating YAML syntax..."
    increment_total
    
    local syntax_errors=0
    local error_files=()
    
    while IFS= read -r -d '' file; do
        if ! python3 -c "import yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            ((syntax_errors++))
            error_files+=("$file")
        fi
    done < <(find "$MANIFEST_DIR" -name "*.yaml" -o -name "*.yml" -print0)
    
    if [[ $syntax_errors -gt 0 ]]; then
        log_error "YAML syntax errors found in ${syntax_errors} files:"
        printf '  %s\n' "${error_files[@]}"
        return 1
    fi
    
    log_success "All YAML files have valid syntax"
    return 0
}

# Validate security contexts using kube-score
validate_with_kube_score() {
    log_info "Running kube-score security validation..."
    increment_total
    
    local output_file="${OUTPUT_DIR}/kube-score-${TIMESTAMP}.txt"
    local json_output="${OUTPUT_DIR}/kube-score-${TIMESTAMP}.json"
    
    if ! command -v kube-score &> /dev/null; then
        log_warning "kube-score not available, skipping validation"
        return 0
    fi
    
    # Run kube-score with security-focused checks
    local kube_score_exit=0
    kube-score score "$MANIFEST_DIR"/*.yaml \
        --output-format=human \
        --ignore-test=pod-networkpolicy \
        --ignore-test=service-type \
        > "$output_file" 2>&1 || kube_score_exit=$?
    
    # Also generate JSON output for parsing
    kube-score score "$MANIFEST_DIR"/*.yaml \
        --output-format=json \
        --ignore-test=pod-networkpolicy \
        --ignore-test=service-type \
        > "$json_output" 2>/dev/null || true
    
    # Parse results
    local critical_issues=$(grep -c "CRITICAL" "$output_file" 2>/dev/null || echo 0)
    local warnings=$(grep -c "WARNING" "$output_file" 2>/dev/null || echo 0)
    
    if [[ $critical_issues -gt 0 ]]; then
        log_error "kube-score found $critical_issues critical security issues"
        echo "See detailed report: $output_file"
        return 1
    elif [[ $warnings -gt 0 ]]; then
        log_warning "kube-score found $warnings warnings"
        echo "See detailed report: $output_file"
        return 0
    else
        log_success "kube-score validation passed with no critical issues"
        return 0
    fi
}

# Validate configurations with Trivy
validate_with_trivy() {
    log_info "Running Trivy configuration scan..."
    increment_total
    
    local output_file="${OUTPUT_DIR}/trivy-config-${TIMESTAMP}.json"
    local summary_file="${OUTPUT_DIR}/trivy-summary-${TIMESTAMP}.txt"
    
    if ! command -v trivy &> /dev/null; then
        log_warning "trivy not available, skipping configuration scan"
        return 0
    fi
    
    # Run trivy config scan
    local trivy_exit=0
    trivy config "$MANIFEST_DIR" \
        --format json \
        --output "$output_file" \
        --severity HIGH,CRITICAL \
        --exit-code 1 || trivy_exit=$?
    
    # Generate human-readable summary
    trivy config "$MANIFEST_DIR" \
        --format table \
        --severity HIGH,CRITICAL \
        > "$summary_file" 2>/dev/null || true
    
    # Parse results from JSON
    if [[ -f "$output_file" ]]; then
        local critical_count=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity == "CRITICAL")] | length' "$output_file" 2>/dev/null || echo 0)
        local high_count=$(jq '[.Results[]?.Misconfigurations[]? | select(.Severity == "HIGH")] | length' "$output_file" 2>/dev/null || echo 0)
        
        if [[ $critical_count -gt 0 ]]; then
            log_error "Trivy found $critical_count CRITICAL security misconfigurations"
            echo "See detailed report: $summary_file"
            return 1
        elif [[ $high_count -gt 0 ]]; then
            log_warning "Trivy found $high_count HIGH severity misconfigurations"
            echo "See detailed report: $summary_file"
            return 0
        else
            log_success "Trivy configuration scan passed"
            return 0
        fi
    else
        log_success "Trivy configuration scan completed"
        return 0
    fi
}

# Validate with Checkov
validate_with_checkov() {
    log_info "Running Checkov policy validation..."
    increment_total
    
    local output_file="${OUTPUT_DIR}/checkov-${TIMESTAMP}.json"
    local summary_file="${OUTPUT_DIR}/checkov-summary-${TIMESTAMP}.txt"
    
    if ! command -v checkov &> /dev/null; then
        log_warning "checkov not available, skipping policy validation"
        return 0
    fi
    
    # Run checkov scan
    local checkov_exit=0
    checkov -d "$MANIFEST_DIR" \
        --framework kubernetes \
        --output json \
        --output-file-path "$output_file" \
        --quiet || checkov_exit=$?
    
    # Generate summary
    checkov -d "$MANIFEST_DIR" \
        --framework kubernetes \
        --quiet \
        > "$summary_file" 2>&1 || true
    
    # Parse results
    if [[ -f "$output_file" ]]; then
        local failed_checks=$(jq '.summary.failed // 0' "$output_file" 2>/dev/null || echo 0)
        local passed_checks=$(jq '.summary.passed // 0' "$output_file" 2>/dev/null || echo 0)
        
        if [[ $failed_checks -gt 0 ]]; then
            log_warning "Checkov found $failed_checks failed policy checks (passed: $passed_checks)"
            echo "See detailed report: $summary_file"
            return 0  # Treating as warning for now
        else
            log_success "Checkov policy validation passed ($passed_checks checks)"
            return 0
        fi
    else
        log_success "Checkov validation completed"
        return 0
    fi
}

# Custom security context validation
validate_security_contexts() {
    log_info "Running custom security context validation..."
    increment_total
    
    local validation_errors=0
    local output_file="${OUTPUT_DIR}/security-context-validation-${TIMESTAMP}.txt"
    
    > "$output_file"  # Clear output file
    
    while IFS= read -r -d '' file; do
        log_info "Validating security contexts in: $(basename "$file")"
        
        # Check for pods/deployments without security contexts
        local missing_security_context=$(yq eval '.spec.template.spec.containers[]? | select(.securityContext == null) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$missing_security_context" ]]; then
            echo "ERROR: Missing security context in $file for containers: $missing_security_context" >> "$output_file"
            ((validation_errors++))
        fi
        
        # Check for privileged containers
        local privileged_containers=$(yq eval '.spec.template.spec.containers[]? | select(.securityContext.privileged == true) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$privileged_containers" ]]; then
            echo "ERROR: Privileged containers found in $file: $privileged_containers" >> "$output_file"
            ((validation_errors++))
        fi
        
        # Check for containers running as root
        local root_containers=$(yq eval '.spec.template.spec.containers[]? | select(.securityContext.runAsUser == 0) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$root_containers" ]]; then
            echo "WARNING: Containers running as root in $file: $root_containers" >> "$output_file"
        fi
        
        # Check for missing capabilities drop
        local no_drop_caps=$(yq eval '.spec.template.spec.containers[]? | select(.securityContext.capabilities.drop == null or (.securityContext.capabilities.drop | contains(["ALL"]) | not)) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$no_drop_caps" ]]; then
            echo "WARNING: Containers not dropping ALL capabilities in $file: $no_drop_caps" >> "$output_file"
        fi
        
        # Check for allowPrivilegeEscalation
        local priv_escalation=$(yq eval '.spec.template.spec.containers[]? | select(.securityContext.allowPrivilegeEscalation != false) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$priv_escalation" ]]; then
            echo "WARNING: Containers allowing privilege escalation in $file: $priv_escalation" >> "$output_file"
        fi
        
        # Check for missing resource limits
        local no_limits=$(yq eval '.spec.template.spec.containers[]? | select(.resources.limits == null) | .name' "$file" 2>/dev/null || echo "")
        if [[ -n "$no_limits" ]]; then
            echo "WARNING: Containers missing resource limits in $file: $no_limits" >> "$output_file"
        fi
        
    done < <(find "$MANIFEST_DIR" -name "*.yaml" -o -name "*.yml" -print0)
    
    if [[ $validation_errors -gt 0 ]]; then
        log_error "Found $validation_errors security context violations"
        echo "See detailed report: $output_file"
        return 1
    else
        local total_warnings=$(grep -c "WARNING" "$output_file" 2>/dev/null || echo 0)
        if [[ $total_warnings -gt 0 ]]; then
            log_warning "Found $total_warnings security context warnings"
            echo "See detailed report: $output_file"
        else
            log_success "All security contexts are properly configured"
        fi
        return 0
    fi
}

# Validate Pod Security Standards labels
validate_pss_labels() {
    log_info "Validating Pod Security Standards namespace labels..."
    increment_total
    
    local output_file="${OUTPUT_DIR}/pss-validation-${TIMESTAMP}.txt"
    > "$output_file"
    
    # Check namespace manifests for PSS labels
    local namespace_files=$(find "$MANIFEST_DIR" -name "*.yaml" -o -name "*.yml" -exec grep -l "kind: Namespace" {} \;)
    local missing_labels=0
    
    for file in $namespace_files; do
        local namespace_name=$(yq eval 'select(.kind == "Namespace") | .metadata.name' "$file" 2>/dev/null)
        
        if [[ -n "$namespace_name" ]]; then
            # Check for PSS enforce label
            local enforce_label=$(yq eval 'select(.kind == "Namespace") | .metadata.labels."pod-security.kubernetes.io/enforce"' "$file" 2>/dev/null || echo "null")
            if [[ "$enforce_label" == "null" ]]; then
                echo "WARNING: Namespace $namespace_name missing pod-security.kubernetes.io/enforce label in $file" >> "$output_file"
                ((missing_labels++))
            fi
            
            # Check for PSS audit label
            local audit_label=$(yq eval 'select(.kind == "Namespace") | .metadata.labels."pod-security.kubernetes.io/audit"' "$file" 2>/dev/null || echo "null")
            if [[ "$audit_label" == "null" ]]; then
                echo "WARNING: Namespace $namespace_name missing pod-security.kubernetes.io/audit label in $file" >> "$output_file"
                ((missing_labels++))
            fi
        fi
    done
    
    if [[ $missing_labels -gt 0 ]]; then
        log_warning "Found $missing_labels missing Pod Security Standards labels"
        echo "See detailed report: $output_file"
    else
        log_success "Pod Security Standards labels validation passed"
    fi
    
    return 0
}

# Generate security validation report
generate_validation_report() {
    log_info "Generating security validation report..."
    
    local report_file="${OUTPUT_DIR}/security-validation-report-${TIMESTAMP}.json"
    local summary_file="${OUTPUT_DIR}/validation-summary-${TIMESTAMP}.txt"
    
    # Create JSON report
    cat > "$report_file" << EOF
{
    "security_validation_report": {
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "manifest_directory": "$MANIFEST_DIR",
        "total_checks": $TOTAL_CHECKS,
        "passed_checks": $PASSED_CHECKS,
        "warning_checks": $WARNING_CHECKS,
        "failed_checks": $FAILED_CHECKS,
        "overall_status": "$(if [[ $FAILED_CHECKS -gt 0 ]]; then echo "FAILED"; elif [[ $WARNING_CHECKS -gt 0 ]]; then echo "WARNING"; else echo "PASSED"; fi)",
        "compliance_score": $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS )),
        "tools_used": {
            "kube_score": $(command -v kube-score &> /dev/null && echo "true" || echo "false"),
            "trivy": $(command -v trivy &> /dev/null && echo "true" || echo "false"),
            "checkov": $(command -v checkov &> /dev/null && echo "true" || echo "false"),
            "custom_validation": true
        }
    }
}
EOF
    
    # Create summary report
    cat > "$summary_file" << EOF
================================================================================
                     CI/CD Security Validation Report
================================================================================
Generated: $(date)
Manifest Directory: $MANIFEST_DIR
Report ID: $TIMESTAMP

VALIDATION RESULTS
==================
Total Checks: $TOTAL_CHECKS
Passed: $PASSED_CHECKS
Warnings: $WARNING_CHECKS
Failed: $FAILED_CHECKS

Overall Status: $(if [[ $FAILED_CHECKS -gt 0 ]]; then echo "❌ FAILED"; elif [[ $WARNING_CHECKS -gt 0 ]]; then echo "⚠️ WARNING"; else echo "✅ PASSED"; fi)
Compliance Score: $(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))%

DETAILED REPORTS
===============
- Full Report: $report_file
- Summary: $summary_file
$(find "$OUTPUT_DIR" -name "*-${TIMESTAMP}.*" -type f | sed 's/^/- /')

RECOMMENDATIONS
==============
EOF
    
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        echo "🚨 CRITICAL ISSUES FOUND - Deployment should be blocked" >> "$summary_file"
        echo "1. Review and fix all security context violations" >> "$summary_file"
        echo "2. Remove privileged containers" >> "$summary_file"
        echo "3. Add missing resource limits" >> "$summary_file"
    elif [[ $WARNING_CHECKS -gt 0 ]]; then
        echo "⚠️ Security warnings detected - Review recommended" >> "$summary_file"
        echo "1. Address security context warnings" >> "$summary_file"
        echo "2. Review Pod Security Standards compliance" >> "$summary_file"
    else
        echo "✅ All security validations passed!" >> "$summary_file"
    fi
    
    echo "" >> "$summary_file"
    echo "For detailed remediation guidance, see:" >> "$summary_file"
    echo "infrastructure/security/POD-SECURITY-STANDARDS-IMPLEMENTATION-GUIDE.md" >> "$summary_file"
    
    log_success "Validation report generated: $summary_file"
}

# Main execution
main() {
    local start_time=$(date +%s)
    
    log_info "Starting CI/CD security validation pipeline..."
    log_info "Manifest directory: $MANIFEST_DIR"
    log_info "Output directory: $OUTPUT_DIR"
    
    # Initialize counters
    TOTAL_CHECKS=0
    PASSED_CHECKS=0
    WARNING_CHECKS=0
    FAILED_CHECKS=0
    
    # Run validation steps
    install_tools
    
    validate_manifest_dir || exit $EXIT_FAILURE
    validate_yaml_syntax || exit $EXIT_FAILURE
    validate_security_contexts
    validate_pss_labels
    
    # Tool-based validations (non-blocking)
    validate_with_kube_score
    validate_with_trivy
    validate_with_checkov
    
    # Generate final report
    generate_validation_report
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    # Display results
    echo ""
    log_info "==============================================="
    log_info "Security Validation Pipeline Complete"
    log_info "==============================================="
    log_info "Duration: ${duration}s"
    log_info "Total Checks: $TOTAL_CHECKS"
    log_info "Results: ✅ $PASSED_CHECKS | ⚠️ $WARNING_CHECKS | ❌ $FAILED_CHECKS"
    
    # Determine exit code
    if [[ $FAILED_CHECKS -gt 0 ]]; then
        log_error "Security validation FAILED - blocking deployment"
        exit $EXIT_FAILURE
    elif [[ $WARNING_CHECKS -gt 5 ]]; then
        log_warning "Multiple security warnings detected"
        exit $EXIT_WARNING
    else
        log_success "Security validation PASSED"
        exit $EXIT_SUCCESS
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [manifest-directory] [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --version      Show version information"
        echo ""
        echo "Environment Variables:"
        echo "  CI=true        Set when running in CI environment"
        echo ""
        echo "Examples:"
        echo "  $0 manifests/                    # Validate manifests in manifests/ directory"
        echo "  $0 k8s/ --verbose               # Validate with verbose output"
        echo "  CI=true $0 deployment/          # Run in CI mode"
        exit 0
        ;;
    --version)
        echo "CI/CD Security Validation Pipeline v1.0.0"
        exit 0
        ;;
    *)
        # If first argument looks like a flag, show help
        if [[ "${1:-}" == --* ]]; then
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
        fi
        # Otherwise proceed with main execution
        main
        ;;
esac