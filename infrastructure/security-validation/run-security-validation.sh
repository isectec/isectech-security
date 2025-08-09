#!/bin/bash
"""
Multi-Region Security Validation Orchestrator
Production-grade security validation runner for all test suites
Integrates penetration testing, compliance, encryption, and IAM validation
"""

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/regions-config.json"
OUTPUT_DIR="${SCRIPT_DIR}/security_validation_reports"
LOG_FILE="${OUTPUT_DIR}/security_validation.log"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Initialize logging
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log() {
    local level="$1"
    shift
    local color=""
    case "$level" in
        "ERROR") color="$RED" ;;
        "SUCCESS") color="$GREEN" ;;
        "WARNING") color="$YELLOW" ;;
        "INFO") color="$BLUE" ;;
        "CRITICAL") color="$PURPLE" ;;
    esac
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] [${color}${level}${NC}] $*"
}

error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "================================================================="
    echo "           iSECTECH Multi-Region Security Validation"
    echo "================================================================="
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Configuration: $CONFIG_FILE"
    echo "Output Directory: $OUTPUT_DIR"
    echo "================================================================="
    echo -e "${NC}"
}

# Check dependencies
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local deps=("python3" "pip3" "openssl" "curl" "jq" "nmap")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log "ERROR" "Missing dependencies: ${missing_deps[*]}"
        log "INFO" "Install missing dependencies and retry"
        exit 1
    fi
    
    # Check Python packages
    log "INFO" "Checking Python packages..."
    local python_packages=("requests" "cryptography" "jwt" "geoip2" "whois" "dnspython")
    local missing_packages=()
    
    for package in "${python_packages[@]}"; do
        if ! python3 -c "import $package" 2>/dev/null; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log "WARNING" "Installing missing Python packages: ${missing_packages[*]}"
        pip3 install "${missing_packages[@]}" || log "WARNING" "Some packages may not have installed correctly"
    fi
    
    log "SUCCESS" "All dependencies satisfied"
}

# Validate configuration
validate_configuration() {
    log "INFO" "Validating configuration file..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        error_exit "Configuration file not found: $CONFIG_FILE"
    fi
    
    # Validate JSON structure
    if ! jq empty "$CONFIG_FILE" 2>/dev/null; then
        error_exit "Invalid JSON in configuration file"
    fi
    
    # Check required fields
    local required_fields=(".regions" ".test_config")
    for field in "${required_fields[@]}"; do
        if ! jq -e "$field" "$CONFIG_FILE" >/dev/null; then
            error_exit "Missing required field in config: $field"
        fi
    done
    
    # Validate regions
    local region_count
    region_count=$(jq '.regions | length' "$CONFIG_FILE")
    if [[ "$region_count" -eq 0 ]]; then
        error_exit "No regions defined in configuration"
    fi
    
    log "SUCCESS" "Configuration validated ($region_count regions configured)"
}

# Run penetration testing
run_penetration_testing() {
    local test_name="Penetration Testing"
    local output_file="${OUTPUT_DIR}/penetration_testing_${TIMESTAMP}.json"
    
    log "INFO" "Starting $test_name..."
    
    if python3 "${SCRIPT_DIR}/multi-region-penetration-testing.py" \
        --config "$CONFIG_FILE" \
        --output "$output_file" \
        --log-level INFO; then
        log "SUCCESS" "$test_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 2 ]]; then
            log "CRITICAL" "$test_name found critical security issues"
        elif [[ $exit_code -eq 1 ]]; then
            log "WARNING" "$test_name found high-priority security issues"
        else
            log "ERROR" "$test_name failed to complete"
        fi
        return $exit_code
    fi
}

# Run data residency compliance testing
run_data_residency_testing() {
    local test_name="Data Residency Compliance Testing"
    local output_dir="${OUTPUT_DIR}/data_residency_${TIMESTAMP}"
    
    log "INFO" "Starting $test_name..."
    
    if python3 "${SCRIPT_DIR}/data-residency-compliance.py" \
        --config "$CONFIG_FILE" \
        --output-dir "$output_dir"; then
        log "SUCCESS" "$test_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 1 ]]; then
            log "CRITICAL" "$test_name found compliance violations"
        else
            log "ERROR" "$test_name failed to complete"
        fi
        return $exit_code
    fi
}

# Run encryption validation
run_encryption_validation() {
    local test_name="Encryption Validation"
    
    log "INFO" "Starting $test_name..."
    
    # Set environment variables for encryption script
    export CONFIG_FILE="$CONFIG_FILE"
    export OUTPUT_DIR="${OUTPUT_DIR}/encryption_${TIMESTAMP}"
    
    if bash "${SCRIPT_DIR}/encryption-validation.sh"; then
        log "SUCCESS" "$test_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 2 ]]; then
            log "CRITICAL" "$test_name found critical encryption issues"
        elif [[ $exit_code -eq 1 ]]; then
            log "WARNING" "$test_name found high-priority encryption issues"
        else
            log "ERROR" "$test_name failed to complete"
        fi
        return $exit_code
    fi
}

# Run IAM and access control testing
run_iam_testing() {
    local test_name="IAM and Access Control Testing"
    local output_dir="${OUTPUT_DIR}/iam_${TIMESTAMP}"
    
    log "INFO" "Starting $test_name..."
    
    if python3 "${SCRIPT_DIR}/iam-access-control-testing.py" \
        --config "$CONFIG_FILE" \
        --output-dir "$output_dir"; then
        log "SUCCESS" "$test_name completed successfully"
        return 0
    else
        local exit_code=$?
        if [[ $exit_code -eq 2 ]]; then
            log "CRITICAL" "$test_name found critical IAM vulnerabilities"
        elif [[ $exit_code -eq 1 ]]; then
            log "WARNING" "$test_name found high-priority IAM issues"
        else
            log "ERROR" "$test_name failed to complete"
        fi
        return $exit_code
    fi
}

# Generate consolidated report
generate_consolidated_report() {
    local consolidated_report="${OUTPUT_DIR}/consolidated_security_report_${TIMESTAMP}.json"
    
    log "INFO" "Generating consolidated security report..."
    
    # Collect all individual reports
    local reports=()
    
    # Find all JSON reports in subdirectories
    while IFS= read -r -d '' report_file; do
        if [[ -f "$report_file" ]]; then
            reports+=("$report_file")
        fi
    done < <(find "${OUTPUT_DIR}" -name "*.json" -type f -print0 2>/dev/null)
    
    # Start building consolidated report
    cat > "$consolidated_report" <<EOF
{
    "report_metadata": {
        "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "report_type": "consolidated_security_validation",
        "version": "1.0",
        "timestamp": "$TIMESTAMP"
    },
    "test_execution_summary": {
EOF
    
    # Add test results
    local total_tests=0
    local total_critical=0
    local total_high=0
    local total_medium=0
    local total_low=0
    local test_results=()
    
    for report_file in "${reports[@]}"; do
        if [[ -f "$report_file" ]]; then
            local report_name
            report_name=$(basename "$report_file" .json)
            
            # Extract summary information
            local critical_count=0
            local high_count=0
            local test_count=0
            
            # Try to extract counts from different report formats
            if critical_count=$(jq '.executive_summary.critical_issues_count // 0' "$report_file" 2>/dev/null); then
                high_count=$(jq '.executive_summary.high_issues_count // 0' "$report_file" 2>/dev/null)
                test_count=$(jq '.executive_summary.total_tests // 0' "$report_file" 2>/dev/null)
            elif critical_count=$(jq '.summary.critical_issues_count // 0' "$report_file" 2>/dev/null); then
                high_count=$(jq '.summary.high_issues_count // 0' "$report_file" 2>/dev/null)
                test_count=$(jq '.summary.total_tests // 0' "$report_file" 2>/dev/null)
            fi
            
            total_tests=$((total_tests + test_count))
            total_critical=$((total_critical + critical_count))
            total_high=$((total_high + high_count))
            
            test_results+=("\"$report_name\": {\"tests\": $test_count, \"critical\": $critical_count, \"high\": $high_count}")
        fi
    done
    
    # Complete the JSON structure
    cat >> "$consolidated_report" <<EOF
        "total_tests_executed": $total_tests,
        "total_critical_issues": $total_critical,
        "total_high_issues": $total_high,
        "test_suite_results": {
            $(IFS=','; echo "${test_results[*]}")
        }
    },
    "overall_risk_assessment": {
        "risk_level": "$(get_overall_risk_level "$total_critical" "$total_high")",
        "security_score": $(calculate_security_score "$total_tests" "$total_critical" "$total_high"),
        "compliance_status": "$(get_compliance_status "$total_critical" "$total_high")"
    },
    "recommendations": [
        $(generate_consolidated_recommendations "$total_critical" "$total_high")
    ],
    "individual_reports": [
        $(for report in "${reports[@]}"; do
            if [[ -f "$report" ]]; then
                echo "\"$(basename "$report")\","
            fi
        done | sed '$ s/,$//')
    ]
}
EOF
    
    log "SUCCESS" "Consolidated report generated: $consolidated_report"
    return 0
}

# Helper function to determine overall risk level
get_overall_risk_level() {
    local critical_count="$1"
    local high_count="$2"
    
    if [[ "$critical_count" -gt 0 ]]; then
        echo "CRITICAL"
    elif [[ "$high_count" -gt 5 ]]; then
        echo "HIGH"
    elif [[ "$high_count" -gt 0 ]]; then
        echo "MEDIUM"
    else
        echo "LOW"
    fi
}

# Helper function to calculate security score
calculate_security_score() {
    local total_tests="$1"
    local critical_count="$2"
    local high_count="$3"
    
    if [[ "$total_tests" -eq 0 ]]; then
        echo "0"
        return
    fi
    
    local score=100
    score=$((score - critical_count * 25))
    score=$((score - high_count * 10))
    
    if [[ "$score" -lt 0 ]]; then
        score=0
    fi
    
    echo "$score"
}

# Helper function to determine compliance status
get_compliance_status() {
    local critical_count="$1"
    local high_count="$2"
    
    if [[ "$critical_count" -gt 0 ]]; then
        echo "NON_COMPLIANT"
    elif [[ "$high_count" -gt 3 ]]; then
        echo "PARTIALLY_COMPLIANT"
    else
        echo "COMPLIANT"
    fi
}

# Helper function to generate consolidated recommendations
generate_consolidated_recommendations() {
    local critical_count="$1"
    local high_count="$2"
    
    local recommendations=()
    
    if [[ "$critical_count" -gt 0 ]]; then
        recommendations+=('"Immediate remediation required for critical security vulnerabilities"')
        recommendations+=('"Implement emergency security patches and controls"')
    fi
    
    if [[ "$high_count" -gt 0 ]]; then
        recommendations+=('"Address high-priority security issues within 30 days"')
        recommendations+=('"Review and enhance security controls and monitoring"')
    fi
    
    recommendations+=('"Conduct regular security validation testing"')
    recommendations+=('"Implement continuous security monitoring and alerting"')
    recommendations+=('"Update security policies and procedures based on findings"')
    
    IFS=','; echo "${recommendations[*]}"
}

# Display final summary
display_final_summary() {
    local consolidated_report="${OUTPUT_DIR}/consolidated_security_report_${TIMESTAMP}.json"
    
    if [[ ! -f "$consolidated_report" ]]; then
        log "WARNING" "Consolidated report not found, generating summary from logs"
        return
    fi
    
    echo ""
    echo -e "${CYAN}=================================================================${NC}"
    echo -e "${CYAN}                    FINAL SECURITY SUMMARY${NC}"
    echo -e "${CYAN}=================================================================${NC}"
    
    local total_tests
    local total_critical
    local total_high
    local risk_level
    local security_score
    local compliance_status
    
    total_tests=$(jq -r '.test_execution_summary.total_tests_executed' "$consolidated_report" 2>/dev/null || echo "N/A")
    total_critical=$(jq -r '.test_execution_summary.total_critical_issues' "$consolidated_report" 2>/dev/null || echo "N/A")
    total_high=$(jq -r '.test_execution_summary.total_high_issues' "$consolidated_report" 2>/dev/null || echo "N/A")
    risk_level=$(jq -r '.overall_risk_assessment.risk_level' "$consolidated_report" 2>/dev/null || echo "N/A")
    security_score=$(jq -r '.overall_risk_assessment.security_score' "$consolidated_report" 2>/dev/null || echo "N/A")
    compliance_status=$(jq -r '.overall_risk_assessment.compliance_status' "$consolidated_report" 2>/dev/null || echo "N/A")
    
    echo -e "Total Security Tests Executed: ${BLUE}$total_tests${NC}"
    echo -e "Critical Issues Found: ${RED}$total_critical${NC}"
    echo -e "High Priority Issues Found: ${YELLOW}$total_high${NC}"
    echo -e "Overall Risk Level: ${PURPLE}$risk_level${NC}"
    echo -e "Security Score: ${GREEN}$security_score/100${NC}"
    echo -e "Compliance Status: ${CYAN}$compliance_status${NC}"
    
    echo ""
    echo -e "${CYAN}Test Suite Breakdown:${NC}"
    
    # Extract and display individual test results
    if jq -e '.test_execution_summary.test_suite_results' "$consolidated_report" >/dev/null 2>&1; then
        jq -r '.test_execution_summary.test_suite_results | to_entries[] | "  \(.key): \(.value.tests) tests, \(.value.critical) critical, \(.value.high) high"' "$consolidated_report" 2>/dev/null || echo "  Unable to parse test results"
    fi
    
    echo ""
    echo -e "${CYAN}Key Recommendations:${NC}"
    
    if jq -e '.recommendations' "$consolidated_report" >/dev/null 2>&1; then
        jq -r '.recommendations[] | "  • \(.)"' "$consolidated_report" 2>/dev/null || echo "  No recommendations available"
    fi
    
    echo ""
    echo -e "${CYAN}Reports Generated:${NC}"
    echo -e "  • Consolidated Report: ${consolidated_report}"
    echo -e "  • Individual Reports: ${OUTPUT_DIR}/"
    echo ""
    echo -e "${CYAN}=================================================================${NC}"
}

# Main execution function
main() {
    local start_time
    start_time=$(date +%s)
    
    print_banner
    
    log "INFO" "Starting multi-region security validation..."
    
    # Pre-flight checks
    check_dependencies
    validate_configuration
    
    # Initialize test results tracking
    local test_results=()
    local overall_exit_code=0
    
    # Run test suites
    log "INFO" "Executing security test suites..."
    
    # Penetration Testing
    if run_penetration_testing; then
        test_results+=("Penetration Testing: PASSED")
    else
        local pen_exit=$?
        test_results+=("Penetration Testing: FAILED (Exit Code: $pen_exit)")
        [[ $pen_exit -gt $overall_exit_code ]] && overall_exit_code=$pen_exit
    fi
    
    # Data Residency Compliance
    if run_data_residency_testing; then
        test_results+=("Data Residency Compliance: PASSED")
    else
        local dr_exit=$?
        test_results+=("Data Residency Compliance: FAILED (Exit Code: $dr_exit)")
        [[ $dr_exit -gt $overall_exit_code ]] && overall_exit_code=$dr_exit
    fi
    
    # Encryption Validation
    if run_encryption_validation; then
        test_results+=("Encryption Validation: PASSED")
    else
        local enc_exit=$?
        test_results+=("Encryption Validation: FAILED (Exit Code: $enc_exit)")
        [[ $enc_exit -gt $overall_exit_code ]] && overall_exit_code=$enc_exit
    fi
    
    # IAM and Access Control Testing
    if run_iam_testing; then
        test_results+=("IAM Access Control: PASSED")
    else
        local iam_exit=$?
        test_results+=("IAM Access Control: FAILED (Exit Code: $iam_exit)")
        [[ $iam_exit -gt $overall_exit_code ]] && overall_exit_code=$iam_exit
    fi
    
    # Generate consolidated report
    generate_consolidated_report
    
    # Calculate total execution time
    local end_time
    end_time=$(date +%s)
    local total_time=$((end_time - start_time))
    
    log "INFO" "All security validation tests completed in ${total_time}s"
    
    # Display results summary
    echo ""
    echo -e "${BLUE}Individual Test Results:${NC}"
    for result in "${test_results[@]}"; do
        echo -e "  $result"
    done
    
    # Display final summary
    display_final_summary
    
    # Determine final exit code and message
    case $overall_exit_code in
        0)
            log "SUCCESS" "All security validation tests passed successfully"
            ;;
        1)
            log "WARNING" "Security validation completed with warnings/high-priority issues"
            ;;
        2)
            log "CRITICAL" "Security validation found critical security vulnerabilities"
            ;;
        *)
            log "ERROR" "Security validation encountered errors during execution"
            ;;
    esac
    
    exit $overall_exit_code
}

# Handle script interruption
cleanup() {
    log "WARNING" "Security validation interrupted by user"
    log "INFO" "Partial results may be available in: $OUTPUT_DIR"
    exit 130
}

trap cleanup SIGINT SIGTERM

# Check if running as main script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi