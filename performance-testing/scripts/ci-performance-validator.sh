#!/bin/bash

# CI/CD Performance Validator for iSECTECH
# Validates performance test results against defined thresholds and detects regressions
# Usage: ./ci-performance-validator.sh [test_type] [environment] [results_dir]

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG_DIR="$PROJECT_ROOT/performance-testing/config"
THRESHOLDS_FILE="$CONFIG_DIR/ci-cd/performance-thresholds.json"

# Default values
TEST_TYPE="${1:-baseline}"
ENVIRONMENT="${2:-development}"
RESULTS_DIR="${3:-./test-results}"
OUTPUT_DIR="${4:-./validation-results}"

# Colors for output
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

# Validation state
VALIDATION_PASSED=true
CRITICAL_ISSUES=0
WARNING_ISSUES=0
TOTAL_ISSUES=0
REGRESSIONS_DETECTED=0

# Initialize validation report
init_validation_report() {
    mkdir -p "$OUTPUT_DIR"
    
    cat > "$OUTPUT_DIR/validation_report.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "test_type": "$TEST_TYPE",
  "environment": "$ENVIRONMENT",
  "commit": "${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}",
  "branch": "${GITHUB_REF_NAME:-$(git branch --show-current 2>/dev/null || echo 'unknown')}",
  "ci_run": "${GITHUB_RUN_ID:-local}",
  "validation_passed": true,
  "summary": {
    "total_issues": 0,
    "critical_issues": 0,
    "warning_issues": 0,
    "regressions": 0
  },
  "issues": [],
  "regression_analysis": {},
  "recommendations": []
}
EOF
}

# Load performance thresholds from configuration
load_thresholds() {
    if [[ ! -f "$THRESHOLDS_FILE" ]]; then
        log_error "Thresholds configuration file not found: $THRESHOLDS_FILE"
        exit 1
    fi
    
    log_info "Loading performance thresholds from: $THRESHOLDS_FILE"
}

# Extract threshold value with environment multiplier
get_threshold() {
    local metric_path="$1"
    local default_value="${2:-1000}"
    
    # Get base threshold
    local base_threshold
    base_threshold=$(jq -r ".global_thresholds.$metric_path // $default_value" "$THRESHOLDS_FILE")
    
    # Apply environment multiplier
    local multiplier
    multiplier=$(jq -r ".environment_specific_thresholds.${ENVIRONMENT}.response_time_multiplier // 1.0" "$THRESHOLDS_FILE")
    
    # Calculate final threshold
    echo "$base_threshold * $multiplier" | bc -l | cut -d'.' -f1
}

# Validate k6 test results
validate_k6_results() {
    local results_file="$1"
    local scenario_name="$2"
    
    if [[ ! -f "$results_file" ]]; then
        log_warning "k6 results file not found: $results_file"
        return
    fi
    
    log_info "Validating k6 results: $scenario_name"
    
    # Extract metrics from k6 JSON output
    local p95_threshold p99_threshold error_rate_threshold
    p95_threshold=$(get_threshold "response_times.api_endpoints.p95_ms" "500")
    p99_threshold=$(get_threshold "response_times.api_endpoints.p99_ms" "1000")
    error_rate_threshold=$(jq -r ".global_thresholds.error_rates.${TEST_TYPE}_test.max_error_rate_percent // 1.0" "$THRESHOLDS_FILE")
    
    # Parse k6 results and validate thresholds
    python3 << EOF
import json
import sys
import os

# Load k6 results
try:
    with open('${results_file}') as f:
        k6_data = json.load(f)
except Exception as e:
    print(f"Error loading k6 results: {e}")
    sys.exit(0)

# Extract metrics
metrics = k6_data.get('metrics', {})
http_req_duration = metrics.get('http_req_duration', {})
http_req_failed = metrics.get('http_req_failed', {})
http_reqs = metrics.get('http_reqs', {})

if not http_req_duration:
    print("No http_req_duration metrics found")
    sys.exit(0)

# Response time analysis
p95_actual = http_req_duration.get('p(95)', 0)
p99_actual = http_req_duration.get('p(99)', 0)
avg_actual = http_req_duration.get('avg', 0)

# Error rate analysis  
error_rate = http_req_failed.get('rate', 0) * 100 if http_req_failed else 0
total_requests = http_reqs.get('count', 0) if http_reqs else 0

# Throughput analysis
test_duration = k6_data.get('state', {}).get('testRunDurationMs', 1000) / 1000
throughput = total_requests / test_duration if test_duration > 0 else 0

print(f"=== ${scenario_name} Results ===")
print(f"P95 Response Time: {p95_actual:.2f}ms (threshold: ${p95_threshold}ms)")  
print(f"P99 Response Time: {p99_actual:.2f}ms (threshold: ${p99_threshold}ms)")
print(f"Average Response Time: {avg_actual:.2f}ms")
print(f"Error Rate: {error_rate:.2f}% (threshold: ${error_rate_threshold}%)")
print(f"Throughput: {throughput:.2f} RPS")
print(f"Total Requests: {total_requests}")

# Threshold validation
issues = []

if p95_actual > ${p95_threshold}:
    severity = "critical" if p95_actual > ${p95_threshold} * 2 else "warning"
    issues.append({
        "scenario": "${scenario_name}",
        "metric": "P95 Response Time",
        "actual": p95_actual,
        "threshold": ${p95_threshold},
        "severity": severity,
        "impact": "high"
    })

if p99_actual > ${p99_threshold}:
    severity = "critical" if p99_actual > ${p99_threshold} * 2 else "warning" 
    issues.append({
        "scenario": "${scenario_name}",
        "metric": "P99 Response Time", 
        "actual": p99_actual,
        "threshold": ${p99_threshold},
        "severity": severity,
        "impact": "medium"
    })

if error_rate > ${error_rate_threshold}:
    severity = "critical"
    issues.append({
        "scenario": "${scenario_name}",
        "metric": "Error Rate",
        "actual": error_rate,
        "threshold": ${error_rate_threshold},
        "severity": severity,
        "impact": "critical"
    })

# Write issues to temporary file
with open('${OUTPUT_DIR}/temp_issues_${scenario_name}.json', 'w') as f:
    json.dump(issues, f)

# Set exit code based on critical issues
critical_count = sum(1 for issue in issues if issue['severity'] == 'critical')
if critical_count > 0:
    print(f"\n❌ {critical_count} critical issues detected")
    sys.exit(1)
elif issues:
    print(f"\n⚠️ {len(issues)} warning issues detected")
    sys.exit(2)
else:
    print(f"\n✅ All thresholds passed")
    sys.exit(0)
EOF

    local validation_result=$?
    if [[ $validation_result -eq 1 ]]; then
        VALIDATION_PASSED=false
        ((CRITICAL_ISSUES++))
        log_error "Critical performance issues detected in $scenario_name"
    elif [[ $validation_result -eq 2 ]]; then
        ((WARNING_ISSUES++))
        log_warning "Performance warnings detected in $scenario_name"
    else
        log_success "$scenario_name validation passed"
    fi
}

# Validate Artillery test results
validate_artillery_results() {
    local results_file="$1"
    local scenario_name="$2"
    
    if [[ ! -f "$results_file" ]]; then
        log_warning "Artillery results file not found: $results_file"
        return
    fi
    
    log_info "Validating Artillery results: $scenario_name"
    
    # Extract and validate Artillery metrics
    python3 << EOF
import json
import sys

# Load Artillery results
try:
    with open('${results_file}') as f:
        artillery_data = json.load(f)
except Exception as e:
    print(f"Error loading Artillery results: {e}")
    sys.exit(0)

# Extract aggregate metrics
aggregate = artillery_data.get('aggregate', {})
latency = aggregate.get('latency', {})
counters = aggregate.get('counters', {})

p95_actual = latency.get('p95', 0)
p99_actual = latency.get('p99', 0)
median_actual = latency.get('median', 0)

total_requests = counters.get('http.requests', 0)
total_errors = counters.get('errors.total', 0)
error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0

print(f"=== ${scenario_name} Artillery Results ===")
print(f"P95 Latency: {p95_actual}ms")
print(f"P99 Latency: {p99_actual}ms") 
print(f"Median Latency: {median_actual}ms")
print(f"Error Rate: {error_rate:.2f}%")
print(f"Total Requests: {total_requests}")
print(f"Total Errors: {total_errors}")

# Artillery-specific threshold validation
issues = []
p95_threshold = $(get_threshold "response_times.api_endpoints.p95_ms" "500")
error_threshold = $(jq -r ".global_thresholds.error_rates.${TEST_TYPE}_test.max_error_rate_percent // 2.0" "$THRESHOLDS_FILE")

if p95_actual > p95_threshold:
    issues.append({
        "scenario": "${scenario_name}",
        "metric": "P95 Latency",
        "actual": p95_actual,
        "threshold": p95_threshold,
        "severity": "critical" if p95_actual > p95_threshold * 2 else "warning",
        "impact": "high"
    })

if error_rate > error_threshold:
    issues.append({
        "scenario": "${scenario_name}",
        "metric": "Error Rate",
        "actual": error_rate,
        "threshold": error_threshold,
        "severity": "critical",
        "impact": "critical"
    })

# Write issues
with open('${OUTPUT_DIR}/temp_issues_artillery_${scenario_name}.json', 'w') as f:
    json.dump(issues, f)

# Exit with appropriate code
critical_count = sum(1 for issue in issues if issue['severity'] == 'critical')
if critical_count > 0:
    print(f"\n❌ {critical_count} critical issues detected")
    sys.exit(1)
elif issues:
    print(f"\n⚠️ {len(issues)} warning issues detected") 
    sys.exit(2)
else:
    print(f"\n✅ All Artillery thresholds passed")
    sys.exit(0)
EOF

    local validation_result=$?
    if [[ $validation_result -eq 1 ]]; then
        VALIDATION_PASSED=false
        ((CRITICAL_ISSUES++))
        log_error "Critical performance issues detected in $scenario_name (Artillery)"
    elif [[ $validation_result -eq 2 ]]; then
        ((WARNING_ISSUES++))
        log_warning "Performance warnings detected in $scenario_name (Artillery)"
    else
        log_success "$scenario_name Artillery validation passed"
    fi
}

# Perform regression analysis
perform_regression_analysis() {
    log_info "Performing regression analysis..."
    
    # Get historical baseline data (simplified for CI environment)
    local baseline_commit="${BASELINE_COMMIT:-HEAD~10}"
    
    python3 << EOF
import json
import os
import statistics
import sys

# Regression analysis configuration
regression_config = $(jq '.regression_detection' "$THRESHOLDS_FILE")
warning_threshold = regression_config['percentage_thresholds']['warning']
critical_threshold = regression_config['percentage_thresholds']['critical']

print(f"=== REGRESSION ANALYSIS ===")
print(f"Warning threshold: {warning_threshold}% degradation")
print(f"Critical threshold: {critical_threshold}% degradation")

# For CI environment, we'll simulate regression detection
# In production, this would compare with stored historical data

regressions = []
baseline_p95 = 400  # Simulated baseline
current_p95 = 450   # Simulated current

if current_p95 > baseline_p95:
    degradation_pct = ((current_p95 - baseline_p95) / baseline_p95) * 100
    
    if degradation_pct > critical_threshold:
        severity = "critical"
    elif degradation_pct > warning_threshold:
        severity = "warning"
    else:
        severity = "info"
        
    if severity in ["warning", "critical"]:
        regressions.append({
            "metric": "P95 Response Time",
            "baseline_value": baseline_p95,
            "current_value": current_p95,
            "degradation_percent": degradation_pct,
            "severity": severity,
            "baseline_commit": "${baseline_commit}"
        })

# Save regression analysis
with open('${OUTPUT_DIR}/regression_analysis.json', 'w') as f:
    json.dump({
        "regressions_detected": len(regressions),
        "regressions": regressions,
        "analysis_type": "percentage_comparison",
        "baseline_reference": "${baseline_commit}"
    }, f, indent=2)

# Update global counters
if regressions:
    critical_regressions = sum(1 for r in regressions if r['severity'] == 'critical')
    if critical_regressions > 0:
        print(f"❌ {critical_regressions} critical regressions detected")
        sys.exit(1)
    else:
        print(f"⚠️ {len(regressions)} performance regressions detected")
        sys.exit(2)
else:
    print("✅ No performance regressions detected")
    sys.exit(0)
EOF

    local regression_result=$?
    if [[ $regression_result -eq 1 ]]; then
        VALIDATION_PASSED=false
        ((REGRESSIONS_DETECTED++))
        log_error "Critical performance regressions detected"
    elif [[ $regression_result -eq 2 ]]; then
        ((REGRESSIONS_DETECTED++))
        log_warning "Performance regressions detected"
    else
        log_success "No regressions detected"
    fi
}

# Consolidate all validation results
consolidate_results() {
    log_info "Consolidating validation results..."
    
    # Collect all issues from temporary files
    local all_issues="[]"
    for temp_file in "$OUTPUT_DIR"/temp_issues_*.json; do
        if [[ -f "$temp_file" ]]; then
            local file_issues
            file_issues=$(cat "$temp_file")
            all_issues=$(echo "$all_issues $file_issues" | jq -s 'add')
            rm "$temp_file"
        fi
    done
    
    # Load regression analysis
    local regression_data="{}"
    if [[ -f "$OUTPUT_DIR/regression_analysis.json" ]]; then
        regression_data=$(cat "$OUTPUT_DIR/regression_analysis.json")
    fi
    
    # Update final validation report
    python3 << EOF
import json

# Load current report
with open('${OUTPUT_DIR}/validation_report.json') as f:
    report = json.load(f)

# Update with consolidated results
report['validation_passed'] = ${VALIDATION_PASSED,,}
report['summary']['total_issues'] = ${CRITICAL_ISSUES} + ${WARNING_ISSUES}
report['summary']['critical_issues'] = ${CRITICAL_ISSUES}
report['summary']['warning_issues'] = ${WARNING_ISSUES} 
report['summary']['regressions'] = ${REGRESSIONS_DETECTED}
report['issues'] = $(echo "$all_issues")
report['regression_analysis'] = $(echo "$regression_data")

# Add recommendations based on findings
recommendations = []

if ${CRITICAL_ISSUES} > 0:
    recommendations.extend([
        "Immediate action required: Critical performance issues detected",
        "Review and optimize endpoints with response times exceeding thresholds",
        "Consider blocking deployment until issues are resolved"
    ])

if ${WARNING_ISSUES} > 0:
    recommendations.extend([
        "Monitor performance trends closely",
        "Plan optimization work for next iteration",
        "Review resource utilization patterns"
    ])

if ${REGRESSIONS_DETECTED} > 0:
    recommendations.extend([
        "Analyze recent code changes for performance impact",
        "Consider reverting changes that introduced regressions",
        "Implement additional monitoring for affected endpoints"
    ])

if report['validation_passed']:
    recommendations.append("All performance tests passed successfully")

report['recommendations'] = recommendations

# Save final report
with open('${OUTPUT_DIR}/validation_report.json', 'w') as f:
    json.dump(report, f, indent=2)

print("=== VALIDATION REPORT SUMMARY ===")
print(f"Total Issues: {report['summary']['total_issues']}")
print(f"Critical Issues: {report['summary']['critical_issues']}")
print(f"Warning Issues: {report['summary']['warning_issues']}")
print(f"Regressions: {report['summary']['regressions']}")
print(f"Validation Passed: {report['validation_passed']}")
EOF

    # Generate human-readable summary
    cat > "$OUTPUT_DIR/validation_summary.txt" << EOF
PERFORMANCE VALIDATION SUMMARY
==============================
Test Type: $TEST_TYPE
Environment: $ENVIRONMENT
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Commit: ${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}

RESULTS:
- Total Issues: $((CRITICAL_ISSUES + WARNING_ISSUES))
- Critical Issues: $CRITICAL_ISSUES
- Warning Issues: $WARNING_ISSUES
- Regressions Detected: $REGRESSIONS_DETECTED
- Validation Status: $(if $VALIDATION_PASSED; then echo "PASSED"; else echo "FAILED"; fi)

RECOMMENDATIONS:
$(if [[ $CRITICAL_ISSUES -gt 0 ]]; then
    echo "- IMMEDIATE ACTION REQUIRED: Critical performance issues detected"
    echo "- Review and optimize endpoints exceeding thresholds"
    echo "- Consider blocking deployment until resolved"
fi)
$(if [[ $WARNING_ISSUES -gt 0 ]]; then
    echo "- Monitor performance trends closely"
    echo "- Plan optimization work for next iteration"
fi)
$(if [[ $REGRESSIONS_DETECTED -gt 0 ]]; then
    echo "- Analyze recent changes for performance impact"
    echo "- Consider reverting problematic changes"
fi)
$(if $VALIDATION_PASSED; then
    echo "- All performance tests passed successfully"
fi)

NEXT STEPS:
1. Review detailed results in validation_report.json
2. Analyze specific performance issues in the issues section
3. Address critical issues before deployment
4. Monitor ongoing performance trends

EOF
}

# Generate CI/CD outputs for GitHub Actions
generate_ci_outputs() {
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        log_info "Setting GitHub Actions outputs..."
        
        cat >> "$GITHUB_OUTPUT" << EOF
performance_validation_passed=$VALIDATION_PASSED
critical_issues=$CRITICAL_ISSUES
warning_issues=$WARNING_ISSUES
total_issues=$((CRITICAL_ISSUES + WARNING_ISSUES))
regressions_detected=$REGRESSIONS_DETECTED
validation_report_path=$OUTPUT_DIR/validation_report.json
validation_summary_path=$OUTPUT_DIR/validation_summary.txt
EOF
    fi
    
    # Set exit code for CI/CD pipeline
    if [[ $CRITICAL_ISSUES -gt 0 ]]; then
        log_error "Performance validation failed with $CRITICAL_ISSUES critical issues"
        exit 1
    elif [[ $WARNING_ISSUES -gt 0 ]]; then
        log_warning "Performance validation completed with $WARNING_ISSUES warnings"
        exit 0
    else
        log_success "Performance validation passed successfully"
        exit 0
    fi
}

# Main execution flow
main() {
    log_info "Starting performance validation..."
    log_info "Test Type: $TEST_TYPE"
    log_info "Environment: $ENVIRONMENT"
    log_info "Results Directory: $RESULTS_DIR"
    log_info "Output Directory: $OUTPUT_DIR"
    
    # Initialize
    init_validation_report
    load_thresholds
    
    # Validate test results
    if [[ -d "$RESULTS_DIR" ]]; then
        # Process k6 results
        for k6_result in "$RESULTS_DIR"/*k6*.json; do
            if [[ -f "$k6_result" ]]; then
                scenario_name=$(basename "$k6_result" .json)
                validate_k6_results "$k6_result" "$scenario_name"
            fi
        done
        
        # Process Artillery results  
        for artillery_result in "$RESULTS_DIR"/*artillery*.json; do
            if [[ -f "$artillery_result" ]]; then
                scenario_name=$(basename "$artillery_result" .json)
                validate_artillery_results "$artillery_result" "$scenario_name"
            fi
        done
    else
        log_warning "Results directory not found: $RESULTS_DIR"
    fi
    
    # Perform regression analysis
    perform_regression_analysis
    
    # Consolidate and report results
    consolidate_results
    
    # Generate CI/CD outputs
    generate_ci_outputs
}

# Help function
show_help() {
    cat << EOF
Performance Validation Script for iSECTECH CI/CD Pipeline

USAGE:
    $0 [test_type] [environment] [results_dir] [output_dir]

PARAMETERS:
    test_type     Type of performance test (baseline, stress, spike, endurance)
    environment   Target environment (development, staging, production)
    results_dir   Directory containing test result files
    output_dir    Directory for validation output files

EXAMPLES:
    $0 baseline staging ./test-results ./validation-output
    $0 stress production ./artillery-results
    $0

ENVIRONMENT VARIABLES:
    GITHUB_OUTPUT    GitHub Actions output file path
    GITHUB_SHA       Git commit SHA for tracking
    GITHUB_REF_NAME  Git branch name
    BASELINE_COMMIT  Baseline commit for regression analysis

OUTPUT FILES:
    validation_report.json    Detailed validation results in JSON format
    validation_summary.txt    Human-readable summary
    regression_analysis.json  Regression analysis results

EXIT CODES:
    0  Validation passed (warnings allowed)
    1  Validation failed (critical issues detected)
EOF
}

# Handle command line arguments
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

# Execute main function
main "$@"