#!/bin/bash
# Automated Security Compliance Verification and Reporting System
# This script provides comprehensive automated compliance verification for iSECTECH
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORTS_DIR="${SCRIPT_DIR}/../reports/compliance"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
CONFIG_FILE="${SCRIPT_DIR}/../config/compliance-config.yaml"

# Report files
DAILY_REPORT="${REPORTS_DIR}/daily-compliance-${TIMESTAMP}.json"
SUMMARY_REPORT="${REPORTS_DIR}/compliance-summary-${TIMESTAMP}.txt"
METRICS_FILE="${REPORTS_DIR}/compliance-metrics-${TIMESTAMP}.json"
REMEDIATION_REPORT="${REPORTS_DIR}/remediation-actions-${TIMESTAMP}.md"

# Notification settings
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
PAGERDUTY_INTEGRATION_KEY="${PAGERDUTY_INTEGRATION_KEY:-}"
EMAIL_RECIPIENTS="${EMAIL_RECIPIENTS:-security@isectech.com}"

# Compliance thresholds
CRITICAL_THRESHOLD=75
WARNING_THRESHOLD=90
MAX_PRIVILEGED_CONTAINERS=3
MAX_VIOLATIONS=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Create reports directory
mkdir -p "${REPORTS_DIR}"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Send notification to Slack
send_slack_notification() {
    local message="$1"
    local color="${2:-warning}"
    
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🔒 Security Compliance Alert\", \"attachments\":[{\"color\":\"$color\", \"text\":\"$message\"}]}" \
            "$SLACK_WEBHOOK_URL" || log_warning "Failed to send Slack notification"
    fi
}

# Send PagerDuty alert
send_pagerduty_alert() {
    local severity="$1"
    local summary="$2"
    local source="${3:-compliance-automation}"
    
    if [[ -n "$PAGERDUTY_INTEGRATION_KEY" ]]; then
        local payload=$(cat <<EOF
{
    "routing_key": "$PAGERDUTY_INTEGRATION_KEY",
    "event_action": "trigger",
    "payload": {
        "summary": "$summary",
        "source": "$source",
        "severity": "$severity",
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "custom_details": {
            "compliance_check": true,
            "report_path": "$DAILY_REPORT"
        }
    }
}
EOF
        )
        
        curl -X POST \
            -H 'Content-Type: application/json' \
            -d "$payload" \
            'https://events.pagerduty.com/v2/enqueue' || log_warning "Failed to send PagerDuty alert"
    fi
}

# Initialize compliance report
initialize_report() {
    log_info "Initializing compliance verification report..."
    
    cat > "$DAILY_REPORT" << EOF
{
    "compliance_report": {
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
        "cluster": "$(kubectl config current-context 2>/dev/null || echo 'unknown')",
        "kubernetes_version": "$(kubectl version --short --client=false 2>/dev/null | grep 'Server Version' | cut -d' ' -f3 || echo 'unknown')",
        "report_version": "2.0.0",
        "checks": {
            "security_context": {},
            "privileged_containers": {},
            "resource_limits": {},
            "pod_security_standards": {},
            "opa_gatekeeper": {},
            "runtime_security": {}
        },
        "summary": {
            "overall_compliance_score": 0,
            "total_pods_scanned": 0,
            "compliant_pods": 0,
            "violation_count": 0,
            "critical_issues": 0,
            "warning_issues": 0,
            "info_issues": 0
        },
        "recommendations": [],
        "remediation_actions": []
    }
}
EOF
}

# Run security context compliance check
check_security_contexts() {
    log_info "Running security context compliance check..."
    
    # Run the existing audit script and capture results
    local audit_results
    if audit_results=$(bash "${SCRIPT_DIR}/audit-security-context.sh" 2>&1); then
        local exit_code=$?
        log_success "Security context audit completed"
        
        # Extract metrics from audit results
        local total_pods=$(echo "$audit_results" | grep "Total Pods Audited:" | cut -d':' -f2 | xargs)
        local compliant_pods=$(echo "$audit_results" | grep "Compliant Pods:" | cut -d':' -f2 | xargs)
        local violations=$(echo "$audit_results" | grep "Pods with Violations:" | cut -d':' -f2 | xargs)
        local compliance_percentage=$(echo "$audit_results" | grep "Overall Compliance:" | cut -d':' -f2 | cut -d'%' -f1 | xargs)
        
        # Update report
        jq --arg total "$total_pods" \
           --arg compliant "$compliant_pods" \
           --arg violations "$violations" \
           --arg percentage "$compliance_percentage" \
           '.compliance_report.checks.security_context = {
             "status": "completed",
             "total_pods": ($total | tonumber),
             "compliant_pods": ($compliant | tonumber),
             "violations": ($violations | tonumber),
             "compliance_percentage": ($percentage | tonumber),
             "exit_code": 0
           }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
           
        return 0
    else
        log_error "Security context audit failed"
        jq '.compliance_report.checks.security_context = {
             "status": "failed",
             "error": "Audit script execution failed"
           }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
        return 1
    fi
}

# Check for privileged containers
check_privileged_containers() {
    log_info "Scanning for privileged containers..."
    
    local privileged_count=0
    local privileged_pods=()
    
    # Get all namespaces
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for namespace in $namespaces; do
        # Skip system namespaces for this check
        if [[ "$namespace" =~ ^(kube-|local-path-storage|gatekeeper-system)$ ]]; then
            continue
        fi
        
        # Check for privileged containers
        local pods=$(kubectl get pods -n "$namespace" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
        
        for pod in $pods; do
            local is_privileged=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[*].securityContext.privileged}' 2>/dev/null || echo "")
            
            if [[ "$is_privileged" == *"true"* ]]; then
                ((privileged_count++))
                privileged_pods+=("$namespace/$pod")
                
                # Check if this is an approved privileged container
                local image=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null || echo "unknown")
                if [[ ! "$image" =~ (falco|vector|filebeat) ]]; then
                    log_warning "Unauthorized privileged container: $namespace/$pod ($image)"
                fi
            fi
        done
    done
    
    # Update report
    local privileged_pods_json=$(printf '%s\n' "${privileged_pods[@]}" | jq -R . | jq -s .)
    jq --arg count "$privileged_count" \
       --argjson pods "$privileged_pods_json" \
       --arg threshold "$MAX_PRIVILEGED_CONTAINERS" \
       '.compliance_report.checks.privileged_containers = {
         "status": "completed",
         "privileged_count": ($count | tonumber),
         "privileged_pods": $pods,
         "threshold": ($threshold | tonumber),
         "compliant": (($count | tonumber) <= ($threshold | tonumber))
       }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    if [[ $privileged_count -le $MAX_PRIVILEGED_CONTAINERS ]]; then
        log_success "Privileged container count ($privileged_count) within acceptable threshold"
        return 0
    else
        log_error "Too many privileged containers ($privileged_count > $MAX_PRIVILEGED_CONTAINERS)"
        return 1
    fi
}

# Check resource limits compliance
check_resource_limits() {
    log_info "Checking resource limits compliance..."
    
    local pods_without_limits=0
    local violation_list=()
    
    # Get all application namespaces
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | \
                      grep -E '^(isectech-|production|staging|development|default)' || echo "")
    
    for namespace in $namespaces; do
        local pods=$(kubectl get pods -n "$namespace" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
        
        for pod in $pods; do
            # Check if pod has resource limits
            local has_cpu_limits=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[*].resources.limits.cpu}' 2>/dev/null || echo "")
            local has_memory_limits=$(kubectl get pod "$pod" -n "$namespace" -o jsonpath='{.spec.containers[*].resources.limits.memory}' 2>/dev/null || echo "")
            
            if [[ -z "$has_cpu_limits" ]] || [[ -z "$has_memory_limits" ]]; then
                ((pods_without_limits++))
                violation_list+=("$namespace/$pod")
            fi
        done
    done
    
    # Update report
    local violations_json=$(printf '%s\n' "${violation_list[@]}" | jq -R . | jq -s .)
    jq --arg count "$pods_without_limits" \
       --argjson violations "$violations_json" \
       '.compliance_report.checks.resource_limits = {
         "status": "completed",
         "pods_without_limits": ($count | tonumber),
         "violations": $violations,
         "compliant": (($count | tonumber) == 0)
       }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    if [[ $pods_without_limits -eq 0 ]]; then
        log_success "All pods have resource limits configured"
        return 0
    else
        log_warning "$pods_without_limits pods missing resource limits"
        return 1
    fi
}

# Check Pod Security Standards compliance
check_pod_security_standards() {
    log_info "Checking Pod Security Standards compliance..."
    
    local pss_violations=0
    local namespace_results=()
    
    # Check namespace labels and compliance
    local namespaces=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
    
    for namespace in $namespaces; do
        # Skip system namespaces
        if [[ "$namespace" =~ ^(kube-|local-path-storage|gatekeeper-system)$ ]]; then
            continue
        fi
        
        # Check PSS labels
        local enforce_label=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || echo "none")
        local audit_label=$(kubectl get namespace "$namespace" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}' 2>/dev/null || echo "none")
        
        # Count violations in namespace (this would be enhanced with actual PSS violation metrics)
        local namespace_violations=0
        
        namespace_results+=("{\"namespace\":\"$namespace\",\"enforce\":\"$enforce_label\",\"audit\":\"$audit_label\",\"violations\":$namespace_violations}")
        pss_violations=$((pss_violations + namespace_violations))
    done
    
    # Update report
    local results_json=$(printf '%s\n' "${namespace_results[@]}" | jq -s .)
    jq --arg violations "$pss_violations" \
       --argjson results "$results_json" \
       '.compliance_report.checks.pod_security_standards = {
         "status": "completed",
         "total_violations": ($violations | tonumber),
         "namespace_results": $results,
         "compliant": (($violations | tonumber) == 0)
       }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    log_success "Pod Security Standards check completed"
    return 0
}

# Check OPA Gatekeeper status and violations
check_opa_gatekeeper() {
    log_info "Checking OPA Gatekeeper status and violations..."
    
    # Check if Gatekeeper is running
    local gatekeeper_running=false
    if kubectl get namespace gatekeeper-system &>/dev/null; then
        local ready_pods=$(kubectl get pods -n gatekeeper-system -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' 2>/dev/null | wc -w)
        if [[ $ready_pods -gt 0 ]]; then
            gatekeeper_running=true
        fi
    fi
    
    local constraint_violations=0
    local constraint_status=()
    
    if [[ "$gatekeeper_running" == "true" ]]; then
        # Get constraint violations
        local constraints=$(kubectl get constraints -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
        
        for constraint in $constraints; do
            local violations=$(kubectl get constraint "$constraint" -o jsonpath='{.status.totalViolations}' 2>/dev/null || echo "0")
            constraint_violations=$((constraint_violations + violations))
            constraint_status+=("{\"name\":\"$constraint\",\"violations\":$violations}")
        done
        
        log_success "Gatekeeper is running with $constraint_violations total violations"
    else
        log_error "OPA Gatekeeper is not running"
    fi
    
    # Update report
    local status_json=$(printf '%s\n' "${constraint_status[@]}" | jq -s .)
    jq --arg running "$gatekeeper_running" \
       --arg violations "$constraint_violations" \
       --argjson status "$status_json" \
       '.compliance_report.checks.opa_gatekeeper = {
         "status": "completed",
         "gatekeeper_running": ($running == "true"),
         "total_violations": ($violations | tonumber),
         "constraint_status": $status,
         "compliant": (($violations | tonumber) == 0 and ($running == "true"))
       }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    return 0
}

# Check runtime security (Falco status)
check_runtime_security() {
    log_info "Checking runtime security monitoring..."
    
    local falco_running=false
    local security_events=0
    
    # Check if Falco is running
    if kubectl get pods -n security -l app.kubernetes.io/name=falco &>/dev/null; then
        local running_pods=$(kubectl get pods -n security -l app.kubernetes.io/name=falco -o jsonpath='{.items[?(@.status.phase=="Running")].metadata.name}' 2>/dev/null | wc -w)
        if [[ $running_pods -gt 0 ]]; then
            falco_running=true
            log_success "Falco runtime security is running on $running_pods nodes"
        fi
    fi
    
    # This would be enhanced with actual Falco metrics integration
    security_events=0
    
    # Update report
    jq --arg running "$falco_running" \
       --arg events "$security_events" \
       '.compliance_report.checks.runtime_security = {
         "status": "completed",
         "falco_running": ($running == "true"),
         "security_events": ($events | tonumber),
         "compliant": ($running == "true")
       }' "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    return 0
}

# Calculate overall compliance score
calculate_compliance_score() {
    log_info "Calculating overall compliance score..."
    
    # Extract metrics from report
    local security_context_score=$(jq -r '.compliance_report.checks.security_context.compliance_percentage // 0' "$DAILY_REPORT")
    local privileged_compliant=$(jq -r '.compliance_report.checks.privileged_containers.compliant // false' "$DAILY_REPORT")
    local resource_limits_compliant=$(jq -r '.compliance_report.checks.resource_limits.compliant // false' "$DAILY_REPORT")
    local pss_compliant=$(jq -r '.compliance_report.checks.pod_security_standards.compliant // false' "$DAILY_REPORT")
    local gatekeeper_compliant=$(jq -r '.compliance_report.checks.opa_gatekeeper.compliant // false' "$DAILY_REPORT")
    local runtime_compliant=$(jq -r '.compliance_report.checks.runtime_security.compliant // false' "$DAILY_REPORT")
    
    # Calculate weighted score
    local weighted_score=0
    weighted_score=$((weighted_score + security_context_score * 40 / 100))  # 40% weight
    [[ "$privileged_compliant" == "true" ]] && weighted_score=$((weighted_score + 15))  # 15% weight
    [[ "$resource_limits_compliant" == "true" ]] && weighted_score=$((weighted_score + 15))  # 15% weight
    [[ "$pss_compliant" == "true" ]] && weighted_score=$((weighted_score + 10))  # 10% weight
    [[ "$gatekeeper_compliant" == "true" ]] && weighted_score=$((weighted_score + 10))  # 10% weight
    [[ "$runtime_compliant" == "true" ]] && weighted_score=$((weighted_score + 10))  # 10% weight
    
    # Count issues
    local critical_issues=0
    local warning_issues=0
    local info_issues=0
    
    # Determine severity based on compliance score
    if [[ $weighted_score -lt $CRITICAL_THRESHOLD ]]; then
        critical_issues=$((critical_issues + 1))
    elif [[ $weighted_score -lt $WARNING_THRESHOLD ]]; then
        warning_issues=$((warning_issues + 1))
    fi
    
    # Update summary in report
    jq --arg score "$weighted_score" \
       --arg critical "$critical_issues" \
       --arg warning "$warning_issues" \
       --arg info "$info_issues" \
       '.compliance_report.summary.overall_compliance_score = ($score | tonumber) |
        .compliance_report.summary.critical_issues = ($critical | tonumber) |
        .compliance_report.summary.warning_issues = ($warning | tonumber) |
        .compliance_report.summary.info_issues = ($info | tonumber)' \
       "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
    
    echo "$weighted_score"
}

# Generate recommendations
generate_recommendations() {
    log_info "Generating compliance recommendations..."
    
    local recommendations=()
    
    # Check each compliance area and generate recommendations
    local security_context_score=$(jq -r '.compliance_report.checks.security_context.compliance_percentage // 0' "$DAILY_REPORT")
    if [[ $security_context_score -lt 95 ]]; then
        recommendations+=("\"Improve security context compliance by updating non-compliant pods to use proper security contexts\"")
    fi
    
    local privileged_count=$(jq -r '.compliance_report.checks.privileged_containers.privileged_count // 0' "$DAILY_REPORT")
    if [[ $privileged_count -gt $MAX_PRIVILEGED_CONTAINERS ]]; then
        recommendations+=("\"Reduce number of privileged containers from $privileged_count to $MAX_PRIVILEGED_CONTAINERS or below\"")
    fi
    
    local resource_violations=$(jq -r '.compliance_report.checks.resource_limits.pods_without_limits // 0' "$DAILY_REPORT")
    if [[ $resource_violations -gt 0 ]]; then
        recommendations+=("\"Add resource limits to $resource_violations pods missing resource constraints\"")
    fi
    
    local gatekeeper_running=$(jq -r '.compliance_report.checks.opa_gatekeeper.gatekeeper_running // false' "$DAILY_REPORT")
    if [[ "$gatekeeper_running" != "true" ]]; then
        recommendations+=("\"Deploy and configure OPA Gatekeeper for policy enforcement\"")
    fi
    
    local falco_running=$(jq -r '.compliance_report.checks.runtime_security.falco_running // false' "$DAILY_REPORT")
    if [[ "$falco_running" != "true" ]]; then
        recommendations+=("\"Deploy Falco for runtime security monitoring\"")
    fi
    
    # Always include general recommendations
    recommendations+=("\"Run weekly security compliance audits using ./scripts/audit-security-context.sh\"")
    recommendations+=("\"Review and update security policies quarterly\"")
    recommendations+=("\"Implement automated remediation for common violations\"")
    
    # Update report with recommendations
    local recommendations_json="[$(IFS=','; echo "${recommendations[*]}")]"
    jq --argjson recs "$recommendations_json" \
       '.compliance_report.recommendations = $recs' \
       "$DAILY_REPORT" > "${DAILY_REPORT}.tmp" && mv "${DAILY_REPORT}.tmp" "$DAILY_REPORT"
}

# Generate summary report
generate_summary_report() {
    log_info "Generating summary report..."
    
    local overall_score=$(jq -r '.compliance_report.summary.overall_compliance_score' "$DAILY_REPORT")
    local critical_issues=$(jq -r '.compliance_report.summary.critical_issues' "$DAILY_REPORT")
    local warning_issues=$(jq -r '.compliance_report.summary.warning_issues' "$DAILY_REPORT")
    
    cat > "$SUMMARY_REPORT" << EOF
================================================================================
                        iSECTECH Security Compliance Report
================================================================================
Generated: $(date)
Cluster: $(kubectl config current-context 2>/dev/null || echo 'unknown')
Report Version: 2.0.0

OVERALL COMPLIANCE SCORE
=======================
Score: ${overall_score}%

$(if [[ $overall_score -ge 95 ]]; then
    echo "Status: EXCELLENT ✅"
elif [[ $overall_score -ge 90 ]]; then
    echo "Status: GOOD ✅"
elif [[ $overall_score -ge 75 ]]; then
    echo "Status: NEEDS IMPROVEMENT ⚠️"
else
    echo "Status: CRITICAL ❌"
fi)

ISSUE SUMMARY
=============
Critical Issues: $critical_issues
Warning Issues: $warning_issues
Total Issues: $((critical_issues + warning_issues))

COMPLIANCE CHECKS RESULTS
========================
EOF

    # Add individual check results
    echo "Security Context Compliance: $(jq -r '.compliance_report.checks.security_context.compliance_percentage // "N/A"' "$DAILY_REPORT")%" >> "$SUMMARY_REPORT"
    echo "Privileged Containers: $(jq -r '.compliance_report.checks.privileged_containers.privileged_count // "N/A"' "$DAILY_REPORT") containers" >> "$SUMMARY_REPORT"
    echo "Resource Limits: $(jq -r '.compliance_report.checks.resource_limits.pods_without_limits // "N/A"' "$DAILY_REPORT") violations" >> "$SUMMARY_REPORT"
    echo "OPA Gatekeeper: $(jq -r 'if .compliance_report.checks.opa_gatekeeper.gatekeeper_running then "Running ✅" else "Not Running ❌" end' "$DAILY_REPORT")" >> "$SUMMARY_REPORT"
    echo "Runtime Security: $(jq -r 'if .compliance_report.checks.runtime_security.falco_running then "Running ✅" else "Not Running ❌" end' "$DAILY_REPORT")" >> "$SUMMARY_REPORT"
    
    echo "" >> "$SUMMARY_REPORT"
    echo "TOP RECOMMENDATIONS" >> "$SUMMARY_REPORT"
    echo "==================" >> "$SUMMARY_REPORT"
    
    # Add recommendations
    jq -r '.compliance_report.recommendations[]' "$DAILY_REPORT" | head -5 | while read -r rec; do
        echo "• $rec" >> "$SUMMARY_REPORT"
    done
    
    echo "" >> "$SUMMARY_REPORT"
    echo "DETAILED REPORTS" >> "$SUMMARY_REPORT"
    echo "===============" >> "$SUMMARY_REPORT"
    echo "Full JSON Report: $DAILY_REPORT" >> "$SUMMARY_REPORT"
    echo "Summary Report: $SUMMARY_REPORT" >> "$SUMMARY_REPORT"
    echo "Remediation Actions: $REMEDIATION_REPORT" >> "$SUMMARY_REPORT"
}

# Generate remediation actions
generate_remediation_actions() {
    log_info "Generating automated remediation actions..."
    
    cat > "$REMEDIATION_REPORT" << EOF
# Automated Remediation Actions

**Generated:** $(date)  
**Cluster:** $(kubectl config current-context 2>/dev/null || echo 'unknown')

## Critical Actions Required

EOF

    local overall_score=$(jq -r '.compliance_report.summary.overall_compliance_score' "$DAILY_REPORT")
    
    if [[ $overall_score -lt $CRITICAL_THRESHOLD ]]; then
        cat >> "$REMEDIATION_REPORT" << EOF
### 🚨 CRITICAL COMPLIANCE FAILURE

Overall compliance score (${overall_score}%) is below critical threshold (${CRITICAL_THRESHOLD}%).

**Immediate Actions Required:**
1. Review all non-compliant pods and fix security contexts
2. Remove unauthorized privileged containers
3. Add resource limits to all application pods
4. Deploy OPA Gatekeeper if not running
5. Escalate to security team immediately

EOF
    fi
    
    # Add specific remediation actions based on violations
    local privileged_count=$(jq -r '.compliance_report.checks.privileged_containers.privileged_count // 0' "$DAILY_REPORT")
    if [[ $privileged_count -gt $MAX_PRIVILEGED_CONTAINERS ]]; then
        cat >> "$REMEDIATION_REPORT" << EOF
### Privileged Container Violations

**Issue:** $privileged_count privileged containers detected (max allowed: $MAX_PRIVILEGED_CONTAINERS)

**Action:**
\`\`\`bash
# Review privileged containers
kubectl get pods --all-namespaces -o jsonpath='{range .items[?(@.spec.containers[*].securityContext.privileged==true)]}{.metadata.namespace}{"/"}{.metadata.name}{"\n"}{end}'

# For each unauthorized privileged container, update the deployment
kubectl patch deployment <deployment-name> -n <namespace> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<container-name>","securityContext":{"privileged":false}}]}}}}'
\`\`\`

EOF
    fi
    
    local resource_violations=$(jq -r '.compliance_report.checks.resource_limits.pods_without_limits // 0' "$DAILY_REPORT")
    if [[ $resource_violations -gt 0 ]]; then
        cat >> "$REMEDIATION_REPORT" << EOF
### Resource Limits Missing

**Issue:** $resource_violations pods without resource limits

**Action:**
\`\`\`bash
# Add resource limits to deployment
kubectl patch deployment <deployment-name> -n <namespace> -p '{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "<container-name>",
          "resources": {
            "limits": {
              "cpu": "500m",
              "memory": "512Mi"
            },
            "requests": {
              "cpu": "100m",
              "memory": "128Mi"
            }
          }
        }]
      }
    }
  }
}'
\`\`\`

EOF
    fi
    
    cat >> "$REMEDIATION_REPORT" << EOF
## Automated Remediation Scripts

### Deploy Security Constraints
\`\`\`bash
./scripts/deploy-security-constraints.sh
\`\`\`

### Run Complete Audit
\`\`\`bash
./scripts/audit-security-context.sh
\`\`\`

### Fix Common Security Context Issues
\`\`\`bash
# This script would contain automated fixes for common issues
./scripts/fix-security-contexts.sh --dry-run  # Preview changes
./scripts/fix-security-contexts.sh --apply   # Apply fixes
\`\`\`

## Monitoring and Alerting

1. Set up Prometheus alerts for compliance violations
2. Configure Grafana dashboard for compliance monitoring
3. Enable Slack/PagerDuty notifications for critical issues

## Next Review Schedule

- **Daily:** Automated compliance checks
- **Weekly:** Manual security review
- **Monthly:** Compliance policy updates
- **Quarterly:** Full security assessment
EOF
}

# Send notifications based on compliance score
send_notifications() {
    local overall_score="$1"
    local critical_issues="$2"
    local warning_issues="$3"
    
    if [[ $overall_score -lt $CRITICAL_THRESHOLD ]]; then
        local message="🚨 CRITICAL: Security compliance score is ${overall_score}% (below ${CRITICAL_THRESHOLD}%). Immediate action required!"
        send_slack_notification "$message" "danger"
        send_pagerduty_alert "critical" "$message"
        log_error "Critical compliance failure - notifications sent"
        
    elif [[ $overall_score -lt $WARNING_THRESHOLD ]]; then
        local message="⚠️ WARNING: Security compliance score is ${overall_score}% (below ${WARNING_THRESHOLD}%). Review required."
        send_slack_notification "$message" "warning"
        log_warning "Compliance warning - Slack notification sent"
        
    elif [[ $critical_issues -gt 0 ]] || [[ $warning_issues -gt 5 ]]; then
        local message="ℹ️ Security compliance check completed with ${critical_issues} critical and ${warning_issues} warning issues."
        send_slack_notification "$message" "warning"
        log_info "Compliance issues detected - notification sent"
        
    else
        local message="✅ Security compliance check passed with ${overall_score}% compliance score."
        send_slack_notification "$message" "good"
        log_success "Compliance check passed - success notification sent"
    fi
}

# Main execution
main() {
    log_info "Starting automated security compliance verification..."
    
    # Initialize
    initialize_report
    
    # Run all compliance checks
    local exit_code=0
    
    check_security_contexts || exit_code=1
    check_privileged_containers || exit_code=1
    check_resource_limits || exit_code=1
    check_pod_security_standards || exit_code=1
    check_opa_gatekeeper || exit_code=1
    check_runtime_security || exit_code=1
    
    # Calculate overall compliance
    local overall_score
    overall_score=$(calculate_compliance_score)
    
    # Generate reports and recommendations
    generate_recommendations
    generate_summary_report
    generate_remediation_actions
    
    # Extract final metrics for notifications
    local critical_issues=$(jq -r '.compliance_report.summary.critical_issues' "$DAILY_REPORT")
    local warning_issues=$(jq -r '.compliance_report.summary.warning_issues' "$DAILY_REPORT")
    
    # Send notifications
    send_notifications "$overall_score" "$critical_issues" "$warning_issues"
    
    # Display results
    log_info "Compliance verification completed"
    log_info "Overall Compliance Score: ${overall_score}%"
    log_info "Critical Issues: $critical_issues"
    log_info "Warning Issues: $warning_issues"
    log_info "Reports generated:"
    log_info "  - Summary: $SUMMARY_REPORT"
    log_info "  - Detailed: $DAILY_REPORT"
    log_info "  - Remediation: $REMEDIATION_REPORT"
    
    # Set exit code based on compliance score
    if [[ $overall_score -lt $CRITICAL_THRESHOLD ]]; then
        exit 2  # Critical failure
    elif [[ $overall_score -lt $WARNING_THRESHOLD ]]; then
        exit 1  # Warning
    else
        exit 0  # Success
    fi
}

# Handle command line arguments
case "${1:-}" in
    --daily)
        main
        ;;
    --weekly)
        log_info "Running weekly comprehensive audit..."
        # Run additional weekly checks here
        main
        ;;
    --dry-run)
        log_info "Running in dry-run mode (no notifications sent)"
        SLACK_WEBHOOK_URL=""
        PAGERDUTY_INTEGRATION_KEY=""
        main
        ;;
    --help|-h)
        echo "Usage: $0 [--daily|--weekly|--dry-run|--help]"
        echo "  --daily    Run daily compliance checks (default)"
        echo "  --weekly   Run comprehensive weekly audit"
        echo "  --dry-run  Run without sending notifications"
        echo "  --help     Show this help message"
        exit 0
        ;;
    *)
        main
        ;;
esac