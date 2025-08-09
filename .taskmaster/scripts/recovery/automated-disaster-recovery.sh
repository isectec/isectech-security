#!/bin/bash

# Automated Disaster Recovery Script - iSECTECH Security Platform
# Version: 1.0
# Author: DevOps Team
# Usage: ./automated-disaster-recovery.sh [recovery-type] [severity] [--dry-run]

set -euo pipefail

# Configuration
PROJECT_ID="isectech-security-platform"
REGION="us-central1"
BACKUP_BUCKET="gs://isectech-infrastructure-backups"
NOTIFICATION_EMAIL="devops@isectech.com"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

# Script parameters
RECOVERY_TYPE=${1:-"full"}
SEVERITY=${2:-"HIGH"}
DRY_RUN=${3:-""}

# Logging setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/automated-recovery-$(date +%Y%m%d%H%M%S).log"
RECOVERY_ID="REC-$(date +%Y%m%d%H%M%S)"

# Color codes for output
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
        ERROR)
            echo -e "${RED}[$timestamp] ERROR: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] WARN: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        INFO)
            echo -e "${BLUE}[$timestamp] INFO: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        SUCCESS)
            echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[$timestamp] $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Function to send notifications
send_notification() {
    local subject="$1"
    local message="$2"
    local priority="${3:-normal}"
    
    # Send email notification
    if command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "$subject" "$NOTIFICATION_EMAIL"
    fi
    
    # Send Slack notification
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚨 **$subject**\n$message\"}" \
            "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
    
    log INFO "Notification sent: $subject"
}

# Function to check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."
    
    # Check required tools
    local required_tools=("gcloud" "curl" "jq" "dig")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log ERROR "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        log ERROR "No active gcloud authentication found"
        exit 1
    fi
    
    # Check project access
    if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
        log ERROR "Cannot access project: $PROJECT_ID"
        exit 1
    fi
    
    log SUCCESS "Prerequisites check passed"
}

# Function to perform system health assessment
assess_system_health() {
    log INFO "Performing system health assessment..."
    
    local health_score=0
    local max_score=10
    
    # Check Cloud Run services
    local services=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")
    local healthy_services=0
    
    for service in "${services[@]}"; do
        local status=$(gcloud run services describe "$service" \
            --region="$REGION" --project="$PROJECT_ID" \
            --format="value(status.conditions[0].status)" 2>/dev/null || echo "UNKNOWN")
        
        if [[ "$status" == "True" ]]; then
            ((healthy_services++))
            log INFO "Service $service: HEALTHY"
        else
            log WARN "Service $service: UNHEALTHY ($status)"
        fi
    done
    
    health_score=$((health_score + (healthy_services * 2)))
    
    # Check database status
    local db_status=$(gcloud sql instances describe isectech-db-primary \
        --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "UNKNOWN")
    
    if [[ "$db_status" == "RUNNABLE" ]]; then
        ((health_score += 2))
        log INFO "Database: HEALTHY"
    else
        log WARN "Database: UNHEALTHY ($db_status)"
    fi
    
    # Check DNS resolution
    local dns_healthy=0
    local domains=("api.isectech.com" "app.isectech.com" "admin.isectech.com")
    
    for domain in "${domains[@]}"; do
        if dig +short "$domain" @8.8.8.8 | grep -q .; then
            ((dns_healthy++))
        fi
    done
    
    if [[ $dns_healthy -eq ${#domains[@]} ]]; then
        ((health_score++))
        log INFO "DNS: HEALTHY"
    else
        log WARN "DNS: PARTIAL ($dns_healthy/${#domains[@]} domains resolving)"
    fi
    
    # Check load balancer
    local lb_healthy=0
    for domain in "${domains[@]}"; do
        local http_status=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/health" 2>/dev/null || echo "000")
        if [[ "$http_status" == "200" ]]; then
            ((lb_healthy++))
        fi
    done
    
    if [[ $lb_healthy -eq ${#domains[@]} ]]; then
        ((health_score++))
        log INFO "Load Balancer: HEALTHY"
    else
        log WARN "Load Balancer: PARTIAL ($lb_healthy/${#domains[@]} endpoints responding)"
    fi
    
    local health_percentage=$((health_score * 100 / max_score))
    log INFO "System Health Score: $health_score/$max_score ($health_percentage%)"
    
    echo "$health_percentage"
}

# Function to execute DNS recovery
execute_dns_recovery() {
    log INFO "Executing DNS recovery..."
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        log INFO "DRY RUN: Would execute DNS recovery procedures"
        return 0
    fi
    
    # Check if DNS recovery script exists
    if [[ -f "$SCRIPT_DIR/../dns-recovery.sh" ]]; then
        bash "$SCRIPT_DIR/../dns-recovery.sh" 2>&1 | tee -a "$LOG_FILE"
        local exit_code=${PIPESTATUS[0]}
        
        if [[ $exit_code -eq 0 ]]; then
            log SUCCESS "DNS recovery completed successfully"
            return 0
        else
            log ERROR "DNS recovery failed with exit code: $exit_code"
            return 1
        fi
    else
        log WARN "DNS recovery script not found, executing basic DNS checks..."
        
        # Basic DNS validation
        local domains=("api.isectech.com" "app.isectech.com" "admin.isectech.com")
        local failed_domains=0
        
        for domain in "${domains[@]}"; do
            if ! dig +short "$domain" @8.8.8.8 | grep -q .; then
                ((failed_domains++))
                log ERROR "DNS resolution failed for: $domain"
            fi
        done
        
        if [[ $failed_domains -gt 0 ]]; then
            log ERROR "DNS recovery needed for $failed_domains domains"
            return 1
        fi
        
        return 0
    fi
}

# Function to execute certificate recovery
execute_certificate_recovery() {
    log INFO "Executing certificate recovery..."
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        log INFO "DRY RUN: Would execute certificate recovery procedures"
        return 0
    fi
    
    # Check certificate status
    local cert_status=$(gcloud certificate-manager certificates describe isectech-ssl-cert \
        --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "NOT_FOUND")
    
    if [[ "$cert_status" != "ACTIVE" ]]; then
        log WARN "Certificate status: $cert_status - initiating recovery"
        
        # Execute certificate recovery script if available
        if [[ -f "$SCRIPT_DIR/../certificate-recovery.sh" ]]; then
            bash "$SCRIPT_DIR/../certificate-recovery.sh" 2>&1 | tee -a "$LOG_FILE"
            local exit_code=${PIPESTATUS[0]}
            
            if [[ $exit_code -eq 0 ]]; then
                log SUCCESS "Certificate recovery completed successfully"
                return 0
            else
                log ERROR "Certificate recovery failed with exit code: $exit_code"
                return 1
            fi
        else
            log ERROR "Certificate recovery needed but script not found"
            return 1
        fi
    else
        log SUCCESS "Certificate is active - no recovery needed"
        return 0
    fi
}

# Function to execute service recovery
execute_service_recovery() {
    log INFO "Executing service recovery..."
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        log INFO "DRY RUN: Would execute service recovery procedures"
        return 0
    fi
    
    local services=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")
    local failed_services=()
    
    # Check service health
    for service in "${services[@]}"; do
        local status=$(gcloud run services describe "$service" \
            --region="$REGION" --project="$PROJECT_ID" \
            --format="value(status.conditions[0].status)" 2>/dev/null || echo "UNKNOWN")
        
        if [[ "$status" != "True" ]]; then
            failed_services+=("$service")
            log WARN "Service $service is unhealthy: $status"
        fi
    done
    
    # Recovery for failed services
    for service in "${failed_services[@]}"; do
        log INFO "Attempting recovery for service: $service"
        
        # Get last known good revision
        local last_good_revision=$(gcloud run revisions list \
            --service="$service" --region="$REGION" --project="$PROJECT_ID" \
            --format="value(metadata.name)" --sort-by="~metadata.creationTimestamp" \
            --limit=2 | tail -1)
        
        if [[ -n "$last_good_revision" ]]; then
            log INFO "Rolling back $service to revision: $last_good_revision"
            
            gcloud run services update-traffic "$service" \
                --to-revisions="$last_good_revision=100" \
                --region="$REGION" --project="$PROJECT_ID" 2>&1 | tee -a "$LOG_FILE"
            
            # Wait for rollback to take effect
            sleep 30
            
            # Verify rollback success
            local new_status=$(gcloud run services describe "$service" \
                --region="$REGION" --project="$PROJECT_ID" \
                --format="value(status.conditions[0].status)" 2>/dev/null || echo "UNKNOWN")
            
            if [[ "$new_status" == "True" ]]; then
                log SUCCESS "Service $service recovery successful"
            else
                log ERROR "Service $service recovery failed"
                return 1
            fi
        else
            log ERROR "No previous revision found for service: $service"
            return 1
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log SUCCESS "All services are healthy - no recovery needed"
    fi
    
    return 0
}

# Function to execute database recovery
execute_database_recovery() {
    log INFO "Executing database recovery..."
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        log INFO "DRY RUN: Would execute database recovery procedures"
        return 0
    fi
    
    # Check database status
    local db_status=$(gcloud sql instances describe isectech-db-primary \
        --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "UNKNOWN")
    
    if [[ "$db_status" != "RUNNABLE" ]]; then
        log WARN "Database status: $db_status - checking for recovery options"
        
        # Check for read replica
        local replica_instance=$(gcloud sql instances list --project="$PROJECT_ID" \
            --filter="masterInstanceName:isectech-db-primary" \
            --format="value(name)" | head -1)
        
        if [[ -n "$replica_instance" ]]; then
            log INFO "Read replica found: $replica_instance"
            
            local replica_status=$(gcloud sql instances describe "$replica_instance" \
                --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "UNKNOWN")
            
            if [[ "$replica_status" == "RUNNABLE" ]]; then
                log WARN "Database recovery required - manual intervention needed for replica promotion"
                send_notification "Database Recovery Required" \
                    "Primary database is down. Replica $replica_instance is available for promotion. Manual intervention required."
                return 1
            fi
        fi
        
        # Check recent backups
        local recent_backup=$(gcloud sql backups list \
            --instance=isectech-db-primary --project="$PROJECT_ID" \
            --format="value(id)" --limit=1 2>/dev/null | head -1)
        
        if [[ -n "$recent_backup" ]]; then
            log INFO "Recent backup available: $recent_backup"
            log WARN "Database recovery from backup requires manual intervention"
            send_notification "Database Backup Available" \
                "Primary database is down. Recent backup $recent_backup is available for restore. Manual intervention required."
        fi
        
        return 1
    else
        log SUCCESS "Database is running - no recovery needed"
        return 0
    fi
}

# Function to validate recovery success
validate_recovery() {
    log INFO "Validating recovery success..."
    
    local validation_errors=0
    
    # Re-assess system health
    local health_percentage=$(assess_system_health)
    
    if [[ $health_percentage -ge 90 ]]; then
        log SUCCESS "Recovery validation passed - system health: $health_percentage%"
    elif [[ $health_percentage -ge 70 ]]; then
        log WARN "Recovery partially successful - system health: $health_percentage%"
        ((validation_errors++))
    else
        log ERROR "Recovery validation failed - system health: $health_percentage%"
        ((validation_errors++))
    fi
    
    # Test critical endpoints
    local domains=("api.isectech.com" "app.isectech.com" "admin.isectech.com")
    local failed_endpoints=0
    
    for domain in "${domains[@]}"; do
        local http_status=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/health" 2>/dev/null || echo "000")
        if [[ "$http_status" != "200" ]]; then
            ((failed_endpoints++))
            log ERROR "Endpoint validation failed: $domain (HTTP $http_status)"
        else
            log INFO "Endpoint validation passed: $domain"
        fi
    done
    
    if [[ $failed_endpoints -gt 0 ]]; then
        ((validation_errors++))
    fi
    
    return $validation_errors
}

# Function to create recovery report
create_recovery_report() {
    local recovery_status="$1"
    local health_percentage="$2"
    
    log INFO "Creating recovery report..."
    
    local report_file="/tmp/recovery-report-$RECOVERY_ID.json"
    
    cat > "$report_file" << EOF
{
  "recovery_id": "$RECOVERY_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "recovery_type": "$RECOVERY_TYPE",
  "severity": "$SEVERITY",
  "status": "$recovery_status",
  "health_percentage": $health_percentage,
  "duration_minutes": $(( ($(date +%s) - $(date -d "$(head -1 "$LOG_FILE" | cut -d']' -f1 | tr -d '[')" +%s)) / 60 )),
  "log_file": "$LOG_FILE",
  "dry_run": $([ "$DRY_RUN" == "--dry-run" ] && echo "true" || echo "false")
}
EOF
    
    # Upload report to backup bucket
    if [[ "$DRY_RUN" != "--dry-run" ]]; then
        gsutil cp "$report_file" "$BACKUP_BUCKET/recovery-reports/" 2>/dev/null || true
    fi
    
    log INFO "Recovery report created: $report_file"
}

# Main recovery orchestration function
main() {
    log INFO "Starting automated disaster recovery - ID: $RECOVERY_ID"
    log INFO "Recovery Type: $RECOVERY_TYPE, Severity: $SEVERITY"
    
    if [[ "$DRY_RUN" == "--dry-run" ]]; then
        log INFO "DRY RUN MODE - No actual changes will be made"
    fi
    
    # Send initial notification
    send_notification "Automated Recovery Started" \
        "Recovery ID: $RECOVERY_ID\nType: $RECOVERY_TYPE\nSeverity: $SEVERITY\nMode: $([ "$DRY_RUN" == "--dry-run" ] && echo "DRY RUN" || echo "LIVE")"
    
    # Check prerequisites
    check_prerequisites
    
    # Initial health assessment
    local initial_health=$(assess_system_health)
    log INFO "Initial system health: $initial_health%"
    
    # Determine recovery actions based on health and type
    local recovery_success=true
    
    case $RECOVERY_TYPE in
        "full")
            log INFO "Executing full disaster recovery..."
            
            if [[ $initial_health -lt 50 ]]; then
                log INFO "Low system health detected - executing comprehensive recovery"
                
                # Execute all recovery procedures
                execute_dns_recovery || recovery_success=false
                execute_certificate_recovery || recovery_success=false
                execute_service_recovery || recovery_success=false
                execute_database_recovery || recovery_success=false
            else
                log INFO "System health acceptable - executing targeted recovery"
                execute_service_recovery || recovery_success=false
            fi
            ;;
            
        "dns")
            execute_dns_recovery || recovery_success=false
            ;;
            
        "certificates")
            execute_certificate_recovery || recovery_success=false
            ;;
            
        "services")
            execute_service_recovery || recovery_success=false
            ;;
            
        "database")
            execute_database_recovery || recovery_success=false
            ;;
            
        *)
            log ERROR "Unknown recovery type: $RECOVERY_TYPE"
            exit 1
            ;;
    esac
    
    # Validate recovery
    local validation_result=0
    if $recovery_success; then
        validate_recovery
        validation_result=$?
    fi
    
    # Final health assessment
    local final_health=$(assess_system_health)
    log INFO "Final system health: $final_health%"
    
    # Determine overall status
    local overall_status
    if $recovery_success && [[ $validation_result -eq 0 ]]; then
        overall_status="SUCCESS"
        log SUCCESS "Automated disaster recovery completed successfully"
    elif $recovery_success && [[ $validation_result -eq 1 ]]; then
        overall_status="PARTIAL"
        log WARN "Automated disaster recovery partially successful"
    else
        overall_status="FAILED"
        log ERROR "Automated disaster recovery failed"
    fi
    
    # Create recovery report
    create_recovery_report "$overall_status" "$final_health"
    
    # Send final notification
    local improvement=$((final_health - initial_health))
    send_notification "Automated Recovery Completed - $overall_status" \
        "Recovery ID: $RECOVERY_ID\nStatus: $overall_status\nHealth Improvement: $improvement% ($initial_health% → $final_health%)\nLog: $LOG_FILE"
    
    log INFO "Recovery process completed - Status: $overall_status"
    log INFO "Log file: $LOG_FILE"
    
    # Exit with appropriate code
    case $overall_status in
        "SUCCESS") exit 0 ;;
        "PARTIAL") exit 1 ;;
        "FAILED") exit 2 ;;
    esac
}

# Script usage
usage() {
    cat << EOF
Usage: $0 [recovery-type] [severity] [--dry-run]

Recovery Types:
  full         - Full disaster recovery (default)
  dns          - DNS-specific recovery
  certificates - Certificate-specific recovery
  services     - Service-specific recovery
  database     - Database-specific recovery

Severity Levels:
  CRITICAL     - Complete system outage
  HIGH         - Significant service degradation (default)  
  MEDIUM       - Partial service impact
  LOW          - Minor issues

Options:
  --dry-run    - Simulate recovery without making changes

Examples:
  $0                           # Full recovery, HIGH severity
  $0 services CRITICAL         # Service recovery, CRITICAL severity
  $0 dns MEDIUM --dry-run      # DNS recovery simulation

Environment Variables:
  PROJECT_ID              - Google Cloud Project ID
  REGION                  - Primary region
  BACKUP_BUCKET          - Backup storage location
  NOTIFICATION_EMAIL     - Alert email address
  SLACK_WEBHOOK_URL      - Slack notification webhook

EOF
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# Execute main function
main "$@"