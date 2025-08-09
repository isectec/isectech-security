#!/bin/bash

# Monitoring and Health Check Script - iSECTECH Security Platform
# Version: 1.0
# Author: DevOps Team
# Usage: ./monitoring-health-check.sh [--continuous] [--alert-threshold]

set -euo pipefail

# Configuration
PROJECT_ID="isectech-security-platform"
REGION="us-central1"
NOTIFICATION_EMAIL="devops@isectech.com"
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"

# Script parameters
CONTINUOUS_MODE=${1:-""}
ALERT_THRESHOLD=${2:-75}

# Logging setup
LOG_FILE="/tmp/health-check-$(date +%Y%m%d%H%M%S).log"
CHECK_ID="HC-$(date +%Y%m%d%H%M%S)"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Health check results
declare -A HEALTH_RESULTS
OVERALL_HEALTH_SCORE=0
MAX_HEALTH_SCORE=0

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

# Function to send alerts
send_alert() {
    local severity="$1"
    local subject="$2"
    local message="$3"
    
    # Send email alert
    if command -v mail >/dev/null 2>&1; then
        echo "$message" | mail -s "[$severity] $subject" "$NOTIFICATION_EMAIL" || true
    fi
    
    # Send Slack alert
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local emoji
        case $severity in
            CRITICAL) emoji="🚨" ;;
            WARNING) emoji="⚠️" ;;
            INFO) emoji="ℹ️" ;;
            *) emoji="📊" ;;
        esac
        
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$emoji **[$severity] $subject**\n$message\"}" \
            "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
    
    log INFO "Alert sent [$severity]: $subject"
}

# Function to update health score
update_health_score() {
    local component="$1"
    local score="$2"
    local max_score="$3"
    local status="$4"
    
    HEALTH_RESULTS["$component"]="$score/$max_score ($status)"
    OVERALL_HEALTH_SCORE=$((OVERALL_HEALTH_SCORE + score))
    MAX_HEALTH_SCORE=$((MAX_HEALTH_SCORE + max_score))
}

# Function to check Cloud Run services
check_cloud_run_services() {
    log INFO "Checking Cloud Run services health..."
    
    local services=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")
    local healthy_services=0
    local total_services=${#services[@]}
    
    for service in "${services[@]}"; do
        log INFO "Checking service: $service"
        
        # Check service status
        local service_status=$(gcloud run services describe "$service" \
            --region="$REGION" --project="$PROJECT_ID" \
            --format="value(status.conditions[0].status)" 2>/dev/null || echo "UNKNOWN")
        
        # Check service URL
        local service_url=$(gcloud run services describe "$service" \
            --region="$REGION" --project="$PROJECT_ID" \
            --format="value(status.url)" 2>/dev/null || echo "")
        
        if [[ "$service_status" == "True" ]]; then
            # Test service endpoint
            if [[ -n "$service_url" ]]; then
                local http_status=$(curl -s -o /dev/null -w "%{http_code}" \
                    "$service_url/health" 2>/dev/null || echo "000")
                
                if [[ "$http_status" == "200" ]]; then
                    ((healthy_services++))
                    log SUCCESS "Service $service: HEALTHY (HTTP $http_status)"
                else
                    log WARN "Service $service: ENDPOINT_FAILED (HTTP $http_status)"
                fi
            else
                ((healthy_services++))
                log SUCCESS "Service $service: DEPLOYED"
            fi
        else
            log ERROR "Service $service: UNHEALTHY ($service_status)"
        fi
        
        # Check recent errors
        local error_count=$(gcloud logging read \
            "resource.type=\"cloud_run_revision\" resource.labels.service_name=\"$service\" severity>=ERROR" \
            --limit=10 --format="value(timestamp)" --freshness=10m 2>/dev/null | wc -l)
        
        if [[ $error_count -gt 5 ]]; then
            log WARN "Service $service: HIGH_ERROR_RATE ($error_count errors in 10min)"
        fi
    done
    
    local service_score=$((healthy_services * 25 / total_services))
    local status
    if [[ $healthy_services -eq $total_services ]]; then
        status="ALL_HEALTHY"
    elif [[ $healthy_services -gt $((total_services / 2)) ]]; then
        status="MOSTLY_HEALTHY"
    else
        status="DEGRADED"
    fi
    
    update_health_score "cloud_run" "$service_score" "25" "$status"
    
    if [[ $healthy_services -lt $total_services ]]; then
        send_alert "WARNING" "Cloud Run Services Degraded" \
            "Only $healthy_services out of $total_services Cloud Run services are healthy."
    fi
}

# Function to check database health
check_database_health() {
    log INFO "Checking database health..."
    
    local instances=("isectech-db-primary")
    local healthy_instances=0
    local total_instances=${#instances[@]}
    
    for instance in "${instances[@]}"; do
        log INFO "Checking database instance: $instance"
        
        # Check instance status
        local instance_status=$(gcloud sql instances describe "$instance" \
            --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "UNKNOWN")
        
        if [[ "$instance_status" == "RUNNABLE" ]]; then
            ((healthy_instances++))
            log SUCCESS "Database $instance: RUNNING"
            
            # Check connectivity
            if gcloud sql connect "$instance" --user=postgres --quiet <<< "SELECT 1;" >/dev/null 2>&1; then
                log SUCCESS "Database $instance: CONNECTIVITY_OK"
            else
                log WARN "Database $instance: CONNECTIVITY_FAILED"
                ((healthy_instances--))
            fi
            
            # Check disk usage
            local disk_usage=$(gcloud sql instances describe "$instance" \
                --project="$PROJECT_ID" --format="value(settings.dataDiskSizeGb)" 2>/dev/null || echo "0")
            
            if [[ $disk_usage -gt 80 ]]; then
                log WARN "Database $instance: HIGH_DISK_USAGE (${disk_usage}%)"
            fi
            
        else
            log ERROR "Database $instance: UNHEALTHY ($instance_status)"
        fi
        
        # Check recent backups
        local recent_backup=$(gcloud sql backups list --instance="$instance" \
            --project="$PROJECT_ID" --limit=1 --format="value(startTime)" 2>/dev/null | head -1)
        
        if [[ -n "$recent_backup" ]]; then
            local backup_age=$(( ($(date +%s) - $(date -d "$recent_backup" +%s)) / 3600 ))
            if [[ $backup_age -gt 24 ]]; then
                log WARN "Database $instance: OLD_BACKUP (${backup_age}h old)"
            else
                log SUCCESS "Database $instance: RECENT_BACKUP (${backup_age}h old)"
            fi
        else
            log ERROR "Database $instance: NO_BACKUP_FOUND"
        fi
    done
    
    local db_score=$((healthy_instances * 20 / total_instances))
    local status
    if [[ $healthy_instances -eq $total_instances ]]; then
        status="HEALTHY"
    else
        status="UNHEALTHY"
    fi
    
    update_health_score "database" "$db_score" "20" "$status"
    
    if [[ $healthy_instances -lt $total_instances ]]; then
        send_alert "CRITICAL" "Database Health Critical" \
            "Database instances are not healthy: $healthy_instances/$total_instances"
    fi
}

# Function to check DNS health
check_dns_health() {
    log INFO "Checking DNS health..."
    
    local domains=("isectech.com" "api.isectech.com" "app.isectech.com" "admin.isectech.com" "monitoring.isectech.com")
    local healthy_domains=0
    local total_domains=${#domains[@]}
    
    # Check DNS zone status
    local dns_zones=("isectech-main-zone")
    for zone in "${dns_zones[@]}"; do
        local zone_status=$(gcloud dns managed-zones describe "$zone" \
            --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")
        
        if [[ -n "$zone_status" ]]; then
            log SUCCESS "DNS zone $zone: EXISTS"
        else
            log ERROR "DNS zone $zone: NOT_FOUND"
        fi
    done
    
    # Check domain resolution
    for domain in "${domains[@]}"; do
        log INFO "Checking DNS resolution for: $domain"
        
        # Test against multiple DNS servers
        local dns_servers=("8.8.8.8" "1.1.1.1" "208.67.222.222")
        local resolved_count=0
        
        for dns_server in "${dns_servers[@]}"; do
            if dig +short "$domain" @"$dns_server" | grep -q .; then
                ((resolved_count++))
            fi
        done
        
        if [[ $resolved_count -eq ${#dns_servers[@]} ]]; then
            ((healthy_domains++))
            log SUCCESS "DNS $domain: RESOLVED_ALL_SERVERS"
        elif [[ $resolved_count -gt 0 ]]; then
            ((healthy_domains++))
            log WARN "DNS $domain: RESOLVED_PARTIAL ($resolved_count/${#dns_servers[@]})"
        else
            log ERROR "DNS $domain: RESOLUTION_FAILED"
        fi
        
        # Check DNSSEC if enabled
        local dnssec_status=$(dig +dnssec +short "$domain" | grep -c RRSIG || echo "0")
        if [[ $dnssec_status -gt 0 ]]; then
            log SUCCESS "DNS $domain: DNSSEC_ENABLED"
        else
            log INFO "DNS $domain: DNSSEC_DISABLED"
        fi
    done
    
    local dns_score=$((healthy_domains * 15 / total_domains))
    local status
    if [[ $healthy_domains -eq $total_domains ]]; then
        status="ALL_RESOLVED"
    elif [[ $healthy_domains -gt $((total_domains / 2)) ]]; then
        status="MOSTLY_RESOLVED"
    else
        status="RESOLUTION_ISSUES"
    fi
    
    update_health_score "dns" "$dns_score" "15" "$status"
    
    if [[ $healthy_domains -lt $total_domains ]]; then
        send_alert "WARNING" "DNS Resolution Issues" \
            "DNS resolution issues detected: $healthy_domains/$total_domains domains resolving properly."
    fi
}

# Function to check SSL certificate health
check_ssl_certificate_health() {
    log INFO "Checking SSL certificate health..."
    
    local domains=("api.isectech.com" "app.isectech.com" "admin.isectech.com" "monitoring.isectech.com")
    local healthy_certs=0
    local total_certs=${#domains[@]}
    
    # Check Certificate Manager certificates
    local cert_manager_certs=$(gcloud certificate-manager certificates list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$cert_manager_certs" ]]; then
        echo "$cert_manager_certs" | while read -r cert_name; do
            if [[ -n "$cert_name" ]]; then
                local cert_status=$(gcloud certificate-manager certificates describe "$cert_name" \
                    --project="$PROJECT_ID" --format="value(state)" 2>/dev/null || echo "UNKNOWN")
                
                if [[ "$cert_status" == "ACTIVE" ]]; then
                    log SUCCESS "Certificate Manager $cert_name: ACTIVE"
                else
                    log WARN "Certificate Manager $cert_name: $cert_status"
                fi
            fi
        done
    fi
    
    # Check domain certificates
    for domain in "${domains[@]}"; do
        log INFO "Checking SSL certificate for: $domain"
        
        # Check certificate validity
        local cert_info=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | \
            openssl x509 -noout -dates 2>/dev/null || echo "")
        
        if [[ -n "$cert_info" ]]; then
            # Check expiration
            local expiry_date=$(echo "$cert_info" | grep notAfter | cut -d= -f2)
            local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || echo "0")
            local current_epoch=$(date +%s)
            local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            if [[ $days_until_expiry -gt 30 ]]; then
                ((healthy_certs++))
                log SUCCESS "SSL $domain: VALID ($days_until_expiry days remaining)"
            elif [[ $days_until_expiry -gt 7 ]]; then
                ((healthy_certs++))
                log WARN "SSL $domain: EXPIRING_SOON ($days_until_expiry days remaining)"
            else
                log ERROR "SSL $domain: EXPIRING_CRITICAL ($days_until_expiry days remaining)"
            fi
            
            # Check certificate chain
            local chain_status=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | \
                openssl verify 2>&1 | grep -c "OK" || echo "0")
            
            if [[ $chain_status -gt 0 ]]; then
                log SUCCESS "SSL $domain: CHAIN_VALID"
            else
                log WARN "SSL $domain: CHAIN_ISSUES"
            fi
        else
            log ERROR "SSL $domain: CONNECTION_FAILED"
        fi
    done
    
    local ssl_score=$((healthy_certs * 15 / total_certs))
    local status
    if [[ $healthy_certs -eq $total_certs ]]; then
        status="ALL_VALID"
    elif [[ $healthy_certs -gt $((total_certs / 2)) ]]; then
        status="MOSTLY_VALID"
    else
        status="CERT_ISSUES"
    fi
    
    update_health_score "ssl_certificates" "$ssl_score" "15" "$status"
    
    if [[ $healthy_certs -lt $total_certs ]]; then
        send_alert "WARNING" "SSL Certificate Issues" \
            "SSL certificate issues detected: $healthy_certs/$total_certs certificates are healthy."
    fi
}

# Function to check load balancer health
check_load_balancer_health() {
    log INFO "Checking load balancer health..."
    
    local domains=("api.isectech.com" "app.isectech.com" "admin.isectech.com" "monitoring.isectech.com")
    local healthy_endpoints=0
    local total_endpoints=${#domains[@]}
    
    # Check backend services
    local backend_services=$(gcloud compute backend-services list --global \
        --project="$PROJECT_ID" --filter="name ~ isectech" \
        --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$backend_services" ]]; then
        echo "$backend_services" | while read -r backend_service; do
            if [[ -n "$backend_service" ]]; then
                log INFO "Checking backend service: $backend_service"
                
                # Check backend service health
                local backend_status=$(gcloud compute backend-services get-health "$backend_service" \
                    --global --project="$PROJECT_ID" --format="value(status.healthStatus[0].healthState)" 2>/dev/null || echo "UNKNOWN")
                
                if [[ "$backend_status" == "HEALTHY" ]]; then
                    log SUCCESS "Backend service $backend_service: HEALTHY"
                else
                    log WARN "Backend service $backend_service: $backend_status"
                fi
            fi
        done
    fi
    
    # Check endpoint availability
    for domain in "${domains[@]}"; do
        log INFO "Checking load balancer endpoint: $domain"
        
        # Test HTTP response
        local http_status=$(curl -s -o /dev/null -w "%{http_code}" "https://$domain/health" 2>/dev/null || echo "000")
        local response_time=$(curl -s -o /dev/null -w "%{time_total}" "https://$domain/health" 2>/dev/null || echo "0")
        
        if [[ "$http_status" == "200" ]]; then
            ((healthy_endpoints++))
            log SUCCESS "Load balancer $domain: HEALTHY (HTTP $http_status, ${response_time}s)"
            
            # Check response time
            if (( $(echo "$response_time > 2.0" | bc -l 2>/dev/null || echo "0") )); then
                log WARN "Load balancer $domain: SLOW_RESPONSE (${response_time}s)"
            fi
        else
            log ERROR "Load balancer $domain: UNHEALTHY (HTTP $http_status)"
        fi
    done
    
    local lb_score=$((healthy_endpoints * 10 / total_endpoints))
    local status
    if [[ $healthy_endpoints -eq $total_endpoints ]]; then
        status="ALL_HEALTHY"
    elif [[ $healthy_endpoints -gt $((total_endpoints / 2)) ]]; then
        status="MOSTLY_HEALTHY"
    else
        status="DEGRADED"
    fi
    
    update_health_score "load_balancer" "$lb_score" "10" "$status"
    
    if [[ $healthy_endpoints -lt $total_endpoints ]]; then
        send_alert "WARNING" "Load Balancer Issues" \
            "Load balancer endpoint issues: $healthy_endpoints/$total_endpoints endpoints healthy."
    fi
}

# Function to check monitoring and logging
check_monitoring_health() {
    log INFO "Checking monitoring and logging health..."
    
    local monitoring_score=0
    local max_monitoring_score=15
    
    # Check Cloud Monitoring metrics availability
    local metrics_available=$(gcloud logging read "resource.type=\"cloud_run_revision\"" \
        --limit=1 --format="value(timestamp)" --freshness=10m 2>/dev/null | wc -l)
    
    if [[ $metrics_available -gt 0 ]]; then
        ((monitoring_score += 5))
        log SUCCESS "Monitoring: METRICS_AVAILABLE"
    else
        log WARN "Monitoring: NO_RECENT_METRICS"
    fi
    
    # Check alerting policies
    local alert_policies=$(gcloud alpha monitoring policies list \
        --filter="enabled=true" --format="value(name)" 2>/dev/null | wc -l)
    
    if [[ $alert_policies -gt 0 ]]; then
        ((monitoring_score += 5))
        log SUCCESS "Monitoring: ALERT_POLICIES_ACTIVE ($alert_policies policies)"
    else
        log WARN "Monitoring: NO_ALERT_POLICIES"
    fi
    
    # Check log ingestion
    local recent_logs=$(gcloud logging read "resource.type=\"cloud_run_revision\"" \
        --limit=10 --format="value(timestamp)" --freshness=5m 2>/dev/null | wc -l)
    
    if [[ $recent_logs -gt 5 ]]; then
        ((monitoring_score += 5))
        log SUCCESS "Monitoring: LOG_INGESTION_ACTIVE ($recent_logs recent logs)"
    else
        log WARN "Monitoring: LOW_LOG_INGESTION ($recent_logs recent logs)"
    fi
    
    local status
    if [[ $monitoring_score -eq $max_monitoring_score ]]; then
        status="FULLY_OPERATIONAL"
    elif [[ $monitoring_score -gt $((max_monitoring_score / 2)) ]]; then
        status="MOSTLY_OPERATIONAL"
    else
        status="DEGRADED"
    fi
    
    update_health_score "monitoring" "$monitoring_score" "$max_monitoring_score" "$status"
}

# Function to generate health report
generate_health_report() {
    log INFO "Generating health report..."
    
    local health_percentage=$((OVERALL_HEALTH_SCORE * 100 / MAX_HEALTH_SCORE))
    local report_file="/tmp/health-report-$CHECK_ID.json"
    
    # Create detailed health report
    cat > "$report_file" << EOF
{
  "check_id": "$CHECK_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "overall_health_percentage": $health_percentage,
  "overall_health_score": "$OVERALL_HEALTH_SCORE/$MAX_HEALTH_SCORE",
  "status": "$(get_overall_status $health_percentage)",
  "components": {
EOF
    
    local first=true
    for component in "${!HEALTH_RESULTS[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$report_file"
        fi
        echo "    \"$component\": \"${HEALTH_RESULTS[$component]}\"" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF
  },
  "log_file": "$LOG_FILE",
  "project_id": "$PROJECT_ID",
  "region": "$REGION"
}
EOF
    
    log INFO "Health report generated: $report_file"
    
    # Upload report to Cloud Storage if available
    if gsutil ls gs://isectech-monitoring-reports/ >/dev/null 2>&1; then
        gsutil cp "$report_file" gs://isectech-monitoring-reports/health-checks/ 2>/dev/null || true
    fi
    
    echo "$health_percentage"
}

# Function to get overall status
get_overall_status() {
    local percentage=$1
    
    if [[ $percentage -ge 95 ]]; then
        echo "EXCELLENT"
    elif [[ $percentage -ge 85 ]]; then
        echo "GOOD"
    elif [[ $percentage -ge 70 ]]; then
        echo "FAIR"
    elif [[ $percentage -ge 50 ]]; then
        echo "POOR"
    else
        echo "CRITICAL"
    fi
}

# Function to run continuous monitoring
run_continuous_monitoring() {
    log INFO "Starting continuous monitoring mode..."
    
    local check_interval=300  # 5 minutes
    local consecutive_failures=0
    local max_consecutive_failures=3
    
    while true; do
        log INFO "Running health check cycle..."
        
        # Reset health scores
        OVERALL_HEALTH_SCORE=0
        MAX_HEALTH_SCORE=0
        declare -A HEALTH_RESULTS
        
        # Run all health checks
        check_cloud_run_services
        check_database_health
        check_dns_health
        check_ssl_certificate_health
        check_load_balancer_health
        check_monitoring_health
        
        # Generate report
        local health_percentage=$(generate_health_report)
        local overall_status=$(get_overall_status $health_percentage)
        
        log INFO "Health check completed - Overall: $health_percentage% ($overall_status)"
        
        # Check if alert threshold is breached
        if [[ $health_percentage -lt $ALERT_THRESHOLD ]]; then
            ((consecutive_failures++))
            log WARN "Health below threshold: $health_percentage% < $ALERT_THRESHOLD% (failure $consecutive_failures/$max_consecutive_failures)"
            
            if [[ $consecutive_failures -ge $max_consecutive_failures ]]; then
                send_alert "CRITICAL" "System Health Critical" \
                    "System health has been below threshold for $consecutive_failures consecutive checks.\nCurrent health: $health_percentage%\nThreshold: $ALERT_THRESHOLD%"
                consecutive_failures=0  # Reset after alerting
            fi
        else
            if [[ $consecutive_failures -gt 0 ]]; then
                log INFO "Health recovered above threshold: $health_percentage% >= $ALERT_THRESHOLD%"
                consecutive_failures=0
            fi
        fi
        
        # Wait for next check
        log INFO "Waiting $check_interval seconds until next check..."
        sleep $check_interval
    done
}

# Main function
main() {
    log INFO "Starting health check - ID: $CHECK_ID"
    
    if [[ "$CONTINUOUS_MODE" == "--continuous" ]]; then
        run_continuous_monitoring
    else
        # Run single health check
        check_cloud_run_services
        check_database_health
        check_dns_health
        check_ssl_certificate_health
        check_load_balancer_health
        check_monitoring_health
        
        # Generate final report
        local health_percentage=$(generate_health_report)
        local overall_status=$(get_overall_status $health_percentage)
        
        log SUCCESS "Health check completed - Overall: $health_percentage% ($overall_status)"
        
        # Send alert if below threshold
        if [[ $health_percentage -lt $ALERT_THRESHOLD ]]; then
            send_alert "WARNING" "System Health Below Threshold" \
                "System health is below the alert threshold.\nCurrent health: $health_percentage%\nThreshold: $ALERT_THRESHOLD%"
        fi
        
        log INFO "Log file: $LOG_FILE"
        
        # Exit with appropriate code based on health
        if [[ $health_percentage -ge 90 ]]; then
            exit 0
        elif [[ $health_percentage -ge 70 ]]; then
            exit 1
        else
            exit 2
        fi
    fi
}

# Script usage
usage() {
    cat << EOF
Usage: $0 [--continuous] [--alert-threshold PERCENTAGE]

Options:
  --continuous           Run in continuous monitoring mode
  --alert-threshold NUM  Health percentage threshold for alerts (default: 75)

Examples:
  $0                            # Single health check
  $0 --continuous               # Continuous monitoring
  $0 --alert-threshold 80       # Single check with 80% alert threshold
  $0 --continuous 90            # Continuous with 90% threshold

Environment Variables:
  PROJECT_ID           - Google Cloud Project ID
  REGION               - Primary region
  NOTIFICATION_EMAIL   - Alert email address
  SLACK_WEBHOOK_URL    - Slack webhook for alerts

Health Check Components:
  - Cloud Run Services (25 points)
  - Database Health (20 points)
  - DNS Resolution (15 points)
  - SSL Certificates (15 points)
  - Load Balancer (10 points)
  - Monitoring/Logging (15 points)
  Total: 100 points

EOF
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# Parse alert threshold if provided
if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
    ALERT_THRESHOLD=$2
fi

# Execute main function
main "$@"