#!/bin/bash

# iSECTECH Automated Rollback System
# Intelligent rollback system with health monitoring and automated recovery
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
MONITORING_INTERVAL="${MONITORING_INTERVAL:-30}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10}"
ROLLBACK_COOLDOWN="${ROLLBACK_COOLDOWN:-300}"

# Rollback trigger thresholds
ERROR_RATE_THRESHOLD="${ERROR_RATE_THRESHOLD:-0.05}"  # 5%
RESPONSE_TIME_THRESHOLD="${RESPONSE_TIME_THRESHOLD:-5000}"  # 5 seconds
AVAILABILITY_THRESHOLD="${AVAILABILITY_THRESHOLD:-0.99}"  # 99%
CONSECUTIVE_FAILURES_THRESHOLD="${CONSECUTIVE_FAILURES_THRESHOLD:-3}"

# Service definitions
SERVICES=(
    "frontend"
    "api-gateway"
    "auth-service"
    "asset-discovery"
    "event-processor"
    "threat-detection"
    "behavioral-analysis"
    "decision-engine"
    "nlp-assistant"
)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

# Initialize rollback state tracking
initialize_rollback_state() {
    local state_dir="/tmp/isectech-rollback-state"
    mkdir -p "$state_dir"
    
    for service in "${SERVICES[@]}"; do
        for env in "development" "staging" "production"; do
            local state_file="${state_dir}/${service}-${env}.json"
            if [ ! -f "$state_file" ]; then
                cat > "$state_file" << EOF
{
  "service": "$service",
  "environment": "$env",
  "consecutive_failures": 0,
  "last_rollback": 0,
  "rollback_count": 0,
  "current_revision": "",
  "previous_revision": "",
  "health_status": "unknown",
  "last_health_check": 0
}
EOF
            fi
        done
    done
    
    log_info "Rollback state initialized"
}

# Update rollback state
update_rollback_state() {
    local service="$1"
    local environment="$2"
    local field="$3"
    local value="$4"
    
    local state_file="/tmp/isectech-rollback-state/${service}-${environment}.json"
    
    # Create temporary file with updated state
    local temp_file=$(mktemp)
    jq --arg field "$field" --arg value "$value" '.[$field] = $value' "$state_file" > "$temp_file"
    mv "$temp_file" "$state_file"
}

# Get rollback state
get_rollback_state() {
    local service="$1"
    local environment="$2"
    local field="$3"
    
    local state_file="/tmp/isectech-rollback-state/${service}-${environment}.json"
    
    if [ -f "$state_file" ]; then
        jq -r ".${field}" "$state_file"
    else
        echo "null"
    fi
}

# Get service health metrics from Cloud Monitoring
get_service_metrics() {
    local service="$1"
    local environment="$2"
    local metric_type="$3"
    local duration="$4"
    
    local service_name="isectech-${service}-${environment}"
    local end_time=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    local start_time=$(date -u -d "${duration} ago" +'%Y-%m-%dT%H:%M:%SZ')
    
    case "$metric_type" in
        "error_rate")
            # Get error rate from Cloud Run metrics
            gcloud monitoring metrics list \
                --filter="metric.type=run.googleapis.com/request_count" \
                --format="value()" \
                --quiet 2>/dev/null | head -1 || echo "0"
            ;;
        "response_time")
            # Get response time from Cloud Run metrics
            gcloud monitoring metrics list \
                --filter="metric.type=run.googleapis.com/request_latencies" \
                --format="value()" \
                --quiet 2>/dev/null | head -1 || echo "0"
            ;;
        "availability")
            # Calculate availability based on successful requests
            echo "0.99"  # Placeholder - would integrate with actual monitoring
            ;;
    esac
}

# Perform comprehensive health check
perform_health_check() {
    local service="$1"
    local environment="$2"
    
    local service_name="isectech-${service}-${environment}"
    
    log_info "Performing health check for $service_name"
    
    # Get service URL
    local service_url
    service_url=$(gcloud run services describe "$service_name" \
        --region="$REGION" \
        --format="value(status.url)" 2>/dev/null) || {
        log_error "Cannot get service URL for $service_name"
        return 1
    }
    
    if [ -z "$service_url" ]; then
        log_error "Service URL is empty for $service_name"
        return 1
    fi
    
    # Perform HTTP health check
    local health_endpoint="/health"
    local http_status
    local response_time
    
    # Measure response time and get HTTP status
    response_time=$(curl -o /dev/null -s -w '%{http_code}:%{time_total}' \
        --max-time "$HEALTH_CHECK_TIMEOUT" \
        "${service_url}${health_endpoint}" 2>/dev/null) || {
        log_error "Health check request failed for $service_name"
        return 1
    }
    
    http_status=$(echo "$response_time" | cut -d':' -f1)
    response_time_seconds=$(echo "$response_time" | cut -d':' -f2)
    
    # Check HTTP status
    if [ "$http_status" != "200" ]; then
        log_error "Health check failed for $service_name (HTTP $http_status)"
        return 1
    fi
    
    # Check response time
    response_time_ms=$(echo "$response_time_seconds * 1000" | bc -l 2>/dev/null || echo "0")
    if (( $(echo "$response_time_ms > $RESPONSE_TIME_THRESHOLD" |bc -l 2>/dev/null || echo "0") )); then
        log_warning "Slow response time for $service_name: ${response_time_ms}ms"
        return 1
    fi
    
    # Additional service-specific health checks
    case "$service" in
        "auth-service")
            # Check authentication endpoints
            local auth_status
            auth_status=$(curl -s --max-time 5 "${service_url}/auth/health" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
            if [ "$auth_status" != "200" ]; then
                log_error "Auth service specific health check failed"
                return 1
            fi
            ;;
        "api-gateway")
            # Check gateway routing
            local gateway_status
            gateway_status=$(curl -s --max-time 5 "${service_url}/api/health" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
            if [ "$gateway_status" != "200" ]; then
                log_error "API Gateway routing health check failed"
                return 1
            fi
            ;;
        "event-processor")
            # Check event processing queue
            local queue_status
            queue_status=$(curl -s --max-time 5 "${service_url}/queue/health" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
            if [ "$queue_status" != "200" ]; then
                log_error "Event processor queue health check failed"
                return 1
            fi
            ;;
    esac
    
    log_success "Health check passed for $service_name"
    return 0
}

# Check if rollback is needed based on metrics and health
check_rollback_needed() {
    local service="$1"
    local environment="$2"
    
    log_info "Checking rollback criteria for $service in $environment"
    
    # Get current failure count
    local consecutive_failures
    consecutive_failures=$(get_rollback_state "$service" "$environment" "consecutive_failures")
    
    # Check if in cooldown period
    local last_rollback
    last_rollback=$(get_rollback_state "$service" "$environment" "last_rollback")
    local current_time=$(date +%s)
    
    if [ "$last_rollback" != "0" ] && [ $((current_time - last_rollback)) -lt "$ROLLBACK_COOLDOWN" ]; then
        log_info "Service $service in cooldown period, skipping rollback check"
        return 1
    fi
    
    # Perform health check
    if perform_health_check "$service" "$environment"; then
        # Health check passed, reset failure count
        update_rollback_state "$service" "$environment" "consecutive_failures" "0"
        update_rollback_state "$service" "$environment" "health_status" "healthy"
        update_rollback_state "$service" "$environment" "last_health_check" "$current_time"
        return 1
    else
        # Health check failed, increment failure count
        consecutive_failures=$((consecutive_failures + 1))
        update_rollback_state "$service" "$environment" "consecutive_failures" "$consecutive_failures"
        update_rollback_state "$service" "$environment" "health_status" "unhealthy"
        update_rollback_state "$service" "$environment" "last_health_check" "$current_time"
    fi
    
    # Check if we've exceeded the failure threshold
    if [ "$consecutive_failures" -ge "$CONSECUTIVE_FAILURES_THRESHOLD" ]; then
        log_error "Service $service has $consecutive_failures consecutive failures (threshold: $CONSECUTIVE_FAILURES_THRESHOLD)"
        return 0
    fi
    
    # Get service metrics
    local error_rate
    local response_time
    local availability
    
    error_rate=$(get_service_metrics "$service" "$environment" "error_rate" "5m")
    response_time=$(get_service_metrics "$service" "$environment" "response_time" "5m")
    availability=$(get_service_metrics "$service" "$environment" "availability" "10m")
    
    # Check error rate threshold
    if (( $(echo "$error_rate > $ERROR_RATE_THRESHOLD" |bc -l 2>/dev/null || echo "0") )); then
        log_error "Service $service error rate ($error_rate) exceeds threshold ($ERROR_RATE_THRESHOLD)"
        return 0
    fi
    
    # Check availability threshold
    if (( $(echo "$availability < $AVAILABILITY_THRESHOLD" |bc -l 2>/dev/null || echo "0") )); then
        log_error "Service $service availability ($availability) below threshold ($AVAILABILITY_THRESHOLD)"
        return 0
    fi
    
    log_info "No rollback needed for $service in $environment"
    return 1
}

# Execute automated rollback
execute_rollback() {
    local service="$1"
    local environment="$2"
    local reason="$3"
    
    local service_name="isectech-${service}-${environment}"
    
    log_warning "Executing automated rollback for $service_name (Reason: $reason)"
    
    # Get previous revision
    local previous_revision
    previous_revision=$(gcloud run revisions list \
        --service="$service_name" \
        --region="$REGION" \
        --limit=2 \
        --format="value(metadata.name)" | tail -n 1)
    
    if [ -z "$previous_revision" ]; then
        log_error "No previous revision found for $service_name - cannot rollback"
        return 1
    fi
    
    log_info "Rolling back $service_name to revision: $previous_revision"
    
    # Store current revision before rollback
    local current_revision
    current_revision=$(gcloud run revisions list \
        --service="$service_name" \
        --region="$REGION" \
        --limit=1 \
        --format="value(metadata.name)")
    
    update_rollback_state "$service" "$environment" "current_revision" "$current_revision"
    update_rollback_state "$service" "$environment" "previous_revision" "$previous_revision"
    
    # Execute rollback
    if gcloud run services update-traffic "$service_name" \
        --to-revisions="$previous_revision=100" \
        --region="$REGION"; then
        
        log_success "Rollback executed successfully for $service_name"
        
        # Update rollback state
        local current_time=$(date +%s)
        local rollback_count
        rollback_count=$(get_rollback_state "$service" "$environment" "rollback_count")
        rollback_count=$((rollback_count + 1))
        
        update_rollback_state "$service" "$environment" "last_rollback" "$current_time"
        update_rollback_state "$service" "$environment" "rollback_count" "$rollback_count"
        update_rollback_state "$service" "$environment" "consecutive_failures" "0"
        
        # Send notification
        send_rollback_notification "$service" "$environment" "$reason" "$current_revision" "$previous_revision"
        
        # Wait and validate rollback
        sleep 30
        if perform_health_check "$service" "$environment"; then
            log_success "Rollback validation successful for $service_name"
            update_rollback_state "$service" "$environment" "health_status" "healthy"
        else
            log_error "Rollback validation failed for $service_name - manual intervention required"
            update_rollback_state "$service" "$environment" "health_status" "critical"
            send_critical_alert "$service" "$environment" "Rollback validation failed"
        fi
        
        return 0
    else
        log_error "Rollback failed for $service_name"
        send_critical_alert "$service" "$environment" "Rollback execution failed"
        return 1
    fi
}

# Send rollback notification
send_rollback_notification() {
    local service="$1"
    local environment="$2"
    local reason="$3"
    local from_revision="$4"
    local to_revision="$5"
    
    local notification_payload=$(cat << EOF
{
  "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "event_type": "automated_rollback",
  "service": "$service",
  "environment": "$environment",
  "reason": "$reason",
  "from_revision": "$from_revision",
  "to_revision": "$to_revision",
  "project_id": "$PROJECT_ID",
  "region": "$REGION"
}
EOF
)
    
    # Log the notification
    echo "$notification_payload" > "/tmp/rollback-notification-$(date +%s).json"
    log_info "Rollback notification generated for $service in $environment"
    
    # Here you would integrate with actual notification systems
    # For example: Slack, PagerDuty, email, etc.
}

# Send critical alert
send_critical_alert() {
    local service="$1"
    local environment="$2"
    local message="$3"
    
    local alert_payload=$(cat << EOF
{
  "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "event_type": "critical_alert",
  "service": "$service",
  "environment": "$environment",
  "message": "$message",
  "severity": "critical",
  "project_id": "$PROJECT_ID",
  "region": "$REGION"
}
EOF
)
    
    echo "$alert_payload" > "/tmp/critical-alert-$(date +%s).json"
    log_error "CRITICAL ALERT: $message for $service in $environment"
}

# Monitor all services
monitor_services() {
    local environment="$1"
    
    log_info "Starting service monitoring for $environment environment"
    
    while true; do
        log_info "Monitoring cycle started for $environment"
        
        for service in "${SERVICES[@]}"; do
            if check_rollback_needed "$service" "$environment"; then
                execute_rollback "$service" "$environment" "Health check failures exceeded threshold"
            fi
        done
        
        log_info "Monitoring cycle completed for $environment, sleeping for ${MONITORING_INTERVAL}s"
        sleep "$MONITORING_INTERVAL"
    done
}

# Generate rollback report
generate_rollback_report() {
    local environment="$1"
    local report_file="/tmp/rollback-report-${environment}-$(date +%Y%m%d-%H%M%S).json"
    
    local services_data="["
    for service in "${SERVICES[@]}"; do
        local state_file="/tmp/isectech-rollback-state/${service}-${environment}.json"
        if [ -f "$state_file" ]; then
            if [ "$services_data" != "[" ]; then
                services_data="${services_data},"
            fi
            services_data="${services_data}$(cat "$state_file")"
        fi
    done
    services_data="${services_data}]"
    
    cat > "$report_file" << EOF
{
  "report_timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "environment": "$environment",
  "project_id": "$PROJECT_ID",
  "region": "$REGION",
  "services": $services_data,
  "thresholds": {
    "error_rate": $ERROR_RATE_THRESHOLD,
    "response_time_ms": $RESPONSE_TIME_THRESHOLD,
    "availability": $AVAILABILITY_THRESHOLD,
    "consecutive_failures": $CONSECUTIVE_FAILURES_THRESHOLD
  },
  "monitoring_interval": $MONITORING_INTERVAL,
  "rollback_cooldown": $ROLLBACK_COOLDOWN
}
EOF
    
    log_success "Rollback report generated: $report_file"
    cat "$report_file"
}

# Show help
show_help() {
    cat << EOF
iSECTECH Automated Rollback System

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    monitor ENVIRONMENT             Start continuous monitoring
    check SERVICE ENVIRONMENT      Check if rollback is needed
    rollback SERVICE ENVIRONMENT   Execute manual rollback
    report ENVIRONMENT             Generate rollback report
    init                          Initialize rollback state
    
Environments:
    development, staging, production

Examples:
    # Start monitoring production environment
    $0 monitor production
    
    # Check if auth-service needs rollback
    $0 check auth-service production
    
    # Execute manual rollback
    $0 rollback api-gateway staging
    
    # Generate report
    $0 report production

Environment Variables:
    PROJECT_ID                      Google Cloud project ID
    REGION                         Google Cloud region
    MONITORING_INTERVAL            Monitoring interval in seconds (default: 30)
    ERROR_RATE_THRESHOLD           Error rate threshold (default: 0.05)
    RESPONSE_TIME_THRESHOLD        Response time threshold in ms (default: 5000)
    AVAILABILITY_THRESHOLD         Availability threshold (default: 0.99)
    CONSECUTIVE_FAILURES_THRESHOLD Consecutive failures threshold (default: 3)
    ROLLBACK_COOLDOWN             Rollback cooldown in seconds (default: 300)

EOF
}

# Main execution
main() {
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        "init")
            initialize_rollback_state
            ;;
        "monitor")
            if [ $# -ne 1 ]; then
                log_error "Usage: $0 monitor ENVIRONMENT"
                exit 1
            fi
            initialize_rollback_state
            monitor_services "$1"
            ;;
        "check")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 check SERVICE ENVIRONMENT"
                exit 1
            fi
            if check_rollback_needed "$1" "$2"; then
                echo "Rollback needed"
                exit 0
            else
                echo "No rollback needed"
                exit 1
            fi
            ;;
        "rollback")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 rollback SERVICE ENVIRONMENT"
                exit 1
            fi
            execute_rollback "$1" "$2" "Manual rollback requested"
            ;;
        "report")
            if [ $# -ne 1 ]; then
                log_error "Usage: $0 report ENVIRONMENT"
                exit 1
            fi
            generate_rollback_report "$1"
            ;;
        "help")
            show_help
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"