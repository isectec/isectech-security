#!/bin/bash

# iSECTECH Comprehensive Health Check System
# Advanced health monitoring with circuit breakers, synthetic testing, and reliability patterns
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Health check configuration
HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL:-30}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-3}"
CIRCUIT_BREAKER_THRESHOLD="${CIRCUIT_BREAKER_THRESHOLD:-5}"
CIRCUIT_BREAKER_TIMEOUT="${CIRCUIT_BREAKER_TIMEOUT:-60}"

# Service definitions with health check endpoints
declare -A SERVICE_HEALTH_CONFIGS=(
    # Core services
    ["frontend"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=5,critical=true"
    ["api-gateway"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=10,critical=true"
    ["auth-service"]="health=/auth/health,readiness=/auth/ready,liveness=/auth/live,startup=/auth/startup,timeout=15,critical=true"
    
    # Processing services
    ["asset-discovery"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=20,critical=true"
    ["event-processor"]="health=/events/health,readiness=/events/ready,liveness=/events/live,startup=/events/startup,timeout=30,critical=true"
    ["threat-detection"]="health=/threats/health,readiness=/threats/ready,liveness=/threats/live,startup=/threats/startup,timeout=45,critical=true"
    
    # AI services
    ["behavioral-analysis"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=60,critical=false"
    ["decision-engine"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=30,critical=false"
    ["nlp-assistant"]="health=/health,readiness=/ready,liveness=/live,startup=/startup,timeout=45,critical=false"
)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

log_debug() {
    echo -e "${PURPLE}[DEBUG]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

# Initialize health check system
initialize_health_system() {
    log_info "Initializing comprehensive health check system"
    
    # Create directories for health data
    mkdir -p /tmp/isectech-health/{state,reports,circuit-breakers,synthetic-tests}
    mkdir -p /tmp/isectech-health/metrics/{latency,availability,errors}
    
    # Initialize circuit breaker states
    for service in "${!SERVICE_HEALTH_CONFIGS[@]}"; do
        for env in "development" "staging" "production"; do
            local cb_file="/tmp/isectech-health/circuit-breakers/${service}-${env}.json"
            if [ ! -f "$cb_file" ]; then
                cat > "$cb_file" << EOF
{
  "service": "$service",
  "environment": "$env",
  "state": "closed",
  "failure_count": 0,
  "last_failure_time": 0,
  "last_success_time": $(date +%s),
  "total_requests": 0,
  "successful_requests": 0,
  "circuit_opened_count": 0,
  "last_state_change": $(date +%s)
}
EOF
            fi
        done
    done
    
    log_success "Health check system initialized"
}

# Parse service health configuration
parse_health_config() {
    local service="$1"
    local config="${SERVICE_HEALTH_CONFIGS[$service]:-}"
    
    # Default values
    HEALTH_ENDPOINT="/health"
    READINESS_ENDPOINT="/ready"
    LIVENESS_ENDPOINT="/live"
    STARTUP_ENDPOINT="/startup"
    ENDPOINT_TIMEOUT="10"
    IS_CRITICAL="true"
    
    if [ -n "$config" ]; then
        # Parse configuration string
        IFS=',' read -ra CONFIG_PARTS <<< "$config"
        for part in "${CONFIG_PARTS[@]}"; do
            IFS='=' read -ra KV <<< "$part"
            case "${KV[0]}" in
                "health") HEALTH_ENDPOINT="${KV[1]}" ;;
                "readiness") READINESS_ENDPOINT="${KV[1]}" ;;
                "liveness") LIVENESS_ENDPOINT="${KV[1]}" ;;
                "startup") STARTUP_ENDPOINT="${KV[1]}" ;;
                "timeout") ENDPOINT_TIMEOUT="${KV[1]}" ;;
                "critical") IS_CRITICAL="${KV[1]}" ;;
            esac
        done
    fi
    
    log_debug "Health config for $service: endpoints=($HEALTH_ENDPOINT,$READINESS_ENDPOINT,$LIVENESS_ENDPOINT), timeout=${ENDPOINT_TIMEOUT}s, critical=$IS_CRITICAL"
}

# Get service URL
get_service_url() {
    local service="$1"
    local environment="$2"
    
    local service_name="isectech-${service}-${environment}"
    
    gcloud run services describe "$service_name" \
        --region="$REGION" \
        --format="value(status.url)" 2>/dev/null || echo ""
}

# Update circuit breaker state
update_circuit_breaker() {
    local service="$1"
    local environment="$2"
    local field="$3"
    local value="$4"
    
    local cb_file="/tmp/isectech-health/circuit-breakers/${service}-${environment}.json"
    
    if [ -f "$cb_file" ]; then
        local temp_file=$(mktemp)
        jq --arg field "$field" --arg value "$value" '.[$field] = ($value | if . == "true" or . == "false" then (. == "true") elif (. | test("^[0-9]+$")) then (. | tonumber) else . end)' "$cb_file" > "$temp_file"
        mv "$temp_file" "$cb_file"
    fi
}

# Get circuit breaker state
get_circuit_breaker_state() {
    local service="$1"
    local environment="$2"
    local field="$3"
    
    local cb_file="/tmp/isectech-health/circuit-breakers/${service}-${environment}.json"
    
    if [ -f "$cb_file" ]; then
        jq -r ".${field}" "$cb_file"
    else
        echo "null"
    fi
}

# Check circuit breaker state
check_circuit_breaker() {
    local service="$1"
    local environment="$2"
    
    local state=$(get_circuit_breaker_state "$service" "$environment" "state")
    local failure_count=$(get_circuit_breaker_state "$service" "$environment" "failure_count")
    local last_failure_time=$(get_circuit_breaker_state "$service" "$environment" "last_failure_time")
    local current_time=$(date +%s)
    
    case "$state" in
        "open")
            # Check if circuit breaker should move to half-open
            if [ $((current_time - last_failure_time)) -gt "$CIRCUIT_BREAKER_TIMEOUT" ]; then
                log_info "Circuit breaker for $service-$environment moving from OPEN to HALF-OPEN"
                update_circuit_breaker "$service" "$environment" "state" "half-open"
                update_circuit_breaker "$service" "$environment" "last_state_change" "$current_time"
                return 2  # Half-open
            else
                log_warning "Circuit breaker for $service-$environment is OPEN (failing fast)"
                return 1  # Open
            fi
            ;;
        "half-open")
            log_debug "Circuit breaker for $service-$environment is HALF-OPEN (testing)"
            return 2  # Half-open
            ;;
        "closed")
            log_debug "Circuit breaker for $service-$environment is CLOSED (normal operation)"
            return 0  # Closed
            ;;
        *)
            log_warning "Unknown circuit breaker state for $service-$environment: $state"
            return 0  # Default to closed
            ;;
    esac
}

# Record circuit breaker success
record_circuit_breaker_success() {
    local service="$1"
    local environment="$2"
    local current_time=$(date +%s)
    
    local state=$(get_circuit_breaker_state "$service" "$environment" "state")
    local total_requests=$(get_circuit_breaker_state "$service" "$environment" "total_requests")
    local successful_requests=$(get_circuit_breaker_state "$service" "$environment" "successful_requests")
    
    # Update counters
    update_circuit_breaker "$service" "$environment" "total_requests" $((total_requests + 1))
    update_circuit_breaker "$service" "$environment" "successful_requests" $((successful_requests + 1))
    update_circuit_breaker "$service" "$environment" "last_success_time" "$current_time"
    
    # Reset failure count and potentially close circuit
    if [ "$state" = "half-open" ]; then
        log_success "Circuit breaker for $service-$environment moving from HALF-OPEN to CLOSED"
        update_circuit_breaker "$service" "$environment" "state" "closed"
        update_circuit_breaker "$service" "$environment" "last_state_change" "$current_time"
    fi
    
    update_circuit_breaker "$service" "$environment" "failure_count" "0"
}

# Record circuit breaker failure
record_circuit_breaker_failure() {
    local service="$1"
    local environment="$2"
    local current_time=$(date +%s)
    
    local state=$(get_circuit_breaker_state "$service" "$environment" "state")
    local failure_count=$(get_circuit_breaker_state "$service" "$environment" "failure_count")
    local total_requests=$(get_circuit_breaker_state "$service" "$environment" "total_requests")
    local circuit_opened_count=$(get_circuit_breaker_state "$service" "$environment" "circuit_opened_count")
    
    # Update counters
    failure_count=$((failure_count + 1))
    update_circuit_breaker "$service" "$environment" "total_requests" $((total_requests + 1))
    update_circuit_breaker "$service" "$environment" "failure_count" "$failure_count"
    update_circuit_breaker "$service" "$environment" "last_failure_time" "$current_time"
    
    # Check if circuit should open
    if [ "$failure_count" -ge "$CIRCUIT_BREAKER_THRESHOLD" ] && [ "$state" != "open" ]; then
        log_error "Circuit breaker for $service-$environment OPENING due to $failure_count consecutive failures"
        update_circuit_breaker "$service" "$environment" "state" "open"
        update_circuit_breaker "$service" "$environment" "circuit_opened_count" $((circuit_opened_count + 1))
        update_circuit_breaker "$service" "$environment" "last_state_change" "$current_time"
    fi
}

# Perform detailed health check
perform_detailed_health_check() {
    local service="$1"
    local environment="$2"
    local check_type="${3:-all}"  # all, health, readiness, liveness, startup
    
    log_info "Performing detailed health check for $service in $environment (type: $check_type)"
    
    # Parse service configuration
    parse_health_config "$service"
    
    # Get service URL
    local service_url=$(get_service_url "$service" "$environment")
    if [ -z "$service_url" ]; then
        log_error "Cannot get service URL for $service in $environment"
        return 1
    fi
    
    # Check circuit breaker
    check_circuit_breaker "$service" "$environment"
    local cb_state=$?
    
    if [ $cb_state -eq 1 ]; then
        # Circuit is open - fail fast
        log_warning "Circuit breaker is OPEN for $service-$environment - failing fast"
        return 1
    fi
    
    local health_results=()
    local overall_success=true
    
    # Define endpoints to check based on check_type
    local endpoints_to_check=()
    case "$check_type" in
        "health") endpoints_to_check=("$HEALTH_ENDPOINT") ;;
        "readiness") endpoints_to_check=("$READINESS_ENDPOINT") ;;
        "liveness") endpoints_to_check=("$LIVENESS_ENDPOINT") ;;
        "startup") endpoints_to_check=("$STARTUP_ENDPOINT") ;;
        "all") endpoints_to_check=("$HEALTH_ENDPOINT" "$READINESS_ENDPOINT" "$LIVENESS_ENDPOINT" "$STARTUP_ENDPOINT") ;;
        *) endpoints_to_check=("$HEALTH_ENDPOINT") ;;
    esac
    
    # Perform health checks on each endpoint
    for endpoint in "${endpoints_to_check[@]}"; do
        local start_time=$(date +%s%3N)
        local http_response
        local exit_code=0
        
        # Perform HTTP request with detailed response capture
        http_response=$(curl -s -w "HTTPSTATUS:%{http_code};TIME:%{time_total};SIZE:%{size_download}" \
            --max-time "$ENDPOINT_TIMEOUT" \
            --retry "$HEALTH_CHECK_RETRIES" \
            --retry-delay 1 \
            "${service_url}${endpoint}" 2>/dev/null) || exit_code=$?
        
        local end_time=$(date +%s%3N)
        local response_time=$((end_time - start_time))
        
        # Parse response
        local http_body=$(echo "$http_response" | sed -E 's/HTTPSTATUS:[0-9]{3};TIME:[0-9.]+;SIZE:[0-9]+$//')
        local http_status=$(echo "$http_response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2)
        local curl_time=$(echo "$http_response" | grep -o "TIME:[0-9.]*" | cut -d: -f2)
        local response_size=$(echo "$http_response" | grep -o "SIZE:[0-9]*" | cut -d: -f2)
        
        # Evaluate health check result
        local endpoint_success=true
        local status_message=""
        
        if [ $exit_code -ne 0 ]; then
            endpoint_success=false
            status_message="Request failed (exit code: $exit_code)"
        elif [ -z "$http_status" ] || [ "$http_status" != "200" ]; then
            endpoint_success=false
            status_message="HTTP error (status: ${http_status:-unknown})"
        elif [ -n "$http_body" ]; then
            # Parse JSON response if available
            local service_status=$(echo "$http_body" | jq -r '.status // "unknown"' 2>/dev/null || echo "unknown")
            if [ "$service_status" = "unhealthy" ] || [ "$service_status" = "down" ]; then
                endpoint_success=false
                status_message="Service reports unhealthy status"
            fi
        fi
        
        # Record result
        if [ "$endpoint_success" = "true" ]; then
            log_success "✓ $service $endpoint: OK (${response_time}ms, ${http_status}, ${response_size} bytes)"
            health_results+=("$endpoint:SUCCESS:${response_time}:${http_status}")
        else
            log_error "✗ $service $endpoint: $status_message (${response_time}ms)"
            health_results+=("$endpoint:FAILURE:${response_time}:${http_status:-000}")
            overall_success=false
        fi
        
        # Store metrics
        store_health_metrics "$service" "$environment" "$endpoint" "$endpoint_success" "$response_time" "$http_status"
    done
    
    # Update circuit breaker based on overall result
    if [ "$overall_success" = "true" ]; then
        record_circuit_breaker_success "$service" "$environment"
        log_success "Overall health check PASSED for $service in $environment"
        
        # Store successful health check state
        store_health_state "$service" "$environment" "healthy" "${health_results[*]}"
        return 0
    else
        record_circuit_breaker_failure "$service" "$environment"
        log_error "Overall health check FAILED for $service in $environment"
        
        # Store failed health check state
        store_health_state "$service" "$environment" "unhealthy" "${health_results[*]}"
        return 1
    fi
}

# Store health metrics
store_health_metrics() {
    local service="$1"
    local environment="$2"
    local endpoint="$3"
    local success="$4"
    local response_time="$5"
    local http_status="$6"
    local timestamp=$(date +%s)
    
    # Store latency metrics
    echo "$timestamp,$service,$environment,$endpoint,$response_time,$success,$http_status" >> "/tmp/isectech-health/metrics/latency/${service}-${environment}.csv"
    
    # Store availability metrics
    local availability_value=0
    if [ "$success" = "true" ]; then
        availability_value=1
    fi
    echo "$timestamp,$service,$environment,$endpoint,$availability_value" >> "/tmp/isectech-health/metrics/availability/${service}-${environment}.csv"
    
    # Store error metrics
    if [ "$success" = "false" ]; then
        echo "$timestamp,$service,$environment,$endpoint,$http_status,health_check_failure" >> "/tmp/isectech-health/metrics/errors/${service}-${environment}.csv"
    fi
}

# Store health state
store_health_state() {
    local service="$1"
    local environment="$2"
    local status="$3"
    local details="$4"
    local timestamp=$(date +%s)
    
    local state_file="/tmp/isectech-health/state/${service}-${environment}.json"
    
    cat > "$state_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "status": "$status",
  "last_check_time": $timestamp,
  "last_check_iso": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "details": "$details",
  "consecutive_failures": $(get_circuit_breaker_state "$service" "$environment" "failure_count"),
  "circuit_breaker_state": "$(get_circuit_breaker_state "$service" "$environment" "state")"
}
EOF
}

# Perform synthetic transaction test
perform_synthetic_test() {
    local service="$1"
    local environment="$2"
    local test_type="${3:-basic}"  # basic, auth_flow, transaction_flow
    
    log_info "Performing synthetic test for $service in $environment (type: $test_type)"
    
    local service_url=$(get_service_url "$service" "$environment")
    if [ -z "$service_url" ]; then
        log_error "Cannot get service URL for synthetic test"
        return 1
    fi
    
    local test_success=true
    local test_details=""
    
    case "$test_type" in
        "auth_flow")
            test_success=$(perform_auth_flow_test "$service_url")
            test_details="Authentication flow test"
            ;;
        "transaction_flow")
            test_success=$(perform_transaction_flow_test "$service_url")
            test_details="Transaction flow test"
            ;;
        "basic")
            # Basic health + functionality test
            if perform_detailed_health_check "$service" "$environment" "health"; then
                test_success=true
                test_details="Basic health check passed"
            else
                test_success=false
                test_details="Basic health check failed"
            fi
            ;;
    esac
    
    # Store synthetic test results
    local timestamp=$(date +%s)
    local result_file="/tmp/isectech-health/synthetic-tests/${service}-${environment}-${test_type}-${timestamp}.json"
    
    cat > "$result_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "test_type": "$test_type",
  "timestamp": $timestamp,
  "success": $test_success,
  "details": "$test_details",
  "service_url": "$service_url"
}
EOF
    
    if [ "$test_success" = "true" ]; then
        log_success "Synthetic test PASSED for $service ($test_type)"
        return 0
    else
        log_error "Synthetic test FAILED for $service ($test_type)"
        return 1
    fi
}

# Perform authentication flow test
perform_auth_flow_test() {
    local service_url="$1"
    
    # Test user registration
    local test_user_data='{"username":"synthetic_test_user","password":"test_password_123","email":"synthetic@isectech.com"}'
    local register_response
    register_response=$(curl -s -X POST "${service_url}/auth/register" \
        -H "Content-Type: application/json" \
        -d "$test_user_data" \
        -w "%{http_code}" -o /tmp/synthetic_register_response.json \
        --max-time 30) || return 1
    
    if [[ ! "$register_response" =~ ^20[0-9]$ ]]; then
        log_debug "Registration failed or user exists: $register_response"
        # This might be expected if user already exists
    fi
    
    # Test user login
    local login_data='{"username":"synthetic_test_user","password":"test_password_123"}'
    local login_response
    login_response=$(curl -s -X POST "${service_url}/auth/login" \
        -H "Content-Type: application/json" \
        -d "$login_data" \
        -w "%{http_code}" -o /tmp/synthetic_login_response.json \
        --max-time 30) || return 1
    
    if [[ "$login_response" =~ ^20[0-9]$ ]]; then
        # Extract token and test protected endpoint
        local token=$(jq -r '.token // .access_token // ""' /tmp/synthetic_login_response.json 2>/dev/null)
        if [ -n "$token" ] && [ "$token" != "null" ]; then
            # Test protected endpoint
            local protected_response
            protected_response=$(curl -s -H "Authorization: Bearer $token" \
                "${service_url}/auth/profile" \
                -w "%{http_code}" -o /dev/null \
                --max-time 15) || return 1
            
            if [[ "$protected_response" =~ ^20[0-9]$ ]]; then
                return 0  # Success
            fi
        fi
    fi
    
    return 1  # Failure
}

# Perform transaction flow test
perform_transaction_flow_test() {
    local service_url="$1"
    
    # This would implement a multi-step transaction test
    # For now, we'll do a simplified version
    
    local endpoints=(
        "/api/v1/health"
        "/api/v1/status"
        "/api/v1/metrics"
    )
    
    for endpoint in "${endpoints[@]}"; do
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" \
            "${service_url}${endpoint}" \
            --max-time 15) || return 1
        
        if [[ ! "$response_code" =~ ^20[0-9]$ ]]; then
            return 1
        fi
    done
    
    return 0
}

# Monitor all services continuously
monitor_all_services() {
    local environment="$1"
    local check_interval="${2:-$HEALTH_CHECK_INTERVAL}"
    
    log_info "Starting continuous health monitoring for $environment environment (interval: ${check_interval}s)"
    
    local services=("${!SERVICE_HEALTH_CONFIGS[@]}")
    local cycle_count=0
    
    while true; do
        cycle_count=$((cycle_count + 1))
        log_info "Health monitoring cycle #$cycle_count started for $environment"
        
        local failed_services=()
        local critical_failures=()
        
        # Check each service
        for service in "${services[@]}"; do
            log_debug "Checking health of $service in $environment"
            
            if perform_detailed_health_check "$service" "$environment" "all"; then
                log_debug "✓ $service is healthy"
            else
                failed_services+=("$service")
                
                # Check if service is critical
                parse_health_config "$service"
                if [ "$IS_CRITICAL" = "true" ]; then
                    critical_failures+=("$service")
                fi
            fi
            
            # Brief pause between service checks
            sleep 2
        done
        
        # Generate cycle report
        generate_monitoring_cycle_report "$environment" "$cycle_count" "${failed_services[@]}" "${critical_failures[@]}"
        
        # Alert on critical failures
        if [ ${#critical_failures[@]} -gt 0 ]; then
            send_critical_health_alert "$environment" "${critical_failures[@]}"
        fi
        
        log_info "Health monitoring cycle #$cycle_count completed for $environment (failed: ${#failed_services[@]}, critical: ${#critical_failures[@]})"
        sleep "$check_interval"
    done
}

# Generate monitoring cycle report
generate_monitoring_cycle_report() {
    local environment="$1"
    local cycle_count="$2"
    shift 2
    local failed_services=("$@")
    
    local timestamp=$(date +%s)
    local report_file="/tmp/isectech-health/reports/cycle-${environment}-${cycle_count}-${timestamp}.json"
    
    local failed_services_json="[]"
    if [ ${#failed_services[@]} -gt 0 ]; then
        failed_services_json=$(printf '%s\n' "${failed_services[@]}" | jq -R . | jq -s .)
    fi
    
    cat > "$report_file" << EOF
{
  "cycle_number": $cycle_count,
  "environment": "$environment",
  "timestamp": $timestamp,
  "timestamp_iso": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "services_checked": $(echo "${!SERVICE_HEALTH_CONFIGS[@]}" | wc -w),
  "failed_services": $failed_services_json,
  "failure_count": ${#failed_services[@]},
  "success_rate": "$(echo "scale=2; ($(echo "${!SERVICE_HEALTH_CONFIGS[@]}" | wc -w) - ${#failed_services[@]}) * 100 / $(echo "${!SERVICE_HEALTH_CONFIGS[@]}" | wc -w)" | bc -l)%"
}
EOF
    
    log_debug "Monitoring cycle report generated: $report_file"
}

# Send critical health alert
send_critical_health_alert() {
    local environment="$1"
    shift
    local critical_failures=("$@")
    
    local alert_payload=$(cat << EOF
{
  "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "event_type": "critical_health_failure",
  "environment": "$environment",
  "critical_services": $(printf '%s\n' "${critical_failures[@]}" | jq -R . | jq -s .),
  "severity": "critical",
  "project_id": "$PROJECT_ID",
  "region": "$REGION"
}
EOF
)
    
    echo "$alert_payload" > "/tmp/isectech-health/critical-health-alert-$(date +%s).json"
    log_error "CRITICAL HEALTH ALERT: Critical services failing in $environment: ${critical_failures[*]}"
}

# Generate comprehensive health report
generate_health_report() {
    local environment="$1"
    local report_file="/tmp/isectech-health/reports/comprehensive-health-report-${environment}-$(date +%Y%m%d-%H%M%S).json"
    
    log_info "Generating comprehensive health report for $environment"
    
    local services_data="["
    local first=true
    
    for service in "${!SERVICE_HEALTH_CONFIGS[@]}"; do
        if [ "$first" = false ]; then
            services_data="${services_data},"
        else
            first=false
        fi
        
        local state_file="/tmp/isectech-health/state/${service}-${environment}.json"
        local cb_file="/tmp/isectech-health/circuit-breakers/${service}-${environment}.json"
        
        local service_data="{"
        service_data="${service_data}\"service\": \"$service\","
        
        if [ -f "$state_file" ]; then
            service_data="${service_data}\"health_state\": $(cat "$state_file"),"
        else
            service_data="${service_data}\"health_state\": null,"
        fi
        
        if [ -f "$cb_file" ]; then
            service_data="${service_data}\"circuit_breaker\": $(cat "$cb_file")"
        else
            service_data="${service_data}\"circuit_breaker\": null"
        fi
        
        service_data="${service_data}}"
        services_data="${services_data}${service_data}"
    done
    services_data="${services_data}]"
    
    cat > "$report_file" << EOF
{
  "report_timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "environment": "$environment",
  "project_id": "$PROJECT_ID",
  "region": "$REGION",
  "health_check_system_version": "2.0.0",
  "services": $services_data,
  "circuit_breaker_config": {
    "failure_threshold": $CIRCUIT_BREAKER_THRESHOLD,
    "timeout_seconds": $CIRCUIT_BREAKER_TIMEOUT
  },
  "monitoring_config": {
    "check_interval": $HEALTH_CHECK_INTERVAL,
    "check_timeout": $HEALTH_CHECK_TIMEOUT,
    "check_retries": $HEALTH_CHECK_RETRIES
  }
}
EOF
    
    log_success "Comprehensive health report generated: $report_file"
    cat "$report_file"
}

# Show help
show_help() {
    cat << EOF
iSECTECH Comprehensive Health Check System

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    init                                    Initialize health check system
    check SERVICE ENVIRONMENT [TYPE]       Perform health check on specific service
    check-all ENVIRONMENT                   Check all services in environment
    monitor ENVIRONMENT [INTERVAL]         Start continuous monitoring
    synthetic SERVICE ENVIRONMENT [TYPE]   Run synthetic test
    report ENVIRONMENT                      Generate comprehensive health report
    circuit-status SERVICE ENVIRONMENT     Show circuit breaker status
    
Health Check Types:
    all         All endpoints (health, readiness, liveness, startup)
    health      Health endpoint only
    readiness   Readiness endpoint only
    liveness    Liveness endpoint only
    startup     Startup endpoint only

Synthetic Test Types:
    basic           Basic health check
    auth_flow       Authentication flow test
    transaction_flow Transaction flow test

Environments:
    development, staging, production

Examples:
    # Initialize system
    $0 init
    
    # Check specific service
    $0 check auth-service production
    
    # Check all services
    $0 check-all production
    
    # Start monitoring with custom interval
    $0 monitor production 60
    
    # Run synthetic authentication test
    $0 synthetic auth-service production auth_flow
    
    # Generate health report
    $0 report production
    
    # Check circuit breaker status
    $0 circuit-status api-gateway production

Environment Variables:
    PROJECT_ID                      Google Cloud project ID
    REGION                         Google Cloud region
    ENVIRONMENT                    Default environment
    HEALTH_CHECK_INTERVAL          Monitoring interval in seconds (default: 30)
    HEALTH_CHECK_TIMEOUT           Health check timeout in seconds (default: 10)
    CIRCUIT_BREAKER_THRESHOLD      Circuit breaker failure threshold (default: 5)
    CIRCUIT_BREAKER_TIMEOUT        Circuit breaker timeout in seconds (default: 60)

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
            initialize_health_system
            ;;
        "check")
            if [ $# -lt 2 ]; then
                log_error "Usage: $0 check SERVICE ENVIRONMENT [TYPE]"
                exit 1
            fi
            initialize_health_system
            perform_detailed_health_check "$1" "$2" "${3:-all}"
            ;;
        "check-all")
            if [ $# -ne 1 ]; then
                log_error "Usage: $0 check-all ENVIRONMENT"
                exit 1
            fi
            initialize_health_system
            local env="$1"
            local failed_count=0
            for service in "${!SERVICE_HEALTH_CONFIGS[@]}"; do
                if ! perform_detailed_health_check "$service" "$env" "all"; then
                    failed_count=$((failed_count + 1))
                fi
            done
            if [ $failed_count -gt 0 ]; then
                log_error "$failed_count services failed health checks"
                exit 1
            else
                log_success "All services passed health checks"
            fi
            ;;
        "monitor")
            if [ $# -lt 1 ]; then
                log_error "Usage: $0 monitor ENVIRONMENT [INTERVAL]"
                exit 1
            fi
            initialize_health_system
            monitor_all_services "$1" "${2:-$HEALTH_CHECK_INTERVAL}"
            ;;
        "synthetic")
            if [ $# -lt 2 ]; then
                log_error "Usage: $0 synthetic SERVICE ENVIRONMENT [TYPE]"
                exit 1
            fi
            initialize_health_system
            perform_synthetic_test "$1" "$2" "${3:-basic}"
            ;;
        "report")
            if [ $# -ne 1 ]; then
                log_error "Usage: $0 report ENVIRONMENT"
                exit 1
            fi
            generate_health_report "$1"
            ;;
        "circuit-status")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 circuit-status SERVICE ENVIRONMENT"
                exit 1
            fi
            local cb_file="/tmp/isectech-health/circuit-breakers/$1-$2.json"
            if [ -f "$cb_file" ]; then
                cat "$cb_file" | jq .
            else
                log_error "Circuit breaker state not found for $1-$2"
                exit 1
            fi
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