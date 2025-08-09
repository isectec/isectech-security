#!/bin/bash

# iSECTECH Circuit Breakers and Reliability Patterns
# Advanced reliability patterns for microservices resilience
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Circuit breaker configuration
CB_FAILURE_THRESHOLD="${CB_FAILURE_THRESHOLD:-5}"
CB_SUCCESS_THRESHOLD="${CB_SUCCESS_THRESHOLD:-3}"
CB_TIMEOUT="${CB_TIMEOUT:-60}"
CB_HALF_OPEN_MAX_CALLS="${CB_HALF_OPEN_MAX_CALLS:-10}"

# Retry configuration
RETRY_MAX_ATTEMPTS="${RETRY_MAX_ATTEMPTS:-3}"
RETRY_BASE_DELAY="${RETRY_BASE_DELAY:-1}"
RETRY_MAX_DELAY="${RETRY_MAX_DELAY:-30}"
RETRY_BACKOFF_MULTIPLIER="${RETRY_BACKOFF_MULTIPLIER:-2}"

# Rate limiting configuration
RATE_LIMIT_WINDOW="${RATE_LIMIT_WINDOW:-60}"  # seconds
RATE_LIMIT_MAX_REQUESTS="${RATE_LIMIT_MAX_REQUESTS:-100}"
RATE_LIMIT_BURST="${RATE_LIMIT_BURST:-20}"

# Timeout configuration
DEFAULT_TIMEOUT="${DEFAULT_TIMEOUT:-30}"
SLOW_OPERATION_TIMEOUT="${SLOW_OPERATION_TIMEOUT:-120}"
CRITICAL_OPERATION_TIMEOUT="${CRITICAL_OPERATION_TIMEOUT:-60}"

# Bulkhead configuration
BULKHEAD_MAX_CONCURRENT="${BULKHEAD_MAX_CONCURRENT:-10}"
BULKHEAD_QUEUE_SIZE="${BULKHEAD_QUEUE_SIZE:-50}"

# Service-specific reliability configurations
declare -A SERVICE_RELIABILITY_CONFIGS=(
    # Core services - high reliability requirements
    ["frontend"]="cb_threshold=3,retry_attempts=5,timeout=15,rate_limit=200,bulkhead_size=20"
    ["api-gateway"]="cb_threshold=5,retry_attempts=3,timeout=30,rate_limit=500,bulkhead_size=50"
    ["auth-service"]="cb_threshold=3,retry_attempts=5,timeout=10,rate_limit=100,bulkhead_size=15"
    
    # Processing services - moderate reliability requirements
    ["asset-discovery"]="cb_threshold=8,retry_attempts=2,timeout=60,rate_limit=50,bulkhead_size=10"
    ["event-processor"]="cb_threshold=10,retry_attempts=3,timeout=90,rate_limit=300,bulkhead_size=25"
    ["threat-detection"]="cb_threshold=5,retry_attempts=2,timeout=120,rate_limit=75,bulkhead_size=12"
    
    # AI services - adaptive reliability requirements
    ["behavioral-analysis"]="cb_threshold=10,retry_attempts=1,timeout=180,rate_limit=25,bulkhead_size=5"
    ["decision-engine"]="cb_threshold=7,retry_attempts=2,timeout=90,rate_limit=50,bulkhead_size=8"
    ["nlp-assistant"]="cb_threshold=8,retry_attempts=1,timeout=150,rate_limit=30,bulkhead_size=6"
)

# Fallback strategies
declare -A FALLBACK_STRATEGIES=(
    ["frontend"]="static_page,cached_content,maintenance_mode"
    ["api-gateway"]="circuit_breaker,service_degradation,error_response"
    ["auth-service"]="cached_tokens,read_only_mode,guest_access"
    ["asset-discovery"]="cached_results,reduced_scanning,manual_override"
    ["event-processor"]="queue_buffering,batch_processing,delayed_retry"
    ["threat-detection"]="baseline_rules,cached_intel,manual_review"
    ["behavioral-analysis"]="rule_based_fallback,cached_analysis,simplified_model"
    ["decision-engine"]="default_policy,cached_decisions,manual_approval"
    ["nlp-assistant"]="template_responses,cached_answers,human_handoff"
)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_circuit() {
    echo -e "${CYAN}[CIRCUIT]${NC} $(date +'%Y-%m-%d %H:%M:%S') $1"
}

# Initialize reliability patterns system
initialize_reliability_system() {
    log_info "Initializing circuit breakers and reliability patterns system"
    
    # Create directories for reliability data
    mkdir -p /tmp/isectech-reliability/{circuit-breakers,retry-states,rate-limiters,bulkheads,timeouts}
    mkdir -p /tmp/isectech-reliability/metrics/{circuit-breaker,retry,rate-limit,bulkhead,timeout}
    mkdir -p /tmp/isectech-reliability/fallbacks
    mkdir -p /tmp/isectech-reliability/reports
    
    # Initialize circuit breaker states for all services
    for service in "${!SERVICE_RELIABILITY_CONFIGS[@]}"; do
        for env in "development" "staging" "production"; do
            initialize_circuit_breaker "$service" "$env"
            initialize_rate_limiter "$service" "$env"
            initialize_bulkhead "$service" "$env"
        done
    done
    
    log_success "Reliability patterns system initialized"
}

# Parse service reliability configuration
parse_reliability_config() {
    local service="$1"
    local config="${SERVICE_RELIABILITY_CONFIGS[$service]:-}"
    
    # Default values
    SERVICE_CB_THRESHOLD="$CB_FAILURE_THRESHOLD"
    SERVICE_RETRY_ATTEMPTS="$RETRY_MAX_ATTEMPTS"
    SERVICE_TIMEOUT="$DEFAULT_TIMEOUT"
    SERVICE_RATE_LIMIT="$RATE_LIMIT_MAX_REQUESTS"
    SERVICE_BULKHEAD_SIZE="$BULKHEAD_MAX_CONCURRENT"
    
    if [ -n "$config" ]; then
        # Parse configuration string
        IFS=',' read -ra CONFIG_PARTS <<< "$config"
        for part in "${CONFIG_PARTS[@]}"; do
            IFS='=' read -ra KV <<< "$part"
            case "${KV[0]}" in
                "cb_threshold") SERVICE_CB_THRESHOLD="${KV[1]}" ;;
                "retry_attempts") SERVICE_RETRY_ATTEMPTS="${KV[1]}" ;;
                "timeout") SERVICE_TIMEOUT="${KV[1]}" ;;
                "rate_limit") SERVICE_RATE_LIMIT="${KV[1]}" ;;
                "bulkhead_size") SERVICE_BULKHEAD_SIZE="${KV[1]}" ;;
            esac
        done
    fi
    
    log_debug "Reliability config for $service: CB=${SERVICE_CB_THRESHOLD}, Retry=${SERVICE_RETRY_ATTEMPTS}, Timeout=${SERVICE_TIMEOUT}s, Rate=${SERVICE_RATE_LIMIT}/min, Bulkhead=${SERVICE_BULKHEAD_SIZE}"
}

# Initialize circuit breaker for a service
initialize_circuit_breaker() {
    local service="$1"
    local environment="$2"
    
    parse_reliability_config "$service"
    
    local cb_file="/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
    
    if [ ! -f "$cb_file" ]; then
        cat > "$cb_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "state": "closed",
  "failure_count": 0,
  "success_count": 0,
  "last_failure_time": 0,
  "last_success_time": $(date +%s),
  "state_changed_time": $(date +%s),
  "total_requests": 0,
  "successful_requests": 0,
  "failed_requests": 0,
  "half_open_calls": 0,
  "circuit_opened_count": 0,
  "configuration": {
    "failure_threshold": $SERVICE_CB_THRESHOLD,
    "success_threshold": $CB_SUCCESS_THRESHOLD,
    "timeout_seconds": $CB_TIMEOUT,
    "half_open_max_calls": $CB_HALF_OPEN_MAX_CALLS
  },
  "metrics": {
    "error_rate": 0.0,
    "average_response_time": 0,
    "last_error": null
  }
}
EOF
        log_debug "Circuit breaker initialized for $service-$environment"
    fi
}

# Initialize rate limiter for a service
initialize_rate_limiter() {
    local service="$1"
    local environment="$2"
    
    parse_reliability_config "$service"
    
    local rl_file="/tmp/isectech-reliability/rate-limiters/${service}-${environment}.json"
    
    if [ ! -f "$rl_file" ]; then
        cat > "$rl_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "current_requests": 0,
  "window_start": $(date +%s),
  "total_requests": 0,
  "blocked_requests": 0,
  "burst_tokens": $RATE_LIMIT_BURST,
  "configuration": {
    "max_requests": $SERVICE_RATE_LIMIT,
    "window_seconds": $RATE_LIMIT_WINDOW,
    "burst_size": $RATE_LIMIT_BURST
  }
}
EOF
        log_debug "Rate limiter initialized for $service-$environment"
    fi
}

# Initialize bulkhead for a service
initialize_bulkhead() {
    local service="$1"
    local environment="$2"
    
    parse_reliability_config "$service"
    
    local bh_file="/tmp/isectech-reliability/bulkheads/${service}-${environment}.json"
    
    if [ ! -f "$bh_file" ]; then
        cat > "$bh_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "active_calls": 0,
  "queued_calls": 0,
  "total_calls": 0,
  "completed_calls": 0,
  "rejected_calls": 0,
  "configuration": {
    "max_concurrent": $SERVICE_BULKHEAD_SIZE,
    "queue_size": $BULKHEAD_QUEUE_SIZE
  }
}
EOF
        log_debug "Bulkhead initialized for $service-$environment"
    fi
}

# Update circuit breaker state
update_circuit_breaker() {
    local service="$1"
    local environment="$2"
    local field="$3"
    local value="$4"
    
    local cb_file="/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
    
    if [ -f "$cb_file" ]; then
        local temp_file=$(mktemp)
        jq --arg field "$field" --arg value "$value" '.[$field] = ($value | if . == "true" or . == "false" then (. == "true") elif (. | test("^[0-9]+$")) then (. | tonumber) elif (. | test("^[0-9.]+$")) then (. | tonumber) else . end)' "$cb_file" > "$temp_file"
        mv "$temp_file" "$cb_file"
    fi
}

# Get circuit breaker state
get_circuit_breaker_value() {
    local service="$1"
    local environment="$2"
    local field="$3"
    
    local cb_file="/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
    
    if [ -f "$cb_file" ]; then
        jq -r ".${field}" "$cb_file"
    else
        echo "null"
    fi
}

# Check if circuit breaker allows request
circuit_breaker_allow_request() {
    local service="$1"
    local environment="$2"
    
    local state=$(get_circuit_breaker_value "$service" "$environment" "state")
    local failure_count=$(get_circuit_breaker_value "$service" "$environment" "failure_count")
    local state_changed_time=$(get_circuit_breaker_value "$service" "$environment" "state_changed_time")
    local failure_threshold=$(get_circuit_breaker_value "$service" "$environment" "configuration.failure_threshold")
    local timeout_seconds=$(get_circuit_breaker_value "$service" "$environment" "configuration.timeout_seconds")
    local half_open_calls=$(get_circuit_breaker_value "$service" "$environment" "half_open_calls")
    local half_open_max=$(get_circuit_breaker_value "$service" "$environment" "configuration.half_open_max_calls")
    
    local current_time=$(date +%s)
    
    case "$state" in
        "closed")
            log_circuit "Circuit breaker $service-$environment: CLOSED (allowing request)"
            return 0  # Allow request
            ;;
        "open")
            # Check if timeout has elapsed
            if [ $((current_time - state_changed_time)) -gt "$timeout_seconds" ]; then
                log_circuit "Circuit breaker $service-$environment: OPEN -> HALF-OPEN (timeout elapsed)"
                update_circuit_breaker "$service" "$environment" "state" "half-open"
                update_circuit_breaker "$service" "$environment" "state_changed_time" "$current_time"
                update_circuit_breaker "$service" "$environment" "half_open_calls" "0"
                return 0  # Allow first request in half-open state
            else
                log_circuit "Circuit breaker $service-$environment: OPEN (rejecting request)"
                return 1  # Reject request
            fi
            ;;
        "half-open")
            # Check if we've exceeded half-open call limit
            if [ "$half_open_calls" -lt "$half_open_max" ]; then
                log_circuit "Circuit breaker $service-$environment: HALF-OPEN (allowing limited request $((half_open_calls + 1))/$half_open_max)"
                update_circuit_breaker "$service" "$environment" "half_open_calls" $((half_open_calls + 1))
                return 0  # Allow request
            else
                log_circuit "Circuit breaker $service-$environment: HALF-OPEN (max calls reached, rejecting)"
                return 1  # Reject request
            fi
            ;;
        *)
            log_warning "Unknown circuit breaker state: $state, defaulting to closed"
            return 0  # Default to allowing request
            ;;
    esac
}

# Record circuit breaker success
record_circuit_breaker_success() {
    local service="$1"
    local environment="$2"
    local response_time="${3:-0}"
    
    local state=$(get_circuit_breaker_value "$service" "$environment" "state")
    local success_count=$(get_circuit_breaker_value "$service" "$environment" "success_count")
    local success_threshold=$(get_circuit_breaker_value "$service" "$environment" "configuration.success_threshold")
    local total_requests=$(get_circuit_breaker_value "$service" "$environment" "total_requests")
    local successful_requests=$(get_circuit_breaker_value "$service" "$environment" "successful_requests")
    
    local current_time=$(date +%s)
    
    # Update counters
    update_circuit_breaker "$service" "$environment" "total_requests" $((total_requests + 1))
    update_circuit_breaker "$service" "$environment" "successful_requests" $((successful_requests + 1))
    update_circuit_breaker "$service" "$environment" "last_success_time" "$current_time"
    update_circuit_breaker "$service" "$environment" "failure_count" "0"  # Reset failure count on success
    
    case "$state" in
        "half-open")
            success_count=$((success_count + 1))
            update_circuit_breaker "$service" "$environment" "success_count" "$success_count"
            
            if [ "$success_count" -ge "$success_threshold" ]; then
                log_circuit "Circuit breaker $service-$environment: HALF-OPEN -> CLOSED (success threshold reached)"
                update_circuit_breaker "$service" "$environment" "state" "closed"
                update_circuit_breaker "$service" "$environment" "state_changed_time" "$current_time"
                update_circuit_breaker "$service" "$environment" "success_count" "0"
                update_circuit_breaker "$service" "$environment" "half_open_calls" "0"
            fi
            ;;
        "closed")
            update_circuit_breaker "$service" "$environment" "success_count" $((success_count + 1))
            ;;
    esac
    
    # Store metrics
    store_circuit_breaker_metrics "$service" "$environment" "success" "$response_time"
    
    log_circuit "Circuit breaker $service-$environment: SUCCESS recorded (response_time: ${response_time}ms)"
}

# Record circuit breaker failure
record_circuit_breaker_failure() {
    local service="$1"
    local environment="$2"
    local error_message="${3:-unknown_error}"
    
    local state=$(get_circuit_breaker_value "$service" "$environment" "state")
    local failure_count=$(get_circuit_breaker_value "$service" "$environment" "failure_count")
    local failure_threshold=$(get_circuit_breaker_value "$service" "$environment" "configuration.failure_threshold")
    local total_requests=$(get_circuit_breaker_value "$service" "$environment" "total_requests")
    local failed_requests=$(get_circuit_breaker_value "$service" "$environment" "failed_requests")
    local circuit_opened_count=$(get_circuit_breaker_value "$service" "$environment" "circuit_opened_count")
    
    local current_time=$(date +%s)
    failure_count=$((failure_count + 1))
    
    # Update counters
    update_circuit_breaker "$service" "$environment" "total_requests" $((total_requests + 1))
    update_circuit_breaker "$service" "$environment" "failed_requests" $((failed_requests + 1))
    update_circuit_breaker "$service" "$environment" "failure_count" "$failure_count"
    update_circuit_breaker "$service" "$environment" "last_failure_time" "$current_time"
    update_circuit_breaker "$service" "$environment" "success_count" "0"  # Reset success count on failure
    
    # Update error information
    local temp_file=$(mktemp)
    jq --arg error "$error_message" '.metrics.last_error = $error' "/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json" > "$temp_file"
    mv "$temp_file" "/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
    
    # Check if circuit should open
    case "$state" in
        "closed")
            if [ "$failure_count" -ge "$failure_threshold" ]; then
                log_circuit "Circuit breaker $service-$environment: CLOSED -> OPEN (failure threshold reached: $failure_count/$failure_threshold)"
                update_circuit_breaker "$service" "$environment" "state" "open"
                update_circuit_breaker "$service" "$environment" "state_changed_time" "$current_time"
                update_circuit_breaker "$service" "$environment" "circuit_opened_count" $((circuit_opened_count + 1))
            fi
            ;;
        "half-open")
            log_circuit "Circuit breaker $service-$environment: HALF-OPEN -> OPEN (failure in half-open state)"
            update_circuit_breaker "$service" "$environment" "state" "open"
            update_circuit_breaker "$service" "$environment" "state_changed_time" "$current_time"
            update_circuit_breaker "$service" "$environment" "circuit_opened_count" $((circuit_opened_count + 1))
            update_circuit_breaker "$service" "$environment" "half_open_calls" "0"
            ;;
    esac
    
    # Store metrics
    store_circuit_breaker_metrics "$service" "$environment" "failure" "0"
    
    log_circuit "Circuit breaker $service-$environment: FAILURE recorded (count: $failure_count, error: $error_message)"
}

# Store circuit breaker metrics
store_circuit_breaker_metrics() {
    local service="$1"
    local environment="$2"
    local result="$3"
    local response_time="$4"
    local timestamp=$(date +%s)
    
    local metrics_file="/tmp/isectech-reliability/metrics/circuit-breaker/${service}-${environment}.csv"
    
    # Create header if file doesn't exist
    if [ ! -f "$metrics_file" ]; then
        echo "timestamp,service,environment,result,response_time_ms" > "$metrics_file"
    fi
    
    echo "$timestamp,$service,$environment,$result,$response_time" >> "$metrics_file"
}

# Execute request with retry pattern
execute_with_retry() {
    local service="$1"
    local environment="$2"
    local command="$3"
    local max_attempts="${4:-$RETRY_MAX_ATTEMPTS}"
    
    log_info "Executing with retry pattern: $service-$environment (max_attempts: $max_attempts)"
    
    parse_reliability_config "$service"
    max_attempts="$SERVICE_RETRY_ATTEMPTS"
    
    local attempt=1
    local delay="$RETRY_BASE_DELAY"
    
    while [ $attempt -le $max_attempts ]; do
        log_debug "Retry attempt $attempt/$max_attempts for $service-$environment"
        
        # Check circuit breaker before attempting
        if ! circuit_breaker_allow_request "$service" "$environment"; then
            log_warning "Circuit breaker rejected request for $service-$environment on attempt $attempt"
            execute_fallback_strategy "$service" "$environment" "circuit_breaker_open"
            return 1
        fi
        
        # Execute command with timeout
        local start_time=$(date +%s%3N)
        local exit_code=0
        
        timeout "$SERVICE_TIMEOUT" bash -c "$command" || exit_code=$?
        
        local end_time=$(date +%s%3N)
        local response_time=$((end_time - start_time))
        
        case $exit_code in
            0)
                # Success
                record_circuit_breaker_success "$service" "$environment" "$response_time"
                store_retry_metrics "$service" "$environment" "success" "$attempt" "$response_time"
                log_success "Request succeeded for $service-$environment on attempt $attempt (${response_time}ms)"
                return 0
                ;;
            124)
                # Timeout
                log_warning "Request timeout for $service-$environment on attempt $attempt"
                record_circuit_breaker_failure "$service" "$environment" "timeout"
                store_retry_metrics "$service" "$environment" "timeout" "$attempt" "$SERVICE_TIMEOUT"
                ;;
            *)
                # Other failure
                log_warning "Request failed for $service-$environment on attempt $attempt (exit code: $exit_code)"
                record_circuit_breaker_failure "$service" "$environment" "request_failed"
                store_retry_metrics "$service" "$environment" "failure" "$attempt" "$response_time"
                ;;
        esac
        
        # Don't retry if this was the last attempt
        if [ $attempt -eq $max_attempts ]; then
            break
        fi
        
        # Calculate exponential backoff delay
        local jitter=$((RANDOM % 1000))  # Add jitter (0-999ms)
        local actual_delay=$(echo "scale=3; $delay + ($jitter / 1000)" | bc -l)
        
        log_debug "Waiting ${actual_delay}s before retry attempt $((attempt + 1))"
        sleep "$actual_delay"
        
        # Update delay for next iteration
        delay=$(echo "scale=3; $delay * $RETRY_BACKOFF_MULTIPLIER" | bc -l)
        if (( $(echo "$delay > $RETRY_MAX_DELAY" | bc -l) )); then
            delay="$RETRY_MAX_DELAY"
        fi
        
        attempt=$((attempt + 1))
    done
    
    # All attempts failed
    log_error "All retry attempts failed for $service-$environment"
    execute_fallback_strategy "$service" "$environment" "max_retries_exceeded"
    return 1
}

# Store retry metrics
store_retry_metrics() {
    local service="$1"
    local environment="$2"
    local result="$3"
    local attempt="$4"
    local response_time="$5"
    local timestamp=$(date +%s)
    
    local metrics_file="/tmp/isectech-reliability/metrics/retry/${service}-${environment}.csv"
    
    # Create header if file doesn't exist
    if [ ! -f "$metrics_file" ]; then
        echo "timestamp,service,environment,result,attempt,response_time_ms" > "$metrics_file"
    fi
    
    echo "$timestamp,$service,$environment,$result,$attempt,$response_time" >> "$metrics_file"
}

# Check rate limiter
check_rate_limiter() {
    local service="$1"
    local environment="$2"
    
    local rl_file="/tmp/isectech-reliability/rate-limiters/${service}-${environment}.json"
    
    if [ ! -f "$rl_file" ]; then
        log_warning "Rate limiter not initialized for $service-$environment"
        return 0  # Allow request if not initialized
    fi
    
    local current_time=$(date +%s)
    local window_start=$(jq -r '.window_start' "$rl_file")
    local current_requests=$(jq -r '.current_requests' "$rl_file")
    local max_requests=$(jq -r '.configuration.max_requests' "$rl_file")
    local window_seconds=$(jq -r '.configuration.window_seconds' "$rl_file")
    local burst_tokens=$(jq -r '.burst_tokens' "$rl_file")
    local burst_size=$(jq -r '.configuration.burst_size' "$rl_file")
    
    # Check if we need to reset the window
    if [ $((current_time - window_start)) -ge "$window_seconds" ]; then
        # Reset window
        local temp_file=$(mktemp)
        jq --arg time "$current_time" --arg burst "$burst_size" '.window_start = ($time | tonumber) | .current_requests = 0 | .burst_tokens = ($burst | tonumber)' "$rl_file" > "$temp_file"
        mv "$temp_file" "$rl_file"
        current_requests=0
        burst_tokens="$burst_size"
    fi
    
    # Check rate limit
    if [ "$current_requests" -lt "$max_requests" ] || [ "$burst_tokens" -gt 0 ]; then
        # Allow request
        local new_requests=$((current_requests + 1))
        local new_burst_tokens=$burst_tokens
        
        if [ "$current_requests" -ge "$max_requests" ]; then
            # Using burst token
            new_burst_tokens=$((burst_tokens - 1))
        fi
        
        # Update counters
        local temp_file=$(mktemp)
        jq --arg requests "$new_requests" --arg burst "$new_burst_tokens" --arg total_reqs "$(jq -r '.total_requests' "$rl_file")" '.current_requests = ($requests | tonumber) | .burst_tokens = ($burst | tonumber) | .total_requests = (($total_reqs | tonumber) + 1)' "$rl_file" > "$temp_file"
        mv "$temp_file" "$rl_file"
        
        store_rate_limit_metrics "$service" "$environment" "allowed" "$new_requests" "$max_requests"
        return 0  # Allow request
    else
        # Rate limit exceeded
        local temp_file=$(mktemp)
        jq --arg blocked_reqs "$(jq -r '.blocked_requests' "$rl_file")" '.blocked_requests = (($blocked_reqs | tonumber) + 1)' "$rl_file" > "$temp_file"
        mv "$temp_file" "$rl_file"
        
        store_rate_limit_metrics "$service" "$environment" "blocked" "$current_requests" "$max_requests"
        log_warning "Rate limit exceeded for $service-$environment ($current_requests/$max_requests)"
        return 1  # Block request
    fi
}

# Store rate limit metrics
store_rate_limit_metrics() {
    local service="$1"
    local environment="$2"
    local result="$3"
    local current_requests="$4"
    local max_requests="$5"
    local timestamp=$(date +%s)
    
    local metrics_file="/tmp/isectech-reliability/metrics/rate-limit/${service}-${environment}.csv"
    
    # Create header if file doesn't exist
    if [ ! -f "$metrics_file" ]; then
        echo "timestamp,service,environment,result,current_requests,max_requests" > "$metrics_file"
    fi
    
    echo "$timestamp,$service,$environment,$result,$current_requests,$max_requests" >> "$metrics_file"
}

# Check bulkhead capacity
check_bulkhead_capacity() {
    local service="$1"
    local environment="$2"
    
    local bh_file="/tmp/isectech-reliability/bulkheads/${service}-${environment}.json"
    
    if [ ! -f "$bh_file" ]; then
        log_warning "Bulkhead not initialized for $service-$environment"
        return 0  # Allow if not initialized
    fi
    
    local active_calls=$(jq -r '.active_calls' "$bh_file")
    local queued_calls=$(jq -r '.queued_calls' "$bh_file")
    local max_concurrent=$(jq -r '.configuration.max_concurrent' "$bh_file")
    local queue_size=$(jq -r '.configuration.queue_size' "$bh_file")
    
    if [ "$active_calls" -lt "$max_concurrent" ]; then
        # Can execute immediately
        local temp_file=$(mktemp)
        jq --arg active "$((active_calls + 1))" --arg total "$(jq -r '.total_calls' "$bh_file")" '.active_calls = ($active | tonumber) | .total_calls = (($total | tonumber) + 1)' "$bh_file" > "$temp_file"
        mv "$temp_file" "$bh_file"
        
        store_bulkhead_metrics "$service" "$environment" "executed" "$active_calls" "$max_concurrent"
        return 0  # Execute immediately
    elif [ "$queued_calls" -lt "$queue_size" ]; then
        # Add to queue
        local temp_file=$(mktemp)
        jq --arg queued "$((queued_calls + 1))" --arg total "$(jq -r '.total_calls' "$bh_file")" '.queued_calls = ($queued | tonumber) | .total_calls = (($total | tonumber) + 1)' "$bh_file" > "$temp_file"
        mv "$temp_file" "$bh_file"
        
        store_bulkhead_metrics "$service" "$environment" "queued" "$queued_calls" "$queue_size"
        log_debug "Request queued for $service-$environment (queue: $((queued_calls + 1))/$queue_size)"
        return 2  # Queued
    else
        # Reject - no capacity
        local temp_file=$(mktemp)
        jq --arg rejected "$(jq -r '.rejected_calls' "$bh_file")" '.rejected_calls = (($rejected | tonumber) + 1)' "$bh_file" > "$temp_file"
        mv "$temp_file" "$bh_file"
        
        store_bulkhead_metrics "$service" "$environment" "rejected" "$active_calls" "$max_concurrent"
        log_warning "Bulkhead capacity exceeded for $service-$environment"
        return 1  # Reject
    fi
}

# Release bulkhead capacity
release_bulkhead_capacity() {
    local service="$1"
    local environment="$2"
    
    local bh_file="/tmp/isectech-reliability/bulkheads/${service}-${environment}.json"
    
    if [ -f "$bh_file" ]; then
        local active_calls=$(jq -r '.active_calls' "$bh_file")
        local queued_calls=$(jq -r '.queued_calls' "$bh_file")
        local completed_calls=$(jq -r '.completed_calls' "$bh_file")
        
        # Decrease active calls
        if [ "$active_calls" -gt 0 ]; then
            active_calls=$((active_calls - 1))
        fi
        
        # Process queued call if any
        if [ "$queued_calls" -gt 0 ]; then
            queued_calls=$((queued_calls - 1))
            active_calls=$((active_calls + 1))
        fi
        
        # Update counters
        local temp_file=$(mktemp)
        jq --arg active "$active_calls" --arg queued "$queued_calls" --arg completed "$((completed_calls + 1))" '.active_calls = ($active | tonumber) | .queued_calls = ($queued | tonumber) | .completed_calls = ($completed | tonumber)' "$bh_file" > "$temp_file"
        mv "$temp_file" "$bh_file"
        
        log_debug "Released bulkhead capacity for $service-$environment (active: $active_calls, queued: $queued_calls)"
    fi
}

# Store bulkhead metrics
store_bulkhead_metrics() {
    local service="$1"
    local environment="$2"
    local result="$3"
    local current_calls="$4"
    local max_calls="$5"
    local timestamp=$(date +%s)
    
    local metrics_file="/tmp/isectech-reliability/metrics/bulkhead/${service}-${environment}.csv"
    
    # Create header if file doesn't exist
    if [ ! -f "$metrics_file" ]; then
        echo "timestamp,service,environment,result,current_calls,max_calls" > "$metrics_file"
    fi
    
    echo "$timestamp,$service,$environment,$result,$current_calls,$max_calls" >> "$metrics_file"
}

# Execute fallback strategy
execute_fallback_strategy() {
    local service="$1"
    local environment="$2"
    local reason="$3"
    
    log_warning "Executing fallback strategy for $service-$environment (reason: $reason)"
    
    local strategies="${FALLBACK_STRATEGIES[$service]:-}"
    if [ -z "$strategies" ]; then
        log_error "No fallback strategies defined for $service"
        return 1
    fi
    
    # Parse fallback strategies
    IFS=',' read -ra STRATEGY_LIST <<< "$strategies"
    
    for strategy in "${STRATEGY_LIST[@]}"; do
        case "$strategy" in
            "static_page")
                log_info "Serving static fallback page for $service"
                echo "Fallback: Static maintenance page served"
                return 0
                ;;
            "cached_content")
                log_info "Serving cached content for $service"
                echo "Fallback: Cached content served"
                return 0
                ;;
            "maintenance_mode")
                log_info "Entering maintenance mode for $service"
                echo "Fallback: Maintenance mode activated"
                return 0
                ;;
            "circuit_breaker")
                log_info "Circuit breaker fallback for $service"
                echo "Fallback: Service temporarily unavailable"
                return 0
                ;;
            "service_degradation")
                log_info "Service degradation mode for $service"
                echo "Fallback: Reduced functionality mode"
                return 0
                ;;
            "error_response")
                log_info "Returning error response for $service"
                echo "Fallback: Service error response"
                return 0
                ;;
            "cached_tokens")
                log_info "Using cached authentication tokens for $service"
                echo "Fallback: Cached authentication active"
                return 0
                ;;
            "read_only_mode")
                log_info "Entering read-only mode for $service"
                echo "Fallback: Read-only mode activated"
                return 0
                ;;
            "guest_access")
                log_info "Providing guest access for $service"
                echo "Fallback: Guest access granted"
                return 0
                ;;
            *)
                log_debug "Unknown fallback strategy: $strategy"
                ;;
        esac
    done
    
    # Store fallback execution
    local fallback_file="/tmp/isectech-reliability/fallbacks/${service}-${environment}-$(date +%s).json"
    cat > "$fallback_file" << EOF
{
  "service": "$service",
  "environment": "$environment",
  "reason": "$reason",
  "strategies_executed": "$(echo "${STRATEGY_LIST[*]}" | tr ' ' ',')",
  "timestamp": $(date +%s),
  "timestamp_iso": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
}
EOF
    
    log_info "Fallback strategies executed for $service-$environment"
    return 0
}

# Execute request with all reliability patterns
execute_with_reliability_patterns() {
    local service="$1"
    local environment="$2"
    local command="$3"
    
    log_info "Executing request with full reliability patterns: $service-$environment"
    
    # Check rate limiter
    if ! check_rate_limiter "$service" "$environment"; then
        log_warning "Rate limit exceeded for $service-$environment"
        execute_fallback_strategy "$service" "$environment" "rate_limit_exceeded"
        return 1
    fi
    
    # Check bulkhead capacity
    local bulkhead_result
    check_bulkhead_capacity "$service" "$environment"
    bulkhead_result=$?
    
    case $bulkhead_result in
        0)
            # Execute immediately
            log_debug "Bulkhead allows immediate execution for $service-$environment"
            ;;
        1)
            # Rejected
            log_warning "Bulkhead capacity exceeded for $service-$environment"
            execute_fallback_strategy "$service" "$environment" "bulkhead_capacity_exceeded"
            return 1
            ;;
        2)
            # Queued
            log_info "Request queued due to bulkhead limit for $service-$environment"
            # In a real implementation, this would wait for capacity
            sleep 2
            ;;
    esac
    
    # Execute with retry pattern (includes circuit breaker checks)
    local execution_result
    execute_with_retry "$service" "$environment" "$command"
    execution_result=$?
    
    # Release bulkhead capacity
    release_bulkhead_capacity "$service" "$environment"
    
    return $execution_result
}

# Generate reliability patterns report
generate_reliability_report() {
    local environment="$1"
    local report_file="/tmp/isectech-reliability/reports/reliability-patterns-report-${environment}-$(date +%Y%m%d-%H%M%S).json"
    
    log_info "Generating reliability patterns report for $environment"
    
    # Collect circuit breaker data
    local circuit_breaker_data="["
    local rate_limiter_data="["
    local bulkhead_data="["
    local first=true
    
    for service in "${!SERVICE_RELIABILITY_CONFIGS[@]}"; do
        local cb_file="/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
        local rl_file="/tmp/isectech-reliability/rate-limiters/${service}-${environment}.json"
        local bh_file="/tmp/isectech-reliability/bulkheads/${service}-${environment}.json"
        
        if [ "$first" = false ]; then
            circuit_breaker_data="${circuit_breaker_data},"
            rate_limiter_data="${rate_limiter_data},"
            bulkhead_data="${bulkhead_data},"
        else
            first=false
        fi
        
        # Circuit breaker data
        if [ -f "$cb_file" ]; then
            circuit_breaker_data="${circuit_breaker_data}$(cat "$cb_file")"
        else
            circuit_breaker_data="${circuit_breaker_data}null"
        fi
        
        # Rate limiter data
        if [ -f "$rl_file" ]; then
            rate_limiter_data="${rate_limiter_data}$(cat "$rl_file")"
        else
            rate_limiter_data="${rate_limiter_data}null"
        fi
        
        # Bulkhead data
        if [ -f "$bh_file" ]; then
            bulkhead_data="${bulkhead_data}$(cat "$bh_file")"
        else
            bulkhead_data="${bulkhead_data}null"
        fi
    done
    
    circuit_breaker_data="${circuit_breaker_data}]"
    rate_limiter_data="${rate_limiter_data}]"
    bulkhead_data="${bulkhead_data}]"
    
    # Generate comprehensive report
    cat > "$report_file" << EOF
{
  "report_timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "environment": "$environment",
  "project_id": "$PROJECT_ID",
  "region": "$REGION",
  "reliability_patterns_version": "2.0.0",
  
  "circuit_breakers": $circuit_breaker_data,
  "rate_limiters": $rate_limiter_data,
  "bulkheads": $bulkhead_data,
  
  "configuration": {
    "circuit_breaker": {
      "failure_threshold": $CB_FAILURE_THRESHOLD,
      "success_threshold": $CB_SUCCESS_THRESHOLD,
      "timeout_seconds": $CB_TIMEOUT,
      "half_open_max_calls": $CB_HALF_OPEN_MAX_CALLS
    },
    "retry": {
      "max_attempts": $RETRY_MAX_ATTEMPTS,
      "base_delay_seconds": $RETRY_BASE_DELAY,
      "max_delay_seconds": $RETRY_MAX_DELAY,
      "backoff_multiplier": $RETRY_BACKOFF_MULTIPLIER
    },
    "rate_limiting": {
      "window_seconds": $RATE_LIMIT_WINDOW,
      "max_requests": $RATE_LIMIT_MAX_REQUESTS,
      "burst_size": $RATE_LIMIT_BURST
    },
    "bulkhead": {
      "max_concurrent": $BULKHEAD_MAX_CONCURRENT,
      "queue_size": $BULKHEAD_QUEUE_SIZE
    }
  },
  
  "fallback_strategies": $(echo "${FALLBACK_STRATEGIES[@]}" | jq -Rn '[inputs | split(" ")]')
}
EOF
    
    log_success "Reliability patterns report generated: $report_file"
    cat "$report_file"
}

# Reset circuit breaker
reset_circuit_breaker() {
    local service="$1"
    local environment="$2"
    
    log_info "Resetting circuit breaker for $service-$environment"
    
    local cb_file="/tmp/isectech-reliability/circuit-breakers/${service}-${environment}.json"
    
    if [ -f "$cb_file" ]; then
        local temp_file=$(mktemp)
        jq --arg time "$(date +%s)" '.state = "closed" | .failure_count = 0 | .success_count = 0 | .state_changed_time = ($time | tonumber) | .half_open_calls = 0' "$cb_file" > "$temp_file"
        mv "$temp_file" "$cb_file"
        
        log_success "Circuit breaker reset for $service-$environment"
    else
        log_error "Circuit breaker state file not found for $service-$environment"
        return 1
    fi
}

# Show help
show_help() {
    cat << EOF
iSECTECH Circuit Breakers and Reliability Patterns

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    init                                    Initialize reliability patterns system
    execute SERVICE ENVIRONMENT COMMAND    Execute command with all reliability patterns
    circuit-status SERVICE ENVIRONMENT     Show circuit breaker status
    circuit-reset SERVICE ENVIRONMENT      Reset circuit breaker to closed state
    test-circuit SERVICE ENVIRONMENT       Test circuit breaker behavior
    test-retry SERVICE ENVIRONMENT         Test retry pattern behavior
    report ENVIRONMENT                     Generate reliability patterns report
    
Pattern Testing:
    test-circuit        Test circuit breaker open/close behavior
    test-retry          Test retry with exponential backoff
    test-rate-limit     Test rate limiting behavior
    test-bulkhead       Test bulkhead isolation
    test-fallback       Test fallback strategies

Environments:
    development, staging, production

Examples:
    # Initialize reliability system
    $0 init
    
    # Execute command with all patterns
    $0 execute auth-service production "curl -f https://auth-service/health"
    
    # Check circuit breaker status
    $0 circuit-status api-gateway production
    
    # Reset circuit breaker
    $0 circuit-reset threat-detection staging
    
    # Generate reliability report
    $0 report production
    
    # Test circuit breaker behavior
    $0 test-circuit frontend development

Environment Variables:
    PROJECT_ID                      Google Cloud project ID
    REGION                         Google Cloud region
    CB_FAILURE_THRESHOLD           Circuit breaker failure threshold (default: 5)
    CB_SUCCESS_THRESHOLD           Circuit breaker success threshold (default: 3)
    CB_TIMEOUT                     Circuit breaker timeout in seconds (default: 60)
    RETRY_MAX_ATTEMPTS             Maximum retry attempts (default: 3)
    RETRY_BASE_DELAY               Base retry delay in seconds (default: 1)
    RATE_LIMIT_MAX_REQUESTS        Rate limit max requests per window (default: 100)
    BULKHEAD_MAX_CONCURRENT        Bulkhead max concurrent requests (default: 10)

Circuit Breaker States:
    closed      Normal operation (allowing requests)
    open        Failing fast (rejecting requests)
    half-open   Testing service recovery (limited requests)

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
            initialize_reliability_system
            ;;
        "execute")
            if [ $# -ne 3 ]; then
                log_error "Usage: $0 execute SERVICE ENVIRONMENT COMMAND"
                exit 1
            fi
            initialize_reliability_system
            execute_with_reliability_patterns "$1" "$2" "$3"
            ;;
        "circuit-status")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 circuit-status SERVICE ENVIRONMENT"
                exit 1
            fi
            local cb_file="/tmp/isectech-reliability/circuit-breakers/$1-$2.json"
            if [ -f "$cb_file" ]; then
                cat "$cb_file" | jq .
            else
                log_error "Circuit breaker state not found for $1-$2"
                exit 1
            fi
            ;;
        "circuit-reset")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 circuit-reset SERVICE ENVIRONMENT"
                exit 1
            fi
            reset_circuit_breaker "$1" "$2"
            ;;
        "test-circuit")
            if [ $# -ne 2 ]; then
                log_error "Usage: $0 test-circuit SERVICE ENVIRONMENT"
                exit 1
            fi
            initialize_reliability_system
            # Simulate failures to test circuit breaker
            for i in {1..6}; do
                log_info "Simulating failure $i/6"
                record_circuit_breaker_failure "$1" "$2" "test_failure_$i"
                sleep 1
            done
            log_info "Testing circuit breaker recovery"
            sleep "$CB_TIMEOUT"
            if circuit_breaker_allow_request "$1" "$2"; then
                record_circuit_breaker_success "$1" "$2" "100"
                record_circuit_breaker_success "$1" "$2" "95"
                record_circuit_breaker_success "$1" "$2" "110"
            fi
            ;;
        "report")
            if [ $# -ne 1 ]; then
                log_error "Usage: $0 report ENVIRONMENT"
                exit 1
            fi
            generate_reliability_report "$1"
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