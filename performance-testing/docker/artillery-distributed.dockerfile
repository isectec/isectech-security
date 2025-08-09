# Artillery Distributed Load Testing Docker Image
# Optimized for iSECTECH security platform distributed load generation

FROM node:18-alpine

# Install system dependencies
RUN apk add --no-cache \
    curl \
    jq \
    netcat-openbsd \
    ca-certificates \
    tzdata \
    bash \
    git

# Create application directory
WORKDIR /app

# Install Artillery and plugins globally
RUN npm install -g \
    artillery@2.0.3 \
    artillery-plugin-prometheus \
    artillery-plugin-cloudwatch \
    artillery-plugin-statsd \
    artillery-plugin-metrics-by-endpoint

# Create directories for configurations and reports
RUN mkdir -p /app/tests /app/config /app/reports /app/data /app/plugins

# Copy Artillery configurations
COPY ./artillery/ /app/tests/

# Install custom plugins and utilities
RUN npm init -y && npm install \
    aws-sdk \
    @prometheus-io/client \
    statsd-client \
    uuid \
    lodash

# Create distributed Artillery entrypoint script
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash

# Artillery Distributed Load Testing Entrypoint
# Supports distributed testing with synchronization and metrics aggregation

set -e

# Configuration variables with defaults
ARTILLERY_TEST_TYPE=${ARTILLERY_TEST_TYPE:-comprehensive}
ARTILLERY_ENVIRONMENT=${ARTILLERY_ENVIRONMENT:-development}
ARTILLERY_DISTRIBUTED_MODE=${ARTILLERY_DISTRIBUTED_MODE:-standalone}
ARTILLERY_WORKER_ID=${ARTILLERY_WORKER_ID:-worker-$(hostname)}
ARTILLERY_COORDINATOR=${ARTILLERY_COORDINATOR:-}
ARTILLERY_PROMETHEUS_ENDPOINT=${ARTILLERY_PROMETHEUS_ENDPOINT:-}
ARTILLERY_CLOUDWATCH_REGION=${ARTILLERY_CLOUDWATCH_REGION:-us-east-1}

# Load testing parameters
ARTILLERY_PHASES=${ARTILLERY_PHASES:-}
ARTILLERY_ARRIVAL_RATE=${ARTILLERY_ARRIVAL_RATE:-}
ARTILLERY_DURATION=${ARTILLERY_DURATION:-}
ARTILLERY_MAX_VUS=${ARTILLERY_MAX_VUS:-200}

# Logging and monitoring
LOG_LEVEL=${LOG_LEVEL:-info}
METRICS_INTERVAL=${METRICS_INTERVAL:-30}

echo "Starting Artillery distributed load testing..."
echo "Mode: $ARTILLERY_DISTRIBUTED_MODE"
echo "Test Type: $ARTILLERY_TEST_TYPE"
echo "Environment: $ARTILLERY_ENVIRONMENT"
echo "Worker ID: $ARTILLERY_WORKER_ID"

# Function to wait for coordinator
wait_for_coordinator() {
    if [ -n "$ARTILLERY_COORDINATOR" ]; then
        echo "Waiting for coordinator at $ARTILLERY_COORDINATOR..."
        timeout 300 bash -c "until nc -z ${ARTILLERY_COORDINATOR%:*} ${ARTILLERY_COORDINATOR#*:}; do sleep 2; done"
        echo "Coordinator is ready"
    fi
}

# Function to setup metrics plugins
setup_metrics_plugins() {
    local config_file=$1
    local plugins_config=""
    
    # Prometheus plugin configuration
    if [ -n "$ARTILLERY_PROMETHEUS_ENDPOINT" ]; then
        echo "Configuring Prometheus metrics endpoint: $ARTILLERY_PROMETHEUS_ENDPOINT"
        plugins_config=$(cat << JSON
{
  "plugins": {
    "prometheus": {
      "pushgateway": "$ARTILLERY_PROMETHEUS_ENDPOINT",
      "prefix": "isectech_artillery_",
      "tags": {
        "worker_id": "$ARTILLERY_WORKER_ID",
        "environment": "$ARTILLERY_ENVIRONMENT",
        "test_type": "$ARTILLERY_TEST_TYPE"
      }
    }
  }
}
JSON
        )
    fi
    
    # CloudWatch plugin configuration
    if [ -n "$AWS_REGION" ]; then
        echo "Configuring CloudWatch metrics for region: $AWS_REGION"
        local cloudwatch_config=$(cat << JSON
{
  "plugins": {
    "cloudwatch": {
      "region": "$AWS_REGION",
      "namespace": "iSECTECH/LoadTesting/Distributed",
      "dimensions": {
        "WorkerId": "$ARTILLERY_WORKER_ID",
        "Environment": "$ARTILLERY_ENVIRONMENT",
        "TestType": "$ARTILLERY_TEST_TYPE"
      }
    }
  }
}
JSON
        )
        
        if [ -n "$plugins_config" ]; then
            plugins_config=$(echo "$plugins_config $cloudwatch_config" | jq -s '.[0] * .[1]')
        else
            plugins_config="$cloudwatch_config"
        fi
    fi
    
    # Write plugins configuration if any plugins are configured
    if [ -n "$plugins_config" ]; then
        echo "$plugins_config" > /app/config/plugins.json
        echo "Metrics plugins configured"
    fi
}

# Function to generate distributed test configuration
generate_distributed_config() {
    local base_config=$1
    local output_config="/app/config/distributed-config.yml"
    
    # Copy base configuration
    cp "$base_config" "$output_config"
    
    # Modify configuration for distributed execution
    if [ "$ARTILLERY_DISTRIBUTED_MODE" = "worker" ]; then
        # Adjust load based on worker position
        case $ARTILLERY_WORKER_ID in
            *worker-0*)
                WORKER_LOAD_FACTOR=1.0
                ;;
            *worker-1*)
                WORKER_LOAD_FACTOR=0.8
                ;;
            *worker-2*)
                WORKER_LOAD_FACTOR=0.6
                ;;
            *)
                WORKER_LOAD_FACTOR=0.4
                ;;
        esac
        
        # Use yq to modify YAML configuration (install if not present)
        if ! command -v yq &> /dev/null; then
            wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
            chmod +x /usr/local/bin/yq
        fi
        
        # Adjust arrival rates based on worker load factor
        yq eval ".config.phases[].arrivalRate |= (. * $WORKER_LOAD_FACTOR | floor)" -i "$output_config"
        
        # Add worker-specific variables
        yq eval ".config.variables.worker_id = \"$ARTILLERY_WORKER_ID\"" -i "$output_config"
        yq eval ".config.variables.load_factor = $WORKER_LOAD_FACTOR" -i "$output_config"
    fi
    
    # Override with environment-specific settings
    if [ -n "$ARTILLERY_PHASES" ]; then
        echo "Overriding phases configuration: $ARTILLERY_PHASES"
        # Parse and apply custom phases (expects JSON format)
        echo "$ARTILLERY_PHASES" | yq eval -P - > /tmp/custom_phases.yml
        yq eval ".config.phases = load(\"/tmp/custom_phases.yml\")" -i "$output_config"
    fi
    
    # Set environment-specific target URL
    case $ARTILLERY_ENVIRONMENT in
        "production")
            yq eval '.config.target = "https://api.isectech.com"' -i "$output_config"
            ;;
        "staging")
            yq eval '.config.target = "https://staging.isectech.com"' -i "$output_config"
            ;;
        *)
            yq eval '.config.target = "http://localhost:3000"' -i "$output_config"
            ;;
    esac
    
    echo "$output_config"
}

# Function to run pre-test validation
run_pre_test_validation() {
    local target_url="$1"
    echo "Running pre-test validation..."
    
    # System health check
    if curl -s --max-time 10 "$target_url/api/health" | jq -e '.status' > /dev/null; then
        echo "✓ Target system is responding"
    else
        echo "⚠ Warning: Target system health check failed"
        return 1
    fi
    
    # Authentication validation
    if [ -n "$ANALYST_TOKEN" ]; then
        if curl -s --max-time 10 -H "Authorization: Bearer $ANALYST_TOKEN" "$target_url/api/auth/profile" | jq -e '.user' > /dev/null; then
            echo "✓ Authentication tokens are valid"
        else
            echo "⚠ Warning: Authentication validation failed"
            return 1
        fi
    fi
    
    # Load balancer and rate limiting check
    for i in {1..5}; do
        response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$target_url/api/health")
        if [ "$response" = "429" ]; then
            echo "⚠ Warning: Rate limiting detected, may affect test results"
            break
        fi
        sleep 1
    done
    
    echo "✓ Pre-test validation completed"
}

# Function to post-process results
post_process_results() {
    local results_dir="/app/reports"
    echo "Post-processing test results..."
    
    # Find the most recent Artillery JSON report
    local latest_report
    latest_report=$(find "$results_dir" -name "*.json" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
    
    if [ -n "$latest_report" ] && [ -f "$latest_report" ]; then
        echo "Processing report: $latest_report"
        
        # Extract key metrics using jq
        local summary=$(jq -r '
            {
                "worker_id": env.ARTILLERY_WORKER_ID,
                "test_type": env.ARTILLERY_TEST_TYPE,
                "environment": env.ARTILLERY_ENVIRONMENT,
                "start_time": .aggregate.firstCounterAt,
                "end_time": .aggregate.lastCounterAt,
                "duration": .aggregate.lastCounterAt - .aggregate.firstCounterAt,
                "total_requests": .aggregate.counters["http.requests"],
                "successful_requests": .aggregate.counters["http.responses"],
                "failed_requests": .aggregate.counters["http.request_errors"],
                "avg_response_time": .aggregate.latency.mean,
                "p95_response_time": .aggregate.latency.p95,
                "p99_response_time": .aggregate.latency.p99,
                "rps": (.aggregate.counters["http.responses"] / ((.aggregate.lastCounterAt - .aggregate.firstCounterAt) / 1000))
            }' "$latest_report")
        
        echo "$summary" > "$results_dir/test-summary-$ARTILLERY_WORKER_ID.json"
        echo "Test summary saved to: $results_dir/test-summary-$ARTILLERY_WORKER_ID.json"
        
        # Log key metrics
        echo "=== TEST RESULTS SUMMARY ==="
        echo "$summary" | jq -r '
            "Worker ID: " + .worker_id,
            "Total Requests: " + (.total_requests // 0 | tostring),
            "Success Rate: " + ((.successful_requests // 0) / (.total_requests // 1) * 100 | floor | tostring) + "%",
            "Average Response Time: " + (.avg_response_time // 0 | floor | tostring) + "ms",
            "95th Percentile: " + (.p95_response_time // 0 | floor | tostring) + "ms",
            "99th Percentile: " + (.p99_response_time // 0 | floor | tostring) + "ms",
            "Requests/sec: " + (.rps // 0 | floor | tostring)
        '
        echo "=========================="
    fi
}

# Function to select test configuration
select_test_config() {
    case $ARTILLERY_TEST_TYPE in
        "comprehensive"|"full")
            echo "/app/tests/comprehensive-load-test.yml"
            ;;
        "security-analyst"|"analyst")
            echo "/app/tests/security-analyst-workflow.yml"
            ;;
        "admin"|"administration")
            echo "/app/tests/admin-operations.yml"
            ;;
        "api"|"api-test")
            echo "/app/tests/api-comprehensive.yml"
            ;;
        *)
            echo "/app/tests/comprehensive-load-test.yml"
            ;;
    esac
}

# Main execution function
main() {
    # Wait for coordinator if in distributed mode
    if [ "$ARTILLERY_DISTRIBUTED_MODE" = "worker" ]; then
        wait_for_coordinator
    fi
    
    # Select test configuration
    local test_config
    test_config=$(select_test_config)
    
    if [ ! -f "$test_config" ]; then
        echo "Error: Test configuration not found: $test_config"
        exit 1
    fi
    
    echo "Using test configuration: $test_config"
    
    # Setup metrics plugins
    setup_metrics_plugins "$test_config"
    
    # Generate distributed configuration
    local final_config
    final_config=$(generate_distributed_config "$test_config")
    
    echo "Generated distributed config: $final_config"
    
    # Run pre-test validation
    local target_url
    target_url=$(yq eval '.config.target' "$final_config")
    
    if ! run_pre_test_validation "$target_url"; then
        echo "Pre-test validation failed. Proceeding with caution..."
    fi
    
    # Prepare Artillery command
    local artillery_cmd="artillery run"
    
    # Add output format
    artillery_cmd="$artillery_cmd --output /app/reports/artillery-results-$ARTILLERY_WORKER_ID-$(date +%Y%m%d-%H%M%S).json"
    
    # Add plugins configuration if exists
    if [ -f "/app/config/plugins.json" ]; then
        artillery_cmd="$artillery_cmd --config /app/config/plugins.json"
    fi
    
    # Add final configuration
    artillery_cmd="$artillery_cmd $final_config"
    
    # Execute Artillery test
    echo "Executing: $artillery_cmd"
    eval "$artillery_cmd"
    
    # Post-process results
    post_process_results
}

# Handle signals gracefully
trap 'echo "Received SIGTERM, shutting down gracefully..."; exit 0' TERM
trap 'echo "Received SIGINT, shutting down gracefully..."; exit 0' INT

# Run main function
main "$@"
EOF

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Create non-root user for security
RUN addgroup -g 1001 artillery && \
    adduser -D -s /bin/bash -u 1001 -G artillery artillery

# Change ownership of app directory
RUN chown -R artillery:artillery /app

# Switch to non-root user
USER artillery

# Set working directory
WORKDIR /app

# Expose ports for metrics and coordination
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health 2>/dev/null || nc -z localhost 8080 || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []