# k6 Distributed Load Testing Docker Image
# Optimized for iSECTECH security platform load testing

FROM grafana/k6:0.47.0

# Install additional dependencies for advanced scenarios
USER root

# Install system dependencies for network utilities and monitoring
RUN apk add --no-cache \
    curl \
    jq \
    netcat-openbsd \
    ca-certificates \
    tzdata \
    bash

# Create directories for test configurations and reports
RUN mkdir -p /app/tests /app/config /app/reports /app/data

# Copy k6 test configurations and scenarios
COPY ./k6/config/ /app/config/
COPY ./k6/scenarios/ /app/tests/

# Create entrypoint script for distributed testing
RUN cat > /app/entrypoint.sh << 'EOF'
#!/bin/bash

# k6 Distributed Load Testing Entrypoint
# Supports master-worker architecture and cloud-distributed testing

set -e

# Configuration variables with defaults
K6_TEST_TYPE=${K6_TEST_TYPE:-baseline}
K6_ENVIRONMENT=${K6_ENVIRONMENT:-development}
K6_DISTRIBUTED_MODE=${K6_DISTRIBUTED_MODE:-standalone}
K6_MASTER_HOST=${K6_MASTER_HOST:-}
K6_WORKER_ID=${K6_WORKER_ID:-worker-$(hostname)}
K6_INFLUX_DB=${K6_INFLUX_DB:-}
K6_PROMETHEUS_REMOTE_URL=${K6_PROMETHEUS_REMOTE_URL:-}
K6_GRAFANA_DASHBOARD=${K6_GRAFANA_DASHBOARD:-}

# Logging configuration
LOG_LEVEL=${LOG_LEVEL:-info}
LOG_FORMAT=${LOG_FORMAT:-json}

echo "Starting k6 distributed load testing..."
echo "Mode: $K6_DISTRIBUTED_MODE"
echo "Test Type: $K6_TEST_TYPE"
echo "Environment: $K6_ENVIRONMENT"
echo "Worker ID: $K6_WORKER_ID"

# Function to wait for dependencies
wait_for_dependency() {
    local host=$1
    local port=$2
    local service=$3
    
    echo "Waiting for $service at $host:$port..."
    timeout 300 bash -c "until nc -z $host $port; do sleep 2; done"
    echo "$service is ready"
}

# Function to setup metrics output
setup_metrics_output() {
    local output_args=""
    
    # InfluxDB output
    if [ -n "$K6_INFLUX_DB" ]; then
        echo "Configuring InfluxDB output: $K6_INFLUX_DB"
        output_args="$output_args --out influxdb=$K6_INFLUX_DB"
    fi
    
    # Prometheus remote write
    if [ -n "$K6_PROMETHEUS_REMOTE_URL" ]; then
        echo "Configuring Prometheus remote write: $K6_PROMETHEUS_REMOTE_URL"
        output_args="$output_args --out experimental-prometheus-rw"
        export K6_PROMETHEUS_RW_SERVER_URL="$K6_PROMETHEUS_REMOTE_URL"
    fi
    
    # JSON output for local processing
    output_args="$output_args --out json=/app/reports/k6-results-$K6_WORKER_ID-$(date +%Y%m%d-%H%M%S).json"
    
    echo "$output_args"
}

# Function to select appropriate test scenario
select_test_scenario() {
    case $K6_TEST_TYPE in
        "baseline"|"smoke")
            echo "/app/tests/security-analyst-workflow.js"
            ;;
        "database"|"db-intensive")
            echo "/app/tests/database-intensive-operations.js"
            ;;
        "api-comprehensive"|"api")
            echo "/app/tests/api-endpoints-comprehensive.js"
            ;;
        "admin")
            echo "/app/tests/admin-operations.js"
            ;;
        *)
            echo "/app/tests/security-analyst-workflow.js"
            ;;
    esac
}

# Function to generate distributed test configuration
generate_distributed_config() {
    local scenario_file=$1
    local output_args=$2
    
    # Base k6 command arguments
    local k6_args="run"
    
    # Add output configurations
    k6_args="$k6_args $output_args"
    
    # Environment and test type
    k6_args="$k6_args --env ENVIRONMENT=$K6_ENVIRONMENT"
    k6_args="$k6_args --env TEST_TYPE=$K6_TEST_TYPE"
    k6_args="$k6_args --env WORKER_ID=$K6_WORKER_ID"
    k6_args="$k6_args --env TEST_RUN_ID=$(date +%Y%m%d%H%M%S)-$K6_WORKER_ID"
    
    # Distributed execution parameters
    if [ "$K6_DISTRIBUTED_MODE" = "worker" ]; then
        k6_args="$k6_args --execution-segment-sequence=0,0.25,0.5,0.75,1"
        
        case $K6_WORKER_ID in
            *worker-0*|*worker-1*)
                k6_args="$k6_args --execution-segment=0:0.25"
                ;;
            *worker-2*|*worker-3*)
                k6_args="$k6_args --execution-segment=0.25:0.5"
                ;;
            *worker-4*|*worker-5*)
                k6_args="$k6_args --execution-segment=0.5:0.75"
                ;;
            *)
                k6_args="$k6_args --execution-segment=0.75:1"
                ;;
        esac
    fi
    
    # Log level and format
    k6_args="$k6_args --log-level=$LOG_LEVEL"
    if [ "$LOG_FORMAT" = "json" ]; then
        k6_args="$k6_args --log-format=json"
    fi
    
    # HTTP and connection settings for high-load testing
    k6_args="$k6_args --http-debug=full"
    k6_args="$k6_args --no-connection-reuse=false"
    k6_args="$k6_args --batch=50"
    k6_args="$k6_args --batch-per-host=20"
    
    # Add the test scenario file
    k6_args="$k6_args $scenario_file"
    
    echo "$k6_args"
}

# Function to run health checks
run_health_checks() {
    local target_url="$1"
    echo "Running pre-test health checks..."
    
    # Basic connectivity test
    if curl -s --max-time 10 "$target_url/api/health" | jq -e '.status == "healthy"' > /dev/null; then
        echo "✓ Target system is healthy"
    else
        echo "⚠ Warning: Target system may not be ready"
    fi
    
    # API authentication test
    if [ -n "$ANALYST_TOKEN" ]; then
        if curl -s --max-time 10 -H "Authorization: Bearer $ANALYST_TOKEN" "$target_url/api/auth/profile" | jq -e '.user' > /dev/null; then
            echo "✓ Authentication is working"
        else
            echo "⚠ Warning: Authentication may be failing"
        fi
    fi
}

# Main execution logic
main() {
    # Wait for dependencies if in distributed mode
    if [ "$K6_DISTRIBUTED_MODE" = "worker" ] && [ -n "$K6_MASTER_HOST" ]; then
        wait_for_dependency "$K6_MASTER_HOST" 6443 "Kubernetes API"
    fi
    
    # Setup metrics output
    local output_args
    output_args=$(setup_metrics_output)
    
    # Select test scenario
    local scenario_file
    scenario_file=$(select_test_scenario)
    
    echo "Selected test scenario: $scenario_file"
    
    # Generate k6 command
    local k6_command
    k6_command=$(generate_distributed_config "$scenario_file" "$output_args")
    
    # Run health checks if target URL is available
    if [ -n "$API_BASE_URL" ]; then
        run_health_checks "$API_BASE_URL"
    fi
    
    # Execute k6 test
    echo "Executing: k6 $k6_command"
    exec k6 $k6_command
}

# Handle signals gracefully
trap 'echo "Received SIGTERM, shutting down gracefully..."; exit 0' TERM
trap 'echo "Received SIGINT, shutting down gracefully..."; exit 0' INT

# Run main function
main "$@"
EOF

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

# Switch back to k6 user for security
USER k6

# Set working directory
WORKDIR /app

# Expose ports for metrics and communication
EXPOSE 6565 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:6565/v1/status || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD []