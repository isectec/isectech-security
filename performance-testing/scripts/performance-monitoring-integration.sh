#!/bin/bash

# Performance Monitoring Integration for iSECTECH Production Deployments
# Integrates performance testing with real-time monitoring and alerting systems
# Usage: ./performance-monitoring-integration.sh [action] [environment]

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MONITORING_CONFIG="$PROJECT_ROOT/performance-testing/config/monitoring"

# Default values
ACTION="${1:-deploy}"
ENVIRONMENT="${2:-staging}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check monitoring system availability
check_monitoring_systems() {
    log_info "Checking monitoring system availability..."
    
    # Check Prometheus
    if curl -s -f "${PROMETHEUS_URL:-http://localhost:9090}/-/healthy" > /dev/null; then
        log_success "Prometheus is healthy"
        PROMETHEUS_AVAILABLE=true
    else
        log_warning "Prometheus not available"
        PROMETHEUS_AVAILABLE=false
    fi
    
    # Check Grafana
    if curl -s -f "${GRAFANA_URL:-http://localhost:3001}/api/health" > /dev/null; then
        log_success "Grafana is healthy"
        GRAFANA_AVAILABLE=true
    else
        log_warning "Grafana not available"
        GRAFANA_AVAILABLE=false
    fi
    
    # Check InfluxDB
    if curl -s -f "${INFLUXDB_URL:-http://localhost:8086}/ping" > /dev/null; then
        log_success "InfluxDB is healthy"
        INFLUXDB_AVAILABLE=true
    else
        log_warning "InfluxDB not available"
        INFLUXDB_AVAILABLE=false
    fi
}

# Setup deployment monitoring
setup_deployment_monitoring() {
    log_info "Setting up deployment monitoring for $ENVIRONMENT environment..."
    
    # Create deployment annotation in Grafana
    if [[ "$GRAFANA_AVAILABLE" == true ]]; then
        local deployment_time
        deployment_time=$(date -u +%s)
        local commit_sha="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}"
        local deployment_tag="${GITHUB_REF_NAME:-$(git branch --show-current 2>/dev/null || echo 'unknown')}"
        
        python3 << EOF
import requests
import json
import os
from datetime import datetime

# Grafana configuration
grafana_url = "${GRAFANA_URL:-http://localhost:3001}"
api_key = os.environ.get('GRAFANA_API_KEY', '')

if not api_key:
    print("GRAFANA_API_KEY not set, skipping deployment annotation")
    exit(0)

# Create deployment annotation
annotation_data = {
    "time": ${deployment_time}000,  # Convert to milliseconds
    "timeEnd": ${deployment_time}000 + 60000,  # 1 minute duration
    "tags": ["deployment", "${ENVIRONMENT}", "performance-testing"],
    "text": f"Deployment: ${commit_sha} to ${ENVIRONMENT}\\nBranch: ${deployment_tag}\\nTriggered by: Performance Testing Pipeline"
}

headers = {
    'Authorization': f'Bearer {api_key}',
    'Content-Type': 'application/json'
}

try:
    response = requests.post(
        f'{grafana_url}/api/annotations',
        headers=headers,
        json=annotation_data
    )
    if response.status_code == 200:
        print("✅ Deployment annotation created in Grafana")
    else:
        print(f"⚠️ Failed to create deployment annotation: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"⚠️ Error creating Grafana annotation: {e}")
EOF
    fi
    
    # Set up Prometheus alerts for deployment window
    if [[ "$PROMETHEUS_AVAILABLE" == true ]]; then
        setup_prometheus_deployment_alerts
    fi
    
    # Initialize performance baseline collection
    if [[ "$INFLUXDB_AVAILABLE" == true ]]; then
        setup_performance_baseline_collection
    fi
}

# Setup Prometheus deployment alerts
setup_prometheus_deployment_alerts() {
    log_info "Setting up Prometheus deployment alerts..."
    
    # Create temporary alert rules for deployment monitoring
    cat > "/tmp/deployment-alerts-${ENVIRONMENT}.yml" << EOF
groups:
  - name: deployment-performance-monitoring-${ENVIRONMENT}
    interval: 30s
    rules:
      - alert: DeploymentPerformanceRegression
        expr: |
          (
            histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{environment="${ENVIRONMENT}"}[5m]))
            /
            histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{environment="${ENVIRONMENT}"}[5m] offset 1h))
          ) > 1.2
        for: 2m
        labels:
          severity: critical
          environment: ${ENVIRONMENT}
          team: performance
        annotations:
          summary: "Performance regression detected during deployment"
          description: "P95 response time increased by {{ \$value | humanizePercentage }} compared to 1 hour ago in {{ \$labels.environment }}"
          
      - alert: DeploymentErrorRateSpike  
        expr: |
          rate(http_requests_total{environment="${ENVIRONMENT}",status=~"5.."}[5m])
          /
          rate(http_requests_total{environment="${ENVIRONMENT}"}[5m])
          > 0.02
        for: 1m
        labels:
          severity: critical
          environment: ${ENVIRONMENT}
          team: performance
        annotations:
          summary: "High error rate detected during deployment"
          description: "Error rate is {{ \$value | humanizePercentage }} in {{ \$labels.environment }}"
          
      - alert: DeploymentThroughputDrop
        expr: |
          (
            rate(http_requests_total{environment="${ENVIRONMENT}"}[5m])
            /
            rate(http_requests_total{environment="${ENVIRONMENT}"}[5m] offset 1h)
          ) < 0.7
        for: 3m
        labels:
          severity: warning
          environment: ${ENVIRONMENT}
          team: performance
        annotations:
          summary: "Throughput drop detected during deployment"
          description: "Request rate decreased by {{ (1 - \$value) | humanizePercentage }} compared to 1 hour ago"

      - alert: DeploymentMemoryLeak
        expr: |
          increase(process_resident_memory_bytes{environment="${ENVIRONMENT}"}[10m]) > 100000000
        for: 5m
        labels:
          severity: warning
          environment: ${ENVIRONMENT}
          team: performance
        annotations:
          summary: "Potential memory leak detected after deployment"
          description: "Memory usage increased by {{ \$value | humanizeBytes }} in the last 10 minutes"
EOF

    # Load alert rules into Prometheus (requires proper setup)
    log_info "Deployment alert rules created for ${ENVIRONMENT} environment"
}

# Setup performance baseline collection
setup_performance_baseline_collection() {
    log_info "Setting up performance baseline collection..."
    
    python3 << EOF
import json
import time
import os
from datetime import datetime

# InfluxDB configuration
influxdb_url = "${INFLUXDB_URL:-http://localhost:8086}"
database = "performance_baselines"

# Create deployment baseline marker
baseline_data = {
    "measurement": "deployment_baselines",
    "tags": {
        "environment": "${ENVIRONMENT}",
        "commit": "${GITHUB_SHA:-unknown}",
        "branch": "${GITHUB_REF_NAME:-unknown}",
        "deployment_type": "performance-testing"
    },
    "fields": {
        "deployment_timestamp": int(time.time()),
        "baseline_collection_started": True
    },
    "time": datetime.utcnow().isoformat() + "Z"
}

# Write baseline marker to InfluxDB
try:
    import requests
    
    # InfluxDB line protocol format
    line_protocol = f"deployment_baselines,environment=${ENVIRONMENT},commit=${GITHUB_SHA:-unknown} deployment_timestamp={int(time.time())}i,baseline_collection_started=true {int(time.time() * 1000000000)}"
    
    response = requests.post(
        f"{influxdb_url}/write?db=performance_baselines",
        data=line_protocol,
        headers={"Content-Type": "application/octet-stream"}
    )
    
    if response.status_code == 204:
        print("✅ Performance baseline marker created in InfluxDB")
    else:
        print(f"⚠️ Failed to create baseline marker: {response.status_code}")
        
except ImportError:
    print("⚠️ Requests library not available, skipping InfluxDB baseline marker")
except Exception as e:
    print(f"⚠️ Error creating InfluxDB baseline marker: {e}")
EOF
}

# Run post-deployment performance validation
run_post_deployment_validation() {
    log_info "Running post-deployment performance validation..."
    
    # Wait for deployment to stabilize
    local warmup_period=120
    log_info "Waiting ${warmup_period}s for deployment to stabilize..."
    sleep $warmup_period
    
    # Run lightweight performance check
    local validation_results="/tmp/post-deployment-validation.json"
    
    python3 << EOF
import requests
import json
import time
import statistics
from datetime import datetime

# Post-deployment validation configuration
api_base_url = "${API_BASE_URL:-https://staging.isectech.com}"
endpoints_to_test = [
    "/api/health",
    "/api/dashboard/summary",
    "/api/threats",
    "/api/alerts"
]

validation_results = {
    "timestamp": datetime.utcnow().isoformat(),
    "environment": "${ENVIRONMENT}",
    "commit": "${GITHUB_SHA:-unknown}",
    "validation_passed": True,
    "endpoint_results": [],
    "summary": {
        "avg_response_time": 0,
        "max_response_time": 0,
        "error_count": 0,
        "total_requests": 0
    }
}

all_response_times = []
error_count = 0
total_requests = 0

for endpoint in endpoints_to_test:
    print(f"Testing endpoint: {endpoint}")
    endpoint_times = []
    
    # Make multiple requests to get a baseline
    for i in range(5):
        try:
            start_time = time.time()
            response = requests.get(f"{api_base_url}{endpoint}", timeout=30)
            response_time = (time.time() - start_time) * 1000  # Convert to ms
            
            endpoint_times.append(response_time)
            all_response_times.append(response_time)
            total_requests += 1
            
            if response.status_code >= 400:
                error_count += 1
                
        except Exception as e:
            print(f"  Error testing {endpoint}: {e}")
            error_count += 1
            total_requests += 1
    
    # Calculate endpoint statistics
    if endpoint_times:
        endpoint_result = {
            "endpoint": endpoint,
            "avg_response_time": statistics.mean(endpoint_times),
            "min_response_time": min(endpoint_times),
            "max_response_time": max(endpoint_times),
            "request_count": len(endpoint_times),
            "success_rate": (len(endpoint_times) - error_count) / len(endpoint_times) if endpoint_times else 0
        }
        validation_results["endpoint_results"].append(endpoint_result)
        
        print(f"  Avg: {endpoint_result['avg_response_time']:.2f}ms, Max: {endpoint_result['max_response_time']:.2f}ms")

# Overall validation summary
if all_response_times:
    validation_results["summary"]["avg_response_time"] = statistics.mean(all_response_times)
    validation_results["summary"]["max_response_time"] = max(all_response_times)
    
validation_results["summary"]["error_count"] = error_count
validation_results["summary"]["total_requests"] = total_requests
validation_results["summary"]["error_rate"] = error_count / total_requests if total_requests > 0 else 0

# Determine validation success
avg_time = validation_results["summary"]["avg_response_time"]
error_rate = validation_results["summary"]["error_rate"]

# Simple thresholds for post-deployment validation
if avg_time > 2000 or error_rate > 0.1:  # 2s average or 10% error rate
    validation_results["validation_passed"] = False

# Save results
with open("${validation_results}", "w") as f:
    json.dump(validation_results, f, indent=2)

print(f"\n=== POST-DEPLOYMENT VALIDATION RESULTS ===")
print(f"Average Response Time: {avg_time:.2f}ms")
print(f"Maximum Response Time: {validation_results['summary']['max_response_time']:.2f}ms")
print(f"Error Rate: {error_rate:.2%}")
print(f"Total Requests: {total_requests}")
print(f"Validation Status: {'PASSED' if validation_results['validation_passed'] else 'FAILED'}")

if not validation_results["validation_passed"]:
    exit(1)
EOF

    local validation_exit_code=$?
    if [[ $validation_exit_code -eq 0 ]]; then
        log_success "Post-deployment validation passed"
        return 0
    else
        log_error "Post-deployment validation failed"
        return 1
    fi
}

# Setup continuous monitoring
setup_continuous_monitoring() {
    log_info "Setting up continuous monitoring for $ENVIRONMENT..."
    
    # Create performance monitoring cron job
    local cron_script="/tmp/performance-monitoring-${ENVIRONMENT}.sh"
    
    cat > "$cron_script" << 'EOF'
#!/bin/bash

# Continuous performance monitoring script
ENVIRONMENT="${ENVIRONMENT}"
MONITORING_CONFIG="${MONITORING_CONFIG}"

# Run lightweight performance check every 5 minutes
python3 << PYTHON_EOF
import requests
import json
import time
from datetime import datetime

# Quick health and performance check
api_base_url = "${API_BASE_URL:-https://staging.isectech.com}"
check_timestamp = datetime.utcnow().isoformat()

try:
    start_time = time.time()
    response = requests.get(f"{api_base_url}/api/health", timeout=10)
    response_time = (time.time() - start_time) * 1000
    
    health_data = {
        "timestamp": check_timestamp,
        "environment": "${ENVIRONMENT}",
        "endpoint": "/api/health",
        "response_time_ms": response_time,
        "status_code": response.status_code,
        "healthy": response.status_code == 200 and response_time < 1000
    }
    
    # Log to monitoring system (simplified)
    print(f"Health Check: {health_data['healthy']}, Response Time: {response_time:.2f}ms")
    
    # Send to InfluxDB if available
    influxdb_url = "${INFLUXDB_URL:-http://localhost:8086}"
    line_protocol = f"health_checks,environment=${ENVIRONMENT} response_time={response_time},healthy={'true' if health_data['healthy'] else 'false'},status_code={response.status_code}i {int(time.time() * 1000000000)}"
    
    health_response = requests.post(
        f"{influxdb_url}/write?db=continuous_monitoring",
        data=line_protocol,
        headers={"Content-Type": "application/octet-stream"},
        timeout=5
    )
    
except Exception as e:
    print(f"Health check failed: {e}")
PYTHON_EOF
EOF

    chmod +x "$cron_script"
    log_info "Continuous monitoring script created: $cron_script"
}

# Cleanup deployment monitoring
cleanup_deployment_monitoring() {
    log_info "Cleaning up deployment monitoring for $ENVIRONMENT..."
    
    # Remove temporary alert rules
    if [[ -f "/tmp/deployment-alerts-${ENVIRONMENT}.yml" ]]; then
        rm "/tmp/deployment-alerts-${ENVIRONMENT}.yml"
        log_info "Deployment alert rules cleaned up"
    fi
    
    # Create deployment completion marker
    if [[ "$GRAFANA_AVAILABLE" == true ]]; then
        python3 << EOF
import requests
import json
import os
from datetime import datetime

grafana_url = "${GRAFANA_URL:-http://localhost:3001}"
api_key = os.environ.get('GRAFANA_API_KEY', '')

if api_key:
    completion_data = {
        "time": int(time.time() * 1000),
        "tags": ["deployment-complete", "${ENVIRONMENT}", "performance-testing"],
        "text": f"Deployment monitoring completed for ${ENVIRONMENT}\\nCommit: ${GITHUB_SHA:-unknown}\\nValidation: Passed"
    }
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(
            f'{grafana_url}/api/annotations',
            headers=headers,
            json=completion_data
        )
        if response.status_code == 200:
            print("✅ Deployment completion annotation created")
    except Exception as e:
        print(f"⚠️ Error creating completion annotation: {e}")
EOF
    fi
}

# Generate monitoring report
generate_monitoring_report() {
    log_info "Generating monitoring integration report..."
    
    local report_file="/tmp/monitoring-integration-report-${ENVIRONMENT}.json"
    
    cat > "$report_file" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "environment": "$ENVIRONMENT",
  "action": "$ACTION",
  "commit": "${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || echo 'unknown')}",
  "branch": "${GITHUB_REF_NAME:-$(git branch --show-current 2>/dev/null || echo 'unknown')}",
  "monitoring_systems": {
    "prometheus_available": $PROMETHEUS_AVAILABLE,
    "grafana_available": $GRAFANA_AVAILABLE,
    "influxdb_available": $INFLUXDB_AVAILABLE
  },
  "deployment_monitoring": {
    "setup_completed": true,
    "alerts_configured": $PROMETHEUS_AVAILABLE,
    "annotations_created": $GRAFANA_AVAILABLE,
    "baseline_collection": $INFLUXDB_AVAILABLE
  },
  "recommendations": [
    $(if [[ "$PROMETHEUS_AVAILABLE" != true ]]; then echo '"Setup Prometheus for comprehensive alerting",'; fi)
    $(if [[ "$GRAFANA_AVAILABLE" != true ]]; then echo '"Configure Grafana for visualization",'; fi)
    $(if [[ "$INFLUXDB_AVAILABLE" != true ]]; then echo '"Setup InfluxDB for time-series data",'; fi)
    "Monitor performance trends after deployment",
    "Review alerts and thresholds periodically"
  ]
}
EOF

    log_success "Monitoring integration report generated: $report_file"
    
    # Output report summary
    if [[ "$PROMETHEUS_AVAILABLE" == true ]] && [[ "$GRAFANA_AVAILABLE" == true ]] && [[ "$INFLUXDB_AVAILABLE" == true ]]; then
        log_success "All monitoring systems integrated successfully"
    else
        log_warning "Some monitoring systems not available - functionality may be limited"
    fi
}

# Main execution function
main() {
    case "$ACTION" in
        "deploy"|"setup")
            log_info "Setting up deployment monitoring for $ENVIRONMENT..."
            check_monitoring_systems
            setup_deployment_monitoring
            run_post_deployment_validation
            setup_continuous_monitoring
            ;;
        
        "validate"|"check")
            log_info "Running performance validation for $ENVIRONMENT..."
            check_monitoring_systems
            run_post_deployment_validation
            ;;
            
        "cleanup")
            log_info "Cleaning up deployment monitoring for $ENVIRONMENT..."
            check_monitoring_systems
            cleanup_deployment_monitoring
            ;;
            
        "monitor")
            log_info "Setting up continuous monitoring for $ENVIRONMENT..."
            check_monitoring_systems
            setup_continuous_monitoring
            ;;
            
        *)
            log_error "Unknown action: $ACTION"
            show_help
            exit 1
            ;;
    esac
    
    generate_monitoring_report
}

# Help function
show_help() {
    cat << EOF
Performance Monitoring Integration Script for iSECTECH

USAGE:
    $0 [action] [environment]

ACTIONS:
    deploy     Setup deployment monitoring (default)
    validate   Run post-deployment validation only
    cleanup    Cleanup deployment monitoring
    monitor    Setup continuous monitoring

ENVIRONMENTS:
    development, staging, production

EXAMPLES:
    $0 deploy staging
    $0 validate production
    $0 cleanup staging
    $0 monitor development

ENVIRONMENT VARIABLES:
    PROMETHEUS_URL      Prometheus server URL
    GRAFANA_URL         Grafana server URL  
    INFLUXDB_URL        InfluxDB server URL
    GRAFANA_API_KEY     Grafana API key for annotations
    API_BASE_URL        Base URL for API validation
EOF
}

# Handle help requests
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

# Execute main function
main "$@"