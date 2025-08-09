#!/bin/bash

# iSECTECH Distributed Load Testing Orchestration Script
# Manages k6 and Artillery distributed load testing across multiple environments

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PERFORMANCE_DIR="$PROJECT_ROOT/performance-testing"

# Default configuration
DEFAULT_TEST_TYPE="baseline"
DEFAULT_ENVIRONMENT="development"
DEFAULT_DURATION="5m"
DEFAULT_WORKERS=3
DEFAULT_TOOL="k6"

# Color output
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

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

iSECTECH Distributed Load Testing Orchestration

COMMANDS:
    start           Start distributed load testing
    stop            Stop all load testing containers/pods
    status          Show current load testing status
    logs            Show logs from load testing components
    clean           Clean up test resources and reports
    build           Build load testing Docker images
    deploy          Deploy to Kubernetes cluster
    report          Generate test results report

OPTIONS:
    -t, --tool TOOL           Load testing tool (k6|artillery|both) [default: k6]
    -e, --env ENVIRONMENT     Target environment (development|staging|production) [default: development]
    -T, --test-type TYPE      Test type (baseline|stress|spike|endurance|api|database) [default: baseline]
    -w, --workers COUNT       Number of worker instances [default: 3]
    -d, --duration TIME       Test duration (e.g., 5m, 30s) [default: 5m]
    -u, --url URL            Target API base URL
    -k, --kubernetes         Use Kubernetes deployment instead of Docker Compose
    -c, --continuous         Run continuous testing (scheduled)
    -r, --report-only        Generate report from existing data
    -v, --verbose            Verbose logging
    -h, --help               Show this help message

EXAMPLES:
    # Basic k6 load test
    $0 start -t k6 -e development -T baseline

    # Stress test with Artillery on staging
    $0 start -t artillery -e staging -T stress -w 5 -d 10m

    # Both tools with custom URL
    $0 start -t both -e production -u https://api.isectech.com -w 8

    # Kubernetes deployment
    $0 deploy -k -t k6 -e staging

    # Generate report from recent test
    $0 report -r

    # Clean up all resources
    $0 clean

EOF
}

# Configuration validation
validate_config() {
    local tool="$1"
    local environment="$2"
    local test_type="$3"

    # Validate tool
    if [[ ! "$tool" =~ ^(k6|artillery|both)$ ]]; then
        log_error "Invalid tool: $tool. Must be k6, artillery, or both"
        return 1
    fi

    # Validate environment
    if [[ ! "$environment" =~ ^(development|staging|production)$ ]]; then
        log_error "Invalid environment: $environment. Must be development, staging, or production"
        return 1
    fi

    # Validate test type
    if [[ ! "$test_type" =~ ^(baseline|stress|spike|endurance|api|database|comprehensive)$ ]]; then
        log_error "Invalid test type: $test_type"
        return 1
    fi

    return 0
}

# Environment setup
setup_environment() {
    local environment="$1"
    local target_url="$2"

    log_info "Setting up environment for $environment"

    # Create .env file for Docker Compose
    cat > "$PERFORMANCE_DIR/.env" << EOF
# Generated environment configuration for distributed load testing
K6_TEST_TYPE=$TEST_TYPE
K6_ENVIRONMENT=$environment
ARTILLERY_TEST_TYPE=$TEST_TYPE
ARTILLERY_ENVIRONMENT=$environment
API_BASE_URL=$target_url

# Authentication tokens (set these based on your environment)
ANALYST_TOKEN=${ANALYST_TOKEN:-dev-analyst-token}
ADMIN_TOKEN=${ADMIN_TOKEN:-dev-admin-token}
VIEWER_TOKEN=${VIEWER_TOKEN:-dev-viewer-token}

# Monitoring configuration
PROMETHEUS_PUSHGATEWAY=http://prometheus-pushgateway:9091
INFLUX_DB_URL=http://influxdb:8086
GRAFANA_URL=http://grafana:3000

# Test configuration
TEST_DURATION=$DURATION
WORKER_COUNT=$WORKERS
LOG_LEVEL=${VERBOSE:+debug}
EOF

    log_success "Environment configuration created"
}

# Docker image building
build_images() {
    local tool="$1"

    log_info "Building Docker images for $tool"

    cd "$PERFORMANCE_DIR/docker"

    if [[ "$tool" == "k6" || "$tool" == "both" ]]; then
        log_info "Building k6 distributed image..."
        docker build -t isectech/k6-distributed:latest -f k6-distributed.dockerfile .
        log_success "k6 image built successfully"
    fi

    if [[ "$tool" == "artillery" || "$tool" == "both" ]]; then
        log_info "Building Artillery distributed image..."
        docker build -t isectech/artillery-distributed:latest -f artillery-distributed.dockerfile .
        log_success "Artillery image built successfully"
    fi
}

# Docker Compose management
manage_docker_compose() {
    local action="$1"
    local tool="$2"

    cd "$PERFORMANCE_DIR/docker"

    case "$action" in
        start)
            log_info "Starting distributed load testing with Docker Compose ($tool)"
            
            # Start monitoring infrastructure first
            docker-compose -f docker-compose.distributed.yml up -d \
                influxdb prometheus-pushgateway grafana

            # Wait for infrastructure to be ready
            log_info "Waiting for monitoring infrastructure to be ready..."
            sleep 30

            # Start appropriate load testing tools
            if [[ "$tool" == "k6" || "$tool" == "both" ]]; then
                docker-compose -f docker-compose.distributed.yml up -d \
                    k6-coordinator k6-worker-1 k6-worker-2
                
                # Scale workers if needed
                if [[ "$WORKERS" -gt 2 ]]; then
                    docker-compose -f docker-compose.distributed.yml up -d --scale k6-worker-1=$WORKERS
                fi
            fi

            if [[ "$tool" == "artillery" || "$tool" == "both" ]]; then
                docker-compose -f docker-compose.distributed.yml up -d \
                    artillery-coordinator artillery-worker-1 artillery-worker-2
                
                # Scale workers if needed
                if [[ "$WORKERS" -gt 2 ]]; then
                    docker-compose -f docker-compose.distributed.yml up -d --scale artillery-worker-1=$WORKERS
                fi
            fi

            log_success "Distributed load testing started"
            log_info "Grafana dashboard available at: http://localhost:3001 (admin/admin123!)"
            ;;
            
        stop)
            log_info "Stopping distributed load testing"
            docker-compose -f docker-compose.distributed.yml down
            log_success "Load testing stopped"
            ;;
            
        status)
            log_info "Load testing status:"
            docker-compose -f docker-compose.distributed.yml ps
            ;;
            
        logs)
            log_info "Load testing logs:"
            docker-compose -f docker-compose.distributed.yml logs -f --tail=50
            ;;
    esac
}

# Kubernetes management
manage_kubernetes() {
    local action="$1"
    local tool="$2"

    case "$action" in
        deploy)
            log_info "Deploying distributed load testing to Kubernetes ($tool)"
            
            # Apply namespace and common resources
            kubectl apply -f "$PERFORMANCE_DIR/kubernetes/k6-distributed-deployment.yaml" -l component=namespace,configuration,secrets,rbac
            
            if [[ "$tool" == "k6" || "$tool" == "both" ]]; then
                log_info "Deploying k6 distributed components..."
                kubectl apply -f "$PERFORMANCE_DIR/kubernetes/k6-distributed-deployment.yaml"
                
                # Scale workers if needed
                if [[ "$WORKERS" -ne 4 ]]; then
                    kubectl scale deployment k6-workers --replicas="$WORKERS" -n performance-testing
                fi
            fi
            
            if [[ "$tool" == "artillery" || "$tool" == "both" ]]; then
                log_info "Deploying Artillery distributed components..."
                kubectl apply -f "$PERFORMANCE_DIR/kubernetes/artillery-distributed-deployment.yaml"
                
                # Scale workers if needed  
                if [[ "$WORKERS" -ne 3 ]]; then
                    kubectl scale deployment artillery-workers --replicas="$WORKERS" -n performance-testing
                fi
            fi
            
            log_success "Kubernetes deployment completed"
            ;;
            
        stop)
            log_info "Stopping Kubernetes load testing"
            kubectl delete namespace performance-testing --ignore-not-found=true
            log_success "Kubernetes resources cleaned up"
            ;;
            
        status)
            log_info "Kubernetes load testing status:"
            kubectl get all -n performance-testing 2>/dev/null || log_warning "No resources found"
            ;;
            
        logs)
            log_info "Kubernetes load testing logs:"
            kubectl logs -n performance-testing -l app=k6-distributed,artillery-distributed --tail=50 -f
            ;;
    esac
}

# Report generation
generate_report() {
    local report_dir="$PERFORMANCE_DIR/reports"
    local timestamp=$(date +"%Y%m%d-%H%M%S")
    local report_file="$report_dir/load-test-report-$timestamp.html"

    log_info "Generating load test report..."

    # Create report directory if it doesn't exist
    mkdir -p "$report_dir"

    # Find the most recent test results
    local k6_results=$(find "$report_dir" -name "k6-results-*.json" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2- || echo "")
    local artillery_results=$(find "$report_dir" -name "artillery-results-*.json" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2- || echo "")

    # Generate HTML report
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH Load Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; color: #2c5aa0; border-bottom: 2px solid #2c5aa0; padding-bottom: 20px; margin-bottom: 30px; }
        .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #2c5aa0; }
        .metric-value { font-size: 2em; font-weight: bold; color: #2c5aa0; }
        .metric-label { color: #666; text-transform: uppercase; font-size: 0.9em; }
        .success { color: #28a745; }
        .warning { color: #ffc107; }
        .danger { color: #dc3545; }
        .section { margin: 30px 0; }
        .section h2 { color: #2c5aa0; border-bottom: 1px solid #dee2e6; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background-color: #f8f9fa; font-weight: bold; }
        .footer { text-align: center; color: #666; margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>iSECTECH Load Test Report</h1>
            <p>Generated on TIMESTAMP</p>
            <p>Environment: ENVIRONMENT | Test Type: TEST_TYPE</p>
        </div>

        <div class="section">
            <h2>Test Summary</h2>
            <div class="metrics">
                <div class="metric-card">
                    <div class="metric-value" id="total-requests">N/A</div>
                    <div class="metric-label">Total Requests</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="success-rate">N/A</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="avg-response-time">N/A</div>
                    <div class="metric-label">Avg Response Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value" id="p95-response-time">N/A</div>
                    <div class="metric-label">95th Percentile</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Performance Thresholds</h2>
            <table>
                <thead>
                    <tr><th>Metric</th><th>Threshold</th><th>Actual</th><th>Status</th></tr>
                </thead>
                <tbody id="thresholds-table">
                    <!-- Populated by JavaScript -->
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Test Configuration</h2>
            <table>
                <thead>
                    <tr><th>Parameter</th><th>Value</th></tr>
                </thead>
                <tbody>
                    <tr><td>Tool</td><td>TOOL</td></tr>
                    <tr><td>Environment</td><td>ENVIRONMENT</td></tr>
                    <tr><td>Test Type</td><td>TEST_TYPE</td></tr>
                    <tr><td>Workers</td><td>WORKERS</td></tr>
                    <tr><td>Duration</td><td>DURATION</td></tr>
                    <tr><td>Target URL</td><td>TARGET_URL</td></tr>
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>Generated by iSECTECH Distributed Load Testing Framework</p>
            <p>For detailed metrics, check Grafana dashboard or raw JSON reports</p>
        </div>
    </div>

    <script>
        // Populate report with actual data
        // This would be enhanced to parse actual JSON results
        document.getElementById('total-requests').textContent = 'Processing...';
        document.getElementById('success-rate').textContent = 'Processing...';
        document.getElementById('avg-response-time').textContent = 'Processing...';
        document.getElementById('p95-response-time').textContent = 'Processing...';
    </script>
</body>
</html>
EOF

    # Replace placeholders
    sed -i "s/TIMESTAMP/$(date)/g" "$report_file"
    sed -i "s/ENVIRONMENT/$ENVIRONMENT/g" "$report_file"
    sed -i "s/TEST_TYPE/$TEST_TYPE/g" "$report_file"
    sed -i "s/TOOL/$TOOL/g" "$report_file"
    sed -i "s/WORKERS/$WORKERS/g" "$report_file"
    sed -i "s/DURATION/$DURATION/g" "$report_file"
    sed -i "s|TARGET_URL|${TARGET_URL:-'N/A'}|g" "$report_file"

    log_success "Report generated: $report_file"
    
    # Try to open report in browser if running interactively
    if [[ -t 1 ]] && command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$report_file" 2>/dev/null || true
    elif [[ -t 1 ]] && command -v open >/dev/null 2>&1; then
        open "$report_file" 2>/dev/null || true
    fi
}

# Cleanup function
cleanup_resources() {
    log_info "Cleaning up load testing resources..."
    
    # Docker Compose cleanup
    cd "$PERFORMANCE_DIR/docker"
    docker-compose -f docker-compose.distributed.yml down -v --remove-orphans 2>/dev/null || true
    
    # Remove unused images
    docker image prune -f --filter label=stage=load-testing 2>/dev/null || true
    
    # Kubernetes cleanup
    kubectl delete namespace performance-testing --ignore-not-found=true 2>/dev/null || true
    
    # Clean old reports (keep last 10)
    find "$PERFORMANCE_DIR/reports" -name "*.json" -type f | sort | head -n -10 | xargs rm -f 2>/dev/null || true
    find "$PERFORMANCE_DIR/reports" -name "*.html" -type f | sort | head -n -10 | xargs rm -f 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main execution logic
main() {
    # Parse command line arguments
    TOOL="$DEFAULT_TOOL"
    ENVIRONMENT="$DEFAULT_ENVIRONMENT"
    TEST_TYPE="$DEFAULT_TEST_TYPE"
    WORKERS="$DEFAULT_WORKERS"
    DURATION="$DEFAULT_DURATION"
    TARGET_URL=""
    USE_KUBERNETES=false
    CONTINUOUS=false
    REPORT_ONLY=false
    VERBOSE=false

    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tool)
                TOOL="$2"
                shift 2
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -T|--test-type)
                TEST_TYPE="$2"
                shift 2
                ;;
            -w|--workers)
                WORKERS="$2"
                shift 2
                ;;
            -d|--duration)
                DURATION="$2"
                shift 2
                ;;
            -u|--url)
                TARGET_URL="$2"
                shift 2
                ;;
            -k|--kubernetes)
                USE_KUBERNETES=true
                shift
                ;;
            -c|--continuous)
                CONTINUOUS=true
                shift
                ;;
            -r|--report-only)
                REPORT_ONLY=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            start|stop|status|logs|clean|build|deploy|report)
                COMMAND="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set default TARGET_URL if not specified
    if [[ -z "$TARGET_URL" ]]; then
        case "$ENVIRONMENT" in
            production)
                TARGET_URL="https://api.isectech.com"
                ;;
            staging)
                TARGET_URL="https://staging.isectech.com"
                ;;
            *)
                TARGET_URL="http://localhost:3000"
                ;;
        esac
    fi

    # Validate configuration
    if ! validate_config "$TOOL" "$ENVIRONMENT" "$TEST_TYPE"; then
        exit 1
    fi

    # Execute command
    case "${COMMAND:-}" in
        start)
            setup_environment "$ENVIRONMENT" "$TARGET_URL"
            if [[ "$USE_KUBERNETES" == true ]]; then
                manage_kubernetes deploy "$TOOL"
            else
                build_images "$TOOL"
                manage_docker_compose start "$TOOL"
            fi
            ;;
        stop)
            if [[ "$USE_KUBERNETES" == true ]]; then
                manage_kubernetes stop "$TOOL"
            else
                manage_docker_compose stop "$TOOL"
            fi
            ;;
        status)
            if [[ "$USE_KUBERNETES" == true ]]; then
                manage_kubernetes status "$TOOL"
            else
                manage_docker_compose status "$TOOL"
            fi
            ;;
        logs)
            if [[ "$USE_KUBERNETES" == true ]]; then
                manage_kubernetes logs "$TOOL"
            else
                manage_docker_compose logs "$TOOL"
            fi
            ;;
        clean)
            cleanup_resources
            ;;
        build)
            build_images "$TOOL"
            ;;
        deploy)
            if [[ "$USE_KUBERNETES" == true ]]; then
                manage_kubernetes deploy "$TOOL"
            else
                log_error "Deploy command requires --kubernetes flag"
                exit 1
            fi
            ;;
        report)
            generate_report
            ;;
        *)
            log_error "Command required. Use -h for help."
            usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"