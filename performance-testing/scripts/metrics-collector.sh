#!/bin/bash

# iSECTECH Metrics Collection and Analysis Script
# Automated collection, analysis, and reporting of load test metrics

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PERFORMANCE_DIR="$PROJECT_ROOT/performance-testing"

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

iSECTECH Metrics Collection and Analysis Tool

COMMANDS:
    collect         Collect metrics from all sources
    analyze         Analyze collected metrics and generate insights
    report          Generate comprehensive performance report
    dashboard       Open Grafana dashboard in browser
    export          Export metrics to various formats
    alert-check     Check alert conditions and thresholds
    cleanup         Clean up old metrics and reports

OPTIONS:
    -s, --start-time TIME     Start time for metric collection (e.g., "2h ago", "2023-01-01T00:00:00Z")
    -e, --end-time TIME       End time for metric collection (default: now)
    -o, --output DIR          Output directory for reports and exports
    -f, --format FORMAT       Export format (json|csv|html|pdf) [default: html]
    -t, --threshold FILE      Custom threshold configuration file
    -v, --verbose             Verbose logging
    -h, --help                Show this help message

EXAMPLES:
    # Collect metrics for the last hour
    $0 collect -s "1h ago"

    # Generate comprehensive report
    $0 report -s "2h ago" -f html

    # Export metrics to CSV
    $0 export -s "30m ago" -f csv -o ./reports

    # Check alert conditions
    $0 alert-check -v

    # Open dashboard
    $0 dashboard

EOF
}

# Metric collection functions
collect_k6_metrics() {
    local start_time="$1"
    local end_time="$2"
    local output_dir="$3"

    log_info "Collecting k6 metrics from InfluxDB..."

    # Connect to InfluxDB and extract k6 metrics
    local influx_query="SELECT * FROM http_reqs, http_req_duration, vus, security_event_processing_success, threat_detection_latency, alert_correlation_time WHERE time >= '$start_time' AND time <= '$end_time'"
    
    # Use InfluxDB API to extract metrics
    curl -s -G "http://localhost:8086/query" \
        --data-urlencode "db=k6_metrics" \
        --data-urlencode "q=$influx_query" \
        --data-urlencode "epoch=ms" > "$output_dir/k6_metrics.json"

    if [[ -s "$output_dir/k6_metrics.json" ]]; then
        log_success "k6 metrics collected successfully"
    else
        log_warning "No k6 metrics found for specified time range"
    fi
}

collect_artillery_metrics() {
    local start_time="$1"
    local end_time="$2" 
    local output_dir="$3"

    log_info "Collecting Artillery metrics from Prometheus..."

    # Convert time format for Prometheus
    local prom_start=$(date -d "$start_time" +%s)
    local prom_end=$(date -d "$end_time" +%s)

    # Query Prometheus for Artillery metrics
    local metrics=(
        "isectech_artillery_http_requests_total"
        "isectech_artillery_response_time_seconds"
        "isectech_artillery_concurrent_users"
    )

    for metric in "${metrics[@]}"; do
        log_info "Collecting metric: $metric"
        curl -s -G "http://localhost:9090/api/v1/query_range" \
            --data-urlencode "query=$metric" \
            --data-urlencode "start=$prom_start" \
            --data-urlencode "end=$prom_end" \
            --data-urlencode "step=15s" > "$output_dir/artillery_${metric}.json"
    done

    log_success "Artillery metrics collected successfully"
}

collect_system_metrics() {
    local start_time="$1"
    local end_time="$2"
    local output_dir="$3"

    log_info "Collecting system metrics from Prometheus..."

    # Convert time format for Prometheus
    local prom_start=$(date -d "$start_time" +%s)
    local prom_end=$(date -d "$end_time" +%s)

    # System metrics to collect
    local system_metrics=(
        "node_cpu_seconds_total"
        "node_memory_MemTotal_bytes"
        "node_memory_MemAvailable_bytes"
        "node_filesystem_avail_bytes"
        "node_network_receive_bytes_total"
        "node_network_transmit_bytes_total"
        "nginx_http_requests_total"
        "postgres_stat_activity_count"
        "postgres_stat_database_tup_fetched_total"
    )

    for metric in "${system_metrics[@]}"; do
        log_info "Collecting system metric: $metric"
        curl -s -G "http://localhost:9090/api/v1/query_range" \
            --data-urlencode "query=$metric" \
            --data-urlencode "start=$prom_start" \
            --data-urlencode "end=$prom_end" \
            --data-urlencode "step=30s" > "$output_dir/system_${metric}.json"
    done

    log_success "System metrics collected successfully"
}

# Analysis functions
analyze_performance_trends() {
    local metrics_dir="$1"
    local output_file="$2"

    log_info "Analyzing performance trends..."

    # Create analysis report
    cat > "$output_file" << 'EOF'
# iSECTECH Load Testing Performance Analysis

## Executive Summary
EOF

    # Analyze k6 metrics if available
    if [[ -f "$metrics_dir/k6_metrics.json" ]]; then
        log_info "Analyzing k6 performance data..."
        
        # Extract key metrics using jq
        local total_requests=$(jq -r '.results[0].series[0].values | length // 0' "$metrics_dir/k6_metrics.json" 2>/dev/null || echo "0")
        local avg_response_time=$(jq -r '.results[1].series[0] | if .values then [.values[][1] | tonumber] | add / length else 0 end' "$metrics_dir/k6_metrics.json" 2>/dev/null || echo "0")
        
        cat >> "$output_file" << EOF

### k6 Load Testing Results
- **Total Requests**: $total_requests
- **Average Response Time**: ${avg_response_time}ms
- **Test Duration**: $(date -d "$START_TIME" +%Y-%m-%d\ %H:%M:%S) to $(date -d "$END_TIME" +%Y-%m-%d\ %H:%M:%S)

EOF
    fi

    # Analyze Artillery metrics if available
    if ls "$metrics_dir"/artillery_*.json 1> /dev/null 2>&1; then
        log_info "Analyzing Artillery performance data..."
        
        cat >> "$output_file" << EOF

### Artillery Load Testing Results
- **Tool**: Artillery distributed load testing
- **Metrics Collection**: Prometheus-based
- **Analysis Period**: $(date -d "$START_TIME" +%Y-%m-%d\ %H:%M:%S) to $(date -d "$END_TIME" +%Y-%m-%d\ %H:%M:%S)

EOF
    fi

    log_success "Performance trends analysis completed"
}

check_performance_thresholds() {
    local metrics_dir="$1"
    local threshold_file="$2"
    local output_file="$3"

    log_info "Checking performance thresholds..."

    # Default thresholds if no file provided
    if [[ ! -f "$threshold_file" ]]; then
        cat > "/tmp/default_thresholds.json" << 'EOF'
{
  "response_time_p95_ms": 1000,
  "response_time_p99_ms": 2000,
  "error_rate_percent": 1,
  "cpu_usage_percent": 80,
  "memory_usage_percent": 85,
  "disk_usage_percent": 90
}
EOF
        threshold_file="/tmp/default_thresholds.json"
    fi

    # Load thresholds
    local rt_p95_threshold=$(jq -r '.response_time_p95_ms' "$threshold_file")
    local error_rate_threshold=$(jq -r '.error_rate_percent' "$threshold_file")
    local cpu_threshold=$(jq -r '.cpu_usage_percent' "$threshold_file")

    # Initialize results
    cat > "$output_file" << EOF
# Performance Threshold Analysis

## Threshold Check Results
Generated at: $(date)

| Metric | Threshold | Actual | Status |
|--------|-----------|--------|---------|
EOF

    # Check response time thresholds
    # This would be enhanced with actual metric analysis
    echo "| Response Time P95 | < ${rt_p95_threshold}ms | TBD | ⚠️ PENDING |" >> "$output_file"
    echo "| Error Rate | < ${error_rate_threshold}% | TBD | ⚠️ PENDING |" >> "$output_file"
    echo "| CPU Usage | < ${cpu_threshold}% | TBD | ⚠️ PENDING |" >> "$output_file"

    cat >> "$output_file" << EOF

## Recommendations

1. **Response Time Optimization**
   - Review slow endpoints identified in load testing
   - Consider database query optimization
   - Evaluate caching strategies

2. **Error Rate Investigation**
   - Analyze error patterns and frequency
   - Review application logs for root causes
   - Implement better error handling

3. **Resource Optimization**
   - Monitor CPU and memory usage patterns
   - Consider horizontal scaling if needed
   - Optimize resource allocation

EOF

    log_success "Performance threshold analysis completed"
}

# Report generation functions
generate_html_report() {
    local metrics_dir="$1"
    local output_file="$2"
    local start_time="$3"
    local end_time="$4"

    log_info "Generating HTML performance report..."

    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH Load Testing Performance Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            color: #2c5aa0;
            border-bottom: 3px solid #2c5aa0;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            color: #666;
            font-size: 1.1em;
        }
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .metric-label {
            font-size: 0.9em;
            opacity: 0.9;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .section {
            margin: 40px 0;
        }
        .section h2 {
            color: #2c5aa0;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .status-good { background: linear-gradient(135deg, #4CAF50, #45a049); }
        .status-warning { background: linear-gradient(135deg, #FF9800, #F57C00); }
        .status-critical { background: linear-gradient(135deg, #f44336, #d32f2f); }
        .chart-placeholder {
            background: #f8f9fa;
            border: 2px dashed #dee2e6;
            height: 300px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #666;
            border-radius: 8px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #2c5aa0;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>iSECTECH Performance Report</h1>
            <p>Load Testing Analysis from $start_time to $end_time</p>
            <p>Generated on $(date)</p>
        </div>

        <div class="section">
            <h2>Performance Overview</h2>
            <div class="metrics-grid">
                <div class="metric-card status-good">
                    <div class="metric-value" id="total-requests">0</div>
                    <div class="metric-label">Total Requests</div>
                </div>
                <div class="metric-card status-good">
                    <div class="metric-value" id="avg-response-time">0ms</div>
                    <div class="metric-label">Avg Response Time</div>
                </div>
                <div class="metric-card status-good">
                    <div class="metric-value" id="success-rate">0%</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card status-warning">
                    <div class="metric-value" id="error-count">0</div>
                    <div class="metric-label">Total Errors</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Response Time Analysis</h2>
            <div class="chart-placeholder">
                <p>Response time percentiles chart would be rendered here<br>
                <small>Connect to Grafana at <a href="http://localhost:3001">http://localhost:3001</a> for interactive charts</small></p>
            </div>
        </div>

        <div class="section">
            <h2>System Resource Utilization</h2>
            <table>
                <thead>
                    <tr><th>Resource</th><th>Average</th><th>Peak</th><th>Status</th></tr>
                </thead>
                <tbody>
                    <tr><td>CPU Usage</td><td>--</td><td>--</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Memory Usage</td><td>--</td><td>--</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Disk I/O</td><td>--</td><td>--</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Network I/O</td><td>--</td><td>--</td><td>🔍 Analyzing</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Security Platform Specific Metrics</h2>
            <table>
                <thead>
                    <tr><th>Metric</th><th>Value</th><th>Threshold</th><th>Status</th></tr>
                </thead>
                <tbody>
                    <tr><td>Threat Detection Latency</td><td>--</td><td>&lt; 500ms</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Alert Correlation Time</td><td>--</td><td>&lt; 200ms</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Security Event Processing Rate</td><td>--</td><td>&gt; 99%</td><td>🔍 Analyzing</td></tr>
                    <tr><td>Authentication Failures</td><td>--</td><td>&lt; 1%</td><td>🔍 Analyzing</td></tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Recommendations</h2>
            <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; border-left: 4px solid #2c5aa0;">
                <h3 style="margin-top: 0;">Performance Optimization Recommendations</h3>
                <ul>
                    <li><strong>Database Optimization</strong>: Review slow queries and consider indexing improvements</li>
                    <li><strong>Caching Strategy</strong>: Implement Redis caching for frequently accessed data</li>
                    <li><strong>API Rate Limiting</strong>: Fine-tune rate limiting policies based on load test results</li>
                    <li><strong>Infrastructure Scaling</strong>: Consider horizontal scaling for high-traffic scenarios</li>
                    <li><strong>Security Processing</strong>: Optimize threat detection algorithms for better performance</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Generated by iSECTECH Performance Testing Framework</p>
            <p>For detailed metrics and real-time monitoring, visit the <a href="http://localhost:3001">Grafana Dashboard</a></p>
        </div>
    </div>

    <script>
        // Enhanced with actual data processing when metrics are available
        document.getElementById('total-requests').textContent = 'Processing...';
        document.getElementById('avg-response-time').textContent = 'Processing...';
        document.getElementById('success-rate').textContent = 'Processing...';
        document.getElementById('error-count').textContent = 'Processing...';

        // This would be enhanced to load actual metrics data
        setTimeout(() => {
            document.getElementById('total-requests').textContent = '0';
            document.getElementById('avg-response-time').textContent = '0ms';
            document.getElementById('success-rate').textContent = '0%';
            document.getElementById('error-count').textContent = '0';
        }, 1000);
    </script>
</body>
</html>
EOF

    log_success "HTML report generated: $output_file"
}

# Alert checking functions
check_alert_conditions() {
    local verbose="$1"

    log_info "Checking alert conditions..."

    # Check if Prometheus is accessible
    if curl -s "http://localhost:9090/api/v1/query?query=up" >/dev/null 2>&1; then
        log_success "Prometheus is accessible"
        
        # Check current alert status
        local alerts_response=$(curl -s "http://localhost:9090/api/v1/alerts")
        local firing_alerts=$(echo "$alerts_response" | jq -r '.data.alerts[] | select(.state=="firing") | .labels.alertname' 2>/dev/null || echo "")
        
        if [[ -n "$firing_alerts" ]]; then
            log_warning "Active alerts detected:"
            echo "$firing_alerts" | while read alert; do
                echo "  - $alert"
            done
        else
            log_success "No active alerts"
        fi
    else
        log_warning "Prometheus not accessible - unable to check alerts"
    fi

    # Check system resources locally
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' 2>/dev/null || echo "0")
    local memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}' 2>/dev/null || echo "0")

    if (( $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "High CPU usage detected: ${cpu_usage}%"
    fi

    if (( $(echo "$memory_usage > 85" | bc -l 2>/dev/null || echo 0) )); then
        log_warning "High memory usage detected: ${memory_usage}%"
    fi
}

# Dashboard functions
open_dashboard() {
    local dashboard_url="http://localhost:3001"
    
    log_info "Opening Grafana dashboard..."
    
    # Check if Grafana is accessible
    if curl -s "$dashboard_url" >/dev/null 2>&1; then
        log_success "Grafana is accessible at $dashboard_url"
        
        # Try to open in browser
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$dashboard_url" 2>/dev/null || true
        elif command -v open >/dev/null 2>&1; then
            open "$dashboard_url" 2>/dev/null || true
        else
            log_info "Please open $dashboard_url in your browser"
        fi
        
        log_info "Default credentials: admin / admin123!"
    else
        log_error "Grafana is not accessible at $dashboard_url"
        log_info "Make sure the distributed load testing stack is running:"
        log_info "cd $PERFORMANCE_DIR/docker && docker-compose -f docker-compose.distributed.yml up -d grafana"
    fi
}

# Cleanup functions
cleanup_old_data() {
    local days_to_keep="${1:-7}"
    
    log_info "Cleaning up data older than $days_to_keep days..."
    
    # Clean up old report files
    find "$PERFORMANCE_DIR/reports" -type f -mtime +$days_to_keep -name "*.html" -delete 2>/dev/null || true
    find "$PERFORMANCE_DIR/reports" -type f -mtime +$days_to_keep -name "*.json" -delete 2>/dev/null || true
    find "$PERFORMANCE_DIR/reports" -type f -mtime +$days_to_keep -name "*.csv" -delete 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main execution logic
main() {
    # Default values
    START_TIME="1h ago"
    END_TIME="now"
    OUTPUT_DIR="$PERFORMANCE_DIR/reports"
    FORMAT="html"
    THRESHOLD_FILE=""
    VERBOSE=false

    # Create output directory if it doesn't exist
    mkdir -p "$OUTPUT_DIR"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--start-time)
                START_TIME="$2"
                shift 2
                ;;
            -e|--end-time)
                END_TIME="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--format)
                FORMAT="$2"
                shift 2
                ;;
            -t|--threshold)
                THRESHOLD_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            collect|analyze|report|dashboard|export|alert-check|cleanup)
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

    # Execute command
    case "${COMMAND:-}" in
        collect)
            log_info "Collecting metrics from $START_TIME to $END_TIME"
            collect_k6_metrics "$START_TIME" "$END_TIME" "$OUTPUT_DIR"
            collect_artillery_metrics "$START_TIME" "$END_TIME" "$OUTPUT_DIR"
            collect_system_metrics "$START_TIME" "$END_TIME" "$OUTPUT_DIR"
            ;;
        analyze)
            local analysis_file="$OUTPUT_DIR/performance-analysis-$(date +%Y%m%d-%H%M%S).md"
            analyze_performance_trends "$OUTPUT_DIR" "$analysis_file"
            check_performance_thresholds "$OUTPUT_DIR" "$THRESHOLD_FILE" "$OUTPUT_DIR/threshold-analysis.md"
            ;;
        report)
            local report_file="$OUTPUT_DIR/performance-report-$(date +%Y%m%d-%H%M%S).$FORMAT"
            case "$FORMAT" in
                html)
                    generate_html_report "$OUTPUT_DIR" "$report_file" "$START_TIME" "$END_TIME"
                    ;;
                *)
                    log_error "Format $FORMAT not yet implemented"
                    exit 1
                    ;;
            esac
            ;;
        dashboard)
            open_dashboard
            ;;
        alert-check)
            check_alert_conditions "$VERBOSE"
            ;;
        cleanup)
            cleanup_old_data
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