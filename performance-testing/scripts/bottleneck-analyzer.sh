#!/bin/bash

# iSECTECH Bottleneck Analysis Script
# Comprehensive performance bottleneck identification and analysis

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
PURPLE='\033[0;35m'
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

log_analysis() {
    echo -e "${PURPLE}[ANALYSIS]${NC} $1"
}

# Usage function
usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

iSECTECH Performance Bottleneck Analysis Tool

COMMANDS:
    analyze-all        Run comprehensive bottleneck analysis
    database          Analyze database performance bottlenecks
    api               Analyze API endpoint bottlenecks  
    network           Analyze network and I/O bottlenecks
    memory            Analyze memory usage patterns
    cpu               Analyze CPU utilization patterns
    correlate         Correlate metrics to identify root causes
    generate-report   Generate bottleneck analysis report

OPTIONS:
    -s, --start-time TIME     Analysis start time (e.g., "2h ago") [default: 1h ago]
    -e, --end-time TIME       Analysis end time [default: now]
    -t, --threshold LEVEL     Analysis sensitivity (low|medium|high) [default: medium]
    -o, --output DIR          Output directory for analysis results
    -f, --format FORMAT       Report format (html|json|md) [default: html]
    -v, --verbose             Verbose analysis output
    -h, --help                Show this help message

EXAMPLES:
    # Run comprehensive analysis for last 2 hours
    $0 analyze-all -s "2h ago"

    # Focus on database bottlenecks with high sensitivity
    $0 database -t high -v

    # Analyze API performance and generate detailed report
    $0 api -s "1h ago" -f html -o ./reports

    # Correlate all metrics for root cause analysis
    $0 correlate -s "30m ago" -v

EOF
}

# Database bottleneck analysis
analyze_database_bottlenecks() {
    local start_time="$1"
    local end_time="$2"
    local threshold_level="$3"
    local output_dir="$4"

    log_analysis "Analyzing database performance bottlenecks..."

    # Set thresholds based on sensitivity level
    local slow_query_threshold_ms
    local connection_usage_threshold
    local lock_wait_threshold_ms
    
    case "$threshold_level" in
        low)
            slow_query_threshold_ms=2000
            connection_usage_threshold=90
            lock_wait_threshold_ms=500
            ;;
        high)
            slow_query_threshold_ms=200
            connection_usage_threshold=60
            lock_wait_threshold_ms=100
            ;;
        *)  # medium
            slow_query_threshold_ms=500
            connection_usage_threshold=80
            lock_wait_threshold_ms=250
            ;;
    esac

    # Convert time format for Prometheus queries
    local prom_start=$(date -d "$start_time" -u +%s 2>/dev/null || echo $(($(date +%s) - 3600)))
    local prom_end=$(date -d "$end_time" -u +%s 2>/dev/null || date +%s)

    # Create database analysis results file
    local db_analysis_file="$output_dir/database_bottlenecks_$(date +%Y%m%d_%H%M%S).json"
    
    log_info "Querying database metrics from Prometheus..."

    # Query database connection metrics
    local connection_query="postgres_stat_activity_count / postgres_settings_max_connections * 100"
    local connection_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$connection_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query database query rate metrics
    local query_rate_query="rate(postgres_stat_database_tup_fetched_total[5m])"
    local query_rate_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$query_rate_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query transaction metrics
    local transaction_query="rate(postgres_stat_database_xact_commit_total[5m]) + rate(postgres_stat_database_xact_rollback_total[5m])"
    local transaction_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$transaction_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Analyze connection usage patterns
    local max_connection_usage=$(echo "$connection_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_connection_usage=$(echo "$connection_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")

    # Analyze query patterns
    local max_query_rate=$(echo "$query_rate_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_query_rate=$(echo "$query_rate_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")

    # Generate database bottleneck analysis
    cat > "$db_analysis_file" << EOF
{
    "analysis_type": "database_bottlenecks",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "time_range": {
        "start": "$start_time",
        "end": "$end_time"
    },
    "threshold_level": "$threshold_level",
    "thresholds": {
        "slow_query_ms": $slow_query_threshold_ms,
        "connection_usage_percent": $connection_usage_threshold,
        "lock_wait_ms": $lock_wait_threshold_ms
    },
    "metrics": {
        "connection_usage": {
            "max_percent": $max_connection_usage,
            "avg_percent": $avg_connection_usage,
            "status": "$(if (( $(echo "$max_connection_usage > $connection_usage_threshold" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        },
        "query_rate": {
            "max_per_second": $max_query_rate,
            "avg_per_second": $avg_query_rate,
            "status": "$(if (( $(echo "$max_query_rate > 1000" | bc -l 2>/dev/null || echo 0) )); then echo "HIGH"; else echo "NORMAL"; fi)"
        }
    },
    "identified_bottlenecks": [
EOF

    # Identify specific bottlenecks
    local bottlenecks_found=false
    
    if (( $(echo "$max_connection_usage > $connection_usage_threshold" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$bottlenecks_found" == "true" ]]; then echo "," >> "$db_analysis_file"; fi
        cat >> "$db_analysis_file" << EOF
        {
            "type": "high_connection_usage",
            "severity": "$(if (( $(echo "$max_connection_usage > 95" | bc -l 2>/dev/null || echo 0) )); then echo "CRITICAL"; else echo "WARNING"; fi)",
            "description": "Database connection pool usage is high ($max_connection_usage%)",
            "recommendation": "Consider increasing connection pool size or optimizing connection lifecycle",
            "impact": "May cause connection timeouts and application blocking"
        }
EOF
        bottlenecks_found=true
    fi

    if (( $(echo "$max_query_rate > 2000" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$bottlenecks_found" == "true" ]]; then echo "," >> "$db_analysis_file"; fi
        cat >> "$db_analysis_file" << EOF
        {
            "type": "high_query_load",
            "severity": "WARNING",
            "description": "High database query rate detected ($max_query_rate queries/sec)",
            "recommendation": "Review query patterns, implement caching, optimize frequent queries",
            "impact": "May lead to database performance degradation"
        }
EOF
        bottlenecks_found=true
    fi

    if [[ "$bottlenecks_found" == "false" ]]; then
        cat >> "$db_analysis_file" << EOF
        {
            "type": "none_detected",
            "severity": "INFO", 
            "description": "No significant database bottlenecks detected",
            "recommendation": "Continue monitoring database performance metrics",
            "impact": "Database performance appears healthy"
        }
EOF
    fi

    cat >> "$db_analysis_file" << EOF
    ],
    "recommendations": [
        "Monitor slow query log for queries exceeding ${slow_query_threshold_ms}ms",
        "Implement connection pooling optimization",
        "Consider read replicas for heavy read workloads",
        "Review and optimize database indexes",
        "Implement query result caching for frequent operations"
    ]
}
EOF

    log_success "Database bottleneck analysis completed: $db_analysis_file"
}

# API endpoint bottleneck analysis
analyze_api_bottlenecks() {
    local start_time="$1"
    local end_time="$2"
    local threshold_level="$3"
    local output_dir="$4"

    log_analysis "Analyzing API endpoint performance bottlenecks..."

    # Set thresholds based on sensitivity level
    local response_time_threshold_ms
    local error_rate_threshold
    local throughput_threshold_rps
    
    case "$threshold_level" in
        low)
            response_time_threshold_ms=2000
            error_rate_threshold=5.0
            throughput_threshold_rps=10
            ;;
        high)
            response_time_threshold_ms=300
            error_rate_threshold=1.0
            throughput_threshold_rps=100
            ;;
        *)  # medium
            response_time_threshold_ms=1000
            error_rate_threshold=2.0
            throughput_threshold_rps=50
            ;;
    esac

    local prom_start=$(date -d "$start_time" -u +%s 2>/dev/null || echo $(($(date +%s) - 3600)))
    local prom_end=$(date -d "$end_time" -u +%s 2>/dev/null || date +%s)

    local api_analysis_file="$output_dir/api_bottlenecks_$(date +%Y%m%d_%H%M%S).json"
    
    log_info "Analyzing API endpoint performance patterns..."

    # Query response time metrics
    local response_time_query="histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) * 1000"
    local response_time_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$response_time_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query error rate metrics
    local error_rate_query="rate(http_requests_total{status!~\"2..\"}[5m]) / rate(http_requests_total[5m]) * 100"
    local error_rate_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$error_rate_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query request rate by endpoint
    local endpoint_rate_query="sum(rate(http_requests_total[5m])) by (endpoint)"
    local endpoint_rate_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$endpoint_rate_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=300s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Analyze metrics
    local max_response_time=$(echo "$response_time_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_response_time=$(echo "$response_time_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")
    
    local max_error_rate=$(echo "$error_rate_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_error_rate=$(echo "$error_rate_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")

    # Generate API bottleneck analysis
    cat > "$api_analysis_file" << EOF
{
    "analysis_type": "api_bottlenecks",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "time_range": {
        "start": "$start_time",
        "end": "$end_time"
    },
    "threshold_level": "$threshold_level",
    "thresholds": {
        "response_time_ms": $response_time_threshold_ms,
        "error_rate_percent": $error_rate_threshold,
        "throughput_rps": $throughput_threshold_rps
    },
    "metrics": {
        "response_time": {
            "max_ms": $max_response_time,
            "avg_ms": $avg_response_time,
            "p95_status": "$(if (( $(echo "$max_response_time > $response_time_threshold_ms" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        },
        "error_rate": {
            "max_percent": $max_error_rate,
            "avg_percent": $avg_error_rate,
            "status": "$(if (( $(echo "$max_error_rate > $error_rate_threshold" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        }
    },
    "endpoint_analysis": {
EOF

    # Analyze individual endpoints if data available
    echo "$endpoint_rate_data" | jq -c '.data.result[]?' 2>/dev/null | head -5 | while IFS= read -r endpoint_data; do
        local endpoint_name=$(echo "$endpoint_data" | jq -r '.metric.endpoint // "unknown"')
        local avg_rate=$(echo "$endpoint_data" | jq -r '[.values[][1] | tonumber] | add / length // 0')
        echo "        \"$endpoint_name\": { \"avg_rps\": $avg_rate },"
    done >> "$api_analysis_file"

    # Remove trailing comma if any endpoints were added
    sed -i '$ s/,$//' "$api_analysis_file" 2>/dev/null || true

    cat >> "$api_analysis_file" << EOF
    },
    "identified_bottlenecks": [
EOF

    # Identify API bottlenecks
    local api_bottlenecks_found=false
    
    if (( $(echo "$max_response_time > $response_time_threshold_ms" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$api_bottlenecks_found" == "true" ]]; then echo "," >> "$api_analysis_file"; fi
        cat >> "$api_analysis_file" << EOF
        {
            "type": "high_response_time",
            "severity": "$(if (( $(echo "$max_response_time > $(($response_time_threshold_ms * 2))" | bc -l 2>/dev/null || echo 0) )); then echo "CRITICAL"; else echo "WARNING"; fi)",
            "description": "API response times exceed threshold (${max_response_time}ms > ${response_time_threshold_ms}ms)",
            "recommendation": "Profile slow endpoints, optimize database queries, implement caching",
            "impact": "Poor user experience and potential timeouts"
        }
EOF
        api_bottlenecks_found=true
    fi

    if (( $(echo "$max_error_rate > $error_rate_threshold" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$api_bottlenecks_found" == "true" ]]; then echo "," >> "$api_analysis_file"; fi
        cat >> "$api_analysis_file" << EOF
        {
            "type": "high_error_rate",
            "severity": "$(if (( $(echo "$max_error_rate > 10" | bc -l 2>/dev/null || echo 0) )); then echo "CRITICAL"; else echo "WARNING"; fi)",
            "description": "API error rate exceeds threshold (${max_error_rate}% > ${error_rate_threshold}%)",
            "recommendation": "Investigate error causes, improve error handling, check dependencies",
            "impact": "Service reliability issues and user frustration"
        }
EOF
        api_bottlenecks_found=true
    fi

    if [[ "$api_bottlenecks_found" == "false" ]]; then
        cat >> "$api_analysis_file" << EOF
        {
            "type": "none_detected",
            "severity": "INFO",
            "description": "No significant API bottlenecks detected",
            "recommendation": "Continue monitoring API performance metrics",
            "impact": "API performance appears healthy"
        }
EOF
    fi

    cat >> "$api_analysis_file" << EOF
    ],
    "recommendations": [
        "Implement API response caching for frequently accessed data",
        "Optimize database queries for slow endpoints",
        "Add circuit breakers for external service calls",
        "Consider API rate limiting to protect against abuse",
        "Monitor and optimize memory usage in API handlers",
        "Implement proper error handling and logging"
    ]
}
EOF

    log_success "API bottleneck analysis completed: $api_analysis_file"
}

# System resource bottleneck analysis
analyze_system_bottlenecks() {
    local start_time="$1"
    local end_time="$2"
    local threshold_level="$3"
    local output_dir="$4"

    log_analysis "Analyzing system resource bottlenecks..."

    # Set thresholds based on sensitivity level
    local cpu_threshold
    local memory_threshold
    local disk_io_threshold
    local network_io_threshold
    
    case "$threshold_level" in
        low)
            cpu_threshold=85
            memory_threshold=90
            disk_io_threshold=80
            network_io_threshold=80
            ;;
        high)
            cpu_threshold=60
            memory_threshold=70
            disk_io_threshold=50
            network_io_threshold=50
            ;;
        *)  # medium
            cpu_threshold=75
            memory_threshold=80
            disk_io_threshold=70
            network_io_threshold=70
            ;;
    esac

    local prom_start=$(date -d "$start_time" -u +%s 2>/dev/null || echo $(($(date +%s) - 3600)))
    local prom_end=$(date -d "$end_time" -u +%s 2>/dev/null || date +%s)

    local system_analysis_file="$output_dir/system_bottlenecks_$(date +%Y%m%d_%H%M%S).json"
    
    log_info "Collecting system resource metrics..."

    # Query CPU usage
    local cpu_query="100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
    local cpu_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$cpu_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query Memory usage
    local memory_query="100 * (1 - ((node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes))"
    local memory_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$memory_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query Disk I/O
    local disk_io_query="rate(node_disk_io_time_seconds_total[5m]) * 100"
    local disk_io_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$disk_io_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Query Network I/O
    local network_query="rate(node_network_receive_bytes_total[5m]) + rate(node_network_transmit_bytes_total[5m])"
    local network_data=$(curl -s -G "http://localhost:9090/api/v1/query_range" \
        --data-urlencode "query=$network_query" \
        --data-urlencode "start=$prom_start" \
        --data-urlencode "end=$prom_end" \
        --data-urlencode "step=60s" 2>/dev/null || echo '{"data":{"result":[]}}')

    # Analyze metrics
    local max_cpu=$(echo "$cpu_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_cpu=$(echo "$cpu_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")
    
    local max_memory=$(echo "$memory_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_memory=$(echo "$memory_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")

    local max_disk_io=$(echo "$disk_io_data" | jq -r '.data.result[0].values[]?[1] // 0' | sort -n | tail -1 2>/dev/null || echo "0")
    local avg_disk_io=$(echo "$disk_io_data" | jq -r '[.data.result[0].values[]?[1] // 0 | tonumber] | add / length' 2>/dev/null || echo "0")

    # Generate system analysis report
    cat > "$system_analysis_file" << EOF
{
    "analysis_type": "system_bottlenecks",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "time_range": {
        "start": "$start_time",
        "end": "$end_time"
    },
    "threshold_level": "$threshold_level",
    "thresholds": {
        "cpu_percent": $cpu_threshold,
        "memory_percent": $memory_threshold,
        "disk_io_percent": $disk_io_threshold,
        "network_io_percent": $network_io_threshold
    },
    "system_metrics": {
        "cpu_usage": {
            "max_percent": $max_cpu,
            "avg_percent": $avg_cpu,
            "status": "$(if (( $(echo "$max_cpu > $cpu_threshold" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        },
        "memory_usage": {
            "max_percent": $max_memory,
            "avg_percent": $avg_memory,
            "status": "$(if (( $(echo "$max_memory > $memory_threshold" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        },
        "disk_io": {
            "max_utilization": $max_disk_io,
            "avg_utilization": $avg_disk_io,
            "status": "$(if (( $(echo "$max_disk_io > $disk_io_threshold" | bc -l 2>/dev/null || echo 0) )); then echo "WARNING"; else echo "OK"; fi)"
        }
    },
    "identified_bottlenecks": [
EOF

    # Identify system bottlenecks
    local system_bottlenecks_found=false
    
    if (( $(echo "$max_cpu > $cpu_threshold" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$system_bottlenecks_found" == "true" ]]; then echo "," >> "$system_analysis_file"; fi
        cat >> "$system_analysis_file" << EOF
        {
            "type": "high_cpu_usage",
            "severity": "$(if (( $(echo "$max_cpu > 90" | bc -l 2>/dev/null || echo 0) )); then echo "CRITICAL"; else echo "WARNING"; fi)",
            "description": "CPU usage exceeds threshold (${max_cpu}% > ${cpu_threshold}%)",
            "recommendation": "Investigate CPU-intensive processes, optimize algorithms, consider scaling",
            "impact": "Application performance degradation and increased response times"
        }
EOF
        system_bottlenecks_found=true
    fi

    if (( $(echo "$max_memory > $memory_threshold" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$system_bottlenecks_found" == "true" ]]; then echo "," >> "$system_analysis_file"; fi
        cat >> "$system_analysis_file" << EOF
        {
            "type": "high_memory_usage",
            "severity": "$(if (( $(echo "$max_memory > 95" | bc -l 2>/dev/null || echo 0) )); then echo "CRITICAL"; else echo "WARNING"; fi)",
            "description": "Memory usage exceeds threshold (${max_memory}% > ${memory_threshold}%)",
            "recommendation": "Check for memory leaks, optimize data structures, increase available memory",
            "impact": "Risk of out-of-memory errors and system instability"
        }
EOF
        system_bottlenecks_found=true
    fi

    if (( $(echo "$max_disk_io > $disk_io_threshold" | bc -l 2>/dev/null || echo 0) )); then
        if [[ "$system_bottlenecks_found" == "true" ]]; then echo "," >> "$system_analysis_file"; fi
        cat >> "$system_analysis_file" << EOF
        {
            "type": "high_disk_io",
            "severity": "WARNING",
            "description": "Disk I/O utilization is high (${max_disk_io}% > ${disk_io_threshold}%)",
            "recommendation": "Optimize database queries, implement SSD storage, review disk usage patterns",
            "impact": "Slow database operations and increased response times"
        }
EOF
        system_bottlenecks_found=true
    fi

    if [[ "$system_bottlenecks_found" == "false" ]]; then
        cat >> "$system_analysis_file" << EOF
        {
            "type": "none_detected",
            "severity": "INFO",
            "description": "No significant system bottlenecks detected",
            "recommendation": "Continue monitoring system resource usage",
            "impact": "System resources appear healthy"
        }
EOF
    fi

    cat >> "$system_analysis_file" << EOF
    ],
    "recommendations": [
        "Monitor resource usage trends for capacity planning",
        "Implement auto-scaling policies for cloud deployments",
        "Optimize application memory usage and garbage collection",
        "Consider upgrading to faster storage (NVMe SSD)",
        "Review and optimize background processes",
        "Implement proper resource limits for containers"
    ]
}
EOF

    log_success "System bottleneck analysis completed: $system_analysis_file"
}

# Correlation analysis to identify root causes
correlate_bottlenecks() {
    local start_time="$1"
    local end_time="$2"
    local threshold_level="$3"
    local output_dir="$4"

    log_analysis "Correlating metrics to identify root cause bottlenecks..."

    local correlation_file="$output_dir/correlation_analysis_$(date +%Y%m%d_%H%M%S).json"
    
    # Find all analysis files from current session
    local analysis_files=($(find "$output_dir" -name "*_bottlenecks_*.json" -newer "$output_dir" 2>/dev/null || true))
    
    if [[ ${#analysis_files[@]} -eq 0 ]]; then
        log_warning "No recent bottleneck analysis files found. Running comprehensive analysis first..."
        analyze_database_bottlenecks "$start_time" "$end_time" "$threshold_level" "$output_dir"
        analyze_api_bottlenecks "$start_time" "$end_time" "$threshold_level" "$output_dir"
        analyze_system_bottlenecks "$start_time" "$end_time" "$threshold_level" "$output_dir"
        analysis_files=($(find "$output_dir" -name "*_bottlenecks_*.json" -newer "$output_dir" 2>/dev/null || true))
    fi

    # Correlate findings across all analysis types
    cat > "$correlation_file" << EOF
{
    "analysis_type": "correlation_analysis",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "time_range": {
        "start": "$start_time",
        "end": "$end_time"
    },
    "analyzed_components": [
EOF

    local first_component=true
    for analysis_file in "${analysis_files[@]}"; do
        if [[ "$first_component" == "false" ]]; then echo "," >> "$correlation_file"; fi
        local component_type=$(jq -r '.analysis_type' "$analysis_file" 2>/dev/null || echo "unknown")
        echo "        \"$component_type\"" >> "$correlation_file"
        first_component=false
    done

    cat >> "$correlation_file" << EOF
    ],
    "correlations": {
        "high_severity_issues": [
EOF

    # Collect all high severity issues
    local high_severity_issues=()
    local first_issue=true
    
    for analysis_file in "${analysis_files[@]}"; do
        local critical_issues=$(jq -r '.identified_bottlenecks[] | select(.severity == "CRITICAL" or .severity == "WARNING") | .type + ":" + .description' "$analysis_file" 2>/dev/null || true)
        
        if [[ -n "$critical_issues" ]]; then
            while IFS= read -r issue; do
                if [[ "$first_issue" == "false" ]]; then echo "," >> "$correlation_file"; fi
                echo "            \"$issue\"" >> "$correlation_file"
                first_issue=false
            done <<< "$critical_issues"
        fi
    done

    cat >> "$correlation_file" << EOF
        ],
        "potential_root_causes": [
            {
                "pattern": "Database + API performance issues",
                "description": "Slow database queries causing API endpoint delays",
                "likelihood": "high",
                "recommendation": "Focus on database query optimization and connection pooling"
            },
            {
                "pattern": "System resources + Database performance",
                "description": "Resource constraints affecting database operations",
                "likelihood": "medium",
                "recommendation": "Scale system resources or optimize resource usage"
            },
            {
                "pattern": "API errors + System resources",
                "description": "Resource exhaustion causing API failures",
                "likelihood": "medium",
                "recommendation": "Implement resource monitoring and auto-scaling"
            }
        ]
    },
    "prioritized_actions": [
        {
            "priority": 1,
            "action": "Address database performance bottlenecks",
            "rationale": "Database issues often cascade to affect API and system performance",
            "expected_impact": "high"
        },
        {
            "priority": 2,
            "action": "Optimize system resource utilization",
            "rationale": "Resource constraints limit overall system capacity",
            "expected_impact": "medium-high"
        },
        {
            "priority": 3,
            "action": "Implement API-level optimizations",
            "rationale": "Direct user-facing improvements",
            "expected_impact": "medium"
        }
    ],
    "monitoring_recommendations": [
        "Set up alerts for correlated metric patterns",
        "Implement distributed tracing to track request flows",
        "Monitor resource utilization trends for capacity planning",
        "Create dashboards showing cross-component correlations"
    ]
}
EOF

    log_success "Correlation analysis completed: $correlation_file"
    
    # Generate summary of findings
    log_analysis "=== BOTTLENECK ANALYSIS SUMMARY ==="
    for analysis_file in "${analysis_files[@]}"; do
        local component=$(jq -r '.analysis_type' "$analysis_file" 2>/dev/null)
        local bottlenecks=$(jq -r '.identified_bottlenecks[].type' "$analysis_file" 2>/dev/null | wc -l || echo "0")
        local critical=$(jq -r '.identified_bottlenecks[] | select(.severity == "CRITICAL") | .type' "$analysis_file" 2>/dev/null | wc -l || echo "0")
        
        echo "  $component: $bottlenecks bottlenecks found ($critical critical)"
    done
    log_analysis "=== END SUMMARY ==="
}

# Generate comprehensive bottleneck report
generate_bottleneck_report() {
    local output_dir="$1"
    local format="$2"
    local start_time="$3"
    local end_time="$4"

    log_info "Generating comprehensive bottleneck analysis report..."

    local report_file="$output_dir/bottleneck_analysis_report_$(date +%Y%m%d_%H%M%S).$format"
    
    case "$format" in
        html)
            generate_html_bottleneck_report "$output_dir" "$report_file" "$start_time" "$end_time"
            ;;
        json)
            generate_json_bottleneck_report "$output_dir" "$report_file" "$start_time" "$end_time"
            ;;
        md)
            generate_markdown_bottleneck_report "$output_dir" "$report_file" "$start_time" "$end_time"
            ;;
        *)
            log_error "Unsupported format: $format"
            return 1
            ;;
    esac

    log_success "Bottleneck analysis report generated: $report_file"
}

generate_html_bottleneck_report() {
    local output_dir="$1"
    local report_file="$2"
    local start_time="$3"
    local end_time="$4"

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iSECTECH Bottleneck Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            line-height: 1.6;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            color: #2c5aa0;
            border-bottom: 3px solid #2c5aa0;
            padding-bottom: 25px;
            margin-bottom: 40px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.8em;
            font-weight: 300;
        }
        .severity-critical { border-left: 5px solid #dc3545; background: #f8d7da; }
        .severity-warning { border-left: 5px solid #ffc107; background: #fff3cd; }
        .severity-info { border-left: 5px solid #17a2b8; background: #d1ecf1; }
        .bottleneck-card {
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #28a745;
        }
        .section {
            margin: 40px 0;
        }
        .section h2 {
            color: #2c5aa0;
            border-bottom: 2px solid #dee2e6;
            padding-bottom: 15px;
            margin-bottom: 25px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            background-color: #2c5aa0;
            color: white;
            font-weight: 600;
        }
        tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        .metric-value {
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .metric-label {
            font-size: 0.95em;
            opacity: 0.95;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .recommendations {
            background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #2c5aa0;
            margin: 30px 0;
        }
        .priority-high { color: #dc3545; font-weight: bold; }
        .priority-medium { color: #ffc107; font-weight: bold; }
        .priority-low { color: #28a745; font-weight: bold; }
        .footer {
            text-align: center;
            color: #6c757d;
            margin-top: 50px;
            padding-top: 25px;
            border-top: 1px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Bottleneck Analysis Report</h1>
            <p><strong>Analysis Period:</strong> $start_time to $end_time</p>
            <p><strong>Generated:</strong> $(date)</p>
        </div>

        <div class="section">
            <h2>🚨 Critical Findings Summary</h2>
            <div id="critical-findings">
                <!-- Critical findings will be populated here -->
                <div class="bottleneck-card severity-info">
                    <h3>Analysis Status</h3>
                    <p>Bottleneck analysis completed. Review individual component analysis files for detailed findings.</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Performance Metrics Overview</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">🔍</div>
                    <div class="metric-label">Database Analysis</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">⚡</div>
                    <div class="metric-label">API Performance</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">💻</div>
                    <div class="metric-label">System Resources</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">🔗</div>
                    <div class="metric-label">Correlations</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🎯 Prioritized Recommendations</h2>
            <table>
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Component</th>
                        <th>Issue</th>
                        <th>Recommendation</th>
                        <th>Expected Impact</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><span class="priority-high">HIGH</span></td>
                        <td>Database</td>
                        <td>Query Performance</td>
                        <td>Optimize slow queries and implement connection pooling</td>
                        <td>Significant response time improvement</td>
                    </tr>
                    <tr>
                        <td><span class="priority-medium">MEDIUM</span></td>
                        <td>System</td>
                        <td>Resource Utilization</td>
                        <td>Monitor and scale resources based on usage patterns</td>
                        <td>Improved stability and performance</td>
                    </tr>
                    <tr>
                        <td><span class="priority-medium">MEDIUM</span></td>
                        <td>API</td>
                        <td>Response Caching</td>
                        <td>Implement intelligent caching strategies</td>
                        <td>Reduced load and faster responses</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>🔧 Optimization Action Plan</h2>
            <div class="recommendations">
                <h3>Immediate Actions (Next 24 hours)</h3>
                <ul>
                    <li><strong>Database:</strong> Identify and optimize the slowest 10 queries</li>
                    <li><strong>Monitoring:</strong> Set up alerts for critical performance thresholds</li>
                    <li><strong>Caching:</strong> Implement basic Redis caching for frequent API calls</li>
                </ul>
                
                <h3>Short-term Actions (Next Week)</h3>
                <ul>
                    <li><strong>Infrastructure:</strong> Review and optimize resource allocation</li>
                    <li><strong>Database:</strong> Implement connection pooling and read replicas</li>
                    <li><strong>API:</strong> Add response compression and optimize serialization</li>
                </ul>
                
                <h3>Long-term Actions (Next Month)</h3>
                <ul>
                    <li><strong>Architecture:</strong> Consider microservices decomposition for high-load components</li>
                    <li><strong>Scaling:</strong> Implement auto-scaling policies</li>
                    <li><strong>Performance:</strong> Establish performance testing in CI/CD pipeline</li>
                </ul>
            </div>
        </div>

        <div class="section">
            <h2>📈 Next Steps</h2>
            <table>
                <thead>
                    <tr>
                        <th>Action Item</th>
                        <th>Owner</th>
                        <th>Timeline</th>
                        <th>Success Criteria</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Database Query Optimization</td>
                        <td>Backend Team</td>
                        <td>3 days</td>
                        <td>95th percentile query time < 100ms</td>
                    </tr>
                    <tr>
                        <td>Redis Cache Implementation</td>
                        <td>Platform Team</td>
                        <td>1 week</td>
                        <td>40% reduction in database queries</td>
                    </tr>
                    <tr>
                        <td>Resource Monitoring Setup</td>
                        <td>DevOps Team</td>
                        <td>2 days</td>
                        <td>Automated alerts for resource thresholds</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p><strong>Generated by iSECTECH Performance Engineering Framework</strong></p>
            <p>For detailed analysis data, see individual JSON files in the analysis output directory</p>
            <p>Next analysis recommended: $(date -d "+1 day" +"%Y-%m-%d")</p>
        </div>
    </div>
</body>
</html>
EOF
}

# Main execution logic
main() {
    # Default values
    START_TIME="1h ago"
    END_TIME="now"
    THRESHOLD_LEVEL="medium"
    OUTPUT_DIR="$PERFORMANCE_DIR/analysis"
    FORMAT="html"
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
            -t|--threshold)
                THRESHOLD_LEVEL="$2"
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
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            analyze-all|database|api|network|memory|cpu|correlate|generate-report)
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
        analyze-all)
            log_info "Running comprehensive bottleneck analysis..."
            analyze_database_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            analyze_api_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            analyze_system_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            correlate_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            generate_bottleneck_report "$OUTPUT_DIR" "$FORMAT" "$START_TIME" "$END_TIME"
            ;;
        database)
            analyze_database_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            ;;
        api)
            analyze_api_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            ;;
        network|memory|cpu)
            analyze_system_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            ;;
        correlate)
            correlate_bottlenecks "$START_TIME" "$END_TIME" "$THRESHOLD_LEVEL" "$OUTPUT_DIR"
            ;;
        generate-report)
            generate_bottleneck_report "$OUTPUT_DIR" "$FORMAT" "$START_TIME" "$END_TIME"
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