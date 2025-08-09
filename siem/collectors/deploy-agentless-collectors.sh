#!/bin/bash

# iSECTECH SIEM Agentless Collectors Deployment Script
# Production-ready deployment for agentless log collection infrastructure

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# SCRIPT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="/var/log/isectech-siem-agentless-deploy.log"
LOCK_FILE="/tmp/isectech-siem-agentless-deploy.lock"

# Default configuration
DEFAULT_MODE="production"
DEFAULT_TENANT_ID="isectech"
DEFAULT_KAFKA_ENDPOINTS="kafka-1.isectech.local:9092,kafka-2.isectech.local:9092,kafka-3.isectech.local:9092"
DEFAULT_ELASTICSEARCH_ENDPOINTS="elasticsearch-1.isectech.local:9200,elasticsearch-2.isectech.local:9200,elasticsearch-3.isectech.local:9200"
DEFAULT_REDIS_ENDPOINT="redis.isectech.local:6379"
DEFAULT_ENVIRONMENT="production"

# Configuration variables
DEPLOYMENT_MODE="${DEPLOYMENT_MODE:-$DEFAULT_MODE}"
TENANT_ID="${TENANT_ID:-$DEFAULT_TENANT_ID}"
KAFKA_ENDPOINTS="${KAFKA_ENDPOINTS:-$DEFAULT_KAFKA_ENDPOINTS}"
ELASTICSEARCH_ENDPOINTS="${ELASTICSEARCH_ENDPOINTS:-$DEFAULT_ELASTICSEARCH_ENDPOINTS}"
REDIS_ENDPOINT="${REDIS_ENDPOINT:-$DEFAULT_REDIS_ENDPOINT}"
ENVIRONMENT="${ENVIRONMENT:-$DEFAULT_ENVIRONMENT}"
VERBOSE=false
DRY_RUN=false
FORCE=false
SKIP_VALIDATION=false
COMPONENTS=""

# Service configuration
DOCKER_COMPOSE_FILE="docker-compose.agentless.yml"
DOCKER_NETWORK="isectech-siem"
MONITORING_NETWORK="monitoring"

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

info() {
    log "INFO" "$@"
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[INFO]${NC} $*" >&2
    fi
}

warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $*" >&2
}

debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        log "DEBUG" "$@"
        echo -e "${PURPLE}[DEBUG]${NC} $*" >&2
    fi
}

# Error handling
cleanup() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
    fi
}

error_exit() {
    error "$1"
    cleanup
    exit 1
}

# Lock management
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            error_exit "Another deployment is already running (PID: $lock_pid)"
        else
            warn "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root"
    fi
}

check_dependencies() {
    local deps=("docker" "docker-compose" "curl" "openssl" "jq")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing_deps[*]}"
        info "Installing missing dependencies..."
        
        # Install dependencies based on OS
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y "${missing_deps[@]}" curl openssl jq
        elif command -v yum &> /dev/null; then
            yum install -y "${missing_deps[@]}" curl openssl jq
        elif command -v dnf &> /dev/null; then
            dnf install -y "${missing_deps[@]}" curl openssl jq
        else
            error_exit "Unsupported package manager. Please install dependencies manually: ${missing_deps[*]}"
        fi
    fi
}

check_docker() {
    if ! systemctl is-active --quiet docker; then
        info "Starting Docker service..."
        systemctl start docker
        systemctl enable docker
    fi
    
    # Verify Docker is working
    if ! docker info &> /dev/null; then
        error_exit "Docker is not working properly"
    fi
    
    # Check Docker Compose version
    local compose_version
    if docker-compose --version &> /dev/null; then
        compose_version=$(docker-compose --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        debug "Docker Compose version: $compose_version"
    else
        error_exit "Docker Compose is not installed or not working"
    fi
}

validate_endpoints() {
    info "Validating endpoint connectivity..."
    
    # Validate Kafka endpoints
    IFS=',' read -ra KAFKA_HOSTS <<< "$KAFKA_ENDPOINTS"
    for kafka_host in "${KAFKA_HOSTS[@]}"; do
        local host=$(echo "$kafka_host" | cut -d':' -f1)
        local port=$(echo "$kafka_host" | cut -d':' -f2)
        
        if ! nc -z "$host" "$port" 2>/dev/null; then
            warn "Cannot connect to Kafka broker: $kafka_host"
        else
            debug "Kafka broker accessible: $kafka_host"
        fi
    done
    
    # Validate Elasticsearch endpoints
    IFS=',' read -ra ES_HOSTS <<< "$ELASTICSEARCH_ENDPOINTS"
    for es_host in "${ES_HOSTS[@]}"; do
        local host=$(echo "$es_host" | cut -d':' -f1)
        local port=$(echo "$es_host" | cut -d':' -f2)
        
        if ! nc -z "$host" "$port" 2>/dev/null; then
            warn "Cannot connect to Elasticsearch: $es_host"
        else
            debug "Elasticsearch accessible: $es_host"
        fi
    done
    
    # Validate Redis endpoint
    local redis_host=$(echo "$REDIS_ENDPOINT" | cut -d':' -f1)
    local redis_port=$(echo "$REDIS_ENDPOINT" | cut -d':' -f2)
    
    if ! nc -z "$redis_host" "$redis_port" 2>/dev/null; then
        warn "Cannot connect to Redis: $REDIS_ENDPOINT"
    else
        debug "Redis accessible: $REDIS_ENDPOINT"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

generate_certificates() {
    local cert_dir="$SCRIPT_DIR/certs"
    
    if [[ -d "$cert_dir" ]] && [[ "$FORCE" != "true" ]]; then
        info "Certificates already exist. Use --force to regenerate."
        return 0
    fi
    
    info "Generating TLS certificates..."
    mkdir -p "$cert_dir"
    
    # Generate CA certificate
    openssl genrsa -out "$cert_dir/ca.key" 4096
    openssl req -new -x509 -days 3650 -key "$cert_dir/ca.key" -out "$cert_dir/ca.crt" -subj "/C=US/ST=California/L=San Francisco/O=iSECTECH/OU=SIEM/CN=iSECTECH-SIEM-CA"
    
    # Generate server certificate
    openssl genrsa -out "$cert_dir/server.key" 4096
    openssl req -new -key "$cert_dir/server.key" -out "$cert_dir/server.csr" -subj "/C=US/ST=California/L=San Francisco/O=iSECTECH/OU=SIEM/CN=*.isectech.local"
    
    # Create extensions file for SAN
    cat > "$cert_dir/extensions.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = *.isectech.local
DNS.2 = syslog-collector.isectech.local
DNS.3 = snmp-collector.isectech.local
DNS.4 = flow-collector.isectech.local
DNS.5 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Sign server certificate
    openssl x509 -req -days 365 -in "$cert_dir/server.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial -out "$cert_dir/server.crt" -extensions v3_req -extfile "$cert_dir/extensions.conf"
    
    # Set appropriate permissions
    chmod 600 "$cert_dir"/*.key
    chmod 644 "$cert_dir"/*.crt
    
    success "TLS certificates generated successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

generate_configurations() {
    info "Generating service configurations..."
    
    # Generate Redis configuration
    cat > "$SCRIPT_DIR/redis.conf" << EOF
# iSECTECH SIEM Redis Configuration
# Production settings for agentless collectors cache

# Network configuration
bind 0.0.0.0
port 6379
tcp-backlog 511
timeout 0
tcp-keepalive 300

# General configuration
daemonize no
supervised no
pidfile /var/run/redis.pid
loglevel notice
logfile ""
databases 16
always-show-logo yes

# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru
maxmemory-samples 5

# Persistence
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /data

# Security
requirepass ${REDIS_PASSWORD:-isectech_siem_cache_2024}

# Performance
hash-max-ziplist-entries 512
hash-max-ziplist-value 64
list-max-ziplist-size -2
list-compress-depth 0
set-max-intset-entries 512
zset-max-ziplist-entries 128
zset-max-ziplist-value 64
hll-sparse-max-bytes 3000
stream-node-max-bytes 4096
stream-node-max-entries 100

# Slow log
slowlog-log-slower-than 10000
slowlog-max-len 128

# Latency monitoring
latency-monitor-threshold 100

# Event notification
notify-keyspace-events ""

# Advanced configuration
client-output-buffer-limit normal 0 0 0
client-output-buffer-limit replica 256mb 64mb 60
client-output-buffer-limit pubsub 32mb 8mb 60
client-query-buffer-limit 1gb
proto-max-bulk-len 512mb

# High frequency writes optimization
hz 10
dynamic-hz yes
aof-rewrite-incremental-fsync yes
rdb-save-incremental-fsync yes
EOF

    # Generate Fluent Bit configuration
    cat > "$SCRIPT_DIR/fluent-bit.conf" << EOF
[SERVICE]
    Flush         5
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf
    HTTP_Server   On
    HTTP_Listen   0.0.0.0
    HTTP_Port     2020
    Health_Check  On

[INPUT]
    Name              tail
    Tag               agentless.syslog
    Path              /var/log/siem/syslog-receiver.log
    Parser            syslog
    DB                /var/lib/fluent-bit/syslog.db
    Mem_Buf_Limit     50MB
    Skip_Long_Lines   On
    Refresh_Interval  10

[INPUT]
    Name              tail
    Tag               agentless.snmp
    Path              /var/log/siem/snmp-collector.log
    Parser            json
    DB                /var/lib/fluent-bit/snmp.db
    Mem_Buf_Limit     50MB
    Skip_Long_Lines   On
    Refresh_Interval  10

[INPUT]
    Name              tail
    Tag               agentless.flow
    Path              /var/log/siem/flow-collector.log
    Parser            json
    DB                /var/lib/fluent-bit/flow.db
    Mem_Buf_Limit     50MB
    Skip_Long_Lines   On
    Refresh_Interval  10

[FILTER]
    Name              modify
    Match             agentless.*
    Add               tenant_id $TENANT_ID
    Add               environment $ENVIRONMENT
    Add               collector_type agentless
    Add               timestamp \${time}

[OUTPUT]
    Name              kafka
    Match             agentless.*
    Brokers           $KAFKA_ENDPOINTS
    Topics            agentless-logs
    Timestamp_Key     timestamp
    Retry_Limit       3
    rdkafka.compression.type gzip
    rdkafka.batch.num.messages 1000
    rdkafka.queue.buffering.max.ms 1000

[OUTPUT]
    Name              elasticsearch
    Match             agentless.*
    Host              $(echo $ELASTICSEARCH_ENDPOINTS | cut -d',' -f1 | cut -d':' -f1)
    Port              $(echo $ELASTICSEARCH_ENDPOINTS | cut -d',' -f1 | cut -d':' -f2)
    Index             agentless-logs
    Type              _doc
    Logstash_Format   On
    Logstash_Prefix   agentless
    Logstash_DateFormat %Y.%m.%d
    Include_Tag_Key   On
    Tag_Key           source
    Retry_Limit       3
EOF

    # Generate SNMP collector configuration
    cat > "$SCRIPT_DIR/snmp-collector.yaml" << EOF
# iSECTECH SIEM SNMP Collector Configuration

collector:
  worker_threads: 20
  batch_size: 100
  collection_timeout: 30
  retry_interval: 60
  metrics_port: 9161

kafka:
  bootstrap_servers:
$(IFS=','; for host in $KAFKA_ENDPOINTS; do echo "    - \"$host\""; done)
  topic: "snmp-metrics"
  batch_size: 1000
  linger_ms: 1000
  compression_type: "gzip"

redis:
  host: "$(echo $REDIS_ENDPOINT | cut -d':' -f1)"
  port: $(echo $REDIS_ENDPOINT | cut -d':' -f2)
  db: 2
  password: "${REDIS_PASSWORD:-isectech_siem_cache_2024}"

logging:
  level: "INFO"
  format: "json"

# Device configurations (loaded from database in production)
devices:
  - hostname: "core-switch-01.isectech.local"
    ip_address: "10.0.1.10"
    community: "isectech_readonly"
    version: "2c"
    device_type: "switch"
    vendor: "cisco"
    model: "catalyst-9300"
    criticality: "high"
    polling_interval: 300
    security_monitoring: true
    tags: ["core", "production", "network"]
  
  - hostname: "firewall-01.isectech.local"
    ip_address: "10.0.1.1"
    community: "isectech_readonly"
    version: "2c"
    device_type: "firewall"
    vendor: "cisco"
    model: "asa-5516"
    criticality: "critical"
    polling_interval: 60
    security_monitoring: true
    tags: ["perimeter", "security", "production"]
EOF

    # Generate flow collector configuration
    cat > "$SCRIPT_DIR/flow-collector.yaml" << EOF
# iSECTECH SIEM Flow Collector Configuration

collector:
  netflow_port: 2055
  sflow_port: 6343
  ipfix_port: 4739
  metrics_port: 9162
  workers: 10
  buffer_size: 1000000
  batch_size: 1000

kafka:
  brokers:
$(IFS=','; for host in $KAFKA_ENDPOINTS; do echo "    - \"$host\""; done)
  topic: "network-flows"
  compression: "gzip"
  batch_timeout: "1s"
  max_message_bytes: 1000000

redis:
  host: "$(echo $REDIS_ENDPOINT | cut -d':' -f1)"
  port: $(echo $REDIS_ENDPOINT | cut -d':' -f2)
  db: 3
  password: "${REDIS_PASSWORD:-isectech_siem_cache_2024}"

security:
  enable_ddos_detection: true
  enable_beaconing_detection: true
  enable_port_scan_detection: true
  anomaly_threshold: 1000
  alert_threshold: 500

logging:
  level: "INFO"
  format: "json"
  file: "/var/log/siem/flow-collector.log"
EOF

    success "Service configurations generated successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOCKER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

setup_docker_networks() {
    info "Setting up Docker networks..."
    
    # Create SIEM network
    if ! docker network ls | grep -q "$DOCKER_NETWORK"; then
        docker network create \
            --driver bridge \
            --subnet=172.20.0.0/16 \
            --gateway=172.20.0.1 \
            --opt com.docker.network.bridge.name=isectech-siem \
            "$DOCKER_NETWORK"
        success "Created Docker network: $DOCKER_NETWORK"
    else
        debug "Docker network already exists: $DOCKER_NETWORK"
    fi
    
    # Create monitoring network
    if ! docker network ls | grep -q "$MONITORING_NETWORK"; then
        docker network create \
            --driver bridge \
            --subnet=172.21.0.0/16 \
            --gateway=172.21.0.1 \
            --opt com.docker.network.bridge.name=monitoring \
            "$MONITORING_NETWORK"
        success "Created Docker network: $MONITORING_NETWORK"
    else
        debug "Docker network already exists: $MONITORING_NETWORK"
    fi
}

build_docker_images() {
    info "Building Docker images..."
    
    # Create Dockerfiles for custom services
    
    # SNMP Collector Dockerfile
    cat > "$SCRIPT_DIR/Dockerfile.snmp" << 'EOF'
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libsnmp-dev \
    snmp-mibs-downloader \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-snmp.txt .
RUN pip install --no-cache-dir -r requirements-snmp.txt

COPY snmp-collector.py .

USER nobody

EXPOSE 9161

CMD ["python3", "snmp-collector.py"]
EOF

    # Flow Collector Dockerfile
    cat > "$SCRIPT_DIR/Dockerfile.flow" << 'EOF'
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY network-flow-collector.go .
COPY go.mod .
COPY go.sum .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o flow-collector .

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /app/flow-collector .

USER nobody

EXPOSE 2055/udp 6343/udp 4739/udp 4739/tcp 9162/tcp

CMD ["./flow-collector"]
EOF

    # Create requirements files
    cat > "$SCRIPT_DIR/requirements-snmp.txt" << EOF
asyncio
asyncpg==0.29.0
kafka-python==2.0.2
pysnmp==4.4.12
prometheus-client==0.19.0
redis==5.0.1
structlog==23.2.0
pyyaml==6.0.1
EOF

    # Build images if they don't exist
    if [[ "$DRY_RUN" != "true" ]]; then
        if [[ -z "$(docker images -q isectech/snmp-collector:latest 2> /dev/null)" ]]; then
            docker build -t isectech/snmp-collector:latest -f Dockerfile.snmp .
        fi
        
        if [[ -z "$(docker images -q isectech/flow-collector:latest 2> /dev/null)" ]]; then
            docker build -t isectech/flow-collector:latest -f Dockerfile.flow .
        fi
    fi
    
    success "Docker images built successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

deploy_services() {
    info "Deploying agentless collectors..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN: Would deploy services with docker-compose"
        return 0
    fi
    
    # Stop existing services if running
    if docker-compose -f "$DOCKER_COMPOSE_FILE" ps | grep -q "Up"; then
        info "Stopping existing services..."
        docker-compose -f "$DOCKER_COMPOSE_FILE" down
    fi
    
    # Deploy services
    docker-compose -f "$DOCKER_COMPOSE_FILE" up -d
    
    # Wait for services to start
    info "Waiting for services to start..."
    sleep 30
    
    # Verify deployment
    verify_deployment
}

verify_deployment() {
    info "Verifying deployment..."
    
    local services=("syslog-receiver" "snmp-collector" "flow-collector" "redis-cache")
    local failed_services=()
    
    for service in "${services[@]}"; do
        if ! docker-compose -f "$DOCKER_COMPOSE_FILE" ps "$service" | grep -q "Up"; then
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        error "Failed services: ${failed_services[*]}"
        return 1
    fi
    
    # Test service endpoints
    local endpoints=(
        "localhost:514:syslog UDP"
        "localhost:9161:SNMP metrics"
        "localhost:9162:Flow metrics"
        "localhost:6379:Redis cache"
    )
    
    for endpoint in "${endpoints[@]}"; do
        local host=$(echo "$endpoint" | cut -d':' -f1)
        local port=$(echo "$endpoint" | cut -d':' -f2)
        local service=$(echo "$endpoint" | cut -d':' -f3)
        
        if nc -z "$host" "$port" 2>/dev/null; then
            success "$service endpoint accessible: $host:$port"
        else
            warn "$service endpoint not accessible: $host:$port"
        fi
    done
    
    success "Deployment verification completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Deploy iSECTECH SIEM agentless collectors

OPTIONS:
    -m, --mode MODE              Deployment mode (production|staging|development) [default: $DEFAULT_MODE]
    -t, --tenant-id ID           Tenant identifier [default: $DEFAULT_TENANT_ID]
    -k, --kafka ENDPOINTS        Kafka broker endpoints [default: $DEFAULT_KAFKA_ENDPOINTS]
    -e, --elasticsearch ENDPOINTS Elasticsearch endpoints [default: $DEFAULT_ELASTICSEARCH_ENDPOINTS]
    -r, --redis ENDPOINT         Redis endpoint [default: $DEFAULT_REDIS_ENDPOINT]
    --environment ENV            Environment name [default: $DEFAULT_ENVIRONMENT]
    -c, --components COMPONENTS  Components to deploy (comma-separated)
    -v, --verbose                Enable verbose output
    -d, --dry-run                Show what would be done without executing
    -f, --force                  Force regeneration of certificates and configs
    --skip-validation            Skip endpoint validation
    -h, --help                   Show this help message

EXAMPLES:
    # Basic deployment
    $SCRIPT_NAME

    # Production deployment with custom settings
    $SCRIPT_NAME --mode production --tenant-id mycompany --verbose

    # Deploy specific components only
    $SCRIPT_NAME --components syslog-receiver,snmp-collector

    # Dry run to see what would be deployed
    $SCRIPT_NAME --dry-run --verbose

COMPONENTS:
    syslog-receiver    Network device syslog collection
    snmp-collector     SNMP monitoring and metrics
    flow-collector     NetFlow/sFlow/IPFIX collection
    redis-cache        Redis caching service
    log-aggregator     Fluent Bit log aggregation
    monitoring         Prometheus monitoring

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -t|--tenant-id)
                TENANT_ID="$2"
                shift 2
                ;;
            -k|--kafka)
                KAFKA_ENDPOINTS="$2"
                shift 2
                ;;
            -e|--elasticsearch)
                ELASTICSEARCH_ENDPOINTS="$2"
                shift 2
                ;;
            -r|--redis)
                REDIS_ENDPOINT="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -c|--components)
                COMPONENTS="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                VERBOSE=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            --skip-validation)
                SKIP_VALIDATION=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

main() {
    # Setup
    acquire_lock
    trap cleanup EXIT
    
    # Initialize logging
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    info "Starting iSECTECH SIEM agentless collectors deployment"
    info "Mode: $DEPLOYMENT_MODE, Tenant: $TENANT_ID, Environment: $ENVIRONMENT"
    
    # Validation
    check_root
    check_dependencies
    check_docker
    
    if [[ "$SKIP_VALIDATION" != "true" ]]; then
        validate_endpoints
    fi
    
    # Preparation
    cd "$SCRIPT_DIR"
    generate_certificates
    generate_configurations
    setup_docker_networks
    build_docker_images
    
    # Deployment
    if [[ "$DRY_RUN" != "true" ]]; then
        deploy_services
        success "Agentless collectors deployed successfully"
        
        info "Deployment Summary:"
        info "- Services: $(docker-compose -f "$DOCKER_COMPOSE_FILE" ps --services | tr '\n' ' ')"
        info "- Networks: $DOCKER_NETWORK, $MONITORING_NETWORK"
        info "- Configuration: $SCRIPT_DIR"
        info "- Logs: $LOG_FILE"
        
        info "Management Commands:"
        info "- Status: docker-compose -f $DOCKER_COMPOSE_FILE ps"
        info "- Logs: docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
        info "- Stop: docker-compose -f $DOCKER_COMPOSE_FILE down"
        info "- Restart: docker-compose -f $DOCKER_COMPOSE_FILE restart"
    else
        info "DRY RUN completed successfully"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCRIPT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

parse_arguments "$@"
main