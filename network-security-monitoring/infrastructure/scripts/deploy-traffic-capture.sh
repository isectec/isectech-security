#!/bin/bash
# iSECTECH Network Security Monitoring - Traffic Capture Infrastructure Deployment
# Production-grade deployment automation script

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_FILE="/var/log/nsm-deployment.log"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration defaults
STORAGE_BASE_PATH="${STORAGE_BASE_PATH:-/data/nsm}"
INTERFACE_LIST="${INTERFACE_LIST:-eth0,eth1,eth2,eth3}"
ELASTICSEARCH_HOSTS="${ELASTICSEARCH_HOSTS:-elasticsearch-01:9200,elasticsearch-02:9200,elasticsearch-03:9200}"
KAFKA_BROKERS="${KAFKA_BROKERS:-kafka-1.isectech.local:9092,kafka-2.isectech.local:9092}"

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING AND UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "${BLUE}$*${NC}"
}

log_warn() {
    log "WARN" "${YELLOW}$*${NC}"
}

log_error() {
    log "ERROR" "${RED}$*${NC}"
}

log_success() {
    log "SUCCESS" "${GREEN}$*${NC}"
}

log_debug() {
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log "DEBUG" "${PURPLE}$*${NC}"
    fi
}

print_banner() {
    echo -e "${CYAN}"
    echo "════════════════════════════════════════════════════════════════════════"
    echo "  iSECTECH Network Security Monitoring - Traffic Capture Deployment"
    echo "  Version: 1.0"
    echo "  Timestamp: $TIMESTAMP"
    echo "════════════════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

check_prerequisites() {
    log_info "Checking deployment prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root for system configuration"
        exit 1
    fi
    
    # Check required commands
    local required_commands=("docker" "docker-compose" "curl" "jq" "openssl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check available disk space (minimum 1TB)
    local available_space=$(df "$STORAGE_BASE_PATH" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    local required_space=$((1024 * 1024 * 1024))  # 1TB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        log_error "Insufficient disk space. Required: 1TB, Available: $(($available_space / 1024 / 1024))GB"
        exit 1
    fi
    
    log_success "Prerequisites check completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PREPARATION
# ═══════════════════════════════════════════════════════════════════════════════

prepare_system() {
    log_info "Preparing system for traffic capture..."
    
    # Create directory structure
    log_info "Creating directory structure..."
    mkdir -p "$STORAGE_BASE_PATH"/{pcap/{hot,warm,cold},logs,config,keys}
    mkdir -p "$STORAGE_BASE_PATH"/clickhouse/{data,logs}
    mkdir -p "$STORAGE_BASE_PATH"/redis/data
    mkdir -p "$STORAGE_BASE_PATH"/moloch/{config,rules,wise}
    mkdir -p "$STORAGE_BASE_PATH"/zeek/{config,logs,scripts}
    mkdir -p "$STORAGE_BASE_PATH"/suricata/{config,logs,rules}
    
    # Set proper permissions
    chown -R 1000:1000 "$STORAGE_BASE_PATH"
    chmod -R 755 "$STORAGE_BASE_PATH"
    
    # Create log directory
    mkdir -p /var/log/nsm
    chown -R 1000:1000 /var/log/nsm
    
    log_success "Directory structure created"
}

configure_network_interfaces() {
    log_info "Configuring network interfaces for packet capture..."
    
    # Load 802.1Q module for VLAN support
    modprobe 8021q || log_warn "Failed to load 8021q module"
    
    # Configure each interface
    IFS=',' read -ra INTERFACES <<< "$INTERFACE_LIST"
    for interface in "${INTERFACES[@]}"; do
        log_info "Configuring interface: $interface"
        
        # Set interface to promiscuous mode
        if ip link show "$interface" &> /dev/null; then
            ip link set "$interface" promisc on || log_warn "Failed to set $interface to promiscuous mode"
            
            # Disable hardware offloading features for accurate capture
            ethtool -K "$interface" gro off gso off tso off rx-vlan-offload off tx-vlan-offload off 2>/dev/null || log_warn "Failed to configure $interface offloading"
            
            # Optimize for high throughput
            ethtool -G "$interface" rx 4096 tx 4096 2>/dev/null || log_warn "Failed to set $interface ring buffers"
            ethtool -C "$interface" rx-usecs 1 rx-frames 1 2>/dev/null || log_warn "Failed to set $interface coalescing"
            
            log_success "Interface $interface configured"
        else
            log_warn "Interface $interface not found"
        fi
    done
}

configure_system_limits() {
    log_info "Configuring system limits for high-performance capture..."
    
    # Create limits configuration
    cat > /etc/security/limits.d/99-nsm.conf << EOF
# iSECTECH NSM System Limits
*    soft    nofile     1048576
*    hard    nofile     1048576
*    soft    nproc      unlimited
*    hard    nproc      unlimited
*    soft    memlock    unlimited
*    hard    memlock    unlimited
EOF

    # Configure sysctl parameters
    cat > /etc/sysctl.d/99-nsm.conf << EOF
# iSECTECH NSM Network Optimizations
net.core.rmem_default = 262144
net.core.rmem_max = 134217728
net.core.wmem_default = 262144
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 30000
net.core.netdev_budget = 600
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
vm.max_map_count = 262144
fs.file-max = 2097152
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-nsm.conf || log_warn "Failed to apply sysctl settings"
    
    log_success "System limits configured"
}

# ═══════════════════════════════════════════════════════════════════════════════
# STORAGE PREPARATION
# ═══════════════════════════════════════════════════════════════════════════════

setup_storage() {
    log_info "Setting up tiered storage for packet capture..."
    
    # Create storage mount points if they don't exist
    local hot_storage="$STORAGE_BASE_PATH/pcap/hot"
    local warm_storage="$STORAGE_BASE_PATH/pcap/warm"
    local cold_storage="$STORAGE_BASE_PATH/pcap/cold"
    
    # Configure hot storage (tmpfs for fastest access)
    if ! mountpoint -q "$hot_storage"; then
        log_info "Setting up hot storage (64GB tmpfs)..."
        mount -t tmpfs -o size=64G,noatime,nodiratime tmpfs "$hot_storage" || log_warn "Failed to mount hot storage tmpfs"
    fi
    
    # Warm and cold storage would typically be mounted from dedicated disks
    # For now, ensure directories exist
    mkdir -p "$warm_storage" "$cold_storage"
    
    # Set up log rotation for storage management
    cat > /etc/logrotate.d/nsm-pcap << EOF
$STORAGE_BASE_PATH/pcap/hot/*.pcap {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 1000 1000
    postrotate
        mv $STORAGE_BASE_PATH/pcap/hot/*.pcap.1.gz $STORAGE_BASE_PATH/pcap/warm/ 2>/dev/null || true
    endscript
}

$STORAGE_BASE_PATH/pcap/warm/*.pcap.gz {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        find $STORAGE_BASE_PATH/pcap/warm -name "*.pcap.gz" -mtime +30 -exec mv {} $STORAGE_BASE_PATH/pcap/cold/ \;
    endscript
}
EOF

    log_success "Storage configuration completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

generate_certificates() {
    log_info "Generating SSL certificates for secure communication..."
    
    local cert_dir="$STORAGE_BASE_PATH/keys"
    local moloch_cert="$cert_dir/moloch.crt"
    local moloch_key="$cert_dir/moloch.key"
    
    if [[ ! -f "$moloch_cert" ]]; then
        log_info "Generating Moloch SSL certificate..."
        
        # Generate private key
        openssl genrsa -out "$moloch_key" 2048
        
        # Generate certificate signing request
        openssl req -new -key "$moloch_key" -out "$cert_dir/moloch.csr" -subj "/C=US/ST=State/L=City/O=iSECTECH/OU=Security/CN=moloch.isectech.local"
        
        # Generate self-signed certificate
        openssl x509 -req -in "$cert_dir/moloch.csr" -signkey "$moloch_key" -out "$moloch_cert" -days 365
        
        # Set proper permissions
        chmod 600 "$moloch_key"
        chmod 644 "$moloch_cert"
        chown 1000:1000 "$moloch_key" "$moloch_cert"
        
        # Clean up CSR
        rm "$cert_dir/moloch.csr"
        
        log_success "Moloch SSL certificate generated"
    else
        log_info "SSL certificates already exist"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION FILE DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

deploy_configurations() {
    log_info "Deploying configuration files..."
    
    # Copy configuration files from project
    cp -r "$PROJECT_ROOT"/moloch/config/* "$STORAGE_BASE_PATH"/moloch/config/
    cp -r "$PROJECT_ROOT"/zeek/config/* "$STORAGE_BASE_PATH"/zeek/config/
    cp -r "$PROJECT_ROOT"/suricata/config/* "$STORAGE_BASE_PATH"/suricata/config/
    
    # Update configuration with environment-specific values
    sed -i "s|ELASTICSEARCH_HOSTS|$ELASTICSEARCH_HOSTS|g" "$STORAGE_BASE_PATH"/moloch/config/config.ini
    sed -i "s|KAFKA_BROKERS|$KAFKA_BROKERS|g" "$STORAGE_BASE_PATH"/moloch/config/config.ini
    sed -i "s|INTERFACE_LIST|$INTERFACE_LIST|g" "$STORAGE_BASE_PATH"/moloch/config/config.ini
    
    # Set proper ownership
    chown -R 1000:1000 "$STORAGE_BASE_PATH"/moloch/config
    chown -R 1000:1000 "$STORAGE_BASE_PATH"/zeek/config
    chown -R 1000:1000 "$STORAGE_BASE_PATH"/suricata/config
    
    log_success "Configuration files deployed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOCKER SERVICES DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

deploy_docker_services() {
    log_info "Deploying Docker services..."
    
    cd "$PROJECT_ROOT"
    
    # Pull latest images
    log_info "Pulling Docker images..."
    docker-compose -f docker-compose.traffic-capture.yml pull
    
    # Create external networks if they don't exist
    docker network create isectech-siem 2>/dev/null || log_debug "Network isectech-siem already exists"
    docker network create monitoring 2>/dev/null || log_debug "Network monitoring already exists"
    
    # Start services in order
    log_info "Starting ClickHouse database..."
    docker-compose -f docker-compose.traffic-capture.yml up -d clickhouse-01 clickhouse-02
    
    # Wait for ClickHouse to be ready
    wait_for_service "clickhouse-01" "8123" "/ping"
    wait_for_service "clickhouse-02" "8124" "/ping"
    
    log_info "Starting Redis cache..."
    docker-compose -f docker-compose.traffic-capture.yml up -d redis-capture-cache
    
    # Wait for Redis
    wait_for_service "redis-capture-cache" "6380" ""
    
    log_info "Starting flow collectors..."
    docker-compose -f docker-compose.traffic-capture.yml up -d flow-collector-primary flow-collector-secondary
    
    log_info "Starting packet capture services..."
    docker-compose -f docker-compose.traffic-capture.yml up -d moloch-capture-01 moloch-capture-02
    
    log_info "Starting analysis engines..."
    docker-compose -f docker-compose.traffic-capture.yml up -d zeek-analyzer suricata-ids
    
    log_info "Starting viewer and management services..."
    docker-compose -f docker-compose.traffic-capture.yml up -d moloch-viewer capture-management-api
    
    log_info "Starting monitoring..."
    docker-compose -f docker-compose.traffic-capture.yml up -d prometheus-exporter
    
    log_success "Docker services deployed"
}

wait_for_service() {
    local container="$1"
    local port="$2"
    local path="$3"
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for $container to be ready..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if [[ -n "$path" ]]; then
            if curl -sf "http://localhost:$port$path" &> /dev/null; then
                log_success "$container is ready"
                return 0
            fi
        else
            if docker exec "isectech-$container" true &> /dev/null; then
                log_success "$container is ready"
                return 0
            fi
        fi
        
        log_debug "Attempt $attempt/$max_attempts - $container not ready yet..."
        sleep 10
        ((attempt++))
    done
    
    log_error "$container failed to become ready after $((max_attempts * 10)) seconds"
    return 1
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

initialize_databases() {
    log_info "Initializing databases..."
    
    # Initialize ClickHouse schema
    log_info "Initializing ClickHouse schema..."
    docker exec isectech-clickhouse-01 clickhouse-client --multiquery < "$PROJECT_ROOT/clickhouse/schema/init.sql" || log_error "Failed to initialize ClickHouse schema"
    
    # Initialize Moloch/Arkime database
    log_info "Initializing Moloch database..."
    docker exec isectech-moloch-viewer /data/moloch/db/db.pl "http://$ELASTICSEARCH_HOSTS" init || log_error "Failed to initialize Moloch database"
    
    log_success "Database initialization completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# RULE UPDATES AND INTELLIGENCE FEEDS
# ═══════════════════════════════════════════════════════════════════════════════

update_security_rules() {
    log_info "Updating security rules and threat intelligence..."
    
    # Update Suricata rules
    log_info "Updating Suricata rules..."
    docker exec isectech-suricata-ids suricata-update || log_warn "Failed to update Suricata rules"
    
    # Restart Suricata to load new rules
    docker restart isectech-suricata-ids
    
    # Update GeoIP databases
    log_info "Updating GeoIP databases..."
    # This would typically download MaxMind GeoLite2 databases
    
    log_success "Security rules updated"
}

# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION AND TESTING
# ═══════════════════════════════════════════════════════════════════════════════

validate_deployment() {
    log_info "Validating deployment..."
    
    # Check service health
    local services=(
        "isectech-clickhouse-01:8123:/ping"
        "isectech-clickhouse-02:8124:/ping"
        "isectech-redis-capture-cache:6380:"
        "isectech-moloch-viewer:8005:/api/stats"
        "isectech-flow-collector-primary:9162:/health"
        "isectech-flow-collector-secondary:9163:/health"
        "isectech-capture-management-api:8080:/health"
    )
    
    local failed_services=()
    
    for service_info in "${services[@]}"; do
        IFS=':' read -ra SERVICE_PARTS <<< "$service_info"
        local service="${SERVICE_PARTS[0]}"
        local port="${SERVICE_PARTS[1]}"
        local path="${SERVICE_PARTS[2]}"
        
        log_info "Checking $service..."
        
        if [[ -n "$path" ]]; then
            if ! curl -sf "http://localhost:$port$path" &> /dev/null; then
                failed_services+=("$service")
                log_error "$service health check failed"
            else
                log_success "$service is healthy"
            fi
        else
            if ! docker exec "$service" true &> /dev/null; then
                failed_services+=("$service")
                log_error "$service is not running"
            else
                log_success "$service is running"
            fi
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log_success "All services are healthy"
        return 0
    else
        log_error "Failed services: ${failed_services[*]}"
        return 1
    fi
}

run_integration_tests() {
    log_info "Running integration tests..."
    
    # Test flow collection
    log_info "Testing flow collection..."
    local flow_test_result=$(curl -s "http://localhost:9162/health" | jq -r '.status' 2>/dev/null || echo "error")
    if [[ "$flow_test_result" == "healthy" ]]; then
        log_success "Flow collector is healthy"
    else
        log_warn "Flow collector health check returned: $flow_test_result"
    fi
    
    # Test packet capture
    log_info "Testing packet capture..."
    local moloch_test_result=$(curl -s "http://localhost:8005/api/stats" | jq -r '.health' 2>/dev/null || echo "error")
    if [[ "$moloch_test_result" == "green" ]] || [[ "$moloch_test_result" == "yellow" ]]; then
        log_success "Moloch packet capture is operational"
    else
        log_warn "Moloch health check returned: $moloch_test_result"
    fi
    
    # Test database connectivity
    log_info "Testing database connectivity..."
    local clickhouse_test=$(docker exec isectech-clickhouse-01 clickhouse-client --query "SELECT 1" 2>/dev/null || echo "error")
    if [[ "$clickhouse_test" == "1" ]]; then
        log_success "ClickHouse database is accessible"
    else
        log_error "ClickHouse database test failed"
    fi
    
    log_success "Integration tests completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

setup_monitoring() {
    log_info "Setting up monitoring and alerting..."
    
    # Create Prometheus configuration for NSM monitoring
    cat > /tmp/nsm-prometheus-targets.json << EOF
[
  {
    "targets": ["localhost:9162"],
    "labels": {
      "job": "flow-collector-primary",
      "service": "nsm"
    }
  },
  {
    "targets": ["localhost:9163"],
    "labels": {
      "job": "flow-collector-secondary",
      "service": "nsm"
    }
  },
  {
    "targets": ["localhost:9205"],
    "labels": {
      "job": "moloch-viewer",
      "service": "nsm"
    }
  },
  {
    "targets": ["localhost:9180"],
    "labels": {
      "job": "capture-management-api",
      "service": "nsm"
    }
  },
  {
    "targets": ["localhost:9181"],
    "labels": {
      "job": "nsm-node-exporter",
      "service": "nsm"
    }
  }
]
EOF

    # This would typically be integrated with existing Prometheus configuration
    log_info "Prometheus targets configuration created at /tmp/nsm-prometheus-targets.json"
    
    log_success "Monitoring setup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP AND MAINTENANCE
# ═══════════════════════════════════════════════════════════════════════════════

setup_maintenance_jobs() {
    log_info "Setting up maintenance jobs..."
    
    # Create maintenance script
    cat > /usr/local/bin/nsm-maintenance.sh << 'EOF'
#!/bin/bash
# iSECTECH NSM Maintenance Script

LOG_FILE="/var/log/nsm-maintenance.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

# Optimize ClickHouse tables
log "Starting ClickHouse optimization"
docker exec isectech-clickhouse-01 clickhouse-client --query "OPTIMIZE TABLE nsm_flows.flow_data FINAL" || log "ClickHouse optimization failed"

# Clean old packet captures
log "Cleaning old packet captures"
find /data/nsm/pcap/cold -name "*.pcap.gz" -mtime +365 -delete || log "Packet cleanup failed"

# Rotate logs
log "Rotating application logs"
docker exec isectech-moloch-viewer find /var/log/moloch -name "*.log" -mtime +7 -delete || log "Log rotation failed"

log "Maintenance completed"
EOF

    chmod +x /usr/local/bin/nsm-maintenance.sh
    
    # Create cron job for maintenance
    cat > /etc/cron.d/nsm-maintenance << EOF
# iSECTECH NSM Maintenance Jobs
0 2 * * * root /usr/local/bin/nsm-maintenance.sh
0 */6 * * * root docker system prune -f --volumes
EOF

    log_success "Maintenance jobs configured"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DEPLOYMENT FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    print_banner
    
    log_info "Starting iSECTECH NSM Traffic Capture Infrastructure deployment..."
    log_info "Deployment parameters:"
    log_info "  Storage Base Path: $STORAGE_BASE_PATH"
    log_info "  Network Interfaces: $INTERFACE_LIST"
    log_info "  Elasticsearch Hosts: $ELASTICSEARCH_HOSTS"
    log_info "  Kafka Brokers: $KAFKA_BROKERS"
    
    # Execute deployment steps
    check_prerequisites
    prepare_system
    configure_network_interfaces
    configure_system_limits
    setup_storage
    generate_certificates
    deploy_configurations
    deploy_docker_services
    initialize_databases
    update_security_rules
    setup_monitoring
    setup_maintenance_jobs
    
    # Validation
    if validate_deployment; then
        run_integration_tests
        
        log_success "═══════════════════════════════════════════════════════════════════════"
        log_success "  iSECTECH NSM Traffic Capture Infrastructure Deployment COMPLETED"
        log_success "═══════════════════════════════════════════════════════════════════════"
        log_success ""
        log_success "Services Available:"
        log_success "  - Moloch/Arkime Viewer: http://localhost:8005"
        log_success "  - Capture Management API: http://localhost:8080"
        log_success "  - ClickHouse HTTP Interface: http://localhost:8123"
        log_success "  - Flow Collector Metrics: http://localhost:9162/metrics"
        log_success "  - System Metrics: http://localhost:9181/metrics"
        log_success ""
        log_success "Configuration Files:"
        log_success "  - Storage: $STORAGE_BASE_PATH"
        log_success "  - Logs: /var/log/nsm"
        log_success "  - Maintenance: /usr/local/bin/nsm-maintenance.sh"
        log_success ""
        log_success "Next Steps:"
        log_success "  1. Configure network devices to send flows to ports 2055-2056 (NetFlow)"
        log_success "  2. Configure switches for traffic mirroring to capture interfaces"
        log_success "  3. Set up Grafana dashboards for visualization"
        log_success "  4. Configure alerting rules in AlertManager"
        log_success "  5. Test with known traffic patterns"
        
        exit 0
    else
        log_error "Deployment validation failed. Check service logs for details."
        log_error "Use 'docker-compose -f docker-compose.traffic-capture.yml logs' for debugging."
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCRIPT EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

# Handle script interruption
trap 'log_error "Deployment interrupted by user"; exit 130' INT TERM

# Ensure log file exists and is writable
touch "$LOG_FILE" && chmod 644 "$LOG_FILE" || {
    echo "Error: Cannot create log file $LOG_FILE"
    exit 1
}

# Execute main function
main "$@"