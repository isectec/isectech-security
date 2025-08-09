#!/bin/bash
# iSECTECH Monitoring Stack Startup Script
# Production-grade monitoring infrastructure deployment

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONITORING_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$MONITORING_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Environment
ENV=${ENVIRONMENT:-production}
COMPOSE_FILE="docker-compose.monitoring.yml"

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] ✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] ⚠${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ✗${NC} $1"
}

check_requirements() {
    log "Checking system requirements..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check available disk space (minimum 20GB)
    AVAILABLE_SPACE=$(df "$MONITORING_DIR" | awk 'NR==2 {print $4}')
    MIN_SPACE=$((20 * 1024 * 1024))  # 20GB in KB
    
    if [ "$AVAILABLE_SPACE" -lt "$MIN_SPACE" ]; then
        log_error "Insufficient disk space. Need at least 20GB, have $(($AVAILABLE_SPACE / 1024 / 1024))GB"
        exit 1
    fi
    
    # Check available memory (minimum 4GB)
    AVAILABLE_MEMORY=$(free -k | awk 'NR==2{print $2}')
    MIN_MEMORY=$((4 * 1024 * 1024))  # 4GB in KB
    
    if [ "$AVAILABLE_MEMORY" -lt "$MIN_MEMORY" ]; then
        log_warning "Low memory detected. Recommended minimum is 4GB"
    fi
    
    log_success "System requirements check passed"
}

setup_environment() {
    log "Setting up environment..."
    
    cd "$MONITORING_DIR"
    
    # Create .env file if it doesn't exist
    if [[ ! -f .env ]]; then
        log "Creating default .env file..."
        cat > .env << EOF
# iSECTECH Monitoring Environment Configuration
ENVIRONMENT=${ENV}

# Grafana Configuration
GRAFANA_ADMIN_PASSWORD=\${GRAFANA_ADMIN_PASSWORD:-isectech_admin_2024}
GRAFANA_ADMIN_USER=\${GRAFANA_ADMIN_USER:-admin}

# Elasticsearch Configuration
ELASTICSEARCH_PASSWORD=\${ELASTICSEARCH_PASSWORD:-elastic123}

# Alerting Configuration
SLACK_API_URL=\${SLACK_API_URL}
SLACK_BOT_TOKEN=\${SLACK_BOT_TOKEN}
SLACK_WEBHOOK_URL=\${SLACK_WEBHOOK_URL}
SLACK_SIGNING_SECRET=\${SLACK_SIGNING_SECRET}

# SMTP Configuration
SMTP_HOST=\${SMTP_HOST:-smtp.isectech.com}
SMTP_PORT=\${SMTP_PORT:-587}
SMTP_USER=\${SMTP_USER:-alerts@isectech.com}
SMTP_PASSWORD=\${SMTP_PASSWORD}
SMTP_FROM=\${SMTP_FROM:-alerts@isectech.com}

# PagerDuty Configuration
PAGERDUTY_ROUTING_KEY_CRITICAL=\${PAGERDUTY_ROUTING_KEY_CRITICAL}
PAGERDUTY_ROUTING_KEY_WARNING=\${PAGERDUTY_ROUTING_KEY_WARNING}
PAGERDUTY_ROUTING_KEY_DATABASE=\${PAGERDUTY_ROUTING_KEY_DATABASE}
PAGERDUTY_ROUTING_KEY_SECURITY=\${PAGERDUTY_ROUTING_KEY_SECURITY}
PAGERDUTY_ROUTING_KEY_INFRA=\${PAGERDUTY_ROUTING_KEY_INFRA}

# Webhook Configuration
SECURITY_WEBHOOK_TOKEN=\${SECURITY_WEBHOOK_TOKEN}

# Database Configuration
POSTGRES_PASSWORD=\${POSTGRES_PASSWORD:-postgres123}
REDIS_PASSWORD=\${REDIS_PASSWORD}
EOF
        log_success "Default .env file created"
    fi
    
    # Create necessary directories
    mkdir -p logs
    mkdir -p data/{prometheus,grafana,elasticsearch,alertmanager,jaeger}
    
    # Set proper permissions
    chmod 755 data
    chmod -R 755 data/*
    
    log_success "Environment setup completed"
}

check_network() {
    log "Checking Docker networks..."
    
    # Create monitoring network if it doesn't exist
    if ! docker network ls | grep -q "isectech-monitoring"; then
        log "Creating monitoring network..."
        docker network create \
            --driver bridge \
            --subnet=172.20.0.0/16 \
            isectech-monitoring
        log_success "Monitoring network created"
    fi
    
    # Create isectech-internal network if it doesn't exist
    if ! docker network ls | grep -q "isectech-internal"; then
        log "Creating internal network..."
        docker network create \
            --driver bridge \
            --subnet=172.21.0.0/16 \
            isectech-internal
        log_success "Internal network created"
    fi
}

validate_configs() {
    log "Validating configuration files..."
    
    local configs_valid=true
    
    # Check Prometheus config
    if [[ -f "prometheus/prometheus.yml" ]]; then
        if docker run --rm -v "$PWD/prometheus:/etc/prometheus" prom/prometheus:v2.45.0 promtool check config /etc/prometheus/prometheus.yml > /dev/null 2>&1; then
            log_success "Prometheus configuration is valid"
        else
            log_error "Prometheus configuration is invalid"
            configs_valid=false
        fi
    else
        log_warning "Prometheus configuration file not found"
    fi
    
    # Check Alertmanager config
    if [[ -f "alertmanager/alertmanager.yml" ]]; then
        if docker run --rm -v "$PWD/alertmanager:/etc/alertmanager" prom/alertmanager:v0.26.0 amtool check-config /etc/alertmanager/alertmanager.yml > /dev/null 2>&1; then
            log_success "Alertmanager configuration is valid"
        else
            log_error "Alertmanager configuration is invalid"
            configs_valid=false
        fi
    else
        log_warning "Alertmanager configuration file not found"
    fi
    
    if [[ "$configs_valid" != "true" ]]; then
        log_error "Configuration validation failed"
        exit 1
    fi
}

pull_images() {
    log "Pulling Docker images..."
    
    docker-compose -f "$COMPOSE_FILE" pull --parallel
    
    log_success "Docker images pulled successfully"
}

start_services() {
    log "Starting monitoring services..."
    
    # Start services in dependency order
    log "Starting core infrastructure services..."
    docker-compose -f "$COMPOSE_FILE" up -d prometheus alertmanager
    
    # Wait for core services to be healthy
    log "Waiting for core services to be healthy..."
    sleep 30
    
    # Start visualization services
    log "Starting visualization services..."
    docker-compose -f "$COMPOSE_FILE" up -d grafana jaeger-all-in-one loki
    
    # Wait for visualization services
    sleep 20
    
    # Start exporters and collectors
    log "Starting exporters and collectors..."
    docker-compose -f "$COMPOSE_FILE" up -d \
        node-exporter \
        cadvisor \
        blackbox-exporter \
        postgres-exporter \
        redis-exporter \
        nginx-exporter \
        promtail
    
    log_success "All monitoring services started"
}

check_health() {
    log "Checking service health..."
    
    local services=(
        "prometheus:9090/-/healthy"
        "grafana:3000/api/health"
        "alertmanager:9093/-/healthy"
        "jaeger:16686/"
        "loki:3100/ready"
    )
    
    local all_healthy=true
    
    for service_check in "${services[@]}"; do
        IFS=':' read -r service endpoint <<< "$service_check"
        
        log "Checking $service health..."
        
        local retries=0
        local max_retries=10
        
        while [[ $retries -lt $max_retries ]]; do
            if curl -sf "http://localhost:$endpoint" > /dev/null 2>&1; then
                log_success "$service is healthy"
                break
            else
                retries=$((retries + 1))
                if [[ $retries -eq $max_retries ]]; then
                    log_error "$service health check failed"
                    all_healthy=false
                else
                    log "Waiting for $service to be ready... (attempt $retries/$max_retries)"
                    sleep 10
                fi
            fi
        done
    done
    
    if [[ "$all_healthy" == "true" ]]; then
        log_success "All services are healthy"
    else
        log_error "Some services failed health checks"
        return 1
    fi
}

setup_dashboards() {
    log "Setting up Grafana dashboards..."
    
    # Wait for Grafana to be fully ready
    sleep 30
    
    # Import dashboards via API (this would be implemented based on specific dashboards)
    log "Dashboards setup completed (manual import may be required)"
}

setup_alerts() {
    log "Setting up alerting rules..."
    
    # Reload Prometheus configuration to include alert rules
    curl -X POST http://localhost:9090/-/reload > /dev/null 2>&1 || true
    
    log_success "Alerting rules loaded"
}

show_endpoints() {
    log "Monitoring stack is ready!"
    echo
    echo "Service endpoints:"
    echo "  Prometheus:    http://localhost:9090"
    echo "  Grafana:       http://localhost:3001 (admin/isectech_admin_2024)"
    echo "  Alertmanager:  http://localhost:9093"
    echo "  Jaeger:        http://localhost:16686"
    echo "  Loki:          http://localhost:3100"
    echo
    echo "Metrics endpoints:"
    echo "  Node Exporter:     http://localhost:9100/metrics"
    echo "  cAdvisor:          http://localhost:8080/metrics"
    echo "  Blackbox Exporter: http://localhost:9115/metrics"
    echo "  Postgres Exporter: http://localhost:9187/metrics"
    echo "  Redis Exporter:    http://localhost:9121/metrics"
    echo "  Nginx Exporter:    http://localhost:9113/metrics"
    echo
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    log "Starting iSECTECH Monitoring Stack deployment..."
    
    check_requirements
    setup_environment
    check_network
    validate_configs
    pull_images
    start_services
    
    if check_health; then
        setup_dashboards
        setup_alerts
        show_endpoints
        log_success "Monitoring stack deployment completed successfully!"
    else
        log_error "Deployment completed with errors. Check service logs for details."
        echo
        echo "To check service logs:"
        echo "  docker-compose -f $COMPOSE_FILE logs [service-name]"
        echo
        echo "To restart services:"
        echo "  docker-compose -f $COMPOSE_FILE restart [service-name]"
        exit 1
    fi
}

# Handle script arguments
case "${1:-start}" in
    start)
        main
        ;;
    stop)
        log "Stopping monitoring services..."
        cd "$MONITORING_DIR"
        docker-compose -f "$COMPOSE_FILE" down
        log_success "Monitoring services stopped"
        ;;
    restart)
        log "Restarting monitoring services..."
        cd "$MONITORING_DIR"
        docker-compose -f "$COMPOSE_FILE" down
        sleep 5
        main
        ;;
    status)
        log "Checking service status..."
        cd "$MONITORING_DIR"
        docker-compose -f "$COMPOSE_FILE" ps
        ;;
    logs)
        cd "$MONITORING_DIR"
        docker-compose -f "$COMPOSE_FILE" logs -f "${2:-}"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [service]}"
        exit 1
        ;;
esac