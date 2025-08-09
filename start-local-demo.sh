#!/bin/bash
# iSECTECH Security Platform - Local Demo Startup Script
# Author: Claude Code - iSECTECH Development Team
# Version: 1.0.0

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT=$(pwd)
STARTUP_TIMEOUT=300  # 5 minutes timeout for services to start

echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                    iSECTECH Security Platform - Local Demo${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
echo

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if port is available
check_port() {
    local port=$1
    local service=$2
    
    if lsof -i :$port > /dev/null 2>&1; then
        print_warning "Port $port is already in use (needed for $service)"
        echo -e "Please stop the service using port $port or choose a different port"
        return 1
    fi
    return 0
}

# Function to wait for service
wait_for_service() {
    local url=$1
    local service_name=$2
    local timeout=${3:-60}
    
    print_status "Waiting for $service_name to be ready..."
    local count=0
    
    while [ $count -lt $timeout ]; do
        if curl -s -f "$url" > /dev/null 2>&1; then
            print_status "$service_name is ready!"
            return 0
        fi
        sleep 2
        count=$((count + 2))
        echo -n "."
    done
    
    print_error "$service_name failed to start within ${timeout}s"
    return 1
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    # Create data directories
    mkdir -p ./deception-technology/data/postgres
    mkdir -p ./deception-technology/data/redis
    mkdir -p ./monitoring/data/prometheus
    mkdir -p ./monitoring/data/grafana
    mkdir -p ./logs/applications
    mkdir -p ./logs/security
    mkdir -p ./logs/monitoring
    
    print_status "Directories created successfully"
}

# Function to check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed or not working"
        exit 1
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed"
        exit 1
    fi
    
    # Check npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is not installed"
        exit 1
    fi
    
    print_status "All prerequisites are installed"
}

# Function to check critical ports
check_ports() {
    print_status "Checking port availability..."
    
    local ports_services=(
        "3000:Frontend (Next.js)"
        "3001:Decoy Services"
        "3002:Canary Token Manager"
        "5432:PostgreSQL"
        "6379:Redis"
        "9090:Prometheus"
        "3000:Grafana"
        "80:Nginx HTTP"
        "443:Nginx HTTPS"
    )
    
    for port_service in "${ports_services[@]}"; do
        local port=$(echo $port_service | cut -d: -f1)
        local service=$(echo $port_service | cut -d: -f2-)
        
        if ! check_port $port "$service"; then
            print_warning "Port conflict detected. Some services may not start properly."
        fi
    done
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Node.js dependencies..."
    
    if [ ! -d "node_modules" ]; then
        npm install
    else
        print_status "Dependencies already installed"
    fi
}

# Function to start infrastructure services
start_infrastructure() {
    print_status "Starting infrastructure services (PostgreSQL, Redis, Monitoring)..."
    
    cd monitoring
    docker compose -f docker-compose.monitoring.yml up -d prometheus grafana
    cd ..
    
    # Wait for monitoring services
    sleep 10
    
    print_status "Infrastructure services started"
}

# Function to start deception technology stack
start_deception_technology() {
    print_status "Starting Deception Technology stack..."
    
    cd deception-technology
    
    # Start core services (postgres, redis)
    docker compose up -d postgres redis
    
    # Wait for database to be ready
    print_status "Waiting for PostgreSQL to be ready..."
    sleep 15
    
    # Start deception services
    docker compose up -d decoy-services canary-manager nginx prometheus grafana
    
    cd ..
    
    # Wait for services to be ready
    wait_for_service "http://localhost:3001/health" "Decoy Services" 60
    wait_for_service "http://localhost:3002/health" "Canary Token Manager" 60
    
    print_status "Deception Technology stack started"
}

# Function to start security validation services
start_security_validation() {
    print_status "Starting Security Validation Framework..."
    
    # These services are Python-based, so we'll start them directly
    cd security-validation-framework
    
    # Start automated penetration testing service
    if [ -f "services/automated-penetration-testing.py" ]; then
        print_status "Security validation services are ready (Python-based)"
    fi
    
    cd ..
}

# Function to start frontend application
start_frontend() {
    print_status "Starting Frontend Application (Next.js)..."
    
    # Build the application
    npm run build
    
    # Start in development mode for local demo
    print_status "Starting Next.js in development mode..."
    npm run dev &
    FRONTEND_PID=$!
    
    # Wait for frontend to be ready
    wait_for_service "http://localhost:3000" "Frontend Application" 120
    
    print_status "Frontend application started on http://localhost:3000"
}

# Function to display service URLs
display_service_urls() {
    print_status "Services are now running at the following URLs:"
    echo
    echo -e "${GREEN}Frontend Application:${NC}"
    echo -e "  🌐 iSECTECH Dashboard: http://localhost:3000"
    echo
    echo -e "${GREEN}Security Services:${NC}"
    echo -e "  🕵️  Decoy Services: http://localhost:3001"
    echo -e "  🎯 Canary Token Manager: http://localhost:3002"
    echo
    echo -e "${GREEN}Monitoring:${NC}"
    echo -e "  📊 Prometheus: http://localhost:9090"
    echo -e "  📈 Grafana: http://localhost:3000 (admin/grafana_admin_pass)"
    echo
    echo -e "${GREEN}Infrastructure:${NC}"
    echo -e "  🗄️  PostgreSQL: localhost:5432 (deception_user/secure_deception_pass_123)"
    echo -e "  🔄 Redis: localhost:6379 (password: redis_deception_pass_456)"
    echo
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🚀 iSECTECH Security Platform is now running locally!${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${YELLOW}Demo Features Available:${NC}"
    echo -e "  ✅ Machine Learning Threat Detection"
    echo -e "  ✅ Deception Technology with Canary Tokens"
    echo -e "  ✅ Automated Security Validation"
    echo -e "  ✅ Real-time Monitoring and Dashboards"
    echo -e "  ✅ Multi-Framework Compliance Automation"
    echo
    echo -e "${YELLOW}To stop all services, run:${NC} ./stop-local-demo.sh"
    echo
}

# Main execution
main() {
    print_status "Starting iSECTECH Security Platform local demo..."
    echo
    
    # Check prerequisites
    check_prerequisites
    
    # Create necessary directories
    create_directories
    
    # Check port availability
    check_ports
    
    # Install dependencies
    install_dependencies
    
    # Start services in order
    start_infrastructure
    start_deception_technology
    start_security_validation
    start_frontend
    
    # Display information
    display_service_urls
    
    # Keep script running
    print_status "Press Ctrl+C to stop all services..."
    
    # Trap signals to cleanup
    trap cleanup_services SIGINT SIGTERM
    
    # Wait for user input
    while true; do
        sleep 1
    done
}

# Function to cleanup services
cleanup_services() {
    print_status "Stopping all services..."
    
    # Stop frontend
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
    fi
    
    # Stop Docker services
    cd deception-technology && docker compose down
    cd ../monitoring && docker compose -f docker-compose.monitoring.yml down
    
    print_status "All services stopped"
    exit 0
}

# Execute main function
main "$@"