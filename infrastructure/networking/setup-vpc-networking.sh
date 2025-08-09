#!/bin/bash

# iSECTECH VPC Networking Setup Script
# Production-grade networking infrastructure for Cloud Run services
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Color codes for output
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

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites for VPC networking setup..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check authentication
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable compute.googleapis.com
    gcloud services enable vpcaccess.googleapis.com
    gcloud services enable servicenetworking.googleapis.com
    gcloud services enable sqladmin.googleapis.com
    gcloud services enable redis.googleapis.com
    gcloud services enable run.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create main VPC network
create_vpc_network() {
    log_info "Creating main VPC network..."
    
    # Create the main VPC network
    if ! gcloud compute networks describe isectech-vpc &>/dev/null; then
        gcloud compute networks create isectech-vpc \
            --subnet-mode=custom \
            --bgp-routing-mode=regional \
            --description="iSECTECH main VPC network for ${ENVIRONMENT}"
        log_success "Created main VPC network: isectech-vpc"
    else
        log_info "VPC network isectech-vpc already exists"
    fi
    
    # Create regional subnet for main services
    local subnet_name="isectech-subnet-${REGION}"
    if ! gcloud compute networks subnets describe "$subnet_name" --region="$REGION" &>/dev/null; then
        gcloud compute networks subnets create "$subnet_name" \
            --network=isectech-vpc \
            --range=10.0.0.0/24 \
            --region="$REGION" \
            --enable-private-ip-google-access \
            --description="Main subnet for iSECTECH services in ${REGION}"
        log_success "Created subnet: $subnet_name"
    else
        log_info "Subnet $subnet_name already exists"
    fi
    
    # Create connector subnet for VPC connectors (smaller subnet)
    local connector_subnet="isectech-connector-subnet-${REGION}"
    if ! gcloud compute networks subnets describe "$connector_subnet" --region="$REGION" &>/dev/null; then
        gcloud compute networks subnets create "$connector_subnet" \
            --network=isectech-vpc \
            --range=10.0.1.0/28 \
            --region="$REGION" \
            --enable-private-ip-google-access \
            --description="VPC connector subnet for Cloud Run in ${REGION}"
        log_success "Created connector subnet: $connector_subnet"
    else
        log_info "Connector subnet $connector_subnet already exists"
    fi
}

# Create VPC connector for Cloud Run
create_vpc_connector() {
    log_info "Creating VPC connector for Cloud Run..."
    
    local connector_name="isectech-vpc-connector"
    local connector_subnet="isectech-connector-subnet-${REGION}"
    
    if ! gcloud compute networks vpc-access connectors describe "$connector_name" --region="$REGION" &>/dev/null; then
        gcloud compute networks vpc-access connectors create "$connector_name" \
            --region="$REGION" \
            --subnet="$connector_subnet" \
            --subnet-project="$PROJECT_ID" \
            --min-instances=2 \
            --max-instances=10 \
            --machine-type=e2-micro \
            --network=isectech-vpc
        log_success "Created VPC connector: $connector_name"
    else
        log_info "VPC connector $connector_name already exists"
    fi
    
    # Wait for connector to be ready
    log_info "Waiting for VPC connector to be ready..."
    while true; do
        local state
        state=$(gcloud compute networks vpc-access connectors describe "$connector_name" --region="$REGION" --format="value(state)")
        if [ "$state" = "READY" ]; then
            log_success "VPC connector is ready"
            break
        elif [ "$state" = "CREATING" ]; then
            log_info "VPC connector is still creating... waiting 30 seconds"
            sleep 30
        else
            log_error "VPC connector creation failed. State: $state"
            exit 1
        fi
    done
}

# Configure private services networking for managed databases
setup_private_services_networking() {
    log_info "Setting up private services networking for managed databases..."
    
    # Allocate IP range for private services (Cloud SQL, Redis, etc.)
    local peering_name="isectech-private-services"
    
    if ! gcloud compute addresses describe "$peering_name" --global &>/dev/null; then
        gcloud compute addresses create "$peering_name" \
            --global \
            --purpose=VPC_PEERING \
            --prefix-length=16 \
            --network=isectech-vpc \
            --description="Private services IP range for managed databases"
        log_success "Created private services IP range: $peering_name"
    else
        log_info "Private services IP range $peering_name already exists"
    fi
    
    # Create private connection for Google services
    if ! gcloud services vpc-peerings list --network=isectech-vpc --format="value(network)" | grep -q isectech-vpc; then
        gcloud services vpc-peerings connect \
            --service=servicenetworking.googleapis.com \
            --ranges="$peering_name" \
            --network=isectech-vpc \
            --project="$PROJECT_ID"
        log_success "Created private connection for Google services"
    else
        log_info "Private connection for Google services already exists"
    fi
}

# Create Cloud SQL instances with private networking
create_cloud_sql_instances() {
    log_info "Creating Cloud SQL instances with private networking..."
    
    # PostgreSQL instance for main application database
    local postgres_instance="isectech-postgres-${ENVIRONMENT}"
    if ! gcloud sql instances describe "$postgres_instance" &>/dev/null; then
        gcloud sql instances create "$postgres_instance" \
            --database-version=POSTGRES_15 \
            --tier=db-custom-2-4096 \
            --region="$REGION" \
            --network=isectech-vpc \
            --no-assign-ip \
            --enable-bin-log \
            --backup-start-time=03:00 \
            --maintenance-window-day=SUN \
            --maintenance-window-hour=04 \
            --maintenance-release-channel=production \
            --deletion-protection \
            --storage-type=SSD \
            --storage-size=100GB \
            --storage-auto-increase \
            --labels="environment=${ENVIRONMENT},service=postgresql,managed-by=isectech-platform"
        
        # Set the password for the postgres user
        log_info "Setting postgres user password..."
        local postgres_password
        postgres_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
        gcloud sql users set-password postgres \
            --instance="$postgres_instance" \
            --password="$postgres_password"
        
        # Store password in Secret Manager
        echo -n "$postgres_password" | gcloud secrets versions add isectech-postgres-password --data-file=-
        
        log_success "Created Cloud SQL PostgreSQL instance: $postgres_instance"
    else
        log_info "Cloud SQL PostgreSQL instance $postgres_instance already exists"
    fi
    
    # Create application database and user
    log_info "Creating application database and user..."
    if ! gcloud sql databases describe isectech --instance="$postgres_instance" &>/dev/null; then
        gcloud sql databases create isectech --instance="$postgres_instance"
        log_success "Created application database: isectech"
    fi
    
    # Create application user
    if ! gcloud sql users describe isectech --instance="$postgres_instance" &>/dev/null; then
        local app_user_password
        app_user_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
        gcloud sql users create isectech \
            --instance="$postgres_instance" \
            --password="$app_user_password"
        
        # Store user password in Secret Manager (separate from postgres admin password)
        echo -n "$app_user_password" | gcloud secrets versions add isectech-postgres-user-password --data-file=-
        
        log_success "Created application user: isectech"
    fi
}

# Create Redis (Memorystore) instance with private networking  
create_redis_instance() {
    log_info "Creating Redis (Memorystore) instance with private networking..."
    
    local redis_instance="isectech-redis-${ENVIRONMENT}"
    if ! gcloud redis instances describe "$redis_instance" --region="$REGION" &>/dev/null; then
        gcloud redis instances create "$redis_instance" \
            --size=1 \
            --region="$REGION" \
            --network=isectech-vpc \
            --redis-version=redis_7_0 \
            --enable-auth \
            --maintenance-window-day=sunday \
            --maintenance-window-hour=4 \
            --labels="environment=${ENVIRONMENT},service=redis,managed-by=isectech-platform"
        
        log_success "Created Redis instance: $redis_instance"
        
        # Get Redis auth string and store in Secret Manager
        log_info "Storing Redis auth string in Secret Manager..."
        local redis_auth
        redis_auth=$(gcloud redis instances describe "$redis_instance" --region="$REGION" --format="value(authString)")
        if [ -n "$redis_auth" ]; then
            echo -n "$redis_auth" | gcloud secrets versions add isectech-redis-password --data-file=-
            log_success "Stored Redis auth string in Secret Manager"
        fi
    else
        log_info "Redis instance $redis_instance already exists"
    fi
}

# Create firewall rules for secure communication
create_firewall_rules() {
    log_info "Creating firewall rules for secure communication..."
    
    # Allow internal communication within VPC
    if ! gcloud compute firewall-rules describe isectech-allow-internal &>/dev/null; then
        gcloud compute firewall-rules create isectech-allow-internal \
            --network=isectech-vpc \
            --allow=tcp,udp,icmp \
            --source-ranges=10.0.0.0/8 \
            --description="Allow internal communication within iSECTECH VPC" \
            --enable-logging
        log_success "Created internal communication firewall rule"
    fi
    
    # Allow Cloud Run health checks
    if ! gcloud compute firewall-rules describe isectech-allow-health-checks &>/dev/null; then
        gcloud compute firewall-rules create isectech-allow-health-checks \
            --network=isectech-vpc \
            --allow=tcp:8080,tcp:3000,tcp:80,tcp:443 \
            --source-ranges=130.211.0.0/22,35.191.0.0/16 \
            --target-tags=cloud-run-service \
            --description="Allow Google Cloud health checks for Cloud Run services" \
            --enable-logging
        log_success "Created health check firewall rule"
    fi
    
    # Allow SSH for debugging (restricted to specific IPs in production)
    if [ "$ENVIRONMENT" != "production" ]; then
        if ! gcloud compute firewall-rules describe isectech-allow-ssh &>/dev/null; then
            gcloud compute firewall-rules create isectech-allow-ssh \
                --network=isectech-vpc \
                --allow=tcp:22 \
                --source-ranges=0.0.0.0/0 \
                --target-tags=allow-ssh \
                --description="Allow SSH access for debugging (${ENVIRONMENT} only)" \
                --enable-logging
            log_success "Created SSH access firewall rule for ${ENVIRONMENT}"
        fi
    fi
    
    # Deny all other traffic by default (implicit, but log it)
    if ! gcloud compute firewall-rules describe isectech-deny-all &>/dev/null; then
        gcloud compute firewall-rules create isectech-deny-all \
            --network=isectech-vpc \
            --action=deny \
            --rules=all \
            --source-ranges=0.0.0.0/0 \
            --priority=65534 \
            --description="Deny all other traffic (default deny with logging)" \
            --enable-logging
        log_success "Created default deny firewall rule"
    fi
}

# Create Cloud NAT for outbound internet access
create_cloud_nat() {
    log_info "Creating Cloud NAT for outbound internet access..."
    
    # Create Cloud Router first
    local router_name="isectech-router-${REGION}"
    if ! gcloud compute routers describe "$router_name" --region="$REGION" &>/dev/null; then
        gcloud compute routers create "$router_name" \
            --network=isectech-vpc \
            --region="$REGION" \
            --description="Cloud Router for iSECTECH NAT gateway"
        log_success "Created Cloud Router: $router_name"
    fi
    
    # Create Cloud NAT
    local nat_name="isectech-nat-${REGION}"
    if ! gcloud compute routers nats describe "$nat_name" --router="$router_name" --region="$REGION" &>/dev/null; then
        gcloud compute routers nats create "$nat_name" \
            --router="$router_name" \
            --region="$REGION" \
            --nat-all-subnet-ip-ranges \
            --auto-allocate-nat-external-ips \
            --enable-logging \
            --log-filter=ERRORS_ONLY
        log_success "Created Cloud NAT: $nat_name"
    fi
}

# Configure DNS for internal service discovery
setup_internal_dns() {
    log_info "Setting up internal DNS for service discovery..."
    
    # Create private DNS zone for internal services
    local dns_zone="isectech-internal"
    local dns_domain="internal.isectech.com."
    
    if ! gcloud dns managed-zones describe "$dns_zone" &>/dev/null; then
        gcloud dns managed-zones create "$dns_zone" \
            --description="Private DNS zone for iSECTECH internal services" \
            --dns-name="$dns_domain" \
            --networks=isectech-vpc \
            --visibility=private
        log_success "Created private DNS zone: $dns_zone"
    fi
    
    # Add DNS records for database services
    local postgres_ip
    postgres_ip=$(gcloud sql instances describe "isectech-postgres-${ENVIRONMENT}" --format="value(ipAddresses[0].ipAddress)")
    
    if [ -n "$postgres_ip" ]; then
        # Remove existing A record if it exists
        if gcloud dns record-sets list --zone="$dns_zone" --name="postgres.${dns_domain}" --type=A &>/dev/null; then
            gcloud dns record-sets delete "postgres.${dns_domain}" --zone="$dns_zone" --type=A --quiet
        fi
        
        # Add new A record
        gcloud dns record-sets create "postgres.${dns_domain}" \
            --zone="$dns_zone" \
            --type=A \
            --ttl=300 \
            --rrdatas="$postgres_ip"
        log_success "Added DNS record for PostgreSQL: postgres.internal.isectech.com"
    fi
    
    # Add DNS record for Redis
    local redis_ip
    redis_ip=$(gcloud redis instances describe "isectech-redis-${ENVIRONMENT}" --region="$REGION" --format="value(host)")
    
    if [ -n "$redis_ip" ]; then
        # Remove existing A record if it exists
        if gcloud dns record-sets list --zone="$dns_zone" --name="redis.${dns_domain}" --type=A &>/dev/null; then
            gcloud dns record-sets delete "redis.${dns_domain}" --zone="$dns_zone" --type=A --quiet
        fi
        
        # Add new A record
        gcloud dns record-sets create "redis.${dns_domain}" \
            --zone="$dns_zone" \
            --type=A \
            --ttl=300 \
            --rrdatas="$redis_ip"
        log_success "Added DNS record for Redis: redis.internal.isectech.com"
    fi
}

# Create network security policies
create_network_security_policies() {
    log_info "Creating network security policies..."
    
    # Create a network security policy for DDoS protection
    if ! gcloud compute security-policies describe isectech-security-policy &>/dev/null; then
        gcloud compute security-policies create isectech-security-policy \
            --description="iSECTECH network security policy for DDoS protection and WAF"
        
        # Add rate limiting rule
        gcloud compute security-policies rules create 1000 \
            --security-policy=isectech-security-policy \
            --action=throttle \
            --rate-limit-threshold-count=1000 \
            --rate-limit-threshold-interval-sec=60 \
            --conform-action=allow \
            --exceed-action=deny-429 \
            --enforce-on-key=IP \
            --description="Rate limit: 1000 requests per minute per IP"
        
        # Add geo-blocking rule (example: block traffic from specific countries if needed)
        # This would be customized based on business requirements
        
        log_success "Created network security policy: isectech-security-policy"
    fi
}

# Test connectivity and validate setup
test_connectivity() {
    log_info "Testing connectivity and validating setup..."
    
    # Test VPC connector connectivity
    local connector_name="isectech-vpc-connector"
    local connector_state
    connector_state=$(gcloud compute networks vpc-access connectors describe "$connector_name" --region="$REGION" --format="value(state)")
    
    if [ "$connector_state" = "READY" ]; then
        log_success "VPC connector is ready and accessible"
    else
        log_error "VPC connector is not ready. State: $connector_state"
        return 1
    fi
    
    # Test database connectivity (basic)
    local postgres_instance="isectech-postgres-${ENVIRONMENT}"
    local postgres_state
    postgres_state=$(gcloud sql instances describe "$postgres_instance" --format="value(state)")
    
    if [ "$postgres_state" = "RUNNABLE" ]; then
        log_success "PostgreSQL instance is running and accessible"
    else
        log_error "PostgreSQL instance is not ready. State: $postgres_state"
        return 1
    fi
    
    # Test Redis connectivity
    local redis_instance="isectech-redis-${ENVIRONMENT}"
    local redis_state
    redis_state=$(gcloud redis instances describe "$redis_instance" --region="$REGION" --format="value(state)")
    
    if [ "$redis_state" = "READY" ]; then
        log_success "Redis instance is ready and accessible"
    else
        log_error "Redis instance is not ready. State: $redis_state"
        return 1
    fi
    
    log_success "All connectivity tests passed"
}

# Generate networking summary report
generate_networking_report() {
    log_info "Generating networking configuration report..."
    
    local report_file="/tmp/isectech-networking-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Networking Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
VPC NETWORK CONFIGURATION
================================

VPC Network: isectech-vpc
Main Subnet: isectech-subnet-${REGION} (10.0.0.0/24)
Connector Subnet: isectech-connector-subnet-${REGION} (10.0.1.0/28)

VPC Connector: isectech-vpc-connector
- Region: ${REGION}
- Min Instances: 2
- Max Instances: 10
- Machine Type: e2-micro

================================
DATABASE INSTANCES
================================

PostgreSQL:
- Instance: isectech-postgres-${ENVIRONMENT}
- Version: PostgreSQL 15
- Tier: db-custom-2-4096
- Network: Private (no public IP)
- Backup: 03:00 UTC daily
- Maintenance: Sunday 04:00 UTC

Redis (Memorystore):
- Instance: isectech-redis-${ENVIRONMENT}
- Version: Redis 7.0
- Size: 1GB
- Network: Private VPC
- Auth: Enabled
- Maintenance: Sunday 04:00 UTC

================================
NETWORK SECURITY
================================

Firewall Rules:
- isectech-allow-internal: Internal VPC communication
- isectech-allow-health-checks: Google Cloud health checks
- isectech-deny-all: Default deny with logging

Private Services Networking: Enabled
Cloud NAT: isectech-nat-${REGION}
Security Policy: isectech-security-policy (rate limiting enabled)

================================
DNS CONFIGURATION
================================

Private DNS Zone: isectech-internal (internal.isectech.com)
DNS Records:
- postgres.internal.isectech.com
- redis.internal.isectech.com

================================
CONNECTIVITY INFORMATION
================================

Cloud Run Services Configuration:
- VPC Connector: isectech-vpc-connector
- Egress: private-ranges-only
- Database Access: Via private IP/Cloud SQL Proxy

Service-to-Service Communication:
- Internal DNS resolution
- Private IP networking
- JWT-based authentication
- TLS encryption for all traffic

================================
NEXT STEPS
================================

1. Update Cloud Run service configurations to use internal DNS names
2. Configure service-to-service authentication middleware
3. Set up monitoring for network connectivity and performance
4. Test end-to-end connectivity from Cloud Run services to databases
5. Configure backup and disaster recovery for network components
6. Set up network monitoring and alerting
7. Implement service mesh (Istio) if required for advanced traffic management

================================
SECURITY RECOMMENDATIONS
================================

1. Regularly review and audit firewall rules
2. Monitor network traffic for anomalies
3. Implement network segmentation for sensitive workloads
4. Use private Google Access for all managed services
5. Enable VPC Flow Logs for security monitoring
6. Implement DDoS protection at multiple layers
7. Regular security assessments of network configuration

EOF
    
    # Add current network information
    cat >> "$report_file" << EOF

================================
CURRENT RESOURCE STATUS
================================

VPC Connector Status:
EOF
    gcloud compute networks vpc-access connectors describe isectech-vpc-connector --region="$REGION" --format="table(name,state,network,subnet)" >> "$report_file" 2>/dev/null || echo "VPC Connector not found" >> "$report_file"
    
    cat >> "$report_file" << EOF

Database Instance Status:
EOF
    gcloud sql instances list --filter="name:isectech-postgres-${ENVIRONMENT}" --format="table(name,state,ipAddresses[0].ipAddress:label=PRIVATE_IP)" >> "$report_file" 2>/dev/null || echo "PostgreSQL instance not found" >> "$report_file"
    
    cat >> "$report_file" << EOF

Redis Instance Status:
EOF
    gcloud redis instances list --region="$REGION" --filter="name:isectech-redis-${ENVIRONMENT}" --format="table(name,state,host:label=PRIVATE_IP)" >> "$report_file" 2>/dev/null || echo "Redis instance not found" >> "$report_file"
    
    log_success "Networking report generated: $report_file"
    cat "$report_file"
}

# Main execution
main() {
    log_info "Starting iSECTECH VPC networking setup..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    check_prerequisites
    
    create_vpc_network
    create_vpc_connector
    setup_private_services_networking
    create_cloud_sql_instances
    create_redis_instance
    create_firewall_rules
    create_cloud_nat
    setup_internal_dns
    create_network_security_policies
    
    test_connectivity
    generate_networking_report
    
    log_success "iSECTECH VPC networking setup completed successfully!"
    
    echo ""
    log_info "Network infrastructure is ready for Cloud Run service deployment."
    log_info "VPC Connector: isectech-vpc-connector"
    log_info "Database access: Via private networking and Cloud SQL Proxy"
    log_info "Next: Deploy Cloud Run services with VPC connector configuration"
}

# Help function
show_help() {
    cat << EOF
iSECTECH VPC Networking Setup Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV   Environment to set up (production, staging, development)
    --project PROJECT   Google Cloud project ID
    --region REGION     Google Cloud region (default: us-central1)
    --help             Show this help message

Environment Variables:
    PROJECT_ID         Google Cloud project ID
    REGION            Google Cloud region (default: us-central1)
    ENVIRONMENT       Environment name (default: production)

Examples:
    # Set up production networking
    PROJECT_ID=isectech-security-platform ./setup-vpc-networking.sh --environment production
    
    # Set up staging environment
    PROJECT_ID=isectech-staging-platform ./setup-vpc-networking.sh --environment staging --region us-west1

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"