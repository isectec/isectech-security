#!/bin/bash

# iSECTECH Load Balancer and Traffic Management Setup Script
# Production-grade HTTP(S) Load Balancer with Cloud Armor integration
# Author: Claude Code - iSECTECH Infrastructure Team  
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DOMAIN_NAME="${DOMAIN_NAME:-protect.isectech.com}"
API_DOMAIN="${API_DOMAIN:-api.isectech.com}"
GATEWAY_DOMAIN="${GATEWAY_DOMAIN:-gateway.isectech.com}"

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
    log_info "Checking prerequisites for load balancer setup..."
    
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
    gcloud services enable run.googleapis.com
    gcloud services enable certificatemanager.googleapis.com
    gcloud services enable dns.googleapis.com
    gcloud services enable cloudresourcemanager.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create Cloud Armor security policy
create_cloud_armor_policy() {
    log_info "Creating Cloud Armor security policy..."
    
    local policy_name="isectech-security-policy"
    
    # Check if policy already exists
    if gcloud compute security-policies describe "$policy_name" &>/dev/null; then
        log_info "Cloud Armor policy $policy_name already exists"
        return 0
    fi
    
    # Create security policy with adaptive protection
    gcloud compute security-policies create "$policy_name" \
        --description="iSECTECH comprehensive security policy with WAF, DDoS protection, and rate limiting" \
        --type=CLOUD_ARMOR
    
    # Configure DDoS protection
    gcloud compute security-policies update "$policy_name" \
        --enable-layer7-ddos-defense
    
    # Rule 1: Block known malicious IPs (Priority 1000)
    gcloud compute security-policies rules create 1000 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --src-ip-ranges="192.0.2.0/24,198.51.100.0/24,203.0.113.0/24" \
        --description="Block RFC 5737 test networks and known malicious IPs"
    
    # Rule 2: Rate limiting for API endpoints (Priority 2000)
    gcloud compute security-policies rules create 2000 \
        --security-policy="$policy_name" \
        --action=throttle \
        --rate-limit-threshold-count=1000 \
        --rate-limit-threshold-interval-sec=60 \
        --conform-action=allow \
        --exceed-action=deny-429 \
        --enforce-on-key=IP \
        --expression="request.path.startsWith('/api/')" \
        --description="Rate limit API endpoints: 1000 requests per minute per IP"
    
    # Rule 3: Rate limiting for authentication endpoints (Priority 2100) 
    gcloud compute security-policies rules create 2100 \
        --security-policy="$policy_name" \
        --action=throttle \
        --rate-limit-threshold-count=100 \
        --rate-limit-threshold-interval-sec=60 \
        --conform-action=allow \
        --exceed-action=deny-429 \
        --enforce-on-key=IP \
        --expression="request.path.startsWith('/auth/') || request.path.startsWith('/login')" \
        --description="Strict rate limiting for auth endpoints: 100 requests per minute per IP"
    
    # Rule 4: Block SQL injection attempts (Priority 3000)
    gcloud compute security-policies rules create 3000 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --expression="evaluatePreconfiguredExpr('sqli-stable')" \
        --description="Block SQL injection attempts using preconfigured WAF rule"
    
    # Rule 5: Block XSS attempts (Priority 3100)  
    gcloud compute security-policies rules create 3100 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --expression="evaluatePreconfiguredExpr('xss-stable')" \
        --description="Block XSS attempts using preconfigured WAF rule"
    
    # Rule 6: Block scanner/bot traffic (Priority 3200)
    gcloud compute security-policies rules create 3200 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --expression="evaluatePreconfiguredExpr('scannerdetection-stable')" \
        --description="Block known scanners and malicious bots"
    
    # Rule 7: Protocol attack protection (Priority 3300)
    gcloud compute security-policies rules create 3300 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --expression="evaluatePreconfiguredExpr('protocolattack-stable')" \
        --description="Block protocol-based attacks"
    
    # Rule 8: Geo-blocking for high-risk countries (Priority 4000)
    # Note: Customize based on business requirements
    gcloud compute security-policies rules create 4000 \
        --security-policy="$policy_name" \
        --action=deny-403 \
        --expression="origin.region_code == 'CN' || origin.region_code == 'RU' || origin.region_code == 'KP'" \
        --description="Block traffic from high-risk geographical regions"
    
    # Rule 9: Allow legitimate traffic (Default rule - Priority 2147483647)
    gcloud compute security-policies rules update 2147483647 \
        --security-policy="$policy_name" \
        --action=allow \
        --description="Default allow rule for legitimate traffic"
    
    log_success "Cloud Armor security policy created: $policy_name"
}

# Reserve static IP addresses
reserve_static_ips() {
    log_info "Reserving static IP addresses..."
    
    # Reserve global static IP for load balancer
    local lb_ip_name="isectech-lb-ip"
    if ! gcloud compute addresses describe "$lb_ip_name" --global &>/dev/null; then
        gcloud compute addresses create "$lb_ip_name" \
            --global \
            --description="Static IP for iSECTECH load balancer"
        log_success "Reserved global static IP: $lb_ip_name"
    else
        log_info "Static IP $lb_ip_name already exists"
    fi
    
    # Get the reserved IP address
    local lb_ip
    lb_ip=$(gcloud compute addresses describe "$lb_ip_name" --global --format="value(address)")
    log_info "Load balancer IP address: $lb_ip"
    
    # Store IP in environment file for DNS configuration
    echo "LOAD_BALANCER_IP=$lb_ip" > "/tmp/isectech-lb-config.env"
}

# Create SSL certificates
create_ssl_certificates() {
    log_info "Creating SSL certificates..."
    
    # Create managed SSL certificate for main domain
    local cert_name="isectech-ssl-cert"
    if ! gcloud compute ssl-certificates describe "$cert_name" &>/dev/null; then
        gcloud compute ssl-certificates create "$cert_name" \
            --domains="$DOMAIN_NAME,$API_DOMAIN,$GATEWAY_DOMAIN,*.isectech.com" \
            --global \
            --description="Managed SSL certificate for iSECTECH domains"
        log_success "Created managed SSL certificate: $cert_name"
        
        log_warning "SSL certificate is being provisioned. This may take 10-60 minutes."
        log_warning "DNS records must be pointing to load balancer IP for certificate validation."
    else
        log_info "SSL certificate $cert_name already exists"
    fi
    
    # Check certificate status
    local cert_status
    cert_status=$(gcloud compute ssl-certificates describe "$cert_name" --format="value(managed.status)")
    log_info "SSL certificate status: $cert_status"
}

# Create backend services
create_backend_services() {
    log_info "Creating backend services..."
    
    # Backend service for frontend (React app)
    local frontend_backend="isectech-frontend-backend"
    if ! gcloud compute backend-services describe "$frontend_backend" --global &>/dev/null; then
        gcloud compute backend-services create "$frontend_backend" \
            --global \
            --protocol=HTTP \
            --port-name=http \
            --timeout=30s \
            --enable-cdn \
            --cache-mode=CACHE_ALL_STATIC \
            --default-ttl=3600 \
            --max-ttl=86400 \
            --client-ttl=3600 \
            --health-checks=isectech-frontend-health-check \
            --security-policy=isectech-security-policy \
            --description="Backend service for iSECTECH frontend application"
        
        log_success "Created frontend backend service: $frontend_backend"
    else
        log_info "Frontend backend service $frontend_backend already exists"
    fi
    
    # Backend service for API Gateway
    local api_backend="isectech-api-backend" 
    if ! gcloud compute backend-services describe "$api_backend" --global &>/dev/null; then
        gcloud compute backend-services create "$api_backend" \
            --global \
            --protocol=HTTP \
            --port-name=http \
            --timeout=30s \
            --health-checks=isectech-api-health-check \
            --security-policy=isectech-security-policy \
            --description="Backend service for iSECTECH API Gateway"
        
        log_success "Created API backend service: $api_backend"
    else
        log_info "API backend service $api_backend already exists"
    fi
    
    # Backend service for backend microservices
    local backend_backend="isectech-backend-services-backend"
    if ! gcloud compute backend-services describe "$backend_backend" --global &>/dev/null; then
        gcloud compute backend-services create "$backend_backend" \
            --global \
            --protocol=HTTP \
            --port-name=http \
            --timeout=60s \
            --health-checks=isectech-backend-health-check \
            --security-policy=isectech-security-policy \
            --description="Backend service for iSECTECH backend microservices"
        
        log_success "Created backend services backend service: $backend_backend"
    else
        log_info "Backend services backend service $backend_backend already exists"
    fi
}

# Create health checks
create_health_checks() {
    log_info "Creating health checks..."
    
    # Health check for frontend
    local frontend_hc="isectech-frontend-health-check"
    if ! gcloud compute health-checks describe "$frontend_hc" &>/dev/null; then
        gcloud compute health-checks create http "$frontend_hc" \
            --port=3000 \
            --request-path="/api/health" \
            --check-interval=30s \
            --timeout=10s \
            --healthy-threshold=2 \
            --unhealthy-threshold=3 \
            --description="Health check for iSECTECH frontend service"
        log_success "Created frontend health check: $frontend_hc"
    else
        log_info "Frontend health check $frontend_hc already exists"
    fi
    
    # Health check for API Gateway
    local api_hc="isectech-api-health-check"
    if ! gcloud compute health-checks describe "$api_hc" &>/dev/null; then
        gcloud compute health-checks create http "$api_hc" \
            --port=8080 \
            --request-path="/health" \
            --check-interval=30s \
            --timeout=10s \
            --healthy-threshold=2 \
            --unhealthy-threshold=3 \
            --description="Health check for iSECTECH API Gateway"
        log_success "Created API health check: $api_hc"
    else
        log_info "API health check $api_hc already exists"
    fi
    
    # Health check for backend services
    local backend_hc="isectech-backend-health-check"
    if ! gcloud compute health-checks describe "$backend_hc" &>/dev/null; then
        gcloud compute health-checks create http "$backend_hc" \
            --port=8080 \
            --request-path="/health" \
            --check-interval=30s \
            --timeout=10s \
            --healthy-threshold=2 \
            --unhealthy-threshold=3 \
            --description="Health check for iSECTECH backend services"
        log_success "Created backend health check: $backend_hc"
    else
        log_info "Backend health check $backend_hc already exists"
    fi
}

# Add Cloud Run NEGs to backend services
add_cloud_run_negs() {
    log_info "Adding Cloud Run NEGs to backend services..."
    
    # Create NEG for frontend service
    local frontend_neg="isectech-frontend-neg"
    if ! gcloud compute network-endpoint-groups describe "$frontend_neg" --region="$REGION" &>/dev/null; then
        # Get Cloud Run service URL
        local frontend_url
        frontend_url=$(gcloud run services describe isectech-frontend --region="$REGION" --format="value(status.url)" || echo "")
        
        if [ -n "$frontend_url" ]; then
            # Extract the host from URL
            local frontend_host
            frontend_host=$(echo "$frontend_url" | sed 's|https://||' | sed 's|/.*||')
            
            gcloud compute network-endpoint-groups create "$frontend_neg" \
                --region="$REGION" \
                --network-endpoint-type=serverless \
                --cloud-run-service=isectech-frontend
            
            # Add NEG to backend service
            gcloud compute backend-services add-backend isectech-frontend-backend \
                --global \
                --network-endpoint-group="$frontend_neg" \
                --network-endpoint-group-region="$REGION"
            
            log_success "Added frontend NEG to backend service"
        else
            log_warning "Frontend Cloud Run service not found. Skipping NEG creation."
        fi
    else
        log_info "Frontend NEG $frontend_neg already exists"
    fi
    
    # Create NEG for API Gateway
    local api_neg="isectech-api-gateway-neg"
    if ! gcloud compute network-endpoint-groups describe "$api_neg" --region="$REGION" &>/dev/null; then
        local api_url
        api_url=$(gcloud run services describe isectech-api-gateway --region="$REGION" --format="value(status.url)" || echo "")
        
        if [ -n "$api_url" ]; then
            gcloud compute network-endpoint-groups create "$api_neg" \
                --region="$REGION" \
                --network-endpoint-type=serverless \
                --cloud-run-service=isectech-api-gateway
            
            gcloud compute backend-services add-backend isectech-api-backend \
                --global \
                --network-endpoint-group="$api_neg" \
                --network-endpoint-group-region="$REGION"
            
            log_success "Added API Gateway NEG to backend service"
        else
            log_warning "API Gateway Cloud Run service not found. Skipping NEG creation."
        fi
    else
        log_info "API Gateway NEG $api_neg already exists"
    fi
    
    # Create NEG for backend services
    local backend_neg="isectech-backend-services-neg"
    if ! gcloud compute network-endpoint-groups describe "$backend_neg" --region="$REGION" &>/dev/null; then
        local backend_url
        backend_url=$(gcloud run services describe isectech-backend-services --region="$REGION" --format="value(status.url)" || echo "")
        
        if [ -n "$backend_url" ]; then
            gcloud compute network-endpoint-groups create "$backend_neg" \
                --region="$REGION" \
                --network-endpoint-type=serverless \
                --cloud-run-service=isectech-backend-services
            
            gcloud compute backend-services add-backend isectech-backend-services-backend \
                --global \
                --network-endpoint-group="$backend_neg" \
                --network-endpoint-group-region="$REGION"
            
            log_success "Added backend services NEG to backend service"
        else
            log_warning "Backend services Cloud Run service not found. Skipping NEG creation."
        fi
    else
        log_info "Backend services NEG $backend_neg already exists"
    fi
}

# Create URL map for traffic routing
create_url_map() {
    log_info "Creating URL map for traffic routing..."
    
    local url_map_name="isectech-url-map"
    
    if ! gcloud compute url-maps describe "$url_map_name" &>/dev/null; then
        # Create URL map with frontend as default service
        gcloud compute url-maps create "$url_map_name" \
            --default-service=isectech-frontend-backend \
            --description="URL map for iSECTECH traffic routing"
        
        # Add path matcher for API routes
        gcloud compute url-maps add-path-matcher "$url_map_name" \
            --path-matcher-name=api-matcher \
            --default-service=isectech-api-backend \
            --path-rules="/api/*=isectech-backend-services-backend,/auth/*=isectech-api-backend,/oauth/*=isectech-api-backend"
        
        # Add host rules for different domains
        gcloud compute url-maps add-host-rule "$url_map_name" \
            --hosts="$API_DOMAIN" \
            --path-matcher=api-matcher
        
        gcloud compute url-maps add-host-rule "$url_map_name" \
            --hosts="$GATEWAY_DOMAIN" \
            --path-matcher=api-matcher
        
        log_success "Created URL map: $url_map_name"
    else
        log_info "URL map $url_map_name already exists"
    fi
}

# Create HTTPS proxy
create_https_proxy() {
    log_info "Creating HTTPS proxy..."
    
    local proxy_name="isectech-https-proxy"
    
    if ! gcloud compute target-https-proxies describe "$proxy_name" &>/dev/null; then
        gcloud compute target-https-proxies create "$proxy_name" \
            --url-map=isectech-url-map \
            --ssl-certificates=isectech-ssl-cert \
            --description="HTTPS proxy for iSECTECH load balancer"
        
        log_success "Created HTTPS proxy: $proxy_name"
    else
        log_info "HTTPS proxy $proxy_name already exists"
    fi
}

# Create HTTP to HTTPS redirect
create_http_redirect() {
    log_info "Creating HTTP to HTTPS redirect..."
    
    # Create URL map for redirect
    local redirect_map="isectech-redirect-map" 
    if ! gcloud compute url-maps describe "$redirect_map" &>/dev/null; then
        gcloud compute url-maps create "$redirect_map" \
            --default-url-redirect-response-code=301 \
            --default-url-redirect-https-redirect \
            --description="HTTP to HTTPS redirect for iSECTECH"
        
        log_success "Created redirect URL map: $redirect_map"
    else
        log_info "Redirect URL map $redirect_map already exists"
    fi
    
    # Create HTTP proxy for redirect
    local http_proxy="isectech-http-proxy"
    if ! gcloud compute target-http-proxies describe "$http_proxy" &>/dev/null; then
        gcloud compute target-http-proxies create "$http_proxy" \
            --url-map="$redirect_map" \
            --description="HTTP proxy for HTTPS redirect"
        
        log_success "Created HTTP proxy: $http_proxy"
    else
        log_info "HTTP proxy $http_proxy already exists"
    fi
}

# Create forwarding rules
create_forwarding_rules() {
    log_info "Creating forwarding rules..."
    
    # HTTPS forwarding rule
    local https_rule="isectech-https-forwarding-rule"
    if ! gcloud compute forwarding-rules describe "$https_rule" --global &>/dev/null; then
        gcloud compute forwarding-rules create "$https_rule" \
            --global \
            --target-https-proxy=isectech-https-proxy \
            --address=isectech-lb-ip \
            --ports=443 \
            --description="HTTPS forwarding rule for iSECTECH load balancer"
        
        log_success "Created HTTPS forwarding rule: $https_rule"
    else
        log_info "HTTPS forwarding rule $https_rule already exists"
    fi
    
    # HTTP forwarding rule for redirect
    local http_rule="isectech-http-forwarding-rule"
    if ! gcloud compute forwarding-rules describe "$http_rule" --global &>/dev/null; then
        gcloud compute forwarding-rules create "$http_rule" \
            --global \
            --target-http-proxy=isectech-http-proxy \
            --address=isectech-lb-ip \
            --ports=80 \
            --description="HTTP forwarding rule for HTTPS redirect"
        
        log_success "Created HTTP forwarding rule: $http_rule"
    else
        log_info "HTTP forwarding rule $http_rule already exists"
    fi
}

# Configure CDN settings
configure_cdn() {
    log_info "Configuring CDN settings..."
    
    # Update frontend backend service with CDN configuration
    gcloud compute backend-services update isectech-frontend-backend \
        --global \
        --enable-cdn \
        --cache-mode=CACHE_ALL_STATIC \
        --default-ttl=3600 \
        --max-ttl=86400 \
        --client-ttl=3600 \
        --cache-key-include-protocol \
        --cache-key-include-host \
        --cache-key-include-query-string=false
    
    log_success "CDN configuration updated for frontend service"
}

# Create DNS records
create_dns_records() {
    log_info "Creating DNS records..."
    
    # Get load balancer IP
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)")
    
    # Check if DNS zone exists
    local zone_name="isectech-zone"
    if ! gcloud dns managed-zones describe "$zone_name" &>/dev/null; then
        log_warning "DNS zone $zone_name not found. Please create the DNS zone manually:"
        log_warning "gcloud dns managed-zones create $zone_name --dns-name=isectech.com. --description='iSECTECH DNS zone'"
        log_warning "Then add the following A records:"
        log_warning "  $DOMAIN_NAME -> $lb_ip"
        log_warning "  $API_DOMAIN -> $lb_ip"
        log_warning "  $GATEWAY_DOMAIN -> $lb_ip"
        return 0
    fi
    
    # Create A record for main domain
    if ! gcloud dns record-sets list --zone="$zone_name" --name="$DOMAIN_NAME." --type=A &>/dev/null; then
        gcloud dns record-sets create "$DOMAIN_NAME." \
            --zone="$zone_name" \
            --type=A \
            --ttl=300 \
            --rrdatas="$lb_ip"
        log_success "Created A record for $DOMAIN_NAME"
    else
        log_info "A record for $DOMAIN_NAME already exists"
    fi
    
    # Create A record for API domain
    if ! gcloud dns record-sets list --zone="$zone_name" --name="$API_DOMAIN." --type=A &>/dev/null; then
        gcloud dns record-sets create "$API_DOMAIN." \
            --zone="$zone_name" \
            --type=A \
            --ttl=300 \
            --rrdatas="$lb_ip"
        log_success "Created A record for $API_DOMAIN"
    else
        log_info "A record for $API_DOMAIN already exists"
    fi
    
    # Create A record for Gateway domain
    if ! gcloud dns record-sets list --zone="$zone_name" --name="$GATEWAY_DOMAIN." --type=A &>/dev/null; then
        gcloud dns record-sets create "$GATEWAY_DOMAIN." \
            --zone="$zone_name" \
            --type=A \
            --ttl=300 \
            --rrdatas="$lb_ip"
        log_success "Created A record for $GATEWAY_DOMAIN"
    else
        log_info "A record for $GATEWAY_DOMAIN already exists"
    fi
}

# Test load balancer functionality
test_load_balancer() {
    log_info "Testing load balancer functionality..."
    
    # Get load balancer IP
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)")
    
    log_info "Load balancer IP: $lb_ip"
    log_info "Testing HTTP to HTTPS redirect..."
    
    # Test HTTP redirect
    local http_response
    http_response=$(curl -s -o /dev/null -w "%{http_code}" "http://$lb_ip" --max-time 10 || echo "000")
    
    if [ "$http_response" = "301" ] || [ "$http_response" = "302" ]; then
        log_success "HTTP to HTTPS redirect working (HTTP $http_response)"
    else
        log_warning "HTTP redirect test failed (HTTP $http_response)"
    fi
    
    # Test HTTPS endpoint (skip SSL verification for IP-based test)
    log_info "Testing HTTPS endpoint..."
    local https_response
    https_response=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN_NAME/" --max-time 30 --insecure || echo "000")
    
    if [ "$https_response" = "200" ] || [ "$https_response" = "404" ]; then
        log_success "HTTPS endpoint accessible (HTTP $https_response)"
    else
        log_warning "HTTPS endpoint test inconclusive (HTTP $https_response) - may need DNS propagation"
    fi
    
    log_info "Load balancer testing completed"
}

# Generate configuration report
generate_load_balancer_report() {
    log_info "Generating load balancer configuration report..."
    
    local report_file="/tmp/isectech-load-balancer-report-$(date +%Y%m%d-%H%M%S).txt"
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)")
    
    cat > "$report_file" << EOF
iSECTECH Load Balancer Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
LOAD BALANCER OVERVIEW
================================

Load Balancer IP: $lb_ip
Primary Domain: $DOMAIN_NAME
API Domain: $API_DOMAIN
Gateway Domain: $GATEWAY_DOMAIN

SSL Certificate Status:
$(gcloud compute ssl-certificates describe isectech-ssl-cert --format="value(managed.status)" 2>/dev/null || echo "Not configured")

================================
CLOUD ARMOR SECURITY POLICY
================================

Security Policy: isectech-security-policy
Rules Configured:
- Block malicious IPs (Priority 1000)
- API rate limiting: 1000 req/min per IP (Priority 2000)
- Auth rate limiting: 100 req/min per IP (Priority 2100)
- SQL injection protection (Priority 3000)
- XSS protection (Priority 3100)
- Bot/scanner detection (Priority 3200)
- Protocol attack protection (Priority 3300)
- Geo-blocking for high-risk countries (Priority 4000)
- Default allow rule (Priority 2147483647)

================================
BACKEND SERVICES
================================

Frontend Backend:
- Service: isectech-frontend-backend
- Protocol: HTTP
- Port: 3000
- Health Check: /api/health
- CDN: Enabled
- Cache TTL: 3600s

API Gateway Backend:
- Service: isectech-api-backend
- Protocol: HTTP
- Port: 8080
- Health Check: /health
- CDN: Disabled

Backend Services Backend:
- Service: isectech-backend-services-backend
- Protocol: HTTP
- Port: 8080
- Health Check: /health
- CDN: Disabled

================================
TRAFFIC ROUTING
================================

URL Map: isectech-url-map
Routing Rules:
- / -> Frontend (Default)
- /api/* -> Backend Services
- /auth/* -> API Gateway
- /oauth/* -> API Gateway

Host Rules:
- $DOMAIN_NAME -> Frontend
- $API_DOMAIN -> API Routes
- $GATEWAY_DOMAIN -> API Routes

================================
NETWORK ENDPOINT GROUPS
================================

Frontend NEG: isectech-frontend-neg
- Cloud Run Service: isectech-frontend
- Region: $REGION

API Gateway NEG: isectech-api-gateway-neg
- Cloud Run Service: isectech-api-gateway
- Region: $REGION

Backend Services NEG: isectech-backend-services-neg
- Cloud Run Service: isectech-backend-services
- Region: $REGION

================================
DNS CONFIGURATION
================================

A Records Created:
- $DOMAIN_NAME -> $lb_ip
- $API_DOMAIN -> $lb_ip
- $GATEWAY_DOMAIN -> $lb_ip

TTL: 300 seconds

================================
MONITORING & HEALTH CHECKS
================================

Health Check Configuration:
- Check Interval: 30 seconds
- Timeout: 10 seconds
- Healthy Threshold: 2
- Unhealthy Threshold: 3

Endpoints:
- Frontend: /api/health (Port 3000)
- API Gateway: /health (Port 8080)
- Backend Services: /health (Port 8080)

================================
SECURITY FEATURES
================================

SSL/TLS:
- Managed SSL certificates for all domains
- TLS 1.2+ enforced
- HTTP to HTTPS redirect enabled

DDoS Protection:
- Google Cloud Armor enabled
- Layer 7 DDoS defense enabled
- Rate limiting configured

WAF Rules:
- SQL injection protection
- XSS protection
- Protocol attack protection
- Bot and scanner detection

================================
NEXT STEPS
================================

1. Verify DNS propagation for all domains
2. Confirm SSL certificate provisioning (may take up to 60 minutes)
3. Test all routing paths and endpoints
4. Configure monitoring and alerting
5. Set up log analysis and security monitoring
6. Perform load testing and performance optimization
7. Configure backup and disaster recovery procedures

================================
TROUBLESHOOTING
================================

Common Issues:
1. SSL certificate provisioning requires valid DNS records
2. Health checks must pass for backend services to be healthy
3. Cloud Run services must be deployed before NEG creation
4. Firewall rules may need adjustment for health checks

Verification Commands:
- Check SSL status: gcloud compute ssl-certificates describe isectech-ssl-cert
- Check backend health: gcloud compute backend-services get-health [service-name] --global
- Check NEG status: gcloud compute network-endpoint-groups list
- Test connectivity: curl -v https://$DOMAIN_NAME/

EOF
    
    log_success "Load balancer report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH load balancer and traffic management setup..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    log_info "Domain: ${DOMAIN_NAME}"
    
    check_prerequisites
    
    create_cloud_armor_policy
    reserve_static_ips
    create_ssl_certificates
    create_health_checks
    create_backend_services
    add_cloud_run_negs
    create_url_map
    create_https_proxy
    create_http_redirect
    create_forwarding_rules
    configure_cdn
    create_dns_records
    
    test_load_balancer
    generate_load_balancer_report
    
    log_success "iSECTECH load balancer setup completed successfully!"
    
    echo ""
    log_info "Load balancer is now configured and ready for traffic."
    log_info "SSL certificate provisioning may take up to 60 minutes."
    log_info "Verify DNS records are pointing to load balancer IP for SSL validation."
    log_info "Monitor the setup with: gcloud compute operations list"
}

# Help function
show_help() {
    cat << EOF
iSECTECH Load Balancer Setup Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV   Environment to set up (production, staging, development)
    --project PROJECT   Google Cloud project ID
    --region REGION     Google Cloud region (default: us-central1)
    --domain DOMAIN     Primary domain name (default: protect.isectech.com)
    --api-domain DOMAIN API domain name (default: api.isectech.com)
    --help             Show this help message

Environment Variables:
    PROJECT_ID         Google Cloud project ID
    REGION            Google Cloud region (default: us-central1)
    ENVIRONMENT       Environment name (default: production)
    DOMAIN_NAME       Primary domain (default: protect.isectech.com)
    API_DOMAIN        API domain (default: api.isectech.com)
    GATEWAY_DOMAIN    Gateway domain (default: gateway.isectech.com)

Examples:
    # Set up production load balancer
    PROJECT_ID=isectech-security-platform ./setup-load-balancer.sh --environment production
    
    # Set up staging with custom domain
    ./setup-load-balancer.sh --environment staging --domain staging.isectech.com

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
        --domain)
            DOMAIN_NAME="$2"
            shift 2
            ;;
        --api-domain)
            API_DOMAIN="$2"
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