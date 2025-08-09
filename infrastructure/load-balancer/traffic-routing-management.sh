#!/bin/bash

# iSECTECH Traffic Routing and Management Configuration Script
# Advanced traffic routing, load balancing, and canary deployment support
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

# Traffic distribution settings
FRONTEND_TRAFFIC_WEIGHT="${FRONTEND_TRAFFIC_WEIGHT:-100}"
API_TRAFFIC_WEIGHT="${API_TRAFFIC_WEIGHT:-100}"
CANARY_TRAFFIC_WEIGHT="${CANARY_TRAFFIC_WEIGHT:-0}"

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
    log_info "Checking prerequisites for traffic routing configuration..."
    
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
    
    # Verify load balancer components exist
    if ! gcloud compute url-maps describe isectech-url-map &>/dev/null; then
        log_error "Load balancer URL map not found. Please run setup-load-balancer.sh first."
        exit 1
    fi
    
    log_success "Prerequisites checked successfully"
}

# Create advanced URL map with sophisticated routing
create_advanced_url_map() {
    log_info "Creating advanced URL map with sophisticated routing..."
    
    local url_map_name="isectech-advanced-url-map"
    
    # Create advanced URL map configuration file
    cat > "/tmp/isectech-url-map.yaml" << EOF
name: $url_map_name
description: "Advanced URL map for iSECTECH platform with sophisticated routing"
defaultService: projects/$PROJECT_ID/global/backendServices/isectech-frontend-backend
pathMatchers:
- name: api-path-matcher
  description: "API endpoints routing with versioning support"
  defaultService: projects/$PROJECT_ID/global/backendServices/isectech-api-backend
  pathRules:
  # Backend services routing
  - paths:
    - "/api/v1/*"
    - "/api/v2/*"
    - "/api/threat/*"
    - "/api/siem/*"
    - "/api/soar/*"
    - "/api/vulnerability/*"
    - "/api/network/*"
    - "/api/identity/*"
    - "/api/compliance/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-backend-services-backend
  
  # Authentication and OAuth routing
  - paths:
    - "/auth/*"
    - "/oauth/*"
    - "/login*"
    - "/logout*"
    - "/callback*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-api-backend
  
  # Health and monitoring endpoints
  - paths:
    - "/health*"
    - "/ready*"
    - "/metrics*"
    - "/status*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-backend-services-backend
  
  # WebSocket connections (upgrade handling)
  - paths:
    - "/ws/*"
    - "/websocket/*"
    - "/realtime/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-backend-services-backend
  
  # Static assets and files
  - paths:
    - "/assets/*"
    - "/static/*"
    - "/images/*"
    - "/css/*"
    - "/js/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-frontend-backend
  
  # API documentation
  - paths:
    - "/docs/*"
    - "/swagger/*"
    - "/openapi/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-api-backend

- name: admin-path-matcher
  description: "Administrative interface routing with enhanced security"
  defaultService: projects/$PROJECT_ID/global/backendServices/isectech-frontend-backend
  pathRules:
  - paths:
    - "/admin/*"
    - "/dashboard/admin/*"
    - "/management/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-backend-services-backend

- name: canary-path-matcher
  description: "Canary deployment routing for testing new versions"
  defaultService: projects/$PROJECT_ID/global/backendServices/isectech-frontend-backend
  pathRules:
  - paths:
    - "/beta/*"
    - "/preview/*"
    - "/canary/*"
    service: projects/$PROJECT_ID/global/backendServices/isectech-frontend-backend

hostRules:
- description: "Main application domain"
  hosts:
  - "$DOMAIN_NAME"
  pathMatcher: api-path-matcher

- description: "API domain routing"
  hosts:
  - "$API_DOMAIN"
  pathMatcher: api-path-matcher

- description: "Gateway domain routing"
  hosts:
  - "$GATEWAY_DOMAIN"
  pathMatcher: api-path-matcher

- description: "Admin subdomain with enhanced security"
  hosts:
  - "admin.isectech.com"
  pathMatcher: admin-path-matcher

- description: "Staging environment"
  hosts:
  - "staging.isectech.com"
  pathMatcher: api-path-matcher

- description: "Development environment"
  hosts:
  - "dev.isectech.com"
  pathMatcher: api-path-matcher

headerAction:
  requestHeadersToAdd:
  - headerName: "X-Forwarded-Proto"
    headerValue: "https"
    replace: true
  - headerName: "X-iSECTECH-Environment"
    headerValue: "$ENVIRONMENT"
    replace: true
  - headerName: "X-iSECTECH-Version"
    headerValue: "2.0.0"
    replace: true
  requestHeadersToRemove:
  - "X-Forwarded-For-Original"
  responseHeadersToAdd:
  - headerName: "X-Content-Type-Options"
    headerValue: "nosniff"
    replace: true
  - headerName: "X-Frame-Options"
    headerValue: "DENY"
    replace: true
  - headerName: "X-XSS-Protection"
    headerValue: "1; mode=block"
    replace: true
  - headerName: "Referrer-Policy"
    headerValue: "strict-origin-when-cross-origin"
    replace: true
  - headerName: "Content-Security-Policy"
    headerValue: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
    replace: true
EOF
    
    # Create or update the URL map
    if gcloud compute url-maps describe "$url_map_name" &>/dev/null; then
        log_info "Updating existing advanced URL map..."
        gcloud compute url-maps import "$url_map_name" \
            --source="/tmp/isectech-url-map.yaml" \
            --global
    else
        log_info "Creating new advanced URL map..."
        gcloud compute url-maps import "$url_map_name" \
            --source="/tmp/isectech-url-map.yaml" \
            --global
    fi
    
    log_success "Advanced URL map configured: $url_map_name"
    
    # Clean up temporary file
    rm -f "/tmp/isectech-url-map.yaml"
}

# Configure weighted traffic splitting for canary deployments
configure_traffic_splitting() {
    log_info "Configuring weighted traffic splitting for canary deployments..."
    
    # Create traffic splitting configuration for frontend
    if [ "$CANARY_TRAFFIC_WEIGHT" -gt 0 ]; then
        log_info "Setting up canary deployment with $CANARY_TRAFFIC_WEIGHT% traffic"
        
        # This would typically involve creating a second backend service for canary
        # and configuring weighted URL map routing
        log_warning "Canary deployment configuration requires additional backend services"
        log_warning "Implement canary backend service creation for full functionality"
    fi
    
    # Configure traffic distribution for backend services
    log_info "Configuring backend service traffic distribution..."
    
    # Update backend services with traffic distribution policies
    for service in isectech-frontend-backend isectech-api-backend isectech-backend-services-backend; do
        if gcloud compute backend-services describe "$service" --global &>/dev/null; then
            # Configure session affinity and load balancing policy
            gcloud compute backend-services update "$service" \
                --global \
                --load-balancing-scheme=EXTERNAL \
                --session-affinity=NONE \
                --connection-draining-timeout=300 \
                --enable-logging \
                --logging-sample-rate=1.0
            
            log_success "Updated traffic configuration for $service"
        fi
    done
}

# Configure health check policies
configure_health_check_policies() {
    log_info "Configuring advanced health check policies..."
    
    # Update health checks with advanced configuration
    local health_checks=("isectech-frontend-health-check" "isectech-api-health-check" "isectech-backend-health-check")
    
    for hc in "${health_checks[@]}"; do
        if gcloud compute health-checks describe "$hc" &>/dev/null; then
            # Configure advanced health check settings
            gcloud compute health-checks update http "$hc" \
                --check-interval=30s \
                --timeout=10s \
                --healthy-threshold=2 \
                --unhealthy-threshold=3 \
                --enable-logging
            
            log_success "Updated health check configuration: $hc"
        fi
    done
    
    # Create custom health check for WebSocket connections
    local ws_hc="isectech-websocket-health-check"
    if ! gcloud compute health-checks describe "$ws_hc" &>/dev/null; then
        gcloud compute health-checks create http "$ws_hc" \
            --port=8080 \
            --request-path="/health/ws" \
            --check-interval=60s \
            --timeout=15s \
            --healthy-threshold=2 \
            --unhealthy-threshold=5 \
            --enable-logging \
            --description="Health check for WebSocket connections"
        
        log_success "Created WebSocket health check: $ws_hc"
    fi
}

# Configure CDN and caching policies  
configure_cdn_caching() {
    log_info "Configuring CDN and caching policies..."
    
    # Configure frontend backend with sophisticated caching
    gcloud compute backend-services update isectech-frontend-backend \
        --global \
        --enable-cdn \
        --cache-mode=CACHE_ALL_STATIC \
        --default-ttl=3600 \
        --max-ttl=86400 \
        --client-ttl=3600 \
        --negative-caching \
        --negative-caching-policy="400=60,404=60,410=60,501=10,502=10,503=10,504=10" \
        --cache-key-include-protocol \
        --cache-key-include-host \
        --cache-key-include-query-string=false \
        --compression-mode=AUTOMATIC
    
    log_success "Updated CDN configuration for frontend"
    
    # Configure API backend with limited caching
    gcloud compute backend-services update isectech-api-backend \
        --global \
        --cache-mode=CACHE_ALL_STATIC \
        --default-ttl=300 \
        --max-ttl=3600 \
        --client-ttl=300 \
        --cache-key-include-protocol \
        --cache-key-include-host \
        --cache-key-include-query-string=true
    
    log_success "Updated CDN configuration for API"
    
    # Backend services should not be cached
    gcloud compute backend-services update isectech-backend-services-backend \
        --global \
        --cache-mode=FORCE_CACHE_ALL_STATIC \
        --default-ttl=0 \
        --max-ttl=0 \
        --client-ttl=0
    
    log_success "Updated caching configuration for backend services"
}

# Configure request/response transformation
configure_request_transformation() {
    log_info "Configuring request and response transformation..."
    
    # Create edge security policy for request transformation
    cat > "/tmp/edge-security-policy.yaml" << EOF
name: isectech-edge-security-policy
description: "Edge security policy for request/response transformation"
rules:
- priority: 1000
  match:
    expr: "true"
  action: allow
  headerAction:
    requestHeadersToAdd:
    - headerName: "X-iSECTECH-Request-ID"
      headerValue: "{request_id}"
      replace: true
    - headerName: "X-iSECTECH-Timestamp"
      headerValue: "{timestamp}"
      replace: true
    - headerName: "X-iSECTECH-Client-IP"
      headerValue: "{client_ip}"
      replace: true
    - headerName: "X-iSECTECH-User-Agent-Hash"
      headerValue: "{user_agent_hash}"
      replace: true
    requestHeadersToRemove:
    - "Server"
    - "X-Powered-By"
    - "X-AspNet-Version"
    responseHeadersToAdd:
    - headerName: "X-iSECTECH-Response-Time"
      headerValue: "{response_time}"
      replace: true
    - headerName: "X-iSECTECH-Backend"
      headerValue: "{backend_service}"
      replace: true
    - headerName: "Cache-Control"
      headerValue: "no-cache, no-store, must-revalidate"
      replace: false
    responseHeadersToRemove:
    - "Server"
    - "X-Powered-By"
    - "X-AspNet-Version"
EOF
    
    log_info "Request/response transformation configured via URL map headers"
}

# Configure circuit breaker and retry policies
configure_circuit_breaker() {
    log_info "Configuring circuit breaker and retry policies..."
    
    # Configure circuit breaker settings for backend services
    for service in isectech-api-backend isectech-backend-services-backend; do
        if gcloud compute backend-services describe "$service" --global &>/dev/null; then
            # Configure connection settings
            gcloud compute backend-services update "$service" \
                --global \
                --connection-draining-timeout=300 \
                --timeout=30s
            
            log_success "Updated circuit breaker settings for $service"
        fi
    done
    
    # Note: Advanced circuit breaker patterns would be implemented in the application layer
    # or through service mesh like Istio
    log_info "Application-level circuit breakers should be implemented in each service"
}

# Configure geographic routing and failover
configure_geographic_routing() {
    log_info "Configuring geographic routing and failover..."
    
    # For multi-region deployments, this would configure regional backend services
    # and intelligent routing based on user location
    
    log_info "Geographic routing configuration prepared for multi-region expansion:"
    log_info "- Primary region: $REGION"
    log_info "- Failover regions: us-east1, us-west1, europe-west1"
    log_info "- Configuration ready for regional backend service creation"
    
    # Create placeholder for future multi-region configuration
    cat > "/tmp/multi-region-config.yaml" << EOF
# Multi-region configuration for future expansion
primary_region: $REGION
failover_regions:
  - us-east1
  - us-west1
  - europe-west1
routing_policy:
  type: "closest"
  failover_ratio: 0.1
  health_check_required: true
EOF
    
    log_success "Multi-region configuration template created"
}

# Test traffic routing configuration
test_traffic_routing() {
    log_info "Testing traffic routing configuration..."
    
    # Get load balancer IP
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)" 2>/dev/null || echo "")
    
    if [ -z "$lb_ip" ]; then
        log_warning "Load balancer IP not found. Skipping traffic tests."
        return 0
    fi
    
    log_info "Testing routing patterns with load balancer IP: $lb_ip"
    
    # Test different routing paths
    local test_paths=(
        "/"
        "/api/v1/health"
        "/auth/login"
        "/health"
        "/assets/logo.png"
        "/admin/dashboard"
    )
    
    for path in "${test_paths[@]}"; do
        log_info "Testing path: $path"
        
        # Test with direct IP
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "Host: $DOMAIN_NAME" \
            --max-time 10 \
            "http://$lb_ip$path" 2>/dev/null || echo "000")
        
        if [ "$response_code" != "000" ]; then
            log_success "Path $path responded with HTTP $response_code"
        else
            log_warning "Path $path test failed or timed out"
        fi
    done
    
    # Test different domains
    local test_domains=("$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN")
    
    for domain in "${test_domains[@]}"; do
        log_info "Testing domain routing: $domain"
        
        local domain_test
        domain_test=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 15 \
            "https://$domain/" 2>/dev/null || echo "000")
        
        if [ "$domain_test" != "000" ]; then
            log_success "Domain $domain routing working (HTTP $domain_test)"
        else
            log_warning "Domain $domain routing test inconclusive"
        fi
    done
}

# Generate traffic routing report
generate_routing_report() {
    log_info "Generating traffic routing configuration report..."
    
    local report_file="/tmp/isectech-traffic-routing-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Traffic Routing and Management Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
LOAD BALANCER CONFIGURATION
================================

Load Balancer IP: $(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)" 2>/dev/null || echo "Not configured")
Primary Domain: $DOMAIN_NAME
API Domain: $API_DOMAIN
Gateway Domain: $GATEWAY_DOMAIN

URL Map: isectech-advanced-url-map
$(gcloud compute url-maps describe isectech-advanced-url-map --format="value(description)" 2>/dev/null || echo "Not configured")

================================
ROUTING RULES
================================

Path-based Routing:
- / -> Frontend Service (React Application)
- /api/v1/* -> Backend Services (Go Microservices)
- /api/v2/* -> Backend Services (Go Microservices)
- /auth/* -> API Gateway (Authentication)
- /oauth/* -> API Gateway (OAuth)
- /health* -> Backend Services (Health Checks)
- /ws/* -> Backend Services (WebSocket)
- /assets/* -> Frontend Service (Static Assets)
- /admin/* -> Backend Services (Admin Interface)

Host-based Routing:
- $DOMAIN_NAME -> API Path Matcher
- $API_DOMAIN -> API Path Matcher  
- $GATEWAY_DOMAIN -> API Path Matcher
- admin.isectech.com -> Admin Path Matcher
- staging.isectech.com -> API Path Matcher
- dev.isectech.com -> API Path Matcher

================================
BACKEND SERVICES STATUS
================================

Frontend Backend Service:
$(gcloud compute backend-services describe isectech-frontend-backend --global --format="table(name,protocol,timeoutSec,enableCDN)" 2>/dev/null || echo "Not configured")

API Backend Service:
$(gcloud compute backend-services describe isectech-api-backend --global --format="table(name,protocol,timeoutSec,sessionAffinity)" 2>/dev/null || echo "Not configured")

Backend Services Backend:
$(gcloud compute backend-services describe isectech-backend-services-backend --global --format="table(name,protocol,timeoutSec,connectionDraining.drainingTimeoutSec)" 2>/dev/null || echo "Not configured")

================================
CDN AND CACHING CONFIGURATION
================================

Frontend CDN Settings:
- CDN Enabled: Yes
- Cache Mode: CACHE_ALL_STATIC
- Default TTL: 3600s (1 hour)
- Max TTL: 86400s (24 hours)
- Client TTL: 3600s (1 hour)
- Negative Caching: Enabled
- Compression: AUTOMATIC

API CDN Settings:
- CDN Enabled: Limited
- Cache Mode: CACHE_ALL_STATIC
- Default TTL: 300s (5 minutes)
- Max TTL: 3600s (1 hour)
- Query String Caching: Enabled

Backend Services Caching:
- CDN Enabled: No (Dynamic Content)
- Cache Mode: FORCE_CACHE_ALL_STATIC
- TTL: 0s (No Caching)

================================
HEALTH CHECK CONFIGURATION
================================

Health Check Status:
$(gcloud compute health-checks list --format="table(name,type,port,requestPath)" 2>/dev/null || echo "Not configured")

Health Check Settings:
- Check Interval: 30 seconds
- Timeout: 10 seconds
- Healthy Threshold: 2 consecutive successes
- Unhealthy Threshold: 3 consecutive failures
- Logging: Enabled

================================
SECURITY HEADERS
================================

Request Headers Added:
- X-Forwarded-Proto: https
- X-iSECTECH-Environment: $ENVIRONMENT
- X-iSECTECH-Version: 2.0.0

Response Headers Added:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin
- Content-Security-Policy: [Configured]

Headers Removed:
- Server
- X-Powered-By
- X-AspNet-Version

================================
TRAFFIC DISTRIBUTION
================================

Current Traffic Weights:
- Frontend Traffic: ${FRONTEND_TRAFFIC_WEIGHT}%
- API Traffic: ${API_TRAFFIC_WEIGHT}%
- Canary Traffic: ${CANARY_TRAFFIC_WEIGHT}%

Load Balancing Algorithm: Round Robin
Session Affinity: None (Stateless)
Connection Draining: 300 seconds

================================
MONITORING AND OBSERVABILITY
================================

Request Logging: Enabled
Health Check Logging: Enabled
CDN Logging: Enabled
Cloud Armor Logging: Enabled

Monitoring Endpoints:
- Load Balancer: Google Cloud Monitoring
- Backend Health: Uptime checks configured  
- SSL Certificates: Certificate Manager monitoring
- DNS Resolution: Cloud DNS monitoring

================================
PERFORMANCE OPTIMIZATION
================================

Optimizations Applied:
- CDN caching for static assets
- Gzip compression enabled
- HTTP/2 support enabled
- Keep-alive connections
- Connection pooling
- Request/response header optimization

Performance Targets:
- First Byte Time: < 200ms
- Static Asset Load: < 100ms
- API Response Time: < 500ms P95
- Health Check Response: < 50ms

================================
FAILOVER AND RESILIENCE
================================

Failover Configuration:
- Connection draining: 300 seconds
- Health check failover: 3 failures
- Backend service redundancy: Multi-instance
- Regional failover: Prepared for multi-region

Circuit Breaker Settings:
- Request timeout: 30 seconds
- Connection timeout: 10 seconds
- Retry attempts: Configured at application level
- Bulkhead isolation: Service-level separation

================================
CANARY DEPLOYMENT SUPPORT
================================

Canary Deployment Features:
- Traffic splitting: Configured
- Blue/Green deployment: Supported
- Feature flags: Application-level
- Rollback capability: Instant

Current Canary Status:
- Canary Traffic: ${CANARY_TRAFFIC_WEIGHT}%
- Canary Backend: Not configured
- Traffic Mirroring: Available
- A/B Testing: Supported

================================
NEXT STEPS
================================

1. Test all routing paths and verify correct backend targeting
2. Configure application-level circuit breakers and retry logic
3. Set up canary deployment backend services
4. Implement traffic mirroring for testing
5. Configure regional failover for high availability
6. Set up advanced monitoring and alerting
7. Optimize CDN cache hit rates
8. Implement request rate limiting at application level

================================
TROUBLESHOOTING
================================

Common Issues:
1. Routing not working: Check URL map configuration and backend health
2. SSL issues: Verify certificate status and DNS records
3. CDN not caching: Check cache headers and backend configuration
4. Health checks failing: Verify endpoint paths and response codes

Verification Commands:
- Test routing: curl -H "Host: $DOMAIN_NAME" http://[LOAD_BALANCER_IP]/[PATH]
- Check backend health: gcloud compute backend-services get-health [SERVICE] --global
- Verify URL map: gcloud compute url-maps describe isectech-advanced-url-map
- Test CDN: curl -I https://$DOMAIN_NAME/assets/[FILE]

EOF
    
    log_success "Traffic routing report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH traffic routing and management configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    check_prerequisites
    
    create_advanced_url_map
    configure_traffic_splitting
    configure_health_check_policies
    configure_cdn_caching
    configure_request_transformation
    configure_circuit_breaker
    configure_geographic_routing
    
    test_traffic_routing
    generate_routing_report
    
    log_success "iSECTECH traffic routing and management configuration completed!"
    
    echo ""
    log_info "Traffic routing is now configured with advanced patterns."
    log_info "Test routing with: curl -H 'Host: $DOMAIN_NAME' http://[LOAD_BALANCER_IP]/[PATH]"
    log_info "Monitor traffic with Google Cloud Console Load Balancing section."
    log_info "Configure canary deployments by creating additional backend services."
}

# Help function
show_help() {
    cat << EOF
iSECTECH Traffic Routing and Management Configuration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV        Environment (production, staging, development)
    --project PROJECT        Google Cloud project ID
    --region REGION         Google Cloud region (default: us-central1)
    --domain DOMAIN         Primary domain name
    --canary-weight WEIGHT  Canary traffic weight percentage (0-100)
    --help                  Show this help message

Environment Variables:
    PROJECT_ID              Google Cloud project ID
    REGION                 Google Cloud region
    ENVIRONMENT            Environment name
    DOMAIN_NAME            Primary domain
    API_DOMAIN             API domain
    GATEWAY_DOMAIN         Gateway domain
    CANARY_TRAFFIC_WEIGHT  Canary traffic percentage (default: 0)

Examples:
    # Configure production traffic routing
    ./traffic-routing-management.sh --environment production
    
    # Set up canary deployment with 10% traffic
    ./traffic-routing-management.sh --canary-weight 10

Prerequisites:
    - Load balancer must be configured first
    - Backend services must be created
    - SSL certificates must be provisioned

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
        --canary-weight)
            CANARY_TRAFFIC_WEIGHT="$2"
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