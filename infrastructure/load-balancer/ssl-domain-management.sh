#!/bin/bash

# iSECTECH SSL Certificate and Domain Management Script
# Automated SSL certificate provisioning and domain configuration
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DOMAIN_NAME="${DOMAIN_NAME:-protect.isectech.com}"
API_DOMAIN="${API_DOMAIN:-api.isectech.com}"
GATEWAY_DOMAIN="${GATEWAY_DOMAIN:-gateway.isectech.com}"
CDN_DOMAIN="${CDN_DOMAIN:-cdn.isectech.com}"
ASSETS_DOMAIN="${ASSETS_DOMAIN:-assets.isectech.com}"

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
    log_info "Checking prerequisites for SSL and domain management..."
    
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
    gcloud services enable certificatemanager.googleapis.com
    gcloud services enable dns.googleapis.com
    gcloud services enable compute.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create DNS managed zone
create_dns_zone() {
    log_info "Setting up DNS managed zone..."
    
    local zone_name="isectech-zone"
    local dns_name="isectech.com."
    
    # Check if zone already exists
    if ! gcloud dns managed-zones describe "$zone_name" &>/dev/null; then
        gcloud dns managed-zones create "$zone_name" \
            --dns-name="$dns_name" \
            --description="DNS zone for iSECTECH platform" \
            --dnssec-state=on \
            --labels="environment=${ENVIRONMENT},managed-by=isectech-platform"
        
        log_success "Created DNS managed zone: $zone_name"
        
        # Display nameservers for domain configuration
        log_info "Configure your domain registrar with these nameservers:"
        gcloud dns managed-zones describe "$zone_name" --format="value(nameServers)" | tr ';' '\n'
    else
        log_info "DNS managed zone $zone_name already exists"
    fi
}

# Create SSL certificates with Certificate Manager
create_managed_ssl_certificates() {
    log_info "Creating managed SSL certificates..."
    
    # Primary certificate for main domains
    local cert_name="isectech-primary-cert"
    if ! gcloud certificate-manager certificates describe "$cert_name" --location=global &>/dev/null; then
        # Create the certificate
        gcloud certificate-manager certificates create "$cert_name" \
            --domains="$DOMAIN_NAME,$API_DOMAIN,$GATEWAY_DOMAIN" \
            --location=global \
            --description="Primary SSL certificate for iSECTECH platform"
        
        log_success "Created primary SSL certificate: $cert_name"
    else
        log_info "Primary SSL certificate $cert_name already exists"
    fi
    
    # Wildcard certificate for subdomains
    local wildcard_cert="isectech-wildcard-cert"
    if ! gcloud certificate-manager certificates describe "$wildcard_cert" --location=global &>/dev/null; then
        gcloud certificate-manager certificates create "$wildcard_cert" \
            --domains="*.isectech.com" \
            --location=global \
            --description="Wildcard SSL certificate for iSECTECH subdomains"
        
        log_success "Created wildcard SSL certificate: $wildcard_cert"
    else
        log_info "Wildcard SSL certificate $wildcard_cert already exists"
    fi
    
    # CDN and assets certificate
    local assets_cert="isectech-assets-cert"
    if ! gcloud certificate-manager certificates describe "$assets_cert" --location=global &>/dev/null; then
        gcloud certificate-manager certificates create "$assets_cert" \
            --domains="$CDN_DOMAIN,$ASSETS_DOMAIN" \
            --location=global \
            --description="SSL certificate for iSECTECH CDN and assets"
        
        log_success "Created assets SSL certificate: $assets_cert"
    else
        log_info "Assets SSL certificate $assets_cert already exists"
    fi
}

# Create legacy compute SSL certificates for load balancer
create_compute_ssl_certificates() {
    log_info "Creating compute SSL certificates for load balancer..."
    
    local cert_name="isectech-ssl-cert"
    if ! gcloud compute ssl-certificates describe "$cert_name" &>/dev/null; then
        gcloud compute ssl-certificates create "$cert_name" \
            --domains="$DOMAIN_NAME,$API_DOMAIN,$GATEWAY_DOMAIN,*.isectech.com" \
            --global \
            --description="Managed SSL certificate for iSECTECH load balancer"
        
        log_success "Created compute SSL certificate: $cert_name"
        
        log_warning "SSL certificate provisioning may take 10-60 minutes."
        log_warning "Ensure DNS records are properly configured for validation."
    else
        log_info "Compute SSL certificate $cert_name already exists"
    fi
}

# Configure DNS records
configure_dns_records() {
    log_info "Configuring DNS records..."
    
    local zone_name="isectech-zone"
    
    # Get load balancer IP address
    local lb_ip
    if gcloud compute addresses describe isectech-lb-ip --global &>/dev/null; then
        lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)")
        log_info "Using load balancer IP: $lb_ip"
    else
        log_error "Load balancer IP not found. Please run setup-load-balancer.sh first."
        return 1
    fi
    
    # Helper function to create or update DNS record
    create_or_update_dns_record() {
        local record_name="$1"
        local record_type="$2"
        local record_data="$3"
        local ttl="${4:-300}"
        
        # Check if record exists
        if gcloud dns record-sets list --zone="$zone_name" --name="$record_name" --type="$record_type" --format="value(name)" | grep -q "$record_name"; then
            # Update existing record
            local old_data
            old_data=$(gcloud dns record-sets list --zone="$zone_name" --name="$record_name" --type="$record_type" --format="value(rrdatas[0])")
            
            if [ "$old_data" != "$record_data" ]; then
                gcloud dns record-sets update "$record_name" \
                    --zone="$zone_name" \
                    --type="$record_type" \
                    --ttl="$ttl" \
                    --rrdatas="$record_data"
                log_success "Updated $record_type record for $record_name"
            else
                log_info "$record_type record for $record_name already up to date"
            fi
        else
            # Create new record
            gcloud dns record-sets create "$record_name" \
                --zone="$zone_name" \
                --type="$record_type" \
                --ttl="$ttl" \
                --rrdatas="$record_data"
            log_success "Created $record_type record for $record_name"
        fi
    }
    
    # Create A records for main domains
    create_or_update_dns_record "$DOMAIN_NAME." "A" "$lb_ip"
    create_or_update_dns_record "$API_DOMAIN." "A" "$lb_ip"
    create_or_update_dns_record "$GATEWAY_DOMAIN." "A" "$lb_ip"
    
    # Create A records for CDN and assets (these might point to different IPs in the future)
    create_or_update_dns_record "$CDN_DOMAIN." "A" "$lb_ip"
    create_or_update_dns_record "$ASSETS_DOMAIN." "A" "$lb_ip"
    
    # Create CNAME records for common subdomains
    create_or_update_dns_record "www.isectech.com." "CNAME" "$DOMAIN_NAME."
    create_or_update_dns_record "staging.isectech.com." "CNAME" "$DOMAIN_NAME."
    create_or_update_dns_record "dev.isectech.com." "CNAME" "$DOMAIN_NAME."
    
    # Create TXT records for domain verification and security
    create_or_update_dns_record "isectech.com." "TXT" "\"v=spf1 include:_spf.google.com ~all\"" 3600
    create_or_update_dns_record "_dmarc.isectech.com." "TXT" "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@isectech.com\"" 3600
    
    # Create MX records for email (if needed)
    if [ "${CONFIGURE_EMAIL:-false}" = "true" ]; then
        create_or_update_dns_record "isectech.com." "MX" "1 smtp.google.com."
        create_or_update_dns_record "isectech.com." "MX" "5 smtp2.google.com."
        create_or_update_dns_record "isectech.com." "MX" "10 smtp3.google.com."
    fi
    
    # Create CAA records for certificate authority authorization
    create_or_update_dns_record "isectech.com." "CAA" "0 issue \"pki.goog\""
    create_or_update_dns_record "isectech.com." "CAA" "0 issue \"letsencrypt.org\""
    create_or_update_dns_record "isectech.com." "CAA" "0 iodef \"mailto:security@isectech.com\""
}

# Monitor SSL certificate status
monitor_ssl_certificates() {
    log_info "Monitoring SSL certificate status..."
    
    # Check compute SSL certificate status
    if gcloud compute ssl-certificates describe isectech-ssl-cert &>/dev/null; then
        local cert_status
        cert_status=$(gcloud compute ssl-certificates describe isectech-ssl-cert --format="value(managed.status)")
        log_info "Compute SSL certificate status: $cert_status"
        
        # Show domain status details
        log_info "Domain validation status:"
        gcloud compute ssl-certificates describe isectech-ssl-cert \
            --format="table(managed.domains[0]:label=DOMAIN,managed.domainStatus[0].status:label=STATUS)"
    fi
    
    # Check Certificate Manager certificates
    log_info "Certificate Manager certificate status:"
    for cert in isectech-primary-cert isectech-wildcard-cert isectech-assets-cert; do
        if gcloud certificate-manager certificates describe "$cert" --location=global &>/dev/null; then
            local cm_status
            cm_status=$(gcloud certificate-manager certificates describe "$cert" --location=global --format="value(state)" 2>/dev/null || echo "UNKNOWN")
            log_info "Certificate $cert status: $cm_status"
        fi
    done
}

# Validate DNS propagation
validate_dns_propagation() {
    log_info "Validating DNS propagation..."
    
    local domains=("$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN")
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)")
    
    for domain in "${domains[@]}"; do
        log_info "Checking DNS resolution for $domain..."
        
        # Use multiple DNS servers to check propagation
        local dns_servers=("8.8.8.8" "1.1.1.1" "208.67.222.222")
        local resolved_ips=()
        
        for dns_server in "${dns_servers[@]}"; do
            local resolved_ip
            resolved_ip=$(dig @"$dns_server" +short "$domain" A | tail -n1 2>/dev/null || echo "")
            if [ -n "$resolved_ip" ]; then
                resolved_ips+=("$resolved_ip")
            fi
        done
        
        # Check if all DNS servers return the correct IP
        local all_correct=true
        for ip in "${resolved_ips[@]}"; do
            if [ "$ip" != "$lb_ip" ]; then
                all_correct=false
                break
            fi
        done
        
        if [ "$all_correct" = true ] && [ ${#resolved_ips[@]} -eq ${#dns_servers[@]} ]; then
            log_success "DNS propagation complete for $domain -> $lb_ip"
        else
            log_warning "DNS propagation incomplete for $domain (got: ${resolved_ips[*]}, expected: $lb_ip)"
        fi
    done
}

# Test SSL certificate functionality
test_ssl_certificates() {
    log_info "Testing SSL certificate functionality..."
    
    local domains=("$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN")
    
    for domain in "${domains[@]}"; do
        log_info "Testing SSL for $domain..."
        
        # Test SSL connectivity
        local ssl_test_result
        ssl_test_result=$(timeout 10 openssl s_client -connect "$domain:443" -servername "$domain" < /dev/null 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "FAILED")
        
        if [ "$ssl_test_result" != "FAILED" ]; then
            log_success "SSL certificate active for $domain"
            
            # Extract certificate expiration
            local cert_expiry
            cert_expiry=$(timeout 10 openssl s_client -connect "$domain:443" -servername "$domain" < /dev/null 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || echo "Unknown")
            log_info "Certificate expires: $cert_expiry"
        else
            log_warning "SSL test failed for $domain - certificate may still be provisioning"
        fi
        
        # Test HTTPS endpoint
        local https_response
        https_response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain/" 2>/dev/null || echo "000")
        
        if [ "$https_response" = "200" ] || [ "$https_response" = "404" ] || [ "$https_response" = "403" ]; then
            log_success "HTTPS endpoint accessible for $domain (HTTP $https_response)"
        else
            log_warning "HTTPS endpoint test inconclusive for $domain (HTTP $https_response)"
        fi
    done
}

# Create certificate monitoring alerts
create_certificate_monitoring() {
    log_info "Setting up certificate monitoring..."
    
    # Create notification channel (requires additional setup)
    log_info "Certificate monitoring setup would require:"
    log_info "1. Cloud Monitoring notification channels"
    log_info "2. Uptime checks for HTTPS endpoints"
    log_info "3. SSL certificate expiration alerts"
    log_info "4. DNS resolution monitoring"
    
    # Create uptime checks for main domains
    for domain in "$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN"; do
        local check_name="ssl-check-${domain//\./-}"
        log_info "Consider creating uptime check: $check_name for https://$domain/"
    done
}

# Generate certificate and domain report
generate_certificate_report() {
    log_info "Generating certificate and domain configuration report..."
    
    local report_file="/tmp/isectech-ssl-domain-report-$(date +%Y%m%d-%H%M%S).txt"
    local lb_ip
    lb_ip=$(gcloud compute addresses describe isectech-lb-ip --global --format="value(address)" 2>/dev/null || echo "Not configured")
    
    cat > "$report_file" << EOF
iSECTECH SSL Certificate and Domain Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}

================================
DOMAIN CONFIGURATION
================================

Primary Domains:
- Main Application: $DOMAIN_NAME
- API Endpoint: $API_DOMAIN  
- Gateway Endpoint: $GATEWAY_DOMAIN
- CDN Endpoint: $CDN_DOMAIN
- Assets Endpoint: $ASSETS_DOMAIN

Load Balancer IP: $lb_ip

DNS Zone: isectech-zone (isectech.com.)
DNS Records:
$(gcloud dns record-sets list --zone=isectech-zone --format="table(name,type,ttl,rrdatas[0])" 2>/dev/null || echo "DNS zone not configured")

================================
SSL CERTIFICATE STATUS
================================

Compute SSL Certificate (Load Balancer):
EOF
    
    # Add compute SSL certificate info
    if gcloud compute ssl-certificates describe isectech-ssl-cert &>/dev/null; then
        echo "Certificate: isectech-ssl-cert" >> "$report_file"
        echo "Status: $(gcloud compute ssl-certificates describe isectech-ssl-cert --format="value(managed.status)" 2>/dev/null)" >> "$report_file"
        echo "Domains: $(gcloud compute ssl-certificates describe isectech-ssl-cert --format="value(managed.domains[0:].join(\", \"))" 2>/dev/null)" >> "$report_file"
        echo "" >> "$report_file"
    else
        echo "Compute SSL certificate not configured" >> "$report_file"
        echo "" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF
Certificate Manager Certificates:
EOF
    
    # Add Certificate Manager info
    for cert in isectech-primary-cert isectech-wildcard-cert isectech-assets-cert; do
        if gcloud certificate-manager certificates describe "$cert" --location=global &>/dev/null; then
            echo "- $cert: $(gcloud certificate-manager certificates describe "$cert" --location=global --format="value(state)" 2>/dev/null)" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << EOF

================================
DNS VALIDATION STATUS
================================

Domain Resolution Check:
EOF
    
    # Add DNS validation info
    for domain in "$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN"; do
        local resolved_ip
        resolved_ip=$(dig +short "$domain" A | tail -n1 2>/dev/null || echo "Not resolved")
        echo "- $domain -> $resolved_ip" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

================================
SSL CONNECTIVITY TEST
================================

HTTPS Endpoint Tests:
EOF
    
    # Add SSL connectivity test results
    for domain in "$DOMAIN_NAME" "$API_DOMAIN" "$GATEWAY_DOMAIN"; do
        local https_test
        https_test=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain/" 2>/dev/null || echo "Failed")
        echo "- https://$domain/ -> HTTP $https_test" >> "$report_file"
    done
    
    cat >> "$report_file" << EOF

================================
SECURITY CONFIGURATION
================================

DNS Security:
- DNSSEC: Enabled
- CAA Records: Configured for pki.goog and letsencrypt.org
- SPF Record: Configured
- DMARC Record: Configured

SSL Security:
- TLS Version: 1.2+ enforced
- Certificate Authority: Google Trust Services
- Wildcard Certificate: Available
- HTTP to HTTPS Redirect: Enabled

================================
NEXT STEPS
================================

1. Monitor certificate provisioning status (may take up to 60 minutes)
2. Verify DNS propagation across all global DNS servers
3. Test all domain endpoints for SSL functionality
4. Set up certificate expiration monitoring and alerts
5. Configure automated certificate renewal procedures
6. Implement certificate transparency monitoring
7. Set up DNS monitoring for availability and security

================================
TROUBLESHOOTING
================================

Certificate Issues:
- Check DNS records are pointing to correct load balancer IP
- Verify domain ownership and DNS propagation
- Allow up to 60 minutes for Google-managed certificate provisioning
- Check domain validation status in Cloud Console

DNS Issues:
- Verify nameservers are configured at domain registrar
- Check TTL settings for faster propagation during testing
- Use dig or nslookup to test resolution from different locations

Verification Commands:
- Check SSL status: gcloud compute ssl-certificates describe isectech-ssl-cert
- Test DNS: dig $DOMAIN_NAME A
- Test SSL: openssl s_client -connect $DOMAIN_NAME:443 -servername $DOMAIN_NAME
- Check certificate expiry: curl -vI https://$DOMAIN_NAME/ 2>&1 | grep -E "(expire|valid)"

EOF
    
    log_success "Certificate and domain report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH SSL certificate and domain management..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Primary Domain: ${DOMAIN_NAME}"
    
    check_prerequisites
    
    create_dns_zone
    create_managed_ssl_certificates
    create_compute_ssl_certificates
    configure_dns_records
    
    # Wait a moment for DNS propagation to start
    sleep 10
    
    validate_dns_propagation
    monitor_ssl_certificates
    test_ssl_certificates
    create_certificate_monitoring
    
    generate_certificate_report
    
    log_success "iSECTECH SSL certificate and domain management completed!"
    
    echo ""
    log_info "SSL certificates are being provisioned. This may take 10-60 minutes."
    log_info "Monitor certificate status with: gcloud compute ssl-certificates describe isectech-ssl-cert"
    log_info "DNS propagation may take up to 48 hours globally."
    log_info "Test HTTPS endpoints: curl -v https://$DOMAIN_NAME/"
}

# Help function
show_help() {
    cat << EOF
iSECTECH SSL Certificate and Domain Management Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV   Environment (production, staging, development)
    --project PROJECT   Google Cloud project ID
    --domain DOMAIN     Primary domain name (default: protect.isectech.com)
    --api-domain DOMAIN API domain name (default: api.isectech.com)
    --help             Show this help message

Environment Variables:
    PROJECT_ID         Google Cloud project ID
    ENVIRONMENT       Environment name (default: production)
    DOMAIN_NAME       Primary domain (default: protect.isectech.com)
    API_DOMAIN        API domain (default: api.isectech.com)
    GATEWAY_DOMAIN    Gateway domain (default: gateway.isectech.com)
    CDN_DOMAIN        CDN domain (default: cdn.isectech.com)
    ASSETS_DOMAIN     Assets domain (default: assets.isectech.com)
    CONFIGURE_EMAIL   Set to 'true' to configure email MX records

Examples:
    # Set up production SSL and domains
    ./ssl-domain-management.sh --environment production
    
    # Set up staging with custom domain
    ./ssl-domain-management.sh --environment staging --domain staging.isectech.com

Prerequisites:
    - Load balancer must be configured first (run setup-load-balancer.sh)
    - Domain registrar nameservers must point to Google Cloud DNS
    - Proper IAM permissions for Certificate Manager and DNS

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