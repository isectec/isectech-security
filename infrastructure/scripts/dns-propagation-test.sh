#!/bin/bash

# iSECTECH DNS Propagation Testing Script
# Production-grade DNS validation and propagation testing
# Author: Claude Code - iSECTECH Infrastructure Team

set -euo pipefail

# Configuration
DOMAINS=(
    "app.isectech.org"
    "api.isectech.org"
    "docs.isectech.org"
    "admin.isectech.org"
    "status.isectech.org"
)

ENVIRONMENTS=(
    "production"
    "staging"
    "development"
)

# DNS Servers to test against
DNS_SERVERS=(
    "8.8.8.8"        # Google DNS
    "8.8.4.4"        # Google DNS Secondary
    "1.1.1.1"        # Cloudflare DNS
    "1.0.0.1"        # Cloudflare DNS Secondary
    "208.67.222.222" # OpenDNS
    "208.67.220.220" # OpenDNS Secondary
)

# Geographic regions for testing
REGIONS=(
    "us-central1"
    "us-east1"
    "europe-west1"
    "asia-northeast1"
)

# Test record types
RECORD_TYPES=(
    "A"
    "AAAA"
    "CNAME"
    "MX"
    "TXT"
    "NS"
    "SOA"
    "CAA"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_DIR="/tmp/dns-propagation-tests"
LOG_FILE="$LOG_DIR/dns-test-$(date +%Y%m%d-%H%M%S).log"
RESULTS_FILE="$LOG_DIR/dns-results-$(date +%Y%m%d-%H%M%S).json"

# Create log directory
mkdir -p "$LOG_DIR"

# Initialize results
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'","tests":[]}' > "$RESULTS_FILE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_json() {
    local test_result="$1"
    # Append to results JSON (simplified - in production would use jq)
    log "JSON: $test_result"
}

test_dns_resolution() {
    local domain="$1"
    local record_type="$2"
    local dns_server="$3"
    local expected_result="$4"
    
    log "Testing $domain ($record_type) against $dns_server"
    
    local start_time=$(date +%s.%N)
    local result
    local status="PASS"
    local error_msg=""
    
    if result=$(dig +short @"$dns_server" "$domain" "$record_type" 2>&1); then
        local end_time=$(date +%s.%N)
        local response_time=$(echo "$end_time - $start_time" | bc -l)
        
        if [[ -z "$result" ]]; then
            status="FAIL"
            error_msg="No DNS response received"
            echo -e "${RED}✗ FAIL${NC}: $domain ($record_type) - No response from $dns_server"
        elif [[ -n "$expected_result" && "$result" != *"$expected_result"* ]]; then
            status="WARN"
            error_msg="Unexpected result: got '$result', expected '$expected_result'"
            echo -e "${YELLOW}⚠ WARN${NC}: $domain ($record_type) - $error_msg"
        else
            echo -e "${GREEN}✓ PASS${NC}: $domain ($record_type) - Response: $result (${response_time}s)"
        fi
    else
        local end_time=$(date +%s.%N)
        local response_time=$(echo "$end_time - $start_time" | bc -l)
        status="FAIL"
        error_msg="DNS query failed: $result"
        echo -e "${RED}✗ FAIL${NC}: $domain ($record_type) - $error_msg"
    fi
    
    # Log structured result
    log_json "{\"domain\":\"$domain\",\"record_type\":\"$record_type\",\"dns_server\":\"$dns_server\",\"status\":\"$status\",\"result\":\"$result\",\"response_time\":\"$response_time\",\"error\":\"$error_msg\"}"
}

test_dns_propagation() {
    local domain="$1"
    
    log "Testing DNS propagation for $domain"
    echo -e "\n${BLUE}═══ Testing DNS Propagation for $domain ═══${NC}"
    
    local propagation_complete=true
    local reference_result=""
    
    # First, get reference result from primary DNS server
    if reference_result=$(dig +short @8.8.8.8 "$domain" A 2>/dev/null); then
        log "Reference result for $domain: $reference_result"
    else
        log "ERROR: Could not get reference result for $domain"
        return 1
    fi
    
    # Test against all DNS servers
    for dns_server in "${DNS_SERVERS[@]}"; do
        local server_result
        if server_result=$(dig +short @"$dns_server" "$domain" A 2>/dev/null); then
            if [[ "$server_result" == "$reference_result" ]]; then
                echo -e "${GREEN}✓${NC} $dns_server: $server_result"
            else
                echo -e "${RED}✗${NC} $dns_server: $server_result (expected: $reference_result)"
                propagation_complete=false
            fi
        else
            echo -e "${RED}✗${NC} $dns_server: Query failed"
            propagation_complete=false
        fi
    done
    
    if $propagation_complete; then
        echo -e "${GREEN}✓ DNS propagation complete for $domain${NC}"
        return 0
    else
        echo -e "${RED}✗ DNS propagation incomplete for $domain${NC}"
        return 1
    fi
}

test_dnssec_validation() {
    local domain="$1"
    
    log "Testing DNSSEC validation for $domain"
    echo -e "\n${BLUE}═══ Testing DNSSEC for $domain ═══${NC}"
    
    local dnssec_result
    if dnssec_result=$(dig +dnssec +short @8.8.8.8 "$domain" A 2>/dev/null); then
        if echo "$dnssec_result" | grep -q "RRSIG"; then
            echo -e "${GREEN}✓ DNSSEC validation successful${NC}"
            log "DNSSEC validation successful for $domain"
            return 0
        else
            echo -e "${YELLOW}⚠ DNSSEC not properly configured${NC}"
            log "DNSSEC not properly configured for $domain"
            return 1
        fi
    else
        echo -e "${RED}✗ DNSSEC validation failed${NC}"
        log "DNSSEC validation failed for $domain"
        return 1
    fi
}

test_domain_security_records() {
    local domain="$1"
    
    log "Testing security records for $domain"
    echo -e "\n${BLUE}═══ Testing Security Records for $domain ═══${NC}"
    
    # Test CAA records
    local caa_result
    if caa_result=$(dig +short @8.8.8.8 "$domain" CAA 2>/dev/null); then
        if [[ -n "$caa_result" ]]; then
            echo -e "${GREEN}✓ CAA records found:${NC} $caa_result"
        else
            echo -e "${YELLOW}⚠ No CAA records found${NC}"
        fi
    fi
    
    # Test SPF records
    local spf_result
    if spf_result=$(dig +short @8.8.8.8 "$domain" TXT 2>/dev/null | grep -i spf); then
        if [[ -n "$spf_result" ]]; then
            echo -e "${GREEN}✓ SPF record found:${NC} $spf_result"
        else
            echo -e "${YELLOW}⚠ No SPF record found${NC}"
        fi
    fi
    
    # Test DMARC records
    local dmarc_result
    if dmarc_result=$(dig +short @8.8.8.8 "_dmarc.$domain" TXT 2>/dev/null); then
        if [[ -n "$dmarc_result" ]]; then
            echo -e "${GREEN}✓ DMARC record found:${NC} $dmarc_result"
        else
            echo -e "${YELLOW}⚠ No DMARC record found${NC}"
        fi
    fi
}

test_geographic_resolution() {
    local domain="$1"
    
    log "Testing geographic DNS resolution for $domain"
    echo -e "\n${BLUE}═══ Testing Geographic Resolution for $domain ═══${NC}"
    
    # This would require actual geo-distributed testing infrastructure
    # For now, we'll test against different DNS servers as a proxy
    
    for dns_server in "${DNS_SERVERS[@]}"; do
        local geo_result
        local provider="Unknown"
        
        case $dns_server in
            "8.8.8.8"|"8.8.4.4") provider="Google" ;;
            "1.1.1.1"|"1.0.0.1") provider="Cloudflare" ;;
            "208.67.222.222"|"208.67.220.220") provider="OpenDNS" ;;
        esac
        
        if geo_result=$(dig +short @"$dns_server" "$domain" A 2>/dev/null); then
            echo -e "${GREEN}✓${NC} $provider ($dns_server): $geo_result"
        else
            echo -e "${RED}✗${NC} $provider ($dns_server): Query failed"
        fi
    done
}

generate_test_report() {
    log "Generating comprehensive test report"
    
    local report_file="$LOG_DIR/dns-test-report-$(date +%Y%m%d-%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>iSECTECH DNS Propagation Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2563eb; color: white; padding: 20px; border-radius: 8px; }
        .section { margin: 20px 0; padding: 15px; border-left: 4px solid #2563eb; }
        .pass { color: #16a34a; }
        .fail { color: #dc2626; }
        .warn { color: #d97706; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f3f4f6; }
    </style>
</head>
<body>
    <div class="header">
        <h1>iSECTECH DNS Propagation Test Report</h1>
        <p>Generated: $(date)</p>
        <p>Test Duration: Full propagation and security validation</p>
    </div>
EOF
    
    echo "    <div class=\"section\">" >> "$report_file"
    echo "        <h2>Test Summary</h2>" >> "$report_file"
    echo "        <p>Comprehensive DNS testing completed for all iSECTECH domains.</p>" >> "$report_file"
    echo "        <p>Log file: <code>$LOG_FILE</code></p>" >> "$report_file"
    echo "        <p>Results file: <code>$RESULTS_FILE</code></p>" >> "$report_file"
    echo "    </div>" >> "$report_file"
    
    echo "</body></html>" >> "$report_file"
    
    log "Test report generated: $report_file"
}

main() {
    log "Starting iSECTECH DNS Propagation Tests"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           iSECTECH DNS Propagation Testing            ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # Test each domain
    for domain in "${DOMAINS[@]}"; do
        echo -e "\n${BLUE}Testing domain: $domain${NC}"
        
        # Basic propagation test
        if test_dns_propagation "$domain"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
        ((total_tests++))
        
        # DNSSEC validation
        if test_dnssec_validation "$domain"; then
            ((passed_tests++))
        else
            ((failed_tests++))
        fi
        ((total_tests++))
        
        # Security records test
        test_domain_security_records "$domain"
        
        # Geographic resolution test
        test_geographic_resolution "$domain"
        
        # Environment-specific domains
        for env in "${ENVIRONMENTS[@]}"; do
            if [[ "$env" != "production" ]]; then
                local env_domain="${domain/app./app-$env.}"
                env_domain="${env_domain/api./api-$env.}"
                env_domain="${env_domain/docs./docs-$env.}"
                env_domain="${env_domain/admin./admin-$env.}"
                env_domain="${env_domain/status./status-$env.}"
                
                echo -e "\n${BLUE}Testing $env environment: $env_domain${NC}"
                if test_dns_propagation "$env_domain"; then
                    ((passed_tests++))
                else
                    ((failed_tests++))
                fi
                ((total_tests++))
            fi
        done
    done
    
    # Generate final report
    generate_test_report
    
    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Test Summary                        ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
    echo -e "Total tests: $total_tests"
    echo -e "${GREEN}Passed: $passed_tests${NC}"
    echo -e "${RED}Failed: $failed_tests${NC}"
    
    if [[ $failed_tests -eq 0 ]]; then
        echo -e "\n${GREEN}✓ All DNS propagation tests passed!${NC}"
        log "All DNS propagation tests completed successfully"
        exit 0
    else
        echo -e "\n${RED}✗ Some DNS propagation tests failed${NC}"
        log "DNS propagation tests completed with $failed_tests failures"
        exit 1
    fi
}

# Check dependencies
command -v dig >/dev/null 2>&1 || { echo "dig command not found. Please install bind-utils/dnsutils"; exit 1; }
command -v bc >/dev/null 2>&1 || { echo "bc command not found. Please install bc"; exit 1; }

# Run main function
main "$@"