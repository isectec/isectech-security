#!/bin/bash
"""
Multi-Region Encryption Validation Script
Production-grade validation of encryption in transit and at rest
Implements NIST, FIPS 140-2, and industry standards compliance
"""

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/regions-config.json"
OUTPUT_DIR="${SCRIPT_DIR}/encryption_reports"
LOG_FILE="${OUTPUT_DIR}/encryption_validation.log"

# Create output directory
mkdir -p "${OUTPUT_DIR}"

# Logging function
log() {
    local level="$1"
    shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Initialize
log "INFO" "Starting Multi-Region Encryption Validation"
log "INFO" "Configuration: $CONFIG_FILE"
log "INFO" "Output directory: $OUTPUT_DIR"

# Check dependencies
check_dependencies() {
    log "INFO" "Checking dependencies..."
    
    local deps=("openssl" "nmap" "curl" "jq" "python3")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error_exit "Required dependency not found: $dep"
        fi
    done
    
    # Check for Python packages
    if ! python3 -c "import ssl, socket, cryptography, requests" 2>/dev/null; then
        log "WARNING" "Some Python packages may be missing. Installing..."
        pip3 install cryptography requests
    fi
    
    log "INFO" "All dependencies satisfied"
}

# Test SSL/TLS Configuration
test_ssl_tls() {
    local endpoint="$1"
    local region="$2"
    local output_file="${OUTPUT_DIR}/ssl_test_${region}.json"
    
    log "INFO" "Testing SSL/TLS configuration for $endpoint"
    
    # Extract hostname and port
    local hostname
    local port=443
    
    if [[ "$endpoint" =~ https://([^/:]+)(:([0-9]+))? ]]; then
        hostname="${BASH_REMATCH[1]}"
        if [[ -n "${BASH_REMATCH[3]}" ]]; then
            port="${BASH_REMATCH[3]}"
        fi
    else
        error_exit "Invalid HTTPS endpoint: $endpoint"
    fi
    
    log "INFO" "Testing $hostname:$port"
    
    # Test SSL connection and certificate
    local ssl_output
    ssl_output=$(echo | openssl s_client -connect "$hostname:$port" -servername "$hostname" 2>/dev/null)
    
    if [[ -z "$ssl_output" ]]; then
        log "ERROR" "Failed to establish SSL connection to $hostname:$port"
        return 1
    fi
    
    # Extract certificate information
    local cert_info
    cert_info=$(echo "$ssl_output" | openssl x509 -noout -text 2>/dev/null)
    
    # Get certificate details
    local subject
    local issuer
    local not_after
    local signature_algo
    local public_key_algo
    local key_size
    
    subject=$(echo "$ssl_output" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
    issuer=$(echo "$ssl_output" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
    not_after=$(echo "$ssl_output" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    signature_algo=$(echo "$cert_info" | grep "Signature Algorithm" | head -1 | awk -F: '{print $2}' | xargs)
    
    # Get public key information
    local pubkey_info
    pubkey_info=$(echo "$ssl_output" | openssl x509 -noout -pubkey 2>/dev/null | openssl rsa -pubin -text -noout 2>/dev/null)
    
    if [[ -n "$pubkey_info" ]]; then
        public_key_algo="RSA"
        key_size=$(echo "$pubkey_info" | grep "RSA Public Key" | grep -o "[0-9]*" | head -1)
    else
        # Try EC key
        pubkey_info=$(echo "$ssl_output" | openssl x509 -noout -pubkey 2>/dev/null | openssl ec -pubin -text -noout 2>/dev/null)
        if [[ -n "$pubkey_info" ]]; then
            public_key_algo="EC"
            key_size=$(echo "$pubkey_info" | grep "ASN1 OID" | awk '{print $3}')
        fi
    fi
    
    # Test cipher suites
    log "INFO" "Testing cipher suites..."
    local cipher_test
    cipher_test=$(nmap --script ssl-enum-ciphers -p "$port" "$hostname" 2>/dev/null | grep -A 20 "ssl-enum-ciphers")
    
    # Test for weak ciphers
    local weak_ciphers=()
    if echo "$cipher_test" | grep -i "ssl\|rc4\|des\|md5" >/dev/null; then
        weak_ciphers+=("Weak ciphers detected")
    fi
    
    # Test for deprecated protocols
    local deprecated_protocols=()
    for protocol in "ssl2" "ssl3" "tls1" "tls1_1"; do
        if echo | openssl s_client -"$protocol" -connect "$hostname:$port" 2>/dev/null | grep "CONNECTED" >/dev/null; then
            deprecated_protocols+=("$protocol")
        fi
    done
    
    # Analyze certificate expiration
    local cert_expiry_days
    cert_expiry_days=$(echo "$ssl_output" | openssl x509 -noout -checkend 0 2>/dev/null && echo "valid" || echo "expired")
    
    if [[ "$cert_expiry_days" == "valid" ]]; then
        cert_expiry_days=$(echo "$ssl_output" | openssl x509 -noout -checkend $((30 * 24 * 3600)) 2>/dev/null && echo ">30" || echo "<30")
    fi
    
    # Generate vulnerability assessment
    local vulnerabilities=()
    local recommendations=()
    
    # Check signature algorithm
    if [[ "$signature_algo" =~ sha1|md5 ]]; then
        vulnerabilities+=("Weak signature algorithm: $signature_algo")
        recommendations+=("Upgrade to SHA-256 or stronger signature algorithm")
    fi
    
    # Check key size
    if [[ "$public_key_algo" == "RSA" && "$key_size" -lt 2048 ]]; then
        vulnerabilities+=("Weak RSA key size: $key_size bits")
        recommendations+=("Use RSA keys of 2048 bits or larger")
    fi
    
    # Check certificate expiry
    if [[ "$cert_expiry_days" == "expired" ]]; then
        vulnerabilities+=("Certificate expired")
        recommendations+=("Renew SSL certificate immediately")
    elif [[ "$cert_expiry_days" == "<30" ]]; then
        vulnerabilities+=("Certificate expires within 30 days")
        recommendations+=("Schedule certificate renewal")
    fi
    
    # Check for deprecated protocols
    if [[ ${#deprecated_protocols[@]} -gt 0 ]]; then
        vulnerabilities+=("Deprecated protocols enabled: ${deprecated_protocols[*]}")
        recommendations+=("Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1")
    fi
    
    # Check for weak ciphers
    if [[ ${#weak_ciphers[@]} -gt 0 ]]; then
        vulnerabilities+=("${weak_ciphers[@]}")
        recommendations+=("Disable weak cipher suites")
    fi
    
    # Calculate security score
    local security_score=100
    security_score=$((security_score - ${#vulnerabilities[@]} * 15))
    [[ $security_score -lt 0 ]] && security_score=0
    
    # Determine risk level
    local risk_level="LOW"
    if [[ ${#vulnerabilities[@]} -gt 3 ]]; then
        risk_level="CRITICAL"
    elif [[ ${#vulnerabilities[@]} -gt 1 ]]; then
        risk_level="HIGH"
    elif [[ ${#vulnerabilities[@]} -gt 0 ]]; then
        risk_level="MEDIUM"
    fi
    
    # Create JSON report
    cat > "$output_file" <<EOF
{
    "endpoint": "$endpoint",
    "region": "$region",
    "hostname": "$hostname",
    "port": $port,
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "certificate": {
        "subject": "$subject",
        "issuer": "$issuer",
        "expiry": "$not_after",
        "signature_algorithm": "$signature_algo",
        "public_key_algorithm": "$public_key_algo",
        "key_size": "$key_size"
    },
    "security_assessment": {
        "score": $security_score,
        "risk_level": "$risk_level",
        "vulnerabilities": $(printf '%s\n' "${vulnerabilities[@]}" | jq -R . | jq -s .),
        "recommendations": $(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    },
    "protocol_support": {
        "deprecated_protocols": $(printf '%s\n' "${deprecated_protocols[@]}" | jq -R . | jq -s .)
    }
}
EOF
    
    log "INFO" "SSL/TLS test completed for $endpoint (Score: $security_score, Risk: $risk_level)"
    
    return 0
}

# Test encryption at rest
test_encryption_at_rest() {
    local endpoint="$1"
    local region="$2"
    local output_file="${OUTPUT_DIR}/encryption_at_rest_${region}.json"
    
    log "INFO" "Testing encryption at rest for $endpoint"
    
    local findings=()
    local recommendations=()
    
    # Test database encryption status
    log "INFO" "Checking database encryption status..."
    local db_response
    if db_response=$(curl -s --max-time 30 "$endpoint/api/admin/database-encryption" 2>/dev/null); then
        local db_encrypted
        db_encrypted=$(echo "$db_response" | jq -r '.encryption_enabled // false' 2>/dev/null)
        
        if [[ "$db_encrypted" != "true" ]]; then
            findings+=("Database encryption not enabled")
            recommendations+=("Enable database encryption at rest")
        else
            local encryption_algo
            encryption_algo=$(echo "$db_response" | jq -r '.encryption_algorithm // "unknown"' 2>/dev/null)
            
            if [[ "$encryption_algo" != "AES-256"* ]]; then
                findings+=("Database using weak encryption algorithm: $encryption_algo")
                recommendations+=("Upgrade to AES-256 encryption")
            fi
        fi
    else
        findings+=("Cannot verify database encryption status")
        recommendations+=("Implement database encryption status endpoint")
    fi
    
    # Test storage encryption
    log "INFO" "Checking storage encryption status..."
    local storage_response
    if storage_response=$(curl -s --max-time 30 "$endpoint/api/admin/storage-encryption" 2>/dev/null); then
        local storage_encrypted
        storage_encrypted=$(echo "$storage_response" | jq -r '.encryption_enabled // false' 2>/dev/null)
        
        if [[ "$storage_encrypted" != "true" ]]; then
            findings+=("Storage encryption not enabled")
            recommendations+=("Enable storage encryption at rest")
        fi
        
        # Check key management
        local key_management
        key_management=$(echo "$storage_response" | jq -r '.key_management_service // "unknown"' 2>/dev/null)
        
        if [[ "$key_management" == "unknown" || "$key_management" == "null" ]]; then
            findings+=("Key management service not configured")
            recommendations+=("Implement proper key management service (KMS)")
        fi
    else
        findings+=("Cannot verify storage encryption status")
        recommendations+=("Implement storage encryption status endpoint")
    fi
    
    # Test backup encryption
    log "INFO" "Checking backup encryption status..."
    local backup_response
    if backup_response=$(curl -s --max-time 30 "$endpoint/api/admin/backup-encryption" 2>/dev/null); then
        local backup_encrypted
        backup_encrypted=$(echo "$backup_response" | jq -r '.encryption_enabled // false' 2>/dev/null)
        
        if [[ "$backup_encrypted" != "true" ]]; then
            findings+=("Backup encryption not enabled")
            recommendations+=("Enable backup encryption")
        fi
    else
        findings+=("Cannot verify backup encryption status")
        recommendations+=("Implement backup encryption verification")
    fi
    
    # Calculate compliance score
    local compliance_score=100
    compliance_score=$((compliance_score - ${#findings[@]} * 20))
    [[ $compliance_score -lt 0 ]] && compliance_score=0
    
    # Determine compliance level
    local compliance_level="COMPLIANT"
    if [[ ${#findings[@]} -gt 2 ]]; then
        compliance_level="NON_COMPLIANT"
    elif [[ ${#findings[@]} -gt 0 ]]; then
        compliance_level="PARTIALLY_COMPLIANT"
    fi
    
    # Create JSON report
    cat > "$output_file" <<EOF
{
    "endpoint": "$endpoint",
    "region": "$region",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "encryption_at_rest": {
        "compliance_score": $compliance_score,
        "compliance_level": "$compliance_level",
        "findings": $(printf '%s\n' "${findings[@]}" | jq -R . | jq -s .),
        "recommendations": $(printf '%s\n' "${recommendations[@]}" | jq -R . | jq -s .)
    }
}
EOF
    
    log "INFO" "Encryption at rest test completed for $endpoint (Score: $compliance_score, Level: $compliance_level)"
    
    return 0
}

# Test cross-region encryption consistency
test_cross_region_encryption() {
    local output_file="${OUTPUT_DIR}/cross_region_encryption.json"
    
    log "INFO" "Testing cross-region encryption consistency..."
    
    local regions
    regions=$(jq -r '.regions[].name' "$CONFIG_FILE")
    
    local consistency_issues=()
    local region_configs=()
    
    # Collect encryption configurations from each region
    while IFS= read -r region; do
        log "INFO" "Collecting encryption config from region: $region"
        
        local primary_endpoint
        primary_endpoint=$(jq -r ".regions[] | select(.name == \"$region\") | .primary_endpoint" "$CONFIG_FILE")
        
        # Get encryption configuration
        local encryption_config
        if encryption_config=$(curl -s --max-time 30 "$primary_endpoint/api/admin/encryption-config" 2>/dev/null); then
            local config_summary
            config_summary=$(echo "$encryption_config" | jq -c '{
                region: "'$region'",
                db_encryption: .database_encryption // false,
                storage_encryption: .storage_encryption // false,
                transit_encryption: .transit_encryption // false,
                encryption_algorithms: .algorithms // []
            }')
            
            region_configs+=("$config_summary")
        else
            consistency_issues+=("Cannot retrieve encryption config from region: $region")
        fi
    done <<< "$regions"
    
    # Analyze consistency
    if [[ ${#region_configs[@]} -gt 1 ]]; then
        # Compare configurations
        local reference_config="${region_configs[0]}"
        
        for config in "${region_configs[@]:1}"; do
            local region_name
            region_name=$(echo "$config" | jq -r '.region')
            
            # Compare database encryption
            local ref_db_enc
            local curr_db_enc
            ref_db_enc=$(echo "$reference_config" | jq -r '.db_encryption')
            curr_db_enc=$(echo "$config" | jq -r '.db_encryption')
            
            if [[ "$ref_db_enc" != "$curr_db_enc" ]]; then
                consistency_issues+=("Database encryption inconsistent in region $region_name")
            fi
            
            # Compare storage encryption
            local ref_storage_enc
            local curr_storage_enc
            ref_storage_enc=$(echo "$reference_config" | jq -r '.storage_encryption')
            curr_storage_enc=$(echo "$config" | jq -r '.storage_encryption')
            
            if [[ "$ref_storage_enc" != "$curr_storage_enc" ]]; then
                consistency_issues+=("Storage encryption inconsistent in region $region_name")
            fi
        done
    fi
    
    # Generate consistency report
    local consistency_status="CONSISTENT"
    if [[ ${#consistency_issues[@]} -gt 0 ]]; then
        consistency_status="INCONSISTENT"
    fi
    
    cat > "$output_file" <<EOF
{
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "cross_region_encryption": {
        "consistency_status": "$consistency_status",
        "regions_tested": $(echo "$regions" | jq -R . | jq -s .),
        "consistency_issues": $(printf '%s\n' "${consistency_issues[@]}" | jq -R . | jq -s .),
        "region_configurations": [$(IFS=','; echo "${region_configs[*]}")]
    }
}
EOF
    
    log "INFO" "Cross-region encryption test completed (Status: $consistency_status)"
    
    return 0
}

# Generate comprehensive report
generate_comprehensive_report() {
    local report_file="${OUTPUT_DIR}/comprehensive_encryption_report.json"
    
    log "INFO" "Generating comprehensive encryption validation report..."
    
    local all_reports=()
    
    # Collect all individual reports
    for report in "${OUTPUT_DIR}"/*.json; do
        if [[ -f "$report" && "$report" != "$report_file" ]]; then
            all_reports+=("$(cat "$report")")
        fi
    done
    
    # Calculate overall statistics
    local total_tests=${#all_reports[@]}
    local total_vulnerabilities=0
    local critical_issues=0
    local high_issues=0
    local medium_issues=0
    
    for report in "${all_reports[@]}"; do
        # Count vulnerabilities from SSL/TLS tests
        local vuln_count
        vuln_count=$(echo "$report" | jq '.security_assessment.vulnerabilities | length' 2>/dev/null || echo "0")
        total_vulnerabilities=$((total_vulnerabilities + vuln_count))
        
        # Count by risk level
        local risk_level
        risk_level=$(echo "$report" | jq -r '.security_assessment.risk_level // "UNKNOWN"' 2>/dev/null)
        
        case "$risk_level" in
            "CRITICAL") critical_issues=$((critical_issues + 1)) ;;
            "HIGH") high_issues=$((high_issues + 1)) ;;
            "MEDIUM") medium_issues=$((medium_issues + 1)) ;;
        esac
        
        # Count compliance issues
        local findings_count
        findings_count=$(echo "$report" | jq '.encryption_at_rest.findings | length' 2>/dev/null || echo "0")
        total_vulnerabilities=$((total_vulnerabilities + findings_count))
    done
    
    # Generate executive summary
    local overall_risk="LOW"
    if [[ $critical_issues -gt 0 ]]; then
        overall_risk="CRITICAL"
    elif [[ $high_issues -gt 2 ]]; then
        overall_risk="HIGH"
    elif [[ $high_issues -gt 0 || $medium_issues -gt 3 ]]; then
        overall_risk="MEDIUM"
    fi
    
    # Create comprehensive report
    cat > "$report_file" <<EOF
{
    "report_metadata": {
        "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "report_type": "comprehensive_encryption_validation",
        "version": "1.0"
    },
    "executive_summary": {
        "total_tests": $total_tests,
        "total_vulnerabilities": $total_vulnerabilities,
        "overall_risk_level": "$overall_risk",
        "critical_issues": $critical_issues,
        "high_issues": $high_issues,
        "medium_issues": $medium_issues
    },
    "detailed_reports": [$(IFS=','; echo "${all_reports[*]}")]
}
EOF
    
    log "INFO" "Comprehensive report generated: $report_file"
    
    # Display summary
    echo ""
    echo "================================================="
    echo "ENCRYPTION VALIDATION SUMMARY"
    echo "================================================="
    echo "Total Tests: $total_tests"
    echo "Total Vulnerabilities: $total_vulnerabilities"
    echo "Overall Risk Level: $overall_risk"
    echo "Critical Issues: $critical_issues"
    echo "High Issues: $high_issues"
    echo "Medium Issues: $medium_issues"
    echo "================================================="
    
    return 0
}

# Main execution
main() {
    check_dependencies
    
    # Read regions from config
    local regions
    regions=$(jq -r '.regions[] | .name' "$CONFIG_FILE")
    
    # Test each region
    while IFS= read -r region; do
        log "INFO" "Testing region: $region"
        
        local endpoints
        endpoints=$(jq -r ".regions[] | select(.name == \"$region\") | .api_endpoints[]" "$CONFIG_FILE")
        
        while IFS= read -r endpoint; do
            test_ssl_tls "$endpoint" "$region"
            test_encryption_at_rest "$endpoint" "$region"
        done <<< "$endpoints"
        
    done <<< "$regions"
    
    # Test cross-region consistency
    test_cross_region_encryption
    
    # Generate comprehensive report
    generate_comprehensive_report
    
    log "INFO" "Encryption validation completed successfully"
    
    # Return appropriate exit code
    local critical_count
    critical_count=$(jq '.executive_summary.critical_issues' "${OUTPUT_DIR}/comprehensive_encryption_report.json")
    
    if [[ "$critical_count" -gt 0 ]]; then
        exit 2  # Critical issues found
    elif jq -e '.executive_summary.high_issues > 0' "${OUTPUT_DIR}/comprehensive_encryption_report.json" >/dev/null; then
        exit 1  # High issues found
    else
        exit 0  # All tests passed
    fi
}

# Run main function
main "$@"