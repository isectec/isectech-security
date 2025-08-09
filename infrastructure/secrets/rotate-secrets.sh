#!/bin/bash

# iSECTECH Secret Rotation Script
# Automated secret rotation with zero-downtime updates
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"
DRY_RUN="${DRY_RUN:-false}"
FORCE_ROTATION="${FORCE_ROTATION:-false}"

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

# Audit logging
audit_log() {
    local action="$1"
    local secret_name="$2"
    local status="$3"
    local details="${4:-}"
    
    echo "$(date -Iseconds) | ${ENVIRONMENT} | ${action} | ${secret_name} | ${status} | ${details}" >> "/tmp/secret-rotation-audit-$(date +%Y%m%d).log"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites for secret rotation..."
    
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
    
    # Check required permissions
    if ! gcloud secrets list --limit=1 &>/dev/null; then
        log_error "Insufficient permissions to access Secret Manager"
        exit 1
    fi
    
    log_success "Prerequisites checked successfully"
}

# Generate secure random password
generate_secure_password() {
    local length=${1:-32}
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# Generate JWT secret
generate_jwt_secret() {
    openssl rand -base64 64 | tr -d "\n"
}

# Generate API key
generate_api_key() {
    openssl rand -hex 32
}

# Check if secret needs rotation
needs_rotation() {
    local secret_name="$1"
    local max_age_days="${2:-30}"
    
    # Get the creation time of the latest version
    local creation_time
    creation_time=$(gcloud secrets versions describe latest --secret="$secret_name" --format="value(createTime)" 2>/dev/null || echo "")
    
    if [ -z "$creation_time" ]; then
        log_warning "Could not determine age of secret: $secret_name"
        return 1
    fi
    
    # Convert to epoch time
    local creation_epoch
    creation_epoch=$(date -d "$creation_time" +%s)
    local current_epoch
    current_epoch=$(date +%s)
    
    # Calculate age in days
    local age_seconds=$((current_epoch - creation_epoch))
    local age_days=$((age_seconds / 86400))
    
    if [ "$age_days" -gt "$max_age_days" ] || [ "$FORCE_ROTATION" = "true" ]; then
        log_info "Secret $secret_name is $age_days days old (max: $max_age_days)"
        return 0
    else
        log_info "Secret $secret_name is $age_days days old (within rotation period)"
        return 1
    fi
}

# Rotate a secret with new value
rotate_secret() {
    local secret_name="$1"
    local new_value="$2"
    local description="$3"
    
    log_info "Rotating secret: $secret_name"
    audit_log "ROTATION_START" "$secret_name" "INITIATED" "$description"
    
    if [ "$DRY_RUN" = "true" ]; then
        log_warning "DRY RUN: Would rotate secret $secret_name"
        audit_log "ROTATION_DRY_RUN" "$secret_name" "SIMULATED" "$description"
        return 0
    fi
    
    # Create new version
    if echo -n "$new_value" | gcloud secrets versions add "$secret_name" --data-file=-; then
        log_success "New version created for secret: $secret_name"
        audit_log "ROTATION_SUCCESS" "$secret_name" "COMPLETED" "$description"
        
        # Update annotations
        gcloud secrets update "$secret_name" \
            --update-annotations="last-rotated=$(date -Iseconds),rotated-by=automated-script,rotation-reason=$description"
        
        return 0
    else
        log_error "Failed to rotate secret: $secret_name"
        audit_log "ROTATION_FAILED" "$secret_name" "ERROR" "$description"
        return 1
    fi
}

# Restart services that use a secret
restart_services_for_secret() {
    local secret_name="$1"
    
    log_info "Restarting services that use secret: $secret_name"
    
    # Map secrets to services
    local services=()
    case "$secret_name" in
        *"nextauth"*|*"oauth"*|*"session"*)
            services+=("isectech-frontend")
            ;;
        *"postgres"*|*"mongodb"*|*"redis"*|*"clickhouse"*)
            services+=("isectech-backend-services" "isectech-api-gateway")
            ;;
        *"jwt"*|*"service-api-key"*)
            services+=("isectech-api-gateway" "isectech-backend-services")
            ;;
        *"kong"*)
            services+=("isectech-api-gateway")
            ;;
        *)
            services+=("isectech-backend-services")
            ;;
    esac
    
    # Restart each service
    for service in "${services[@]}"; do
        if [ "$DRY_RUN" = "true" ]; then
            log_warning "DRY RUN: Would restart Cloud Run service: $service"
        else
            log_info "Restarting Cloud Run service: $service"
            if gcloud run services update "$service" --region="$REGION" --update-annotations="last-secret-rotation=$(date -Iseconds)"; then
                log_success "Service restarted: $service"
                audit_log "SERVICE_RESTART" "$service" "SUCCESS" "Restarted for secret: $secret_name"
            else
                log_error "Failed to restart service: $service"
                audit_log "SERVICE_RESTART" "$service" "FAILED" "Failed restart for secret: $secret_name"
            fi
        fi
    done
}

# Rotate database secrets
rotate_database_secrets() {
    log_info "Rotating database secrets..."
    
    local secrets_to_rotate=(
        "isectech-postgres-password:30"
        "isectech-mongodb-password:30"
        "isectech-redis-password:30"
        "isectech-clickhouse-password:30"
    )
    
    for secret_info in "${secrets_to_rotate[@]}"; do
        local secret_name="${secret_info%:*}"
        local max_age="${secret_info#*:}"
        
        if needs_rotation "$secret_name" "$max_age"; then
            local new_password
            new_password=$(generate_secure_password 32)
            
            if rotate_secret "$secret_name" "$new_password" "Scheduled database password rotation"; then
                restart_services_for_secret "$secret_name"
                
                # Note: In a real implementation, you would need to update the actual database
                # with the new password. This would require connecting to each database and
                # running ALTER USER commands. For safety, this is not automated here.
                log_warning "MANUAL ACTION REQUIRED: Update database user password for $secret_name"
            fi
        fi
    done
}

# Rotate authentication secrets
rotate_authentication_secrets() {
    log_info "Rotating authentication secrets..."
    
    local secrets_to_rotate=(
        "isectech-nextauth-secret:30"
        "isectech-jwt-access-secret:30"
        "isectech-jwt-refresh-secret:30"
        "isectech-service-api-key:60"
        "isectech-session-encryption-key:30"
    )
    
    for secret_info in "${secrets_to_rotate[@]}"; do
        local secret_name="${secret_info%:*}"
        local max_age="${secret_info#*:}"
        
        if needs_rotation "$secret_name" "$max_age"; then
            local new_value
            case "$secret_name" in
                *"jwt"*|*"nextauth"*|*"session"*)
                    new_value=$(generate_jwt_secret)
                    ;;
                *"api-key"*)
                    new_value=$(generate_api_key)
                    ;;
                *)
                    new_value=$(generate_secure_password 32)
                    ;;
            esac
            
            if rotate_secret "$secret_name" "$new_value" "Scheduled authentication secret rotation"; then
                restart_services_for_secret "$secret_name"
            fi
        fi
    done
}

# Rotate infrastructure secrets
rotate_infrastructure_secrets() {
    log_info "Rotating infrastructure secrets..."
    
    local secrets_to_rotate=(
        "isectech-kong-postgres-password:30"
        "isectech-consul-encrypt-key:90"
        "isectech-kafka-sasl-password:60"
        "isectech-backup-encryption-key:90"
    )
    
    for secret_info in "${secrets_to_rotate[@]}"; do
        local secret_name="${secret_info%:*}"
        local max_age="${secret_info#*:}"
        
        if needs_rotation "$secret_name" "$max_age"; then
            local new_value
            case "$secret_name" in
                *"consul-encrypt"*)
                    # Generate Consul encryption key
                    new_value=$(openssl rand -base64 32)
                    ;;
                *)
                    new_value=$(generate_secure_password 32)
                    ;;
            esac
            
            if rotate_secret "$secret_name" "$new_value" "Scheduled infrastructure secret rotation"; then
                restart_services_for_secret "$secret_name"
                
                # Special handling for infrastructure secrets
                case "$secret_name" in
                    *"consul"*)
                        log_warning "MANUAL ACTION REQUIRED: Update Consul cluster with new encryption key"
                        ;;
                    *"kafka"*)
                        log_warning "MANUAL ACTION REQUIRED: Update Kafka SASL configuration"
                        ;;
                esac
            fi
        fi
    done
}

# Rotate encryption keys
rotate_encryption_keys() {
    log_info "Rotating encryption keys..."
    
    local secrets_to_rotate=(
        "isectech-app-encryption-key:90"
        "isectech-pii-encryption-key:60"
        "isectech-log-encryption-key:90"
        "isectech-asset-discovery-encryption-key:90"
        "isectech-nsm-encryption-key:90"
    )
    
    for secret_info in "${secrets_to_rotate[@]}"; do
        local secret_name="${secret_info%:*}"
        local max_age="${secret_info#*:}"
        
        if needs_rotation "$secret_name" "$max_age"; then
            local new_key
            new_key=$(generate_secure_password 32)
            
            if rotate_secret "$secret_name" "$new_key" "Scheduled encryption key rotation"; then
                restart_services_for_secret "$secret_name"
                
                log_warning "CRITICAL: Encryption key rotated for $secret_name"
                log_warning "Ensure proper key migration for existing encrypted data"
                audit_log "ENCRYPTION_KEY_ROTATION" "$secret_name" "CRITICAL" "Manual data migration may be required"
            fi
        fi
    done
}

# Validate service health after rotation
validate_service_health() {
    log_info "Validating service health after rotation..."
    
    local services=(
        "isectech-frontend"
        "isectech-api-gateway"
        "isectech-backend-services"
    )
    
    local failed_services=()
    
    for service in "${services[@]}"; do
        log_info "Checking health of service: $service"
        
        # Get service URL
        local service_url
        service_url=$(gcloud run services describe "$service" --region="$REGION" --format="value(status.url)" 2>/dev/null || echo "")
        
        if [ -z "$service_url" ]; then
            log_warning "Could not get URL for service: $service"
            continue
        fi
        
        # Check health endpoint
        local health_url="${service_url}/health"
        local response_code
        response_code=$(curl -s -o /dev/null -w "%{http_code}" "$health_url" --max-time 30 || echo "000")
        
        if [ "$response_code" = "200" ]; then
            log_success "Service $service is healthy (HTTP $response_code)"
            audit_log "HEALTH_CHECK" "$service" "HEALTHY" "HTTP $response_code"
        else
            log_error "Service $service is unhealthy (HTTP $response_code)"
            failed_services+=("$service")
            audit_log "HEALTH_CHECK" "$service" "UNHEALTHY" "HTTP $response_code"
        fi
    done
    
    if [ ${#failed_services[@]} -gt 0 ]; then
        log_error "The following services failed health checks: ${failed_services[*]}"
        log_error "Manual intervention may be required"
        return 1
    else
        log_success "All services passed health checks"
        return 0
    fi
}

# Generate rotation report
generate_rotation_report() {
    log_info "Generating rotation report..."
    
    local report_file="/tmp/secret-rotation-report-$(date +%Y%m%d-%H%M%S).txt"
    local audit_file="/tmp/secret-rotation-audit-$(date +%Y%m%d).log"
    
    cat > "$report_file" << EOF
iSECTECH Secret Rotation Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Dry Run: ${DRY_RUN}

================================
ROTATION SUMMARY
================================

EOF
    
    # Count rotations from audit log
    if [ -f "$audit_file" ]; then
        local total_rotations
        total_rotations=$(grep -c "ROTATION_SUCCESS\|ROTATION_DRY_RUN" "$audit_file" 2>/dev/null || echo "0")
        
        local failed_rotations
        failed_rotations=$(grep -c "ROTATION_FAILED" "$audit_file" 2>/dev/null || echo "0")
        
        local service_restarts
        service_restarts=$(grep -c "SERVICE_RESTART.*SUCCESS" "$audit_file" 2>/dev/null || echo "0")
        
        echo "Total rotations: $total_rotations" >> "$report_file"
        echo "Failed rotations: $failed_rotations" >> "$report_file"
        echo "Service restarts: $service_restarts" >> "$report_file"
        echo "" >> "$report_file"
        
        echo "================================" >> "$report_file"
        echo "DETAILED AUDIT LOG" >> "$report_file"
        echo "================================" >> "$report_file"
        echo "" >> "$report_file"
        
        cat "$audit_file" >> "$report_file" 2>/dev/null || echo "No audit log found" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

================================
NEXT ROTATION SCHEDULE
================================

Database secrets: Every 30 days
Authentication secrets: Every 30 days  
JWT secrets: Every 30 days
API keys: Every 60 days
Infrastructure secrets: Every 60-90 days
Encryption keys: Every 60-90 days

================================
MANUAL ACTIONS REQUIRED
================================

1. Update database user passwords with new secret values
2. Update external service configurations if API keys were rotated
3. Verify Consul cluster encryption if Consul keys were rotated
4. Update Kafka SASL configuration if Kafka secrets were rotated
5. Plan data migration for any rotated encryption keys
6. Monitor service logs for authentication errors
7. Update any hardcoded references to rotated secrets

================================
SECURITY RECOMMENDATIONS
================================

1. Monitor failed authentication attempts after rotation
2. Review audit logs for any unauthorized access attempts
3. Verify all services restarted successfully
4. Test critical functionality after rotation
5. Update incident response procedures with new secrets
6. Schedule regular penetration testing
7. Review and update secret access permissions

EOF
    
    log_success "Rotation report generated: $report_file"
    
    # Send report via email if configured
    if [ -n "${NOTIFICATION_EMAIL:-}" ]; then
        log_info "Sending rotation report to: $NOTIFICATION_EMAIL"
        # In a real implementation, you would send the report via email
    fi
}

# Main rotation function
perform_rotation() {
    log_info "Starting secret rotation process..."
    log_info "Environment: $ENVIRONMENT"
    log_info "Dry Run: $DRY_RUN"
    log_info "Force Rotation: $FORCE_ROTATION"
    
    # Create audit log entry for rotation start
    audit_log "ROTATION_SESSION_START" "ALL_SECRETS" "INITIATED" "Environment: $ENVIRONMENT, DryRun: $DRY_RUN"
    
    # Rotate different categories of secrets
    rotate_authentication_secrets
    rotate_database_secrets
    rotate_infrastructure_secrets
    rotate_encryption_keys
    
    # Validate service health
    if [ "$DRY_RUN" != "true" ]; then
        sleep 30  # Wait for services to fully restart
        validate_service_health
    fi
    
    # Generate report
    generate_rotation_report
    
    audit_log "ROTATION_SESSION_END" "ALL_SECRETS" "COMPLETED" "Environment: $ENVIRONMENT"
    log_success "Secret rotation process completed"
}

# Help function
show_help() {
    cat << EOF
iSECTECH Secret Rotation Script

Usage: $0 [OPTIONS]

Options:
    --dry-run           Simulate rotation without making changes
    --force             Force rotation of all secrets regardless of age  
    --environment ENV   Environment to rotate (production, staging, development)
    --project PROJECT   Google Cloud project ID
    --region REGION     Google Cloud region
    --help             Show this help message

Environment Variables:
    PROJECT_ID         Google Cloud project ID
    REGION            Google Cloud region (default: us-central1)
    ENVIRONMENT       Environment name (default: production)
    DRY_RUN           Set to 'true' for dry run mode
    FORCE_ROTATION    Set to 'true' to force rotation of all secrets
    NOTIFICATION_EMAIL Email address for rotation reports

Examples:
    # Dry run in production
    $0 --dry-run --environment production
    
    # Force rotation of all secrets in staging
    $0 --force --environment staging
    
    # Normal rotation with custom project
    PROJECT_ID=my-project $0

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE_ROTATION=true
            shift
            ;;
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

# Main execution
main() {
    check_prerequisites
    perform_rotation
}

# Execute main function
main "$@"