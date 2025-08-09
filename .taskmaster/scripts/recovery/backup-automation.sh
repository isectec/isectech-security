#!/bin/bash

# Backup Automation Script - iSECTECH Security Platform
# Version: 1.0
# Author: DevOps Team
# Usage: ./backup-automation.sh [backup-type] [--schedule]

set -euo pipefail

# Configuration
PROJECT_ID="isectech-security-platform"
REGION="us-central1"
BACKUP_BUCKET="gs://isectech-infrastructure-backups"
NOTIFICATION_EMAIL="devops@isectech.com"

# Script parameters
BACKUP_TYPE=${1:-"full"}
SCHEDULE_MODE=${2:-""}

# Logging setup
LOG_FILE="/tmp/backup-automation-$(date +%Y%m%d%H%M%S).log"
BACKUP_ID="BAK-$(date +%Y%m%d%H%M%S)"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        ERROR)
            echo -e "${RED}[$timestamp] ERROR: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] WARN: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        INFO)
            echo -e "${BLUE}[$timestamp] INFO: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        SUCCESS)
            echo -e "${GREEN}[$timestamp] SUCCESS: $message${NC}" | tee -a "$LOG_FILE"
            ;;
        *)
            echo "[$timestamp] $message" | tee -a "$LOG_FILE"
            ;;
    esac
}

# Function to backup Terraform state
backup_terraform_state() {
    log INFO "Starting Terraform state backup..."
    
    local environments=("production" "staging" "development")
    local backup_dir="/tmp/terraform-state-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    for env in "${environments[@]}"; do
        log INFO "Backing up Terraform state for environment: $env"
        
        local state_file="$backup_dir/terraform-state-$env-$(date +%Y%m%d%H%M%S).tfstate"
        
        # Download current state
        if gsutil cp "gs://isectech-terraform-state/$env/default.tfstate" "$state_file" 2>/dev/null; then
            log SUCCESS "Terraform state backed up for $env"
        else
            log WARN "Failed to backup Terraform state for $env"
        fi
    done
    
    # Create archive
    local archive_file="terraform-state-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    tar -czf "/tmp/$archive_file" -C "$backup_dir" .
    
    # Upload to backup bucket
    if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/terraform-state/"; then
        log SUCCESS "Terraform state archive uploaded: $archive_file"
    else
        log ERROR "Failed to upload Terraform state archive"
        return 1
    fi
    
    # Cleanup
    rm -rf "$backup_dir" "/tmp/$archive_file"
    
    return 0
}

# Function to backup database
backup_database() {
    log INFO "Starting database backup..."
    
    local instances=("isectech-db-primary")
    
    for instance in "${instances[@]}"; do
        log INFO "Creating backup for database instance: $instance"
        
        local backup_id="backup-$instance-$(date +%Y%m%d%H%M%S)"
        
        # Create database backup
        if gcloud sql backups create --instance="$instance" --project="$PROJECT_ID" \
            --description="Automated backup created by backup-automation.sh on $(date)" 2>&1 | tee -a "$LOG_FILE"; then
            log SUCCESS "Database backup created for $instance: $backup_id"
        else
            log ERROR "Failed to create database backup for $instance"
            return 1
        fi
        
        # Export database to Cloud Storage
        local export_file="gs://isectech-db-exports/export-$instance-$(date +%Y%m%d%H%M%S).sql"
        
        if gcloud sql export sql "$instance" "$export_file" \
            --project="$PROJECT_ID" --database=isectech_db 2>&1 | tee -a "$LOG_FILE"; then
            log SUCCESS "Database exported to: $export_file"
        else
            log WARN "Failed to export database to Cloud Storage"
        fi
    done
    
    return 0
}

# Function to backup DNS configuration
backup_dns_configuration() {
    log INFO "Starting DNS configuration backup..."
    
    local dns_zones=("isectech-main-zone")
    local backup_dir="/tmp/dns-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    for zone in "${dns_zones[@]}"; do
        log INFO "Backing up DNS zone: $zone"
        
        local zone_file="$backup_dir/zone-$zone-$(date +%Y%m%d%H%M%S).json"
        local records_file="$backup_dir/records-$zone-$(date +%Y%m%d%H%M%S).json"
        
        # Export zone information
        if gcloud dns managed-zones describe "$zone" --project="$PROJECT_ID" \
            --format="json" > "$zone_file" 2>/dev/null; then
            log SUCCESS "DNS zone exported: $zone"
        else
            log ERROR "Failed to export DNS zone: $zone"
            continue
        fi
        
        # Export DNS records
        if gcloud dns record-sets export "$records_file" --zone="$zone" \
            --project="$PROJECT_ID" 2>/dev/null; then
            log SUCCESS "DNS records exported for zone: $zone"
        else
            log ERROR "Failed to export DNS records for zone: $zone"
        fi
    done
    
    # Create archive
    local archive_file="dns-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    tar -czf "/tmp/$archive_file" -C "$backup_dir" .
    
    # Upload to backup bucket
    if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/dns-configs/"; then
        log SUCCESS "DNS configuration archive uploaded: $archive_file"
    else
        log ERROR "Failed to upload DNS configuration archive"
        return 1
    fi
    
    # Cleanup
    rm -rf "$backup_dir" "/tmp/$archive_file"
    
    return 0
}

# Function to backup SSL certificates
backup_ssl_certificates() {
    log INFO "Starting SSL certificate backup..."
    
    local backup_dir="/tmp/ssl-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup Certificate Manager certificates
    log INFO "Backing up Certificate Manager certificates..."
    
    local certificates=$(gcloud certificate-manager certificates list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$certificates" ]]; then
        echo "$certificates" | while read -r cert_name; do
            if [[ -n "$cert_name" ]]; then
                log INFO "Backing up certificate: $cert_name"
                
                local cert_file="$backup_dir/cert-$cert_name-$(date +%Y%m%d%H%M%S).json"
                
                if gcloud certificate-manager certificates describe "$cert_name" \
                    --project="$PROJECT_ID" --format="json" > "$cert_file" 2>/dev/null; then
                    log SUCCESS "Certificate backed up: $cert_name"
                else
                    log WARN "Failed to backup certificate: $cert_name"
                fi
            fi
        done
    else
        log WARN "No Certificate Manager certificates found"
    fi
    
    # Backup Compute Engine SSL certificates
    log INFO "Backing up Compute Engine SSL certificates..."
    
    local compute_certs=$(gcloud compute ssl-certificates list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$compute_certs" ]]; then
        echo "$compute_certs" | while read -r cert_name; do
            if [[ -n "$cert_name" ]]; then
                log INFO "Backing up Compute SSL certificate: $cert_name"
                
                local cert_file="$backup_dir/compute-cert-$cert_name-$(date +%Y%m%d%H%M%S).json"
                
                if gcloud compute ssl-certificates describe "$cert_name" \
                    --global --project="$PROJECT_ID" --format="json" > "$cert_file" 2>/dev/null; then
                    log SUCCESS "Compute SSL certificate backed up: $cert_name"
                else
                    log WARN "Failed to backup Compute SSL certificate: $cert_name"
                fi
            fi
        done
    else
        log INFO "No Compute Engine SSL certificates found"
    fi
    
    # Create archive
    if [[ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]]; then
        local archive_file="ssl-certificates-backup-$(date +%Y%m%d%H%M%S).tar.gz"
        tar -czf "/tmp/$archive_file" -C "$backup_dir" .
        
        # Upload to backup bucket
        if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/ssl-certificates/"; then
            log SUCCESS "SSL certificates archive uploaded: $archive_file"
        else
            log ERROR "Failed to upload SSL certificates archive"
            return 1
        fi
        
        # Cleanup
        rm -f "/tmp/$archive_file"
    else
        log INFO "No SSL certificates to archive"
    fi
    
    rm -rf "$backup_dir"
    return 0
}

# Function to backup Cloud Run configurations
backup_cloud_run_configurations() {
    log INFO "Starting Cloud Run configurations backup..."
    
    local services=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")
    local backup_dir="/tmp/cloud-run-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    for service in "${services[@]}"; do
        log INFO "Backing up Cloud Run service: $service"
        
        local service_file="$backup_dir/service-$service-$(date +%Y%m%d%H%M%S).yaml"
        
        # Export service configuration
        if gcloud run services describe "$service" --region="$REGION" \
            --project="$PROJECT_ID" --format="export" > "$service_file" 2>/dev/null; then
            log SUCCESS "Cloud Run service backed up: $service"
        else
            log WARN "Failed to backup Cloud Run service: $service"
        fi
        
        # Backup domain mappings
        local domain_mappings=$(gcloud run domain-mappings list --region="$REGION" \
            --project="$PROJECT_ID" --filter="spec.routeName:$service" \
            --format="value(metadata.name)" 2>/dev/null || echo "")
        
        if [[ -n "$domain_mappings" ]]; then
            echo "$domain_mappings" | while read -r domain; do
                if [[ -n "$domain" ]]; then
                    local domain_file="$backup_dir/domain-$service-$domain-$(date +%Y%m%d%H%M%S).yaml"
                    
                    if gcloud run domain-mappings describe "$domain" --region="$REGION" \
                        --project="$PROJECT_ID" --format="export" > "$domain_file" 2>/dev/null; then
                        log SUCCESS "Domain mapping backed up: $domain for $service"
                    else
                        log WARN "Failed to backup domain mapping: $domain"
                    fi
                fi
            done
        fi
    done
    
    # Create archive
    local archive_file="cloud-run-backup-$(date +%Y%m%d%H%M%S).tar.gz"
    tar -czf "/tmp/$archive_file" -C "$backup_dir" .
    
    # Upload to backup bucket
    if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/cloud-run-configs/"; then
        log SUCCESS "Cloud Run configurations archive uploaded: $archive_file"
    else
        log ERROR "Failed to upload Cloud Run configurations archive"
        return 1
    fi
    
    # Cleanup
    rm -rf "$backup_dir" "/tmp/$archive_file"
    
    return 0
}

# Function to backup load balancer configurations
backup_load_balancer_configurations() {
    log INFO "Starting load balancer configurations backup..."
    
    local backup_dir="/tmp/lb-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup URL maps
    log INFO "Backing up URL maps..."
    local url_maps=$(gcloud compute url-maps list --global --project="$PROJECT_ID" \
        --filter="name ~ isectech" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$url_maps" ]]; then
        echo "$url_maps" | while read -r url_map; do
            if [[ -n "$url_map" ]]; then
                local url_map_file="$backup_dir/url-map-$url_map-$(date +%Y%m%d%H%M%S).yaml"
                
                if gcloud compute url-maps export "$url_map" \
                    --destination="$url_map_file" --global --project="$PROJECT_ID" 2>/dev/null; then
                    log SUCCESS "URL map backed up: $url_map"
                else
                    log WARN "Failed to backup URL map: $url_map"
                fi
            fi
        done
    fi
    
    # Backup backend services
    log INFO "Backing up backend services..."
    local backend_services=$(gcloud compute backend-services list --global --project="$PROJECT_ID" \
        --filter="name ~ isectech" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$backend_services" ]]; then
        echo "$backend_services" | while read -r backend_service; do
            if [[ -n "$backend_service" ]]; then
                local backend_file="$backup_dir/backend-service-$backend_service-$(date +%Y%m%d%H%M%S).yaml"
                
                if gcloud compute backend-services export "$backend_service" \
                    --destination="$backend_file" --global --project="$PROJECT_ID" 2>/dev/null; then
                    log SUCCESS "Backend service backed up: $backend_service"
                else
                    log WARN "Failed to backup backend service: $backend_service"
                fi
            fi
        done
    fi
    
    # Backup target proxies
    log INFO "Backing up target proxies..."
    local target_proxies=$(gcloud compute target-https-proxies list --global --project="$PROJECT_ID" \
        --filter="name ~ isectech" --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$target_proxies" ]]; then
        echo "$target_proxies" | while read -r proxy; do
            if [[ -n "$proxy" ]]; then
                local proxy_file="$backup_dir/target-proxy-$proxy-$(date +%Y%m%d%H%M%S).json"
                
                if gcloud compute target-https-proxies describe "$proxy" \
                    --global --project="$PROJECT_ID" --format="json" > "$proxy_file" 2>/dev/null; then
                    log SUCCESS "Target proxy backed up: $proxy"
                else
                    log WARN "Failed to backup target proxy: $proxy"
                fi
            fi
        done
    fi
    
    # Create archive
    if [[ -n "$(ls -A "$backup_dir" 2>/dev/null)" ]]; then
        local archive_file="load-balancer-backup-$(date +%Y%m%d%H%M%S).tar.gz"
        tar -czf "/tmp/$archive_file" -C "$backup_dir" .
        
        # Upload to backup bucket
        if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/load-balancer-configs/"; then
            log SUCCESS "Load balancer configurations archive uploaded: $archive_file"
        else
            log ERROR "Failed to upload load balancer configurations archive"
            return 1
        fi
        
        # Cleanup
        rm -f "/tmp/$archive_file"
    else
        log INFO "No load balancer configurations to archive"
    fi
    
    rm -rf "$backup_dir"
    return 0
}

# Function to backup Cloud Armor security policies
backup_cloud_armor_policies() {
    log INFO "Starting Cloud Armor security policies backup..."
    
    local backup_dir="/tmp/armor-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    local policies=$(gcloud compute security-policies list --project="$PROJECT_ID" \
        --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$policies" ]]; then
        echo "$policies" | while read -r policy; do
            if [[ -n "$policy" ]]; then
                log INFO "Backing up Cloud Armor policy: $policy"
                
                local policy_file="$backup_dir/security-policy-$policy-$(date +%Y%m%d%H%M%S).yaml"
                
                if gcloud compute security-policies export "$policy" \
                    --destination="$policy_file" --project="$PROJECT_ID" 2>/dev/null; then
                    log SUCCESS "Cloud Armor policy backed up: $policy"
                else
                    log WARN "Failed to backup Cloud Armor policy: $policy"
                fi
            fi
        done
        
        # Create archive
        local archive_file="cloud-armor-policies-$(date +%Y%m%d%H%M%S).tar.gz"
        tar -czf "/tmp/$archive_file" -C "$backup_dir" .
        
        # Upload to backup bucket
        if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/cloud-armor-policies/"; then
            log SUCCESS "Cloud Armor policies archive uploaded: $archive_file"
        else
            log ERROR "Failed to upload Cloud Armor policies archive"
            return 1
        fi
        
        # Cleanup
        rm -f "/tmp/$archive_file"
    else
        log INFO "No Cloud Armor policies found to backup"
    fi
    
    rm -rf "$backup_dir"
    return 0
}

# Function to backup secrets
backup_secrets() {
    log INFO "Starting secrets backup..."
    
    local backup_dir="/tmp/secrets-backup-$(date +%Y%m%d%H%M%S)"
    mkdir -p "$backup_dir"
    
    # List all secrets (metadata only, not values)
    local secrets=$(gcloud secrets list --project="$PROJECT_ID" \
        --format="value(name)" 2>/dev/null || echo "")
    
    if [[ -n "$secrets" ]]; then
        # Create secrets inventory
        local inventory_file="$backup_dir/secrets-inventory-$(date +%Y%m%d%H%M%S).json"
        
        gcloud secrets list --project="$PROJECT_ID" \
            --format="json" > "$inventory_file" 2>/dev/null
        
        log SUCCESS "Secrets inventory created (metadata only)"
        
        # Note: We don't backup secret values for security reasons
        echo "# Secrets Backup Information" > "$backup_dir/README.md"
        echo "This backup contains metadata about secrets only." >> "$backup_dir/README.md"
        echo "Secret values are not included for security reasons." >> "$backup_dir/README.md"
        echo "Generated: $(date)" >> "$backup_dir/README.md"
        
        # Create archive
        local archive_file="secrets-metadata-$(date +%Y%m%d%H%M%S).tar.gz"
        tar -czf "/tmp/$archive_file" -C "$backup_dir" .
        
        # Upload to backup bucket
        if gsutil cp "/tmp/$archive_file" "$BACKUP_BUCKET/secrets-metadata/"; then
            log SUCCESS "Secrets metadata archive uploaded: $archive_file"
        else
            log ERROR "Failed to upload secrets metadata archive"
            return 1
        fi
        
        # Cleanup
        rm -f "/tmp/$archive_file"
    else
        log INFO "No secrets found to backup"
    fi
    
    rm -rf "$backup_dir"
    return 0
}

# Function to cleanup old backups
cleanup_old_backups() {
    log INFO "Starting old backup cleanup..."
    
    local retention_days=${BACKUP_RETENTION_DAYS:-30}
    local cutoff_date=$(date -d "$retention_days days ago" +%Y%m%d)
    
    local backup_types=("terraform-state" "dns-configs" "ssl-certificates" "cloud-run-configs" "load-balancer-configs" "cloud-armor-policies" "secrets-metadata")
    
    for backup_type in "${backup_types[@]}"; do
        log INFO "Cleaning up old $backup_type backups..."
        
        # List and delete old backups
        gsutil ls "$BACKUP_BUCKET/$backup_type/" 2>/dev/null | \
        grep -E "[0-9]{8}" | \
        while read -r backup_file; do
            # Extract date from filename
            local file_date=$(echo "$backup_file" | grep -o '[0-9]\{8\}' | head -1)
            
            if [[ "$file_date" < "$cutoff_date" ]]; then
                log INFO "Deleting old backup: $backup_file"
                gsutil rm "$backup_file" 2>/dev/null || log WARN "Failed to delete: $backup_file"
            fi
        done
    done
    
    log SUCCESS "Old backup cleanup completed"
}

# Function to create backup manifest
create_backup_manifest() {
    local backup_status="$1"
    
    log INFO "Creating backup manifest..."
    
    local manifest_file="/tmp/backup-manifest-$BACKUP_ID.json"
    
    cat > "$manifest_file" << EOF
{
  "backup_id": "$BACKUP_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "backup_type": "$BACKUP_TYPE",
  "status": "$backup_status",
  "duration_minutes": $(( ($(date +%s) - $(date -d "$(head -1 "$LOG_FILE" | cut -d']' -f1 | tr -d '[')" +%s)) / 60 )),
  "log_file": "$LOG_FILE",
  "schedule_mode": $([ "$SCHEDULE_MODE" == "--schedule" ] && echo "true" || echo "false"),
  "project_id": "$PROJECT_ID",
  "region": "$REGION",
  "backup_bucket": "$BACKUP_BUCKET"
}
EOF
    
    # Upload manifest to backup bucket
    gsutil cp "$manifest_file" "$BACKUP_BUCKET/manifests/" 2>/dev/null || true
    
    log INFO "Backup manifest created: $manifest_file"
}

# Main backup orchestration function
main() {
    log INFO "Starting automated backup process - ID: $BACKUP_ID"
    log INFO "Backup Type: $BACKUP_TYPE"
    
    if [[ "$SCHEDULE_MODE" == "--schedule" ]]; then
        log INFO "Running in scheduled mode"
    fi
    
    local backup_success=true
    
    case $BACKUP_TYPE in
        "full")
            log INFO "Executing full backup..."
            
            backup_terraform_state || backup_success=false
            backup_database || backup_success=false
            backup_dns_configuration || backup_success=false
            backup_ssl_certificates || backup_success=false
            backup_cloud_run_configurations || backup_success=false
            backup_load_balancer_configurations || backup_success=false
            backup_cloud_armor_policies || backup_success=false
            backup_secrets || backup_success=false
            
            # Cleanup old backups in full backup mode
            cleanup_old_backups || true
            ;;
            
        "terraform")
            backup_terraform_state || backup_success=false
            ;;
            
        "database")
            backup_database || backup_success=false
            ;;
            
        "dns")
            backup_dns_configuration || backup_success=false
            ;;
            
        "certificates")
            backup_ssl_certificates || backup_success=false
            ;;
            
        "services")
            backup_cloud_run_configurations || backup_success=false
            ;;
            
        "loadbalancer")
            backup_load_balancer_configurations || backup_success=false
            ;;
            
        "security")
            backup_cloud_armor_policies || backup_success=false
            backup_secrets || backup_success=false
            ;;
            
        *)
            log ERROR "Unknown backup type: $BACKUP_TYPE"
            exit 1
            ;;
    esac
    
    # Determine overall status
    local overall_status
    if $backup_success; then
        overall_status="SUCCESS"
        log SUCCESS "Automated backup completed successfully"
    else
        overall_status="FAILED"
        log ERROR "Automated backup failed"
    fi
    
    # Create backup manifest
    create_backup_manifest "$overall_status"
    
    # Send notification if email is available
    if command -v mail >/dev/null 2>&1; then
        echo "Backup ID: $BACKUP_ID\nStatus: $overall_status\nType: $BACKUP_TYPE\nLog: $LOG_FILE" | \
            mail -s "Backup $overall_status - $BACKUP_TYPE" "$NOTIFICATION_EMAIL" || true
    fi
    
    log INFO "Backup process completed - Status: $overall_status"
    log INFO "Log file: $LOG_FILE"
    
    # Exit with appropriate code
    if $backup_success; then
        exit 0
    else
        exit 1
    fi
}

# Script usage
usage() {
    cat << EOF
Usage: $0 [backup-type] [--schedule]

Backup Types:
  full          - Full backup of all components (default)
  terraform     - Terraform state backup only
  database      - Database backup only
  dns           - DNS configuration backup only
  certificates  - SSL certificates backup only
  services      - Cloud Run services backup only
  loadbalancer  - Load balancer configurations backup only
  security      - Cloud Armor and secrets backup only

Options:
  --schedule    - Run in scheduled mode (suppresses some output)

Examples:
  $0                    # Full backup
  $0 database           # Database backup only
  $0 full --schedule    # Scheduled full backup

Environment Variables:
  PROJECT_ID               - Google Cloud Project ID
  REGION                   - Primary region
  BACKUP_BUCKET           - Backup storage location
  NOTIFICATION_EMAIL      - Alert email address
  BACKUP_RETENTION_DAYS   - Backup retention period (default: 30)

EOF
}

# Handle command line arguments
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    usage
    exit 0
fi

# Execute main function
main "$@"