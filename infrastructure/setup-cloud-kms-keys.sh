#!/bin/bash

# iSECTECH Cloud KMS Keys Setup - macOS Compatible
# Create encryption keys in existing key rings
# PRODUCTION-READY - No demo code, custom security tailored for iSECTECH

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-protech-project}"

# Multi-region configuration
REGIONS=("us-central1" "europe-west1" "asia-southeast1")
REGION_NAMES=("us" "eu" "asia")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
section() { echo -e "${PURPLE}[SECTION]${NC} $1"; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

# Export Google Cloud SDK to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

# Set project
gcloud config set project "$PROJECT_ID"

section "Creating iSECTECH Enterprise Encryption Keys"
log "Project: $PROJECT_ID"
log "Regions: ${REGIONS[*]}"

# Function to create encryption key (simplified)
create_encryption_key() {
    local key_ring="$1"
    local region="$2"
    local key_name="$3"
    local purpose="$4"
    local rotation_period="$5"
    
    log "Creating encryption key: $key_name in $key_ring"
    
    if gcloud kms keys describe "$key_name" --keyring="$key_ring" --location="$region" &>/dev/null; then
        warning "Key $key_name already exists in $key_ring"
        return 0
    fi
    
    # Calculate next rotation time (30 days from now)
    local next_rotation=$(date -u -v+30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '+30 days' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "2025-09-03T00:00:00Z")
    
    gcloud kms keys create "$key_name" \
        --keyring="$key_ring" \
        --location="$region" \
        --purpose=encryption \
        --rotation-period="$rotation_period" \
        --next-rotation-time="$next_rotation" \
        --protection-level=software \
        --quiet 2>/dev/null || {
            warning "Failed to create key $key_name"
            return 1
        }
    
    success "Created encryption key: $key_name ($rotation_period rotation)"
}

# Function to create signing key (simplified)
create_signing_key() {
    local key_ring="$1"
    local region="$2"
    local key_name="$3"
    local purpose="$4"
    local algorithm="${5:-rsa-sign-pss-2048-sha256}"
    
    log "Creating signing key: $key_name in $key_ring"
    
    if gcloud kms keys describe "$key_name" --keyring="$key_ring" --location="$region" &>/dev/null; then
        warning "Key $key_name already exists in $key_ring"
        return 0
    fi
    
    gcloud kms keys create "$key_name" \
        --keyring="$key_ring" \
        --location="$region" \
        --purpose=asymmetric-signing \
        --default-algorithm="$algorithm" \
        --protection-level=software \
        --quiet 2>/dev/null || {
            warning "Failed to create signing key $key_name"
            return 1
        }
    
    success "Created signing key: $key_name ($algorithm)"
}

# Create encryption keys in each region
section "Creating Multi-Purpose Encryption Keys"

for i in "${!REGIONS[@]}"; do
    region="${REGIONS[$i]}"
    region_short="${REGION_NAMES[$i]}"
    key_ring="isectech-keyring-${region_short}"
    
    info "Creating keys in $region ($key_ring)"
    
    # Database encryption keys (30-day rotation for high security)
    create_encryption_key "$key_ring" "$region" "database-primary-key" \
        "Primary Cloud SQL database encryption" "30d"
    
    create_encryption_key "$key_ring" "$region" "database-backup-key" \
        "Database backup encryption" "30d"
    
    # Application secrets (90-day rotation)
    create_encryption_key "$key_ring" "$region" "app-secrets-key" \
        "Application configuration secrets" "90d"
    
    create_encryption_key "$key_ring" "$region" "api-keys-encryption" \
        "API keys and external service credentials" "90d"
    
    # Kubernetes secrets (60-day rotation for container security)
    create_encryption_key "$key_ring" "$region" "kubernetes-secrets-key" \
        "GKE cluster secrets and config maps" "60d"
    
    create_encryption_key "$key_ring" "$region" "kubernetes-etcd-key" \
        "GKE etcd encryption at rest" "60d"
    
    # Multi-tenant isolation keys (30-day rotation for compliance)
    create_encryption_key "$key_ring" "$region" "tenant-data-isolation" \
        "Multi-tenant data isolation encryption" "30d"
    
    create_encryption_key "$key_ring" "$region" "tenant-secrets-isolation" \
        "Per-tenant secrets isolation" "30d"
    
    # Backup and archive encryption (365-day rotation for long-term storage)
    create_encryption_key "$key_ring" "$region" "backup-archive-key" \
        "Long-term backup and archive encryption" "365d"
    
    create_encryption_key "$key_ring" "$region" "disaster-recovery-key" \
        "Disaster recovery data encryption" "365d"
    
    # Audit and compliance keys (90-day rotation)
    create_encryption_key "$key_ring" "$region" "audit-logs-key" \
        "Audit log encryption for compliance" "90d"
    
    create_encryption_key "$key_ring" "$region" "compliance-data-key" \
        "Compliance reporting data encryption" "90d"
    
    # Certificate authority key (1 year rotation)
    create_encryption_key "$key_ring" "$region" "certificate-authority-key" \
        "Internal certificate authority encryption" "365d"
    
    sleep 2  # Rate limiting between regions
done

# Create signing keys for JWT and document signing
section "Creating Asymmetric Signing Keys"

for i in "${!REGIONS[@]}"; do
    region="${REGIONS[$i]}"
    region_short="${REGION_NAMES[$i]}"
    key_ring="isectech-keyring-${region_short}"
    
    info "Creating signing keys in $region"
    
    # JWT signing keys
    create_signing_key "$key_ring" "$region" "jwt-signing-key" \
        "JWT token signing for authentication" "rsa-sign-pss-2048-sha256"
    
    # Document signing keys
    create_signing_key "$key_ring" "$region" "document-signing-key" \
        "Security document and report signing" "rsa-sign-pss-4096-sha256"
    
    # API request signing
    create_signing_key "$key_ring" "$region" "api-request-signing" \
        "API request signature verification" "ec-sign-p256-sha256"
    
    sleep 2
done

section "Cloud KMS Keys Setup Complete!"
success "iSECTECH Enterprise KMS keys created successfully"
success "All encryption and signing keys deployed across 3 regions"

log "Verifying key creation:"
for i in "${!REGIONS[@]}"; do
    region="${REGIONS[$i]}"
    region_short="${REGION_NAMES[$i]}"
    key_ring="isectech-keyring-${region_short}"
    
    key_count=$(gcloud kms keys list --keyring="$key_ring" --location="$region" --format="value(name)" | wc -l)
    log "  $region ($key_ring): $key_count keys created"
done

log "KMS keys setup completed successfully with enterprise security standards!"