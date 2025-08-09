# SSL Certificate Recovery Runbook - iSECTECH Security Platform

**Document Version:** 1.0  
**Last Updated:** 2025-08-05  
**Owner:** DevOps Team  
**Classification:** CONFIDENTIAL - Internal Use Only

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Certificate Infrastructure](#certificate-infrastructure)
4. [Recovery Scenarios](#recovery-scenarios)
5. [Step-by-Step Recovery Procedures](#step-by-step-recovery-procedures)
6. [Validation and Testing](#validation-and-testing)
7. [Certificate Rotation Procedures](#certificate-rotation-procedures)
8. [Troubleshooting](#troubleshooting)
9. [Emergency Contacts](#emergency-contacts)
10. [Post-Recovery Actions](#post-recovery-actions)

## Overview

This runbook provides comprehensive procedures for recovering SSL certificates for the iSECTECH Security Platform. It covers Google Certificate Manager certificates, manual certificate restoration, domain validation recovery, and certificate chain reconstruction.

### Certificate Infrastructure Components

- **Certificate Manager:** Google Cloud Certificate Manager (managed certificates)
- **Certificate Domains:**
  - `api.isectech.com` (API Gateway - TLS termination)
  - `app.isectech.com` (Frontend Application - HTTPS)
  - `admin.isectech.com` (Admin Portal - HTTPS + Client Cert Auth)
  - `monitoring.isectech.com` (Monitoring Dashboard - HTTPS)
  - `docs.isectech.com` (Documentation Portal - HTTPS)
- **Certificate Types:** 
  - Domain Validation (DV) certificates via Let's Encrypt/Google CA
  - Extended Validation (EV) for admin portal
- **Certificate Distribution:** Cloud Load Balancer, Cloud Run, Cloud Armor

### Recovery Objectives

- **RTO (Recovery Time Objective):** 15 minutes for certificate provisioning
- **RPO (Recovery Point Objective):** Immediate (certificates are always current)
- **Maximum Allowable Downtime:** 30 minutes with SSL warnings acceptable

## Prerequisites

### Required Access and Permissions

```bash
# Required Google Cloud IAM roles
- roles/certificatemanager.editor (Certificate Manager Editor)
- roles/compute.loadBalancerAdmin (Load Balancer Admin)
- roles/run.admin (Cloud Run Admin)
- roles/dns.admin (DNS Administrator - for ACME challenges)
- roles/storage.objectAdmin (for certificate backups)
- roles/logging.viewer (for audit logs)
```

### Required Tools and Dependencies

```bash
# Install required tools
gcloud components install certificate-manager
openssl version
curl --version
jq --version

# Verify certificate manager API is enabled
gcloud services enable certificatemanager.googleapis.com
```

### Environment Variables

```bash
export PROJECT_ID="isectech-security-platform"
export REGION="us-central1"
export CERTIFICATE_NAME="isectech-ssl-cert"
export BACKUP_BUCKET="gs://isectech-cert-backups"
export DNS_ZONE_NAME="isectech-main-zone"
export NOTIFICATION_EMAIL="devops@isectech.com"
export SECURITY_EMAIL="security@isectech.com"
```

## Certificate Infrastructure

### Current Certificate Configuration

```yaml
# Certificate Manager Configuration
certificates:
  - name: "isectech-ssl-cert"
    domains:
      - "api.isectech.com"
      - "app.isectech.com"
      - "admin.isectech.com"
      - "monitoring.isectech.com"
      - "docs.isectech.com"
    managed: true
    scope: "EDGE_CACHE"
    
  - name: "isectech-admin-client-cert"
    domains:
      - "admin.isectech.com"
    type: "CLIENT_CERTIFICATE"
    managed: false
    
load_balancer_certificates:
  - certificate_name: "isectech-ssl-cert"
    load_balancer: "isectech-main-lb"
    
cloud_run_certificates:
  - service: "isectech-api"
    certificate: "isectech-ssl-cert"
  - service: "isectech-frontend"
    certificate: "isectech-ssl-cert"
```

### Certificate Chain Architecture

```
Root CA (Google Trust Services/Let's Encrypt)
├── Intermediate CA (R3/GTS CA 1D4)
│   ├── isectech-ssl-cert (SAN: *.isectech.com)
│   │   ├── api.isectech.com
│   │   ├── app.isectech.com
│   │   ├── admin.isectech.com
│   │   ├── monitoring.isectech.com
│   │   └── docs.isectech.com
│   └── isectech-admin-client-cert (EV Certificate)
└── Certificate Transparency Logs
    ├── Google Logs (Argon, Xenon)
    └── Other CT Logs
```

## Recovery Scenarios

### Scenario 1: Certificate Manager Certificate Deletion

**Symptoms:**
- All HTTPS services return SSL/TLS errors
- Certificate Manager shows no certificates
- Load balancer SSL termination fails

**Impact:** CRITICAL - Complete HTTPS service outage

### Scenario 2: Certificate Expired or Revoked

**Symptoms:**
- Browser certificate warnings
- API clients rejecting connections
- Certificate validation failures

**Impact:** HIGH - Service degradation with security warnings

### Scenario 3: Domain Validation Failure

**Symptoms:**
- Certificate stuck in "PROVISIONING" state
- ACME challenge failures in logs
- DNS validation timeout errors

**Impact:** MEDIUM - New certificate issuance blocked

### Scenario 4: Certificate Chain Issues

**Symptoms:**
- Some clients accepting certificates, others rejecting
- Intermediate certificate missing errors
- SSL Labs showing chain issues

**Impact:** MEDIUM - Compatibility issues with some clients

### Scenario 5: Client Certificate Authentication Failure

**Symptoms:**
- Admin portal rejecting client certificates
- Certificate-based API authentication failing
- mTLS handshake failures

**Impact:** HIGH - Administrative access blocked

## Step-by-Step Recovery Procedures

### Procedure 1: Complete Certificate Manager Recovery

```bash
#!/bin/bash
# Certificate Manager Complete Recovery Script
# Usage: ./certificate-recovery.sh [force-recreate]

set -euo pipefail

FORCE_RECREATE=${1:-"false"}
RECOVERY_LOG="/tmp/cert-recovery-$(date +%Y%m%d%H%M%S).log"

echo "Starting Certificate Manager Recovery - $(date)" | tee -a $RECOVERY_LOG

# Step 1: Check current certificate status
echo "Step 1: Checking current certificate status..." | tee -a $RECOVERY_LOG
CERT_EXISTS=$(gcloud certificate-manager certificates list \
    --filter="name:$CERTIFICATE_NAME" \
    --format="value(name)" \
    --project=$PROJECT_ID 2>/dev/null || echo "")

if [[ -n "$CERT_EXISTS" ]] && [[ "$FORCE_RECREATE" != "true" ]]; then
    echo "Certificate exists. Current status:" | tee -a $RECOVERY_LOG
    gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID \
        --format="table(name,state,domains)" 2>&1 | tee -a $RECOVERY_LOG
    
    CERT_STATE=$(gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID \
        --format="value(state)" 2>/dev/null)
    
    if [[ "$CERT_STATE" == "ACTIVE" ]]; then
        echo "Certificate is already active. Skipping recreation." | tee -a $RECOVERY_LOG
        exit 0
    fi
fi

# Step 2: Backup existing certificate if it exists
if [[ -n "$CERT_EXISTS" ]]; then
    echo "Step 2: Backing up existing certificate configuration..." | tee -a $RECOVERY_LOG
    gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID \
        --format="export" > /tmp/cert-backup-$(date +%Y%m%d%H%M%S).yaml 2>&1 | tee -a $RECOVERY_LOG
    
    # Delete existing certificate if force recreate
    if [[ "$FORCE_RECREATE" == "true" ]]; then
        echo "Force recreate: Deleting existing certificate..." | tee -a $RECOVERY_LOG
        gcloud certificate-manager certificates delete $CERTIFICATE_NAME \
            --project=$PROJECT_ID \
            --quiet 2>&1 | tee -a $RECOVERY_LOG
    fi
fi

# Step 3: Create new managed certificate
echo "Step 3: Creating new managed certificate..." | tee -a $RECOVERY_LOG
gcloud certificate-manager certificates create $CERTIFICATE_NAME \
    --domains="api.isectech.com,app.isectech.com,admin.isectech.com,monitoring.isectech.com,docs.isectech.com" \
    --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG

# Step 4: Monitor certificate provisioning
echo "Step 4: Monitoring certificate provisioning..." | tee -a $RECOVERY_LOG
MAX_WAIT_MINUTES=30
WAIT_COUNT=0

while [[ $WAIT_COUNT -lt $MAX_WAIT_MINUTES ]]; do
    CERT_STATE=$(gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID \
        --format="value(state)" 2>/dev/null || echo "UNKNOWN")
    
    echo "Certificate state: $CERT_STATE (waited ${WAIT_COUNT} minutes)" | tee -a $RECOVERY_LOG
    
    if [[ "$CERT_STATE" == "ACTIVE" ]]; then
        echo "Certificate successfully provisioned!" | tee -a $RECOVERY_LOG
        break
    elif [[ "$CERT_STATE" == "FAILED" ]]; then
        echo "ERROR: Certificate provisioning failed!" | tee -a $RECOVERY_LOG
        # Get detailed error information
        gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
            --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG
        exit 1
    fi
    
    sleep 60
    ((WAIT_COUNT++))
done

if [[ $WAIT_COUNT -ge $MAX_WAIT_MINUTES ]]; then
    echo "WARNING: Certificate provisioning timeout after $MAX_WAIT_MINUTES minutes" | tee -a $RECOVERY_LOG
    echo "Current certificate status:" | tee -a $RECOVERY_LOG
    gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG
fi

# Step 5: Update load balancer certificate mapping
echo "Step 5: Updating load balancer certificate mapping..." | tee -a $RECOVERY_LOG
./update-load-balancer-certificates.sh 2>&1 | tee -a $RECOVERY_LOG

# Step 6: Update Cloud Run certificate mapping
echo "Step 6: Updating Cloud Run certificate mapping..." | tee -a $RECOVERY_LOG
./update-cloud-run-certificates.sh 2>&1 | tee -a $RECOVERY_LOG

# Step 7: Verify certificate installation
echo "Step 7: Verifying certificate installation..." | tee -a $RECOVERY_LOG
./verify-certificate-installation.sh 2>&1 | tee -a $RECOVERY_LOG

echo "Certificate Manager Recovery completed - $(date)" | tee -a $RECOVERY_LOG
echo "Recovery log saved to: $RECOVERY_LOG"
```

### Procedure 2: Domain Validation Recovery

```bash
#!/bin/bash
# Domain Validation Recovery Script
# Usage: ./domain-validation-recovery.sh [domain]

set -euo pipefail

DOMAIN=${1:-"api.isectech.com"}
VALIDATION_LOG="/tmp/domain-validation-$(date +%Y%m%d%H%M%S).log"

echo "Starting Domain Validation Recovery for $DOMAIN - $(date)" | tee -a $VALIDATION_LOG

# Step 1: Check current validation status
echo "Step 1: Checking domain validation status..." | tee -a $VALIDATION_LOG
CERT_STATUS=$(gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
    --project=$PROJECT_ID \
    --format="json" 2>/dev/null)

echo "$CERT_STATUS" | jq -r '.managedCertificate.domainStatus[] | "\(.domain): \(.state)"' | tee -a $VALIDATION_LOG

# Step 2: Check DNS records for ACME challenges
echo "Step 2: Checking DNS records for ACME challenges..." | tee -a $VALIDATION_LOG
ACME_CHALLENGE="_acme-challenge.$DOMAIN"

# Look for existing ACME challenge records
EXISTING_CHALLENGES=$(dig +short TXT $ACME_CHALLENGE @8.8.8.8 2>/dev/null || echo "NONE")
echo "Existing ACME challenges for $DOMAIN: $EXISTING_CHALLENGES" | tee -a $VALIDATION_LOG

# Step 3: Clear stale ACME challenge records
if [[ "$EXISTING_CHALLENGES" != "NONE" ]]; then
    echo "Step 3: Clearing stale ACME challenge records..." | tee -a $VALIDATION_LOG
    
    # Export current records
    gcloud dns record-sets export /tmp/current-dns-records.yaml \
        --zone=$DNS_ZONE_NAME \
        --project=$PROJECT_ID 2>&1 | tee -a $VALIDATION_LOG
    
    # Remove ACME challenge records
    gcloud dns record-sets list --zone=$DNS_ZONE_NAME --project=$PROJECT_ID \
        --filter="name ~ _acme-challenge" \
        --format="value(name,type)" | \
    while IFS=$'\t' read -r name type; do
        if [[ -n "$name" ]] && [[ -n "$type" ]]; then
            echo "Removing stale ACME record: $name $type" | tee -a $VALIDATION_LOG
            gcloud dns record-sets delete "$name" \
                --type="$type" \
                --zone=$DNS_ZONE_NAME \
                --project=$PROJECT_ID \
                --quiet 2>&1 | tee -a $VALIDATION_LOG || true
        fi
    done
fi

# Step 4: Trigger certificate re-validation
echo "Step 4: Triggering certificate re-validation..." | tee -a $VALIDATION_LOG

# Delete and recreate certificate to trigger fresh validation
gcloud certificate-manager certificates delete $CERTIFICATE_NAME \
    --project=$PROJECT_ID \
    --quiet 2>&1 | tee -a $VALIDATION_LOG

# Wait for deletion to complete
echo "Waiting 60 seconds for certificate deletion..." | tee -a $VALIDATION_LOG
sleep 60

# Recreate certificate
gcloud certificate-manager certificates create $CERTIFICATE_NAME \
    --domains="api.isectech.com,app.isectech.com,admin.isectech.com,monitoring.isectech.com,docs.isectech.com" \
    --project=$PROJECT_ID 2>&1 | tee -a $VALIDATION_LOG

# Step 5: Monitor new validation process
echo "Step 5: Monitoring new validation process..." | tee -a $VALIDATION_LOG
MAX_VALIDATION_WAIT=20
VALIDATION_COUNT=0

while [[ $VALIDATION_COUNT -lt $MAX_VALIDATION_WAIT ]]; do
    echo "Checking validation status (attempt $((VALIDATION_COUNT + 1))/$MAX_VALIDATION_WAIT)..." | tee -a $VALIDATION_LOG
    
    CERT_STATUS=$(gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
        --project=$PROJECT_ID \
        --format="json" 2>/dev/null || echo "{}")
    
    # Check domain validation status
    DOMAIN_STATUS=$(echo "$CERT_STATUS" | jq -r ".managedCertificate.domainStatus[]? | select(.domain == \"$DOMAIN\") | .state" 2>/dev/null || echo "UNKNOWN")
    echo "$DOMAIN validation status: $DOMAIN_STATUS" | tee -a $VALIDATION_LOG
    
    # Check for ACME challenge DNS records
    ACME_RECORDS=$(dig +short TXT "_acme-challenge.$DOMAIN" @8.8.8.8 2>/dev/null || echo "NONE")
    if [[ "$ACME_RECORDS" != "NONE" ]]; then
        echo "ACME challenge DNS record found: $ACME_RECORDS" | tee -a $VALIDATION_LOG
    fi
    
    if [[ "$DOMAIN_STATUS" == "ACTIVE" ]]; then
        echo "Domain $DOMAIN validation successful!" | tee -a $VALIDATION_LOG
        break
    elif [[ "$DOMAIN_STATUS" == "FAILED" ]]; then
        echo "ERROR: Domain $DOMAIN validation failed!" | tee -a $VALIDATION_LOG
        echo "Full certificate status:" | tee -a $VALIDATION_LOG
        echo "$CERT_STATUS" | jq . | tee -a $VALIDATION_LOG
        exit 1
    fi
    
    sleep 60
    ((VALIDATION_COUNT++))
done

if [[ $VALIDATION_COUNT -ge $MAX_VALIDATION_WAIT ]]; then
    echo "WARNING: Domain validation timeout after $MAX_VALIDATION_WAIT minutes" | tee -a $VALIDATION_LOG
    echo "Manual intervention may be required" | tee -a $VALIDATION_LOG
fi

echo "Domain Validation Recovery completed - $(date)" | tee -a $VALIDATION_LOG
echo "Validation log saved to: $VALIDATION_LOG"
```

### Procedure 3: Client Certificate Recovery

```bash
#!/bin/bash
# Client Certificate Recovery Script
# Usage: ./client-certificate-recovery.sh

set -euo pipefail

CLIENT_CERT_LOG="/tmp/client-cert-recovery-$(date +%Y%m%d%H%M%S).log"

echo "Starting Client Certificate Recovery - $(date)" | tee -a $CLIENT_CERT_LOG

# Step 1: Check for backed up client certificates
echo "Step 1: Checking for backed up client certificates..." | tee -a $CLIENT_CERT_LOG
gsutil ls $BACKUP_BUCKET/client-certificates/ 2>&1 | tee -a $CLIENT_CERT_LOG || {
    echo "No client certificate backups found. Creating new certificates." | tee -a $CLIENT_CERT_LOG
}

# Step 2: Generate new client certificate authority if needed
echo "Step 2: Setting up client certificate authority..." | tee -a $CLIENT_CERT_LOG

CA_DIR="/tmp/client-ca-$(date +%Y%m%d%H%M%S)"
mkdir -p $CA_DIR

# Generate CA private key
openssl genrsa -out $CA_DIR/ca-key.pem 4096 2>&1 | tee -a $CLIENT_CERT_LOG

# Generate CA certificate
openssl req -new -x509 -days 3650 -key $CA_DIR/ca-key.pem -out $CA_DIR/ca-cert.pem \
    -subj "/C=US/ST=CA/L=San Francisco/O=iSECTECH/OU=Security/CN=iSECTECH Client CA" \
    2>&1 | tee -a $CLIENT_CERT_LOG

# Step 3: Generate admin client certificate
echo "Step 3: Generating admin client certificate..." | tee -a $CLIENT_CERT_LOG

# Generate client private key
openssl genrsa -out $CA_DIR/admin-client-key.pem 2048 2>&1 | tee -a $CLIENT_CERT_LOG

# Generate client certificate signing request
openssl req -new -key $CA_DIR/admin-client-key.pem -out $CA_DIR/admin-client.csr \
    -subj "/C=US/ST=CA/L=San Francisco/O=iSECTECH/OU=Admin/CN=admin.isectech.com" \
    2>&1 | tee -a $CLIENT_CERT_LOG

# Create certificate extensions file
cat > $CA_DIR/client-cert-extensions.txt << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = admin.isectech.com
DNS.2 = *.admin.isectech.com
EOF

# Sign client certificate
openssl x509 -req -in $CA_DIR/admin-client.csr -CA $CA_DIR/ca-cert.pem -CAkey $CA_DIR/ca-key.pem \
    -CAcreateserial -out $CA_DIR/admin-client-cert.pem -days 365 \
    -extensions v3_req -extfile $CA_DIR/client-cert-extensions.txt \
    2>&1 | tee -a $CLIENT_CERT_LOG

# Step 4: Create client certificate bundle
echo "Step 4: Creating client certificate bundle..." | tee -a $CLIENT_CERT_LOG

# Create PKCS#12 bundle for browsers
openssl pkcs12 -export -out $CA_DIR/admin-client.p12 \
    -inkey $CA_DIR/admin-client-key.pem \
    -in $CA_DIR/admin-client-cert.pem \
    -certfile $CA_DIR/ca-cert.pem \
    -passout pass:isectech-admin-2025 \
    2>&1 | tee -a $CLIENT_CERT_LOG

# Step 5: Upload certificates to Cloud Run and Load Balancer
echo "Step 5: Uploading client certificates to services..." | tee -a $CLIENT_CERT_LOG

# Upload CA certificate to Secret Manager
gcloud secrets create client-ca-cert --data-file=$CA_DIR/ca-cert.pem --project=$PROJECT_ID 2>&1 | tee -a $CLIENT_CERT_LOG || {
    # Update existing secret
    gcloud secrets versions add client-ca-cert --data-file=$CA_DIR/ca-cert.pem --project=$PROJECT_ID 2>&1 | tee -a $CLIENT_CERT_LOG
}

# Upload client certificate bundle to Secret Manager
gcloud secrets create admin-client-cert --data-file=$CA_DIR/admin-client.p12 --project=$PROJECT_ID 2>&1 | tee -a $CLIENT_CERT_LOG || {
    # Update existing secret
    gcloud secrets versions add admin-client-cert --data-file=$CA_DIR/admin-client.p12 --project=$PROJECT_ID 2>&1 | tee -a $CLIENT_CERT_LOG
}

# Step 6: Update application configuration
echo "Step 6: Updating application configuration for client certificates..." | tee -a $CLIENT_CERT_LOG

# Update Cloud Run service to use client certificate validation
gcloud run services update isectech-admin \
    --set-env-vars="CLIENT_CA_CERT_SECRET=client-ca-cert" \
    --set-env-vars="REQUIRE_CLIENT_CERT=true" \
    --region=$REGION \
    --project=$PROJECT_ID 2>&1 | tee -a $CLIENT_CERT_LOG

# Step 7: Backup new certificates
echo "Step 7: Backing up new certificates..." | tee -a $CLIENT_CERT_LOG
BACKUP_DIR="client-certificates/$(date +%Y%m%d%H%M%S)"

gsutil cp $CA_DIR/ca-cert.pem $BACKUP_BUCKET/$BACKUP_DIR/ 2>&1 | tee -a $CLIENT_CERT_LOG
gsutil cp $CA_DIR/admin-client.p12 $BACKUP_BUCKET/$BACKUP_DIR/ 2>&1 | tee -a $CLIENT_CERT_LOG

# Create certificate information file
cat > $CA_DIR/certificate-info.txt << EOF
Client Certificate Recovery Information
Generated: $(date)
CA Certificate: ca-cert.pem
Client Certificate Bundle: admin-client.p12
Client Certificate Password: isectech-admin-2025
Valid Until: $(openssl x509 -in $CA_DIR/admin-client-cert.pem -noout -enddate)

Installation Instructions:
1. Download admin-client.p12 from backup bucket
2. Import into browser certificate store with password: isectech-admin-2025
3. Access https://admin.isectech.com
4. Browser should prompt for certificate selection
EOF

gsutil cp $CA_DIR/certificate-info.txt $BACKUP_BUCKET/$BACKUP_DIR/ 2>&1 | tee -a $CLIENT_CERT_LOG

# Step 8: Verify client certificate authentication
echo "Step 8: Verifying client certificate authentication..." | tee -a $CLIENT_CERT_LOG

# Test client certificate authentication (this will likely fail in automated script, but shows the process)
curl -v --cert $CA_DIR/admin-client-cert.pem --key $CA_DIR/admin-client-key.pem \
    https://admin.isectech.com/health 2>&1 | tee -a $CLIENT_CERT_LOG || {
    echo "Client certificate test failed (expected in recovery scenario)" | tee -a $CLIENT_CERT_LOG
}

echo "Client Certificate Recovery completed - $(date)" | tee -a $CLIENT_CERT_LOG
echo "Client certificate log saved to: $CLIENT_CERT_LOG"
echo "Client certificate bundle location: $CA_DIR/admin-client.p12"
echo "Certificate backup location: $BACKUP_BUCKET/$BACKUP_DIR/"
echo "Certificate password: isectech-admin-2025"
```

## Validation and Testing

### Certificate Installation Verification Script

```bash
#!/bin/bash
# Certificate Installation Verification
# Usage: ./verify-certificate-installation.sh

set -euo pipefail

VERIFICATION_LOG="/tmp/cert-verification-$(date +%Y%m%d%H%M%S).log"

echo "Starting Certificate Installation Verification - $(date)" | tee -a $VERIFICATION_LOG

DOMAINS=("api.isectech.com" "app.isectech.com" "admin.isectech.com" "monitoring.isectech.com" "docs.isectech.com")

for domain in "${DOMAINS[@]}"; do
    echo "Verifying certificate for $domain..." | tee -a $VERIFICATION_LOG
    
    # Test 1: Basic SSL connection
    SSL_CONNECT=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | \
        openssl x509 -noout -subject -dates 2>/dev/null || echo "FAILED")
    
    if [[ "$SSL_CONNECT" == "FAILED" ]]; then
        echo "  FAILED: SSL connection to $domain" | tee -a $VERIFICATION_LOG
        continue
    else
        echo "  OK: SSL connection successful" | tee -a $VERIFICATION_LOG
        echo "  Certificate info: $SSL_CONNECT" | tee -a $VERIFICATION_LOG
    fi
    
    # Test 2: Certificate chain validation
    CHAIN_VALID=$(echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | \
        openssl verify 2>&1 | grep -c "OK" || echo "0")
    
    if [[ "$CHAIN_VALID" -gt 0 ]]; then
        echo "  OK: Certificate chain valid" | tee -a $VERIFICATION_LOG
    else
        echo "  WARNING: Certificate chain validation issues" | tee -a $VERIFICATION_LOG
    fi
    
    # Test 3: Certificate transparency logs
    CT_LOGS=$(curl -s "https://crt.sh/?q=$domain&output=json" | jq length 2>/dev/null || echo "0")
    echo "  Certificate Transparency entries: $CT_LOGS" | tee -a $VERIFICATION_LOG
    
    # Test 4: SSL Labs grade (external check)
    echo "  External SSL check: https://www.ssllabs.com/ssltest/analyze.html?d=$domain" | tee -a $VERIFICATION_LOG
    
    # Test 5: OCSP stapling
    OCSP_STATUS=$(echo | openssl s_client -servername $domain -connect $domain:443 -status 2>/dev/null | \
        grep -c "OCSP Response Status: successful" || echo "0")
    
    if [[ "$OCSP_STATUS" -gt 0 ]]; then
        echo "  OK: OCSP stapling enabled" | tee -a $VERIFICATION_LOG
    else
        echo "  INFO: OCSP stapling not detected" | tee -a $VERIFICATION_LOG
    fi
    
    echo "" | tee -a $VERIFICATION_LOG
done

# Test Certificate Manager status
echo "Certificate Manager Status:" | tee -a $VERIFICATION_LOG
gcloud certificate-manager certificates list --project=$PROJECT_ID \
    --format="table(name,state,domains,managed.domainStatus[].state)" 2>&1 | tee -a $VERIFICATION_LOG

echo "Certificate Installation Verification completed - $(date)" | tee -a $VERIFICATION_LOG
echo "Verification log saved to: $VERIFICATION_LOG"
```

### Load Balancer Certificate Update Script

```bash
#!/bin/bash
# Load Balancer Certificate Update Script
# Usage: ./update-load-balancer-certificates.sh

set -euo pipefail

LB_UPDATE_LOG="/tmp/lb-cert-update-$(date +%Y%m%d%H%M%S).log"

echo "Starting Load Balancer Certificate Update - $(date)" | tee -a $LB_UPDATE_LOG

# Step 1: List current SSL certificates on load balancer
echo "Step 1: Current load balancer SSL certificate configuration..." | tee -a $LB_UPDATE_LOG
gcloud compute ssl-certificates list --project=$PROJECT_ID \
    --format="table(name,type,creationTimestamp,expireTime)" 2>&1 | tee -a $LB_UPDATE_LOG

# Step 2: Create new SSL certificate resource pointing to Certificate Manager
echo "Step 2: Creating SSL certificate resource..." | tee -a $LB_UPDATE_LOG

# Delete existing SSL certificate resource if exists
gcloud compute ssl-certificates delete isectech-ssl-cert-resource \
    --global \
    --project=$PROJECT_ID \
    --quiet 2>&1 | tee -a $LB_UPDATE_LOG || true

# Create new SSL certificate resource
gcloud compute ssl-certificates create isectech-ssl-cert-resource \
    --certificate-manager-certificates=$CERTIFICATE_NAME \
    --global \
    --project=$PROJECT_ID 2>&1 | tee -a $LB_UPDATE_LOG

# Step 3: Update HTTPS load balancer target proxy
echo "Step 3: Updating HTTPS load balancer target proxy..." | tee -a $LB_UPDATE_LOG

# Find the target HTTPS proxy
TARGET_PROXY=$(gcloud compute target-https-proxies list \
    --filter="name ~ isectech" \
    --format="value(name)" \
    --project=$PROJECT_ID | head -1)

if [[ -n "$TARGET_PROXY" ]]; then
    echo "Updating target proxy: $TARGET_PROXY" | tee -a $LB_UPDATE_LOG
    gcloud compute target-https-proxies update $TARGET_PROXY \
        --ssl-certificates=isectech-ssl-cert-resource \
        --global \
        --project=$PROJECT_ID 2>&1 | tee -a $LB_UPDATE_LOG
else
    echo "WARNING: No target HTTPS proxy found for update" | tee -a $LB_UPDATE_LOG
fi

# Step 4: Verify load balancer configuration
echo "Step 4: Verifying load balancer certificate configuration..." | tee -a $LB_UPDATE_LOG
gcloud compute target-https-proxies describe $TARGET_PROXY \
    --global \
    --project=$PROJECT_ID \
    --format="table(name,sslCertificates)" 2>&1 | tee -a $LB_UPDATE_LOG

echo "Load Balancer Certificate Update completed - $(date)" | tee -a $LB_UPDATE_LOG
echo "Update log saved to: $LB_UPDATE_LOG"
```

### Cloud Run Certificate Update Script

```bash
#!/bin/bash
# Cloud Run Certificate Update Script
# Usage: ./update-cloud-run-certificates.sh

set -euo pipefail

CR_UPDATE_LOG="/tmp/cr-cert-update-$(date +%Y%m%d%H%M%S).log"

echo "Starting Cloud Run Certificate Update - $(date)" | tee -a $CR_UPDATE_LOG

SERVICES=("isectech-api" "isectech-frontend" "isectech-admin" "isectech-monitoring")

for service in "${SERVICES[@]}"; do
    echo "Updating certificate mapping for service: $service" | tee -a $CR_UPDATE_LOG
    
    # Step 1: Remove existing domain mappings
    echo "  Removing existing domain mappings..." | tee -a $CR_UPDATE_LOG
    gcloud run domain-mappings list --region=$REGION --project=$PROJECT_ID \
        --filter="spec.routeName:$service" \
        --format="value(metadata.name)" | \
    while read -r domain_mapping; do
        if [[ -n "$domain_mapping" ]]; then
            echo "    Removing domain mapping: $domain_mapping" | tee -a $CR_UPDATE_LOG
            gcloud run domain-mappings delete "$domain_mapping" \
                --region=$REGION \
                --project=$PROJECT_ID \
                --quiet 2>&1 | tee -a $CR_UPDATE_LOG || true
        fi
    done
    
    # Step 2: Create new domain mappings with updated certificate
    case $service in
        "isectech-api")
            DOMAIN="api.isectech.com"
            ;;
        "isectech-frontend")
            DOMAIN="app.isectech.com"
            ;;
        "isectech-admin")
            DOMAIN="admin.isectech.com"
            ;;
        "isectech-monitoring")
            DOMAIN="monitoring.isectech.com"
            ;;
        *)
            echo "    WARNING: Unknown service $service, skipping" | tee -a $CR_UPDATE_LOG
            continue
            ;;
    esac
    
    echo "  Creating domain mapping: $DOMAIN -> $service" | tee -a $CR_UPDATE_LOG
    gcloud run domain-mappings create \
        --service=$service \
        --domain=$DOMAIN \
        --region=$REGION \
        --project=$PROJECT_ID 2>&1 | tee -a $CR_UPDATE_LOG
    
    # Step 3: Verify domain mapping
    echo "  Verifying domain mapping..." | tee -a $CR_UPDATE_LOG
    gcloud run domain-mappings describe $DOMAIN \
        --region=$REGION \
        --project=$PROJECT_ID \
        --format="table(metadata.name,spec.routeName,status.conditions[0].type,status.conditions[0].status)" \
        2>&1 | tee -a $CR_UPDATE_LOG
    
    echo "" | tee -a $CR_UPDATE_LOG
done

echo "Cloud Run Certificate Update completed - $(date)" | tee -a $CR_UPDATE_LOG
echo "Update log saved to: $CR_UPDATE_LOG"
```

## Certificate Rotation Procedures

### Automated Certificate Rotation

```bash
#!/bin/bash
# Automated Certificate Rotation Script
# Usage: ./certificate-rotation.sh [days-before-expiry]

set -euo pipefail

DAYS_BEFORE_EXPIRY=${1:-30}
ROTATION_LOG="/tmp/cert-rotation-$(date +%Y%m%d%H%M%S).log"

echo "Starting Certificate Rotation Check - $(date)" | tee -a $ROTATION_LOG
echo "Checking certificates expiring in $DAYS_BEFORE_EXPIRY days" | tee -a $ROTATION_LOG

# Check Certificate Manager certificates
echo "Checking Certificate Manager certificates..." | tee -a $ROTATION_LOG
CERT_LIST=$(gcloud certificate-manager certificates list --project=$PROJECT_ID --format="json")

echo "$CERT_LIST" | jq -r '.[] | "\(.name) \(.expireTime)"' | \
while read -r cert_name expire_time; do
    if [[ -n "$expire_time" ]] && [[ "$expire_time" != "null" ]]; then
        EXPIRE_EPOCH=$(date -d "$expire_time" +%s 2>/dev/null || echo "0")
        CURRENT_EPOCH=$(date +%s)
        DAYS_TO_EXPIRY=$(( (EXPIRE_EPOCH - CURRENT_EPOCH) / 86400 ))
        
        echo "Certificate: $cert_name, Days to expiry: $DAYS_TO_EXPIRY" | tee -a $ROTATION_LOG
        
        if [[ $DAYS_TO_EXPIRY -le $DAYS_BEFORE_EXPIRY ]] && [[ $DAYS_TO_EXPIRY -gt 0 ]]; then
            echo "  ACTION: Certificate $cert_name needs rotation" | tee -a $ROTATION_LOG
            
            # Trigger certificate renewal
            gcloud certificate-manager certificates update $cert_name \
                --update-labels=rotation-requested=$(date +%Y%m%d) \
                --project=$PROJECT_ID 2>&1 | tee -a $ROTATION_LOG
                
            # Send notification
            echo "Certificate rotation notification for $cert_name" | \
                mail -s "Certificate Rotation Required: $cert_name" $NOTIFICATION_EMAIL
        fi
    fi
done

echo "Certificate Rotation Check completed - $(date)" | tee -a $ROTATION_LOG
echo "Rotation log saved to: $ROTATION_LOG"
```

## Troubleshooting

### Common Certificate Issues and Solutions

#### Issue 1: Certificate Provisioning Stuck

**Symptoms:**
- Certificate stays in "PROVISIONING" state for hours
- Domain validation challenges failing

**Diagnostic Commands:**
```bash
# Check certificate detailed status
gcloud certificate-manager certificates describe $CERTIFICATE_NAME \
    --project=$PROJECT_ID --format="json" | jq '.managedCertificate.domainStatus'

# Check DNS ACME challenge records
dig +short TXT _acme-challenge.api.isectech.com @8.8.8.8
```

**Resolution:**
```bash
# Clear all ACME challenge records and restart
./domain-validation-recovery.sh api.isectech.com
```

#### Issue 2: Certificate Chain Issues

**Symptoms:**
- Some browsers/clients reject certificate
- SSL Labs shows chain issues

**Diagnostic Commands:**
```bash
# Check certificate chain
echo | openssl s_client -servername api.isectech.com -connect api.isectech.com:443 -showcerts

# Verify chain validity
echo | openssl s_client -servername api.isectech.com -connect api.isectech.com:443 | openssl verify
```

**Resolution:**
```bash
# Force certificate recreation
./certificate-recovery.sh force-recreate
```

#### Issue 3: Client Certificate Authentication Failures

**Symptoms:**
- Admin portal rejects client certificates
- Browser doesn't prompt for certificate selection

**Diagnostic Commands:**
```bash
# Test client certificate validation
curl -v --cert admin-client-cert.pem --key admin-client-key.pem https://admin.isectech.com/

# Check CA certificate in service
gcloud secrets versions access latest --secret="client-ca-cert" --project=$PROJECT_ID
```

**Resolution:**
```bash
# Regenerate client certificates
./client-certificate-recovery.sh
```

## Emergency Contacts

### Primary Contacts
- **DevOps On-Call:** +1-555-0123 (oncall@isectech.com)
- **Security Team:** +1-555-0124 (security@isectech.com)
- **Engineering Manager:** +1-555-0125 (engineering-mgr@isectech.com)

### Certificate Authority Contacts
- **Let's Encrypt Status:** https://letsencrypt.status.io/
- **Google CA Support:** Via Google Cloud Console
- **Certificate Transparency Logs:** https://www.certificate-transparency.org/

### Communication Channels
- **Slack:** #certificate-alerts, #incident-response
- **Email:** security@isectech.com
- **Status Page:** status.isectech.com

## Post-Recovery Actions

### Immediate Actions (0-15 minutes)
1. **Verify all services are accessible via HTTPS**
   ```bash
   ./verify-certificate-installation.sh
   ```

2. **Check certificate expiration dates**
   ```bash
   gcloud certificate-manager certificates list --project=$PROJECT_ID
   ```

3. **Update monitoring and alerting**
   - Verify certificate expiration monitoring
   - Clear any certificate-related alerts

### Short-term Actions (15 minutes - 2 hours)
1. **Update certificate inventory**
   - Document new certificate serial numbers
   - Update certificate management database

2. **Notify stakeholders**
   - Send recovery confirmation to security team
   - Update incident response documentation

3. **Review certificate logs**
   - Check Certificate Transparency logs
   - Verify proper certificate rotation logging

### Long-term Actions (2+ hours)
1. **Post-incident review**
   - Analyze root cause of certificate issues
   - Identify process improvements

2. **Update automation**
   - Enhance certificate monitoring
   - Improve automated recovery procedures

3. **Security assessment**
   - Review certificate-related security policies
   - Update client certificate management procedures

---

**Document Control:**
- **Classification:** CONFIDENTIAL - Internal Use Only
- **Review Frequency:** Quarterly
- **Next Review Date:** 2025-11-05
- **Owner:** DevOps Team
- **Approver:** Security Team Lead

**Change Log:**
- v1.0 (2025-08-05): Initial version - Comprehensive SSL certificate recovery procedures