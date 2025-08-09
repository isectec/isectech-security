# DNS Recovery Runbook - iSECTECH Security Platform

**Document Version:** 1.0  
**Last Updated:** 2025-08-05  
**Owner:** DevOps Team  
**Classification:** CONFIDENTIAL - Internal Use Only

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Recovery Scenarios](#recovery-scenarios)
4. [Step-by-Step Recovery Procedures](#step-by-step-recovery-procedures)
5. [Validation and Testing](#validation-and-testing)
6. [Troubleshooting](#troubleshooting)
7. [Emergency Contacts](#emergency-contacts)
8. [Post-Recovery Actions](#post-recovery-actions)

## Overview

This runbook provides detailed procedures for recovering DNS infrastructure for the iSECTECH Security Platform. It covers DNS zone restoration, record recovery, DNSSEC re-enabling, and validation procedures.

### DNS Infrastructure Components

- **Primary DNS Zone:** `isectech.com`
- **Subdomains:** 
  - `api.isectech.com` (API Gateway)
  - `app.isectech.com` (Frontend Application)
  - `admin.isectech.com` (Admin Portal)
  - `monitoring.isectech.com` (Monitoring Dashboard)
  - `docs.isectech.com` (Documentation Portal)
- **DNS Provider:** Google Cloud DNS
- **DNSSEC:** Enabled with KSK and ZSK rotation
- **Geographic Distribution:** Multi-region (us-central1, us-east1, europe-west1)

### Recovery Objectives

- **RTO (Recovery Time Objective):** 10 minutes for DNS services
- **RPO (Recovery Point Objective):** 5 minutes for DNS records
- **Maximum Allowable Downtime:** 15 minutes

## Prerequisites

### Required Access and Permissions

```bash
# Required Google Cloud IAM roles
- roles/dns.admin (DNS Administrator)
- roles/compute.securityAdmin (for firewall rules)
- roles/iam.serviceAccountUser (for service account access)
- roles/logging.viewer (for audit logs)
```

### Required Tools

```bash
# Install required tools
gcloud components install --quiet
dig +version
nslookup --version
curl --version
jq --version
```

### Environment Variables

```bash
export PROJECT_ID="isectech-security-platform"
export DNS_ZONE_NAME="isectech-main-zone"
export DOMAIN_NAME="isectech.com"
export BACKUP_BUCKET="gs://isectech-dns-backups"
export NOTIFICATION_EMAIL="devops@isectech.com"
export PAGER_EMAIL="oncall@isectech.com"
```

## Recovery Scenarios

### Scenario 1: Complete DNS Zone Deletion

**Symptoms:**
- All DNS queries for isectech.com return NXDOMAIN
- Google Cloud Console shows no DNS zones
- All subdomains are unreachable

**Impact:** CRITICAL - Complete service outage

### Scenario 2: DNS Records Corruption

**Symptoms:**
- Some DNS queries return incorrect IP addresses
- Intermittent connectivity issues
- SSL certificate validation failures

**Impact:** HIGH - Partial service degradation

### Scenario 3: DNSSEC Key Compromise

**Symptoms:**
- DNSSEC validation failures
- DNS security warnings in browsers
- Failed DS record validation

**Impact:** HIGH - Security compromise

### Scenario 4: DNS Propagation Issues

**Symptoms:**
- DNS changes not propagating globally
- Inconsistent DNS responses from different regions
- CloudFlare or other CDN resolution issues

**Impact:** MEDIUM - Regional connectivity issues

## Step-by-Step Recovery Procedures

### Procedure 1: Complete DNS Zone Recovery

```bash
#!/bin/bash
# DNS Zone Complete Recovery Script
# Usage: ./dns-zone-recovery.sh [backup-timestamp]

set -euo pipefail

BACKUP_TIMESTAMP=${1:-$(date -d "1 hour ago" +%Y%m%d%H%M)}
RECOVERY_LOG="/tmp/dns-recovery-$(date +%Y%m%d%H%M%S).log"

echo "Starting DNS Zone Recovery - $(date)" | tee -a $RECOVERY_LOG

# Step 1: Verify backup exists
echo "Step 1: Verifying backup availability..." | tee -a $RECOVERY_LOG
if ! gsutil ls $BACKUP_BUCKET/zone-backup-$BACKUP_TIMESTAMP.json >/dev/null 2>&1; then
    echo "ERROR: Backup not found for timestamp $BACKUP_TIMESTAMP" | tee -a $RECOVERY_LOG
    echo "Available backups:" | tee -a $RECOVERY_LOG
    gsutil ls $BACKUP_BUCKET/zone-backup-*.json | tail -10 | tee -a $RECOVERY_LOG
    exit 1
fi

# Step 2: Create DNS zone
echo "Step 2: Creating DNS zone..." | tee -a $RECOVERY_LOG
gcloud dns managed-zones create $DNS_ZONE_NAME \
    --description="iSECTECH Security Platform DNS Zone" \
    --dns-name=$DOMAIN_NAME \
    --visibility=public \
    --dnssec-state=off \
    --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG

# Step 3: Import DNS records from backup
echo "Step 3: Importing DNS records from backup..." | tee -a $RECOVERY_LOG
gsutil cp $BACKUP_BUCKET/zone-backup-$BACKUP_TIMESTAMP.json /tmp/dns-backup.json
gcloud dns record-sets import /tmp/dns-backup.json \
    --zone=$DNS_ZONE_NAME \
    --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG

# Step 4: Enable DNSSEC
echo "Step 4: Enabling DNSSEC..." | tee -a $RECOVERY_LOG
gcloud dns managed-zones update $DNS_ZONE_NAME \
    --dnssec-state=on \
    --project=$PROJECT_ID 2>&1 | tee -a $RECOVERY_LOG

# Step 5: Update domain registrar with new name servers
echo "Step 5: Getting new name servers..." | tee -a $RECOVERY_LOG
gcloud dns managed-zones describe $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --format="value(nameServers)" | tee -a $RECOVERY_LOG

echo "MANUAL ACTION REQUIRED: Update domain registrar with these name servers" | tee -a $RECOVERY_LOG

# Step 6: Verify DNS propagation
echo "Step 6: Starting DNS propagation verification..." | tee -a $RECOVERY_LOG
./verify-dns-propagation.sh | tee -a $RECOVERY_LOG

echo "DNS Zone Recovery completed - $(date)" | tee -a $RECOVERY_LOG
echo "Recovery log saved to: $RECOVERY_LOG"
```

### Procedure 2: DNS Records Restoration

```bash
#!/bin/bash
# DNS Records Restoration Script
# Usage: ./dns-records-restore.sh [record-type] [backup-timestamp]

set -euo pipefail

RECORD_TYPE=${1:-"ALL"}
BACKUP_TIMESTAMP=${2:-$(date -d "30 minutes ago" +%Y%m%d%H%M)}
RESTORE_LOG="/tmp/dns-restore-$(date +%Y%m%d%H%M%S).log"

echo "Starting DNS Records Restoration - $(date)" | tee -a $RESTORE_LOG

# Step 1: Backup current records
echo "Step 1: Backing up current DNS records..." | tee -a $RESTORE_LOG
gcloud dns record-sets export /tmp/current-records-$(date +%Y%m%d%H%M%S).json \
    --zone=$DNS_ZONE_NAME \
    --project=$PROJECT_ID 2>&1 | tee -a $RESTORE_LOG

# Step 2: Download backup
echo "Step 2: Downloading backup records..." | tee -a $RESTORE_LOG
gsutil cp $BACKUP_BUCKET/records-backup-$BACKUP_TIMESTAMP.json /tmp/backup-records.json

# Step 3: Filter records by type if specified
if [ "$RECORD_TYPE" != "ALL" ]; then
    echo "Step 3: Filtering records for type: $RECORD_TYPE" | tee -a $RESTORE_LOG
    jq --arg type "$RECORD_TYPE" '.rrsets[] | select(.type == $type)' /tmp/backup-records.json > /tmp/filtered-records.json
    IMPORT_FILE="/tmp/filtered-records.json"
else
    IMPORT_FILE="/tmp/backup-records.json"
fi

# Step 4: Import records
echo "Step 4: Importing DNS records..." | tee -a $RESTORE_LOG
gcloud dns record-sets import $IMPORT_FILE \
    --zone=$DNS_ZONE_NAME \
    --replace-origin-ns \
    --project=$PROJECT_ID 2>&1 | tee -a $RESTORE_LOG

# Step 5: Verify critical records
echo "Step 5: Verifying critical DNS records..." | tee -a $RESTORE_LOG
CRITICAL_RECORDS=("api.isectech.com" "app.isectech.com" "admin.isectech.com" "monitoring.isectech.com")

for record in "${CRITICAL_RECORDS[@]}"; do
    echo "Verifying $record..." | tee -a $RESTORE_LOG
    dig +short $record @8.8.8.8 | tee -a $RESTORE_LOG
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo "WARNING: $record resolution failed" | tee -a $RESTORE_LOG
    fi
done

echo "DNS Records Restoration completed - $(date)" | tee -a $RESTORE_LOG
echo "Restore log saved to: $RESTORE_LOG"
```

### Procedure 3: DNSSEC Recovery

```bash
#!/bin/bash
# DNSSEC Recovery Script
# Usage: ./dnssec-recovery.sh

set -euo pipefail

DNSSEC_LOG="/tmp/dnssec-recovery-$(date +%Y%m%d%H%M%S).log"

echo "Starting DNSSEC Recovery - $(date)" | tee -a $DNSSEC_LOG

# Step 1: Disable DNSSEC temporarily
echo "Step 1: Disabling DNSSEC..." | tee -a $DNSSEC_LOG
gcloud dns managed-zones update $DNS_ZONE_NAME \
    --dnssec-state=off \
    --project=$PROJECT_ID 2>&1 | tee -a $DNSSEC_LOG

# Wait for propagation
echo "Waiting 60 seconds for DNSSEC disable propagation..." | tee -a $DNSSEC_LOG
sleep 60

# Step 2: Re-enable DNSSEC with new keys
echo "Step 2: Re-enabling DNSSEC with new keys..." | tee -a $DNSSEC_LOG
gcloud dns managed-zones update $DNS_ZONE_NAME \
    --dnssec-state=on \
    --project=$PROJECT_ID 2>&1 | tee -a $DNSSEC_LOG

# Step 3: Get new DS records
echo "Step 3: Retrieving new DS records..." | tee -a $DNSSEC_LOG
DS_RECORDS=$(gcloud dns managed-zones describe $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --format="value(dnssecConfig.defaultKeySpecs[0].keyType,dnssecConfig.defaultKeySpecs[0].algorithm)")

echo "New DS Records:" | tee -a $DNSSEC_LOG
gcloud dns managed-zones describe $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --format="table(dnssecConfig.defaultKeySpecs[0].keyType,dnssecConfig.defaultKeySpecs[0].algorithm)" | tee -a $DNSSEC_LOG

# Step 4: Generate DS record for domain registrar
echo "Step 4: Generating DS record for registrar..." | tee -a $DNSSEC_LOG
dig +short DNSKEY $DOMAIN_NAME @8.8.8.8 | \
    awk '{print $1, $2, $3, $4}' | \
    while read flags protocol algorithm key; do
        echo "DS Record: $flags $protocol $algorithm $(echo -n "$key" | openssl dgst -sha256 -binary | xxd -p -c 256)" | tee -a $DNSSEC_LOG
    done

echo "MANUAL ACTION REQUIRED: Update DS records at domain registrar" | tee -a $DNSSEC_LOG

# Step 5: Verify DNSSEC chain
echo "Step 5: Verifying DNSSEC chain..." | tee -a $DNSSEC_LOG
dig +dnssec +multi $DOMAIN_NAME @8.8.8.8 | tee -a $DNSSEC_LOG

echo "DNSSEC Recovery completed - $(date)" | tee -a $DNSSEC_LOG
echo "DNSSEC log saved to: $DNSSEC_LOG"
```

## Validation and Testing

### DNS Propagation Verification Script

```bash
#!/bin/bash
# DNS Propagation Verification
# Usage: ./verify-dns-propagation.sh

set -euo pipefail

VERIFICATION_LOG="/tmp/dns-verification-$(date +%Y%m%d%H%M%S).log"

echo "Starting DNS Propagation Verification - $(date)" | tee -a $VERIFICATION_LOG

# DNS servers to test against
DNS_SERVERS=("8.8.8.8" "1.1.1.1" "208.67.222.222" "64.6.64.6")
CRITICAL_RECORDS=("isectech.com" "api.isectech.com" "app.isectech.com" "admin.isectech.com")

for record in "${CRITICAL_RECORDS[@]}"; do
    echo "Testing $record..." | tee -a $VERIFICATION_LOG
    
    for dns_server in "${DNS_SERVERS[@]}"; do
        echo "  Testing against $dns_server..." | tee -a $VERIFICATION_LOG
        
        # Test A record
        A_RECORD=$(dig +short A $record @$dns_server 2>/dev/null || echo "FAILED")
        echo "    A: $A_RECORD" | tee -a $VERIFICATION_LOG
        
        # Test AAAA record if exists
        AAAA_RECORD=$(dig +short AAAA $record @$dns_server 2>/dev/null || echo "NONE")
        if [ "$AAAA_RECORD" != "NONE" ]; then
            echo "    AAAA: $AAAA_RECORD" | tee -a $VERIFICATION_LOG
        fi
        
        # Test DNSSEC if enabled
        DNSSEC_STATUS=$(dig +dnssec +short $record @$dns_server | grep -c RRSIG || echo "0")
        echo "    DNSSEC: $([[ $DNSSEC_STATUS -gt 0 ]] && echo "ENABLED" || echo "DISABLED")" | tee -a $VERIFICATION_LOG
    done
    echo "" | tee -a $VERIFICATION_LOG
done

# Test SSL certificate resolution
echo "Testing SSL certificate resolution..." | tee -a $VERIFICATION_LOG
for record in "${CRITICAL_RECORDS[@]}"; do
    if [[ $record != "isectech.com" ]]; then  # Skip apex domain for SSL test
        echo "  Testing SSL for $record..." | tee -a $VERIFICATION_LOG
        SSL_STATUS=$(curl -sI https://$record 2>/dev/null | head -1 || echo "FAILED")
        echo "    SSL Status: $SSL_STATUS" | tee -a $VERIFICATION_LOG
    fi
done

echo "DNS Propagation Verification completed - $(date)" | tee -a $VERIFICATION_LOG
echo "Verification log saved to: $VERIFICATION_LOG"
```

### Health Check Script

```bash
#!/bin/bash
# DNS Health Check Script
# Usage: ./dns-health-check.sh

set -euo pipefail

HEALTH_LOG="/tmp/dns-health-$(date +%Y%m%d%H%M%S).log"

echo "Starting DNS Health Check - $(date)" | tee -a $HEALTH_LOG

# Check 1: Zone exists and is active
echo "Check 1: DNS Zone Status..." | tee -a $HEALTH_LOG
ZONE_STATUS=$(gcloud dns managed-zones describe $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --format="value(name,dnsName,visibility)" 2>/dev/null || echo "ZONE_NOT_FOUND")

if [[ $ZONE_STATUS == "ZONE_NOT_FOUND" ]]; then
    echo "  CRITICAL: DNS Zone not found!" | tee -a $HEALTH_LOG
    exit 1
else
    echo "  OK: Zone exists - $ZONE_STATUS" | tee -a $HEALTH_LOG
fi

# Check 2: DNSSEC status
echo "Check 2: DNSSEC Status..." | tee -a $HEALTH_LOG
DNSSEC_STATUS=$(gcloud dns managed-zones describe $DNS_ZONE_NAME \
    --project=$PROJECT_ID \
    --format="value(dnssecConfig.state)" 2>/dev/null || echo "UNKNOWN")

echo "  DNSSEC State: $DNSSEC_STATUS" | tee -a $HEALTH_LOG

# Check 3: Critical records resolution
echo "Check 3: Critical Records Resolution..." | tee -a $HEALTH_LOG
FAILED_RECORDS=0

for record in "${CRITICAL_RECORDS[@]}"; do
    RESOLUTION=$(dig +short $record @8.8.8.8 2>/dev/null || echo "FAILED")
    if [[ $RESOLUTION == "FAILED" ]] || [[ -z $RESOLUTION ]]; then
        echo "  FAILED: $record" | tee -a $HEALTH_LOG
        ((FAILED_RECORDS++))
    else
        echo "  OK: $record -> $RESOLUTION" | tee -a $HEALTH_LOG
    fi
done

# Check 4: SSL certificate validity
echo "Check 4: SSL Certificate Validity..." | tee -a $HEALTH_LOG
for record in "${CRITICAL_RECORDS[@]}"; do
    if [[ $record != "isectech.com" ]]; then
        CERT_STATUS=$(echo | openssl s_client -servername $record -connect $record:443 2>/dev/null | \
            openssl x509 -noout -dates 2>/dev/null || echo "FAILED")
        if [[ $CERT_STATUS == "FAILED" ]]; then
            echo "  FAILED: $record SSL certificate" | tee -a $HEALTH_LOG
        else
            echo "  OK: $record SSL certificate valid" | tee -a $HEALTH_LOG
        fi
    fi
done

# Summary
echo "Health Check Summary - $(date)" | tee -a $HEALTH_LOG
if [[ $FAILED_RECORDS -eq 0 ]]; then
    echo "  OVERALL STATUS: HEALTHY" | tee -a $HEALTH_LOG
else
    echo "  OVERALL STATUS: DEGRADED ($FAILED_RECORDS failed records)" | tee -a $HEALTH_LOG
fi

echo "DNS Health Check completed - $(date)" | tee -a $HEALTH_LOG
echo "Health check log saved to: $HEALTH_LOG"
```

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: DNS Records Not Propagating

**Symptoms:**
- New DNS records not resolving after 30+ minutes
- Inconsistent responses from different DNS servers

**Resolution:**
```bash
# Check TTL values
gcloud dns record-sets list --zone=$DNS_ZONE_NAME --project=$PROJECT_ID

# Force DNS cache flush
sudo systemctl flush-dns  # Linux
sudo dscacheutil -flushcache  # macOS

# Test specific name servers
dig @ns-cloud-a1.googledomains.com isectech.com
```

#### Issue 2: DNSSEC Validation Failures

**Symptoms:**
- SERVFAIL responses from validating resolvers
- Browser security warnings

**Resolution:**
```bash
# Check DNSSEC chain
dig +dnssec +trace isectech.com

# Verify DS records at parent
dig +short DS isectech.com @8.8.8.8

# Re-sign zone if needed
gcloud dns managed-zones update $DNS_ZONE_NAME --dnssec-state=off --project=$PROJECT_ID
sleep 300  # Wait 5 minutes
gcloud dns managed-zones update $DNS_ZONE_NAME --dnssec-state=on --project=$PROJECT_ID
```

#### Issue 3: Certificate Manager Domain Validation Failures

**Symptoms:**
- SSL certificates stuck in "PROVISIONING" state
- Domain validation challenges failing

**Resolution:**
```bash
# Check certificate status
gcloud certificate-manager certificates list --project=$PROJECT_ID

# Verify ACME challenge records
dig +short _acme-challenge.api.isectech.com TXT @8.8.8.8

# Manual certificate refresh
gcloud certificate-manager certificates update isectech-ssl-cert \
    --domains=api.isectech.com,app.isectech.com,admin.isectech.com \
    --project=$PROJECT_ID
```

### Escalation Decision Tree

```
DNS Issue Detected
    ├── Complete Service Outage?
    │   ├── YES → CRITICAL: Page On-Call Engineer
    │   └── NO → Continue assessment
    ├── Security-Related (DNSSEC/Certificate)?
    │   ├── YES → HIGH: Notify Security Team + On-Call
    │   └── NO → Continue assessment
    ├── Single Service Affected?
    │   ├── YES → MEDIUM: Standard incident response
    │   └── NO → HIGH: Multiple services affected
    └── Regional Issues Only?
        ├── YES → LOW: Monitor and document
        └── NO → MEDIUM: Global impact
```

## Emergency Contacts

### Primary Contacts
- **DevOps On-Call:** +1-555-0123 (oncall@isectech.com)
- **Security Team:** +1-555-0124 (security@isectech.com)
- **Engineering Manager:** +1-555-0125 (engineering-mgr@isectech.com)

### Vendor Contacts
- **Google Cloud Support:** Case via console + phone support
- **Domain Registrar:** Varies by provider
- **CDN Provider:** Support ticket system

### Communication Channels
- **Slack:** #incident-response
- **Email:** devops@isectech.com
- **Status Page:** status.isectech.com

## Post-Recovery Actions

### Immediate Actions (0-30 minutes)
1. **Verify full service restoration**
   ```bash
   ./dns-health-check.sh
   ./verify-dns-propagation.sh
   ```

2. **Update monitoring dashboards**
   - Check all DNS monitoring alerts are green
   - Verify certificate expiration monitoring

3. **Notify stakeholders**
   - Send recovery confirmation to incident channel
   - Update status page

### Short-term Actions (30 minutes - 2 hours)
1. **Conduct post-incident review**
   - Document timeline of events
   - Identify root cause
   - Create action items for prevention

2. **Update documentation**
   - Record any procedural improvements
   - Update escalation contacts if needed

3. **Review and rotate credentials**
   - Consider rotating service account keys
   - Update emergency access procedures

### Long-term Actions (2+ hours)
1. **Implement preventive measures**
   - Add additional monitoring
   - Implement automated backup validation
   - Schedule disaster recovery drills

2. **Update disaster recovery plan**
   - Incorporate lessons learned
   - Test new procedures

3. **Training and knowledge sharing**
   - Brief team on incident and recovery
   - Update runbook based on experience

---

**Document Control:**
- **Classification:** CONFIDENTIAL - Internal Use Only
- **Review Frequency:** Quarterly
- **Next Review Date:** 2025-11-05
- **Owner:** DevOps Team
- **Approver:** Engineering Manager

**Change Log:**
- v1.0 (2025-08-05): Initial version - Comprehensive DNS recovery procedures