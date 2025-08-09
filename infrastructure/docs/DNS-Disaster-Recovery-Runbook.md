# iSECTECH DNS Disaster Recovery Runbook

## Executive Summary

This runbook provides comprehensive procedures for responding to DNS infrastructure failures and conducting disaster recovery operations for iSECTECH's DNS infrastructure. All procedures are production-tested and designed for zero-tolerance failure scenarios.

**CRITICAL**: This runbook assumes DNS failures can impact all iSECTECH services. Follow procedures exactly as documented.

---

## Table of Contents

1. [Emergency Response Team](#emergency-response-team)
2. [Incident Classification](#incident-classification)
3. [DNS Infrastructure Overview](#dns-infrastructure-overview)
4. [Monitoring and Alerting](#monitoring-and-alerting)
5. [Emergency Response Procedures](#emergency-response-procedures)
6. [Disaster Recovery Procedures](#disaster-recovery-procedures)
7. [Backup and Restore Operations](#backup-and-restore-operations)
8. [Environment Isolation Procedures](#environment-isolation-procedures)
9. [DNS Failover Activation](#dns-failover-activation)
10. [Testing and Validation](#testing-and-validation)
11. [Post-Incident Procedures](#post-incident-procedures)
12. [Appendices](#appendices)

---

## Emergency Response Team

### Primary Contacts
- **DNS Lead**: Infrastructure Team Lead
- **Secondary**: DevOps Engineer (24/7)
- **Escalation**: CTO/CISO
- **External**: Google Cloud Support (Premium)

### On-Call Rotation
- Primary: Week 1-2 rotation
- Secondary: Week 3-4 rotation
- Emergency escalation: 15-minute response SLA

---

## Incident Classification

### Severity Levels

#### **CRITICAL (SEV-1)**
- Complete DNS resolution failure
- All domains unresolvable
- Production services down
- **Response Time**: Immediate (< 5 minutes)
- **Escalation**: All hands, CTO notification

#### **HIGH (SEV-2)**
- Partial DNS failures (> 50% domains affected)
- Intermittent resolution issues
- DNSSEC validation failures
- **Response Time**: < 15 minutes
- **Escalation**: DNS team + management

#### **MEDIUM (SEV-3)**
- Single domain resolution issues
- Propagation delays
- Non-production environment issues
- **Response Time**: < 30 minutes
- **Escalation**: DNS team

#### **LOW (SEV-4)**
- Monitoring alert anomalies
- Performance degradation
- **Response Time**: < 1 hour
- **Escalation**: DNS team

---

## DNS Infrastructure Overview

### Production Domains
```
Primary Domains:
- app.isectech.org (Production Application)
- api.isectech.org (Production API)
- docs.isectech.org (Documentation)
- admin.isectech.org (Admin Portal)
- status.isectech.org (Status Page)

Environment-Specific:
- app-staging.isectech.org
- api-staging.isectech.org
- app-development.isectech.org
- api-development.isectech.org
```

### DNS Infrastructure Components

#### **Google Cloud DNS**
- **Project**: `isectech-security-platform`
- **Zones**: Production, staging, development, private
- **DNSSEC**: Enabled with automatic key rotation
- **Backup**: Automated daily backups to Cloud Storage

#### **Health Monitoring**
- **Uptime Checks**: 1-minute intervals from global locations
- **Alerting**: Cloud Monitoring with PagerDuty integration
- **Thresholds**: 2 consecutive failures trigger alerts

#### **Failover System**
- **Method**: Health-check integrated weighted routing
- **Detection**: Automated health check failures
- **Recovery**: Automatic failback when health restored

#### **Backup System**
- **Schedule**: Daily (production), weekly (non-production)
- **Retention**: 90 days production, 30 days non-production
- **Storage**: Versioned Cloud Storage buckets
- **Format**: YAML for human readability

---

## Monitoring and Alerting

### Key Monitoring Metrics

#### **DNS Health Metrics**
```
custom.googleapis.com/dns/uptime_check_success
custom.googleapis.com/dns/response_time
custom.googleapis.com/dns/backup_success
custom.googleapis.com/dns/restore_success
custom.googleapis.com/dns/propagation_consistency
```

#### **Alert Thresholds**
- **DNS Resolution Failure**: 2 consecutive failures
- **Response Time**: > 5 seconds
- **Backup Failure**: Any backup failure
- **Propagation Issues**: < 90% consistency across DNS servers

### Alerting Channels
- **PagerDuty**: SEV-1/SEV-2 incidents
- **Slack**: `#dns-alerts` channel
- **Email**: dns-team@isectech.com
- **SMS**: On-call engineer

---

## Emergency Response Procedures

### Immediate Response (First 5 Minutes)

#### **Step 1: Assess Situation**
```bash
# Check DNS health dashboard
https://console.cloud.google.com/monitoring/dashboards/custom/dns-health

# Quick DNS test
./infrastructure/scripts/dns-propagation-test.sh

# Check Cloud DNS console
https://console.cloud.google.com/net-services/dns/zones
```

#### **Step 2: Verify Scope**
```bash
# Test all critical domains
dig app.isectech.org A
dig api.isectech.org A
dig docs.isectech.org A
dig admin.isectech.org A
dig status.isectech.org A

# Test from multiple locations
nslookup app.isectech.org 8.8.8.8
nslookup app.isectech.org 1.1.1.1
```

#### **Step 3: Initial Triage**
1. **Complete Outage**: Proceed to [Critical DNS Failure](#critical-dns-failure)
2. **Partial Issues**: Proceed to [Partial DNS Failure](#partial-dns-failure)
3. **Single Domain**: Proceed to [Single Domain Issues](#single-domain-issues)

### Critical DNS Failure

#### **Immediate Actions (0-5 minutes)**
```bash
# 1. Activate incident response
# Open incident in PagerDuty, notify team

# 2. Check Google Cloud DNS status
gcloud dns managed-zones list --project=isectech-security-platform

# 3. Verify DNS servers are responding
dig @ns-cloud-a1.googledomains.com app.isectech.org A

# 4. Check for service outages
https://status.cloud.google.com/

# 5. Immediate failover if available
# (Automated failover should activate, verify manually)
```

#### **Recovery Actions (5-15 minutes)**
```bash
# 1. Restore from latest backup if corruption suspected
gcloud functions call dns-restore-cloud-function \
    --data='{"dry_run": true}' \
    --region=us-central1

# 2. If dry run successful, perform actual restore
gcloud functions call dns-restore-cloud-function \
    --data='{"dry_run": false, "force_restore": true}' \
    --region=us-central1

# 3. Verify restore success
./infrastructure/scripts/dns-propagation-test.sh

# 4. Monitor propagation
python3 infrastructure/scripts/dns-validation-function.py
```

### Partial DNS Failure

#### **Diagnosis Steps**
```bash
# 1. Identify affected domains
for domain in app.isectech.org api.isectech.org docs.isectech.org admin.isectech.org status.isectech.org; do
    echo "Testing $domain:"
    dig +short $domain A || echo "FAILED"
done

# 2. Check specific DNS zones
gcloud dns record-sets list --zone=isectech-production --project=isectech-security-platform

# 3. Verify DNSSEC status
dig +dnssec +short app.isectech.org A

# 4. Test from multiple resolvers
./infrastructure/scripts/dns-propagation-test.sh
```

#### **Recovery Actions**
```bash
# 1. Restore specific zone if corrupted
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "specific-backup-path.yaml", "dry_run": false, "force_restore": true}' \
    --region=us-central1

# 2. Manual record recreation if needed
gcloud dns record-sets transaction start --zone=isectech-production --project=isectech-security-platform
gcloud dns record-sets transaction add --zone=isectech-production --name=app.isectech.org. --type=A --ttl=300 "IP_ADDRESS" --project=isectech-security-platform
gcloud dns record-sets transaction execute --zone=isectech-production --project=isectech-security-platform
```

### Single Domain Issues

#### **Diagnosis and Resolution**
```bash
# 1. Check specific domain records
gcloud dns record-sets list --zone=isectech-production --filter="name:app.isectech.org." --project=isectech-security-platform

# 2. Verify upstream health
# Check load balancer/server health that domain points to

# 3. Test propagation consistency
dig app.isectech.org A @8.8.8.8
dig app.isectech.org A @1.1.1.1
dig app.isectech.org A @208.67.222.222

# 4. Fix individual record if needed
gcloud dns record-sets transaction start --zone=isectech-production --project=isectech-security-platform
gcloud dns record-sets transaction remove --zone=isectech-production --name=app.isectech.org. --type=A --ttl=OLD_TTL "OLD_IP" --project=isectech-security-platform
gcloud dns record-sets transaction add --zone=isectech-production --name=app.isectech.org. --type=A --ttl=300 "NEW_IP" --project=isectech-security-platform
gcloud dns record-sets transaction execute --zone=isectech-production --project=isectech-security-platform
```

---

## Disaster Recovery Procedures

### Complete Infrastructure Rebuild

#### **Prerequisites**
- Google Cloud project access
- Terraform state backup
- DNS backup files
- Domain registrar access

#### **Rebuild Process**

##### **Step 1: Infrastructure Restoration**
```bash
# 1. Navigate to DNS module
cd /Users/cf-215/Documents/isectech/infrastructure/terraform/modules/dns

# 2. Verify Terraform state
terraform init
terraform plan

# 3. Recreate DNS infrastructure
terraform apply -auto-approve

# 4. Verify zones created
gcloud dns managed-zones list --project=isectech-security-platform
```

##### **Step 2: DNS Data Restoration**
```bash
# 1. List available backups
gsutil ls gs://isectech-production-dns-backups/

# 2. Find latest backup
gsutil ls -l gs://isectech-production-dns-backups/latest/

# 3. Restore from backup
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "latest/production-dns-backup-latest.yaml", "dry_run": false, "force_restore": true}' \
    --region=us-central1
```

##### **Step 3: Validation and Testing**
```bash
# 1. Comprehensive DNS testing
./infrastructure/scripts/dns-propagation-test.sh

# 2. Automated validation
python3 infrastructure/scripts/dns-validation-function.py

# 3. Manual verification
for domain in app.isectech.org api.isectech.org docs.isectech.org admin.isectech.org status.isectech.org; do
    echo "Testing $domain from multiple resolvers:"
    dig +short @8.8.8.8 $domain A
    dig +short @1.1.1.1 $domain A
    dig +short @208.67.222.222 $domain A
    echo "---"
done
```

### Cross-Region Failover

#### **Regional DNS Failure Recovery**
```bash
# 1. Check regional health
gcloud compute regions list --filter="status:UP"

# 2. Activate alternate region (if configured)
# Update DNS records to point to alternate region infrastructure

# 3. Update load balancer backend
gcloud compute backend-services update isectech-backend \
    --region=us-east1 \
    --project=isectech-security-platform
```

---

## Backup and Restore Operations

### Manual Backup Creation

#### **On-Demand Backup**
```bash
# 1. Trigger backup Cloud Function
gcloud functions call dns-backup-cloud-function \
    --data='{"backup_type": "manual", "full_backup": true}' \
    --region=us-central1

# 2. Verify backup created
gsutil ls -l gs://isectech-production-dns-backups/$(date +%Y/%m/%d)/

# 3. Test backup integrity
gcloud functions call dns-restore-cloud-function \
    --data='{"dry_run": true}' \
    --region=us-central1
```

### Restore Operations

#### **Full Restore from Backup**
```bash
# 1. List available backups
python3 << EOF
import os
os.environ['PROJECT_ID'] = 'isectech-security-platform'
os.environ['ENVIRONMENT'] = 'production'
os.environ['BACKUP_BUCKET'] = 'isectech-production-dns-backups'

from infrastructure.scripts.dns_restore_function import DNSRestoreManager
restore_manager = DNSRestoreManager()
backups = restore_manager.list_available_backups()
for backup in backups[:5]:  # Show latest 5
    print(f"{backup['name']} - {backup['created']}")
EOF

# 2. Perform dry run restore
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "SPECIFIC_BACKUP_PATH", "dry_run": true}' \
    --region=us-central1

# 3. Execute actual restore
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "SPECIFIC_BACKUP_PATH", "dry_run": false, "force_restore": true}' \
    --region=us-central1
```

#### **Selective Zone Restore**
```bash
# For restoring specific zones, modify the restore function call
# or use manual Terraform operations:

# 1. Export specific zone from backup
gsutil cp gs://isectech-production-dns-backups/latest/production-dns-backup-latest.yaml /tmp/backup.yaml

# 2. Extract zone data and manually recreate records
# (Requires custom script or manual gcloud commands)
```

### Backup Validation

#### **Regular Backup Testing**
```bash
# Weekly backup validation script
#!/bin/bash
set -e

echo "Starting weekly backup validation..."

# 1. Trigger fresh backup  
gcloud functions call dns-backup-cloud-function \
    --data='{"backup_type": "validation", "full_backup": true}' \
    --region=us-central1

# 2. Wait for backup completion
sleep 60

# 3. Test restore (dry run)
gcloud functions call dns-restore-cloud-function \
    --data='{"dry_run": true}' \
    --region=us-central1

echo "Backup validation completed successfully"
```

---

## Environment Isolation Procedures

### Environment-Specific Recovery

#### **Production Environment Recovery**
```bash
# 1. Verify production zone health
gcloud dns managed-zones describe isectech-production --project=isectech-security-platform

# 2. Check production-specific records
gcloud dns record-sets list --zone=isectech-production --project=isectech-security-platform

# 3. Restore production environment
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "latest/production-dns-backup-latest.yaml", "dry_run": false, "force_restore": true}' \
    --region=us-central1
```

#### **Staging Environment Recovery**
```bash
# 1. Check staging zone
gcloud dns managed-zones describe isectech-staging --project=isectech-security-platform

# 2. Restore staging from backup
gcloud functions call dns-restore-cloud-function \
    --data='{"backup_path": "latest/staging-dns-backup-latest.yaml", "dry_run": false, "force_restore": true}' \
    --region=us-central1
```

#### **Development Environment Recovery**
```bash
# Development can be rebuilt from Terraform
cd /Users/cf-215/Documents/isectech/infrastructure/terraform/modules/dns

# Target only development resources
terraform apply -target=google_dns_managed_zone.development_zones -auto-approve
terraform apply -target=google_dns_record_set.development_records -auto-approve
```

### Private Zone Recovery

#### **Private DNS Zone Issues**
```bash
# 1. Check private zone configuration  
gcloud dns managed-zones list --filter="visibility:private" --project=isectech-security-platform

# 2. Verify VPC network associations
gcloud dns managed-zones describe isectech-private --project=isectech-security-platform

# 3. Recreate private zone if needed
terraform apply -target=google_dns_managed_zone.private_zones -auto-approve
```

---

## DNS Failover Activation

### Automated Failover Monitoring

#### **Verify Failover Status**
```bash
# 1. Check current routing policy status
gcloud dns record-sets list --zone=isectech-production --filter="type:A" --project=isectech-security-platform

# 2. Verify health check status
gcloud compute health-checks list --project=isectech-security-platform

# 3. Check routing policy configuration
gcloud dns policies list --project=isectech-security-platform
```

### Manual Failover Activation

#### **Force Failover to Secondary**
```bash
# 1. Update DNS records to point to secondary infrastructure
gcloud dns record-sets transaction start --zone=isectech-production --project=isectech-security-platform

# 2. Remove primary A records
gcloud dns record-sets transaction remove --zone=isectech-production \
    --name=app.isectech.org. --type=A --ttl=300 "PRIMARY_IP" \
    --project=isectech-security-platform

# 3. Add secondary A records  
gcloud dns record-sets transaction add --zone=isectech-production \
    --name=app.isectech.org. --type=A --ttl=300 "SECONDARY_IP" \
    --project=isectech-security-platform

# 4. Execute transaction
gcloud dns record-sets transaction execute --zone=isectech-production --project=isectech-security-platform
```

#### **Verify Failover Success**
```bash
# 1. Test DNS resolution
dig +short app.isectech.org A

# 2. Verify from multiple resolvers
for resolver in 8.8.8.8 1.1.1.1 208.67.222.222; do
    echo "Testing via $resolver:"
    dig +short @$resolver app.isectech.org A
done

# 3. Test application connectivity
curl -s -o /dev/null -w "%{http_code}" https://app.isectech.org/health
```

---

## Testing and Validation

### Post-Recovery Testing

#### **Comprehensive DNS Testing**
```bash
# 1. Full propagation test
./infrastructure/scripts/dns-propagation-test.sh

# 2. Automated validation
python3 infrastructure/scripts/dns-validation-function.py

# 3. DNSSEC validation
for domain in app.isectech.org api.isectech.org docs.isectech.org; do
    echo "DNSSEC test for $domain:"
    dig +dnssec +short $domain A | head -5
done

# 4. Security records validation
for domain in app.isectech.org api.isectech.org; do
    echo "Security records for $domain:"
    echo "CAA:" && dig +short $domain CAA
    echo "SPF:" && dig +short $domain TXT | grep spf
    echo "DMARC:" && dig +short _dmarc.$domain TXT
    echo "---"
done
```

#### **Performance Testing**
```bash
# 1. Response time testing
for i in {1..10}; do
    time dig app.isectech.org A >/dev/null
done

# 2. Load testing DNS queries
# (Use custom load testing tool or external service)

# 3. Geographic resolution testing
./infrastructure/scripts/dns-propagation-test.sh
```

### Validation Checklist

#### **Critical Validation Points**
- [ ] All production domains resolve correctly
- [ ] DNSSEC validation passes
- [ ] Health checks are passing
- [ ] Backup system is operational
- [ ] Monitoring and alerting functional
- [ ] Failover mechanisms tested
- [ ] Security records present and valid
- [ ] Environment isolation maintained
- [ ] Performance within SLA thresholds
- [ ] Documentation updated

---

## Post-Incident Procedures

### Immediate Post-Recovery (0-2 hours)

#### **Service Validation**
```bash
# 1. Comprehensive service testing
curl -s https://app.isectech.org/health
curl -s https://api.isectech.org/health  
curl -s https://docs.isectech.org/health
curl -s https://admin.isectech.org/health
curl -s https://status.isectech.org/health

# 2. Verify all DNS records
gcloud dns record-sets list --zone=isectech-production --project=isectech-security-platform

# 3. Confirm monitoring recovery
# Check all alerts are resolved in Cloud Monitoring console
```

#### **Communication Updates**
1. Update status page: status.isectech.org
2. Notify stakeholders of service restoration
3. Internal team notification via Slack
4. Customer communication if external impact occurred

### Investigation Phase (2-24 hours)

#### **Root Cause Analysis**
```bash
# 1. Collect logs from incident timeframe
gcloud logging read "timestamp>=\"$(date -d '2 hours ago' --iso-8601)\"" \
    --filter="resource.type=dns_query OR resource.type=gce_instance" \
    --project=isectech-security-platform

# 2. Review monitoring data
# Export metrics from Cloud Monitoring for analysis

# 3. Check infrastructure changes
git log --since="24 hours ago" --oneline infrastructure/
```

#### **Documentation Updates**
1. Create incident report in internal wiki
2. Update runbook based on lessons learned
3. Review and update monitoring thresholds
4. Update escalation procedures if needed

### Long-term Improvements (1-4 weeks)

#### **Infrastructure Hardening**
1. Review and enhance monitoring coverage
2. Improve automation based on manual steps taken
3. Enhance backup and restore procedures
4. Update disaster recovery testing schedule

#### **Process Improvements**
1. Conduct post-incident review meeting
2. Update training materials and procedures
3. Schedule additional disaster recovery drills
4. Review and update SLA agreements

---

## Appendices

### Appendix A: Emergency Contacts

#### **Primary Contacts**
```
DNS Team Lead: [Contact Info]
DevOps Engineer: [Contact Info]  
Infrastructure Manager: [Contact Info]
CTO: [Contact Info]
Google Cloud Support: [Premium Support Number]
```

#### **External Contacts**
```
Domain Registrar: [Contact Info]
CDN Provider: [Contact Info if applicable]
Network Provider: [Contact Info]
```

### Appendix B: DNS Configuration Details

#### **DNS Zones**
```
Production Zone: isectech-production
Staging Zone: isectech-staging  
Development Zone: isectech-development
Private Zone: isectech-private
```

#### **Critical DNS Records**
```
app.isectech.org A [Production IP]
api.isectech.org A [Production IP]
docs.isectech.org A [Production IP]
admin.isectech.org A [Production IP]  
status.isectech.org A [Production IP]
```

### Appendix C: Backup Locations

#### **Backup Storage**
```
Production: gs://isectech-production-dns-backups/
Staging: gs://isectech-staging-dns-backups/
Development: gs://isectech-development-dns-backups/
```

#### **Terraform State**
```
Remote State: gs://isectech-terraform-state/dns/terraform.tfstate
Local Backup: /Users/cf-215/Documents/isectech/infrastructure/backups/
```

### Appendix D: Monitoring Dashboards

#### **Key Dashboards**
```
DNS Health: https://console.cloud.google.com/monitoring/dashboards/custom/dns-health
Infrastructure: https://console.cloud.google.com/monitoring/dashboards/custom/infrastructure  
Application Health: https://console.cloud.google.com/monitoring/dashboards/custom/app-health
```

### Appendix E: Automated Scripts

#### **Script Locations**
```
DNS Testing: /infrastructure/scripts/dns-propagation-test.sh
Validation: /infrastructure/scripts/dns-validation-function.py
Backup: /infrastructure/scripts/dns-backup-function.py
Restore: /infrastructure/scripts/dns-restore-function.py
```

---

## Document Information

**Document Version**: 1.0  
**Last Updated**: 2024-12-19  
**Next Review Date**: 2025-03-19  
**Owner**: iSECTECH Infrastructure Team  
**Approver**: CTO  

**Revision History**:
- v1.0 (2024-12-19): Initial creation - Comprehensive DNS disaster recovery procedures

---

*This document contains sensitive infrastructure information. Treat as CONFIDENTIAL.*