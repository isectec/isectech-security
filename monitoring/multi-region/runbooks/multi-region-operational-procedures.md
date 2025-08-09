# iSECTECH Multi-Region Operational Procedures

## Overview

Comprehensive operational runbooks for managing the iSECTECH multi-region deployment using the Regional Hybrid model across 5 global regions with strict data residency compliance.

## Regional Architecture Summary

### Active Regions (Serving Traffic)
- **us-central1** (US Central - CCPA) - 40% traffic weight
- **europe-west4** (Netherlands - GDPR) - 30% traffic weight  
- **asia-northeast1** (Tokyo - APPI) - 30% traffic weight

### Backup Regions (Disaster Recovery)
- **us-east1** (US East - CCPA backup)
- **europe-west1** (Belgium - GDPR backup)

## Emergency Response Procedures

### 1. Regional Failure Response

#### Immediate Actions (Within 5 Minutes)

```bash
# Step 1: Verify the scope of the outage
kubectl get nodes --context=<failed-region>
gcloud compute instances list --zones=<failed-region>-a,<failed-region>-b,<failed-region>-c

# Step 2: Check load balancer health
gcloud compute backend-services get-health <backend-service> --global
gcloud compute health-checks describe <health-check-name> --global

# Step 3: Initiate DNS failover if needed
./infrastructure/scripts/cross-region-failover.sh --from=<failed-region> --to=<backup-region>
```

#### Investigation Actions (5-15 Minutes)

```bash
# Check monitoring dashboards
# - Executive Overview Dashboard
# - SRE Operational Dashboard  
# - Regional Health Status

# Review recent logs
gcloud logging read "resource.type=gce_instance AND resource.labels.zone=<failed-region>" --limit=100

# Check for recent deployments
kubectl get deployments --all-namespaces --context=<failed-region>
gcloud container images list --repository=gcr.io/<project-id>
```

#### Recovery Actions (15+ Minutes)

```bash
# If infrastructure issue - recreate resources
terraform plan -target=module.regional_infrastructure[\"<failed-region>\"]
terraform apply -target=module.regional_infrastructure[\"<failed-region>\"]

# If application issue - rollback deployment
kubectl rollout undo deployment/<app-name> --context=<failed-region>

# Verify recovery
./infrastructure/scripts/validate-region-health.sh --region=<failed-region>
```

### 2. Compliance Violation Response

#### Critical Compliance Violation (Immediate Response)

**SEVERITY: CRITICAL - Response Time: < 1 Minute**

```bash
# Step 1: Isolate the affected data immediately
# Block access to potentially violating resources
gcloud compute firewall-rules create emergency-block-<timestamp> \
  --direction=INGRESS \
  --priority=1000 \
  --source-ranges=0.0.0.0/0 \
  --rules=all \
  --target-tags=<affected-resource-tags> \
  --action=DENY

# Step 2: Capture evidence
gcloud logging read "resource.type=cloud_function AND logName=projects/<project>/logs/cloudfunctions.googleapis.com%2Fcloud-functions" \
  --filter='jsonPayload.compliance_report.overall_status!="compliant"' \
  --limit=50 > compliance-violation-evidence-$(date +%Y%m%d-%H%M%S).json

# Step 3: Notify legal and compliance teams
# (Automated via alert policy - verify notifications sent)

# Step 4: Begin investigation
gcloud audit logs read --service=storage.googleapis.com --filter='protoPayload.methodName="storage.objects.create"'
```

#### Data Residency Investigation

```bash
# Check for cross-region data transfers
gcloud compute operations list --filter="targetLink:*transfer*"
gcloud storage transfer operations list

# Verify bucket locations and access patterns
gsutil ls -L gs://<bucket-name> | grep Location
gcloud logging read "protoPayload.resourceName:gs://<bucket-name>" --limit=100

# Check database replica configurations
gcloud sql instances list --filter="region!=<expected-region>"
gcloud sql backups list --instance=<instance-name>
```

#### Compliance Remediation Steps

```bash
# Step 1: Stop the violating process
gcloud functions stop <function-name> --region=<region>
kubectl scale deployment <deployment-name> --replicas=0 --context=<region>

# Step 2: Quarantine affected data
gsutil -m mv gs://<source-bucket>/* gs://<quarantine-bucket>/
gcloud sql export sql <instance-name> gs://<secure-bucket>/<backup-name>.sql \
  --database=<database-name>

# Step 3: Fix the underlying issue
# Apply compliance-validated configuration
terraform apply -var="compliance_mode=strict" -target=<resource>

# Step 4: Verify compliance restoration  
gcloud functions call compliance-monitor --region=us-central1
```

### 3. Performance Degradation Response

#### High Latency Detected

```bash
# Step 1: Identify bottlenecks
# Check cross-region latency
curl -w "@curl-format.txt" https://app-<region>.isectech.org/api/v1/ping

# Check database performance
gcloud sql operations list --instance=<instance-name> --limit=10
gcloud monitoring metrics list --filter="metric.type=cloudsql.googleapis.com/database/cpu/utilization"

# Step 2: Scale resources if needed
kubectl scale deployment <app-deployment> --replicas=<new-count> --context=<region>
gcloud sql instances patch <instance-name> --cpu=<new-cpu-count> --memory=<new-memory>

# Step 3: Verify improvement
# Monitor dashboards for 10-15 minutes
# Check SLO compliance metrics
```

#### Resource Exhaustion Response

```bash
# Step 1: Immediate scaling
kubectl get hpa --all-namespaces --context=<region>
kubectl scale deployment <deployment> --replicas=<emergency-count> --context=<region>

# Step 2: Resource analysis
kubectl top nodes --context=<region>
kubectl top pods --all-namespaces --context=<region>

# Step 3: Capacity planning
# Review capacity planning dashboard
# Calculate projected growth
# Submit capacity increase requests
```

## Routine Operational Procedures

### Daily Health Checks

```bash
#!/bin/bash
# Daily multi-region health check script

# Check all regions
for region in us-central1 europe-west4 asia-northeast1; do
  echo "Checking region: $region"
  
  # Health check API endpoints
  curl -f -s https://app-$region.isectech.org/api/v1/health || echo "FAILED: $region API"
  
  # Check database connectivity  
  gcloud sql connect isectech-$region-primary --user=monitoring --quiet << EOF
SELECT 1;
EOF
  
  # Check cache connectivity
  gcloud redis instances describe isectech-$region-cache --region=$region
  
  # Verify compliance monitoring
  gcloud functions call compliance-monitor --region=$region --data='{"region":"'$region'"}'
done

# Generate daily report
./monitoring/scripts/generate-daily-report.sh
```

### Weekly Capacity Review

```bash
#!/bin/bash
# Weekly capacity planning review

# Resource utilization analysis
for region in us-central1 europe-west4 asia-northeast1; do
  echo "=== $region Capacity Analysis ==="
  
  # CPU utilization trends
  gcloud monitoring metrics list \
    --filter="metric.type=compute.googleapis.com/instance/cpu/utilization" \
    --filter="resource.label.zone=$region*"
  
  # Memory utilization trends  
  gcloud monitoring metrics list \
    --filter="metric.type=agent.googleapis.com/memory/percent_used" \
    --filter="resource.label.zone=$region*"
  
  # Database capacity
  gcloud sql instances describe isectech-$region-primary \
    --format="value(settings.dataDiskSizeGb,settings.tier)"
done

# Generate capacity recommendations
python3 ./monitoring/scripts/capacity-recommendations.py
```

### Monthly Compliance Audit

```bash
#!/bin/bash
# Monthly compliance audit procedures

echo "Starting monthly compliance audit - $(date)"

# Data residency verification
echo "=== Data Residency Verification ==="
for zone in gdpr ccpa appi; do
  echo "Checking $zone compliance zone..."
  
  # Verify bucket locations
  gsutil ls -L gs://isectech-*-$zone-* | grep Location
  
  # Check database locations
  gcloud sql instances list --filter="region:*$(case $zone in gdpr) echo "europe";; ccpa) echo "us";; appi) echo "asia";; esac)*"
done

# Audit log analysis
echo "=== Audit Log Analysis ==="
gcloud logging read "protoPayload.serviceName=storage.googleapis.com" \
  --filter="timestamp>=2024-01-01T00:00:00Z" \
  --format="csv(timestamp,protoPayload.resourceName,protoPayload.authenticationInfo.principalEmail)"

# Compliance report generation
gcloud functions call compliance-monitor --region=us-central1 --data='{"action":"generate_monthly_report"}'

echo "Compliance audit completed - $(date)"
```

## Disaster Recovery Procedures

### Regional Failover Process

#### Planned Failover (Maintenance)

```bash
#!/bin/bash
# Planned regional failover for maintenance

SOURCE_REGION=$1
TARGET_REGION=$2

echo "Starting planned failover from $SOURCE_REGION to $TARGET_REGION"

# Step 1: Pre-failover verification
echo "Pre-failover checks..."
./scripts/pre-failover-checks.sh --source=$SOURCE_REGION --target=$TARGET_REGION

# Step 2: Gradually reduce traffic to source region
echo "Reducing traffic to source region..."
gcloud compute backend-services update <backend-service> \
  --global \
  --backend-configs="zone=$SOURCE_REGION-a,balancing-mode=RATE,max-rate=100"

# Wait for traffic to drain
sleep 300

# Step 3: Update DNS to point to target region
echo "Updating DNS configuration..."
gcloud dns record-sets transaction start --zone=<dns-zone>
gcloud dns record-sets transaction remove --zone=<dns-zone> \
  --name="app.isectech.org." \
  --type=A \
  --value=<source-region-ip>
gcloud dns record-sets transaction add --zone=<dns-zone> \
  --name="app.isectech.org." \
  --type=A \
  --value=<target-region-ip>
gcloud dns record-sets transaction execute --zone=<dns-zone>

# Step 4: Verify failover success
echo "Verifying failover..."
./scripts/post-failover-verification.sh --region=$TARGET_REGION

echo "Planned failover completed successfully"
```

#### Emergency Failover (Outage)

```bash
#!/bin/bash
# Emergency failover script for regional outage

FAILED_REGION=$1

echo "EMERGENCY: Starting emergency failover for $FAILED_REGION"

# Step 1: Immediate DNS update (aggressive TTL)
gcloud dns record-sets transaction start --zone=<dns-zone>
gcloud dns record-sets transaction remove --zone=<dns-zone> \
  --name="app.isectech.org." \
  --type=A \
  --value=<failed-region-ip> \
  --ttl=60  # Short TTL for fast propagation
  
# Add backup region IP
BACKUP_REGION=$(case $FAILED_REGION in
  us-central1) echo "us-east1";;
  europe-west4) echo "europe-west1";;
  asia-northeast1) echo "asia-northeast1";; # No backup, use primary
esac)

gcloud dns record-sets transaction add --zone=<dns-zone> \
  --name="app.isectech.org." \
  --type=A \
  --value=<backup-region-ip> \
  --ttl=60
gcloud dns record-sets transaction execute --zone=<dns-zone>

# Step 2: Update load balancer backend  
gcloud compute backend-services update <backend-service> \
  --global \
  --remove-backends="zone=$FAILED_REGION-a"

# Step 3: Scale up backup region
kubectl scale deployment <app-deployment> --replicas=10 --context=$BACKUP_REGION

# Step 4: Database failover (if needed)
if [ "$DATABASE_FAILOVER" = "true" ]; then
  gcloud sql instances promote-replica <backup-db-instance> --region=$BACKUP_REGION
fi

# Step 5: Notify stakeholders
echo "Emergency failover completed for $FAILED_REGION -> $BACKUP_REGION"
```

### Data Recovery Procedures

#### Database Recovery

```bash
#!/bin/bash
# Database recovery from backup

REGION=$1
RECOVERY_TIME=$2  # Format: 2024-01-15T10:30:00Z

echo "Starting database recovery for $REGION to $RECOVERY_TIME"

# Step 1: Create recovery instance
gcloud sql instances clone isectech-$REGION-primary \
  isectech-$REGION-recovery \
  --point-in-time=$RECOVERY_TIME \
  --region=$REGION

# Step 2: Verify data integrity  
gcloud sql connect isectech-$REGION-recovery --user=admin << EOF
-- Run data integrity checks
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM security_events;
-- Add more validation queries as needed
EOF

# Step 3: Switch application to recovery instance
kubectl set env deployment/<app-deployment> \
  DATABASE_HOST=<recovery-instance-ip> \
  --context=$REGION

echo "Database recovery completed"
```

#### Storage Recovery

```bash
#!/bin/bash
# Storage recovery from backup

REGION=$1
BUCKET_NAME=$2
RECOVERY_TIME=$3

echo "Starting storage recovery for $BUCKET_NAME in $REGION"

# Step 1: List available backups
gsutil ls gs://<backup-bucket>/$BUCKET_NAME/

# Step 2: Restore from backup
gsutil -m cp -r gs://<backup-bucket>/$BUCKET_NAME/$RECOVERY_TIME/* \
  gs://$BUCKET_NAME-recovery/

# Step 3: Verify restoration
gsutil ls -r gs://$BUCKET_NAME-recovery/ | wc -l
gsutil du -s gs://$BUCKET_NAME-recovery/

echo "Storage recovery completed"
```

## Monitoring and Alerting Management

### Alert Acknowledgment Process

```bash
#!/bin/bash
# Alert acknowledgment and investigation

ALERT_ID=$1
REGION=$2
SEVERITY=$3

echo "Acknowledging alert $ALERT_ID in $REGION (Severity: $SEVERITY)"

# Step 1: Acknowledge alert in monitoring system
gcloud alpha monitoring alerts acknowledge $ALERT_ID

# Step 2: Begin investigation based on severity
case $SEVERITY in
  "CRITICAL")
    echo "CRITICAL alert - starting immediate investigation"
    ./runbooks/critical-alert-response.sh --alert=$ALERT_ID --region=$REGION
    ;;
  "WARNING")
    echo "WARNING alert - starting standard investigation"  
    ./runbooks/warning-alert-response.sh --alert=$ALERT_ID --region=$REGION
    ;;
  *)
    echo "INFO alert - logging for analysis"
    ;;
esac

# Step 3: Update incident management system
curl -X POST https://incident-management.isectech.org/api/incidents \
  -H "Authorization: Bearer $INCIDENT_API_KEY" \
  -d "{\"alert_id\":\"$ALERT_ID\",\"region\":\"$REGION\",\"severity\":\"$SEVERITY\",\"status\":\"investigating\"}"
```

### SLO Breach Investigation

```bash
#!/bin/bash
# SLO breach investigation procedures

SLO_NAME=$1
BREACH_TIME=$2

echo "Investigating SLO breach: $SLO_NAME at $BREACH_TIME"

# Step 1: Gather breach details
gcloud monitoring slos describe $SLO_NAME --service=<service-name>

# Step 2: Analyze contributing factors
case $SLO_NAME in
  "global-availability")
    echo "Investigating global availability breach..."
    # Check regional health status
    # Review load balancer metrics
    # Analyze error rates by region
    ;;
  "api-latency-p95")
    echo "Investigating API latency breach..."
    # Check database performance
    # Review network latency
    # Analyze request patterns
    ;;
  "compliance-violations")
    echo "Investigating compliance SLO breach..."
    # Review compliance monitoring logs
    # Check data residency violations
    # Verify audit trail integrity
    ;;
esac

# Step 3: Calculate error budget impact
# Generate post-incident review items
echo "SLO breach investigation completed for $SLO_NAME"
```

## Security Incident Response

### Compliance Security Incident

```bash
#!/bin/bash
# Compliance-related security incident response

INCIDENT_TYPE=$1  # data-breach, unauthorized-access, etc.
AFFECTED_REGION=$2
REGULATION=$3     # gdpr, ccpa, appi

echo "SECURITY INCIDENT: $INCIDENT_TYPE in $AFFECTED_REGION ($REGULATION)"

# Step 1: Immediate containment
echo "Implementing containment measures..."
case $INCIDENT_TYPE in
  "data-breach")
    # Block access to affected resources
    # Isolate potentially compromised data
    # Preserve evidence for investigation
    ;;
  "unauthorized-access")
    # Revoke suspicious access tokens
    # Force password resets
    # Enable additional authentication factors
    ;;
esac

# Step 2: Regulatory notification preparation
echo "Preparing regulatory notifications..."
case $REGULATION in
  "gdpr")
    # Must notify within 72 hours
    # Prepare GDPR breach notification
    ;;
  "ccpa")
    # Prepare CCPA incident report
    # Review consumer notification requirements
    ;;
  "appi")
    # Prepare APPI compliance report
    # Review cross-border data transfer implications
    ;;
esac

# Step 3: Evidence preservation
gcloud logging read "timestamp>=\"$INCIDENT_TIME\"" \
  --format="json" > security-incident-logs-$(date +%Y%m%d-%H%M%S).json

echo "Security incident response initiated"
```

## Contact Information

### Emergency Escalation

- **SRE On-Call**: +1-555-SRE-CALL
- **Security Team**: security-emergency@isectech.org  
- **Compliance Team**: compliance-urgent@isectech.org
- **Legal Team**: legal-emergency@isectech.org
- **Executive Team**: exec-emergency@isectech.org

### Regional Contacts

- **US Operations**: us-ops@isectech.org
- **EU Operations**: eu-ops@isectech.org
- **APAC Operations**: apac-ops@isectech.org

## Appendix: Quick Reference Commands

### Health Check Commands
```bash
# Quick health check all regions
for r in us-central1 europe-west4 asia-northeast1; do curl -f https://app-$r.isectech.org/health; done

# Check database connectivity
gcloud sql instances list --filter="name:isectech-*-primary"

# Verify compliance status
gcloud functions call compliance-monitor --region=us-central1
```

### Emergency Commands
```bash
# Emergency traffic drain
gcloud compute backend-services update <service> --global --backend-configs="zone=<zone>,balancing-mode=RATE,max-rate=0"

# Emergency scale up
kubectl scale deployment <app> --replicas=20 --context=<region>

# Emergency DNS update
gcloud dns record-sets transaction start --zone=<zone>
```

---
**Document Version**: 1.0  
**Last Updated**: $(date)  
**Next Review**: $(date -d "+3 months")**