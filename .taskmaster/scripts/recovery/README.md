# Recovery Automation Scripts - iSECTECH Security Platform

This directory contains automated scripts for disaster recovery, backup management, and system health monitoring for the iSECTECH Security Platform.

## Scripts Overview

### 1. Automated Disaster Recovery (`automated-disaster-recovery.sh`)

**Purpose:** Orchestrates automated disaster recovery procedures across all platform components.

**Usage:**
```bash
./automated-disaster-recovery.sh [recovery-type] [severity] [--dry-run]
```

**Recovery Types:**
- `full` - Complete disaster recovery (default)
- `dns` - DNS-specific recovery
- `certificates` - SSL certificate recovery
- `services` - Cloud Run services recovery
- `database` - Database recovery

**Severity Levels:**
- `CRITICAL` - Complete system outage
- `HIGH` - Significant service degradation (default)
- `MEDIUM` - Partial service impact
- `LOW` - Minor issues

**Examples:**
```bash
# Full recovery with high severity
./automated-disaster-recovery.sh

# Service-specific recovery for critical incident
./automated-disaster-recovery.sh services CRITICAL

# DNS recovery simulation (dry run)
./automated-disaster-recovery.sh dns MEDIUM --dry-run
```

**Features:**
- Automated health assessment
- Component-specific recovery procedures
- Recovery validation and verification
- Comprehensive logging and reporting
- Notification system integration
- Rollback capabilities

### 2. Backup Automation (`backup-automation.sh`)

**Purpose:** Automated backup of all infrastructure components and configurations.

**Usage:**
```bash
./backup-automation.sh [backup-type] [--schedule]
```

**Backup Types:**
- `full` - Complete backup of all components (default)
- `terraform` - Terraform state backup
- `database` - Database backup
- `dns` - DNS configuration backup
- `certificates` - SSL certificates backup
- `services` - Cloud Run services backup
- `loadbalancer` - Load balancer configuration backup
- `security` - Cloud Armor and secrets backup

**Examples:**
```bash
# Full backup
./backup-automation.sh

# Database backup only
./backup-automation.sh database

# Scheduled full backup (suppresses verbose output)
./backup-automation.sh full --schedule
```

**Features:**
- Incremental and full backup support
- Automated backup retention management
- Cloud Storage integration
- Backup verification and validation
- Notification on backup completion/failure
- Manifest generation for backup tracking

### 3. Monitoring and Health Check (`monitoring-health-check.sh`)

**Purpose:** Comprehensive system health monitoring with automated alerting.

**Usage:**
```bash
./monitoring-health-check.sh [--continuous] [--alert-threshold PERCENTAGE]
```

**Options:**
- `--continuous` - Run in continuous monitoring mode
- `--alert-threshold NUM` - Health percentage threshold for alerts (default: 75)

**Examples:**
```bash
# Single health check
./monitoring-health-check.sh

# Continuous monitoring
./monitoring-health-check.sh --continuous

# Single check with custom alert threshold
./monitoring-health-check.sh --alert-threshold 80

# Continuous monitoring with 90% threshold
./monitoring-health-check.sh --continuous 90
```

**Health Check Components:**
- **Cloud Run Services (25 points)** - Service status, endpoint health, error rates
- **Database Health (20 points)** - Instance status, connectivity, backup status
- **DNS Resolution (15 points)** - Domain resolution, DNSSEC validation
- **SSL Certificates (15 points)** - Certificate validity, expiration monitoring
- **Load Balancer (10 points)** - Backend health, endpoint availability
- **Monitoring/Logging (15 points)** - Metrics availability, alert policies

**Total Health Score:** 100 points

## Environment Variables

All scripts use the following environment variables:

```bash
export PROJECT_ID="isectech-security-platform"
export REGION="us-central1"
export BACKUP_BUCKET="gs://isectech-infrastructure-backups"
export NOTIFICATION_EMAIL="devops@isectech.com"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export BACKUP_RETENTION_DAYS="30"
```

## Integration Examples

### Cron Jobs for Automated Operations

```bash
# Daily full backup at 2 AM
0 2 * * * /path/to/automated-disaster-recovery/backup-automation.sh full --schedule

# Hourly health checks
0 * * * * /path/to/automated-disaster-recovery/monitoring-health-check.sh

# Weekly Terraform state backup
0 3 * * 0 /path/to/automated-disaster-recovery/backup-automation.sh terraform --schedule
```

### Incident Response Integration

```bash
# Trigger automated recovery based on monitoring alerts
if [[ $HEALTH_PERCENTAGE -lt 50 ]]; then
    ./automated-disaster-recovery.sh full CRITICAL
fi

# Backup before major deployments
./backup-automation.sh full
deploy-application.sh
```

### Monitoring Integration

```bash
# Continuous monitoring with PagerDuty integration
export SLACK_WEBHOOK_URL="https://hooks.slack.com/your-webhook"
./monitoring-health-check.sh --continuous --alert-threshold 80
```

## Logging and Reporting

All scripts generate detailed logs and reports:

### Log Files
- Location: `/tmp/[script-name]-[timestamp].log`
- Format: Timestamped entries with severity levels
- Retention: Managed by system log rotation

### Reports
- **Recovery Reports:** JSON format with recovery details
- **Backup Manifests:** Backup metadata and verification
- **Health Reports:** Detailed component health status

### Cloud Storage Integration
- Reports uploaded to `gs://isectech-infrastructure-backups/`
- Organized by type and timestamp
- Automated cleanup based on retention policies

## Notification System

### Email Notifications
- Sent to `NOTIFICATION_EMAIL` environment variable
- Include summary and links to detailed logs
- Configurable severity thresholds

### Slack Integration
- Webhook-based notifications to team channels
- Rich formatting with severity indicators
- Real-time status updates

### Alert Severity Levels
- **CRITICAL:** Complete system failures requiring immediate attention
- **WARNING:** Degraded performance or partial failures
- **INFO:** Successful operations and status updates

## Security Considerations

### Credentials and Access
- Scripts require appropriate Google Cloud IAM permissions
- Use service accounts with minimal required permissions
- Secrets and sensitive data are never logged

### Backup Security
- Backups stored in encrypted Cloud Storage buckets
- Access restricted to authorized personnel only
- Backup integrity verification included

### Network Security
- Scripts operate within VPC security boundaries
- All communications use encrypted channels
- Rate limiting to prevent abuse

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Ensure proper IAM permissions
   gcloud auth list
   gcloud projects get-iam-policy $PROJECT_ID
   ```

2. **Network Connectivity Issues**
   ```bash
   # Test basic connectivity
   curl -I https://api.isectech.com/health
   dig api.isectech.com
   ```

3. **Backup Failures**
   ```bash
   # Check Cloud Storage access
   gsutil ls $BACKUP_BUCKET
   gsutil acl get $BACKUP_BUCKET
   ```

### Debug Mode
Enable verbose logging by setting:
```bash
export DEBUG=true
bash -x ./script-name.sh
```

### Log Analysis
```bash
# Search for errors in logs
grep -i error /tmp/automated-recovery-*.log

# Check recovery success rates
grep -c "SUCCESS\|FAILED" /tmp/backup-automation-*.log
```

## Maintenance

### Script Updates
- Review and update scripts quarterly
- Test in staging environment before production deployment
- Maintain backward compatibility for existing integrations

### Backup Retention
- Default retention: 30 days
- Critical backups: 90 days
- Annual archive: 7 years

### Health Check Tuning
- Adjust thresholds based on SLA requirements
- Update component weights based on business criticality
- Add new health checks as infrastructure grows

## Support and Escalation

For issues with recovery automation scripts:

1. **Check logs** in `/tmp/` directory
2. **Verify environment variables** and permissions
3. **Contact DevOps team** at devops@isectech.com
4. **Emergency escalation** to on-call engineer: +1-555-0123

---

**Last Updated:** 2025-08-05  
**Version:** 1.0  
**Maintainer:** DevOps Team