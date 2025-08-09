# iSECTECH Secret Management Procedures

**Version:** 2.0.0  
**Author:** Claude Code - iSECTECH Infrastructure Team  
**Last Updated:** January 2025  
**Classification:** Internal - Security Critical

## Table of Contents

1. [Overview](#overview)
2. [Secret Categories and Classification](#secret-categories-and-classification)
3. [Secret Lifecycle Management](#secret-lifecycle-management)
4. [Environment Separation](#environment-separation)
5. [Access Control and IAM](#access-control-and-iam)
6. [Rotation Procedures](#rotation-procedures)
7. [Emergency Procedures](#emergency-procedures)
8. [Monitoring and Auditing](#monitoring-and-auditing)
9. [Compliance and Governance](#compliance-and-governance)
10. [Incident Response](#incident-response)
11. [Maintenance and Operations](#maintenance-and-operations)

---

## Overview

The iSECTECH platform utilizes Google Cloud Secret Manager for centralized secret management across all environments. This document outlines comprehensive procedures for managing secrets throughout their lifecycle, ensuring security, compliance, and operational excellence.

### Key Principles

- **Zero Trust Security**: No service or user has implicit trust
- **Principle of Least Privilege**: Minimal access required for function
- **Defense in Depth**: Multiple layers of security controls
- **Audit Everything**: Complete visibility into all secret operations
- **Automated Where Possible**: Reduce human error through automation

---

## Secret Categories and Classification

### Database Secrets
**Classification:** Critical  
**Rotation Frequency:** 30 days  
**Backup Required:** Yes

- `isectech-postgres-password` - PostgreSQL database password
- `isectech-mongodb-password` - MongoDB database password  
- `isectech-redis-password` - Redis cache password
- `isectech-clickhouse-password` - ClickHouse analytics password

### Authentication Secrets
**Classification:** Critical  
**Rotation Frequency:** 30 days  
**Backup Required:** Yes

- `isectech-nextauth-secret` - NextAuth session secret
- `isectech-jwt-access-secret` - JWT access token signing key
- `isectech-jwt-refresh-secret` - JWT refresh token signing key
- `isectech-service-api-key` - Inter-service authentication key
- `isectech-session-encryption-key` - Session data encryption key

### OAuth Provider Secrets
**Classification:** High  
**Rotation Frequency:** 90 days  
**Backup Required:** Yes

- `isectech-google-oauth-client-secret` - Google OAuth client secret
- `isectech-microsoft-oauth-client-secret` - Microsoft OAuth client secret
- `isectech-okta-oauth-client-secret` - Okta OAuth client secret

### External API Keys
**Classification:** Medium-High  
**Rotation Frequency:** 60-90 days  
**Backup Required:** No (can be regenerated)

- `isectech-virustotal-api-key` - VirusTotal API key
- `isectech-recorded-future-api-key` - Recorded Future API key
- `isectech-nessus-api-key` - Nessus vulnerability scanner API key
- `isectech-splunk-hec-token` - Splunk HTTP Event Collector token

### Infrastructure Secrets
**Classification:** Critical  
**Rotation Frequency:** 60-90 days  
**Backup Required:** Yes

- `isectech-kong-postgres-password` - Kong API Gateway database password
- `isectech-consul-encrypt-key` - Consul gossip encryption key
- `isectech-kafka-sasl-password` - Kafka SASL authentication password

### Encryption Keys
**Classification:** Critical  
**Rotation Frequency:** 90 days  
**Backup Required:** Yes (with key escrow)

- `isectech-app-encryption-key` - Application data encryption key
- `isectech-pii-encryption-key` - PII data encryption key
- `isectech-log-encryption-key` - Log data encryption key

---

## Secret Lifecycle Management

### 1. Secret Creation

#### Prerequisites
- Approved change request
- Environment determination (prod/staging/dev)
- Classification assessment
- Access control matrix defined

#### Creation Process
```bash
# 1. Generate secure value
NEW_SECRET=$(openssl rand -base64 32)

# 2. Create secret with proper labels
gcloud secrets create "secret-name" \
    --replication-policy="automatic" \
    --labels="environment=production,category=database,managed-by=isectech-platform"

# 3. Set initial value
echo -n "$NEW_SECRET" | gcloud secrets versions add "secret-name" --data-file=-

# 4. Configure IAM permissions
gcloud secrets add-iam-policy-binding "secret-name" \
    --member="serviceAccount:service-account@project.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

# 5. Update annotations
gcloud secrets update "secret-name" \
    --update-annotations="description=Purpose of secret,rotation-period=30,created-by=username"
```

### 2. Secret Updates

#### Manual Updates
```bash
# Update secret value
echo -n "new-secret-value" | gcloud secrets versions add "secret-name" --data-file=-

# Update metadata
gcloud secrets update "secret-name" \
    --update-annotations="last-updated=$(date -Iseconds),updated-by=username"
```

#### Automated Updates
Use the rotation script:
```bash
./rotate-secrets.sh --environment production --dry-run
./rotate-secrets.sh --environment production
```

### 3. Secret Deletion

#### Prerequisites
- Approved change request
- Verification that secret is no longer in use
- Backup created if required
- All dependent services updated

#### Deletion Process
```bash
# 1. Disable secret (mark for deletion)
gcloud secrets update "secret-name" \
    --update-annotations="status=deprecated,deletion-scheduled=$(date -d '+30 days' -Iseconds)"

# 2. Remove IAM bindings
gcloud secrets remove-iam-policy-binding "secret-name" \
    --member="serviceAccount:service-account@project.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

# 3. After grace period, delete
gcloud secrets delete "secret-name"
```

---

## Environment Separation

### Production Environment
- **Project:** `isectech-security-platform`
- **Service Accounts:** Dedicated per service
- **Access:** Strictly controlled, audit logged
- **Rotation:** Automated with manual approval

### Staging Environment
- **Project:** `isectech-staging-platform`
- **Service Accounts:** Dedicated per service
- **Access:** Developer access with approval
- **Rotation:** Automated without approval required

### Development Environment
- **Project:** `isectech-dev-platform`
- **Service Accounts:** Shared development account
- **Access:** All developers
- **Rotation:** Manual or disabled

### Cross-Environment Policies
- **No secret sharing** between environments
- **Different encryption keys** for each environment
- **Separate IAM policies** and service accounts
- **Environment-specific naming** conventions

---

## Access Control and IAM

### Service Account Matrix

| Service Account | Environment | Secrets Access | Additional Roles |
|----------------|-------------|----------------|------------------|
| `isectech-frontend-sa` | Production | OAuth, Session, Maps API | `run.invoker` |
| `isectech-backend-services-sa` | Production | Database, API keys, Encryption | `cloudsql.client`, `pubsub.publisher` |
| `isectech-api-gateway-sa` | Production | JWT, Kong, Service API | `run.invoker`, `compute.networkUser` |
| `isectech-monitoring-sa` | Production | Monitoring APIs | `monitoring.metricWriter`, `logging.logWriter` |
| `isectech-deployment-sa` | Production | All secrets (limited) | `run.admin`, `secretmanager.admin` |
| `isectech-secret-rotation-sa` | Production | All secrets (admin) | `run.developer`, `cloudscheduler.admin` |

### Access Patterns

#### Read-Only Access
```bash
# Grant read access to specific secret
gcloud secrets add-iam-policy-binding "secret-name" \
    --member="serviceAccount:service@project.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

#### Admin Access (Limited Users)
```bash
# Grant admin access to secret
gcloud secrets add-iam-policy-binding "secret-name" \
    --member="user:admin@isectech.com" \
    --role="roles/secretmanager.admin" \
    --condition='expression=request.time < timestamp("2024-12-31T23:59:59Z"),title=Temporary Access'
```

### Emergency Access

#### Break-Glass Procedure
1. Security incident declared
2. Emergency access group activated
3. Temporary elevated permissions granted
4. All actions logged and reviewed
5. Access revoked within 24 hours

---

## Rotation Procedures

### Automated Rotation Schedule

| Secret Category | Frequency | Method | Approval Required |
|----------------|-----------|---------|------------------|
| Database passwords | 30 days | Automated | Yes (Production) |
| Authentication secrets | 30 days | Automated | Yes (Production) |
| OAuth secrets | 90 days | Manual | Yes (All environments) |
| API keys | 60 days | Automated | No (Staging/Dev) |
| Encryption keys | 90 days | Manual | Yes (All environments) |

### Pre-Rotation Checklist

- [ ] Verify rotation script is tested
- [ ] Confirm backup procedures are working
- [ ] Check dependent services are healthy
- [ ] Ensure on-call engineer is available
- [ ] Verify rollback procedures
- [ ] Schedule maintenance window if required

### Rotation Process

#### 1. Pre-Rotation
```bash
# Check current secret age
gcloud secrets versions describe latest --secret="secret-name" --format="value(createTime)"

# Verify services using the secret
gcloud logging read 'resource.type="cloud_run_revision" AND jsonPayload.message=~"secret-name"' --limit=10

# Create backup if required
gcloud secrets versions access latest --secret="secret-name" > backup-file.txt
```

#### 2. Rotation Execution
```bash
# Execute rotation (dry run first)
./rotate-secrets.sh --environment production --dry-run

# Execute actual rotation
./rotate-secrets.sh --environment production
```

#### 3. Post-Rotation Validation
```bash
# Verify services are healthy
curl -s "https://api.isectech.com/health" | jq '.status'
curl -s "https://protect.isectech.com/api/health" | jq '.status'

# Check for authentication errors
gcloud logging read 'severity>=ERROR AND resource.type="cloud_run_revision" AND timestamp>="2024-01-01T00:00:00Z"' --limit=50

# Verify secret access patterns
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com" AND timestamp>="2024-01-01T00:00:00Z"' --limit=20
```

### Rollback Procedures

#### Immediate Rollback
```bash
# Identify previous version
gcloud secrets versions list "secret-name" --limit=5

# Promote previous version to latest
gcloud secrets versions access "version-number" --secret="secret-name" | \
    gcloud secrets versions add "secret-name" --data-file=-

# Restart affected services
gcloud run services update "service-name" --region="us-central1"
```

#### Emergency Rollback
```bash
# Use emergency break-glass access
gcloud auth activate-service-account emergency-access@project.iam.gserviceaccount.com --key-file=emergency.json

# Restore from backup
cat backup-file.txt | gcloud secrets versions add "secret-name" --data-file=-

# Immediately restart all services
for service in $(gcloud run services list --format="value(metadata.name)"); do
    gcloud run services update "$service" --region="us-central1" &
done
wait
```

---

## Emergency Procedures

### Secret Compromise Response

#### Immediate Actions (0-15 minutes)
1. **Isolate the compromised secret**
   ```bash
   # Disable all versions
   for version in $(gcloud secrets versions list "compromised-secret" --format="value(name)"); do
       gcloud secrets versions disable "$version" --secret="compromised-secret"
   done
   ```

2. **Generate new secret immediately**
   ```bash
   NEW_SECRET=$(openssl rand -base64 32)
   echo -n "$NEW_SECRET" | gcloud secrets versions add "compromised-secret" --data-file=-
   ```

3. **Restart all affected services**
   ```bash
   ./emergency-restart-services.sh "compromised-secret"
   ```

#### Short-term Actions (15 minutes - 2 hours)
1. **Revoke related credentials**
2. **Update external systems**
3. **Enable enhanced monitoring**
4. **Notify stakeholders**

#### Long-term Actions (2+ hours)
1. **Root cause analysis**
2. **Security review**
3. **Process improvements**
4. **Documentation updates**

### Service Outage Due to Secrets

#### Diagnosis
```bash
# Check service health
gcloud run services describe "service-name" --region="us-central1" --format="value(status.conditions)"

# Check secret access logs
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com" AND protoPayload.authenticationInfo.principalEmail=~"service-name"' --limit=10

# Check application logs for auth errors
gcloud logging read 'resource.type="cloud_run_revision" AND severity>=ERROR AND jsonPayload.message=~"authentication|authorization"' --limit=20
```

#### Resolution
```bash
# Verify secret exists and is accessible
gcloud secrets versions access latest --secret="secret-name"

# Check IAM permissions
gcloud secrets get-iam-policy "secret-name"

# Restart service with debug logging
gcloud run services update "service-name" --region="us-central1" --update-env-vars="LOG_LEVEL=debug"
```

---

## Monitoring and Auditing

### Key Metrics to Monitor

#### Secret Manager Metrics
- Secret access frequency and patterns
- Failed access attempts
- Secret version creation/deletion events
- IAM policy changes

#### Service Health Metrics
- Authentication failure rates
- Service startup times
- Database connection errors
- API response times

### Alerting Rules

#### Critical Alerts
```yaml
# Secret access failures
- alert: SecretAccessFailure
  expr: rate(secretmanager_access_failures_total[5m]) > 0.1
  for: 1m
  labels:
    severity: critical
  annotations:
    summary: "High rate of secret access failures"

# Unauthorized secret access
- alert: UnauthorizedSecretAccess
  expr: secretmanager_unauthorized_access_total > 0
  for: 0m
  labels:
    severity: critical
  annotations:
    summary: "Unauthorized access to secrets detected"
```

#### Warning Alerts
```yaml
# Secrets nearing rotation
- alert: SecretRotationDue
  expr: (time() - secretmanager_secret_created_time) / 86400 > 25
  for: 0m
  labels:
    severity: warning
  annotations:
    summary: "Secret rotation due within 5 days"
```

### Audit Log Analysis

#### Daily Audit Queries
```bash
# All secret operations
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com" AND timestamp>="2024-01-01T00:00:00Z"' --format=json > daily-audit.json

# Failed authentication events
gcloud logging read 'protoPayload.serviceName="secretmanager.googleapis.com" AND protoPayload.authorizationInfo.granted=false' --format=json

# Service account key usage
gcloud logging read 'protoPayload.serviceName="iam.googleapis.com" AND protoPayload.methodName="google.iam.admin.v1.IAM.CreateServiceAccountKey"'
```

#### Weekly Security Review
- Review all secret access patterns
- Analyze failed authentication attempts  
- Check for unusual access times/locations
- Verify rotation compliance
- Review IAM policy changes

---

## Compliance and Governance

### Regulatory Requirements

#### SOC 2 Type II
- All secret access must be logged
- Quarterly access reviews required
- Encryption at rest and in transit
- Separation of duties for secret management

#### ISO 27001
- Risk assessment for each secret category
- Documented procedures for all operations
- Regular security awareness training
- Incident response procedures tested quarterly

#### GDPR (for EU operations)
- Data protection by design
- Right to erasure for user-specific secrets
- Data processing records maintained
- Privacy impact assessments

### Governance Framework

#### Roles and Responsibilities

| Role | Responsibilities |
|------|-----------------|
| **Security Team** | Policy definition, compliance monitoring, incident response |
| **Platform Team** | Implementation, automation, operational procedures |
| **Development Teams** | Proper secret usage, secure coding practices |
| **Operations Team** | Monitoring, rotation execution, maintenance |

#### Review Processes

##### Monthly Reviews
- Secret inventory and classification
- Access control matrix verification
- Rotation schedule compliance
- Incident review and lessons learned

##### Quarterly Reviews
- Policy updates and improvements
- Threat model updates
- Disaster recovery testing
- Compliance audit preparation

##### Annual Reviews
- Complete security assessment
- Third-party security audit
- Business continuity planning
- Training program effectiveness

---

## Incident Response

### Classification Levels

#### Level 1 - Critical
- Secret compromise confirmed
- Multiple services affected
- External access possible
- **Response Time:** 15 minutes

#### Level 2 - High
- Suspected secret compromise
- Single service affected
- Internal access only
- **Response Time:** 1 hour

#### Level 3 - Medium
- Secret rotation failure
- Service degradation
- Monitoring alerts
- **Response Time:** 4 hours

### Response Procedures

#### Initial Response (All Levels)
1. **Assess and contain**
   - Identify scope of compromise
   - Isolate affected systems
   - Preserve evidence

2. **Communicate**
   - Notify incident commander
   - Update stakeholders
   - Document timeline

3. **Immediate remediation**
   - Rotate compromised secrets
   - Restart affected services
   - Verify system integrity

#### Investigation Phase
1. **Evidence collection**
   - Collect audit logs
   - Analyze access patterns
   - Interview personnel

2. **Root cause analysis**
   - Technical analysis
   - Process review
   - Timeline reconstruction

3. **Impact assessment**
   - Data exposure evaluation
   - Service availability impact
   - Compliance implications

#### Recovery Phase
1. **System restoration**
   - Verify all secrets rotated
   - Confirm service health
   - Test functionality

2. **Monitoring enhancement**
   - Increase log retention
   - Add additional alerts
   - Enhanced access controls

3. **Documentation**
   - Incident report
   - Lessons learned
   - Process improvements

### Communication Templates

#### Internal Notification
```
SUBJECT: [INCIDENT] Secret Management Incident - Level X

SUMMARY:
- Incident ID: INC-YYYYMMDD-XXX
- Start Time: YYYY-MM-DD HH:MM UTC
- Affected Systems: [List]
- Current Status: [Active/Contained/Resolved]

IMPACT:
- Services affected: [List]
- User impact: [Description]
- Data exposure: [None/Suspected/Confirmed]

ACTIONS TAKEN:
- [List of immediate actions]

NEXT STEPS:
- [List of planned actions]

INCIDENT COMMANDER: [Name/Contact]
```

#### External Notification (if required)
```
SUBJECT: Security Incident Notification

Dear [Customer/Partner],

We are writing to inform you of a security incident that occurred on [DATE]. 
[Provide appropriate level of detail based on impact and legal requirements]

WHAT HAPPENED:
[Brief description]

WHAT WE'RE DOING:
[Response actions]

WHAT YOU SHOULD DO:
[Any required customer actions]

We will provide updates as our investigation continues.

Contact: security@isectech.com
```

---

## Maintenance and Operations

### Regular Maintenance Tasks

#### Daily Tasks
- [ ] Review monitoring dashboards
- [ ] Check rotation schedule compliance
- [ ] Review audit logs for anomalies
- [ ] Verify backup integrity

#### Weekly Tasks  
- [ ] Execute rotation dry runs
- [ ] Review access control matrix
- [ ] Update documentation
- [ ] Test emergency procedures

#### Monthly Tasks
- [ ] Complete secret inventory
- [ ] Review and update IAM policies
- [ ] Analyze secret usage patterns
- [ ] Conduct security training

#### Quarterly Tasks
- [ ] Disaster recovery testing
- [ ] Third-party security assessment
- [ ] Policy review and updates
- [ ] Compliance audit preparation

### Automation Maintenance

#### Script Updates
```bash
# Test rotation scripts in staging
./rotate-secrets.sh --environment staging --dry-run

# Update script with new secret types
vi rotate-secrets.sh

# Test updated script
./test-rotation-script.sh

# Deploy to production
git commit -m "Update rotation script"
git push origin main
```

#### Monitoring Updates
```bash
# Update alerting rules
kubectl apply -f monitoring/secret-alerts.yaml

# Test alert notifications
./test-alerts.sh

# Update dashboards
curl -X POST "grafana.isectech.com/api/dashboards/db" -d @dashboards/secrets.json
```

### Performance Optimization

#### Secret Manager Optimization
- Use appropriate secret sizes
- Implement client-side caching with TTL
- Batch secret operations where possible
- Use regional replication for performance

#### Service Performance
- Minimize secret access frequency
- Implement circuit breakers
- Use connection pooling
- Monitor and optimize startup times

### Capacity Planning

#### Secret Manager Limits
- 1,000 secrets per project (soft limit)
- 100 versions per secret
- 1MB maximum secret size
- 1,000 requests per second per region

#### Scaling Considerations
- Plan for secret growth over time
- Consider multi-project architecture
- Implement regional distribution
- Monitor quota usage and request limits

---

## Conclusion

This document provides comprehensive procedures for managing secrets in the iSECTECH platform. Regular review and updates ensure these procedures remain effective as the platform evolves.

### Key Success Factors

1. **Automation First** - Reduce human error through automation
2. **Defense in Depth** - Multiple layers of security controls
3. **Continuous Monitoring** - Real-time visibility into all operations
4. **Regular Testing** - Procedures must be tested to be effective
5. **Documentation** - Keep procedures current and accessible

### Contact Information

- **Security Team:** security@isectech.com
- **Platform Team:** platform@isectech.com  
- **Emergency Hotline:** +1-800-ISECTECH (24/7)
- **Documentation:** https://docs.isectech.com/security/secrets

---

**Document Classification:** Internal - Security Critical  
**Next Review Date:** 2025-07-01  
**Document Owner:** Chief Security Officer  
**Approved By:** Chief Technology Officer