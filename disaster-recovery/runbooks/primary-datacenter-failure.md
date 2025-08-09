# Primary Datacenter Failure - Disaster Recovery Runbook

**Runbook ID:** DR-001  
**Scenario:** Complete failure of primary datacenter (us-east-1)  
**RTO Target:** 15 minutes  
**RPO Target:** 5 minutes  
**Last Updated:** 2024-01-15  
**Owner:** Platform Engineering Team  

## Overview

This runbook covers the complete failure of the primary datacenter (us-east-1) and the procedures to failover to the secondary datacenter (us-west-2) while maintaining service availability and data integrity.

## Prerequisites

- [ ] Access to AWS Console for both us-east-1 and us-west-2 regions
- [ ] VPN connection established to emergency operations center
- [ ] PagerDuty/emergency contact list available
- [ ] Secondary datacenter infrastructure verified healthy
- [ ] Database replica lag < 5 minutes in secondary region

## Failure Detection Triggers

### Automated Triggers
- Route53 health checks failing for >3 minutes
- EKS cluster unreachable from secondary region
- Aurora primary cluster connection failures
- CloudWatch alarms: `PrimaryDatacenterDown`

### Manual Triggers
- AWS service health dashboard shows region-wide issues
- Network connectivity loss to primary region
- Physical datacenter security/safety events

## Step-by-Step Recovery Procedure

### Phase 1: Immediate Assessment (0-2 minutes)

#### 1.1 Verify Failure Scope
```bash
# Check AWS service health
aws service-health describe-events --region us-east-1

# Verify Route53 health check status
aws route53 get-health-check-status --health-check-id hc-primary-isectech

# Check EKS cluster status
aws eks describe-cluster --name isectech-production-primary --region us-east-1
```

#### 1.2 Confirm Secondary Infrastructure Health
```bash
# Verify secondary EKS cluster
aws eks describe-cluster --name isectech-production-secondary --region us-west-2

# Check Aurora secondary cluster status
aws rds describe-db-clusters --db-cluster-identifier isectech-production-secondary --region us-west-2

# Verify ElastiCache Redis secondary
aws elasticache describe-replication-groups --region us-west-2
```

#### 1.3 Notify Stakeholders
```bash
# Send initial notification
curl -X POST "https://api.pagerduty.com/incidents" \
  -H "Content-Type: application/json" \
  -H "Authorization: Token token=YOUR_PD_TOKEN" \
  -d '{
    "incident": {
      "type": "incident",
      "title": "Primary Datacenter Failure - DR Activation",
      "service": {"id": "PSERVICE_ID", "type": "service_reference"},
      "urgency": "high",
      "body": {"type": "incident_body", "details": "Initiating DR failover to us-west-2"}
    }
  }'

# Notify Slack emergency channel
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"🚨 PRIMARY DATACENTER FAILURE - Initiating DR procedures"}' \
  $SLACK_EMERGENCY_WEBHOOK
```

### Phase 2: DNS Failover (2-5 minutes)

#### 2.1 Update Route53 Records
```bash
# Update main application record to point to secondary ALB
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "isectech.com",
        "Type": "A",
        "AliasTarget": {
          "DNSName": "isectech-alb-secondary.us-west-2.elb.amazonaws.com",
          "EvaluateTargetHealth": true,
          "HostedZoneId": "Z1D633PJN98FT9"
        }
      }
    }]
  }'

# Update API subdomain
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789 \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.isectech.com",
        "Type": "A",
        "AliasTarget": {
          "DNSName": "isectech-alb-secondary.us-west-2.elb.amazonaws.com",
          "EvaluateTargetHealth": true,
          "HostedZoneId": "Z1D633PJN98FT9"
        }
      }
    }]
  }'
```

#### 2.2 Verify DNS Propagation
```bash
# Check DNS resolution
dig isectech.com
dig api.isectech.com

# Verify from multiple locations
for location in 8.8.8.8 1.1.1.1 208.67.222.222; do
  dig @$location isectech.com
done
```

### Phase 3: Database Failover (3-8 minutes)

#### 3.1 Promote Aurora Secondary to Primary
```bash
# Promote Aurora secondary cluster
aws rds failover-global-cluster \
  --global-cluster-identifier isectech-production-global \
  --target-db-cluster-identifier isectech-production-secondary \
  --region us-west-2

# Wait for promotion to complete
aws rds wait db-cluster-available \
  --db-cluster-identifier isectech-production-secondary \
  --region us-west-2
```

#### 3.2 Update Database Connection Strings
```bash
# Update Kubernetes secrets in secondary cluster
kubectl config use-context isectech-production-secondary

# Update database endpoint secret
kubectl patch secret database-config -p '{
  "data": {
    "host": "'$(echo -n "isectech-production-secondary.cluster-xyz.us-west-2.rds.amazonaws.com" | base64)'"
  }
}'

# Restart applications to pick up new connection string
kubectl rollout restart deployment -n isectech-production
```

#### 3.3 Verify Database Connectivity
```bash
# Test database connectivity from secondary region
kubectl run db-test --image=postgres:15 --rm -it --restart=Never -- \
  psql -h isectech-production-secondary.cluster-xyz.us-west-2.rds.amazonaws.com \
       -U isectech_admin \
       -d isectech \
       -c "SELECT 1;"
```

### Phase 4: Application Services Scaling (5-10 minutes)

#### 4.1 Scale Up Secondary Region Workloads
```bash
# Scale up EKS node groups
aws eks update-nodegroup-config \
  --cluster-name isectech-production-secondary \
  --nodegroup-name application \
  --scaling-config minSize=6,maxSize=20,desiredSize=12 \
  --region us-west-2

# Scale up application deployments
kubectl scale deployment isectech-frontend --replicas=6 -n isectech-production
kubectl scale deployment isectech-backend --replicas=8 -n isectech-production
kubectl scale deployment isectech-security-service --replicas=4 -n isectech-security
```

#### 4.2 Update Load Balancer Target Groups
```bash
# Verify targets are healthy in secondary ALB
aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:us-west-2:ACCOUNT:targetgroup/isectech-frontend-secondary \
  --region us-west-2

aws elbv2 describe-target-health \
  --target-group-arn arn:aws:elasticloadbalancing:us-west-2:ACCOUNT:targetgroup/isectech-backend-secondary \
  --region us-west-2
```

### Phase 5: Cache and Session Management (8-12 minutes)

#### 5.1 Redis Failover
```bash
# Update Redis endpoint configuration
kubectl patch configmap redis-config -p '{
  "data": {
    "endpoint": "isectech-redis-secondary.def456.usw2.cache.amazonaws.com:6379"
  }
}'

# Restart services that use Redis
kubectl rollout restart deployment isectech-session-manager -n isectech-production
kubectl rollout restart deployment isectech-cache-service -n isectech-production
```

#### 5.2 Session Recovery
```bash
# If using sticky sessions, execute session recovery script
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: session-recovery
  namespace: isectech-production
spec:
  template:
    spec:
      containers:
      - name: session-recovery
        image: isectech/session-recovery:latest
        env:
        - name: REDIS_ENDPOINT
          value: "isectech-redis-secondary.def456.usw2.cache.amazonaws.com:6379"
        - name: RECOVERY_MODE
          value: "disaster-recovery"
      restartPolicy: Never
EOF
```

### Phase 6: Monitoring and Verification (10-15 minutes)

#### 6.1 Verify Service Health
```bash
# Health check endpoints
curl -f https://isectech.com/health
curl -f https://api.isectech.com/health
curl -f https://security.isectech.com/health

# Check application logs
kubectl logs -f deployment/isectech-frontend -n isectech-production --tail=100
kubectl logs -f deployment/isectech-backend -n isectech-production --tail=100
```

#### 6.2 Update Monitoring Systems
```bash
# Update monitoring dashboards to show secondary region metrics
curl -X POST "https://grafana.isectech.com/api/dashboards/db" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -d @disaster-recovery-dashboard.json

# Update alerting rules for new infrastructure
kubectl apply -f monitoring/disaster-recovery-alerts.yaml
```

#### 6.3 Validate Business Functions
```bash
# Execute automated business function tests
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: business-function-test
  namespace: isectech-testing
spec:
  template:
    spec:
      containers:
      - name: function-test
        image: isectech/business-tests:latest
        env:
        - name: TEST_SUITE
          value: "disaster-recovery"
        - name: TARGET_ENV
          value: "secondary-production"
      restartPolicy: Never
EOF
```

## Verification Checklist

### Technical Verification
- [ ] DNS resolves to secondary datacenter (us-west-2)
- [ ] All health check endpoints return 200 OK
- [ ] Database is writable and readable
- [ ] Redis cache is accessible
- [ ] Application performance within acceptable limits
- [ ] SSL certificates valid and working
- [ ] CDN pointing to correct origin

### Business Verification
- [ ] User authentication working
- [ ] Core business transactions processing
- [ ] Payment systems functional
- [ ] Email notifications sending
- [ ] Third-party integrations responding
- [ ] Security scanning services operational

### Monitoring Verification
- [ ] All critical alerts resolved or acknowledged
- [ ] Monitoring dashboards updated for secondary region
- [ ] Log aggregation working from secondary region
- [ ] Backup systems running in secondary region
- [ ] Performance metrics within SLA thresholds

## Communication Templates

### Initial Notification (0-2 minutes)
```
Subject: [CRITICAL] Primary Datacenter Failure - DR Activation in Progress

Team,

We have detected a complete failure of our primary datacenter (us-east-1). 
Disaster recovery procedures are being initiated immediately.

Current Status:
- Primary datacenter: DOWN
- Secondary datacenter: HEALTHY
- DR procedure: IN PROGRESS
- Expected recovery time: 15 minutes

We will provide updates every 5 minutes.

Platform Engineering Team
```

### Update Notification (5-minute intervals)
```
Subject: [UPDATE] DR Recovery Progress - [X] minutes elapsed

Update #[N] - [X] minutes since failure detection

Completed:
- [List completed steps]

In Progress:
- [Current step]

Next Steps:
- [Upcoming steps]

Estimated time to full recovery: [X] minutes

Platform Engineering Team
```

### Recovery Complete Notification
```
Subject: [RESOLVED] DR Recovery Complete - Services Restored

Team,

Disaster recovery has been successfully completed. All services have been 
restored and are operating normally from our secondary datacenter (us-west-2).

Recovery Summary:
- Total outage time: [X] minutes
- RTO achieved: [Y] minutes (target: 15 minutes)
- RPO achieved: [Z] minutes (target: 5 minutes)
- All business functions verified

Post-incident review will be scheduled within 24 hours.

Platform Engineering Team
```

## Post-Recovery Actions

### Immediate (0-1 hour)
1. **Document the incident**
   - Record actual RTO/RPO achieved
   - Note any deviations from runbook
   - Capture lessons learned

2. **Stabilize secondary region**
   - Monitor for any issues
   - Ensure all services are stable
   - Verify backup systems running

3. **Customer communication**
   - Update status page
   - Send customer notifications
   - Prepare executive summary

### Short-term (1-24 hours)
1. **Post-incident review**
   - Schedule review meeting
   - Gather all stakeholders
   - Analyze response effectiveness

2. **Primary region assessment**
   - Determine cause of failure
   - Estimate repair timeline
   - Plan primary region recovery

3. **Update documentation**
   - Revise runbook based on experience
   - Update emergency contact information
   - Review and update procedures

### Long-term (1-30 days)
1. **Implement improvements**
   - Address identified gaps
   - Enhance automation
   - Improve monitoring

2. **Plan primary region recovery**
   - Schedule maintenance window
   - Prepare failback procedures
   - Test failback process

3. **Conduct DR drill review**
   - Schedule additional testing
   - Update training materials
   - Refresh team knowledge

## Rollback Procedures

If issues are detected after failover, use the following rollback steps:

### Emergency Rollback (if primary becomes available)
```bash
# Only if primary region comes back online and secondary has issues

# 1. Stop new writes to secondary database
kubectl scale deployment isectech-backend --replicas=0 -n isectech-production

# 2. Revert DNS records to primary
aws route53 change-resource-record-sets --hosted-zone-id Z123456789 \
  --change-batch file://revert-to-primary-dns.json

# 3. Restart primary services
kubectl config use-context isectech-production-primary
kubectl scale deployment isectech-backend --replicas=8 -n isectech-production
```

## Testing and Validation

This runbook should be tested monthly through:
- Tabletop exercises
- Partial failover tests
- Full disaster recovery drills

**Next scheduled test:** [Date]  
**Test coordinator:** [Name]  
**Test participants:** [Team members]

## Emergency Contacts

| Role | Primary | Secondary | Phone |
|------|---------|-----------|-------|
| Platform Engineering Lead | [Name] | [Name] | [Phone] |
| DevOps On-Call | [Name] | [Name] | [Phone] |
| Database Administrator | [Name] | [Name] | [Phone] |
| Security Team Lead | [Name] | [Name] | [Phone] |
| Executive Escalation | [Name] | [Name] | [Phone] |

## Appendix

### A. Configuration Files
- DNS change batch files
- Kubernetes manifests
- Monitoring configurations

### B. Scripts and Automation
- Automated failover scripts
- Health check scripts
- Notification scripts

### C. Dependencies
- Third-party service contacts
- Vendor escalation procedures
- External dependency runbooks