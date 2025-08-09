# Database Failure - Disaster Recovery Runbook

**Runbook ID:** DR-002  
**Scenario:** Primary Aurora PostgreSQL cluster failure  
**RTO Target:** 10 minutes  
**RPO Target:** 2 minutes  
**Last Updated:** 2024-01-15  
**Owner:** Database Engineering Team  

## Overview

This runbook covers Aurora PostgreSQL primary cluster failures, including writer instance failures, complete cluster outages, and cross-region database recovery procedures.

## Prerequisites

- [ ] Access to AWS RDS Console in all regions
- [ ] Database administrator credentials
- [ ] Read replica status verified healthy
- [ ] Cross-region replica lag < 2 minutes
- [ ] Application connection pool monitoring access

## Failure Scenarios

### Scenario A: Writer Instance Failure
**Detection:** Writer instance becomes unresponsive but readers remain healthy
**Expected Duration:** 2-5 minutes
**Action:** Automatic failover to reader instance

### Scenario B: Complete Cluster Failure
**Detection:** All instances in primary cluster unresponsive
**Expected Duration:** 5-10 minutes
**Action:** Promote cross-region read replica

### Scenario C: Data Corruption
**Detection:** Data integrity checks fail, corrupt data detected
**Expected Duration:** 15-30 minutes
**Action:** Point-in-time recovery from backup

## Detection and Alerts

### Automated Detection
```bash
# CloudWatch Alarms
- DatabaseConnections < 1 for 2 minutes
- DatabaseCPUUtilization = 0 for 2 minutes
- DatabaseWriteLatency > 5000ms for 3 minutes
- DatabaseReadLatency > 1000ms for 3 minutes

# Custom Health Checks
curl -f https://api.isectech.com/health/database
```

### Manual Verification
```bash
# Test direct database connection
psql -h isectech-postgres-primary.cluster-xyz.us-east-1.rds.amazonaws.com \
     -U isectech_admin \
     -d isectech \
     -c "SELECT NOW();"

# Check RDS cluster status
aws rds describe-db-clusters \
  --db-cluster-identifier isectech-production-primary \
  --region us-east-1
```

## Recovery Procedures

### Scenario A: Writer Instance Failover

#### Step 1: Verify Failure (0-1 minute)
```bash
# Check cluster status
aws rds describe-db-clusters \
  --db-cluster-identifier isectech-production-primary \
  --query 'DBClusters[0].Status'

# Check individual instances
aws rds describe-db-instances \
  --db-instance-identifier isectech-primary-writer \
  --query 'DBInstances[0].DBInstanceStatus'
```

#### Step 2: Initiate Manual Failover (1-3 minutes)
```bash
# Failover to reader instance
aws rds failover-db-cluster \
  --db-cluster-identifier isectech-production-primary \
  --target-db-instance-identifier isectech-primary-reader-1

# Monitor failover progress
aws rds describe-db-clusters \
  --db-cluster-identifier isectech-production-primary \
  --query 'DBClusters[0].[Status,Endpoint,ReaderEndpoint]'
```

#### Step 3: Verify Application Connectivity (3-5 minutes)
```bash
# Test new writer endpoint
psql -h isectech-postgres-primary.cluster-xyz.us-east-1.rds.amazonaws.com \
     -U isectech_admin \
     -d isectech \
     -c "SELECT pg_is_in_recovery();"  # Should return 'f' for writer

# Check application health
kubectl get pods -n isectech-production -l component=backend
kubectl logs -f deployment/isectech-backend -n isectech-production --tail=50
```

### Scenario B: Complete Cluster Failover

#### Step 1: Assess Cross-Region Replica (0-2 minutes)
```bash
# Check secondary region cluster
aws rds describe-db-clusters \
  --db-cluster-identifier isectech-production-secondary \
  --region us-west-2 \
  --query 'DBClusters[0].[Status,GlobalClusterResourceId]'

# Verify replication lag
aws rds describe-db-clusters \
  --db-cluster-identifier isectech-production-secondary \
  --region us-west-2 \
  --query 'DBClusters[0].GlobalWriteForwardingRequested'
```

#### Step 2: Promote Secondary to Primary (2-6 minutes)
```bash
# Remove from global cluster
aws rds remove-from-global-cluster \
  --global-cluster-identifier isectech-production-global \
  --db-cluster-identifier isectech-production-secondary \
  --region us-west-2

# Wait for removal
aws rds wait db-cluster-available \
  --db-cluster-identifier isectech-production-secondary \
  --region us-west-2

# The cluster is now independent and writable
```

#### Step 3: Update Application Configuration (4-8 minutes)
```bash
# Update Kubernetes secret with new endpoint
kubectl patch secret database-config -p '{
  "data": {
    "host": "'$(echo -n "isectech-production-secondary.cluster-xyz.us-west-2.rds.amazonaws.com" | base64)'",
    "port": "'$(echo -n "5432" | base64)'"
  }
}' -n isectech-production

# Restart applications to pick up new connection
kubectl rollout restart deployment isectech-backend -n isectech-production
kubectl rollout restart deployment isectech-frontend -n isectech-production
```

#### Step 4: Update DNS and Load Balancer (6-10 minutes)
```bash
# Update internal DNS records
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456789INTERNAL \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "database.internal.isectech.com",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "isectech-production-secondary.cluster-xyz.us-west-2.rds.amazonaws.com"}]
      }
    }]
  }'
```

### Scenario C: Point-in-Time Recovery

#### Step 1: Identify Recovery Point (0-5 minutes)
```bash
# Find the last known good backup
aws rds describe-db-cluster-snapshots \
  --db-cluster-identifier isectech-production-primary \
  --snapshot-type automated \
  --query 'DBClusterSnapshots[0].[DBClusterSnapshotIdentifier,SnapshotCreateTime]'

# Determine point-in-time recovery target
# Usually 5-10 minutes before corruption detection
RECOVERY_TIME="2024-01-15T10:30:00.000Z"
```

#### Step 2: Create Recovery Cluster (5-15 minutes)
```bash
# Restore cluster from point-in-time
aws rds restore-db-cluster-to-point-in-time \
  --db-cluster-identifier isectech-production-recovery \
  --source-db-cluster-identifier isectech-production-primary \
  --restore-to-time $RECOVERY_TIME \
  --engine aurora-postgresql \
  --engine-version 15.4

# Create instances in recovery cluster
aws rds create-db-instance \
  --db-instance-identifier isectech-recovery-writer \
  --db-cluster-identifier isectech-production-recovery \
  --db-instance-class db.r6g.xlarge \
  --engine aurora-postgresql

aws rds create-db-instance \
  --db-instance-identifier isectech-recovery-reader-1 \
  --db-cluster-identifier isectech-production-recovery \
  --db-instance-class db.r6g.xlarge \
  --engine aurora-postgresql
```

#### Step 3: Validate Data Integrity (10-20 minutes)
```bash
# Connect to recovery cluster
psql -h isectech-production-recovery.cluster-xyz.us-east-1.rds.amazonaws.com \
     -U isectech_admin \
     -d isectech

# Run data integrity checks
SELECT 
  schemaname,
  tablename,
  n_tup_ins,
  n_tup_upd,
  n_tup_del
FROM pg_stat_user_tables 
ORDER BY n_tup_ins DESC;

# Verify specific business data
SELECT COUNT(*) FROM users WHERE created_at >= '2024-01-15 10:00:00';
SELECT COUNT(*) FROM transactions WHERE created_at >= '2024-01-15 10:00:00';
```

#### Step 4: Switch to Recovery Cluster (15-25 minutes)
```bash
# Update application configuration
kubectl patch secret database-config -p '{
  "data": {
    "host": "'$(echo -n "isectech-production-recovery.cluster-xyz.us-east-1.rds.amazonaws.com" | base64)'"
  }
}' -n isectech-production

# Rolling restart of applications
kubectl rollout restart deployment -n isectech-production
```

## Verification Procedures

### Database Health Checks
```sql
-- Connection test
SELECT NOW() as current_time;

-- Replication status (for readers)
SELECT pg_is_in_recovery();

-- Active connections
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

-- Transaction rate
SELECT 
  xact_commit + xact_rollback as total_transactions,
  xact_commit,
  xact_rollback
FROM pg_stat_database 
WHERE datname = 'isectech';

-- Performance metrics
SELECT 
  schemaname,
  tablename,
  seq_scan,
  seq_tup_read,
  idx_scan,
  idx_tup_fetch
FROM pg_stat_user_tables 
WHERE schemaname = 'public'
ORDER BY seq_scan DESC;
```

### Application Integration Tests
```bash
# API health check with database dependency
curl -f https://api.isectech.com/health/database

# User authentication test (requires database)
curl -X POST https://api.isectech.com/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@isectech.com","password":"testpass"}'

# Business transaction test
curl -X POST https://api.isectech.com/transactions \
  -H "Authorization: Bearer $TEST_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount":1.00,"description":"DB test transaction"}'
```

## Monitoring and Alerting

### Key Metrics to Monitor
```bash
# Database Performance
- ConnectionCount
- DatabaseConnections
- CPUUtilization
- FreeStorageSpace
- ReadLatency
- WriteLatency
- ReadThroughput
- WriteThroughput

# Replication Metrics
- AuroraReplicaLag
- BinlogReplicaLag (if applicable)

# Application Metrics
- Database connection pool utilization
- Query execution time
- Transaction success rate
```

### Alert Configuration
```yaml
# CloudWatch Alarms
DatabaseWriterConnectionsHigh:
  MetricName: DatabaseConnections
  Threshold: 80
  ComparisonOperator: GreaterThanThreshold
  
DatabaseHighCPU:
  MetricName: CPUUtilization
  Threshold: 80
  ComparisonOperator: GreaterThanThreshold
  
DatabaseHighWriteLatency:
  MetricName: WriteLatency
  Threshold: 0.2  # 200ms
  ComparisonOperator: GreaterThanThreshold
  
AuroraReplicaLagHigh:
  MetricName: AuroraReplicaLag
  Threshold: 30000  # 30 seconds
  ComparisonOperator: GreaterThanThreshold
```

## Communication Templates

### Database Failure Alert
```
Subject: [CRITICAL] Database Failure Detected - Recovery in Progress

Database failure detected at [TIMESTAMP]
Failure Type: [Writer Instance Failure / Complete Cluster Failure / Data Corruption]
Expected RTO: [X] minutes
Current Status: [IN PROGRESS / COMPLETED]

Actions Taken:
- [List actions]

Next Steps:
- [List next steps]

Database Team
```

### Recovery Complete
```
Subject: [RESOLVED] Database Recovery Complete

Database recovery has been completed successfully.

Recovery Summary:
- Failure type: [Type]
- Recovery time: [X] minutes (RTO target: 10 minutes)
- Data loss: [X] minutes (RPO target: 2 minutes)
- Recovery method: [Method used]

All database services are now operational.

Database Team
```

## Post-Recovery Actions

### Immediate (0-2 hours)
1. **Monitor database performance**
   - Watch for any performance degradation
   - Monitor connection counts
   - Verify replication is re-established

2. **Backup verification**
   - Ensure backups are running
   - Verify point-in-time recovery capability
   - Test backup restoration

3. **Application stability**
   - Monitor application error rates
   - Verify all database-dependent features
   - Check for any data consistency issues

### Short-term (2-24 hours)
1. **Root cause analysis**
   - Review database logs
   - Analyze AWS CloudTrail logs
   - Identify failure trigger

2. **Performance optimization**
   - Review slow query logs
   - Optimize any problematic queries
   - Adjust connection pool settings

3. **Replication rebuild**
   - If using cross-region replica, ensure it's rebuilt
   - Verify global cluster configuration
   - Test failover capabilities

### Long-term (1-7 days)
1. **Runbook updates**
   - Document lessons learned
   - Update procedures based on experience
   - Review and improve automation

2. **Infrastructure improvements**
   - Implement additional monitoring
   - Enhance backup strategies
   - Consider multi-AZ improvements

3. **Training and documentation**
   - Update team training materials
   - Conduct post-incident review
   - Schedule additional DR drills

## Automation Scripts

### Health Check Script
```bash
#!/bin/bash
# db-health-check.sh

DB_ENDPOINT="$1"
DB_NAME="$2"
DB_USER="$3"

# Test connection
if psql -h "$DB_ENDPOINT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" &>/dev/null; then
    echo "Database connection: OK"
else
    echo "Database connection: FAILED"
    exit 1
fi

# Check if it's a writer
WRITER_CHECK=$(psql -h "$DB_ENDPOINT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT pg_is_in_recovery();" | xargs)
if [ "$WRITER_CHECK" = "f" ]; then
    echo "Database role: WRITER"
else
    echo "Database role: READER"
fi

# Check active connections
ACTIVE_CONN=$(psql -h "$DB_ENDPOINT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';" | xargs)
echo "Active connections: $ACTIVE_CONN"

# Check replication lag (if reader)
if [ "$WRITER_CHECK" = "t" ]; then
    LAG=$(psql -h "$DB_ENDPOINT" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));" | xargs)
    echo "Replication lag: ${LAG}s"
fi
```

### Emergency Contacts

| Role | Primary | Secondary | Phone |
|------|---------|-----------|-------|
| Database Administrator | [Name] | [Name] | [Phone] |
| Platform Engineering Lead | [Name] | [Name] | [Phone] |
| DevOps On-Call | [Name] | [Name] | [Phone] |
| AWS Support | N/A | N/A | Enterprise Support |

## Testing Schedule

- **Monthly:** Writer instance failover test
- **Quarterly:** Cross-region failover test  
- **Bi-annually:** Point-in-time recovery test
- **Annually:** Complete disaster recovery drill

**Next scheduled test:** [Date]  
**Test coordinator:** [Name]