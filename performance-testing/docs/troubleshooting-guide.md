# Performance Testing Framework Troubleshooting Guide

## Overview

This guide provides comprehensive troubleshooting procedures for the iSECTECH Performance Testing Framework, covering common issues, diagnostic procedures, and resolution steps.

## 🚨 Emergency Procedures

### Critical Performance Issues in Production

If performance issues are detected in production:

1. **Immediate Assessment**
   ```bash
   # Check system health
   ./scripts/performance-monitoring-integration.sh validate production
   
   # Quick bottleneck analysis
   ./scripts/bottleneck-analyzer.sh --environment production --quick-scan
   ```

2. **Rollback Decision**
   ```bash
   # Check recent deployments
   git log --oneline -10
   
   # Review performance trends
   # Access Grafana: http://localhost:3001
   # Check "System Performance Overview" dashboard
   ```

3. **Emergency Contacts**
   - DevOps On-Call: Use PagerDuty
   - Performance Team: performance-team@isectech.com
   - Backend Team: backend@isectech.com

### Rollback Procedures

```bash
# Automatic rollback via optimization script
./scripts/performance-optimizer.sh --rollback --backup-id LATEST

# Manual rollback to previous known good state
git revert <commit-hash>
# Or use deployment pipeline rollback
```

## 🔍 Diagnostic Tools

### Health Check Commands

```bash
# Overall system health
docker-compose -f performance-testing/docker/docker-compose.distributed.yml ps

# Service-specific health checks
curl -f http://localhost:8086/ping              # InfluxDB
curl -f http://localhost:9090/-/healthy         # Prometheus  
curl -f http://localhost:3001/api/health        # Grafana

# Kubernetes health (if using K8s deployment)
kubectl get pods -n performance-testing
kubectl describe pod <pod-name> -n performance-testing
```

### Log Analysis

```bash
# Docker logs
docker-compose -f docker/docker-compose.distributed.yml logs -f k6-coordinator
docker-compose -f docker/docker-compose.distributed.yml logs -f artillery-coordinator

# Kubernetes logs
kubectl logs -f deployment/k6-coordinator -n performance-testing
kubectl logs -f deployment/k6-workers -n performance-testing

# Application logs
tail -f /var/log/isectech/application.log
journalctl -u isectech-api -f
```

### Performance Metrics Collection

```bash
# Real-time metrics
./scripts/bottleneck-analyzer.sh --real-time --environment staging

# Historical analysis
./scripts/bottleneck-analyzer.sh --period 24h --report-format html

# CI/CD validation logs
./scripts/ci-performance-validator.sh baseline staging ./test-results ./diagnostics
```

## 🐛 Common Issues and Solutions

### 1. Test Infrastructure Issues

#### Issue: Docker Services Not Starting

**Symptoms:**
- `docker-compose up` fails
- Services exit immediately
- Port binding errors

**Diagnosis:**
```bash
# Check port availability
netstat -tulpn | grep :8086  # InfluxDB
netstat -tulpn | grep :9090  # Prometheus
netstat -tulpn | grep :3001  # Grafana

# Check Docker daemon
docker info
docker system df
```

**Solution:**
```bash
# Stop conflicting services
sudo systemctl stop influxdb prometheus grafana-server

# Clean up Docker resources
docker system prune -f
docker volume prune -f

# Restart with different ports if needed
export INFLUXDB_PORT=8087
export PROMETHEUS_PORT=9091
export GRAFANA_PORT=3002
docker-compose -f docker/docker-compose.distributed.yml up -d
```

#### Issue: Kubernetes Pods Failing to Start

**Symptoms:**
- Pods stuck in Pending/CrashLoopBackOff
- Resource quota exceeded
- Image pull errors

**Diagnosis:**
```bash
# Check pod status
kubectl describe pod <pod-name> -n performance-testing

# Check resource usage
kubectl top nodes
kubectl describe resourcequota -n performance-testing

# Check image availability
kubectl get events -n performance-testing --sort-by='.lastTimestamp'
```

**Solution:**
```bash
# Scale down other deployments if resource constrained
kubectl scale deployment non-essential-app --replicas=0

# Update resource requests/limits
kubectl patch deployment k6-workers -n performance-testing -p '{"spec":{"template":{"spec":{"containers":[{"name":"k6-worker","resources":{"requests":{"memory":"256Mi","cpu":"100m"}}}]}}}}'

# Pull images manually if needed
docker pull isectech/k6-distributed:latest
docker pull isectech/artillery-distributed:latest
```

### 2. Load Test Execution Issues

#### Issue: k6 Tests Failing with Connection Errors

**Symptoms:**
- "dial tcp: connection refused" errors
- High error rates in test results
- Tests timing out

**Diagnosis:**
```bash
# Test API connectivity
curl -I https://api.isectech.com/health
curl -w "@curl-format.txt" -s -o /dev/null https://api.isectech.com/api/dashboard/summary

# Check DNS resolution
nslookup api.isectech.com
dig api.isectech.com

# Test from k6 container
docker run --rm grafana/k6 run -e API_BASE_URL=https://api.isectech.com - <<EOF
import http from 'k6/http';
export default function() {
  let response = http.get(__ENV.API_BASE_URL + '/health');
  console.log('Status:', response.status);
}
EOF
```

**Solution:**
```bash
# Update base URL in environment
export API_BASE_URL="https://staging.isectech.com"  # Use staging if prod issues

# Add retry logic to k6 scripts
# Edit k6/config/config.js to increase timeouts:
# http: { timeout: '60s' }

# Check rate limiting
# Review API gateway logs for 429 responses
kubectl logs -f deployment/api-gateway
```

#### Issue: Artillery Tests Producing Invalid Results

**Symptoms:**
- Missing metrics in output
- Artillery process crashes
- Incomplete test phases

**Diagnosis:**
```bash
# Run Artillery with debug output
artillery run --debug artillery/comprehensive-load-test.yml

# Check Artillery configuration
artillery validate artillery/comprehensive-load-test.yml

# Test with minimal config
cat > minimal-test.yml << EOF
config:
  target: 'https://api.isectech.com'
  phases:
    - duration: 60
      arrivalRate: 1
scenarios:
  - name: 'Health check'
    requests:
      - get:
          url: '/health'
EOF
artillery run minimal-test.yml
```

**Solution:**
```bash
# Update Artillery configuration
# Fix common issues in artillery/comprehensive-load-test.yml:
# - Reduce arrival rates if target cannot handle load
# - Increase timeouts for slow endpoints
# - Add proper error handling

# Upgrade Artillery
npm install -g artillery@latest

# Use Artillery with resource limits
docker run --rm -m 1g --cpus 1 artilleryio/artillery:latest run /test/comprehensive-load-test.yml
```

### 3. Monitoring and Metrics Issues

#### Issue: Missing Metrics in InfluxDB

**Symptoms:**
- Empty dashboards in Grafana
- No data in InfluxDB queries
- Metrics not appearing in Prometheus

**Diagnosis:**
```bash
# Check InfluxDB connectivity
curl -I http://localhost:8086/ping

# List databases
curl -G 'http://localhost:8086/query' --data-urlencode 'q=SHOW DATABASES'

# Check specific database
curl -G 'http://localhost:8086/query?db=k6_metrics' --data-urlencode 'q=SHOW MEASUREMENTS'

# Check k6 output configuration
k6 run --out influxdb=http://localhost:8086/k6_metrics k6/scenarios/api-endpoints-comprehensive.js --dry-run
```

**Solution:**
```bash
# Recreate InfluxDB database
curl -X POST 'http://localhost:8086/query' --data-urlencode 'q=CREATE DATABASE k6_metrics'
curl -X POST 'http://localhost:8086/query' --data-urlencode 'q=CREATE DATABASE artillery_metrics'

# Fix k6 output configuration
export K6_INFLUXDB_PUSH_INTERVAL=5s
export K6_INFLUXDB_CONCURRENT_WRITES=10

# Verify InfluxDB line protocol format
# Check k6/config/config.js for proper InfluxDB configuration
```

#### Issue: Grafana Dashboards Not Loading

**Symptoms:**
- Blank panels in dashboards
- "Query returned no data" messages
- Dashboard loading errors

**Diagnosis:**
```bash
# Check Grafana logs
docker logs performance-testing_grafana_1

# Test data source connectivity
curl -H "Authorization: Bearer $GRAFANA_API_KEY" \
     http://localhost:3001/api/datasources/1/health

# Check dashboard configuration
curl -H "Authorization: Bearer $GRAFANA_API_KEY" \
     http://localhost:3001/api/dashboards/home
```

**Solution:**
```bash
# Restart Grafana with fresh configuration
docker-compose -f docker/docker-compose.distributed.yml restart grafana

# Reimport dashboards
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GRAFANA_API_KEY" \
     -d @config/grafana/dashboards/k6-performance-dashboard.json \
     http://localhost:3001/api/dashboards/db

# Reset data sources
# Access Grafana UI: http://localhost:3001
# Configuration > Data Sources > Add data source
# InfluxDB: http://influxdb:8086, Database: k6_metrics
```

### 4. CI/CD Pipeline Issues

#### Issue: GitHub Actions Workflow Failing

**Symptoms:**
- Workflow runs fail at performance testing step
- Timeout errors in CI
- Permission denied errors

**Diagnosis:**
```bash
# Check workflow runs
gh run list --workflow=performance-testing.yml

# View specific run logs
gh run view <run-id> --log

# Test workflow components locally
act -j performance-baseline-test  # Using act to run GitHub Actions locally
```

**Solution:**
```bash
# Update GitHub secrets
gh secret set GRAFANA_API_KEY --body "<your-api-key>"
gh secret set SLACK_PERFORMANCE_WEBHOOK --body "<webhook-url>"

# Fix timeout issues by adjusting workflow
# Edit .github/workflows/performance-testing.yml:
# - Increase timeout values
# - Reduce test duration for CI
# - Use smaller concurrent user counts

# Fix permission issues
# Ensure proper secrets and environment variables are set
```

#### Issue: Performance Validation Failing

**Symptoms:**
- CI reports performance regression when none exists
- Incorrect baseline comparisons
- Validation script errors

**Diagnosis:**
```bash
# Run validation script manually
./scripts/ci-performance-validator.sh baseline staging ./test-results ./debug-output

# Check threshold configuration
jq '.global_thresholds' config/ci-cd/performance-thresholds.json

# Review validation report
cat ./debug-output/validation_report.json | jq '.issues[]'
```

**Solution:**
```bash
# Update performance thresholds if they're too strict
vim config/ci-cd/performance-thresholds.json

# Reset baseline measurements
rm -rf .performance-baselines/
./scripts/ci-performance-validator.sh --reset-baselines baseline staging ./test-results

# Fix regression detection sensitivity
# Edit regression_detection.percentage_thresholds in thresholds config
```

### 5. Performance Optimization Issues

#### Issue: Optimization Script Failures

**Symptoms:**
- Performance optimizer crashes
- No improvement after optimization
- Configuration rollback failures

**Diagnosis:**
```bash
# Run optimizer with verbose logging
./scripts/performance-optimizer.sh --strategy balanced --environment staging --verbose

# Check current configuration backup
ls -la /tmp/performance-backups/

# Verify optimization targets
./scripts/bottleneck-analyzer.sh --environment staging --report-format json
```

**Solution:**
```bash
# Fix database optimization issues
# Check PostgreSQL connectivity and permissions
psql -h localhost -U postgres -d isectech -c "\l"

# Fix Redis optimization issues  
redis-cli ping
redis-cli info memory

# Rollback if optimization caused issues
./scripts/performance-optimizer.sh --rollback --backup-id LATEST

# Apply optimizations incrementally
./scripts/performance-optimizer.sh --strategy conservative --component database
./scripts/performance-optimizer.sh --strategy conservative --component cache
```

### 6. Network and Connectivity Issues

#### Issue: Network Timeouts and Connectivity Problems

**Symptoms:**
- Intermittent connection failures
- High latency in test results  
- DNS resolution errors

**Diagnosis:**
```bash
# Test network connectivity
ping api.isectech.com
traceroute api.isectech.com
curl -w "@curl-format.txt" -s -o /dev/null https://api.isectech.com/health

# Check Docker network
docker network ls
docker network inspect performance-testing_default

# Test from different locations
# Run tests from different machines/networks
```

**Solution:**
```bash
# Configure network timeouts
export K6_HTTP_TIMEOUT=60s
export ARTILLERY_HTTP_TIMEOUT=45s

# Use different DNS servers
echo "nameserver 8.8.8.8" > /etc/resolv.conf

# Configure Docker network for better performance
docker network create --driver bridge --opt com.docker.network.driver.mtu=9000 perf-network

# Use connection pooling
# Update k6 configuration for connection reuse
# Edit k6/config/config.js: http: { pool: 50 }
```

## 🔧 Maintenance Procedures

### Regular Health Checks

```bash
#!/bin/bash
# Daily health check script

echo "=== Performance Testing Framework Health Check ==="
echo "Date: $(date)"

# Check Docker services
echo "Docker Services Status:"
docker-compose -f performance-testing/docker/docker-compose.distributed.yml ps

# Check storage usage
echo "Storage Usage:"
df -h | grep -E "(influxdb|grafana|prometheus)"

# Check recent test results
echo "Recent Test Runs:"
find ./test-results -name "*.json" -mtime -1 | wc -l

# Check for alerts
echo "Active Alerts:"
curl -s http://localhost:9090/api/v1/alerts | jq '.data.alerts | length'

echo "Health check completed."
```

### Database Maintenance

```bash
# InfluxDB maintenance
docker exec performance-testing_influxdb_1 influx -execute "SHOW RETENTION POLICIES ON k6_metrics"

# Clean old data
docker exec performance-testing_influxdb_1 influx -execute "DROP RETENTION POLICY old_data ON k6_metrics"

# Compact database
docker exec performance-testing_influxdb_1 influx -execute "COMPACT"

# Backup critical data
docker exec performance-testing_influxdb_1 influxd backup -database k6_metrics /backup/
```

### Log Rotation

```bash
# Setup log rotation for performance test logs
cat > /etc/logrotate.d/performance-testing << EOF
/var/log/performance-testing/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    create 644 root root
    postrotate
        docker-compose -f /path/to/docker-compose.yml restart
    endscript
}
EOF
```

## 📞 Escalation Matrix

### Issue Severity Levels

#### P0 - Critical (Production Down)
- **Response Time**: Immediate
- **Escalation**: Page DevOps On-Call
- **Contacts**: PagerDuty, Slack #emergency
- **Actions**: Immediate rollback if performance-related

#### P1 - High (Performance Degradation)
- **Response Time**: 15 minutes
- **Escalation**: Performance Engineering Team
- **Contacts**: performance-team@isectech.com, Slack #performance-alerts
- **Actions**: Analysis and optimization within 1 hour

#### P2 - Medium (CI/CD Issues)
- **Response Time**: 2 hours
- **Escalation**: DevOps Team
- **Contacts**: devops@isectech.com
- **Actions**: Fix within business day

#### P3 - Low (Enhancement/Question)
- **Response Time**: Next business day
- **Escalation**: Backend Team
- **Contacts**: backend@isectech.com
- **Actions**: Schedule for next sprint

### Contact Information

- **Performance Engineering Lead**: performance-lead@isectech.com
- **DevOps Manager**: devops-manager@isectech.com  
- **Backend Team Lead**: backend-lead@isectech.com
- **Emergency Hotline**: +1-555-ISECTECH
- **Slack Channels**: #performance-alerts, #devops-alerts, #backend-support

## 📋 Troubleshooting Checklist

### Before Escalating

- [ ] Checked service health (`docker-compose ps`)
- [ ] Reviewed recent logs (last 1 hour)
- [ ] Confirmed network connectivity to target systems
- [ ] Verified configuration hasn't changed recently
- [ ] Attempted basic restart of affected services
- [ ] Checked disk space and system resources
- [ ] Reviewed Grafana dashboards for trends

### Information to Provide

When escalating issues, include:

- **Issue Description**: What is not working as expected?
- **Environment**: Development, staging, or production
- **Timeline**: When did the issue start?
- **Error Messages**: Specific error logs and messages
- **Steps to Reproduce**: How to recreate the issue
- **Impact Assessment**: Who/what is affected?
- **Attempted Solutions**: What has already been tried?

### Documentation Updates

After resolving issues:

1. Update this troubleshooting guide with new solutions
2. Add monitoring alerts to prevent recurrence  
3. Update runbooks with new procedures
4. Share learnings with the team
5. Consider automating the solution

---

**Remember**: When in doubt, don't hesitate to escalate. It's better to involve the team early than to let issues escalate to production outages.

**Emergency Contact**: For critical production issues affecting user experience, immediately contact DevOps On-Call via PagerDuty.