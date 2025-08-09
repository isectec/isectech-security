# iSECTECH SIEM Agent-Based Log Collection

## Overview

This directory contains the implementation of agent-based log collection for the iSECTECH SIEM system. The implementation provides comprehensive security event collection from endpoints, servers, and containers using industry-standard agents and custom configurations optimized for security monitoring.

## Architecture

### Components

1. **Vector Agent** - High-performance data collection and routing
2. **Filebeat Agent** - Elastic Beat for file-based log collection
3. **Auditd** - Linux kernel audit framework for system call monitoring
4. **Osquery** - SQL-based operating system instrumentation framework
5. **Kubernetes Agents** - Container and orchestration platform monitoring

### Data Flow

```
Endpoints/Servers → Agents → Kafka → Stream Processing → Elasticsearch → SIEM
```

## Agent Configurations

### 1. Vector Agent (`vector-agent-config.toml`)

**Purpose**: High-performance log collection with real-time processing and enrichment

**Key Features**:
- Multi-source data collection (files, journald, Windows Event Log, network)
- Real-time security event parsing and risk scoring
- GeoIP enrichment and threat intelligence correlation
- Asset inventory integration
- Kafka and Elasticsearch output with backup mechanisms

**Supported Data Sources**:
- System security logs (`/var/log/auth.log`, `/var/log/secure`)
- Application logs with JSON parsing
- Windows Event Logs (Security, System)
- Network connections and process monitoring
- Container logs with Docker metadata

**Security Features**:
- Real-time risk scoring algorithm
- Authentication event detection
- Privilege escalation monitoring
- Command execution tracking
- Geographic risk assessment

### 2. Filebeat Security Configuration (`filebeat-security.yml`)

**Purpose**: Comprehensive file-based log collection with security-focused parsing

**Key Features**:
- Security-specific input configurations
- Advanced JavaScript processors for threat detection
- Module-based collection for common services
- Kubernetes auto-discovery
- Performance optimization for high-volume environments

**Monitored Log Types**:
- Linux security logs (auth, audit, sudo, kern)
- Web server logs (Nginx, Apache) with attack pattern detection
- Database logs (PostgreSQL, MySQL, MongoDB, Redis)
- Container logs with Kubernetes metadata
- Network security logs via syslog

**Detection Capabilities**:
- SQL injection pattern detection
- XSS and CSRF attack identification
- Path traversal and command injection
- DDoS and port scanning detection
- Database authentication failures

### 3. Kubernetes Deployment (`k8s-security-agents-deployment.yaml`)

**Purpose**: Container-native deployment for Kubernetes environments

**Key Features**:
- DaemonSet deployment ensuring agent presence on all nodes
- RBAC configuration for secure cluster access
- Resource limits and security contexts
- Service monitoring and network policies
- Automatic certificate management

**Security Controls**:
- Minimal privileged access with capability restrictions
- Read-only root filesystems where possible
- Network policies for traffic isolation
- Pod disruption budgets for availability
- Security context constraints

### 4. Deployment Script (`deploy-security-agents.sh`)

**Purpose**: Automated, production-ready agent deployment

**Key Features**:
- Multi-OS support (Ubuntu, Debian, RHEL, CentOS, Fedora)
- Dependency management and validation
- TLS certificate generation
- Service configuration and startup
- Health monitoring setup

**Deployment Options**:
- Production, staging, and development modes
- Selective component installation
- Configuration customization
- Validation and testing

## Installation

### Prerequisites

- Root access on target systems
- Network connectivity to Kafka and Elasticsearch clusters
- Supported operating system (Linux-based)
- Minimum 1GB RAM and 10GB disk space

### Quick Start

```bash
# Basic installation
sudo ./deploy-security-agents.sh

# Production deployment with custom configuration
sudo ./deploy-security-agents.sh \
  --mode production \
  --tenant-id isectech \
  --kafka "kafka-1.isectech.local:9092,kafka-2.isectech.local:9092" \
  --verbose

# Kubernetes deployment
kubectl apply -f k8s-security-agents-deployment.yaml
```

### Configuration Options

#### Environment Variables

```bash
export DEPLOYMENT_MODE="production"
export TENANT_ID="isectech"
export KAFKA_ENDPOINTS="kafka-cluster:9092"
export ELASTICSEARCH_ENDPOINTS="es-cluster:9200"
export ENVIRONMENT="production"
```

#### Agent-Specific Configuration

**Vector Configuration**:
- Modify `vector-agent-config.toml` for custom sources and transformations
- Adjust buffer sizes and performance settings
- Configure custom risk scoring algorithms

**Filebeat Configuration**:
- Update `filebeat-security.yml` for additional log paths
- Customize JavaScript processors for specific threat patterns
- Configure module settings for supported services

## Security Features

### Real-Time Threat Detection

1. **Authentication Monitoring**
   - Failed login attempts with source IP tracking
   - Privilege escalation detection
   - Unusual authentication patterns

2. **System Activity Monitoring**
   - Process execution with command line analysis
   - File access patterns for sensitive files
   - Network connection monitoring

3. **Application Security**
   - Web attack pattern detection (SQL injection, XSS, CSRF)
   - Database security event monitoring
   - Container escape attempt detection

### Risk Scoring Algorithm

The agents implement a sophisticated risk scoring system:

```javascript
// Base risk scores by event type
authentication_failure: 3
privilege_escalation: 7
data_exfiltration: 9
malware_detection: 8

// Risk multipliers
asset_criticality: 1.0-2.0
geographic_origin: 1.0-2.0
time_of_day: 1.0-1.5
threat_intelligence: 0.5-3.0
```

### Data Enrichment

1. **Geographic Enrichment**
   - GeoIP lookup for source IP addresses
   - Country-based risk assessment
   - ISP and organization identification

2. **Asset Context**
   - Asset inventory correlation
   - Business unit and criticality mapping
   - Owner and contact information

3. **Threat Intelligence**
   - IOC matching against threat feeds
   - Reputation scoring for IP addresses
   - Malware family identification

## Monitoring and Maintenance

### Health Checks

The deployment includes automated health monitoring:

```bash
# Manual health check
/opt/isectech-siem-agents/check-agents.sh

# Service status
systemctl status vector-agent filebeat-agent auditd osqueryd

# Log monitoring
tail -f /var/log/isectech-siem-agents/*.log
```

### Performance Monitoring

**Key Metrics**:
- Events per second processed
- Processing latency (95th percentile)
- Buffer utilization
- Network throughput
- Disk I/O patterns

**Prometheus Metrics Endpoints**:
- Vector: `http://localhost:9598/metrics`
- Filebeat: `http://localhost:5066/stats`

### Maintenance Tasks

1. **Log Rotation**
   - Automatic rotation based on size and age
   - Compression for historical logs
   - Retention policy enforcement

2. **Certificate Management**
   - Automatic certificate renewal
   - Key rotation procedures
   - Trust store updates

3. **Configuration Updates**
   - Rolling updates for configuration changes
   - Version control integration
   - Change auditing

## Troubleshooting

### Common Issues

1. **Agent Not Starting**
   ```bash
   # Check service status
   systemctl status vector-agent
   
   # Review logs
   journalctl -u vector-agent -f
   
   # Validate configuration
   /opt/isectech-siem-agents/vector --config /etc/isectech-siem-agents/vector/vector.toml --dry-run
   ```

2. **No Data in SIEM**
   ```bash
   # Verify network connectivity
   telnet kafka-cluster 9092
   
   # Check agent metrics
   curl -s http://localhost:9598/metrics | grep events
   
   # Validate log file permissions
   ls -la /var/log/auth.log
   ```

3. **High Resource Usage**
   ```bash
   # Monitor resource consumption
   top -p $(pgrep vector)
   
   # Adjust buffer sizes
   # Edit vector-agent-config.toml
   # Restart service
   systemctl restart vector-agent
   ```

### Log Analysis

**Important Log Locations**:
- Agent logs: `/var/log/isectech-siem-agents/`
- System logs: `/var/log/audit/audit.log`
- Service logs: `journalctl -u vector-agent`

**Debug Mode**:
```bash
# Enable verbose logging
export VECTOR_LOG=debug
systemctl restart vector-agent

# Monitor debug output
tail -f /var/log/isectech-siem-agents/vector.log
```

## Performance Tuning

### Optimization Guidelines

1. **Buffer Sizing**
   - Increase buffer sizes for high-volume environments
   - Balance memory usage vs. throughput
   - Monitor buffer utilization metrics

2. **Network Optimization**
   - Enable compression for network transport
   - Adjust batch sizes for optimal throughput
   - Configure connection pooling

3. **Disk I/O Optimization**
   - Use separate disks for logs and data
   - Configure appropriate filesystem (ext4, xfs)
   - Enable disk read-ahead optimization

### Scaling Considerations

**Horizontal Scaling**:
- Deploy additional agents on high-volume systems
- Use load balancing for Kafka producers
- Implement agent failover mechanisms

**Vertical Scaling**:
- Increase agent memory allocation
- Add CPU cores for processing-intensive workloads
- Optimize disk performance with SSDs

## Security Considerations

### Agent Security

1. **Access Control**
   - Run agents with minimal required privileges
   - Implement capability-based security
   - Regular security updates and patching

2. **Network Security**
   - Use TLS for all network communications
   - Implement certificate-based authentication
   - Network segmentation for agent traffic

3. **Data Protection**
   - Encrypt sensitive data in transit and at rest
   - Implement data loss prevention controls
   - Regular security assessments

### Compliance

The agent implementation supports compliance with:
- **SOC 2 Type II**: Comprehensive audit logging
- **PCI DSS**: Payment card data security requirements
- **GDPR**: Data privacy and protection regulations
- **NIST Cybersecurity Framework**: Security control implementation

## Integration

### SIEM Integration

The agents integrate seamlessly with the broader iSECTECH SIEM platform:

1. **Stream Processing Integration**
   - Real-time event correlation
   - Advanced analytics and ML
   - Threat intelligence enrichment

2. **Alerting Integration**
   - Real-time alert generation
   - Escalation workflows
   - Notification channels

3. **Investigation Integration**
   - Event search and analysis
   - Timeline reconstruction
   - Forensic capabilities

### Third-Party Integration

**Supported Integrations**:
- **SOAR Platforms**: Automated response and orchestration
- **Ticketing Systems**: Incident management integration
- **Communication Platforms**: Slack, Microsoft Teams, email
- **Threat Intelligence**: Commercial and open-source feeds

## Support and Documentation

### Additional Resources

- [Vector Documentation](https://vector.dev/docs/)
- [Filebeat Reference](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Auditd Manual](https://linux.die.net/man/8/auditd)
- [Osquery Documentation](https://osquery.readthedocs.io/)

### Contact Information

For support and questions:
- Email: siem-support@isectech.com
- Documentation: https://docs.isectech.com/siem/agents
- Issues: https://github.com/isectech/siem-agents/issues

---

**Note**: This implementation provides production-ready security log collection capabilities. Regular maintenance, monitoring, and updates are essential for optimal performance and security.