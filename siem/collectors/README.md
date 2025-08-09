# iSECTECH SIEM Agentless and Network Device Log Collection

## Overview

This directory contains the implementation of agentless log collection for the iSECTECH SIEM system. The implementation provides comprehensive security event collection from network devices, legacy systems, and infrastructure components without requiring agent installation.

## Architecture

### Collection Methods

1. **Syslog Collection** - Network device and application logs
2. **SNMP Monitoring** - Infrastructure metrics and security indicators  
3. **Network Flow Analysis** - NetFlow/sFlow/IPFIX traffic analysis
4. **WMI Collection** - Windows management instrumentation
5. **API Integration** - Cloud services and third-party systems

### Data Flow

```
Network Devices → Syslog/SNMP/Flow → Collectors → Kafka → Stream Processing → Elasticsearch → SIEM
```

## Components

### 1. Syslog Receiver (`syslog-receiver.conf`)

**Purpose**: High-performance syslog collection with device-specific parsing

**Key Features**:
- Multi-protocol support (UDP, TCP, TLS, RELP)
- Vendor-specific log parsing (Cisco, Palo Alto, Juniper, Fortinet, Check Point)
- Real-time risk scoring and geographic enrichment
- Kafka integration with high-availability configuration
- Advanced security analysis and threat detection

**Supported Devices**:
- **Cisco**: ASA, FTD, IOS switches and routers
- **Palo Alto**: PAN-OS firewalls and security platforms
- **Juniper**: SRX firewalls and EX switches
- **Fortinet**: FortiGate firewalls
- **Check Point**: Security gateways
- **Generic**: DHCP, DNS, and other network services

**Security Features**:
- Authentication event analysis
- Traffic flow inspection
- VPN connection monitoring
- Firewall rule violations
- Geographic risk assessment
- Time-based anomaly detection

### 2. SNMP Collector (`snmp-collector.py`)

**Purpose**: Comprehensive infrastructure monitoring with security focus

**Key Features**:
- High-performance async SNMP collection
- Vendor-specific OID definitions
- Real-time security alerting
- Prometheus metrics integration
- Redis caching for performance
- Multi-threaded collection architecture

**Monitored Metrics**:
- **Security Indicators**: Failed login attempts, port security violations, firewall blocks
- **Performance Metrics**: CPU utilization, memory usage, interface statistics
- **Environmental**: Temperature, power consumption, environmental sensors
- **Network Health**: Interface status, error rates, traffic patterns

**Vendor Support**:
- **Cisco**: Catalyst switches, ASA firewalls, ISR routers
- **Juniper**: EX switches, SRX firewalls, MX routers
- **Palo Alto**: PAN-OS security metrics
- **Generic**: Standard SNMP MIB-II metrics

### 3. Network Flow Collector (`network-flow-collector.go`)

**Purpose**: Real-time network traffic analysis and security monitoring

**Key Features**:
- Multi-protocol support (NetFlow v5/v9, sFlow, IPFIX)
- Real-time security analysis (DDoS, beaconing, port scanning)
- Geographic enrichment and threat intelligence
- High-performance Go implementation
- Kafka streaming with security alerts

**Detection Capabilities**:
- **DDoS Attacks**: Traffic volume and pattern analysis
- **Beaconing Activity**: Periodic communication detection
- **Port Scanning**: Sequential port access patterns
- **Data Exfiltration**: Unusual outbound traffic patterns
- **Lateral Movement**: Internal network traversal

**Security Analysis**:
```go
// Example security analysis
func (fc *FlowCollector) performSecurityAnalysis(record *FlowRecord) *SecurityAnalysis {
    analysis := &SecurityAnalysis{
        SecurityTags: []string{},
        AlertTypes:   []string{},
    }
    
    // DDoS detection
    if record.PacketCount > fc.config.Security.DDoSThreshold {
        analysis.SecurityTags = append(analysis.SecurityTags, "ddos_candidate")
        analysis.AlertTypes = append(analysis.AlertTypes, "ddos")
    }
    
    return analysis
}
```

### 4. Docker Deployment (`docker-compose.agentless.yml`)

**Purpose**: Production-ready containerized deployment

**Key Features**:
- Multi-service orchestration
- Network segmentation and security
- Health monitoring and auto-restart
- Resource limits and optimization
- TLS encryption and certificate management

**Services**:
- **syslog-receiver**: Rsyslog with custom configuration
- **snmp-collector**: Python-based SNMP monitoring
- **flow-collector**: Go-based network flow analysis
- **redis-cache**: High-performance caching layer
- **wmi-collector**: Windows management instrumentation
- **log-aggregator**: Fluent Bit for log forwarding
- **prometheus-exporter**: Metrics collection

### 5. Deployment Script (`deploy-agentless-collectors.sh`)

**Purpose**: Automated production deployment and management

**Key Features**:
- Multi-OS support and dependency management
- TLS certificate generation and management
- Configuration templating and customization
- Health monitoring and validation
- Rolling updates and rollback capabilities

**Deployment Options**:
```bash
# Basic deployment
./deploy-agentless-collectors.sh

# Production deployment with custom configuration
./deploy-agentless-collectors.sh \
  --mode production \
  --tenant-id isectech \
  --kafka "kafka-1.isectech.local:9092,kafka-2.isectech.local:9092" \
  --verbose

# Component-specific deployment
./deploy-agentless-collectors.sh \
  --components syslog-receiver,snmp-collector \
  --environment staging
```

## Installation and Configuration

### Prerequisites

- Docker and Docker Compose
- Root access for privileged ports (514, 161, 2055)
- Network connectivity to Kafka and Elasticsearch clusters
- TLS certificates for secure communication
- GeoIP database for geographic enrichment

### Quick Start

1. **Clone and Prepare**:
```bash
cd /opt/isectech-siem
git clone <repository> collectors
cd collectors
```

2. **Configure Environment**:
```bash
export DEPLOYMENT_MODE="production"
export TENANT_ID="isectech"
export KAFKA_ENDPOINTS="kafka-cluster:9092"
export ELASTICSEARCH_ENDPOINTS="es-cluster:9200"
```

3. **Deploy Services**:
```bash
sudo ./deploy-agentless-collectors.sh --verbose
```

4. **Verify Deployment**:
```bash
docker-compose -f docker-compose.agentless.yml ps
docker-compose -f docker-compose.agentless.yml logs -f
```

### Network Device Configuration

#### Cisco ASA/FTD Syslog Configuration
```
logging enable
logging timestamp
logging buffer-size 32768
logging host inside 10.0.1.100
logging trap informational
logging facility 16
```

#### Palo Alto PAN-OS Syslog Configuration
```
set deviceconfig system syslog-server syslog-server-1 server 10.0.1.100
set deviceconfig system syslog-server syslog-server-1 transport UDP
set deviceconfig system syslog-server syslog-server-1 port 514
set deviceconfig system syslog-server syslog-server-1 format BSD
set deviceconfig system syslog-server syslog-server-1 facility LOG_USER
```

#### Juniper SRX Syslog Configuration
```
set system syslog host 10.0.1.100 any any
set system syslog host 10.0.1.100 facility-override local7
set system syslog host 10.0.1.100 source-address 10.0.1.5
```

#### SNMP Configuration (Generic)
```
snmp-server community isectech_readonly RO
snmp-server host 10.0.1.100 version 2c isectech_readonly
snmp-server enable traps
```

## Security Features

### Real-Time Threat Detection

1. **Network Security Events**:
   - Firewall denies and permits analysis
   - VPN authentication monitoring
   - Intrusion prevention system alerts
   - DNS security events

2. **Infrastructure Security**:
   - Failed authentication attempts
   - Port security violations
   - Spanning tree topology changes
   - Environmental anomalies

3. **Traffic Analysis**:
   - DDoS attack detection
   - Lateral movement patterns
   - Data exfiltration indicators
   - Command and control communication

### Risk Scoring Algorithm

The collectors implement a sophisticated risk scoring system:

```python
# Risk scoring example from syslog parsing
def calculate_risk_score(event):
    base_score = EVENT_BASE_SCORES.get(event.type, 1)
    
    # Geographic risk multiplier
    if event.source_country in HIGH_RISK_COUNTRIES:
        base_score *= 2.0
    
    # Time-based risk
    if is_off_hours(event.timestamp):
        base_score *= 1.5
    
    # Asset criticality
    if event.asset_criticality == "critical":
        base_score *= 2.0
    
    return min(base_score, 10)  # Cap at maximum risk
```

### Data Enrichment

1. **Geographic Enrichment**:
   - GeoIP lookup for source IP addresses
   - Country-based risk assessment
   - ISP and organization identification

2. **Asset Context**:
   - Device inventory correlation
   - Business unit and criticality mapping
   - Owner and contact information

3. **Threat Intelligence**:
   - IOC matching against threat feeds
   - Reputation scoring for IP addresses
   - Malware family identification

## Monitoring and Maintenance

### Health Monitoring

The deployment includes comprehensive health monitoring:

```bash
# Service status
docker-compose -f docker-compose.agentless.yml ps

# Service logs
docker-compose -f docker-compose.agentless.yml logs -f [service-name]

# Metrics endpoints
curl http://localhost:9161/metrics  # SNMP collector
curl http://localhost:9162/metrics  # Flow collector
curl http://localhost:9101/metrics  # Syslog receiver
```

### Performance Metrics

**Key Performance Indicators**:
- Events per second processed
- Processing latency (95th percentile)
- Buffer utilization and backpressure
- Network throughput and packet loss
- Error rates and retry counts

**Prometheus Metrics**:
```
# SNMP collector metrics
snmp_collections_total{device="firewall-01", status="success"} 1500
snmp_collection_duration_seconds{device="firewall-01"} 0.25
snmp_security_alerts_total{device="firewall-01", alert_type="failed_logins"} 5

# Flow collector metrics
flow_records_processed_total{protocol="netflow_v9"} 50000
flow_security_alerts_total{alert_type="ddos"} 3
flow_processing_duration_seconds 0.001
```

### Maintenance Tasks

1. **Certificate Management**:
   - Automatic certificate renewal (Let's Encrypt integration)
   - Key rotation procedures
   - Trust store updates

2. **Configuration Management**:
   - Rolling updates for configuration changes
   - Version control integration (Git hooks)
   - Change auditing and approval workflows

3. **Performance Optimization**:
   - Buffer sizing and memory tuning
   - Network optimization and connection pooling
   - Disk I/O optimization

## Troubleshooting

### Common Issues

1. **No Logs Received**:
```bash
# Check network connectivity
nc -u 10.0.1.100 514

# Verify firewall rules
iptables -L | grep 514

# Check service logs
docker logs isectech-syslog-receiver
```

2. **High Memory Usage**:
```bash
# Monitor resource usage
docker stats

# Adjust buffer sizes in configuration
# Edit syslog-receiver.conf or docker-compose.yml
# Restart services
docker-compose restart
```

3. **SNMP Collection Failures**:
```bash
# Test SNMP connectivity
snmpwalk -v2c -c isectech_readonly 10.0.1.10 1.3.6.1.2.1.1.1.0

# Check collector logs
docker logs isectech-snmp-collector

# Verify device configuration
# Ensure SNMP community strings match
```

### Log Analysis

**Important Log Locations**:
- Syslog receiver: `/var/log/siem/syslog-receiver.log`
- SNMP collector: `/var/log/siem/snmp-collector.log`
- Flow collector: `/var/log/siem/flow-collector.log`
- Container logs: `docker logs <container-name>`

**Debug Mode**:
```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
docker-compose restart

# Monitor debug output
docker-compose logs -f --tail=100
```

## Performance Tuning

### High-Volume Environments

1. **Buffer Optimization**:
   - Increase rsyslog buffer sizes for high syslog volume
   - Tune Kafka producer batch settings
   - Optimize Redis memory allocation

2. **Network Optimization**:
   - Enable compression for network transport
   - Adjust TCP window sizes
   - Configure connection pooling

3. **Resource Scaling**:
   - Scale collector containers horizontally
   - Increase CPU and memory allocation
   - Use SSD storage for high I/O workloads

### Scaling Considerations

**Horizontal Scaling**:
```bash
# Scale SNMP collector instances
docker-compose up -d --scale snmp-collector=3

# Load balance with multiple syslog receivers
# Configure round-robin DNS or load balancer
```

**Vertical Scaling**:
```yaml
# Increase resource limits in docker-compose.yml
services:
  snmp-collector:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

## Security Considerations

### Network Security

1. **Access Control**:
   - Firewall rules for collector ports
   - Network segmentation for management traffic
   - VPN access for remote administration

2. **Encryption**:
   - TLS for all external communications
   - Certificate-based authentication
   - Encrypted storage for sensitive data

3. **Monitoring**:
   - Collector security event monitoring
   - Anomaly detection for collector behavior
   - Regular security assessments

### Compliance

The agentless collection implementation supports:
- **SOC 2 Type II**: Comprehensive audit logging and controls
- **PCI DSS**: Network security monitoring for payment environments
- **NIST Cybersecurity Framework**: Security control implementation
- **GDPR**: Data privacy and protection measures

## Integration

### SIEM Platform Integration

The collectors integrate with the broader iSECTECH SIEM platform:

1. **Stream Processing Integration**:
   - Real-time event correlation engine
   - Advanced analytics and machine learning
   - Threat intelligence enrichment

2. **Alerting Integration**:
   - Real-time alert generation and escalation
   - Integration with SOAR platforms
   - Notification channels (email, Slack, SMS)

3. **Investigation Integration**:
   - Event search and analysis capabilities
   - Timeline reconstruction and forensics
   - Case management integration

### Third-Party Integration

**Supported Integrations**:
- **Threat Intelligence**: Commercial and open-source feeds
- **SOAR Platforms**: Automated response and orchestration
- **Ticketing Systems**: Incident management integration
- **Communication**: Slack, Microsoft Teams, email notifications

## Support and Documentation

### Additional Resources

- [Rsyslog Documentation](https://www.rsyslog.com/doc/master/)
- [SNMP Protocol Reference](https://tools.ietf.org/html/rfc1157)
- [NetFlow Protocol Specification](https://tools.ietf.org/html/rfc3954)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Contact Information

For support and questions:
- Email: siem-support@isectech.com
- Documentation: https://docs.isectech.com/siem/agentless
- Issues: https://github.com/isectech/siem-agentless/issues

---

**Note**: This implementation provides production-ready agentless security log collection capabilities. Regular maintenance, monitoring, and updates are essential for optimal performance and security.