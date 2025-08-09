# iSECTECH SIEM Cloud Service Log Integration

## Overview

This directory contains the implementation of cloud service log integration for the iSECTECH SIEM system. The implementation provides comprehensive security event collection from AWS, Azure, and Google Cloud Platform through their native APIs and security services.

## Architecture

### Integration Methods

1. **AWS CloudTrail Integration** - AWS API calls and security events
2. **Azure Activity Log Integration** - Azure resource and authentication events  
3. **GCP Audit Log Integration** - Google Cloud API audit trails
4. **Multi-Cloud Event Correlation** - Cross-cloud security analysis
5. **Real-Time Stream Processing** - Kafka-based event streaming

### Data Flow

```
Cloud APIs → Collectors → Kafka → Stream Processing → Elasticsearch → SIEM
     ↓
Security Centers → GuardDuty/Security Center/Security Command Center → Alerts
```

## Components

### 1. AWS CloudTrail Collector (`aws-cloudtrail-collector.py`)

**Purpose**: Comprehensive AWS security event collection with advanced threat detection

**Key Features**:
- CloudTrail log collection from S3 buckets
- GuardDuty findings integration
- AWS Config compliance monitoring
- Real-time security analysis and risk scoring
- Multi-account support with role assumption
- Kafka streaming with high-availability configuration

**Supported AWS Services**:
- **CloudTrail**: Management and data events across all services
- **GuardDuty**: Threat detection and security findings
- **Config**: Configuration compliance monitoring
- **VPC Flow Logs**: Network traffic analysis (planned)
- **CloudWatch**: Security metrics and alarms

**Security Analysis Features**:
- Authentication event analysis (console logins, role assumptions)
- High-risk IAM operations (privilege escalation detection)
- Resource deletion and modification tracking
- Geographic anomaly detection
- Time-based security analysis
- Compliance violation detection (SOC 2, PCI DSS, HIPAA)

**Risk Scoring Algorithm**:
```python
# Example from aws-cloudtrail-collector.py:425-641
def _analyze_event_security(self, event: CloudTrailEvent, account: AWSAccount):
    # Base risk score from event type
    event.risk_score = HIGH_RISK_EVENTS.get(event.event_name, 1)
    
    # Geographic risk assessment
    if self._is_geographic_anomaly(event.source_ip_address, account):
        event.risk_score += 2
        event.threat_indicators.append("geographic_anomaly")
    
    # Time-based risk (off-hours activity)
    if self._is_off_hours_activity(event.event_time):
        event.risk_score += 1
        event.threat_indicators.append("off_hours_activity")
```

### 2. Azure Activity Collector (`azure-activity-collector.py`)

**Purpose**: Comprehensive Azure security event collection with identity-focused analysis

**Key Features**:
- Azure Activity Log collection via Monitor API
- Azure Security Center alerts integration
- Azure AD sign-in log analysis
- Multi-subscription support
- Advanced authentication analysis
- Real-time threat detection

**Supported Azure Services**:
- **Activity Logs**: Resource management and administrative operations
- **Security Center**: Security alerts and recommendations
- **Azure AD**: Authentication and identity events
- **Log Analytics**: Query-based data collection
- **Azure Monitor**: Metrics and diagnostic data

**Security Features**:
- Identity and access management monitoring
- Resource configuration change tracking
- Network security group modification detection
- Key Vault access monitoring
- Risky sign-in detection
- Privilege escalation analysis

**Authentication Security Analysis**:
```python
# Example from azure-activity-collector.py:841-873
def _analyze_signin_security(self, event: AzureActivityEvent, signin_data: Dict[str, Any]):
    # Check for risky sign-ins
    risk_level = signin_data.get('riskLevelAggregated', '')
    if risk_level in ['high', 'medium']:
        event.risk_score += 4 if risk_level == 'high' else 2
        event.threat_indicators.append(f"risky_signin_{risk_level}")
    
    # Check for legacy authentication
    client_app = signin_data.get('clientAppUsed', '')
    if client_app in ['Exchange ActiveSync', 'Other clients', 'IMAP', 'POP']:
        event.risk_score += 2
        event.threat_indicators.append("legacy_authentication")
```

### 3. GCP Audit Collector (`gcp-audit-collector.py`)

**Purpose**: Comprehensive Google Cloud security event collection with API-focused monitoring

**Key Features**:
- Cloud Audit Log collection via Logging API
- Security Command Center findings integration
- Cloud Asset inventory monitoring
- Service account activity tracking
- IAM policy change detection
- Real-time security analysis

**Supported GCP Services**:
- **Cloud Audit Logs**: API calls and administrative operations
- **Security Command Center**: Security findings and vulnerabilities
- **Cloud Asset Inventory**: Resource configuration tracking
- **Cloud Monitoring**: Performance and security metrics
- **Cloud Identity**: Authentication and access management

**Security Features**:
- IAM privilege escalation detection
- Resource deletion and configuration changes
- Service account key management monitoring
- Cloud KMS key operations tracking
- Firewall rule modification detection
- Compliance policy violation analysis

**IAM Security Analysis**:
```python
# Example from gcp-audit-collector.py:633-653
def _is_privilege_escalation(self, event: GCPAuditEvent) -> bool:
    escalation_methods = [
        "google.iam.admin.v1.IAM.SetIamPolicy",
        "google.iam.admin.v1.IAM.CreateRole",
        "google.cloud.resourcemanager.v1.Organizations.SetIamPolicy"
    ]
    
    if event.method_name in escalation_methods:
        # Check if granting high-privilege roles
        request = event.request
        if isinstance(request, dict) and 'policy' in request:
            policy = request['policy']
            for binding in policy.get('bindings', []):
                role = binding.get('role', '')
                if any(privilege in role for privilege in ["owner", "editor", "admin"]):
                    return True
```

### 4. Docker Deployment (`docker-compose.cloud-integrations.yml`)

**Purpose**: Production-ready containerized deployment for cloud integrations

**Key Features**:
- Multi-service orchestration for all three cloud providers
- Network segmentation and security hardening
- Health monitoring and auto-restart capabilities
- Resource limits and performance optimization
- Prometheus metrics integration
- TLS encryption and certificate management

**Services**:
- **aws-collector**: AWS CloudTrail and GuardDuty integration
- **azure-collector**: Azure Activity Log and Security Center integration
- **gcp-collector**: GCP Audit Log and Security Command Center integration
- **redis-cache**: High-performance caching layer for correlation
- **cloud-api-gateway**: Unified API interface for cloud integrations
- **prometheus-exporter**: Metrics collection and monitoring

**Security Configuration**:
```yaml
# Example security hardening from docker-compose
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp:noexec,nosuid,size=512m
```

## Installation and Configuration

### Prerequisites

- Docker and Docker Compose
- Cloud provider credentials and API access
- Network connectivity to cloud APIs
- Kafka and Redis infrastructure
- TLS certificates for secure communication

### Cloud Provider Setup

#### AWS Configuration

1. **IAM Role Setup**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "s3:GetObject",
        "s3:ListBucket",
        "guardduty:GetFindings",
        "guardduty:ListFindings",
        "config:DescribeComplianceByConfigRule"
      ],
      "Resource": "*"
    }
  ]
}
```

2. **CloudTrail Configuration**:
```bash
aws cloudtrail create-trail \
  --name isectech-security-trail \
  --s3-bucket-name isectech-cloudtrail-logs \
  --include-global-service-events \
  --is-multi-region-trail \
  --enable-log-file-validation
```

3. **GuardDuty Setup**:
```bash
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES
```

#### Azure Configuration

1. **Service Principal Creation**:
```bash
az ad sp create-for-rbac \
  --name "isectech-siem-collector" \
  --role "Security Reader" \
  --scopes "/subscriptions/{subscription-id}"
```

2. **Activity Log Export**:
```bash
az monitor diagnostic-settings create \
  --name "isectech-siem-export" \
  --resource "/subscriptions/{subscription-id}" \
  --logs '[{"category": "Administrative", "enabled": true}]' \
  --workspace "/subscriptions/{subscription-id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
```

3. **Security Center Configuration**:
```bash
az security pricing create \
  --name "VirtualMachines" \
  --tier "Standard"
```

#### GCP Configuration

1. **Service Account Setup**:
```bash
gcloud iam service-accounts create isectech-siem-collector \
  --display-name="iSECTECH SIEM Collector"

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:isectech-siem-collector@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.viewer"
```

2. **Audit Log Configuration**:
```bash
gcloud logging sinks create isectech-siem-audit \
  pubsub.googleapis.com/projects/PROJECT_ID/topics/audit-logs \
  --log-filter='protoPayload.serviceName!="" AND protoPayload.methodName!=""'
```

3. **Security Command Center Setup**:
```bash
gcloud scc sources list --organization=ORGANIZATION_ID
```

### Quick Start

1. **Clone and Prepare**:
```bash
cd /opt/isectech-siem
git clone <repository> cloud-integrations
cd cloud-integrations
```

2. **Configure Environment**:
```bash
export AWS_ACCESS_KEY_ID="your_aws_key"
export AWS_SECRET_ACCESS_KEY="your_aws_secret"
export AZURE_CLIENT_ID="your_azure_client_id"
export AZURE_CLIENT_SECRET="your_azure_secret"
export AZURE_TENANT_ID="your_azure_tenant_id"
```

3. **Deploy Services**:
```bash
sudo docker-compose -f docker-compose.cloud-integrations.yml up -d
```

4. **Verify Deployment**:
```bash
docker-compose -f docker-compose.cloud-integrations.yml ps
docker-compose -f docker-compose.cloud-integrations.yml logs -f
```

## Security Features

### Multi-Cloud Threat Detection

1. **Cross-Cloud Correlation**:
   - Identity mapping across cloud providers
   - Synchronized attack pattern detection
   - Multi-cloud privilege escalation analysis
   - Coordinated resource access monitoring

2. **Advanced Analytics**:
   - Machine learning-based anomaly detection
   - Behavioral analysis across cloud environments
   - Threat intelligence integration
   - Real-time risk scoring

3. **Compliance Monitoring**:
   - SOC 2 Type II compliance tracking
   - PCI DSS cloud security monitoring
   - GDPR data protection compliance
   - NIST Cybersecurity Framework alignment

### Real-Time Security Analysis

**Risk Scoring System**:
The collectors implement a sophisticated multi-factor risk scoring algorithm:

```python
# Unified risk scoring across all cloud providers
def calculate_unified_risk_score(event):
    base_score = get_base_risk_score(event.operation)
    
    # Geographic risk multiplier
    if is_high_risk_geography(event.source_ip):
        base_score *= 2.0
    
    # Time-based risk
    if is_off_hours(event.timestamp):
        base_score *= 1.5
    
    # Service criticality
    if is_critical_service(event.service):
        base_score *= 2.0
    
    # Cross-cloud correlation
    if has_correlated_activity(event):
        base_score *= 1.8
    
    return min(base_score, 10)  # Cap at maximum risk
```

**Threat Indicators**:
- **Authentication Anomalies**: Unusual login patterns, failed authentications, privilege escalations
- **Resource Modifications**: Unauthorized changes to critical resources, security policy modifications
- **Data Access Patterns**: Unusual data access, bulk downloads, cross-region transfers
- **Infrastructure Changes**: Network security modifications, encryption setting changes

### Data Enrichment

1. **Identity Context**:
   - User and service account mapping
   - Role and permission analysis
   - Authentication method tracking
   - Session correlation across clouds

2. **Geographic Analysis**:
   - GeoIP lookup for source IP addresses
   - Country-based risk assessment
   - VPN and proxy detection
   - Geofencing violation alerts

3. **Threat Intelligence Integration**:
   - IOC matching against threat feeds
   - IP reputation scoring
   - Malware family identification
   - APT group attribution

## Monitoring and Maintenance

### Performance Metrics

**Key Performance Indicators**:
- Events per second processed per cloud provider
- API call latency (95th percentile)
- Processing queue depth and backpressure
- Error rates and retry counts
- Data enrichment success rates

**Prometheus Metrics**:
```
# AWS collector metrics
aws_events_total{account="prod-main", service="iam", event_name="AssumeRole"} 1500
aws_security_alerts_total{account="prod-main", alert_type="privilege_escalation"} 5
aws_collection_duration_seconds{account="prod-main", service="cloudtrail"} 0.35

# Azure collector metrics
azure_events_total{subscription="prod-main", resource_provider="Microsoft.Authorization", operation="roleAssignments/write"} 50
azure_security_alerts_total{subscription="prod-main", alert_type="risky_signin"} 12

# GCP collector metrics
gcp_events_total{project="isectech-prod", service="iam", method="SetIamPolicy"} 25
gcp_security_alerts_total{project="isectech-prod", alert_type="service_account_privileged_operation"} 8
```

### Health Monitoring

The deployment includes comprehensive health monitoring:

```bash
# Service status
docker-compose -f docker-compose.cloud-integrations.yml ps

# Service logs
docker-compose -f docker-compose.cloud-integrations.yml logs -f [service-name]

# Metrics endpoints
curl http://localhost:9164/metrics  # AWS collector
curl http://localhost:9165/metrics  # Azure collector  
curl http://localhost:9166/metrics  # GCP collector
curl http://localhost:8080/health   # API Gateway
```

### Maintenance Tasks

1. **Credential Management**:
   - Automatic credential rotation
   - Key expiration monitoring
   - Multi-factor authentication enforcement
   - Regular access review and cleanup

2. **Configuration Management**:
   - Rolling updates for configuration changes
   - Version control integration (Git hooks)
   - Change auditing and approval workflows
   - Automated testing of configuration changes

3. **Performance Optimization**:
   - API rate limiting and throttling
   - Connection pooling and caching
   - Batch processing optimization
   - Memory and resource tuning

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
```bash
# Check AWS credentials
aws sts get-caller-identity

# Test Azure authentication
az account show

# Verify GCP service account
gcloud auth list
```

2. **API Rate Limiting**:
```bash
# Monitor API usage
docker logs isectech-aws-collector | grep "rate limit"

# Adjust collection intervals
# Edit configuration files and restart services
docker-compose restart aws-collector
```

3. **Missing Events**:
```bash
# Check cloud service configurations
aws cloudtrail describe-trails
az monitor diagnostic-settings list
gcloud logging sinks list

# Verify collector connectivity
docker exec isectech-aws-collector python3 -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

### Debug Mode

**Enable verbose logging**:
```bash
# Set debug environment variables
export LOG_LEVEL=DEBUG
docker-compose restart

# Monitor debug output
docker-compose logs -f --tail=100
```

**Test cloud connectivity**:
```bash
# AWS connectivity test
docker exec isectech-aws-collector python3 -c "
import boto3
try:
    client = boto3.client('cloudtrail')
    trails = client.describe_trails()
    print(f'Found {len(trails[\"trailList\"])} CloudTrail trails')
except Exception as e:
    print(f'AWS API error: {e}')
"

# Azure connectivity test
docker exec isectech-azure-collector python3 -c "
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
try:
    credential = ClientSecretCredential(tenant_id='...', client_id='...', client_secret='...')
    monitor_client = MonitorManagementClient(credential, subscription_id='...')
    print('Azure API connection successful')
except Exception as e:
    print(f'Azure API error: {e}')
"

# GCP connectivity test
docker exec isectech-gcp-collector python3 -c "
from google.cloud import logging
try:
    client = logging.Client()
    print('GCP API connection successful')
except Exception as e:
    print(f'GCP API error: {e}')
"
```

## Performance Tuning

### High-Volume Environments

1. **API Optimization**:
   - Implement intelligent polling intervals
   - Use delta queries where supported
   - Enable compression for API responses
   - Implement exponential backoff for retries

2. **Data Processing**:
   - Batch event processing for efficiency
   - Parallel processing for multiple accounts/subscriptions/projects
   - Optimize JSON parsing and serialization
   - Implement caching for repetitive operations

3. **Resource Scaling**:
   - Horizontal scaling of collector instances
   - Load balancing across multiple collectors
   - Database connection pooling
   - Memory optimization for large payloads

### Scaling Considerations

**Horizontal Scaling**:
```bash
# Scale collector instances
docker-compose up -d --scale aws-collector=3 --scale azure-collector=2

# Load balance with multiple API gateways
# Configure round-robin DNS or load balancer
```

**Vertical Scaling**:
```yaml
# Increase resource limits in docker-compose.yml
services:
  aws-collector:
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
   - Firewall rules for API endpoints
   - Network segmentation for cloud traffic
   - VPN access for remote administration
   - Zero-trust network architecture

2. **Encryption**:
   - TLS 1.3 for all external communications
   - Certificate-based authentication
   - Encrypted storage for sensitive configuration
   - End-to-end encryption for event streams

3. **Monitoring**:
   - Collector security event monitoring
   - Anomaly detection for collector behavior
   - Regular security assessments and penetration testing
   - Continuous compliance monitoring

### Compliance

The cloud integration implementation supports:
- **SOC 2 Type II**: Comprehensive audit logging and security controls
- **PCI DSS**: Payment card industry security monitoring
- **NIST Cybersecurity Framework**: Identify, protect, detect, respond, recover
- **GDPR**: Data privacy and protection measures
- **HIPAA**: Healthcare data security compliance

## Integration

### SIEM Platform Integration

The cloud collectors integrate with the broader iSECTECH SIEM platform:

1. **Stream Processing Integration**:
   - Real-time event correlation across cloud providers
   - Advanced analytics and machine learning
   - Threat intelligence enrichment and IOC matching
   - Behavioral analysis and anomaly detection

2. **Alerting Integration**:
   - Real-time alert generation and escalation
   - Integration with SOAR platforms
   - Multi-channel notifications (email, Slack, SMS, webhooks)
   - Alert prioritization and de-duplication

3. **Investigation Integration**:
   - Cross-cloud event search and analysis
   - Timeline reconstruction and forensic analysis
   - Case management integration
   - Evidence collection and chain of custody

### Third-Party Integration

**Supported Integrations**:
- **Threat Intelligence**: Commercial and open-source feeds (MISP, ThreatConnect, etc.)
- **SOAR Platforms**: Phantom, Demisto, TheHive automated response
- **Ticketing Systems**: Jira, ServiceNow, PagerDuty incident management
- **Communication**: Slack, Microsoft Teams, email notifications
- **Security Tools**: Splunk, QRadar, ArcSight SIEM integration

## API Reference

### Cloud API Gateway Endpoints

**Health and Status**:
- `GET /health` - Service health check
- `GET /status` - Detailed service status
- `GET /metrics` - Prometheus metrics

**Configuration Management**:
- `GET /config/aws` - AWS collector configuration
- `PUT /config/aws` - Update AWS collector configuration
- `GET /config/azure` - Azure collector configuration  
- `PUT /config/azure` - Update Azure collector configuration
- `GET /config/gcp` - GCP collector configuration
- `PUT /config/gcp` - Update GCP collector configuration

**Event Management**:
- `GET /events/recent` - Recent security events across all clouds
- `GET /events/aws` - AWS-specific events
- `GET /events/azure` - Azure-specific events
- `GET /events/gcp` - GCP-specific events
- `POST /events/replay` - Replay events from specific time range

## Support and Documentation

### Additional Resources

- [AWS CloudTrail Documentation](https://docs.aws.amazon.com/cloudtrail/)
- [Azure Activity Log Documentation](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log)
- [GCP Audit Log Documentation](https://cloud.google.com/logging/docs/audit)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Contact Information

For support and questions:
- Email: siem-support@isectech.com
- Documentation: https://docs.isectech.com/siem/cloud-integrations
- Issues: https://github.com/isectech/siem-cloud-integrations/issues

---

**Note**: This implementation provides production-ready cloud service log integration capabilities with enterprise-grade security, compliance, and scalability features. Regular maintenance, monitoring, and updates are essential for optimal performance and security.