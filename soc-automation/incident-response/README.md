# SOC Automation - Incident Response Orchestration

A production-grade incident response orchestration system that automates the detection, investigation, containment, and recovery phases of cybersecurity incidents. This system integrates with alert triage systems, evidence collection platforms, and case management tools to provide a comprehensive automated response capability.

## Features

### Core Capabilities
- **Automated Incident Detection**: Monitors alert streams and triggers incident response based on configurable rules
- **Playbook Orchestration**: Executes predefined incident response playbooks with automated and manual steps
- **Digital Forensics**: Automated evidence collection with proper chain-of-custody maintenance
- **Case Management**: Integration with TheHive and SOAR platforms for incident tracking
- **Real-time Monitoring**: Prometheus metrics and health checks for operational visibility

### Incident Response Workflows
- **Malware Incident Response**: Endpoint isolation, memory/disk imaging, malware analysis
- **Phishing Response**: Email quarantine, URL blocking, user notification
- **Data Breach Response**: Immediate containment, evidence collection, legal notification
- **DDoS Attack Mitigation**: Traffic analysis, mitigation activation, service recovery
- **Insider Threat Investigation**: User activity analysis, data access auditing
- **Privilege Escalation Response**: Account lockdown, access review, lateral movement investigation

### Evidence Collection Types
- Memory dumps (RAM acquisition)
- Disk images (forensic imaging)
- Network packet captures (PCAP)
- System and application logs
- Email messages and attachments
- Registry hives and system artifacts
- Browser artifacts and history
- Database exports
- Malware samples

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Alert Triage  │───▶│  Alert           │───▶│  Incident       │
│   System        │    │  Integration     │    │  Response       │
│                 │    │                  │    │  Orchestrator   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Digital       │    │   Correlation    │    │   TheHive       │
│   Forensics     │    │   Engine         │    │   Integration   │
│   Evidence      │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                       │                        │
        ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Evidence      │    │   Redis          │    │   Case          │
│   Storage       │    │   (Queues)       │    │   Management    │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.8+
- Redis 6.0+
- Elasticsearch 7.x+
- TheHive 4.x (optional)

### Installation

1. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

2. **Configure Environment**:
```bash
cp config/incident-response.yaml.example config/incident-response.yaml
# Edit configuration file with your environment details
```

3. **Set Environment Variables**:
```bash
export THEHIVE_API_KEY="your_thehive_api_key"
export EDR_CLIENT_ID="your_edr_client_id"
export EDR_CLIENT_SECRET="your_edr_client_secret"
export NETWORK_MONITOR_API_KEY="your_network_monitor_api_key"
```

4. **Start the Service**:
```bash
python -m incident_response_service config/incident-response.yaml
```

### Docker Deployment

```bash
# Build the container
docker build -t soc-incident-response .

# Run with configuration
docker run -d \
  --name soc-incident-response \
  -v /path/to/config:/etc/soc-automation \
  -v /evidence:/evidence \
  -p 8080:8080 \
  soc-incident-response
```

## Configuration

### Main Configuration File

The service is configured via YAML file (`config/incident-response.yaml`):

```yaml
# Redis for message queuing
redis:
  host: redis.soc.internal
  port: 6379
  db: 0

# Elasticsearch for data storage
elasticsearch:
  host: elasticsearch.soc.internal
  port: 9200

# Evidence collection settings
evidence_collection:
  enabled: true
  evidence_storage_path: /evidence
  encryption_enabled: true
  signing_enabled: true

# TheHive integration
thehive:
  enabled: true
  url: https://thehive.soc.internal
  api_key: ${THEHIVE_API_KEY}
```

### Trigger Rules Configuration

Configure when incident response should be triggered:

```yaml
trigger_rules:
  - rule_id: "critical_severity"
    name: "Critical Severity Incidents"
    enabled: true
    priority: 1
    policy_type: "severity_based"
    conditions:
      severities: ["critical"]
    actions: ["create_incident"]
    evidence_collection: true
    immediate_containment: true
```

### Playbook Configuration

Define custom incident response playbooks:

```yaml
playbooks:
  malware_response:
    name: "Malware Incident Response"
    incident_types: ["malware_incident"]
    severity_levels: ["high", "critical"]
    sla_minutes: 240
    steps:
      - step_id: "isolate_endpoint"
        name: "Isolate Infected Endpoints"
        type: "automated"
        action: "isolate_endpoint"
        timeout: 120
```

## API Reference

### REST API Endpoints

#### Get Service Status
```http
GET /api/v1/status
```

Response:
```json
{
  "service": "incident_response",
  "running": true,
  "components": {
    "orchestrator": true,
    "evidence_collector": true,
    "thehive_integration": true
  }
}
```

#### Trigger Manual Incident
```http
POST /api/v1/incidents/trigger
Content-Type: application/json

{
  "alert_data": {
    "id": "alert_12345",
    "severity": "high",
    "category": "malware",
    "source_ip": "192.168.1.100",
    "description": "Malware detected on endpoint"
  }
}
```

#### Get Incident Details
```http
GET /api/v1/incidents/{incident_id}
```

#### List Evidence for Incident
```http
GET /api/v1/incidents/{incident_id}/evidence
```

### Python API

```python
from incident_response_service import IncidentResponseService

# Initialize service
service = IncidentResponseService('config/incident-response.yaml')
await service.initialize()

# Trigger incident manually
incident_id = await service.trigger_manual_incident({
    'severity': 'high',
    'category': 'malware',
    'source_ip': '192.168.1.100'
})

# Get service status
status = await service.get_service_status()
```

## Playbook Development

### Creating Custom Playbooks

1. **Define Playbook Structure**:
```python
from orchestration_engine import Playbook, PlaybookStep

custom_playbook = Playbook(
    playbook_id="custom_response",
    name="Custom Incident Response",
    description="Custom response for specific incident type",
    incident_types=["custom_incident"],
    severity_levels=[IncidentSeverity.HIGH],
    steps=[
        PlaybookStep(
            step_id="custom_step",
            name="Custom Action",
            description="Perform custom response action",
            step_type="automated",
            action="custom_action_handler",
            parameters={"param1": "value1"}
        )
    ],
    sla_minutes=120
)
```

2. **Register Custom Step Handlers**:
```python
async def custom_action_handler(**params):
    context = params['context']
    execution = params['execution']
    
    # Perform custom action
    result = perform_custom_action(context)
    
    return {
        'output': 'Custom action completed',
        'evidence': [{'type': 'custom_evidence', 'details': result}]
    }

# Register handler
orchestrator.step_handlers['custom_action_handler'] = custom_action_handler
```

### Built-in Step Actions

| Action | Description | Parameters |
|--------|-------------|------------|
| `isolate_endpoint` | Isolate endpoints from network | `endpoints: List[str]` |
| `block_ip_address` | Block IP addresses in firewall | `ip_addresses: List[str]` |
| `collect_memory_dump` | Collect memory dumps | `hostnames: List[str]` |
| `collect_disk_image` | Create forensic disk images | `hostnames: List[str]` |
| `collect_network_pcap` | Collect network packet captures | `ip_addresses: List[str]`, `time_window: str` |
| `quarantine_email` | Quarantine malicious emails | `email_ids: List[str]` |
| `notify_stakeholders` | Send notifications | `notification_type: str`, `urgency: str` |
| `analyze_malware_sample` | Analyze malware in sandbox | `sample_path: str` |

## Evidence Collection

### Automated Evidence Collection

The system automatically collects evidence based on incident type:

- **Malware Incidents**: Memory dumps, disk images, network captures
- **Phishing Incidents**: Email messages, URL reputation data, user logs
- **Data Breach**: Disk images, access logs, network flows, database exports
- **Network Attacks**: Packet captures, firewall logs, IDS alerts

### Chain of Custody

All evidence maintains proper chain of custody with:
- Digital signatures for integrity verification
- Cryptographic hashes (MD5, SHA1, SHA256, SHA512)
- Timestamped custody entries
- Actor identification and witness records
- Automated evidence preservation

### Evidence Storage Structure

```
/evidence/
├── EV_20240101_abcd1234/
│   ├── metadata.json
│   ├── memory/
│   │   └── host1_20240101_120000.mem
│   ├── disk/
│   │   └── host1_20240101_120000.dd
│   ├── network/
│   │   └── 192.168.1.100_20240101_120000.pcap
│   └── logs/
│       └── system_20240101_120000.logs
└── backup/
    └── EV_20240101_abcd1234_backup.tar.gz
```

## Integration

### TheHive Integration

Automatically creates cases in TheHive with:
- Incident details and timeline
- Associated tasks for manual work
- Observables from IOCs
- Evidence attachments
- Progress tracking

### SOAR Platform Integration

Supports integration with:
- Phantom (Splunk SOAR)
- Demisto (Palo Alto Cortex XSOAR)
- IBM Resilient
- Custom SOAR platforms via REST API

### EDR Platform Integration

Supports endpoint detection and response platforms:
- CrowdStrike Falcon
- SentinelOne
- Carbon Black
- Microsoft Defender for Endpoint
- Custom EDR via API

## Monitoring and Metrics

### Prometheus Metrics

Key metrics exposed on port 8080:

- `soc_incidents_created_total` - Total incidents created by type/severity
- `soc_playbook_executions_total` - Playbook executions by status
- `soc_evidence_collected_total` - Evidence items collected by type
- `soc_incident_processing_seconds` - Incident processing time
- `soc_active_incidents` - Currently active incidents

### Health Checks

Automated health checks monitor:
- Redis connectivity
- Elasticsearch connectivity
- External system APIs (TheHive, EDR, etc.)
- Evidence storage accessibility
- Queue processing status

### Logging

Structured JSON logging with configurable levels:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "level": "INFO",
  "logger": "incident_response",
  "message": "Incident created successfully",
  "incident_id": "INC_20240101_abcd1234",
  "incident_type": "malware_incident",
  "severity": "high",
  "playbook": "malware_response_v1"
}
```

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check configuration syntax
python -c "import yaml; yaml.safe_load(open('config/incident-response.yaml'))"

# Check Redis connectivity
redis-cli -h redis.soc.internal ping

# Check Elasticsearch connectivity
curl -X GET "elasticsearch.soc.internal:9200/_cluster/health"
```

#### Evidence Collection Fails
```bash
# Check storage permissions
ls -la /evidence
sudo chown -R soc-automation:soc-automation /evidence

# Check EDR API connectivity
curl -H "Authorization: Bearer $EDR_API_KEY" https://api.edr.internal/status
```

#### TheHive Integration Issues
```bash
# Test TheHive API
curl -H "Authorization: Bearer $THEHIVE_API_KEY" \
     -X GET "https://thehive.soc.internal/api/v1/status"
```

### Debug Mode

Enable debug mode in configuration:

```yaml
logging:
  level: DEBUG

development:
  debug_mode: true
  mock_external_systems: true
```

## Performance Tuning

### Scaling Guidelines

- **Small Environment**: 1-2 workers, 10 concurrent executions
- **Medium Environment**: 5-10 workers, 25 concurrent executions  
- **Large Environment**: 10-20 workers, 50+ concurrent executions

### Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Orchestrator | 2 cores | 4GB RAM | 100GB |
| Evidence Collector | 4 cores | 8GB RAM | 10TB+ |
| Alert Integration | 2 cores | 2GB RAM | 50GB |

### Optimization Tips

1. **Evidence Storage**: Use fast SSD storage for temporary evidence collection
2. **Network**: Ensure high-bandwidth connections to endpoints for memory/disk imaging
3. **Database**: Configure Elasticsearch with adequate heap size and indexing optimization
4. **Caching**: Use Redis cluster for high-availability message queuing

## Security Considerations

### Authentication
- API key-based authentication for service-to-service communication
- Role-based access control for manual operations
- Integration with enterprise identity providers

### Encryption
- Evidence files encrypted at rest using AES-256-GCM
- TLS encryption for all API communications
- Digital signatures for chain-of-custody integrity

### Network Security
- Deploy in isolated network segment
- Firewall rules restricting access to necessary ports only
- VPN or private networking for cloud deployments

### Audit Logging
- All actions logged with user/system attribution
- Tamper-evident log storage
- Integration with SIEM for security monitoring

## Contributing

1. Follow the existing code style and patterns
2. Add comprehensive tests for new functionality
3. Update documentation for any changes
4. Ensure security best practices are followed

### Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 .
black .
```

## License

This software is proprietary to iSECTECH and is not licensed for external use or distribution.

## Support

For technical support or questions:
- Internal Slack: #soc-automation
- Email: soc-team@isectech.com
- Documentation: https://docs.soc.internal/incident-response