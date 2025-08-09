# iSECTECH SIEM Custom Log Format Support and Log Integrity Verification

## Overview

This directory contains the implementation of advanced log processing capabilities for the iSECTECH SIEM system, providing comprehensive custom log format parsing and cryptographic integrity verification. The implementation supports flexible parsing of diverse log formats with real-time tamper detection and chain verification.

## Architecture

### Processing Pipeline

```
Raw Logs → Format Detection → Parsing → Field Mapping → Integrity Signing → Output
     ↓               ↓           ↓          ↓              ↓             ↓
Custom Formats → Regex/JSON → Validation → Normalization → Crypto → Kafka
```

### Data Flow

```
Log Sources → Custom Parser → Integrity Verifier → Stream Processing → SIEM
     ↓             ↓               ↓                    ↓            ↓
Format Rules → Parsed Events → Signed Records → Enrichment → Storage
```

## Components

### 1. Custom Log Parser (`custom-log-parser.py`)

**Purpose**: Advanced log parsing engine with support for custom formats and flexible field mapping

**Key Features**:
- **Multi-Format Support**: Regex, JSON, CSV, and custom parsing engines
- **Dynamic Format Loading**: Runtime addition and modification of log formats
- **Field Mapping**: Automatic normalization to standardized field names
- **Performance Optimization**: Async processing with configurable worker threads
- **Extensive Built-in Formats**: Apache, Nginx, Windows EventLog, Syslog, Fortinet, Check Point
- **Validation Rules**: Pre and post-processing validation
- **Error Handling**: Graceful parsing failure handling with detailed error reporting

**Supported Log Formats**:

#### Built-in Formats
1. **Apache Common Log Format**:
   ```
   Pattern: ^(?P<client_ip>\S+) \S+ (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)" (?P<status>\d+) (?P<size>\S+)$
   Example: 192.168.1.100 - user [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
   ```

2. **Nginx JSON Format**:
   ```json
   {
     "remote_addr": "192.168.1.100",
     "time_iso8601": "2024-01-01T12:00:00+00:00",
     "request": "GET /api/v1/data HTTP/1.1",
     "status": 200,
     "body_bytes_sent": 1024
   }
   ```

3. **Windows EventLog**:
   ```
   Pattern: ^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<level>\w+) (?P<source>\w+) (?P<event_id>\d+) (?P<message>.*)$
   Example: 2024-01-01 12:00:00 INFO Security 4624 An account was successfully logged on
   ```

4. **Syslog RFC3164**:
   ```
   Pattern: ^<(?P<priority>\d+)>(?P<timestamp>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<tag>[^:]+): (?P<message>.*)$
   Example: <134>Jan 01 12:00:00 hostname service: message content
   ```

5. **Fortinet FortiGate**:
   ```
   Key-Value Format: srcip=192.168.1.100 dstip=10.0.0.1 srcport=12345 dstport=80 action=accept
   ```

6. **Check Point Logs**:
   ```
   Pipe-separated: timestamp|src=192.168.1.100|dst=10.0.0.1|action=accept|rule=allow_web
   ```

#### Custom Format Definition
```yaml
# Example custom format definition
name: "custom_application"
pattern: "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z) \\[(?P<level>\\w+)\\] (?P<component>\\w+): (?P<message>.*)$"
pattern_type: "regex"
field_mappings:
  timestamp: "@timestamp"
  level: "log.level"
  component: "service.name"
  message: "message"
timestamp_field: "timestamp"
timestamp_format: "iso8601"
severity_field: "level"
message_field: "message"
tags: ["application", "custom", "json"]
priority: 50
enabled: true
```

**Advanced Parsing Features**:

```python
# Example from custom-log-parser.py:636-661
def _parse_fortinet_kv(self, raw_log: str) -> Dict[str, Any]:
    """Parse Fortinet key-value format"""
    fields = {}
    
    # Extract key-value pairs with regex
    kv_pattern = r'(\w+)=([^=]*?)(?=\s+\w+=|\s*$)'
    matches = re.findall(kv_pattern, raw_log)
    
    for key, value in matches:
        fields[key] = value.strip('"')
    
    return fields
```

**Field Mapping and Normalization**:
```python
# Example from custom-log-parser.py:663-676
def _apply_field_mappings(self, parsed_fields: Dict[str, Any], log_format: LogFormat) -> Dict[str, Any]:
    """Apply field mappings to normalize field names"""
    mapped_fields = {}
    
    for source_field, target_field in log_format.field_mappings.items():
        if source_field in parsed_fields:
            mapped_fields[target_field] = parsed_fields[source_field]
    
    # Copy unmapped fields
    for field, value in parsed_fields.items():
        if field not in log_format.field_mappings:
            mapped_fields[field] = value
    
    return mapped_fields
```

### 2. Log Integrity Verifier (`log-integrity-verifier.py`)

**Purpose**: Advanced cryptographic integrity verification and tamper detection system

**Key Features**:
- **Multi-Algorithm Support**: HMAC, RSA-PSS digital signatures, SHA-256/512 hashing
- **Chain Verification**: Blockchain-like integrity chain for tamper detection
- **Real-Time Verification**: Continuous integrity monitoring of log streams
- **Batch Verification**: Periodic re-verification of stored logs
- **Tamper Detection**: Advanced algorithms for detecting log modifications
- **Key Management**: Automatic RSA key pair generation and secure storage
- **Performance Optimization**: Async processing with configurable verification intervals

**Cryptographic Features**:

#### Signature Generation
```python
# Example from log-integrity-verifier.py:478-533
async def _generate_signature(self, data: str, data_hash: str) -> str:
    """Generate signature for data"""
    signature_data = f"{data_hash}:{int(time.time())}"
    
    # Combined HMAC + RSA signature
    if self.hmac_key and self.private_key:
        hmac_signature = hmac.new(
            self.hmac_key,
            signature_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        rsa_signature = self.private_key.sign(
            signature_data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        combined_signature = {
            "hmac": hmac_signature,
            "rsa": base64.b64encode(rsa_signature).decode('utf-8'),
            "timestamp": int(time.time())
        }
        
        return base64.b64encode(json.dumps(combined_signature).encode('utf-8')).decode('utf-8')
```

#### Chain Verification
```python
# Example from log-integrity-verifier.py:933-989
async def _verify_log_chain(self, source_system: str):
    """Verify integrity chain for a source system"""
    chain_records = await self._get_chain_records(source_system)
    
    verification_result = ChainVerificationResult(
        chain_id=source_system,
        start_timestamp=min(r.timestamp for r in chain_records),
        end_timestamp=max(r.timestamp for r in chain_records),
        total_records=len(chain_records),
        verified_records=0,
        failed_records=0,
        missing_records=0,
        chain_integrity=True
    )
    
    # Verify chain continuity
    for i, record in enumerate(chain_records):
        if i > 0:
            previous_record = chain_records[i-1]
            
            # Verify chain link
            if record.previous_record_hash != previous_record.original_hash:
                verification_result.chain_integrity = False
                verification_result.failed_records += 1
```

#### Tamper Detection
```python
# Example from log-integrity-verifier.py:674-731
async def _detect_tampering(self, log_event: Dict[str, Any], integrity_record: IntegrityRecord) -> TamperDetection:
    """Detect tampering in log event"""
    tamper_detected = False
    tamper_type = "none"
    confidence_score = 0.0
    evidence = []
    
    # Hash comparison
    current_hash = self._calculate_hash(log_event.get("raw_message", ""))
    if current_hash != integrity_record.original_hash:
        tamper_detected = True
        tamper_type = "content_modification"
        confidence_score += 0.5
        evidence.append("Hash mismatch detected")
    
    # Signature verification failure
    if integrity_record.verification_status == "failed":
        tamper_detected = True
        tamper_type = "signature_tampering"
        confidence_score += 0.3
        evidence.append("Signature verification failed")
    
    # Chain verification
    chain_integrity = await self._verify_chain_integrity(integrity_record)
    if not chain_integrity:
        tamper_detected = True
        tamper_type = "chain_tampering"
        confidence_score += 0.4
        evidence.append("Chain integrity violation")
```

### 3. Docker Deployment (`docker-compose.log-processing.yml`)

**Purpose**: Production-ready containerized deployment for log processing services

**Key Features**:
- **Multi-Service Orchestration**: Parser, verifier, gateway, and management services
- **Security Hardening**: Read-only containers, no-new-privileges, network segmentation
- **Scalability**: Horizontal scaling support with load balancing
- **Monitoring Integration**: Prometheus metrics and health checks
- **Key Management**: Secure cryptographic key handling
- **API Gateway**: Unified interface for all log processing operations

**Services Configuration**:
- **custom-log-parser**: Port 8081 (API), 9167 (metrics)
- **log-integrity-verifier**: Port 8082 (API), 9168 (metrics)
- **log-processing-gateway**: Port 8083 (API), 9169 (metrics)
- **log-format-manager**: Port 8084 (API), 9171 (metrics)
- **redis-cache**: Port 6381 (Redis DB 7-8)

## Installation and Configuration

### Prerequisites

- Docker and Docker Compose
- Kafka cluster for log streaming
- Redis instance for caching and state management
- OpenSSL for cryptographic key generation
- Adequate storage for integrity records

### Quick Start

1. **Clone and Prepare**:
```bash
cd /opt/isectech-siem
git clone <repository> log-processing
cd log-processing
```

2. **Generate Cryptographic Keys**:
```bash
mkdir -p ./integrity-keys
openssl genrsa -out ./integrity-keys/integrity-private.pem 2048
openssl rsa -in ./integrity-keys/integrity-private.pem -pubout -out ./integrity-keys/integrity-public.pem
chmod 600 ./integrity-keys/integrity-private.pem
chmod 644 ./integrity-keys/integrity-public.pem
```

3. **Configure Custom Formats**:
```bash
mkdir -p ./custom-formats
# Add custom format definitions as YAML files
```

4. **Deploy Services**:
```bash
sudo docker-compose -f docker-compose.log-processing.yml up -d
```

5. **Verify Deployment**:
```bash
docker-compose -f docker-compose.log-processing.yml ps
docker-compose -f docker-compose.log-processing.yml logs -f
```

### Configuration Management

#### Custom Log Format Addition

**Via API**:
```bash
curl -X POST http://localhost:8084/formats \
  -H "Content-Type: application/json" \
  -d '{
    "name": "custom_app_format",
    "pattern": "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z) \\[(?P<level>\\w+)\\] (?P<message>.*)$",
    "pattern_type": "regex",
    "field_mappings": {
      "timestamp": "@timestamp",
      "level": "log.level",
      "message": "message"
    },
    "timestamp_field": "timestamp",
    "timestamp_format": "iso8601",
    "severity_field": "level",
    "tags": ["application", "custom"]
  }'
```

**Via Configuration File**:
```yaml
# /etc/isectech-siem/custom-formats/custom_app.yaml
name: "custom_app_format"
pattern: "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z) \\[(?P<level>\\w+)\\] (?P<message>.*)$"
pattern_type: "regex"
field_mappings:
  timestamp: "@timestamp"
  level: "log.level"
  message: "message"
timestamp_field: "timestamp"
timestamp_format: "iso8601"
severity_field: "level"
message_field: "message"
tags: ["application", "custom"]
priority: 50
enabled: true
```

#### Integrity Configuration

**HMAC Configuration**:
```yaml
# integrity-verifier.yaml
integrity:
  enable_hmac: true
  hmac_key: "your_secure_hmac_key_here"
  hash_algorithm: "sha256"
```

**Digital Signature Configuration**:
```yaml
integrity:
  enable_digital_signatures: true
  signature_algorithm: "rsa_pss"
  key_size: 2048
  private_key_path: "/etc/isectech-siem/keys/integrity-private.pem"
  public_key_path: "/etc/isectech-siem/keys/integrity-public.pem"
```

**Chain Verification Configuration**:
```yaml
integrity:
  enable_chain_verification: true
  chain_verification_depth: 1000
  tamper_detection_threshold: 0.8
```

## API Reference

### Custom Log Parser API

**Parse Single Log**:
```bash
curl -X POST http://localhost:8081/parse \
  -H "Content-Type: application/json" \
  -d '{
    "log": "2024-01-01T12:00:00Z [INFO] Application started successfully",
    "format_hint": "custom_app_format"
  }'
```

**Response**:
```json
{
  "success": true,
  "parsed_log": {
    "timestamp": "2024-01-01T12:00:00+00:00",
    "parsed_fields": {
      "@timestamp": "2024-01-01T12:00:00Z",
      "log.level": "INFO",
      "message": "Application started successfully"
    },
    "format_name": "custom_app_format",
    "severity": "info",
    "log_hash": "abc123...",
    "integrity_verified": false
  }
}
```

**Get Supported Formats**:
```bash
curl http://localhost:8081/formats
```

**Add Custom Format**:
```bash
curl -X POST http://localhost:8081/formats \
  -H "Content-Type: application/json" \
  -d '{ format definition }'
```

### Log Integrity Verifier API

**Verify Log Integrity**:
```bash
curl -X POST http://localhost:8082/verify \
  -H "Content-Type: application/json" \
  -d '{
    "log_id": "abc123",
    "raw_message": "original log content",
    "signature": "base64_encoded_signature"
  }'
```

**Response**:
```json
{
  "success": true,
  "verification_result": {
    "log_id": "abc123",
    "verified": true,
    "verification_timestamp": "2024-01-01T12:00:00+00:00",
    "signature_valid": true,
    "hash_valid": true,
    "chain_valid": true,
    "errors": []
  }
}
```

**Get Integrity Status**:
```bash
curl http://localhost:8082/status/integrity/{source_system}
```

**Verify Chain**:
```bash
curl -X POST http://localhost:8082/verify/chain \
  -H "Content-Type: application/json" \
  -d '{
    "source_system": "application_logs",
    "depth": 100
  }'
```

### Log Processing Gateway API

**Unified Log Processing**:
```bash
curl -X POST http://localhost:8083/process \
  -H "Content-Type: application/json" \
  -d '{
    "log": "raw log content",
    "source_system": "application",
    "enable_integrity": true,
    "format_hint": "custom_format"
  }'
```

**Batch Processing**:
```bash
curl -X POST http://localhost:8083/process/batch \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {"log": "log1", "source": "app1"},
      {"log": "log2", "source": "app2"}
    ],
    "enable_integrity": true
  }'
```

## Security Features

### Cryptographic Integrity

1. **Multi-Layer Security**:
   - HMAC for fast verification
   - RSA-PSS digital signatures for non-repudiation
   - SHA-256/512 hashing for content integrity
   - Blockchain-like chaining for tamper detection

2. **Key Management**:
   - Automatic RSA key pair generation
   - Secure key storage with proper permissions
   - Key rotation support
   - Hardware Security Module (HSM) integration ready

3. **Tamper Detection**:
   - Real-time integrity monitoring
   - Content modification detection
   - Timestamp manipulation detection
   - Chain integrity verification
   - Confidence scoring for alert prioritization

### Access Control

1. **API Security**:
   - Rate limiting on all endpoints
   - Authentication token validation
   - Input validation and sanitization
   - Audit logging for all operations

2. **Network Security**:
   - TLS encryption for all communications
   - Network segmentation with Docker networks
   - Firewall rules for port access
   - VPN access for administration

### Compliance

The log processing implementation supports:
- **SOC 2 Type II**: Integrity and availability controls
- **PCI DSS**: Log integrity for payment environments
- **HIPAA**: Audit trail integrity for healthcare
- **GDPR**: Data integrity and audit requirements
- **NIST SP 800-92**: Log management security guidelines

## Performance and Monitoring

### Performance Metrics

**Key Performance Indicators**:
- Logs processed per second by format type
- Parsing latency (95th percentile)
- Integrity verification rate
- Memory and CPU utilization
- Error rates by format and operation

**Prometheus Metrics**:
```
# Parser metrics
logs_parsed_total{format="apache_common", status="success"} 150000
log_parsing_duration_seconds{format="nginx_json"} 0.001
parsing_errors_total{format="custom_app", error_type="regex_error"} 5

# Integrity metrics
log_integrity_checks_total{status="verified", source="application"} 145000
log_tamper_detections_total{type="content_modification", source="web_server"} 2
log_chain_verifications_total{status="verified"} 500
```

### Health Monitoring

**Health Check Endpoints**:
```bash
# Service health
curl http://localhost:8081/health  # Parser
curl http://localhost:8082/health  # Integrity verifier
curl http://localhost:8083/health  # Gateway

# Metrics endpoints
curl http://localhost:9167/metrics  # Parser metrics
curl http://localhost:9168/metrics  # Integrity metrics
curl http://localhost:9169/metrics  # Gateway metrics
```

**Service Status Monitoring**:
```bash
# Container status
docker-compose -f docker-compose.log-processing.yml ps

# Service logs
docker-compose -f docker-compose.log-processing.yml logs -f custom-log-parser
docker-compose -f docker-compose.log-processing.yml logs -f log-integrity-verifier

# Resource usage
docker stats isectech-custom-log-parser isectech-log-integrity-verifier
```

## Troubleshooting

### Common Issues

1. **Parsing Failures**:
```bash
# Check format definitions
curl http://localhost:8081/formats

# Test specific format
curl -X POST http://localhost:8081/parse \
  -H "Content-Type: application/json" \
  -d '{"log": "test log", "format_hint": "format_name"}'

# Check parser logs
docker logs isectech-custom-log-parser
```

2. **Integrity Verification Failures**:
```bash
# Check key availability
curl http://localhost:8082/keys/status

# Verify specific log
curl -X POST http://localhost:8082/verify \
  -H "Content-Type: application/json" \
  -d '{"log_id": "abc123", "signature": "..."}'

# Check verifier logs
docker logs isectech-log-integrity-verifier
```

3. **Performance Issues**:
```bash
# Monitor metrics
curl http://localhost:9167/metrics | grep parsing_duration
curl http://localhost:9168/metrics | grep integrity_verification

# Check resource usage
docker stats --no-stream

# Adjust worker threads
# Edit docker-compose.yml and restart services
```

### Debug Mode

**Enable verbose logging**:
```bash
# Set debug environment
export LOG_LEVEL=DEBUG
docker-compose restart

# Monitor debug output
docker-compose logs -f --tail=100
```

**Test Format Parsing**:
```bash
# Interactive format testing
docker exec -it isectech-custom-log-parser python3 -c "
from custom_log_parser import CustomLogParser
import asyncio

async def test():
    parser = CustomLogParser()
    await parser.initialize()
    
    result = await parser.parse_single_log(
        'test log content',
        'format_name'
    )
    print(result)

asyncio.run(test())
"
```

## Advanced Features

### Custom Processing Rules

**Pre-processing Rules**:
```yaml
preprocessing_rules:
  - "strip_whitespace"
  - "normalize_unicode"
  - "remove_null_bytes"
  - "truncate:1048576"  # 1MB max
```

**Validation Rules**:
```yaml
validation_rules:
  - "require_timestamp"
  - "validate_ip_addresses"
  - "check_field_lengths"
  - "sanitize_sql_injection"
```

### Multi-Line Log Support

**Configuration**:
```yaml
name: "java_stacktrace"
pattern: "^(?P<timestamp>\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) (?P<level>\\w+) (?P<message>.*)"
multiline_pattern: "^\\s+at\\s+"
pattern_type: "regex"
```

### Real-Time Format Updates

**Dynamic Format Management**:
```bash
# Add format at runtime
curl -X POST http://localhost:8084/formats \
  -H "Content-Type: application/json" \
  -d '{ format definition }'

# Update existing format
curl -X PUT http://localhost:8084/formats/format_name \
  -H "Content-Type: application/json" \
  -d '{ updated format definition }'

# Enable/disable format
curl -X PATCH http://localhost:8084/formats/format_name \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

## Integration

### SIEM Platform Integration

The log processing components integrate with the broader iSECTECH SIEM platform:

1. **Stream Processing Integration**:
   - Real-time parsed log streaming to correlation engines
   - Field normalization for consistent analysis
   - Integrity status propagation through processing pipeline

2. **Storage Integration**:
   - Elasticsearch index mapping for parsed fields
   - Long-term integrity record storage
   - Efficient querying of processed logs

3. **Alerting Integration**:
   - Tamper detection alerts to SOAR platforms
   - Parsing failure notifications
   - Integrity violation escalation

### Third-Party Integration

**Supported Integrations**:
- **Log Shippers**: Filebeat, Fluentd, Logstash, Vector
- **SIEM Platforms**: Splunk, QRadar, ArcSight format export
- **Compliance Tools**: Audit report generation, SOX compliance
- **Monitoring**: Grafana dashboards, Nagios checks

## Support and Documentation

### Additional Resources

- [Custom Log Format Specification](https://docs.isectech.com/siem/log-formats)
- [Integrity Verification Guide](https://docs.isectech.com/siem/integrity)
- [API Reference Documentation](https://docs.isectech.com/siem/api)
- [Performance Tuning Guide](https://docs.isectech.com/siem/performance)

### Contact Information

For support and questions:
- Email: siem-support@isectech.com
- Documentation: https://docs.isectech.com/siem/log-processing
- Issues: https://github.com/isectech/siem-log-processing/issues

---

**Note**: This implementation provides enterprise-grade log processing capabilities with advanced format support and cryptographic integrity verification. Regular maintenance, monitoring, and security updates are essential for optimal performance and security.