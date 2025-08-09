# iSECTECH POC Sample Data Generator

## Production-Grade Cybersecurity Sample Data Generation System

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/isectech/poc-sample-data-generator)
[![Go Version](https://img.shields.io/badge/go-1.21-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Overview

The iSECTECH POC Sample Data Generator is a sophisticated system that creates realistic, industry-specific cybersecurity sample data for proof-of-concept environments. It generates comprehensive datasets including security events, network traffic, vulnerabilities, incidents, and user activities tailored to specific industry verticals and compliance requirements.

### Key Features

🎯 **Industry-Specific Data**: Tailored datasets for financial services, healthcare, government, and more  
🔒 **Privacy-Compliant Generation**: GDPR/HIPAA compliant with PII anonymization  
📊 **Comprehensive Data Types**: Security events, network traffic, vulnerabilities, incidents, user activities  
🏗️ **Realistic Attack Scenarios**: MITRE ATT&CK framework integration with industry-specific threats  
⚡ **High-Volume Generation**: Scalable generation supporting millions of records  
🎨 **Flexible Output Formats**: JSON, CSV, SIEM-specific formats, and custom schemas  
📈 **Quality Metrics**: Built-in data quality assessment and validation  
🔄 **Progressive Generation**: Real-time progress tracking and status updates  

---

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│ Provisioning    │────│  Data Generator │────│  Industry       │
│ Engine          │    │     Engine      │    │  Schemas        │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   PostgreSQL    │    │   Data          │    │   Generated     │
│   (Job Queue)   │    │   Generators    │    │   Datasets      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Components

**Data Generation Engine**
- Pluggable generator architecture for different data types
- Industry-specific schema definitions and templates
- Advanced randomization with realistic patterns
- Multi-threaded generation for performance

**Security Event Generator**
- MITRE ATT&CK technique simulation
- Industry-specific attack patterns
- Realistic IP ranges and geolocation data
- Threat intelligence integration

**Network Traffic Generator**
- Protocol-specific traffic patterns
- Realistic bandwidth and connection behaviors
- Network topology simulation
- Anomaly injection for detection scenarios

**Vulnerability Generator**
- CVE database integration
- CVSS scoring simulation
- Asset-specific vulnerability assignments
- Patch management timeline simulation

---

## Technology Stack

**Backend Service**
- Go 1.21 with high-performance generators
- Gin framework for REST API
- GORM for database operations
- Advanced statistical modeling for realistic data

**Data Generation**
- Industry-specific schema definitions
- Pluggable generator architecture
- Statistical distribution modeling
- Quality assurance and validation

**Storage & Output**
- PostgreSQL for job tracking and metadata
- File system storage for generated datasets
- Multiple output format support
- Compression and archival capabilities

**Privacy & Compliance**
- PII anonymization and pseudonymization
- GDPR/HIPAA compliance features
- Data classification and handling
- Audit trail generation

---

## Project Structure

```
sample-data-generator/
├── main.go                       # Main application entry point
├── go.mod                        # Go module dependencies
├── Dockerfile                    # Container configuration
├── k8s/                          # Kubernetes deployment manifests
│   └── deployment.yaml           # Complete K8s configuration
├── schemas/                      # Industry-specific data schemas
│   ├── financial_services.json   # Financial services data patterns
│   ├── healthcare.json           # Healthcare data patterns
│   └── government.json           # Government data patterns
├── generators/                   # Data generator implementations
│   ├── security_events.go        # Security event generation
│   ├── network_traffic.go        # Network traffic generation
│   ├── vulnerabilities.go        # Vulnerability data generation
│   └── user_activities.go        # User activity generation
├── generated-data/               # Output directory for datasets
│   └── [tenant-slug]/            # Per-tenant data directories
└── README.md                     # This file
```

---

## Quick Start

### Prerequisites

- **Go 1.21+**
- **PostgreSQL 15+**
- **Docker** (optional)
- **Kubernetes** (for production deployment)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/isectech/poc-sample-data-generator.git
   cd poc-sample-data-generator
   ```

2. **Setup environment variables**
   ```bash
   export DATABASE_URL="postgres://user:pass@localhost:5432/isectech_poc?sslmode=disable"
   export DATA_OUTPUT_PATH="./generated-data"
   export ENABLE_GDPR_MODE="true"
   ```

3. **Install dependencies**
   ```bash
   go mod download
   ```

4. **Run the data generator**
   ```bash
   go run main.go
   ```

5. **Test the service**
   ```bash
   curl http://localhost:8082/api/v1/health
   ```

---

## API Reference

### Base URL
- **Development**: `http://localhost:8082/api/v1`
- **Production**: `http://poc-data-generator-service.poc-data-generator.svc.cluster.local/api/v1`

### Core Endpoints

#### POST `/data-generation/generate`
Submit a new data generation request.

**Request Body:**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "industry_vertical": "financial_services",
  "company_size": "enterprise",
  "security_scenarios": [
    "payment_fraud_detection",
    "regulatory_compliance_monitoring",
    "trading_platform_security"
  ],
  "data_volume": {
    "total_events": 100000,
    "users_count": 500,
    "assets_count": 200,
    "vulnerabilities_count": 150,
    "incidents_count": 25,
    "time_range_days": 30
  },
  "compliance_level": "high",
  "custom_requirements": {
    "include_mitre_mapping": true,
    "threat_intelligence_integration": true,
    "geo_location_diversity": "global"
  },
  "output_formats": ["json", "csv", "splunk"],
  "privacy_settings": {
    "anonymize_personal_data": true,
    "gdpr_compliant": true,
    "remove_pii": true,
    "use_hashed_identifiers": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Data generation job queued successfully",
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "progress_tracking": "/api/v1/data-generation/status/123e4567-e89b-12d3-a456-426614174000"
}
```

#### GET `/data-generation/status/{job_id}`
Get the status of a data generation job.

**Response:**
```json
{
  "success": true,
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "progress_percent": 100,
  "current_dataset": "completed",
  "completed_datasets": 5,
  "total_datasets": 5,
  "generated_datasets": {
    "security_events": {
      "count": 100000,
      "schema": {
        "type": "security_events",
        "description": "Cybersecurity event logs with threat intelligence"
      }
    },
    "network_traffic": {
      "count": 50000,
      "schema": {
        "type": "network_traffic",
        "description": "Network connection and traffic data"
      }
    },
    "vulnerabilities": {
      "count": 150,
      "schema": {
        "type": "vulnerabilities",
        "description": "Security vulnerability data with CVSS scoring"
      }
    }
  },
  "output_locations": {
    "security_events": "/app/generated-data/acme-cybersecurity-inc-a1b2c3d4/security_events_20240115_103000.json",
    "network_traffic": "/app/generated-data/acme-cybersecurity-inc-a1b2c3d4/network_traffic_20240115_103000.json",
    "vulnerabilities": "/app/generated-data/acme-cybersecurity-inc-a1b2c3d4/vulnerabilities_20240115_103000.json"
  },
  "data_quality_metrics": {
    "completeness_score": 98,
    "accuracy_score": 95,
    "consistency_score": 92,
    "timeliness_score": 99,
    "validity_score": 96,
    "uniqueness_score": 99,
    "total_records": 150150,
    "duplicate_rate": 0.002,
    "error_rate": 0.001
  },
  "total_records": 150150,
  "data_size_mb": 75.075
}
```

#### GET `/health`
Check service health status.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "generators": 4,
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Industry-Specific Data Generation

### Financial Services

**Security Scenarios:**
- Payment fraud detection with transaction anomalies
- Regulatory compliance monitoring (SOX, PCI DSS, FFIEC)
- Trading platform security with market manipulation attempts
- Core banking system security monitoring

**Sample Data Types:**
- Credit card transaction logs with fraud indicators
- Wire transfer monitoring with AML flags
- Trading algorithm anomaly detection
- Customer authentication and access logs

**Compliance Integration:**
- SOX financial reporting controls
- PCI DSS payment card data protection
- FFIEC cybersecurity framework alignment
- Basel III operational risk requirements

### Healthcare

**Security Scenarios:**
- Patient data protection (PHI/HIPAA compliance)
- Medical device security (IoMT monitoring)
- Ransomware defense scenarios
- Clinical research data security

**Sample Data Types:**
- EHR access logs with PHI protection
- Medical device communication logs
- Patient monitoring system data
- Clinical trial and research data

**Compliance Integration:**
- HIPAA privacy and security rules
- HITECH breach notification requirements
- FDA 21 CFR Part 11 for clinical trials
- Medical device cybersecurity frameworks

### Government

**Security Scenarios:**
- Classified data protection scenarios
- Insider threat detection patterns
- Supply chain security monitoring
- Critical infrastructure protection

**Sample Data Types:**
- Classified system access logs
- Security clearance monitoring
- Government network traffic analysis
- Critical infrastructure monitoring

**Compliance Integration:**
- FISMA security controls
- FedRAMP cloud security requirements
- NIST 800-53 security control families
- CJIS security policy compliance

---

## Data Generation Features

### Security Events Generator

**Event Types:**
- Authentication failures and anomalies
- Malware detection and analysis
- Intrusion attempts and lateral movement
- Data exfiltration scenarios
- Privilege escalation attempts
- Policy violations and compliance events

**MITRE ATT&CK Integration:**
- Technique-specific event generation
- Attack pattern simulation
- Threat actor behavior modeling
- Kill chain stage progression

**Threat Intelligence:**
- IOC (Indicators of Compromise) integration
- Threat actor attribution
- Geographic threat distribution
- Campaign and malware family correlation

### Network Traffic Generator

**Traffic Types:**
- HTTP/HTTPS web traffic with realistic patterns
- Database connections and queries
- Email communication (SMTP/IMAP/POP3)
- File transfer protocols (FTP/SFTP)
- DNS queries and responses
- Peer-to-peer and encrypted traffic

**Anomaly Scenarios:**
- DDoS attack simulations
- Data exfiltration patterns
- Command and control communications
- Lateral movement traffic
- Protocol abuse and tunneling

### Vulnerability Generator

**Vulnerability Types:**
- Web application vulnerabilities (OWASP Top 10)
- Operating system vulnerabilities
- Network device vulnerabilities
- Database security issues
- Third-party software vulnerabilities

**CVSS Integration:**
- Accurate CVSS v3.1 scoring
- Environmental and temporal metrics
- Industry-specific impact assessment
- Patch timeline simulation

---

## Data Quality & Validation

### Quality Metrics

**Completeness Score (95-100%)**
- Measures percentage of fields populated
- Validates required field presence
- Checks for empty or null values

**Accuracy Score (90-100%)**
- Validates data format correctness
- Checks business rule compliance
- Verifies cross-field consistency

**Consistency Score (85-100%)**
- Ensures uniform data representation
- Validates naming conventions
- Checks reference data integrity

**Timeliness Score (95-100%)**
- Validates timestamp accuracy
- Checks chronological ordering
- Ensures realistic time progression

### Validation Rules

**Format Validation:**
- IP address format checking
- Email address validation
- URL structure verification
- Timestamp format compliance

**Business Rule Validation:**
- Security event severity mapping
- CVSS score range validation
- Geographic location consistency
- User activity pattern validation

**Cross-Reference Validation:**
- Asset-vulnerability relationships
- User-system access patterns
- Network topology consistency
- Incident-event correlations

---

## Privacy & Compliance

### GDPR Compliance

**Data Minimization:**
- Generate only necessary data fields
- Implement purpose limitation principles
- Provide data retention controls

**Anonymization Techniques:**
- Statistical disclosure control
- K-anonymity implementation
- Differential privacy options
- Pseudonymization services

**Rights Implementation:**
- Right to erasure (data deletion)
- Right to rectification (data correction)
- Right to portability (data export)
- Right to restrict processing

### HIPAA Compliance

**PHI Protection:**
- De-identification according to Safe Harbor method
- Limited data set creation options
- Minimum necessary principle implementation

**Security Controls:**
- Access controls and audit logging
- Encryption in transit and at rest
- Breach notification procedures
- Business associate compliance

### Industry Standards

**Financial Services:**
- PCI DSS data protection requirements
- SOX internal control compliance
- FFIEC cybersecurity framework alignment

**Healthcare:**
- HITECH security requirements
- FDA 21 CFR Part 11 compliance
- Medical device cybersecurity guidelines

---

## Performance & Scalability

### Generation Performance

**High-Volume Generation:**
- Multi-threaded data generation
- Memory-efficient streaming processing
- Batch processing optimization
- Resource usage monitoring

**Scalability Features:**
- Horizontal scaling with Kubernetes
- Load balancing across generator instances
- Distributed data generation
- Queue-based job processing

### Resource Optimization

**Memory Management:**
- Streaming data generation
- Garbage collection optimization
- Memory pool utilization
- Resource leak prevention

**Storage Optimization:**
- Compressed output formats
- Incremental data generation
- Efficient file system usage
- Automated cleanup processes

---

## Monitoring & Observability

### Generation Metrics

**Performance Metrics:**
- Records generated per second
- Generation job completion time
- Resource utilization patterns
- Error rates and retry statistics

**Quality Metrics:**
- Data quality score distributions
- Validation failure rates
- Schema compliance percentages
- Anomaly detection accuracy

### Logging & Alerting

**Structured Logging:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "component": "security_event_generator",
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "dataset_type": "security_events",
  "records_generated": 25000,
  "progress": "25%",
  "message": "Security events generation in progress"
}
```

**Health Monitoring:**
- Service availability monitoring
- Database connectivity checks
- File system capacity monitoring
- Generation queue health

---

## Integration with POC Platform

### Provisioning Engine Integration

```go
// Integration with provisioning engine
type DataGenerationRequest struct {
    TenantID         uuid.UUID
    TenantSlug       string
    IndustryVertical string
    CompanySize      string
    // ... additional fields
}

// Called from provisioning engine after infrastructure setup
func RequestDataGeneration(request DataGenerationRequest) (*DataGenerationResponse, error) {
    // Submit data generation job
    // Track progress and completion
    // Return dataset locations and metadata
}
```

### POC Environment Population

**Automated Population:**
- Integration with provisioning pipeline
- Automated dataset assignment to tenants
- Real-time data streaming to POC environments
- SIEM and security tool integration

**Data Distribution:**
- Multi-format output support
- Direct database population
- API-based data streaming
- File-based data transfer

---

## Deployment & Operations

### Kubernetes Deployment

```yaml
# Deploy the data generator
kubectl apply -f k8s/deployment.yaml

# Check deployment status
kubectl get pods -n poc-data-generator

# Monitor generation jobs
kubectl logs -f deployment/poc-data-generator -n poc-data-generator
```

### Production Configuration

**Resource Requirements:**
- CPU: 500m-2000m per pod
- Memory: 1Gi-4Gi per pod
- Storage: 50Gi persistent volume
- Network: Standard cluster networking

**Scaling Configuration:**
- Min replicas: 2
- Max replicas: 8
- CPU target: 70%
- Memory target: 80%

### Data Lifecycle Management

**Retention Policies:**
- Generated data retention: 30 days default
- Job metadata retention: 90 days
- Audit log retention: 7 years
- Automated cleanup scheduling

**Archival Processes:**
- Compressed long-term storage
- Cloud storage integration
- Compliance retention requirements
- Data classification handling

---

## Security Considerations

### Data Security

**Generation Security:**
- Secure random number generation
- Cryptographically strong pseudorandomization
- Protection against timing attacks
- Secure deletion of temporary data

**Storage Security:**
- Encryption at rest for generated data
- Access control for data files
- Audit logging for data access
- Secure data transmission

### Application Security

**API Security:**
- Input validation and sanitization
- Rate limiting and throttling
- Authentication and authorization
- Audit logging for all operations

**Container Security:**
- Non-root container execution
- Read-only root filesystem
- Security context configuration
- Network policy enforcement

---

## Troubleshooting

### Common Issues

1. **Generation Performance Issues**
   ```bash
   # Check resource utilization
   kubectl top pods -n poc-data-generator
   
   # Monitor generation progress
   curl -s http://localhost:8082/api/v1/data-generation/status/{job_id}
   
   # Check for memory issues
   kubectl describe pod {pod-name} -n poc-data-generator
   ```

2. **Data Quality Problems**
   ```bash
   # Validate generated data
   curl -s http://localhost:8082/api/v1/data-generation/status/{job_id} | jq .data_quality_metrics
   
   # Check generation logs
   kubectl logs -f deployment/poc-data-generator -n poc-data-generator | grep "quality"
   ```

3. **Storage Issues**
   ```bash
   # Check disk space
   kubectl exec -it deployment/poc-data-generator -n poc-data-generator -- df -h
   
   # Verify persistent volume
   kubectl get pvc -n poc-data-generator
   ```

### Debug Mode

Enable debug logging:
```bash
kubectl patch deployment poc-data-generator -n poc-data-generator -p '{"spec":{"template":{"spec":{"containers":[{"name":"poc-data-generator","env":[{"name":"LOG_LEVEL","value":"debug"}]}]}}}}'
```

---

## Contributing

### Development Guidelines

1. **Code Quality**
   - Follow Go best practices and conventions
   - Write comprehensive unit tests
   - Implement proper error handling
   - Document generator algorithms

2. **Data Generator Development**
   - Implement DataGenerator interface
   - Provide comprehensive schema definitions
   - Include validation and quality checks
   - Support privacy compliance features

3. **Testing**
   ```bash
   # Unit tests
   go test ./... -v -cover
   
   # Data quality tests
   go test -tags=quality ./... -v
   
   # Performance benchmarks
   go test -bench=. ./...
   ```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

### Technical Support
- **Email**: poc-support@isectech.org
- **Documentation**: https://docs.isectech.org/data-generation
- **GitHub Issues**: https://github.com/isectech/poc-sample-data-generator/issues

### Data Schema Support
- **Schema Documentation**: https://docs.isectech.org/schemas
- **Industry Templates**: https://templates.isectech.org
- **Custom Schema Requests**: schema-support@isectech.org

---

**Built with 🎯 by the iSECTECH Platform Engineering Team**