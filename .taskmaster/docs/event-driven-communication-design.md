# iSECTECH Protect - Event-Driven Communication Design

**Version:** 1.0  
**Date:** 2025-07-31  
**Status:** In Progress  
**Task Reference:** 26.3

## Executive Summary

This document defines the event-driven communication patterns for the iSECTECH Protect platform, designed to handle 1B+ events per day with fault tolerance, ordering guarantees, and multi-tenant isolation. The architecture uses Apache Kafka as the central event streaming platform with strict schema governance and security controls.

## Design Principles

### Event-Driven Architecture Principles

1. **Loose Coupling:** Services communicate through events, not direct API calls
2. **Event Sourcing:** All significant state changes are captured as events
3. **Eventual Consistency:** Services maintain their own state and sync via events
4. **Scalability:** Horizontal scaling through partitioning and consumer groups
5. **Fault Tolerance:** Multiple replicas and dead-letter queues for error handling
6. **Security:** Zero Trust principles with encryption and access controls

### Messaging Patterns

- **Publish-Subscribe:** Domain events for loose coupling between services
- **Request-Reply:** Synchronous operations when immediate response needed
- **Event Sourcing:** Audit trail and state reconstruction capabilities
- **CQRS:** Separate read/write models with event-driven synchronization

---

## 1. Apache Kafka Infrastructure Design

### Cluster Architecture

```yaml
# Kafka Cluster Configuration
Cluster Size: 9 brokers (3 per availability zone)
Replication Factor: 3 (minimum for production)
Min In-Sync Replicas: 2
Partition Count: 100-1000 per topic (based on throughput)
Retention Policy: 7 days (configurable per topic)
Compression: LZ4 for optimal throughput/compression balance
```

### Multi-Region Deployment

- **Primary Region:** us-central1 (Google Cloud)
- **Secondary Region:** us-east1 (Google Cloud)
- **Cross-Region Replication:** MirrorMaker 2.0 for disaster recovery
- **Regional Failover:** Automated with < 30 seconds RTO

### Performance Targets

- **Throughput:** 1M+ events/second sustained
- **Latency:** P99 < 100ms end-to-end
- **Availability:** 99.99% uptime
- **Scalability:** Linear scaling with partition addition

---

## 2. Topic Design & Taxonomy

### Domain-Driven Topic Structure

#### Network Security Domain Topics

```
network.events                    # All network security events
├── network.flows                # Network flow data (high volume)
├── network.threats              # Threat detection events
├── network.anomalies            # Anomaly detection results
└── network.assets               # Asset discovery and changes
```

#### Application Security Domain Topics

```
application.events               # All application security events
├── application.vulnerabilities  # Vulnerability scan results
├── application.runtime          # Runtime protection events
├── application.scans            # Scanning operations and results
└── application.attacks          # Application attack detection
```

#### Data Security Domain Topics

```
data.events                      # All data security events
├── data.classification          # Data classification results
├── data.dlp                     # DLP violations and events
├── data.encryption              # Encryption operations
└── data.access                  # Data access monitoring
```

#### Identity & Access Domain Topics

```
identity.events                  # All identity and access events
├── identity.authentication      # Authentication events
├── identity.authorization       # Authorization decisions
├── identity.analytics           # UEBA and risk scoring
└── identity.sessions            # Session management events
```

#### Monitoring & Analytics Domain Topics

```
monitoring.events                # Centralized monitoring events
├── monitoring.alerts            # Alert generation and management
├── monitoring.metrics           # Security metrics and KPIs
├── monitoring.compliance        # Compliance-related events
└── monitoring.reports           # Report generation events
```

#### Cross-Domain Topics

```
platform.events                 # Platform-wide events
├── platform.configuration      # Configuration changes
├── platform.deployment         # Deployment and health events
├── platform.audit              # Audit trail events
└── platform.integration        # External integration events

tenant.events                   # Multi-tenant events
├── tenant.provisioning         # Tenant lifecycle events
├── tenant.isolation            # Tenant boundary events
└── tenant.billing              # Usage and billing events

alerts.events                   # Critical alerting
├── alerts.critical             # P1 security incidents
├── alerts.compliance           # Compliance violations
└── alerts.operational          # System health alerts
```

### Topic Configuration Strategy

#### High-Volume Topics (> 10M events/day)

```yaml
Partitions: 1000
Retention: 24 hours
Compression: LZ4
Replication: 3
Min ISR: 2
Cleanup Policy: delete
```

#### Standard Topics (1M-10M events/day)

```yaml
Partitions: 100
Retention: 7 days
Compression: LZ4
Replication: 3
Min ISR: 2
Cleanup Policy: delete
```

#### Audit/Compliance Topics

```yaml
Partitions: 50
Retention: 90 days
Compression: GZIP
Replication: 3
Min ISR: 2
Cleanup Policy: compact
```

---

## 3. Event Schema Design

### Standardized Event Envelope

#### Base Event Schema (JSON)

```json
{
  "$schema": "https://api.isectech.org/schemas/v1/base-event.json",
  "eventId": "550e8400-e29b-41d4-a716-446655440000",
  "eventType": "NetworkThreatDetected",
  "eventVersion": "1.2.0",
  "timestamp": "2025-07-31T10:30:00.123Z",
  "source": {
    "service": "network-threat-detection-service",
    "version": "2.1.5",
    "instance": "ntd-pod-abc123"
  },
  "tenant": {
    "tenantId": "tenant-12345",
    "organizationId": "org-67890"
  },
  "correlation": {
    "correlationId": "corr-abc123",
    "traceId": "trace-def456",
    "causationId": "cause-ghi789"
  },
  "security": {
    "classification": "internal",
    "sensitivity": "medium"
  },
  "data": {
    // Event-specific payload
  }
}
```

#### Event Metadata Standards

- **eventId:** UUID v4 for unique identification
- **eventType:** PascalCase naming (e.g., `NetworkThreatDetected`)
- **eventVersion:** Semantic versioning for schema evolution
- **timestamp:** ISO 8601 with microsecond precision
- **source:** Complete service identification for debugging
- **tenant:** Multi-tenant context for isolation
- **correlation:** Distributed tracing support
- **security:** Data classification for access control

### Domain-Specific Event Schemas

#### Network Security Events

```json
{
  "eventType": "NetworkThreatDetected",
  "data": {
    "threatId": "threat-456",
    "threatType": "malware",
    "severity": "high",
    "confidence": 0.95,
    "source": {
      "ip": "192.168.1.100",
      "port": 443,
      "hostname": "suspicious.example.com"
    },
    "destination": {
      "ip": "10.0.0.50",
      "port": 80,
      "assetId": "asset-789"
    },
    "detection": {
      "signature": "trojan.generic.variant",
      "engine": "suricata",
      "ruleId": "2024001"
    },
    "metadata": {
      "protocol": "TCP",
      "bytes": 1024,
      "packets": 15,
      "duration": 5.2
    }
  }
}
```

#### Identity & Access Events

```json
{
  "eventType": "UserAuthenticationSucceeded",
  "data": {
    "userId": "user-123",
    "sessionId": "session-abc789",
    "authMethod": "mfa-totp",
    "client": {
      "ip": "203.0.113.100",
      "userAgent": "Mozilla/5.0...",
      "device": "laptop-456"
    },
    "context": {
      "location": "US-CA-SanFrancisco",
      "riskScore": 0.15,
      "anomalies": ["unusual-location"]
    },
    "session": {
      "expiresAt": "2025-07-31T18:30:00Z",
      "permissions": ["read:alerts", "write:policies"]
    }
  }
}
```

#### Vulnerability Management Events

```json
{
  "eventType": "VulnerabilityDiscovered",
  "data": {
    "vulnerabilityId": "vuln-789",
    "cve": "CVE-2024-12345",
    "severity": "critical",
    "cvss": {
      "version": "3.1",
      "score": 9.8,
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "asset": {
      "assetId": "asset-456",
      "hostname": "web-server-01",
      "type": "server",
      "os": "Ubuntu 22.04"
    },
    "discovery": {
      "scanner": "nessus",
      "scanId": "scan-123",
      "plugin": "plugin-789"
    },
    "remediation": {
      "action": "patch",
      "priority": "urgent",
      "dueDate": "2025-08-07T00:00:00Z"
    }
  }
}
```

### Schema Evolution Strategy

#### Versioning Rules

1. **Backward Compatible:** Add optional fields only
2. **Breaking Changes:** Increment major version, maintain parallel schemas
3. **Field Deprecation:** Mark deprecated, remove after 6 months
4. **Schema Registry:** Enforce validation at producer level

#### Evolution Example

```json
// Version 1.0.0
{
  "eventType": "NetworkThreatDetected",
  "data": {
    "threatId": "threat-456",
    "severity": "high"
  }
}

// Version 1.1.0 (Backward Compatible)
{
  "eventType": "NetworkThreatDetected",
  "data": {
    "threatId": "threat-456",
    "severity": "high",
    "confidence": 0.95,        // New optional field
    "mitigationStatus": "pending"  // New optional field
  }
}
```

---

## 4. Message Ordering & Delivery Guarantees

### Partitioning Strategy

#### Partition Key Selection

- **Network Events:** `assetId` or `sourceIp` for session ordering
- **Identity Events:** `userId` for user activity ordering
- **Vulnerability Events:** `assetId` for asset-centric ordering
- **Alert Events:** `incidentId` for incident correlation
- **Audit Events:** `tenantId` for tenant-specific ordering

#### Ordering Guarantees

- **Within Partition:** Strict FIFO ordering preserved
- **Cross Partition:** No ordering guarantees (by design)
- **Global Ordering:** Not supported for scalability reasons

### Delivery Semantics

#### Producer Configuration

```java
// Kafka Producer Settings
props.put("acks", "all");                    // Wait for all replicas
props.put("retries", Integer.MAX_VALUE);      // Infinite retries
props.put("enable.idempotence", true);        // Prevent duplicates
props.put("batch.size", 16384);              // Batch for throughput
props.put("linger.ms", 5);                   // Small batching delay
props.put("compression.type", "lz4");         // Optimal compression
```

#### Consumer Configuration

```java
// Kafka Consumer Settings
props.put("enable.auto.commit", false);       // Manual offset commit
props.put("isolation.level", "read_committed"); // Read only committed records
props.put("max.poll.records", 500);           // Optimize batch processing
props.put("session.timeout.ms", 30000);       // Group membership timeout
props.put("heartbeat.interval.ms", 3000);     // Heartbeat frequency
```

### Idempotency Patterns

- **Producer Idempotency:** Built-in Kafka idempotent producer
- **Consumer Idempotency:** Event deduplication using `eventId`
- **Processing Idempotency:** Upsert operations and version checks

---

## 5. Fault Tolerance & Error Handling

### Error Handling Patterns

#### Dead Letter Queue (DLQ) Strategy

```yaml
# DLQ Topic Configuration
Topic Pattern: '{original-topic}.dlq'
Examples:
  - network.events.dlq
  - identity.events.dlq
  - monitoring.events.dlq

Retention: 30 days
Processing: Manual review and replay capability
Alerting: Immediate notification on DLQ messages
```

#### Retry Logic

```java
// Exponential Backoff Configuration
InitialDelay: 100ms
MaxDelay: 30 seconds
BackoffMultiplier: 2.0
MaxRetries: 5
JitterEnabled: true
```

#### Circuit Breaker Pattern

```yaml
# Circuit Breaker Configuration
FailureThreshold: 5 consecutive failures
RecoveryTimeout: 30 seconds
HalfOpenMaxCalls: 3
MonitoringWindow: 60 seconds
```

### High Availability Design

#### Kafka Cluster HA

- **Multi-AZ Deployment:** Brokers spread across 3 availability zones
- **Replication Factor:** 3 with min.insync.replicas = 2
- **Leader Election:** Automatic with controlled shutdown
- **Network Partitions:** Majority quorum for split-brain prevention

#### Consumer Group Resilience

- **Automatic Rebalancing:** Failed consumers trigger partition reassignment
- **Graceful Shutdown:** Proper offset commit before termination
- **Health Checks:** Kubernetes liveness/readiness probes
- **Scaling:** Horizontal Pod Autoscaler based on consumer lag

### Disaster Recovery

#### Cross-Region Replication

```yaml
# MirrorMaker 2.0 Configuration
Source Cluster: us-central1-kafka
Target Cluster: us-east1-kafka
Replication Topics: All production topics
Lag Monitoring: < 10 seconds RPO
Failover: Automated with DNS switch
```

#### Backup Strategy

- **Topic Snapshots:** Daily snapshots to Google Cloud Storage
- **Offset Backup:** Consumer group offset preservation
- **Schema Backup:** Schema registry backup and versioning
- **Recovery Time:** < 1 hour RTO for full cluster restoration

---

## 6. Security & Access Control

### Authentication & Authorization

#### Service Authentication

```yaml
# mTLS Configuration
Certificate Authority: Internal PKI
Certificate Rotation: 90 days
Client Certificates: Per microservice
Protocol: TLS 1.3 minimum
```

#### Kafka ACLs

```yaml
# Example ACL Configuration
Network Threat Detection Service:
  - ALLOW WRITE to network.threats
  - ALLOW READ from network.flows
  - DENY ALL other topics

Identity Analytics Service:
  - ALLOW WRITE to identity.analytics
  - ALLOW READ from identity.events
  - DENY ALL other topics

Event Aggregation Service:
  - ALLOW READ from *.events
  - ALLOW WRITE to monitoring.events
  - DENY ALL configuration topics
```

### Data Protection

#### Encryption

- **In Transit:** TLS 1.3 for all client-broker communication
- **At Rest:** Broker-level encryption with AES-256
- **Client-Side:** Optional payload encryption for sensitive data

#### Data Classification

```json
{
  "security": {
    "classification": "confidential", // public, internal, confidential, restricted
    "sensitivity": "high", // low, medium, high, critical
    "retention": "P90D", // ISO 8601 duration
    "geography": "US" // Data residency requirements
  }
}
```

### Multi-Tenant Isolation

#### Tenant-Aware Topics

```yaml
# Tenant Isolation Strategy
Option 1: Tenant-Specific Topics
  - tenant-123.network.events
  - tenant-456.network.events

Option 2: Shared Topics with Filtering
  - network.events (with tenantId in payload)
  - Consumer-side filtering by tenantId

Recommendation: Option 2 for operational simplicity
```

#### Access Control

- **Topic-Level ACLs:** Restrict tenant access to specific topics
- **Consumer Groups:** Tenant-specific consumer group names
- **Message Filtering:** Consumer-side filtering by tenantId
- **Audit Logging:** All topic access logged for compliance

---

## 7. Monitoring & Observability

### Kafka Metrics

#### Broker Metrics

```yaml
Key Metrics:
  - kafka.server.BrokerTopicMetrics.MessagesInPerSec
  - kafka.server.BrokerTopicMetrics.BytesInPerSec
  - kafka.server.ReplicaManager.LeaderCount
  - kafka.server.ReplicaManager.PartitionCount
  - kafka.log.LogFlushStats.LogFlushRateAndTimeMs

Alerting Thresholds:
  - Disk Usage > 80%
  - CPU Usage > 80%
  - Network IO > 80%
  - Replication Lag > 1000ms
```

#### Consumer Lag Monitoring

```yaml
Metrics:
  - kafka.consumer.ConsumerLagMetrics.records-lag-max
  - kafka.consumer.ConsumerLagMetrics.records-lag-avg
  - kafka.consumer.ConsumerFetchManagerMetrics.fetch-rate

Alerting:
  - Consumer Lag > 10,000 messages (Critical)
  - Consumer Lag > 1,000 messages (Warning)
  - No Consumer Activity > 5 minutes (Warning)
```

### Distributed Tracing

#### Trace Propagation

```json
{
  "correlation": {
    "traceId": "trace-abc123", // Unique per request chain
    "spanId": "span-def456", // Unique per service hop
    "parentSpanId": "span-xyz789", // Parent service span
    "correlationId": "corr-abc123" // Business correlation ID
  }
}
```

#### Integration with Jaeger

- **Trace Collection:** OpenTelemetry instrumentation
- **Sampling Rate:** 1% for production traffic
- **Retention:** 7 days for trace data
- **Analysis:** Service dependency mapping and latency analysis

### Event Flow Monitoring

#### End-to-End Latency Tracking

```yaml
Measurement Points: 1. Event Production Timestamp
  2. Kafka Broker Ingestion
  3. Consumer Processing Start
  4. Downstream Service Processing
  5. Final Output/Action

SLA Targets:
  - P95 End-to-End Latency < 500ms
  - P99 End-to-End Latency < 2 seconds
  - Event Loss Rate < 0.001%
```

---

## 8. Performance Optimization

### Throughput Optimization

#### Producer Optimization

```java
// High-Throughput Producer Configuration
props.put("batch.size", 65536);          // Larger batches
props.put("linger.ms", 10);              // Wait for batching
props.put("buffer.memory", 67108864);     // 64MB buffer
props.put("compression.type", "lz4");     // Fast compression
props.put("max.in.flight.requests.per.connection", 5);
```

#### Consumer Optimization

```java
// High-Throughput Consumer Configuration
props.put("fetch.min.bytes", 1024);      // Minimum fetch size
props.put("fetch.max.wait.ms", 500);     // Max wait for batch
props.put("max.poll.records", 1000);     // Process in larger batches
props.put("receive.buffer.bytes", 65536); // Network buffer
```

### Latency Optimization

#### Low-Latency Configuration

```yaml
# Critical Path Topics
Topic: alerts.critical
Config:
  unclean.leader.election.enable: false
  min.insync.replicas: 1 # Reduce for lower latency
  acks: 1 # Leader acknowledgment only
  linger.ms: 0 # No batching delay
  compression.type: none # No compression overhead
```

### Resource Management

#### JVM Tuning

```yaml
# Kafka Broker JVM Settings
Heap Size: 8GB (50% of available RAM)
GC Algorithm: G1GC
GC Logging: Enabled for monitoring
Memory Mapped Files: Optimized for log segments
```

#### Disk Performance

- **Storage Type:** SSD NVMe for log directories
- **File System:** XFS with optimal mount options
- **RAID Configuration:** RAID 10 for balance of performance/reliability
- **Separate Disks:** Logs and OS on separate drives

---

## 9. Event Processing Patterns

### Stream Processing Patterns

#### Real-Time Aggregation

```yaml
Pattern: Event Stream Aggregation
Use Case: Security metrics calculation
Technology: Kafka Streams
Window: Tumbling 1-minute windows
State Store: RocksDB
Output: monitoring.metrics topic
```

#### Complex Event Processing

```yaml
Pattern: Multi-Stream Join
Use Case: Correlation of network and identity events
Technology: Apache Flink
Window: Session windows (30-minute timeout)
Watermarks: 5-second late arrival tolerance
Output: monitoring.correlated-events topic
```

### Event Sourcing Implementation

#### Event Store Design

```yaml
Aggregate: SecurityIncident
Events:
  - IncidentCreated
  - EvidenceAdded
  - IncidentEscalated
  - IncidentResolved
Topic: incidents.events
Snapshots: Every 100 events
Replay: Full history reconstruction capability
```

#### CQRS Integration

```yaml
Command Side: Write operations to event store
Query Side: Materialized views from events
Projection Updates: Real-time via Kafka Streams
Consistency: Eventual consistency across read models
```

---

## 10. Integration Patterns

### External System Integration

#### SIEM Integration

```yaml
Pattern: Event Forwarding
Target: Splunk, QRadar, Sentinel
Protocol: Syslog, REST API, Kafka Connect
Format: CEF, LEEF, JSON
Filtering: Critical events only
Rate Limiting: 10,000 events/minute
```

#### API Gateway Integration

```yaml
Pattern: Request-Response over Events
Inbound: HTTP requests converted to events
Processing: Async processing via Kafka
Outbound: WebSocket/SSE for real-time updates
Timeout: 30 seconds for sync operations
```

### Microservice Communication

#### Async Command Pattern

```yaml
Scenario: Vulnerability Remediation
Flow: 1. VulnManagement publishes RemediationRequired event
  2. PatchManagement consumes and starts patching
  3. PatchManagement publishes PatchingStarted event
  4. VulnManagement updates vulnerability status
  5. PatchManagement publishes PatchingCompleted event
  6. VulnManagement runs verification scan
```

#### Saga Pattern for Distributed Transactions

```yaml
Scenario: Incident Response Workflow
Saga Steps:
  1. CreateIncident (Compensate: CancelIncident)
  2. NotifyTeam (Compensate: CancelNotification)
  3. IsolateAsset (Compensate: RestoreAsset)
  4. CollectEvidence (Compensate: DeleteEvidence)
Coordinator: IncidentOrchestrator service
State: Persisted in incidents.saga-state topic
```

---

## 11. Testing & Validation

### Load Testing

#### Performance Test Scenarios

```yaml
Scenario 1: Peak Load Simulation
Events/Second: 2M (2x normal load)
Duration: 1 hour
Topics: All production topics
Validation: No message loss, latency < SLA

Scenario 2: Burst Traffic
Events/Second: 5M for 5 minutes
Recovery: Return to normal within 1 minute
Validation: System stability maintained

Scenario 3: Failover Testing
Trigger: Kafka broker failure
Expected: Automatic failover < 30 seconds
Validation: Zero message loss during failover
```

### Chaos Engineering

#### Failure Scenarios

```yaml
Network Partitions:
  - Isolate Kafka broker from cluster
  - Simulate consumer network failures
  - Test cross-region connectivity loss

Resource Exhaustion:
  - Fill Kafka broker disk space
  - Exhaust broker memory
  - CPU spike simulation

Message Corruption:
  - Invalid schema messages
  - Oversized message payloads
  - Network-level corruption simulation
```

### Schema Evolution Testing

#### Compatibility Testing

```yaml
Test Cases:
  - Forward Compatibility: New consumer, old events
  - Backward Compatibility: Old consumer, new events
  - Breaking Changes: Version migration testing
  - Schema Registry: Validation enforcement testing
```

---

## 12. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-4)

- **Kafka Cluster Setup:** Multi-AZ deployment on GCP
- **Basic Topics:** Core domain topics creation
- **Schema Registry:** Setup with basic schemas
- **Security:** mTLS and basic ACLs
- **Monitoring:** Basic broker and topic monitoring

### Phase 2: Domain Integration (Weeks 5-8)

- **Producer Integration:** All microservices publishing events
- **Consumer Implementation:** Basic event consumption patterns
- **Schema Evolution:** Complete schema governance process
- **Error Handling:** DLQ implementation and retry logic
- **Testing:** Load testing and performance validation

### Phase 3: Advanced Features (Weeks 9-12)

- **Stream Processing:** Kafka Streams/Flink integration
- **Cross-Region Replication:** Disaster recovery setup
- **Advanced Monitoring:** Distributed tracing and metrics
- **Security Hardening:** Complete ACL implementation
- **Performance Tuning:** Optimization for 1B+ events/day

### Phase 4: Production Readiness (Weeks 13-16)

- **Chaos Engineering:** Fault tolerance validation
- **Documentation:** Complete operational runbooks
- **Training:** Team education on event-driven patterns
- **Migration:** Production cutover planning
- **Optimization:** Final performance tuning

---

## 13. Success Criteria

### Performance Criteria

- **Throughput:** Sustained 1M+ events/second
- **Latency:** P99 < 100ms end-to-end
- **Availability:** 99.99% uptime
- **Scalability:** Linear scaling validation
- **Resource Efficiency:** < 10% CPU overhead

### Functional Criteria

- **Event Ordering:** Correct ordering within partitions
- **Message Delivery:** Zero message loss under normal operations
- **Schema Evolution:** Seamless backward/forward compatibility
- **Error Handling:** < 0.1% events to DLQ
- **Security:** All events encrypted and access-controlled

### Operational Criteria

- **Monitoring:** Complete observability dashboard
- **Alerting:** Proactive issue detection
- **Documentation:** Complete operational procedures
- **Recovery:** < 1 hour RTO for disaster scenarios
- **Compliance:** Full audit trail for all events

---

**Next Steps:**

- Proceed to Task 26.4: Select and Configure API Gateway Solution
- Begin Kafka cluster provisioning on Google Cloud Platform
- Implement schema registry with initial event schemas
- Set up monitoring and alerting infrastructure
- Plan integration testing with microservice teams
