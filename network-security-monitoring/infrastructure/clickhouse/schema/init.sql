-- iSECTECH Network Security Monitoring - ClickHouse Schema
-- High-performance time-series storage for network flow data
-- Production-ready schema with optimizations for security analytics

-- ═══════════════════════════════════════════════════════════════════════════════
-- DATABASE CREATION
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE DATABASE IF NOT EXISTS nsm_flows;
USE nsm_flows;

-- ═══════════════════════════════════════════════════════════════════════════════
-- MAIN FLOW DATA TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS flow_data (
    -- Temporal information
    timestamp DateTime64(3) COMMENT 'Flow timestamp with millisecond precision',
    start_time DateTime64(3) COMMENT 'Flow start time',
    end_time DateTime64(3) COMMENT 'Flow end time',
    duration_ms UInt32 COMMENT 'Flow duration in milliseconds',
    
    -- Network addressing
    source_ip IPv6 COMMENT 'Source IP address (IPv4 mapped to IPv6)',
    dest_ip IPv6 COMMENT 'Destination IP address (IPv4 mapped to IPv6)',
    source_port UInt16 COMMENT 'Source port number',
    dest_port UInt16 COMMENT 'Destination port number',
    protocol UInt8 COMMENT 'IP protocol number (1=ICMP, 6=TCP, 17=UDP)',
    
    -- Traffic metrics
    packets UInt64 COMMENT 'Total packet count',
    bytes UInt64 COMMENT 'Total byte count',
    packets_reverse UInt64 COMMENT 'Reverse direction packet count',
    bytes_reverse UInt64 COMMENT 'Reverse direction byte count',
    
    -- Flow characteristics
    tcp_flags UInt16 COMMENT 'TCP flags (if applicable)',
    tos UInt8 COMMENT 'Type of Service field',
    tcp_window_size UInt32 COMMENT 'TCP window size',
    tcp_mss UInt16 COMMENT 'TCP Maximum Segment Size',
    
    -- Device and infrastructure
    device_ip IPv6 COMMENT 'Network device IP that reported the flow',
    device_name LowCardinality(String) COMMENT 'Network device hostname',
    input_interface UInt32 COMMENT 'Input interface index',
    output_interface UInt32 COMMENT 'Output interface index',
    vlan_id UInt16 COMMENT 'VLAN identifier',
    
    -- Network topology
    network_segment LowCardinality(String) COMMENT 'Network segment classification',
    flow_direction LowCardinality(String) COMMENT 'Flow direction (inbound, outbound, internal, external)',
    is_internal Bool COMMENT 'True if both endpoints are internal',
    
    -- Geographic and organizational data
    source_country FixedString(2) COMMENT 'Source IP country code (ISO 3166-1)',
    dest_country FixedString(2) COMMENT 'Destination IP country code (ISO 3166-1)',
    source_asn UInt32 COMMENT 'Source Autonomous System Number',
    dest_asn UInt32 COMMENT 'Destination Autonomous System Number',
    source_org LowCardinality(String) COMMENT 'Source organization name',
    dest_org LowCardinality(String) COMMENT 'Destination organization name',
    
    -- Security analytics
    threat_score UInt8 COMMENT 'Threat intelligence score (0-100)',
    risk_level Enum8('unknown'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) COMMENT 'Risk classification',
    security_tags Array(LowCardinality(String)) COMMENT 'Security-related tags',
    ioc_matches Array(String) COMMENT 'Threat intelligence IOC matches',
    behavioral_flags Array(LowCardinality(String)) COMMENT 'Behavioral analysis flags',
    
    -- Application and service identification
    application LowCardinality(String) COMMENT 'Identified application protocol',
    service_name LowCardinality(String) COMMENT 'Identified service name',
    user_agent String COMMENT 'HTTP User-Agent string (if applicable)',
    
    -- Performance metrics
    packets_per_second Float32 COMMENT 'Average packets per second',
    bytes_per_second Float64 COMMENT 'Average bytes per second',
    round_trip_time Float32 COMMENT 'Estimated round-trip time (ms)',
    
    -- Quality indicators
    packet_loss_percent Float32 COMMENT 'Estimated packet loss percentage',
    out_of_order_packets UInt32 COMMENT 'Out-of-order packet count',
    retransmitted_packets UInt32 COMMENT 'Retransmitted packet count',
    
    -- Compliance and auditing
    compliance_tags Array(LowCardinality(String)) COMMENT 'Compliance-related tags (PCI, HIPAA, etc.)',
    data_classification LowCardinality(String) COMMENT 'Data sensitivity classification',
    retention_policy LowCardinality(String) COMMENT 'Data retention policy applied',
    
    -- Processing metadata
    collector_id LowCardinality(String) COMMENT 'Flow collector identifier',
    processing_time DateTime64(3) COMMENT 'When flow was processed',
    processing_latency_ms UInt32 COMMENT 'Processing latency in milliseconds',
    flow_version UInt8 COMMENT 'Flow record format version',
    
    -- Environment and tenant information
    environment LowCardinality(String) COMMENT 'Environment (production, staging, dev)',
    tenant_id LowCardinality(String) COMMENT 'Multi-tenant identifier',
    
    -- Hash for deduplication
    flow_hash UInt64 COMMENT 'Hash for flow deduplication'
    
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip, dest_ip, source_port, dest_port)
TTL timestamp + INTERVAL 90 DAY
SETTINGS 
    index_granularity = 8192,
    ttl_only_drop_parts = 1,
    merge_with_ttl_timeout = 3600,
    storage_policy = 'hot_to_cold';

-- ═══════════════════════════════════════════════════════════════════════════════
-- AGGREGATED FLOW ANALYTICS TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS flow_analytics (
    time_bucket DateTime COMMENT 'Time bucket (1-minute intervals)',
    source_ip IPv6 COMMENT 'Source IP address',
    dest_ip IPv6 COMMENT 'Destination IP address',
    protocol UInt8 COMMENT 'IP protocol number',
    
    -- Aggregated metrics
    total_flows UInt64 COMMENT 'Total number of flows',
    total_packets UInt64 COMMENT 'Total packet count',
    total_bytes UInt64 COMMENT 'Total byte count',
    avg_duration_ms Float32 COMMENT 'Average flow duration',
    max_threat_score UInt8 COMMENT 'Maximum threat score',
    unique_dest_ports Array(UInt16) COMMENT 'Unique destination ports',
    
    -- Security aggregations
    security_tags Array(LowCardinality(String)) COMMENT 'All security tags',
    risk_levels Array(UInt8) COMMENT 'All risk levels seen',
    ioc_count UInt32 COMMENT 'Total IOC matches',
    
    -- Behavioral patterns
    flow_pattern LowCardinality(String) COMMENT 'Identified flow pattern',
    connection_state LowCardinality(String) COMMENT 'Connection state analysis',
    
    -- Geographic distribution
    source_countries Array(FixedString(2)) COMMENT 'Source countries seen',
    dest_countries Array(FixedString(2)) COMMENT 'Destination countries seen',
    
    -- Device and network information
    devices Array(LowCardinality(String)) COMMENT 'Reporting devices',
    network_segments Array(LowCardinality(String)) COMMENT 'Network segments involved'
    
) ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(time_bucket)
ORDER BY (time_bucket, source_ip, dest_ip, protocol)
TTL time_bucket + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ═══════════════════════════════════════════════════════════════════════════════
-- MATERIALIZED VIEW FOR REAL-TIME ANALYTICS
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE MATERIALIZED VIEW IF NOT EXISTS flow_analytics_mv TO flow_analytics
AS SELECT
    toStartOfMinute(timestamp) as time_bucket,
    source_ip,
    dest_ip,
    protocol,
    
    count() as total_flows,
    sum(packets) as total_packets,
    sum(bytes) as total_bytes,
    avg(duration_ms) as avg_duration_ms,
    max(threat_score) as max_threat_score,
    groupUniqArray(dest_port) as unique_dest_ports,
    
    groupUniqArray(security_tags) as security_tags,
    groupArray(risk_level) as risk_levels,
    sum(length(ioc_matches)) as ioc_count,
    
    any(flow_direction) as flow_pattern,
    any(if(tcp_flags > 0, 'tcp_connection', 'other')) as connection_state,
    
    groupUniqArray(source_country) as source_countries,
    groupUniqArray(dest_country) as dest_countries,
    
    groupUniqArray(device_name) as devices,
    groupUniqArray(network_segment) as network_segments
    
FROM flow_data
GROUP BY time_bucket, source_ip, dest_ip, protocol;

-- ═══════════════════════════════════════════════════════════════════════════════
-- THREAT INTELLIGENCE TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS threat_intelligence (
    indicator String COMMENT 'Threat indicator (IP, domain, hash, etc.)',
    indicator_type LowCardinality(String) COMMENT 'Type of indicator (ip, domain, hash, url)',
    threat_type LowCardinality(String) COMMENT 'Type of threat (malware, c2, phishing, etc.)',
    confidence UInt8 COMMENT 'Confidence level (0-100)',
    severity LowCardinality(String) COMMENT 'Severity level (low, medium, high, critical)',
    
    -- Source information
    source LowCardinality(String) COMMENT 'Threat intelligence source',
    feed_name LowCardinality(String) COMMENT 'Specific feed name',
    
    -- Temporal information
    first_seen DateTime COMMENT 'First time indicator was seen',
    last_seen DateTime COMMENT 'Last time indicator was seen',
    created_date DateTime COMMENT 'When record was created',
    expires_date DateTime COMMENT 'When indicator expires',
    
    -- Additional context
    description String COMMENT 'Human-readable description',
    tags Array(LowCardinality(String)) COMMENT 'Associated tags',
    kill_chain_phases Array(LowCardinality(String)) COMMENT 'MITRE kill chain phases',
    
    -- Metadata
    tlp_level LowCardinality(String) COMMENT 'Traffic Light Protocol level',
    is_active Bool COMMENT 'Whether indicator is currently active'
    
) ENGINE = ReplacingMergeTree(last_seen)
PARTITION BY toYYYYMM(created_date)
ORDER BY (indicator_type, indicator, source)
TTL expires_date
SETTINGS index_granularity = 8192;

-- ═══════════════════════════════════════════════════════════════════════════════
-- SECURITY EVENTS TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS security_events (
    event_id String COMMENT 'Unique event identifier',
    timestamp DateTime64(3) COMMENT 'Event timestamp',
    
    -- Source information
    source_system LowCardinality(String) COMMENT 'System that generated the event',
    event_type LowCardinality(String) COMMENT 'Type of security event',
    event_category LowCardinality(String) COMMENT 'Event category',
    
    -- Network context
    source_ip IPv6 COMMENT 'Source IP address',
    dest_ip IPv6 COMMENT 'Destination IP address',
    source_port UInt16 COMMENT 'Source port',
    dest_port UInt16 COMMENT 'Destination port',
    protocol UInt8 COMMENT 'IP protocol',
    
    -- Event details
    severity LowCardinality(String) COMMENT 'Event severity',
    confidence UInt8 COMMENT 'Detection confidence (0-100)',
    rule_id String COMMENT 'Detection rule identifier',
    rule_name String COMMENT 'Detection rule name',
    message String COMMENT 'Event message/description',
    
    -- Flow correlation
    flow_hash UInt64 COMMENT 'Associated flow hash',
    session_id String COMMENT 'Session identifier',
    
    -- MITRE ATT&CK mapping
    attack_tactics Array(LowCardinality(String)) COMMENT 'MITRE ATT&CK tactics',
    attack_techniques Array(LowCardinality(String)) COMMENT 'MITRE ATT&CK techniques',
    
    -- Response information
    action_taken LowCardinality(String) COMMENT 'Action taken in response',
    status LowCardinality(String) COMMENT 'Event status (open, investigating, closed)',
    
    -- Additional metadata
    tags Array(LowCardinality(String)) COMMENT 'Event tags',
    custom_fields Map(String, String) COMMENT 'Custom key-value fields'
    
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip, dest_ip, event_type)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ═══════════════════════════════════════════════════════════════════════════════
-- ASSET INVENTORY TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS asset_inventory (
    ip_address IPv6 COMMENT 'Asset IP address',
    mac_address String COMMENT 'MAC address',
    hostname String COMMENT 'Asset hostname',
    
    -- Classification
    asset_type LowCardinality(String) COMMENT 'Type of asset (server, workstation, iot, etc.)',
    operating_system LowCardinality(String) COMMENT 'Operating system',
    os_version String COMMENT 'OS version',
    
    -- Network information
    network_segment LowCardinality(String) COMMENT 'Network segment',
    vlan_id UInt16 COMMENT 'VLAN ID',
    subnet String COMMENT 'Subnet',
    
    -- Business context
    business_unit LowCardinality(String) COMMENT 'Business unit',
    asset_owner String COMMENT 'Asset owner',
    criticality LowCardinality(String) COMMENT 'Business criticality',
    
    -- Security posture
    security_zone LowCardinality(String) COMMENT 'Security zone',
    compliance_scope Array(LowCardinality(String)) COMMENT 'Compliance requirements',
    vulnerability_score UInt8 COMMENT 'Vulnerability score (0-100)',
    
    -- Temporal information
    first_seen DateTime COMMENT 'First discovery time',
    last_seen DateTime COMMENT 'Last seen time',
    last_updated DateTime COMMENT 'Last inventory update',
    
    -- Services and ports
    open_ports Array(UInt16) COMMENT 'Known open ports',
    services Array(String) COMMENT 'Identified services',
    
    -- Tags and metadata
    tags Array(LowCardinality(String)) COMMENT 'Asset tags',
    is_active Bool COMMENT 'Whether asset is currently active'
    
) ENGINE = ReplacingMergeTree(last_updated)
PARTITION BY toYYYYMM(last_updated)
ORDER BY (ip_address, asset_type)
SETTINGS index_granularity = 8192;

-- ═══════════════════════════════════════════════════════════════════════════════
-- INDEXES FOR PERFORMANCE OPTIMIZATION
-- ═══════════════════════════════════════════════════════════════════════════════

-- Indexes on flow_data for common queries
ALTER TABLE flow_data ADD INDEX idx_source_ip_timestamp source_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE flow_data ADD INDEX idx_dest_ip_timestamp dest_ip TYPE bloom_filter GRANULARITY 4;
ALTER TABLE flow_data ADD INDEX idx_threat_score threat_score TYPE minmax GRANULARITY 8;
ALTER TABLE flow_data ADD INDEX idx_security_tags arrayConcat(security_tags) TYPE bloom_filter GRANULARITY 4;
ALTER TABLE flow_data ADD INDEX idx_application application TYPE set(1000) GRANULARITY 8;

-- Indexes on threat_intelligence for rapid lookups
ALTER TABLE threat_intelligence ADD INDEX idx_indicator indicator TYPE bloom_filter GRANULARITY 1;
ALTER TABLE threat_intelligence ADD INDEX idx_indicator_type indicator_type TYPE set(100) GRANULARITY 1;

-- ═══════════════════════════════════════════════════════════════════════════════
-- STORAGE POLICIES FOR TIERED STORAGE
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create storage policy for hot/warm/cold data lifecycle
-- (This would be configured in ClickHouse config.xml)

-- ═══════════════════════════════════════════════════════════════════════════════
-- VIEWS FOR COMMON QUERIES
-- ═══════════════════════════════════════════════════════════════════════════════

-- High-risk flows view
CREATE VIEW IF NOT EXISTS high_risk_flows AS
SELECT 
    timestamp,
    source_ip,
    dest_ip,
    source_port,
    dest_port,
    protocol,
    threat_score,
    risk_level,
    security_tags,
    ioc_matches,
    packets,
    bytes
FROM flow_data
WHERE threat_score >= 70 OR risk_level IN ('high', 'critical')
ORDER BY timestamp DESC;

-- External communication view
CREATE VIEW IF NOT EXISTS external_communication AS
SELECT 
    timestamp,
    source_ip,
    dest_ip,
    source_port,
    dest_port,
    protocol,
    source_country,
    dest_country,
    application,
    threat_score,
    packets,
    bytes
FROM flow_data
WHERE is_internal = 0
ORDER BY timestamp DESC;

-- Top talkers view (last 24 hours)
CREATE VIEW IF NOT EXISTS top_talkers_24h AS
SELECT 
    source_ip,
    count() as flow_count,
    sum(packets) as total_packets,
    sum(bytes) as total_bytes,
    uniq(dest_ip) as unique_destinations,
    max(threat_score) as max_threat_score
FROM flow_data
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY source_ip
ORDER BY total_bytes DESC
LIMIT 100;

-- Security events summary view
CREATE VIEW IF NOT EXISTS security_events_summary AS
SELECT 
    toStartOfHour(timestamp) as hour,
    event_type,
    severity,
    count() as event_count,
    uniq(source_ip) as unique_sources,
    uniq(dest_ip) as unique_destinations
FROM security_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY hour, event_type, severity
ORDER BY hour DESC, event_count DESC;

-- ═══════════════════════════════════════════════════════════════════════════════
-- FUNCTIONS FOR COMMON CALCULATIONS
-- ═══════════════════════════════════════════════════════════════════════════════

-- Function to calculate risk score based on multiple factors
-- (This would be implemented as a custom function or in application logic)

-- ═══════════════════════════════════════════════════════════════════════════════
-- SAMPLE DATA INSERTION (FOR TESTING)
-- ═══════════════════════════════════════════════════════════════════════════════

-- Insert sample threat intelligence data
INSERT INTO threat_intelligence VALUES
('192.168.1.100', 'ip', 'c2', 85, 'high', 'internal_analysis', 'iSECTECH', 
 '2024-01-01 00:00:00', '2024-01-03 12:00:00', '2024-01-01 00:00:00', '2024-12-31 23:59:59',
 'Known C2 server for APT group', ['apt', 'c2', 'malware'], ['command-and-control'], 'amber', true);

-- Insert sample asset data
INSERT INTO asset_inventory VALUES
(toIPv6('192.168.1.10'), '00:11:22:33:44:55', 'workstation-01.isectech.local',
 'workstation', 'Windows', '10 Pro', 'corporate_workstations', 100, '192.168.1.0/24',
 'IT', 'john.doe@isectech.com', 'medium', 'trusted', ['PCI-DSS'], 25,
 '2024-01-01 08:00:00', '2024-01-03 17:30:00', '2024-01-03 18:00:00',
 [80, 443, 135, 445], ['http', 'https', 'rpc', 'smb'], ['corporate', 'managed'], true);

-- ═══════════════════════════════════════════════════════════════════════════════
-- MAINTENANCE PROCEDURES
-- ═══════════════════════════════════════════════════════════════════════════════

-- Optimize tables (run periodically)
-- OPTIMIZE TABLE flow_data FINAL;
-- OPTIMIZE TABLE flow_analytics FINAL;
-- OPTIMIZE TABLE threat_intelligence FINAL;
-- OPTIMIZE TABLE security_events FINAL;

-- Check table sizes and performance
-- SELECT table, formatReadableSize(total_bytes) as size FROM system.tables WHERE database = 'nsm_flows';

-- Monitor query performance
-- SELECT query, query_duration_ms, memory_usage FROM system.query_log WHERE type = 'QueryFinish' ORDER BY query_start_time DESC LIMIT 10;

-- ═══════════════════════════════════════════════════════════════════════════════
-- BACKUP AND RECOVERY
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create backup
-- BACKUP TABLE nsm_flows.flow_data TO Disk('backup_disk', 'nsm_flows_backup_{uuid}');

-- Restore from backup
-- RESTORE TABLE nsm_flows.flow_data FROM Disk('backup_disk', 'nsm_flows_backup_{uuid}');

-- ═══════════════════════════════════════════════════════════════════════════════
-- MONITORING QUERIES
-- ═══════════════════════════════════════════════════════════════════════════════

-- Monitor ingestion rate
-- SELECT toStartOfMinute(timestamp) as minute, count() as flows_per_minute FROM flow_data WHERE timestamp >= now() - INTERVAL 1 HOUR GROUP BY minute ORDER BY minute;

-- Monitor threat detection
-- SELECT threat_score, count() as flow_count FROM flow_data WHERE timestamp >= now() - INTERVAL 1 HOUR GROUP BY threat_score ORDER BY threat_score DESC;

-- Monitor storage utilization
-- SELECT formatReadableSize(sum(bytes_on_disk)) as total_size FROM system.parts WHERE database = 'nsm_flows';

-- Check data quality
-- SELECT count() as total_flows, countIf(source_ip = '::') as invalid_source_ip, countIf(dest_ip = '::') as invalid_dest_ip FROM flow_data WHERE timestamp >= now() - INTERVAL 1 HOUR;