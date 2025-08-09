# iSECTECH SIEM Integration for Zeek
# Real-time security event forwarding and enrichment for SIEM platforms

module iSECTECH;

export {
    ## SIEM platform types
    type SIEMPlatform: enum {
        SPLUNK,
        ELASTIC_STACK,
        QRADAR,
        ARCSIGHT,
        SENTINEL,
        CHRONICLE,
        SUMO_LOGIC,
        LOGRHYTHM,
        CUSTOM
    };

    ## Event severity mapping for SIEM
    type SIEMSeverity: enum {
        INFORMATIONAL,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };

    ## Common Event Format for SIEM
    type SIEMEvent: record {
        timestamp: time &log;
        event_id: string &log;
        source_system: string &log;
        event_type: string &log;
        severity: string &log;
        source_ip: addr &log &optional;
        destination_ip: addr &log &optional;
        source_port: port &log &optional;
        destination_port: port &log &optional;
        protocol: string &log &optional;
        user_name: string &log &optional;
        event_description: string &log;
        raw_data: string &log &optional;
        threat_indicators: vector of string &log &optional;
        mitre_tactics: set[string] &log &optional;
        mitre_techniques: set[string] &log &optional;
        confidence_score: count &log &optional;
        asset_criticality: string &log &optional;
        geo_location: string &log &optional;
        network_segment: string &log &optional;
        correlation_id: string &log &optional;
    };

    ## Log stream for SIEM events
    redef enum Log::ID += { SIEM_EVENTS_LOG };

    ## Configuration options
    option siem_platform: SIEMPlatform = ELASTIC_STACK;
    option enable_real_time_forwarding: bool = T;
    option enable_event_enrichment: bool = T;
    option enable_correlation: bool = T;
    option batch_size: count = 100;
    option batch_timeout: interval = 30sec;
    option include_raw_logs: bool = F;
    option siem_endpoints: set[string] = { "siem-collector-01:514", "siem-collector-02:514" };
}

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT CORRELATION AND TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

type CorrelationContext: record {
    session_id: string;
    related_events: vector of string;
    start_time: time;
    last_activity: time;
    event_count: count;
    severity_score: count;
    threat_actors: set[string];
    affected_assets: set[addr];
    attack_stages: set[string];
};

global correlation_sessions: table[string] of CorrelationContext;
global event_buffer: vector of SIEMEvent;
global event_counter: count = 0;

# ═══════════════════════════════════════════════════════════════════════════════
# ASSET CLASSIFICATION AND ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

type AssetInfo: record {
    ip_address: addr;
    hostname: string;
    asset_type: string;
    criticality: string;
    owner: string;
    location: string;
    network_segment: string;
    os_type: string;
    services: set[string];
    tags: set[string];
};

# Asset inventory (would typically be loaded from CMDB)
global asset_inventory: table[addr] of AssetInfo = {
    [10.0.1.10] = AssetInfo(
        $ip_address = 10.0.1.10,
        $hostname = "dc01.isectech.local",
        $asset_type = "Domain Controller",
        $criticality = "CRITICAL",
        $owner = "IT Infrastructure",
        $location = "DataCenter-A",
        $network_segment = "Server_VLAN",
        $os_type = "Windows Server 2019",
        $services = set("AD", "DNS", "LDAP"),
        $tags = set("critical", "infrastructure", "windows")
    ),
    [10.0.2.50] = AssetInfo(
        $ip_address = 10.0.2.50,
        $hostname = "db01.isectech.local",
        $asset_type = "Database Server",
        $criticality = "HIGH",
        $owner = "Database Team",
        $location = "DataCenter-A",
        $network_segment = "Database_VLAN",
        $os_type = "Ubuntu 20.04 LTS",
        $services = set("MySQL", "PostgreSQL"),
        $tags = set("database", "production", "linux")
    )
};

# ═══════════════════════════════════════════════════════════════════════════════
# SIEM EVENT GENERATION AND ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

function create_siem_event(event_type: string, severity: SIEMSeverity, description: string,
                          source_ip: addr &default=0.0.0.0,
                          dest_ip: addr &default=0.0.0.0,
                          source_port: port &default=0/tcp,
                          dest_port: port &default=0/tcp,
                          protocol: string &default="",
                          user_name: string &default="",
                          threat_indicators: vector of string &default=vector(),
                          mitre_tactics: set[string] &default=set(),
                          mitre_techniques: set[string] &default=set(),
                          confidence_score: count &default=0,
                          raw_data: string &default=""): SIEMEvent
{
    # Generate unique event ID
    event_counter += 1;
    local event_id = fmt("ISEC-%d-%d", double_to_count(network_time()), event_counter);
    
    # Create base SIEM event
    local siem_event = SIEMEvent(
        $timestamp = network_time(),
        $event_id = event_id,
        $source_system = "iSECTECH-NSM",
        $event_type = event_type,
        $severity = fmt("%s", severity),
        $event_description = description
    );
    
    # Add optional fields
    if (source_ip != 0.0.0.0)
        siem_event$source_ip = source_ip;
    if (dest_ip != 0.0.0.0)
        siem_event$destination_ip = dest_ip;
    if (source_port != 0/tcp)
        siem_event$source_port = source_port;
    if (dest_port != 0/tcp)
        siem_event$destination_port = dest_port;
    if (protocol != "")
        siem_event$protocol = protocol;
    if (user_name != "")
        siem_event$user_name = user_name;
    if (|threat_indicators| > 0)
        siem_event$threat_indicators = threat_indicators;
    if (|mitre_tactics| > 0)
        siem_event$mitre_tactics = mitre_tactics;
    if (|mitre_techniques| > 0)
        siem_event$mitre_techniques = mitre_techniques;
    if (confidence_score > 0)
        siem_event$confidence_score = confidence_score;
    if (include_raw_logs && raw_data != "")
        siem_event$raw_data = raw_data;
    
    # Enrich with asset information
    if (enable_event_enrichment) {
        enrich_siem_event(siem_event);
    }
    
    return siem_event;
}

function enrich_siem_event(siem_event: SIEMEvent)
{
    # Enrich with source asset information
    if (siem_event?$source_ip && siem_event$source_ip in asset_inventory) {
        local src_asset = asset_inventory[siem_event$source_ip];
        siem_event$asset_criticality = src_asset$criticality;
        siem_event$network_segment = src_asset$network_segment;
        
        # Add geo-location if available
        siem_event$geo_location = src_asset$location;
    }
    
    # Enrich with destination asset information if source not found
    if (!siem_event?$asset_criticality && siem_event?$destination_ip && 
        siem_event$destination_ip in asset_inventory) {
        local dst_asset = asset_inventory[siem_event$destination_ip];
        siem_event$asset_criticality = dst_asset$criticality;
        siem_event$network_segment = dst_asset$network_segment;
        siem_event$geo_location = dst_asset$location;
    }
    
    # Add correlation ID if part of ongoing incident
    if (enable_correlation) {
        add_correlation_context(siem_event);
    }
}

function add_correlation_context(siem_event: SIEMEvent)
{
    # Simple correlation based on source IP and time proximity
    if (!siem_event?$source_ip)
        return;
    
    local correlation_key = fmt("%s", siem_event$source_ip);
    local current_time = network_time();
    
    # Check for existing correlation session
    local found_session = F;
    for (session_id in correlation_sessions) {
        local session = correlation_sessions[session_id];
        
        # Check if this event belongs to an existing session (within 1 hour)
        if (current_time - session$last_activity < 1hr) {
            if (siem_event$source_ip in session$affected_assets ||
                (siem_event?$destination_ip && siem_event$destination_ip in session$affected_assets)) {
                
                # Add event to existing session
                session$related_events += siem_event$event_id;
                session$last_activity = current_time;
                session$event_count += 1;
                
                # Update severity score
                local event_severity_score = get_severity_score(siem_event$severity);
                session$severity_score = max(session$severity_score, event_severity_score);
                
                # Add affected assets
                if (siem_event?$source_ip)
                    add session$affected_assets[siem_event$source_ip];
                if (siem_event?$destination_ip)
                    add session$affected_assets[siem_event$destination_ip];
                
                siem_event$correlation_id = session_id;
                correlation_sessions[session_id] = session;
                found_session = T;
                break;
            }
        }
    }
    
    # Create new correlation session if none found
    if (!found_session && get_severity_score(siem_event$severity) >= 3) {
        local new_session_id = fmt("CORR-%d-%s", double_to_count(current_time), correlation_key);
        
        local new_session = CorrelationContext(
            $session_id = new_session_id,
            $related_events = vector(siem_event$event_id),
            $start_time = current_time,
            $last_activity = current_time,
            $event_count = 1,
            $severity_score = get_severity_score(siem_event$severity),
            $threat_actors = set(),
            $affected_assets = set(),
            $attack_stages = set()
        );
        
        if (siem_event?$source_ip)
            add new_session$affected_assets[siem_event$source_ip];
        if (siem_event?$destination_ip)
            add new_session$affected_assets[siem_event$destination_ip];
        
        correlation_sessions[new_session_id] = new_session;
        siem_event$correlation_id = new_session_id;
    }
}

function get_severity_score(severity: string): count
{
    switch (severity) {
        case "INFORMATIONAL":
            return 1;
        case "LOW":
            return 2;
        case "MEDIUM":
            return 3;
        case "HIGH":
            return 4;
        case "CRITICAL":
            return 5;
        default:
            return 0;
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT FORWARDING AND BATCHING
# ═══════════════════════════════════════════════════════════════════════════════

function queue_siem_event(siem_event: SIEMEvent)
{
    # Add event to buffer
    event_buffer += siem_event;
    
    # Write to log immediately
    Log::write(SIEM_EVENTS_LOG, siem_event);
    
    # Check if buffer should be flushed
    if (|event_buffer| >= batch_size) {
        flush_event_buffer();
    }
}

function flush_event_buffer()
{
    if (|event_buffer| == 0)
        return;
    
    if (enable_real_time_forwarding) {
        forward_events_to_siem(event_buffer);
    }
    
    # Clear buffer
    event_buffer = vector();
}

function forward_events_to_siem(events: vector of SIEMEvent)
{
    # Format events based on SIEM platform
    local formatted_events = format_events_for_siem(events);
    
    # Send to configured SIEM endpoints
    for (endpoint in siem_endpoints) {
        send_to_siem_endpoint(endpoint, formatted_events);
    }
    
    print fmt("Forwarded %d events to SIEM platform", |events|);
}

function format_events_for_siem(events: vector of SIEMEvent): string
{
    local formatted = "";
    
    switch (siem_platform) {
        case SPLUNK:
            formatted = format_splunk_events(events);
            break;
        case ELASTIC_STACK:
            formatted = format_elastic_events(events);
            break;
        case QRADAR:
            formatted = format_qradar_events(events);
            break;
        default:
            formatted = format_json_events(events);
            break;
    }
    
    return formatted;
}

function format_splunk_events(events: vector of SIEMEvent): string
{
    local splunk_format = "";
    
    for (idx in events) {
        local event = events[idx];
        
        # Splunk key-value format
        splunk_format += fmt("timestamp=\"%s\" ", strftime("%Y-%m-%d %H:%M:%S", event$timestamp));
        splunk_format += fmt("event_id=\"%s\" ", event$event_id);
        splunk_format += fmt("source_system=\"%s\" ", event$source_system);
        splunk_format += fmt("event_type=\"%s\" ", event$event_type);
        splunk_format += fmt("severity=\"%s\" ", event$severity);
        splunk_format += fmt("description=\"%s\" ", event$event_description);
        
        if (event?$source_ip)
            splunk_format += fmt("src_ip=\"%s\" ", event$source_ip);
        if (event?$destination_ip)
            splunk_format += fmt("dest_ip=\"%s\" ", event$destination_ip);
        if (event?$source_port)
            splunk_format += fmt("src_port=\"%s\" ", event$source_port);
        if (event?$destination_port)
            splunk_format += fmt("dest_port=\"%s\" ", event$destination_port);
        
        splunk_format += "\n";
    }
    
    return splunk_format;
}

function format_elastic_events(events: vector of SIEMEvent): string
{
    local elastic_format = "";
    
    for (idx in events) {
        local event = events[idx];
        
        # Elasticsearch JSON format
        elastic_format += "{";
        elastic_format += fmt("\"@timestamp\":\"%s\",", strftime("%Y-%m-%dT%H:%M:%S.000Z", event$timestamp));
        elastic_format += fmt("\"event_id\":\"%s\",", event$event_id);
        elastic_format += fmt("\"source_system\":\"%s\",", event$source_system);
        elastic_format += fmt("\"event_type\":\"%s\",", event$event_type);
        elastic_format += fmt("\"severity\":\"%s\",", event$severity);
        elastic_format += fmt("\"description\":\"%s\"", event$event_description);
        
        if (event?$source_ip)
            elastic_format += fmt(",\"source_ip\":\"%s\"", event$source_ip);
        if (event?$destination_ip)
            elastic_format += fmt(",\"destination_ip\":\"%s\"", event$destination_ip);
        if (event?$correlation_id)
            elastic_format += fmt(",\"correlation_id\":\"%s\"", event$correlation_id);
        
        elastic_format += "}\n";
    }
    
    return elastic_format;
}

function format_qradar_events(events: vector of SIEMEvent): string
{
    # QRadar LEEF format
    local qradar_format = "";
    
    for (idx in events) {
        local event = events[idx];
        
        qradar_format += "LEEF:2.0|iSECTECH|NSM|1.0|";
        qradar_format += fmt("%s|", event$event_type);
        qradar_format += fmt("devTime=%s|", strftime("%Y-%m-%d %H:%M:%S", event$timestamp));
        qradar_format += fmt("severity=%s|", event$severity);
        qradar_format += fmt("msg=%s|", event$event_description);
        
        if (event?$source_ip)
            qradar_format += fmt("src=%s|", event$source_ip);
        if (event?$destination_ip)
            qradar_format += fmt("dst=%s|", event$destination_ip);
        
        qradar_format += "\n";
    }
    
    return qradar_format;
}

function format_json_events(events: vector of SIEMEvent): string
{
    # Generic JSON format
    local json_format = "[";
    
    for (idx in events) {
        local event = events[idx];
        
        if (idx > 0)
            json_format += ",";
        
        json_format += "{";
        json_format += fmt("\"timestamp\":\"%s\",", strftime("%Y-%m-%dT%H:%M:%S.000Z", event$timestamp));
        json_format += fmt("\"event_id\":\"%s\",", event$event_id);
        json_format += fmt("\"source_system\":\"%s\",", event$source_system);
        json_format += fmt("\"event_type\":\"%s\",", event$event_type);
        json_format += fmt("\"severity\":\"%s\",", event$severity);
        json_format += fmt("\"description\":\"%s\"", event$event_description);
        json_format += "}";
    }
    
    json_format += "]";
    return json_format;
}

function send_to_siem_endpoint(endpoint: string, data: string)
{
    # This would typically use a network client to send data
    # For now, simulate successful transmission
    print fmt("Sending %d bytes to SIEM endpoint: %s", |data|, endpoint);
}

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT HANDLERS FOR DIFFERENT ZEEK MODULES
# ═══════════════════════════════════════════════════════════════════════════════

# Threat detection events
event iSECTECH::threat_detected(c: connection, threat: ConnectionThreat)
{
    local siem_event = create_siem_event(
        "THREAT_DETECTION",
        threat$threat_level == CRITICAL ? CRITICAL : HIGH,
        fmt("Threat detected: %s (Score: %d)", threat$threat_level, threat$threat_score),
        $source_ip = c$id$orig_h,
        $dest_ip = c$id$resp_h,
        $source_port = c$id$orig_p,
        $dest_port = c$id$resp_p,
        $threat_indicators = threat$indicators,
        $mitre_tactics = threat$mitre_tactics,
        $mitre_techniques = threat$mitre_techniques,
        $confidence_score = threat$threat_score
    );
    
    queue_siem_event(siem_event);
}

# Data exfiltration events
event iSECTECH::data_exfiltration_detected(c: connection, exfil: DataExfiltration)
{
    local severity_level = exfil$confidence >= 80 ? CRITICAL : HIGH;
    
    local siem_event = create_siem_event(
        "DATA_EXFILTRATION",
        severity_level,
        fmt("Data exfiltration detected: %s", exfil$description),
        $source_ip = c$id$orig_h,
        $dest_ip = c$id$resp_h,
        $source_port = c$id$orig_p,
        $dest_port = c$id$resp_p,
        $threat_indicators = exfil$indicators,
        $confidence_score = exfil$confidence
    );
    
    queue_siem_event(siem_event);
}

# Lateral movement events
event iSECTECH::lateral_movement_detected(c: connection, movement: LateralMovement)
{
    local severity_level = movement$confidence >= 70 ? HIGH : MEDIUM;
    
    local siem_event = create_siem_event(
        "LATERAL_MOVEMENT",
        severity_level,
        fmt("Lateral movement detected: %s", movement$description),
        $source_ip = movement$source_host,
        $dest_ip = movement$target_host,
        $threat_indicators = movement$indicators,
        $confidence_score = movement$confidence
    );
    
    if (movement?$mitre_technique)
        siem_event$mitre_techniques = set(movement$mitre_technique);
    
    queue_siem_event(siem_event);
}

# C2 detection events
event iSECTECH::c2_detected(c: connection, detection: C2Detection)
{
    local severity_level = detection$confidence >= 80 ? CRITICAL : HIGH;
    
    local siem_event = create_siem_event(
        "C2_COMMUNICATION",
        severity_level,
        fmt("C2 communication detected: %s", detection$description),
        $source_ip = c$id$orig_h,
        $dest_ip = c$id$resp_h,
        $source_port = c$id$orig_p,
        $dest_port = c$id$resp_p,
        $threat_indicators = detection$indicators,
        $confidence_score = detection$confidence
    );
    
    if (detection?$mitre_technique)
        siem_event$mitre_techniques = set(detection$mitre_technique);
    
    queue_siem_event(siem_event);
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND MAINTENANCE
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(SIEM_EVENTS_LOG, [$columns=SIEMEvent, $path="siem_events"]);
    print fmt("iSECTECH SIEM Integration Module loaded (Platform: %s)", siem_platform);
    
    # Schedule periodic buffer flush
    schedule batch_timeout { buffer_flush_timer() };
}

event buffer_flush_timer()
{
    flush_event_buffer();
    
    # Schedule next flush
    schedule batch_timeout { buffer_flush_timer() };
}

# Cleanup old correlation sessions
event correlation_cleanup_timer()
{
    local cutoff_time = network_time() - 24hr;
    local cleaned_count = 0;
    
    for (session_id in correlation_sessions) {
        if (correlation_sessions[session_id]$last_activity < cutoff_time) {
            delete correlation_sessions[session_id];
            cleaned_count += 1;
        }
    }
    
    if (cleaned_count > 0) {
        print fmt("Cleaned up %d old correlation sessions", cleaned_count);
    }
    
    # Schedule next cleanup
    schedule 6hr { correlation_cleanup_timer() };
}

event zeek_init() &priority=-10
{
    # Start correlation cleanup timer
    schedule 6hr { correlation_cleanup_timer() };
}