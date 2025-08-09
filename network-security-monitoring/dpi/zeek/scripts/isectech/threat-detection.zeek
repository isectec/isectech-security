# iSECTECH Advanced Threat Detection for Zeek
# Production-grade threat analysis and behavioral detection

module iSECTECH;

export {
    ## Threat scoring levels
    type ThreatLevel: enum {
        LOW,
        MEDIUM, 
        HIGH,
        CRITICAL
    };

    ## Threat categories
    type ThreatCategory: enum {
        MALWARE,
        C2_COMMUNICATION,
        DATA_EXFILTRATION,
        LATERAL_MOVEMENT,
        RECONNAISSANCE,
        EXPLOITATION,
        PERSISTENCE,
        PRIVILEGE_ESCALATION,
        DEFENSE_EVASION,
        CREDENTIAL_ACCESS,
        DISCOVERY,
        COLLECTION,
        COMMAND_CONTROL,
        IMPACT
    };

    ## iSECTECH threat intelligence record
    type ThreatIntel: record {
        indicator: string;
        threat_type: ThreatCategory;
        confidence: count;
        severity: ThreatLevel;
        source: string;
        description: string;
        first_seen: time;
        last_seen: time;
        tags: set[string];
    };

    ## Connection threat assessment
    type ConnectionThreat: record {
        uid: string;
        threat_score: count;
        threat_level: ThreatLevel;
        threat_categories: set[ThreatCategory];
        indicators: vector of string;
        behavioral_flags: set[string];
        risk_factors: vector of string;
        mitre_tactics: set[string];
        mitre_techniques: set[string];
    };

    ## Log stream for threat events
    redef enum Log::ID += { THREAT_LOG };

    ## Threat detection log record
    type ThreatInfo: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        threat_score: count &log;
        threat_level: string &log;
        threat_categories: set[string] &log;
        indicators: vector of string &log;
        behavioral_flags: set[string] &log;
        risk_factors: vector of string &log;
        mitre_tactics: set[string] &log;
        mitre_techniques: set[string] &log;
        payload_analysis: string &log &optional;
        geo_risk: string &log &optional;
        reputation_score: count &log &optional;
    };

    ## Events for threat detection
    global threat_detected: event(c: connection, threat: ConnectionThreat);
    global high_threat_detected: event(c: connection, threat: ConnectionThreat);
    global critical_threat_detected: event(c: connection, threat: ConnectionThreat);

    ## Configuration options
    option threat_score_threshold: count = 70;
    option high_threat_threshold: count = 85;
    option critical_threat_threshold: count = 95;
    option enable_behavioral_analysis: bool = T;
    option enable_payload_analysis: bool = T;
    option enable_geo_analysis: bool = T;
    option max_threat_score: count = 100;

    ## Global threat intelligence table
    global threat_intel_db: table[string] of ThreatIntel;
    
    ## Behavioral analysis state
    global connection_profiles: table[addr] of ConnectionProfile;
    global suspicious_patterns: table[string] of PatternInfo;
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES FOR BEHAVIORAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

type ConnectionProfile: record {
    host: addr;
    total_connections: count;
    unique_destinations: set[addr];
    data_volume: count;
    connection_frequency: double;
    protocols_used: set[string];
    port_diversity: count;
    geo_diversity: set[string];
    first_seen: time;
    last_activity: time;
    behavioral_score: count;
    anomaly_flags: set[string];
};

type PatternInfo: record {
    pattern_type: string;
    confidence: count;
    frequency: count;
    first_detected: time;
    last_detected: time;
    associated_threats: set[ThreatCategory];
};

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT SCORING ALGORITHMS
# ═══════════════════════════════════════════════════════════════════════════════

function calculate_threat_score(c: connection): count
{
    local score = 0;
    local id = c$id;
    
    # Base scoring factors
    local base_factors: table[string] of count = {
        ["suspicious_port"] = 5,
        ["high_data_volume"] = 10,
        ["external_communication"] = 3,
        ["encrypted_tunnel"] = 7,
        ["protocol_anomaly"] = 8,
        ["timing_anomaly"] = 6,
        ["payload_anomaly"] = 12,
        ["geo_risk"] = 15,
        ["reputation_risk"] = 20,
        ["intelligence_match"] = 25
    };
    
    # Check for suspicious destination ports
    if (id$resp_p in suspicious_ports)
        score += base_factors["suspicious_port"];
    
    # Analyze data volume patterns
    if (c?$orig_bytes && c?$resp_bytes) {
        local total_bytes = c$orig_bytes + c$resp_bytes;
        if (total_bytes > 10000000) # > 10MB
            score += base_factors["high_data_volume"];
        
        # Check for asymmetric data flow (potential exfiltration)
        if (c$orig_bytes > 0 && c$resp_bytes > 0) {
            local ratio = c$orig_bytes / c$resp_bytes;
            if (ratio > 10 || ratio < 0.1)
                score += base_factors["payload_anomaly"];
        }
    }
    
    # External communication risk
    if (!Site::is_local_addr(id$resp_h))
        score += base_factors["external_communication"];
    
    # Check for protocol anomalies
    if (c?$service && c$service in unusual_services)
        score += base_factors["protocol_anomaly"];
    
    # Geographic risk assessment
    local geo_risk = assess_geographic_risk(id$resp_h);
    if (geo_risk > 0)
        score += geo_risk;
    
    # Threat intelligence matching
    local intel_score = check_threat_intelligence(c);
    score += intel_score;
    
    # Behavioral analysis
    if (enable_behavioral_analysis) {
        local behavior_score = analyze_behavioral_patterns(c);
        score += behavior_score;
    }
    
    # Cap the maximum score
    if (score > max_threat_score)
        score = max_threat_score;
    
    return score;
}

function assess_geographic_risk(ip: addr): count
{
    if (!enable_geo_analysis)
        return 0;
    
    # This would integrate with GeoIP databases
    # For now, return basic risk assessment
    local risk_score = 0;
    
    # High-risk countries (would be configurable)
    local high_risk_countries = set("CN", "RU", "KP", "IR");
    
    # Placeholder for actual GeoIP lookup
    # local country = lookup_country(ip);
    # if (country in high_risk_countries)
    #     risk_score = 15;
    
    return risk_score;
}

function check_threat_intelligence(c: connection): count
{
    local score = 0;
    local id = c$id;
    
    # Check source IP
    local src_str = fmt("%s", id$orig_h);
    if (src_str in threat_intel_db) {
        local intel = threat_intel_db[src_str];
        score += intel$confidence / 4; # Scale confidence to score
    }
    
    # Check destination IP
    local dst_str = fmt("%s", id$resp_h);
    if (dst_str in threat_intel_db) {
        local intel = threat_intel_db[dst_str];
        score += intel$confidence / 4;
    }
    
    return score;
}

function analyze_behavioral_patterns(c: connection): count
{
    if (!enable_behavioral_analysis)
        return 0;
    
    local score = 0;
    local id = c$id;
    local src = id$orig_h;
    
    # Update connection profile
    if (src !in connection_profiles) {
        connection_profiles[src] = ConnectionProfile(
            $host = src,
            $total_connections = 0,
            $unique_destinations = set(),
            $data_volume = 0,
            $connection_frequency = 0.0,
            $protocols_used = set(),
            $port_diversity = 0,
            $geo_diversity = set(),
            $first_seen = network_time(),
            $last_activity = network_time(),
            $behavioral_score = 0,
            $anomaly_flags = set()
        );
    }
    
    local profile = connection_profiles[src];
    profile$total_connections += 1;
    add profile$unique_destinations[id$resp_h];
    profile$last_activity = network_time();
    
    if (c?$service)
        add profile$protocols_used[c$service];
    
    # Analyze for suspicious patterns
    local time_window = profile$last_activity - profile$first_seen;
    if (time_window > 0secs) {
        profile$connection_frequency = profile$total_connections / time_window;
        
        # High frequency connections (potential beaconing)
        if (profile$connection_frequency > 0.1) { # More than 1 connection per 10 seconds
            add profile$anomaly_flags["high_frequency"];
            score += 8;
        }
        
        # Large number of unique destinations (potential scanning)
        if (|profile$unique_destinations| > 100) {
            add profile$anomaly_flags["many_destinations"];
            score += 12;
        }
        
        # Port diversity (potential port scanning)
        profile$port_diversity = |profile$protocols_used|;
        if (profile$port_diversity > 20) {
            add profile$anomaly_flags["port_diversity"];
            score += 10;
        }
    }
    
    connection_profiles[src] = profile;
    return score;
}

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT LEVEL CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

function classify_threat_level(score: count): ThreatLevel
{
    if (score >= critical_threat_threshold)
        return CRITICAL;
    else if (score >= high_threat_threshold)
        return HIGH;
    else if (score >= threat_score_threshold)
        return MEDIUM;
    else
        return LOW;
}

# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING
# ═══════════════════════════════════════════════════════════════════════════════

function map_to_mitre_tactics(threat_categories: set[ThreatCategory]): set[string]
{
    local tactics: set[string];
    
    for (category in threat_categories) {
        switch (category) {
            case RECONNAISSANCE:
                add tactics["TA0043"];
                break;
            case INITIAL_ACCESS:
                add tactics["TA0001"];
                break;
            case EXECUTION:
                add tactics["TA0002"];
                break;
            case PERSISTENCE:
                add tactics["TA0003"];
                break;
            case PRIVILEGE_ESCALATION:
                add tactics["TA0004"];
                break;
            case DEFENSE_EVASION:
                add tactics["TA0005"];
                break;
            case CREDENTIAL_ACCESS:
                add tactics["TA0006"];
                break;
            case DISCOVERY:
                add tactics["TA0007"];
                break;
            case LATERAL_MOVEMENT:
                add tactics["TA0008"];
                break;
            case COLLECTION:
                add tactics["TA0009"];
                break;
            case C2_COMMUNICATION:
                add tactics["TA0011"];
                break;
            case DATA_EXFILTRATION:
                add tactics["TA0010"];
                break;
            case IMPACT:
                add tactics["TA0040"];
                break;
        }
    }
    
    return tactics;
}

function map_to_mitre_techniques(behavioral_flags: set[string]): set[string]
{
    local techniques: set[string];
    
    for (flag in behavioral_flags) {
        switch (flag) {
            case "high_frequency":
                add techniques["T1071.001"]; # Application Layer Protocol: Web Protocols
                break;
            case "many_destinations":
                add techniques["T1046"]; # Network Service Scanning
                break;
            case "port_diversity":
                add techniques["T1021"]; # Remote Services
                break;
            case "data_exfiltration":
                add techniques["T1041"]; # Exfiltration Over C2 Channel
                break;
            case "encrypted_tunnel":
                add techniques["T1572"]; # Protocol Tunneling
                break;
        }
    }
    
    return techniques;
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUSPICIOUS PATTERNS AND INDICATORS
# ═══════════════════════════════════════════════════════════════════════════════

const suspicious_ports: set[port] = {
    22/tcp,    # SSH
    23/tcp,    # Telnet
    135/tcp,   # RPC
    139/tcp,   # NetBIOS
    445/tcp,   # SMB
    1433/tcp,  # SQL Server
    3389/tcp,  # RDP
    5432/tcp,  # PostgreSQL
    5900/tcp,  # VNC
    6379/tcp,  # Redis
    27017/tcp  # MongoDB
};

const unusual_services: set[string] = {
    "unknown",
    "backdoor",
    "trojan",
    "irc",
    "p2p"
};

# ═══════════════════════════════════════════════════════════════════════════════
# EVENT HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(THREAT_LOG, [$columns=ThreatInfo, $path="threat"]);
    print "iSECTECH Threat Detection Module loaded";
}

event connection_state_remove(c: connection)
{
    # Perform threat analysis on completed connections
    local threat_score = calculate_threat_score(c);
    
    if (threat_score >= threat_score_threshold) {
        local threat_level = classify_threat_level(threat_score);
        local threat_categories: set[ThreatCategory];
        local behavioral_flags: set[string];
        local indicators: vector of string;
        local risk_factors: vector of string;
        
        # Determine threat categories based on analysis
        if (c$id$resp_h !in Site::local_nets)
            add threat_categories[C2_COMMUNICATION];
        
        if (c?$orig_bytes && c$orig_bytes > 1000000)
            add threat_categories[DATA_EXFILTRATION];
        
        # Get behavioral flags from connection profile
        if (c$id$orig_h in connection_profiles) {
            behavioral_flags = connection_profiles[c$id$orig_h]$anomaly_flags;
        }
        
        # Create threat assessment
        local threat = ConnectionThreat(
            $uid = c$uid,
            $threat_score = threat_score,
            $threat_level = threat_level,
            $threat_categories = threat_categories,
            $indicators = indicators,
            $behavioral_flags = behavioral_flags,
            $risk_factors = risk_factors,
            $mitre_tactics = map_to_mitre_tactics(threat_categories),
            $mitre_techniques = map_to_mitre_techniques(behavioral_flags)
        );
        
        # Log threat event
        local threat_info = ThreatInfo(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $threat_score = threat_score,
            $threat_level = fmt("%s", threat_level),
            $threat_categories = {fmt("%s", cat) for cat in threat_categories},
            $indicators = indicators,
            $behavioral_flags = behavioral_flags,
            $risk_factors = risk_factors,
            $mitre_tactics = threat$mitre_tactics,
            $mitre_techniques = threat$mitre_techniques
        );
        
        Log::write(THREAT_LOG, threat_info);
        
        # Generate events based on threat level
        event threat_detected(c, threat);
        
        if (threat_level == HIGH)
            event high_threat_detected(c, threat);
        else if (threat_level == CRITICAL)
            event critical_threat_detected(c, threat);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, entry: Intel::Item)
{
    # Process threat intelligence indicators
    if (entry?$indicator) {
        local threat = ThreatIntel(
            $indicator = entry$indicator,
            $threat_type = MALWARE, # Default, would be parsed from feed
            $confidence = 80, # Default confidence
            $severity = MEDIUM, # Default severity
            $source = entry?$meta$source ? entry$meta$source : "unknown",
            $description = entry?$meta$desc ? entry$meta$desc : "",
            $first_seen = network_time(),
            $last_seen = network_time(),
            $tags = set()
        );
        
        threat_intel_db[entry$indicator] = threat;
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP AND MAINTENANCE
# ═══════════════════════════════════════════════════════════════════════════════

event maintenance_timer()
{
    # Clean up old connection profiles (older than 24 hours)
    local cutoff_time = network_time() - 24hrs;
    
    for (host in connection_profiles) {
        if (connection_profiles[host]$last_activity < cutoff_time) {
            delete connection_profiles[host];
        }
    }
    
    # Schedule next maintenance
    schedule 1hr { maintenance_timer() };
}

event zeek_init() &priority=-10
{
    # Start maintenance timer
    schedule 1hr { maintenance_timer() };
}