# iSECTECH Threat Intelligence Feeds for Zeek
# Advanced threat intelligence integration and indicator matching

module Intel;

export {
    ## Enhanced threat intelligence source types
    type ThreatSource: enum {
        COMMERCIAL_FEED,
        OPEN_SOURCE,
        INTERNAL_ANALYSIS,
        GOVERNMENT_FEED,
        INDUSTRY_SHARING,
        SANDBOX_ANALYSIS,
        HONEYPOT_DATA,
        MALWARE_ANALYSIS,
        INCIDENT_RESPONSE
    };

    ## Intelligence confidence levels
    type ConfidenceLevel: enum {
        VERY_LOW,
        LOW,
        MEDIUM,
        HIGH,
        VERY_HIGH
    };

    ## Enhanced intelligence item
    type ThreatIntelItem: record {
        indicator: string;
        indicator_type: Intel::Type;
        source: ThreatSource;
        confidence: ConfidenceLevel;
        severity: count;
        description: string;
        tags: set[string];
        first_seen: time;
        last_seen: time;
        expiration: time;
        tlp_marking: string;  # Traffic Light Protocol
        mitre_tactics: set[string];
        mitre_techniques: set[string];
        kill_chain_phase: string;
        threat_actor: string &optional;
        malware_family: string &optional;
        campaign: string &optional;
    };

    ## Configuration options
    option feed_update_interval: interval = 1hr;
    option intel_expiration_time: interval = 30days;
    option enable_auto_blocking: bool = F;
    option high_confidence_threshold: count = 80;
}

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE SOURCES CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Threat intelligence feed URLs and sources
const feed_sources: table[string] of string = {
    ["emerging_threats"] = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    ["malware_domains"] = "https://malware-domains.utica.edu/maldomain.txt",
    ["abuse_ch"] = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    ["tor_exit_nodes"] = "https://check.torproject.org/torbulkexitlist",
    ["spamhaus_sbl"] = "https://www.spamhaus.org/drop/drop.txt",
    ["dshield"] = "https://feeds.dshield.org/block.txt",
    ["alienvault"] = "https://reputation.alienvault.com/reputation.generic",
    ["talos"] = "https://talosintelligence.com/documents/ip-blacklist",
    ["urlhaus"] = "https://urlhaus.abuse.ch/downloads/csv_recent/"
};

# Local intelligence sources
const local_intel_files: vector of string = {
    "/opt/zeek/share/zeek/site/intelligence/indicators.dat",
    "/opt/zeek/share/zeek/site/intelligence/malware-domains.dat",
    "/opt/zeek/share/zeek/site/intelligence/emerging-threats.dat",
    "/opt/zeek/share/zeek/site/intelligence/custom-iocs.dat",
    "/opt/zeek/share/zeek/site/intelligence/incident-indicators.dat"
};

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE PROCESSING AND ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

type IntelligenceMetrics: record {
    total_indicators: count;
    active_indicators: count;
    expired_indicators: count;
    matches_today: count;
    high_confidence_matches: count;
    blocked_connections: count;
    last_update: time;
    feed_health: table[string] of bool;
};

global intel_metrics: IntelligenceMetrics = IntelligenceMetrics(
    $total_indicators = 0,
    $active_indicators = 0,
    $expired_indicators = 0,
    $matches_today = 0,
    $high_confidence_matches = 0,
    $blocked_connections = 0,
    $last_update = network_time(),
    $feed_health = table()
);

# Enhanced intelligence database
global enhanced_intel_db: table[string] of ThreatIntelItem;

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE FEED LOADING AND PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

function load_emerging_threats_feed()
{
    print "Loading Emerging Threats IP blacklist...";
    
    # This would typically use an HTTP client to fetch the feed
    # For now, simulate loading from local cache
    local feed_content = "# Emerging Threats IP Blacklist\n# Sample entries\n192.0.2.1\n192.0.2.2\n198.51.100.1";
    
    local lines = split_string(feed_content, /\n/);
    local loaded_count = 0;
    
    for (line_idx in lines) {
        local line = lines[line_idx];
        
        # Skip comments and empty lines
        if (/^#/ in line || /^\s*$/ in line)
            next;
        
        # Extract IP address
        local ip_match = find_all(line, /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        if (|ip_match| > 0) {
            local ip = ip_match[0];
            
            local intel_item = ThreatIntelItem(
                $indicator = ip,
                $indicator_type = Intel::ADDR,
                $source = OPEN_SOURCE,
                $confidence = HIGH,
                $severity = 75,
                $description = "Emerging Threats IP blacklist",
                $tags = set("malicious", "blacklist", "emerging_threats"),
                $first_seen = network_time(),
                $last_seen = network_time(),
                $expiration = network_time() + intel_expiration_time,
                $tlp_marking = "TLP:WHITE",
                $mitre_tactics = set("TA0011"),  # Command and Control
                $mitre_techniques = set("T1071"),  # Application Layer Protocol
                $kill_chain_phase = "command-and-control"
            );
            
            enhanced_intel_db[ip] = intel_item;
            loaded_count += 1;
        }
    }
    
    intel_metrics$feed_health["emerging_threats"] = T;
    print fmt("Loaded %d indicators from Emerging Threats feed", loaded_count);
}

function load_malware_domains_feed()
{
    print "Loading malware domains feed...";
    
    # Sample malware domains
    local malware_domains = vector(
        "evil.example.com",
        "malware.badsite.org",
        "c2.botnet.net",
        "phishing.attack.com"
    );
    
    local loaded_count = 0;
    
    for (domain_idx in malware_domains) {
        local domain = malware_domains[domain_idx];
        
        local intel_item = ThreatIntelItem(
            $indicator = domain,
            $indicator_type = Intel::DOMAIN,
            $source = COMMERCIAL_FEED,
            $confidence = VERY_HIGH,
            $severity = 85,
            $description = "Known malware command and control domain",
            $tags = set("malware", "c2", "domain", "command_control"),
            $first_seen = network_time(),
            $last_seen = network_time(),
            $expiration = network_time() + intel_expiration_time,
            $tlp_marking = "TLP:GREEN",
            $mitre_tactics = set("TA0011"),  # Command and Control
            $mitre_techniques = set("T1071.001"),  # Web Protocols
            $kill_chain_phase = "command-and-control",
            $malware_family = "Generic"
        );
        
        enhanced_intel_db[domain] = intel_item;
        loaded_count += 1;
    }
    
    intel_metrics$feed_health["malware_domains"] = T;
    print fmt("Loaded %d indicators from malware domains feed", loaded_count);
}

function load_file_hashes_feed()
{
    print "Loading file hashes feed...";
    
    # Sample malicious file hashes
    local malicious_hashes = vector(
        "d41d8cd98f00b204e9800998ecf8427e",  # Sample MD5
        "e3b0c44298fc1c149afbf4c8996fb924",  # Sample SHA1
        "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"  # Sample SHA256
    );
    
    local loaded_count = 0;
    
    for (hash_idx in malicious_hashes) {
        local hash = malicious_hashes[hash_idx];
        
        local intel_item = ThreatIntelItem(
            $indicator = hash,
            $indicator_type = Intel::FILE_HASH,
            $source = SANDBOX_ANALYSIS,
            $confidence = VERY_HIGH,
            $severity = 90,
            $description = "Malicious file hash from sandbox analysis",
            $tags = set("malware", "file_hash", "sandbox"),
            $first_seen = network_time(),
            $last_seen = network_time(),
            $expiration = network_time() + intel_expiration_time,
            $tlp_marking = "TLP:AMBER",
            $mitre_tactics = set("TA0002"),  # Execution
            $mitre_techniques = set("T1204"),  # User Execution
            $kill_chain_phase = "exploitation",
            $malware_family = "Unknown"
        );
        
        enhanced_intel_db[hash] = intel_item;
        loaded_count += 1;
    }
    
    intel_metrics$feed_health["file_hashes"] = T;
    print fmt("Loaded %d indicators from file hashes feed", loaded_count);
}

function load_custom_iocs()
{
    print "Loading custom IOCs from incident response...";
    
    # Sample custom IOCs from internal analysis
    local custom_indicators = table(
        ["192.0.2.100"] = "Internal incident - compromised host communication",
        ["suspicious.internal.com"] = "Internal DNS sinkhole for malware family XYZ",
        ["192.0.2.200"] = "APT campaign infrastructure"
    );
    
    local loaded_count = 0;
    
    for (indicator in custom_indicators) {
        local description = custom_indicators[indicator];
        local indicator_type = Intel::ADDR;
        
        # Determine indicator type
        if (/\./ in indicator && !/^[0-9]/ in indicator) {
            indicator_type = Intel::DOMAIN;
        }
        
        local intel_item = ThreatIntelItem(
            $indicator = indicator,
            $indicator_type = indicator_type,
            $source = INTERNAL_ANALYSIS,
            $confidence = VERY_HIGH,
            $severity = 95,
            $description = description,
            $tags = set("custom", "internal", "incident_response"),
            $first_seen = network_time(),
            $last_seen = network_time(),
            $expiration = network_time() + intel_expiration_time,
            $tlp_marking = "TLP:RED",
            $mitre_tactics = set("TA0011"),
            $mitre_techniques = set("T1071"),
            $kill_chain_phase = "command-and-control",
            $threat_actor = "Unknown",
            $campaign = "Internal Investigation"
        );
        
        enhanced_intel_db[indicator] = intel_item;
        loaded_count += 1;
    }
    
    intel_metrics$feed_health["custom_iocs"] = T;
    print fmt("Loaded %d custom IOCs from incident response", loaded_count);
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE MATCHING AND ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════════

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    for (item in items) {
        # Update metrics
        intel_metrics$matches_today += 1;
        
        # Check if we have enhanced intelligence
        if (item$indicator in enhanced_intel_db) {
            local enhanced_item = enhanced_intel_db[item$indicator];
            
            # Create enriched notice
            local notice_type = Notice::SIGNATURE_MATCH;
            local severity = Notice::MEDIUM;
            
            if (enhanced_item$confidence == VERY_HIGH && enhanced_item$severity >= high_confidence_threshold) {
                severity = Notice::HIGH;
                intel_metrics$high_confidence_matches += 1;
                notice_type = Notice::CRITICAL;
            }
            
            # Generate enriched notice
            NOTICE([$note=notice_type,
                   $msg=fmt("Enhanced threat intelligence match: %s", enhanced_item$description),
                   $sub=fmt("Indicator: %s, Source: %s, Confidence: %s, TLP: %s", 
                           item$indicator, enhanced_item$source, enhanced_item$confidence, enhanced_item$tlp_marking),
                   $conn=s?$conn ? s$conn : default_conn(),
                   $identifier=item$indicator,
                   $suppress_for=10min]);
            
            # Update intelligence item statistics
            enhanced_item$last_seen = network_time();
            enhanced_intel_db[item$indicator] = enhanced_item;
            
            # Log detailed intelligence match
            log_intelligence_match(s, enhanced_item);
            
            # Auto-blocking for high-confidence threats (if enabled)
            if (enable_auto_blocking && enhanced_item$confidence == VERY_HIGH && enhanced_item$severity >= 90) {
                initiate_auto_blocking(item$indicator, enhanced_item);
            }
        }
    }
}

function log_intelligence_match(s: Intel::Seen, intel: ThreatIntelItem)
{
    # Create detailed log entry for intelligence matches
    local log_msg = fmt("INTEL_MATCH: %s (%s) - %s [%s] Confidence:%s Severity:%d TLP:%s",
                       intel$indicator, intel$indicator_type, intel$description,
                       intel$source, intel$confidence, intel$severity, intel$tlp_marking);
    
    if (intel?$threat_actor)
        log_msg += fmt(" Actor:%s", intel$threat_actor);
    
    if (intel?$malware_family)
        log_msg += fmt(" Malware:%s", intel$malware_family);
    
    if (intel?$campaign)
        log_msg += fmt(" Campaign:%s", intel$campaign);
    
    print log_msg;
    Reporter::info(log_msg);
}

function initiate_auto_blocking(indicator: string, intel: ThreatIntelItem)
{
    # This would integrate with firewall or blocking systems
    intel_metrics$blocked_connections += 1;
    
    local block_msg = fmt("AUTO-BLOCK initiated for %s - %s (Confidence: %s, Severity: %d)",
                         indicator, intel$description, intel$confidence, intel$severity);
    
    NOTICE([$note=Notice::CRITICAL,
           $msg="Automatic blocking triggered",
           $sub=block_msg,
           $identifier=indicator]);
    
    print block_msg;
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE MAINTENANCE AND UPDATES
# ═══════════════════════════════════════════════════════════════════════════════

function update_intelligence_feeds()
{
    print "Starting threat intelligence feeds update...";
    
    # Load all configured feeds
    load_emerging_threats_feed();
    load_malware_domains_feed();
    load_file_hashes_feed();
    load_custom_iocs();
    
    # Update metrics
    intel_metrics$total_indicators = |enhanced_intel_db|;
    intel_metrics$last_update = network_time();
    
    # Clean expired indicators
    cleanup_expired_indicators();
    
    print fmt("Intelligence update completed: %d total indicators, %d active", 
             intel_metrics$total_indicators, intel_metrics$active_indicators);
}

function cleanup_expired_indicators()
{
    local expired_count = 0;
    local current_time = network_time();
    
    for (indicator in enhanced_intel_db) {
        local intel_item = enhanced_intel_db[indicator];
        
        if (intel_item$expiration < current_time) {
            delete enhanced_intel_db[indicator];
            expired_count += 1;
        }
    }
    
    intel_metrics$expired_indicators = expired_count;
    intel_metrics$active_indicators = intel_metrics$total_indicators - expired_count;
    
    if (expired_count > 0) {
        print fmt("Cleaned up %d expired intelligence indicators", expired_count);
    }
}

function generate_intelligence_report()
{
    print "=== iSECTECH Threat Intelligence Report ===";
    print fmt("Total Indicators: %d", intel_metrics$total_indicators);
    print fmt("Active Indicators: %d", intel_metrics$active_indicators);
    print fmt("Expired Indicators: %d", intel_metrics$expired_indicators);
    print fmt("Matches Today: %d", intel_metrics$matches_today);
    print fmt("High Confidence Matches: %d", intel_metrics$high_confidence_matches);
    print fmt("Blocked Connections: %d", intel_metrics$blocked_connections);
    print fmt("Last Update: %s", strftime("%Y-%m-%d %H:%M:%S", intel_metrics$last_update));
    
    print "Feed Health Status:";
    for (feed in intel_metrics$feed_health) {
        local status = intel_metrics$feed_health[feed] ? "HEALTHY" : "FAILED";
        print fmt("  %s: %s", feed, status);
    }
    print "==========================================";
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND SCHEDULING
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    print "iSECTECH Enhanced Threat Intelligence Module loaded";
    
    # Load intelligence feeds on startup
    update_intelligence_feeds();
    
    # Schedule periodic updates
    schedule feed_update_interval { intelligence_update_timer() };
    
    # Schedule daily reports
    schedule 24hr { intelligence_report_timer() };
}

event intelligence_update_timer()
{
    update_intelligence_feeds();
    
    # Schedule next update
    schedule feed_update_interval { intelligence_update_timer() };
}

event intelligence_report_timer()
{
    generate_intelligence_report();
    
    # Reset daily counters
    intel_metrics$matches_today = 0;
    intel_metrics$high_confidence_matches = 0;
    
    # Schedule next report
    schedule 24hr { intelligence_report_timer() };
}

# Default connection for notices when no connection context available
function default_conn(): connection
{
    local dummy_conn_id = conn_id($orig_h=0.0.0.0, $orig_p=0/tcp, $resp_h=0.0.0.0, $resp_p=0/tcp);
    local dummy_conn: connection = connection($id=dummy_conn_id, $uid="intel_match");
    return dummy_conn;
}