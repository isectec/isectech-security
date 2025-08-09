# iSECTECH Command and Control (C2) Detection for Zeek
# Advanced detection of C2 communications and beaconing behavior

module iSECTECH;

export {
    ## C2 communication patterns
    type C2Pattern: enum {
        HTTP_BEACONING,
        DNS_BEACONING,
        ICMP_BEACONING,
        TLS_BEACONING,
        IRC_COMMUNICATION,
        P2P_COMMUNICATION,
        ENCRYPTED_TUNNEL,
        DOMAIN_GENERATION,
        FAST_FLUX,
        COVERT_TIMING,
        PROTOCOL_HOPPING
    };

    ## C2 detection record
    type C2Detection: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        pattern: string &log;
        confidence: count &log;
        severity: string &log;
        beacon_interval: interval &log &optional;
        jitter_factor: double &log &optional;
        data_volume: count &log &optional;
        session_count: count &log &optional;
        indicators: vector of string &log;
        description: string &log;
        c2_host: addr &log &optional;
        c2_domain: string &log &optional;
        user_agent: string &log &optional;
        payload_entropy: double &log &optional;
        mitre_technique: string &log &optional;
    };

    ## Log stream for C2 detection events
    redef enum Log::ID += { C2_DETECTION_LOG };

    ## Events
    global c2_detected: event(c: connection, detection: C2Detection);

    ## Configuration options
    option beacon_detection_threshold: count = 5;
    option beacon_time_tolerance: interval = 10sec;
    option max_jitter_variance: double = 0.3;
    option enable_dga_detection: bool = T;
    option enable_entropy_analysis: bool = T;
    option suspicious_user_agents: set[string] = {
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    };
}

# ═══════════════════════════════════════════════════════════════════════════════
# BEACONING BEHAVIOR TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

type BeaconSession: record {
    client: addr;
    server: addr;
    server_port: port;
    connection_times: vector of time;
    intervals: vector of interval;
    data_sizes: vector of count;
    user_agents: set[string];
    uris: set[string];
    first_seen: time;
    last_seen: time;
    session_count: count;
    avg_interval: interval;
    interval_variance: double;
    avg_data_size: double;
    data_variance: double;
    regularity_score: double;
};

global beacon_sessions: table[string] of BeaconSession;

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP C2 BEACONING DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    local client = c$id$orig_h;
    local server = c$id$resp_h;
    local server_port = c$id$resp_p;
    
    # Create session key
    local session_key = fmt("%s-%s-%s", client, server, server_port);
    
    # Initialize or update beacon session
    if (session_key !in beacon_sessions) {
        beacon_sessions[session_key] = BeaconSession(
            $client = client,
            $server = server,
            $server_port = server_port,
            $connection_times = vector(),
            $intervals = vector(),
            $data_sizes = vector(),
            $user_agents = set(),
            $uris = set(),
            $first_seen = network_time(),
            $last_seen = network_time(),
            $session_count = 0,
            $avg_interval = 0secs,
            $interval_variance = 0.0,
            $avg_data_size = 0.0,
            $data_variance = 0.0,
            $regularity_score = 0.0
        );
    }
    
    local session = beacon_sessions[session_key];
    session$connection_times += network_time();
    session$last_seen = network_time();
    session$session_count += 1;
    add session$uris[original_URI];
    
    # Calculate intervals if we have multiple connections
    if (|session$connection_times| > 1) {
        local current_time = network_time();
        local last_time = session$connection_times[|session$connection_times| - 2];
        local interval = current_time - last_time;
        session$intervals += interval;
        
        # Update interval statistics
        update_beacon_statistics(session);
        
        # Analyze for beaconing behavior
        if (|session$intervals| >= beacon_detection_threshold) {
            analyze_beaconing_pattern(c, session);
        }
    }
    
    beacon_sessions[session_key] = session;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if (!is_orig || name != "USER-AGENT")
        return;
        
    local session_key = fmt("%s-%s-%s", c$id$orig_h, c$id$resp_h, c$id$resp_p);
    
    if (session_key in beacon_sessions) {
        local session = beacon_sessions[session_key];
        add session$user_agents[value];
        beacon_sessions[session_key] = session;
        
        # Check for suspicious user agents
        if (value in suspicious_user_agents) {
            create_c2_detection(c, "HTTP_BEACONING", 30, 
                               vector("suspicious_user_agent"), 
                               fmt("Suspicious User-Agent: %s", value),
                               $user_agent = value);
        }
    }
}

function update_beacon_statistics(session: BeaconSession)
{
    if (|session$intervals| == 0)
        return;
        
    # Calculate average interval
    local total_interval = 0.0;
    for (idx in session$intervals) {
        total_interval += session$intervals[idx];
    }
    session$avg_interval = total_interval / |session$intervals|;
    
    # Calculate interval variance
    local variance_sum = 0.0;
    for (idx in session$intervals) {
        local diff = session$intervals[idx] - session$avg_interval;
        variance_sum += diff * diff;
    }
    session$interval_variance = variance_sum / |session$intervals|;
    
    # Calculate regularity score (lower variance = higher regularity)
    if (session$avg_interval > 0secs) {
        session$regularity_score = 1.0 - (session$interval_variance / (session$avg_interval * session$avg_interval));
    }
}

function analyze_beaconing_pattern(c: connection, session: BeaconSession)
{
    local indicators: vector of string;
    local confidence = 0;
    
    # Check for regular intervals (low variance)
    if (session$regularity_score > 0.8) {
        indicators += "regular_intervals";
        confidence += 35;
    }
    
    # Check for consistent interval (jitter analysis)
    local jitter_factor = sqrt(session$interval_variance) / session$avg_interval;
    if (jitter_factor < max_jitter_variance) {
        indicators += "low_jitter";
        confidence += 25;
    }
    
    # Check for suspicious interval patterns
    if (session$avg_interval >= 30sec && session$avg_interval <= 1hr) {
        indicators += "suspicious_interval_range";
        confidence += 20;
    }
    
    # Check for consistent small data sizes
    if (session$avg_data_size < 1024 && session$data_variance < 100) {
        indicators += "consistent_small_payloads";
        confidence += 20;
    }
    
    # Check for single User-Agent consistency
    if (|session$user_agents| == 1) {
        indicators += "consistent_user_agent";
        confidence += 15;
    }
    
    # Check for limited URI diversity
    if (|session$uris| <= 3 && session$session_count > 10) {
        indicators += "limited_uri_diversity";
        confidence += 20;
    }
    
    # Check for external destination
    if (!Site::is_local_addr(session$server)) {
        indicators += "external_destination";
        confidence += 15;
    }
    
    if (confidence >= 40) {
        create_c2_detection(c, "HTTP_BEACONING", confidence, indicators,
                           fmt("HTTP beaconing detected (interval: %.1fs, jitter: %.2f, sessions: %d)",
                               session$avg_interval, jitter_factor, session$session_count),
                           $beacon_interval = session$avg_interval,
                           $jitter_factor = jitter_factor,
                           $session_count = session$session_count,
                           $c2_host = session$server);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS C2 DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

type DNSBeaconProfile: record {
    client: addr;
    server: addr;
    query_domains: set[string];
    query_times: vector of time;
    query_intervals: vector of interval;
    first_query: time;
    last_query: time;
    query_count: count;
    avg_interval: interval;
    domain_entropy: double;
    subdomain_patterns: set[string];
};

global dns_beacon_profiles: table[string] of DNSBeaconProfile;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local client = c$id$orig_h;
    local server = c$id$resp_h;
    local profile_key = fmt("%s-%s", client, server);
    
    # Initialize or update DNS beacon profile
    if (profile_key !in dns_beacon_profiles) {
        dns_beacon_profiles[profile_key] = DNSBeaconProfile(
            $client = client,
            $server = server,
            $query_domains = set(),
            $query_times = vector(),
            $query_intervals = vector(),
            $first_query = network_time(),
            $last_query = network_time(),
            $query_count = 0,
            $avg_interval = 0secs,
            $domain_entropy = 0.0,
            $subdomain_patterns = set()
        );
    }
    
    local profile = dns_beacon_profiles[profile_key];
    add profile$query_domains[query];
    profile$query_times += network_time();
    profile$last_query = network_time();
    profile$query_count += 1;
    
    # Calculate intervals for DNS beaconing
    if (|profile$query_times| > 1) {
        local current_time = network_time();
        local last_time = profile$query_times[|profile$query_times| - 2];
        local interval = current_time - last_time;
        profile$query_intervals += interval;
        
        # Update average interval
        if (|profile$query_intervals| > 0) {
            local total_interval = 0.0;
            for (idx in profile$query_intervals) {
                total_interval += profile$query_intervals[idx];
            }
            profile$avg_interval = total_interval / |profile$query_intervals|;
        }
    }
    
    # Check for Domain Generation Algorithm (DGA) patterns
    if (enable_dga_detection) {
        check_dga_patterns(c, query, profile);
    }
    
    dns_beacon_profiles[profile_key] = profile;
    
    # Analyze for DNS beaconing if we have enough data
    if (|profile$query_intervals| >= beacon_detection_threshold) {
        analyze_dns_beaconing(c, profile, query);
    }
}

function check_dga_patterns(c: connection, query: string, profile: DNSBeaconProfile)
{
    local indicators: vector of string;
    local confidence = 0;
    
    # Calculate domain entropy
    local entropy = calculate_domain_entropy(query);
    if (entropy > 4.0) {
        indicators += "high_entropy_domain";
        confidence += 25;
    }
    
    # Check for algorithmic patterns
    if (/^[a-z]{8,20}\.[a-z]{2,4}$/ in query) {
        indicators += "dga_pattern";
        confidence += 30;
    }
    
    # Check for consonant/vowel ratio (DGAs often have unusual ratios)
    local consonant_ratio = calculate_consonant_ratio(query);
    if (consonant_ratio > 0.8 || consonant_ratio < 0.2) {
        indicators += "unusual_consonant_ratio";
        confidence += 20;
    }
    
    # Check for numeric/alphabetic mix patterns
    if (/[0-9]{3,}[a-z]{3,}|[a-z]{3,}[0-9]{3,}/ in query) {
        indicators += "mixed_alphanumeric";
        confidence += 15;
    }
    
    if (confidence >= 30) {
        create_c2_detection(c, "DOMAIN_GENERATION", confidence, indicators,
                           fmt("DGA domain detected: %s (entropy: %.2f)", query, entropy),
                           $c2_domain = query);
    }
}

function analyze_dns_beaconing(c: connection, profile: DNSBeaconProfile, current_query: string)
{
    local indicators: vector of string;
    local confidence = 0;
    
    # Check for regular DNS query intervals
    local interval_variance = calculate_interval_variance(profile$query_intervals);
    local jitter_factor = sqrt(interval_variance) / profile$avg_interval;
    
    if (jitter_factor < 0.2) {  # Very regular queries
        indicators += "regular_dns_intervals";
        confidence += 30;
    }
    
    # Check for suspicious query interval range
    if (profile$avg_interval >= 10sec && profile$avg_interval <= 10min) {
        indicators += "suspicious_query_interval";
        confidence += 20;
    }
    
    # Check for subdomain patterns (potential data exfiltration)
    if (|profile$query_domains| > 20) {
        indicators += "many_unique_subdomains";
        confidence += 25;
    }
    
    # Check for external DNS server usage
    if (!Site::is_local_addr(profile$server)) {
        indicators += "external_dns_server";
        confidence += 15;
    }
    
    if (confidence >= 35) {
        create_c2_detection(c, "DNS_BEACONING", confidence, indicators,
                           fmt("DNS beaconing detected (interval: %.1fs, domains: %d)",
                               profile$avg_interval, |profile$query_domains|),
                           $beacon_interval = profile$avg_interval,
                           $session_count = profile$query_count,
                           $c2_host = profile$server,
                           $c2_domain = current_query);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLS/ENCRYPTED C2 DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event ssl_established(c: connection)
{
    # Monitor for TLS-based C2 patterns
    local client = c$id$orig_h;
    local server = c$id$resp_h;
    
    # Check for suspicious TLS patterns
    local indicators: vector of string;
    local confidence = 0;
    
    if (c?$ssl && c$ssl?$server_name) {
        local server_name = c$ssl$server_name;
        
        # Check for suspicious certificate characteristics
        if (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {
            local cert = c$ssl$cert_chain[0];
            
            # Self-signed certificates (common in C2)
            if (cert?$subject && cert?$issuer && cert$subject == cert$issuer) {
                indicators += "self_signed_cert";
                confidence += 25;
            }
            
            # Short-lived certificates
            if (cert?$not_valid_before && cert?$not_valid_after) {
                local validity = cert$not_valid_after - cert$not_valid_before;
                if (validity < 90days) {
                    indicators += "short_validity_cert";
                    confidence += 20;
                }
            }
        }
        
        # Check for domain generation patterns in SNI
        if (enable_dga_detection) {
            local entropy = calculate_domain_entropy(server_name);
            if (entropy > 4.5) {
                indicators += "high_entropy_sni";
                confidence += 30;
            }
        }
    }
    
    # Check for non-standard TLS ports
    if (c$id$resp_p !in { 443/tcp, 993/tcp, 995/tcp, 8443/tcp }) {
        indicators += "non_standard_tls_port";
        confidence += 20;
    }
    
    if (confidence >= 30) {
        create_c2_detection(c, "TLS_BEACONING", confidence, indicators,
                           "Suspicious TLS communication pattern detected",
                           $c2_host = server);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function create_c2_detection(c: connection, pattern: string, confidence: count, 
                            indicators: vector of string, description: string,
                            beacon_interval: interval &default=0secs,
                            jitter_factor: double &default=0.0,
                            data_volume: count &default=0,
                            session_count: count &default=0,
                            c2_host: addr &default=0.0.0.0,
                            c2_domain: string &default="",
                            user_agent: string &default="",
                            payload_entropy: double &default=0.0)
{
    local severity = "MEDIUM";
    if (confidence >= 70)
        severity = "HIGH";
    else if (confidence >= 90)
        severity = "CRITICAL";
    
    local mitre_technique = "";
    switch (pattern) {
        case "HTTP_BEACONING":
            mitre_technique = "T1071.001";
            break;
        case "DNS_BEACONING":
            mitre_technique = "T1071.004";
            break;
        case "DOMAIN_GENERATION":
            mitre_technique = "T1568.002";
            break;
        case "TLS_BEACONING":
            mitre_technique = "T1573.002";
            break;
    }
    
    local detection = C2Detection(
        $ts = network_time(),
        $uid = c$uid,
        $id = c$id,
        $pattern = pattern,
        $confidence = confidence,
        $severity = severity,
        $indicators = indicators,
        $description = description,
        $mitre_technique = mitre_technique
    );
    
    # Set optional fields
    if (beacon_interval > 0secs)
        detection$beacon_interval = beacon_interval;
    if (jitter_factor > 0.0)
        detection$jitter_factor = jitter_factor;
    if (data_volume > 0)
        detection$data_volume = data_volume;
    if (session_count > 0)
        detection$session_count = session_count;
    if (c2_host != 0.0.0.0)
        detection$c2_host = c2_host;
    if (c2_domain != "")
        detection$c2_domain = c2_domain;
    if (user_agent != "")
        detection$user_agent = user_agent;
    if (payload_entropy > 0.0)
        detection$payload_entropy = payload_entropy;
    
    Log::write(C2_DETECTION_LOG, detection);
    event c2_detected(c, detection);
}

function calculate_domain_entropy(domain: string): double
{
    # Extract just the subdomain part for entropy calculation
    local parts = split_string(domain, /\./);
    if (|parts| == 0)
        return 0.0;
    
    local subdomain = parts[0];
    local char_counts: table[string] of count;
    local total_chars = |subdomain|;
    
    if (total_chars == 0)
        return 0.0;
    
    # Count character frequencies
    for (i in subdomain) {
        local char = to_lower(subdomain[i]);
        if (char !in char_counts)
            char_counts[char] = 0;
        char_counts[char] += 1;
    }
    
    # Calculate Shannon entropy
    local entropy = 0.0;
    for (char in char_counts) {
        local freq = char_counts[char] / total_chars;
        if (freq > 0)
            entropy -= freq * log(freq) / log(2.0);
    }
    
    return entropy;
}

function calculate_consonant_ratio(str: string): double
{
    local consonants = "bcdfghjklmnpqrstvwxyz";
    local vowels = "aeiou";
    local consonant_count = 0;
    local vowel_count = 0;
    
    for (i in str) {
        local char = to_lower(str[i]);
        if (char in consonants)
            consonant_count += 1;
        else if (char in vowels)
            vowel_count += 1;
    }
    
    local total_letters = consonant_count + vowel_count;
    if (total_letters == 0)
        return 0.0;
    
    return consonant_count / total_letters;
}

function calculate_interval_variance(intervals: vector of interval): double
{
    if (|intervals| <= 1)
        return 0.0;
    
    # Calculate mean
    local sum = 0.0;
    for (idx in intervals) {
        sum += intervals[idx];
    }
    local mean = sum / |intervals|;
    
    # Calculate variance
    local variance_sum = 0.0;
    for (idx in intervals) {
        local diff = intervals[idx] - mean;
        variance_sum += diff * diff;
    }
    
    return variance_sum / |intervals|;
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(C2_DETECTION_LOG, [$columns=C2Detection, $path="c2_detection"]);
    print "iSECTECH C2 Detection Module loaded";
}

# Cleanup old beacon sessions
event beacon_cleanup_timer()
{
    local cutoff_time = network_time() - 4hr;
    
    # Clean up old beacon sessions
    for (session_key in beacon_sessions) {
        if (beacon_sessions[session_key]$last_seen < cutoff_time) {
            delete beacon_sessions[session_key];
        }
    }
    
    # Clean up old DNS beacon profiles
    for (profile_key in dns_beacon_profiles) {
        if (dns_beacon_profiles[profile_key]$last_query < cutoff_time) {
            delete dns_beacon_profiles[profile_key];
        }
    }
    
    # Schedule next cleanup
    schedule 2hr { beacon_cleanup_timer() };
}

event zeek_init() &priority=-5
{
    # Start beacon cleanup timer
    schedule 2hr { beacon_cleanup_timer() };
}