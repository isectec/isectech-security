# iSECTECH Data Exfiltration Detection for Zeek
# Advanced detection of data theft and unauthorized data movement

module iSECTECH;

export {
    ## Data exfiltration methods
    type ExfiltrationMethod: enum {
        HTTP_POST,
        DNS_TUNNELING,
        ICMP_TUNNELING,
        FTP_UPLOAD,
        EMAIL_ATTACHMENT,
        CLOUD_UPLOAD,
        ENCRYPTED_TUNNEL,
        PROTOCOL_MISUSE,
        STEGANOGRAPHY,
        COVERT_TIMING
    };

    ## Data exfiltration event record
    type DataExfiltration: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        method: string &log;
        confidence: count &log;
        severity: string &log;
        data_volume: count &log &optional;
        duration: interval &log &optional;
        indicators: vector of string &log;
        description: string &log;
        source_internal: bool &log;
        destination_external: bool &log;
        file_type: string &log &optional;
        encryption_detected: bool &log &optional;
        suspicious_patterns: set[string] &log &optional;
    };

    ## Log stream for data exfiltration events
    redef enum Log::ID += { DATA_EXFIL_LOG };

    ## Events
    global data_exfiltration_detected: event(c: connection, exfil: DataExfiltration);

    ## Configuration options
    option exfil_volume_threshold: count = 10485760;  # 10MB
    option exfil_duration_threshold: interval = 1hr;
    option enable_content_analysis: bool = T;
    option enable_timing_analysis: bool = T;
    option suspicious_file_extensions: set[string] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".sql", ".db", ".csv", 
        ".xlsx", ".docx", ".pdf", ".pst", ".ost", ".vmdk", ".vhd"
    };
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA VOLUME TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

type DataTransferProfile: record {
    host: addr;
    total_uploads: count;
    total_downloads: count;
    upload_destinations: set[addr];
    large_transfers: count;
    external_transfers: count;
    suspicious_transfers: count;
    first_seen: time;
    last_activity: time;
    avg_transfer_size: double;
    max_transfer_size: count;
};

global transfer_profiles: table[addr] of DataTransferProfile;
global large_transfers: table[string] of time;  # Track UIDs of large transfers

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP DATA EXFILTRATION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
    if (!enable_content_analysis || !is_orig)
        return;

    local indicators: vector of string;
    local suspicious_patterns: set[string];
    local confidence = 0;

    # Check for large POST data (potential file upload)
    if (length > exfil_volume_threshold) {
        indicators += "large_post_data";
        confidence += 30;
        add suspicious_patterns["large_upload"];
        
        # Track this transfer
        large_transfers[c$uid] = network_time();
    }

    # Analyze data content for sensitive patterns
    if (enable_content_analysis && |data| > 0) {
        # Look for database dump patterns
        if (/(?i)(insert\s+into|create\s+table|select\s+\*\s+from)/ in data) {
            indicators += "database_dump_pattern";
            confidence += 25;
            add suspicious_patterns["sql_dump"];
        }

        # Look for structured data patterns (CSV, JSON)
        if (/^[a-zA-Z0-9_]+,[a-zA-Z0-9_,\s]+$/ in data) {
            indicators += "csv_data_pattern";
            confidence += 15;
            add suspicious_patterns["structured_data"];
        }

        # Look for Base64 encoded data
        if (/[A-Za-z0-9+\/]{100,}={0,2}/ in data) {
            indicators += "base64_encoded_data";
            confidence += 20;
            add suspicious_patterns["encoded_data"];
        }

        # Look for credit card patterns
        if (/\b(?:\d{4}[\s-]?){3}\d{4}\b/ in data) {
            indicators += "credit_card_pattern";
            confidence += 40;
            add suspicious_patterns["financial_data"];
        }

        # Look for social security number patterns
        if (/\b\d{3}-\d{2}-\d{4}\b/ in data) {
            indicators += "ssn_pattern";
            confidence += 40;
            add suspicious_patterns["pii_data"];
        }
    }

    # Generate alert if confidence threshold met
    if (confidence >= 25) {
        local exfil_event = DataExfiltration(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $method = "HTTP_POST",
            $confidence = confidence,
            $severity = confidence >= 50 ? "HIGH" : "MEDIUM",
            $data_volume = length,
            $indicators = indicators,
            $description = "Suspicious data upload via HTTP POST",
            $source_internal = Site::is_local_addr(c$id$orig_h),
            $destination_external = !Site::is_local_addr(c$id$resp_h),
            $suspicious_patterns = suspicious_patterns
        );

        Log::write(DATA_EXFIL_LOG, exfil_event);
        event data_exfiltration_detected(c, exfil_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS TUNNELING DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

type DNSProfile: record {
    client: addr;
    query_count: count;
    unique_domains: set[string];
    avg_query_length: double;
    max_query_length: count;
    subdomain_entropy: double;
    request_frequency: double;
    first_seen: time;
    last_seen: time;
};

global dns_profiles: table[addr] of DNSProfile;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local client = c$id$orig_h;
    local indicators: vector of string;
    local confidence = 0;

    # Initialize or update DNS profile
    if (client !in dns_profiles) {
        dns_profiles[client] = DNSProfile(
            $client = client,
            $query_count = 0,
            $unique_domains = set(),
            $avg_query_length = 0.0,
            $max_query_length = 0,
            $subdomain_entropy = 0.0,
            $request_frequency = 0.0,
            $first_seen = network_time(),
            $last_seen = network_time()
        );
    }

    local profile = dns_profiles[client];
    profile$query_count += 1;
    add profile$unique_domains[query];
    profile$last_seen = network_time();

    # Update query length statistics
    local query_len = |query|;
    if (query_len > profile$max_query_length) {
        profile$max_query_length = query_len;
    }
    profile$avg_query_length = (profile$avg_query_length * (profile$query_count - 1) + query_len) / profile$query_count;

    # Calculate request frequency
    local time_window = profile$last_seen - profile$first_seen;
    if (time_window > 0secs) {
        profile$request_frequency = profile$query_count / time_window;
    }

    # Check for DNS tunneling indicators
    
    # 1. Excessive query length
    if (query_len > 200) {
        indicators += "long_dns_query";
        confidence += 25;
    }

    # 2. High entropy subdomains (random-looking)
    local entropy = calculate_string_entropy(query);
    if (entropy > 4.5) {
        indicators += "high_entropy_subdomain";
        confidence += 20;
    }

    # 3. Unusual character patterns
    if (/[0-9a-f]{32,}/ in query) {  # Hex patterns
        indicators += "hex_pattern_subdomain";
        confidence += 15;
    }

    # 4. Base32/Base64 patterns in subdomains
    if (/[A-Z2-7]{20,}/ in query || /[A-Za-z0-9+\/]{20,}/ in query) {
        indicators += "encoded_subdomain";
        confidence += 25;
    }

    # 5. High request frequency to same domain
    if (profile$request_frequency > 1.0) {  # More than 1 request per second
        indicators += "high_frequency_requests";
        confidence += 20;
    }

    # 6. Multiple queries to same domain with varying subdomains
    local base_domain = extract_base_domain(query);
    local unique_subdomains = count_unique_subdomains(profile$unique_domains, base_domain);
    if (unique_subdomains > 50) {
        indicators += "many_unique_subdomains";
        confidence += 25;
    }

    # Update profile
    dns_profiles[client] = profile;

    # Generate alert if confidence threshold met
    if (confidence >= 30) {
        local exfil_event = DataExfiltration(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $method = "DNS_TUNNELING",
            $confidence = confidence,
            $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
            $indicators = indicators,
            $description = fmt("Suspicious DNS tunneling activity to %s", query),
            $source_internal = Site::is_local_addr(c$id$orig_h),
            $destination_external = !Site::is_local_addr(c$id$resp_h)
        );

        Log::write(DATA_EXFIL_LOG, exfil_event);
        event data_exfiltration_detected(c, exfil_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# FTP DATA EXFILTRATION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event ftp_request(c: connection, command: string, arg: string)
{
    if (command !in ["STOR", "PUT", "APPE"])
        return;

    local indicators: vector of string;
    local confidence = 0;
    local file_ext = "";

    # Extract file extension
    if (/\.([a-zA-Z0-9]+)$/ in arg) {
        local matches = find_all(arg, /\.([a-zA-Z0-9]+)$/);
        if (|matches| > 0) {
            file_ext = to_lower(matches[0]);
        }
    }

    # Check for suspicious file types
    if (file_ext in suspicious_file_extensions) {
        indicators += "suspicious_file_type";
        confidence += 30;
    }

    # Check for large file names (potential encoded data)
    if (|arg| > 100) {
        indicators += "long_filename";
        confidence += 15;
    }

    # Check if upload to external server
    if (!Site::is_local_addr(c$id$resp_h)) {
        indicators += "external_upload";
        confidence += 25;
    }

    # Check for unusual upload times (outside business hours)
    local hour = double_to_count(strftime("%H", network_time()));
    if (hour < 7 || hour > 19) {
        indicators += "off_hours_activity";
        confidence += 15;
    }

    if (confidence >= 25) {
        local exfil_event = DataExfiltration(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $method = "FTP_UPLOAD",
            $confidence = confidence,
            $severity = confidence >= 50 ? "HIGH" : "MEDIUM",
            $indicators = indicators,
            $description = fmt("Suspicious FTP upload: %s", arg),
            $source_internal = Site::is_local_addr(c$id$orig_h),
            $destination_external = !Site::is_local_addr(c$id$resp_h),
            $file_type = file_ext
        );

        Log::write(DATA_EXFIL_LOG, exfil_event);
        event data_exfiltration_detected(c, exfil_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BULK DATA TRANSFER ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

event connection_state_remove(c: connection)
{
    local src = c$id$orig_h;
    local total_bytes = 0;
    local indicators: vector of string;
    local confidence = 0;

    if (c?$orig_bytes && c?$resp_bytes) {
        total_bytes = c$orig_bytes + c$resp_bytes;
    }

    # Update transfer profile
    if (src !in transfer_profiles) {
        transfer_profiles[src] = DataTransferProfile(
            $host = src,
            $total_uploads = 0,
            $total_downloads = 0,
            $upload_destinations = set(),
            $large_transfers = 0,
            $external_transfers = 0,
            $suspicious_transfers = 0,
            $first_seen = network_time(),
            $last_activity = network_time(),
            $avg_transfer_size = 0.0,
            $max_transfer_size = 0
        );
    }

    local profile = transfer_profiles[src];
    profile$last_activity = network_time();

    # Analyze upload patterns (more orig_bytes than resp_bytes)
    if (c?$orig_bytes && c?$resp_bytes && c$orig_bytes > c$resp_bytes * 2) {
        profile$total_uploads += c$orig_bytes;
        add profile$upload_destinations[c$id$resp_h];

        # Check for large upload
        if (c$orig_bytes > exfil_volume_threshold) {
            profile$large_transfers += 1;
            indicators += "large_data_transfer";
            confidence += 25;
        }

        # Check for external destination
        if (!Site::is_local_addr(c$id$resp_h)) {
            profile$external_transfers += 1;
            indicators += "external_destination";
            confidence += 20;
        }

        # Check for continuous large transfers
        if (profile$large_transfers > 5) {
            indicators += "multiple_large_transfers";
            confidence += 30;
        }
    }

    # Update statistics
    if (total_bytes > profile$max_transfer_size) {
        profile$max_transfer_size = total_bytes;
    }

    # Calculate average transfer size
    local total_connections = profile$total_uploads + profile$total_downloads + 1;
    profile$avg_transfer_size = (profile$avg_transfer_size * (total_connections - 1) + total_bytes) / total_connections;

    # Check for unusual transfer patterns
    if (total_bytes > profile$avg_transfer_size * 10 && profile$avg_transfer_size > 0) {
        indicators += "unusual_transfer_size";
        confidence += 20;
    }

    # Update profile
    transfer_profiles[src] = profile;

    # Generate alert for suspicious transfers
    if (confidence >= 30) {
        local exfil_event = DataExfiltration(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $method = "BULK_TRANSFER",
            $confidence = confidence,
            $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
            $data_volume = total_bytes,
            $duration = c?$duration ? c$duration : 0secs,
            $indicators = indicators,
            $description = "Suspicious bulk data transfer detected",
            $source_internal = Site::is_local_addr(c$id$orig_h),
            $destination_external = !Site::is_local_addr(c$id$resp_h)
        );

        Log::write(DATA_EXFIL_LOG, exfil_event);
        event data_exfiltration_detected(c, exfil_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function calculate_string_entropy(str: string): double
{
    local char_counts: table[string] of count;
    local total_chars = |str|;
    
    if (total_chars == 0)
        return 0.0;
    
    # Count character frequencies
    for (i in str) {
        local char = str[i];
        if (char !in char_counts)
            char_counts[char] = 0;
        char_counts[char] += 1;
    }
    
    # Calculate Shannon entropy
    local entropy = 0.0;
    for (char in char_counts) {
        local freq = char_counts[char] / total_chars;
        if (freq > 0)
            entropy -= freq * log2(freq);
    }
    
    return entropy;
}

function extract_base_domain(query: string): string
{
    # Extract base domain from DNS query
    local parts = split_string(query, /\./);
    if (|parts| >= 2) {
        return fmt("%s.%s", parts[|parts|-2], parts[|parts|-1]);
    }
    return query;
}

function count_unique_subdomains(domains: set[string], base_domain: string): count
{
    local subdomain_count = 0;
    for (domain in domains) {
        if (base_domain in domain && domain != base_domain) {
            subdomain_count += 1;
        }
    }
    return subdomain_count;
}

function log2(x: double): double
{
    return log(x) / log(2.0);
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(DATA_EXFIL_LOG, [$columns=DataExfiltration, $path="data_exfiltration"]);
    print "iSECTECH Data Exfiltration Detection Module loaded";
}

# Cleanup old profiles periodically
event profile_cleanup_timer()
{
    local cutoff_time = network_time() - 24hrs;
    
    # Clean up old transfer profiles
    for (host in transfer_profiles) {
        if (transfer_profiles[host]$last_activity < cutoff_time) {
            delete transfer_profiles[host];
        }
    }
    
    # Clean up old DNS profiles
    for (client in dns_profiles) {
        if (dns_profiles[client]$last_seen < cutoff_time) {
            delete dns_profiles[client];
        }
    }
    
    # Clean up old large transfer tracking
    for (uid in large_transfers) {
        if (large_transfers[uid] < cutoff_time) {
            delete large_transfers[uid];
        }
    }
    
    # Schedule next cleanup
    schedule 6hr { profile_cleanup_timer() };
}

event zeek_init() &priority=-5
{
    # Start cleanup timer
    schedule 6hr { profile_cleanup_timer() };
}