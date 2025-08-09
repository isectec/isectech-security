# iSECTECH Protocol Anomaly Detection for Zeek
# Advanced protocol deviation and manipulation detection

module iSECTECH;

export {
    ## Protocol anomaly categories
    type ProtocolAnomalyType: enum {
        MALFORMED_HEADER,
        PROTOCOL_VIOLATION,
        UNEXPECTED_BEHAVIOR,
        SIZE_ANOMALY,
        TIMING_ANOMALY,
        ENCRYPTION_ANOMALY,
        PROTOCOL_TUNNELING,
        COVERT_CHANNEL
    };

    ## Protocol anomaly record
    type ProtocolAnomaly: record {
        ts: time;
        uid: string;
        id: conn_id;
        protocol: string;
        anomaly_type: ProtocolAnomalyType;
        severity: ThreatLevel;
        description: string;
        details: string;
        indicators: vector of string;
        confidence: count;
    };

    ## Log stream for protocol anomalies
    redef enum Log::ID += { PROTOCOL_ANOMALY_LOG };

    ## Events
    global protocol_anomaly_detected: event(c: connection, anomaly: ProtocolAnomaly);

    ## Configuration
    option enable_deep_protocol_inspection: bool = T;
    option protocol_size_deviation_threshold: double = 2.0;
    option timing_anomaly_threshold: interval = 50msec;
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL BASELINE TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

type ProtocolBaseline: record {
    protocol: string;
    avg_request_size: double;
    avg_response_size: double;
    std_request_size: double;
    std_response_size: double;
    avg_response_time: interval;
    std_response_time: interval;
    sample_count: count;
    last_updated: time;
};

global protocol_baselines: table[string] of ProtocolBaseline;

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP PROTOCOL ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (!enable_deep_protocol_inspection)
        return;

    local anomalies: vector of ProtocolAnomaly;

    # Check for malformed HTTP headers
    if (method !in set("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")) {
        local anomaly = ProtocolAnomaly(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = "HTTP",
            $anomaly_type = PROTOCOL_VIOLATION,
            $severity = MEDIUM,
            $description = "Unusual HTTP method detected",
            $details = fmt("HTTP method: %s", method),
            $indicators = vector(method),
            $confidence = 85
        );
        anomalies += anomaly;
    }

    # Check for extremely long URIs (potential overflow attempts)
    if (|original_URI| > 8192) {
        local long_uri_anomaly = ProtocolAnomaly(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = "HTTP",
            $anomaly_type = SIZE_ANOMALY,
            $severity = HIGH,
            $description = "Extremely long HTTP URI detected",
            $details = fmt("URI length: %d bytes", |original_URI|),
            $indicators = vector("long_uri"),
            $confidence = 90
        );
        anomalies += long_uri_anomaly;
    }

    # Check for URI encoding anomalies
    if (original_URI != unescaped_URI) {
        local uri_diff = |original_URI| - |unescaped_URI|;
        if (uri_diff > |original_URI| * 0.5) {  # More than 50% encoded
            local encoding_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = "HTTP",
                $anomaly_type = PROTOCOL_VIOLATION,
                $severity = MEDIUM,
                $description = "Excessive URI encoding detected",
                $details = fmt("Encoding ratio: %.2f%%", (uri_diff * 100.0) / |original_URI|),
                $indicators = vector("excessive_encoding"),
                $confidence = 75
            );
            anomalies += encoding_anomaly;
        }
    }

    # Log detected anomalies
    for (idx in anomalies) {
        Log::write(PROTOCOL_ANOMALY_LOG, anomalies[idx]);
        event protocol_anomaly_detected(c, anomalies[idx]);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS PROTOCOL ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (!enable_deep_protocol_inspection)
        return;

    local anomalies: vector of ProtocolAnomaly;

    # Check for DNS tunneling indicators
    if (|query| > 253) {  # DNS name too long
        local dns_anomaly = ProtocolAnomaly(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = "DNS",
            $anomaly_type = PROTOCOL_TUNNELING,
            $severity = HIGH,
            $description = "DNS query name exceeds RFC limits",
            $details = fmt("Query length: %d bytes, Query: %s", |query|, query),
            $indicators = vector("dns_tunneling", "oversized_query"),
            $confidence = 95
        );
        anomalies += dns_anomaly;
    }

    # Check for suspicious subdomain count (potential data exfiltration)
    local subdomain_count = 0;
    local parts = split_string(query, /\./);
    subdomain_count = |parts| - 2;  # Subtract domain and TLD

    if (subdomain_count > 10) {
        local subdomain_anomaly = ProtocolAnomaly(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $protocol = "DNS",
            $anomaly_type = COVERT_CHANNEL,
            $severity = MEDIUM,
            $description = "Excessive DNS subdomain levels detected",
            $details = fmt("Subdomain levels: %d, Query: %s", subdomain_count, query),
            $indicators = vector("dns_tunneling", "excessive_subdomains"),
            $confidence = 80
        );
        anomalies += subdomain_anomaly;
    }

    # Check for Base32/Base64 encoded data in DNS queries
    if (/[a-z0-9]{20,}/ in query && /[^a-z0-9\.-]/ !in query) {
        local encoding_pattern = extract_pattern(query, /[a-z0-9]{20,}/);
        if (is_likely_encoded(encoding_pattern)) {
            local encoded_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = "DNS",
                $anomaly_type = COVERT_CHANNEL,
                $severity = HIGH,
                $description = "Encoded data in DNS query detected",
                $details = fmt("Suspicious pattern: %s", encoding_pattern),
                $indicators = vector("dns_tunneling", "encoded_data"),
                $confidence = 85
            );
            anomalies += encoded_anomaly;
        }
    }

    # Log detected anomalies
    for (idx in anomalies) {
        Log::write(PROTOCOL_ANOMALY_LOG, anomalies[idx]);
        event protocol_anomaly_detected(c, anomalies[idx]);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TLS/SSL PROTOCOL ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event ssl_established(c: connection)
{
    if (!enable_deep_protocol_inspection)
        return;

    local anomalies: vector of ProtocolAnomaly;

    # Check for weak TLS versions
    if (c?$ssl && c$ssl?$version) {
        if (c$ssl$version in ["SSLv2", "SSLv3", "TLSv10", "TLSv11"]) {
            local weak_tls_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = "TLS",
                $anomaly_type = PROTOCOL_VIOLATION,
                $severity = MEDIUM,
                $description = "Weak TLS version detected",
                $details = fmt("TLS version: %s", c$ssl$version),
                $indicators = vector("weak_crypto", c$ssl$version),
                $confidence = 100
            );
            anomalies += weak_tls_anomaly;
        }
    }

    # Check for suspicious certificate characteristics
    if (c?$ssl && c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) {
        local cert = c$ssl$cert_chain[0];
        
        # Self-signed certificate detection
        if (cert?$subject && cert?$issuer && cert$subject == cert$issuer) {
            local self_signed_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = "TLS",
                $anomaly_type = ENCRYPTION_ANOMALY,
                $severity = MEDIUM,
                $description = "Self-signed certificate detected",
                $details = fmt("Subject: %s", cert$subject),
                $indicators = vector("self_signed_cert"),
                $confidence = 100
            );
            anomalies += self_signed_anomaly;
        }

        # Short validity period (potential throwaway cert)
        if (cert?$not_valid_before && cert?$not_valid_after) {
            local validity_period = cert$not_valid_after - cert$not_valid_before;
            if (validity_period < 30days) {
                local short_validity_anomaly = ProtocolAnomaly(
                    $ts = network_time(),
                    $uid = c$uid,
                    $id = c$id,
                    $protocol = "TLS",
                    $anomaly_type = ENCRYPTION_ANOMALY,
                    $severity = MEDIUM,
                    $description = "Certificate with unusually short validity period",
                    $details = fmt("Validity period: %.1f days", validity_period / 1day),
                    $indicators = vector("short_cert_validity"),
                    $confidence = 85
                );
                anomalies += short_validity_anomaly;
            }
        }
    }

    # Log detected anomalies
    for (idx in anomalies) {
        Log::write(PROTOCOL_ANOMALY_LOG, anomalies[idx]);
        event protocol_anomaly_detected(c, anomalies[idx]);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TIMING ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event connection_state_remove(c: connection)
{
    if (!enable_deep_protocol_inspection)
        return;

    local anomalies: vector of ProtocolAnomaly;

    # Analyze connection timing patterns
    if (c?$duration) {
        local service = c?$service ? c$service : "unknown";
        
        # Check for extremely short connections (potential scanning)
        if (c$duration < 1msec && c?$orig_bytes && c$orig_bytes > 0) {
            local short_conn_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = service,
                $anomaly_type = TIMING_ANOMALY,
                $severity = LOW,
                $description = "Extremely short connection duration",
                $details = fmt("Duration: %.3f ms", c$duration / 1msec),
                $indicators = vector("short_connection"),
                $confidence = 70
            );
            anomalies += short_conn_anomaly;
        }

        # Check for extremely long connections without data transfer
        if (c$duration > 1hr && (!c?$orig_bytes || c$orig_bytes < 100)) {
            local long_idle_anomaly = ProtocolAnomaly(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $protocol = service,
                $anomaly_type = TIMING_ANOMALY,
                $severity = MEDIUM,
                $description = "Long idle connection detected",
                $details = fmt("Duration: %.1f hours, Bytes: %d", c$duration / 1hr, c?$orig_bytes ? c$orig_bytes : 0),
                $indicators = vector("long_idle_connection"),
                $confidence = 75
            );
            anomalies += long_idle_anomaly;
        }
    }

    # Log detected anomalies
    for (idx in anomalies) {
        Log::write(PROTOCOL_ANOMALY_LOG, anomalies[idx]);
        event protocol_anomaly_detected(c, anomalies[idx]);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function is_likely_encoded(data: string): bool
{
    # Simple heuristic to detect Base32/Base64 encoded data
    # Check for high entropy and character distribution
    local char_counts: table[string] of count;
    local total_chars = |data|;
    
    if (total_chars < 20)
        return F;
    
    # Count character frequencies
    for (i in data) {
        local char = data[i];
        if (char !in char_counts)
            char_counts[char] = 0;
        char_counts[char] += 1;
    }
    
    # Calculate entropy-like metric
    local unique_chars = |char_counts|;
    local entropy_score = (unique_chars * 100) / total_chars;
    
    # Encoded data typically has more uniform character distribution
    return entropy_score > 15;  # Threshold for encoded data
}

function extract_pattern(str: string, pattern: pattern): string
{
    # Extract first match of pattern from string
    # This is a simplified implementation
    local matches = find_all(str, pattern);
    if (|matches| > 0)
        return matches[0];
    else
        return "";
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(PROTOCOL_ANOMALY_LOG, [$columns=ProtocolAnomaly, $path="protocol_anomalies"]);
    print "iSECTECH Protocol Anomaly Detection Module loaded";
}

# Update protocol baselines periodically
event baseline_update_timer()
{
    # Update baselines for all tracked protocols
    for (protocol in protocol_baselines) {
        local baseline = protocol_baselines[protocol];
        # Age out old baselines
        if (network_time() - baseline$last_updated > 24hrs) {
            # Reset baseline for fresh data
            baseline$sample_count = 0;
        }
    }
    
    # Schedule next update
    schedule 1hr { baseline_update_timer() };
}

event zeek_init() &priority=-5
{
    # Start baseline update timer
    schedule 1hr { baseline_update_timer() };
}