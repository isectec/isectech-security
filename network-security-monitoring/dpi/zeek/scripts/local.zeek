# iSECTECH Network Security Monitoring - Zeek Local Configuration
# Production-grade deep packet inspection and protocol analysis

@load base/frameworks/cluster
@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/reporter
@load base/frameworks/sumstats
@load base/frameworks/intel
@load base/frameworks/control
@load base/frameworks/config

# ═══════════════════════════════════════════════════════════════════════════════
# CORE PROTOCOL ANALYZERS
# ═══════════════════════════════════════════════════════════════════════════════

# Network Layer Protocols
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/dhcp
@load base/protocols/icmp

# Transport Layer Protocols  
@load base/protocols/tcp
@load base/protocols/udp

# Application Layer Protocols
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/smtp
@load base/protocols/pop3
@load base/protocols/imap
@load base/protocols/ftp
@load base/protocols/snmp
@load base/protocols/ntp
@load base/protocols/sip
@load base/protocols/rpc
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/ldap
@load base/protocols/mysql
@load base/protocols/postgresql
@load base/protocols/kerberos
@load base/protocols/radius
@load base/protocols/modbus
@load base/protocols/dnp3

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED ANALYSIS FRAMEWORKS
# ═══════════════════════════════════════════════════════════════════════════════

# File Analysis
@load base/frameworks/files
@load base/files/hash
@load base/files/pe
@load base/files/x509

# Network Analysis
@load base/frameworks/tunnels
@load base/frameworks/packet-filter
@load base/frameworks/dpd

# Intelligence Framework
@load base/frameworks/intel/seen
@load base/frameworks/intel/do_notice

# Software Framework
@load base/frameworks/software

# Signature Framework  
@load base/frameworks/signatures

# ═══════════════════════════════════════════════════════════════════════════════
# POLICY SCRIPTS FOR ENHANCED SECURITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

# Network protocols
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/dns/detect-external-names
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/http/header-names
@load policy/protocols/http/var-extraction-uri
@load policy/protocols/ssl/certificate-log
@load policy/protocols/ssl/extract-certs-pem
@load policy/protocols/ssl/heartbleed
@load policy/protocols/ssl/known-certs
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/geo-data
@load policy/protocols/ssh/interesting-hostnames
@load policy/protocols/smtp/blocklists
@load policy/protocols/smtp/detect-suspicious-orig
@load policy/protocols/ftp/detect-bruteforcing
@load policy/protocols/ftp/detect

# File analysis
@load policy/frameworks/files/detect-MHR
@load policy/frameworks/files/entropy-test-all-files
@load policy/frameworks/files/hash-all-files

# Intelligence  
@load policy/frameworks/intel/seen/where-locations

# Network behaviors
@load policy/misc/detect-traceroute
@load policy/misc/dump-events
@load policy/misc/known-devices
@load policy/misc/scan
@load policy/misc/stats
@load policy/misc/weird-stats

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM ISECTECH SECURITY ANALYZERS
# ═══════════════════════════════════════════════════════════════════════════════

@load ./isectech/threat-detection
@load ./isectech/protocol-anomalies
@load ./isectech/data-exfiltration
@load ./isectech/lateral-movement
@load ./isectech/c2-detection
@load ./isectech/malware-analysis
@load ./isectech/compliance-monitoring
@load ./isectech/performance-monitoring
@load ./isectech/kafka-integration
@load ./isectech/siem-integration

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# JSON logging for SIEM integration
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef LogAscii::include_meta = T;

# Log rotation configuration
redef Log::default_rotation_interval = 1hrs;
redef Log::default_rotation_postprocessor = "gzip";

# Performance optimizations
redef dpd_match_only_beginning = T;
redef dpd_buffer_size = 1024;

# ═══════════════════════════════════════════════════════════════════════════════
# CLUSTER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Enable cluster mode
@if (Cluster::is_enabled())
redef Cluster::retry_interval = 30sec;
redef Cluster::worker_count = 4;
redef Cluster::proxy_count = 2;
@endif

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENCE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Load threat intelligence feeds
@load ./intelligence/feeds

# Intelligence matching configuration
redef Intel::read_files += {
    "/opt/zeek/share/zeek/site/intelligence/indicators.dat",
    "/opt/zeek/share/zeek/site/intelligence/malware-domains.dat",
    "/opt/zeek/share/zeek/site/intelligence/emerging-threats.dat"
};

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Define internal networks
redef Site::local_nets += { 
    10.0.0.0/8,
    192.168.0.0/16,
    172.16.0.0/12
};

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE AND RESOURCE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Connection tracking optimization
redef Conn::default_inactivity_timeout = 15mins;
redef TCP::default_inactivity_timeout = 15mins;
redef UDP::default_inactivity_timeout = 1min;

# Memory management
redef table_expire_interval = 10mins;
redef table_expire_delay = 1min;

# Packet processing optimization
redef PacketFilter::enable_auto_protocol_capture_filters = T;
redef PacketFilter::unrestricted_filter = "";

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING CUSTOMIZATION FOR ISECTECH SIEM
# ═══════════════════════════════════════════════════════════════════════════════

# Add custom fields to connection logs
redef Conn::log_policy += [$columns=set(Conn::UID, Conn::ID, Conn::ORIG_BYTES, Conn::RESP_BYTES)];

# Add GeoIP information
@load ./isectech/geoip-enrichment

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM EVENT HANDLERS FOR REAL-TIME PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init() &priority=5
{
    print "iSECTECH Zeek NSM System initialized";
    Log::write(Reporter::LOG, [$ts=network_time(), $level=Reporter::INFO, 
                               $message="iSECTECH Zeek NSM System started"]);
}

event zeek_done()
{
    print "iSECTECH Zeek NSM System shutting down";
    Log::write(Reporter::LOG, [$ts=network_time(), $level=Reporter::INFO, 
                               $message="iSECTECH Zeek NSM System stopped"]);
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

event reporter_error(t: time, msg: string, location: string)
{
    # Forward critical errors to SIEM
    local notice_msg = fmt("Zeek Error: %s at %s", msg, location);
    NOTICE([$note=Reporter::Error, $msg=notice_msg, $identifier=location]);
}

event weird(name: string, orig: addr, resp: addr, addl: string)
{
    # Log unusual network behavior
    if (name in ["truncated_header", "bad_TCP_header", "connection_originator_SYN_ack"])
        NOTICE([$note=Weird::Activity, $msg=fmt("Weird activity: %s", name),
                $src=orig, $dst=resp, $identifier=addl]);
}