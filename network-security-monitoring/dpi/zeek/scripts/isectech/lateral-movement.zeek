# iSECTECH Lateral Movement Detection for Zeek
# Advanced detection of internal network reconnaissance and privilege escalation

module iSECTECH;

export {
    ## Lateral movement techniques
    type LateralMovementTechnique: enum {
        CREDENTIAL_BRUTE_FORCE,
        CREDENTIAL_STUFFING,
        PASS_THE_HASH,
        PASS_THE_TICKET,
        REMOTE_EXECUTION,
        REMOTE_SERVICES,
        NETWORK_SCANNING,
        SERVICE_ENUMERATION,
        SHARE_ENUMERATION,
        PRIVILEGE_ESCALATION,
        WMIC_EXECUTION,
        PSEXEC_USAGE,
        WMI_ACTIVITY,
        LATERAL_TOOL_USAGE
    };

    ## Lateral movement event record
    type LateralMovement: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        technique: string &log;
        confidence: count &log;
        severity: string &log;
        source_host: addr &log;
        target_host: addr &log;
        service: string &log &optional;
        username: string &log &optional;
        success: bool &log &optional;
        indicators: vector of string &log;
        description: string &log;
        mitre_technique: string &log &optional;
        evidence: string &log &optional;
        tool_signatures: set[string] &log &optional;
    };

    ## Log stream for lateral movement events
    redef enum Log::ID += { LATERAL_MOVEMENT_LOG };

    ## Events
    global lateral_movement_detected: event(c: connection, movement: LateralMovement);

    ## Configuration options
    option lateral_scan_threshold: count = 10;
    option lateral_time_window: interval = 5min;
    option enable_credential_monitoring: bool = T;
    option enable_scanning_detection: bool = T;
    option admin_subnets: set[subnet] = { 10.0.1.0/24, 192.168.1.0/24 };
}

# ═══════════════════════════════════════════════════════════════════════════════
# HOST ACTIVITY TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

type HostActivity: record {
    host: addr;
    target_hosts: set[addr];
    target_services: set[string];
    login_attempts: count;
    successful_logins: count;
    failed_logins: count;
    scan_targets: count;
    admin_access_attempts: count;
    suspicious_tools: set[string];
    first_activity: time;
    last_activity: time;
    activity_window: interval;
};

global host_activities: table[addr] of HostActivity;

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK SCANNING DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

type ScanPattern: record {
    scanner: addr;
    targets: set[addr];
    ports: set[port];
    scan_start: time;
    scan_duration: interval;
    connection_attempts: count;
    successful_connections: count;
    scan_type: string;
};

global active_scans: table[addr] of ScanPattern;

event connection_attempt(c: connection)
{
    local scanner = c$id$orig_h;
    local target = c$id$resp_h;
    local target_port = c$id$resp_p;

    # Only track internal-to-internal scanning
    if (!Site::is_local_addr(scanner) || !Site::is_local_addr(target))
        return;

    # Initialize or update scan pattern
    if (scanner !in active_scans) {
        active_scans[scanner] = ScanPattern(
            $scanner = scanner,
            $targets = set(),
            $ports = set(),
            $scan_start = network_time(),
            $scan_duration = 0secs,
            $connection_attempts = 0,
            $successful_connections = 0,
            $scan_type = ""
        );
    }

    local scan = active_scans[scanner];
    add scan$targets[target];
    add scan$ports[target_port];
    scan$connection_attempts += 1;
    scan$scan_duration = network_time() - scan$scan_start;

    # Update scan type classification
    if (|scan$targets| > 20 && |scan$ports| < 5) {
        scan$scan_type = "host_sweep";
    } else if (|scan$ports| > 20 && |scan$targets| < 5) {
        scan$scan_type = "port_scan";
    } else if (|scan$targets| > 10 && |scan$ports| > 10) {
        scan$scan_type = "network_scan";
    }

    active_scans[scanner] = scan;

    # Check for scanning threshold
    if ((|scan$targets| >= lateral_scan_threshold || |scan$ports| >= lateral_scan_threshold) &&
        scan$scan_duration <= lateral_time_window) {
        
        local indicators: vector of string;
        local confidence = 0;
        
        indicators += fmt("scanned_%d_targets", |scan$targets|);
        indicators += fmt("scanned_%d_ports", |scan$ports|);
        confidence += 40;

        # Higher confidence for rapid scanning
        if (scan$scan_duration < 1min) {
            indicators += "rapid_scanning";
            confidence += 20;
        }

        # Check for administrative service targeting
        local admin_ports = { 22/tcp, 23/tcp, 135/tcp, 139/tcp, 445/tcp, 3389/tcp, 5985/tcp, 5986/tcp };
        local admin_port_count = 0;
        for (port in scan$ports) {
            if (port in admin_ports) {
                admin_port_count += 1;
            }
        }
        
        if (admin_port_count > 0) {
            indicators += "admin_service_targeting";
            confidence += 25;
        }

        local movement_event = LateralMovement(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $technique = "NETWORK_SCANNING",
            $confidence = confidence,
            $severity = confidence >= 70 ? "HIGH" : "MEDIUM",
            $source_host = scanner,
            $target_host = target,
            $indicators = indicators,
            $description = fmt("Network scanning detected: %s (%d targets, %d ports)", 
                              scan$scan_type, |scan$targets|, |scan$ports|),
            $mitre_technique = "T1046",
            $evidence = fmt("Scanned %d hosts and %d ports in %.1f seconds", 
                           |scan$targets|, |scan$ports|, scan$scan_duration)
        );

        Log::write(LATERAL_MOVEMENT_LOG, movement_event);
        event lateral_movement_detected(c, movement_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SMB/WINDOWS CREDENTIAL ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════

event smb2_tree_connect_request(c: connection, hdr: SMB2::Header, req: SMB2::TreeConnectRequest)
{
    if (!enable_credential_monitoring)
        return;

    local source = c$id$orig_h;
    local target = c$id$resp_h;
    local share_path = req$path;

    # Track SMB share access patterns
    update_host_activity(source, target, "SMB");

    local indicators: vector of string;
    local confidence = 0;

    # Check for administrative share access
    if (/\$/ in share_path && /(C|ADMIN|IPC)\$/ in share_path) {
        indicators += "admin_share_access";
        confidence += 30;
    }

    # Check for SYSVOL/NETLOGON access (domain controller shares)
    if (/(SYSVOL|NETLOGON)/i in share_path) {
        indicators += "domain_share_access";
        confidence += 25;
    }

    # Check if accessing multiple different shares rapidly
    if (source in host_activities) {
        local activity = host_activities[source];
        if (|activity$target_hosts| > 5 && 
            network_time() - activity$first_activity < 5min) {
            indicators += "rapid_share_enumeration";
            confidence += 30;
        }
    }

    if (confidence >= 25) {
        local movement_event = LateralMovement(
            $ts = network_time(),
            $uid = c$uid,
            $id = c$id,
            $technique = "SHARE_ENUMERATION",
            $confidence = confidence,
            $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
            $source_host = source,
            $target_host = target,
            $service = "SMB",
            $indicators = indicators,
            $description = fmt("SMB share enumeration: %s", share_path),
            $mitre_technique = "T1135",
            $evidence = fmt("SMB TreeConnect to %s", share_path)
        );

        Log::write(LATERAL_MOVEMENT_LOG, movement_event);
        event lateral_movement_detected(c, movement_event);
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSH LATERAL MOVEMENT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event ssh_auth_attempted(c: connection, authenticated: bool)
{
    if (!enable_credential_monitoring)
        return;

    local source = c$id$orig_h;
    local target = c$id$resp_h;

    # Track SSH authentication patterns
    update_host_activity(source, target, "SSH");

    if (source in host_activities) {
        local activity = host_activities[source];
        
        if (authenticated) {
            activity$successful_logins += 1;
        } else {
            activity$failed_logins += 1;
        }

        local indicators: vector of string;
        local confidence = 0;

        # Check for brute force patterns
        if (activity$failed_logins > 10 && 
            network_time() - activity$first_activity < 10min) {
            indicators += "ssh_brute_force";
            confidence += 40;
        }

        # Check for successful login after failures
        if (authenticated && activity$failed_logins > 5) {
            indicators += "successful_after_failures";
            confidence += 30;
        }

        # Check for lateral SSH connections (internal to internal)
        if (Site::is_local_addr(source) && Site::is_local_addr(target) && source != target) {
            indicators += "internal_ssh_lateral";
            confidence += 25;
        }

        # Check for multiple target enumeration
        if (|activity$target_hosts| > 3 && 
            network_time() - activity$first_activity < 15min) {
            indicators += "ssh_host_enumeration";
            confidence += 30;
        }

        host_activities[source] = activity;

        if (confidence >= 25) {
            local movement_event = LateralMovement(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $technique = authenticated ? "REMOTE_SERVICES" : "CREDENTIAL_BRUTE_FORCE",
                $confidence = confidence,
                $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
                $source_host = source,
                $target_host = target,
                $service = "SSH",
                $success = authenticated,
                $indicators = indicators,
                $description = authenticated ? "Lateral SSH access" : "SSH brute force attempt",
                $mitre_technique = authenticated ? "T1021.004" : "T1110.001",
                $evidence = fmt("SSH auth: %s (failures: %d, targets: %d)", 
                               authenticated ? "success" : "failure", 
                               activity$failed_logins, |activity$target_hosts|)
            );

            Log::write(LATERAL_MOVEMENT_LOG, movement_event);
            event lateral_movement_detected(c, movement_event);
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# RDP LATERAL MOVEMENT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event connection_established(c: connection)
{
    if (c$id$resp_p != 3389/tcp)
        return;

    local source = c$id$orig_h;
    local target = c$id$resp_h;

    # Track RDP connections for lateral movement
    if (!Site::is_local_addr(source) || !Site::is_local_addr(target))
        return;

    update_host_activity(source, target, "RDP");

    if (source in host_activities) {
        local activity = host_activities[source];
        local indicators: vector of string;
        local confidence = 0;

        # Internal RDP connection
        indicators += "internal_rdp_connection";
        confidence += 20;

        # Check for RDP hopping (multiple targets)
        if (|activity$target_hosts| > 2) {
            indicators += "rdp_hopping";
            confidence += 35;
        }

        # Check for admin subnet targeting
        for (subnet in admin_subnets) {
            if (target in subnet) {
                indicators += "admin_subnet_targeting";
                confidence += 30;
                break;
            }
        }

        # Check for rapid RDP connections
        if (network_time() - activity$first_activity < 10min && |activity$target_hosts| > 1) {
            indicators += "rapid_rdp_connections";
            confidence += 25;
        }

        host_activities[source] = activity;

        if (confidence >= 30) {
            local movement_event = LateralMovement(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $technique = "REMOTE_SERVICES",
                $confidence = confidence,
                $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
                $source_host = source,
                $target_host = target,
                $service = "RDP",
                $success = T,
                $indicators = indicators,
                $description = "Lateral RDP connection established",
                $mitre_technique = "T1021.001",
                $evidence = fmt("RDP connection from %s to %s (targets: %d)", 
                               source, target, |activity$target_hosts|)
            );

            Log::write(LATERAL_MOVEMENT_LOG, movement_event);
            event lateral_movement_detected(c, movement_event);
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# WMI AND REMOTE EXECUTION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

event dce_rpc_request(c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
{
    # WMI typically uses DCOM interface {4D36E978-E325-11CE-BFC1-08002BE10318}
    # This is a simplified detection - full WMI detection requires deeper protocol parsing
    
    local source = c$id$orig_h;
    local target = c$id$resp_h;

    if (c$id$resp_p != 135/tcp && c$id$resp_p !in { 1024/tcp-65535/tcp })
        return;

    # Track potential WMI activity
    update_host_activity(source, target, "WMI");

    if (source in host_activities) {
        local activity = host_activities[source];
        local indicators: vector of string;
        local confidence = 0;

        # DCOM/RPC activity to multiple hosts
        if (|activity$target_hosts| > 3) {
            indicators += "dcom_enumeration";
            confidence += 25;
        }

        # Rapid DCOM connections
        if (network_time() - activity$first_activity < 5min && |activity$target_hosts| > 1) {
            indicators += "rapid_dcom_activity";
            confidence += 30;
        }

        # Check for administrative target ports
        if (c$id$resp_p == 135/tcp) {
            indicators += "rpc_endpoint_mapper";
            confidence += 20;
        }

        host_activities[source] = activity;

        if (confidence >= 25) {
            local movement_event = LateralMovement(
                $ts = network_time(),
                $uid = c$uid,
                $id = c$id,
                $technique = "WMI_ACTIVITY",
                $confidence = confidence,
                $severity = confidence >= 60 ? "HIGH" : "MEDIUM",
                $source_host = source,
                $target_host = target,
                $service = "DCOM/WMI",
                $indicators = indicators,
                $description = "Suspicious WMI/DCOM activity detected",
                $mitre_technique = "T1047",
                $evidence = fmt("DCOM RPC request to %s:%d (opnum: %d)", target, c$id$resp_p, opnum)
            );

            Log::write(LATERAL_MOVEMENT_LOG, movement_event);
            event lateral_movement_detected(c, movement_event);
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

function update_host_activity(source: addr, target: addr, service: string)
{
    if (source !in host_activities) {
        host_activities[source] = HostActivity(
            $host = source,
            $target_hosts = set(),
            $target_services = set(),
            $login_attempts = 0,
            $successful_logins = 0,
            $failed_logins = 0,
            $scan_targets = 0,
            $admin_access_attempts = 0,
            $suspicious_tools = set(),
            $first_activity = network_time(),
            $last_activity = network_time(),
            $activity_window = 0secs
        );
    }

    local activity = host_activities[source];
    add activity$target_hosts[target];
    add activity$target_services[service];
    activity$last_activity = network_time();
    activity$activity_window = activity$last_activity - activity$first_activity;
    activity$login_attempts += 1;

    host_activities[source] = activity;
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION AND CLEANUP
# ═══════════════════════════════════════════════════════════════════════════════

event zeek_init()
{
    Log::create_stream(LATERAL_MOVEMENT_LOG, [$columns=LateralMovement, $path="lateral_movement"]);
    print "iSECTECH Lateral Movement Detection Module loaded";
}

# Cleanup old activity tracking
event activity_cleanup_timer()
{
    local cutoff_time = network_time() - 2hr;
    
    # Clean up old host activities
    for (host in host_activities) {
        if (host_activities[host]$last_activity < cutoff_time) {
            delete host_activities[host];
        }
    }
    
    # Clean up old scan patterns
    for (scanner in active_scans) {
        if (active_scans[scanner]$scan_start < cutoff_time) {
            delete active_scans[scanner];
        }
    }
    
    # Schedule next cleanup
    schedule 1hr { activity_cleanup_timer() };
}

event zeek_init() &priority=-5
{
    # Start cleanup timer
    schedule 1hr { activity_cleanup_timer() };
}