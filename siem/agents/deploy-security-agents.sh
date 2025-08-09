#!/bin/bash
# iSECTECH SIEM Security Agents Deployment Script
# Automated deployment of security logging agents across multiple platforms

set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_MODE="${DEPLOYMENT_MODE:-production}"
TENANT_ID="${TENANT_ID:-isectech}"
KAFKA_ENDPOINTS="${KAFKA_ENDPOINTS:-kafka-1.isectech.local:9092,kafka-2.isectech.local:9092,kafka-3.isectech.local:9092}"
ELASTICSEARCH_ENDPOINTS="${ELASTICSEARCH_ENDPOINTS:-elasticsearch-1.isectech.local:9200,elasticsearch-2.isectech.local:9200,elasticsearch-3.isectech.local:9200}"

# Agent versions
VECTOR_VERSION="0.34.0"
FILEBEAT_VERSION="8.11.0"
ELASTIC_AGENT_VERSION="8.11.0"

# Directories
INSTALL_DIR="/opt/isectech-siem-agents"
CONFIG_DIR="/etc/isectech-siem-agents"
LOG_DIR="/var/log/isectech-siem-agents"
DATA_DIR="/var/lib/isectech-siem-agents"

# Logging
LOG_FILE="/var/log/agent-deployment.log"
VERBOSE="${VERBOSE:-false}"

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING AND UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    if [[ "$VERBOSE" == "true" ]]; then
        echo "[$timestamp] [$level] $message" >&2
    fi
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "WARN" "$@"
}

log_error() {
    log "ERROR" "$@"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        log "DEBUG" "$@"
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS="$ID"
        VERSION="$VERSION_ID"
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
        VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release | head -1)
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        VERSION=$(cat /etc/debian_version)
    else
        log_error "Unable to detect operating system"
        exit 1
    fi
    
    log_info "Detected OS: $OS $VERSION"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"
    mkdir -p "$CONFIG_DIR/vector" "$CONFIG_DIR/filebeat" "$CONFIG_DIR/certs"
    mkdir -p "$DATA_DIR/vector" "$DATA_DIR/filebeat"
    
    # Set appropriate permissions
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"
    chmod 750 "$DATA_DIR"
    chmod 700 "$CONFIG_DIR/certs"
    
    log_info "Directories created successfully"
}

check_dependencies() {
    log_info "Checking system dependencies..."
    
    local deps=("curl" "wget" "systemctl" "tar" "gzip")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Installing missing dependencies..."
        
        case "$OS" in
            ubuntu|debian)
                apt-get update
                apt-get install -y "${missing_deps[@]}"
                ;;
            rhel|centos|fedora)
                if command -v dnf &> /dev/null; then
                    dnf install -y "${missing_deps[@]}"
                else
                    yum install -y "${missing_deps[@]}"
                fi
                ;;
            *)
                log_error "Unsupported OS for automatic dependency installation: $OS"
                exit 1
                ;;
        esac
    fi
    
    log_info "Dependencies check completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

generate_certificates() {
    log_info "Generating TLS certificates for secure communication..."
    
    local hostname=$(hostname -f)
    local cert_dir="$CONFIG_DIR/certs"
    
    # Generate CA private key
    openssl genrsa -out "$cert_dir/ca-key.pem" 4096
    
    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key "$cert_dir/ca-key.pem" \
        -out "$cert_dir/ca.pem" \
        -subj "/C=US/ST=State/L=City/O=iSECTECH/OU=SIEM/CN=iSECTECH-CA"
    
    # Generate agent private key
    openssl genrsa -out "$cert_dir/agent-key.pem" 4096
    
    # Generate agent certificate request
    openssl req -new -key "$cert_dir/agent-key.pem" \
        -out "$cert_dir/agent.csr" \
        -subj "/C=US/ST=State/L=City/O=iSECTECH/OU=SIEM/CN=$hostname"
    
    # Create extensions file
    cat > "$cert_dir/agent-ext.cnf" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $hostname
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Generate agent certificate
    openssl x509 -req -in "$cert_dir/agent.csr" \
        -CA "$cert_dir/ca.pem" \
        -CAkey "$cert_dir/ca-key.pem" \
        -CAcreateserial \
        -out "$cert_dir/agent.pem" \
        -days 365 \
        -extensions v3_req \
        -extfile "$cert_dir/agent-ext.cnf"
    
    # Set permissions
    chmod 600 "$cert_dir"/*-key.pem
    chmod 644 "$cert_dir"/*.pem "$cert_dir"/*.csr
    
    # Clean up
    rm "$cert_dir/agent.csr" "$cert_dir/agent-ext.cnf"
    
    log_info "Certificates generated successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# VECTOR AGENT INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════

install_vector() {
    log_info "Installing Vector agent version $VECTOR_VERSION..."
    
    local arch
    case "$(uname -m)" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    local vector_url="https://github.com/vectordotdev/vector/releases/download/v${VECTOR_VERSION}/vector-${VECTOR_VERSION}-${arch}-unknown-linux-gnu.tar.gz"
    local temp_dir=$(mktemp -d)
    
    log_debug "Downloading Vector from: $vector_url"
    wget -q -O "$temp_dir/vector.tar.gz" "$vector_url"
    
    tar -xzf "$temp_dir/vector.tar.gz" -C "$temp_dir"
    mv "$temp_dir/vector-"*"/bin/vector" "$INSTALL_DIR/"
    
    # Copy configuration
    cp "$SCRIPT_DIR/vector-agent-config.toml" "$CONFIG_DIR/vector/vector.toml"
    
    # Update configuration with environment-specific values
    sed -i "s|bootstrap_servers = \"kafka-cluster:9092\"|bootstrap_servers = \"$KAFKA_ENDPOINTS\"|g" \
        "$CONFIG_DIR/vector/vector.toml"
    
    # Create systemd service
    cat > /etc/systemd/system/vector-agent.service << EOF
[Unit]
Description=iSECTECH Vector Security Agent
Documentation=https://vector.dev/
After=network-online.target
Requires=network-online.target

[Service]
Type=exec
User=root
Group=root
ExecStart=$INSTALL_DIR/vector --config $CONFIG_DIR/vector/vector.toml
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
LimitNOFILE=65536
LimitNPROC=65536

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR/vector $LOG_DIR $CONFIG_DIR/vector
PrivateTmp=true
PrivateDevices=false
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Environment
Environment=ENVIRONMENT=$DEPLOYMENT_MODE
Environment=TENANT_ID=$TENANT_ID

[Install]
WantedBy=multi-user.target
EOF
    
    # Set permissions
    chmod +x "$INSTALL_DIR/vector"
    chmod 644 "$CONFIG_DIR/vector/vector.toml"
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable vector-agent
    
    # Clean up
    rm -rf "$temp_dir"
    
    log_info "Vector agent installed successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# FILEBEAT INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════

install_filebeat() {
    log_info "Installing Filebeat version $FILEBEAT_VERSION..."
    
    local arch
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    local filebeat_url="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-${FILEBEAT_VERSION}-linux-${arch}.tar.gz"
    local temp_dir=$(mktemp -d)
    
    log_debug "Downloading Filebeat from: $filebeat_url"
    wget -q -O "$temp_dir/filebeat.tar.gz" "$filebeat_url"
    
    tar -xzf "$temp_dir/filebeat.tar.gz" -C "$temp_dir"
    mv "$temp_dir/filebeat-"*"/filebeat" "$INSTALL_DIR/"
    
    # Copy modules and other necessary files
    cp -r "$temp_dir/filebeat-"*"/modules.d" "$CONFIG_DIR/filebeat/"
    cp -r "$temp_dir/filebeat-"*"/module" "$CONFIG_DIR/filebeat/" 2>/dev/null || true
    
    # Copy configuration
    cp "$SCRIPT_DIR/filebeat-security.yml" "$CONFIG_DIR/filebeat/filebeat.yml"
    
    # Update configuration with environment-specific values
    sed -i "s|kafka-cluster:9092|$KAFKA_ENDPOINTS|g" "$CONFIG_DIR/filebeat/filebeat.yml"
    
    # Create systemd service
    cat > /etc/systemd/system/filebeat-agent.service << EOF
[Unit]
Description=iSECTECH Filebeat Security Agent
Documentation=https://www.elastic.co/beats/filebeat
After=network-online.target
Requires=network-online.target

[Service]
Type=exec
User=root
Group=root
ExecStart=$INSTALL_DIR/filebeat -c $CONFIG_DIR/filebeat/filebeat.yml -path.home $DATA_DIR/filebeat -path.config $CONFIG_DIR/filebeat -path.data $DATA_DIR/filebeat/data -path.logs $LOG_DIR
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
LimitNOFILE=65536
LimitNPROC=65536

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR/filebeat $LOG_DIR $CONFIG_DIR/filebeat
PrivateTmp=true
PrivateDevices=false
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false

# Environment
Environment=ENVIRONMENT=$DEPLOYMENT_MODE
Environment=TENANT_ID=$TENANT_ID

[Install]
WantedBy=multi-user.target
EOF
    
    # Set permissions
    chmod +x "$INSTALL_DIR/filebeat"
    chmod 644 "$CONFIG_DIR/filebeat/filebeat.yml"
    chmod -R 644 "$CONFIG_DIR/filebeat/modules.d/"*
    
    # Create data directory
    mkdir -p "$DATA_DIR/filebeat/data"
    chown -R root:root "$DATA_DIR/filebeat"
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable filebeat-agent
    
    # Clean up
    rm -rf "$temp_dir"
    
    log_info "Filebeat agent installed successfully"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUDITD CONFIGURATION FOR ENHANCED SECURITY LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

configure_auditd() {
    log_info "Configuring auditd for enhanced security logging..."
    
    # Install auditd if not present
    if ! command -v auditctl &> /dev/null; then
        case "$OS" in
            ubuntu|debian)
                apt-get install -y auditd audispd-plugins
                ;;
            rhel|centos|fedora)
                if command -v dnf &> /dev/null; then
                    dnf install -y audit audit-libs
                else
                    yum install -y audit audit-libs
                fi
                ;;
        esac
    fi
    
    # Backup existing configuration
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.backup.$(date +%Y%m%d%H%M%S)
    cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.backup.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
    
    # Configure auditd.conf
    cat > /etc/audit/auditd.conf << EOF
# iSECTECH SIEM Enhanced Auditd Configuration

# Local events
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = root
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
num_logs = 10
priority_boost = 4
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
##name = mydomain
max_log_file_action = ROTATE
space_left = 500
space_left_action = SYSLOG
verify_email = yes
action_mail_acct = root
admin_space_left = 100
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
EOF
    
    # Create comprehensive audit rules
    cat > /etc/audit/rules.d/isectech-security.rules << EOF
# iSECTECH SIEM Security Audit Rules
# Based on NIST 800-53 and CIS recommendations

# Remove existing rules
-D

# Set buffer size
-b 8192

# Set failure mode (0=silent, 1=printk, 2=panic)
-f 1

# Monitor authentication and authorization
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/ping -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/reboot -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/halt -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/sysconfig/network-scripts/ -p wa -k network
-w /etc/resolv.conf -p wa -k network

# Monitor system startup scripts
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/systemd/ -p wa -k init
-w /etc/rc.d/init.d/ -p wa -k init

# Monitor library files
-w /lib -p wa -k libs
-w /lib64 -p wa -k libs
-w /usr/lib -p wa -k libs
-w /usr/lib64 -p wa -k libs

# Monitor kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

# Monitor file permission changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitor unauthorized access attempts
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Monitor process and session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Monitor login configuration
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login

# Monitor discretionary access control permission modification events
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Monitor successful file system mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Monitor file deletion events by user
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Monitor changes to system administration scope
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor system administrator actions
-w /var/log/sudo.log -p wa -k actions

# Make the configuration immutable
-e 2
EOF
    
    # Restart auditd
    systemctl enable auditd
    systemctl restart auditd
    
    log_info "Auditd configuration completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# OSQUERY INSTALLATION FOR ENDPOINT MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

install_osquery() {
    log_info "Installing osquery for endpoint monitoring..."
    
    case "$OS" in
        ubuntu)
            export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
            apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY
            add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'
            apt-get update
            apt-get install -y osquery
            ;;
        debian)
            wget -q https://pkg.osquery.io/deb/pubkey.gpg -O- | apt-key add -
            echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list
            apt-get update
            apt-get install -y osquery
            ;;
        rhel|centos)
            curl -L https://pkg.osquery.io/rpm/GPG | rpm --import -
            yum-config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
            yum install -y osquery
            ;;
        fedora)
            curl -L https://pkg.osquery.io/rpm/GPG | rpm --import -
            dnf config-manager --add-repo https://pkg.osquery.io/rpm/osquery-s3-rpm.repo
            dnf install -y osquery
            ;;
        *)
            log_warn "Osquery installation not supported for OS: $OS"
            return
            ;;
    esac
    
    # Configure osquery
    cat > /etc/osquery/osquery.conf << EOF
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "utc": "true",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "logger_path": "/var/log/osquery",
    "logger_mode": "0640",
    "disable_events": "false",
    "disable_audit": "false",
    "audit_allow_config": "true",
    "host_identifier": "hostname",
    "enable_syslog": "true",
    "audit_allow_sockets": "true",
    "schedule_default_interval": "3600",
    "enable_file_events": "true",
    "enable_process_events": "true",
    "enable_network_events": "true"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "network_interfaces": {
      "query": "SELECT interface, address, mask, broadcast, point_to_point FROM interface_addresses WHERE interface NOT LIKE 'lo%';",
      "interval": 600
    },
    "listening_ports": {
      "query": "SELECT pid, port, protocol, family, address FROM listening_ports WHERE port != 0;",
      "interval": 86400
    },
    "logged_in_users": {
      "query": "SELECT user, tty, time, host FROM logged_in_users;",
      "interval": 600
    },
    "crontab": {
      "query": "SELECT command, path FROM crontab;",
      "interval": 3600
    },
    "kernel_modules": {
      "query": "SELECT name, size, used_by FROM kernel_modules;",
      "interval": 3600
    },
    "open_sockets": {
      "query": "SELECT pid, family, protocol, local_address, local_port, remote_address, remote_port, path, state FROM process_open_sockets WHERE path <> '' OR remote_address <> '';",
      "interval": 86400
    },
    "shell_history": {
      "query": "SELECT uid, command, time FROM shell_history WHERE time > ((SELECT unix_time FROM time) - 86400);",
      "interval": 3600
    },
    "startup_items": {
      "query": "SELECT name, path, args, type FROM startup_items;",
      "interval": 3600
    },
    "suid_bin": {
      "query": "SELECT path, permissions FROM suid_bin;",
      "interval": 3600
    }
  },
  "file_paths": {
    "configuration": [
      "/etc/passwd",
      "/etc/shadow",
      "/etc/ld.so.preload",
      "/etc/ld.so.conf",
      "/etc/ld.so.conf.d/%%",
      "/etc/pam.d/%%",
      "/etc/resolv.conf",
      "/etc/rc%/%%",
      "/etc/my.cnf",
      "/etc/nginx/nginx.conf",
      "/etc/apache2/apache2.conf",
      "/etc/httpd/conf/httpd.conf",
      "/etc/mysql/my.cnf"
    ],
    "binaries": [
      "/usr/bin/%%",
      "/usr/sbin/%%",
      "/bin/%%",
      "/sbin/%%",
      "/usr/local/bin/%%",
      "/usr/local/sbin/%%" 
    ]
  },
  "events": {
    "disable_subscribers": ["user_events"]
  }
}
EOF
    
    # Configure osquery flags
    cat > /etc/osquery/osquery.flags << EOF
--config_path=/etc/osquery/osquery.conf
--logger_path=/var/log/osquery
--pidfile=/var/osquery/osquery.pidfile
--database_path=/var/osquery/osquery.db
--utc
--verbose=false
--disable_logging=false
--enable_file_events=true
--enable_process_events=true
--enable_network_events=true
EOF
    
    # Create osquery directories
    mkdir -p /var/osquery /var/log/osquery
    
    # Enable and start osquery
    systemctl enable osqueryd
    systemctl start osqueryd
    
    log_info "Osquery installation completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

setup_monitoring() {
    log_info "Setting up agent monitoring and health checks..."
    
    # Create monitoring script
    cat > "$INSTALL_DIR/check-agents.sh" << 'EOF'
#!/bin/bash
# iSECTECH SIEM Agents Health Check Script

LOG_FILE="/var/log/agent-health.log"
METRIC_FILE="/var/log/agent-metrics.log"

log_metric() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $*" >> "$METRIC_FILE"
}

check_service() {
    local service_name="$1"
    local friendly_name="$2"
    
    if systemctl is-active --quiet "$service_name"; then
        log_metric "service.status,$friendly_name,1"
        echo "✓ $friendly_name is running"
    else
        log_metric "service.status,$friendly_name,0"
        echo "✗ $friendly_name is not running"
        return 1
    fi
}

check_port() {
    local port="$1"
    local service_name="$2"
    
    if netstat -tuln | grep -q ":$port "; then
        log_metric "service.port,$service_name,$port,1"
        echo "✓ $service_name port $port is listening"
    else
        log_metric "service.port,$service_name,$port,0"
        echo "✗ $service_name port $port is not listening"
        return 1
    fi
}

check_log_file() {
    local log_path="$1"
    local service_name="$2"
    local max_age_minutes="$3"
    
    if [[ -f "$log_path" ]]; then
        local file_age=$(( ($(date +%s) - $(stat -c %Y "$log_path")) / 60 ))
        if [[ $file_age -le $max_age_minutes ]]; then
            log_metric "log.freshness,$service_name,1"
            echo "✓ $service_name logs are fresh (${file_age}m old)"
        else
            log_metric "log.freshness,$service_name,0"
            echo "✗ $service_name logs are stale (${file_age}m old)"
            return 1
        fi
    else
        log_metric "log.exists,$service_name,0"
        echo "✗ $service_name log file does not exist: $log_path"
        return 1
    fi
}

main() {
    echo "=== iSECTECH SIEM Agents Health Check ===" 
    echo "Timestamp: $(date)"
    echo
    
    local overall_status=0
    
    # Check services
    check_service "vector-agent" "Vector" || overall_status=1
    check_service "filebeat-agent" "Filebeat" || overall_status=1
    check_service "auditd" "Auditd" || overall_status=1
    check_service "osqueryd" "Osquery" || overall_status=1
    
    echo
    
    # Check ports
    check_port "8686" "Vector API" || overall_status=1
    check_port "5066" "Filebeat HTTP" || overall_status=1
    
    echo
    
    # Check log freshness
    check_log_file "/var/log/audit/audit.log" "auditd" 10 || overall_status=1
    check_log_file "/var/log/osquery/osqueryd.results.log" "osquery" 30 || overall_status=1
    
    echo
    
    # Check disk space
    local log_disk_usage=$(df /var/log | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $log_disk_usage -lt 80 ]]; then
        log_metric "disk.usage,logs,$log_disk_usage"
        echo "✓ Log disk usage: ${log_disk_usage}%"
    else
        log_metric "disk.usage,logs,$log_disk_usage"
        echo "✗ Log disk usage critical: ${log_disk_usage}%"
        overall_status=1
    fi
    
    # Overall status
    echo
    if [[ $overall_status -eq 0 ]]; then
        echo "✓ All agents are healthy"
        log_metric "health.overall,1"
    else
        echo "✗ Some agents have issues"
        log_metric "health.overall,0"
    fi
    
    exit $overall_status
}

main "$@"
EOF
    
    chmod +x "$INSTALL_DIR/check-agents.sh"
    
    # Create systemd timer for health checks
    cat > /etc/systemd/system/agent-health-check.service << EOF
[Unit]
Description=iSECTECH SIEM Agents Health Check
After=multi-user.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/check-agents.sh
User=root
EOF
    
    cat > /etc/systemd/system/agent-health-check.timer << EOF
[Unit]
Description=Run iSECTECH SIEM Agents Health Check every 5 minutes
Requires=agent-health-check.service

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    systemctl daemon-reload
    systemctl enable agent-health-check.timer
    systemctl start agent-health-check.timer
    
    log_info "Monitoring setup completed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGENT STARTUP AND VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

start_agents() {
    log_info "Starting all security agents..."
    
    local services=("auditd" "osqueryd" "vector-agent" "filebeat-agent")
    local failed_services=()
    
    for service in "${services[@]}"; do
        log_info "Starting $service..."
        if systemctl start "$service"; then
            sleep 5
            if systemctl is-active --quiet "$service"; then
                log_info "$service started successfully"
            else
                log_error "$service failed to start properly"
                failed_services+=("$service")
            fi
        else
            log_error "Failed to start $service"
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -gt 0 ]]; then
        log_error "Failed to start services: ${failed_services[*]}"
        log_info "Check logs for more details:"
        for service in "${failed_services[@]}"; do
            echo "  journalctl -u $service --no-pager -n 20"
        done
        return 1
    fi
    
    log_info "All agents started successfully"
}

validate_deployment() {
    log_info "Validating agent deployment..."
    
    # Run health check
    if "$INSTALL_DIR/check-agents.sh"; then
        log_info "All health checks passed"
    else
        log_warn "Some health checks failed - review agent status"
    fi
    
    # Check if agents are sending data
    log_info "Testing data flow (this may take a few minutes)..."
    
    # Generate test events
    logger -t "isectech-test" "SIEM agent deployment test - $(date)"
    sudo -u root whoami > /dev/null 2>&1
    
    # Wait for events to be processed
    sleep 30
    
    log_info "Deployment validation completed"
    log_info "Monitor agent status with: $INSTALL_DIR/check-agents.sh"
    log_info "Agent logs are available in: $LOG_DIR"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN DEPLOYMENT LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy iSECTECH SIEM security agents

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose logging
    -m, --mode MODE         Deployment mode (production|staging|development)
    -t, --tenant-id ID      Tenant identifier
    -k, --kafka ENDPOINTS   Kafka broker endpoints (comma-separated)
    -e, --elasticsearch ENDPOINTS  Elasticsearch endpoints (comma-separated)
    --skip-auditd           Skip auditd configuration
    --skip-osquery          Skip osquery installation
    --skip-certs            Skip certificate generation
    --agents-only           Install only Vector and Filebeat agents
    --validate-only         Only run validation checks

EXAMPLES:
    $0                      # Standard production deployment
    $0 -v -m staging        # Staging deployment with verbose logging
    $0 --agents-only        # Install only core agents
    $0 --validate-only      # Run health checks only
EOF
}

main() {
    local skip_auditd=false
    local skip_osquery=false
    local skip_certs=false
    local agents_only=false
    local validate_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -t|--tenant-id)
                TENANT_ID="$2"
                shift 2
                ;;
            -k|--kafka)
                KAFKA_ENDPOINTS="$2"
                shift 2
                ;;
            -e|--elasticsearch)
                ELASTICSEARCH_ENDPOINTS="$2"
                shift 2
                ;;
            --skip-auditd)
                skip_auditd=true
                shift
                ;;
            --skip-osquery)
                skip_osquery=true
                shift
                ;;
            --skip-certs)
                skip_certs=true
                shift
                ;;
            --agents-only)
                agents_only=true
                shift
                ;;
            --validate-only)
                validate_only=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Header
    echo "=================================================="
    echo "iSECTECH SIEM Security Agents Deployment"
    echo "=================================================="
    echo "Mode: $DEPLOYMENT_MODE"
    echo "Tenant: $TENANT_ID"
    echo "Kafka: $KAFKA_ENDPOINTS"
    echo "Log file: $LOG_FILE"
    echo "=================================================="
    echo
    
    # Validation only mode
    if [[ "$validate_only" == "true" ]]; then
        if [[ -x "$INSTALL_DIR/check-agents.sh" ]]; then
            "$INSTALL_DIR/check-agents.sh"
        else
            log_error "Health check script not found - agents may not be installed"
            exit 1
        fi
        exit $?
    fi
    
    # Pre-flight checks
    check_root
    detect_os
    check_dependencies
    create_directories
    
    # Generate certificates if not skipped
    if [[ "$skip_certs" != "true" ]]; then
        generate_certificates
    fi
    
    # Install core agents
    install_vector
    install_filebeat
    
    # Install additional components if not agents-only
    if [[ "$agents_only" != "true" ]]; then
        if [[ "$skip_auditd" != "true" ]]; then
            configure_auditd
        fi
        
        if [[ "$skip_osquery" != "true" ]]; then
            install_osquery
        fi
    fi
    
    # Setup monitoring
    setup_monitoring
    
    # Start agents
    start_agents
    
    # Validate deployment
    validate_deployment
    
    echo
    echo "=================================================="
    echo "Deployment completed successfully!"
    echo "=================================================="
    echo "Next steps:"
    echo "1. Monitor agent status: $INSTALL_DIR/check-agents.sh"
    echo "2. Review logs in: $LOG_DIR"
    echo "3. Verify data flow in SIEM dashboard"
    echo "4. Configure additional alerting if needed"
    echo "=================================================="
}

# Run main function
main "$@"