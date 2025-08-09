#!/bin/bash
# Redis Sentinel Startup Script for iSECTECH Trust Scoring
# Production-grade Redis Sentinel configuration with automatic failover

set -euo pipefail

# Configuration
readonly PROJECT_ID="${project_id}"
readonly REGION="${region}"
readonly ENVIRONMENT="${environment:-production}"
readonly LOG_FILE="/var/log/redis-sentinel-setup.log"
readonly SENTINEL_PORT="26379"
readonly SENTINEL_CONFIG="/etc/redis/sentinel.conf"

# Logging
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_info() {
    log "[INFO] $*"
}

log_error() {
    log "[ERROR] $*"
}

log_success() {
    log "[SUCCESS] $*"
}

# Error handling
trap 'log_error "Script failed at line $LINENO"' ERR

main() {
    log_info "Starting Redis Sentinel configuration..."
    
    # Update system
    log_info "Updating system packages..."
    apt-get update -y
    apt-get upgrade -y
    
    # Install required packages
    log_info "Installing required packages..."
    apt-get install -y \
        redis-server \
        redis-tools \
        curl \
        jq \
        google-cloud-ops-agent \
        netcat-openbsd
    
    # Install Google Cloud SDK
    log_info "Installing Google Cloud SDK..."
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
    apt-get update -y
    apt-get install -y google-cloud-cli
    
    # Create Redis directories
    log_info "Creating Redis directories..."
    mkdir -p /etc/redis /var/lib/redis /var/log/redis
    chown redis:redis /var/lib/redis /var/log/redis
    chmod 755 /var/lib/redis
    chmod 750 /var/log/redis
    
    # Get Redis master information
    log_info "Retrieving Redis master information..."
    REDIS_MASTER_HOST=$(gcloud redis instances describe "isectech-trust-cache-primary" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(host)")
    
    REDIS_MASTER_PORT=$(gcloud redis instances describe "isectech-trust-cache-primary" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(port)")
    
    if [[ -z "$REDIS_MASTER_HOST" || -z "$REDIS_MASTER_PORT" ]]; then
        log_error "Failed to retrieve Redis master information"
        exit 1
    fi
    
    log_info "Redis master: $REDIS_MASTER_HOST:$REDIS_MASTER_PORT"
    
    # Get Redis password from Secret Manager
    log_info "Retrieving Redis password..."
    REDIS_PASSWORD=$(gcloud secrets versions access latest \
        --secret="redis-password-primary" \
        --project="$PROJECT_ID")
    
    if [[ -z "$REDIS_PASSWORD" ]]; then
        log_error "Failed to retrieve Redis password"
        exit 1
    fi
    
    # Create Sentinel configuration
    log_info "Creating Sentinel configuration..."
    cat > "$SENTINEL_CONFIG" << EOF
# Redis Sentinel Configuration for iSECTECH Trust Scoring
# Generated on $(date)

port $SENTINEL_PORT

# Master configuration
sentinel monitor isectech-trust-master $REDIS_MASTER_HOST $REDIS_MASTER_PORT 2

# Authentication
sentinel auth-pass isectech-trust-master $REDIS_PASSWORD

# Timing configuration
sentinel down-after-milliseconds isectech-trust-master 30000
sentinel parallel-syncs isectech-trust-master 1
sentinel failover-timeout isectech-trust-master 180000

# Sentinel configuration
sentinel deny-scripts-reconfig yes
sentinel resolve-hostnames yes
sentinel announce-hostnames yes

# Network configuration
bind 0.0.0.0
protected-mode no

# Logging
logfile /var/log/redis/sentinel.log
loglevel notice
syslog-enabled yes
syslog-ident sentinel

# Persistence
dir /var/lib/redis

# Security
requirepass $REDIS_PASSWORD

# Performance tuning
tcp-keepalive 300
tcp-backlog 511

# Client limits
maxclients 10000

# Script configuration
sentinel notification-script isectech-trust-master /usr/local/bin/sentinel-notify.sh
sentinel client-reconfig-script isectech-trust-master /usr/local/bin/sentinel-reconfig.sh

# Additional masters for multi-region setup
sentinel monitor isectech-trust-europe europe-redis-host 6379 1
sentinel monitor isectech-trust-asia asia-redis-host 6379 1
sentinel monitor isectech-trust-australia australia-redis-host 6379 1

EOF
    
    # Create notification script
    log_info "Creating Sentinel notification script..."
    cat > /usr/local/bin/sentinel-notify.sh << 'EOF'
#!/bin/bash
# Sentinel notification script
EVENT_TYPE="$1"
INSTANCE_NAME="$2"
EVENT_DATA="$3"

LOG_FILE="/var/log/redis/sentinel-events.log"

echo "$(date): Sentinel Event - Type: $EVENT_TYPE, Instance: $INSTANCE_NAME, Data: $EVENT_DATA" >> "$LOG_FILE"

# Send notification to monitoring system
curl -X POST \
    -H "Content-Type: application/json" \
    -d "{
        \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\",
        \"event_type\": \"$EVENT_TYPE\",
        \"instance\": \"$INSTANCE_NAME\",
        \"data\": \"$EVENT_DATA\",
        \"hostname\": \"$(hostname)\",
        \"environment\": \"$ENVIRONMENT\"
    }" \
    "https://monitoring.isectech.com/api/sentinel-events" || echo "Failed to send notification"
EOF
    
    chmod +x /usr/local/bin/sentinel-notify.sh
    
    # Create reconfiguration script
    log_info "Creating Sentinel reconfiguration script..."
    cat > /usr/local/bin/sentinel-reconfig.sh << 'EOF'
#!/bin/bash
# Sentinel client reconfiguration script
MASTER_NAME="$1"
ROLE="$2"
STATE="$3"
FROM_IP="$4"
FROM_PORT="$5"
TO_IP="$6"
TO_PORT="$7"

LOG_FILE="/var/log/redis/sentinel-reconfig.log"

echo "$(date): Master reconfiguration - Name: $MASTER_NAME, Role: $ROLE, State: $STATE, From: $FROM_IP:$FROM_PORT, To: $TO_IP:$TO_PORT" >> "$LOG_FILE"

# Update application configuration with new master
# This would typically update a configuration service or restart applications
curl -X POST \
    -H "Content-Type: application/json" \
    -d "{
        \"master_name\": \"$MASTER_NAME\",
        \"new_master_ip\": \"$TO_IP\",
        \"new_master_port\": \"$TO_PORT\",
        \"timestamp\": \"$(date -u +'%Y-%m-%dT%H:%M:%SZ')\"
    }" \
    "https://config.isectech.com/api/redis-master-update" || echo "Failed to update configuration"
EOF
    
    chmod +x /usr/local/bin/sentinel-reconfig.sh
    
    # Create Sentinel systemd service
    log_info "Creating Sentinel systemd service..."
    cat > /etc/systemd/system/redis-sentinel.service << EOF
[Unit]
Description=Advanced key-value store sentinel
After=network.target
Documentation=http://redis.io/documentation, man:redis-sentinel(1)

[Service]
Type=notify
ExecStart=/usr/bin/redis-sentinel $SENTINEL_CONFIG
TimeoutStopSec=0
Restart=always
User=redis
Group=redis
RuntimeDirectory=redis
RuntimeDirectoryMode=0755

# Security measures
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=-/var/lib/redis
ReadWritePaths=-/var/log/redis
ReadWritePaths=-/var/run/redis

# System call restrictions
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io @module

# Capabilities
CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SYS_RESOURCE
AmbientCapabilities=CAP_SETGID CAP_SETUID CAP_SYS_RESOURCE

# Resource limits
LimitNOFILE=65535
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    
    # Set correct ownership and permissions
    chown redis:redis "$SENTINEL_CONFIG"
    chmod 640 "$SENTINEL_CONFIG"
    
    # Configure Redis Sentinel for monitoring
    log_info "Configuring monitoring..."
    
    # Create monitoring configuration
    cat > /etc/google-cloud-ops-agent/config.yaml << EOF
logging:
  receivers:
    redis_sentinel_logs:
      type: files
      include_paths:
        - /var/log/redis/sentinel.log
        - /var/log/redis/sentinel-events.log
        - /var/log/redis/sentinel-reconfig.log
      record_log_file_path: true
    
  processors:
    redis_sentinel_parser:
      type: parse_json
      field: message
      
  service:
    pipelines:
      default_pipeline:
        receivers: [redis_sentinel_logs]
        processors: [redis_sentinel_parser]

metrics:
  receivers:
    redis_sentinel_metrics:
      type: redis
      endpoint: localhost:$SENTINEL_PORT
      collection_interval: 60s
      password: "$REDIS_PASSWORD"
      
  service:
    pipelines:
      default_pipeline:
        receivers: [redis_sentinel_metrics]
EOF
    
    # Enable and start services
    log_info "Starting services..."
    systemctl daemon-reload
    systemctl enable redis-sentinel
    systemctl enable google-cloud-ops-agent
    
    systemctl start google-cloud-ops-agent
    systemctl start redis-sentinel
    
    # Wait for Sentinel to start
    sleep 10
    
    # Verify Sentinel is running
    if systemctl is-active --quiet redis-sentinel; then
        log_success "Redis Sentinel started successfully"
        
        # Test Sentinel connection
        if redis-cli -p "$SENTINEL_PORT" -a "$REDIS_PASSWORD" ping | grep -q PONG; then
            log_success "Sentinel responding to ping"
        else
            log_error "Sentinel not responding to ping"
        fi
        
        # Show Sentinel info
        log_info "Sentinel master info:"
        redis-cli -p "$SENTINEL_PORT" -a "$REDIS_PASSWORD" sentinel masters || log_error "Failed to get master info"
    else
        log_error "Failed to start Redis Sentinel"
        systemctl status redis-sentinel
        exit 1
    fi
    
    # Configure firewall
    log_info "Configuring firewall..."
    ufw --force enable
    ufw allow "$SENTINEL_PORT"/tcp
    ufw allow ssh
    
    # Create health check endpoint
    log_info "Creating health check endpoint..."
    cat > /usr/local/bin/sentinel-health-check.sh << EOF
#!/bin/bash
# Health check script for Redis Sentinel

PORT=$SENTINEL_PORT
PASSWORD="$REDIS_PASSWORD"

# Check if Sentinel is listening
if ! netcat -z localhost \$PORT; then
    echo "ERROR: Sentinel not listening on port \$PORT"
    exit 1
fi

# Check if Sentinel responds to ping
if ! redis-cli -p \$PORT -a "\$PASSWORD" ping 2>/dev/null | grep -q PONG; then
    echo "ERROR: Sentinel not responding to ping"
    exit 1
fi

# Check if master is being monitored
MASTERS=\$(redis-cli -p \$PORT -a "\$PASSWORD" sentinel masters 2>/dev/null | grep -c "isectech-trust")

if [[ \$MASTERS -lt 1 ]]; then
    echo "ERROR: No masters being monitored"
    exit 1
fi

echo "OK: Sentinel healthy, monitoring \$MASTERS masters"
exit 0
EOF
    
    chmod +x /usr/local/bin/sentinel-health-check.sh
    
    # Create cron job for health monitoring
    cat > /etc/cron.d/sentinel-health << EOF
# Redis Sentinel health monitoring
*/5 * * * * redis /usr/local/bin/sentinel-health-check.sh >> /var/log/redis/health-check.log 2>&1
EOF
    
    # Final verification
    log_info "Performing final verification..."
    if /usr/local/bin/sentinel-health-check.sh; then
        log_success "Redis Sentinel setup completed successfully!"
    else
        log_error "Health check failed after setup"
        exit 1
    fi
    
    log_info "Setup logs available at: $LOG_FILE"
    log_info "Sentinel configuration: $SENTINEL_CONFIG"
    log_info "Sentinel port: $SENTINEL_PORT"
}

# Run main function
main "$@"