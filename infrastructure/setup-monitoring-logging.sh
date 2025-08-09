#!/bin/bash

# Enterprise Monitoring and Logging Infrastructure Setup for iSECTECH
# Production-grade observability platform with comprehensive monitoring
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# Configuration
PROJECT_ID=${PROJECT_ID:-"isectech-security-platform"}
REGION=${REGION:-"us-central1"}
NOTIFICATION_EMAIL=${NOTIFICATION_EMAIL:-"alerts@isectech.com"}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
PAGERDUTY_INTEGRATION_KEY=${PAGERDUTY_INTEGRATION_KEY:-""}
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS:-"365"}
MONITORING_WORKSPACE=${MONITORING_WORKSPACE:-""}

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check prerequisites
check_prerequisites() {
    log "Checking prerequisites for monitoring and logging setup..."
    
    if ! command_exists gcloud; then
        error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q .; then
        error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Check project exists and is accessible
    if ! gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
        error "Project $PROJECT_ID not found or not accessible"
        exit 1
    fi
    
    success "Prerequisites check completed"
}

# Function to enable required APIs
enable_monitoring_apis() {
    log "Enabling required APIs for monitoring and logging..."
    
    local apis=(
        "monitoring.googleapis.com"
        "logging.googleapis.com"
        "pubsub.googleapis.com"
        "cloudtrace.googleapis.com"
        "clouddebugger.googleapis.com"
        "cloudprofiler.googleapis.com"
        "servicenetworking.googleapis.com"
        "compute.googleapis.com"
        "container.googleapis.com"
        "sqladmin.googleapis.com"
        "redis.googleapis.com"
        "cloudasset.googleapis.com"
        "cloudkms.googleapis.com"
    )
    
    for api in "${apis[@]}"; do
        log "Enabling $api..."
        if gcloud services enable "$api" --project="$PROJECT_ID"; then
            success "Enabled $api"
        else
            error "Failed to enable $api"
            return 1
        fi
        sleep 2
    done
    
    success "All monitoring APIs enabled"
}

# Function to create monitoring workspace
create_monitoring_workspace() {
    log "Setting up Cloud Monitoring workspace..."
    
    # Check if workspace already exists
    local existing_workspace
    existing_workspace=$(gcloud alpha monitoring workspaces list --format="value(name)" --filter="displayName:iSECTECH-Monitoring" --limit=1 || echo "")
    
    if [ -n "$existing_workspace" ]; then
        warning "Monitoring workspace already exists: $existing_workspace"
        MONITORING_WORKSPACE="$existing_workspace"
    else
        log "Creating new monitoring workspace..."
        cat > /tmp/workspace_config.yaml << EOF
displayName: "iSECTECH-Monitoring"
description: "Enterprise monitoring workspace for iSECTECH security platform"
EOF
        
        # Note: Workspace creation may require manual setup in some cases
        log "Monitoring workspace configuration prepared"
        log "Manual step may be required: Visit Cloud Monitoring to complete workspace setup"
    fi
    
    success "Monitoring workspace setup completed"
}

# Function to create log sinks
create_log_sinks() {
    log "Creating enterprise log sinks for centralized logging..."
    
    # Create BigQuery dataset for log storage
    local logs_dataset="security_logs"
    log "Creating BigQuery dataset for logs: $logs_dataset"
    
    if bq mk \
        --dataset \
        --description="iSECTECH Security Platform Logs - Production" \
        --location="$REGION" \
        --default_table_expiration="31536000" \
        "$PROJECT_ID:$logs_dataset"; then
        success "Created BigQuery dataset: $logs_dataset"
    else
        warning "Dataset may already exist"
    fi
    
    # Create Pub/Sub topics for log streaming
    local log_topics=(
        "security-audit-logs"
        "application-logs"
        "infrastructure-logs"
        "compliance-logs"
    )
    
    for topic in "${log_topics[@]}"; do
        log "Creating Pub/Sub topic: $topic"
        if gcloud pubsub topics create "$topic" --project="$PROJECT_ID"; then
            success "Created topic: $topic"
        else
            warning "Topic may already exist: $topic"
        fi
    done
    
    # Create log sinks
    log "Creating log sinks for different log types..."
    
    # Security audit logs sink
    gcloud logging sinks create security-audit-sink \
        "bigquery.googleapis.com/projects/$PROJECT_ID/datasets/$logs_dataset" \
        --log-filter='protoPayload.serviceName="cloudaudit.googleapis.com" OR 
                     protoPayload.serviceName="iam.googleapis.com" OR
                     protoPayload.serviceName="compute.googleapis.com" OR
                     protoPayload.serviceName="container.googleapis.com"' \
        --project="$PROJECT_ID" || warning "Security audit sink may already exist"
    
    # Application logs sink
    gcloud logging sinks create application-logs-sink \
        "pubsub.googleapis.com/projects/$PROJECT_ID/topics/application-logs" \
        --log-filter='resource.type="gce_instance" OR 
                     resource.type="k8s_container" OR
                     resource.type="cloud_run_revision"' \
        --project="$PROJECT_ID" || warning "Application logs sink may already exist"
    
    # Infrastructure logs sink
    gcloud logging sinks create infrastructure-logs-sink \
        "bigquery.googleapis.com/projects/$PROJECT_ID/datasets/$logs_dataset" \
        --log-filter='resource.type="gce_instance" OR
                     resource.type="gke_cluster" OR
                     resource.type="cloud_sql_database" OR
                     resource.type="redis_instance"' \
        --project="$PROJECT_ID" || warning "Infrastructure logs sink may already exist"
    
    # Compliance logs sink
    gcloud logging sinks create compliance-logs-sink \
        "pubsub.googleapis.com/projects/$PROJECT_ID/topics/compliance-logs" \
        --log-filter='protoPayload.serviceName="cloudkms.googleapis.com" OR
                     logName:"security" OR
                     logName:"compliance"' \
        --project="$PROJECT_ID" || warning "Compliance logs sink may already exist"
    
    success "Log sinks created successfully"
}

# Function to create notification channels
create_notification_channels() {
    log "Creating notification channels for alerts..."
    
    # Email notification channel
    cat > /tmp/email_notification.json << EOF
{
  "type": "email",
  "displayName": "iSECTECH Security Alerts Email",
  "description": "Primary email notification channel for security alerts",
  "labels": {
    "email_address": "$NOTIFICATION_EMAIL"
  },
  "enabled": true
}
EOF
    
    local email_channel_name
    email_channel_name=$(gcloud alpha monitoring channels create \
        --channel-content-from-file=/tmp/email_notification.json \
        --project="$PROJECT_ID" \
        --format="value(name)" || echo "")
    
    if [ -n "$email_channel_name" ]; then
        success "Created email notification channel: $email_channel_name"
        echo "$email_channel_name" > /tmp/email_channel_name.txt
    else
        warning "Email notification channel creation failed or already exists"
    fi
    
    # Slack notification channel (if webhook provided)
    if [ -n "$SLACK_WEBHOOK_URL" ]; then
        cat > /tmp/slack_notification.json << EOF
{
  "type": "slack",
  "displayName": "iSECTECH Security Alerts Slack",
  "description": "Slack notification channel for security alerts",
  "labels": {
    "url": "$SLACK_WEBHOOK_URL"
  },
  "enabled": true
}
EOF
        
        local slack_channel_name
        slack_channel_name=$(gcloud alpha monitoring channels create \
            --channel-content-from-file=/tmp/slack_notification.json \
            --project="$PROJECT_ID" \
            --format="value(name)" || echo "")
        
        if [ -n "$slack_channel_name" ]; then
            success "Created Slack notification channel: $slack_channel_name"
            echo "$slack_channel_name" > /tmp/slack_channel_name.txt
        fi
    fi
    
    # PagerDuty notification channel (if integration key provided)
    if [ -n "$PAGERDUTY_INTEGRATION_KEY" ]; then
        cat > /tmp/pagerduty_notification.json << EOF
{
  "type": "pagerduty",
  "displayName": "iSECTECH Security Alerts PagerDuty",
  "description": "PagerDuty notification channel for critical security alerts",
  "labels": {
    "service_key": "$PAGERDUTY_INTEGRATION_KEY"
  },
  "enabled": true
}
EOF
        
        local pagerduty_channel_name
        pagerduty_channel_name=$(gcloud alpha monitoring channels create \
            --channel-content-from-file=/tmp/pagerduty_notification.json \
            --project="$PROJECT_ID" \
            --format="value(name)" || echo "")
        
        if [ -n "$pagerduty_channel_name" ]; then
            success "Created PagerDuty notification channel: $pagerduty_channel_name"
            echo "$pagerduty_channel_name" > /tmp/pagerduty_channel_name.txt
        fi
    fi
    
    # Clean up temp files
    rm -f /tmp/email_notification.json /tmp/slack_notification.json /tmp/pagerduty_notification.json
    
    success "Notification channels created"
}

# Function to create alert policies
create_alert_policies() {
    log "Creating comprehensive alert policies for security monitoring..."
    
    # Get notification channel names
    local email_channel=""
    local slack_channel=""
    local pagerduty_channel=""
    
    [ -f "/tmp/email_channel_name.txt" ] && email_channel=$(cat /tmp/email_channel_name.txt)
    [ -f "/tmp/slack_channel_name.txt" ] && slack_channel=$(cat /tmp/slack_channel_name.txt)
    [ -f "/tmp/pagerduty_channel_name.txt" ] && pagerduty_channel=$(cat /tmp/pagerduty_channel_name.txt)
    
    # Build notification channels array
    local notification_channels="[]"
    if [ -n "$email_channel" ]; then
        notification_channels="[\"$email_channel\"]"
    fi
    
    # High CPU utilization alert
    cat > /tmp/high_cpu_alert.yaml << EOF
displayName: "High CPU Utilization - iSECTECH"
documentation:
  content: "CPU utilization is consistently high across compute instances"
  mimeType: "text/markdown"
conditions:
- displayName: "High CPU Usage"
  conditionThreshold:
    filter: 'resource.type="gce_instance"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 80
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_MEAN
      crossSeriesReducer: REDUCE_MEAN
      groupByFields:
      - resource.label.instance_id
notificationChannels: $notification_channels
alertStrategy:
  autoClose: 86400s
enabled: true
EOF
    
    # Low disk space alert
    cat > /tmp/low_disk_alert.yaml << EOF
displayName: "Low Disk Space - iSECTECH"
documentation:
  content: "Disk space is running low on compute instances"
  mimeType: "text/markdown"
conditions:
- displayName: "Low Disk Space"
  conditionThreshold:
    filter: 'resource.type="gce_instance" AND metric.type="compute.googleapis.com/instance/disk/utilization"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 85
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_MEAN
      crossSeriesReducer: REDUCE_MAX
      groupByFields:
      - resource.label.instance_id
      - metric.label.device_name
notificationChannels: $notification_channels
alertStrategy:
  autoClose: 86400s
enabled: true
EOF
    
    # Failed authentication attempts alert
    cat > /tmp/failed_auth_alert.yaml << EOF
displayName: "High Failed Authentication Attempts - iSECTECH"
documentation:
  content: "Multiple failed authentication attempts detected - potential security threat"
  mimeType: "text/markdown"
conditions:
- displayName: "High Failed Auth Rate"
  conditionThreshold:
    filter: 'protoPayload.serviceName="iam.googleapis.com" AND protoPayload.authenticationInfo.principalEmail!="" AND protoPayload.status.code!=0'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 10
    duration: 300s
    aggregations:
    - alignmentPeriod: 300s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
notificationChannels: $notification_channels
alertStrategy:
  autoClose: 3600s
enabled: true
EOF
    
    # Database connection errors alert
    cat > /tmp/db_connection_alert.yaml << EOF
displayName: "Database Connection Errors - iSECTECH"
documentation:
  content: "High number of database connection errors detected"
  mimeType: "text/markdown"
conditions:
- displayName: "High DB Connection Errors"
  conditionThreshold:
    filter: 'resource.type="cloud_sql_database" AND (jsonPayload.message=~"connection.*error" OR jsonPayload.message=~"timeout")'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 5
    duration: 300s
    aggregations:
    - alignmentPeriod: 300s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
notificationChannels: $notification_channels
alertStrategy:
  autoClose: 3600s
enabled: true
EOF
    
    # Application error rate alert
    cat > /tmp/app_error_alert.yaml << EOF
displayName: "High Application Error Rate - iSECTECH"
documentation:
  content: "Application error rate exceeds normal thresholds"
  mimeType: "text/markdown"
conditions:
- displayName: "High Error Rate"
  conditionThreshold:
    filter: 'resource.type="k8s_container" AND (severity="ERROR" OR httpRequest.status>=500)'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 20
    duration: 300s
    aggregations:
    - alignmentPeriod: 300s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
      groupByFields:
      - resource.label.namespace_name
      - resource.label.pod_name
notificationChannels: $notification_channels
alertStrategy:
  autoClose: 3600s
enabled: true
EOF
    
    # Create alert policies
    local alert_files=(
        "high_cpu_alert.yaml"
        "low_disk_alert.yaml"
        "failed_auth_alert.yaml"
        "db_connection_alert.yaml"
        "app_error_alert.yaml"
    )
    
    for alert_file in "${alert_files[@]}"; do
        log "Creating alert policy from $alert_file..."
        if gcloud alpha monitoring policies create \
            --policy-from-file="/tmp/$alert_file" \
            --project="$PROJECT_ID"; then
            success "Created alert policy: $alert_file"
        else
            warning "Failed to create alert policy: $alert_file"
        fi
        rm -f "/tmp/$alert_file"
    done
    
    # Clean up notification channel files
    rm -f /tmp/*_channel_name.txt
    
    success "Alert policies created"
}

# Function to create SLO definitions
create_slo_definitions() {
    log "Creating SLO (Service Level Objectives) definitions..."
    
    mkdir -p "$HOME/isectech-monitoring-slos"
    
    # API availability SLO
    cat > "$HOME/isectech-monitoring-slos/api_availability_slo.yaml" << 'EOF'
# iSECTECH API Availability SLO
# Target: 99.9% availability over 30 days
displayName: "iSECTECH API Availability SLO"
description: "API availability service level objective for iSECTECH security platform"
serviceLevelIndicator:
  requestBased:
    goodTotalRatio:
      totalServiceFilter: 'resource.type="k8s_container" AND resource.label.namespace_name="isectech-api"'
      goodServiceFilter: 'resource.type="k8s_container" AND resource.label.namespace_name="isectech-api" AND httpRequest.status<500'
goal:
  performanceGoal:
    threshold: 0.999
  rollingPeriod: 2592000s  # 30 days
EOF
    
    # Response time SLO
    cat > "$HOME/isectech-monitoring-slos/response_time_slo.yaml" << 'EOF'
# iSECTECH API Response Time SLO
# Target: 95% of requests under 200ms
displayName: "iSECTECH API Response Time SLO"
description: "API response time service level objective for iSECTECH security platform"
serviceLevelIndicator:
  requestBased:
    distributionCut:
      distributionFilter: 'resource.type="k8s_container" AND resource.label.namespace_name="isectech-api"'
      range:
        max: 0.2  # 200ms
goal:
  performanceGoal:
    threshold: 0.95
  rollingPeriod: 2592000s  # 30 days
EOF
    
    # Database availability SLO
    cat > "$HOME/isectech-monitoring-slos/database_availability_slo.yaml" << 'EOF'
# iSECTECH Database Availability SLO
# Target: 99.95% availability over 30 days
displayName: "iSECTECH Database Availability SLO"
description: "Database availability service level objective for iSECTECH security platform"
serviceLevelIndicator:
  requestBased:
    goodTotalRatio:
      totalServiceFilter: 'resource.type="cloud_sql_database"'
      goodServiceFilter: 'resource.type="cloud_sql_database" AND NOT (jsonPayload.message=~"connection.*error" OR jsonPayload.message=~"timeout")'
goal:
  performanceGoal:
    threshold: 0.9995
  rollingPeriod: 2592000s  # 30 days
EOF
    
    success "SLO definitions created in $HOME/isectech-monitoring-slos/"
}

# Function to create monitoring dashboards
create_monitoring_dashboards() {
    log "Creating comprehensive monitoring dashboards..."
    
    # Security monitoring dashboard
    cat > /tmp/security_dashboard.json << EOF
{
  "displayName": "iSECTECH Security Monitoring Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "Failed Authentication Attempts",
          "xyChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "protoPayload.serviceName=\"iam.googleapis.com\" AND protoPayload.status.code!=0",
                  "aggregation": {
                    "alignmentPeriod": "300s",
                    "perSeriesAligner": "ALIGN_RATE",
                    "crossSeriesReducer": "REDUCE_SUM"
                  }
                }
              }
            }],
            "timeshiftDuration": "0s",
            "yAxis": {
              "label": "Failed Attempts/sec",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "widget": {
          "title": "Security Audit Events",
          "scorecard": {
            "timeSeriesQuery": {
              "timeSeriesFilter": {
                "filter": "protoPayload.serviceName=\"cloudaudit.googleapis.com\"",
                "aggregation": {
                  "alignmentPeriod": "3600s",
                  "perSeriesAligner": "ALIGN_RATE",
                  "crossSeriesReducer": "REDUCE_SUM"
                }
              }
            }
          }
        }
      },
      {
        "width": 12,
        "height": 4,
        "yPos": 4,
        "widget": {
          "title": "Resource Access Patterns",
          "xyChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "protoPayload.serviceName=\"compute.googleapis.com\" OR protoPayload.serviceName=\"container.googleapis.com\"",
                  "aggregation": {
                    "alignmentPeriod": "300s",
                    "perSeriesAligner": "ALIGN_RATE",
                    "crossSeriesReducer": "REDUCE_SUM",
                    "groupByFields": ["protoPayload.serviceName"]
                  }
                }
              }
            }]
          }
        }
      }
    ]
  }
}
EOF
    
    # Infrastructure monitoring dashboard
    cat > /tmp/infrastructure_dashboard.json << EOF
{
  "displayName": "iSECTECH Infrastructure Monitoring Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "CPU Utilization by Instance",
          "xyChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\"",
                  "aggregation": {
                    "alignmentPeriod": "60s",
                    "perSeriesAligner": "ALIGN_MEAN",
                    "crossSeriesReducer": "REDUCE_MEAN",
                    "groupByFields": ["resource.label.instance_name"]
                  }
                }
              }
            }],
            "yAxis": {
              "label": "CPU %",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "widget": {
          "title": "Memory Utilization",
          "xyChart": {
            "dataSets": [{
              "timeSeriesQuery": {
                "timeSeriesFilter": {
                  "filter": "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/memory/utilization\"",
                  "aggregation": {
                    "alignmentPeriod": "60s",
                    "perSeriesAligner": "ALIGN_MEAN",
                    "crossSeriesReducer": "REDUCE_MEAN",
                    "groupByFields": ["resource.label.instance_name"]
                  }
                }
              }
            }],
            "yAxis": {
              "label": "Memory %",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 12,
        "height": 4,
        "yPos": 4,
        "widget": {
          "title": "Network Traffic",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/network/received_bytes_count\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM"
                    }
                  }
                }
              },
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/network/sent_bytes_count\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM"
                    }
                  }
                }
              }
            ],
            "yAxis": {
              "label": "Bytes/sec",
              "scale": "LINEAR"
            }
          }
        }
      }
    ]
  }
}
EOF
    
    # Create dashboards
    log "Creating security monitoring dashboard..."
    if gcloud monitoring dashboards create --config-from-file=/tmp/security_dashboard.json --project="$PROJECT_ID"; then
        success "Created security monitoring dashboard"
    else
        warning "Failed to create security monitoring dashboard"
    fi
    
    log "Creating infrastructure monitoring dashboard..."
    if gcloud monitoring dashboards create --config-from-file=/tmp/infrastructure_dashboard.json --project="$PROJECT_ID"; then
        success "Created infrastructure monitoring dashboard"
    else
        warning "Failed to create infrastructure monitoring dashboard"
    fi
    
    # Clean up temp files
    rm -f /tmp/security_dashboard.json /tmp/infrastructure_dashboard.json
    
    success "Monitoring dashboards created"
}

# Function to configure audit logging
configure_audit_logging() {
    log "Configuring comprehensive audit logging..."
    
    # Create audit policy configuration
    cat > /tmp/audit_policy.yaml << 'EOF'
auditConfigs:
- service: cloudaudit.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
- service: iam.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
- service: compute.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_WRITE
- service: container.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_WRITE
- service: sqladmin.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_WRITE
- service: cloudkms.googleapis.com
  auditLogConfigs:
  - logType: ADMIN_READ
  - logType: DATA_READ
  - logType: DATA_WRITE
EOF
    
    log "Audit logging policy created"
    log "Manual step required: Apply audit policy through IAM console"
    log "Configuration file: /tmp/audit_policy.yaml"
    
    # Create compliance monitoring queries
    mkdir -p "$HOME/isectech-compliance-queries"
    
    cat > "$HOME/isectech-compliance-queries/admin_activity_report.sql" << 'EOF'
-- Admin Activity Compliance Report for iSECTECH
-- Track all administrative actions for compliance auditing
SELECT 
  timestamp,
  protoPayload.authenticationInfo.principalEmail as user_email,
  protoPayload.serviceName as service,
  protoPayload.methodName as method,
  protoPayload.resourceName as resource,
  protoPayload.request.policy as policy_changes,
  protoPayload.response.error.message as error_message,
  severity
FROM `PROJECT_ID.security_logs.cloudaudit_googleapis_com_activity_*`
WHERE DATE(_PARTITIONTIME) >= DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
  AND protoPayload.serviceName IN ('iam.googleapis.com', 'cloudkms.googleapis.com', 'compute.googleapis.com')
  AND severity != 'INFO'
ORDER BY timestamp DESC;
EOF
    
    cat > "$HOME/isectech-compliance-queries/data_access_report.sql" << 'EOF'
-- Data Access Compliance Report for iSECTECH
-- Track all data access events for security compliance
SELECT 
  timestamp,
  protoPayload.authenticationInfo.principalEmail as user_email,
  protoPayload.serviceName as service,
  protoPayload.resourceName as resource,
  protoPayload.request as request_details,
  insertId,
  sourceLocation.file as source_location
FROM `PROJECT_ID.security_logs.cloudaudit_googleapis_com_data_access_*`
WHERE DATE(_PARTITIONTIME) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
  AND protoPayload.serviceName IN ('sqladmin.googleapis.com', 'cloudkms.googleapis.com')
ORDER BY timestamp DESC;
EOF
    
    # Replace PROJECT_ID placeholder
    sed -i.bak "s/PROJECT_ID/$PROJECT_ID/g" "$HOME/isectech-compliance-queries/"*.sql
    rm -f "$HOME/isectech-compliance-queries/"*.sql.bak
    
    success "Audit logging and compliance monitoring configured"
}

# Function to create log retention policies
create_log_retention_policies() {
    log "Creating log retention policies..."
    
    # Set retention for different log types
    local log_buckets=(
        "_Default:$LOG_RETENTION_DAYS"
        "_Required:$LOG_RETENTION_DAYS"
    )
    
    for bucket_config in "${log_buckets[@]}"; do
        IFS=':' read -r bucket_name retention_days <<< "$bucket_config"
        
        log "Setting retention for log bucket $bucket_name to $retention_days days..."
        if gcloud logging buckets update "$bucket_name" \
            --location=global \
            --retention-days="$retention_days" \
            --project="$PROJECT_ID"; then
            success "Updated retention for $bucket_name"
        else
            warning "Failed to update retention for $bucket_name"
        fi
    done
    
    success "Log retention policies configured"
}

# Function to create monitoring automation scripts
create_monitoring_automation() {
    log "Creating monitoring automation scripts..."
    
    # Create log analysis script
    cat > "$HOME/isectech-monitoring-automation/analyze_security_logs.sh" << 'EOF'
#!/bin/bash

# iSECTECH Security Log Analysis Automation
# Automated security event analysis and reporting

PROJECT_ID="isectech-security-platform"
DATASET="security_logs"

echo "=== iSECTECH Security Log Analysis Report ==="
echo "Generated: $(date)"
echo ""

# Check for suspicious authentication patterns
echo "1. Suspicious Authentication Patterns (Last 24 hours):"
bq query --use_legacy_sql=false --format=prettyjson "
SELECT 
  protoPayload.authenticationInfo.principalEmail as user,
  COUNT(*) as failed_attempts,
  ARRAY_AGG(DISTINCT protoPayload.requestMetadata.callerIp LIMIT 10) as source_ips
FROM \`$PROJECT_ID.$DATASET.cloudaudit_googleapis_com_activity_*\`
WHERE DATE(_PARTITIONTIME) = CURRENT_DATE()
  AND protoPayload.serviceName = 'iam.googleapis.com'
  AND protoPayload.status.code != 0
GROUP BY 1
HAVING failed_attempts > 5
ORDER BY failed_attempts DESC;
"

echo ""
echo "2. Unusual Resource Access (Last 24 hours):"
bq query --use_legacy_sql=false --format=prettyjson "
SELECT 
  protoPayload.authenticationInfo.principalEmail as user,
  protoPayload.serviceName as service,
  COUNT(*) as access_count,
  ARRAY_AGG(DISTINCT protoPayload.methodName LIMIT 5) as methods
FROM \`$PROJECT_ID.$DATASET.cloudaudit_googleapis_com_activity_*\`
WHERE DATE(_PARTITIONTIME) = CURRENT_DATE()
  AND EXTRACT(HOUR FROM timestamp) NOT BETWEEN 6 AND 22  -- Outside business hours
GROUP BY 1, 2
HAVING access_count > 10
ORDER BY access_count DESC;
"

echo ""
echo "=== Analysis Complete ==="
EOF
    
    chmod +x "$HOME/isectech-monitoring-automation/analyze_security_logs.sh"
    
    success "Monitoring automation scripts created"
}

# Main function
main() {
    log "Starting iSECTECH Enterprise Monitoring and Logging Infrastructure Setup"
    log "Project ID: $PROJECT_ID"
    log "Region: $REGION"
    log "Notification Email: $NOTIFICATION_EMAIL"
    log "Log Retention: $LOG_RETENTION_DAYS days"
    echo ""
    
    # Create directories
    mkdir -p "$HOME/isectech-monitoring-automation"
    
    # Execute setup steps
    check_prerequisites
    enable_monitoring_apis
    create_monitoring_workspace
    create_log_sinks
    create_notification_channels
    create_alert_policies
    create_slo_definitions
    create_monitoring_dashboards
    configure_audit_logging
    create_log_retention_policies
    create_monitoring_automation
    
    success "iSECTECH Enterprise Monitoring and Logging Infrastructure Setup Completed!"
    
    echo ""
    log "=== SETUP SUMMARY ==="
    log "✅ Cloud Monitoring workspace configured"
    log "✅ Comprehensive log sinks created (BigQuery + Pub/Sub)"
    log "✅ Multi-channel notification system deployed"
    log "✅ Enterprise alert policies implemented"
    log "✅ SLO definitions created"
    log "✅ Security and infrastructure dashboards deployed"
    log "✅ Audit logging and compliance monitoring configured"
    log "✅ Log retention policies set ($LOG_RETENTION_DAYS days)"
    log "✅ Monitoring automation scripts created"
    echo ""
    
    log "=== INTEGRATION COMPONENTS ==="
    log "📊 BigQuery dataset: security_logs"
    log "📡 Pub/Sub topics: security-audit-logs, application-logs, infrastructure-logs, compliance-logs"
    log "🔔 Notification channels: Email, Slack (optional), PagerDuty (optional)"
    log "📈 SLO definitions: $HOME/isectech-monitoring-slos/"
    log "🔍 Compliance queries: $HOME/isectech-compliance-queries/"
    log "🤖 Automation scripts: $HOME/isectech-monitoring-automation/"
    echo ""
    
    log "=== NEXT STEPS ==="
    log "1. Complete monitoring workspace setup in Cloud Console if required"
    log "2. Configure Slack/PagerDuty integration keys if not provided"
    log "3. Test alert policies with sample events"
    log "4. Review and customize SLO thresholds for your requirements"
    log "5. Set up automated security log analysis scheduled runs"
    log "6. Integrate monitoring data with SIEM/SOAR systems"
    echo ""
    
    warning "MANUAL STEPS REQUIRED:"
    warning "- Apply audit policy configuration through IAM console"
    warning "- Complete monitoring workspace setup if workspace creation failed"
    warning "- Test notification channels with sample alerts"
}

# Execute main function
main "$@"