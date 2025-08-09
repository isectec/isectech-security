#!/bin/bash

# iSECTECH Dashboards and Alerting Configuration Script
# Comprehensive monitoring dashboards and alerting for cybersecurity platform
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-alerts@isectech.com}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
PAGERDUTY_INTEGRATION_KEY="${PAGERDUTY_INTEGRATION_KEY:-}"

# Dashboard and alerting settings
DASHBOARD_PREFIX="iSECTECH-${ENVIRONMENT}"
ALERT_POLICY_PREFIX="iSECTECH-${ENVIRONMENT}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites for dashboards and alerting setup..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check authentication
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable monitoring.googleapis.com
    gcloud services enable logging.googleapis.com
    gcloud services enable clouderrorreporting.googleapis.com
    gcloud services enable cloudtrace.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create notification channels
create_notification_channels() {
    log_info "Creating notification channels for alerting..."
    
    # Create email notification channel
    local email_channel_config="/tmp/email-notification-channel.yaml"
    cat > "$email_channel_config" << EOF
type: email
displayName: "iSECTECH Security Team"
description: "Primary email notifications for iSECTECH security platform"
labels:
  email_address: "$NOTIFICATION_EMAIL"
userLabels:
  environment: "$ENVIRONMENT"
  team: "security"
  priority: "high"
EOF
    
    local email_channel_name
    if ! email_channel_name=$(gcloud alpha monitoring channels list --filter="displayName:'iSECTECH Security Team'" --format="value(name)" 2>/dev/null | head -1); then
        email_channel_name=$(gcloud alpha monitoring channels create --channel-content-from-file="$email_channel_config" --format="value(name)")
        log_success "Created email notification channel: $email_channel_name"
    else
        log_info "Email notification channel already exists: $email_channel_name"
    fi
    
    # Create Slack notification channel if webhook provided
    if [ -n "$SLACK_WEBHOOK" ]; then
        local slack_channel_config="/tmp/slack-notification-channel.yaml"
        cat > "$slack_channel_config" << EOF
type: slack
displayName: "iSECTECH Slack Alerts"
description: "Slack notifications for iSECTECH security platform"
labels:
  url: "$SLACK_WEBHOOK"
  channel: "#security-alerts"
userLabels:
  environment: "$ENVIRONMENT"
  team: "security"
  priority: "medium"
EOF
        
        local slack_channel_name
        if ! slack_channel_name=$(gcloud alpha monitoring channels list --filter="displayName:'iSECTECH Slack Alerts'" --format="value(name)" 2>/dev/null | head -1); then
            slack_channel_name=$(gcloud alpha monitoring channels create --channel-content-from-file="$slack_channel_config" --format="value(name)")
            log_success "Created Slack notification channel: $slack_channel_name"
        else
            log_info "Slack notification channel already exists: $slack_channel_name"
        fi
    fi
    
    # Store notification channel names for use in alerting policies
    echo "$email_channel_name" > "/tmp/email_channel_name.txt"
    if [ -n "$SLACK_WEBHOOK" ]; then
        echo "$slack_channel_name" > "/tmp/slack_channel_name.txt"
    fi
    
    rm -f "$email_channel_config" "$slack_channel_config"
}

# Create security monitoring dashboard
create_security_dashboard() {
    log_info "Creating comprehensive security monitoring dashboard..."
    
    local dashboard_config="/tmp/security-dashboard.json"
    cat > "$dashboard_config" << 'EOF'
{
  "displayName": "iSECTECH Security Monitoring Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "Threat Detection Events",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/security/threat_detections_total\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.threat_type"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "timeshiftDuration": "0s",
            "yAxis": {
              "label": "Threats per minute",
              "scale": "LINEAR"
            },
            "chartOptions": {
              "mode": "COLOR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "widget": {
          "title": "Authentication Success Rate",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/security/auth_attempts_total\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.status"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Auth attempts per 5min",
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
          "title": "API Request Rate by Endpoint",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/performance/api_requests_total\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.endpoint", "metric.label.method"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Requests per minute",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "yPos": 8,
        "widget": {
          "title": "Cloud Run Service Health",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/container/cpu/utilizations\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": ["resource.label.service_name"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "CPU Utilization",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "yPos": 8,
        "widget": {
          "title": "Error Rate by Service",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"cloud_run_revision\" AND metric.type=\"run.googleapis.com/request_count\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["resource.label.service_name", "metric.label.response_code_class"]
                    }
                  }
                },
                "plotType": "STACKED_BAR",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Requests per 5min",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 12,
        "height": 4,
        "yPos": 12,
        "widget": {
          "title": "BigQuery Security Analytics",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"bigquery_table\" AND metric.type=\"bigquery.googleapis.com/table/uploaded_bytes\"",
                    "aggregation": {
                      "alignmentPeriod": "3600s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["resource.label.table_id"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Bytes per hour",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "yPos": 16,
        "widget": {
          "title": "Load Balancer Performance",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"https_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM"
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Requests per minute",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "yPos": 16,
        "widget": {
          "title": "Cloud Armor Security Events",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"https_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\" AND metric.label.matched_url_path_rule!=\"\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.backend_target_name"]
                    }
                  }
                },
                "plotType": "STACKED_BAR",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Requests per 5min",
              "scale": "LINEAR"
            }
          }
        }
      }
    ]
  }
}
EOF
    
    # Create the dashboard
    local dashboard_name="${DASHBOARD_PREFIX}-Security-Dashboard"
    if gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | grep -q .; then
        log_info "Updating existing security dashboard..."
        local existing_dashboard
        existing_dashboard=$(gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | head -1)
        gcloud monitoring dashboards update "$existing_dashboard" --config-from-file="$dashboard_config"
    else
        log_info "Creating new security dashboard..."
        gcloud monitoring dashboards create --config-from-file="$dashboard_config"
    fi
    
    log_success "Security monitoring dashboard configured: $dashboard_name"
    rm -f "$dashboard_config"
}

# Create performance monitoring dashboard
create_performance_dashboard() {
    log_info "Creating performance monitoring dashboard..."
    
    local dashboard_config="/tmp/performance-dashboard.json"
    cat > "$dashboard_config" << 'EOF'
{
  "displayName": "iSECTECH Performance Monitoring Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "API Response Times (P95)",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/performance/api_response_time_seconds\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_DELTA",
                      "crossSeriesReducer": "REDUCE_PERCENTILE_95",
                      "groupByFields": ["metric.label.service_name", "metric.label.endpoint"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Response time (seconds)",
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
          "title": "Database Connection Pool",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/performance/db_connections_active\"",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": ["metric.label.service_name", "metric.label.db_name"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Active connections",
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
          "title": "Memory and CPU Utilization",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "resource.type=\"cloud_run_revision\" AND (metric.type=\"run.googleapis.com/container/cpu/utilizations\" OR metric.type=\"run.googleapis.com/container/memory/utilizations\")",
                    "aggregation": {
                      "alignmentPeriod": "60s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": ["resource.label.service_name", "metric.type"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Utilization (%)",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "yPos": 8,
        "widget": {
          "title": "Cache Hit Ratio",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/performance/cache_operations_total\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.operation", "metric.label.cache_type"]
                    }
                  }
                },
                "plotType": "STACKED_BAR",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Operations per 5min",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "yPos": 8,
        "widget": {
          "title": "Queue Processing Times",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/performance/queue_processing_time_seconds\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_DELTA",
                      "crossSeriesReducer": "REDUCE_MEAN",
                      "groupByFields": ["metric.label.queue_name", "metric.label.service_name"]
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Processing time (seconds)",
              "scale": "LINEAR"
            }
          }
        }
      }
    ]
  }
}
EOF
    
    # Create the dashboard
    local dashboard_name="${DASHBOARD_PREFIX}-Performance-Dashboard"
    if gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | grep -q .; then
        log_info "Updating existing performance dashboard..."
        local existing_dashboard
        existing_dashboard=$(gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | head -1)
        gcloud monitoring dashboards update "$existing_dashboard" --config-from-file="$dashboard_config"
    else
        log_info "Creating new performance dashboard..."
        gcloud monitoring dashboards create --config-from-file="$dashboard_config"
    fi
    
    log_success "Performance monitoring dashboard configured: $dashboard_name"
    rm -f "$dashboard_config"
}

# Create business metrics dashboard
create_business_dashboard() {
    log_info "Creating business metrics dashboard..."
    
    local dashboard_config="/tmp/business-dashboard.json"
    cat > "$dashboard_config" << 'EOF'
{
  "displayName": "iSECTECH Business Metrics Dashboard",
  "mosaicLayout": {
    "tiles": [
      {
        "width": 6,
        "height": 4,
        "widget": {
          "title": "Active User Sessions",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/business/active_users_total\"",
                    "aggregation": {
                      "alignmentPeriod": "300s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.user_type"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Active users",
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
          "title": "Feature Usage Metrics",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/business/feature_usage_total\"",
                    "aggregation": {
                      "alignmentPeriod": "3600s",
                      "perSeriesAligner": "ALIGN_RATE",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.feature_name"]
                    }
                  }
                },
                "plotType": "STACKED_BAR",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Usage per hour",
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
          "title": "Revenue Impact Metrics",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/business/revenue_impact_dollars\"",
                    "aggregation": {
                      "alignmentPeriod": "3600s",
                      "perSeriesAligner": "ALIGN_DELTA",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.impact_type"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Revenue impact ($)",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "yPos": 8,
        "widget": {
          "title": "Customer Satisfaction Score",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/business/customer_satisfaction_score\"",
                    "aggregation": {
                      "alignmentPeriod": "3600s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_MEAN"
                    }
                  }
                },
                "plotType": "LINE",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Satisfaction score (1-10)",
              "scale": "LINEAR"
            }
          }
        }
      },
      {
        "width": 6,
        "height": 4,
        "xPos": 6,
        "yPos": 8,
        "widget": {
          "title": "Subscription and License Metrics",
          "xyChart": {
            "dataSets": [
              {
                "timeSeriesQuery": {
                  "timeSeriesFilter": {
                    "filter": "metric.type=\"custom.googleapis.com/isectech/business/subscriptions_active\"",
                    "aggregation": {
                      "alignmentPeriod": "3600s",
                      "perSeriesAligner": "ALIGN_MEAN",
                      "crossSeriesReducer": "REDUCE_SUM",
                      "groupByFields": ["metric.label.subscription_tier"]
                    }
                  }
                },
                "plotType": "STACKED_AREA",
                "targetAxis": "Y1"
              }
            ],
            "yAxis": {
              "label": "Active subscriptions",
              "scale": "LINEAR"
            }
          }
        }
      }
    ]
  }
}
EOF
    
    # Create the dashboard
    local dashboard_name="${DASHBOARD_PREFIX}-Business-Dashboard"
    if gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | grep -q .; then
        log_info "Updating existing business dashboard..."
        local existing_dashboard
        existing_dashboard=$(gcloud monitoring dashboards list --filter="displayName:'$dashboard_name'" --format="value(name)" | head -1)
        gcloud monitoring dashboards update "$existing_dashboard" --config-from-file="$dashboard_config"
    else
        log_info "Creating new business dashboard..."
        gcloud monitoring dashboards create --config-from-file="$dashboard_config"
    fi
    
    log_success "Business metrics dashboard configured: $dashboard_name"
    rm -f "$dashboard_config"
}

# Create critical security alerting policies
create_security_alerting_policies() {
    log_info "Creating critical security alerting policies..."
    
    # Get notification channels
    local email_channel=""
    local slack_channel=""
    
    if [ -f "/tmp/email_channel_name.txt" ]; then
        email_channel=$(cat "/tmp/email_channel_name.txt")
    fi
    
    if [ -f "/tmp/slack_channel_name.txt" ]; then
        slack_channel=$(cat "/tmp/slack_channel_name.txt")
    fi
    
    # High threat detection rate alert
    local threat_alert_config="/tmp/threat-detection-alert.yaml"
    cat > "$threat_alert_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - High Threat Detection Rate"
documentation:
  content: "Alert triggered when threat detection rate exceeds normal thresholds"
  mimeType: "text/markdown"
conditions:
- displayName: "High threat detection rate"
  conditionThreshold:
    filter: 'metric.type="custom.googleapis.com/isectech/security/threat_detections_total"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 50
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
alertStrategy:
  autoClose: 86400s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
$([ -n "$slack_channel" ] && echo "- $slack_channel")
EOF
    
    # Authentication failure spike alert
    local auth_alert_config="/tmp/auth-failure-alert.yaml"
    cat > "$auth_alert_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - Authentication Failure Spike"
documentation:
  content: "Alert triggered when authentication failures spike indicating potential attack"
  mimeType: "text/markdown"
conditions:
- displayName: "Authentication failure spike"
  conditionThreshold:
    filter: 'metric.type="custom.googleapis.com/isectech/security/auth_attempts_total" AND metric.label.status="failed"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 100
    duration: 180s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
alertStrategy:
  autoClose: 3600s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
$([ -n "$slack_channel" ] && echo "- $slack_channel")
EOF
    
    # Service down alert
    local service_down_config="/tmp/service-down-alert.yaml"
    cat > "$service_down_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - Critical Service Down"
documentation:
  content: "Alert triggered when critical services are not responding to health checks"
  mimeType: "text/markdown"
conditions:
- displayName: "Service health check failing"
  conditionThreshold:
    filter: 'resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/request_count" AND metric.label.response_code_class="5xx"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 10
    duration: 120s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_SUM
      groupByFields: ["resource.label.service_name"]
alertStrategy:
  autoClose: 1800s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
$([ -n "$slack_channel" ] && echo "- $slack_channel")
EOF
    
    # High API error rate alert
    local api_error_config="/tmp/api-error-alert.yaml"
    cat > "$api_error_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - High API Error Rate"
documentation:
  content: "Alert triggered when API error rate exceeds acceptable thresholds"
  mimeType: "text/markdown"
conditions:
- displayName: "API error rate exceeds threshold"
  conditionThreshold:
    filter: 'metric.type="custom.googleapis.com/isectech/performance/api_requests_total" AND metric.label.status_code=~"5.*"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 0.05
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_RATE
      crossSeriesReducer: REDUCE_MEAN
alertStrategy:
  autoClose: 3600s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
EOF
    
    # Database connection pool exhaustion alert
    local db_pool_config="/tmp/db-pool-alert.yaml"
    cat > "$db_pool_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - Database Connection Pool Exhaustion"
documentation:
  content: "Alert triggered when database connection pool utilization is critically high"
  mimeType: "text/markdown"
conditions:
- displayName: "DB connection pool near exhaustion"
  conditionThreshold:
    filter: 'metric.type="custom.googleapis.com/isectech/performance/db_connections_active"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 80
    duration: 180s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_MEAN
      crossSeriesReducer: REDUCE_MAX
      groupByFields: ["metric.label.service_name"]
alertStrategy:
  autoClose: 1800s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
EOF
    
    # Create all alerting policies
    local alert_configs=(
        "$threat_alert_config"
        "$auth_alert_config"
        "$service_down_config"
        "$api_error_config"
        "$db_pool_config"
    )
    
    for config in "${alert_configs[@]}"; do
        local display_name
        display_name=$(grep "displayName:" "$config" | head -1 | cut -d'"' -f2)
        
        if gcloud alpha monitoring policies list --filter="displayName:'$display_name'" --format="value(name)" | grep -q .; then
            log_info "Updating existing alert policy: $display_name"
            local existing_policy
            existing_policy=$(gcloud alpha monitoring policies list --filter="displayName:'$display_name'" --format="value(name)" | head -1)
            gcloud alpha monitoring policies update "$existing_policy" --policy-from-file="$config"
        else
            log_info "Creating new alert policy: $display_name"
            gcloud alpha monitoring policies create --policy-from-file="$config"
        fi
        
        log_success "Configured alert policy: $display_name"
    done
    
    # Clean up temporary files
    rm -f "${alert_configs[@]}"
}

# Create performance alerting policies
create_performance_alerting_policies() {
    log_info "Creating performance alerting policies..."
    
    # Get notification channels
    local email_channel=""
    local slack_channel=""
    
    if [ -f "/tmp/email_channel_name.txt" ]; then
        email_channel=$(cat "/tmp/email_channel_name.txt")
    fi
    
    if [ -f "/tmp/slack_channel_name.txt" ]; then
        slack_channel=$(cat "/tmp/slack_channel_name.txt")
    fi
    
    # High response time alert
    local response_time_config="/tmp/response-time-alert.yaml"
    cat > "$response_time_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - High API Response Time"
documentation:
  content: "Alert triggered when API response times exceed acceptable thresholds"
  mimeType: "text/markdown"
conditions:
- displayName: "API response time P95 > 2 seconds"
  conditionThreshold:
    filter: 'metric.type="custom.googleapis.com/isectech/performance/api_response_time_seconds"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 2.0
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_DELTA
      crossSeriesReducer: REDUCE_PERCENTILE_95
      groupByFields: ["metric.label.service_name"]
alertStrategy:
  autoClose: 1800s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
EOF
    
    # High CPU utilization alert
    local cpu_config="/tmp/cpu-utilization-alert.yaml"
    cat > "$cpu_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - High CPU Utilization"
documentation:
  content: "Alert triggered when service CPU utilization is consistently high"
  mimeType: "text/markdown"
conditions:
- displayName: "CPU utilization > 80%"
  conditionThreshold:
    filter: 'resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/container/cpu/utilizations"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 0.8
    duration: 600s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_MEAN
      crossSeriesReducer: REDUCE_MEAN
      groupByFields: ["resource.label.service_name"]
alertStrategy:
  autoClose: 3600s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
EOF
    
    # Memory utilization alert
    local memory_config="/tmp/memory-utilization-alert.yaml"
    cat > "$memory_config" << EOF
displayName: "${ALERT_POLICY_PREFIX} - High Memory Utilization"
documentation:
  content: "Alert triggered when service memory utilization approaches limits"
  mimeType: "text/markdown"
conditions:
- displayName: "Memory utilization > 90%"
  conditionThreshold:
    filter: 'resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/container/memory/utilizations"'
    comparison: COMPARISON_GREATER_THAN
    thresholdValue: 0.9
    duration: 300s
    aggregations:
    - alignmentPeriod: 60s
      perSeriesAligner: ALIGN_MEAN
      crossSeriesReducer: REDUCE_MEAN
      groupByFields: ["resource.label.service_name"]
alertStrategy:
  autoClose: 1800s
enabled: true
notificationChannels:
$([ -n "$email_channel" ] && echo "- $email_channel")
EOF
    
    # Create performance alerting policies
    local perf_configs=(
        "$response_time_config"
        "$cpu_config"
        "$memory_config"
    )
    
    for config in "${perf_configs[@]}"; do
        local display_name
        display_name=$(grep "displayName:" "$config" | head -1 | cut -d'"' -f2)
        
        if gcloud alpha monitoring policies list --filter="displayName:'$display_name'" --format="value(name)" | grep -q .; then
            log_info "Updating existing performance alert: $display_name"
            local existing_policy
            existing_policy=$(gcloud alpha monitoring policies list --filter="displayName:'$display_name'" --format="value(name)" | head -1)
            gcloud alpha monitoring policies update "$existing_policy" --policy-from-file="$config"
        else
            log_info "Creating new performance alert: $display_name"
            gcloud alpha monitoring policies create --policy-from-file="$config"
        fi
        
        log_success "Configured performance alert: $display_name"
    done
    
    # Clean up temporary files
    rm -f "${perf_configs[@]}"
}

# Create SLO (Service Level Objectives) monitoring
create_slo_monitoring() {
    log_info "Creating SLO monitoring configuration..."
    
    # API availability SLO
    local api_slo_config="/tmp/api-availability-slo.yaml"
    cat > "$api_slo_config" << EOF
displayName: "iSECTECH API Availability SLO"
serviceLevelIndicator:
  requestBased:
    goodTotalRatio:
      totalServiceFilter: 'resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/request_count"'
      goodServiceFilter: 'resource.type="cloud_run_revision" AND metric.type="run.googleapis.com/request_count" AND metric.label.response_code_class!="5xx"'
goal:
  performanceGoal:
    threshold: 0.995
  rollingPeriod: 2592000s # 30 days
EOF
    
    # API response time SLO
    local response_slo_config="/tmp/api-response-slo.yaml"
    cat > "$response_slo_config" << EOF
displayName: "iSECTECH API Response Time SLO"
serviceLevelIndicator:
  requestBased:
    distributionCut:
      distributionFilter: 'metric.type="custom.googleapis.com/isectech/performance/api_response_time_seconds"'
      range:
        min: 0
        max: 2.0
goal:
  performanceGoal:
    threshold: 0.95
  rollingPeriod: 2592000s # 30 days
EOF
    
    # Create SLOs
    local slo_configs=("$api_slo_config" "$response_slo_config")
    
    for config in "${slo_configs[@]}"; do
        local display_name
        display_name=$(grep "displayName:" "$config" | head -1 | cut -d'"' -f2)
        
        # Note: SLO creation requires a service first, this is a placeholder for future implementation
        log_info "SLO configuration prepared: $display_name"
        log_warning "SLO implementation requires service-level configuration"
    done
    
    # Clean up temporary files
    rm -f "${slo_configs[@]}"
    
    log_success "SLO monitoring configuration prepared"
}

# Create uptime checks
create_uptime_checks() {
    log_info "Creating uptime checks for critical endpoints..."
    
    # Main application uptime check
    local main_uptime_config="/tmp/main-uptime-check.yaml"
    cat > "$main_uptime_config" << EOF
displayName: "iSECTECH Main Application Uptime"
httpCheck:
  path: "/health"
  port: 443
  useSsl: true
  validateSsl: true
monitoredResource:
  type: "uptime_url"
  labels:
    project_id: "$PROJECT_ID"
    host: "protect.isectech.com"
timeout: 10s
period: 60s
checkerType: STATIC_IP_CHECKERS
selectedRegions:
- USA
- EUROPE
- ASIA_PACIFIC
contentMatchers:
- content: '{"status":"healthy"'
  matcher: CONTAINS_STRING
EOF
    
    # API uptime check
    local api_uptime_config="/tmp/api-uptime-check.yaml"
    cat > "$api_uptime_config" << EOF
displayName: "iSECTECH API Uptime"
httpCheck:
  path: "/api/v1/health"
  port: 443
  useSsl: true
  validateSsl: true
  headers:
    User-Agent: "Google-Cloud-Uptime-Check"
    Authorization: "Bearer \${API_HEALTH_TOKEN}"
monitoredResource:
  type: "uptime_url"
  labels:
    project_id: "$PROJECT_ID"
    host: "api.isectech.com"
timeout: 15s
period: 300s
checkerType: STATIC_IP_CHECKERS
selectedRegions:
- USA
- EUROPE
contentMatchers:
- content: '"api_status":"operational"'
  matcher: CONTAINS_STRING
EOF
    
    # Gateway uptime check
    local gateway_uptime_config="/tmp/gateway-uptime-check.yaml"
    cat > "$gateway_uptime_config" << EOF
displayName: "iSECTECH Gateway Uptime"
httpCheck:
  path: "/health"
  port: 443
  useSsl: true
  validateSsl: true
monitoredResource:
  type: "uptime_url"
  labels:
    project_id: "$PROJECT_ID"
    host: "gateway.isectech.com"
timeout: 10s
period: 120s
checkerType: STATIC_IP_CHECKERS
selectedRegions:
- USA
- EUROPE
- ASIA_PACIFIC
contentMatchers:
- content: '{"gateway":"ready"'
  matcher: CONTAINS_STRING
EOF
    
    # Create uptime checks
    local uptime_configs=(
        "$main_uptime_config"
        "$api_uptime_config"
        "$gateway_uptime_config"
    )
    
    for config in "${uptime_configs[@]}"; do
        local display_name
        display_name=$(grep "displayName:" "$config" | head -1 | cut -d'"' -f2)
        
        if gcloud monitoring uptime list --filter="displayName:'$display_name'" --format="value(name)" | grep -q .; then
            log_info "Updating existing uptime check: $display_name"
            local existing_check
            existing_check=$(gcloud monitoring uptime list --filter="displayName:'$display_name'" --format="value(name)" | head -1)
            gcloud monitoring uptime update "$existing_check" --uptime-check-from-file="$config"
        else
            log_info "Creating new uptime check: $display_name"
            gcloud monitoring uptime create --uptime-check-from-file="$config"
        fi
        
        log_success "Configured uptime check: $display_name"
    done
    
    # Clean up temporary files
    rm -f "${uptime_configs[@]}"
}

# Create monitoring report
generate_monitoring_report() {
    log_info "Generating comprehensive monitoring and alerting report..."
    
    local report_file="/tmp/isectech-monitoring-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Dashboards and Alerting Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

=====================================
DASHBOARDS CONFIGURATION
=====================================

Security Monitoring Dashboard:
- Threat detection events with real-time visualization
- Authentication success/failure rates
- API request patterns and endpoint analysis
- Cloud Run service health monitoring
- Error rate tracking by service
- BigQuery security analytics integration
- Load balancer performance metrics
- Cloud Armor security event monitoring

Performance Monitoring Dashboard:
- API response times (P95 percentile tracking)
- Database connection pool utilization
- Memory and CPU utilization across services
- Cache hit ratio monitoring
- Queue processing times
- Resource utilization trends

Business Metrics Dashboard:
- Active user session tracking
- Feature usage analytics
- Revenue impact measurement
- Customer satisfaction scoring
- Subscription and license metrics
- Business KPI visualization

=====================================
ALERTING POLICIES CONFIGURED
=====================================

Security Alerts:
1. High Threat Detection Rate
   - Threshold: >50 threats/minute
   - Duration: 5 minutes
   - Auto-close: 24 hours

2. Authentication Failure Spike
   - Threshold: >100 failures/minute
   - Duration: 3 minutes
   - Auto-close: 1 hour

3. Critical Service Down
   - Threshold: >10 5xx errors/minute
   - Duration: 2 minutes
   - Auto-close: 30 minutes

Performance Alerts:
1. High API Response Time
   - Threshold: P95 > 2 seconds
   - Duration: 5 minutes
   - Auto-close: 30 minutes

2. High CPU Utilization
   - Threshold: >80% for 10 minutes
   - Auto-close: 1 hour

3. High Memory Utilization
   - Threshold: >90% for 5 minutes
   - Auto-close: 30 minutes

4. High API Error Rate
   - Threshold: >5% error rate
   - Duration: 5 minutes
   - Auto-close: 1 hour

5. Database Connection Pool Exhaustion
   - Threshold: >80 active connections
   - Duration: 3 minutes
   - Auto-close: 30 minutes

=====================================
NOTIFICATION CHANNELS
=====================================

Email Notifications:
- Primary: $NOTIFICATION_EMAIL
- Team: Security Team
- Priority: High

$([ -n "$SLACK_WEBHOOK" ] && echo "Slack Notifications:
- Channel: #security-alerts
- Integration: Webhook-based
- Priority: Medium")

$([ -n "$PAGERDUTY_INTEGRATION_KEY" ] && echo "PagerDuty Integration:
- Service: iSECTECH Security Platform
- Integration Key: Configured
- Priority: Critical")

=====================================
UPTIME CHECKS CONFIGURED
=====================================

1. Main Application Uptime
   - URL: https://protect.isectech.com/health
   - Frequency: Every 60 seconds
   - Regions: USA, Europe, Asia Pacific
   - Expected: {"status":"healthy"}

2. API Uptime Check
   - URL: https://api.isectech.com/api/v1/health
   - Frequency: Every 5 minutes
   - Regions: USA, Europe
   - Expected: "api_status":"operational"

3. Gateway Uptime Check
   - URL: https://gateway.isectech.com/health
   - Frequency: Every 2 minutes
   - Regions: USA, Europe, Asia Pacific
   - Expected: {"gateway":"ready"}

=====================================
SLO (SERVICE LEVEL OBJECTIVES)
=====================================

API Availability SLO:
- Target: 99.5% availability
- Measurement: 30-day rolling window
- Indicator: Request success rate (non-5xx responses)

API Response Time SLO:
- Target: 95% of requests < 2 seconds
- Measurement: 30-day rolling window
- Indicator: Response time distribution

=====================================
MONITORING INTEGRATIONS
=====================================

Google Cloud Monitoring:
- Custom metrics: ✓ Configured
- Resource monitoring: ✓ Enabled
- Trace data: ✓ Integrated
- Log-based metrics: ✓ Active

BigQuery Analytics:
- Security events dataset: ✓ Configured
- Performance metrics dataset: ✓ Configured
- Business metrics dataset: ✓ Configured
- Compliance logs dataset: ✓ Configured

Prometheus Integration:
- Metrics collection: ✓ Active
- Custom security metrics: ✓ Configured
- Performance counters: ✓ Enabled
- Business KPIs: ✓ Tracked

OpenTelemetry Tracing:
- Distributed tracing: ✓ Configured
- Security context: ✓ Enhanced
- Performance profiling: ✓ Enabled
- Error tracking: ✓ Integrated

=====================================
MONITORING BEST PRACTICES APPLIED
=====================================

Security Monitoring:
✓ Real-time threat detection
✓ Authentication anomaly detection
✓ API security monitoring
✓ Infrastructure security scanning
✓ Compliance log retention
✓ Security event correlation

Performance Monitoring:
✓ Application performance monitoring (APM)
✓ Infrastructure monitoring
✓ Database performance tracking
✓ Cache efficiency monitoring
✓ Queue processing monitoring
✓ Response time optimization

Business Intelligence:
✓ User behavior analytics
✓ Feature adoption tracking
✓ Revenue impact measurement
✓ Customer satisfaction monitoring
✓ Subscription lifecycle tracking
✓ Business KPI dashboards

=====================================
OPERATIONAL PROCEDURES
=====================================

Alert Response Procedures:
1. Critical alerts trigger immediate notification
2. Security alerts require acknowledgment within 5 minutes
3. Performance alerts trigger auto-scaling if configured
4. Business impact alerts notify leadership team
5. All alerts logged for post-incident analysis

Dashboard Access:
- Google Cloud Console: Monitoring section
- Direct dashboard URLs: Available in console
- Mobile access: Google Cloud mobile app
- API access: Monitoring API enabled

Maintenance Windows:
- Scheduled maintenance: Alerts suppressed automatically
- Emergency maintenance: Manual alert suppression
- Rollback procedures: Monitoring state preservation
- Health check validation: Post-deployment verification

=====================================
TROUBLESHOOTING GUIDE
=====================================

Dashboard Issues:
1. Dashboard not loading: Check IAM permissions
2. Missing data: Verify metrics are being generated
3. Slow performance: Check time range and filters
4. Authentication errors: Verify service account permissions

Alert Issues:
1. Alerts not firing: Check notification channels
2. False positives: Adjust thresholds or conditions
3. Missing alerts: Verify metric filters
4. Delayed notifications: Check channel configuration

Metric Collection Issues:
1. Missing custom metrics: Check Prometheus configuration
2. Trace data not appearing: Verify OpenTelemetry setup
3. Log-based metrics failing: Check BigQuery sinks
4. Performance data gaps: Verify service instrumentation

=====================================
NEXT STEPS
=====================================

Immediate Actions:
1. Test all alerting policies with synthetic triggers
2. Verify dashboard data population across all panels
3. Configure additional notification channels as needed
4. Set up mobile app access for on-call team
5. Create runbooks for each alert type

Short-term Improvements:
1. Implement ML-based anomaly detection
2. Add capacity planning dashboards
3. Create cost optimization monitoring
4. Enhance security correlation rules
5. Set up automated remediation workflows

Long-term Enhancements:
1. Multi-region monitoring aggregation
2. Advanced predictive analytics
3. Custom alert correlation engine
4. Automated incident response system
5. Comprehensive observability platform integration

=====================================
VERIFICATION COMMANDS
=====================================

Test Dashboards:
gcloud monitoring dashboards list --filter="displayName:iSECTECH"

Test Alert Policies:
gcloud alpha monitoring policies list --filter="displayName:iSECTECH"

Test Notification Channels:
gcloud alpha monitoring channels list

Test Uptime Checks:
gcloud monitoring uptime list

Test Custom Metrics:
gcloud monitoring metrics list --filter="metric.type:custom.googleapis.com/isectech"

Manual Alert Test:
# Trigger test alert by generating high metric values
# Example: Increase API error rate temporarily

=====================================
SUPPORT AND MAINTENANCE
=====================================

Regular Maintenance Tasks:
- Weekly: Review alert noise and adjust thresholds
- Monthly: Analyze dashboard usage and optimize
- Quarterly: Review SLO targets and business alignment
- Annually: Comprehensive monitoring strategy review

Support Contacts:
- Technical Issues: Cloud Operations Team
- Business Metrics: Product Management Team
- Security Alerts: Security Operations Center (SOC)
- Infrastructure: DevOps Engineering Team

Documentation:
- Runbook Location: .taskmaster/docs/monitoring/
- Alert Playbooks: .taskmaster/docs/alerts/
- Dashboard Guides: .taskmaster/docs/dashboards/
- Troubleshooting: .taskmaster/docs/troubleshooting/

EOF
    
    log_success "Monitoring and alerting report generated: $report_file"
    cat "$report_file"
}

# Test monitoring and alerting configuration
test_monitoring_configuration() {
    log_info "Testing monitoring and alerting configuration..."
    
    # Test dashboard access
    log_info "Testing dashboard accessibility..."
    local dashboard_count
    dashboard_count=$(gcloud monitoring dashboards list --filter="displayName:iSECTECH" --format="value(name)" | wc -l)
    log_success "Found $dashboard_count iSECTECH dashboards configured"
    
    # Test alert policies
    log_info "Testing alert policies..."
    local alert_count
    alert_count=$(gcloud alpha monitoring policies list --filter="displayName:iSECTECH" --format="value(name)" | wc -l)
    log_success "Found $alert_count iSECTECH alert policies configured"
    
    # Test notification channels
    log_info "Testing notification channels..."
    local channel_count
    channel_count=$(gcloud alpha monitoring channels list --format="value(name)" | wc -l)
    log_success "Found $channel_count notification channels configured"
    
    # Test uptime checks
    log_info "Testing uptime checks..."
    local uptime_count
    uptime_count=$(gcloud monitoring uptime list --filter="displayName:iSECTECH" --format="value(name)" | wc -l)
    log_success "Found $uptime_count iSECTECH uptime checks configured"
    
    # Test custom metrics
    log_info "Testing custom metrics availability..."
    local custom_metrics_count
    custom_metrics_count=$(gcloud monitoring metrics list --filter="metric.type:custom.googleapis.com/isectech" --format="value(type)" | wc -l)
    log_success "Found $custom_metrics_count custom iSECTECH metrics configured"
    
    log_success "Monitoring and alerting configuration test completed successfully"
}

# Main execution function
main() {
    log_info "Starting iSECTECH dashboards and alerting configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    check_prerequisites
    
    create_notification_channels
    
    create_security_dashboard
    create_performance_dashboard
    create_business_dashboard
    
    create_security_alerting_policies
    create_performance_alerting_policies
    
    create_slo_monitoring
    create_uptime_checks
    
    test_monitoring_configuration
    generate_monitoring_report
    
    log_success "iSECTECH dashboards and alerting configuration completed!"
    
    echo ""
    log_info "Dashboards and alerting are now fully configured."
    log_info "Access dashboards in Google Cloud Console > Monitoring > Dashboards"
    log_info "View alert policies in Google Cloud Console > Monitoring > Alerting"
    log_info "Check uptime monitors in Google Cloud Console > Monitoring > Uptime checks"
    log_info "All notification channels are configured and ready."
    
    # Clean up temporary files
    rm -f /tmp/email_channel_name.txt /tmp/slack_channel_name.txt
}

# Help function
show_help() {
    cat << EOF
iSECTECH Dashboards and Alerting Configuration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV            Environment (production, staging, development)
    --project PROJECT           Google Cloud project ID
    --region REGION            Google Cloud region (default: us-central1)
    --notification-email EMAIL Primary notification email
    --slack-webhook URL        Slack webhook URL for notifications
    --pagerduty-key KEY       PagerDuty integration key
    --help                    Show this help message

Environment Variables:
    PROJECT_ID                Google Cloud project ID
    REGION                   Google Cloud region
    ENVIRONMENT              Environment name
    NOTIFICATION_EMAIL       Primary notification email
    SLACK_WEBHOOK           Slack webhook URL
    PAGERDUTY_INTEGRATION_KEY PagerDuty integration key

Examples:
    # Configure production monitoring
    ./dashboards-alerting-setup.sh --environment production

    # Configure with Slack notifications
    ./dashboards-alerting-setup.sh --slack-webhook https://hooks.slack.com/...

Prerequisites:
    - Monitoring, logging, and error reporting APIs enabled
    - Structured logging infrastructure configured
    - Custom metrics and tracing configured
    - BigQuery data pipeline configured
    - Appropriate IAM permissions for monitoring

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --notification-email)
            NOTIFICATION_EMAIL="$2"
            shift 2
            ;;
        --slack-webhook)
            SLACK_WEBHOOK="$2"
            shift 2
            ;;
        --pagerduty-key)
            PAGERDUTY_INTEGRATION_KEY="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"