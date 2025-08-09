# iSECTECH Multi-Region Monitoring and Health Checks
# Comprehensive monitoring, alerting, and health checks for multi-region deployment
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Multi-Region Monitoring Implementation

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL HEALTH CHECK CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Comprehensive uptime checks for each regional endpoint
resource "google_monitoring_uptime_check_config" "regional_api_health" {
  for_each = local.regions
  
  display_name = "iSECTECH ${each.key} API Health Check"
  timeout      = "10s"
  period       = "${var.health_check_interval}s"
  project      = var.project_id
  
  http_check {
    path           = "${var.health_check_path}/api"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
    
    headers = {
      "User-Agent"    = "iSECTECH-HealthCheck/1.0"
      "Host"          = "api.${trimsuffix(var.domain_name, ".")}"
      "X-Region"      = each.key
      "X-Environment" = var.environment
    }
    
    body = ""
    content_type = "TEXT"
    custom_content_type = ""
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = "api-${each.key}.${trimsuffix(var.domain_name, ".")}"
    }
  }
  
  # Check from multiple global locations for comprehensive coverage
  selected_regions = var.environment == "production" ? [
    "USA_OREGON",
    "USA_VIRGINIA",
    "EUROPE",
    "ASIA_PACIFIC"
  ] : ["USA"]
  
  checker_type = "STATIC_IP_CHECKERS"
}

# Database connectivity health checks
resource "google_monitoring_uptime_check_config" "regional_db_health" {
  for_each = local.regions
  
  display_name = "iSECTECH ${each.key} Database Health"
  timeout      = "15s"
  period       = "60s"  # Database checks less frequent
  project      = var.project_id
  
  http_check {
    path           = "${var.health_check_path}/db"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
    
    headers = {
      "User-Agent"    = "iSECTECH-DB-HealthCheck/1.0"
      "Host"          = "api.${trimsuffix(var.domain_name, ".")}"
      "X-Region"      = each.key
      "X-Check-Type"  = "database"
    }
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = "db-${each.key}.${trimsuffix(var.domain_name, ".")}"
    }
  }
  
  selected_regions = var.environment == "production" ? [
    "USA",
    "EUROPE",
    "ASIA_PACIFIC"
  ] : ["USA"]
  
  checker_type = "STATIC_IP_CHECKERS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE MONITORING DASHBOARDS
# ═══════════════════════════════════════════════════════════════════════════════

# Multi-region overview dashboard
resource "google_monitoring_dashboard" "multi_region_overview" {
  dashboard_json = jsonencode({
    displayName = "iSECTECH Multi-Region Infrastructure Overview"
    mosaicLayout = {
      tiles = [
        {
          width = 12
          height = 4
          widget = {
            title = "Global Health Status"
            scorecard = {
              sparkChartView = {
                sparkChartType = "SPARK_LINE"
              }
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"uptime_url\""
                  aggregation = {
                    alignmentPeriod = "60s"
                    perSeriesAligner = "ALIGN_FRACTION_TRUE"
                    crossSeriesReducer = "REDUCE_MEAN"
                    groupByFields = ["resource.label.host"]
                  }
                }
              }
              thresholds = [
                {
                  value = 0.95
                  color = "RED"
                  direction = "BELOW"
                }
              ]
            }
          }
        },
        {
          width = 6
          height = 4
          yPos = 4
          widget = {
            title = "Regional Response Times"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
                      aggregation = {
                        alignmentPeriod = "60s"
                        perSeriesAligner = "ALIGN_FRACTION_TRUE"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields = ["resource.label.host"]
                      }
                    }
                  }
                  plotType = "LINE"
                  targetAxis = "Y1"
                }
              ]
              yAxis = {
                label = "Success Rate"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width = 6
          height = 4
          xPos = 6
          yPos = 4
          widget = {
            title = "Regional Traffic Distribution"
            pieChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/network/received_bytes_count\""
                      aggregation = {
                        alignmentPeriod = "300s"
                        perSeriesAligner = "ALIGN_RATE"
                        crossSeriesReducer = "REDUCE_SUM"
                        groupByFields = ["resource.label.zone"]
                      }
                    }
                  }
                }
              ]
            }
          }
        }
      ]
    }
  })
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# ALERT POLICIES FOR MULTI-REGION MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Regional endpoint failure alert
resource "google_monitoring_alert_policy" "regional_endpoint_failure" {
  display_name = "iSECTECH Regional Endpoint Failure"
  combiner    = "OR"
  enabled     = true
  project     = var.project_id
  
  notification_channels = var.monitoring_notification_channels
  
  conditions {
    display_name = "Regional Endpoint Down"
    
    condition_threshold {
      filter         = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      duration       = "180s"  # 3 minutes of failures
      comparison     = "COMPARISON_LESS_THAN"
      threshold_value = 0.8    # Less than 80% success rate
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner  = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields     = ["resource.label.host"]
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  conditions {
    display_name = "Regional Database Connectivity"
    
    condition_threshold {
      filter         = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" AND resource.label.host=~\"db-.*\""
      duration       = "300s"  # 5 minutes for database issues
      comparison     = "COMPARISON_LESS_THAN"
      threshold_value = 0.9    # Less than 90% success rate
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner  = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields     = ["resource.label.host"]
      }
    }
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "300s"  # Limit notifications to every 5 minutes
    }
    auto_close = "1800s"  # Auto-close after 30 minutes if resolved
  }
  
  documentation {
    content = "Regional endpoint or database connectivity failure detected. Check regional infrastructure and failover procedures."
    mime_type = "text/markdown"
  }
}

# DNS resolution failure alert
resource "google_monitoring_alert_policy" "dns_resolution_failure" {
  display_name = "iSECTECH DNS Resolution Failure"
  combiner    = "OR"
  enabled     = true
  project     = var.project_id
  
  notification_channels = var.monitoring_notification_channels
  
  conditions {
    display_name = "High DNS Query Failure Rate"
    
    condition_threshold {
      filter         = "resource.type=\"dns_query\" AND metric.type=\"dns.googleapis.com/query/count\""
      duration       = "300s"
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 100  # More than 100 failed queries in 5 minutes
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner  = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields     = ["resource.label.source_type"]
      }
    }
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "600s"  # Limit to every 10 minutes
    }
    auto_close = "3600s"  # Auto-close after 1 hour
  }
  
  documentation {
    content = "High DNS query failure rate detected. Check DNS zone configuration and name server availability."
    mime_type = "text/markdown"
  }
}

# Cross-region latency alert
resource "google_monitoring_alert_policy" "cross_region_latency" {
  display_name = "iSECTECH Cross-Region High Latency"
  combiner    = "OR"
  enabled     = true
  project     = var.project_id
  
  notification_channels = var.monitoring_notification_channels
  
  conditions {
    display_name = "High Response Time"
    
    condition_threshold {
      filter         = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/time_until_ssl_cert_expires\""
      duration       = "600s"  # 10 minutes of high latency
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 5000   # 5 seconds response time
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner  = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields     = ["resource.label.host"]
      }
    }
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "900s"  # Every 15 minutes
    }
    auto_close = "1800s"
  }
  
  documentation {
    content = "High response times detected across regions. Check network connectivity and regional load balancing."
    mime_type = "text/markdown"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLO/SLI CONFIGURATION FOR MULTI-REGION
# ═══════════════════════════════════════════════════════════════════════════════

# Service Level Objective for overall availability
resource "google_monitoring_slo" "global_availability_slo" {
  count        = var.environment == "production" ? 1 : 0
  service      = google_monitoring_service.isectech_service[0].name
  display_name = "Global API Availability SLO"
  project      = var.project_id
  
  goal = 0.9995  # 99.95% availability target
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = "resource.type=\"uptime_url\""
      good_service_filter  = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
    }
  }
  
  rolling_period_days = 28  # 28-day rolling window
}

# Service definition for SLO tracking
resource "google_monitoring_service" "isectech_service" {
  count        = var.environment == "production" ? 1 : 0
  service_id   = "isectech-multi-region-service"
  display_name = "iSECTECH Multi-Region Service"
  project      = var.project_id
  
  user_labels = {
    environment = var.environment
    service     = "multi-region"
    team        = "devops"
  }
}

# Regional performance SLO
resource "google_monitoring_slo" "regional_performance_slo" {
  for_each = var.environment == "production" ? local.regions : {}
  
  service      = google_monitoring_service.isectech_service[0].name
  display_name = "${each.key} Performance SLO"
  project      = var.project_id
  
  goal = each.value.role == "primary" ? 0.999 : 0.995  # Higher SLO for primary regions
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = "resource.type=\"uptime_url\" AND resource.label.host=~\".*${each.key}.*\""
      good_service_filter  = "resource.type=\"uptime_url\" AND resource.label.host=~\".*${each.key}.*\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
    }
  }
  
  rolling_period_days = 7  # Weekly SLO for regional performance
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNELS FOR ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Email notification channel for critical alerts
resource "google_monitoring_notification_channel" "critical_email" {
  count        = var.enable_logging_monitoring ? 1 : 0
  display_name = "iSECTECH Critical Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "critical-alerts@isectech.org"
  }
  
  description = "Critical infrastructure alerts for multi-region deployment"
  enabled     = true
  
  user_labels = {
    environment = var.environment
    severity    = "critical"
    team        = "devops"
  }
}

# Slack notification channel (if webhook provided)
resource "google_monitoring_notification_channel" "slack_alerts" {
  count        = var.slack_webhook_url != "" ? 1 : 0
  display_name = "iSECTECH Slack Alerts"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    url = var.slack_webhook_url
  }
  
  description = "Slack notifications for multi-region infrastructure"
  enabled     = true
  
  user_labels = {
    environment = var.environment
    team        = "devops"
  }
}

# PagerDuty integration (if key provided)
resource "google_monitoring_notification_channel" "pagerduty_alerts" {
  count        = var.pagerduty_integration_key != "" ? 1 : 0
  display_name = "iSECTECH PagerDuty"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_integration_key
  }
  
  description = "PagerDuty integration for critical multi-region alerts"
  enabled     = true
  
  user_labels = {
    environment = var.environment
    severity    = "critical"
    escalation  = "enabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR MONITORING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

output "monitoring_configuration" {
  description = "Multi-region monitoring and alerting configuration"
  value = {
    health_checks = {
      for region in keys(local.regions) : region => {
        api_health = google_monitoring_uptime_check_config.regional_api_health[region].name
        db_health  = google_monitoring_uptime_check_config.regional_db_health[region].name
      }
    }
    
    alert_policies = {
      endpoint_failure    = google_monitoring_alert_policy.regional_endpoint_failure.name
      dns_resolution     = google_monitoring_alert_policy.dns_resolution_failure.name
      cross_region_latency = google_monitoring_alert_policy.cross_region_latency.name
    }
    
    slo_configuration = var.environment == "production" ? {
      global_availability_slo = google_monitoring_slo.global_availability_slo[0].name
      regional_performance_slos = {
        for region in keys(local.regions) : region => google_monitoring_slo.regional_performance_slo[region].name
      }
    } : null
    
    dashboards = {
      multi_region_overview = google_monitoring_dashboard.multi_region_overview.id
    }
    
    notification_channels = compact([
      try(google_monitoring_notification_channel.critical_email[0].name, ""),
      try(google_monitoring_notification_channel.slack_alerts[0].name, ""),
      try(google_monitoring_notification_channel.pagerduty_alerts[0].name, "")
    ])
  }
  sensitive = false
}