# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH MULTI-REGION MONITORING INFRASTRUCTURE
# Production-grade monitoring stack for Regional Hybrid deployment model
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.9 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING STRATEGY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Multi-region monitoring configuration aligned with Regional Hybrid model
  monitoring_strategy = {
    deployment_model = "regional-hybrid"
    description = "Comprehensive monitoring for multi-region deployment with compliance"
    
    # Active regions requiring full monitoring coverage
    active_regions = ["us-central1", "europe-west4", "asia-northeast1"]
    
    # Backup regions with basic monitoring
    backup_regions = ["us-east1", "europe-west1"]
    
    # All monitored regions
    all_regions = ["us-central1", "europe-west4", "asia-northeast1", "us-east1", "europe-west1"]
    
    # Monitoring objectives and SLIs/SLOs
    sli_slo_config = {
      availability = {
        global_target = 99.95
        regional_target = 99.9
        measurement_window = "28d"
        error_budget_burn_rate_thresholds = {
          page_immediately = 14.4  # 1 hour window
          page_soon = 6.0         # 6 hours window
          ticket = 1.0           # 3 days window
        }
      }
      
      latency = {
        p50_target_ms = 200
        p95_target_ms = 500
        p99_target_ms = 1000
        measurement_window = "5m"
      }
      
      error_rate = {
        target_percentage = 0.1  # 99.9% success rate
        measurement_window = "5m"
      }
    }
    
    # Health check configuration
    health_checks = {
      frequency_seconds = 30
      timeout_seconds = 10
      failure_threshold = 3
      success_threshold = 2
      
      checks = {
        api_health = {
          path = "/api/v1/health"
          expected_status = 200
          timeout_seconds = 5
        }
        database_health = {
          path = "/api/v1/health/database"
          expected_status = 200
          timeout_seconds = 10
        }
        cache_health = {
          path = "/api/v1/health/cache"  
          expected_status = 200
          timeout_seconds = 5
        }
        auth_health = {
          path = "/api/v1/health/auth"
          expected_status = 200
          timeout_seconds = 5
        }
      }
    }
    
    # Compliance monitoring zones
    compliance_zones = {
      gdpr = {
        regions = ["europe-west4", "europe-west1"]
        data_residency_monitoring = true
        audit_logging_required = true
        retention_days = 2555  # 7 years
        encryption_monitoring = true
      }
      ccpa = {
        regions = ["us-central1", "us-east1"] 
        data_residency_monitoring = true
        audit_logging_required = true
        retention_days = 1095  # 3 years
        encryption_monitoring = true
      }
      appi = {
        regions = ["asia-northeast1"]
        data_residency_monitoring = true
        audit_logging_required = true
        retention_days = 1825  # 5 years
        encryption_monitoring = true
      }
    }
    
    # Alerting configuration
    alerting = {
      escalation_levels = {
        info = {
          channels = ["email", "slack"]
          escalation_delay = "0s"
        }
        warning = {
          channels = ["email", "slack", "teams"]
          escalation_delay = "5m"
        }
        critical = {
          channels = ["email", "slack", "teams", "pagerduty"]
          escalation_delay = "1m"
        }
      }
      
      correlation_window = "5m"
      deduplication_window = "1h"
      auto_resolve_timeout = "24h"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING INFRASTRUCTURE RESOURCES
# ═══════════════════════════════════════════════════════════════════════════════

# Random suffix for unique resource naming
resource "random_id" "monitoring_suffix" {
  byte_length = 4
}

# Dedicated monitoring project for centralized observability (optional)
resource "google_project" "monitoring_project" {
  count           = var.create_dedicated_monitoring_project ? 1 : 0
  project_id      = "${var.project_id}-monitoring-${random_id.monitoring_suffix.hex}"
  name            = "iSECTECH Monitoring Hub"
  org_id          = var.org_id
  billing_account = var.billing_account
  
  labels = merge(local.common_labels, {
    purpose = "monitoring"
    scope   = "multi-region"
  })
}

# Monitoring workspace for centralized metrics
resource "google_monitoring_workspace" "multi_region_workspace" {
  workspace_id = var.create_dedicated_monitoring_project ? google_project.monitoring_project[0].project_id : var.project_id
  display_name = "iSECTECH Multi-Region Monitoring Workspace"
  
  dynamic "monitored_projects" {
    for_each = var.create_dedicated_monitoring_project ? [var.project_id] : []
    content {
      name = "projects/${monitored_projects.value}"
    }
  }
  
  provider = google
}

# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-REGION HEALTH MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Global HTTP(S) load balancer health check
resource "google_compute_health_check" "multi_region_health_check" {
  name               = "isectech-multi-region-health-check-${var.environment}"
  description        = "Health check for multi-region deployment"
  timeout_sec        = local.monitoring_strategy.health_checks.timeout_seconds
  check_interval_sec = local.monitoring_strategy.health_checks.frequency_seconds
  
  # Configure for global load balancer
  healthy_threshold   = local.monitoring_strategy.health_checks.success_threshold
  unhealthy_threshold = local.monitoring_strategy.health_checks.failure_threshold
  
  http_health_check {
    request_path = local.monitoring_strategy.health_checks.checks.api_health.path
    port         = 443
    port_specification = "USE_FIXED_PORT"
    proxy_header = "NONE"
  }
  
  log_config {
    enable = true
  }
  
  project = var.project_id
}

# Regional uptime checks for each region
resource "google_monitoring_uptime_check_config" "regional_uptime_checks" {
  for_each = toset(local.monitoring_strategy.all_regions)
  
  display_name = "Regional Uptime Check - ${each.value}"
  timeout      = "${local.monitoring_strategy.health_checks.timeout_seconds}s"
  period       = "${local.monitoring_strategy.health_checks.frequency_seconds}s"
  
  # Target the regional endpoint
  monitored_resource {
    type = "uptime_url"
    labels = {
      host       = "app-${each.value}.${trimsuffix(var.domain_name, ".")}"
      project_id = var.project_id
    }
  }
  
  http_check {
    request_method = "GET"
    path           = local.monitoring_strategy.health_checks.checks.api_health.path
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    
    # Add regional header for proper routing
    headers = {
      "X-Region-Check" = each.value
      "User-Agent"     = "iSECTECH-Multi-Region-Monitor/1.0"
    }
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
  }
  
  # Checker locations distributed globally
  checker_type = "STATIC_IP_CHECKERS"
  selected_regions = [
    "USA_OREGON",
    "USA_VIRGINIA", 
    "EUROPE_LONDON",
    "ASIA_PACIFIC_SINGAPORE"
  ]
  
  project = var.project_id
}

# Cross-region latency monitoring
resource "google_monitoring_uptime_check_config" "cross_region_latency_checks" {
  for_each = {
    for pair in [
      for source in local.monitoring_strategy.active_regions : [
        for target in local.monitoring_strategy.active_regions : {
          source = source
          target = target
          key    = "${source}-to-${target}"
        } if source != target
      ]
    ] : pair.key => pair
  }
  
  display_name = "Cross-Region Latency - ${each.value.source} to ${each.value.target}"
  timeout      = "10s"
  period       = "60s"  # Check every minute for latency monitoring
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      host       = "app-${each.value.target}.${trimsuffix(var.domain_name, ".")}"
      project_id = var.project_id
    }
  }
  
  http_check {
    request_method = "GET"
    path           = "/api/v1/ping"
    port           = 443
    use_ssl        = true
    
    headers = {
      "X-Source-Region" = each.value.source
      "X-Target-Region" = each.value.target
      "X-Latency-Check" = "true"
    }
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
  }
  
  checker_type = "STATIC_IP_CHECKERS"
  selected_regions = [
    contains(["us-central1", "us-east1"], each.value.source) ? "USA_OREGON" : 
    contains(["europe-west4", "europe-west1"], each.value.source) ? "EUROPE_LONDON" :
    "ASIA_PACIFIC_SINGAPORE"
  ]
  
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE MONITORING INFRASTRUCTURE  
# ═══════════════════════════════════════════════════════════════════════════════

# Data residency violation detection Cloud Function
resource "google_storage_bucket" "compliance_monitor_function" {
  name     = "isectech-compliance-monitor-${var.environment}-${random_id.monitoring_suffix.hex}"
  location = "US"  # Function bucket can be in US for global deployment
  project  = var.project_id
  
  uniform_bucket_level_access = true
  force_destroy = true
  
  labels = merge(local.common_labels, {
    function-type = "compliance-monitoring"
  })
}

# Compliance monitoring function source
resource "google_storage_bucket_object" "compliance_monitor_source" {
  name   = "compliance-monitor-${random_id.monitoring_suffix.hex}.zip"
  bucket = google_storage_bucket.compliance_monitor_function.name
  source = data.archive_file.compliance_monitor_source.output_path
  
  depends_on = [data.archive_file.compliance_monitor_source]
}

data "archive_file" "compliance_monitor_source" {
  type        = "zip"
  output_path = "/tmp/compliance-monitor.zip"
  
  source {
    content = templatefile("${path.module}/functions/compliance_monitor.py", {
      monitoring_strategy = jsonencode(local.monitoring_strategy)
      project_id         = var.project_id
      environment        = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/requirements.txt")
    filename = "requirements.txt"
  }
}

# Compliance monitoring Cloud Function
resource "google_cloudfunctions2_function" "compliance_monitor" {
  name        = "isectech-compliance-monitor-${var.environment}"
  location    = "us-central1"  # Primary region for compliance monitoring
  project     = var.project_id
  description = "Monitor data residency compliance across regions"
  
  build_config {
    runtime     = "python311"
    entry_point = "monitor_compliance"
    
    source {
      storage_source {
        bucket = google_storage_bucket.compliance_monitor_function.name
        object = google_storage_bucket_object.compliance_monitor_source.name
      }
    }
  }
  
  service_config {
    max_instance_count = 20
    available_memory   = "1Gi"
    timeout_seconds    = 540  # 9 minutes
    
    environment_variables = {
      PROJECT_ID          = var.project_id
      ENVIRONMENT         = var.environment
      MONITORING_STRATEGY = jsonencode(local.monitoring_strategy)
      COMPLIANCE_ZONES    = jsonencode(local.monitoring_strategy.compliance_zones)
    }
    
    service_account_email = google_service_account.compliance_monitor.email
  }
  
  # Event-driven trigger for compliance violations
  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.audit.log.v1.written"
    
    event_filters {
      attribute = "serviceName"
      value     = "storage.googleapis.com"
    }
    
    event_filters {
      attribute = "methodName"
      value     = "storage.objects.create"
    }
  }
  
  depends_on = [
    google_project_service.cloudfunctions,
    google_storage_bucket_object.compliance_monitor_source
  ]
}

# Service account for compliance monitoring
resource "google_service_account" "compliance_monitor" {
  account_id   = "compliance-monitor-${var.environment}"
  display_name = "Compliance Monitor Service Account"
  description  = "Service account for multi-region compliance monitoring"
  project      = var.project_id
}

# IAM bindings for compliance monitoring
resource "google_project_iam_member" "compliance_monitor_roles" {
  for_each = toset([
    "roles/cloudsql.viewer",
    "roles/storage.admin", 
    "roles/redis.viewer",
    "roles/pubsub.viewer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/cloudaudit.viewer",
    "roles/iam.securityReviewer"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.compliance_monitor.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED TRACING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Trace for distributed tracing across regions
resource "google_project_service" "cloudtrace" {
  project = var.project_id
  service = "cloudtrace.googleapis.com"
  
  disable_dependent_services = false
}

# Custom metrics for cross-region tracing
resource "google_monitoring_metric_descriptor" "cross_region_trace_latency" {
  type         = "custom.googleapis.com/tracing/cross_region_latency"
  metric_kind  = "GAUGE" 
  value_type   = "DOUBLE"
  description  = "Cross-region request latency in milliseconds"
  display_name = "Cross-Region Trace Latency"
  
  labels {
    key         = "source_region"
    value_type  = "STRING"
    description = "Source region of the request"
  }
  
  labels {
    key         = "target_region"
    value_type  = "STRING"
    description = "Target region of the request"
  }
  
  labels {
    key         = "service_name"
    value_type  = "STRING"
    description = "Name of the service being traced"
  }
  
  labels {
    key         = "compliance_zone"
    value_type  = "STRING"
    description = "Compliance zone for the trace"
  }
  
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLI/SLO MONITORING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

# SLO configuration for each region
resource "google_monitoring_slo" "regional_availability_slo" {
  for_each = toset(local.monitoring_strategy.active_regions)
  
  slo_id       = "regional-availability-${each.value}-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.regional_services[each.value].service_id}"
  display_name = "Regional Availability SLO - ${each.value}"
  
  # 99.9% availability SLO for regional services
  goal                = local.monitoring_strategy.sli_slo_config.availability.regional_target / 100
  rolling_period_days = 28
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.value}-.*\""
      good_service_filter  = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.value}-.*\" AND metric.type=\"compute.googleapis.com/instance/up\""
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.regional_services]
}

# Global availability SLO
resource "google_monitoring_slo" "global_availability_slo" {
  slo_id       = "global-availability-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.global_service.service_id}"
  display_name = "Global Availability SLO"
  
  # 99.95% availability SLO for global service
  goal                = local.monitoring_strategy.sli_slo_config.availability.global_target / 100
  rolling_period_days = 28
  
  request_based_sli {
    distribution_cut {
      distribution_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\""
      
      range {
        max = 500  # Treat responses >= 500ms as bad
      }
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.global_service]
}

# Monitoring services for SLO tracking
resource "google_monitoring_service" "regional_services" {
  for_each = toset(local.monitoring_strategy.active_regions)
  
  service_id   = "regional-service-${each.value}-${var.environment}"
  display_name = "Regional Service - ${each.value}"
  
  telemetry {
    resource_name = "//compute.googleapis.com/projects/${var.project_id}/zones/${each.value}-a/instances/*"
  }
  
  project = var.project_id
}

resource "google_monitoring_service" "global_service" {
  service_id   = "global-service-${var.environment}"
  display_name = "Global Load Balancer Service"
  
  telemetry {
    resource_name = "//compute.googleapis.com/projects/${var.project_id}/global/urlMaps/*"
  }
  
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTELLIGENT ALERTING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

# Alert policy for regional failures
resource "google_monitoring_alert_policy" "regional_failure_alert" {
  for_each = toset(local.monitoring_strategy.active_regions)
  
  display_name = "Regional Failure Alert - ${each.value}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Regional service unavailable"
    
    condition_threshold {
      filter          = "resource.type=\"uptime_url\" AND resource.label.host=\"app-${each.value}.${trimsuffix(var.domain_name, ".")}\""
      duration        = "180s"  # 3 minutes
      comparison      = "COMPARISON_LESS_THAN"
      threshold_value = 1  # Uptime check success
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        
        group_by_fields = [
          "resource.label.host"
        ]
      }
      
      trigger {
        count   = 1
        percent = 0
      }
    }
  }
  
  # Critical severity for regional failures
  severity = "CRITICAL"
  
  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
  
  notification_channels = [
    google_monitoring_notification_channel.critical_email.id,
    google_monitoring_notification_channel.critical_slack.id,
    google_monitoring_notification_channel.critical_pagerduty.id
  ]
  
  documentation {
    content = "Regional failure detected in ${each.value}. Immediate investigation and failover procedures required."
    mime_type = "text/markdown"
  }
}

# Cross-region latency alert
resource "google_monitoring_alert_policy" "cross_region_latency_alert" {
  display_name = "Cross-Region Latency Alert"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "High cross-region latency detected"
    
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/time_until_ssl_cert_expires\""
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 1000    # 1 second latency threshold
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MAX"
        
        group_by_fields = [
          "resource.label.host"
        ]
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.warning_email.id,
    google_monitoring_notification_channel.warning_slack.id
  ]
  
  documentation {
    content = "Cross-region latency exceeds acceptable thresholds. Performance investigation required."
    mime_type = "text/markdown"
  }
}

# Compliance violation alert
resource "google_monitoring_alert_policy" "compliance_violation_alert" {
  display_name = "Data Residency Compliance Violation"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Data residency violation detected"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"custom.googleapis.com/compliance/violation_count\""
      duration        = "60s"   # 1 minute
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0       # Any violation is critical
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  
  severity = "CRITICAL"
  
  alert_strategy {
    auto_close = "3600s"  # 1 hour
  }
  
  notification_channels = [
    google_monitoring_notification_channel.critical_email.id,
    google_monitoring_notification_channel.critical_slack.id,
    google_monitoring_notification_channel.critical_pagerduty.id
  ]
  
  documentation {
    content = "**CRITICAL COMPLIANCE VIOLATION DETECTED**\n\nData residency violation has been detected. Immediate investigation required to ensure regulatory compliance."
    mime_type = "text/markdown"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNELS
# ═══════════════════════════════════════════════════════════════════════════════

# Critical severity notifications
resource "google_monitoring_notification_channel" "critical_email" {
  display_name = "Critical Alerts Email"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.critical_alerts_email
  }
  
  force_delete = false
}

resource "google_monitoring_notification_channel" "critical_slack" {
  display_name = "Critical Alerts Slack"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    channel_name = var.slack_channel_critical
  }
  
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
  
  force_delete = false
}

resource "google_monitoring_notification_channel" "critical_pagerduty" {
  display_name = "Critical Alerts PagerDuty"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_service_key
  }
  
  force_delete = false
}

# Warning severity notifications
resource "google_monitoring_notification_channel" "warning_email" {
  display_name = "Warning Alerts Email"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.warning_alerts_email
  }
  
  force_delete = false
}

resource "google_monitoring_notification_channel" "warning_slack" {
  display_name = "Warning Alerts Slack"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    channel_name = var.slack_channel_warning
  }
  
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
  
  force_delete = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

# BigQuery dataset for anomaly detection ML models
resource "google_bigquery_dataset" "anomaly_detection" {
  dataset_id  = "anomaly_detection_${var.environment}"
  project     = var.project_id
  description = "Dataset for multi-region anomaly detection ML models"
  location    = "US"  # Multi-region for global data analysis
  
  # Data retention for compliance
  default_table_expiration_ms = 7776000000  # 90 days
  
  access {
    role          = "OWNER"
    user_by_email = google_service_account.anomaly_detection.email
  }
  
  labels = merge(local.common_labels, {
    data-type = "anomaly-detection"
    purpose   = "ml-analytics"
  })
}

# Anomaly detection service account
resource "google_service_account" "anomaly_detection" {
  account_id   = "anomaly-detection-${var.environment}"
  display_name = "Anomaly Detection Service Account"
  description  = "Service account for ML-powered anomaly detection"
  project      = var.project_id
}

# IAM bindings for anomaly detection
resource "google_project_iam_member" "anomaly_detection_roles" {
  for_each = toset([
    "roles/bigquery.dataEditor",
    "roles/bigquery.jobUser",
    "roles/ml.developer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.anomaly_detection.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REQUIRED SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_project_service" "required_services" {
  for_each = toset([
    "monitoring.googleapis.com",
    "logging.googleapis.com", 
    "cloudfunctions.googleapis.com",
    "cloudtrace.googleapis.com",
    "bigquery.googleapis.com",
    "ml.googleapis.com",
    "compute.googleapis.com"
  ])
  
  project = var.project_id
  service = each.value
  
  disable_dependent_services = false
}

# Reference existing services
resource "google_project_service" "cloudfunctions" {
  project = var.project_id
  service = "cloudfunctions.googleapis.com"
  
  disable_dependent_services = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "monitoring_workspace" {
  description = "Multi-region monitoring workspace configuration"
  value = {
    workspace_id = google_monitoring_workspace.multi_region_workspace.workspace_id
    name         = google_monitoring_workspace.multi_region_workspace.name
  }
}

output "health_checks" {
  description = "Regional health check configurations"
  value = {
    global_health_check = google_compute_health_check.multi_region_health_check.name
    regional_uptime_checks = {
      for region, check in google_monitoring_uptime_check_config.regional_uptime_checks : region => {
        name         = check.name
        display_name = check.display_name
      }
    }
    cross_region_latency_checks = {
      for key, check in google_monitoring_uptime_check_config.cross_region_latency_checks : key => {
        name         = check.name
        display_name = check.display_name
      }
    }
  }
}

output "compliance_monitoring" {
  description = "Compliance monitoring configuration"
  value = {
    function_name       = google_cloudfunctions2_function.compliance_monitor.name
    service_account     = google_service_account.compliance_monitor.email
    monitoring_zones    = local.monitoring_strategy.compliance_zones
  }
  sensitive = true
}

output "slo_configurations" {
  description = "SLO and SLI configurations"
  value = {
    regional_slos = {
      for region, slo in google_monitoring_slo.regional_availability_slo : region => {
        slo_id = slo.slo_id
        goal   = slo.goal
      }
    }
    global_slo = {
      slo_id = google_monitoring_slo.global_availability_slo.slo_id
      goal   = google_monitoring_slo.global_availability_slo.goal
    }
    sli_slo_config = local.monitoring_strategy.sli_slo_config
  }
}

output "alert_policies" {
  description = "Alert policy configurations"
  value = {
    regional_failure_alerts = {
      for region, alert in google_monitoring_alert_policy.regional_failure_alert : region => alert.name
    }
    cross_region_latency_alert = google_monitoring_alert_policy.cross_region_latency_alert.name
    compliance_violation_alert = google_monitoring_alert_policy.compliance_violation_alert.name
  }
}

output "notification_channels" {
  description = "Notification channel configurations"
  value = {
    critical = {
      email     = google_monitoring_notification_channel.critical_email.name
      slack     = google_monitoring_notification_channel.critical_slack.name
      pagerduty = google_monitoring_notification_channel.critical_pagerduty.name
    }
    warning = {
      email = google_monitoring_notification_channel.warning_email.name
      slack = google_monitoring_notification_channel.warning_slack.name
    }
  }
  sensitive = true
}

output "anomaly_detection" {
  description = "Anomaly detection infrastructure"
  value = {
    bigquery_dataset    = google_bigquery_dataset.anomaly_detection.dataset_id
    service_account     = google_service_account.anomaly_detection.email
  }
}

output "monitoring_strategy" {
  description = "Complete monitoring strategy configuration"
  value = {
    deployment_model    = local.monitoring_strategy.deployment_model
    active_regions      = local.monitoring_strategy.active_regions
    backup_regions      = local.monitoring_strategy.backup_regions
    sli_slo_config      = local.monitoring_strategy.sli_slo_config
    health_checks       = local.monitoring_strategy.health_checks
    compliance_zones    = local.monitoring_strategy.compliance_zones
    alerting           = local.monitoring_strategy.alerting
  }
}