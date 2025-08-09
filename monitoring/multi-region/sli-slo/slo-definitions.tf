# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH SLI/SLO DEFINITIONS FOR MULTI-REGION DEPLOYMENT
# Service Level Indicators and Objectives for Regional Hybrid model
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.9 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLI/SLO CONFIGURATION LOCALS
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # SLI/SLO definitions aligned with business requirements
  sli_slo_definitions = {
    # Global service availability SLO - 99.95% uptime
    global_availability = {
      name = "Global Service Availability"
      description = "Overall availability of iSECTECH platform across all regions"
      slo_target = 0.9995  # 99.95%
      measurement_window_days = 28
      
      # Error budget calculations
      error_budget_minutes_per_28_days = 20.16  # 0.05% of 28 days
      burn_rate_thresholds = {
        page_immediately = 14.4   # 1h to burn 5% of error budget
        page_soon = 6.0          # 6h to burn 10% of error budget  
        ticket = 1.0             # 3d to burn 100% of error budget
      }
      
      # SLI definition
      sli = {
        type = "availability"
        good_service_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\" AND metric.label.response_code_class!=\"5xx\""
        total_service_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\""
      }
    }
    
    # Regional availability SLOs - 99.9% uptime per region
    regional_availability = {
      name = "Regional Service Availability"
      description = "Availability of services within individual regions"
      slo_target = 0.999  # 99.9%
      measurement_window_days = 28
      
      error_budget_minutes_per_28_days = 40.32  # 0.1% of 28 days
      burn_rate_thresholds = {
        page_immediately = 14.4
        page_soon = 6.0
        ticket = 1.0
      }
      
      sli = {
        type = "availability"
        good_service_filter = "resource.type=\"gce_instance\" AND metric.type=\"compute.googleapis.com/instance/up\""
        total_service_filter = "resource.type=\"gce_instance\""
      }
    }
    
    # API response latency SLO - 95% of requests < 500ms
    api_latency_p95 = {
      name = "API Response Latency P95"
      description = "95th percentile API response latency"
      slo_target = 0.95  # 95% of requests
      latency_threshold_ms = 500
      measurement_window_days = 7  # Weekly measurement for latency
      
      sli = {
        type = "latency"
        distribution_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/total_latencies\""
        threshold_ms = 500
      }
    }
    
    # API response latency SLO - 99% of requests < 1000ms
    api_latency_p99 = {
      name = "API Response Latency P99"
      description = "99th percentile API response latency"
      slo_target = 0.99  # 99% of requests
      latency_threshold_ms = 1000
      measurement_window_days = 7
      
      sli = {
        type = "latency"
        distribution_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/total_latencies\""
        threshold_ms = 1000
      }
    }
    
    # Error rate SLO - 99.9% success rate
    error_rate = {
      name = "API Error Rate"
      description = "Percentage of successful API requests"
      slo_target = 0.999  # 99.9% success rate (0.1% error rate)
      measurement_window_days = 7
      
      sli = {
        type = "availability" 
        good_service_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\" AND metric.label.response_code_class=\"2xx\""
        total_service_filter = "resource.type=\"http_load_balancer\" AND metric.type=\"loadbalancing.googleapis.com/https/request_count\""
      }
    }
    
    # Database availability SLO per region
    database_availability = {
      name = "Database Availability"
      description = "Availability of database services per region"
      slo_target = 0.999  # 99.9%
      measurement_window_days = 28
      
      sli = {
        type = "availability"
        good_service_filter = "resource.type=\"cloudsql_database\" AND metric.type=\"cloudsql.googleapis.com/database/up\""
        total_service_filter = "resource.type=\"cloudsql_database\""
      }
    }
    
    # Cross-region replication lag SLO
    replication_lag = {
      name = "Cross-Region Replication Lag"
      description = "Replication lag between regions"
      slo_target = 0.95  # 95% of time lag < 60 seconds
      lag_threshold_seconds = 60
      measurement_window_days = 7
      
      sli = {
        type = "latency"
        distribution_filter = "metric.type=\"custom.googleapis.com/replication/lag_seconds\""
        threshold_seconds = 60
      }
    }
    
    # Compliance monitoring SLO
    compliance_violations = {
      name = "Compliance Violations"
      description = "Data residency compliance violations"
      slo_target = 1.0  # 100% compliant (zero violations)
      measurement_window_days = 1  # Daily compliance check
      
      sli = {
        type = "availability"
        good_service_filter = "metric.type=\"custom.googleapis.com/compliance/violation_count\" AND metric.value=0"
        total_service_filter = "metric.type=\"custom.googleapis.com/compliance/violation_count\""
      }
    }
  }
  
  # Regional SLO configurations
  regional_slos = {
    for region in ["us-central1", "europe-west4", "asia-northeast1"] : region => {
      availability_target = 0.999
      latency_p95_ms = 200  # Lower latency within region
      latency_p99_ms = 500
      error_rate_target = 0.999
      compliance_zone = {
        "us-central1" = "ccpa"
        "europe-west4" = "gdpr"
        "asia-northeast1" = "appi"
      }[region]
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL SLO CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Global availability SLO
resource "google_monitoring_slo" "global_availability" {
  slo_id       = "global-availability-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.global_lb_service.service_id}"
  display_name = local.sli_slo_definitions.global_availability.name
  
  goal                = local.sli_slo_definitions.global_availability.slo_target
  rolling_period_days = local.sli_slo_definitions.global_availability.measurement_window_days
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = local.sli_slo_definitions.global_availability.sli.total_service_filter
      good_service_filter  = local.sli_slo_definitions.global_availability.sli.good_service_filter
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.global_lb_service]
}

# API latency P95 SLO
resource "google_monitoring_slo" "api_latency_p95" {
  slo_id       = "api-latency-p95-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.api_service.service_id}"
  display_name = local.sli_slo_definitions.api_latency_p95.name
  
  goal                = local.sli_slo_definitions.api_latency_p95.slo_target
  rolling_period_days = local.sli_slo_definitions.api_latency_p95.measurement_window_days
  
  request_based_sli {
    distribution_cut {
      distribution_filter = local.sli_slo_definitions.api_latency_p95.sli.distribution_filter
      
      range {
        max = local.sli_slo_definitions.api_latency_p95.sli.threshold_ms
      }
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.api_service]
}

# API latency P99 SLO
resource "google_monitoring_slo" "api_latency_p99" {
  slo_id       = "api-latency-p99-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.api_service.service_id}"
  display_name = local.sli_slo_definitions.api_latency_p99.name
  
  goal                = local.sli_slo_definitions.api_latency_p99.slo_target
  rolling_period_days = local.sli_slo_definitions.api_latency_p99.measurement_window_days
  
  request_based_sli {
    distribution_cut {
      distribution_filter = local.sli_slo_definitions.api_latency_p99.sli.distribution_filter
      
      range {
        max = local.sli_slo_definitions.api_latency_p99.sli.threshold_ms
      }
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.api_service]
}

# Error rate SLO
resource "google_monitoring_slo" "error_rate" {
  slo_id       = "error-rate-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.api_service.service_id}"
  display_name = local.sli_slo_definitions.error_rate.name
  
  goal                = local.sli_slo_definitions.error_rate.slo_target
  rolling_period_days = local.sli_slo_definitions.error_rate.measurement_window_days
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = local.sli_slo_definitions.error_rate.sli.total_service_filter
      good_service_filter  = local.sli_slo_definitions.error_rate.sli.good_service_filter
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.api_service]
}

# Compliance violations SLO (zero tolerance)
resource "google_monitoring_slo" "compliance_violations" {
  slo_id       = "compliance-violations-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.compliance_service.service_id}"
  display_name = local.sli_slo_definitions.compliance_violations.name
  
  goal                = local.sli_slo_definitions.compliance_violations.slo_target
  rolling_period_days = local.sli_slo_definitions.compliance_violations.measurement_window_days
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = local.sli_slo_definitions.compliance_violations.sli.total_service_filter
      good_service_filter  = local.sli_slo_definitions.compliance_violations.sli.good_service_filter
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.compliance_service]
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL SLO CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional availability SLOs
resource "google_monitoring_slo" "regional_availability" {
  for_each = local.regional_slos
  
  slo_id       = "regional-availability-${each.key}-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.regional_services[each.key].service_id}"
  display_name = "Regional Availability - ${each.key}"
  
  goal                = each.value.availability_target
  rolling_period_days = 28
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.key}-.*\""
      good_service_filter  = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.key}-.*\" AND metric.type=\"compute.googleapis.com/instance/up\""
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.regional_services]
}

# Regional database availability SLOs
resource "google_monitoring_slo" "regional_database_availability" {
  for_each = local.regional_slos
  
  slo_id       = "regional-db-availability-${each.key}-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.database_services[each.key].service_id}"
  display_name = "Database Availability - ${each.key}"
  
  goal                = each.value.availability_target
  rolling_period_days = 28
  
  request_based_sli {
    good_total_ratio {
      total_service_filter = "resource.type=\"cloudsql_database\" AND resource.label.region=\"${each.key}\""
      good_service_filter  = "resource.type=\"cloudsql_database\" AND resource.label.region=\"${each.key}\" AND metric.type=\"cloudsql.googleapis.com/database/up\""
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.database_services]
}

# Cross-region replication lag SLO
resource "google_monitoring_slo" "replication_lag" {
  slo_id       = "replication-lag-${var.environment}"
  service      = "projects/${var.project_id}/services/${google_monitoring_service.replication_service.service_id}"
  display_name = local.sli_slo_definitions.replication_lag.name
  
  goal                = local.sli_slo_definitions.replication_lag.slo_target
  rolling_period_days = local.sli_slo_definitions.replication_lag.measurement_window_days
  
  request_based_sli {
    distribution_cut {
      distribution_filter = local.sli_slo_definitions.replication_lag.sli.distribution_filter
      
      range {
        max = local.sli_slo_definitions.replication_lag.sli.threshold_seconds
      }
    }
  }
  
  project = var.project_id
  
  depends_on = [google_monitoring_service.replication_service]
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING SERVICES FOR SLO TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

# Global load balancer service
resource "google_monitoring_service" "global_lb_service" {
  service_id   = "global-loadbalancer-${var.environment}"
  display_name = "Global Load Balancer Service"
  
  telemetry {
    resource_name = "//compute.googleapis.com/projects/${var.project_id}/global/urlMaps/*"
  }
  
  project = var.project_id
}

# API service for latency and error rate tracking
resource "google_monitoring_service" "api_service" {
  service_id   = "api-service-${var.environment}"
  display_name = "iSECTECH API Service"
  
  telemetry {
    resource_name = "//compute.googleapis.com/projects/${var.project_id}/global/backendServices/*"
  }
  
  project = var.project_id
}

# Compliance service
resource "google_monitoring_service" "compliance_service" {
  service_id   = "compliance-service-${var.environment}"
  display_name = "Data Residency Compliance Service"
  
  telemetry {
    resource_name = "//cloudfunctions.googleapis.com/projects/${var.project_id}/locations/*/functions/compliance-monitor*"
  }
  
  project = var.project_id
}

# Regional services
resource "google_monitoring_service" "regional_services" {
  for_each = local.regional_slos
  
  service_id   = "regional-service-${each.key}-${var.environment}"
  display_name = "Regional Service - ${each.key}"
  
  telemetry {
    resource_name = "//compute.googleapis.com/projects/${var.project_id}/zones/${each.key}-*/instances/*"
  }
  
  project = var.project_id
}

# Database services per region
resource "google_monitoring_service" "database_services" {
  for_each = local.regional_slos
  
  service_id   = "database-service-${each.key}-${var.environment}"
  display_name = "Database Service - ${each.key}"
  
  telemetry {
    resource_name = "//sqladmin.googleapis.com/projects/${var.project_id}/instances/*${each.key}*"
  }
  
  project = var.project_id
}

# Replication service
resource "google_monitoring_service" "replication_service" {
  service_id   = "replication-service-${var.environment}"
  display_name = "Cross-Region Replication Service"
  
  telemetry {
    resource_name = "//cloudfunctions.googleapis.com/projects/${var.project_id}/locations/*/functions/replication-monitor*"
  }
  
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# ERROR BUDGET ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Global availability error budget burn rate alerts
resource "google_monitoring_alert_policy" "global_availability_error_budget" {
  display_name = "Global Availability Error Budget Burn Rate"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Fast error budget burn rate"
    
    condition_threshold {
      filter          = "select_slo_burn_rate(\"${google_monitoring_slo.global_availability.name}\", \"3600s\")"
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = local.sli_slo_definitions.global_availability.burn_rate_thresholds.page_immediately
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  conditions {
    display_name = "Medium error budget burn rate"
    
    condition_threshold {
      filter          = "select_slo_burn_rate(\"${google_monitoring_slo.global_availability.name}\", \"21600s\")"
      duration        = "900s"  # 15 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = local.sli_slo_definitions.global_availability.burn_rate_thresholds.page_soon
      
      aggregations {
        alignment_period   = "900s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  severity = "CRITICAL"
  
  notification_channels = [
    google_monitoring_notification_channel.sre_critical.id,
    google_monitoring_notification_channel.pagerduty.id
  ]
  
  documentation {
    content = "Global availability SLO is burning error budget rapidly. This indicates a significant service degradation affecting multiple regions."
    mime_type = "text/markdown"
  }
  
  depends_on = [google_monitoring_slo.global_availability]
}

# API latency SLO alerts  
resource "google_monitoring_alert_policy" "api_latency_slo" {
  display_name = "API Latency SLO Violation"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "API P95 latency SLO violation"
    
    condition_threshold {
      filter          = "select_slo_burn_rate(\"${google_monitoring_slo.api_latency_p95.name}\", \"3600s\")"
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 4.0  # Fast burn rate for latency
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.sre_alerts.id
  ]
  
  documentation {
    content = "API latency SLO is being violated. Response times are exceeding acceptable thresholds."
    mime_type = "text/markdown"
  }
  
  depends_on = [google_monitoring_slo.api_latency_p95]
}

# Compliance SLO alert (zero tolerance)
resource "google_monitoring_alert_policy" "compliance_slo" {
  display_name = "Compliance SLO Violation"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Data residency compliance violation"
    
    condition_threshold {
      filter          = "select_slo_burn_rate(\"${google_monitoring_slo.compliance_violations.name}\", \"60s\")"
      duration        = "60s"   # Immediate alert for compliance
      comparison      = "COMPARISON_GT"
      threshold_value = 0       # Any violation
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  severity = "CRITICAL"
  
  notification_channels = [
    google_monitoring_notification_channel.sre_critical.id,
    google_monitoring_notification_channel.compliance_team.id,
    google_monitoring_notification_channel.pagerduty.id
  ]
  
  documentation {
    content = "**CRITICAL COMPLIANCE VIOLATION**\n\nData residency compliance SLO has been violated. This indicates potential regulatory non-compliance requiring immediate investigation and remediation."
    mime_type = "text/markdown"
  }
  
  depends_on = [google_monitoring_slo.compliance_violations]
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNELS
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_monitoring_notification_channel" "sre_critical" {
  display_name = "SRE Critical Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.critical_alerts_email
  }
}

resource "google_monitoring_notification_channel" "sre_alerts" {
  display_name = "SRE General Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.warning_alerts_email
  }
}

resource "google_monitoring_notification_channel" "compliance_team" {
  display_name = "Compliance Team Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "compliance@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "pagerduty" {
  display_name = "PagerDuty Critical"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_service_key
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "slo_definitions" {
  description = "Complete SLI/SLO definitions and configurations"
  value = {
    definitions = local.sli_slo_definitions
    
    global_slos = {
      availability = {
        slo_id = google_monitoring_slo.global_availability.slo_id
        goal   = google_monitoring_slo.global_availability.goal
        name   = google_monitoring_slo.global_availability.name
      }
      api_latency_p95 = {
        slo_id = google_monitoring_slo.api_latency_p95.slo_id
        goal   = google_monitoring_slo.api_latency_p95.goal
        name   = google_monitoring_slo.api_latency_p95.name
      }
      api_latency_p99 = {
        slo_id = google_monitoring_slo.api_latency_p99.slo_id
        goal   = google_monitoring_slo.api_latency_p99.goal
        name   = google_monitoring_slo.api_latency_p99.name
      }
      error_rate = {
        slo_id = google_monitoring_slo.error_rate.slo_id
        goal   = google_monitoring_slo.error_rate.goal
        name   = google_monitoring_slo.error_rate.name
      }
      compliance = {
        slo_id = google_monitoring_slo.compliance_violations.slo_id
        goal   = google_monitoring_slo.compliance_violations.goal
        name   = google_monitoring_slo.compliance_violations.name
      }
    }
    
    regional_slos = {
      for region, slo in google_monitoring_slo.regional_availability : region => {
        slo_id = slo.slo_id
        goal   = slo.goal
        name   = slo.name
      }
    }
    
    alert_policies = {
      global_availability_error_budget = google_monitoring_alert_policy.global_availability_error_budget.name
      api_latency_slo = google_monitoring_alert_policy.api_latency_slo.name
      compliance_slo = google_monitoring_alert_policy.compliance_slo.name
    }
  }
}