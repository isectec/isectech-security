# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH INTELLIGENT ALERTING SYSTEM
# Region-aware alerting with correlation and business impact assessment
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
# INTELLIGENT ALERTING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Alerting strategy configuration
  alerting_strategy = {
    # Business impact classification
    business_impact_levels = {
      critical = {
        description = "Service completely unavailable or major security breach"
        response_time_minutes = 5
        escalation_levels = ["sre-oncall", "engineering-manager", "cto"]
        notification_channels = ["pagerduty", "slack-critical", "email-critical", "sms"]
        auto_escalation_minutes = 15
      }
      
      high = {
        description = "Significant service degradation affecting multiple regions"
        response_time_minutes = 15
        escalation_levels = ["sre-oncall", "engineering-manager"]
        notification_channels = ["pagerduty", "slack-high", "email-high"]
        auto_escalation_minutes = 30
      }
      
      medium = {
        description = "Service degradation in single region or minor compliance issues"
        response_time_minutes = 30
        escalation_levels = ["sre-oncall"]
        notification_channels = ["slack-medium", "email-medium"]
        auto_escalation_minutes = 60
      }
      
      low = {
        description = "Minor issues or capacity warnings"
        response_time_minutes = 60
        escalation_levels = ["sre-oncall"]
        notification_channels = ["slack-low", "email-low"]
        auto_escalation_minutes = 240
      }
    }
    
    # Regional weighting for business impact calculation
    regional_business_impact = {
      "us-central1" = {
        traffic_weight = 0.40
        customer_count_percentage = 45
        revenue_percentage = 42
        compliance_zone = "ccpa"
        priority_multiplier = 1.0
      }
      "europe-west4" = {
        traffic_weight = 0.30
        customer_count_percentage = 35
        revenue_percentage = 38
        compliance_zone = "gdpr"
        priority_multiplier = 1.2  # Higher due to strict GDPR requirements
      }
      "asia-northeast1" = {
        traffic_weight = 0.30
        customer_count_percentage = 20
        revenue_percentage = 20
        compliance_zone = "appi"
        priority_multiplier = 1.0
      }
      "us-east1" = {
        traffic_weight = 0.0  # Backup region
        customer_count_percentage = 0
        revenue_percentage = 0
        compliance_zone = "ccpa"
        priority_multiplier = 0.5
      }
      "europe-west1" = {
        traffic_weight = 0.0  # Backup region
        customer_count_percentage = 0
        revenue_percentage = 0
        compliance_zone = "gdpr"
        priority_multiplier = 0.5
      }
    }
    
    # Alert correlation rules
    correlation_rules = {
      regional_failure = {
        description = "Correlate multiple failures within same region"
        time_window_minutes = 10
        minimum_alerts = 2
        correlation_tags = ["region", "availability_zone"]
        suppress_individual_alerts = true
        create_incident = true
      }
      
      cross_region_impact = {
        description = "Correlate failures affecting multiple regions"
        time_window_minutes = 15
        minimum_alerts = 2
        correlation_tags = ["service_type", "component"]
        suppress_individual_alerts = false
        create_incident = true
        escalate_immediately = true
      }
      
      compliance_cascade = {
        description = "Correlate compliance violations with service issues"
        time_window_minutes = 5
        minimum_alerts = 1
        correlation_tags = ["compliance_zone"]
        suppress_individual_alerts = false
        create_incident = true
        escalate_immediately = true
      }
    }
    
    # Automated response actions
    automated_responses = {
      regional_failover = {
        triggers = ["regional_availability_critical", "database_unavailable"]
        actions = ["dns_failover", "traffic_rerouting", "incident_creation"]
        confirmation_required = false
        rollback_after_minutes = 60
      }
      
      capacity_scaling = {
        triggers = ["high_cpu_utilization", "high_memory_usage", "request_queue_depth"]
        actions = ["auto_scale_up", "alert_capacity_team"]
        confirmation_required = false
        rollback_after_minutes = 30
      }
      
      compliance_lockdown = {
        triggers = ["compliance_violation_critical"]
        actions = ["data_access_lockdown", "audit_log_collection", "compliance_team_notification"]
        confirmation_required = true
        rollback_after_minutes = 0  # Manual rollback only
      }
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL AVAILABILITY ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional service unavailable - Critical business impact
resource "google_monitoring_alert_policy" "regional_service_unavailable" {
  for_each = local.alerting_strategy.regional_business_impact
  
  display_name = "Regional Service Unavailable - ${each.key}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Service completely unavailable in ${each.key}"
    
    condition_threshold {
      filter          = "resource.type=\"uptime_url\" AND resource.label.host=~\".*${each.key}.*\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_LT"
      threshold_value = 1  # No successful checks
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_FRACTION_TRUE"
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
  
  severity = "CRITICAL"
  
  # Calculate business impact for notification priority
  alert_strategy {
    auto_close = "3600s"  # 1 hour
    
    notification_rate_limit {
      period = "300s"  # 5 minutes between notifications
    }
  }
  
  notification_channels = [
    google_monitoring_notification_channel.pagerduty_critical.id,
    google_monitoring_notification_channel.slack_critical.id,
    google_monitoring_notification_channel.sre_critical_email.id
  ]
  
  documentation {
    content = templatefile("${path.module}/alert-runbooks/regional-service-unavailable.md", {
      region = each.key
      traffic_weight = each.value.traffic_weight
      customer_percentage = each.value.customer_count_percentage
      compliance_zone = each.value.compliance_zone
    })
    mime_type = "text/markdown"
  }
  
  # Custom labels for alert routing and correlation
  user_labels = {
    severity = "critical"
    region = each.key
    business_impact = "high"
    compliance_zone = each.value.compliance_zone
    traffic_weight = tostring(each.value.traffic_weight)
    alert_type = "availability"
    component = "regional_service"
    auto_escalate = "true"
  }
}

# Regional service degraded - High business impact
resource "google_monitoring_alert_policy" "regional_service_degraded" {
  for_each = local.alerting_strategy.regional_business_impact
  
  display_name = "Regional Service Degraded - ${each.key}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Service partially degraded in ${each.key}"
    
    condition_threshold {
      filter          = "resource.type=\"uptime_url\" AND resource.label.host=~\".*${each.key}.*\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      duration        = "900s"  # 15 minutes
      comparison      = "COMPARISON_LT"
      threshold_value = 0.9  # Less than 90% success rate
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        
        group_by_fields = [
          "resource.label.host"
        ]
      }
    }
  }
  
  conditions {
    display_name = "High latency in ${each.key}"
    
    condition_threshold {
      filter          = "resource.type=\"http_load_balancer\" AND resource.label.backend_target_name=~\".*${each.key}.*\" AND metric.type=\"loadbalancing.googleapis.com/https/total_latencies\""
      duration        = "600s"  # 10 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 2000  # 2 seconds
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_PERCENTILE_95"
        cross_series_reducer = "REDUCE_MEAN"
        
        group_by_fields = [
          "resource.label.backend_target_name"
        ]
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.slack_high.id,
    google_monitoring_notification_channel.sre_alerts_email.id
  ]
  
  documentation {
    content = templatefile("${path.module}/alert-runbooks/regional-service-degraded.md", {
      region = each.key
      traffic_weight = each.value.traffic_weight
      compliance_zone = each.value.compliance_zone
    })
    mime_type = "text/markdown"
  }
  
  user_labels = {
    severity = "warning"
    region = each.key
    business_impact = "medium"
    compliance_zone = each.value.compliance_zone
    alert_type = "performance"
    component = "regional_service"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE AVAILABILITY ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Database unavailable - Critical impact
resource "google_monitoring_alert_policy" "database_unavailable" {
  for_each = toset(["us-central1", "europe-west4", "asia-northeast1"])
  
  display_name = "Database Unavailable - ${each.value}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Primary database unavailable"
    
    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\" AND resource.label.region=\"${each.value}\" AND metric.type=\"cloudsql.googleapis.com/database/up\""
      duration        = "180s"  # 3 minutes
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MIN"
        
        group_by_fields = [
          "resource.label.database_id"
        ]
      }
    }
  }
  
  conditions {
    display_name = "Database connection failures"
    
    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\" AND resource.label.region=\"${each.value}\" AND metric.type=\"cloudsql.googleapis.com/database/network/connections\""
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  
  severity = "CRITICAL"
  
  notification_channels = [
    google_monitoring_notification_channel.pagerduty_critical.id,
    google_monitoring_notification_channel.slack_critical.id,
    google_monitoring_notification_channel.dba_team_email.id
  ]
  
  documentation {
    content = templatefile("${path.module}/alert-runbooks/database-unavailable.md", {
      region = each.value
      compliance_zone = local.alerting_strategy.regional_business_impact[each.value].compliance_zone
    })
    mime_type = "text/markdown"
  }
  
  user_labels = {
    severity = "critical"
    region = each.value
    business_impact = "critical"
    alert_type = "availability"
    component = "database"
    auto_failover = "enabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE VIOLATION ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Data residency violation - Critical compliance impact
resource "google_monitoring_alert_policy" "compliance_data_residency_violation" {
  display_name = "Data Residency Compliance Violation"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Cross-region data transfer detected"
    
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/compliance/violation_count\" AND metric.label.violation_type=\"location_compliance\""
      duration        = "60s"   # 1 minute - immediate response required
      comparison      = "COMPARISON_GT"
      threshold_value = 0       # Zero tolerance
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        
        group_by_fields = [
          "metric.label.regulation",
          "metric.label.compliance_zone"
        ]
      }
    }
  }
  
  conditions {
    display_name = "PII detected in wrong region"
    
    condition_threshold {
      filter          = "metric.type=\"custom.googleapis.com/compliance/violation_count\" AND metric.label.violation_type=\"pii_exposure\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        
        group_by_fields = [
          "metric.label.regulation",
          "metric.label.compliance_zone"
        ]
      }
    }
  }
  
  severity = "CRITICAL"
  
  alert_strategy {
    auto_close = "0s"  # Manual resolution required
  }
  
  notification_channels = [
    google_monitoring_notification_channel.compliance_critical.id,
    google_monitoring_notification_channel.legal_team.id,
    google_monitoring_notification_channel.ciso_escalation.id,
    google_monitoring_notification_channel.pagerduty_critical.id
  ]
  
  documentation {
    content = file("${path.module}/alert-runbooks/compliance-violation-critical.md")
    mime_type = "text/markdown"
  }
  
  user_labels = {
    severity = "critical"
    business_impact = "critical"
    alert_type = "compliance"
    component = "data_residency"
    requires_legal_review = "true"
    auto_escalate = "immediate"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-REGION LATENCY ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# High cross-region latency
resource "google_monitoring_alert_policy" "cross_region_latency_high" {
  display_name = "High Cross-Region Latency"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Cross-region request latency exceeded"
    
    condition_threshold {
      filter          = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/time_until_ssl_cert_expires\""
      duration        = "900s"  # 15 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 2000    # 2 seconds
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_PERCENTILE_95"
        cross_series_reducer = "REDUCE_MAX"
        
        group_by_fields = [
          "resource.label.host"
        ]
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.network_team.id,
    google_monitoring_notification_channel.slack_medium.id
  ]
  
  documentation {
    content = file("${path.module}/alert-runbooks/cross-region-latency.md")
    mime_type = "text/markdown"
  }
  
  user_labels = {
    severity = "warning"
    business_impact = "medium"
    alert_type = "performance"
    component = "network"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CAPACITY PLANNING ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional capacity threshold
resource "google_monitoring_alert_policy" "regional_capacity_threshold" {
  for_each = toset(["us-central1", "europe-west4", "asia-northeast1"])
  
  display_name = "Regional Capacity Threshold - ${each.value}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "CPU utilization high"
    
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.value}-.*\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "600s"  # 10 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 0.8     # 80% CPU utilization
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        
        group_by_fields = [
          "resource.label.zone"
        ]
      }
    }
  }
  
  conditions {
    display_name = "Memory utilization high"
    
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND resource.label.zone=~\"${each.value}-.*\" AND metric.type=\"agent.googleapis.com/memory/percent_used\""
      duration        = "600s"
      comparison      = "COMPARISON_GT"
      threshold_value = 85      # 85% memory utilization
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
        
        group_by_fields = [
          "resource.label.zone"
        ]
      }
    }
  }
  
  severity = "WARNING"
  
  notification_channels = [
    google_monitoring_notification_channel.capacity_team.id,
    google_monitoring_notification_channel.slack_medium.id
  ]
  
  documentation {
    content = templatefile("${path.module}/alert-runbooks/capacity-threshold.md", {
      region = each.value
    })
    mime_type = "text/markdown"
  }
  
  user_labels = {
    severity = "warning"
    region = each.value
    business_impact = "medium"
    alert_type = "capacity"
    component = "compute"
    auto_scale = "enabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CHANNELS
# ═══════════════════════════════════════════════════════════════════════════════

# Critical severity channels
resource "google_monitoring_notification_channel" "pagerduty_critical" {
  display_name = "PagerDuty Critical"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_critical_service_key
  }
  
  enabled = var.enable_pagerduty
}

resource "google_monitoring_notification_channel" "slack_critical" {
  display_name = "Slack Critical Alerts"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    channel_name = "#sre-critical"
  }
  
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
}

resource "google_monitoring_notification_channel" "sre_critical_email" {
  display_name = "SRE Critical Email"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "sre-critical@isectech.org"
  }
}

# High severity channels
resource "google_monitoring_notification_channel" "slack_high" {
  display_name = "Slack High Priority"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    channel_name = "#sre-high-priority"
  }
  
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
}

# Medium severity channels  
resource "google_monitoring_notification_channel" "slack_medium" {
  display_name = "Slack Medium Priority"
  type         = "slack"
  project      = var.project_id
  
  labels = {
    channel_name = "#sre-alerts"
  }
  
  sensitive_labels {
    auth_token = var.slack_auth_token
  }
}

# Team-specific channels
resource "google_monitoring_notification_channel" "compliance_critical" {
  display_name = "Compliance Team Critical"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "compliance-critical@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "legal_team" {
  display_name = "Legal Team Notifications"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "legal-alerts@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "ciso_escalation" {
  display_name = "CISO Escalation"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "ciso@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "dba_team_email" {
  display_name = "Database Team"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "dba-alerts@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "network_team" {
  display_name = "Network Team"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "network-alerts@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "capacity_team" {
  display_name = "Capacity Planning Team"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "capacity-planning@isectech.org"
  }
}

resource "google_monitoring_notification_channel" "sre_alerts_email" {
  display_name = "SRE General Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.warning_alerts_email
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "alerting_configuration" {
  description = "Comprehensive alerting configuration"
  value = {
    strategy = local.alerting_strategy
    
    alert_policies = {
      regional_service_unavailable = {
        for region, policy in google_monitoring_alert_policy.regional_service_unavailable : region => {
          name = policy.name
          severity = "CRITICAL"
          business_impact = local.alerting_strategy.regional_business_impact[region]
        }
      }
      
      regional_service_degraded = {
        for region, policy in google_monitoring_alert_policy.regional_service_degraded : region => {
          name = policy.name
          severity = "WARNING"
        }
      }
      
      database_unavailable = {
        for region, policy in google_monitoring_alert_policy.database_unavailable : region => {
          name = policy.name
          severity = "CRITICAL"
        }
      }
      
      compliance_violation = google_monitoring_alert_policy.compliance_data_residency_violation.name
      cross_region_latency = google_monitoring_alert_policy.cross_region_latency_high.name
      
      capacity_threshold = {
        for region, policy in google_monitoring_alert_policy.regional_capacity_threshold : region => {
          name = policy.name
          severity = "WARNING"
        }
      }
    }
    
    notification_channels = {
      critical = {
        pagerduty = google_monitoring_notification_channel.pagerduty_critical.name
        slack = google_monitoring_notification_channel.slack_critical.name
        email = google_monitoring_notification_channel.sre_critical_email.name
      }
      compliance = {
        email = google_monitoring_notification_channel.compliance_critical.name
        legal = google_monitoring_notification_channel.legal_team.name
        ciso = google_monitoring_notification_channel.ciso_escalation.name
      }
      teams = {
        database = google_monitoring_notification_channel.dba_team_email.name
        network = google_monitoring_notification_channel.network_team.name
        capacity = google_monitoring_notification_channel.capacity_team.name
      }
    }
  }
  sensitive = true
}