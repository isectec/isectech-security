# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH MULTI-REGION MONITORING VARIABLES
# Variable definitions for multi-region monitoring infrastructure
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.9 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "GCP Project ID for multi-region deployment"
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID cannot be empty."
  }
}

variable "org_id" {
  description = "GCP Organization ID (required for dedicated monitoring project)"
  type        = string
  default     = ""
}

variable "billing_account" {
  description = "GCP Billing Account ID (required for dedicated monitoring project)"
  type        = string
  default     = ""
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "domain_name" {
  description = "Primary domain name for the application"
  type        = string
  default     = "isectech.org."
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "create_dedicated_monitoring_project" {
  description = "Create dedicated monitoring project for centralized observability"
  type        = bool
  default     = false
}

variable "monitoring_retention_days" {
  description = "Number of days to retain monitoring data"
  type        = number
  default     = 90
  
  validation {
    condition     = var.monitoring_retention_days >= 30 && var.monitoring_retention_days <= 3650
    error_message = "Monitoring retention must be between 30 and 3650 days."
  }
}

variable "health_check_frequency_seconds" {
  description = "Frequency of health checks in seconds"
  type        = number
  default     = 30
  
  validation {
    condition     = var.health_check_frequency_seconds >= 10 && var.health_check_frequency_seconds <= 300
    error_message = "Health check frequency must be between 10 and 300 seconds."
  }
}

variable "compliance_scan_frequency_minutes" {
  description = "Frequency of compliance scans in minutes"
  type        = number
  default     = 60
  
  validation {
    condition     = var.compliance_scan_frequency_minutes >= 15 && var.compliance_scan_frequency_minutes <= 1440
    error_message = "Compliance scan frequency must be between 15 minutes and 24 hours."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLI/SLO CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "global_availability_target" {
  description = "Global availability SLO target percentage"
  type        = number
  default     = 99.95
  
  validation {
    condition     = var.global_availability_target >= 95.0 && var.global_availability_target <= 100.0
    error_message = "Global availability target must be between 95% and 100%."
  }
}

variable "regional_availability_target" {
  description = "Regional availability SLO target percentage"
  type        = number
  default     = 99.9
  
  validation {
    condition     = var.regional_availability_target >= 95.0 && var.regional_availability_target <= 100.0
    error_message = "Regional availability target must be between 95% and 100%."
  }
}

variable "latency_p95_target_ms" {
  description = "95th percentile latency SLO target in milliseconds"
  type        = number
  default     = 500
  
  validation {
    condition     = var.latency_p95_target_ms >= 100 && var.latency_p95_target_ms <= 5000
    error_message = "P95 latency target must be between 100ms and 5000ms."
  }
}

variable "latency_p99_target_ms" {
  description = "99th percentile latency SLO target in milliseconds"
  type        = number
  default     = 1000
  
  validation {
    condition     = var.latency_p99_target_ms >= 200 && var.latency_p99_target_ms <= 10000
    error_message = "P99 latency target must be between 200ms and 10000ms."
  }
}

variable "error_rate_target_percentage" {
  description = "Error rate SLO target percentage (maximum allowed error rate)"
  type        = number
  default     = 0.1
  
  validation {
    condition     = var.error_rate_target_percentage >= 0.0 && var.error_rate_target_percentage <= 5.0
    error_message = "Error rate target must be between 0% and 5%."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "critical_alerts_email" {
  description = "Email address for critical alerts"
  type        = string
  default     = "sre-critical@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.critical_alerts_email))
    error_message = "Critical alerts email must be a valid email address."
  }
}

variable "warning_alerts_email" {
  description = "Email address for warning alerts"
  type        = string
  default     = "sre-warnings@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.warning_alerts_email))
    error_message = "Warning alerts email must be a valid email address."
  }
}

variable "operations_email" {
  description = "Email address for operations notifications"
  type        = string
  default     = "operations@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.operations_email))
    error_message = "Operations email must be a valid email address."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLACK CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "slack_auth_token" {
  description = "Slack authentication token for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_channel_critical" {
  description = "Slack channel for critical alerts"
  type        = string
  default     = "#sre-critical"
}

variable "slack_channel_warning" {
  description = "Slack channel for warning alerts"
  type        = string
  default     = "#sre-alerts"
}

variable "slack_channel_operations" {
  description = "Slack channel for operational notifications"
  type        = string
  default     = "#operations"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PAGERDUTY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "pagerduty_service_key" {
  description = "PagerDuty service key for critical alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_pagerduty" {
  description = "Enable PagerDuty notifications for critical alerts"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_gdpr_monitoring" {
  description = "Enable GDPR compliance monitoring for European regions"
  type        = bool
  default     = true
}

variable "enable_ccpa_monitoring" {
  description = "Enable CCPA compliance monitoring for US regions"
  type        = bool
  default     = true
}

variable "enable_appi_monitoring" {
  description = "Enable APPI compliance monitoring for Asia-Pacific regions"
  type        = bool
  default     = true
}

variable "compliance_violation_threshold" {
  description = "Number of compliance violations before triggering critical alert"
  type        = number
  default     = 1
  
  validation {
    condition     = var.compliance_violation_threshold >= 1 && var.compliance_violation_threshold <= 100
    error_message = "Compliance violation threshold must be between 1 and 100."
  }
}

variable "pii_scan_sample_size" {
  description = "Number of objects to sample for PII scanning per bucket"
  type        = number
  default     = 100
  
  validation {
    condition     = var.pii_scan_sample_size >= 10 && var.pii_scan_sample_size <= 1000
    error_message = "PII scan sample size must be between 10 and 1000."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_security_scanning" {
  description = "Enable security vulnerability scanning of monitoring infrastructure"
  type        = bool
  default     = true
}

variable "encryption_key_rotation_days" {
  description = "Number of days between encryption key rotations"
  type        = number
  default     = 90
  
  validation {
    condition     = var.encryption_key_rotation_days >= 30 && var.encryption_key_rotation_days <= 365
    error_message = "Key rotation period must be between 30 and 365 days."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_anomaly_detection" {
  description = "Enable ML-powered anomaly detection"
  type        = bool
  default     = true
}

variable "anomaly_detection_sensitivity" {
  description = "Sensitivity level for anomaly detection (low, medium, high)"
  type        = string
  default     = "medium"
  
  validation {
    condition     = contains(["low", "medium", "high"], var.anomaly_detection_sensitivity)
    error_message = "Anomaly detection sensitivity must be one of: low, medium, high."
  }
}

variable "anomaly_detection_window_minutes" {
  description = "Time window for anomaly detection in minutes"
  type        = number
  default     = 15
  
  validation {
    condition     = var.anomaly_detection_window_minutes >= 5 && var.anomaly_detection_window_minutes <= 60
    error_message = "Anomaly detection window must be between 5 and 60 minutes."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CAPACITY PLANNING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_capacity_planning" {
  description = "Enable automated capacity planning analysis"
  type        = bool
  default     = true
}

variable "capacity_forecast_days" {
  description = "Number of days to forecast capacity needs"
  type        = number
  default     = 30
  
  validation {
    condition     = var.capacity_forecast_days >= 7 && var.capacity_forecast_days <= 90
    error_message = "Capacity forecast period must be between 7 and 90 days."
  }
}

variable "capacity_threshold_percentage" {
  description = "Capacity utilization threshold for alerts (percentage)"
  type        = number
  default     = 80
  
  validation {
    condition     = var.capacity_threshold_percentage >= 50 && var.capacity_threshold_percentage <= 95
    error_message = "Capacity threshold must be between 50% and 95%."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED TRACING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_distributed_tracing" {
  description = "Enable distributed tracing across regions"
  type        = bool
  default     = true
}

variable "trace_sampling_rate" {
  description = "Sampling rate for distributed tracing (0.0 to 1.0)"
  type        = number
  default     = 0.1
  
  validation {
    condition     = var.trace_sampling_rate >= 0.0 && var.trace_sampling_rate <= 1.0
    error_message = "Trace sampling rate must be between 0.0 and 1.0."
  }
}

variable "trace_retention_days" {
  description = "Number of days to retain trace data"
  type        = number
  default     = 7
  
  validation {
    condition     = var.trace_retention_days >= 1 && var.trace_retention_days <= 30
    error_message = "Trace retention must be between 1 and 30 days."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_cost_optimization" {
  description = "Enable cost optimization for monitoring infrastructure"
  type        = bool
  default     = true
}

variable "cost_budget_amount_usd" {
  description = "Monthly cost budget for monitoring in USD"
  type        = number
  default     = 500
  
  validation {
    condition     = var.cost_budget_amount_usd >= 100 && var.cost_budget_amount_usd <= 10000
    error_message = "Cost budget must be between $100 and $10,000 USD per month."
  }
}

variable "cost_alert_threshold_percentage" {
  description = "Cost threshold percentage for budget alerts"
  type        = number
  default     = 80
  
  validation {
    condition     = var.cost_alert_threshold_percentage >= 50 && var.cost_alert_threshold_percentage <= 100
    error_message = "Cost alert threshold must be between 50% and 100%."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "active_regions" {
  description = "List of active regions for monitoring"
  type        = list(string)
  default     = ["us-central1", "europe-west4", "asia-northeast1"]
  
  validation {
    condition     = length(var.active_regions) >= 2 && length(var.active_regions) <= 10
    error_message = "Must specify between 2 and 10 active regions."
  }
}

variable "backup_regions" {
  description = "List of backup regions for disaster recovery"
  type        = list(string)
  default     = ["us-east1", "europe-west1"]
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMMON LABELS
# ═══════════════════════════════════════════════════════════════════════════════

variable "common_labels" {
  description = "Common labels to apply to all monitoring resources"
  type        = map(string)
  default = {
    project      = "isectech"
    component    = "monitoring"
    managed-by   = "terraform"
    environment  = "production"
    team         = "sre"
    purpose      = "multi-region-monitoring"
    compliance   = "gdpr-ccpa-appi"
  }
}

# Make common_labels available as local
locals {
  common_labels = merge(var.common_labels, {
    environment = var.environment
  })
}