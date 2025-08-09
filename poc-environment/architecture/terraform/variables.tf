# iSECTECH POC Environment - Terraform Variables
# Production-Grade Multi-Tenant POC Provisioning System
# Version: 1.0

# Project Configuration
variable "project_id" {
  description = "Google Cloud Project ID for POC environments"
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be 6-30 characters, start with lowercase letter, and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "primary_region" {
  description = "Primary Google Cloud region for POC environments"
  type        = string
  default     = "us-central1"
  validation {
    condition = contains([
      "us-central1", "us-east1", "us-west1", "us-west2",
      "europe-west1", "europe-west2", "europe-west3", "europe-west4",
      "asia-east1", "asia-northeast1", "asia-southeast1"
    ], var.primary_region)
    error_message = "Region must be a valid Google Cloud region with appropriate data residency compliance."
  }
}

variable "primary_zone" {
  description = "Primary Google Cloud zone within the region"
  type        = string
  default     = "us-central1-a"
}

# Tenant Configuration
variable "tenant_id" {
  description = "Unique tenant identifier for POC environment (must be globally unique)"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,61}[a-z0-9]$", var.tenant_id))
    error_message = "Tenant ID must be 4-63 characters, contain only lowercase letters, numbers, and hyphens, and start/end with alphanumeric character."
  }
}

variable "tenant_display_name" {
  description = "Human-readable tenant display name"
  type        = string
  validation {
    condition     = length(var.tenant_display_name) >= 2 && length(var.tenant_display_name) <= 100
    error_message = "Tenant display name must be between 2 and 100 characters."
  }
}

variable "company_info" {
  description = "Company information for the POC tenant"
  type = object({
    company_name     = string
    industry_vertical = string
    company_size     = string
    contact_email    = string
    contact_name     = string
    website_url      = optional(string)
    headquarters_country = string
  })
  validation {
    condition = contains([
      "financial_services", "healthcare", "government", "education",
      "retail", "manufacturing", "technology", "energy", "telecommunications",
      "media_entertainment", "transportation", "real_estate", "other"
    ], var.company_info.industry_vertical)
    error_message = "Industry vertical must be from the predefined list of supported industries."
  }
  validation {
    condition = contains([
      "startup", "small", "medium", "large", "enterprise"
    ], var.company_info.company_size)
    error_message = "Company size must be one of: startup, small, medium, large, enterprise."
  }
  validation {
    condition     = can(regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", var.company_info.contact_email))
    error_message = "Contact email must be a valid email address."
  }
}

# POC Configuration
variable "poc_tier" {
  description = "POC tier determining resource allocation and features"
  type        = string
  default     = "standard"
  validation {
    condition     = contains(["standard", "enterprise", "premium"], var.poc_tier)
    error_message = "POC tier must be one of: standard, enterprise, premium."
  }
}

variable "poc_duration_days" {
  description = "Duration of POC in days"
  type        = number
  default     = 30
  validation {
    condition     = var.poc_duration_days >= 7 && var.poc_duration_days <= 180
    error_message = "POC duration must be between 7 and 180 days."
  }
}

variable "poc_expires_at" {
  description = "POC expiration timestamp (ISO 8601 format)"
  type        = string
  validation {
    condition     = can(formatdate("RFC3339", var.poc_expires_at))
    error_message = "POC expiration must be a valid ISO 8601 timestamp."
  }
}

variable "auto_cleanup_enabled" {
  description = "Enable automatic cleanup of POC resources upon expiration"
  type        = bool
  default     = true
}

# Security Configuration
variable "security_clearance" {
  description = "Security clearance level for the POC environment"
  type        = string
  default     = "unclassified"
  validation {
    condition = contains([
      "unclassified", "confidential", "secret", "top_secret"
    ], var.security_clearance)
    error_message = "Security clearance must be one of: unclassified, confidential, secret, top_secret."
  }
}

variable "data_residency_region" {
  description = "Data residency region for compliance requirements"
  type        = string
  default     = "us"
  validation {
    condition = contains([
      "us", "eu", "uk", "ca", "au", "jp", "in", "sg", "global"
    ], var.data_residency_region)
    error_message = "Data residency region must be one of the supported compliance regions."
  }
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to implement"
  type        = list(string)
  default     = ["soc2", "iso27001"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks : contains([
        "soc2", "iso27001", "hipaa", "gdpr", "fedramp", "fisma", 
        "pci_dss", "ccpa", "nist", "cis", "custom"
      ], framework)
    ])
    error_message = "All compliance frameworks must be from the supported list."
  }
}

variable "network_isolation_level" {
  description = "Level of network isolation for the POC environment"
  type        = string
  default     = "high"
  validation {
    condition     = contains(["standard", "high", "maximum"], var.network_isolation_level)
    error_message = "Network isolation level must be one of: standard, high, maximum."
  }
}

# Integration Configuration
variable "main_platform_integration" {
  description = "Configuration for integration with main iSECTECH platform"
  type = object({
    enabled                = bool
    api_endpoint           = optional(string)
    authentication_method  = optional(string, "oauth2")
    data_sharing_level     = optional(string, "metadata_only")
    sso_integration        = optional(bool, false)
    audit_log_sharing      = optional(bool, true)
  })
  default = {
    enabled = true
  }
}

variable "allowed_data_connectors" {
  description = "List of allowed data connectors for customer integration"
  type        = list(string)
  default = [
    "splunk", "qradar", "sentinel", "elasticsearch", "sumo_logic",
    "crowdstrike", "sentinelone", "carbon_black", "cylance",
    "okta", "active_directory", "ping_identity", "auth0",
    "aws_security_hub", "azure_security_center", "gcp_security_command_center"
  ]
}

variable "crm_integration_config" {
  description = "CRM integration configuration for POC lifecycle management"
  type = object({
    enabled      = bool
    crm_system   = optional(string, "salesforce")
    api_endpoint = optional(string)
    sync_frequency = optional(string, "daily")
    sync_fields = optional(list(string), [
      "poc_status", "user_engagement", "feature_usage", 
      "evaluation_score", "conversion_probability"
    ])
  })
  default = {
    enabled = false
  }
}

# Feature Configuration
variable "enabled_features" {
  description = "List of enabled features for the POC environment"
  type        = list(string)
  default = [
    "threat_detection", "vulnerability_management", "compliance_reporting",
    "siem_analytics", "email_security", "network_monitoring",
    "identity_analytics", "incident_response", "dashboards_reporting"
  ]
  validation {
    condition = alltrue([
      for feature in var.enabled_features : contains([
        "threat_detection", "vulnerability_management", "compliance_reporting",
        "siem_analytics", "email_security", "network_monitoring",
        "identity_analytics", "incident_response", "dashboards_reporting",
        "soar_automation", "ai_ml_analytics", "custom_integrations",
        "white_labeling", "advanced_reporting", "api_access",
        "mobile_app", "custom_dashboards", "advanced_analytics"
      ], feature)
    ])
    error_message = "All enabled features must be from the supported feature list."
  }
}

# Monitoring Configuration
variable "monitoring_config" {
  description = "Monitoring and observability configuration"
  type = object({
    enabled = bool
    retention_days = optional(number, 30)
    detailed_monitoring = optional(bool, true)
    custom_metrics = optional(bool, true)
    alerting_enabled = optional(bool, true)
    dashboard_creation = optional(bool, true)
    
    # Database monitoring
    database = optional(object({
      query_insights = optional(bool, true)
      performance_insights = optional(bool, true)
      slow_query_log = optional(bool, true)
      connection_monitoring = optional(bool, true)
    }), {})
    
    # Application monitoring
    application = optional(object({
      apm_enabled = optional(bool, true)
      trace_sampling_rate = optional(number, 0.1)
      error_reporting = optional(bool, true)
      performance_monitoring = optional(bool, true)
    }), {})
    
    # Infrastructure monitoring
    infrastructure = optional(object({
      node_monitoring = optional(bool, true)
      network_monitoring = optional(bool, true)
      storage_monitoring = optional(bool, true)
      security_monitoring = optional(bool, true)
    }), {})
  })
  default = {
    enabled = true
  }
}

variable "alerting_config" {
  description = "Alerting configuration for POC environments"
  type = object({
    enabled = bool
    email_notifications = optional(list(string), [])
    slack_webhook = optional(string)
    pagerduty_integration = optional(string)
    
    # Alert thresholds
    cpu_threshold = optional(number, 80)
    memory_threshold = optional(number, 85)
    disk_threshold = optional(number, 90)
    error_rate_threshold = optional(number, 5)
    response_time_threshold = optional(number, 2000)
    
    # Alert policies
    high_severity_alerts = optional(list(string), [
      "pod_crash_looping", "database_connection_failure",
      "high_error_rate", "security_incident"
    ])
    medium_severity_alerts = optional(list(string), [
      "high_resource_usage", "slow_response_time",
      "storage_usage_high", "ssl_certificate_expiry"
    ])
  })
  default = {
    enabled = true
  }
}

variable "logging_config" {
  description = "Logging configuration for POC environments"
  type = object({
    enabled = bool
    retention_days = optional(number, 30)
    log_level = optional(string, "INFO")
    structured_logging = optional(bool, true)
    
    # Log exporters
    export_to_bigquery = optional(bool, false)
    export_to_cloud_storage = optional(bool, true)
    export_to_external_siem = optional(bool, false)
    
    # Log types
    application_logs = optional(bool, true)
    audit_logs = optional(bool, true)
    security_logs = optional(bool, true)
    performance_logs = optional(bool, true)
    system_logs = optional(bool, true)
  })
  default = {
    enabled = true
  }
}

# Cost Management
variable "cost_management_config" {
  description = "Cost management and optimization configuration"
  type = object({
    enabled = bool
    daily_budget_limit = optional(number, 100)
    monthly_budget_limit = optional(number, 2000)
    budget_alerts = optional(list(number), [50, 80, 100])
    
    # Cost optimization
    auto_scaling_enabled = optional(bool, true)
    preemptible_nodes = optional(bool, false)
    committed_use_discounts = optional(bool, false)
    
    # Cost tracking
    detailed_billing = optional(bool, true)
    cost_allocation_tags = optional(list(string), [
      "tenant_id", "poc_tier", "environment", "component"
    ])
  })
  default = {
    enabled = true
  }
}

# Kubernetes Configuration
variable "service_accounts" {
  description = "Kubernetes service accounts to create"
  type = map(object({
    namespace = string
    annotations = optional(map(string), {})
    labels = optional(map(string), {})
  }))
  default = {
    poc-app = {
      namespace = "default"
    }
    poc-monitoring = {
      namespace = "default"
    }
  }
}

variable "rbac_rules" {
  description = "RBAC rules for POC environment"
  type = map(object({
    api_groups = list(string)
    resources  = list(string)
    verbs      = list(string)
    namespaces = optional(list(string), [])
  }))
  default = {
    poc-app-access = {
      api_groups = ["", "apps", "extensions"]
      resources  = ["pods", "services", "deployments", "configmaps", "secrets"]
      verbs      = ["get", "list", "watch", "create", "update", "patch"]
    }
    poc-monitoring-access = {
      api_groups = ["", "metrics.k8s.io"]
      resources  = ["nodes", "pods", "services", "endpoints"]
      verbs      = ["get", "list", "watch"]
    }
  }
}

# Notification Configuration
variable "notification_channels" {
  description = "Notification channels for alerts and updates"
  type = map(object({
    type = string
    config = map(string)
    enabled = optional(bool, true)
  }))
  default = {}
}

# Additional Labels
variable "additional_labels" {
  description = "Additional labels to apply to all resources"
  type        = map(string)
  default     = {}
  validation {
    condition = alltrue([
      for key, value in var.additional_labels : can(regex("^[a-z][a-z0-9_-]*$", key))
    ])
    error_message = "Label keys must start with lowercase letter and contain only lowercase letters, numbers, underscores, and hyphens."
  }
}

# Advanced Configuration
variable "advanced_config" {
  description = "Advanced configuration options for power users"
  type = object({
    # Network configuration
    custom_vpc_cidr = optional(string)
    enable_private_cluster = optional(bool, true)
    enable_network_policy = optional(bool, true)
    
    # Security configuration
    enable_binary_authorization = optional(bool, true)
    enable_pod_security_policy = optional(bool, true)
    enable_workload_identity = optional(bool, true)
    
    # Performance configuration
    enable_horizontal_pod_autoscaling = optional(bool, true)
    enable_vertical_pod_autoscaling = optional(bool, false)
    enable_cluster_autoscaling = optional(bool, true)
    
    # Storage configuration
    storage_class = optional(string, "ssd")
    enable_backup = optional(bool, true)
    backup_schedule = optional(string, "0 2 * * *")
    
    # Experimental features
    enable_experimental_features = optional(bool, false)
    experimental_feature_flags = optional(list(string), [])
  })
  default = {}
}