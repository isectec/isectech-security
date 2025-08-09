# iSECTECH Multi-Region Deployment Variables
# Variable definitions for multi-region GCP infrastructure
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Multi-Region Architecture Implementation

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT AND ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "Google Cloud Project ID for multi-region deployment"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be a valid Google Cloud project ID (6-30 characters, lowercase letters, numbers, and hyphens)."
  }
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "terraform_state_bucket" {
  description = "Google Cloud Storage bucket for Terraform state storage"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]*[a-z0-9]$", var.terraform_state_bucket))
    error_message = "Terraform state bucket name must be a valid GCS bucket name."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-REGION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "deployment_model" {
  description = "Multi-region deployment model: active-active, active-passive, active-active-regional"
  type        = string
  default     = "active-active-regional"
  
  validation {
    condition     = contains(["active-active", "active-passive", "active-active-regional"], var.deployment_model)
    error_message = "Deployment model must be one of: active-active, active-passive, active-active-regional."
  }
}

variable "primary_region" {
  description = "Primary region for active-passive deployments"
  type        = string
  default     = "us-central1"
}

variable "enabled_regions" {
  description = "List of regions to deploy to (subset of us-central1, europe-west4, asia-northeast1, us-east1, europe-west1)"
  type        = list(string)
  default     = ["us-central1", "europe-west4", "asia-northeast1"]
  
  validation {
    condition = alltrue([
      for region in var.enabled_regions : contains([
        "us-central1", "europe-west4", "asia-northeast1", "us-east1", "europe-west1"
      ], region)
    ])
    error_message = "Enabled regions must be from the predefined list of supported regions."
  }
}

variable "backup_regions" {
  description = "List of backup regions to deploy for disaster recovery"
  type        = list(string)
  default     = ["us-east1", "europe-west1"]
  
  validation {
    condition = alltrue([
      for region in var.backup_regions : contains([
        "us-central1", "europe-west4", "asia-northeast1", "us-east1", "europe-west1"
      ], region)
    ])
    error_message = "Backup regions must be from the predefined list of supported regions."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND DATA RESIDENCY
# ═══════════════════════════════════════════════════════════════════════════════

variable "data_residency_enforcement" {
  description = "Enforce strict data residency rules per region"
  type        = bool
  default     = true
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["GDPR", "CCPA", "APPI", "SOC2", "ISO27001"]
  
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks : contains([
        "GDPR", "CCPA", "APPI", "SOC2", "ISO27001", "HIPAA", "PCI-DSS", "FedRAMP"
      ], framework)
    ])
    error_message = "Compliance frameworks must be valid framework names."
  }
}

variable "cross_region_data_transfer" {
  description = "Allow cross-region data transfer (should be false for strict compliance)"
  type        = bool
  default     = false
}

variable "compliance_email" {
  description = "Email address for compliance violation notifications"
  type        = string
  default     = "compliance@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.compliance_email))
    error_message = "Compliance email must be a valid email address."
  }
}

variable "pagerduty_service_key" {
  description = "PagerDuty service integration key for critical alerts (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "data_retention_overrides" {
  description = "Override default retention periods by compliance zone (days)"
  type = map(number)
  default = {
    gdpr = 365
    ccpa = 730
    appi = 1095
  }
  
  validation {
    condition = alltrue([
      for days in values(var.data_retention_overrides) : days >= 1 && days <= 3653
    ])
    error_message = "Data retention days must be between 1 and 3653 (10 years)."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORKING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "authorized_networks" {
  description = "List of authorized networks that can access GKE cluster masters"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
  
  validation {
    condition = alltrue([
      for network in var.authorized_networks : can(cidrhost(network.cidr_block, 0))
    ])
    error_message = "All authorized network CIDR blocks must be valid."
  }
}

variable "enable_cross_region_peering" {
  description = "Enable VPC peering between regions (careful with data residency)"
  type        = bool
  default     = false
}

variable "global_load_balancer_type" {
  description = "Type of global load balancer: dns-based, anycast, regional"
  type        = string
  default     = "dns-based"
  
  validation {
    condition     = contains(["dns-based", "anycast", "regional"], var.global_load_balancer_type)
    error_message = "Global load balancer type must be dns-based, anycast, or regional."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_workload_identity" {
  description = "Enable Workload Identity for secure pod-to-GCP service authentication"
  type        = bool
  default     = true
}

variable "enable_shielded_nodes" {
  description = "Enable shielded nodes for additional security"
  type        = bool
  default     = true
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization for container image security"
  type        = bool
  default     = false
}

variable "enable_network_policy" {
  description = "Enable Kubernetes network policy"
  type        = bool
  default     = true
}

variable "kms_key_rotation_period" {
  description = "KMS key rotation period in seconds"
  type        = string
  default     = "2592000s" # 30 days
  
  validation {
    condition     = can(regex("^[0-9]+s$", var.kms_key_rotation_period))
    error_message = "KMS key rotation period must be in seconds format (e.g., 2592000s)."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLUSTER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "kubernetes_version" {
  description = "Kubernetes version for GKE clusters"
  type        = string
  default     = "1.28"
  
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+$", var.kubernetes_version))
    error_message = "Kubernetes version must be in format X.Y (e.g., 1.28)."
  }
}

variable "cluster_configuration" {
  description = "Per-environment cluster configuration"
  type = object({
    production = object({
      node_count         = number
      min_node_count     = number
      max_node_count     = number
      machine_type       = string
      disk_size_gb       = number
      disk_type          = string
      enable_autoscaling = bool
      preemptible        = bool
    })
    staging = object({
      node_count         = number
      min_node_count     = number
      max_node_count     = number
      machine_type       = string
      disk_size_gb       = number
      disk_type          = string
      enable_autoscaling = bool
      preemptible        = bool
    })
    development = object({
      node_count         = number
      min_node_count     = number
      max_node_count     = number
      machine_type       = string
      disk_size_gb       = number
      disk_type          = string
      enable_autoscaling = bool
      preemptible        = bool
    })
  })
  
  default = {
    production = {
      node_count         = 3
      min_node_count     = 3
      max_node_count     = 20
      machine_type       = "e2-standard-4"
      disk_size_gb       = 100
      disk_type          = "pd-ssd"
      enable_autoscaling = true
      preemptible        = false
    }
    staging = {
      node_count         = 2
      min_node_count     = 2
      max_node_count     = 8
      machine_type       = "e2-standard-2"
      disk_size_gb       = 50
      disk_type          = "pd-standard"
      enable_autoscaling = true
      preemptible        = true
    }
    development = {
      node_count         = 1
      min_node_count     = 1
      max_node_count     = 4
      machine_type       = "e2-medium"
      disk_size_gb       = 30
      disk_type          = "pd-standard"
      enable_autoscaling = true
      preemptible        = true
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_logging_monitoring" {
  description = "Enable Cloud Logging and Monitoring for GKE"
  type        = bool
  default     = true
}

variable "monitoring_notification_channels" {
  description = "List of notification channels for monitoring alerts"
  type        = list(string)
  default     = []
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 90
  
  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3653
    error_message = "Log retention days must be between 1 and 3653 (10 years)."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP AND DISASTER RECOVERY
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_backup" {
  description = "Enable GKE Backup for cluster data protection"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
  
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention days must be between 1 and 365."
  }
}

variable "backup_schedule" {
  description = "Cron schedule for backups"
  type        = string
  default     = "0 2 * * *" # Daily at 2 AM
  
  validation {
    condition     = can(regex("^[0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+$", var.backup_schedule))
    error_message = "Backup schedule must be a valid cron expression."
  }
}

variable "disaster_recovery_rto" {
  description = "Recovery Time Objective in minutes"
  type        = number
  default     = 60
  
  validation {
    condition     = var.disaster_recovery_rto >= 5 && var.disaster_recovery_rto <= 1440
    error_message = "RTO must be between 5 minutes and 24 hours."
  }
}

variable "disaster_recovery_rpo" {
  description = "Recovery Point Objective in minutes"
  type        = number
  default     = 15
  
  validation {
    condition     = var.disaster_recovery_rpo >= 1 && var.disaster_recovery_rpo <= 1440
    error_message = "RPO must be between 1 minute and 24 hours."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "preemptible_percentage" {
  description = "Percentage of preemptible nodes (0-100, production should be low)"
  type        = number
  default     = 0
  
  validation {
    condition     = var.preemptible_percentage >= 0 && var.preemptible_percentage <= 100
    error_message = "Preemptible percentage must be between 0 and 100."
  }
}

variable "auto_scaling_enabled" {
  description = "Enable cluster auto-scaling"
  type        = bool
  default     = true
}

variable "resource_quotas" {
  description = "Regional resource quotas to prevent cost overruns"
  type = map(object({
    cpu_limit    = string
    memory_limit = string
    storage_limit = string
  }))
  default = {
    production = {
      cpu_limit    = "100"
      memory_limit = "500Gi"
      storage_limit = "1Ti"
    }
    staging = {
      cpu_limit    = "50"
      memory_limit = "200Gi"
      storage_limit = "500Gi"
    }
    development = {
      cpu_limit    = "20"
      memory_limit = "100Gi"
      storage_limit = "200Gi"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS AND EXPERIMENTAL
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_istio" {
  description = "Enable Istio service mesh for cross-region traffic management"
  type        = bool
  default     = false
}

variable "enable_anthos" {
  description = "Enable Anthos features for multi-cloud management"
  type        = bool
  default     = false
}

variable "enable_beta_features" {
  description = "Enable beta GKE features"
  type        = bool
  default     = false
}

variable "enable_autopilot" {
  description = "Use GKE Autopilot instead of standard clusters"
  type        = bool
  default     = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS AND DOMAIN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "domain_name" {
  description = "Primary domain name for the global load balancer"
  type        = string
  default     = "isectech.org."
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9.-]+\\.$", var.domain_name))
    error_message = "Domain name must be a valid FQDN ending with a dot."
  }
}

variable "enable_dnssec" {
  description = "Enable DNSSEC for the primary DNS zone"
  type        = bool
  default     = true
}

variable "dns_ttl" {
  description = "TTL for DNS records in seconds"
  type        = number
  default     = 300
  
  validation {
    condition     = var.dns_ttl >= 60 && var.dns_ttl <= 86400
    error_message = "DNS TTL must be between 60 and 86400 seconds."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

variable "traffic_distribution" {
  description = "Traffic distribution percentage by region for active-active"
  type = map(number)
  default = {
    "us-central1"     = 40
    "europe-west4"    = 30
    "asia-northeast1" = 30
  }
  
  validation {
    condition = sum(values(var.traffic_distribution)) == 100
    error_message = "Traffic distribution percentages must sum to 100."
  }
}

variable "health_check_path" {
  description = "Health check path for load balancers"
  type        = string
  default     = "/health"
}

variable "health_check_interval" {
  description = "Health check interval in seconds"
  type        = number
  default     = 30
  
  validation {
    condition     = var.health_check_interval >= 5 && var.health_check_interval <= 300
    error_message = "Health check interval must be between 5 and 300 seconds."
  }
}

variable "enable_health_checks" {
  description = "Enable health checks for DNS routing"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM LABELS AND TAGS
# ═══════════════════════════════════════════════════════════════════════════════

variable "additional_labels" {
  description = "Additional labels to apply to all resources"
  type        = map(string)
  default     = {}
  
  validation {
    condition = alltrue([
      for k, v in var.additional_labels : can(regex("^[a-z0-9_-]+$", k)) && can(regex("^[a-zA-Z0-9_.-]+$", v))
    ])
    error_message = "Label keys must contain only lowercase letters, numbers, underscores, and hyphens. Values must contain only letters, numbers, underscores, periods, and hyphens."
  }
}

variable "resource_labels" {
  description = "Resource-specific labels for multi-region deployment"
  type = object({
    cost_center       = optional(string, "infrastructure")
    team             = optional(string, "devops")
    owner            = optional(string, "isectech")
    criticality      = optional(string, "high")
    data_class       = optional(string, "internal")
    backup_required  = optional(string, "true")
    deployment_type  = optional(string, "multi-region")
    compliance_level = optional(string, "strict")
  })
  default = {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-REGION REPLICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for high availability"
  type        = bool
  default     = true
}

variable "replication_model" {
  description = "Replication model: regional-hybrid, active-active, active-passive"
  type        = string
  default     = "regional-hybrid"
  
  validation {
    condition     = contains(["regional-hybrid", "active-active", "active-passive"], var.replication_model)
    error_message = "Replication model must be regional-hybrid, active-active, or active-passive."
  }
}

variable "database_replication_enabled" {
  description = "Enable database read replica creation"
  type        = bool
  default     = true
}

variable "storage_replication_type" {
  description = "Cloud Storage replication type: regional, dual-region, multi-region"
  type        = string
  default     = "dual-region"
  
  validation {
    condition     = contains(["regional", "dual-region", "multi-region"], var.storage_replication_type)
    error_message = "Storage replication type must be regional, dual-region, or multi-region."
  }
}

variable "cache_replication_enabled" {
  description = "Enable Redis/Memorystore replication"
  type        = bool
  default     = true
}

variable "replication_rpo_minutes" {
  description = "Recovery Point Objective (RPO) in minutes for replication"
  type        = number
  default     = 5
  
  validation {
    condition     = var.replication_rpo_minutes >= 1 && var.replication_rpo_minutes <= 60
    error_message = "RPO must be between 1 and 60 minutes."
  }
}

variable "replication_rto_minutes" {
  description = "Recovery Time Objective (RTO) in minutes for replication"
  type        = number
  default     = 15
  
  validation {
    condition     = var.replication_rto_minutes >= 1 && var.replication_rto_minutes <= 240
    error_message = "RTO must be between 1 and 240 minutes."
  }
}

variable "replication_monitoring_enabled" {
  description = "Enable replication health monitoring and alerting"
  type        = bool
  default     = true
}

variable "replication_backup_frequency" {
  description = "Backup frequency for replication: continuous, hourly, daily"
  type        = string
  default     = "continuous"
  
  validation {
    condition     = contains(["continuous", "hourly", "daily"], var.replication_backup_frequency)
    error_message = "Backup frequency must be continuous, hourly, or daily."
  }
}

variable "operations_email" {
  description = "Email address for operations team notifications"
  type        = string
  default     = "operations@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.operations_email))
    error_message = "Operations email must be a valid email address."
  }
}

variable "enable_state_replication" {
  description = "Enable application state replication via Pub/Sub"
  type        = bool
  default     = true
}

variable "replication_consistency_level" {
  description = "Data consistency level: strong, eventual, session"
  type        = string
  default     = "strong"
  
  validation {
    condition     = contains(["strong", "eventual", "session"], var.replication_consistency_level)
    error_message = "Consistency level must be strong, eventual, or session."
  }
}