# iSECTECH Google Cloud Infrastructure Variables
# Comprehensive variable definitions for production-grade GCP infrastructure
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0 - Google Cloud Platform

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT AND ENVIRONMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "Google Cloud Project ID for resource deployment"
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

variable "region" {
  description = "Google Cloud region for resource deployment"
  type        = string
  default     = "us-central1"
  
  validation {
    condition = contains([
      "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
      "europe-north1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
      "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
      "asia-south1", "asia-southeast1", "asia-southeast2", "australia-southeast1"
    ], var.region)
    error_message = "Region must be a valid Google Cloud region."
  }
}

variable "zone" {
  description = "Google Cloud zone for zonal resources"
  type        = string
  default     = "us-central1-a"
  
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+-[a-z]$", var.zone))
    error_message = "Zone must be a valid Google Cloud zone format."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TERRAFORM STATE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "terraform_state_bucket" {
  description = "Google Cloud Storage bucket for Terraform state storage"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]*[a-z0-9]$", var.terraform_state_bucket))
    error_message = "Terraform state bucket name must be a valid GCS bucket name."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# GKE CLUSTER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "kubernetes_version" {
  description = "Kubernetes version for the GKE cluster"
  type        = string
  default     = "1.28"
  
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+$", var.kubernetes_version))
    error_message = "Kubernetes version must be in format X.Y (e.g., 1.28)."
  }
}

variable "node_machine_type" {
  description = "Machine type for GKE nodes"
  type        = string
  default     = "e2-standard-2"
  
  validation {
    condition     = can(regex("^[a-z0-9]+-[a-z0-9]+-[0-9]+$", var.node_machine_type))
    error_message = "Machine type must be a valid Google Cloud machine type."
  }
}

variable "node_disk_size_gb" {
  description = "Disk size in GB for GKE nodes"
  type        = number
  default     = 50
  
  validation {
    condition     = var.node_disk_size_gb >= 20 && var.node_disk_size_gb <= 2000
    error_message = "Node disk size must be between 20 and 2000 GB."
  }
}

variable "node_disk_type" {
  description = "Disk type for GKE nodes"
  type        = string
  default     = "pd-standard"
  
  validation {
    condition     = contains(["pd-standard", "pd-ssd", "pd-balanced"], var.node_disk_type)
    error_message = "Node disk type must be one of: pd-standard, pd-ssd, pd-balanced."
  }
}

variable "initial_node_count" {
  description = "Initial number of nodes in the GKE cluster"
  type        = number
  default     = 3
  
  validation {
    condition     = var.initial_node_count >= 1 && var.initial_node_count <= 50
    error_message = "Initial node count must be between 1 and 50."
  }
}

variable "max_node_count" {
  description = "Maximum number of nodes in the GKE cluster"
  type        = number
  default     = 20
  
  validation {
    condition     = var.max_node_count >= 1 && var.max_node_count <= 100
    error_message = "Maximum node count must be between 1 and 100."
  }
}

variable "min_node_count" {
  description = "Minimum number of nodes in the GKE cluster"
  type        = number
  default     = 1
  
  validation {
    condition     = var.min_node_count >= 1 && var.min_node_count <= 50
    error_message = "Minimum node count must be between 1 and 50."
  }
}

variable "enable_autoscaling" {
  description = "Enable autoscaling for GKE node pools"
  type        = bool
  default     = true
}

variable "enable_preemptible_nodes" {
  description = "Enable preemptible nodes for cost optimization"
  type        = bool
  default     = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORKING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "vpc_cidr" {
  description = "CIDR block for the VPC network"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid CIDR block."
  }
}

variable "subnet_cidr" {
  description = "CIDR block for the primary subnet"
  type        = string
  default     = "10.0.1.0/24"
  
  validation {
    condition     = can(cidrhost(var.subnet_cidr, 0))
    error_message = "Subnet CIDR must be a valid CIDR block."
  }
}

variable "pods_cidr_range" {
  description = "CIDR block for Kubernetes pods"
  type        = string
  default     = "10.1.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.pods_cidr_range, 0))
    error_message = "Pods CIDR range must be a valid CIDR block."
  }
}

variable "services_cidr_range" {
  description = "CIDR block for Kubernetes services"
  type        = string
  default     = "10.2.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.services_cidr_range, 0))
    error_message = "Services CIDR range must be a valid CIDR block."
  }
}

variable "authorized_networks" {
  description = "List of authorized networks that can access the GKE cluster master"
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

variable "enable_private_nodes" {
  description = "Enable private nodes in the GKE cluster"
  type        = bool
  default     = true
}

variable "enable_private_endpoint" {
  description = "Enable private endpoint for the GKE cluster"
  type        = bool
  default     = false
}

variable "master_ipv4_cidr_block" {
  description = "CIDR block for the GKE cluster master"
  type        = string
  default     = "172.16.0.0/28"
  
  validation {
    condition     = can(cidrhost(var.master_ipv4_cidr_block, 0))
    error_message = "Master IPv4 CIDR block must be a valid CIDR block."
  }
}

variable "allowed_cidr_ranges" {
  description = "List of CIDR ranges allowed by Cloud Armor security policy"
  type        = list(string)
  default     = ["0.0.0.0/0"]
  
  validation {
    condition = alltrue([
      for cidr in var.allowed_cidr_ranges : can(cidrhost(cidr, 0))
    ])
    error_message = "All allowed CIDR ranges must be valid CIDR blocks."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_network_policy" {
  description = "Enable Kubernetes network policy"
  type        = bool
  default     = true
}

variable "enable_pod_security_policy" {
  description = "Enable Kubernetes pod security policy"
  type        = bool
  default     = true
}

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

variable "enable_image_streaming" {
  description = "Enable image streaming for faster container startup"
  type        = bool
  default     = true
}

variable "enable_network_policy_config" {
  description = "Enable network policy configuration"
  type        = bool
  default     = true
}

variable "enable_intranode_visibility" {
  description = "Enable intranode visibility for network monitoring"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "database_version" {
  description = "PostgreSQL version for Cloud SQL"
  type        = string
  default     = "POSTGRES_15"
  
  validation {
    condition     = contains(["POSTGRES_13", "POSTGRES_14", "POSTGRES_15"], var.database_version)
    error_message = "Database version must be a supported PostgreSQL version."
  }
}

variable "database_tier" {
  description = "Machine type for Cloud SQL instance"
  type        = string
  default     = "db-f1-micro"
  
  validation {
    condition     = can(regex("^db-", var.database_tier))
    error_message = "Database tier must be a valid Cloud SQL machine type."
  }
}

variable "database_disk_size" {
  description = "Disk size in GB for Cloud SQL instance"
  type        = number
  default     = 20
  
  validation {
    condition     = var.database_disk_size >= 10 && var.database_disk_size <= 30720
    error_message = "Database disk size must be between 10 and 30720 GB."
  }
}

variable "database_disk_type" {
  description = "Disk type for Cloud SQL instance"
  type        = string
  default     = "PD_STANDARD"
  
  validation {
    condition     = contains(["PD_STANDARD", "PD_SSD"], var.database_disk_type)
    error_message = "Database disk type must be either PD_STANDARD or PD_SSD."
  }
}

variable "database_backup_enabled" {
  description = "Enable automated backups for Cloud SQL"
  type        = bool
  default     = true
}

variable "database_backup_start_time" {
  description = "Start time for automated backups (HH:MM format)"
  type        = string
  default     = "03:00"
  
  validation {
    condition     = can(regex("^[0-2][0-9]:[0-5][0-9]$", var.database_backup_start_time))
    error_message = "Database backup start time must be in HH:MM format."
  }
}

variable "database_name" {
  description = "Name of the application database"
  type        = string
  default     = "isectech"
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.database_name))
    error_message = "Database name must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "database_user" {
  description = "Username for the application database"
  type        = string
  default     = "isectech"
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]*$", var.database_user))
    error_message = "Database user must start with a letter and contain only letters, numbers, and underscores."
  }
}

variable "enable_database_high_availability" {
  description = "Enable high availability for Cloud SQL"
  type        = bool
  default     = false
}

variable "database_deletion_protection" {
  description = "Enable deletion protection for Cloud SQL instance"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "redis_memory_size_gb" {
  description = "Memory size in GB for Redis instance"
  type        = number
  default     = 1
  
  validation {
    condition     = var.redis_memory_size_gb >= 1 && var.redis_memory_size_gb <= 300
    error_message = "Redis memory size must be between 1 and 300 GB."
  }
}

variable "redis_version" {
  description = "Redis version"
  type        = string
  default     = "REDIS_7_0"
  
  validation {
    condition     = contains(["REDIS_6_X", "REDIS_7_0"], var.redis_version)
    error_message = "Redis version must be either REDIS_6_X or REDIS_7_0."
  }
}

variable "redis_tier" {
  description = "Redis service tier"
  type        = string
  default     = "BASIC"
  
  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.redis_tier)
    error_message = "Redis tier must be either BASIC or STANDARD_HA."
  }
}

variable "enable_redis_auth" {
  description = "Enable Redis AUTH"
  type        = bool
  default     = true
}

variable "redis_transit_encryption_mode" {
  description = "Transit encryption mode for Redis"
  type        = string
  default     = "SERVER_AUTH"
  
  validation {
    condition     = contains(["DISABLED", "SERVER_AUTH"], var.redis_transit_encryption_mode)
    error_message = "Redis transit encryption mode must be either DISABLED or SERVER_AUTH."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_logging_monitoring" {
  description = "Enable Cloud Logging and Monitoring for GKE"
  type        = bool
  default     = true
}

variable "enable_system_monitoring" {
  description = "Enable system monitoring components"
  type        = bool
  default     = true
}

variable "logging_service" {
  description = "Logging service for GKE cluster"
  type        = string
  default     = "logging.googleapis.com/kubernetes"
  
  validation {
    condition = contains([
      "logging.googleapis.com/kubernetes",
      "logging.googleapis.com",
      "none"
    ], var.logging_service)
    error_message = "Logging service must be a valid GKE logging service."
  }
}

variable "monitoring_service" {
  description = "Monitoring service for GKE cluster"
  type        = string
  default     = "monitoring.googleapis.com/kubernetes"
  
  validation {
    condition = contains([
      "monitoring.googleapis.com/kubernetes",
      "monitoring.googleapis.com",
      "none"
    ], var.monitoring_service)
    error_message = "Monitoring service must be a valid GKE monitoring service."
  }
}

variable "notification_email" {
  description = "Email address for monitoring notifications"
  type        = string
  default     = "alerts@isectech.org"
  
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address."
  }
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "pagerduty_integration_key" {
  description = "PagerDuty integration key for critical alerts (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# KMS ENCRYPTION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_envelope_encryption" {
  description = "Enable envelope encryption for GKE cluster secrets"
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
# BACKUP AND DISASTER RECOVERY
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_backup" {
  description = "Enable GKE Backup for cluster data protection"
  type        = bool
  default     = false
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

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "enable_node_auto_provisioning" {
  description = "Enable node auto-provisioning for optimal resource allocation"
  type        = bool
  default     = false
}

variable "enable_cluster_autoscaling" {
  description = "Enable cluster autoscaling"
  type        = bool
  default     = true
}

variable "enable_horizontal_pod_autoscaling" {
  description = "Enable horizontal pod autoscaling"
  type        = bool
  default     = true
}

variable "enable_vertical_pod_autoscaling" {
  description = "Enable vertical pod autoscaling"
  type        = bool
  default     = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["NIST", "SOC2", "ISO27001"]
  
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks : contains([
        "NIST", "SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR", "FedRAMP"
      ], framework)
    ])
    error_message = "Compliance frameworks must be valid framework names."
  }
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging"
  type        = bool
  default     = true
}

variable "enable_security_scanning" {
  description = "Enable security scanning for containers and infrastructure"
  type        = bool
  default     = true
}

variable "enable_vulnerability_scanning" {
  description = "Enable vulnerability scanning for container images"
  type        = bool
  default     = true
}

variable "enable_config_connector" {
  description = "Enable Config Connector for managing GCP resources via Kubernetes"
  type        = bool
  default     = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADDONS AND INTEGRATIONS
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_istio" {
  description = "Enable Istio service mesh"
  type        = bool
  default     = false
}

variable "enable_cloudrun" {
  description = "Enable Cloud Run for Anthos"
  type        = bool
  default     = false
}

variable "enable_dns_cache" {
  description = "Enable NodeLocal DNSCache"
  type        = bool
  default     = true
}

variable "enable_http_load_balancing" {
  description = "Enable HTTP load balancing add-on"
  type        = bool
  default     = true
}

variable "enable_network_policy_enforcement" {
  description = "Enable Calico network policy enforcement"
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
  description = "Resource-specific labels"
  type = object({
    cost_center     = optional(string, "infrastructure")
    team            = optional(string, "devops")
    owner           = optional(string, "isectech")
    criticality     = optional(string, "high")
    data_class      = optional(string, "internal")
    backup_required = optional(string, "true")
  })
  default = {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_alpha_features" {
  description = "Enable alpha/experimental features (use with caution in production)"
  type        = bool
  default     = false
}

variable "enable_beta_features" {
  description = "Enable beta features"
  type        = bool
  default     = false
}

variable "enable_spot_instances" {
  description = "Enable spot (preemptible) instances for cost optimization"
  type        = bool
  default     = false
}

variable "enable_gpu_nodes" {
  description = "Enable GPU-enabled nodes"
  type        = bool
  default     = false
}

variable "gpu_type" {
  description = "GPU type for GPU-enabled nodes"
  type        = string
  default     = "nvidia-tesla-t4"
  
  validation {
    condition = contains([
      "nvidia-tesla-k80", "nvidia-tesla-p4", "nvidia-tesla-p100",
      "nvidia-tesla-v100", "nvidia-tesla-t4", "nvidia-a100-80gb"
    ], var.gpu_type)
    error_message = "GPU type must be a supported NVIDIA GPU type."
  }
}

variable "gpu_count" {
  description = "Number of GPUs per node"
  type        = number
  default     = 1
  
  validation {
    condition     = var.gpu_count >= 1 && var.gpu_count <= 8
    error_message = "GPU count must be between 1 and 8."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAINTENANCE AND OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

variable "maintenance_window_start_time" {
  description = "Start time for maintenance window (RFC3339 format)"
  type        = string
  default     = "2024-01-01T03:00:00Z"
  
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.maintenance_window_start_time))
    error_message = "Maintenance window start time must be in RFC3339 format."
  }
}

variable "maintenance_window_duration" {
  description = "Duration of maintenance window"
  type        = string
  default     = "4h"
  
  validation {
    condition     = can(regex("^[0-9]+h$", var.maintenance_window_duration))
    error_message = "Maintenance window duration must be in hours format (e.g., 4h)."
  }
}

variable "maintenance_window_recurrence" {
  description = "Recurrence pattern for maintenance window"
  type        = string
  default     = "FREQ=WEEKLY;BYDAY=SU"
}

variable "auto_upgrade_nodes" {
  description = "Enable automatic node upgrades"
  type        = bool
  default     = true
}

variable "auto_repair_nodes" {
  description = "Enable automatic node repair"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORKING ADVANCED
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_ip_masq_agent" {
  description = "Enable IP masquerade agent"
  type        = bool
  default     = true
}

variable "enable_l4_ilb_subsetting" {
  description = "Enable L4 ILB subsetting"
  type        = bool
  default     = true
}

variable "datapath_provider" {
  description = "Datapath provider for the cluster"
  type        = string
  default     = "ADVANCED_DATAPATH"
  
  validation {
    condition     = contains(["DATAPATH_PROVIDER_UNSPECIFIED", "LEGACY_DATAPATH", "ADVANCED_DATAPATH"], var.datapath_provider)
    error_message = "Datapath provider must be a valid option."
  }
}

variable "enable_private_service_connect" {
  description = "Enable Private Service Connect"
  type        = bool
  default     = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE AND SCALING
# ═══════════════════════════════════════════════════════════════════════════════

variable "max_pods_per_node" {
  description = "Maximum number of pods per node"
  type        = number
  default     = 110
  
  validation {
    condition     = var.max_pods_per_node >= 8 && var.max_pods_per_node <= 256
    error_message = "Maximum pods per node must be between 8 and 256."
  }
}

variable "enable_gcfs_fuse_csi_driver" {
  description = "Enable GCS FUSE CSI driver"
  type        = bool
  default     = false
}

variable "enable_gcp_filestore_csi_driver" {
  description = "Enable GCP Filestore CSI driver"
  type        = bool
  default     = false
}