# iSECTECH High Availability Infrastructure Variables
# Terraform variable definitions for multi-region deployment

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "isectech"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, production."
  }
}

variable "domain_name" {
  description = "Primary domain name for the application"
  type        = string
  default     = "isectech.com"
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.primary_region))
    error_message = "Primary region must be a valid AWS region format."
  }
}

variable "secondary_region" {
  description = "Secondary AWS region for disaster recovery"
  type        = string
  default     = "us-west-2"
  
  validation {
    condition = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.secondary_region))
    error_message = "Secondary region must be a valid AWS region format."
  }
}

variable "tertiary_region" {
  description = "Tertiary AWS region for additional redundancy"
  type        = string
  default     = "eu-west-1"
  
  validation {
    condition = can(regex("^[a-z]{2}-[a-z]+-[0-9]+$", var.tertiary_region))
    error_message = "Tertiary region must be a valid AWS region format."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# KUBERNETES CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "kubernetes_version" {
  description = "Kubernetes version for EKS clusters"
  type        = string
  default     = "1.28"
  
  validation {
    condition = can(regex("^[0-9]+\\.[0-9]+$", var.kubernetes_version))
    error_message = "Kubernetes version must be in format X.Y (e.g., 1.28)."
  }
}

variable "node_group_instance_types" {
  description = "Instance types for EKS node groups"
  type = object({
    system      = list(string)
    application = list(string)
    monitoring  = list(string)
  })
  default = {
    system      = ["m6i.large", "m6i.xlarge"]
    application = ["m6i.xlarge", "m6i.2xlarge", "c6i.xlarge"]
    monitoring  = ["m6i.large", "m6i.xlarge"]
  }
}

variable "node_group_scaling" {
  description = "Scaling configuration for EKS node groups"
  type = object({
    system = object({
      min_size     = number
      max_size     = number
      desired_size = number
    })
    application = object({
      min_size     = number
      max_size     = number
      desired_size = number
    })
    monitoring = object({
      min_size     = number
      max_size     = number
      desired_size = number
    })
  })
  default = {
    system = {
      min_size     = 3
      max_size     = 6
      desired_size = 3
    }
    application = {
      min_size     = 6
      max_size     = 20
      desired_size = 6
    }
    monitoring = {
      min_size     = 2
      max_size     = 4
      desired_size = 2
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "database_name" {
  description = "Name of the primary database"
  type        = string
  default     = "isectech"
  sensitive   = false
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{0,62}$", var.database_name))
    error_message = "Database name must start with a letter and contain only alphanumeric characters and underscores, max 63 characters."
  }
}

variable "database_username" {
  description = "Master username for the database"
  type        = string
  default     = "isectech_admin"
  sensitive   = true
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9_]{2,15}$", var.database_username))
    error_message = "Database username must start with a letter, contain only alphanumeric characters and underscores, and be 3-16 characters long."
  }
}

variable "aurora_version" {
  description = "Aurora PostgreSQL engine version"
  type        = string
  default     = "15.4"
  
  validation {
    condition = can(regex("^[0-9]+\\.[0-9]+$", var.aurora_version))
    error_message = "Aurora version must be in format X.Y (e.g., 15.4)."
  }
}

variable "database_instance_class" {
  description = "Instance class for Aurora database instances"
  type        = string
  default     = "db.r6g.xlarge"
  
  validation {
    condition = can(regex("^db\\.[a-z0-9]+\\.[a-z0-9]+$", var.database_instance_class))
    error_message = "Database instance class must be a valid RDS instance type."
  }
}

variable "database_backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 35
  
  validation {
    condition     = var.database_backup_retention_period >= 7 && var.database_backup_retention_period <= 35
    error_message = "Backup retention period must be between 7 and 35 days."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CACHE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "redis_version" {
  description = "Redis engine version for ElastiCache"
  type        = string
  default     = "7.0"
  
  validation {
    condition = can(regex("^[0-9]+\\.[0-9]+$", var.redis_version))
    error_message = "Redis version must be in format X.Y (e.g., 7.0)."
  }
}

variable "redis_node_type" {
  description = "Node type for Redis ElastiCache clusters"
  type        = string
  default     = "cache.r7g.large"
  
  validation {
    condition = can(regex("^cache\\.[a-z0-9]+\\.[a-z0-9]+$", var.redis_node_type))
    error_message = "Redis node type must be a valid ElastiCache node type."
  }
}

variable "redis_num_cache_clusters" {
  description = "Number of cache clusters per Redis replication group"
  type = object({
    primary   = number
    secondary = number
    tertiary  = number
  })
  default = {
    primary   = 3
    secondary = 2
    tertiary  = 2
  }
  
  validation {
    condition = (
      var.redis_num_cache_clusters.primary >= 2 &&
      var.redis_num_cache_clusters.secondary >= 2 &&
      var.redis_num_cache_clusters.tertiary >= 2
    )
    error_message = "Each region must have at least 2 Redis cache clusters for high availability."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the infrastructure"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # Internal traffic only by default
  
  validation {
    condition = alltrue([
      for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "All allowed CIDR blocks must be valid CIDR notation."
  }
}

variable "enable_waf" {
  description = "Enable AWS WAF for application load balancers"
  type        = bool
  default     = true
}

variable "enable_shield_advanced" {
  description = "Enable AWS Shield Advanced for DDoS protection"
  type        = bool
  default     = true
}

variable "ssl_policy" {
  description = "SSL security policy for load balancers"
  type        = string
  default     = "ELBSecurityPolicy-TLS-1-2-2017-01"
  
  validation {
    condition = contains([
      "ELBSecurityPolicy-TLS-1-2-2017-01",
      "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
      "ELBSecurityPolicy-FS-2018-06",
      "ELBSecurityPolicy-FS-1-2-2019-08",
      "ELBSecurityPolicy-FS-1-2-Res-2020-10"
    ], var.ssl_policy)
    error_message = "SSL policy must be a valid ELB security policy."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 365
  
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch Logs retention value."
  }
}

variable "enable_xray_tracing" {
  description = "Enable AWS X-Ray tracing"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP AND DISASTER RECOVERY
# ═══════════════════════════════════════════════════════════════════════════════

variable "backup_retention_period" {
  description = "Backup retention period in days"
  type        = number
  default     = 90
  
  validation {
    condition     = var.backup_retention_period >= 7 && var.backup_retention_period <= 2555
    error_message = "Backup retention period must be between 7 and 2555 days."
  }
}

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup replication"
  type        = bool
  default     = true
}

variable "backup_schedule" {
  description = "Backup schedule configuration"
  type = object({
    full_backup_cron        = string
    incremental_backup_cron = string
    backup_window          = string
    maintenance_window     = string
  })
  default = {
    full_backup_cron        = "0 2 * * *"    # Daily at 2 AM
    incremental_backup_cron = "0 */6 * * *"  # Every 6 hours
    backup_window          = "03:00-05:00"   # UTC
    maintenance_window     = "sun:05:00-sun:07:00"  # UTC
  }
  
  validation {
    condition = can(regex("^[0-9]{2}:[0-9]{2}-[0-9]{2}:[0-9]{2}$", var.backup_schedule.backup_window))
    error_message = "Backup window must be in format HH:MM-HH:MM."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_spot_instances" {
  description = "Enable Spot instances for non-critical workloads"
  type        = bool
  default     = false  # Disabled for production by default
}

variable "enable_reserved_instances" {
  description = "Enable Reserved Instance recommendations"
  type        = bool
  default     = true
}

variable "cost_allocation_tags" {
  description = "Cost allocation tags for billing"
  type        = map(string)
  default = {
    Project     = "iSECTECH"
    Team        = "Platform Engineering"
    CostCenter  = "Engineering"
    Environment = "Production"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS
# ═══════════════════════════════════════════════════════════════════════════════

variable "feature_flags" {
  description = "Feature flags for enabling/disabling infrastructure components"
  type = object({
    enable_aurora_global_cluster = bool
    enable_elasticsearch_cluster = bool
    enable_service_mesh         = bool
    enable_secrets_manager      = bool
    enable_parameter_store      = bool
    enable_cognito_integration  = bool
  })
  default = {
    enable_aurora_global_cluster = true
    enable_elasticsearch_cluster = true
    enable_service_mesh         = true
    enable_secrets_manager      = true
    enable_parameter_store      = true
    enable_cognito_integration  = false
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "notification_endpoints" {
  description = "SNS notification endpoints for alerts"
  type = object({
    email = list(string)
    slack = object({
      webhook_url = string
      channel     = string
    })
    pagerduty = object({
      integration_key = string
    })
  })
  default = {
    email = ["ops@isectech.com", "platform@isectech.com"]
    slack = {
      webhook_url = ""
      channel     = "#alerts-infrastructure"
    }
    pagerduty = {
      integration_key = ""
    }
  }
  sensitive = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════

variable "compliance_standards" {
  description = "Compliance standards to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "GDPR"]
  
  validation {
    condition = alltrue([
      for standard in var.compliance_standards : contains(["SOC2", "ISO27001", "GDPR", "HIPAA", "PCI-DSS"], standard)
    ])
    error_message = "Compliance standards must be from the supported list: SOC2, ISO27001, GDPR, HIPAA, PCI-DSS."
  }
}

variable "data_classification" {
  description = "Data classification level for the infrastructure"
  type        = string
  default     = "confidential"
  
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}