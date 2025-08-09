# iSECTECH Redis Infrastructure Variables
# Production-grade Redis configuration variables

variable "project_id" {
  description = "GCP project ID for Redis deployment"
  type        = string
  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID cannot be empty."
  }
}

variable "environment" {
  description = "Environment name (production, staging, development)"
  type        = string
  default     = "production"
  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "primary_region" {
  description = "Primary GCP region for Redis deployment"
  type        = string
  default     = "us-central1"
  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]$", var.primary_region))
    error_message = "Primary region must be a valid GCP region format (e.g., us-central1)."
  }
}

variable "secondary_regions" {
  description = "List of secondary GCP regions for Redis deployment"
  type        = list(string)
  default     = ["europe-west1", "asia-northeast1", "australia-southeast1"]
  validation {
    condition     = length(var.secondary_regions) > 0
    error_message = "At least one secondary region must be specified."
  }
}

variable "notification_email" {
  description = "Email address for monitoring notifications"
  type        = string
  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.notification_email))
    error_message = "Notification email must be a valid email address."
  }
}

# Redis instance configuration
variable "redis_memory_size_primary" {
  description = "Memory size for primary Redis instance in GB"
  type        = number
  default     = 16
  validation {
    condition     = var.redis_memory_size_primary >= 1 && var.redis_memory_size_primary <= 300
    error_message = "Redis memory size must be between 1 and 300 GB."
  }
}

variable "redis_memory_size_secondary" {
  description = "Memory size for secondary Redis instances in GB"
  type        = number
  default     = 8
  validation {
    condition     = var.redis_memory_size_secondary >= 1 && var.redis_memory_size_secondary <= 300
    error_message = "Redis memory size must be between 1 and 300 GB."
  }
}

variable "redis_tier" {
  description = "Redis service tier"
  type        = string
  default     = "STANDARD_HA"
  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.redis_tier)
    error_message = "Redis tier must be either BASIC or STANDARD_HA."
  }
}

variable "redis_version" {
  description = "Redis version to deploy"
  type        = string
  default     = "REDIS_7_0"
  validation {
    condition     = contains(["REDIS_6_X", "REDIS_7_0"], var.redis_version)
    error_message = "Redis version must be REDIS_6_X or REDIS_7_0."
  }
}

variable "redis_replica_count" {
  description = "Number of read replicas for Redis instances"
  type        = number
  default     = 2
  validation {
    condition     = var.redis_replica_count >= 0 && var.redis_replica_count <= 5
    error_message = "Redis replica count must be between 0 and 5."
  }
}

# Network configuration
variable "vpc_name" {
  description = "Name of the VPC network for Redis deployment"
  type        = string
  default     = "isectech-vpc"
}

variable "private_subnet_name" {
  description = "Name of the private subnet for Redis deployment"
  type        = string
  default     = "isectech-private-subnet"
}

variable "private_ip_cidr" {
  description = "CIDR block for private IP address range"
  type        = string
  default     = "10.1.0.0/16"
  validation {
    condition     = can(cidrhost(var.private_ip_cidr, 0))
    error_message = "Private IP CIDR must be a valid CIDR block."
  }
}

# Security configuration
variable "auth_enabled" {
  description = "Enable Redis authentication"
  type        = bool
  default     = true
}

variable "transit_encryption_mode" {
  description = "Transit encryption mode for Redis"
  type        = string
  default     = "SERVER_AUTHENTICATION"
  validation {
    condition     = contains(["DISABLED", "SERVER_AUTHENTICATION"], var.transit_encryption_mode)
    error_message = "Transit encryption mode must be DISABLED or SERVER_AUTHENTICATION."
  }
}

variable "password_length" {
  description = "Length of Redis passwords"
  type        = number
  default     = 32
  validation {
    condition     = var.password_length >= 16 && var.password_length <= 128
    error_message = "Password length must be between 16 and 128 characters."
  }
}

# Cache configuration
variable "trust_score_ttl" {
  description = "TTL for trust scores in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.trust_score_ttl > 0 && var.trust_score_ttl <= 86400
    error_message = "Trust score TTL must be between 1 second and 1 day."
  }
}

variable "device_profile_ttl" {
  description = "TTL for device profiles in seconds"
  type        = number
  default     = 1800
  validation {
    condition     = var.device_profile_ttl > 0 && var.device_profile_ttl <= 86400
    error_message = "Device profile TTL must be between 1 second and 1 day."
  }
}

variable "network_context_ttl" {
  description = "TTL for network context in seconds"
  type        = number
  default     = 600
  validation {
    condition     = var.network_context_ttl > 0 && var.network_context_ttl <= 86400
    error_message = "Network context TTL must be between 1 second and 1 day."
  }
}

variable "threat_intelligence_ttl" {
  description = "TTL for threat intelligence in seconds"
  type        = number
  default     = 3600
  validation {
    condition     = var.threat_intelligence_ttl > 0 && var.threat_intelligence_ttl <= 86400
    error_message = "Threat intelligence TTL must be between 1 second and 1 day."
  }
}

# Performance configuration
variable "max_memory_policy" {
  description = "Redis max memory policy"
  type        = string
  default     = "allkeys-lru"
  validation {
    condition = contains([
      "noeviction",
      "allkeys-lru",
      "allkeys-lfu", 
      "volatile-lru",
      "volatile-lfu",
      "allkeys-random",
      "volatile-random",
      "volatile-ttl"
    ], var.max_memory_policy)
    error_message = "Max memory policy must be a valid Redis eviction policy."
  }
}

variable "tcp_keepalive" {
  description = "TCP keepalive setting for Redis"
  type        = number
  default     = 300
  validation {
    condition     = var.tcp_keepalive >= 0 && var.tcp_keepalive <= 3600
    error_message = "TCP keepalive must be between 0 and 3600 seconds."
  }
}

variable "timeout" {
  description = "Client idle timeout for Redis in seconds (0 = disabled)"
  type        = number
  default     = 0
  validation {
    condition     = var.timeout >= 0 && var.timeout <= 3600
    error_message = "Timeout must be between 0 and 3600 seconds."
  }
}

variable "databases" {
  description = "Number of Redis databases"
  type        = number
  default     = 16
  validation {
    condition     = var.databases >= 1 && var.databases <= 16
    error_message = "Number of databases must be between 1 and 16."
  }
}

# Monitoring configuration
variable "memory_utilization_threshold" {
  description = "Memory utilization threshold for alerts (percentage)"
  type        = number
  default     = 85
  validation {
    condition     = var.memory_utilization_threshold > 0 && var.memory_utilization_threshold <= 100
    error_message = "Memory utilization threshold must be between 1 and 100 percent."
  }
}

variable "connection_count_threshold" {
  description = "Connection count threshold for alerts"
  type        = number
  default     = 1000
  validation {
    condition     = var.connection_count_threshold > 0 && var.connection_count_threshold <= 10000
    error_message = "Connection count threshold must be between 1 and 10000."
  }
}

variable "alert_notification_channels" {
  description = "List of notification channels for alerts"
  type        = list(string)
  default     = []
}

# Backup configuration
variable "backup_enabled" {
  description = "Enable automated backups for Redis"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain Redis backups"
  type        = number
  default     = 14
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention days must be between 1 and 365."
  }
}

variable "backup_schedule" {
  description = "Backup schedule in cron format"
  type        = string
  default     = "0 4 * * *"  # Daily at 4 AM
}

# Sentinel configuration
variable "sentinel_enabled" {
  description = "Enable Redis Sentinel for high availability"
  type        = bool
  default     = true
}

variable "sentinel_instances" {
  description = "Number of Sentinel instances to deploy"
  type        = number
  default     = 3
  validation {
    condition     = var.sentinel_instances >= 3 && var.sentinel_instances % 2 == 1
    error_message = "Sentinel instances must be an odd number >= 3 for proper quorum."
  }
}

variable "sentinel_machine_type" {
  description = "Machine type for Sentinel instances"
  type        = string
  default     = "e2-standard-2"
}

variable "sentinel_port" {
  description = "Port for Redis Sentinel"
  type        = number
  default     = 26379
  validation {
    condition     = var.sentinel_port > 1024 && var.sentinel_port < 65536
    error_message = "Sentinel port must be between 1024 and 65535."
  }
}

# Labels and tagging
variable "labels" {
  description = "Additional labels to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "environment_labels" {
  description = "Environment-specific labels"
  type        = map(string)
  default = {
    managed-by = "terraform"
    component  = "redis"
    service    = "trust-scoring"
  }
}

# Compliance configuration
variable "data_residency_enabled" {
  description = "Enable data residency controls"
  type        = bool
  default     = true
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "GDPR", "HIPAA"]
}

# Advanced configuration
variable "custom_redis_configs" {
  description = "Custom Redis configuration parameters"
  type        = map(string)
  default     = {}
}

variable "enable_cross_region_replication" {
  description = "Enable cross-region replication for disaster recovery"
  type        = bool
  default     = false
}

variable "maintenance_window_day" {
  description = "Day of the week for maintenance window"
  type        = string
  default     = "SUNDAY"
  validation {
    condition = contains([
      "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", 
      "FRIDAY", "SATURDAY", "SUNDAY"
    ], var.maintenance_window_day)
    error_message = "Maintenance window day must be a valid day of the week."
  }
}

variable "maintenance_window_hour" {
  description = "Hour of the day for maintenance window (0-23)"
  type        = number
  default     = 2
  validation {
    condition     = var.maintenance_window_hour >= 0 && var.maintenance_window_hour <= 23
    error_message = "Maintenance window hour must be between 0 and 23."
  }
}