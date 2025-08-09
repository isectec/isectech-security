# iSECTECH Artifact Registry Module Variables
# Configuration variables for production-grade container registry
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

# ═══════════════════════════════════════════════════════════════════════════════
# CORE CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "Google Cloud Project ID for iSECTECH platform"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be a valid Google Cloud project ID."
  }
}

variable "region" {
  description = "Google Cloud region for Artifact Registry repositories"
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

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_vulnerability_scanning" {
  description = "Enable vulnerability scanning for container images"
  type        = bool
  default     = true
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization for production image verification"
  type        = bool
  default     = true
}

variable "attestor_public_key" {
  description = "PGP public key for Binary Authorization attestor (production only)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "workload_identity_sa" {
  description = "Email of the workload identity service account for Cloud Run access"
  type        = string
  default     = ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPOSITORY CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "cleanup_policy_untagged_days" {
  description = "Number of days after which untagged images are deleted"
  type        = number
  default     = 7
  
  validation {
    condition     = var.cleanup_policy_untagged_days >= 1 && var.cleanup_policy_untagged_days <= 365
    error_message = "Cleanup policy untagged days must be between 1 and 365."
  }
}

variable "cleanup_policy_keep_versions" {
  description = "Number of recent versions to keep per repository"
  type        = number
  default     = 10
  
  validation {
    condition     = var.cleanup_policy_keep_versions >= 1 && var.cleanup_policy_keep_versions <= 100
    error_message = "Keep versions must be between 1 and 100."
  }
}

variable "cleanup_policy_older_than_days" {
  description = "Delete images older than specified days (keeping minimum versions)"
  type        = number
  default     = 30
  
  validation {
    condition     = var.cleanup_policy_older_than_days >= 1 && var.cleanup_policy_older_than_days <= 365
    error_message = "Older than days must be between 1 and 365."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ISECTECH-SPECIFIC SERVICE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "isectech_services" {
  description = "List of iSECTECH microservices requiring container repositories"
  type        = list(string)
  default = [
    "api-gateway",
    "auth-service",
    "event-processor", 
    "asset-discovery",
    "threat-detection",
    "siem-engine",
    "soar-orchestrator",
    "threat-intelligence",
    "vulnerability-scanner",
    "compliance-manager",
    "data-classifier",
    "identity-analytics",
    "network-monitor",
    "frontend-app"
  ]
}

variable "enable_security_tools_repo" {
  description = "Enable dedicated repository for security scanning tools"
  type        = bool
  default     = true
}

variable "enable_environment_repos" {
  description = "Enable separate repositories for each environment"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_monitoring" {
  description = "Enable monitoring and alerting for Artifact Registry"
  type        = bool
  default     = true
}

variable "notification_channels" {
  description = "List of notification channel IDs for alerts"
  type        = list(string)
  default     = []
}

variable "vulnerability_threshold" {
  description = "Alert threshold for number of vulnerabilities in container images"
  type        = number
  default     = 10
  
  validation {
    condition     = var.vulnerability_threshold >= 1 && var.vulnerability_threshold <= 100
    error_message = "Vulnerability threshold must be between 1 and 100."
  }
}

variable "failed_push_threshold" {
  description = "Alert threshold for number of failed image pushes"
  type        = number
  default     = 5
  
  validation {
    condition     = var.failed_push_threshold >= 1 && var.failed_push_threshold <= 50
    error_message = "Failed push threshold must be between 1 and 50."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_cost_optimization" {
  description = "Enable aggressive cleanup policies for cost optimization"
  type        = bool
  default     = true
}

variable "production_keep_versions" {
  description = "Number of versions to keep in production repository"
  type        = number
  default     = 50
  
  validation {
    condition     = var.production_keep_versions >= 10 && var.production_keep_versions <= 200
    error_message = "Production keep versions must be between 10 and 200."
  }
}

variable "development_keep_versions" {
  description = "Number of versions to keep in development repository"
  type        = number
  default     = 10
  
  validation {
    condition     = var.development_keep_versions >= 5 && var.development_keep_versions <= 50
    error_message = "Development keep versions must be between 5 and 50."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND GOVERNANCE VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "NIST"]
  
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks : contains([
        "SOC2", "ISO27001", "NIST", "HIPAA", "PCI-DSS", "GDPR", "FedRAMP"
      ], framework)
    ])
    error_message = "Compliance frameworks must be valid framework names."
  }
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging for registry operations"
  type        = bool
  default     = true
}

variable "data_residency_regions" {
  description = "List of allowed regions for data residency compliance"
  type        = list(string)
  default     = ["us-central1", "us-east1", "us-west1"]
  
  validation {
    condition = alltrue([
      for region in var.data_residency_regions : contains([
        "us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
        "europe-north1", "europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
        "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
        "asia-south1", "asia-southeast1", "asia-southeast2", "australia-southeast1"
      ], region)
    ])
    error_message = "All data residency regions must be valid Google Cloud regions."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "ci_cd_service_accounts" {
  description = "List of CI/CD service account emails that need write access"
  type        = list(string)
  default     = []
}

variable "runtime_service_accounts" {
  description = "List of runtime service account emails that need read access"
  type        = list(string)
  default     = []
}

variable "kms_key_id" {
  description = "KMS key ID for encrypting container images (optional)"
  type        = string
  default     = ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# LABELING AND TAGGING VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "labels" {
  description = "Labels to apply to all Artifact Registry resources"
  type        = map(string)
  default = {
    project    = "isectech"
    managed-by = "terraform"
    component  = "artifact-registry"
  }
  
  validation {
    condition = alltrue([
      for k, v in var.labels : can(regex("^[a-z0-9_-]+$", k)) && can(regex("^[a-zA-Z0-9_.-]+$", v))
    ])
    error_message = "Label keys must contain only lowercase letters, numbers, underscores, and hyphens. Values must contain only letters, numbers, underscores, periods, and hyphens."
  }
}

variable "additional_labels" {
  description = "Additional labels to apply to resources"
  type        = map(string)
  default     = {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED CONFIGURATION VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_immutable_tags" {
  description = "Enable immutable tags to prevent tag overwriting"
  type        = bool
  default     = false
}

variable "repository_format" {
  description = "Repository format (DOCKER, MAVEN, NPM, APT, YUM, PYTHON)"
  type        = string
  default     = "DOCKER"
  
  validation {
    condition     = contains(["DOCKER", "MAVEN", "NPM", "APT", "YUM", "PYTHON"], var.repository_format)
    error_message = "Repository format must be one of: DOCKER, MAVEN, NPM, APT, YUM, PYTHON."
  }
}

variable "enable_remote_repositories" {
  description = "Enable remote repositories for upstream caching"
  type        = bool
  default     = false
}

variable "upstream_repositories" {
  description = "List of upstream repositories for remote caching"
  type = list(object({
    name        = string
    remote_url  = string
    description = string
  }))
  default = []
}