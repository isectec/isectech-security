# iSECTECH POC Environment - Main Terraform Configuration
# Production-Grade Multi-Tenant POC Provisioning System
# Version: 1.0
# Author: Claude Code Implementation

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  # Use Google Cloud Storage for state management
  backend "gcs" {
    bucket = "isectech-terraform-state-poc"
    prefix = "poc-environments"
  }
}

# Configure the Google Cloud Provider
provider "google" {
  project = var.project_id
  region  = var.primary_region
  zone    = var.primary_zone
}

provider "google-beta" {
  project = var.project_id
  region  = var.primary_region
  zone    = var.primary_zone
}

# Local values for consistent naming and tagging
locals {
  # Standardized naming convention
  project_name = "isectech-poc"
  environment  = "production"
  
  # Common tags for all resources
  common_tags = {
    Project     = "iSECTECH-POC-Platform"
    Environment = local.environment
    ManagedBy   = "terraform"
    Team        = "platform-engineering"
    Purpose     = "poc-environment-management"
    CreatedBy   = "automated-deployment"
    LastUpdated = timestamp()
  }
  
  # Security-specific configurations
  security_config = {
    enable_shielded_vms           = true
    enable_confidential_computing = true
    require_tls_minimum_version   = "1.3"
    enable_network_policy         = true
    enable_pod_security_policy    = true
    enable_workload_identity      = true
  }
  
  # Resource naming patterns
  naming_patterns = {
    vpc_name        = "${local.project_name}-vpc-${var.tenant_id}"
    subnet_name     = "${local.project_name}-subnet-${var.tenant_id}"
    cluster_name    = "${local.project_name}-cluster-${var.tenant_id}"
    database_name   = "${local.project_name}-db-${var.tenant_id}"
    namespace_name  = "poc-${var.tenant_id}"
  }
}

# Random ID for unique resource naming
resource "random_id" "poc_suffix" {
  byte_length = 4
}

# Data sources for existing infrastructure
data "google_project" "current" {}

data "google_compute_zones" "available" {
  region = var.primary_region
}

# Main POC Environment Module
module "poc_environment" {
  source = "./modules/poc-environment"
  
  # Project configuration
  project_id = var.project_id
  region     = var.primary_region
  zones      = data.google_compute_zones.available.names
  
  # Tenant configuration
  tenant_id           = var.tenant_id
  tenant_display_name = var.tenant_display_name
  company_info        = var.company_info
  
  # POC configuration
  poc_tier              = var.poc_tier
  poc_duration_days     = var.poc_duration_days
  poc_expires_at        = var.poc_expires_at
  auto_cleanup_enabled  = var.auto_cleanup_enabled
  
  # Resource allocation based on POC tier
  resource_allocation = local.resource_allocations[var.poc_tier]
  
  # Security configuration
  security_clearance         = var.security_clearance
  data_residency_region     = var.data_residency_region
  compliance_frameworks     = var.compliance_frameworks
  network_isolation_level   = var.network_isolation_level
  
  # Integration settings
  main_platform_integration = var.main_platform_integration
  allowed_data_connectors   = var.allowed_data_connectors
  crm_integration_config    = var.crm_integration_config
  
  # Monitoring and observability
  monitoring_config = var.monitoring_config
  alerting_config   = var.alerting_config
  logging_config    = var.logging_config
  
  # Feature gates
  enabled_features = var.enabled_features
  
  # Cost management
  cost_management_config = var.cost_management_config
  
  # Tags and labels
  labels = merge(local.common_tags, var.additional_labels)
  
  # Dependency management
  depends_on = [
    google_project_service.required_apis
  ]
}

# Enable required Google Cloud APIs
resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sql.googleapis.com",
    "sqladmin.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com",
    "servicenetworking.googleapis.com",
    "vpcaccess.googleapis.com",
    "redis.googleapis.com",
    "firestore.googleapis.com",
    "certificatemanager.googleapis.com",
    "dns.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudfunctions.googleapis.com",
    "eventarc.googleapis.com",
    "pubsub.googleapis.com",
    "storage.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com",
    "securitycenter.googleapis.com"
  ])
  
  project = var.project_id
  service = each.value
  
  disable_dependent_services = false
  disable_on_destroy        = false
  
  timeouts {
    create = "10m"
    update = "10m"
    delete = "10m"
  }
}

# POC Tenant Database
module "poc_database" {
  source = "./modules/poc-database"
  
  # Project and location
  project_id = var.project_id
  region     = var.primary_region
  
  # Database configuration
  tenant_id        = var.tenant_id
  database_name    = "${var.tenant_id}_poc_db"
  database_tier    = local.database_tiers[var.poc_tier]
  storage_size_gb  = local.storage_allocations[var.poc_tier]
  
  # Security configuration
  require_ssl                = true
  enable_backup              = true
  backup_retention_days      = local.backup_retention_days[var.poc_tier]
  enable_point_in_time_recovery = true
  
  # Network configuration
  vpc_network = module.poc_environment.vpc_network
  
  # Monitoring and alerting
  enable_query_insights = true
  monitoring_config     = var.monitoring_config.database
  
  # Labels and tags
  labels = merge(local.common_tags, {
    Component = "database"
    TenantID  = var.tenant_id
  })
  
  depends_on = [
    module.poc_environment
  ]
}

# POC Kubernetes Namespace and Resources
module "poc_kubernetes" {
  source = "./modules/poc-kubernetes"
  
  # Cluster information
  cluster_name       = module.poc_environment.cluster_name
  cluster_endpoint   = module.poc_environment.cluster_endpoint
  cluster_ca_certificate = module.poc_environment.cluster_ca_certificate
  
  # Namespace configuration
  tenant_id      = var.tenant_id
  namespace_name = local.naming_patterns.namespace_name
  
  # Resource quotas based on POC tier
  resource_quotas = local.resource_allocations[var.poc_tier].kubernetes
  
  # Security policies
  pod_security_policy = {
    privileged               = false
    allow_privilege_escalation = false
    required_drop_capabilities = ["ALL"]
    allowed_capabilities     = []
    volumes                 = ["configMap", "emptyDir", "projected", "secret", "downwardAPI", "persistentVolumeClaim"]
    host_network           = false
    host_ipc              = false
    host_pid              = false
    run_as_user           = "1000"
    run_as_group          = "1000"
    fs_group              = "1000"
  }
  
  # Network policies for tenant isolation
  network_policies = {
    deny_all_ingress = true
    deny_all_egress  = false
    allowed_ingress  = [
      {
        from_namespaces = ["istio-system", "kube-system"]
        ports          = [8080, 8443]
      }
    ]
    allowed_egress = [
      {
        to_namespaces = ["kube-system"]
        ports        = [53, 443]
      }
    ]
  }
  
  # Service accounts and RBAC
  service_accounts = var.service_accounts
  rbac_rules      = var.rbac_rules
  
  # Labels and annotations
  labels = merge(local.common_tags, {
    Component = "kubernetes"
    TenantID  = var.tenant_id
  })
  
  depends_on = [
    module.poc_environment,
    module.poc_database
  ]
}

# POC Monitoring and Observability
module "poc_monitoring" {
  source = "./modules/poc-monitoring"
  
  # Project configuration
  project_id = var.project_id
  region     = var.primary_region
  
  # Tenant configuration
  tenant_id = var.tenant_id
  
  # Monitoring targets
  monitored_resources = {
    gke_cluster      = module.poc_environment.cluster_name
    sql_instance     = module.poc_database.instance_name
    vpc_network      = module.poc_environment.vpc_network.name
    kubernetes_namespace = module.poc_kubernetes.namespace_name
  }
  
  # Alerting configuration
  notification_channels = var.notification_channels
  alert_policies = {
    high_cpu_usage = {
      threshold = 80
      duration  = "300s"
    }
    high_memory_usage = {
      threshold = 85
      duration  = "300s"
    }
    database_connection_issues = {
      threshold = 5
      duration  = "60s"
    }
    pod_crash_looping = {
      threshold = 3
      duration  = "180s"
    }
  }
  
  # Custom metrics for POC-specific monitoring
  custom_metrics = [
    {
      name        = "poc_active_users"
      description = "Number of active users in POC environment"
      metric_kind = "GAUGE"
      value_type  = "INT64"
    },
    {
      name        = "poc_feature_usage"
      description = "Feature usage metrics for POC evaluation"
      metric_kind = "CUMULATIVE"
      value_type  = "INT64"
    },
    {
      name        = "poc_evaluation_score"
      description = "POC evaluation progress score"
      metric_kind = "GAUGE"
      value_type  = "DOUBLE"
    }
  ]
  
  # Dashboards
  create_dashboards = true
  dashboard_config = {
    poc_overview = {
      title = "POC Environment Overview - ${var.tenant_display_name}"
      widgets = [
        "infrastructure_health",
        "application_performance",
        "user_activity",
        "feature_usage",
        "evaluation_metrics"
      ]
    }
  }
  
  # Labels
  labels = merge(local.common_tags, {
    Component = "monitoring"
    TenantID  = var.tenant_id
  })
  
  depends_on = [
    module.poc_environment,
    module.poc_database,
    module.poc_kubernetes
  ]
}

# POC Security Configuration
module "poc_security" {
  source = "./modules/poc-security"
  
  # Project configuration
  project_id = var.project_id
  region     = var.primary_region
  
  # Tenant configuration
  tenant_id           = var.tenant_id
  security_clearance  = var.security_clearance
  compliance_frameworks = var.compliance_frameworks
  
  # Encryption configuration
  kms_config = {
    key_ring_name = "poc-${var.tenant_id}-keyring"
    crypto_keys = {
      database = {
        purpose          = "ENCRYPT_DECRYPT"
        rotation_period  = "7776000s"  # 90 days
        protection_level = "SOFTWARE"
      }
      storage = {
        purpose          = "ENCRYPT_DECRYPT"
        rotation_period  = "7776000s"  # 90 days
        protection_level = "SOFTWARE"
      }
      secrets = {
        purpose          = "ENCRYPT_DECRYPT"
        rotation_period  = "2592000s"  # 30 days
        protection_level = "SOFTWARE"
      }
    }
  }
  
  # Secret management
  secrets_config = {
    database_credentials = {
      secret_id   = "poc-${var.tenant_id}-db-credentials"
      secret_data = "auto-generated"
      replication = "multi-region"
    }
    api_keys = {
      secret_id   = "poc-${var.tenant_id}-api-keys"
      secret_data = "auto-generated"
      replication = "multi-region"
    }
    jwt_signing_key = {
      secret_id   = "poc-${var.tenant_id}-jwt-key"
      secret_data = "auto-generated"
      replication = "multi-region"
    }
  }
  
  # Security policies
  security_policies = {
    binary_authorization = true
    pod_security_policy  = true
    network_security_policy = true
    workload_identity    = true
  }
  
  # Audit logging
  audit_config = {
    enable_data_access_logs = true
    enable_admin_activity_logs = true
    log_retention_days = 365
    export_to_bigquery = true
  }
  
  # Vulnerability scanning
  vulnerability_scanning = {
    enable_container_analysis = true
    enable_dependency_scanning = true
    enable_license_scanning   = true
    fail_on_critical_vulnerabilities = true
  }
  
  # Labels
  labels = merge(local.common_tags, {
    Component = "security"
    TenantID  = var.tenant_id
  })
  
  depends_on = [
    module.poc_environment
  ]
}

# Local values for resource allocation tiers
locals {
  # Resource allocation by POC tier
  resource_allocations = {
    standard = {
      cpu_cores    = 8
      memory_gb    = 32
      storage_gb   = 500
      max_users    = 25
      kubernetes = {
        cpu_limit      = "6000m"
        memory_limit   = "24Gi"
        storage_limit  = "400Gi"
        pod_limit      = 100
      }
    }
    enterprise = {
      cpu_cores    = 16
      memory_gb    = 64
      storage_gb   = 1000
      max_users    = 100
      kubernetes = {
        cpu_limit      = "12000m"
        memory_limit   = "48Gi"
        storage_limit  = "800Gi"
        pod_limit      = 200
      }
    }
    premium = {
      cpu_cores    = 32
      memory_gb    = 128
      storage_gb   = 2000
      max_users    = 500
      kubernetes = {
        cpu_limit      = "24000m"
        memory_limit   = "96Gi"
        storage_limit  = "1600Gi"
        pod_limit      = 500
      }
    }
  }
  
  # Database tier mapping
  database_tiers = {
    standard   = "db-custom-4-15360"   # 4 vCPU, 15GB RAM
    enterprise = "db-custom-8-30720"   # 8 vCPU, 30GB RAM  
    premium    = "db-custom-16-61440"  # 16 vCPU, 60GB RAM
  }
  
  # Storage allocation by tier
  storage_allocations = {
    standard   = 200
    enterprise = 500
    premium    = 1000
  }
  
  # Backup retention by tier
  backup_retention_days = {
    standard   = 7
    enterprise = 14
    premium    = 30
  }
}