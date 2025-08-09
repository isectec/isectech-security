# iSECTECH Google Cloud Infrastructure as Code
# Production-grade GCP infrastructure with comprehensive security
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0 - Google Cloud Platform

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.10"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  backend "gcs" {
    bucket = var.terraform_state_bucket
    prefix = "infrastructure/terraform.tfstate"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "kubernetes" {
  host                   = "https://${module.gke.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.gke.ca_certificate)
}

provider "helm" {
  kubernetes {
    host                   = "https://${module.gke.endpoint}"
    token                  = data.google_client_config.default.access_token
    cluster_ca_certificate = base64decode(module.gke.ca_certificate)
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

data "google_client_config" "default" {}

data "google_project" "project" {
  project_id = var.project_id
}

data "google_compute_zones" "available" {
  region = var.region
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL VALUES
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  cluster_name = "isectech-${var.environment}"
  
  common_labels = {
    project     = "isectech"
    environment = var.environment
    managed-by  = "terraform"
    team        = "devops"
  }
  
  # Environment-specific configurations
  cluster_config = {
    production = {
      node_count                = 3
      min_node_count           = 3
      max_node_count           = 20
      machine_type             = "e2-standard-4"
      disk_size_gb             = 100
      disk_type                = "pd-ssd"
      enable_autoscaling       = true
      enable_autorepair        = true
      enable_autoupgrade       = true
      preemptible              = false
      maintenance_policy       = "MIGRATE"
      enable_private_nodes     = true
      enable_private_endpoint  = false
    }
    staging = {
      node_count               = 2
      min_node_count           = 2
      max_node_count           = 8
      machine_type             = "e2-standard-2"
      disk_size_gb             = 50
      disk_type                = "pd-standard"
      enable_autoscaling       = true
      enable_autorepair        = true
      enable_autoupgrade       = true
      preemptible              = true
      maintenance_policy       = "MIGRATE"
      enable_private_nodes     = true
      enable_private_endpoint  = false
    }
    development = {
      node_count               = 1
      min_node_count           = 1
      max_node_count           = 4
      machine_type             = "e2-medium"
      disk_size_gb             = 30
      disk_type                = "pd-standard"
      enable_autoscaling       = true
      enable_autorepair        = true
      enable_autoupgrade       = true
      preemptible              = true
      maintenance_policy       = "MIGRATE"
      enable_private_nodes     = true
      enable_private_endpoint  = false
    }
  }
  
  # Database configurations
  database_config = {
    production = {
      tier                = "db-custom-2-4096"
      disk_size           = 100
      disk_type           = "PD_SSD"
      backup_enabled      = true
      backup_start_time   = "03:00"
      maintenance_window_day = 7
      maintenance_window_hour = 3
      deletion_protection = true
      high_availability   = true
    }
    staging = {
      tier                = "db-custom-1-2048"
      disk_size           = 50
      disk_type           = "PD_STANDARD"
      backup_enabled      = true
      backup_start_time   = "03:00"
      maintenance_window_day = 7
      maintenance_window_hour = 3
      deletion_protection = false
      high_availability   = false
    }
    development = {
      tier                = "db-f1-micro"
      disk_size           = 20
      disk_type           = "PD_STANDARD"
      backup_enabled      = false
      backup_start_time   = "03:00"
      maintenance_window_day = 7
      maintenance_window_hour = 3
      deletion_protection = false
      high_availability   = false
    }
  }
  
  # Security configurations
  security_config = {
    enable_network_policy            = true
    enable_pod_security_policy       = true
    enable_workload_identity         = true
    enable_shielded_nodes           = true
    enable_binary_authorization     = var.environment == "production"
    enable_istio                    = var.environment == "production"
    enable_private_cluster          = true
    master_ipv4_cidr_block          = "172.16.0.0/28"
    authorized_networks             = var.authorized_networks
    enable_network_policy_config    = true
    enable_intranode_visibility     = true
  }
  
  # Network configuration
  network_config = {
    vpc_cidr              = "10.0.0.0/16"
    subnet_cidr           = "10.0.1.0/24"
    pods_cidr_range       = "10.1.0.0/16"
    services_cidr_range   = "10.2.0.0/16"
    enable_flow_logs      = true
    flow_logs_sampling    = var.environment == "production" ? 1.0 : 0.5
    flow_logs_interval    = "INTERVAL_10_MIN"
    flow_logs_metadata    = "INCLUDE_ALL_METADATA"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# RANDOM RESOURCES FOR SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

resource "random_string" "cluster_suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "random_password" "database_password" {
  length  = 32
  special = true
}

resource "random_password" "redis_auth_string" {
  length  = 32
  special = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC NETWORK MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "vpc" {
  source = "./modules/vpc"
  
  project_id    = var.project_id
  region        = var.region
  environment   = var.environment
  cluster_name  = local.cluster_name
  
  # Network configuration
  vpc_cidr                    = local.network_config.vpc_cidr
  subnet_cidr                 = local.network_config.subnet_cidr
  pods_cidr_range            = local.network_config.pods_cidr_range
  services_cidr_range        = local.network_config.services_cidr_range
  
  # Flow logs configuration
  enable_flow_logs           = local.network_config.enable_flow_logs
  flow_logs_sampling         = local.network_config.flow_logs_sampling
  flow_logs_interval         = local.network_config.flow_logs_interval
  flow_logs_metadata         = local.network_config.flow_logs_metadata
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD KMS MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "kms" {
  source = "./modules/kms"
  
  project_id   = var.project_id
  region       = var.region
  environment  = var.environment
  cluster_name = local.cluster_name
  
  # Key configurations
  key_rotation_period = var.environment == "production" ? "2592000s" : "7776000s" # 30 days prod, 90 days dev
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# GKE CLUSTER MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "gke" {
  source = "./modules/gke"
  
  project_id      = var.project_id
  region          = var.region
  zone            = var.zone
  environment     = var.environment
  cluster_name    = local.cluster_name
  
  # Network configuration
  network_name           = module.vpc.network_name
  subnet_name           = module.vpc.subnet_name
  pods_range_name       = module.vpc.pods_range_name
  services_range_name   = module.vpc.services_range_name
  
  # Cluster configuration
  kubernetes_version             = var.kubernetes_version
  node_count                    = local.cluster_config[var.environment].node_count
  min_node_count               = local.cluster_config[var.environment].min_node_count
  max_node_count               = local.cluster_config[var.environment].max_node_count
  machine_type                 = local.cluster_config[var.environment].machine_type
  disk_size_gb                 = local.cluster_config[var.environment].disk_size_gb
  disk_type                    = local.cluster_config[var.environment].disk_type
  enable_autoscaling           = local.cluster_config[var.environment].enable_autoscaling
  enable_autorepair            = local.cluster_config[var.environment].enable_autorepair
  enable_autoupgrade           = local.cluster_config[var.environment].enable_autoupgrade
  preemptible                  = local.cluster_config[var.environment].preemptible
  
  # Security configuration
  enable_network_policy         = local.security_config.enable_network_policy
  enable_pod_security_policy    = local.security_config.enable_pod_security_policy
  enable_workload_identity      = local.security_config.enable_workload_identity
  enable_shielded_nodes        = local.security_config.enable_shielded_nodes
  enable_binary_authorization  = local.security_config.enable_binary_authorization
  enable_private_cluster       = local.security_config.enable_private_cluster
  enable_private_nodes         = local.cluster_config[var.environment].enable_private_nodes
  enable_private_endpoint      = local.cluster_config[var.environment].enable_private_endpoint
  master_ipv4_cidr_block      = local.security_config.master_ipv4_cidr_block
  authorized_networks         = local.security_config.authorized_networks
  
  # Encryption
  database_encryption_key_name = module.kms.gke_key_id
  
  # Monitoring and logging
  enable_logging_monitoring    = var.enable_logging_monitoring
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD SQL MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "cloud_sql" {
  source = "./modules/cloud-sql"
  
  project_id      = var.project_id
  region          = var.region
  environment     = var.environment
  cluster_name    = local.cluster_name
  
  # Network configuration
  network_id           = module.vpc.network_id
  authorized_networks  = [module.vpc.subnet_cidr]
  
  # Database configuration
  database_version              = var.database_version
  tier                         = local.database_config[var.environment].tier
  disk_size                    = local.database_config[var.environment].disk_size
  disk_type                    = local.database_config[var.environment].disk_type
  backup_enabled               = local.database_config[var.environment].backup_enabled
  backup_start_time            = local.database_config[var.environment].backup_start_time
  maintenance_window_day       = local.database_config[var.environment].maintenance_window_day
  maintenance_window_hour      = local.database_config[var.environment].maintenance_window_hour
  deletion_protection          = local.database_config[var.environment].deletion_protection
  availability_type            = local.database_config[var.environment].high_availability ? "REGIONAL" : "ZONAL"
  
  # Security configuration
  database_flags = [
    {
      name  = "log_checkpoints"
      value = "on"
    },
    {
      name  = "log_connections"
      value = "on"
    },
    {
      name  = "log_disconnections"
      value = "on"
    },
    {
      name  = "log_statement"
      value = "all"
    },
    {
      name  = "log_min_duration_statement"
      value = "1000"
    }
  ]
  
  # Encryption
  kms_key_name = module.kms.sql_key_name
  
  # Database credentials
  database_name     = var.database_name
  database_user     = var.database_user
  database_password = random_password.database_password.result
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS MEMORYSTORE MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "redis" {
  source = "./modules/redis"
  
  project_id      = var.project_id
  region          = var.region
  environment     = var.environment
  cluster_name    = local.cluster_name
  
  # Network configuration
  network_id = module.vpc.network_id
  
  # Redis configuration
  memory_size_gb        = var.redis_memory_size_gb
  redis_version         = var.redis_version
  tier                 = var.environment == "production" ? "STANDARD_HA" : "BASIC"
  auth_enabled         = true
  auth_string          = random_password.redis_auth_string.result
  transit_encryption_mode = "SERVER_AUTH"
  
  # Maintenance configuration
  maintenance_policy = {
    day          = "SUNDAY"
    start_time   = "03:00"
  }
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "monitoring" {
  source = "./modules/monitoring"
  
  project_id      = var.project_id
  region          = var.region
  environment     = var.environment
  cluster_name    = local.cluster_name
  
  # Notification configuration
  notification_email        = var.notification_email
  slack_webhook_url         = var.slack_webhook_url
  pagerduty_integration_key = var.pagerduty_integration_key
  
  # Alert configuration
  enable_slo_monitoring     = var.environment == "production"
  enable_cost_alerts        = true
  enable_security_alerts    = true
  
  # Resource references for monitoring
  gke_cluster_name     = module.gke.cluster_name
  sql_instance_name    = module.cloud_sql.instance_name
  redis_instance_name  = module.redis.instance_name
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS MANAGEMENT MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "dns" {
  source = "./modules/dns"
  
  project_id  = var.project_id
  region      = var.region
  environment = var.environment
  
  # Network configuration for private zones
  vpc_network_id = module.vpc.network_id
  
  # DNS security configuration
  enable_dnssec           = true
  enable_dns_logging      = true
  enable_dns_forwarding   = var.environment == "production"
  enable_private_zones    = false  # Public zones for Cloud Run
  
  # Domain verification codes (from Secret Manager in production)
  google_site_verification_code     = var.environment == "production" ? "" : ""
  microsoft_domain_verification_code = var.environment == "production" ? "" : ""
  custom_verification_code          = var.environment == "production" ? "" : ""
  
  # Email security configuration
  spf_record    = "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
  dmarc_policy  = "v=DMARC1; p=quarantine; rua=mailto:dmarc@isectech.org; ruf=mailto:forensic@isectech.org; fo=1"
  
  # Cloud Run integration
  enable_cloud_run_mapping = true
  cloud_run_services = {
    "app.isectech.org" = {
      service_name = "isectech-frontend"
      region       = var.region
    }
    "api.isectech.org" = {
      service_name = "isectech-backend-services"
      region       = var.region
    }
    "docs.isectech.org" = {
      service_name = "isectech-documentation"
      region       = var.region
    }
    "admin.isectech.org" = {
      service_name = "isectech-admin-panel"
      region       = var.region
    }
    "status.isectech.org" = {
      service_name = "isectech-status-page"
      region       = var.region
    }
  }
  
  # Certificate domains for SSL management
  certificate_domains = [
    "app.isectech.org",
    "api.isectech.org", 
    "docs.isectech.org",
    "admin.isectech.org",
    "status.isectech.org"
  ]
  
  # Monitoring configuration
  enable_dns_monitoring     = var.enable_logging_monitoring
  notification_channels     = module.monitoring.notification_channels
  dns_query_threshold_production    = 50000
  dns_query_threshold_nonproduction = 5000
  dns_failure_threshold            = 100
  
  # Performance optimization
  dns_cache_ttl      = var.environment == "production" ? 300 : 60
  enable_geo_routing = var.environment == "production"
  
  # Compliance configuration
  compliance_frameworks = var.compliance_frameworks
  enable_audit_logging  = true
  data_residency_regions = ["us-central1", "us-east1"]
  
  # Backup configuration
  enable_dns_backup    = true
  backup_retention_days = var.environment == "production" ? 90 : 30
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT REGISTRY MODULE
# ═══════════════════════════════════════════════════════════════════════════════

module "artifact_registry" {
  source = "./modules/artifact-registry"
  
  project_id  = var.project_id
  region      = var.region
  environment = var.environment
  
  # Security configuration
  enable_vulnerability_scanning = true
  enable_binary_authorization  = var.environment == "production"
  workload_identity_sa         = google_service_account.workload.email
  
  # iSECTECH specific services
  isectech_services = [
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
  
  # Cost optimization based on environment
  cleanup_policy_untagged_days = var.environment == "production" ? 14 : 7
  cleanup_policy_keep_versions = var.environment == "production" ? 50 : 20
  production_keep_versions     = 100
  development_keep_versions    = 30
  
  # Compliance configuration
  compliance_frameworks = var.compliance_frameworks
  enable_audit_logging = true
  
  # Monitoring integration
  enable_monitoring      = var.enable_logging_monitoring
  notification_channels  = module.monitoring.notification_channels
  vulnerability_threshold = var.environment == "production" ? 5 : 10
  failed_push_threshold   = var.environment == "production" ? 3 : 5
  
  # CI/CD integration
  ci_cd_service_accounts = [
    "${var.project_id}@cloudbuild.gserviceaccount.com"
  ]
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# WORKLOAD IDENTITY BINDINGS
# ═══════════════════════════════════════════════════════════════════════════════

# Service Account for application workloads
resource "google_service_account" "workload" {
  account_id   = "${local.cluster_name}-workload"
  display_name = "iSECTECH Workload Identity Service Account"
  description  = "Service account for iSECTECH application workloads"
  project      = var.project_id
}

# Workload Identity binding
resource "google_service_account_iam_binding" "workload_identity" {
  service_account_id = google_service_account.workload.name
  role               = "roles/iam.workloadIdentityUser"
  
  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[default/isectech-workload]",
    "serviceAccount:${var.project_id}.svc.id.goog[kube-system/isectech-workload]"
  ]
}

# IAM bindings for application access
resource "google_project_iam_member" "workload_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_project_iam_member" "workload_monitoring_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_project_iam_member" "workload_logging_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_project_iam_member" "workload_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECRET MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

# Database connection secret
resource "google_secret_manager_secret" "database_connection" {
  secret_id = "${local.cluster_name}-database-connection"
  project   = var.project_id
  
  replication {
    auto {}
  }
  
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "database_connection" {
  secret      = google_secret_manager_secret.database_connection.id
  secret_data = jsonencode({
    host     = module.cloud_sql.private_ip_address
    port     = "5432"
    database = var.database_name
    username = var.database_user
    password = random_password.database_password.result
    sslmode  = "require"
  })
}

# Redis connection secret
resource "google_secret_manager_secret" "redis_connection" {
  secret_id = "${local.cluster_name}-redis-connection"
  project   = var.project_id
  
  replication {
    auto {}
  }
  
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "redis_connection" {
  secret      = google_secret_manager_secret.redis_connection.id
  secret_data = jsonencode({
    host        = module.redis.host
    port        = module.redis.port
    auth_string = random_password.redis_auth_string.result
  })
}

# Application secrets
resource "google_secret_manager_secret" "application_secrets" {
  secret_id = "${local.cluster_name}-application-secrets"
  project   = var.project_id
  
  replication {
    auto {}
  }
  
  labels = local.common_labels
}

resource "google_secret_manager_secret_version" "application_secrets" {
  secret      = google_secret_manager_secret.application_secrets.id
  secret_data = jsonencode({
    jwt_secret_key        = base64encode(random_password.database_password.result)
    api_encryption_key    = base64encode(random_password.redis_auth_string.result)
    session_secret        = base64encode("${random_password.database_password.result}${random_password.redis_auth_string.result}")
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# IAM POLICIES FOR SECRET ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_secret_manager_secret_iam_binding" "database_connection" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.database_connection.secret_id
  role      = "roles/secretmanager.secretAccessor"
  
  members = [
    "serviceAccount:${google_service_account.workload.email}"
  ]
}

resource "google_secret_manager_secret_iam_binding" "redis_connection" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.redis_connection.secret_id
  role      = "roles/secretmanager.secretAccessor"
  
  members = [
    "serviceAccount:${google_service_account.workload.email}"
  ]
}

resource "google_secret_manager_secret_iam_binding" "application_secrets" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.application_secrets.secret_id
  role      = "roles/secretmanager.secretAccessor"
  
  members = [
    "serviceAccount:${google_service_account.workload.email}"
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD ARMOR SECURITY POLICY
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_compute_security_policy" "isectech_security_policy" {
  name        = "${local.cluster_name}-security-policy"
  description = "Security policy for iSECTECH applications"
  project     = var.project_id

  # Default rule to deny all traffic
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny all rule"
  }

  # Allow specific CIDR ranges
  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = var.allowed_cidr_ranges
      }
    }
    description = "Allow trusted IP ranges"
  }

  # Rate limiting rule
  rule {
    action   = "rate_based_ban"
    priority = "1500"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action      = "allow"
      exceed_action       = "deny(429)"
      enforce_on_key      = "IP"
      enforce_on_key_name = ""
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      ban_duration_sec = 300
    }
    description = "Rate limiting rule - 100 requests per minute"
  }

  # Block common attack patterns
  rule {
    action   = "deny(403)"
    priority = "2000"
    match {
      expr {
        expression = "origin.region_code == 'CN' || origin.region_code == 'RU'"
      }
    }
    description = "Block traffic from specific regions"
  }

  # SQL injection protection
  rule {
    action   = "deny(403)"
    priority = "2100"
    match {
      expr {
        expression = "has(request.headers['user-agent']) && request.headers['user-agent'].contains('sqlmap')"
      }
    }
    description = "Block SQL injection tools"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Backup plan for persistent volumes
resource "google_gke_backup_backup_plan" "isectech_backup_plan" {
  count = var.enable_backup ? 1 : 0
  
  name     = "${local.cluster_name}-backup-plan"
  cluster  = module.gke.cluster_id
  location = var.region
  project  = var.project_id

  retention_policy {
    backup_delete_lock_days = var.environment == "production" ? 30 : 7
    backup_retain_days     = var.environment == "production" ? 90 : 30
    locked                 = var.environment == "production"
  }

  backup_schedule {
    cron_schedule = var.environment == "production" ? "0 2 * * *" : "0 2 * * 0" # Daily for prod, weekly for others
  }

  backup_config {
    include_volume_data    = true
    include_secrets       = false # Secrets are managed separately
    all_namespaces        = false
    
    selected_namespaces {
      namespaces = ["default", "isectech-app"]
    }
    
    encryption_key {
      gcp_kms_encryption_key = module.kms.backup_key_id
    }
  }
  
  labels = local.common_labels
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR MODULE REFERENCES
# ═══════════════════════════════════════════════════════════════════════════════

# Network outputs
output "network_name" {
  description = "Name of the VPC network"
  value       = module.vpc.network_name
}

output "subnet_name" {
  description = "Name of the subnet"
  value       = module.vpc.subnet_name
}

# GKE outputs  
output "cluster_name" {
  description = "Name of the GKE cluster"
  value       = module.gke.cluster_name
}

output "cluster_endpoint" {
  description = "Endpoint of the GKE cluster"
  value       = module.gke.endpoint
  sensitive   = true
}

# Database outputs
output "database_connection_name" {
  description = "Connection name of the Cloud SQL instance"
  value       = module.cloud_sql.connection_name
}

output "database_private_ip" {
  description = "Private IP address of the Cloud SQL instance"
  value       = module.cloud_sql.private_ip_address
  sensitive   = true
}

# Redis outputs
output "redis_host" {
  description = "Host of the Redis instance"
  value       = module.redis.host
  sensitive   = true
}

# Service account outputs
output "workload_service_account_email" {
  description = "Email of the workload identity service account"
  value       = google_service_account.workload.email
}

# Monitoring outputs
output "monitoring_workspace_name" {
  description = "Name of the monitoring workspace"
  value       = module.monitoring.workspace_name
}

# Security outputs
output "security_policy_name" {
  description = "Name of the Cloud Armor security policy"
  value       = google_compute_security_policy.isectech_security_policy.name
}

# DNS outputs
output "dns_primary_zone_name_servers" {
  description = "Name servers for the primary DNS zone"
  value       = module.dns.primary_zone_name_servers
}

output "dns_domain_configuration" {
  description = "Complete domain configuration for environment"
  value       = module.dns.domain_configuration
}

output "dns_manager_service_account_email" {
  description = "Email of the DNS manager service account"
  value       = module.dns.dns_manager_service_account_email
}