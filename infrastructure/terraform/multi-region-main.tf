# iSECTECH Multi-Region Deployment Architecture
# Production-grade multi-region GCP infrastructure with global load balancing
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Multi-Region Architecture Implementation

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
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
  
  backend "gcs" {
    bucket = var.terraform_state_bucket
    prefix = "multi-region/terraform.tfstate"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PROVIDER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Primary provider for us-central1
provider "google" {
  alias   = "us-central1"
  project = var.project_id
  region  = "us-central1"
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    region-role         = "primary"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

# European provider for europe-west4
provider "google" {
  alias   = "europe-west4"
  project = var.project_id
  region  = "europe-west4"
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    region-role         = "secondary"
    compliance-zone     = "gdpr"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

# Asian provider for asia-northeast1
provider "google" {
  alias   = "asia-northeast1"
  project = var.project_id
  region  = "asia-northeast1"
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    region-role         = "secondary"
    compliance-zone     = "appi"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

# US East backup provider
provider "google" {
  alias   = "us-east1"
  project = var.project_id
  region  = "us-east1"
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    region-role         = "backup"
    compliance-zone     = "ccpa"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

# EU backup provider
provider "google" {
  alias   = "europe-west1"
  project = var.project_id
  region  = "europe-west1"
  
  default_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    region-role         = "backup"
    compliance-zone     = "gdpr"
    cost-center         = "infrastructure"
    security-compliance = "required"
    data-classification = "internal"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES
# ═══════════════════════════════════════════════════════════════════════════════

data "google_project" "project" {
  project_id = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL VALUES FOR MULTI-REGION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Multi-region configuration
  regions = {
    "us-central1" = {
      provider_alias     = "us-central1"
      zone              = "us-central1-a"
      role              = "primary"
      compliance_zone   = "ccpa"
      vpc_cidr         = "10.0.0.0/16"
      subnet_cidr      = "10.0.1.0/24"
      pods_cidr        = "10.1.0.0/16"
      services_cidr    = "10.2.0.0/16"
      priority         = 1
    }
    "europe-west4" = {
      provider_alias     = "europe-west4"
      zone              = "europe-west4-a"
      role              = "secondary"
      compliance_zone   = "gdpr"
      vpc_cidr         = "10.10.0.0/16"
      subnet_cidr      = "10.10.1.0/24"
      pods_cidr        = "10.11.0.0/16"
      services_cidr    = "10.12.0.0/16"
      priority         = 2
    }
    "asia-northeast1" = {
      provider_alias     = "asia-northeast1"
      zone              = "asia-northeast1-a"
      role              = "secondary"
      compliance_zone   = "appi"
      vpc_cidr         = "10.20.0.0/16"
      subnet_cidr      = "10.20.1.0/24"
      pods_cidr        = "10.21.0.0/16"
      services_cidr    = "10.22.0.0/16"
      priority         = 3
    }
    "us-east1" = {
      provider_alias     = "us-east1"
      zone              = "us-east1-b"
      role              = "backup"
      compliance_zone   = "ccpa"
      vpc_cidr         = "10.30.0.0/16"
      subnet_cidr      = "10.30.1.0/24"
      pods_cidr        = "10.31.0.0/16"
      services_cidr    = "10.32.0.0/16"
      priority         = 4
    }
    "europe-west1" = {
      provider_alias     = "europe-west1"
      zone              = "europe-west1-b"
      role              = "backup"
      compliance_zone   = "gdpr"
      vpc_cidr         = "10.40.0.0/16"
      subnet_cidr      = "10.40.1.0/24"
      pods_cidr        = "10.41.0.0/16"
      services_cidr    = "10.42.0.0/16"
      priority         = 5
    }
  }
  
  common_labels = {
    project             = "isectech"
    environment         = var.environment
    managed-by          = "terraform"
    team                = "devops"
    deployment-type     = "multi-region"
    cost-center         = "infrastructure"
    security-compliance = "required"
  }
  
  # Environment-specific cluster configurations
  cluster_config = {
    production = {
      node_count           = 3
      min_node_count       = 3
      max_node_count       = 20
      machine_type         = "e2-standard-4"
      disk_size_gb         = 100
      disk_type            = "pd-ssd"
      enable_autoscaling   = true
      enable_autorepair    = true
      enable_autoupgrade   = true
      preemptible          = false
      enable_private_nodes = true
    }
    staging = {
      node_count           = 2
      min_node_count       = 2
      max_node_count       = 8
      machine_type         = "e2-standard-2"
      disk_size_gb         = 50
      disk_type            = "pd-standard"
      enable_autoscaling   = true
      enable_autorepair    = true
      enable_autoupgrade   = true
      preemptible          = true
      enable_private_nodes = true
    }
    development = {
      node_count           = 1
      min_node_count       = 1
      max_node_count       = 4
      machine_type         = "e2-medium"
      disk_size_gb         = 30
      disk_type            = "pd-standard"
      enable_autoscaling   = true
      enable_autorepair    = true
      enable_autoupgrade   = true
      preemptible          = true
      enable_private_nodes = true
    }
  }
  
  # Security configuration for all regions
  security_config = {
    enable_network_policy            = true
    enable_pod_security_policy       = true
    enable_workload_identity         = true
    enable_shielded_nodes           = true
    enable_binary_authorization     = var.environment == "production"
    enable_private_cluster          = true
    master_ipv4_cidr_blocks = {
      "us-central1"     = "172.16.0.0/28"
      "europe-west4"    = "172.17.0.0/28"
      "asia-northeast1" = "172.18.0.0/28"
      "us-east1"        = "172.19.0.0/28"
      "europe-west1"    = "172.20.0.0/28"
    }
    authorized_networks             = var.authorized_networks
    enable_network_policy_config    = true
    enable_intranode_visibility     = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-REGION VPC NETWORKS
# ═══════════════════════════════════════════════════════════════════════════════

# Create separate VPC for each region with proper isolation
resource "google_compute_network" "regional_vpc" {
  for_each = local.regions
  
  name                    = "isectech-${each.key}-${var.environment}"
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"
  project                = var.project_id
  
  # Use provider alias for regional deployment
  provider = google.${each.value.provider_alias}
}

# Regional subnets with compliance-aware CIDR allocation
resource "google_compute_subnetwork" "regional_subnet" {
  for_each = local.regions
  
  name          = "isectech-${each.key}-subnet-${var.environment}"
  ip_cidr_range = each.value.subnet_cidr
  region        = each.key
  network       = google_compute_network.regional_vpc[each.key].id
  project       = var.project_id
  
  # Secondary ranges for Kubernetes
  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = each.value.pods_cidr
  }
  
  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = each.value.services_cidr
  }
  
  # Enable flow logs for security monitoring
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = var.environment == "production" ? 1.0 : 0.5
    metadata             = "INCLUDE_ALL_METADATA"
    metadata_fields      = []
    filter_expr          = "true"
  }
  
  # Private Google access for security
  private_ip_google_access = true
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL CLOUD NAT FOR PRIVATE CLUSTERS
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Router for each region
resource "google_compute_router" "regional_router" {
  for_each = local.regions
  
  name    = "isectech-${each.key}-router-${var.environment}"
  region  = each.key
  network = google_compute_network.regional_vpc[each.key].id
  project = var.project_id
  
  provider = google.${each.value.provider_alias}
}

# Cloud NAT for each region (required for private clusters)
resource "google_compute_router_nat" "regional_nat" {
  for_each = local.regions
  
  name                               = "isectech-${each.key}-nat-${var.environment}"
  router                            = google_compute_router.regional_router[each.key].name
  region                            = each.key
  nat_ip_allocate_option           = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  project                          = var.project_id
  
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL KMS KEYS FOR DATA ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════════

# Regional KMS keyrings for data sovereignty
resource "google_kms_key_ring" "regional_keyring" {
  for_each = local.regions
  
  name     = "isectech-${each.key}-keyring-${var.environment}"
  location = each.key
  project  = var.project_id
  
  provider = google.${each.value.provider_alias}
}

# GKE encryption keys
resource "google_kms_crypto_key" "gke_key" {
  for_each = local.regions
  
  name     = "isectech-${each.key}-gke-key-${var.environment}"
  key_ring = google_kms_key_ring.regional_keyring[each.key].id
  purpose  = "ENCRYPT_DECRYPT"
  
  rotation_period = var.environment == "production" ? "2592000s" : "7776000s"
  
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }
  
  provider = google.${each.value.provider_alias}
}

# Database encryption keys
resource "google_kms_crypto_key" "sql_key" {
  for_each = local.regions
  
  name     = "isectech-${each.key}-sql-key-${var.environment}"
  key_ring = google_kms_key_ring.regional_keyring[each.key].id
  purpose  = "ENCRYPT_DECRYPT"
  
  rotation_period = var.environment == "production" ? "2592000s" : "7776000s"
  
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL GKE CLUSTERS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional GKE clusters with private nodes and workload identity
resource "google_container_cluster" "regional_cluster" {
  for_each = local.regions
  
  name     = "isectech-${each.key}-${var.environment}"
  location = each.key
  project  = var.project_id
  
  # Remove default node pool to use custom node pool
  remove_default_node_pool = true
  initial_node_count       = 1
  
  # Network configuration
  network    = google_compute_network.regional_vpc[each.key].id
  subnetwork = google_compute_subnetwork.regional_subnet[each.key].id
  
  # IP allocation policy for pods and services
  ip_allocation_policy {
    cluster_secondary_range_name  = "pods"
    services_secondary_range_name = "services"
  }
  
  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = local.security_config.master_ipv4_cidr_blocks[each.key]
  }
  
  # Master authorized networks
  dynamic "master_authorized_networks_config" {
    for_each = length(var.authorized_networks) > 0 ? [1] : []
    content {
      dynamic "cidr_blocks" {
        for_each = var.authorized_networks
        content {
          cidr_block   = cidr_blocks.value.cidr_block
          display_name = cidr_blocks.value.display_name
        }
      }
    }
  }
  
  # Workload Identity
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }
  
  # Network policy
  network_policy {
    enabled = true
  }
  
  # Database encryption
  database_encryption {
    state    = "ENCRYPTED"
    key_name = google_kms_crypto_key.gke_key[each.key].id
  }
  
  # Release channel
  release_channel {
    channel = var.environment == "production" ? "REGULAR" : "RAPID"
  }
  
  # Enable shielded nodes
  enable_shielded_nodes = true
  
  # Monitoring and logging
  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"
  
  # Maintenance policy
  maintenance_policy {
    daily_maintenance_window {
      start_time = "03:00"
    }
  }
  
  # Addons configuration
  addons_config {
    http_load_balancing {
      disabled = false
    }
    
    horizontal_pod_autoscaling {
      disabled = false
    }
    
    network_policy_config {
      disabled = false
    }
    
    dns_cache_config {
      enabled = true
    }
  }
  
  # Binary authorization (production only)
  dynamic "binary_authorization" {
    for_each = var.environment == "production" ? [1] : []
    content {
      evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
    }
  }
  
  # Resource labels for compliance and cost tracking
  resource_labels = merge(local.common_labels, {
    region           = each.key
    region-role      = each.value.role
    compliance-zone  = each.value.compliance_zone
    cluster-priority = tostring(each.value.priority)
  })
  
  provider = google.${each.value.provider_alias}
}

# Regional node pools with compliance-aware configuration
resource "google_container_node_pool" "regional_node_pool" {
  for_each = local.regions
  
  name       = "isectech-${each.key}-nodes-${var.environment}"
  location   = each.key
  cluster    = google_container_cluster.regional_cluster[each.key].name
  project    = var.project_id
  
  # Node configuration based on environment
  node_count = local.cluster_config[var.environment].node_count
  
  # Autoscaling
  autoscaling {
    min_node_count = local.cluster_config[var.environment].min_node_count
    max_node_count = local.cluster_config[var.environment].max_node_count
  }
  
  # Management
  management {
    auto_repair  = local.cluster_config[var.environment].enable_autorepair
    auto_upgrade = local.cluster_config[var.environment].enable_autoupgrade
  }
  
  # Node configuration
  node_config {
    preemptible  = local.cluster_config[var.environment].preemptible
    machine_type = local.cluster_config[var.environment].machine_type
    
    # Google service account
    service_account = google_service_account.regional_workload[each.key].email
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/trace.append",
    ]
    
    # Boot disk configuration
    disk_size_gb = local.cluster_config[var.environment].disk_size_gb
    disk_type    = local.cluster_config[var.environment].disk_type
    image_type   = "COS_CONTAINERD"
    
    # Shielded instance config
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    
    # Workload metadata config
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
    
    # Metadata
    metadata = {
      disable-legacy-endpoints = "true"
    }
    
    # Labels for compliance
    labels = merge(local.common_labels, {
      region          = each.key
      compliance-zone = each.value.compliance_zone
      node-role       = "worker"
    })
    
    # Taints for workload isolation (if needed)
    dynamic "taint" {
      for_each = each.value.role == "backup" ? [1] : []
      content {
        key    = "backup-node"
        value  = "true"
        effect = "NO_SCHEDULE"
      }
    }
  }
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL SERVICE ACCOUNTS FOR WORKLOAD IDENTITY
# ═══════════════════════════════════════════════════════════════════════════════

# Service accounts for each regional workload
resource "google_service_account" "regional_workload" {
  for_each = local.regions
  
  account_id   = "isectech-${each.key}-workload-${var.environment}"
  display_name = "iSECTECH ${each.key} Workload Identity Service Account"
  description  = "Service account for iSECTECH workloads in ${each.key}"
  project      = var.project_id
  
  provider = google.${each.value.provider_alias}
}

# Workload Identity bindings for each region
resource "google_service_account_iam_binding" "regional_workload_identity" {
  for_each = local.regions
  
  service_account_id = google_service_account.regional_workload[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  
  members = [
    "serviceAccount:${var.project_id}.svc.id.goog[default/isectech-workload]",
    "serviceAccount:${var.project_id}.svc.id.goog[kube-system/isectech-workload]"
  ]
  
  provider = google.${each.value.provider_alias}
}

# IAM bindings for regional workloads
resource "google_project_iam_member" "regional_workload_sql_client" {
  for_each = local.regions
  
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.regional_workload[each.key].email}"
  
  provider = google.${each.value.provider_alias}
}

resource "google_project_iam_member" "regional_workload_monitoring_writer" {
  for_each = local.regions
  
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.regional_workload[each.key].email}"
  
  provider = google.${each.value.provider_alias}
}

resource "google_project_iam_member" "regional_workload_logging_writer" {
  for_each = local.regions
  
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.regional_workload[each.key].email}"
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR MULTI-REGION REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════

output "regional_clusters" {
  description = "Map of regional GKE cluster information"
  value = {
    for region, config in local.regions : region => {
      cluster_name     = google_container_cluster.regional_cluster[region].name
      cluster_endpoint = google_container_cluster.regional_cluster[region].endpoint
      region          = region
      role            = config.role
      compliance_zone = config.compliance_zone
      vpc_network     = google_compute_network.regional_vpc[region].name
      subnet_name     = google_compute_subnetwork.regional_subnet[region].name
    }
  }
  sensitive = true
}

output "regional_service_accounts" {
  description = "Map of regional service account emails"
  value = {
    for region in keys(local.regions) : region => google_service_account.regional_workload[region].email
  }
}

output "kms_keys" {
  description = "Map of regional KMS keys"
  value = {
    for region in keys(local.regions) : region => {
      gke_key = google_kms_crypto_key.gke_key[region].id
      sql_key = google_kms_crypto_key.sql_key[region].id
    }
  }
}

output "network_configuration" {
  description = "Regional network configuration summary"
  value = {
    for region, config in local.regions : region => {
      vpc_cidr      = config.vpc_cidr
      subnet_cidr   = config.subnet_cidr
      pods_cidr     = config.pods_cidr
      services_cidr = config.services_cidr
      nat_ip        = google_compute_router_nat.regional_nat[region].name
    }
  }
}