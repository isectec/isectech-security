# iSECTECH Google Cloud Infrastructure Outputs
# Comprehensive output definitions for GCP infrastructure components
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0 - Google Cloud Platform

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT AND ENVIRONMENT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "project_id" {
  description = "Google Cloud Project ID"
  value       = var.project_id
}

output "environment" {
  description = "Environment name"
  value       = var.environment
}

output "region" {
  description = "Google Cloud region"
  value       = var.region
}

output "zone" {
  description = "Google Cloud zone"
  value       = var.zone
}

# ═══════════════════════════════════════════════════════════════════════════════
# VPC NETWORK OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "vpc_network_name" {
  description = "Name of the VPC network"
  value       = module.vpc.network_name
}

output "vpc_network_id" {
  description = "ID of the VPC network"
  value       = module.vpc.network_id
}

output "vpc_network_self_link" {
  description = "Self-link of the VPC network"
  value       = module.vpc.network_self_link
}


output "subnet_id" {
  description = "ID of the primary subnet"
  value       = module.vpc.subnet_id
}

output "subnet_self_link" {
  description = "Self-link of the primary subnet"
  value       = module.vpc.subnet_self_link
}

output "subnet_cidr" {
  description = "CIDR range of the primary subnet"
  value       = module.vpc.subnet_cidr
}

output "pods_range_name" {
  description = "Name of the pods secondary range"
  value       = module.vpc.pods_range_name
}

output "services_range_name" {
  description = "Name of the services secondary range"
  value       = module.vpc.services_range_name
}

output "nat_gateway_ips" {
  description = "External IP addresses of NAT gateways"
  value       = module.vpc.nat_gateway_ips
}

# ═══════════════════════════════════════════════════════════════════════════════
# GKE CLUSTER OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "gke_cluster_name" {
  description = "Name of the GKE cluster"
  value       = module.gke.cluster_name
}

output "gke_cluster_id" {
  description = "ID of the GKE cluster"
  value       = module.gke.cluster_id
}

output "gke_cluster_endpoint" {
  description = "Endpoint URL of the GKE cluster"
  value       = module.gke.endpoint
  sensitive   = true
}

output "gke_cluster_ca_certificate" {
  description = "Cluster CA certificate (base64 encoded)"
  value       = module.gke.ca_certificate
  sensitive   = true
}

output "gke_cluster_master_version" {
  description = "Master version of the GKE cluster"
  value       = module.gke.master_version
}

output "gke_cluster_location" {
  description = "Location of the GKE cluster"
  value       = module.gke.location
}

output "gke_cluster_self_link" {
  description = "Self-link of the GKE cluster"
  value       = module.gke.self_link
}

output "gke_node_pools" {
  description = "Node pools in the GKE cluster"
  value       = module.gke.node_pools
}

output "gke_service_account_email" {
  description = "Email of the GKE service account"
  value       = module.gke.service_account_email
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD SQL OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cloud_sql_instance_name" {
  description = "Name of the Cloud SQL instance"
  value       = module.cloud_sql.instance_name
}

output "cloud_sql_instance_id" {
  description = "ID of the Cloud SQL instance"
  value       = module.cloud_sql.instance_id
}

output "cloud_sql_connection_name" {
  description = "Connection name of the Cloud SQL instance"
  value       = module.cloud_sql.connection_name
}

output "cloud_sql_private_ip_address" {
  description = "Private IP address of the Cloud SQL instance"
  value       = module.cloud_sql.private_ip_address
  sensitive   = true
}

output "cloud_sql_public_ip_address" {
  description = "Public IP address of the Cloud SQL instance"
  value       = module.cloud_sql.public_ip_address
  sensitive   = true
}

output "cloud_sql_database_name" {
  description = "Name of the application database"
  value       = module.cloud_sql.database_name
}

output "cloud_sql_database_user" {
  description = "Username of the application database user"
  value       = module.cloud_sql.database_user
  sensitive   = true
}

output "cloud_sql_self_link" {
  description = "Self-link of the Cloud SQL instance"
  value       = module.cloud_sql.self_link
}

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS MEMORYSTORE OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "redis_instance_name" {
  description = "Name of the Redis instance"
  value       = module.redis.instance_name
}

output "redis_instance_id" {
  description = "ID of the Redis instance"
  value       = module.redis.instance_id
}


output "redis_port" {
  description = "Port of the Redis instance"
  value       = module.redis.port
}

output "redis_auth_string" {
  description = "Auth string for the Redis instance"
  value       = module.redis.auth_string
  sensitive   = true
}

output "redis_memory_size_gb" {
  description = "Memory size of the Redis instance in GB"
  value       = module.redis.memory_size_gb
}

output "redis_version" {
  description = "Redis version"
  value       = module.redis.redis_version
}

# ═══════════════════════════════════════════════════════════════════════════════
# KMS ENCRYPTION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "kms_keyring_name" {
  description = "Name of the KMS keyring"
  value       = module.kms.keyring_name
}

output "kms_keyring_id" {
  description = "ID of the KMS keyring"
  value       = module.kms.keyring_id
}

output "kms_gke_key_name" {
  description = "Name of the KMS key for GKE encryption"
  value       = module.kms.gke_key_name
}

output "kms_gke_key_id" {
  description = "ID of the KMS key for GKE encryption"
  value       = module.kms.gke_key_id
}

output "kms_sql_key_name" {
  description = "Name of the KMS key for Cloud SQL encryption"
  value       = module.kms.sql_key_name
}

output "kms_sql_key_id" {
  description = "ID of the KMS key for Cloud SQL encryption"
  value       = module.kms.sql_key_id
}

output "kms_backup_key_name" {
  description = "Name of the KMS key for backup encryption"
  value       = module.kms.backup_key_name
}

output "kms_backup_key_id" {
  description = "ID of the KMS key for backup encryption"
  value       = module.kms.backup_key_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════


output "monitoring_notification_channels" {
  description = "Monitoring notification channels"
  value       = module.monitoring.notification_channels
  sensitive   = true
}

output "monitoring_alert_policies" {
  description = "Monitoring alert policies"
  value       = module.monitoring.alert_policies
}

output "monitoring_dashboards" {
  description = "Monitoring dashboards"
  value       = module.monitoring.dashboards
}

output "monitoring_slo_names" {
  description = "Names of the SLO definitions"
  value       = module.monitoring.slo_names
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "workload_service_account_name" {
  description = "Name of the workload identity service account"
  value       = google_service_account.workload.name
}


output "workload_service_account_id" {
  description = "ID of the workload identity service account"
  value       = google_service_account.workload.id
}

output "workload_service_account_unique_id" {
  description = "Unique ID of the workload identity service account"
  value       = google_service_account.workload.unique_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECRET MANAGER OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "secret_database_connection_name" {
  description = "Name of the database connection secret"
  value       = google_secret_manager_secret.database_connection.secret_id
}

output "secret_database_connection_id" {
  description = "ID of the database connection secret"
  value       = google_secret_manager_secret.database_connection.id
}

output "secret_redis_connection_name" {
  description = "Name of the Redis connection secret"
  value       = google_secret_manager_secret.redis_connection.secret_id
}

output "secret_redis_connection_id" {
  description = "ID of the Redis connection secret"
  value       = google_secret_manager_secret.redis_connection.id
}

output "secret_application_secrets_name" {
  description = "Name of the application secrets"
  value       = google_secret_manager_secret.application_secrets.secret_id
}

output "secret_application_secrets_id" {
  description = "ID of the application secrets"
  value       = google_secret_manager_secret.application_secrets.id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cloud_armor_security_policy_name" {
  description = "Name of the Cloud Armor security policy"
  value       = google_compute_security_policy.isectech_security_policy.name
}

output "cloud_armor_security_policy_id" {
  description = "ID of the Cloud Armor security policy"
  value       = google_compute_security_policy.isectech_security_policy.id
}

output "cloud_armor_security_policy_self_link" {
  description = "Self-link of the Cloud Armor security policy"
  value       = google_compute_security_policy.isectech_security_policy.self_link
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "backup_plan_name" {
  description = "Name of the GKE backup plan"
  value       = var.enable_backup ? google_gke_backup_backup_plan.isectech_backup_plan[0].name : null
}

output "backup_plan_id" {
  description = "ID of the GKE backup plan"
  value       = var.enable_backup ? google_gke_backup_backup_plan.isectech_backup_plan[0].id : null
}

# ═══════════════════════════════════════════════════════════════════════════════
# KUBECTL CONFIGURATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "kubectl_config" {
  description = "kubectl configuration for accessing the cluster"
  value = {
    cluster_name                = module.gke.cluster_name
    cluster_endpoint           = module.gke.endpoint
    cluster_ca_certificate     = module.gke.ca_certificate
    cluster_region             = var.region
    cluster_zone               = var.zone
    cluster_master_version     = module.gke.master_version
    project_id                 = var.project_id
  }
  sensitive = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONNECTION COMMANDS OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "connection_commands" {
  description = "Commands to connect to various services"
  value = {
    gke_get_credentials = "gcloud container clusters get-credentials ${module.gke.cluster_name} --region ${var.region} --project ${var.project_id}"
    kubectl_cluster_info = "kubectl cluster-info"
    kubectl_get_nodes    = "kubectl get nodes"
    cloud_sql_proxy      = "cloud-sql-proxy --instances=${module.cloud_sql.connection_name}=tcp:5432"
    redis_cli            = "redis-cli -h ${module.redis.host} -p ${module.redis.port} -a [AUTH_STRING]"
  }
  sensitive = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT INFORMATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "deployment_info" {
  description = "Comprehensive deployment information"
  value = {
    project_id                     = var.project_id
    environment                    = var.environment
    region                         = var.region
    zone                          = var.zone
    cluster_name                  = module.gke.cluster_name
    cluster_endpoint              = module.gke.endpoint
    vpc_network_name              = module.vpc.network_name
    subnet_name                   = module.vpc.subnet_name
    database_instance_name        = module.cloud_sql.instance_name
    redis_instance_name           = module.redis.instance_name
    workload_service_account      = google_service_account.workload.email
    kms_keyring_name              = module.kms.keyring_name
    monitoring_workspace          = module.monitoring.workspace_name
    security_policy_name          = google_compute_security_policy.isectech_security_policy.name
    backup_enabled                = var.enable_backup
    created_timestamp             = timestamp()
  }
  sensitive = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY COMPLIANCE OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "security_compliance" {
  description = "Security and compliance configuration status"
  value = {
    workload_identity_enabled      = var.enable_workload_identity
    network_policy_enabled         = var.enable_network_policy
    pod_security_policy_enabled    = var.enable_pod_security_policy
    shielded_nodes_enabled         = var.enable_shielded_nodes
    binary_authorization_enabled   = var.enable_binary_authorization
    envelope_encryption_enabled    = var.enable_envelope_encryption
    private_nodes_enabled          = var.enable_private_nodes
    private_endpoint_enabled       = var.enable_private_endpoint
    audit_logging_enabled          = var.enable_audit_logging
    vulnerability_scanning_enabled = var.enable_vulnerability_scanning
    compliance_frameworks          = var.compliance_frameworks
    cloud_armor_enabled            = true
    kms_encryption_enabled         = true
    secret_manager_integration     = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cost_optimization" {
  description = "Cost optimization features and configurations"
  value = {
    preemptible_nodes_enabled       = var.enable_preemptible_nodes
    cluster_autoscaling_enabled     = var.enable_cluster_autoscaling
    horizontal_pod_autoscaling      = var.enable_horizontal_pod_autoscaling
    vertical_pod_autoscaling        = var.enable_vertical_pod_autoscaling
    node_auto_provisioning_enabled  = var.enable_node_auto_provisioning
    spot_instances_enabled          = var.enable_spot_instances
    cost_optimization_enabled       = var.enable_cost_optimization
    environment                     = var.environment
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORKING DETAILS OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "networking_details" {
  description = "Detailed networking configuration"
  value = {
    vpc_cidr                       = module.vpc.network_cidr
    subnet_cidr                    = module.vpc.subnet_cidr
    pods_cidr_range                = var.pods_cidr_range
    services_cidr_range            = var.services_cidr_range
    master_ipv4_cidr_block         = var.master_ipv4_cidr_block
    nat_gateway_ips                = module.vpc.nat_gateway_ips
    private_cluster_enabled        = local.security_config.enable_private_cluster
    network_policy_enabled         = var.enable_network_policy
    intranode_visibility_enabled   = var.enable_intranode_visibility
    datapath_provider              = var.datapath_provider
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# RESOURCE LABELS OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "resource_labels" {
  description = "Common labels applied to all resources"
  value = merge(
    local.common_labels,
    var.additional_labels,
    {
      cost-center         = var.resource_labels.cost_center
      team               = var.resource_labels.team
      owner              = var.resource_labels.owner
      criticality        = var.resource_labels.criticality
      data-class         = var.resource_labels.data_class
      backup-required    = var.resource_labels.backup_required
    }
  )
}

# ═══════════════════════════════════════════════════════════════════════════════
# OPERATIONAL OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "operational_info" {
  description = "Operational information and maintenance details"
  value = {
    maintenance_window_start      = var.maintenance_window_start_time
    maintenance_window_duration   = var.maintenance_window_duration
    maintenance_window_recurrence = var.maintenance_window_recurrence
    auto_upgrade_nodes           = var.auto_upgrade_nodes
    auto_repair_nodes            = var.auto_repair_nodes
    backup_schedule              = var.backup_schedule
    backup_retention_days        = var.backup_retention_days
    kms_key_rotation_period      = var.kms_key_rotation_period
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "feature_flags" {
  description = "Enabled feature flags and experimental features"
  value = {
    alpha_features_enabled           = var.enable_alpha_features
    beta_features_enabled            = var.enable_beta_features
    istio_enabled                   = var.enable_istio
    cloudrun_enabled                = var.enable_cloudrun
    config_connector_enabled        = var.enable_config_connector
    gpu_nodes_enabled               = var.enable_gpu_nodes
    gpu_type                        = var.enable_gpu_nodes ? var.gpu_type : null
    gpu_count                       = var.enable_gpu_nodes ? var.gpu_count : null
    image_streaming_enabled         = var.enable_image_streaming
    dns_cache_enabled               = var.enable_dns_cache
    http_load_balancing_enabled     = var.enable_http_load_balancing
    network_policy_enforcement      = var.enable_network_policy_enforcement
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION ENDPOINTS OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "integration_endpoints" {
  description = "Integration endpoints for external systems"
  value = {
    monitoring_workspace_url = "https://console.cloud.google.com/monitoring/workspaces?project=${var.project_id}"
    logging_url             = "https://console.cloud.google.com/logs/query?project=${var.project_id}"
    gke_workloads_url       = "https://console.cloud.google.com/kubernetes/workload/overview?project=${var.project_id}"
    cloud_sql_url           = "https://console.cloud.google.com/sql/instances?project=${var.project_id}"
    secret_manager_url      = "https://console.cloud.google.com/security/secret-manager?project=${var.project_id}"
    kms_url                 = "https://console.cloud.google.com/security/kms?project=${var.project_id}"
    vpc_networks_url        = "https://console.cloud.google.com/networking/networks/list?project=${var.project_id}"
    backup_url              = var.enable_backup ? "https://console.cloud.google.com/kubernetes/backup/overview?project=${var.project_id}" : null
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

output "infrastructure_summary" {
  description = "High-level summary of deployed infrastructure"
  value = {
    description = "iSECTECH Security Platform - Google Cloud Infrastructure"
    version     = "2.0.0"
    
    # Core Infrastructure
    project_id          = var.project_id
    environment         = var.environment
    region             = var.region
    
    # Major Components
    gke_cluster        = module.gke.cluster_name
    vpc_network        = module.vpc.network_name
    database           = module.cloud_sql.instance_name
    redis_cache        = module.redis.instance_name
    
    # Security Features
    encryption_at_rest = var.enable_envelope_encryption
    private_cluster    = var.enable_private_nodes
    workload_identity  = var.enable_workload_identity
    network_policies   = var.enable_network_policy
    
    # Monitoring & Compliance
    monitoring_enabled = var.enable_logging_monitoring
    backup_enabled     = var.enable_backup
    compliance_frameworks = var.compliance_frameworks
    
    # Cost Optimization
    autoscaling_enabled = var.enable_cluster_autoscaling
    preemptible_nodes   = var.enable_preemptible_nodes
    
    deployment_timestamp = timestamp()
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT REGISTRY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "artifact_registry_main_repository_url" {
  description = "URL of the main Docker repository"
  value       = module.artifact_registry.main_repository_url
}

output "artifact_registry_environment_repositories" {
  description = "Map of environment repository information"
  value       = module.artifact_registry.environment_repositories
  sensitive   = true
}

output "artifact_registry_security_tools_repository" {
  description = "Security tools repository information"
  value       = module.artifact_registry.security_tools_repository
  sensitive   = true
}

output "artifact_registry_ci_cd_service_account" {
  description = "CI/CD service account for registry access"
  value       = module.artifact_registry.ci_cd_service_account_email
}

output "artifact_registry_runtime_service_account" {
  description = "Runtime service account for image pulling"
  value       = module.artifact_registry.runtime_service_account_email
}

output "artifact_registry_docker_config_commands" {
  description = "Docker configuration commands for authentication"
  value       = module.artifact_registry.docker_config_commands
}

output "artifact_registry_image_tagging_strategy" {
  description = "Recommended image tagging strategy for iSECTECH services"
  value       = module.artifact_registry.image_tagging_strategy
  sensitive   = true
}

output "artifact_registry_cloud_build_integration" {
  description = "Cloud Build integration configuration"
  value       = module.artifact_registry.cloud_build_integration
  sensitive   = true
}

output "artifact_registry_github_actions_config" {
  description = "GitHub Actions configuration for iSECTECH CI/CD"
  value       = module.artifact_registry.github_actions_config
  sensitive   = true
}