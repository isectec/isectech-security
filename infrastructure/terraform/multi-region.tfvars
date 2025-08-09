# iSECTECH Multi-Region Deployment Configuration
# Production-ready multi-region deployment settings
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Multi-Region Architecture Implementation

# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

project_id                = "isectech-platform"
environment              = "production"
terraform_state_bucket   = "isectech-terraform-state"

# ═══════════════════════════════════════════════════════════════════════════════
# MULTI-REGION DEPLOYMENT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

deployment_model        = "active-active-regional"
primary_region         = "us-central1"

# Primary regions for global coverage and compliance
enabled_regions = [
  "us-central1",     # Primary - US Central, CCPA compliant
  "europe-west4",    # Netherlands - GDPR compliant
  "asia-northeast1"  # Tokyo - APPI compliant
]

# Backup regions for disaster recovery
backup_regions = [
  "us-east1",      # US East Coast backup
  "europe-west1"   # EU backup (Belgium)
]

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND DATA RESIDENCY
# ═══════════════════════════════════════════════════════════════════════════════

data_residency_enforcement = true
cross_region_data_transfer = false

compliance_frameworks = [
  "GDPR",      # European General Data Protection Regulation
  "CCPA",      # California Consumer Privacy Act
  "APPI",      # Japan Act on Protection of Personal Information
  "SOC2",      # Service Organization Control 2
  "ISO27001"   # Information Security Management
]

# ═══════════════════════════════════════════════════════════════════════════════
# DNS AND DOMAIN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

domain_name    = "isectech.org."
enable_dnssec  = true
dns_ttl        = 300

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORKING AND LOAD BALANCING
# ═══════════════════════════════════════════════════════════════════════════════

# Authorized networks for cluster access (update as needed)
authorized_networks = [
  {
    cidr_block   = "10.0.0.0/8"
    display_name = "Private RFC1918 10.x"
  },
  {
    cidr_block   = "172.16.0.0/12"
    display_name = "Private RFC1918 172.x"
  },
  {
    cidr_block   = "192.168.0.0/16"
    display_name = "Private RFC1918 192.x"
  }
]

enable_cross_region_peering = false  # Maintain strict isolation
global_load_balancer_type   = "dns-based"

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

enable_workload_identity     = true
enable_shielded_nodes       = true
enable_binary_authorization = true  # Production security
enable_network_policy       = true

# KMS key rotation every 30 days for production
kms_key_rotation_period = "2592000s"

# ═══════════════════════════════════════════════════════════════════════════════
# KUBERNETES CLUSTER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

kubernetes_version = "1.28"

# Production cluster configuration optimized for multi-region
cluster_configuration = {
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

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING, LOGGING, AND OBSERVABILITY
# ═══════════════════════════════════════════════════════════════════════════════

enable_logging_monitoring = true
enable_audit_logging      = true
log_retention_days        = 90  # 90 days for compliance

# Monitoring notification channels (update with actual channels)
monitoring_notification_channels = [
  # "projects/isectech-platform/notificationChannels/CHANNEL_ID"
]

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP AND DISASTER RECOVERY
# ═══════════════════════════════════════════════════════════════════════════════

enable_backup            = true
backup_retention_days    = 30
backup_schedule          = "0 2 * * *"  # Daily at 2 AM

# Recovery objectives for production
disaster_recovery_rto    = 60   # 1 hour Recovery Time Objective
disaster_recovery_rpo    = 15   # 15 minutes Recovery Point Objective

# ═══════════════════════════════════════════════════════════════════════════════
# COST OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

enable_cost_optimization = true
preemptible_percentage   = 0     # No preemptible nodes in production
auto_scaling_enabled     = true

# Regional resource quotas to prevent cost overruns
resource_quotas = {
  production = {
    cpu_limit     = "200"      # 200 vCPUs per region
    memory_limit  = "800Gi"    # 800 GiB RAM per region
    storage_limit = "2Ti"      # 2 TiB storage per region
  }
  staging = {
    cpu_limit     = "100"      # 100 vCPUs per region
    memory_limit  = "400Gi"    # 400 GiB RAM per region
    storage_limit = "1Ti"      # 1 TiB storage per region
  }
  development = {
    cpu_limit     = "50"       # 50 vCPUs per region
    memory_limit  = "200Gi"    # 200 GiB RAM per region
    storage_limit = "500Gi"    # 500 GiB storage per region
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED FEATURES
# ═══════════════════════════════════════════════════════════════════════════════

enable_istio      = true   # Service mesh for cross-region traffic
enable_anthos     = false  # Not needed for initial deployment
enable_autopilot  = false  # Use standard GKE for more control

# Beta features (use cautiously in production)
enable_beta_features = false

# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Traffic distribution for active-active deployment
traffic_distribution = {
  "us-central1"     = 40  # 40% - Primary US region
  "europe-west4"    = 30  # 30% - Primary EU region
  "asia-northeast1" = 30  # 30% - Primary APAC region
}

health_check_path     = "/health"
health_check_interval = 30  # 30 seconds
enable_health_checks  = true

# ═══════════════════════════════════════════════════════════════════════════════
# RESOURCE LABELS AND TAGGING
# ═══════════════════════════════════════════════════════════════════════════════

additional_labels = {
  project-phase      = "implementation"
  security-tier      = "high"
  compliance-level   = "strict"
  data-sensitivity   = "confidential"
  business-unit      = "security"
  cost-tracking      = "enabled"
}

resource_labels = {
  cost_center       = "infrastructure"
  team             = "devops"
  owner            = "isectech"
  criticality      = "high"
  data_class       = "internal"
  backup_required  = "true"
  deployment_type  = "multi-region"
  compliance_level = "strict"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CROSS-REGION REPLICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Enable cross-region replication aligned with Regional Hybrid deployment model
enable_cross_region_replication = true
replication_model = "regional-hybrid"

# Database replication settings
database_replication_enabled = true

# Storage replication settings  
storage_replication_type = "dual-region"

# Cache replication settings
cache_replication_enabled = true

# Recovery objectives aligned with 99.95% availability target
replication_rpo_minutes = 5   # 5-minute Recovery Point Objective
replication_rto_minutes = 15  # 15-minute Recovery Time Objective

# Monitoring and alerting
replication_monitoring_enabled = true
operations_email = "operations@isectech.org"

# Application state replication
enable_state_replication = true

# Data consistency for compliance
replication_consistency_level = "strong"

# Backup frequency for active regions
replication_backup_frequency = "continuous"