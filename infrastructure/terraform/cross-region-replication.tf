# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH CROSS-REGION REPLICATION STRATEGY
# Production-grade replication system aligned with Regional Hybrid deployment model
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.7 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.10"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPLICATION STRATEGY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Replication strategy aligned with Regional Hybrid deployment model
  replication_strategy = {
    model = "regional-hybrid"
    description = "Cross-region replication with data residency compliance"
    
    # Active regions that serve traffic and require real-time replication
    active_regions = ["us-central1", "europe-west4", "asia-northeast1"]
    
    # Backup regions for disaster recovery with scheduled replication
    backup_regions = ["us-east1", "europe-west1"]
    
    # Replication patterns by data type
    replication_patterns = {
      # Critical application data - real-time sync within compliance zones
      application_data = {
        strategy = "active-active-within-zone"
        consistency = "strong"
        rpo_minutes = 1
        rto_minutes = 5
        cross_zone_allowed = false  # Data residency compliance
      }
      
      # Session data - regional caching with failover
      session_data = {
        strategy = "regional-primary-backup"
        consistency = "eventual"
        rpo_minutes = 5
        rto_minutes = 2
        cross_zone_allowed = false
      }
      
      # Configuration data - eventual consistency across all regions
      configuration_data = {
        strategy = "multi-master"
        consistency = "eventual"
        rpo_minutes = 15
        rto_minutes = 10
        cross_zone_allowed = true  # Configuration is not personal data
      }
      
      # Audit logs - immutable replication for compliance
      audit_logs = {
        strategy = "append-only-replication"
        consistency = "strong"
        rpo_minutes = 1
        rto_minutes = 30
        cross_zone_allowed = false
        retention_years = 7
      }
    }
    
    # Compliance zone replication rules
    compliance_zones = {
      gdpr = {
        source_regions = ["europe-west4"]
        replica_regions = ["europe-west1"]
        cross_zone_replication = false
        encryption_required = true
        audit_required = true
      }
      ccpa = {
        source_regions = ["us-central1"]
        replica_regions = ["us-east1"]
        cross_zone_replication = false
        encryption_required = true
        audit_required = true
      }
      appi = {
        source_regions = ["asia-northeast1"]
        replica_regions = []  # No backup region in APPI zone currently
        cross_zone_replication = false
        encryption_required = true
        audit_required = true
      }
    }
  }
  
  # Replication configuration for each region
  regional_replication_config = {
    for region, config in local.regions : region => {
      is_active = contains(local.replication_strategy.active_regions, region)
      is_backup = contains(local.replication_strategy.backup_regions, region)
      compliance_zone = config.compliance_zone
      
      # Database replication configuration
      database_replication = {
        create_read_replicas = config.role == "primary" || contains(local.replication_strategy.active_regions, region)
        replica_regions = local.replication_strategy.compliance_zones[config.compliance_zone].replica_regions
        backup_frequency = config.role == "primary" ? "continuous" : "daily"
        point_in_time_recovery = true
        cross_region_automated_backup = false  # Data residency compliance
      }
      
      # Storage replication configuration
      storage_replication = {
        replication_type = config.role == "primary" ? "multi-regional" : "regional"
        nearline_transition_days = 30
        coldline_transition_days = 90
        archive_transition_days = 365
        cross_region_replication = false  # Compliance requirement
      }
      
      # Cache replication configuration
      cache_replication = {
        redis_tier = config.role == "primary" ? "STANDARD_HA" : "BASIC"
        memory_size_gb = config.role == "primary" ? 4 : 1
        read_replicas_count = contains(local.replication_strategy.active_regions, region) ? 2 : 0
        cross_region_sync = false
      }
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE REPLICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Read replicas for high availability within compliance zones
resource "google_sql_database_instance" "regional_read_replicas" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.database_replication.create_read_replicas && length(config.database_replication.replica_regions) > 0
  }
  
  # Create read replica in backup region within same compliance zone
  name                 = "isectech-${each.key}-replica-${var.environment}"
  database_version     = "POSTGRES_15"
  region              = each.value.database_replication.replica_regions[0] # First backup region
  project             = var.project_id
  deletion_protection = var.environment == "production"
  
  # Reference master database
  master_instance_name = google_sql_database_instance.regional_primary[each.key].name
  
  # Replica-specific configuration
  replica_configuration {
    failover_target = true  # Enable automatic failover
  }
  
  settings {
    tier              = var.environment == "production" ? "db-custom-2-8192" : "db-custom-1-4096"
    availability_type = "ZONAL" # Read replicas are zonal by design
    disk_type         = "PD_SSD"
    disk_size         = var.environment == "production" ? 250 : 50
    disk_autoresize   = true
    
    # IP configuration for private access
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.regional_vpc[each.value.database_replication.replica_regions[0]].id
      require_ssl     = true
    }
    
    # Database flags optimized for read replicas
    database_flags {
      name  = "max_connections"
      value = "200"
    }
    database_flags {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    }
    
    # Backup configuration (even for replicas for point-in-time recovery)
    backup_configuration {
      enabled                        = true
      start_time                    = "04:00"  # Different from primary
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
      location = each.value.database_replication.replica_regions[0]
    }
    
    # User labels for compliance tracking
    user_labels = merge(local.common_labels, {
      replica-type      = "read-replica"
      compliance-zone   = each.value.compliance_zone
      master-region     = each.key
      replica-region    = each.value.database_replication.replica_regions[0]
      data-residency    = "enforced"
      replication-mode  = "synchronous"
    })
  }
  
  # Encryption using regional KMS key from replica region
  encryption_key_name = google_kms_crypto_key.sql_key[each.value.database_replication.replica_regions[0]].id
  
  provider = google.${local.regions[each.value.database_replication.replica_regions[0]].provider_alias}
  
  depends_on = [
    google_sql_database_instance.regional_primary
  ]
}

# Cross-region backup for disaster recovery (within compliance zones)
resource "google_sql_backup_run" "cross_region_backup" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.database_replication.create_read_replicas
  }
  
  instance = google_sql_database_instance.regional_primary[each.key].name
  project  = var.project_id
  
  # Backup configuration
  description = "Cross-region disaster recovery backup for ${each.key}"
  type        = "ON_DEMAND"
  
  # Schedule backups during low-traffic periods
  depends_on = [
    google_sql_database_instance.regional_primary
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD STORAGE REPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Dual-region storage buckets for high availability within compliance zones
resource "google_storage_bucket" "dual_region_data" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active && length(local.replication_strategy.compliance_zones[config.compliance_zone].replica_regions) > 0
  }
  
  name     = "isectech-${each.key}-dual-${var.environment}-${random_id.replication_suffix.hex}"
  location = each.key  # Primary location
  project  = var.project_id
  
  force_destroy = var.environment != "production"
  uniform_bucket_level_access = true
  public_access_prevention = "enforced"
  
  # Enable versioning for data protection
  versioning {
    enabled = true
  }
  
  # Lifecycle management for cost optimization
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
  }
  
  # Retention policy for compliance
  retention_policy {
    retention_period = local.compliance_zones[each.value.compliance_zone].retention_days * 24 * 60 * 60  # Convert to seconds
    is_locked        = var.environment == "production"
  }
  
  # Customer-managed encryption
  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_key[each.key].id
  }
  
  # Access logging
  logging {
    log_bucket        = google_storage_bucket.regional_audit_logs[each.key].name
    log_object_prefix = "dual-region-access-logs/"
  }
  
  labels = merge(local.common_labels, {
    storage-type     = "dual-region"
    compliance-zone  = each.value.compliance_zone
    replication-mode = "synchronous"
    data-residency   = "enforced"
    availability     = "high"
  })
  
  provider = google.${local.regions[each.key].provider_alias}
  
  depends_on = [
    google_kms_crypto_key.storage_key
  ]
}

# Transfer jobs for cross-region backup (within compliance zones)
resource "google_storage_transfer_job" "cross_region_backup" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active && length(local.replication_strategy.compliance_zones[config.compliance_zone].replica_regions) > 0
  }
  
  description = "Backup transfer from ${each.key} to ${local.replication_strategy.compliance_zones[each.value.compliance_zone].replica_regions[0]}"
  project     = var.project_id
  
  transfer_spec {
    # Source bucket
    gcs_data_source {
      bucket_name = google_storage_bucket.regional_data[each.key].name
      path        = "backups/"
    }
    
    # Destination bucket in backup region
    gcs_data_sink {
      bucket_name = google_storage_bucket.regional_data[local.replication_strategy.compliance_zones[each.value.compliance_zone].replica_regions[0]].name
      path        = "dr-backups/${each.key}/"
    }
    
    # Transfer options
    object_conditions {
      min_time_elapsed_since_last_modification = "3600s"  # 1 hour
      exclude_prefixes = ["temp/", "cache/"]
    }
    
    transfer_options {
      overwrite_objects_already_existing_in_sink = false
      delete_objects_unique_in_sink = false
      delete_objects_from_source_after_transfer = false
    }
  }
  
  # Schedule daily backup transfers
  schedule {
    schedule_start_date {
      year  = 2025
      month = 1
      day   = 1
    }
    
    start_time_of_day {
      hours   = 2  # 2 AM in source region
      minutes = 0
      seconds = 0
      nanos   = 0
    }
    
    repeat_interval = "86400s"  # 24 hours
  }
  
  status = "ENABLED"
  
  depends_on = [
    google_storage_bucket.regional_data,
    google_storage_bucket.dual_region_data
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# REDIS/MEMORYSTORE REPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Regional Redis instances for session management
resource "google_redis_instance" "regional_cache" {
  for_each = local.regional_replication_config
  
  name               = "isectech-${each.key}-cache-${var.environment}"
  memory_size_gb     = each.value.cache_replication.memory_size_gb
  region             = each.key
  tier               = each.value.cache_replication.redis_tier
  project            = var.project_id
  
  # Network configuration
  authorized_network = google_compute_network.regional_vpc[each.key].id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  
  # Redis configuration
  redis_version       = "REDIS_6_X"
  display_name       = "iSECTECH ${each.key} Cache - ${var.environment}"
  
  # Maintenance policy
  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 3
        minutes = 0
      }
    }
  }
  
  # Enable AUTH for security
  auth_enabled = true
  
  # Transit encryption
  transit_encryption_mode = "SERVER_CLIENT"
  
  # Labels for compliance tracking
  labels = merge(local.common_labels, {
    cache-type       = "session-data"
    compliance-zone  = each.value.compliance_zone
    redis-tier       = lower(each.value.cache_replication.redis_tier)
    data-residency   = "enforced"
  })
  
  provider = google.${local.regions[each.key].provider_alias}
  
  depends_on = [
    google_compute_network.regional_vpc
  ]
}

# Redis backup configuration
resource "google_redis_backup" "daily_cache_backup" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  instance = google_redis_instance.regional_cache[each.key].id
  project  = var.project_id
  
  # Backup retention
  retention_period = "${local.compliance_zones[each.value.compliance_zone].retention_days}d"
  
  depends_on = [
    google_redis_instance.regional_cache
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# APPLICATION STATE REPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Pub/Sub topics for real-time state synchronization within compliance zones
resource "google_pubsub_topic" "state_replication" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  name    = "isectech-${each.key}-state-replication-${var.environment}"
  project = var.project_id
  
  # Message retention for reliability
  message_retention_duration = "86400s"  # 24 hours
  
  # Message storage policy to enforce data residency
  message_storage_policy {
    allowed_persistence_regions = [each.key]
  }
  
  labels = merge(local.common_labels, {
    topic-type       = "state-replication"
    compliance-zone  = each.value.compliance_zone
    data-residency   = "enforced"
  })
  
  provider = google.${local.regions[each.key].provider_alias}
}

# Subscriptions for state synchronization
resource "google_pubsub_subscription" "state_sync_subscription" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  name    = "isectech-${each.key}-state-sync-${var.environment}"
  topic   = google_pubsub_topic.state_replication[each.key].name
  project = var.project_id
  
  # Subscription configuration
  message_retention_duration = "86400s"  # 24 hours
  retain_acked_messages      = false
  ack_deadline_seconds       = 60
  
  # Enable message ordering for consistent state replication
  enable_message_ordering = true
  
  # Dead letter policy
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.state_replication_dlq[each.key].id
    max_delivery_attempts = 10
  }
  
  # Retry policy
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
  
  # Push configuration for real-time processing
  push_config {
    push_endpoint = "https://app-${each.key}.${trimsuffix(var.domain_name, ".")}/api/v1/state-sync"
    
    attributes = {
      region          = each.key
      compliance_zone = each.value.compliance_zone
      environment     = var.environment
    }
    
    # OIDC authentication for security
    oidc_token {
      service_account_email = google_service_account.state_replication[each.key].email
    }
  }
  
  provider = google.${local.regions[each.key].provider_alias}
  
  depends_on = [
    google_pubsub_topic.state_replication
  ]
}

# Dead letter queues for failed state synchronization
resource "google_pubsub_topic" "state_replication_dlq" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  name    = "isectech-${each.key}-state-dlq-${var.environment}"
  project = var.project_id
  
  # Longer retention for troubleshooting
  message_retention_duration = "604800s"  # 7 days
  
  labels = merge(local.common_labels, {
    topic-type       = "dead-letter-queue"
    compliance-zone  = each.value.compliance_zone
  })
  
  provider = google.${local.regions[each.key].provider_alias}
}

# Service accounts for state replication
resource "google_service_account" "state_replication" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  account_id   = "state-replication-${each.key}-${var.environment}"
  display_name = "State Replication Service Account - ${each.key}"
  description  = "Service account for cross-region state replication in ${each.key}"
  project      = var.project_id
  
  provider = google.${local.regions[each.key].provider_alias}
}

# IAM bindings for state replication service accounts
resource "google_project_iam_member" "state_replication_roles" {
  for_each = {
    for region, config in local.regional_replication_config : region => config
    if config.is_active
  }
  
  project = var.project_id
  role    = "roles/pubsub.editor"
  member  = "serviceAccount:${google_service_account.state_replication[each.key].email}"
  
  provider = google.${local.regions[each.key].provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPLICATION MONITORING AND ALERTING
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Functions for replication monitoring
resource "google_storage_bucket" "replication_monitor_function" {
  name     = "isectech-replication-monitor-${var.environment}-${random_id.replication_suffix.hex}"
  location = "US"
  project  = var.project_id
  
  uniform_bucket_level_access = true
  force_destroy = true
  
  labels = merge(local.common_labels, {
    function-type = "replication-monitoring"
  })
}

# Function source code for replication monitoring
resource "google_storage_bucket_object" "replication_monitor_source" {
  name   = "replication-monitor-${random_id.replication_suffix.hex}.zip"
  bucket = google_storage_bucket.replication_monitor_function.name
  source = data.archive_file.replication_monitor_source.output_path
  
  depends_on = [data.archive_file.replication_monitor_source]
}

# Create the function source code
data "archive_file" "replication_monitor_source" {
  type        = "zip"
  output_path = "/tmp/replication-monitor.zip"
  
  source {
    content = templatefile("${path.module}/functions/replication_monitor.py", {
      replication_strategy = jsonencode(local.replication_strategy)
      project_id          = var.project_id
      regions             = jsonencode(local.regions)
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/requirements.txt")
    filename = "requirements.txt"
  }
}

# Cloud Function for replication monitoring
resource "google_cloudfunctions2_function" "replication_monitor" {
  name        = "isectech-replication-monitor-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Monitor cross-region replication health and performance"
  
  build_config {
    runtime     = "python311"
    entry_point = "monitor_replication"
    
    source {
      storage_source {
        bucket = google_storage_bucket.replication_monitor_function.name
        object = google_storage_bucket_object.replication_monitor_source.name
      }
    }
  }
  
  service_config {
    max_instance_count = 10
    available_memory   = "512M"
    timeout_seconds    = 300
    
    environment_variables = {
      PROJECT_ID           = var.project_id
      ENVIRONMENT          = var.environment
      REPLICATION_STRATEGY = jsonencode(local.replication_strategy)
      REGIONS              = jsonencode(local.regions)
    }
    
    service_account_email = google_service_account.replication_monitor.email
  }
  
  # Scheduled trigger every 5 minutes
  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.scheduler.job.v1.executed"
    pubsub_topic   = google_pubsub_topic.replication_monitoring.id
  }
  
  depends_on = [
    google_project_service.cloudfunctions,
    google_storage_bucket_object.replication_monitor_source
  ]
}

# Service account for replication monitoring
resource "google_service_account" "replication_monitor" {
  account_id   = "replication-monitor-${var.environment}"
  display_name = "Replication Monitor Service Account"
  description  = "Service account for monitoring cross-region replication"
  project      = var.project_id
}

# IAM bindings for monitoring service account
resource "google_project_iam_member" "replication_monitor_roles" {
  for_each = toset([
    "roles/cloudsql.viewer",
    "roles/storage.admin",
    "roles/redis.viewer",
    "roles/pubsub.viewer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.replication_monitor.email}"
}

# Pub/Sub topic for replication monitoring events
resource "google_pubsub_topic" "replication_monitoring" {
  name    = "isectech-replication-monitoring-${var.environment}"
  project = var.project_id
  
  labels = merge(local.common_labels, {
    topic-type = "replication-monitoring"
  })
}

# Cloud Scheduler job to trigger monitoring
resource "google_cloud_scheduler_job" "replication_monitor" {
  name             = "isectech-replication-monitor-${var.environment}"
  region           = "us-central1"
  project          = var.project_id
  description      = "Trigger replication monitoring every 5 minutes"
  schedule         = "*/5 * * * *"  # Every 5 minutes
  time_zone        = "UTC"
  attempt_deadline = "300s"
  
  pubsub_target {
    topic_name = google_pubsub_topic.replication_monitoring.id
    data       = base64encode(jsonencode({
      action = "monitor_replication"
      timestamp = timestamp()
    }))
  }
  
  depends_on = [
    google_pubsub_topic.replication_monitoring
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# REPLICATION METRICS AND ALERTING
# ═══════════════════════════════════════════════════════════════════════════════

# Custom metrics for replication monitoring
resource "google_monitoring_metric_descriptor" "replication_lag" {
  type         = "custom.googleapis.com/replication/lag_seconds"
  metric_kind  = "GAUGE"
  value_type   = "DOUBLE"
  description  = "Replication lag in seconds between regions"
  display_name = "Replication Lag"
  
  labels {
    key         = "source_region"
    value_type  = "STRING"
    description = "Source region for replication"
  }
  
  labels {
    key         = "target_region"
    value_type  = "STRING"
    description = "Target region for replication"
  }
  
  labels {
    key         = "data_type"
    value_type  = "STRING"
    description = "Type of data being replicated"
  }
  
  project = var.project_id
}

# Alert policy for replication lag
resource "google_monitoring_alert_policy" "replication_lag_alert" {
  display_name = "Replication Lag Alert - ${var.environment}"
  project      = var.project_id
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "High replication lag detected"
    
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"custom.googleapis.com/replication/lag_seconds\""
      duration        = "300s"  # 5 minutes
      comparison      = "COMPARISON_GT"
      threshold_value = 60  # 1 minute lag threshold
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MAX"
        
        group_by_fields = [
          "metric.labels.source_region",
          "metric.labels.target_region",
          "metric.labels.data_type"
        ]
      }
    }
  }
  
  alert_strategy {
    auto_close = "1800s"  # 30 minutes
  }
  
  notification_channels = [
    google_monitoring_notification_channel.replication_email.id
  ]
  
  documentation {
    content = "Replication lag has exceeded acceptable thresholds. Check replication health and network connectivity."
  }
}

# Email notification channel for replication alerts
resource "google_monitoring_notification_channel" "replication_email" {
  display_name = "Replication Alerts Email"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.operations_email
  }
  
  force_delete = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# RANDOM SUFFIX FOR UNIQUE RESOURCE NAMES
# ═══════════════════════════════════════════════════════════════════════════════

resource "random_id" "replication_suffix" {
  byte_length = 4
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR REPLICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

output "replication_strategy" {
  description = "Cross-region replication strategy configuration"
  value = {
    model                = local.replication_strategy.model
    active_regions       = local.replication_strategy.active_regions
    backup_regions       = local.replication_strategy.backup_regions
    replication_patterns = local.replication_strategy.replication_patterns
    compliance_zones     = local.replication_strategy.compliance_zones
  }
}

output "database_replicas" {
  description = "Database read replica configuration"
  value = {
    for region, instance in google_sql_database_instance.regional_read_replicas : region => {
      replica_name        = instance.name
      master_region       = region
      replica_region      = instance.region
      connection_name     = instance.connection_name
      compliance_zone     = local.regional_replication_config[region].compliance_zone
    }
  }
  sensitive = true
}

output "storage_replication" {
  description = "Storage replication configuration"
  value = {
    for region, bucket in google_storage_bucket.dual_region_data : region => {
      bucket_name      = bucket.name
      location         = bucket.location
      compliance_zone  = local.regional_replication_config[region].compliance_zone
      replication_type = "dual-region"
    }
  }
}

output "cache_instances" {
  description = "Regional cache instance configuration"
  value = {
    for region, instance in google_redis_instance.regional_cache : region => {
      instance_name    = instance.name
      memory_size_gb   = instance.memory_size_gb
      tier            = instance.tier
      compliance_zone = local.regional_replication_config[region].compliance_zone
    }
  }
}

output "state_replication_topics" {
  description = "Pub/Sub topics for state replication"
  value = {
    for region, topic in google_pubsub_topic.state_replication : region => {
      topic_name       = topic.name
      subscription_name = google_pubsub_subscription.state_sync_subscription[region].name
      compliance_zone   = local.regional_replication_config[region].compliance_zone
    }
  }
}

output "monitoring_configuration" {
  description = "Replication monitoring configuration"
  value = {
    monitor_function_name = google_cloudfunctions2_function.replication_monitor.name
    monitoring_topic     = google_pubsub_topic.replication_monitoring.name
    scheduler_job        = google_cloud_scheduler_job.replication_monitor.name
    alert_policy         = google_monitoring_alert_policy.replication_lag_alert.name
    metrics_descriptor   = google_monitoring_metric_descriptor.replication_lag.type
  }
}