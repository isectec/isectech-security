# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH DATA RESIDENCY AND SOVEREIGNTY ENFORCEMENT
# Production-grade compliance system for GDPR, CCPA, and APPI
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.5 Implementation
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
# DATA RESIDENCY POLICY DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Compliance zone definitions with strict data residency rules
  compliance_zones = {
    gdpr = {
      regions              = ["europe-west4", "europe-west1"]
      allowed_countries    = ["DE", "NL", "FR", "BE", "IT", "ES", "AT"]
      data_export_allowed  = false
      retention_days       = 365
      encryption_required  = true
      pseudonymization     = true
      right_to_deletion    = true
      data_portability     = true
      consent_required     = true
      dpo_required         = true
      breach_notification_hours = 72
    }
    ccpa = {
      regions              = ["us-central1", "us-east1"]
      allowed_countries    = ["US"]
      data_export_allowed  = false
      retention_days       = 730
      encryption_required  = true
      pseudonymization     = false
      right_to_deletion    = true
      data_portability     = true
      consent_required     = false
      dpo_required         = false
      breach_notification_hours = 72
    }
    appi = {
      regions              = ["asia-northeast1"]
      allowed_countries    = ["JP"]
      data_export_allowed  = false
      retention_days       = 1095
      encryption_required  = true
      pseudonymization     = false
      right_to_deletion    = false
      data_portability     = false
      consent_required     = true
      dpo_required         = false
      breach_notification_hours = 24
    }
  }

  # Data classification levels
  data_classifications = {
    public = {
      encryption_at_rest  = false
      encryption_in_transit = true
      cross_region_allowed = true
      retention_override = false
    }
    internal = {
      encryption_at_rest  = true
      encryption_in_transit = true
      cross_region_allowed = false
      retention_override = false
    }
    confidential = {
      encryption_at_rest  = true
      encryption_in_transit = true
      cross_region_allowed = false
      retention_override = false
      additional_controls = ["access_logging", "approval_required"]
    }
    restricted = {
      encryption_at_rest  = true
      encryption_in_transit = true
      cross_region_allowed = false
      retention_override = false
      additional_controls = ["access_logging", "approval_required", "dual_authorization", "audit_trail"]
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL DATA STORAGE WITH RESIDENCY CONTROLS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional Cloud SQL instances with strict data residency
resource "google_sql_database_instance" "regional_primary" {
  for_each = local.regions

  name                = "isectech-${each.key}-primary-${var.environment}"
  database_version    = "POSTGRES_15"
  region              = each.key
  project             = var.project_id
  deletion_protection = var.environment == "production"

  settings {
    tier              = var.environment == "production" ? "db-custom-4-16384" : "db-custom-2-8192"
    availability_type = each.value.role == "primary" ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = var.environment == "production" ? 500 : 100
    disk_autoresize   = true

    # Backup configuration with regional retention
    backup_configuration {
      enabled                        = true
      start_time                    = "03:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = local.compliance_zones[each.value.compliance_zone].retention_days / 30
        retention_unit   = "COUNT"
      }
      location = each.key # Keep backups in same region
      
      # Transaction log retention for compliance
      transaction_log_retention_days = 7
    }

    # IP configuration for private access only
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.regional_vpc[each.key].id
      require_ssl     = true
      
      # Restrict access to authorized networks only
      dynamic "authorized_networks" {
        for_each = var.authorized_networks
        content {
          name  = authorized_networks.value.display_name
          value = authorized_networks.value.cidr_block
        }
      }
    }

    # Database flags for compliance
    database_flags {
      name  = "log_statement"
      value = "all"
    }
    database_flags {
      name  = "log_duration"
      value = "on"
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    # Maintenance window during low-traffic hours
    maintenance_window {
      day  = 7
      hour = 3
    }

    # Insights configuration for monitoring
    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = true
    }

    # User labels for compliance tracking
    user_labels = merge(local.common_labels, {
      compliance-zone    = each.value.compliance_zone
      data-residency     = "enforced"
      backup-region      = each.key
      encryption-status  = "enabled"
      retention-policy   = "compliant"
    })
  }

  # Encryption at rest using regional KMS keys
  encryption_key_name = google_kms_crypto_key.sql_key[each.key].id

  provider = google.${each.value.provider_alias}

  depends_on = [
    google_compute_network.regional_vpc,
    google_kms_crypto_key.sql_key
  ]
}

# Regional Cloud Storage buckets with data residency enforcement
resource "google_storage_bucket" "regional_data" {
  for_each = local.regions

  name     = "isectech-${each.key}-data-${var.environment}-${random_id.bucket_suffix.hex}"
  location = each.key
  project  = var.project_id

  # Force destroy for non-production (safety measure)
  force_destroy = var.environment != "production"

  # Uniform bucket-level access for consistent IAM
  uniform_bucket_level_access = true

  # Public access prevention (strict data residency)
  public_access_prevention = "enforced"

  # Versioning for data protection
  versioning {
    enabled = true
  }

  # Lifecycle management based on compliance requirements
  lifecycle_rule {
    condition {
      age = local.compliance_zones[each.value.compliance_zone].retention_days
    }
    action {
      type = "Delete"
    }
  }

  # Lifecycle rule for version cleanup
  lifecycle_rule {
    condition {
      age                   = 30
      with_state           = "ARCHIVED"
      num_newer_versions   = 3
    }
    action {
      type = "Delete"
    }
  }

  # Encryption with regional KMS keys
  encryption {
    default_kms_key_name = google_kms_crypto_key.storage_key[each.key].id
  }

  # Logging for data access tracking
  logging {
    log_bucket        = google_storage_bucket.regional_audit_logs[each.key].name
    log_object_prefix = "data-access-logs/"
  }

  # Labels for compliance tracking
  labels = merge(local.common_labels, {
    compliance-zone   = each.value.compliance_zone
    data-residency   = "enforced"
    encryption-type  = "cmek"
    region-locked    = "true"
  })

  provider = google.${each.value.provider_alias}

  depends_on = [
    google_kms_crypto_key.storage_key,
    google_storage_bucket.regional_audit_logs
  ]
}

# Regional audit log buckets
resource "google_storage_bucket" "regional_audit_logs" {
  for_each = local.regions

  name     = "isectech-${each.key}-audit-${var.environment}-${random_id.bucket_suffix.hex}"
  location = each.key
  project  = var.project_id

  force_destroy = var.environment != "production"
  uniform_bucket_level_access = true
  public_access_prevention = "enforced"

  # Long-term retention for audit logs
  lifecycle_rule {
    condition {
      age = local.compliance_zones[each.value.compliance_zone].retention_days * 2 # Double retention for audit logs
    }
    action {
      type = "Delete"
    }
  }

  # Archive old audit logs
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  # Encryption for audit logs
  encryption {
    default_kms_key_name = google_kms_crypto_key.audit_key[each.key].id
  }

  labels = merge(local.common_labels, {
    compliance-zone = each.value.compliance_zone
    bucket-type    = "audit-logs"
    data-residency = "enforced"
  })

  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL KMS KEYS FOR DATA RESIDENCY
# ═══════════════════════════════════════════════════════════════════════════════

# Storage encryption keys
resource "google_kms_crypto_key" "storage_key" {
  for_each = local.regions

  name     = "isectech-${each.key}-storage-key-${var.environment}"
  key_ring = google_kms_key_ring.regional_keyring[each.key].id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = var.environment == "production" ? "2592000s" : "7776000s" # 30 days prod, 90 days non-prod

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.environment == "production" ? "HSM" : "SOFTWARE"
  }

  labels = {
    purpose         = "storage-encryption"
    compliance-zone = each.value.compliance_zone
    data-residency  = "enforced"
  }

  provider = google.${each.value.provider_alias}
}

# Audit log encryption keys
resource "google_kms_crypto_key" "audit_key" {
  for_each = local.regions

  name     = "isectech-${each.key}-audit-key-${var.environment}"
  key_ring = google_kms_key_ring.regional_keyring[each.key].id
  purpose  = "ENCRYPT_DECRYPT"

  rotation_period = var.environment == "production" ? "7776000s" : "15552000s" # 90 days prod, 180 days non-prod

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.environment == "production" ? "HSM" : "SOFTWARE"
  }

  labels = {
    purpose         = "audit-encryption"
    compliance-zone = each.value.compliance_zone
    data-residency  = "enforced"
  }

  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA RESIDENCY MONITORING AND ALERTING
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Asset Inventory for tracking data location
resource "google_project_service" "asset_inventory" {
  service = "cloudasset.googleapis.com"
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy        = false
}

# Data Location Monitoring using Cloud Functions
resource "google_storage_bucket" "data_residency_function" {
  name     = "isectech-data-residency-functions-${var.environment}-${random_id.bucket_suffix.hex}"
  location = "US"
  project  = var.project_id

  uniform_bucket_level_access = true
  force_destroy = true

  labels = merge(local.common_labels, {
    function-type = "data-residency-monitoring"
  })
}

# Function source code for data residency monitoring
resource "google_storage_bucket_object" "data_residency_source" {
  name   = "data-residency-monitor-${random_id.bucket_suffix.hex}.zip"
  bucket = google_storage_bucket.data_residency_function.name
  source = data.archive_file.data_residency_function_source.output_path

  depends_on = [data.archive_file.data_residency_function_source]
}

# Create the function source code
data "archive_file" "data_residency_function_source" {
  type        = "zip"
  output_path = "/tmp/data-residency-monitor.zip"
  
  source {
    content = templatefile("${path.module}/functions/data_residency_monitor.py", {
      compliance_zones = jsonencode(local.compliance_zones)
      project_id      = var.project_id
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/requirements.txt")
    filename = "requirements.txt"
  }
}

# Cloud Function for data residency monitoring
resource "google_cloudfunctions2_function" "data_residency_monitor" {
  name        = "isectech-data-residency-monitor-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Monitor data residency compliance across all regions"

  build_config {
    runtime     = "python311"
    entry_point = "monitor_data_residency"

    source {
      storage_source {
        bucket = google_storage_bucket.data_residency_function.name
        object = google_storage_bucket_object.data_residency_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    available_memory   = "256M"
    timeout_seconds    = 300

    environment_variables = {
      PROJECT_ID        = var.project_id
      ENVIRONMENT       = var.environment
      COMPLIANCE_ZONES  = jsonencode(local.compliance_zones)
    }

    service_account_email = google_service_account.data_residency_monitor.email
  }

  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.data_residency_events.id
  }

  depends_on = [
    google_project_service.cloudfunctions,
    google_storage_bucket_object.data_residency_source
  ]
}

# Service account for data residency monitoring
resource "google_service_account" "data_residency_monitor" {
  account_id   = "data-residency-monitor-${var.environment}"
  display_name = "Data Residency Monitor Service Account"
  description  = "Service account for monitoring data residency compliance"
  project      = var.project_id
}

# IAM bindings for monitoring service account
resource "google_project_iam_member" "data_residency_monitor_roles" {
  for_each = toset([
    "roles/cloudasset.viewer",
    "roles/storage.admin",
    "roles/sql.viewer", 
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/pubsub.subscriber"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.data_residency_monitor.email}"
}

# Pub/Sub topic for data residency events
resource "google_pubsub_topic" "data_residency_events" {
  name    = "isectech-data-residency-events-${var.environment}"
  project = var.project_id

  labels = merge(local.common_labels, {
    topic-type = "data-residency-monitoring"
  })
}

# Pub/Sub subscription for processing events
resource "google_pubsub_subscription" "data_residency_subscription" {
  name    = "isectech-data-residency-sub-${var.environment}"
  topic   = google_pubsub_topic.data_residency_events.name
  project = var.project_id

  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false
  ack_deadline_seconds       = 300

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.data_residency_dlq.id
    max_delivery_attempts = 5
  }
}

# Dead letter queue for failed monitoring events
resource "google_pubsub_topic" "data_residency_dlq" {
  name    = "isectech-data-residency-dlq-${var.environment}"
  project = var.project_id

  labels = merge(local.common_labels, {
    topic-type = "dead-letter-queue"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE POLICY ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Organization Policy for data residency (if using organization)
# Note: These require organization-level permissions
# Included for completeness but may need to be applied separately

# # Restrict resource locations
# resource "google_organization_policy" "restrict_resource_locations" {
#   org_id     = var.org_id
#   constraint = "constraints/gcp.resourceLocations"

#   list_policy {
#     allow {
#       values = flatten([
#         for zone_name, zone_config in local.compliance_zones : zone_config.regions
#       ])
#     }
#   }
# }

# # Restrict VM external IPs
# resource "google_organization_policy" "restrict_vm_external_ips" {
#   org_id     = var.org_id
#   constraint = "constraints/compute.vmExternalIpAccess"

#   list_policy {
#     deny {
#       all = true
#     }
#   }
# }

# Binary Authorization policy for container image scanning
resource "google_binary_authorization_policy" "data_residency_policy" {
  count   = var.environment == "production" ? 1 : 0
  project = var.project_id

  # Default rule: require attestation
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    
    require_attestations_by = [
      google_binary_authorization_attestor.data_residency_attestor[0].name
    ]
  }

  # Cluster-specific admission rules for each region
  dynamic "cluster_admission_rules" {
    for_each = local.regions
    content {
      cluster = "projects/${var.project_id}/locations/${cluster_admission_rules.key}/clusters/isectech-${cluster_admission_rules.key}-${var.environment}"
      
      evaluation_mode  = "REQUIRE_ATTESTATION"
      enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
      
      require_attestations_by = [
        google_binary_authorization_attestor.data_residency_attestor[0].name
      ]
    }
  }

  depends_on = [
    google_container_cluster.regional_cluster
  ]
}

# Binary Authorization attestor for data residency compliance
resource "google_binary_authorization_attestor" "data_residency_attestor" {
  count   = var.environment == "production" ? 1 : 0
  name    = "data-residency-attestor-${var.environment}"
  project = var.project_id

  description = "Attestor for data residency compliance verification"

  attestation_authority_note {
    note_reference = google_container_analysis_note.data_residency_note[0].name
    
    public_keys {
      id = "data-residency-key"
      
      pkix_public_key {
        public_key_pem      = tls_private_key.attestor_key[0].public_key_pem
        signature_algorithm = "RSA_PSS_2048_SHA256"
      }
    }
  }
}

# Container Analysis note for attestation
resource "google_container_analysis_note" "data_residency_note" {
  count   = var.environment == "production" ? 1 : 0
  name    = "data-residency-note-${var.environment}"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "Data Residency Compliance Attestor"
    }
  }
}

# TLS private key for attestation signing
resource "tls_private_key" "attestor_key" {
  count     = var.environment == "production" ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 2048
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING FOR DATA RESIDENCY
# ═══════════════════════════════════════════════════════════════════════════════

# Custom metrics for data residency monitoring
resource "google_monitoring_metric_descriptor" "data_residency_violations" {
  type        = "custom.googleapis.com/data_residency/violations"
  metric_kind = "GAUGE"
  value_type  = "INT64"
  description = "Number of data residency violations detected"
  
  labels {
    key         = "region"
    value_type  = "STRING"
    description = "GCP region where violation was detected"
  }
  
  labels {
    key         = "compliance_zone"
    value_type  = "STRING"
    description = "Compliance zone (GDPR, CCPA, APPI)"
  }
  
  labels {
    key         = "violation_type"
    value_type  = "STRING"
    description = "Type of violation (cross_region_transfer, unauthorized_access, etc.)"
  }

  project = var.project_id
}

# Alert policy for data residency violations
resource "google_monitoring_alert_policy" "data_residency_violations" {
  display_name = "Data Residency Violations - ${var.environment}"
  project      = var.project_id
  
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Data residency violation detected"
    
    condition_threshold {
      filter          = "resource.type=\"global\" AND metric.type=\"custom.googleapis.com/data_residency/violations\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  alert_strategy {
    auto_close = "604800s" # 7 days
  }

  notification_channels = [
    google_monitoring_notification_channel.data_residency_email.id,
    google_monitoring_notification_channel.data_residency_pager.id
  ]

  documentation {
    content = "Data residency violation detected. Immediate investigation required."
  }
}

# Email notification channel
resource "google_monitoring_notification_channel" "data_residency_email" {
  display_name = "Data Residency Email Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.compliance_email
  }
  
  force_delete = false
}

# PagerDuty notification channel (if configured)
resource "google_monitoring_notification_channel" "data_residency_pager" {
  count = var.pagerduty_service_key != "" ? 1 : 0
  
  display_name = "Data Residency PagerDuty"
  type         = "pagerduty"
  project      = var.project_id
  
  labels = {
    service_key = var.pagerduty_service_key
  }
  
  force_delete = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# REQUIRED SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_project_service" "required_services" {
  for_each = toset([
    "cloudfunctions.googleapis.com",
    "pubsub.googleapis.com",
    "binaryauthorization.googleapis.com",
    "containeranalysis.googleapis.com"
  ])

  service = each.value
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy        = false
}

# Convenience reference for required services
resource "google_project_service" "cloudfunctions" {
  service = "cloudfunctions.googleapis.com"
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy        = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# RANDOM SUFFIX FOR UNIQUE RESOURCE NAMES
# ═══════════════════════════════════════════════════════════════════════════════

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR DATA RESIDENCY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

output "regional_databases" {
  description = "Regional database instances with data residency enforcement"
  value = {
    for region, config in local.regions : region => {
      instance_name     = google_sql_database_instance.regional_primary[region].name
      connection_name   = google_sql_database_instance.regional_primary[region].connection_name
      compliance_zone   = config.compliance_zone
      encryption_key    = google_kms_crypto_key.sql_key[region].id
      backup_location   = region
    }
  }
  sensitive = true
}

output "regional_storage_buckets" {
  description = "Regional storage buckets with data residency enforcement"
  value = {
    for region, config in local.regions : region => {
      data_bucket_name     = google_storage_bucket.regional_data[region].name
      audit_bucket_name    = google_storage_bucket.regional_audit_logs[region].name
      compliance_zone      = config.compliance_zone
      encryption_key       = google_kms_crypto_key.storage_key[region].id
      retention_days       = local.compliance_zones[config.compliance_zone].retention_days
    }
  }
}

output "data_residency_monitoring" {
  description = "Data residency monitoring configuration"
  value = {
    monitor_function_name = google_cloudfunctions2_function.data_residency_monitor.name
    pubsub_topic         = google_pubsub_topic.data_residency_events.name
    alert_policy         = google_monitoring_alert_policy.data_residency_violations.name
    compliance_zones     = local.compliance_zones
  }
}

output "kms_keys_residency" {
  description = "Additional KMS keys for data residency enforcement"
  value = {
    for region in keys(local.regions) : region => {
      storage_key = google_kms_crypto_key.storage_key[region].id
      audit_key   = google_kms_crypto_key.audit_key[region].id
    }
  }
}