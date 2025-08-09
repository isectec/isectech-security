# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH DATA RESIDENCY POLICY ENGINE
# OPA-based policy enforcement for strict data residency compliance
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.5 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════════
# DATA RESIDENCY POLICY ENGINE SERVICE ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_service_account" "policy_engine" {
  account_id   = "data-residency-policy-${var.environment}"
  display_name = "Data Residency Policy Engine Service Account"
  description  = "Service account for data residency policy enforcement"
  project      = var.project_id
}

# IAM bindings for policy engine
resource "google_project_iam_member" "policy_engine_roles" {
  for_each = toset([
    "roles/orgpolicy.policyAdmin",
    "roles/resourcemanager.organizationAdmin",
    "roles/cloudasset.viewer",
    "roles/iam.securityReviewer",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudsql.viewer",
    "roles/storage.admin",
    "roles/compute.viewer",
    "roles/bigquery.dataViewer"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.policy_engine.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD BUILD FOR POLICY DEPLOYMENT
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_cloudbuild_trigger" "policy_deployment" {
  name        = "data-residency-policy-deployment-${var.environment}"
  project     = var.project_id
  description = "Deploy data residency policies on infrastructure changes"

  github {
    owner = "isectech"
    name  = "infrastructure"
    
    push {
      branch = var.environment == "production" ? "main" : var.environment
    }
  }

  filename = "infrastructure/policy/cloudbuild-policy.yaml"

  substitutions = {
    _ENVIRONMENT         = var.environment
    _PROJECT_ID         = var.project_id
    _POLICY_ENGINE_SA   = google_service_account.policy_engine.email
  }

  service_account = google_service_account.policy_engine.id
}

# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENFORCEMENT CLOUD FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Policy enforcement function source bucket
resource "google_storage_bucket" "policy_engine_source" {
  name     = "isectech-policy-engine-${var.environment}-${random_id.bucket_suffix.hex}"
  location = "US-CENTRAL1"
  project  = var.project_id

  uniform_bucket_level_access = true
  force_destroy = true
  public_access_prevention = "enforced"

  labels = merge(local.common_labels, {
    function-type = "policy-enforcement"
  })
}

# Policy enforcement function source code
resource "google_storage_bucket_object" "policy_enforcement_source" {
  name   = "policy-enforcement-${random_id.bucket_suffix.hex}.zip"
  bucket = google_storage_bucket.policy_engine_source.name
  source = data.archive_file.policy_enforcement_source.output_path

  depends_on = [data.archive_file.policy_enforcement_source]
}

# Create policy enforcement function source
data "archive_file" "policy_enforcement_source" {
  type        = "zip"
  output_path = "/tmp/policy-enforcement.zip"
  
  source {
    content = templatefile("${path.module}/functions/policy_enforcement.py", {
      compliance_zones = jsonencode(local.compliance_zones)
      project_id      = var.project_id
      environment     = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/policy-requirements.txt")
    filename = "requirements.txt"
  }
  
  source {
    content = file("${path.module}/policies/data_residency_policies.rego")
    filename = "policies.rego"
  }
}

# Policy enforcement Cloud Function
resource "google_cloudfunctions2_function" "policy_enforcement" {
  name        = "isectech-policy-enforcement-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Enforce data residency policies in real-time"

  build_config {
    runtime     = "python311"
    entry_point = "enforce_policies"

    source {
      storage_source {
        bucket = google_storage_bucket.policy_engine_source.name
        object = google_storage_bucket_object.policy_enforcement_source.name
      }
    }
  }

  service_config {
    max_instance_count = 100
    available_memory   = "512M"
    timeout_seconds    = 300
    
    environment_variables = {
      PROJECT_ID           = var.project_id
      ENVIRONMENT          = var.environment
      COMPLIANCE_ZONES     = jsonencode(local.compliance_zones)
      ENFORCEMENT_MODE     = var.environment == "production" ? "BLOCK" : "WARN"
      POLICY_VIOLATIONS_TOPIC = google_pubsub_topic.policy_violations.name
    }

    service_account_email = google_service_account.policy_engine.email
  }

  event_trigger {
    trigger_region = "global"
    event_type     = "google.cloud.audit.log.v1.written"
    
    event_filters {
      attribute = "serviceName"
      value     = "storage.googleapis.com"
    }
    
    event_filters {
      attribute = "serviceName" 
      value     = "sqladmin.googleapis.com"
    }
    
    event_filters {
      attribute = "serviceName"
      value     = "compute.googleapis.com"
    }
  }

  depends_on = [
    google_project_service.required_services,
    google_storage_bucket_object.policy_enforcement_source
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# POLICY VIOLATION PROCESSING
# ═══════════════════════════════════════════════════════════════════════════════

# Pub/Sub topic for policy violations
resource "google_pubsub_topic" "policy_violations" {
  name    = "isectech-policy-violations-${var.environment}"
  project = var.project_id

  labels = merge(local.common_labels, {
    topic-type = "policy-violations"
  })
}

# Policy violation processing function
resource "google_cloudfunctions2_function" "policy_violation_processor" {
  name        = "isectech-policy-violation-processor-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Process and respond to policy violations"

  build_config {
    runtime     = "python311"
    entry_point = "process_policy_violation"

    source {
      storage_source {
        bucket = google_storage_bucket.policy_engine_source.name
        object = google_storage_bucket_object.policy_violation_processor_source.name
      }
    }
  }

  service_config {
    max_instance_count = 50
    available_memory   = "256M"
    timeout_seconds    = 180

    environment_variables = {
      PROJECT_ID       = var.project_id
      ENVIRONMENT      = var.environment
      COMPLIANCE_EMAIL = var.compliance_email
      ENFORCEMENT_MODE = var.environment == "production" ? "BLOCK" : "WARN"
    }

    service_account_email = google_service_account.policy_engine.email
  }

  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.policy_violations.id
  }

  depends_on = [
    google_storage_bucket_object.policy_violation_processor_source
  ]
}

# Policy violation processor source
resource "google_storage_bucket_object" "policy_violation_processor_source" {
  name   = "policy-violation-processor-${random_id.bucket_suffix.hex}.zip"
  bucket = google_storage_bucket.policy_engine_source.name
  source = data.archive_file.policy_violation_processor_source.output_path

  depends_on = [data.archive_file.policy_violation_processor_source]
}

data "archive_file" "policy_violation_processor_source" {
  type        = "zip"
  output_path = "/tmp/policy-violation-processor.zip"
  
  source {
    content = templatefile("${path.module}/functions/policy_violation_processor.py", {
      project_id  = var.project_id
      environment = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/policy-requirements.txt")
    filename = "requirements.txt"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED COMPLIANCE AUDITS
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Scheduler job for daily compliance audits
resource "google_cloud_scheduler_job" "compliance_audit" {
  name        = "data-residency-compliance-audit-${var.environment}"
  project     = var.project_id
  region      = "us-central1"
  description = "Daily data residency compliance audit"

  schedule  = "0 6 * * *" # Daily at 6 AM UTC
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.data_residency_monitor.service_config[0].uri
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = base64encode(jsonencode({
      type      = "scheduled_audit"
      timestamp = timestamp()
      scope     = "full_compliance_check"
    }))

    oidc_token {
      service_account_email = google_service_account.policy_engine.email
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL BOUNDARY ENFORCEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Firewall rules to prevent cross-region data flow
resource "google_compute_firewall" "block_cross_region_traffic" {
  for_each = local.regions

  name    = "isectech-block-cross-region-${each.key}-${var.environment}"
  network = google_compute_network.regional_vpc[each.key].id
  project = var.project_id

  # Block traffic to other regions' CIDR blocks
  deny {
    protocol = "tcp"
    ports    = ["443", "80", "5432", "3306", "6379"] # Common data ports
  }

  deny {
    protocol = "udp"
    ports    = ["53", "123"] # DNS, NTP
  }

  # Define destination ranges (other regions)
  destination_ranges = [
    for region, config in local.regions : config.vpc_cidr
    if region != each.key
  ]

  priority = 1000

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Allow traffic within same compliance zone
resource "google_compute_firewall" "allow_compliance_zone_traffic" {
  for_each = local.regions

  name    = "isectech-allow-compliance-zone-${each.key}-${var.environment}"
  network = google_compute_network.regional_vpc[each.key].id
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["443", "80"]
  }

  # Only allow traffic from regions in same compliance zone
  source_ranges = [
    for region, config in local.regions : config.vpc_cidr
    if local.compliance_zones[config.compliance_zone] == local.compliance_zones[each.value.compliance_zone]
  ]

  priority = 900

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE REPORTING AND DASHBOARDS
# ═══════════════════════════════════════════════════════════════════════════════

# BigQuery dataset for compliance analytics (regional)
resource "google_bigquery_dataset" "compliance_analytics" {
  for_each = local.regions

  dataset_id    = "isectech_compliance_analytics_${replace(each.key, "-", "_")}_${var.environment}"
  friendly_name = "iSECTECH Compliance Analytics - ${each.key}"
  description   = "Compliance monitoring and analytics data for ${each.key}"
  location      = each.key
  project       = var.project_id

  default_encryption_configuration {
    kms_key_name = google_kms_crypto_key.audit_key[each.key].id
  }

  access {
    role          = "OWNER"
    user_by_email = google_service_account.policy_engine.email
  }

  access {
    role         = "READER"
    special_group = "projectReaders"
  }

  labels = merge(local.common_labels, {
    compliance-zone = each.value.compliance_zone
    dataset-type   = "compliance-analytics"
    region         = each.key
  })
}

# Compliance violations table
resource "google_bigquery_table" "compliance_violations" {
  for_each = local.regions

  dataset_id = google_bigquery_dataset.compliance_analytics[each.key].dataset_id
  table_id   = "compliance_violations"
  project    = var.project_id

  time_partitioning {
    type  = "DAY"
    field = "violation_timestamp"
  }

  clustering = ["violation_type", "resource_type", "severity"]

  schema = jsonencode([
    {
      name = "violation_id"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "violation_timestamp"
      type = "TIMESTAMP"
      mode = "REQUIRED"
    },
    {
      name = "resource_type"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "resource_name"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "violation_type"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "compliance_zone"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "severity"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "region"
      type = "STRING"
      mode = "REQUIRED"
    },
    {
      name = "details"
      type = "STRING"
      mode = "NULLABLE"
    },
    {
      name = "resolved"
      type = "BOOLEAN"
      mode = "REQUIRED"
    },
    {
      name = "resolution_timestamp"
      type = "TIMESTAMP"
      mode = "NULLABLE"
    }
  ])

  labels = merge(local.common_labels, {
    table-type      = "compliance-violations"
    compliance-zone = each.value.compliance_zone
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR DATA RESIDENCY POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

output "policy_engine_configuration" {
  description = "Data residency policy engine configuration"
  value = {
    service_account_email     = google_service_account.policy_engine.email
    policy_enforcement_function = google_cloudfunctions2_function.policy_enforcement.name
    violation_processor_function = google_cloudfunctions2_function.policy_violation_processor.name
    policy_violations_topic     = google_pubsub_topic.policy_violations.name
    compliance_audit_schedule   = google_cloud_scheduler_job.compliance_audit.schedule
  }
}

output "compliance_analytics" {
  description = "Regional compliance analytics datasets"
  value = {
    for region in keys(local.regions) : region => {
      dataset_id       = google_bigquery_dataset.compliance_analytics[region].dataset_id
      violations_table = google_bigquery_table.compliance_violations[region].table_id
      region          = region
      compliance_zone = local.regions[region].compliance_zone
    }
  }
}

output "firewall_rules" {
  description = "Cross-region traffic control firewall rules"
  value = {
    block_cross_region_rules = {
      for region in keys(local.regions) : region => google_compute_firewall.block_cross_region_traffic[region].name
    }
    allow_compliance_zone_rules = {
      for region in keys(local.regions) : region => google_compute_firewall.allow_compliance_zone_traffic[region].name
    }
  }
}