# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH COMPLIANCE AUTOMATION INTEGRATION
# Integration between multi-region data residency enforcement and Task 36 framework
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.6 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE FRAMEWORK INTEGRATION SERVICE ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_service_account" "compliance_integration" {
  account_id   = "compliance-integration-${var.environment}"
  display_name = "Compliance Framework Integration Service Account"
  description  = "Service account for integrating data residency with compliance automation"
  project      = var.project_id
}

# IAM bindings for compliance integration
resource "google_project_iam_member" "compliance_integration_roles" {
  for_each = toset([
    "roles/cloudasset.viewer",
    "roles/storage.admin",
    "roles/sql.viewer",
    "roles/monitoring.metricWriter", 
    "roles/logging.logWriter",
    "roles/pubsub.editor",
    "roles/bigquery.dataEditor",
    "roles/cloudfunctions.invoker",
    "roles/secretmanager.secretAccessor",
    "roles/cloudsql.client",
    "roles/compute.viewer"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.compliance_integration.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE EVIDENCE COLLECTION SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

# Regional evidence collection buckets
resource "google_storage_bucket" "compliance_evidence" {
  for_each = local.regions

  name     = "isectech-compliance-evidence-${each.key}-${var.environment}-${random_id.bucket_suffix.hex}"
  location = each.key
  project  = var.project_id

  force_destroy = var.environment != "production"
  uniform_bucket_level_access = true
  public_access_prevention = "enforced"

  # Versioning for audit trail integrity
  versioning {
    enabled = true
  }

  # Long-term retention for regulatory compliance
  lifecycle_rule {
    condition {
      age = local.compliance_zones[each.value.compliance_zone].retention_days
    }
    action {
      type = "Delete"
    }
  }

  # Archive evidence after 1 year
  lifecycle_rule {
    condition {
      age = 365
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  # WORM compliance for regulatory evidence
  retention_policy {
    retention_period = 2592000 # 30 days minimum
  }

  # Encryption with compliance zone keys
  encryption {
    default_kms_key_name = google_kms_crypto_key.compliance_evidence_key[each.key].id
  }

  # Access logging for evidence integrity
  logging {
    log_bucket        = google_storage_bucket.regional_audit_logs[each.key].name
    log_object_prefix = "evidence-access-logs/"
  }

  labels = merge(local.common_labels, {
    compliance-zone = each.value.compliance_zone
    evidence-type   = "regulatory-compliance"
    retention-class = "long-term"
  })

  depends_on = [
    google_kms_crypto_key.compliance_evidence_key,
    google_storage_bucket.regional_audit_logs
  ]
}

# Evidence-specific KMS keys
resource "google_kms_crypto_key" "compliance_evidence_key" {
  for_each = local.regions

  name     = "isectech-${each.key}-evidence-key-${var.environment}"
  key_ring = google_kms_key_ring.regional_keyring[each.key].id
  purpose  = "ENCRYPT_DECRYPT"

  # Longer rotation period for evidence integrity
  rotation_period = var.environment == "production" ? "7776000s" : "15552000s" # 90 days prod, 180 days non-prod

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.environment == "production" ? "HSM" : "SOFTWARE"
  }

  labels = {
    purpose         = "compliance-evidence"
    compliance-zone = each.value.compliance_zone
    data-residency  = "enforced"
  }

  # Prevent accidental destruction of evidence keys
  lifecycle {
    prevent_destroy = true
  }

  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AUTOMATION CLOUD FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Compliance automation function source bucket
resource "google_storage_bucket" "compliance_automation_source" {
  name     = "isectech-compliance-automation-${var.environment}-${random_id.bucket_suffix.hex}"
  location = "US-CENTRAL1"
  project  = var.project_id

  uniform_bucket_level_access = true
  force_destroy = true
  public_access_prevention = "enforced"

  labels = merge(local.common_labels, {
    function-type = "compliance-automation"
  })
}

# Compliance automation function source code
resource "google_storage_bucket_object" "compliance_automation_source" {
  name   = "compliance-automation-${random_id.bucket_suffix.hex}.zip"
  bucket = google_storage_bucket.compliance_automation_source.name
  source = data.archive_file.compliance_automation_source.output_path

  depends_on = [data.archive_file.compliance_automation_source]
}

# Create compliance automation function source
data "archive_file" "compliance_automation_source" {
  type        = "zip"
  output_path = "/tmp/compliance-automation.zip"
  
  source {
    content = templatefile("${path.module}/functions/compliance_automation.py", {
      compliance_zones = jsonencode(local.compliance_zones)
      project_id      = var.project_id
      environment     = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/compliance-requirements.txt")
    filename = "requirements.txt"
  }
}

# Compliance evidence collector Cloud Function
resource "google_cloudfunctions2_function" "compliance_evidence_collector" {
  name        = "isectech-compliance-evidence-collector-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Collect and process compliance evidence from multi-region deployments"

  build_config {
    runtime     = "python311"
    entry_point = "collect_compliance_evidence"

    source {
      storage_source {
        bucket = google_storage_bucket.compliance_automation_source.name
        object = google_storage_bucket_object.compliance_automation_source.name
      }
    }
  }

  service_config {
    max_instance_count = 50
    available_memory   = "512M"
    timeout_seconds    = 300

    environment_variables = {
      PROJECT_ID           = var.project_id
      ENVIRONMENT          = var.environment
      COMPLIANCE_ZONES     = jsonencode(local.compliance_zones)
      EVIDENCE_BUCKET_PREFIX = "isectech-compliance-evidence"
      OPA_ENDPOINT         = "http://opa.isectech.local:8181"
    }

    service_account_email = google_service_account.compliance_integration.email
  }

  event_trigger {
    trigger_region = "us-central1"
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.compliance_automation_events.id
  }

  depends_on = [
    google_project_service.required_services,
    google_storage_bucket_object.compliance_automation_source
  ]
}

# Compliance report generator Cloud Function
resource "google_cloudfunctions2_function" "compliance_report_generator" {
  name        = "isectech-compliance-report-generator-${var.environment}"
  location    = "us-central1"
  project     = var.project_id
  description = "Generate comprehensive compliance reports across all regions"

  build_config {
    runtime     = "python311"
    entry_point = "generate_compliance_report"

    source {
      storage_source {
        bucket = google_storage_bucket.compliance_automation_source.name
        object = google_storage_bucket_object.compliance_report_generator_source.name
      }
    }
  }

  service_config {
    max_instance_count = 10
    available_memory   = "1Gi"
    timeout_seconds    = 600 # 10 minutes for complex reports

    environment_variables = {
      PROJECT_ID           = var.project_id
      ENVIRONMENT          = var.environment
      COMPLIANCE_ZONES     = jsonencode(local.compliance_zones)
      EVIDENCE_BUCKET_PREFIX = "isectech-compliance-evidence"
      REPORT_FORMATS       = "PDF,JSON,CSV"
    }

    service_account_email = google_service_account.compliance_integration.email
  }

  depends_on = [
    google_storage_bucket_object.compliance_report_generator_source
  ]
}

# Compliance report generator source
resource "google_storage_bucket_object" "compliance_report_generator_source" {
  name   = "compliance-report-generator-${random_id.bucket_suffix.hex}.zip"
  bucket = google_storage_bucket.compliance_automation_source.name
  source = data.archive_file.compliance_report_generator_source.output_path

  depends_on = [data.archive_file.compliance_report_generator_source]
}

data "archive_file" "compliance_report_generator_source" {
  type        = "zip"
  output_path = "/tmp/compliance-report-generator.zip"
  
  source {
    content = templatefile("${path.module}/functions/compliance_report_generator.py", {
      project_id  = var.project_id
      environment = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/functions/compliance-requirements.txt")
    filename = "requirements.txt"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AUTOMATION MESSAGING
# ═══════════════════════════════════════════════════════════════════════════════

# Pub/Sub topic for compliance automation events
resource "google_pubsub_topic" "compliance_automation_events" {
  name    = "isectech-compliance-automation-events-${var.environment}"
  project = var.project_id

  labels = merge(local.common_labels, {
    topic-type = "compliance-automation"
  })
}

# Schema for compliance events
resource "google_pubsub_schema" "compliance_event_schema" {
  name       = "compliance-event-schema-${var.environment}"
  type       = "AVRO"
  definition = jsonencode({
    type = "record"
    name = "ComplianceEvent"
    fields = [
      {
        name = "eventId"
        type = "string"
      },
      {
        name = "timestamp"
        type = "long"
      },
      {
        name = "eventType"
        type = {
          type = "enum"
          name = "EventType"
          symbols = ["POLICY_VIOLATION", "EVIDENCE_COLLECTED", "REPORT_GENERATED", "AUDIT_REQUIRED"]
        }
      },
      {
        name = "complianceZone"
        type = {
          type = "enum"
          name = "ComplianceZone"
          symbols = ["gdpr", "ccpa", "appi"]
        }
      },
      {
        name = "region"
        type = "string"
      },
      {
        name = "resourceId"
        type = ["null", "string"]
        default = null
      },
      {
        name = "severity"
        type = {
          type = "enum"
          name = "Severity"
          symbols = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        }
      },
      {
        name = "details"
        type = ["null", "string"]
        default = null
      },
      {
        name = "evidence"
        type = ["null", "string"]
        default = null
      }
    ]
  })

  project = var.project_id
}

# Connect policy violations to compliance automation
resource "google_pubsub_subscription" "policy_violations_to_compliance" {
  name    = "policy-violations-to-compliance-${var.environment}"
  topic   = google_pubsub_topic.policy_violations.name
  project = var.project_id

  message_retention_duration = "604800s" # 7 days
  retain_acked_messages      = false
  ack_deadline_seconds       = 300

  push_config {
    push_endpoint = google_cloudfunctions2_function.compliance_evidence_collector.service_config[0].uri
    
    oidc_token {
      service_account_email = google_service_account.compliance_integration.email
    }
    
    attributes = {
      source = "policy-violation-processor"
      type   = "compliance-event"
    }
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.compliance_dlq.id
    max_delivery_attempts = 5
  }
}

# Dead letter queue for compliance events
resource "google_pubsub_topic" "compliance_dlq" {
  name    = "isectech-compliance-dlq-${var.environment}"
  project = var.project_id

  labels = merge(local.common_labels, {
    topic-type = "compliance-dead-letter"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE DASHBOARD AND REPORTING
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Run service for compliance dashboard
resource "google_cloud_run_v2_service" "compliance_dashboard" {
  name     = "isectech-compliance-dashboard-${var.environment}"
  location = "us-central1"
  project  = var.project_id

  template {
    containers {
      image = "gcr.io/${var.project_id}/compliance-dashboard:latest"
      
      ports {
        container_port = 8080
      }

      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      
      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      
      env {
        name  = "COMPLIANCE_ZONES"
        value = jsonencode(local.compliance_zones)
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "4Gi"
        }
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 10
        timeout_seconds      = 5
        period_seconds       = 5
        failure_threshold    = 3
      }

      liveness_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 30
        timeout_seconds      = 5
        period_seconds       = 30
        failure_threshold    = 3
      }
    }

    service_account = google_service_account.compliance_integration.email
    
    scaling {
      min_instance_count = var.environment == "production" ? 2 : 1
      max_instance_count = var.environment == "production" ? 10 : 3
    }

    annotations = {
      "run.googleapis.com/cpu-throttling" = "false"
      "autoscaling.knative.dev/maxScale" = var.environment == "production" ? "10" : "3"
    }
  }

  labels = merge(local.common_labels, {
    service-type = "compliance-dashboard"
  })

  depends_on = [
    google_project_service.cloudrun
  ]
}

# IAM policy for compliance dashboard access
resource "google_cloud_run_service_iam_binding" "compliance_dashboard_invoker" {
  location = google_cloud_run_v2_service.compliance_dashboard.location
  project  = google_cloud_run_v2_service.compliance_dashboard.project
  service  = google_cloud_run_v2_service.compliance_dashboard.name
  role     = "roles/run.invoker"
  
  members = [
    "serviceAccount:${google_service_account.compliance_integration.email}",
    "group:compliance-team@isectech.org"
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# SCHEDULED COMPLIANCE AUDITS
# ═══════════════════════════════════════════════════════════════════════════════

# Daily compliance evidence collection
resource "google_cloud_scheduler_job" "daily_compliance_collection" {
  name        = "daily-compliance-collection-${var.environment}"
  project     = var.project_id
  region      = "us-central1"
  description = "Daily automated compliance evidence collection"

  schedule  = "0 2 * * *" # Daily at 2 AM UTC
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.compliance_evidence_collector.service_config[0].uri
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = base64encode(jsonencode({
      type      = "scheduled_collection"
      scope     = "all_regions"
      timestamp = timestamp()
    }))

    oidc_token {
      service_account_email = google_service_account.compliance_integration.email
    }
  }
}

# Weekly compliance reporting
resource "google_cloud_scheduler_job" "weekly_compliance_report" {
  name        = "weekly-compliance-report-${var.environment}"
  project     = var.project_id
  region      = "us-central1"
  description = "Weekly comprehensive compliance report generation"

  schedule  = "0 6 * * 1" # Weekly on Monday at 6 AM UTC
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.compliance_report_generator.service_config[0].uri
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = base64encode(jsonencode({
      type      = "weekly_report"
      formats   = ["PDF", "JSON"]
      recipients = [var.compliance_email]
      timestamp = timestamp()
    }))

    oidc_token {
      service_account_email = google_service_account.compliance_integration.email
    }
  }
}

# Monthly comprehensive audit
resource "google_cloud_scheduler_job" "monthly_compliance_audit" {
  name        = "monthly-compliance-audit-${var.environment}"
  project     = var.project_id
  region      = "us-central1"
  description = "Monthly comprehensive compliance audit and assessment"

  schedule  = "0 8 1 * *" # Monthly on 1st at 8 AM UTC
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.compliance_report_generator.service_config[0].uri
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = base64encode(jsonencode({
      type          = "comprehensive_audit"
      scope         = "all_frameworks"
      detail_level  = "full"
      include_recommendations = true
      timestamp     = timestamp()
    }))

    oidc_token {
      service_account_email = google_service_account.compliance_integration.email
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# REQUIRED SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_project_service" "cloudrun" {
  service = "run.googleapis.com"
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy        = false
}

resource "google_project_service" "cloudscheduler" {
  service = "cloudscheduler.googleapis.com"
  project = var.project_id

  disable_dependent_services = true
  disable_on_destroy        = false
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR COMPLIANCE INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

output "compliance_evidence_buckets" {
  description = "Regional compliance evidence collection buckets"
  value = {
    for region in keys(local.regions) : region => {
      bucket_name     = google_storage_bucket.compliance_evidence[region].name
      encryption_key  = google_kms_crypto_key.compliance_evidence_key[region].id
      compliance_zone = local.regions[region].compliance_zone
    }
  }
}

output "compliance_automation_functions" {
  description = "Compliance automation Cloud Functions"
  value = {
    evidence_collector    = google_cloudfunctions2_function.compliance_evidence_collector.name
    report_generator     = google_cloudfunctions2_function.compliance_report_generator.name
    evidence_collector_uri = google_cloudfunctions2_function.compliance_evidence_collector.service_config[0].uri
    report_generator_uri = google_cloudfunctions2_function.compliance_report_generator.service_config[0].uri
  }
}

output "compliance_dashboard" {
  description = "Compliance dashboard service information"
  value = {
    service_name = google_cloud_run_v2_service.compliance_dashboard.name
    service_uri  = google_cloud_run_v2_service.compliance_dashboard.uri
    location     = google_cloud_run_v2_service.compliance_dashboard.location
  }
}

output "compliance_schedules" {
  description = "Compliance automation schedules"
  value = {
    daily_collection_schedule = google_cloud_scheduler_job.daily_compliance_collection.schedule
    weekly_report_schedule   = google_cloud_scheduler_job.weekly_compliance_report.schedule
    monthly_audit_schedule   = google_cloud_scheduler_job.monthly_compliance_audit.schedule
  }
}

output "compliance_messaging" {
  description = "Compliance automation messaging configuration"
  value = {
    automation_topic    = google_pubsub_topic.compliance_automation_events.name
    violations_subscription = google_pubsub_subscription.policy_violations_to_compliance.name
    dead_letter_topic   = google_pubsub_topic.compliance_dlq.name
    event_schema       = google_pubsub_schema.compliance_event_schema.name
  }
}