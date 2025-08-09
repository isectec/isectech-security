# iSECTECH Artifact Registry Module
# Production-grade container registry with security scanning and multi-environment support
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.10"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOCAL VALUES FOR ISECTECH REGISTRY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # iSECTECH microservices requiring containerization
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

  # Multi-environment registry repositories
  environment_repos = [
    "development",
    "staging", 
    "production"
  ]

  # Security-specific repositories
  security_repos = [
    "security-tools",
    "vulnerability-scanners",
    "compliance-agents"
  ]

  common_labels = merge(var.labels, {
    project     = "isectech"
    component   = "artifact-registry"
    environment = var.environment
    managed-by  = "terraform"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# ARTIFACT REGISTRY REPOSITORIES FOR ISECTECH SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

# Main Docker repository for iSECTECH microservices
resource "google_artifact_registry_repository" "isectech_docker" {
  repository_id = "isectech-docker"
  location      = var.region
  format        = "DOCKER"
  project       = var.project_id
  
  description = "iSECTECH Security Platform - Main Docker repository for all microservices"
  
  labels = local.common_labels

  # Cleanup policy for cost optimization
  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      untagged_since_days = 7
    }
  }

  cleanup_policies {
    id     = "keep-minimum-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-old-versions"
    action = "DELETE"
    condition {
      older_than = "2592000s" # 30 days
    }
    most_recent_versions {
      keep_count = 5
    }
  }
}

# Environment-specific repositories for deployment isolation
resource "google_artifact_registry_repository" "environment_repos" {
  for_each = toset(local.environment_repos)
  
  repository_id = "isectech-${each.key}"
  location      = var.region
  format        = "DOCKER"
  project       = var.project_id
  
  description = "iSECTECH Security Platform - ${title(each.key)} environment container repository"
  
  labels = merge(local.common_labels, {
    environment = each.key
  })

  # Environment-specific cleanup policies
  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      untagged_since_days = each.key == "production" ? 14 : 3
    }
  }

  cleanup_policies {
    id     = "keep-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = each.key == "production" ? 50 : 10
    }
  }
}

# Security tools repository with enhanced scanning
resource "google_artifact_registry_repository" "security_tools" {
  repository_id = "isectech-security-tools"
  location      = var.region
  format        = "DOCKER"
  project       = var.project_id
  
  description = "iSECTECH Security Platform - Security scanning and monitoring tools"
  
  labels = merge(local.common_labels, {
    category = "security-tools"
  })

  # Stricter cleanup for security tools
  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      untagged_since_days = 1
    }
  }

  cleanup_policies {
    id     = "keep-security-versions"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Enable Container Analysis API for vulnerability scanning
resource "google_project_service" "container_analysis" {
  service = "containeranalysis.googleapis.com"
  project = var.project_id
  
  disable_on_destroy = false
}

# Binary Authorization policy for production security
resource "google_binary_authorization_policy" "isectech_policy" {
  count = var.environment == "production" ? 1 : 0
  
  project = var.project_id

  # Default rule - require attestation for production
  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    
    require_attestations_by = [
      google_binary_authorization_attestor.isectech_attestor[0].name
    ]
  }

  # Allow Google-built images (for base images)
  admission_whitelist_patterns {
    name_pattern = "gcr.io/google-containers/*"
  }

  admission_whitelist_patterns {
    name_pattern = "gcr.io/google_containers/*"
  }

  # Allow iSECTECH development images in non-prod
  dynamic "admission_whitelist_patterns" {
    for_each = var.environment != "production" ? [1] : []
    content {
      name_pattern = "${var.region}-docker.pkg.dev/${var.project_id}/isectech-development/*"
    }
  }
}

# Binary Authorization attestor for production images
resource "google_binary_authorization_attestor" "isectech_attestor" {
  count = var.environment == "production" ? 1 : 0
  
  name    = "isectech-security-attestor"
  project = var.project_id
  
  description = "iSECTECH Security Platform attestor for production container verification"

  attestation_authority_note {
    note_reference = google_container_analysis_note.isectech_attestor_note[0].name
    
    public_keys {
      ascii_armored_pgp_public_key = var.attestor_public_key
      id                          = "isectech-security-key"
    }
  }
}

# Container Analysis note for attestor
resource "google_container_analysis_note" "isectech_attestor_note" {
  count = var.environment == "production" ? 1 : 0
  
  name    = "isectech-attestor-note"
  project = var.project_id

  attestation_authority {
    hint {
      human_readable_name = "iSECTECH Security Platform Attestor"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# IAM CONFIGURATION FOR SECURE ACCESS
# ═══════════════════════════════════════════════════════════════════════════════

# Service account for CI/CD pipeline
resource "google_service_account" "registry_ci_cd" {
  account_id   = "isectech-registry-cicd"
  display_name = "iSECTECH Registry CI/CD Service Account"
  description  = "Service account for CI/CD pipeline access to Artifact Registry"
  project      = var.project_id
}

# Service account for Cloud Run services
resource "google_service_account" "registry_runtime" {
  account_id   = "isectech-registry-runtime"
  display_name = "iSECTECH Registry Runtime Service Account"
  description  = "Service account for Cloud Run services to pull images"
  project      = var.project_id
}

# IAM binding for CI/CD pipeline - write access
resource "google_artifact_registry_repository_iam_binding" "ci_cd_writer" {
  for_each = {
    main        = google_artifact_registry_repository.isectech_docker.name
    development = google_artifact_registry_repository.environment_repos["development"].name
    staging     = google_artifact_registry_repository.environment_repos["staging"].name
    production  = google_artifact_registry_repository.environment_repos["production"].name
    security    = google_artifact_registry_repository.security_tools.name
  }

  project    = var.project_id
  location   = var.region
  repository = each.value
  role       = "roles/artifactregistry.writer"
  
  members = [
    "serviceAccount:${google_service_account.registry_ci_cd.email}",
    "serviceAccount:${var.project_id}@cloudbuild.gserviceaccount.com"
  ]
}

# IAM binding for runtime services - read access only
resource "google_artifact_registry_repository_iam_binding" "runtime_reader" {
  for_each = {
    main        = google_artifact_registry_repository.isectech_docker.name
    development = google_artifact_registry_repository.environment_repos["development"].name
    staging     = google_artifact_registry_repository.environment_repos["staging"].name
    production  = google_artifact_registry_repository.environment_repos["production"].name
    security    = google_artifact_registry_repository.security_tools.name
  }

  project    = var.project_id
  location   = var.region
  repository = each.value
  role       = "roles/artifactregistry.reader"
  
  members = [
    "serviceAccount:${google_service_account.registry_runtime.email}",
    "serviceAccount:${var.workload_identity_sa}"
  ]
}

# Additional IAM for vulnerability scanning
resource "google_project_iam_member" "vulnerability_scanner" {
  project = var.project_id
  role    = "roles/containeranalysis.occurrences.viewer"
  member  = "serviceAccount:${google_service_account.registry_ci_cd.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING
# ═══════════════════════════════════════════════════════════════════════════════

# Alert policy for high vulnerability count
resource "google_monitoring_alert_policy" "high_vulnerability_alert" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - High Vulnerability Count in Container Images"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content   = "Alert when container images have high number of vulnerabilities"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "High vulnerability count"
    
    condition_threshold {
      filter          = "resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 10
      duration        = "300s"
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  alert_strategy {
    auto_close = "86400s" # 24 hours
  }
}

# Alert policy for failed image pushes
resource "google_monitoring_alert_policy" "failed_push_alert" {
  count = var.enable_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - Failed Container Image Pushes"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content   = "Alert when container image pushes fail to Artifact Registry"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Failed image pushes"
    
    condition_threshold {
      filter          = "resource.type=\"artifact_registry\" AND metric.type=\"artifactregistry.googleapis.com/repository/push_request_count\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 5
      duration        = "300s"
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "3600s" # 1 hour
  }
}