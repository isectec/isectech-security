# iSECTECH Artifact Registry Module Outputs
# Output definitions for container registry resources
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

# ═══════════════════════════════════════════════════════════════════════════════
# REPOSITORY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "main_repository_name" {
  description = "Name of the main Docker repository"
  value       = google_artifact_registry_repository.isectech_docker.name
}

output "main_repository_id" {
  description = "ID of the main Docker repository"
  value       = google_artifact_registry_repository.isectech_docker.id
}

output "main_repository_url" {
  description = "URL of the main Docker repository"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}"
}

output "environment_repositories" {
  description = "Map of environment repository names and URLs"
  value = {
    for env, repo in google_artifact_registry_repository.environment_repos : env => {
      name = repo.name
      id   = repo.id
      url  = "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}"
    }
  }
}

output "security_tools_repository" {
  description = "Security tools repository information"
  value = {
    name = google_artifact_registry_repository.security_tools.name
    id   = google_artifact_registry_repository.security_tools.id
    url  = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.security_tools.repository_id}"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "ci_cd_service_account_email" {
  description = "Email of the CI/CD service account for registry access"
  value       = google_service_account.registry_ci_cd.email
}

output "ci_cd_service_account_name" {
  description = "Name of the CI/CD service account"
  value       = google_service_account.registry_ci_cd.name
}

output "ci_cd_service_account_unique_id" {
  description = "Unique ID of the CI/CD service account"
  value       = google_service_account.registry_ci_cd.unique_id
}

output "runtime_service_account_email" {
  description = "Email of the runtime service account for image pulling"
  value       = google_service_account.registry_runtime.email
}

output "runtime_service_account_name" {
  description = "Name of the runtime service account"
  value       = google_service_account.registry_runtime.name
}

output "runtime_service_account_unique_id" {
  description = "Unique ID of the runtime service account"
  value       = google_service_account.registry_runtime.unique_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "binary_authorization_policy_name" {
  description = "Name of the Binary Authorization policy (production only)"
  value       = var.environment == "production" && var.enable_binary_authorization ? google_binary_authorization_policy.isectech_policy[0].name : null
}

output "attestor_name" {
  description = "Name of the Binary Authorization attestor (production only)"
  value       = var.environment == "production" && var.enable_binary_authorization ? google_binary_authorization_attestor.isectech_attestor[0].name : null
}

output "container_analysis_note_name" {
  description = "Name of the Container Analysis note for attestation"
  value       = var.environment == "production" && var.enable_binary_authorization ? google_container_analysis_note.isectech_attestor_note[0].name : null
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOCKER CONFIGURATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "docker_config_commands" {
  description = "Docker configuration commands for authentication"
  value = {
    configure_auth = "gcloud auth configure-docker ${var.region}-docker.pkg.dev"
    login_command  = "docker login -u _token -p \"$(gcloud auth print-access-token)\" https://${var.region}-docker.pkg.dev"
  }
}

output "image_tagging_strategy" {
  description = "Recommended image tagging strategy for iSECTECH services"
  value = {
    main_repo = {
      base_url = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}"
      examples = [
        "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}/api-gateway:latest",
        "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}/api-gateway:v1.0.0",
        "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}/api-gateway:sha-abc123"
      ]
    }
    environment_repos = {
      for env, repo in google_artifact_registry_repository.environment_repos : env => {
        base_url = "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}"
        examples = [
          "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}/api-gateway:${env}-latest",
          "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}/api-gateway:${env}-v1.0.0",
          "${var.region}-docker.pkg.dev/${var.project_id}/${repo.repository_id}/api-gateway:${env}-sha-abc123"
        ]
      }
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CI/CD INTEGRATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cloud_build_integration" {
  description = "Cloud Build integration configuration"
  value = {
    service_account_email = google_service_account.registry_ci_cd.email
    substitutions = {
      "_REGISTRY_REGION"  = var.region
      "_PROJECT_ID"       = var.project_id
      "_MAIN_REPO"        = google_artifact_registry_repository.isectech_docker.repository_id
      "_DEV_REPO"         = google_artifact_registry_repository.environment_repos["development"].repository_id
      "_STAGING_REPO"     = google_artifact_registry_repository.environment_repos["staging"].repository_id
      "_PROD_REPO"        = google_artifact_registry_repository.environment_repos["production"].repository_id
      "_SECURITY_REPO"    = google_artifact_registry_repository.security_tools.repository_id
    }
  }
}

output "github_actions_config" {
  description = "GitHub Actions configuration for iSECTECH CI/CD"
  value = {
    workload_identity_provider = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/github-actions/providers/github-actions"
    service_account           = google_service_account.registry_ci_cd.email
    environment_variables = {
      REGISTRY_REGION = var.region
      PROJECT_ID      = var.project_id
      MAIN_REPO       = google_artifact_registry_repository.isectech_docker.repository_id
      DEV_REPO        = google_artifact_registry_repository.environment_repos["development"].repository_id
      STAGING_REPO    = google_artifact_registry_repository.environment_repos["staging"].repository_id
      PROD_REPO       = google_artifact_registry_repository.environment_repos["production"].repository_id
      SECURITY_REPO   = google_artifact_registry_repository.security_tools.repository_id
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "monitoring_alert_policies" {
  description = "Names of monitoring alert policies created"
  value = var.enable_monitoring ? {
    high_vulnerability_alert = google_monitoring_alert_policy.high_vulnerability_alert[0].name
    failed_push_alert       = google_monitoring_alert_policy.failed_push_alert[0].name
  } : {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# OPERATIONAL OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cleanup_policies_summary" {
  description = "Summary of cleanup policies applied to repositories"
  value = {
    untagged_retention_days = var.cleanup_policy_untagged_days
    keep_versions          = var.cleanup_policy_keep_versions
    older_than_days        = var.cleanup_policy_older_than_days
    production_keep        = var.production_keep_versions
    development_keep       = var.development_keep_versions
  }
}

output "security_configuration" {
  description = "Security configuration summary"
  value = {
    vulnerability_scanning_enabled = var.enable_vulnerability_scanning
    binary_authorization_enabled  = var.enable_binary_authorization && var.environment == "production"
    audit_logging_enabled         = var.enable_audit_logging
    compliance_frameworks         = var.compliance_frameworks
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "isectech_services_list" {
  description = "List of iSECTECH services for container naming"
  value       = var.isectech_services
}

output "deployment_commands" {
  description = "Useful commands for deployment and management"
  value = {
    list_repositories = "gcloud artifacts repositories list --location=${var.region} --project=${var.project_id}"
    list_images       = "gcloud artifacts docker images list ${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}"
    scan_vulnerabilities = "gcloud artifacts docker images scan ${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.isectech_docker.repository_id}/SERVICE_NAME:TAG"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DATA SOURCES FOR REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════

data "google_project" "current" {
  project_id = var.project_id
}