# iSECTECH Deployment Model Configuration
# Active-Active and Active-Passive deployment models with intelligent traffic management
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Deployment Model Implementation

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT MODEL SELECTION LOGIC
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # Define deployment model configurations
  deployment_models = {
    "active-active" = {
      description = "All regions actively serve traffic simultaneously"
      regions_active = keys(local.regions)
      traffic_distribution = var.traffic_distribution
      failover_strategy = "immediate"
      data_sync = "real-time"
      cost_multiplier = 1.0
      availability_target = 0.9999  # 99.99%
      rpo_minutes = 1    # Recovery Point Objective
      rto_minutes = 5    # Recovery Time Objective
    }
    
    "active-passive" = {
      description = "Primary region serves traffic, others standby for failover"
      regions_active = [var.primary_region]
      traffic_distribution = {
        for region in keys(local.regions) : region => (
          region == var.primary_region ? 100 : 0
        )
      }
      failover_strategy = "manual-or-health-based"
      data_sync = "scheduled"
      cost_multiplier = 0.6  # ~60% cost of active-active
      availability_target = 0.999   # 99.9%
      rpo_minutes = 15   # Recovery Point Objective  
      rto_minutes = 30   # Recovery Time Objective
    }
    
    "active-active-regional" = {
      description = "Active-active within regions, passive across regions"
      regions_active = [var.primary_region, "europe-west4", "asia-northeast1"]
      traffic_distribution = {
        "us-central1"     = 40
        "europe-west4"    = 30
        "asia-northeast1" = 30
        "us-east1"        = 0
        "europe-west1"    = 0
      }
      failover_strategy = "regional-then-global"
      data_sync = "regional-real-time-global-scheduled"
      cost_multiplier = 0.8  # 80% cost of full active-active
      availability_target = 0.9995  # 99.95%
      rpo_minutes = 5    # Recovery Point Objective
      rto_minutes = 15   # Recovery Time Objective
    }
  }
  
  # Current deployment model configuration
  current_model = local.deployment_models[var.deployment_model]
  
  # Regional configurations based on deployment model
  regional_configurations = {
    for region, config in local.regions : region => merge(config, {
      is_active = contains(local.current_model.regions_active, region)
      traffic_weight = lookup(local.current_model.traffic_distribution, region, 0)
      replication_priority = config.priority
      failover_eligible = config.role != "backup" || var.deployment_model == "active-passive"
      
      # Resource scaling based on deployment model
      resource_scale = var.deployment_model == "active-active" ? 1.0 : (
        contains(local.current_model.regions_active, region) ? 1.0 : 0.3
      )
      
      # Backup configuration
      backup_enabled = config.role == "primary" || var.deployment_model == "active-active"
      backup_frequency = var.deployment_model == "active-active" ? "15min" : "1hour"
    })
  }
  
  # Compliance requirements by deployment model
  compliance_requirements = {
    data_residency_strict = var.data_residency_enforcement
    cross_region_replication = var.deployment_model != "active-passive" || var.disaster_recovery_rpo < 60
    encryption_in_transit = true
    encryption_at_rest = true
    audit_logging = true
    compliance_monitoring = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CONDITIONAL RESOURCE DEPLOYMENT BASED ON MODEL
# ═══════════════════════════════════════════════════════════════════════════════

# Regional load balancers (active regions only)
resource "google_compute_region_backend_service" "regional_app_service" {
  for_each = {
    for region, config in local.regional_configurations : region => config
    if config.is_active
  }
  
  name                  = "isectech-${each.key}-app-service-${var.environment}"
  region               = each.key
  protocol             = "HTTP"
  load_balancing_scheme = "EXTERNAL"
  timeout_sec          = 30
  project              = var.project_id
  
  health_checks = [google_compute_region_health_check.app_health_check[each.key].id]
  
  # Connection draining
  connection_draining_timeout_sec = 60
  
  # Session affinity for stateful applications
  session_affinity = var.deployment_model == "active-active" ? "CLIENT_IP" : "NONE"
  
  # Circuit breaker configuration
  circuit_breakers {
    max_requests_per_connection = 100
    max_requests               = 1000
    max_pending_requests       = 100
    max_retries               = 3
  }
  
  # Consistent hash for session stickiness in active-active
  dynamic "consistent_hash" {
    for_each = var.deployment_model == "active-active" ? [1] : []
    content {
      http_cookie {
        name = "isectech-session-${each.key}"
        ttl {
          seconds = 3600  # 1 hour session stickiness
        }
      }
    }
  }
  
  labels = merge(local.common_labels, {
    region         = each.key
    deployment-model = var.deployment_model
    traffic-weight = tostring(each.value.traffic_weight)
    is-active      = tostring(each.value.is_active)
  })
  
  provider = google.${each.value.provider_alias}
}

# Regional health checks
resource "google_compute_region_health_check" "app_health_check" {
  for_each = local.regional_configurations
  
  name               = "isectech-${each.key}-app-health-${var.environment}"
  region            = each.key
  check_interval_sec = each.value.is_active ? var.health_check_interval : 60
  timeout_sec        = 10
  healthy_threshold  = 2
  unhealthy_threshold = each.value.is_active ? 3 : 5  # More tolerance for passive regions
  project           = var.project_id
  
  http_health_check {
    request_path = "${var.health_check_path}?model=${var.deployment_model}"
    port         = 8080
    host         = "app-${each.key}.${trimsuffix(var.domain_name, ".")}"
    proxy_header = "PROXY_V1"
  }
  
  log_config {
    enable = true
  }
  
  labels = merge(local.common_labels, {
    region        = each.key
    is-active     = tostring(each.value.is_active)
    check-type    = "application"
  })
  
  provider = google.${each.value.provider_alias}
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT MODEL SPECIFIC CONFIGURATIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Active-Active specific resources
resource "google_compute_global_network_endpoint_group" "active_active_neg" {
  count                = var.deployment_model == "active-active" ? length(local.current_model.regions_active) : 0
  name                 = "isectech-active-neg-${local.current_model.regions_active[count.index]}-${var.environment}"
  network_endpoint_type = "INTERNET_IP_PORT"
  project              = var.project_id
  
  labels = merge(local.common_labels, {
    deployment-model = "active-active"
    region          = local.current_model.regions_active[count.index]
  })
}

# Active-Passive specific resources
resource "google_compute_region_autoscaler" "passive_region_autoscaler" {
  for_each = {
    for region, config in local.regional_configurations : region => config
    if var.deployment_model == "active-passive" && region != var.primary_region
  }
  
  name   = "isectech-${each.key}-passive-autoscaler-${var.environment}"
  region = each.key
  target = google_container_node_pool.regional_node_pool[each.key].instance_group_manager
  project = var.project_id
  
  autoscaling_policy {
    max_replicas    = 2  # Minimal scaling for passive regions
    min_replicas    = 0  # Can scale to zero
    cooldown_period = 300
    
    # CPU utilization targeting for passive regions
    cpu_utilization {
      target = 0.9  # Higher threshold for passive regions
    }
  }
  
  provider = google.${each.value.provider_alias}
}

# Deployment model configuration map
resource "google_secret_manager_secret" "deployment_model_config" {
  secret_id = "isectech-deployment-model-config-${var.environment}"
  project   = var.project_id
  
  replication {
    auto {}
  }
  
  labels = merge(local.common_labels, {
    config-type = "deployment-model"
    model       = var.deployment_model
  })
}

resource "google_secret_manager_secret_version" "deployment_model_config" {
  secret      = google_secret_manager_secret.deployment_model_config.id
  secret_data = jsonencode({
    deployment_model = var.deployment_model
    model_config     = local.current_model
    regional_configs = local.regional_configurations
    compliance_requirements = local.compliance_requirements
    
    # Runtime configuration
    runtime_config = {
      health_check_endpoints = {
        for region, config in local.regional_configurations : region => {
          enabled = config.is_active
          endpoint = "https://api-${region}.${trimsuffix(var.domain_name, ".")}/health"
          weight = config.traffic_weight
        }
      }
      
      failover_sequence = var.deployment_model == "active-passive" ? [
        var.primary_region,
        # Backup regions in priority order
        for region, config in local.regions : region 
        if config.role == "backup" && config.compliance_zone == local.regions[var.primary_region].compliance_zone
      ] : []
      
      data_sync_intervals = {
        for region, config in local.regional_configurations : region => (
          config.is_active ? "real-time" : "scheduled"
        )
      }
    }
    
    # Monitoring configuration
    monitoring_config = {
      slo_targets = {
        availability = local.current_model.availability_target
        rpo_minutes  = local.current_model.rpo_minutes
        rto_minutes  = local.current_model.rto_minutes
      }
      
      alert_thresholds = {
        region_failure_threshold = var.deployment_model == "active-active" ? 2 : 1
        latency_threshold_ms     = 5000
        error_rate_threshold     = 0.01  # 1%
      }
    }
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT MODEL VALIDATION RULES
# ═══════════════════════════════════════════════════════════════════════════════

# Validation check for deployment model consistency
resource "null_resource" "deployment_model_validation" {
  triggers = {
    deployment_model = var.deployment_model
    regions_count    = length(var.enabled_regions)
    compliance_check = var.data_residency_enforcement
    primary_region   = var.primary_region
  }
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== Deployment Model Validation ==="
      echo "Model: ${var.deployment_model}"
      echo "Primary Region: ${var.primary_region}"
      echo "Active Regions: ${jsonencode(local.current_model.regions_active)}"
      echo "Traffic Distribution: ${jsonencode(local.current_model.traffic_distribution)}"
      echo "Expected Availability: ${local.current_model.availability_target * 100}%"
      echo "RTO Target: ${local.current_model.rto_minutes} minutes"
      echo "RPO Target: ${local.current_model.rpo_minutes} minutes"
      echo "Data Residency: ${var.data_residency_enforcement ? "ENFORCED" : "NOT ENFORCED"}"
      
      # Validate configuration consistency
      if [ "${var.deployment_model}" = "active-passive" ] && [ "${var.primary_region}" = "" ]; then
        echo "ERROR: Active-passive model requires primary_region to be set"
        exit 1
      fi
      
      if [ "${var.data_residency_enforcement}" = "true" ] && [ "${var.cross_region_data_transfer}" = "true" ]; then
        echo "WARNING: Data residency enforcement conflicts with cross-region data transfer"
      fi
      
      echo "=== Validation Complete ==="
    EOT
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR DEPLOYMENT MODEL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

output "deployment_model_configuration" {
  description = "Complete deployment model configuration and status"
  value = {
    selected_model = var.deployment_model
    model_details  = local.current_model
    
    regional_status = {
      for region, config in local.regional_configurations : region => {
        is_active         = config.is_active
        traffic_weight    = config.traffic_weight
        role             = config.role
        compliance_zone   = config.compliance_zone
        resource_scale    = config.resource_scale
        backup_enabled    = config.backup_enabled
        backup_frequency  = config.backup_frequency
      }
    }
    
    operational_parameters = {
      availability_target = local.current_model.availability_target
      rpo_minutes        = local.current_model.rpo_minutes
      rto_minutes        = local.current_model.rto_minutes
      failover_strategy  = local.current_model.failover_strategy
      data_sync_mode     = local.current_model.data_sync
      estimated_cost_multiplier = local.current_model.cost_multiplier
    }
    
    compliance_status = {
      data_residency_enforced = var.data_residency_enforcement
      cross_region_transfer   = var.cross_region_data_transfer
      audit_logging_enabled   = local.compliance_requirements.audit_logging
      encryption_in_transit   = local.compliance_requirements.encryption_in_transit
      encryption_at_rest      = local.compliance_requirements.encryption_at_rest
    }
    
    health_check_configuration = {
      for region, config in local.regional_configurations : region => {
        enabled = config.is_active
        interval_seconds = config.is_active ? var.health_check_interval : 60
        endpoint = "https://api-${region}.${trimsuffix(var.domain_name, ".")}/health?model=${var.deployment_model}"
      }
    }
  }
  sensitive = false
}

output "failover_configuration" {
  description = "Failover and disaster recovery configuration"
  value = {
    failover_strategy = local.current_model.failover_strategy
    
    primary_region = var.primary_region
    backup_regions = [
      for region, config in local.regions : region 
      if config.role == "backup"
    ]
    
    regional_priorities = {
      for region, config in local.regions : region => config.priority
    }
    
    compliance_routing = {
      us_regions = [
        for region, config in local.regions : region 
        if config.compliance_zone == "ccpa"
      ]
      eu_regions = [
        for region, config in local.regions : region 
        if config.compliance_zone == "gdpr"
      ]
      apac_regions = [
        for region, config in local.regions : region 
        if config.compliance_zone == "appi"
      ]
    }
    
    disaster_recovery = {
      rpo_target_minutes = var.disaster_recovery_rpo
      rto_target_minutes = var.disaster_recovery_rto
      backup_retention_days = var.backup_retention_days
      cross_region_backup = var.deployment_model != "active-passive" || var.enable_backup
    }
  }
  sensitive = false
}