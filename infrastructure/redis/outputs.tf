# iSECTECH Redis Infrastructure Outputs
# Production-grade Redis deployment outputs for integration

# Redis instance outputs
output "redis_instances" {
  description = "Redis instance details for all regions"
  value = {
    for key, instance in google_redis_instance.trust_scoring_cache : key => {
      name                = instance.name
      host               = instance.host
      port               = instance.port
      region             = instance.region
      memory_size_gb     = instance.memory_size_gb
      tier               = instance.tier
      redis_version      = instance.redis_version
      auth_enabled       = instance.auth_enabled
      transit_encryption = instance.transit_encryption_mode
      replica_count      = instance.replica_count
      status             = instance.current_location_id
      labels             = instance.labels
    }
  }
  sensitive = false
}

output "redis_primary_instance" {
  description = "Primary Redis instance details"
  value = {
    name                = google_redis_instance.trust_scoring_cache["primary"].name
    host               = google_redis_instance.trust_scoring_cache["primary"].host
    port               = google_redis_instance.trust_scoring_cache["primary"].port
    region             = google_redis_instance.trust_scoring_cache["primary"].region
    memory_size_gb     = google_redis_instance.trust_scoring_cache["primary"].memory_size_gb
    connection_string  = "redis://${google_redis_instance.trust_scoring_cache["primary"].host}:${google_redis_instance.trust_scoring_cache["primary"].port}"
    auth_enabled       = google_redis_instance.trust_scoring_cache["primary"].auth_enabled
  }
  sensitive = false
}

output "redis_secondary_instances" {
  description = "Secondary Redis instances details"
  value = {
    for key, instance in google_redis_instance.trust_scoring_cache : key => {
      name                = instance.name
      host               = instance.host
      port               = instance.port
      region             = instance.region
      connection_string  = "redis://${instance.host}:${instance.port}"
    } if key != "primary"
  }
  sensitive = false
}

# Connection information
output "redis_connection_configs" {
  description = "Redis connection configurations for applications"
  value = {
    for key, instance in google_redis_instance.trust_scoring_cache : key => {
      host        = instance.host
      port        = instance.port
      region      = instance.region
      auth_string = "redis://:${random_password.redis_password[key].result}@${instance.host}:${instance.port}/0"
      tls_enabled = instance.transit_encryption_mode == "SERVER_AUTHENTICATION"
    }
  }
  sensitive = true
}

# Secret Manager outputs
output "redis_password_secrets" {
  description = "Secret Manager secret names for Redis passwords"
  value = {
    for key, secret in google_secret_manager_secret.redis_password : key => {
      secret_id   = secret.secret_id
      secret_name = secret.name
      project_id  = secret.project
    }
  }
  sensitive = false
}

# Sentinel configuration outputs
output "redis_sentinel_config" {
  description = "Redis Sentinel configuration details"
  value = var.sentinel_enabled ? {
    instance_group_name = google_compute_region_instance_group_manager.redis_sentinel.name
    target_size         = google_compute_region_instance_group_manager.redis_sentinel.target_size
    region              = google_compute_region_instance_group_manager.redis_sentinel.region
    sentinel_port       = var.sentinel_port
    health_check_url    = google_compute_health_check.redis_sentinel.id
    service_account     = google_service_account.redis_sentinel.email
  } : null
  sensitive = false
}

# Network configuration outputs  
output "redis_network_config" {
  description = "Redis network configuration details"
  value = {
    vpc_network              = data.google_compute_network.vpc.name
    private_subnet          = data.google_compute_subnetwork.private_subnet.name
    private_ip_range        = google_compute_global_address.private_ip_address.address
    private_ip_prefix       = google_compute_global_address.private_ip_address.prefix_length
    service_connection_name = google_service_networking_connection.private_vpc_connection.network
  }
  sensitive = false
}

# Monitoring outputs
output "redis_monitoring_config" {
  description = "Redis monitoring and alerting configuration"
  value = {
    notification_channel = google_monitoring_notification_channel.email.name
    alert_policies = {
      memory_utilization = {
        for key, policy in google_monitoring_alert_policy.redis_memory_utilization : key => {
          name         = policy.display_name
          policy_id    = policy.name
          threshold    = var.memory_utilization_threshold
        }
      }
      connection_count = {
        for key, policy in google_monitoring_alert_policy.redis_connection_count : key => {
          name         = policy.display_name
          policy_id    = policy.name
          threshold    = var.connection_count_threshold
        }
      }
    }
  }
  sensitive = false
}

# Backup configuration outputs
output "redis_backup_config" {
  description = "Redis backup configuration details"
  value = var.backup_enabled ? {
    backup_policy_name    = google_compute_resource_policy.redis_backup.name
    retention_days        = var.backup_retention_days
    backup_schedule       = var.backup_schedule
    storage_locations     = [var.primary_region]
  } : null
  sensitive = false
}

# Cache configuration outputs
output "cache_configuration" {
  description = "Cache configuration parameters for applications"
  value = {
    trust_score_ttl       = var.trust_score_ttl
    device_profile_ttl    = var.device_profile_ttl
    network_context_ttl   = var.network_context_ttl
    threat_intelligence_ttl = var.threat_intelligence_ttl
    max_memory_policy     = var.max_memory_policy
    tcp_keepalive        = var.tcp_keepalive
    timeout              = var.timeout
    databases            = var.databases
  }
  sensitive = false
}

# Performance metrics outputs
output "redis_performance_config" {
  description = "Redis performance configuration parameters"
  value = {
    for key, instance in google_redis_instance.trust_scoring_cache : key => {
      memory_size_gb    = instance.memory_size_gb
      replica_count     = instance.replica_count
      tier             = instance.tier
      max_connections  = 65000  # Default Redis max connections
      expected_throughput = {
        read_ops_per_second  = instance.memory_size_gb * 10000  # Estimated
        write_ops_per_second = instance.memory_size_gb * 8000   # Estimated
      }
    }
  }
  sensitive = false
}

# Security configuration outputs
output "redis_security_config" {
  description = "Redis security configuration details"
  value = {
    auth_enabled           = var.auth_enabled
    transit_encryption     = var.transit_encryption_mode
    password_secret_names  = [for secret in google_secret_manager_secret.redis_password : secret.name]
    network_isolation      = "PRIVATE_VPC"
    firewall_rules        = "INTERNAL_ONLY"
    compliance_frameworks  = var.compliance_frameworks
    data_residency_enabled = var.data_residency_enabled
  }
  sensitive = false
}

# Service endpoints for applications
output "cache_service_endpoints" {
  description = "Cache service endpoints for application configuration"
  value = {
    primary_endpoint = {
      region  = google_redis_instance.trust_scoring_cache["primary"].region
      host    = google_redis_instance.trust_scoring_cache["primary"].host
      port    = google_redis_instance.trust_scoring_cache["primary"].port
      db      = 0
    }
    regional_endpoints = {
      for key, instance in google_redis_instance.trust_scoring_cache : key => {
        region = instance.region
        host   = instance.host
        port   = instance.port
        db     = 0
      } if key != "primary"
    }
    sentinel_endpoints = var.sentinel_enabled ? [
      for i in range(var.sentinel_instances) : {
        host = "sentinel-${i}.${var.primary_region}.c.${var.project_id}.internal"
        port = var.sentinel_port
      }
    ] : []
  }
  sensitive = false
}

# Application configuration template
output "application_config_template" {
  description = "Template configuration for applications using Redis cache"
  value = {
    redis_config = {
      primary = {
        host                = google_redis_instance.trust_scoring_cache["primary"].host
        port                = google_redis_instance.trust_scoring_cache["primary"].port
        password_secret     = google_secret_manager_secret.redis_password["primary"].name
        db                  = 0
        timeout             = 5
        retry_attempts      = 3
        max_connections     = 100
      }
      sentinel = var.sentinel_enabled ? {
        enabled    = true
        masters    = ["isectech-trust-master"]
        hosts      = [
          for i in range(var.sentinel_instances) : {
            host = "sentinel-${i}.${var.primary_region}.c.${var.project_id}.internal"
            port = var.sentinel_port
          }
        ]
        password_secret = google_secret_manager_secret.redis_password["primary"].name
      } : null
      cache_policies = {
        trust_scores = {
          ttl_seconds       = var.trust_score_ttl
          compression       = true
          serialization     = "pickle"
        }
        device_profiles = {
          ttl_seconds       = var.device_profile_ttl
          compression       = true
          serialization     = "json"
        }
        network_context = {
          ttl_seconds       = var.network_context_ttl
          compression       = false
          serialization     = "json"
        }
        threat_intelligence = {
          ttl_seconds       = var.threat_intelligence_ttl
          compression       = true
          serialization     = "pickle"
        }
      }
    }
    monitoring = {
      metrics_enabled     = true
      prometheus_port     = 9121
      health_check_path   = "/health"
      log_level          = "INFO"
    }
  }
  sensitive = false
}

# Resource identifiers for other Terraform modules
output "resource_ids" {
  description = "Resource identifiers for integration with other Terraform modules"
  value = {
    redis_instances = {
      for key, instance in google_redis_instance.trust_scoring_cache : key => instance.id
    }
    secret_ids = {
      for key, secret in google_secret_manager_secret.redis_password : key => secret.id
    }
    service_account_id = google_service_account.redis_sentinel.id
    vpc_connection_id  = google_service_networking_connection.private_vpc_connection.network
    health_check_id    = var.sentinel_enabled ? google_compute_health_check.redis_sentinel.id : null
    instance_group_id  = var.sentinel_enabled ? google_compute_region_instance_group_manager.redis_sentinel.id : null
  }
  sensitive = false
}

# Summary output for documentation
output "deployment_summary" {
  description = "Summary of Redis deployment for documentation and runbooks"
  value = {
    deployment_info = {
      environment         = var.environment
      primary_region      = var.primary_region
      secondary_regions   = var.secondary_regions
      total_instances     = length(google_redis_instance.trust_scoring_cache)
      total_memory_gb     = sum([for instance in google_redis_instance.trust_scoring_cache : instance.memory_size_gb])
      redis_version       = var.redis_version
      high_availability   = var.redis_tier == "STANDARD_HA"
      sentinel_enabled    = var.sentinel_enabled
      backup_enabled      = var.backup_enabled
    }
    access_info = {
      authentication_required = var.auth_enabled
      encryption_in_transit   = var.transit_encryption_mode != "DISABLED"
      network_access         = "PRIVATE_VPC_ONLY"
      password_location      = "Google_Secret_Manager"
    }
    operational_info = {
      monitoring_enabled    = true
      automated_backups     = var.backup_enabled
      maintenance_window    = "${var.maintenance_window_day} ${var.maintenance_window_hour}:00 UTC"
      expected_throughput   = "100,000+ operations/second"
      multi_region_setup    = length(var.secondary_regions) > 0
    }
  }
  sensitive = false
}