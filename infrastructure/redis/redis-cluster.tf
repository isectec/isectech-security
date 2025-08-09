# iSECTECH Redis Cluster Configuration for Trust Scoring
# Production-grade Redis deployment with high availability and performance optimization

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

# Local variables
locals {
  redis_instances = {
    primary = {
      region           = var.primary_region
      tier            = "STANDARD_HA"
      memory_size_gb  = 16
      replica_count   = 2
    }
    europe = {
      region           = "europe-west1"
      tier            = "STANDARD_HA" 
      memory_size_gb  = 8
      replica_count   = 1
    }
    asia = {
      region           = "asia-northeast1"
      tier            = "STANDARD_HA"
      memory_size_gb  = 8
      replica_count   = 1
    }
    australia = {
      region           = "australia-southeast1"
      tier            = "STANDARD_HA"
      memory_size_gb  = 8
      replica_count   = 1
    }
  }
  
  # Cache configuration
  cache_policies = {
    trust_scores = {
      ttl_seconds = 300  # 5 minutes
      max_memory_policy = "allkeys-lru"
    }
    device_profiles = {
      ttl_seconds = 1800  # 30 minutes
      max_memory_policy = "allkeys-lru"
    }
    network_context = {
      ttl_seconds = 600  # 10 minutes
      max_memory_policy = "volatile-lru"
    }
    threat_intelligence = {
      ttl_seconds = 3600  # 1 hour
      max_memory_policy = "volatile-ttl"
    }
  }
}

# Redis instances for each region
resource "google_redis_instance" "trust_scoring_cache" {
  for_each = local.redis_instances
  
  name           = "isectech-trust-cache-${each.key}"
  project        = var.project_id
  region         = each.value.region
  memory_size_gb = each.value.memory_size_gb
  tier           = each.value.tier
  
  # Network configuration
  authorized_network = data.google_compute_network.vpc.id
  connect_mode      = "PRIVATE_SERVICE_ACCESS"
  
  # Redis configuration
  redis_version     = "REDIS_7_0"
  display_name      = "iSECTECH Trust Scoring Cache - ${title(each.key)} Region"
  
  # High availability configuration
  replica_count            = each.value.replica_count
  read_replicas_mode      = "READ_REPLICAS_ENABLED"
  
  # Security configuration
  auth_enabled           = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  
  # Redis configuration parameters
  redis_configs = {
    # Memory management
    maxmemory-policy = "allkeys-lru"
    maxmemory-samples = "10"
    
    # Performance optimization
    tcp-keepalive = "300"
    timeout = "0"
    
    # Persistence configuration
    save = "900 1 300 10 60 10000"
    
    # Security settings
    requirepass = random_password.redis_password[each.key].result
    
    # Connection settings
    tcp-backlog = "511"
    databases = "16"
    
    # Performance tuning for trust scoring workloads
    hash-max-ziplist-entries = "512"
    hash-max-ziplist-value = "64"
    list-max-ziplist-size = "-2"
    set-max-intset-entries = "512"
    zset-max-ziplist-entries = "128"
    zset-max-ziplist-value = "64"
    
    # Client output buffer limits
    client-output-buffer-limit-normal = "0 0 0"
    client-output-buffer-limit-replica = "256mb 64mb 60"
    client-output-buffer-limit-pubsub = "32mb 8mb 60"
  }
  
  # Maintenance window
  maintenance_policy {
    weekly_maintenance_window {
      day = "SUNDAY"
      start_time {
        hours   = 2
        minutes = 0
        seconds = 0
        nanos   = 0
      }
    }
  }
  
  labels = {
    environment = var.environment
    application = "trust-scoring"
    region     = each.key
    tier       = "cache"
    component  = "redis"
  }
  
  depends_on = [
    google_service_networking_connection.private_vpc_connection
  ]
}

# Generate secure passwords for Redis instances
resource "random_password" "redis_password" {
  for_each = local.redis_instances
  
  length  = 32
  special = true
  upper   = true
  lower   = true
  numeric = true
}

# Store Redis passwords in Secret Manager
resource "google_secret_manager_secret" "redis_password" {
  for_each  = local.redis_instances
  project   = var.project_id
  secret_id = "redis-password-${each.key}"
  
  labels = {
    environment = var.environment
    application = "trust-scoring"
    component   = "redis"
    region     = each.key
  }
  
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "redis_password" {
  for_each = local.redis_instances
  
  secret      = google_secret_manager_secret.redis_password[each.key].id
  secret_data = random_password.redis_password[each.key].result
}

# Redis Sentinel configuration for failover
resource "google_compute_instance_template" "redis_sentinel" {
  name_prefix = "redis-sentinel-template-"
  project     = var.project_id
  
  machine_type = "e2-standard-2"
  
  # Boot disk
  disk {
    source_image = "ubuntu-os-cloud/ubuntu-2204-lts"
    auto_delete  = true
    boot        = true
    disk_size_gb = 20
    disk_type    = "pd-ssd"
  }
  
  # Network configuration
  network_interface {
    network    = data.google_compute_network.vpc.id
    subnetwork = data.google_compute_subnetwork.private_subnet.id
  }
  
  # Service account
  service_account {
    email  = google_service_account.redis_sentinel.email
    scopes = [
      "cloud-platform"
    ]
  }
  
  # Startup script to configure Redis Sentinel
  metadata_startup_script = templatefile("${path.module}/scripts/redis-sentinel-startup.sh", {
    project_id = var.project_id
    region     = var.primary_region
  })
  
  tags = ["redis-sentinel", "allow-internal"]
  
  labels = {
    environment = var.environment
    application = "trust-scoring"
    component   = "redis-sentinel"
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Managed instance group for Redis Sentinel
resource "google_compute_region_instance_group_manager" "redis_sentinel" {
  name   = "redis-sentinel-group"
  region = var.primary_region
  
  base_instance_name = "redis-sentinel"
  target_size        = 3  # Odd number for quorum
  
  version {
    instance_template = google_compute_instance_template.redis_sentinel.id
  }
  
  # Auto-healing policy
  auto_healing_policies {
    health_check      = google_compute_health_check.redis_sentinel.id
    initial_delay_sec = 300
  }
  
  # Update policy
  update_policy {
    type                         = "PROACTIVE"
    instance_redistribution_type = "PROACTIVE"
    minimal_action              = "REPLACE"
    max_surge_fixed             = 1
    max_unavailable_fixed       = 1
  }
}

# Health check for Redis Sentinel
resource "google_compute_health_check" "redis_sentinel" {
  name = "redis-sentinel-health-check"
  
  timeout_sec        = 5
  check_interval_sec = 10
  
  tcp_health_check {
    port = "26379"
  }
}

# Service account for Redis Sentinel
resource "google_service_account" "redis_sentinel" {
  project      = var.project_id
  account_id   = "redis-sentinel-sa"
  display_name = "Redis Sentinel Service Account"
  description  = "Service account for Redis Sentinel instances"
}

# IAM binding for Redis Sentinel
resource "google_project_iam_member" "redis_sentinel_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.redis_sentinel.email}"
}

resource "google_project_iam_member" "redis_sentinel_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer" 
  member  = "serviceAccount:${google_service_account.redis_sentinel.email}"
}

# VPC and networking resources
data "google_compute_network" "vpc" {
  name    = "isectech-vpc"
  project = var.project_id
}

data "google_compute_subnetwork" "private_subnet" {
  name   = "isectech-private-subnet"
  region = var.primary_region
}

# Private service connection for Redis
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = data.google_compute_network.vpc.id
  service                = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

resource "google_compute_global_address" "private_ip_address" {
  project       = var.project_id
  name          = "redis-private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = data.google_compute_network.vpc.id
}

# Cloud Monitoring alerts for Redis
resource "google_monitoring_alert_policy" "redis_memory_utilization" {
  for_each = local.redis_instances
  
  display_name = "Redis Memory Utilization - ${title(each.key)}"
  project      = var.project_id
  
  conditions {
    display_name = "Memory utilization too high"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"redis.googleapi.com/stats/memory/utilization\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0.85
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }
  
  notification_channels = [google_monitoring_notification_channel.email.name]
  
  enabled = true
}

resource "google_monitoring_alert_policy" "redis_connection_count" {
  for_each = local.redis_instances
  
  display_name = "Redis Connection Count - ${title(each.key)}"
  project      = var.project_id
  
  conditions {
    display_name = "Too many connections"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"redis.googleapi.com/clients/connected\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 1000
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  notification_channels = [google_monitoring_notification_channel.email.name]
  
  enabled = true
}

# Notification channel
resource "google_monitoring_notification_channel" "email" {
  display_name = "Email Notification Channel"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = var.notification_email
  }
}

# Backup configuration for Redis
resource "google_compute_resource_policy" "redis_backup" {
  name   = "redis-backup-policy"
  region = var.primary_region
  
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "04:00"
      }
    }
    retention_policy {
      max_retention_days    = 14
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
    snapshot_properties {
      labels = {
        backup_type = "redis-daily"
        environment = var.environment
      }
      storage_locations = [var.primary_region]
      guest_flush       = false
    }
  }
}