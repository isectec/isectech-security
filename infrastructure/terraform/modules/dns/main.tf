# iSECTECH DNS Management Module
# Production-grade DNS managed zones and certificate management for custom domains
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

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
# LOCAL VALUES FOR ISECTECH DOMAIN CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

locals {
  # iSECTECH domain structure
  base_domain = "isectech.org"
  
  # Environment-specific subdomains
  domain_config = {
    production = {
      main_domain      = "app.${local.base_domain}"
      api_domain       = "api.${local.base_domain}"
      docs_domain      = "docs.${local.base_domain}"
      status_domain    = "status.${local.base_domain}"
      admin_domain     = "admin.${local.base_domain}"
    }
    staging = {
      main_domain      = "staging.${local.base_domain}"
      api_domain       = "api-staging.${local.base_domain}"
      docs_domain      = "docs-staging.${local.base_domain}"
      status_domain    = "status-staging.${local.base_domain}"
      admin_domain     = "admin-staging.${local.base_domain}"
    }
    development = {
      main_domain      = "dev.${local.base_domain}"
      api_domain       = "api-dev.${local.base_domain}"
      docs_domain      = "docs-dev.${local.base_domain}"
      status_domain    = "status-dev.${local.base_domain}"
      admin_domain     = "admin-dev.${local.base_domain}"
    }
  }
  
  # Current environment domains
  current_domains = local.domain_config[var.environment]
  
  # All domains for certificate management
  all_domains = [
    local.current_domains.main_domain,
    local.current_domains.api_domain,
    local.current_domains.docs_domain,
    local.current_domains.status_domain,
    local.current_domains.admin_domain
  ]
  
  common_labels = merge(var.labels, {
    project     = "isectech"
    component   = "dns-management"
    environment = var.environment
    managed-by  = "terraform"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS MANAGED ZONES FOR ISECTECH DOMAINS
# ═══════════════════════════════════════════════════════════════════════════════

# Primary managed zone for isectech.org
resource "google_dns_managed_zone" "isectech_primary" {
  name     = "isectech-${var.environment}-primary"
  dns_name = "${local.base_domain}."
  project  = var.project_id
  
  description = "Primary DNS zone for iSECTECH Security Platform - ${title(var.environment)} Environment"
  
  labels = local.common_labels

  # DNS security settings
  dnssec_config {
    kind          = "dns#managedZoneDnsSecConfig"
    non_existence = "nsec3"
    state         = "on"
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
      kind       = "dns#dnsKeySpec"
    }
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 1024
      key_type   = "zoneSigning"
      kind       = "dns#dnsKeySpec"
    }
  }
  
  # Forwarding configuration for private zones
  dynamic "forwarding_config" {
    for_each = var.enable_private_zones ? [1] : []
    content {
      target_name_servers {
        ipv4_address    = "8.8.8.8"
        forwarding_path = "default"
      }
      target_name_servers {
        ipv4_address    = "8.8.4.4"
        forwarding_path = "default"
      }
    }
  }
  
  # Private visibility for internal resolution
  dynamic "private_visibility_config" {
    for_each = var.enable_private_zones ? [1] : []
    content {
      networks {
        network_url = var.vpc_network_id
      }
    }
  }
  
  visibility = var.enable_private_zones ? "private" : "public"
}

# Environment-specific managed zones for isolated domain management
resource "google_dns_managed_zone" "environment_zones" {
  for_each = var.create_environment_zones ? toset([
    "app-${var.environment}",
    "api-${var.environment}",
    "docs-${var.environment}",
    "admin-${var.environment}",
    "status-${var.environment}"
  ]) : toset([])
  
  name     = "isectech-${each.key}-zone"
  dns_name = "${replace(each.key, "-${var.environment}", "")}-${var.environment == "production" ? "" : "${var.environment}."}${local.base_domain}."
  project  = var.project_id
  
  description = "DNS zone for ${each.key} - iSECTECH ${title(var.environment)} Environment"
  
  labels = merge(local.common_labels, {
    subdomain = replace(each.key, "-${var.environment}", "")
  })

  # DNSSEC configuration for enhanced security
  dnssec_config {
    kind          = "dns#managedZoneDnsSecConfig"
    non_existence = "nsec3"
    state         = "on"
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
      kind       = "dns#dnsKeySpec"
    }
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 1024
      key_type   = "zoneSigning"
      kind       = "dns#dnsKeySpec"
    }
  }
  
  visibility = "public"
}

# Private DNS zones for environment-specific internal communication
resource "google_dns_managed_zone" "environment_private_zones" {
  for_each = var.create_environment_zones ? toset([
    "internal-${var.environment}",
    "services-${var.environment}", 
    "databases-${var.environment}",
    "cache-${var.environment}"
  ]) : toset([])
  
  name     = "isectech-${each.key}-private-zone"
  dns_name = "${each.key}.isectech.internal."
  project  = var.project_id
  
  description = "Private DNS zone for ${each.key} - iSECTECH Internal ${title(var.environment)} Services"
  
  labels = merge(local.common_labels, {
    zone_type = "private"
    isolation_level = "environment"
    network_tier = replace(each.key, "-${var.environment}", "")
  })

  # DNSSEC for private zones (enhanced security)
  dnssec_config {
    kind          = "dns#managedZoneDnsSecConfig"
    non_existence = "nsec3"
    state         = "on"
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
      kind       = "dns#dnsKeySpec"
    }
    
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 1024
      key_type   = "zoneSigning"
      kind       = "dns#dnsKeySpec"
    }
  }
  
  # Private visibility restricted to environment VPC
  visibility = "private"
  
  private_visibility_config {
    networks {
      network_url = var.vpc_network_id
    }
  }
  
  # Forwarding configuration for internal resolution
  forwarding_config {
    target_name_servers {
      ipv4_address    = "169.254.169.254"  # GCP metadata server
      forwarding_path = "default"
    }
  }
}

# Environment isolation policies
resource "google_dns_policy" "environment_isolation_policy" {
  for_each = var.create_environment_zones ? toset([var.environment]) : toset([])
  
  name    = "isectech-${each.key}-isolation-policy"
  project = var.project_id
  
  description = "DNS isolation policy for iSECTECH ${title(each.key)} environment"
  
  enable_inbound_forwarding = false  # Prevent cross-environment resolution
  enable_logging           = var.enable_dns_logging
  
  # Alternative name servers for environment isolation
  alternative_name_server_config {
    target_name_servers {
      ipv4_address    = "8.8.8.8"
      forwarding_path = "default"
    }
    target_name_servers {
      ipv4_address    = "8.8.4.4"  
      forwarding_path = "default"
    }
  }
  
  networks {
    network_url = var.vpc_network_id
  }
}

# Internal service records for environment isolation
resource "google_dns_record_set" "internal_service_records" {
  for_each = var.create_environment_zones ? {
    "api.internal-${var.environment}.isectech.internal."      = ["10.${var.environment == "production" ? "1" : var.environment == "staging" ? "2" : "3"}.1.10"]
    "db.databases-${var.environment}.isectech.internal."      = ["10.${var.environment == "production" ? "1" : var.environment == "staging" ? "2" : "3"}.2.10"]
    "redis.cache-${var.environment}.isectech.internal."       = ["10.${var.environment == "production" ? "1" : var.environment == "staging" ? "2" : "3"}.3.10"]
    "logs.services-${var.environment}.isectech.internal."     = ["10.${var.environment == "production" ? "1" : var.environment == "staging" ? "2" : "3"}.4.10"]
    "metrics.services-${var.environment}.isectech.internal."  = ["10.${var.environment == "production" ? "1" : var.environment == "staging" ? "2" : "3"}.5.10"]
  } : {}
  
  name = each.key
  managed_zone = google_dns_managed_zone.environment_private_zones[
    split(".", each.key)[1]  # Extract zone from FQDN
  ].name
  type    = "A"
  ttl     = 300
  project = var.project_id

  rrdatas = each.value
}

# Cross-environment access controls via DNS firewall rules
resource "google_compute_firewall" "dns_environment_isolation" {
  count = var.create_environment_zones ? 1 : 0
  
  name    = "isectech-${var.environment}-dns-isolation"
  network = var.vpc_network_id
  project = var.project_id

  description = "DNS firewall rules for environment isolation"

  # Deny DNS queries from other environments
  deny {
    protocol = "udp"
    ports    = ["53"]
  }
  
  deny {
    protocol = "tcp"
    ports    = ["53"]
  }
  
  # Source ranges for other environments (to be blocked)
  source_ranges = var.environment == "production" ? [
    "10.2.0.0/16",  # staging
    "10.3.0.0/16"   # development
  ] : var.environment == "staging" ? [
    "10.1.0.0/16",  # production
    "10.3.0.0/16"   # development
  ] : [
    "10.1.0.0/16",  # production
    "10.2.0.0/16"   # staging
  ]
  
  # Apply to DNS servers only
  target_tags = ["dns-server"]
  
  priority = 1000
}

# Allow DNS within the same environment
resource "google_compute_firewall" "dns_environment_allow" {
  count = var.create_environment_zones ? 1 : 0
  
  name    = "isectech-${var.environment}-dns-allow"
  network = var.vpc_network_id
  project = var.project_id

  description = "Allow DNS queries within the same environment"

  allow {
    protocol = "udp"
    ports    = ["53"]
  }
  
  allow {
    protocol = "tcp"
    ports    = ["53"]
  }
  
  # Source ranges for current environment
  source_ranges = [
    var.environment == "production" ? "10.1.0.0/16" : 
    var.environment == "staging" ? "10.2.0.0/16" : "10.3.0.0/16"
  ]
  
  target_tags = ["dns-server"]
  priority = 900  # Higher priority than deny rules
}

# Environment-specific Cloud Armor security policies for DNS
resource "google_compute_security_policy" "dns_environment_security" {
  count = var.create_environment_zones ? 1 : 0
  
  name        = "isectech-${var.environment}-dns-security"
  project     = var.project_id
  description = "Security policy for DNS environment isolation"

  # Default rule - deny all
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny rule for DNS environment isolation"
  }

  # Allow from same environment CIDR
  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = [
          var.environment == "production" ? "10.1.0.0/16" : 
          var.environment == "staging" ? "10.2.0.0/16" : "10.3.0.0/16"
        ]
      }
    }
    description = "Allow DNS from same environment"
  }

  # Rate limiting per environment
  rule {
    action   = "rate_based_ban"
    priority = "1500"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.environment == "production" ? 1000 : 500
        interval_sec = 60
      }
      ban_duration_sec = 600  # 10 minutes
    }
    description = "Environment-specific DNS rate limiting"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS POLICY FOR ENHANCED SECURITY AND PERFORMANCE
# ═══════════════════════════════════════════════════════════════════════════════

# DNS policy for enhanced security
resource "google_dns_policy" "isectech_dns_policy" {
  name    = "isectech-${var.environment}-dns-policy"
  project = var.project_id
  
  description = "DNS policy for enhanced security and performance - iSECTECH ${title(var.environment)}"
  
  # Enable DNS logging for security monitoring
  enable_logging = var.enable_dns_logging
  
  # Enable inbound DNS forwarding for hybrid environments
  enable_inbound_forwarding = var.enable_dns_forwarding
  
  # Configure alternative name servers for reliability
  alternative_name_server_config {
    target_name_servers {
      ipv4_address    = "1.1.1.1"      # Cloudflare DNS
      forwarding_path = "default"
    }
    target_name_servers {
      ipv4_address    = "1.0.0.1"      # Cloudflare DNS Secondary
      forwarding_path = "default"
    }
    target_name_servers {
      ipv4_address    = "8.8.8.8"      # Google DNS
      forwarding_path = "default"
    }
    target_name_servers {
      ipv4_address    = "8.8.4.4"      # Google DNS Secondary
      forwarding_path = "default"
    }
  }
  
  # Network associations for policy application
  networks {
    network_url = var.vpc_network_id
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS RECORD SETS FOR DOMAIN VERIFICATION AND INITIAL SETUP
# ═══════════════════════════════════════════════════════════════════════════════

# CAA records for certificate authority authorization
resource "google_dns_record_set" "caa_records" {
  name         = google_dns_managed_zone.isectech_primary.dns_name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "CAA"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "0 issue \"letsencrypt.org\"",
    "0 issue \"google.com\"",
    "0 issuewild \"letsencrypt.org\"",
    "0 issuewild \"google.com\"",
    "0 iodef \"mailto:security@isectech.org\""
  ]
}

# TXT records for domain verification and security
resource "google_dns_record_set" "txt_verification" {
  name         = google_dns_managed_zone.isectech_primary.dns_name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "\"v=spf1 include:_spf.google.com ~all\"",
    "\"google-site-verification=${var.google_site_verification_code}\"",
    "\"MS=${var.microsoft_domain_verification_code}\"",
    "\"isectech-verification=${var.custom_verification_code}\""
  ]
}

# DMARC record for email security
resource "google_dns_record_set" "dmarc_record" {
  name         = "_dmarc.${google_dns_managed_zone.isectech_primary.dns_name}"
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@isectech.org; ruf=mailto:forensic@isectech.org; fo=1\""
  ]
}

# DKIM selector records for email authentication
resource "google_dns_record_set" "dkim_records" {
  for_each = var.dkim_selectors
  
  name         = "${each.key}._domainkey.${google_dns_managed_zone.isectech_primary.dns_name}"
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [each.value]
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING FOR DNS
# ═══════════════════════════════════════════════════════════════════════════════

# DNS query count monitoring
resource "google_monitoring_alert_policy" "dns_query_volume" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - High DNS Query Volume"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content   = "Alert when DNS query volume exceeds normal thresholds for ${var.environment} environment"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "High DNS query volume"
    
    condition_threshold {
      filter          = "resource.type=\"dns_query\" AND resource.labels.project_id=\"${var.project_id}\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.environment == "production" ? 10000 : 1000
      duration        = "300s"
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  alert_strategy {
    auto_close = "86400s" # 24 hours
  }
}

# DNS resolution failure monitoring
resource "google_monitoring_alert_policy" "dns_resolution_failures" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - DNS Resolution Failures"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content   = "Alert when DNS resolution failures exceed acceptable thresholds"
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "DNS resolution failures"
    
    condition_threshold {
      filter          = "resource.type=\"dns_query\" AND metric.type=\"dns.googleapis.com/query/count\" AND metric.labels.response_code!=\"NOERROR\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 50
      duration        = "300s"
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  alert_strategy {
    auto_close = "3600s" # 1 hour
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD RUN DOMAIN MAPPING AND DNS RECORDS
# ═══════════════════════════════════════════════════════════════════════════════

# Data source to get Cloud Run service URLs
data "google_cloud_run_service" "services" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name     = each.value.service_name
  project  = var.project_id
  location = each.value.region
}

# Create domain mapping resources for Cloud Run services
resource "google_cloud_run_domain_mapping" "domain_mappings" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name     = each.key
  project  = var.project_id
  location = each.value.region

  metadata {
    namespace = var.project_id
    labels = merge(local.common_labels, {
      domain   = replace(each.key, ".", "-")
      service  = each.value.service_name
    })
    
    annotations = {
      "run.googleapis.com/ingress" = "all"
      "run.googleapis.com/ingress-status" = "all"
    }
  }

  spec {
    route_name       = each.value.service_name
    certificate_mode = "AUTOMATIC"
    force_override   = true
  }

  depends_on = [google_dns_record_set.cloud_run_cname_records]
}

# Create CNAME records pointing to Cloud Run services
resource "google_dns_record_set" "cloud_run_cname_records" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "CNAME"
  ttl          = var.dns_cache_ttl
  project      = var.project_id

  rrdatas = ["ghs.googlehosted.com."]
  
  depends_on = [google_dns_managed_zone.isectech_primary]
}

# Create A records for root domain if needed
resource "google_dns_record_set" "cloud_run_a_records" {
  for_each = var.enable_cloud_run_mapping ? {
    for domain, config in var.cloud_run_services : domain => config
    if !can(regex("^[^.]+\\.", domain))  # Only for root domains
  } : {}
  
  name         = google_dns_managed_zone.isectech_primary.dns_name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "A"
  ttl          = var.dns_cache_ttl
  project      = var.project_id

  # Google Cloud Run IPv4 addresses for domain mapping
  rrdatas = [
    "216.239.32.21",
    "216.239.34.21",
    "216.239.36.21",
    "216.239.38.21"
  ]
}

# Create domain verification TXT records for Google Search Console
resource "google_dns_record_set" "google_search_console_verification" {
  for_each = var.enable_cloud_run_mapping && var.google_site_verification_code != "" ? var.cloud_run_services : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = ["google-site-verification=${var.google_site_verification_code}"]
}

# Create domain ownership verification records for Cloud Run
resource "google_dns_record_set" "cloud_run_domain_verification" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name         = "_domainkey.${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = ["google-domain-verification=${each.key}"]
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS HEALTH MONITORING AND FAILOVER
# ═══════════════════════════════════════════════════════════════════════════════

# Create uptime checks for all Cloud Run domains
resource "google_monitoring_uptime_check_config" "cloud_run_health_checks" {
  for_each = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? var.cloud_run_services : {}
  
  display_name = "iSECTECH Health Check - ${each.key}"
  project      = var.project_id
  timeout      = "10s"
  period       = "60s"
  
  selected_regions = [
    "USA_OREGON",
    "USA_VIRGINIA", 
    "EUROPE_IRELAND",
    "ASIA_PACIFIC_SINGAPORE"
  ]

  http_check {
    path               = "/health"
    port               = "443"
    use_ssl            = true
    validate_ssl       = true
    request_method     = "GET"
    
    headers = {
      "User-Agent" = "GoogleHC/1.0 (iSECTECH-Monitor)"
      "Accept"     = "application/json"
    }
    
    accepted_response_status_codes {
      status_value = 200
    }
    
    accepted_response_status_codes {
      status_value = 204
    }
  }

  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = each.key
    }
  }

  content_matchers {
    content = "healthy"
    matcher = "CONTAINS_STRING"
  }
}

# Create notification channels for health check failures
resource "google_monitoring_notification_channel" "dns_health_email" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name = "iSECTECH DNS Health - Email Notifications"
  project      = var.project_id
  type         = "email"
  
  labels = {
    email_address = var.dns_health_notification_email != "" ? var.dns_health_notification_email : "alerts@isectech.org"
  }
  
  description = "Email notifications for DNS health check failures"
}

resource "google_monitoring_notification_channel" "dns_health_slack" {
  count = var.enable_dns_monitoring && var.slack_webhook_url != "" ? 1 : 0
  
  display_name = "iSECTECH DNS Health - Slack Notifications"
  project      = var.project_id
  type         = "slack"
  
  labels = {
    url = var.slack_webhook_url
  }
  
  description = "Slack notifications for DNS health check failures"
}

# Alert policy for uptime check failures
resource "google_monitoring_alert_policy" "cloud_run_health_failures" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - Cloud Run Service Health Failures"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_dns_monitoring ? try(google_monitoring_notification_channel.dns_health_email[0].id, "") : "",
    var.enable_dns_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.dns_health_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # iSECTECH Cloud Run Service Health Alert
      
      One or more Cloud Run services are failing health checks.
      
      ## Immediate Actions:
      1. Check service status in Google Cloud Console
      2. Review service logs for errors
      3. Verify DNS resolution for affected domains
      4. Check for ongoing deployments
      
      ## Escalation:
      - If multiple services are affected, this may indicate infrastructure issues
      - Contact on-call engineer if resolution time exceeds 5 minutes
      
      Dashboard: https://console.cloud.google.com/monitoring
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Cloud Run service health check failure"
    
    condition_threshold {
      filter         = "resource.type=\"uptime_url\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      comparison     = "COMPARISON_EQUAL"
      threshold_value = 0
      duration       = "300s"  # 5 minutes
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields    = ["resource.label.host"]
      }
      
      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"  # 24 hours
    
    notification_rate_limit {
      period = "300s"  # Limit notifications to once per 5 minutes
    }
  }
}

# DNS failover policy using health-check integrated weighted routing
resource "google_dns_policy" "isectech_failover_policy" {
  count = var.enable_dns_monitoring && var.enable_dns_failover ? 1 : 0
  
  name    = "isectech-${var.environment}-failover-policy"
  project = var.project_id
  
  description = "DNS failover policy for iSECTECH domains with health check integration"
  
  enable_inbound_forwarding = true
  enable_logging           = var.enable_dns_logging
  
  networks {
    network_url = var.vpc_network_id
  }
}

# Primary A records with health check integration
resource "google_dns_record_set" "primary_a_records_with_failover" {
  for_each = var.enable_dns_monitoring && var.enable_dns_failover ? var.cloud_run_services : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "A"
  ttl          = 60  # Low TTL for quick failover
  project      = var.project_id

  # Primary Cloud Run service IPs
  rrdatas = [
    "216.239.32.21",
    "216.239.34.21", 
    "216.239.36.21",
    "216.239.38.21"
  ]
  
  # Routing policy for health-based failover
  routing_policy {
    wrr {
      weight  = 100
      rrdatas = [
        "216.239.32.21",
        "216.239.34.21", 
        "216.239.36.21",
        "216.239.38.21"
      ]
      
      # Health check configuration
      health_checked_targets {
        internal_load_balancers {
          load_balancer_type = "globalL7ilb"
          ip_address         = "216.239.32.21"
          port               = "443"
          ip_protocol        = "tcp"
          network_url        = var.vpc_network_id
          project            = var.project_id
        }
      }
    }
    
    # Backup endpoint with lower weight
    wrr {
      weight  = 0  # Only used when primary fails
      rrdatas = ["35.186.224.25"]  # Maintenance page IP
    }
    
    # Enable health checking for automated failover
    enable_health_checking = true
  }
}

# Backup CNAME records for complete service failure
resource "google_dns_record_set" "backup_cname_records" {
  for_each = var.enable_dns_monitoring && var.enable_dns_failover ? var.cloud_run_services : {}
  
  name         = "backup-${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "CNAME"
  ttl          = 300
  project      = var.project_id

  # Point to geographically distributed backup or CDN
  rrdatas = ["${each.key}.backup.googleapis.com."]
}

# Create maintenance page record for failover scenarios
resource "google_dns_record_set" "maintenance_page" {
  count = var.enable_dns_monitoring && var.enable_dns_failover ? 1 : 0
  
  name         = "maintenance.${google_dns_managed_zone.isectech_primary.dns_name}"
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "A"
  ttl          = 60  # Low TTL for quick maintenance mode activation
  project      = var.project_id

  # Point to a static maintenance page (hosted on Cloud Storage with CDN)
  rrdatas = [
    "35.186.224.25"  # Google Load Balancer IP for maintenance page
  ]
}

# Automated failover trigger alert policy
resource "google_monitoring_alert_policy" "dns_failover_trigger" {
  count = var.enable_dns_monitoring && var.enable_dns_failover ? 1 : 0
  
  display_name          = "iSECTECH - DNS Failover Trigger"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content = <<-EOT
      # DNS Failover Trigger Alert
      
      Automatic DNS failover has been triggered due to primary service health check failures.
      
      ## Immediate Actions:
      1. Verify primary service status
      2. Check load balancer health checks
      3. Monitor failover routing effectiveness
      4. Prepare for service restoration
      
      ## Recovery Steps:
      1. Restore primary service
      2. Verify health checks pass
      3. Monitor traffic return to primary
      4. Document incident details
      
      ## Resources:
      - Cloud Monitoring: https://console.cloud.google.com/monitoring
      - DNS Console: https://console.cloud.google.com/net-services/dns
      - Load Balancer Console: https://console.cloud.google.com/net-services/loadbalancing
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Primary service health check failures triggering failover"
    
    condition_threshold {
      filter          = "resource.type=\"gce_instance\" AND metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\""
      comparison      = "COMPARISON_LESS_THAN"
      threshold_value = 0.5  # Less than 50% of health checks passing
      duration        = "180s"  # 3 minutes of failures triggers failover
      
      aggregations {
        alignment_period     = "60s"
        per_series_aligner  = "ALIGN_FRACTION_TRUE"
        cross_series_reducer = "REDUCE_MEAN"
        group_by_fields     = ["resource.labels.instance_id"]
      }
      
      trigger {
        count = 1
      }
    }
  }

  alert_strategy {
    auto_close = "3600s"  # 1 hour
    
    notification_rate_limit {
      period = "300s"  # Limit notifications to once per 5 minutes
    }
  }
  
  severity = "CRITICAL"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS PROPAGATION TESTING AND VALIDATION INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Storage bucket for DNS test results
resource "google_storage_bucket" "dns_test_results" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  name     = "isectech-${var.environment}-dns-test-results"
  location = var.region
  project  = var.project_id
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.backup_retention_days
    }
  }
  
  uniform_bucket_level_access = true
  
  labels = merge(var.labels, {
    purpose = "dns-testing"
    component = "validation"
  })
}

# Service account for DNS validation function
resource "google_service_account" "dns_validation_sa" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  account_id   = "dns-validation-${var.environment}"
  display_name = "iSECTECH DNS Validation Service Account"
  description  = "Service account for DNS propagation testing and validation"
  project      = var.project_id
}

# IAM bindings for DNS validation service account
resource "google_project_iam_member" "dns_validation_monitoring_writer" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.dns_validation_sa[0].email}"
}

resource "google_project_iam_member" "dns_validation_storage_admin" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.dns_validation_sa[0].email}"
}

# DNS validation Cloud Function source archive
resource "google_storage_bucket_object" "dns_validation_source" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  name   = "dns-validation-source-${formatdate("YYYY-MM-DD-hhmm", timestamp())}.zip"
  bucket = google_storage_bucket.dns_test_results[0].name
  source = data.archive_file.dns_validation_source[0].output_path
  
  depends_on = [data.archive_file.dns_validation_source]
}

data "archive_file" "dns_validation_source" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  type        = "zip"
  output_path = "/tmp/dns-validation-function.zip"
  
  source {
    content = templatefile("${path.module}/../../../scripts/dns-validation-function.py", {
      project_id = var.project_id
      domains    = jsonencode([
        "app.isectech.org",
        "api.isectech.org",
        "docs.isectech.org",
        "admin.isectech.org",
        "status.isectech.org"
      ])
    })
    filename = "main.py"
  }
  
  source {
    content = <<-EOF
      dnspython==2.3.0
      google-cloud-monitoring==2.15.1
      google-cloud-storage==2.10.0
      google-cloud-functions==1.13.3
    EOF
    filename = "requirements.txt"
  }
}

# DNS validation Cloud Function
resource "google_cloudfunctions_function" "dns_validation" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  name        = "dns-validation-${var.environment}"
  project     = var.project_id
  region      = var.region
  description = "iSECTECH DNS propagation testing and validation function"
  
  runtime     = "python39"
  timeout     = 540  # 9 minutes
  memory      = 512
  
  source_archive_bucket = google_storage_bucket.dns_test_results[0].name
  source_archive_object = google_storage_bucket_object.dns_validation_source[0].name
  entry_point          = "dns_validation_cloud_function"
  
  service_account_email = google_service_account.dns_validation_sa[0].email
  
  # Environment variables
  environment_variables = {
    PROJECT_ID    = var.project_id
    ENVIRONMENT   = var.environment
    BUCKET_NAME   = google_storage_bucket.dns_test_results[0].name
  }
  
  # Trigger configuration
  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = google_pubsub_topic.dns_validation_trigger[0].name
  }
  
  labels = merge(var.labels, {
    purpose = "dns-validation"
    component = "testing"
  })
}

# Pub/Sub topic for triggering DNS validation
resource "google_pubsub_topic" "dns_validation_trigger" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  name    = "dns-validation-trigger-${var.environment}"
  project = var.project_id
  
  labels = merge(var.labels, {
    purpose = "dns-validation"
    component = "trigger"
  })
}

# Cloud Scheduler job for regular DNS validation
resource "google_cloud_scheduler_job" "dns_validation_schedule" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  name        = "dns-validation-schedule-${var.environment}"
  project     = var.project_id
  region      = var.region
  description = "Scheduled DNS propagation and validation testing"
  
  # Run every 4 hours for production, every 12 hours for others
  schedule = var.environment == "production" ? "0 */4 * * *" : "0 */12 * * *"
  time_zone = "UTC"
  
  pubsub_target {
    topic_name = google_pubsub_topic.dns_validation_trigger[0].id
    data       = base64encode(jsonencode({
      trigger_type = "scheduled"
      environment  = var.environment
    }))
  }
  
  retry_config {
    retry_count = 3
  }
}

# Alert policy for DNS validation failures
resource "google_monitoring_alert_policy" "dns_validation_failures" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - DNS Validation Test Failures"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content = <<-EOT
      # DNS Validation Test Failures
      
      Automated DNS validation tests are failing, indicating potential DNS propagation or configuration issues.
      
      ## Investigation Steps:
      1. Check DNS validation function logs
      2. Review recent DNS configuration changes
      3. Test DNS resolution manually from multiple locations
      4. Verify DNS server responsiveness
      
      ## Recovery Actions:
      1. Identify failing domains/records
      2. Verify DNS zone configurations
      3. Check name server delegation
      4. Test DNS propagation manually
      
      ## Resources:
      - Function Logs: https://console.cloud.google.com/functions
      - DNS Console: https://console.cloud.google.com/net-services/dns
      - Test Results: gs://${var.enable_dns_monitoring ? google_storage_bucket.dns_test_results[0].name : ""}
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "DNS validation test failure rate"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND metric.type=\"custom.googleapis.com/dns/test_success_rate\""
      comparison      = "COMPARISON_LESS_THAN"
      threshold_value = 80  # Alert if success rate drops below 80%
      duration        = "300s"
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner  = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_MEAN"
      }
    }
  }

  alert_strategy {
    auto_close = "7200s"  # 2 hours
  }
  
  severity = "WARNING"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS BACKUP AND VERSIONING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════

# Cloud Storage bucket for DNS configuration backups
resource "google_storage_bucket" "dns_backups" {
  count = var.enable_dns_backup ? 1 : 0
  
  name     = "isectech-${var.environment}-dns-backups"
  location = var.region
  project  = var.project_id
  
  # Enable versioning for backup history
  versioning {
    enabled = true
  }
  
  # Lifecycle management for backup retention
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age = var.backup_retention_days
    }
  }
  
  # Keep multiple versions but delete old ones
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age                        = 30
      with_state                = "ARCHIVED"
      num_newer_versions        = 10
    }
  }
  
  # Archive old versions after 7 days
  lifecycle_rule {
    action {
      type = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 7
      matches_storage_class = ["STANDARD"]
    }
  }
  
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  
  labels = merge(var.labels, {
    purpose = "dns-backup"
    component = "disaster-recovery"
    retention = "long-term"
  })
}

# Service account for DNS backup operations
resource "google_service_account" "dns_backup_sa" {
  count = var.enable_dns_backup ? 1 : 0
  
  account_id   = "dns-backup-${var.environment}"
  display_name = "iSECTECH DNS Backup Service Account"
  description  = "Service account for DNS configuration backup and restore operations"
  project      = var.project_id
}

# IAM bindings for DNS backup service account
resource "google_project_iam_member" "dns_backup_storage_admin" {
  count = var.enable_dns_backup ? 1 : 0
  
  project = var.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.dns_backup_sa[0].email}"
}

resource "google_project_iam_member" "dns_backup_dns_admin" {
  count = var.enable_dns_backup ? 1 : 0
  
  project = var.project_id
  role    = "roles/dns.admin"
  member  = "serviceAccount:${google_service_account.dns_backup_sa[0].email}"
}

resource "google_project_iam_member" "dns_backup_monitoring_writer" {
  count = var.enable_dns_backup ? 1 : 0
  
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.dns_backup_sa[0].email}"
}

# DNS backup Cloud Function source
resource "google_storage_bucket_object" "dns_backup_source" {
  count = var.enable_dns_backup ? 1 : 0
  
  name   = "dns-backup-source-${formatdate("YYYY-MM-DD-hhmm", timestamp())}.zip"
  bucket = google_storage_bucket.dns_backups[0].name
  source = data.archive_file.dns_backup_source[0].output_path
  
  depends_on = [data.archive_file.dns_backup_source]
}

data "archive_file" "dns_backup_source" {
  count = var.enable_dns_backup ? 1 : 0
  
  type        = "zip"
  output_path = "/tmp/dns-backup-function.zip"
  
  source {
    content = templatefile("${path.module}/../../../scripts/dns-backup-function.py", {
      project_id = var.project_id
      bucket_name = var.enable_dns_backup ? google_storage_bucket.dns_backups[0].name : ""
      environment = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = <<-EOF
      google-cloud-dns==0.34.0
      google-cloud-storage==2.10.0
      google-cloud-monitoring==2.15.1
      google-resumable-media==2.6.0
      pyyaml==6.0.1
    EOF
    filename = "requirements.txt"
  }
}

# DNS backup Cloud Function
resource "google_cloudfunctions_function" "dns_backup" {
  count = var.enable_dns_backup ? 1 : 0
  
  name        = "dns-backup-${var.environment}"
  project     = var.project_id
  region      = var.region
  description = "iSECTECH DNS configuration backup and versioning function"
  
  runtime     = "python39"
  timeout     = 540  # 9 minutes
  memory      = 1024
  
  source_archive_bucket = google_storage_bucket.dns_backups[0].name
  source_archive_object = google_storage_bucket_object.dns_backup_source[0].name
  entry_point          = "dns_backup_cloud_function"
  
  service_account_email = google_service_account.dns_backup_sa[0].email
  
  # Environment variables
  environment_variables = {
    PROJECT_ID      = var.project_id
    ENVIRONMENT     = var.environment
    BACKUP_BUCKET   = google_storage_bucket.dns_backups[0].name
    RETENTION_DAYS  = var.backup_retention_days
  }
  
  # HTTP trigger for manual backups
  https_trigger {}
  
  labels = merge(var.labels, {
    purpose = "dns-backup"
    component = "disaster-recovery"
  })
}

# Pub/Sub topic for scheduled DNS backups
resource "google_pubsub_topic" "dns_backup_trigger" {
  count = var.enable_dns_backup ? 1 : 0
  
  name    = "dns-backup-trigger-${var.environment}"
  project = var.project_id
  
  labels = merge(var.labels, {
    purpose = "dns-backup"
    component = "scheduling"
  })
}

# Cloud Scheduler job for automated DNS backups
resource "google_cloud_scheduler_job" "dns_backup_schedule" {
  count = var.enable_dns_backup ? 1 : 0
  
  name        = "dns-backup-schedule-${var.environment}"
  project     = var.project_id
  region      = var.region
  description = "Scheduled DNS configuration backup"
  
  # Daily backups for production, weekly for others
  schedule = var.environment == "production" ? "0 2 * * *" : "0 2 * * 0"
  time_zone = "UTC"
  
  http_target {
    uri         = google_cloudfunctions_function.dns_backup[0].https_trigger_url
    http_method = "POST"
    
    headers = {
      "Content-Type" = "application/json"
    }
    
    body = base64encode(jsonencode({
      backup_type = "scheduled"
      environment = var.environment
      full_backup = true
    }))
  }
  
  retry_config {
    retry_count = 3
  }
}

# DNS restore Cloud Function for disaster recovery
resource "google_cloudfunctions_function" "dns_restore" {
  count = var.enable_dns_backup ? 1 : 0
  
  name        = "dns-restore-${var.environment}"
  project     = var.project_id
  region      = var.region
  description = "iSECTECH DNS configuration restore function for disaster recovery"
  
  runtime     = "python39"
  timeout     = 540  # 9 minutes
  memory      = 1024
  
  source_archive_bucket = google_storage_bucket.dns_backups[0].name
  source_archive_object = google_storage_bucket_object.dns_restore_source[0].name
  entry_point          = "dns_restore_cloud_function"
  
  service_account_email = google_service_account.dns_backup_sa[0].email
  
  # Environment variables
  environment_variables = {
    PROJECT_ID      = var.project_id
    ENVIRONMENT     = var.environment
    BACKUP_BUCKET   = google_storage_bucket.dns_backups[0].name
  }
  
  # HTTP trigger for restore operations
  https_trigger {}
  
  labels = merge(var.labels, {
    purpose = "dns-restore"
    component = "disaster-recovery"
  })
}

# DNS restore function source
resource "google_storage_bucket_object" "dns_restore_source" {
  count = var.enable_dns_backup ? 1 : 0
  
  name   = "dns-restore-source-${formatdate("YYYY-MM-DD-hhmm", timestamp())}.zip"
  bucket = google_storage_bucket.dns_backups[0].name
  source = data.archive_file.dns_restore_source[0].output_path
  
  depends_on = [data.archive_file.dns_restore_source]
}

data "archive_file" "dns_restore_source" {
  count = var.enable_dns_backup ? 1 : 0
  
  type        = "zip"
  output_path = "/tmp/dns-restore-function.zip"
  
  source {
    content = templatefile("${path.module}/../../../scripts/dns-restore-function.py", {
      project_id = var.project_id
      bucket_name = var.enable_dns_backup ? google_storage_bucket.dns_backups[0].name : ""
      environment = var.environment
    })
    filename = "main.py"
  }
  
  source {
    content = <<-EOF
      google-cloud-dns==0.34.0
      google-cloud-storage==2.10.0
      google-cloud-monitoring==2.15.1
      google-resumable-media==2.6.0
      pyyaml==6.0.1
    EOF
    filename = "requirements.txt"
  }
}

# Backup monitoring alert policy
resource "google_monitoring_alert_policy" "dns_backup_failures" {
  count = var.enable_dns_backup ? 1 : 0
  
  display_name          = "iSECTECH - DNS Backup Failures"
  project              = var.project_id
  enabled              = true
  notification_channels = var.notification_channels
  
  documentation {
    content = <<-EOT
      # DNS Backup Failures
      
      DNS configuration backup operations are failing, which could impact disaster recovery capabilities.
      
      ## Investigation Steps:
      1. Check DNS backup function logs
      2. Verify Cloud Storage permissions and quotas
      3. Check DNS API permissions
      4. Review backup function execution errors
      
      ## Recovery Actions:
      1. Run manual backup to test functionality
      2. Verify service account permissions
      3. Check storage bucket accessibility
      4. Review and fix any configuration issues
      
      ## Resources:
      - Backup Function: https://console.cloud.google.com/functions
      - Backup Storage: gs://${var.enable_dns_backup ? google_storage_bucket.dns_backups[0].name : ""}
      - Function Logs: https://console.cloud.google.com/logs
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "DNS backup function execution failures"
    
    condition_threshold {
      filter          = "resource.type=\"cloud_function\" AND resource.labels.function_name=\"dns-backup-${var.environment}\" AND metric.type=\"cloudfunctions.googleapis.com/function/execution_count\" AND metric.labels.status=\"error\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 0
      duration        = "300s"
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner  = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
  
  severity = "ERROR"
}

# Alert policy for DNS resolution failures  
resource "google_monitoring_alert_policy" "dns_resolution_health" {
  count = var.enable_dns_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - DNS Resolution Health Issues"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_dns_monitoring ? try(google_monitoring_notification_channel.dns_health_email[0].id, "") : "",
    var.enable_dns_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.dns_health_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # DNS Resolution Health Alert
      
      DNS resolution issues detected for iSECTECH domains.
      
      ## Troubleshooting Steps:
      1. Check DNS zone configuration
      2. Verify name server delegation
      3. Test DNS resolution from multiple locations
      4. Check for DNS propagation issues
      
      ## Tools:
      - `dig @8.8.8.8 domain.isectech.org`
      - DNS propagation checker: https://dnschecker.org
      - Google DNS Console: https://console.cloud.google.com/net-services/dns
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "High DNS query failure rate"
    
    condition_threshold {
      filter         = "resource.type=\"dns_query\" AND resource.labels.project_id=\"${var.project_id}\" AND metric.labels.response_code!=\"NOERROR\""
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = var.dns_failure_threshold
      duration       = "300s"
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "3600s"  # 1 hour
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Certificate Map for managing multiple certificates
resource "google_certificate_manager_certificate_map" "isectech_certificate_map" {
  count = var.enable_certificate_manager ? 1 : 0
  
  name        = "isectech-${var.environment}-certificate-map"
  description = "Certificate map for iSECTECH ${title(var.environment)} environment"
  project     = var.project_id
  
  labels = merge(local.common_labels, {
    certificate-type = "managed"
    usage           = "cloud-run-domains"
  })
}

# DNS Authorization for domain validation
resource "google_certificate_manager_dns_authorization" "domain_authorizations" {
  for_each = var.enable_certificate_manager ? toset(var.certificate_domains) : toset([])
  
  name   = "isectech-${var.environment}-${replace(each.value, ".", "-")}-auth"
  domain = each.value
  project = var.project_id
  
  description = "DNS authorization for ${each.value} in ${var.environment} environment"
  
  labels = merge(local.common_labels, {
    domain      = replace(each.value, ".", "-")
    auth-method = "dns"
  })
}

# Create DNS records for certificate validation
resource "google_dns_record_set" "certificate_validation_records" {
  for_each = var.enable_certificate_manager ? google_certificate_manager_dns_authorization.domain_authorizations : {}
  
  name         = each.value.dns_resource_record[0].name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = each.value.dns_resource_record[0].type
  ttl          = 300
  project      = var.project_id

  rrdatas = [each.value.dns_resource_record[0].data]
  
  depends_on = [google_certificate_manager_dns_authorization.domain_authorizations]
}

# Managed SSL Certificates using Certificate Manager
resource "google_certificate_manager_certificate" "managed_certificates" {
  for_each = var.enable_certificate_manager ? toset(var.certificate_domains) : toset([])
  
  name        = "isectech-${var.environment}-${replace(each.value, ".", "-")}-cert"
  description = "Managed SSL certificate for ${each.value}"
  project     = var.project_id
  scope       = "DEFAULT"
  
  managed {
    domains            = [each.value]
    dns_authorizations = [google_certificate_manager_dns_authorization.domain_authorizations[each.value].id]
  }
  
  labels = merge(local.common_labels, {
    domain          = replace(each.value, ".", "-")
    certificate-type = "managed"
    auto-renewal    = "enabled"
  })
  
  depends_on = [
    google_dns_record_set.certificate_validation_records,
    google_certificate_manager_dns_authorization.domain_authorizations
  ]
}

# Wildcard certificate for subdomains
resource "google_certificate_manager_certificate" "wildcard_certificate" {
  count = var.enable_certificate_manager && var.enable_wildcard_certificate ? 1 : 0
  
  name        = "isectech-${var.environment}-wildcard-cert"
  description = "Wildcard SSL certificate for *.${local.base_domain}"
  project     = var.project_id
  scope       = "DEFAULT"
  
  managed {
    domains = ["*.${local.base_domain}"]
    dns_authorizations = [
      google_certificate_manager_dns_authorization.wildcard_authorization[0].id
    ]
  }
  
  labels = merge(local.common_labels, {
    certificate-type = "wildcard"
    auto-renewal    = "enabled"
  })
  
  depends_on = [
    google_dns_record_set.wildcard_validation_record,
    google_certificate_manager_dns_authorization.wildcard_authorization
  ]
}

# DNS Authorization for wildcard certificate
resource "google_certificate_manager_dns_authorization" "wildcard_authorization" {
  count = var.enable_certificate_manager && var.enable_wildcard_certificate ? 1 : 0
  
  name   = "isectech-${var.environment}-wildcard-auth"
  domain = "*.${local.base_domain}"
  project = var.project_id
  
  description = "DNS authorization for wildcard certificate *.${local.base_domain}"
  
  labels = merge(local.common_labels, {
    certificate-type = "wildcard"
    auth-method     = "dns"
  })
}

# DNS record for wildcard certificate validation
resource "google_dns_record_set" "wildcard_validation_record" {
  count = var.enable_certificate_manager && var.enable_wildcard_certificate ? 1 : 0
  
  name         = google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].type
  ttl          = 300
  project      = var.project_id

  rrdatas = [google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].data]
  
  depends_on = [google_certificate_manager_dns_authorization.wildcard_authorization]
}

# Certificate Map Entries - Map domains to certificates
resource "google_certificate_manager_certificate_map_entry" "certificate_map_entries" {
  for_each = var.enable_certificate_manager ? toset(var.certificate_domains) : toset([])
  
  name         = "isectech-${var.environment}-${replace(each.value, ".", "-")}-entry"
  map          = google_certificate_manager_certificate_map.isectech_certificate_map[0].name
  certificates = [google_certificate_manager_certificate.managed_certificates[each.value].id]
  hostname     = each.value
  project      = var.project_id
  
  labels = merge(local.common_labels, {
    domain = replace(each.value, ".", "-")
  })
  
  depends_on = [
    google_certificate_manager_certificate.managed_certificates,
    google_certificate_manager_certificate_map.isectech_certificate_map
  ]
}

# Certificate Map Entry for wildcard certificate
resource "google_certificate_manager_certificate_map_entry" "wildcard_certificate_entry" {
  count = var.enable_certificate_manager && var.enable_wildcard_certificate ? 1 : 0
  
  name         = "isectech-${var.environment}-wildcard-entry"
  map          = google_certificate_manager_certificate_map.isectech_certificate_map[0].name
  certificates = [google_certificate_manager_certificate.wildcard_certificate[0].id]
  matcher      = "PRIMARY"
  project      = var.project_id
  
  labels = merge(local.common_labels, {
    certificate-type = "wildcard"
  })
  
  depends_on = [
    google_certificate_manager_certificate.wildcard_certificate,
    google_certificate_manager_certificate_map.isectech_certificate_map
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE RENEWAL AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Notification channel for SSL certificate alerts
resource "google_monitoring_notification_channel" "ssl_certificate_email" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring ? 1 : 0
  
  display_name = "iSECTECH SSL Certificate - Email Notifications"
  project      = var.project_id
  type         = "email"
  
  labels = {
    email_address = var.certificate_notification_email != "" ? var.certificate_notification_email : "security@isectech.org"
  }
  
  description = "Email notifications for SSL certificate issues"
}

resource "google_monitoring_notification_channel" "ssl_certificate_slack" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring && var.slack_webhook_url != "" ? 1 : 0
  
  display_name = "iSECTECH SSL Certificate - Slack Notifications"
  project      = var.project_id
  type         = "slack"
  
  labels = {
    url = var.slack_webhook_url
  }
  
  description = "Slack notifications for SSL certificate issues"
}

# Alert policy for certificate provisioning failures
resource "google_monitoring_alert_policy" "certificate_provisioning_failures" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - SSL Certificate Provisioning Failures"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_certificate_monitoring ? try(google_monitoring_notification_channel.ssl_certificate_email[0].id, "") : "",
    var.enable_certificate_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.ssl_certificate_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # SSL Certificate Provisioning Failure Alert
      
      One or more SSL certificates failed to provision properly via Google Certificate Manager.
      
      ## Immediate Actions:
      1. Check Certificate Manager console for detailed error messages
      2. Verify DNS records for domain validation are correctly configured
      3. Ensure domain ownership is properly established
      4. Check for any domain authorization issues
      
      ## Common Issues:
      - DNS propagation delays (wait 24-48 hours)
      - Incorrect DNS validation records
      - Domain ownership verification failures
      - Rate limiting from Let's Encrypt
      
      ## Resources:
      - Certificate Manager Console: https://console.cloud.google.com/security/ccm
      - DNS Console: https://console.cloud.google.com/net-services/dns
      
      ## Escalation:
      Contact DevOps team if issues persist beyond 48 hours.
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Certificate provisioning failure"
    
    condition_threshold {
      filter         = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/state\" AND metric.labels.state=\"FAILED\""
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 0
      duration       = "300s"  # Alert after 5 minutes
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MAX"
        cross_series_reducer = "REDUCE_COUNT"
        group_by_fields    = ["resource.label.certificate_name"]
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"  # 24 hours
    
    notification_rate_limit {
      period = "3600s"  # Limit notifications to once per hour
    }
  }
}

# Alert policy for certificate expiration warnings
resource "google_monitoring_alert_policy" "certificate_expiration_warning" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - SSL Certificate Expiration Warning"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_certificate_monitoring ? try(google_monitoring_notification_channel.ssl_certificate_email[0].id, "") : "",
    var.enable_certificate_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.ssl_certificate_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # SSL Certificate Expiration Warning
      
      One or more SSL certificates are approaching expiration.
      
      ## Expected Behavior:
      Google Certificate Manager should automatically renew certificates before expiration.
      This alert serves as an early warning system.
      
      ## Actions:
      1. Verify automatic renewal is enabled for affected certificates
      2. Check Certificate Manager console for renewal status
      3. Ensure DNS validation records are still correctly configured
      4. Monitor for successful renewal in the next 24-48 hours
      
      ## Manual Renewal (if needed):
      If automatic renewal fails, certificates may need manual intervention:
      1. Review certificate validation requirements
      2. Check domain authorization status
      3. Recreate certificate if necessary
      
      Console: https://console.cloud.google.com/security/ccm
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Certificate expires soon"
    
    condition_threshold {
      filter         = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/expiration_time\""
      comparison     = "COMPARISON_LESS_THAN"
      # Alert 30 days before expiration (configurable via variable)
      threshold_value = var.certificate_renewal_buffer_days * 24 * 3600  # Convert days to seconds
      duration       = "3600s"  # Alert after 1 hour
      
      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_MIN"
        cross_series_reducer = "REDUCE_MIN"
        group_by_fields    = ["resource.label.certificate_name"]
      }
    }
  }

  alert_strategy {
    auto_close = "604800s"  # 7 days
    
    notification_rate_limit {
      period = "86400s"  # Once per day
    }
  }
}

# Alert policy for certificate renewal failures
resource "google_monitoring_alert_policy" "certificate_renewal_failures" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - SSL Certificate Renewal Failures"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_certificate_monitoring ? try(google_monitoring_notification_channel.ssl_certificate_email[0].id, "") : "",
    var.enable_certificate_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.ssl_certificate_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # SSL Certificate Renewal Failure Alert
      
      **CRITICAL**: SSL certificate renewal has failed. Immediate action required.
      
      ## Immediate Actions:
      1. **HIGH PRIORITY**: Check certificate status in Certificate Manager console
      2. Verify DNS validation records are still correct
      3. Check domain authorization status
      4. Review renewal attempt logs for specific error messages
      
      ## Common Renewal Failure Causes:
      - DNS validation record changes or deletion
      - Domain ownership verification issues
      - Rate limiting from certificate authority
      - Network connectivity issues
      - Configuration changes affecting domain validation
      
      ## Recovery Steps:
      1. Verify current DNS configuration matches requirements
      2. Check domain authorization records are intact
      3. If needed, recreate authorization and certificate resources
      4. Monitor for successful renewal
      
      ## Timeline:
      - Act within 24 hours to prevent service disruption
      - Certificates typically expire 90 days after issuance
      
      Console: https://console.cloud.google.com/security/ccm
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Certificate renewal failed"
    
    condition_threshold {
      filter         = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/renewal_failure\""
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 0
      duration       = "60s"  # Alert immediately
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT_TRUE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields    = ["resource.label.certificate_name"]
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"  # 24 hours
    
    notification_rate_limit {
      period = "1800s"  # Allow notifications every 30 minutes for critical issues
    }
  }
}

# Log-based metric for certificate state changes
resource "google_logging_metric" "certificate_state_changes" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring ? 1 : 0
  
  name   = "isectech_certificate_state_changes"
  project = var.project_id
  
  filter = <<-EOT
    resource.type="certificate_manager_certificate"
    protoPayload.methodName="google.cloud.certificatemanager.v1.CertificateManager.UpdateCertificate"
    OR protoPayload.methodName="google.cloud.certificatemanager.v1.CertificateManager.CreateCertificate"
  EOT
  
  label_extractors = {
    certificate_name = "EXTRACT(resource.labels.certificate_name)"
    operation_type   = "EXTRACT(protoPayload.methodName)"
  }
  
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Certificate State Changes"
    description  = "Tracks certificate state changes for monitoring renewal activity"
  }
}

# Dashboard for SSL certificate monitoring
resource "google_monitoring_dashboard" "ssl_certificate_dashboard" {
  count = var.enable_certificate_manager && var.enable_certificate_monitoring && var.create_certificate_dashboard ? 1 : 0
  
  dashboard_json = jsonencode({
    displayName = "iSECTECH SSL Certificate Monitoring - ${title(var.environment)}"
    
    mosaicLayout = {
      tiles = [
        {
          width = 6
          height = 4
          widget = {
            title = "Certificate Status Overview"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/state\""
                  aggregation = {
                    alignmentPeriod = "60s"
                    perSeriesAligner = "ALIGN_MAX"
                    crossSeriesReducer = "REDUCE_COUNT"
                    groupByFields = ["metric.label.state"]
                  }
                }
              }
              sparkChartView = {
                sparkChartType = "SPARK_BAR"
              }
              gaugeView = {
                lowerBound = 0
                upperBound = 10
              }
            }
          }
        },
        {
          width = 6
          height = 4
          xPos = 6
          widget = {
            title = "Certificate Expiration Timeline"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/expiration_time\""
                    aggregation = {
                      alignmentPeriod = "3600s"
                      perSeriesAligner = "ALIGN_MAX"
                      crossSeriesReducer = "REDUCE_MIN"
                      groupByFields = ["resource.label.certificate_name"]
                    }
                  }
                }
                plotType = "LINE"
              }]
              timeshiftDuration = "0s"
              yAxis = {
                label = "Days Until Expiration"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width = 12
          height = 4
          yPos = 4
          widget = {
            title = "Certificate Validation Status"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "resource.type=\"certificate_manager_certificate\" AND metric.type=\"certificatemanager.googleapis.com/certificate/validation_state\""
                    aggregation = {
                      alignmentPeriod = "300s"
                      perSeriesAligner = "ALIGN_MAX"
                      crossSeriesReducer = "REDUCE_COUNT"
                      groupByFields = ["metric.label.validation_state", "resource.label.certificate_name"]
                    }
                  }
                }
                plotType = "STACKED_BAR"
              }]
            }
          }
        }
      ]
    }
  })
  
  project = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS AND CERTIFICATE PINNING
# ═══════════════════════════════════════════════════════════════════════════════

# Create security policy for HTTP security headers
resource "google_compute_security_policy" "isectech_security_headers_policy" {
  count = var.enable_security_headers ? 1 : 0
  
  name        = "isectech-${var.environment}-security-headers"
  description = "Security policy with HTTP security headers for iSECTECH domains"
  project     = var.project_id

  # Default rule to allow traffic with security headers
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule with security headers"
    
    header_action {
      request_headers_to_add {
        header_name  = "X-Forwarded-Proto"
        header_value = "https"
        replace      = true
      }
    }
  }
  
  # Security headers configuration
  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Apply security headers to all requests"
    
    header_action {
      # HTTP Strict Transport Security (HSTS)
      response_headers_to_add {
        header_name  = "Strict-Transport-Security"
        header_value = "max-age=31536000; includeSubDomains; preload"
      }
      
      # Content Security Policy (CSP)
      response_headers_to_add {
        header_name  = "Content-Security-Policy"
        header_value = var.content_security_policy
      }
      
      # X-Content-Type-Options
      response_headers_to_add {
        header_name  = "X-Content-Type-Options"
        header_value = "nosniff"
      }
      
      # X-Frame-Options
      response_headers_to_add {
        header_name  = "X-Frame-Options"
        header_value = "DENY"
      }
      
      # X-XSS-Protection
      response_headers_to_add {
        header_name  = "X-XSS-Protection"
        header_value = "1; mode=block"
      }
      
      # Referrer Policy
      response_headers_to_add {
        header_name  = "Referrer-Policy"
        header_value = "strict-origin-when-cross-origin"
      }
      
      # Permissions Policy
      response_headers_to_add {
        header_name  = "Permissions-Policy"
        header_value = var.permissions_policy
      }
      
      # Expect-CT (Certificate Transparency)
      response_headers_to_add {
        header_name  = "Expect-CT"
        header_value = "max-age=86400, enforce, report-uri=\"https://isectech.report-uri.com/r/d/ct/enforce\""
      }
      
      # Public Key Pinning (HPKP) - Backup pins for certificate rotation
      response_headers_to_add {
        header_name  = "Public-Key-Pins"
        header_value = var.certificate_pins
      }
    }
  }
  
  labels = merge(local.common_labels, {
    security-type = "headers"
    purpose      = "domain-security"
  })
}

# DNS records for Certificate Authority Authorization (CAA) with pinning
resource "google_dns_record_set" "enhanced_caa_records" {
  count = var.enable_security_headers ? 1 : 0
  
  name         = google_dns_managed_zone.isectech_primary.dns_name
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "CAA"
  ttl          = 300
  project      = var.project_id

  # Enhanced CAA records with certificate pinning support
  rrdatas = [
    "0 issue \"letsencrypt.org\"",
    "0 issue \"google.com\"",
    "0 issuewild \"letsencrypt.org\"", 
    "0 issuewild \"google.com\"",
    "0 iodef \"mailto:security@isectech.org\"",
    # Certificate pinning via CAA (if supported by CA)
    "0 issue \"letsencrypt.org; validationmethods=dns-01; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/${var.acme_account_id}\"",
    "0 issue \"google.com; validationmethods=dns-01\""
  ]
  
  depends_on = [google_dns_record_set.caa_records]
}

# TXT records for HTTP Public Key Pinning (HPKP) backup information
resource "google_dns_record_set" "hpkp_backup_info" {
  count = var.enable_security_headers && var.enable_certificate_pinning ? 1 : 0
  
  name         = "_hpkp.${google_dns_managed_zone.isectech_primary.dns_name}"
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "\"v=hpkp1; backup-pins=${var.backup_certificate_pins}; contact=security@isectech.org\""
  ]
}

# DNS-based Authentication of Named Entities (DANE) TLSA records for certificate pinning
resource "google_dns_record_set" "dane_tlsa_records" {
  for_each = var.enable_security_headers && var.enable_certificate_pinning ? toset(var.certificate_domains) : toset([])
  
  name         = "_443._tcp.${each.value}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TLSA"
  ttl          = 300
  project      = var.project_id

  # TLSA record format: Usage Selector MatchingType Certificate
  # Usage: 3 (Domain-issued certificate)
  # Selector: 1 (Subject Public Key Info)  
  # MatchingType: 1 (SHA-256 hash)
  rrdatas = length(var.tlsa_records) > 0 && can(var.tlsa_records[each.value]) ? var.tlsa_records[each.value] : ["3 1 1 ${var.default_tlsa_hash}"]
}

# Security.txt file hosted via DNS TXT record for security contact information
resource "google_dns_record_set" "security_txt" {
  count = var.enable_security_headers ? 1 : 0
  
  name         = "_security.${google_dns_managed_zone.isectech_primary.dns_name}"
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "\"Contact: mailto:security@isectech.org\"",
    "\"Contact: https://security.isectech.org/.well-known/security.txt\"", 
    "\"Encryption: https://security.isectech.org/pgp-key.txt\"",
    "\"Preferred-Languages: en\"",
    "\"Canonical: https://security.isectech.org/.well-known/security.txt\"",
    "\"Policy: https://security.isectech.org/security-policy\""
  ]
}

# Certificate Transparency (CT) monitoring records
resource "google_dns_record_set" "ct_monitoring" {
  count = var.enable_certificate_transparency ? 1 : 0
  
  name         = "_ct.${google_dns_managed_zone.isectech_primary.dns_name}" 
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id

  rrdatas = [
    "\"ct-policy=expect-ct; max-age=86400; enforce; report-uri=https://isectech.report-uri.com/r/d/ct/enforce\"",
    "\"ct-logs=google-pilot,google-rocketeer,cloudflare-nimbus\"",
    "\"ct-submission=automatic\"",
    "\"ct-scts=require-sct-list\"",
    "\"ct-audit=enabled\""
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE TRANSPARENCY LOGGING AND ROTATION
# ═══════════════════════════════════════════════════════════════════════════════

# Certificate Transparency log monitoring via Cloud Logging
resource "google_logging_metric" "certificate_transparency_submissions" {
  count = var.enable_certificate_transparency ? 1 : 0
  
  name   = "isectech_certificate_transparency_submissions"
  project = var.project_id
  
  filter = <<-EOT
    resource.type="certificate_manager_certificate"
    protoPayload.methodName="google.cloud.certificatemanager.v1.CertificateManager.CreateCertificate"
    OR protoPayload.methodName="google.cloud.certificatemanager.v1.CertificateManager.UpdateCertificate"
    OR jsonPayload.certificate_transparency_log_submission="true"
  EOT
  
  label_extractors = {
    certificate_name = "EXTRACT(resource.labels.certificate_name)"
    ct_log_server    = "EXTRACT(jsonPayload.ct_log_server)"
    submission_status = "EXTRACT(jsonPayload.ct_submission_status)"
  }
  
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    display_name = "Certificate Transparency Submissions"
    description  = "Tracks certificate submissions to CT logs for transparency monitoring"
  }
}

# Alert policy for failed CT log submissions
resource "google_monitoring_alert_policy" "ct_submission_failures" {
  count = var.enable_certificate_transparency && var.enable_certificate_monitoring ? 1 : 0
  
  display_name          = "iSECTECH - Certificate Transparency Submission Failures"
  project              = var.project_id
  enabled              = true
  
  notification_channels = compact([
    var.enable_certificate_monitoring ? try(google_monitoring_notification_channel.ssl_certificate_email[0].id, "") : "",
    var.enable_certificate_monitoring && var.slack_webhook_url != "" ? try(google_monitoring_notification_channel.ssl_certificate_slack[0].id, "") : ""
  ])
  
  documentation {
    content = <<-EOT
      # Certificate Transparency Submission Failure Alert
      
      **WARNING**: Certificate Transparency log submission has failed.
      
      ## Impact:
      - Certificates may not be visible in CT logs
      - Compliance and audit requirements may not be met
      - Browser warnings possible for missing SCTs
      
      ## Immediate Actions:
      1. Check Certificate Manager console for CT submission status
      2. Verify CT log server availability and connectivity
      3. Review certificate provisioning logs for errors
      4. Check if certificate includes required SCTs (Signed Certificate Timestamps)
      
      ## Common Causes:
      - CT log server downtime or rate limiting
      - Network connectivity issues
      - Certificate format incompatibilities
      - CT log server policy changes
      
      ## Recovery Steps:
      1. Retry certificate provisioning if necessary
      2. Verify CT log submissions manually if needed
      3. Check browser compatibility for SCT requirements
      4. Contact CT log operators if persistent issues occur
      
      Console: https://console.cloud.google.com/security/ccm
    EOT
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "CT submission failure detected"
    
    condition_threshold {
      filter         = "resource.type=\"logging_metric\" AND metric.type=\"logging.googleapis.com/user/${google_logging_metric.certificate_transparency_submissions[0].name}\" AND metric.labels.submission_status=\"failed\""
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 0
      duration       = "300s"
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_COUNT_TRUE"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"  # 24 hours
    
    notification_rate_limit {
      period = "3600s"  # Once per hour
    }
  }
}

# Cloud Function for automated certificate rotation procedures
resource "google_cloudfunctions_function" "certificate_rotation_manager" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name        = "isectech-${var.environment}-cert-rotation-manager"
  description = "Automated certificate rotation management for iSECTECH domains"
  runtime     = "python39"
  project     = var.project_id
  region      = var.region

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.certificate_rotation_artifacts[0].name
  source_archive_object = google_storage_bucket_object.certificate_rotation_source[0].name
  timeout               = 300
  entry_point          = "handle_certificate_rotation"
  
  environment_variables = {
    PROJECT_ID = var.project_id
    ENVIRONMENT = var.environment
    NOTIFICATION_EMAIL = var.certificate_notification_email != "" ? var.certificate_notification_email : "security@isectech.org"
    SLACK_WEBHOOK_URL = var.slack_webhook_url
    CT_LOGS_ENABLED = var.enable_certificate_transparency
    BACKUP_PINS = var.backup_certificate_pins
  }

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.certificate_rotation_events[0].name
  }

  labels = merge(local.common_labels, {
    function-type = "certificate-rotation"
    automation   = "enabled"
  })
  
  depends_on = [
    google_storage_bucket_object.certificate_rotation_source,
    google_pubsub_topic.certificate_rotation_events
  ]
}

# Storage bucket for certificate rotation function source code
resource "google_storage_bucket" "certificate_rotation_artifacts" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name     = "isectech-${var.environment}-cert-rotation-artifacts-${random_string.bucket_suffix[0].result}"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
  
  labels = merge(local.common_labels, {
    purpose = "certificate-rotation"
    type    = "function-artifacts"
  })
}

resource "random_string" "bucket_suffix" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  length  = 8
  special = false
  upper   = false
}

# Upload certificate rotation function source code
resource "google_storage_bucket_object" "certificate_rotation_source" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name   = "certificate-rotation-${var.environment}-${formatdate("YYYYMMDD-hhmmss", timestamp())}.zip"
  bucket = google_storage_bucket.certificate_rotation_artifacts[0].name
  source = data.archive_file.certificate_rotation_source[0].output_path
}

# Archive certificate rotation function source
data "archive_file" "certificate_rotation_source" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  type        = "zip"
  output_path = "/tmp/certificate-rotation.zip"
  
  source {
    content = templatefile("${path.module}/scripts/certificate_rotation.py.tpl", {
      project_id    = var.project_id
      environment   = var.environment
      domains       = var.certificate_domains
      ct_logs       = var.certificate_transparency_logs
      backup_pins   = var.backup_certificate_pins
    })
    filename = "main.py"
  }
  
  source {
    content = file("${path.module}/scripts/requirements.txt")
    filename = "requirements.txt"
  }
}

# Pub/Sub topic for certificate rotation events
resource "google_pubsub_topic" "certificate_rotation_events" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name    = "isectech-${var.environment}-certificate-rotation-events"
  project = var.project_id
  
  labels = merge(local.common_labels, {
    purpose = "certificate-rotation"
    type    = "event-trigger"
  })
}

# Pub/Sub subscription for certificate rotation events
resource "google_pubsub_subscription" "certificate_rotation_subscription" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name  = "isectech-${var.environment}-cert-rotation-sub"
  topic = google_pubsub_topic.certificate_rotation_events[0].name
  project = var.project_id
  
  ack_deadline_seconds = 300
  
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
  
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.certificate_rotation_dead_letter[0].id
    max_delivery_attempts = 5
  }
  
  labels = merge(local.common_labels, {
    purpose = "certificate-rotation"
    type    = "event-subscription"
  })
}

# Dead letter topic for failed certificate rotation events
resource "google_pubsub_topic" "certificate_rotation_dead_letter" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name    = "isectech-${var.environment}-cert-rotation-dead-letter"
  project = var.project_id
  
  labels = merge(local.common_labels, {
    purpose = "certificate-rotation"
    type    = "dead-letter"
  })
}

# Cloud Scheduler job for periodic certificate rotation checks
resource "google_cloud_scheduler_job" "certificate_rotation_check" {
  count = var.enable_certificate_rotation_automation ? 1 : 0
  
  name     = "isectech-${var.environment}-cert-rotation-check"
  project  = var.project_id
  region   = var.region
  schedule = var.certificate_rotation_check_schedule
  
  description = "Periodic check for certificate rotation requirements"
  
  pubsub_target {
    topic_name = google_pubsub_topic.certificate_rotation_events[0].id
    data       = base64encode(jsonencode({
      action = "check_rotation_needed"
      environment = var.environment
      domains = var.certificate_domains
    }))
  }
  
  retry_config {
    retry_count = 3
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# IAM BINDINGS FOR DNS MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

# Service account for DNS management
resource "google_service_account" "dns_manager" {
  account_id   = "isectech-dns-manager-${var.environment}"
  display_name = "iSECTECH DNS Manager - ${title(var.environment)}"
  description  = "Service account for DNS zone management and certificate automation"
  project      = var.project_id
}

# DNS admin role for automated certificate management
resource "google_project_iam_member" "dns_admin" {
  project = var.project_id
  role    = "roles/dns.admin"
  member  = "serviceAccount:${google_service_account.dns_manager.email}"
}

# Certificate manager role for SSL automation
resource "google_project_iam_member" "certificate_manager" {
  project = var.project_id
  role    = "roles/certificatemanager.editor"
  member  = "serviceAccount:${google_service_account.dns_manager.email}"
}

# Cloud Run admin role for domain mapping
resource "google_project_iam_member" "cloud_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.dns_manager.email}"
}

# Service account user role for Cloud Run deployments
resource "google_project_iam_member" "service_account_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.dns_manager.email}"
}

# Monitoring writer for DNS metrics
resource "google_project_iam_member" "monitoring_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.dns_manager.email}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.8: CUSTOM DOMAIN MAPPING TO CLOUD RUN SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

# Data source to get Cloud Run service information
data "google_cloud_run_service" "isectech_services" {
  for_each = var.cloud_run_services
  
  name     = each.value.service_name
  location = each.value.region
  project  = var.project_id
}


# Create CNAME records for Cloud Run domain mapping
resource "google_dns_record_set" "cloud_run_domain_records" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "A"
  ttl          = var.dns_cache_ttl
  
  rrdatas = ["216.239.32.21", "216.239.34.21", "216.239.36.21", "216.239.38.21"]
  
  depends_on = [google_dns_managed_zone.isectech_primary]
}

# CNAME records for www subdomains
resource "google_dns_record_set" "www_domain_records" {
  for_each = var.enable_cloud_run_mapping ? {
    for domain, config in var.cloud_run_services : "www.${domain}" => config
    if !startswith(domain, "www.")
  } : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "CNAME"
  ttl          = var.dns_cache_ttl
  
  rrdatas = [replace(each.key, "www.", "")]
  
  depends_on = [google_dns_managed_zone.isectech_primary]
}

# Domain verification records for Google Cloud Console
resource "google_dns_record_set" "domain_verification_records" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "TXT"
  ttl          = 300
  
  rrdatas = [
    "v=spf1 include:_spf.google.com ~all",
    format("google-site-verification=%s", 
      var.google_site_verification_code != "" ? var.google_site_verification_code : "placeholder-verification"
    )
  ]
  
  depends_on = [google_dns_managed_zone.isectech_primary]
}

# Environment-specific domain mappings for staging and development
resource "google_cloud_run_domain_mapping" "environment_domain_mappings" {
  for_each = var.enable_cloud_run_mapping && var.create_environment_zones ? {
    for env in ["staging", "development"] : "${env}.${local.base_domain}" => {
      service_name = "isectech-${env}-frontend"
      region       = var.region
    }
  } : {}
  
  location = each.value.region
  name     = each.key
  project  = var.project_id
  
  metadata {
    namespace = var.project_id
    
    labels = merge(var.labels, {
      environment = split(".", each.key)[0]  # staging or development
      domain      = replace(each.key, ".", "-")
      service     = each.value.service_name
      managed-by  = "terraform"
    })
    
    annotations = {
      "run.googleapis.com/ingress"        = "all"
      "run.googleapis.com/ingress-status" = "all"
    }
  }
  
  spec {
    route_name = each.value.service_name
    
    # Force HTTPS redirect
    force_override = true
    
    # Certificate mode - automatic SSL provisioning
    certificate_mode = "AUTOMATIC"
  }
  
  depends_on = [
    google_dns_managed_zone.environment_zones
  ]
}

# DNS records for environment-specific domains
resource "google_dns_record_set" "environment_domain_records" {
  for_each = var.enable_cloud_run_mapping && var.create_environment_zones ? {
    for env in ["staging", "development"] : "${env}.${local.base_domain}" => {
      zone_name = "isectech-${env}-zone"
    }
  } : {}
  
  name         = "${each.key}."
  managed_zone = each.value.zone_name
  type         = "A"
  ttl          = var.dns_cache_ttl
  
  rrdatas = ["216.239.32.21", "216.239.34.21", "216.239.36.21", "216.239.38.21"]
  
  depends_on = [google_dns_managed_zone.environment_zones]
}

# Health checks for mapped domains
resource "google_monitoring_uptime_check_config" "domain_mapping_health_checks" {
  for_each = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? var.cloud_run_services : {}
  
  display_name = "iSECTECH Domain Health - ${each.key}"
  timeout      = "10s"
  period       = "60s"
  
  http_check {
    path           = "/health"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
    
    headers = {
      "User-Agent" = "GoogleHC/1.0"
      "Host"       = each.key
    }
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = each.key
    }
  }
  
  selected_regions = ["USA", "EUROPE", "ASIA_PACIFIC"]
  
  depends_on = [google_cloud_run_domain_mapping.domain_mappings]
}

# Alert policy for domain mapping failures
resource "google_monitoring_alert_policy" "domain_mapping_failures" {
  count = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? 1 : 0
  
  display_name = "iSECTECH Domain Mapping Failures - ${title(var.environment)}"
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Domain Mapping Health Check Failure"
    
    condition_threshold {
      filter          = "metric.type=\"monitoring.googleapis.com/uptime_check/check_passed\" resource.type=\"uptime_url\""
      duration        = "300s"
      comparison      = "COMPARISON_EQUAL"
      threshold_value = 0
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = var.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
  
  depends_on = [google_monitoring_uptime_check_config.domain_mapping_health_checks]
}

# Traffic allocation configuration for gradual rollouts
resource "google_cloud_run_service" "traffic_allocation" {
  for_each = var.enable_cloud_run_mapping ? {
    for domain, config in var.cloud_run_services : domain => config
    if config.traffic_allocation != null && config.traffic_allocation < 100
  } : {}
  
  name     = data.google_cloud_run_service.isectech_services[each.key].name
  location = each.value.region
  project  = var.project_id
  
  traffic {
    percent         = each.value.traffic_allocation
    latest_revision = true
  }
  
  traffic {
    percent = 100 - each.value.traffic_allocation
    tag     = "stable"
  }
  
  depends_on = [google_cloud_run_domain_mapping.domain_mappings]
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.9: DOMAIN ROUTING RULES AND LOAD BALANCING
# ═══════════════════════════════════════════════════════════════════════════════

# Global Load Balancer for advanced routing
resource "google_compute_global_address" "isectech_load_balancer_ip" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name         = "isectech-${var.environment}-lb-ip"
  project      = var.project_id
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
}

# SSL Certificate for Load Balancer
resource "google_compute_managed_ssl_certificate" "load_balancer_cert" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name    = "isectech-${var.environment}-lb-cert"
  project = var.project_id
  
  managed {
    domains = concat(
      keys(var.cloud_run_services),
      [for domain in keys(var.cloud_run_services) : "www.${domain}"]
    )
  }
  
  depends_on = [google_dns_record_set.cloud_run_domain_records]
}

# Backend Services for each Cloud Run service
resource "google_compute_backend_service" "cloud_run_backends" {
  for_each = var.enable_cloud_run_mapping && var.enable_geo_routing ? var.cloud_run_services : {}
  
  name        = "isectech-${var.environment}-${replace(each.key, ".", "-")}-backend"
  project     = var.project_id
  protocol    = "HTTPS"
  timeout_sec = 30
  
  backend {
    group = google_compute_region_network_endpoint_group.cloud_run_neg[each.key].id
  }
  
  load_balancing_scheme = "EXTERNAL_MANAGED"
  
  # Health check configuration
  health_checks = [google_compute_health_check.cloud_run_health_check[each.key].id]
  
  # Security policy
  security_policy = var.enable_security_headers ? google_compute_security_policy.isectech_security_headers_policy[0].id : null
  
  # CDN configuration for static assets
  enable_cdn = true
  cdn_policy {
    cache_mode        = "CACHE_ALL_STATIC"
    default_ttl       = 3600
    max_ttl           = 86400
    client_ttl        = 3600
    negative_caching  = true
    serve_while_stale = 86400
    
    cache_key_policy {
      include_host         = true
      include_protocol     = true
      include_query_string = false
    }
  }
  
  # Connection draining timeout
  connection_draining_timeout_sec = 300
  
  depends_on = [
    google_compute_region_network_endpoint_group.cloud_run_neg,
    google_compute_health_check.cloud_run_health_check
  ]
}

# Network Endpoint Groups for Cloud Run services
resource "google_compute_region_network_endpoint_group" "cloud_run_neg" {
  for_each = var.enable_cloud_run_mapping && var.enable_geo_routing ? var.cloud_run_services : {}
  
  name                  = "isectech-${var.environment}-${replace(each.key, ".", "-")}-neg"
  project               = var.project_id
  network_endpoint_type = "SERVERLESS"
  region                = each.value.region
  
  cloud_run {
    service = each.value.service_name
  }
  
  depends_on = [data.google_cloud_run_service.isectech_services]
}

# Health checks for backend services
resource "google_compute_health_check" "cloud_run_health_check" {
  for_each = var.enable_cloud_run_mapping && var.enable_geo_routing ? var.cloud_run_services : {}
  
  name    = "isectech-${var.environment}-${replace(each.key, ".", "-")}-hc"
  project = var.project_id
  
  timeout_sec         = 5
  check_interval_sec  = 30
  healthy_threshold   = 2
  unhealthy_threshold = 2
  
  https_health_check {
    port               = 443
    host               = each.key
    request_path       = "/health"
    proxy_header       = "PROXY_V1"
    port_specification = "USE_FIXED_PORT"
  }
}

# URL Map for routing rules
resource "google_compute_url_map" "isectech_url_map" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name            = "isectech-${var.environment}-url-map"
  project         = var.project_id
  default_service = google_compute_backend_service.cloud_run_backends[keys(var.cloud_run_services)[0]].id
  
  # Host rules for different domains
  dynamic "host_rule" {
    for_each = var.cloud_run_services
    content {
      hosts        = [host_rule.key, "www.${host_rule.key}"]
      path_matcher = "path-matcher-${replace(host_rule.key, ".", "-")}"
    }
  }
  
  # Path matchers for routing rules
  dynamic "path_matcher" {
    for_each = var.cloud_run_services
    content {
      name            = "path-matcher-${replace(path_matcher.key, ".", "-")}"
      default_service = google_compute_backend_service.cloud_run_backends[path_matcher.key].id
      
      # API routing rules
      path_rule {
        paths   = ["/api/*", "/v1/*", "/v2/*"]
        service = google_compute_backend_service.cloud_run_backends[path_matcher.key].id
        
        route_action {
          timeout {
            seconds = 60
          }
        }
      }
      
      # Static assets routing
      path_rule {
        paths   = ["/assets/*", "/static/*", "/images/*", "/css/*", "/js/*"]
        service = google_compute_backend_service.cloud_run_backends[path_matcher.key].id
        
        route_action {
          timeout {
            seconds = 30
          }
        }
      }
      
      # Health check routing
      path_rule {
        paths   = ["/health", "/ready", "/live"]
        service = google_compute_backend_service.cloud_run_backends[path_matcher.key].id
        
        route_action {
          timeout {
            seconds = 10
          }
        }
      }
    }
  }
  
  depends_on = [google_compute_backend_service.cloud_run_backends]
}

# HTTPS Proxy
resource "google_compute_target_https_proxy" "isectech_https_proxy" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name    = "isectech-${var.environment}-https-proxy"
  project = var.project_id
  url_map = google_compute_url_map.isectech_url_map[0].id
  
  ssl_certificates = [google_compute_managed_ssl_certificate.load_balancer_cert[0].id]
  
  depends_on = [
    google_compute_url_map.isectech_url_map,
    google_compute_managed_ssl_certificate.load_balancer_cert
  ]
}

# HTTP to HTTPS Redirect
resource "google_compute_url_map" "isectech_http_redirect" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name    = "isectech-${var.environment}-http-redirect"
  project = var.project_id
  
  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

# HTTP Proxy for redirect
resource "google_compute_target_http_proxy" "isectech_http_proxy" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name    = "isectech-${var.environment}-http-proxy"
  project = var.project_id
  url_map = google_compute_url_map.isectech_http_redirect[0].id
}

# Global Forwarding Rules
resource "google_compute_global_forwarding_rule" "isectech_https_forwarding_rule" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name       = "isectech-${var.environment}-https-forwarding-rule"
  project    = var.project_id
  target     = google_compute_target_https_proxy.isectech_https_proxy[0].id
  port_range = "443"
  ip_address = google_compute_global_address.isectech_load_balancer_ip[0].address
  
  depends_on = [google_compute_target_https_proxy.isectech_https_proxy]
}

resource "google_compute_global_forwarding_rule" "isectech_http_forwarding_rule" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing ? 1 : 0
  
  name       = "isectech-${var.environment}-http-forwarding-rule"
  project    = var.project_id
  target     = google_compute_target_http_proxy.isectech_http_proxy[0].id
  port_range = "80"
  ip_address = google_compute_global_address.isectech_load_balancer_ip[0].address
  
  depends_on = [google_compute_target_http_proxy.isectech_http_proxy]
}

# Geographic routing policies for DNS
resource "google_dns_record_set" "geo_routing_records" {
  for_each = var.enable_geo_routing && length(var.geo_routing_policies) > 0 ? var.geo_routing_policies : {}
  
  name         = "${each.key}."
  managed_zone = google_dns_managed_zone.isectech_primary.name
  type         = "A"
  ttl          = var.dns_cache_ttl
  
  rrdatas = each.value.rrdatas
  
  routing_policy {
    geo {
      location = each.value.location
      rrdatas  = each.value.rrdatas
    }
  }
  
  depends_on = [google_dns_managed_zone.isectech_primary]
}

# Load balancer monitoring
resource "google_monitoring_uptime_check_config" "load_balancer_health_check" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing && var.enable_dns_monitoring ? 1 : 0
  
  display_name = "iSECTECH Load Balancer Health - ${title(var.environment)}"
  timeout      = "10s"
  period       = "60s"
  
  http_check {
    path           = "/health"
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
    
    headers = {
      "User-Agent" = "GoogleHC/1.0"
      "Host"       = keys(var.cloud_run_services)[0]
    }
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = google_compute_global_address.isectech_load_balancer_ip[0].address
    }
  }
  
  selected_regions = ["USA", "EUROPE", "ASIA_PACIFIC"]
  
  depends_on = [
    google_compute_global_forwarding_rule.isectech_https_forwarding_rule,
    google_compute_global_address.isectech_load_balancer_ip
  ]
}

# Alert policy for load balancer failures
resource "google_monitoring_alert_policy" "load_balancer_failures" {
  count = var.enable_cloud_run_mapping && var.enable_geo_routing && var.enable_dns_monitoring ? 1 : 0
  
  display_name = "iSECTECH Load Balancer Failures - ${title(var.environment)}"
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "Load Balancer Health Check Failure"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 10
      
      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["resource.label.backend_service_name"]
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  conditions {
    display_name = "Load Balancer 5xx Errors"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" metric.label.response_code_class=\"500\""
      duration        = "180s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 5
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = var.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
  
  depends_on = [google_monitoring_uptime_check_config.load_balancer_health_check]
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.10: DOMAIN-SPECIFIC SECURITY, LOGGING, AND MONITORING
# ═══════════════════════════════════════════════════════════════════════════════

# Enhanced Security Policy for domain-specific rules
resource "google_compute_security_policy" "domain_specific_security_policy" {
  for_each = var.enable_cloud_run_mapping ? var.cloud_run_services : {}
  
  name        = "isectech-${var.environment}-${replace(each.key, ".", "-")}-security"
  description = "Domain-specific security policy for ${each.key}"
  project     = var.project_id
  type        = "CLOUD_ARMOR"
  
  # Default rule - allow all
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }
  
  # Rate limiting rule per domain
  rule {
    action   = "rate_based_ban"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Rate limiting for ${each.key}"
    
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      
      ban_duration_sec = 300
    }
  }
  
  # Block suspicious countries for production domains
  dynamic "rule" {
    for_each = var.environment == "production" ? [1] : []
    content {
      action   = "deny(403)"
      priority = "900"
      match {
        expr {
          expression = "origin.region_code == 'CN' || origin.region_code == 'RU' || origin.region_code == 'KP'"
        }
      }
      description = "Block suspicious regions for production"
    }
  }
  
  # SQL injection protection
  rule {
    action   = "deny(403)"
    priority = "800"
    match {
      expr {
        expression = "has(request.headers['user-agent']) && request.headers['user-agent'].contains('sqlmap')"
      }
    }
    description = "Block SQL injection attempts"
  }
  
  # XSS protection
  rule {
    action   = "deny(403)"
    priority = "700"
    match {
      expr {
        expression = "request.url_query.contains('<script>') || request.url_query.contains('javascript:')"
      }
    }
    description = "Block XSS attempts"
  }
  
  # Protocol attack protection
  rule {
    action   = "deny(403)"
    priority = "600"
    match {
      expr {
        expression = "request.method == 'TRACE' || request.method == 'TRACK'"
      }
    }
    description = "Block HTTP TRACE/TRACK methods"
  }
  
  # Advanced bot protection
  rule {
    action   = "deny(403)"
    priority = "500"
    match {
      expr {
        expression = "!has(request.headers['user-agent']) || request.headers['user-agent'] == '' || request.headers['user-agent'].size() > 512"
      }
    }
    description = "Block requests with suspicious user agents"
  }
  
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
    auto_deploy_config {
      load_threshold               = 0.1
      confidence_threshold         = 0.5
      impacted_baseline_threshold  = 0.01
      expiration_sec              = 7200
    }
  }
}

# Domain-specific logging sink
resource "google_logging_project_sink" "domain_security_logs" {
  for_each = var.enable_cloud_run_mapping && var.enable_audit_logging ? var.cloud_run_services : {}
  
  name        = "isectech-${var.environment}-${replace(each.key, ".", "-")}-security-sink"
  description = "Security logs for domain ${each.key}"
  
  destination = "storage.googleapis.com/${google_storage_bucket.domain_security_logs[each.key].name}"
  
  filter = <<-EOT
    resource.type = "http_load_balancer"
    httpRequest.requestUrl =~ "${each.key}"
    (
      httpRequest.status >= 400 OR
      jsonPayload.enforcedSecurityPolicy.name != "" OR
      jsonPayload.statusDetails = "denied_by_security_policy" OR
      protoPayload.methodName = "compute.securityPolicies.patch"
    )
  EOT
  
  unique_writer_identity = true
  
  depends_on = [google_storage_bucket.domain_security_logs]
}

# Storage buckets for domain-specific logs
resource "google_storage_bucket" "domain_security_logs" {
  for_each = var.enable_cloud_run_mapping && var.enable_audit_logging ? var.cloud_run_services : {}
  
  name          = "isectech-${var.environment}-${replace(each.key, ".", "-")}-security-logs"
  location      = var.region
  project       = var.project_id
  force_destroy = false
  
  uniform_bucket_level_access = true
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
  
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
  
  labels = merge(var.labels, {
    environment = var.environment
    domain      = replace(each.key, ".", "-")
    purpose     = "security-logs"
  })
}

# Domain-specific monitoring dashboard
resource "google_monitoring_dashboard" "domain_security_dashboard" {
  for_each = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? var.cloud_run_services : {}
  
  dashboard_json = jsonencode({
    displayName = "iSECTECH ${title(each.key)} Security Dashboard"
    mosaicLayout = {
      tiles = [
        {
          width  = 6
          height = 4
          widget = {
            title = "Request Rate for ${each.key}"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" resource.label.url_map_name=\"isectech-${var.environment}-url-map\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
                plotType = "LINE"
              }]
              yAxis = {
                label = "Requests/sec"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width  = 6
          height = 4
          xPos   = 6
          widget = {
            title = "Security Policy Violations for ${each.key}"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" metric.label.response_code_class=\"400\""
                    aggregation = {
                      alignmentPeriod  = "60s"
                      perSeriesAligner = "ALIGN_RATE"
                    }
                  }
                }
                plotType = "LINE"
              }]
              yAxis = {
                label = "Blocked Requests/sec"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width  = 6
          height = 4
          yPos   = 4
          widget = {
            title = "Response Latency for ${each.key}"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"loadbalancing.googleapis.com/https/total_latencies\" resource.type=\"https_lb_rule\""
                    aggregation = {
                      alignmentPeriod    = "60s"
                      perSeriesAligner   = "ALIGN_DELTA"
                      crossSeriesReducer = "REDUCE_PERCENTILE_95"
                    }
                  }
                }
                plotType = "LINE"
              }]
              yAxis = {
                label = "Latency (ms)"
                scale = "LINEAR"
              }
            }
          }
        },
        {
          width  = 6
          height = 4
          xPos   = 6
          yPos   = 4
          widget = {
            title = "SSL Certificate Status for ${each.key}"
            xyChart = {
              dataSets = [{
                timeSeriesQuery = {
                  timeSeriesFilter = {
                    filter = "metric.type=\"certificatemanager.googleapis.com/certificate/expiration_time\" resource.label.certificate_name=~\".*${replace(each.key, ".", "-")}.*\""
                    aggregation = {
                      alignmentPeriod  = "300s"
                      perSeriesAligner = "ALIGN_NEXT_OLDER"
                    }
                  }
                }
                plotType = "LINE"
              }]
              yAxis = {
                label = "Days to Expiration"
                scale = "LINEAR"
              }
            }
          }
        }
      ]
    }
  })
  
  depends_on = [google_compute_security_policy.domain_specific_security_policy]
}

# Domain-specific alert policies
resource "google_monitoring_alert_policy" "domain_security_violations" {
  for_each = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? var.cloud_run_services : {}
  
  display_name = "iSECTECH ${title(each.key)} Security Violations"
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "High Rate of Security Policy Violations"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" metric.label.response_code_class=\"400\""
      duration        = "180s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 50
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  conditions {
    display_name = "Suspicious Geographic Traffic"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" metric.label.response_code=\"403\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 10
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = var.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
  
  depends_on = [google_compute_security_policy.domain_specific_security_policy]
}

# Domain performance monitoring
resource "google_monitoring_alert_policy" "domain_performance_degradation" {
  for_each = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? var.cloud_run_services : {}
  
  display_name = "iSECTECH ${title(each.key)} Performance Degradation"
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "High Response Latency"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/total_latencies\" resource.type=\"https_lb_rule\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 2000
      
      aggregations {
        alignment_period    = "60s"
        per_series_aligner  = "ALIGN_DELTA"
        cross_series_reducer = "REDUCE_PERCENTILE_95"
      }
      
      trigger {
        count = 2
      }
    }
  }
  
  conditions {
    display_name = "High Error Rate"
    
    condition_threshold {
      filter          = "metric.type=\"loadbalancing.googleapis.com/https/request_count\" resource.type=\"https_lb_rule\" metric.label.response_code_class=\"500\""
      duration        = "180s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 5
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = var.notification_channels
  
  alert_strategy {
    auto_close = "1800s"
  }
}

# Domain-specific access control
resource "google_compute_security_policy" "domain_access_control" {
  for_each = var.environment == "production" ? {} : var.cloud_run_services
  
  name        = "isectech-${var.environment}-${replace(each.key, ".", "-")}-access"
  description = "Access control policy for ${each.key} in ${var.environment}"
  project     = var.project_id
  type        = "CLOUD_ARMOR"
  
  # Allow internal iSECTECH office IPs for non-production
  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = [
          "10.0.0.0/8",      # Internal networks
          "172.16.0.0/12",   # Private networks
          "192.168.0.0/16"   # Local networks
        ]
      }
    }
    description = "Allow internal networks for ${var.environment}"
  }
  
  # Default deny for non-production
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny for ${var.environment} environment"
  }
}

# Cloud Logging metrics for custom security events
resource "google_logging_metric" "domain_security_events" {
  for_each = var.enable_cloud_run_mapping && var.enable_audit_logging ? var.cloud_run_services : {}
  
  name   = "isectech_${var.environment}_${replace(each.key, ".", "_")}_security_events"
  filter = <<-EOT
    resource.type = "http_load_balancer"
    httpRequest.requestUrl =~ "${each.key}"
    httpRequest.status >= 400
    jsonPayload.enforcedSecurityPolicy.name != ""
  EOT
  
  metric_descriptor {
    metric_kind = "COUNTER"
    value_type  = "INT64"
    display_name = "Security Events for ${each.key}"
    description  = "Count of security policy violations for domain ${each.key}"
    
    labels {
      key         = "response_code"
      value_type  = "STRING"
      description = "HTTP response code"
    }
    
    labels {
      key         = "country"
      value_type  = "STRING"
      description = "Source country"
    }
    
    labels {
      key         = "policy_name"
      value_type  = "STRING"
      description = "Security policy name"
    }
  }
  
  label_extractors = {
    response_code = "EXTRACT(httpRequest.status)"
    country       = "EXTRACT(httpRequest.remoteIp)"
    policy_name   = "EXTRACT(jsonPayload.enforcedSecurityPolicy.name)"
  }
}

# Domain SSL certificate monitoring
resource "google_monitoring_alert_policy" "domain_ssl_certificate_expiration" {
  for_each = var.enable_certificate_monitoring ? var.cloud_run_services : {}
  
  display_name = "iSECTECH ${title(each.key)} SSL Certificate Expiration"
  combiner     = "OR"
  enabled      = true
  
  conditions {
    display_name = "SSL Certificate Expiring Soon"
    
    condition_threshold {
      filter          = "metric.type=\"certificatemanager.googleapis.com/certificate/expiration_time\" resource.label.certificate_name=~\".*${replace(each.key, ".", "-")}.*\""
      duration        = "0s"
      comparison      = "COMPARISON_LESS_THAN"
      threshold_value = 2592000  # 30 days in seconds
      
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_NEXT_OLDER"
      }
      
      trigger {
        count = 1
      }
    }
  }
  
  notification_channels = var.notification_channels
  
  alert_strategy {
    auto_close = "86400s"  # 24 hours
  }
  
  depends_on = [google_certificate_manager_certificate.managed_certificates]
}

# =============================================================================
# Task 61.11: Multi-Environment Domain Management and Testing
# =============================================================================


# Environment-specific A records
resource "google_dns_record_set" "environment_a_records" {
  for_each = var.enable_multi_environment ? {
    for combo in flatten([
      for env_key, env_config in var.environment_configs : [
        for record in env_config.a_records : {
          env_key = env_key
          name    = record.name
          config  = record
        }
      ]
    ]) : "${combo.env_key}-${combo.name}" => combo
  } : {}

  name         = "${each.value.name}.${each.value.env_key}.${var.domain_name}."
  type         = "A"
  ttl          = each.value.config.ttl
  managed_zone = google_dns_managed_zone.environment_zones[each.value.env_key].name
  rrdatas      = each.value.config.rrdatas

  project = var.project_id
}

# Environment-specific CNAME records
resource "google_dns_record_set" "environment_cname_records" {
  for_each = var.enable_multi_environment ? {
    for combo in flatten([
      for env_key, env_config in var.environment_configs : [
        for record in env_config.cname_records : {
          env_key = env_key
          name    = record.name
          config  = record
        }
      ]
    ]) : "${combo.env_key}-${combo.name}" => combo
  } : {}

  name         = "${each.value.name}.${each.value.env_key}.${var.domain_name}."
  type         = "CNAME"
  ttl          = each.value.config.ttl
  managed_zone = google_dns_managed_zone.environment_zones[each.value.env_key].name
  rrdatas      = each.value.config.rrdatas

  project = var.project_id
}

# Environment-specific SSL certificates
resource "google_certificate_manager_certificate" "environment_certificates" {
  for_each = var.enable_multi_environment ? var.environment_configs : {}

  name        = "${each.key}-${var.certificate_name}"
  description = "SSL Certificate for ${title(each.key)} environment - iSECTECH Multi-Environment Certificate"
  project     = var.project_id
  location    = "global"

  managed {
    domains = [
      for domain in each.value.certificate_domains : 
      "${domain}.${each.key}.${var.domain_name}"
    ]
    
    dns_authorizations = [
      for domain in each.value.certificate_domains :
      google_certificate_manager_dns_authorization.environment_dns_auth["${each.key}-${domain}"].id
    ]
    
    issuance_config = var.enable_ca_service ? google_certificate_manager_certificate_issuance_config.ca_config[0].id : null
  }

  labels = merge(var.labels, {
    environment = each.key
    purpose     = "multi-environment-ssl"
    component   = "certificate"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Environment-specific DNS authorizations
resource "google_certificate_manager_dns_authorization" "environment_dns_auth" {
  for_each = var.enable_multi_environment ? {
    for combo in flatten([
      for env_key, env_config in var.environment_configs : [
        for domain in env_config.certificate_domains : {
          env_key = env_key
          domain  = domain
        }
      ]
    ]) : "${combo.env_key}-${combo.domain}" => combo
  } : {}

  name        = "${each.value.env_key}-${each.value.domain}-auth"
  description = "DNS Authorization for ${each.value.domain}.${each.value.env_key}.${var.domain_name}"
  project     = var.project_id
  location    = "global"
  domain      = "${each.value.domain}.${each.value.env_key}.${var.domain_name}"

  labels = merge(var.labels, {
    environment = each.value.env_key
    domain      = each.value.domain
    purpose     = "dns-authorization"
  })
}

# Environment-specific DNS challenge records
resource "google_dns_record_set" "environment_dns_challenge" {
  for_each = var.enable_multi_environment ? {
    for combo in flatten([
      for env_key, env_config in var.environment_configs : [
        for domain in env_config.certificate_domains : {
          env_key = env_key
          domain  = domain
        }
      ]
    ]) : "${combo.env_key}-${combo.domain}" => combo
  } : {}

  name         = google_certificate_manager_dns_authorization.environment_dns_auth[each.key].dns_resource_record[0].name
  type         = google_certificate_manager_dns_authorization.environment_dns_auth[each.key].dns_resource_record[0].type
  ttl          = 300
  managed_zone = google_dns_managed_zone.environment_zones[each.value.env_key].name
  rrdatas      = [google_certificate_manager_dns_authorization.environment_dns_auth[each.key].dns_resource_record[0].data]

  project = var.project_id
}


# Environment isolation via Cloud Armor security policies
resource "google_compute_security_policy" "environment_security_policies" {
  for_each = var.enable_multi_environment ? var.environment_configs : {}

  name    = "${each.key}-environment-security-policy"
  project = var.project_id

  description = "Security policy for ${title(each.key)} environment - Environment Isolation and Access Control"

  # Allow internal traffic for staging/dev environments
  dynamic "rule" {
    for_each = each.key != "production" ? [1] : []
    content {
      action   = "allow"
      priority = "100"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = each.value.allowed_ip_ranges
        }
      }
      description = "Allow ${each.key} environment access from specified IP ranges"
    }
  }

  # Production environment gets stricter controls
  dynamic "rule" {
    for_each = each.key == "production" ? [1] : []
    content {
      action   = "allow"
      priority = "200"
      match {
        versioned_expr = "SRC_IPS_V1"
        config {
          src_ip_ranges = ["0.0.0.0/0"]  # Public access for production
        }
      }
      description = "Allow production environment public access with rate limiting"
    }
  }

  # Rate limiting specific to environment
  rule {
    action   = "rate_based_ban"
    priority = "300"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = each.value.rate_limit_requests_per_minute
        interval_sec = 60
      }
      ban_duration_sec = each.value.rate_limit_ban_duration_sec
    }
    description = "Rate limiting for ${each.key} environment"
  }

  # Block malicious patterns
  rule {
    action   = "deny(403)"
    priority = "400"
    match {
      expr {
        expression = <<-EOT
          request.headers['user-agent'].contains('bot') ||
          request.headers['user-agent'].contains('crawler') ||
          request.uri.contains('../') ||
          request.uri.contains('..\\')
        EOT
      }
    }
    description = "Block common attack patterns for ${each.key} environment"
  }

  # Default allow rule
  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule for ${each.key} environment"
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = each.value.enable_adaptive_protection
    }
  }
}

# Environment-specific health check endpoints
resource "google_compute_health_check" "environment_health_checks" {
  for_each = var.enable_multi_environment ? var.environment_configs : {}

  name    = "${each.key}-environment-health-check"
  project = var.project_id

  description      = "Health check for ${title(each.key)} environment services"
  timeout_sec      = each.value.health_check_timeout_sec
  check_interval_sec = each.value.health_check_interval_sec
  healthy_threshold   = each.value.health_check_healthy_threshold
  unhealthy_threshold = each.value.health_check_unhealthy_threshold

  http_health_check {
    port               = each.value.health_check_port
    request_path       = each.value.health_check_path
    host               = "${each.value.health_check_host}.${each.key}.${var.domain_name}"
    response           = each.value.health_check_response
    port_specification = "USE_FIXED_PORT"
  }

  log_config {
    enable = true
  }
}

# Environment testing Cloud Function
resource "google_cloudfunctions2_function" "environment_testing" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  name     = "environment-domain-testing"
  location = var.region
  project  = var.project_id

  description = "Automated testing for multi-environment domain configurations"

  build_config {
    runtime     = "python311"
    entry_point = "test_environment_domains"
    
    source {
      storage_source {
        bucket = google_storage_bucket.environment_testing_bucket[0].name
        object = google_storage_bucket_object.environment_testing_source[0].name
      }
    }
  }

  service_config {
    max_instance_count    = 10
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 540
    max_instance_request_concurrency = 1
    available_cpu         = "1"
    ingress_settings      = "ALLOW_INTERNAL_ONLY"
    all_traffic_on_latest_revision = true

    environment_variables = {
      PROJECT_ID           = var.project_id
      ENVIRONMENT_CONFIGS  = jsonencode(var.environment_configs)
      DOMAIN_NAME         = var.domain_name
      NOTIFICATION_EMAIL  = var.environment_testing_notification_email
    }

    secret_environment_variables {
      key        = "SENDGRID_API_KEY"
      project_id = var.project_id
      secret     = google_secret_manager_secret.environment_testing_secrets[0].secret_id
      version    = "latest"
    }

    service_account_email = google_service_account.environment_testing_sa[0].email
  }

  event_trigger {
    trigger_region        = var.region
    event_type           = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic         = google_pubsub_topic.environment_testing_trigger[0].id
    retry_policy         = "RETRY_POLICY_RETRY"
    service_account_email = google_service_account.environment_testing_sa[0].email
  }

  depends_on = [
    google_storage_bucket_object.environment_testing_source,
    google_secret_manager_secret_version.environment_testing_secrets
  ]
}

# Storage bucket for testing source code
resource "google_storage_bucket" "environment_testing_bucket" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  name     = "${var.project_id}-environment-testing-source"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  labels = merge(var.labels, {
    purpose   = "environment-testing"
    component = "source-bucket"
  })
}

# Upload testing source code
resource "google_storage_bucket_object" "environment_testing_source" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  name   = "environment_testing_source.zip"
  bucket = google_storage_bucket.environment_testing_bucket[0].name
  source = data.archive_file.environment_testing_source[0].output_path

  depends_on = [data.archive_file.environment_testing_source]
}

# Archive testing source code
data "archive_file" "environment_testing_source" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  type        = "zip"
  output_path = "${path.module}/environment_testing_source.zip"
  
  source {
    content = templatefile("${path.module}/environment_testing_main.py", {
      project_id = var.project_id
    })
    filename = "main.py"
  }
  
  source {
    content  = file("${path.module}/requirements.txt")
    filename = "requirements.txt"
  }
}

# Service account for environment testing
resource "google_service_account" "environment_testing_sa" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  account_id   = "environment-testing-sa"
  display_name = "Environment Testing Service Account"
  description  = "Service account for automated environment domain testing"
  project      = var.project_id
}

# IAM bindings for environment testing service account
resource "google_project_iam_member" "environment_testing_permissions" {
  for_each = var.enable_multi_environment && var.enable_environment_testing ? toset([
    "roles/dns.reader",
    "roles/certificatemanager.viewer",
    "roles/compute.viewer",
    "roles/run.viewer",
    "roles/monitoring.metricWriter",
    "roles/logging.logWriter",
    "roles/secretmanager.secretAccessor"
  ]) : toset([])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.environment_testing_sa[0].email}"
}

# Pub/Sub topic for triggering environment tests
resource "google_pubsub_topic" "environment_testing_trigger" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  name    = "environment-testing-trigger"
  project = var.project_id

  labels = merge(var.labels, {
    purpose   = "environment-testing"
    component = "pubsub-trigger"
  })

  message_retention_duration = "86400s"
}

# Cloud Scheduler job for regular environment testing
resource "google_cloud_scheduler_job" "environment_testing_schedule" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  name      = "environment-testing-schedule"
  project   = var.project_id
  region    = var.region
  schedule  = var.environment_testing_schedule
  time_zone = var.environment_testing_timezone

  description = "Scheduled environment domain testing for all environments"

  pubsub_target {
    topic_name = google_pubsub_topic.environment_testing_trigger[0].id
    data = base64encode(jsonencode({
      trigger_type = "scheduled"
      environments = keys(var.environment_configs)
      timestamp    = "{{.google.internal.timestamp}}"
    }))
  }

  retry_config {
    retry_count          = 3
    max_retry_duration   = "300s"
    min_backoff_duration = "5s"
    max_backoff_duration = "60s"
    max_doublings        = 3
  }
}

# Secret Manager secret for testing notifications
resource "google_secret_manager_secret" "environment_testing_secrets" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  secret_id = "environment-testing-secrets"
  project   = var.project_id

  labels = merge(var.labels, {
    purpose   = "environment-testing"
    component = "secrets"
  })

  replication {
    auto {}
  }
}

# Secret version for testing API keys
resource "google_secret_manager_secret_version" "environment_testing_secrets" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  secret = google_secret_manager_secret.environment_testing_secrets[0].id
  secret_data = jsonencode({
    sendgrid_api_key = var.environment_testing_sendgrid_api_key
  })
}

# Environment testing monitoring dashboard
resource "google_monitoring_dashboard" "environment_testing_dashboard" {
  count = var.enable_multi_environment && var.enable_environment_testing ? 1 : 0

  project        = var.project_id
  dashboard_json = templatefile("${path.module}/environment_testing_dashboard.json", {
    project_id = var.project_id
  })

  depends_on = [google_cloudfunctions2_function.environment_testing]
}