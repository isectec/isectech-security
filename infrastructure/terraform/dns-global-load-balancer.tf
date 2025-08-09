# iSECTECH DNS-Based Global Load Balancing Configuration
# DNS-based global load balancing with regional health checks and failover
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - DNS Global Load Balancing Implementation

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL DNS MANAGED ZONE
# ═══════════════════════════════════════════════════════════════════════════════

# Primary managed DNS zone for isectech.org
resource "google_dns_managed_zone" "primary_zone" {
  name        = "isectech-primary-zone-${var.environment}"
  dns_name    = var.domain_name
  description = "Primary DNS zone for iSECTECH multi-region deployment"
  project     = var.project_id
  
  # Enable DNSSEC for security
  dynamic "dnssec_config" {
    for_each = var.enable_dnssec ? [1] : []
    content {
      state         = "on"
      non_existence = "nsec3"
    }
  }
  
  labels = merge(local.common_labels, {
    zone-type    = "primary"
    purpose      = "global-lb"
    dnssec       = var.enable_dnssec ? "enabled" : "disabled"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL STATIC IP ADDRESSES
# ═══════════════════════════════════════════════════════════════════════════════

# Static IP addresses for each regional load balancer
resource "google_compute_address" "regional_ip" {
  for_each = local.regions
  
  name         = "isectech-${each.key}-ip-${var.environment}"
  address_type = "EXTERNAL"
  region       = each.key
  project      = var.project_id
  
  labels = merge(local.common_labels, {
    region   = each.key
    purpose  = "regional-lb"
    priority = tostring(each.value.priority)
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL HEALTH CHECKS (HTTP-based)
# ═══════════════════════════════════════════════════════════════════════════════

# Health check service for each region
resource "google_monitoring_uptime_check_config" "regional_health_check" {
  for_each = local.regions
  
  display_name = "iSECTECH ${each.key} Health Check"
  timeout      = "10s"
  period       = "${var.health_check_interval}s"
  project      = var.project_id
  
  http_check {
    path           = var.health_check_path
    port           = 443
    use_ssl        = true
    validate_ssl   = true
    request_method = "GET"
    
    accepted_response_status_codes {
      status_class = "STATUS_CLASS_2XX"
    }
    
    headers = {
      "User-Agent" = "iSECTECH-Global-LoadBalancer/1.0"
      "Host"       = "api.${trimsuffix(var.domain_name, ".")}"
    }
  }
  
  monitored_resource {
    type = "uptime_url"
    labels = {
      project_id = var.project_id
      host       = google_compute_address.regional_ip[each.key].address
    }
  }
  
  # Check from multiple locations
  selected_regions = var.environment == "production" ? [
    "USA",
    "EUROPE",
    "ASIA_PACIFIC"
  ] : ["USA"]
  
  checker_type = "STATIC_IP_CHECKERS"
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS ROUTING POLICY (Geo-based routing)
# ═══════════════════════════════════════════════════════════════════════════════

# Policy for US traffic routing
resource "google_dns_policy" "us_routing_policy" {
  count   = var.global_load_balancer_type == "dns-based" ? 1 : 0
  name    = "isectech-us-routing-policy-${var.environment}"
  project = var.project_id
  
  enable_inbound_forwarding = false
  enable_logging           = true
  
  networks {
    network_url = google_compute_network.regional_vpc["us-central1"].id
  }
  
  networks {
    network_url = google_compute_network.regional_vpc["us-east1"].id
  }
}

# Policy for European traffic routing
resource "google_dns_policy" "eu_routing_policy" {
  count   = var.global_load_balancer_type == "dns-based" ? 1 : 0
  name    = "isectech-eu-routing-policy-${var.environment}"
  project = var.project_id
  
  enable_inbound_forwarding = false
  enable_logging           = true
  
  networks {
    network_url = google_compute_network.regional_vpc["europe-west4"].id
  }
  
  networks {
    network_url = google_compute_network.regional_vpc["europe-west1"].id
  }
}

# Policy for Asia-Pacific traffic routing
resource "google_dns_policy" "apac_routing_policy" {
  count   = var.global_load_balancer_type == "dns-based" ? 1 : 0
  name    = "isectech-apac-routing-policy-${var.environment}"
  project = var.project_id
  
  enable_inbound_forwarding = false
  enable_logging           = true
  
  networks {
    network_url = google_compute_network.regional_vpc["asia-northeast1"].id
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS RECORDS WITH WEIGHTED ROUTING
# ═══════════════════════════════════════════════════════════════════════════════

# A record for root domain with weighted routing
resource "google_dns_record_set" "root_domain_weighted" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = var.dns_ttl
  project      = var.project_id
  
  routing_policy {
    dynamic "wrr" {
      for_each = var.deployment_model == "active-active" ? local.regions : { (var.primary_region) = local.regions[var.primary_region] }
      content {
        weight = var.deployment_model == "active-active" ? 
                 lookup(var.traffic_distribution, wrr.key, 0) : 
                 (wrr.key == var.primary_region ? 100 : 0)
        rrdatas = [google_compute_address.regional_ip[wrr.key].address]
        
        # Health check for failover
        dynamic "health_checked_targets" {
          for_each = var.enable_health_checks ? [1] : []
          content {
            internal_load_balancers {
              load_balancer_type = "regionalL4ilb"
              ip_address        = google_compute_address.regional_ip[wrr.key].address
              port              = "443"
              ip_protocol       = "tcp"
              network_url       = google_compute_network.regional_vpc[wrr.key].id
              project           = var.project_id
            }
          }
        }
      }
    }
  }
}

# Weighted A records for API subdomain
resource "google_dns_record_set" "api_subdomain_weighted" {
  name         = "api.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = var.dns_ttl
  project      = var.project_id
  
  routing_policy {
    dynamic "wrr" {
      for_each = var.deployment_model == "active-active" ? local.regions : { (var.primary_region) = local.regions[var.primary_region] }
      content {
        weight = var.deployment_model == "active-active" ? 
                 lookup(var.traffic_distribution, wrr.key, 0) : 
                 (wrr.key == var.primary_region ? 100 : 0)
        rrdatas = [google_compute_address.regional_ip[wrr.key].address]
      }
    }
  }
}

# Geo-based routing for application subdomain
resource "google_dns_record_set" "app_subdomain_geo" {
  name         = "app.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = var.dns_ttl
  project      = var.project_id
  
  routing_policy {
    # US traffic to US regions
    geo {
      location = "us-central1"
      rrdatas  = [google_compute_address.regional_ip["us-central1"].address]
      
      dynamic "health_checked_targets" {
        for_each = var.enable_health_checks ? [1] : []
        content {
          internal_load_balancers {
            load_balancer_type = "regionalL4ilb"
            ip_address        = google_compute_address.regional_ip["us-central1"].address
            port              = "443"
            ip_protocol       = "tcp"
            network_url       = google_compute_network.regional_vpc["us-central1"].id
            project           = var.project_id
          }
        }
      }
    }
    
    geo {
      location = "us-east1"
      rrdatas  = [google_compute_address.regional_ip["us-east1"].address]
    }
    
    # European traffic to EU regions
    geo {
      location = "europe-west4"
      rrdatas  = [google_compute_address.regional_ip["europe-west4"].address]
      
      dynamic "health_checked_targets" {
        for_each = var.enable_health_checks ? [1] : []
        content {
          internal_load_balancers {
            load_balancer_type = "regionalL4ilb"
            ip_address        = google_compute_address.regional_ip["europe-west4"].address
            port              = "443"
            ip_protocol       = "tcp"
            network_url       = google_compute_network.regional_vpc["europe-west4"].id
            project           = var.project_id
          }
        }
      }
    }
    
    geo {
      location = "europe-west1"
      rrdatas  = [google_compute_address.regional_ip["europe-west1"].address]
    }
    
    # Asia-Pacific traffic to APAC region
    geo {
      location = "asia-northeast1"
      rrdatas  = [google_compute_address.regional_ip["asia-northeast1"].address]
      
      dynamic "health_checked_targets" {
        for_each = var.enable_health_checks ? [1] : []
        content {
          internal_load_balancers {
            load_balancer_type = "regionalL4ilb"
            ip_address        = google_compute_address.regional_ip["asia-northeast1"].address
            port              = "443"
            ip_protocol       = "tcp"
            network_url       = google_compute_network.regional_vpc["asia-northeast1"].id
            project           = var.project_id
          }
        }
      }
    }
  }
}

# Admin subdomain - restrict to primary regions for security
resource "google_dns_record_set" "admin_subdomain_restricted" {
  name         = "admin.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = var.dns_ttl
  project      = var.project_id
  
  routing_policy {
    wrr {
      weight  = 70
      rrdatas = [google_compute_address.regional_ip["us-central1"].address]
    }
    
    wrr {
      weight  = 30
      rrdatas = [google_compute_address.regional_ip["europe-west4"].address]
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MX RECORDS FOR EMAIL
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_dns_record_set" "mx_record" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "MX"
  ttl          = 3600
  project      = var.project_id
  
  rrdatas = [
    "1 smtp.google.com.",
    "5 alt1.gmx-smtp-in.l.google.com.",
    "5 alt2.gmx-smtp-in.l.google.com.",
    "10 alt3.gmx-smtp-in.l.google.com.",
    "10 alt4.gmx-smtp-in.l.google.com."
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# TXT RECORDS FOR VERIFICATION AND SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

# SPF record for email security
resource "google_dns_record_set" "spf_record" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [
    "\"v=spf1 include:_spf.google.com include:mailgun.org include:sendgrid.net ~all\""
  ]
}

# DMARC record for email authentication
resource "google_dns_record_set" "dmarc_record" {
  name         = "_dmarc.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [
    "\"v=DMARC1; p=quarantine; rua=mailto:dmarc@isectech.org; ruf=mailto:forensic@isectech.org; fo=1; adkim=s; aspf=s\""
  ]
}

# Domain verification record
resource "random_string" "domain_verification" {
  length  = 68
  special = false
  upper   = true
  lower   = true
  numeric = true
}

resource "google_dns_record_set" "domain_verification" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "TXT"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [
    "\"google-site-verification=${random_string.domain_verification.result}\"",
    "\"isectech-verification=${substr(sha256("${var.project_id}-${var.environment}"), 0, 32)}\""
  ]
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING FOR DNS
# ═══════════════════════════════════════════════════════════════════════════════

# Monitoring notification channel for DNS alerts
resource "google_monitoring_notification_channel" "dns_alerts" {
  count        = length(var.monitoring_notification_channels) > 0 ? 1 : 0
  display_name = "iSECTECH DNS Alerts"
  type         = "email"
  project      = var.project_id
  
  labels = {
    email_address = "dns-alerts@isectech.org"
  }
}

# Alert policy for DNS failures
resource "google_monitoring_alert_policy" "dns_failure_alert" {
  count               = var.enable_logging_monitoring ? 1 : 0
  display_name        = "iSECTECH DNS Resolution Failure"
  combiner           = "OR"
  enabled            = true
  notification_channels = var.monitoring_notification_channels
  project            = var.project_id
  
  conditions {
    display_name = "DNS Query Failure Rate"
    
    condition_threshold {
      filter         = "resource.type=\"dns_query\" AND metric.type=\"dns.googleapis.com/query/count\""
      duration       = "300s"
      comparison     = "COMPARISON_GREATER_THAN"
      threshold_value = 10
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields    = ["resource.label.source_type"]
      }
    }
  }
  
  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    
    auto_close = "86400s"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR DNS GLOBAL LOAD BALANCING
# ═══════════════════════════════════════════════════════════════════════════════

output "dns_global_load_balancing" {
  description = "DNS-based global load balancing configuration"
  value = {
    primary_zone_name = google_dns_managed_zone.primary_zone.name
    domain_name      = var.domain_name
    name_servers     = google_dns_managed_zone.primary_zone.name_servers
    dnssec_enabled   = var.enable_dnssec
    
    regional_ips = {
      for region in keys(local.regions) : region => {
        ip_address = google_compute_address.regional_ip[region].address
        priority   = local.regions[region].priority
        role       = local.regions[region].role
      }
    }
    
    routing_configuration = {
      deployment_model     = var.deployment_model
      traffic_distribution = var.traffic_distribution
      health_checks_enabled = var.enable_health_checks
      dns_ttl              = var.dns_ttl
    }
    
    verification_records = {
      google_verification = random_string.domain_verification.result
      isectech_verification = substr(sha256("${var.project_id}-${var.environment}"), 0, 32)
    }
  }
  sensitive = false
}

output "dns_nameservers" {
  description = "DNS name servers for domain delegation"
  value       = google_dns_managed_zone.primary_zone.name_servers
}