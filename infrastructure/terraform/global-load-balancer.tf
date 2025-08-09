# iSECTECH Global Load Balancing Configuration
# DNS-based global load balancing with health checks and failover
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Global Load Balancing Implementation

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
  dnssec_config {
    state         = "on"
    non_existence = "nsec3"
  }
  
  labels = merge(local.common_labels, {
    zone-type    = "primary"
    purpose      = "global-lb"
    dnssec       = "enabled"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL HTTP(S) LOAD BALANCER
# ═══════════════════════════════════════════════════════════════════════════════

# Global static IP for load balancer
resource "google_compute_global_address" "global_lb_ip" {
  name         = "isectech-global-lb-ip-${var.environment}"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"
  project      = var.project_id
  
  labels = merge(local.common_labels, {
    purpose = "global-lb"
    type    = "external-ip"
  })
}

# Global IPv6 address for load balancer
resource "google_compute_global_address" "global_lb_ipv6" {
  name         = "isectech-global-lb-ipv6-${var.environment}"
  address_type = "EXTERNAL"
  ip_version   = "IPV6"
  project      = var.project_id
  
  labels = merge(local.common_labels, {
    purpose = "global-lb"
    type    = "external-ipv6"
  })
}

# SSL certificate for HTTPS
resource "google_compute_managed_ssl_certificate" "global_ssl_cert" {
  name        = "isectech-global-ssl-cert-${var.environment}"
  description = "Managed SSL certificate for iSECTECH global load balancer"
  project     = var.project_id
  
  managed {
    domains = [
      var.domain_name,
      "app.${var.domain_name}",
      "api.${var.domain_name}",
      "admin.${var.domain_name}",
      "*.${var.domain_name}"
    ]
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKEND SERVICES FOR EACH REGION
# ═══════════════════════════════════════════════════════════════════════════════

# Regional backend services for application traffic
resource "google_compute_backend_service" "regional_backend" {
  for_each = local.regions
  
  name                  = "isectech-${each.key}-backend-${var.environment}"
  description          = "Backend service for ${each.key} region"
  protocol             = "HTTP"
  port_name            = "http"
  timeout_sec          = 30
  enable_cdn           = true
  load_balancing_scheme = "EXTERNAL"
  project              = var.project_id
  
  # Health check
  health_checks = [google_compute_health_check.regional_health_check[each.key].id]
  
  # Backend configuration
  dynamic "backend" {
    for_each = var.deployment_model == "active-active" || each.value.role == "primary" ? [1] : []
    content {
      group                 = google_compute_instance_group_manager.regional_ig[each.key].instance_group
      balancing_mode       = "UTILIZATION"
      max_utilization      = 0.8
      capacity_scaler      = each.value.role == "primary" ? 1.0 : 0.8
    }
  }
  
  # CDN configuration
  cdn_policy {
    cache_mode                   = "CACHE_ALL_STATIC"
    default_ttl                  = 3600
    max_ttl                      = 86400
    negative_caching             = true
    serve_while_stale            = 86400
    
    negative_caching_policy {
      code = 404
      ttl  = 120
    }
    
    negative_caching_policy {
      code = 410
      ttl  = 120
    }
    
    cache_key_policy {
      include_host         = true
      include_protocol     = true
      include_query_string = false
    }
  }
  
  # Circuit breaker
  circuit_breakers {
    max_requests_per_connection = 1000
    max_requests                = 10000
    max_pending_requests        = 100
    max_retries                 = 3
    max_connections             = 500
  }
  
  # Consistent hash-based load balancing for session affinity
  consistent_hash {
    http_cookie {
      name = "isectech-region-affinity"
      ttl {
        seconds = 3600
      }
    }
  }
  
  # Outlier detection
  outlier_detection {
    consecutive_errors                    = 3
    consecutive_gateway_failure_threshold = 3
    interval {
      seconds = 30
    }
    base_ejection_time {
      seconds = 30
    }
    max_ejection_percent = 50
    split_external_local_origin_errors = false
  }
  
  # Connection draining
  connection_draining_timeout_sec = 60
  
  # Locality preferences for routing
  locality_lb_policy = "ROUND_ROBIN"
  
  labels = merge(local.common_labels, {
    region          = each.key
    compliance-zone = each.value.compliance_zone
    backend-type    = "regional"
    priority        = tostring(each.value.priority)
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# HEALTH CHECKS FOR BACKEND SERVICES
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_compute_health_check" "regional_health_check" {
  for_each = local.regions
  
  name               = "isectech-${each.key}-health-check-${var.environment}"
  description        = "Health check for ${each.key} backend service"
  check_interval_sec = var.health_check_interval
  timeout_sec        = 10
  healthy_threshold   = 2
  unhealthy_threshold = 3
  project            = var.project_id
  
  http_health_check {
    request_path         = var.health_check_path
    port                = "8080"
    host                = "app.${var.domain_name}"
    proxy_header        = "PROXY_V1"
    port_specification  = "USE_FIXED_PORT"
  }
  
  log_config {
    enable = true
  }
  
  labels = merge(local.common_labels, {
    region = each.key
    type   = "health-check"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# URL MAP FOR TRAFFIC ROUTING
# ═══════════════════════════════════════════════════════════════════════════════

# URL map for global load balancing with regional routing
resource "google_compute_url_map" "global_url_map" {
  name            = "isectech-global-url-map-${var.environment}"
  description     = "Global URL map for multi-region traffic routing"
  default_service = google_compute_backend_service.regional_backend["us-central1"].id
  project         = var.project_id
  
  # Host rules for different subdomains
  dynamic "host_rule" {
    for_each = [
      {
        hosts = ["app.${var.domain_name}"]
        path_matcher = "app-matcher"
      },
      {
        hosts = ["api.${var.domain_name}"]
        path_matcher = "api-matcher"
      },
      {
        hosts = ["admin.${var.domain_name}"]
        path_matcher = "admin-matcher"
      }
    ]
    content {
      hosts        = host_rule.value.hosts
      path_matcher = host_rule.value.path_matcher
    }
  }
  
  # Path matchers for application routing
  path_matcher {
    name            = "app-matcher"
    default_service = google_compute_backend_service.regional_backend["us-central1"].id
    
    # Route by geographic proximity
    route_rules {
      priority = 1
      match_rules {
        prefix_match = "/"
        header_matches {
          name         = "cloudfront-viewer-country"
          exact_match  = "US"
        }
      }
      route_action {
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["us-central1"].id
          weight         = 100
        }
      }
    }
    
    route_rules {
      priority = 2
      match_rules {
        prefix_match = "/"
        header_matches {
          name         = "cloudfront-viewer-country"
          regex_match  = "^(DE|FR|IT|ES|NL|BE|AT|CH|DK|SE|NO|FI)$"
        }
      }
      route_action {
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["europe-west4"].id
          weight         = 100
        }
      }
    }
    
    route_rules {
      priority = 3
      match_rules {
        prefix_match = "/"
        header_matches {
          name         = "cloudfront-viewer-country"
          regex_match  = "^(JP|KR|SG|AU|IN|CN|HK|TW)$"
        }
      }
      route_action {
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["asia-northeast1"].id
          weight         = 100
        }
      }
    }
    
    # Default route to primary region
    path_rules {
      paths   = ["/*"]
      service = google_compute_backend_service.regional_backend["us-central1"].id
    }
  }
  
  # API routing
  path_matcher {
    name            = "api-matcher"
    default_service = google_compute_backend_service.regional_backend["us-central1"].id
    
    # API versioning and regional routing
    path_rules {
      paths = ["/v1/*", "/api/v1/*"]
      route_action {
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["us-central1"].id
          weight         = 40
        }
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["europe-west4"].id
          weight         = 30
        }
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["asia-northeast1"].id
          weight         = 30
        }
      }
    }
    
    # Health check endpoint
    path_rules {
      paths   = ["/health", "/healthz", "/ready"]
      service = google_compute_backend_service.regional_backend["us-central1"].id
    }
  }
  
  # Admin interface routing (restricted to primary regions)
  path_matcher {
    name            = "admin-matcher"
    default_service = google_compute_backend_service.regional_backend["us-central1"].id
    
    path_rules {
      paths = ["/*"]
      route_action {
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["us-central1"].id
          weight         = 70
        }
        weighted_backend_services {
          backend_service = google_compute_backend_service.regional_backend["europe-west4"].id
          weight         = 30
        }
      }
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTPS PROXY AND TARGET PROXY
# ═══════════════════════════════════════════════════════════════════════════════

# HTTPS target proxy
resource "google_compute_target_https_proxy" "global_https_proxy" {
  name             = "isectech-global-https-proxy-${var.environment}"
  description      = "Global HTTPS proxy for iSECTECH multi-region deployment"
  url_map          = google_compute_url_map.global_url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.global_ssl_cert.id]
  project          = var.project_id
  
  # Security policies
  ssl_policy = google_compute_ssl_policy.global_ssl_policy.id
  
  # QUIC protocol support
  quic_override = "ENABLE"
}

# HTTP redirect proxy (redirect HTTP to HTTPS)
resource "google_compute_url_map" "http_redirect" {
  name        = "isectech-http-redirect-${var.environment}"
  description = "HTTP to HTTPS redirect"
  project     = var.project_id
  
  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_target_http_proxy" "http_redirect_proxy" {
  name        = "isectech-http-redirect-proxy-${var.environment}"
  description = "HTTP redirect proxy to HTTPS"
  url_map     = google_compute_url_map.http_redirect.id
  project     = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL POLICY FOR SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_compute_ssl_policy" "global_ssl_policy" {
  name            = "isectech-ssl-policy-${var.environment}"
  description     = "SSL policy for iSECTECH global load balancer"
  profile         = var.environment == "production" ? "MODERN" : "COMPATIBLE"
  min_tls_version = "TLS_1_2"
  project         = var.project_id
  
  # Custom features for enhanced security
  custom_features = var.environment == "production" ? [
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
  ] : null
}

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL FORWARDING RULES
# ═══════════════════════════════════════════════════════════════════════════════

# HTTPS forwarding rule
resource "google_compute_global_forwarding_rule" "https_forwarding_rule" {
  name                  = "isectech-https-forwarding-rule-${var.environment}"
  description           = "Global HTTPS forwarding rule"
  target                = google_compute_target_https_proxy.global_https_proxy.id
  port_range            = "443"
  ip_protocol           = "TCP"
  ip_address           = google_compute_global_address.global_lb_ip.id
  load_balancing_scheme = "EXTERNAL"
  project               = var.project_id
  
  labels = merge(local.common_labels, {
    protocol = "https"
    port     = "443"
  })
}

# HTTP forwarding rule (for redirect)
resource "google_compute_global_forwarding_rule" "http_forwarding_rule" {
  name                  = "isectech-http-forwarding-rule-${var.environment}"
  description           = "Global HTTP forwarding rule for redirect"
  target                = google_compute_target_http_proxy.http_redirect_proxy.id
  port_range            = "80"
  ip_protocol           = "TCP"
  ip_address           = google_compute_global_address.global_lb_ip.id
  load_balancing_scheme = "EXTERNAL"
  project               = var.project_id
  
  labels = merge(local.common_labels, {
    protocol = "http"
    port     = "80"
  })
}

# IPv6 HTTPS forwarding rule
resource "google_compute_global_forwarding_rule" "https_ipv6_forwarding_rule" {
  name                  = "isectech-https-ipv6-forwarding-rule-${var.environment}"
  description           = "Global HTTPS IPv6 forwarding rule"
  target                = google_compute_target_https_proxy.global_https_proxy.id
  port_range            = "443"
  ip_protocol           = "TCP"
  ip_address           = google_compute_global_address.global_lb_ipv6.id
  load_balancing_scheme = "EXTERNAL"
  project               = var.project_id
  
  labels = merge(local.common_labels, {
    protocol = "https"
    port     = "443"
    ip-version = "ipv6"
  })
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS RECORDS FOR GLOBAL LOAD BALANCING
# ═══════════════════════════════════════════════════════════════════════════════

# A record pointing to global load balancer
resource "google_dns_record_set" "lb_a_record" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [google_compute_global_address.global_lb_ip.address]
}

# AAAA record for IPv6
resource "google_dns_record_set" "lb_aaaa_record" {
  name         = var.domain_name
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "AAAA"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [google_compute_global_address.global_lb_ipv6.address]
}

# Wildcard A records for subdomains
resource "google_dns_record_set" "wildcard_a_record" {
  name         = "*.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [google_compute_global_address.global_lb_ip.address]
}

# Specific subdomain records
resource "google_dns_record_set" "subdomain_records" {
  for_each = toset(["app", "api", "admin", "status", "docs"])
  
  name         = "${each.key}.${var.domain_name}"
  managed_zone = google_dns_managed_zone.primary_zone.name
  type         = "A"
  ttl          = 300
  project      = var.project_id
  
  rrdatas = [google_compute_global_address.global_lb_ip.address]
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD ARMOR SECURITY POLICY FOR GLOBAL LOAD BALANCER
# ═══════════════════════════════════════════════════════════════════════════════

resource "google_compute_security_policy" "global_security_policy" {
  name        = "isectech-global-security-policy-${var.environment}"
  description = "Security policy for iSECTECH global load balancer"
  project     = var.project_id
  
  # Default deny rule
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny rule"
  }
  
  # Allow legitimate traffic
  rule {
    action   = "allow"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["0.0.0.0/0"]
      }
    }
    description = "Allow all legitimate traffic"
    rate_limit_options {
      conform_action      = "allow"
      exceed_action       = "deny(429)"
      enforce_on_key      = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      ban_duration_sec = 600
    }
  }
  
  # Block known attack sources
  rule {
    action   = "deny(403)"
    priority = "2000"
    match {
      expr {
        expression = "origin.region_code == 'CN' || origin.region_code == 'RU' || origin.region_code == 'KP'"
      }
    }
    description = "Block traffic from high-risk regions"
  }
  
  # SQL injection protection
  rule {
    action   = "deny(403)"
    priority = "2100"
    match {
      expr {
        expression = "has(request.headers['user-agent']) && (request.headers['user-agent'].contains('sqlmap') || request.headers['user-agent'].contains('nmap'))"
      }
    }
    description = "Block known security scanning tools"
  }
  
  # DDoS protection
  rule {
    action   = "rate_based_ban"
    priority = "2200"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action      = "allow"
      exceed_action       = "deny(429)"
      enforce_on_key      = "IP"
      rate_limit_threshold {
        count        = 1000
        interval_sec = 300
      }
      ban_duration_sec = 1800
    }
    description = "Rate limiting and DDoS protection"
  }
  
  # Adaptive protection (ML-based)
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }
}

# Apply security policy to backend services
resource "google_compute_backend_service_security_policy_attachment" "backend_security" {
  for_each = local.regions
  
  backend_service   = google_compute_backend_service.regional_backend[each.key].name
  security_policy   = google_compute_security_policy.global_security_policy.name
  project          = var.project_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS FOR GLOBAL LOAD BALANCER
# ═══════════════════════════════════════════════════════════════════════════════

output "global_load_balancer" {
  description = "Global load balancer configuration"
  value = {
    ip_address     = google_compute_global_address.global_lb_ip.address
    ipv6_address   = google_compute_global_address.global_lb_ipv6.address
    dns_name       = var.domain_name
    ssl_cert_name  = google_compute_managed_ssl_certificate.global_ssl_cert.name
    url_map_name   = google_compute_url_map.global_url_map.name
    backend_services = {
      for region in keys(local.regions) : region => google_compute_backend_service.regional_backend[region].name
    }
  }
  sensitive = false
}

output "dns_configuration" {
  description = "DNS configuration for global load balancing"
  value = {
    primary_zone_name    = google_dns_managed_zone.primary_zone.name
    name_servers        = google_dns_managed_zone.primary_zone.name_servers
    domain_verification = {
      google  = "google-site-verification=${random_string.google_verification.result}"
      txt_records = [
        "v=spf1 include:_spf.google.com ~all",
        "google-site-verification=${random_string.google_verification.result}"
      ]
    }
  }
}

# Random string for domain verification
resource "random_string" "google_verification" {
  length  = 68
  special = false
  upper   = true
  lower   = true
  numeric = true
}