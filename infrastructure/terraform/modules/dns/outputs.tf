# iSECTECH DNS Management Module Outputs
# Production-grade DNS outputs for infrastructure integration
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

# ═══════════════════════════════════════════════════════════════════════════════
# DNS MANAGED ZONE OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "primary_zone_name" {
  description = "Name of the primary DNS managed zone"
  value       = google_dns_managed_zone.isectech_primary.name
}

output "primary_zone_id" {
  description = "ID of the primary DNS managed zone"
  value       = google_dns_managed_zone.isectech_primary.id
}

output "primary_zone_dns_name" {
  description = "DNS name of the primary managed zone"
  value       = google_dns_managed_zone.isectech_primary.dns_name
}

output "primary_zone_name_servers" {
  description = "Name servers for the primary DNS zone"
  value       = google_dns_managed_zone.isectech_primary.name_servers
}

output "environment_zones" {
  description = "Map of environment-specific DNS zones"
  value = {
    for zone_key, zone in google_dns_managed_zone.environment_zones : zone_key => {
      name         = zone.name
      id           = zone.id
      dns_name     = zone.dns_name
      name_servers = zone.name_servers
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS POLICY OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "dns_policy_name" {
  description = "Name of the DNS policy"
  value       = google_dns_policy.isectech_dns_policy.name
}

output "dns_policy_id" {
  description = "ID of the DNS policy"
  value       = google_dns_policy.isectech_dns_policy.id
}

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE ACCOUNT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "dns_manager_service_account_email" {
  description = "Email of the DNS manager service account"
  value       = google_service_account.dns_manager.email
}

output "dns_manager_service_account_id" {
  description = "ID of the DNS manager service account"
  value       = google_service_account.dns_manager.id
}

output "dns_manager_service_account_unique_id" {
  description = "Unique ID of the DNS manager service account"
  value       = google_service_account.dns_manager.unique_id
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN CONFIGURATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "domain_configuration" {
  description = "Complete domain configuration for environment"
  value = {
    base_domain    = local.base_domain
    environment    = var.environment
    domains        = local.current_domains
    all_domains    = local.all_domains
  }
}

output "isectech_domains" {
  description = "List of all iSECTECH domains for the environment"
  value       = local.all_domains
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "dns_monitoring_alerts" {
  description = "DNS monitoring alert policies"
  value = var.enable_dns_monitoring ? {
    query_volume_alert = {
      name         = google_monitoring_alert_policy.dns_query_volume[0].name
      display_name = google_monitoring_alert_policy.dns_query_volume[0].display_name
    }
    resolution_failures_alert = {
      name         = google_monitoring_alert_policy.dns_resolution_failures[0].name
      display_name = google_monitoring_alert_policy.dns_resolution_failures[0].display_name
    }
  } : {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# RECORD SET OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "caa_record_data" {
  description = "CAA record data for certificate authority authorization"
  value       = google_dns_record_set.caa_records.rrdatas
}

output "txt_verification_record_data" {
  description = "TXT verification record data"
  value       = google_dns_record_set.txt_verification.rrdatas
  sensitive   = true
}

output "dmarc_record_data" {
  description = "DMARC record data for email security"
  value       = google_dns_record_set.dmarc_record.rrdatas
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "dnssec_enabled" {
  description = "Whether DNSSEC is enabled for the zones"
  value       = var.enable_dnssec
}

output "dns_logging_enabled" {
  description = "Whether DNS logging is enabled"
  value       = var.enable_dns_logging
}

output "dns_forwarding_enabled" {
  description = "Whether DNS forwarding is enabled"
  value       = var.enable_dns_forwarding
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD RUN INTEGRATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cloud_run_domain_mappings" {
  description = "Cloud Run domain mapping configurations"
  value = var.enable_cloud_run_mapping ? {
    for domain, mapping in google_cloud_run_domain_mapping.domain_mappings : domain => {
      name     = mapping.name
      status   = mapping.status
      location = mapping.location
    }
  } : {}
}

output "cloud_run_dns_records" {
  description = "DNS records created for Cloud Run services"
  value = var.enable_cloud_run_mapping ? {
    cname_records = {
      for domain, record in google_dns_record_set.cloud_run_cname_records : domain => {
        name    = record.name
        type    = record.type
        ttl     = record.ttl
        rrdatas = record.rrdatas
      }
    }
    verification_records = {
      for domain, record in google_dns_record_set.google_search_console_verification : domain => {
        name    = record.name
        type    = record.type
        rrdatas = record.rrdatas
      }
    }
    domain_verification_records = {
      for domain, record in google_dns_record_set.cloud_run_domain_verification : domain => {
        name    = record.name
        type    = record.type
        rrdatas = record.rrdatas
      }
    }
  } : {}
}

output "cloud_run_services_data" {
  description = "Data about Cloud Run services for domain mapping"
  value = var.enable_cloud_run_mapping ? {
    for domain, service in data.google_cloud_run_service.services : domain => {
      name     = service.name
      location = service.location
      url      = service.status[0].url
    }
  } : {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS HEALTH MONITORING AND FAILOVER OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "health_check_configurations" {
  description = "Health check configurations for Cloud Run services"
  value = var.enable_dns_monitoring ? {
    for domain, check in google_monitoring_uptime_check_config.cloud_run_health_checks : domain => {
      name            = check.name
      display_name    = check.display_name
      timeout         = check.timeout
      period          = check.period
      selected_regions = check.selected_regions
      monitored_resource = check.monitored_resource
    }
  } : {}
}

output "health_monitoring_alerts" {
  description = "Health monitoring alert policies"
  value = var.enable_dns_monitoring ? {
    cloud_run_health_failures = length(google_monitoring_alert_policy.cloud_run_health_failures) > 0 ? {
      name         = google_monitoring_alert_policy.cloud_run_health_failures[0].name
      display_name = google_monitoring_alert_policy.cloud_run_health_failures[0].display_name
      enabled      = google_monitoring_alert_policy.cloud_run_health_failures[0].enabled
    } : null
    dns_resolution_health = length(google_monitoring_alert_policy.dns_resolution_health) > 0 ? {
      name         = google_monitoring_alert_policy.dns_resolution_health[0].name
      display_name = google_monitoring_alert_policy.dns_resolution_health[0].display_name
      enabled      = google_monitoring_alert_policy.dns_resolution_health[0].enabled
    } : null
  } : {}
}

output "notification_channels" {
  description = "Notification channels for DNS health monitoring"
  value = var.enable_dns_monitoring ? {
    email = length(google_monitoring_notification_channel.dns_health_email) > 0 ? {
      id           = google_monitoring_notification_channel.dns_health_email[0].id
      display_name = google_monitoring_notification_channel.dns_health_email[0].display_name
      type         = google_monitoring_notification_channel.dns_health_email[0].type
    } : null
    slack = length(google_monitoring_notification_channel.dns_health_slack) > 0 ? {
      id           = google_monitoring_notification_channel.dns_health_slack[0].id
      display_name = google_monitoring_notification_channel.dns_health_slack[0].display_name
      type         = google_monitoring_notification_channel.dns_health_slack[0].type
    } : null
  } : {}
}

output "failover_configuration" {
  description = "DNS failover configuration details"
  value = var.enable_dns_failover ? {
    enabled = var.enable_dns_failover
    failover_records = {
      for domain, record in google_dns_record_set.failover_cname_records : domain => {
        name    = record.name
        type    = record.type
        ttl     = record.ttl
        rrdatas = record.rrdatas
      }
    }
    maintenance_page = length(google_dns_record_set.maintenance_page) > 0 ? {
      name    = google_dns_record_set.maintenance_page[0].name
      type    = google_dns_record_set.maintenance_page[0].type
      rrdatas = google_dns_record_set.maintenance_page[0].rrdatas
    } : null
  } : {
    enabled = false
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE MANAGEMENT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "certificate_map" {
  description = "Certificate map configuration for SSL certificates"
  value = var.enable_certificate_manager && length(google_certificate_manager_certificate_map.isectech_certificate_map) > 0 ? {
    name        = google_certificate_manager_certificate_map.isectech_certificate_map[0].name
    id          = google_certificate_manager_certificate_map.isectech_certificate_map[0].id
    description = google_certificate_manager_certificate_map.isectech_certificate_map[0].description
  } : null
}

output "managed_certificates" {
  description = "Managed SSL certificates provisioned via Certificate Manager"
  value = var.enable_certificate_manager ? {
    for domain, cert in google_certificate_manager_certificate.managed_certificates : domain => {
      name        = cert.name
      id          = cert.id
      domain      = domain
      state       = cert.managed[0].state
      provisioning_issue = length(cert.managed[0].provisioning_issue) > 0 ? cert.managed[0].provisioning_issue[0] : null
      authorization_attempt_info = length(cert.managed[0].authorization_attempt_info) > 0 ? cert.managed[0].authorization_attempt_info[0] : null
    }
  } : {}
}

output "wildcard_certificate" {
  description = "Wildcard SSL certificate information"
  value = var.enable_certificate_manager && var.enable_wildcard_certificate && length(google_certificate_manager_certificate.wildcard_certificate) > 0 ? {
    name        = google_certificate_manager_certificate.wildcard_certificate[0].name
    id          = google_certificate_manager_certificate.wildcard_certificate[0].id
    domain      = "*.${local.base_domain}"
    state       = google_certificate_manager_certificate.wildcard_certificate[0].managed[0].state
    provisioning_issue = length(google_certificate_manager_certificate.wildcard_certificate[0].managed[0].provisioning_issue) > 0 ? google_certificate_manager_certificate.wildcard_certificate[0].managed[0].provisioning_issue[0] : null
  } : null
}

output "dns_authorizations" {
  description = "DNS authorizations for certificate validation"
  value = var.enable_certificate_manager ? {
    domain_authorizations = {
      for domain, auth in google_certificate_manager_dns_authorization.domain_authorizations : domain => {
        name   = auth.name
        id     = auth.id
        domain = auth.domain
        dns_resource_record = length(auth.dns_resource_record) > 0 ? {
          name = auth.dns_resource_record[0].name
          type = auth.dns_resource_record[0].type
          data = auth.dns_resource_record[0].data
        } : null
      }
    }
    wildcard_authorization = var.enable_wildcard_certificate && length(google_certificate_manager_dns_authorization.wildcard_authorization) > 0 ? {
      name   = google_certificate_manager_dns_authorization.wildcard_authorization[0].name
      id     = google_certificate_manager_dns_authorization.wildcard_authorization[0].id
      domain = google_certificate_manager_dns_authorization.wildcard_authorization[0].domain
      dns_resource_record = length(google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record) > 0 ? {
        name = google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].name
        type = google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].type
        data = google_certificate_manager_dns_authorization.wildcard_authorization[0].dns_resource_record[0].data
      } : null
    } : null
  } : {}
}

output "certificate_validation_records" {
  description = "DNS records created for certificate validation"
  value = var.enable_certificate_manager ? {
    for domain, record in google_dns_record_set.certificate_validation_records : domain => {
      name    = record.name
      type    = record.type
      ttl     = record.ttl
      rrdatas = record.rrdatas
    }
  } : {}
}

output "certificate_map_entries" {
  description = "Certificate map entries mapping domains to certificates"
  value = var.enable_certificate_manager ? {
    domain_entries = {
      for domain, entry in google_certificate_manager_certificate_map_entry.certificate_map_entries : domain => {
        name         = entry.name
        hostname     = entry.hostname
        certificates = entry.certificates
      }
    }
    wildcard_entry = var.enable_wildcard_certificate && length(google_certificate_manager_certificate_map_entry.wildcard_certificate_entry) > 0 ? {
      name         = google_certificate_manager_certificate_map_entry.wildcard_certificate_entry[0].name
      matcher      = google_certificate_manager_certificate_map_entry.wildcard_certificate_entry[0].matcher
      certificates = google_certificate_manager_certificate_map_entry.wildcard_certificate_entry[0].certificates
    } : null
  } : {}
}

output "ssl_certificate_status" {
  description = "Overall SSL certificate provisioning status"
  value = var.enable_certificate_manager ? {
    certificate_manager_enabled = var.enable_certificate_manager
    wildcard_certificate_enabled = var.enable_wildcard_certificate
    total_certificates = length(var.certificate_domains) + (var.enable_wildcard_certificate ? 1 : 0)
    certificate_map_ready = length(google_certificate_manager_certificate_map.isectech_certificate_map) > 0
    domains_covered = var.certificate_domains
  } : {
    certificate_manager_enabled = false
    message = "Certificate Manager is disabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSL CERTIFICATE RENEWAL AND MONITORING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "certificate_monitoring_configuration" {
  description = "SSL certificate monitoring and alerting configuration"
  value = var.enable_certificate_monitoring ? {
    monitoring_enabled = var.enable_certificate_monitoring
    renewal_buffer_days = var.certificate_renewal_buffer_days
    notification_channels = {
      email = length(google_monitoring_notification_channel.ssl_certificate_email) > 0 ? {
        id           = google_monitoring_notification_channel.ssl_certificate_email[0].id 
        display_name = google_monitoring_notification_channel.ssl_certificate_email[0].display_name
        email        = var.certificate_notification_email != "" ? var.certificate_notification_email : "security@isectech.org"
      } : null
      slack = length(google_monitoring_notification_channel.ssl_certificate_slack) > 0 ? {
        id           = google_monitoring_notification_channel.ssl_certificate_slack[0].id
        display_name = google_monitoring_notification_channel.ssl_certificate_slack[0].display_name
      } : null
    }
  } : {
    monitoring_enabled = false
  }
}

output "certificate_alert_policies" {
  description = "SSL certificate monitoring alert policies"
  value = var.enable_certificate_monitoring ? {
    provisioning_failures = length(google_monitoring_alert_policy.certificate_provisioning_failures) > 0 ? {
      name         = google_monitoring_alert_policy.certificate_provisioning_failures[0].name
      display_name = google_monitoring_alert_policy.certificate_provisioning_failures[0].display_name
      enabled      = google_monitoring_alert_policy.certificate_provisioning_failures[0].enabled
    } : null
    expiration_warning = length(google_monitoring_alert_policy.certificate_expiration_warning) > 0 ? {
      name         = google_monitoring_alert_policy.certificate_expiration_warning[0].name
      display_name = google_monitoring_alert_policy.certificate_expiration_warning[0].display_name
      enabled      = google_monitoring_alert_policy.certificate_expiration_warning[0].enabled
    } : null
    renewal_failures = length(google_monitoring_alert_policy.certificate_renewal_failures) > 0 ? {
      name         = google_monitoring_alert_policy.certificate_renewal_failures[0].name
      display_name = google_monitoring_alert_policy.certificate_renewal_failures[0].display_name
      enabled      = google_monitoring_alert_policy.certificate_renewal_failures[0].enabled
    } : null
  } : {}
}

output "certificate_logging_metrics" {
  description = "SSL certificate logging metrics for monitoring"
  value = var.enable_certificate_monitoring ? {
    state_changes = length(google_logging_metric.certificate_state_changes) > 0 ? {
      name         = google_logging_metric.certificate_state_changes[0].name
      display_name = google_logging_metric.certificate_state_changes[0].metric_descriptor[0].display_name
      description  = google_logging_metric.certificate_state_changes[0].metric_descriptor[0].description
    } : null
  } : {}
}

output "certificate_dashboard" {
  description = "SSL certificate monitoring dashboard"
  value = var.enable_certificate_monitoring && var.create_certificate_dashboard && length(google_monitoring_dashboard.ssl_certificate_dashboard) > 0 ? {
    dashboard_url = "https://console.cloud.google.com/monitoring/dashboards/custom/${google_monitoring_dashboard.ssl_certificate_dashboard[0].id}?project=${var.project_id}"
    dashboard_id  = google_monitoring_dashboard.ssl_certificate_dashboard[0].id
  } : null
}

output "certificate_renewal_status" {
  description = "SSL certificate automatic renewal configuration status"
  value = var.enable_certificate_manager ? {
    automatic_renewal_enabled = true  # Google Certificate Manager automatically renews certificates
    renewal_buffer_days = var.certificate_renewal_buffer_days
    monitoring_enabled = var.enable_certificate_monitoring
    renewal_policy = {
      provider = "google-certificate-manager"
      renewal_window = "30 days before expiration"
      retry_policy = "Automatic with exponential backoff"
      notification_policy = var.enable_certificate_monitoring ? "Enabled" : "Disabled"
    }
    domains_covered = var.certificate_domains
    wildcard_renewal = var.enable_wildcard_certificate
  } : {
    automatic_renewal_enabled = false
    message = "Certificate Manager is disabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS AND CERTIFICATE PINNING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "security_headers_configuration" {
  description = "HTTP security headers and policies configuration"
  value = var.enable_security_headers ? {
    security_policy_name = length(google_compute_security_policy.isectech_security_headers_policy) > 0 ? google_compute_security_policy.isectech_security_headers_policy[0].name : null
    security_policy_id = length(google_compute_security_policy.isectech_security_headers_policy) > 0 ? google_compute_security_policy.isectech_security_headers_policy[0].id : null
    headers_configured = {
      hsts = "max-age=31536000; includeSubDomains; preload"
      csp = var.content_security_policy
      x_content_type_options = "nosniff"
      x_frame_options = "DENY"
      x_xss_protection = "1; mode=block"
      referrer_policy = "strict-origin-when-cross-origin"
      permissions_policy = var.permissions_policy
      expect_ct = true
      hpkp = var.enable_certificate_pinning
    }
  } : {
    enabled = false
    message = "Security headers are disabled"
  }
}

output "certificate_pinning_configuration" {
  description = "Certificate pinning configuration and DNS records"
  value = var.enable_certificate_pinning ? {
    hpkp_enabled = var.enable_certificate_pinning
    dane_tlsa_records = {
      for domain, record in google_dns_record_set.dane_tlsa_records : domain => {
        name = record.name
        type = record.type
        ttl  = record.ttl
        rrdatas = record.rrdatas
      }
    }
    hpkp_backup_info = length(google_dns_record_set.hpkp_backup_info) > 0 ? {
      name = google_dns_record_set.hpkp_backup_info[0].name
      rrdatas = google_dns_record_set.hpkp_backup_info[0].rrdatas
    } : null
    enhanced_caa_records = length(google_dns_record_set.enhanced_caa_records) > 0 ? {
      name = google_dns_record_set.enhanced_caa_records[0].name
      rrdatas = google_dns_record_set.enhanced_caa_records[0].rrdatas
    } : null
  } : {
    enabled = false
    message = "Certificate pinning is disabled"
  }
}

output "security_contact_information" {
  description = "Security contact and policy information"
  value = var.enable_security_headers ? {
    security_txt_record = length(google_dns_record_set.security_txt) > 0 ? {
      name = google_dns_record_set.security_txt[0].name
      rrdatas = google_dns_record_set.security_txt[0].rrdatas
    } : null
    contact_email = "security@isectech.org"
    security_policy_url = "https://security.isectech.org/security-policy"
    encryption_key_url = "https://security.isectech.org/pgp-key.txt"
  } : {
    enabled = false
  }
}

output "certificate_transparency_configuration" {
  description = "Certificate Transparency monitoring configuration"
  value = var.enable_certificate_transparency ? {
    ct_monitoring_enabled = var.enable_certificate_transparency
    ct_dns_record = length(google_dns_record_set.ct_monitoring) > 0 ? {
      name = google_dns_record_set.ct_monitoring[0].name
      rrdatas = google_dns_record_set.ct_monitoring[0].rrdatas
    } : null
    expect_ct_header = "max-age=86400, enforce, report-uri=\"https://isectech.report-uri.com/r/d/ct/enforce\""
    monitored_ct_logs = ["google-pilot", "google-rocketeer", "cloudflare-nimbus"]
  } : {
    enabled = false
    message = "Certificate Transparency monitoring is disabled"
  }
}

output "domain_security_status" {
  description = "Overall domain security configuration status"
  value = {
    security_headers_enabled = var.enable_security_headers
    certificate_pinning_enabled = var.enable_certificate_pinning
    certificate_transparency_enabled = var.enable_certificate_transparency
    dane_tlsa_enabled = var.enable_certificate_pinning
    hpkp_enabled = var.enable_certificate_pinning
    security_contact_configured = var.enable_security_headers
    caa_records_enhanced = var.enable_security_headers
    security_compliance_level = var.enable_security_headers && var.enable_certificate_pinning && var.enable_certificate_transparency ? "maximum" : var.enable_security_headers ? "standard" : "basic"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "cloud_run_integration_ready" {
  description = "Whether the DNS configuration is ready for Cloud Run integration"
  value       = var.enable_cloud_run_mapping
}

output "certificate_domains_list" {
  description = "List of domains configured for certificate management"
  value       = length(var.certificate_domains) > 0 ? var.certificate_domains : local.all_domains
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND AUDIT OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "compliance_frameworks_applied" {
  description = "List of compliance frameworks applied to DNS configuration"
  value       = var.compliance_frameworks
}

output "audit_logging_enabled" {
  description = "Whether comprehensive audit logging is enabled"
  value       = var.enable_audit_logging
}

output "backup_configuration" {
  description = "DNS backup configuration details"
  value = {
    enabled         = var.enable_dns_backup
    retention_days  = var.backup_retention_days
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE CONFIGURATION OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "dns_cache_ttl" {
  description = "Default TTL for DNS records"
  value       = var.dns_cache_ttl
}

output "geo_routing_enabled" {
  description = "Whether geographic routing is enabled"
  value       = var.enable_geo_routing
}

output "performance_optimization_settings" {
  description = "DNS performance optimization settings"
  value = {
    cache_ttl     = var.dns_cache_ttl
    geo_routing   = var.enable_geo_routing
    private_zones = var.enable_private_zones
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.8: CUSTOM DOMAIN MAPPING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "domain_mappings" {
  description = "Custom domain mappings to Cloud Run services"
  value = var.enable_cloud_run_mapping ? {
    production_mappings = {
      for domain, mapping in google_cloud_run_domain_mapping.domain_mappings : domain => {
        name         = mapping.name
        location     = mapping.location
        status       = mapping.status
        url          = "https://${domain}"
        service_name = var.cloud_run_services[domain].service_name
      }
    }
    environment_mappings = var.create_environment_zones ? {
      for domain, mapping in google_cloud_run_domain_mapping.environment_domain_mappings : domain => {
        name         = mapping.name
        location     = mapping.location
        status       = mapping.status
        url          = "https://${domain}"
        service_name = split(".", domain)[0]  # staging or development
      }
    } : {}
  } : {
    enabled = false
    message = "Cloud Run domain mapping is disabled"
  }
}

output "domain_dns_records" {
  description = "DNS records created for domain mapping"
  value = var.enable_cloud_run_mapping ? {
    primary_domains = {
      for domain, record in google_dns_record_set.cloud_run_domain_records : domain => {
        name    = record.name
        type    = record.type
        ttl     = record.ttl
        rrdatas = record.rrdatas
      }
    }
    www_domains = {
      for domain, record in google_dns_record_set.www_domain_records : domain => {
        name    = record.name
        type    = record.type
        ttl     = record.ttl
        rrdatas = record.rrdatas
      }
    }
    verification_records = {
      for domain, record in google_dns_record_set.domain_verification_records : domain => {
        name    = record.name
        type    = record.type
        rrdatas = record.rrdatas
      }
    }
    environment_domains = var.create_environment_zones ? {
      for domain, record in google_dns_record_set.environment_domain_records : domain => {
        name    = record.name
        type    = record.type
        ttl     = record.ttl
        rrdatas = record.rrdatas
      }
    } : {}
  } : {}
}

output "domain_health_monitoring" {
  description = "Health monitoring configuration for mapped domains"
  value = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? {
    health_checks = {
      for domain, check in google_monitoring_uptime_check_config.domain_mapping_health_checks : domain => {
        display_name = check.display_name
        timeout      = check.timeout
        period       = check.period
        regions      = check.selected_regions
        endpoint     = "https://${domain}/health"
      }
    }
    alert_policies = length(google_monitoring_alert_policy.domain_mapping_failures) > 0 ? {
      name         = google_monitoring_alert_policy.domain_mapping_failures[0].name
      display_name = google_monitoring_alert_policy.domain_mapping_failures[0].display_name
      enabled      = google_monitoring_alert_policy.domain_mapping_failures[0].enabled
    } : null
  } : {
    enabled = false
    health_checks = {}
    alert_policies = null
  }
}

output "traffic_allocation_configuration" {
  description = "Traffic allocation configuration for gradual rollouts"
  value = var.enable_cloud_run_mapping ? {
    configured_services = {
      for domain, config in var.cloud_run_services : domain => {
        service_name      = config.service_name
        region            = config.region
        traffic_allocation = config.traffic_allocation != null ? config.traffic_allocation : 100
        gradual_rollout   = config.traffic_allocation != null && config.traffic_allocation < 100
      }
    }
    active_rollouts = {
      for domain, service in google_cloud_run_service.traffic_allocation : domain => {
        name     = service.name
        location = service.location
        traffic  = service.traffic
      }
    }
  } : {
    enabled = false
    message = "Cloud Run domain mapping is disabled"
  }
}

output "domain_mapping_status" {
  description = "Overall status of domain mapping configuration"
  value = {
    enabled                = var.enable_cloud_run_mapping
    total_domains         = length(var.cloud_run_services)
    environment_zones     = var.create_environment_zones
    health_monitoring     = var.enable_dns_monitoring
    ssl_certificates      = var.enable_certificate_manager
    security_headers      = var.enable_security_headers
    configured_domains    = keys(var.cloud_run_services)
    ready_for_production  = var.enable_cloud_run_mapping && var.enable_certificate_manager && var.enable_dns_monitoring
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.9: DOMAIN ROUTING RULES AND LOAD BALANCING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "load_balancer_configuration" {
  description = "Global Load Balancer configuration for advanced routing"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    global_ip = length(google_compute_global_address.isectech_load_balancer_ip) > 0 ? {
      address = google_compute_global_address.isectech_load_balancer_ip[0].address
      name    = google_compute_global_address.isectech_load_balancer_ip[0].name
    } : null
    ssl_certificate = length(google_compute_managed_ssl_certificate.load_balancer_cert) > 0 ? {
      name    = google_compute_managed_ssl_certificate.load_balancer_cert[0].name
      domains = google_compute_managed_ssl_certificate.load_balancer_cert[0].managed[0].domains
    } : null
    url_map = length(google_compute_url_map.isectech_url_map) > 0 ? {
      name = google_compute_url_map.isectech_url_map[0].name
    } : null
    https_proxy = length(google_compute_target_https_proxy.isectech_https_proxy) > 0 ? {
      name = google_compute_target_https_proxy.isectech_https_proxy[0].name
    } : null
    http_proxy = length(google_compute_target_http_proxy.isectech_http_proxy) > 0 ? {
      name = google_compute_target_http_proxy.isectech_http_proxy[0].name
    } : null
  } : {
    enabled = false
    message = "Load balancer configuration is disabled"
  }
}

output "backend_services" {
  description = "Backend services configuration for Cloud Run services"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    for domain, backend in google_compute_backend_service.cloud_run_backends : domain => {
      name            = backend.name
      protocol        = backend.protocol
      timeout_sec     = backend.timeout_sec
      enable_cdn      = backend.enable_cdn
      security_policy = backend.security_policy
      health_checks   = backend.health_checks
    }
  } : {}
}

output "network_endpoint_groups" {
  description = "Network Endpoint Groups for serverless Cloud Run backends"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    for domain, neg in google_compute_region_network_endpoint_group.cloud_run_neg : domain => {
      name                  = neg.name
      region                = neg.region
      network_endpoint_type = neg.network_endpoint_type
      cloud_run_service     = var.cloud_run_services[domain].service_name
    }
  } : {}
}

output "health_checks" {
  description = "Health check configurations for load balancer backends"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    for domain, hc in google_compute_health_check.cloud_run_health_check : domain => {
      name                = hc.name
      timeout_sec         = hc.timeout_sec
      check_interval_sec  = hc.check_interval_sec
      healthy_threshold   = hc.healthy_threshold
      unhealthy_threshold = hc.unhealthy_threshold
      request_path        = hc.https_health_check[0].request_path
    }
  } : {}
}

output "forwarding_rules" {
  description = "Global forwarding rules for HTTP and HTTPS traffic"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    https = length(google_compute_global_forwarding_rule.isectech_https_forwarding_rule) > 0 ? {
      name       = google_compute_global_forwarding_rule.isectech_https_forwarding_rule[0].name
      ip_address = google_compute_global_forwarding_rule.isectech_https_forwarding_rule[0].ip_address
      port_range = google_compute_global_forwarding_rule.isectech_https_forwarding_rule[0].port_range
      target     = google_compute_global_forwarding_rule.isectech_https_forwarding_rule[0].target
    } : null
    http = length(google_compute_global_forwarding_rule.isectech_http_forwarding_rule) > 0 ? {
      name       = google_compute_global_forwarding_rule.isectech_http_forwarding_rule[0].name
      ip_address = google_compute_global_forwarding_rule.isectech_http_forwarding_rule[0].ip_address
      port_range = google_compute_global_forwarding_rule.isectech_http_forwarding_rule[0].port_range
      target     = google_compute_global_forwarding_rule.isectech_http_forwarding_rule[0].target
    } : null
  } : {
    enabled = false
    https   = null
    http    = null
  }
}

output "geographic_routing" {
  description = "Geographic routing policies and DNS records"
  value = var.enable_geo_routing && length(var.geo_routing_policies) > 0 ? {
    enabled = true
    policies = {
      for domain, record in google_dns_record_set.geo_routing_records : domain => {
        name     = record.name
        type     = record.type
        ttl      = record.ttl
        location = var.geo_routing_policies[domain].location
        rrdatas  = record.rrdatas
      }
    }
  } : {
    enabled  = false
    policies = {}
  }
}

output "routing_rules" {
  description = "URL routing rules and path-based routing configuration"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing ? {
    configured_paths = {
      api_paths     = ["/api/*", "/v1/*", "/v2/*"]
      static_paths  = ["/assets/*", "/static/*", "/images/*", "/css/*", "/js/*"]
      health_paths  = ["/health", "/ready", "/live"]
    }
    timeout_configuration = {
      api_timeout     = "60s"
      static_timeout  = "30s"
      health_timeout  = "10s"
      default_timeout = "30s"
    }
    cdn_configuration = {
      enabled           = true
      cache_mode        = "CACHE_ALL_STATIC"
      default_ttl       = 3600
      max_ttl           = 86400
      client_ttl        = 3600
      negative_caching  = true
      serve_while_stale = 86400
    }
  } : {
    enabled = false
    message = "Advanced routing is disabled"
  }
}

output "load_balancer_monitoring" {
  description = "Load balancer monitoring and alerting configuration"
  value = var.enable_cloud_run_mapping && var.enable_geo_routing && var.enable_dns_monitoring ? {
    health_check = length(google_monitoring_uptime_check_config.load_balancer_health_check) > 0 ? {
      display_name = google_monitoring_uptime_check_config.load_balancer_health_check[0].display_name
      timeout      = google_monitoring_uptime_check_config.load_balancer_health_check[0].timeout
      period       = google_monitoring_uptime_check_config.load_balancer_health_check[0].period
      regions      = google_monitoring_uptime_check_config.load_balancer_health_check[0].selected_regions
    } : null
    alert_policy = length(google_monitoring_alert_policy.load_balancer_failures) > 0 ? {
      name         = google_monitoring_alert_policy.load_balancer_failures[0].name
      display_name = google_monitoring_alert_policy.load_balancer_failures[0].display_name
      enabled      = google_monitoring_alert_policy.load_balancer_failures[0].enabled
      conditions   = length(google_monitoring_alert_policy.load_balancer_failures[0].conditions)
    } : null
  } : {
    enabled      = false
    health_check = null
    alert_policy = null
  }
}

output "routing_status" {
  description = "Overall status of domain routing and load balancing configuration"
  value = {
    load_balancer_enabled = var.enable_cloud_run_mapping && var.enable_geo_routing
    geographic_routing    = var.enable_geo_routing && length(var.geo_routing_policies) > 0
    cdn_enabled          = var.enable_cloud_run_mapping && var.enable_geo_routing
    https_redirect       = var.enable_cloud_run_mapping && var.enable_geo_routing
    health_monitoring    = var.enable_dns_monitoring
    backend_services     = length(var.cloud_run_services)
    ready_for_traffic    = var.enable_cloud_run_mapping && var.enable_geo_routing && var.enable_certificate_manager
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# TASK 61.10: DOMAIN-SPECIFIC SECURITY, LOGGING, AND MONITORING OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════

output "domain_security_policies" {
  description = "Domain-specific security policies and configurations"
  value = var.enable_cloud_run_mapping ? {
    security_policies = {
      for domain, policy in google_compute_security_policy.domain_specific_security_policy : domain => {
        name        = policy.name
        description = policy.description
        type        = policy.type
        rule_count  = length(policy.rule)
        adaptive_protection = policy.adaptive_protection_config != null
      }
    }
    access_control_policies = var.environment != "production" ? {
      for domain, policy in google_compute_security_policy.domain_access_control : domain => {
        name        = policy.name
        description = policy.description
        environment = var.environment
      }
    } : {}
  } : {
    enabled = false
    message = "Domain security policies are disabled"
  }
}

output "domain_logging_configuration" {
  description = "Domain-specific logging sinks and storage configuration"
  value = var.enable_cloud_run_mapping && var.enable_audit_logging ? {
    logging_sinks = {
      for domain, sink in google_logging_project_sink.domain_security_logs : domain => {
        name        = sink.name
        destination = sink.destination
        filter      = sink.filter
      }
    }
    storage_buckets = {
      for domain, bucket in google_storage_bucket.domain_security_logs : domain => {
        name               = bucket.name
        location           = bucket.location
        versioning_enabled = bucket.versioning[0].enabled
        lifecycle_rules    = length(bucket.lifecycle_rule)
        uniform_access     = bucket.uniform_bucket_level_access
      }
    }
    logging_metrics = {
      for domain, metric in google_logging_metric.domain_security_events : domain => {
        name         = metric.name
        filter       = metric.filter
        metric_kind  = metric.metric_descriptor[0].metric_kind
        value_type   = metric.metric_descriptor[0].value_type
        labels_count = length(metric.metric_descriptor[0].labels)
      }
    }
  } : {
    enabled = false
    message = "Domain logging is disabled"
  }
}

output "domain_monitoring_dashboards" {
  description = "Domain-specific monitoring dashboards and configurations"
  value = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? {
    security_dashboards = {
      for domain, dashboard in google_monitoring_dashboard.domain_security_dashboard : domain => {
        dashboard_url = "https://console.cloud.google.com/monitoring/dashboards/custom/${dashboard.id}?project=${var.project_id}"
        display_name  = jsondecode(dashboard.dashboard_json).displayName
        tiles_count   = length(jsondecode(dashboard.dashboard_json).mosaicLayout.tiles)
      }
    }
    monitored_metrics = {
      request_rate          = "loadbalancing.googleapis.com/https/request_count"
      security_violations   = "loadbalancing.googleapis.com/https/request_count (4xx)"
      response_latency      = "loadbalancing.googleapis.com/https/total_latencies"
      ssl_certificate_expiry = "certificatemanager.googleapis.com/certificate/expiration_time"
    }
  } : {
    enabled = false
    security_dashboards = {}
  }
}

output "domain_alert_policies" {
  description = "Domain-specific alert policies and monitoring rules"
  value = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? {
    security_violation_alerts = {
      for domain, alert in google_monitoring_alert_policy.domain_security_violations : domain => {
        name         = alert.name
        display_name = alert.display_name
        enabled      = alert.enabled
        conditions   = length(alert.conditions)
        combiner     = alert.combiner
      }
    }
    performance_alerts = {
      for domain, alert in google_monitoring_alert_policy.domain_performance_degradation : domain => {
        name         = alert.name
        display_name = alert.display_name
        enabled      = alert.enabled
        conditions   = length(alert.conditions)
        combiner     = alert.combiner
      }
    }
    ssl_certificate_alerts = var.enable_certificate_monitoring ? {
      for domain, alert in google_monitoring_alert_policy.domain_ssl_certificate_expiration : domain => {
        name         = alert.name
        display_name = alert.display_name
        enabled      = alert.enabled
        threshold    = "30 days"
        auto_close   = alert.alert_strategy[0].auto_close
      }
    } : {}
  } : {
    enabled = false
    security_violation_alerts = {}
    performance_alerts        = {}
    ssl_certificate_alerts    = {}
  }
}

output "security_protection_features" {
  description = "Active security protection features per domain"
  value = var.enable_cloud_run_mapping ? {
    for domain in keys(var.cloud_run_services) : domain => {
      rate_limiting = {
        enabled     = true
        threshold   = "100 requests/minute"
        ban_duration = "5 minutes"
      }
      geographic_blocking = var.environment == "production" ? {
        enabled         = true
        blocked_regions = ["CN", "RU", "KP"]
      } : {
        enabled = false
      }
      attack_protection = {
        sql_injection = true
        xss_protection = true
        protocol_attacks = true
        bot_protection = true
      }
      adaptive_protection = {
        ddos_defense = true
        auto_deploy = true
        load_threshold = 0.1
        confidence_threshold = 0.5
      }
      access_control = var.environment != "production" ? {
        enabled = true
        allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        default_action = "deny"
      } : {
        enabled = false
        default_action = "allow"
      }
    }
  } : {}
}

output "domain_security_summary" {
  description = "Summary of domain security, logging, and monitoring status"
  value = {
    total_domains = length(var.cloud_run_services)
    security_policies_configured = var.enable_cloud_run_mapping ? length(var.cloud_run_services) : 0
    logging_enabled = var.enable_audit_logging
    monitoring_enabled = var.enable_dns_monitoring
    dashboards_created = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? length(var.cloud_run_services) : 0
    alert_policies = var.enable_cloud_run_mapping && var.enable_dns_monitoring ? length(var.cloud_run_services) * 3 : 0
    environment_restrictions = var.environment != "production"
    adaptive_protection = var.enable_cloud_run_mapping
    certificate_monitoring = var.enable_certificate_monitoring
    storage_retention = var.enable_audit_logging ? "90 days" : "disabled"
    compliance_ready = var.enable_cloud_run_mapping && var.enable_audit_logging && var.enable_dns_monitoring
  }
}

# =============================================================================
# Task 61.11: Multi-Environment Domain Management and Testing Outputs
# =============================================================================


output "environment_certificates" {
  description = "SSL certificates for each environment"
  value = var.enable_multi_environment ? {
    for env_key, cert in google_certificate_manager_certificate.environment_certificates : env_key => {
      certificate_id   = cert.id
      certificate_name = cert.name
      domains         = cert.managed[0].domains
      state           = cert.managed[0].state
      provisioning_issue = cert.managed[0].provisioning_issue
    }
  } : {}
}

output "environment_domain_mappings" {
  description = "Cloud Run domain mappings for each environment"
  value = var.enable_multi_environment && var.enable_cloud_run_integration ? {
    for mapping_key, mapping in google_cloud_run_domain_mapping.environment_domain_mappings : mapping_key => {
      domain_mapping_id = mapping.id
      name             = mapping.name
      location         = mapping.location
      status           = mapping.status
      url              = mapping.status[0].url
      resource_records = mapping.status[0].resource_records
    }
  } : {}
}

output "environment_security_policies" {
  description = "Security policies for environment isolation"
  value = var.enable_multi_environment ? {
    for env_key, policy in google_compute_security_policy.environment_security_policies : env_key => {
      policy_id           = policy.id
      policy_name         = policy.name
      rule_count         = length(policy.rule)
      adaptive_protection = policy.adaptive_protection_config[0].layer_7_ddos_defense_config[0].enable
      fingerprint        = policy.fingerprint
    }
  } : {}
}

output "environment_health_checks" {
  description = "Health checks for each environment"
  value = var.enable_multi_environment ? {
    for env_key, health_check in google_compute_health_check.environment_health_checks : env_key => {
      health_check_id   = health_check.id
      health_check_name = health_check.name
      check_interval    = health_check.check_interval_sec
      timeout          = health_check.timeout_sec
      healthy_threshold = health_check.healthy_threshold
      unhealthy_threshold = health_check.unhealthy_threshold
    }
  } : {}
}

output "environment_testing_function" {
  description = "Environment testing Cloud Function details"
  value = var.enable_multi_environment && var.enable_environment_testing ? {
    function_id    = google_cloudfunctions2_function.environment_testing[0].id
    function_name  = google_cloudfunctions2_function.environment_testing[0].name
    function_url   = google_cloudfunctions2_function.environment_testing[0].service_config[0].uri
    trigger_topic  = google_pubsub_topic.environment_testing_trigger[0].name
    schedule       = google_cloud_scheduler_job.environment_testing_schedule[0].schedule
    service_account = google_service_account.environment_testing_sa[0].email
  } : null
}

output "environment_testing_schedule" {
  description = "Environment testing schedule configuration"
  value = var.enable_multi_environment && var.enable_environment_testing ? {
    schedule_name = google_cloud_scheduler_job.environment_testing_schedule[0].name
    cron_schedule = google_cloud_scheduler_job.environment_testing_schedule[0].schedule
    timezone     = google_cloud_scheduler_job.environment_testing_schedule[0].time_zone
    topic_name   = google_pubsub_topic.environment_testing_trigger[0].name
    notification_email = var.environment_testing_notification_email
  } : null
}

output "environment_dns_records" {
  description = "DNS records for each environment"
  value = var.enable_multi_environment ? {
    a_records = {
      for record_key, record in google_dns_record_set.environment_a_records : record_key => {
        name         = record.name
        type         = record.type
        ttl          = record.ttl
        rrdatas      = record.rrdatas
        managed_zone = record.managed_zone
      }
    }
    cname_records = {
      for record_key, record in google_dns_record_set.environment_cname_records : record_key => {
        name         = record.name
        type         = record.type
        ttl          = record.ttl
        rrdatas      = record.rrdatas
        managed_zone = record.managed_zone
      }
    }
  } : { a_records = {}, cname_records = {} }
}

output "environment_isolation_summary" {
  description = "Summary of environment isolation and configuration"
  value = var.enable_multi_environment ? {
    environments_configured = keys(var.environment_configs)
    total_environments     = length(var.environment_configs)
    testing_enabled       = var.enable_environment_testing
    security_policies     = length(google_compute_security_policy.environment_security_policies)
    health_checks        = length(google_compute_health_check.environment_health_checks)
    
    isolation_features = {
      separate_dns_zones    = true
      environment_certificates = true
      security_policies    = true
      access_control      = true
      health_monitoring   = true
      automated_testing   = var.enable_environment_testing
    }
    
    compliance_status = {
      environment_separation = true
      access_restrictions   = length([for config in var.environment_configs : config if length(config.allowed_ip_ranges) > 0]) > 0
      rate_limiting        = true
      adaptive_protection  = length([for config in var.environment_configs : config if config.enable_adaptive_protection]) > 0
      health_monitoring    = true
    }
  } : {
    environments_configured = []
    total_environments     = 0
    testing_enabled       = false
    security_policies     = 0
    health_checks        = 0
    isolation_features    = {}
    compliance_status     = {}
  }
}