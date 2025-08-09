# iSECTECH DNS Management Module Variables
# Production-grade DNS configuration variables
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 1.0.0

# ═══════════════════════════════════════════════════════════════════════════════
# CORE PROJECT CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "project_id" {
  description = "Google Cloud Project ID for DNS resources"
  type        = string
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must be a valid Google Cloud project ID."
  }
}

variable "environment" {
  description = "Environment name (development, staging, production)"
  type        = string
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be one of: development, staging, production."
  }
}

variable "region" {
  description = "Google Cloud region for DNS resources"
  type        = string
  default     = "us-central1"
}

variable "labels" {
  description = "Labels to apply to all DNS resources"
  type        = map(string)
  default     = {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS ZONE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "base_domain" {
  description = "Base domain for iSECTECH (e.g., isectech.org)"
  type        = string
  default     = "isectech.org"
  
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]*[a-z0-9]\\.[a-z]{2,}$", var.base_domain))
    error_message = "Base domain must be a valid domain name."
  }
}

variable "create_environment_zones" {
  description = "Whether to create separate managed zones for each subdomain"
  type        = bool
  default     = true
}

variable "enable_private_zones" {
  description = "Enable private DNS zones for internal resolution"
  type        = bool
  default     = false
}

variable "vpc_network_id" {
  description = "VPC network ID for private DNS zones"
  type        = string
  default     = ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# DNS POLICY AND SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_dns_logging" {
  description = "Enable DNS query logging for security monitoring"
  type        = bool
  default     = true
}

variable "enable_dns_forwarding" {
  description = "Enable inbound DNS forwarding for hybrid environments"
  type        = bool
  default     = false
}

variable "enable_dnssec" {
  description = "Enable DNSSEC for enhanced security"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN VERIFICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "google_site_verification_code" {
  description = "Google Search Console verification code"
  type        = string
  default     = ""
  sensitive   = true
}

variable "microsoft_domain_verification_code" {
  description = "Microsoft domain verification code"
  type        = string
  default     = ""
  sensitive   = true
}

variable "custom_verification_code" {
  description = "Custom domain verification code for iSECTECH"
  type        = string
  default     = ""
  sensitive   = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "dkim_selectors" {
  description = "DKIM selector records for email authentication"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "spf_record" {
  description = "SPF record for email security"
  type        = string
  default     = "v=spf1 include:_spf.google.com ~all"
}

variable "dmarc_policy" {
  description = "DMARC policy configuration"
  type        = string
  default     = "v=DMARC1; p=quarantine; rua=mailto:dmarc@isectech.org; ruf=mailto:forensic@isectech.org; fo=1"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND ALERTING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_dns_monitoring" {
  description = "Enable DNS monitoring and alerting"
  type        = bool
  default     = true
}

variable "notification_channels" {
  description = "List of notification channels for DNS alerts"
  type        = list(string)
  default     = []
}

variable "dns_query_threshold_production" {
  description = "DNS query volume threshold for production alerts"
  type        = number
  default     = 10000
}

variable "dns_query_threshold_nonproduction" {
  description = "DNS query volume threshold for non-production alerts"
  type        = number
  default     = 1000
}

variable "dns_failure_threshold" {
  description = "DNS resolution failure threshold for alerts"
  type        = number
  default     = 50
}

variable "dns_health_notification_email" {
  description = "Email address for DNS health check notifications"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for DNS health notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_dns_failover" {
  description = "Enable DNS failover mechanisms for high availability"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "certificate_domains" {
  description = "List of domains for SSL certificate provisioning"
  type        = list(string)
  default     = []
}

variable "enable_certificate_transparency" {
  description = "Enable Certificate Transparency logging"
  type        = bool
  default     = true
}

variable "certificate_renewal_buffer_days" {
  description = "Days before expiration to trigger renewal alerts"
  type        = number
  default     = 30
  
  validation {
    condition     = var.certificate_renewal_buffer_days >= 7 && var.certificate_renewal_buffer_days <= 90
    error_message = "Certificate renewal buffer must be between 7 and 90 days."
  }
}

variable "enable_certificate_manager" {
  description = "Enable Google Certificate Manager for SSL certificate provisioning"
  type        = bool
  default     = true
}

variable "enable_wildcard_certificate" {
  description = "Enable wildcard SSL certificate for subdomains"
  type        = bool
  default     = true
}

variable "enable_certificate_monitoring" {
  description = "Enable SSL certificate monitoring and alerting"
  type        = bool
  default     = true
}

variable "certificate_notification_email" {
  description = "Email address for SSL certificate notifications"
  type        = string
  default     = ""
}

variable "create_certificate_dashboard" {
  description = "Create monitoring dashboard for SSL certificates"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS AND CERTIFICATE PINNING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_security_headers" {
  description = "Enable HTTP security headers and related security policies"
  type        = bool
  default     = true
}

variable "enable_certificate_pinning" {
  description = "Enable certificate pinning via HPKP and DANE TLSA records"
  type        = bool
  default     = true
}

variable "content_security_policy" {
  description = "Content Security Policy (CSP) header value"
  type        = string
  default     = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://www.google.com https://ssl.gstatic.com https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https: blob:; connect-src 'self' https://api.isectech.org https://app.isectech.org wss://ws.isectech.org; frame-src 'self' https://www.google.com; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests"
}

variable "permissions_policy" {
  description = "Permissions Policy header value for browser feature control"
  type        = string
  default     = "geolocation=(), microphone=(), camera=(), fullscreen=(self), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), autoplay=(self), encrypted-media=(self), picture-in-picture=(), display-capture=()"
}

variable "certificate_pins" {
  description = "HTTP Public Key Pinning (HPKP) certificate pins"
  type        = string
  default     = "pin-sha256=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"; pin-sha256=\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\"; max-age=2592000; includeSubDomains; report-uri=\"https://isectech.report-uri.org/r/d/hpkp/enforce\""
  sensitive   = true
}

variable "backup_certificate_pins" {
  description = "Backup certificate pins for HPKP rotation"
  type        = string
  default     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  sensitive   = true
}

variable "tlsa_records" {
  description = "DANE TLSA records for certificate pinning by domain"
  type        = map(list(string))
  default     = {}
  sensitive   = true
}

variable "default_tlsa_hash" {
  description = "Default TLSA hash for domains without specific TLSA records"
  type        = string
  default     = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  sensitive   = true
}

variable "acme_account_id" {
  description = "ACME account ID for Let's Encrypt certificate authorization"
  type        = string
  default     = ""
  sensitive   = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CERTIFICATE TRANSPARENCY AND ROTATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_certificate_rotation_automation" {
  description = "Enable automated certificate rotation procedures and monitoring"
  type        = bool
  default     = true
}

variable "certificate_transparency_logs" {
  description = "List of Certificate Transparency log servers to submit certificates to"
  type        = list(string)
  default     = [
    "google-pilot",
    "google-rocketeer", 
    "cloudflare-nimbus",
    "digicert-ct1",
    "digicert-ct2",
    "lets-encrypt-ct1",
    "lets-encrypt-ct2"
  ]
}

variable "certificate_rotation_check_schedule" {
  description = "Cron schedule for automated certificate rotation checks"
  type        = string
  default     = "0 2 * * *"  # Daily at 2 AM
}

variable "certificate_rotation_lead_time_days" {
  description = "Number of days before expiration to trigger certificate rotation"
  type        = number
  default     = 30
  
  validation {
    condition     = var.certificate_rotation_lead_time_days >= 7 && var.certificate_rotation_lead_time_days <= 60
    error_message = "Certificate rotation lead time must be between 7 and 60 days."
  }
}

variable "ct_log_submission_timeout" {
  description = "Timeout in seconds for Certificate Transparency log submissions"
  type        = number
  default     = 30
}

variable "enable_automated_pin_rotation" {
  description = "Enable automated HPKP pin rotation during certificate renewal"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD RUN INTEGRATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "cloud_run_services" {
  description = "Map of domains to Cloud Run service configurations"
  type = map(object({
    service_name = string
    region       = string
    traffic_allocation = optional(number, 100)
  }))
  default = {}
}

variable "enable_cloud_run_mapping" {
  description = "Enable automatic Cloud Run domain mapping"
  type        = bool
  default     = true
}

# ═══════════════════════════════════════════════════════════════════════════════
# BACKUP AND DISASTER RECOVERY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "enable_dns_backup" {
  description = "Enable DNS configuration backup"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain DNS configuration backups"
  type        = number
  default     = 90
  
  validation {
    condition     = var.backup_retention_days >= 30 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 30 and 365 days."
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE OPTIMIZATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "dns_cache_ttl" {
  description = "Default TTL for DNS records in seconds"
  type        = number
  default     = 300
  
  validation {
    condition     = var.dns_cache_ttl >= 60 && var.dns_cache_ttl <= 86400
    error_message = "DNS TTL must be between 60 seconds and 24 hours."
  }
}

variable "enable_geo_routing" {
  description = "Enable geographic routing for global performance"
  type        = bool
  default     = false
}

variable "geo_routing_policies" {
  description = "Geographic routing policies for DNS resolution"
  type = map(object({
    location = string
    rrdatas  = list(string)
  }))
  default = {}
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPLIANCE AND SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "ISO27001", "GDPR", "HIPAA"]
}

variable "enable_audit_logging" {
  description = "Enable comprehensive audit logging for DNS operations"
  type        = bool
  default     = true
}

variable "data_residency_regions" {
  description = "Regions where DNS data must reside for compliance"
  type        = list(string)
  default     = ["us-central1", "us-east1"]
}

# =============================================================================
# Task 61.11: Multi-Environment Domain Management and Testing Variables
# =============================================================================

variable "enable_multi_environment" {
  description = "Enable multi-environment domain management and testing"
  type        = bool
  default     = false
}

variable "environment_configs" {
  description = "Configuration for each environment (staging, development, etc.)"
  type = map(object({
    certificate_domains = list(string)
    allowed_ip_ranges   = list(string)
    rate_limit_requests_per_minute = number
    rate_limit_ban_duration_sec    = number
    enable_adaptive_protection     = bool
    
    a_records = list(object({
      name    = string
      ttl     = number
      rrdatas = list(string)
    }))
    
    cname_records = list(object({
      name    = string
      ttl     = number
      rrdatas = list(string)
    }))
    
    cloud_run_mappings = list(object({
      domain         = string
      service_name   = string
      region         = string
      ingress        = string
      force_override = bool
    }))
    
    health_check_timeout_sec        = number
    health_check_interval_sec       = number
    health_check_healthy_threshold  = number
    health_check_unhealthy_threshold = number
    health_check_port               = number
    health_check_path               = string
    health_check_host               = string
    health_check_response           = string
  }))
  default = {
    staging = {
      certificate_domains = ["api", "app", "admin"]
      allowed_ip_ranges   = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      rate_limit_requests_per_minute = 1000
      rate_limit_ban_duration_sec    = 300
      enable_adaptive_protection     = true
      
      a_records = [
        {
          name    = "api"
          ttl     = 300
          rrdatas = ["34.102.136.180"]
        }
      ]
      
      cname_records = [
        {
          name    = "app"
          ttl     = 300
          rrdatas = ["staging-app.isectech.org."]
        }
      ]
      
      cloud_run_mappings = [
        {
          domain         = "api"
          service_name   = "isectech-api-staging"
          region         = "us-central1"
          ingress        = "INGRESS_TRAFFIC_INTERNAL_ONLY"
          force_override = false
        }
      ]
      
      health_check_timeout_sec        = 10
      health_check_interval_sec       = 30
      health_check_healthy_threshold  = 2
      health_check_unhealthy_threshold = 3
      health_check_port               = 8080
      health_check_path               = "/health"
      health_check_host               = "api"
      health_check_response           = "OK"
    }
    
    development = {
      certificate_domains = ["api", "app"]
      allowed_ip_ranges   = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      rate_limit_requests_per_minute = 500
      rate_limit_ban_duration_sec    = 600
      enable_adaptive_protection     = false
      
      a_records = [
        {
          name    = "api"
          ttl     = 300
          rrdatas = ["34.102.136.181"]
        }
      ]
      
      cname_records = [
        {
          name    = "app"
          ttl     = 300
          rrdatas = ["dev-app.isectech.org."]
        }
      ]
      
      cloud_run_mappings = [
        {
          domain         = "api"
          service_name   = "isectech-api-dev"
          region         = "us-central1"
          ingress        = "INGRESS_TRAFFIC_INTERNAL_ONLY"
          force_override = false
        }
      ]
      
      health_check_timeout_sec        = 15
      health_check_interval_sec       = 60
      health_check_healthy_threshold  = 2
      health_check_unhealthy_threshold = 5
      health_check_port               = 8080
      health_check_path               = "/health"
      health_check_host               = "api"
      health_check_response           = "OK"
    }
  }
}

variable "enable_environment_testing" {
  description = "Enable automated environment domain testing"
  type        = bool
  default     = false
}

variable "environment_testing_schedule" {
  description = "Cron schedule for environment testing (default: every 6 hours)"
  type        = string
  default     = "0 */6 * * *"
}

variable "environment_testing_timezone" {
  description = "Timezone for environment testing schedule"
  type        = string
  default     = "UTC"
}

variable "environment_testing_notification_email" {
  description = "Email address for environment testing notifications"
  type        = string
  default     = "devops@isectech.org"
}

variable "environment_testing_sendgrid_api_key" {
  description = "SendGrid API key for environment testing notifications"
  type        = string
  default     = ""
  sensitive   = true
}