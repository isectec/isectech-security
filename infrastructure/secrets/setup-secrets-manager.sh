#!/bin/bash

# iSECTECH Secrets Manager Setup Script
# Production-grade secret management for Google Cloud Secret Manager
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"  
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check if authenticated
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable Secret Manager API
    log_info "Enabling Secret Manager API..."
    gcloud services enable secretmanager.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Generate secure random password
generate_secure_password() {
    local length=${1:-32}
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# Generate JWT secret
generate_jwt_secret() {
    openssl rand -base64 64 | tr -d "\n"
}

# Generate API key
generate_api_key() {
    openssl rand -hex 32
}

# Create secret with proper labels and annotations
create_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local description="$3"
    local category="$4"
    local rotation_period="${5:-2592000}" # 30 days default
    
    log_info "Creating secret: ${secret_name}"
    
    # Create the secret
    echo -n "$secret_value" | gcloud secrets create "$secret_name" \
        --replication-policy="automatic" \
        --data-file=- \
        --labels="environment=${ENVIRONMENT},category=${category},managed-by=isectech-platform" || {
        log_warning "Secret ${secret_name} may already exist, updating..."
        echo -n "$secret_value" | gcloud secrets versions add "$secret_name" --data-file=-
    }
    
    # Add annotations for metadata
    gcloud secrets update "$secret_name" \
        --update-annotations="description=${description},rotation-period=${rotation_period},created-by=setup-script,last-updated=$(date -Iseconds)"
    
    log_success "Secret ${secret_name} created/updated successfully"
}

# Database secrets
setup_database_secrets() {
    log_info "Setting up database secrets..."
    
    # PostgreSQL secrets
    local postgres_password=$(generate_secure_password 32)
    create_secret "isectech-postgres-password" "$postgres_password" "PostgreSQL database password for main application database" "database"
    create_secret "isectech-postgres-user" "isectech" "PostgreSQL database username" "database"
    create_secret "isectech-postgres-database" "isectech" "PostgreSQL database name" "database"
    
    # MongoDB secrets
    local mongodb_password=$(generate_secure_password 32)
    create_secret "isectech-mongodb-password" "$mongodb_password" "MongoDB database password for document storage" "database"
    create_secret "isectech-mongodb-user" "isectech" "MongoDB database username" "database"
    create_secret "isectech-mongodb-database" "isectech" "MongoDB database name" "database"
    
    # Redis secrets
    local redis_password=$(generate_secure_password 32)
    create_secret "isectech-redis-password" "$redis_password" "Redis password for caching and sessions" "database"
    
    # ClickHouse secrets (for analytics)
    local clickhouse_password=$(generate_secure_password 32)
    create_secret "isectech-clickhouse-password" "$clickhouse_password" "ClickHouse password for analytics database" "database"
    create_secret "isectech-clickhouse-user" "isectech" "ClickHouse database username" "database"
    create_secret "isectech-clickhouse-database" "isectech_analytics" "ClickHouse database name" "database"
    
    log_success "Database secrets configured"
}

# Authentication secrets
setup_authentication_secrets() {
    log_info "Setting up authentication secrets..."
    
    # NextAuth secret
    local nextauth_secret=$(generate_jwt_secret)
    create_secret "isectech-nextauth-secret" "$nextauth_secret" "NextAuth session secret for frontend authentication" "authentication"
    
    # JWT signing keys
    local jwt_access_secret=$(generate_jwt_secret)
    local jwt_refresh_secret=$(generate_jwt_secret)
    create_secret "isectech-jwt-access-secret" "$jwt_access_secret" "JWT access token signing secret" "authentication"
    create_secret "isectech-jwt-refresh-secret" "$jwt_refresh_secret" "JWT refresh token signing secret" "authentication"
    
    # Service-to-service authentication
    local service_api_key=$(generate_api_key)
    create_secret "isectech-service-api-key" "$service_api_key" "Inter-service API authentication key" "authentication"
    
    # Session encryption key
    local session_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-session-encryption-key" "$session_encryption_key" "Session data encryption key" "authentication"
    
    log_success "Authentication secrets configured"
}

# OAuth provider secrets (placeholders - to be updated with real values)
setup_oauth_secrets() {
    log_info "Setting up OAuth provider secrets..."
    
    # Google OAuth
    create_secret "isectech-google-oauth-client-id" "PLACEHOLDER_GOOGLE_CLIENT_ID" "Google OAuth client ID" "oauth"
    create_secret "isectech-google-oauth-secret" "PLACEHOLDER_GOOGLE_CLIENT_SECRET" "Google OAuth client secret" "oauth"
    
    # Microsoft OAuth
    create_secret "isectech-microsoft-oauth-client-id" "PLACEHOLDER_MICROSOFT_CLIENT_ID" "Microsoft OAuth client ID" "oauth"
    create_secret "isectech-microsoft-oauth-secret" "PLACEHOLDER_MICROSOFT_CLIENT_SECRET" "Microsoft OAuth client secret" "oauth"
    
    # Okta OAuth
    create_secret "isectech-okta-oauth-client-id" "PLACEHOLDER_OKTA_CLIENT_ID" "Okta OAuth client ID" "oauth"
    create_secret "isectech-okta-oauth-secret" "PLACEHOLDER_OKTA_CLIENT_SECRET" "Okta OAuth client secret" "oauth"
    create_secret "isectech-okta-issuer" "https://isectech.okta.com" "Okta OAuth issuer URL" "oauth"
    
    log_warning "OAuth secrets created with placeholders. Update with real values before deployment."
    log_success "OAuth provider secrets configured"
}

# External API keys and integrations
setup_external_api_keys() {
    log_info "Setting up external API keys..."
    
    # Threat Intelligence APIs
    create_secret "isectech-virustotal-api-key" "PLACEHOLDER_VIRUSTOTAL_API_KEY" "VirusTotal API key for malware analysis" "threat-intelligence"
    create_secret "isectech-recorded-future-api-key" "PLACEHOLDER_RECORDED_FUTURE_API_KEY" "Recorded Future API key for threat intelligence" "threat-intelligence"
    create_secret "isectech-misp-api-key" "PLACEHOLDER_MISP_API_KEY" "MISP API key for threat sharing" "threat-intelligence"
    
    # Security Tools
    create_secret "isectech-nessus-api-key" "PLACEHOLDER_NESSUS_API_KEY" "Nessus API key for vulnerability scanning" "security-tools"
    create_secret "isectech-openvas-password" "PLACEHOLDER_OPENVAS_PASSWORD" "OpenVAS password for vulnerability scanning" "security-tools"
    create_secret "isectech-qualys-api-key" "PLACEHOLDER_QUALYS_API_KEY" "Qualys API key for vulnerability management" "security-tools"
    
    # SIEM/SOAR Integrations
    create_secret "isectech-splunk-hec-token" "PLACEHOLDER_SPLUNK_HEC_TOKEN" "Splunk HTTP Event Collector token" "siem"
    create_secret "isectech-elastic-password" "PLACEHOLDER_ELASTIC_PASSWORD" "Elasticsearch password for log aggregation" "siem"
    create_secret "isectech-phantom-auth-token" "PLACEHOLDER_PHANTOM_AUTH_TOKEN" "Phantom SOAR authentication token" "soar"
    create_secret "isectech-demisto-api-key" "PLACEHOLDER_DEMISTO_API_KEY" "Demisto SOAR API key" "soar"
    
    # Communication & Notifications
    create_secret "isectech-smtp-password" "PLACEHOLDER_SMTP_PASSWORD" "SMTP password for email notifications" "communication"
    create_secret "isectech-slack-bot-token" "PLACEHOLDER_SLACK_BOT_TOKEN" "Slack bot token for notifications" "communication"
    create_secret "isectech-twilio-auth-token" "PLACEHOLDER_TWILIO_AUTH_TOKEN" "Twilio authentication token for SMS" "communication"
    create_secret "isectech-pagerduty-integration-key" "PLACEHOLDER_PAGERDUTY_KEY" "PagerDuty integration key for alerts" "communication"
    
    # Monitoring & Analytics
    create_secret "isectech-sentry-dsn" "PLACEHOLDER_SENTRY_DSN" "Sentry DSN for error tracking" "monitoring"
    create_secret "isectech-newrelic-license-key" "PLACEHOLDER_NEWRELIC_KEY" "New Relic license key for APM" "monitoring"
    create_secret "isectech-google-analytics-id" "PLACEHOLDER_GA_ID" "Google Analytics tracking ID" "analytics"
    create_secret "isectech-mixpanel-token" "PLACEHOLDER_MIXPANEL_TOKEN" "Mixpanel analytics token" "analytics"
    
    # Cloud Services
    create_secret "isectech-google-maps-api-key" "PLACEHOLDER_GOOGLE_MAPS_KEY" "Google Maps API key for geolocation" "cloud-services"
    create_secret "isectech-mapbox-access-token" "PLACEHOLDER_MAPBOX_TOKEN" "Mapbox access token for mapping" "cloud-services"
    create_secret "isectech-s3-access-key" "PLACEHOLDER_S3_ACCESS_KEY" "AWS S3 access key for storage" "cloud-services"
    create_secret "isectech-s3-secret-key" "PLACEHOLDER_S3_SECRET_KEY" "AWS S3 secret key for storage" "cloud-services"
    
    log_warning "External API keys created with placeholders. Update with real values before deployment."
    log_success "External API keys configured"
}

# Infrastructure secrets
setup_infrastructure_secrets() {
    log_info "Setting up infrastructure secrets..."
    
    # Kong API Gateway
    local kong_postgres_password=$(generate_secure_password 32)
    create_secret "isectech-kong-postgres-password" "$kong_postgres_password" "Kong PostgreSQL database password" "infrastructure"
    
    # Service mesh authentication
    local service_mesh_ca_key=$(openssl genrsa 4096 2>/dev/null | base64 -w 0)
    create_secret "isectech-service-mesh-ca-key" "$service_mesh_ca_key" "Service mesh CA private key" "infrastructure"
    
    # Consul encryption
    local consul_encrypt_key=$(consul keygen 2>/dev/null || openssl rand -base64 32)
    create_secret "isectech-consul-encrypt-key" "$consul_encrypt_key" "Consul gossip encryption key" "infrastructure"
    
    # Kafka SASL credentials
    local kafka_sasl_password=$(generate_secure_password 32)
    create_secret "isectech-kafka-sasl-username" "isectech" "Kafka SASL username" "infrastructure"
    create_secret "isectech-kafka-sasl-password" "$kafka_sasl_password" "Kafka SASL password" "infrastructure"
    
    # Backup encryption
    local backup_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-backup-encryption-key" "$backup_encryption_key" "Backup data encryption key" "infrastructure"
    
    log_success "Infrastructure secrets configured"
}

# Encryption keys for data protection
setup_encryption_keys() {
    log_info "Setting up encryption keys..."
    
    # Application-level encryption keys
    local app_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-app-encryption-key" "$app_encryption_key" "Application data encryption key" "encryption"
    
    # PII encryption key
    local pii_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-pii-encryption-key" "$pii_encryption_key" "PII data encryption key" "encryption"
    
    # Log encryption key
    local log_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-log-encryption-key" "$log_encryption_key" "Log data encryption key" "encryption"
    
    # Asset discovery encryption key
    local asset_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-asset-discovery-encryption-key" "$asset_encryption_key" "Asset discovery data encryption key" "encryption"
    
    # Network monitoring encryption key
    local nsm_encryption_key=$(generate_secure_password 32)
    create_secret "isectech-nsm-encryption-key" "$nsm_encryption_key" "Network security monitoring encryption key" "encryption"
    
    log_success "Encryption keys configured"
}

# Environment-specific secrets
setup_environment_secrets() {
    log_info "Setting up environment-specific secrets..."
    
    # Environment identifier
    create_secret "isectech-environment" "$ENVIRONMENT" "Current deployment environment" "environment"
    
    # Database connection strings (will be constructed from individual components)
    local postgres_conn="postgresql://isectech:$(gcloud secrets versions access latest --secret=isectech-postgres-password)@localhost:5432/isectech"
    local mongodb_conn="mongodb://isectech:$(gcloud secrets versions access latest --secret=isectech-mongodb-password)@localhost:27017/isectech"
    local redis_conn="redis://:$(gcloud secrets versions access latest --secret=isectech-redis-password)@localhost:6379"
    
    # Note: These will be updated with actual Cloud SQL/managed service URLs in production
    create_secret "isectech-postgres-connection-string" "PLACEHOLDER_POSTGRES_URL" "PostgreSQL connection string" "database"
    create_secret "isectech-mongodb-connection-string" "PLACEHOLDER_MONGODB_URL" "MongoDB connection string" "database"
    create_secret "isectech-redis-connection-string" "PLACEHOLDER_REDIS_URL" "Redis connection string" "database"
    create_secret "isectech-clickhouse-connection-string" "PLACEHOLDER_CLICKHOUSE_URL" "ClickHouse connection string" "database"
    
    log_success "Environment-specific secrets configured"
}

# Generate summary report
generate_summary_report() {
    log_info "Generating secrets summary report..."
    
    local report_file="/tmp/isectech-secrets-summary-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Secrets Manager Summary Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}

================================
SECRETS CREATED/UPDATED
================================

EOF
    
    # List all secrets with labels
    gcloud secrets list --filter="labels.managed-by=isectech-platform" --format="table(
        name:label=SECRET_NAME,
        labels.category:label=CATEGORY,
        createTime.date('%Y-%m-%d %H:%M:%S'):label=CREATED,
        annotations.description:label=DESCRIPTION
    )" >> "$report_file"
    
    cat >> "$report_file" << EOF

================================
NEXT STEPS
================================

Database Secrets:
- Update Cloud SQL connection strings with actual instance URLs
- Configure automatic backups for database credentials
- Set up database credential rotation policies

OAuth Secrets:
- Replace placeholder OAuth client IDs and secrets with real provider credentials
- Configure OAuth application redirects in provider consoles
- Test OAuth flows in staging environment

External API Keys:
- Obtain real API keys from threat intelligence providers
- Configure API rate limits and usage monitoring
- Set up API key rotation schedules

Infrastructure:
- Deploy generated CA keys to service mesh
- Configure Consul with encryption keys
- Set up monitoring for secret access patterns

Security:
- Review and audit all secret access permissions
- Configure secret rotation policies (recommended: 30-90 days)
- Set up alerts for secret access anomalies
- Implement secret scanning in CI/CD pipelines

================================
SECURITY REMINDERS
================================

1. Never log or expose secret values in plain text
2. Rotate all secrets regularly (recommended schedule included in annotations)
3. Monitor secret access logs for anomalies
4. Use least privilege access for all service accounts
5. Enable audit logging for all secret operations
6. Test secret rotation procedures regularly
7. Maintain an incident response plan for compromised secrets

EOF
    
    log_success "Summary report generated: $report_file"
    log_info "Please review the report and complete the next steps before production deployment."
}

# Main execution
main() {
    log_info "Starting iSECTECH Secrets Manager setup..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    check_prerequisites
    
    setup_database_secrets
    setup_authentication_secrets  
    setup_oauth_secrets
    setup_external_api_keys
    setup_infrastructure_secrets
    setup_encryption_keys
    setup_environment_secrets
    
    generate_summary_report
    
    log_success "iSECTECH Secrets Manager setup completed successfully!"
    log_info "Total secrets created: $(gcloud secrets list --filter='labels.managed-by=isectech-platform' --format='value(name)' | wc -l)"
    
    echo ""
    log_warning "IMPORTANT: Update placeholder values with real credentials before production deployment!"
    log_info "Run './setup-iam-secret-access.sh' next to configure service account permissions."
}

# Execute main function
main "$@"