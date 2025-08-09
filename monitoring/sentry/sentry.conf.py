# iSECTECH Sentry Configuration
# Production-grade error tracking and performance monitoring configuration

import os
from urllib.parse import urlparse

# ═══════════════════════════════════════════════════════════════════════════════
# BASIC CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'sentry.db.postgres',
        'NAME': os.getenv('SENTRY_DB_NAME', 'sentry'),
        'USER': os.getenv('SENTRY_DB_USER', 'sentry'),
        'PASSWORD': os.getenv('SENTRY_DB_PASSWORD', 'sentry_password'),
        'HOST': os.getenv('SENTRY_DB_HOST', 'postgres'),
        'PORT': os.getenv('SENTRY_DB_PORT', '5432'),
        'OPTIONS': {
            'autocommit': True,
        },
    }
}

# Cache configuration (Redis)
SENTRY_CACHE = 'sentry.cache.redis.RedisCache'
SENTRY_CACHE_OPTIONS = {
    'hosts': {
        0: {
            'host': os.getenv('SENTRY_REDIS_HOST', 'redis'),
            'port': int(os.getenv('SENTRY_REDIS_PORT', '6379')),
            'password': os.getenv('SENTRY_REDIS_PASSWORD', ''),
            'db': int(os.getenv('SENTRY_REDIS_DB', '0')),
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# WEB SERVER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SENTRY_WEB_HOST = '0.0.0.0'
SENTRY_WEB_PORT = 9000
SENTRY_WEB_OPTIONS = {
    'workers': int(os.getenv('SENTRY_WEB_WORKERS', '3')),
    'limit_request_line': 0,
    'limit_request_field_size': 0,
}

# URL configuration
SENTRY_URL_PREFIX = os.getenv('SENTRY_URL_PREFIX', 'https://sentry.isectech.com')
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_TLS = True

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Security settings
SECRET_KEY = os.getenv('SENTRY_SECRET_KEY', 'isectech_sentry_secret_key_change_in_production')
ALLOWED_HOSTS = [
    'sentry.isectech.com',
    'sentry.isectech.local',
    'localhost',
    '127.0.0.1',
    os.getenv('SENTRY_HOST', 'sentry'),
]

# Session configuration
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# ═══════════════════════════════════════════════════════════════════════════════
# EMAIL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.getenv('SENTRY_EMAIL_HOST', 'smtp.isectech.com')
EMAIL_PORT = int(os.getenv('SENTRY_EMAIL_PORT', '587'))
EMAIL_HOST_USER = os.getenv('SENTRY_EMAIL_USER', 'sentry@isectech.com')
EMAIL_HOST_PASSWORD = os.getenv('SENTRY_EMAIL_PASSWORD', '')
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
SERVER_EMAIL = EMAIL_HOST_USER
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
        'file': {
            'level': 'WARNING',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/var/log/sentry/sentry.log',
            'maxBytes': 50 * 1024 * 1024,  # 50 MB
            'backupCount': 5,
            'formatter': 'verbose'
        },
    },
    'root': {
        'level': 'WARNING',
        'handlers': ['console', 'file'],
    },
    'loggers': {
        'sentry': {
            'level': 'INFO',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
        'sentry.errors': {
            'level': 'WARNING',
            'handlers': ['console', 'file'],
            'propagate': False,
        },
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# PERFORMANCE AND SCALING
# ═══════════════════════════════════════════════════════════════════════════════

# Buffer configuration
SENTRY_BUFFER = 'sentry.buffer.redis.RedisBuffer'
SENTRY_BUFFER_OPTIONS = SENTRY_CACHE_OPTIONS

# Queue configuration
CELERY_BROKER_URL = f"redis://{os.getenv('SENTRY_REDIS_HOST', 'redis')}:{os.getenv('SENTRY_REDIS_PORT', '6379')}/1"
CELERY_RESULT_BACKEND = CELERY_BROKER_URL

# Rate limiting
SENTRY_RATELIMITER = 'sentry.ratelimits.redis.RedisRateLimiter'
SENTRY_RATELIMITER_OPTIONS = SENTRY_CACHE_OPTIONS

# Quotas
SENTRY_QUOTAS = 'sentry.quotas.redis.RedisQuota'
SENTRY_QUOTA_OPTIONS = SENTRY_CACHE_OPTIONS

# ═══════════════════════════════════════════════════════════════════════════════
# DATA RETENTION
# ═══════════════════════════════════════════════════════════════════════════════

# Event retention (in days)
SENTRY_EVENT_RETENTION_DAYS = int(os.getenv('SENTRY_EVENT_RETENTION_DAYS', '30'))

# File storage
SENTRY_FILESTORE = 'django.core.files.storage.FileSystemStorage'
SENTRY_FILESTORE_OPTIONS = {
    'location': '/var/lib/sentry/files',
}

# ═══════════════════════════════════════════════════════════════════════════════
# ISECTECH CUSTOM CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Organization configuration
SENTRY_SINGLE_ORGANIZATION = True
SENTRY_ORGANIZATION_NAME = 'iSECTECH'

# Feature flags for iSECTECH
SENTRY_FEATURES = {
    'organizations:discover': True,
    'organizations:events': True,
    'organizations:global-views': True,
    'organizations:performance-view': True,
    'organizations:performance-issues-dev': True,
    'organizations:transaction-comparison': True,
    'organizations:performance-tag-page': True,
    'organizations:performance-frontend-use-events-endpoint': True,
    'organizations:performance-landing-v3': True,
    'organizations:performance-change-explorer': True,
    'organizations:performance-new-trends': True,
    'organizations:performance-trace-details': True,
    'organizations:performance-trace-explorer': True,
    'organizations:profiling': True,
    'organizations:profiling-summary-redesign': True,
    'organizations:release-health-check-metrics': True,
    'organizations:dashboards-basic': True,
    'organizations:dashboards-edit': True,
    'organizations:custom-event-title': True,
    'organizations:alert-allow-indexed': True,
    'organizations:metric-alert-builder-aggregate': True,
    'organizations:incidents': True,
    'organizations:integrations-v3': True,
    'organizations:slack-overage-notifications': True,
    'organizations:notification-platform': True,
    'organizations:issue-platform': True,
    'organizations:reprocessing-v2': True,
    'organizations:grouping-stacktrace-ui': True,
    'organizations:grouping-tree-ui': True,
    'organizations:similarity-view': True,
    'organizations:similarity-view-v2': True,
    'organizations:symbol-sources': True,
    'organizations:custom-symbol-sources': True,
    'organizations:data-forwarding': True,
    'organizations:relay': True,
    'organizations:minute-resolution-sessions': True,
    'organizations:monitors': True,
    'organizations:user-feedback-ui': True,
}

# Custom project defaults for iSECTECH
SENTRY_PROJECT_DEFAULTS = {
    'platform': 'javascript',
    'default_environment': 'production',
    'resolve_age': 720,  # 30 days
    'scrub_data': True,
    'scrub_defaults': True,
    'sensitive_fields': [
        'password',
        'secret',
        'passwd',
        'api_key',
        'apikey',
        'auth',
        'credentials',
        'mysql_pwd',
        'privatekey',
        'private_key',
        'token',
        'session_id',
        'session',
        'sessionid',
        'ssn',
        'social_security_number',
        'credit_card',
        'card_number',
        'email',
        'user_email',
        'phone',
        'phone_number',
    ],
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'sentry.auth.providers.saml2.provider.SAML2Provider',  # SSO
    'django.contrib.auth.backends.ModelBackend',
]

# Session settings
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 3600 * 24 * 7  # 1 week

# ═══════════════════════════════════════════════════════════════════════════════
# INTEGRATION CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Slack integration
SLACK_CLIENT_ID = os.getenv('SENTRY_SLACK_CLIENT_ID', '')
SLACK_CLIENT_SECRET = os.getenv('SENTRY_SLACK_CLIENT_SECRET', '')
SLACK_VERIFICATION_TOKEN = os.getenv('SENTRY_SLACK_VERIFICATION_TOKEN', '')

# GitHub integration
GITHUB_APP_ID = os.getenv('SENTRY_GITHUB_APP_ID', '')
GITHUB_API_SECRET = os.getenv('SENTRY_GITHUB_API_SECRET', '')

# PagerDuty integration
PAGERDUTY_APP_ID = os.getenv('SENTRY_PAGERDUTY_APP_ID', '')

# ═══════════════════════════════════════════════════════════════════════════════
# MONITORING AND HEALTH CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

# Health check endpoint
SENTRY_SYSTEM_MAX_EVENTS_PER_MINUTE = 1000

# Metrics backend
SENTRY_METRICS_BACKEND = 'sentry.metrics.statsd.StatsdMetricsBackend'
SENTRY_METRICS_OPTIONS = {
    'host': os.getenv('STATSD_HOST', 'localhost'),
    'port': int(os.getenv('STATSD_PORT', '8125')),
    'prefix': 'sentry.',
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYMBOLICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Symbolicator configuration for native crash reports
SENTRY_SYMBOLICATOR_OPTIONS = {
    'url': 'http://symbolicator:3021',
}

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'sentry.middleware.proxy.ProxyMiddleware',
    'sentry.middleware.stats.RequestTimingMiddleware',
]

# CORS settings for frontend integration
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    "https://isectech.com",
    "https://www.isectech.com",
    "https://app.isectech.com",
    "http://localhost:3000",  # Development
]

CORS_ALLOW_CREDENTIALS = True
CORS_PREFLIGHT_MAX_AGE = 86400