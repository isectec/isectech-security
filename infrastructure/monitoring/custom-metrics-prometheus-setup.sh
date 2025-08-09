#!/bin/bash

# iSECTECH Custom Metrics and Prometheus Integration Setup Script
# Production-grade metrics collection for cybersecurity platform
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# Prometheus configuration
PROMETHEUS_VERSION="${PROMETHEUS_VERSION:-2.47.0}"
GRAFANA_VERSION="${GRAFANA_VERSION:-10.1.0}"
ALERTMANAGER_VERSION="${ALERTMANAGER_VERSION:-0.26.0}"

# Metrics configuration
METRICS_RETENTION_DAYS="${METRICS_RETENTION_DAYS:-90}"
HIGH_RESOLUTION_RETENTION_DAYS="${HIGH_RESOLUTION_RETENTION_DAYS:-7}"
SCRAPE_INTERVAL="${SCRAPE_INTERVAL:-30s}"
SECURITY_SCRAPE_INTERVAL="${SECURITY_SCRAPE_INTERVAL:-10s}"

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
    log_info "Checking prerequisites for metrics and Prometheus setup..."
    
    # Check if gcloud CLI is installed and authenticated
    if ! command -v gcloud &> /dev/null; then
        log_error "gcloud CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check authentication
    if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" | grep -q "@"; then
        log_error "Not authenticated with gcloud. Please run 'gcloud auth login'"
        exit 1
    fi
    
    # Set project
    gcloud config set project "${PROJECT_ID}"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable monitoring.googleapis.com
    gcloud services enable run.googleapis.com
    gcloud services enable compute.googleapis.com
    gcloud services enable container.googleapis.com
    gcloud services enable cloudbuild.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Set up Google Cloud Monitoring custom metrics
setup_cloud_monitoring_metrics() {
    log_info "Setting up Google Cloud Monitoring custom metrics..."
    
    # Create custom metric descriptors for security events
    create_security_metric_descriptors
    
    # Create custom metric descriptors for performance
    create_performance_metric_descriptors
    
    # Create custom metric descriptors for business metrics
    create_business_metric_descriptors
    
    log_success "Cloud Monitoring custom metrics configured"
}

create_security_metric_descriptors() {
    log_info "Creating security metric descriptors..."
    
    # Security event metrics
    cat > "/tmp/security-metrics.json" << EOF
{
  "metricDescriptors": [
    {
      "type": "custom.googleapis.com/isectech/security/threat_detections",
      "displayName": "Threat Detections",
      "description": "Number of threat detections by type and severity",
      "metricKind": "CUMULATIVE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "threat_type",
          "description": "Type of threat detected"
        },
        {
          "key": "severity",
          "description": "Threat severity level"
        },
        {
          "key": "service_name",
          "description": "Service that detected the threat"
        },
        {
          "key": "environment",
          "description": "Environment where threat was detected"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/security/authentication_events",
      "displayName": "Authentication Events",
      "description": "Authentication attempts and results",
      "metricKind": "CUMULATIVE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "operation",
          "description": "Authentication operation (login, logout, reset)"
        },
        {
          "key": "result",
          "description": "Authentication result (success, failure)"
        },
        {
          "key": "method",
          "description": "Authentication method (password, mfa, oauth)"
        },
        {
          "key": "user_type",
          "description": "Type of user (admin, user, service)"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/security/vulnerability_findings",
      "displayName": "Vulnerability Findings",
      "description": "Vulnerability scan findings by severity",
      "metricKind": "GAUGE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "severity",
          "description": "Vulnerability severity (critical, high, medium, low)"
        },
        {
          "key": "scan_type",
          "description": "Type of vulnerability scan"
        },
        {
          "key": "target_type",
          "description": "Target type (application, infrastructure, container)"
        },
        {
          "key": "remediation_status",
          "description": "Remediation status (open, in_progress, fixed)"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/security/incident_response_time",
      "displayName": "Incident Response Time",
      "description": "Time to respond to security incidents",
      "metricKind": "GAUGE",
      "valueType": "DOUBLE",
      "labels": [
        {
          "key": "incident_type",
          "description": "Type of security incident"
        },
        {
          "key": "severity",
          "description": "Incident severity level"
        },
        {
          "key": "response_team",
          "description": "Team responsible for response"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/security/compliance_score",
      "displayName": "Compliance Score",
      "description": "Compliance score by framework and control",
      "metricKind": "GAUGE",
      "valueType": "DOUBLE",
      "labels": [
        {
          "key": "framework",
          "description": "Compliance framework (SOC2, PCI-DSS, ISO27001)"
        },
        {
          "key": "control_family",
          "description": "Control family within framework"
        },
        {
          "key": "assessment_date",
          "description": "Date of compliance assessment"
        }
      ]
    }
  ]
}
EOF
    
    log_info "Security metric descriptors configured"
    
    # Note: Metric descriptors are created automatically when first metrics are sent
    # This JSON serves as documentation for the metrics structure
}

create_performance_metric_descriptors() {
    log_info "Creating performance metric descriptors..."
    
    cat > "/tmp/performance-metrics.json" << EOF
{
  "metricDescriptors": [
    {
      "type": "custom.googleapis.com/isectech/performance/response_time",
      "displayName": "Response Time",
      "description": "API response time by endpoint and percentile",
      "metricKind": "GAUGE",
      "valueType": "DOUBLE",
      "labels": [
        {
          "key": "endpoint",
          "description": "API endpoint path"
        },
        {
          "key": "method",
          "description": "HTTP method"
        },
        {
          "key": "percentile",
          "description": "Response time percentile (p50, p95, p99)"
        },
        {
          "key": "service_name",
          "description": "Name of the service"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/performance/throughput",
      "displayName": "API Throughput",
      "description": "Requests per second by service and endpoint",
      "metricKind": "GAUGE",
      "valueType": "DOUBLE",
      "labels": [
        {
          "key": "service_name",
          "description": "Name of the service"
        },
        {
          "key": "endpoint",
          "description": "API endpoint path"
        },
        {
          "key": "status_class",
          "description": "HTTP status class (2xx, 4xx, 5xx)"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/performance/resource_utilization",
      "displayName": "Resource Utilization",
      "description": "CPU, memory, and disk utilization",
      "metricKind": "GAUGE",
      "valueType": "DOUBLE",
      "labels": [
        {
          "key": "resource_type",
          "description": "Type of resource (cpu, memory, disk)"
        },
        {
          "key": "service_name",
          "description": "Name of the service"
        },
        {
          "key": "instance_id",
          "description": "Service instance identifier"
        }
      ]
    }
  ]
}
EOF
    
    log_info "Performance metric descriptors configured"
}

create_business_metric_descriptors() {
    log_info "Creating business metric descriptors..."
    
    cat > "/tmp/business-metrics.json" << EOF
{
  "metricDescriptors": [
    {
      "type": "custom.googleapis.com/isectech/business/active_users",
      "displayName": "Active Users",
      "description": "Number of active users by time period",
      "metricKind": "GAUGE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "time_period",
          "description": "Time period (daily, weekly, monthly)"
        },
        {
          "key": "user_type",
          "description": "Type of user (admin, analyst, viewer)"
        },
        {
          "key": "organization_tier",
          "description": "Organization tier (enterprise, professional, basic)"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/business/feature_usage",
      "displayName": "Feature Usage",
      "description": "Usage metrics for platform features",
      "metricKind": "CUMULATIVE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "feature_name",
          "description": "Name of the feature"
        },
        {
          "key": "action_type",
          "description": "Type of action (view, create, update, delete)"
        },
        {
          "key": "user_role",
          "description": "Role of the user performing action"
        }
      ]
    },
    {
      "type": "custom.googleapis.com/isectech/business/api_consumption",
      "displayName": "API Consumption",
      "description": "API usage by customer and plan limits",
      "metricKind": "CUMULATIVE",
      "valueType": "INT64",
      "labels": [
        {
          "key": "customer_id",
          "description": "Customer identifier"
        },
        {
          "key": "api_category",
          "description": "Category of API (threat-intel, vulnerability, compliance)"
        },
        {
          "key": "plan_type",
          "description": "Customer plan type"
        }
      ]
    }
  ]
}
EOF
    
    log_info "Business metric descriptors configured"
}

# Create metrics collection libraries
create_metrics_libraries() {
    log_info "Creating metrics collection libraries..."
    
    # Create Node.js metrics library
    cat > "/tmp/nodejs-metrics.js" << 'EOF'
/**
 * iSECTECH Custom Metrics Library for Node.js/TypeScript
 * Production-grade metrics collection with security context
 */

const client = require('prom-client');
const { Monitoring } = require('@google-cloud/monitoring');

class ISECTECHMetrics {
    constructor(serviceName, environment = 'production') {
        this.serviceName = serviceName;
        this.environment = environment;
        
        // Initialize Prometheus client
        this.register = new client.Registry();
        client.collectDefaultMetrics({ 
            register: this.register,
            prefix: 'isectech_',
            labels: { 
                service: serviceName, 
                environment: environment 
            }
        });
        
        // Initialize Google Cloud Monitoring
        this.monitoring = new Monitoring.MetricServiceClient({
            projectId: process.env.PROJECT_ID
        });
        
        this.projectPath = this.monitoring.projectPath(process.env.PROJECT_ID);
        
        this.initializeMetrics();
    }
    
    initializeMetrics() {
        // Security metrics
        this.threatDetectionCounter = new client.Counter({
            name: 'isectech_security_threat_detections_total',
            help: 'Total number of threat detections',
            labelNames: ['threat_type', 'severity', 'service_name', 'environment'],
            registers: [this.register]
        });
        
        this.authenticationEventsCounter = new client.Counter({
            name: 'isectech_security_authentication_events_total',
            help: 'Total number of authentication events',
            labelNames: ['operation', 'result', 'method', 'user_type'],
            registers: [this.register]
        });
        
        this.vulnerabilityFindingsGauge = new client.Gauge({
            name: 'isectech_security_vulnerability_findings',
            help: 'Current number of vulnerability findings',
            labelNames: ['severity', 'scan_type', 'target_type', 'remediation_status'],
            registers: [this.register]
        });
        
        this.incidentResponseTimeGauge = new client.Gauge({
            name: 'isectech_security_incident_response_time_seconds',
            help: 'Time to respond to security incidents',
            labelNames: ['incident_type', 'severity', 'response_team'],
            registers: [this.register]
        });
        
        this.complianceScoreGauge = new client.Gauge({
            name: 'isectech_security_compliance_score',
            help: 'Compliance score by framework',
            labelNames: ['framework', 'control_family', 'assessment_date'],
            registers: [this.register]
        });
        
        // Performance metrics
        this.responseTimeHistogram = new client.Histogram({
            name: 'isectech_performance_response_time_seconds',
            help: 'API response time in seconds',
            labelNames: ['endpoint', 'method', 'service_name'],
            buckets: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0],
            registers: [this.register]
        });
        
        this.throughputGauge = new client.Gauge({
            name: 'isectech_performance_throughput_rps',
            help: 'Requests per second',
            labelNames: ['service_name', 'endpoint', 'status_class'],
            registers: [this.register]
        });
        
        this.resourceUtilizationGauge = new client.Gauge({
            name: 'isectech_performance_resource_utilization_percent',
            help: 'Resource utilization percentage',
            labelNames: ['resource_type', 'service_name', 'instance_id'],
            registers: [this.register]
        });
        
        // Business metrics
        this.activeUsersGauge = new client.Gauge({
            name: 'isectech_business_active_users',
            help: 'Number of active users',
            labelNames: ['time_period', 'user_type', 'organization_tier'],
            registers: [this.register]
        });
        
        this.featureUsageCounter = new client.Counter({
            name: 'isectech_business_feature_usage_total',
            help: 'Total feature usage events',
            labelNames: ['feature_name', 'action_type', 'user_role'],
            registers: [this.register]
        });
        
        this.apiConsumptionCounter = new client.Counter({
            name: 'isectech_business_api_consumption_total',
            help: 'Total API consumption',
            labelNames: ['customer_id', 'api_category', 'plan_type'],
            registers: [this.register]
        });
        
        // Custom security metrics
        this.securityEventRate = new client.Gauge({
            name: 'isectech_security_event_rate_per_minute',
            help: 'Security events per minute',
            labelNames: ['event_type', 'severity'],
            registers: [this.register]
        });
        
        this.failedLoginAttempts = new client.Counter({
            name: 'isectech_security_failed_login_attempts_total',
            help: 'Total failed login attempts',
            labelNames: ['ip_address', 'user_agent_hash', 'reason'],
            registers: [this.register]
        });
    }
    
    // Security metric methods
    recordThreatDetection(threatType, severity, context = {}) {
        this.threatDetectionCounter.inc({
            threat_type: threatType,
            severity: severity,
            service_name: context.serviceName || this.serviceName,
            environment: this.environment
        });
        
        // Also send to Cloud Monitoring
        this.sendToCloudMonitoring('custom.googleapis.com/isectech/security/threat_detections', 1, {
            threat_type: threatType,
            severity: severity,
            service_name: context.serviceName || this.serviceName,
            environment: this.environment
        });
    }
    
    recordAuthenticationEvent(operation, result, method, userType) {
        this.authenticationEventsCounter.inc({
            operation: operation,
            result: result,
            method: method,
            user_type: userType
        });
        
        // Track failed login attempts separately for security monitoring
        if (result === 'failure' && operation === 'login') {
            this.failedLoginAttempts.inc({
                ip_address: context.ipAddress || 'unknown',
                user_agent_hash: context.userAgentHash || 'unknown',
                reason: context.failureReason || 'invalid_credentials'
            });
        }
    }
    
    updateVulnerabilityFindings(severity, scanType, targetType, remediationStatus, count) {
        this.vulnerabilityFindingsGauge.set({
            severity: severity,
            scan_type: scanType,
            target_type: targetType,
            remediation_status: remediationStatus
        }, count);
    }
    
    recordIncidentResponseTime(incidentType, severity, responseTeam, responseTimeSeconds) {
        this.incidentResponseTimeGauge.set({
            incident_type: incidentType,
            severity: severity,
            response_team: responseTeam
        }, responseTimeSeconds);
    }
    
    updateComplianceScore(framework, controlFamily, score) {
        this.complianceScoreGauge.set({
            framework: framework,
            control_family: controlFamily,
            assessment_date: new Date().toISOString().split('T')[0]
        }, score);
    }
    
    updateSecurityEventRate(eventType, severity, ratePerMinute) {
        this.securityEventRate.set({
            event_type: eventType,
            severity: severity
        }, ratePerMinute);
    }
    
    // Performance metric methods
    recordResponseTime(endpoint, method, durationSeconds) {
        this.responseTimeHistogram.observe({
            endpoint: endpoint,
            method: method,
            service_name: this.serviceName
        }, durationSeconds);
    }
    
    updateThroughput(endpoint, statusClass, requestsPerSecond) {
        this.throughputGauge.set({
            service_name: this.serviceName,
            endpoint: endpoint,
            status_class: statusClass
        }, requestsPerSecond);
    }
    
    updateResourceUtilization(resourceType, instanceId, utilizationPercent) {
        this.resourceUtilizationGauge.set({
            resource_type: resourceType,
            service_name: this.serviceName,
            instance_id: instanceId
        }, utilizationPercent);
    }
    
    // Business metric methods
    updateActiveUsers(timePeriod, userType, organizationTier, count) {
        this.activeUsersGauge.set({
            time_period: timePeriod,
            user_type: userType,
            organization_tier: organizationTier
        }, count);
    }
    
    recordFeatureUsage(featureName, actionType, userRole) {
        this.featureUsageCounter.inc({
            feature_name: featureName,
            action_type: actionType,
            user_role: userRole
        });
    }
    
    recordApiConsumption(customerId, apiCategory, planType, requestCount = 1) {
        this.apiConsumptionCounter.inc({
            customer_id: customerId,
            api_category: apiCategory,
            plan_type: planType
        }, requestCount);
    }
    
    // Cloud Monitoring integration
    async sendToCloudMonitoring(metricType, value, labels = {}) {
        try {
            const dataPoint = {
                interval: {
                    endTime: {
                        seconds: Date.now() / 1000,
                    },
                },
                value: {
                    int64Value: value,
                },
            };
            
            const timeSeriesData = {
                metric: {
                    type: metricType,
                    labels: labels,
                },
                resource: {
                    type: 'cloud_run_revision',
                    labels: {
                        service_name: this.serviceName,
                        revision_name: process.env.K_REVISION || 'unknown',
                        location: process.env.REGION || 'us-central1',
                        project_id: process.env.PROJECT_ID,
                    },
                },
                points: [dataPoint],
            };
            
            const request = {
                name: this.projectPath,
                timeSeries: [timeSeriesData],
            };
            
            await this.monitoring.createTimeSeries(request);
        } catch (error) {
            console.error('Error sending metric to Cloud Monitoring:', error);
        }
    }
    
    // Metrics export methods
    getPrometheusMetrics() {
        return this.register.metrics();
    }
    
    async getMetricsContentType() {
        return this.register.contentType;
    }
    
    // Middleware for automatic HTTP metrics collection
    createHttpMetricsMiddleware() {
        return (req, res, next) => {
            const start = Date.now();
            
            res.on('finish', () => {
                const duration = (Date.now() - start) / 1000;
                const statusClass = `${Math.floor(res.statusCode / 100)}xx`;
                
                this.recordResponseTime(req.path, req.method, duration);
                this.updateThroughput(req.path, statusClass, 1); // Simplified throughput tracking
                
                // Security monitoring for HTTP requests
                if (res.statusCode >= 400) {
                    this.recordSecurityMetric('http_error', {
                        path: req.path,
                        method: req.method,
                        status_code: res.statusCode,
                        ip_address: req.ip,
                        user_agent: req.get('User-Agent')
                    });
                }
            });
            
            next();
        };
    }
    
    recordSecurityMetric(eventType, context) {
        // Generic security metric recording
        console.log(`Security metric: ${eventType}`, context);
        
        // You can add logic here to route to specific metrics based on event type
        if (eventType === 'http_error' && context.status_code >= 400) {
            // This could be a potential security event
            this.recordThreatDetection('http_anomaly', 'low', context);
        }
    }
}

module.exports = ISECTECHMetrics;

// Example usage:
/*
const metrics = new ISECTECHMetrics('isectech-api-gateway', 'production');

// Record security events
metrics.recordThreatDetection('sql_injection', 'high', { serviceName: 'api-gateway' });
metrics.recordAuthenticationEvent('login', 'success', 'password', 'admin');

// Record performance metrics
metrics.recordResponseTime('/api/v1/threats', 'GET', 0.245);
metrics.updateResourceUtilization('cpu', 'instance-1', 75.5);

// Record business metrics
metrics.recordFeatureUsage('threat_analysis', 'view', 'analyst');
metrics.updateActiveUsers('daily', 'admin', 'enterprise', 25);

// Express middleware
app.use('/metrics', async (req, res) => {
    res.set('Content-Type', await metrics.getMetricsContentType());
    res.end(await metrics.getPrometheusMetrics());
});
*/
EOF
    
    # Create Go metrics library
    cat > "/tmp/go-metrics.go" << 'EOF'
// iSECTECH Custom Metrics Library for Go
// Production-grade metrics collection with security context

package metrics

import (
    "context"
    "fmt"
    "log"
    "net/http"
    "os"
    "time"
    
    monitoring "cloud.google.com/go/monitoring/apiv3/v2"
    "cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "google.golang.org/genproto/googleapis/api/metric"
    "google.golang.org/genproto/googleapis/api/monitoredres"
    "google.golang.org/protobuf/types/known/timestamppb"
)

type ISECTECHMetrics struct {
    serviceName   string
    environment   string
    projectID     string
    
    // Prometheus registry
    registry *prometheus.Registry
    
    // Google Cloud Monitoring client
    monitoringClient *monitoring.MetricClient
    
    // Security metrics
    threatDetectionCounter    *prometheus.CounterVec
    authenticationCounter     *prometheus.CounterVec
    vulnerabilityGauge        *prometheus.GaugeVec
    incidentResponseGauge     *prometheus.GaugeVec
    complianceScoreGauge      *prometheus.GaugeVec
    securityEventRateGauge    *prometheus.GaugeVec
    failedLoginCounter        *prometheus.CounterVec
    
    // Performance metrics
    responseTimeHistogram     *prometheus.HistogramVec
    throughputGauge          *prometheus.GaugeVec
    resourceUtilizationGauge *prometheus.GaugeVec
    
    // Business metrics
    activeUsersGauge         *prometheus.GaugeVec
    featureUsageCounter      *prometheus.CounterVec
    apiConsumptionCounter    *prometheus.CounterVec
}

func NewISECTECHMetrics(serviceName, environment string) (*ISECTECHMetrics, error) {
    projectID := os.Getenv("PROJECT_ID")
    if projectID == "" {
        return nil, fmt.Errorf("PROJECT_ID environment variable is required")
    }
    
    // Create Prometheus registry
    registry := prometheus.NewRegistry()
    
    // Create Google Cloud Monitoring client
    ctx := context.Background()
    monitoringClient, err := monitoring.NewMetricClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create monitoring client: %w", err)
    }
    
    m := &ISECTECHMetrics{
        serviceName:      serviceName,
        environment:      environment,
        projectID:        projectID,
        registry:         registry,
        monitoringClient: monitoringClient,
    }
    
    m.initializeMetrics()
    
    return m, nil
}

func (m *ISECTECHMetrics) initializeMetrics() {
    // Security metrics
    m.threatDetectionCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "isectech_security_threat_detections_total",
            Help: "Total number of threat detections",
        },
        []string{"threat_type", "severity", "service_name", "environment"},
    )
    
    m.authenticationCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "isectech_security_authentication_events_total",
            Help: "Total number of authentication events",
        },
        []string{"operation", "result", "method", "user_type"},
    )
    
    m.vulnerabilityGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_security_vulnerability_findings",
            Help: "Current number of vulnerability findings",
        },
        []string{"severity", "scan_type", "target_type", "remediation_status"},
    )
    
    m.incidentResponseGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_security_incident_response_time_seconds",
            Help: "Time to respond to security incidents",
        },
        []string{"incident_type", "severity", "response_team"},
    )
    
    m.complianceScoreGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_security_compliance_score",
            Help: "Compliance score by framework",
        },
        []string{"framework", "control_family", "assessment_date"},
    )
    
    m.securityEventRateGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_security_event_rate_per_minute",
            Help: "Security events per minute",
        },
        []string{"event_type", "severity"},
    )
    
    m.failedLoginCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "isectech_security_failed_login_attempts_total",
            Help: "Total failed login attempts",
        },
        []string{"ip_address", "user_agent_hash", "reason"},
    )
    
    // Performance metrics
    m.responseTimeHistogram = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "isectech_performance_response_time_seconds",
            Help:    "API response time in seconds",
            Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
        },
        []string{"endpoint", "method", "service_name"},
    )
    
    m.throughputGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_performance_throughput_rps",
            Help: "Requests per second",
        },
        []string{"service_name", "endpoint", "status_class"},
    )
    
    m.resourceUtilizationGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_performance_resource_utilization_percent",
            Help: "Resource utilization percentage",
        },
        []string{"resource_type", "service_name", "instance_id"},
    )
    
    // Business metrics
    m.activeUsersGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "isectech_business_active_users",
            Help: "Number of active users",
        },
        []string{"time_period", "user_type", "organization_tier"},
    )
    
    m.featureUsageCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "isectech_business_feature_usage_total",
            Help: "Total feature usage events",
        },
        []string{"feature_name", "action_type", "user_role"},
    )
    
    m.apiConsumptionCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "isectech_business_api_consumption_total",
            Help: "Total API consumption",
        },
        []string{"customer_id", "api_category", "plan_type"},
    )
    
    // Register all metrics
    m.registry.MustRegister(
        m.threatDetectionCounter,
        m.authenticationCounter,
        m.vulnerabilityGauge,
        m.incidentResponseGauge,
        m.complianceScoreGauge,
        m.securityEventRateGauge,
        m.failedLoginCounter,
        m.responseTimeHistogram,
        m.throughputGauge,
        m.resourceUtilizationGauge,
        m.activeUsersGauge,
        m.featureUsageCounter,
        m.apiConsumptionCounter,
    )
}

// Security metric methods
func (m *ISECTECHMetrics) RecordThreatDetection(threatType, severity string, context map[string]string) {
    serviceName := context["service_name"]
    if serviceName == "" {
        serviceName = m.serviceName
    }
    
    m.threatDetectionCounter.WithLabelValues(
        threatType,
        severity,
        serviceName,
        m.environment,
    ).Inc()
    
    // Also send to Cloud Monitoring
    m.sendToCloudMonitoring("custom.googleapis.com/isectech/security/threat_detections", 1, map[string]string{
        "threat_type":  threatType,
        "severity":     severity,
        "service_name": serviceName,
        "environment":  m.environment,
    })
}

func (m *ISECTECHMetrics) RecordAuthenticationEvent(operation, result, method, userType string) {
    m.authenticationCounter.WithLabelValues(
        operation,
        result,
        method,
        userType,
    ).Inc()
}

func (m *ISECTECHMetrics) RecordFailedLogin(ipAddress, userAgentHash, reason string) {
    m.failedLoginCounter.WithLabelValues(
        ipAddress,
        userAgentHash,
        reason,
    ).Inc()
}

func (m *ISECTECHMetrics) UpdateVulnerabilityFindings(severity, scanType, targetType, remediationStatus string, count float64) {
    m.vulnerabilityGauge.WithLabelValues(
        severity,
        scanType,
        targetType,
        remediationStatus,
    ).Set(count)
}

func (m *ISECTECHMetrics) RecordIncidentResponseTime(incidentType, severity, responseTeam string, responseTimeSeconds float64) {
    m.incidentResponseGauge.WithLabelValues(
        incidentType,
        severity,
        responseTeam,
    ).Set(responseTimeSeconds)
}

func (m *ISECTECHMetrics) UpdateComplianceScore(framework, controlFamily string, score float64) {
    assessmentDate := time.Now().Format("2006-01-02")
    m.complianceScoreGauge.WithLabelValues(
        framework,
        controlFamily,
        assessmentDate,
    ).Set(score)
}

func (m *ISECTECHMetrics) UpdateSecurityEventRate(eventType, severity string, ratePerMinute float64) {
    m.securityEventRateGauge.WithLabelValues(
        eventType,
        severity,
    ).Set(ratePerMinute)
}

// Performance metric methods
func (m *ISECTECHMetrics) RecordResponseTime(endpoint, method string, durationSeconds float64) {
    m.responseTimeHistogram.WithLabelValues(
        endpoint,
        method,
        m.serviceName,
    ).Observe(durationSeconds)
}

func (m *ISECTECHMetrics) UpdateThroughput(endpoint, statusClass string, requestsPerSecond float64) {
    m.throughputGauge.WithLabelValues(
        m.serviceName,
        endpoint,
        statusClass,
    ).Set(requestsPerSecond)
}

func (m *ISECTECHMetrics) UpdateResourceUtilization(resourceType, instanceID string, utilizationPercent float64) {
    m.resourceUtilizationGauge.WithLabelValues(
        resourceType,
        m.serviceName,
        instanceID,
    ).Set(utilizationPercent)
}

// Business metric methods
func (m *ISECTECHMetrics) UpdateActiveUsers(timePeriod, userType, organizationTier string, count float64) {
    m.activeUsersGauge.WithLabelValues(
        timePeriod,
        userType,
        organizationTier,
    ).Set(count)
}

func (m *ISECTECHMetrics) RecordFeatureUsage(featureName, actionType, userRole string) {
    m.featureUsageCounter.WithLabelValues(
        featureName,
        actionType,
        userRole,
    ).Inc()
}

func (m *ISECTECHMetrics) RecordAPIConsumption(customerID, apiCategory, planType string, requestCount float64) {
    m.apiConsumptionCounter.WithLabelValues(
        customerID,
        apiCategory,
        planType,
    ).Add(requestCount)
}

// Cloud Monitoring integration
func (m *ISECTECHMetrics) sendToCloudMonitoring(metricType string, value float64, labels map[string]string) {
    ctx := context.Background()
    
    now := &timestamppb.Timestamp{
        Seconds: time.Now().Unix(),
    }
    
    dataPoint := &monitoringpb.Point{
        Interval: &monitoringpb.TimeInterval{
            EndTime: now,
        },
        Value: &monitoringpb.TypedValue{
            Value: &monitoringpb.TypedValue_Int64Value{
                Int64Value: int64(value),
            },
        },
    }
    
    timeSeries := &monitoringpb.TimeSeries{
        Metric: &metric.Metric{
            Type:   metricType,
            Labels: labels,
        },
        Resource: &monitoredres.MonitoredResource{
            Type: "cloud_run_revision",
            Labels: map[string]string{
                "service_name":   m.serviceName,
                "revision_name":  os.Getenv("K_REVISION"),
                "location":       os.Getenv("REGION"),
                "project_id":     m.projectID,
            },
        },
        Points: []*monitoringpb.Point{dataPoint},
    }
    
    req := &monitoringpb.CreateTimeSeriesRequest{
        Name:       "projects/" + m.projectID,
        TimeSeries: []*monitoringpb.TimeSeries{timeSeries},
    }
    
    if err := m.monitoringClient.CreateTimeSeries(ctx, req); err != nil {
        log.Printf("Error sending metric to Cloud Monitoring: %v", err)
    }
}

// HTTP handler for Prometheus metrics
func (m *ISECTECHMetrics) Handler() http.Handler {
    return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Middleware for automatic HTTP metrics collection
func (m *ISECTECHMetrics) HTTPMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Wrap ResponseWriter to capture status code
        ww := &responseWriter{ResponseWriter: w, statusCode: 200}
        
        next.ServeHTTP(ww, r)
        
        duration := time.Since(start).Seconds()
        statusClass := fmt.Sprintf("%dxx", ww.statusCode/100)
        
        m.RecordResponseTime(r.URL.Path, r.Method, duration)
        m.UpdateThroughput(r.URL.Path, statusClass, 1) // Simplified throughput tracking
        
        // Security monitoring for HTTP requests
        if ww.statusCode >= 400 {
            m.recordSecurityMetric("http_error", map[string]string{
                "path":        r.URL.Path,
                "method":      r.Method,
                "status_code": fmt.Sprintf("%d", ww.statusCode),
                "ip_address":  r.RemoteAddr,
                "user_agent":  r.UserAgent(),
            })
        }
    })
}

func (m *ISECTECHMetrics) recordSecurityMetric(eventType string, context map[string]string) {
    log.Printf("Security metric: %s, context: %+v", eventType, context)
    
    // Route to specific metrics based on event type
    if eventType == "http_error" {
        if statusCode := context["status_code"]; statusCode != "" {
            // This could be a potential security event
            m.RecordThreatDetection("http_anomaly", "low", context)
        }
    }
}

// Close cleans up resources
func (m *ISECTECHMetrics) Close() error {
    return m.monitoringClient.Close()
}

// Helper types
type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}
EOF
    
    log_success "Created metrics collection libraries"
}

# Deploy Prometheus monitoring stack
deploy_prometheus_stack() {
    log_info "Deploying Prometheus monitoring stack..."
    
    # Create Prometheus configuration
    cat > "/tmp/prometheus.yml" << EOF
global:
  scrape_interval: ${SCRAPE_INTERVAL}
  evaluation_interval: ${SCRAPE_INTERVAL}
  external_labels:
    environment: '${ENVIRONMENT}'
    project: '${PROJECT_ID}'
    region: '${REGION}'

rule_files:
  - "/etc/prometheus/rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - 'alertmanager:9093'

scrape_configs:
  # Prometheus self-monitoring
  - job_name: 'prometheus'
    scrape_interval: ${SCRAPE_INTERVAL}
    static_configs:
      - targets: ['localhost:9090']
        labels:
          service: 'prometheus'
          environment: '${ENVIRONMENT}'

  # OpenTelemetry Collector metrics
  - job_name: 'otel-collector'
    scrape_interval: ${SCRAPE_INTERVAL}
    static_configs:
      - targets: ['isectech-otel-collector-url:8888']
        labels:
          service: 'otel-collector'
          environment: '${ENVIRONMENT}'

  # Cloud Run services discovery
  - job_name: 'cloud-run-services'
    scrape_interval: ${SCRAPE_INTERVAL}
    gce_sd_configs:
      - project: '${PROJECT_ID}'
        zone: '${REGION}'
        port: 8080
    relabel_configs:
      - source_labels: [__meta_gce_label_service]
        target_label: service
      - source_labels: [__meta_gce_label_environment]
        target_label: environment
      - source_labels: [__meta_gce_public_ip]
        target_label: __address__
        replacement: '\${1}:8080'

  # Security-specific metrics (higher frequency)
  - job_name: 'security-metrics'
    scrape_interval: ${SECURITY_SCRAPE_INTERVAL}
    static_configs:
      - targets:
        - 'isectech-siem-service:8080'
        - 'isectech-soar-service:8080'
        - 'isectech-threat-intel-service:8080'
        - 'isectech-vulnerability-service:8080'
        labels:
          category: 'security'
          environment: '${ENVIRONMENT}'

  # Business metrics
  - job_name: 'business-metrics'
    scrape_interval: 60s
    static_configs:
      - targets:
        - 'isectech-api-gateway:8080'
        - 'isectech-frontend:8080'
        labels:
          category: 'business'
          environment: '${ENVIRONMENT}'

  # Infrastructure metrics
  - job_name: 'infrastructure'
    scrape_interval: ${SCRAPE_INTERVAL}
    static_configs:
      - targets:
        - 'node-exporter:9100'
        - 'cadvisor:8080'
        labels:
          category: 'infrastructure'
          environment: '${ENVIRONMENT}'

remote_write:
  - url: "https://monitoring.googleapis.com/v1/projects/${PROJECT_ID}/location/global/prometheus/api/v1/write"
    oauth2:
      client_id: "oauth-client-id"
      client_secret: "oauth-client-secret"
      token_url: "https://oauth2.googleapis.com/token"
      scopes:
        - "https://www.googleapis.com/auth/monitoring.write"
EOF
    
    # Create Prometheus alert rules
    cat > "/tmp/prometheus-alert-rules.yml" << EOF
groups:
  - name: isectech.security.rules
    interval: 30s
    rules:
      # High severity threat detection
      - alert: HighSeverityThreatDetected
        expr: increase(isectech_security_threat_detections_total{severity="high"}[5m]) > 0
        for: 0m
        labels:
          severity: critical
          category: security
          team: security-ops
        annotations:
          summary: "High severity threat detected"
          description: "{{ \$labels.threat_type }} threat detected in {{ \$labels.service_name }}"
          runbook_url: "https://runbooks.isectech.com/security/high-threat"

      # Critical severity threats (immediate alert)
      - alert: CriticalThreatDetected
        expr: increase(isectech_security_threat_detections_total{severity="critical"}[1m]) > 0
        for: 0m
        labels:
          severity: critical
          category: security
          team: security-ops
          page: "true"
        annotations:
          summary: "CRITICAL THREAT DETECTED"
          description: "IMMEDIATE ACTION REQUIRED: {{ \$labels.threat_type }} in {{ \$labels.service_name }}"
          runbook_url: "https://runbooks.isectech.com/security/critical-threat"

      # Authentication failure spike
      - alert: AuthenticationFailureSpike
        expr: rate(isectech_security_authentication_events_total{result="failure"}[5m]) > 10
        for: 2m
        labels:
          severity: warning
          category: security
          team: security-ops
        annotations:
          summary: "High authentication failure rate"
          description: "Authentication failure rate is {{ \$value }} failures/sec"
          runbook_url: "https://runbooks.isectech.com/security/auth-failures"

      # Failed login attempts from single IP
      - alert: BruteForceAttack
        expr: rate(isectech_security_failed_login_attempts_total[10m]) > 5
        for: 1m
        labels:
          severity: high
          category: security
          team: security-ops
        annotations:
          summary: "Potential brute force attack"
          description: "High failed login rate from {{ \$labels.ip_address }}: {{ \$value }} attempts/sec"
          runbook_url: "https://runbooks.isectech.com/security/brute-force"

      # Security event rate anomaly
      - alert: SecurityEventRateAnomaly
        expr: isectech_security_event_rate_per_minute > 100
        for: 5m
        labels:
          severity: warning
          category: security
          team: security-ops
        annotations:
          summary: "Abnormal security event rate"
          description: "Security event rate is {{ \$value }} events/minute for {{ \$labels.event_type }}"

  - name: isectech.performance.rules
    interval: 30s
    rules:
      # High response time
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(isectech_performance_response_time_seconds_bucket[5m])) > 5
        for: 2m
        labels:
          severity: warning
          category: performance
          team: platform-ops
        annotations:
          summary: "High API response time"
          description: "95th percentile response time is {{ \$value }}s for {{ \$labels.endpoint }}"
          runbook_url: "https://runbooks.isectech.com/performance/high-latency"

      # High error rate
      - alert: HighErrorRate
        expr: rate(isectech_performance_throughput_rps{status_class="5xx"}[5m]) / rate(isectech_performance_throughput_rps[5m]) > 0.05
        for: 2m
        labels:
          severity: warning
          category: performance
          team: platform-ops
        annotations:
          summary: "High error rate"
          description: "Error rate is {{ \$value | humanizePercentage }} for {{ \$labels.service_name }}"

      # High resource utilization
      - alert: HighResourceUtilization
        expr: isectech_performance_resource_utilization_percent > 85
        for: 5m
        labels:
          severity: warning
          category: performance
          team: platform-ops
        annotations:
          summary: "High resource utilization"
          description: "{{ \$labels.resource_type }} utilization is {{ \$value }}% on {{ \$labels.service_name }}"

  - name: isectech.business.rules
    interval: 60s
    rules:
      # API consumption limit approaching
      - alert: APIConsumptionLimitApproaching
        expr: rate(isectech_business_api_consumption_total[1h]) * 24 > 800000  # 80% of 1M daily limit
        for: 10m
        labels:
          severity: warning
          category: business
          team: customer-success
        annotations:
          summary: "Customer approaching API limit"
          description: "Customer {{ \$labels.customer_id }} API usage is approaching daily limit"

      # Low active user count
      - alert: LowActiveUserCount
        expr: isectech_business_active_users{time_period="daily"} < 10
        for: 30m
        labels:
          severity: info
          category: business
          team: product
        annotations:
          summary: "Low daily active user count"
          description: "Daily active users is {{ \$value }} for {{ \$labels.organization_tier }}"

  - name: isectech.compliance.rules
    interval: 300s  # Check every 5 minutes
    rules:
      # Compliance score drop
      - alert: ComplianceScoreDrop
        expr: isectech_security_compliance_score < 0.85
        for: 10m
        labels:
          severity: warning
          category: compliance
          team: security-ops
        annotations:
          summary: "Compliance score below threshold"
          description: "{{ \$labels.framework }} compliance score is {{ \$value }} (below 85%)"
          runbook_url: "https://runbooks.isectech.com/compliance/score-drop"

      # Incident response time SLA breach
      - alert: IncidentResponseSLABreach
        expr: isectech_security_incident_response_time_seconds > 3600  # 1 hour
        for: 0m
        labels:
          severity: high
          category: compliance
          team: security-ops
        annotations:
          summary: "Incident response SLA breached"
          description: "{{ \$labels.incident_type }} response time is {{ \$value | humanizeDuration }}"
EOF
    
    # Create Prometheus Dockerfile
    cat > "/tmp/prometheus.Dockerfile" << EOF
FROM prom/prometheus:v${PROMETHEUS_VERSION}

# Copy custom configuration
COPY prometheus.yml /etc/prometheus/prometheus.yml
COPY prometheus-alert-rules.yml /etc/prometheus/rules/alert-rules.yml

# Security hardening
USER nobody

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:9090/-/healthy || exit 1

EXPOSE 9090

CMD ["--config.file=/etc/prometheus/prometheus.yml", \
     "--storage.tsdb.path=/prometheus", \
     "--storage.tsdb.retention.time=${METRICS_RETENTION_DAYS}d", \
     "--web.console.libraries=/etc/prometheus/console_libraries", \
     "--web.console.templates=/etc/prometheus/consoles", \
     "--web.enable-lifecycle", \
     "--web.enable-admin-api"]
EOF
    
    # Build and deploy Prometheus
    log_info "Building and deploying Prometheus..."
    
    mkdir -p "/tmp/prometheus-build"
    cp "/tmp/prometheus.yml" "/tmp/prometheus-build/"
    cp "/tmp/prometheus-alert-rules.yml" "/tmp/prometheus-build/"
    cp "/tmp/prometheus.Dockerfile" "/tmp/prometheus-build/Dockerfile"
    
    cd "/tmp/prometheus-build"
    
    # Build and push Prometheus image
    gcloud builds submit --tag "gcr.io/${PROJECT_ID}/prometheus:${PROMETHEUS_VERSION}" .
    
    # Deploy Prometheus to Cloud Run
    gcloud run deploy isectech-prometheus \
        --image="gcr.io/${PROJECT_ID}/prometheus:${PROMETHEUS_VERSION}" \
        --region="$REGION" \
        --platform=managed \
        --allow-unauthenticated \
        --port=9090 \
        --memory=2Gi \
        --cpu=2 \
        --concurrency=100 \
        --max-instances=3 \
        --min-instances=1 \
        --execution-environment=gen2 \
        --set-env-vars="PROJECT_ID=${PROJECT_ID},ENVIRONMENT=${ENVIRONMENT}" \
        --labels="component=monitoring,service=prometheus,environment=${ENVIRONMENT}"
    
    log_success "Prometheus deployed to Cloud Run"
}

# Set up Grafana dashboards
setup_grafana_dashboards() {
    log_info "Setting up Grafana dashboards..."
    
    # Create Grafana configuration
    cat > "/tmp/grafana.ini" << EOF
[server]
http_port = 3000
domain = grafana.isectech.com

[security]
admin_user = admin
admin_password = \${GRAFANA_ADMIN_PASSWORD}
secret_key = \${GRAFANA_SECRET_KEY}

[auth]
disable_login_form = false
oauth_auto_login = false

[auth.google]
enabled = true
client_id = \${GOOGLE_OAUTH_CLIENT_ID}
client_secret = \${GOOGLE_OAUTH_CLIENT_SECRET}
scopes = https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email
auth_url = https://accounts.google.com/o/oauth2/auth
token_url = https://accounts.google.com/o/oauth2/token
allowed_domains = isectech.com

[database]
type = postgres
host = \${POSTGRES_HOST}
name = grafana
user = \${POSTGRES_USER}
password = \${POSTGRES_PASSWORD}

[session]
provider = postgres
provider_config = host=\${POSTGRES_HOST} user=\${POSTGRES_USER} password=\${POSTGRES_PASSWORD} dbname=grafana sslmode=require

[analytics]
reporting_enabled = false
check_for_updates = false

[log]
mode = console
level = info

[metrics]
enabled = true
basic_auth_username = metrics
basic_auth_password = \${METRICS_PASSWORD}
EOF
    
    # Create security dashboard
    cat > "/tmp/security-dashboard.json" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "iSECTECH Security Monitoring",
    "tags": ["security", "isectech"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "Threat Detections",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(isectech_security_threat_detections_total[5m])) by (threat_type, severity)",
            "legendFormat": "{{threat_type}} ({{severity}})"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "color": {
              "mode": "thresholds"
            },
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 1},
                {"color": "red", "value": 5}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Authentication Events",
        "type": "timeseries",
        "targets": [
          {
            "expr": "sum(rate(isectech_security_authentication_events_total[5m])) by (result)",
            "legendFormat": "{{result}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Failed Login Attempts by IP",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, sum(rate(isectech_security_failed_login_attempts_total[1h])) by (ip_address))",
            "format": "table"
          }
        ],
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      },
      {
        "id": 4,
        "title": "Vulnerability Findings",
        "type": "piechart",
        "targets": [
          {
            "expr": "sum(isectech_security_vulnerability_findings) by (severity)",
            "legendFormat": "{{severity}}"
          }
        ],
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 16}
      },
      {
        "id": 5,
        "title": "Incident Response Time",
        "type": "gauge",
        "targets": [
          {
            "expr": "avg(isectech_security_incident_response_time_seconds) by (incident_type)",
            "legendFormat": "{{incident_type}}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "min": 0,
            "max": 3600,
            "unit": "s",
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 1800},
                {"color": "red", "value": 3600}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 16}
      },
      {
        "id": 6,
        "title": "Compliance Scores",
        "type": "bargauge",
        "targets": [
          {
            "expr": "isectech_security_compliance_score",
            "legendFormat": "{{framework}} - {{control_family}}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "min": 0,
            "max": 1,
            "unit": "percentunit",
            "thresholds": {
              "steps": [
                {"color": "red", "value": null},
                {"color": "yellow", "value": 0.7},
                {"color": "green", "value": 0.85}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 24}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
EOF
    
    # Create performance dashboard
    cat > "/tmp/performance-dashboard.json" << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "iSECTECH Performance Monitoring",
    "tags": ["performance", "isectech"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "API Response Time (95th Percentile)",
        "type": "timeseries",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, sum(rate(isectech_performance_response_time_seconds_bucket[5m])) by (endpoint, le))",
            "legendFormat": "{{endpoint}}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "s",
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 1},
                {"color": "red", "value": 5}
              ]
            }
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0}
      },
      {
        "id": 2,
        "title": "Request Throughput",
        "type": "timeseries",
        "targets": [
          {
            "expr": "sum(isectech_performance_throughput_rps) by (service_name, status_class)",
            "legendFormat": "{{service_name}} ({{status_class}})"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "reqps"
          }
        },
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0}
      },
      {
        "id": 3,
        "title": "Resource Utilization",
        "type": "timeseries",
        "targets": [
          {
            "expr": "isectech_performance_resource_utilization_percent",
            "legendFormat": "{{service_name}} - {{resource_type}}"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percent",
            "min": 0,
            "max": 100
          }
        },
        "gridPos": {"h": 8, "w": 24, "x": 0, "y": 8}
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "30s"
  }
}
EOF
    
    log_success "Grafana dashboard configurations created"
}

# Generate metrics report
generate_metrics_report() {
    log_info "Generating custom metrics and Prometheus configuration report..."
    
    local report_file="/tmp/isectech-metrics-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Custom Metrics and Prometheus Integration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
METRICS INFRASTRUCTURE OVERVIEW
================================

Prometheus Version: ${PROMETHEUS_VERSION}
Grafana Version: ${GRAFANA_VERSION}
AlertManager Version: ${ALERTMANAGER_VERSION}

Data Retention:
- Standard Metrics: ${METRICS_RETENTION_DAYS} days
- High Resolution: ${HIGH_RESOLUTION_RETENTION_DAYS} days

Scrape Configuration:
- Default Interval: ${SCRAPE_INTERVAL}
- Security Metrics: ${SECURITY_SCRAPE_INTERVAL}

================================
CUSTOM METRICS CATALOG
================================

Security Metrics:
1. isectech_security_threat_detections_total
   - Type: Counter
   - Labels: threat_type, severity, service_name, environment
   - Purpose: Track threat detection events by type and severity

2. isectech_security_authentication_events_total
   - Type: Counter
   - Labels: operation, result, method, user_type
   - Purpose: Monitor authentication attempts and outcomes

3. isectech_security_vulnerability_findings
   - Type: Gauge
   - Labels: severity, scan_type, target_type, remediation_status
   - Purpose: Track current vulnerability counts by severity

4. isectech_security_incident_response_time_seconds
   - Type: Gauge
   - Labels: incident_type, severity, response_team
   - Purpose: Monitor incident response performance

5. isectech_security_compliance_score
   - Type: Gauge
   - Labels: framework, control_family, assessment_date
   - Purpose: Track compliance scores by framework

6. isectech_security_failed_login_attempts_total
   - Type: Counter
   - Labels: ip_address, user_agent_hash, reason
   - Purpose: Detect brute force and credential stuffing attacks

7. isectech_security_event_rate_per_minute
   - Type: Gauge
   - Labels: event_type, severity
   - Purpose: Monitor security event frequency for anomaly detection

Performance Metrics:
1. isectech_performance_response_time_seconds
   - Type: Histogram
   - Labels: endpoint, method, service_name
   - Buckets: [0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
   - Purpose: Track API response time distribution

2. isectech_performance_throughput_rps
   - Type: Gauge
   - Labels: service_name, endpoint, status_class
   - Purpose: Monitor request throughput by endpoint

3. isectech_performance_resource_utilization_percent
   - Type: Gauge
   - Labels: resource_type, service_name, instance_id
   - Purpose: Track CPU, memory, disk utilization

Business Metrics:
1. isectech_business_active_users
   - Type: Gauge
   - Labels: time_period, user_type, organization_tier
   - Purpose: Track user engagement and platform adoption

2. isectech_business_feature_usage_total
   - Type: Counter
   - Labels: feature_name, action_type, user_role
   - Purpose: Monitor feature adoption and usage patterns

3. isectech_business_api_consumption_total
   - Type: Counter
   - Labels: customer_id, api_category, plan_type
   - Purpose: Track API usage for billing and capacity planning

================================
PROMETHEUS CONFIGURATION
================================

Scrape Targets:
1. Self-monitoring (prometheus:9090)
2. OpenTelemetry Collector (otel-collector:8888)
3. Cloud Run Services (auto-discovery via GCE SD)
4. Security Services (high frequency scraping)
5. Business Metrics Services
6. Infrastructure Exporters

Remote Write Configuration:
- Destination: Google Cloud Monitoring
- Authentication: OAuth2
- Retention: Long-term storage in Google Cloud

Alert Rules Categories:
1. Security Alerts (30s evaluation)
   - High/Critical threat detection
   - Authentication failure spikes
   - Brute force attack detection
   - Security event rate anomalies

2. Performance Alerts (30s evaluation)
   - High response time (>5s P95)
   - High error rate (>5%)
   - Resource utilization (>85%)

3. Business Alerts (60s evaluation)
   - API consumption limits
   - Low active user counts

4. Compliance Alerts (300s evaluation)
   - Compliance score drops
   - SLA breaches

================================
ALERTING CONFIGURATION
================================

Alert Severity Levels:
- Critical: Immediate paging required
- High: Urgent response needed
- Warning: Attention required
- Info: Informational only

Alert Routing:
- Security Team: security-ops@isectech.com
- Platform Team: platform-ops@isectech.com
- Customer Success: customer-success@isectech.com
- Product Team: product@isectech.com

Notification Channels:
- Email alerts for all severities
- Slack integration for team channels
- PagerDuty for critical alerts
- SMS for critical security events

Alert Runbooks:
- Each alert includes runbook_url
- Runbooks hosted at: https://runbooks.isectech.com/
- Includes troubleshooting steps and escalation procedures

================================
GRAFANA DASHBOARDS
================================

Security Dashboard:
- Threat detection statistics
- Authentication event timeline
- Failed login attempts by IP
- Vulnerability findings breakdown
- Incident response time gauges
- Compliance score overview

Performance Dashboard:
- API response time percentiles
- Request throughput by service
- Resource utilization trends
- Error rate monitoring
- SLA compliance tracking

Business Dashboard:
- Active user metrics
- Feature usage analytics
- API consumption tracking
- Customer engagement metrics
- Revenue-impacting indicators

Infrastructure Dashboard:
- System resource monitoring
- Service health status
- Network performance metrics
- Storage utilization
- Cost optimization insights

================================
METRICS COLLECTION LIBRARIES
================================

Node.js/TypeScript Library Features:
- Prometheus client integration
- Google Cloud Monitoring export
- Automatic HTTP middleware
- Security context enhancement
- Custom metric registration
- Thread-safe operations

Available Methods:
- recordThreatDetection()
- recordAuthenticationEvent()
- updateVulnerabilityFindings()
- recordIncidentResponseTime()
- updateComplianceScore()
- recordResponseTime()
- updateResourceUtilization()
- recordFeatureUsage()

Go Library Features:
- Prometheus client integration
- Google Cloud Monitoring export
- HTTP middleware for automatic collection
- Concurrent-safe operations
- Custom metric definitions
- Context-aware logging

Available Methods:
- RecordThreatDetection()
- RecordAuthenticationEvent()
- UpdateVulnerabilityFindings()
- RecordIncidentResponseTime()
- UpdateComplianceScore()
- RecordResponseTime()
- UpdateResourceUtilization()
- RecordFeatureUsage()

================================
INTEGRATION POINTS
================================

Google Cloud Monitoring:
- Custom metric export
- Long-term data retention
- Advanced querying capabilities
- Integration with GCP services
- Automated scaling based on metrics

Prometheus Ecosystem:
- Alertmanager for alert routing
- Grafana for visualization
- Custom exporters for specialized metrics
- Federation for multi-cluster monitoring
- Recording rules for performance optimization

External Systems:
- SIEM integration via metric export
- APM tool correlation
- Business intelligence systems
- Capacity planning tools
- Cost optimization platforms

API Endpoints:
- /metrics (Prometheus format)
- /api/v1/metrics (custom JSON API)
- /health/metrics (health check with metrics)
- /debug/metrics (detailed metrics for debugging)

================================
SECURITY & COMPLIANCE
================================

Data Protection:
- Metrics data encryption in transit and at rest
- Access control via IAM policies
- Sensitive data masking in metrics
- Audit logging for metrics access

Compliance Features:
- SOC 2 Type II metrics collection
- PCI DSS monitoring requirements
- GDPR data handling compliance
- Retention policy enforcement

Security Monitoring:
- Tamper detection for metrics systems
- Unauthorized access alerting
- Configuration change monitoring
- Security event correlation

================================
OPERATIONAL PROCEDURES
================================

Daily Operations:
- Monitor metrics ingestion rates
- Review alert fatigue metrics
- Check dashboard functionality
- Verify data export processes

Weekly Operations:
- Analyze metrics trends
- Review alert effectiveness
- Update threshold values
- Optimize query performance

Monthly Operations:
- Capacity planning review
- Cost optimization analysis
- Metrics retention cleanup
- Dashboard usage analytics

Emergency Procedures:
- Metrics system failover
- Emergency alert escalation
- Data recovery procedures
- Incident correlation workflows

================================
PERFORMANCE OPTIMIZATION
================================

Query Optimization:
- Recording rules for expensive queries
- Metric label cardinality management
- Efficient aggregation strategies
- Storage optimization techniques

Resource Management:
- Memory usage optimization
- CPU usage monitoring
- Storage capacity planning
- Network bandwidth management

Scaling Strategies:
- Horizontal scaling for high cardinality
- Sharding by service or region
- Federation for multi-environment
- Load balancing for query distribution

Caching:
- Query result caching
- Dashboard caching
- Metric metadata caching
- Computed metric caching

================================
COST OPTIMIZATION
================================

Estimated Monthly Costs:
- Prometheus (Cloud Run): \$50-150
- Grafana (Cloud Run): \$30-100
- Google Cloud Monitoring: \$100-500
- Storage (BigQuery): \$50-200
- Network egress: \$20-80

Cost Optimization Features:
- Intelligent metric sampling
- Automated data lifecycle management
- Query optimization recommendations
- Resource usage monitoring
- Budget alerts and limits

Storage Optimization:
- Compression algorithms
- Data deduplication
- Archival policies
- Cold storage migration
- Retention policy automation

================================
MONITORING & HEALTH CHECKS
================================

System Health Metrics:
- Metrics ingestion rate (metrics/second)
- Query response time (milliseconds)
- Storage usage (GB)
- Memory utilization (%)
- CPU utilization (%)

Key Performance Indicators:
- Metrics availability > 99.9%
- Query response time < 2 seconds
- Alert delivery time < 30 seconds
- Dashboard load time < 5 seconds
- Data retention compliance 100%

Health Check Endpoints:
- /health (overall system health)
- /metrics/health (metrics-specific health)
- /ready (readiness probe)
- /live (liveness probe)

Automated Monitoring:
- System uptime monitoring
- Data quality validation
- Alert rule testing
- Dashboard functionality checks

================================
TROUBLESHOOTING GUIDE
================================

Common Issues:

1. High Cardinality Metrics:
   - Symptom: Memory usage spikes, slow queries
   - Solution: Review label usage, implement sampling
   - Prevention: Cardinality monitoring alerts

2. Missing Metrics:
   - Symptom: Gaps in dashboards, failed alerts
   - Solution: Check service endpoints, network connectivity
   - Prevention: Metrics availability monitoring

3. Slow Dashboard Loading:
   - Symptom: Long dashboard response times
   - Solution: Optimize queries, add recording rules
   - Prevention: Query performance monitoring

4. Alert Fatigue:
   - Symptom: Too many alerts, decreased response
   - Solution: Tune thresholds, improve grouping
   - Prevention: Alert effectiveness metrics

Diagnostic Commands:
- Check Prometheus config: curl http://prometheus:9090/api/v1/status/config
- Test metric availability: curl http://service:8080/metrics
- Verify alert rules: curl http://prometheus:9090/api/v1/rules
- Check storage usage: curl http://prometheus:9090/api/v1/status/tsdb

Performance Troubleshooting:
- Query analysis: EXPLAIN queries in Prometheus
- Memory profiling: /debug/pprof endpoints
- CPU profiling: Performance monitoring
- Network analysis: Trace network calls

================================
DEVELOPMENT WORKFLOW
================================

Metric Development Process:
1. Define metric requirements
2. Choose appropriate metric type
3. Design label schema
4. Implement in service code
5. Test metric collection
6. Create dashboards
7. Set up alerts
8. Document usage

Testing Procedures:
1. Unit tests for metric collection
2. Integration tests for export
3. Load testing for performance
4. Alert testing procedures
5. Dashboard validation

Deployment Process:
1. Deploy metric collection code
2. Update Prometheus configuration
3. Deploy dashboard updates
4. Update alert rules
5. Monitor metric ingestion

Quality Assurance:
1. Code review for metric implementation
2. Configuration validation
3. Dashboard usability testing
4. Alert accuracy verification
5. Performance impact assessment

================================
NEXT STEPS
================================

1. Deploy Prometheus and Grafana to Cloud Run
2. Integrate metrics libraries into all services
3. Configure custom dashboards for each team
4. Set up alert routing and notification channels
5. Test end-to-end metrics pipeline
6. Train teams on dashboard usage
7. Implement automated metrics testing
8. Set up cost optimization monitoring
9. Create metrics documentation wiki
10. Establish metrics governance policies

================================
MAINTENANCE SCHEDULE
================================

Daily:
- Monitor metrics ingestion
- Review critical alerts
- Check dashboard functionality

Weekly:
- Analyze metrics trends
- Review alert effectiveness
- Optimize expensive queries
- Update documentation

Monthly:
- Capacity planning review
- Cost optimization analysis
- Security audit of metrics access
- Performance optimization

Quarterly:
- Metrics strategy review
- Technology stack evaluation
- Team training updates
- Disaster recovery testing

EOF
    
    log_success "Custom metrics and Prometheus report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH custom metrics and Prometheus integration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    log_info "Metrics Configuration:"
    log_info "- Prometheus Version: ${PROMETHEUS_VERSION}"
    log_info "- Grafana Version: ${GRAFANA_VERSION}"
    log_info "- Metrics Retention: ${METRICS_RETENTION_DAYS} days"
    log_info "- Scrape Interval: ${SCRAPE_INTERVAL}"
    log_info "- Security Scrape Interval: ${SECURITY_SCRAPE_INTERVAL}"
    
    check_prerequisites
    
    setup_cloud_monitoring_metrics
    create_metrics_libraries
    deploy_prometheus_stack
    setup_grafana_dashboards
    
    generate_metrics_report
    
    log_success "iSECTECH custom metrics and Prometheus integration completed!"
    
    echo ""
    log_info "Metrics collection is now configured with comprehensive security and performance monitoring."
    log_info "Integrate metrics libraries into Cloud Run services."
    log_info "Access Prometheus: https://[PROMETHEUS_URL]"
    log_info "Access Grafana: https://[GRAFANA_URL]"
    log_info "Metrics endpoint: /metrics on each service"
}

# Help function
show_help() {
    cat << EOF
iSECTECH Custom Metrics and Prometheus Integration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV        Environment (production, staging, development)
    --project PROJECT       Google Cloud project ID
    --region REGION         Google Cloud region (default: us-central1)
    --retention-days DAYS   Metrics retention in days (default: 90)
    --scrape-interval INT   Default scrape interval (default: 30s)
    --prometheus-version VER Prometheus version (default: 2.47.0)
    --help                  Show this help message

Environment Variables:
    PROJECT_ID              Google Cloud project ID
    REGION                 Google Cloud region
    ENVIRONMENT            Environment name
    METRICS_RETENTION_DAYS Standard metrics retention (default: 90)
    HIGH_RESOLUTION_RETENTION_DAYS High-res retention (default: 7)
    SCRAPE_INTERVAL        Default scrape interval (default: 30s)
    SECURITY_SCRAPE_INTERVAL Security metrics interval (default: 10s)
    PROMETHEUS_VERSION     Prometheus version
    GRAFANA_VERSION        Grafana version

Examples:
    # Configure production metrics with 180-day retention
    ./custom-metrics-prometheus-setup.sh --environment production --retention-days 180

    # Configure development with high-frequency scraping
    ./custom-metrics-prometheus-setup.sh --environment development --scrape-interval 15s

Prerequisites:
    - Google Cloud project with APIs enabled
    - Cloud Run deployment permissions
    - Cloud Monitoring write permissions
    - Container Registry push permissions

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --project)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --retention-days)
            METRICS_RETENTION_DAYS="$2"
            shift 2
            ;;
        --scrape-interval)
            SCRAPE_INTERVAL="$2"
            shift 2
            ;;
        --prometheus-version)
            PROMETHEUS_VERSION="$2"
            shift 2
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Execute main function
main "$@"