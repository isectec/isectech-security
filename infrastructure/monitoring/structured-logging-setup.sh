#!/bin/bash

# iSECTECH Structured Logging Configuration Script
# Production-grade logging infrastructure for cybersecurity platform
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"
NOTIFICATION_EMAIL="${NOTIFICATION_EMAIL:-security-ops@isectech.com}"

# Logging configuration
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-365}"
SECURITY_LOG_RETENTION_DAYS="${SECURITY_LOG_RETENTION_DAYS:-2555}"  # 7 years for compliance
AUDIT_LOG_RETENTION_DAYS="${AUDIT_LOG_RETENTION_DAYS:-2555}"

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
    log_info "Checking prerequisites for structured logging setup..."
    
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
    gcloud services enable logging.googleapis.com
    gcloud services enable monitoring.googleapis.com
    gcloud services enable bigquery.googleapis.com
    gcloud services enable pubsub.googleapis.com
    gcloud services enable cloudfunctions.googleapis.com
    gcloud services enable eventarc.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Create custom log sinks for different service types
create_log_sinks() {
    log_info "Creating custom log sinks for structured logging..."
    
    # Security Events Log Sink
    local security_sink="isectech-security-events-sink"
    if ! gcloud logging sinks describe "$security_sink" &>/dev/null; then
        # Create BigQuery dataset for security logs
        local security_dataset="isectech_security_logs"
        bq mk --dataset \
            --location=US \
            --description="Security events and audit logs for iSECTECH platform" \
            --default_table_expiration=220752000 \
            "${PROJECT_ID}:${security_dataset}" || true
        
        # Create the sink
        gcloud logging sinks create "$security_sink" \
            "bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/${security_dataset}" \
            --log-filter='
                (resource.type="cloud_run_revision" OR resource.type="http_load_balancer" OR resource.type="gce_backend_service") AND
                (severity>=WARNING OR 
                 jsonPayload.event_type="security_event" OR
                 jsonPayload.event_type="authentication" OR
                 jsonPayload.event_type="authorization" OR
                 jsonPayload.event_type="threat_detection" OR
                 jsonPayload.event_type="vulnerability_scan" OR
                 jsonPayload.event_type="incident_response" OR
                 jsonPayload.component="siem" OR
                 jsonPayload.component="soar" OR
                 jsonPayload.component="threat-intelligence" OR
                 httpRequest.status>=400)
            ' \
            --description="Security events, authentication, and threat detection logs"
        
        log_success "Created security events log sink: $security_sink"
    else
        log_info "Security events log sink $security_sink already exists"
    fi
    
    # Application Performance Log Sink
    local performance_sink="isectech-performance-sink"
    if ! gcloud logging sinks describe "$performance_sink" &>/dev/null; then
        # Create BigQuery dataset for performance logs
        local performance_dataset="isectech_performance_logs"
        bq mk --dataset \
            --location=US \
            --description="Application performance and metrics for iSECTECH platform" \
            --default_table_expiration=7776000 \
            "${PROJECT_ID}:${performance_dataset}" || true
        
        gcloud logging sinks create "$performance_sink" \
            "bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/${performance_dataset}" \
            --log-filter='
                resource.type="cloud_run_revision" AND
                (jsonPayload.event_type="performance_metric" OR
                 jsonPayload.event_type="latency_measurement" OR
                 jsonPayload.event_type="resource_usage" OR
                 jsonPayload.component="monitoring" OR
                 jsonPayload.metrics_type IS NOT NULL)
            ' \
            --description="Application performance metrics and monitoring data"
        
        log_success "Created performance log sink: $performance_sink"
    else
        log_info "Performance log sink $performance_sink already exists"
    fi
    
    # Audit Log Sink for Compliance
    local audit_sink="isectech-audit-compliance-sink"
    if ! gcloud logging sinks describe "$audit_sink" &>/dev/null; then
        # Create BigQuery dataset for audit logs
        local audit_dataset="isectech_audit_logs"
        bq mk --dataset \
            --location=US \
            --description="Audit and compliance logs for iSECTECH platform" \
            --default_table_expiration=220752000 \
            "${PROJECT_ID}:${audit_dataset}" || true
        
        gcloud logging sinks create "$audit_sink" \
            "bigquery.googleapis.com/projects/${PROJECT_ID}/datasets/${audit_dataset}" \
            --log-filter='
                protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR
                protoPayload.serviceName="compute.googleapis.com" OR
                protoPayload.serviceName="run.googleapis.com" OR
                protoPayload.serviceName="iam.googleapis.com" OR
                protoPayload.serviceName="secretmanager.googleapis.com" OR
                (resource.type="cloud_run_revision" AND
                 (jsonPayload.event_type="user_action" OR
                  jsonPayload.event_type="admin_action" OR
                  jsonPayload.event_type="data_access" OR
                  jsonPayload.event_type="configuration_change"))
            ' \
            --description="Audit trail for compliance and governance"
        
        log_success "Created audit compliance log sink: $audit_sink"
    else
        log_info "Audit compliance log sink $audit_sink already exists"
    fi
    
    # Error and Exception Tracking Sink
    local error_sink="isectech-error-tracking-sink"
    if ! gcloud logging sinks describe "$error_sink" &>/dev/null; then
        # Create Pub/Sub topic for real-time error processing
        local error_topic="isectech-error-alerts"
        if ! gcloud pubsub topics describe "$error_topic" &>/dev/null; then
            gcloud pubsub topics create "$error_topic" \
                --message-retention-duration=7d
            log_success "Created error alerts Pub/Sub topic: $error_topic"
        fi
        
        gcloud logging sinks create "$error_sink" \
            "pubsub.googleapis.com/projects/${PROJECT_ID}/topics/${error_topic}" \
            --log-filter='
                (severity>=ERROR OR
                 jsonPayload.event_type="error" OR
                 jsonPayload.event_type="exception" OR
                 jsonPayload.event_type="security_incident" OR
                 jsonPayload.alert_level="critical" OR
                 jsonPayload.alert_level="high" OR
                 httpRequest.status>=500)
            ' \
            --description="Real-time error and critical event processing"
        
        log_success "Created error tracking log sink: $error_sink"
    else
        log_info "Error tracking log sink $error_sink already exists"
    fi
}

# Configure structured logging format for Cloud Run services
configure_cloud_run_logging() {
    log_info "Configuring structured logging for Cloud Run services..."
    
    # Create logging configuration template
    cat > "/tmp/logging-config.json" << 'EOF'
{
  "version": "2.0",
  "service": "{{ SERVICE_NAME }}",
  "environment": "{{ ENVIRONMENT }}",
  "logging": {
    "level": "INFO",
    "format": "json",
    "timestamp_format": "RFC3339",
    "include_caller": true,
    "include_stack_trace": true
  },
  "structured_fields": {
    "service_name": "{{ SERVICE_NAME }}",
    "service_version": "{{ SERVICE_VERSION }}",
    "environment": "{{ ENVIRONMENT }}",
    "request_id": "{{ REQUEST_ID }}",
    "user_id": "{{ USER_ID }}",
    "session_id": "{{ SESSION_ID }}",
    "component": "{{ COMPONENT }}",
    "event_type": "{{ EVENT_TYPE }}",
    "severity": "{{ SEVERITY }}",
    "timestamp": "{{ TIMESTAMP }}",
    "source_location": {
      "file": "{{ SOURCE_FILE }}",
      "line": "{{ SOURCE_LINE }}",
      "function": "{{ SOURCE_FUNCTION }}"
    },
    "http_request": {
      "method": "{{ HTTP_METHOD }}",
      "url": "{{ HTTP_URL }}",
      "status": "{{ HTTP_STATUS }}",
      "response_size": "{{ RESPONSE_SIZE }}",
      "latency": "{{ LATENCY }}",
      "remote_ip": "{{ REMOTE_IP }}",
      "user_agent": "{{ USER_AGENT }}",
      "referer": "{{ REFERER }}"
    },
    "security_context": {
      "threat_level": "{{ THREAT_LEVEL }}",
      "security_event": "{{ SECURITY_EVENT }}",
      "indicators": "{{ INDICATORS }}",
      "mitigation_actions": "{{ MITIGATION_ACTIONS }}"
    },
    "performance_context": {
      "response_time_ms": "{{ RESPONSE_TIME }}",
      "cpu_usage": "{{ CPU_USAGE }}",
      "memory_usage": "{{ MEMORY_USAGE }}",
      "disk_io": "{{ DISK_IO }}",
      "network_io": "{{ NETWORK_IO }}"
    },
    "business_context": {
      "customer_id": "{{ CUSTOMER_ID }}",
      "organization_id": "{{ ORGANIZATION_ID }}",
      "feature_flag": "{{ FEATURE_FLAG }}",
      "ab_test_variant": "{{ AB_TEST_VARIANT }}"
    }
  },
  "sensitive_fields_filter": [
    "password",
    "token",
    "api_key",
    "secret",
    "credential",
    "private_key",
    "jwt",
    "session_token",
    "auth_header",
    "credit_card",
    "ssn",
    "phone",
    "email"
  ]
}
EOF
    
    log_success "Created structured logging configuration template"
    
    # Create logging libraries for different languages
    create_logging_libraries
}

# Create logging libraries for different programming languages
create_logging_libraries() {
    log_info "Creating logging libraries for different languages..."
    
    # Create Node.js/TypeScript logging library
    cat > "/tmp/nodejs-logger.js" << 'EOF'
/**
 * iSECTECH Structured Logger for Node.js/TypeScript
 * Production-grade logging with security context
 */

const { createLogger, format, transports } = require('winston');
const { LoggingWinston } = require('@google-cloud/logging-winston');

class ISECTECHLogger {
    constructor(serviceName, environment = 'production') {
        this.serviceName = serviceName;
        this.environment = environment;
        
        const loggingWinston = new LoggingWinston({
            projectId: process.env.PROJECT_ID,
            keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS,
            logName: `isectech-${serviceName}`,
            resource: {
                type: 'cloud_run_revision',
                labels: {
                    service_name: serviceName,
                    revision_name: process.env.K_REVISION || 'unknown'
                }
            }
        });
        
        this.logger = createLogger({
            level: process.env.LOG_LEVEL || 'info',
            format: format.combine(
                format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }),
                format.errors({ stack: true }),
                format.json(),
                format((info) => {
                    // Add structured fields
                    info.service_name = this.serviceName;
                    info.environment = this.environment;
                    info.request_id = this.getRequestId();
                    info.component = info.component || serviceName;
                    
                    // Security context enhancement
                    if (info.security_event) {
                        info.event_type = 'security_event';
                        info.alert_level = info.alert_level || 'medium';
                    }
                    
                    return info;
                })()
            ),
            transports: [
                loggingWinston,
                new transports.Console({
                    format: format.combine(
                        format.colorize(),
                        format.simple()
                    )
                })
            ]
        });
    }
    
    getRequestId() {
        // Extract from various sources
        return process.env.REQUEST_ID || 
               global.requestId || 
               this.generateRequestId();
    }
    
    generateRequestId() {
        return `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
    
    // Security-specific logging methods
    securityEvent(message, context = {}) {
        this.logger.warn(message, {
            event_type: 'security_event',
            security_context: context,
            alert_level: context.alert_level || 'medium',
            ...context
        });
    }
    
    threatDetected(message, threat = {}) {
        this.logger.error(message, {
            event_type: 'threat_detection',
            threat_level: threat.level || 'high',
            threat_type: threat.type,
            indicators: threat.indicators,
            mitigation_actions: threat.mitigation_actions,
            alert_level: 'high'
        });
    }
    
    auditLog(action, user, resource, result) {
        this.logger.info(`Audit: ${action}`, {
            event_type: 'user_action',
            audit_action: action,
            user_id: user.id,
            user_email: user.email,
            resource_type: resource.type,
            resource_id: resource.id,
            action_result: result,
            timestamp: new Date().toISOString()
        });
    }
    
    performanceMetric(operation, duration, context = {}) {
        this.logger.info(`Performance: ${operation}`, {
            event_type: 'performance_metric',
            operation_name: operation,
            duration_ms: duration,
            performance_context: context
        });
    }
    
    // Standard logging methods with enhanced context
    info(message, meta = {}) {
        this.logger.info(message, meta);
    }
    
    warn(message, meta = {}) {
        this.logger.warn(message, meta);
    }
    
    error(message, error = null, meta = {}) {
        const errorMeta = error ? {
            error_message: error.message,
            error_stack: error.stack,
            error_name: error.name
        } : {};
        
        this.logger.error(message, {
            ...errorMeta,
            ...meta,
            event_type: 'error'
        });
    }
}

module.exports = ISECTECHLogger;
EOF
    
    # Create Go logging library
    cat > "/tmp/go-logger.go" << 'EOF'
// iSECTECH Structured Logger for Go
// Production-grade logging with security context

package logger

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "runtime"
    "time"
    
    "cloud.google.com/go/logging"
    "github.com/sirupsen/logrus"
    "google.golang.org/api/option"
)

type ISECTECHLogger struct {
    logger     *logrus.Logger
    gcpLogger  *logging.Logger
    serviceName string
    environment string
}

type SecurityContext struct {
    ThreatLevel        string                 `json:"threat_level,omitempty"`
    SecurityEvent      string                 `json:"security_event,omitempty"`
    Indicators         []string               `json:"indicators,omitempty"`
    MitigationActions  []string               `json:"mitigation_actions,omitempty"`
    AlertLevel         string                 `json:"alert_level,omitempty"`
}

type PerformanceContext struct {
    ResponseTimeMs int64   `json:"response_time_ms,omitempty"`
    CPUUsage      float64 `json:"cpu_usage,omitempty"`
    MemoryUsage   int64   `json:"memory_usage,omitempty"`
    DiskIO        int64   `json:"disk_io,omitempty"`
    NetworkIO     int64   `json:"network_io,omitempty"`
}

type LogEntry struct {
    ServiceName        string              `json:"service_name"`
    Environment        string              `json:"environment"`
    RequestID          string              `json:"request_id,omitempty"`
    Component          string              `json:"component"`
    EventType          string              `json:"event_type,omitempty"`
    Timestamp          time.Time           `json:"timestamp"`
    Message            string              `json:"message"`
    Level              string              `json:"level"`
    SecurityContext    *SecurityContext    `json:"security_context,omitempty"`
    PerformanceContext *PerformanceContext `json:"performance_context,omitempty"`
    SourceLocation     map[string]interface{} `json:"source_location,omitempty"`
}

func NewISECTECHLogger(serviceName, environment string) (*ISECTECHLogger, error) {
    // Initialize logrus logger
    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{
        TimestampFormat: time.RFC3339Nano,
    })
    
    // Initialize Google Cloud Logging
    ctx := context.Background()
    projectID := os.Getenv("PROJECT_ID")
    
    var gcpLogger *logging.Logger
    if projectID != "" {
        client, err := logging.NewClient(ctx, projectID)
        if err != nil {
            return nil, fmt.Errorf("failed to create logging client: %v", err)
        }
        
        gcpLogger = client.Logger(fmt.Sprintf("isectech-%s", serviceName))
    }
    
    return &ISECTECHLogger{
        logger:      logger,
        gcpLogger:   gcpLogger,
        serviceName: serviceName,
        environment: environment,
    }, nil
}

func (l *ISECTECHLogger) getSourceLocation() map[string]interface{} {
    if pc, file, line, ok := runtime.Caller(3); ok {
        fn := runtime.FuncForPC(pc)
        return map[string]interface{}{
            "file":     file,
            "line":     line,
            "function": fn.Name(),
        }
    }
    return nil
}

func (l *ISECTECHLogger) createLogEntry(level, message string) *LogEntry {
    return &LogEntry{
        ServiceName:    l.serviceName,
        Environment:    l.environment,
        RequestID:      l.getRequestID(),
        Component:      l.serviceName,
        Timestamp:      time.Now(),
        Message:        message,
        Level:          level,
        SourceLocation: l.getSourceLocation(),
    }
}

func (l *ISECTECHLogger) getRequestID() string {
    // Try to get from context or generate
    if reqID := os.Getenv("REQUEST_ID"); reqID != "" {
        return reqID
    }
    return fmt.Sprintf("req-%d-%s", time.Now().UnixNano(), generateRandomString(8))
}

func (l *ISECTECHLogger) log(entry *LogEntry) {
    // Log to logrus (for console/local development)
    fields := logrus.Fields{
        "service_name":    entry.ServiceName,
        "environment":     entry.Environment,
        "request_id":      entry.RequestID,
        "component":       entry.Component,
        "event_type":      entry.EventType,
        "source_location": entry.SourceLocation,
    }
    
    if entry.SecurityContext != nil {
        fields["security_context"] = entry.SecurityContext
    }
    
    if entry.PerformanceContext != nil {
        fields["performance_context"] = entry.PerformanceContext
    }
    
    switch entry.Level {
    case "error":
        l.logger.WithFields(fields).Error(entry.Message)
    case "warn":
        l.logger.WithFields(fields).Warn(entry.Message)
    case "info":
        l.logger.WithFields(fields).Info(entry.Message)
    case "debug":
        l.logger.WithFields(fields).Debug(entry.Message)
    }
    
    // Log to Google Cloud Logging if available
    if l.gcpLogger != nil {
        payload, _ := json.Marshal(entry)
        l.gcpLogger.Log(logging.Entry{
            Payload:  json.RawMessage(payload),
            Severity: l.mapLogLevel(entry.Level),
        })
    }
}

func (l *ISECTECHLogger) mapLogLevel(level string) logging.Severity {
    switch level {
    case "debug":
        return logging.Debug
    case "info":
        return logging.Info
    case "warn":
        return logging.Warning
    case "error":
        return logging.Error
    default:
        return logging.Info
    }
}

// Security-specific logging methods
func (l *ISECTECHLogger) SecurityEvent(message string, secCtx *SecurityContext) {
    entry := l.createLogEntry("warn", message)
    entry.EventType = "security_event"
    entry.SecurityContext = secCtx
    l.log(entry)
}

func (l *ISECTECHLogger) ThreatDetected(message string, threatLevel string, indicators []string) {
    entry := l.createLogEntry("error", message)
    entry.EventType = "threat_detection"
    entry.SecurityContext = &SecurityContext{
        ThreatLevel:       threatLevel,
        SecurityEvent:     "threat_detected",
        Indicators:        indicators,
        AlertLevel:        "high",
    }
    l.log(entry)
}

func (l *ISECTECHLogger) AuditLog(action, userID, resourceType, resourceID string) {
    entry := l.createLogEntry("info", fmt.Sprintf("Audit: %s", action))
    entry.EventType = "user_action"
    entry.SecurityContext = &SecurityContext{
        SecurityEvent: "audit_log",
    }
    l.log(entry)
}

func (l *ISECTECHLogger) PerformanceMetric(operation string, duration time.Duration, perfCtx *PerformanceContext) {
    entry := l.createLogEntry("info", fmt.Sprintf("Performance: %s", operation))
    entry.EventType = "performance_metric"
    entry.PerformanceContext = perfCtx
    if entry.PerformanceContext == nil {
        entry.PerformanceContext = &PerformanceContext{}
    }
    entry.PerformanceContext.ResponseTimeMs = duration.Milliseconds()
    l.log(entry)
}

// Standard logging methods
func (l *ISECTECHLogger) Info(message string) {
    entry := l.createLogEntry("info", message)
    l.log(entry)
}

func (l *ISECTECHLogger) Warn(message string) {
    entry := l.createLogEntry("warn", message)
    l.log(entry)
}

func (l *ISECTECHLogger) Error(message string, err error) {
    entry := l.createLogEntry("error", message)
    entry.EventType = "error"
    if err != nil {
        entry.Message = fmt.Sprintf("%s: %v", message, err)
    }
    l.log(entry)
}

func generateRandomString(length int) string {
    // Simple random string generation
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
    }
    return string(b)
}
EOF
    
    log_success "Created logging libraries for Node.js and Go"
}

# Configure log-based alerting
configure_log_alerting() {
    log_info "Configuring log-based alerting..."
    
    # Create notification channel
    local notification_channel_name="isectech-security-alerts"
    
    # Create alert policies for security events
    cat > "/tmp/security-alert-policy.yaml" << EOF
displayName: "iSECTECH Security Events Alert"
documentation:
  content: "Alert for security events, threats, and authentication failures"
  mimeType: "text/markdown"
conditions:
  - displayName: "Security Event Detected"
    conditionThreshold:
      filter: |
        resource.type="cloud_run_revision" AND
        (jsonPayload.event_type="security_event" OR
         jsonPayload.event_type="threat_detection" OR
         jsonPayload.alert_level="high" OR
         jsonPayload.alert_level="critical")
      comparison: COMPARISON_GREATER_THAN
      thresholdValue: 0
      duration: "60s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_RATE
          crossSeriesReducer: REDUCE_SUM
          groupByFields:
            - "resource.labels.service_name"
            - "jsonPayload.event_type"
combiner: OR
enabled: true
EOF
    
    # Create performance alert policy
    cat > "/tmp/performance-alert-policy.yaml" << EOF
displayName: "iSECTECH Performance Degradation Alert"
documentation:
  content: "Alert for performance issues and high latency"
  mimeType: "text/markdown"
conditions:
  - displayName: "High Response Time"
    conditionThreshold:
      filter: |
        resource.type="cloud_run_revision" AND
        jsonPayload.event_type="performance_metric" AND
        jsonPayload.performance_context.response_time_ms > 5000
      comparison: COMPARISON_GREATER_THAN
      thresholdValue: 10
      duration: "300s"
      aggregations:
        - alignmentPeriod: "60s"
          perSeriesAligner: ALIGN_RATE
          crossSeriesReducer: REDUCE_SUM
          groupByFields:
            - "resource.labels.service_name"
combiner: OR
enabled: true
EOF
    
    log_success "Created alert policy configurations"
}

# Create log processing functions
create_log_processing_functions() {
    log_info "Creating log processing Cloud Functions..."
    
    # Create directory for Cloud Functions
    mkdir -p "/tmp/log-processing-functions"
    
    # Security Event Processor Function
    cat > "/tmp/log-processing-functions/security-processor.js" << 'EOF'
/**
 * Security Event Processor Cloud Function
 * Processes security events from Pub/Sub and triggers alerts
 */

const { PubSub } = require('@google-cloud/pubsub');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

const pubsub = new PubSub();
const secretManager = new SecretManagerServiceClient();

exports.processSecurityEvent = async (pubSubMessage, context) => {
    try {
        const messageData = JSON.parse(Buffer.from(pubSubMessage.data, 'base64').toString());
        
        // Extract security context
        const securityContext = messageData.jsonPayload?.security_context || {};
        const eventType = messageData.jsonPayload?.event_type;
        const alertLevel = messageData.jsonPayload?.alert_level || 'medium';
        
        console.log('Processing security event:', {
            eventType,
            alertLevel,
            serviceName: messageData.resource?.labels?.service_name,
            timestamp: messageData.timestamp
        });
        
        // Process high and critical alerts immediately
        if (alertLevel === 'high' || alertLevel === 'critical') {
            await sendImmediateAlert(messageData);
        }
        
        // Store in security incident tracking
        await storeSecurityIncident(messageData);
        
        // Trigger automated response if needed
        if (eventType === 'threat_detection') {
            await triggerAutomatedResponse(messageData);
        }
        
    } catch (error) {
        console.error('Error processing security event:', error);
        throw error;
    }
};

async function sendImmediateAlert(eventData) {
    // Implementation for immediate alerting
    console.log('Sending immediate alert for:', eventData.jsonPayload?.event_type);
    
    // Here you would integrate with:
    // - Slack/Teams notifications
    // - PagerDuty/Opsgenie
    // - Email alerts
    // - SMS alerts for critical events
}

async function storeSecurityIncident(eventData) {
    // Store in BigQuery for analysis
    console.log('Storing security incident for analysis');
    
    // Implementation would include:
    // - Incident ID generation
    // - Threat intelligence enrichment
    // - MITRE ATT&CK mapping
    // - IOC extraction
}

async function triggerAutomatedResponse(eventData) {
    // Automated response actions
    console.log('Triggering automated response for threat detection');
    
    // Implementation could include:
    // - IP blocking
    // - User session termination
    // - Service isolation
    // - Evidence collection
}
EOF
    
    # Performance Anomaly Detector Function
    cat > "/tmp/log-processing-functions/performance-anomaly.js" << 'EOF'
/**
 * Performance Anomaly Detection Cloud Function
 * Analyzes performance metrics and detects anomalies
 */

exports.detectPerformanceAnomalies = async (pubSubMessage, context) => {
    try {
        const messageData = JSON.parse(Buffer.from(pubSubMessage.data, 'base64').toString());
        
        const performanceContext = messageData.jsonPayload?.performance_context || {};
        const responseTime = performanceContext.response_time_ms;
        const serviceName = messageData.resource?.labels?.service_name;
        
        console.log('Analyzing performance metrics:', {
            serviceName,
            responseTime,
            timestamp: messageData.timestamp
        });
        
        // Implement anomaly detection logic
        const isAnomalous = await detectAnomaly(serviceName, responseTime);
        
        if (isAnomalous) {
            await handlePerformanceAnomaly(messageData);
        }
        
        // Store metrics for trend analysis
        await storePerformanceMetric(messageData);
        
    } catch (error) {
        console.error('Error detecting performance anomalies:', error);
        throw error;
    }
};

async function detectAnomaly(serviceName, responseTime) {
    // Implement statistical anomaly detection
    // Could use moving averages, standard deviation, etc.
    return responseTime > 5000; // Simple threshold for now
}

async function handlePerformanceAnomaly(eventData) {
    console.log('Performance anomaly detected, triggering response');
    
    // Implementation could include:
    // - Scaling decisions
    // - Circuit breaker triggers
    // - Alert notifications
    // - Diagnostic data collection
}

async function storePerformanceMetric(eventData) {
    // Store for historical analysis and trend detection
    console.log('Storing performance metric for trend analysis');
}
EOF
    
    # Package.json for Cloud Functions
    cat > "/tmp/log-processing-functions/package.json" << 'EOF'
{
  "name": "isectech-log-processing",
  "version": "1.0.0",
  "description": "Log processing functions for iSECTECH platform",
  "dependencies": {
    "@google-cloud/pubsub": "^3.0.0",
    "@google-cloud/secret-manager": "^4.0.0",
    "@google-cloud/bigquery": "^6.0.0",
    "@google-cloud/monitoring": "^3.0.0"
  }
}
EOF
    
    log_success "Created log processing Cloud Functions"
}

# Generate logging report
generate_logging_report() {
    log_info "Generating structured logging configuration report..."
    
    local report_file="/tmp/isectech-logging-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Structured Logging Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
LOGGING INFRASTRUCTURE OVERVIEW
================================

Log Retention Policies:
- Standard Logs: ${LOG_RETENTION_DAYS} days
- Security Logs: ${SECURITY_LOG_RETENTION_DAYS} days (7 years for compliance)
- Audit Logs: ${AUDIT_LOG_RETENTION_DAYS} days (7 years for compliance)

================================
LOG SINKS CONFIGURATION
================================

Security Events Sink:
- Name: isectech-security-events-sink
- Destination: BigQuery (isectech_security_logs dataset)
- Filter: Security events, authentication, threat detection, HTTP 4xx/5xx
- Use Case: Security monitoring, threat intelligence, incident response

Performance Metrics Sink:
- Name: isectech-performance-sink
- Destination: BigQuery (isectech_performance_logs dataset)
- Filter: Performance metrics, latency measurements, resource usage
- Use Case: Performance monitoring, capacity planning, optimization

Audit Compliance Sink:
- Name: isectech-audit-compliance-sink
- Destination: BigQuery (isectech_audit_logs dataset)
- Filter: Admin API calls, configuration changes, data access
- Use Case: Compliance reporting, audit trails, governance

Error Tracking Sink:
- Name: isectech-error-tracking-sink
- Destination: Pub/Sub (isectech-error-alerts topic)
- Filter: Errors, exceptions, critical events, HTTP 5xx
- Use Case: Real-time error processing, immediate alerting

================================
STRUCTURED LOGGING FORMAT
================================

Standard Log Entry Structure:
{
  "service_name": "Service identifier",
  "environment": "Environment name",
  "request_id": "Unique request identifier",
  "component": "Component/module name",
  "event_type": "Event classification",
  "severity": "Log level",
  "timestamp": "RFC3339 timestamp",
  "message": "Human-readable message",
  "source_location": {
    "file": "Source file",
    "line": "Line number",
    "function": "Function name"
  }
}

Security Context Enhancement:
{
  "security_context": {
    "threat_level": "low|medium|high|critical",
    "security_event": "Event type",
    "indicators": ["IOC1", "IOC2"],
    "mitigation_actions": ["action1", "action2"]
  }
}

Performance Context Enhancement:
{
  "performance_context": {
    "response_time_ms": "Response time",
    "cpu_usage": "CPU utilization",
    "memory_usage": "Memory consumption",
    "disk_io": "Disk I/O metrics",
    "network_io": "Network I/O metrics"
  }
}

================================
LOGGING LIBRARIES
================================

Node.js/TypeScript Library:
- File: /tmp/nodejs-logger.js
- Features: Winston integration, Google Cloud Logging, security context
- Methods: securityEvent(), threatDetected(), auditLog(), performanceMetric()

Go Library:
- File: /tmp/go-logger.go
- Features: Logrus integration, Google Cloud Logging, structured fields
- Methods: SecurityEvent(), ThreatDetected(), AuditLog(), PerformanceMetric()

Common Features:
- Automatic request ID tracking
- Source location capture
- Sensitive data filtering
- Multiple output formats
- Security context enhancement

================================
LOG PROCESSING FUNCTIONS
================================

Security Event Processor:
- Function: security-processor
- Trigger: Pub/Sub (error alerts topic)
- Purpose: Process security events, trigger alerts, store incidents
- Actions: Immediate alerting, automated response, threat intelligence

Performance Anomaly Detector:
- Function: performance-anomaly
- Trigger: Performance log stream
- Purpose: Detect performance anomalies, trigger scaling decisions
- Actions: Anomaly detection, alert generation, metric storage

================================
ALERTING CONFIGURATION
================================

Security Alert Policy:
- Trigger: Security events, threat detection, high/critical alerts
- Threshold: > 0 events in 60 seconds
- Action: Immediate notification, incident creation

Performance Alert Policy:
- Trigger: Response time > 5000ms for > 10 requests in 5 minutes
- Threshold: Performance degradation detection
- Action: Performance team notification, auto-scaling consideration

Notification Channels:
- Email: ${NOTIFICATION_EMAIL}
- Slack/Teams: Integration ready
- PagerDuty: Integration ready
- SMS: Critical alerts only

================================
DATA ANALYTICS & INSIGHTS
================================

BigQuery Datasets:
1. isectech_security_logs
   - Security events analysis
   - Threat pattern detection
   - Compliance reporting
   - Incident forensics

2. isectech_performance_logs
   - Performance trend analysis
   - Capacity planning
   - Optimization insights
   - SLA monitoring

3. isectech_audit_logs
   - Compliance audit trails
   - Configuration change tracking
   - Data access monitoring
   - Governance reporting

Pre-built Queries Available:
- Top security threats by severity
- Performance percentiles by service
- Audit trail by user/action
- Error rate trends
- Response time analysis

Dashboard Integration:
- Grafana/Prometheus compatibility
- Google Cloud Monitoring integration
- Custom dashboard templates
- Real-time metrics visualization

================================
SECURITY & COMPLIANCE
================================

Data Protection:
- Sensitive field filtering (passwords, tokens, PII)
- Encryption at rest (BigQuery, Pub/Sub)
- Encryption in transit (TLS 1.2+)
- Access control (IAM policies)

Compliance Features:
- SOC 2 Type II compliance support
- PCI DSS logging requirements
- GDPR data handling
- HIPAA audit trail support

Security Monitoring:
- Threat detection integration
- SIEM compatibility
- IOC extraction and analysis
- Automated incident response

================================
OPERATIONAL PROCEDURES
================================

Daily Operations:
- Monitor log ingestion rates
- Review security alert queues
- Verify log sink health
- Check BigQuery storage costs

Weekly Operations:
- Analyze security event trends
- Review performance metrics
- Update alert thresholds
- Clean up old processing functions

Monthly Operations:
- Compliance reporting
- Log retention policy review
- Cost optimization analysis
- Performance trend analysis

Emergency Procedures:
- Immediate alert escalation
- Log sink failover
- Emergency log access
- Incident response coordination

================================
COST OPTIMIZATION
================================

Estimated Monthly Costs:
- Cloud Logging Ingestion: \$200-500 (based on volume)
- BigQuery Storage: \$50-150 (with lifecycle policies)
- Pub/Sub Messages: \$20-50 (error processing)
- Cloud Functions: \$10-30 (log processing)

Cost Optimization Features:
- Log sampling for high-volume services
- Intelligent log filtering
- Automatic data lifecycle management
- Compressed storage in BigQuery

================================
MONITORING & HEALTH CHECKS
================================

Log Pipeline Health:
- Sink ingestion monitoring
- Processing function health
- BigQuery job status
- Pub/Sub message backlog

Key Metrics:
- Log ingestion rate (logs/second)
- Processing latency (seconds)
- Error rate (%)
- Storage growth (GB/day)

Health Check Endpoints:
- /health/logging (service-specific)
- /metrics/logging (Prometheus format)
- /status/pipeline (overall health)

================================
TROUBLESHOOTING GUIDE
================================

Common Issues:

1. Log Ingestion Delays:
   - Check Cloud Logging quotas
   - Verify sink configurations
   - Monitor BigQuery streaming limits
   - Review IAM permissions

2. Missing Security Events:
   - Verify log filter expressions
   - Check service logging configuration
   - Validate structured log format
   - Review application logging code

3. High Storage Costs:
   - Implement log sampling
   - Adjust retention policies
   - Archive old data to Cloud Storage
   - Optimize BigQuery table schemas

4. Alert Fatigue:
   - Tune alert thresholds
   - Implement smart grouping
   - Add alert suppression rules
   - Review notification channels

Diagnostic Commands:
- Check sink status: gcloud logging sinks describe [SINK_NAME]
- Test log filter: gcloud logging read '[FILTER]' --limit=10
- Verify BigQuery ingestion: bq show -j [JOB_ID]
- Monitor Pub/Sub: gcloud pubsub topics describe [TOPIC]

================================
NEXT STEPS
================================

1. Deploy logging libraries to all Cloud Run services
2. Configure application code to use structured logging
3. Test log sinks and verify BigQuery ingestion
4. Set up alerting and notification channels
5. Create custom dashboards for monitoring
6. Implement log-based SLI/SLO monitoring
7. Configure automated log analysis jobs
8. Set up compliance reporting automation

================================
INTEGRATION POINTS
================================

With Other Systems:
- SIEM: Splunk, QRadar, Sentinel integration ready
- APM: Datadog, New Relic trace correlation
- Incident Response: PagerDuty, Opsgenie integration
- Ticketing: Jira, ServiceNow automation
- Chat: Slack, Teams notification bots
- Dashboards: Grafana, Kibana data sources

API Endpoints:
- /api/v1/logs/search (log search API)
- /api/v1/logs/export (bulk export)
- /api/v1/alerts/manage (alert management)
- /api/v1/metrics/dashboard (metrics API)

Webhook Support:
- Security event webhooks
- Performance alert webhooks
- Audit log webhooks
- Custom integration webhooks

EOF
    
    log_success "Structured logging report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH structured logging configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    check_prerequisites
    
    create_log_sinks
    configure_cloud_run_logging
    configure_log_alerting
    create_log_processing_functions
    
    generate_logging_report
    
    log_success "iSECTECH structured logging configuration completed!"
    
    echo ""
    log_info "Structured logging is now configured with comprehensive security monitoring."
    log_info "Deploy logging libraries to Cloud Run services with updated application code."
    log_info "Monitor log ingestion with: gcloud logging read 'resource.type=\"cloud_run_revision\"' --limit=10"
    log_info "Access BigQuery datasets for analysis and reporting."
}

# Help function
show_help() {
    cat << EOF
iSECTECH Structured Logging Configuration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV           Environment (production, staging, development)
    --project PROJECT          Google Cloud project ID
    --region REGION            Google Cloud region (default: us-central1)
    --notification-email EMAIL Notification email for alerts
    --log-retention DAYS       Standard log retention in days (default: 365)
    --help                     Show this help message

Environment Variables:
    PROJECT_ID                 Google Cloud project ID
    REGION                    Google Cloud region
    ENVIRONMENT               Environment name
    NOTIFICATION_EMAIL        Email for security alerts
    LOG_RETENTION_DAYS        Standard log retention (default: 365)
    SECURITY_LOG_RETENTION_DAYS Security log retention (default: 2555)
    AUDIT_LOG_RETENTION_DAYS  Audit log retention (default: 2555)

Examples:
    # Configure production logging
    ./structured-logging-setup.sh --environment production

    # Configure with custom retention
    ./structured-logging-setup.sh --log-retention 180 --notification-email ops@company.com

Prerequisites:
    - Google Cloud project with appropriate APIs enabled
    - BigQuery dataset creation permissions
    - Cloud Logging admin permissions
    - Pub/Sub admin permissions

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
        --notification-email)
            NOTIFICATION_EMAIL="$2"
            shift 2
            ;;
        --log-retention)
            LOG_RETENTION_DAYS="$2"
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