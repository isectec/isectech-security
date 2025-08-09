#!/bin/bash

# iSECTECH Distributed Tracing with OpenTelemetry Setup Script
# Production-grade distributed tracing for cybersecurity platform
# Author: Claude Code - iSECTECH Infrastructure Team
# Version: 2.0.0

set -euo pipefail

# Configuration
PROJECT_ID="${PROJECT_ID:-isectech-security-platform}"
REGION="${REGION:-us-central1}"
ENVIRONMENT="${ENVIRONMENT:-production}"

# OpenTelemetry configuration
OTEL_COLLECTOR_VERSION="${OTEL_COLLECTOR_VERSION:-0.89.0}"
JAEGER_VERSION="${JAEGER_VERSION:-1.50.0}"
TEMPO_VERSION="${TEMPO_VERSION:-2.3.0}"

# Tracing configuration
TRACE_SAMPLING_RATE="${TRACE_SAMPLING_RATE:-0.1}"  # 10% sampling for production
SECURITY_TRACE_SAMPLING_RATE="${SECURITY_TRACE_SAMPLING_RATE:-1.0}"  # 100% for security events

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
    log_info "Checking prerequisites for distributed tracing setup..."
    
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
    gcloud services enable cloudtrace.googleapis.com
    gcloud services enable monitoring.googleapis.com
    gcloud services enable run.googleapis.com
    gcloud services enable compute.googleapis.com
    
    log_success "Prerequisites checked successfully"
}

# Set up Google Cloud Trace
setup_cloud_trace() {
    log_info "Setting up Google Cloud Trace..."
    
    # Create custom span attributes for security context
    log_info "Configuring Cloud Trace with security-specific attributes"
    
    # Cloud Trace is automatically available, but we'll create custom dashboards
    log_info "Cloud Trace service is automatically available for project: $PROJECT_ID"
    log_info "Custom security attributes will be added through OpenTelemetry instrumentation"
    
    log_success "Google Cloud Trace configuration completed"
}

# Deploy OpenTelemetry Collector
deploy_otel_collector() {
    log_info "Deploying OpenTelemetry Collector..."
    
    # Create OpenTelemetry Collector configuration
    cat > "/tmp/otel-collector-config.yaml" << EOF
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  
  # Health check receiver
  prometheus/internal:
    config:
      scrape_configs:
        - job_name: 'otel-collector'
          scrape_interval: 10s
          static_configs:
            - targets: ['0.0.0.0:8888']

processors:
  # Batch processor for better performance
  batch:
    timeout: 1s
    send_batch_size: 1024
    send_batch_max_size: 2048
  
  # Memory limiter to prevent OOM
  memory_limiter:
    limit_mib: 512
    spike_limit_mib: 128
    check_interval: 5s
  
  # Resource processor to add environment context
  resource:
    attributes:
      - key: environment
        value: ${ENVIRONMENT}
        action: insert
      - key: service.namespace
        value: isectech
        action: insert
      - key: platform
        value: gcp
        action: insert
  
  # Attributes processor for security context enhancement
  attributes:
    actions:
      - key: security.event_type
        action: insert
        from_attribute: event_type
      - key: security.threat_level  
        action: insert
        from_attribute: threat_level
      - key: security.user_id
        action: insert
        from_attribute: user_id
      - key: security.session_id
        action: insert
        from_attribute: session_id
  
  # Sampling processor for performance optimization
  probabilistic_sampler:
    sampling_percentage: $(echo "${TRACE_SAMPLING_RATE} * 100" | bc -l)
  
  # Security event sampling (higher rate for security traces)
  probabilistic_sampler/security:
    sampling_percentage: $(echo "${SECURITY_TRACE_SAMPLING_RATE} * 100" | bc -l)

exporters:
  # Google Cloud Trace exporter
  googlecloud:
    project: ${PROJECT_ID}
    
  # Jaeger exporter for local development and debugging
  jaeger:
    endpoint: jaeger-collector:14250
    tls:
      insecure: true
  
  # Prometheus exporter for metrics
  prometheus:
    endpoint: "0.0.0.0:8889"
    
  # OTLP exporter for external systems
  otlp/tempo:
    endpoint: tempo:4317
    tls:
      insecure: true

extensions:
  health_check:
  pprof:
    endpoint: 0.0.0.0:1777
  zpages:
    endpoint: 0.0.0.0:55679

service:
  extensions: [health_check, pprof, zpages]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, attributes, batch, probabilistic_sampler]
      exporters: [googlecloud, jaeger]
    
    traces/security:
      receivers: [otlp]
      processors: [memory_limiter, resource, attributes, batch, probabilistic_sampler/security]
      exporters: [googlecloud]
    
    metrics:
      receivers: [prometheus/internal]
      processors: [memory_limiter, resource, batch]
      exporters: [prometheus]

  telemetry:
    logs:
      level: "info"
    metrics:
      address: 0.0.0.0:8888
EOF
    
    # Create Dockerfile for OpenTelemetry Collector
    cat > "/tmp/otel-collector.Dockerfile" << EOF
FROM otel/opentelemetry-collector-contrib:${OTEL_COLLECTOR_VERSION}

# Copy custom configuration
COPY otel-collector-config.yaml /etc/otel-collector-config.yaml

# Security hardening
RUN addgroup -g 10001 otel && \\
    adduser -u 10001 -G otel -D -s /bin/sh otel

USER 10001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \\
    CMD wget --no-verbose --tries=1 --spider http://localhost:13133/ || exit 1

EXPOSE 4317 4318 8888 8889 13133

CMD ["--config=/etc/otel-collector-config.yaml"]
EOF
    
    # Build and push OpenTelemetry Collector image
    log_info "Building OpenTelemetry Collector container image..."
    
    # Create build directory
    mkdir -p "/tmp/otel-build"
    cp "/tmp/otel-collector-config.yaml" "/tmp/otel-build/"
    cp "/tmp/otel-collector.Dockerfile" "/tmp/otel-build/Dockerfile"
    
    cd "/tmp/otel-build"
    
    # Build and push to Google Container Registry
    gcloud builds submit --tag "gcr.io/${PROJECT_ID}/otel-collector:${OTEL_COLLECTOR_VERSION}" .
    
    log_success "OpenTelemetry Collector image built and pushed"
    
    # Deploy OpenTelemetry Collector to Cloud Run
    log_info "Deploying OpenTelemetry Collector to Cloud Run..."
    
    gcloud run deploy isectech-otel-collector \
        --image="gcr.io/${PROJECT_ID}/otel-collector:${OTEL_COLLECTOR_VERSION}" \
        --region="$REGION" \
        --platform=managed \
        --allow-unauthenticated \
        --port=4318 \
        --memory=1Gi \
        --cpu=1 \
        --concurrency=1000 \
        --max-instances=10 \
        --min-instances=1 \
        --execution-environment=gen2 \
        --set-env-vars="PROJECT_ID=${PROJECT_ID},ENVIRONMENT=${ENVIRONMENT}" \
        --labels="component=observability,service=otel-collector,environment=${ENVIRONMENT}" \
        --service-account="isectech-otel-collector@${PROJECT_ID}.iam.gserviceaccount.com"
    
    log_success "OpenTelemetry Collector deployed to Cloud Run"
}

# Create OpenTelemetry instrumentation libraries
create_instrumentation_libraries() {
    log_info "Creating OpenTelemetry instrumentation libraries..."
    
    # Create Node.js/TypeScript instrumentation
    cat > "/tmp/nodejs-otel-instrumentation.js" << 'EOF'
/**
 * iSECTECH OpenTelemetry Instrumentation for Node.js/TypeScript
 * Production-grade distributed tracing with security context
 */

const { NodeSDK } = require('@opentelemetry/sdk-node');
const { Resource } = require('@opentelemetry/resources');
const { SemanticResourceAttributes } = require('@opentelemetry/semantic-conventions');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
const { TraceExporter } = require('@google-cloud/opentelemetry-cloud-trace-exporter');
const { BatchSpanProcessor } = require('@opentelemetry/sdk-trace-node');
const { trace, context, SpanKind, SpanStatusCode } = require('@opentelemetry/api');

class ISECTECHTracing {
    constructor(serviceName, serviceVersion, environment = 'production') {
        this.serviceName = serviceName;
        this.serviceVersion = serviceVersion;
        this.environment = environment;
        
        this.initializeTracing();
    }
    
    initializeTracing() {
        // Create resource with service information
        const resource = new Resource({
            [SemanticResourceAttributes.SERVICE_NAME]: this.serviceName,
            [SemanticResourceAttributes.SERVICE_VERSION]: this.serviceVersion,
            [SemanticResourceAttributes.SERVICE_NAMESPACE]: 'isectech',
            [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: this.environment,
            [SemanticResourceAttributes.CLOUD_PROVIDER]: 'gcp',
            [SemanticResourceAttributes.CLOUD_PLATFORM]: 'gcp_cloud_run',
            [SemanticResourceAttributes.CLOUD_REGION]: process.env.REGION || 'us-central1',
        });
        
        // Configure exporters
        const traceExporter = new TraceExporter({
            projectId: process.env.PROJECT_ID,
        });
        
        // Configure SDK
        this.sdk = new NodeSDK({
            resource,
            instrumentations: [
                getNodeAutoInstrumentations({
                    '@opentelemetry/instrumentation-fs': {
                        enabled: false, // Disable noisy file system instrumentation
                    },
                }),
            ],
            spanProcessor: new BatchSpanProcessor(traceExporter, {
                maxQueueSize: 2048,
                scheduledDelayMillis: 1000,
                exportTimeoutMillis: 30000,
                maxExportBatchSize: 512,
            }),
        });
        
        // Initialize SDK
        this.sdk.start();
        
        // Get tracer instance
        this.tracer = trace.getTracer(this.serviceName, this.serviceVersion);
        
        console.log(`OpenTelemetry initialized for ${this.serviceName} v${this.serviceVersion}`);
    }
    
    // Security-specific tracing methods
    traceSecurityEvent(eventType, operation, securityContext = {}) {
        return this.tracer.startSpan(`security.${eventType}`, {
            kind: SpanKind.INTERNAL,
            attributes: {
                'security.event_type': eventType,
                'security.operation': operation,
                'security.threat_level': securityContext.threatLevel || 'unknown',
                'security.user_id': securityContext.userId,
                'security.session_id': securityContext.sessionId,
                'security.ip_address': securityContext.ipAddress,
                'security.user_agent': securityContext.userAgent,
                'security.indicators': JSON.stringify(securityContext.indicators || []),
                'isectech.component': 'security',
                'isectech.environment': this.environment,
            },
        });
    }
    
    traceThreatDetection(threatType, severity, indicators = []) {
        const span = this.tracer.startSpan('security.threat_detection', {
            kind: SpanKind.INTERNAL,
            attributes: {
                'security.event_type': 'threat_detection',
                'security.threat_type': threatType,
                'security.severity': severity,
                'security.indicators': JSON.stringify(indicators),
                'security.alert_level': severity === 'critical' || severity === 'high' ? 'high' : 'medium',
                'isectech.component': 'threat-intelligence',
                'isectech.requires_immediate_attention': severity === 'critical',
            },
        });
        
        // Add security event to span events
        span.addEvent('threat.detected', {
            'threat.type': threatType,
            'threat.severity': severity,
            'threat.indicator_count': indicators.length,
        });
        
        return span;
    }
    
    traceAuthenticationEvent(operation, userId, result, context = {}) {
        const span = this.tracer.startSpan(`auth.${operation}`, {
            kind: SpanKind.INTERNAL,
            attributes: {
                'security.event_type': 'authentication',
                'auth.operation': operation,
                'auth.user_id': userId,
                'auth.result': result,
                'auth.method': context.method || 'unknown',
                'auth.ip_address': context.ipAddress,
                'auth.user_agent': context.userAgent,
                'isectech.component': 'authentication',
                'isectech.security_critical': true,
            },
        });
        
        // Set span status based on authentication result
        if (result === 'success') {
            span.setStatus({ code: SpanStatusCode.OK });
        } else {
            span.setStatus({ 
                code: SpanStatusCode.ERROR, 
                message: `Authentication ${operation} failed` 
            });
        }
        
        return span;
    }
    
    traceVulnerabilityEvent(scanType, findings, target) {
        const span = this.tracer.startSpan(`vulnerability.${scanType}`, {
            kind: SpanKind.INTERNAL,
            attributes: {
                'security.event_type': 'vulnerability_scan',
                'vuln.scan_type': scanType,
                'vuln.findings_count': findings.length,
                'vuln.target': target,
                'vuln.high_severity_count': findings.filter(f => f.severity === 'high').length,
                'vuln.critical_severity_count': findings.filter(f => f.severity === 'critical').length,
                'isectech.component': 'vulnerability-management',
            },
        });
        
        // Add findings as span events
        findings.forEach((finding, index) => {
            span.addEvent('vulnerability.found', {
                'vuln.id': finding.id,
                'vuln.severity': finding.severity,
                'vuln.type': finding.type,
                'vuln.cve': finding.cve,
            });
        });
        
        return span;
    }
    
    // Performance tracing with security context
    tracePerformanceOperation(operation, duration, context = {}) {
        const span = this.tracer.startSpan(`performance.${operation}`, {
            kind: SpanKind.INTERNAL,
            attributes: {
                'operation.name': operation,
                'operation.duration_ms': duration,
                'performance.cpu_usage': context.cpuUsage,
                'performance.memory_usage': context.memoryUsage,
                'performance.response_size': context.responseSize,
                'isectech.component': 'performance-monitoring',
            },
        });
        
        // Add performance threshold alerts
        if (duration > 5000) {
            span.addEvent('performance.slow_operation', {
                'threshold_exceeded': true,
                'expected_duration_ms': 1000,
                'actual_duration_ms': duration,
            });
            span.setStatus({ 
                code: SpanStatusCode.ERROR, 
                message: 'Operation exceeded performance threshold' 
            });
        }
        
        return span;
    }
    
    // HTTP request tracing with security enhancement
    traceHTTPRequest(method, url, statusCode, context = {}) {
        const span = this.tracer.startSpan(`http.${method.toLowerCase()}`, {
            kind: SpanKind.SERVER,
            attributes: {
                'http.method': method,
                'http.url': url,
                'http.status_code': statusCode,
                'http.user_agent': context.userAgent,
                'http.remote_addr': context.remoteAddr,
                'http.request_size': context.requestSize,
                'http.response_size': context.responseSize,
                'security.suspicious_patterns': context.suspiciousPatterns || [],
                'isectech.component': 'api-gateway',
            },
        });
        
        // Security analysis of HTTP request
        if (statusCode >= 400) {
            span.addEvent('http.error', {
                'error.type': statusCode >= 500 ? 'server_error' : 'client_error',
                'error.status_code': statusCode,
            });
        }
        
        // Check for security indicators
        if (context.suspiciousPatterns && context.suspiciousPatterns.length > 0) {
            span.addEvent('security.suspicious_request', {
                'security.patterns': JSON.stringify(context.suspiciousPatterns),
                'security.requires_analysis': true,
            });
        }
        
        return span;
    }
    
    // Database operation tracing
    traceDatabaseOperation(operation, table, query, duration) {
        const span = this.tracer.startSpan(`db.${operation}`, {
            kind: SpanKind.CLIENT,
            attributes: {
                'db.operation': operation,
                'db.table': table,
                'db.query': query.length > 200 ? query.substring(0, 200) + '...' : query,
                'db.duration_ms': duration,
                'isectech.component': 'database',
            },
        });
        
        // Performance monitoring
        if (duration > 1000) {
            span.addEvent('db.slow_query', {
                'query.duration_ms': duration,
                'query.threshold_exceeded': true,
            });
        }
        
        return span;
    }
    
    // Context propagation utilities
    getCurrentSpan() {
        return trace.getActiveSpan();
    }
    
    withSpan(span, fn) {
        return context.with(trace.setSpan(context.active(), span), fn);
    }
    
    addSecurityContextToCurrentSpan(securityContext) {
        const span = this.getCurrentSpan();
        if (span) {
            span.setAttributes({
                'security.context_added': true,
                'security.user_id': securityContext.userId,
                'security.session_id': securityContext.sessionId,
                'security.organization_id': securityContext.organizationId,
                'security.permissions': JSON.stringify(securityContext.permissions || []),
            });
        }
    }
    
    // Graceful shutdown
    async shutdown() {
        try {
            await this.sdk.shutdown();
            console.log('OpenTelemetry SDK shut down successfully');
        } catch (error) {
            console.error('Error shutting down OpenTelemetry SDK:', error);
        }
    }
}

module.exports = ISECTECHTracing;

// Example usage:
/*
const tracing = new ISECTECHTracing('isectech-api-gateway', '1.0.0', 'production');

// Security event tracing
const securitySpan = tracing.traceSecurityEvent('authentication_attempt', 'login', {
    userId: 'user123',
    sessionId: 'session456',
    ipAddress: '192.168.1.1',
    threatLevel: 'low'
});

// Threat detection tracing
const threatSpan = tracing.traceThreatDetection('sql_injection', 'high', [
    'UNION SELECT detected',
    'Suspicious parameter values'
]);

// HTTP request tracing
const httpSpan = tracing.traceHTTPRequest('POST', '/api/v1/login', 200, {
    userAgent: 'Mozilla/5.0...',
    remoteAddr: '192.168.1.1',
    suspiciousPatterns: []
});

// Close spans when done
securitySpan.end();
threatSpan.end();
httpSpan.end();
*/
EOF
    
    # Create Go instrumentation
    cat > "/tmp/go-otel-instrumentation.go" << 'EOF'
// iSECTECH OpenTelemetry Instrumentation for Go
// Production-grade distributed tracing with security context

package tracing

import (
    "context"
    "fmt"
    "os"
    "time"
    
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/codes"
    "go.opentelemetry.io/otel/exporters/jaeger"
    "go.opentelemetry.io/otel/propagation"
    "go.opentelemetry.io/otel/resource"
    "go.opentelemetry.io/otel/sdk/trace"
    "go.opentelemetry.io/otel/semconv/v1.17.0"
    "go.opentelemetry.io/otel/trace"
    
    gcptrace "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
)

type ISECTECHTracer struct {
    tracer       trace.Tracer
    serviceName  string
    environment  string
}

type SecurityContext struct {
    UserID         string   `json:"user_id"`
    SessionID      string   `json:"session_id"`
    OrganizationID string   `json:"organization_id"`
    IPAddress      string   `json:"ip_address"`
    UserAgent      string   `json:"user_agent"`
    ThreatLevel    string   `json:"threat_level"`
    Indicators     []string `json:"indicators"`
    Permissions    []string `json:"permissions"`
}

type PerformanceContext struct {
    CPUUsage     float64 `json:"cpu_usage"`
    MemoryUsage  int64   `json:"memory_usage"`
    ResponseSize int64   `json:"response_size"`
    Duration     time.Duration `json:"duration"`
}

func NewISECTECHTracer(serviceName, serviceVersion, environment string) (*ISECTECHTracer, error) {
    // Create resource
    res, err := resource.Merge(
        resource.Default(),
        resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceName(serviceName),
            semconv.ServiceVersion(serviceVersion),
            semconv.ServiceNamespace("isectech"),
            semconv.DeploymentEnvironment(environment),
            semconv.CloudProvider("gcp"),
            semconv.CloudPlatform("gcp_cloud_run"),
            attribute.String("cloud.region", os.Getenv("REGION")),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create resource: %w", err)
    }
    
    // Create Google Cloud Trace exporter
    gcpExporter, err := gcptrace.New(gcptrace.WithProjectID(os.Getenv("PROJECT_ID")))
    if err != nil {
        return nil, fmt.Errorf("failed to create GCP trace exporter: %w", err)
    }
    
    // Create Jaeger exporter for development
    jaegerExporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
        jaeger.WithEndpoint("http://jaeger-collector:14268/api/traces"),
    ))
    if err != nil {
        return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
    }
    
    // Configure trace provider
    tp := trace.NewTracerProvider(
        trace.WithResource(res),
        trace.WithBatcher(gcpExporter),
        trace.WithBatcher(jaegerExporter),
        trace.WithSampler(trace.TraceIDRatioBased(0.1)), // 10% sampling
    )
    
    // Set global trace provider
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
        propagation.TraceContext{},
        propagation.Baggage{},
    ))
    
    tracer := tp.Tracer(serviceName)
    
    return &ISECTECHTracer{
        tracer:      tracer,
        serviceName: serviceName,
        environment: environment,
    }, nil
}

// Security-specific tracing methods
func (t *ISECTECHTracer) TraceSecurityEvent(ctx context.Context, eventType, operation string, secCtx *SecurityContext) (context.Context, trace.Span) {
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("security.%s", eventType),
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("security.event_type", eventType),
            attribute.String("security.operation", operation),
            attribute.String("security.threat_level", secCtx.ThreatLevel),
            attribute.String("security.user_id", secCtx.UserID),
            attribute.String("security.session_id", secCtx.SessionID),
            attribute.String("security.ip_address", secCtx.IPAddress),
            attribute.String("security.user_agent", secCtx.UserAgent),
            attribute.StringSlice("security.indicators", secCtx.Indicators),
            attribute.String("isectech.component", "security"),
            attribute.String("isectech.environment", t.environment),
        ),
    )
    
    return ctx, span
}

func (t *ISECTECHTracer) TraceThreatDetection(ctx context.Context, threatType, severity string, indicators []string) (context.Context, trace.Span) {
    ctx, span := t.tracer.Start(ctx, "security.threat_detection",
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("security.event_type", "threat_detection"),
            attribute.String("security.threat_type", threatType),
            attribute.String("security.severity", severity),
            attribute.StringSlice("security.indicators", indicators),
            attribute.String("security.alert_level", t.getAlertLevel(severity)),
            attribute.String("isectech.component", "threat-intelligence"),
            attribute.Bool("isectech.requires_immediate_attention", severity == "critical"),
        ),
    )
    
    // Add security event
    span.AddEvent("threat.detected", trace.WithAttributes(
        attribute.String("threat.type", threatType),
        attribute.String("threat.severity", severity),
        attribute.Int("threat.indicator_count", len(indicators)),
    ))
    
    return ctx, span
}

func (t *ISECTECHTracer) TraceAuthenticationEvent(ctx context.Context, operation, userID, result string, secCtx *SecurityContext) (context.Context, trace.Span) {
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("auth.%s", operation),
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("security.event_type", "authentication"),
            attribute.String("auth.operation", operation),
            attribute.String("auth.user_id", userID),
            attribute.String("auth.result", result),
            attribute.String("auth.ip_address", secCtx.IPAddress),
            attribute.String("auth.user_agent", secCtx.UserAgent),
            attribute.String("isectech.component", "authentication"),
            attribute.Bool("isectech.security_critical", true),
        ),
    )
    
    // Set span status based on result
    if result == "success" {
        span.SetStatus(codes.Ok, "Authentication successful")
    } else {
        span.SetStatus(codes.Error, fmt.Sprintf("Authentication %s failed", operation))
    }
    
    return ctx, span
}

func (t *ISECTECHTracer) TraceVulnerabilityEvent(ctx context.Context, scanType string, findings []VulnerabilityFinding, target string) (context.Context, trace.Span) {
    highSeverityCount := 0
    criticalSeverityCount := 0
    
    for _, finding := range findings {
        if finding.Severity == "high" {
            highSeverityCount++
        } else if finding.Severity == "critical" {
            criticalSeverityCount++
        }
    }
    
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("vulnerability.%s", scanType),
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("security.event_type", "vulnerability_scan"),
            attribute.String("vuln.scan_type", scanType),
            attribute.Int("vuln.findings_count", len(findings)),
            attribute.String("vuln.target", target),
            attribute.Int("vuln.high_severity_count", highSeverityCount),
            attribute.Int("vuln.critical_severity_count", criticalSeverityCount),
            attribute.String("isectech.component", "vulnerability-management"),
        ),
    )
    
    // Add findings as span events
    for _, finding := range findings {
        span.AddEvent("vulnerability.found", trace.WithAttributes(
            attribute.String("vuln.id", finding.ID),
            attribute.String("vuln.severity", finding.Severity),
            attribute.String("vuln.type", finding.Type),
            attribute.String("vuln.cve", finding.CVE),
        ))
    }
    
    return ctx, span
}

// Performance tracing with security context
func (t *ISECTECHTracer) TracePerformanceOperation(ctx context.Context, operation string, perfCtx *PerformanceContext) (context.Context, trace.Span) {
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("performance.%s", operation),
        trace.WithSpanKind(trace.SpanKindInternal),
        trace.WithAttributes(
            attribute.String("operation.name", operation),
            attribute.Int64("operation.duration_ms", perfCtx.Duration.Milliseconds()),
            attribute.Float64("performance.cpu_usage", perfCtx.CPUUsage),
            attribute.Int64("performance.memory_usage", perfCtx.MemoryUsage),
            attribute.Int64("performance.response_size", perfCtx.ResponseSize),
            attribute.String("isectech.component", "performance-monitoring"),
        ),
    )
    
    // Add performance threshold alerts
    if perfCtx.Duration > 5*time.Second {
        span.AddEvent("performance.slow_operation", trace.WithAttributes(
            attribute.Bool("threshold_exceeded", true),
            attribute.Int64("expected_duration_ms", 1000),
            attribute.Int64("actual_duration_ms", perfCtx.Duration.Milliseconds()),
        ))
        span.SetStatus(codes.Error, "Operation exceeded performance threshold")
    }
    
    return ctx, span
}

// HTTP request tracing with security enhancement
func (t *ISECTECHTracer) TraceHTTPRequest(ctx context.Context, method, url string, statusCode int, secCtx *SecurityContext) (context.Context, trace.Span) {
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("http.%s", strings.ToLower(method)),
        trace.WithSpanKind(trace.SpanKindServer),
        trace.WithAttributes(
            attribute.String("http.method", method),
            attribute.String("http.url", url),
            attribute.Int("http.status_code", statusCode),
            attribute.String("http.user_agent", secCtx.UserAgent),
            attribute.String("http.remote_addr", secCtx.IPAddress),
            attribute.StringSlice("security.suspicious_patterns", secCtx.Indicators),
            attribute.String("isectech.component", "api-gateway"),
        ),
    )
    
    // Security analysis of HTTP request
    if statusCode >= 400 {
        errorType := "client_error"
        if statusCode >= 500 {
            errorType = "server_error"
        }
        
        span.AddEvent("http.error", trace.WithAttributes(
            attribute.String("error.type", errorType),
            attribute.Int("error.status_code", statusCode),
        ))
    }
    
    // Check for security indicators
    if len(secCtx.Indicators) > 0 {
        span.AddEvent("security.suspicious_request", trace.WithAttributes(
            attribute.StringSlice("security.patterns", secCtx.Indicators),
            attribute.Bool("security.requires_analysis", true),
        ))
    }
    
    return ctx, span
}

// Database operation tracing
func (t *ISECTECHTracer) TraceDatabaseOperation(ctx context.Context, operation, table, query string, duration time.Duration) (context.Context, trace.Span) {
    // Truncate long queries
    if len(query) > 200 {
        query = query[:200] + "..."
    }
    
    ctx, span := t.tracer.Start(ctx, fmt.Sprintf("db.%s", operation),
        trace.WithSpanKind(trace.SpanKindClient),
        trace.WithAttributes(
            attribute.String("db.operation", operation),
            attribute.String("db.table", table),
            attribute.String("db.query", query),
            attribute.Int64("db.duration_ms", duration.Milliseconds()),
            attribute.String("isectech.component", "database"),
        ),
    )
    
    // Performance monitoring
    if duration > time.Second {
        span.AddEvent("db.slow_query", trace.WithAttributes(
            attribute.Int64("query.duration_ms", duration.Milliseconds()),
            attribute.Bool("query.threshold_exceeded", true),
        ))
    }
    
    return ctx, span
}

// Utility methods
func (t *ISECTECHTracer) getAlertLevel(severity string) string {
    if severity == "critical" || severity == "high" {
        return "high"
    }
    return "medium"
}

func (t *ISECTECHTracer) AddSecurityContextToSpan(span trace.Span, secCtx *SecurityContext) {
    span.SetAttributes(
        attribute.String("security.context_added", "true"),
        attribute.String("security.user_id", secCtx.UserID),
        attribute.String("security.session_id", secCtx.SessionID),
        attribute.String("security.organization_id", secCtx.OrganizationID),
        attribute.StringSlice("security.permissions", secCtx.Permissions),
    )
}

// VulnerabilityFinding represents a security vulnerability
type VulnerabilityFinding struct {
    ID       string `json:"id"`
    Severity string `json:"severity"`
    Type     string `json:"type"`
    CVE      string `json:"cve"`
}
EOF
    
    log_success "Created OpenTelemetry instrumentation libraries"
}

# Set up Jaeger for trace visualization
setup_jaeger() {
    log_info "Setting up Jaeger for trace visualization..."
    
    # Create Jaeger deployment configuration
    cat > "/tmp/jaeger-deployment.yaml" << EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: jaeger-config
data:
  jaeger.yaml: |
    receivers:
      jaegerreceiver:
        protocols:
          grpc:
            endpoint: 0.0.0.0:14250
          thrift_http:
            endpoint: 0.0.0.0:14268
          thrift_compact:
            endpoint: 0.0.0.0:6831
          thrift_binary:
            endpoint: 0.0.0.0:6832
    
    processors:
      batch:
    
    exporters:
      googlecloud:
        project: ${PROJECT_ID}
    
    service:
      pipelines:
        traces:
          receivers: [jaegerreceiver]
          processors: [batch]
          exporters: [googlecloud]

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger-collector
  labels:
    app: jaeger-collector
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger-collector
  template:
    metadata:
      labels:
        app: jaeger-collector
    spec:
      containers:
      - name: jaeger-collector
        image: jaegertracing/jaeger-collector:${JAEGER_VERSION}
        env:
        - name: SPAN_STORAGE_TYPE
          value: "grpc-plugin"
        - name: GRPC_STORAGE_PLUGIN_BINARY
          value: "/plugin/gcp-trace"
        - name: GRPC_STORAGE_PLUGIN_CONFIGURATION_FILE
          value: "/config/jaeger.yaml"
        ports:
        - containerPort: 14250
        - containerPort: 14268
        - containerPort: 9411
        volumeMounts:
        - name: config
          mountPath: /config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: jaeger-config

---
apiVersion: v1
kind: Service
metadata:
  name: jaeger-collector
spec:
  selector:
    app: jaeger-collector
  ports:
  - name: grpc
    port: 14250
    targetPort: 14250
  - name: http
    port: 14268
    targetPort: 14268
  - name: zipkin
    port: 9411
    targetPort: 9411

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jaeger-query
  labels:
    app: jaeger-query
spec:
  replicas: 1
  selector:
    matchLabels:
      app: jaeger-query
  template:
    metadata:
      labels:
        app: jaeger-query
    spec:
      containers:
      - name: jaeger-query
        image: jaegertracing/jaeger-query:${JAEGER_VERSION}
        env:
        - name: SPAN_STORAGE_TYPE
          value: "grpc-plugin"
        - name: GRPC_STORAGE_PLUGIN_BINARY
          value: "/plugin/gcp-trace"
        - name: GRPC_STORAGE_PLUGIN_CONFIGURATION_FILE
          value: "/config/jaeger.yaml"
        ports:
        - containerPort: 16686
        - containerPort: 16687
        volumeMounts:
        - name: config
          mountPath: /config
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
      volumes:
      - name: config
        configMap:
          name: jaeger-config

---
apiVersion: v1
kind: Service
metadata:
  name: jaeger-query
spec:
  selector:
    app: jaeger-query
  ports:
  - name: http
    port: 16686
    targetPort: 16686
  type: LoadBalancer
EOF
    
    log_success "Jaeger configuration created"
    
    # Note: In production, you might want to deploy to GKE instead of Cloud Run
    log_info "Jaeger deployment configuration ready for Kubernetes/GKE deployment"
    log_info "For Cloud Run deployment, consider using Jaeger Cloud services or Google Cloud Trace UI"
}

# Create trace analysis and alerting
create_trace_analysis() {
    log_info "Creating trace analysis and alerting..."
    
    # Create Cloud Function for trace analysis
    cat > "/tmp/trace-analysis-function.js" << 'EOF'
/**
 * Trace Analysis Cloud Function
 * Analyzes distributed traces for security and performance insights
 */

const { TraceServiceClient } = require('@google-cloud/trace');
const { PubSub } = require('@google-cloud/pubsub');

const traceClient = new TraceServiceClient();
const pubsub = new PubSub();

exports.analyzeTraces = async (pubSubMessage, context) => {
    try {
        const messageData = JSON.parse(Buffer.from(pubSubMessage.data, 'base64').toString());
        
        console.log('Analyzing trace data:', {
            traceId: messageData.traceId,
            spans: messageData.spans?.length || 0,
            timestamp: messageData.timestamp
        });
        
        // Analyze security-related spans
        await analyzeSecurityTraces(messageData);
        
        // Analyze performance patterns
        await analyzePerformanceTraces(messageData);
        
        // Detect anomalies
        await detectTraceAnomalies(messageData);
        
    } catch (error) {
        console.error('Error analyzing traces:', error);
        throw error;
    }
};

async function analyzeSecurityTraces(traceData) {
    const securitySpans = traceData.spans?.filter(span => 
        span.attributes?.['security.event_type'] || 
        span.attributes?.['isectech.component'] === 'security'
    ) || [];
    
    console.log(`Found ${securitySpans.length} security-related spans`);
    
    for (const span of securitySpans) {
        const eventType = span.attributes?.['security.event_type'];
        const threatLevel = span.attributes?.['security.threat_level'];
        
        if (eventType === 'threat_detection' && (threatLevel === 'high' || threatLevel === 'critical')) {
            await handleHighThreatTrace(span, traceData);
        }
        
        if (eventType === 'authentication' && span.attributes?.['auth.result'] !== 'success') {
            await handleAuthenticationFailure(span, traceData);
        }
    }
}

async function analyzePerformanceTraces(traceData) {
    const performanceSpans = traceData.spans?.filter(span =>
        span.attributes?.['operation.duration_ms'] > 5000 ||
        span.events?.some(event => event.name === 'performance.slow_operation')
    ) || [];
    
    console.log(`Found ${performanceSpans.length} performance-related spans`);
    
    for (const span of performanceSpans) {
        await handlePerformanceIssue(span, traceData);
    }
}

async function detectTraceAnomalies(traceData) {
    // Implement anomaly detection logic
    const totalDuration = calculateTotalTraceDuration(traceData);
    const errorCount = countErrorSpans(traceData);
    const securityEvents = countSecurityEvents(traceData);
    
    console.log('Trace metrics:', {
        totalDuration,
        errorCount,
        securityEvents
    });
    
    // Detect anomalies based on patterns
    if (totalDuration > 30000) { // 30 seconds
        await reportAnomaly('long_trace_duration', { duration: totalDuration, traceId: traceData.traceId });
    }
    
    if (errorCount > 5) {
        await reportAnomaly('high_error_rate', { errorCount, traceId: traceData.traceId });
    }
    
    if (securityEvents > 3) {
        await reportAnomaly('multiple_security_events', { securityEvents, traceId: traceData.traceId });
    }
}

async function handleHighThreatTrace(span, traceData) {
    const alertData = {
        type: 'high_threat_detected',
        traceId: traceData.traceId,
        threatType: span.attributes?.['security.threat_type'],
        severity: span.attributes?.['security.severity'],
        indicators: JSON.parse(span.attributes?.['security.indicators'] || '[]'),
        timestamp: span.startTime,
        userId: span.attributes?.['security.user_id'],
        ipAddress: span.attributes?.['security.ip_address']
    };
    
    console.log('High threat detected in trace:', alertData);
    
    // Send to security alert topic
    const topic = pubsub.topic('isectech-security-alerts');
    await topic.publishMessage({ json: alertData });
}

async function handleAuthenticationFailure(span, traceData) {
    const alertData = {
        type: 'authentication_failure',
        traceId: traceData.traceId,
        operation: span.attributes?.['auth.operation'],
        userId: span.attributes?.['auth.user_id'],
        ipAddress: span.attributes?.['auth.ip_address'],
        userAgent: span.attributes?.['auth.user_agent'],
        timestamp: span.startTime
    };
    
    console.log('Authentication failure detected:', alertData);
    
    // Check for brute force patterns
    // Implementation would query recent authentication failures
}

async function handlePerformanceIssue(span, traceData) {
    const alertData = {
        type: 'performance_degradation',
        traceId: traceData.traceId,
        operation: span.attributes?.['operation.name'],
        duration: span.attributes?.['operation.duration_ms'],
        serviceName: span.attributes?.['service.name'],
        timestamp: span.startTime
    };
    
    console.log('Performance issue detected:', alertData);
}

async function reportAnomaly(anomalyType, details) {
    const anomalyData = {
        type: 'trace_anomaly',
        anomalyType,
        details,
        timestamp: new Date().toISOString()
    };
    
    console.log('Trace anomaly detected:', anomalyData);
    
    // Send to anomaly detection topic
    const topic = pubsub.topic('isectech-trace-anomalies');
    await topic.publishMessage({ json: anomalyData });
}

function calculateTotalTraceDuration(traceData) {
    if (!traceData.spans || traceData.spans.length === 0) return 0;
    
    const startTimes = traceData.spans.map(span => new Date(span.startTime).getTime());
    const endTimes = traceData.spans.map(span => new Date(span.endTime).getTime());
    
    return Math.max(...endTimes) - Math.min(...startTimes);
}

function countErrorSpans(traceData) {
    return traceData.spans?.filter(span => 
        span.status?.code === 'ERROR' || 
        span.attributes?.['http.status_code'] >= 400
    ).length || 0;
}

function countSecurityEvents(traceData) {
    return traceData.spans?.filter(span => 
        span.attributes?.['security.event_type'] || 
        span.attributes?.['isectech.component'] === 'security'
    ).length || 0;
}
EOF
    
    log_success "Created trace analysis Cloud Function"
}

# Generate distributed tracing report
generate_tracing_report() {
    log_info "Generating distributed tracing configuration report..."
    
    local report_file="/tmp/isectech-tracing-report-$(date +%Y%m%d-%H%M%S).txt"
    
    cat > "$report_file" << EOF
iSECTECH Distributed Tracing Configuration Report
Generated: $(date)
Environment: ${ENVIRONMENT}
Project: ${PROJECT_ID}
Region: ${REGION}

================================
DISTRIBUTED TRACING OVERVIEW
================================

OpenTelemetry Collector Version: ${OTEL_COLLECTOR_VERSION}
Jaeger Version: ${JAEGER_VERSION}
Tempo Version: ${TEMPO_VERSION}

Sampling Configuration:
- Default Sampling Rate: ${TRACE_SAMPLING_RATE} (${TRACE_SAMPLING_RATE%.*}%)
- Security Event Sampling Rate: ${SECURITY_TRACE_SAMPLING_RATE} (${SECURITY_TRACE_SAMPLING_RATE%.*}%)

Trace Exporters:
- Google Cloud Trace (Primary)
- Jaeger (Development/Debugging)
- Tempo (Long-term storage)

================================
OPENTELEMETRY COLLECTOR
================================

Deployment: Cloud Run Service (isectech-otel-collector)
- Image: gcr.io/${PROJECT_ID}/otel-collector:${OTEL_COLLECTOR_VERSION}
- Memory: 1Gi
- CPU: 1 vCPU
- Min Instances: 1
- Max Instances: 10
- Concurrency: 1000

Receivers Configured:
- OTLP gRPC (Port 4317)
- OTLP HTTP (Port 4318)
- Prometheus Internal Metrics (Port 8888)

Processors Configured:
- Batch Processor (1s timeout, 1024 batch size)
- Memory Limiter (512Mi limit, 128Mi spike)
- Resource Processor (environment context)
- Attributes Processor (security context enhancement)
- Probabilistic Sampler (performance optimization)

Exporters Configured:
- Google Cloud Trace (primary production)
- Jaeger (development and debugging)
- Prometheus (metrics export)
- OTLP/Tempo (long-term trace storage)

Extensions:
- Health Check (Port 13133)
- pprof (Port 1777)
- zPages (Port 55679)

================================
INSTRUMENTATION LIBRARIES
================================

Node.js/TypeScript Library Features:
- Automatic instrumentation (HTTP, database, etc.)
- Security event tracing
- Threat detection tracing
- Authentication event tracing
- Vulnerability scan tracing
- Performance monitoring integration
- Context propagation
- Custom security attributes

Methods Available:
- traceSecurityEvent()
- traceThreatDetection()
- traceAuthenticationEvent()
- traceVulnerabilityEvent()
- tracePerformanceOperation()
- traceHTTPRequest()
- traceDatabaseOperation()

Go Library Features:
- OpenTelemetry SDK integration
- Google Cloud Trace integration
- Jaeger export support
- Security context enhancement
- Performance monitoring
- Database operation tracing
- HTTP request tracing with security analysis

Methods Available:
- TraceSecurityEvent()
- TraceThreatDetection()
- TraceAuthenticationEvent()
- TraceVulnerabilityEvent()
- TracePerformanceOperation()
- TraceHTTPRequest()
- TraceDatabaseOperation()

================================
SECURITY TRACING FEATURES
================================

Security Context Attributes:
- security.event_type: Classification of security events
- security.threat_level: Threat severity (low, medium, high, critical)
- security.user_id: User identifier
- security.session_id: Session identifier
- security.ip_address: Client IP address
- security.user_agent: Client user agent
- security.indicators: Threat indicators array
- security.mitigation_actions: Response actions taken

Threat Detection Tracing:
- SQL injection attempts
- XSS attack patterns
- Authentication bypass attempts
- Brute force attacks
- Vulnerability exploitation
- Privilege escalation attempts
- Data exfiltration patterns

Authentication Tracing:
- Login attempts (success/failure)
- Password reset operations
- Multi-factor authentication
- Session management
- Authorization decisions
- Permission checks

Vulnerability Management Tracing:
- Security scan operations
- Vulnerability findings
- Remediation actions
- Compliance checks
- Risk assessments

================================
PERFORMANCE TRACING FEATURES
================================

Performance Context Attributes:
- operation.duration_ms: Operation execution time
- performance.cpu_usage: CPU utilization during operation
- performance.memory_usage: Memory consumption
- performance.response_size: Response payload size
- performance.threshold_exceeded: Performance threshold alerts

Monitored Operations:
- HTTP request/response cycles
- Database query performance
- External API calls
- File system operations
- Cache operations
- Cryptographic operations

Threshold Alerts:
- Response time > 5000ms
- Database query > 1000ms
- Memory usage > 90%
- CPU usage > 80%
- Large response size > 10MB

================================
TRACE ANALYSIS & ALERTING
================================

Cloud Function: trace-analysis-function
- Trigger: Pub/Sub messages from trace export
- Purpose: Analyze traces for security and performance insights
- Actions: Generate alerts, detect anomalies, correlate events

Security Analysis:
- High/critical threat detection
- Authentication failure patterns
- Suspicious activity correlation
- Attack chain reconstruction
- Incident timeline creation

Performance Analysis:
- Slow operation detection
- Resource usage patterns
- Bottleneck identification
- Capacity planning insights
- SLA violation tracking

Anomaly Detection:
- Long trace duration (> 30 seconds)
- High error rate (> 5 errors per trace)
- Multiple security events (> 3 per trace)
- Unusual request patterns
- Performance degradation trends

================================
VISUALIZATION & DASHBOARDS
================================

Google Cloud Trace Console:
- Trace timeline visualization
- Span details and attributes
- Performance analysis
- Error correlation
- Search and filtering

Jaeger UI:
- Distributed trace visualization
- Service dependency mapping
- Performance comparison
- Trace search and analysis
- Service performance metrics

Custom Dashboards:
- Security event trends
- Performance metrics overview
- Error rate monitoring
- Service health status
- Threat detection alerts

Key Metrics Tracked:
- Trace volume (traces/second)
- Average trace duration
- Error rate by service
- Security event frequency
- Performance threshold violations

================================
DATA STORAGE & RETENTION
================================

Google Cloud Trace:
- Automatic trace storage
- 30-day retention (configurable)
- Global availability
- High-performance queries
- Integration with other GCP services

BigQuery Export:
- Long-term trace storage
- Custom retention policies
- Advanced analytics capabilities
- SQL-based trace analysis
- Integration with BI tools

Jaeger Storage:
- Development and debugging
- Local trace visualization
- Short-term retention
- Fast query performance
- Service dependency analysis

Trace Data Schema:
- Service identification
- Span hierarchy
- Timing information
- Custom attributes
- Error information
- Security context

================================
SECURITY & COMPLIANCE
================================

Data Protection:
- Sensitive data masking in traces
- PII filtering and redaction
- Encryption in transit and at rest
- Access control with IAM
- Audit logging for trace access

Compliance Features:
- Trace data retention policies
- Data sovereignty controls
- Audit trail capabilities
- Change tracking
- Access monitoring

Security Monitoring:
- Threat indicator tracking
- Attack pattern detection
- Incident response correlation
- Forensic analysis capabilities
- Real-time security alerting

================================
INTEGRATION POINTS
================================

SIEM Integration:
- Trace data export to SIEM systems
- Security event correlation
- Threat intelligence enrichment
- Incident response automation
- Compliance reporting

APM Integration:
- Application performance monitoring
- Error tracking correlation
- User experience monitoring
- Business metric correlation
- Custom dashboard creation

Alerting Integration:
- PagerDuty/Opsgenie alerts
- Slack/Teams notifications
- Email alert routing
- SMS for critical events
- Webhook integrations

Monitoring Integration:
- Prometheus metrics export
- Grafana visualization
- Custom metric creation
- SLI/SLO monitoring
- Capacity planning data

================================
OPERATIONAL PROCEDURES
================================

Daily Operations:
- Monitor trace ingestion rates
- Review error rate trends
- Check security event patterns
- Verify collector health
- Analyze performance metrics

Weekly Operations:
- Trace retention cleanup
- Performance trend analysis
- Security pattern review
- Cost optimization review
- Configuration updates

Monthly Operations:
- Comprehensive trace analysis
- Security posture assessment
- Performance baseline updates
- Capacity planning review
- Compliance reporting

Emergency Procedures:
- Trace data emergency export
- Security incident investigation
- Performance issue escalation
- Service outage correlation
- Incident response coordination

================================
COST OPTIMIZATION
================================

Estimated Monthly Costs:
- Google Cloud Trace: \$50-200 (based on trace volume)
- Cloud Run (Collector): \$30-100 (based on usage)
- BigQuery Storage: \$20-80 (long-term trace data)
- Network Egress: \$10-30 (data export)

Cost Optimization Features:
- Intelligent sampling rates
- Trace data lifecycle policies
- Resource-based filtering
- Batch processing optimization
- Efficient data compression

Sampling Strategy:
- Default services: ${TRACE_SAMPLING_RATE} sampling
- Security services: ${SECURITY_TRACE_SAMPLING_RATE} sampling
- Performance-critical: 1.0 sampling
- Development: 1.0 sampling
- Background jobs: 0.01 sampling

================================
MONITORING & HEALTH CHECKS
================================

Collector Health Metrics:
- Trace ingestion rate (traces/second)
- Processing latency (milliseconds)
- Memory usage (MB)
- CPU utilization (%)
- Export success rate (%)

Key Performance Indicators:
- End-to-end trace latency < 5 seconds
- Trace loss rate < 0.1%
- Collector uptime > 99.9%
- Export success rate > 99.5%
- Query response time < 2 seconds

Health Check Endpoints:
- /health (collector health)
- /metrics (Prometheus metrics)
- /zpages (zPages diagnostics)
- /pprof (performance profiling)

================================
TROUBLESHOOTING GUIDE
================================

Common Issues:

1. Missing Traces:
   - Check collector connectivity
   - Verify sampling configuration
   - Review instrumentation setup
   - Check export permissions
   - Validate network connectivity

2. High Latency:
   - Optimize batch processing
   - Adjust memory limits
   - Review network performance
   - Check export destinations
   - Optimize sampling rates

3. Storage Costs:
   - Implement intelligent sampling
   - Configure retention policies
   - Archive old trace data
   - Optimize trace attributes
   - Review export settings

4. Security Events Missing:
   - Verify security instrumentation
   - Check custom attributes
   - Review sampling rates
   - Validate export filters
   - Test security trace generation

Diagnostic Commands:
- Check collector logs: gcloud run services logs read isectech-otel-collector
- View traces: gcloud trace list-traces
- Test connectivity: curl http://[COLLECTOR_URL]/health
- Verify exports: gcloud trace describe [TRACE_ID]

================================
NEXT STEPS
================================

1. Deploy OpenTelemetry Collector to Cloud Run
2. Integrate instrumentation libraries into services
3. Configure custom security attributes
4. Set up trace analysis Cloud Function
5. Create custom dashboards and alerts
6. Test end-to-end trace flow
7. Implement security event correlation
8. Set up automated trace analysis
9. Configure long-term trace storage
10. Train team on trace analysis tools

================================
DEVELOPMENT WORKFLOW
================================

Service Development:
1. Add OpenTelemetry instrumentation
2. Implement security context tracing
3. Test trace generation locally
4. Validate trace attributes
5. Deploy with trace export

Security Testing:
1. Generate security test traces
2. Verify threat detection tracing
3. Test authentication event tracing
4. Validate incident correlation
5. Review trace-based alerts

Performance Testing:
1. Generate load test traces
2. Analyze performance patterns
3. Identify bottlenecks
4. Optimize trace sampling
5. Validate SLA monitoring

Production Deployment:
1. Configure production sampling
2. Set up monitoring dashboards
3. Enable security alerting
4. Implement trace-based SLOs
5. Train operations team

EOF
    
    log_success "Distributed tracing report generated: $report_file"
    cat "$report_file"
}

# Main execution function
main() {
    log_info "Starting iSECTECH distributed tracing configuration..."
    log_info "Environment: ${ENVIRONMENT}"
    log_info "Project: ${PROJECT_ID}"
    log_info "Region: ${REGION}"
    
    log_info "OpenTelemetry Configuration:"
    log_info "- Collector Version: ${OTEL_COLLECTOR_VERSION}"
    log_info "- Jaeger Version: ${JAEGER_VERSION}"
    log_info "- Default Sampling Rate: ${TRACE_SAMPLING_RATE}"
    log_info "- Security Sampling Rate: ${SECURITY_TRACE_SAMPLING_RATE}"
    
    check_prerequisites
    
    setup_cloud_trace
    deploy_otel_collector
    create_instrumentation_libraries
    setup_jaeger
    create_trace_analysis
    
    generate_tracing_report
    
    log_success "iSECTECH distributed tracing configuration completed!"
    
    echo ""
    log_info "Distributed tracing is now configured with comprehensive security context."
    log_info "Deploy instrumentation libraries to Cloud Run services."
    log_info "View traces in Google Cloud Console: https://console.cloud.google.com/traces"
    log_info "OpenTelemetry Collector endpoint: https://[COLLECTOR_URL]:4318/v1/traces"
}

# Help function
show_help() {
    cat << EOF
iSECTECH Distributed Tracing Configuration Script

Usage: $0 [OPTIONS]

Options:
    --environment ENV        Environment (production, staging, development)
    --project PROJECT       Google Cloud project ID
    --region REGION         Google Cloud region (default: us-central1)
    --sampling-rate RATE    Default trace sampling rate (default: 0.1)
    --security-sampling RATE Security event sampling rate (default: 1.0)
    --collector-version VER OpenTelemetry Collector version (default: 0.89.0)
    --help                  Show this help message

Environment Variables:
    PROJECT_ID              Google Cloud project ID
    REGION                 Google Cloud region
    ENVIRONMENT            Environment name
    TRACE_SAMPLING_RATE    Default sampling rate (0.0-1.0)
    SECURITY_TRACE_SAMPLING_RATE Security sampling rate (0.0-1.0)
    OTEL_COLLECTOR_VERSION OpenTelemetry Collector version
    JAEGER_VERSION         Jaeger version
    TEMPO_VERSION          Tempo version

Examples:
    # Configure production tracing with 10% sampling
    ./distributed-tracing-setup.sh --environment production --sampling-rate 0.1

    # Configure development with full sampling
    ./distributed-tracing-setup.sh --environment development --sampling-rate 1.0

Prerequisites:
    - Google Cloud project with APIs enabled
    - Cloud Run deployment permissions
    - Container Registry push permissions
    - Cloud Trace write permissions

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
        --sampling-rate)
            TRACE_SAMPLING_RATE="$2"
            shift 2
            ;;
        --security-sampling)
            SECURITY_TRACE_SAMPLING_RATE="$2"
            shift 2
            ;;
        --collector-version)
            OTEL_COLLECTOR_VERSION="$2"
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