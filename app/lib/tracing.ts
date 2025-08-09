// iSECTECH OpenTelemetry Instrumentation
// Production-grade distributed tracing for Next.js application

import { NodeSDK } from '@opentelemetry/sdk-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { JaegerExporter } from '@opentelemetry/exporter-jaeger';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { BatchSpanProcessor, ConsoleSpanExporter } from '@opentelemetry/sdk-trace-node';
import { NodeSDKConfiguration } from '@opentelemetry/sdk-node';
import { Sampler, AlwaysOnSampler, TraceIdRatioBasedSampler, ParentBasedSampler } from '@opentelemetry/sdk-trace-base';

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const SERVICE_NAME = 'isectech-frontend';
const SERVICE_VERSION = process.env.npm_package_version || '1.0.0';
const ENVIRONMENT = process.env.NODE_ENV || 'development';
const TRACE_ENDPOINT = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT || 'http://localhost:4318/v1/traces';
const METRICS_ENDPOINT = process.env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT || 'http://localhost:4318/v1/metrics';
const JAEGER_ENDPOINT = process.env.JAEGER_ENDPOINT || 'http://localhost:14268/api/traces';

// ═══════════════════════════════════════════════════════════════════════════════
// RESOURCE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const resource = new Resource({
  [SemanticResourceAttributes.SERVICE_NAME]: SERVICE_NAME,
  [SemanticResourceAttributes.SERVICE_VERSION]: SERVICE_VERSION,
  [SemanticResourceAttributes.SERVICE_NAMESPACE]: 'isectech',
  [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]: ENVIRONMENT,
  [SemanticResourceAttributes.SERVICE_INSTANCE_ID]: process.env.HOSTNAME || 'unknown',
  [SemanticResourceAttributes.CONTAINER_NAME]: process.env.CONTAINER_NAME || 'frontend',
  [SemanticResourceAttributes.CONTAINER_ID]: process.env.CONTAINER_ID || 'unknown',
  [SemanticResourceAttributes.K8S_POD_NAME]: process.env.K8S_POD_NAME || 'unknown',
  [SemanticResourceAttributes.K8S_NAMESPACE_NAME]: process.env.K8S_NAMESPACE || 'default',
  [SemanticResourceAttributes.K8S_CLUSTER_NAME]: process.env.K8S_CLUSTER_NAME || 'isectech-cluster',
  // Custom attributes for iSECTECH
  'isectech.component': 'frontend',
  'isectech.team': 'frontend-team',
  'isectech.environment.type': ENVIRONMENT,
  'isectech.version': SERVICE_VERSION,
});

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLING CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

function createSampler(): Sampler {
  const samplingRate = parseFloat(process.env.OTEL_TRACES_SAMPLER_ARG || '0.1');
  
  if (ENVIRONMENT === 'development') {
    return new AlwaysOnSampler();
  }
  
  // Production sampling strategy
  return new ParentBasedSampler({
    root: new TraceIdRatioBasedSampler(samplingRate),
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRACE EXPORTERS
// ═══════════════════════════════════════════════════════════════════════════════

const traceExporters = [];

// OTLP HTTP Exporter (primary)
traceExporters.push(
  new OTLPTraceExporter({
    url: TRACE_ENDPOINT,
    headers: {
      'Authorization': `Bearer ${process.env.OTEL_AUTH_TOKEN || ''}`,
      'X-Service-Name': SERVICE_NAME,
    },
    compression: 'gzip',
  })
);

// Jaeger Exporter (backup/legacy)
if (process.env.ENABLE_JAEGER_EXPORT === 'true') {
  traceExporters.push(
    new JaegerExporter({
      endpoint: JAEGER_ENDPOINT,
      tags: [
        { key: 'service.name', value: SERVICE_NAME },
        { key: 'environment', value: ENVIRONMENT },
      ],
    })
  );
}

// Console exporter for development
if (ENVIRONMENT === 'development' && process.env.OTEL_DEBUG === 'true') {
  traceExporters.push(new ConsoleSpanExporter());
}

// ═══════════════════════════════════════════════════════════════════════════════
// METRICS CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const metricExporter = new OTLPMetricExporter({
  url: METRICS_ENDPOINT,
  headers: {
    'Authorization': `Bearer ${process.env.OTEL_AUTH_TOKEN || ''}`,
    'X-Service-Name': SERVICE_NAME,
  },
  compression: 'gzip',
});

const metricReader = new PeriodicExportingMetricReader({
  exporter: metricExporter,
  exportIntervalMillis: 30000, // 30 seconds
  exportTimeoutMillis: 5000,   // 5 seconds
});

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUMENTATION CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const instrumentations = [
  getNodeAutoInstrumentations({
    '@opentelemetry/instrumentation-http': {
      enabled: true,
      ignoreIncomingRequestHook: (req) => {
        // Ignore health checks and metrics endpoints
        const ignoredPaths = ['/health', '/metrics', '/favicon.ico', '/_next/static'];
        return ignoredPaths.some(path => req.url?.includes(path));
      },
      ignoreOutgoingRequestHook: (req) => {
        // Ignore requests to telemetry endpoints
        const ignoredHosts = ['localhost:4318', 'jaeger-collector', 'otel-collector'];
        return ignoredHosts.some(host => req.hostname?.includes(host));
      },
      responseHook: (span, response) => {
        // Add custom attributes for security monitoring
        if (response.statusCode && response.statusCode >= 400) {
          span.setAttributes({
            'isectech.error': true,
            'isectech.error_type': response.statusCode >= 500 ? 'server_error' : 'client_error',
          });
        }
      },
      requestHook: (span, request) => {
        // Add custom security attributes
        span.setAttributes({
          'isectech.user_agent': request.headers['user-agent'] || 'unknown',
          'isectech.request_id': request.headers['x-request-id'] || 'unknown',
          'isectech.client_ip': request.headers['x-forwarded-for'] || request.socket?.remoteAddress || 'unknown',
        });
      },
    },
    '@opentelemetry/instrumentation-express': {
      enabled: true,
      ignoreLayers: [
        (name) => name === 'query' || name === 'expressInit',
      ],
    },
    '@opentelemetry/instrumentation-fs': {
      enabled: false, // Disabled to reduce noise
    },
    '@opentelemetry/instrumentation-dns': {
      enabled: false, // Disabled to reduce noise
    },
    '@opentelemetry/instrumentation-net': {
      enabled: false, // Disabled to reduce noise
    },
    '@opentelemetry/instrumentation-graphql': {
      enabled: true,
      allowValues: false, // Security: don't capture actual values
      depth: 2,
    },
    '@opentelemetry/instrumentation-redis': {
      enabled: true,
      dbStatementSerializer: (cmdName, cmdArgs) => {
        // Security: don't capture sensitive Redis data
        return `${cmdName} [REDACTED]`;
      },
    },
  }),
];

// ═══════════════════════════════════════════════════════════════════════════════
// SDK CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

const sdkConfig: NodeSDKConfiguration = {
  resource,
  instrumentations,
  sampler: createSampler(),
  spanProcessors: traceExporters.map(exporter => new BatchSpanProcessor(exporter, {
    maxQueueSize: 2048,
    maxExportBatchSize: 512,
    exportTimeoutMillis: 30000,
    scheduledDelayMillis: 5000,
  })),
  metricReader,
};

// ═══════════════════════════════════════════════════════════════════════════════
// SDK INITIALIZATION
// ═══════════════════════════════════════════════════════════════════════════════

let sdk: NodeSDK | null = null;

export function initializeTracing(): NodeSDK {
  if (sdk) {
    console.warn('Tracing already initialized');
    return sdk;
  }

  try {
    sdk = new NodeSDK(sdkConfig);
    sdk.start();
    
    console.log(`✅ OpenTelemetry tracing initialized for ${SERVICE_NAME}`, {
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      environment: ENVIRONMENT,
      traceEndpoint: TRACE_ENDPOINT,
      metricsEndpoint: METRICS_ENDPOINT,
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      sdk?.shutdown()
        .then(() => console.log('✅ OpenTelemetry terminated'))
        .catch((error) => console.error('❌ Error terminating OpenTelemetry', error))
        .finally(() => process.exit(0));
    });

    return sdk;
  } catch (error) {
    console.error('❌ Error initializing OpenTelemetry tracing:', error);
    throw error;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

export function getTraceId(): string | undefined {
  const { trace } = require('@opentelemetry/api');
  const span = trace.getActiveSpan();
  return span?.spanContext().traceId;
}

export function getSpanId(): string | undefined {
  const { trace } = require('@opentelemetry/api');
  const span = trace.getActiveSpan();
  return span?.spanContext().spanId;
}

export function addSpanAttributes(attributes: Record<string, string | number | boolean>): void {
  const { trace } = require('@opentelemetry/api');
  const span = trace.getActiveSpan();
  if (span) {
    span.setAttributes(attributes);
  }
}

export function addSpanEvent(name: string, attributes?: Record<string, string | number | boolean>): void {
  const { trace } = require('@opentelemetry/api');
  const span = trace.getActiveSpan();
  if (span) {
    span.addEvent(name, attributes);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM SPAN UTILITIES FOR ISECTECH
// ═══════════════════════════════════════════════════════════════════════════════

export function createSecuritySpan(name: string, attributes?: Record<string, any>) {
  const { trace } = require('@opentelemetry/api');
  const tracer = trace.getTracer(SERVICE_NAME, SERVICE_VERSION);
  
  return tracer.startSpan(name, {
    attributes: {
      'isectech.operation_type': 'security',
      'isectech.component': 'security',
      ...attributes,
    },
  });
}

export function createBusinessSpan(name: string, userId?: string, attributes?: Record<string, any>) {
  const { trace } = require('@opentelemetry/api');
  const tracer = trace.getTracer(SERVICE_NAME, SERVICE_VERSION);
  
  return tracer.startSpan(name, {
    attributes: {
      'isectech.operation_type': 'business',
      'isectech.user_id': userId || 'anonymous',
      ...attributes,
    },
  });
}

// Auto-initialize if not in test environment
if (process.env.NODE_ENV !== 'test' && !process.env.DISABLE_TRACING) {
  initializeTracing();
}