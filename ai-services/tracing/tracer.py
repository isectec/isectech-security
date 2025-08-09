"""
iSECTECH Python OpenTelemetry Instrumentation
Production-grade distributed tracing for AI services
"""

import os
import logging
from typing import Dict, Any, Optional
from contextlib import contextmanager

from opentelemetry import trace, metrics
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.trace import TracerProvider, Span
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.semconv.resource import ResourceAttributes
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositeHTTPPropagator
from opentelemetry.sdk.trace.sampling import (
    TraceIdRatioBasedSampler,
    AlwaysSample,
    ParentBasedSampler,
)
from opentelemetry.instrumentation.auto_instrumentation import sitecustomize

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

SERVICE_NAME = "isectech-ai-services"
SERVICE_NAMESPACE = "isectech"
DEFAULT_VERSION = "1.0.0"

logger = logging.getLogger(__name__)


class TracingConfig:
    """Configuration class for OpenTelemetry tracing"""
    
    def __init__(self):
        self.service_name = os.getenv("OTEL_SERVICE_NAME", SERVICE_NAME)
        self.service_version = os.getenv("OTEL_SERVICE_VERSION", DEFAULT_VERSION)
        self.environment = os.getenv("OTEL_ENVIRONMENT", "development")
        self.otlp_endpoint = os.getenv(
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", 
            "http://localhost:4318/v1/traces"
        )
        self.metrics_endpoint = os.getenv(
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            "http://localhost:4318/v1/metrics"
        )
        self.jaeger_endpoint = os.getenv(
            "JAEGER_ENDPOINT", 
            "http://localhost:14268/api/traces"
        )
        self.sampling_rate = float(os.getenv("OTEL_TRACES_SAMPLER_ARG", "0.1"))
        self.debug = os.getenv("OTEL_DEBUG", "false").lower() == "true"
        self.enable_jaeger = os.getenv("ENABLE_JAEGER_EXPORT", "false").lower() == "true"
        self.enable_otlp = os.getenv("ENABLE_OTLP_EXPORT", "true").lower() == "true"
        self.auth_token = os.getenv("OTEL_AUTH_TOKEN", "")


class ISECTECHTracerProvider:
    """Custom tracer provider for iSECTECH AI services"""
    
    def __init__(self, config: TracingConfig):
        self.config = config
        self.tracer_provider = None
        self.tracer = None
        self.meter_provider = None
        self.meter = None
        self._initialize()
    
    def _create_resource(self) -> Resource:
        """Create OpenTelemetry resource with service information"""
        attributes = {
            ResourceAttributes.SERVICE_NAME: self.config.service_name,
            ResourceAttributes.SERVICE_VERSION: self.config.service_version,
            ResourceAttributes.SERVICE_NAMESPACE: SERVICE_NAMESPACE,
            ResourceAttributes.DEPLOYMENT_ENVIRONMENT: self.config.environment,
            ResourceAttributes.SERVICE_INSTANCE_ID: os.getenv("HOSTNAME", "unknown"),
            ResourceAttributes.CONTAINER_NAME: os.getenv("CONTAINER_NAME", "ai-services"),
            ResourceAttributes.CONTAINER_ID: os.getenv("CONTAINER_ID", "unknown"),
            ResourceAttributes.K8S_POD_NAME: os.getenv("K8S_POD_NAME", "unknown"),
            ResourceAttributes.K8S_NAMESPACE_NAME: os.getenv("K8S_NAMESPACE", "default"),
            ResourceAttributes.K8S_CLUSTER_NAME: os.getenv("K8S_CLUSTER_NAME", "isectech-cluster"),
            
            # Custom iSECTECH attributes
            "isectech.component": "ai-services",
            "isectech.team": "ai-team",
            "isectech.environment.type": self.config.environment,
            "isectech.version": self.config.service_version,
        }
        
        return Resource.create(attributes)
    
    def _create_sampler(self):
        """Create trace sampler based on environment"""
        if self.config.environment == "development" or self.config.debug:
            return AlwaysSample()
        
        # Production sampling with parent-based sampling
        return ParentBasedSampler(
            root=TraceIdRatioBasedSampler(self.config.sampling_rate)
        )
    
    def _create_span_processors(self):
        """Create span processors with configured exporters"""
        span_processors = []
        
        # OTLP HTTP Exporter
        if self.config.enable_otlp:
            headers = {}
            if self.config.auth_token:
                headers = {
                    "Authorization": f"Bearer {self.config.auth_token}",
                    "X-Service-Name": self.config.service_name,
                }
            
            otlp_exporter = OTLPSpanExporter(
                endpoint=self.config.otlp_endpoint,
                headers=headers,
                compression="gzip",
            )
            
            span_processors.append(
                BatchSpanProcessor(
                    otlp_exporter,
                    max_queue_size=2048,
                    max_export_batch_size=512,
                    export_timeout_millis=30000,
                    schedule_delay_millis=5000,
                )
            )
        
        # Jaeger Exporter
        if self.config.enable_jaeger:
            jaeger_exporter = JaegerExporter(
                collector_endpoint=self.config.jaeger_endpoint,
            )
            span_processors.append(BatchSpanProcessor(jaeger_exporter))
        
        # Console exporter for development
        if self.config.debug and self.config.environment == "development":
            span_processors.append(BatchSpanProcessor(ConsoleSpanExporter()))
        
        return span_processors
    
    def _create_metric_reader(self):
        """Create metric reader for OTLP metrics export"""
        if not self.config.enable_otlp:
            return None
            
        headers = {}
        if self.config.auth_token:
            headers = {
                "Authorization": f"Bearer {self.config.auth_token}",
                "X-Service-Name": self.config.service_name,
            }
        
        metric_exporter = OTLPMetricExporter(
            endpoint=self.config.metrics_endpoint,
            headers=headers,
            compression="gzip",
        )
        
        return PeriodicExportingMetricReader(
            exporter=metric_exporter,
            export_interval_millis=30000,  # 30 seconds
            export_timeout_millis=5000,    # 5 seconds
        )
    
    def _initialize(self):
        """Initialize the tracer and meter providers"""
        try:
            # Create resource
            resource = self._create_resource()
            
            # Initialize tracer provider
            self.tracer_provider = TracerProvider(
                resource=resource,
                sampler=self._create_sampler(),
            )
            
            # Add span processors
            for processor in self._create_span_processors():
                self.tracer_provider.add_span_processor(processor)
            
            # Set global tracer provider
            trace.set_tracer_provider(self.tracer_provider)
            
            # Create tracer
            self.tracer = trace.get_tracer(
                self.config.service_name,
                self.config.service_version,
            )
            
            # Initialize meter provider
            metric_reader = self._create_metric_reader()
            if metric_reader:
                self.meter_provider = MeterProvider(
                    resource=resource,
                    metric_readers=[metric_reader],
                )
                metrics.set_meter_provider(self.meter_provider)
                self.meter = metrics.get_meter(
                    self.config.service_name,
                    self.config.service_version,
                )
            
            # Set global propagator
            trace.set_global_textmap(
                CompositeHTTPPropagator([
                    TraceContextTextMapPropagator(),
                    W3CBaggagePropagator(),
                ])
            )
            
            logger.info(
                f"✅ OpenTelemetry tracing initialized for {self.config.service_name}",
                extra={
                    "service": self.config.service_name,
                    "version": self.config.service_version,
                    "environment": self.config.environment,
                    "otlp_endpoint": self.config.otlp_endpoint,
                    "sampling_rate": self.config.sampling_rate,
                }
            )
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize OpenTelemetry tracing: {e}")
            raise
    
    def get_tracer(self) -> trace.Tracer:
        """Get the configured tracer"""
        return self.tracer
    
    def get_meter(self) -> Optional[metrics.Meter]:
        """Get the configured meter"""
        return self.meter
    
    def shutdown(self):
        """Shutdown the tracer provider"""
        if self.tracer_provider:
            self.tracer_provider.shutdown()
        if self.meter_provider:
            self.meter_provider.shutdown()


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL TRACER PROVIDER
# ═══════════════════════════════════════════════════════════════════════════════

_global_tracer_provider: Optional[ISECTECHTracerProvider] = None


def initialize_tracing(config: Optional[TracingConfig] = None) -> ISECTECHTracerProvider:
    """Initialize global tracing"""
    global _global_tracer_provider
    
    if _global_tracer_provider:
        logger.warning("Tracing already initialized")
        return _global_tracer_provider
    
    if config is None:
        config = TracingConfig()
    
    _global_tracer_provider = ISECTECHTracerProvider(config)
    return _global_tracer_provider


def get_tracer() -> trace.Tracer:
    """Get the global tracer"""
    if _global_tracer_provider:
        return _global_tracer_provider.get_tracer()
    return trace.get_tracer(SERVICE_NAME)


def get_meter() -> Optional[metrics.Meter]:
    """Get the global meter"""
    if _global_tracer_provider:
        return _global_tracer_provider.get_meter()
    return None


def shutdown_tracing():
    """Shutdown global tracing"""
    global _global_tracer_provider
    if _global_tracer_provider:
        _global_tracer_provider.shutdown()
        _global_tracer_provider = None


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM SPAN UTILITIES FOR ISECTECH
# ═══════════════════════════════════════════════════════════════════════════════

@contextmanager
def create_security_span(name: str, attributes: Optional[Dict[str, Any]] = None):
    """Create a span for security operations"""
    tracer = get_tracer()
    span_attributes = {
        "isectech.operation_type": "security",
        "isectech.component": "security",
    }
    if attributes:
        span_attributes.update(attributes)
    
    with tracer.start_as_current_span(name, attributes=span_attributes) as span:
        yield span


@contextmanager
def create_ai_span(name: str, model_name: str = None, attributes: Optional[Dict[str, Any]] = None):
    """Create a span for AI/ML operations"""
    tracer = get_tracer()
    span_attributes = {
        "isectech.operation_type": "ai",
        "isectech.component": "ai",
    }
    if model_name:
        span_attributes["ai.model.name"] = model_name
    if attributes:
        span_attributes.update(attributes)
    
    with tracer.start_as_current_span(name, attributes=span_attributes) as span:
        yield span


@contextmanager
def create_business_span(name: str, user_id: str = None, attributes: Optional[Dict[str, Any]] = None):
    """Create a span for business operations"""
    tracer = get_tracer()
    span_attributes = {
        "isectech.operation_type": "business",
        "isectech.user_id": user_id or "anonymous",
    }
    if attributes:
        span_attributes.update(attributes)
    
    with tracer.start_as_current_span(name, attributes=span_attributes) as span:
        yield span


@contextmanager
def create_database_span(operation: str, table: str = None, attributes: Optional[Dict[str, Any]] = None):
    """Create a span for database operations"""
    tracer = get_tracer()
    span_name = f"db.{operation}"
    if table:
        span_name += f" {table}"
    
    span_attributes = {
        "isectech.operation_type": "database",
        "db.operation": operation,
        "isectech.component": "database",
    }
    if table:
        span_attributes["db.sql.table"] = table
    if attributes:
        span_attributes.update(attributes)
    
    with tracer.start_as_current_span(span_name, attributes=span_attributes) as span:
        yield span


# ═══════════════════════════════════════════════════════════════════════════════
# SPAN UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def add_security_event(event_type: str, attributes: Optional[Dict[str, Any]] = None):
    """Add a security event to the current span"""
    span = trace.get_current_span()
    if span.is_recording():
        event_attributes = {"isectech.security.event_type": event_type}
        if attributes:
            event_attributes.update(attributes)
        span.add_event("security.event", event_attributes)


def add_error_event(error: Exception, error_type: str = None):
    """Add an error event to the current span"""
    span = trace.get_current_span()
    if span.is_recording():
        span.record_exception(error)
        span.set_attributes({
            "isectech.error": True,
            "isectech.error.type": error_type or type(error).__name__,
        })
        span.set_status(trace.Status(trace.StatusCode.ERROR, str(error)))


def get_trace_id() -> Optional[str]:
    """Get the current trace ID"""
    span = trace.get_current_span()
    if span.get_span_context().is_valid:
        return format(span.get_span_context().trace_id, "032x")
    return None


def get_span_id() -> Optional[str]:
    """Get the current span ID"""
    span = trace.get_current_span()
    if span.get_span_context().is_valid:
        return format(span.get_span_context().span_id, "016x")
    return None


def add_span_attributes(attributes: Dict[str, Any]):
    """Add attributes to the current span"""
    span = trace.get_current_span()
    if span.is_recording():
        span.set_attributes(attributes)


# ═══════════════════════════════════════════════════════════════════════════════
# AI/ML SPECIFIC UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def trace_model_inference(model_name: str, input_size: int = None, output_size: int = None):
    """Decorator for tracing AI model inference"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with create_ai_span(
                f"ai.inference.{model_name}",
                model_name=model_name,
                attributes={
                    "ai.model.input_size": input_size,
                    "ai.model.output_size": output_size,
                }
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("ai.inference.success", True)
                    return result
                except Exception as e:
                    span.set_attribute("ai.inference.success", False)
                    add_error_event(e, "ai_inference_error")
                    raise
        return wrapper
    return decorator


def trace_data_processing(operation_type: str):
    """Decorator for tracing data processing operations"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            with create_ai_span(
                f"data.processing.{operation_type}",
                attributes={"data.operation_type": operation_type}
            ) as span:
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("data.processing.success", True)
                    return result
                except Exception as e:
                    span.set_attribute("data.processing.success", False)
                    add_error_event(e, "data_processing_error")
                    raise
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

# Auto-initialize tracing if not in test environment
if (
    os.getenv("PYTEST_CURRENT_TEST") is None and 
    os.getenv("DISABLE_TRACING", "false").lower() != "true"
):
    try:
        initialize_tracing()
    except Exception as e:
        logger.error(f"Failed to auto-initialize tracing: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP ON EXIT
# ═══════════════════════════════════════════════════════════════════════════════

import atexit
atexit.register(shutdown_tracing)