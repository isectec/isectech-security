"""
FastAPI application for behavioral analysis service.

This module provides the main FastAPI application with middleware,
security, monitoring, and endpoint routing.
"""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Optional

import structlog
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel
import yaml
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GzipMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware

from ....shared.config.settings import Settings, get_settings
from ....shared.security import get_auth_manager, get_authorization_manager, get_audit_logger
from ....shared.security.authentication import AuthenticationManager
from ....shared.security.authorization import AuthorizationManager, SecurityContext
from ....shared.security.audit import AuditLogger, AuditEventType, AuditSeverity
from .endpoints import analysis_router, baseline_router, health_router, metrics_router
from .models import ErrorResponse
from .service_manager import BehavioralAnalysisServiceManager


# Prometheus metrics
REQUEST_COUNT = Counter(
    'behavioral_analysis_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)

REQUEST_DURATION = Histogram(
    'behavioral_analysis_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

ANOMALY_DETECTIONS = Counter(
    'behavioral_analysis_anomalies_total',
    'Total anomalies detected',
    ['entity_type', 'threat_level']
)

BASELINE_OPERATIONS = Counter(
    'behavioral_analysis_baseline_operations_total',
    'Baseline operations',
    ['operation', 'status']
)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Custom security middleware for authentication and authorization."""
    
    def __init__(self, app, auth_manager: AuthenticationManager, 
                 authz_manager: AuthorizationManager, audit_logger: AuditLogger):
        super().__init__(app)
        self.auth_manager = auth_manager
        self.authz_manager = authz_manager
        self.audit_logger = audit_logger
        self.logger = structlog.get_logger("security_middleware")
    
    async def dispatch(self, request: Request, call_next):
        """Process request with security checks."""
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        # Add request ID to headers
        request.state.request_id = request_id
        
        # Skip authentication for health and metrics endpoints
        if request.url.path in ["/health", "/metrics", "/docs", "/redoc", "/openapi.json"]:
            response = await call_next(request)
            return response
        
        try:
            # Extract authentication token
            auth_header = request.headers.get("Authorization")
            api_key = request.headers.get("X-API-Key")
            
            user_claims = None
            auth_method = "none"
            
            if auth_header and auth_header.startswith("Bearer "):
                # JWT token authentication
                token = auth_header[7:]
                try:
                    user_claims = self.auth_manager.jwt_manager.validate_token(token)
                    auth_method = "jwt"
                except Exception as e:
                    await self._log_auth_failure(request, "Invalid JWT token", str(e))
                    return self._create_auth_error_response("Invalid authentication token")
            
            elif api_key:
                # API key authentication
                try:
                    user_claims = self.auth_manager.authenticate_api_key(api_key)
                    auth_method = "api_key"
                except Exception as e:
                    await self._log_auth_failure(request, "Invalid API key", str(e))
                    return self._create_auth_error_response("Invalid API key")
            
            else:
                await self._log_auth_failure(request, "Missing authentication", "No auth header or API key")
                return self._create_auth_error_response("Authentication required")
            
            if not user_claims:
                await self._log_auth_failure(request, "Authentication failed", "No valid claims")
                return self._create_auth_error_response("Authentication failed")
            
            # Create security context
            security_context = SecurityContext(
                user_claims=user_claims,
                request_ip=self._get_client_ip(request),
                request_time=datetime.utcnow(),
                additional_context={
                    "request_id": request_id,
                    "auth_method": auth_method,
                    "user_agent": request.headers.get("User-Agent", ""),
                    "endpoint": request.url.path,
                    "method": request.method
                }
            )
            
            # Store security context in request state
            request.state.security_context = security_context
            request.state.user_claims = user_claims
            
            # Log successful authentication
            self.audit_logger.log_authentication_event(
                success=True,
                user_id=user_claims.user_id,
                tenant_id=user_claims.tenant_id,
                source_ip=security_context.request_ip,
                user_agent=request.headers.get("User-Agent")
            )
            
            # Process request
            response = await call_next(request)
            
            # Log request completion
            processing_time = time.time() - start_time
            self.logger.info(
                "Request completed",
                request_id=request_id,
                user_id=user_claims.user_id,
                tenant_id=user_claims.tenant_id,
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                processing_time=processing_time
            )
            
            return response
        
        except Exception as e:
            self.logger.error(
                "Security middleware error",
                request_id=request_id,
                error=str(e),
                path=request.url.path
            )
            return self._create_error_response("Internal security error", 500)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"
    
    async def _log_auth_failure(self, request: Request, reason: str, detail: str):
        """Log authentication failure."""
        self.audit_logger.log_authentication_event(
            success=False,
            user_id="unknown",
            tenant_id="unknown",
            source_ip=self._get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            failure_reason=f"{reason}: {detail}"
        )
    
    def _create_auth_error_response(self, message: str) -> JSONResponse:
        """Create authentication error response."""
        return JSONResponse(
            status_code=401,
            content=ErrorResponse(
                error="authentication_failed",
                message=message,
                suggestions=["Check your authentication token or API key"]
            ).dict()
        )
    
    def _create_error_response(self, message: str, status_code: int) -> JSONResponse:
        """Create generic error response."""
        return JSONResponse(
            status_code=status_code,
            content=ErrorResponse(
                error="internal_error",
                message=message
            ).dict()
        )


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware for collecting metrics."""
    
    async def dispatch(self, request: Request, call_next):
        """Collect request metrics."""
        start_time = time.time()
        
        # Process request
        response = await call_next(request)
        
        # Record metrics
        duration = time.time() - start_time
        method = request.method
        endpoint = request.url.path
        status_code = str(response.status_code)
        
        REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        REQUEST_DURATION.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        return response


class ServiceManager:
    """Global service manager instance."""
    
    def __init__(self):
        self.manager: Optional[BehavioralAnalysisServiceManager] = None
        self.settings: Optional[Settings] = None
        self.auth_manager: Optional[AuthenticationManager] = None
        self.authz_manager: Optional[AuthorizationManager] = None
        self.audit_logger: Optional[AuditLogger] = None
    
    async def initialize(self):
        """Initialize all services."""
        self.settings = get_settings()
        self.settings.service_name = "behavioral-analysis"
        
        # Initialize security components
        self.auth_manager = get_auth_manager(self.settings.security)
        self.authz_manager = get_authorization_manager()
        self.audit_logger = get_audit_logger("behavioral-analysis")
        
        # Initialize service manager
        self.manager = BehavioralAnalysisServiceManager(self.settings)
        await self.manager.initialize()
    
    async def shutdown(self):
        """Shutdown all services."""
        if self.manager:
            await self.manager.shutdown()


# Global service manager
service_manager = ServiceManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    # Startup
    await service_manager.initialize()
    yield
    # Shutdown
    await service_manager.shutdown()


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="iSECTECH Behavioral Analysis Service",
        description="Production-grade User and Entity Behavior Analytics (UEBA) service",
        version="1.0.0",
        docs_url="/docs" if settings.is_development else None,
        redoc_url="/redoc" if settings.is_development else None,
        lifespan=lifespan
    )

    # Load and validate data sources config at startup
    class DataSourcesConfig(BaseModel):
        defaults: dict
        kafka: dict
        postgres: dict
        elasticsearch: dict

    def load_data_sources_config() -> DataSourcesConfig:
        cfg_path = Path(__file__).parent.parent / "config" / "data-sources.yaml"
        with cfg_path.open("r") as f:
            data = yaml.safe_load(f)
        return DataSourcesConfig(**{k: v for k, v in data.items() if k != "version"})

    try:
        app.state.data_sources = load_data_sources_config()
    except Exception as e:
        raise RuntimeError(f"Failed to load data-sources.yaml: {e}")
    
    # Add middleware
    app.add_middleware(GzipMiddleware, minimum_size=1000)
    
    # CORS middleware for development
    if settings.is_development:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    # Add custom middleware
    app.add_middleware(MetricsMiddleware)
    
    # Security middleware will be added after service initialization
    @app.middleware("http")
    async def add_security_middleware(request: Request, call_next):
        """Dynamically add security middleware when services are ready."""
        if (service_manager.auth_manager and 
            service_manager.authz_manager and 
            service_manager.audit_logger):
            
            security_middleware = SecurityMiddleware(
                app,
                service_manager.auth_manager,
                service_manager.authz_manager,
                service_manager.audit_logger
            )
            return await security_middleware.dispatch(request, call_next)
        else:
            # Services not ready, allow health checks only
            if request.url.path in ["/health", "/metrics"]:
                return await call_next(request)
            else:
                return JSONResponse(
                    status_code=503,
                    content={"error": "service_unavailable", "message": "Service is starting up"}
                )
    
    # Global exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle uncaught exceptions."""
        request_id = getattr(request.state, 'request_id', str(uuid.uuid4()))
        
        logger = structlog.get_logger("api_exception")
        logger.error(
            "Unhandled exception",
            request_id=request_id,
            path=request.url.path,
            method=request.method,
            exception=str(exc),
            exc_info=True
        )
        
        # Log security event if user context available
        if hasattr(request.state, 'security_context'):
            if service_manager.audit_logger:
                service_manager.audit_logger.log_security_event(
                    event_type=AuditEventType.ERROR_OCCURRED,
                    severity=AuditSeverity.HIGH,
                    user_id=request.state.security_context.user_id,
                    tenant_id=request.state.security_context.tenant_id,
                    description=f"Unhandled API exception: {str(exc)}",
                    source_ip=request.state.security_context.request_ip
                )
        
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="internal_server_error",
                message="An internal error occurred",
                detail=str(exc) if settings.is_development else None,
                request_id=request_id,
                suggestions=["Please try again later or contact support"]
            ).dict()
        )
    
    # HTTP exception handler
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        request_id = getattr(request.state, 'request_id', str(uuid.uuid4()))
        
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error="http_error",
                message=exc.detail,
                request_id=request_id
            ).dict()
        )
    
    # Add routers
    app.include_router(health_router, prefix="/health", tags=["Health"])
    app.include_router(metrics_router, prefix="/metrics", tags=["Metrics"])
    app.include_router(analysis_router, prefix="/api/v1/analysis", tags=["Analysis"])
    app.include_router(baseline_router, prefix="/api/v1/baseline", tags=["Baseline"])
    
    # Prometheus metrics endpoint
    @app.get("/metrics")
    async def get_metrics():
        """Get Prometheus metrics."""
        return Response(generate_latest(), media_type="text/plain")
    
    # Root endpoint
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "iSECTECH Behavioral Analysis Service",
            "version": "1.0.0",
            "status": "running",
            "docs": "/docs" if settings.is_development else "disabled",
            "health": "/health",
            "metrics": "/metrics"
        }
    
    return app


def get_service_manager() -> BehavioralAnalysisServiceManager:
    """Get the global service manager."""
    if not service_manager.manager:
        raise HTTPException(status_code=503, detail="Service not initialized")
    return service_manager.manager


def get_security_context(request: Request) -> SecurityContext:
    """Get security context from request."""
    if not hasattr(request.state, 'security_context'):
        raise HTTPException(status_code=401, detail="No security context available")
    return request.state.security_context