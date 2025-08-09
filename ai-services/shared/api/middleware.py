"""
Production-Grade FastAPI Middleware for iSECTECH AI Services

Provides enterprise middleware including:
- Request/response logging and audit trails
- Security headers and CORS configuration
- Rate limiting and DDoS protection
- Performance monitoring and metrics collection
- Error handling and exception management
- Request validation and sanitization
"""

import asyncio
import json
import time
import traceback
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint

from .monitoring import APIMetricsCollector, HealthChecker
from .security import APISecurityManager, SecurityContext
from ..config.settings import SecuritySettings
from ..security.audit import AuditLogger


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    def __init__(self, app, settings: SecuritySettings):
        super().__init__(app)
        self.settings = settings
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        
        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        response.headers["Content-Security-Policy"] = csp
        
        # HSTS for HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # Remove server information
        response.headers.pop("server", None)
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Comprehensive request/response logging and audit trails"""
    
    def __init__(self, app, audit_logger: AuditLogger, metrics_collector: APIMetricsCollector):
        super().__init__(app)
        self.audit_logger = audit_logger
        self.metrics_collector = metrics_collector
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate request ID
        request_id = str(uuid4())
        request.state.request_id = request_id
        
        # Start timing
        start_time = time.time()
        
        # Extract request details
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        method = request.method
        path = request.url.path
        
        # Log request start
        request_details = {
            "request_id": request_id,
            "method": method,
            "path": path,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "headers": dict(request.headers),
            "query_params": dict(request.query_params)
        }
        
        # Don't log sensitive headers
        if "authorization" in request_details["headers"]:
            request_details["headers"]["authorization"] = "[REDACTED]"
        if "x-api-key" in request_details["headers"]:
            request_details["headers"]["x-api-key"] = "[REDACTED]"
        
        self.audit_logger.log_api_request(
            method=method,
            path=path,
            client_ip=client_ip,
            user_agent=user_agent,
            details=request_details
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate timing
            duration = time.time() - start_time
            
            # Extract tenant ID from security context if available
            tenant_id = getattr(request.state, "tenant_id", "unknown")
            
            # Record metrics
            self.metrics_collector.record_request(
                method=method,
                endpoint=path,
                status_code=response.status_code,
                duration=duration,
                tenant_id=tenant_id
            )
            
            # Log response
            response_details = {
                "request_id": request_id,
                "status_code": response.status_code,
                "duration_ms": duration * 1000,
                "response_headers": dict(response.headers)
            }
            
            self.audit_logger.log_api_response(
                status_code=response.status_code,
                duration_ms=duration * 1000,
                details=response_details
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            # Calculate timing for error case
            duration = time.time() - start_time
            
            # Log error
            error_details = {
                "request_id": request_id,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "duration_ms": duration * 1000,
                "traceback": traceback.format_exc()
            }
            
            self.audit_logger.log_api_error(
                error_type=type(e).__name__,
                error_message=str(e),
                details=error_details
            )
            
            # Record error metrics
            tenant_id = getattr(request.state, "tenant_id", "unknown")
            self.metrics_collector.record_request(
                method=method,
                endpoint=path,
                status_code=500,
                duration=duration,
                tenant_id=tenant_id
            )
            
            raise
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP handling proxies"""
        # Check for forwarded headers (load balancer, reverse proxy)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Rate limiting and DDoS protection"""
    
    def __init__(self, app, security_manager: APISecurityManager):
        super().__init__(app)
        self.security_manager = security_manager
        
        # Default rate limits (requests per minute)
        self.default_rate_limits = {
            "authenticated": 1000,
            "api_key": 5000,
            "anonymous": 100
        }
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip rate limiting for health checks
        if request.url.path in ["/health", "/metrics"]:
            return await call_next(request)
        
        # Determine rate limit identifier and limit
        identifier, rate_limit = await self._get_rate_limit_info(request)
        
        # Check rate limit
        if not await self.security_manager.check_rate_limit(identifier, rate_limit):
            # Log rate limit violation
            self.security_manager.audit_logger.log_security_event(
                event_type="rate_limit_violation",
                details={
                    "identifier": identifier,
                    "rate_limit": rate_limit,
                    "client_ip": request.client.host,
                    "user_agent": request.headers.get("user-agent", ""),
                    "path": request.url.path
                }
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(rate_limit),
                    "X-RateLimit-Remaining": "0"
                }
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(rate_limit)
        
        return response
    
    async def _get_rate_limit_info(self, request: Request) -> tuple[str, int]:
        """Determine rate limit identifier and limit"""
        
        # Check for API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            try:
                key_info = await self.security_manager.verify_api_key(api_key)
                return f"api_key:{key_info.key_id}", key_info.rate_limit
            except:
                pass
        
        # Check for JWT token
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                payload = await self.security_manager.verify_token(token)
                return f"user:{payload.sub}", self.default_rate_limits["authenticated"]
            except:
                pass
        
        # Fall back to IP-based rate limiting
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}", self.default_rate_limits["anonymous"]


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Global error handling and sanitization"""
    
    def __init__(self, app, audit_logger: AuditLogger, debug: bool = False):
        super().__init__(app)
        self.audit_logger = audit_logger
        self.debug = debug
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            return await call_next(request)
            
        except HTTPException:
            # Let FastAPI handle HTTP exceptions
            raise
            
        except Exception as e:
            # Log unexpected errors
            error_id = str(uuid4())
            request_id = getattr(request.state, "request_id", "unknown")
            
            error_details = {
                "error_id": error_id,
                "request_id": request_id,
                "error_type": type(e).__name__,
                "error_message": str(e),
                "path": request.url.path,
                "method": request.method,
                "client_ip": request.client.host if request.client else "unknown"
            }
            
            if self.debug:
                error_details["traceback"] = traceback.format_exc()
            
            self.audit_logger.log_api_error(
                error_type=type(e).__name__,
                error_message=str(e),
                details=error_details
            )
            
            # Return sanitized error response
            error_response = {
                "error": "Internal server error",
                "error_id": error_id,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            if self.debug:
                error_response["details"] = str(e)
                error_response["traceback"] = traceback.format_exc()
            
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content=error_response
            )


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Request validation and sanitization"""
    
    def __init__(self, app):
        super().__init__(app)
        
        # Suspicious patterns
        self.suspicious_patterns = [
            "script>", "<iframe", "javascript:", "vbscript:",
            "onload=", "onerror=", "onclick=", "eval(",
            "../", "..\\", "/etc/", "/proc/",
            "union select", "drop table", "delete from",
            "${", "#{", "<%", "%>"
        ]
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Validate request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 10 * 1024 * 1024:  # 10MB limit
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request too large"
            )
        
        # Validate headers
        self._validate_headers(request)
        
        # Validate query parameters
        self._validate_query_params(request)
        
        # For POST/PUT requests, validate body
        if request.method in ["POST", "PUT", "PATCH"]:
            await self._validate_body(request)
        
        return await call_next(request)
    
    def _validate_headers(self, request: Request):
        """Validate request headers for suspicious content"""
        for name, value in request.headers.items():
            if self._contains_suspicious_content(value):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid header: {name}"
                )
    
    def _validate_query_params(self, request: Request):
        """Validate query parameters"""
        for name, value in request.query_params.items():
            if self._contains_suspicious_content(value):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid query parameter: {name}"
                )
    
    async def _validate_body(self, request: Request):
        """Validate request body"""
        try:
            # Read body
            body = await request.body()
            
            if body:
                # Convert to string for pattern matching
                body_str = body.decode("utf-8", errors="ignore")
                
                if self._contains_suspicious_content(body_str):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid request content"
                    )
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid request encoding"
            )
    
    def _contains_suspicious_content(self, content: str) -> bool:
        """Check if content contains suspicious patterns"""
        content_lower = content.lower()
        return any(pattern in content_lower for pattern in self.suspicious_patterns)


class TenantMiddleware(BaseHTTPMiddleware):
    """Multi-tenant context middleware"""
    
    def __init__(self, app):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract tenant information from various sources
        tenant_id = None
        
        # 1. Check X-Tenant-ID header
        tenant_id = request.headers.get("X-Tenant-ID")
        
        # 2. Check subdomain
        if not tenant_id:
            host = request.headers.get("host", "")
            if "." in host:
                subdomain = host.split(".")[0]
                if subdomain not in ["www", "api", "admin"]:
                    tenant_id = subdomain
        
        # 3. Check JWT token (will be set by authentication middleware)
        if not tenant_id and hasattr(request.state, "security_context"):
            security_context: SecurityContext = request.state.security_context
            tenant_id = security_context.tenant_id
        
        # Set tenant context
        request.state.tenant_id = tenant_id or "default"
        
        return await call_next(request)


def setup_cors_middleware(app, settings: SecuritySettings):
    """Configure CORS middleware"""
    
    # Determine allowed origins
    if settings.environment == "development":
        allowed_origins = ["*"]
        allow_credentials = False
    else:
        # Production: restrict origins
        allowed_origins = [
            "https://app.isectech.com",
            "https://admin.isectech.com",
            "https://dashboard.isectech.com"
        ]
        allow_credentials = True
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"]
    )


def setup_middleware(app, 
                    settings: SecuritySettings,
                    security_manager: APISecurityManager,
                    audit_logger: AuditLogger,
                    metrics_collector: APIMetricsCollector,
                    debug: bool = False):
    """Setup all middleware in correct order"""
    
    # 1. CORS (must be first)
    setup_cors_middleware(app, settings)
    
    # 2. Security headers
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    
    # 3. Request validation and sanitization
    app.add_middleware(RequestValidationMiddleware)
    
    # 4. Rate limiting
    app.add_middleware(RateLimitingMiddleware, security_manager=security_manager)
    
    # 5. Tenant context
    app.add_middleware(TenantMiddleware)
    
    # 6. Request logging (near the end to capture all context)
    app.add_middleware(
        RequestLoggingMiddleware,
        audit_logger=audit_logger,
        metrics_collector=metrics_collector
    )
    
    # 7. Error handling (last to catch all errors)
    app.add_middleware(
        ErrorHandlingMiddleware,
        audit_logger=audit_logger,
        debug=debug
    )