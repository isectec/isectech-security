"""
Production-Grade FastAPI Application Foundation for iSECTECH AI Services

Provides enterprise application setup including:
- FastAPI application factory with security integration
- Health check and metrics endpoints
- Authentication and authorization setup
- Monitoring and observability integration
- Multi-tenant configuration
- Production deployment configuration
"""

import asyncio
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel

from .monitoring import (
    APIMetricsCollector, HealthChecker, AlertManager,
    SystemHealth, PerformanceMetrics, SecurityMetrics, BusinessMetrics
)
from .security import (
    APISecurityManager, APIAuthentication, PermissionChecker,
    SecurityContext, APIPermission, SecurityClearance
)
from .middleware import setup_middleware
from ..config.settings import SecuritySettings, MonitoringSettings, MLSettings
from ..security.audit import AuditLogger
from ..mlflow.integration import MLflowIntegration, create_mlflow_router


class APIResponse(BaseModel):
    """Standard API response format"""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime
    request_id: str
    version: str


class APIError(BaseModel):
    """Standard API error format"""
    error: str
    error_code: str
    message: str
    timestamp: datetime
    request_id: str
    details: Optional[Dict[str, Any]] = None


class ServiceInfo(BaseModel):
    """Service information"""
    name: str
    version: str
    description: str
    environment: str
    build_time: str
    commit_hash: str


class ISECTECHApp:
    """Enterprise FastAPI application for iSECTECH AI services"""
    
    def __init__(self,
                 service_name: str,
                 service_version: str,
                 service_description: str,
                 settings: SecuritySettings,
                 monitoring_settings: MonitoringSettings,
                 ml_settings: MLSettings = None,
                 debug: bool = False):
        
        self.service_name = service_name
        self.service_version = service_version
        self.service_description = service_description
        self.settings = settings
        self.monitoring_settings = monitoring_settings
        self.ml_settings = ml_settings or MLSettings()
        self.debug = debug
        
        # Initialize core components
        self.audit_logger = AuditLogger(settings)
        self.security_manager = APISecurityManager(settings)
        self.metrics_collector = APIMetricsCollector(service_name)
        self.health_checker = HealthChecker(settings, monitoring_settings)
        self.alert_manager = AlertManager(settings)
        self.auth = APIAuthentication(self.security_manager)
        
        # Initialize MLflow integration
        self.mlflow_integration = MLflowIntegration(
            security_settings=settings,
            ml_settings=self.ml_settings,
            monitoring_settings=monitoring_settings
        )
        
        # Create FastAPI app
        self.app = self._create_app()
        
        # Setup middleware
        setup_middleware(
            self.app,
            settings,
            self.security_manager,
            self.audit_logger,
            self.metrics_collector,
            debug
        )
        
        # Add core endpoints
        self._add_core_endpoints()
        
        # Add MLflow endpoints
        self._add_mlflow_endpoints()
        
        # Setup background tasks
        self._setup_background_tasks()
    
    def _create_app(self) -> FastAPI:
        """Create FastAPI application with iSECTECH configuration"""
        
        # Custom OpenAPI schema
        def custom_openapi():
            if self.app.openapi_schema:
                return self.app.openapi_schema
            
            openapi_schema = get_openapi(
                title=f"iSECTECH {self.service_name} API",
                version=self.service_version,
                description=self.service_description,
                routes=self.app.routes,
            )
            
            # Add security schemes
            openapi_schema["components"]["securitySchemes"] = {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
            
            # Apply security to all endpoints
            for path in openapi_schema["paths"]:
                for method in openapi_schema["paths"][path]:
                    if method != "options":
                        openapi_schema["paths"][path][method]["security"] = [
                            {"BearerAuth": []},
                            {"ApiKeyAuth": []}
                        ]
            
            self.app.openapi_schema = openapi_schema
            return self.app.openapi_schema
        
        app = FastAPI(
            title=f"iSECTECH {self.service_name} API",
            version=self.service_version,
            description=self.service_description,
            debug=self.debug,
            openapi_url="/openapi.json" if self.debug else None,  # Disable in production
            docs_url="/docs" if self.debug else None,  # Disable in production
            redoc_url="/redoc" if self.debug else None,  # Disable in production
            openapi=custom_openapi
        )
        
        return app
    
    def _add_core_endpoints(self):
        """Add core system endpoints"""
        
        @self.app.get("/", response_model=ServiceInfo, tags=["System"])
        async def root():
            """Service information endpoint"""
            return ServiceInfo(
                name=self.service_name,
                version=self.service_version,
                description=self.service_description,
                environment=self.settings.environment,
                build_time=os.getenv("BUILD_TIME", "unknown"),
                commit_hash=os.getenv("COMMIT_HASH", "unknown")
            )
        
        @self.app.get("/health", response_model=SystemHealth, tags=["Monitoring"])
        async def health_check():
            """Comprehensive health check endpoint"""
            return await self.health_checker.check_health(
                self.service_name,
                self.service_version
            )
        
        @self.app.get("/health/live", tags=["Monitoring"])
        async def liveness_probe():
            """Kubernetes liveness probe"""
            return {"status": "ok", "timestamp": datetime.utcnow()}
        
        @self.app.get("/health/ready", tags=["Monitoring"])
        async def readiness_probe():
            """Kubernetes readiness probe"""
            health = await self.health_checker.check_health(
                self.service_name,
                self.service_version
            )
            
            if health.overall_status == "healthy":
                return {"status": "ready", "timestamp": datetime.utcnow()}
            else:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Service not ready"
                )
        
        @self.app.get("/metrics", response_class=PlainTextResponse, tags=["Monitoring"])
        async def metrics():
            """Prometheus metrics endpoint"""
            # Update system metrics before returning
            self.metrics_collector.update_system_metrics()
            return self.metrics_collector.get_metrics()
        
        @self.app.get("/version", tags=["System"])
        async def version():
            """Service version information"""
            return {
                "service": self.service_name,
                "version": self.service_version,
                "build_time": os.getenv("BUILD_TIME", "unknown"),
                "commit_hash": os.getenv("COMMIT_HASH", "unknown"),
                "environment": self.settings.environment
            }
        
        @self.app.post("/auth/revoke", tags=["Authentication"])
        async def revoke_token(
            request: Request,
            security_context: SecurityContext = Depends(self.auth)
        ):
            """Revoke JWT token"""
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="No token provided"
                )
            
            token = auth_header[7:]
            success = await self.security_manager.revoke_token(token)
            
            if success:
                self.audit_logger.log_security_event(
                    event_type="token_revoked",
                    user_id=security_context.user_id,
                    tenant_id=security_context.tenant_id,
                    details={"token_revoked": True}
                )
                return {"message": "Token revoked successfully"}
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to revoke token"
                )
        
        # Admin endpoints (require admin permissions)
        @self.app.get("/admin/stats", tags=["Administration"])
        async def admin_stats(
            security_context: SecurityContext = Depends(
                PermissionChecker([APIPermission.SYSTEM_ADMIN])
            )
        ):
            """Administrative statistics"""
            
            # Get health status
            health = await self.health_checker.check_health(
                self.service_name,
                self.service_version
            )
            
            # Mock performance metrics (in production, get from monitoring system)
            performance = PerformanceMetrics(
                request_count=1000,
                error_count=5,
                success_rate=0.995,
                avg_response_time_ms=150.0,
                p95_response_time_ms=300.0,
                p99_response_time_ms=500.0,
                requests_per_second=50.0,
                active_connections=25,
                memory_usage_mb=512.0,
                cpu_usage_percent=35.0
            )
            
            # Mock security metrics
            security = SecurityMetrics(
                failed_auth_attempts=3,
                rate_limit_violations=1,
                suspicious_requests=0,
                blocked_ips=[],
                security_events=2,
                clearance_violations=0,
                permission_denials=1
            )
            
            # Mock business metrics
            business = BusinessMetrics(
                active_tenants=15,
                api_calls_by_service={
                    "behavioral_analysis": 500,
                    "nlp_assistant": 300,
                    "decision_engine": 200
                },
                top_users_by_requests={
                    "user1": 100,
                    "user2": 85,
                    "user3": 60
                },
                data_processed_mb=1024.0,
                ml_predictions_made=750,
                security_incidents_detected=12,
                automated_responses_triggered=8
            )
            
            return {
                "health": health,
                "performance": performance,
                "security": security,
                "business": business
            }
        
        @self.app.get("/admin/alerts", tags=["Administration"])
        async def admin_alerts(
            security_context: SecurityContext = Depends(
                PermissionChecker([APIPermission.SYSTEM_ADMIN])
            )
        ):
            """Get current system alerts"""
            
            # Get metrics (mocked for now)
            health = await self.health_checker.check_health(
                self.service_name,
                self.service_version
            )
            
            performance = PerformanceMetrics(
                request_count=1000, error_count=5, success_rate=0.995,
                avg_response_time_ms=150.0, p95_response_time_ms=300.0,
                p99_response_time_ms=500.0, requests_per_second=50.0,
                active_connections=25, memory_usage_mb=512.0, cpu_usage_percent=35.0
            )
            
            security = SecurityMetrics(
                failed_auth_attempts=3, rate_limit_violations=1,
                suspicious_requests=0, blocked_ips=[], security_events=2,
                clearance_violations=0, permission_denials=1
            )
            
            alerts = await self.alert_manager.check_alerts(performance, security, health)
            
            return {"alerts": alerts, "alert_count": len(alerts)}
    
    def _add_mlflow_endpoints(self):
        """Add MLflow integration endpoints"""
        
        # Create MLflow router
        mlflow_router = create_mlflow_router(self.mlflow_integration)
        
        # Add to app with authentication
        self.app.include_router(
            mlflow_router,
            prefix="/api/v1/mlflow",
            dependencies=[Depends(self.auth)]
        )
        
        self.audit_logger.log_system_event(
            event_type="mlflow_endpoints_added",
            details={"prefix": "/api/v1/mlflow"}
        )
    
    def _setup_background_tasks(self):
        """Setup background monitoring and maintenance tasks"""
        
        @self.app.on_event("startup")
        async def startup_event():
            """Application startup tasks"""
            
            self.audit_logger.log_system_event(
                event_type="service_started",
                details={
                    "service": self.service_name,
                    "version": self.service_version,
                    "environment": self.settings.environment
                }
            )
            
            # Start background tasks
            asyncio.create_task(self._metrics_collection_task())
            asyncio.create_task(self._health_monitoring_task())
        
        @self.app.on_event("shutdown")
        async def shutdown_event():
            """Application shutdown tasks"""
            
            self.audit_logger.log_system_event(
                event_type="service_stopped",
                details={
                    "service": self.service_name,
                    "version": self.service_version
                }
            )
    
    async def _metrics_collection_task(self):
        """Background task for metrics collection"""
        while True:
            try:
                # Update system metrics
                self.metrics_collector.update_system_metrics()
                
                # Sleep for 30 seconds
                await asyncio.sleep(30)
                
            except Exception as e:
                self.audit_logger.log_system_event(
                    event_type="metrics_collection_error",
                    details={"error": str(e)}
                )
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _health_monitoring_task(self):
        """Background task for health monitoring"""
        while True:
            try:
                # Perform health check
                health = await self.health_checker.check_health(
                    self.service_name,
                    self.service_version
                )
                
                # Log unhealthy status
                if health.overall_status != "healthy":
                    self.audit_logger.log_system_event(
                        event_type="health_check_warning",
                        details={
                            "overall_status": health.overall_status,
                            "unhealthy_components": [
                                comp.name for comp in health.components
                                if comp.status != "healthy"
                            ]
                        }
                    )
                
                # Sleep for 5 minutes
                await asyncio.sleep(300)
                
            except Exception as e:
                self.audit_logger.log_system_event(
                    event_type="health_monitoring_error",
                    details={"error": str(e)}
                )
                await asyncio.sleep(600)  # Wait longer on error
    
    def add_router(self, router, prefix: str = "", dependencies: List[Any] = None):
        """Add a router to the application"""
        self.app.include_router(router, prefix=prefix, dependencies=dependencies)
    
    def require_permissions(self, *permissions: str):
        """Create permission checker dependency"""
        return PermissionChecker(list(permissions))
    
    def require_clearance(self, clearance: str):
        """Create clearance checker dependency"""
        return PermissionChecker(required_clearance=clearance)
    
    def require_auth(self):
        """Get authentication dependency"""
        return self.auth


def create_isectech_app(
    service_name: str,
    service_version: str,
    service_description: str,
    settings: SecuritySettings,
    monitoring_settings: MonitoringSettings,
    ml_settings: MLSettings = None,
    debug: bool = False
) -> ISECTECHApp:
    """Factory function to create iSECTECH application"""
    
    return ISECTECHApp(
        service_name=service_name,
        service_version=service_version,
        service_description=service_description,
        settings=settings,
        monitoring_settings=monitoring_settings,
        ml_settings=ml_settings,
        debug=debug
    )