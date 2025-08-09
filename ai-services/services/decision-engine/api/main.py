"""
Main FastAPI Application for Automated Decision Making and Response Service

Production-grade API service for:
- Risk-based automated decision making and response selection
- Playbook execution and orchestration with Ray distributed processing
- Containment action authorization with security clearance integration
- Feedback learning from human overrides for continuous improvement
- Comprehensive risk assessment and business impact analysis
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ....shared.api.app import create_isectech_app
from ....shared.config.settings import SecuritySettings, MonitoringSettings
from .router import DecisionEngineService, create_decision_engine_router


# Service configuration
SERVICE_NAME = "Automated Decision Making and Response"
SERVICE_VERSION = "1.0.0"
SERVICE_DESCRIPTION = """
iSECTECH Automated Decision Making and Response Service

Production-grade AI-powered decision engine providing:
- Risk-based automated decision making with multi-model ensemble approaches
- Intelligent response selection and action coordination for security incidents
- Automated playbook execution with Ray distributed processing for scalability
- Security clearance-based containment action authorization and approval workflows
- Continuous learning from human feedback with bias detection and model improvement
- Comprehensive risk assessment across multiple dimensions and business contexts

Features:
- Advanced ML decision models (PyTorch, TensorFlow, Scikit-learn) with ensemble predictions
- Sophisticated response orchestration with dependency management and conflict resolution
- Ray distributed processing for high-performance playbook execution and parallel operations
- iSECTECH-specific authorization policies with security clearance integration (PUBLIC → TOP SECRET)
- Feedback learning system with pattern recognition and bias detection for continuous improvement
- Multi-dimensional risk assessment with business impact forecasting and escalation thresholds
- Production-grade security with comprehensive audit logging and regulatory compliance
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    
    # Startup
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    
    # Initialize decision models and distributed processing
    # Note: In production, add Ray cluster initialization and model loading here
    
    yield
    
    # Shutdown
    print(f"Shutting down {SERVICE_NAME}")
    
    # Cleanup resources
    # Note: In production, add Ray cluster shutdown and cleanup logic here


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    
    # Load settings
    security_settings = SecuritySettings()
    monitoring_settings = MonitoringSettings()
    
    # Determine debug mode
    debug = os.getenv("DEBUG", "false").lower() == "true"
    
    # Create iSECTECH application with enterprise features
    isectech_app = create_isectech_app(
        service_name=SERVICE_NAME,
        service_version=SERVICE_VERSION,
        service_description=SERVICE_DESCRIPTION,
        settings=security_settings,
        monitoring_settings=monitoring_settings,
        debug=debug
    )
    
    # Initialize decision engine service
    decision_service = DecisionEngineService(
        settings=security_settings,
        audit_logger=isectech_app.audit_logger,
        metrics_collector=isectech_app.metrics_collector
    )
    
    # Create and add decision engine router
    decision_router = create_decision_engine_router(decision_service)
    isectech_app.add_router(
        decision_router,
        prefix="/api/v1/decision",
        dependencies=[isectech_app.require_auth()]
    )
    
    # Configure lifespan
    isectech_app.app.router.lifespan_context = lifespan
    
    return isectech_app.app


# Create the FastAPI application
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    # Configuration for development
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8003,
        reload=True,
        log_level="info"
    )