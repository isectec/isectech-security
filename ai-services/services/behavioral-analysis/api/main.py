"""
Main FastAPI Application for Behavioral Analysis & Anomaly Detection Service

Production-grade API service for:
- Real-time behavioral analysis and anomaly detection
- User behavior baseline establishment and management
- Risk assessment and threat classification
- ML model monitoring and health checks
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ....shared.api.app import create_isectech_app
from ....shared.config.settings import SecuritySettings, MonitoringSettings
from .router import BehavioralAnalysisService, create_behavioral_analysis_router


# Service configuration
SERVICE_NAME = "Behavioral Analysis & Anomaly Detection"
SERVICE_VERSION = "1.0.0"
SERVICE_DESCRIPTION = """
iSECTECH Behavioral Analysis & Anomaly Detection Service

Production-grade AI-powered behavioral analysis service providing:
- User and Entity Behavior Analytics (UEBA) with machine learning
- Real-time anomaly detection with confidence scoring
- Behavioral baseline establishment and drift detection
- Comprehensive risk assessment and threat classification
- Multi-tenant security with enterprise-grade audit logging

Features:
- Advanced feature engineering for behavioral patterns
- Ensemble anomaly detection algorithms (Isolation Forest, LSTM, Autoencoders)
- MITRE ATT&CK framework integration for threat mapping
- Continuous learning with feedback incorporation
- Production-grade security with clearance-based access control
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    
    # Startup
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    
    # Initialize ML models and warm up
    # Note: In production, add model loading and warm-up here
    
    yield
    
    # Shutdown
    print(f"Shutting down {SERVICE_NAME}")
    
    # Cleanup resources
    # Note: In production, add cleanup logic here


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
    
    # Initialize behavioral analysis service
    behavioral_service = BehavioralAnalysisService(
        settings=security_settings,
        audit_logger=isectech_app.audit_logger,
        metrics_collector=isectech_app.metrics_collector
    )
    
    # Create and add behavioral analysis router
    behavioral_router = create_behavioral_analysis_router(behavioral_service)
    isectech_app.add_router(
        behavioral_router,
        prefix="/api/v1/behavioral",
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
        port=8001,
        reload=True,
        log_level="info"
    )