"""
Main FastAPI Application for NLP Security Assistant Service

Production-grade API service for:
- Security event processing and threat analysis with NLP
- Plain English threat explanations for multiple audiences
- Guided investigation recommendations and workflows
- Automated security report generation in multiple formats
- IOC extraction and MITRE ATT&CK framework mapping
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ....shared.api.app import create_isectech_app
from ....shared.config.settings import SecuritySettings, MonitoringSettings
from .router import NLPAssistantService, create_nlp_assistant_router


# Service configuration
SERVICE_NAME = "NLP Security Assistant"
SERVICE_VERSION = "1.0.0"
SERVICE_DESCRIPTION = """
iSECTECH NLP Security Assistant Service

Production-grade AI-powered natural language processing service providing:
- Advanced security event processing with threat analysis and classification
- Multi-audience threat explanations in plain English for technical, executive, and compliance teams
- Intelligent investigation guidance with workflow recommendations and resource planning
- Automated security report generation in multiple formats (PDF, HTML, DOCX, etc.)
- IOC extraction and MITRE ATT&CK framework integration for threat intelligence

Features:
- Hugging Face Transformers integration for state-of-the-art NLP capabilities
- Custom security-focused NLP models trained on cybersecurity data
- Multi-language support for global security operations
- Template-driven report generation with customizable branding
- Real-time threat explanation with quality scoring and confidence assessment
- MITRE ATT&CK tactical mapping and contextual threat intelligence
- Production-grade security with multi-tenant isolation and audit logging
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    
    # Startup
    print(f"Starting {SERVICE_NAME} v{SERVICE_VERSION}")
    
    # Initialize NLP models and warm up
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
    
    # Initialize NLP assistant service
    nlp_service = NLPAssistantService(
        settings=security_settings,
        audit_logger=isectech_app.audit_logger,
        metrics_collector=isectech_app.metrics_collector
    )
    
    # Create and add NLP assistant router
    nlp_router = create_nlp_assistant_router(nlp_service)
    isectech_app.add_router(
        nlp_router,
        prefix="/api/v1/nlp",
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
        port=8002,
        reload=True,
        log_level="info"
    )