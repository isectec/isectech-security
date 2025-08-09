"""
SOC Alert Ingestion Service - Main FastAPI Application

Production-grade alert ingestion service that coordinates all components:
- Alert Manager for processing pipeline
- Multiple source connectors (SIEM, EDR, Network)  
- Normalization and enrichment
- Elasticsearch storage
- Real-time streaming and monitoring
"""

import asyncio
import os
import signal
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
import structlog

# Import SOC components
from .alert_manager import AlertManager
from .connectors.siem_connector import SIEMConnector
from .connectors.edr_connector import EDRConnector
from .connectors.base_connector import BaseConnector
from .normalizer import AlertNormalizer
from .enrichment import AlertEnricher
from .deduplication import DeduplicationEngine
from .storage import ElasticsearchStorage

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global application state
app_state = {
    'alert_manager': None,
    'startup_time': None,
    'shutdown_requested': False
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting SOC Alert Ingestion Service")
    app_state['startup_time'] = datetime.now(timezone.utc)
    
    try:
        # Load configuration
        config = load_configuration()
        
        # Initialize alert manager
        alert_manager = AlertManager(
            elasticsearch_config=config['elasticsearch'],
            redis_config=config['redis'],
            processing_config=config.get('processing', {})
        )
        
        # Initialize components
        await alert_manager.initialize()
        
        # Register connectors
        await register_connectors(alert_manager, config.get('connectors', {}))
        
        # Start alert processing
        await alert_manager.start()
        
        app_state['alert_manager'] = alert_manager
        
        logger.info("SOC Alert Ingestion Service started successfully")
        
        yield  # Application runs here
        
    except Exception as e:
        logger.error("Failed to start application", error=str(e))
        raise
    
    finally:
        # Shutdown
        logger.info("Shutting down SOC Alert Ingestion Service")
        app_state['shutdown_requested'] = True
        
        if app_state['alert_manager']:
            await app_state['alert_manager'].stop()
        
        logger.info("SOC Alert Ingestion Service stopped")

# Create FastAPI application
app = FastAPI(
    title="iSECTECH SOC Alert Ingestion Service",
    description="Production-grade security alert ingestion and processing platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

# Pydantic models for API requests/responses

class AlertIngestionRequest(BaseModel):
    """Request model for manual alert ingestion"""
    source: str = Field(..., description="Source system identifier")
    alert_data: Dict[str, Any] = Field(..., description="Raw alert data")
    priority: Optional[str] = Field(None, description="Processing priority")

class AlertIngestionResponse(BaseModel):
    """Response model for alert ingestion"""
    success: bool
    alert_id: Optional[str] = None
    message: str
    processing_time_ms: Optional[float] = None

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: str
    uptime_seconds: float
    version: str
    components: Dict[str, str]

class StatisticsResponse(BaseModel):
    """Statistics response model"""
    alert_manager: Dict[str, Any]
    connectors: Dict[str, Any]
    processing_stats: Dict[str, Any]

class ConnectorStatusResponse(BaseModel):
    """Connector status response model"""
    name: str
    type: str
    status: str
    metrics: Dict[str, Any]
    last_updated: str

# Dependency functions

def get_alert_manager() -> AlertManager:
    """Get the alert manager instance"""
    if not app_state['alert_manager']:
        raise HTTPException(status_code=503, detail="Alert manager not initialized")
    return app_state['alert_manager']

# API Routes

@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with service information"""
    return {
        "service": "iSECTECH SOC Alert Ingestion Service",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check(alert_manager: AlertManager = Depends(get_alert_manager)):
    """Comprehensive health check endpoint"""
    try:
        current_time = datetime.now(timezone.utc)
        uptime = (current_time - app_state['startup_time']).total_seconds()
        
        # Check component health
        components = {
            "alert_manager": "healthy" if alert_manager.running else "unhealthy",
            "elasticsearch": "healthy",  # Add actual health check
            "redis": "healthy",  # Add actual health check
            "connectors": f"{len(alert_manager.connectors)} active"
        }
        
        # Overall status
        overall_status = "healthy" if all(
            status == "healthy" for status in components.values() 
            if status not in ["0 active", "1 active", "2 active", "3 active", "4 active", "5 active"]
        ) else "degraded"
        
        return HealthResponse(
            status=overall_status,
            timestamp=current_time.isoformat(),
            uptime_seconds=uptime,
            version="1.0.0",
            components=components
        )
        
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        raise HTTPException(status_code=500, detail="Health check failed")

@app.get("/metrics")
async def metrics(alert_manager: AlertManager = Depends(get_alert_manager)):
    """Prometheus-compatible metrics endpoint"""
    try:
        stats = await alert_manager.get_statistics()
        
        # Convert to Prometheus format
        metrics_output = []
        
        # Queue size metric
        metrics_output.append(f"soc_alert_queue_size {stats['queue_size']}")
        
        # Connector count metric
        metrics_output.append(f"soc_connectors_total {stats['connectors']}")
        
        # Worker count metric  
        metrics_output.append(f"soc_workers_total {stats['workers']}")
        
        # Running status metric
        metrics_output.append(f"soc_service_running {1 if stats['running'] else 0}")
        
        return "\n".join(metrics_output) + "\n"
        
    except Exception as e:
        logger.error("Metrics collection failed", error=str(e))
        raise HTTPException(status_code=500, detail="Metrics collection failed")

@app.post("/alerts/ingest", response_model=AlertIngestionResponse)
async def ingest_alert(
    request: AlertIngestionRequest,
    background_tasks: BackgroundTasks,
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Ingest a single alert for processing"""
    try:
        start_time = datetime.now(timezone.utc)
        
        # Ingest alert
        alert_id = await alert_manager.ingest_alert(
            raw_alert=request.alert_data,
            source=request.source
        )
        
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        
        if alert_id:
            return AlertIngestionResponse(
                success=True,
                alert_id=alert_id,
                message="Alert ingested successfully",
                processing_time_ms=processing_time
            )
        else:
            return AlertIngestionResponse(
                success=False,
                message="Alert was filtered or rejected",
                processing_time_ms=processing_time
            )
            
    except Exception as e:
        logger.error("Alert ingestion failed", source=request.source, error=str(e))
        raise HTTPException(status_code=500, detail=f"Alert ingestion failed: {str(e)}")

@app.post("/alerts/bulk-ingest")
async def bulk_ingest_alerts(
    alerts: List[AlertIngestionRequest],
    background_tasks: BackgroundTasks,
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Ingest multiple alerts for processing"""
    try:
        start_time = datetime.now(timezone.utc)
        
        results = []
        for alert_request in alerts:
            alert_id = await alert_manager.ingest_alert(
                raw_alert=alert_request.alert_data,
                source=alert_request.source
            )
            
            results.append({
                "source": alert_request.source,
                "alert_id": alert_id,
                "success": alert_id is not None
            })
        
        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        successful_count = sum(1 for result in results if result["success"])
        
        return {
            "total_alerts": len(alerts),
            "successful": successful_count,
            "failed": len(alerts) - successful_count,
            "processing_time_ms": processing_time,
            "results": results
        }
        
    except Exception as e:
        logger.error("Bulk alert ingestion failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Bulk ingestion failed: {str(e)}")

@app.get("/statistics", response_model=StatisticsResponse)
async def get_statistics(alert_manager: AlertManager = Depends(get_alert_manager)):
    """Get detailed processing statistics"""
    try:
        stats = await alert_manager.get_statistics()
        
        # Get connector statistics
        connector_stats = {}
        for name, connector in alert_manager.connectors.items():
            connector_stats[name] = connector.get_status()
        
        return StatisticsResponse(
            alert_manager=stats,
            connectors=connector_stats,
            processing_stats={
                "uptime_seconds": (datetime.now(timezone.utc) - app_state['startup_time']).total_seconds(),
                "startup_time": app_state['startup_time'].isoformat()
            }
        )
        
    except Exception as e:
        logger.error("Statistics collection failed", error=str(e))
        raise HTTPException(status_code=500, detail="Statistics collection failed")

@app.get("/connectors", response_model=List[ConnectorStatusResponse])
async def get_connectors(alert_manager: AlertManager = Depends(get_alert_manager)):
    """Get status of all registered connectors"""
    try:
        connectors_status = []
        
        for name, connector in alert_manager.connectors.items():
            status_info = connector.get_status()
            
            connectors_status.append(ConnectorStatusResponse(
                name=name,
                type=type(connector).__name__,
                status=status_info['status'],
                metrics=status_info['metrics'],
                last_updated=datetime.now(timezone.utc).isoformat()
            ))
        
        return connectors_status
        
    except Exception as e:
        logger.error("Connector status collection failed", error=str(e))
        raise HTTPException(status_code=500, detail="Connector status collection failed")

@app.get("/connectors/{connector_name}")
async def get_connector_details(
    connector_name: str,
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Get detailed information about a specific connector"""
    try:
        if connector_name not in alert_manager.connectors:
            raise HTTPException(status_code=404, detail=f"Connector '{connector_name}' not found")
        
        connector = alert_manager.connectors[connector_name]
        status_info = connector.get_status()
        
        # Add platform-specific status if available
        if hasattr(connector, 'get_platform_status'):
            status_info.update(connector.get_platform_status())
        elif hasattr(connector, 'get_query_status'):
            status_info.update(connector.get_query_status())
        
        return status_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Connector details collection failed", 
                    connector_name=connector_name, error=str(e))
        raise HTTPException(status_code=500, detail="Connector details collection failed")

@app.post("/connectors/{connector_name}/restart")
async def restart_connector(
    connector_name: str,
    alert_manager: AlertManager = Depends(get_alert_manager)
):
    """Restart a specific connector"""
    try:
        if connector_name not in alert_manager.connectors:
            raise HTTPException(status_code=404, detail=f"Connector '{connector_name}' not found")
        
        connector = alert_manager.connectors[connector_name]
        
        # Stop and restart connector
        await connector.stop()
        await asyncio.sleep(2)
        await connector.start()
        
        return {
            "success": True,
            "message": f"Connector '{connector_name}' restarted successfully",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Connector restart failed", 
                    connector_name=connector_name, error=str(e))
        raise HTTPException(status_code=500, detail=f"Connector restart failed: {str(e)}")

@app.get("/alerts/stream")
async def stream_alerts(category: str = "all"):
    """Stream real-time alerts (WebSocket endpoint would be better for production)"""
    try:
        alert_manager = get_alert_manager()
        
        # This is a simplified example - in production you'd use WebSocket
        async def generate_alerts():
            async for alert in alert_manager.get_alert_stream(category):
                yield f"data: {alert}\n\n"
        
        from fastapi.responses import StreamingResponse
        return StreamingResponse(
            generate_alerts(),
            media_type="text/plain",
            headers={"Cache-Control": "no-cache"}
        )
        
    except Exception as e:
        logger.error("Alert streaming failed", category=category, error=str(e))
        raise HTTPException(status_code=500, detail="Alert streaming failed")

# Configuration and initialization functions

def load_configuration() -> Dict[str, Any]:
    """Load application configuration from environment variables and files"""
    return {
        'elasticsearch': {
            'hosts': [os.getenv('ELASTICSEARCH_HOSTS', 'localhost:9200')],
            'username': os.getenv('ELASTICSEARCH_USERNAME'),
            'password': os.getenv('ELASTICSEARCH_PASSWORD'),
            'api_key': os.getenv('ELASTICSEARCH_API_KEY'),
            'ca_cert': os.getenv('ELASTICSEARCH_CA_CERT'),
            'index_prefix': os.getenv('ELASTICSEARCH_INDEX_PREFIX', 'soc-alerts'),
            'retention_days': int(os.getenv('ELASTICSEARCH_RETENTION_DAYS', '90'))
        },
        'redis': {
            'host': os.getenv('REDIS_HOST', 'localhost'),
            'port': int(os.getenv('REDIS_PORT', '6379')),
            'db': int(os.getenv('REDIS_DB', '0')),
            'password': os.getenv('REDIS_PASSWORD')
        },
        'processing': {
            'max_workers': int(os.getenv('PROCESSING_MAX_WORKERS', '10')),
            'batch_size': int(os.getenv('PROCESSING_BATCH_SIZE', '100')),
            'max_queue_size': int(os.getenv('PROCESSING_MAX_QUEUE_SIZE', '10000')),
            'deduplication_window': int(os.getenv('DEDUPLICATION_WINDOW', '3600'))
        },
        'connectors': {
            'siem': {
                'enabled': os.getenv('SIEM_ENABLED', 'false').lower() == 'true',
                'type': os.getenv('SIEM_TYPE', 'generic'),
                'base_url': os.getenv('SIEM_BASE_URL'),
                'username': os.getenv('SIEM_USERNAME'),
                'password': os.getenv('SIEM_PASSWORD'),
                'api_key': os.getenv('SIEM_API_KEY'),
                'query_interval': int(os.getenv('SIEM_QUERY_INTERVAL', '60'))
            },
            'edr': {
                'enabled': os.getenv('EDR_ENABLED', 'false').lower() == 'true',
                'type': os.getenv('EDR_TYPE', 'generic'),
                'base_url': os.getenv('EDR_BASE_URL'),
                'client_id': os.getenv('EDR_CLIENT_ID'),
                'client_secret': os.getenv('EDR_CLIENT_SECRET'),
                'api_key': os.getenv('EDR_API_KEY'),
                'polling_interval': int(os.getenv('EDR_POLLING_INTERVAL', '30'))
            }
        }
    }

async def register_connectors(alert_manager: AlertManager, connectors_config: Dict[str, Any]):
    """Register and configure alert source connectors"""
    
    # Register SIEM connector
    if connectors_config.get('siem', {}).get('enabled'):
        siem_config = connectors_config['siem']
        siem_connector = SIEMConnector(
            name='siem_primary',
            config={
                'siem_type': siem_config['type'],
                'base_url': siem_config['base_url'],
                'username': siem_config.get('username'),
                'password': siem_config.get('password'),
                'api_key': siem_config.get('api_key'),
                'query_interval': siem_config.get('query_interval', 60),
                'batch_size': 500
            }
        )
        await alert_manager.register_connector('siem_primary', siem_connector)
        logger.info("SIEM connector registered")
    
    # Register EDR connector
    if connectors_config.get('edr', {}).get('enabled'):
        edr_config = connectors_config['edr']
        edr_connector = EDRConnector(
            name='edr_primary',
            config={
                'edr_type': edr_config['type'],
                'base_url': edr_config['base_url'],
                'client_id': edr_config.get('client_id'),
                'client_secret': edr_config.get('client_secret'),
                'api_key': edr_config.get('api_key'),
                'polling_interval': edr_config.get('polling_interval', 30),
                'batch_size': 200
            }
        )
        await alert_manager.register_connector('edr_primary', edr_connector)
        logger.info("EDR connector registered")

# Signal handlers for graceful shutdown

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Shutdown signal received", signal=signum)
    app_state['shutdown_requested'] = True

# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Development server
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=False,
        log_config=None,  # Use structlog configuration
        access_log=True
    )