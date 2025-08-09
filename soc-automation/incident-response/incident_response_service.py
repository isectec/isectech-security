"""
SOC Automation - Incident Response Service

Main service that coordinates incident response orchestration, evidence collection,
and integration with external systems. This is the primary entry point for
the incident response automation platform.
"""

import asyncio
import logging
import json
import signal
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path
import structlog
import yaml
from prometheus_client import start_http_server

from .orchestration_engine import IncidentResponseOrchestrator
from .alert_integration import AlertIncidentIntegration
from .thehive_integration import TheHiveIntegration
from ..forensics.evidence_collection_engine import DigitalForensicsEvidenceCollector

logger = structlog.get_logger(__name__)

class IncidentResponseService:
    """
    Main Incident Response Automation Service
    
    Coordinates all components of the incident response system:
    - Alert monitoring and triage integration
    - Incident response orchestration
    - Evidence collection automation
    - External system integration (TheHive, SOAR)
    - Monitoring and metrics collection
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "/etc/soc-automation/incident-response.yaml"
        self.config = {}
        self.running = False
        
        # Initialize components
        self.alert_integration: AlertIncidentIntegration = None
        self.orchestrator: IncidentResponseOrchestrator = None
        self.evidence_collector: DigitalForensicsEvidenceCollector = None
        self.thehive_integration: TheHiveIntegration = None
        
        # Runtime tasks
        self.service_tasks: List[asyncio.Task] = []
        
        logger.info("IncidentResponseService initialized", config_path=self.config_path)
    
    async def initialize(self):
        """Initialize the incident response service"""
        try:
            # Load configuration
            await self._load_configuration()
            
            # Initialize logging
            self._setup_logging()
            
            # Start Prometheus metrics server
            if self.config.get('metrics', {}).get('enabled', True):
                metrics_port = self.config.get('metrics', {}).get('port', 8080)
                start_http_server(metrics_port)
                logger.info("Prometheus metrics server started", port=metrics_port)
            
            # Initialize orchestration engine
            orchestrator_config = self.config.get('orchestrator', {})
            self.orchestrator = IncidentResponseOrchestrator(orchestrator_config)
            await self.orchestrator.initialize()
            
            # Initialize evidence collector
            if self.config.get('evidence_collection', {}).get('enabled', True):
                evidence_config = self.config.get('evidence_collection', {})
                self.evidence_collector = DigitalForensicsEvidenceCollector(evidence_config)
                await self.evidence_collector.initialize()
                await self.evidence_collector.start_collection_workers()
            
            # Initialize TheHive integration
            if self.config.get('thehive', {}).get('enabled', False):
                thehive_config = self.config.get('thehive', {})
                self.thehive_integration = TheHiveIntegration(thehive_config)
                await self.thehive_integration.initialize()
            
            # Initialize alert integration (must be last)
            alert_integration_config = {
                'redis': self.config.get('redis', {}),
                'elasticsearch': self.config.get('elasticsearch', {}),
                'orchestrator': orchestrator_config,
                'evidence_collector': self.config.get('evidence_collection', {}),
                **self.config.get('alert_integration', {})
            }
            
            self.alert_integration = AlertIncidentIntegration(alert_integration_config)
            await self.alert_integration.initialize()
            
            logger.info("IncidentResponseService initialized successfully",
                       components={
                           'orchestrator': True,
                           'evidence_collector': bool(self.evidence_collector),
                           'thehive_integration': bool(self.thehive_integration),
                           'alert_integration': True
                       })
            
        except Exception as e:
            logger.error("Failed to initialize IncidentResponseService", error=str(e))
            raise
    
    async def start(self):
        """Start the incident response service"""
        if self.running:
            logger.warning("IncidentResponseService is already running")
            return
        
        try:
            self.running = True
            
            logger.info("Starting IncidentResponseService...")
            
            # Start alert monitoring (main service loop)
            alert_monitor_task = asyncio.create_task(
                self.alert_integration.start_monitoring(),
                name="alert_monitor"
            )
            self.service_tasks.append(alert_monitor_task)
            
            # Start health check service
            health_check_task = asyncio.create_task(
                self._health_check_service(),
                name="health_check"
            )
            self.service_tasks.append(health_check_task)
            
            # Start metrics collection
            metrics_task = asyncio.create_task(
                self._metrics_collection_service(),
                name="metrics_collection"
            )
            self.service_tasks.append(metrics_task)
            
            # Start configuration reload service
            config_reload_task = asyncio.create_task(
                self._config_reload_service(),
                name="config_reload"
            )
            self.service_tasks.append(config_reload_task)
            
            logger.info("IncidentResponseService started successfully",
                       tasks=len(self.service_tasks))
            
            # Setup signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
            # Wait for all service tasks
            await asyncio.gather(*self.service_tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error("Error running IncidentResponseService", error=str(e))
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the incident response service"""
        if not self.running:
            return
        
        logger.info("Stopping IncidentResponseService...")
        
        self.running = False
        
        # Cancel all service tasks
        for task in self.service_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete with timeout
        if self.service_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*self.service_tasks, return_exceptions=True),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                logger.warning("Service tasks did not complete within timeout")
        
        # Stop components
        try:
            if self.alert_integration:
                await self.alert_integration.stop_monitoring()
            
            if self.evidence_collector:
                await self.evidence_collector.stop_collection_workers()
            
            if self.thehive_integration:
                await self.thehive_integration.close()
                
        except Exception as e:
            logger.error("Error stopping service components", error=str(e))
        
        self.service_tasks.clear()
        
        logger.info("IncidentResponseService stopped")
    
    async def _load_configuration(self):
        """Load configuration from file"""
        try:
            config_file = Path(self.config_path)
            
            if not config_file.exists():
                logger.warning("Configuration file not found, using defaults", 
                             path=self.config_path)
                self.config = self._get_default_configuration()
                return
            
            with open(config_file, 'r') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    self.config = yaml.safe_load(f)
                else:
                    self.config = json.load(f)
            
            logger.info("Configuration loaded successfully", 
                       path=self.config_path,
                       components=list(self.config.keys()))
            
        except Exception as e:
            logger.error("Failed to load configuration", 
                        path=self.config_path, error=str(e))
            logger.info("Using default configuration")
            self.config = self._get_default_configuration()
    
    def _get_default_configuration(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'logging': {
                'level': 'INFO',
                'format': 'json'
            },
            'metrics': {
                'enabled': True,
                'port': 8080
            },
            'redis': {
                'host': 'localhost',
                'port': 6379,
                'db': 0
            },
            'elasticsearch': {
                'host': 'localhost',
                'port': 9200
            },
            'orchestrator': {
                'max_concurrent_executions': 50,
                'execution_timeout': 3600,
                'evidence_retention_days': 2555
            },
            'evidence_collection': {
                'enabled': True,
                'evidence_storage_path': '/evidence',
                'temp_storage_path': '/tmp/evidence',
                'backup_storage_path': '/evidence/backup',
                'max_concurrent_collections': 10,
                'collection_timeout': 3600,
                'encryption_enabled': True,
                'signing_enabled': True
            },
            'alert_integration': {
                'alert_stream_keys': ['alerts:all'],
                'correlation_window': 300,
                'max_correlation_alerts': 50,
                'evidence_auto_collect': True
            },
            'thehive': {
                'enabled': False,
                'url': 'http://localhost:9000',
                'api_key': '',
                'organization': 'default',
                'verify_ssl': True
            }
        }
    
    def _setup_logging(self):
        """Setup structured logging"""
        log_config = self.config.get('logging', {})
        log_level = log_config.get('level', 'INFO')
        
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(message)s'
        )
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer() if log_config.get('format') == 'json' 
                else structlog.dev.ConsoleRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal", signal=signum)
            asyncio.create_task(self.stop())
        
        # Register handlers for common termination signals
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Handle SIGHUP for configuration reload
        def reload_handler(signum, frame):
            logger.info("Received reload signal")
            asyncio.create_task(self._reload_configuration())
        
        signal.signal(signal.SIGHUP, reload_handler)
    
    async def _health_check_service(self):
        """Health check service for monitoring"""
        logger.info("Health check service started")
        
        while self.running:
            try:
                # Check component health
                health_status = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'service': 'incident_response',
                    'status': 'healthy',
                    'components': {}
                }
                
                # Check alert integration
                if self.alert_integration:
                    try:
                        stats = await self.alert_integration.get_correlation_statistics()
                        health_status['components']['alert_integration'] = {
                            'status': 'healthy',
                            'active_correlations': stats['active_correlations']
                        }
                    except Exception as e:
                        health_status['components']['alert_integration'] = {
                            'status': 'unhealthy',
                            'error': str(e)
                        }
                        health_status['status'] = 'degraded'
                
                # Check evidence collector
                if self.evidence_collector:
                    health_status['components']['evidence_collector'] = {
                        'status': 'healthy',
                        'storage_path': str(self.evidence_collector.evidence_storage_path)
                    }
                
                # Check TheHive integration
                if self.thehive_integration:
                    health_status['components']['thehive'] = {
                        'status': 'healthy',
                        'url': self.thehive_integration.base_url
                    }
                
                logger.debug("Health check completed", status=health_status['status'])
                
                # Store health status in Redis for monitoring
                if hasattr(self.alert_integration, 'redis_client') and self.alert_integration.redis_client:
                    await self.alert_integration.redis_client.setex(
                        'soc:health:incident_response',
                        300,  # 5 minute TTL
                        json.dumps(health_status)
                    )
                
                # Wait 60 seconds before next check
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check service error", error=str(e))
                await asyncio.sleep(30)  # Back off on error
        
        logger.info("Health check service stopped")
    
    async def _metrics_collection_service(self):
        """Collect and report service metrics"""
        logger.info("Metrics collection service started")
        
        while self.running:
            try:
                # Collect metrics from components
                metrics = {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'service': 'incident_response',
                    'uptime_seconds': (datetime.now(timezone.utc) - self._start_time).total_seconds() if hasattr(self, '_start_time') else 0,
                    'components': {}
                }
                
                # Alert integration metrics
                if self.alert_integration:
                    try:
                        stats = await self.alert_integration.get_correlation_statistics()
                        metrics['components']['alert_integration'] = stats
                    except Exception as e:
                        logger.error("Failed to collect alert integration metrics", error=str(e))
                
                # Evidence collector metrics
                if self.evidence_collector:
                    metrics['components']['evidence_collector'] = {
                        'active_collections': len(self.evidence_collector.active_collections),
                        'max_concurrent': self.evidence_collector.max_concurrent_collections
                    }
                
                logger.debug("Metrics collected", components=len(metrics['components']))
                
                # Store metrics in Elasticsearch
                if hasattr(self.alert_integration, 'elasticsearch') and self.alert_integration.elasticsearch:
                    try:
                        await self.alert_integration.elasticsearch.index(
                            index=f"soc-incident-response-metrics-{datetime.now().strftime('%Y-%m')}",
                            body=metrics
                        )
                    except Exception as e:
                        logger.error("Failed to store metrics", error=str(e))
                
                # Wait 5 minutes before next collection
                await asyncio.sleep(300)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Metrics collection service error", error=str(e))
                await asyncio.sleep(60)  # Back off on error
        
        logger.info("Metrics collection service stopped")
    
    async def _config_reload_service(self):
        """Configuration reload service"""
        logger.info("Configuration reload service started")
        
        last_modified = None
        config_file = Path(self.config_path)
        
        while self.running:
            try:
                if config_file.exists():
                    current_modified = config_file.stat().st_mtime
                    
                    if last_modified is None:
                        last_modified = current_modified
                    elif current_modified > last_modified:
                        logger.info("Configuration file changed, reloading")
                        await self._reload_configuration()
                        last_modified = current_modified
                
                # Check every 30 seconds
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Configuration reload service error", error=str(e))
                await asyncio.sleep(60)  # Back off on error
        
        logger.info("Configuration reload service stopped")
    
    async def _reload_configuration(self):
        """Reload configuration without restarting service"""
        try:
            old_config = self.config.copy()
            await self._load_configuration()
            
            # Check if critical configuration changed
            critical_sections = ['redis', 'elasticsearch', 'orchestrator']
            critical_changed = any(
                old_config.get(section) != self.config.get(section)
                for section in critical_sections
            )
            
            if critical_changed:
                logger.warning("Critical configuration changed, service restart required")
            else:
                logger.info("Configuration reloaded successfully")
                
                # Update non-critical configuration
                log_config = self.config.get('logging', {})
                if old_config.get('logging') != log_config:
                    self._setup_logging()
                    logger.info("Logging configuration updated")
                
        except Exception as e:
            logger.error("Failed to reload configuration", error=str(e))
    
    # Public API methods
    async def get_service_status(self) -> Dict[str, Any]:
        """Get service status"""
        return {
            'service': 'incident_response',
            'running': self.running,
            'components': {
                'orchestrator': bool(self.orchestrator),
                'evidence_collector': bool(self.evidence_collector),
                'thehive_integration': bool(self.thehive_integration),
                'alert_integration': bool(self.alert_integration)
            },
            'active_tasks': len(self.service_tasks),
            'config_path': self.config_path
        }
    
    async def trigger_manual_incident(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """Manually trigger incident response for an alert"""
        if not self.orchestrator:
            logger.error("Orchestrator not available")
            return None
        
        try:
            incident_id = await self.orchestrator.process_alert_for_incident(alert_data)
            logger.info("Manual incident triggered", incident_id=incident_id)
            return incident_id
        except Exception as e:
            logger.error("Failed to trigger manual incident", error=str(e))
            return None


async def main():
    """Main entry point for the service"""
    import sys
    
    # Get config path from command line or use default
    config_path = sys.argv[1] if len(sys.argv) > 1 else None
    
    # Create and start service
    service = IncidentResponseService(config_path)
    
    try:
        service._start_time = datetime.now(timezone.utc)
        await service.initialize()
        await service.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Service failed", error=str(e))
        sys.exit(1)
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())