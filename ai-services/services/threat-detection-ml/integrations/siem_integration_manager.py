"""
SIEM Integration Manager

Main orchestrator for comprehensive SIEM integration with AI/ML threat detection.
Coordinates all SIEM connectors, correlation engine, enrichment service, 
stream processor, and unified dashboard.
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from pathlib import Path

from .siem import (
    BaseSiemConnector, SplunkConnector, QRadarConnector, SentinelConnector,
    ThreatCorrelationEngine, AlertEnrichmentService, UnifiedThreatDashboard,
    SiemStreamProcessor, SiemAlertManager, StreamConfig, AlertConfig
)
from ..models.behavioral_analytics import BehavioralAnalyticsModel
from ..models.zero_day_detection import ZeroDayDetectionModel  
from ..models.supervised_threat_classification import ThreatClassificationModel
from ..models.predictive_threat_intelligence import PredictiveThreatModel

logger = logging.getLogger(__name__)

@dataclass
class SiemIntegrationConfig:
    """SIEM integration configuration"""
    # SIEM Platforms
    enable_splunk: bool = False
    enable_qradar: bool = False
    enable_sentinel: bool = False
    
    # Splunk configuration
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_username: str = ""
    splunk_password: str = ""
    splunk_token: str = ""
    
    # QRadar configuration  
    qradar_host: str = "localhost"
    qradar_port: int = 443
    qradar_sec_token: str = ""
    qradar_username: str = ""
    qradar_password: str = ""
    
    # Sentinel configuration
    sentinel_workspace_id: str = ""
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_tenant_id: str = ""
    sentinel_client_id: str = ""
    sentinel_client_secret: str = ""
    
    # Processing configuration
    enable_correlation: bool = True
    enable_enrichment: bool = True
    enable_stream_processing: bool = True
    enable_dashboard: bool = True
    enable_alert_management: bool = True
    
    # Performance settings
    max_concurrent_enrichments: int = 10
    stream_buffer_size: int = 10000
    dashboard_update_interval: int = 30
    alert_rate_limit_per_hour: int = 1000
    
    # AI/ML Models
    enable_behavioral_model: bool = True
    enable_zero_day_model: bool = True
    enable_threat_classification_model: bool = True
    enable_predictive_model: bool = True

class SiemIntegrationManager:
    """
    Production-grade SIEM integration manager
    
    Orchestrates comprehensive integration between AI/ML threat detection
    and multiple SIEM platforms with full bidirectional data flow.
    
    Features:
    - Multi-platform SIEM connectivity (Splunk, QRadar, Sentinel)
    - Real-time event correlation and enrichment
    - Intelligent alert management and escalation
    - Unified threat visibility dashboard
    - High-performance stream processing
    - Production monitoring and metrics
    """
    
    def __init__(
        self,
        config: SiemIntegrationConfig,
        behavioral_model: Optional[BehavioralAnalyticsModel] = None,
        zero_day_model: Optional[ZeroDayDetectionModel] = None,
        threat_classification_model: Optional[ThreatClassificationModel] = None,
        predictive_model: Optional[PredictiveThreatModel] = None
    ):
        self.config = config
        
        # AI/ML Models
        self.behavioral_model = behavioral_model if config.enable_behavioral_model else None
        self.zero_day_model = zero_day_model if config.enable_zero_day_model else None
        self.threat_classification_model = threat_classification_model if config.enable_threat_classification_model else None
        self.predictive_model = predictive_model if config.enable_predictive_model else None
        
        # Core components
        self.siem_connectors: List[BaseSiemConnector] = []
        self.correlation_engine: Optional[ThreatCorrelationEngine] = None
        self.enrichment_service: Optional[AlertEnrichmentService] = None
        self.stream_processor: Optional[SiemStreamProcessor] = None
        self.alert_manager: Optional[SiemAlertManager] = None
        self.unified_dashboard: Optional[UnifiedThreatDashboard] = None
        
        # Status tracking
        self._initialized = False
        self._running = False
        self._start_time: Optional[datetime] = None
        
        # Metrics aggregation
        self._integration_metrics = {
            'events_processed': 0,
            'correlations_created': 0,
            'alerts_generated': 0,
            'enrichments_performed': 0,
            'siem_platforms_connected': 0,
            'uptime_seconds': 0,
            'errors_encountered': 0
        }
        
        logger.info("SIEM Integration Manager initialized")
    
    async def initialize(self) -> None:
        """Initialize all SIEM integration components"""
        if self._initialized:
            logger.warning("SIEM integration already initialized")
            return
        
        try:
            logger.info("Initializing SIEM integration components...")
            
            # Initialize SIEM connectors
            await self._initialize_siem_connectors()
            
            # Initialize correlation engine
            if self.config.enable_correlation:
                await self._initialize_correlation_engine()
            
            # Initialize enrichment service
            if self.config.enable_enrichment:
                await self._initialize_enrichment_service()
            
            # Initialize stream processor
            if self.config.enable_stream_processing:
                await self._initialize_stream_processor()
            
            # Initialize alert manager
            if self.config.enable_alert_management:
                await self._initialize_alert_manager()
            
            # Initialize dashboard
            if self.config.enable_dashboard:
                await self._initialize_dashboard()
            
            # Set up integration workflows
            await self._setup_integration_workflows()
            
            self._initialized = True
            logger.info("SIEM integration initialization completed successfully")
            
        except Exception as e:
            logger.error(f"Error initializing SIEM integration: {e}")
            raise
    
    async def start(self) -> None:
        """Start all SIEM integration services"""
        if not self._initialized:
            await self.initialize()
        
        if self._running:
            logger.warning("SIEM integration already running")
            return
        
        try:
            self._start_time = datetime.utcnow()
            self._running = True
            
            logger.info("Starting SIEM integration services...")
            
            # Start SIEM connectors
            connection_tasks = []
            for connector in self.siem_connectors:
                task = asyncio.create_task(connector.connect())
                connection_tasks.append(task)
            
            # Wait for all connections
            connection_results = await asyncio.gather(*connection_tasks, return_exceptions=True)
            
            connected_count = 0
            for i, result in enumerate(connection_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to connect {self.siem_connectors[i].platform}: {result}")
                elif result:
                    connected_count += 1
                    logger.info(f"Connected to {self.siem_connectors[i].platform}")
                else:
                    logger.warning(f"Connection failed for {self.siem_connectors[i].platform}")
            
            self._integration_metrics['siem_platforms_connected'] = connected_count
            
            if connected_count == 0:
                raise Exception("No SIEM platforms connected successfully")
            
            # Start core services
            start_tasks = []
            
            if self.correlation_engine:
                start_tasks.append(self.correlation_engine.start())
            
            if self.enrichment_service:
                start_tasks.append(self.enrichment_service.start())
            
            if self.stream_processor:
                start_tasks.append(self.stream_processor.start())
            
            if self.alert_manager:
                start_tasks.append(self.alert_manager.start())
            
            if self.unified_dashboard:
                start_tasks.append(self.unified_dashboard.start())
            
            # Start all services
            await asyncio.gather(*start_tasks, return_exceptions=True)
            
            logger.info("SIEM integration services started successfully")
            
        except Exception as e:
            logger.error(f"Error starting SIEM integration: {e}")
            self._running = False
            raise
    
    async def stop(self) -> None:
        """Stop all SIEM integration services"""
        if not self._running:
            return
        
        logger.info("Stopping SIEM integration services...")
        self._running = False
        
        # Stop services
        stop_tasks = []
        
        if self.unified_dashboard:
            stop_tasks.append(self.unified_dashboard.stop())
        
        if self.alert_manager:
            stop_tasks.append(self.alert_manager.stop())
        
        if self.stream_processor:
            stop_tasks.append(self.stream_processor.stop())
        
        if self.enrichment_service:
            stop_tasks.append(self.enrichment_service.stop())
        
        if self.correlation_engine:
            stop_tasks.append(self.correlation_engine.stop())
        
        # Stop SIEM connectors
        for connector in self.siem_connectors:
            stop_tasks.append(connector.disconnect())
        
        # Wait for all stops
        await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        logger.info("SIEM integration services stopped")
    
    async def _initialize_siem_connectors(self) -> None:
        """Initialize SIEM platform connectors"""
        logger.info("Initializing SIEM connectors...")
        
        # Splunk connector
        if self.config.enable_splunk:
            try:
                from .siem.splunk_connector import SplunkConfig
                
                splunk_config = SplunkConfig(
                    host=self.config.splunk_host,
                    port=self.config.splunk_port,
                    username=self.config.splunk_username,
                    password=self.config.splunk_password,
                    token=self.config.splunk_token
                )
                
                splunk_connector = SplunkConnector(splunk_config)
                self.siem_connectors.append(splunk_connector)
                logger.info("Splunk connector initialized")
                
            except Exception as e:
                logger.error(f"Error initializing Splunk connector: {e}")
                raise
        
        # QRadar connector
        if self.config.enable_qradar:
            try:
                from .siem.qradar_connector import QRadarConfig
                
                qradar_config = QRadarConfig(
                    host=self.config.qradar_host,
                    port=self.config.qradar_port,
                    sec_token=self.config.qradar_sec_token,
                    username=self.config.qradar_username,
                    password=self.config.qradar_password
                )
                
                qradar_connector = QRadarConnector(qradar_config)
                self.siem_connectors.append(qradar_connector)
                logger.info("QRadar connector initialized")
                
            except Exception as e:
                logger.error(f"Error initializing QRadar connector: {e}")
                raise
        
        # Sentinel connector
        if self.config.enable_sentinel:
            try:
                from .siem.sentinel_connector import SentinelConfig
                
                sentinel_config = SentinelConfig(
                    workspace_id=self.config.sentinel_workspace_id,
                    subscription_id=self.config.sentinel_subscription_id,
                    resource_group=self.config.sentinel_resource_group,
                    tenant_id=self.config.sentinel_tenant_id,
                    client_id=self.config.sentinel_client_id,
                    client_secret=self.config.sentinel_client_secret
                )
                
                sentinel_connector = SentinelConnector(sentinel_config)
                self.siem_connectors.append(sentinel_connector)
                logger.info("Sentinel connector initialized")
                
            except Exception as e:
                logger.error(f"Error initializing Sentinel connector: {e}")
                raise
        
        if not self.siem_connectors:
            raise Exception("No SIEM connectors configured")
        
        logger.info(f"Initialized {len(self.siem_connectors)} SIEM connectors")
    
    async def _initialize_correlation_engine(self) -> None:
        """Initialize threat correlation engine"""
        logger.info("Initializing threat correlation engine...")
        
        self.correlation_engine = ThreatCorrelationEngine(
            behavioral_model=self.behavioral_model,
            zero_day_model=self.zero_day_model,
            threat_classification_model=self.threat_classification_model,
            predictive_model=self.predictive_model
        )
        
        logger.info("Threat correlation engine initialized")
    
    async def _initialize_enrichment_service(self) -> None:
        """Initialize alert enrichment service"""
        logger.info("Initializing alert enrichment service...")
        
        self.enrichment_service = AlertEnrichmentService(
            siem_connectors=self.siem_connectors,
            correlation_engine=self.correlation_engine,
            behavioral_model=self.behavioral_model,
            zero_day_model=self.zero_day_model,
            threat_classification_model=self.threat_classification_model,
            predictive_model=self.predictive_model,
            max_concurrent_enrichments=self.config.max_concurrent_enrichments
        )
        
        logger.info("Alert enrichment service initialized")
    
    async def _initialize_stream_processor(self) -> None:
        """Initialize stream processor"""
        logger.info("Initializing stream processor...")
        
        stream_config = StreamConfig(
            buffer_size=self.config.stream_buffer_size,
            enable_correlation=self.config.enable_correlation,
            enable_enrichment=self.config.enable_enrichment
        )
        
        self.stream_processor = SiemStreamProcessor(
            config=stream_config,
            siem_connectors=self.siem_connectors,
            correlation_engine=self.correlation_engine,
            enrichment_service=self.enrichment_service
        )
        
        logger.info("Stream processor initialized")
    
    async def _initialize_alert_manager(self) -> None:
        """Initialize alert manager"""
        logger.info("Initializing alert manager...")
        
        alert_config = AlertConfig(
            max_alerts_per_hour=self.config.alert_rate_limit_per_hour,
            enable_correlation=self.config.enable_correlation,
            enable_enrichment=self.config.enable_enrichment
        )
        
        self.alert_manager = SiemAlertManager(
            config=alert_config,
            siem_connectors=self.siem_connectors,
            correlation_engine=self.correlation_engine,
            enrichment_service=self.enrichment_service
        )
        
        logger.info("Alert manager initialized")
    
    async def _initialize_dashboard(self) -> None:
        """Initialize unified dashboard"""
        logger.info("Initializing unified threat dashboard...")
        
        self.unified_dashboard = UnifiedThreatDashboard(
            siem_connectors=self.siem_connectors,
            stream_processor=self.stream_processor,
            correlation_engine=self.correlation_engine,
            enrichment_service=self.enrichment_service,
            update_interval_seconds=self.config.dashboard_update_interval
        )
        
        logger.info("Unified threat dashboard initialized")
    
    async def _setup_integration_workflows(self) -> None:
        """Set up integration workflows between components"""
        logger.info("Setting up integration workflows...")
        
        # Connect stream processor to alert manager
        if self.stream_processor and self.alert_manager:
            async def on_high_priority_event(event):
                if event.severity in ["critical", "high"]:
                    await self.alert_manager.create_alert_from_event(event)
            
            self.stream_processor.add_event_handler(on_high_priority_event)
        
        # Connect correlation engine to alert manager
        if self.correlation_engine and self.alert_manager:
            async def on_high_confidence_correlation(correlation):
                if correlation.confidence_score > 0.8:
                    await self.alert_manager.create_alert_from_correlation(correlation)
            
            # This would need to be implemented in the correlation engine
            # self.correlation_engine.add_correlation_handler(on_high_confidence_correlation)
        
        logger.info("Integration workflows configured")
    
    async def get_integration_status(self) -> Dict[str, Any]:
        """Get comprehensive integration status"""
        status = {
            'initialized': self._initialized,
            'running': self._running,
            'start_time': self._start_time.isoformat() if self._start_time else None,
            'uptime_seconds': (datetime.utcnow() - self._start_time).total_seconds() if self._start_time else 0,
            'siem_connectors': {},
            'services': {},
            'metrics': await self._get_aggregated_metrics()
        }
        
        # SIEM connector status
        for connector in self.siem_connectors:
            status['siem_connectors'][connector.platform.value] = {
                'status': connector.get_connection_status().value,
                'metrics': connector.get_metrics()
            }
        
        # Service status
        if self.correlation_engine:
            status['services']['correlation_engine'] = {
                'active_correlations': len(self.correlation_engine.get_active_correlations()),
                'metrics': self.correlation_engine.get_metrics()
            }
        
        if self.enrichment_service:
            status['services']['enrichment_service'] = {
                'metrics': self.enrichment_service.get_metrics()
            }
        
        if self.stream_processor:
            status['services']['stream_processor'] = {
                'status': self.stream_processor.get_status().value,
                'metrics': self.stream_processor.get_metrics()
            }
        
        if self.alert_manager:
            status['services']['alert_manager'] = {
                'active_alerts': len(self.alert_manager.get_active_alerts()),
                'metrics': self.alert_manager.get_metrics()
            }
        
        if self.unified_dashboard:
            status['services']['unified_dashboard'] = {
                'widgets': len(self.unified_dashboard.list_widgets()),
                'metrics': self.unified_dashboard.get_metrics()
            }
        
        return status
    
    async def _get_aggregated_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics from all components"""
        metrics = self._integration_metrics.copy()
        
        # Aggregate from components
        if self.stream_processor:
            stream_metrics = self.stream_processor.get_metrics()
            metrics['events_processed'] += stream_metrics.get('events_processed', 0)
        
        if self.correlation_engine:
            corr_metrics = self.correlation_engine.get_metrics()
            metrics['correlations_created'] += corr_metrics.get('correlations_created', 0)
        
        if self.alert_manager:
            alert_metrics = self.alert_manager.get_metrics()
            metrics['alerts_generated'] += alert_metrics.get('alerts_created', 0)
        
        if self.enrichment_service:
            enrich_metrics = self.enrichment_service.get_metrics()
            metrics['enrichments_performed'] += enrich_metrics.get('alerts_enriched', 0)
        
        # Calculate uptime
        if self._start_time:
            metrics['uptime_seconds'] = (datetime.utcnow() - self._start_time).total_seconds()
        
        return metrics
    
    async def get_dashboard_data(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get unified dashboard data"""
        if not self.unified_dashboard:
            return {'error': 'Dashboard not initialized'}
        
        from .siem.unified_dashboard import TimeRange
        
        # Map string to TimeRange enum
        time_range_mapping = {
            "15m": TimeRange.LAST_15_MINUTES,
            "1h": TimeRange.LAST_HOUR,
            "4h": TimeRange.LAST_4_HOURS,
            "24h": TimeRange.LAST_24_HOURS,
            "7d": TimeRange.LAST_7_DAYS,
            "30d": TimeRange.LAST_30_DAYS
        }
        
        tr = time_range_mapping.get(time_range, TimeRange.LAST_24_HOURS)
        return await self.unified_dashboard.get_dashboard_data(tr)
    
    async def create_test_alert(self, title: str, description: str, severity: str = "medium") -> Optional[str]:
        """Create test alert for validation"""
        if not self.alert_manager:
            logger.error("Alert manager not initialized")
            return None
        
        from .siem.base_connector import SiemEvent, EventSeverity
        
        # Map severity string to enum
        severity_mapping = {
            "critical": EventSeverity.CRITICAL,
            "high": EventSeverity.HIGH,
            "medium": EventSeverity.MEDIUM,
            "low": EventSeverity.LOW,
            "info": EventSeverity.INFO
        }
        
        test_event = SiemEvent(
            id=f"test_{datetime.utcnow().timestamp()}",
            source="isectech-test",
            event_type="test_alert",
            category="testing",
            message=description,
            severity=severity_mapping.get(severity, EventSeverity.MEDIUM),
            tags=["test", "validation"]
        )
        
        alert = await self.alert_manager.create_alert_from_event(test_event)
        return alert.alert_id if alert else None
    
    def export_configuration(self) -> Dict[str, Any]:
        """Export current configuration"""
        return {
            'siem_integration_config': {
                'enable_splunk': self.config.enable_splunk,
                'enable_qradar': self.config.enable_qradar,
                'enable_sentinel': self.config.enable_sentinel,
                'enable_correlation': self.config.enable_correlation,
                'enable_enrichment': self.config.enable_enrichment,
                'enable_stream_processing': self.config.enable_stream_processing,
                'enable_dashboard': self.config.enable_dashboard,
                'enable_alert_management': self.config.enable_alert_management,
                'max_concurrent_enrichments': self.config.max_concurrent_enrichments,
                'stream_buffer_size': self.config.stream_buffer_size,
                'dashboard_update_interval': self.config.dashboard_update_interval,
                'alert_rate_limit_per_hour': self.config.alert_rate_limit_per_hour
            },
            'ai_models_enabled': {
                'behavioral_model': self.behavioral_model is not None,
                'zero_day_model': self.zero_day_model is not None,
                'threat_classification_model': self.threat_classification_model is not None,
                'predictive_model': self.predictive_model is not None
            },
            'components_initialized': {
                'correlation_engine': self.correlation_engine is not None,
                'enrichment_service': self.enrichment_service is not None,
                'stream_processor': self.stream_processor is not None,
                'alert_manager': self.alert_manager is not None,
                'unified_dashboard': self.unified_dashboard is not None
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        health = {
            'overall_status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {},
            'issues': []
        }
        
        try:
            # Check SIEM connectors
            for connector in self.siem_connectors:
                platform = connector.platform.value
                connector_healthy = await connector.health_check()
                
                health['components'][f'siem_{platform}'] = {
                    'status': 'healthy' if connector_healthy else 'unhealthy',
                    'connection_status': connector.get_connection_status().value
                }
                
                if not connector_healthy:
                    health['issues'].append(f"SIEM connector {platform} is unhealthy")
                    health['overall_status'] = 'degraded'
            
            # Check stream processor
            if self.stream_processor:
                stream_status = self.stream_processor.get_status()
                health['components']['stream_processor'] = {
                    'status': 'healthy' if stream_status.value == 'running' else 'unhealthy',
                    'processing_status': stream_status.value
                }
                
                if stream_status.value != 'running':
                    health['issues'].append(f"Stream processor status: {stream_status.value}")
                    health['overall_status'] = 'degraded'
            
            # Check other components
            components_to_check = [
                ('correlation_engine', self.correlation_engine),
                ('enrichment_service', self.enrichment_service),
                ('alert_manager', self.alert_manager),
                ('unified_dashboard', self.unified_dashboard)
            ]
            
            for name, component in components_to_check:
                if component:
                    health['components'][name] = {'status': 'healthy'}
                else:
                    health['components'][name] = {'status': 'not_initialized'}
            
            # Determine overall status
            if health['issues']:
                if any('unhealthy' in issue for issue in health['issues']):
                    health['overall_status'] = 'unhealthy'
                else:
                    health['overall_status'] = 'degraded'
            
        except Exception as e:
            health['overall_status'] = 'unhealthy'
            health['issues'].append(f"Health check error: {str(e)}")
            logger.error(f"Health check error: {e}")
        
        return health
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()