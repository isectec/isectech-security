"""
SIEM Integration Module

Production-grade bidirectional integration with SIEM platforms (Splunk, QRadar, Sentinel)
providing real-time event streaming, threat correlation, and alert enrichment capabilities.
"""

from .base_connector import BaseSiemConnector, SiemConfig, SiemEvent, SiemResponse
from .splunk_connector import SplunkConnector, SplunkConfig
from .qradar_connector import QRadarConnector, QRadarConfig  
from .sentinel_connector import SentinelConnector, SentinelConfig
from .correlation_engine import ThreatCorrelationEngine, CorrelationRule, CorrelationResult
from .enrichment_service import AlertEnrichmentService, EnrichmentData, EnrichedAlert
from .unified_dashboard import UnifiedThreatDashboard, ThreatMetrics, DashboardWidget
from .stream_processor import SiemStreamProcessor, StreamConfig, EventBuffer
from .alert_manager import SiemAlertManager, AlertConfig, AlertSeverity

__all__ = [
    "BaseSiemConnector",
    "SiemConfig", 
    "SiemEvent",
    "SiemResponse",
    "SplunkConnector",
    "SplunkConfig",
    "QRadarConnector", 
    "QRadarConfig",
    "SentinelConnector",
    "SentinelConfig",
    "ThreatCorrelationEngine",
    "CorrelationRule",
    "CorrelationResult",
    "AlertEnrichmentService",
    "EnrichmentData",
    "EnrichedAlert",
    "UnifiedThreatDashboard",
    "ThreatMetrics",
    "DashboardWidget",
    "SiemStreamProcessor",
    "StreamConfig",
    "EventBuffer", 
    "SiemAlertManager",
    "AlertConfig",
    "AlertSeverity"
]