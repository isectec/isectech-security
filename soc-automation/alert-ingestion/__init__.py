"""
SOC Automation Platform - Alert Ingestion Module
==============================================

This module provides comprehensive alert ingestion capabilities for the SOC automation platform.
It handles alerts from multiple sources, normalizes data formats, and stores alerts for processing.

Architecture:
- Multi-source connectors (SIEM, EDR, Network, Cloud, Custom APIs)
- Real-time and batch ingestion modes
- Alert normalization to Common Event Format (CEF)
- Elasticsearch storage with proper indexing
- Rate limiting and backpressure handling
- Duplicate detection and filtering
- Data enrichment pipeline integration

Integration with existing monitoring in monitoring/ directory for metrics and observability.
"""

__version__ = "1.0.0"
__author__ = "iSecTech SOC Automation Team"

from .alert_manager import AlertManager
from .connectors import *
from .normalizer import AlertNormalizer
from .storage import ElasticsearchStorage
from .enrichment import AlertEnricher

__all__ = [
    "AlertManager",
    "AlertNormalizer", 
    "ElasticsearchStorage",
    "AlertEnricher"
]