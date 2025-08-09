"""
Alert Source Connectors for SOC Automation Platform

This module provides connectors for various security tools and data sources
to ingest alerts into the SOC automation platform.

Supported connectors:
- SIEM platforms (Splunk, Elastic Security, QRadar)
- EDR solutions (CrowdStrike, SentinelOne, Carbon Black)
- Network security (Suricata, Snort, Zeek)
- Cloud security (AWS CloudTrail, Azure Sentinel, GCP Security)
- Custom API connectors
- Webhook receivers
"""

from .base_connector import BaseConnector, ConnectorStatus
from .siem_connectors import SplunkConnector, ElasticConnector
from .edr_connectors import CrowdStrikeConnector
from .network_connectors import SuricataConnector
from .cloud_connectors import CloudTrailConnector
from .webhook_connector import WebhookConnector
from .custom_connector import CustomAPIConnector

__all__ = [
    'BaseConnector',
    'ConnectorStatus',
    'SplunkConnector',
    'ElasticConnector', 
    'CrowdStrikeConnector',
    'SuricataConnector',
    'CloudTrailConnector',
    'WebhookConnector',
    'CustomAPIConnector'
]