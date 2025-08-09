"""
Data Sources Integration for ML User Behavior Analysis.

This module provides comprehensive data source integration capabilities for collecting,
normalizing, and aggregating user behavior data from multiple sources required for
machine learning model training and real-time inference.

Performance Engineering Focus:
- Asynchronous data collection with connection pooling
- Batch processing for high throughput (>10K events/sec)
- Memory-efficient streaming data processing
- Optimized data normalization and schema validation
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator, Callable, Union
from enum import Enum
import json
import aiohttp
import aiokafka
import asyncpg
import aioredis
from sqlalchemy.ext.asyncio import create_async_engine
from elasticsearch import AsyncElasticsearch
import pandas as pd
import numpy as np
from pydantic import BaseModel, Field, ValidationError
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)


class DataSourceType(Enum):
    """Types of data sources for behavior analysis."""
    AUTHENTICATION_LOGS = "authentication_logs"
    APPLICATION_LOGS = "application_logs"
    NETWORK_LOGS = "network_logs"
    CLICKSTREAM_DATA = "clickstream_data"
    DEVICE_METADATA = "device_metadata"
    ACCESS_CONTROL_LOGS = "access_control_logs"
    VPN_LOGS = "vpn_logs"
    EMAIL_ACTIVITY = "email_activity"
    FILE_ACCESS_LOGS = "file_access_logs"
    ENDPOINT_SECURITY = "endpoint_security"
    CLOUD_AUDIT_LOGS = "cloud_audit_logs"
    DATABASE_ACTIVITY = "database_activity"


class DataQualityStatus(Enum):
    """Data quality assessment status."""
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    INSUFFICIENT = "insufficient"


@dataclass
class DataSourceConfig:
    """Configuration for a data source."""
    source_id: str
    source_type: DataSourceType
    name: str
    description: str
    connection_config: Dict[str, Any]
    schema_mapping: Dict[str, str]
    collection_interval_seconds: int = 60
    batch_size: int = 1000
    enabled: bool = True
    priority: str = "medium"  # high, medium, low
    retention_days: int = 365
    quality_checks: List[str] = field(default_factory=list)
    data_classification: str = "internal"  # public, internal, confidential, restricted


@dataclass 
class BehaviorEvent:
    """Standardized behavior event structure."""
    event_id: str
    user_id: str
    session_id: Optional[str]
    timestamp: datetime
    event_type: str
    source: str
    data: Dict[str, Any]
    device_info: Optional[Dict[str, Any]] = None
    location_info: Optional[Dict[str, Any]] = None
    risk_indicators: Dict[str, Any] = field(default_factory=dict)
    processed: bool = False
    quality_score: float = 1.0


class SchemaValidator:
    """Schema validation for incoming data."""
    
    def __init__(self):
        self.schemas = self._load_schemas()
    
    def _load_schemas(self) -> Dict[str, Dict]:
        """Load predefined schemas for different data sources."""
        return {
            DataSourceType.AUTHENTICATION_LOGS.value: {
                "required_fields": ["user_id", "timestamp", "action", "result", "source_ip"],
                "optional_fields": ["user_agent", "device_id", "mfa_used", "location"],
                "field_types": {
                    "user_id": str,
                    "timestamp": datetime,
                    "action": str,
                    "result": str,
                    "source_ip": str
                }
            },
            DataSourceType.APPLICATION_LOGS.value: {
                "required_fields": ["user_id", "timestamp", "application", "action", "resource"],
                "optional_fields": ["session_id", "duration", "parameters", "response_code"],
                "field_types": {
                    "user_id": str,
                    "timestamp": datetime,
                    "application": str,
                    "action": str,
                    "resource": str
                }
            },
            DataSourceType.NETWORK_LOGS.value: {
                "required_fields": ["user_id", "timestamp", "source_ip", "destination_ip", "protocol"],
                "optional_fields": ["port", "bytes_sent", "bytes_received", "duration", "flags"],
                "field_types": {
                    "user_id": str,
                    "timestamp": datetime,
                    "source_ip": str,
                    "destination_ip": str,
                    "protocol": str
                }
            }
        }
    
    def validate_event(self, event_data: Dict[str, Any], source_type: DataSourceType) -> tuple[bool, List[str]]:
        """Validate event data against schema."""
        if source_type.value not in self.schemas:
            return False, [f"No schema defined for source type: {source_type.value}"]
        
        schema = self.schemas[source_type.value]
        errors = []
        
        # Check required fields
        for field in schema["required_fields"]:
            if field not in event_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate field types
        for field, expected_type in schema["field_types"].items():
            if field in event_data:
                if not isinstance(event_data[field], expected_type) and expected_type != datetime:
                    if expected_type == datetime and isinstance(event_data[field], str):
                        try:
                            datetime.fromisoformat(event_data[field].replace('Z', '+00:00'))
                        except ValueError:
                            errors.append(f"Invalid datetime format for field: {field}")
                    else:
                        errors.append(f"Invalid type for field {field}: expected {expected_type.__name__}")
        
        return len(errors) == 0, errors


class DataQualityAssessment:
    """Data quality assessment and monitoring."""
    
    def __init__(self):
        self.quality_metrics = {}
        self.quality_history = {}
    
    async def assess_data_quality(self, events: List[BehaviorEvent], source_id: str) -> Dict[str, Any]:
        """Assess data quality for a batch of events."""
        if not events:
            return {"status": DataQualityStatus.INSUFFICIENT.value, "score": 0.0}
        
        metrics = {
            "completeness": self._assess_completeness(events),
            "validity": self._assess_validity(events),
            "consistency": self._assess_consistency(events),
            "timeliness": self._assess_timeliness(events),
            "uniqueness": self._assess_uniqueness(events)
        }
        
        # Calculate overall quality score (weighted average)
        weights = {"completeness": 0.25, "validity": 0.25, "consistency": 0.2, "timeliness": 0.15, "uniqueness": 0.15}
        overall_score = sum(metrics[key] * weights[key] for key in weights.keys())
        
        # Determine quality status
        if overall_score >= 0.9:
            status = DataQualityStatus.EXCELLENT
        elif overall_score >= 0.75:
            status = DataQualityStatus.GOOD
        elif overall_score >= 0.6:
            status = DataQualityStatus.FAIR
        elif overall_score >= 0.4:
            status = DataQualityStatus.POOR
        else:
            status = DataQualityStatus.INSUFFICIENT
        
        quality_report = {
            "status": status.value,
            "overall_score": overall_score,
            "metrics": metrics,
            "event_count": len(events),
            "assessment_timestamp": datetime.utcnow().isoformat()
        }
        
        # Store quality metrics
        self.quality_metrics[source_id] = quality_report
        
        return quality_report
    
    def _assess_completeness(self, events: List[BehaviorEvent]) -> float:
        """Assess data completeness."""
        if not events:
            return 0.0
        
        total_fields = 0
        complete_fields = 0
        
        for event in events:
            # Check core fields
            core_fields = ['user_id', 'timestamp', 'event_type', 'source']
            for field in core_fields:
                total_fields += 1
                if hasattr(event, field) and getattr(event, field) is not None:
                    complete_fields += 1
        
        return complete_fields / total_fields if total_fields > 0 else 0.0
    
    def _assess_validity(self, events: List[BehaviorEvent]) -> float:
        """Assess data validity."""
        if not events:
            return 0.0
        
        valid_events = 0
        for event in events:
            is_valid = True
            
            # Check timestamp validity
            if not isinstance(event.timestamp, datetime):
                is_valid = False
            
            # Check user_id format
            if not event.user_id or len(event.user_id) < 1:
                is_valid = False
            
            # Check event_type format
            if not event.event_type or len(event.event_type) < 1:
                is_valid = False
            
            if is_valid:
                valid_events += 1
        
        return valid_events / len(events)
    
    def _assess_consistency(self, events: List[BehaviorEvent]) -> float:
        """Assess data consistency."""
        if len(events) < 2:
            return 1.0
        
        # Check timestamp ordering
        timestamps = [event.timestamp for event in events if isinstance(event.timestamp, datetime)]
        if len(timestamps) < 2:
            return 0.5
        
        ordered_count = sum(1 for i in range(1, len(timestamps)) if timestamps[i] >= timestamps[i-1])
        consistency_score = ordered_count / (len(timestamps) - 1) if len(timestamps) > 1 else 1.0
        
        return consistency_score
    
    def _assess_timeliness(self, events: List[BehaviorEvent]) -> float:
        """Assess data timeliness."""
        if not events:
            return 0.0
        
        current_time = datetime.utcnow()
        timely_events = 0
        
        for event in events:
            if isinstance(event.timestamp, datetime):
                age_minutes = (current_time - event.timestamp).total_seconds() / 60
                if age_minutes <= 60:  # Consider events timely if within 1 hour
                    timely_events += 1
        
        return timely_events / len(events)
    
    def _assess_uniqueness(self, events: List[BehaviorEvent]) -> float:
        """Assess data uniqueness."""
        if not events:
            return 0.0
        
        event_hashes = set()
        for event in events:
            event_key = f"{event.user_id}:{event.timestamp.isoformat()}:{event.event_type}"
            event_hashes.add(event_key)
        
        return len(event_hashes) / len(events)


class DataSourceConnector(ABC):
    """Abstract base class for data source connectors."""
    
    def __init__(self, config: DataSourceConfig):
        self.config = config
        self.is_connected = False
        self.connection_pool = None
        self.last_collection_time = None
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to data source."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to data source."""
        pass
    
    @abstractmethod
    async def collect_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Collect events from data source."""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """Test connection health."""
        pass


class PostgreSQLConnector(DataSourceConnector):
    """PostgreSQL database connector for structured log data."""
    
    async def connect(self) -> bool:
        """Connect to PostgreSQL database."""
        try:
            connection_string = (
                f"postgresql+asyncpg://{self.config.connection_config['username']}:"
                f"{self.config.connection_config['password']}@"
                f"{self.config.connection_config['host']}:"
                f"{self.config.connection_config['port']}/"
                f"{self.config.connection_config['database']}"
            )
            
            self.connection_pool = create_async_engine(
                connection_string,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            self.is_connected = True
            logger.info(f"Connected to PostgreSQL: {self.config.source_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL {self.config.source_id}: {str(e)}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from PostgreSQL."""
        if self.connection_pool:
            await self.connection_pool.dispose()
            self.is_connected = False
    
    async def collect_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Collect events from PostgreSQL."""
        if not self.is_connected:
            await self.connect()
        
        query = self.config.connection_config.get('query', '')
        if not query:
            return []
        
        try:
            async with self.connection_pool.connect() as conn:
                result = await conn.execute(query, {
                    'start_time': start_time,
                    'end_time': end_time,
                    'limit': self.config.batch_size
                })
                
                rows = await result.fetchall()
                events = [dict(row) for row in rows]
                
                logger.debug(f"Collected {len(events)} events from PostgreSQL: {self.config.source_id}")
                return events
        except Exception as e:
            logger.error(f"Error collecting from PostgreSQL {self.config.source_id}: {str(e)}")
            return []
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test PostgreSQL connection."""
        try:
            async with self.connection_pool.connect() as conn:
                result = await conn.execute("SELECT 1")
                await result.fetchone()
                return {"status": "healthy", "latency_ms": 0}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


class ElasticsearchConnector(DataSourceConnector):
    """Elasticsearch connector for log aggregation."""
    
    async def connect(self) -> bool:
        """Connect to Elasticsearch."""
        try:
            self.connection_pool = AsyncElasticsearch([{
                'host': self.config.connection_config['host'],
                'port': self.config.connection_config['port'],
                'use_ssl': self.config.connection_config.get('use_ssl', False)
            }])
            
            # Test connection
            info = await self.connection_pool.info()
            self.is_connected = True
            logger.info(f"Connected to Elasticsearch: {self.config.source_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch {self.config.source_id}: {str(e)}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Elasticsearch."""
        if self.connection_pool:
            await self.connection_pool.close()
            self.is_connected = False
    
    async def collect_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Collect events from Elasticsearch."""
        if not self.is_connected:
            await self.connect()
        
        index_pattern = self.config.connection_config.get('index_pattern', '*')
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_time.isoformat(),
                        "lte": end_time.isoformat()
                    }
                }
            },
            "size": self.config.batch_size,
            "sort": [{"@timestamp": "asc"}]
        }
        
        try:
            response = await self.connection_pool.search(
                index=index_pattern,
                body=query
            )
            
            events = [hit['_source'] for hit in response['hits']['hits']]
            logger.debug(f"Collected {len(events)} events from Elasticsearch: {self.config.source_id}")
            return events
        except Exception as e:
            logger.error(f"Error collecting from Elasticsearch {self.config.source_id}: {str(e)}")
            return []
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Elasticsearch connection."""
        try:
            info = await self.connection_pool.info()
            return {"status": "healthy", "cluster_name": info['cluster_name']}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


class KafkaConnector(DataSourceConnector):
    """Kafka connector for real-time event streaming."""
    
    async def connect(self) -> bool:
        """Connect to Kafka."""
        try:
            self.consumer = aiokafka.AIOKafkaConsumer(
                *self.config.connection_config.get('topics', []),
                bootstrap_servers=self.config.connection_config['bootstrap_servers'],
                group_id=self.config.connection_config.get('group_id', 'behavior-analysis'),
                auto_offset_reset='latest',
                enable_auto_commit=True,
                max_poll_records=self.config.batch_size
            )
            
            await self.consumer.start()
            self.is_connected = True
            logger.info(f"Connected to Kafka: {self.config.source_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Kafka {self.config.source_id}: {str(e)}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Kafka."""
        if hasattr(self, 'consumer'):
            await self.consumer.stop()
            self.is_connected = False
    
    async def collect_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Collect events from Kafka (streaming mode)."""
        if not self.is_connected:
            await self.connect()
        
        events = []
        try:
            async for msg in self.consumer:
                try:
                    event_data = json.loads(msg.value.decode('utf-8'))
                    events.append(event_data)
                    
                    if len(events) >= self.config.batch_size:
                        break
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in Kafka message: {self.config.source_id}")
                    continue
        except Exception as e:
            logger.error(f"Error collecting from Kafka {self.config.source_id}: {str(e)}")
        
        return events
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Kafka connection."""
        try:
            partitions = self.consumer.assignment()
            return {"status": "healthy", "partitions": len(partitions)}
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}


class DataSourceIntegrationManager:
    """Central manager for all data source integrations."""
    
    def __init__(self):
        self.data_sources: Dict[str, DataSourceConfig] = {}
        self.connectors: Dict[str, DataSourceConnector] = {}
        self.schema_validator = SchemaValidator()
        self.quality_assessor = DataQualityAssessment()
        self.event_buffer: List[BehaviorEvent] = []
        self.processing_stats = {
            "events_processed": 0,
            "events_rejected": 0,
            "last_processing_time": None,
            "average_processing_latency": 0.0
        }
    
    def register_data_source(self, config: DataSourceConfig) -> bool:
        """Register a new data source configuration."""
        try:
            self.data_sources[config.source_id] = config
            
            # Create appropriate connector
            if 'postgresql' in config.connection_config.get('type', '').lower():
                self.connectors[config.source_id] = PostgreSQLConnector(config)
            elif 'elasticsearch' in config.connection_config.get('type', '').lower():
                self.connectors[config.source_id] = ElasticsearchConnector(config)
            elif 'kafka' in config.connection_config.get('type', '').lower():
                self.connectors[config.source_id] = KafkaConnector(config)
            else:
                logger.error(f"Unsupported data source type for {config.source_id}")
                return False
            
            logger.info(f"Registered data source: {config.source_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to register data source {config.source_id}: {str(e)}")
            return False
    
    async def initialize_connections(self) -> Dict[str, bool]:
        """Initialize connections to all registered data sources."""
        connection_results = {}
        
        for source_id, connector in self.connectors.items():
            try:
                result = await connector.connect()
                connection_results[source_id] = result
                logger.info(f"Data source {source_id}: {'Connected' if result else 'Failed'}")
            except Exception as e:
                logger.error(f"Connection failed for {source_id}: {str(e)}")
                connection_results[source_id] = False
        
        return connection_results
    
    async def collect_all_events(self, start_time: datetime, end_time: datetime) -> List[BehaviorEvent]:
        """Collect events from all enabled data sources."""
        all_events = []
        collection_tasks = []
        
        for source_id, config in self.data_sources.items():
            if config.enabled and source_id in self.connectors:
                task = asyncio.create_task(
                    self._collect_from_source(source_id, start_time, end_time)
                )
                collection_tasks.append(task)
        
        # Execute all collection tasks concurrently
        results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        
        for source_id, result in zip(self.data_sources.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"Collection failed for {source_id}: {str(result)}")
            else:
                all_events.extend(result)
                logger.debug(f"Collected {len(result)} events from {source_id}")
        
        return all_events
    
    async def _collect_from_source(self, source_id: str, start_time: datetime, end_time: datetime) -> List[BehaviorEvent]:
        """Collect events from a specific data source."""
        connector = self.connectors[source_id]
        config = self.data_sources[source_id]
        
        try:
            # Collect raw events
            raw_events = await connector.collect_events(start_time, end_time)
            
            # Normalize and validate events
            normalized_events = []
            for raw_event in raw_events:
                behavior_event = await self._normalize_event(raw_event, config)
                if behavior_event:
                    normalized_events.append(behavior_event)
            
            # Assess data quality
            quality_report = await self.quality_assessor.assess_data_quality(normalized_events, source_id)
            logger.info(f"Data quality for {source_id}: {quality_report['status']} (score: {quality_report['overall_score']:.2f})")
            
            return normalized_events
        except Exception as e:
            logger.error(f"Error collecting from {source_id}: {str(e)}")
            return []
    
    async def _normalize_event(self, raw_event: Dict[str, Any], config: DataSourceConfig) -> Optional[BehaviorEvent]:
        """Normalize raw event data into standardized BehaviorEvent."""
        try:
            # Validate against schema
            is_valid, errors = self.schema_validator.validate_event(raw_event, config.source_type)
            if not is_valid:
                logger.warning(f"Schema validation failed for {config.source_id}: {errors}")
                self.processing_stats["events_rejected"] += 1
                return None
            
            # Apply field mapping
            mapped_data = {}
            for standard_field, source_field in config.schema_mapping.items():
                if source_field in raw_event:
                    mapped_data[standard_field] = raw_event[source_field]
            
            # Create standardized event
            event_id = hashlib.md5(
                f"{mapped_data.get('user_id', '')}{mapped_data.get('timestamp', '')}{config.source_id}".encode()
            ).hexdigest()
            
            # Handle timestamp conversion
            timestamp = mapped_data.get('timestamp')
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.utcnow()
            
            behavior_event = BehaviorEvent(
                event_id=event_id,
                user_id=mapped_data.get('user_id', ''),
                session_id=mapped_data.get('session_id'),
                timestamp=timestamp,
                event_type=mapped_data.get('event_type', config.source_type.value),
                source=config.source_id,
                data=mapped_data,
                device_info=mapped_data.get('device_info'),
                location_info=mapped_data.get('location_info')
            )
            
            self.processing_stats["events_processed"] += 1
            return behavior_event
        except Exception as e:
            logger.error(f"Event normalization failed: {str(e)}")
            self.processing_stats["events_rejected"] += 1
            return None
    
    async def health_check_all_sources(self) -> Dict[str, Dict[str, Any]]:
        """Perform health checks on all data sources."""
        health_results = {}
        
        for source_id, connector in self.connectors.items():
            try:
                health_result = await connector.test_connection()
                health_results[source_id] = health_result
            except Exception as e:
                health_results[source_id] = {"status": "error", "error": str(e)}
        
        return health_results
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get data processing statistics."""
        total_events = self.processing_stats["events_processed"] + self.processing_stats["events_rejected"]
        success_rate = (self.processing_stats["events_processed"] / total_events * 100) if total_events > 0 else 0
        
        return {
            "events_processed": self.processing_stats["events_processed"],
            "events_rejected": self.processing_stats["events_rejected"],
            "success_rate_percentage": success_rate,
            "last_processing_time": self.processing_stats["last_processing_time"],
            "average_processing_latency": self.processing_stats["average_processing_latency"],
            "registered_sources": len(self.data_sources),
            "active_connections": sum(1 for conn in self.connectors.values() if conn.is_connected)
        }
    
    async def cleanup_connections(self) -> None:
        """Clean up all data source connections."""
        for connector in self.connectors.values():
            try:
                await connector.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting connector: {str(e)}")


# Factory function for creating common data source configurations
def create_standard_data_sources() -> List[DataSourceConfig]:
    """Create standard data source configurations for common enterprise systems."""
    
    return [
        DataSourceConfig(
            source_id="auth_logs_postgres",
            source_type=DataSourceType.AUTHENTICATION_LOGS,
            name="Authentication Logs (PostgreSQL)",
            description="User authentication events from central identity provider",
            connection_config={
                "type": "postgresql",
                "host": "localhost",
                "port": 5432,
                "database": "security_logs",
                "username": "behavior_reader",
                "password": "${POSTGRES_PASSWORD}",
                "query": """
                    SELECT user_id, timestamp, action, result, source_ip, user_agent, 
                           device_id, mfa_used, location
                    FROM authentication_logs 
                    WHERE timestamp BETWEEN %(start_time)s AND %(end_time)s 
                    ORDER BY timestamp ASC 
                    LIMIT %(limit)s
                """
            },
            schema_mapping={
                "user_id": "user_id",
                "timestamp": "timestamp",
                "event_type": "action",
                "result": "result",
                "source_ip": "source_ip",
                "user_agent": "user_agent",
                "device_info": "device_id",
                "location_info": "location"
            },
            collection_interval_seconds=30,
            batch_size=1000,
            priority="high",
            quality_checks=["timestamp_validation", "user_id_validation", "ip_validation"]
        ),
        
        DataSourceConfig(
            source_id="app_logs_elasticsearch",
            source_type=DataSourceType.APPLICATION_LOGS,
            name="Application Logs (Elasticsearch)",
            description="Application access and activity logs",
            connection_config={
                "type": "elasticsearch",
                "host": "localhost",
                "port": 9200,
                "index_pattern": "app-logs-*",
                "use_ssl": False
            },
            schema_mapping={
                "user_id": "user.id",
                "timestamp": "@timestamp",
                "event_type": "action",
                "application": "app.name",
                "resource": "resource.path",
                "session_id": "session.id"
            },
            collection_interval_seconds=60,
            batch_size=2000,
            priority="medium"
        ),
        
        DataSourceConfig(
            source_id="network_logs_kafka",
            source_type=DataSourceType.NETWORK_LOGS,
            name="Network Logs (Kafka Stream)",
            description="Real-time network activity monitoring",
            connection_config={
                "type": "kafka",
                "bootstrap_servers": ["localhost:9092"],
                "topics": ["network-events", "firewall-logs"],
                "group_id": "behavior-analysis-network"
            },
            schema_mapping={
                "user_id": "user_id",
                "timestamp": "timestamp",
                "source_ip": "src_ip",
                "destination_ip": "dst_ip",
                "protocol": "protocol",
                "bytes_sent": "bytes_out",
                "bytes_received": "bytes_in"
            },
            collection_interval_seconds=15,
            batch_size=5000,
            priority="high"
        ),
        
        DataSourceConfig(
            source_id="endpoint_security_logs",
            source_type=DataSourceType.ENDPOINT_SECURITY,
            name="Endpoint Security Events",
            description="Endpoint detection and response events",
            connection_config={
                "type": "elasticsearch",
                "host": "localhost",
                "port": 9200,
                "index_pattern": "endpoint-security-*",
                "use_ssl": True
            },
            schema_mapping={
                "user_id": "user.name",
                "timestamp": "@timestamp",
                "event_type": "event.category",
                "device_info": "host",
                "process_info": "process"
            },
            collection_interval_seconds=45,
            batch_size=1500,
            priority="high",
            data_classification="confidential"
        )
    ]


async def initialize_behavior_data_integration() -> DataSourceIntegrationManager:
    """Initialize the complete data integration system for behavior analysis."""
    logger.info("Initializing Behavior Data Integration Manager")
    
    manager = DataSourceIntegrationManager()
    
    # Register standard data sources
    standard_sources = create_standard_data_sources()
    for source_config in standard_sources:
        success = manager.register_data_source(source_config)
        if success:
            logger.info(f"Registered data source: {source_config.source_id}")
        else:
            logger.error(f"Failed to register data source: {source_config.source_id}")
    
    # Initialize connections
    connection_results = await manager.initialize_connections()
    successful_connections = sum(1 for success in connection_results.values() if success)
    
    logger.info(f"Data Integration Manager initialized with {successful_connections}/{len(connection_results)} successful connections")
    
    return manager


# Example usage and testing
if __name__ == "__main__":
    async def test_data_integration():
        manager = await initialize_behavior_data_integration()
        
        # Perform health checks
        health_results = await manager.health_check_all_sources()
        print("Health Check Results:")
        for source_id, health in health_results.items():
            print(f"  {source_id}: {health['status']}")
        
        # Collect sample events
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        events = await manager.collect_all_events(start_time, end_time)
        print(f"\nCollected {len(events)} events")
        
        # Show processing statistics
        stats = manager.get_processing_statistics()
        print(f"Processing Statistics: {stats}")
        
        # Cleanup
        await manager.cleanup_connections()
    
    asyncio.run(test_data_integration())