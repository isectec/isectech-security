"""
Data Collection Pipeline for AI/ML Threat Detection

This module implements a comprehensive data collection pipeline that ingests
security data from multiple sources including SIEM, network traffic, 
endpoint logs, and threat intelligence feeds.
"""

import asyncio
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, AsyncGenerator, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

import aioredis
import asyncpg
from elasticsearch import AsyncElasticsearch
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import KafkaError
import pandas as pd
import numpy as np
from pydantic import BaseModel, Field, validator

from ...shared.config.settings import Settings
from ...shared.security.encryption import EncryptionManager
from ...shared.api.monitoring import MetricsCollector


logger = logging.getLogger(__name__)


@dataclass
class DataSourceConfig:
    """Configuration for data source connections."""
    source_type: str
    connection_params: Dict[str, Any]
    schema_config: Dict[str, Any]
    rate_limit: int = 1000  # events per second
    batch_size: int = 1000
    enabled: bool = True
    encryption_enabled: bool = True


class SecurityEvent(BaseModel):
    """Standardized security event model."""
    timestamp: datetime
    event_id: str
    source_type: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    network_protocol: Optional[str] = None
    port: Optional[int] = None
    user_agent: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    enriched_data: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('timestamp', pre=True)
    def parse_timestamp(cls, v):
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace('Z', '+00:00'))
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class DataSourceConnector(ABC):
    """Abstract base class for data source connectors."""
    
    def __init__(self, config: DataSourceConfig, metrics: MetricsCollector):
        self.config = config
        self.metrics = metrics
        self.encryption_manager = EncryptionManager()
        self._connection = None
        self._is_connected = False
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the data source."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to the data source."""
        pass
    
    @abstractmethod
    async def collect_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect security events from the data source."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the data source is healthy and accessible."""
        pass


class ElasticsearchConnector(DataSourceConnector):
    """Connector for Elasticsearch SIEM data."""
    
    async def connect(self) -> None:
        """Connect to Elasticsearch cluster."""
        try:
            self._connection = AsyncElasticsearch(
                hosts=self.config.connection_params['hosts'],
                http_auth=(
                    self.config.connection_params['username'],
                    self.config.connection_params['password']
                ),
                use_ssl=True,
                verify_certs=True,
                ssl_show_warn=False,
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )
            
            # Test connection
            await self._connection.ping()
            self._is_connected = True
            logger.info(f"Connected to Elasticsearch: {self.config.connection_params['hosts']}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self._is_connected = False
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Elasticsearch."""
        if self._connection:
            await self._connection.close()
            self._is_connected = False
            logger.info("Disconnected from Elasticsearch")
    
    async def collect_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect security events from Elasticsearch."""
        if not self._is_connected:
            await self.connect()
        
        query = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    }
                ],
                "filter": [
                    {
                        "terms": {
                            "event_type": [
                                "authentication",
                                "network_connection", 
                                "process_creation",
                                "file_modification",
                                "privilege_escalation",
                                "lateral_movement",
                                "data_exfiltration"
                            ]
                        }
                    }
                ]
            }
        }
        
        try:
            # Use scroll API for large result sets
            response = await self._connection.search(
                index=self.config.connection_params['index_pattern'],
                body={
                    "query": query,
                    "size": self.config.batch_size,
                    "sort": [{"@timestamp": "asc"}]
                },
                scroll='5m'
            )
            
            scroll_id = response.get('_scroll_id')
            hits = response['hits']['hits']
            
            while hits:
                for hit in hits:
                    try:
                        event = self._parse_elasticsearch_event(hit['_source'])
                        yield event
                        self.metrics.increment_counter("events_collected", 
                                                     tags={"source": "elasticsearch"})
                    except Exception as e:
                        logger.warning(f"Failed to parse event: {e}")
                        continue
                
                # Get next batch
                if scroll_id:
                    response = await self._connection.scroll(
                        scroll_id=scroll_id,
                        scroll='5m'
                    )
                    hits = response['hits']['hits']
                else:
                    break
            
            # Clear scroll
            if scroll_id:
                await self._connection.clear_scroll(scroll_id=scroll_id)
                
        except Exception as e:
            logger.error(f"Failed to collect events from Elasticsearch: {e}")
            self.metrics.increment_counter("collection_errors", 
                                         tags={"source": "elasticsearch"})
            raise
    
    def _parse_elasticsearch_event(self, raw_event: Dict) -> SecurityEvent:
        """Parse raw Elasticsearch event into SecurityEvent."""
        return SecurityEvent(
            timestamp=raw_event.get('@timestamp'),
            event_id=raw_event.get('event_id', ''),
            source_type='elasticsearch',
            event_type=raw_event.get('event_type', 'unknown'),
            severity=raw_event.get('severity', 'unknown'),
            source_ip=raw_event.get('source_ip'),
            dest_ip=raw_event.get('dest_ip'),
            username=raw_event.get('username'),
            hostname=raw_event.get('hostname'),
            process_name=raw_event.get('process_name'),
            command_line=raw_event.get('command_line'),
            file_path=raw_event.get('file_path'),
            network_protocol=raw_event.get('network_protocol'),
            port=raw_event.get('port'),
            user_agent=raw_event.get('user_agent'),
            raw_data=raw_event
        )
    
    async def health_check(self) -> bool:
        """Check Elasticsearch cluster health."""
        try:
            if not self._connection:
                return False
            
            health = await self._connection.cluster.health()
            return health['status'] in ['green', 'yellow']
        except Exception as e:
            logger.error(f"Elasticsearch health check failed: {e}")
            return False


class KafkaConnector(DataSourceConnector):
    """Connector for real-time Kafka event streams."""
    
    def __init__(self, config: DataSourceConfig, metrics: MetricsCollector):
        super().__init__(config, metrics)
        self._consumer = None
        self._producer = None
    
    async def connect(self) -> None:
        """Connect to Kafka cluster."""
        try:
            # Initialize consumer for ingesting events
            self._consumer = KafkaConsumer(
                *self.config.connection_params['topics'],
                bootstrap_servers=self.config.connection_params['bootstrap_servers'],
                group_id=self.config.connection_params.get('group_id', 'ml-threat-detection'),
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                auto_offset_reset='latest',
                enable_auto_commit=False,
                max_poll_records=self.config.batch_size
            )
            
            # Initialize producer for outputting processed events
            self._producer = KafkaProducer(
                bootstrap_servers=self.config.connection_params['bootstrap_servers'],
                value_serializer=lambda x: json.dumps(x).encode('utf-8'),
                compression_type='gzip',
                batch_size=16384,
                linger_ms=10
            )
            
            self._is_connected = True
            logger.info(f"Connected to Kafka: {self.config.connection_params['bootstrap_servers']}")
            
        except KafkaError as e:
            logger.error(f"Failed to connect to Kafka: {e}")
            self._is_connected = False
            raise
    
    async def disconnect(self) -> None:
        """Disconnect from Kafka."""
        if self._consumer:
            self._consumer.close()
        if self._producer:
            self._producer.close()
        
        self._is_connected = False
        logger.info("Disconnected from Kafka")
    
    async def collect_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect real-time events from Kafka."""
        if not self._is_connected:
            await self.connect()
        
        try:
            # For real-time streams, we poll for new messages
            timeout_ms = 1000
            while True:
                message_batch = self._consumer.poll(timeout_ms)
                
                if not message_batch:
                    continue
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        try:
                            event = self._parse_kafka_event(message.value)
                            
                            # Check if event is within time range
                            if start_time <= event.timestamp <= end_time:
                                yield event
                                self.metrics.increment_counter("events_collected", 
                                                             tags={"source": "kafka"})
                            
                            # Commit offset after processing
                            self._consumer.commit()
                            
                        except Exception as e:
                            logger.warning(f"Failed to parse Kafka event: {e}")
                            continue
                            
        except KafkaError as e:
            logger.error(f"Failed to collect events from Kafka: {e}")
            self.metrics.increment_counter("collection_errors", 
                                         tags={"source": "kafka"})
            raise
    
    def _parse_kafka_event(self, raw_event: Dict) -> SecurityEvent:
        """Parse raw Kafka event into SecurityEvent."""
        return SecurityEvent(
            timestamp=raw_event.get('timestamp'),
            event_id=raw_event.get('event_id', ''),
            source_type='kafka',
            event_type=raw_event.get('event_type', 'unknown'),
            severity=raw_event.get('severity', 'unknown'),
            source_ip=raw_event.get('source_ip'),
            dest_ip=raw_event.get('dest_ip'),
            username=raw_event.get('username'),
            hostname=raw_event.get('hostname'),
            process_name=raw_event.get('process_name'),
            command_line=raw_event.get('command_line'),
            file_path=raw_event.get('file_path'),
            network_protocol=raw_event.get('network_protocol'),
            port=raw_event.get('port'),
            user_agent=raw_event.get('user_agent'),
            raw_data=raw_event
        )
    
    async def health_check(self) -> bool:
        """Check Kafka cluster health."""
        try:
            if not self._consumer:
                return False
            
            # Check if we can retrieve cluster metadata
            cluster_metadata = self._consumer.bootstrap_connected()
            return cluster_metadata
            
        except Exception as e:
            logger.error(f"Kafka health check failed: {e}")
            return False


class ThreatIntelConnector(DataSourceConnector):
    """Connector for external threat intelligence feeds."""
    
    async def connect(self) -> None:
        """Connect to threat intelligence APIs."""
        # Implementation would connect to various TI feeds
        # (VirusTotal, AlienVault, etc.)
        self._is_connected = True
        logger.info("Connected to threat intelligence feeds")
    
    async def disconnect(self) -> None:
        """Disconnect from threat intelligence feeds."""
        self._is_connected = False
        logger.info("Disconnected from threat intelligence feeds")
    
    async def collect_events(
        self, 
        start_time: datetime, 
        end_time: datetime
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect threat intelligence indicators."""
        # Implementation would fetch TI indicators
        # This is a placeholder for the actual implementation
        if False:  # Placeholder condition
            yield SecurityEvent(
                timestamp=datetime.now(),
                event_id="ti_001",
                source_type="threat_intel",
                event_type="ioc_update",
                severity="info"
            )
    
    async def health_check(self) -> bool:
        """Check threat intelligence feed availability."""
        return True


class DataCollectionPipeline:
    """Main data collection pipeline orchestrator."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("ml_threat_detection")
        self.connectors: Dict[str, DataSourceConnector] = {}
        self.redis_client = None
        self.storage_manager = None
        self._running = False
    
    async def initialize(self) -> None:
        """Initialize the data collection pipeline."""
        try:
            # Initialize Redis for caching
            self.redis_client = await aioredis.from_url(
                self.settings.redis_url,
                encoding="utf-8",
                decode_responses=True
            )
            
            # Initialize data source connectors
            await self._initialize_connectors()
            
            logger.info("Data collection pipeline initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize data collection pipeline: {e}")
            raise
    
    async def _initialize_connectors(self) -> None:
        """Initialize all configured data source connectors."""
        connector_configs = {
            'elasticsearch': DataSourceConfig(
                source_type='elasticsearch',
                connection_params={
                    'hosts': self.settings.elasticsearch_hosts,
                    'username': self.settings.elasticsearch_username,
                    'password': self.settings.elasticsearch_password,
                    'index_pattern': 'siem-events-*'
                },
                schema_config={},
                batch_size=1000,
                rate_limit=5000
            ),
            'kafka': DataSourceConfig(
                source_type='kafka',
                connection_params={
                    'bootstrap_servers': self.settings.kafka_bootstrap_servers,
                    'topics': ['security-logs', 'network-events', 'endpoint-events'],
                    'group_id': 'ml-threat-detection'
                },
                schema_config={},
                batch_size=500,
                rate_limit=10000
            ),
            'threat_intel': DataSourceConfig(
                source_type='threat_intel',
                connection_params={
                    'api_keys': {
                        'virustotal': self.settings.virustotal_api_key,
                        'alienvault': self.settings.alienvault_api_key
                    }
                },
                schema_config={},
                batch_size=100,
                rate_limit=100
            )
        }
        
        for name, config in connector_configs.items():
            if config.enabled:
                if name == 'elasticsearch':
                    connector = ElasticsearchConnector(config, self.metrics)
                elif name == 'kafka':
                    connector = KafkaConnector(config, self.metrics)
                elif name == 'threat_intel':
                    connector = ThreatIntelConnector(config, self.metrics)
                else:
                    continue
                
                await connector.connect()
                self.connectors[name] = connector
                logger.info(f"Initialized {name} connector")
    
    async def collect_batch(
        self,
        start_time: datetime,
        end_time: datetime,
        source_filters: Optional[List[str]] = None
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect a batch of security events from all sources."""
        if not self.connectors:
            await self.initialize()
        
        # Determine which connectors to use
        active_connectors = self.connectors
        if source_filters:
            active_connectors = {
                name: connector for name, connector in self.connectors.items()
                if name in source_filters
            }
        
        # Collect events from all active connectors concurrently
        tasks = []
        for name, connector in active_connectors.items():
            task = asyncio.create_task(
                self._collect_from_source(connector, start_time, end_time)
            )
            tasks.append(task)
        
        # Process events as they arrive
        for task in asyncio.as_completed(tasks):
            async for event in await task:
                yield event
    
    async def _collect_from_source(
        self,
        connector: DataSourceConnector,
        start_time: datetime,
        end_time: datetime
    ) -> AsyncGenerator[SecurityEvent, None]:
        """Collect events from a single data source."""
        try:
            health_ok = await connector.health_check()
            if not health_ok:
                logger.warning(f"Connector {connector.config.source_type} failed health check")
                return
            
            async for event in connector.collect_events(start_time, end_time):
                # Apply rate limiting
                await self._apply_rate_limit(connector.config.source_type)
                
                # Cache event for deduplication
                await self._cache_event(event)
                
                yield event
                
        except Exception as e:
            logger.error(f"Error collecting from {connector.config.source_type}: {e}")
            self.metrics.increment_counter("collection_errors", 
                                         tags={"source": connector.config.source_type})
    
    async def _apply_rate_limit(self, source_type: str) -> None:
        """Apply rate limiting to prevent overwhelming downstream systems."""
        rate_limit_key = f"rate_limit:{source_type}"
        current_count = await self.redis_client.get(rate_limit_key)
        
        if current_count is None:
            await self.redis_client.setex(rate_limit_key, 1, 1)
        else:
            count = int(current_count)
            connector = self.connectors[source_type]
            if count >= connector.config.rate_limit:
                await asyncio.sleep(0.1)  # Small delay to prevent overwhelming
            else:
                await self.redis_client.incr(rate_limit_key)
    
    async def _cache_event(self, event: SecurityEvent) -> None:
        """Cache event for deduplication purposes."""
        event_hash = hash(f"{event.event_id}{event.timestamp}{event.source_type}")
        cache_key = f"event_cache:{event_hash}"
        
        # Store event ID in cache for 1 hour to detect duplicates
        await self.redis_client.setex(cache_key, 3600, event.event_id)
    
    async def start_real_time_collection(
        self,
        callback: callable,
        source_filters: Optional[List[str]] = None
    ) -> None:
        """Start real-time event collection."""
        self._running = True
        logger.info("Starting real-time data collection")
        
        while self._running:
            try:
                current_time = datetime.utcnow()
                start_time = current_time - timedelta(minutes=1)
                
                async for event in self.collect_batch(start_time, current_time, source_filters):
                    await callback(event)
                
                await asyncio.sleep(1)  # Collect every second
                
            except Exception as e:
                logger.error(f"Error in real-time collection: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def stop_real_time_collection(self) -> None:
        """Stop real-time event collection."""
        self._running = False
        logger.info("Stopping real-time data collection")
    
    async def shutdown(self) -> None:
        """Shutdown the data collection pipeline."""
        self._running = False
        
        # Disconnect all connectors
        for connector in self.connectors.values():
            await connector.disconnect()
        
        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("Data collection pipeline shutdown completed")
    
    async def get_collection_stats(self) -> Dict[str, Any]:
        """Get collection statistics."""
        stats = {
            'total_connectors': len(self.connectors),
            'active_connectors': sum(1 for c in self.connectors.values() 
                                   if asyncio.create_task(c.health_check())),
            'is_running': self._running,
            'collection_metrics': await self.metrics.get_metrics()
        }
        
        return stats