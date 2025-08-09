"""
SOC Alert Manager - Central Alert Processing Engine

Handles the complete alert lifecycle from ingestion to storage.
Integrates with existing monitoring infrastructure in monitoring/ directory.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass, asdict
from enum import Enum
import json
import hashlib
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
from prometheus_client import Counter, Histogram, Gauge
import structlog

from .connectors.base_connector import BaseConnector
from .normalizer import AlertNormalizer
from .storage import ElasticsearchStorage
from .enrichment import AlertEnricher
from .deduplication import DeduplicationEngine

# Prometheus metrics
ALERTS_INGESTED = Counter('soc_alerts_ingested_total', 'Total alerts ingested', ['source', 'severity'])
ALERTS_PROCESSED = Counter('soc_alerts_processed_total', 'Total alerts processed', ['status'])
ALERT_PROCESSING_TIME = Histogram('soc_alert_processing_seconds', 'Alert processing time')
ALERT_QUEUE_SIZE = Gauge('soc_alert_queue_size', 'Current alert queue size')

logger = structlog.get_logger(__name__)

class AlertPriority(Enum):
    """Alert priority levels for processing queue"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class AlertMetadata:
    """Metadata for alert processing tracking"""
    ingestion_time: datetime
    source: str
    processing_stage: str
    enrichment_count: int = 0
    deduplication_hash: str = ""
    priority: AlertPriority = AlertPriority.MEDIUM

class AlertManager:
    """
    Central alert processing engine for SOC automation platform.
    
    Responsibilities:
    - Coordinate alert ingestion from multiple sources
    - Manage alert processing pipeline
    - Handle duplicate detection and filtering  
    - Route alerts to appropriate handlers
    - Provide real-time alert streaming
    - Integrate with monitoring and metrics collection
    """
    
    def __init__(
        self,
        elasticsearch_config: Dict[str, Any],
        redis_config: Dict[str, Any],
        processing_config: Dict[str, Any] = None
    ):
        self.elasticsearch_config = elasticsearch_config
        self.redis_config = redis_config
        self.processing_config = processing_config or {}
        
        # Initialize components
        self.storage = ElasticsearchStorage(elasticsearch_config)
        self.normalizer = AlertNormalizer()
        self.enricher = AlertEnricher()
        self.deduplicator = DeduplicationEngine()
        
        # Processing queues and state
        self.connectors: Dict[str, BaseConnector] = {}
        self.processing_queue: asyncio.Queue = None
        self.redis_client: redis.Redis = None
        self.running = False
        self.worker_tasks: List[asyncio.Task] = []
        
        # Configuration
        self.max_workers = processing_config.get('max_workers', 10)
        self.batch_size = processing_config.get('batch_size', 100)
        self.max_queue_size = processing_config.get('max_queue_size', 10000)
        self.deduplication_window = processing_config.get('deduplication_window', 3600)  # 1 hour
        
        logger.info("AlertManager initialized", 
                   max_workers=self.max_workers, 
                   batch_size=self.batch_size)
    
    async def initialize(self):
        """Initialize async components and connections"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                db=self.redis_config.get('db', 0),
                decode_responses=True
            )
            await self.redis_client.ping()
            
            # Initialize storage
            await self.storage.initialize()
            
            # Initialize processing queue
            self.processing_queue = asyncio.Queue(maxsize=self.max_queue_size)
            
            # Initialize deduplication engine
            await self.deduplicator.initialize(self.redis_client, self.deduplication_window)
            
            logger.info("AlertManager components initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize AlertManager", error=str(e))
            raise
    
    async def register_connector(self, name: str, connector: BaseConnector):
        """Register an alert source connector"""
        if not isinstance(connector, BaseConnector):
            raise ValueError(f"Connector {name} must inherit from BaseConnector")
        
        self.connectors[name] = connector
        logger.info("Connector registered", name=name, type=type(connector).__name__)
    
    async def start(self):
        """Start the alert processing engine"""
        if self.running:
            logger.warning("AlertManager is already running")
            return
        
        self.running = True
        
        # Start worker tasks
        for i in range(self.max_workers):
            task = asyncio.create_task(self._worker(f"worker-{i}"))
            self.worker_tasks.append(task)
        
        # Start connector tasks
        for name, connector in self.connectors.items():
            task = asyncio.create_task(self._run_connector(name, connector))
            self.worker_tasks.append(task)
        
        # Start queue size monitoring
        monitoring_task = asyncio.create_task(self._monitor_queue_size())
        self.worker_tasks.append(monitoring_task)
        
        logger.info("AlertManager started", workers=self.max_workers, connectors=len(self.connectors))
    
    async def stop(self):
        """Stop the alert processing engine"""
        if not self.running:
            return
        
        self.running = False
        
        # Stop all connectors
        for connector in self.connectors.values():
            await connector.stop()
        
        # Cancel all worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        self.worker_tasks.clear()
        
        # Close connections
        if self.redis_client:
            await self.redis_client.close()
        
        await self.storage.close()
        
        logger.info("AlertManager stopped")
    
    async def ingest_alert(self, raw_alert: Dict[str, Any], source: str) -> Optional[str]:
        """
        Ingest a single alert into the processing pipeline
        
        Args:
            raw_alert: Raw alert data from source
            source: Source identifier
            
        Returns:
            Alert ID if successfully queued, None if filtered/rejected
        """
        try:
            # Create metadata
            metadata = AlertMetadata(
                ingestion_time=datetime.now(timezone.utc),
                source=source,
                processing_stage="ingestion"
            )
            
            # Add to processing queue
            alert_item = {
                'raw_alert': raw_alert,
                'metadata': metadata,
                'id': self._generate_alert_id(raw_alert, source)
            }
            
            await self.processing_queue.put(alert_item)
            
            # Update metrics
            severity = raw_alert.get('severity', 'unknown')
            ALERTS_INGESTED.labels(source=source, severity=severity).inc()
            
            logger.debug("Alert queued for processing", 
                        alert_id=alert_item['id'], 
                        source=source)
            
            return alert_item['id']
            
        except asyncio.QueueFull:
            logger.error("Alert processing queue is full, dropping alert", source=source)
            ALERTS_PROCESSED.labels(status="dropped_queue_full").inc()
            return None
        except Exception as e:
            logger.error("Failed to ingest alert", source=source, error=str(e))
            ALERTS_PROCESSED.labels(status="ingestion_error").inc()
            return None
    
    async def _worker(self, worker_id: str):
        """Alert processing worker"""
        logger.info("Worker started", worker_id=worker_id)
        
        while self.running:
            try:
                # Get alert from queue with timeout
                alert_item = await asyncio.wait_for(
                    self.processing_queue.get(),
                    timeout=1.0
                )
                
                await self._process_alert(alert_item, worker_id)
                
            except asyncio.TimeoutError:
                continue  # Normal timeout, check if still running
            except Exception as e:
                logger.error("Worker error", worker_id=worker_id, error=str(e))
    
    async def _process_alert(self, alert_item: Dict[str, Any], worker_id: str):
        """Process a single alert through the complete pipeline"""
        start_time = asyncio.get_event_loop().time()
        alert_id = alert_item['id']
        metadata = alert_item['metadata']
        
        try:
            with ALERT_PROCESSING_TIME.time():
                # Stage 1: Normalization
                metadata.processing_stage = "normalization"
                normalized_alert = await self.normalizer.normalize(
                    alert_item['raw_alert'],
                    metadata.source
                )
                
                if not normalized_alert:
                    logger.warning("Alert normalization failed", alert_id=alert_id)
                    ALERTS_PROCESSED.labels(status="normalization_failed").inc()
                    return
                
                # Stage 2: Deduplication
                metadata.processing_stage = "deduplication"
                dedup_hash = self._calculate_dedup_hash(normalized_alert)
                metadata.deduplication_hash = dedup_hash
                
                if await self.deduplicator.is_duplicate(dedup_hash):
                    logger.debug("Duplicate alert filtered", alert_id=alert_id, hash=dedup_hash[:8])
                    ALERTS_PROCESSED.labels(status="duplicate_filtered").inc()
                    return
                
                # Mark as seen for deduplication
                await self.deduplicator.mark_seen(dedup_hash)
                
                # Stage 3: Enrichment
                metadata.processing_stage = "enrichment"
                enriched_alert = await self.enricher.enrich(normalized_alert)
                metadata.enrichment_count = len(enriched_alert.get('enrichments', {}))
                
                # Stage 4: Priority calculation
                metadata.processing_stage = "prioritization"
                priority = self._calculate_priority(enriched_alert)
                metadata.priority = priority
                
                # Stage 5: Storage
                metadata.processing_stage = "storage"
                final_alert = {
                    **enriched_alert,
                    'metadata': asdict(metadata),
                    'processing_time_ms': int((asyncio.get_event_loop().time() - start_time) * 1000)
                }
                
                await self.storage.store_alert(final_alert)
                
                # Stage 6: Real-time streaming
                await self._stream_alert(final_alert)
                
                ALERTS_PROCESSED.labels(status="success").inc()
                logger.info("Alert processed successfully",
                           alert_id=alert_id,
                           source=metadata.source,
                           priority=priority.name,
                           enrichments=metadata.enrichment_count,
                           worker_id=worker_id)
                
        except Exception as e:
            logger.error("Alert processing failed",
                        alert_id=alert_id,
                        stage=metadata.processing_stage,
                        worker_id=worker_id,
                        error=str(e))
            ALERTS_PROCESSED.labels(status="processing_error").inc()
    
    async def _run_connector(self, name: str, connector: BaseConnector):
        """Run a connector and feed alerts to the processing queue"""
        logger.info("Starting connector", name=name)
        
        try:
            async for alert in connector.get_alerts():
                if not self.running:
                    break
                
                await self.ingest_alert(alert, name)
                
        except Exception as e:
            logger.error("Connector error", name=name, error=str(e))
        
        logger.info("Connector stopped", name=name)
    
    async def _stream_alert(self, alert: Dict[str, Any]):
        """Stream alert to real-time subscribers"""
        try:
            # Publish to Redis streams for real-time consumers
            stream_key = f"alerts:{alert.get('category', 'general')}"
            await self.redis_client.xadd(stream_key, alert)
            
            # Publish to general alert stream
            await self.redis_client.xadd("alerts:all", alert)
            
        except Exception as e:
            logger.error("Failed to stream alert", error=str(e))
    
    async def _monitor_queue_size(self):
        """Monitor and report queue size metrics"""
        while self.running:
            try:
                queue_size = self.processing_queue.qsize()
                ALERT_QUEUE_SIZE.set(queue_size)
                
                if queue_size > self.max_queue_size * 0.8:
                    logger.warning("Alert queue nearly full", 
                                 size=queue_size, 
                                 max_size=self.max_queue_size)
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error("Queue monitoring error", error=str(e))
    
    def _generate_alert_id(self, alert: Dict[str, Any], source: str) -> str:
        """Generate unique alert ID"""
        timestamp = datetime.now(timezone.utc).isoformat()
        content = json.dumps(alert, sort_keys=True)
        hash_input = f"{source}:{timestamp}:{content}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _calculate_dedup_hash(self, alert: Dict[str, Any]) -> str:
        """Calculate hash for deduplication"""
        # Use key fields for deduplication
        dedup_fields = {
            'source_ip': alert.get('source_ip'),
            'destination_ip': alert.get('destination_ip'),
            'alert_type': alert.get('alert_type'),
            'signature': alert.get('signature'),
            'rule_id': alert.get('rule_id')
        }
        
        # Remove None values
        dedup_fields = {k: v for k, v in dedup_fields.items() if v is not None}
        
        content = json.dumps(dedup_fields, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _calculate_priority(self, alert: Dict[str, Any]) -> AlertPriority:
        """Calculate alert processing priority based on severity and context"""
        severity = alert.get('severity', '').lower()
        category = alert.get('category', '').lower()
        
        # Critical priority conditions
        if (severity in ['critical', 'high'] and 
            any(keyword in category for keyword in ['malware', 'ransomware', 'data_exfiltration'])):
            return AlertPriority.CRITICAL
        
        # High priority conditions
        if severity in ['critical', 'high'] or 'privilege_escalation' in category:
            return AlertPriority.HIGH
        
        # Medium priority (default)
        if severity in ['medium', 'warning']:
            return AlertPriority.MEDIUM
        
        # Low priority
        return AlertPriority.LOW
    
    async def get_alert_stream(self, category: str = "all") -> AsyncGenerator[Dict[str, Any], None]:
        """Get real-time alert stream for a specific category"""
        stream_key = f"alerts:{category}"
        last_id = "0"
        
        while self.running:
            try:
                messages = await self.redis_client.xread({stream_key: last_id}, block=1000)
                
                for stream, msgs in messages:
                    for msg_id, fields in msgs:
                        last_id = msg_id
                        yield fields
                        
            except Exception as e:
                logger.error("Stream reading error", category=category, error=str(e))
                await asyncio.sleep(1)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            'queue_size': self.processing_queue.qsize() if self.processing_queue else 0,
            'connectors': len(self.connectors),
            'workers': len(self.worker_tasks),
            'running': self.running,
            'config': {
                'max_workers': self.max_workers,
                'batch_size': self.batch_size,
                'max_queue_size': self.max_queue_size,
                'deduplication_window': self.deduplication_window
            }
        }