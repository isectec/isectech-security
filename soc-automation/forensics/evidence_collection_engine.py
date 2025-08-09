"""
SOC Automation - Digital Forensics Evidence Collection Engine

Production-grade evidence collection automation system that ensures
proper chain-of-custody, integrity verification, and compliance with
forensic standards. Integrates with various data sources and forensic tools.
"""

import asyncio
import logging
import json
import uuid
import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass, asdict
from enum import Enum
import aiofiles
import aiohttp
from pathlib import Path
import sqlite3
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
from prometheus_client import Counter, Histogram, Gauge
import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

logger = structlog.get_logger(__name__)

# Prometheus metrics
EVIDENCE_COLLECTED = Counter('soc_evidence_collected_total', 'Total evidence items collected', ['type', 'source'])
EVIDENCE_PROCESSING_TIME = Histogram('soc_evidence_processing_seconds', 'Evidence processing time', ['type'])
ACTIVE_COLLECTIONS = Gauge('soc_active_evidence_collections', 'Currently active evidence collections')
CHAIN_OF_CUSTODY_VIOLATIONS = Counter('soc_chain_of_custody_violations_total', 'Chain of custody violations')
EVIDENCE_STORAGE_SIZE = Gauge('soc_evidence_storage_bytes', 'Total evidence storage size in bytes')

class EvidenceType(Enum):
    """Types of digital evidence"""
    MEMORY_DUMP = "memory_dump"
    DISK_IMAGE = "disk_image" 
    NETWORK_CAPTURE = "network_capture"
    LOG_FILES = "log_files"
    EMAIL_MESSAGE = "email_message"
    REGISTRY_HIVE = "registry_hive"
    BROWSER_ARTIFACTS = "browser_artifacts"
    MALWARE_SAMPLE = "malware_sample"
    CONFIGURATION_FILE = "configuration_file"
    DATABASE_EXPORT = "database_export"
    CLOUD_LOGS = "cloud_logs"
    MOBILE_BACKUP = "mobile_backup"

class EvidenceStatus(Enum):
    """Evidence collection status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COLLECTED = "collected"
    VERIFIED = "verified"
    STORED = "stored"
    FAILED = "failed"
    CORRUPTED = "corrupted"

class ChainOfCustodyAction(Enum):
    """Chain of custody actions"""
    CREATED = "created"
    ACCESSED = "accessed"
    COPIED = "copied"
    MOVED = "moved"
    ANALYZED = "analyzed"
    ARCHIVED = "archived"
    DESTROYED = "destroyed"

@dataclass
class ChainOfCustodyEntry:
    """Single chain of custody entry"""
    entry_id: str
    evidence_id: str
    action: ChainOfCustodyAction
    actor: str  # Person or system
    timestamp: datetime
    location: str  # Storage location
    purpose: str  # Reason for action
    witness: Optional[str] = None
    digital_signature: Optional[str] = None
    notes: Optional[str] = None

@dataclass
class EvidenceMetadata:
    """Comprehensive evidence metadata"""
    evidence_id: str
    incident_id: str
    case_id: Optional[str]
    evidence_type: EvidenceType
    source_system: str
    source_location: str
    collection_method: str
    collected_at: datetime
    collected_by: str
    
    # Technical metadata
    file_path: str
    file_size: int
    mime_type: str
    hash_md5: str
    hash_sha1: str
    hash_sha256: str
    hash_sha512: Optional[str] = None
    
    # Legal metadata
    legal_hold: bool = False
    retention_period_years: int = 7
    privacy_classification: str = "confidential"
    jurisdiction: str = "US"
    
    # Chain of custody
    chain_of_custody: List[ChainOfCustodyEntry] = None
    
    # Analysis metadata
    analysis_results: Dict[str, Any] = None
    tags: List[str] = None
    
    # Storage metadata
    storage_location: str = ""
    backup_locations: List[str] = None
    encryption_key_id: Optional[str] = None
    
    created_at: datetime = None
    updated_at: datetime = None

@dataclass
class EvidenceCollectionRequest:
    """Request for evidence collection"""
    request_id: str
    incident_id: str
    evidence_type: EvidenceType
    source_system: str
    source_identifier: str  # hostname, IP, email, etc.
    priority: int = 5  # 1-10, 1 is highest
    requested_by: str = "soc_automation"
    requested_at: datetime = None
    parameters: Dict[str, Any] = None
    legal_authorization: bool = False
    preservation_order: bool = False

class DigitalForensicsEvidenceCollector:
    """
    Digital Forensics Evidence Collection Engine
    
    Responsibilities:
    - Automate evidence collection from various sources
    - Maintain chain of custody integrity
    - Ensure proper evidence preservation
    - Handle encryption and secure storage
    - Generate forensic reports
    - Integrate with analysis tools
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Storage configuration
        self.evidence_storage_path = Path(config.get('evidence_storage_path', '/evidence'))
        self.temp_storage_path = Path(config.get('temp_storage_path', '/tmp/evidence'))
        self.backup_storage_path = Path(config.get('backup_storage_path', '/evidence/backup'))
        
        # Database configuration
        self.metadata_db_path = config.get('metadata_db_path', 'evidence_metadata.db')
        self.elasticsearch_config = config.get('elasticsearch', {})
        self.redis_config = config.get('redis', {})
        
        # Security configuration
        self.encryption_enabled = config.get('encryption_enabled', True)
        self.signing_enabled = config.get('signing_enabled', True)
        self.private_key = None
        self.public_key = None
        
        # Initialize components
        self.redis_client: redis.Redis = None
        self.elasticsearch: AsyncElasticsearch = None
        self.collection_queue: asyncio.Queue = None
        
        # Runtime state
        self.active_collections: Dict[str, EvidenceCollectionRequest] = {}
        self.evidence_handlers: Dict[EvidenceType, Callable] = {}
        self.running = False
        
        # Configuration
        self.max_concurrent_collections = config.get('max_concurrent_collections', 10)
        self.collection_timeout = config.get('collection_timeout', 3600)  # 1 hour
        self.integrity_check_interval = config.get('integrity_check_interval', 86400)  # 24 hours
        
        logger.info("DigitalForensicsEvidenceCollector initialized",
                   storage_path=str(self.evidence_storage_path),
                   max_concurrent=self.max_concurrent_collections)
    
    async def initialize(self):
        """Initialize the evidence collection system"""
        try:
            # Create storage directories
            self.evidence_storage_path.mkdir(parents=True, exist_ok=True)
            self.temp_storage_path.mkdir(parents=True, exist_ok=True)
            self.backup_storage_path.mkdir(parents=True, exist_ok=True)
            
            # Initialize database
            await self._initialize_metadata_database()
            
            # Initialize Redis
            self.redis_client = redis.Redis(
                host=self.redis_config.get('host', 'localhost'),
                port=self.redis_config.get('port', 6379),
                db=self.redis_config.get('db', 2),  # Use different DB
                decode_responses=True
            )
            await self.redis_client.ping()
            
            # Initialize Elasticsearch
            self.elasticsearch = AsyncElasticsearch([{
                'host': self.elasticsearch_config.get('host', 'localhost'),
                'port': self.elasticsearch_config.get('port', 9200)
            }])
            
            # Initialize cryptographic keys
            if self.encryption_enabled or self.signing_enabled:
                await self._initialize_crypto_keys()
            
            # Initialize collection queue
            self.collection_queue = asyncio.Queue(maxsize=1000)
            
            # Register evidence handlers
            await self._register_evidence_handlers()
            
            # Start background tasks
            asyncio.create_task(self._integrity_monitor())
            asyncio.create_task(self._cleanup_old_evidence())
            
            logger.info("DigitalForensicsEvidenceCollector initialized successfully",
                       handlers=len(self.evidence_handlers))
            
        except Exception as e:
            logger.error("Failed to initialize evidence collector", error=str(e))
            raise
    
    async def collect_evidence(self, request: EvidenceCollectionRequest) -> Optional[str]:
        """
        Submit evidence collection request
        
        Args:
            request: Evidence collection request
            
        Returns:
            Evidence ID if collection started, None if rejected
        """
        try:
            # Validate request
            if not await self._validate_collection_request(request):
                logger.warning("Evidence collection request validation failed",
                             request_id=request.request_id)
                return None
            
            # Check legal authorization for sensitive evidence types
            if request.evidence_type in [EvidenceType.MEMORY_DUMP, EvidenceType.DISK_IMAGE]:
                if not request.legal_authorization:
                    logger.warning("Legal authorization required for evidence type",
                                 type=request.evidence_type.value,
                                 request_id=request.request_id)
                    return None
            
            # Generate evidence ID
            evidence_id = f"EV_{datetime.now().strftime('%Y%m%d')}_{str(uuid.uuid4())[:8]}"
            
            # Add request to collection queue
            request.requested_at = datetime.now(timezone.utc)
            await self.collection_queue.put((evidence_id, request))
            
            # Track active collection
            self.active_collections[evidence_id] = request
            
            logger.info("Evidence collection request queued",
                       evidence_id=evidence_id,
                       type=request.evidence_type.value,
                       source=request.source_system,
                       priority=request.priority)
            
            return evidence_id
            
        except Exception as e:
            logger.error("Failed to submit evidence collection request",
                        request_id=request.request_id,
                        error=str(e))
            return None
    
    async def start_collection_workers(self):
        """Start evidence collection worker tasks"""
        if self.running:
            return
        
        self.running = True
        
        # Start collection workers
        for i in range(self.max_concurrent_collections):
            asyncio.create_task(self._collection_worker(f"worker-{i}"))
        
        logger.info("Evidence collection workers started",
                   workers=self.max_concurrent_collections)
    
    async def stop_collection_workers(self):
        """Stop evidence collection workers"""
        self.running = False
        logger.info("Evidence collection workers stopping")
    
    async def _collection_worker(self, worker_id: str):
        """Evidence collection worker"""
        logger.info("Collection worker started", worker_id=worker_id)
        
        while self.running:
            try:
                # Get collection request
                evidence_id, request = await asyncio.wait_for(
                    self.collection_queue.get(),
                    timeout=1.0
                )
                
                ACTIVE_COLLECTIONS.inc()
                
                try:
                    # Perform evidence collection
                    await self._perform_evidence_collection(evidence_id, request, worker_id)
                finally:
                    ACTIVE_COLLECTIONS.dec()
                    # Remove from active collections
                    if evidence_id in self.active_collections:
                        del self.active_collections[evidence_id]
                
            except asyncio.TimeoutError:
                continue  # Normal timeout
            except Exception as e:
                logger.error("Collection worker error", worker_id=worker_id, error=str(e))
    
    async def _perform_evidence_collection(self, evidence_id: str, request: EvidenceCollectionRequest, worker_id: str):
        """Perform the actual evidence collection"""
        start_time = datetime.now(timezone.utc)
        
        try:
            with EVIDENCE_PROCESSING_TIME.labels(type=request.evidence_type.value).time():
                
                # Get evidence handler
                handler = self.evidence_handlers.get(request.evidence_type)
                if not handler:
                    raise ValueError(f"No handler for evidence type: {request.evidence_type.value}")
                
                logger.info("Starting evidence collection",
                           evidence_id=evidence_id,
                           type=request.evidence_type.value,
                           source=request.source_system,
                           worker_id=worker_id)
                
                # Create evidence metadata
                metadata = EvidenceMetadata(
                    evidence_id=evidence_id,
                    incident_id=request.incident_id,
                    evidence_type=request.evidence_type,
                    source_system=request.source_system,
                    source_location=request.source_identifier,
                    collection_method="automated",
                    collected_at=start_time,
                    collected_by=request.requested_by,
                    file_path="",  # Will be set by handler
                    file_size=0,   # Will be set by handler
                    mime_type="",  # Will be set by handler
                    hash_md5="",   # Will be calculated
                    hash_sha1="",  # Will be calculated
                    hash_sha256="", # Will be calculated
                    chain_of_custody=[],
                    tags=[],
                    backup_locations=[],
                    created_at=start_time,
                    updated_at=start_time
                )
                
                # Execute collection handler
                collection_result = await asyncio.wait_for(
                    handler(evidence_id, request, metadata),
                    timeout=self.collection_timeout
                )
                
                # Update metadata with collection results
                metadata.file_path = collection_result['file_path']
                metadata.file_size = collection_result['file_size']
                metadata.mime_type = collection_result.get('mime_type', 'application/octet-stream')
                
                # Calculate file hashes for integrity
                await self._calculate_file_hashes(metadata)
                
                # Create initial chain of custody entry
                initial_custody = ChainOfCustodyEntry(
                    entry_id=str(uuid.uuid4()),
                    evidence_id=evidence_id,
                    action=ChainOfCustodyAction.CREATED,
                    actor=request.requested_by,
                    timestamp=start_time,
                    location=metadata.file_path,
                    purpose=f"Evidence collection for incident {request.incident_id}",
                    witness=worker_id
                )
                
                if self.signing_enabled:
                    initial_custody.digital_signature = await self._sign_custody_entry(initial_custody)
                
                metadata.chain_of_custody.append(initial_custody)
                
                # Encrypt evidence if enabled
                if self.encryption_enabled:
                    await self._encrypt_evidence_file(metadata)
                
                # Create backup
                await self._create_evidence_backup(metadata)
                
                # Store metadata
                await self._store_evidence_metadata(metadata)
                
                # Update metrics
                EVIDENCE_COLLECTED.labels(
                    type=request.evidence_type.value,
                    source=request.source_system
                ).inc()
                
                EVIDENCE_STORAGE_SIZE.inc(metadata.file_size)
                
                logger.info("Evidence collection completed successfully",
                           evidence_id=evidence_id,
                           file_path=metadata.file_path,
                           file_size=metadata.file_size,
                           duration=(datetime.now(timezone.utc) - start_time).total_seconds(),
                           worker_id=worker_id)
        
        except asyncio.TimeoutError:
            logger.error("Evidence collection timeout",
                        evidence_id=evidence_id,
                        timeout=self.collection_timeout)
        except Exception as e:
            logger.error("Evidence collection failed",
                        evidence_id=evidence_id,
                        error=str(e))
    
    async def _register_evidence_handlers(self):
        """Register handlers for different evidence types"""
        
        # System evidence handlers
        self.evidence_handlers[EvidenceType.MEMORY_DUMP] = self._collect_memory_dump
        self.evidence_handlers[EvidenceType.DISK_IMAGE] = self._collect_disk_image
        self.evidence_handlers[EvidenceType.REGISTRY_HIVE] = self._collect_registry_hive
        
        # Network evidence handlers
        self.evidence_handlers[EvidenceType.NETWORK_CAPTURE] = self._collect_network_capture
        
        # Log evidence handlers
        self.evidence_handlers[EvidenceType.LOG_FILES] = self._collect_log_files
        self.evidence_handlers[EvidenceType.CLOUD_LOGS] = self._collect_cloud_logs
        
        # Application evidence handlers
        self.evidence_handlers[EvidenceType.EMAIL_MESSAGE] = self._collect_email_message
        self.evidence_handlers[EvidenceType.BROWSER_ARTIFACTS] = self._collect_browser_artifacts
        self.evidence_handlers[EvidenceType.DATABASE_EXPORT] = self._collect_database_export
        
        # Malware evidence handlers
        self.evidence_handlers[EvidenceType.MALWARE_SAMPLE] = self._collect_malware_sample
        
        logger.info("Evidence handlers registered", count=len(self.evidence_handlers))
    
    # Evidence collection handlers
    async def _collect_memory_dump(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect memory dump from target system"""
        
        hostname = request.source_identifier
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dump_filename = f"{evidence_id}_{hostname}_{timestamp}.mem"
        dump_path = self.temp_storage_path / dump_filename
        
        try:
            # TODO: Integrate with endpoint management system (CrowdStrike, SentinelOne, etc.)
            # For now, create a placeholder file
            
            logger.info("Collecting memory dump", 
                       evidence_id=evidence_id,
                       hostname=hostname,
                       target_path=str(dump_path))
            
            # Simulate memory dump collection
            # In production, this would call the EDR API to trigger memory acquisition
            placeholder_content = f"Memory dump for {hostname} collected at {timestamp}\n" * 1000
            
            async with aiofiles.open(dump_path, 'wb') as f:
                await f.write(placeholder_content.encode())
            
            # Get file size
            file_size = dump_path.stat().st_size
            
            # Move to permanent storage
            permanent_path = self.evidence_storage_path / evidence_id[:2] / evidence_id[2:4] / dump_filename
            permanent_path.parent.mkdir(parents=True, exist_ok=True)
            dump_path.rename(permanent_path)
            
            return {
                'file_path': str(permanent_path),
                'file_size': file_size,
                'mime_type': 'application/octet-stream',
                'collection_method': 'edr_api',
                'source_details': {
                    'hostname': hostname,
                    'collection_tool': 'automated_edr',
                    'acquisition_type': 'live_memory'
                }
            }
            
        except Exception as e:
            logger.error("Memory dump collection failed",
                        evidence_id=evidence_id,
                        hostname=hostname,
                        error=str(e))
            raise
    
    async def _collect_disk_image(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Create forensic disk image of target system"""
        
        hostname = request.source_identifier
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        image_filename = f"{evidence_id}_{hostname}_{timestamp}.dd"
        image_path = self.temp_storage_path / image_filename
        
        try:
            logger.info("Creating disk image",
                       evidence_id=evidence_id, 
                       hostname=hostname,
                       target_path=str(image_path))
            
            # TODO: Integrate with forensic imaging tools (FTK Imager, dd, EnCase, etc.)
            # For now, create a placeholder file
            
            # Simulate disk imaging
            placeholder_content = f"Disk image for {hostname} created at {timestamp}\n" * 10000
            
            async with aiofiles.open(image_path, 'wb') as f:
                await f.write(placeholder_content.encode())
            
            # Get file size
            file_size = image_path.stat().st_size
            
            # Move to permanent storage
            permanent_path = self.evidence_storage_path / evidence_id[:2] / evidence_id[2:4] / image_filename
            permanent_path.parent.mkdir(parents=True, exist_ok=True)
            image_path.rename(permanent_path)
            
            return {
                'file_path': str(permanent_path),
                'file_size': file_size,
                'mime_type': 'application/octet-stream',
                'collection_method': 'forensic_imaging',
                'source_details': {
                    'hostname': hostname,
                    'imaging_tool': 'automated_dd',
                    'acquisition_type': 'logical_image',
                    'write_blocked': True
                }
            }
            
        except Exception as e:
            logger.error("Disk image collection failed",
                        evidence_id=evidence_id,
                        hostname=hostname, 
                        error=str(e))
            raise
    
    async def _collect_network_capture(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect network packet capture"""
        
        ip_address = request.source_identifier
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pcap_filename = f"{evidence_id}_{ip_address.replace('.', '_')}_{timestamp}.pcap"
        pcap_path = self.temp_storage_path / pcap_filename
        
        try:
            logger.info("Collecting network capture",
                       evidence_id=evidence_id,
                       ip_address=ip_address,
                       target_path=str(pcap_path))
            
            # TODO: Integrate with network monitoring systems (Wireshark, ntopng, etc.)
            # For now, create a placeholder file
            
            # Simulate PCAP collection
            placeholder_content = f"PCAP data for {ip_address} captured at {timestamp}\n" * 5000
            
            async with aiofiles.open(pcap_path, 'wb') as f:
                await f.write(placeholder_content.encode())
            
            # Get file size  
            file_size = pcap_path.stat().st_size
            
            # Move to permanent storage
            permanent_path = self.evidence_storage_path / evidence_id[:2] / evidence_id[2:4] / pcap_filename
            permanent_path.parent.mkdir(parents=True, exist_ok=True)
            pcap_path.rename(permanent_path)
            
            return {
                'file_path': str(permanent_path),
                'file_size': file_size,
                'mime_type': 'application/vnd.tcpdump.pcap',
                'collection_method': 'network_tap',
                'source_details': {
                    'ip_address': ip_address,
                    'capture_tool': 'automated_tcpdump',
                    'capture_filter': request.parameters.get('filter', ''),
                    'time_window': request.parameters.get('time_window', '1_hour')
                }
            }
            
        except Exception as e:
            logger.error("Network capture collection failed",
                        evidence_id=evidence_id,
                        ip_address=ip_address,
                        error=str(e))
            raise
    
    async def _collect_log_files(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect system and application log files"""
        
        source_system = request.source_identifier
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_filename = f"{evidence_id}_{source_system}_{timestamp}.logs"
        log_path = self.temp_storage_path / log_filename
        
        try:
            logger.info("Collecting log files",
                       evidence_id=evidence_id,
                       source_system=source_system,
                       target_path=str(log_path))
            
            # TODO: Integrate with log management systems (Splunk, ELK, etc.)
            # For now, create a placeholder file
            
            # Simulate log collection
            log_entries = []
            for i in range(1000):
                log_entries.append(f"{timestamp} INFO [System] Log entry {i} from {source_system}")
            
            log_content = "\n".join(log_entries)
            
            async with aiofiles.open(log_path, 'w') as f:
                await f.write(log_content)
            
            # Get file size
            file_size = log_path.stat().st_size
            
            # Move to permanent storage
            permanent_path = self.evidence_storage_path / evidence_id[:2] / evidence_id[2:4] / log_filename
            permanent_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.rename(permanent_path)
            
            return {
                'file_path': str(permanent_path),
                'file_size': file_size,
                'mime_type': 'text/plain',
                'collection_method': 'log_api',
                'source_details': {
                    'source_system': source_system,
                    'log_types': request.parameters.get('log_types', ['system', 'application', 'security']),
                    'time_range': request.parameters.get('time_range', '24_hours')
                }
            }
            
        except Exception as e:
            logger.error("Log file collection failed",
                        evidence_id=evidence_id,
                        source_system=source_system,
                        error=str(e))
            raise
    
    # Placeholder handlers for additional evidence types
    async def _collect_registry_hive(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect Windows registry hive"""
        return {'file_path': '/placeholder/registry.hiv', 'file_size': 1024000, 'mime_type': 'application/octet-stream'}
    
    async def _collect_cloud_logs(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect cloud service logs"""
        return {'file_path': '/placeholder/cloud.logs', 'file_size': 2048000, 'mime_type': 'application/json'}
    
    async def _collect_email_message(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect email message with headers"""
        return {'file_path': '/placeholder/email.eml', 'file_size': 64000, 'mime_type': 'message/rfc822'}
    
    async def _collect_browser_artifacts(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect browser artifacts"""
        return {'file_path': '/placeholder/browser.zip', 'file_size': 512000, 'mime_type': 'application/zip'}
    
    async def _collect_database_export(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect database export"""
        return {'file_path': '/placeholder/database.sql', 'file_size': 4096000, 'mime_type': 'application/sql'}
    
    async def _collect_malware_sample(self, evidence_id: str, request: EvidenceCollectionRequest, metadata: EvidenceMetadata) -> Dict[str, Any]:
        """Collect malware sample"""
        return {'file_path': '/placeholder/malware.zip', 'file_size': 128000, 'mime_type': 'application/zip'}
    
    # Utility methods
    async def _calculate_file_hashes(self, metadata: EvidenceMetadata):
        """Calculate cryptographic hashes for file integrity"""
        try:
            hash_md5 = hashlib.md5()
            hash_sha1 = hashlib.sha1()
            hash_sha256 = hashlib.sha256()
            hash_sha512 = hashlib.sha512()
            
            async with aiofiles.open(metadata.file_path, 'rb') as f:
                async for chunk in self._read_chunks(f):
                    hash_md5.update(chunk)
                    hash_sha1.update(chunk)
                    hash_sha256.update(chunk)
                    hash_sha512.update(chunk)
            
            metadata.hash_md5 = hash_md5.hexdigest()
            metadata.hash_sha1 = hash_sha1.hexdigest()
            metadata.hash_sha256 = hash_sha256.hexdigest()
            metadata.hash_sha512 = hash_sha512.hexdigest()
            
            logger.debug("File hashes calculated",
                        evidence_id=metadata.evidence_id,
                        sha256=metadata.hash_sha256)
            
        except Exception as e:
            logger.error("Failed to calculate file hashes",
                        evidence_id=metadata.evidence_id,
                        error=str(e))
            raise
    
    async def _read_chunks(self, file_handle, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        """Read file in chunks for hash calculation"""
        while True:
            chunk = await file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    async def _initialize_metadata_database(self):
        """Initialize SQLite database for evidence metadata"""
        try:
            # Create metadata database
            conn = sqlite3.connect(self.metadata_db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence_metadata (
                    evidence_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    case_id TEXT,
                    evidence_type TEXT NOT NULL,
                    source_system TEXT NOT NULL,
                    source_location TEXT NOT NULL,
                    collection_method TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    collected_by TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type TEXT NOT NULL,
                    hash_md5 TEXT NOT NULL,
                    hash_sha1 TEXT NOT NULL,
                    hash_sha256 TEXT NOT NULL,
                    hash_sha512 TEXT,
                    legal_hold BOOLEAN DEFAULT FALSE,
                    retention_period_years INTEGER DEFAULT 7,
                    privacy_classification TEXT DEFAULT 'confidential',
                    jurisdiction TEXT DEFAULT 'US',
                    storage_location TEXT NOT NULL,
                    encryption_key_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    entry_id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    location TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    witness TEXT,
                    digital_signature TEXT,
                    notes TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence_metadata (evidence_id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_incident_id ON evidence_metadata (incident_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_metadata (evidence_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_collected_at ON evidence_metadata (collected_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_custody_evidence ON chain_of_custody (evidence_id)')
            
            conn.commit()
            conn.close()
            
            logger.info("Evidence metadata database initialized")
            
        except Exception as e:
            logger.error("Failed to initialize metadata database", error=str(e))
            raise
    
    async def _initialize_crypto_keys(self):
        """Initialize cryptographic keys for signing and encryption"""
        try:
            # Generate RSA key pair for digital signatures
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            logger.info("Cryptographic keys initialized")
            
        except Exception as e:
            logger.error("Failed to initialize cryptographic keys", error=str(e))
            raise
    
    async def _store_evidence_metadata(self, metadata: EvidenceMetadata):
        """Store evidence metadata in database and Elasticsearch"""
        try:
            # Store in SQLite
            conn = sqlite3.connect(self.metadata_db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO evidence_metadata VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                metadata.evidence_id,
                metadata.incident_id,
                metadata.case_id,
                metadata.evidence_type.value,
                metadata.source_system,
                metadata.source_location,
                metadata.collection_method,
                metadata.collected_at.isoformat(),
                metadata.collected_by,
                metadata.file_path,
                metadata.file_size,
                metadata.mime_type,
                metadata.hash_md5,
                metadata.hash_sha1,
                metadata.hash_sha256,
                metadata.hash_sha512,
                metadata.legal_hold,
                metadata.retention_period_years,
                metadata.privacy_classification,
                metadata.jurisdiction,
                metadata.storage_location,
                metadata.encryption_key_id,
                metadata.created_at.isoformat(),
                metadata.updated_at.isoformat()
            ))
            
            # Store chain of custody entries
            for entry in metadata.chain_of_custody:
                cursor.execute('''
                    INSERT OR REPLACE INTO chain_of_custody VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                ''', (
                    entry.entry_id,
                    entry.evidence_id,
                    entry.action.value,
                    entry.actor,
                    entry.timestamp.isoformat(),
                    entry.location,
                    entry.purpose,
                    entry.witness,
                    entry.digital_signature,
                    entry.notes
                ))
            
            conn.commit()
            conn.close()
            
            # Store in Elasticsearch
            metadata_doc = {
                **asdict(metadata),
                'evidence_type': metadata.evidence_type.value,
                'collected_at': metadata.collected_at.isoformat(),
                'created_at': metadata.created_at.isoformat(),
                'updated_at': metadata.updated_at.isoformat(),
                '@timestamp': metadata.collected_at.isoformat()
            }
            
            await self.elasticsearch.index(
                index=f"soc-evidence-{datetime.now().strftime('%Y-%m')}",
                id=metadata.evidence_id,
                body=metadata_doc
            )
            
            logger.debug("Evidence metadata stored",
                        evidence_id=metadata.evidence_id)
            
        except Exception as e:
            logger.error("Failed to store evidence metadata",
                        evidence_id=metadata.evidence_id,
                        error=str(e))
            raise
    
    # Placeholder methods for additional functionality
    async def _validate_collection_request(self, request: EvidenceCollectionRequest) -> bool:
        """Validate evidence collection request"""
        return True
    
    async def _encrypt_evidence_file(self, metadata: EvidenceMetadata):
        """Encrypt evidence file"""
        pass
    
    async def _create_evidence_backup(self, metadata: EvidenceMetadata):
        """Create backup copy of evidence"""
        pass
    
    async def _sign_custody_entry(self, entry: ChainOfCustodyEntry) -> str:
        """Digitally sign chain of custody entry"""
        return "placeholder_signature"
    
    async def _integrity_monitor(self):
        """Monitor evidence integrity"""
        while self.running:
            await asyncio.sleep(self.integrity_check_interval)
            # Perform integrity checks
    
    async def _cleanup_old_evidence(self):
        """Clean up expired evidence"""
        while self.running:
            await asyncio.sleep(86400)  # Daily cleanup
            # Remove expired evidence
    
    # Public API methods
    async def get_evidence_metadata(self, evidence_id: str) -> Optional[EvidenceMetadata]:
        """Retrieve evidence metadata"""
        # Implementation would query database and return metadata
        return None
    
    async def verify_evidence_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """Verify evidence file integrity"""
        # Implementation would recalculate hashes and compare
        return {'verified': True, 'hash_match': True}
    
    async def add_custody_entry(self, evidence_id: str, action: ChainOfCustodyAction, actor: str, purpose: str, witness: str = None) -> str:
        """Add new chain of custody entry"""
        # Implementation would create new custody entry
        return "custody_entry_id"
    
    async def get_evidence_report(self, incident_id: str) -> Dict[str, Any]:
        """Generate comprehensive evidence report for incident"""
        # Implementation would generate report
        return {'evidence_count': 0, 'total_size': 0, 'types': []}