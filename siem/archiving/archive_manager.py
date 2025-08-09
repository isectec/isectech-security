#!/usr/bin/env python3
"""
iSECTECH SIEM Archive Manager
Production-grade long-term storage and archiving system
Manages retention policies, compliance requirements, and data lifecycle
"""

import asyncio
import json
import logging
import gzip
import lzma
import bz2
import hashlib
import shutil
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
import boto3
import psycopg2
from psycopg2.extras import RealDictCursor
from elasticsearch import Elasticsearch, helpers
import redis.asyncio as redis
import yaml
import tarfile
import zipfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ArchiveJob:
    """Archive job definition"""
    job_id: str
    job_type: str  # archive, restore, delete, verify
    data_source: str  # elasticsearch, database, files
    source_config: Dict[str, Any]
    destination_config: Dict[str, Any]
    date_range: Tuple[datetime, datetime]
    retention_policy: str
    compression: str  # none, gzip, lzma, bz2
    encryption: bool
    priority: int  # 1=high, 2=medium, 3=low
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed, cancelled
    progress: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

@dataclass
class RetentionPolicy:
    """Data retention policy definition"""
    policy_name: str
    data_types: List[str]
    hot_storage_days: int
    warm_storage_days: int
    cold_storage_days: int
    archive_storage_days: int
    total_retention_days: int
    compliance_requirements: List[str]
    encryption_required: bool
    compression_level: str
    geographic_restrictions: List[str]
    legal_hold_support: bool

@dataclass
class ArchiveLocation:
    """Archive storage location configuration"""
    location_id: str
    location_type: str  # s3, azure, gcs, nfs, local
    config: Dict[str, Any]
    encryption_enabled: bool
    compression_enabled: bool
    access_tier: str  # hot, warm, cold, archive
    cost_per_gb_per_month: float
    retrieval_time_sla: str
    geographic_location: str
    compliance_certifications: List[str]

class ArchiveManager:
    """
    Production archive manager for SIEM data
    Handles long-term storage, retention policies, and compliance requirements
    """
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.retention_policies = {}
        self.archive_locations = {}
        self.active_jobs = {}
        self.job_queue = asyncio.Queue()
        self.worker_tasks = []
        self.redis_client = None
        self.db_connection = None
        self.es_client = None
        self.encryption_key = None
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Performance metrics
        self.metrics = {
            'jobs_completed': 0,
            'data_archived_gb': 0.0,
            'data_restored_gb': 0.0,
            'avg_compression_ratio': 0.0,
            'avg_archive_time_per_gb': 0.0,
            'storage_cost_savings': 0.0
        }
        
    async def initialize(self):
        """Initialize the archive manager"""
        try:
            await self._load_config()
            await self._setup_database()
            await self._setup_redis()
            await self._setup_elasticsearch()
            await self._setup_encryption()
            await self._load_retention_policies()
            await self._load_archive_locations()
            await self._start_workers()
            await self._schedule_maintenance_tasks()
            logger.info("Archive Manager initialized successfully")
        except Exception as e:
            logger.error(f"Archive Manager initialization failed: {e}")
            raise
            
    async def _load_config(self):
        """Load archiving configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            # Use default configuration
            self.config = {
                'database': {'host': 'localhost', 'port': 5432, 'database': 'siem_archive'},
                'redis': {'host': 'localhost', 'port': 6379, 'db': 5},
                'elasticsearch': {'hosts': ['localhost:9200']},
                'workers': {'count': 2, 'batch_size': 1000},
                'storage': {'local_path': '/opt/siem/archive'}
            }
            
    async def _setup_database(self):
        """Setup PostgreSQL connection"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'siem_archive'),
                user=db_config.get('user', 'archive_user'),
                password=db_config.get('password', 'archive_password'),
                cursor_factory=RealDictCursor
            )
            self.db_connection.autocommit = True
            logger.info("Database connection established")
        except Exception as e:
            logger.warning(f"Database connection failed: {e}")
            self.db_connection = None
            
    async def _setup_redis(self):
        """Setup Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 5),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
            
    async def _setup_elasticsearch(self):
        """Setup Elasticsearch connection"""
        try:
            es_config = self.config.get('elasticsearch', {})
            self.es_client = Elasticsearch(
                hosts=es_config.get('hosts', ['localhost:9200']),
                verify_certs=es_config.get('verify_certs', False),
                use_ssl=es_config.get('use_ssl', False),
                timeout=es_config.get('timeout', 30)
            )
            
            # Test connection
            if self.es_client.ping():
                logger.info("Elasticsearch connection established")
            else:
                logger.warning("Elasticsearch connection failed")
                self.es_client = None
                
        except Exception as e:
            logger.warning(f"Elasticsearch setup failed: {e}")
            self.es_client = None
            
    async def _setup_encryption(self):
        """Setup encryption for sensitive data"""
        try:
            encryption_config = self.config.get('encryption', {})
            
            if encryption_config.get('enabled', True):
                # Generate or load encryption key
                key_path = encryption_config.get('key_path', '/opt/siem/keys/archive.key')
                
                if Path(key_path).exists():
                    with open(key_path, 'rb') as f:
                        self.encryption_key = f.read()
                else:
                    # Generate new key
                    password = encryption_config.get('password', 'default_password').encode()
                    salt = encryption_config.get('salt', b'salt_1234567890123456').encode()[:16]
                    
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    self.encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
                    
                    # Save key
                    os.makedirs(Path(key_path).parent, exist_ok=True)
                    with open(key_path, 'wb') as f:
                        f.write(self.encryption_key)
                    os.chmod(key_path, 0o600)
                    
                logger.info("Encryption initialized")
            else:
                logger.warning("Encryption disabled")
                
        except Exception as e:
            logger.error(f"Encryption setup failed: {e}")
            
    async def _load_retention_policies(self):
        """Load retention policies from database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT policy_name, data_types, hot_storage_days, warm_storage_days,
                           cold_storage_days, archive_storage_days, total_retention_days,
                           compliance_requirements, encryption_required, compression_level,
                           geographic_restrictions, legal_hold_support
                    FROM retention_policies 
                    WHERE enabled = true
                """)
                
                for row in cursor.fetchall():
                    policy = RetentionPolicy(
                        policy_name=row['policy_name'],
                        data_types=json.loads(row['data_types']),
                        hot_storage_days=row['hot_storage_days'],
                        warm_storage_days=row['warm_storage_days'],
                        cold_storage_days=row['cold_storage_days'],
                        archive_storage_days=row['archive_storage_days'],
                        total_retention_days=row['total_retention_days'],
                        compliance_requirements=json.loads(row['compliance_requirements']),
                        encryption_required=row['encryption_required'],
                        compression_level=row['compression_level'],
                        geographic_restrictions=json.loads(row['geographic_restrictions']),
                        legal_hold_support=row['legal_hold_support']
                    )
                    self.retention_policies[row['policy_name']] = policy
                    
                cursor.close()
                logger.info(f"Loaded {len(self.retention_policies)} retention policies")
                
        except Exception as e:
            logger.error(f"Failed to load retention policies: {e}")
            # Create default policy
            await self._create_default_retention_policy()
            
    async def _create_default_retention_policy(self):
        """Create default retention policy"""
        default_policy = RetentionPolicy(
            policy_name="default_security_logs",
            data_types=["security_logs", "audit_logs", "alerts"],
            hot_storage_days=30,
            warm_storage_days=90,
            cold_storage_days=365,
            archive_storage_days=2555,  # 7 years
            total_retention_days=2555,
            compliance_requirements=["SOX", "GDPR", "HIPAA"],
            encryption_required=True,
            compression_level="high",
            geographic_restrictions=["US", "EU"],
            legal_hold_support=True
        )
        self.retention_policies["default_security_logs"] = default_policy
        
    async def _load_archive_locations(self):
        """Load archive storage locations from database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT location_id, location_type, config, encryption_enabled,
                           compression_enabled, access_tier, cost_per_gb_per_month,
                           retrieval_time_sla, geographic_location, compliance_certifications
                    FROM archive_locations 
                    WHERE enabled = true
                """)
                
                for row in cursor.fetchall():
                    location = ArchiveLocation(
                        location_id=row['location_id'],
                        location_type=row['location_type'],
                        config=json.loads(row['config']),
                        encryption_enabled=row['encryption_enabled'],
                        compression_enabled=row['compression_enabled'],
                        access_tier=row['access_tier'],
                        cost_per_gb_per_month=row['cost_per_gb_per_month'],
                        retrieval_time_sla=row['retrieval_time_sla'],
                        geographic_location=row['geographic_location'],
                        compliance_certifications=json.loads(row['compliance_certifications'])
                    )
                    self.archive_locations[row['location_id']] = location
                    
                cursor.close()
                logger.info(f"Loaded {len(self.archive_locations)} archive locations")
                
        except Exception as e:
            logger.error(f"Failed to load archive locations: {e}")
            # Create default local location
            await self._create_default_archive_location()
            
    async def _create_default_archive_location(self):
        """Create default local archive location"""
        default_location = ArchiveLocation(
            location_id="local_archive",
            location_type="local",
            config={
                "base_path": "/opt/siem/archive",
                "max_size_gb": 1000
            },
            encryption_enabled=True,
            compression_enabled=True,
            access_tier="cold",
            cost_per_gb_per_month=0.01,
            retrieval_time_sla="immediate",
            geographic_location="on-premises",
            compliance_certifications=["SOC2", "ISO27001"]
        )
        self.archive_locations["local_archive"] = default_location
        
    async def _start_workers(self):
        """Start archive worker tasks"""
        worker_count = self.config.get('workers', {}).get('count', 2)
        
        for i in range(worker_count):
            task = asyncio.create_task(self._archive_worker(f"worker-{i}"))
            self.worker_tasks.append(task)
            
        logger.info(f"Started {worker_count} archive workers")
        
    async def _schedule_maintenance_tasks(self):
        """Schedule periodic maintenance tasks"""
        # Schedule daily retention policy enforcement
        asyncio.create_task(self._periodic_retention_enforcement())
        
        # Schedule weekly storage optimization
        asyncio.create_task(self._periodic_storage_optimization())
        
        # Schedule monthly compliance reporting
        asyncio.create_task(self._periodic_compliance_reporting())
        
        logger.info("Maintenance tasks scheduled")
        
    async def create_archive_job(self, job_config: Dict[str, Any]) -> ArchiveJob:
        """Create a new archive job"""
        try:
            job = ArchiveJob(
                job_id=job_config.get('job_id', self._generate_job_id()),
                job_type=job_config['job_type'],
                data_source=job_config['data_source'],
                source_config=job_config['source_config'],
                destination_config=job_config['destination_config'],
                date_range=(
                    datetime.fromisoformat(job_config['start_date']),
                    datetime.fromisoformat(job_config['end_date'])
                ),
                retention_policy=job_config.get('retention_policy', 'default_security_logs'),
                compression=job_config.get('compression', 'gzip'),
                encryption=job_config.get('encryption', True),
                priority=job_config.get('priority', 2),
                created_at=datetime.now(timezone.utc),
                metadata=job_config.get('metadata', {})
            )
            
            # Validate job configuration
            await self._validate_archive_job(job)
            
            # Store job in database
            await self._store_archive_job(job)
            
            # Add to queue
            await self.job_queue.put(job)
            
            logger.info(f"Archive job created: {job.job_id}")
            return job
            
        except Exception as e:
            logger.error(f"Failed to create archive job: {e}")
            raise
            
    async def _validate_archive_job(self, job: ArchiveJob):
        """Validate archive job configuration"""
        # Check retention policy exists
        if job.retention_policy not in self.retention_policies:
            raise ValueError(f"Unknown retention policy: {job.retention_policy}")
            
        # Check date range is valid
        if job.date_range[0] >= job.date_range[1]:
            raise ValueError("Invalid date range: start date must be before end date")
            
        # Check data source configuration
        if job.data_source == 'elasticsearch' and not self.es_client:
            raise ValueError("Elasticsearch not configured")
            
        # Check destination configuration
        destination_id = job.destination_config.get('location_id')
        if destination_id and destination_id not in self.archive_locations:
            raise ValueError(f"Unknown archive location: {destination_id}")
            
    async def _store_archive_job(self, job: ArchiveJob):
        """Store archive job in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    INSERT INTO archive_jobs 
                    (job_id, job_type, data_source, source_config, destination_config,
                     start_date, end_date, retention_policy, compression, encryption,
                     priority, created_at, status, progress, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    job.job_id, job.job_type, job.data_source,
                    json.dumps(job.source_config), json.dumps(job.destination_config),
                    job.date_range[0], job.date_range[1], job.retention_policy,
                    job.compression, job.encryption, job.priority,
                    job.created_at, job.status, job.progress,
                    json.dumps(job.metadata)
                ))
                cursor.close()
                
        except Exception as e:
            logger.error(f"Failed to store archive job: {e}")
            
    async def _archive_worker(self, worker_id: str):
        """Archive worker process"""
        logger.info(f"Archive worker {worker_id} started")
        
        while True:
            try:
                # Get job from queue
                job = await self.job_queue.get()
                
                # Update job status
                job.status = "running"
                job.started_at = datetime.now(timezone.utc)
                await self._update_job_status(job)
                
                # Process job
                logger.info(f"Worker {worker_id} processing job: {job.job_id}")
                
                if job.job_type == "archive":
                    await self._process_archive_job(job)
                elif job.job_type == "restore":
                    await self._process_restore_job(job)
                elif job.job_type == "delete":
                    await self._process_delete_job(job)
                elif job.job_type == "verify":
                    await self._process_verify_job(job)
                else:
                    raise ValueError(f"Unknown job type: {job.job_type}")
                    
                # Mark job as completed
                job.status = "completed"
                job.completed_at = datetime.now(timezone.utc)
                job.progress = 1.0
                await self._update_job_status(job)
                
                self.metrics['jobs_completed'] += 1
                logger.info(f"Worker {worker_id} completed job: {job.job_id}")
                
            except Exception as e:
                logger.error(f"Worker {worker_id} job failed: {e}")
                if 'job' in locals():
                    job.status = "failed"
                    job.error_message = str(e)
                    job.completed_at = datetime.now(timezone.utc)
                    await self._update_job_status(job)
                    
            finally:
                if 'job' in locals():
                    self.active_jobs.pop(job.job_id, None)
                    
            await asyncio.sleep(1)  # Brief pause between jobs
            
    async def _process_archive_job(self, job: ArchiveJob):
        """Process data archiving job"""
        try:
            # Get data from source
            data_iterator = await self._get_data_from_source(job)
            
            # Get destination configuration
            destination = await self._get_destination_config(job)
            
            # Process data in batches
            batch_size = self.config.get('workers', {}).get('batch_size', 1000)
            total_processed = 0
            total_size_bytes = 0
            
            for batch in self._batch_iterator(data_iterator, batch_size):
                # Compress and encrypt if required
                processed_data = await self._process_data_batch(
                    batch, job.compression, job.encryption
                )
                
                # Store batch to destination
                await self._store_data_batch(processed_data, destination, job)
                
                # Update progress
                total_processed += len(batch)
                total_size_bytes += len(processed_data)
                
                # Estimate progress (rough approximation)
                days_range = (job.date_range[1] - job.date_range[0]).days
                estimated_total = days_range * batch_size * 10  # Rough estimate
                job.progress = min(total_processed / estimated_total, 0.99)
                
                if total_processed % (batch_size * 10) == 0:  # Update every 10 batches
                    await self._update_job_status(job)
                    
            # Update metrics
            size_gb = total_size_bytes / (1024**3)
            self.metrics['data_archived_gb'] += size_gb
            
            # Store job completion metadata
            job.metadata.update({
                'total_records': total_processed,
                'total_size_bytes': total_size_bytes,
                'compression_ratio': await self._calculate_compression_ratio(job),
                'archive_location': destination['location_id']
            })
            
            logger.info(f"Archive job completed: {total_processed} records, {size_gb:.2f} GB")
            
        except Exception as e:
            logger.error(f"Archive job processing failed: {e}")
            raise
            
    async def _get_data_from_source(self, job: ArchiveJob):
        """Get data from source system"""
        if job.data_source == "elasticsearch":
            return await self._get_elasticsearch_data(job)
        elif job.data_source == "database":
            return await self._get_database_data(job)
        elif job.data_source == "files":
            return await self._get_files_data(job)
        else:
            raise ValueError(f"Unsupported data source: {job.data_source}")
            
    async def _get_elasticsearch_data(self, job: ArchiveJob):
        """Get data from Elasticsearch"""
        if not self.es_client:
            raise ValueError("Elasticsearch client not available")
            
        source_config = job.source_config
        index_pattern = source_config.get('index_pattern', 'logs-*')
        query = source_config.get('query', {'match_all': {}})
        
        # Build time range query
        time_range_query = {
            "bool": {
                "must": [query],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": job.date_range[0].isoformat(),
                                "lt": job.date_range[1].isoformat()
                            }
                        }
                    }
                ]
            }
        }
        
        # Use scroll API for large datasets
        scroll_timeout = source_config.get('scroll_timeout', '5m')
        size = source_config.get('size', 1000)
        
        try:
            # Initial search
            response = self.es_client.search(
                index=index_pattern,
                body={"query": time_range_query},
                scroll=scroll_timeout,
                size=size
            )
            
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            
            # Yield initial batch
            if hits:
                yield hits
                
            # Continue scrolling
            while True:
                response = self.es_client.scroll(
                    scroll_id=scroll_id,
                    scroll=scroll_timeout
                )
                
                hits = response['hits']['hits']
                if not hits:
                    break
                    
                yield hits
                
        finally:
            # Clear scroll
            try:
                self.es_client.clear_scroll(scroll_id=scroll_id)
            except:
                pass
                
    async def _get_database_data(self, job: ArchiveJob):
        """Get data from database"""
        if not self.db_connection:
            raise ValueError("Database connection not available")
            
        source_config = job.source_config
        table_name = source_config['table_name']
        timestamp_column = source_config.get('timestamp_column', 'timestamp')
        batch_size = source_config.get('batch_size', 1000)
        
        cursor = self.db_connection.cursor()
        
        try:
            # Count total records
            cursor.execute(f"""
                SELECT COUNT(*) FROM {table_name}
                WHERE {timestamp_column} >= %s AND {timestamp_column} < %s
            """, (job.date_range[0], job.date_range[1]))
            
            total_count = cursor.fetchone()[0]
            
            # Fetch data in batches
            offset = 0
            while offset < total_count:
                cursor.execute(f"""
                    SELECT * FROM {table_name}
                    WHERE {timestamp_column} >= %s AND {timestamp_column} < %s
                    ORDER BY {timestamp_column}
                    LIMIT %s OFFSET %s
                """, (job.date_range[0], job.date_range[1], batch_size, offset))
                
                rows = cursor.fetchall()
                if not rows:
                    break
                    
                # Convert to dictionaries
                batch = [dict(row) for row in rows]
                yield batch
                
                offset += len(rows)
                
        finally:
            cursor.close()
            
    async def _get_files_data(self, job: ArchiveJob):
        """Get data from files"""
        source_config = job.source_config
        base_path = Path(source_config['base_path'])
        file_pattern = source_config.get('file_pattern', '*.log')
        
        if not base_path.exists():
            raise ValueError(f"Source path does not exist: {base_path}")
            
        # Find files within date range
        files = []
        for file_path in base_path.glob(file_pattern):
            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
            if job.date_range[0] <= file_mtime < job.date_range[1]:
                files.append(file_path)
                
        # Process files
        for file_path in files:
            with open(file_path, 'r') as f:
                batch = []
                for line in f:
                    try:
                        # Try to parse as JSON
                        data = json.loads(line.strip())
                        batch.append(data)
                        
                        if len(batch) >= 1000:
                            yield batch
                            batch = []
                    except:
                        # Skip invalid lines
                        continue
                        
                if batch:
                    yield batch
                    
    def _batch_iterator(self, data_iterator, batch_size: int):
        """Convert data iterator to batches"""
        for batch in data_iterator:
            if isinstance(batch, list) and len(batch) <= batch_size:
                yield batch
            else:
                # Split large batches
                if isinstance(batch, list):
                    for i in range(0, len(batch), batch_size):
                        yield batch[i:i + batch_size]
                else:
                    yield [batch]
                    
    async def _process_data_batch(self, batch: List[Dict[str, Any]], 
                                compression: str, encryption: bool) -> bytes:
        """Process data batch with compression and encryption"""
        try:
            # Convert to JSON
            json_data = json.dumps(batch, default=str).encode('utf-8')
            
            # Apply compression
            if compression == 'gzip':
                compressed_data = gzip.compress(json_data)
            elif compression == 'lzma':
                compressed_data = lzma.compress(json_data)
            elif compression == 'bz2':
                compressed_data = bz2.compress(json_data)
            else:
                compressed_data = json_data
                
            # Apply encryption
            if encryption and self.encryption_key:
                fernet = Fernet(self.encryption_key)
                encrypted_data = fernet.encrypt(compressed_data)
                return encrypted_data
            else:
                return compressed_data
                
        except Exception as e:
            logger.error(f"Data processing failed: {e}")
            raise
            
    async def _get_destination_config(self, job: ArchiveJob) -> Dict[str, Any]:
        """Get destination configuration for job"""
        destination_config = job.destination_config.copy()
        location_id = destination_config.get('location_id', 'local_archive')
        
        if location_id in self.archive_locations:
            location = self.archive_locations[location_id]
            destination_config.update({
                'location': location,
                'location_type': location.location_type
            })
            
        return destination_config
        
    async def _store_data_batch(self, data: bytes, destination: Dict[str, Any], job: ArchiveJob):
        """Store data batch to destination"""
        location_type = destination.get('location_type', 'local')
        
        if location_type == 'local':
            await self._store_to_local(data, destination, job)
        elif location_type == 's3':
            await self._store_to_s3(data, destination, job)
        elif location_type == 'azure':
            await self._store_to_azure(data, destination, job)
        elif location_type == 'gcs':
            await self._store_to_gcs(data, destination, job)
        else:
            raise ValueError(f"Unsupported destination type: {location_type}")
            
    async def _store_to_local(self, data: bytes, destination: Dict[str, Any], job: ArchiveJob):
        """Store data to local filesystem"""
        try:
            location = destination['location']
            base_path = Path(location.config['base_path'])
            
            # Create directory structure: base_path/year/month/day/job_id/
            date_path = job.date_range[0].strftime('%Y/%m/%d')
            job_path = base_path / date_path / job.job_id
            job_path.mkdir(parents=True, exist_ok=True)
            
            # Generate unique filename
            timestamp = int(time.time() * 1000)
            filename = f"batch_{timestamp}.{job.compression}"
            if job.encryption:
                filename += ".enc"
                
            file_path = job_path / filename
            
            # Write data
            with open(file_path, 'wb') as f:
                f.write(data)
                
            # Create metadata file
            metadata = {
                'job_id': job.job_id,
                'batch_timestamp': timestamp,
                'compression': job.compression,
                'encryption': job.encryption,
                'size_bytes': len(data),
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            metadata_path = job_path / f"batch_{timestamp}.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f)
                
        except Exception as e:
            logger.error(f"Local storage failed: {e}")
            raise
            
    async def _store_to_s3(self, data: bytes, destination: Dict[str, Any], job: ArchiveJob):
        """Store data to Amazon S3"""
        try:
            location = destination['location']
            s3_config = location.config
            
            # Initialize S3 client
            s3_client = boto3.client(
                's3',
                aws_access_key_id=s3_config.get('access_key_id'),
                aws_secret_access_key=s3_config.get('secret_access_key'),
                region_name=s3_config.get('region', 'us-east-1')
            )
            
            # Generate S3 key
            date_path = job.date_range[0].strftime('%Y/%m/%d')
            timestamp = int(time.time() * 1000)
            key = f"{s3_config.get('prefix', 'archive')}/{date_path}/{job.job_id}/batch_{timestamp}.{job.compression}"
            
            if job.encryption:
                key += ".enc"
                
            # Upload data
            s3_client.put_object(
                Bucket=s3_config['bucket'],
                Key=key,
                Body=data,
                StorageClass=s3_config.get('storage_class', 'GLACIER'),
                Metadata={
                    'job-id': job.job_id,
                    'compression': job.compression,
                    'encryption': str(job.encryption).lower(),
                    'size-bytes': str(len(data))
                }
            )
            
        except Exception as e:
            logger.error(f"S3 storage failed: {e}")
            raise
            
    async def _update_job_status(self, job: ArchiveJob):
        """Update job status in database"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    UPDATE archive_jobs 
                    SET status = %s, progress = %s, started_at = %s, 
                        completed_at = %s, error_message = %s, metadata = %s
                    WHERE job_id = %s
                """, (
                    job.status, job.progress, job.started_at,
                    job.completed_at, job.error_message,
                    json.dumps(job.metadata), job.job_id
                ))
                cursor.close()
                
        except Exception as e:
            logger.error(f"Failed to update job status: {e}")
            
    def _generate_job_id(self) -> str:
        """Generate unique job ID"""
        timestamp = int(time.time() * 1000)
        return f"archive_{timestamp}_{hash(str(timestamp)) % 10000:04d}"
        
    async def _calculate_compression_ratio(self, job: ArchiveJob) -> float:
        """Calculate compression ratio for job"""
        # This is a simplified calculation
        # In production, you'd track original vs compressed sizes
        compression_ratios = {
            'none': 1.0,
            'gzip': 0.3,
            'lzma': 0.2,
            'bz2': 0.25
        }
        return compression_ratios.get(job.compression, 0.3)
        
    async def _process_restore_job(self, job: ArchiveJob):
        """Process data restoration job"""
        try:
            # Implementation for data restoration
            logger.info(f"Processing restore job: {job.job_id}")
            
            # This would implement the reverse of archiving:
            # 1. Find archived data files
            # 2. Decrypt and decompress
            # 3. Restore to target system
            
            # Placeholder implementation
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Restore job failed: {e}")
            raise
            
    async def _process_delete_job(self, job: ArchiveJob):
        """Process data deletion job"""
        try:
            # Implementation for data deletion
            logger.info(f"Processing delete job: {job.job_id}")
            
            # This would implement secure data deletion:
            # 1. Locate data to delete
            # 2. Verify retention policies allow deletion
            # 3. Securely delete data
            # 4. Update metadata
            
            # Placeholder implementation
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Delete job failed: {e}")
            raise
            
    async def _process_verify_job(self, job: ArchiveJob):
        """Process data verification job"""
        try:
            # Implementation for data verification
            logger.info(f"Processing verify job: {job.job_id}")
            
            # This would implement:
            # 1. Check data integrity
            # 2. Verify checksums
            # 3. Test restoration capability
            # 4. Validate compliance requirements
            
            # Placeholder implementation
            await asyncio.sleep(1)
            
        except Exception as e:
            logger.error(f"Verify job failed: {e}")
            raise
            
    async def _periodic_retention_enforcement(self):
        """Periodic retention policy enforcement"""
        while True:
            try:
                await asyncio.sleep(86400)  # Daily
                
                logger.info("Starting retention policy enforcement")
                
                # Check all retention policies
                for policy_name, policy in self.retention_policies.items():
                    await self._enforce_retention_policy(policy)
                    
                logger.info("Retention policy enforcement completed")
                
            except Exception as e:
                logger.error(f"Retention enforcement failed: {e}")
                
    async def _enforce_retention_policy(self, policy: RetentionPolicy):
        """Enforce a specific retention policy"""
        try:
            # Calculate cutoff dates
            now = datetime.now(timezone.utc)
            cutoff_date = now - timedelta(days=policy.total_retention_days)
            
            # Find data past retention period
            # This would query the archive metadata to find eligible data
            
            # Create deletion jobs for expired data
            # Implementation would create delete jobs
            
            logger.info(f"Enforced retention policy: {policy.policy_name}")
            
        except Exception as e:
            logger.error(f"Retention policy enforcement failed: {e}")
            
    async def _periodic_storage_optimization(self):
        """Periodic storage optimization"""
        while True:
            try:
                await asyncio.sleep(604800)  # Weekly
                
                logger.info("Starting storage optimization")
                
                # Optimize storage tiers
                await self._optimize_storage_tiers()
                
                # Cleanup temporary files
                await self._cleanup_temporary_files()
                
                # Update storage metrics
                await self._update_storage_metrics()
                
                logger.info("Storage optimization completed")
                
            except Exception as e:
                logger.error(f"Storage optimization failed: {e}")
                
    async def _periodic_compliance_reporting(self):
        """Periodic compliance reporting"""
        while True:
            try:
                await asyncio.sleep(2592000)  # Monthly
                
                logger.info("Starting compliance reporting")
                
                # Generate compliance reports
                await self._generate_compliance_reports()
                
                logger.info("Compliance reporting completed")
                
            except Exception as e:
                logger.error(f"Compliance reporting failed: {e}")
                
    async def get_job_status(self, job_id: str) -> Optional[ArchiveJob]:
        """Get status of archive job"""
        try:
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("SELECT * FROM archive_jobs WHERE job_id = %s", (job_id,))
                row = cursor.fetchone()
                cursor.close()
                
                if row:
                    return ArchiveJob(
                        job_id=row['job_id'],
                        job_type=row['job_type'],
                        data_source=row['data_source'],
                        source_config=json.loads(row['source_config']),
                        destination_config=json.loads(row['destination_config']),
                        date_range=(row['start_date'], row['end_date']),
                        retention_policy=row['retention_policy'],
                        compression=row['compression'],
                        encryption=row['encryption'],
                        priority=row['priority'],
                        created_at=row['created_at'],
                        started_at=row['started_at'],
                        completed_at=row['completed_at'],
                        status=row['status'],
                        progress=row['progress'],
                        error_message=row['error_message'],
                        metadata=json.loads(row['metadata'] or '{}')
                    )
                    
            return None
            
        except Exception as e:
            logger.error(f"Failed to get job status: {e}")
            return None
            
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel archive job"""
        try:
            job = await self.get_job_status(job_id)
            if job and job.status in ['pending', 'running']:
                job.status = 'cancelled'
                job.completed_at = datetime.now(timezone.utc)
                await self._update_job_status(job)
                
                # Remove from active jobs
                self.active_jobs.pop(job_id, None)
                
                logger.info(f"Job cancelled: {job_id}")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to cancel job: {e}")
            return False
            
    def get_metrics(self) -> Dict[str, Any]:
        """Get archive manager metrics"""
        return self.metrics.copy()
        
    async def cleanup(self):
        """Cleanup resources"""
        try:
            # Cancel worker tasks
            for task in self.worker_tasks:
                task.cancel()
                
            # Close connections
            if self.db_connection:
                self.db_connection.close()
            if self.redis_client:
                await self.redis_client.close()
            if self.es_client:
                self.es_client.close()
                
            # Shutdown thread pool
            self.thread_pool.shutdown(wait=True)
            
            logger.info("Archive Manager cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

if __name__ == "__main__":
    # Example usage
    async def main():
        archive_manager = ArchiveManager("/path/to/archive_config.yaml")
        await archive_manager.initialize()
        
        # Create test archive job
        job_config = {
            'job_type': 'archive',
            'data_source': 'elasticsearch',
            'source_config': {
                'index_pattern': 'security-logs-*',
                'query': {'match_all': {}}
            },
            'destination_config': {
                'location_id': 'local_archive'
            },
            'start_date': '2024-01-01T00:00:00Z',
            'end_date': '2024-01-02T00:00:00Z',
            'retention_policy': 'default_security_logs'
        }
        
        job = await archive_manager.create_archive_job(job_config)
        print(f"Archive job created: {job.job_id}")
        
        # Monitor job progress
        while True:
            status = await archive_manager.get_job_status(job.job_id)
            if status:
                print(f"Job status: {status.status}, Progress: {status.progress:.2%}")
                if status.status in ['completed', 'failed', 'cancelled']:
                    break
            await asyncio.sleep(5)
            
        await archive_manager.cleanup()
        
    # Run example
    # asyncio.run(main())