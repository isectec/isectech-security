#!/usr/bin/env python3
"""
ISECTECH Data Loss Prevention - Data Discovery and Classification Engine
Production-grade data discovery system for automated sensitive data identification.

This module provides comprehensive data discovery capabilities across:
- File systems and network shares
- Databases (SQL and NoSQL)
- Cloud storage platforms
- Real-time data streams
- Custom data sources

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import hashlib
import json
import logging
import mimetypes
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, AsyncGenerator
from urllib.parse import urlparse

import aiofiles
import aiohttp
import boto3
from azure.storage.blob import BlobServiceClient
from google.cloud import storage as gcs
import pymongo
import redis
import magic
import chardet
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

# ISECTECH Security Configuration
from ..config.security_config import SecurityConfig
from ..core.logging import SecurityLogger
from ..core.metrics import MetricsCollector
from ..core.encryption import DataEncryption


class DataSensitivityLevel(Enum):
    """Data sensitivity classification levels for ISECTECH."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class DataClassification(Enum):
    """Data classification types for ISECTECH compliance."""
    PII = "personally_identifiable_information"
    PHI = "protected_health_information"
    PCI = "payment_card_information"
    TRADE_SECRET = "trade_secret"
    INTELLECTUAL_PROPERTY = "intellectual_property"
    FINANCIAL = "financial_data"
    BIOMETRIC = "biometric_data"
    GOVERNMENT_ID = "government_identification"
    EDUCATION_RECORD = "education_record"
    EMPLOYMENT_DATA = "employment_data"


class DiscoveryStatus(Enum):
    """Discovery job status tracking."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class DataSource:
    """Data source configuration."""
    id: str
    name: str
    type: str  # filesystem, database, cloud_storage, api
    connection_string: str
    credentials: Dict[str, Any]
    enabled: bool = True
    scan_schedule: Optional[str] = None
    last_scan: Optional[datetime] = None
    metadata: Dict[str, Any] = None


@dataclass
class ClassificationRule:
    """Data classification rule definition."""
    id: str
    name: str
    classification: DataClassification
    sensitivity: DataSensitivityLevel
    pattern: str
    pattern_type: str  # regex, keyword, ml_model
    confidence_threshold: float
    enabled: bool = True
    priority: int = 1
    metadata: Dict[str, Any] = None


@dataclass
class DiscoveredData:
    """Discovered sensitive data record."""
    id: str
    source_id: str
    file_path: str
    data_type: str
    classification: DataClassification
    sensitivity: DataSensitivityLevel
    confidence_score: float
    match_details: Dict[str, Any]
    file_size: int
    file_hash: str
    created_time: datetime
    modified_time: datetime
    owner: Optional[str] = None
    permissions: Optional[str] = None
    tags: List[str] = None
    risk_score: float = 0.0


@dataclass
class DiscoveryJob:
    """Discovery job tracking."""
    id: str
    name: str
    source_ids: List[str]
    status: DiscoveryStatus
    created_time: datetime
    started_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None
    total_files: int = 0
    processed_files: int = 0
    sensitive_files: int = 0
    errors: List[str] = None
    metadata: Dict[str, Any] = None


class DataDiscoveryEngine:
    """
    ISECTECH Data Loss Prevention - Data Discovery Engine
    
    Production-grade data discovery system with:
    - Multi-source data discovery
    - Real-time classification
    - Compliance-specific detection
    - Performance optimization
    - Comprehensive audit trails
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = SecurityLogger("data_discovery_engine")
        self.metrics = MetricsCollector("dlp_discovery")
        self.encryption = DataEncryption()
        
        # Database setup
        self.db_path = config.get("dlp.database_path", "dlp_discovery.db")
        self._init_database()
        
        # Redis for caching
        self.redis_client = redis.Redis(
            host=config.get("redis.host", "localhost"),
            port=config.get("redis.port", 6379),
            db=config.get("redis.db", 2),
            decode_responses=True
        )
        
        # Thread pool for concurrent processing
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get("dlp.discovery.max_workers", 10)
        )
        
        # Classification rules
        self.classification_rules: Dict[str, ClassificationRule] = {}
        self._load_classification_rules()
        
        # Data sources
        self.data_sources: Dict[str, DataSource] = {}
        self._load_data_sources()
        
        # Performance tracking
        self.discovery_stats = {
            "total_scanned": 0,
            "total_classified": 0,
            "total_errors": 0,
            "scan_duration": 0.0
        }
        
        self.logger.info("ISECTECH Data Discovery Engine initialized")


    def _init_database(self):
        """Initialize SQLite database with optimized schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Data sources table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            connection_string TEXT NOT NULL,
            credentials TEXT NOT NULL,  -- Encrypted
            enabled BOOLEAN DEFAULT 1,
            scan_schedule TEXT,
            last_scan TIMESTAMP,
            metadata TEXT,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Classification rules table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS classification_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            classification TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            pattern TEXT NOT NULL,
            pattern_type TEXT NOT NULL,
            confidence_threshold REAL NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            priority INTEGER DEFAULT 1,
            metadata TEXT,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Discovered data table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovered_data (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            data_type TEXT NOT NULL,
            classification TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            match_details TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_hash TEXT NOT NULL,
            created_time TIMESTAMP NOT NULL,
            modified_time TIMESTAMP NOT NULL,
            owner TEXT,
            permissions TEXT,
            tags TEXT,
            risk_score REAL DEFAULT 0.0,
            discovered_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_id) REFERENCES data_sources (id)
        )
        """)
        
        # Discovery jobs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS discovery_jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            source_ids TEXT NOT NULL,
            status TEXT NOT NULL,
            created_time TIMESTAMP NOT NULL,
            started_time TIMESTAMP,
            completed_time TIMESTAMP,
            total_files INTEGER DEFAULT 0,
            processed_files INTEGER DEFAULT 0,
            sensitive_files INTEGER DEFAULT 0,
            errors TEXT,
            metadata TEXT
        )
        """)
        
        # Data inventory table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_inventory (
            id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            file_path TEXT NOT NULL,
            data_catalog TEXT NOT NULL,
            lineage_info TEXT,
            data_owner TEXT,
            retention_policy TEXT,
            compliance_tags TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (source_id) REFERENCES data_sources (id)
        )
        """)
        
        # Performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_data_classification ON discovered_data(classification)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_data_sensitivity ON discovered_data(sensitivity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_data_source ON discovered_data(source_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovered_data_hash ON discovered_data(file_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_discovery_jobs_status ON discovery_jobs(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_data_inventory_owner ON data_inventory(data_owner)")
        
        conn.commit()
        conn.close()
        
        self.logger.info("Database initialized with optimized schema")


    def _load_classification_rules(self):
        """Load classification rules from database and configuration."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM classification_rules WHERE enabled = 1")
        rows = cursor.fetchall()
        
        for row in rows:
            rule = ClassificationRule(
                id=row[0],
                name=row[1],
                classification=DataClassification(row[2]),
                sensitivity=DataSensitivityLevel(row[3]),
                pattern=row[4],
                pattern_type=row[5],
                confidence_threshold=row[6],
                enabled=bool(row[7]),
                priority=row[8],
                metadata=json.loads(row[9]) if row[9] else {}
            )
            self.classification_rules[rule.id] = rule
        
        conn.close()
        
        # Add default ISECTECH rules if none exist
        if not self.classification_rules:
            self._create_default_classification_rules()
        
        self.logger.info(f"Loaded {len(self.classification_rules)} classification rules")


    def _create_default_classification_rules(self):
        """Create default ISECTECH-specific classification rules."""
        default_rules = [
            {
                "id": "isec_ssn_rule",
                "name": "Social Security Number Detection",
                "classification": DataClassification.PII,
                "sensitivity": DataSensitivityLevel.CONFIDENTIAL,
                "pattern": r"\b(?:\d{3}-?\d{2}-?\d{4})\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.9,
                "priority": 1
            },
            {
                "id": "isec_credit_card_rule",
                "name": "Credit Card Number Detection",
                "classification": DataClassification.PCI,
                "sensitivity": DataSensitivityLevel.RESTRICTED,
                "pattern": r"\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.85,
                "priority": 1
            },
            {
                "id": "isec_email_rule",
                "name": "Email Address Detection",
                "classification": DataClassification.PII,
                "sensitivity": DataSensitivityLevel.INTERNAL,
                "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.8,
                "priority": 2
            },
            {
                "id": "isec_phone_rule",
                "name": "Phone Number Detection",
                "classification": DataClassification.PII,
                "sensitivity": DataSensitivityLevel.INTERNAL,
                "pattern": r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.75,
                "priority": 3
            },
            {
                "id": "isec_medical_record_rule",
                "name": "Medical Record Number Detection",
                "classification": DataClassification.PHI,
                "sensitivity": DataSensitivityLevel.RESTRICTED,
                "pattern": r"\b(?:MRN|MR|Medical Record|Patient ID)[-:\s]*([A-Z0-9]{6,12})\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.9,
                "priority": 1
            },
            {
                "id": "isec_trade_secret_rule",
                "name": "ISECTECH Trade Secret Detection",
                "classification": DataClassification.TRADE_SECRET,
                "sensitivity": DataSensitivityLevel.TOP_SECRET,
                "pattern": r"(?i)\b(?:proprietary|confidential|trade secret|internal only|isectech exclusive)\b",
                "pattern_type": "regex",
                "confidence_threshold": 0.7,
                "priority": 1
            }
        ]
        
        for rule_data in default_rules:
            rule = ClassificationRule(**rule_data)
            self.add_classification_rule(rule)


    def _load_data_sources(self):
        """Load data sources from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM data_sources WHERE enabled = 1")
        rows = cursor.fetchall()
        
        for row in rows:
            # Decrypt credentials
            encrypted_creds = row[4]
            credentials = json.loads(self.encryption.decrypt(encrypted_creds))
            
            source = DataSource(
                id=row[0],
                name=row[1],
                type=row[2],
                connection_string=row[3],
                credentials=credentials,
                enabled=bool(row[5]),
                scan_schedule=row[6],
                last_scan=datetime.fromisoformat(row[7]) if row[7] else None,
                metadata=json.loads(row[8]) if row[8] else {}
            )
            self.data_sources[source.id] = source
        
        conn.close()
        self.logger.info(f"Loaded {len(self.data_sources)} data sources")


    async def discover_data_async(self, source_ids: Optional[List[str]] = None, 
                                job_name: Optional[str] = None) -> str:
        """
        Start asynchronous data discovery across specified sources.
        
        Args:
            source_ids: List of source IDs to scan. If None, scans all enabled sources.
            job_name: Optional job name for tracking
            
        Returns:
            Job ID for tracking discovery progress
        """
        if source_ids is None:
            source_ids = list(self.data_sources.keys())
        
        job_id = f"discovery_{int(time.time())}_{hashlib.md5(''.join(source_ids).encode()).hexdigest()[:8]}"
        job_name = job_name or f"Discovery Job {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Create discovery job
        job = DiscoveryJob(
            id=job_id,
            name=job_name,
            source_ids=source_ids,
            status=DiscoveryStatus.PENDING,
            created_time=datetime.now(),
            errors=[]
        )
        
        # Save job to database
        self._save_discovery_job(job)
        
        # Start discovery in background
        asyncio.create_task(self._run_discovery_job(job))
        
        self.logger.info(f"Started discovery job {job_id} for sources: {source_ids}")
        return job_id


    async def _run_discovery_job(self, job: DiscoveryJob):
        """Execute discovery job across all specified sources."""
        try:
            job.status = DiscoveryStatus.IN_PROGRESS
            job.started_time = datetime.now()
            self._save_discovery_job(job)
            
            total_discovered = 0
            
            # Process each data source
            for source_id in job.source_ids:
                if source_id not in self.data_sources:
                    error = f"Data source {source_id} not found"
                    job.errors.append(error)
                    self.logger.error(error)
                    continue
                
                source = self.data_sources[source_id]
                self.logger.info(f"Starting discovery for source: {source.name}")
                
                try:
                    discovered_count = await self._discover_from_source(source, job)
                    total_discovered += discovered_count
                    
                except Exception as e:
                    error = f"Error discovering from source {source.name}: {str(e)}"
                    job.errors.append(error)
                    self.logger.error(error, exc_info=True)
            
            # Complete job
            job.status = DiscoveryStatus.COMPLETED
            job.completed_time = datetime.now()
            job.sensitive_files = total_discovered
            
            self.metrics.increment("discovery_jobs_completed")
            self.metrics.gauge("discovery_sensitive_files_found", total_discovered)
            
        except Exception as e:
            job.status = DiscoveryStatus.FAILED
            job.errors.append(f"Job failed: {str(e)}")
            self.logger.error(f"Discovery job {job.id} failed", exc_info=True)
            self.metrics.increment("discovery_jobs_failed")
        
        finally:
            job.completed_time = datetime.now()
            self._save_discovery_job(job)
            
            self.logger.info(f"Discovery job {job.id} completed with status: {job.status.value}")


    async def _discover_from_source(self, source: DataSource, job: DiscoveryJob) -> int:
        """Discover data from a specific source."""
        discovered_count = 0
        
        if source.type == "filesystem":
            discovered_count = await self._discover_filesystem(source, job)
        elif source.type == "database":
            discovered_count = await self._discover_database(source, job)
        elif source.type == "cloud_storage":
            discovered_count = await self._discover_cloud_storage(source, job)
        elif source.type == "api":
            discovered_count = await self._discover_api_source(source, job)
        else:
            raise ValueError(f"Unsupported source type: {source.type}")
        
        # Update source last scan time
        source.last_scan = datetime.now()
        self._save_data_source(source)
        
        return discovered_count


    async def _discover_filesystem(self, source: DataSource, job: DiscoveryJob) -> int:
        """Discover data from filesystem source."""
        root_path = Path(source.connection_string)
        if not root_path.exists():
            raise FileNotFoundError(f"Path does not exist: {root_path}")
        
        discovered_count = 0
        semaphore = asyncio.Semaphore(10)  # Limit concurrent file processing
        
        async def process_file(file_path: Path):
            async with semaphore:
                try:
                    if file_path.is_file() and not file_path.is_symlink():
                        discovered_data = await self._analyze_file(file_path, source)
                        if discovered_data:
                            self._save_discovered_data(discovered_data)
                            return 1
                except Exception as e:
                    self.logger.debug(f"Error processing file {file_path}: {str(e)}")
                return 0
        
        # Process files concurrently
        tasks = []
        for file_path in root_path.rglob("*"):
            if file_path.is_file():
                job.total_files += 1
                task = asyncio.create_task(process_file(file_path))
                tasks.append(task)
        
        # Execute all tasks and collect results
        for task in asyncio.as_completed(tasks):
            result = await task
            discovered_count += result
            job.processed_files += 1
            
            # Update job progress periodically
            if job.processed_files % 100 == 0:
                self._save_discovery_job(job)
        
        return discovered_count


    async def _discover_database(self, source: DataSource, job: DiscoveryJob) -> int:
        """Discover data from database source."""
        discovered_count = 0
        
        try:
            engine = create_engine(source.connection_string)
            
            with engine.connect() as conn:
                # Get all tables
                if "mysql" in source.connection_string or "postgresql" in source.connection_string:
                    tables_query = text("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()")
                elif "sqlite" in source.connection_string:
                    tables_query = text("SELECT name FROM sqlite_master WHERE type='table'")
                else:
                    raise ValueError(f"Unsupported database type in connection string")
                
                tables_result = conn.execute(tables_query)
                tables = [row[0] for row in tables_result]
                
                # Analyze each table
                for table_name in tables:
                    job.total_files += 1
                    
                    try:
                        # Sample data from table (limit for performance)
                        sample_query = text(f"SELECT * FROM {table_name} LIMIT 1000")
                        sample_result = conn.execute(sample_query)
                        
                        # Analyze sample data
                        for row in sample_result:
                            row_data = dict(row._mapping)
                            discovered_data = await self._analyze_database_row(
                                table_name, row_data, source
                            )
                            
                            if discovered_data:
                                for data in discovered_data:
                                    self._save_discovered_data(data)
                                    discovered_count += 1
                    
                    except Exception as e:
                        error = f"Error analyzing table {table_name}: {str(e)}"
                        job.errors.append(error)
                        self.logger.warning(error)
                    
                    job.processed_files += 1
        
        except SQLAlchemyError as e:
            raise Exception(f"Database connection error: {str(e)}")
        
        return discovered_count


    async def _discover_cloud_storage(self, source: DataSource, job: DiscoveryJob) -> int:
        """Discover data from cloud storage source."""
        discovered_count = 0
        
        if source.metadata.get("provider") == "aws_s3":
            discovered_count = await self._discover_aws_s3(source, job)
        elif source.metadata.get("provider") == "azure_blob":
            discovered_count = await self._discover_azure_blob(source, job)
        elif source.metadata.get("provider") == "gcp_storage":
            discovered_count = await self._discover_gcp_storage(source, job)
        else:
            raise ValueError(f"Unsupported cloud storage provider")
        
        return discovered_count


    async def _discover_aws_s3(self, source: DataSource, job: DiscoveryJob) -> int:
        """Discover data from AWS S3."""
        discovered_count = 0
        
        s3_client = boto3.client(
            's3',
            aws_access_key_id=source.credentials['access_key_id'],
            aws_secret_access_key=source.credentials['secret_access_key'],
            region_name=source.credentials.get('region', 'us-east-1')
        )
        
        bucket_name = source.metadata['bucket_name']
        prefix = source.metadata.get('prefix', '')
        
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)
        
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    job.total_files += 1
                    
                    try:
                        # Download and analyze object
                        response = s3_client.get_object(Bucket=bucket_name, Key=obj['Key'])
                        content = response['Body'].read()
                        
                        discovered_data = await self._analyze_content(
                            obj['Key'], content, source
                        )
                        
                        if discovered_data:
                            self._save_discovered_data(discovered_data)
                            discovered_count += 1
                    
                    except Exception as e:
                        self.logger.debug(f"Error processing S3 object {obj['Key']}: {str(e)}")
                    
                    job.processed_files += 1
        
        return discovered_count


    async def _analyze_file(self, file_path: Path, source: DataSource) -> Optional[DiscoveredData]:
        """Analyze a file for sensitive data."""
        try:
            # Get file metadata
            stat = file_path.stat()
            file_size = stat.st_size
            modified_time = datetime.fromtimestamp(stat.st_mtime)
            created_time = datetime.fromtimestamp(stat.st_ctime)
            
            # Skip binary files and large files
            if file_size > self.config.get("dlp.max_file_size", 100 * 1024 * 1024):  # 100MB
                return None
            
            # Detect file type
            mime_type = magic.from_file(str(file_path), mime=True)
            if mime_type.startswith('image/') or mime_type.startswith('video/') or mime_type.startswith('audio/'):
                return None
            
            # Read file content
            async with aiofiles.open(file_path, 'rb') as f:
                content = await f.read()
            
            # Detect encoding and decode
            encoding = chardet.detect(content)['encoding']
            if not encoding:
                return None
            
            try:
                text_content = content.decode(encoding)
            except UnicodeDecodeError:
                return None
            
            # Generate file hash
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Check if already processed
            cache_key = f"file_analysis:{file_hash}"
            cached_result = self.redis_client.get(cache_key)
            if cached_result:
                return json.loads(cached_result)
            
            # Classify content
            classification_results = await self._classify_content(text_content)
            
            if classification_results:
                # Create discovered data record
                discovered_data = DiscoveredData(
                    id=f"file_{hashlib.md5(str(file_path).encode()).hexdigest()}",
                    source_id=source.id,
                    file_path=str(file_path),
                    data_type=mime_type,
                    classification=classification_results['classification'],
                    sensitivity=classification_results['sensitivity'],
                    confidence_score=classification_results['confidence'],
                    match_details=classification_results['matches'],
                    file_size=file_size,
                    file_hash=file_hash,
                    created_time=created_time,
                    modified_time=modified_time,
                    owner=self._get_file_owner(file_path),
                    permissions=self._get_file_permissions(file_path),
                    tags=[],
                    risk_score=self._calculate_risk_score(classification_results)
                )
                
                # Cache result
                self.redis_client.setex(
                    cache_key, 
                    3600,  # 1 hour cache
                    json.dumps(asdict(discovered_data), default=str)
                )
                
                return discovered_data
        
        except Exception as e:
            self.logger.debug(f"Error analyzing file {file_path}: {str(e)}")
        
        return None


    async def _classify_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Classify content using classification rules."""
        best_match = None
        highest_confidence = 0.0
        all_matches = []
        
        for rule in sorted(self.classification_rules.values(), key=lambda r: r.priority):
            if not rule.enabled:
                continue
            
            matches = []
            confidence = 0.0
            
            if rule.pattern_type == "regex":
                pattern = re.compile(rule.pattern, re.IGNORECASE | re.MULTILINE)
                regex_matches = pattern.findall(content)
                
                if regex_matches:
                    matches = [{"match": match, "position": content.find(match)} for match in regex_matches]
                    confidence = min(0.95, rule.confidence_threshold + (len(regex_matches) * 0.05))
            
            elif rule.pattern_type == "keyword":
                keywords = rule.pattern.split(',')
                for keyword in keywords:
                    if keyword.strip().lower() in content.lower():
                        matches.append({"keyword": keyword.strip(), "found": True})
                
                if matches:
                    confidence = rule.confidence_threshold
            
            if matches and confidence >= rule.confidence_threshold:
                match_data = {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "classification": rule.classification,
                    "sensitivity": rule.sensitivity,
                    "confidence": confidence,
                    "matches": matches
                }
                
                all_matches.append(match_data)
                
                if confidence > highest_confidence:
                    highest_confidence = confidence
                    best_match = match_data
        
        if best_match:
            return {
                "classification": best_match["classification"],
                "sensitivity": best_match["sensitivity"],
                "confidence": highest_confidence,
                "matches": all_matches
            }
        
        return None


    def _calculate_risk_score(self, classification_results: Dict[str, Any]) -> float:
        """Calculate risk score based on classification results."""
        base_score = 0.0
        
        # Sensitivity level scoring
        sensitivity = classification_results['sensitivity']
        sensitivity_scores = {
            DataSensitivityLevel.PUBLIC: 0.1,
            DataSensitivityLevel.INTERNAL: 0.3,
            DataSensitivityLevel.CONFIDENTIAL: 0.6,
            DataSensitivityLevel.RESTRICTED: 0.8,
            DataSensitivityLevel.TOP_SECRET: 1.0
        }
        base_score += sensitivity_scores.get(sensitivity, 0.5)
        
        # Classification type scoring
        classification = classification_results['classification']
        classification_scores = {
            DataClassification.PII: 0.7,
            DataClassification.PHI: 0.9,
            DataClassification.PCI: 0.9,
            DataClassification.TRADE_SECRET: 1.0,
            DataClassification.INTELLECTUAL_PROPERTY: 0.8,
            DataClassification.FINANCIAL: 0.8,
            DataClassification.BIOMETRIC: 0.9,
            DataClassification.GOVERNMENT_ID: 0.8
        }
        base_score += classification_scores.get(classification, 0.5)
        
        # Confidence multiplier
        confidence = classification_results['confidence']
        base_score *= confidence
        
        # Match count multiplier
        match_count = len(classification_results.get('matches', []))
        multiplier = min(2.0, 1.0 + (match_count * 0.1))
        base_score *= multiplier
        
        return min(10.0, base_score * 5.0)  # Scale to 0-10


    def _get_file_owner(self, file_path: Path) -> Optional[str]:
        """Get file owner information."""
        try:
            import pwd
            stat = file_path.stat()
            return pwd.getpwuid(stat.st_uid).pw_name
        except:
            return None


    def _get_file_permissions(self, file_path: Path) -> Optional[str]:
        """Get file permissions."""
        try:
            stat = file_path.stat()
            return oct(stat.st_mode)[-3:]
        except:
            return None


    def add_classification_rule(self, rule: ClassificationRule):
        """Add a new classification rule."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO classification_rules 
        (id, name, classification, sensitivity, pattern, pattern_type, 
         confidence_threshold, enabled, priority, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule.id, rule.name, rule.classification.value, rule.sensitivity.value,
            rule.pattern, rule.pattern_type, rule.confidence_threshold,
            rule.enabled, rule.priority, json.dumps(rule.metadata or {})
        ))
        
        conn.commit()
        conn.close()
        
        self.classification_rules[rule.id] = rule
        self.logger.info(f"Added classification rule: {rule.name}")


    def add_data_source(self, source: DataSource):
        """Add a new data source."""
        # Encrypt credentials
        encrypted_creds = self.encryption.encrypt(json.dumps(source.credentials))
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO data_sources 
        (id, name, type, connection_string, credentials, enabled, 
         scan_schedule, last_scan, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            source.id, source.name, source.type, source.connection_string,
            encrypted_creds, source.enabled, source.scan_schedule,
            source.last_scan.isoformat() if source.last_scan else None,
            json.dumps(source.metadata or {})
        ))
        
        conn.commit()
        conn.close()
        
        self.data_sources[source.id] = source
        self.logger.info(f"Added data source: {source.name}")


    def _save_discovery_job(self, job: DiscoveryJob):
        """Save discovery job to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO discovery_jobs 
        (id, name, source_ids, status, created_time, started_time, 
         completed_time, total_files, processed_files, sensitive_files, 
         errors, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job.id, job.name, json.dumps(job.source_ids), job.status.value,
            job.created_time.isoformat(),
            job.started_time.isoformat() if job.started_time else None,
            job.completed_time.isoformat() if job.completed_time else None,
            job.total_files, job.processed_files, job.sensitive_files,
            json.dumps(job.errors or []), json.dumps(job.metadata or {})
        ))
        
        conn.commit()
        conn.close()


    def _save_discovered_data(self, data: DiscoveredData):
        """Save discovered data to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO discovered_data 
        (id, source_id, file_path, data_type, classification, sensitivity,
         confidence_score, match_details, file_size, file_hash, created_time,
         modified_time, owner, permissions, tags, risk_score)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data.id, data.source_id, data.file_path, data.data_type,
            data.classification.value, data.sensitivity.value,
            data.confidence_score, json.dumps(data.match_details),
            data.file_size, data.file_hash,
            data.created_time.isoformat(), data.modified_time.isoformat(),
            data.owner, data.permissions, json.dumps(data.tags or []),
            data.risk_score
        ))
        
        conn.commit()
        conn.close()
        
        # Update metrics
        self.metrics.increment("sensitive_data_discovered")
        self.metrics.increment(f"classification_{data.classification.value}")


    def get_discovery_job_status(self, job_id: str) -> Optional[DiscoveryJob]:
        """Get discovery job status."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM discovery_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        
        if row:
            job = DiscoveryJob(
                id=row[0],
                name=row[1],
                source_ids=json.loads(row[2]),
                status=DiscoveryStatus(row[3]),
                created_time=datetime.fromisoformat(row[4]),
                started_time=datetime.fromisoformat(row[5]) if row[5] else None,
                completed_time=datetime.fromisoformat(row[6]) if row[6] else None,
                total_files=row[7],
                processed_files=row[8],
                sensitive_files=row[9],
                errors=json.loads(row[10]) if row[10] else [],
                metadata=json.loads(row[11]) if row[11] else {}
            )
            conn.close()
            return job
        
        conn.close()
        return None


    def get_discovered_data(self, limit: int = 100, offset: int = 0, 
                          filters: Optional[Dict[str, Any]] = None) -> List[DiscoveredData]:
        """Get discovered data with filtering and pagination."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM discovered_data"
        params = []
        
        if filters:
            conditions = []
            if 'classification' in filters:
                conditions.append("classification = ?")
                params.append(filters['classification'])
            if 'sensitivity' in filters:
                conditions.append("sensitivity = ?")
                params.append(filters['sensitivity'])
            if 'source_id' in filters:
                conditions.append("source_id = ?")
                params.append(filters['source_id'])
            if 'min_risk_score' in filters:
                conditions.append("risk_score >= ?")
                params.append(filters['min_risk_score'])
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY discovered_time DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        discovered_data = []
        for row in rows:
            data = DiscoveredData(
                id=row[0],
                source_id=row[1],
                file_path=row[2],
                data_type=row[3],
                classification=DataClassification(row[4]),
                sensitivity=DataSensitivityLevel(row[5]),
                confidence_score=row[6],
                match_details=json.loads(row[7]),
                file_size=row[8],
                file_hash=row[9],
                created_time=datetime.fromisoformat(row[10]),
                modified_time=datetime.fromisoformat(row[11]),
                owner=row[12],
                permissions=row[13],
                tags=json.loads(row[14]) if row[14] else [],
                risk_score=row[15]
            )
            discovered_data.append(data)
        
        conn.close()
        return discovered_data


    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery engine statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total discovered data
        cursor.execute("SELECT COUNT(*) FROM discovered_data")
        total_discovered = cursor.fetchone()[0]
        
        # By classification
        cursor.execute("""
        SELECT classification, COUNT(*) 
        FROM discovered_data 
        GROUP BY classification
        """)
        by_classification = dict(cursor.fetchall())
        
        # By sensitivity
        cursor.execute("""
        SELECT sensitivity, COUNT(*) 
        FROM discovered_data 
        GROUP BY sensitivity
        """)
        by_sensitivity = dict(cursor.fetchall())
        
        # High-risk data
        cursor.execute("SELECT COUNT(*) FROM discovered_data WHERE risk_score >= 7.0")
        high_risk_count = cursor.fetchone()[0]
        
        # Recent discoveries (last 24 hours)
        yesterday = datetime.now() - timedelta(days=1)
        cursor.execute("""
        SELECT COUNT(*) FROM discovered_data 
        WHERE discovered_time >= ?
        """, (yesterday.isoformat(),))
        recent_discoveries = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_discovered": total_discovered,
            "by_classification": by_classification,
            "by_sensitivity": by_sensitivity,
            "high_risk_count": high_risk_count,
            "recent_discoveries": recent_discoveries,
            "active_sources": len([s for s in self.data_sources.values() if s.enabled]),
            "classification_rules": len(self.classification_rules)
        }


    async def create_data_inventory(self, source_id: str) -> Dict[str, Any]:
        """Create comprehensive data inventory for a source."""
        if source_id not in self.data_sources:
            raise ValueError(f"Data source {source_id} not found")
        
        source = self.data_sources[source_id]
        
        # Get all discovered data for this source
        discovered_data = self.get_discovered_data(
            limit=10000, 
            filters={"source_id": source_id}
        )
        
        # Create inventory summary
        inventory = {
            "source_id": source_id,
            "source_name": source.name,
            "total_files": len(discovered_data),
            "data_types": {},
            "classifications": {},
            "sensitivity_levels": {},
            "risk_distribution": {
                "low": 0,      # 0-3
                "medium": 0,   # 3-7
                "high": 0,     # 7-10
                "critical": 0  # 10
            },
            "owners": {},
            "created_time": datetime.now().isoformat()
        }
        
        for data in discovered_data:
            # Data types
            inventory["data_types"][data.data_type] = inventory["data_types"].get(data.data_type, 0) + 1
            
            # Classifications
            classification = data.classification.value
            inventory["classifications"][classification] = inventory["classifications"].get(classification, 0) + 1
            
            # Sensitivity levels
            sensitivity = data.sensitivity.value
            inventory["sensitivity_levels"][sensitivity] = inventory["sensitivity_levels"].get(sensitivity, 0) + 1
            
            # Risk distribution
            if data.risk_score < 3:
                inventory["risk_distribution"]["low"] += 1
            elif data.risk_score < 7:
                inventory["risk_distribution"]["medium"] += 1
            elif data.risk_score < 10:
                inventory["risk_distribution"]["high"] += 1
            else:
                inventory["risk_distribution"]["critical"] += 1
            
            # Owners
            if data.owner:
                inventory["owners"][data.owner] = inventory["owners"].get(data.owner, 0) + 1
        
        # Save inventory to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO data_inventory 
        (id, source_id, file_path, data_catalog, lineage_info, data_owner, 
         retention_policy, compliance_tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f"inventory_{source_id}_{int(time.time())}",
            source_id,
            f"inventory_summary_{source_id}",
            json.dumps(inventory),
            json.dumps({"created": datetime.now().isoformat()}),
            "system",
            json.dumps({"default_retention": "7_years"}),
            json.dumps(["gdpr", "hipaa", "pci_dss"])
        ))
        
        conn.commit()
        conn.close()
        
        self.logger.info(f"Created data inventory for source {source.name}")
        return inventory


    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=True)
        if hasattr(self, 'redis_client'):
            self.redis_client.close()