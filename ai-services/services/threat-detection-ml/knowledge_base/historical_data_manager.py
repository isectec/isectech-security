"""
Historical Threat Data Manager for Long-term Pattern Analysis

This module manages historical threat data storage, retrieval, and analysis
with support for data retention policies, archival, and temporal pattern
discovery across multiple time horizons.
"""

import asyncio
import logging
import json
import uuid
import gzip
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict, deque
from enum import Enum
import threading
import time
import sqlite3
import os
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import DBSCAN
import networkx as nx

from ..data_pipeline.collector import SecurityEvent
from ..threat_hunting.automated_threat_hunter import ThreatHuntResult
from .threat_pattern_database import ThreatPattern, PatternMatch
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector


logger = logging.getLogger(__name__)


class DataRetentionPolicy(Enum):
    """Data retention policies for different data types."""
    REAL_TIME = "real_time"  # 7 days
    SHORT_TERM = "short_term"  # 30 days
    MEDIUM_TERM = "medium_term"  # 90 days
    LONG_TERM = "long_term"  # 1 year
    ARCHIVAL = "archival"  # 7 years
    PERMANENT = "permanent"  # Forever


class DataType(Enum):
    """Types of historical data stored."""
    SECURITY_EVENTS = "security_events"
    THREAT_PATTERNS = "threat_patterns"
    HUNT_RESULTS = "hunt_results"
    PATTERN_MATCHES = "pattern_matches"
    BEHAVIORAL_ANOMALIES = "behavioral_anomalies"
    IOC_DATA = "ioc_data"
    ATTRIBUTION_DATA = "attribution_data"


@dataclass
class DataPartition:
    """Represents a time-based data partition."""
    partition_id: str
    data_type: DataType
    start_time: datetime
    end_time: datetime
    record_count: int
    file_path: str
    compressed: bool
    retention_policy: DataRetentionPolicy
    created_at: datetime
    last_accessed: datetime
    archive_status: str  # 'active', 'archived', 'compressed'


@dataclass
class TemporalPattern:
    """Pattern discovered through temporal analysis."""
    pattern_id: str
    pattern_name: str
    description: str
    time_range: Tuple[datetime, datetime]
    frequency: str  # 'hourly', 'daily', 'weekly', 'monthly', 'seasonal'
    confidence_score: float
    
    # Pattern characteristics
    peak_times: List[datetime]
    activity_cycles: List[Dict[str, Any]]
    seasonal_components: Dict[str, float]
    trend_direction: str  # 'increasing', 'decreasing', 'stable', 'cyclical'
    
    # Supporting data
    event_count: int
    affected_entities: List[str]
    correlated_patterns: List[str]
    statistical_significance: float
    
    # Context
    threat_actors: List[str] = field(default_factory=list)
    campaign_associations: List[str] = field(default_factory=list)
    geographic_distribution: Dict[str, int] = field(default_factory=dict)
    
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


class HistoricalThreatDataManager:
    """
    Comprehensive manager for historical threat data with advanced analytics.
    """
    
    def __init__(self, settings: Settings, data_directory: str = None):
        self.settings = settings
        self.data_directory = Path(data_directory or "./historical_threat_data")
        self.metrics = MetricsCollector("historical_data_manager")
        
        # Create data directory structure
        self.data_directory.mkdir(parents=True, exist_ok=True)
        for data_type in DataType:
            (self.data_directory / data_type.value).mkdir(exist_ok=True)
        
        # Database for metadata and indexing
        self.metadata_db_path = self.data_directory / "metadata.db"
        self._db_lock = threading.RLock()
        self._connection = None
        
        # In-memory indexes for performance
        self._partition_index: Dict[str, DataPartition] = {}
        self._time_index: Dict[DataType, List[Tuple[datetime, datetime, str]]] = defaultdict(list)
        
        # Temporal analysis components
        self.temporal_patterns: Dict[str, TemporalPattern] = {}
        self.trend_analyzer = None
        
        # Background tasks
        self._cleanup_task = None
        self._archive_task = None
        self._analysis_task = None
        self._stop_tasks = False
        
        # Initialize components
        self._initialize_metadata_database()
        self._load_partition_index()
        self._start_background_tasks()
        
        logger.info(f"Initialized historical threat data manager at {self.data_directory}")
    
    def _initialize_metadata_database(self) -> None:
        """Initialize SQLite database for metadata management."""
        with self._db_lock:
            self._connection = sqlite3.connect(
                str(self.metadata_db_path),
                check_same_thread=False,
                timeout=30.0
            )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            
            # Create tables
            self._create_metadata_tables()
            
            logger.info("Initialized historical data metadata database")
    
    def _create_metadata_tables(self) -> None:
        """Create metadata tables."""
        # Data partitions table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS data_partitions (
                partition_id TEXT PRIMARY KEY,
                data_type TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                record_count INTEGER DEFAULT 0,
                file_path TEXT NOT NULL,
                compressed INTEGER DEFAULT 0,
                retention_policy TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed TEXT NOT NULL,
                archive_status TEXT DEFAULT 'active'
            )
        """)
        
        # Temporal patterns table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS temporal_patterns (
                pattern_id TEXT PRIMARY KEY,
                pattern_name TEXT NOT NULL,
                description TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                frequency TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                peak_times TEXT,
                activity_cycles TEXT,
                seasonal_components TEXT,
                trend_direction TEXT,
                event_count INTEGER DEFAULT 0,
                affected_entities TEXT,
                correlated_patterns TEXT,
                statistical_significance REAL DEFAULT 0.0,
                threat_actors TEXT,
                campaign_associations TEXT,
                geographic_distribution TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        
        # Data access logs table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS data_access_logs (
                access_id TEXT PRIMARY KEY,
                partition_id TEXT NOT NULL,
                access_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                query_details TEXT,
                records_returned INTEGER DEFAULT 0,
                FOREIGN KEY (partition_id) REFERENCES data_partitions (partition_id)
            )
        """)
        
        # Create indexes
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_partitions_type ON data_partitions (data_type)",
            "CREATE INDEX IF NOT EXISTS idx_partitions_time ON data_partitions (start_time, end_time)",
            "CREATE INDEX IF NOT EXISTS idx_partitions_status ON data_partitions (archive_status)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_time ON temporal_patterns (start_time, end_time)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_frequency ON temporal_patterns (frequency)",
            "CREATE INDEX IF NOT EXISTS idx_access_logs_time ON data_access_logs (timestamp)"
        ]
        
        for index_sql in indexes:
            self._connection.execute(index_sql)
        
        self._connection.commit()
    
    async def store_historical_data(
        self,
        data_type: DataType,
        data: Union[List[SecurityEvent], List[ThreatHuntResult], List[PatternMatch]],
        time_range: Tuple[datetime, datetime],
        retention_policy: DataRetentionPolicy = DataRetentionPolicy.MEDIUM_TERM
    ) -> str:
        """Store historical data in time-based partitions."""
        try:
            partition_id = str(uuid.uuid4())
            start_time, end_time = time_range
            
            # Determine storage path
            date_str = start_time.strftime("%Y%m%d")
            partition_dir = self.data_directory / data_type.value / date_str
            partition_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = partition_dir / f"{partition_id}.json"
            
            # Serialize and store data
            serialized_data = []
            for item in data:
                if hasattr(item, '__dict__'):
                    # Convert dataclass or object to dict
                    if hasattr(item, 'to_dict'):
                        serialized_data.append(item.to_dict())
                    else:
                        serialized_data.append(asdict(item) if hasattr(item, '__dataclass_fields__') else item.__dict__)
                else:
                    serialized_data.append(item)
            
            # Write data to file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(serialized_data, f, default=self._json_serializer, indent=2)
            
            # Create partition metadata
            partition = DataPartition(
                partition_id=partition_id,
                data_type=data_type,
                start_time=start_time,
                end_time=end_time,
                record_count=len(data),
                file_path=str(file_path),
                compressed=False,
                retention_policy=retention_policy,
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow(),
                archive_status='active'
            )
            
            # Store metadata in database
            await self._store_partition_metadata(partition)
            
            # Update indexes
            self._partition_index[partition_id] = partition
            self._time_index[data_type].append((start_time, end_time, partition_id))
            self._time_index[data_type].sort()  # Keep sorted by start time
            
            self.metrics.increment_counter(
                "historical_data_stored",
                tags={"data_type": data_type.value, "record_count": len(data)}
            )
            
            logger.info(f"Stored {len(data)} {data_type.value} records in partition {partition_id}")
            
            return partition_id
            
        except Exception as e:
            logger.error(f"Error storing historical data: {e}")
            raise
    
    async def retrieve_historical_data(
        self,
        data_type: DataType,
        time_range: Tuple[datetime, datetime],
        filters: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve historical data within specified time range."""
        try:
            start_time, end_time = time_range
            relevant_partitions = []
            
            # Find overlapping partitions
            for partition_start, partition_end, partition_id in self._time_index[data_type]:
                if (partition_start <= end_time and partition_end >= start_time):
                    relevant_partitions.append(partition_id)
            
            if not relevant_partitions:
                logger.info(f"No partitions found for {data_type.value} in time range {start_time} - {end_time}")
                return []
            
            # Load data from partitions
            all_data = []
            for partition_id in relevant_partitions:
                partition = self._partition_index.get(partition_id)
                if not partition:
                    continue
                
                # Load partition data
                partition_data = await self._load_partition_data(partition)
                
                # Filter data by time range and additional filters
                filtered_data = self._filter_data(partition_data, start_time, end_time, filters)
                all_data.extend(filtered_data)
                
                # Update last accessed time
                await self._update_partition_access(partition_id)
            
            # Apply limit if specified
            if limit and len(all_data) > limit:
                all_data = all_data[:limit]
            
            # Log access
            await self._log_data_access(relevant_partitions, 'retrieve', len(all_data))
            
            self.metrics.increment_counter(
                "historical_data_retrieved",
                tags={"data_type": data_type.value, "record_count": len(all_data)}
            )
            
            logger.info(f"Retrieved {len(all_data)} {data_type.value} records from {len(relevant_partitions)} partitions")
            
            return all_data
            
        except Exception as e:
            logger.error(f"Error retrieving historical data: {e}")
            return []
    
    async def analyze_temporal_patterns(
        self,
        data_type: DataType,
        analysis_period: timedelta = timedelta(days=90),
        pattern_types: List[str] = None
    ) -> List[TemporalPattern]:
        """Analyze temporal patterns in historical data."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - analysis_period
            
            # Retrieve historical data
            data = await self.retrieve_historical_data(
                data_type, (start_time, end_time)
            )
            
            if not data:
                logger.info(f"No data available for temporal analysis of {data_type.value}")
                return []
            
            patterns = []
            
            # Convert to DataFrame for analysis
            df = pd.DataFrame(data)
            
            # Ensure timestamp column exists
            timestamp_col = None
            for col in ['timestamp', 'created_at', 'first_observed', 'hunt_start_time']:
                if col in df.columns:
                    timestamp_col = col
                    break
            
            if not timestamp_col:
                logger.warning(f"No timestamp column found in {data_type.value} data")
                return patterns
            
            # Convert timestamps
            df[timestamp_col] = pd.to_datetime(df[timestamp_col])
            df = df.sort_values(timestamp_col)
            
            # Analyze different time frequencies
            frequencies = [
                ('hourly', 'H'),
                ('daily', 'D'),
                ('weekly', 'W'),
                ('monthly', 'M')
            ]
            
            for freq_name, freq_code in frequencies:
                pattern = await self._analyze_frequency_pattern(
                    df, timestamp_col, freq_name, freq_code, data_type
                )
                if pattern:
                    patterns.append(pattern)
            
            # Store discovered patterns
            for pattern in patterns:
                await self._store_temporal_pattern(pattern)
                self.temporal_patterns[pattern.pattern_id] = pattern
            
            self.metrics.increment_counter(
                "temporal_patterns_analyzed",
                tags={"data_type": data_type.value, "patterns_found": len(patterns)}
            )
            
            logger.info(f"Discovered {len(patterns)} temporal patterns in {data_type.value}")
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing temporal patterns: {e}")
            return []
    
    async def get_trend_analysis(
        self,
        data_type: DataType,
        metric: str,
        period: timedelta = timedelta(days=30),
        granularity: str = 'daily'
    ) -> Dict[str, Any]:
        """Get trend analysis for a specific metric."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - period
            
            # Retrieve historical data
            data = await self.retrieve_historical_data(
                data_type, (start_time, end_time)
            )
            
            if not data:
                return {'trend': 'no_data', 'message': 'Insufficient data for trend analysis'}
            
            # Convert to DataFrame
            df = pd.DataFrame(data)
            
            # Find timestamp column
            timestamp_col = None
            for col in ['timestamp', 'created_at', 'first_observed']:
                if col in df.columns:
                    timestamp_col = col
                    break
            
            if not timestamp_col:
                return {'trend': 'error', 'message': 'No timestamp column found'}
            
            # Convert timestamps and set as index
            df[timestamp_col] = pd.to_datetime(df[timestamp_col])
            df.set_index(timestamp_col, inplace=True)
            
            # Resample data based on granularity
            freq_map = {
                'hourly': 'H',
                'daily': 'D',
                'weekly': 'W',
                'monthly': 'M'
            }
            
            freq = freq_map.get(granularity, 'D')
            
            if metric == 'count':
                # Count records per time period
                trend_data = df.resample(freq).size()
            elif metric in df.columns:
                # Analyze specific metric
                if df[metric].dtype in [np.float64, np.int64]:
                    trend_data = df[metric].resample(freq).mean()
                else:
                    trend_data = df[metric].resample(freq).count()
            else:
                return {'trend': 'error', 'message': f'Metric {metric} not found in data'}
            
            # Calculate trend direction
            if len(trend_data) < 2:
                trend_direction = 'insufficient_data'
            else:
                # Simple linear trend
                x = np.arange(len(trend_data))
                y = trend_data.values
                
                # Remove NaN values
                mask = ~np.isnan(y)
                if np.sum(mask) < 2:
                    trend_direction = 'insufficient_data'
                else:
                    x_clean = x[mask]
                    y_clean = y[mask]
                    
                    # Calculate trend slope
                    slope = np.polyfit(x_clean, y_clean, 1)[0]
                    
                    if slope > 0.1:
                        trend_direction = 'increasing'
                    elif slope < -0.1:
                        trend_direction = 'decreasing'
                    else:
                        trend_direction = 'stable'
            
            # Calculate statistics
            stats = {
                'mean': float(np.nanmean(trend_data)),
                'std': float(np.nanstd(trend_data)),
                'min': float(np.nanmin(trend_data)),
                'max': float(np.nanmax(trend_data)),
                'trend_direction': trend_direction,
                'data_points': len(trend_data),
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                }
            }
            
            # Convert trend data to list for JSON serialization
            stats['trend_data'] = [
                {
                    'timestamp': ts.isoformat(),
                    'value': float(val) if not np.isnan(val) else 0
                }
                for ts, val in trend_data.items()
            ]
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting trend analysis: {e}")
            return {'trend': 'error', 'message': str(e)}
    
    async def compress_old_partitions(self, age_threshold: timedelta = timedelta(days=30)) -> int:
        """Compress old data partitions to save storage space."""
        compressed_count = 0
        
        try:
            cutoff_time = datetime.utcnow() - age_threshold
            
            for partition in self._partition_index.values():
                if (partition.created_at < cutoff_time and 
                    not partition.compressed and 
                    partition.archive_status == 'active'):
                    
                    try:
                        # Compress partition file
                        original_path = Path(partition.file_path)
                        compressed_path = original_path.with_suffix('.json.gz')
                        
                        with open(original_path, 'rb') as f_in:
                            with gzip.open(compressed_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        
                        # Remove original file
                        original_path.unlink()
                        
                        # Update partition metadata
                        partition.file_path = str(compressed_path)
                        partition.compressed = True
                        partition.archive_status = 'compressed'
                        
                        await self._update_partition_metadata(partition)
                        
                        compressed_count += 1
                        
                        logger.debug(f"Compressed partition {partition.partition_id}")
                        
                    except Exception as e:
                        logger.error(f"Error compressing partition {partition.partition_id}: {e}")
            
            if compressed_count > 0:
                self.metrics.increment_counter("partitions_compressed", value=compressed_count)
                logger.info(f"Compressed {compressed_count} historical data partitions")
            
        except Exception as e:
            logger.error(f"Error compressing partitions: {e}")
        
        return compressed_count
    
    async def archive_expired_data(self) -> Dict[str, int]:
        """Archive data based on retention policies."""
        archive_counts = {}
        
        try:
            current_time = datetime.utcnow()
            retention_periods = {
                DataRetentionPolicy.REAL_TIME: timedelta(days=7),
                DataRetentionPolicy.SHORT_TERM: timedelta(days=30),
                DataRetentionPolicy.MEDIUM_TERM: timedelta(days=90),
                DataRetentionPolicy.LONG_TERM: timedelta(days=365),
                DataRetentionPolicy.ARCHIVAL: timedelta(days=365*7)
                # PERMANENT data is never archived
            }
            
            for partition in list(self._partition_index.values()):
                if partition.retention_policy == DataRetentionPolicy.PERMANENT:
                    continue
                
                retention_period = retention_periods.get(partition.retention_policy)
                if not retention_period:
                    continue
                
                if current_time - partition.created_at > retention_period:
                    try:
                        # Move to archive or delete based on policy
                        if partition.retention_policy == DataRetentionPolicy.ARCHIVAL:
                            # Move to archive directory
                            await self._move_to_archive(partition)
                            archive_counts['archived'] = archive_counts.get('archived', 0) + 1
                        else:
                            # Delete expired data
                            await self._delete_partition(partition)
                            archive_counts['deleted'] = archive_counts.get('deleted', 0) + 1
                            
                    except Exception as e:
                        logger.error(f"Error archiving partition {partition.partition_id}: {e}")
            
            if archive_counts:
                for action, count in archive_counts.items():
                    self.metrics.increment_counter(f"partitions_{action}", value=count)
                
                logger.info(f"Archived expired data: {archive_counts}")
            
        except Exception as e:
            logger.error(f"Error archiving expired data: {e}")
        
        return archive_counts
    
    # Private helper methods
    def _json_serializer(self, obj) -> str:
        """Custom JSON serializer for complex objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.integer, np.floating)):
            return obj.item()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    def _load_partition_index(self) -> None:
        """Load partition index from metadata database."""
        try:
            with self._db_lock:
                cursor = self._connection.execute("SELECT * FROM data_partitions")
                
                for row in cursor.fetchall():
                    partition = DataPartition(
                        partition_id=row[0],
                        data_type=DataType(row[1]),
                        start_time=datetime.fromisoformat(row[2]),
                        end_time=datetime.fromisoformat(row[3]),
                        record_count=row[4],
                        file_path=row[5],
                        compressed=bool(row[6]),
                        retention_policy=DataRetentionPolicy(row[7]),
                        created_at=datetime.fromisoformat(row[8]),
                        last_accessed=datetime.fromisoformat(row[9]),
                        archive_status=row[10]
                    )
                    
                    self._partition_index[partition.partition_id] = partition
                    self._time_index[partition.data_type].append(
                        (partition.start_time, partition.end_time, partition.partition_id)
                    )
                
                # Sort time indexes
                for data_type in self._time_index:
                    self._time_index[data_type].sort()
                
                logger.info(f"Loaded {len(self._partition_index)} partitions to index")
                
        except Exception as e:
            logger.error(f"Error loading partition index: {e}")
    
    async def _store_partition_metadata(self, partition: DataPartition) -> None:
        """Store partition metadata in database."""
        with self._db_lock:
            self._connection.execute("""
                INSERT INTO data_partitions (
                    partition_id, data_type, start_time, end_time, record_count,
                    file_path, compressed, retention_policy, created_at,
                    last_accessed, archive_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                partition.partition_id, partition.data_type.value,
                partition.start_time.isoformat(), partition.end_time.isoformat(),
                partition.record_count, partition.file_path, int(partition.compressed),
                partition.retention_policy.value, partition.created_at.isoformat(),
                partition.last_accessed.isoformat(), partition.archive_status
            ))
            
            self._connection.commit()
    
    async def _update_partition_metadata(self, partition: DataPartition) -> None:
        """Update partition metadata in database."""
        with self._db_lock:
            self._connection.execute("""
                UPDATE data_partitions SET
                    file_path = ?, compressed = ?, archive_status = ?,
                    last_accessed = ?
                WHERE partition_id = ?
            """, (
                partition.file_path, int(partition.compressed),
                partition.archive_status, partition.last_accessed.isoformat(),
                partition.partition_id
            ))
            
            self._connection.commit()
    
    async def _load_partition_data(self, partition: DataPartition) -> List[Dict[str, Any]]:
        """Load data from a partition file."""
        try:
            file_path = Path(partition.file_path)
            
            if partition.compressed:
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            return data
            
        except Exception as e:
            logger.error(f"Error loading partition data from {partition.file_path}: {e}")
            return []
    
    def _filter_data(
        self,
        data: List[Dict[str, Any]],
        start_time: datetime,
        end_time: datetime,
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Filter data by time range and additional criteria."""
        filtered = []
        
        for record in data:
            # Time filtering
            record_time = None
            for time_field in ['timestamp', 'created_at', 'first_observed', 'hunt_start_time']:
                if time_field in record:
                    try:
                        record_time = datetime.fromisoformat(record[time_field])
                        break
                    except (ValueError, TypeError):
                        continue
            
            if record_time and (record_time < start_time or record_time > end_time):
                continue
            
            # Additional filters
            if filters:
                match = True
                for key, value in filters.items():
                    if key in record and record[key] != value:
                        match = False
                        break
                
                if not match:
                    continue
            
            filtered.append(record)
        
        return filtered
    
    async def _update_partition_access(self, partition_id: str) -> None:
        """Update partition last accessed time."""
        if partition_id in self._partition_index:
            partition = self._partition_index[partition_id]
            partition.last_accessed = datetime.utcnow()
            await self._update_partition_metadata(partition)
    
    async def _log_data_access(
        self,
        partition_ids: List[str],
        access_type: str,
        records_returned: int
    ) -> None:
        """Log data access for audit purposes."""
        try:
            access_id = str(uuid.uuid4())
            timestamp = datetime.utcnow()
            
            with self._db_lock:
                for partition_id in partition_ids:
                    self._connection.execute("""
                        INSERT INTO data_access_logs (
                            access_id, partition_id, access_type, timestamp,
                            records_returned
                        ) VALUES (?, ?, ?, ?, ?)
                    """, (
                        f"{access_id}_{partition_id}", partition_id, access_type,
                        timestamp.isoformat(), records_returned
                    ))
                
                self._connection.commit()
                
        except Exception as e:
            logger.warning(f"Error logging data access: {e}")
    
    async def _analyze_frequency_pattern(
        self,
        df: pd.DataFrame,
        timestamp_col: str,
        freq_name: str,
        freq_code: str,
        data_type: DataType
    ) -> Optional[TemporalPattern]:
        """Analyze patterns at a specific frequency."""
        try:
            # Resample data
            df_resampled = df.set_index(timestamp_col).resample(freq_code).size()
            
            if len(df_resampled) < 3:  # Need minimum data points
                return None
            
            # Calculate statistics
            mean_activity = df_resampled.mean()
            std_activity = df_resampled.std()
            
            # Find peaks (activity > mean + std)
            peak_threshold = mean_activity + std_activity
            peaks = df_resampled[df_resampled > peak_threshold]
            
            if len(peaks) == 0:
                return None
            
            # Calculate confidence based on pattern strength
            confidence = min(len(peaks) / len(df_resampled), 0.95)
            
            # Create pattern
            pattern = TemporalPattern(
                pattern_id=str(uuid.uuid4()),
                pattern_name=f"{data_type.value}_{freq_name}_pattern",
                description=f"{freq_name.title()} pattern in {data_type.value} data",
                time_range=(df_resampled.index[0].to_pydatetime(), df_resampled.index[-1].to_pydatetime()),
                frequency=freq_name,
                confidence_score=confidence,
                peak_times=[peak_time.to_pydatetime() for peak_time in peaks.index],
                activity_cycles=[{
                    'period': freq_name,
                    'mean_activity': float(mean_activity),
                    'peak_activity': float(peaks.max()),
                    'pattern_strength': float(std_activity / mean_activity) if mean_activity > 0 else 0
                }],
                seasonal_components={},
                trend_direction='stable',  # Would need more sophisticated analysis
                event_count=int(df_resampled.sum()),
                affected_entities=[],  # Would extract from data
                correlated_patterns=[],
                statistical_significance=confidence
            )
            
            return pattern
            
        except Exception as e:
            logger.warning(f"Error analyzing {freq_name} pattern: {e}")
            return None
    
    async def _store_temporal_pattern(self, pattern: TemporalPattern) -> None:
        """Store temporal pattern in database."""
        try:
            with self._db_lock:
                self._connection.execute("""
                    INSERT OR REPLACE INTO temporal_patterns (
                        pattern_id, pattern_name, description, start_time, end_time,
                        frequency, confidence_score, peak_times, activity_cycles,
                        seasonal_components, trend_direction, event_count,
                        affected_entities, correlated_patterns, statistical_significance,
                        threat_actors, campaign_associations, geographic_distribution,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern.pattern_id, pattern.pattern_name, pattern.description,
                    pattern.time_range[0].isoformat(), pattern.time_range[1].isoformat(),
                    pattern.frequency, pattern.confidence_score,
                    json.dumps([t.isoformat() for t in pattern.peak_times]),
                    json.dumps(pattern.activity_cycles),
                    json.dumps(pattern.seasonal_components),
                    pattern.trend_direction, pattern.event_count,
                    json.dumps(pattern.affected_entities),
                    json.dumps(pattern.correlated_patterns),
                    pattern.statistical_significance,
                    json.dumps(pattern.threat_actors),
                    json.dumps(pattern.campaign_associations),
                    json.dumps(pattern.geographic_distribution),
                    pattern.created_at.isoformat(),
                    pattern.updated_at.isoformat()
                ))
                
                self._connection.commit()
                
        except Exception as e:
            logger.error(f"Error storing temporal pattern: {e}")
    
    async def _move_to_archive(self, partition: DataPartition) -> None:
        """Move partition to archive directory."""
        try:
            archive_dir = self.data_directory / "archive" / partition.data_type.value
            archive_dir.mkdir(parents=True, exist_ok=True)
            
            current_path = Path(partition.file_path)
            archive_path = archive_dir / current_path.name
            
            # Move file
            shutil.move(str(current_path), str(archive_path))
            
            # Update partition metadata
            partition.file_path = str(archive_path)
            partition.archive_status = 'archived'
            
            await self._update_partition_metadata(partition)
            
            logger.debug(f"Moved partition {partition.partition_id} to archive")
            
        except Exception as e:
            logger.error(f"Error moving partition to archive: {e}")
            raise
    
    async def _delete_partition(self, partition: DataPartition) -> None:
        """Delete expired partition."""
        try:
            # Delete file
            file_path = Path(partition.file_path)
            if file_path.exists():
                file_path.unlink()
            
            # Remove from database
            with self._db_lock:
                self._connection.execute(
                    "DELETE FROM data_partitions WHERE partition_id = ?",
                    (partition.partition_id,)
                )
                self._connection.commit()
            
            # Remove from indexes
            if partition.partition_id in self._partition_index:
                del self._partition_index[partition.partition_id]
            
            # Remove from time index
            time_entries = self._time_index[partition.data_type]
            self._time_index[partition.data_type] = [
                entry for entry in time_entries
                if entry[2] != partition.partition_id
            ]
            
            logger.debug(f"Deleted expired partition {partition.partition_id}")
            
        except Exception as e:
            logger.error(f"Error deleting partition: {e}")
            raise
    
    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        def cleanup_task():
            while not self._stop_tasks:
                try:
                    asyncio.run(self.compress_old_partitions())
                    asyncio.run(self.archive_expired_data())
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
                
                time.sleep(3600)  # Run every hour
        
        def analysis_task():
            while not self._stop_tasks:
                try:
                    # Analyze patterns for each data type
                    for data_type in DataType:
                        asyncio.run(self.analyze_temporal_patterns(data_type))
                except Exception as e:
                    logger.error(f"Error in analysis task: {e}")
                
                time.sleep(86400)  # Run daily
        
        self._cleanup_task = threading.Thread(target=cleanup_task, daemon=True)
        self._analysis_task = threading.Thread(target=analysis_task, daemon=True)
        
        self._cleanup_task.start()
        self._analysis_task.start()
        
        logger.info("Started background maintenance tasks")
    
    async def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics."""
        try:
            stats = {
                'total_partitions': len(self._partition_index),
                'partitions_by_type': {},
                'partitions_by_status': {},
                'storage_usage': {},
                'retention_summary': {}
            }
            
            total_size = 0
            
            for partition in self._partition_index.values():
                # Count by type
                type_key = partition.data_type.value
                stats['partitions_by_type'][type_key] = stats['partitions_by_type'].get(type_key, 0) + 1
                
                # Count by status
                status_key = partition.archive_status
                stats['partitions_by_status'][status_key] = stats['partitions_by_status'].get(status_key, 0) + 1
                
                # Count by retention policy
                retention_key = partition.retention_policy.value
                stats['retention_summary'][retention_key] = stats['retention_summary'].get(retention_key, 0) + 1
                
                # Calculate file size
                try:
                    file_size = Path(partition.file_path).stat().st_size
                    total_size += file_size
                    
                    if type_key not in stats['storage_usage']:
                        stats['storage_usage'][type_key] = 0
                    stats['storage_usage'][type_key] += file_size
                    
                except OSError:
                    pass  # File might not exist
            
            stats['total_storage_bytes'] = total_size
            stats['total_storage_mb'] = total_size / (1024 * 1024)
            stats['data_directory'] = str(self.data_directory)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting storage statistics: {e}")
            return {}
    
    def close(self) -> None:
        """Close database connections and stop background tasks."""
        try:
            self._stop_tasks = True
            
            if self._cleanup_task and self._cleanup_task.is_alive():
                self._cleanup_task.join(timeout=5)
            
            if self._analysis_task and self._analysis_task.is_alive():
                self._analysis_task.join(timeout=5)
            
            if self._connection:
                self._connection.close()
            
            logger.info("Closed historical threat data manager")
            
        except Exception as e:
            logger.error(f"Error closing historical data manager: {e}")