"""
Threat Pattern Database for Historical Analysis and Pattern Learning

This module implements a comprehensive database system for storing, retrieving,
and analyzing threat patterns with support for pattern evolution, similarity
matching, and automated learning from historical incidents.
"""

import asyncio
import logging
import json
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict, Counter
from enum import Enum
import sqlite3
import threading
import pickle
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import LatentDirichletAllocation
from sklearn.neighbors import NearestNeighbors
from sklearn.ensemble import IsolationForest
import networkx as nx
import faiss
import sentence_transformers

from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector


logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of threat patterns."""
    APT_CAMPAIGN = "apt_campaign"
    MALWARE_FAMILY = "malware_family"
    ATTACK_TECHNIQUE = "attack_technique"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    NETWORK_PATTERN = "network_pattern"
    FILE_SIGNATURE = "file_signature"
    COMMUNICATION_PATTERN = "communication_pattern"
    TEMPORAL_PATTERN = "temporal_pattern"


class PatternSeverity(Enum):
    """Severity levels for threat patterns."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PatternStatus(Enum):
    """Status of threat patterns in the database."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    UNDER_REVIEW = "under_review"
    FALSE_POSITIVE = "false_positive"
    MERGED = "merged"


@dataclass
class ThreatIndicator:
    """Individual threat indicator within a pattern."""
    indicator_id: str
    indicator_type: str  # 'ip', 'domain', 'hash', 'registry_key', 'file_path', etc.
    value: str
    confidence_score: float
    first_seen: datetime
    last_seen: datetime
    frequency: int
    sources: List[str]
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackTechnique:
    """MITRE ATT&CK technique information."""
    technique_id: str  # e.g., "T1566.001"
    tactic: str
    technique_name: str
    sub_technique: Optional[str] = None
    description: str = ""
    confidence_score: float = 0.0
    evidence_count: int = 0
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)


@dataclass
class ThreatPattern:
    """Comprehensive threat pattern definition."""
    pattern_id: str
    pattern_name: str
    pattern_type: PatternType
    severity: PatternSeverity
    status: PatternStatus
    
    # Pattern details
    description: str
    summary: str
    kill_chain_phases: List[str]
    attack_techniques: List[AttackTechnique]
    indicators: List[ThreatIndicator]
    
    # Pattern characteristics
    signature: str  # Hash of pattern characteristics
    similarity_hash: str  # For clustering similar patterns
    feature_vector: Optional[List[float]] = None
    
    # Historical data
    first_observed: datetime
    last_observed: datetime
    observation_count: int
    detection_count: int
    false_positive_count: int
    
    # Evolution tracking
    parent_pattern_id: Optional[str] = None
    child_patterns: List[str] = field(default_factory=list)
    evolution_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attribution and context
    attributed_threat_actors: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    target_sectors: List[str] = field(default_factory=list)
    geographic_regions: List[str] = field(default_factory=list)
    
    # Effectiveness metrics
    true_positive_rate: float = 0.0
    false_positive_rate: float = 0.0
    detection_accuracy: float = 0.0
    analyst_feedback_score: float = 0.0
    
    # Metadata
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: int = 1
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternMatch:
    """Result of pattern matching operation."""
    match_id: str
    pattern_id: str
    match_score: float
    confidence_level: float
    
    # Matching details
    matched_indicators: List[str]
    matched_techniques: List[str]
    partial_matches: Dict[str, float]
    
    # Context
    event_ids: List[str]
    timestamp: datetime
    entity_id: str
    
    # Analysis
    similarity_reasons: List[str]
    deviation_notes: List[str]
    analyst_verification: Optional[bool] = None
    feedback_notes: str = ""


class ThreatPatternDatabase:
    """
    Comprehensive database for threat patterns with advanced analytics capabilities.
    """
    
    def __init__(self, settings: Settings, database_path: str = ":memory:"):
        self.settings = settings
        self.database_path = database_path
        self.metrics = MetricsCollector("threat_pattern_database")
        
        # Database connection with thread safety
        self._db_lock = threading.RLock()
        self._connection = None
        
        # In-memory caches for performance
        self._pattern_cache: Dict[str, ThreatPattern] = {}
        self._signature_index: Dict[str, Set[str]] = defaultdict(set)
        self._indicator_index: Dict[str, Set[str]] = defaultdict(set)
        
        # ML models for pattern analysis
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.pattern_clusters: Dict[str, List[str]] = {}
        self.similarity_model = None
        
        # Advanced ML indexing
        self.sentence_transformer = None
        self.faiss_index = None
        self.pattern_embeddings: Dict[str, np.ndarray] = {}
        self.nearest_neighbors = NearestNeighbors(n_neighbors=10, metric='cosine')
        self.anomaly_detector = IsolationForest(contamination=0.1)
        
        # ML-powered threat intelligence
        self.threat_actor_embeddings: Dict[str, np.ndarray] = {}
        self.campaign_similarity_cache: Dict[str, List[Tuple[str, float]]] = {}
        self.temporal_pattern_analyzer = None
        
        # Initialize database
        self._initialize_database()
        self._load_patterns_to_cache()
        
        # Initialize ML components
        asyncio.create_task(self._initialize_ml_components())
        
    def _initialize_database(self) -> None:
        """Initialize SQLite database with required tables."""
        with self._db_lock:
            self._connection = sqlite3.connect(
                self.database_path,
                check_same_thread=False,
                timeout=30.0
            )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            
            # Create tables
            self._create_tables()
            
            logger.info(f"Initialized threat pattern database at {self.database_path}")
    
    def _create_tables(self) -> None:
        """Create database tables for threat patterns."""
        # Main patterns table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS threat_patterns (
                pattern_id TEXT PRIMARY KEY,
                pattern_name TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                summary TEXT,
                signature TEXT UNIQUE,
                similarity_hash TEXT,
                first_observed TEXT,
                last_observed TEXT,
                observation_count INTEGER DEFAULT 0,
                detection_count INTEGER DEFAULT 0,
                false_positive_count INTEGER DEFAULT 0,
                parent_pattern_id TEXT,
                true_positive_rate REAL DEFAULT 0.0,
                false_positive_rate REAL DEFAULT 0.0,
                detection_accuracy REAL DEFAULT 0.0,
                analyst_feedback_score REAL DEFAULT 0.0,
                created_by TEXT,
                created_at TEXT,
                updated_at TEXT,
                version INTEGER DEFAULT 1,
                FOREIGN KEY (parent_pattern_id) REFERENCES threat_patterns (pattern_id)
            )
        """)
        
        # Indicators table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                frequency INTEGER DEFAULT 1,
                sources TEXT,
                tags TEXT,
                metadata TEXT,
                FOREIGN KEY (pattern_id) REFERENCES threat_patterns (pattern_id) ON DELETE CASCADE
            )
        """)
        
        # Attack techniques table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS attack_techniques (
                technique_id TEXT,
                pattern_id TEXT NOT NULL,
                tactic TEXT,
                technique_name TEXT,
                sub_technique TEXT,
                description TEXT,
                confidence_score REAL DEFAULT 0.0,
                evidence_count INTEGER DEFAULT 0,
                platforms TEXT,
                data_sources TEXT,
                PRIMARY KEY (technique_id, pattern_id),
                FOREIGN KEY (pattern_id) REFERENCES threat_patterns (pattern_id) ON DELETE CASCADE
            )
        """)
        
        # Pattern matches table
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS pattern_matches (
                match_id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL,
                match_score REAL NOT NULL,
                confidence_level REAL NOT NULL,
                matched_indicators TEXT,
                matched_techniques TEXT,
                event_ids TEXT,
                timestamp TEXT,
                entity_id TEXT,
                similarity_reasons TEXT,
                analyst_verification INTEGER,
                feedback_notes TEXT,
                FOREIGN KEY (pattern_id) REFERENCES threat_patterns (pattern_id)
            )
        """)
        
        # Pattern evolution history
        self._connection.execute("""
            CREATE TABLE IF NOT EXISTS pattern_evolution (
                evolution_id TEXT PRIMARY KEY,
                pattern_id TEXT NOT NULL,
                change_type TEXT NOT NULL,
                change_description TEXT,
                old_values TEXT,
                new_values TEXT,
                change_timestamp TEXT,
                changed_by TEXT,
                FOREIGN KEY (pattern_id) REFERENCES threat_patterns (pattern_id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_patterns_type ON threat_patterns (pattern_type)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_severity ON threat_patterns (severity)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_status ON threat_patterns (status)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_signature ON threat_patterns (signature)",
            "CREATE INDEX IF NOT EXISTS idx_patterns_similarity ON threat_patterns (similarity_hash)",
            "CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators (indicator_type)",
            "CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators (value)",
            "CREATE INDEX IF NOT EXISTS idx_techniques_id ON attack_techniques (technique_id)",
            "CREATE INDEX IF NOT EXISTS idx_matches_pattern ON pattern_matches (pattern_id)",
            "CREATE INDEX IF NOT EXISTS idx_matches_timestamp ON pattern_matches (timestamp)"
        ]
        
        for index_sql in indexes:
            self._connection.execute(index_sql)
        
        self._connection.commit()
    
    def _load_patterns_to_cache(self) -> None:
        """Load patterns from database to memory cache."""
        with self._db_lock:
            cursor = self._connection.execute("SELECT COUNT(*) FROM threat_patterns")
            count = cursor.fetchone()[0]
            
            if count > 0:
                patterns = self._fetch_all_patterns()
                for pattern in patterns:
                    self._add_to_cache(pattern)
                    
                logger.info(f"Loaded {len(patterns)} patterns to cache")
    
    async def store_threat_pattern(self, pattern: ThreatPattern) -> bool:
        """Store a new threat pattern in the database."""
        try:
            with self._db_lock:
                # Generate signature and similarity hash
                pattern.signature = self._generate_pattern_signature(pattern)
                pattern.similarity_hash = self._generate_similarity_hash(pattern)
                
                # Check for existing pattern with same signature
                existing = self._connection.execute(
                    "SELECT pattern_id FROM threat_patterns WHERE signature = ?",
                    (pattern.signature,)
                ).fetchone()
                
                if existing:
                    logger.warning(f"Pattern with signature {pattern.signature} already exists")
                    return False
                
                # Insert main pattern
                self._connection.execute("""
                    INSERT INTO threat_patterns (
                        pattern_id, pattern_name, pattern_type, severity, status,
                        description, summary, signature, similarity_hash,
                        first_observed, last_observed, observation_count,
                        detection_count, false_positive_count, parent_pattern_id,
                        true_positive_rate, false_positive_rate, detection_accuracy,
                        analyst_feedback_score, created_by, created_at, updated_at, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    pattern.pattern_id, pattern.pattern_name, pattern.pattern_type.value,
                    pattern.severity.value, pattern.status.value, pattern.description,
                    pattern.summary, pattern.signature, pattern.similarity_hash,
                    pattern.first_observed.isoformat(), pattern.last_observed.isoformat(),
                    pattern.observation_count, pattern.detection_count,
                    pattern.false_positive_count, pattern.parent_pattern_id,
                    pattern.true_positive_rate, pattern.false_positive_rate,
                    pattern.detection_accuracy, pattern.analyst_feedback_score,
                    pattern.created_by, pattern.created_at.isoformat(),
                    pattern.updated_at.isoformat(), pattern.version
                ))
                
                # Insert indicators
                for indicator in pattern.indicators:
                    self._connection.execute("""
                        INSERT INTO threat_indicators (
                            indicator_id, pattern_id, indicator_type, value,
                            confidence_score, first_seen, last_seen, frequency,
                            sources, tags, metadata
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        indicator.indicator_id, pattern.pattern_id,
                        indicator.indicator_type, indicator.value,
                        indicator.confidence_score, indicator.first_seen.isoformat(),
                        indicator.last_seen.isoformat(), indicator.frequency,
                        json.dumps(indicator.sources), json.dumps(indicator.tags),
                        json.dumps(indicator.metadata)
                    ))
                
                # Insert attack techniques
                for technique in pattern.attack_techniques:
                    self._connection.execute("""
                        INSERT INTO attack_techniques (
                            technique_id, pattern_id, tactic, technique_name,
                            sub_technique, description, confidence_score,
                            evidence_count, platforms, data_sources
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        technique.technique_id, pattern.pattern_id, technique.tactic,
                        technique.technique_name, technique.sub_technique,
                        technique.description, technique.confidence_score,
                        technique.evidence_count, json.dumps(technique.platforms),
                        json.dumps(technique.data_sources)
                    ))
                
                self._connection.commit()
                
                # Add to cache
                self._add_to_cache(pattern)
                
                self.metrics.increment_counter("patterns_stored", tags={"type": pattern.pattern_type.value})
                
                logger.info(f"Stored threat pattern {pattern.pattern_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to store threat pattern {pattern.pattern_id}: {e}")
            if self._connection:
                self._connection.rollback()
            return False
    
    async def find_similar_patterns(
        self,
        pattern: ThreatPattern,
        similarity_threshold: float = 0.7,
        max_results: int = 10
    ) -> List[Tuple[ThreatPattern, float]]:
        """Find patterns similar to the given pattern."""
        similar_patterns = []
        
        try:
            # Check similarity hash for exact matches first
            if pattern.similarity_hash in self._signature_index:
                exact_matches = self._signature_index[pattern.similarity_hash]
                for pattern_id in exact_matches:
                    if pattern_id != pattern.pattern_id and pattern_id in self._pattern_cache:
                        similar_patterns.append((self._pattern_cache[pattern_id], 1.0))
            
            # Use ML similarity for approximate matches
            if len(similar_patterns) < max_results:
                ml_similar = await self._find_ml_similar_patterns(
                    pattern, similarity_threshold, max_results - len(similar_patterns)
                )
                similar_patterns.extend(ml_similar)
            
            # Sort by similarity score
            similar_patterns.sort(key=lambda x: x[1], reverse=True)
            
            self.metrics.increment_counter("similarity_searches")
            
            return similar_patterns[:max_results]
            
        except Exception as e:
            logger.error(f"Error finding similar patterns: {e}")
            return []
    
    async def search_patterns(
        self,
        query: Dict[str, Any],
        limit: int = 100
    ) -> List[ThreatPattern]:
        """Search patterns based on various criteria."""
        try:
            sql_conditions = []
            params = []
            
            # Build SQL query based on search criteria
            if 'pattern_type' in query:
                sql_conditions.append("pattern_type = ?")
                params.append(query['pattern_type'])
            
            if 'severity' in query:
                sql_conditions.append("severity = ?")
                params.append(query['severity'])
            
            if 'status' in query:
                sql_conditions.append("status = ?")
                params.append(query['status'])
            
            if 'created_after' in query:
                sql_conditions.append("created_at >= ?")
                params.append(query['created_after'].isoformat())
            
            if 'created_before' in query:
                sql_conditions.append("created_at <= ?")
                params.append(query['created_before'].isoformat())
            
            if 'min_accuracy' in query:
                sql_conditions.append("detection_accuracy >= ?")
                params.append(query['min_accuracy'])
            
            # Construct WHERE clause
            where_clause = ""
            if sql_conditions:
                where_clause = "WHERE " + " AND ".join(sql_conditions)
            
            sql = f"""
                SELECT pattern_id FROM threat_patterns
                {where_clause}
                ORDER BY updated_at DESC
                LIMIT ?
            """
            params.append(limit)
            
            with self._db_lock:
                cursor = self._connection.execute(sql, params)
                pattern_ids = [row[0] for row in cursor.fetchall()]
            
            # Get full pattern data
            patterns = []
            for pattern_id in pattern_ids:
                pattern = await self.get_pattern(pattern_id)
                if pattern:
                    patterns.append(pattern)
            
            self.metrics.increment_counter("pattern_searches")
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error searching patterns: {e}")
            return []
    
    async def get_pattern(self, pattern_id: str) -> Optional[ThreatPattern]:
        """Retrieve a specific threat pattern by ID."""
        try:
            # Check cache first
            if pattern_id in self._pattern_cache:
                return self._pattern_cache[pattern_id]
            
            # Fetch from database
            pattern = await self._fetch_pattern_from_db(pattern_id)
            if pattern:
                self._add_to_cache(pattern)
            
            return pattern
            
        except Exception as e:
            logger.error(f"Error retrieving pattern {pattern_id}: {e}")
            return None
    
    async def update_pattern(
        self,
        pattern_id: str,
        updates: Dict[str, Any],
        user_id: str
    ) -> bool:
        """Update an existing threat pattern."""
        try:
            pattern = await self.get_pattern(pattern_id)
            if not pattern:
                logger.error(f"Pattern {pattern_id} not found for update")
                return False
            
            # Record evolution history
            evolution_entry = {
                'evolution_id': str(uuid.uuid4()),
                'change_type': 'update',
                'change_description': f"Updated fields: {', '.join(updates.keys())}",
                'old_values': {k: getattr(pattern, k, None) for k in updates.keys()},
                'new_values': updates,
                'change_timestamp': datetime.utcnow().isoformat(),
                'changed_by': user_id
            }
            
            # Update pattern object
            for field, value in updates.items():
                if hasattr(pattern, field):
                    setattr(pattern, field, value)
            
            pattern.updated_at = datetime.utcnow()
            pattern.version += 1
            pattern.evolution_history.append(evolution_entry)
            
            # Update in database
            success = await self._update_pattern_in_db(pattern, evolution_entry)
            
            if success:
                # Update cache
                self._add_to_cache(pattern)
                self.metrics.increment_counter("patterns_updated")
            
            return success
            
        except Exception as e:
            logger.error(f"Error updating pattern {pattern_id}: {e}")
            return False
    
    async def record_pattern_match(self, match: PatternMatch) -> bool:
        """Record a pattern match for analytics."""
        try:
            with self._db_lock:
                self._connection.execute("""
                    INSERT INTO pattern_matches (
                        match_id, pattern_id, match_score, confidence_level,
                        matched_indicators, matched_techniques, event_ids,
                        timestamp, entity_id, similarity_reasons,
                        analyst_verification, feedback_notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    match.match_id, match.pattern_id, match.match_score,
                    match.confidence_level, json.dumps(match.matched_indicators),
                    json.dumps(match.matched_techniques), json.dumps(match.event_ids),
                    match.timestamp.isoformat(), match.entity_id,
                    json.dumps(match.similarity_reasons),
                    match.analyst_verification, match.feedback_notes
                ))
                
                self._connection.commit()
            
            # Update pattern statistics
            await self._update_pattern_statistics(match.pattern_id, match)
            
            self.metrics.increment_counter("pattern_matches_recorded")
            
            return True
            
        except Exception as e:
            logger.error(f"Error recording pattern match: {e}")
            return False
    
    async def get_pattern_statistics(
        self,
        pattern_id: str,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get comprehensive statistics for a pattern."""
        try:
            cutoff_date = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
            
            with self._db_lock:
                # Get match statistics
                cursor = self._connection.execute("""
                    SELECT 
                        COUNT(*) as total_matches,
                        AVG(match_score) as avg_match_score,
                        AVG(confidence_level) as avg_confidence,
                        COUNT(CASE WHEN analyst_verification = 1 THEN 1 END) as verified_matches,
                        COUNT(CASE WHEN analyst_verification = 0 THEN 1 END) as false_positives
                    FROM pattern_matches
                    WHERE pattern_id = ? AND timestamp >= ?
                """, (pattern_id, cutoff_date))
                
                stats = cursor.fetchone()
                
                # Get pattern info
                pattern = await self.get_pattern(pattern_id)
                
                return {
                    'pattern_id': pattern_id,
                    'total_matches': stats[0] or 0,
                    'avg_match_score': stats[1] or 0.0,
                    'avg_confidence': stats[2] or 0.0,
                    'verified_matches': stats[3] or 0,
                    'false_positives': stats[4] or 0,
                    'accuracy': (stats[3] or 0) / max(stats[0] or 1, 1),
                    'pattern_age_days': (datetime.utcnow() - pattern.created_at).days if pattern else 0,
                    'last_updated': pattern.updated_at.isoformat() if pattern else None
                }
                
        except Exception as e:
            logger.error(f"Error getting pattern statistics: {e}")
            return {}
    
    async def cluster_patterns(
        self,
        pattern_type: Optional[PatternType] = None,
        min_cluster_size: int = 2
    ) -> Dict[str, List[str]]:
        """Cluster similar patterns for analysis."""
        try:
            # Get patterns to cluster
            patterns = []
            if pattern_type:
                patterns = await self.search_patterns({'pattern_type': pattern_type.value})
            else:
                patterns = list(self._pattern_cache.values())
            
            if len(patterns) < min_cluster_size:
                return {}
            
            # Extract features for clustering
            features = []
            pattern_ids = []
            
            for pattern in patterns:
                feature_vector = self._extract_pattern_features(pattern)
                if feature_vector is not None:
                    features.append(feature_vector)
                    pattern_ids.append(pattern.pattern_id)
            
            if len(features) < min_cluster_size:
                return {}
            
            # Perform clustering
            features_array = np.array(features)
            clustering = DBSCAN(eps=0.3, min_samples=min_cluster_size)
            cluster_labels = clustering.fit_predict(features_array)
            
            # Group patterns by cluster
            clusters = defaultdict(list)
            for i, label in enumerate(cluster_labels):
                if label != -1:  # -1 is noise in DBSCAN
                    clusters[f"cluster_{label}"].append(pattern_ids[i])
            
            self.metrics.increment_counter("pattern_clustering_executed")
            
            return dict(clusters)
            
        except Exception as e:
            logger.error(f"Error clustering patterns: {e}")
            return {}
    
    # Private helper methods
    def _generate_pattern_signature(self, pattern: ThreatPattern) -> str:
        """Generate a unique signature for the pattern."""
        # Combine key pattern characteristics
        signature_components = [
            pattern.pattern_type.value,
            pattern.pattern_name,
            "|".join(sorted([ind.value for ind in pattern.indicators])),
            "|".join(sorted([tech.technique_id for tech in pattern.attack_techniques]))
        ]
        
        signature_string = "|".join(signature_components)
        return hashlib.sha256(signature_string.encode()).hexdigest()
    
    def _generate_similarity_hash(self, pattern: ThreatPattern) -> str:
        """Generate a hash for pattern similarity matching."""
        # Use less specific characteristics for similarity
        similarity_components = [
            pattern.pattern_type.value,
            "|".join(sorted([tech.tactic for tech in pattern.attack_techniques])),
            "|".join(sorted([ind.indicator_type for ind in pattern.indicators]))
        ]
        
        similarity_string = "|".join(similarity_components)
        return hashlib.md5(similarity_string.encode()).hexdigest()
    
    def _add_to_cache(self, pattern: ThreatPattern) -> None:
        """Add pattern to in-memory caches."""
        self._pattern_cache[pattern.pattern_id] = pattern
        self._signature_index[pattern.similarity_hash].add(pattern.pattern_id)
        
        # Index indicators
        for indicator in pattern.indicators:
            self._indicator_index[indicator.value].add(pattern.pattern_id)
    
    async def _find_ml_similar_patterns(
        self,
        pattern: ThreatPattern,
        threshold: float,
        max_results: int
    ) -> List[Tuple[ThreatPattern, float]]:
        """Use ML to find similar patterns."""
        similar = []
        
        try:
            # Extract features for the query pattern
            query_features = self._extract_pattern_features(pattern)
            if query_features is None:
                return similar
            
            # Compare with cached patterns
            for cached_pattern in self._pattern_cache.values():
                if cached_pattern.pattern_id == pattern.pattern_id:
                    continue
                
                cached_features = self._extract_pattern_features(cached_pattern)
                if cached_features is None:
                    continue
                
                # Calculate cosine similarity
                similarity = cosine_similarity(
                    [query_features], [cached_features]
                )[0][0]
                
                if similarity >= threshold:
                    similar.append((cached_pattern, float(similarity)))
            
            # Sort by similarity
            similar.sort(key=lambda x: x[1], reverse=True)
            
        except Exception as e:
            logger.warning(f"ML similarity search failed: {e}")
        
        return similar[:max_results]
    
    def _extract_pattern_features(self, pattern: ThreatPattern) -> Optional[List[float]]:
        """Extract numerical features from a pattern for ML analysis."""
        try:
            features = []
            
            # Basic features
            features.extend([
                len(pattern.indicators),
                len(pattern.attack_techniques),
                pattern.detection_accuracy,
                pattern.observation_count,
                pattern.true_positive_rate,
                pattern.false_positive_rate,
                len(pattern.target_sectors),
                len(pattern.attributed_threat_actors)
            ])
            
            # Indicator type distribution
            indicator_types = Counter([ind.indicator_type for ind in pattern.indicators])
            common_types = ['ip', 'domain', 'hash', 'file_path', 'registry_key']
            for itype in common_types:
                features.append(indicator_types.get(itype, 0))
            
            # Technique tactic distribution
            tactics = Counter([tech.tactic for tech in pattern.attack_techniques])
            common_tactics = ['initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion']
            for tactic in common_tactics:
                features.append(tactics.get(tactic, 0))
            
            return features
            
        except Exception as e:
            logger.warning(f"Feature extraction failed for pattern {pattern.pattern_id}: {e}")
            return None
    
    async def _fetch_pattern_from_db(self, pattern_id: str) -> Optional[ThreatPattern]:
        """Fetch complete pattern data from database."""
        try:
            with self._db_lock:
                # Get main pattern data
                cursor = self._connection.execute("""
                    SELECT * FROM threat_patterns WHERE pattern_id = ?
                """, (pattern_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Convert row to pattern object
                pattern = self._row_to_pattern(row)
                
                # Get indicators
                cursor = self._connection.execute("""
                    SELECT * FROM threat_indicators WHERE pattern_id = ?
                """, (pattern_id,))
                
                indicators = [self._row_to_indicator(ind_row) for ind_row in cursor.fetchall()]
                pattern.indicators = indicators
                
                # Get attack techniques
                cursor = self._connection.execute("""
                    SELECT * FROM attack_techniques WHERE pattern_id = ?
                """, (pattern_id,))
                
                techniques = [self._row_to_technique(tech_row) for tech_row in cursor.fetchall()]
                pattern.attack_techniques = techniques
                
                return pattern
                
        except Exception as e:
            logger.error(f"Error fetching pattern from DB: {e}")
            return None
    
    def _row_to_pattern(self, row) -> ThreatPattern:
        """Convert database row to ThreatPattern object."""
        return ThreatPattern(
            pattern_id=row[0],
            pattern_name=row[1],
            pattern_type=PatternType(row[2]),
            severity=PatternSeverity(row[3]),
            status=PatternStatus(row[4]),
            description=row[5] or "",
            summary=row[6] or "",
            signature=row[7],
            similarity_hash=row[8],
            first_observed=datetime.fromisoformat(row[9]),
            last_observed=datetime.fromisoformat(row[10]),
            observation_count=row[11],
            detection_count=row[12],
            false_positive_count=row[13],
            parent_pattern_id=row[14],
            true_positive_rate=row[15],
            false_positive_rate=row[16],
            detection_accuracy=row[17],
            analyst_feedback_score=row[18],
            created_by=row[19],
            created_at=datetime.fromisoformat(row[20]),
            updated_at=datetime.fromisoformat(row[21]),
            version=row[22],
            kill_chain_phases=[],  # These would need separate tables
            indicators=[],  # Populated separately
            attack_techniques=[]  # Populated separately
        )
    
    def _row_to_indicator(self, row) -> ThreatIndicator:
        """Convert database row to ThreatIndicator object."""
        return ThreatIndicator(
            indicator_id=row[0],
            indicator_type=row[2],
            value=row[3],
            confidence_score=row[4],
            first_seen=datetime.fromisoformat(row[5]),
            last_seen=datetime.fromisoformat(row[6]),
            frequency=row[7],
            sources=json.loads(row[8]) if row[8] else [],
            tags=json.loads(row[9]) if row[9] else [],
            metadata=json.loads(row[10]) if row[10] else {}
        )
    
    def _row_to_technique(self, row) -> AttackTechnique:
        """Convert database row to AttackTechnique object."""
        return AttackTechnique(
            technique_id=row[0],
            tactic=row[2],
            technique_name=row[3],
            sub_technique=row[4],
            description=row[5] or "",
            confidence_score=row[6],
            evidence_count=row[7],
            platforms=json.loads(row[8]) if row[8] else [],
            data_sources=json.loads(row[9]) if row[9] else []
        )
    
    def _fetch_all_patterns(self) -> List[ThreatPattern]:
        """Fetch all patterns from database for cache loading."""
        patterns = []
        
        try:
            cursor = self._connection.execute("SELECT pattern_id FROM threat_patterns")
            pattern_ids = [row[0] for row in cursor.fetchall()]
            
            for pattern_id in pattern_ids:
                pattern = asyncio.run(self._fetch_pattern_from_db(pattern_id))
                if pattern:
                    patterns.append(pattern)
                    
        except Exception as e:
            logger.error(f"Error fetching all patterns: {e}")
        
        return patterns
    
    async def _update_pattern_in_db(
        self,
        pattern: ThreatPattern,
        evolution_entry: Dict[str, Any]
    ) -> bool:
        """Update pattern in database with evolution tracking."""
        try:
            with self._db_lock:
                # Update main pattern
                self._connection.execute("""
                    UPDATE threat_patterns SET
                        pattern_name = ?, description = ?, summary = ?,
                        severity = ?, status = ?, updated_at = ?, version = ?
                    WHERE pattern_id = ?
                """, (
                    pattern.pattern_name, pattern.description, pattern.summary,
                    pattern.severity.value, pattern.status.value,
                    pattern.updated_at.isoformat(), pattern.version,
                    pattern.pattern_id
                ))
                
                # Record evolution
                self._connection.execute("""
                    INSERT INTO pattern_evolution (
                        evolution_id, pattern_id, change_type, change_description,
                        old_values, new_values, change_timestamp, changed_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    evolution_entry['evolution_id'], pattern.pattern_id,
                    evolution_entry['change_type'], evolution_entry['change_description'],
                    json.dumps(evolution_entry['old_values']),
                    json.dumps(evolution_entry['new_values']),
                    evolution_entry['change_timestamp'], evolution_entry['changed_by']
                ))
                
                self._connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error updating pattern in DB: {e}")
            if self._connection:
                self._connection.rollback()
            return False
    
    async def _update_pattern_statistics(
        self,
        pattern_id: str,
        match: PatternMatch
    ) -> None:
        """Update pattern statistics based on match result."""
        try:
            pattern = await self.get_pattern(pattern_id)
            if not pattern:
                return
            
            # Update detection count
            pattern.detection_count += 1
            
            # Update accuracy based on analyst feedback
            if match.analyst_verification is not None:
                if match.analyst_verification:
                    # True positive
                    pattern.true_positive_rate = (
                        pattern.true_positive_rate * (pattern.detection_count - 1) + 1
                    ) / pattern.detection_count
                else:
                    # False positive
                    pattern.false_positive_count += 1
                    pattern.false_positive_rate = (
                        pattern.false_positive_rate * (pattern.detection_count - 1) + 1
                    ) / pattern.detection_count
                
                pattern.detection_accuracy = pattern.true_positive_rate
            
            # Update in database
            await self._update_pattern_in_db(pattern, {
                'evolution_id': str(uuid.uuid4()),
                'change_type': 'statistics_update',
                'change_description': 'Updated statistics based on match result',
                'old_values': {},
                'new_values': {'detection_count': pattern.detection_count},
                'change_timestamp': datetime.utcnow().isoformat(),
                'changed_by': 'system'
            })
            
        except Exception as e:
            logger.error(f"Error updating pattern statistics: {e}")
    
    async def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics."""
        try:
            with self._db_lock:
                stats = {}
                
                # Pattern counts by type
                cursor = self._connection.execute("""
                    SELECT pattern_type, COUNT(*) FROM threat_patterns 
                    GROUP BY pattern_type
                """)
                stats['patterns_by_type'] = dict(cursor.fetchall())
                
                # Pattern counts by severity
                cursor = self._connection.execute("""
                    SELECT severity, COUNT(*) FROM threat_patterns 
                    GROUP BY severity
                """)
                stats['patterns_by_severity'] = dict(cursor.fetchall())
                
                # Total indicators
                cursor = self._connection.execute("SELECT COUNT(*) FROM threat_indicators")
                stats['total_indicators'] = cursor.fetchone()[0]
                
                # Total matches
                cursor = self._connection.execute("SELECT COUNT(*) FROM pattern_matches")
                stats['total_matches'] = cursor.fetchone()[0]
                
                # Recent activity (last 7 days)
                week_ago = (datetime.utcnow() - timedelta(days=7)).isoformat()
                cursor = self._connection.execute("""
                    SELECT COUNT(*) FROM pattern_matches WHERE timestamp >= ?
                """, (week_ago,))
                stats['recent_matches'] = cursor.fetchone()[0]
                
                stats['cache_size'] = len(self._pattern_cache)
                stats['database_path'] = self.database_path
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting database statistics: {e}")
            return {}
    
    async def _initialize_ml_components(self) -> None:
        """Initialize ML-powered components for advanced pattern analysis."""
        try:
            # Initialize sentence transformer for semantic similarity
            try:
                from sentence_transformers import SentenceTransformer
                self.sentence_transformer = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("Initialized sentence transformer model")
            except ImportError:
                logger.warning("sentence-transformers not available, using fallback similarity")
            
            # Initialize FAISS index for fast similarity search
            try:
                import faiss
                # Start with a basic index - will be rebuilt when patterns are added
                self.faiss_index = faiss.IndexFlatIP(384)  # 384 is embedding dimension
                logger.info("Initialized FAISS index for fast similarity search")
            except ImportError:
                logger.warning("FAISS not available, using fallback similarity search")
            
            # Build embeddings for existing patterns
            await self._build_pattern_embeddings()
            
            # Initialize temporal pattern analysis
            await self._initialize_temporal_analyzer()
            
        except Exception as e:
            logger.error(f"Error initializing ML components: {e}")
    
    async def _build_pattern_embeddings(self) -> None:
        """Build semantic embeddings for all patterns."""
        if not self.sentence_transformer:
            return
        
        try:
            pattern_texts = []
            pattern_ids = []
            
            for pattern in self._pattern_cache.values():
                # Combine pattern text for embedding
                text_components = [
                    pattern.pattern_name,
                    pattern.description,
                    pattern.summary,
                    " ".join([tech.technique_name for tech in pattern.attack_techniques]),
                    " ".join([ind.value for ind in pattern.indicators[:10]])  # Limit indicators
                ]
                pattern_text = " ".join(filter(None, text_components))
                
                pattern_texts.append(pattern_text)
                pattern_ids.append(pattern.pattern_id)
            
            if pattern_texts:
                # Generate embeddings
                embeddings = self.sentence_transformer.encode(pattern_texts)
                
                # Store embeddings
                for i, pattern_id in enumerate(pattern_ids):
                    self.pattern_embeddings[pattern_id] = embeddings[i]
                
                # Rebuild FAISS index if available
                if self.faiss_index is not None:
                    self.faiss_index.reset()
                    self.faiss_index.add(embeddings.astype('float32'))
                
                logger.info(f"Built embeddings for {len(pattern_texts)} patterns")
                
        except Exception as e:
            logger.error(f"Error building pattern embeddings: {e}")
    
    async def _initialize_temporal_analyzer(self) -> None:
        """Initialize temporal pattern analysis for campaign detection."""
        try:
            # Analyze temporal patterns in existing data
            temporal_features = []
            
            for pattern in self._pattern_cache.values():
                # Extract temporal features
                features = self._extract_temporal_features(pattern)
                if features:
                    temporal_features.append(features)
            
            if len(temporal_features) > 10:
                # Fit anomaly detector on temporal patterns
                self.anomaly_detector.fit(temporal_features)
                logger.info("Initialized temporal pattern analyzer")
            
        except Exception as e:
            logger.error(f"Error initializing temporal analyzer: {e}")
    
    def _extract_temporal_features(self, pattern: ThreatPattern) -> Optional[List[float]]:
        """Extract temporal features from pattern for analysis."""
        try:
            features = []
            
            # Time-based features
            age_days = (datetime.utcnow() - pattern.created_at).days
            observation_span = (pattern.last_observed - pattern.first_observed).days
            
            features.extend([
                age_days,
                observation_span,
                pattern.observation_count,
                pattern.detection_count,
                pattern.observation_count / max(observation_span, 1),  # frequency
                pattern.detection_count / max(pattern.observation_count, 1)  # detection rate
            ])
            
            # Pattern evolution features
            features.extend([
                len(pattern.evolution_history),
                pattern.version,
                len(pattern.child_patterns)
            ])
            
            return features
            
        except Exception as e:
            logger.warning(f"Error extracting temporal features: {e}")
            return None
    
    async def find_semantic_similar_patterns(
        self,
        pattern: ThreatPattern,
        similarity_threshold: float = 0.7,
        max_results: int = 10
    ) -> List[Tuple[ThreatPattern, float]]:
        """Find semantically similar patterns using ML embeddings."""
        try:
            if not self.sentence_transformer:
                # Fallback to existing similarity method
                return await self.find_similar_patterns(pattern, similarity_threshold, max_results)
            
            # Generate embedding for query pattern
            text_components = [
                pattern.pattern_name,
                pattern.description,
                pattern.summary,
                " ".join([tech.technique_name for tech in pattern.attack_techniques]),
                " ".join([ind.value for ind in pattern.indicators[:10]])
            ]
            pattern_text = " ".join(filter(None, text_components))
            query_embedding = self.sentence_transformer.encode([pattern_text])[0]
            
            similar_patterns = []
            
            if self.faiss_index is not None and len(self.pattern_embeddings) > 0:
                # Use FAISS for fast similarity search
                scores, indices = self.faiss_index.search(
                    query_embedding.reshape(1, -1).astype('float32'),
                    min(max_results * 2, len(self.pattern_embeddings))
                )
                
                pattern_ids_list = list(self.pattern_embeddings.keys())
                for score, idx in zip(scores[0], indices[0]):
                    if idx < len(pattern_ids_list):
                        pattern_id = pattern_ids_list[idx]
                        if pattern_id != pattern.pattern_id and score >= similarity_threshold:
                            similar_pattern = self._pattern_cache.get(pattern_id)
                            if similar_pattern:
                                similar_patterns.append((similar_pattern, float(score)))
            else:
                # Fallback to manual similarity calculation
                for pattern_id, cached_embedding in self.pattern_embeddings.items():
                    if pattern_id == pattern.pattern_id:
                        continue
                    
                    similarity = cosine_similarity(
                        [query_embedding], [cached_embedding]
                    )[0][0]
                    
                    if similarity >= similarity_threshold:
                        similar_pattern = self._pattern_cache.get(pattern_id)
                        if similar_pattern:
                            similar_patterns.append((similar_pattern, float(similarity)))
            
            # Sort by similarity score
            similar_patterns.sort(key=lambda x: x[1], reverse=True)
            
            self.metrics.increment_counter("semantic_similarity_searches")
            
            return similar_patterns[:max_results]
            
        except Exception as e:
            logger.error(f"Error in semantic similarity search: {e}")
            # Fallback to existing method
            return await self.find_similar_patterns(pattern, similarity_threshold, max_results)
    
    async def detect_campaign_patterns(
        self,
        time_window_days: int = 30,
        min_pattern_correlation: float = 0.6
    ) -> List[Dict[str, Any]]:
        """Detect potential threat campaigns using ML pattern analysis."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=time_window_days)
            
            # Get recent patterns
            recent_patterns = [
                pattern for pattern in self._pattern_cache.values()
                if pattern.last_observed >= cutoff_date
            ]
            
            if len(recent_patterns) < 2:
                return []
            
            campaigns = []
            
            # Analyze patterns for campaign indicators
            for i, pattern1 in enumerate(recent_patterns):
                for pattern2 in recent_patterns[i+1:]:
                    correlation_score = await self._calculate_campaign_correlation(
                        pattern1, pattern2
                    )
                    
                    if correlation_score >= min_pattern_correlation:
                        campaign_id = f"campaign_{pattern1.pattern_id[:8]}_{pattern2.pattern_id[:8]}"
                        
                        campaigns.append({
                            'campaign_id': campaign_id,
                            'patterns': [pattern1.pattern_id, pattern2.pattern_id],
                            'correlation_score': correlation_score,
                            'indicators': self._find_shared_indicators(pattern1, pattern2),
                            'techniques': self._find_shared_techniques(pattern1, pattern2),
                            'threat_actors': list(set(pattern1.attributed_threat_actors + pattern2.attributed_threat_actors)),
                            'time_overlap': self._calculate_time_overlap(pattern1, pattern2),
                            'confidence': correlation_score * 0.8  # Adjust confidence
                        })
            
            # Sort campaigns by correlation score
            campaigns.sort(key=lambda x: x['correlation_score'], reverse=True)
            
            self.metrics.increment_counter("campaign_detections", tags={"count": len(campaigns)})
            
            return campaigns[:10]  # Return top 10 campaigns
            
        except Exception as e:
            logger.error(f"Error detecting campaign patterns: {e}")
            return []
    
    async def _calculate_campaign_correlation(
        self,
        pattern1: ThreatPattern,
        pattern2: ThreatPattern
    ) -> float:
        """Calculate correlation score between two patterns for campaign detection."""
        try:
            correlation_factors = []
            
            # Semantic similarity
            if pattern1.pattern_id in self.pattern_embeddings and pattern2.pattern_id in self.pattern_embeddings:
                semantic_sim = cosine_similarity(
                    [self.pattern_embeddings[pattern1.pattern_id]],
                    [self.pattern_embeddings[pattern2.pattern_id]]
                )[0][0]
                correlation_factors.append(semantic_sim * 0.3)
            
            # Shared threat actors
            shared_actors = set(pattern1.attributed_threat_actors) & set(pattern2.attributed_threat_actors)
            actor_score = len(shared_actors) / max(
                len(pattern1.attributed_threat_actors) + len(pattern2.attributed_threat_actors), 1
            )
            correlation_factors.append(actor_score * 0.25)
            
            # Shared techniques
            shared_techniques = set([t.technique_id for t in pattern1.attack_techniques]) & \
                              set([t.technique_id for t in pattern2.attack_techniques])
            technique_score = len(shared_techniques) / max(
                len(pattern1.attack_techniques) + len(pattern2.attack_techniques), 1
            )
            correlation_factors.append(technique_score * 0.2)
            
            # Shared indicators
            shared_indicators = set([i.value for i in pattern1.indicators]) & \
                               set([i.value for i in pattern2.indicators])
            indicator_score = len(shared_indicators) / max(
                len(pattern1.indicators) + len(pattern2.indicators), 1
            )
            correlation_factors.append(indicator_score * 0.15)
            
            # Temporal correlation
            time_overlap = self._calculate_time_overlap(pattern1, pattern2)
            temporal_score = min(time_overlap / 30.0, 1.0)  # 30 days max overlap
            correlation_factors.append(temporal_score * 0.1)
            
            return sum(correlation_factors)
            
        except Exception as e:
            logger.warning(f"Error calculating campaign correlation: {e}")
            return 0.0
    
    def _find_shared_indicators(self, pattern1: ThreatPattern, pattern2: ThreatPattern) -> List[Dict[str, Any]]:
        """Find shared indicators between two patterns."""
        shared = []
        
        indicators1 = {ind.value: ind for ind in pattern1.indicators}
        indicators2 = {ind.value: ind for ind in pattern2.indicators}
        
        for value in indicators1.keys() & indicators2.keys():
            ind1 = indicators1[value]
            ind2 = indicators2[value]
            
            shared.append({
                'value': value,
                'type': ind1.indicator_type,
                'confidence_avg': (ind1.confidence_score + ind2.confidence_score) / 2,
                'frequency_sum': ind1.frequency + ind2.frequency
            })
        
        return shared
    
    def _find_shared_techniques(self, pattern1: ThreatPattern, pattern2: ThreatPattern) -> List[Dict[str, Any]]:
        """Find shared attack techniques between two patterns."""
        shared = []
        
        techniques1 = {tech.technique_id: tech for tech in pattern1.attack_techniques}
        techniques2 = {tech.technique_id: tech for tech in pattern2.attack_techniques}
        
        for tech_id in techniques1.keys() & techniques2.keys():
            tech1 = techniques1[tech_id]
            tech2 = techniques2[tech_id]
            
            shared.append({
                'technique_id': tech_id,
                'technique_name': tech1.technique_name,
                'tactic': tech1.tactic,
                'confidence_avg': (tech1.confidence_score + tech2.confidence_score) / 2,
                'evidence_sum': tech1.evidence_count + tech2.evidence_count
            })
        
        return shared
    
    def _calculate_time_overlap(self, pattern1: ThreatPattern, pattern2: ThreatPattern) -> float:
        """Calculate time overlap between two patterns in days."""
        try:
            # Find overlap period
            start_overlap = max(pattern1.first_observed, pattern2.first_observed)
            end_overlap = min(pattern1.last_observed, pattern2.last_observed)
            
            if start_overlap <= end_overlap:
                return (end_overlap - start_overlap).days
            else:
                return 0.0
                
        except Exception as e:
            logger.warning(f"Error calculating time overlap: {e}")
            return 0.0
    
    async def predict_pattern_evolution(
        self,
        pattern: ThreatPattern,
        prediction_window_days: int = 30
    ) -> Dict[str, Any]:
        """Predict how a pattern might evolve using ML analysis."""
        try:
            if not self.anomaly_detector:
                return {}
            
            # Extract current pattern features
            current_features = self._extract_temporal_features(pattern)
            if not current_features:
                return {}
            
            # Predict anomaly score (lower = more normal evolution)
            anomaly_score = self.anomaly_detector.score_samples([current_features])[0]
            
            # Analyze historical evolution patterns
            similar_patterns = await self.find_semantic_similar_patterns(pattern, 0.6, 5)
            
            evolution_predictions = {
                'pattern_id': pattern.pattern_id,
                'prediction_window_days': prediction_window_days,
                'anomaly_score': float(anomaly_score),
                'predicted_changes': [],
                'confidence': 0.7,  # Base confidence
                'similar_pattern_analysis': []
            }
            
            # Analyze similar patterns for evolution insights
            for similar_pattern, similarity_score in similar_patterns:
                if len(similar_pattern.evolution_history) > 0:
                    evolution_predictions['similar_pattern_analysis'].append({
                        'pattern_id': similar_pattern.pattern_id,
                        'similarity_score': similarity_score,
                        'evolution_count': len(similar_pattern.evolution_history),
                        'last_change': similar_pattern.evolution_history[-1]['change_type'],
                        'pattern_age_days': (datetime.utcnow() - similar_pattern.created_at).days
                    })
            
            # Generate predictions based on analysis
            if anomaly_score < -0.5:  # Highly anomalous
                evolution_predictions['predicted_changes'].append({
                    'type': 'major_revision',
                    'probability': 0.8,
                    'description': 'Pattern shows anomalous behavior and may require major revision'
                })
            elif len(pattern.evolution_history) == 0 and (datetime.utcnow() - pattern.created_at).days > 30:
                evolution_predictions['predicted_changes'].append({
                    'type': 'first_update',
                    'probability': 0.6,
                    'description': 'Pattern is mature and may receive its first update'
                })
            
            # Consider detection accuracy trends
            if pattern.detection_accuracy < 0.7:
                evolution_predictions['predicted_changes'].append({
                    'type': 'accuracy_improvement',
                    'probability': 0.7,
                    'description': 'Low accuracy may trigger pattern refinement'
                })
            
            return evolution_predictions
            
        except Exception as e:
            logger.error(f"Error predicting pattern evolution: {e}")
            return {}
    
    async def get_ml_insights(self, pattern_id: str) -> Dict[str, Any]:
        """Get comprehensive ML-powered insights for a pattern."""
        try:
            pattern = await self.get_pattern(pattern_id)
            if not pattern:
                return {}
            
            insights = {
                'pattern_id': pattern_id,
                'semantic_analysis': {},
                'campaign_analysis': {},
                'evolution_prediction': {},
                'anomaly_assessment': {},
                'recommendation_score': 0.0
            }
            
            # Semantic analysis
            similar_patterns = await self.find_semantic_similar_patterns(pattern, 0.5, 5)
            insights['semantic_analysis'] = {
                'similar_patterns_count': len(similar_patterns),
                'top_similarities': [
                    {
                        'pattern_id': p.pattern_id,
                        'pattern_name': p.pattern_name,
                        'similarity_score': score
                    }
                    for p, score in similar_patterns[:3]
                ]
            }
            
            # Campaign analysis
            campaigns = await self.detect_campaign_patterns(30, 0.6)
            pattern_campaigns = [c for c in campaigns if pattern_id in c['patterns']]
            insights['campaign_analysis'] = {
                'active_campaigns': len(pattern_campaigns),
                'campaign_details': pattern_campaigns[:3]  # Top 3 campaigns
            }
            
            # Evolution prediction
            insights['evolution_prediction'] = await self.predict_pattern_evolution(pattern)
            
            # Anomaly assessment
            temporal_features = self._extract_temporal_features(pattern)
            if temporal_features and self.anomaly_detector:
                anomaly_score = self.anomaly_detector.score_samples([temporal_features])[0]
                insights['anomaly_assessment'] = {
                    'anomaly_score': float(anomaly_score),
                    'is_anomalous': anomaly_score < -0.3,
                    'confidence': min(abs(anomaly_score), 1.0)
                }
            
            # Calculate overall recommendation score
            insights['recommendation_score'] = self._calculate_ml_recommendation_score(
                pattern, similar_patterns, insights
            )
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating ML insights: {e}")
            return {}
    
    def _calculate_ml_recommendation_score(
        self,
        pattern: ThreatPattern,
        similar_patterns: List[Tuple[ThreatPattern, float]],
        insights: Dict[str, Any]
    ) -> float:
        """Calculate ML-based recommendation score for pattern usage."""
        try:
            score_factors = []
            
            # Base accuracy score
            score_factors.append(pattern.detection_accuracy * 0.3)
            
            # Similarity to high-performing patterns
            if similar_patterns:
                high_performing = [p for p, _ in similar_patterns if p.detection_accuracy > 0.8]
                similarity_boost = len(high_performing) / len(similar_patterns) * 0.2
                score_factors.append(similarity_boost)
            
            # Campaign involvement (active campaigns are valuable)
            campaign_count = insights.get('campaign_analysis', {}).get('active_campaigns', 0)
            campaign_score = min(campaign_count / 3.0, 1.0) * 0.2
            score_factors.append(campaign_score)
            
            # Recency factor
            age_days = (datetime.utcnow() - pattern.created_at).days
            recency_score = max(0, (365 - age_days) / 365) * 0.15
            score_factors.append(recency_score)
            
            # Evolution stability (not too many changes)
            evolution_stability = max(0, 1.0 - len(pattern.evolution_history) / 10.0) * 0.1
            score_factors.append(evolution_stability)
            
            # Anomaly penalty
            anomaly_info = insights.get('anomaly_assessment', {})
            if anomaly_info.get('is_anomalous', False):
                score_factors.append(-0.05)  # Small penalty for anomalous patterns
            
            return max(0.0, min(1.0, sum(score_factors)))
            
        except Exception as e:
            logger.warning(f"Error calculating recommendation score: {e}")
            return 0.5  # Default middle score
    
    def close(self) -> None:
        """Close database connection and cleanup resources."""
        try:
            if self._connection:
                self._connection.close()
                
            self._pattern_cache.clear()
            self._signature_index.clear()
            self._indicator_index.clear()
            
            # Cleanup ML components
            self.pattern_embeddings.clear()
            self.threat_actor_embeddings.clear()
            self.campaign_similarity_cache.clear()
            
            logger.info("Closed threat pattern database")
            
        except Exception as e:
            logger.error(f"Error closing database: {e}")