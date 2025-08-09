"""
Feature Store Integration for ML User Behavior Analysis.

This module provides integration with feature stores for consistent feature serving,
versioning, and management across different ML models and applications.

Performance Engineering Focus:
- Sub-10ms feature retrieval for real-time inference
- Horizontal scaling for high-throughput feature serving
- Efficient feature caching and precomputation
- Version management for feature consistency
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, AsyncGenerator
from enum import Enum
import json
import hashlib
from pathlib import Path
import time

import numpy as np
import pandas as pd
import aioredis
import aiokafka
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, insert, update, delete, text
import joblib
from pydantic import BaseModel, Field

from .feature_engineering_pipeline import FeatureVector, ComputedFeature, FeatureType
from .data_sources_integration import BehaviorEvent

logger = logging.getLogger(__name__)


class FeatureStoreType(Enum):
    """Types of feature stores."""
    REDIS = "redis"
    POSTGRESQL = "postgresql"
    ELASTICSEARCH = "elasticsearch"
    DELTA_LAKE = "delta_lake"
    FEAST = "feast"


class FeatureServingMode(Enum):
    """Feature serving modes."""
    ONLINE = "online"      # Real-time serving
    OFFLINE = "offline"    # Batch/training serving
    HYBRID = "hybrid"      # Both online and offline


@dataclass
class FeatureMetadata:
    """Metadata for a feature definition."""
    name: str
    feature_type: FeatureType
    data_type: str
    description: str
    version: str
    created_at: datetime
    updated_at: datetime
    tags: List[str] = field(default_factory=list)
    owner: str = "system"
    ttl_seconds: Optional[int] = None
    serving_modes: List[FeatureServingMode] = field(default_factory=lambda: [FeatureServingMode.ONLINE])


@dataclass
class FeatureGroup:
    """Group of related features."""
    name: str
    description: str
    features: List[str]
    version: str
    entity_key: str  # Primary key for the features (e.g., user_id)
    created_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureVector:
    """Feature vector with metadata for storage."""
    entity_id: str  # user_id, session_id, etc.
    feature_group: str
    features: Dict[str, Any]
    timestamp: datetime
    version: str = "v1"
    ttl_seconds: Optional[int] = None


@dataclass
class FeatureServingRequest:
    """Request for feature serving."""
    entity_ids: List[str]
    feature_names: List[str]
    timestamp: Optional[datetime] = None
    version: Optional[str] = None
    max_staleness_seconds: int = 300  # 5 minutes default


@dataclass
class FeatureServingResponse:
    """Response from feature serving."""
    features: Dict[str, Dict[str, Any]]  # entity_id -> {feature_name: value}
    metadata: Dict[str, Any]
    served_at: datetime
    latency_ms: float


class FeatureStore(ABC):
    """Abstract feature store interface."""
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the feature store."""
        pass
    
    @abstractmethod
    async def register_feature_group(self, feature_group: FeatureGroup) -> bool:
        """Register a new feature group."""
        pass
    
    @abstractmethod
    async def store_features(self, feature_vectors: List[FeatureVector]) -> bool:
        """Store feature vectors."""
        pass
    
    @abstractmethod
    async def get_features(self, request: FeatureServingRequest) -> FeatureServingResponse:
        """Retrieve features for serving."""
        pass
    
    @abstractmethod
    async def get_feature_metadata(self, feature_name: str) -> Optional[FeatureMetadata]:
        """Get metadata for a specific feature."""
        pass
    
    @abstractmethod
    async def list_feature_groups(self) -> List[FeatureGroup]:
        """List all feature groups."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources."""
        pass


class RedisFeatureStore(FeatureStore):
    """Redis-based feature store for high-performance online serving."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", key_prefix: str = "fs:"):
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.redis_pool = None
        self.performance_metrics = {
            "get_requests": 0,
            "get_latency_ms": [],
            "store_requests": 0,
            "store_latency_ms": [],
            "cache_hits": 0,
            "cache_misses": 0
        }
    
    async def initialize(self) -> None:
        """Initialize Redis connection."""
        self.redis_pool = aioredis.ConnectionPool.from_url(
            self.redis_url,
            max_connections=50,
            encoding="utf-8",
            decode_responses=True
        )
        logger.info("Redis Feature Store initialized")
    
    async def register_feature_group(self, feature_group: FeatureGroup) -> bool:
        """Register feature group in Redis."""
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            key = f"{self.key_prefix}groups:{feature_group.name}"
            
            group_data = asdict(feature_group)
            group_data['created_at'] = group_data['created_at'].isoformat()
            
            await redis.hset(key, mapping={
                "data": json.dumps(group_data, default=str),
                "registered_at": datetime.utcnow().isoformat()
            })
            
            # Create feature name index
            features_key = f"{self.key_prefix}group_features:{feature_group.name}"
            await redis.delete(features_key)
            await redis.sadd(features_key, *feature_group.features)
            
            logger.info(f"Registered feature group: {feature_group.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to register feature group {feature_group.name}: {str(e)}")
            return False
    
    async def store_features(self, feature_vectors: List[FeatureVector]) -> bool:
        """Store feature vectors in Redis."""
        start_time = time.time()
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            pipeline = redis.pipeline()
            
            for fv in feature_vectors:
                # Main feature key
                feature_key = f"{self.key_prefix}features:{fv.feature_group}:{fv.entity_id}"
                
                # Prepare feature data
                feature_data = {
                    "features": json.dumps(fv.features, default=str),
                    "timestamp": fv.timestamp.isoformat(),
                    "version": fv.version,
                    "stored_at": datetime.utcnow().isoformat()
                }
                
                # Store with TTL if specified
                pipeline.hset(feature_key, mapping=feature_data)
                if fv.ttl_seconds:
                    pipeline.expire(feature_key, fv.ttl_seconds)
                
                # Store individual features for faster access
                for feature_name, feature_value in fv.features.items():
                    individual_key = f"{self.key_prefix}feature:{fv.feature_group}:{feature_name}:{fv.entity_id}"
                    individual_data = {
                        "value": json.dumps(feature_value, default=str),
                        "timestamp": fv.timestamp.isoformat(),
                        "version": fv.version
                    }
                    pipeline.hset(individual_key, mapping=individual_data)
                    if fv.ttl_seconds:
                        pipeline.expire(individual_key, fv.ttl_seconds)
            
            await pipeline.execute()
            
            # Update metrics
            latency_ms = (time.time() - start_time) * 1000
            self.performance_metrics["store_requests"] += 1
            self.performance_metrics["store_latency_ms"].append(latency_ms)
            
            logger.debug(f"Stored {len(feature_vectors)} feature vectors in {latency_ms:.2f}ms")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store feature vectors: {str(e)}")
            return False
    
    async def get_features(self, request: FeatureServingRequest) -> FeatureServingResponse:
        """Retrieve features from Redis."""
        start_time = time.time()
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            result_features = {}
            
            # Determine feature group (simplified - assumes single group for request)
            feature_groups = await self._get_feature_groups_for_features(request.feature_names)
            
            for entity_id in request.entity_ids:
                result_features[entity_id] = {}
                
                # Batch get individual features
                pipeline = redis.pipeline()
                feature_keys = []
                
                for feature_group in feature_groups:
                    for feature_name in request.feature_names:
                        feature_key = f"{self.key_prefix}feature:{feature_group}:{feature_name}:{entity_id}"
                        pipeline.hgetall(feature_key)
                        feature_keys.append((feature_group, feature_name, feature_key))
                
                results = await pipeline.execute()
                
                # Process results
                for (feature_group, feature_name, feature_key), result in zip(feature_keys, results):
                    if result:
                        try:
                            feature_data = json.loads(result.get('value', 'null'))
                            feature_timestamp = datetime.fromisoformat(result.get('timestamp', datetime.utcnow().isoformat()))
                            
                            # Check staleness
                            if request.timestamp:
                                staleness_seconds = (request.timestamp - feature_timestamp).total_seconds()
                                if staleness_seconds > request.max_staleness_seconds:
                                    continue  # Skip stale feature
                            
                            result_features[entity_id][feature_name] = feature_data
                            self.performance_metrics["cache_hits"] += 1
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.warning(f"Failed to parse feature {feature_name} for {entity_id}: {str(e)}")
                            self.performance_metrics["cache_misses"] += 1
                    else:
                        self.performance_metrics["cache_misses"] += 1
            
            # Update metrics
            latency_ms = (time.time() - start_time) * 1000
            self.performance_metrics["get_requests"] += 1
            self.performance_metrics["get_latency_ms"].append(latency_ms)
            
            response = FeatureServingResponse(
                features=result_features,
                metadata={
                    "feature_groups": feature_groups,
                    "requested_features": request.feature_names,
                    "cache_stats": self._get_cache_stats()
                },
                served_at=datetime.utcnow(),
                latency_ms=latency_ms
            )
            
            logger.debug(f"Served features for {len(request.entity_ids)} entities in {latency_ms:.2f}ms")
            return response
            
        except Exception as e:
            logger.error(f"Failed to get features: {str(e)}")
            return FeatureServingResponse(
                features={},
                metadata={"error": str(e)},
                served_at=datetime.utcnow(),
                latency_ms=(time.time() - start_time) * 1000
            )
    
    async def get_feature_metadata(self, feature_name: str) -> Optional[FeatureMetadata]:
        """Get metadata for a feature."""
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            metadata_key = f"{self.key_prefix}metadata:{feature_name}"
            
            metadata_data = await redis.hgetall(metadata_key)
            if metadata_data:
                metadata_dict = json.loads(metadata_data.get('data', '{}'))
                return FeatureMetadata(**metadata_dict)
            
            return None
        except Exception as e:
            logger.error(f"Failed to get feature metadata for {feature_name}: {str(e)}")
            return None
    
    async def list_feature_groups(self) -> List[FeatureGroup]:
        """List all feature groups."""
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            pattern = f"{self.key_prefix}groups:*"
            
            group_keys = await redis.keys(pattern)
            groups = []
            
            for key in group_keys:
                group_data = await redis.hgetall(key)
                if group_data:
                    group_dict = json.loads(group_data.get('data', '{}'))
                    group_dict['created_at'] = datetime.fromisoformat(group_dict['created_at'])
                    groups.append(FeatureGroup(**group_dict))
            
            return groups
        except Exception as e:
            logger.error(f"Failed to list feature groups: {str(e)}")
            return []
    
    async def _get_feature_groups_for_features(self, feature_names: List[str]) -> List[str]:
        """Get feature groups that contain the requested features."""
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            # For simplicity, check all registered groups
            groups = await self.list_feature_groups()
            matching_groups = []
            
            for group in groups:
                if any(feature_name in group.features for feature_name in feature_names):
                    matching_groups.append(group.name)
            
            return matching_groups or ["default"]  # Fallback to default group
        except Exception:
            return ["default"]
    
    def _get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        total_requests = self.performance_metrics["cache_hits"] + self.performance_metrics["cache_misses"]
        hit_rate = (self.performance_metrics["cache_hits"] / total_requests * 100) if total_requests > 0 else 0
        
        avg_get_latency = (
            sum(self.performance_metrics["get_latency_ms"]) / len(self.performance_metrics["get_latency_ms"])
            if self.performance_metrics["get_latency_ms"] else 0
        )
        
        avg_store_latency = (
            sum(self.performance_metrics["store_latency_ms"]) / len(self.performance_metrics["store_latency_ms"])
            if self.performance_metrics["store_latency_ms"] else 0
        )
        
        return {
            "hit_rate_percentage": hit_rate,
            "cache_hits": self.performance_metrics["cache_hits"],
            "cache_misses": self.performance_metrics["cache_misses"],
            "average_get_latency_ms": avg_get_latency,
            "average_store_latency_ms": avg_store_latency,
            "total_get_requests": self.performance_metrics["get_requests"],
            "total_store_requests": self.performance_metrics["store_requests"]
        }
    
    async def cleanup(self) -> None:
        """Cleanup Redis connections."""
        if self.redis_pool:
            await self.redis_pool.disconnect()


class PostgreSQLFeatureStore(FeatureStore):
    """PostgreSQL-based feature store for offline/batch serving."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.engine = None
        self.session_factory = None
    
    async def initialize(self) -> None:
        """Initialize PostgreSQL connection."""
        self.engine = create_async_engine(
            self.connection_string,
            pool_size=20,
            max_overflow=30,
            pool_pre_ping=True
        )
        
        self.session_factory = sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        # Create tables
        await self._create_tables()
        logger.info("PostgreSQL Feature Store initialized")
    
    async def _create_tables(self) -> None:
        """Create feature store tables."""
        create_tables_sql = """
        CREATE TABLE IF NOT EXISTS feature_groups (
            name VARCHAR(255) PRIMARY KEY,
            description TEXT,
            features JSONB,
            version VARCHAR(50),
            entity_key VARCHAR(255),
            created_at TIMESTAMP,
            metadata JSONB
        );
        
        CREATE TABLE IF NOT EXISTS feature_vectors (
            id SERIAL PRIMARY KEY,
            entity_id VARCHAR(255),
            feature_group VARCHAR(255),
            features JSONB,
            timestamp TIMESTAMP,
            version VARCHAR(50),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ttl_expires_at TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_feature_vectors_entity_group 
        ON feature_vectors(entity_id, feature_group);
        
        CREATE INDEX IF NOT EXISTS idx_feature_vectors_timestamp 
        ON feature_vectors(timestamp);
        
        CREATE INDEX IF NOT EXISTS idx_feature_vectors_ttl 
        ON feature_vectors(ttl_expires_at);
        
        CREATE TABLE IF NOT EXISTS feature_metadata (
            name VARCHAR(255) PRIMARY KEY,
            feature_type VARCHAR(50),
            data_type VARCHAR(50),
            description TEXT,
            version VARCHAR(50),
            created_at TIMESTAMP,
            updated_at TIMESTAMP,
            tags JSONB,
            owner VARCHAR(255),
            ttl_seconds INTEGER,
            serving_modes JSONB
        );
        """
        
        async with self.engine.begin() as conn:
            for statement in create_tables_sql.split(';'):
                if statement.strip():
                    await conn.execute(text(statement))
    
    async def register_feature_group(self, feature_group: FeatureGroup) -> bool:
        """Register feature group in PostgreSQL."""
        try:
            async with self.session_factory() as session:
                # Check if group exists
                result = await session.execute(
                    select(text("1")).select_from(text("feature_groups")).where(text("name = :name")),
                    {"name": feature_group.name}
                )
                exists = result.first() is not None
                
                if exists:
                    # Update existing
                    await session.execute(
                        update(text("feature_groups")).where(text("name = :name")).values(
                            description=feature_group.description,
                            features=json.dumps(feature_group.features),
                            version=feature_group.version,
                            entity_key=feature_group.entity_key,
                            metadata=json.dumps(feature_group.metadata)
                        ),
                        {"name": feature_group.name}
                    )
                else:
                    # Insert new
                    await session.execute(
                        insert(text("feature_groups")).values(
                            name=feature_group.name,
                            description=feature_group.description,
                            features=json.dumps(feature_group.features),
                            version=feature_group.version,
                            entity_key=feature_group.entity_key,
                            created_at=feature_group.created_at,
                            metadata=json.dumps(feature_group.metadata)
                        )
                    )
                
                await session.commit()
                logger.info(f"Registered feature group: {feature_group.name}")
                return True
        except Exception as e:
            logger.error(f"Failed to register feature group {feature_group.name}: {str(e)}")
            return False
    
    async def store_features(self, feature_vectors: List[FeatureVector]) -> bool:
        """Store feature vectors in PostgreSQL."""
        try:
            async with self.session_factory() as session:
                for fv in feature_vectors:
                    ttl_expires_at = None
                    if fv.ttl_seconds:
                        ttl_expires_at = fv.timestamp + timedelta(seconds=fv.ttl_seconds)
                    
                    await session.execute(
                        insert(text("feature_vectors")).values(
                            entity_id=fv.entity_id,
                            feature_group=fv.feature_group,
                            features=json.dumps(fv.features, default=str),
                            timestamp=fv.timestamp,
                            version=fv.version,
                            ttl_expires_at=ttl_expires_at
                        )
                    )
                
                await session.commit()
                logger.debug(f"Stored {len(feature_vectors)} feature vectors in PostgreSQL")
                return True
        except Exception as e:
            logger.error(f"Failed to store feature vectors: {str(e)}")
            return False
    
    async def get_features(self, request: FeatureServingRequest) -> FeatureServingResponse:
        """Retrieve features from PostgreSQL."""
        start_time = time.time()
        
        try:
            async with self.session_factory() as session:
                result_features = {}
                
                for entity_id in request.entity_ids:
                    result_features[entity_id] = {}
                    
                    # Build query
                    query_conditions = ["entity_id = :entity_id"]
                    params = {"entity_id": entity_id}
                    
                    if request.timestamp:
                        query_conditions.append("timestamp <= :max_timestamp")
                        params["max_timestamp"] = request.timestamp
                        
                        # Staleness check
                        min_timestamp = request.timestamp - timedelta(seconds=request.max_staleness_seconds)
                        query_conditions.append("timestamp >= :min_timestamp")
                        params["min_timestamp"] = min_timestamp
                    
                    # TTL check
                    query_conditions.append("(ttl_expires_at IS NULL OR ttl_expires_at > NOW())")
                    
                    query_sql = f"""
                        SELECT DISTINCT ON (feature_group) 
                               feature_group, features, timestamp, version
                        FROM feature_vectors 
                        WHERE {' AND '.join(query_conditions)}
                        ORDER BY feature_group, timestamp DESC
                    """
                    
                    result = await session.execute(text(query_sql), params)
                    rows = result.fetchall()
                    
                    # Extract requested features
                    for row in rows:
                        feature_data = json.loads(row.features)
                        for feature_name in request.feature_names:
                            if feature_name in feature_data:
                                result_features[entity_id][feature_name] = feature_data[feature_name]
                
                latency_ms = (time.time() - start_time) * 1000
                
                response = FeatureServingResponse(
                    features=result_features,
                    metadata={
                        "source": "postgresql",
                        "requested_features": request.feature_names
                    },
                    served_at=datetime.utcnow(),
                    latency_ms=latency_ms
                )
                
                logger.debug(f"Served features for {len(request.entity_ids)} entities in {latency_ms:.2f}ms")
                return response
                
        except Exception as e:
            logger.error(f"Failed to get features: {str(e)}")
            return FeatureServingResponse(
                features={},
                metadata={"error": str(e)},
                served_at=datetime.utcnow(),
                latency_ms=(time.time() - start_time) * 1000
            )
    
    async def get_feature_metadata(self, feature_name: str) -> Optional[FeatureMetadata]:
        """Get metadata for a feature."""
        try:
            async with self.session_factory() as session:
                result = await session.execute(
                    select(text("*")).select_from(text("feature_metadata")).where(text("name = :name")),
                    {"name": feature_name}
                )
                row = result.first()
                
                if row:
                    return FeatureMetadata(
                        name=row.name,
                        feature_type=FeatureType(row.feature_type),
                        data_type=row.data_type,
                        description=row.description,
                        version=row.version,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                        tags=json.loads(row.tags or '[]'),
                        owner=row.owner,
                        ttl_seconds=row.ttl_seconds,
                        serving_modes=[FeatureServingMode(mode) for mode in json.loads(row.serving_modes or '[]')]
                    )
                
                return None
        except Exception as e:
            logger.error(f"Failed to get feature metadata for {feature_name}: {str(e)}")
            return None
    
    async def list_feature_groups(self) -> List[FeatureGroup]:
        """List all feature groups."""
        try:
            async with self.session_factory() as session:
                result = await session.execute(select(text("*")).select_from(text("feature_groups")))
                rows = result.fetchall()
                
                groups = []
                for row in rows:
                    groups.append(FeatureGroup(
                        name=row.name,
                        description=row.description,
                        features=json.loads(row.features),
                        version=row.version,
                        entity_key=row.entity_key,
                        created_at=row.created_at,
                        metadata=json.loads(row.metadata or '{}')
                    ))
                
                return groups
        except Exception as e:
            logger.error(f"Failed to list feature groups: {str(e)}")
            return []
    
    async def cleanup(self) -> None:
        """Cleanup PostgreSQL connections."""
        if self.engine:
            await self.engine.dispose()


class HybridFeatureStore(FeatureStore):
    """Hybrid feature store combining online and offline stores."""
    
    def __init__(self, online_store: FeatureStore, offline_store: FeatureStore):
        self.online_store = online_store
        self.offline_store = offline_store
        self.routing_rules = {}  # feature_name -> preferred store
    
    async def initialize(self) -> None:
        """Initialize both stores."""
        await asyncio.gather(
            self.online_store.initialize(),
            self.offline_store.initialize()
        )
        logger.info("Hybrid Feature Store initialized")
    
    def configure_routing(self, feature_routing: Dict[str, FeatureStoreType]) -> None:
        """Configure which features should be served from which store."""
        self.routing_rules = feature_routing
    
    async def register_feature_group(self, feature_group: FeatureGroup) -> bool:
        """Register feature group in both stores."""
        online_result, offline_result = await asyncio.gather(
            self.online_store.register_feature_group(feature_group),
            self.offline_store.register_feature_group(feature_group),
            return_exceptions=True
        )
        
        return (
            not isinstance(online_result, Exception) and online_result and
            not isinstance(offline_result, Exception) and offline_result
        )
    
    async def store_features(self, feature_vectors: List[FeatureVector]) -> bool:
        """Store features in both online and offline stores."""
        online_result, offline_result = await asyncio.gather(
            self.online_store.store_features(feature_vectors),
            self.offline_store.store_features(feature_vectors),
            return_exceptions=True
        )
        
        return (
            not isinstance(online_result, Exception) and online_result and
            not isinstance(offline_result, Exception) and offline_result
        )
    
    async def get_features(self, request: FeatureServingRequest) -> FeatureServingResponse:
        """Route feature requests to appropriate store."""
        # Determine routing
        online_features = []
        offline_features = []
        
        for feature_name in request.feature_names:
            preferred_store = self.routing_rules.get(feature_name, FeatureStoreType.REDIS)
            if preferred_store == FeatureStoreType.REDIS:
                online_features.append(feature_name)
            else:
                offline_features.append(feature_name)
        
        # Create separate requests
        responses = []
        
        if online_features:
            online_request = FeatureServingRequest(
                entity_ids=request.entity_ids,
                feature_names=online_features,
                timestamp=request.timestamp,
                version=request.version,
                max_staleness_seconds=request.max_staleness_seconds
            )
            online_response = await self.online_store.get_features(online_request)
            responses.append(online_response)
        
        if offline_features:
            offline_request = FeatureServingRequest(
                entity_ids=request.entity_ids,
                feature_names=offline_features,
                timestamp=request.timestamp,
                version=request.version,
                max_staleness_seconds=request.max_staleness_seconds
            )
            offline_response = await self.offline_store.get_features(offline_request)
            responses.append(offline_response)
        
        # Merge responses
        merged_features = {}
        total_latency = 0.0
        
        for response in responses:
            for entity_id, features in response.features.items():
                if entity_id not in merged_features:
                    merged_features[entity_id] = {}
                merged_features[entity_id].update(features)
            total_latency = max(total_latency, response.latency_ms)
        
        return FeatureServingResponse(
            features=merged_features,
            metadata={
                "routing": {"online": online_features, "offline": offline_features},
                "stores_used": len(responses)
            },
            served_at=datetime.utcnow(),
            latency_ms=total_latency
        )
    
    async def get_feature_metadata(self, feature_name: str) -> Optional[FeatureMetadata]:
        """Get metadata from online store first, then offline."""
        metadata = await self.online_store.get_feature_metadata(feature_name)
        if not metadata:
            metadata = await self.offline_store.get_feature_metadata(feature_name)
        return metadata
    
    async def list_feature_groups(self) -> List[FeatureGroup]:
        """List feature groups from online store."""
        return await self.online_store.list_feature_groups()
    
    async def cleanup(self) -> None:
        """Cleanup both stores."""
        await asyncio.gather(
            self.online_store.cleanup(),
            self.offline_store.cleanup()
        )


class FeatureStoreManager:
    """High-level manager for feature store operations."""
    
    def __init__(self, feature_store: FeatureStore):
        self.feature_store = feature_store
        self.registered_groups = {}
        self.performance_metrics = {
            "store_operations": 0,
            "get_operations": 0,
            "average_store_latency_ms": 0.0,
            "average_get_latency_ms": 0.0
        }
    
    async def initialize(self) -> None:
        """Initialize the feature store manager."""
        await self.feature_store.initialize()
        
        # Register default feature groups for behavioral analysis
        await self._register_default_feature_groups()
        
        logger.info("Feature Store Manager initialized")
    
    async def _register_default_feature_groups(self) -> None:
        """Register default feature groups for behavioral analysis."""
        # Temporal features group
        temporal_group = FeatureGroup(
            name="temporal_features",
            description="Time-based behavioral features",
            features=[
                "hour_of_day", "day_of_week", "is_weekend", "is_business_hours",
                "time_since_last_activity", "session_duration", "login_frequency_1h",
                "login_frequency_24h", "activity_burst_score", "time_pattern_anomaly"
            ],
            version="v1",
            entity_key="user_id",
            created_at=datetime.utcnow(),
            metadata={"category": "temporal", "update_frequency": "real_time"}
        )
        
        # Categorical features group
        categorical_group = FeatureGroup(
            name="categorical_features",
            description="Categorical and contextual behavioral features",
            features=[
                "device_change_score", "location_change_score", "user_agent_change_score",
                "ip_reputation_score", "is_new_device", "is_new_location",
                "device_diversity_score", "location_entropy"
            ],
            version="v1",
            entity_key="user_id",
            created_at=datetime.utcnow(),
            metadata={"category": "categorical", "update_frequency": "real_time"}
        )
        
        # Behavioral features group
        behavioral_group = FeatureGroup(
            name="behavioral_features",
            description="Behavioral aggregation and pattern features",
            features=[
                "resource_access_rate", "unique_resources_count", "api_call_diversity",
                "data_transfer_volume", "failure_rate", "admin_action_count",
                "privilege_escalation_attempts", "behavioral_consistency_score"
            ],
            version="v1",
            entity_key="user_id",
            created_at=datetime.utcnow(),
            metadata={"category": "behavioral", "update_frequency": "real_time"}
        )
        
        # Register groups
        for group in [temporal_group, categorical_group, behavioral_group]:
            success = await self.feature_store.register_feature_group(group)
            if success:
                self.registered_groups[group.name] = group
                logger.info(f"Registered feature group: {group.name}")
    
    async def store_behavior_features(self, user_id: str, features: Dict[str, Any], 
                                   timestamp: datetime = None) -> bool:
        """Store behavioral features organized by feature groups."""
        if timestamp is None:
            timestamp = datetime.utcnow()
        
        # Organize features by groups
        feature_vectors = []
        
        for group_name, group in self.registered_groups.items():
            group_features = {}
            
            # Extract features belonging to this group
            for feature_name in group.features:
                if feature_name in features:
                    group_features[feature_name] = features[feature_name]
            
            if group_features:
                fv = FeatureVector(
                    entity_id=user_id,
                    feature_group=group_name,
                    features=group_features,
                    timestamp=timestamp,
                    version=group.version,
                    ttl_seconds=86400  # 24 hours TTL
                )
                feature_vectors.append(fv)
        
        if feature_vectors:
            return await self.feature_store.store_features(feature_vectors)
        
        return False
    
    async def get_behavior_features(self, user_ids: List[str], 
                                  feature_names: Optional[List[str]] = None,
                                  max_staleness_seconds: int = 300) -> FeatureServingResponse:
        """Get behavioral features for users."""
        # Use all features if none specified
        if feature_names is None:
            feature_names = []
            for group in self.registered_groups.values():
                feature_names.extend(group.features)
        
        request = FeatureServingRequest(
            entity_ids=user_ids,
            feature_names=feature_names,
            timestamp=datetime.utcnow(),
            max_staleness_seconds=max_staleness_seconds
        )
        
        return await self.feature_store.get_features(request)
    
    async def get_user_feature_vector(self, user_id: str, 
                                    feature_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get complete feature vector for a single user."""
        response = await self.get_behavior_features([user_id], feature_names)
        return response.features.get(user_id, {})
    
    async def validate_feature_freshness(self, user_id: str, max_age_seconds: int = 300) -> Dict[str, Any]:
        """Validate freshness of user features."""
        # Get recent features
        response = await self.get_behavior_features([user_id], max_staleness_seconds=max_age_seconds)
        user_features = response.features.get(user_id, {})
        
        # Calculate freshness metrics
        total_features = 0
        for group in self.registered_groups.values():
            total_features += len(group.features)
        
        available_features = len(user_features)
        freshness_ratio = available_features / total_features if total_features > 0 else 0
        
        return {
            "user_id": user_id,
            "total_expected_features": total_features,
            "available_features": available_features,
            "freshness_ratio": freshness_ratio,
            "is_fresh": freshness_ratio >= 0.8,  # 80% threshold
            "served_at": response.served_at,
            "serving_latency_ms": response.latency_ms
        }
    
    async def get_performance_metrics(self) -> Dict[str, Any]:
        """Get feature store performance metrics."""
        # Get metrics from underlying store if available
        store_metrics = {}
        if hasattr(self.feature_store, '_get_cache_stats'):
            store_metrics = self.feature_store._get_cache_stats()
        elif hasattr(self.feature_store, 'performance_metrics'):
            store_metrics = self.feature_store.performance_metrics
        
        return {
            "manager_metrics": self.performance_metrics,
            "store_metrics": store_metrics,
            "registered_groups": len(self.registered_groups),
            "total_features": sum(len(group.features) for group in self.registered_groups.values())
        }
    
    async def cleanup(self) -> None:
        """Cleanup feature store resources."""
        await self.feature_store.cleanup()


# Factory functions
async def create_redis_feature_store(redis_url: str = "redis://localhost:6379") -> RedisFeatureStore:
    """Create and initialize Redis feature store."""
    store = RedisFeatureStore(redis_url)
    await store.initialize()
    return store


async def create_postgresql_feature_store(connection_string: str) -> PostgreSQLFeatureStore:
    """Create and initialize PostgreSQL feature store."""
    store = PostgreSQLFeatureStore(connection_string)
    await store.initialize()
    return store


async def create_hybrid_feature_store(redis_url: str = "redis://localhost:6379",
                                    postgres_connection: str = "") -> HybridFeatureStore:
    """Create and initialize hybrid feature store."""
    online_store = await create_redis_feature_store(redis_url)
    offline_store = await create_postgresql_feature_store(postgres_connection)
    
    hybrid_store = HybridFeatureStore(online_store, offline_store)
    await hybrid_store.initialize()
    
    # Configure default routing
    hybrid_store.configure_routing({
        # Route real-time features to Redis
        "hour_of_day": FeatureStoreType.REDIS,
        "session_duration": FeatureStoreType.REDIS,
        "resource_access_rate": FeatureStoreType.REDIS,
        "failure_rate": FeatureStoreType.REDIS,
        
        # Route historical features to PostgreSQL
        "behavioral_consistency_score": FeatureStoreType.POSTGRESQL,
        "time_pattern_anomaly": FeatureStoreType.POSTGRESQL,
        "location_entropy": FeatureStoreType.POSTGRESQL,
    })
    
    return hybrid_store


async def initialize_feature_store_manager(store_type: FeatureStoreType = FeatureStoreType.REDIS,
                                         **config) -> FeatureStoreManager:
    """Initialize feature store manager with specified store type."""
    if store_type == FeatureStoreType.REDIS:
        redis_url = config.get('redis_url', 'redis://localhost:6379')
        feature_store = await create_redis_feature_store(redis_url)
    elif store_type == FeatureStoreType.POSTGRESQL:
        connection_string = config.get('connection_string', '')
        feature_store = await create_postgresql_feature_store(connection_string)
    elif store_type == FeatureStoreType.DELTA_LAKE:
        # Placeholder for future Delta Lake implementation
        raise NotImplementedError("Delta Lake feature store not yet implemented")
    else:
        # Default to hybrid
        feature_store = await create_hybrid_feature_store(
            redis_url=config.get('redis_url', 'redis://localhost:6379'),
            postgres_connection=config.get('postgres_connection', '')
        )
    
    manager = FeatureStoreManager(feature_store)
    await manager.initialize()
    
    logger.info(f"Feature Store Manager initialized with {store_type.value} store")
    return manager


# Example usage and testing
if __name__ == "__main__":
    async def test_feature_store():
        # Initialize feature store manager
        manager = await initialize_feature_store_manager(FeatureStoreType.REDIS)
        
        # Sample features
        sample_features = {
            "hour_of_day": 14,
            "is_weekend": False,
            "device_change_score": 0.2,
            "resource_access_rate": 15.5,
            "behavioral_consistency_score": 0.85
        }
        
        user_id = "test_user_123"
        
        # Store features
        success = await manager.store_behavior_features(user_id, sample_features)
        print(f"Stored features: {success}")
        
        # Retrieve features
        response = await manager.get_behavior_features([user_id])
        print(f"Retrieved features: {response.features}")
        print(f"Serving latency: {response.latency_ms:.2f}ms")
        
        # Validate freshness
        freshness = await manager.validate_feature_freshness(user_id)
        print(f"Feature freshness: {freshness}")
        
        # Performance metrics
        metrics = await manager.get_performance_metrics()
        print(f"Performance metrics: {metrics}")
        
        # Cleanup
        await manager.cleanup()
    
    asyncio.run(test_feature_store())