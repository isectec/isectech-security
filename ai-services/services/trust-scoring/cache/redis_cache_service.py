"""
iSECTECH Trust Scoring Redis Cache Service
Production-grade caching implementation for high-performance trust score calculations
Supports 100,000+ operations per second with intelligent caching strategies
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from concurrent.futures import ThreadPoolExecutor
import hashlib
import pickle
import zlib

import redis.asyncio as redis
from redis.exceptions import ConnectionError, TimeoutError, RedisError
import redis.sentinel
from prometheus_client import Counter, Histogram, Gauge

# Metrics
cache_hits = Counter('trust_score_cache_hits_total', 'Total cache hits', ['cache_type', 'region'])
cache_misses = Counter('trust_score_cache_misses_total', 'Total cache misses', ['cache_type', 'region'])
cache_operations = Histogram('trust_score_cache_operation_duration_seconds', 'Cache operation duration', ['operation', 'cache_type'])
cache_memory_usage = Gauge('trust_score_cache_memory_bytes', 'Cache memory usage', ['instance', 'region'])
cache_connections = Gauge('trust_score_cache_connections_active', 'Active cache connections', ['instance', 'region'])


@dataclass
class CacheConfiguration:
    """Redis cache configuration"""
    redis_url: str
    sentinel_hosts: List[Tuple[str, int]]
    master_name: str
    password: str
    db: int = 0
    max_connections: int = 100
    health_check_interval: int = 30
    retry_attempts: int = 3
    timeout: int = 5
    region: str = 'primary'
    
    # Cache policies
    trust_score_ttl: int = 300  # 5 minutes
    device_profile_ttl: int = 1800  # 30 minutes  
    network_context_ttl: int = 600  # 10 minutes
    threat_intelligence_ttl: int = 3600  # 1 hour
    
    # Performance settings
    compression_enabled: bool = True
    compression_threshold: int = 1024  # bytes
    serialization_format: str = 'pickle'  # pickle, json, msgpack
    pipeline_size: int = 100


@dataclass 
class TrustScoreData:
    """Trust score data structure"""
    device_id: str
    user_id: str
    score: float
    confidence: float
    factors: Dict[str, Any]
    timestamp: datetime
    expires_at: datetime
    metadata: Dict[str, Any]


@dataclass
class CacheStats:
    """Cache statistics"""
    hits: int = 0
    misses: int = 0
    errors: int = 0
    total_operations: int = 0
    hit_rate: float = 0.0
    average_response_time: float = 0.0
    memory_usage: int = 0
    active_connections: int = 0


class TrustScoreRedisCache:
    """High-performance Redis cache for trust scoring system"""
    
    def __init__(self, config: CacheConfiguration):
        self.config = config
        self.logger = self._setup_logging()
        self.redis_client: Optional[redis.Redis] = None
        self.sentinel: Optional[redis.sentinel.Sentinel] = None
        self.stats = CacheStats()
        self.executor = ThreadPoolExecutor(max_workers=10)
        self._health_check_task: Optional[asyncio.Task] = None
        self._connected = False
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    async def connect(self) -> bool:
        """Establish connection to Redis with Sentinel support"""
        try:
            self.logger.info(f"Connecting to Redis in region: {self.config.region}")
            
            if self.config.sentinel_hosts:
                # Use Sentinel for high availability
                self.logger.info("Connecting via Redis Sentinel...")
                self.sentinel = redis.sentinel.Sentinel(
                    self.config.sentinel_hosts,
                    password=self.config.password,
                    socket_timeout=self.config.timeout
                )
                
                # Get master connection
                self.redis_client = self.sentinel.master_for(
                    self.config.master_name,
                    password=self.config.password,
                    db=self.config.db,
                    socket_timeout=self.config.timeout,
                    retry_on_timeout=True,
                    decode_responses=False  # We handle binary data
                )
            else:
                # Direct connection
                self.redis_client = redis.from_url(
                    self.config.redis_url,
                    db=self.config.db,
                    password=self.config.password,
                    max_connections=self.config.max_connections,
                    socket_timeout=self.config.timeout,
                    retry_on_timeout=True,
                    decode_responses=False
                )
            
            # Test connection
            await self.redis_client.ping()
            self._connected = True
            
            # Start health check task
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.logger.info("Redis connection established successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Redis"""
        self._connected = False
        
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self.redis_client:
            await self.redis_client.close()
            
        self.executor.shutdown(wait=True)
        self.logger.info("Redis connection closed")
    
    async def _health_check_loop(self):
        """Periodic health check for Redis connection"""
        while self._connected:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                
                # Ping Redis
                await self.redis_client.ping()
                
                # Update connection metrics
                info = await self.redis_client.info()
                cache_memory_usage.labels(
                    instance=self.config.master_name,
                    region=self.config.region
                ).set(info.get('used_memory', 0))
                
                cache_connections.labels(
                    instance=self.config.master_name,
                    region=self.config.region
                ).set(info.get('connected_clients', 0))
                
                self.stats.memory_usage = info.get('used_memory', 0)
                self.stats.active_connections = info.get('connected_clients', 0)
                
            except Exception as e:
                self.logger.warning(f"Health check failed: {e}")
                # Attempt to reconnect
                if not await self.connect():
                    self.logger.error("Failed to reconnect to Redis")
    
    def _generate_cache_key(self, key_type: str, identifier: str, **kwargs) -> str:
        """Generate cache key with consistent format"""
        key_parts = [
            'isectech',
            'trust_score',
            key_type,
            identifier
        ]
        
        # Add additional key components
        for k, v in sorted(kwargs.items()):
            key_parts.append(f"{k}:{v}")
        
        key = ":".join(key_parts)
        
        # Hash long keys to prevent key length issues
        if len(key) > 200:
            key_hash = hashlib.md5(key.encode()).hexdigest()
            return f"isectech:trust_score:{key_type}:hash:{key_hash}"
        
        return key
    
    def _serialize_data(self, data: Any) -> bytes:
        """Serialize data for Redis storage with optional compression"""
        try:
            if self.config.serialization_format == 'pickle':
                serialized = pickle.dumps(data)
            elif self.config.serialization_format == 'json':
                serialized = json.dumps(data, default=str).encode('utf-8')
            else:
                raise ValueError(f"Unsupported serialization format: {self.config.serialization_format}")
            
            # Apply compression if data is large enough
            if self.config.compression_enabled and len(serialized) > self.config.compression_threshold:
                compressed = zlib.compress(serialized)
                # Only use compression if it actually reduces size
                if len(compressed) < len(serialized):
                    return b'compressed:' + compressed
            
            return serialized
            
        except Exception as e:
            self.logger.error(f"Serialization failed: {e}")
            raise
    
    def _deserialize_data(self, data: bytes) -> Any:
        """Deserialize data from Redis storage"""
        try:
            # Check if data was compressed
            if data.startswith(b'compressed:'):
                data = zlib.decompress(data[11:])  # Remove 'compressed:' prefix
            
            if self.config.serialization_format == 'pickle':
                return pickle.loads(data)
            elif self.config.serialization_format == 'json':
                return json.loads(data.decode('utf-8'))
            else:
                raise ValueError(f"Unsupported serialization format: {self.config.serialization_format}")
                
        except Exception as e:
            self.logger.error(f"Deserialization failed: {e}")
            raise
    
    @cache_operations.labels(operation='get', cache_type='trust_score').time()
    async def get_trust_score(self, device_id: str, user_id: str) -> Optional[TrustScoreData]:
        """Get trust score from cache"""
        cache_key = self._generate_cache_key('score', device_id, user_id=user_id)
        
        try:
            start_time = time.time()
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                trust_score_data = self._deserialize_data(cached_data)
                
                # Check if data has expired
                if trust_score_data.expires_at > datetime.now():
                    cache_hits.labels(cache_type='trust_score', region=self.config.region).inc()
                    self.stats.hits += 1
                    
                    response_time = time.time() - start_time
                    self.stats.average_response_time = (
                        (self.stats.average_response_time * self.stats.total_operations + response_time) /
                        (self.stats.total_operations + 1)
                    )
                    self.stats.total_operations += 1
                    
                    self.logger.debug(f"Cache hit for trust score: {device_id}")
                    return trust_score_data
                else:
                    # Data expired, remove from cache
                    await self.redis_client.delete(cache_key)
            
            cache_misses.labels(cache_type='trust_score', region=self.config.region).inc()
            self.stats.misses += 1
            self.stats.total_operations += 1
            
            self.logger.debug(f"Cache miss for trust score: {device_id}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting trust score from cache: {e}")
            self.stats.errors += 1
            return None
    
    @cache_operations.labels(operation='set', cache_type='trust_score').time()
    async def set_trust_score(self, trust_score_data: TrustScoreData) -> bool:
        """Store trust score in cache"""
        cache_key = self._generate_cache_key(
            'score', 
            trust_score_data.device_id, 
            user_id=trust_score_data.user_id
        )
        
        try:
            # Set expiration time
            trust_score_data.expires_at = datetime.now() + timedelta(seconds=self.config.trust_score_ttl)
            
            serialized_data = self._serialize_data(trust_score_data)
            
            await self.redis_client.setex(
                cache_key,
                self.config.trust_score_ttl,
                serialized_data
            )
            
            self.logger.debug(f"Trust score cached: {trust_score_data.device_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting trust score in cache: {e}")
            self.stats.errors += 1
            return False
    
    async def get_device_profile(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device profile from cache"""
        cache_key = self._generate_cache_key('device_profile', device_id)
        
        try:
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                cache_hits.labels(cache_type='device_profile', region=self.config.region).inc()
                return self._deserialize_data(cached_data)
            
            cache_misses.labels(cache_type='device_profile', region=self.config.region).inc()
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting device profile from cache: {e}")
            return None
    
    async def set_device_profile(self, device_id: str, profile_data: Dict[str, Any]) -> bool:
        """Store device profile in cache"""
        cache_key = self._generate_cache_key('device_profile', device_id)
        
        try:
            serialized_data = self._serialize_data(profile_data)
            await self.redis_client.setex(
                cache_key,
                self.config.device_profile_ttl,
                serialized_data
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting device profile in cache: {e}")
            return False
    
    async def get_network_context(self, network_id: str) -> Optional[Dict[str, Any]]:
        """Get network context from cache"""
        cache_key = self._generate_cache_key('network_context', network_id)
        
        try:
            cached_data = await self.redis_client.get(cache_key)
            if cached_data:
                cache_hits.labels(cache_type='network_context', region=self.config.region).inc()
                return self._deserialize_data(cached_data)
            
            cache_misses.labels(cache_type='network_context', region=self.config.region).inc()
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting network context from cache: {e}")
            return None
    
    async def set_network_context(self, network_id: str, context_data: Dict[str, Any]) -> bool:
        """Store network context in cache"""
        cache_key = self._generate_cache_key('network_context', network_id)
        
        try:
            serialized_data = self._serialize_data(context_data)
            await self.redis_client.setex(
                cache_key,
                self.config.network_context_ttl,
                serialized_data
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting network context in cache: {e}")
            return False
    
    async def bulk_get_trust_scores(self, device_ids: List[str], user_id: str) -> Dict[str, Optional[TrustScoreData]]:
        """Get multiple trust scores in bulk for efficiency"""
        cache_keys = [
            self._generate_cache_key('score', device_id, user_id=user_id)
            for device_id in device_ids
        ]
        
        try:
            # Use pipeline for bulk operations
            pipe = self.redis_client.pipeline()
            for key in cache_keys:
                pipe.get(key)
            
            results = await pipe.execute()
            
            trust_scores = {}
            for i, result in enumerate(results):
                device_id = device_ids[i]
                if result:
                    try:
                        trust_score_data = self._deserialize_data(result)
                        if trust_score_data.expires_at > datetime.now():
                            trust_scores[device_id] = trust_score_data
                            cache_hits.labels(cache_type='trust_score', region=self.config.region).inc()
                        else:
                            trust_scores[device_id] = None
                            cache_misses.labels(cache_type='trust_score', region=self.config.region).inc()
                    except Exception as e:
                        self.logger.error(f"Error deserializing trust score for {device_id}: {e}")
                        trust_scores[device_id] = None
                else:
                    trust_scores[device_id] = None
                    cache_misses.labels(cache_type='trust_score', region=self.config.region).inc()
            
            return trust_scores
            
        except Exception as e:
            self.logger.error(f"Error in bulk get trust scores: {e}")
            return {device_id: None for device_id in device_ids}
    
    async def bulk_set_trust_scores(self, trust_scores: List[TrustScoreData]) -> bool:
        """Set multiple trust scores in bulk for efficiency"""
        try:
            pipe = self.redis_client.pipeline()
            
            for trust_score in trust_scores:
                cache_key = self._generate_cache_key(
                    'score',
                    trust_score.device_id,
                    user_id=trust_score.user_id
                )
                
                # Set expiration time
                trust_score.expires_at = datetime.now() + timedelta(seconds=self.config.trust_score_ttl)
                serialized_data = self._serialize_data(trust_score)
                
                pipe.setex(cache_key, self.config.trust_score_ttl, serialized_data)
            
            await pipe.execute()
            return True
            
        except Exception as e:
            self.logger.error(f"Error in bulk set trust scores: {e}")
            return False
    
    async def invalidate_user_scores(self, user_id: str) -> bool:
        """Invalidate all trust scores for a user"""
        try:
            pattern = self._generate_cache_key('score', '*', user_id=user_id)
            
            # Find all matching keys
            matching_keys = []
            async for key in self.redis_client.scan_iter(match=pattern):
                matching_keys.append(key)
            
            if matching_keys:
                await self.redis_client.delete(*matching_keys)
                self.logger.info(f"Invalidated {len(matching_keys)} trust scores for user {user_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error invalidating user scores: {e}")
            return False
    
    async def invalidate_device_cache(self, device_id: str) -> bool:
        """Invalidate all cache entries for a device"""
        try:
            patterns = [
                self._generate_cache_key('score', device_id, user_id='*'),
                self._generate_cache_key('device_profile', device_id)
            ]
            
            matching_keys = []
            for pattern in patterns:
                async for key in self.redis_client.scan_iter(match=pattern):
                    matching_keys.append(key)
            
            if matching_keys:
                await self.redis_client.delete(*matching_keys)
                self.logger.info(f"Invalidated {len(matching_keys)} cache entries for device {device_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error invalidating device cache: {e}")
            return False
    
    async def warm_cache(self, trust_scores: List[TrustScoreData]) -> bool:
        """Pre-populate cache with trust scores (cache warming)"""
        self.logger.info(f"Warming cache with {len(trust_scores)} trust scores")
        return await self.bulk_set_trust_scores(trust_scores)
    
    def get_cache_stats(self) -> CacheStats:
        """Get current cache statistics"""
        if self.stats.total_operations > 0:
            self.stats.hit_rate = self.stats.hits / self.stats.total_operations
        
        return self.stats
    
    async def flush_cache(self) -> bool:
        """Flush all cache data (use with caution)"""
        try:
            await self.redis_client.flushdb()
            self.logger.warning("Cache flushed - all data cleared")
            return True
            
        except Exception as e:
            self.logger.error(f"Error flushing cache: {e}")
            return False
    
    def __str__(self) -> str:
        return f"TrustScoreRedisCache(region={self.config.region}, connected={self._connected})"
    
    def __repr__(self) -> str:
        return self.__str__()