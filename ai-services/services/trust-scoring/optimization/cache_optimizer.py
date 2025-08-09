"""
Trust Score Cache Optimization System

Intelligent caching and precomputation strategies for trust scoring
with multi-layer cache architecture and predictive prefetching.
"""

import asyncio
import logging
import time
import json
import hashlib
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union, Set, Tuple
from enum import Enum
from collections import defaultdict, OrderedDict
import redis
import pickle
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from ..models.trust_calculator import TrustScoreResult
from ..models.trust_parameters import TrustLevel, TrustFactorType
from ...shared.config.settings import Settings

logger = logging.getLogger(__name__)


class CacheStrategy(Enum):
    """Cache eviction strategies."""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    TTL = "ttl"  # Time To Live
    ADAPTIVE = "adaptive"  # Adaptive based on access patterns


class CacheLayer(Enum):
    """Cache layer types."""
    MEMORY = "memory"
    REDIS = "redis"
    PERSISTENT = "persistent"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 0
    last_access: datetime = field(default_factory=datetime.utcnow)
    ttl_seconds: int = 300
    size_bytes: int = 0
    hit_count: int = 0
    miss_penalty: float = 0.0  # Cost of cache miss
    
    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.timestamp + timedelta(seconds=self.ttl_seconds)
    
    @property
    def age_seconds(self) -> float:
        return (datetime.utcnow() - self.timestamp).total_seconds()
    
    def touch(self):
        """Update access metadata."""
        self.access_count += 1
        self.last_access = datetime.utcnow()
        self.hit_count += 1


class MemoryCache:
    """High-performance in-memory cache with intelligent eviction."""
    
    def __init__(
        self,
        max_size: int = 10000,
        max_memory_mb: int = 256,
        strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    ):
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.strategy = strategy
        
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.access_pattern: Dict[str, List[float]] = defaultdict(list)
        self.size_bytes = 0
        
        # Performance metrics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key not in self.cache:
            self.misses += 1
            return None
        
        entry = self.cache[key]
        
        if entry.is_expired:
            del self.cache[key]
            self.size_bytes -= entry.size_bytes
            self.misses += 1
            return None
        
        # Update access pattern
        entry.touch()
        self.access_pattern[key].append(time.time())
        
        # Move to end for LRU
        if self.strategy == CacheStrategy.LRU:
            self.cache.move_to_end(key)
        
        self.hits += 1
        return entry.value
    
    def set(self, key: str, value: Any, ttl_seconds: int = 300):
        """Set value in cache."""
        # Estimate size
        try:
            size_bytes = len(pickle.dumps(value))
        except:
            size_bytes = 1024  # Default estimate
        
        # Check if we need to evict
        while (len(self.cache) >= self.max_size or 
               self.size_bytes + size_bytes > self.max_memory_bytes):
            if not self._evict_one():
                break
        
        # Create cache entry
        entry = CacheEntry(
            key=key,
            value=value,
            ttl_seconds=ttl_seconds,
            size_bytes=size_bytes
        )
        
        # Remove old entry if exists
        if key in self.cache:
            old_entry = self.cache[key]
            self.size_bytes -= old_entry.size_bytes
        
        # Add new entry
        self.cache[key] = entry
        self.size_bytes += size_bytes
        self.access_pattern[key].append(time.time())
        
        # Move to end for LRU
        if self.strategy == CacheStrategy.LRU:
            self.cache.move_to_end(key)
    
    def _evict_one(self) -> bool:
        """Evict one entry based on strategy."""
        if not self.cache:
            return False
        
        if self.strategy == CacheStrategy.LRU:
            key = next(iter(self.cache))
        elif self.strategy == CacheStrategy.LFU:
            key = min(self.cache.keys(), key=lambda k: self.cache[k].access_count)
        elif self.strategy == CacheStrategy.TTL:
            # Find most expired
            key = min(self.cache.keys(), key=lambda k: self.cache[k].timestamp)
        else:  # ADAPTIVE
            key = self._adaptive_eviction()
        
        entry = self.cache.pop(key)
        self.size_bytes -= entry.size_bytes
        self.evictions += 1
        
        # Clean up access pattern
        if key in self.access_pattern:
            del self.access_pattern[key]
        
        return True
    
    def _adaptive_eviction(self) -> str:
        """Adaptive eviction based on access patterns and value."""
        scores = {}
        current_time = time.time()
        
        for key, entry in self.cache.items():
            # Calculate score based on multiple factors
            recency_score = 1.0 / max(1.0, current_time - entry.last_access.timestamp())
            frequency_score = entry.access_count / max(1.0, entry.age_seconds)
            size_penalty = entry.size_bytes / (1024 * 1024)  # MB
            
            # Access pattern analysis
            pattern_score = 1.0
            if key in self.access_pattern and len(self.access_pattern[key]) > 3:
                access_times = self.access_pattern[key][-10:]  # Last 10 accesses
                intervals = [access_times[i] - access_times[i-1] for i in range(1, len(access_times))]
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    pattern_score = 1.0 / max(0.1, avg_interval)  # Higher for frequent access
            
            # Combine scores (higher is more valuable, less likely to evict)
            composite_score = (recency_score * 0.3 + 
                             frequency_score * 0.4 + 
                             pattern_score * 0.2 - 
                             size_penalty * 0.1)
            scores[key] = composite_score
        
        # Return key with lowest score
        return min(scores.keys(), key=lambda k: scores[k])
    
    def clear(self):
        """Clear all cache entries."""
        self.cache.clear()
        self.access_pattern.clear()
        self.size_bytes = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / max(total_requests, 1)
        
        return {
            'size': len(self.cache),
            'max_size': self.max_size,
            'memory_usage_mb': self.size_bytes / 1024 / 1024,
            'max_memory_mb': self.max_memory_bytes / 1024 / 1024,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'evictions': self.evictions,
            'strategy': self.strategy.value
        }


class RedisCache:
    """Redis-based distributed cache for trust scores."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", db: int = 0):
        self.redis_client = redis.from_url(redis_url, db=db, decode_responses=False)
        self.prefix = "trust_score:"
        
        # Performance metrics
        self.hits = 0
        self.misses = 0
        
    async def get(self, key: str) -> Optional[Any]:
        """Get value from Redis cache."""
        try:
            full_key = f"{self.prefix}{key}"
            data = self.redis_client.get(full_key)
            
            if data is None:
                self.misses += 1
                return None
            
            value = pickle.loads(data)
            self.hits += 1
            return value
            
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            self.misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl_seconds: int = 300):
        """Set value in Redis cache."""
        try:
            full_key = f"{self.prefix}{key}"
            data = pickle.dumps(value)
            self.redis_client.setex(full_key, ttl_seconds, data)
        except Exception as e:
            logger.error(f"Redis set error: {e}")
    
    async def delete(self, key: str):
        """Delete value from Redis cache."""
        try:
            full_key = f"{self.prefix}{key}"
            self.redis_client.delete(full_key)
        except Exception as e:
            logger.error(f"Redis delete error: {e}")
    
    async def clear_pattern(self, pattern: str):
        """Clear keys matching pattern."""
        try:
            full_pattern = f"{self.prefix}{pattern}"
            keys = self.redis_client.keys(full_pattern)
            if keys:
                self.redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Redis clear pattern error: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Redis cache statistics."""
        try:
            info = self.redis_client.info('memory')
            total_requests = self.hits + self.misses
            hit_rate = self.hits / max(total_requests, 1)
            
            return {
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'redis_memory_mb': info.get('used_memory', 0) / 1024 / 1024,
                'redis_peak_memory_mb': info.get('used_memory_peak', 0) / 1024 / 1024,
                'connected': self.redis_client.ping()
            }
        except Exception as e:
            logger.error(f"Redis stats error: {e}")
            return {'connected': False, 'error': str(e)}


class TrustScoreCache:
    """
    Multi-layer intelligent caching system for trust scores with
    predictive prefetching and adaptive cache management.
    """
    
    def __init__(
        self,
        memory_cache_size: int = 10000,
        memory_cache_mb: int = 256,
        redis_url: Optional[str] = None,
        enable_prefetch: bool = True,
        cache_strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    ):
        # Cache layers
        self.memory_cache = MemoryCache(
            max_size=memory_cache_size,
            max_memory_mb=memory_cache_mb,
            strategy=cache_strategy
        )
        
        self.redis_cache: Optional[RedisCache] = None
        if redis_url:
            self.redis_cache = RedisCache(redis_url)
        
        # Prefetch settings
        self.enable_prefetch = enable_prefetch
        self.prefetch_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="prefetch")
        
        # Access pattern learning
        self.access_patterns: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self.entity_clusters: Optional[Dict[str, int]] = None
        self.cluster_cache_priorities: Dict[int, float] = {}
        
        # Performance metrics
        self.total_requests = 0
        self.cache_hits = 0
        self.prefetch_hits = 0
        
        logger.info("TrustScoreCache initialized")
    
    def _generate_cache_key(
        self,
        entity_id: str,
        entity_type: str,
        context_hash: Optional[str] = None
    ) -> str:
        """Generate cache key for trust score."""
        base_key = f"{entity_type}:{entity_id}"
        if context_hash:
            base_key += f":{context_hash}"
        return base_key
    
    def _hash_context(self, context_data: Dict[str, Any]) -> str:
        """Generate hash for context data."""
        # Sort keys for consistent hashing
        sorted_context = json.dumps(context_data, sort_keys=True, default=str)
        return hashlib.sha256(sorted_context.encode()).hexdigest()[:16]
    
    async def get(
        self,
        entity_id: str,
        entity_type: str,
        context_data: Optional[Dict[str, Any]] = None
    ) -> Optional[TrustScoreResult]:
        """Get trust score from cache."""
        self.total_requests += 1
        
        # Generate cache key
        context_hash = self._hash_context(context_data) if context_data else None
        cache_key = self._generate_cache_key(entity_id, entity_type, context_hash)
        
        # Record access pattern
        self.access_patterns[entity_id].append((time.time(), entity_type))
        
        # Try memory cache first
        result = self.memory_cache.get(cache_key)
        if result is not None:
            self.cache_hits += 1
            self._trigger_related_prefetch(entity_id, entity_type)
            return result
        
        # Try Redis cache
        if self.redis_cache:
            result = await self.redis_cache.get(cache_key)
            if result is not None:
                # Populate memory cache
                self.memory_cache.set(cache_key, result)
                self.cache_hits += 1
                self._trigger_related_prefetch(entity_id, entity_type)
                return result
        
        return None
    
    async def set(
        self,
        entity_id: str,
        entity_type: str,
        trust_score_result: TrustScoreResult,
        context_data: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 300
    ):
        """Set trust score in cache."""
        context_hash = self._hash_context(context_data) if context_data else None
        cache_key = self._generate_cache_key(entity_id, entity_type, context_hash)
        
        # Set in memory cache
        self.memory_cache.set(cache_key, trust_score_result, ttl_seconds)
        
        # Set in Redis cache
        if self.redis_cache:
            await self.redis_cache.set(cache_key, trust_score_result, ttl_seconds)
        
        # Update learning patterns
        await self._update_access_patterns(entity_id, entity_type)
    
    async def invalidate(
        self,
        entity_id: str,
        entity_type: Optional[str] = None
    ):
        """Invalidate cache entries for an entity."""
        if entity_type:
            # Specific entity type
            pattern = f"{entity_type}:{entity_id}:*"
        else:
            # All entity types
            pattern = f"*:{entity_id}:*"
        
        # Clear from Redis
        if self.redis_cache:
            await self.redis_cache.clear_pattern(pattern)
        
        # Clear from memory cache (need to iterate)
        keys_to_remove = [
            key for key in self.memory_cache.cache.keys()
            if entity_id in key
        ]
        
        for key in keys_to_remove:
            if key in self.memory_cache.cache:
                entry = self.memory_cache.cache.pop(key)
                self.memory_cache.size_bytes -= entry.size_bytes
    
    async def warmup(
        self,
        entity_predictions: List[Tuple[str, str, Dict[str, Any]]],
        batch_calculator: Callable
    ):
        """Warm up cache with predicted entities."""
        logger.info(f"Warming up cache with {len(entity_predictions)} predictions")
        
        # Filter out already cached entities
        cache_misses = []
        for entity_id, entity_type, context_data in entity_predictions:
            result = await self.get(entity_id, entity_type, context_data)
            if result is None:
                cache_misses.append((entity_id, entity_type, context_data))
        
        if not cache_misses:
            return
        
        logger.info(f"Computing {len(cache_misses)} missing trust scores")
        
        # Calculate missing trust scores
        results = await batch_calculator(cache_misses)
        
        # Cache results
        for (entity_id, entity_type, context_data), result in zip(cache_misses, results):
            if result.success:
                await self.set(
                    entity_id,
                    entity_type,
                    result.trust_score_result,
                    context_data,
                    ttl_seconds=600  # Longer TTL for warmed data
                )
    
    def _trigger_related_prefetch(self, entity_id: str, entity_type: str):
        """Trigger prefetch for related entities."""
        if not self.enable_prefetch:
            return
        
        # Submit prefetch task asynchronously
        self.prefetch_executor.submit(
            self._prefetch_related_entities,
            entity_id,
            entity_type
        )
    
    def _prefetch_related_entities(self, entity_id: str, entity_type: str):
        """Prefetch related entities based on access patterns."""
        try:
            # Find entities that are often accessed together
            related_entities = self._find_related_entities(entity_id, entity_type)
            
            for related_entity_id, related_entity_type in related_entities[:5]:  # Top 5
                cache_key = self._generate_cache_key(related_entity_id, related_entity_type)
                
                # Check if already cached
                if self.memory_cache.get(cache_key) is not None:
                    continue
                
                # This would trigger calculation and caching
                # In a real implementation, this would call the trust calculator
                logger.debug(f"Prefetching {related_entity_type}:{related_entity_id}")
                
        except Exception as e:
            logger.error(f"Prefetch error: {e}")
    
    def _find_related_entities(self, entity_id: str, entity_type: str) -> List[Tuple[str, str]]:
        """Find entities that are frequently accessed together."""
        if entity_id not in self.access_patterns:
            return []
        
        # Get recent access history
        recent_accesses = self.access_patterns[entity_id][-50:]  # Last 50 accesses
        access_times = [access[0] for access in recent_accesses]
        
        # Find entities accessed within time windows
        related_entities: Dict[Tuple[str, str], int] = defaultdict(int)
        time_window = 300  # 5 minutes
        
        for entity_id_2, pattern_history in self.access_patterns.items():
            if entity_id_2 == entity_id:
                continue
            
            for access_time_1 in access_times:
                for access_time_2, entity_type_2 in pattern_history:
                    if abs(access_time_1 - access_time_2) <= time_window:
                        related_entities[(entity_id_2, entity_type_2)] += 1
        
        # Sort by frequency and return top candidates
        sorted_related = sorted(
            related_entities.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [entity_info for entity_info, count in sorted_related]
    
    async def _update_access_patterns(self, entity_id: str, entity_type: str):
        """Update machine learning models for access pattern prediction."""
        # This could be enhanced with more sophisticated ML models
        # For now, just maintain the access history
        pass
    
    async def optimize_cache_distribution(self):
        """Optimize cache distribution across layers."""
        # Analyze access patterns and move frequently accessed items to memory
        memory_stats = self.memory_cache.get_stats()
        
        if memory_stats['hit_rate'] < 0.8 and self.redis_cache:
            # Move more items to memory cache
            logger.info("Optimizing cache distribution - promoting items to memory")
            
            # This is a simplified version - real implementation would be more sophisticated
            await self._promote_hot_items_to_memory()
    
    async def _promote_hot_items_to_memory(self):
        """Promote frequently accessed items from Redis to memory."""
        # In a real implementation, this would analyze Redis access patterns
        # and promote the most frequently accessed items to memory cache
        pass
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        memory_stats = self.memory_cache.get_stats()
        
        stats = {
            'total_requests': self.total_requests,
            'cache_hits': self.cache_hits,
            'prefetch_hits': self.prefetch_hits,
            'overall_hit_rate': self.cache_hits / max(self.total_requests, 1),
            'memory_cache': memory_stats,
            'prefetch_enabled': self.enable_prefetch,
            'access_patterns_tracked': len(self.access_patterns)
        }
        
        if self.redis_cache:
            stats['redis_cache'] = self.redis_cache.get_stats()
        
        return stats
    
    async def cleanup(self):
        """Cleanup resources."""
        self.prefetch_executor.shutdown(wait=True)
        
        # Clear old access patterns
        current_time = time.time()
        cutoff_time = current_time - 86400  # 24 hours
        
        for entity_id in list(self.access_patterns.keys()):
            self.access_patterns[entity_id] = [
                (access_time, entity_type)
                for access_time, entity_type in self.access_patterns[entity_id]
                if access_time > cutoff_time
            ]
            
            if not self.access_patterns[entity_id]:
                del self.access_patterns[entity_id]


class PrecomputationEngine:
    """
    Predictive precomputation engine for trust scores based on
    usage patterns and entity relationships.
    """
    
    def __init__(
        self,
        cache: TrustScoreCache,
        batch_calculator: Callable,
        precompute_interval_minutes: int = 30
    ):
        self.cache = cache
        self.batch_calculator = batch_calculator
        self.precompute_interval = precompute_interval_minutes * 60
        
        self.entity_importance_scores: Dict[str, float] = {}
        self.prediction_model: Optional[Any] = None
        
        self.precompute_task: Optional[asyncio.Task] = None
        self.active = False
        
    async def start(self):
        """Start the precomputation engine."""
        if self.active:
            return
        
        self.active = True
        self.precompute_task = asyncio.create_task(self._precomputation_loop())
        logger.info("PrecomputationEngine started")
    
    async def stop(self):
        """Stop the precomputation engine."""
        self.active = False
        if self.precompute_task:
            self.precompute_task.cancel()
            try:
                await self.precompute_task
            except asyncio.CancelledError:
                pass
        logger.info("PrecomputationEngine stopped")
    
    async def _precomputation_loop(self):
        """Main precomputation loop."""
        while self.active:
            try:
                await self._run_precomputation_cycle()
                await asyncio.sleep(self.precompute_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Precomputation cycle error: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _run_precomputation_cycle(self):
        """Run a single precomputation cycle."""
        logger.info("Starting precomputation cycle")
        
        # 1. Analyze access patterns
        important_entities = self._identify_important_entities()
        
        # 2. Predict likely access patterns
        predicted_entities = self._predict_future_accesses(important_entities)
        
        # 3. Precompute trust scores
        if predicted_entities:
            await self.cache.warmup(predicted_entities, self.batch_calculator)
        
        logger.info(f"Precomputation cycle completed: {len(predicted_entities)} entities processed")
    
    def _identify_important_entities(self) -> List[Tuple[str, str]]:
        """Identify important entities based on access patterns."""
        entity_scores: Dict[Tuple[str, str], float] = defaultdict(float)
        current_time = time.time()
        
        # Analyze recent access patterns
        for entity_id, accesses in self.cache.access_patterns.items():
            recent_accesses = [
                (access_time, entity_type)
                for access_time, entity_type in accesses
                if current_time - access_time < 3600  # Last hour
            ]
            
            for access_time, entity_type in recent_accesses:
                # Score based on recency and frequency
                recency_score = 1.0 / max(1.0, (current_time - access_time) / 60)  # Minutes
                entity_key = (entity_id, entity_type)
                entity_scores[entity_key] += recency_score
        
        # Return top entities
        sorted_entities = sorted(
            entity_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [entity_key for entity_key, score in sorted_entities[:100]]
    
    def _predict_future_accesses(
        self,
        important_entities: List[Tuple[str, str]]
    ) -> List[Tuple[str, str, Dict[str, Any]]]:
        """Predict future access patterns."""
        predictions = []
        
        # Simple prediction based on historical patterns
        for entity_id, entity_type in important_entities:
            # Default context for precomputation
            default_context = {
                'precomputed': True,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            predictions.append((entity_id, entity_type, default_context))
        
        return predictions


# Export for external use
__all__ = [
    'TrustScoreCache',
    'CacheStrategy',
    'PrecomputationEngine',
    'MemoryCache',
    'RedisCache'
]