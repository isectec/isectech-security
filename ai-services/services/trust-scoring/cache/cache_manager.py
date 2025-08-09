"""
iSECTECH Trust Scoring Cache Manager
Production-grade cache management with warming, invalidation, and performance optimization
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Callable, Any
import time

from .redis_cache_service import TrustScoreRedisCache, CacheConfiguration, TrustScoreData
from prometheus_client import Counter, Histogram, Gauge


# Metrics
cache_warming_operations = Counter('trust_score_cache_warming_operations_total', 'Cache warming operations', ['status'])
cache_invalidation_operations = Counter('trust_score_cache_invalidation_operations_total', 'Cache invalidation operations', ['type'])
cache_eviction_operations = Counter('trust_score_cache_eviction_operations_total', 'Cache eviction operations', ['reason'])
cache_warming_duration = Histogram('trust_score_cache_warming_duration_seconds', 'Cache warming duration')
cache_size_gauge = Gauge('trust_score_cache_size_entries', 'Number of entries in cache', ['cache_type', 'region'])


@dataclass
class CacheWarmingConfig:
    """Configuration for cache warming strategies"""
    enabled: bool = True
    batch_size: int = 1000
    concurrent_requests: int = 10
    warming_interval: int = 3600  # seconds
    priority_users: List[str] = None
    priority_devices: List[str] = None
    warm_on_startup: bool = True
    max_warming_duration: int = 1800  # 30 minutes


@dataclass
class CacheEvictionConfig:
    """Configuration for cache eviction policies"""
    enabled: bool = True
    memory_threshold: float = 0.85  # 85% memory usage
    eviction_batch_size: int = 1000
    lru_eviction_enabled: bool = True
    ttl_based_eviction: bool = True
    custom_eviction_rules: Dict[str, Any] = None


class CacheManager:
    """Comprehensive cache management system for trust scoring"""
    
    def __init__(self, cache_configs: Dict[str, CacheConfiguration],
                 warming_config: Optional[CacheWarmingConfig] = None,
                 eviction_config: Optional[CacheEvictionConfig] = None):
        self.cache_instances: Dict[str, TrustScoreRedisCache] = {}
        self.warming_config = warming_config or CacheWarmingConfig()
        self.eviction_config = eviction_config or CacheEvictionConfig()
        self.logger = self._setup_logging()
        
        # Initialize cache instances for each region
        for region, config in cache_configs.items():
            self.cache_instances[region] = TrustScoreRedisCache(config)
        
        # Cache warming state
        self._warming_active = False
        self._warming_task: Optional[asyncio.Task] = None
        self._warming_stats = {
            'last_warming': None,
            'entries_warmed': 0,
            'warming_duration': 0,
            'success_rate': 0.0
        }
        
        # Eviction state
        self._eviction_active = False
        self._eviction_task: Optional[asyncio.Task] = None
        
        # Performance tracking
        self._performance_metrics = {
            'total_requests': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0,
            'average_response_time': 0.0
        }
    
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
    
    async def initialize(self) -> bool:
        """Initialize all cache instances"""
        try:
            self.logger.info("Initializing cache manager...")
            
            # Connect all cache instances
            connection_tasks = []
            for region, cache in self.cache_instances.items():
                connection_tasks.append(cache.connect())
            
            results = await asyncio.gather(*connection_tasks, return_exceptions=True)
            
            connected_regions = []
            for i, (region, result) in enumerate(zip(self.cache_instances.keys(), results)):
                if isinstance(result, Exception):
                    self.logger.error(f"Failed to connect to cache in region {region}: {result}")
                elif result:
                    connected_regions.append(region)
                    self.logger.info(f"✓ Cache connected in region: {region}")
            
            if not connected_regions:
                self.logger.error("Failed to connect to any cache instances")
                return False
            
            # Start cache warming if enabled
            if self.warming_config.enabled:
                if self.warming_config.warm_on_startup:
                    await self.warm_cache()
                
                # Start periodic warming
                self._warming_task = asyncio.create_task(self._periodic_warming())
            
            # Start cache eviction if enabled
            if self.eviction_config.enabled:
                self._eviction_task = asyncio.create_task(self._periodic_eviction())
            
            self.logger.info(f"Cache manager initialized with {len(connected_regions)} regions")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing cache manager: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown cache manager and all connections"""
        self.logger.info("Shutting down cache manager...")
        
        # Stop warming and eviction tasks
        if self._warming_task:
            self._warming_task.cancel()
        if self._eviction_task:
            self._eviction_task.cancel()
        
        # Disconnect all cache instances
        disconnect_tasks = []
        for cache in self.cache_instances.values():
            disconnect_tasks.append(cache.disconnect())
        
        await asyncio.gather(*disconnect_tasks, return_exceptions=True)
        self.logger.info("Cache manager shutdown complete")
    
    async def get_trust_score(self, device_id: str, user_id: str, 
                            preferred_region: str = None) -> Optional[TrustScoreData]:
        """Get trust score with intelligent region selection"""
        start_time = time.time()
        
        try:
            # Determine which cache to query
            cache_instance = self._select_cache_instance(preferred_region)
            if not cache_instance:
                self.logger.error("No available cache instances")
                return None
            
            # Try to get from cache
            trust_score = await cache_instance.get_trust_score(device_id, user_id)
            
            # Update performance metrics
            self._performance_metrics['total_requests'] += 1
            if trust_score:
                self._performance_metrics['cache_hits'] += 1
            else:
                self._performance_metrics['cache_misses'] += 1
            
            response_time = time.time() - start_time
            self._update_average_response_time(response_time)
            
            return trust_score
            
        except Exception as e:
            self.logger.error(f"Error getting trust score: {e}")
            self._performance_metrics['errors'] += 1
            return None
    
    async def set_trust_score(self, trust_score_data: TrustScoreData,
                            target_regions: List[str] = None) -> bool:
        """Set trust score in specified regions or all regions"""
        try:
            if target_regions:
                cache_instances = [self.cache_instances[region] for region in target_regions 
                                 if region in self.cache_instances]
            else:
                cache_instances = list(self.cache_instances.values())
            
            if not cache_instances:
                self.logger.error("No available cache instances for setting trust score")
                return False
            
            # Set trust score in all target cache instances
            set_tasks = []
            for cache in cache_instances:
                set_tasks.append(cache.set_trust_score(trust_score_data))
            
            results = await asyncio.gather(*set_tasks, return_exceptions=True)
            
            success_count = sum(1 for result in results if result is True)
            
            if success_count > 0:
                self.logger.debug(f"Trust score set in {success_count}/{len(cache_instances)} regions")
                return True
            else:
                self.logger.error("Failed to set trust score in any region")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting trust score: {e}")
            return False
    
    async def warm_cache(self, user_ids: List[str] = None, 
                        device_ids: List[str] = None) -> bool:
        """Warm cache with trust scores for specified users/devices"""
        if self._warming_active:
            self.logger.warning("Cache warming already in progress")
            return False
        
        self._warming_active = True
        start_time = time.time()
        
        try:
            with cache_warming_duration.time():
                self.logger.info("Starting cache warming...")
                
                # Get target users and devices
                target_users = user_ids or self.warming_config.priority_users or []
                target_devices = device_ids or self.warming_config.priority_devices or []
                
                if not target_users and not target_devices:
                    # Get active users from recent activity (would integrate with analytics)
                    target_users = await self._get_active_users()
                    target_devices = await self._get_active_devices()
                
                # Generate trust scores for warming
                warming_data = await self._generate_warming_data(target_users, target_devices)
                
                if not warming_data:
                    self.logger.warning("No warming data available")
                    return False
                
                # Warm caches in batches
                total_warmed = 0
                batch_size = self.warming_config.batch_size
                
                for i in range(0, len(warming_data), batch_size):
                    batch = warming_data[i:i + batch_size]
                    
                    # Warm all regions concurrently
                    warming_tasks = []
                    for cache in self.cache_instances.values():
                        warming_tasks.append(cache.bulk_set_trust_scores(batch))
                    
                    results = await asyncio.gather(*warming_tasks, return_exceptions=True)
                    
                    success_count = sum(1 for result in results if result is True)
                    if success_count > 0:
                        total_warmed += len(batch)
                    
                    self.logger.info(f"Warmed batch {i//batch_size + 1}: {len(batch)} entries")
                
                # Update warming stats
                warming_duration = time.time() - start_time
                self._warming_stats.update({
                    'last_warming': datetime.now(),
                    'entries_warmed': total_warmed,
                    'warming_duration': warming_duration,
                    'success_rate': total_warmed / len(warming_data) if warming_data else 0
                })
                
                cache_warming_operations.labels(status='success').inc()
                self.logger.info(f"Cache warming completed: {total_warmed} entries in {warming_duration:.2f}s")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error during cache warming: {e}")
            cache_warming_operations.labels(status='error').inc()
            return False
        finally:
            self._warming_active = False
    
    async def invalidate_cache(self, invalidation_type: str, 
                             identifiers: List[str],
                             target_regions: List[str] = None) -> bool:
        """Invalidate cache entries based on type and identifiers"""
        try:
            cache_instances = (
                [self.cache_instances[region] for region in target_regions if region in self.cache_instances]
                if target_regions else list(self.cache_instances.values())
            )
            
            invalidation_tasks = []
            
            for cache in cache_instances:
                for identifier in identifiers:
                    if invalidation_type == 'user':
                        task = cache.invalidate_user_scores(identifier)
                    elif invalidation_type == 'device':
                        task = cache.invalidate_device_cache(identifier)
                    else:
                        self.logger.error(f"Unknown invalidation type: {invalidation_type}")
                        continue
                    
                    invalidation_tasks.append(task)
            
            results = await asyncio.gather(*invalidation_tasks, return_exceptions=True)
            
            success_count = sum(1 for result in results if result is True)
            
            cache_invalidation_operations.labels(type=invalidation_type).inc(len(identifiers))
            
            self.logger.info(f"Invalidated {success_count}/{len(results)} cache entries")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Error during cache invalidation: {e}")
            return False
    
    async def _periodic_warming(self):
        """Periodic cache warming task"""
        while True:
            try:
                await asyncio.sleep(self.warming_config.warming_interval)
                
                if not self._warming_active:
                    await self.warm_cache()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic warming: {e}")
    
    async def _periodic_eviction(self):
        """Periodic cache eviction task"""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                if not self._eviction_active:
                    await self._check_and_evict()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic eviction: {e}")
    
    async def _check_and_evict(self):
        """Check memory usage and evict if necessary"""
        self._eviction_active = True
        
        try:
            for region, cache in self.cache_instances.items():
                stats = cache.get_cache_stats()
                
                # Check memory threshold (this would be more sophisticated in production)
                if stats.memory_usage > 0 and hasattr(stats, 'memory_limit'):
                    memory_usage_ratio = stats.memory_usage / stats.memory_limit
                    
                    if memory_usage_ratio > self.eviction_config.memory_threshold:
                        self.logger.warning(f"Memory threshold exceeded in {region}: {memory_usage_ratio:.2%}")
                        
                        # Implement eviction logic (simplified)
                        # In production, this would use Redis MEMORY USAGE commands
                        await self._evict_expired_entries(cache)
                        
                        cache_eviction_operations.labels(reason='memory_pressure').inc()
        
        except Exception as e:
            self.logger.error(f"Error in eviction check: {e}")
        finally:
            self._eviction_active = False
    
    async def _evict_expired_entries(self, cache: TrustScoreRedisCache):
        """Evict expired entries from cache"""
        try:
            # This would implement more sophisticated eviction in production
            # For now, we rely on Redis TTL-based expiration
            self.logger.info("Triggering expired key cleanup")
            
        except Exception as e:
            self.logger.error(f"Error evicting expired entries: {e}")
    
    def _select_cache_instance(self, preferred_region: str = None) -> Optional[TrustScoreRedisCache]:
        """Select the best cache instance based on region preference and health"""
        if preferred_region and preferred_region in self.cache_instances:
            return self.cache_instances[preferred_region]
        
        # Return first available instance (in production, would implement load balancing)
        for cache in self.cache_instances.values():
            if cache._connected:
                return cache
        
        return None
    
    def _update_average_response_time(self, response_time: float):
        """Update average response time metric"""
        current_avg = self._performance_metrics['average_response_time']
        total_requests = self._performance_metrics['total_requests']
        
        if total_requests > 1:
            new_avg = ((current_avg * (total_requests - 1)) + response_time) / total_requests
            self._performance_metrics['average_response_time'] = new_avg
        else:
            self._performance_metrics['average_response_time'] = response_time
    
    async def _get_active_users(self) -> List[str]:
        """Get list of active users for cache warming"""
        # In production, this would query analytics/activity data
        # For now, return placeholder data
        return []
    
    async def _get_active_devices(self) -> List[str]:
        """Get list of active devices for cache warming"""
        # In production, this would query device registry
        # For now, return placeholder data
        return []
    
    async def _generate_warming_data(self, user_ids: List[str], 
                                   device_ids: List[str]) -> List[TrustScoreData]:
        """Generate trust score data for cache warming"""
        # In production, this would call the trust scoring service
        # For now, return placeholder data
        warming_data = []
        
        for user_id in user_ids[:100]:  # Limit for example
            for device_id in device_ids[:10]:  # Limit for example
                trust_score = TrustScoreData(
                    device_id=device_id,
                    user_id=user_id,
                    score=0.75,  # Placeholder score
                    confidence=0.85,
                    factors={'warming': True},
                    timestamp=datetime.now(),
                    expires_at=datetime.now() + timedelta(minutes=5),
                    metadata={'warmed': True}
                )
                warming_data.append(trust_score)
        
        return warming_data
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        stats = {
            'performance': self._performance_metrics.copy(),
            'warming': self._warming_stats.copy(),
            'regions': {}
        }
        
        for region, cache in self.cache_instances.items():
            region_stats = cache.get_cache_stats()
            stats['regions'][region] = {
                'hits': region_stats.hits,
                'misses': region_stats.misses,
                'errors': region_stats.errors,
                'hit_rate': region_stats.hit_rate,
                'response_time': region_stats.average_response_time,
                'memory_usage': region_stats.memory_usage,
                'connections': region_stats.active_connections
            }
        
        return stats
    
    def get_warming_status(self) -> Dict[str, Any]:
        """Get cache warming status"""
        return {
            'active': self._warming_active,
            'enabled': self.warming_config.enabled,
            'last_warming': self._warming_stats['last_warming'],
            'entries_warmed': self._warming_stats['entries_warmed'],
            'duration': self._warming_stats['warming_duration'],
            'success_rate': self._warming_stats['success_rate']
        }
    
    def __str__(self) -> str:
        return f"CacheManager(regions={list(self.cache_instances.keys())}, warming={self.warming_config.enabled})"
    
    def __repr__(self) -> str:
        return self.__str__()