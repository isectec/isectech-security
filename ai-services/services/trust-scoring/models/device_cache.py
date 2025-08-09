"""
Redis-based Device Posture Caching System

This module implements high-performance Redis caching for device posture data
to support real-time trust scoring with sub-100ms response times.
"""

import asyncio
import json
import logging
import pickle
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Union, Tuple
import redis.asyncio as redis
import hashlib
from contextlib import asynccontextmanager

from .device_posture import DevicePosture, DevicePostureCollector
from .device_connectors import DeviceConnector, DeviceConnectorFactory, MDMCredentials

logger = logging.getLogger(__name__)


@dataclass
class CacheConfig:
    """Configuration for device posture caching."""
    # Redis connection settings
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    redis_password: Optional[str] = None
    redis_ssl: bool = False
    
    # Cache TTL settings (in seconds)
    device_posture_ttl: int = 3600  # 1 hour
    device_info_ttl: int = 1800     # 30 minutes
    compliance_ttl: int = 900       # 15 minutes
    apps_ttl: int = 3600           # 1 hour
    patches_ttl: int = 1800        # 30 minutes
    
    # Cache key prefixes
    key_prefix: str = "trust_score:device_posture"
    tenant_isolation: bool = True
    
    # Performance settings
    max_retries: int = 3
    retry_delay: float = 0.1
    connection_timeout: int = 5
    
    # Compression settings
    compress_data: bool = True
    compression_threshold_bytes: int = 1024


class DevicePostureCache:
    """High-performance Redis-based cache for device posture data."""
    
    def __init__(self, config: CacheConfig, tenant_id: str):
        self.config = config
        self.tenant_id = tenant_id
        self.redis_client: Optional[redis.Redis] = None
        
        # Cache statistics
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_sets": 0,
            "cache_errors": 0,
            "avg_response_time_ms": 0.0,
            "last_reset": time.time()
        }
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
    
    async def connect(self):
        """Connect to Redis."""
        try:
            self.redis_client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                ssl=self.config.redis_ssl,
                socket_timeout=self.config.connection_timeout,
                retry_on_timeout=True,
                decode_responses=False  # We handle encoding ourselves
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info(f"Connected to Redis at {self.config.redis_host}:{self.config.redis_port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from Redis."""
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Disconnected from Redis")
    
    def _build_cache_key(self, key_type: str, device_id: str, additional_keys: List[str] = None) -> str:
        """Build standardized cache key."""
        key_parts = [self.config.key_prefix]
        
        if self.config.tenant_isolation:
            key_parts.append(self.tenant_id)
        
        key_parts.extend([key_type, device_id])
        
        if additional_keys:
            key_parts.extend(additional_keys)
        
        return ":".join(key_parts)
    
    def _serialize_data(self, data: Any) -> bytes:
        """Serialize data for caching with optional compression."""
        try:
            if isinstance(data, DevicePosture):
                # Use the object's to_dict method for DevicePosture
                serialized = json.dumps(data.to_dict())
            else:
                serialized = json.dumps(data, default=str)
            
            serialized_bytes = serialized.encode('utf-8')
            
            # Apply compression if data is large enough
            if (self.config.compress_data and 
                len(serialized_bytes) > self.config.compression_threshold_bytes):
                import zlib
                compressed = zlib.compress(serialized_bytes)
                # Add compression marker
                return b'COMPRESSED:' + compressed
            
            return serialized_bytes
            
        except Exception as e:
            logger.error(f"Error serializing data: {e}")
            raise
    
    def _deserialize_data(self, data_bytes: bytes) -> Any:
        """Deserialize cached data with compression support."""
        try:
            # Check for compression marker
            if data_bytes.startswith(b'COMPRESSED:'):
                import zlib
                compressed_data = data_bytes[11:]  # Remove 'COMPRESSED:' prefix
                data_bytes = zlib.decompress(compressed_data)
            
            serialized = data_bytes.decode('utf-8')
            return json.loads(serialized)
            
        except Exception as e:
            logger.error(f"Error deserializing data: {e}")
            raise
    
    async def get_device_posture(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get cached device posture."""
        start_time = time.time()
        
        try:
            cache_key = self._build_cache_key("posture", device_id)
            cached_data = await self._get_with_retry(cache_key)
            
            if cached_data:
                self.stats["cache_hits"] += 1
                result = self._deserialize_data(cached_data)
                self._update_avg_response_time(start_time)
                return result
            
            self.stats["cache_misses"] += 1
            return None
            
        except Exception as e:
            self.stats["cache_errors"] += 1
            logger.error(f"Error getting cached device posture for {device_id}: {e}")
            return None
    
    async def set_device_posture(self, device_id: str, posture: DevicePosture, ttl: Optional[int] = None):
        """Cache device posture."""
        try:
            cache_key = self._build_cache_key("posture", device_id)
            serialized_data = self._serialize_data(posture)
            ttl = ttl or self.config.device_posture_ttl
            
            await self._set_with_retry(cache_key, serialized_data, ttl)
            self.stats["cache_sets"] += 1
            
            logger.debug(f"Cached device posture for {device_id} (TTL: {ttl}s)")
            
        except Exception as e:
            self.stats["cache_errors"] += 1
            logger.error(f"Error caching device posture for {device_id}: {e}")
    
    async def get_device_info(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get cached device info."""
        return await self._get_cached_data("info", device_id)
    
    async def set_device_info(self, device_id: str, info: Dict[str, Any], ttl: Optional[int] = None):
        """Cache device info."""
        await self._set_cached_data("info", device_id, info, ttl or self.config.device_info_ttl)
    
    async def get_device_compliance(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get cached device compliance data."""
        return await self._get_cached_data("compliance", device_id)
    
    async def set_device_compliance(self, device_id: str, compliance: Dict[str, Any], ttl: Optional[int] = None):
        """Cache device compliance data."""
        await self._set_cached_data("compliance", device_id, compliance, ttl or self.config.compliance_ttl)
    
    async def get_device_apps(self, device_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached device apps."""
        return await self._get_cached_data("apps", device_id)
    
    async def set_device_apps(self, device_id: str, apps: List[Dict[str, Any]], ttl: Optional[int] = None):
        """Cache device apps."""
        await self._set_cached_data("apps", device_id, apps, ttl or self.config.apps_ttl)
    
    async def get_device_patches(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get cached device patch data."""
        return await self._get_cached_data("patches", device_id)
    
    async def set_device_patches(self, device_id: str, patches: Dict[str, Any], ttl: Optional[int] = None):
        """Cache device patch data."""
        await self._set_cached_data("patches", device_id, patches, ttl or self.config.patches_ttl)
    
    async def _get_cached_data(self, data_type: str, device_id: str) -> Optional[Any]:
        """Generic method to get cached data."""
        start_time = time.time()
        
        try:
            cache_key = self._build_cache_key(data_type, device_id)
            cached_data = await self._get_with_retry(cache_key)
            
            if cached_data:
                self.stats["cache_hits"] += 1
                result = self._deserialize_data(cached_data)
                self._update_avg_response_time(start_time)
                return result
            
            self.stats["cache_misses"] += 1
            return None
            
        except Exception as e:
            self.stats["cache_errors"] += 1
            logger.error(f"Error getting cached {data_type} for {device_id}: {e}")
            return None
    
    async def _set_cached_data(self, data_type: str, device_id: str, data: Any, ttl: int):
        """Generic method to cache data."""
        try:
            cache_key = self._build_cache_key(data_type, device_id)
            serialized_data = self._serialize_data(data)
            
            await self._set_with_retry(cache_key, serialized_data, ttl)
            self.stats["cache_sets"] += 1
            
            logger.debug(f"Cached {data_type} for {device_id} (TTL: {ttl}s)")
            
        except Exception as e:
            self.stats["cache_errors"] += 1
            logger.error(f"Error caching {data_type} for {device_id}: {e}")
    
    async def _get_with_retry(self, key: str) -> Optional[bytes]:
        """Get from Redis with retry logic."""
        for attempt in range(self.config.max_retries):
            try:
                return await self.redis_client.get(key)
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    raise
                logger.warning(f"Redis get retry {attempt + 1}/{self.config.max_retries}: {e}")
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
        
        return None
    
    async def _set_with_retry(self, key: str, value: bytes, ttl: int):
        """Set to Redis with retry logic."""
        for attempt in range(self.config.max_retries):
            try:
                await self.redis_client.setex(key, ttl, value)
                return
            except Exception as e:
                if attempt == self.config.max_retries - 1:
                    raise
                logger.warning(f"Redis set retry {attempt + 1}/{self.config.max_retries}: {e}")
                await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
    
    async def invalidate_device_cache(self, device_id: str):
        """Invalidate all cached data for a device."""
        try:
            cache_keys = [
                self._build_cache_key("posture", device_id),
                self._build_cache_key("info", device_id),
                self._build_cache_key("compliance", device_id),
                self._build_cache_key("apps", device_id),
                self._build_cache_key("patches", device_id)
            ]
            
            await self.redis_client.delete(*cache_keys)
            logger.info(f"Invalidated cache for device {device_id}")
            
        except Exception as e:
            logger.error(f"Error invalidating cache for device {device_id}: {e}")
    
    async def get_cache_info(self, device_id: str) -> Dict[str, Any]:
        """Get cache information for a device."""
        try:
            cache_keys = {
                "posture": self._build_cache_key("posture", device_id),
                "info": self._build_cache_key("info", device_id),
                "compliance": self._build_cache_key("compliance", device_id),
                "apps": self._build_cache_key("apps", device_id),
                "patches": self._build_cache_key("patches", device_id)
            }
            
            pipeline = self.redis_client.pipeline()
            for cache_type, key in cache_keys.items():
                pipeline.ttl(key)
            
            ttl_results = await pipeline.execute()
            
            cache_info = {}
            for i, (cache_type, key) in enumerate(cache_keys.items()):
                ttl = ttl_results[i]
                cache_info[cache_type] = {
                    "cached": ttl > 0,
                    "ttl_seconds": ttl if ttl > 0 else 0,
                    "expires_at": (datetime.utcnow() + timedelta(seconds=ttl)).isoformat() if ttl > 0 else None
                }
            
            return cache_info
            
        except Exception as e:
            logger.error(f"Error getting cache info for device {device_id}: {e}")
            return {}
    
    async def warm_cache(self, device_ids: List[str], connector: DeviceConnector):
        """Pre-warm cache for multiple devices."""
        logger.info(f"Warming cache for {len(device_ids)} devices")
        
        # Process devices in batches to avoid overwhelming APIs
        batch_size = 10
        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i:i + batch_size]
            tasks = [self._warm_device_cache(device_id, connector) for device_id in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            # Small delay between batches to be API-friendly
            if i + batch_size < len(device_ids):
                await asyncio.sleep(0.5)
        
        logger.info("Cache warming completed")
    
    async def _warm_device_cache(self, device_id: str, connector: DeviceConnector):
        """Warm cache for a single device."""
        try:
            # Collect all device data
            device_info_task = connector.get_device_info(device_id)
            compliance_task = connector.get_device_compliance(device_id)
            apps_task = connector.get_device_apps(device_id)
            patches_task = connector.get_device_patches(device_id)
            
            device_info, compliance, apps, patches = await asyncio.gather(
                device_info_task, compliance_task, apps_task, patches_task,
                return_exceptions=True
            )
            
            # Cache the results
            cache_tasks = []
            if device_info and not isinstance(device_info, Exception):
                cache_tasks.append(self.set_device_info(device_id, device_info))
            if compliance and not isinstance(compliance, Exception):
                cache_tasks.append(self.set_device_compliance(device_id, compliance))
            if apps and not isinstance(apps, Exception):
                cache_tasks.append(self.set_device_apps(device_id, apps))
            if patches and not isinstance(patches, Exception):
                cache_tasks.append(self.set_device_patches(device_id, patches))
            
            if cache_tasks:
                await asyncio.gather(*cache_tasks)
                logger.debug(f"Warmed cache for device {device_id}")
            
        except Exception as e:
            logger.warning(f"Failed to warm cache for device {device_id}: {e}")
    
    def _update_avg_response_time(self, start_time: float):
        """Update average response time metric."""
        response_time_ms = (time.time() - start_time) * 1000
        
        if self.stats["cache_hits"] + self.stats["cache_misses"] == 1:
            self.stats["avg_response_time_ms"] = response_time_ms
        else:
            # Rolling average
            total_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
            current_avg = self.stats["avg_response_time_ms"]
            self.stats["avg_response_time_ms"] = (
                (current_avg * (total_requests - 1) + response_time_ms) / total_requests
            )
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        total_requests = self.stats["cache_hits"] + self.stats["cache_misses"]
        hit_rate = (self.stats["cache_hits"] / max(total_requests, 1)) * 100
        
        return {
            "cache_hits": self.stats["cache_hits"],
            "cache_misses": self.stats["cache_misses"],
            "cache_sets": self.stats["cache_sets"],
            "cache_errors": self.stats["cache_errors"],
            "hit_rate_percent": round(hit_rate, 2),
            "avg_response_time_ms": round(self.stats["avg_response_time_ms"], 2),
            "total_requests": total_requests,
            "uptime_seconds": int(time.time() - self.stats["last_reset"])
        }
    
    def reset_stats(self):
        """Reset cache statistics."""
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_sets": 0,
            "cache_errors": 0,
            "avg_response_time_ms": 0.0,
            "last_reset": time.time()
        }
        logger.info("Cache statistics reset")


class CachedDevicePostureCollector(DevicePostureCollector):
    """Device posture collector with Redis caching integration."""
    
    def __init__(self, tenant_id: str, cache: DevicePostureCache, connectors: Dict[str, DeviceConnector]):
        super().__init__(tenant_id)
        self.cache = cache
        self.connectors = connectors  # Map of platform -> connector
        
    async def collect_device_posture(self, 
                                   device_id: str, 
                                   user_id: Optional[str] = None,
                                   force_refresh: bool = False,
                                   platform: str = "intune") -> DevicePosture:
        """Collect device posture with caching."""
        
        # Check cache first (unless force refresh)
        if not force_refresh:
            cached_posture = await self.cache.get_device_posture(device_id)
            if cached_posture:
                logger.debug(f"Returning cached device posture for {device_id}")
                # Convert dict back to DevicePosture object
                return self._dict_to_device_posture(cached_posture)
        
        # Get fresh data from MDM connector
        connector = self.connectors.get(platform)
        if not connector:
            logger.warning(f"No connector available for platform {platform}, falling back to mock data")
            return await super().collect_device_posture(device_id, user_id, force_refresh)
        
        try:
            # Collect data from MDM
            device_info = await self.cache.get_device_info(device_id)
            if not device_info or force_refresh:
                device_info = await connector.get_device_info(device_id)
                if device_info:
                    await self.cache.set_device_info(device_id, device_info)
            
            compliance = await self.cache.get_device_compliance(device_id)
            if not compliance or force_refresh:
                compliance = await connector.get_device_compliance(device_id)
                if compliance:
                    await self.cache.set_device_compliance(device_id, compliance)
            
            apps = await self.cache.get_device_apps(device_id)
            if not apps or force_refresh:
                apps = await connector.get_device_apps(device_id)
                if apps:
                    await self.cache.set_device_apps(device_id, apps)
            
            patches = await self.cache.get_device_patches(device_id)
            if not patches or force_refresh:
                patches = await connector.get_device_patches(device_id)
                if patches:
                    await self.cache.set_device_patches(device_id, patches)
            
            # Transform collected data into DevicePosture
            posture = await self._build_device_posture_from_mdm_data(
                device_id, user_id, device_info, compliance, apps, patches
            )
            
            # Cache the complete posture
            await self.cache.set_device_posture(device_id, posture)
            
            logger.info(f"Collected and cached device posture for {device_id}: trust_score={posture.trust_score:.3f}")
            return posture
            
        except Exception as e:
            logger.error(f"Error collecting device posture for {device_id}: {e}")
            # Fallback to cached data if available
            cached_posture = await self.cache.get_device_posture(device_id)
            if cached_posture:
                logger.info(f"Using cached device posture for {device_id} due to collection error")
                return self._dict_to_device_posture(cached_posture)
            
            # Final fallback to mock data
            return await super().collect_device_posture(device_id, user_id, force_refresh)
    
    async def _build_device_posture_from_mdm_data(self,
                                                device_id: str,
                                                user_id: Optional[str],
                                                device_info: Optional[Dict[str, Any]],
                                                compliance: Optional[Dict[str, Any]],
                                                apps: Optional[List[Dict[str, Any]]],
                                                patches: Optional[Dict[str, Any]]) -> DevicePosture:
        """Build DevicePosture from real MDM data."""
        # Start with base posture
        posture = await super().collect_device_posture(device_id, user_id, False)
        
        # Override with real data where available
        if device_info:
            posture.device_type = self._map_device_type(device_info.get("device_type"))
            posture.operating_system = self._map_os(device_info.get("os"))
            posture.os_version = device_info.get("os_version")
            posture.os_build = device_info.get("os_build")
            posture.device_name = device_info.get("device_name")
            posture.is_managed_device = device_info.get("managed", False)
            posture.mdm_enrolled = device_info.get("mdm_enrolled", False)
        
        if compliance:
            posture.mdm_compliant = compliance.get("overall_compliance", False)
            posture.compliance_violations = compliance.get("policy_violations", [])
        
        if apps:
            posture.applications_installed = [app.get("name", "") for app in apps]
            posture.suspicious_applications = [
                app.get("name", "") for app in apps 
                if self._is_suspicious_app(app)
            ]
            posture.unsigned_applications = [
                app.get("name", "") for app in apps 
                if not app.get("signed", True)
            ]
        
        if patches:
            if patches.get("last_patch_date"):
                posture.last_patch_date = datetime.fromisoformat(
                    patches["last_patch_date"].replace('Z', '+00:00')
                )
            posture.patches_pending = patches.get("patches_pending", 0)
            posture.critical_patches_pending = patches.get("critical_patches_pending", 0)
            posture.automatic_updates_enabled = patches.get("auto_updates_enabled", False)
        
        # Recalculate scores with real data
        posture.overall_risk_score = self._calculate_risk_score(posture)
        posture.trust_score = 1.0 - posture.overall_risk_score
        
        return posture
    
    def _dict_to_device_posture(self, posture_dict: Dict[str, Any]) -> DevicePosture:
        """Convert dictionary back to DevicePosture object."""
        # This is a simplified conversion - in production you'd want full object reconstruction
        from .device_posture import DevicePosture, DeviceType, OperatingSystem
        
        posture = DevicePosture(
            device_id=posture_dict["device_id"],
            tenant_id=posture_dict["tenant_id"],
            user_id=posture_dict.get("user_id")
        )
        
        # Set basic fields
        posture.device_type = DeviceType(posture_dict.get("device_type", "unknown"))
        posture.operating_system = OperatingSystem(posture_dict.get("operating_system", "unknown"))
        posture.trust_score = posture_dict.get("trust_score", 0.5)
        posture.overall_risk_score = posture_dict.get("overall_risk_score", 0.5)
        
        return posture
    
    def _is_suspicious_app(self, app: Dict[str, Any]) -> bool:
        """Check if an application is suspicious."""
        suspicious_indicators = [
            "keygen", "crack", "hack", "bypass", "torrent", 
            "backdoor", "trojan", "malware", "virus"
        ]
        
        app_name = app.get("name", "").lower()
        return any(indicator in app_name for indicator in suspicious_indicators)


# Export main classes
__all__ = [
    "CacheConfig",
    "DevicePostureCache", 
    "CachedDevicePostureCollector"
]