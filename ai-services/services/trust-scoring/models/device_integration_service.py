"""
Device Integration Service

This module provides a unified service layer that integrates device posture assessment
with real MDM connectors and Redis caching for high-performance trust scoring.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import json

from .device_posture import DevicePosture, DevicePostureCollector
from .device_connectors import (
    DeviceConnector, 
    DeviceConnectorFactory, 
    MDMCredentials,
    MicrosoftIntuneConnector,
    VMwareWorkspaceOneConnector,
    JAMFConnector
)
from .device_cache import DevicePostureCache, CacheConfig, CachedDevicePostureCollector

logger = logging.getLogger(__name__)


@dataclass
class MDMConfiguration:
    """Configuration for MDM platform integration."""
    platform: str
    enabled: bool = True
    credentials: Optional[MDMCredentials] = None
    priority: int = 1  # 1 = primary, 2 = secondary, etc.
    device_filters: List[str] = None  # Device types this MDM handles


@dataclass
class DeviceIntegrationConfig:
    """Complete configuration for device integration service."""
    tenant_id: str
    
    # MDM configurations
    mdm_configs: List[MDMConfiguration]
    
    # Cache configuration
    cache_config: CacheConfig
    
    # Performance settings
    concurrent_device_limit: int = 50
    api_timeout_seconds: int = 30
    retry_attempts: int = 3
    
    # Health check settings
    health_check_interval_minutes: int = 15
    health_check_device_sample_size: int = 10


class DeviceIntegrationService:
    """Unified service for device posture assessment with MDM integration and caching."""
    
    def __init__(self, config: DeviceIntegrationConfig):
        self.config = config
        self.cache: Optional[DevicePostureCache] = None
        self.connectors: Dict[str, DeviceConnector] = {}
        self.posture_collector: Optional[CachedDevicePostureCollector] = None
        
        # Service status tracking
        self.service_status = {
            "initialized": False,
            "cache_healthy": False,
            "connectors_healthy": {},
            "last_health_check": None
        }
        
        # Performance metrics
        self.metrics = {
            "devices_assessed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "mdm_api_calls": 0,
            "errors": 0,
            "avg_assessment_time_ms": 0.0
        }
    
    async def initialize(self):
        """Initialize all service components."""
        logger.info(f"Initializing Device Integration Service for tenant {self.config.tenant_id}")
        
        try:
            # Initialize cache
            await self._initialize_cache()
            
            # Initialize MDM connectors
            await self._initialize_connectors()
            
            # Initialize posture collector
            self._initialize_posture_collector()
            
            # Perform initial health check
            await self._health_check()
            
            self.service_status["initialized"] = True
            logger.info("Device Integration Service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Device Integration Service: {e}")
            raise
    
    async def shutdown(self):
        """Shutdown service and cleanup resources."""
        logger.info("Shutting down Device Integration Service")
        
        try:
            # Close connectors
            for platform, connector in self.connectors.items():
                try:
                    if hasattr(connector, '__aexit__'):
                        await connector.__aexit__(None, None, None)
                except Exception as e:
                    logger.warning(f"Error closing connector {platform}: {e}")
            
            # Close cache
            if self.cache:
                await self.cache.disconnect()
            
            logger.info("Device Integration Service shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during service shutdown: {e}")
    
    async def assess_device_posture(self, 
                                  device_id: str, 
                                  user_id: Optional[str] = None,
                                  force_refresh: bool = False,
                                  preferred_platform: Optional[str] = None) -> DevicePosture:
        """Assess device security posture using available MDM platforms."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Determine best MDM platform for this device
            platform = await self._select_mdm_platform(device_id, preferred_platform)
            
            # Perform assessment using cached collector
            if self.posture_collector:
                posture = await self.posture_collector.collect_device_posture(
                    device_id=device_id,
                    user_id=user_id,
                    force_refresh=force_refresh,
                    platform=platform
                )
            else:
                # Fallback to direct collection
                collector = DevicePostureCollector(self.config.tenant_id)
                posture = await collector.collect_device_posture(
                    device_id=device_id,
                    user_id=user_id,
                    force_refresh=force_refresh
                )
            
            # Update metrics
            self.metrics["devices_assessed"] += 1
            assessment_time = (asyncio.get_event_loop().time() - start_time) * 1000
            self._update_avg_assessment_time(assessment_time)
            
            logger.info(f"Device posture assessed for {device_id}: "
                       f"trust_score={posture.trust_score:.3f}, "
                       f"platform={platform}, "
                       f"time={assessment_time:.1f}ms")
            
            return posture
            
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Error assessing device posture for {device_id}: {e}")
            raise
    
    async def assess_multiple_devices(self, 
                                    device_ids: List[str],
                                    user_ids: Optional[Dict[str, str]] = None,
                                    force_refresh: bool = False) -> Dict[str, DevicePosture]:
        """Assess multiple devices concurrently with rate limiting."""
        user_ids = user_ids or {}
        results = {}
        
        # Process devices in batches to avoid overwhelming APIs
        batch_size = min(self.config.concurrent_device_limit, len(device_ids))
        
        for i in range(0, len(device_ids), batch_size):
            batch = device_ids[i:i + batch_size]
            
            # Create assessment tasks for this batch
            tasks = [
                self.assess_device_posture(
                    device_id=device_id,
                    user_id=user_ids.get(device_id),
                    force_refresh=force_refresh
                )
                for device_id in batch
            ]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for device_id, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to assess device {device_id}: {result}")
                    # Create minimal posture for failed assessments
                    results[device_id] = DevicePosture(
                        device_id=device_id,
                        tenant_id=self.config.tenant_id,
                        trust_score=0.0,
                        overall_risk_score=1.0,
                        risk_factors=["assessment_failed"]
                    )
                else:
                    results[device_id] = result
            
            # Small delay between batches to be API-friendly
            if i + batch_size < len(device_ids):
                await asyncio.sleep(0.5)
        
        logger.info(f"Completed assessment of {len(device_ids)} devices, "
                   f"{len([r for r in results.values() if r.trust_score > 0])} successful")
        
        return results
    
    async def warm_cache_for_devices(self, device_ids: List[str]):
        """Pre-warm cache for specified devices."""
        if not self.cache:
            logger.warning("Cache not available for warming")
            return
        
        logger.info(f"Warming cache for {len(device_ids)} devices")
        
        # Group devices by preferred MDM platform
        platform_groups = await self._group_devices_by_platform(device_ids)
        
        for platform, devices in platform_groups.items():
            connector = self.connectors.get(platform)
            if connector:
                await self.cache.warm_cache(devices, connector)
            else:
                logger.warning(f"No connector available for platform {platform}")
    
    async def invalidate_device_cache(self, device_id: str):
        """Invalidate cached data for a specific device."""
        if self.cache:
            await self.cache.invalidate_device_cache(device_id)
            logger.info(f"Invalidated cache for device {device_id}")
    
    async def get_device_cache_info(self, device_id: str) -> Dict[str, Any]:
        """Get cache information for a device."""
        if self.cache:
            return await self.cache.get_cache_info(device_id)
        return {}
    
    async def get_service_status(self) -> Dict[str, Any]:
        """Get comprehensive service status."""
        # Perform health check
        await self._health_check()
        
        # Gather cache stats
        cache_stats = {}
        if self.cache:
            cache_stats = self.cache.get_cache_stats()
        
        return {
            "service_status": self.service_status,
            "cache_stats": cache_stats,
            "performance_metrics": self.metrics,
            "mdm_platforms": {
                platform: {
                    "enabled": config.enabled,
                    "healthy": self.service_status["connectors_healthy"].get(platform, False)
                }
                for config in self.config.mdm_configs
                for platform in [config.platform]
            }
        }
    
    async def _initialize_cache(self):
        """Initialize Redis cache."""
        try:
            self.cache = DevicePostureCache(self.config.cache_config, self.config.tenant_id)
            await self.cache.connect()
            self.service_status["cache_healthy"] = True
            logger.info("Redis cache initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize cache: {e}")
            self.service_status["cache_healthy"] = False
            raise
    
    async def _initialize_connectors(self):
        """Initialize MDM connectors."""
        for mdm_config in self.config.mdm_configs:
            if not mdm_config.enabled or not mdm_config.credentials:
                continue
            
            try:
                connector = DeviceConnectorFactory.create_connector(mdm_config.credentials)
                
                # Test connection
                async with connector:
                    await connector.authenticate()
                    # Store the configured connector
                    self.connectors[mdm_config.platform] = connector
                    self.service_status["connectors_healthy"][mdm_config.platform] = True
                    logger.info(f"Initialized {mdm_config.platform} connector successfully")
                
            except Exception as e:
                logger.error(f"Failed to initialize {mdm_config.platform} connector: {e}")
                self.service_status["connectors_healthy"][mdm_config.platform] = False
        
        if not self.connectors:
            logger.warning("No MDM connectors available - using mock data only")
    
    def _initialize_posture_collector(self):
        """Initialize cached device posture collector."""
        if self.cache and self.connectors:
            self.posture_collector = CachedDevicePostureCollector(
                tenant_id=self.config.tenant_id,
                cache=self.cache,
                connectors=self.connectors
            )
            logger.info("Initialized cached device posture collector")
        else:
            logger.warning("Cannot initialize cached collector - missing cache or connectors")
    
    async def _select_mdm_platform(self, device_id: str, preferred_platform: Optional[str] = None) -> str:
        """Select best MDM platform for device assessment."""
        # Use preferred platform if available and healthy
        if preferred_platform and preferred_platform in self.connectors:
            if self.service_status["connectors_healthy"].get(preferred_platform):
                return preferred_platform
        
        # Select primary platform based on priority
        available_platforms = [
            (config.platform, config.priority)
            for config in self.config.mdm_configs
            if (config.enabled and 
                config.platform in self.connectors and
                self.service_status["connectors_healthy"].get(config.platform, False))
        ]
        
        if available_platforms:
            # Sort by priority (lower number = higher priority)
            available_platforms.sort(key=lambda x: x[1])
            return available_platforms[0][0]
        
        # Fallback to first available connector
        for platform in self.connectors:
            if self.service_status["connectors_healthy"].get(platform):
                return platform
        
        # No healthy connectors available
        return "mock"  # Will use mock data
    
    async def _group_devices_by_platform(self, device_ids: List[str]) -> Dict[str, List[str]]:
        """Group devices by their preferred MDM platform."""
        # For now, use simple round-robin assignment
        # In production, you might determine platform based on device type, user, etc.
        
        healthy_platforms = [
            platform for platform in self.connectors
            if self.service_status["connectors_healthy"].get(platform)
        ]
        
        if not healthy_platforms:
            return {"mock": device_ids}
        
        groups = {platform: [] for platform in healthy_platforms}
        
        for i, device_id in enumerate(device_ids):
            platform = healthy_platforms[i % len(healthy_platforms)]
            groups[platform].append(device_id)
        
        return groups
    
    async def _health_check(self):
        """Perform health check on all service components."""
        self.service_status["last_health_check"] = datetime.utcnow()
        
        # Check cache health
        if self.cache:
            try:
                # Test cache with a simple operation
                test_key = f"health_check:{int(asyncio.get_event_loop().time())}"
                await self.cache._set_with_retry(test_key.encode(), b"test", 10)
                self.service_status["cache_healthy"] = True
            except Exception as e:
                logger.warning(f"Cache health check failed: {e}")
                self.service_status["cache_healthy"] = False
        
        # Check connector health
        for platform, connector in self.connectors.items():
            try:
                # Test with a simple device info query
                await connector.get_device_info("health_check")
                self.service_status["connectors_healthy"][platform] = True
            except Exception as e:
                logger.warning(f"Connector {platform} health check failed: {e}")
                self.service_status["connectors_healthy"][platform] = False
    
    def _update_avg_assessment_time(self, assessment_time_ms: float):
        """Update average assessment time metric."""
        current_avg = self.metrics["avg_assessment_time_ms"]
        total_assessments = self.metrics["devices_assessed"]
        
        if total_assessments == 1:
            self.metrics["avg_assessment_time_ms"] = assessment_time_ms
        else:
            # Rolling average
            self.metrics["avg_assessment_time_ms"] = (
                (current_avg * (total_assessments - 1) + assessment_time_ms) / total_assessments
            )


class DeviceIntegrationServiceFactory:
    """Factory for creating device integration services with common configurations."""
    
    @staticmethod
    def create_production_service(tenant_id: str, 
                                mdm_credentials: Dict[str, MDMCredentials],
                                redis_config: Dict[str, Any]) -> DeviceIntegrationService:
        """Create a production-ready device integration service."""
        
        # Build MDM configurations
        mdm_configs = []
        priority = 1
        
        for platform, credentials in mdm_credentials.items():
            mdm_configs.append(MDMConfiguration(
                platform=platform,
                enabled=True,
                credentials=credentials,
                priority=priority
            ))
            priority += 1
        
        # Build cache configuration
        cache_config = CacheConfig(
            redis_host=redis_config.get("host", "localhost"),
            redis_port=redis_config.get("port", 6379),
            redis_db=redis_config.get("db", 0),
            redis_password=redis_config.get("password"),
            redis_ssl=redis_config.get("ssl", False),
            device_posture_ttl=3600,  # 1 hour
            compress_data=True
        )
        
        # Build service configuration
        service_config = DeviceIntegrationConfig(
            tenant_id=tenant_id,
            mdm_configs=mdm_configs,
            cache_config=cache_config,
            concurrent_device_limit=50,
            api_timeout_seconds=30
        )
        
        return DeviceIntegrationService(service_config)
    
    @staticmethod
    def create_development_service(tenant_id: str = "dev") -> DeviceIntegrationService:
        """Create a development service with mock data only."""
        
        cache_config = CacheConfig(
            redis_host="localhost",
            redis_port=6379,
            redis_db=1,  # Use different DB for dev
            device_posture_ttl=300  # 5 minutes for dev
        )
        
        service_config = DeviceIntegrationConfig(
            tenant_id=tenant_id,
            mdm_configs=[],  # No real MDM connectors in dev
            cache_config=cache_config,
            concurrent_device_limit=10
        )
        
        return DeviceIntegrationService(service_config)


# Export main classes
__all__ = [
    "MDMConfiguration",
    "DeviceIntegrationConfig", 
    "DeviceIntegrationService",
    "DeviceIntegrationServiceFactory"
]