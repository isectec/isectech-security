"""
Trust Scoring Service

This module provides the main service layer for trust scoring that integrates
user behavior analysis, device posture assessment, network context analysis,
and authentication factors into a comprehensive trust scoring system.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
import json
import redis
import uuid

from ..models.trust_calculator import (
    TrustScoreCalculator, 
    TrustScoreResult,
    TrustFactorScore,
    TrustLevel
)
from ..models.trust_parameters import TrustScoreConfiguration
from ..models.behavior_collector import BehaviorDataCollector, UserBehaviorProfile
from ..models.device_posture import DevicePostureCollector, DevicePosture
from ..models.device_integration_service import DeviceIntegrationService
from ..models.network_integration_service import NetworkIntegrationService
from ...behavioral-analysis.models.feature_engineering import BehavioralFeatures

logger = logging.getLogger(__name__)


@dataclass
class TrustScoreRequest:
    """Request for trust score calculation."""
    entity_id: str
    entity_type: str = "user"  # user, device, session
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    tenant_id: str = ""
    
    # Force refresh flags
    force_behavior_refresh: bool = False
    force_device_refresh: bool = False
    include_trends: bool = False
    
    # Context data
    current_ip: Optional[str] = None
    authentication_context: Optional[Dict[str, Any]] = None
    network_context: Optional[Dict[str, Any]] = None


@dataclass
class TrustScoreResponse:
    """Response containing trust score and metadata."""
    request_id: str
    trust_score_result: TrustScoreResult
    processing_time_ms: int
    cache_hit: bool = False
    data_freshness: Dict[str, datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary."""
        return {
            "request_id": self.request_id,
            "processing_time_ms": self.processing_time_ms,
            "cache_hit": self.cache_hit,
            "data_freshness": {
                k: v.isoformat() if v else None 
                for k, v in (self.data_freshness or {}).items()
            },
            "trust_score": self.trust_score_result.to_dict()
        }


class TrustScoringService:
    """Main trust scoring service that orchestrates all trust factors."""
    
    def __init__(self, 
                 config: TrustScoreConfiguration,
                 redis_client: Optional[redis.Redis] = None,
                 tenant_id: str = "default",
                 device_integration_service: Optional[DeviceIntegrationService] = None,
                 network_integration_service: Optional[NetworkIntegrationService] = None):
        self.config = config
        self.tenant_id = tenant_id
        self.redis_client = redis_client
        
        # Initialize calculator and collectors
        self.trust_calculator = TrustScoreCalculator(config)
        self.behavior_collector = BehaviorDataCollector(
            tenant_id=tenant_id,
            buffer_size=10000
        )
        
        # Use enhanced device integration service if available, fallback to basic collector
        if device_integration_service:
            self.device_integration_service = device_integration_service
            self.device_posture_collector = None  # Use integration service instead
        else:
            self.device_integration_service = None
            self.device_posture_collector = DevicePostureCollector(tenant_id)
        
        # Use enhanced network integration service if available
        self.network_integration_service = network_integration_service
        
        # Cache configuration
        self.cache_ttl_seconds = 300  # 5 minutes default
        self.cache_prefix = f"trust_score:{tenant_id}:"
        
        # Performance monitoring
        self.metrics = {
            "requests_processed": 0,
            "cache_hits": 0,
            "avg_processing_time_ms": 0.0,
            "error_count": 0
        }
        
    async def calculate_trust_score(self, request: TrustScoreRequest) -> TrustScoreResponse:
        """Calculate comprehensive trust score for an entity."""
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        logger.info(f"Processing trust score request {request_id} for entity {request.entity_id}")
        
        try:
            # Check cache first
            cached_result = await self._get_cached_result(request)
            if cached_result and not self._should_force_refresh(request):
                processing_time = int((time.time() - start_time) * 1000)
                self.metrics["cache_hits"] += 1
                logger.debug(f"Returning cached trust score for {request.entity_id}")
                
                return TrustScoreResponse(
                    request_id=request_id,
                    trust_score_result=cached_result,
                    processing_time_ms=processing_time,
                    cache_hit=True
                )
            
            # Collect data from various sources
            data_freshness = {}
            
            # Collect behavioral features
            behavioral_features = None
            if request.user_id:
                user_profile = await self._collect_user_behavior(
                    request.user_id, 
                    force_refresh=request.force_behavior_refresh
                )
                if user_profile:
                    behavioral_features = self._convert_to_behavioral_features(user_profile)
                    data_freshness["user_behavior"] = user_profile.last_updated
            
            # Collect device posture
            device_data = None
            if request.device_id:
                device_posture = await self._collect_device_posture(
                    request.device_id,
                    request.user_id,
                    force_refresh=request.force_device_refresh
                )
                if device_posture:
                    device_data = self._convert_device_posture_to_dict(device_posture)
                    data_freshness["device_posture"] = device_posture.assessment_timestamp
            
            # Collect network context
            network_data = await self._collect_network_context(
                request.current_ip,
                request.network_context
            )
            if network_data:
                data_freshness["network_context"] = datetime.utcnow()
            
            # Collect authentication context  
            auth_data = await self._collect_authentication_context(
                request.user_id,
                request.authentication_context
            )
            if auth_data:
                data_freshness["authentication"] = datetime.utcnow()
            
            # Get previous score for trend analysis
            previous_score = await self._get_previous_score(request.entity_id)
            
            # Calculate trust score
            result = self.trust_calculator.calculate_trust_score(
                entity_id=request.entity_id,
                entity_type=request.entity_type,
                behavioral_features=behavioral_features,
                device_data=device_data,
                network_data=network_data,
                auth_data=auth_data,
                previous_score=previous_score
            )
            
            # Cache the result
            await self._cache_result(request, result)
            
            # Update metrics
            processing_time = int((time.time() - start_time) * 1000)
            self.metrics["requests_processed"] += 1
            self._update_avg_processing_time(processing_time)
            
            logger.info(f"Trust score calculated for {request.entity_id}: {result.trust_score:.3f} "
                       f"(level: {result.trust_level.value}, confidence: {result.confidence:.3f})")
            
            return TrustScoreResponse(
                request_id=request_id,
                trust_score_result=result,
                processing_time_ms=processing_time,
                cache_hit=False,
                data_freshness=data_freshness
            )
            
        except Exception as e:
            self.metrics["error_count"] += 1
            logger.error(f"Error calculating trust score for request {request_id}: {e}")
            
            # Return minimal trust score on error
            error_result = TrustScoreResult(
                entity_id=request.entity_id,
                entity_type=request.entity_type,
                trust_score=0.0,
                trust_level=TrustLevel.UNTRUSTED,
                confidence=0.0,
                anomaly_indicators=["calculation_error"]
            )
            
            processing_time = int((time.time() - start_time) * 1000)
            return TrustScoreResponse(
                request_id=request_id,
                trust_score_result=error_result,
                processing_time_ms=processing_time,
                cache_hit=False
            )
    
    async def _collect_user_behavior(self, 
                                   user_id: str, 
                                   force_refresh: bool = False) -> Optional[UserBehaviorProfile]:
        """Collect user behavior data for trust scoring."""
        try:
            # Check if we have recent cached behavior data
            if not force_refresh:
                cached_profile = await self._get_cached_behavior_profile(user_id)
                if cached_profile:
                    return cached_profile
            
            # Generate fresh behavior profile
            profile = await self.behavior_collector.generate_user_profile(user_id)
            if profile:
                await self._cache_behavior_profile(user_id, profile)
                logger.debug(f"Collected fresh behavior data for user {user_id}")
            
            return profile
            
        except Exception as e:
            logger.error(f"Error collecting user behavior for {user_id}: {e}")
            return None
    
    async def _collect_device_posture(self, 
                                    device_id: str,
                                    user_id: Optional[str] = None,
                                    force_refresh: bool = False) -> Optional[DevicePosture]:
        """Collect device security posture for trust scoring."""
        try:
            # Use enhanced device integration service if available
            if self.device_integration_service:
                posture = await self.device_integration_service.assess_device_posture(
                    device_id=device_id,
                    user_id=user_id,
                    force_refresh=force_refresh
                )
            else:
                # Fallback to basic collector
                posture = await self.device_posture_collector.collect_device_posture(
                    device_id=device_id,
                    user_id=user_id,
                    force_refresh=force_refresh
                )
            
            logger.debug(f"Collected device posture for {device_id}: trust_score={posture.trust_score:.3f}")
            return posture
            
        except Exception as e:
            logger.error(f"Error collecting device posture for {device_id}: {e}")
            return None
    
    async def _collect_network_context(self, 
                                     ip_address: Optional[str],
                                     network_context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Collect network context data for trust scoring."""
        if not ip_address and not network_context:
            return None
        
        try:
            if ip_address and self.network_integration_service:
                # Use enhanced network integration service
                network_ctx = await self.network_integration_service.analyze_network_context(
                    ip_address=ip_address,
                    additional_context=network_context
                )
                
                # Convert NetworkContext to dictionary format expected by trust calculator
                return {
                    "ip_address": ip_address,
                    "ip_reputation_score": network_ctx.threat_intel.reputation_score,
                    "geolocation_consistent": network_ctx.location_consistency > 0.7,
                    "is_corporate_network": network_ctx.network_type.value == "corporate",
                    "vpn_detected": network_ctx.is_vpn,
                    "tor_exit_node": network_ctx.is_tor,
                    "network_trust_score": network_ctx.calculate_network_trust_score(),
                    "risk_level": network_ctx.risk_level.value,
                    "country": network_ctx.geolocation.country,
                    "country_code": network_ctx.geolocation.country_code,
                    "isp": network_ctx.geolocation.isp,
                    "threat_types": [t.value for t in network_ctx.threat_intel.threat_types],
                    "malicious": network_ctx.threat_intel.is_malicious,
                    "travel_feasible": network_ctx.travel_feasibility > 0.7
                }
            else:
                # Fallback to basic network context collection
                context_data = network_context.copy() if network_context else {}
                
                if ip_address:
                    # Add IP-based context (mock implementation)
                    context_data.update({
                        "ip_address": ip_address,
                        "ip_reputation_score": await self._get_ip_reputation(ip_address),
                        "geolocation_consistent": await self._check_geolocation_consistency(ip_address),
                        "is_corporate_network": await self._is_corporate_network(ip_address),
                        "vpn_detected": await self._detect_vpn_usage(ip_address),
                        "tor_exit_node": await self._is_tor_exit_node(ip_address)
                    })
                
                return context_data
            
        except Exception as e:
            logger.error(f"Error collecting network context: {e}")
            return None
    
    async def _collect_authentication_context(self, 
                                            user_id: Optional[str],
                                            auth_context: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Collect authentication context for trust scoring."""
        if not auth_context:
            return None
        
        try:
            context_data = auth_context.copy()
            
            if user_id:
                # Enhance with authentication history and patterns
                context_data.update({
                    "recent_auth_success": await self._get_recent_auth_success(user_id),
                    "password_age_days": await self._get_password_age(user_id),
                    "brute_force_detected": await self._check_brute_force_activity(user_id),
                    "credential_strength_score": await self._assess_credential_strength(user_id)
                })
            
            return context_data
            
        except Exception as e:
            logger.error(f"Error collecting authentication context: {e}")
            return None
    
    def _convert_to_behavioral_features(self, profile: UserBehaviorProfile) -> BehavioralFeatures:
        """Convert UserBehaviorProfile to BehavioralFeatures format."""
        return BehavioralFeatures(
            user_id=profile.user_id,
            features=profile.get_features_dict(),
            timestamp=profile.last_updated
        )
    
    def _convert_device_posture_to_dict(self, posture: DevicePosture) -> Dict[str, Any]:
        """Convert DevicePosture to dictionary for calculator."""
        posture_dict = posture.to_dict()
        
        # Map to calculator expected format
        return {
            "os_patch_level": (datetime.utcnow() - posture.last_patch_date).days 
                            if posture.last_patch_date else 365,
            "antivirus_status": any(c.name.lower() == "antivirus" and c.status.value == "enabled" 
                                 for c in posture.security_controls),
            "firewall_enabled": any(c.name.lower() == "firewall" and c.status.value == "enabled" 
                                  for c in posture.security_controls),
            "encryption_status": any(c.name.lower() == "encryption" and c.status.value == "enabled" 
                                   for c in posture.security_controls),
            "device_registered": posture.is_managed_device or posture.mdm_enrolled,
            "compliance_score": posture.calculate_posture_score(),
            "jailbroken": False,  # Would be detected in device assessment
            "rooted": False,
            "tpm_present": posture.hardware_info.has_tpm,
            "secure_boot_enabled": True,  # Would be detected in device assessment
            "biometric_available": posture.hardware_info.has_biometric_auth,
            "certificate_valid": True,  # Would be verified in device assessment
            "code_signing_verified": len(posture.unsigned_applications) == 0,
            "suspicious_processes_count": len(posture.malware_types)
        }
    
    def _should_force_refresh(self, request: TrustScoreRequest) -> bool:
        """Determine if cache should be bypassed."""
        return (request.force_behavior_refresh or 
                request.force_device_refresh or
                request.include_trends)
    
    async def _get_cached_result(self, request: TrustScoreRequest) -> Optional[TrustScoreResult]:
        """Get cached trust score result."""
        if not self.redis_client:
            return None
        
        try:
            cache_key = f"{self.cache_prefix}result:{request.entity_id}"
            cached_data = self.redis_client.get(cache_key)
            
            if cached_data:
                result_dict = json.loads(cached_data)
                # Reconstruct TrustScoreResult from cached data
                return self._deserialize_trust_result(result_dict)
            
        except Exception as e:
            logger.warning(f"Error retrieving cached result: {e}")
        
        return None
    
    async def _cache_result(self, request: TrustScoreRequest, result: TrustScoreResult):
        """Cache trust score result."""
        if not self.redis_client:
            return
        
        try:
            cache_key = f"{self.cache_prefix}result:{request.entity_id}"
            cached_data = json.dumps(result.to_dict())
            self.redis_client.setex(cache_key, self.cache_ttl_seconds, cached_data)
            
            # Also cache previous score for trend analysis
            score_key = f"{self.cache_prefix}score:{request.entity_id}"
            self.redis_client.setex(score_key, 86400, str(result.trust_score))  # 24 hours
            
        except Exception as e:
            logger.warning(f"Error caching result: {e}")
    
    async def _get_previous_score(self, entity_id: str) -> Optional[float]:
        """Get previous trust score for trend analysis."""
        if not self.redis_client:
            return None
        
        try:
            score_key = f"{self.cache_prefix}score:{entity_id}"
            cached_score = self.redis_client.get(score_key)
            return float(cached_score) if cached_score else None
        except Exception as e:
            logger.debug(f"No previous score found for {entity_id}: {e}")
            return None
    
    async def _get_cached_behavior_profile(self, user_id: str) -> Optional[UserBehaviorProfile]:
        """Get cached user behavior profile."""
        if not self.redis_client:
            return None
        
        try:
            cache_key = f"{self.cache_prefix}behavior:{user_id}"
            cached_data = self.redis_client.get(cache_key)
            
            if cached_data:
                profile_dict = json.loads(cached_data)
                # Reconstruct UserBehaviorProfile from cached data
                return UserBehaviorProfile.from_dict(profile_dict)
                
        except Exception as e:
            logger.debug(f"Error retrieving cached behavior profile: {e}")
        
        return None
    
    async def _cache_behavior_profile(self, user_id: str, profile: UserBehaviorProfile):
        """Cache user behavior profile."""
        if not self.redis_client:
            return
        
        try:
            cache_key = f"{self.cache_prefix}behavior:{user_id}"
            cached_data = json.dumps(profile.to_dict())
            self.redis_client.setex(cache_key, 3600, cached_data)  # 1 hour TTL
            
        except Exception as e:
            logger.warning(f"Error caching behavior profile: {e}")
    
    def _deserialize_trust_result(self, result_dict: Dict[str, Any]) -> TrustScoreResult:
        """Reconstruct TrustScoreResult from dictionary."""
        # This is a simplified deserialization - in production you'd want full reconstruction
        return TrustScoreResult(
            entity_id=result_dict["entity_id"],
            entity_type=result_dict["entity_type"],
            trust_score=result_dict["trust_score"],
            trust_level=TrustLevel(result_dict["trust_level"]),
            confidence=result_dict["confidence"],
            calculation_id=result_dict["calculation_id"],
            timestamp=datetime.fromisoformat(result_dict["timestamp"]),
            data_sources=result_dict.get("data_sources", []),
            anomaly_indicators=result_dict.get("anomaly_indicators", [])
        )
    
    def _update_avg_processing_time(self, processing_time_ms: int):
        """Update average processing time metric."""
        current_avg = self.metrics["avg_processing_time_ms"]
        total_requests = self.metrics["requests_processed"]
        
        if total_requests == 1:
            self.metrics["avg_processing_time_ms"] = processing_time_ms
        else:
            # Rolling average
            self.metrics["avg_processing_time_ms"] = (
                (current_avg * (total_requests - 1) + processing_time_ms) / total_requests
            )
    
    # Placeholder methods for external service integrations
    async def _get_ip_reputation(self, ip_address: str) -> float:
        """Get IP reputation score from threat intelligence feeds."""
        # Implement integration with threat intelligence APIs
        return 0.8  # Mock score
    
    async def _check_geolocation_consistency(self, ip_address: str) -> bool:
        """Check if IP geolocation is consistent with user's typical locations."""
        # Implement geolocation consistency checking
        return True  # Mock result
    
    async def _is_corporate_network(self, ip_address: str) -> bool:
        """Check if IP is from corporate network ranges."""
        # Implement corporate network range checking
        return False  # Mock result
    
    async def _detect_vpn_usage(self, ip_address: str) -> bool:
        """Detect if IP is from a VPN service."""
        # Implement VPN detection logic
        return False  # Mock result
    
    async def _is_tor_exit_node(self, ip_address: str) -> bool:
        """Check if IP is a Tor exit node."""
        # Implement Tor exit node detection
        return False  # Mock result
    
    async def _get_recent_auth_success(self, user_id: str) -> bool:
        """Check if user had recent successful authentication."""
        # Implement authentication history check
        return True  # Mock result
    
    async def _get_password_age(self, user_id: str) -> int:
        """Get password age in days."""
        # Implement password age lookup
        return 45  # Mock age
    
    async def _check_brute_force_activity(self, user_id: str) -> bool:
        """Check for recent brute force activity."""
        # Implement brute force detection
        return False  # Mock result
    
    async def _assess_credential_strength(self, user_id: str) -> float:
        """Assess credential strength score."""
        # Implement credential strength assessment
        return 0.8  # Mock score
    
    def get_service_metrics(self) -> Dict[str, Any]:
        """Get service performance metrics."""
        cache_hit_rate = (
            self.metrics["cache_hits"] / max(self.metrics["requests_processed"], 1) * 100
        )
        
        return {
            "requests_processed": self.metrics["requests_processed"],
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "avg_processing_time_ms": round(self.metrics["avg_processing_time_ms"], 2),
            "error_count": self.metrics["error_count"],
            "uptime_seconds": int(time.time() - getattr(self, '_start_time', time.time()))
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform service health check."""
        health_status = {
            "service": "trust_scoring",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {}
        }
        
        # Check Redis connectivity
        if self.redis_client:
            try:
                self.redis_client.ping()
                health_status["checks"]["redis"] = "healthy"
            except Exception as e:
                health_status["checks"]["redis"] = f"unhealthy: {e}"
                health_status["status"] = "degraded"
        
        # Check data collectors
        try:
            # Test behavior collector
            test_profile = await self.behavior_collector.generate_user_profile("health_check")
            health_status["checks"]["behavior_collector"] = "healthy" if test_profile else "degraded"
        except Exception as e:
            health_status["checks"]["behavior_collector"] = f"unhealthy: {e}"
            health_status["status"] = "degraded"
        
        try:
            # Test device posture collection
            if self.device_integration_service:
                # Test the enhanced device integration service
                service_status = await self.device_integration_service.get_service_status()
                overall_healthy = (
                    service_status["service_status"]["initialized"] and
                    service_status["service_status"]["cache_healthy"]
                )
                health_status["checks"]["device_posture"] = "healthy" if overall_healthy else "degraded"
                health_status["checks"]["device_integration_details"] = service_status
            else:
                # Test basic device posture collector
                test_posture = await self.device_posture_collector.collect_device_posture("health_check")
                health_status["checks"]["device_posture"] = "healthy" if test_posture else "degraded"
        except Exception as e:
            health_status["checks"]["device_posture"] = f"unhealthy: {e}"
            health_status["status"] = "degraded"
        
        return health_status


# Export main service class
__all__ = ["TrustScoringService", "TrustScoreRequest", "TrustScoreResponse"]