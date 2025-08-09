"""
Network Integration Service

This module provides a unified service layer that integrates network context analysis
with real threat intelligence feeds, geolocation services, and network classification
for comprehensive network-based trust scoring.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import os

from .network_context import NetworkContext, NetworkContextAnalyzer
from .threat_intelligence import (
    ThreatIntelligenceAggregator,
    create_threat_intelligence_system
)
from .geolocation_services import (
    GeolocationService,
    create_geolocation_service
)

logger = logging.getLogger(__name__)


@dataclass
class NetworkIntegrationConfig:
    """Configuration for network integration service."""
    tenant_id: str
    
    # Service enablement flags
    enable_threat_intelligence: bool = True
    enable_geolocation: bool = True
    enable_user_tracking: bool = True
    
    # Analysis settings
    cache_ttl_hours: int = 6
    max_cached_contexts: int = 10000
    concurrent_analysis_limit: int = 100
    
    # Corporate network ranges (CIDR notation)
    corporate_ip_ranges: List[str] = None
    
    # Risk assessment settings
    high_risk_countries: List[str] = None
    blocked_asns: List[int] = None
    
    def __post_init__(self):
        if self.corporate_ip_ranges is None:
            self.corporate_ip_ranges = [
                "10.0.0.0/8",
                "172.16.0.0/12", 
                "192.168.0.0/16"
            ]
        
        if self.high_risk_countries is None:
            # Example high-risk countries for demonstration
            self.high_risk_countries = []
        
        if self.blocked_asns is None:
            self.blocked_asns = []


class NetworkIntegrationService:
    """Unified service for comprehensive network context analysis."""
    
    def __init__(self, config: NetworkIntegrationConfig):
        self.config = config
        
        # Initialize external services
        self.threat_intel_service: Optional[ThreatIntelligenceAggregator] = None
        self.geolocation_service: Optional[GeolocationService] = None
        self.network_analyzer: Optional[NetworkContextAnalyzer] = None
        
        # Service status
        self.service_status = {
            "initialized": False,
            "threat_intel_healthy": False,
            "geolocation_healthy": False,
            "last_health_check": None
        }
        
        # Performance metrics
        self.metrics = {
            "contexts_analyzed": 0,
            "threat_intel_queries": 0,
            "geolocation_queries": 0,
            "high_risk_detections": 0,
            "blocked_ips": 0,
            "errors": 0,
            "avg_analysis_time_ms": 0.0
        }
    
    async def initialize(self):
        """Initialize all network analysis services."""
        logger.info(f"Initializing Network Integration Service for tenant {self.config.tenant_id}")
        
        try:
            # Initialize threat intelligence service
            if self.config.enable_threat_intelligence:
                await self._initialize_threat_intelligence()
            
            # Initialize geolocation service  
            if self.config.enable_geolocation:
                await self._initialize_geolocation()
            
            # Initialize network context analyzer
            self.network_analyzer = NetworkContextAnalyzer(
                tenant_id=self.config.tenant_id,
                threat_intel_service=self.threat_intel_service,
                geolocation_service=self.geolocation_service
            )
            
            # Configure corporate IP ranges
            if self.config.corporate_ip_ranges:
                self.network_analyzer.corporate_ranges = self.config.corporate_ip_ranges
            
            # Perform health check
            await self._health_check()
            
            self.service_status["initialized"] = True
            logger.info("Network Integration Service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Network Integration Service: {e}")
            raise
    
    async def analyze_network_context(self,
                                    ip_address: str,
                                    user_id: Optional[str] = None,
                                    session_id: Optional[str] = None,
                                    additional_context: Optional[Dict[str, Any]] = None) -> NetworkContext:
        """Analyze complete network context for trust scoring."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            if not self.network_analyzer:
                raise RuntimeError("Network Integration Service not initialized")
            
            # Perform comprehensive network analysis
            context = await self.network_analyzer.analyze_network_context(
                ip_address=ip_address,
                user_id=user_id,
                session_id=session_id,
                additional_context=additional_context
            )
            
            # Apply tenant-specific risk assessment rules
            await self._apply_tenant_risk_rules(context)
            
            # Update metrics
            self.metrics["contexts_analyzed"] += 1
            analysis_time = (asyncio.get_event_loop().time() - start_time) * 1000
            self._update_avg_analysis_time(analysis_time)
            
            logger.info(f"Network context analyzed for {ip_address}: "
                       f"risk_level={context.risk_level.value}, "
                       f"trust_score={context.calculate_network_trust_score():.3f}, "
                       f"time={analysis_time:.1f}ms")
            
            return context
            
        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Error analyzing network context for {ip_address}: {e}")
            raise
    
    async def analyze_multiple_ips(self, 
                                 ip_addresses: List[str],
                                 user_contexts: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, NetworkContext]:
        """Analyze multiple IP addresses concurrently."""
        user_contexts = user_contexts or {}
        results = {}
        
        # Process IPs in batches to avoid overwhelming external APIs
        batch_size = min(self.config.concurrent_analysis_limit, len(ip_addresses))
        
        for i in range(0, len(ip_addresses), batch_size):
            batch = ip_addresses[i:i + batch_size]
            
            # Create analysis tasks for this batch
            tasks = []
            for ip in batch:
                user_context = user_contexts.get(ip, {})
                task = self.analyze_network_context(
                    ip_address=ip,
                    user_id=user_context.get("user_id"),
                    session_id=user_context.get("session_id"),
                    additional_context=user_context.get("additional_context")
                )
                tasks.append(task)
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for ip, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to analyze IP {ip}: {result}")
                    # Create minimal high-risk context for failed analysis
                    results[ip] = NetworkContext(
                        ip_address=ip,
                        tenant_id=self.config.tenant_id,
                        risk_score=0.9,
                        risk_factors=["analysis_failed"]
                    )
                else:
                    results[ip] = result
            
            # Small delay between batches to be API-friendly
            if i + batch_size < len(ip_addresses):
                await asyncio.sleep(0.5)
        
        logger.info(f"Completed network analysis of {len(ip_addresses)} IPs")
        return results
    
    async def check_ip_blocklist(self, ip_address: str) -> bool:
        """Check if IP should be blocked based on reputation and policies."""
        try:
            context = await self.analyze_network_context(ip_address)
            
            # Check various blocking criteria
            should_block = (
                # Critical risk level
                context.risk_level.value == "critical" or
                
                # High threat intelligence confidence
                (context.threat_intel.is_malicious and context.threat_intel.confidence > 0.8) or
                
                # High-risk countries (if configured)
                (self.config.high_risk_countries and 
                 context.geolocation.country_code in self.config.high_risk_countries) or
                
                # Blocked ASNs (if configured)
                (self.config.blocked_asns and 
                 context.geolocation.as_number in self.config.blocked_asns) or
                
                # Tor exit nodes
                context.is_tor
            )
            
            if should_block:
                self.metrics["blocked_ips"] += 1
                logger.warning(f"IP {ip_address} blocked: risk_level={context.risk_level.value}")
            
            return should_block
            
        except Exception as e:
            logger.error(f"Error checking blocklist for {ip_address}: {e}")
            # Default to blocking on error for security
            return True
    
    async def get_network_risk_summary(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Get risk summary for multiple IP addresses."""
        contexts = await self.analyze_multiple_ips(ip_addresses)
        
        risk_summary = {
            "total_ips": len(ip_addresses),
            "risk_distribution": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0
            },
            "threat_types": {},
            "countries": {},
            "network_types": {},
            "malicious_ips": [],
            "high_risk_ips": [],
            "tor_ips": []
        }
        
        for ip, context in contexts.items():
            # Risk level distribution
            risk_summary["risk_distribution"][context.risk_level.value] += 1
            
            # Threat types
            for threat_type in context.threat_intel.threat_types:
                risk_summary["threat_types"][threat_type.value] = (
                    risk_summary["threat_types"].get(threat_type.value, 0) + 1
                )
            
            # Countries
            if context.geolocation.country:
                risk_summary["countries"][context.geolocation.country] = (
                    risk_summary["countries"].get(context.geolocation.country, 0) + 1
                )
            
            # Network types
            risk_summary["network_types"][context.network_type.value] = (
                risk_summary["network_types"].get(context.network_type.value, 0) + 1
            )
            
            # Special categories
            if context.threat_intel.is_malicious:
                risk_summary["malicious_ips"].append(ip)
            
            if context.risk_level.value in ["high", "critical"]:
                risk_summary["high_risk_ips"].append(ip)
            
            if context.is_tor:
                risk_summary["tor_ips"].append(ip)
        
        return risk_summary
    
    async def _initialize_threat_intelligence(self):
        """Initialize threat intelligence service."""
        try:
            self.threat_intel_service = create_threat_intelligence_system()
            if self.threat_intel_service.providers:
                self.service_status["threat_intel_healthy"] = True
                logger.info(f"Initialized threat intelligence with {len(self.threat_intel_service.providers)} providers")
            else:
                logger.warning("No threat intelligence providers available")
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence: {e}")
            self.service_status["threat_intel_healthy"] = False
    
    async def _initialize_geolocation(self):
        """Initialize geolocation service."""
        try:
            self.geolocation_service = create_geolocation_service()
            if self.geolocation_service.providers:
                self.service_status["geolocation_healthy"] = True
                logger.info(f"Initialized geolocation with {len(self.geolocation_service.providers)} providers")
            else:
                logger.warning("No geolocation providers available")
        except Exception as e:
            logger.error(f"Failed to initialize geolocation service: {e}")
            self.service_status["geolocation_healthy"] = False
    
    async def _apply_tenant_risk_rules(self, context: NetworkContext):
        """Apply tenant-specific risk assessment rules."""
        # High-risk country check
        if (self.config.high_risk_countries and 
            context.geolocation.country_code in self.config.high_risk_countries):
            context.risk_score += 0.3
            context.risk_factors.append(f"high_risk_country_{context.geolocation.country_code}")
        
        # Blocked ASN check
        if (self.config.blocked_asns and 
            context.geolocation.as_number in self.config.blocked_asns):
            context.risk_score = 0.9
            context.risk_factors.append(f"blocked_asn_{context.geolocation.as_number}")
        
        # Update high-risk detections metric
        if context.risk_score >= 0.8:
            self.metrics["high_risk_detections"] += 1
    
    async def _health_check(self):
        """Perform health check on all services."""
        self.service_status["last_health_check"] = datetime.utcnow()
        
        # Test threat intelligence service
        if self.threat_intel_service:
            try:
                # Quick test with a known clean IP
                test_result = await self.threat_intel_service.get_ip_reputation("8.8.8.8")
                self.service_status["threat_intel_healthy"] = test_result is not None
            except Exception as e:
                logger.warning(f"Threat intelligence health check failed: {e}")
                self.service_status["threat_intel_healthy"] = False
        
        # Test geolocation service
        if self.geolocation_service:
            try:
                # Quick test with a known IP
                test_result = await self.geolocation_service.get_ip_location("8.8.8.8")
                self.service_status["geolocation_healthy"] = test_result is not None
            except Exception as e:
                logger.warning(f"Geolocation health check failed: {e}")
                self.service_status["geolocation_healthy"] = False
    
    def _update_avg_analysis_time(self, analysis_time_ms: float):
        """Update average analysis time metric."""
        current_avg = self.metrics["avg_analysis_time_ms"]
        total_analyses = self.metrics["contexts_analyzed"]
        
        if total_analyses == 1:
            self.metrics["avg_analysis_time_ms"] = analysis_time_ms
        else:
            # Rolling average
            self.metrics["avg_analysis_time_ms"] = (
                (current_avg * (total_analyses - 1) + analysis_time_ms) / total_analyses
            )
    
    def get_service_metrics(self) -> Dict[str, Any]:
        """Get comprehensive service metrics."""
        # Combine metrics from all services
        service_metrics = self.metrics.copy()
        
        if self.threat_intel_service:
            threat_metrics = self.threat_intel_service.get_metrics()
            service_metrics["threat_intelligence"] = threat_metrics
        
        if self.geolocation_service:
            geo_metrics = self.geolocation_service.get_metrics()
            service_metrics["geolocation"] = geo_metrics
        
        if self.network_analyzer:
            analyzer_metrics = self.network_analyzer.get_metrics()
            service_metrics["network_analysis"] = analyzer_metrics
        
        return service_metrics
    
    async def get_service_status(self) -> Dict[str, Any]:
        """Get comprehensive service status."""
        # Perform health check
        await self._health_check()
        
        return {
            "service_status": self.service_status,
            "config": {
                "threat_intelligence_enabled": self.config.enable_threat_intelligence,
                "geolocation_enabled": self.config.enable_geolocation,
                "user_tracking_enabled": self.config.enable_user_tracking,
                "corporate_ip_ranges_count": len(self.config.corporate_ip_ranges),
                "high_risk_countries_count": len(self.config.high_risk_countries),
                "blocked_asns_count": len(self.config.blocked_asns)
            },
            "performance_metrics": self.get_service_metrics()
        }


class NetworkIntegrationServiceFactory:
    """Factory for creating network integration services."""
    
    @staticmethod
    def create_production_service(tenant_id: str, 
                                corporate_ip_ranges: List[str] = None,
                                high_risk_countries: List[str] = None) -> NetworkIntegrationService:
        """Create production-ready network integration service."""
        
        config = NetworkIntegrationConfig(
            tenant_id=tenant_id,
            enable_threat_intelligence=True,
            enable_geolocation=True,
            enable_user_tracking=True,
            cache_ttl_hours=6,
            max_cached_contexts=10000,
            concurrent_analysis_limit=50,
            corporate_ip_ranges=corporate_ip_ranges,
            high_risk_countries=high_risk_countries
        )
        
        return NetworkIntegrationService(config)
    
    @staticmethod 
    def create_development_service(tenant_id: str = "dev") -> NetworkIntegrationService:
        """Create development service with minimal configuration."""
        
        config = NetworkIntegrationConfig(
            tenant_id=tenant_id,
            enable_threat_intelligence=False,  # Use mock data in dev
            enable_geolocation=False,         # Use mock data in dev
            enable_user_tracking=True,
            cache_ttl_hours=1,               # Shorter cache for dev
            max_cached_contexts=1000,        # Lower limits for dev
            concurrent_analysis_limit=10
        )
        
        return NetworkIntegrationService(config)


# Export main classes
__all__ = [
    "NetworkIntegrationConfig",
    "NetworkIntegrationService",
    "NetworkIntegrationServiceFactory"
]