"""
Real Threat Intelligence API Integrations

This module provides production-ready integrations with major threat intelligence
providers for IP reputation checking, malware detection, and network risk assessment.
"""

import asyncio
import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
import aiohttp
import hashlib
import base64
from urllib.parse import urljoin

from .network_context import ThreatIntelligence, ThreatType

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelConfig:
    """Configuration for threat intelligence providers."""
    provider_name: str
    api_key: str
    base_url: str
    rate_limit_per_minute: int = 60
    timeout_seconds: int = 10
    enabled: bool = True
    priority: int = 1  # Lower number = higher priority


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""
    
    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_counts = {}
        self.last_reset_time = datetime.utcnow()
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    @abstractmethod
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation with the provider."""
        pass
    
    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = datetime.utcnow()
        
        # Reset counters every minute
        if (now - self.last_reset_time).seconds >= 60:
            self.request_counts.clear()
            self.last_reset_time = now
        
        current_requests = self.request_counts.get("requests", 0)
        return current_requests < self.config.rate_limit_per_minute
    
    def _increment_request_count(self):
        """Increment request counter."""
        self.request_counts["requests"] = self.request_counts.get("requests", 0) + 1


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal threat intelligence provider."""
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation with VirusTotal."""
        if not self._check_rate_limit():
            logger.warning("VirusTotal rate limit reached")
            return None
        
        try:
            url = f"{self.config.base_url}/ip-addresses/{ip_address}"
            headers = {
                "x-apikey": self.config.api_key,
                "Accept": "application/json"
            }
            
            async with self.session.get(url, headers=headers) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_virustotal_response(data)
                elif response.status == 429:
                    logger.warning("VirusTotal rate limit exceeded")
                    return None
                elif response.status == 404:
                    # IP not found in database - neutral reputation
                    return ThreatIntelligence(
                        is_malicious=False,
                        reputation_score=0.5,
                        confidence=0.3,
                        source_feeds=["virustotal"]
                    )
                else:
                    logger.error(f"VirusTotal API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying VirusTotal for {ip_address}: {e}")
            return None
    
    def _parse_virustotal_response(self, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse VirusTotal API response."""
        attributes = data.get("data", {}).get("attributes", {})
        
        # Get detection statistics
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0) 
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        total_engines = malicious + suspicious + harmless + undetected
        
        # Calculate reputation score
        if total_engines > 0:
            reputation_score = (harmless + undetected) / total_engines
            confidence = min(1.0, total_engines / 50)  # Higher confidence with more engines
        else:
            reputation_score = 0.5
            confidence = 0.0
        
        # Determine if malicious
        is_malicious = malicious > 3 or (malicious > 0 and malicious > harmless)
        
        # Extract threat types
        threat_types = []
        if malicious > 0:
            threat_types.append(ThreatType.MALWARE)
        if suspicious > 3:
            threat_types.append(ThreatType.SUSPICIOUS)
        
        # Get additional context
        categories = attributes.get("categories", {})
        if "phishing" in str(categories).lower():
            threat_types.append(ThreatType.PHISHING)
        if "botnet" in str(categories).lower():
            threat_types.append(ThreatType.BOTNET)
        
        return ThreatIntelligence(
            is_malicious=is_malicious,
            threat_types=threat_types,
            reputation_score=reputation_score,
            confidence=confidence,
            first_seen=self._parse_date(attributes.get("first_submission_date")),
            last_seen=self._parse_date(attributes.get("last_modification_date")),
            source_feeds=["virustotal"],
            additional_info={
                "detection_stats": stats,
                "categories": categories,
                "total_engines": total_engines
            }
        )
    
    def _parse_date(self, timestamp: Optional[int]) -> Optional[datetime]:
        """Parse Unix timestamp to datetime."""
        if timestamp:
            return datetime.fromtimestamp(timestamp)
        return None


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB threat intelligence provider."""
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation with AbuseIPDB."""
        if not self._check_rate_limit():
            logger.warning("AbuseIPDB rate limit reached")
            return None
        
        try:
            url = self.config.base_url
            headers = {
                "Key": self.config.api_key,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            async with self.session.get(url, headers=headers, params=params) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_abuseipdb_response(data)
                elif response.status == 429:
                    logger.warning("AbuseIPDB rate limit exceeded")
                    return None
                elif response.status == 422:
                    # Invalid IP or other client error
                    logger.warning(f"AbuseIPDB invalid request for {ip_address}")
                    return None
                else:
                    logger.error(f"AbuseIPDB API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying AbuseIPDB for {ip_address}: {e}")
            return None
    
    def _parse_abuseipdb_response(self, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse AbuseIPDB API response."""
        ip_data = data.get("data", {})
        
        # Get abuse confidence score (0-100)
        abuse_confidence = ip_data.get("abuseConfidencePercentage", 0)
        
        # Convert to reputation score (invert abuse confidence)
        reputation_score = max(0.0, (100 - abuse_confidence) / 100)
        
        # Determine if malicious
        is_malicious = abuse_confidence > 75
        
        # Extract threat types from usage categories
        threat_types = []
        usage_type = ip_data.get("usageType", "").lower()
        
        if "malware" in usage_type:
            threat_types.append(ThreatType.MALWARE)
        if "botnet" in usage_type or "bot" in usage_type:
            threat_types.append(ThreatType.BOTNET)
        if "spam" in usage_type:
            threat_types.append(ThreatType.SPAM)
        if "phishing" in usage_type:
            threat_types.append(ThreatType.PHISHING)
        if "proxy" in usage_type:
            threat_types.append(ThreatType.PROXY)
        
        # Add general threat types based on abuse confidence
        if abuse_confidence > 50:
            threat_types.append(ThreatType.SUSPICIOUS)
        if abuse_confidence > 90:
            threat_types.append(ThreatType.KNOWN_ATTACKER)
        
        # Confidence based on total reports and age
        total_reports = ip_data.get("totalReports", 0)
        confidence = min(1.0, total_reports / 10)  # Higher confidence with more reports
        
        return ThreatIntelligence(
            is_malicious=is_malicious,
            threat_types=threat_types,
            reputation_score=reputation_score,
            confidence=confidence,
            first_seen=self._parse_iso_date(ip_data.get("firstSeenDate")),
            last_seen=self._parse_iso_date(ip_data.get("lastReportedAt")),
            source_feeds=["abuseipdb"],
            additional_info={
                "abuse_confidence": abuse_confidence,
                "total_reports": total_reports,
                "country_code": ip_data.get("countryCode"),
                "usage_type": ip_data.get("usageType"),
                "isp": ip_data.get("isp"),
                "is_whitelisted": ip_data.get("isWhitelisted", False)
            }
        )
    
    def _parse_iso_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime."""
        if date_str:
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except ValueError:
                return None
        return None


class GreyNoiseProvider(ThreatIntelProvider):
    """GreyNoise threat intelligence provider."""
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation with GreyNoise."""
        if not self._check_rate_limit():
            logger.warning("GreyNoise rate limit reached")
            return None
        
        try:
            url = f"{self.config.base_url}/v3/community/{ip_address}"
            headers = {
                "key": self.config.api_key,
                "Accept": "application/json"
            }
            
            async with self.session.get(url, headers=headers) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_greynoise_response(data)
                elif response.status == 404:
                    # IP not seen by GreyNoise - neutral reputation
                    return ThreatIntelligence(
                        is_malicious=False,
                        reputation_score=0.6,  # Slightly positive for unknown IPs
                        confidence=0.4,
                        source_feeds=["greynoise"]
                    )
                elif response.status == 429:
                    logger.warning("GreyNoise rate limit exceeded")
                    return None
                else:
                    logger.error(f"GreyNoise API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying GreyNoise for {ip_address}: {e}")
            return None
    
    def _parse_greynoise_response(self, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse GreyNoise API response."""
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "").lower()
        name = data.get("name", "")
        
        # Determine reputation
        if riot:  # RIOT = Restricted Intelligence of Things (benign services)
            reputation_score = 0.9
            is_malicious = False
            confidence = 0.8
        elif noise:
            if classification == "malicious":
                reputation_score = 0.1
                is_malicious = True
                confidence = 0.9
            elif classification == "benign":
                reputation_score = 0.7
                is_malicious = False
                confidence = 0.7
            else:  # unknown classification
                reputation_score = 0.3
                is_malicious = False
                confidence = 0.5
        else:
            # Not seen in GreyNoise internet scanning
            reputation_score = 0.6
            is_malicious = False
            confidence = 0.4
        
        # Extract threat types from classification and name
        threat_types = []
        if classification == "malicious":
            threat_types.append(ThreatType.MALWARE)
            
            name_lower = name.lower()
            if "bot" in name_lower:
                threat_types.append(ThreatType.BOTNET)
            if "scan" in name_lower:
                threat_types.append(ThreatType.SUSPICIOUS)
            if "attack" in name_lower:
                threat_types.append(ThreatType.KNOWN_ATTACKER)
        
        return ThreatIntelligence(
            is_malicious=is_malicious,
            threat_types=threat_types,
            reputation_score=reputation_score,
            confidence=confidence,
            first_seen=self._parse_iso_date(data.get("first_seen")),
            last_seen=self._parse_iso_date(data.get("last_seen")),
            source_feeds=["greynoise"],
            additional_info={
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "name": name,
                "link": data.get("link")
            }
        )
    
    def _parse_iso_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO date string to datetime."""
        if date_str:
            try:
                return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            except ValueError:
                return None
        return None


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX (Open Threat Exchange) provider."""
    
    async def check_ip_reputation(self, ip_address: str) -> Optional[ThreatIntelligence]:
        """Check IP reputation with OTX."""
        if not self._check_rate_limit():
            logger.warning("OTX rate limit reached")
            return None
        
        try:
            url = f"{self.config.base_url}/indicators/IPv4/{ip_address}/general"
            headers = {
                "X-OTX-API-KEY": self.config.api_key,
                "Accept": "application/json"
            }
            
            async with self.session.get(url, headers=headers) as response:
                self._increment_request_count()
                
                if response.status == 200:
                    data = await response.json()
                    return self._parse_otx_response(data)
                elif response.status == 404:
                    # IP not found in OTX
                    return ThreatIntelligence(
                        is_malicious=False,
                        reputation_score=0.5,
                        confidence=0.3,
                        source_feeds=["otx"]
                    )
                elif response.status == 429:
                    logger.warning("OTX rate limit exceeded") 
                    return None
                else:
                    logger.error(f"OTX API error: {response.status}")
                    return None
                    
        except Exception as e:
            logger.error(f"Error querying OTX for {ip_address}: {e}")
            return None
    
    def _parse_otx_response(self, data: Dict[str, Any]) -> ThreatIntelligence:
        """Parse OTX API response."""
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        
        # Analyze pulses for threat indicators
        is_malicious = len(pulses) > 0
        reputation_score = max(0.1, 1.0 - (len(pulses) * 0.1))
        confidence = min(1.0, len(pulses) * 0.2)
        
        # Extract threat types from pulse names and tags
        threat_types = []
        for pulse in pulses:
            name = pulse.get("name", "").lower()
            tags = [tag.lower() for tag in pulse.get("tags", [])]
            
            if any(term in name for term in ["malware", "trojan", "virus"]):
                threat_types.append(ThreatType.MALWARE)
            if any(term in name for term in ["botnet", "bot"]):
                threat_types.append(ThreatType.BOTNET)
            if any(term in name for term in ["phishing", "phish"]):
                threat_types.append(ThreatType.PHISHING)
            if any(term in name for term in ["spam", "spammer"]):
                threat_types.append(ThreatType.SPAM)
            
            # Check tags as well
            if "malware" in tags:
                threat_types.append(ThreatType.MALWARE)
            if "botnet" in tags:
                threat_types.append(ThreatType.BOTNET)
        
        # Remove duplicates
        threat_types = list(set(threat_types))
        
        if is_malicious and not threat_types:
            threat_types.append(ThreatType.SUSPICIOUS)
        
        return ThreatIntelligence(
            is_malicious=is_malicious,
            threat_types=threat_types,
            reputation_score=reputation_score,
            confidence=confidence,
            source_feeds=["otx"],
            additional_info={
                "pulse_count": len(pulses),
                "pulses": [
                    {
                        "name": p.get("name"),
                        "author": p.get("author_name"),
                        "created": p.get("created"),
                        "tags": p.get("tags", [])
                    }
                    for p in pulses[:5]  # Limit to first 5 pulses
                ]
            }
        )


class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple providers."""
    
    def __init__(self, providers: List[ThreatIntelProvider]):
        self.providers = sorted(providers, key=lambda p: p.config.priority)
        self.cache = {}
        self.cache_ttl = timedelta(hours=6)  # Cache results for 6 hours
        
        self.metrics = {
            "queries": 0,
            "cache_hits": 0,
            "provider_queries": {p.config.provider_name: 0 for p in providers},
            "provider_errors": {p.config.provider_name: 0 for p in providers}
        }
    
    async def get_ip_reputation(self, ip_address: str) -> ThreatIntelligence:
        """Get aggregated threat intelligence for an IP."""
        # Check cache first
        cache_key = hashlib.md5(ip_address.encode()).hexdigest()
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if datetime.utcnow() - cached_time < self.cache_ttl:
                self.metrics["cache_hits"] += 1
                return cached_data
        
        self.metrics["queries"] += 1
        
        # Query providers in priority order
        all_results = []
        
        for provider in self.providers:
            if not provider.config.enabled:
                continue
                
            try:
                result = await provider.check_ip_reputation(ip_address)
                if result:
                    all_results.append((provider.config.provider_name, result))
                    self.metrics["provider_queries"][provider.config.provider_name] += 1
                    
                    # If we get a high-confidence malicious result, we can stop early
                    if result.is_malicious and result.confidence > 0.8:
                        break
                        
            except Exception as e:
                logger.error(f"Error querying {provider.config.provider_name}: {e}")
                self.metrics["provider_errors"][provider.config.provider_name] += 1
        
        # Aggregate results
        aggregated = self._aggregate_results(all_results)
        
        # Cache the result
        self.cache[cache_key] = (aggregated, datetime.utcnow())
        
        return aggregated
    
    def _aggregate_results(self, results: List[Tuple[str, ThreatIntelligence]]) -> ThreatIntelligence:
        """Aggregate results from multiple providers."""
        if not results:
            # No data available
            return ThreatIntelligence(
                is_malicious=False,
                reputation_score=0.5,
                confidence=0.0,
                source_feeds=[]
            )
        
        # Collect all data
        malicious_votes = sum(1 for _, r in results if r.is_malicious)
        reputation_scores = [r.reputation_score for _, r in results]
        confidences = [r.confidence for _, r in results]
        all_threat_types = []
        all_source_feeds = []
        
        for provider_name, result in results:
            all_threat_types.extend(result.threat_types)
            all_source_feeds.append(provider_name)
        
        # Weighted aggregation (providers with higher confidence get more weight)
        if confidences:
            total_weight = sum(confidences)
            if total_weight > 0:
                weighted_reputation = sum(
                    score * confidence for score, confidence in zip(reputation_scores, confidences)
                ) / total_weight
            else:
                weighted_reputation = sum(reputation_scores) / len(reputation_scores)
        else:
            weighted_reputation = 0.5
        
        # Determine if malicious (majority vote with confidence weighting)
        malicious_confidence = sum(
            confidence for _, result in results 
            if result.is_malicious
            for confidence in [result.confidence]
        )
        benign_confidence = sum(
            confidence for _, result in results 
            if not result.is_malicious
            for confidence in [result.confidence]
        )
        
        is_malicious = malicious_confidence > benign_confidence
        
        # Aggregate confidence (average of all confidences)
        overall_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        
        # Remove duplicate threat types
        unique_threat_types = list(set(all_threat_types))
        
        return ThreatIntelligence(
            is_malicious=is_malicious,
            threat_types=unique_threat_types,
            reputation_score=weighted_reputation,
            confidence=overall_confidence,
            source_feeds=all_source_feeds,
            additional_info={
                "provider_count": len(results),
                "malicious_votes": malicious_votes,
                "benign_votes": len(results) - malicious_votes,
                "raw_scores": reputation_scores
            }
        )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregator metrics."""
        cache_hit_rate = (
            self.metrics["cache_hits"] / max(self.metrics["queries"], 1) * 100
        )
        
        return {
            "total_queries": self.metrics["queries"],
            "cache_hits": self.metrics["cache_hits"],
            "cache_hit_rate_percent": round(cache_hit_rate, 2),
            "provider_queries": self.metrics["provider_queries"],
            "provider_errors": self.metrics["provider_errors"],
            "cached_entries": len(self.cache)
        }
    
    def clear_cache(self):
        """Clear the threat intelligence cache."""
        self.cache.clear()


def create_threat_intelligence_system() -> ThreatIntelligenceAggregator:
    """Create a complete threat intelligence system with multiple providers."""
    providers = []
    
    # VirusTotal
    if os.getenv("VIRUSTOTAL_API_KEY"):
        config = ThreatIntelConfig(
            provider_name="virustotal",
            api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            base_url="https://www.virustotal.com/api/v3",
            rate_limit_per_minute=4,  # Free tier limit
            priority=1
        )
        providers.append(VirusTotalProvider(config))
    
    # AbuseIPDB
    if os.getenv("ABUSEIPDB_API_KEY"):
        config = ThreatIntelConfig(
            provider_name="abuseipdb",
            api_key=os.getenv("ABUSEIPDB_API_KEY"),
            base_url="https://api.abuseipdb.com/api/v2/check",
            rate_limit_per_minute=1000,  # Free tier limit
            priority=2
        )
        providers.append(AbuseIPDBProvider(config))
    
    # GreyNoise
    if os.getenv("GREYNOISE_API_KEY"):
        config = ThreatIntelConfig(
            provider_name="greynoise",
            api_key=os.getenv("GREYNOISE_API_KEY"),
            base_url="https://api.greynoise.io",
            rate_limit_per_minute=1000,  # Community tier
            priority=3
        )
        providers.append(GreyNoiseProvider(config))
    
    # OTX
    if os.getenv("OTX_API_KEY"):
        config = ThreatIntelConfig(
            provider_name="otx",
            api_key=os.getenv("OTX_API_KEY"),
            base_url="https://otx.alienvault.com/api/v1",
            rate_limit_per_minute=300,  # Free tier limit
            priority=4
        )
        providers.append(OTXProvider(config))
    
    if not providers:
        logger.warning("No threat intelligence providers configured - using mock data only")
    
    return ThreatIntelligenceAggregator(providers)


# Export main classes
__all__ = [
    "ThreatIntelConfig",
    "ThreatIntelProvider",
    "VirusTotalProvider",
    "AbuseIPDBProvider", 
    "GreyNoiseProvider",
    "OTXProvider",
    "ThreatIntelligenceAggregator",
    "create_threat_intelligence_system"
]