#!/usr/bin/env python3
"""
iSECTECH SIEM Log Enrichment Engine
Production-grade log enrichment with contextual data integration
Supports asset inventory, threat intelligence, user context, and vulnerability data
"""

import asyncio
import json
import yaml
import logging
import time
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Union, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import aiofiles
import aiohttp
import hashlib
from urllib.parse import urlparse
import dns.resolver
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EnrichmentConfig:
    """Configuration for log enrichment"""
    asset_inventory_file: str = "/opt/siem/enrichment/data/asset_inventory.json"
    threat_intel_feeds: List[str] = None
    user_directory_url: str = ""
    vulnerability_db_url: str = ""
    network_topology_file: str = "/opt/siem/enrichment/data/network_topology.json"
    geoip_database: str = "/opt/geoip/GeoLite2-City.mmdb"
    cache_ttl_seconds: int = 3600
    max_cache_size: int = 10000
    enable_async_enrichment: bool = True
    enrichment_timeout_seconds: int = 5

@dataclass
class EnrichmentResult:
    """Result of log enrichment"""
    original_log: Dict[str, Any]
    enriched_fields: Dict[str, Any]
    enrichment_sources: List[str]
    enrichment_time_ms: float
    errors: List[str]
    cache_hits: List[str]

@dataclass
class AssetInfo:
    """Asset inventory information"""
    asset_id: str
    hostname: str
    ip_addresses: List[str]
    asset_type: str
    operating_system: str
    owner: str
    business_unit: str
    criticality: str
    location: str
    compliance_tags: List[str]
    last_updated: datetime

@dataclass
class ThreatIntelData:
    """Threat intelligence information"""
    indicator: str
    indicator_type: str
    threat_type: str
    confidence_score: int
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str
    tags: List[str]

@dataclass
class UserContext:
    """User context information"""
    user_id: str
    username: str
    email: str
    full_name: str
    department: str
    job_title: str
    manager: str
    privileges: List[str]
    groups: List[str]
    risk_score: int
    last_login: datetime

@dataclass
class NetworkContext:
    """Network context information"""
    ip_address: str
    subnet: str
    vlan_id: str
    network_zone: str
    gateway: str
    dns_servers: List[str]
    network_type: str
    security_level: str

@dataclass
class VulnerabilityData:
    """Vulnerability information"""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_products: List[str]
    patches_available: bool
    exploits_available: bool
    first_published: datetime

class LogEnrichmentEngine:
    """
    Production-grade log enrichment engine for iSECTECH SIEM
    Integrates multiple context sources to enhance security log analysis
    """
    
    def __init__(self, config: EnrichmentConfig):
        self.config = config
        self.asset_inventory: Dict[str, AssetInfo] = {}
        self.threat_intel_cache: Dict[str, ThreatIntelData] = {}
        self.user_context_cache: Dict[str, UserContext] = {}
        self.network_context_cache: Dict[str, NetworkContext] = {}
        self.vulnerability_cache: Dict[str, VulnerabilityData] = {}
        
        # General purpose cache for enrichment data
        self.enrichment_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_timestamps: Dict[str, datetime] = {}
        
        # Performance metrics
        self.stats = {
            "total_enrichments": 0,
            "successful_enrichments": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_enrichment_time_ms": 0,
            "enrichment_sources_used": {},
            "errors": 0
        }
        
        # Initialize HTTP session for external API calls
        self.http_session = None
        
    async def initialize(self):
        """Initialize the enrichment engine"""
        try:
            # Initialize HTTP session
            self.http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.enrichment_timeout_seconds)
            )
            
            # Load static data sources
            await self._load_asset_inventory()
            await self._load_network_topology()
            
            # Initialize threat intelligence feeds
            await self._initialize_threat_feeds()
            
            logger.info("Log enrichment engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize enrichment engine: {e}")
            raise
            
    async def enrich_log(self, log_entry: Dict[str, Any]) -> EnrichmentResult:
        """
        Enrich a log entry with contextual data
        
        Args:
            log_entry: Original log entry to enrich
            
        Returns:
            EnrichmentResult with enriched data
        """
        start_time = time.perf_counter()
        self.stats["total_enrichments"] += 1
        
        enriched_fields = {}
        enrichment_sources = []
        errors = []
        cache_hits = []
        
        try:
            # Asset enrichment
            asset_enrichment = await self._enrich_with_asset_data(log_entry)
            if asset_enrichment:
                enriched_fields.update(asset_enrichment["fields"])
                enrichment_sources.append("asset_inventory")
                if asset_enrichment.get("cache_hit"):
                    cache_hits.append("asset_inventory")
                    
            # Threat intelligence enrichment
            threat_enrichment = await self._enrich_with_threat_intel(log_entry)
            if threat_enrichment:
                enriched_fields.update(threat_enrichment["fields"])
                enrichment_sources.append("threat_intelligence")
                if threat_enrichment.get("cache_hit"):
                    cache_hits.append("threat_intelligence")
                    
            # User context enrichment
            user_enrichment = await self._enrich_with_user_context(log_entry)
            if user_enrichment:
                enriched_fields.update(user_enrichment["fields"])
                enrichment_sources.append("user_directory")
                if user_enrichment.get("cache_hit"):
                    cache_hits.append("user_directory")
                    
            # Network context enrichment
            network_enrichment = await self._enrich_with_network_context(log_entry)
            if network_enrichment:
                enriched_fields.update(network_enrichment["fields"])
                enrichment_sources.append("network_topology")
                if network_enrichment.get("cache_hit"):
                    cache_hits.append("network_topology")
                    
            # Vulnerability enrichment
            vuln_enrichment = await self._enrich_with_vulnerability_data(log_entry)
            if vuln_enrichment:
                enriched_fields.update(vuln_enrichment["fields"])
                enrichment_sources.append("vulnerability_db")
                if vuln_enrichment.get("cache_hit"):
                    cache_hits.append("vulnerability_db")
                    
            # Add enrichment metadata
            enriched_fields["enrichment.timestamp"] = datetime.now(timezone.utc).isoformat()
            enriched_fields["enrichment.sources"] = enrichment_sources
            enriched_fields["enrichment.version"] = "1.0.0"
            
            self.stats["successful_enrichments"] += 1
            self.stats["cache_hits"] += len(cache_hits)
            
        except Exception as e:
            logger.error(f"Enrichment failed: {e}")
            errors.append(str(e))
            self.stats["errors"] += 1
            
        processing_time = (time.perf_counter() - start_time) * 1000
        self._update_performance_stats(processing_time)
        
        return EnrichmentResult(
            original_log=log_entry,
            enriched_fields=enriched_fields,
            enrichment_sources=enrichment_sources,
            enrichment_time_ms=processing_time,
            errors=errors,
            cache_hits=cache_hits
        )
        
    async def _load_asset_inventory(self):
        """Load asset inventory from file"""
        try:
            if not Path(self.config.asset_inventory_file).exists():
                logger.warning(f"Asset inventory file not found: {self.config.asset_inventory_file}")
                return
                
            async with aiofiles.open(self.config.asset_inventory_file, 'r') as f:
                content = await f.read()
                inventory_data = json.loads(content)
                
            # Process inventory data
            for asset_data in inventory_data.get("assets", []):
                asset_info = AssetInfo(
                    asset_id=asset_data["asset_id"],
                    hostname=asset_data["hostname"],
                    ip_addresses=asset_data["ip_addresses"],
                    asset_type=asset_data["asset_type"],
                    operating_system=asset_data["operating_system"],
                    owner=asset_data["owner"],
                    business_unit=asset_data["business_unit"],
                    criticality=asset_data["criticality"],
                    location=asset_data["location"],
                    compliance_tags=asset_data.get("compliance_tags", []),
                    last_updated=datetime.fromisoformat(asset_data["last_updated"])
                )
                
                # Index by hostname and IP addresses
                self.asset_inventory[asset_info.hostname.lower()] = asset_info
                for ip in asset_info.ip_addresses:
                    self.asset_inventory[ip] = asset_info
                    
            logger.info(f"Loaded {len(inventory_data.get('assets', []))} assets into inventory")
            
        except Exception as e:
            logger.error(f"Failed to load asset inventory: {e}")
            
    async def _load_network_topology(self):
        """Load network topology information"""
        try:
            if not Path(self.config.network_topology_file).exists():
                logger.warning(f"Network topology file not found: {self.config.network_topology_file}")
                return
                
            async with aiofiles.open(self.config.network_topology_file, 'r') as f:
                content = await f.read()
                topology_data = json.loads(content)
                
            # Process network segments
            for segment in topology_data.get("network_segments", []):
                subnet = segment["subnet"]
                network = ipaddress.ip_network(subnet, strict=False)
                
                network_context = NetworkContext(
                    ip_address="",  # Will be set per IP
                    subnet=subnet,
                    vlan_id=segment.get("vlan_id", ""),
                    network_zone=segment.get("network_zone", ""),
                    gateway=segment.get("gateway", ""),
                    dns_servers=segment.get("dns_servers", []),
                    network_type=segment.get("network_type", ""),
                    security_level=segment.get("security_level", "")
                )
                
                # Cache network context for the subnet
                cache_key = f"network_segment:{subnet}"
                self.network_context_cache[cache_key] = network_context
                
            logger.info(f"Loaded {len(topology_data.get('network_segments', []))} network segments")
            
        except Exception as e:
            logger.error(f"Failed to load network topology: {e}")
            
    async def _initialize_threat_feeds(self):
        """Initialize threat intelligence feeds"""
        if not self.config.threat_intel_feeds:
            self.config.threat_intel_feeds = [
                "https://feeds.isectech.com/indicators/iocs.json",
                "https://otx.alienvault.com/api/v1/indicators/export",
                "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/"
            ]
            
        logger.info(f"Initialized {len(self.config.threat_intel_feeds)} threat intelligence feeds")
        
    async def _enrich_with_asset_data(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich log with asset inventory data"""
        enrichment = {"fields": {}, "cache_hit": False}
        
        # Look for host identifiers
        host_identifiers = []
        
        if "host.name" in log_entry:
            host_identifiers.append(log_entry["host.name"].lower())
        if "host.hostname" in log_entry:
            host_identifiers.append(log_entry["host.hostname"].lower())
        if "source.ip" in log_entry:
            host_identifiers.append(log_entry["source.ip"])
        if "destination.ip" in log_entry:
            host_identifiers.append(log_entry["destination.ip"])
            
        # Find matching asset
        for identifier in host_identifiers:
            if identifier in self.asset_inventory:
                asset = self.asset_inventory[identifier]
                enrichment["fields"].update({
                    "asset.id": asset.asset_id,
                    "asset.type": asset.asset_type,
                    "asset.operating_system": asset.operating_system,
                    "asset.owner": asset.owner,
                    "asset.business_unit": asset.business_unit,
                    "asset.criticality": asset.criticality,
                    "asset.location": asset.location,
                    "asset.compliance_tags": asset.compliance_tags,
                    "asset.last_updated": asset.last_updated.isoformat()
                })
                enrichment["cache_hit"] = True
                break
                
        return enrichment if enrichment["fields"] else None
        
    async def _enrich_with_threat_intel(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich log with threat intelligence data"""
        enrichment = {"fields": {}, "cache_hit": False}
        
        # Extract potential IOCs from log
        iocs = await self._extract_iocs(log_entry)
        
        threat_matches = []
        for ioc in iocs:
            # Check cache first
            cache_key = f"threat_intel:{ioc}"
            if cache_key in self.enrichment_cache:
                cached_data = self.enrichment_cache[cache_key]
                if self._is_cache_valid(cache_key):
                    threat_matches.append(cached_data)
                    enrichment["cache_hit"] = True
                    continue
                    
            # Query threat intelligence feeds
            threat_data = await self._query_threat_feeds(ioc)
            if threat_data:
                threat_matches.append(threat_data)
                self._cache_data(cache_key, threat_data)
                
        if threat_matches:
            # Aggregate threat intelligence data
            max_confidence = max(match.get("confidence_score", 0) for match in threat_matches)
            threat_types = list(set(match.get("threat_type", "") for match in threat_matches if match.get("threat_type")))
            sources = list(set(match.get("source", "") for match in threat_matches if match.get("source")))
            
            enrichment["fields"].update({
                "threat.indicator.matched": True,
                "threat.indicator.count": len(threat_matches),
                "threat.indicator.confidence": max_confidence,
                "threat.indicator.types": threat_types,
                "threat.indicator.sources": sources,
                "threat.indicator.first_seen": min(
                    match.get("first_seen", datetime.now(timezone.utc).isoformat()) 
                    for match in threat_matches
                ),
                "threat.indicator.last_seen": max(
                    match.get("last_seen", datetime.now(timezone.utc).isoformat()) 
                    for match in threat_matches
                )
            })
            
        return enrichment if enrichment["fields"] else None
        
    async def _enrich_with_user_context(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich log with user context data"""
        enrichment = {"fields": {}, "cache_hit": False}
        
        # Extract user identifiers
        user_identifiers = []
        
        if "user.name" in log_entry:
            user_identifiers.append(log_entry["user.name"])
        if "user.email" in log_entry:
            user_identifiers.append(log_entry["user.email"])
        if "user.id" in log_entry:
            user_identifiers.append(log_entry["user.id"])
            
        # Look up user context
        for identifier in user_identifiers:
            cache_key = f"user_context:{identifier}"
            
            # Check cache first
            if cache_key in self.enrichment_cache:
                if self._is_cache_valid(cache_key):
                    user_data = self.enrichment_cache[cache_key]
                    enrichment["fields"].update({
                        "user.department": user_data.get("department", ""),
                        "user.job_title": user_data.get("job_title", ""),
                        "user.manager": user_data.get("manager", ""),
                        "user.privileges": user_data.get("privileges", []),
                        "user.groups": user_data.get("groups", []),
                        "user.risk_score": user_data.get("risk_score", 0),
                        "user.last_login": user_data.get("last_login", "")
                    })
                    enrichment["cache_hit"] = True
                    break
                    
            # Query user directory
            if self.config.user_directory_url:
                user_data = await self._query_user_directory(identifier)
                if user_data:
                    enrichment["fields"].update(user_data)
                    self._cache_data(cache_key, user_data)
                    break
                    
        return enrichment if enrichment["fields"] else None
        
    async def _enrich_with_network_context(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich log with network context data"""
        enrichment = {"fields": {}, "cache_hit": False}
        
        # Extract IP addresses
        ip_addresses = []
        
        if "source.ip" in log_entry:
            ip_addresses.append(log_entry["source.ip"])
        if "destination.ip" in log_entry:
            ip_addresses.append(log_entry["destination.ip"])
        if "client.ip" in log_entry:
            ip_addresses.append(log_entry["client.ip"])
            
        # Find network context for each IP
        for ip_addr in ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip_addr)
                
                # Find matching network segment
                for cache_key, network_context in self.network_context_cache.items():
                    if cache_key.startswith("network_segment:"):
                        subnet = cache_key.split(":", 1)[1]
                        network = ipaddress.ip_network(subnet, strict=False)
                        
                        if ip_obj in network:
                            prefix = "source" if ip_addr == log_entry.get("source.ip") else "destination"
                            
                            enrichment["fields"].update({
                                f"{prefix}.network.subnet": network_context.subnet,
                                f"{prefix}.network.vlan_id": network_context.vlan_id,
                                f"{prefix}.network.zone": network_context.network_zone,
                                f"{prefix}.network.gateway": network_context.gateway,
                                f"{prefix}.network.type": network_context.network_type,
                                f"{prefix}.network.security_level": network_context.security_level
                            })
                            enrichment["cache_hit"] = True
                            break
                            
            except (ipaddress.AddressValueError, ValueError):
                continue
                
        return enrichment if enrichment["fields"] else None
        
    async def _enrich_with_vulnerability_data(self, log_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Enrich log with vulnerability data"""
        enrichment = {"fields": {}, "cache_hit": False}
        
        # Look for CVE references in the log
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        log_text = json.dumps(log_entry)
        cve_matches = re.findall(cve_pattern, log_text, re.IGNORECASE)
        
        if cve_matches:
            vuln_data = []
            
            for cve_id in cve_matches:
                cache_key = f"vulnerability:{cve_id.upper()}"
                
                # Check cache first
                if cache_key in self.enrichment_cache:
                    if self._is_cache_valid(cache_key):
                        vuln_data.append(self.enrichment_cache[cache_key])
                        enrichment["cache_hit"] = True
                        continue
                        
                # Query vulnerability database
                if self.config.vulnerability_db_url:
                    vuln_info = await self._query_vulnerability_db(cve_id)
                    if vuln_info:
                        vuln_data.append(vuln_info)
                        self._cache_data(cache_key, vuln_info)
                        
            if vuln_data:
                # Aggregate vulnerability data
                max_cvss = max(vuln.get("cvss_score", 0) for vuln in vuln_data)
                severities = list(set(vuln.get("severity", "") for vuln in vuln_data if vuln.get("severity")))
                
                enrichment["fields"].update({
                    "vulnerability.cve_ids": [vuln.get("cve_id") for vuln in vuln_data],
                    "vulnerability.max_cvss_score": max_cvss,
                    "vulnerability.severities": severities,
                    "vulnerability.exploits_available": any(vuln.get("exploits_available", False) for vuln in vuln_data),
                    "vulnerability.patches_available": any(vuln.get("patches_available", False) for vuln in vuln_data)
                })
                
        return enrichment if enrichment["fields"] else None
        
    async def _extract_iocs(self, log_entry: Dict[str, Any]) -> List[str]:
        """Extract potential indicators of compromise from log"""
        iocs = []
        
        # IP addresses
        for field in ["source.ip", "destination.ip", "client.ip"]:
            if field in log_entry:
                iocs.append(log_entry[field])
                
        # Domain names
        for field in ["url.domain", "dns.question.name", "destination.domain"]:
            if field in log_entry:
                iocs.append(log_entry[field])
                
        # File hashes
        for field in ["file.hash.md5", "file.hash.sha1", "file.hash.sha256", "process.hash.md5", "process.hash.sha256"]:
            if field in log_entry:
                iocs.append(log_entry[field])
                
        # URLs
        if "url.original" in log_entry:
            iocs.append(log_entry["url.original"])
            
        # Email addresses
        if "user.email" in log_entry:
            iocs.append(log_entry["user.email"])
            
        return list(set(iocs))  # Remove duplicates
        
    async def _query_threat_feeds(self, ioc: str) -> Optional[Dict[str, Any]]:
        """Query threat intelligence feeds for IOC"""
        try:
            # Simulate threat intelligence lookup
            # In production, this would query actual threat feeds
            
            # Mock threat intelligence data
            if any(suspicious in ioc.lower() for suspicious in ["malicious", "threat", "bad", "evil"]):
                return {
                    "indicator": ioc,
                    "threat_type": "malware",
                    "confidence_score": 85,
                    "source": "mock_threat_feed",
                    "first_seen": (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "description": f"Suspicious indicator: {ioc}"
                }
                
            # Check against known bad IPs/domains (simplified)
            known_bad_indicators = [
                "203.0.113.100",  # Example bad IP
                "malicious.example.com",  # Example bad domain
                "evil-hash-placeholder"  # Example bad hash
            ]
            
            if ioc in known_bad_indicators:
                return {
                    "indicator": ioc,
                    "threat_type": "known_bad",
                    "confidence_score": 95,
                    "source": "internal_blocklist",
                    "first_seen": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "description": f"Known malicious indicator: {ioc}"
                }
                
        except Exception as e:
            logger.warning(f"Failed to query threat feeds for {ioc}: {e}")
            
        return None
        
    async def _query_user_directory(self, user_identifier: str) -> Optional[Dict[str, Any]]:
        """Query user directory for user context"""
        try:
            # Simulate user directory lookup
            # In production, this would query LDAP/AD or user directory API
            
            # Mock user data
            mock_users = {
                "admin": {
                    "department": "IT Security",
                    "job_title": "Security Administrator",
                    "manager": "security.manager@isectech.com",
                    "privileges": ["admin", "security_operator"],
                    "groups": ["Domain Admins", "Security Team"],
                    "risk_score": 20,  # Admins have higher risk
                    "last_login": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
                },
                "user123": {
                    "department": "Finance",
                    "job_title": "Financial Analyst",
                    "manager": "finance.manager@isectech.com",
                    "privileges": ["user"],
                    "groups": ["Finance Users"],
                    "risk_score": 5,
                    "last_login": (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
                }
            }
            
            if user_identifier.lower() in mock_users:
                return mock_users[user_identifier.lower()]
                
        except Exception as e:
            logger.warning(f"Failed to query user directory for {user_identifier}: {e}")
            
        return None
        
    async def _query_vulnerability_db(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Query vulnerability database for CVE information"""
        try:
            # Simulate vulnerability database lookup
            # In production, this would query NVD API or internal vulnerability database
            
            # Mock vulnerability data
            mock_vulnerabilities = {
                "CVE-2024-1234": {
                    "cve_id": "CVE-2024-1234",
                    "cvss_score": 9.8,
                    "severity": "critical",
                    "description": "Remote code execution vulnerability",
                    "exploits_available": True,
                    "patches_available": True,
                    "first_published": "2024-01-15T00:00:00Z"
                },
                "CVE-2023-5678": {
                    "cve_id": "CVE-2023-5678",
                    "cvss_score": 6.5,
                    "severity": "medium",
                    "description": "Information disclosure vulnerability",
                    "exploits_available": False,
                    "patches_available": True,
                    "first_published": "2023-12-01T00:00:00Z"
                }
            }
            
            if cve_id.upper() in mock_vulnerabilities:
                return mock_vulnerabilities[cve_id.upper()]
                
        except Exception as e:
            logger.warning(f"Failed to query vulnerability database for {cve_id}: {e}")
            
        return None
        
    def _cache_data(self, key: str, data: Dict[str, Any]):
        """Cache enrichment data"""
        # Implement LRU cache logic
        if len(self.enrichment_cache) >= self.config.max_cache_size:
            # Remove oldest entry
            oldest_key = min(self.cache_timestamps.keys(), key=lambda k: self.cache_timestamps[k])
            del self.enrichment_cache[oldest_key]
            del self.cache_timestamps[oldest_key]
            
        self.enrichment_cache[key] = data
        self.cache_timestamps[key] = datetime.now(timezone.utc)
        
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached data is still valid"""
        if key not in self.cache_timestamps:
            return False
            
        age = datetime.now(timezone.utc) - self.cache_timestamps[key]
        return age.total_seconds() < self.config.cache_ttl_seconds
        
    def _update_performance_stats(self, processing_time_ms: float):
        """Update performance statistics"""
        current_avg = self.stats["avg_enrichment_time_ms"]
        total_enrichments = self.stats["total_enrichments"]
        
        # Calculate new running average
        self.stats["avg_enrichment_time_ms"] = (
            (current_avg * (total_enrichments - 1) + processing_time_ms) / total_enrichments
        )
        
    async def enrich_batch(self, log_entries: List[Dict[str, Any]]) -> List[EnrichmentResult]:
        """Enrich a batch of log entries efficiently"""
        if self.config.enable_async_enrichment:
            # Process entries concurrently
            tasks = [self.enrich_log(entry) for entry in log_entries]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions
            enrichment_results = []
            for result in results:
                if isinstance(result, EnrichmentResult):
                    enrichment_results.append(result)
                elif isinstance(result, Exception):
                    logger.error(f"Batch enrichment error: {result}")
                    
            return enrichment_results
        else:
            # Process entries sequentially
            results = []
            for entry in log_entries:
                result = await self.enrich_log(entry)
                results.append(result)
            return results
            
    async def get_statistics(self) -> Dict[str, Any]:
        """Get enrichment engine statistics"""
        cache_hit_rate = (self.stats["cache_hits"] / max(self.stats["total_enrichments"], 1)) * 100
        success_rate = (self.stats["successful_enrichments"] / max(self.stats["total_enrichments"], 1)) * 100
        
        return {
            **self.stats,
            "cache_hit_rate_percent": cache_hit_rate,
            "success_rate_percent": success_rate,
            "cache_size": len(self.enrichment_cache),
            "asset_inventory_size": len(self.asset_inventory)
        }
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.http_session:
            await self.http_session.close()
            
        # Clear caches
        self.enrichment_cache.clear()
        self.cache_timestamps.clear()
        
        logger.info("Log enrichment engine cleanup completed")

# Example usage
async def main():
    """Example usage of the log enrichment engine"""
    config = EnrichmentConfig(
        asset_inventory_file="/opt/siem/enrichment/data/asset_inventory.json",
        threat_intel_feeds=["https://feeds.isectech.com/indicators/iocs.json"],
        user_directory_url="ldap://dc.isectech.com",
        vulnerability_db_url="https://nvd.nist.gov/rest/json/cves/2.0/",
        cache_ttl_seconds=3600,
        enable_async_enrichment=True
    )
    
    enrichment_engine = LogEnrichmentEngine(config)
    await enrichment_engine.initialize()
    
    # Example log entry
    test_log = {
        "@timestamp": "2024-01-15T10:30:00Z",
        "event.action": "login",
        "source.ip": "192.168.1.100",
        "user.name": "admin",
        "host.name": "WORKSTATION01",
        "url.domain": "malicious.example.com"
    }
    
    # Enrich the log
    result = await enrichment_engine.enrich_log(test_log)
    
    print("Original log:")
    print(json.dumps(result.original_log, indent=2))
    print("\nEnriched fields:")
    print(json.dumps(result.enriched_fields, indent=2, default=str))
    print(f"\nEnrichment sources: {result.enrichment_sources}")
    print(f"Processing time: {result.enrichment_time_ms:.2f}ms")
    
    # Get statistics
    stats = await enrichment_engine.get_statistics()
    print(f"\nStatistics: {json.dumps(stats, indent=2)}")
    
    await enrichment_engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())