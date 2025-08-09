#!/usr/bin/env python3
"""
iSECTECH SIEM Threat Intelligence Feed Manager
Production-grade threat intelligence integration with multiple feed sources
Supports IOC management, feed validation, and automated enrichment
"""

import asyncio
import json
import yaml
import logging
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import aiofiles
import aiohttp
from urllib.parse import urlparse
import csv
import re
import ipaddress

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatFeedConfig:
    """Configuration for threat intelligence feeds"""
    feed_url: str
    feed_type: str  # json, csv, stix, misp, txt
    api_key: str = ""
    feed_name: str = ""
    confidence_weight: float = 1.0
    update_interval_minutes: int = 60
    enabled: bool = True
    verify_ssl: bool = True
    timeout_seconds: int = 30
    max_indicators: int = 100000

@dataclass
class ThreatIndicator:
    """Threat intelligence indicator"""
    value: str
    indicator_type: str  # ip, domain, url, hash, email
    threat_type: str
    confidence_score: int
    first_seen: datetime
    last_seen: datetime
    source: str
    description: str
    tags: List[str]
    ttl_hours: int = 24
    malware_family: str = ""
    kill_chain_phase: str = ""
    actor_group: str = ""

@dataclass
class FeedUpdateResult:
    """Result of feed update operation"""
    feed_name: str
    success: bool
    indicators_added: int
    indicators_updated: int
    indicators_removed: int
    total_indicators: int
    update_time_ms: float
    error_message: str = ""

class ThreatIntelligenceFeedManager:
    """
    Production-grade threat intelligence feed manager
    Handles multiple feed sources, IOC validation, and automated updates
    """
    
    def __init__(self, feeds_config_file: str):
        self.feeds_config_file = feeds_config_file
        self.feed_configs: List[ThreatFeedConfig] = []
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.indicator_index: Dict[str, Set[str]] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
            "email": set()
        }
        
        # HTTP session for feed downloads
        self.http_session = None
        
        # Statistics
        self.stats = {
            "total_feeds": 0,
            "active_feeds": 0,
            "total_indicators": 0,
            "indicators_by_type": {},
            "last_update": None,
            "update_errors": 0,
            "feed_performance": {}
        }
        
        # Update locks to prevent concurrent updates
        self._update_locks: Dict[str, asyncio.Lock] = {}
        
    async def initialize(self):
        """Initialize the threat intelligence feed manager"""
        try:
            # Initialize HTTP session
            self.http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )
            
            # Load feed configurations
            await self._load_feed_configs()
            
            # Initialize update locks for each feed
            for feed_config in self.feed_configs:
                self._update_locks[feed_config.feed_name] = asyncio.Lock()
                
            # Load existing indicators from cache
            await self._load_cached_indicators()
            
            logger.info("Threat intelligence feed manager initialized successfully")
            logger.info(f"Loaded {len(self.feed_configs)} feed configurations")
            
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence feed manager: {e}")
            raise
            
    async def _load_feed_configs(self):
        """Load threat intelligence feed configurations"""
        try:
            if not Path(self.feeds_config_file).exists():
                # Create default configuration
                await self._create_default_config()
                
            async with aiofiles.open(self.feeds_config_file, 'r') as f:
                content = await f.read()
                config_data = yaml.safe_load(content)
                
            # Parse feed configurations
            for feed_data in config_data.get("threat_feeds", []):
                feed_config = ThreatFeedConfig(
                    feed_url=feed_data["feed_url"],
                    feed_type=feed_data["feed_type"],
                    api_key=feed_data.get("api_key", ""),
                    feed_name=feed_data.get("feed_name", self._generate_feed_name(feed_data["feed_url"])),
                    confidence_weight=feed_data.get("confidence_weight", 1.0),
                    update_interval_minutes=feed_data.get("update_interval_minutes", 60),
                    enabled=feed_data.get("enabled", True),
                    verify_ssl=feed_data.get("verify_ssl", True),
                    timeout_seconds=feed_data.get("timeout_seconds", 30),
                    max_indicators=feed_data.get("max_indicators", 100000)
                )
                
                if feed_config.enabled:
                    self.feed_configs.append(feed_config)
                    
            self.stats["total_feeds"] = len(self.feed_configs)
            self.stats["active_feeds"] = len([f for f in self.feed_configs if f.enabled])
            
        except Exception as e:
            logger.error(f"Failed to load feed configurations: {e}")
            raise
            
    async def _create_default_config(self):
        """Create default threat intelligence feed configuration"""
        default_config = {
            "version": "1.0.0",
            "description": "iSECTECH SIEM Threat Intelligence Feeds Configuration",
            "threat_feeds": [
                {
                    "feed_name": "abuse_ch_malware_bazaar",
                    "feed_url": "https://bazaar.abuse.ch/export/csv/recent/",
                    "feed_type": "csv",
                    "confidence_weight": 0.9,
                    "update_interval_minutes": 60,
                    "enabled": True,
                    "description": "Abuse.ch Malware Bazaar - Recent malware samples"
                },
                {
                    "feed_name": "abuse_ch_threatfox",
                    "feed_url": "https://threatfox.abuse.ch/export/csv/recent/",
                    "feed_type": "csv",
                    "confidence_weight": 0.9,
                    "update_interval_minutes": 30,
                    "enabled": True,
                    "description": "Abuse.ch ThreatFox - IOCs from various sources"
                },
                {
                    "feed_name": "alienvault_otx",
                    "feed_url": "https://otx.alienvault.com/api/v1/indicators/export",
                    "feed_type": "json",
                    "api_key": "${OTX_API_KEY}",
                    "confidence_weight": 0.8,
                    "update_interval_minutes": 120,
                    "enabled": False,
                    "description": "AlienVault OTX - Community threat intelligence"
                },
                {
                    "feed_name": "emergingthreats_compromised",
                    "feed_url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
                    "feed_type": "txt",
                    "confidence_weight": 0.85,
                    "update_interval_minutes": 240,
                    "enabled": True,
                    "description": "Emerging Threats - Compromised IP addresses"
                },
                {
                    "feed_name": "malwaredomainlist",
                    "feed_url": "https://www.malwaredomainlist.com/hostslist/hosts.txt",
                    "feed_type": "txt",
                    "confidence_weight": 0.8,
                    "update_interval_minutes": 360,
                    "enabled": True,
                    "description": "Malware Domain List - Known malicious domains"
                },
                {
                    "feed_name": "isectech_internal",
                    "feed_url": "https://feeds.isectech.com/threat-intel/iocs.json",
                    "feed_type": "json",
                    "api_key": "${ISECTECH_FEED_API_KEY}",
                    "confidence_weight": 1.0,
                    "update_interval_minutes": 15,
                    "enabled": True,
                    "description": "iSECTECH Internal Threat Intelligence Feed"
                }
            ],
            "indicator_types": {
                "ip": {
                    "validation_regex": "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                    "default_ttl_hours": 24,
                    "max_indicators": 50000
                },
                "domain": {
                    "validation_regex": "^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.[a-zA-Z]{2,}$",
                    "default_ttl_hours": 48,
                    "max_indicators": 30000
                },
                "url": {
                    "validation_regex": "^https?://[^\\s/$.?#].[^\\s]*$",
                    "default_ttl_hours": 12,
                    "max_indicators": 20000
                },
                "hash": {
                    "validation_regex": "^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$",
                    "default_ttl_hours": 168,
                    "max_indicators": 100000
                },
                "email": {
                    "validation_regex": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                    "default_ttl_hours": 24,
                    "max_indicators": 10000
                }
            },
            "cleanup_policies": {
                "expired_indicator_cleanup": True,
                "cleanup_interval_hours": 6,
                "max_cache_size_mb": 500,
                "confidence_threshold": 30
            }
        }
        
        # Create directory if it doesn't exist
        config_path = Path(self.feeds_config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiofiles.open(self.feeds_config_file, 'w') as f:
            await f.write(yaml.dump(default_config, default_flow_style=False))
            
        logger.info(f"Created default threat intelligence feed configuration: {self.feeds_config_file}")
        
    def _generate_feed_name(self, feed_url: str) -> str:
        """Generate feed name from URL"""
        parsed = urlparse(feed_url)
        domain = parsed.netloc.replace("www.", "")
        return f"feed_{domain.replace('.', '_')}"
        
    async def _load_cached_indicators(self):
        """Load cached indicators from previous runs"""
        cache_file = Path(self.feeds_config_file).parent / "threat_indicators_cache.json"
        
        if cache_file.exists():
            try:
                async with aiofiles.open(cache_file, 'r') as f:
                    content = await f.read()
                    cached_data = json.loads(content)
                    
                # Load indicators and rebuild index
                for indicator_data in cached_data.get("indicators", []):
                    indicator = ThreatIndicator(
                        value=indicator_data["value"],
                        indicator_type=indicator_data["indicator_type"],
                        threat_type=indicator_data["threat_type"],
                        confidence_score=indicator_data["confidence_score"],
                        first_seen=datetime.fromisoformat(indicator_data["first_seen"]),
                        last_seen=datetime.fromisoformat(indicator_data["last_seen"]),
                        source=indicator_data["source"],
                        description=indicator_data["description"],
                        tags=indicator_data["tags"],
                        ttl_hours=indicator_data.get("ttl_hours", 24),
                        malware_family=indicator_data.get("malware_family", ""),
                        kill_chain_phase=indicator_data.get("kill_chain_phase", ""),
                        actor_group=indicator_data.get("actor_group", "")
                    )
                    
                    # Check if indicator is still valid (not expired)
                    if self._is_indicator_valid(indicator):
                        self._add_indicator_to_index(indicator)
                        
                logger.info(f"Loaded {len(self.indicators)} cached threat indicators")
                
            except Exception as e:
                logger.warning(f"Failed to load cached indicators: {e}")
                
    async def update_all_feeds(self) -> List[FeedUpdateResult]:
        """Update all enabled threat intelligence feeds"""
        update_tasks = []
        
        for feed_config in self.feed_configs:
            if feed_config.enabled:
                task = asyncio.create_task(self.update_feed(feed_config))
                update_tasks.append(task)
                
        results = await asyncio.gather(*update_tasks, return_exceptions=True)
        
        # Process results
        feed_results = []
        for result in results:
            if isinstance(result, FeedUpdateResult):
                feed_results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Feed update failed: {result}")
                self.stats["update_errors"] += 1
                
        # Update statistics
        self.stats["last_update"] = datetime.now(timezone.utc).isoformat()
        self._update_statistics()
        
        # Save updated indicators to cache
        await self._save_indicators_cache()
        
        return feed_results
        
    async def update_feed(self, feed_config: ThreatFeedConfig) -> FeedUpdateResult:
        """Update a single threat intelligence feed"""
        start_time = time.perf_counter()
        
        async with self._update_locks[feed_config.feed_name]:
            try:
                logger.info(f"Updating threat intelligence feed: {feed_config.feed_name}")
                
                # Download feed data
                feed_data = await self._download_feed(feed_config)
                if not feed_data:
                    return FeedUpdateResult(
                        feed_name=feed_config.feed_name,
                        success=False,
                        indicators_added=0,
                        indicators_updated=0,
                        indicators_removed=0,
                        total_indicators=0,
                        update_time_ms=0,
                        error_message="Failed to download feed data"
                    )
                    
                # Parse indicators from feed data
                new_indicators = await self._parse_feed_data(feed_data, feed_config)
                
                # Update indicator database
                added, updated, removed = await self._update_indicators(new_indicators, feed_config.feed_name)
                
                processing_time = (time.perf_counter() - start_time) * 1000
                
                # Update feed performance statistics
                self.stats["feed_performance"][feed_config.feed_name] = {
                    "last_update": datetime.now(timezone.utc).isoformat(),
                    "processing_time_ms": processing_time,
                    "indicators_count": len(new_indicators),
                    "success": True
                }
                
                return FeedUpdateResult(
                    feed_name=feed_config.feed_name,
                    success=True,
                    indicators_added=added,
                    indicators_updated=updated,
                    indicators_removed=removed,
                    total_indicators=len(new_indicators),
                    update_time_ms=processing_time
                )
                
            except Exception as e:
                processing_time = (time.perf_counter() - start_time) * 1000
                error_msg = str(e)
                
                logger.error(f"Failed to update feed {feed_config.feed_name}: {error_msg}")
                
                self.stats["feed_performance"][feed_config.feed_name] = {
                    "last_update": datetime.now(timezone.utc).isoformat(),
                    "processing_time_ms": processing_time,
                    "indicators_count": 0,
                    "success": False,
                    "error": error_msg
                }
                
                return FeedUpdateResult(
                    feed_name=feed_config.feed_name,
                    success=False,
                    indicators_added=0,
                    indicators_updated=0,
                    indicators_removed=0,
                    total_indicators=0,
                    update_time_ms=processing_time,
                    error_message=error_msg
                )
                
    async def _download_feed(self, feed_config: ThreatFeedConfig) -> Optional[str]:
        """Download threat intelligence feed data"""
        try:
            headers = {}
            if feed_config.api_key:
                headers["Authorization"] = f"Bearer {feed_config.api_key}"
                headers["X-API-Key"] = feed_config.api_key
                
            async with self.http_session.get(
                feed_config.feed_url,
                headers=headers,
                ssl=feed_config.verify_ssl,
                timeout=aiohttp.ClientTimeout(total=feed_config.timeout_seconds)
            ) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    logger.warning(f"Feed download failed with status {response.status}: {feed_config.feed_url}")
                    return None
                    
        except Exception as e:
            logger.error(f"Failed to download feed {feed_config.feed_name}: {e}")
            return None
            
    async def _parse_feed_data(self, feed_data: str, feed_config: ThreatFeedConfig) -> List[ThreatIndicator]:
        """Parse indicators from feed data based on feed type"""
        indicators = []
        
        try:
            if feed_config.feed_type == "json":
                indicators = await self._parse_json_feed(feed_data, feed_config)
            elif feed_config.feed_type == "csv":
                indicators = await self._parse_csv_feed(feed_data, feed_config)
            elif feed_config.feed_type == "txt":
                indicators = await self._parse_txt_feed(feed_data, feed_config)
            elif feed_config.feed_type == "stix":
                indicators = await self._parse_stix_feed(feed_data, feed_config)
            else:
                logger.warning(f"Unsupported feed type: {feed_config.feed_type}")
                
        except Exception as e:
            logger.error(f"Failed to parse feed data for {feed_config.feed_name}: {e}")
            
        return indicators[:feed_config.max_indicators]  # Limit indicators
        
    async def _parse_json_feed(self, feed_data: str, feed_config: ThreatFeedConfig) -> List[ThreatIndicator]:
        """Parse JSON format threat intelligence feed"""
        indicators = []
        
        try:
            data = json.loads(feed_data)
            
            # Handle different JSON structures
            if isinstance(data, list):
                indicator_list = data
            elif isinstance(data, dict):
                indicator_list = data.get("indicators", data.get("data", []))
            else:
                return indicators
                
            for item in indicator_list:
                if isinstance(item, dict):
                    indicator = self._create_indicator_from_dict(item, feed_config)
                    if indicator:
                        indicators.append(indicator)
                        
        except Exception as e:
            logger.error(f"JSON parsing error for {feed_config.feed_name}: {e}")
            
        return indicators
        
    async def _parse_csv_feed(self, feed_data: str, feed_config: ThreatFeedConfig) -> List[ThreatIndicator]:
        """Parse CSV format threat intelligence feed"""
        indicators = []
        
        try:
            # Handle CSV with different structures
            lines = feed_data.strip().split('\n')
            if not lines:
                return indicators
                
            # Try to detect if first line is header
            first_line = lines[0]
            has_header = any(header in first_line.lower() for header in ['indicator', 'ioc', 'value', 'type'])
            
            reader = csv.DictReader(lines) if has_header else None
            
            for i, line in enumerate(lines):
                if has_header and i == 0:
                    continue
                    
                if reader and i > 0:
                    # Use CSV reader for structured data
                    row = next(reader, None)
                    if row:
                        indicator = self._create_indicator_from_csv_row(row, feed_config)
                        if indicator:
                            indicators.append(indicator)
                else:
                    # Parse as simple text list
                    indicator = self._create_indicator_from_text(line.strip(), feed_config)
                    if indicator:
                        indicators.append(indicator)
                        
        except Exception as e:
            logger.error(f"CSV parsing error for {feed_config.feed_name}: {e}")
            
        return indicators
        
    async def _parse_txt_feed(self, feed_data: str, feed_config: ThreatFeedConfig) -> List[ThreatIndicator]:
        """Parse text format threat intelligence feed"""
        indicators = []
        
        try:
            lines = feed_data.strip().split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                    
                indicator = self._create_indicator_from_text(line, feed_config)
                if indicator:
                    indicators.append(indicator)
                    
        except Exception as e:
            logger.error(f"TXT parsing error for {feed_config.feed_name}: {e}")
            
        return indicators
        
    async def _parse_stix_feed(self, feed_data: str, feed_config: ThreatFeedConfig) -> List[ThreatIndicator]:
        """Parse STIX format threat intelligence feed"""
        # Placeholder for STIX parsing
        # In production, would use python-stix2 library
        indicators = []
        logger.warning(f"STIX parsing not implemented for {feed_config.feed_name}")
        return indicators
        
    def _create_indicator_from_dict(self, data: Dict[str, Any], feed_config: ThreatFeedConfig) -> Optional[ThreatIndicator]:
        """Create threat indicator from dictionary data"""
        try:
            # Extract indicator value
            value = data.get("indicator", data.get("value", data.get("ioc", "")))
            if not value:
                return None
                
            # Detect indicator type
            indicator_type = self._detect_indicator_type(value)
            if not indicator_type:
                return None
                
            # Extract other fields
            threat_type = data.get("threat_type", data.get("type", "unknown"))
            confidence = int(data.get("confidence", data.get("score", 50)) * feed_config.confidence_weight)
            description = data.get("description", f"{threat_type} indicator from {feed_config.feed_name}")
            tags = data.get("tags", [])
            
            # Parse timestamps
            first_seen = self._parse_timestamp(data.get("first_seen", data.get("created")))
            last_seen = self._parse_timestamp(data.get("last_seen", data.get("updated")))
            
            return ThreatIndicator(
                value=value,
                indicator_type=indicator_type,
                threat_type=threat_type,
                confidence_score=min(confidence, 100),
                first_seen=first_seen,
                last_seen=last_seen,
                source=feed_config.feed_name,
                description=description,
                tags=tags if isinstance(tags, list) else [tags],
                malware_family=data.get("malware_family", ""),
                kill_chain_phase=data.get("kill_chain_phase", ""),
                actor_group=data.get("actor_group", "")
            )
            
        except Exception as e:
            logger.warning(f"Failed to create indicator from dict: {e}")
            return None
            
    def _create_indicator_from_csv_row(self, row: Dict[str, str], feed_config: ThreatFeedConfig) -> Optional[ThreatIndicator]:
        """Create threat indicator from CSV row"""
        # Map common CSV column names
        value_fields = ['indicator', 'ioc', 'value', 'ip', 'domain', 'url', 'hash']
        value = None
        
        for field in value_fields:
            if field in row and row[field]:
                value = row[field].strip()
                break
                
        if not value:
            return None
            
        indicator_type = self._detect_indicator_type(value)
        if not indicator_type:
            return None
            
        # Create indicator with default values
        return ThreatIndicator(
            value=value,
            indicator_type=indicator_type,
            threat_type=row.get("threat_type", row.get("type", "malware")),
            confidence_score=min(int(float(row.get("confidence", "50")) * feed_config.confidence_weight), 100),
            first_seen=self._parse_timestamp(row.get("first_seen")),
            last_seen=self._parse_timestamp(row.get("last_seen")),
            source=feed_config.feed_name,
            description=row.get("description", f"Indicator from {feed_config.feed_name}"),
            tags=row.get("tags", "").split(",") if row.get("tags") else []
        )
        
    def _create_indicator_from_text(self, text: str, feed_config: ThreatFeedConfig) -> Optional[ThreatIndicator]:
        """Create threat indicator from plain text"""
        if not text:
            return None
            
        # Clean up the text (remove common prefixes/suffixes)
        text = text.strip()
        text = re.sub(r'^(https?://)?', '', text)  # Remove protocol
        text = re.sub(r'/.*$', '', text)  # Remove path for URLs
        
        indicator_type = self._detect_indicator_type(text)
        if not indicator_type:
            return None
            
        return ThreatIndicator(
            value=text,
            indicator_type=indicator_type,
            threat_type="malicious",
            confidence_score=int(70 * feed_config.confidence_weight),
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source=feed_config.feed_name,
            description=f"Malicious {indicator_type} from {feed_config.feed_name}",
            tags=["automated_feed"]
        )
        
    def _detect_indicator_type(self, value: str) -> Optional[str]:
        """Detect the type of threat indicator"""
        value = value.strip().lower()
        
        # IP address
        try:
            ipaddress.ip_address(value)
            return "ip"
        except ValueError:
            pass
            
        # Domain name
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}$', value):
            return "domain"
            
        # URL
        if re.match(r'^https?://[^\s/$.?#].[^\s]*$', value):
            return "url"
            
        # Hash (MD5, SHA1, SHA256)
        if re.match(r'^[a-fA-F0-9]{32}$', value):  # MD5
            return "hash"
        elif re.match(r'^[a-fA-F0-9]{40}$', value):  # SHA1
            return "hash"
        elif re.match(r'^[a-fA-F0-9]{64}$', value):  # SHA256
            return "hash"
            
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "email"
            
        return None
        
    def _parse_timestamp(self, timestamp_str: Optional[str]) -> datetime:
        """Parse timestamp from various formats"""
        if not timestamp_str:
            return datetime.now(timezone.utc)
            
        try:
            # Try ISO format first
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            pass
            
        # Try other common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%Y-%m-%d",
            "%d-%m-%Y"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
                
        # Default to current time
        return datetime.now(timezone.utc)
        
    async def _update_indicators(self, new_indicators: List[ThreatIndicator], feed_name: str) -> Tuple[int, int, int]:
        """Update indicator database with new indicators"""
        added = 0
        updated = 0
        removed = 0
        
        # Create a set of new indicator values for this feed
        new_values = {ind.value for ind in new_indicators}
        
        # Remove old indicators from this feed that are not in the new set
        to_remove = []
        for indicator_id, indicator in self.indicators.items():
            if (indicator.source == feed_name and 
                indicator.value not in new_values and 
                not self._is_indicator_valid(indicator)):
                to_remove.append(indicator_id)
                
        for indicator_id in to_remove:
            indicator = self.indicators[indicator_id]
            self._remove_indicator_from_index(indicator)
            del self.indicators[indicator_id]
            removed += 1
            
        # Add or update new indicators
        for indicator in new_indicators:
            indicator_id = self._generate_indicator_id(indicator)
            
            if indicator_id in self.indicators:
                # Update existing indicator
                existing = self.indicators[indicator_id]
                existing.last_seen = indicator.last_seen
                existing.confidence_score = max(existing.confidence_score, indicator.confidence_score)
                existing.tags = list(set(existing.tags + indicator.tags))
                updated += 1
            else:
                # Add new indicator
                self.indicators[indicator_id] = indicator
                self._add_indicator_to_index(indicator)
                added += 1
                
        return added, updated, removed
        
    def _generate_indicator_id(self, indicator: ThreatIndicator) -> str:
        """Generate unique ID for indicator"""
        data = f"{indicator.value}:{indicator.indicator_type}:{indicator.source}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
        
    def _add_indicator_to_index(self, indicator: ThreatIndicator):
        """Add indicator to search index"""
        if indicator.indicator_type in self.indicator_index:
            self.indicator_index[indicator.indicator_type].add(indicator.value)
            
    def _remove_indicator_from_index(self, indicator: ThreatIndicator):
        """Remove indicator from search index"""
        if indicator.indicator_type in self.indicator_index:
            self.indicator_index[indicator.indicator_type].discard(indicator.value)
            
    def _is_indicator_valid(self, indicator: ThreatIndicator) -> bool:
        """Check if indicator is still valid (not expired)"""
        if indicator.ttl_hours <= 0:
            return True  # No expiration
            
        expiry_time = indicator.last_seen + timedelta(hours=indicator.ttl_hours)
        return datetime.now(timezone.utc) < expiry_time
        
    def _update_statistics(self):
        """Update internal statistics"""
        self.stats["total_indicators"] = len(self.indicators)
        
        # Count by type
        type_counts = {}
        for indicator in self.indicators.values():
            type_counts[indicator.indicator_type] = type_counts.get(indicator.indicator_type, 0) + 1
            
        self.stats["indicators_by_type"] = type_counts
        
    async def _save_indicators_cache(self):
        """Save indicators to cache file"""
        try:
            cache_file = Path(self.feeds_config_file).parent / "threat_indicators_cache.json"
            
            cache_data = {
                "version": "1.0.0",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "indicators": [
                    {
                        "value": ind.value,
                        "indicator_type": ind.indicator_type,
                        "threat_type": ind.threat_type,
                        "confidence_score": ind.confidence_score,
                        "first_seen": ind.first_seen.isoformat(),
                        "last_seen": ind.last_seen.isoformat(),
                        "source": ind.source,
                        "description": ind.description,
                        "tags": ind.tags,
                        "ttl_hours": ind.ttl_hours,
                        "malware_family": ind.malware_family,
                        "kill_chain_phase": ind.kill_chain_phase,
                        "actor_group": ind.actor_group
                    }
                    for ind in self.indicators.values()
                    if self._is_indicator_valid(ind)  # Only save valid indicators
                ]
            }
            
            async with aiofiles.open(cache_file, 'w') as f:
                await f.write(json.dumps(cache_data, indent=2))
                
            logger.info(f"Saved {len(cache_data['indicators'])} indicators to cache")
            
        except Exception as e:
            logger.error(f"Failed to save indicators cache: {e}")
            
    async def lookup_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Look up a threat indicator by value"""
        # First check if the value exists in any index
        for indicator_type, values in self.indicator_index.items():
            if value in values:
                # Find the actual indicator
                for indicator in self.indicators.values():
                    if indicator.value == value and self._is_indicator_valid(indicator):
                        return indicator
                        
        return None
        
    async def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics"""
        return {
            **self.stats,
            "cache_size_mb": len(json.dumps([asdict(ind) for ind in self.indicators.values()])) / (1024 * 1024),
            "index_sizes": {itype: len(values) for itype, values in self.indicator_index.items()}
        }
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.http_session:
            await self.http_session.close()
            
        # Save final cache
        await self._save_indicators_cache()
        
        logger.info("Threat intelligence feed manager cleanup completed")

# Example usage
async def main():
    """Example usage of threat intelligence feed manager"""
    feed_manager = ThreatIntelligenceFeedManager("/opt/siem/enrichment/config/threat_feeds.yaml")
    await feed_manager.initialize()
    
    # Update all feeds
    results = await feed_manager.update_all_feeds()
    
    for result in results:
        print(f"Feed: {result.feed_name}")
        print(f"  Success: {result.success}")
        print(f"  Indicators added: {result.indicators_added}")
        print(f"  Processing time: {result.update_time_ms:.2f}ms")
        
    # Look up an indicator
    indicator = await feed_manager.lookup_indicator("203.0.113.100")
    if indicator:
        print(f"Found threat indicator: {indicator.value} ({indicator.threat_type})")
        
    # Get statistics
    stats = await feed_manager.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    await feed_manager.cleanup()

if __name__ == "__main__":
    asyncio.run(main())