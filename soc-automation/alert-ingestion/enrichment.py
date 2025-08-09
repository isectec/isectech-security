"""
Alert Enrichment Engine - Comprehensive alert context enhancement

Enriches normalized alerts with contextual information from multiple sources
including threat intelligence, asset inventory, user behavior, and geolocation data.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
import aiohttp
import geoip2.database
from geoip2.errors import AddressNotFoundError
import structlog

logger = structlog.get_logger(__name__)

class EnrichmentStatus(Enum):
    """Enrichment operation status"""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    NOT_FOUND = "not_found"

@dataclass
class EnrichmentResult:
    """Result of an enrichment operation"""
    service: str
    status: EnrichmentStatus
    data: Dict[str, Any]
    processing_time_ms: float
    error_message: Optional[str] = None

class AlertEnricher:
    """
    Comprehensive alert enrichment engine that adds contextual information
    from multiple sources to enhance security alert analysis.
    
    Enrichment sources:
    - Threat Intelligence (IOCs, reputation scores)
    - Asset Inventory (criticality, ownership, configuration)
    - User Context (behavior profiles, risk scores)
    - Geolocation (IP geolocation, ASN information)
    - Vulnerability Data (CVE information, patch status)
    - Historical Context (alert frequency, patterns)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Configuration
        self.timeout = self.config.get('timeout', 5.0)  # 5 seconds per enrichment
        self.parallel_enrichment = self.config.get('parallel_enrichment', True)
        self.max_concurrent = self.config.get('max_concurrent_enrichments', 10)
        self.cache_ttl = self.config.get('cache_ttl', 3600)  # 1 hour
        
        # External service configurations
        self.threat_intel_config = self.config.get('threat_intelligence', {})
        self.asset_db_config = self.config.get('asset_database', {})
        self.user_context_config = self.config.get('user_context', {})
        self.geoip_db_path = self.config.get('geoip_database', '/opt/geoip/GeoLite2-City.mmdb')
        
        # Initialize services
        self.geoip_reader = None
        self.http_session = None
        self.enrichment_cache = {}
        
        # Semaphore for concurrent enrichment limiting
        self.enrichment_semaphore = asyncio.Semaphore(self.max_concurrent)
        
        logger.info("AlertEnricher initialized",
                   parallel_enrichment=self.parallel_enrichment,
                   timeout=self.timeout,
                   max_concurrent=self.max_concurrent)
    
    async def initialize(self):
        """Initialize enrichment services"""
        try:
            # Initialize GeoIP database
            if self.geoip_db_path:
                try:
                    self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                    logger.info("GeoIP database loaded", path=self.geoip_db_path)
                except Exception as e:
                    logger.warning("Failed to load GeoIP database", error=str(e))
            
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(
                limit=100,
                limit_per_host=20,
                keepalive_timeout=30
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            self.http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'User-Agent': 'iSECTECH-SOC-Automation/1.0'}
            )
            
            logger.info("Alert enrichment services initialized")
            
        except Exception as e:
            logger.error("Failed to initialize enrichment services", error=str(e))
            raise
    
    async def close(self):
        """Close enrichment services"""
        if self.http_session:
            await self.http_session.close()
        
        if self.geoip_reader:
            self.geoip_reader.close()
        
        logger.info("Enrichment services closed")
    
    async def enrich(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich alert with contextual information from multiple sources
        
        Args:
            alert: Normalized alert dictionary
            
        Returns:
            Alert dictionary with enrichment data added
        """
        enrichment_start = datetime.now(timezone.utc)
        enriched_alert = alert.copy()
        enrichments = {}
        
        try:
            # Define enrichment tasks based on available data
            enrichment_tasks = []
            
            # IP-based enrichments
            source_ip = alert.get('source_ip')
            dest_ip = alert.get('destination_ip')
            
            if source_ip:
                enrichment_tasks.extend([
                    self._enrich_geolocation(source_ip, 'source'),
                    self._enrich_threat_intelligence_ip(source_ip, 'source'),
                    self._enrich_asn_information(source_ip, 'source')
                ])
            
            if dest_ip:
                enrichment_tasks.extend([
                    self._enrich_geolocation(dest_ip, 'destination'),
                    self._enrich_threat_intelligence_ip(dest_ip, 'destination'),
                    self._enrich_asn_information(dest_ip, 'destination')
                ])
            
            # Hostname-based enrichments
            hostname = alert.get('hostname')
            if hostname:
                enrichment_tasks.extend([
                    self._enrich_asset_information(hostname),
                    self._enrich_vulnerability_data(hostname)
                ])
            
            # User-based enrichments
            user = alert.get('user')
            if user:
                enrichment_tasks.append(
                    self._enrich_user_context(user)
                )
            
            # Hash/file-based enrichments
            file_hashes = self._extract_file_hashes(alert)
            for hash_value, hash_type in file_hashes:
                enrichment_tasks.append(
                    self._enrich_file_reputation(hash_value, hash_type)
                )
            
            # Domain-based enrichments
            domains = self._extract_domains(alert)
            for domain in domains:
                enrichment_tasks.extend([
                    self._enrich_domain_reputation(domain),
                    self._enrich_domain_whois(domain)
                ])
            
            # Historical context enrichment
            enrichment_tasks.append(
                self._enrich_historical_context(alert)
            )
            
            # Execute enrichments
            if self.parallel_enrichment:
                # Run enrichments in parallel
                results = await asyncio.gather(
                    *enrichment_tasks,
                    return_exceptions=True
                )
            else:
                # Run enrichments sequentially
                results = []
                for task in enrichment_tasks:
                    try:
                        result = await task
                        results.append(result)
                    except Exception as e:
                        results.append(e)
            
            # Process enrichment results
            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Enrichment task failed", error=str(result))
                    continue
                
                if isinstance(result, EnrichmentResult):
                    if result.status == EnrichmentStatus.SUCCESS:
                        enrichments[result.service] = result.data
                    elif result.status == EnrichmentStatus.PARTIAL:
                        enrichments[result.service] = result.data
                        logger.warning("Partial enrichment result",
                                     service=result.service,
                                     error=result.error_message)
            
            # Add enrichments to alert
            enriched_alert['enrichments'] = enrichments
            
            # Calculate enrichment summary
            processing_time = (datetime.now(timezone.utc) - enrichment_start).total_seconds() * 1000
            enrichment_summary = {
                'total_enrichments': len(enrichments),
                'successful_enrichments': len([r for r in results if isinstance(r, EnrichmentResult) and r.status == EnrichmentStatus.SUCCESS]),
                'failed_enrichments': len([r for r in results if isinstance(r, Exception) or (isinstance(r, EnrichmentResult) and r.status == EnrichmentStatus.FAILED)]),
                'processing_time_ms': processing_time,
                'timestamp': enrichment_start.isoformat()
            }
            
            enriched_alert['enrichment_summary'] = enrichment_summary
            
            logger.debug("Alert enrichment completed",
                        alert_id=alert.get('alert_id'),
                        enrichments=len(enrichments),
                        processing_time_ms=processing_time)
            
            return enriched_alert
            
        except Exception as e:
            logger.error("Alert enrichment failed",
                        alert_id=alert.get('alert_id'),
                        error=str(e))
            # Return original alert if enrichment fails
            return alert
    
    async def _enrich_geolocation(self, ip_address: str, ip_type: str) -> EnrichmentResult:
        """Enrich IP address with geolocation information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Check cache first
                cache_key = f"geoip:{ip_address}"
                if cache_key in self.enrichment_cache:
                    cached_data = self.enrichment_cache[cache_key]
                    if datetime.now(timezone.utc) - cached_data['timestamp'] < timedelta(seconds=self.cache_ttl):
                        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                        return EnrichmentResult(
                            service=f"geolocation_{ip_type}",
                            status=EnrichmentStatus.SUCCESS,
                            data=cached_data['data'],
                            processing_time_ms=processing_time
                        )
                
                if not self.geoip_reader:
                    return EnrichmentResult(
                        service=f"geolocation_{ip_type}",
                        status=EnrichmentStatus.FAILED,
                        data={},
                        processing_time_ms=0,
                        error_message="GeoIP database not available"
                    )
                
                try:
                    response = self.geoip_reader.city(ip_address)
                    
                    geo_data = {
                        'country': response.country.name,
                        'country_code': response.country.iso_code,
                        'city': response.city.name,
                        'latitude': float(response.location.latitude) if response.location.latitude else None,
                        'longitude': float(response.location.longitude) if response.location.longitude else None,
                        'timezone': response.location.time_zone,
                        'accuracy_radius': response.location.accuracy_radius,
                        'postal_code': response.postal.code
                    }
                    
                    # Cache the result
                    self.enrichment_cache[cache_key] = {
                        'data': geo_data,
                        'timestamp': datetime.now(timezone.utc)
                    }
                    
                    processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    
                    return EnrichmentResult(
                        service=f"geolocation_{ip_type}",
                        status=EnrichmentStatus.SUCCESS,
                        data=geo_data,
                        processing_time_ms=processing_time
                    )
                    
                except AddressNotFoundError:
                    processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                    return EnrichmentResult(
                        service=f"geolocation_{ip_type}",
                        status=EnrichmentStatus.NOT_FOUND,
                        data={},
                        processing_time_ms=processing_time,
                        error_message=f"No geolocation data for IP {ip_address}"
                    )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service=f"geolocation_{ip_type}",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_threat_intelligence_ip(self, ip_address: str, ip_type: str) -> EnrichmentResult:
        """Enrich IP address with threat intelligence data"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Check cache first
                cache_key = f"threat_intel_ip:{ip_address}"
                if cache_key in self.enrichment_cache:
                    cached_data = self.enrichment_cache[cache_key]
                    if datetime.now(timezone.utc) - cached_data['timestamp'] < timedelta(seconds=self.cache_ttl):
                        processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                        return EnrichmentResult(
                            service=f"threat_intelligence_{ip_type}",
                            status=EnrichmentStatus.SUCCESS,
                            data=cached_data['data'],
                            processing_time_ms=processing_time
                        )
                
                # Mock threat intelligence data (replace with real API calls)
                threat_data = {
                    'reputation_score': self._calculate_reputation_score(ip_address),
                    'threat_categories': self._get_threat_categories(ip_address),
                    'first_seen': self._get_first_seen_date(ip_address),
                    'last_seen': datetime.now(timezone.utc).isoformat(),
                    'is_malicious': self._is_ip_malicious(ip_address),
                    'sources': ['internal_feeds', 'community_feeds']
                }
                
                # Cache the result
                self.enrichment_cache[cache_key] = {
                    'data': threat_data,
                    'timestamp': datetime.now(timezone.utc)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service=f"threat_intelligence_{ip_type}",
                    status=EnrichmentStatus.SUCCESS,
                    data=threat_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service=f"threat_intelligence_{ip_type}",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_asn_information(self, ip_address: str, ip_type: str) -> EnrichmentResult:
        """Enrich IP address with ASN information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock ASN data (replace with real ASN database lookup)
                asn_data = {
                    'asn': self._get_asn_number(ip_address),
                    'organization': self._get_asn_organization(ip_address),
                    'network': self._get_network_range(ip_address),
                    'country': self._get_asn_country(ip_address)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service=f"asn_{ip_type}",
                    status=EnrichmentStatus.SUCCESS,
                    data=asn_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service=f"asn_{ip_type}",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_asset_information(self, hostname: str) -> EnrichmentResult:
        """Enrich hostname with asset inventory information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock asset data (replace with real CMDB/asset database query)
                asset_data = {
                    'asset_id': f"asset_{hash(hostname) % 10000:04d}",
                    'owner': self._get_asset_owner(hostname),
                    'criticality': self._get_asset_criticality(hostname),
                    'business_unit': self._get_business_unit(hostname),
                    'location': self._get_asset_location(hostname),
                    'os_type': self._get_os_type(hostname),
                    'last_seen': datetime.now(timezone.utc).isoformat(),
                    'services': self._get_running_services(hostname),
                    'compliance_status': self._get_compliance_status(hostname)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="asset_information",
                    status=EnrichmentStatus.SUCCESS,
                    data=asset_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="asset_information",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_user_context(self, username: str) -> EnrichmentResult:
        """Enrich username with user behavior and risk context"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock user context data (replace with real user behavior analytics)
                user_data = {
                    'user_id': f"user_{hash(username) % 10000:04d}",
                    'risk_score': self._calculate_user_risk_score(username),
                    'department': self._get_user_department(username),
                    'title': self._get_user_title(username),
                    'manager': self._get_user_manager(username),
                    'typical_locations': self._get_typical_locations(username),
                    'typical_hours': self._get_typical_hours(username),
                    'recent_activities': self._get_recent_activities(username),
                    'access_privileges': self._get_access_privileges(username),
                    'last_login': self._get_last_login(username)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="user_context",
                    status=EnrichmentStatus.SUCCESS,
                    data=user_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="user_context",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_vulnerability_data(self, hostname: str) -> EnrichmentResult:
        """Enrich asset with vulnerability information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock vulnerability data (replace with real vulnerability scanner integration)
                vuln_data = {
                    'critical_vulnerabilities': self._get_critical_vulns(hostname),
                    'high_vulnerabilities': self._get_high_vulns(hostname),
                    'total_vulnerabilities': self._get_total_vulns(hostname),
                    'last_scan_date': self._get_last_scan_date(hostname),
                    'patch_level': self._get_patch_level(hostname),
                    'compliance_score': self._get_vuln_compliance_score(hostname)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="vulnerability_data",
                    status=EnrichmentStatus.SUCCESS,
                    data=vuln_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="vulnerability_data",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_file_reputation(self, file_hash: str, hash_type: str) -> EnrichmentResult:
        """Enrich file hash with reputation information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock file reputation data (replace with VirusTotal or similar API)
                reputation_data = {
                    'hash': file_hash,
                    'hash_type': hash_type,
                    'reputation_score': self._calculate_file_reputation(file_hash),
                    'malware_families': self._get_malware_families(file_hash),
                    'detection_engines': self._get_detection_engines(file_hash),
                    'first_submission': self._get_first_submission_date(file_hash),
                    'last_analysis': datetime.now(timezone.utc).isoformat(),
                    'is_malicious': self._is_file_malicious(file_hash)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service=f"file_reputation_{hash_type}",
                    status=EnrichmentStatus.SUCCESS,
                    data=reputation_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service=f"file_reputation_{hash_type}",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_domain_reputation(self, domain: str) -> EnrichmentResult:
        """Enrich domain with reputation information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock domain reputation data
                domain_data = {
                    'domain': domain,
                    'reputation_score': self._calculate_domain_reputation(domain),
                    'category': self._get_domain_category(domain),
                    'is_malicious': self._is_domain_malicious(domain),
                    'creation_date': self._get_domain_creation_date(domain),
                    'dns_records': self._get_dns_records(domain),
                    'subdomains': self._get_subdomains(domain)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="domain_reputation",
                    status=EnrichmentStatus.SUCCESS,
                    data=domain_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="domain_reputation",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_domain_whois(self, domain: str) -> EnrichmentResult:
        """Enrich domain with WHOIS information"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock WHOIS data
                whois_data = {
                    'domain': domain,
                    'registrar': self._get_domain_registrar(domain),
                    'creation_date': self._get_domain_creation_date(domain),
                    'expiration_date': self._get_domain_expiration_date(domain),
                    'registrant_country': self._get_registrant_country(domain),
                    'name_servers': self._get_name_servers(domain)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="domain_whois",
                    status=EnrichmentStatus.SUCCESS,
                    data=whois_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="domain_whois",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    async def _enrich_historical_context(self, alert: Dict[str, Any]) -> EnrichmentResult:
        """Enrich alert with historical context and patterns"""
        start_time = datetime.now(timezone.utc)
        
        try:
            async with self.enrichment_semaphore:
                # Mock historical context data
                historical_data = {
                    'similar_alerts_24h': self._get_similar_alerts_count(alert, hours=24),
                    'similar_alerts_7d': self._get_similar_alerts_count(alert, hours=168),
                    'first_occurrence': self._get_first_occurrence(alert),
                    'frequency_score': self._calculate_frequency_score(alert),
                    'trend': self._get_alert_trend(alert),
                    'related_incidents': self._get_related_incidents(alert)
                }
                
                processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
                
                return EnrichmentResult(
                    service="historical_context",
                    status=EnrichmentStatus.SUCCESS,
                    data=historical_data,
                    processing_time_ms=processing_time
                )
                
        except Exception as e:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            return EnrichmentResult(
                service="historical_context",
                status=EnrichmentStatus.FAILED,
                data={},
                processing_time_ms=processing_time,
                error_message=str(e)
            )
    
    # Helper methods (mock implementations - replace with real data sources)
    
    def _extract_file_hashes(self, alert: Dict[str, Any]) -> List[tuple]:
        """Extract file hashes from alert data"""
        hashes = []
        
        # Look for common hash fields
        if 'file_hash' in alert:
            hashes.append((alert['file_hash'], 'unknown'))
        if 'md5' in alert:
            hashes.append((alert['md5'], 'md5'))
        if 'sha1' in alert:
            hashes.append((alert['sha1'], 'sha1'))
        if 'sha256' in alert:
            hashes.append((alert['sha256'], 'sha256'))
        
        # Extract from details or raw data
        for field in ['details', 'raw_data']:
            if field in alert and isinstance(alert[field], dict):
                for key, value in alert[field].items():
                    if 'hash' in key.lower() and isinstance(value, str) and len(value) in [32, 40, 64]:
                        hash_type = 'md5' if len(value) == 32 else ('sha1' if len(value) == 40 else 'sha256')
                        hashes.append((value, hash_type))
        
        return hashes
    
    def _extract_domains(self, alert: Dict[str, Any]) -> List[str]:
        """Extract domain names from alert data"""
        domains = []
        
        # Look for common domain fields
        if 'domain' in alert:
            domains.append(alert['domain'])
        if 'hostname' in alert and '.' in alert['hostname']:
            domains.append(alert['hostname'])
        
        # Extract from URLs
        if 'url' in alert:
            import re
            domain_match = re.search(r'https?://([^/]+)', alert['url'])
            if domain_match:
                domains.append(domain_match.group(1))
        
        return list(set(domains))  # Remove duplicates
    
    # Mock data generation methods (replace with real implementations)
    
    def _calculate_reputation_score(self, ip: str) -> int:
        """Mock reputation score calculation"""
        return hash(ip) % 100  # 0-99 score
    
    def _get_threat_categories(self, ip: str) -> List[str]:
        """Mock threat categories"""
        categories = ['malware', 'botnet', 'phishing', 'spam', 'scanner']
        return [categories[hash(ip) % len(categories)]]
    
    def _get_first_seen_date(self, ip: str) -> str:
        """Mock first seen date"""
        days_ago = hash(ip) % 365
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    
    def _is_ip_malicious(self, ip: str) -> bool:
        """Mock malicious IP detection"""
        return hash(ip) % 10 == 0  # 10% chance
    
    def _get_asn_number(self, ip: str) -> int:
        """Mock ASN number"""
        return hash(ip) % 65535
    
    def _get_asn_organization(self, ip: str) -> str:
        """Mock ASN organization"""
        orgs = ['Amazon', 'Google', 'Microsoft', 'Cloudflare', 'DigitalOcean']
        return orgs[hash(ip) % len(orgs)]
    
    def _get_network_range(self, ip: str) -> str:
        """Mock network range"""
        parts = ip.split('.')[:3]
        return f"{'.'.join(parts)}.0/24"
    
    def _get_asn_country(self, ip: str) -> str:
        """Mock ASN country"""
        countries = ['US', 'CA', 'UK', 'DE', 'FR', 'JP', 'AU']
        return countries[hash(ip) % len(countries)]
    
    def _get_asset_owner(self, hostname: str) -> str:
        """Mock asset owner"""
        owners = ['IT-Team', 'Dev-Team', 'QA-Team', 'Security-Team']
        return owners[hash(hostname) % len(owners)]
    
    def _get_asset_criticality(self, hostname: str) -> str:
        """Mock asset criticality"""
        levels = ['critical', 'high', 'medium', 'low']
        return levels[hash(hostname) % len(levels)]
    
    def _get_business_unit(self, hostname: str) -> str:
        """Mock business unit"""
        units = ['Engineering', 'Sales', 'Marketing', 'Finance', 'HR']
        return units[hash(hostname) % len(units)]
    
    def _get_asset_location(self, hostname: str) -> str:
        """Mock asset location"""
        locations = ['DC-East', 'DC-West', 'Cloud-AWS', 'Cloud-Azure', 'Remote']
        return locations[hash(hostname) % len(locations)]
    
    def _get_os_type(self, hostname: str) -> str:
        """Mock OS type"""
        os_types = ['Windows', 'Linux', 'macOS', 'FreeBSD']
        return os_types[hash(hostname) % len(os_types)]
    
    def _get_running_services(self, hostname: str) -> List[str]:
        """Mock running services"""
        services = ['web', 'ssh', 'database', 'mail', 'dns']
        return services[:hash(hostname) % 3 + 1]
    
    def _get_compliance_status(self, hostname: str) -> str:
        """Mock compliance status"""
        statuses = ['compliant', 'non-compliant', 'partially-compliant', 'unknown']
        return statuses[hash(hostname) % len(statuses)]
    
    def _calculate_user_risk_score(self, username: str) -> int:
        """Mock user risk score"""
        return hash(username) % 100
    
    def _get_user_department(self, username: str) -> str:
        """Mock user department"""
        departments = ['IT', 'Engineering', 'Sales', 'Marketing', 'Finance', 'HR']
        return departments[hash(username) % len(departments)]
    
    def _get_user_title(self, username: str) -> str:
        """Mock user title"""
        titles = ['Engineer', 'Manager', 'Director', 'Analyst', 'Specialist']
        return titles[hash(username) % len(titles)]
    
    def _get_user_manager(self, username: str) -> str:
        """Mock user manager"""
        return f"manager_{hash(username) % 100}"
    
    def _get_typical_locations(self, username: str) -> List[str]:
        """Mock typical user locations"""
        locations = ['Office-HQ', 'Office-Remote', 'Home', 'Branch-Office']
        return [locations[hash(username) % len(locations)]]
    
    def _get_typical_hours(self, username: str) -> str:
        """Mock typical working hours"""
        return "09:00-17:00"
    
    def _get_recent_activities(self, username: str) -> List[str]:
        """Mock recent user activities"""
        activities = ['login', 'file_access', 'email_send', 'system_admin']
        return activities[:hash(username) % 3 + 1]
    
    def _get_access_privileges(self, username: str) -> List[str]:
        """Mock user access privileges"""
        privileges = ['user', 'admin', 'power_user', 'guest']
        return [privileges[hash(username) % len(privileges)]]
    
    def _get_last_login(self, username: str) -> str:
        """Mock last login time"""
        hours_ago = hash(username) % 24
        return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    
    def _get_critical_vulns(self, hostname: str) -> int:
        """Mock critical vulnerability count"""
        return hash(hostname) % 5
    
    def _get_high_vulns(self, hostname: str) -> int:
        """Mock high vulnerability count"""
        return hash(hostname) % 10
    
    def _get_total_vulns(self, hostname: str) -> int:
        """Mock total vulnerability count"""
        return hash(hostname) % 50
    
    def _get_last_scan_date(self, hostname: str) -> str:
        """Mock last scan date"""
        days_ago = hash(hostname) % 7
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    
    def _get_patch_level(self, hostname: str) -> str:
        """Mock patch level"""
        levels = ['current', 'behind', 'critical_missing']
        return levels[hash(hostname) % len(levels)]
    
    def _get_vuln_compliance_score(self, hostname: str) -> int:
        """Mock vulnerability compliance score"""
        return hash(hostname) % 100
    
    def _calculate_file_reputation(self, file_hash: str) -> int:
        """Mock file reputation score"""
        return hash(file_hash) % 100
    
    def _get_malware_families(self, file_hash: str) -> List[str]:
        """Mock malware families"""
        families = ['trojan', 'ransomware', 'adware', 'spyware', 'rootkit']
        return [families[hash(file_hash) % len(families)]]
    
    def _get_detection_engines(self, file_hash: str) -> int:
        """Mock detection engine count"""
        return hash(file_hash) % 60  # Out of 60 engines
    
    def _get_first_submission_date(self, file_hash: str) -> str:
        """Mock first submission date"""
        days_ago = hash(file_hash) % 365
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    
    def _is_file_malicious(self, file_hash: str) -> bool:
        """Mock file maliciousness detection"""
        return hash(file_hash) % 10 == 0  # 10% chance
    
    def _calculate_domain_reputation(self, domain: str) -> int:
        """Mock domain reputation score"""
        return hash(domain) % 100
    
    def _get_domain_category(self, domain: str) -> str:
        """Mock domain category"""
        categories = ['business', 'education', 'entertainment', 'news', 'shopping', 'suspicious']
        return categories[hash(domain) % len(categories)]
    
    def _is_domain_malicious(self, domain: str) -> bool:
        """Mock domain maliciousness detection"""
        return hash(domain) % 20 == 0  # 5% chance
    
    def _get_domain_creation_date(self, domain: str) -> str:
        """Mock domain creation date"""
        days_ago = hash(domain) % 3650  # Up to 10 years ago
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    
    def _get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Mock DNS records"""
        return {
            'A': ['1.2.3.4'],
            'MX': ['mail.example.com'],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }
    
    def _get_subdomains(self, domain: str) -> List[str]:
        """Mock subdomains"""
        return [f"www.{domain}", f"mail.{domain}"]
    
    def _get_domain_registrar(self, domain: str) -> str:
        """Mock domain registrar"""
        registrars = ['GoDaddy', 'Namecheap', 'Google Domains', 'CloudFlare']
        return registrars[hash(domain) % len(registrars)]
    
    def _get_domain_expiration_date(self, domain: str) -> str:
        """Mock domain expiration date"""
        days_ahead = hash(domain) % 365
        return (datetime.now(timezone.utc) + timedelta(days=days_ahead)).isoformat()
    
    def _get_registrant_country(self, domain: str) -> str:
        """Mock registrant country"""
        countries = ['US', 'CA', 'UK', 'DE', 'FR', 'AU']
        return countries[hash(domain) % len(countries)]
    
    def _get_name_servers(self, domain: str) -> List[str]:
        """Mock name servers"""
        return [f"ns1.{domain}", f"ns2.{domain}"]
    
    def _get_similar_alerts_count(self, alert: Dict[str, Any], hours: int) -> int:
        """Mock similar alerts count"""
        alert_sig = f"{alert.get('alert_type', '')}{alert.get('source_ip', '')}"
        return hash(alert_sig) % 50
    
    def _get_first_occurrence(self, alert: Dict[str, Any]) -> str:
        """Mock first occurrence of similar alert"""
        alert_sig = f"{alert.get('alert_type', '')}{alert.get('source_ip', '')}"
        days_ago = hash(alert_sig) % 30
        return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    
    def _calculate_frequency_score(self, alert: Dict[str, Any]) -> float:
        """Mock frequency score calculation"""
        alert_sig = f"{alert.get('alert_type', '')}{alert.get('source_ip', '')}"
        return (hash(alert_sig) % 100) / 10.0  # 0.0 to 9.9
    
    def _get_alert_trend(self, alert: Dict[str, Any]) -> str:
        """Mock alert trend"""
        trends = ['increasing', 'decreasing', 'stable', 'spike']
        alert_sig = f"{alert.get('alert_type', '')}{alert.get('source_ip', '')}"
        return trends[hash(alert_sig) % len(trends)]
    
    def _get_related_incidents(self, alert: Dict[str, Any]) -> List[str]:
        """Mock related incidents"""
        alert_sig = f"{alert.get('alert_type', '')}{alert.get('source_ip', '')}"
        incident_count = hash(alert_sig) % 3
        return [f"INC-{hash(alert_sig + str(i)) % 10000:04d}" for i in range(incident_count)]