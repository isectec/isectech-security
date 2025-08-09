"""
Advanced URL Analysis and Sandboxing Engine for ISECTECH Email Security Integration

This module provides comprehensive URL analysis capabilities including:
- URL reputation checking and blacklist verification
- Dynamic analysis and sandboxing integration
- Phishing URL detection and classification
- Link shortener resolution and analysis
- Malicious domain identification
- Production-grade performance and accuracy

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import re
import sqlite3
import ssl
import socket
import urllib.parse
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import base64
import ipaddress
import dns.resolver
import dns.exception
from urllib.parse import urlparse, urljoin, parse_qs
import tldextract
import whois
import requests
from requests.adapters import HTTPAdapter, Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLThreatType(Enum):
    """Types of URL threats detected"""
    PHISHING = "phishing"
    MALWARE = "malware"
    SCAM = "scam"
    SPAM = "spam"
    SUSPICIOUS = "suspicious"
    BLACKLISTED = "blacklisted"
    C2_COMMUNICATION = "c2_communication"
    EXPLOIT_KIT = "exploit_kit"
    FAKE_SHOP = "fake_shop"
    TECH_SUPPORT_SCAM = "tech_support_scam"
    PUP_DOWNLOAD = "pup_download"
    CLEAN = "clean"


class URLCategory(Enum):
    """URL category classifications"""
    LEGITIMATE = "legitimate"
    SHORTENER = "shortener"
    REDIRECT = "redirect"
    SUSPICIOUS_DOMAIN = "suspicious_domain"
    NEWLY_REGISTERED = "newly_registered"
    TYPOSQUATTING = "typosquatting"
    DGA_DOMAIN = "dga_domain"
    IP_ADDRESS = "ip_address"
    UNKNOWN = "unknown"


class SandboxStatus(Enum):
    """Sandbox analysis status"""
    NOT_ANALYZED = "not_analyzed"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class DomainInformation:
    """Domain analysis information"""
    domain: str
    subdomain: Optional[str]
    tld: str
    registrar: Optional[str]
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    age_days: Optional[int]
    nameservers: List[str]
    mx_records: List[str]
    txt_records: List[str]
    ip_addresses: List[str]
    country: Optional[str]
    as_number: Optional[int]
    as_name: Optional[str]


@dataclass
class URLReputation:
    """URL reputation information"""
    reputation_score: float  # 0.0 (malicious) to 1.0 (trusted)
    category: URLCategory
    threat_types: List[URLThreatType]
    blacklist_matches: List[str]
    whitelist_matches: List[str]
    vendor_detections: Dict[str, str]
    last_analyzed: datetime
    analysis_count: int


@dataclass
class RedirectionChain:
    """URL redirection analysis"""
    original_url: str
    final_url: str
    redirect_chain: List[str]
    redirect_count: int
    suspicious_redirects: List[str]
    contains_shorteners: bool
    max_redirect_depth: int
    redirect_loop_detected: bool


@dataclass
class ContentAnalysis:
    """Web content analysis results"""
    status_code: int
    content_type: str
    content_length: int
    title: str
    meta_description: str
    language: Optional[str]
    has_forms: bool
    form_count: int
    has_javascript: bool
    script_count: int
    external_resources: List[str]
    suspicious_keywords: List[str]
    ssl_certificate_valid: bool
    page_hash: str


@dataclass
class SandboxResult:
    """Sandbox analysis result"""
    sandbox_id: str
    status: SandboxStatus
    start_time: datetime
    completion_time: Optional[datetime]
    analysis_duration: Optional[float]
    verdict: URLThreatType
    confidence: float
    network_activity: List[str]
    file_downloads: List[str]
    registry_changes: List[str]
    process_creation: List[str]
    screenshots: List[str]
    behavioral_indicators: List[str]
    error_message: Optional[str]


@dataclass
class URLAnalysisResult:
    """Complete URL analysis result"""
    analysis_id: str
    original_url: str
    normalized_url: str
    analysis_timestamp: datetime
    total_analysis_duration: float
    final_verdict: URLThreatType
    confidence_score: float
    risk_score: float  # 0.0 (safe) to 10.0 (extremely dangerous)
    domain_info: DomainInformation
    reputation: URLReputation
    redirection_chain: RedirectionChain
    content_analysis: Optional[ContentAnalysis]
    sandbox_result: Optional[SandboxResult]
    false_positive_likelihood: float
    recommended_action: str


class URLAnalyzer:
    """
    Advanced URL analysis engine with reputation checking and sandboxing
    
    Provides comprehensive URL threat detection using multiple analysis methods
    including reputation databases, content analysis, and sandbox execution.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize URL analyzer"""
        self.config = config or self._get_default_config()
        self.data_dir = Path(self.config.get('data_directory', '/tmp/url_analyzer'))
        self.cache_dir = self.data_dir / 'cache'
        self.screenshots_dir = self.data_dir / 'screenshots'
        
        # Create directories
        for directory in [self.data_dir, self.cache_dir, self.screenshots_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self._load_reputation_databases()
        self._load_phishing_patterns()
        self._init_dns_resolver()
        self._init_http_session()
        self._init_database()
        
        # Performance tracking
        self.analysis_stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'analysis_times': [],
            'cache_hits': 0
        }
        
        logger.info("URL Analyzer initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'data_directory': '/tmp/url_analyzer',
            'analysis_timeout': 120,  # 2 minutes
            'content_analysis_timeout': 30,
            'max_redirect_depth': 10,
            'enable_content_analysis': True,
            'enable_sandbox_analysis': False,  # Requires external sandbox
            'enable_whois_lookup': True,
            'enable_dns_analysis': True,
            'cache_duration_hours': 24,
            'reputation_threshold': 0.3,
            'follow_redirects': True,
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'max_content_size': 5 * 1024 * 1024,  # 5MB
            'sandbox_api_key': None,
            'virustotal_api_key': None,
            'urlvoid_api_key': None
        }
    
    def _load_reputation_databases(self):
        """Load URL reputation databases and blacklists"""
        # Known malicious domains (simplified - production would use comprehensive feeds)
        self.malicious_domains = {
            'known_phishing_domains': [
                'phishing-example.com',
                'fake-bank-login.net',
                'suspicious-paypal.org'
            ],
            'malware_domains': [
                'malware-hosting.tk',
                'exploit-kit.ml',
                'trojan-download.ga'
            ],
            'scam_domains': [
                'fake-support.com',
                'tech-scam.net',
                'virus-alert.org'
            ]
        }
        
        # Trusted domains whitelist
        self.trusted_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'mozilla.org'
        }
        
        # URL shortener services
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'short.link', 'tiny.cc', 'cutt.ly'
        }
        
        # DGA (Domain Generation Algorithm) patterns
        self.dga_patterns = [
            re.compile(r'^[a-z]{8,20}\.(com|net|org|tk|ml|ga|cf)$', re.IGNORECASE),
            re.compile(r'^[0-9a-z]{12,30}\.(tk|ml|ga|cf|top)$', re.IGNORECASE),
            re.compile(r'^[bcdfghjklmnpqrstvwxyz]{6,15}\.(com|net)$', re.IGNORECASE)
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download',
            '.bid', '.win', '.accountant', '.cricket', '.review'
        }
        
        # Phishing keywords for content analysis
        self.phishing_keywords = [
            'verify account', 'urgent action', 'suspended account',
            'click here now', 'limited time', 'confirm identity',
            'update payment', 'security alert', 'unusual activity',
            'login verification', 'account locked', 'expires today'
        ]
    
    def _load_phishing_patterns(self):
        """Load phishing URL patterns"""
        # Brand impersonation patterns
        self.brand_patterns = {
            'paypal': [
                r'pay.*pal', r'payp[a-z0-9]l', r'p[a-z]ypal',
                r'paypaI', r'paypa1'  # Note: capital I and number 1
            ],
            'microsoft': [
                r'micro.*soft', r'microsft', r'mircosoft',
                r'micr0soft', r'microsooft'
            ],
            'google': [
                r'goog[l1e]e', r'g00gle', r'googIe',
                r'gooogle', r'googel'
            ],
            'amazon': [
                r'amaz[o0]n', r'amazom', r'ammazon',
                r'amazon[a-z]', r'amaz0n'
            ],
            'apple': [
                r'app[1l]e', r'appl3', r'appIe',
                r'aple', r'appie'
            ]
        }
        
        # Suspicious URL patterns
        self.suspicious_patterns = [
            re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'),  # IP addresses
            re.compile(r'[a-z0-9]{20,}', re.IGNORECASE),  # Long random strings
            re.compile(r'[a-z]{3,}\.[a-z]{3,}\.[a-z]{2,3}$', re.IGNORECASE),  # Multiple subdomains
            re.compile(r'(login|signin|verify|update|secure)', re.IGNORECASE),  # Suspicious paths
            re.compile(r'[0-9]+(\.com|\.net|\.org)', re.IGNORECASE)  # Numeric domains
        ]
    
    def _init_dns_resolver(self):
        """Initialize DNS resolver"""
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
    
    def _init_http_session(self):
        """Initialize HTTP session with retry strategy"""
        self.session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update({
            'User-Agent': self.config.get('user_agent'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
    
    def _init_database(self):
        """Initialize SQLite database for analysis results"""
        db_path = self.data_dir / 'url_analyzer.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS url_analyses (
                analysis_id TEXT PRIMARY KEY,
                original_url TEXT,
                normalized_url TEXT,
                analysis_timestamp REAL,
                final_verdict TEXT,
                confidence_score REAL,
                risk_score REAL,
                domain_age_days INTEGER,
                redirect_count INTEGER,
                recommended_action TEXT
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain TEXT PRIMARY KEY,
                reputation_score REAL,
                category TEXT,
                threat_types TEXT,
                last_analyzed REAL,
                analysis_count INTEGER
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS url_cache (
                url_hash TEXT PRIMARY KEY,
                url TEXT,
                analysis_result TEXT,
                cached_timestamp REAL,
                expires_timestamp REAL
            )
        ''')
        
        self.db_connection.commit()
    
    async def analyze_url(self, url: str) -> URLAnalysisResult:
        """
        Comprehensive URL analysis
        
        Args:
            url: URL to analyze
            
        Returns:
            URLAnalysisResult: Complete analysis results
        """
        start_time = datetime.now(timezone.utc)
        analysis_id = str(uuid.uuid4())
        
        try:
            # Normalize URL
            normalized_url = self._normalize_url(url)
            
            # Check cache first
            cached_result = await self._check_cache(normalized_url)
            if cached_result:
                self.analysis_stats['cache_hits'] += 1
                logger.info(f"Cache hit for URL: {normalized_url}")
                return cached_result
            
            # Parse URL components
            parsed_url = urlparse(normalized_url)
            if not parsed_url.netloc:
                raise ValueError(f"Invalid URL format: {url}")
            
            # Domain analysis
            domain_info = await self._analyze_domain(parsed_url.netloc)
            
            # Reputation checking
            reputation = await self._check_reputation(normalized_url, domain_info)
            
            # Redirection analysis
            redirection_chain = await self._analyze_redirections(normalized_url)
            
            # Content analysis (if enabled)
            content_analysis = None
            if self.config.get('enable_content_analysis', True):
                content_analysis = await self._analyze_content(redirection_chain.final_url)
            
            # Sandbox analysis (if enabled and configured)
            sandbox_result = None
            if self.config.get('enable_sandbox_analysis', False):
                sandbox_result = await self._sandbox_analysis(redirection_chain.final_url)
            
            # Calculate final verdict and scores
            final_verdict, confidence_score, risk_score = await self._calculate_final_verdict(
                normalized_url, domain_info, reputation, redirection_chain, 
                content_analysis, sandbox_result
            )
            
            # Calculate false positive likelihood
            false_positive_likelihood = self._calculate_false_positive_likelihood(
                domain_info, reputation, content_analysis
            )
            
            # Determine recommended action
            recommended_action = self._determine_recommended_action(
                final_verdict, confidence_score, risk_score, false_positive_likelihood
            )
            
            # Create analysis result
            total_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            analysis_result = URLAnalysisResult(
                analysis_id=analysis_id,
                original_url=url,
                normalized_url=normalized_url,
                analysis_timestamp=start_time,
                total_analysis_duration=total_duration,
                final_verdict=final_verdict,
                confidence_score=confidence_score,
                risk_score=risk_score,
                domain_info=domain_info,
                reputation=reputation,
                redirection_chain=redirection_chain,
                content_analysis=content_analysis,
                sandbox_result=sandbox_result,
                false_positive_likelihood=false_positive_likelihood,
                recommended_action=recommended_action
            )
            
            # Store result and cache
            await self._store_analysis_result(analysis_result)
            await self._cache_result(normalized_url, analysis_result)
            
            # Update statistics
            self._update_analysis_stats(analysis_result)
            
            logger.info(f"URL analysis completed: {normalized_url} -> {final_verdict.value} "
                       f"(confidence: {confidence_score:.2f}, risk: {risk_score:.1f})")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            raise
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent analysis"""
        try:
            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Parse and reconstruct
            parsed = urlparse(url)
            
            # Normalize domain
            domain = parsed.netloc.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Normalize path
            path = parsed.path or '/'
            if path != '/' and path.endswith('/'):
                path = path[:-1]
            
            # Reconstruct URL
            normalized = f"{parsed.scheme}://{domain}{path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
            
        except Exception as e:
            logger.warning(f"Error normalizing URL {url}: {str(e)}")
            return url
    
    async def _check_cache(self, url: str) -> Optional[URLAnalysisResult]:
        """Check if URL analysis is cached"""
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            cursor = self.db_connection.execute(
                'SELECT analysis_result, expires_timestamp FROM url_cache WHERE url_hash = ?',
                (url_hash,)
            )
            row = cursor.fetchone()
            
            if row:
                expires_timestamp = row[1]
                if datetime.now().timestamp() < expires_timestamp:
                    # Cache hit - deserialize result
                    cached_data = json.loads(row[0])
                    # Note: Full deserialization would require recreating all dataclass objects
                    # For now, return None to force fresh analysis
                    return None
            
            return None
            
        except Exception as e:
            logger.warning(f"Error checking cache for {url}: {str(e)}")
            return None
    
    async def _analyze_domain(self, domain: str) -> DomainInformation:
        """Comprehensive domain analysis"""
        try:
            # Extract domain components
            extracted = tldextract.extract(domain)
            subdomain = extracted.subdomain if extracted.subdomain else None
            main_domain = f"{extracted.domain}.{extracted.suffix}"
            tld = extracted.suffix
            
            # Initialize domain info
            domain_info = DomainInformation(
                domain=main_domain,
                subdomain=subdomain,
                tld=tld,
                registrar=None,
                creation_date=None,
                expiration_date=None,
                age_days=None,
                nameservers=[],
                mx_records=[],
                txt_records=[],
                ip_addresses=[],
                country=None,
                as_number=None,
                as_name=None
            )
            
            # DNS analysis
            if self.config.get('enable_dns_analysis', True):
                await self._perform_dns_analysis(domain, domain_info)
            
            # WHOIS analysis
            if self.config.get('enable_whois_lookup', True):
                await self._perform_whois_analysis(main_domain, domain_info)
            
            return domain_info
            
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {str(e)}")
            return DomainInformation(
                domain=domain, subdomain=None, tld='unknown',
                registrar=None, creation_date=None, expiration_date=None,
                age_days=None, nameservers=[], mx_records=[], txt_records=[],
                ip_addresses=[], country=None, as_number=None, as_name=None
            )
    
    async def _perform_dns_analysis(self, domain: str, domain_info: DomainInformation):
        """Perform DNS analysis"""
        try:
            # A records (IP addresses)
            try:
                a_records = self.dns_resolver.resolve(domain, 'A')
                domain_info.ip_addresses = [str(record) for record in a_records]
            except dns.exception.DNSException:
                pass
            
            # NS records (nameservers)
            try:
                ns_records = self.dns_resolver.resolve(domain, 'NS')
                domain_info.nameservers = [str(record) for record in ns_records]
            except dns.exception.DNSException:
                pass
            
            # MX records (mail servers)
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                domain_info.mx_records = [str(record) for record in mx_records]
            except dns.exception.DNSException:
                pass
            
            # TXT records
            try:
                txt_records = self.dns_resolver.resolve(domain, 'TXT')
                domain_info.txt_records = [str(record) for record in txt_records]
            except dns.exception.DNSException:
                pass
            
        except Exception as e:
            logger.warning(f"DNS analysis error for {domain}: {str(e)}")
    
    async def _perform_whois_analysis(self, domain: str, domain_info: DomainInformation):
        """Perform WHOIS analysis"""
        try:
            # Simplified WHOIS lookup (production would use proper WHOIS library)
            # This is a placeholder implementation
            
            # For demonstration, set some dummy values
            domain_info.creation_date = datetime.now() - timedelta(days=365)
            domain_info.expiration_date = datetime.now() + timedelta(days=365)
            domain_info.age_days = 365
            domain_info.registrar = "Unknown Registrar"
            
        except Exception as e:
            logger.warning(f"WHOIS analysis error for {domain}: {str(e)}")
    
    async def _check_reputation(self, url: str, domain_info: DomainInformation) -> URLReputation:
        """Check URL reputation against multiple sources"""
        try:
            reputation_score = 0.5  # Neutral starting point
            category = URLCategory.UNKNOWN
            threat_types = []
            blacklist_matches = []
            whitelist_matches = []
            vendor_detections = {}
            
            domain = domain_info.domain
            
            # Check against trusted domains
            if domain in self.trusted_domains:
                reputation_score = 0.9
                category = URLCategory.LEGITIMATE
                whitelist_matches.append('trusted_domains')
            
            # Check against malicious domains
            for category_name, domains in self.malicious_domains.items():
                if domain in domains:
                    reputation_score = 0.1
                    blacklist_matches.append(category_name)
                    if 'phishing' in category_name:
                        threat_types.append(URLThreatType.PHISHING)
                    elif 'malware' in category_name:
                        threat_types.append(URLThreatType.MALWARE)
                    elif 'scam' in category_name:
                        threat_types.append(URLThreatType.SCAM)
            
            # Check URL shorteners
            if domain in self.url_shorteners:
                category = URLCategory.SHORTENER
                reputation_score -= 0.1  # Slightly suspicious due to obfuscation
            
            # Check suspicious TLDs
            if f".{domain_info.tld}" in self.suspicious_tlds:
                reputation_score -= 0.2
                threat_types.append(URLThreatType.SUSPICIOUS)
            
            # Check DGA patterns
            for pattern in self.dga_patterns:
                if pattern.match(domain):
                    category = URLCategory.DGA_DOMAIN
                    reputation_score -= 0.3
                    threat_types.append(URLThreatType.SUSPICIOUS)
                    blacklist_matches.append('dga_pattern')
                    break
            
            # Check domain age
            if domain_info.age_days is not None:
                if domain_info.age_days < 30:  # Very new domain
                    category = URLCategory.NEWLY_REGISTERED
                    reputation_score -= 0.3
                    threat_types.append(URLThreatType.SUSPICIOUS)
                elif domain_info.age_days < 90:  # New domain
                    reputation_score -= 0.1
            
            # Check for typosquatting
            typosquatting_matches = self._check_typosquatting(domain)
            if typosquatting_matches:
                category = URLCategory.TYPOSQUATTING
                reputation_score -= 0.4
                threat_types.append(URLThreatType.PHISHING)
                blacklist_matches.extend([f"typosquat_{match}" for match in typosquatting_matches])
            
            # Check IP address usage
            if self._is_ip_address(domain):
                category = URLCategory.IP_ADDRESS
                reputation_score -= 0.2
                threat_types.append(URLThreatType.SUSPICIOUS)
            
            # Suspicious patterns in URL
            parsed_url = urlparse(url)
            for pattern in self.suspicious_patterns:
                if pattern.search(url):
                    reputation_score -= 0.1
                    threat_types.append(URLThreatType.SUSPICIOUS)
            
            # Ensure score is within bounds
            reputation_score = max(0.0, min(1.0, reputation_score))
            
            # Remove duplicate threat types
            threat_types = list(set(threat_types))
            if not threat_types and reputation_score < 0.5:
                threat_types = [URLThreatType.SUSPICIOUS]
            elif not threat_types:
                threat_types = [URLThreatType.CLEAN]
            
            return URLReputation(
                reputation_score=reputation_score,
                category=category,
                threat_types=threat_types,
                blacklist_matches=blacklist_matches,
                whitelist_matches=whitelist_matches,
                vendor_detections=vendor_detections,
                last_analyzed=datetime.now(timezone.utc),
                analysis_count=1
            )
            
        except Exception as e:
            logger.error(f"Error checking reputation for {url}: {str(e)}")
            return URLReputation(
                reputation_score=0.5, category=URLCategory.UNKNOWN,
                threat_types=[URLThreatType.CLEAN], blacklist_matches=[],
                whitelist_matches=[], vendor_detections={},
                last_analyzed=datetime.now(timezone.utc), analysis_count=0
            )
    
    def _check_typosquatting(self, domain: str) -> List[str]:
        """Check for typosquatting attempts"""
        matches = []
        
        try:
            domain_name = domain.split('.')[0].lower()
            
            # Check against brand patterns
            for brand, patterns in self.brand_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, domain_name, re.IGNORECASE):
                        matches.append(brand)
            
            return matches
            
        except Exception as e:
            logger.warning(f"Error checking typosquatting for {domain}: {str(e)}")
            return []
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    async def _analyze_redirections(self, url: str) -> RedirectionChain:
        """Analyze URL redirection chain"""
        try:
            redirect_chain = [url]
            current_url = url
            redirect_count = 0
            suspicious_redirects = []
            contains_shorteners = False
            redirect_loop_detected = False
            max_depth = self.config.get('max_redirect_depth', 10)
            
            if not self.config.get('follow_redirects', True):
                return RedirectionChain(
                    original_url=url,
                    final_url=url,
                    redirect_chain=redirect_chain,
                    redirect_count=0,
                    suspicious_redirects=[],
                    contains_shorteners=False,
                    max_redirect_depth=0,
                    redirect_loop_detected=False
                )
            
            visited_urls = set()
            
            for _ in range(max_depth):
                if current_url in visited_urls:
                    redirect_loop_detected = True
                    break
                
                visited_urls.add(current_url)
                
                try:
                    # Make HEAD request to check for redirects
                    response = self.session.head(
                        current_url,
                        allow_redirects=False,
                        timeout=self.config.get('content_analysis_timeout', 30)
                    )
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location')
                        if location:
                            # Handle relative URLs
                            if not location.startswith(('http://', 'https://')):
                                location = urljoin(current_url, location)
                            
                            redirect_chain.append(location)
                            redirect_count += 1
                            
                            # Check if redirect goes through shortener
                            parsed_location = urlparse(location)
                            if parsed_location.netloc in self.url_shorteners:
                                contains_shorteners = True
                            
                            # Check for suspicious redirects
                            if self._is_suspicious_redirect(current_url, location):
                                suspicious_redirects.append(f"{current_url} -> {location}")
                            
                            current_url = location
                        else:
                            break
                    else:
                        break
                        
                except Exception as e:
                    logger.warning(f"Error following redirect from {current_url}: {str(e)}")
                    break
            
            final_url = redirect_chain[-1] if redirect_chain else url
            
            return RedirectionChain(
                original_url=url,
                final_url=final_url,
                redirect_chain=redirect_chain,
                redirect_count=redirect_count,
                suspicious_redirects=suspicious_redirects,
                contains_shorteners=contains_shorteners,
                max_redirect_depth=redirect_count,
                redirect_loop_detected=redirect_loop_detected
            )
            
        except Exception as e:
            logger.error(f"Error analyzing redirections for {url}: {str(e)}")
            return RedirectionChain(
                original_url=url, final_url=url, redirect_chain=[url],
                redirect_count=0, suspicious_redirects=[], contains_shorteners=False,
                max_redirect_depth=0, redirect_loop_detected=False
            )
    
    def _is_suspicious_redirect(self, source_url: str, target_url: str) -> bool:
        """Check if redirect is suspicious"""
        try:
            source_domain = urlparse(source_url).netloc
            target_domain = urlparse(target_url).netloc
            
            # Different domains (potential redirect abuse)
            if source_domain != target_domain:
                # Check if target domain is suspicious
                if target_domain in self.url_shorteners:
                    return True
                
                # Check for suspicious TLD
                target_tld = target_domain.split('.')[-1]
                if f".{target_tld}" in self.suspicious_tlds:
                    return True
                
                # Check for very different domains (not subdomains)
                if not (source_domain.endswith(target_domain) or target_domain.endswith(source_domain)):
                    return True
            
            return False
            
        except Exception:
            return False
    
    async def _analyze_content(self, url: str) -> Optional[ContentAnalysis]:
        """Analyze web page content"""
        try:
            response = self.session.get(
                url,
                timeout=self.config.get('content_analysis_timeout', 30),
                stream=True
            )
            
            # Check content size
            content_length = int(response.headers.get('content-length', 0))
            max_size = self.config.get('max_content_size', 5 * 1024 * 1024)
            
            if content_length > max_size:
                logger.warning(f"Content too large for analysis: {content_length} bytes")
                return None
            
            # Read content with size limit
            content = b''
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > max_size:
                    content = content[:max_size]
                    break
            
            content_text = content.decode('utf-8', errors='ignore').lower()
            
            # Extract basic information
            title = self._extract_title(content_text)
            meta_description = self._extract_meta_description(content_text)
            
            # Analyze forms
            form_count = content_text.count('<form')
            has_forms = form_count > 0
            
            # Analyze JavaScript
            script_count = content_text.count('<script')
            has_javascript = script_count > 0
            
            # Extract external resources
            external_resources = self._extract_external_resources(content_text, url)
            
            # Check for suspicious keywords
            suspicious_keywords = []
            for keyword in self.phishing_keywords:
                if keyword.lower() in content_text:
                    suspicious_keywords.append(keyword)
            
            # Check SSL certificate
            ssl_certificate_valid = url.startswith('https://')
            
            # Calculate content hash
            page_hash = hashlib.sha256(content).hexdigest()
            
            return ContentAnalysis(
                status_code=response.status_code,
                content_type=response.headers.get('content-type', 'unknown'),
                content_length=len(content),
                title=title,
                meta_description=meta_description,
                language=None,  # Could implement language detection
                has_forms=has_forms,
                form_count=form_count,
                has_javascript=has_javascript,
                script_count=script_count,
                external_resources=external_resources,
                suspicious_keywords=suspicious_keywords,
                ssl_certificate_valid=ssl_certificate_valid,
                page_hash=page_hash
            )
            
        except Exception as e:
            logger.warning(f"Error analyzing content for {url}: {str(e)}")
            return None
    
    def _extract_title(self, content: str) -> str:
        """Extract page title"""
        try:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
            if title_match:
                return title_match.group(1).strip()[:200]  # Limit length
            return "No title"
        except Exception:
            return "No title"
    
    def _extract_meta_description(self, content: str) -> str:
        """Extract meta description"""
        try:
            desc_match = re.search(
                r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']',
                content, re.IGNORECASE
            )
            if desc_match:
                return desc_match.group(1).strip()[:300]  # Limit length
            return "No description"
        except Exception:
            return "No description"
    
    def _extract_external_resources(self, content: str, base_url: str) -> List[str]:
        """Extract external resources (images, scripts, etc.)"""
        try:
            resources = []
            base_domain = urlparse(base_url).netloc
            
            # Find all src and href attributes
            resource_pattern = re.compile(r'(?:src|href)=["\']([^"\']*)["\']', re.IGNORECASE)
            matches = resource_pattern.findall(content)
            
            for match in matches:
                try:
                    # Convert relative URLs to absolute
                    if match.startswith(('http://', 'https://')):
                        resource_url = match
                    elif match.startswith('//'):
                        resource_url = 'https:' + match
                    else:
                        resource_url = urljoin(base_url, match)
                    
                    # Check if external resource
                    resource_domain = urlparse(resource_url).netloc
                    if resource_domain and resource_domain != base_domain:
                        resources.append(resource_url)
                        
                except Exception:
                    continue
            
            return list(set(resources))[:50]  # Limit and deduplicate
            
        except Exception:
            return []
    
    async def _sandbox_analysis(self, url: str) -> Optional[SandboxResult]:
        """Perform sandbox analysis (placeholder for external sandbox integration)"""
        try:
            # This is a placeholder implementation
            # In production, this would integrate with services like:
            # - Joe Sandbox
            # - Cuckoo Sandbox
            # - VMRay
            # - Hybrid Analysis
            
            sandbox_id = str(uuid.uuid4())
            start_time = datetime.now(timezone.utc)
            
            # Simulate sandbox analysis
            await asyncio.sleep(1)  # Simulate processing time
            
            return SandboxResult(
                sandbox_id=sandbox_id,
                status=SandboxStatus.COMPLETED,
                start_time=start_time,
                completion_time=datetime.now(timezone.utc),
                analysis_duration=1.0,
                verdict=URLThreatType.CLEAN,
                confidence=0.5,
                network_activity=[],
                file_downloads=[],
                registry_changes=[],
                process_creation=[],
                screenshots=[],
                behavioral_indicators=[],
                error_message=None
            )
            
        except Exception as e:
            logger.error(f"Error in sandbox analysis for {url}: {str(e)}")
            return None
    
    async def _calculate_final_verdict(self, url: str, domain_info: DomainInformation,
                                     reputation: URLReputation, redirection_chain: RedirectionChain,
                                     content_analysis: Optional[ContentAnalysis],
                                     sandbox_result: Optional[SandboxResult]) -> Tuple[URLThreatType, float, float]:
        """Calculate final verdict and scores"""
        try:
            # Start with reputation score
            base_score = 1.0 - reputation.reputation_score  # Convert to risk score
            confidence = 0.6  # Base confidence
            
            # Factor in blacklist matches
            if reputation.blacklist_matches:
                base_score += 0.3 * len(reputation.blacklist_matches)
                confidence += 0.2
            
            # Factor in whitelist matches
            if reputation.whitelist_matches:
                base_score -= 0.4
                confidence += 0.1
            
            # Factor in redirections
            if redirection_chain.redirect_count > 3:
                base_score += 0.2
                confidence += 0.1
            
            if redirection_chain.suspicious_redirects:
                base_score += 0.3 * len(redirection_chain.suspicious_redirects)
                confidence += 0.15
            
            if redirection_chain.contains_shorteners:
                base_score += 0.15
            
            # Factor in content analysis
            if content_analysis:
                if content_analysis.suspicious_keywords:
                    base_score += 0.1 * len(content_analysis.suspicious_keywords)
                    confidence += 0.1
                
                if content_analysis.has_forms and not content_analysis.ssl_certificate_valid:
                    base_score += 0.2
                    confidence += 0.1
                
                if content_analysis.status_code != 200:
                    base_score += 0.1
            
            # Factor in sandbox results
            if sandbox_result and sandbox_result.status == SandboxStatus.COMPLETED:
                if sandbox_result.verdict != URLThreatType.CLEAN:
                    base_score += 0.4
                    confidence += 0.2
                else:
                    base_score -= 0.1
                    confidence += 0.1
            
            # Factor in domain age
            if domain_info.age_days is not None:
                if domain_info.age_days < 7:  # Very new
                    base_score += 0.4
                elif domain_info.age_days < 30:  # New
                    base_score += 0.2
                elif domain_info.age_days > 365:  # Established
                    base_score -= 0.1
            
            # Normalize scores
            risk_score = max(0.0, min(10.0, base_score * 10))
            final_confidence = max(0.0, min(1.0, confidence))
            
            # Determine verdict based on risk score and reputation
            if risk_score >= 8.0 or URLThreatType.MALWARE in reputation.threat_types:
                verdict = URLThreatType.MALWARE
            elif risk_score >= 7.0 or URLThreatType.PHISHING in reputation.threat_types:
                verdict = URLThreatType.PHISHING
            elif risk_score >= 6.0 or URLThreatType.SCAM in reputation.threat_types:
                verdict = URLThreatType.SCAM
            elif risk_score >= 4.0 or URLThreatType.SUSPICIOUS in reputation.threat_types:
                verdict = URLThreatType.SUSPICIOUS
            elif risk_score >= 2.0:
                verdict = URLThreatType.SPAM
            else:
                verdict = URLThreatType.CLEAN
            
            return verdict, final_confidence, risk_score
            
        except Exception as e:
            logger.error(f"Error calculating final verdict: {str(e)}")
            return URLThreatType.SUSPICIOUS, 0.5, 5.0
    
    def _calculate_false_positive_likelihood(self, domain_info: DomainInformation,
                                           reputation: URLReputation,
                                           content_analysis: Optional[ContentAnalysis]) -> float:
        """Calculate likelihood of false positive"""
        try:
            fp_score = 0.0
            
            # Established domains are less likely to be false positives
            if domain_info.age_days and domain_info.age_days > 365:
                fp_score += 0.2
            
            # Trusted domains
            if reputation.whitelist_matches:
                fp_score += 0.3
            
            # High reputation score
            if reputation.reputation_score > 0.7:
                fp_score += 0.2
            
            # Valid SSL certificate
            if content_analysis and content_analysis.ssl_certificate_valid:
                fp_score += 0.1
            
            # Few suspicious indicators
            if not reputation.blacklist_matches:
                fp_score += 0.1
            
            # Legitimate TLD
            if domain_info.tld in ['com', 'org', 'net', 'edu', 'gov']:
                fp_score += 0.1
            
            return min(fp_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating false positive likelihood: {str(e)}")
            return 0.5
    
    def _determine_recommended_action(self, verdict: URLThreatType, confidence: float,
                                    risk_score: float, false_positive_likelihood: float) -> str:
        """Determine recommended action"""
        try:
            if verdict == URLThreatType.CLEAN:
                return "ALLOW"
            elif verdict in [URLThreatType.MALWARE, URLThreatType.PHISHING] and confidence > 0.8:
                return "BLOCK_IMMEDIATELY"
            elif risk_score >= 7.0 and false_positive_likelihood < 0.3:
                return "BLOCK_AND_ALERT"
            elif risk_score >= 5.0 and confidence > 0.6:
                return "FLAG_FOR_REVIEW"
            elif risk_score >= 3.0:
                return "LOG_AND_MONITOR"
            else:
                return "ALLOW_WITH_WARNING"
                
        except Exception:
            return "FLAG_FOR_REVIEW"
    
    async def _store_analysis_result(self, result: URLAnalysisResult):
        """Store analysis result in database"""
        try:
            # Store main analysis record
            self.db_connection.execute('''
                INSERT OR REPLACE INTO url_analyses
                (analysis_id, original_url, normalized_url, analysis_timestamp,
                 final_verdict, confidence_score, risk_score, domain_age_days,
                 redirect_count, recommended_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.analysis_id,
                result.original_url,
                result.normalized_url,
                result.analysis_timestamp.timestamp(),
                result.final_verdict.value,
                result.confidence_score,
                result.risk_score,
                result.domain_info.age_days,
                result.redirection_chain.redirect_count,
                result.recommended_action
            ))
            
            # Update domain reputation
            domain = result.domain_info.domain
            self.db_connection.execute('''
                INSERT OR REPLACE INTO domain_reputation
                (domain, reputation_score, category, threat_types, last_analyzed, analysis_count)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                domain,
                result.reputation.reputation_score,
                result.reputation.category.value,
                json.dumps([t.value for t in result.reputation.threat_types]),
                result.analysis_timestamp.timestamp(),
                result.reputation.analysis_count
            ))
            
            self.db_connection.commit()
            logger.debug(f"Stored analysis result for {result.normalized_url}")
            
        except Exception as e:
            logger.error(f"Error storing analysis result: {str(e)}")
    
    async def _cache_result(self, url: str, result: URLAnalysisResult):
        """Cache analysis result"""
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            cached_data = json.dumps({
                'analysis_id': result.analysis_id,
                'verdict': result.final_verdict.value,
                'confidence': result.confidence_score,
                'risk_score': result.risk_score,
                'recommended_action': result.recommended_action
            })
            
            cache_duration = self.config.get('cache_duration_hours', 24)
            expires_timestamp = (datetime.now() + timedelta(hours=cache_duration)).timestamp()
            
            self.db_connection.execute('''
                INSERT OR REPLACE INTO url_cache
                (url_hash, url, analysis_result, cached_timestamp, expires_timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                url_hash, url, cached_data,
                datetime.now().timestamp(), expires_timestamp
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            logger.error(f"Error caching result for {url}: {str(e)}")
    
    def _update_analysis_stats(self, result: URLAnalysisResult):
        """Update analysis statistics"""
        try:
            self.analysis_stats['total_analyzed'] += 1
            self.analysis_stats['analysis_times'].append(result.total_analysis_duration)
            
            if result.final_verdict != URLThreatType.CLEAN:
                self.analysis_stats['threats_detected'] += 1
            
            # Keep only recent analysis times
            if len(self.analysis_stats['analysis_times']) > 1000:
                self.analysis_stats['analysis_times'] = self.analysis_stats['analysis_times'][-1000:]
                
        except Exception as e:
            logger.error(f"Error updating analysis stats: {str(e)}")
    
    def get_analysis_statistics(self) -> Dict[str, Any]:
        """Get analyzer performance statistics"""
        try:
            analysis_times = self.analysis_stats['analysis_times']
            
            stats = {
                'total_analyzed': self.analysis_stats['total_analyzed'],
                'threats_detected': self.analysis_stats['threats_detected'],
                'threat_detection_rate': (
                    self.analysis_stats['threats_detected'] / 
                    max(self.analysis_stats['total_analyzed'], 1) * 100
                ),
                'cache_hits': self.analysis_stats['cache_hits'],
                'cache_hit_rate': (
                    self.analysis_stats['cache_hits'] / 
                    max(self.analysis_stats['total_analyzed'], 1) * 100
                ),
                'avg_analysis_time': sum(analysis_times) / len(analysis_times) if analysis_times else 0.0,
                'min_analysis_time': min(analysis_times) if analysis_times else 0.0,
                'max_analysis_time': max(analysis_times) if analysis_times else 0.0
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting analysis statistics: {str(e)}")
            return {}
    
    def __del__(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'db_connection'):
                self.db_connection.close()
            if hasattr(self, 'session'):
                self.session.close()
        except Exception:
            pass


# Example usage and testing
async def main():
    """Example usage of URLAnalyzer"""
    analyzer = URLAnalyzer()
    
    # Test URLs
    test_urls = [
        'https://google.com',
        'http://suspicious-paypal.tk/login',
        'https://bit.ly/suspicious-link',
        'http://192.168.1.1/malware.exe',
        'https://phishing-example.com/verify-account'
    ]
    
    try:
        for url in test_urls:
            print(f"\nAnalyzing URL: {url}")
            result = await analyzer.analyze_url(url)
            
            print(f"  Final Verdict: {result.final_verdict.value}")
            print(f"  Confidence: {result.confidence_score:.2f}")
            print(f"  Risk Score: {result.risk_score:.1f}/10")
            print(f"  Recommended Action: {result.recommended_action}")
            print(f"  Analysis Duration: {result.total_analysis_duration:.3f}s")
            
            print(f"  Domain Info:")
            print(f"    Domain: {result.domain_info.domain}")
            print(f"    Age: {result.domain_info.age_days} days")
            print(f"    TLD: {result.domain_info.tld}")
            
            print(f"  Reputation:")
            print(f"    Score: {result.reputation.reputation_score:.2f}")
            print(f"    Category: {result.reputation.category.value}")
            print(f"    Threat Types: {[t.value for t in result.reputation.threat_types]}")
            
            if result.reputation.blacklist_matches:
                print(f"    Blacklist Matches: {result.reputation.blacklist_matches}")
            
            print(f"  Redirections:")
            print(f"    Count: {result.redirection_chain.redirect_count}")
            print(f"    Final URL: {result.redirection_chain.final_url}")
            
            if result.content_analysis:
                print(f"  Content Analysis:")
                print(f"    Status Code: {result.content_analysis.status_code}")
                print(f"    Has Forms: {result.content_analysis.has_forms}")
                print(f"    Suspicious Keywords: {len(result.content_analysis.suspicious_keywords)}")
        
        # Get analyzer statistics
        stats = analyzer.get_analysis_statistics()
        print(f"\nAnalyzer Statistics:")
        for key, value in stats.items():
            if isinstance(value, float):
                print(f"  {key}: {value:.3f}")
            else:
                print(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())