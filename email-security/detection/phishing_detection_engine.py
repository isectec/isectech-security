"""
Advanced Phishing Detection Engine for ISECTECH Email Security Integration

This module provides comprehensive phishing detection capabilities including:
- Machine learning-based phishing classification
- Natural Language Processing for content analysis
- Business Email Compromise (BEC) detection
- Domain reputation and spoofing detection
- Advanced pattern recognition and behavioral analysis
- Production-grade performance and accuracy

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import difflib
import urllib.parse
from collections import Counter, defaultdict
import math

# NLP and ML imports (using built-in libraries for production compatibility)
import string
from collections import namedtuple

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PhishingThreatType(Enum):
    """Types of phishing threats detected"""
    CREDENTIAL_HARVESTING = "credential_harvesting"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    MALWARE_DELIVERY = "malware_delivery"
    FINANCIAL_FRAUD = "financial_fraud"
    SOCIAL_ENGINEERING = "social_engineering"
    BRAND_IMPERSONATION = "brand_impersonation"
    SPEAR_PHISHING = "spear_phishing"
    WHALING = "whaling"
    CLONE_PHISHING = "clone_phishing"
    PHARMING = "pharming"


class PhishingConfidence(Enum):
    """Confidence levels for phishing detection"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"
    CONFIRMED = "confirmed"


@dataclass
class PhishingIndicator:
    """Individual phishing indicator with confidence and reasoning"""
    indicator_type: str
    description: str
    confidence: float  # 0.0 - 1.0
    weight: float     # Impact on overall score
    evidence: Dict[str, Any]
    severity: str


@dataclass
class DomainAnalysis:
    """Domain reputation and analysis results"""
    domain: str
    is_suspicious: bool
    reputation_score: float
    age_days: Optional[int]
    registrar: Optional[str]
    country: Optional[str]
    is_homograph: bool
    similar_domains: List[str]
    typosquatting_score: float
    subdomain_analysis: Dict[str, Any]


@dataclass
class ContentAnalysis:
    """Email content analysis results"""
    sentiment_score: float
    urgency_score: float
    authority_score: float
    trust_indicators: List[str]
    deception_indicators: List[str]
    linguistic_patterns: Dict[str, float]
    social_engineering_tactics: List[str]
    keyword_matches: Dict[str, int]
    readability_score: float


@dataclass
class BECAnalysis:
    """Business Email Compromise specific analysis"""
    is_bec_candidate: bool
    executive_impersonation: bool
    vendor_impersonation: bool
    payroll_fraud_indicators: List[str]
    wire_transfer_keywords: List[str]
    invoice_fraud_indicators: List[str]
    urgency_manipulation: List[str]
    authority_manipulation: List[str]
    trust_exploitation: List[str]


@dataclass
class PhishingDetectionResult:
    """Complete phishing detection analysis result"""
    email_id: str
    detection_timestamp: datetime
    is_phishing: bool
    confidence_level: PhishingConfidence
    overall_score: float  # 0.0 - 10.0
    threat_types: List[PhishingThreatType]
    indicators: List[PhishingIndicator]
    domain_analysis: DomainAnalysis
    content_analysis: ContentAnalysis
    bec_analysis: BECAnalysis
    ml_prediction: Dict[str, float]
    recommended_action: str
    false_positive_likelihood: float


class PhishingDetectionEngine:
    """
    Advanced phishing detection engine using multiple detection methods
    
    Combines machine learning, natural language processing, domain analysis,
    and behavioral pattern recognition for comprehensive phishing detection.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize phishing detection engine"""
        self.config = config or self._get_default_config()
        self.data_dir = Path(self.config.get('data_directory', '/tmp/phishing_detection'))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize detection components
        self._load_phishing_patterns()
        self._load_brand_databases()
        self._load_bec_patterns()
        self._init_ml_models()
        self._init_database()
        
        # Performance tracking
        self.detection_stats = {
            'total_analyzed': 0,
            'phishing_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'processing_times': []
        }
        
        logger.info("Phishing Detection Engine initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'data_directory': '/tmp/phishing_detection',
            'confidence_threshold': 0.7,
            'ml_model_threshold': 0.8,
            'domain_reputation_threshold': 0.5,
            'enable_ml_detection': True,
            'enable_nlp_analysis': True,
            'enable_domain_analysis': True,
            'enable_bec_detection': True,
            'max_similar_domains': 20,
            'homograph_sensitivity': 0.8,
            'update_detection_models': True,
            'store_detection_results': True
        }
    
    def _load_phishing_patterns(self):
        """Load phishing detection patterns and signatures"""
        # Urgency indicators
        self.urgency_patterns = [
            r'urgent.*action.*required',
            r'immediate.*response.*needed',
            r'act.*now.*before',
            r'expires.*today',
            r'limited.*time.*only',
            r'deadline.*approaching',
            r'suspended.*unless',
            r'verify.*within.*\d+.*hours',
            r'respond.*immediately',
            r'time.*sensitive'
        ]
        
        # Authority manipulation patterns
        self.authority_patterns = [
            r'from.*security.*team',
            r'bank.*notification',
            r'system.*administrator',
            r'compliance.*department',
            r'fraud.*prevention',
            r'account.*verification',
            r'it.*support.*department',
            r'customer.*service.*team'
        ]
        
        # Credential harvesting patterns
        self.credential_patterns = [
            r'verify.*password',
            r'confirm.*identity',
            r'update.*payment.*information',
            r'validate.*account',
            r'login.*credentials',
            r'security.*questions',
            r'personal.*information',
            r'banking.*details'
        ]
        
        # Financial fraud patterns
        self.financial_patterns = [
            r'wire.*transfer',
            r'invoice.*payment',
            r'refund.*processing',
            r'tax.*return',
            r'lottery.*winnings',
            r'inheritance.*funds',
            r'payment.*confirmation',
            r'billing.*statement'
        ]
        
        # Deception indicators
        self.deception_patterns = [
            r'congratulations.*winner',
            r'selected.*randomly',
            r'claim.*prize',
            r'free.*money',
            r'no.*cost.*to.*you',
            r'guaranteed.*approval',
            r'risk.*free',
            r'limited.*availability'
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = {
            'urgency': [re.compile(p, re.IGNORECASE) for p in self.urgency_patterns],
            'authority': [re.compile(p, re.IGNORECASE) for p in self.authority_patterns],
            'credential': [re.compile(p, re.IGNORECASE) for p in self.credential_patterns],
            'financial': [re.compile(p, re.IGNORECASE) for p in self.financial_patterns],
            'deception': [re.compile(p, re.IGNORECASE) for p in self.deception_patterns]
        }
    
    def _load_brand_databases(self):
        """Load legitimate brand and organization databases"""
        # Top brands commonly impersonated in phishing
        self.legitimate_brands = {
            'banks': [
                'chase', 'bank of america', 'wells fargo', 'citibank', 'goldman sachs',
                'jpmorgan', 'morgan stanley', 'credit suisse', 'deutsche bank'
            ],
            'tech': [
                'microsoft', 'google', 'apple', 'amazon', 'facebook', 'netflix',
                'adobe', 'salesforce', 'oracle', 'ibm', 'cisco', 'intel'
            ],
            'payment': [
                'paypal', 'stripe', 'square', 'visa', 'mastercard', 'american express',
                'discover', 'western union', 'moneygram'
            ],
            'government': [
                'irs', 'social security', 'medicare', 'postal service', 'homeland security'
            ],
            'services': [
                'fedex', 'ups', 'dhl', 'linkedin', 'twitter', 'instagram', 'zoom'
            ]
        }
        
        # Legitimate domains for brand verification
        self.legitimate_domains = {
            'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com',
            'google.com', 'gmail.com', 'googlemail.com',
            'apple.com', 'icloud.com', 'me.com',
            'amazon.com', 'amazonaws.com',
            'paypal.com', 'paypal-notifications.com'
        }
    
    def _load_bec_patterns(self):
        """Load Business Email Compromise detection patterns"""
        # Executive titles for impersonation detection
        self.executive_titles = [
            'ceo', 'cfo', 'coo', 'president', 'vice president', 'vp',
            'chief executive', 'chief financial', 'chief operating',
            'executive director', 'managing director', 'general manager'
        ]
        
        # BEC-specific keywords
        self.bec_keywords = {
            'urgency': [
                'confidential', 'urgent request', 'immediate attention',
                'time sensitive', 'asap', 'quick favor', 'need this done'
            ],
            'financial': [
                'wire transfer', 'bank transfer', 'payment', 'invoice',
                'vendor payment', 'supplier payment', 'refund', 'reimbursement'
            ],
            'manipulation': [
                'keep this between us', 'do not discuss', 'confidential matter',
                'handle personally', 'urgent approval needed'
            ]
        }
        
        # Vendor impersonation patterns
        self.vendor_patterns = [
            r'bank.*account.*change',
            r'payment.*information.*update',
            r'new.*banking.*details',
            r'updated.*wire.*instructions',
            r'revised.*payment.*method'
        ]
    
    def _init_ml_models(self):
        """Initialize machine learning models for phishing detection"""
        # Simplified ML model implementation using statistical methods
        # In production, this would use scikit-learn, TensorFlow, or similar
        
        # Feature weights for different indicators
        self.ml_feature_weights = {
            'url_suspicious': 0.15,
            'domain_age': 0.10,
            'sender_reputation': 0.12,
            'content_urgency': 0.08,
            'credential_harvesting': 0.20,
            'financial_indicators': 0.15,
            'brand_impersonation': 0.12,
            'grammar_errors': 0.08
        }
        
        # Baseline thresholds for classification
        self.ml_thresholds = {
            'phishing_score': 0.7,
            'confidence_threshold': 0.8,
            'false_positive_threshold': 0.3
        }
    
    def _init_database(self):
        """Initialize SQLite database for detection results"""
        db_path = self.data_dir / 'phishing_detection.db'
        self.db_connection = sqlite3.connect(str(db_path), check_same_thread=False)
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS phishing_detections (
                detection_id TEXT PRIMARY KEY,
                email_id TEXT NOT NULL,
                detection_timestamp REAL,
                is_phishing BOOLEAN,
                confidence_level TEXT,
                overall_score REAL,
                threat_types TEXT,
                indicators_count INTEGER,
                ml_prediction REAL,
                false_positive_likelihood REAL,
                recommended_action TEXT
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS detection_indicators (
                indicator_id TEXT PRIMARY KEY,
                detection_id TEXT,
                indicator_type TEXT,
                description TEXT,
                confidence REAL,
                weight REAL,
                evidence TEXT,
                FOREIGN KEY (detection_id) REFERENCES phishing_detections (detection_id)
            )
        ''')
        
        self.db_connection.execute('''
            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain TEXT PRIMARY KEY,
                reputation_score REAL,
                last_updated REAL,
                is_suspicious BOOLEAN,
                analysis_data TEXT
            )
        ''')
        
        self.db_connection.commit()
    
    async def detect_phishing(self, email_data: Dict[str, Any]) -> PhishingDetectionResult:
        """
        Comprehensive phishing detection analysis
        
        Args:
            email_data: Processed email data from EmailProcessingEngine
            
        Returns:
            PhishingDetectionResult: Complete detection analysis
        """
        start_time = datetime.now(timezone.utc)
        detection_id = str(uuid.uuid4())
        
        try:
            # Extract email components
            email_id = email_data.get('email_id', str(uuid.uuid4()))
            headers = email_data.get('headers', {})
            content = email_data.get('content', {})
            attachments = email_data.get('attachments', [])
            
            # Initialize analysis components
            indicators = []
            threat_types = []
            
            # Domain analysis
            domain_analysis = await self._analyze_sender_domain(headers)
            
            # Content analysis
            content_analysis = await self._analyze_email_content(content)
            
            # BEC analysis
            bec_analysis = await self._analyze_bec_indicators(headers, content)
            
            # Pattern-based detection
            pattern_indicators = await self._detect_phishing_patterns(content, headers)
            indicators.extend(pattern_indicators)
            
            # ML-based detection
            if self.config.get('enable_ml_detection', True):
                ml_prediction = await self._ml_phishing_classification(
                    headers, content, domain_analysis, content_analysis
                )
            else:
                ml_prediction = {'phishing_probability': 0.0, 'confidence': 0.0}
            
            # Brand impersonation detection
            brand_indicators = await self._detect_brand_impersonation(headers, content)
            indicators.extend(brand_indicators)
            
            # URL analysis
            url_indicators = await self._analyze_urls(content.get('urls', []))
            indicators.extend(url_indicators)
            
            # Calculate overall score and confidence
            overall_score, confidence_level = self._calculate_overall_score(
                indicators, ml_prediction, domain_analysis, content_analysis, bec_analysis
            )
            
            # Determine threat types
            threat_types = self._identify_threat_types(indicators, bec_analysis)
            
            # Determine if this is phishing based on threshold
            is_phishing = overall_score >= self.config.get('confidence_threshold', 0.7)
            
            # Calculate false positive likelihood
            false_positive_likelihood = self._calculate_false_positive_likelihood(
                indicators, domain_analysis, content_analysis
            )
            
            # Determine recommended action
            recommended_action = self._determine_recommended_action(
                overall_score, confidence_level, false_positive_likelihood
            )
            
            # Create detection result
            detection_result = PhishingDetectionResult(
                email_id=email_id,
                detection_timestamp=start_time,
                is_phishing=is_phishing,
                confidence_level=confidence_level,
                overall_score=overall_score,
                threat_types=threat_types,
                indicators=indicators,
                domain_analysis=domain_analysis,
                content_analysis=content_analysis,
                bec_analysis=bec_analysis,
                ml_prediction=ml_prediction,
                recommended_action=recommended_action,
                false_positive_likelihood=false_positive_likelihood
            )
            
            # Store detection result
            if self.config.get('store_detection_results', True):
                await self._store_detection_result(detection_result)
            
            # Update statistics
            self._update_detection_stats(detection_result, start_time)
            
            logger.info(f"Phishing detection completed for email {email_id}: "
                       f"Score={overall_score:.2f}, Phishing={is_phishing}")
            
            return detection_result
            
        except Exception as e:
            logger.error(f"Error in phishing detection: {str(e)}")
            raise
    
    async def _analyze_sender_domain(self, headers: Dict[str, Any]) -> DomainAnalysis:
        """Analyze sender domain for reputation and suspicious characteristics"""
        try:
            from_address = headers.get('from_address', '')
            if not from_address or '@' not in from_address:
                return DomainAnalysis(
                    domain='unknown',
                    is_suspicious=True,
                    reputation_score=0.0,
                    age_days=None,
                    registrar=None,
                    country=None,
                    is_homograph=False,
                    similar_domains=[],
                    typosquatting_score=0.0,
                    subdomain_analysis={}
                )
            
            domain = from_address.split('@')[1].lower()
            
            # Check domain reputation cache
            reputation_data = await self._get_domain_reputation(domain)
            
            # Analyze for typosquatting
            similar_domains = self._find_similar_domains(domain)
            typosquatting_score = self._calculate_typosquatting_score(domain, similar_domains)
            
            # Check for homograph attacks (IDN spoofing)
            is_homograph = self._detect_homograph_attack(domain)
            
            # Analyze subdomains
            subdomain_analysis = self._analyze_subdomains(domain)
            
            # Calculate overall suspicion score
            is_suspicious = (
                reputation_data['reputation_score'] < 0.5 or
                typosquatting_score > 0.7 or
                is_homograph or
                subdomain_analysis.get('suspicious_subdomain', False)
            )
            
            return DomainAnalysis(
                domain=domain,
                is_suspicious=is_suspicious,
                reputation_score=reputation_data['reputation_score'],
                age_days=reputation_data.get('age_days'),
                registrar=reputation_data.get('registrar'),
                country=reputation_data.get('country'),
                is_homograph=is_homograph,
                similar_domains=similar_domains[:10],  # Limit results
                typosquatting_score=typosquatting_score,
                subdomain_analysis=subdomain_analysis
            )
            
        except Exception as e:
            logger.error(f"Error analyzing sender domain: {str(e)}")
            return DomainAnalysis(
                domain='error',
                is_suspicious=True,
                reputation_score=0.0,
                age_days=None,
                registrar=None,
                country=None,
                is_homograph=False,
                similar_domains=[],
                typosquatting_score=0.0,
                subdomain_analysis={}
            )
    
    async def _get_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Get domain reputation from cache or analysis"""
        try:
            # Check cache first
            cursor = self.db_connection.execute(
                'SELECT * FROM domain_reputation WHERE domain = ?', (domain,)
            )
            row = cursor.fetchone()
            
            if row:
                # Check if data is recent (within 24 hours)
                last_updated = datetime.fromtimestamp(row[2])
                if (datetime.now() - last_updated).total_seconds() < 86400:
                    return json.loads(row[4])
            
            # Perform new analysis
            reputation_data = await self._analyze_domain_reputation(domain)
            
            # Cache the result
            self.db_connection.execute('''
                INSERT OR REPLACE INTO domain_reputation 
                (domain, reputation_score, last_updated, is_suspicious, analysis_data)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                domain,
                reputation_data['reputation_score'],
                datetime.now().timestamp(),
                reputation_data.get('is_suspicious', False),
                json.dumps(reputation_data)
            ))
            self.db_connection.commit()
            
            return reputation_data
            
        except Exception as e:
            logger.error(f"Error getting domain reputation for {domain}: {str(e)}")
            return {'reputation_score': 0.5, 'is_suspicious': False}
    
    async def _analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Analyze domain reputation using heuristics"""
        try:
            reputation_score = 0.5  # Neutral starting point
            factors = []
            
            # Check against known legitimate domains
            if domain in self.legitimate_domains:
                reputation_score += 0.4
                factors.append('legitimate_domain')
            
            # Check domain structure
            parts = domain.split('.')
            
            # Suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                reputation_score -= 0.3
                factors.append('suspicious_tld')
            
            # Long subdomains are suspicious
            if len(parts) > 3:
                reputation_score -= 0.2
                factors.append('excessive_subdomains')
            
            # Numeric domains are suspicious
            if any(char.isdigit() for char in parts[0]):
                reputation_score -= 0.15
                factors.append('numeric_domain')
            
            # Very short domains (< 4 chars) are suspicious
            if len(parts[0]) < 4:
                reputation_score -= 0.1
                factors.append('short_domain')
            
            # Very long domains (> 20 chars) are suspicious
            if len(parts[0]) > 20:
                reputation_score -= 0.1
                factors.append('long_domain')
            
            # Hyphens in domain name
            if '-' in parts[0]:
                reputation_score -= 0.05
                factors.append('hyphenated_domain')
            
            # Multiple consecutive vowels or consonants
            vowels = 'aeiou'
            consonants = 'bcdfghjklmnpqrstvwxyz'
            domain_name = parts[0]
            
            vowel_streak = consonant_streak = 0
            max_vowel_streak = max_consonant_streak = 0
            
            for char in domain_name:
                if char in vowels:
                    vowel_streak += 1
                    consonant_streak = 0
                    max_vowel_streak = max(max_vowel_streak, vowel_streak)
                elif char in consonants:
                    consonant_streak += 1
                    vowel_streak = 0
                    max_consonant_streak = max(max_consonant_streak, consonant_streak)
                else:
                    vowel_streak = consonant_streak = 0
            
            if max_vowel_streak > 3 or max_consonant_streak > 4:
                reputation_score -= 0.1
                factors.append('unusual_character_pattern')
            
            # Ensure score is within bounds
            reputation_score = max(0.0, min(1.0, reputation_score))
            
            return {
                'reputation_score': reputation_score,
                'is_suspicious': reputation_score < 0.4,
                'factors': factors,
                'age_days': None,  # Would require WHOIS lookup
                'registrar': None,
                'country': None
            }
            
        except Exception as e:
            logger.error(f"Error analyzing domain reputation: {str(e)}")
            return {'reputation_score': 0.5, 'is_suspicious': False, 'factors': []}
    
    def _find_similar_domains(self, domain: str) -> List[str]:
        """Find domains similar to legitimate brands (typosquatting detection)"""
        similar_domains = []
        
        try:
            domain_base = domain.split('.')[0]
            
            # Check against all legitimate brands
            for category, brands in self.legitimate_brands.items():
                for brand in brands:
                    brand_clean = brand.replace(' ', '').lower()
                    
                    # Calculate similarity using difflib
                    similarity = difflib.SequenceMatcher(None, domain_base, brand_clean).ratio()
                    
                    # Check for common typosquatting techniques
                    if (similarity > 0.7 or 
                        self._check_typosquatting_patterns(domain_base, brand_clean)):
                        similar_domains.append(f"{brand} ({category})")
            
            return similar_domains[:self.config.get('max_similar_domains', 20)]
            
        except Exception as e:
            logger.error(f"Error finding similar domains: {str(e)}")
            return []
    
    def _check_typosquatting_patterns(self, domain: str, brand: str) -> bool:
        """Check for common typosquatting patterns"""
        try:
            # Character substitution (o->0, i->1, etc.)
            substitutions = {'o': '0', '0': 'o', 'i': '1', '1': 'i', 'e': '3', '3': 'e'}
            
            # Check character substitutions
            for original, substitute in substitutions.items():
                if domain == brand.replace(original, substitute):
                    return True
            
            # Character omission
            for i in range(len(brand)):
                if domain == brand[:i] + brand[i+1:]:
                    return True
            
            # Character insertion
            for i in range(len(brand) + 1):
                for char in 'abcdefghijklmnopqrstuvwxyz0123456789':
                    if domain == brand[:i] + char + brand[i:]:
                        return True
            
            # Character transposition
            for i in range(len(brand) - 1):
                transposed = brand[:i] + brand[i+1] + brand[i] + brand[i+2:]
                if domain == transposed:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _calculate_typosquatting_score(self, domain: str, similar_domains: List[str]) -> float:
        """Calculate typosquatting likelihood score"""
        if not similar_domains:
            return 0.0
        
        # Base score on number of similar domains found
        base_score = min(len(similar_domains) * 0.2, 0.8)
        
        # Increase score for exact character-level similarities
        domain_base = domain.split('.')[0]
        max_similarity = 0.0
        
        for similar in similar_domains:
            brand_name = similar.split('(')[0].strip().replace(' ', '').lower()
            similarity = difflib.SequenceMatcher(None, domain_base, brand_name).ratio()
            max_similarity = max(max_similarity, similarity)
        
        # Combine base score with similarity
        final_score = (base_score * 0.6) + (max_similarity * 0.4)
        return min(final_score, 1.0)
    
    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect IDN homograph attacks using suspicious character patterns"""
        try:
            # Check for mixed scripts (Latin + Cyrillic, etc.)
            # Simplified detection - in production would use full Unicode analysis
            
            suspicious_chars = [
                'а', 'е', 'о', 'р', 'с', 'у', 'х',  # Cyrillic look-alikes
                'ο', 'ρ', 'α', 'ν', 'κ',            # Greek look-alikes
            ]
            
            # Check if domain contains suspicious characters
            for char in domain:
                if char in suspicious_chars:
                    return True
            
            # Check for punycode (xn--)
            if domain.startswith('xn--'):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _analyze_subdomains(self, domain: str) -> Dict[str, Any]:
        """Analyze subdomain structure for suspicious patterns"""
        try:
            parts = domain.split('.')
            analysis = {
                'subdomain_count': len(parts) - 2,  # Exclude domain and TLD
                'suspicious_subdomain': False,
                'subdomain_patterns': []
            }
            
            if len(parts) <= 2:
                return analysis
            
            # Check for suspicious subdomain patterns
            suspicious_patterns = [
                'secure', 'login', 'auth', 'verify', 'account', 'update',
                'service', 'support', 'mail', 'webmail', 'portal'
            ]
            
            for part in parts[:-2]:  # Exclude main domain and TLD
                if any(pattern in part.lower() for pattern in suspicious_patterns):
                    analysis['suspicious_subdomain'] = True
                    analysis['subdomain_patterns'].append(part)
            
            # Very long subdomains are suspicious
            if any(len(part) > 15 for part in parts[:-2]):
                analysis['suspicious_subdomain'] = True
                analysis['subdomain_patterns'].append('long_subdomain')
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing subdomains: {str(e)}")
            return {'subdomain_count': 0, 'suspicious_subdomain': False, 'subdomain_patterns': []}
    
    async def _analyze_email_content(self, content: Dict[str, Any]) -> ContentAnalysis:
        """Comprehensive email content analysis using NLP techniques"""
        try:
            text_content = (content.get('plain_text', '') + ' ' + 
                          content.get('html_content', '')).lower()
            
            if not text_content.strip():
                return ContentAnalysis(
                    sentiment_score=0.0,
                    urgency_score=0.0,
                    authority_score=0.0,
                    trust_indicators=[],
                    deception_indicators=[],
                    linguistic_patterns={},
                    social_engineering_tactics=[],
                    keyword_matches={},
                    readability_score=0.0
                )
            
            # Sentiment analysis (simplified)
            sentiment_score = self._analyze_sentiment(text_content)
            
            # Urgency analysis
            urgency_score = self._analyze_urgency(text_content)
            
            # Authority manipulation analysis
            authority_score = self._analyze_authority_manipulation(text_content)
            
            # Trust and deception indicators
            trust_indicators = self._identify_trust_indicators(text_content)
            deception_indicators = self._identify_deception_indicators(text_content)
            
            # Linguistic pattern analysis
            linguistic_patterns = self._analyze_linguistic_patterns(text_content)
            
            # Social engineering tactics
            social_engineering_tactics = self._identify_social_engineering(text_content)
            
            # Keyword matching
            keyword_matches = self._analyze_keyword_matches(text_content)
            
            # Readability analysis
            readability_score = self._calculate_readability_score(text_content)
            
            return ContentAnalysis(
                sentiment_score=sentiment_score,
                urgency_score=urgency_score,
                authority_score=authority_score,
                trust_indicators=trust_indicators,
                deception_indicators=deception_indicators,
                linguistic_patterns=linguistic_patterns,
                social_engineering_tactics=social_engineering_tactics,
                keyword_matches=keyword_matches,
                readability_score=readability_score
            )
            
        except Exception as e:
            logger.error(f"Error analyzing email content: {str(e)}")
            return ContentAnalysis(
                sentiment_score=0.0, urgency_score=0.0, authority_score=0.0,
                trust_indicators=[], deception_indicators=[], linguistic_patterns={},
                social_engineering_tactics=[], keyword_matches={}, readability_score=0.0
            )
    
    def _analyze_sentiment(self, text: str) -> float:
        """Analyze sentiment polarity (simplified implementation)"""
        try:
            # Positive indicators
            positive_words = [
                'congratulations', 'winner', 'selected', 'lucky', 'free', 'gift',
                'bonus', 'reward', 'prize', 'exclusive', 'special', 'amazing'
            ]
            
            # Negative indicators
            negative_words = [
                'suspended', 'blocked', 'expired', 'failed', 'problem', 'issue',
                'error', 'warning', 'alert', 'danger', 'risk', 'threat'
            ]
            
            # Neutral indicators
            neutral_words = [
                'update', 'notification', 'information', 'request', 'confirmation'
            ]
            
            words = text.lower().split()
            positive_count = sum(1 for word in words if any(pos in word for pos in positive_words))
            negative_count = sum(1 for word in words if any(neg in word for neg in negative_words))
            
            if positive_count + negative_count == 0:
                return 0.0  # Neutral
            
            # Calculate polarity (-1 to 1, then normalize to 0-1)
            polarity = (positive_count - negative_count) / (positive_count + negative_count)
            return (polarity + 1) / 2  # Normalize to 0-1
            
        except Exception:
            return 0.5  # Default neutral
    
    def _analyze_urgency(self, text: str) -> float:
        """Analyze urgency indicators in text"""
        try:
            urgency_score = 0.0
            matches = 0
            
            for pattern in self.compiled_patterns['urgency']:
                pattern_matches = len(pattern.findall(text))
                if pattern_matches > 0:
                    urgency_score += pattern_matches * 0.2
                    matches += pattern_matches
            
            # Additional urgency indicators
            urgency_words = [
                'immediately', 'now', 'today', 'asap', 'urgent', 'emergency',
                'deadline', 'expires', 'limited time', 'act fast'
            ]
            
            for word in urgency_words:
                if word in text:
                    urgency_score += 0.15
                    matches += 1
            
            # Normalize score based on text length and matches
            if matches > 0:
                text_length_factor = min(len(text.split()) / 100, 1.0)  # Normalize by text length
                urgency_score = min(urgency_score * text_length_factor, 1.0)
            
            return urgency_score
            
        except Exception:
            return 0.0
    
    def _analyze_authority_manipulation(self, text: str) -> float:
        """Analyze authority manipulation indicators"""
        try:
            authority_score = 0.0
            
            for pattern in self.compiled_patterns['authority']:
                matches = len(pattern.findall(text))
                if matches > 0:
                    authority_score += matches * 0.25
            
            # Check for impersonation of specific authorities
            authority_entities = [
                'bank', 'government', 'irs', 'police', 'security team',
                'system administrator', 'it department', 'fraud prevention'
            ]
            
            for entity in authority_entities:
                if entity in text:
                    authority_score += 0.2
            
            return min(authority_score, 1.0)
            
        except Exception:
            return 0.0
    
    def _identify_trust_indicators(self, text: str) -> List[str]:
        """Identify trust-building indicators"""
        trust_indicators = []
        
        trust_patterns = [
            'secure connection', 'ssl encrypted', 'verified sender', 'official notification',
            'customer service', 'support team', 'help desk', 'legitimate business'
        ]
        
        for pattern in trust_patterns:
            if pattern in text:
                trust_indicators.append(pattern)
        
        return trust_indicators
    
    def _identify_deception_indicators(self, text: str) -> List[str]:
        """Identify deception indicators"""
        deception_indicators = []
        
        for pattern in self.compiled_patterns['deception']:
            matches = pattern.findall(text)
            deception_indicators.extend(matches)
        
        # Additional deception checks
        deception_phrases = [
            'you have been selected', 'random winner', 'claim your prize',
            'no strings attached', 'completely free', 'guaranteed'
        ]
        
        for phrase in deception_phrases:
            if phrase in text:
                deception_indicators.append(phrase)
        
        return list(set(deception_indicators))  # Remove duplicates
    
    def _analyze_linguistic_patterns(self, text: str) -> Dict[str, float]:
        """Analyze linguistic patterns for authenticity"""
        try:
            patterns = {}
            
            # Grammar and spelling errors (simplified detection)
            words = text.split()
            if words:
                # Check for excessive capitalization
                caps_ratio = sum(1 for word in words if word.isupper()) / len(words)
                patterns['excessive_caps'] = caps_ratio
                
                # Check for repeated punctuation
                repeated_punct = len(re.findall(r'[!]{2,}|[?]{2,}|[.]{3,}', text))
                patterns['repeated_punctuation'] = min(repeated_punct / 10, 1.0)
                
                # Check average word length (very short words might indicate poor grammar)
                avg_word_length = sum(len(word) for word in words) / len(words)
                patterns['avg_word_length'] = min(avg_word_length / 10, 1.0)
                
                # Check for excessive use of certain words
                word_freq = Counter(words)
                most_common = word_freq.most_common(1)
                if most_common:
                    max_freq = most_common[0][1]
                    patterns['word_repetition'] = min(max_freq / len(words), 1.0)
            
            return patterns
            
        except Exception:
            return {}
    
    def _identify_social_engineering(self, text: str) -> List[str]:
        """Identify social engineering tactics"""
        tactics = []
        
        # Fear tactics
        fear_patterns = [
            'account will be closed', 'suspended', 'blocked', 'terminated',
            'legal action', 'fraud alert', 'security breach'
        ]
        
        for pattern in fear_patterns:
            if pattern in text:
                tactics.append(f"fear_tactic: {pattern}")
        
        # Urgency tactics
        urgency_patterns = [
            'expires today', 'limited time', 'act now', 'immediate action'
        ]
        
        for pattern in urgency_patterns:
            if pattern in text:
                tactics.append(f"urgency_tactic: {pattern}")
        
        # Authority tactics
        authority_patterns = [
            'official notice', 'government agency', 'legal department',
            'compliance team', 'security department'
        ]
        
        for pattern in authority_patterns:
            if pattern in text:
                tactics.append(f"authority_tactic: {pattern}")
        
        return tactics
    
    def _analyze_keyword_matches(self, text: str) -> Dict[str, int]:
        """Analyze keyword matches for different threat categories"""
        keyword_matches = defaultdict(int)
        
        # Financial keywords
        financial_keywords = [
            'bank account', 'credit card', 'wire transfer', 'payment',
            'invoice', 'refund', 'transaction', 'billing'
        ]
        
        for keyword in financial_keywords:
            if keyword in text:
                keyword_matches['financial'] += 1
        
        # Credential harvesting keywords
        credential_keywords = [
            'password', 'login', 'username', 'verify account', 'update information'
        ]
        
        for keyword in credential_keywords:
            if keyword in text:
                keyword_matches['credential_harvesting'] += 1
        
        # Malware delivery keywords
        malware_keywords = [
            'download', 'attachment', 'click here', 'install', 'update software'
        ]
        
        for keyword in malware_keywords:
            if keyword in text:
                keyword_matches['malware_delivery'] += 1
        
        return dict(keyword_matches)
    
    def _calculate_readability_score(self, text: str) -> float:
        """Calculate readability score (simplified Flesch Reading Ease)"""
        try:
            sentences = len(re.split(r'[.!?]+', text))
            words = len(text.split())
            syllables = sum(self._count_syllables(word) for word in text.split())
            
            if sentences == 0 or words == 0:
                return 0.0
            
            # Simplified Flesch Reading Ease formula
            score = 206.835 - (1.015 * (words / sentences)) - (84.6 * (syllables / words))
            
            # Normalize to 0-1 range (higher is more readable)
            normalized_score = max(0, min(100, score)) / 100
            
            return normalized_score
            
        except Exception:
            return 0.5  # Default average readability
    
    def _count_syllables(self, word: str) -> int:
        """Count syllables in a word (simplified implementation)"""
        word = word.lower()
        vowels = 'aeiouy'
        count = 0
        prev_was_vowel = False
        
        for char in word:
            is_vowel = char in vowels
            if is_vowel and not prev_was_vowel:
                count += 1
            prev_was_vowel = is_vowel
        
        # Handle silent 'e'
        if word.endswith('e'):
            count -= 1
        
        return max(1, count)  # At least one syllable
    
    # Continue with remaining methods in next part...
    
    async def _analyze_bec_indicators(self, headers: Dict[str, Any], 
                                    content: Dict[str, Any]) -> BECAnalysis:
        """Analyze Business Email Compromise indicators"""
        try:
            text_content = (content.get('plain_text', '') + ' ' + 
                          content.get('html_content', '')).lower()
            from_address = headers.get('from_address', '').lower()
            subject = headers.get('subject', '').lower()
            
            # Initialize BEC analysis
            is_bec_candidate = False
            executive_impersonation = False
            vendor_impersonation = False
            payroll_fraud_indicators = []
            wire_transfer_keywords = []
            invoice_fraud_indicators = []
            urgency_manipulation = []
            authority_manipulation = []
            trust_exploitation = []
            
            # Check for executive impersonation
            for title in self.executive_titles:
                if title in from_address or title in subject or title in text_content:
                    executive_impersonation = True
                    authority_manipulation.append(f"executive_title: {title}")
            
            # Check for vendor impersonation patterns
            for pattern in self.vendor_patterns:
                matches = re.findall(pattern, text_content)
                if matches:
                    vendor_impersonation = True
                    invoice_fraud_indicators.extend(matches)
            
            # Check BEC-specific keywords
            for category, keywords in self.bec_keywords.items():
                for keyword in keywords:
                    if keyword in text_content:
                        if category == 'urgency':
                            urgency_manipulation.append(keyword)
                        elif category == 'financial':
                            wire_transfer_keywords.append(keyword)
                        elif category == 'manipulation':
                            trust_exploitation.append(keyword)
            
            # Payroll fraud indicators
            payroll_keywords = [
                'payroll', 'employee', 'salary', 'wages', 'direct deposit',
                'bank routing', 'account change', 'hr department'
            ]
            
            for keyword in payroll_keywords:
                if keyword in text_content:
                    payroll_fraud_indicators.append(keyword)
            
            # Determine if this is a BEC candidate
            is_bec_candidate = (
                executive_impersonation or 
                vendor_impersonation or 
                len(payroll_fraud_indicators) > 0 or
                len(wire_transfer_keywords) > 2 or
                len(urgency_manipulation) > 1
            )
            
            return BECAnalysis(
                is_bec_candidate=is_bec_candidate,
                executive_impersonation=executive_impersonation,
                vendor_impersonation=vendor_impersonation,
                payroll_fraud_indicators=payroll_fraud_indicators,
                wire_transfer_keywords=wire_transfer_keywords,
                invoice_fraud_indicators=invoice_fraud_indicators,
                urgency_manipulation=urgency_manipulation,
                authority_manipulation=authority_manipulation,
                trust_exploitation=trust_exploitation
            )
            
        except Exception as e:
            logger.error(f"Error analyzing BEC indicators: {str(e)}")
            return BECAnalysis(
                is_bec_candidate=False, executive_impersonation=False,
                vendor_impersonation=False, payroll_fraud_indicators=[],
                wire_transfer_keywords=[], invoice_fraud_indicators=[],
                urgency_manipulation=[], authority_manipulation=[],
                trust_exploitation=[]
            )
    
    async def _detect_phishing_patterns(self, content: Dict[str, Any], 
                                       headers: Dict[str, Any]) -> List[PhishingIndicator]:
        """Detect phishing patterns using rule-based analysis"""
        indicators = []
        
        try:
            text_content = (content.get('plain_text', '') + ' ' + 
                          content.get('html_content', '')).lower()
            
            # Check each pattern category
            for category, patterns in self.compiled_patterns.items():
                for pattern in patterns:
                    matches = pattern.findall(text_content)
                    if matches:
                        confidence = 0.7 + (len(matches) * 0.1)  # Increase confidence with more matches
                        confidence = min(confidence, 1.0)
                        
                        indicator = PhishingIndicator(
                            indicator_type=f"pattern_{category}",
                            description=f"{category.title()} pattern detected: {pattern.pattern}",
                            confidence=confidence,
                            weight=0.15,
                            evidence={"matches": matches, "count": len(matches)},
                            severity="medium" if confidence > 0.8 else "low"
                        )
                        indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error detecting phishing patterns: {str(e)}")
            return []
    
    async def _ml_phishing_classification(self, headers: Dict[str, Any], 
                                        content: Dict[str, Any],
                                        domain_analysis: DomainAnalysis,
                                        content_analysis: ContentAnalysis) -> Dict[str, float]:
        """Machine learning-based phishing classification"""
        try:
            # Extract features for ML model
            features = self._extract_ml_features(headers, content, domain_analysis, content_analysis)
            
            # Apply feature weights and calculate prediction
            weighted_score = 0.0
            confidence = 0.0
            
            for feature_name, feature_value in features.items():
                if feature_name in self.ml_feature_weights:
                    weight = self.ml_feature_weights[feature_name]
                    weighted_score += feature_value * weight
                    confidence += weight
            
            # Normalize scores
            if confidence > 0:
                phishing_probability = min(weighted_score / confidence, 1.0)
                confidence_score = min(confidence, 1.0)
            else:
                phishing_probability = 0.0
                confidence_score = 0.0
            
            return {
                'phishing_probability': phishing_probability,
                'confidence': confidence_score,
                'features': features,
                'model_version': '1.0.0'
            }
            
        except Exception as e:
            logger.error(f"Error in ML phishing classification: {str(e)}")
            return {'phishing_probability': 0.0, 'confidence': 0.0}
    
    def _extract_ml_features(self, headers: Dict[str, Any], content: Dict[str, Any],
                           domain_analysis: DomainAnalysis, 
                           content_analysis: ContentAnalysis) -> Dict[str, float]:
        """Extract features for ML model"""
        features = {}
        
        try:
            # Domain-based features
            features['domain_reputation'] = 1.0 - domain_analysis.reputation_score
            features['domain_suspicious'] = 1.0 if domain_analysis.is_suspicious else 0.0
            features['typosquatting_score'] = domain_analysis.typosquatting_score
            features['homograph_attack'] = 1.0 if domain_analysis.is_homograph else 0.0
            
            # Content-based features
            features['urgency_score'] = content_analysis.urgency_score
            features['authority_score'] = content_analysis.authority_score
            features['deception_indicators'] = min(len(content_analysis.deception_indicators) / 5, 1.0)
            features['social_engineering'] = min(len(content_analysis.social_engineering_tactics) / 10, 1.0)
            
            # URL-based features
            urls = content.get('urls', [])
            features['url_count'] = min(len(urls) / 20, 1.0)
            features['external_links'] = min(len(content.get('external_links', [])) / 15, 1.0)
            
            # Authentication features
            features['missing_auth'] = 1.0 if not headers.get('dkim_signature') and not headers.get('spf_result') else 0.0
            
            # Structural features
            features['has_attachments'] = 1.0 if content.get('attachments') else 0.0
            features['has_scripts'] = 1.0 if content.get('has_scripts') else 0.0
            features['has_forms'] = 1.0 if content.get('has_forms') else 0.0
            
            # Linguistic features
            linguistic = content_analysis.linguistic_patterns
            features['excessive_caps'] = linguistic.get('excessive_caps', 0.0)
            features['repeated_punctuation'] = linguistic.get('repeated_punctuation', 0.0)
            features['word_repetition'] = linguistic.get('word_repetition', 0.0)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting ML features: {str(e)}")
            return {}
    
    async def _detect_brand_impersonation(self, headers: Dict[str, Any], 
                                        content: Dict[str, Any]) -> List[PhishingIndicator]:
        """Detect brand impersonation attempts"""
        indicators = []
        
        try:
            text_content = (content.get('plain_text', '') + ' ' + 
                          content.get('html_content', '')).lower()
            from_address = headers.get('from_address', '').lower()
            subject = headers.get('subject', '').lower()
            
            all_text = f"{from_address} {subject} {text_content}"
            
            # Check for brand mentions without legitimate domain
            for category, brands in self.legitimate_brands.items():
                for brand in brands:
                    brand_lower = brand.lower()
                    
                    # Check if brand is mentioned in text
                    if brand_lower in all_text:
                        # Check if sender domain is legitimate for this brand
                        sender_domain = from_address.split('@')[1] if '@' in from_address else ''
                        
                        # Simple check - in production would use comprehensive domain mapping
                        is_legitimate_domain = any(
                            legitimate in sender_domain 
                            for legitimate in self.legitimate_domains
                            if brand_lower.replace(' ', '') in legitimate
                        )
                        
                        if not is_legitimate_domain:
                            confidence = 0.8
                            if brand_lower in subject:
                                confidence += 0.1  # Higher confidence if in subject
                            
                            indicator = PhishingIndicator(
                                indicator_type="brand_impersonation",
                                description=f"Impersonation of {brand} ({category}) detected",
                                confidence=min(confidence, 1.0),
                                weight=0.25,
                                evidence={
                                    "brand": brand,
                                    "category": category,
                                    "sender_domain": sender_domain,
                                    "mentioned_in": "subject" if brand_lower in subject else "content"
                                },
                                severity="high"
                            )
                            indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error detecting brand impersonation: {str(e)}")
            return []
    
    async def _analyze_urls(self, urls: List[str]) -> List[PhishingIndicator]:
        """Analyze URLs for suspicious characteristics"""
        indicators = []
        
        try:
            for url in urls:
                url_indicators = await self._analyze_single_url(url)
                indicators.extend(url_indicators)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error analyzing URLs: {str(e)}")
            return []
    
    async def _analyze_single_url(self, url: str) -> List[PhishingIndicator]:
        """Analyze a single URL for suspicious characteristics"""
        indicators = []
        
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly',  # URL shorteners
                r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
                r'[a-z0-9]{20,}',  # Very long random strings
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url):
                    indicator = PhishingIndicator(
                        indicator_type="suspicious_url",
                        description=f"Suspicious URL pattern: {pattern}",
                        confidence=0.7,
                        weight=0.2,
                        evidence={"url": url, "pattern": pattern},
                        severity="medium"
                    )
                    indicators.append(indicator)
            
            # Check for suspicious path patterns
            suspicious_paths = [
                'login', 'signin', 'verify', 'update', 'secure', 'account',
                'confirm', 'validate', 'authenticate', 'portal'
            ]
            
            for suspicious_path in suspicious_paths:
                if suspicious_path in path:
                    indicator = PhishingIndicator(
                        indicator_type="suspicious_url_path",
                        description=f"Suspicious URL path: {suspicious_path}",
                        confidence=0.6,
                        weight=0.15,
                        evidence={"url": url, "path_element": suspicious_path},
                        severity="low"
                    )
                    indicators.append(indicator)
            
            # Check for homograph attacks in domain
            if self._detect_homograph_attack(domain):
                indicator = PhishingIndicator(
                    indicator_type="url_homograph",
                    description="Potential homograph attack in URL domain",
                    confidence=0.9,
                    weight=0.3,
                    evidence={"url": url, "domain": domain},
                    severity="high"
                )
                indicators.append(indicator)
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return []
    
    def _calculate_overall_score(self, indicators: List[PhishingIndicator],
                               ml_prediction: Dict[str, float],
                               domain_analysis: DomainAnalysis,
                               content_analysis: ContentAnalysis,
                               bec_analysis: BECAnalysis) -> Tuple[float, PhishingConfidence]:
        """Calculate overall phishing score and confidence level"""
        try:
            # Start with ML prediction if available
            base_score = ml_prediction.get('phishing_probability', 0.0)
            
            # Add weighted indicator scores
            indicator_score = 0.0
            total_weight = 0.0
            
            for indicator in indicators:
                weighted_contribution = indicator.confidence * indicator.weight
                indicator_score += weighted_contribution
                total_weight += indicator.weight
            
            # Normalize indicator score
            if total_weight > 0:
                indicator_score = indicator_score / total_weight
            
            # Combine scores
            combined_score = (base_score * 0.4) + (indicator_score * 0.6)
            
            # Apply domain analysis boost
            if domain_analysis.is_suspicious:
                combined_score += 0.1
            
            if domain_analysis.typosquatting_score > 0.7:
                combined_score += 0.15
            
            # Apply content analysis boost
            if content_analysis.urgency_score > 0.8:
                combined_score += 0.1
            
            if len(content_analysis.deception_indicators) > 3:
                combined_score += 0.1
            
            # Apply BEC analysis boost
            if bec_analysis.is_bec_candidate:
                combined_score += 0.2
            
            # Ensure score is within bounds
            final_score = max(0.0, min(1.0, combined_score))
            
            # Determine confidence level
            if final_score >= 0.9:
                confidence_level = PhishingConfidence.CONFIRMED
            elif final_score >= 0.8:
                confidence_level = PhishingConfidence.VERY_HIGH
            elif final_score >= 0.7:
                confidence_level = PhishingConfidence.HIGH
            elif final_score >= 0.5:
                confidence_level = PhishingConfidence.MEDIUM
            elif final_score >= 0.3:
                confidence_level = PhishingConfidence.LOW
            else:
                confidence_level = PhishingConfidence.VERY_LOW
            
            return final_score, confidence_level
            
        except Exception as e:
            logger.error(f"Error calculating overall score: {str(e)}")
            return 0.5, PhishingConfidence.MEDIUM
    
    def _identify_threat_types(self, indicators: List[PhishingIndicator],
                             bec_analysis: BECAnalysis) -> List[PhishingThreatType]:
        """Identify specific threat types based on analysis"""
        threat_types = []
        
        try:
            # Check indicator types for threat classification
            indicator_types = [ind.indicator_type for ind in indicators]
            
            # Credential harvesting
            if any('credential' in ind_type for ind_type in indicator_types):
                threat_types.append(PhishingThreatType.CREDENTIAL_HARVESTING)
            
            # Brand impersonation
            if any('brand_impersonation' in ind_type for ind_type in indicator_types):
                threat_types.append(PhishingThreatType.BRAND_IMPERSONATION)
            
            # Financial fraud
            if any('financial' in ind_type for ind_type in indicator_types):
                threat_types.append(PhishingThreatType.FINANCIAL_FRAUD)
            
            # Business Email Compromise
            if bec_analysis.is_bec_candidate:
                threat_types.append(PhishingThreatType.BUSINESS_EMAIL_COMPROMISE)
                
                if bec_analysis.executive_impersonation:
                    threat_types.append(PhishingThreatType.WHALING)
                
                if bec_analysis.vendor_impersonation:
                    threat_types.append(PhishingThreatType.SPEAR_PHISHING)
            
            # Social engineering
            social_engineering_indicators = [
                ind for ind in indicators 
                if 'authority' in ind.indicator_type or 'urgency' in ind.indicator_type
            ]
            if social_engineering_indicators:
                threat_types.append(PhishingThreatType.SOCIAL_ENGINEERING)
            
            # Default if no specific type identified
            if not threat_types:
                threat_types.append(PhishingThreatType.SOCIAL_ENGINEERING)
            
            return threat_types
            
        except Exception as e:
            logger.error(f"Error identifying threat types: {str(e)}")
            return [PhishingThreatType.SOCIAL_ENGINEERING]
    
    def _calculate_false_positive_likelihood(self, indicators: List[PhishingIndicator],
                                           domain_analysis: DomainAnalysis,
                                           content_analysis: ContentAnalysis) -> float:
        """Calculate likelihood of false positive"""
        try:
            false_positive_score = 0.0
            
            # Legitimate domain reduces false positive likelihood
            if not domain_analysis.is_suspicious:
                false_positive_score += 0.3
            
            # Proper authentication reduces false positive likelihood
            if domain_analysis.reputation_score > 0.7:
                false_positive_score += 0.2
            
            # Low urgency indicates legitimate email
            if content_analysis.urgency_score < 0.3:
                false_positive_score += 0.2
            
            # Few deception indicators
            if len(content_analysis.deception_indicators) == 0:
                false_positive_score += 0.15
            
            # High readability suggests legitimate content
            if content_analysis.readability_score > 0.7:
                false_positive_score += 0.1
            
            # Few suspicious indicators overall
            high_confidence_indicators = [
                ind for ind in indicators if ind.confidence > 0.8
            ]
            if len(high_confidence_indicators) == 0:
                false_positive_score += 0.05
            
            return min(false_positive_score, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating false positive likelihood: {str(e)}")
            return 0.5
    
    def _determine_recommended_action(self, overall_score: float,
                                    confidence_level: PhishingConfidence,
                                    false_positive_likelihood: float) -> str:
        """Determine recommended action based on analysis"""
        try:
            if overall_score >= 0.9 and false_positive_likelihood < 0.2:
                return "BLOCK_IMMEDIATELY"
            elif overall_score >= 0.8 and false_positive_likelihood < 0.3:
                return "QUARANTINE_AND_ALERT"
            elif overall_score >= 0.7:
                return "FLAG_FOR_REVIEW"
            elif overall_score >= 0.5:
                return "MONITOR_AND_LOG"
            elif overall_score >= 0.3:
                return "LOG_ONLY"
            else:
                return "ALLOW"
                
        except Exception:
            return "FLAG_FOR_REVIEW"
    
    async def _store_detection_result(self, result: PhishingDetectionResult):
        """Store detection result in database"""
        try:
            detection_id = str(uuid.uuid4())
            
            # Store main detection record
            self.db_connection.execute('''
                INSERT INTO phishing_detections 
                (detection_id, email_id, detection_timestamp, is_phishing, 
                 confidence_level, overall_score, threat_types, indicators_count,
                 ml_prediction, false_positive_likelihood, recommended_action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detection_id,
                result.email_id,
                result.detection_timestamp.timestamp(),
                result.is_phishing,
                result.confidence_level.value,
                result.overall_score,
                json.dumps([t.value for t in result.threat_types]),
                len(result.indicators),
                result.ml_prediction.get('phishing_probability', 0.0),
                result.false_positive_likelihood,
                result.recommended_action
            ))
            
            # Store indicators
            for i, indicator in enumerate(result.indicators):
                indicator_id = f"{detection_id}_{i}"
                self.db_connection.execute('''
                    INSERT INTO detection_indicators
                    (indicator_id, detection_id, indicator_type, description,
                     confidence, weight, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator_id,
                    detection_id,
                    indicator.indicator_type,
                    indicator.description,
                    indicator.confidence,
                    indicator.weight,
                    json.dumps(indicator.evidence)
                ))
            
            self.db_connection.commit()
            logger.debug(f"Stored detection result for email {result.email_id}")
            
        except Exception as e:
            logger.error(f"Error storing detection result: {str(e)}")
    
    def _update_detection_stats(self, result: PhishingDetectionResult, start_time: datetime):
        """Update detection performance statistics"""
        try:
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            self.detection_stats['total_analyzed'] += 1
            self.detection_stats['processing_times'].append(processing_time)
            
            if result.is_phishing:
                self.detection_stats['phishing_detected'] += 1
            
            # Keep only recent processing times for performance calculation
            if len(self.detection_stats['processing_times']) > 1000:
                self.detection_stats['processing_times'] = self.detection_stats['processing_times'][-1000:]
            
        except Exception as e:
            logger.error(f"Error updating detection stats: {str(e)}")
    
    def get_detection_statistics(self) -> Dict[str, Any]:
        """Get detection engine performance statistics"""
        try:
            processing_times = self.detection_stats['processing_times']
            
            stats = {
                'total_analyzed': self.detection_stats['total_analyzed'],
                'phishing_detected': self.detection_stats['phishing_detected'],
                'detection_rate': (
                    self.detection_stats['phishing_detected'] / 
                    max(self.detection_stats['total_analyzed'], 1) * 100
                ),
                'avg_processing_time': (
                    sum(processing_times) / len(processing_times) 
                    if processing_times else 0.0
                ),
                'min_processing_time': min(processing_times) if processing_times else 0.0,
                'max_processing_time': max(processing_times) if processing_times else 0.0
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting detection statistics: {str(e)}")
            return {}
    
    def __del__(self):
        """Cleanup database connection"""
        try:
            if hasattr(self, 'db_connection'):
                self.db_connection.close()
        except Exception:
            pass


# Example usage and testing
async def main():
    """Example usage of PhishingDetectionEngine"""
    engine = PhishingDetectionEngine()
    
    # Example email data for testing
    test_email_data = {
        'email_id': 'test_email_001',
        'headers': {
            'from_address': 'security@paypaI.com',  # Note the capital I instead of l
            'subject': 'Urgent: Verify your PayPal account immediately',
            'to_addresses': ['user@isectech.com']
        },
        'content': {
            'plain_text': '''
            Dear Valued Customer,
            
            We have detected suspicious activity on your PayPal account.
            Your account will be suspended unless you verify your identity immediately.
            
            Click here to verify your account: http://paypal-verification.suspicious-domain.tk/login
            
            This request is urgent and must be completed within 24 hours.
            
            Thank you,
            PayPal Security Team
            ''',
            'urls': ['http://paypal-verification.suspicious-domain.tk/login'],
            'external_links': ['http://paypal-verification.suspicious-domain.tk/login'],
            'has_scripts': False,
            'has_forms': False
        },
        'attachments': []
    }
    
    try:
        # Perform phishing detection
        result = await engine.detect_phishing(test_email_data)
        
        print(f"Phishing Detection Result:")
        print(f"  Email ID: {result.email_id}")
        print(f"  Is Phishing: {result.is_phishing}")
        print(f"  Overall Score: {result.overall_score:.2f}")
        print(f"  Confidence: {result.confidence_level.value}")
        print(f"  Threat Types: {[t.value for t in result.threat_types]}")
        print(f"  Recommended Action: {result.recommended_action}")
        print(f"  False Positive Likelihood: {result.false_positive_likelihood:.2f}")
        
        print(f"\nDetection Indicators ({len(result.indicators)}):")
        for indicator in result.indicators:
            print(f"  - {indicator.indicator_type}: {indicator.description} "
                  f"(confidence: {indicator.confidence:.2f})")
        
        # Print domain analysis
        print(f"\nDomain Analysis:")
        print(f"  Domain: {result.domain_analysis.domain}")
        print(f"  Suspicious: {result.domain_analysis.is_suspicious}")
        print(f"  Reputation Score: {result.domain_analysis.reputation_score:.2f}")
        print(f"  Typosquatting Score: {result.domain_analysis.typosquatting_score:.2f}")
        print(f"  Similar Domains: {result.domain_analysis.similar_domains}")
        
        # Print BEC analysis
        print(f"\nBEC Analysis:")
        print(f"  BEC Candidate: {result.bec_analysis.is_bec_candidate}")
        print(f"  Executive Impersonation: {result.bec_analysis.executive_impersonation}")
        print(f"  Vendor Impersonation: {result.bec_analysis.vendor_impersonation}")
        
        # Get engine statistics
        stats = engine.get_detection_statistics()
        print(f"\nEngine Statistics:")
        for key, value in stats.items():
            if isinstance(value, float):
                print(f"  {key}: {value:.3f}")
            else:
                print(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())