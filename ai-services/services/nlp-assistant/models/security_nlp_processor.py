"""
Security NLP Processor for iSECTECH Platform.

This module provides the core NLP processing capabilities tailored specifically for
cybersecurity use cases, including threat analysis, event classification, and
security context understanding.
"""

import asyncio
import logging
import re
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
import spacy
import torch
from pydantic import BaseModel, Field, validator
from transformers import (
    AutoModel,
    AutoTokenizer,
    pipeline,
    DistilBertForSequenceClassification,
    BertForSequenceClassification,
)

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.encryption import SecurityEncryption
from ...shared.security.audit import AuditLogger


# Configure logging
logger = logging.getLogger(__name__)


class ThreatSeverity(str, Enum):
    """Threat severity levels aligned with cybersecurity standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class EventCategory(str, Enum):
    """Security event categories for classification."""
    MALWARE = "MALWARE"
    INTRUSION = "INTRUSION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    INSIDER_THREAT = "INSIDER_THREAT"
    PHISHING = "PHISHING"
    VULNERABILITY = "VULNERABILITY"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    AUTHENTICATION = "AUTHENTICATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COMMAND_CONTROL = "COMMAND_CONTROL"
    RECONNAISSANCE = "RECONNAISSANCE"


class SecurityContext(BaseModel):
    """Security context container for NLP processing."""
    
    # Event metadata
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    source_system: str = Field(..., description="Source system generating the event")
    
    # Security classification
    classification: SecurityClassification = Field(
        default=SecurityClassification.UNCLASSIFIED,
        description="Security classification level"
    )
    
    # Event details
    event_type: str = Field(..., description="Type of security event")
    raw_message: str = Field(..., description="Raw event message or log")
    structured_data: Dict[str, Any] = Field(default_factory=dict, description="Structured event data")
    
    # Context enrichment
    asset_info: Optional[Dict[str, Any]] = Field(default=None, description="Asset context information")
    user_context: Optional[Dict[str, Any]] = Field(default=None, description="User context information")
    network_context: Optional[Dict[str, Any]] = Field(default=None, description="Network context information")
    
    # Threat intelligence
    threat_indicators: List[str] = Field(default_factory=list, description="Threat indicators (IOCs)")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator("event_id")
    def validate_event_id(cls, v):
        """Validate event ID format."""
        if not v or len(v) < 8:
            raise ValueError("Event ID must be at least 8 characters long")
        return v
    
    @validator("tenant_id")
    def validate_tenant_id(cls, v):
        """Validate tenant ID format."""
        if not v or len(v) < 3:
            raise ValueError("Tenant ID must be at least 3 characters long")
        return v


class NLPProcessingResult(BaseModel):
    """Result container for NLP processing operations."""
    
    # Processing metadata
    processing_id: str = Field(..., description="Unique processing identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    
    # Classification results
    event_category: EventCategory = Field(..., description="Classified event category")
    threat_severity: ThreatSeverity = Field(..., description="Assessed threat severity")
    confidence_score: float = Field(..., description="Classification confidence (0-1)")
    
    # Extracted entities and keywords
    entities: Dict[str, List[str]] = Field(default_factory=dict, description="Named entities extracted")
    keywords: List[str] = Field(default_factory=list, description="Security-relevant keywords")
    indicators: List[str] = Field(default_factory=list, description="Threat indicators extracted")
    
    # Semantic analysis
    intent: str = Field(..., description="Detected security intent")
    emotion_sentiment: float = Field(..., description="Sentiment score (-1 to 1)")
    urgency_score: float = Field(..., description="Urgency assessment (0-1)")
    
    # Context understanding
    affected_assets: List[str] = Field(default_factory=list, description="Potentially affected assets")
    related_events: List[str] = Field(default_factory=list, description="Related event IDs")
    
    @validator("confidence_score", "emotion_sentiment", "urgency_score")
    def validate_score_range(cls, v):
        """Validate score ranges."""
        if not -1 <= v <= 1:
            raise ValueError("Scores must be between -1 and 1")
        return v


class SecurityNLPProcessor:
    """
    Production-grade NLP processor for cybersecurity events and text analysis.
    
    Provides specialized NLP capabilities for threat analysis, event classification,
    and security context understanding tailored for the iSECTECH platform.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the security NLP processor."""
        self.settings = settings or get_settings()
        self.encryption = SecurityEncryption(self.settings.security)
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Model configuration
        self.device = torch.device("cuda" if torch.cuda.is_available() and self.settings.ml.enable_gpu else "cpu")
        self.max_length = self.settings.ml.max_sequence_length
        
        # Initialize models and processors
        self._models: Dict[str, Any] = {}
        self._tokenizers: Dict[str, Any] = {}
        self._nlp_pipeline = None
        self._classification_pipeline = None
        self._entity_pipeline = None
        
        # Security-specific patterns and vocabularies
        self._threat_patterns = self._load_threat_patterns()
        self._security_vocabulary = self._load_security_vocabulary()
        self._mitre_mapping = self._load_mitre_mapping()
        
        # Performance metrics
        self._processing_metrics = {
            "total_processed": 0,
            "average_processing_time": 0.0,
            "error_count": 0,
            "cache_hits": 0,
        }
        
        # Initialize components
        asyncio.create_task(self._initialize_models())
    
    async def _initialize_models(self) -> None:
        """Initialize NLP models and pipelines."""
        try:
            logger.info("Initializing security NLP models...")
            
            # Load spaCy model for entity recognition
            self._nlp_pipeline = spacy.load("en_core_web_sm")
            
            # Add custom security entity patterns
            ruler = self._nlp_pipeline.add_pipe("entity_ruler", before="ner")
            ruler.add_patterns(self._get_security_patterns())
            
            # Initialize transformer models for classification
            model_name = "distilbert-base-uncased"
            self._tokenizers["classification"] = AutoTokenizer.from_pretrained(model_name)
            self._models["classification"] = DistilBertForSequenceClassification.from_pretrained(
                model_name,
                num_labels=len(EventCategory),
            ).to(self.device)
            
            # Initialize sentiment analysis pipeline
            self._classification_pipeline = pipeline(
                "sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment-latest",
                device=0 if self.device.type == "cuda" else -1,
            )
            
            # Initialize threat classification pipeline
            self._entity_pipeline = pipeline(
                "ner",
                model="dbmdz/bert-large-cased-finetuned-conll03-english",
                aggregation_strategy="simple",
                device=0 if self.device.type == "cuda" else -1,
            )
            
            logger.info("Security NLP models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize NLP models: {e}")
            await self.audit_logger.log_security_event(
                event_type="MODEL_INITIALIZATION_FAILED",
                details={"error": str(e)},
                severity="HIGH",
            )
            raise
    
    def _load_threat_patterns(self) -> Dict[str, List[str]]:
        """Load cybersecurity threat patterns and indicators."""
        return {
            "malware_indicators": [
                r"\b(?:trojan|virus|malware|ransomware|backdoor|rootkit|spyware)\b",
                r"\b(?:suspicious|malicious|infected|compromised)\b",
                r"\bmd5\s*:\s*[a-f0-9]{32}\b",
                r"\bsha256\s*:\s*[a-f0-9]{64}\b",
            ],
            "network_indicators": [
                r"\b(?:ddos|dos|botnet|c2|command.control)\b",
                r"\b(?:lateral.movement|privilege.escalation)\b",
                r"\b(?:port.scan|network.scan|reconnaissance)\b",
            ],
            "data_indicators": [
                r"\b(?:data.exfiltration|data.breach|unauthorized.access)\b",
                r"\b(?:sensitive.data|pii|personal.information|credit.card)\b",
                r"\b(?:sql.injection|xss|csrf|code.injection)\b",
            ],
            "authentication_indicators": [
                r"\b(?:brute.force|password.attack|credential.stuffing)\b",
                r"\b(?:failed.login|unauthorized.access|account.lockout)\b",
                r"\b(?:privilege.escalation|admin.access|root.access)\b",
            ],
        }
    
    def _load_security_vocabulary(self) -> Set[str]:
        """Load cybersecurity-specific vocabulary."""
        return {
            # Threat actors and tools
            "apt", "advanced persistent threat", "nation state", "cybercriminal",
            "hacker", "attacker", "adversary", "threat actor",
            # Attack vectors
            "phishing", "spear phishing", "watering hole", "drive by",
            "zero day", "exploit", "vulnerability", "cve",
            # Security controls
            "firewall", "antivirus", "ids", "ips", "siem", "soar",
            "endpoint protection", "network security", "access control",
            # Incident response
            "containment", "eradication", "recovery", "forensics",
            "incident response", "threat hunting", "malware analysis",
        }
    
    def _load_mitre_mapping(self) -> Dict[str, Dict[str, str]]:
        """Load MITRE ATT&CK framework mappings."""
        return {
            "tactics": {
                "initial_access": "TA0001",
                "execution": "TA0002", 
                "persistence": "TA0003",
                "privilege_escalation": "TA0004",
                "defense_evasion": "TA0005",
                "credential_access": "TA0006",
                "discovery": "TA0007",
                "lateral_movement": "TA0008",
                "collection": "TA0009",
                "command_and_control": "TA0011",
                "exfiltration": "TA0010",
                "impact": "TA0040",
            },
            "techniques": {
                "spearphishing_attachment": "T1566.001",
                "powershell": "T1059.001",
                "windows_command_shell": "T1059.003",
                "remote_desktop_protocol": "T1021.001",
                "valid_accounts": "T1078",
                "brute_force": "T1110",
                "data_encrypted_for_impact": "T1486",
                "network_service_scanning": "T1046",
            },
        }
    
    def _get_security_patterns(self) -> List[Dict[str, Any]]:
        """Get spaCy entity patterns for security terms."""
        patterns = []
        
        # IP address patterns
        patterns.append({
            "label": "IP_ADDRESS",
            "pattern": [{"TEXT": {"REGEX": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"}}]
        })
        
        # Hash patterns
        patterns.append({
            "label": "MD5_HASH",
            "pattern": [{"TEXT": {"REGEX": r"\b[a-f0-9]{32}\b"}}]
        })
        
        patterns.append({
            "label": "SHA256_HASH", 
            "pattern": [{"TEXT": {"REGEX": r"\b[a-f0-9]{64}\b"}}]
        })
        
        # Domain patterns
        patterns.append({
            "label": "DOMAIN",
            "pattern": [{"TEXT": {"REGEX": r"\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b"}}]
        })
        
        # CVE patterns
        patterns.append({
            "label": "CVE",
            "pattern": [{"TEXT": {"REGEX": r"\bCVE-\d{4}-\d{4,7}\b"}}]
        })
        
        return patterns
    
    async def process_security_event(
        self,
        context: SecurityContext,
        extract_entities: bool = True,
        classify_threat: bool = True,
        assess_urgency: bool = True,
    ) -> NLPProcessingResult:
        """
        Process a security event with comprehensive NLP analysis.
        
        Args:
            context: Security context containing event details
            extract_entities: Whether to extract named entities
            classify_threat: Whether to classify threat category
            assess_urgency: Whether to assess urgency level
            
        Returns:
            Comprehensive NLP processing results
        """
        start_time = datetime.utcnow()
        processing_id = f"nlp-{context.event_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Processing security event {context.event_id}")
            
            # Audit log the processing request
            await self.audit_logger.log_security_event(
                event_type="NLP_PROCESSING_STARTED",
                details={
                    "event_id": context.event_id,
                    "processing_id": processing_id,
                    "tenant_id": context.tenant_id,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Initialize result container
            result = NLPProcessingResult(
                processing_id=processing_id,
                event_category=EventCategory.NETWORK_ANOMALY,  # Default, will be updated
                threat_severity=ThreatSeverity.LOW,  # Default, will be updated
                confidence_score=0.0,
                intent="unknown",
                emotion_sentiment=0.0,
                urgency_score=0.0,
            )
            
            # Process the raw message
            text = context.raw_message
            if not text:
                text = str(context.structured_data)
            
            # Extract entities if requested
            if extract_entities:
                result.entities = await self._extract_entities(text)
                result.keywords = await self._extract_keywords(text)
                result.indicators = await self._extract_threat_indicators(text, context)
            
            # Classify threat if requested
            if classify_threat:
                category, severity, confidence = await self._classify_threat(text, context)
                result.event_category = category
                result.threat_severity = severity
                result.confidence_score = confidence
            
            # Assess urgency if requested
            if assess_urgency:
                result.intent = await self._detect_intent(text)
                result.emotion_sentiment = await self._analyze_sentiment(text)
                result.urgency_score = await self._assess_urgency(text, context)
            
            # Identify affected assets and related events
            result.affected_assets = await self._identify_affected_assets(text, context)
            result.related_events = await self._find_related_events(context)
            
            # Calculate processing time
            end_time = datetime.utcnow()
            result.processing_time_ms = (end_time - start_time).total_seconds() * 1000
            
            # Update metrics
            self._update_metrics(result.processing_time_ms)
            
            # Audit log successful processing
            await self.audit_logger.log_security_event(
                event_type="NLP_PROCESSING_COMPLETED",
                details={
                    "processing_id": processing_id,
                    "event_category": result.event_category,
                    "threat_severity": result.threat_severity,
                    "confidence_score": result.confidence_score,
                    "processing_time_ms": result.processing_time_ms,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Completed processing event {context.event_id} in {result.processing_time_ms:.2f}ms")
            return result
            
        except Exception as e:
            logger.error(f"Failed to process security event {context.event_id}: {e}")
            await self.audit_logger.log_security_event(
                event_type="NLP_PROCESSING_FAILED",
                details={
                    "processing_id": processing_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            self._processing_metrics["error_count"] += 1
            raise
    
    async def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extract named entities from security event text."""
        try:
            entities = {}
            
            # Use spaCy for general entity recognition
            doc = self._nlp_pipeline(text)
            for ent in doc.ents:
                if ent.label_ not in entities:
                    entities[ent.label_] = []
                entities[ent.label_].append(ent.text)
            
            # Use transformer model for additional entity extraction
            if self._entity_pipeline:
                transformer_entities = self._entity_pipeline(text)
                for entity in transformer_entities:
                    label = entity["entity_group"]
                    if label not in entities:
                        entities[label] = []
                    entities[label].append(entity["word"])
            
            # Remove duplicates and clean up
            for label in entities:
                entities[label] = list(set(entities[label]))
            
            return entities
            
        except Exception as e:
            logger.warning(f"Entity extraction failed: {e}")
            return {}
    
    async def _extract_keywords(self, text: str) -> List[str]:
        """Extract security-relevant keywords from text."""
        try:
            keywords = []
            text_lower = text.lower()
            
            # Find security vocabulary matches
            for word in self._security_vocabulary:
                if word in text_lower:
                    keywords.append(word)
            
            # Extract noun phrases using spaCy
            doc = self._nlp_pipeline(text)
            for chunk in doc.noun_chunks:
                if any(token.pos_ in ["NOUN", "PROPN"] for token in chunk):
                    keywords.append(chunk.text.lower())
            
            return list(set(keywords))
            
        except Exception as e:
            logger.warning(f"Keyword extraction failed: {e}")
            return []
    
    async def _extract_threat_indicators(self, text: str, context: SecurityContext) -> List[str]:
        """Extract threat indicators and IOCs from text."""
        try:
            indicators = []
            
            # Apply threat pattern matching
            for category, patterns in self._threat_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    indicators.extend(matches)
            
            # Add context-provided threat indicators
            indicators.extend(context.threat_indicators)
            
            return list(set(indicators))
            
        except Exception as e:
            logger.warning(f"Threat indicator extraction failed: {e}")
            return []
    
    async def _classify_threat(
        self, 
        text: str, 
        context: SecurityContext
    ) -> Tuple[EventCategory, ThreatSeverity, float]:
        """Classify threat category and severity."""
        try:
            # Simple rule-based classification for demonstration
            # In production, this would use a trained model
            text_lower = text.lower()
            
            # Determine category based on keywords and patterns
            if any(word in text_lower for word in ["malware", "virus", "trojan", "ransomware"]):
                category = EventCategory.MALWARE
                severity = ThreatSeverity.HIGH
            elif any(word in text_lower for word in ["phishing", "spear", "social engineering"]):
                category = EventCategory.PHISHING
                severity = ThreatSeverity.MEDIUM
            elif any(word in text_lower for word in ["intrusion", "breach", "unauthorized"]):
                category = EventCategory.INTRUSION
                severity = ThreatSeverity.HIGH
            elif any(word in text_lower for word in ["data", "exfiltration", "leak"]):
                category = EventCategory.DATA_EXFILTRATION
                severity = ThreatSeverity.CRITICAL
            else:
                category = EventCategory.NETWORK_ANOMALY
                severity = ThreatSeverity.LOW
            
            # Calculate confidence based on keyword matches
            confidence = min(0.95, len([w for w in text_lower.split() if w in self._security_vocabulary]) / 10)
            
            return category, severity, confidence
            
        except Exception as e:
            logger.warning(f"Threat classification failed: {e}")
            return EventCategory.NETWORK_ANOMALY, ThreatSeverity.LOW, 0.1
    
    async def _detect_intent(self, text: str) -> str:
        """Detect the security intent from the event text."""
        try:
            text_lower = text.lower()
            
            if any(word in text_lower for word in ["alert", "warning", "detected"]):
                return "threat_detection"
            elif any(word in text_lower for word in ["blocked", "prevented", "stopped"]):
                return "threat_prevention" 
            elif any(word in text_lower for word in ["investigate", "analyze", "review"]):
                return "investigation_required"
            elif any(word in text_lower for word in ["access", "login", "authentication"]):
                return "access_management"
            else:
                return "general_security_event"
                
        except Exception as e:
            logger.warning(f"Intent detection failed: {e}")
            return "unknown"
    
    async def _analyze_sentiment(self, text: str) -> float:
        """Analyze sentiment of the security event text."""
        try:
            if self._classification_pipeline:
                result = self._classification_pipeline(text)
                sentiment = result[0]["label"]
                score = result[0]["score"]
                
                # Convert to -1 to 1 scale
                if sentiment == "NEGATIVE":
                    return -score
                elif sentiment == "POSITIVE":
                    return score
                else:  # NEUTRAL
                    return 0.0
            
            return 0.0
            
        except Exception as e:
            logger.warning(f"Sentiment analysis failed: {e}")
            return 0.0
    
    async def _assess_urgency(self, text: str, context: SecurityContext) -> float:
        """Assess the urgency level of the security event."""
        try:
            urgency_score = 0.0
            text_lower = text.lower()
            
            # Keyword-based urgency assessment
            critical_words = ["critical", "urgent", "immediate", "emergency", "breach"]
            high_words = ["important", "high", "severe", "serious", "attack"]
            medium_words = ["moderate", "medium", "warning", "suspicious"]
            
            if any(word in text_lower for word in critical_words):
                urgency_score = 0.9
            elif any(word in text_lower for word in high_words):
                urgency_score = 0.7
            elif any(word in text_lower for word in medium_words):
                urgency_score = 0.5
            else:
                urgency_score = 0.3
            
            # Adjust based on context
            if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
                urgency_score = min(1.0, urgency_score + 0.2)
            
            if context.mitre_tactics:
                urgency_score = min(1.0, urgency_score + 0.1)
            
            return urgency_score
            
        except Exception as e:
            logger.warning(f"Urgency assessment failed: {e}")
            return 0.5
    
    async def _identify_affected_assets(self, text: str, context: SecurityContext) -> List[str]:
        """Identify potentially affected assets from the event."""
        try:
            assets = []
            
            # Extract from context if available
            if context.asset_info:
                assets.extend(context.asset_info.get("asset_names", []))
            
            # Extract from text using entity recognition
            entities = await self._extract_entities(text)
            for entity_type in ["ORG", "PERSON", "IP_ADDRESS", "DOMAIN"]:
                if entity_type in entities:
                    assets.extend(entities[entity_type])
            
            return list(set(assets))
            
        except Exception as e:
            logger.warning(f"Asset identification failed: {e}")
            return []
    
    async def _find_related_events(self, context: SecurityContext) -> List[str]:
        """Find related events based on context and indicators."""
        try:
            # This would typically query a database or event store
            # For now, return placeholder implementation
            related = []
            
            # Simple correlation based on time and asset
            # In production, this would use more sophisticated correlation algorithms
            
            return related
            
        except Exception as e:
            logger.warning(f"Related event finding failed: {e}")
            return []
    
    def _update_metrics(self, processing_time_ms: float) -> None:
        """Update processing performance metrics."""
        self._processing_metrics["total_processed"] += 1
        current_avg = self._processing_metrics["average_processing_time"]
        count = self._processing_metrics["total_processed"]
        
        # Calculate running average
        self._processing_metrics["average_processing_time"] = (
            (current_avg * (count - 1)) + processing_time_ms
        ) / count
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current processing metrics."""
        return self._processing_metrics.copy()
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            "device": str(self.device),
            "max_length": self.max_length,
            "models_loaded": list(self._models.keys()),
            "pipelines_available": {
                "classification": self._classification_pipeline is not None,
                "entity_extraction": self._entity_pipeline is not None,
                "nlp_processing": self._nlp_pipeline is not None,
            },
        }