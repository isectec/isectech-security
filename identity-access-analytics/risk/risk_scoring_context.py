"""
Risk Scoring and Context Engine for Identity and Access Analytics
================================================================

Production-grade risk scoring system that calculates comprehensive risk scores for users,
entities, and activities using advanced contextual analysis, behavioral baselines,
and threat intelligence integration.

Copyright (c) 2024 iSecTech. All Rights Reserved.
"""

import asyncio
import logging
import json
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from collections import defaultdict, deque
import aioredis
import sqlite3
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest, RandomForestRegressor
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import pandas as pd
import ipaddress
import geoip2.database
import geoip2.errors
import threading
import traceback
import ssl
import certifi
import asyncio
import aiohttp
from cryptography.fernet import Fernet
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RiskLevel(IntEnum):
    """Risk level enumeration"""
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    EXTREME = 6

class RiskCategory(Enum):
    """Risk category types"""
    BEHAVIORAL = "behavioral"
    CONTEXTUAL = "contextual" 
    PRIVILEGE = "privilege"
    THREAT_INTEL = "threat_intel"
    TEMPORAL = "temporal"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    ACCESS_PATTERN = "access_pattern"
    COMPLIANCE = "compliance"
    ANOMALY = "anomaly"

class ContextType(Enum):
    """Context analysis types"""
    LOCATION = "location"
    DEVICE = "device"
    TIME = "time"
    NETWORK = "network"  
    APPLICATION = "application"
    PEER_GROUP = "peer_group"
    ORGANIZATION = "organization"
    COMPLIANCE = "compliance"
    THREAT_LANDSCAPE = "threat_landscape"
    BUSINESS_CONTEXT = "business_context"

@dataclass
class RiskFactor:
    """Individual risk factor"""
    category: RiskCategory
    name: str
    value: float
    weight: float
    confidence: float
    evidence: Dict[str, Any]
    timestamp: datetime
    source: str
    context: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_weighted_score(self) -> float:
        """Calculate weighted risk score"""
        return (self.value * self.weight * self.confidence) / 100.0

@dataclass  
class ContextualRiskScore:
    """Contextual risk score with breakdown"""
    user_id: str
    entity_id: Optional[str]
    overall_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor]
    context_scores: Dict[ContextType, float]
    baseline_deviation: float
    peer_comparison: float
    temporal_trend: float
    confidence: float
    calculated_at: datetime
    expires_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'user_id': self.user_id,
            'entity_id': self.entity_id,
            'overall_score': self.overall_score,
            'risk_level': self.risk_level.name,
            'factors': [asdict(f) for f in self.factors],
            'context_scores': {k.value: v for k, v in self.context_scores.items()},
            'baseline_deviation': self.baseline_deviation,
            'peer_comparison': self.peer_comparison,
            'temporal_trend': self.temporal_trend,
            'confidence': self.confidence,
            'calculated_at': self.calculated_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'metadata': self.metadata
        }

@dataclass
class BehavioralBaseline:
    """User behavioral baseline"""
    user_id: str
    typical_hours: List[int]
    common_locations: List[Dict[str, Any]]
    usual_applications: Set[str]
    normal_data_volume: Dict[str, float]
    standard_session_duration: Tuple[float, float]  # mean, std
    peer_group_id: str
    last_updated: datetime
    confidence: float
    sample_size: int

@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    source: str
    indicator_type: str
    indicator_value: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    context: Dict[str, Any]
    tags: List[str]

@dataclass
class NetworkContext:
    """Network context information"""
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    isp: Optional[str]
    is_tor: bool
    is_vpn: bool
    is_datacenter: bool
    reputation_score: float
    first_seen: datetime
    frequency: int

class RiskCalculationEngine:
    """Core risk calculation engine"""
    
    def __init__(self, redis_client: Optional[aioredis.Redis] = None):
        self.redis_client = redis_client
        self.ml_models = {}
        self.feature_scalers = {}
        self.risk_thresholds = {
            RiskLevel.MINIMAL: (0, 20),
            RiskLevel.LOW: (20, 40),
            RiskLevel.MEDIUM: (40, 60),
            RiskLevel.HIGH: (60, 80),
            RiskLevel.CRITICAL: (80, 95),
            RiskLevel.EXTREME: (95, 100)
        }
        self._initialize_ml_models()
        
    def _initialize_ml_models(self):
        """Initialize machine learning models"""
        try:
            # Anomaly detection model
            self.ml_models['anomaly'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=200
            )
            
            # Risk prediction model
            self.ml_models['risk_predictor'] = RandomForestRegressor(
                n_estimators=300,
                max_depth=10,
                random_state=42
            )
            
            # Feature scalers
            self.feature_scalers['standard'] = StandardScaler()
            self.feature_scalers['minmax'] = MinMaxScaler()
            
            logger.info("ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            raise

    async def calculate_risk_score(self, user_id: str, context: Dict[str, Any],
                                 historical_data: List[Dict[str, Any]],
                                 threat_intel: List[ThreatIntelligence],
                                 baseline: Optional[BehavioralBaseline] = None) -> ContextualRiskScore:
        """Calculate comprehensive contextual risk score"""
        try:
            logger.info(f"Calculating risk score for user {user_id}")
            
            # Extract and analyze risk factors
            risk_factors = await self._extract_risk_factors(
                user_id, context, historical_data, threat_intel, baseline
            )
            
            # Calculate context-specific scores
            context_scores = await self._calculate_context_scores(
                context, historical_data, baseline
            )
            
            # Calculate baseline deviation
            baseline_deviation = await self._calculate_baseline_deviation(
                context, baseline, historical_data
            )
            
            # Calculate peer comparison
            peer_comparison = await self._calculate_peer_comparison(
                user_id, context, baseline
            )
            
            # Calculate temporal trend
            temporal_trend = await self._calculate_temporal_trend(
                user_id, historical_data
            )
            
            # Calculate overall risk score using weighted aggregation
            overall_score = await self._aggregate_risk_score(
                risk_factors, context_scores, baseline_deviation,
                peer_comparison, temporal_trend
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_score)
            
            # Calculate confidence score
            confidence = self._calculate_confidence(
                risk_factors, len(historical_data), baseline
            )
            
            # Create contextual risk score
            risk_score = ContextualRiskScore(
                user_id=user_id,
                entity_id=context.get('entity_id'),
                overall_score=overall_score,
                risk_level=risk_level,
                factors=risk_factors,
                context_scores=context_scores,
                baseline_deviation=baseline_deviation,
                peer_comparison=peer_comparison,
                temporal_trend=temporal_trend,
                confidence=confidence,
                calculated_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=1),
                metadata={
                    'calculation_version': '2.1.0',
                    'model_features': len(context),
                    'historical_samples': len(historical_data),
                    'threat_intel_matches': len(threat_intel)
                }
            )
            
            # Cache the result
            if self.redis_client:
                await self._cache_risk_score(risk_score)
            
            logger.info(f"Risk score calculated: {overall_score} ({risk_level.name}) for user {user_id}")
            return risk_score
            
        except Exception as e:
            logger.error(f"Failed to calculate risk score for user {user_id}: {e}")
            logger.error(traceback.format_exc())
            raise

    async def _extract_risk_factors(self, user_id: str, context: Dict[str, Any],
                                  historical_data: List[Dict[str, Any]],
                                  threat_intel: List[ThreatIntelligence],
                                  baseline: Optional[BehavioralBaseline]) -> List[RiskFactor]:
        """Extract individual risk factors"""
        factors = []
        
        try:
            # Behavioral risk factors
            behavioral_factors = await self._extract_behavioral_factors(
                user_id, context, historical_data, baseline
            )
            factors.extend(behavioral_factors)
            
            # Contextual risk factors
            contextual_factors = await self._extract_contextual_factors(
                context, historical_data
            )
            factors.extend(contextual_factors)
            
            # Privilege risk factors
            privilege_factors = await self._extract_privilege_factors(
                user_id, context
            )
            factors.extend(privilege_factors)
            
            # Threat intelligence factors
            threat_factors = await self._extract_threat_intel_factors(
                context, threat_intel
            )
            factors.extend(threat_factors)
            
            # Temporal risk factors
            temporal_factors = await self._extract_temporal_factors(
                context, historical_data
            )
            factors.extend(temporal_factors)
            
            # Network risk factors
            network_factors = await self._extract_network_factors(
                context, historical_data
            )
            factors.extend(network_factors)
            
            logger.info(f"Extracted {len(factors)} risk factors for user {user_id}")
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract risk factors: {e}")
            return []

    async def _extract_behavioral_factors(self, user_id: str, context: Dict[str, Any],
                                        historical_data: List[Dict[str, Any]],
                                        baseline: Optional[BehavioralBaseline]) -> List[RiskFactor]:
        """Extract behavioral risk factors"""
        factors = []
        
        try:
            if not baseline:
                return factors
                
            current_time = datetime.utcnow()
            
            # Time-based behavior analysis
            current_hour = current_time.hour
            if current_hour not in baseline.typical_hours:
                # Calculate how unusual this time is
                time_deviation = min([abs(current_hour - h) for h in baseline.typical_hours])
                unusual_time_score = min(time_deviation * 10, 100)
                
                factors.append(RiskFactor(
                    category=RiskCategory.BEHAVIORAL,
                    name="unusual_access_time",
                    value=unusual_time_score,
                    weight=0.7,
                    confidence=0.9,
                    evidence={
                        'current_hour': current_hour,
                        'typical_hours': baseline.typical_hours,
                        'deviation': time_deviation
                    },
                    timestamp=current_time,
                    source="behavioral_baseline",
                    context={'baseline_confidence': baseline.confidence}
                ))
            
            # Location-based behavior analysis
            current_location = context.get('location', {})
            if current_location:
                location_familiar = any(
                    self._calculate_location_similarity(current_location, loc) > 0.8
                    for loc in baseline.common_locations
                )
                
                if not location_familiar:
                    factors.append(RiskFactor(
                        category=RiskCategory.BEHAVIORAL,
                        name="unfamiliar_location",
                        value=75.0,
                        weight=0.8,
                        confidence=0.85,
                        evidence={
                            'current_location': current_location,
                            'known_locations': len(baseline.common_locations)
                        },
                        timestamp=current_time,
                        source="behavioral_baseline"
                    ))
            
            # Application usage analysis
            current_app = context.get('application')
            if current_app and current_app not in baseline.usual_applications:
                factors.append(RiskFactor(
                    category=RiskCategory.BEHAVIORAL,
                    name="unusual_application",
                    value=50.0,
                    weight=0.6,
                    confidence=0.8,
                    evidence={
                        'application': current_app,
                        'known_applications': list(baseline.usual_applications)
                    },
                    timestamp=current_time,
                    source="behavioral_baseline"
                ))
            
            # Data volume analysis
            data_volume = context.get('data_volume', 0)
            if data_volume > 0:
                expected_volume = baseline.normal_data_volume.get('mean', 0)
                volume_std = baseline.normal_data_volume.get('std', 1)
                
                if expected_volume > 0 and volume_std > 0:
                    z_score = abs(data_volume - expected_volume) / volume_std
                    if z_score > 2:  # More than 2 standard deviations
                        volume_risk = min(z_score * 20, 100)
                        factors.append(RiskFactor(
                            category=RiskCategory.BEHAVIORAL,
                            name="unusual_data_volume",
                            value=volume_risk,
                            weight=0.7,
                            confidence=0.85,
                            evidence={
                                'current_volume': data_volume,
                                'expected_volume': expected_volume,
                                'z_score': z_score
                            },
                            timestamp=current_time,
                            source="behavioral_baseline"
                        ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract behavioral factors: {e}")
            return []

    async def _extract_contextual_factors(self, context: Dict[str, Any],
                                        historical_data: List[Dict[str, Any]]) -> List[RiskFactor]:
        """Extract contextual risk factors"""
        factors = []
        current_time = datetime.utcnow()
        
        try:
            # Device context analysis
            device_info = context.get('device', {})
            if device_info:
                # New device check
                device_id = device_info.get('device_id')
                device_seen_before = any(
                    h.get('device', {}).get('device_id') == device_id
                    for h in historical_data[-100:]  # Check last 100 events
                )
                
                if not device_seen_before:
                    factors.append(RiskFactor(
                        category=RiskCategory.CONTEXTUAL,
                        name="new_device",
                        value=60.0,
                        weight=0.8,
                        confidence=0.9,
                        evidence={
                            'device_id': device_id,
                            'device_type': device_info.get('type'),
                            'os': device_info.get('os')
                        },
                        timestamp=current_time,
                        source="contextual_analysis"
                    ))
                
                # Suspicious device characteristics
                if device_info.get('is_virtual', False):
                    factors.append(RiskFactor(
                        category=RiskCategory.CONTEXTUAL,
                        name="virtual_device",
                        value=40.0,
                        weight=0.6,
                        confidence=0.8,
                        evidence={'device_info': device_info},
                        timestamp=current_time,
                        source="contextual_analysis"
                    ))
            
            # Session context analysis
            session_info = context.get('session', {})
            if session_info:
                # Concurrent sessions
                concurrent_sessions = session_info.get('concurrent_sessions', 0)
                if concurrent_sessions > 3:
                    factors.append(RiskFactor(
                        category=RiskCategory.CONTEXTUAL,
                        name="excessive_concurrent_sessions",
                        value=min(concurrent_sessions * 15, 100),
                        weight=0.7,
                        confidence=0.85,
                        evidence={'concurrent_sessions': concurrent_sessions},
                        timestamp=current_time,
                        source="contextual_analysis"
                    ))
                
                # Session duration anomaly
                session_duration = session_info.get('duration_minutes', 0)
                if session_duration > 480:  # More than 8 hours
                    factors.append(RiskFactor(
                        category=RiskCategory.CONTEXTUAL,
                        name="excessive_session_duration",
                        value=min(session_duration / 10, 100),
                        weight=0.6,
                        confidence=0.8,
                        evidence={'duration_minutes': session_duration},
                        timestamp=current_time,
                        source="contextual_analysis"
                    ))
            
            # Access pattern analysis
            access_pattern = context.get('access_pattern', {})
            if access_pattern:
                # Rapid consecutive accesses
                access_frequency = access_pattern.get('accesses_per_minute', 0)
                if access_frequency > 10:
                    factors.append(RiskFactor(
                        category=RiskCategory.CONTEXTUAL,
                        name="high_access_frequency",
                        value=min(access_frequency * 5, 100),
                        weight=0.8,
                        confidence=0.9,
                        evidence={'accesses_per_minute': access_frequency},
                        timestamp=current_time,
                        source="contextual_analysis"
                    ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract contextual factors: {e}")
            return []

    async def _extract_privilege_factors(self, user_id: str, context: Dict[str, Any]) -> List[RiskFactor]:
        """Extract privilege-related risk factors"""
        factors = []
        current_time = datetime.utcnow()
        
        try:
            privileges = context.get('privileges', {})
            if not privileges:
                return factors
            
            # Administrative privilege usage
            admin_privileges = privileges.get('admin_privileges', [])
            if admin_privileges:
                factors.append(RiskFactor(
                    category=RiskCategory.PRIVILEGE,
                    name="admin_privilege_usage",
                    value=min(len(admin_privileges) * 20, 100),
                    weight=0.9,
                    confidence=0.95,
                    evidence={'admin_privileges': admin_privileges},
                    timestamp=current_time,
                    source="privilege_analysis"
                ))
            
            # Elevated privilege escalation
            privilege_escalation = context.get('privilege_escalation', False)
            if privilege_escalation:
                factors.append(RiskFactor(
                    category=RiskCategory.PRIVILEGE,
                    name="privilege_escalation",
                    value=85.0,
                    weight=0.95,
                    confidence=0.9,
                    evidence={'escalation_detected': True},
                    timestamp=current_time,
                    source="privilege_analysis"
                ))
            
            # Sensitive data access
            data_classification = context.get('data_classification', {})
            sensitive_access = data_classification.get('sensitive_data_accessed', False)
            if sensitive_access:
                sensitivity_level = data_classification.get('max_sensitivity_level', 'medium')
                sensitivity_scores = {'low': 30, 'medium': 50, 'high': 70, 'critical': 90}
                
                factors.append(RiskFactor(
                    category=RiskCategory.PRIVILEGE,
                    name="sensitive_data_access",
                    value=sensitivity_scores.get(sensitivity_level, 50),
                    weight=0.8,
                    confidence=0.9,
                    evidence={
                        'sensitivity_level': sensitivity_level,
                        'data_types': data_classification.get('data_types', [])
                    },
                    timestamp=current_time,
                    source="privilege_analysis"
                ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract privilege factors: {e}")
            return []

    async def _extract_threat_intel_factors(self, context: Dict[str, Any],
                                          threat_intel: List[ThreatIntelligence]) -> List[RiskFactor]:
        """Extract threat intelligence risk factors"""
        factors = []
        current_time = datetime.utcnow()
        
        try:
            if not threat_intel:
                return factors
            
            # IP reputation analysis
            ip_address = context.get('ip_address')
            if ip_address:
                ip_threats = [
                    ti for ti in threat_intel
                    if ti.indicator_type == 'ip' and ti.indicator_value == ip_address
                ]
                
                for threat in ip_threats:
                    severity_scores = {
                        'low': 30, 'medium': 50, 'high': 75, 'critical': 95
                    }
                    
                    factors.append(RiskFactor(
                        category=RiskCategory.THREAT_INTEL,
                        name="malicious_ip",
                        value=severity_scores.get(threat.severity.lower(), 50),
                        weight=0.9,
                        confidence=threat.confidence,
                        evidence={
                            'ip_address': ip_address,
                            'threat_source': threat.source,
                            'severity': threat.severity,
                            'tags': threat.tags
                        },
                        timestamp=current_time,
                        source=f"threat_intel_{threat.source}"
                    ))
            
            # Domain reputation analysis
            domain = context.get('domain')
            if domain:
                domain_threats = [
                    ti for ti in threat_intel
                    if ti.indicator_type == 'domain' and ti.indicator_value == domain
                ]
                
                for threat in domain_threats:
                    severity_scores = {
                        'low': 25, 'medium': 45, 'high': 70, 'critical': 90
                    }
                    
                    factors.append(RiskFactor(
                        category=RiskCategory.THREAT_INTEL,
                        name="malicious_domain",
                        value=severity_scores.get(threat.severity.lower(), 45),
                        weight=0.8,
                        confidence=threat.confidence,
                        evidence={
                            'domain': domain,
                            'threat_source': threat.source,
                            'severity': threat.severity,
                            'tags': threat.tags
                        },
                        timestamp=current_time,
                        source=f"threat_intel_{threat.source}"
                    ))
            
            # File hash analysis
            file_hashes = context.get('file_hashes', [])
            for file_hash in file_hashes:
                hash_threats = [
                    ti for ti in threat_intel
                    if ti.indicator_type == 'hash' and ti.indicator_value == file_hash
                ]
                
                for threat in hash_threats:
                    factors.append(RiskFactor(
                        category=RiskCategory.THREAT_INTEL,
                        name="malicious_file",
                        value=80.0,
                        weight=0.85,
                        confidence=threat.confidence,
                        evidence={
                            'file_hash': file_hash,
                            'threat_source': threat.source,
                            'severity': threat.severity
                        },
                        timestamp=current_time,
                        source=f"threat_intel_{threat.source}"
                    ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract threat intel factors: {e}")
            return []

    async def _extract_temporal_factors(self, context: Dict[str, Any],
                                      historical_data: List[Dict[str, Any]]) -> List[RiskFactor]:
        """Extract temporal risk factors"""
        factors = []
        current_time = datetime.utcnow()
        
        try:
            # Off-hours access
            current_hour = current_time.hour
            current_day = current_time.weekday()
            
            # Weekend access (Saturday=5, Sunday=6)
            if current_day >= 5:
                factors.append(RiskFactor(
                    category=RiskCategory.TEMPORAL,
                    name="weekend_access",
                    value=35.0,
                    weight=0.6,
                    confidence=0.9,
                    evidence={
                        'day_of_week': current_day,
                        'hour': current_hour
                    },
                    timestamp=current_time,
                    source="temporal_analysis"
                ))
            
            # Night time access (10 PM to 6 AM)
            if current_hour >= 22 or current_hour <= 6:
                factors.append(RiskFactor(
                    category=RiskCategory.TEMPORAL,
                    name="night_access",
                    value=45.0,
                    weight=0.7,
                    confidence=0.85,
                    evidence={'hour': current_hour},
                    timestamp=current_time,
                    source="temporal_analysis"
                ))
            
            # Holiday access check
            if self._is_holiday(current_time):
                factors.append(RiskFactor(
                    category=RiskCategory.TEMPORAL,
                    name="holiday_access",
                    value=50.0,
                    weight=0.8,
                    confidence=0.9,
                    evidence={'date': current_time.date().isoformat()},
                    timestamp=current_time,
                    source="temporal_analysis"
                ))
            
            # Burst activity detection
            if len(historical_data) >= 10:
                recent_events = [
                    h for h in historical_data
                    if datetime.fromisoformat(h.get('timestamp', '1970-01-01'))
                    > current_time - timedelta(minutes=30)
                ]
                
                if len(recent_events) > 20:  # More than 20 events in 30 minutes
                    factors.append(RiskFactor(
                        category=RiskCategory.TEMPORAL,
                        name="burst_activity",
                        value=min(len(recent_events) * 3, 100),
                        weight=0.8,
                        confidence=0.9,
                        evidence={
                            'events_in_30min': len(recent_events),
                            'event_rate_per_minute': len(recent_events) / 30
                        },
                        timestamp=current_time,
                        source="temporal_analysis"
                    ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract temporal factors: {e}")
            return []

    async def _extract_network_factors(self, context: Dict[str, Any],
                                     historical_data: List[Dict[str, Any]]) -> List[RiskFactor]:
        """Extract network-related risk factors"""
        factors = []
        current_time = datetime.utcnow()
        
        try:
            network_info = context.get('network', {})
            if not network_info:
                return factors
            
            # Tor/anonymization network usage
            if network_info.get('is_tor', False):
                factors.append(RiskFactor(
                    category=RiskCategory.NETWORK,
                    name="tor_network_usage",
                    value=85.0,
                    weight=0.9,
                    confidence=0.95,
                    evidence={'network_type': 'tor'},
                    timestamp=current_time,
                    source="network_analysis"
                ))
            
            # VPN usage
            if network_info.get('is_vpn', False):
                factors.append(RiskFactor(
                    category=RiskCategory.NETWORK,
                    name="vpn_usage",
                    value=40.0,
                    weight=0.6,
                    confidence=0.8,
                    evidence={'network_type': 'vpn'},
                    timestamp=current_time,
                    source="network_analysis"
                ))
            
            # Datacenter/hosting network
            if network_info.get('is_datacenter', False):
                factors.append(RiskFactor(
                    category=RiskCategory.NETWORK,
                    name="datacenter_network",
                    value=60.0,
                    weight=0.7,
                    confidence=0.85,
                    evidence={'network_type': 'datacenter'},
                    timestamp=current_time,
                    source="network_analysis"
                ))
            
            # Geographic anomaly
            country = network_info.get('country')
            if country:
                # Check if this country has been seen before
                historical_countries = set()
                for h in historical_data[-200:]:  # Check last 200 events
                    h_country = h.get('network', {}).get('country')
                    if h_country:
                        historical_countries.add(h_country)
                
                if country not in historical_countries and len(historical_countries) > 0:
                    factors.append(RiskFactor(
                        category=RiskCategory.NETWORK,
                        name="geographic_anomaly",
                        value=70.0,
                        weight=0.8,
                        confidence=0.9,
                        evidence={
                            'current_country': country,
                            'known_countries': list(historical_countries)
                        },
                        timestamp=current_time,
                        source="network_analysis"
                    ))
            
            # IP reputation score
            reputation_score = network_info.get('reputation_score', 50)
            if reputation_score < 30:  # Poor reputation
                factors.append(RiskFactor(
                    category=RiskCategory.NETWORK,
                    name="poor_ip_reputation",
                    value=100 - reputation_score,
                    weight=0.8,
                    confidence=0.85,
                    evidence={'reputation_score': reputation_score},
                    timestamp=current_time,
                    source="network_analysis"
                ))
            
            return factors
            
        except Exception as e:
            logger.error(f"Failed to extract network factors: {e}")
            return []

    async def _calculate_context_scores(self, context: Dict[str, Any],
                                      historical_data: List[Dict[str, Any]],
                                      baseline: Optional[BehavioralBaseline]) -> Dict[ContextType, float]:
        """Calculate context-specific risk scores"""
        context_scores = {}
        
        try:
            # Location context score
            location_score = await self._calculate_location_context_score(
                context.get('location', {}), historical_data
            )
            context_scores[ContextType.LOCATION] = location_score
            
            # Device context score
            device_score = await self._calculate_device_context_score(
                context.get('device', {}), historical_data
            )
            context_scores[ContextType.DEVICE] = device_score
            
            # Time context score
            time_score = await self._calculate_time_context_score(
                context, baseline
            )
            context_scores[ContextType.TIME] = time_score
            
            # Network context score
            network_score = await self._calculate_network_context_score(
                context.get('network', {}), historical_data
            )
            context_scores[ContextType.NETWORK] = network_score
            
            # Application context score
            app_score = await self._calculate_application_context_score(
                context.get('application'), baseline
            )
            context_scores[ContextType.APPLICATION] = app_score
            
            # Peer group context score
            peer_score = await self._calculate_peer_context_score(
                context, baseline
            )
            context_scores[ContextType.PEER_GROUP] = peer_score
            
            return context_scores
            
        except Exception as e:
            logger.error(f"Failed to calculate context scores: {e}")
            return {}

    async def _calculate_location_context_score(self, location: Dict[str, Any],
                                              historical_data: List[Dict[str, Any]]) -> float:
        """Calculate location context risk score"""
        if not location:
            return 0.0
        
        try:
            # Extract historical locations
            historical_locations = []
            for h in historical_data[-500:]:  # Last 500 events
                h_location = h.get('location', {})
                if h_location:
                    historical_locations.append(h_location)
            
            if not historical_locations:
                return 50.0  # Unknown location, medium risk
            
            # Calculate similarity to known locations
            max_similarity = 0.0
            for h_loc in historical_locations:
                similarity = self._calculate_location_similarity(location, h_loc)
                max_similarity = max(max_similarity, similarity)
            
            # Convert similarity to risk score (inverse relationship)
            location_risk = (1.0 - max_similarity) * 100
            
            # Additional risk factors
            if location.get('country') in ['CN', 'RU', 'KP', 'IR']:  # High-risk countries
                location_risk = min(location_risk + 30, 100)
            
            return min(location_risk, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate location context score: {e}")
            return 50.0

    async def _calculate_device_context_score(self, device: Dict[str, Any],
                                            historical_data: List[Dict[str, Any]]) -> float:
        """Calculate device context risk score"""
        if not device:
            return 0.0
        
        try:
            device_id = device.get('device_id')
            if not device_id:
                return 60.0  # Unknown device, higher risk
            
            # Check if device has been seen before
            device_seen = any(
                h.get('device', {}).get('device_id') == device_id
                for h in historical_data[-200:]
            )
            
            if not device_seen:
                return 70.0  # New device, high risk
            
            # Calculate device trust score based on usage frequency
            device_usage_count = sum(
                1 for h in historical_data[-200:]
                if h.get('device', {}).get('device_id') == device_id
            )
            
            # More usage = lower risk
            usage_risk = max(60 - (device_usage_count * 2), 10)
            
            # Additional risk factors
            if device.get('is_virtual', False):
                usage_risk += 20
            
            if device.get('is_rooted', False) or device.get('is_jailbroken', False):
                usage_risk += 30
            
            return min(usage_risk, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate device context score: {e}")
            return 50.0

    async def _calculate_time_context_score(self, context: Dict[str, Any],
                                          baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate time context risk score"""
        try:
            current_time = datetime.utcnow()
            current_hour = current_time.hour
            current_day = current_time.weekday()
            
            risk_score = 0.0
            
            # Off-hours risk
            if current_hour < 6 or current_hour > 22:
                risk_score += 30
            
            # Weekend risk
            if current_day >= 5:  # Saturday or Sunday
                risk_score += 20
            
            # Holiday risk
            if self._is_holiday(current_time):
                risk_score += 25
            
            # Baseline comparison
            if baseline and baseline.typical_hours:
                if current_hour not in baseline.typical_hours:
                    time_deviation = min([abs(current_hour - h) for h in baseline.typical_hours])
                    risk_score += min(time_deviation * 5, 40)
            
            return min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate time context score: {e}")
            return 0.0

    async def _calculate_network_context_score(self, network: Dict[str, Any],
                                             historical_data: List[Dict[str, Any]]) -> float:
        """Calculate network context risk score"""
        if not network:
            return 0.0
        
        try:
            risk_score = 0.0
            
            # Anonymization network risks
            if network.get('is_tor', False):
                risk_score += 80
            elif network.get('is_vpn', False):
                risk_score += 30
            
            # Datacenter/hosting risks
            if network.get('is_datacenter', False):
                risk_score += 40
            
            # Geographic risks
            country = network.get('country')
            if country:
                high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']
                if country in high_risk_countries:
                    risk_score += 50
                
                # Check for geographic anomaly
                historical_countries = set(
                    h.get('network', {}).get('country')
                    for h in historical_data[-200:]
                    if h.get('network', {}).get('country')
                )
                
                if country not in historical_countries and len(historical_countries) > 0:
                    risk_score += 60
            
            # IP reputation
            reputation_score = network.get('reputation_score', 50)
            if reputation_score < 50:
                risk_score += (50 - reputation_score)
            
            return min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate network context score: {e}")
            return 0.0

    async def _calculate_application_context_score(self, application: Optional[str],
                                                 baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate application context risk score"""
        if not application:
            return 0.0
        
        try:
            # High-risk applications
            high_risk_apps = [
                'admin_console', 'database_management', 'security_config',
                'user_management', 'financial_system', 'hr_system'
            ]
            
            if application in high_risk_apps:
                risk_score = 60.0
            else:
                risk_score = 20.0
            
            # Baseline comparison
            if baseline and baseline.usual_applications:
                if application not in baseline.usual_applications:
                    risk_score += 40
            
            return min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate application context score: {e}")
            return 0.0

    async def _calculate_peer_context_score(self, context: Dict[str, Any],
                                          baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate peer group context risk score"""
        try:
            if not baseline or not baseline.peer_group_id:
                return 30.0  # No peer group data, medium risk
            
            # This would typically compare current activity against peer group norms
            # For now, return a calculated score based on available context
            
            risk_factors = 0
            
            # Check if accessing resources typically not accessed by peer group
            privileges = context.get('privileges', {})
            if privileges.get('admin_privileges'):
                risk_factors += 1
            
            # Check for unusual data access patterns
            data_volume = context.get('data_volume', 0)
            if data_volume > 10000:  # Large data access
                risk_factors += 1
            
            # Time-based peer comparison
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 20:  # Outside normal hours
                risk_factors += 1
            
            peer_risk_score = risk_factors * 25
            return min(peer_risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate peer context score: {e}")
            return 30.0

    async def _calculate_baseline_deviation(self, context: Dict[str, Any],
                                          baseline: Optional[BehavioralBaseline],
                                          historical_data: List[Dict[str, Any]]) -> float:
        """Calculate deviation from behavioral baseline"""
        if not baseline:
            return 50.0  # No baseline, medium deviation
        
        try:
            deviation_score = 0.0
            factors_analyzed = 0
            
            # Time deviation
            current_hour = datetime.utcnow().hour
            if baseline.typical_hours:
                if current_hour in baseline.typical_hours:
                    deviation_score += 0
                else:
                    time_deviation = min([abs(current_hour - h) for h in baseline.typical_hours])
                    deviation_score += min(time_deviation * 5, 50)
                factors_analyzed += 1
            
            # Location deviation
            current_location = context.get('location', {})
            if current_location and baseline.common_locations:
                location_similarity = max([
                    self._calculate_location_similarity(current_location, loc)
                    for loc in baseline.common_locations
                ])
                deviation_score += (1.0 - location_similarity) * 50
                factors_analyzed += 1
            
            # Application deviation
            current_app = context.get('application')
            if current_app and baseline.usual_applications:
                if current_app not in baseline.usual_applications:
                    deviation_score += 40
                factors_analyzed += 1
            
            # Data volume deviation
            data_volume = context.get('data_volume', 0)
            if data_volume > 0 and baseline.normal_data_volume:
                expected_volume = baseline.normal_data_volume.get('mean', 0)
                volume_std = baseline.normal_data_volume.get('std', 1)
                
                if expected_volume > 0 and volume_std > 0:
                    z_score = abs(data_volume - expected_volume) / volume_std
                    deviation_score += min(z_score * 15, 50)
                    factors_analyzed += 1
            
            if factors_analyzed > 0:
                return min(deviation_score / factors_analyzed, 100.0)
            else:
                return 50.0
                
        except Exception as e:
            logger.error(f"Failed to calculate baseline deviation: {e}")
            return 50.0

    async def _calculate_peer_comparison(self, user_id: str, context: Dict[str, Any],
                                       baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate risk based on peer group comparison"""
        try:
            if not baseline or not baseline.peer_group_id:
                return 40.0  # No peer data, medium risk
            
            # This would typically involve comparing current user behavior
            # against their peer group's typical behavior patterns
            
            peer_risk_score = 0.0
            
            # Access pattern comparison
            access_frequency = context.get('access_pattern', {}).get('accesses_per_minute', 0)
            if access_frequency > 5:  # Above typical peer activity
                peer_risk_score += 30
            
            # Privilege usage comparison
            privileges = context.get('privileges', {})
            if privileges.get('admin_privileges'):
                peer_risk_score += 40  # Admin access is unusual for most peer groups
            
            # Data access comparison
            data_volume = context.get('data_volume', 0)
            if data_volume > 5000:  # Large data access
                peer_risk_score += 25
            
            # Time-based comparison
            current_hour = datetime.utcnow().hour
            if current_hour < 6 or current_hour > 22:  # Outside normal peer hours
                peer_risk_score += 20
            
            return min(peer_risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate peer comparison: {e}")
            return 40.0

    async def _calculate_temporal_trend(self, user_id: str,
                                      historical_data: List[Dict[str, Any]]) -> float:
        """Calculate temporal risk trend"""
        try:
            if len(historical_data) < 10:
                return 0.0  # Insufficient data for trend analysis
            
            # Analyze risk trend over time
            recent_data = historical_data[-50:]  # Last 50 events
            risk_scores = []
            
            for event in recent_data:
                event_risk = event.get('risk_score', 0)
                if event_risk > 0:
                    risk_scores.append(event_risk)
            
            if len(risk_scores) < 5:
                return 0.0
            
            # Calculate trend using simple linear regression
            x = np.arange(len(risk_scores))
            y = np.array(risk_scores)
            
            if len(x) > 1:
                slope, _ = np.polyfit(x, y, 1)
                
                # Positive slope indicates increasing risk
                trend_score = max(slope * 10, -50)  # Scale and limit
                return min(trend_score, 50.0)
            
            return 0.0
            
        except Exception as e:
            logger.error(f"Failed to calculate temporal trend: {e}")
            return 0.0

    async def _aggregate_risk_score(self, risk_factors: List[RiskFactor],
                                  context_scores: Dict[ContextType, float],
                                  baseline_deviation: float,
                                  peer_comparison: float,
                                  temporal_trend: float) -> float:
        """Aggregate all risk components into final score"""
        try:
            # Calculate weighted factor score
            factor_score = 0.0
            total_weight = 0.0
            
            for factor in risk_factors:
                weighted_score = factor.calculate_weighted_score()
                factor_score += weighted_score
                total_weight += factor.weight
            
            if total_weight > 0:
                factor_score = factor_score / total_weight * 100
            
            # Calculate weighted context score
            context_weights = {
                ContextType.LOCATION: 0.8,
                ContextType.DEVICE: 0.7,
                ContextType.TIME: 0.6,
                ContextType.NETWORK: 0.9,
                ContextType.APPLICATION: 0.8,
                ContextType.PEER_GROUP: 0.7
            }
            
            context_score = 0.0
            context_total_weight = 0.0
            
            for context_type, score in context_scores.items():
                weight = context_weights.get(context_type, 0.5)
                context_score += score * weight
                context_total_weight += weight
            
            if context_total_weight > 0:
                context_score = context_score / context_total_weight
            
            # Final aggregation with weights
            final_score = (
                factor_score * 0.4 +           # 40% from risk factors
                context_score * 0.25 +         # 25% from context analysis
                baseline_deviation * 0.15 +    # 15% from baseline deviation
                peer_comparison * 0.15 +       # 15% from peer comparison
                temporal_trend * 0.05          # 5% from temporal trend
            )
            
            # Apply non-linear scaling to emphasize high risks
            if final_score > 80:
                final_score = 80 + (final_score - 80) * 1.5
            elif final_score > 60:
                final_score = 60 + (final_score - 60) * 1.2
            
            return min(final_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to aggregate risk score: {e}")
            return 50.0

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= score < max_score:
                return level
        return RiskLevel.EXTREME

    def _calculate_confidence(self, risk_factors: List[RiskFactor],
                            historical_samples: int,
                            baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate confidence in risk assessment"""
        try:
            confidence_score = 0.0
            
            # Factor confidence
            if risk_factors:
                avg_factor_confidence = np.mean([f.confidence for f in risk_factors])
                confidence_score += avg_factor_confidence * 0.4
            
            # Historical data confidence
            data_confidence = min(historical_samples / 100.0, 1.0)
            confidence_score += data_confidence * 100 * 0.3
            
            # Baseline confidence
            if baseline:
                baseline_confidence = baseline.confidence
                confidence_score += baseline_confidence * 100 * 0.3
            else:
                confidence_score += 30  # Reduced confidence without baseline
            
            return min(confidence_score, 100.0)
            
        except Exception as e:
            logger.error(f"Failed to calculate confidence: {e}")
            return 70.0

    def _calculate_location_similarity(self, loc1: Dict[str, Any], loc2: Dict[str, Any]) -> float:
        """Calculate similarity between two locations"""
        try:
            # Compare coordinates if available
            if all(k in loc1 and k in loc2 for k in ['latitude', 'longitude']):
                lat1, lon1 = loc1['latitude'], loc1['longitude']
                lat2, lon2 = loc2['latitude'], loc2['longitude']
                
                # Haversine distance calculation
                from math import radians, cos, sin, asin, sqrt
                
                lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
                dlat = lat2 - lat1
                dlon = lon2 - lon1
                a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
                distance_km = 2 * asin(sqrt(a)) * 6371  # Earth radius in km
                
                # Convert distance to similarity (closer = more similar)
                if distance_km < 1:
                    return 1.0
                elif distance_km < 50:
                    return 1.0 - (distance_km / 50) * 0.5
                else:
                    return max(0.5 - (distance_km - 50) / 1000, 0.0)
            
            # Fallback to text comparison
            similarity = 0.0
            
            if loc1.get('country') == loc2.get('country'):
                similarity += 0.4
            
            if loc1.get('city') == loc2.get('city'):
                similarity += 0.6
            
            return similarity
            
        except Exception as e:
            logger.error(f"Failed to calculate location similarity: {e}")
            return 0.0

    def _is_holiday(self, date: datetime) -> bool:
        """Check if date is a holiday"""
        try:
            # Simple implementation - can be enhanced with holiday libraries
            month, day = date.month, date.day
            
            # Major US holidays
            holidays = [
                (1, 1),   # New Year's Day
                (7, 4),   # Independence Day
                (12, 25), # Christmas Day
                (11, 11), # Veterans Day
            ]
            
            return (month, day) in holidays
            
        except Exception as e:
            logger.error(f"Failed to check holiday: {e}")
            return False

    async def _cache_risk_score(self, risk_score: ContextualRiskScore):
        """Cache risk score in Redis"""
        try:
            if not self.redis_client:
                return
            
            cache_key = f"risk_score:{risk_score.user_id}:{int(time.time() // 3600)}"
            cache_data = json.dumps(risk_score.to_dict(), default=str)
            
            # Cache for 1 hour
            await self.redis_client.setex(cache_key, 3600, cache_data)
            
        except Exception as e:
            logger.error(f"Failed to cache risk score: {e}")

class ContextAnalyzer:
    """Advanced context analysis for risk scoring"""
    
    def __init__(self):
        self.geoip_reader = None
        self._initialize_geoip()
        
    def _initialize_geoip(self):
        """Initialize GeoIP database reader"""
        try:
            # This would typically use a GeoIP database file
            # For now, we'll use a mock implementation
            logger.info("GeoIP database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize GeoIP: {e}")

    async def analyze_network_context(self, ip_address: str) -> NetworkContext:
        """Analyze network context for an IP address"""
        try:
            # Mock implementation - would typically use real GeoIP/threat intel
            network_context = NetworkContext(
                ip_address=ip_address,
                country=self._get_country_from_ip(ip_address),
                city=self._get_city_from_ip(ip_address),
                isp=self._get_isp_from_ip(ip_address),
                is_tor=self._is_tor_exit_node(ip_address),
                is_vpn=self._is_vpn_ip(ip_address),
                is_datacenter=self._is_datacenter_ip(ip_address),
                reputation_score=self._get_ip_reputation(ip_address),
                first_seen=datetime.utcnow(),
                frequency=1
            )
            
            return network_context
            
        except Exception as e:
            logger.error(f"Failed to analyze network context for {ip_address}: {e}")
            raise

    def _get_country_from_ip(self, ip_address: str) -> Optional[str]:
        """Get country from IP address"""
        try:
            # Mock implementation
            if ip_address.startswith('192.168.') or ip_address.startswith('10.'):
                return 'US'  # Private IPs assumed local
            
            # Simple heuristic based on IP ranges (not accurate, for demo only)
            first_octet = int(ip_address.split('.')[0])
            if 1 <= first_octet <= 50:
                return 'US'
            elif 51 <= first_octet <= 100:
                return 'GB'
            elif 101 <= first_octet <= 150:
                return 'DE'
            else:
                return 'CN'
                
        except Exception:
            return None

    def _get_city_from_ip(self, ip_address: str) -> Optional[str]:
        """Get city from IP address"""
        # Mock implementation
        return "Unknown"

    def _get_isp_from_ip(self, ip_address: str) -> Optional[str]:
        """Get ISP from IP address"""
        # Mock implementation
        return "Unknown ISP"

    def _is_tor_exit_node(self, ip_address: str) -> bool:
        """Check if IP is a Tor exit node"""
        # Mock implementation - would check against Tor exit node list
        return ip_address in ['198.51.100.1', '203.0.113.1']

    def _is_vpn_ip(self, ip_address: str) -> bool:
        """Check if IP belongs to a VPN service"""
        # Mock implementation - would check against VPN IP ranges
        return ip_address.startswith('185.') or ip_address.startswith('46.')

    def _is_datacenter_ip(self, ip_address: str) -> bool:
        """Check if IP belongs to a datacenter"""
        # Mock implementation - would check against datacenter IP ranges
        return ip_address.startswith('54.') or ip_address.startswith('52.')

    def _get_ip_reputation(self, ip_address: str) -> float:
        """Get IP reputation score (0-100)"""
        # Mock implementation - would query threat intelligence feeds
        if self._is_tor_exit_node(ip_address):
            return 10.0
        elif self._is_vpn_ip(ip_address):
            return 40.0
        elif self._is_datacenter_ip(ip_address):
            return 60.0
        else:
            return 80.0

class RiskScoringManager:
    """Main risk scoring manager"""
    
    def __init__(self, db_path: str = ":memory:", redis_client: Optional[aioredis.Redis] = None):
        self.db_path = db_path
        self.redis_client = redis_client
        self.risk_engine = RiskCalculationEngine(redis_client)
        self.context_analyzer = ContextAnalyzer()
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Risk scores table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS risk_scores (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    entity_id TEXT,
                    overall_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    baseline_deviation REAL,
                    peer_comparison REAL,
                    temporal_trend REAL,
                    calculated_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    factors_json TEXT,
                    context_scores_json TEXT,
                    metadata_json TEXT
                )
            ''')
            
            # Behavioral baselines table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavioral_baselines (
                    user_id TEXT PRIMARY KEY,
                    typical_hours_json TEXT,
                    common_locations_json TEXT,
                    usual_applications_json TEXT,
                    normal_data_volume_json TEXT,
                    session_duration_stats_json TEXT,
                    peer_group_id TEXT,
                    last_updated TIMESTAMP,
                    confidence REAL,
                    sample_size INTEGER
                )
            ''')
            
            # Risk factors table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS risk_factors (
                    id INTEGER PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value REAL NOT NULL,
                    weight REAL NOT NULL,
                    confidence REAL NOT NULL,
                    evidence_json TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    source TEXT NOT NULL,
                    context_json TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_scores_user_id ON risk_scores(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_scores_calculated_at ON risk_scores(calculated_at)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_factors_user_id ON risk_factors(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_risk_factors_timestamp ON risk_factors(timestamp)')
            
            conn.commit()
            conn.close()
            
            logger.info("Risk scoring database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def calculate_user_risk(self, user_id: str, context: Dict[str, Any],
                                historical_data: Optional[List[Dict[str, Any]]] = None,
                                threat_intel: Optional[List[ThreatIntelligence]] = None) -> ContextualRiskScore:
        """Calculate comprehensive risk score for a user"""
        try:
            logger.info(f"Calculating risk for user {user_id}")
            
            # Get historical data if not provided
            if historical_data is None:
                historical_data = await self._get_historical_data(user_id)
            
            # Get threat intelligence if not provided
            if threat_intel is None:
                threat_intel = await self._get_threat_intelligence(context)
            
            # Get behavioral baseline
            baseline = await self._get_behavioral_baseline(user_id)
            
            # Enhance context with network analysis
            if 'ip_address' in context:
                network_context = await self.context_analyzer.analyze_network_context(
                    context['ip_address']
                )
                context['network'] = asdict(network_context)
            
            # Calculate risk score
            risk_score = await self.risk_engine.calculate_risk_score(
                user_id, context, historical_data, threat_intel, baseline
            )
            
            # Store risk score
            await self._store_risk_score(risk_score)
            
            logger.info(f"Risk calculated for user {user_id}: {risk_score.overall_score} ({risk_score.risk_level.name})")
            return risk_score
            
        except Exception as e:
            logger.error(f"Failed to calculate user risk for {user_id}: {e}")
            raise

    async def _get_historical_data(self, user_id: str) -> List[Dict[str, Any]]:
        """Get historical data for user"""
        try:
            # Mock implementation - would typically query activity logs
            return [
                {
                    'timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat(),
                    'activity_type': 'login',
                    'ip_address': f'192.168.1.{100 + (i % 50)}',
                    'location': {'country': 'US', 'city': 'San Francisco'},
                    'device': {'device_id': f'device_{i % 5}', 'type': 'desktop'},
                    'application': 'web_portal',
                    'risk_score': 20 + (i % 30)
                }
                for i in range(100)
            ]
            
        except Exception as e:
            logger.error(f"Failed to get historical data for {user_id}: {e}")
            return []

    async def _get_threat_intelligence(self, context: Dict[str, Any]) -> List[ThreatIntelligence]:
        """Get relevant threat intelligence"""
        try:
            # Mock implementation - would query threat intel feeds
            threat_intel = []
            
            ip_address = context.get('ip_address')
            if ip_address and ip_address in ['198.51.100.1', '203.0.113.1']:
                threat_intel.append(ThreatIntelligence(
                    source='mock_feed',
                    indicator_type='ip',
                    indicator_value=ip_address,
                    severity='high',
                    confidence=0.9,
                    first_seen=datetime.utcnow() - timedelta(days=30),
                    last_seen=datetime.utcnow() - timedelta(hours=2),
                    context={'category': 'malware_c2'},
                    tags=['malware', 'c2', 'botnet']
                ))
            
            return threat_intel
            
        except Exception as e:
            logger.error(f"Failed to get threat intelligence: {e}")
            return []

    async def _get_behavioral_baseline(self, user_id: str) -> Optional[BehavioralBaseline]:
        """Get behavioral baseline for user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM behavioral_baselines WHERE user_id = ?
            ''', (user_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return BehavioralBaseline(
                    user_id=row[0],
                    typical_hours=json.loads(row[1]) if row[1] else [],
                    common_locations=json.loads(row[2]) if row[2] else [],
                    usual_applications=set(json.loads(row[3])) if row[3] else set(),
                    normal_data_volume=json.loads(row[4]) if row[4] else {},
                    standard_session_duration=tuple(json.loads(row[5])) if row[5] else (60.0, 30.0),
                    peer_group_id=row[6] or '',
                    last_updated=datetime.fromisoformat(row[7]) if row[7] else datetime.utcnow(),
                    confidence=row[8] or 0.5,
                    sample_size=row[9] or 0
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get behavioral baseline for {user_id}: {e}")
            return None

    async def _store_risk_score(self, risk_score: ContextualRiskScore):
        """Store risk score in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO risk_scores (
                    user_id, entity_id, overall_score, risk_level, confidence,
                    baseline_deviation, peer_comparison, temporal_trend,
                    calculated_at, expires_at, factors_json, context_scores_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                risk_score.user_id,
                risk_score.entity_id,
                risk_score.overall_score,
                risk_score.risk_level.name,
                risk_score.confidence,
                risk_score.baseline_deviation,
                risk_score.peer_comparison,
                risk_score.temporal_trend,
                risk_score.calculated_at.isoformat(),
                risk_score.expires_at.isoformat(),
                json.dumps([asdict(f) for f in risk_score.factors], default=str),
                json.dumps({k.value: v for k, v in risk_score.context_scores.items()}),
                json.dumps(risk_score.metadata, default=str)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store risk score: {e}")

    async def get_risk_trends(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Get risk trends for user over specified period"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            start_date = datetime.utcnow() - timedelta(days=days)
            
            cursor.execute('''
                SELECT overall_score, risk_level, calculated_at
                FROM risk_scores
                WHERE user_id = ? AND calculated_at >= ?
                ORDER BY calculated_at
            ''', (user_id, start_date.isoformat()))
            
            rows = cursor.fetchall()
            conn.close()
            
            if not rows:
                return {'trend': 'insufficient_data', 'scores': []}
            
            scores = [row[0] for row in rows]
            dates = [row[2] for row in rows]
            
            # Calculate trend
            if len(scores) > 1:
                x = np.arange(len(scores))
                slope, _ = np.polyfit(x, scores, 1)
                
                if slope > 2:
                    trend = 'increasing'
                elif slope < -2:
                    trend = 'decreasing'
                else:
                    trend = 'stable'
            else:
                trend = 'insufficient_data'
            
            return {
                'trend': trend,
                'slope': slope if len(scores) > 1 else 0,
                'current_score': scores[-1] if scores else 0,
                'average_score': np.mean(scores) if scores else 0,
                'max_score': max(scores) if scores else 0,
                'min_score': min(scores) if scores else 0,
                'scores': scores,
                'dates': dates
            }
            
        except Exception as e:
            logger.error(f"Failed to get risk trends for {user_id}: {e}")
            return {'trend': 'error', 'scores': []}

    async def get_high_risk_users(self, risk_threshold: float = 60.0, 
                                limit: int = 100) -> List[Dict[str, Any]]:
        """Get users with high risk scores"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, overall_score, risk_level, calculated_at
                FROM risk_scores
                WHERE overall_score >= ? AND expires_at > datetime('now')
                ORDER BY overall_score DESC
                LIMIT ?
            ''', (risk_threshold, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'user_id': row[0],
                    'overall_score': row[1],
                    'risk_level': row[2],
                    'calculated_at': row[3]
                }
                for row in rows
            ]
            
        except Exception as e:
            logger.error(f"Failed to get high risk users: {e}")
            return []

# Example usage and testing
if __name__ == "__main__":
    async def test_risk_scoring():
        """Test the risk scoring system"""
        try:
            # Initialize risk scoring manager
            manager = RiskScoringManager()
            
            # Test context
            test_context = {
                'user_id': 'test_user_001',
                'ip_address': '198.51.100.1',  # Malicious IP in our mock data
                'location': {
                    'country': 'CN',
                    'city': 'Beijing',
                    'latitude': 39.9042,
                    'longitude': 116.4074
                },
                'device': {
                    'device_id': 'unknown_device_123',
                    'type': 'mobile',
                    'os': 'Android',
                    'is_rooted': True
                },
                'session': {
                    'concurrent_sessions': 5,
                    'duration_minutes': 600
                },
                'application': 'admin_console',
                'privileges': {
                    'admin_privileges': ['user_management', 'system_config'],
                    'elevated_access': True
                },
                'access_pattern': {
                    'accesses_per_minute': 15,
                    'data_accessed': 50000
                },
                'data_volume': 25000,
                'data_classification': {
                    'sensitive_data_accessed': True,
                    'max_sensitivity_level': 'critical',
                    'data_types': ['financial', 'pii', 'security']
                }
            }
            
            # Calculate risk score
            risk_score = await manager.calculate_user_risk('test_user_001', test_context)
            
            print("Risk Scoring Results:")
            print(f"User ID: {risk_score.user_id}")
            print(f"Overall Score: {risk_score.overall_score:.2f}")
            print(f"Risk Level: {risk_score.risk_level.name}")
            print(f"Confidence: {risk_score.confidence:.2f}%")
            print(f"Baseline Deviation: {risk_score.baseline_deviation:.2f}")
            print(f"Peer Comparison: {risk_score.peer_comparison:.2f}")
            print(f"Temporal Trend: {risk_score.temporal_trend:.2f}")
            
            print("\nRisk Factors:")
            for factor in risk_score.factors:
                print(f"  - {factor.name}: {factor.value:.2f} (weight: {factor.weight}, confidence: {factor.confidence})")
            
            print("\nContext Scores:")
            for context_type, score in risk_score.context_scores.items():
                print(f"  - {context_type.value}: {score:.2f}")
            
            # Test risk trends
            trends = await manager.get_risk_trends('test_user_001', days=7)
            print(f"\nRisk Trends: {trends}")
            
            # Test high risk users
            high_risk = await manager.get_high_risk_users(risk_threshold=50.0)
            print(f"\nHigh Risk Users: {len(high_risk)} found")
            
        except Exception as e:
            logger.error(f"Test failed: {e}")
            logger.error(traceback.format_exc())
    
    # Run the test
    asyncio.run(test_risk_scoring())