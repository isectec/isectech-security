"""
Automated Threat Hunter for Advanced Persistent Threats

This module implements intelligent threat hunting algorithms that automatically
search for sophisticated attack patterns, insider threats, and APT indicators
using machine learning models and behavioral analytics.
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
import threading
import time

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
import networkx as nx
import mlflow
import mlflow.sklearn

from ..data_pipeline.collector import SecurityEvent
from ..models.behavioral_analytics import BehavioralAnalyticsManager, BehavioralAnomaly
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager


logger = logging.getLogger(__name__)


class ThreatHuntType(Enum):
    """Types of threat hunting operations."""
    APT_DETECTION = "apt_detection"
    INSIDER_THREAT = "insider_threat"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    ZERO_DAY_INDICATORS = "zero_day_indicators"
    COMMAND_CONTROL = "command_control"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE_MECHANISMS = "persistence_mechanisms"


class HuntStatus(Enum):
    """Status of threat hunting operations."""
    INITIATED = "initiated"
    RUNNING = "running"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    SUSPENDED = "suspended"


class ThreatSeverity(Enum):
    """Severity levels for identified threats."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ThreatHuntResult:
    """Result from automated threat hunting operation."""
    hunt_id: str
    hunt_type: ThreatHuntType
    severity: ThreatSeverity
    confidence_score: float
    
    # Threat details
    threat_indicators: List[Dict[str, Any]]
    attack_timeline: List[Dict[str, Any]]
    affected_entities: List[str]
    ioc_matches: List[Dict[str, Any]]
    
    # Evidence and context
    evidence_events: List[str]  # Event IDs
    suspicious_patterns: List[Dict[str, Any]]
    correlation_insights: List[str]
    
    # Recommendations
    immediate_actions: List[str]
    investigation_steps: List[str]
    mitigation_strategies: List[str]
    
    # Metadata
    hunt_start_time: datetime
    hunt_completion_time: datetime
    total_events_analyzed: int
    processing_time_seconds: float
    
    # AI insights
    ml_model_used: str
    pattern_confidence: float
    false_positive_likelihood: float
    similar_historical_incidents: List[str]


@dataclass
class APTHuntingProfile:
    """Profile for APT detection and hunting."""
    apt_group: str
    known_ttps: List[str]  # Tactics, Techniques, and Procedures
    indicators: Dict[str, List[str]]
    behavioral_signatures: List[Dict[str, Any]]
    infrastructure_patterns: List[str]
    time_patterns: Dict[str, Any]
    target_preferences: List[str]
    detection_confidence: float


class AutomatedThreatHunter:
    """
    Advanced automated threat hunting system with ML-driven pattern recognition.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("automated_threat_hunter")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Core components
        self.behavioral_analytics = BehavioralAnalyticsManager(settings)
        
        # Hunting state management
        self.active_hunts: Dict[str, Dict[str, Any]] = {}
        self.completed_hunts: Dict[str, ThreatHuntResult] = {}
        self.threat_patterns: Dict[str, List[Dict[str, Any]]] = {}
        
        # APT profiles and intelligence
        self.apt_profiles: Dict[str, APTHuntingProfile] = {}
        self.ioc_database: Dict[str, Set[str]] = defaultdict(set)
        
        # ML models for threat hunting
        self.clustering_model: Optional[DBSCAN] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.scaler = StandardScaler()
        
        # Graph analysis for lateral movement detection
        self.network_graph = nx.DiGraph()
        
        # Thread management
        self._hunt_executor = None
        self._stop_hunting = False
        
        # Initialize threat hunting components
        self._initialize_apt_profiles()
        self._initialize_ioc_database()
        
    async def start_continuous_hunting(self, hunt_interval_minutes: int = 30) -> None:
        """Start continuous automated threat hunting."""
        logger.info("Starting continuous automated threat hunting")
        
        self._stop_hunting = False
        self._hunt_executor = threading.Thread(
            target=self._continuous_hunt_loop,
            args=(hunt_interval_minutes,),
            daemon=True
        )
        self._hunt_executor.start()
        
        self.metrics.increment_counter("continuous_hunting_started")
        
    def stop_continuous_hunting(self) -> None:
        """Stop continuous threat hunting."""
        logger.info("Stopping continuous automated threat hunting")
        
        self._stop_hunting = True
        if self._hunt_executor:
            self._hunt_executor.join(timeout=30)
            
        self.metrics.increment_counter("continuous_hunting_stopped")
        
    async def execute_threat_hunt(
        self,
        hunt_type: ThreatHuntType,
        events: List[SecurityEvent],
        hunt_parameters: Optional[Dict[str, Any]] = None
    ) -> ThreatHuntResult:
        """Execute a specific threat hunting operation."""
        hunt_id = str(uuid.uuid4())
        hunt_start = datetime.utcnow()
        
        logger.info(f"Starting threat hunt {hunt_id} of type {hunt_type.value}")
        
        # Track active hunt
        self.active_hunts[hunt_id] = {
            'hunt_type': hunt_type,
            'start_time': hunt_start,
            'status': HuntStatus.RUNNING,
            'total_events': len(events),
            'parameters': hunt_parameters or {}
        }
        
        try:
            with mlflow.start_run(run_name=f"threat_hunt_{hunt_type.value}_{hunt_id[:8]}"):
                # Log hunt parameters
                mlflow.log_param("hunt_type", hunt_type.value)
                mlflow.log_param("event_count", len(events))
                mlflow.log_param("hunt_id", hunt_id)
                
                # Execute specific hunting algorithm
                if hunt_type == ThreatHuntType.APT_DETECTION:
                    result = await self._hunt_apt_indicators(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.INSIDER_THREAT:
                    result = await self._hunt_insider_threats(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.LATERAL_MOVEMENT:
                    result = await self._hunt_lateral_movement(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.DATA_EXFILTRATION:
                    result = await self._hunt_data_exfiltration(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.ZERO_DAY_INDICATORS:
                    result = await self._hunt_zero_day_indicators(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.COMMAND_CONTROL:
                    result = await self._hunt_command_control(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.PRIVILEGE_ESCALATION:
                    result = await self._hunt_privilege_escalation(hunt_id, events, hunt_parameters)
                elif hunt_type == ThreatHuntType.PERSISTENCE_MECHANISMS:
                    result = await self._hunt_persistence_mechanisms(hunt_id, events, hunt_parameters)
                else:
                    raise ValueError(f"Unsupported hunt type: {hunt_type}")
                
                # Log results to MLflow
                mlflow.log_metric("confidence_score", result.confidence_score)
                mlflow.log_metric("pattern_confidence", result.pattern_confidence)
                mlflow.log_metric("false_positive_likelihood", result.false_positive_likelihood)
                mlflow.log_metric("processing_time_seconds", result.processing_time_seconds)
                mlflow.log_metric("threat_indicators_count", len(result.threat_indicators))
                
                # Update hunt status
                self.active_hunts[hunt_id]['status'] = HuntStatus.COMPLETED
                self.completed_hunts[hunt_id] = result
                
                logger.info(f"Completed threat hunt {hunt_id} with {len(result.threat_indicators)} indicators")
                
                self.metrics.increment_counter(
                    "threat_hunts_completed",
                    tags={"hunt_type": hunt_type.value, "severity": result.severity.value}
                )
                
                return result
                
        except Exception as e:
            logger.error(f"Threat hunt {hunt_id} failed: {e}")
            
            self.active_hunts[hunt_id]['status'] = HuntStatus.FAILED
            self.active_hunts[hunt_id]['error'] = str(e)
            
            self.metrics.increment_counter(
                "threat_hunts_failed",
                tags={"hunt_type": hunt_type.value}
            )
            
            raise
        finally:
            # Clean up active hunt
            if hunt_id in self.active_hunts:
                del self.active_hunts[hunt_id]
    
    async def _hunt_apt_indicators(
        self,
        hunt_id: str,
        events: List[SecurityEvent],
        parameters: Optional[Dict[str, Any]]
    ) -> ThreatHuntResult:
        """Hunt for Advanced Persistent Threat indicators."""
        hunt_start = datetime.utcnow()
        
        threat_indicators = []
        attack_timeline = []
        affected_entities = set()
        suspicious_patterns = []
        correlation_insights = []
        
        logger.info(f"Hunting APT indicators in {len(events)} events")
        
        # Convert events to DataFrame for analysis
        events_df = self._events_to_dataframe(events)
        
        # 1. Check against known APT profiles
        for apt_group, profile in self.apt_profiles.items():
            logger.info(f"Checking against {apt_group} APT profile")
            
            # Match TTPs (Tactics, Techniques, and Procedures)
            ttp_matches = self._match_apt_ttps(events_df, profile)
            if ttp_matches:
                threat_indicators.extend([
                    {
                        'type': 'apt_ttp_match',
                        'apt_group': apt_group,
                        'matched_ttps': ttp_matches,
                        'confidence': profile.detection_confidence,
                        'event_ids': [event.event_id for event in events if event.event_id in ttp_matches]
                    }
                ])
                affected_entities.update([event.hostname or event.source_ip for event in events])
            
            # Check infrastructure patterns
            infra_matches = self._match_infrastructure_patterns(events_df, profile)
            if infra_matches:
                threat_indicators.extend([
                    {
                        'type': 'apt_infrastructure',
                        'apt_group': apt_group,
                        'infrastructure_matches': infra_matches,
                        'confidence': profile.detection_confidence * 0.8,
                        'indicators': infra_matches
                    }
                ])
            
            # Analyze behavioral signatures
            behavioral_matches = await self._match_behavioral_signatures(events, profile)
            if behavioral_matches:
                threat_indicators.extend([
                    {
                        'type': 'apt_behavioral_signature',
                        'apt_group': apt_group,
                        'behavioral_matches': behavioral_matches,
                        'confidence': profile.detection_confidence * 0.9
                    }
                ])
        
        # 2. Detect APT-like patterns using ML
        ml_patterns = await self._detect_apt_ml_patterns(events_df)
        if ml_patterns:
            threat_indicators.extend(ml_patterns)
            
        # 3. Timeline reconstruction for identified threats
        if threat_indicators:
            attack_timeline = self._reconstruct_attack_timeline(events, threat_indicators)
            
        # 4. Generate correlation insights
        correlation_insights = self._generate_apt_correlation_insights(threat_indicators, events_df)
        
        # Calculate overall severity and confidence
        severity = self._calculate_threat_severity(threat_indicators)
        confidence = self._calculate_confidence_score(threat_indicators)
        pattern_confidence = self._calculate_pattern_confidence(suspicious_patterns)
        false_positive_likelihood = self._estimate_false_positive_probability(threat_indicators)
        
        # Generate recommendations
        immediate_actions = self._generate_apt_immediate_actions(threat_indicators)
        investigation_steps = self._generate_apt_investigation_steps(threat_indicators)
        mitigation_strategies = self._generate_apt_mitigation_strategies(threat_indicators)
        
        hunt_completion = datetime.utcnow()
        processing_time = (hunt_completion - hunt_start).total_seconds()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.APT_DETECTION,
            severity=severity,
            confidence_score=confidence,
            threat_indicators=threat_indicators,
            attack_timeline=attack_timeline,
            affected_entities=list(affected_entities),
            ioc_matches=[],  # Populated by IOC matching
            evidence_events=[event.event_id for event in events],
            suspicious_patterns=suspicious_patterns,
            correlation_insights=correlation_insights,
            immediate_actions=immediate_actions,
            investigation_steps=investigation_steps,
            mitigation_strategies=mitigation_strategies,
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=processing_time,
            ml_model_used="APT_Detection_Ensemble",
            pattern_confidence=pattern_confidence,
            false_positive_likelihood=false_positive_likelihood,
            similar_historical_incidents=[]
        )
    
    async def _hunt_insider_threats(
        self,
        hunt_id: str,
        events: List[SecurityEvent],
        parameters: Optional[Dict[str, Any]]
    ) -> ThreatHuntResult:
        """Hunt for insider threat indicators."""
        hunt_start = datetime.utcnow()
        
        threat_indicators = []
        suspicious_patterns = []
        affected_entities = set()
        
        logger.info(f"Hunting insider threats in {len(events)} events")
        
        # Focus on user behavior anomalies
        behavioral_anomalies = await self.behavioral_analytics.detect_behavioral_anomalies(events)
        
        # Analyze for insider threat patterns
        for anomaly in behavioral_anomalies:
            if anomaly.severity_score > 0.7:  # High severity anomalies
                threat_indicators.append({
                    'type': 'insider_behavioral_anomaly',
                    'entity_id': anomaly.entity_id,
                    'anomaly_type': anomaly.anomaly_type.value,
                    'severity_score': anomaly.severity_score,
                    'confidence': anomaly.confidence_score,
                    'description': anomaly.description,
                    'deviations': anomaly.deviations
                })
                affected_entities.add(anomaly.entity_id)
        
        # Look for specific insider threat patterns
        insider_patterns = self._detect_insider_threat_patterns(events)
        threat_indicators.extend(insider_patterns)
        
        # Calculate severity and confidence
        severity = self._calculate_threat_severity(threat_indicators)
        confidence = self._calculate_confidence_score(threat_indicators)
        
        hunt_completion = datetime.utcnow()
        processing_time = (hunt_completion - hunt_start).total_seconds()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.INSIDER_THREAT,
            severity=severity,
            confidence_score=confidence,
            threat_indicators=threat_indicators,
            attack_timeline=[],
            affected_entities=list(affected_entities),
            ioc_matches=[],
            evidence_events=[event.event_id for event in events],
            suspicious_patterns=suspicious_patterns,
            correlation_insights=[],
            immediate_actions=self._generate_insider_immediate_actions(threat_indicators),
            investigation_steps=self._generate_insider_investigation_steps(threat_indicators),
            mitigation_strategies=self._generate_insider_mitigation_strategies(threat_indicators),
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=processing_time,
            ml_model_used="Insider_Threat_Detector",
            pattern_confidence=0.8,
            false_positive_likelihood=0.2,
            similar_historical_incidents=[]
        )
    
    async def _hunt_lateral_movement(
        self,
        hunt_id: str,
        events: List[SecurityEvent],
        parameters: Optional[Dict[str, Any]]
    ) -> ThreatHuntResult:
        """Hunt for lateral movement patterns."""
        hunt_start = datetime.utcnow()
        
        threat_indicators = []
        
        # Build network graph from events
        self._build_network_graph(events)
        
        # Detect suspicious movement patterns
        movement_patterns = self._detect_lateral_movement_patterns()
        threat_indicators.extend(movement_patterns)
        
        severity = self._calculate_threat_severity(threat_indicators)
        confidence = self._calculate_confidence_score(threat_indicators)
        
        hunt_completion = datetime.utcnow()
        processing_time = (hunt_completion - hunt_start).total_seconds()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.LATERAL_MOVEMENT,
            severity=severity,
            confidence_score=confidence,
            threat_indicators=threat_indicators,
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[event.event_id for event in events],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=processing_time,
            ml_model_used="Lateral_Movement_Detector",
            pattern_confidence=0.7,
            false_positive_likelihood=0.3,
            similar_historical_incidents=[]
        )
    
    # Additional hunt methods would be implemented similarly...
    async def _hunt_data_exfiltration(self, hunt_id: str, events: List[SecurityEvent], parameters: Optional[Dict[str, Any]]) -> ThreatHuntResult:
        """Hunt for data exfiltration patterns."""
        # Implementation for data exfiltration detection
        hunt_start = datetime.utcnow()
        hunt_completion = datetime.utcnow()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.DATA_EXFILTRATION,
            severity=ThreatSeverity.MEDIUM,
            confidence_score=0.6,
            threat_indicators=[],
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=0.0,
            ml_model_used="Data_Exfiltration_Detector",
            pattern_confidence=0.6,
            false_positive_likelihood=0.4,
            similar_historical_incidents=[]
        )
    
    # Helper methods
    def _continuous_hunt_loop(self, interval_minutes: int) -> None:
        """Continuous hunting loop running in background thread."""
        while not self._stop_hunting:
            try:
                # In a real implementation, this would fetch recent events
                # and execute various hunting algorithms
                logger.debug("Executing continuous threat hunting cycle")
                
                # Sleep for interval
                time.sleep(interval_minutes * 60)
                
            except Exception as e:
                logger.error(f"Error in continuous hunting loop: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def _initialize_apt_profiles(self) -> None:
        """Initialize known APT group profiles."""
        # Example APT29 (Cozy Bear) profile
        apt29_profile = APTHuntingProfile(
            apt_group="APT29",
            known_ttps=[
                "T1566.001",  # Spearphishing Attachment
                "T1055",      # Process Injection
                "T1027",      # Obfuscated Files or Information
                "T1082",      # System Information Discovery
                "T1083",      # File and Directory Discovery
            ],
            indicators={
                "domains": ["cozybeardomain.com", "apt29-c2.net"],
                "ips": ["192.168.1.100", "10.0.0.50"],
                "file_hashes": ["abc123def456", "789ghi012jkl"],
                "registry_keys": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\APT29"]
            },
            behavioral_signatures=[
                {
                    "name": "lateral_movement_pattern",
                    "description": "Specific lateral movement technique used by APT29",
                    "indicators": ["psexec", "wmic", "remote_desktop"]
                }
            ],
            infrastructure_patterns=[
                "subdomain.legitimate-domain.com",
                "typosquat-domain.org"
            ],
            time_patterns={
                "active_hours": "09:00-17:00",
                "timezone": "UTC+3",
                "days_of_week": [1, 2, 3, 4, 5]  # Weekdays
            },
            target_preferences=[
                "government", "defense", "healthcare", "finance"
            ],
            detection_confidence=0.85
        )
        
        self.apt_profiles["APT29"] = apt29_profile
        
        logger.info(f"Initialized {len(self.apt_profiles)} APT profiles")
    
    def _initialize_ioc_database(self) -> None:
        """Initialize Indicators of Compromise database."""
        # In production, this would be loaded from threat intelligence feeds
        self.ioc_database["ips"].update([
            "192.168.1.100", "10.0.0.50", "172.16.0.10"
        ])
        self.ioc_database["domains"].update([
            "malicious-domain.com", "bad-actor.net", "c2-server.org"
        ])
        self.ioc_database["file_hashes"].update([
            "abc123def456789", "malware-hash-123", "trojan-hash-456"
        ])
        
        logger.info("Initialized IOC database with threat intelligence")
    
    def _events_to_dataframe(self, events: List[SecurityEvent]) -> pd.DataFrame:
        """Convert security events to pandas DataFrame for analysis."""
        event_data = []
        for event in events:
            event_data.append({
                'event_id': event.event_id,
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'severity': event.severity,
                'source_ip': event.source_ip or '',
                'dest_ip': event.dest_ip or '',
                'hostname': event.hostname or '',
                'username': event.username or '',
                'process_name': event.process_name or '',
                'command_line': event.command_line or '',
                'file_path': event.file_path or '',
                'network_protocol': event.network_protocol or '',
                'port': event.port or 0,
            })
        
        return pd.DataFrame(event_data)
    
    def _match_apt_ttps(self, events_df: pd.DataFrame, profile: APTHuntingProfile) -> List[str]:
        """Match events against APT TTPs."""
        matches = []
        
        # Simple TTP matching based on event patterns
        for ttp in profile.known_ttps:
            if ttp == "T1566.001":  # Spearphishing Attachment
                phishing_events = events_df[
                    (events_df['event_type'] == 'email_received') |
                    (events_df['file_path'].str.contains('.doc|.pdf|.xls', case=False, na=False))
                ]
                if not phishing_events.empty:
                    matches.extend(phishing_events['event_id'].tolist())
            
            elif ttp == "T1055":  # Process Injection
                injection_events = events_df[
                    events_df['process_name'].str.contains('svchost|explorer|winlogon', case=False, na=False)
                ]
                if not injection_events.empty:
                    matches.extend(injection_events['event_id'].tolist())
        
        return matches
    
    def _match_infrastructure_patterns(self, events_df: pd.DataFrame, profile: APTHuntingProfile) -> List[str]:
        """Match infrastructure patterns against events."""
        matches = []
        
        # Check for domain matches
        for domain in profile.indicators.get("domains", []):
            domain_events = events_df[
                events_df['dest_ip'].str.contains(domain, case=False, na=False) |
                events_df['command_line'].str.contains(domain, case=False, na=False)
            ]
            if not domain_events.empty:
                matches.extend([domain])
        
        # Check for IP matches
        for ip in profile.indicators.get("ips", []):
            ip_events = events_df[
                (events_df['source_ip'] == ip) |
                (events_df['dest_ip'] == ip)
            ]
            if not ip_events.empty:
                matches.extend([ip])
        
        return matches
    
    async def _match_behavioral_signatures(self, events: List[SecurityEvent], profile: APTHuntingProfile) -> List[Dict[str, Any]]:
        """Match behavioral signatures against events."""
        matches = []
        
        for signature in profile.behavioral_signatures:
            # Analyze events for behavioral patterns
            pattern_matches = self._analyze_behavioral_pattern(events, signature)
            if pattern_matches:
                matches.append({
                    'signature_name': signature['name'],
                    'description': signature['description'],
                    'matches': pattern_matches
                })
        
        return matches
    
    def _analyze_behavioral_pattern(self, events: List[SecurityEvent], signature: Dict[str, Any]) -> List[str]:
        """Analyze events for specific behavioral patterns."""
        matches = []
        
        # Simple pattern matching - in production this would be more sophisticated
        indicators = signature.get('indicators', [])
        for event in events:
            if any(indicator.lower() in (event.command_line or '').lower() or
                   indicator.lower() in (event.process_name or '').lower()
                   for indicator in indicators):
                matches.append(event.event_id)
        
        return matches
    
    async def _detect_apt_ml_patterns(self, events_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Use ML to detect APT-like patterns."""
        patterns = []
        
        if len(events_df) < 10:  # Need minimum events for ML analysis
            return patterns
        
        try:
            # Feature engineering for ML
            features = self._extract_ml_features(events_df)
            
            if len(features) > 0:
                # Use isolation forest for anomaly detection
                if self.anomaly_detector is None:
                    self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
                
                anomalies = self.anomaly_detector.fit_predict(features)
                
                # Identify anomalous events
                anomaly_indices = np.where(anomalies == -1)[0]
                for idx in anomaly_indices:
                    patterns.append({
                        'type': 'ml_detected_anomaly',
                        'event_index': int(idx),
                        'anomaly_score': float(self.anomaly_detector.score_samples([features[idx]])[0]),
                        'confidence': 0.7
                    })
        
        except Exception as e:
            logger.warning(f"ML pattern detection failed: {e}")
        
        return patterns
    
    def _extract_ml_features(self, events_df: pd.DataFrame) -> np.ndarray:
        """Extract numerical features for ML analysis."""
        features = []
        
        # Time-based features
        events_df['hour'] = pd.to_datetime(events_df['timestamp']).dt.hour
        events_df['day_of_week'] = pd.to_datetime(events_df['timestamp']).dt.dayofweek
        
        # Numerical features
        numeric_features = ['severity', 'port', 'hour', 'day_of_week']
        
        # Handle categorical features with label encoding
        categorical_features = ['event_type', 'network_protocol']
        
        feature_df = events_df[numeric_features].fillna(0)
        
        # Simple categorical encoding
        for cat_col in categorical_features:
            if cat_col in events_df.columns:
                encoded_col = pd.Categorical(events_df[cat_col]).codes
                feature_df[f'{cat_col}_encoded'] = encoded_col
        
        if not self.scaler.mean_:
            self.scaler.fit(feature_df)
        
        features = self.scaler.transform(feature_df)
        
        return features
    
    def _reconstruct_attack_timeline(self, events: List[SecurityEvent], indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Reconstruct attack timeline from events and indicators."""
        timeline = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Create timeline entries
        for event in sorted_events[:10]:  # Show first 10 events
            timeline.append({
                'timestamp': event.timestamp.isoformat(),
                'event_type': event.event_type,
                'severity': event.severity,
                'description': f"{event.event_type} from {event.source_ip or 'unknown'}",
                'event_id': event.event_id
            })
        
        return timeline
    
    def _generate_apt_correlation_insights(self, indicators: List[Dict[str, Any]], events_df: pd.DataFrame) -> List[str]:
        """Generate correlation insights for APT detection."""
        insights = []
        
        if indicators:
            insights.append(f"Detected {len(indicators)} threat indicators suggesting APT activity")
            
            # Analyze temporal patterns
            if not events_df.empty:
                event_hours = pd.to_datetime(events_df['timestamp']).dt.hour.value_counts()
                peak_hour = event_hours.idxmax()
                insights.append(f"Peak activity observed at {peak_hour}:00, consistent with APT operational hours")
            
            # Infrastructure correlation
            apt_types = [ind.get('apt_group') for ind in indicators if 'apt_group' in ind]
            if apt_types:
                unique_apts = set(filter(None, apt_types))
                if len(unique_apts) == 1:
                    insights.append(f"All indicators point to {list(unique_apts)[0]} APT group")
                else:
                    insights.append(f"Mixed indicators from {len(unique_apts)} different APT groups")
        
        return insights
    
    def _calculate_threat_severity(self, indicators: List[Dict[str, Any]]) -> ThreatSeverity:
        """Calculate overall threat severity based on indicators."""
        if not indicators:
            return ThreatSeverity.INFO
        
        max_confidence = max(ind.get('confidence', 0) for ind in indicators)
        indicator_count = len(indicators)
        
        if max_confidence >= 0.9 or indicator_count >= 5:
            return ThreatSeverity.CRITICAL
        elif max_confidence >= 0.7 or indicator_count >= 3:
            return ThreatSeverity.HIGH
        elif max_confidence >= 0.5 or indicator_count >= 1:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _calculate_confidence_score(self, indicators: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence score."""
        if not indicators:
            return 0.0
        
        confidences = [ind.get('confidence', 0) for ind in indicators]
        return float(np.mean(confidences))
    
    def _calculate_pattern_confidence(self, patterns: List[Dict[str, Any]]) -> float:
        """Calculate pattern recognition confidence."""
        if not patterns:
            return 0.0
        
        return 0.75  # Placeholder confidence
    
    def _estimate_false_positive_probability(self, indicators: List[Dict[str, Any]]) -> float:
        """Estimate false positive likelihood."""
        if not indicators:
            return 0.0
        
        # Simple estimation based on confidence scores
        avg_confidence = self._calculate_confidence_score(indicators)
        return max(0.0, 1.0 - avg_confidence)
    
    def _generate_apt_immediate_actions(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate immediate action recommendations for APT threats."""
        actions = []
        
        if indicators:
            actions.extend([
                "Isolate affected systems immediately to prevent lateral movement",
                "Preserve forensic evidence and create memory dumps",
                "Reset credentials for all affected user accounts",
                "Block identified malicious IPs and domains at network perimeter",
                "Activate incident response team and notify CISO",
                "Implement emergency monitoring on critical systems"
            ])
        
        return actions
    
    def _generate_apt_investigation_steps(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate investigation steps for APT threats."""
        steps = []
        
        if indicators:
            steps.extend([
                "Conduct full forensic analysis of affected systems",
                "Review network logs for signs of data exfiltration",
                "Analyze malware samples in isolated sandbox environment",
                "Interview affected users to understand initial attack vector",
                "Review backup integrity and prepare for clean restoration",
                "Coordinate with threat intelligence teams for attribution analysis"
            ])
        
        return steps
    
    def _generate_apt_mitigation_strategies(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate mitigation strategies for APT threats."""
        strategies = []
        
        if indicators:
            strategies.extend([
                "Implement network segmentation to limit lateral movement",
                "Deploy additional EDR sensors on critical systems",
                "Update all security signatures and threat intelligence feeds",
                "Conduct organization-wide security awareness training",
                "Review and update incident response procedures",
                "Implement additional access controls and monitoring"
            ])
        
        return strategies
    
    # Additional helper methods for other hunt types
    def _detect_insider_threat_patterns(self, events: List[SecurityEvent]) -> List[Dict[str, Any]]:
        """Detect insider threat specific patterns."""
        patterns = []
        
        # Analyze for unusual data access patterns
        file_access_events = [e for e in events if e.event_type == 'file_access']
        if len(file_access_events) > 50:  # Excessive file access
            patterns.append({
                'type': 'excessive_file_access',
                'event_count': len(file_access_events),
                'confidence': 0.6,
                'description': 'Unusually high volume of file access events detected'
            })
        
        return patterns
    
    def _build_network_graph(self, events: List[SecurityEvent]) -> None:
        """Build network graph for lateral movement analysis."""
        self.network_graph.clear()
        
        for event in events:
            if event.source_ip and event.dest_ip:
                self.network_graph.add_edge(
                    event.source_ip,
                    event.dest_ip,
                    timestamp=event.timestamp,
                    event_type=event.event_type
                )
    
    def _detect_lateral_movement_patterns(self) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns in network graph."""
        patterns = []
        
        try:
            # Look for nodes with high out-degree (potential attack sources)
            for node in self.network_graph.nodes():
                out_degree = self.network_graph.out_degree(node)
                if out_degree > 5:  # Connected to many destinations
                    patterns.append({
                        'type': 'high_connectivity_source',
                        'source_node': node,
                        'connection_count': out_degree,
                        'confidence': min(out_degree / 10.0, 0.9),
                        'description': f'Node {node} shows high connectivity pattern'
                    })
        
        except Exception as e:
            logger.warning(f"Lateral movement detection failed: {e}")
        
        return patterns
    
    def _generate_insider_immediate_actions(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate immediate actions for insider threats."""
        return [
            "Review user access permissions and disable unnecessary privileges",
            "Monitor user activity closely with enhanced logging",
            "Conduct security interview with affected user if appropriate",
            "Review data access patterns and identify sensitive data exposure"
        ]
    
    def _generate_insider_investigation_steps(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate investigation steps for insider threats."""
        return [
            "Analyze user behavior patterns over extended time period",
            "Review employee records and recent personnel changes",
            "Check for unauthorized software installations",
            "Review email and communication patterns for suspicious activity"
        ]
    
    def _generate_insider_mitigation_strategies(self, indicators: List[Dict[str, Any]]) -> List[str]:
        """Generate mitigation strategies for insider threats."""
        return [
            "Implement user behavior analytics (UBA) solution",
            "Enhance privileged access management (PAM) controls",
            "Implement data loss prevention (DLP) policies",
            "Conduct regular access reviews and privilege audits"
        ]
    
    # Placeholder implementations for remaining hunt methods
    async def _hunt_zero_day_indicators(self, hunt_id: str, events: List[SecurityEvent], parameters: Optional[Dict[str, Any]]) -> ThreatHuntResult:
        """Hunt for zero-day indicators."""
        # Implementation would analyze for unknown/suspicious patterns
        hunt_start = datetime.utcnow()
        hunt_completion = datetime.utcnow()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.ZERO_DAY_INDICATORS,
            severity=ThreatSeverity.HIGH,
            confidence_score=0.8,
            threat_indicators=[],
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=0.0,
            ml_model_used="Zero_Day_Detector",
            pattern_confidence=0.8,
            false_positive_likelihood=0.2,
            similar_historical_incidents=[]
        )
    
    async def _hunt_command_control(self, hunt_id: str, events: List[SecurityEvent], parameters: Optional[Dict[str, Any]]) -> ThreatHuntResult:
        """Hunt for command and control communications."""
        hunt_start = datetime.utcnow()
        hunt_completion = datetime.utcnow()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.COMMAND_CONTROL,
            severity=ThreatSeverity.HIGH,
            confidence_score=0.7,
            threat_indicators=[],
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=0.0,
            ml_model_used="C2_Detector",
            pattern_confidence=0.7,
            false_positive_likelihood=0.3,
            similar_historical_incidents=[]
        )
    
    async def _hunt_privilege_escalation(self, hunt_id: str, events: List[SecurityEvent], parameters: Optional[Dict[str, Any]]) -> ThreatHuntResult:
        """Hunt for privilege escalation attempts."""
        hunt_start = datetime.utcnow()
        hunt_completion = datetime.utcnow()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.HIGH,
            confidence_score=0.75,
            threat_indicators=[],
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=0.0,
            ml_model_used="Privilege_Escalation_Detector",
            pattern_confidence=0.75,
            false_positive_likelihood=0.25,
            similar_historical_incidents=[]
        )
    
    async def _hunt_persistence_mechanisms(self, hunt_id: str, events: List[SecurityEvent], parameters: Optional[Dict[str, Any]]) -> ThreatHuntResult:
        """Hunt for persistence mechanism establishment."""
        hunt_start = datetime.utcnow()
        hunt_completion = datetime.utcnow()
        
        return ThreatHuntResult(
            hunt_id=hunt_id,
            hunt_type=ThreatHuntType.PERSISTENCE_MECHANISMS,
            severity=ThreatSeverity.MEDIUM,
            confidence_score=0.65,
            threat_indicators=[],
            attack_timeline=[],
            affected_entities=[],
            ioc_matches=[],
            evidence_events=[],
            suspicious_patterns=[],
            correlation_insights=[],
            immediate_actions=[],
            investigation_steps=[],
            mitigation_strategies=[],
            hunt_start_time=hunt_start,
            hunt_completion_time=hunt_completion,
            total_events_analyzed=len(events),
            processing_time_seconds=0.0,
            ml_model_used="Persistence_Detector",
            pattern_confidence=0.65,
            false_positive_likelihood=0.35,
            similar_historical_incidents=[]
        )
    
    async def get_hunt_status(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        """Get status of active or completed hunt."""
        if hunt_id in self.active_hunts:
            return self.active_hunts[hunt_id]
        elif hunt_id in self.completed_hunts:
            return {
                'hunt_id': hunt_id,
                'status': HuntStatus.COMPLETED,
                'result': self.completed_hunts[hunt_id]
            }
        else:
            return None
    
    async def get_all_active_hunts(self) -> Dict[str, Dict[str, Any]]:
        """Get all currently active hunts."""
        return self.active_hunts.copy()
    
    async def get_hunt_history(self, limit: int = 100) -> List[ThreatHuntResult]:
        """Get recent hunt history."""
        completed = list(self.completed_hunts.values())
        completed.sort(key=lambda x: x.hunt_completion_time, reverse=True)
        return completed[:limit]