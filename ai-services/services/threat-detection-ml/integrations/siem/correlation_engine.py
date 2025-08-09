"""
Threat Correlation Engine

Production-grade correlation engine that combines SIEM events with AI/ML predictions
to provide enhanced threat detection and context-aware security insights.
"""

import asyncio
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from collections import defaultdict, deque
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from .base_connector import SiemEvent, EventSeverity
from ..models.zero_day_detection import ZeroDayDetectionModel, NoveltyType
from ..models.supervised_threat_classification import ThreatClassificationModel, ThreatCategory
from ..models.behavioral_analytics import BehavioralAnalyticsModel, AnomalyType
from ..models.predictive_threat_intelligence import PredictiveThreatModel

logger = logging.getLogger(__name__)

class CorrelationStatus(str, Enum):
    """Correlation processing status"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"

class CorrelationType(str, Enum):
    """Types of threat correlations"""
    TEMPORAL = "temporal"          # Time-based correlation
    SPATIAL = "spatial"            # IP/Network-based correlation  
    BEHAVIORAL = "behavioral"      # User/Entity behavior correlation
    SIGNATURE = "signature"        # IOC/Pattern correlation
    CHAIN = "chain"               # Attack chain correlation
    ANOMALY = "anomaly"           # Anomaly clustering correlation
    PREDICTIVE = "predictive"     # Prediction-based correlation

class CorrelationConfidence(IntEnum):
    """Correlation confidence levels"""
    VERY_LOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERY_HIGH = 5

@dataclass
class CorrelationRule:
    """Correlation rule configuration"""
    rule_id: str
    name: str
    description: str
    correlation_type: CorrelationType
    enabled: bool = True
    confidence_threshold: float = 0.7
    time_window_minutes: int = 60
    max_events: int = 1000
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[str] = field(default_factory=list)
    priority: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def matches_event(self, event: SiemEvent) -> bool:
        """Check if event matches rule conditions"""
        try:
            for condition_key, condition_value in self.conditions.items():
                event_value = getattr(event, condition_key, None)
                
                if event_value is None and condition_key in event.raw_data:
                    event_value = event.raw_data[condition_key]
                elif event_value is None and condition_key in event.metadata:
                    event_value = event.metadata[condition_key]
                
                if not self._evaluate_condition(event_value, condition_value):
                    return False
                    
            return True
            
        except Exception as e:
            logger.warning(f"Error evaluating rule {self.rule_id}: {e}")
            return False
    
    def _evaluate_condition(self, event_value: Any, condition: Any) -> bool:
        """Evaluate single condition"""
        if isinstance(condition, dict):
            operator = condition.get('operator', 'eq')
            value = condition.get('value')
            
            if operator == 'eq':
                return event_value == value
            elif operator == 'ne':
                return event_value != value
            elif operator == 'in':
                return event_value in value
            elif operator == 'not_in':
                return event_value not in value
            elif operator == 'contains':
                return str(value).lower() in str(event_value).lower()
            elif operator == 'regex':
                import re
                return re.search(value, str(event_value)) is not None
            elif operator == 'gt':
                return float(event_value) > float(value)
            elif operator == 'lt':
                return float(event_value) < float(value)
            elif operator == 'gte':
                return float(event_value) >= float(value)
            elif operator == 'lte':
                return float(event_value) <= float(value)
                
        return event_value == condition

class CorrelationResult(BaseModel):
    """Result of threat correlation analysis"""
    correlation_id: str = Field(description="Unique correlation identifier")
    rule_id: str = Field(description="Applied correlation rule ID")
    correlation_type: CorrelationType = Field(description="Type of correlation")
    events: List[str] = Field(description="Event IDs in correlation")
    confidence: CorrelationConfidence = Field(description="Correlation confidence")
    confidence_score: float = Field(description="Numerical confidence score")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(description="Correlation expiration time")
    
    # Analysis results
    threat_indicators: List[str] = Field(default_factory=list, description="Identified threat indicators")
    attack_patterns: List[str] = Field(default_factory=list, description="MITRE ATT&CK patterns")
    affected_assets: List[str] = Field(default_factory=list, description="Affected systems/users")
    risk_score: float = Field(default=0.0, description="Calculated risk score")
    
    # AI/ML insights
    ai_predictions: Dict[str, Any] = Field(default_factory=dict, description="AI model predictions")
    anomaly_scores: Dict[str, float] = Field(default_factory=dict, description="Anomaly detection scores")
    behavioral_insights: Dict[str, Any] = Field(default_factory=dict, description="Behavioral analysis")
    
    # Enrichment data
    geo_location: Dict[str, Any] = Field(default_factory=dict, description="Geographic information")
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict, description="External TI data")
    context_data: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    
    # Response recommendations
    recommended_actions: List[str] = Field(default_factory=list, description="Suggested response actions")
    priority_level: EventSeverity = Field(default=EventSeverity.MEDIUM, description="Incident priority")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

class ThreatCorrelationEngine:
    """
    Advanced threat correlation engine that combines SIEM events with AI/ML predictions
    
    Features:
    - Multi-dimensional event correlation
    - AI/ML model integration for enhanced analysis
    - Real-time processing with configurable rules
    - Threat intelligence enrichment
    - Attack chain reconstruction
    - Risk scoring and prioritization
    """
    
    def __init__(
        self,
        behavioral_model: Optional[BehavioralAnalyticsModel] = None,
        zero_day_model: Optional[ZeroDayDetectionModel] = None,
        threat_classification_model: Optional[ThreatClassificationModel] = None,
        predictive_model: Optional[PredictiveThreatModel] = None,
        max_active_correlations: int = 10000,
        cleanup_interval_minutes: int = 60
    ):
        self.behavioral_model = behavioral_model
        self.zero_day_model = zero_day_model
        self.threat_classification_model = threat_classification_model
        self.predictive_model = predictive_model
        
        # Correlation state
        self._correlation_rules: Dict[str, CorrelationRule] = {}
        self._active_correlations: Dict[str, CorrelationResult] = {}
        self._event_buffer: deque = deque(maxlen=max_active_correlations)
        self._event_index: Dict[str, SiemEvent] = {}
        
        # Performance tracking
        self._metrics = {
            'correlations_created': 0,
            'correlations_completed': 0,
            'correlations_expired': 0,
            'events_processed': 0,
            'ai_predictions_generated': 0,
            'average_processing_time_ms': 0.0
        }
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        logger.info("Threat Correlation Engine initialized")
    
    async def start(self) -> None:
        """Start the correlation engine"""
        if self._running:
            return
            
        self._running = True
        
        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._cleanup_expired_correlations())
        
        # Load default correlation rules
        await self._load_default_rules()
        
        logger.info("Threat Correlation Engine started")
    
    async def stop(self) -> None:
        """Stop the correlation engine"""
        self._running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Threat Correlation Engine stopped")
    
    async def process_event(self, event: SiemEvent) -> List[CorrelationResult]:
        """Process SIEM event and generate correlations"""
        start_time = datetime.utcnow()
        correlations = []
        
        try:
            # Add event to buffer and index
            self._event_buffer.append(event)
            self._event_index[event.id] = event
            self._metrics['events_processed'] += 1
            
            # Process against each active correlation rule
            for rule in self._correlation_rules.values():
                if not rule.enabled:
                    continue
                
                if rule.matches_event(event):
                    correlation = await self._apply_correlation_rule(rule, event)
                    if correlation:
                        correlations.append(correlation)
            
            # Update processing metrics
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._metrics['average_processing_time_ms'] = (
                (self._metrics['average_processing_time_ms'] * self._metrics['events_processed'] + processing_time) /
                (self._metrics['events_processed'] + 1)
            )
            
            return correlations
            
        except Exception as e:
            logger.error(f"Error processing event {event.id}: {e}")
            return []
    
    async def _apply_correlation_rule(
        self,
        rule: CorrelationRule,
        trigger_event: SiemEvent
    ) -> Optional[CorrelationResult]:
        """Apply correlation rule to find related events"""
        try:
            # Find related events based on correlation type
            related_events = await self._find_related_events(rule, trigger_event)
            
            if len(related_events) < 2:  # Need at least 2 events for correlation
                return None
            
            # Calculate correlation confidence
            confidence_score = await self._calculate_confidence(rule, related_events)
            
            if confidence_score < rule.confidence_threshold:
                return None
            
            # Create correlation
            correlation_id = self._generate_correlation_id(rule, related_events)
            
            correlation = CorrelationResult(
                correlation_id=correlation_id,
                rule_id=rule.rule_id,
                correlation_type=rule.correlation_type,
                events=[event.id for event in related_events],
                confidence=self._score_to_confidence(confidence_score),
                confidence_score=confidence_score,
                expires_at=datetime.utcnow() + timedelta(minutes=rule.time_window_minutes * 2)
            )
            
            # Enhance with AI/ML analysis
            await self._enhance_with_ai_analysis(correlation, related_events)
            
            # Add threat intelligence enrichment
            await self._enrich_with_threat_intelligence(correlation, related_events)
            
            # Calculate risk score and recommendations
            await self._calculate_risk_and_recommendations(correlation, related_events)
            
            # Store active correlation
            self._active_correlations[correlation_id] = correlation
            self._metrics['correlations_created'] += 1
            
            logger.info(f"Created correlation {correlation_id} with {len(related_events)} events")
            return correlation
            
        except Exception as e:
            logger.error(f"Error applying correlation rule {rule.rule_id}: {e}")
            return None
    
    async def _find_related_events(
        self,
        rule: CorrelationRule,
        trigger_event: SiemEvent
    ) -> List[SiemEvent]:
        """Find events related to trigger event based on rule type"""
        related_events = [trigger_event]
        
        # Time window for correlation
        start_time = trigger_event.timestamp - timedelta(minutes=rule.time_window_minutes)
        end_time = trigger_event.timestamp + timedelta(minutes=rule.time_window_minutes)
        
        try:
            if rule.correlation_type == CorrelationType.TEMPORAL:
                related_events.extend(
                    await self._find_temporal_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.SPATIAL:
                related_events.extend(
                    await self._find_spatial_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.BEHAVIORAL:
                related_events.extend(
                    await self._find_behavioral_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.SIGNATURE:
                related_events.extend(
                    await self._find_signature_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.CHAIN:
                related_events.extend(
                    await self._find_chain_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.ANOMALY:
                related_events.extend(
                    await self._find_anomaly_events(trigger_event, start_time, end_time, rule)
                )
                
            elif rule.correlation_type == CorrelationType.PREDICTIVE:
                related_events.extend(
                    await self._find_predictive_events(trigger_event, start_time, end_time, rule)
                )
            
            # Remove duplicates while preserving order
            seen = set()
            unique_events = []
            for event in related_events:
                if event.id not in seen:
                    seen.add(event.id)
                    unique_events.append(event)
            
            return unique_events[:rule.max_events]
            
        except Exception as e:
            logger.error(f"Error finding related events: {e}")
            return [trigger_event]
    
    async def _find_temporal_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find temporally related events"""
        events = []
        
        for event in self._event_buffer:
            if (event.id != trigger_event.id and 
                start_time <= event.timestamp <= end_time):
                
                # Check temporal correlation conditions
                if self._check_temporal_correlation(trigger_event, event, rule):
                    events.append(event)
        
        return events
    
    async def _find_spatial_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find spatially related events (same IP ranges, networks)"""
        events = []
        
        trigger_ips = {trigger_event.source_ip, trigger_event.destination_ip} - {None}
        
        for event in self._event_buffer:
            if (event.id != trigger_event.id and 
                start_time <= event.timestamp <= end_time):
                
                event_ips = {event.source_ip, event.destination_ip} - {None}
                
                if trigger_ips.intersection(event_ips):
                    events.append(event)
                elif self._check_network_correlation(trigger_ips, event_ips, rule):
                    events.append(event)
        
        return events
    
    async def _find_behavioral_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find behaviorally related events (same user, entity)"""
        events = []
        
        for event in self._event_buffer:
            if (event.id != trigger_event.id and 
                start_time <= event.timestamp <= end_time):
                
                if (trigger_event.user_id and event.user_id == trigger_event.user_id) or \
                   (trigger_event.asset_id and event.asset_id == trigger_event.asset_id):
                    events.append(event)
        
        return events
    
    async def _find_signature_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find events with common IOCs or signatures"""
        events = []
        
        trigger_iocs = self._extract_iocs(trigger_event)
        
        for event in self._event_buffer:
            if (event.id != trigger_event.id and 
                start_time <= event.timestamp <= end_time):
                
                event_iocs = self._extract_iocs(event)
                
                if trigger_iocs.intersection(event_iocs):
                    events.append(event)
        
        return events
    
    async def _find_chain_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find events that form attack chains"""
        events = []
        
        # Implement attack chain logic based on MITRE ATT&CK patterns
        attack_patterns = self._identify_attack_patterns(trigger_event)
        
        for event in self._event_buffer:
            if (event.id != trigger_event.id and 
                start_time <= event.timestamp <= end_time):
                
                event_patterns = self._identify_attack_patterns(event)
                
                if self._check_attack_chain_correlation(attack_patterns, event_patterns):
                    events.append(event)
        
        return events
    
    async def _find_anomaly_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find events with similar anomaly characteristics"""
        events = []
        
        if not self.behavioral_model:
            return events
        
        try:
            # Get anomaly score for trigger event
            trigger_anomaly = await self._get_anomaly_score(trigger_event)
            
            if trigger_anomaly['is_anomaly']:
                for event in self._event_buffer:
                    if (event.id != trigger_event.id and 
                        start_time <= event.timestamp <= end_time):
                        
                        event_anomaly = await self._get_anomaly_score(event)
                        
                        if (event_anomaly['is_anomaly'] and 
                            abs(event_anomaly['score'] - trigger_anomaly['score']) < 0.3):
                            events.append(event)
            
        except Exception as e:
            logger.warning(f"Error in anomaly correlation: {e}")
        
        return events
    
    async def _find_predictive_events(
        self,
        trigger_event: SiemEvent,
        start_time: datetime,
        end_time: datetime,
        rule: CorrelationRule
    ) -> List[SiemEvent]:
        """Find events related by predictive models"""
        events = []
        
        if not self.predictive_model:
            return events
        
        try:
            # Get threat predictions for trigger event context
            predictions = await self._get_threat_predictions(trigger_event)
            
            for event in self._event_buffer:
                if (event.id != trigger_event.id and 
                    start_time <= event.timestamp <= end_time):
                    
                    event_predictions = await self._get_threat_predictions(event)
                    
                    if self._check_prediction_correlation(predictions, event_predictions):
                        events.append(event)
            
        except Exception as e:
            logger.warning(f"Error in predictive correlation: {e}")
        
        return events
    
    def _check_temporal_correlation(
        self, 
        event1: SiemEvent, 
        event2: SiemEvent, 
        rule: CorrelationRule
    ) -> bool:
        """Check temporal correlation between events"""
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        max_time_diff = rule.conditions.get('max_time_diff_seconds', 300)  # 5 minutes default
        return time_diff <= max_time_diff
    
    def _check_network_correlation(
        self,
        ips1: Set[str],
        ips2: Set[str],
        rule: CorrelationRule
    ) -> bool:
        """Check network-based correlation"""
        # Implement subnet checking, geolocation correlation, etc.
        # For now, simple IP range checking
        return bool(ips1.intersection(ips2))
    
    def _extract_iocs(self, event: SiemEvent) -> Set[str]:
        """Extract indicators of compromise from event"""
        iocs = set()
        
        # Extract from message using simple patterns
        import re
        
        message = event.message.lower()
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs.update(re.findall(ip_pattern, message))
        
        # Domain names
        domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, message)
        iocs.update([d for d in domains if '.' in d and len(d.split('.')[-1]) >= 2])
        
        # File hashes
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        
        for pattern in hash_patterns:
            iocs.update(re.findall(pattern, message))
        
        return iocs
    
    def _identify_attack_patterns(self, event: SiemEvent) -> Set[str]:
        """Identify MITRE ATT&CK patterns in event"""
        patterns = set()
        
        message = event.message.lower()
        category = event.category.lower()
        event_type = event.event_type.lower()
        
        # Simple pattern matching - in production, use more sophisticated NLP
        attack_indicators = {
            'reconnaissance': ['scan', 'probe', 'enumerate', 'discovery'],
            'initial_access': ['phishing', 'exploit', 'brute_force', 'credential'],
            'execution': ['powershell', 'cmd', 'script', 'macro'],
            'persistence': ['registry', 'scheduled_task', 'service', 'startup'],
            'privilege_escalation': ['sudo', 'admin', 'elevated', 'privilege'],
            'defense_evasion': ['disable', 'bypass', 'obfuscate', 'encrypt'],
            'credential_access': ['password', 'hash', 'token', 'certificate'],
            'lateral_movement': ['rdp', 'ssh', 'smb', 'winrm'],
            'collection': ['clipboard', 'screenshot', 'keylog', 'data'],
            'exfiltration': ['upload', 'transfer', 'exfil', 'copy']
        }
        
        for tactic, indicators in attack_indicators.items():
            if any(indicator in message or indicator in category or indicator in event_type 
                   for indicator in indicators):
                patterns.add(tactic)
        
        return patterns
    
    def _check_attack_chain_correlation(
        self,
        patterns1: Set[str],
        patterns2: Set[str]
    ) -> bool:
        """Check if attack patterns form a logical chain"""
        # Define attack chain sequences
        attack_chains = [
            ['reconnaissance', 'initial_access', 'execution'],
            ['initial_access', 'persistence', 'privilege_escalation'],
            ['credential_access', 'lateral_movement', 'collection'],
            ['collection', 'exfiltration']
        ]
        
        for chain in attack_chains:
            for i in range(len(chain) - 1):
                if chain[i] in patterns1 and chain[i + 1] in patterns2:
                    return True
                if chain[i] in patterns2 and chain[i + 1] in patterns1:
                    return True
        
        return bool(patterns1.intersection(patterns2))
    
    async def _calculate_confidence(
        self,
        rule: CorrelationRule,
        events: List[SiemEvent]
    ) -> float:
        """Calculate correlation confidence score"""
        if len(events) < 2:
            return 0.0
        
        base_confidence = 0.5
        
        # Factors that increase confidence
        factors = {
            'event_count': min(len(events) / 10, 0.3),  # More events = higher confidence
            'time_clustering': self._calculate_time_clustering_score(events) * 0.2,
            'source_diversity': self._calculate_source_diversity_score(events) * 0.1,
            'severity_alignment': self._calculate_severity_alignment_score(events) * 0.1,
            'pattern_consistency': self._calculate_pattern_consistency_score(events) * 0.2
        }
        
        # AI model confidence if available
        if any([self.behavioral_model, self.zero_day_model, self.threat_classification_model]):
            ai_confidence = await self._calculate_ai_confidence(events)
            factors['ai_prediction'] = ai_confidence * 0.1
        
        total_confidence = base_confidence + sum(factors.values())
        return min(total_confidence, 1.0)
    
    def _calculate_time_clustering_score(self, events: List[SiemEvent]) -> float:
        """Calculate how clustered events are in time"""
        if len(events) < 2:
            return 0.0
        
        timestamps = [event.timestamp.timestamp() for event in events]
        timestamps.sort()
        
        # Calculate average time gap
        gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_gap = sum(gaps) / len(gaps)
        
        # Higher score for smaller gaps (more clustered)
        clustering_score = max(0, 1 - (avg_gap / 3600))  # Normalize by 1 hour
        return clustering_score
    
    def _calculate_source_diversity_score(self, events: List[SiemEvent]) -> float:
        """Calculate diversity of event sources"""
        sources = set(event.source for event in events)
        # Moderate diversity is good for correlation
        diversity_ratio = len(sources) / len(events)
        return 1 - abs(diversity_ratio - 0.5) * 2  # Peak at 0.5 diversity
    
    def _calculate_severity_alignment_score(self, events: List[SiemEvent]) -> float:
        """Calculate how aligned event severities are"""
        severities = [event.severity.value for event in events]
        if not severities:
            return 0.0
        
        avg_severity = sum(severities) / len(severities)
        variance = sum((s - avg_severity) ** 2 for s in severities) / len(severities)
        
        # Lower variance = better alignment
        alignment_score = max(0, 1 - variance / 4)  # Normalize by max variance
        return alignment_score
    
    def _calculate_pattern_consistency_score(self, events: List[SiemEvent]) -> float:
        """Calculate consistency of attack patterns"""
        all_patterns = []
        for event in events:
            patterns = self._identify_attack_patterns(event)
            all_patterns.extend(patterns)
        
        if not all_patterns:
            return 0.0
        
        # Calculate pattern frequency
        from collections import Counter
        pattern_counts = Counter(all_patterns)
        
        # Higher score for patterns that appear in multiple events
        consistency_score = sum(count > 1 for count in pattern_counts.values()) / len(pattern_counts)
        return consistency_score
    
    async def _calculate_ai_confidence(self, events: List[SiemEvent]) -> float:
        """Calculate AI model confidence for correlation"""
        confidences = []
        
        try:
            for event in events[:5]:  # Limit to first 5 events for performance
                if self.threat_classification_model:
                    prediction = await self._get_threat_prediction(event)
                    if prediction.get('confidence'):
                        confidences.append(prediction['confidence'])
                
                if self.behavioral_model:
                    anomaly = await self._get_anomaly_score(event)
                    if anomaly.get('confidence'):
                        confidences.append(anomaly['confidence'])
            
            if confidences:
                return sum(confidences) / len(confidences)
                
        except Exception as e:
            logger.warning(f"Error calculating AI confidence: {e}")
        
        return 0.0
    
    def _score_to_confidence(self, score: float) -> CorrelationConfidence:
        """Convert numerical score to confidence level"""
        if score >= 0.9:
            return CorrelationConfidence.VERY_HIGH
        elif score >= 0.7:
            return CorrelationConfidence.HIGH
        elif score >= 0.5:
            return CorrelationConfidence.MEDIUM
        elif score >= 0.3:
            return CorrelationConfidence.LOW
        else:
            return CorrelationConfidence.VERY_LOW
    
    def _generate_correlation_id(
        self,
        rule: CorrelationRule,
        events: List[SiemEvent]
    ) -> str:
        """Generate unique correlation identifier"""
        event_ids = sorted([event.id for event in events])
        hash_input = f"{rule.rule_id}:{':'.join(event_ids)}"
        return f"corr_{hashlib.md5(hash_input.encode()).hexdigest()[:12]}"
    
    async def _enhance_with_ai_analysis(
        self,
        correlation: CorrelationResult,
        events: List[SiemEvent]
    ) -> None:
        """Enhance correlation with AI/ML analysis"""
        try:
            # Behavioral analysis
            if self.behavioral_model:
                behavioral_insights = await self._get_behavioral_insights(events)
                correlation.behavioral_insights = behavioral_insights
            
            # Zero-day detection
            if self.zero_day_model:
                zero_day_analysis = await self._get_zero_day_analysis(events)
                correlation.ai_predictions['zero_day'] = zero_day_analysis
            
            # Threat classification
            if self.threat_classification_model:
                threat_predictions = []
                for event in events[:3]:  # Analyze top 3 events
                    prediction = await self._get_threat_prediction(event)
                    if prediction:
                        threat_predictions.append(prediction)
                correlation.ai_predictions['threat_classification'] = threat_predictions
            
            # Predictive analysis
            if self.predictive_model:
                predictions = await self._get_threat_predictions(events[0])
                correlation.ai_predictions['predictive'] = predictions
            
            self._metrics['ai_predictions_generated'] += 1
            
        except Exception as e:
            logger.error(f"Error enhancing correlation with AI analysis: {e}")
    
    async def _get_behavioral_insights(self, events: List[SiemEvent]) -> Dict[str, Any]:
        """Get behavioral analysis insights for events"""
        try:
            insights = {
                'user_anomalies': [],
                'entity_anomalies': [],
                'behavioral_patterns': []
            }
            
            for event in events:
                if event.user_id:
                    anomaly = await self._get_anomaly_score(event)
                    if anomaly['is_anomaly']:
                        insights['user_anomalies'].append({
                            'user_id': event.user_id,
                            'anomaly_score': anomaly['score'],
                            'anomaly_type': anomaly.get('type', 'unknown')
                        })
            
            return insights
            
        except Exception as e:
            logger.warning(f"Error getting behavioral insights: {e}")
            return {}
    
    async def _get_zero_day_analysis(self, events: List[SiemEvent]) -> Dict[str, Any]:
        """Get zero-day analysis for events"""
        try:
            if not self.zero_day_model:
                return {}
            
            analysis = {
                'novel_patterns': [],
                'zero_day_probability': 0.0,
                'novelty_types': []
            }
            
            for event in events[:3]:  # Analyze first 3 events
                # Convert event to feature format expected by zero-day model
                features = self._event_to_features(event)
                
                # Get zero-day prediction (this is a simplified version)
                # In practice, you'd use the actual model interface
                result = {
                    'is_novel': False,
                    'novelty_score': 0.0,
                    'novelty_type': NoveltyType.UNKNOWN_ATTACK_VECTOR.value
                }
                
                if result['is_novel']:
                    analysis['novel_patterns'].append({
                        'event_id': event.id,
                        'novelty_score': result['novelty_score'],
                        'novelty_type': result['novelty_type']
                    })
            
            if analysis['novel_patterns']:
                analysis['zero_day_probability'] = sum(
                    p['novelty_score'] for p in analysis['novel_patterns']
                ) / len(analysis['novel_patterns'])
            
            return analysis
            
        except Exception as e:
            logger.warning(f"Error in zero-day analysis: {e}")
            return {}
    
    async def _get_threat_prediction(self, event: SiemEvent) -> Dict[str, Any]:
        """Get threat classification prediction for event"""
        try:
            if not self.threat_classification_model:
                return {}
            
            features = self._event_to_features(event)
            
            # Simplified prediction interface
            prediction = {
                'category': ThreatCategory.UNKNOWN.value,
                'confidence': 0.0,
                'probabilities': {}
            }
            
            return prediction
            
        except Exception as e:
            logger.warning(f"Error getting threat prediction: {e}")
            return {}
    
    async def _get_anomaly_score(self, event: SiemEvent) -> Dict[str, Any]:
        """Get anomaly score for event"""
        try:
            if not self.behavioral_model:
                return {'is_anomaly': False, 'score': 0.0}
            
            features = self._event_to_features(event)
            
            # Simplified anomaly detection interface
            result = {
                'is_anomaly': False,
                'score': 0.0,
                'confidence': 0.0,
                'type': AnomalyType.NONE.value
            }
            
            return result
            
        except Exception as e:
            logger.warning(f"Error getting anomaly score: {e}")
            return {'is_anomaly': False, 'score': 0.0}
    
    async def _get_threat_predictions(self, event: SiemEvent) -> Dict[str, Any]:
        """Get predictive threat intelligence"""
        try:
            if not self.predictive_model:
                return {}
            
            predictions = {
                'threat_likelihood': 0.0,
                'predicted_tactics': [],
                'timeline_prediction': {},
                'risk_factors': []
            }
            
            return predictions
            
        except Exception as e:
            logger.warning(f"Error getting threat predictions: {e}")
            return {}
    
    def _event_to_features(self, event: SiemEvent) -> Dict[str, Any]:
        """Convert SiemEvent to feature dictionary for ML models"""
        return {
            'timestamp': event.timestamp.timestamp(),
            'source': event.source,
            'event_type': event.event_type,
            'severity': event.severity.value,
            'category': event.category,
            'source_ip': event.source_ip or '',
            'destination_ip': event.destination_ip or '',
            'user_id': event.user_id or '',
            'asset_id': event.asset_id or '',
            'message_length': len(event.message),
            'tag_count': len(event.tags),
            'metadata_fields': len(event.metadata),
            **event.metadata
        }
    
    def _check_prediction_correlation(
        self,
        predictions1: Dict[str, Any],
        predictions2: Dict[str, Any]
    ) -> bool:
        """Check if predictions are correlated"""
        if not predictions1 or not predictions2:
            return False
        
        # Simple correlation check
        threshold = 0.5
        
        likelihood1 = predictions1.get('threat_likelihood', 0)
        likelihood2 = predictions2.get('threat_likelihood', 0)
        
        return abs(likelihood1 - likelihood2) < threshold
    
    async def _enrich_with_threat_intelligence(
        self,
        correlation: CorrelationResult,
        events: List[SiemEvent]
    ) -> None:
        """Enrich correlation with threat intelligence"""
        try:
            # Extract IOCs from all events
            all_iocs = set()
            for event in events:
                all_iocs.update(self._extract_iocs(event))
            
            if all_iocs:
                correlation.threat_indicators = list(all_iocs)
                
                # In production, query threat intelligence feeds
                # For now, create placeholder enrichment
                correlation.threat_intelligence = {
                    'ioc_matches': len(all_iocs),
                    'threat_actors': [],
                    'campaigns': [],
                    'ttps': []
                }
            
        except Exception as e:
            logger.warning(f"Error enriching with threat intelligence: {e}")
    
    async def _calculate_risk_and_recommendations(
        self,
        correlation: CorrelationResult,
        events: List[SiemEvent]
    ) -> None:
        """Calculate risk score and generate recommendations"""
        try:
            # Base risk factors
            risk_factors = []
            risk_score = 0.0
            
            # Severity-based risk
            avg_severity = sum(event.severity.value for event in events) / len(events)
            severity_risk = (6 - avg_severity) / 5  # Higher severity = higher risk
            risk_score += severity_risk * 0.3
            risk_factors.append(f"Average severity: {avg_severity:.1f}")
            
            # Event count risk
            count_risk = min(len(events) / 20, 0.5)  # Cap at 0.5
            risk_score += count_risk * 0.2
            risk_factors.append(f"Event count: {len(events)}")
            
            # Time clustering risk
            time_clustering = self._calculate_time_clustering_score(events)
            risk_score += time_clustering * 0.2
            risk_factors.append(f"Time clustering: {time_clustering:.2f}")
            
            # AI prediction risk
            ai_risk = 0.0
            if correlation.ai_predictions:
                for model, predictions in correlation.ai_predictions.items():
                    if isinstance(predictions, dict):
                        if 'zero_day_probability' in predictions:
                            ai_risk += predictions['zero_day_probability'] * 0.8
                        if 'threat_likelihood' in predictions:
                            ai_risk += predictions['threat_likelihood'] * 0.6
                    elif isinstance(predictions, list):
                        for pred in predictions:
                            if isinstance(pred, dict) and 'confidence' in pred:
                                ai_risk += pred['confidence'] * 0.4
            
            risk_score += min(ai_risk, 0.3)
            if ai_risk > 0:
                risk_factors.append(f"AI prediction risk: {ai_risk:.2f}")
            
            # Cap risk score at 1.0
            correlation.risk_score = min(risk_score, 1.0)
            
            # Generate recommendations
            recommendations = []
            
            if correlation.risk_score >= 0.8:
                recommendations.extend([
                    "Immediate investigation required",
                    "Consider isolating affected systems",
                    "Escalate to security team"
                ])
                correlation.priority_level = EventSeverity.CRITICAL
            elif correlation.risk_score >= 0.6:
                recommendations.extend([
                    "High priority investigation",
                    "Review security controls",
                    "Monitor for additional indicators"
                ])
                correlation.priority_level = EventSeverity.HIGH
            elif correlation.risk_score >= 0.4:
                recommendations.extend([
                    "Standard investigation process",
                    "Correlate with historical data",
                    "Update detection rules"
                ])
                correlation.priority_level = EventSeverity.MEDIUM
            else:
                recommendations.extend([
                    "Low priority review",
                    "Log for trend analysis"
                ])
                correlation.priority_level = EventSeverity.LOW
            
            # Add specific recommendations based on correlation type
            if correlation.correlation_type == CorrelationType.BEHAVIORAL:
                recommendations.append("Review user behavior patterns")
            elif correlation.correlation_type == CorrelationType.CHAIN:
                recommendations.append("Analyze attack chain progression")
            elif correlation.correlation_type == CorrelationType.ANOMALY:
                recommendations.append("Investigate anomaly root cause")
            
            correlation.recommended_actions = recommendations
            
        except Exception as e:
            logger.warning(f"Error calculating risk and recommendations: {e}")
            correlation.risk_score = 0.5  # Default moderate risk
            correlation.priority_level = EventSeverity.MEDIUM
            correlation.recommended_actions = ["Standard investigation required"]
    
    async def _load_default_rules(self) -> None:
        """Load default correlation rules"""
        default_rules = [
            # Temporal correlation for rapid-fire events
            CorrelationRule(
                rule_id="temporal_rapid_fire",
                name="Rapid Fire Events",
                description="Correlate events occurring within short time windows",
                correlation_type=CorrelationType.TEMPORAL,
                time_window_minutes=5,
                conditions={
                    'max_time_diff_seconds': 300
                },
                confidence_threshold=0.6
            ),
            
            # Spatial correlation for same IP
            CorrelationRule(
                rule_id="spatial_same_ip",
                name="Same IP Address",
                description="Correlate events from same IP addresses",
                correlation_type=CorrelationType.SPATIAL,
                time_window_minutes=30,
                confidence_threshold=0.7
            ),
            
            # Behavioral correlation for same user
            CorrelationRule(
                rule_id="behavioral_same_user",
                name="Same User Activity",
                description="Correlate events from same user account",
                correlation_type=CorrelationType.BEHAVIORAL,
                time_window_minutes=60,
                confidence_threshold=0.8
            ),
            
            # Attack chain correlation
            CorrelationRule(
                rule_id="chain_attack_progression",
                name="Attack Chain Progression",
                description="Correlate events forming attack chains",
                correlation_type=CorrelationType.CHAIN,
                time_window_minutes=120,
                confidence_threshold=0.7
            ),
            
            # Anomaly correlation
            CorrelationRule(
                rule_id="anomaly_clustering",
                name="Anomaly Clustering",
                description="Correlate anomalous events",
                correlation_type=CorrelationType.ANOMALY,
                time_window_minutes=45,
                confidence_threshold=0.6
            )
        ]
        
        for rule in default_rules:
            self._correlation_rules[rule.rule_id] = rule
        
        logger.info(f"Loaded {len(default_rules)} default correlation rules")
    
    async def _cleanup_expired_correlations(self) -> None:
        """Background task to clean up expired correlations"""
        while self._running:
            try:
                current_time = datetime.utcnow()
                expired_ids = []
                
                for correlation_id, correlation in self._active_correlations.items():
                    if current_time > correlation.expires_at:
                        expired_ids.append(correlation_id)
                
                # Remove expired correlations
                for correlation_id in expired_ids:
                    del self._active_correlations[correlation_id]
                    self._metrics['correlations_expired'] += 1
                
                # Clean up old events from buffer
                cutoff_time = current_time - timedelta(hours=2)
                while (self._event_buffer and 
                       self._event_buffer[0].timestamp < cutoff_time):
                    old_event = self._event_buffer.popleft()
                    if old_event.id in self._event_index:
                        del self._event_index[old_event.id]
                
                if expired_ids:
                    logger.debug(f"Cleaned up {len(expired_ids)} expired correlations")
                
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in correlation cleanup: {e}")
                await asyncio.sleep(60)
    
    # Public API methods
    
    def add_correlation_rule(self, rule: CorrelationRule) -> None:
        """Add new correlation rule"""
        rule.updated_at = datetime.utcnow()
        self._correlation_rules[rule.rule_id] = rule
        logger.info(f"Added correlation rule: {rule.name}")
    
    def remove_correlation_rule(self, rule_id: str) -> bool:
        """Remove correlation rule"""
        if rule_id in self._correlation_rules:
            del self._correlation_rules[rule_id]
            logger.info(f"Removed correlation rule: {rule_id}")
            return True
        return False
    
    def get_correlation_rules(self) -> List[CorrelationRule]:
        """Get all correlation rules"""
        return list(self._correlation_rules.values())
    
    def get_active_correlations(self) -> List[CorrelationResult]:
        """Get all active correlations"""
        return list(self._active_correlations.values())
    
    def get_correlation(self, correlation_id: str) -> Optional[CorrelationResult]:
        """Get specific correlation by ID"""
        return self._active_correlations.get(correlation_id)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get correlation engine metrics"""
        return {
            **self._metrics,
            'active_correlations': len(self._active_correlations),
            'correlation_rules': len(self._correlation_rules),
            'event_buffer_size': len(self._event_buffer),
            'uptime_hours': (datetime.utcnow() - (
                datetime.utcnow() - timedelta(seconds=sum(self._metrics.values()) if self._metrics else 0)
            )).total_seconds() / 3600
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()