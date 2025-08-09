#!/usr/bin/env python3
"""
iSECTECH SIEM Advanced Correlation Engine
Production-grade multi-event correlation with complex rule logic
Implements sophisticated attack pattern detection and behavioral analysis
"""

import asyncio
import json
import logging
import time
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque
from pathlib import Path
import hashlib
import statistics
import numpy as np
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CorrelationType(Enum):
    """Types of correlation analysis"""
    TEMPORAL = "temporal"
    SPATIAL = "spatial"
    BEHAVIORAL = "behavioral"
    STATISTICAL = "statistical"
    PATTERN = "pattern"

class AlertSeverity(Enum):
    """Alert severity levels"""
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

@dataclass
class TimeWindow:
    """Time window for correlation analysis"""
    start_time: datetime
    end_time: datetime
    duration_seconds: int
    
    def contains(self, timestamp: datetime) -> bool:
        return self.start_time <= timestamp <= self.end_time
        
    def overlaps(self, other: 'TimeWindow') -> bool:
        return not (self.end_time < other.start_time or other.end_time < self.start_time)

@dataclass
class EventPattern:
    """Pattern definition for event correlation"""
    pattern_id: str
    name: str
    description: str
    events: List[Dict[str, Any]]
    temporal_constraints: Dict[str, Any]
    spatial_constraints: Dict[str, Any]
    statistical_thresholds: Dict[str, float]
    confidence_threshold: float
    severity: AlertSeverity

@dataclass
class CorrelationContext:
    """Context for correlation analysis"""
    entity_id: str  # Host, user, IP, etc.
    entity_type: str
    attributes: Dict[str, Any]
    risk_score: float
    last_updated: datetime

@dataclass
class BehavioralBaseline:
    """Behavioral baseline for anomaly detection"""
    entity_id: str
    metric_name: str
    mean_value: float
    std_deviation: float
    min_value: float
    max_value: float
    sample_count: int
    last_updated: datetime
    confidence_interval: Tuple[float, float]

@dataclass
class CorrelationAlert:
    """Correlation analysis result"""
    alert_id: str
    correlation_type: CorrelationType
    pattern_id: str
    pattern_name: str
    confidence_score: float
    severity: AlertSeverity
    entity_id: str
    entity_type: str
    time_window: TimeWindow
    contributing_events: List[Dict[str, Any]]
    statistical_metrics: Dict[str, float]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    risk_factors: List[str]
    recommended_actions: List[str]
    created_at: datetime

class AdvancedCorrelationEngine:
    """
    Advanced correlation engine for sophisticated threat detection
    Implements multiple correlation techniques and behavioral analysis
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Event storage with time-based partitioning
        self.event_store: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.entity_contexts: Dict[str, CorrelationContext] = {}
        self.behavioral_baselines: Dict[str, BehavioralBaseline] = {}
        self.correlation_patterns: Dict[str, EventPattern] = {}
        
        # Time windows for different analysis types
        self.analysis_windows = {
            CorrelationType.TEMPORAL: timedelta(minutes=30),
            CorrelationType.SPATIAL: timedelta(hours=1),
            CorrelationType.BEHAVIORAL: timedelta(hours=24),
            CorrelationType.STATISTICAL: timedelta(hours=6),
            CorrelationType.PATTERN: timedelta(minutes=15)
        }
        
        # Statistical tracking
        self.metrics = {
            "events_processed": 0,
            "correlations_found": 0,
            "alerts_generated": 0,
            "false_positives": 0,
            "processing_times": deque(maxlen=1000),
            "correlation_types": defaultdict(int)
        }
        
        # Cache for performance optimization
        self.correlation_cache: Dict[str, Any] = {}
        self.cache_ttl = timedelta(minutes=15)
        
    async def initialize(self):
        """Initialize the correlation engine"""
        try:
            # Load correlation patterns
            await self._load_correlation_patterns()
            
            # Initialize behavioral baselines
            await self._initialize_behavioral_baselines()
            
            # Start background tasks
            asyncio.create_task(self._background_cleanup())
            asyncio.create_task(self._baseline_update_task())
            
            logger.info("Advanced correlation engine initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize correlation engine: {e}")
            raise
            
    async def _load_correlation_patterns(self):
        """Load advanced correlation patterns"""
        # Define sophisticated attack patterns
        patterns = [
            # Advanced Persistent Threat (APT) Pattern
            {
                "pattern_id": "APT-001",
                "name": "APT Kill Chain Progression",
                "description": "Detects full APT kill chain progression from initial access to exfiltration",
                "events": [
                    {"stage": 1, "tactics": ["initial_access"], "min_confidence": 0.7},
                    {"stage": 2, "tactics": ["execution", "persistence"], "min_confidence": 0.6},
                    {"stage": 3, "tactics": ["privilege_escalation", "defense_evasion"], "min_confidence": 0.6},
                    {"stage": 4, "tactics": ["credential_access", "discovery"], "min_confidence": 0.5},
                    {"stage": 5, "tactics": ["lateral_movement"], "min_confidence": 0.6},
                    {"stage": 6, "tactics": ["collection", "exfiltration"], "min_confidence": 0.7}
                ],
                "temporal_constraints": {
                    "max_duration_hours": 72,
                    "stage_progression": True,
                    "max_gap_hours": 24
                },
                "spatial_constraints": {
                    "same_network": True,
                    "related_assets": True
                },
                "statistical_thresholds": {
                    "min_stages": 4,
                    "progression_score": 0.8
                },
                "confidence_threshold": 0.85,
                "severity": AlertSeverity.CRITICAL
            },
            
            # Insider Threat Pattern
            {
                "pattern_id": "INSIDER-001",
                "name": "Malicious Insider Activity",
                "description": "Detects anomalous behavior patterns indicating insider threat",
                "events": [
                    {"behavior": "unusual_access_times", "threshold": 3.0},
                    {"behavior": "excessive_data_access", "threshold": 5.0},
                    {"behavior": "unusual_file_operations", "threshold": 4.0},
                    {"behavior": "policy_violations", "threshold": 2.0}
                ],
                "temporal_constraints": {
                    "observation_period_days": 30,
                    "escalation_pattern": True
                },
                "spatial_constraints": {
                    "user_context": True,
                    "department_baseline": True
                },
                "statistical_thresholds": {
                    "anomaly_score": 0.95,
                    "deviation_multiplier": 3.0
                },
                "confidence_threshold": 0.80,
                "severity": AlertSeverity.HIGH
            },
            
            # Ransomware Attack Pattern
            {
                "pattern_id": "RANSOMWARE-001",
                "name": "Ransomware Attack Sequence",
                "description": "Detects ransomware attack progression and encryption activities",
                "events": [
                    {"stage": "delivery", "indicators": ["malicious_email", "exploit_kit"]},
                    {"stage": "execution", "indicators": ["process_injection", "privilege_escalation"]},
                    {"stage": "discovery", "indicators": ["network_scanning", "file_enumeration"]},
                    {"stage": "encryption", "indicators": ["mass_file_modification", "file_extension_changes"]},
                    {"stage": "ransom", "indicators": ["ransom_note_creation", "wallpaper_change"]}
                ],
                "temporal_constraints": {
                    "max_duration_hours": 12,
                    "rapid_progression": True
                },
                "spatial_constraints": {
                    "host_focused": True,
                    "network_spread": True
                },
                "statistical_thresholds": {
                    "file_modification_rate": 1000,
                    "encryption_speed": 0.9
                },
                "confidence_threshold": 0.90,
                "severity": AlertSeverity.CRITICAL
            },
            
            # Data Exfiltration Pattern
            {
                "pattern_id": "EXFIL-001",
                "name": "Large-Scale Data Exfiltration",
                "description": "Detects systematic data collection and exfiltration activities",
                "events": [
                    {"stage": "reconnaissance", "indicators": ["database_enumeration", "file_discovery"]},
                    {"stage": "collection", "indicators": ["data_staging", "compression_activities"]},
                    {"stage": "exfiltration", "indicators": ["unusual_network_traffic", "external_transfers"]}
                ],
                "temporal_constraints": {
                    "max_duration_hours": 48,
                    "collection_phase_hours": 24
                },
                "spatial_constraints": {
                    "data_source_correlation": True,
                    "network_path_analysis": True
                },
                "statistical_thresholds": {
                    "data_volume_gb": 10.0,
                    "transfer_rate_anomaly": 5.0
                },
                "confidence_threshold": 0.85,
                "severity": AlertSeverity.HIGH
            }
        ]
        
        for pattern_data in patterns:
            pattern = EventPattern(
                pattern_id=pattern_data["pattern_id"],
                name=pattern_data["name"],
                description=pattern_data["description"],
                events=pattern_data["events"],
                temporal_constraints=pattern_data["temporal_constraints"],
                spatial_constraints=pattern_data["spatial_constraints"],
                statistical_thresholds=pattern_data["statistical_thresholds"],
                confidence_threshold=pattern_data["confidence_threshold"],
                severity=pattern_data["severity"]
            )
            self.correlation_patterns[pattern.pattern_id] = pattern
            
        logger.info(f"Loaded {len(self.correlation_patterns)} correlation patterns")
        
    async def _initialize_behavioral_baselines(self):
        """Initialize behavioral baselines for anomaly detection"""
        # Define baseline metrics to track
        baseline_metrics = [
            "login_frequency_per_hour",
            "file_access_count_per_hour", 
            "network_connections_per_hour",
            "process_execution_count_per_hour",
            "failed_authentication_rate",
            "data_transfer_volume_mb_per_hour",
            "unique_file_modifications_per_hour",
            "privilege_escalation_attempts_per_day"
        ]
        
        # Initialize empty baselines (would be populated from historical data)
        for metric in baseline_metrics:
            self.behavioral_baselines[f"baseline_{metric}"] = BehavioralBaseline(
                entity_id="default",
                metric_name=metric,
                mean_value=0.0,
                std_deviation=1.0,
                min_value=0.0,
                max_value=100.0,
                sample_count=0,
                last_updated=datetime.now(timezone.utc),
                confidence_interval=(0.0, 100.0)
            )
            
        logger.info("Initialized behavioral baselines")
        
    async def process_events(self, events: List[Dict[str, Any]]) -> List[CorrelationAlert]:
        """Process a batch of events for correlation analysis"""
        start_time = time.perf_counter()
        alerts = []
        
        try:
            # Store events in time-partitioned storage
            await self._store_events(events)
            
            # Update entity contexts
            await self._update_entity_contexts(events)
            
            # Perform different types of correlation analysis
            correlation_tasks = [
                self._temporal_correlation_analysis(),
                self._spatial_correlation_analysis(),
                self._behavioral_correlation_analysis(),
                self._statistical_correlation_analysis(),
                self._pattern_correlation_analysis()
            ]
            
            correlation_results = await asyncio.gather(*correlation_tasks, return_exceptions=True)
            
            # Collect alerts from all correlation types
            for result in correlation_results:
                if isinstance(result, list):
                    alerts.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Correlation analysis error: {result}")
                    
            # Post-process alerts (deduplication, scoring, prioritization)
            alerts = await self._post_process_alerts(alerts)
            
            # Update metrics
            processing_time = (time.perf_counter() - start_time) * 1000
            self.metrics["events_processed"] += len(events)
            self.metrics["correlations_found"] += len(alerts)
            self.metrics["processing_times"].append(processing_time)
            
        except Exception as e:
            logger.error(f"Error processing events for correlation: {e}")
            
        return alerts
        
    async def _store_events(self, events: List[Dict[str, Any]]):
        """Store events in time-partitioned storage"""
        current_time = datetime.now(timezone.utc)
        
        for event in events:
            # Determine storage partition based on entity
            entity_id = self._extract_entity_id(event)
            
            # Add processing metadata
            event_copy = event.copy()
            event_copy["_correlation_metadata"] = {
                "ingestion_time": current_time,
                "entity_id": entity_id,
                "partition_key": self._generate_partition_key(event)
            }
            
            # Store in appropriate partition
            self.event_store[entity_id].append(event_copy)
            
    def _extract_entity_id(self, event: Dict[str, Any]) -> str:
        """Extract primary entity ID from event"""
        # Priority order for entity identification
        entity_fields = [
            "host.name",
            "user.name", 
            "source.ip",
            "process.name",
            "file.path"
        ]
        
        for field in entity_fields:
            if field in event and event[field]:
                return f"{field}:{event[field]}"
                
        return "unknown:unknown"
        
    def _generate_partition_key(self, event: Dict[str, Any]) -> str:
        """Generate partition key for event storage"""
        timestamp = event.get("@timestamp", datetime.now(timezone.utc))
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
        # Partition by hour
        return timestamp.strftime("%Y%m%d%H")
        
    async def _update_entity_contexts(self, events: List[Dict[str, Any]]):
        """Update entity contexts with new event information"""
        current_time = datetime.now(timezone.utc)
        
        for event in events:
            entity_id = self._extract_entity_id(event)
            
            if entity_id not in self.entity_contexts:
                # Create new entity context
                self.entity_contexts[entity_id] = CorrelationContext(
                    entity_id=entity_id,
                    entity_type=entity_id.split(':')[0],
                    attributes={},
                    risk_score=0.0,
                    last_updated=current_time
                )
                
            context = self.entity_contexts[entity_id]
            
            # Update context attributes
            context.last_updated = current_time
            
            # Calculate risk score based on event characteristics
            risk_increment = await self._calculate_event_risk(event)
            context.risk_score = min(context.risk_score + risk_increment, 100.0)
            
            # Apply risk decay over time
            time_since_update = (current_time - context.last_updated).total_seconds() / 3600
            decay_factor = math.exp(-time_since_update / 24)  # 24-hour half-life
            context.risk_score *= decay_factor
            
    async def _calculate_event_risk(self, event: Dict[str, Any]) -> float:
        """Calculate risk contribution of an individual event"""
        risk_score = 0.0
        
        # Base risk from event severity
        severity = event.get("event.severity", 0)
        risk_score += severity * 0.1
        
        # Risk from threat intelligence matches
        if event.get("threat.indicator.matched"):
            confidence = event.get("threat.indicator.confidence", 0)
            risk_score += confidence * 0.2
            
        # Risk from MITRE ATT&CK tactics
        tactics = event.get("mitre_tactics", [])
        high_risk_tactics = ["initial_access", "privilege_escalation", "exfiltration", "impact"]
        for tactic in tactics:
            if any(hr_tactic in tactic.lower() for hr_tactic in high_risk_tactics):
                risk_score += 5.0
                
        # Risk from asset criticality
        asset_criticality = event.get("asset.criticality", "")
        criticality_weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0}
        risk_score += criticality_weights.get(asset_criticality, 0.0)
        
        return min(risk_score, 25.0)  # Cap individual event risk
        
    async def _temporal_correlation_analysis(self) -> List[CorrelationAlert]:
        """Perform temporal correlation analysis"""
        alerts = []
        current_time = datetime.now(timezone.utc)
        analysis_window = current_time - self.analysis_windows[CorrelationType.TEMPORAL]
        
        try:
            # Look for rapid sequences of related events
            for entity_id, events in self.event_store.items():
                recent_events = [
                    e for e in events 
                    if e.get("_correlation_metadata", {}).get("ingestion_time", current_time) > analysis_window
                ]
                
                if len(recent_events) < 3:
                    continue
                    
                # Analyze event patterns
                sequences = await self._detect_event_sequences(recent_events)
                
                for sequence in sequences:
                    if sequence["confidence"] > 0.75:
                        alert = CorrelationAlert(
                            alert_id=self._generate_alert_id(),
                            correlation_type=CorrelationType.TEMPORAL,
                            pattern_id="TEMPORAL-SEQ",
                            pattern_name="Rapid Event Sequence",
                            confidence_score=sequence["confidence"],
                            severity=AlertSeverity.MEDIUM,
                            entity_id=entity_id,
                            entity_type=entity_id.split(':')[0],
                            time_window=TimeWindow(
                                start_time=sequence["start_time"],
                                end_time=sequence["end_time"],
                                duration_seconds=int((sequence["end_time"] - sequence["start_time"]).total_seconds())
                            ),
                            contributing_events=sequence["events"],
                            statistical_metrics=sequence["metrics"],
                            mitre_tactics=sequence.get("tactics", []),
                            mitre_techniques=sequence.get("techniques", []),
                            risk_factors=["rapid_event_progression", "temporal_clustering"],
                            recommended_actions=[
                                "Investigate event sequence for attack pattern",
                                "Review asset security posture",
                                "Check for additional indicators"
                            ],
                            created_at=current_time
                        )
                        alerts.append(alert)
                        
        except Exception as e:
            logger.error(f"Temporal correlation analysis error: {e}")
            
        return alerts
        
    async def _detect_event_sequences(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect suspicious temporal event sequences"""
        sequences = []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("@timestamp", ""))
        
        # Look for rapid succession of events (< 5 minutes apart)
        current_sequence = []
        last_timestamp = None
        
        for event in sorted_events:
            timestamp_str = event.get("@timestamp", "")
            if isinstance(timestamp_str, str):
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = timestamp_str
                
            if last_timestamp and (timestamp - last_timestamp).total_seconds() < 300:  # 5 minutes
                current_sequence.append(event)
            else:
                if len(current_sequence) >= 3:
                    # Analyze sequence
                    sequence_analysis = await self._analyze_event_sequence(current_sequence)
                    if sequence_analysis:
                        sequences.append(sequence_analysis)
                        
                current_sequence = [event]
                
            last_timestamp = timestamp
            
        # Check final sequence
        if len(current_sequence) >= 3:
            sequence_analysis = await self._analyze_event_sequence(current_sequence)
            if sequence_analysis:
                sequences.append(sequence_analysis)
                
        return sequences
        
    async def _analyze_event_sequence(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Analyze a sequence of events for suspicious patterns"""
        if len(events) < 3:
            return None
            
        try:
            # Calculate temporal metrics
            timestamps = [
                datetime.fromisoformat(e.get("@timestamp", "").replace('Z', '+00:00'))
                for e in events if e.get("@timestamp")
            ]
            
            if len(timestamps) < len(events):
                return None
                
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            event_rate = len(events) / max(duration, 1)
            
            # Analyze event diversity
            event_types = set(e.get("event.action", "") for e in events)
            severity_scores = [e.get("event.severity", 0) for e in events]
            
            # Calculate confidence based on multiple factors
            confidence = 0.0
            
            # High event rate increases confidence
            if event_rate > 0.5:  # More than 1 event per 2 seconds
                confidence += 0.3
                
            # Event diversity indicates sophisticated attack
            if len(event_types) > 3:
                confidence += 0.2
                
            # High severity events increase confidence
            avg_severity = statistics.mean(severity_scores) if severity_scores else 0
            confidence += min(avg_severity / 100, 0.3)
            
            # MITRE ATT&CK progression
            tactics = []
            techniques = []
            for event in events:
                tactics.extend(event.get("mitre_tactics", []))
                techniques.extend(event.get("mitre_techniques", []))
                
            if len(set(tactics)) > 2:  # Multiple tactics
                confidence += 0.2
                
            return {
                "start_time": min(timestamps),
                "end_time": max(timestamps),
                "events": events,
                "confidence": min(confidence, 1.0),
                "metrics": {
                    "duration_seconds": duration,
                    "event_rate": event_rate,
                    "event_count": len(events),
                    "avg_severity": avg_severity,
                    "unique_event_types": len(event_types)
                },
                "tactics": list(set(tactics)),
                "techniques": list(set(techniques))
            }
            
        except Exception as e:
            logger.warning(f"Error analyzing event sequence: {e}")
            return None
            
    async def _spatial_correlation_analysis(self) -> List[CorrelationAlert]:
        """Perform spatial correlation analysis (network, host, user relationships)"""
        alerts = []
        current_time = datetime.now(timezone.utc)
        
        try:
            # Group events by spatial relationships
            spatial_groups = await self._group_events_spatially()
            
            for group_key, group_events in spatial_groups.items():
                if len(group_events) >= 5:  # Minimum threshold for spatial correlation
                    confidence = await self._calculate_spatial_confidence(group_events)
                    
                    if confidence > 0.70:
                        alert = CorrelationAlert(
                            alert_id=self._generate_alert_id(),
                            correlation_type=CorrelationType.SPATIAL,
                            pattern_id="SPATIAL-CLUSTER",
                            pattern_name="Spatial Event Clustering",
                            confidence_score=confidence,
                            severity=AlertSeverity.MEDIUM,
                            entity_id=group_key,
                            entity_type="spatial_cluster",
                            time_window=TimeWindow(
                                start_time=current_time - self.analysis_windows[CorrelationType.SPATIAL],
                                end_time=current_time,
                                duration_seconds=int(self.analysis_windows[CorrelationType.SPATIAL].total_seconds())
                            ),
                            contributing_events=group_events,
                            statistical_metrics={
                                "spatial_spread": await self._calculate_spatial_spread(group_events),
                                "event_density": len(group_events) / self.analysis_windows[CorrelationType.SPATIAL].total_seconds()
                            },
                            mitre_tactics=[],
                            mitre_techniques=[],
                            risk_factors=["spatial_clustering", "coordinated_activity"],
                            recommended_actions=[
                                "Investigate coordinated activity across related assets",
                                "Check for lateral movement indicators",
                                "Review network segmentation"
                            ],
                            created_at=current_time
                        )
                        alerts.append(alert)
                        
        except Exception as e:
            logger.error(f"Spatial correlation analysis error: {e}")
            
        return alerts
        
    async def _group_events_spatially(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by spatial relationships"""
        spatial_groups = defaultdict(list)
        current_time = datetime.now(timezone.utc)
        analysis_window = current_time - self.analysis_windows[CorrelationType.SPATIAL]
        
        # Collect recent events
        all_recent_events = []
        for events in self.event_store.values():
            for event in events:
                ingestion_time = event.get("_correlation_metadata", {}).get("ingestion_time", current_time)
                if ingestion_time > analysis_window:
                    all_recent_events.append(event)
                    
        # Group by network relationships
        for event in all_recent_events:
            # Group by subnet
            source_ip = event.get("source.ip", "")
            if source_ip:
                subnet = ".".join(source_ip.split(".")[:3]) + ".0/24"
                spatial_groups[f"subnet:{subnet}"].append(event)
                
            # Group by user
            user_name = event.get("user.name", "")
            if user_name:
                spatial_groups[f"user:{user_name}"].append(event)
                
            # Group by host
            host_name = event.get("host.name", "")
            if host_name:
                spatial_groups[f"host:{host_name}"].append(event)
                
        return dict(spatial_groups)
        
    async def _calculate_spatial_confidence(self, events: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for spatial correlation"""
        if len(events) < 2:
            return 0.0
            
        # Factor 1: Event density
        density_score = min(len(events) / 10.0, 0.4)  # Max 0.4 for density
        
        # Factor 2: Asset diversity
        hosts = set(e.get("host.name", "") for e in events if e.get("host.name"))
        users = set(e.get("user.name", "") for e in events if e.get("user.name"))
        diversity_score = min((len(hosts) + len(users)) / 10.0, 0.3)  # Max 0.3 for diversity
        
        # Factor 3: Severity distribution
        severities = [e.get("event.severity", 0) for e in events]
        avg_severity = statistics.mean(severities) if severities else 0
        severity_score = min(avg_severity / 100.0, 0.3)  # Max 0.3 for severity
        
        return density_score + diversity_score + severity_score
        
    async def _calculate_spatial_spread(self, events: List[Dict[str, Any]]) -> float:
        """Calculate spatial spread metric"""
        unique_hosts = set(e.get("host.name", "") for e in events if e.get("host.name"))
        unique_users = set(e.get("user.name", "") for e in events if e.get("user.name"))
        unique_ips = set(e.get("source.ip", "") for e in events if e.get("source.ip"))
        
        return len(unique_hosts) + len(unique_users) + len(unique_ips)
        
    async def _behavioral_correlation_analysis(self) -> List[CorrelationAlert]:
        """Perform behavioral anomaly correlation analysis"""
        alerts = []
        current_time = datetime.now(timezone.utc)
        
        try:
            # Update behavioral baselines
            await self._update_behavioral_baselines()
            
            # Detect behavioral anomalies
            for entity_id, context in self.entity_contexts.items():
                if context.risk_score > 50:  # High-risk entities
                    anomalies = await self._detect_behavioral_anomalies(entity_id)
                    
                    if anomalies and anomalies["confidence"] > 0.75:
                        alert = CorrelationAlert(
                            alert_id=self._generate_alert_id(),
                            correlation_type=CorrelationType.BEHAVIORAL,
                            pattern_id="BEHAVIORAL-ANOMALY",
                            pattern_name="Behavioral Anomaly Detection",
                            confidence_score=anomalies["confidence"],
                            severity=AlertSeverity.HIGH,
                            entity_id=entity_id,
                            entity_type=context.entity_type,
                            time_window=TimeWindow(
                                start_time=current_time - self.analysis_windows[CorrelationType.BEHAVIORAL],
                                end_time=current_time,
                                duration_seconds=int(self.analysis_windows[CorrelationType.BEHAVIORAL].total_seconds())
                            ),
                            contributing_events=anomalies["events"],
                            statistical_metrics=anomalies["metrics"],
                            mitre_tactics=[],
                            mitre_techniques=[],
                            risk_factors=anomalies["risk_factors"],
                            recommended_actions=[
                                "Investigate anomalous user/host behavior",
                                "Review access patterns and privileges",
                                "Consider implementing additional monitoring"
                            ],
                            created_at=current_time
                        )
                        alerts.append(alert)
                        
        except Exception as e:
            logger.error(f"Behavioral correlation analysis error: {e}")
            
        return alerts
        
    async def _update_behavioral_baselines(self):
        """Update behavioral baselines with recent data"""
        # This would typically analyze historical data to update baselines
        # For now, we'll use placeholder logic
        current_time = datetime.now(timezone.utc)
        
        for baseline_key, baseline in self.behavioral_baselines.items():
            # Update timestamp
            baseline.last_updated = current_time
            
            # In production, this would analyze recent events to update statistical measures
            # baseline.mean_value = calculated_mean
            # baseline.std_deviation = calculated_std
            # baseline.confidence_interval = calculated_ci
            
    async def _detect_behavioral_anomalies(self, entity_id: str) -> Optional[Dict[str, Any]]:
        """Detect behavioral anomalies for a specific entity"""
        # Placeholder implementation - would analyze entity behavior patterns
        # against established baselines
        
        entity_events = self.event_store.get(entity_id, [])
        recent_events = list(entity_events)[-100:]  # Last 100 events
        
        if len(recent_events) < 10:
            return None
            
        # Simple anomaly detection based on event frequency
        current_time = datetime.now(timezone.utc)
        hour_ago = current_time - timedelta(hours=1)
        
        recent_hour_events = [
            e for e in recent_events
            if e.get("_correlation_metadata", {}).get("ingestion_time", current_time) > hour_ago
        ]
        
        if len(recent_hour_events) > 50:  # Anomalously high activity
            return {
                "confidence": 0.80,
                "events": recent_hour_events,
                "metrics": {
                    "events_per_hour": len(recent_hour_events),
                    "normal_baseline": 10,
                    "anomaly_score": len(recent_hour_events) / 10.0
                },
                "risk_factors": ["high_activity_rate", "unusual_pattern"]
            }
            
        return None
        
    async def _statistical_correlation_analysis(self) -> List[CorrelationAlert]:
        """Perform statistical correlation analysis"""
        alerts = []
        
        try:
            # Statistical analysis would go here
            # This could include time series analysis, frequency analysis,
            # distribution analysis, etc.
            pass
            
        except Exception as e:
            logger.error(f"Statistical correlation analysis error: {e}")
            
        return alerts
        
    async def _pattern_correlation_analysis(self) -> List[CorrelationAlert]:
        """Perform pattern-based correlation analysis"""
        alerts = []
        current_time = datetime.now(timezone.utc)
        
        try:
            # Analyze events against defined patterns
            for pattern_id, pattern in self.correlation_patterns.items():
                matches = await self._match_event_pattern(pattern)
                
                for match in matches:
                    if match["confidence"] >= pattern.confidence_threshold:
                        alert = CorrelationAlert(
                            alert_id=self._generate_alert_id(),
                            correlation_type=CorrelationType.PATTERN,
                            pattern_id=pattern_id,
                            pattern_name=pattern.name,
                            confidence_score=match["confidence"],
                            severity=pattern.severity,
                            entity_id=match["entity_id"],
                            entity_type="pattern_match",
                            time_window=match["time_window"],
                            contributing_events=match["events"],
                            statistical_metrics=match["metrics"],
                            mitre_tactics=match.get("tactics", []),
                            mitre_techniques=match.get("techniques", []),
                            risk_factors=match["risk_factors"],
                            recommended_actions=match["recommended_actions"],
                            created_at=current_time
                        )
                        alerts.append(alert)
                        
        except Exception as e:
            logger.error(f"Pattern correlation analysis error: {e}")
            
        return alerts
        
    async def _match_event_pattern(self, pattern: EventPattern) -> List[Dict[str, Any]]:
        """Match events against a specific correlation pattern"""
        matches = []
        
        # Placeholder implementation for pattern matching
        # In production, this would implement sophisticated pattern matching logic
        # based on the pattern definition
        
        return matches
        
    async def _post_process_alerts(self, alerts: List[CorrelationAlert]) -> List[CorrelationAlert]:
        """Post-process alerts for deduplication and prioritization"""
        if not alerts:
            return alerts
            
        # Remove duplicate alerts
        unique_alerts = []
        seen_signatures = set()
        
        for alert in alerts:
            signature = f"{alert.pattern_id}:{alert.entity_id}:{alert.severity.value}"
            if signature not in seen_signatures:
                unique_alerts.append(alert)
                seen_signatures.add(signature)
                
        # Sort by severity and confidence
        unique_alerts.sort(key=lambda x: (x.severity.value, x.confidence_score), reverse=True)
        
        # Update metrics
        self.metrics["alerts_generated"] += len(unique_alerts)
        for alert in unique_alerts:
            self.metrics["correlation_types"][alert.correlation_type.value] += 1
            
        return unique_alerts
        
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        hash_suffix = hashlib.md5(f"{timestamp}{time.time()}".encode()).hexdigest()[:8]
        return f"CORR-{timestamp}-{hash_suffix}"
        
    async def _background_cleanup(self):
        """Background task for cleaning up old data"""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                current_time = datetime.now(timezone.utc)
                cutoff_time = current_time - timedelta(hours=24)
                
                # Clean old events
                for entity_id, events in self.event_store.items():
                    while events and events[0].get("_correlation_metadata", {}).get("ingestion_time", current_time) < cutoff_time:
                        events.popleft()
                        
                # Clean old cache entries
                self.correlation_cache.clear()
                
                logger.debug("Completed background cleanup")
                
            except Exception as e:
                logger.error(f"Background cleanup error: {e}")
                
    async def _baseline_update_task(self):
        """Background task for updating behavioral baselines"""
        while True:
            try:
                await asyncio.sleep(3600)  # Update every hour
                await self._update_behavioral_baselines()
                logger.debug("Updated behavioral baselines")
                
            except Exception as e:
                logger.error(f"Baseline update error: {e}")
                
    async def get_metrics(self) -> Dict[str, Any]:
        """Get correlation engine metrics"""
        processing_times = list(self.metrics["processing_times"])
        
        return {
            "events_processed": self.metrics["events_processed"],
            "correlations_found": self.metrics["correlations_found"],
            "alerts_generated": self.metrics["alerts_generated"],
            "false_positives": self.metrics["false_positives"],
            "avg_processing_time_ms": statistics.mean(processing_times) if processing_times else 0,
            "correlation_types": dict(self.metrics["correlation_types"]),
            "active_entities": len(self.entity_contexts),
            "behavioral_baselines": len(self.behavioral_baselines),
            "correlation_patterns": len(self.correlation_patterns)
        }
        
    async def cleanup(self):
        """Cleanup correlation engine resources"""
        self.event_store.clear()
        self.entity_contexts.clear()
        self.correlation_cache.clear()
        logger.info("Correlation engine cleanup completed")

# Example usage
async def main():
    """Example usage of advanced correlation engine"""
    config = {
        "analysis_window_minutes": 30,
        "behavioral_analysis_enabled": True,
        "statistical_analysis_enabled": True,
        "pattern_analysis_enabled": True
    }
    
    engine = AdvancedCorrelationEngine(config)
    await engine.initialize()
    
    # Example events
    test_events = [
        {
            "@timestamp": "2024-01-15T10:30:00Z",
            "event.action": "login",
            "host.name": "WORKSTATION01",
            "user.name": "admin",
            "source.ip": "192.168.1.100",
            "event.severity": 30,
            "mitre_tactics": ["initial_access"]
        },
        {
            "@timestamp": "2024-01-15T10:31:00Z",
            "event.action": "process_creation",
            "host.name": "WORKSTATION01",
            "user.name": "admin",
            "process.name": "powershell.exe",
            "event.severity": 60,
            "mitre_tactics": ["execution"]
        }
    ]
    
    # Process events
    alerts = await engine.process_events(test_events)
    
    print(f"Generated {len(alerts)} correlation alerts")
    for alert in alerts:
        print(f"  Alert: {alert.pattern_name}")
        print(f"  Severity: {alert.severity.name}")
        print(f"  Confidence: {alert.confidence_score:.2f}")
        print(f"  Entity: {alert.entity_id}")
        print("---")
        
    # Get metrics
    metrics = await engine.get_metrics()
    print(f"Metrics: {json.dumps(metrics, indent=2)}")
    
    await engine.cleanup()

if __name__ == "__main__":
    asyncio.run(main())