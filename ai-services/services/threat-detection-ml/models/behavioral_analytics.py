"""
Behavioral Analytics Models for AI/ML Threat Detection

This module implements behavioral analytics models that establish baselines
for normal user and entity behavior using statistical and machine learning
techniques. It includes user behavior profiling, entity behavior analysis,
and deviation detection for threat identification.
"""

import asyncio
import logging
import json
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN, IsolationForest
from sklearn.ensemble import IsolationForest, OneClassSVM
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA
import scipy.stats as stats
from scipy.spatial.distance import mahalanobis
import mlflow
import mlflow.sklearn
from pydantic import BaseModel, Field

from ..data_pipeline.collector import SecurityEvent
from ...shared.config.settings import Settings
from ...shared.api.monitoring import MetricsCollector
from ...shared.mlflow.integration import MLFlowManager


logger = logging.getLogger(__name__)


class BehaviorType(Enum):
    """Types of behavior patterns to analyze."""
    USER_LOGIN = "user_login"
    NETWORK_ACCESS = "network_access"
    FILE_ACCESS = "file_access"
    PROCESS_EXECUTION = "process_execution"
    PRIVILEGE_USAGE = "privilege_usage"
    DATA_MOVEMENT = "data_movement"


class AnomalyType(Enum):
    """Types of behavioral anomalies."""
    STATISTICAL_OUTLIER = "statistical_outlier"
    TEMPORAL_ANOMALY = "temporal_anomaly"
    FREQUENCY_ANOMALY = "frequency_anomaly"
    PATTERN_DEVIATION = "pattern_deviation"
    CLUSTERING_OUTLIER = "clustering_outlier"


@dataclass
class BehaviorProfile:
    """Profile representing normal behavior patterns for an entity."""
    entity_id: str
    entity_type: str  # 'user', 'host', 'service'
    behavior_type: BehaviorType
    
    # Statistical baselines
    mean_values: Dict[str, float] = field(default_factory=dict)
    std_values: Dict[str, float] = field(default_factory=dict)
    quantiles: Dict[str, Dict[str, float]] = field(default_factory=dict)
    
    # Temporal patterns
    hourly_patterns: Dict[int, float] = field(default_factory=dict)
    daily_patterns: Dict[int, float] = field(default_factory=dict)
    weekly_patterns: Dict[int, float] = field(default_factory=dict)
    
    # Frequency patterns
    frequency_distributions: Dict[str, Dict[str, float]] = field(default_factory=dict)
    sequence_patterns: List[str] = field(default_factory=list)
    
    # Model parameters
    cluster_centers: Optional[np.ndarray] = None
    covariance_matrix: Optional[np.ndarray] = None
    anomaly_threshold: float = 2.0
    
    # Metadata
    training_start: Optional[datetime] = None
    training_end: Optional[datetime] = None
    total_events: int = 0
    last_update: Optional[datetime] = None


class BehavioralAnomaly(BaseModel):
    """Represents a detected behavioral anomaly."""
    entity_id: str
    entity_type: str
    behavior_type: BehaviorType
    anomaly_type: AnomalyType
    severity_score: float = Field(ge=0.0, le=1.0)
    confidence_score: float = Field(ge=0.0, le=1.0)
    
    # Anomaly details
    observed_values: Dict[str, Any]
    expected_values: Dict[str, Any]
    deviations: Dict[str, float]
    
    # Context
    timestamp: datetime
    related_events: List[str] = Field(default_factory=list)
    description: str = ""
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            BehaviorType: lambda v: v.value,
            AnomalyType: lambda v: v.value
        }


class EntityBehaviorAnalyzer:
    """Analyzes behavior patterns for individual entities."""
    
    def __init__(self, behavior_type: BehaviorType, settings: Settings):
        self.behavior_type = behavior_type
        self.settings = settings
        self.profiles: Dict[str, BehaviorProfile] = {}
        self.scaler = RobustScaler()
        self.cluster_model = None
        self.isolation_forest = None
        self.fitted = False
        
    def create_behavior_profile(
        self, 
        entity_id: str, 
        entity_type: str,
        events: List[SecurityEvent]
    ) -> BehaviorProfile:
        """Create a behavioral profile for an entity."""
        if not events:
            return BehaviorProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                behavior_type=self.behavior_type
            )
        
        # Convert events to DataFrame for analysis
        events_df = pd.DataFrame([self._extract_features(event) for event in events])
        
        profile = BehaviorProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            behavior_type=self.behavior_type,
            total_events=len(events),
            training_start=min(event.timestamp for event in events),
            training_end=max(event.timestamp for event in events),
            last_update=datetime.utcnow()
        )
        
        # Calculate statistical baselines
        profile.mean_values, profile.std_values, profile.quantiles = self._calculate_statistics(events_df)
        
        # Analyze temporal patterns
        profile.hourly_patterns = self._analyze_hourly_patterns(events)
        profile.daily_patterns = self._analyze_daily_patterns(events)
        profile.weekly_patterns = self._analyze_weekly_patterns(events)
        
        # Analyze frequency patterns
        profile.frequency_distributions = self._analyze_frequency_patterns(events_df)
        profile.sequence_patterns = self._analyze_sequence_patterns(events)
        
        # Fit clustering and anomaly detection models
        if len(events_df) >= 10:  # Need minimum samples for modeling
            try:
                features = self._prepare_features_for_modeling(events_df)
                if len(features) > 0:
                    # Fit clustering model
                    optimal_clusters = self._find_optimal_clusters(features)
                    if optimal_clusters > 1:
                        cluster_model = KMeans(n_clusters=optimal_clusters, random_state=42)
                        cluster_labels = cluster_model.fit_predict(features)
                        profile.cluster_centers = cluster_model.cluster_centers_
                    
                    # Calculate covariance matrix for Mahalanobis distance
                    if features.shape[1] > 1:
                        profile.covariance_matrix = np.cov(features.T)
                        
            except Exception as e:
                logger.warning(f"Failed to fit models for {entity_id}: {e}")
        
        return profile
    
    def _extract_features(self, event: SecurityEvent) -> Dict[str, Any]:
        """Extract relevant features from security event based on behavior type."""
        base_features = {
            'timestamp': event.timestamp,
            'hour': event.timestamp.hour,
            'day_of_week': event.timestamp.weekday(),
            'severity': event.severity,
            'source_ip': event.source_ip or 'unknown',
            'dest_ip': event.dest_ip or 'unknown',
        }
        
        if self.behavior_type == BehaviorType.USER_LOGIN:
            return {
                **base_features,
                'username': event.username or 'unknown',
                'hostname': event.hostname or 'unknown',
                'login_method': event.raw_data.get('login_method', 'unknown'),
                'success': event.raw_data.get('login_success', True)
            }
        elif self.behavior_type == BehaviorType.NETWORK_ACCESS:
            return {
                **base_features,
                'protocol': event.network_protocol or 'unknown',
                'port': event.port or 0,
                'bytes_sent': event.raw_data.get('bytes_sent', 0),
                'bytes_received': event.raw_data.get('bytes_received', 0)
            }
        elif self.behavior_type == BehaviorType.FILE_ACCESS:
            return {
                **base_features,
                'file_path': event.file_path or 'unknown',
                'file_operation': event.raw_data.get('file_operation', 'unknown'),
                'file_size': event.raw_data.get('file_size', 0)
            }
        elif self.behavior_type == BehaviorType.PROCESS_EXECUTION:
            return {
                **base_features,
                'process_name': event.process_name or 'unknown',
                'command_line': event.command_line or '',
                'parent_process': event.raw_data.get('parent_process', 'unknown')
            }
        else:
            return base_features
    
    def _calculate_statistics(self, df: pd.DataFrame) -> Tuple[Dict, Dict, Dict]:
        """Calculate statistical baselines from event data."""
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        
        mean_values = {}
        std_values = {}
        quantiles = {}
        
        for col in numeric_cols:
            if col != 'timestamp':
                mean_values[col] = float(df[col].mean())
                std_values[col] = float(df[col].std())
                quantiles[col] = {
                    'q25': float(df[col].quantile(0.25)),
                    'q50': float(df[col].quantile(0.50)),
                    'q75': float(df[col].quantile(0.75)),
                    'q90': float(df[col].quantile(0.90)),
                    'q95': float(df[col].quantile(0.95))
                }
        
        return mean_values, std_values, quantiles
    
    def _analyze_hourly_patterns(self, events: List[SecurityEvent]) -> Dict[int, float]:
        """Analyze hourly activity patterns."""
        hour_counts = defaultdict(int)
        for event in events:
            hour_counts[event.timestamp.hour] += 1
        
        total_events = len(events)
        return {hour: count / total_events for hour, count in hour_counts.items()}
    
    def _analyze_daily_patterns(self, events: List[SecurityEvent]) -> Dict[int, float]:
        """Analyze daily activity patterns."""
        day_counts = defaultdict(int)
        for event in events:
            day_counts[event.timestamp.weekday()] += 1
        
        total_events = len(events)
        return {day: count / total_events for day, count in day_counts.items()}
    
    def _analyze_weekly_patterns(self, events: List[SecurityEvent]) -> Dict[int, float]:
        """Analyze weekly activity patterns."""
        week_counts = defaultdict(int)
        for event in events:
            week = event.timestamp.isocalendar()[1]
            week_counts[week] += 1
        
        total_events = len(events)
        return {week: count / total_events for week, count in week_counts.items()}
    
    def _analyze_frequency_patterns(self, df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
        """Analyze frequency patterns for categorical features."""
        categorical_cols = df.select_dtypes(include=['object']).columns
        frequency_patterns = {}
        
        for col in categorical_cols:
            if col != 'timestamp':
                value_counts = df[col].value_counts()
                total = len(df)
                frequency_patterns[col] = {
                    str(value): count / total 
                    for value, count in value_counts.items()
                }
        
        return frequency_patterns
    
    def _analyze_sequence_patterns(self, events: List[SecurityEvent]) -> List[str]:
        """Analyze sequential patterns in events."""
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Extract sequence patterns (simplified approach)
        sequences = []
        window_size = 5
        
        for i in range(len(sorted_events) - window_size + 1):
            window_events = sorted_events[i:i + window_size]
            sequence = " -> ".join([
                f"{event.event_type}:{event.severity}" 
                for event in window_events
            ])
            sequences.append(sequence)
        
        # Return most common sequences
        from collections import Counter
        sequence_counts = Counter(sequences)
        return [seq for seq, count in sequence_counts.most_common(10)]
    
    def _prepare_features_for_modeling(self, df: pd.DataFrame) -> np.ndarray:
        """Prepare features for clustering and anomaly detection models."""
        # Select numeric features
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_cols = [col for col in numeric_cols if col != 'timestamp']
        
        if len(numeric_cols) == 0:
            return np.array([])
        
        features = df[numeric_cols].fillna(0)
        
        # Scale features
        if not hasattr(self.scaler, 'scale_'):
            self.scaler.fit(features)
        
        return self.scaler.transform(features)
    
    def _find_optimal_clusters(self, features: np.ndarray) -> int:
        """Find optimal number of clusters using silhouette score."""
        if len(features) < 4:
            return 1
        
        max_clusters = min(10, len(features) // 2)
        best_score = -1
        best_k = 1
        
        for k in range(2, max_clusters + 1):
            try:
                kmeans = KMeans(n_clusters=k, random_state=42)
                cluster_labels = kmeans.fit_predict(features)
                score = silhouette_score(features, cluster_labels)
                
                if score > best_score:
                    best_score = score
                    best_k = k
            except Exception:
                continue
        
        return best_k if best_score > 0.3 else 1


class BehavioralAnomalyDetector:
    """Detects behavioral anomalies using established profiles."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("behavioral_anomaly_detection")
        self.profiles: Dict[Tuple[str, BehaviorType], BehaviorProfile] = {}
        
    def load_profiles(self, profiles: Dict[Tuple[str, BehaviorType], BehaviorProfile]) -> None:
        """Load behavioral profiles for anomaly detection."""
        self.profiles = profiles
        logger.info(f"Loaded {len(profiles)} behavioral profiles")
    
    async def detect_anomalies(
        self, 
        events: List[SecurityEvent],
        behavior_type: BehaviorType
    ) -> List[BehavioralAnomaly]:
        """Detect behavioral anomalies in a batch of events."""
        anomalies = []
        
        # Group events by entity
        entity_events = defaultdict(list)
        for event in events:
            entity_id = self._get_entity_id(event, behavior_type)
            if entity_id:
                entity_events[entity_id].append(event)
        
        # Check each entity for anomalies
        for entity_id, entity_event_list in entity_events.items():
            profile_key = (entity_id, behavior_type)
            
            if profile_key not in self.profiles:
                # No profile exists, skip or create baseline
                continue
            
            profile = self.profiles[profile_key]
            entity_anomalies = await self._detect_entity_anomalies(
                entity_id, entity_event_list, profile
            )
            anomalies.extend(entity_anomalies)
        
        logger.info(f"Detected {len(anomalies)} behavioral anomalies")
        return anomalies
    
    async def _detect_entity_anomalies(
        self,
        entity_id: str,
        events: List[SecurityEvent],
        profile: BehaviorProfile
    ) -> List[BehavioralAnomaly]:
        """Detect anomalies for a specific entity."""
        anomalies = []
        
        # Analyze each event against the profile
        for event in events:
            event_anomalies = []
            
            # Statistical anomaly detection
            statistical_anomaly = self._detect_statistical_anomaly(event, profile)
            if statistical_anomaly:
                event_anomalies.append(statistical_anomaly)
            
            # Temporal anomaly detection
            temporal_anomaly = self._detect_temporal_anomaly(event, profile)
            if temporal_anomaly:
                event_anomalies.append(temporal_anomaly)
            
            # Frequency anomaly detection
            frequency_anomaly = self._detect_frequency_anomaly(event, profile)
            if frequency_anomaly:
                event_anomalies.append(frequency_anomaly)
            
            # Clustering-based anomaly detection
            clustering_anomaly = self._detect_clustering_anomaly(event, profile)
            if clustering_anomaly:
                event_anomalies.append(clustering_anomaly)
            
            anomalies.extend(event_anomalies)
        
        # Aggregate anomalies if multiple detected for same event
        return self._aggregate_anomalies(anomalies)
    
    def _detect_statistical_anomaly(
        self, 
        event: SecurityEvent, 
        profile: BehaviorProfile
    ) -> Optional[BehavioralAnomaly]:
        """Detect statistical anomalies using z-scores."""
        analyzer = EntityBehaviorAnalyzer(profile.behavior_type, self.settings)
        features = analyzer._extract_features(event)
        
        deviations = {}
        anomaly_score = 0.0
        
        for feature, value in features.items():
            if isinstance(value, (int, float)) and feature in profile.mean_values:
                mean_val = profile.mean_values[feature]
                std_val = profile.std_values[feature]
                
                if std_val > 0:
                    z_score = abs((value - mean_val) / std_val)
                    if z_score > profile.anomaly_threshold:
                        deviations[feature] = z_score
                        anomaly_score = max(anomaly_score, min(z_score / 5.0, 1.0))
        
        if deviations:
            return BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                behavior_type=profile.behavior_type,
                anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
                severity_score=anomaly_score,
                confidence_score=min(len(deviations) * 0.2, 1.0),
                observed_values={k: features.get(k) for k in deviations.keys()},
                expected_values={k: profile.mean_values.get(k) for k in deviations.keys()},
                deviations=deviations,
                timestamp=event.timestamp,
                related_events=[event.event_id],
                description=f"Statistical outlier detected in {', '.join(deviations.keys())}"
            )
        
        return None
    
    def _detect_temporal_anomaly(
        self, 
        event: SecurityEvent, 
        profile: BehaviorProfile
    ) -> Optional[BehavioralAnomaly]:
        """Detect temporal anomalies based on time patterns."""
        hour = event.timestamp.hour
        day_of_week = event.timestamp.weekday()
        
        # Check hourly patterns
        expected_hourly_freq = profile.hourly_patterns.get(hour, 0.0)
        hourly_threshold = np.mean(list(profile.hourly_patterns.values())) * 0.1
        
        # Check daily patterns
        expected_daily_freq = profile.daily_patterns.get(day_of_week, 0.0)
        daily_threshold = np.mean(list(profile.daily_patterns.values())) * 0.1
        
        anomaly_score = 0.0
        deviations = {}
        
        if expected_hourly_freq < hourly_threshold:
            deviations['unusual_hour'] = hour
            anomaly_score = max(anomaly_score, 0.6)
        
        if expected_daily_freq < daily_threshold:
            deviations['unusual_day'] = day_of_week
            anomaly_score = max(anomaly_score, 0.4)
        
        if deviations:
            return BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                behavior_type=profile.behavior_type,
                anomaly_type=AnomalyType.TEMPORAL_ANOMALY,
                severity_score=anomaly_score,
                confidence_score=0.7,
                observed_values={
                    'hour': hour,
                    'day_of_week': day_of_week
                },
                expected_values={
                    'typical_hour_frequency': expected_hourly_freq,
                    'typical_daily_frequency': expected_daily_freq
                },
                deviations=deviations,
                timestamp=event.timestamp,
                related_events=[event.event_id],
                description=f"Activity detected at unusual time: {deviations}"
            )
        
        return None
    
    def _detect_frequency_anomaly(
        self, 
        event: SecurityEvent, 
        profile: BehaviorProfile
    ) -> Optional[BehavioralAnomaly]:
        """Detect frequency-based anomalies."""
        analyzer = EntityBehaviorAnalyzer(profile.behavior_type, self.settings)
        features = analyzer._extract_features(event)
        
        deviations = {}
        anomaly_score = 0.0
        
        for feature, value in features.items():
            if isinstance(value, str) and feature in profile.frequency_distributions:
                expected_freq = profile.frequency_distributions[feature].get(value, 0.0)
                avg_freq = np.mean(list(profile.frequency_distributions[feature].values()))
                
                if expected_freq < avg_freq * 0.01:  # Very rare value
                    deviations[feature] = value
                    anomaly_score = max(anomaly_score, 0.5)
        
        if deviations:
            return BehavioralAnomaly(
                entity_id=profile.entity_id,
                entity_type=profile.entity_type,
                behavior_type=profile.behavior_type,
                anomaly_type=AnomalyType.FREQUENCY_ANOMALY,
                severity_score=anomaly_score,
                confidence_score=0.6,
                observed_values=deviations,
                expected_values={k: "common_value" for k in deviations.keys()},
                deviations={k: f"rare_value_{v}" for k, v in deviations.items()},
                timestamp=event.timestamp,
                related_events=[event.event_id],
                description=f"Rare values detected: {deviations}"
            )
        
        return None
    
    def _detect_clustering_anomaly(
        self, 
        event: SecurityEvent, 
        profile: BehaviorProfile
    ) -> Optional[BehavioralAnomaly]:
        """Detect anomalies using clustering-based approach."""
        if profile.cluster_centers is None or profile.covariance_matrix is None:
            return None
        
        analyzer = EntityBehaviorAnalyzer(profile.behavior_type, self.settings)
        features = analyzer._extract_features(event)
        
        # Prepare feature vector
        feature_df = pd.DataFrame([features])
        feature_vector = analyzer._prepare_features_for_modeling(feature_df)
        
        if len(feature_vector) == 0:
            return None
        
        try:
            # Calculate Mahalanobis distance to nearest cluster center
            min_distance = float('inf')
            for center in profile.cluster_centers:
                if len(center) == len(feature_vector[0]):
                    distance = mahalanobis(
                        feature_vector[0], 
                        center, 
                        np.linalg.inv(profile.covariance_matrix)
                    )
                    min_distance = min(min_distance, distance)
            
            # Threshold based on chi-square distribution
            threshold = stats.chi2.ppf(0.95, len(feature_vector[0]))
            
            if min_distance > threshold:
                anomaly_score = min(min_distance / (threshold * 2), 1.0)
                
                return BehavioralAnomaly(
                    entity_id=profile.entity_id,
                    entity_type=profile.entity_type,
                    behavior_type=profile.behavior_type,
                    anomaly_type=AnomalyType.CLUSTERING_OUTLIER,
                    severity_score=anomaly_score,
                    confidence_score=0.8,
                    observed_values=features,
                    expected_values={"cluster_distance": float(min_distance)},
                    deviations={"mahalanobis_distance": float(min_distance)},
                    timestamp=event.timestamp,
                    related_events=[event.event_id],
                    description=f"Event far from normal behavior clusters (distance: {min_distance:.2f})"
                )
        
        except Exception as e:
            logger.warning(f"Error in clustering anomaly detection: {e}")
        
        return None
    
    def _aggregate_anomalies(
        self, 
        anomalies: List[BehavioralAnomaly]
    ) -> List[BehavioralAnomaly]:
        """Aggregate multiple anomalies for the same event."""
        if not anomalies:
            return []
        
        # Group by timestamp and related events
        event_anomalies = defaultdict(list)
        for anomaly in anomalies:
            key = (anomaly.timestamp, tuple(anomaly.related_events))
            event_anomalies[key].append(anomaly)
        
        aggregated = []
        for (timestamp, related_events), group_anomalies in event_anomalies.items():
            if len(group_anomalies) == 1:
                aggregated.append(group_anomalies[0])
            else:
                # Aggregate multiple anomalies
                max_severity = max(a.severity_score for a in group_anomalies)
                avg_confidence = np.mean([a.confidence_score for a in group_anomalies])
                
                combined_anomaly = BehavioralAnomaly(
                    entity_id=group_anomalies[0].entity_id,
                    entity_type=group_anomalies[0].entity_type,
                    behavior_type=group_anomalies[0].behavior_type,
                    anomaly_type=AnomalyType.PATTERN_DEVIATION,
                    severity_score=max_severity,
                    confidence_score=avg_confidence,
                    observed_values={},
                    expected_values={},
                    deviations={},
                    timestamp=timestamp,
                    related_events=list(related_events),
                    description=f"Multiple behavioral anomalies detected: {[a.anomaly_type.value for a in group_anomalies]}"
                )
                
                aggregated.append(combined_anomaly)
        
        return aggregated
    
    def _get_entity_id(self, event: SecurityEvent, behavior_type: BehaviorType) -> Optional[str]:
        """Extract entity ID based on behavior type."""
        if behavior_type == BehaviorType.USER_LOGIN:
            return event.username
        elif behavior_type in [BehaviorType.NETWORK_ACCESS, BehaviorType.FILE_ACCESS, 
                               BehaviorType.PROCESS_EXECUTION]:
            return event.hostname or event.source_ip
        else:
            return event.username or event.hostname or event.source_ip


class BehavioralAnalyticsManager:
    """Main manager for behavioral analytics and anomaly detection."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.metrics = MetricsCollector("behavioral_analytics")
        self.mlflow_manager = MLFlowManager(settings)
        
        # Initialize analyzers for different behavior types
        self.analyzers: Dict[BehaviorType, EntityBehaviorAnalyzer] = {
            behavior_type: EntityBehaviorAnalyzer(behavior_type, settings)
            for behavior_type in BehaviorType
        }
        
        # Initialize anomaly detector
        self.anomaly_detector = BehavioralAnomalyDetector(settings)
        
        # Storage for profiles
        self.profiles: Dict[Tuple[str, BehaviorType], BehaviorProfile] = {}
        
    async def train_behavioral_models(
        self, 
        training_events: List[SecurityEvent],
        behavior_types: Optional[List[BehaviorType]] = None
    ) -> Dict[str, Any]:
        """Train behavioral models on historical data."""
        if behavior_types is None:
            behavior_types = list(BehaviorType)
        
        training_results = {}
        
        with mlflow.start_run(run_name="behavioral_analytics_training"):
            for behavior_type in behavior_types:
                logger.info(f"Training behavioral models for {behavior_type.value}")
                
                # Filter events relevant to this behavior type
                relevant_events = self._filter_events_by_behavior_type(
                    training_events, behavior_type
                )
                
                if not relevant_events:
                    logger.warning(f"No events found for behavior type {behavior_type.value}")
                    continue
                
                # Group events by entity
                entity_events = defaultdict(list)
                for event in relevant_events:
                    entity_id = self.anomaly_detector._get_entity_id(event, behavior_type)
                    if entity_id:
                        entity_events[entity_id].append(event)
                
                # Train models for each entity
                analyzer = self.analyzers[behavior_type]
                entity_profiles = {}
                
                for entity_id, events in entity_events.items():
                    if len(events) >= 10:  # Minimum events for meaningful profile
                        entity_type = self._infer_entity_type(entity_id, events)
                        profile = analyzer.create_behavior_profile(
                            entity_id, entity_type, events
                        )
                        entity_profiles[entity_id] = profile
                        self.profiles[(entity_id, behavior_type)] = profile
                
                # Log training metrics
                mlflow.log_metric(f"{behavior_type.value}_entities_trained", len(entity_profiles))
                mlflow.log_metric(f"{behavior_type.value}_total_events", len(relevant_events))
                
                training_results[behavior_type.value] = {
                    'entities_trained': len(entity_profiles),
                    'total_events': len(relevant_events),
                    'profiles': entity_profiles
                }
                
                logger.info(f"Trained {len(entity_profiles)} entity profiles for {behavior_type.value}")
        
        # Load profiles into anomaly detector
        self.anomaly_detector.load_profiles(self.profiles)
        
        # Log overall training metrics
        mlflow.log_metric("total_profiles_trained", len(self.profiles))
        
        return training_results
    
    async def detect_behavioral_anomalies(
        self, 
        events: List[SecurityEvent],
        behavior_types: Optional[List[BehaviorType]] = None
    ) -> List[BehavioralAnomaly]:
        """Detect behavioral anomalies in new events."""
        if behavior_types is None:
            behavior_types = list(BehaviorType)
        
        all_anomalies = []
        
        for behavior_type in behavior_types:
            relevant_events = self._filter_events_by_behavior_type(events, behavior_type)
            
            if relevant_events:
                anomalies = await self.anomaly_detector.detect_anomalies(
                    relevant_events, behavior_type
                )
                all_anomalies.extend(anomalies)
                
                # Log detection metrics
                self.metrics.increment_counter(
                    "anomalies_detected",
                    value=len(anomalies),
                    tags={"behavior_type": behavior_type.value}
                )
        
        logger.info(f"Detected {len(all_anomalies)} total behavioral anomalies")
        return all_anomalies
    
    def _filter_events_by_behavior_type(
        self, 
        events: List[SecurityEvent], 
        behavior_type: BehaviorType
    ) -> List[SecurityEvent]:
        """Filter events relevant to specific behavior type."""
        relevant_events = []
        
        for event in events:
            if behavior_type == BehaviorType.USER_LOGIN:
                if event.event_type in ['authentication', 'login', 'logon']:
                    relevant_events.append(event)
            elif behavior_type == BehaviorType.NETWORK_ACCESS:
                if event.event_type in ['network_connection', 'network_traffic', 'connection']:
                    relevant_events.append(event)
            elif behavior_type == BehaviorType.FILE_ACCESS:
                if event.event_type in ['file_access', 'file_modification', 'file_creation']:
                    relevant_events.append(event)
            elif behavior_type == BehaviorType.PROCESS_EXECUTION:
                if event.event_type in ['process_creation', 'process_execution', 'command_execution']:
                    relevant_events.append(event)
            elif behavior_type == BehaviorType.PRIVILEGE_USAGE:
                if event.event_type in ['privilege_escalation', 'privilege_use', 'elevation']:
                    relevant_events.append(event)
            elif behavior_type == BehaviorType.DATA_MOVEMENT:
                if event.event_type in ['data_transfer', 'data_exfiltration', 'file_transfer']:
                    relevant_events.append(event)
        
        return relevant_events
    
    def _infer_entity_type(self, entity_id: str, events: List[SecurityEvent]) -> str:
        """Infer entity type (user, host, service) from ID and events."""
        # Simple heuristics for entity type inference
        if '@' in entity_id or entity_id.startswith('user'):
            return 'user'
        elif '.' in entity_id or any(event.hostname == entity_id for event in events):
            return 'host'
        else:
            return 'user'  # Default assumption
    
    async def update_behavioral_profiles(
        self, 
        new_events: List[SecurityEvent],
        entity_id: Optional[str] = None,
        behavior_type: Optional[BehaviorType] = None
    ) -> Dict[str, Any]:
        """Update existing behavioral profiles with new events."""
        update_results = {}
        
        # Determine which profiles to update
        profiles_to_update = []
        
        if entity_id and behavior_type:
            key = (entity_id, behavior_type)
            if key in self.profiles:
                profiles_to_update.append(key)
        else:
            # Update all relevant profiles
            for key in self.profiles.keys():
                profile_entity, profile_behavior = key
                if (entity_id is None or profile_entity == entity_id) and \
                   (behavior_type is None or profile_behavior == behavior_type):
                    profiles_to_update.append(key)
        
        for profile_key in profiles_to_update:
            entity_id, behavior_type = profile_key
            profile = self.profiles[profile_key]
            
            # Filter relevant events
            relevant_events = []
            for event in new_events:
                event_entity_id = self.anomaly_detector._get_entity_id(event, behavior_type)
                if event_entity_id == entity_id:
                    event_behavior_events = self._filter_events_by_behavior_type([event], behavior_type)
                    relevant_events.extend(event_behavior_events)
            
            if relevant_events:
                # Update profile with new events
                analyzer = self.analyzers[behavior_type]
                updated_profile = analyzer.create_behavior_profile(
                    entity_id, profile.entity_type, relevant_events
                )
                
                # Merge with existing profile (weighted approach)
                merged_profile = self._merge_profiles(profile, updated_profile)
                self.profiles[profile_key] = merged_profile
                
                update_results[f"{entity_id}_{behavior_type.value}"] = {
                    'new_events': len(relevant_events),
                    'total_events': merged_profile.total_events,
                    'last_update': merged_profile.last_update
                }
        
        # Reload profiles in anomaly detector
        self.anomaly_detector.load_profiles(self.profiles)
        
        return update_results
    
    def _merge_profiles(
        self, 
        existing_profile: BehaviorProfile, 
        new_profile: BehaviorProfile
    ) -> BehaviorProfile:
        """Merge existing profile with new profile using weighted approach."""
        # Simple weighted merge based on event counts
        existing_weight = existing_profile.total_events
        new_weight = new_profile.total_events
        total_weight = existing_weight + new_weight
        
        if total_weight == 0:
            return existing_profile
        
        # Merge statistical values
        merged_means = {}
        merged_stds = {}
        
        for key in set(existing_profile.mean_values.keys()) | set(new_profile.mean_values.keys()):
            existing_val = existing_profile.mean_values.get(key, 0)
            new_val = new_profile.mean_values.get(key, 0)
            
            merged_means[key] = (existing_val * existing_weight + new_val * new_weight) / total_weight
            
            # Simplified std merge (could be improved)
            existing_std = existing_profile.std_values.get(key, 0)
            new_std = new_profile.std_values.get(key, 0)
            merged_stds[key] = np.sqrt(
                (existing_std**2 * existing_weight + new_std**2 * new_weight) / total_weight
            )
        
        # Create merged profile
        merged_profile = BehaviorProfile(
            entity_id=existing_profile.entity_id,
            entity_type=existing_profile.entity_type,
            behavior_type=existing_profile.behavior_type,
            mean_values=merged_means,
            std_values=merged_stds,
            quantiles=new_profile.quantiles,  # Use latest quantiles
            hourly_patterns=new_profile.hourly_patterns,  # Use latest patterns
            daily_patterns=new_profile.daily_patterns,
            weekly_patterns=new_profile.weekly_patterns,
            frequency_distributions=new_profile.frequency_distributions,
            sequence_patterns=new_profile.sequence_patterns,
            cluster_centers=new_profile.cluster_centers,
            covariance_matrix=new_profile.covariance_matrix,
            anomaly_threshold=existing_profile.anomaly_threshold,
            training_start=existing_profile.training_start,
            training_end=new_profile.training_end,
            total_events=total_weight,
            last_update=datetime.utcnow()
        )
        
        return merged_profile
    
    async def save_profiles(self, filepath: str) -> None:
        """Save behavioral profiles to disk."""
        try:
            # Convert profiles to serializable format
            serializable_profiles = {}
            for key, profile in self.profiles.items():
                entity_id, behavior_type = key
                serializable_key = f"{entity_id}_{behavior_type.value}"
                
                serializable_profiles[serializable_key] = {
                    'entity_id': profile.entity_id,
                    'entity_type': profile.entity_type,
                    'behavior_type': profile.behavior_type.value,
                    'mean_values': profile.mean_values,
                    'std_values': profile.std_values,
                    'quantiles': profile.quantiles,
                    'hourly_patterns': profile.hourly_patterns,
                    'daily_patterns': profile.daily_patterns,
                    'weekly_patterns': profile.weekly_patterns,
                    'frequency_distributions': profile.frequency_distributions,
                    'sequence_patterns': profile.sequence_patterns,
                    'cluster_centers': profile.cluster_centers.tolist() if profile.cluster_centers is not None else None,
                    'covariance_matrix': profile.covariance_matrix.tolist() if profile.covariance_matrix is not None else None,
                    'anomaly_threshold': profile.anomaly_threshold,
                    'training_start': profile.training_start.isoformat() if profile.training_start else None,
                    'training_end': profile.training_end.isoformat() if profile.training_end else None,
                    'total_events': profile.total_events,
                    'last_update': profile.last_update.isoformat() if profile.last_update else None
                }
            
            with open(filepath, 'w') as f:
                json.dump(serializable_profiles, f, indent=2)
            
            logger.info(f"Saved {len(self.profiles)} behavioral profiles to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save profiles: {e}")
            raise
    
    async def load_profiles(self, filepath: str) -> None:
        """Load behavioral profiles from disk."""
        try:
            with open(filepath, 'r') as f:
                serializable_profiles = json.load(f)
            
            self.profiles = {}
            for serializable_key, profile_data in serializable_profiles.items():
                entity_id = profile_data['entity_id']
                behavior_type = BehaviorType(profile_data['behavior_type'])
                
                profile = BehaviorProfile(
                    entity_id=entity_id,
                    entity_type=profile_data['entity_type'],
                    behavior_type=behavior_type,
                    mean_values=profile_data['mean_values'],
                    std_values=profile_data['std_values'],
                    quantiles=profile_data['quantiles'],
                    hourly_patterns=profile_data['hourly_patterns'],
                    daily_patterns=profile_data['daily_patterns'],
                    weekly_patterns=profile_data['weekly_patterns'],
                    frequency_distributions=profile_data['frequency_distributions'],
                    sequence_patterns=profile_data['sequence_patterns'],
                    cluster_centers=np.array(profile_data['cluster_centers']) if profile_data['cluster_centers'] else None,
                    covariance_matrix=np.array(profile_data['covariance_matrix']) if profile_data['covariance_matrix'] else None,
                    anomaly_threshold=profile_data['anomaly_threshold'],
                    training_start=datetime.fromisoformat(profile_data['training_start']) if profile_data['training_start'] else None,
                    training_end=datetime.fromisoformat(profile_data['training_end']) if profile_data['training_end'] else None,
                    total_events=profile_data['total_events'],
                    last_update=datetime.fromisoformat(profile_data['last_update']) if profile_data['last_update'] else None
                )
                
                self.profiles[(entity_id, behavior_type)] = profile
            
            # Load profiles into anomaly detector
            self.anomaly_detector.load_profiles(self.profiles)
            
            logger.info(f"Loaded {len(self.profiles)} behavioral profiles from {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to load profiles: {e}")
            raise
    
    async def get_analytics_metrics(self) -> Dict[str, Any]:
        """Get behavioral analytics metrics and statistics."""
        metrics = {
            'total_profiles': len(self.profiles),
            'profiles_by_behavior_type': {},
            'profiles_by_entity_type': {},
            'recent_updates': 0,
            'model_health': {}
        }
        
        # Count profiles by behavior type
        for (entity_id, behavior_type) in self.profiles.keys():
            behavior_key = behavior_type.value
            metrics['profiles_by_behavior_type'][behavior_key] = \
                metrics['profiles_by_behavior_type'].get(behavior_key, 0) + 1
        
        # Count profiles by entity type  
        for profile in self.profiles.values():
            entity_type = profile.entity_type
            metrics['profiles_by_entity_type'][entity_type] = \
                metrics['profiles_by_entity_type'].get(entity_type, 0) + 1
        
        # Count recent updates (last 24 hours)
        cutoff_time = datetime.utcnow() - timedelta(days=1)
        for profile in self.profiles.values():
            if profile.last_update and profile.last_update > cutoff_time:
                metrics['recent_updates'] += 1
        
        # Model health indicators
        healthy_profiles = sum(
            1 for profile in self.profiles.values()
            if profile.total_events >= 10  # Minimum events for healthy profile
        )
        
        metrics['model_health'] = {
            'healthy_profiles': healthy_profiles,
            'profile_health_ratio': healthy_profiles / len(self.profiles) if self.profiles else 0
        }
        
        return metrics