#!/usr/bin/env python3
"""
ISECTECH Identity and Access Analytics - User Behavior Analytics Engine
Advanced behavioral baseline establishment and anomaly detection system.

This module provides comprehensive user behavior analytics including:
- Statistical analysis of user patterns and peer group comparison
- Machine learning models for behavioral profiling and anomaly detection
- Geolocation analysis with impossible travel detection
- Time-series analysis for authentication patterns
- Advanced analytics with ensemble methods

Author: ISECTECH Security Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import time
import statistics
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib
import pickle

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import scipy.stats as stats
import geopy.distance
from hmmlearn import hmm
import redis
from croniter import croniter

# ISECTECH Security Configuration
from ..config.security_config import SecurityConfig
from ..core.logging import SecurityLogger
from ..core.metrics import MetricsCollector
from ..core.cache import CacheManager


class BehaviorAnomalyType(Enum):
    """Types of behavioral anomalies detected."""
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    OFF_HOURS_ACCESS = "off_hours_access"
    UNUSUAL_LOCATION = "unusual_location"
    ABNORMAL_FREQUENCY = "abnormal_frequency"
    NEW_DEVICE = "new_device"
    PEER_GROUP_DEVIATION = "peer_group_deviation"
    SESSION_ANOMALY = "session_anomaly"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNUSUAL_RESOURCE_ACCESS = "unusual_resource_access"
    TEMPORAL_PATTERN_BREAK = "temporal_pattern_break"


class RiskLevel(Enum):
    """Risk levels for behavioral anomalies."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class UserProfile:
    """User behavioral profile."""
    user_id: str
    department: str
    role: str
    peer_group: str
    baseline_locations: List[Dict[str, Any]]
    typical_hours: Dict[str, Any]
    device_fingerprints: List[str]
    access_patterns: Dict[str, Any]
    session_characteristics: Dict[str, Any]
    created_time: datetime
    updated_time: datetime
    confidence_score: float = 0.0


@dataclass
class BehaviorEvent:
    """Individual behavior event record."""
    event_id: str
    user_id: str
    timestamp: datetime
    event_type: str
    location: Optional[Dict[str, Any]] = None
    device_info: Optional[Dict[str, Any]] = None
    session_info: Optional[Dict[str, Any]] = None
    resource_accessed: Optional[str] = None
    authentication_method: Optional[str] = None
    success: bool = True
    metadata: Dict[str, Any] = None


@dataclass
class AnomalyResult:
    """Behavioral anomaly detection result."""
    anomaly_id: str
    user_id: str
    anomaly_type: BehaviorAnomalyType
    risk_level: RiskLevel
    confidence_score: float
    description: str
    detected_time: datetime
    event_data: Dict[str, Any]
    baseline_comparison: Dict[str, Any]
    peer_comparison: Dict[str, Any]
    recommended_actions: List[str]
    metadata: Dict[str, Any] = None


@dataclass
class PeerGroup:
    """Peer group definition for comparative analysis."""
    group_id: str
    name: str
    criteria: Dict[str, Any]
    members: List[str]
    behavioral_baseline: Dict[str, Any]
    statistics: Dict[str, Any]
    created_time: datetime
    updated_time: datetime


class UserBehaviorAnalytics:
    """
    ISECTECH User Behavior Analytics Engine
    
    Advanced behavioral analysis system with:
    - Statistical baseline establishment and peer group analysis
    - Machine learning anomaly detection with ensemble methods
    - Geolocation and impossible travel detection
    - Time-series analysis for authentication patterns
    - Real-time behavioral scoring and risk assessment
    """
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.logger = SecurityLogger("user_behavior_analytics")
        self.metrics = MetricsCollector("iaa_behavior")
        self.cache = CacheManager("behavior_cache")
        
        # Database setup
        self.db_path = config.get("iaa.behavior_db_path", "iaa_behavior_analytics.db")
        self._init_database()
        
        # Redis for real-time caching
        self.redis_client = redis.Redis(
            host=config.get("redis.host", "localhost"),
            port=config.get("redis.port", 6379),
            db=config.get("redis.db", 6),
            decode_responses=False
        )
        
        # Thread pool for ML operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=config.get("iaa.behavior.max_workers", 6)
        )
        
        # User profiles and peer groups
        self.user_profiles: Dict[str, UserProfile] = {}
        self.peer_groups: Dict[str, PeerGroup] = {}
        
        # ML models for anomaly detection
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.one_class_svm = OneClassSVM(nu=0.1)
        self.scaler = StandardScaler()
        
        # Behavioral parameters
        self.impossible_travel_threshold = config.get("iaa.behavior.impossible_travel_kmh", 800)  # km/h
        self.location_radius_km = config.get("iaa.behavior.location_radius_km", 50)
        self.baseline_days = config.get("iaa.behavior.baseline_days", 30)
        self.anomaly_threshold = config.get("iaa.behavior.anomaly_threshold", 0.7)
        
        # Load existing data
        self._load_user_profiles()
        self._load_peer_groups()
        
        # Start background tasks
        asyncio.create_task(self._baseline_update_task())
        asyncio.create_task(self._peer_group_update_task())
        
        self.logger.info("ISECTECH User Behavior Analytics Engine initialized")


    def _init_database(self):
        """Initialize SQLite database with behavior analytics schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # User profiles table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_profiles (
            user_id TEXT PRIMARY KEY,
            department TEXT NOT NULL,
            role TEXT NOT NULL,
            peer_group TEXT NOT NULL,
            baseline_locations TEXT NOT NULL,  -- JSON
            typical_hours TEXT NOT NULL,      -- JSON
            device_fingerprints TEXT NOT NULL, -- JSON
            access_patterns TEXT NOT NULL,    -- JSON
            session_characteristics TEXT NOT NULL, -- JSON
            confidence_score REAL DEFAULT 0.0,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Behavior events table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavior_events (
            event_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            event_type TEXT NOT NULL,
            location TEXT,                    -- JSON
            device_info TEXT,                -- JSON
            session_info TEXT,               -- JSON
            resource_accessed TEXT,
            authentication_method TEXT,
            success BOOLEAN DEFAULT 1,
            metadata TEXT,                   -- JSON
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
        """)
        
        # Anomaly results table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomaly_results (
            anomaly_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            description TEXT NOT NULL,
            detected_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_data TEXT NOT NULL,        -- JSON
            baseline_comparison TEXT NOT NULL, -- JSON
            peer_comparison TEXT NOT NULL,   -- JSON
            recommended_actions TEXT NOT NULL, -- JSON
            metadata TEXT,                   -- JSON
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
        """)
        
        # Peer groups table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS peer_groups (
            group_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            criteria TEXT NOT NULL,         -- JSON
            members TEXT NOT NULL,          -- JSON
            behavioral_baseline TEXT NOT NULL, -- JSON
            statistics TEXT NOT NULL,       -- JSON
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Behavioral baselines table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS behavioral_baselines (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            baseline_type TEXT NOT NULL,
            baseline_data TEXT NOT NULL,    -- JSON
            validity_period INTEGER NOT NULL, -- days
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_time TIMESTAMP NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user_profiles (user_id)
        )
        """)
        
        # Performance indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_events_user ON behavior_events(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_behavior_events_timestamp ON behavior_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_results_user ON anomaly_results(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_results_type ON anomaly_results(anomaly_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_results_risk ON anomaly_results(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_user ON behavioral_baselines(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_baselines_type ON behavioral_baselines(baseline_type)")
        
        conn.commit()
        conn.close()
        
        self.logger.info("Behavior analytics database initialized")


    def _load_user_profiles(self):
        """Load user profiles from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM user_profiles")
        rows = cursor.fetchall()
        
        for row in rows:
            profile = UserProfile(
                user_id=row[0],
                department=row[1],
                role=row[2],
                peer_group=row[3],
                baseline_locations=json.loads(row[4]),
                typical_hours=json.loads(row[5]),
                device_fingerprints=json.loads(row[6]),
                access_patterns=json.loads(row[7]),
                session_characteristics=json.loads(row[8]),
                confidence_score=row[9],
                created_time=datetime.fromisoformat(row[10]),
                updated_time=datetime.fromisoformat(row[11])
            )
            self.user_profiles[profile.user_id] = profile
        
        conn.close()
        self.logger.info(f"Loaded {len(self.user_profiles)} user profiles")


    def _load_peer_groups(self):
        """Load peer groups from database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM peer_groups")
        rows = cursor.fetchall()
        
        for row in rows:
            peer_group = PeerGroup(
                group_id=row[0],
                name=row[1],
                criteria=json.loads(row[2]),
                members=json.loads(row[3]),
                behavioral_baseline=json.loads(row[4]),
                statistics=json.loads(row[5]),
                created_time=datetime.fromisoformat(row[6]),
                updated_time=datetime.fromisoformat(row[7])
            )
            self.peer_groups[peer_group.group_id] = peer_group
        
        conn.close()
        self.logger.info(f"Loaded {len(self.peer_groups)} peer groups")


    async def process_behavior_event_async(self, event: BehaviorEvent) -> List[AnomalyResult]:
        """
        Process a behavior event and detect anomalies.
        
        Args:
            event: Behavior event to analyze
            
        Returns:
            List of detected anomalies
        """
        start_time = time.time()
        anomalies = []
        
        # Save event to database
        await self._save_behavior_event(event)
        
        # Get or create user profile
        user_profile = await self._get_or_create_user_profile(event.user_id)
        
        # Check for various anomaly types
        anomaly_checks = [
            self._check_impossible_travel,
            self._check_off_hours_access,
            self._check_unusual_location,
            self._check_abnormal_frequency,
            self._check_new_device,
            self._check_peer_group_deviation,
            self._check_session_anomaly,
            self._check_temporal_pattern_break
        ]
        
        # Run anomaly checks concurrently
        check_tasks = []
        for check_func in anomaly_checks:
            task = asyncio.create_task(
                asyncio.get_event_loop().run_in_executor(
                    self.thread_pool,
                    check_func,
                    event, user_profile
                )
            )
            check_tasks.append(task)
        
        # Collect results
        for task in asyncio.as_completed(check_tasks):
            try:
                result = await task
                if result:
                    anomalies.append(result)
            except Exception as e:
                self.logger.error(f"Anomaly check failed: {str(e)}")
        
        # Save anomalies
        for anomaly in anomalies:
            await self._save_anomaly_result(anomaly)
        
        # Update user profile
        await self._update_user_profile_incremental(user_profile, event)
        
        processing_time = time.time() - start_time
        
        # Update metrics
        self.metrics.increment("behavior_events_processed")
        self.metrics.histogram("behavior_processing_time", processing_time)
        self.metrics.gauge("anomalies_detected", len(anomalies))
        
        return anomalies


    def _check_impossible_travel(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for impossible travel based on location and timing."""
        if not event.location or not profile.baseline_locations:
            return None
        
        current_location = (event.location.get('latitude'), event.location.get('longitude'))
        if not all(current_location):
            return None
        
        # Get recent events for this user
        recent_events = self._get_recent_events(event.user_id, hours=24)
        
        for recent_event in recent_events:
            if not recent_event.location:
                continue
                
            prev_location = (recent_event.location.get('latitude'), recent_event.location.get('longitude'))
            if not all(prev_location):
                continue
            
            # Calculate distance and time
            distance = geopy.distance.distance(current_location, prev_location).kilometers
            time_diff = (event.timestamp - recent_event.timestamp).total_seconds() / 3600  # hours
            
            if time_diff > 0:
                velocity = distance / time_diff  # km/h
                
                if velocity > self.impossible_travel_threshold:
                    return AnomalyResult(
                        anomaly_id=f"impossible_travel_{event.user_id}_{int(time.time())}",
                        user_id=event.user_id,
                        anomaly_type=BehaviorAnomalyType.IMPOSSIBLE_TRAVEL,
                        risk_level=RiskLevel.HIGH,
                        confidence_score=min(1.0, velocity / self.impossible_travel_threshold),
                        description=f"Impossible travel detected: {distance:.1f}km in {time_diff:.1f}h ({velocity:.1f}km/h)",
                        detected_time=datetime.now(),
                        event_data=asdict(event),
                        baseline_comparison={
                            "previous_location": prev_location,
                            "current_location": current_location,
                            "distance_km": distance,
                            "time_hours": time_diff,
                            "velocity_kmh": velocity
                        },
                        peer_comparison={},
                        recommended_actions=[
                            "Verify user identity through additional authentication",
                            "Check for account compromise indicators",
                            "Review recent access patterns"
                        ]
                    )
        
        return None


    def _check_off_hours_access(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for access outside typical hours."""
        typical_hours = profile.typical_hours
        if not typical_hours:
            return None
        
        event_hour = event.timestamp.hour
        event_weekday = event.timestamp.weekday()
        
        # Check if within typical hours
        weekday_hours = typical_hours.get('weekday_hours', [])
        weekend_hours = typical_hours.get('weekend_hours', [])
        
        if event_weekday < 5:  # Weekday
            typical_range = weekday_hours
        else:  # Weekend
            typical_range = weekend_hours
        
        if typical_range and (event_hour < typical_range[0] or event_hour > typical_range[1]):
            # Calculate confidence based on how far outside typical hours
            if event_weekday < 5:
                mid_hour = (typical_range[0] + typical_range[1]) / 2
                distance_from_typical = min(
                    abs(event_hour - typical_range[0]),
                    abs(event_hour - typical_range[1])
                )
                confidence = min(1.0, distance_from_typical / 12.0)
            else:
                confidence = 0.8  # Weekend access is generally more suspicious
            
            return AnomalyResult(
                anomaly_id=f"off_hours_{event.user_id}_{int(time.time())}",
                user_id=event.user_id,
                anomaly_type=BehaviorAnomalyType.OFF_HOURS_ACCESS,
                risk_level=RiskLevel.MEDIUM if confidence < 0.7 else RiskLevel.HIGH,
                confidence_score=confidence,
                description=f"Off-hours access detected at {event_hour}:00 on {'weekday' if event_weekday < 5 else 'weekend'}",
                detected_time=datetime.now(),
                event_data=asdict(event),
                baseline_comparison={
                    "typical_weekday_hours": weekday_hours,
                    "typical_weekend_hours": weekend_hours,
                    "event_hour": event_hour,
                    "event_weekday": event_weekday
                },
                peer_comparison={},
                recommended_actions=[
                    "Verify business justification for off-hours access",
                    "Check for automated processes or scheduled tasks",
                    "Monitor for additional suspicious activity"
                ]
            )
        
        return None


    def _check_unusual_location(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for access from unusual locations."""
        if not event.location or not profile.baseline_locations:
            return None
        
        current_location = (event.location.get('latitude'), event.location.get('longitude'))
        if not all(current_location):
            return None
        
        # Check if location is within radius of any baseline location
        for baseline_loc in profile.baseline_locations:
            baseline_coords = (baseline_loc.get('latitude'), baseline_loc.get('longitude'))
            if not all(baseline_coords):
                continue
            
            distance = geopy.distance.distance(current_location, baseline_coords).kilometers
            if distance <= self.location_radius_km:
                return None  # Within normal radius
        
        # Calculate confidence based on distance from nearest baseline
        min_distance = float('inf')
        for baseline_loc in profile.baseline_locations:
            baseline_coords = (baseline_loc.get('latitude'), baseline_loc.get('longitude'))
            if all(baseline_coords):
                distance = geopy.distance.distance(current_location, baseline_coords).kilometers
                min_distance = min(min_distance, distance)
        
        if min_distance != float('inf'):
            confidence = min(1.0, (min_distance - self.location_radius_km) / 1000.0)  # Scale by distance
            
            return AnomalyResult(
                anomaly_id=f"unusual_location_{event.user_id}_{int(time.time())}",
                user_id=event.user_id,
                anomaly_type=BehaviorAnomalyType.UNUSUAL_LOCATION,
                risk_level=RiskLevel.MEDIUM if confidence < 0.5 else RiskLevel.HIGH,
                confidence_score=confidence,
                description=f"Unusual location detected: {min_distance:.1f}km from nearest baseline",
                detected_time=datetime.now(),
                event_data=asdict(event),
                baseline_comparison={
                    "baseline_locations": profile.baseline_locations,
                    "current_location": current_location,
                    "min_distance_km": min_distance
                },
                peer_comparison={},
                recommended_actions=[
                    "Verify user travel plans or remote work arrangements",
                    "Check for VPN usage or location spoofing",
                    "Implement step-up authentication for new locations"
                ]
            )
        
        return None


    def _check_abnormal_frequency(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for abnormal authentication frequency."""
        # Get events from the last hour
        recent_events = self._get_recent_events(event.user_id, hours=1)
        current_hour_count = len(recent_events)
        
        # Get typical hourly frequency from profile
        typical_frequency = profile.access_patterns.get('typical_hourly_frequency', {})
        hour_of_day = event.timestamp.hour
        expected_count = typical_frequency.get(str(hour_of_day), 1)
        
        # Calculate z-score if we have baseline data
        if expected_count > 0:
            # Get historical data for this hour
            historical_counts = self._get_historical_hourly_counts(event.user_id, hour_of_day)
            
            if len(historical_counts) >= 7:  # Need at least a week of data
                mean_count = statistics.mean(historical_counts)
                std_count = statistics.stdev(historical_counts) if len(historical_counts) > 1 else 1
                
                if std_count > 0:
                    z_score = (current_hour_count - mean_count) / std_count
                    
                    if abs(z_score) > 2.5:  # More than 2.5 standard deviations
                        confidence = min(1.0, abs(z_score) / 5.0)
                        
                        return AnomalyResult(
                            anomaly_id=f"abnormal_frequency_{event.user_id}_{int(time.time())}",
                            user_id=event.user_id,
                            anomaly_type=BehaviorAnomalyType.ABNORMAL_FREQUENCY,
                            risk_level=RiskLevel.MEDIUM if confidence < 0.7 else RiskLevel.HIGH,
                            confidence_score=confidence,
                            description=f"Abnormal frequency: {current_hour_count} events in hour vs avg {mean_count:.1f}",
                            detected_time=datetime.now(),
                            event_data=asdict(event),
                            baseline_comparison={
                                "current_hour_count": current_hour_count,
                                "expected_count": expected_count,
                                "mean_count": mean_count,
                                "std_count": std_count,
                                "z_score": z_score
                            },
                            peer_comparison={},
                            recommended_actions=[
                                "Check for automated processes or scripts",
                                "Verify user is not experiencing technical issues",
                                "Monitor for brute force attack patterns"
                            ]
                        )
        
        return None


    def _check_new_device(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for access from new devices."""
        if not event.device_info:
            return None
        
        # Generate device fingerprint
        device_fingerprint = self._generate_device_fingerprint(event.device_info)
        
        if device_fingerprint not in profile.device_fingerprints:
            return AnomalyResult(
                anomaly_id=f"new_device_{event.user_id}_{int(time.time())}",
                user_id=event.user_id,
                anomaly_type=BehaviorAnomalyType.NEW_DEVICE,
                risk_level=RiskLevel.MEDIUM,
                confidence_score=0.8,
                description="Access from new device detected",
                detected_time=datetime.now(),
                event_data=asdict(event),
                baseline_comparison={
                    "known_devices": len(profile.device_fingerprints),
                    "new_device_fingerprint": device_fingerprint,
                    "device_info": event.device_info
                },
                peer_comparison={},
                recommended_actions=[
                    "Verify device ownership with user",
                    "Implement device registration workflow",
                    "Monitor device for suspicious activity"
                ]
            )
        
        return None


    def _check_peer_group_deviation(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for deviation from peer group behavior."""
        peer_group = self.peer_groups.get(profile.peer_group)
        if not peer_group:
            return None
        
        # Get peer group baseline for current time/day
        peer_baseline = peer_group.behavioral_baseline
        current_hour = event.timestamp.hour
        current_weekday = event.timestamp.weekday()
        
        # Compare activity level with peer group
        peer_activity = peer_baseline.get('hourly_activity', {}).get(f"{current_weekday}_{current_hour}", 0)
        user_recent_activity = len(self._get_recent_events(event.user_id, hours=1))
        
        if peer_activity > 0:
            deviation_ratio = user_recent_activity / peer_activity
            
            # Flag if significantly higher than peer group (potential compromise) or lower (potential insider threat)
            if deviation_ratio > 3.0 or deviation_ratio < 0.1:
                confidence = min(1.0, abs(np.log(deviation_ratio)) / 2.0)
                
                return AnomalyResult(
                    anomaly_id=f"peer_deviation_{event.user_id}_{int(time.time())}",
                    user_id=event.user_id,
                    anomaly_type=BehaviorAnomalyType.PEER_GROUP_DEVIATION,
                    risk_level=RiskLevel.MEDIUM,
                    confidence_score=confidence,
                    description=f"Peer group deviation: {deviation_ratio:.2f}x normal activity",
                    detected_time=datetime.now(),
                    event_data=asdict(event),
                    baseline_comparison={},
                    peer_comparison={
                        "peer_group": profile.peer_group,
                        "peer_activity_level": peer_activity,
                        "user_activity_level": user_recent_activity,
                        "deviation_ratio": deviation_ratio
                    },
                    recommended_actions=[
                        "Compare with other peer group members",
                        "Check for role changes or special projects",
                        "Monitor for privilege escalation attempts"
                    ]
                )
        
        return None


    def _check_session_anomaly(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for session-based anomalies."""
        if not event.session_info:
            return None
        
        session_duration = event.session_info.get('duration_minutes', 0)
        typical_duration = profile.session_characteristics.get('typical_duration_minutes', 60)
        
        # Check for unusually long or short sessions
        if typical_duration > 0:
            duration_ratio = session_duration / typical_duration
            
            if duration_ratio > 5.0 or duration_ratio < 0.1:
                confidence = min(1.0, abs(np.log(duration_ratio)) / 3.0)
                
                return AnomalyResult(
                    anomaly_id=f"session_anomaly_{event.user_id}_{int(time.time())}",
                    user_id=event.user_id,
                    anomaly_type=BehaviorAnomalyType.SESSION_ANOMALY,
                    risk_level=RiskLevel.LOW if duration_ratio > 1 else RiskLevel.MEDIUM,
                    confidence_score=confidence,
                    description=f"Unusual session duration: {session_duration}min vs typical {typical_duration}min",
                    detected_time=datetime.now(),
                    event_data=asdict(event),
                    baseline_comparison={
                        "session_duration": session_duration,
                        "typical_duration": typical_duration,
                        "duration_ratio": duration_ratio
                    },
                    peer_comparison={},
                    recommended_actions=[
                        "Check for session hijacking indicators",
                        "Verify user activity during extended sessions",
                        "Review session timeout policies"
                    ]
                )
        
        return None


    def _check_temporal_pattern_break(self, event: BehaviorEvent, profile: UserProfile) -> Optional[AnomalyResult]:
        """Check for breaks in temporal access patterns using HMM."""
        # Get recent sequence of access hours for this user
        recent_events = self._get_recent_events(event.user_id, days=7)
        if len(recent_events) < 10:
            return None
        
        # Create sequence of hour-of-day values
        hour_sequence = [e.timestamp.hour for e in recent_events]
        
        # Use cached HMM model or create new one
        cache_key = f"hmm_model_{event.user_id}"
        hmm_model = self.cache.get(cache_key)
        
        if not hmm_model:
            # Train simple HMM on user's historical patterns
            try:
                # Get longer history for training
                historical_events = self._get_recent_events(event.user_id, days=30)
                if len(historical_events) < 50:
                    return None
                
                training_sequence = np.array([[e.timestamp.hour] for e in historical_events])
                
                hmm_model = hmm.GaussianHMM(n_components=3, covariance_type="full")
                hmm_model.fit(training_sequence)
                
                # Cache model for 24 hours
                self.cache.set(cache_key, hmm_model, ttl=86400)
                
            except Exception as e:
                self.logger.debug(f"HMM training failed for user {event.user_id}: {str(e)}")
                return None
        
        # Calculate likelihood of current sequence
        try:
            current_sequence = np.array([[event.timestamp.hour]])
            log_likelihood = hmm_model.score(current_sequence)
            
            # Compare with typical likelihood
            baseline_likelihood = profile.access_patterns.get('typical_hmm_likelihood', log_likelihood)
            
            if baseline_likelihood != 0:
                likelihood_ratio = log_likelihood / baseline_likelihood
                
                if likelihood_ratio < 0.1:  # Very low likelihood
                    confidence = min(1.0, abs(np.log(likelihood_ratio)) / 5.0)
                    
                    return AnomalyResult(
                        anomaly_id=f"temporal_break_{event.user_id}_{int(time.time())}",
                        user_id=event.user_id,
                        anomaly_type=BehaviorAnomalyType.TEMPORAL_PATTERN_BREAK,
                        risk_level=RiskLevel.MEDIUM,
                        confidence_score=confidence,
                        description="Temporal pattern break detected using HMM analysis",
                        detected_time=datetime.now(),
                        event_data=asdict(event),
                        baseline_comparison={
                            "log_likelihood": log_likelihood,
                            "baseline_likelihood": baseline_likelihood,
                            "likelihood_ratio": likelihood_ratio
                        },
                        peer_comparison={},
                        recommended_actions=[
                            "Analyze sequence of recent activities",
                            "Check for role or responsibility changes",
                            "Monitor for additional pattern deviations"
                        ]
                    )
                    
        except Exception as e:
            self.logger.debug(f"HMM scoring failed: {str(e)}")
        
        return None


    async def _get_or_create_user_profile(self, user_id: str) -> UserProfile:
        """Get existing user profile or create new one."""
        if user_id in self.user_profiles:
            return self.user_profiles[user_id]
        
        # Create new profile with minimal data
        profile = UserProfile(
            user_id=user_id,
            department="unknown",
            role="unknown", 
            peer_group="default",
            baseline_locations=[],
            typical_hours={},
            device_fingerprints=[],
            access_patterns={},
            session_characteristics={},
            created_time=datetime.now(),
            updated_time=datetime.now()
        )
        
        # Try to enrich from external sources (would integrate with HR/LDAP systems)
        # For now, use default values
        
        self.user_profiles[user_id] = profile
        await self._save_user_profile(profile)
        
        return profile


    def _get_recent_events(self, user_id: str, hours: int = None, days: int = None) -> List[BehaviorEvent]:
        """Get recent events for a user."""
        if hours:
            since_time = datetime.now() - timedelta(hours=hours)
        elif days:
            since_time = datetime.now() - timedelta(days=days)
        else:
            since_time = datetime.now() - timedelta(hours=24)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT * FROM behavior_events 
        WHERE user_id = ? AND timestamp >= ?
        ORDER BY timestamp DESC
        """, (user_id, since_time.isoformat()))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = BehaviorEvent(
                event_id=row[0],
                user_id=row[1],
                timestamp=datetime.fromisoformat(row[2]),
                event_type=row[3],
                location=json.loads(row[4]) if row[4] else None,
                device_info=json.loads(row[5]) if row[5] else None,
                session_info=json.loads(row[6]) if row[6] else None,
                resource_accessed=row[7],
                authentication_method=row[8],
                success=bool(row[9]),
                metadata=json.loads(row[10]) if row[10] else {}
            )
            events.append(event)
        
        return events


    def _get_historical_hourly_counts(self, user_id: str, hour_of_day: int, days: int = 30) -> List[int]:
        """Get historical hourly event counts for statistical analysis."""
        since_time = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count
        FROM behavior_events 
        WHERE user_id = ? 
        AND timestamp >= ?
        AND CAST(strftime('%H', timestamp) AS INTEGER) = ?
        GROUP BY DATE(timestamp)
        """, (user_id, since_time.isoformat(), hour_of_day))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [row[1] for row in rows]


    def _generate_device_fingerprint(self, device_info: Dict[str, Any]) -> str:
        """Generate device fingerprint from device information."""
        fingerprint_data = {
            'user_agent': device_info.get('user_agent', ''),
            'screen_resolution': device_info.get('screen_resolution', ''),
            'timezone': device_info.get('timezone', ''),
            'language': device_info.get('language', ''),
            'platform': device_info.get('platform', ''),
            'plugins': device_info.get('plugins', [])
        }
        
        fingerprint_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.sha256(fingerprint_str.encode()).hexdigest()


    async def _save_behavior_event(self, event: BehaviorEvent):
        """Save behavior event to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO behavior_events 
        (event_id, user_id, timestamp, event_type, location, device_info,
         session_info, resource_accessed, authentication_method, success, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_id,
            event.user_id,
            event.timestamp.isoformat(),
            event.event_type,
            json.dumps(event.location) if event.location else None,
            json.dumps(event.device_info) if event.device_info else None,
            json.dumps(event.session_info) if event.session_info else None,
            event.resource_accessed,
            event.authentication_method,
            event.success,
            json.dumps(event.metadata or {})
        ))
        
        conn.commit()
        conn.close()


    async def _save_anomaly_result(self, anomaly: AnomalyResult):
        """Save anomaly result to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT INTO anomaly_results 
        (anomaly_id, user_id, anomaly_type, risk_level, confidence_score,
         description, event_data, baseline_comparison, peer_comparison,
         recommended_actions, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            anomaly.anomaly_id,
            anomaly.user_id,
            anomaly.anomaly_type.value,
            anomaly.risk_level.value,
            anomaly.confidence_score,
            anomaly.description,
            json.dumps(anomaly.event_data),
            json.dumps(anomaly.baseline_comparison),
            json.dumps(anomaly.peer_comparison),
            json.dumps(anomaly.recommended_actions),
            json.dumps(anomaly.metadata or {})
        ))
        
        conn.commit()
        conn.close()


    async def _save_user_profile(self, profile: UserProfile):
        """Save user profile to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
        INSERT OR REPLACE INTO user_profiles 
        (user_id, department, role, peer_group, baseline_locations,
         typical_hours, device_fingerprints, access_patterns,
         session_characteristics, confidence_score, created_time, updated_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            profile.user_id,
            profile.department,
            profile.role,
            profile.peer_group,
            json.dumps(profile.baseline_locations),
            json.dumps(profile.typical_hours),
            json.dumps(profile.device_fingerprints),
            json.dumps(profile.access_patterns),
            json.dumps(profile.session_characteristics),
            profile.confidence_score,
            profile.created_time.isoformat(),
            profile.updated_time.isoformat()
        ))
        
        conn.commit()
        conn.close()


    async def _update_user_profile_incremental(self, profile: UserProfile, event: BehaviorEvent):
        """Incrementally update user profile with new event data."""
        # Update device fingerprints
        if event.device_info:
            fingerprint = self._generate_device_fingerprint(event.device_info)
            if fingerprint not in profile.device_fingerprints:
                profile.device_fingerprints.append(fingerprint)
                
                # Keep only last 10 devices
                if len(profile.device_fingerprints) > 10:
                    profile.device_fingerprints = profile.device_fingerprints[-10:]
        
        # Update baseline locations
        if event.location:
            location_data = {
                'latitude': event.location.get('latitude'),
                'longitude': event.location.get('longitude'),
                'last_seen': event.timestamp.isoformat(),
                'frequency': 1
            }
            
            # Check if location already exists
            location_exists = False
            for i, baseline_loc in enumerate(profile.baseline_locations):
                if (abs(baseline_loc.get('latitude', 0) - location_data['latitude']) < 0.01 and
                    abs(baseline_loc.get('longitude', 0) - location_data['longitude']) < 0.01):
                    profile.baseline_locations[i]['frequency'] += 1
                    profile.baseline_locations[i]['last_seen'] = location_data['last_seen']
                    location_exists = True
                    break
            
            if not location_exists:
                profile.baseline_locations.append(location_data)
                
                # Keep only top 5 most frequent locations
                if len(profile.baseline_locations) > 5:
                    profile.baseline_locations.sort(key=lambda x: x['frequency'], reverse=True)
                    profile.baseline_locations = profile.baseline_locations[:5]
        
        # Update typical hours
        hour = event.timestamp.hour
        weekday = event.timestamp.weekday()
        
        if 'hourly_frequency' not in profile.access_patterns:
            profile.access_patterns['hourly_frequency'] = {}
        
        hour_key = f"{weekday}_{hour}"
        profile.access_patterns['hourly_frequency'][hour_key] = (
            profile.access_patterns['hourly_frequency'].get(hour_key, 0) + 1
        )
        
        profile.updated_time = datetime.now()
        await self._save_user_profile(profile)


    async def _baseline_update_task(self):
        """Background task to update behavioral baselines."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Update baselines for all users
                for user_id in self.user_profiles:
                    await self._update_user_baseline(user_id)
                
                self.logger.debug("Baseline update task completed")
                
            except Exception as e:
                self.logger.error(f"Baseline update task failed: {str(e)}")


    async def _peer_group_update_task(self):
        """Background task to update peer groups."""
        while True:
            try:
                await asyncio.sleep(86400)  # Run daily
                
                # Rebuild peer groups based on current user attributes
                await self._rebuild_peer_groups()
                
                self.logger.debug("Peer group update task completed")
                
            except Exception as e:
                self.logger.error(f"Peer group update task failed: {str(e)}")


    async def _update_user_baseline(self, user_id: str):
        """Update behavioral baseline for a specific user."""
        # Implementation would analyze recent patterns and update baselines
        # This is a simplified version
        pass


    async def _rebuild_peer_groups(self):
        """Rebuild peer groups based on current user attributes."""
        # Implementation would cluster users by department, role, and behavior patterns
        # This is a simplified version
        pass


    def get_user_risk_score(self, user_id: str) -> float:
        """Calculate current risk score for a user based on recent anomalies."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent anomalies (last 24 hours)
        since_time = datetime.now() - timedelta(hours=24)
        cursor.execute("""
        SELECT risk_level, confidence_score 
        FROM anomaly_results 
        WHERE user_id = ? AND detected_time >= ?
        """, (user_id, since_time.isoformat()))
        
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            return 0.0
        
        # Calculate weighted risk score
        risk_weights = {
            'low': 0.25,
            'medium': 0.5,
            'high': 0.75,
            'critical': 1.0
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for risk_level, confidence in rows:
            weight = risk_weights.get(risk_level, 0.5)
            total_score += weight * confidence
            total_weight += confidence
        
        return min(1.0, total_score / total_weight if total_weight > 0 else 0.0)


    def get_statistics(self) -> Dict[str, Any]:
        """Get behavior analytics statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total events processed
        cursor.execute("SELECT COUNT(*) FROM behavior_events")
        total_events = cursor.fetchone()[0]
        
        # Anomalies by type
        cursor.execute("""
        SELECT anomaly_type, COUNT(*) 
        FROM anomaly_results 
        GROUP BY anomaly_type
        """)
        anomalies_by_type = dict(cursor.fetchall())
        
        # Recent anomalies (last 24 hours)
        since_time = datetime.now() - timedelta(hours=24)
        cursor.execute("""
        SELECT COUNT(*) FROM anomaly_results 
        WHERE detected_time >= ?
        """, (since_time.isoformat(),))
        recent_anomalies = cursor.fetchone()[0]
        
        # High-risk users
        cursor.execute("""
        SELECT COUNT(DISTINCT user_id) FROM anomaly_results 
        WHERE risk_level IN ('high', 'critical') 
        AND detected_time >= ?
        """, (since_time.isoformat(),))
        high_risk_users = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_events_processed": total_events,
            "anomalies_by_type": anomalies_by_type,
            "recent_anomalies_24h": recent_anomalies,
            "high_risk_users": high_risk_users,
            "active_user_profiles": len(self.user_profiles),
            "peer_groups": len(self.peer_groups)
        }


    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'thread_pool'):
            self.thread_pool.shutdown(wait=True)
        if hasattr(self, 'redis_client'):
            self.redis_client.close()