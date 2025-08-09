"""
Feature Engineering Pipeline for ML User Behavior Analysis.

This module provides a high-performance feature engineering pipeline that transforms
raw user behavior events into model-ready features for anomaly detection and 
behavioral analysis.

Performance Engineering Focus:
- Sub-50ms feature extraction per event
- >10,000 events/second processing throughput
- Memory-efficient real-time computation
- Optimized temporal aggregations with caching
- Vectorized feature transformations
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, AsyncGenerator
from enum import Enum
import json
import hashlib
from pathlib import Path
from collections import defaultdict, deque
import time

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import aioredis
from pydantic import BaseModel, Field
import joblib

from .data_sources_integration import BehaviorEvent
from .objectives_and_metrics import TechnicalMetric

logger = logging.getLogger(__name__)


class FeatureType(Enum):
    """Types of features for behavioral analysis."""
    TEMPORAL = "temporal"
    CATEGORICAL = "categorical"
    NUMERICAL = "numerical"
    BEHAVIORAL = "behavioral"
    CONTEXTUAL = "contextual"
    AGGREGATED = "aggregated"


class AggregationWindow(Enum):
    """Time windows for feature aggregation."""
    REAL_TIME = "real_time"  # Current event
    LAST_HOUR = "1h"
    LAST_4_HOURS = "4h"
    LAST_24_HOURS = "24h"
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"


@dataclass
class FeatureSpec:
    """Specification for a feature."""
    name: str
    feature_type: FeatureType
    description: str
    data_type: str  # 'float', 'int', 'bool', 'string'
    aggregation_window: Optional[AggregationWindow] = None
    requires_history: bool = False
    cache_ttl_seconds: int = 300  # 5 minutes default
    computation_weight: str = "light"  # light, medium, heavy


@dataclass
class ComputedFeature:
    """A computed feature with metadata."""
    name: str
    value: Union[float, int, str, bool]
    feature_type: FeatureType
    computation_time_ms: float
    timestamp: datetime
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureVector:
    """Complete feature vector for a user event."""
    user_id: str
    event_id: str
    timestamp: datetime
    features: Dict[str, ComputedFeature]
    total_computation_time_ms: float
    feature_quality_score: float = 1.0


class FeatureCache:
    """High-performance feature caching system."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis_pool = None
        self.local_cache: Dict[str, Any] = {}
        self.cache_hits = 0
        self.cache_misses = 0
    
    async def initialize(self) -> None:
        """Initialize Redis connection pool."""
        self.redis_pool = aioredis.ConnectionPool.from_url(
            self.redis_url, 
            max_connections=20,
            encoding="utf-8",
            decode_responses=True
        )
    
    async def get(self, key: str) -> Optional[Any]:
        """Get cached value."""
        try:
            # Try local cache first
            if key in self.local_cache:
                self.cache_hits += 1
                return self.local_cache[key]
            
            # Try Redis cache
            if self.redis_pool:
                redis = aioredis.Redis(connection_pool=self.redis_pool)
                value = await redis.get(key)
                if value:
                    parsed_value = json.loads(value)
                    self.local_cache[key] = parsed_value
                    self.cache_hits += 1
                    return parsed_value
            
            self.cache_misses += 1
            return None
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {str(e)}")
            self.cache_misses += 1
            return None
    
    async def set(self, key: str, value: Any, ttl_seconds: int = 300) -> None:
        """Set cached value."""
        try:
            # Set in local cache
            self.local_cache[key] = value
            
            # Set in Redis cache
            if self.redis_pool:
                redis = aioredis.Redis(connection_pool=self.redis_pool)
                await redis.setex(key, ttl_seconds, json.dumps(value, default=str))
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {str(e)}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache performance statistics."""
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "hit_rate_percentage": hit_rate,
            "local_cache_size": len(self.local_cache)
        }


class FeatureExtractor(ABC):
    """Abstract base class for feature extractors."""
    
    def __init__(self, cache: FeatureCache):
        self.cache = cache
        self.computation_times = deque(maxlen=1000)  # Track recent computation times
    
    @abstractmethod
    async def extract_features(self, event: BehaviorEvent, context: Dict[str, Any]) -> Dict[str, ComputedFeature]:
        """Extract features from a behavior event."""
        pass
    
    def get_average_computation_time(self) -> float:
        """Get average computation time in milliseconds."""
        if not self.computation_times:
            return 0.0
        return sum(self.computation_times) / len(self.computation_times)


class TemporalFeatureExtractor(FeatureExtractor):
    """Extract temporal features from user behavior events."""
    
    def __init__(self, cache: FeatureCache):
        super().__init__(cache)
        self.feature_specs = [
            FeatureSpec("hour_of_day", FeatureType.TEMPORAL, "Hour of day (0-23)", "int"),
            FeatureSpec("day_of_week", FeatureType.TEMPORAL, "Day of week (0-6)", "int"),
            FeatureSpec("is_weekend", FeatureType.TEMPORAL, "Whether event occurred on weekend", "bool"),
            FeatureSpec("is_business_hours", FeatureType.TEMPORAL, "Whether event occurred during business hours", "bool"),
            FeatureSpec("time_since_last_activity", FeatureType.TEMPORAL, "Minutes since last user activity", "float", AggregationWindow.REAL_TIME, True),
            FeatureSpec("session_duration", FeatureType.TEMPORAL, "Current session duration in minutes", "float", AggregationWindow.REAL_TIME, True),
            FeatureSpec("login_frequency_1h", FeatureType.TEMPORAL, "Login attempts in last hour", "int", AggregationWindow.LAST_HOUR, True),
            FeatureSpec("login_frequency_24h", FeatureType.TEMPORAL, "Login attempts in last 24 hours", "int", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("activity_burst_score", FeatureType.TEMPORAL, "Activity burst detection score", "float", AggregationWindow.LAST_HOUR, True),
            FeatureSpec("time_pattern_anomaly", FeatureType.TEMPORAL, "Deviation from normal time patterns", "float", AggregationWindow.LAST_7_DAYS, True)
        ]
    
    async def extract_features(self, event: BehaviorEvent, context: Dict[str, Any]) -> Dict[str, ComputedFeature]:
        """Extract temporal features."""
        start_time = time.time()
        features = {}
        
        timestamp = event.timestamp
        user_id = event.user_id
        
        # Basic temporal features
        features["hour_of_day"] = ComputedFeature(
            name="hour_of_day",
            value=timestamp.hour,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=0.1,
            timestamp=timestamp
        )
        
        features["day_of_week"] = ComputedFeature(
            name="day_of_week",
            value=timestamp.weekday(),
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=0.1,
            timestamp=timestamp
        )
        
        features["is_weekend"] = ComputedFeature(
            name="is_weekend",
            value=timestamp.weekday() >= 5,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=0.1,
            timestamp=timestamp
        )
        
        features["is_business_hours"] = ComputedFeature(
            name="is_business_hours",
            value=9 <= timestamp.hour <= 17 and timestamp.weekday() < 5,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=0.1,
            timestamp=timestamp
        )
        
        # Historical temporal features (require cache lookups)
        cache_key_prefix = f"temporal_features:{user_id}"
        
        # Time since last activity
        last_activity_key = f"{cache_key_prefix}:last_activity"
        last_activity = await self.cache.get(last_activity_key)
        
        if last_activity:
            last_timestamp = datetime.fromisoformat(last_activity)
            time_diff = (timestamp - last_timestamp).total_seconds() / 60  # minutes
            features["time_since_last_activity"] = ComputedFeature(
                name="time_since_last_activity",
                value=min(time_diff, 10080),  # Cap at 1 week
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=1.0,
                timestamp=timestamp
            )
        else:
            features["time_since_last_activity"] = ComputedFeature(
                name="time_since_last_activity",
                value=0.0,
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=1.0,
                timestamp=timestamp
            )
        
        # Update last activity timestamp
        await self.cache.set(last_activity_key, timestamp.isoformat(), ttl_seconds=604800)  # 1 week
        
        # Session duration
        session_id = event.session_id or f"{user_id}_{timestamp.date()}"
        session_start_key = f"{cache_key_prefix}:session_start:{session_id}"
        session_start = await self.cache.get(session_start_key)
        
        if session_start:
            start_timestamp = datetime.fromisoformat(session_start)
            session_duration = (timestamp - start_timestamp).total_seconds() / 60  # minutes
        else:
            session_duration = 0.0
            await self.cache.set(session_start_key, timestamp.isoformat(), ttl_seconds=86400)  # 24 hours
        
        features["session_duration"] = ComputedFeature(
            name="session_duration",
            value=session_duration,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=2.0,
            timestamp=timestamp
        )
        
        # Login frequency features
        await self._extract_frequency_features(features, user_id, timestamp, event)
        
        # Activity burst detection
        burst_score = await self._compute_activity_burst_score(user_id, timestamp)
        features["activity_burst_score"] = ComputedFeature(
            name="activity_burst_score",
            value=burst_score,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=5.0,
            timestamp=timestamp
        )
        
        # Time pattern anomaly
        anomaly_score = await self._compute_time_pattern_anomaly(user_id, timestamp)
        features["time_pattern_anomaly"] = ComputedFeature(
            name="time_pattern_anomaly",
            value=anomaly_score,
            feature_type=FeatureType.TEMPORAL,
            computation_time_ms=8.0,
            timestamp=timestamp
        )
        
        total_time = (time.time() - start_time) * 1000
        self.computation_times.append(total_time)
        
        return features
    
    async def _extract_frequency_features(self, features: Dict[str, ComputedFeature], 
                                        user_id: str, timestamp: datetime, event: BehaviorEvent) -> None:
        """Extract login frequency features."""
        if event.event_type in ['login', 'authentication', 'signin']:
            # Update login frequency counters
            hourly_key = f"login_freq:{user_id}:1h"
            daily_key = f"login_freq:{user_id}:24h"
            
            # Get current counts
            hourly_count = await self.cache.get(hourly_key) or 0
            daily_count = await self.cache.get(daily_key) or 0
            
            # Increment counts
            hourly_count += 1
            daily_count += 1
            
            # Cache with appropriate TTL
            await self.cache.set(hourly_key, hourly_count, ttl_seconds=3600)  # 1 hour
            await self.cache.set(daily_key, daily_count, ttl_seconds=86400)  # 24 hours
            
            features["login_frequency_1h"] = ComputedFeature(
                name="login_frequency_1h",
                value=hourly_count,
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=3.0,
                timestamp=timestamp
            )
            
            features["login_frequency_24h"] = ComputedFeature(
                name="login_frequency_24h",
                value=daily_count,
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=3.0,
                timestamp=timestamp
            )
        else:
            # Get existing counts without incrementing
            hourly_count = await self.cache.get(f"login_freq:{user_id}:1h") or 0
            daily_count = await self.cache.get(f"login_freq:{user_id}:24h") or 0
            
            features["login_frequency_1h"] = ComputedFeature(
                name="login_frequency_1h",
                value=hourly_count,
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=2.0,
                timestamp=timestamp
            )
            
            features["login_frequency_24h"] = ComputedFeature(
                name="login_frequency_24h",
                value=daily_count,
                feature_type=FeatureType.TEMPORAL,
                computation_time_ms=2.0,
                timestamp=timestamp
            )
    
    async def _compute_activity_burst_score(self, user_id: str, timestamp: datetime) -> float:
        """Compute activity burst detection score."""
        activity_key = f"activity_timeline:{user_id}"
        activity_timeline = await self.cache.get(activity_key) or []
        
        # Add current timestamp
        activity_timeline.append(timestamp.isoformat())
        
        # Keep only last hour of activity
        one_hour_ago = timestamp - timedelta(hours=1)
        activity_timeline = [
            ts for ts in activity_timeline 
            if datetime.fromisoformat(ts) > one_hour_ago
        ]
        
        # Cache updated timeline
        await self.cache.set(activity_key, activity_timeline, ttl_seconds=3600)
        
        # Calculate burst score based on activity density
        if len(activity_timeline) <= 2:
            return 0.0
        
        # Convert to minutes and calculate intervals
        timestamps = [datetime.fromisoformat(ts) for ts in activity_timeline]
        intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() / 60 
                    for i in range(1, len(timestamps))]
        
        if not intervals:
            return 0.0
        
        # Calculate coefficient of variation as burst indicator
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if mean_interval == 0:
            return 0.0
        
        burst_score = min(std_interval / mean_interval, 2.0)  # Cap at 2.0
        return burst_score
    
    async def _compute_time_pattern_anomaly(self, user_id: str, timestamp: datetime) -> float:
        """Compute time pattern anomaly score."""
        pattern_key = f"time_patterns:{user_id}"
        historical_hours = await self.cache.get(pattern_key) or []
        
        # Add current hour
        current_hour = timestamp.hour
        historical_hours.append(current_hour)
        
        # Keep only last 7 days (max 168 hours)
        if len(historical_hours) > 168:
            historical_hours = historical_hours[-168:]
        
        # Cache updated patterns
        await self.cache.set(pattern_key, historical_hours, ttl_seconds=604800)  # 1 week
        
        if len(historical_hours) < 10:  # Need minimum history
            return 0.0
        
        # Calculate hour frequency distribution
        hour_counts = np.bincount(historical_hours, minlength=24)
        hour_probs = hour_counts / np.sum(hour_counts)
        
        # Current hour probability (anomaly = low probability)
        current_prob = hour_probs[current_hour]
        
        # Convert to anomaly score (0-1, where 1 is most anomalous)
        anomaly_score = 1.0 - min(current_prob * 24, 1.0)  # Scale by 24 for normalization
        
        return anomaly_score


class CategoricalFeatureExtractor(FeatureExtractor):
    """Extract categorical and contextual features from user behavior events."""
    
    def __init__(self, cache: FeatureCache):
        super().__init__(cache)
        self.feature_specs = [
            FeatureSpec("device_change_score", FeatureType.CATEGORICAL, "Device change anomaly score", "float", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("location_change_score", FeatureType.CATEGORICAL, "Location change anomaly score", "float", AggregationWindow.REAL_TIME, True),
            FeatureSpec("user_agent_change_score", FeatureType.CATEGORICAL, "User agent change frequency", "float", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("ip_reputation_score", FeatureType.CATEGORICAL, "IP address reputation score", "float"),
            FeatureSpec("is_new_device", FeatureType.CATEGORICAL, "Whether using a new device", "bool", AggregationWindow.LAST_30_DAYS, True),
            FeatureSpec("is_new_location", FeatureType.CATEGORICAL, "Whether from a new location", "bool", AggregationWindow.LAST_30_DAYS, True),
            FeatureSpec("device_diversity_score", FeatureType.CATEGORICAL, "Diversity of devices used", "float", AggregationWindow.LAST_7_DAYS, True),
            FeatureSpec("location_entropy", FeatureType.CATEGORICAL, "Entropy of location patterns", "float", AggregationWindow.LAST_7_DAYS, True)
        ]
    
    async def extract_features(self, event: BehaviorEvent, context: Dict[str, Any]) -> Dict[str, ComputedFeature]:
        """Extract categorical features."""
        start_time = time.time()
        features = {}
        
        user_id = event.user_id
        timestamp = event.timestamp
        
        # Device-based features
        await self._extract_device_features(features, event, user_id, timestamp)
        
        # Location-based features
        await self._extract_location_features(features, event, user_id, timestamp)
        
        # IP reputation features
        await self._extract_ip_features(features, event, timestamp)
        
        total_time = (time.time() - start_time) * 1000
        self.computation_times.append(total_time)
        
        return features
    
    async def _extract_device_features(self, features: Dict[str, ComputedFeature], 
                                     event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract device-related features."""
        device_info = event.device_info or {}
        current_device = self._get_device_fingerprint(device_info, event.data.get('user_agent', ''))
        
        # Track device history
        device_history_key = f"device_history:{user_id}"
        device_history = await self.cache.get(device_history_key) or []
        
        # Check if new device
        is_new_device = current_device not in device_history
        
        if is_new_device:
            device_history.append(current_device)
            # Keep only last 10 devices
            if len(device_history) > 10:
                device_history = device_history[-10:]
        
        # Cache updated history
        await self.cache.set(device_history_key, device_history, ttl_seconds=2592000)  # 30 days
        
        features["is_new_device"] = ComputedFeature(
            name="is_new_device",
            value=is_new_device,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=3.0,
            timestamp=timestamp
        )
        
        # Device diversity score
        device_diversity = len(set(device_history)) / 10.0  # Normalize by max devices
        features["device_diversity_score"] = ComputedFeature(
            name="device_diversity_score",
            value=device_diversity,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=2.0,
            timestamp=timestamp
        )
        
        # Device change score (based on recent changes)
        device_change_score = await self._compute_device_change_score(user_id, current_device, timestamp)
        features["device_change_score"] = ComputedFeature(
            name="device_change_score",
            value=device_change_score,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=5.0,
            timestamp=timestamp
        )
        
        # User agent change score
        user_agent = event.data.get('user_agent', '')
        ua_change_score = await self._compute_user_agent_change_score(user_id, user_agent, timestamp)
        features["user_agent_change_score"] = ComputedFeature(
            name="user_agent_change_score",
            value=ua_change_score,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=4.0,
            timestamp=timestamp
        )
    
    async def _extract_location_features(self, features: Dict[str, ComputedFeature], 
                                       event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract location-related features."""
        location_info = event.location_info or {}
        source_ip = event.data.get('source_ip', '')
        
        current_location = self._get_location_key(location_info, source_ip)
        
        # Track location history
        location_history_key = f"location_history:{user_id}"
        location_history = await self.cache.get(location_history_key) or []
        
        # Check if new location
        is_new_location = current_location not in location_history
        
        if is_new_location:
            location_history.append(current_location)
            # Keep only last 20 locations
            if len(location_history) > 20:
                location_history = location_history[-20:]
        
        # Cache updated history
        await self.cache.set(location_history_key, location_history, ttl_seconds=2592000)  # 30 days
        
        features["is_new_location"] = ComputedFeature(
            name="is_new_location",
            value=is_new_location,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=3.0,
            timestamp=timestamp
        )
        
        # Location entropy (diversity measure)
        if len(location_history) > 1:
            location_counts = {}
            for loc in location_history:
                location_counts[loc] = location_counts.get(loc, 0) + 1
            
            total = len(location_history)
            entropy = -sum((count/total) * np.log2(count/total) for count in location_counts.values())
            # Normalize by theoretical maximum entropy
            max_entropy = np.log2(min(len(location_counts), 20))  # Max 20 locations
            location_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
        else:
            location_entropy = 0.0
        
        features["location_entropy"] = ComputedFeature(
            name="location_entropy",
            value=location_entropy,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=6.0,
            timestamp=timestamp
        )
        
        # Location change score
        location_change_score = await self._compute_location_change_score(user_id, current_location, timestamp)
        features["location_change_score"] = ComputedFeature(
            name="location_change_score",
            value=location_change_score,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=4.0,
            timestamp=timestamp
        )
    
    async def _extract_ip_features(self, features: Dict[str, ComputedFeature], 
                                 event: BehaviorEvent, timestamp: datetime) -> None:
        """Extract IP-based features."""
        source_ip = event.data.get('source_ip', '')
        
        # Simplified IP reputation score (in real implementation, this would query threat intelligence)
        ip_reputation_score = await self._compute_ip_reputation_score(source_ip)
        
        features["ip_reputation_score"] = ComputedFeature(
            name="ip_reputation_score",
            value=ip_reputation_score,
            feature_type=FeatureType.CATEGORICAL,
            computation_time_ms=10.0,  # Would be higher with real threat intel lookup
            timestamp=timestamp
        )
    
    def _get_device_fingerprint(self, device_info: Dict[str, Any], user_agent: str) -> str:
        """Generate device fingerprint."""
        device_components = [
            device_info.get('device_id', ''),
            device_info.get('device_type', ''),
            device_info.get('os_type', ''),
            device_info.get('os_version', ''),
            user_agent[:100]  # First 100 chars of user agent
        ]
        
        fingerprint_data = '|'.join(str(comp) for comp in device_components)
        return hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]
    
    def _get_location_key(self, location_info: Dict[str, Any], source_ip: str) -> str:
        """Generate location key."""
        if location_info:
            location_key = f"{location_info.get('country', 'Unknown')}:{location_info.get('city', 'Unknown')}"
        else:
            # Use IP subnet as rough location indicator
            if source_ip:
                ip_parts = source_ip.split('.')
                if len(ip_parts) >= 3:
                    location_key = f"IP:{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.x"
                else:
                    location_key = f"IP:{source_ip}"
            else:
                location_key = "Unknown:Unknown"
        
        return location_key
    
    async def _compute_device_change_score(self, user_id: str, current_device: str, timestamp: datetime) -> float:
        """Compute device change anomaly score."""
        recent_devices_key = f"recent_devices:{user_id}"
        recent_devices = await self.cache.get(recent_devices_key) or []
        
        # Add current device with timestamp
        device_entry = {"device": current_device, "timestamp": timestamp.isoformat()}
        recent_devices.append(device_entry)
        
        # Keep only last 24 hours
        cutoff_time = timestamp - timedelta(hours=24)
        recent_devices = [
            entry for entry in recent_devices 
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
        ]
        
        # Cache updated list
        await self.cache.set(recent_devices_key, recent_devices, ttl_seconds=86400)
        
        # Calculate change score based on unique devices in 24h
        unique_devices = len(set(entry["device"] for entry in recent_devices))
        
        # Normalize: 1 device = score 0, 5+ devices = score 1
        change_score = min((unique_devices - 1) / 4.0, 1.0)
        
        return change_score
    
    async def _compute_user_agent_change_score(self, user_id: str, user_agent: str, timestamp: datetime) -> float:
        """Compute user agent change score."""
        ua_history_key = f"ua_history:{user_id}"
        ua_history = await self.cache.get(ua_history_key) or []
        
        # Simplified UA fingerprint (browser + version)
        ua_fingerprint = self._extract_ua_fingerprint(user_agent)
        
        ua_history.append({"ua": ua_fingerprint, "timestamp": timestamp.isoformat()})
        
        # Keep only last 24 hours
        cutoff_time = timestamp - timedelta(hours=24)
        ua_history = [
            entry for entry in ua_history 
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
        ]
        
        await self.cache.set(ua_history_key, ua_history, ttl_seconds=86400)
        
        # Calculate change score
        unique_uas = len(set(entry["ua"] for entry in ua_history))
        change_score = min((unique_uas - 1) / 3.0, 1.0)  # Cap at 4 different UAs
        
        return change_score
    
    async def _compute_location_change_score(self, user_id: str, current_location: str, timestamp: datetime) -> float:
        """Compute location change score."""
        last_location_key = f"last_location:{user_id}"
        last_location_data = await self.cache.get(last_location_key)
        
        if last_location_data:
            last_location = last_location_data.get("location")
            last_timestamp = datetime.fromisoformat(last_location_data.get("timestamp"))
            
            # If location changed and it's within reasonable time window
            if last_location != current_location:
                time_diff_hours = (timestamp - last_timestamp).total_seconds() / 3600
                
                # Score based on how quickly location changed
                if time_diff_hours < 1:  # Very fast change
                    change_score = 1.0
                elif time_diff_hours < 6:  # Moderate change
                    change_score = 0.6
                else:  # Normal change
                    change_score = 0.2
            else:
                change_score = 0.0
        else:
            change_score = 0.0  # First location data
        
        # Update last location
        await self.cache.set(last_location_key, {
            "location": current_location,
            "timestamp": timestamp.isoformat()
        }, ttl_seconds=86400)
        
        return change_score
    
    async def _compute_ip_reputation_score(self, source_ip: str) -> float:
        """Compute IP reputation score (simplified version)."""
        if not source_ip:
            return 0.5  # Unknown/neutral score
        
        # In production, this would query threat intelligence feeds
        # For now, use simple heuristics
        
        # Check for private IP ranges (lower risk)
        if (source_ip.startswith('10.') or 
            source_ip.startswith('192.168.') or 
            source_ip.startswith('172.')):
            return 0.1  # Low risk for private IPs
        
        # Simple hash-based risk assignment for demo
        ip_hash = hashlib.md5(source_ip.encode()).hexdigest()
        risk_score = (int(ip_hash[:8], 16) % 100) / 100.0
        
        return risk_score
    
    def _extract_ua_fingerprint(self, user_agent: str) -> str:
        """Extract simplified user agent fingerprint."""
        if not user_agent:
            return "Unknown"
        
        # Simple extraction of browser and major version
        user_agent_lower = user_agent.lower()
        
        if 'chrome' in user_agent_lower:
            return "Chrome"
        elif 'firefox' in user_agent_lower:
            return "Firefox"
        elif 'safari' in user_agent_lower:
            return "Safari"
        elif 'edge' in user_agent_lower:
            return "Edge"
        else:
            return "Other"


class BehavioralFeatureExtractor(FeatureExtractor):
    """Extract behavioral aggregation features from user activity patterns."""
    
    def __init__(self, cache: FeatureCache):
        super().__init__(cache)
        self.feature_specs = [
            FeatureSpec("resource_access_rate", FeatureType.BEHAVIORAL, "Rate of resource access per hour", "float", AggregationWindow.LAST_HOUR, True),
            FeatureSpec("unique_resources_count", FeatureType.BEHAVIORAL, "Number of unique resources accessed", "int", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("api_call_diversity", FeatureType.BEHAVIORAL, "Diversity of API calls made", "float", AggregationWindow.LAST_4_HOURS, True),
            FeatureSpec("data_transfer_volume", FeatureType.BEHAVIORAL, "Volume of data transferred (MB)", "float", AggregationWindow.LAST_HOUR, True),
            FeatureSpec("failure_rate", FeatureType.BEHAVIORAL, "Rate of failed operations", "float", AggregationWindow.LAST_HOUR, True),
            FeatureSpec("admin_action_count", FeatureType.BEHAVIORAL, "Number of admin actions performed", "int", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("privilege_escalation_attempts", FeatureType.BEHAVIORAL, "Privilege escalation attempt count", "int", AggregationWindow.LAST_24_HOURS, True),
            FeatureSpec("behavioral_consistency_score", FeatureType.BEHAVIORAL, "Consistency with historical behavior", "float", AggregationWindow.LAST_7_DAYS, True)
        ]
    
    async def extract_features(self, event: BehaviorEvent, context: Dict[str, Any]) -> Dict[str, ComputedFeature]:
        """Extract behavioral features."""
        start_time = time.time()
        features = {}
        
        user_id = event.user_id
        timestamp = event.timestamp
        
        # Resource access patterns
        await self._extract_resource_features(features, event, user_id, timestamp)
        
        # API and data transfer features
        await self._extract_api_features(features, event, user_id, timestamp)
        
        # Administrative and security features
        await self._extract_security_features(features, event, user_id, timestamp)
        
        # Behavioral consistency
        await self._extract_consistency_features(features, event, user_id, timestamp)
        
        total_time = (time.time() - start_time) * 1000
        self.computation_times.append(total_time)
        
        return features
    
    async def _extract_resource_features(self, features: Dict[str, ComputedFeature], 
                                       event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract resource access features."""
        # Track resource access
        resource_key = f"resources:{user_id}"
        recent_resources = await self.cache.get(resource_key) or []
        
        # Add current resource if available
        resource_path = event.data.get('resource', event.data.get('url', ''))
        if resource_path:
            resource_entry = {
                "resource": resource_path,
                "timestamp": timestamp.isoformat()
            }
            recent_resources.append(resource_entry)
        
        # Filter to last 24 hours
        cutoff_time = timestamp - timedelta(hours=24)
        recent_resources = [
            entry for entry in recent_resources 
            if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
        ]
        
        # Cache updated resources
        await self.cache.set(resource_key, recent_resources, ttl_seconds=86400)
        
        # Calculate features
        total_accesses = len(recent_resources)
        unique_resources = len(set(entry["resource"] for entry in recent_resources))
        
        # Resource access rate (per hour)
        hourly_cutoff = timestamp - timedelta(hours=1)
        hourly_accesses = sum(1 for entry in recent_resources 
                            if datetime.fromisoformat(entry["timestamp"]) > hourly_cutoff)
        
        features["resource_access_rate"] = ComputedFeature(
            name="resource_access_rate",
            value=float(hourly_accesses),
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=5.0,
            timestamp=timestamp
        )
        
        features["unique_resources_count"] = ComputedFeature(
            name="unique_resources_count",
            value=unique_resources,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=3.0,
            timestamp=timestamp
        )
    
    async def _extract_api_features(self, features: Dict[str, ComputedFeature], 
                                  event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract API and data transfer features."""
        # API diversity tracking
        if event.event_type in ['api_call', 'graphql', 'rest_api']:
            api_key = f"api_calls:{user_id}"
            recent_apis = await self.cache.get(api_key) or []
            
            endpoint = event.data.get('endpoint', event.data.get('api_endpoint', ''))
            method = event.data.get('method', event.data.get('http_method', ''))
            
            if endpoint:
                api_call = f"{method}:{endpoint}"
                api_entry = {
                    "api": api_call,
                    "timestamp": timestamp.isoformat()
                }
                recent_apis.append(api_entry)
                
                # Filter to last 4 hours
                cutoff_time = timestamp - timedelta(hours=4)
                recent_apis = [
                    entry for entry in recent_apis 
                    if datetime.fromisoformat(entry["timestamp"]) > cutoff_time
                ]
                
                await self.cache.set(api_key, recent_apis, ttl_seconds=14400)  # 4 hours
                
                # Calculate API diversity
                unique_apis = len(set(entry["api"] for entry in recent_apis))
                total_apis = len(recent_apis)
                
                # Diversity score (Shannon entropy normalized)
                if total_apis > 1:
                    api_counts = {}
                    for entry in recent_apis:
                        api_counts[entry["api"]] = api_counts.get(entry["api"], 0) + 1
                    
                    entropy = -sum((count/total_apis) * np.log2(count/total_apis) 
                                 for count in api_counts.values())
                    max_entropy = np.log2(unique_apis)
                    diversity_score = entropy / max_entropy if max_entropy > 0 else 0.0
                else:
                    diversity_score = 0.0
                
                features["api_call_diversity"] = ComputedFeature(
                    name="api_call_diversity",
                    value=diversity_score,
                    feature_type=FeatureType.BEHAVIORAL,
                    computation_time_ms=8.0,
                    timestamp=timestamp
                )
        else:
            # Get existing diversity without updating
            api_key = f"api_calls:{user_id}"
            recent_apis = await self.cache.get(api_key) or []
            
            if recent_apis:
                unique_apis = len(set(entry["api"] for entry in recent_apis))
                total_apis = len(recent_apis)
                
                if total_apis > 1:
                    api_counts = {}
                    for entry in recent_apis:
                        api_counts[entry["api"]] = api_counts.get(entry["api"], 0) + 1
                    
                    entropy = -sum((count/total_apis) * np.log2(count/total_apis) 
                                 for count in api_counts.values())
                    max_entropy = np.log2(unique_apis)
                    diversity_score = entropy / max_entropy if max_entropy > 0 else 0.0
                else:
                    diversity_score = 0.0
            else:
                diversity_score = 0.0
            
            features["api_call_diversity"] = ComputedFeature(
                name="api_call_diversity",
                value=diversity_score,
                feature_type=FeatureType.BEHAVIORAL,
                computation_time_ms=4.0,
                timestamp=timestamp
            )
        
        # Data transfer volume
        bytes_sent = event.data.get('bytes_sent', event.data.get('request_size', 0))
        bytes_received = event.data.get('bytes_received', event.data.get('response_size', 0))
        
        if isinstance(bytes_sent, str):
            bytes_sent = 0
        if isinstance(bytes_received, str):
            bytes_received = 0
            
        total_bytes = int(bytes_sent) + int(bytes_received)
        data_mb = total_bytes / (1024 * 1024)  # Convert to MB
        
        # Track hourly data transfer
        data_key = f"data_transfer:{user_id}"
        hourly_data = await self.cache.get(data_key) or []
        
        if data_mb > 0:
            data_entry = {
                "mb": data_mb,
                "timestamp": timestamp.isoformat()
            }
            hourly_data.append(data_entry)
        
        # Filter to last hour
        hourly_cutoff = timestamp - timedelta(hours=1)
        hourly_data = [
            entry for entry in hourly_data 
            if datetime.fromisoformat(entry["timestamp"]) > hourly_cutoff
        ]
        
        await self.cache.set(data_key, hourly_data, ttl_seconds=3600)
        
        total_data_mb = sum(entry["mb"] for entry in hourly_data)
        
        features["data_transfer_volume"] = ComputedFeature(
            name="data_transfer_volume",
            value=total_data_mb,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=4.0,
            timestamp=timestamp
        )
        
        # Failure rate
        await self._extract_failure_rate(features, event, user_id, timestamp)
    
    async def _extract_security_features(self, features: Dict[str, ComputedFeature], 
                                       event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract security-related behavioral features."""
        # Admin action tracking
        is_admin_action = self._is_admin_action(event)
        admin_key = f"admin_actions:{user_id}"
        
        if is_admin_action:
            admin_actions = await self.cache.get(admin_key) or []
            admin_actions.append(timestamp.isoformat())
            
            # Filter to last 24 hours
            cutoff_time = timestamp - timedelta(hours=24)
            admin_actions = [
                ts for ts in admin_actions 
                if datetime.fromisoformat(ts) > cutoff_time
            ]
            
            await self.cache.set(admin_key, admin_actions, ttl_seconds=86400)
            admin_count = len(admin_actions)
        else:
            admin_actions = await self.cache.get(admin_key) or []
            cutoff_time = timestamp - timedelta(hours=24)
            admin_count = sum(1 for ts in admin_actions 
                            if datetime.fromisoformat(ts) > cutoff_time)
        
        features["admin_action_count"] = ComputedFeature(
            name="admin_action_count",
            value=admin_count,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=3.0,
            timestamp=timestamp
        )
        
        # Privilege escalation attempts
        is_priv_escalation = self._is_privilege_escalation(event)
        priv_key = f"priv_escalation:{user_id}"
        
        if is_priv_escalation:
            priv_attempts = await self.cache.get(priv_key) or []
            priv_attempts.append(timestamp.isoformat())
            
            cutoff_time = timestamp - timedelta(hours=24)
            priv_attempts = [
                ts for ts in priv_attempts 
                if datetime.fromisoformat(ts) > cutoff_time
            ]
            
            await self.cache.set(priv_key, priv_attempts, ttl_seconds=86400)
            priv_count = len(priv_attempts)
        else:
            priv_attempts = await self.cache.get(priv_key) or []
            cutoff_time = timestamp - timedelta(hours=24)
            priv_count = sum(1 for ts in priv_attempts 
                           if datetime.fromisoformat(ts) > cutoff_time)
        
        features["privilege_escalation_attempts"] = ComputedFeature(
            name="privilege_escalation_attempts",
            value=priv_count,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=3.0,
            timestamp=timestamp
        )
    
    async def _extract_consistency_features(self, features: Dict[str, ComputedFeature], 
                                          event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract behavioral consistency features."""
        # Track behavioral profile
        behavior_key = f"behavior_profile:{user_id}"
        behavior_profile = await self.cache.get(behavior_key) or {
            "event_types": {},
            "resources": {},
            "time_patterns": {},
            "total_events": 0
        }
        
        # Update profile
        event_type = event.event_type
        resource = event.data.get('resource', 'unknown')
        hour_of_day = timestamp.hour
        
        behavior_profile["event_types"][event_type] = behavior_profile["event_types"].get(event_type, 0) + 1
        behavior_profile["resources"][resource] = behavior_profile["resources"].get(resource, 0) + 1
        behavior_profile["time_patterns"][str(hour_of_day)] = behavior_profile["time_patterns"].get(str(hour_of_day), 0) + 1
        behavior_profile["total_events"] += 1
        
        await self.cache.set(behavior_key, behavior_profile, ttl_seconds=604800)  # 1 week
        
        # Calculate consistency score
        if behavior_profile["total_events"] > 10:
            # Calculate how typical current behavior is
            event_type_freq = behavior_profile["event_types"].get(event_type, 0) / behavior_profile["total_events"]
            resource_freq = behavior_profile["resources"].get(resource, 0) / behavior_profile["total_events"]
            time_freq = behavior_profile["time_patterns"].get(str(hour_of_day), 0) / behavior_profile["total_events"]
            
            # Consistency score based on frequencies (higher = more consistent)
            consistency_score = (event_type_freq + resource_freq + time_freq) / 3.0
        else:
            consistency_score = 0.5  # Neutral score for new users
        
        features["behavioral_consistency_score"] = ComputedFeature(
            name="behavioral_consistency_score",
            value=consistency_score,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=10.0,
            timestamp=timestamp
        )
    
    async def _extract_failure_rate(self, features: Dict[str, ComputedFeature], 
                                  event: BehaviorEvent, user_id: str, timestamp: datetime) -> None:
        """Extract failure rate feature."""
        # Track success/failure
        outcome_key = f"outcomes:{user_id}"
        recent_outcomes = await self.cache.get(outcome_key) or []
        
        # Determine if current event is a failure
        is_failure = self._is_failure_event(event)
        
        outcome_entry = {
            "success": not is_failure,
            "timestamp": timestamp.isoformat()
        }
        recent_outcomes.append(outcome_entry)
        
        # Filter to last hour
        hourly_cutoff = timestamp - timedelta(hours=1)
        recent_outcomes = [
            entry for entry in recent_outcomes 
            if datetime.fromisoformat(entry["timestamp"]) > hourly_cutoff
        ]
        
        await self.cache.set(outcome_key, recent_outcomes, ttl_seconds=3600)
        
        # Calculate failure rate
        if recent_outcomes:
            failures = sum(1 for entry in recent_outcomes if not entry["success"])
            failure_rate = failures / len(recent_outcomes)
        else:
            failure_rate = 0.0
        
        features["failure_rate"] = ComputedFeature(
            name="failure_rate",
            value=failure_rate,
            feature_type=FeatureType.BEHAVIORAL,
            computation_time_ms=4.0,
            timestamp=timestamp
        )
    
    def _is_admin_action(self, event: BehaviorEvent) -> bool:
        """Determine if event represents an admin action."""
        admin_indicators = [
            'admin', 'create_user', 'delete_user', 'modify_permissions',
            'system_config', 'backup', 'restore', 'sudo', 'privilege'
        ]
        
        event_data = json.dumps(event.data).lower()
        return any(indicator in event_data for indicator in admin_indicators)
    
    def _is_privilege_escalation(self, event: BehaviorEvent) -> bool:
        """Determine if event represents privilege escalation attempt."""
        escalation_indicators = [
            'sudo', 'su -', 'privilege_escalation', 'runas', 'elevate',
            'admin_login', 'role_change', 'permission_request'
        ]
        
        event_data = json.dumps(event.data).lower()
        event_type_lower = event.event_type.lower()
        
        return any(indicator in event_data or indicator in event_type_lower 
                  for indicator in escalation_indicators)
    
    def _is_failure_event(self, event: BehaviorEvent) -> bool:
        """Determine if event represents a failure."""
        # Check for explicit failure indicators
        result = event.data.get('result', '').lower()
        status_code = event.data.get('response_code', event.data.get('status_code', 0))
        
        if result in ['failed', 'error', 'denied', 'rejected']:
            return True
        
        if isinstance(status_code, (int, str)):
            try:
                status_int = int(status_code)
                if status_int >= 400:  # HTTP error codes
                    return True
            except (ValueError, TypeError):
                pass
        
        return False


class FeatureEngineeringPipeline:
    """High-performance feature engineering pipeline for user behavior analysis."""
    
    def __init__(self, cache_url: str = "redis://localhost:6379"):
        self.cache = FeatureCache(cache_url)
        
        # Initialize extractors
        self.temporal_extractor = TemporalFeatureExtractor(self.cache)
        self.categorical_extractor = CategoricalFeatureExtractor(self.cache)
        self.behavioral_extractor = BehavioralFeatureExtractor(self.cache)
        
        # Feature scalers
        self.scalers = {
            'standard': StandardScaler(),
            'robust': RobustScaler(),
            'minmax': MinMaxScaler()
        }
        
        # Performance metrics
        self.processing_stats = {
            "events_processed": 0,
            "total_processing_time_ms": 0.0,
            "average_processing_time_ms": 0.0,
            "feature_extraction_errors": 0,
            "cache_performance": {}
        }
        
        # Feature specifications registry
        self.feature_specs = self._build_feature_specs()
    
    def _build_feature_specs(self) -> Dict[str, FeatureSpec]:
        """Build comprehensive feature specifications registry."""
        specs = {}
        
        # Combine specs from all extractors
        for extractor in [self.temporal_extractor, self.categorical_extractor, self.behavioral_extractor]:
            for spec in extractor.feature_specs:
                specs[spec.name] = spec
        
        return specs
    
    async def initialize(self) -> None:
        """Initialize the feature engineering pipeline."""
        logger.info("Initializing Feature Engineering Pipeline")
        await self.cache.initialize()
        logger.info("Feature Engineering Pipeline initialized successfully")
    
    async def extract_features(self, event: BehaviorEvent, context: Optional[Dict[str, Any]] = None) -> FeatureVector:
        """Extract complete feature vector from behavior event."""
        start_time = time.time()
        context = context or {}
        
        try:
            # Extract features from all extractors concurrently
            extraction_tasks = [
                self.temporal_extractor.extract_features(event, context),
                self.categorical_extractor.extract_features(event, context),
                self.behavioral_extractor.extract_features(event, context)
            ]
            
            results = await asyncio.gather(*extraction_tasks, return_exceptions=True)
            
            # Combine features
            all_features = {}
            for result in results:
                if isinstance(result, dict):
                    all_features.update(result)
                else:
                    logger.error(f"Feature extraction error: {result}")
                    self.processing_stats["feature_extraction_errors"] += 1
            
            # Calculate total computation time
            total_time_ms = (time.time() - start_time) * 1000
            
            # Create feature vector
            feature_vector = FeatureVector(
                user_id=event.user_id,
                event_id=event.event_id,
                timestamp=event.timestamp,
                features=all_features,
                total_computation_time_ms=total_time_ms,
                feature_quality_score=self._calculate_feature_quality(all_features)
            )
            
            # Update processing statistics
            self._update_processing_stats(total_time_ms)
            
            return feature_vector
            
        except Exception as e:
            logger.error(f"Feature extraction failed for event {event.event_id}: {str(e)}")
            self.processing_stats["feature_extraction_errors"] += 1
            
            # Return minimal feature vector on error
            return FeatureVector(
                user_id=event.user_id,
                event_id=event.event_id,
                timestamp=event.timestamp,
                features={},
                total_computation_time_ms=(time.time() - start_time) * 1000,
                feature_quality_score=0.0
            )
    
    async def extract_features_batch(self, events: List[BehaviorEvent], 
                                   max_concurrent: int = 10) -> List[FeatureVector]:
        """Extract features for multiple events with controlled concurrency."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def extract_with_semaphore(event):
            async with semaphore:
                return await self.extract_features(event)
        
        tasks = [extract_with_semaphore(event) for event in events]
        return await asyncio.gather(*tasks, return_exceptions=False)
    
    def prepare_ml_features(self, feature_vectors: List[FeatureVector], 
                          scaler_type: str = 'standard') -> Tuple[np.ndarray, List[str]]:
        """Prepare features for ML model training/inference."""
        if not feature_vectors:
            return np.array([]), []
        
        # Get all unique feature names
        all_feature_names = set()
        for fv in feature_vectors:
            all_feature_names.update(fv.features.keys())
        
        feature_names = sorted(list(all_feature_names))
        
        # Create feature matrix
        feature_matrix = []
        for fv in feature_vectors:
            row = []
            for feature_name in feature_names:
                if feature_name in fv.features:
                    value = fv.features[feature_name].value
                    # Convert to numeric
                    if isinstance(value, bool):
                        row.append(float(value))
                    elif isinstance(value, (int, float)):
                        row.append(float(value))
                    else:
                        row.append(0.0)  # Default for non-numeric values
                else:
                    row.append(0.0)  # Missing feature
            feature_matrix.append(row)
        
        feature_array = np.array(feature_matrix)
        
        # Apply scaling if requested
        if scaler_type in self.scalers and feature_array.shape[0] > 1:
            feature_array = self.scalers[scaler_type].fit_transform(feature_array)
        
        return feature_array, feature_names
    
    def _calculate_feature_quality(self, features: Dict[str, ComputedFeature]) -> float:
        """Calculate overall feature quality score."""
        if not features:
            return 0.0
        
        # Quality based on number of features extracted and their confidence
        total_confidence = sum(feature.confidence for feature in features.values())
        average_confidence = total_confidence / len(features)
        
        # Penalty for missing critical features
        critical_features = ['hour_of_day', 'device_change_score', 'resource_access_rate']
        missing_critical = sum(1 for cf in critical_features if cf not in features)
        completeness_score = max(0.0, 1.0 - (missing_critical / len(critical_features)))
        
        # Combined quality score
        quality_score = (average_confidence * 0.7) + (completeness_score * 0.3)
        
        return min(quality_score, 1.0)
    
    def _update_processing_stats(self, processing_time_ms: float) -> None:
        """Update processing performance statistics."""
        self.processing_stats["events_processed"] += 1
        self.processing_stats["total_processing_time_ms"] += processing_time_ms
        
        # Update moving average
        self.processing_stats["average_processing_time_ms"] = (
            self.processing_stats["total_processing_time_ms"] / 
            self.processing_stats["events_processed"]
        )
    
    async def get_pipeline_performance(self) -> Dict[str, Any]:
        """Get comprehensive pipeline performance metrics."""
        cache_stats = self.cache.get_cache_stats()
        
        performance_data = {
            "processing_statistics": self.processing_stats,
            "cache_performance": cache_stats,
            "extractor_performance": {
                "temporal_avg_time_ms": self.temporal_extractor.get_average_computation_time(),
                "categorical_avg_time_ms": self.categorical_extractor.get_average_computation_time(),
                "behavioral_avg_time_ms": self.behavioral_extractor.get_average_computation_time()
            },
            "feature_registry": {
                "total_features": len(self.feature_specs),
                "feature_types": {
                    ft.value: sum(1 for spec in self.feature_specs.values() if spec.feature_type == ft)
                    for ft in FeatureType
                }
            }
        }
        
        return performance_data
    
    async def validate_feature_quality(self, feature_vectors: List[FeatureVector]) -> Dict[str, Any]:
        """Validate quality of extracted features."""
        if not feature_vectors:
            return {"status": "no_data", "quality_score": 0.0}
        
        # Analyze feature completeness
        all_possible_features = set(self.feature_specs.keys())
        actual_features = set()
        for fv in feature_vectors:
            actual_features.update(fv.features.keys())
        
        completeness = len(actual_features) / len(all_possible_features)
        
        # Analyze feature quality scores
        quality_scores = [fv.feature_quality_score for fv in feature_vectors]
        avg_quality = sum(quality_scores) / len(quality_scores)
        
        # Analyze computation times
        computation_times = [fv.total_computation_time_ms for fv in feature_vectors]
        avg_computation_time = sum(computation_times) / len(computation_times)
        
        # Performance validation
        performance_ok = avg_computation_time < 50.0  # Target: <50ms
        quality_ok = avg_quality > 0.8  # Target: >80% quality
        completeness_ok = completeness > 0.7  # Target: >70% feature coverage
        
        validation_result = {
            "status": "valid" if all([performance_ok, quality_ok, completeness_ok]) else "issues_detected",
            "overall_quality_score": (completeness + avg_quality) / 2.0,
            "feature_completeness": completeness,
            "average_quality_score": avg_quality,
            "average_computation_time_ms": avg_computation_time,
            "performance_target_met": performance_ok,
            "quality_target_met": quality_ok,
            "completeness_target_met": completeness_ok,
            "total_vectors_analyzed": len(feature_vectors),
            "unique_features_found": len(actual_features),
            "missing_features": list(all_possible_features - actual_features)
        }
        
        return validation_result
    
    async def cleanup(self) -> None:
        """Cleanup pipeline resources."""
        # Close cache connections
        if self.cache.redis_pool:
            await self.cache.redis_pool.disconnect()
        
        logger.info("Feature Engineering Pipeline cleanup completed")


# Factory function for pipeline initialization
async def initialize_feature_engineering_pipeline(cache_url: str = "redis://localhost:6379") -> FeatureEngineeringPipeline:
    """Initialize and return configured feature engineering pipeline."""
    logger.info("Initializing Feature Engineering Pipeline")
    
    pipeline = FeatureEngineeringPipeline(cache_url)
    await pipeline.initialize()
    
    logger.info(f"Feature Engineering Pipeline initialized with {len(pipeline.feature_specs)} feature specifications")
    
    return pipeline


# Example usage and testing
if __name__ == "__main__":
    async def test_feature_pipeline():
        from .data_sources_integration import BehaviorEvent
        from datetime import datetime
        
        # Initialize pipeline
        pipeline = await initialize_feature_engineering_pipeline()
        
        # Create sample behavior event
        sample_event = BehaviorEvent(
            event_id="test_001",
            user_id="user123",
            session_id="session_abc",
            timestamp=datetime.utcnow(),
            event_type="login",
            source="auth_system",
            data={
                "source_ip": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "result": "success",
                "mfa_used": True
            },
            device_info={"device_id": "device123", "device_type": "desktop"},
            location_info={"country": "US", "city": "Seattle"}
        )
        
        # Extract features
        feature_vector = await pipeline.extract_features(sample_event)
        
        print("=== Feature Extraction Test Results ===")
        print(f"User ID: {feature_vector.user_id}")
        print(f"Total Features Extracted: {len(feature_vector.features)}")
        print(f"Computation Time: {feature_vector.total_computation_time_ms:.2f}ms")
        print(f"Feature Quality Score: {feature_vector.feature_quality_score:.3f}")
        
        print("\nExtracted Features:")
        for name, feature in feature_vector.features.items():
            print(f"  {name}: {feature.value} ({feature.feature_type.value})")
        
        # Performance metrics
        performance = await pipeline.get_pipeline_performance()
        print(f"\nPipeline Performance:")
        print(f"  Average Processing Time: {performance['processing_statistics']['average_processing_time_ms']:.2f}ms")
        print(f"  Cache Hit Rate: {performance['cache_performance']['hit_rate_percentage']:.1f}%")
        
        # Cleanup
        await pipeline.cleanup()
    
    asyncio.run(test_feature_pipeline())