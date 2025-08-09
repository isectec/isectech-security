"""
User Behavior Data Collection

This module implements data collection mechanisms for user behavior metrics
that feed into the trust scoring system. It captures login patterns, resource
access, session anomalies, and other behavioral indicators while ensuring
privacy compliance and data protection.
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, deque
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Types of behavioral events to collect."""
    LOGIN = "login"
    LOGOUT = "logout"
    RESOURCE_ACCESS = "resource_access"
    DATA_TRANSFER = "data_transfer"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_ACTIVITY = "session_activity"
    AUTHENTICATION_FAILURE = "auth_failure"
    PASSWORD_CHANGE = "password_change"
    MFA_VERIFICATION = "mfa_verification"
    ADMIN_ACTION = "admin_action"


class DataSensitivityLevel(str, Enum):
    """Data sensitivity levels for access tracking."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


@dataclass
class BehavioralEvent:
    """Individual behavioral event with privacy protection."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = ""
    tenant_id: str = ""
    session_id: str = ""
    event_type: EventType = EventType.LOGIN
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Event details (anonymized where needed)
    ip_address_hash: str = ""  # SHA-256 hash of IP for privacy
    user_agent_hash: str = ""  # Hashed user agent
    resource_accessed: Optional[str] = None
    data_sensitivity: DataSensitivityLevel = DataSensitivityLevel.INTERNAL
    data_volume_bytes: int = 0
    
    # Context information
    location_country: Optional[str] = None
    location_region: Optional[str] = None
    is_business_hours: bool = True
    is_weekend: bool = False
    
    # Security context
    mfa_verified: bool = False
    authentication_method: Optional[str] = None
    privilege_level: str = "user"
    success: bool = True
    failure_reason: Optional[str] = None
    
    # Network context
    is_vpn: bool = False
    is_public_wifi: bool = False
    is_corporate_network: bool = False
    network_trust_score: float = 0.5
    
    # Derived metrics (calculated at collection time)
    session_duration_minutes: Optional[int] = None
    concurrent_sessions: int = 1
    
    def __post_init__(self):
        """Post-initialization processing for privacy and validation."""
        if self.ip_address_hash and not self._is_valid_hash(self.ip_address_hash):
            raise ValueError("Invalid IP address hash format")
        if self.user_agent_hash and not self._is_valid_hash(self.user_agent_hash):
            raise ValueError("Invalid user agent hash format")
    
    @staticmethod
    def _is_valid_hash(hash_str: str) -> bool:
        """Validate that a string is a valid SHA-256 hash."""
        return len(hash_str) == 64 and all(c in '0123456789abcdef' for c in hash_str.lower())
    
    @staticmethod
    def hash_pii_data(data: str) -> str:
        """Hash PII data for privacy protection."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for storage/transmission."""
        return {
            "event_id": self.event_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "session_id": self.session_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "ip_address_hash": self.ip_address_hash,
            "user_agent_hash": self.user_agent_hash,
            "resource_accessed": self.resource_accessed,
            "data_sensitivity": self.data_sensitivity.value,
            "data_volume_bytes": self.data_volume_bytes,
            "location_country": self.location_country,
            "location_region": self.location_region,
            "is_business_hours": self.is_business_hours,
            "is_weekend": self.is_weekend,
            "mfa_verified": self.mfa_verified,
            "authentication_method": self.authentication_method,
            "privilege_level": self.privilege_level,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "is_vpn": self.is_vpn,
            "is_public_wifi": self.is_public_wifi,
            "is_corporate_network": self.is_corporate_network,
            "network_trust_score": self.network_trust_score,
            "session_duration_minutes": self.session_duration_minutes,
            "concurrent_sessions": self.concurrent_sessions
        }


@dataclass
class UserBehaviorProfile:
    """Aggregated user behavior profile for analysis."""
    user_id: str
    tenant_id: str
    profile_period_start: datetime
    profile_period_end: datetime
    
    # Login patterns
    login_times: List[int] = field(default_factory=list)  # Hours of day
    login_days: List[int] = field(default_factory=list)   # Days of week (0=Monday)
    unique_locations: Set[str] = field(default_factory=set)  # Country codes
    unique_ip_hashes: Set[str] = field(default_factory=set)
    
    # Session patterns
    avg_session_duration: float = 0.0
    max_concurrent_sessions: int = 1
    total_sessions: int = 0
    
    # Access patterns
    resources_accessed: Set[str] = field(default_factory=set)
    data_sensitivity_accessed: Set[DataSensitivityLevel] = field(default_factory=set)
    total_data_transferred: int = 0
    
    # Authentication patterns
    failed_login_attempts: int = 0
    mfa_usage_rate: float = 0.0
    authentication_methods: Set[str] = field(default_factory=set)
    
    # Risk indicators
    privilege_escalation_attempts: int = 0
    off_hours_activity_count: int = 0
    weekend_activity_count: int = 0
    public_wifi_usage_count: int = 0
    
    # Network patterns
    vpn_usage_rate: float = 0.0
    corporate_network_rate: float = 0.0
    avg_network_trust: float = 0.5
    
    # Calculated metrics
    business_hours_ratio: float = 0.0
    weekend_ratio: float = 0.0
    success_rate: float = 1.0
    location_consistency_score: float = 1.0
    time_consistency_score: float = 1.0
    
    def calculate_derived_metrics(self):
        """Calculate derived metrics from raw data."""
        if not self.login_times:
            return
        
        # Business hours ratio (9 AM to 5 PM)
        business_hours_logins = sum(1 for hour in self.login_times if 9 <= hour <= 17)
        self.business_hours_ratio = business_hours_logins / len(self.login_times) if self.login_times else 0
        
        # Weekend ratio (Saturday=5, Sunday=6)  
        weekend_logins = sum(1 for day in self.login_days if day >= 5)
        self.weekend_ratio = weekend_logins / len(self.login_days) if self.login_days else 0
        
        # Location consistency (fewer unique locations = higher consistency)
        self.location_consistency_score = max(0.0, 1.0 - (len(self.unique_locations) - 1) * 0.2)
        
        # Time consistency (lower standard deviation = higher consistency)
        if len(self.login_times) > 1:
            import numpy as np
            time_std = np.std(self.login_times)
            self.time_consistency_score = max(0.0, 1.0 - (time_std / 12))  # Normalize by 12 hours
    
    def to_features_dict(self) -> Dict[str, Any]:
        """Convert profile to features dictionary for trust scoring."""
        self.calculate_derived_metrics()
        
        return {
            "user_id": self.user_id,
            "profile_period_days": (self.profile_period_end - self.profile_period_start).days,
            
            # Login patterns
            "unique_locations": len(self.unique_locations),
            "unique_ip_addresses": len(self.unique_ip_hashes),
            "most_common_login_hour": max(set(self.login_times), key=self.login_times.count) if self.login_times else 12,
            "login_time_variance": np.var(self.login_times) if self.login_times else 0,
            
            # Session metrics
            "avg_session_duration": self.avg_session_duration,
            "max_concurrent_sessions": self.max_concurrent_sessions,
            "total_sessions": self.total_sessions,
            
            # Access metrics
            "unique_resources": len(self.resources_accessed),
            "highest_data_sensitivity": self._get_highest_sensitivity(),
            "total_data_transferred": self.total_data_transferred,
            "classified_data_ratio": self._get_classified_data_ratio(),
            
            # Authentication metrics
            "failure_count": self.failed_login_attempts,
            "mfa_usage_rate": self.mfa_usage_rate,
            "auth_methods_used": len(self.authentication_methods),
            
            # Risk metrics
            "privilege_escalation_attempts": self.privilege_escalation_attempts,
            "off_hours_activity_count": self.off_hours_activity_count,
            "weekend_activity_count": self.weekend_activity_count,
            "public_wifi_usage_count": self.public_wifi_usage_count,
            
            # Network metrics  
            "vpn_usage_rate": self.vpn_usage_rate,
            "corporate_network_rate": self.corporate_network_rate,
            "avg_network_trust": self.avg_network_trust,
            
            # Calculated ratios
            "business_hours_ratio": self.business_hours_ratio,
            "weekend_ratio": self.weekend_ratio,
            "success_rate": self.success_rate,
            "location_consistency_score": self.location_consistency_score,
            "time_consistency_score": self.time_consistency_score
        }
    
    def _get_highest_sensitivity(self) -> str:
        """Get the highest data sensitivity level accessed."""
        sensitivity_order = [
            DataSensitivityLevel.PUBLIC,
            DataSensitivityLevel.INTERNAL,
            DataSensitivityLevel.CONFIDENTIAL,
            DataSensitivityLevel.SECRET,
            DataSensitivityLevel.TOP_SECRET
        ]
        
        for level in reversed(sensitivity_order):
            if level in self.data_sensitivity_accessed:
                return level.value
        
        return DataSensitivityLevel.PUBLIC.value
    
    def _get_classified_data_ratio(self) -> float:
        """Get ratio of classified (above internal) data accessed."""
        classified_levels = {
            DataSensitivityLevel.CONFIDENTIAL,
            DataSensitivityLevel.SECRET,
            DataSensitivityLevel.TOP_SECRET
        }
        
        classified_count = len(classified_levels.intersection(self.data_sensitivity_accessed))
        total_count = len(self.data_sensitivity_accessed)
        
        return classified_count / total_count if total_count > 0 else 0.0


class BehaviorDataCollector:
    """Main collector for user behavior data."""
    
    def __init__(self, retention_days: int = 90, privacy_mode: bool = True):
        self.retention_days = retention_days
        self.privacy_mode = privacy_mode
        
        # In-memory storage for recent events (would be replaced with proper storage)
        self.event_buffer: deque = deque(maxlen=10000)  # Recent events buffer
        self.user_sessions: Dict[str, Dict[str, Any]] = {}  # Active session tracking
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}  # Cached profiles
        
        # Event aggregation buffers
        self.hourly_aggregates: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.daily_aggregates: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        
        logger.info(f"Initialized BehaviorDataCollector with {retention_days} day retention")
    
    def collect_event(self, 
                     user_id: str,
                     tenant_id: str,
                     event_type: EventType,
                     ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None,
                     resource_accessed: Optional[str] = None,
                     data_volume: int = 0,
                     additional_context: Optional[Dict[str, Any]] = None) -> BehavioralEvent:
        """Collect a behavioral event with privacy protection."""
        
        try:
            # Create base event
            event = BehavioralEvent(
                user_id=user_id,
                tenant_id=tenant_id,
                event_type=event_type,
                resource_accessed=resource_accessed,
                data_volume_bytes=data_volume
            )
            
            # Hash PII data for privacy
            if ip_address and self.privacy_mode:
                event.ip_address_hash = BehavioralEvent.hash_pii_data(ip_address)
            elif ip_address:
                event.ip_address_hash = ip_address  # Non-privacy mode for testing
            
            if user_agent and self.privacy_mode:
                event.user_agent_hash = BehavioralEvent.hash_pii_data(user_agent)
            elif user_agent:
                event.user_agent_hash = user_agent[:50]  # Truncate for non-privacy mode
            
            # Add additional context if provided
            if additional_context:
                event.location_country = additional_context.get("country")
                event.location_region = additional_context.get("region")
                event.is_business_hours = self._is_business_hours(event.timestamp)
                event.is_weekend = self._is_weekend(event.timestamp)
                event.mfa_verified = additional_context.get("mfa_verified", False)
                event.authentication_method = additional_context.get("auth_method")
                event.privilege_level = additional_context.get("privilege_level", "user")
                event.success = additional_context.get("success", True)
                event.failure_reason = additional_context.get("failure_reason")
                event.is_vpn = additional_context.get("is_vpn", False)
                event.is_public_wifi = additional_context.get("is_public_wifi", False)
                event.is_corporate_network = additional_context.get("is_corporate_network", False)
                event.network_trust_score = additional_context.get("network_trust_score", 0.5)
            
            # Handle session tracking
            if event_type == EventType.LOGIN and event.success:
                self._start_session_tracking(user_id, event.session_id, event.timestamp)
            elif event_type == EventType.LOGOUT:
                self._end_session_tracking(user_id, event.session_id, event.timestamp)
                
            # Update concurrent session count
            event.concurrent_sessions = self._get_concurrent_sessions(user_id)
            
            # Add event to buffer
            self.event_buffer.append(event)
            
            # Update aggregates
            self._update_aggregates(event)
            
            # Trigger profile updates for significant events
            if event_type in [EventType.LOGIN, EventType.RESOURCE_ACCESS, EventType.PRIVILEGE_ESCALATION]:
                self._update_user_profile(user_id, event)
            
            logger.debug(f"Collected {event_type.value} event for user {user_id}")
            return event
            
        except Exception as e:
            logger.error(f"Error collecting behavioral event: {e}")
            raise
    
    def get_user_behavior_profile(self, 
                                 user_id: str,
                                 days_back: int = 30,
                                 force_recalculate: bool = False) -> UserBehaviorProfile:
        """Get behavioral profile for a user."""
        
        profile_key = f"{user_id}_{days_back}"
        
        # Return cached profile if available and not forced to recalculate
        if profile_key in self.user_profiles and not force_recalculate:
            cached_profile = self.user_profiles[profile_key]
            # Check if cached profile is still fresh (less than 1 hour old)
            if (datetime.utcnow() - cached_profile.profile_period_end).seconds < 3600:
                return cached_profile
        
        # Calculate new profile
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days_back)
        
        profile = UserBehaviorProfile(
            user_id=user_id,
            tenant_id="",  # Will be set from first event
            profile_period_start=start_time,
            profile_period_end=end_time
        )
        
        # Analyze events for this user in the time period
        user_events = [
            event for event in self.event_buffer
            if (event.user_id == user_id and 
                start_time <= event.timestamp <= end_time)
        ]
        
        if not user_events:
            logger.warning(f"No events found for user {user_id} in last {days_back} days")
            return profile
        
        # Set tenant ID from first event
        profile.tenant_id = user_events[0].tenant_id
        
        # Aggregate login patterns
        login_events = [e for e in user_events if e.event_type == EventType.LOGIN]
        profile.login_times = [e.timestamp.hour for e in login_events]
        profile.login_days = [e.timestamp.weekday() for e in login_events]
        profile.unique_locations = {e.location_country for e in login_events if e.location_country}
        profile.unique_ip_hashes = {e.ip_address_hash for e in login_events if e.ip_address_hash}
        
        # Calculate session metrics
        session_durations = [e.session_duration_minutes for e in user_events 
                           if e.session_duration_minutes is not None]
        if session_durations:
            profile.avg_session_duration = sum(session_durations) / len(session_durations)
        
        profile.max_concurrent_sessions = max((e.concurrent_sessions for e in user_events), default=1)
        profile.total_sessions = len(set(e.session_id for e in user_events if e.session_id))
        
        # Access patterns
        access_events = [e for e in user_events if e.event_type == EventType.RESOURCE_ACCESS]
        profile.resources_accessed = {e.resource_accessed for e in access_events if e.resource_accessed}
        profile.data_sensitivity_accessed = {e.data_sensitivity for e in access_events}
        profile.total_data_transferred = sum(e.data_volume_bytes for e in access_events)
        
        # Authentication patterns
        auth_failure_events = [e for e in user_events if e.event_type == EventType.AUTHENTICATION_FAILURE]
        profile.failed_login_attempts = len(auth_failure_events)
        
        mfa_events = [e for e in user_events if e.mfa_verified]
        total_auth_events = len([e for e in user_events if e.event_type in [EventType.LOGIN, EventType.MFA_VERIFICATION]])
        profile.mfa_usage_rate = len(mfa_events) / total_auth_events if total_auth_events > 0 else 0.0
        
        profile.authentication_methods = {e.authentication_method for e in user_events 
                                        if e.authentication_method}
        
        # Risk indicators
        priv_esc_events = [e for e in user_events if e.event_type == EventType.PRIVILEGE_ESCALATION]
        profile.privilege_escalation_attempts = len(priv_esc_events)
        
        profile.off_hours_activity_count = len([e for e in user_events if not e.is_business_hours])
        profile.weekend_activity_count = len([e for e in user_events if e.is_weekend])
        profile.public_wifi_usage_count = len([e for e in user_events if e.is_public_wifi])
        
        # Network patterns
        network_events = [e for e in user_events if hasattr(e, 'is_vpn')]
        if network_events:
            profile.vpn_usage_rate = sum(1 for e in network_events if e.is_vpn) / len(network_events)
            profile.corporate_network_rate = sum(1 for e in network_events if e.is_corporate_network) / len(network_events)
            profile.avg_network_trust = sum(e.network_trust_score for e in network_events) / len(network_events)
        
        # Success rate
        total_events_with_status = len([e for e in user_events if hasattr(e, 'success')])
        successful_events = len([e for e in user_events if hasattr(e, 'success') and e.success])
        profile.success_rate = successful_events / total_events_with_status if total_events_with_status > 0 else 1.0
        
        # Cache the profile
        self.user_profiles[profile_key] = profile
        
        logger.info(f"Generated behavior profile for user {user_id} with {len(user_events)} events")
        return profile
    
    def get_behavior_features(self, 
                            user_id: str, 
                            days_back: int = 30) -> Dict[str, Any]:
        """Get behavior features for trust scoring."""
        profile = self.get_user_behavior_profile(user_id, days_back)
        return profile.to_features_dict()
    
    def cleanup_old_data(self):
        """Clean up old events beyond retention period."""
        cutoff_time = datetime.utcnow() - timedelta(days=self.retention_days)
        
        # Filter event buffer
        original_size = len(self.event_buffer)
        self.event_buffer = deque(
            (event for event in self.event_buffer if event.timestamp >= cutoff_time),
            maxlen=self.event_buffer.maxlen
        )
        
        cleaned_count = original_size - len(self.event_buffer)
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old events")
        
        # Clean up cached profiles
        self.user_profiles.clear()  # Force recalculation of profiles
    
    def _is_business_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is during business hours (9 AM - 5 PM, weekdays)."""
        return (timestamp.weekday() < 5 and  # Monday-Friday
                9 <= timestamp.hour <= 17)      # 9 AM - 5 PM
    
    def _is_weekend(self, timestamp: datetime) -> bool:
        """Check if timestamp is on weekend."""
        return timestamp.weekday() >= 5  # Saturday or Sunday
    
    def _start_session_tracking(self, user_id: str, session_id: str, start_time: datetime):
        """Start tracking a user session."""
        if user_id not in self.user_sessions:
            self.user_sessions[user_id] = {}
        
        self.user_sessions[user_id][session_id] = {
            "start_time": start_time,
            "last_activity": start_time,
            "active": True
        }
    
    def _end_session_tracking(self, user_id: str, session_id: str, end_time: datetime):
        """End tracking a user session."""
        if (user_id in self.user_sessions and 
            session_id in self.user_sessions[user_id]):
            
            session = self.user_sessions[user_id][session_id]
            session["end_time"] = end_time
            session["active"] = False
            
            # Calculate session duration
            duration = end_time - session["start_time"]
            session["duration_minutes"] = int(duration.total_seconds() / 60)
    
    def _get_concurrent_sessions(self, user_id: str) -> int:
        """Get count of concurrent active sessions for user."""
        if user_id not in self.user_sessions:
            return 0
        
        active_sessions = sum(1 for session in self.user_sessions[user_id].values() 
                            if session.get("active", False))
        return active_sessions
    
    def _update_aggregates(self, event: BehavioralEvent):
        """Update hourly and daily aggregates."""
        hour_key = event.timestamp.strftime("%Y-%m-%d-%H")
        day_key = event.timestamp.strftime("%Y-%m-%d")
        
        # Update hourly aggregates
        self.hourly_aggregates[hour_key]["total_events"] += 1
        self.hourly_aggregates[hour_key][event.event_type.value] += 1
        if not event.success:
            self.hourly_aggregates[hour_key]["failed_events"] += 1
        
        # Update daily aggregates
        self.daily_aggregates[day_key]["total_events"] += 1
        self.daily_aggregates[day_key][event.event_type.value] += 1
        self.daily_aggregates[day_key]["unique_users"].add(event.user_id)
        
    def _update_user_profile(self, user_id: str, event: BehavioralEvent):
        """Update cached user profile with new event."""
        # This is a simplified update - in production, would use more sophisticated
        # incremental update logic
        pass
    
    def get_aggregated_metrics(self, 
                             time_range: str = "24h") -> Dict[str, Any]:
        """Get aggregated behavioral metrics for monitoring."""
        if time_range == "24h":
            cutoff = datetime.utcnow() - timedelta(hours=24)
            relevant_hours = [
                hour_key for hour_key in self.hourly_aggregates.keys()
                if datetime.strptime(hour_key, "%Y-%m-%d-%H") >= cutoff
            ]
            
            total_events = sum(
                self.hourly_aggregates[hour]["total_events"] 
                for hour in relevant_hours
            )
            
            failed_events = sum(
                self.hourly_aggregates[hour]["failed_events"]
                for hour in relevant_hours
            )
            
            return {
                "time_range": time_range,
                "total_events": total_events,
                "failed_events": failed_events,
                "success_rate": (total_events - failed_events) / total_events if total_events > 0 else 1.0,
                "active_users": len(set(event.user_id for event in self.event_buffer 
                                      if event.timestamp >= cutoff)),
                "event_types": dict(defaultdict(int))  # Would calculate event type distribution
            }
        
        return {"error": "Unsupported time range"}


# Export main classes
__all__ = [
    "BehavioralEvent",
    "UserBehaviorProfile", 
    "BehaviorDataCollector",
    "EventType",
    "DataSensitivityLevel"
]