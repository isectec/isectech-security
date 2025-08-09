"""
Trust Score Parameters and Configuration

This module defines all parameters that influence trust score calculation,
their weightings, and baseline configurations for continuous verification.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid


class TrustLevel(str, Enum):
    """Trust levels for access decisions."""
    UNTRUSTED = "untrusted"      # 0.0 - 0.2
    LOW = "low"                  # 0.2 - 0.4  
    MEDIUM = "medium"            # 0.4 - 0.6
    HIGH = "high"                # 0.6 - 0.8
    TRUSTED = "trusted"          # 0.8 - 1.0


class TrustFactorType(str, Enum):
    """Categories of factors that influence trust score."""
    USER_BEHAVIOR = "user_behavior"
    DEVICE_POSTURE = "device_posture" 
    NETWORK_CONTEXT = "network_context"
    AUTHENTICATION = "authentication"
    ACCESS_PATTERNS = "access_patterns"
    TEMPORAL = "temporal"
    GEOSPATIAL = "geospatial"


@dataclass
class TrustFactorWeight:
    """Weight configuration for trust score factors."""
    factor_type: TrustFactorType
    weight: float  # 0.0 to 1.0
    description: str
    enabled: bool = True
    min_confidence: float = 0.5
    decay_rate: float = 0.1  # How fast this factor decays over time
    
    def __post_init__(self):
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError(f"Weight must be between 0.0 and 1.0, got {self.weight}")


@dataclass 
class UserBehaviorParameters:
    """Parameters for user behavior analysis in trust scoring."""
    
    # Login behavior weights
    login_time_consistency: float = 0.15
    login_location_consistency: float = 0.20
    login_frequency_pattern: float = 0.10
    failed_login_attempts: float = -0.25  # Negative weight (decreases trust)
    
    # Access pattern weights
    resource_access_pattern: float = 0.12
    privilege_escalation_attempts: float = -0.30
    unusual_data_access: float = -0.20
    data_volume_anomalies: float = -0.15
    
    # Session behavior weights
    session_duration_consistency: float = 0.08
    concurrent_sessions: float = -0.10
    idle_time_patterns: float = 0.05
    
    # Activity timing weights
    business_hours_activity: float = 0.10
    weekend_activity: float = -0.05
    night_activity: float = -0.08
    
    # Baseline thresholds
    baseline_learning_days: int = 30
    anomaly_threshold: float = 0.7
    confidence_threshold: float = 0.6


@dataclass
class DevicePostureParameters:
    """Parameters for device security posture assessment."""
    
    # Security state weights
    os_patch_level: float = 0.25
    antivirus_status: float = 0.20
    firewall_enabled: float = 0.15
    encryption_status: float = 0.20
    
    # Device trust weights  
    device_registration_status: float = 0.15
    device_compliance_score: float = 0.18
    jailbreak_root_detection: float = -0.40  # Major trust reduction
    
    # Hardware security weights
    tpm_presence: float = 0.10
    secure_boot_status: float = 0.12
    biometric_capability: float = 0.08
    
    # Software integrity weights
    certificate_validation: float = 0.15
    code_signing_verification: float = 0.12
    suspicious_processes: float = -0.25
    
    # Baseline requirements
    minimum_os_age_days: int = 90  # OS must be updated within 90 days
    required_security_controls: List[str] = field(default_factory=lambda: [
        "antivirus", "firewall", "encryption", "auto_update"
    ])


@dataclass
class NetworkContextParameters:
    """Parameters for network location and context analysis."""
    
    # Location-based weights
    known_location_bonus: float = 0.20
    corporate_network_bonus: float = 0.25
    vpn_usage_bonus: float = 0.15
    public_wifi_penalty: float = -0.20
    
    # IP reputation weights
    ip_reputation_score: float = 0.30
    geolocation_consistency: float = 0.18
    tor_exit_node_penalty: float = -0.50
    suspicious_asn_penalty: float = -0.25
    
    # Network behavior weights
    bandwidth_usage_pattern: float = 0.10
    connection_timing: float = 0.12
    dns_query_patterns: float = 0.08
    
    # Threat intelligence integration
    ioc_match_penalty: float = -0.80  # Severe penalty for IOC matches
    threat_feed_correlation: float = 0.15
    
    # Baseline configuration
    trusted_ip_ranges: List[str] = field(default_factory=list)
    trusted_countries: List[str] = field(default_factory=lambda: ["US", "CA", "GB", "AU"])
    blocked_countries: List[str] = field(default_factory=list)


@dataclass
class AuthenticationParameters:
    """Parameters for authentication-related trust factors."""
    
    # MFA weights
    mfa_enabled_bonus: float = 0.25
    mfa_method_strength: Dict[str, float] = field(default_factory=lambda: {
        "TOTP": 0.20,
        "FIDO2": 0.30,
        "SMS": 0.10,
        "EMAIL": 0.05,
        "BACKUP_CODE": 0.08
    })
    
    # Authentication success weights
    recent_auth_success: float = 0.15
    password_age_factor: float = 0.10
    credential_strength: float = 0.18
    
    # Risk factors
    brute_force_indicators: float = -0.40
    credential_stuffing_indicators: float = -0.35
    password_spray_indicators: float = -0.30
    
    # Session security
    session_encryption: float = 0.12
    secure_cookie_usage: float = 0.08
    csrf_protection: float = 0.06


@dataclass
class TemporalParameters:
    """Parameters for time-based trust factors."""
    
    # Time consistency weights
    access_time_consistency: float = 0.20
    work_hours_alignment: float = 0.15
    timezone_consistency: float = 0.18
    
    # Velocity analysis weights
    impossible_travel_detection: float = -0.50
    rapid_location_changes: float = -0.25
    velocity_threshold_kmh: float = 900.0  # Speed of commercial aircraft
    
    # Temporal patterns
    regular_schedule_bonus: float = 0.12
    weekend_anomaly_penalty: float = -0.10
    holiday_access_penalty: float = -0.08
    
    # Time windows for analysis
    short_term_window_hours: int = 24
    medium_term_window_days: int = 7
    long_term_window_days: int = 30


@dataclass
class GeospatialParameters:
    """Parameters for geospatial analysis in trust scoring."""
    
    # Location analysis weights
    historical_location_match: float = 0.25
    approved_location_bonus: float = 0.20
    restricted_location_penalty: float = -0.40
    
    # Distance-based factors
    distance_from_home_office: float = 0.15
    distance_from_last_login: float = 0.18
    location_accuracy_confidence: float = 0.10
    
    # Geofencing
    corporate_geofence_bonus: float = 0.22
    sensitive_area_restrictions: Dict[str, float] = field(default_factory=lambda: {
        "embassy": -0.30,
        "government": -0.20,
        "military": -0.40,
        "foreign_country": -0.15
    })
    
    # Location verification
    gps_spoofing_detection: float = -0.35
    location_service_reliability: float = 0.12


@dataclass
class TrustScoreConfiguration:
    """Complete trust score configuration with all parameters."""
    
    # Core configuration
    version: str = "1.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    tenant_id: Optional[str] = None
    
    # Factor weights (must sum to approximately 1.0)
    factor_weights: Dict[TrustFactorType, float] = field(default_factory=lambda: {
        TrustFactorType.USER_BEHAVIOR: 0.25,
        TrustFactorType.DEVICE_POSTURE: 0.20,
        TrustFactorType.NETWORK_CONTEXT: 0.20,
        TrustFactorType.AUTHENTICATION: 0.15,
        TrustFactorType.ACCESS_PATTERNS: 0.10,
        TrustFactorType.TEMPORAL: 0.05,
        TrustFactorType.GEOSPATIAL: 0.05
    })
    
    # Parameter sets
    user_behavior: UserBehaviorParameters = field(default_factory=UserBehaviorParameters)
    device_posture: DevicePostureParameters = field(default_factory=DevicePostureParameters)
    network_context: NetworkContextParameters = field(default_factory=NetworkContextParameters)
    authentication: AuthenticationParameters = field(default_factory=AuthenticationParameters)
    temporal: TemporalParameters = field(default_factory=TemporalParameters)
    geospatial: GeospatialParameters = field(default_factory=GeospatialParameters)
    
    # Global settings
    base_trust_score: float = 0.5  # Starting trust score for new entities
    trust_decay_rate: float = 0.02  # Daily decay rate when no activity
    min_trust_score: float = 0.0
    max_trust_score: float = 1.0
    
    # Score calculation settings
    smoothing_factor: float = 0.1  # For exponential smoothing
    confidence_threshold: float = 0.6  # Minimum confidence for score updates
    score_update_frequency_minutes: int = 5
    
    # Caching and performance
    cache_ttl_seconds: int = 300  # 5 minutes
    batch_processing_size: int = 100
    max_historical_data_days: int = 90
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        self.validate_weights()
        self.validate_parameters()
    
    def validate_weights(self):
        """Validate that factor weights are reasonable."""
        total_weight = sum(self.factor_weights.values())
        if not 0.95 <= total_weight <= 1.05:  # Allow small rounding differences
            raise ValueError(f"Factor weights must sum to ~1.0, got {total_weight}")
        
        for factor_type, weight in self.factor_weights.items():
            if not 0.0 <= weight <= 1.0:
                raise ValueError(f"Weight for {factor_type} must be 0.0-1.0, got {weight}")
    
    def validate_parameters(self):
        """Validate parameter ranges."""
        if not 0.0 <= self.base_trust_score <= 1.0:
            raise ValueError("base_trust_score must be between 0.0 and 1.0")
        
        if not 0.0 <= self.trust_decay_rate <= 1.0:
            raise ValueError("trust_decay_rate must be between 0.0 and 1.0")
        
        if self.min_trust_score >= self.max_trust_score:
            raise ValueError("min_trust_score must be less than max_trust_score")
    
    def get_trust_level_thresholds(self) -> Dict[TrustLevel, tuple]:
        """Get trust level thresholds for score classification."""
        return {
            TrustLevel.UNTRUSTED: (0.0, 0.2),
            TrustLevel.LOW: (0.2, 0.4),
            TrustLevel.MEDIUM: (0.4, 0.6), 
            TrustLevel.HIGH: (0.6, 0.8),
            TrustLevel.TRUSTED: (0.8, 1.0)
        }
    
    def classify_trust_level(self, score: float) -> TrustLevel:
        """Classify a trust score into a trust level."""
        thresholds = self.get_trust_level_thresholds()
        
        for level, (min_score, max_score) in thresholds.items():
            if min_score <= score < max_score:
                return level
        
        # Handle edge case for perfect score
        if score == 1.0:
            return TrustLevel.TRUSTED
        
        return TrustLevel.UNTRUSTED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization."""
        return {
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "tenant_id": self.tenant_id,
            "factor_weights": {k.value: v for k, v in self.factor_weights.items()},
            "base_trust_score": self.base_trust_score,
            "trust_decay_rate": self.trust_decay_rate,
            "min_trust_score": self.min_trust_score,
            "max_trust_score": self.max_trust_score,
            "smoothing_factor": self.smoothing_factor,
            "confidence_threshold": self.confidence_threshold,
            "score_update_frequency_minutes": self.score_update_frequency_minutes,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "batch_processing_size": self.batch_processing_size,
            "max_historical_data_days": self.max_historical_data_days,
            "trust_level_thresholds": {
                level.value: thresholds for level, thresholds in self.get_trust_level_thresholds().items()
            }
        }


class TrustScoreConfigurationFactory:
    """Factory for creating specialized trust score configurations."""
    
    @staticmethod
    def create_high_security_config() -> TrustScoreConfiguration:
        """Create configuration for high-security environments."""
        config = TrustScoreConfiguration()
        
        # Increase security-critical weights
        config.factor_weights[TrustFactorType.DEVICE_POSTURE] = 0.30
        config.factor_weights[TrustFactorType.AUTHENTICATION] = 0.25
        config.factor_weights[TrustFactorType.NETWORK_CONTEXT] = 0.25
        config.factor_weights[TrustFactorType.USER_BEHAVIOR] = 0.15
        config.factor_weights[TrustFactorType.ACCESS_PATTERNS] = 0.05
        
        # More restrictive baseline settings
        config.base_trust_score = 0.3  # Lower starting trust
        config.trust_decay_rate = 0.05  # Faster decay
        config.confidence_threshold = 0.8  # Higher confidence required
        
        # Stricter device requirements
        config.device_posture.minimum_os_age_days = 30
        config.device_posture.jailbreak_root_detection = -0.80
        
        # More restrictive network policies
        config.network_context.public_wifi_penalty = -0.40
        config.network_context.tor_exit_node_penalty = -1.0
        
        return config
    
    @staticmethod 
    def create_standard_config() -> TrustScoreConfiguration:
        """Create standard configuration for typical enterprise use."""
        return TrustScoreConfiguration()  # Use defaults
    
    @staticmethod
    def create_permissive_config() -> TrustScoreConfiguration:
        """Create permissive configuration for development/testing."""
        config = TrustScoreConfiguration()
        
        # More balanced weights favoring behavior
        config.factor_weights[TrustFactorType.USER_BEHAVIOR] = 0.40
        config.factor_weights[TrustFactorType.DEVICE_POSTURE] = 0.15
        config.factor_weights[TrustFactorType.NETWORK_CONTEXT] = 0.15
        config.factor_weights[TrustFactorType.AUTHENTICATION] = 0.15
        config.factor_weights[TrustFactorType.ACCESS_PATTERNS] = 0.10
        config.factor_weights[TrustFactorType.TEMPORAL] = 0.03
        config.factor_weights[TrustFactorType.GEOSPATIAL] = 0.02
        
        # More lenient settings
        config.base_trust_score = 0.7  # Higher starting trust
        config.trust_decay_rate = 0.01  # Slower decay
        config.confidence_threshold = 0.4  # Lower confidence required
        
        # Reduced penalties
        config.device_posture.jailbreak_root_detection = -0.20
        config.network_context.public_wifi_penalty = -0.10
        config.network_context.tor_exit_node_penalty = -0.30
        
        return config