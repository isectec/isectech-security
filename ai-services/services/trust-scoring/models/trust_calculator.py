"""
Trust Score Calculator

This module implements the core trust score calculation algorithm that combines
multiple factors to produce a continuous verification trust score.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import numpy as np
from collections import defaultdict

from .trust_parameters import (
    TrustScoreConfiguration,
    TrustLevel,
    TrustFactorType,
    UserBehaviorParameters,
    DevicePostureParameters, 
    NetworkContextParameters,
    AuthenticationParameters,
    TemporalParameters,
    GeospatialParameters
)

# Import from existing behavioral analysis
from ...behavioral-analysis.models.risk_scoring import ThreatRiskAssessment
from ...behavioral-analysis.models.feature_engineering import BehavioralFeatures


logger = logging.getLogger(__name__)


@dataclass
class TrustFactorScore:
    """Individual trust factor score and metadata."""
    factor_type: TrustFactorType
    score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    weight: float  # Weight used in calculation
    contributing_features: Dict[str, float] = field(default_factory=dict)
    risk_indicators: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate factor score values."""
        if not 0.0 <= self.score <= 1.0:
            raise ValueError(f"Score must be between 0.0 and 1.0, got {self.score}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")


@dataclass
class TrustScoreResult:
    """Complete trust score calculation result."""
    entity_id: str
    entity_type: str
    trust_score: float  # Final calculated trust score (0.0 to 1.0)
    trust_level: TrustLevel
    confidence: float  # Overall confidence in the score
    
    # Factor breakdown
    factor_scores: Dict[TrustFactorType, TrustFactorScore] = field(default_factory=dict)
    
    # Metadata
    calculation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ttl_seconds: int = 300  # Time to live for caching
    
    # Contributing data
    data_sources: List[str] = field(default_factory=list)
    feature_count: int = 0
    anomaly_indicators: List[str] = field(default_factory=list)
    
    # Historical context
    previous_score: Optional[float] = None
    score_trend: Optional[str] = None  # "increasing", "decreasing", "stable"
    score_volatility: float = 0.0  # Measure of score stability
    
    def get_weighted_score(self) -> float:
        """Calculate the final weighted trust score."""
        if not self.factor_scores:
            return 0.0
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        for factor_score in self.factor_scores.values():
            if factor_score.confidence >= 0.1:  # Only use factors with some confidence
                weighted_value = factor_score.score * factor_score.weight * factor_score.confidence
                total_weighted_score += weighted_value
                total_weight += factor_score.weight * factor_score.confidence
        
        if total_weight == 0.0:
            return 0.0
        
        return total_weighted_score / total_weight
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get a summary of risk indicators and concerns."""
        all_risks = []
        high_risk_factors = []
        
        for factor_type, factor_score in self.factor_scores.items():
            if factor_score.score < 0.4:  # Low trust score indicates high risk
                high_risk_factors.append(factor_type.value)
            all_risks.extend(factor_score.risk_indicators)
        
        return {
            "total_risk_indicators": len(all_risks),
            "unique_risks": list(set(all_risks)),
            "high_risk_factors": high_risk_factors,
            "overall_risk_level": "HIGH" if self.trust_score < 0.4 else 
                                "MEDIUM" if self.trust_score < 0.6 else "LOW"
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "calculation_id": self.calculation_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "trust_score": float(self.trust_score),
            "trust_level": self.trust_level.value,
            "confidence": float(self.confidence),
            "timestamp": self.timestamp.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "factor_scores": {
                factor_type.value: {
                    "score": factor_score.score,
                    "confidence": factor_score.confidence,
                    "weight": factor_score.weight,
                    "contributing_features": factor_score.contributing_features,
                    "risk_indicators": factor_score.risk_indicators,
                    "timestamp": factor_score.timestamp.isoformat()
                }
                for factor_type, factor_score in self.factor_scores.items()
            },
            "data_sources": self.data_sources,
            "feature_count": self.feature_count,
            "anomaly_indicators": self.anomaly_indicators,
            "previous_score": self.previous_score,
            "score_trend": self.score_trend,
            "score_volatility": float(self.score_volatility),
            "risk_summary": self.get_risk_summary()
        }


class UserBehaviorCalculator:
    """Calculate user behavior trust factor."""
    
    def __init__(self, params: UserBehaviorParameters):
        self.params = params
        
    def calculate(self, features: BehavioralFeatures, 
                 risk_assessment: Optional[ThreatRiskAssessment] = None) -> TrustFactorScore:
        """Calculate user behavior trust score."""
        
        behavior_scores = {}
        risk_indicators = []
        
        # Login behavior analysis
        if "login_time_variance" in features.features:
            time_consistency = 1.0 - min(features.features["login_time_variance"], 1.0)
            behavior_scores["login_time_consistency"] = time_consistency * self.params.login_time_consistency
            
            if time_consistency < 0.3:
                risk_indicators.append("inconsistent_login_times")
        
        if "unique_locations" in features.features:
            location_count = features.features["unique_locations"]
            location_consistency = max(0.0, 1.0 - (location_count / 10))  # Normalize to 0-1
            behavior_scores["location_consistency"] = location_consistency * self.params.login_location_consistency
            
            if location_count > 5:
                risk_indicators.append("multiple_login_locations")
        
        # Failed login penalty
        if "failure_count" in features.features:
            failure_count = features.features["failure_count"]
            failure_penalty = min(failure_count / 50, 1.0)  # Normalize failures
            behavior_scores["failed_logins"] = failure_penalty * self.params.failed_login_attempts
            
            if failure_count > 10:
                risk_indicators.append("excessive_failed_logins")
        
        # Access pattern analysis
        if "unique_resources" in features.features:
            resource_diversity = min(features.features["unique_resources"] / 20, 1.0)
            behavior_scores["resource_access"] = resource_diversity * self.params.resource_access_pattern
        
        if "privilege_escalation_score" in features.features:
            priv_esc_score = features.features["privilege_escalation_score"]
            behavior_scores["privilege_escalation"] = priv_esc_score * self.params.privilege_escalation_attempts
            
            if priv_esc_score > 0.7:
                risk_indicators.append("privilege_escalation_attempts")
        
        # Data access anomalies
        if "total_data_transferred" in features.features:
            data_volume = features.features["total_data_transferred"]
            if data_volume > 100000000:  # > 100MB
                data_anomaly_score = min(data_volume / 1000000000, 1.0)  # Normalize to GB
                behavior_scores["data_volume_anomaly"] = data_anomaly_score * self.params.data_volume_anomalies
                risk_indicators.append("large_data_transfers")
        
        # Session behavior
        if "avg_session_duration" in features.features:
            session_duration = features.features["avg_session_duration"]
            # Normal session duration is considered 2-8 hours
            if 2 <= session_duration <= 8:
                session_score = 1.0
            else:
                session_score = max(0.0, 1.0 - abs(session_duration - 5) / 10)
            behavior_scores["session_duration"] = session_score * self.params.session_duration_consistency
        
        if "concurrent_sessions" in features.features:
            concurrent = features.features["concurrent_sessions"]
            concurrent_penalty = min(concurrent / 5, 1.0)  # Penalty for too many sessions
            behavior_scores["concurrent_sessions"] = concurrent_penalty * self.params.concurrent_sessions
            
            if concurrent > 3:
                risk_indicators.append("multiple_concurrent_sessions")
        
        # Time-based patterns
        if "business_hours_ratio" in features.features:
            business_ratio = features.features["business_hours_ratio"]
            behavior_scores["business_hours"] = business_ratio * self.params.business_hours_activity
        
        if "night_activity_ratio" in features.features:
            night_ratio = features.features["night_activity_ratio"]
            behavior_scores["night_activity"] = night_ratio * self.params.night_activity
            
            if night_ratio > 0.3:
                risk_indicators.append("excessive_night_activity")
        
        if "weekend_ratio" in features.features:
            weekend_ratio = features.features["weekend_ratio"]
            behavior_scores["weekend_activity"] = weekend_ratio * self.params.weekend_activity
        
        # Calculate final score
        total_score = sum(behavior_scores.values())
        normalized_score = max(0.0, min(1.0, 0.5 + total_score))  # Base 0.5 + adjustments
        
        # Calculate confidence based on available data
        available_features = len([k for k in behavior_scores.keys() if k in features.features])
        expected_features = 10  # Expected number of behavior features
        confidence = min(available_features / expected_features, 1.0)
        
        return TrustFactorScore(
            factor_type=TrustFactorType.USER_BEHAVIOR,
            score=normalized_score,
            confidence=confidence,
            weight=0.25,  # Will be set by main calculator
            contributing_features=behavior_scores,
            risk_indicators=risk_indicators
        )


class DevicePostureCalculator:
    """Calculate device security posture trust factor."""
    
    def __init__(self, params: DevicePostureParameters):
        self.params = params
        
    def calculate(self, device_data: Dict[str, Any]) -> TrustFactorScore:
        """Calculate device posture trust score."""
        
        posture_scores = {}
        risk_indicators = []
        
        # Operating system security
        if "os_patch_level" in device_data:
            patch_age_days = device_data["os_patch_level"]
            if patch_age_days <= self.params.minimum_os_age_days:
                patch_score = 1.0
            else:
                # Decay score based on patch age
                patch_score = max(0.0, 1.0 - (patch_age_days - self.params.minimum_os_age_days) / 365)
            posture_scores["os_patch_level"] = patch_score * self.params.os_patch_level
            
            if patch_age_days > 180:  # 6 months
                risk_indicators.append("outdated_os_patches")
        
        # Security software status
        security_controls = ["antivirus_status", "firewall_enabled", "encryption_status"]
        for control in security_controls:
            if control in device_data:
                enabled = bool(device_data[control])
                weight = getattr(self.params, control)
                posture_scores[control] = (1.0 if enabled else 0.0) * weight
                
                if not enabled:
                    risk_indicators.append(f"{control}_disabled")
        
        # Device registration and compliance
        if "device_registered" in device_data:
            registered = bool(device_data["device_registered"])
            posture_scores["device_registration"] = (1.0 if registered else 0.0) * self.params.device_registration_status
            
            if not registered:
                risk_indicators.append("unregistered_device")
        
        if "compliance_score" in device_data:
            compliance = float(device_data["compliance_score"])
            posture_scores["compliance"] = compliance * self.params.device_compliance_score
            
            if compliance < 0.6:
                risk_indicators.append("device_compliance_issues")
        
        # Critical security violations
        if "jailbroken" in device_data or "rooted" in device_data:
            is_compromised = device_data.get("jailbroken", False) or device_data.get("rooted", False)
            if is_compromised:
                posture_scores["jailbreak_root"] = self.params.jailbreak_root_detection
                risk_indicators.append("device_compromised")
        
        # Hardware security features
        hardware_features = ["tpm_present", "secure_boot_enabled", "biometric_available"]
        for feature in hardware_features:
            if feature in device_data:
                present = bool(device_data[feature])
                weight = getattr(self.params, feature.replace("_present", "_presence").replace("_enabled", "_status").replace("_available", "_capability"))
                posture_scores[feature] = (1.0 if present else 0.0) * weight
        
        # Certificate and code signing
        if "certificate_valid" in device_data:
            cert_valid = bool(device_data["certificate_valid"])
            posture_scores["certificate_validation"] = (1.0 if cert_valid else 0.0) * self.params.certificate_validation
            
            if not cert_valid:
                risk_indicators.append("invalid_certificates")
        
        if "code_signing_verified" in device_data:
            code_verified = bool(device_data["code_signing_verified"])
            posture_scores["code_signing"] = (1.0 if code_verified else 0.0) * self.params.code_signing_verification
            
            if not code_verified:
                risk_indicators.append("unsigned_code_detected")
        
        # Suspicious processes
        if "suspicious_processes_count" in device_data:
            suspicious_count = int(device_data["suspicious_processes_count"])
            if suspicious_count > 0:
                suspicious_penalty = min(suspicious_count / 10, 1.0)
                posture_scores["suspicious_processes"] = suspicious_penalty * self.params.suspicious_processes
                risk_indicators.append("suspicious_processes_detected")
        
        # Calculate final score
        total_score = sum(posture_scores.values())
        normalized_score = max(0.0, min(1.0, 0.5 + total_score))
        
        # Calculate confidence
        available_data = len([k for k in posture_scores.keys() if k in device_data])
        expected_data = 12  # Expected number of device posture indicators
        confidence = min(available_data / expected_data, 1.0)
        
        return TrustFactorScore(
            factor_type=TrustFactorType.DEVICE_POSTURE,
            score=normalized_score,
            confidence=confidence,
            weight=0.20,  # Will be set by main calculator
            contributing_features=posture_scores,
            risk_indicators=risk_indicators
        )


class NetworkContextCalculator:
    """Calculate network context trust factor."""
    
    def __init__(self, params: NetworkContextParameters):
        self.params = params
        
    def calculate(self, network_data: Dict[str, Any]) -> TrustFactorScore:
        """Calculate network context trust score."""
        
        network_scores = {}
        risk_indicators = []
        
        # Location-based analysis
        if "ip_address" in network_data:
            ip_address = network_data["ip_address"]
            
            # Check if IP is in trusted ranges
            if "trusted_ip_ranges" in network_data:
                in_trusted_range = network_data["trusted_ip_ranges"]
                if in_trusted_range:
                    network_scores["known_location"] = self.params.known_location_bonus
                else:
                    risk_indicators.append("untrusted_ip_range")
            
            # Corporate network detection
            if "is_corporate_network" in network_data:
                is_corporate = bool(network_data["is_corporate_network"])
                network_scores["corporate_network"] = (1.0 if is_corporate else 0.0) * self.params.corporate_network_bonus
            
            # VPN usage
            if "vpn_detected" in network_data:
                using_vpn = bool(network_data["vpn_detected"])
                network_scores["vpn_usage"] = (1.0 if using_vpn else 0.0) * self.params.vpn_usage_bonus
            
            # Public WiFi detection
            if "is_public_wifi" in network_data:
                is_public = bool(network_data["is_public_wifi"])
                if is_public:
                    network_scores["public_wifi"] = self.params.public_wifi_penalty
                    risk_indicators.append("public_wifi_usage")
        
        # IP reputation analysis
        if "ip_reputation_score" in network_data:
            reputation = float(network_data["ip_reputation_score"])
            network_scores["ip_reputation"] = reputation * self.params.ip_reputation_score
            
            if reputation < 0.3:
                risk_indicators.append("bad_ip_reputation")
        
        # Geolocation consistency
        if "geolocation_consistent" in network_data:
            geo_consistent = bool(network_data["geolocation_consistent"])
            network_scores["geolocation"] = (1.0 if geo_consistent else 0.0) * self.params.geolocation_consistency
            
            if not geo_consistent:
                risk_indicators.append("inconsistent_geolocation")
        
        # Tor and anonymization detection
        if "tor_exit_node" in network_data:
            is_tor = bool(network_data["tor_exit_node"])
            if is_tor:
                network_scores["tor_usage"] = self.params.tor_exit_node_penalty
                risk_indicators.append("tor_exit_node_detected")
        
        # Suspicious ASN
        if "suspicious_asn" in network_data:
            suspicious_asn = bool(network_data["suspicious_asn"])
            if suspicious_asn:
                network_scores["suspicious_asn"] = self.params.suspicious_asn_penalty
                risk_indicators.append("suspicious_asn_detected")
        
        # Network behavior patterns
        if "bandwidth_usage_anomaly" in network_data:
            bandwidth_anomaly = float(network_data["bandwidth_usage_anomaly"])
            if bandwidth_anomaly > 0.7:
                network_scores["bandwidth_anomaly"] = -bandwidth_anomaly * 0.2
                risk_indicators.append("bandwidth_usage_anomaly")
        
        # Threat intelligence correlation
        if "ioc_matches" in network_data:
            ioc_count = int(network_data["ioc_matches"])
            if ioc_count > 0:
                ioc_penalty = min(ioc_count / 5, 1.0)
                network_scores["ioc_matches"] = ioc_penalty * self.params.ioc_match_penalty
                risk_indicators.append("threat_intelligence_match")
        
        if "threat_feed_score" in network_data:
            threat_score = float(network_data["threat_feed_score"])
            network_scores["threat_correlation"] = threat_score * self.params.threat_feed_correlation
            
            if threat_score < 0.3:
                risk_indicators.append("threat_feed_correlation")
        
        # Calculate final score
        total_score = sum(network_scores.values())
        normalized_score = max(0.0, min(1.0, 0.5 + total_score))
        
        # Calculate confidence
        available_data = len([k for k in network_scores.keys() if k in network_data])
        expected_data = 10  # Expected number of network context indicators
        confidence = min(available_data / expected_data, 1.0)
        
        return TrustFactorScore(
            factor_type=TrustFactorType.NETWORK_CONTEXT,
            score=normalized_score,
            confidence=confidence,
            weight=0.20,  # Will be set by main calculator
            contributing_features=network_scores,
            risk_indicators=risk_indicators
        )


class AuthenticationCalculator:
    """Calculate authentication trust factor."""
    
    def __init__(self, params: AuthenticationParameters):
        self.params = params
        
    def calculate(self, auth_data: Dict[str, Any]) -> TrustFactorScore:
        """Calculate authentication trust score."""
        
        auth_scores = {}
        risk_indicators = []
        
        # MFA analysis
        if "mfa_enabled" in auth_data:
            mfa_enabled = bool(auth_data["mfa_enabled"])
            auth_scores["mfa_enabled"] = (1.0 if mfa_enabled else 0.0) * self.params.mfa_enabled_bonus
            
            if not mfa_enabled:
                risk_indicators.append("mfa_not_enabled")
        
        if "mfa_method" in auth_data:
            mfa_method = auth_data["mfa_method"]
            method_strength = self.params.mfa_method_strength.get(mfa_method, 0.0)
            auth_scores["mfa_method_strength"] = method_strength
        
        # Authentication success patterns
        if "recent_auth_success" in auth_data:
            recent_success = bool(auth_data["recent_auth_success"])
            auth_scores["recent_success"] = (1.0 if recent_success else 0.0) * self.params.recent_auth_success
        
        if "password_age_days" in auth_data:
            password_age = int(auth_data["password_age_days"])
            # Passwords should be neither too old nor too new
            if 30 <= password_age <= 90:
                password_score = 1.0
            elif password_age > 365:
                password_score = 0.0
                risk_indicators.append("password_too_old")
            elif password_age < 1:
                password_score = 0.5  # Very new password might indicate compromise
                risk_indicators.append("password_very_recent")
            else:
                password_score = 0.8
            
            auth_scores["password_age"] = password_score * self.params.password_age_factor
        
        if "credential_strength_score" in auth_data:
            cred_strength = float(auth_data["credential_strength_score"])
            auth_scores["credential_strength"] = cred_strength * self.params.credential_strength
            
            if cred_strength < 0.5:
                risk_indicators.append("weak_credentials")
        
        # Attack indicators
        attack_indicators = [
            ("brute_force_detected", self.params.brute_force_indicators, "brute_force_attack"),
            ("credential_stuffing_detected", self.params.credential_stuffing_indicators, "credential_stuffing"),
            ("password_spray_detected", self.params.password_spray_indicators, "password_spray_attack")
        ]
        
        for indicator, weight, risk_name in attack_indicators:
            if indicator in auth_data and auth_data[indicator]:
                auth_scores[indicator] = weight
                risk_indicators.append(risk_name)
        
        # Session security
        if "session_encrypted" in auth_data:
            encrypted = bool(auth_data["session_encrypted"])
            auth_scores["session_encryption"] = (1.0 if encrypted else 0.0) * self.params.session_encryption
            
            if not encrypted:
                risk_indicators.append("unencrypted_session")
        
        if "secure_cookies" in auth_data:
            secure_cookies = bool(auth_data["secure_cookies"])
            auth_scores["secure_cookies"] = (1.0 if secure_cookies else 0.0) * self.params.secure_cookie_usage
        
        if "csrf_protected" in auth_data:
            csrf_protected = bool(auth_data["csrf_protected"])
            auth_scores["csrf_protection"] = (1.0 if csrf_protected else 0.0) * self.params.csrf_protection
        
        # Calculate final score
        total_score = sum(auth_scores.values())
        normalized_score = max(0.0, min(1.0, 0.5 + total_score))
        
        # Calculate confidence
        available_data = len([k for k in auth_scores.keys() if k in auth_data])
        expected_data = 8  # Expected number of authentication indicators
        confidence = min(available_data / expected_data, 1.0)
        
        return TrustFactorScore(
            factor_type=TrustFactorType.AUTHENTICATION,
            score=normalized_score,
            confidence=confidence,
            weight=0.15,  # Will be set by main calculator
            contributing_features=auth_scores,
            risk_indicators=risk_indicators
        )


class TrustScoreCalculator:
    """Main trust score calculation engine."""
    
    def __init__(self, config: TrustScoreConfiguration):
        self.config = config
        
        # Initialize factor calculators
        self.behavior_calculator = UserBehaviorCalculator(config.user_behavior)
        self.device_calculator = DevicePostureCalculator(config.device_posture)
        self.network_calculator = NetworkContextCalculator(config.network_context)
        self.auth_calculator = AuthenticationCalculator(config.authentication)
        
        # Historical scores for trend analysis
        self.historical_scores: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        
    def calculate_trust_score(self, 
                            entity_id: str,
                            entity_type: str,
                            behavioral_features: Optional[BehavioralFeatures] = None,
                            device_data: Optional[Dict[str, Any]] = None,
                            network_data: Optional[Dict[str, Any]] = None,
                            auth_data: Optional[Dict[str, Any]] = None,
                            risk_assessment: Optional[ThreatRiskAssessment] = None,
                            previous_score: Optional[float] = None) -> TrustScoreResult:
        """Calculate comprehensive trust score for an entity."""
        
        result = TrustScoreResult(
            entity_id=entity_id,
            entity_type=entity_type,
            trust_score=self.config.base_trust_score,
            trust_level=TrustLevel.MEDIUM,
            confidence=0.0,
            previous_score=previous_score
        )
        
        factor_scores = {}
        data_sources = []
        
        # Calculate individual factor scores
        try:
            # User behavior factor
            if behavioral_features is not None:
                behavior_score = self.behavior_calculator.calculate(behavioral_features, risk_assessment)
                behavior_score.weight = self.config.factor_weights[TrustFactorType.USER_BEHAVIOR]
                factor_scores[TrustFactorType.USER_BEHAVIOR] = behavior_score
                data_sources.append("behavioral_analysis")
                result.feature_count += len(behavioral_features.features)
            
            # Device posture factor
            if device_data is not None:
                device_score = self.device_calculator.calculate(device_data)
                device_score.weight = self.config.factor_weights[TrustFactorType.DEVICE_POSTURE]
                factor_scores[TrustFactorType.DEVICE_POSTURE] = device_score
                data_sources.append("device_management")
            
            # Network context factor
            if network_data is not None:
                network_score = self.network_calculator.calculate(network_data)
                network_score.weight = self.config.factor_weights[TrustFactorType.NETWORK_CONTEXT]
                factor_scores[TrustFactorType.NETWORK_CONTEXT] = network_score
                data_sources.append("network_monitoring")
            
            # Authentication factor
            if auth_data is not None:
                auth_score = self.auth_calculator.calculate(auth_data)
                auth_score.weight = self.config.factor_weights[TrustFactorType.AUTHENTICATION]
                factor_scores[TrustFactorType.AUTHENTICATION] = auth_score
                data_sources.append("authentication_service")
            
            # Store factor scores in result
            result.factor_scores = factor_scores
            result.data_sources = data_sources
            
            # Calculate weighted trust score
            if factor_scores:
                weighted_score = result.get_weighted_score()
                
                # Apply smoothing if we have previous score
                if previous_score is not None:
                    smoothed_score = (self.config.smoothing_factor * weighted_score + 
                                    (1 - self.config.smoothing_factor) * previous_score)
                    result.trust_score = smoothed_score
                    result.score_trend = self._calculate_trend(previous_score, smoothed_score)
                else:
                    result.trust_score = weighted_score
                
                # Ensure score is within bounds
                result.trust_score = max(self.config.min_trust_score, 
                                       min(self.config.max_trust_score, result.trust_score))
                
                # Determine trust level
                result.trust_level = self.config.classify_trust_level(result.trust_score)
                
                # Calculate overall confidence
                confidences = [fs.confidence for fs in factor_scores.values() if fs.confidence > 0]
                if confidences:
                    result.confidence = np.mean(confidences)
                
                # Collect anomaly indicators
                all_risks = []
                for factor_score in factor_scores.values():
                    all_risks.extend(factor_score.risk_indicators)
                result.anomaly_indicators = list(set(all_risks))
                
                # Calculate score volatility
                result.score_volatility = self._calculate_volatility(entity_id, result.trust_score)
                
                # Store score for historical analysis
                self._store_historical_score(entity_id, result.trust_score)
                
            else:
                # No factor data available
                result.confidence = 0.0
                result.trust_level = TrustLevel.UNTRUSTED
                logger.warning(f"No trust factor data available for entity {entity_id}")
            
        except Exception as e:
            logger.error(f"Error calculating trust score for {entity_id}: {e}")
            result.trust_score = 0.0
            result.trust_level = TrustLevel.UNTRUSTED
            result.confidence = 0.0
            result.anomaly_indicators.append("calculation_error")
        
        return result
    
    def _calculate_trend(self, previous_score: float, current_score: float) -> str:
        """Calculate score trend direction."""
        diff = current_score - previous_score
        if abs(diff) < 0.05:  # Small changes are considered stable
            return "stable"
        elif diff > 0:
            return "increasing"
        else:
            return "decreasing"
    
    def _calculate_volatility(self, entity_id: str, current_score: float) -> float:
        """Calculate score volatility based on historical data."""
        history = self.historical_scores.get(entity_id, [])
        if len(history) < 3:
            return 0.0
        
        # Get recent scores
        recent_scores = [score for _, score in history[-10:]]  # Last 10 scores
        recent_scores.append(current_score)
        
        # Calculate standard deviation as measure of volatility
        return float(np.std(recent_scores))
    
    def _store_historical_score(self, entity_id: str, score: float):
        """Store score for historical analysis."""
        current_time = datetime.utcnow()
        
        # Add current score
        self.historical_scores[entity_id].append((current_time, score))
        
        # Keep only recent history (limit memory usage)
        cutoff_time = current_time - timedelta(days=self.config.max_historical_data_days)
        self.historical_scores[entity_id] = [
            (ts, s) for ts, s in self.historical_scores[entity_id]
            if ts >= cutoff_time
        ]
    
    def get_trust_trends(self, entity_id: str, days: int = 7) -> Dict[str, Any]:
        """Get trust score trends for an entity."""
        history = self.historical_scores.get(entity_id, [])
        if not history:
            return {"message": "No historical data available"}
        
        cutoff_time = datetime.utcnow() - timedelta(days=days)
        recent_history = [(ts, score) for ts, score in history if ts >= cutoff_time]
        
        if len(recent_history) < 2:
            return {"message": "Insufficient historical data"}
        
        scores = [score for _, score in recent_history]
        times = [ts for ts, _ in recent_history]
        
        return {
            "entity_id": entity_id,
            "time_range_days": days,
            "data_points": len(scores),
            "current_score": scores[-1],
            "min_score": min(scores),
            "max_score": max(scores),
            "avg_score": np.mean(scores),
            "volatility": np.std(scores),
            "trend": "increasing" if scores[-1] > scores[0] else 
                    "decreasing" if scores[-1] < scores[0] else "stable",
            "first_recorded": times[0].isoformat(),
            "last_updated": times[-1].isoformat()
        }