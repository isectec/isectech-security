"""
Risk scoring and threat assessment for behavioral analysis.

This module provides comprehensive risk assessment capabilities including
threat scoring, impact assessment, and actionable recommendations.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from .anomaly_detection import AnomalyResult
from .baseline import BehavioralBaseline
from .feature_engineering import BehavioralFeatures


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskCategory(str, Enum):
    """Risk categories for classification."""
    INSIDER_THREAT = "insider_threat"
    ACCOUNT_COMPROMISE = "account_compromise"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"
    PERSISTENCE = "persistence"
    POLICY_VIOLATION = "policy_violation"
    UNUSUAL_BEHAVIOR = "unusual_behavior"


class MITREAttackTactic(str, Enum):
    """MITRE ATT&CK tactics for threat classification."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ThreatRiskAssessment:
    """Container for comprehensive threat risk assessment."""
    
    def __init__(self, entity_id: str, entity_type: str):
        self.assessment_id = str(uuid.uuid4())
        self.entity_id = entity_id
        self.entity_type = entity_type
        self.timestamp = datetime.utcnow()
        
        # Risk scoring
        self.risk_score = 0.0  # 0.0 to 1.0
        self.threat_level = ThreatLevel.LOW
        self.confidence_score = 0.0  # 0.0 to 1.0
        
        # Classification
        self.risk_categories: List[RiskCategory] = []
        self.mitre_tactics: List[MITREAttackTactic] = []
        
        # Contributing factors
        self.anomaly_contributions: Dict[str, float] = {}
        self.baseline_deviations: Dict[str, float] = {}
        self.contextual_factors: Dict[str, Any] = {}
        
        # Impact assessment
        self.potential_impact = {
            "data_sensitivity": 0.0,
            "system_criticality": 0.0,
            "business_impact": 0.0,
            "compliance_impact": 0.0
        }
        
        # Recommendations
        self.recommendations: List[Dict[str, Any]] = []
        self.investigation_priority = 0  # 1-10 scale
        self.suggested_actions: List[str] = []
        
        # Tracking
        self.false_positive_likelihood = 0.0
        self.similar_incidents_count = 0
        self.historical_context: Dict[str, Any] = {}
    
    def add_recommendation(self, action: str, priority: int, 
                          rationale: str, automation_ready: bool = False):
        """Add security recommendation."""
        self.recommendations.append({
            "action": action,
            "priority": priority,
            "rationale": rationale,
            "automation_ready": automation_ready,
            "category": "security_action"
        })
    
    def add_investigation_step(self, step: str, priority: int,
                             data_sources: List[str] = None):
        """Add investigation recommendation."""
        self.recommendations.append({
            "action": step,
            "priority": priority,
            "rationale": "Investigation step for anomaly analysis",
            "automation_ready": False,
            "category": "investigation",
            "data_sources": data_sources or []
        })
    
    def to_dict(self) -> Dict:
        """Convert assessment to dictionary for serialization."""
        return {
            "assessment_id": self.assessment_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "timestamp": self.timestamp.isoformat(),
            "risk_score": float(self.risk_score),
            "threat_level": self.threat_level.value,
            "confidence_score": float(self.confidence_score),
            "risk_categories": [cat.value for cat in self.risk_categories],
            "mitre_tactics": [tactic.value for tactic in self.mitre_tactics],
            "anomaly_contributions": {k: float(v) for k, v in self.anomaly_contributions.items()},
            "baseline_deviations": {k: float(v) for k, v in self.baseline_deviations.items()},
            "contextual_factors": self.contextual_factors,
            "potential_impact": {k: float(v) for k, v in self.potential_impact.items()},
            "recommendations": self.recommendations,
            "investigation_priority": self.investigation_priority,
            "suggested_actions": self.suggested_actions,
            "false_positive_likelihood": float(self.false_positive_likelihood),
            "similar_incidents_count": self.similar_incidents_count,
            "historical_context": self.historical_context
        }


class SecurityContextAnalyzer:
    """Analyze security context for risk assessment."""
    
    def __init__(self):
        # Security classification impact weights
        self.classification_weights = {
            "UNCLASSIFIED": 0.1,
            "CONFIDENTIAL": 0.4,
            "SECRET": 0.7,
            "TOP_SECRET": 1.0
        }
        
        # Entity type risk multipliers
        self.entity_risk_multipliers = {
            "user": 1.0,
            "admin_user": 1.5,
            "service_account": 1.2,
            "privileged_user": 1.8,
            "device": 0.8,
            "server": 1.3,
            "database": 1.6,
            "application": 1.1
        }
    
    def analyze_data_sensitivity(self, features: BehavioralFeatures) -> float:
        """Analyze data sensitivity based on access patterns."""
        sensitivity_score = 0.0
        
        # Security classification analysis
        if "highest_classification_accessed" in features.features:
            classification = features.features["highest_classification_accessed"]
            sensitivity_score += self.classification_weights.get(classification, 0.1)
        
        # Classified data ratio
        if "classified_data_ratio" in features.features:
            ratio = features.features["classified_data_ratio"]
            sensitivity_score += ratio * 0.5
        
        # Data volume analysis
        if "total_data_transferred" in features.features:
            data_volume = features.features["total_data_transferred"]
            # Normalize large transfers as higher sensitivity
            if data_volume > 1000000:  # >1MB
                sensitivity_score += 0.3
            elif data_volume > 100000000:  # >100MB
                sensitivity_score += 0.6
        
        return min(sensitivity_score, 1.0)
    
    def analyze_system_criticality(self, features: BehavioralFeatures,
                                 entity_type: str) -> float:
        """Analyze system criticality based on access patterns."""
        criticality_score = 0.0
        
        # Entity type multiplier
        criticality_score += self.entity_risk_multipliers.get(entity_type, 1.0) * 0.3
        
        # Unique systems accessed
        if "unique_applications" in features.features:
            app_count = features.features["unique_applications"]
            # More systems = higher criticality
            criticality_score += min(app_count / 10, 0.4)
        
        # Administrative actions
        if "most_common_action" in features.features:
            action = features.features["most_common_action"].lower()
            admin_actions = {"create", "delete", "update", "modify", "admin", "configure"}
            if any(admin_action in action for admin_action in admin_actions):
                criticality_score += 0.3
        
        return min(criticality_score, 1.0)
    
    def analyze_business_impact(self, features: BehavioralFeatures,
                              time_context: datetime) -> float:
        """Analyze potential business impact."""
        impact_score = 0.0
        
        # Business hours factor
        if "business_hours_ratio" in features.features:
            business_ratio = features.features["business_hours_ratio"]
            impact_score += business_ratio * 0.4
        
        # Time sensitivity (business hours are more critical)
        current_hour = time_context.hour
        if 9 <= current_hour <= 17:  # Business hours
            impact_score += 0.3
        elif 22 <= current_hour or current_hour <= 6:  # Night hours
            impact_score += 0.1
        
        # Success rate (failed activities may indicate attacks)
        if "success_rate" in features.features:
            success_rate = features.features["success_rate"]
            if success_rate < 0.5:  # High failure rate
                impact_score += 0.3
        
        return min(impact_score, 1.0)
    
    def analyze_compliance_impact(self, features: BehavioralFeatures) -> float:
        """Analyze compliance-related impact."""
        compliance_score = 0.0
        
        # Audit-relevant activities
        if "event_count" in features.features:
            event_count = features.features["event_count"]
            # High activity volumes need audit attention
            if event_count > 1000:
                compliance_score += 0.4
        
        # Data export activities
        if "most_common_action" in features.features:
            action = features.features["most_common_action"].lower()
            export_actions = {"export", "download", "copy", "backup"}
            if any(export_action in action for export_action in export_actions):
                compliance_score += 0.5
        
        # Failed authentication attempts
        if "failure_count" in features.features:
            failure_count = features.features["failure_count"]
            if failure_count > 10:
                compliance_score += 0.3
        
        return min(compliance_score, 1.0)


class ThreatClassifier:
    """Classify threats based on behavioral patterns."""
    
    def __init__(self):
        # Pattern definitions for threat classification
        self.threat_patterns = {
            RiskCategory.INSIDER_THREAT: {
                "indicators": [
                    "high_data_transfer_volume",
                    "unusual_resource_access",
                    "off_hours_activity",
                    "multiple_location_access"
                ],
                "mitre_tactics": [
                    MITREAttackTactic.COLLECTION,
                    MITREAttackTactic.EXFILTRATION
                ]
            },
            RiskCategory.ACCOUNT_COMPROMISE: {
                "indicators": [
                    "unusual_login_times",
                    "new_ip_addresses",
                    "failed_authentication_spike",
                    "unusual_user_agent"
                ],
                "mitre_tactics": [
                    MITREAttackTactic.INITIAL_ACCESS,
                    MITREAttackTactic.CREDENTIAL_ACCESS
                ]
            },
            RiskCategory.PRIVILEGE_ESCALATION: {
                "indicators": [
                    "admin_action_increase",
                    "unusual_system_access",
                    "configuration_changes"
                ],
                "mitre_tactics": [
                    MITREAttackTactic.PRIVILEGE_ESCALATION,
                    MITREAttackTactic.PERSISTENCE
                ]
            },
            RiskCategory.DATA_EXFILTRATION: {
                "indicators": [
                    "large_data_transfers",
                    "unusual_export_activities",
                    "external_ip_communication"
                ],
                "mitre_tactics": [
                    MITREAttackTactic.COLLECTION,
                    MITREAttackTactic.EXFILTRATION
                ]
            },
            RiskCategory.LATERAL_MOVEMENT: {
                "indicators": [
                    "multiple_system_access",
                    "network_scanning_patterns",
                    "service_account_usage"
                ],
                "mitre_tactics": [
                    MITREAttackTactic.LATERAL_MOVEMENT,
                    MITREAttackTactic.DISCOVERY
                ]
            }
        }
    
    def classify_threat(self, features: BehavioralFeatures,
                       anomaly_result: AnomalyResult,
                       baseline_deviations: Dict[str, float]) -> Tuple[List[RiskCategory], List[MITREAttackTactic]]:
        """Classify threat based on behavioral patterns."""
        identified_categories = []
        identified_tactics = []
        
        # Analyze each threat category
        for category, pattern_info in self.threat_patterns.items():
            match_score = self._calculate_pattern_match(
                features, anomaly_result, baseline_deviations, pattern_info["indicators"]
            )
            
            if match_score > 0.5:  # Threshold for category match
                identified_categories.append(category)
                identified_tactics.extend(pattern_info["mitre_tactics"])
        
        # Remove duplicate tactics
        identified_tactics = list(set(identified_tactics))
        
        # If no specific categories, use general classification
        if not identified_categories:
            if anomaly_result.anomaly_score > 0.7:
                identified_categories.append(RiskCategory.UNUSUAL_BEHAVIOR)
        
        return identified_categories, identified_tactics
    
    def _calculate_pattern_match(self, features: BehavioralFeatures,
                               anomaly_result: AnomalyResult,
                               baseline_deviations: Dict[str, float],
                               indicators: List[str]) -> float:
        """Calculate how well features match threat pattern indicators."""
        matches = 0
        total_indicators = len(indicators)
        
        for indicator in indicators:
            if self._check_indicator(indicator, features, anomaly_result, baseline_deviations):
                matches += 1
        
        return matches / max(total_indicators, 1)
    
    def _check_indicator(self, indicator: str, features: BehavioralFeatures,
                        anomaly_result: AnomalyResult,
                        baseline_deviations: Dict[str, float]) -> bool:
        """Check if specific threat indicator is present."""
        
        if indicator == "high_data_transfer_volume":
            return features.features.get("total_data_transferred", 0) > 100000000  # >100MB
        
        elif indicator == "unusual_resource_access":
            return baseline_deviations.get("unique_resources", 0) > 0.7
        
        elif indicator == "off_hours_activity":
            return features.features.get("night_activity_ratio", 0) > 0.3
        
        elif indicator == "multiple_location_access":
            return features.features.get("location_changes", 0) > 3
        
        elif indicator == "unusual_login_times":
            return baseline_deviations.get("most_active_hour", 0) > 0.8
        
        elif indicator == "new_ip_addresses":
            return baseline_deviations.get("unique_ips", 0) > 0.6
        
        elif indicator == "failed_authentication_spike":
            return features.features.get("failure_count", 0) > 20
        
        elif indicator == "unusual_user_agent":
            return features.features.get("bot_indicator_score", 0) > 0.5
        
        elif indicator == "admin_action_increase":
            action = features.features.get("most_common_action", "").lower()
            return any(admin in action for admin in ["admin", "create", "delete", "modify"])
        
        elif indicator == "large_data_transfers":
            return features.features.get("max_data_transfer", 0) > 50000000  # >50MB
        
        elif indicator == "external_ip_communication":
            return features.features.get("foreign_ip_ratio", 0) > 0.1
        
        elif indicator == "multiple_system_access":
            return features.features.get("unique_applications", 0) > 5
        
        return False


class RiskScorer:
    """Main risk scoring engine for threat assessment."""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.context_analyzer = SecurityContextAnalyzer()
        self.threat_classifier = ThreatClassifier()
        
        # Risk scoring weights
        self.risk_weights = self.config.get("risk_weights", {
            "anomaly_score": 0.4,
            "impact_assessment": 0.3,
            "threat_classification": 0.2,
            "contextual_factors": 0.1
        })
        
        # Historical data for false positive estimation
        self.historical_assessments: List[ThreatRiskAssessment] = []
        self.false_positive_patterns: Dict[str, float] = {}
    
    def assess_risk(self, entity_id: str, entity_type: str,
                   features: BehavioralFeatures,
                   anomaly_result: AnomalyResult,
                   baseline: Optional[BehavioralBaseline] = None) -> ThreatRiskAssessment:
        """Perform comprehensive risk assessment."""
        
        assessment = ThreatRiskAssessment(entity_id, entity_type)
        
        # Extract baseline deviations
        baseline_deviations = anomaly_result.contributing_features
        assessment.baseline_deviations = baseline_deviations
        assessment.anomaly_contributions = {
            "overall_anomaly_score": anomaly_result.anomaly_score,
            "anomaly_confidence": anomaly_result.confidence,
            "detection_method": anomaly_result.detection_method
        }
        
        # Analyze security context and impact
        impact_analysis = self._analyze_impact(features, entity_type)
        assessment.potential_impact = impact_analysis
        
        # Classify threat
        risk_categories, mitre_tactics = self.threat_classifier.classify_threat(
            features, anomaly_result, baseline_deviations
        )
        assessment.risk_categories = risk_categories
        assessment.mitre_tactics = mitre_tactics
        
        # Calculate overall risk score
        assessment.risk_score = self._calculate_risk_score(
            anomaly_result, impact_analysis, risk_categories, baseline_deviations
        )
        
        # Determine threat level
        assessment.threat_level = self._determine_threat_level(assessment.risk_score)
        
        # Calculate confidence
        assessment.confidence_score = self._calculate_confidence(
            anomaly_result, impact_analysis, baseline
        )
        
        # Add contextual factors
        assessment.contextual_factors = self._extract_contextual_factors(
            features, entity_type, anomaly_result
        )
        
        # Generate recommendations
        self._generate_recommendations(assessment, features, anomaly_result)
        
        # Estimate false positive likelihood
        assessment.false_positive_likelihood = self._estimate_false_positive_likelihood(
            assessment, features
        )
        
        # Set investigation priority
        assessment.investigation_priority = self._calculate_investigation_priority(assessment)
        
        # Store for historical analysis
        self.historical_assessments.append(assessment)
        if len(self.historical_assessments) > 1000:  # Keep recent history
            self.historical_assessments = self.historical_assessments[-500:]
        
        return assessment
    
    def _analyze_impact(self, features: BehavioralFeatures, entity_type: str) -> Dict[str, float]:
        """Analyze potential security impact."""
        return {
            "data_sensitivity": self.context_analyzer.analyze_data_sensitivity(features),
            "system_criticality": self.context_analyzer.analyze_system_criticality(features, entity_type),
            "business_impact": self.context_analyzer.analyze_business_impact(features, datetime.utcnow()),
            "compliance_impact": self.context_analyzer.analyze_compliance_impact(features)
        }
    
    def _calculate_risk_score(self, anomaly_result: AnomalyResult,
                            impact_analysis: Dict[str, float],
                            risk_categories: List[RiskCategory],
                            baseline_deviations: Dict[str, float]) -> float:
        """Calculate overall risk score."""
        
        # Anomaly score component
        anomaly_component = anomaly_result.anomaly_score * self.risk_weights["anomaly_score"]
        
        # Impact assessment component
        avg_impact = np.mean(list(impact_analysis.values()))
        impact_component = avg_impact * self.risk_weights["impact_assessment"]
        
        # Threat classification component
        threat_severity = {
            RiskCategory.CRITICAL: 1.0,
            RiskCategory.INSIDER_THREAT: 0.9,
            RiskCategory.ACCOUNT_COMPROMISE: 0.8,
            RiskCategory.DATA_EXFILTRATION: 0.85,
            RiskCategory.PRIVILEGE_ESCALATION: 0.8,
            RiskCategory.LATERAL_MOVEMENT: 0.7,
            RiskCategory.POLICY_VIOLATION: 0.6,
            RiskCategory.UNUSUAL_BEHAVIOR: 0.5
        }
        
        max_threat_score = max([threat_severity.get(cat, 0.5) for cat in risk_categories], default=0.5)
        threat_component = max_threat_score * self.risk_weights["threat_classification"]
        
        # Contextual factors component
        significant_deviations = sum(1 for score in baseline_deviations.values() if score > 0.7)
        contextual_factor = min(significant_deviations / max(len(baseline_deviations), 1), 1.0)
        contextual_component = contextual_factor * self.risk_weights["contextual_factors"]
        
        # Combine components
        total_score = anomaly_component + impact_component + threat_component + contextual_component
        
        return min(total_score, 1.0)
    
    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Determine threat level based on risk score."""
        if risk_score >= 0.8:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.6:
            return ThreatLevel.HIGH
        elif risk_score >= 0.4:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def _calculate_confidence(self, anomaly_result: AnomalyResult,
                            impact_analysis: Dict[str, float],
                            baseline: Optional[BehavioralBaseline]) -> float:
        """Calculate confidence in risk assessment."""
        confidence_factors = []
        
        # Anomaly detection confidence
        confidence_factors.append(anomaly_result.confidence)
        
        # Baseline quality
        if baseline:
            confidence_factors.append(baseline.confidence_score)
        else:
            confidence_factors.append(0.3)  # Lower confidence without baseline
        
        # Impact analysis confidence (based on data availability)
        impact_confidence = sum(1 for score in impact_analysis.values() if score > 0) / len(impact_analysis)
        confidence_factors.append(impact_confidence)
        
        return np.mean(confidence_factors)
    
    def _extract_contextual_factors(self, features: BehavioralFeatures,
                                  entity_type: str,
                                  anomaly_result: AnomalyResult) -> Dict[str, Any]:
        """Extract contextual factors for risk assessment."""
        factors = {
            "entity_type": entity_type,
            "detection_timestamp": datetime.utcnow().isoformat(),
            "feature_extraction_timestamp": features.extraction_timestamp.isoformat(),
            "anomaly_type": anomaly_result.anomaly_type,
            "time_window_hours": features.time_window.total_seconds() / 3600,
        }
        
        # Add relevant behavioral factors
        if "business_hours_ratio" in features.features:
            factors["business_hours_activity"] = features.features["business_hours_ratio"]
        
        if "weekend_ratio" in features.features:
            factors["weekend_activity"] = features.features["weekend_ratio"]
        
        if "unique_locations" in features.features:
            factors["location_diversity"] = features.features["unique_locations"]
        
        return factors
    
    def _generate_recommendations(self, assessment: ThreatRiskAssessment,
                                features: BehavioralFeatures,
                                anomaly_result: AnomalyResult):
        """Generate security recommendations based on assessment."""
        
        # High-level recommendations based on threat level
        if assessment.threat_level == ThreatLevel.CRITICAL:
            assessment.add_recommendation(
                "Immediately investigate and potentially suspend entity access",
                priority=1,
                rationale="Critical threat level requires immediate attention",
                automation_ready=False
            )
            assessment.add_investigation_step(
                "Review all recent activities and access patterns",
                priority=1,
                data_sources=["audit_logs", "access_logs", "network_logs"]
            )
        
        elif assessment.threat_level == ThreatLevel.HIGH:
            assessment.add_recommendation(
                "Escalate to security team for detailed investigation",
                priority=2,
                rationale="High threat level requires security team review",
                automation_ready=False
            )
            assessment.add_investigation_step(
                "Analyze recent behavioral changes and access patterns",
                priority=2,
                data_sources=["audit_logs", "access_logs"]
            )
        
        # Category-specific recommendations
        if RiskCategory.DATA_EXFILTRATION in assessment.risk_categories:
            assessment.add_recommendation(
                "Monitor data transfer activities and implement DLP alerts",
                priority=1,
                rationale="Potential data exfiltration detected",
                automation_ready=True
            )
        
        if RiskCategory.ACCOUNT_COMPROMISE in assessment.risk_categories:
            assessment.add_recommendation(
                "Force password reset and enable additional authentication factors",
                priority=1,
                rationale="Account compromise indicators detected",
                automation_ready=True
            )
        
        if RiskCategory.PRIVILEGE_ESCALATION in assessment.risk_categories:
            assessment.add_recommendation(
                "Review and audit current permissions and recent privilege changes",
                priority=2,
                rationale="Privilege escalation patterns detected",
                automation_ready=False
            )
        
        # Feature-specific recommendations
        if "failure_count" in features.features and features.features["failure_count"] > 20:
            assessment.add_recommendation(
                "Investigate authentication failures and implement account lockout",
                priority=2,
                rationale="High number of authentication failures",
                automation_ready=True
            )
        
        if assessment.potential_impact["data_sensitivity"] > 0.7:
            assessment.add_recommendation(
                "Apply additional monitoring for sensitive data access",
                priority=2,
                rationale="High sensitivity data accessed",
                automation_ready=True
            )
        
        # Set suggested actions
        assessment.suggested_actions = [rec["action"] for rec in assessment.recommendations[:3]]
    
    def _estimate_false_positive_likelihood(self, assessment: ThreatRiskAssessment,
                                          features: BehavioralFeatures) -> float:
        """Estimate likelihood of false positive."""
        fp_factors = []
        
        # Historical false positive rate for similar patterns
        entity_type_fp_rate = self.false_positive_patterns.get(assessment.entity_type, 0.1)
        fp_factors.append(entity_type_fp_rate)
        
        # Time-based factors (off-hours activities often legitimate for certain entities)
        if assessment.entity_type == "service_account":
            night_activity = features.features.get("night_activity_ratio", 0)
            if night_activity > 0.5:
                fp_factors.append(0.3)  # Service accounts often active at night
        
        # Data volume factors
        if "total_data_transferred" in features.features:
            data_volume = features.features["total_data_transferred"]
            if data_volume < 10000:  # Small transfers less likely to be malicious
                fp_factors.append(0.4)
        
        # Success rate factors
        success_rate = features.features.get("success_rate", 1.0)
        if success_rate > 0.95:  # High success rate suggests legitimate activity
            fp_factors.append(0.3)
        
        return min(np.mean(fp_factors), 0.8)  # Cap at 80%
    
    def _calculate_investigation_priority(self, assessment: ThreatRiskAssessment) -> int:
        """Calculate investigation priority (1-10 scale)."""
        priority_score = 0
        
        # Base score from threat level
        threat_level_scores = {
            ThreatLevel.CRITICAL: 8,
            ThreatLevel.HIGH: 6,
            ThreatLevel.MEDIUM: 4,
            ThreatLevel.LOW: 2
        }
        priority_score += threat_level_scores[assessment.threat_level]
        
        # Adjust for confidence
        priority_score += int(assessment.confidence_score * 2)
        
        # Adjust for false positive likelihood
        priority_score -= int(assessment.false_positive_likelihood * 3)
        
        # Adjust for impact
        avg_impact = np.mean(list(assessment.potential_impact.values()))
        priority_score += int(avg_impact * 2)
        
        return max(1, min(priority_score, 10))
    
    def get_risk_trends(self, entity_id: str = None, 
                       time_window: timedelta = timedelta(days=7)) -> Dict[str, Any]:
        """Get risk trends for monitoring."""
        cutoff_time = datetime.utcnow() - time_window
        
        relevant_assessments = [
            assessment for assessment in self.historical_assessments
            if assessment.timestamp >= cutoff_time
            and (entity_id is None or assessment.entity_id == entity_id)
        ]
        
        if not relevant_assessments:
            return {"message": "No assessments in time window"}
        
        # Calculate trends
        risk_scores = [a.risk_score for a in relevant_assessments]
        threat_levels = [a.threat_level.value for a in relevant_assessments]
        
        return {
            "assessment_count": len(relevant_assessments),
            "avg_risk_score": np.mean(risk_scores),
            "max_risk_score": np.max(risk_scores),
            "trend_direction": "increasing" if len(risk_scores) > 1 and risk_scores[-1] > risk_scores[0] else "stable",
            "critical_alerts": sum(1 for level in threat_levels if level == "critical"),
            "high_alerts": sum(1 for level in threat_levels if level == "high"),
            "most_common_categories": self._get_most_common_categories(relevant_assessments),
            "avg_investigation_priority": np.mean([a.investigation_priority for a in relevant_assessments])
        }
    
    def _get_most_common_categories(self, assessments: List[ThreatRiskAssessment]) -> List[str]:
        """Get most common risk categories from assessments."""
        category_counts = defaultdict(int)
        
        for assessment in assessments:
            for category in assessment.risk_categories:
                category_counts[category.value] += 1
        
        # Return top 3 categories
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        return [category for category, count in sorted_categories[:3]]
    
    def update_false_positive_patterns(self, entity_type: str, fp_rate: float):
        """Update false positive patterns based on feedback."""
        self.false_positive_patterns[entity_type] = fp_rate