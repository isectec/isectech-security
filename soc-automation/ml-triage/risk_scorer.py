"""
Risk Scorer - Multi-dimensional risk assessment for security alerts

Implements sophisticated risk scoring algorithms that combine multiple risk factors
including threat intelligence, asset criticality, user context, and behavioral patterns.
"""

import asyncio
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import structlog

logger = structlog.get_logger(__name__)

class RiskFactor(Enum):
    """Risk factor categories"""
    THREAT_INTELLIGENCE = "threat_intelligence"
    ASSET_CRITICALITY = "asset_criticality"
    USER_RISK = "user_risk"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    TEMPORAL_PATTERN = "temporal_pattern"
    NETWORK_CONTEXT = "network_context"
    HISTORICAL_PATTERN = "historical_pattern"
    ALERT_QUALITY = "alert_quality"

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result"""
    composite_score: float
    confidence: float
    risk_factors: Dict[str, float]
    contributing_factors: List[str]
    risk_explanation: List[str]
    mitigation_suggestions: List[str]
    assessment_timestamp: str

class RiskScorer:
    """
    Advanced risk scoring engine that evaluates security alerts across
    multiple dimensions to provide comprehensive risk assessments.
    
    Risk factors considered:
    - Threat Intelligence (IOCs, reputation, malware indicators)
    - Asset Criticality (business impact, data sensitivity)
    - User Context (risk profile, behavior patterns, privileges)
    - Behavioral Anomalies (unusual patterns, deviations)
    - Temporal Patterns (time-based risk factors)
    - Network Context (network position, communication patterns)
    - Historical Patterns (alert frequency, incident history)
    - Alert Quality (completeness, reliability)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Risk factor weights (customizable based on environment)
        self.risk_weights = self.config.get('risk_weights', {
            RiskFactor.THREAT_INTELLIGENCE.value: 0.25,
            RiskFactor.ASSET_CRITICALITY.value: 0.20,
            RiskFactor.USER_RISK.value: 0.15,
            RiskFactor.BEHAVIORAL_ANOMALY.value: 0.15,
            RiskFactor.TEMPORAL_PATTERN.value: 0.10,
            RiskFactor.NETWORK_CONTEXT.value: 0.10,
            RiskFactor.HISTORICAL_PATTERN.value: 0.08,
            RiskFactor.ALERT_QUALITY.value: 0.07
        })
        
        # Risk thresholds
        self.risk_thresholds = self.config.get('risk_thresholds', {
            'critical': 0.85,
            'high': 0.65,
            'medium': 0.45,
            'low': 0.25
        })
        
        # Confidence calculation parameters
        self.confidence_factors = self.config.get('confidence_factors', {
            'data_completeness_weight': 0.3,
            'source_reliability_weight': 0.25,
            'enrichment_quality_weight': 0.25,
            'temporal_freshness_weight': 0.2
        })
        
        # Cache for repeated calculations
        self.risk_cache = {}
        self.cache_ttl = self.config.get('cache_ttl', 300)  # 5 minutes
        
        # Behavioral baselines (would be populated from historical data)
        self.behavioral_baselines = self._initialize_baselines()
        
        logger.info("RiskScorer initialized",
                   risk_weights=self.risk_weights,
                   risk_thresholds=self.risk_thresholds)
    
    async def initialize(self):
        """Initialize risk scorer"""
        # Load historical baselines, threat intelligence feeds, etc.
        logger.info("Risk scorer initialized")
    
    async def calculate_risk_score(
        self, 
        enriched_alert: Dict[str, Any],
        features: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for an alert
        
        Args:
            enriched_alert: Alert with enrichment data
            features: Extracted features (optional)
            
        Returns:
            Risk assessment dictionary
        """
        try:
            alert_id = enriched_alert.get('alert_id', 'unknown')
            assessment_start = datetime.now(timezone.utc)
            
            # Calculate individual risk factors
            risk_factors = {}
            explanations = []
            contributing_factors = []
            
            # Threat Intelligence Risk
            ti_risk, ti_explanation = await self._calculate_threat_intelligence_risk(enriched_alert)
            risk_factors[RiskFactor.THREAT_INTELLIGENCE.value] = ti_risk
            if ti_explanation:
                explanations.extend(ti_explanation)
                if ti_risk > 0.5:
                    contributing_factors.append("High threat intelligence risk")
            
            # Asset Criticality Risk  
            asset_risk, asset_explanation = await self._calculate_asset_criticality_risk(enriched_alert)
            risk_factors[RiskFactor.ASSET_CRITICALITY.value] = asset_risk
            if asset_explanation:
                explanations.extend(asset_explanation)
                if asset_risk > 0.7:
                    contributing_factors.append("Critical asset involved")
            
            # User Risk
            user_risk, user_explanation = await self._calculate_user_risk(enriched_alert)
            risk_factors[RiskFactor.USER_RISK.value] = user_risk
            if user_explanation:
                explanations.extend(user_explanation)
                if user_risk > 0.6:
                    contributing_factors.append("High-risk user involved")
            
            # Behavioral Anomaly Risk
            behavioral_risk, behavioral_explanation = await self._calculate_behavioral_anomaly_risk(enriched_alert, features)
            risk_factors[RiskFactor.BEHAVIORAL_ANOMALY.value] = behavioral_risk
            if behavioral_explanation:
                explanations.extend(behavioral_explanation)
                if behavioral_risk > 0.6:
                    contributing_factors.append("Behavioral anomaly detected")
            
            # Temporal Pattern Risk
            temporal_risk, temporal_explanation = await self._calculate_temporal_pattern_risk(enriched_alert)
            risk_factors[RiskFactor.TEMPORAL_PATTERN.value] = temporal_risk
            if temporal_explanation:
                explanations.extend(temporal_explanation)
                if temporal_risk > 0.5:
                    contributing_factors.append("Suspicious timing pattern")
            
            # Network Context Risk
            network_risk, network_explanation = await self._calculate_network_context_risk(enriched_alert)
            risk_factors[RiskFactor.NETWORK_CONTEXT.value] = network_risk
            if network_explanation:
                explanations.extend(network_explanation)
                if network_risk > 0.5:
                    contributing_factors.append("Suspicious network activity")
            
            # Historical Pattern Risk
            historical_risk, historical_explanation = await self._calculate_historical_pattern_risk(enriched_alert)
            risk_factors[RiskFactor.HISTORICAL_PATTERN.value] = historical_risk
            if historical_explanation:
                explanations.extend(historical_explanation)
                if historical_risk > 0.4:
                    contributing_factors.append("Concerning historical patterns")
            
            # Alert Quality Risk (inverse - higher quality = lower risk)
            quality_risk, quality_explanation = await self._calculate_alert_quality_risk(enriched_alert)
            risk_factors[RiskFactor.ALERT_QUALITY.value] = quality_risk
            if quality_explanation:
                explanations.extend(quality_explanation)
            
            # Calculate composite risk score
            composite_score = self._calculate_composite_score(risk_factors)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(enriched_alert, risk_factors)
            
            # Generate mitigation suggestions
            mitigation_suggestions = self._generate_mitigation_suggestions(risk_factors, enriched_alert)
            
            # Create risk assessment
            risk_assessment = {
                'composite_score': composite_score,
                'confidence': confidence_score,
                'risk_factors': risk_factors,
                'contributing_factors': contributing_factors,
                'risk_explanation': explanations,
                'mitigation_suggestions': mitigation_suggestions,
                'assessment_timestamp': assessment_start.isoformat(),
                'risk_level': self._determine_risk_level(composite_score),
                'processing_time_ms': (datetime.now(timezone.utc) - assessment_start).total_seconds() * 1000
            }
            
            logger.debug("Risk assessment completed",
                        alert_id=alert_id,
                        composite_score=composite_score,
                        confidence=confidence_score,
                        risk_level=risk_assessment['risk_level'])
            
            return risk_assessment
            
        except Exception as e:
            logger.error("Risk score calculation failed",
                        alert_id=enriched_alert.get('alert_id'),
                        error=str(e))
            
            # Return default risk assessment
            return {
                'composite_score': 0.5,
                'confidence': 0.0,
                'risk_factors': {},
                'contributing_factors': ["Risk calculation error"],
                'risk_explanation': ["Unable to calculate risk score"],
                'mitigation_suggestions': ["Manual review required"],
                'assessment_timestamp': datetime.now(timezone.utc).isoformat(),
                'risk_level': 'medium',
                'processing_time_ms': 0
            }
    
    async def _calculate_threat_intelligence_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk from threat intelligence indicators"""
        risk_score = 0.0
        explanations = []
        
        try:
            enrichments = alert.get('enrichments', {})
            
            # Source IP threat intelligence
            source_ti = enrichments.get('threat_intelligence_source', {})
            if source_ti:
                source_score = source_ti.get('reputation_score', 0) / 100.0
                is_malicious = source_ti.get('is_malicious', False)
                
                if is_malicious:
                    risk_score = max(risk_score, 0.9)
                    explanations.append("Source IP flagged as malicious")
                elif source_score > 0.7:
                    risk_score = max(risk_score, source_score * 0.8)
                    explanations.append(f"Source IP has high threat score ({source_score:.2f})")
            
            # Destination IP threat intelligence
            dest_ti = enrichments.get('threat_intelligence_destination', {})
            if dest_ti:
                dest_score = dest_ti.get('reputation_score', 0) / 100.0
                is_malicious = dest_ti.get('is_malicious', False)
                
                if is_malicious:
                    risk_score = max(risk_score, 0.8)  # Slightly lower than source
                    explanations.append("Destination IP flagged as malicious")
                elif dest_score > 0.7:
                    risk_score = max(risk_score, dest_score * 0.7)
                    explanations.append(f"Destination IP has high threat score ({dest_score:.2f})")
            
            # File reputation (if available)
            for key in enrichments:
                if 'file_reputation' in key:
                    file_rep = enrichments[key]
                    if file_rep.get('is_malicious'):
                        risk_score = max(risk_score, 0.95)
                        explanations.append("File flagged as malicious")
                    elif file_rep.get('reputation_score', 0) > 70:
                        risk_score = max(risk_score, 0.8)
                        explanations.append("File has suspicious reputation")
            
            # Domain reputation (if available)
            domain_rep = enrichments.get('domain_reputation', {})
            if domain_rep:
                if domain_rep.get('is_malicious'):
                    risk_score = max(risk_score, 0.85)
                    explanations.append("Domain flagged as malicious")
                elif domain_rep.get('reputation_score', 0) > 70:
                    risk_score = max(risk_score, 0.7)
                    explanations.append("Domain has suspicious reputation")
            
            return min(risk_score, 1.0), explanations
            
        except Exception as e:
            logger.warning("Threat intelligence risk calculation failed", error=str(e))
            return 0.5, ["Threat intelligence analysis unavailable"]
    
    async def _calculate_asset_criticality_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk based on asset criticality and context"""
        risk_score = 0.0
        explanations = []
        
        try:
            asset_info = alert.get('enrichments', {}).get('asset_information', {})
            
            if asset_info:
                # Asset criticality mapping
                criticality = asset_info.get('criticality', 'low').lower()
                criticality_scores = {
                    'critical': 0.9,
                    'high': 0.7,
                    'medium': 0.5,
                    'low': 0.3,
                    'unknown': 0.5
                }
                
                crit_score = criticality_scores.get(criticality, 0.5)
                risk_score = max(risk_score, crit_score)
                
                if criticality in ['critical', 'high']:
                    explanations.append(f"Asset marked as {criticality} criticality")
                
                # Business unit risk
                business_unit = asset_info.get('business_unit', '').lower()
                high_risk_units = ['finance', 'hr', 'executive', 'security', 'legal']
                
                if any(unit in business_unit for unit in high_risk_units):
                    risk_score = max(risk_score, 0.8)
                    explanations.append(f"Asset belongs to high-risk business unit: {business_unit}")
                
                # Compliance status
                compliance = asset_info.get('compliance_status', '').lower()
                if compliance in ['non-compliant', 'partially-compliant']:
                    risk_score = min(risk_score + 0.2, 1.0)
                    explanations.append("Asset has compliance issues")
            
            else:
                # No asset information available - assume medium risk
                risk_score = 0.5
                explanations.append("Asset context unavailable - assuming medium risk")
            
            return risk_score, explanations
            
        except Exception as e:
            logger.warning("Asset criticality risk calculation failed", error=str(e))
            return 0.5, ["Asset risk analysis unavailable"]
    
    async def _calculate_user_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk based on user context and behavior"""
        risk_score = 0.0
        explanations = []
        
        try:
            user_context = alert.get('enrichments', {}).get('user_context', {})
            
            if user_context:
                # User risk score
                user_risk_score = user_context.get('risk_score', 50) / 100.0
                risk_score = max(risk_score, user_risk_score)
                
                if user_risk_score > 0.7:
                    explanations.append(f"User has high risk score ({user_risk_score:.2f})")
                
                # Privileged access
                access_privileges = user_context.get('access_privileges', [])
                if isinstance(access_privileges, list):
                    privileged_roles = ['admin', 'root', 'administrator', 'power_user']
                    has_privileged = any(priv in ' '.join(access_privileges).lower() 
                                       for priv in privileged_roles)
                    
                    if has_privileged:
                        risk_score = min(risk_score + 0.3, 1.0)
                        explanations.append("User has privileged access")
                
                # Department risk assessment
                department = user_context.get('department', '').lower()
                high_privilege_depts = ['it', 'security', 'finance', 'hr', 'executive']
                
                if any(dept in department for dept in high_privilege_depts):
                    risk_score = min(risk_score + 0.2, 1.0)
                    explanations.append(f"User in high-privilege department: {department}")
                
                # Recent activity analysis
                recent_activities = user_context.get('recent_activities', [])
                if isinstance(recent_activities, list) and len(recent_activities) > 10:
                    risk_score = min(risk_score + 0.1, 1.0)
                    explanations.append("User has unusually high recent activity")
            
            else:
                # No user context - check if user field exists in alert
                if alert.get('user'):
                    risk_score = 0.4  # User involved but no context
                    explanations.append("User involved but context unavailable")
                else:
                    risk_score = 0.2  # No user involvement
                    explanations.append("No user involvement detected")
            
            return risk_score, explanations
            
        except Exception as e:
            logger.warning("User risk calculation failed", error=str(e))
            return 0.3, ["User risk analysis unavailable"]
    
    async def _calculate_behavioral_anomaly_risk(
        self, 
        alert: Dict[str, Any], 
        features: Dict[str, Any] = None
    ) -> Tuple[float, List[str]]:
        """Calculate risk based on behavioral anomalies"""
        risk_score = 0.0
        explanations = []
        
        try:
            if not features:
                return 0.3, ["Feature data unavailable for behavioral analysis"]
            
            # Network behavior anomalies
            if features.get('traffic_is_outbound') and features.get('dest_ip_is_external'):
                risk_score = max(risk_score, 0.6)
                explanations.append("Outbound traffic to external destination")
            
            if features.get('is_after_hours') and not features.get('user_has_recent_activity'):
                risk_score = max(risk_score, 0.7)
                explanations.append("After-hours activity without expected user activity")
            
            # Port and protocol anomalies
            if features.get('dest_port_is_privileged') and not features.get('user_has_privileged_access'):
                risk_score = max(risk_score, 0.6)
                explanations.append("Non-privileged user accessing privileged port")
            
            # Frequency anomalies
            if features.get('is_rare_alert') and features.get('severity_is_critical'):
                risk_score = max(risk_score, 0.8)
                explanations.append("Rare critical alert pattern")
            
            if features.get('is_frequent_alert') and features.get('severity_is_high'):
                risk_score = max(risk_score, 0.6)
                explanations.append("High-frequency high-severity alerts")
            
            # Asset vs. user mismatch
            if (features.get('asset_is_critical') and 
                not features.get('user_has_privileged_access')):
                risk_score = max(risk_score, 0.7)
                explanations.append("Non-privileged user accessing critical asset")
            
            # Geographical anomalies (if geolocation available)
            enrichments = alert.get('enrichments', {})
            source_geo = enrichments.get('geolocation_source', {})
            if source_geo:
                country = source_geo.get('country_code', '').upper()
                high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']  # Example list
                
                if country in high_risk_countries:
                    risk_score = max(risk_score, 0.8)
                    explanations.append(f"Connection from high-risk country: {country}")
            
            return min(risk_score, 1.0), explanations
            
        except Exception as e:
            logger.warning("Behavioral anomaly risk calculation failed", error=str(e))
            return 0.3, ["Behavioral anomaly analysis unavailable"]
    
    async def _calculate_temporal_pattern_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk based on temporal patterns"""
        risk_score = 0.0
        explanations = []
        
        try:
            # Parse alert timestamp
            timestamp_str = alert.get('timestamp')
            if timestamp_str:
                if isinstance(timestamp_str, str):
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = timestamp_str
            else:
                return 0.2, ["No timestamp available for temporal analysis"]
            
            # Time-based risk factors
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            # After-hours risk
            if hour < 6 or hour > 22:
                risk_score = max(risk_score, 0.5)
                explanations.append("Alert occurred during after-hours")
            
            # Weekend risk
            if day_of_week >= 5:  # Saturday = 5, Sunday = 6
                risk_score = max(risk_score, 0.4)
                explanations.append("Alert occurred during weekend")
            
            # Holiday risk (simplified - would use actual holiday calendar)
            if day_of_week == 6 or (day_of_week == 4 and hour > 17):  # Sunday or Friday evening
                risk_score = max(risk_score, 0.3)
                explanations.append("Alert occurred during typical holiday time")
            
            # Peak attack times (based on threat intelligence)
            if 2 <= hour <= 4:  # 2-4 AM typical for automated attacks
                risk_score = max(risk_score, 0.6)
                explanations.append("Alert during peak attack hours (2-4 AM)")
            
            # Historical trend analysis
            historical_context = alert.get('enrichments', {}).get('historical_context', {})
            if historical_context:
                trend = historical_context.get('trend', '').lower()
                
                if trend == 'spike':
                    risk_score = max(risk_score, 0.7)
                    explanations.append("Alert frequency shows suspicious spike pattern")
                elif trend == 'increasing':
                    risk_score = max(risk_score, 0.5)
                    explanations.append("Alert frequency is increasing over time")
            
            return risk_score, explanations
            
        except Exception as e:
            logger.warning("Temporal pattern risk calculation failed", error=str(e))
            return 0.3, ["Temporal pattern analysis failed"]
    
    async def _calculate_network_context_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk based on network context"""
        risk_score = 0.0
        explanations = []
        
        try:
            source_ip = alert.get('source_ip')
            dest_ip = alert.get('destination_ip')
            
            if not source_ip and not dest_ip:
                return 0.2, ["No network context available"]
            
            # External to internal traffic
            if source_ip and dest_ip:
                source_private = self._is_private_ip(source_ip)
                dest_private = self._is_private_ip(dest_ip)
                
                if not source_private and dest_private:
                    risk_score = max(risk_score, 0.6)
                    explanations.append("External to internal traffic detected")
                elif source_private and not dest_private:
                    risk_score = max(risk_score, 0.5)
                    explanations.append("Internal to external traffic detected")
                elif not source_private and not dest_private:
                    risk_score = max(risk_score, 0.4)
                    explanations.append("External to external traffic pattern")
            
            # Port-based risk assessment
            dest_port = alert.get('destination_port')
            if dest_port:
                # High-risk ports
                high_risk_ports = [22, 23, 135, 139, 445, 1433, 3389, 5432, 3306]
                if dest_port in high_risk_ports:
                    risk_score = max(risk_score, 0.6)
                    explanations.append(f"Connection to high-risk port: {dest_port}")
                
                # Unusual high ports
                if dest_port > 49152:
                    risk_score = max(risk_score, 0.4)
                    explanations.append("Connection to unusual high port number")
            
            # Protocol-based risk
            protocol = alert.get('protocol', '').lower()
            if protocol in ['icmp', 'gre']:
                risk_score = max(risk_score, 0.5)
                explanations.append(f"Unusual protocol detected: {protocol.upper()}")
            
            # ASN-based risk (if available)
            enrichments = alert.get('enrichments', {})
            for direction in ['source', 'destination']:
                asn_data = enrichments.get(f'asn_{direction}', {})
                if asn_data:
                    org = asn_data.get('organization', '').lower()
                    # Check for hosting providers commonly used for attacks
                    suspicious_orgs = ['bulletproof', 'offshore', 'anonymous']
                    if any(sus_org in org for sus_org in suspicious_orgs):
                        risk_score = max(risk_score, 0.7)
                        explanations.append(f"Connection via suspicious hosting provider: {org}")
            
            return min(risk_score, 1.0), explanations
            
        except Exception as e:
            logger.warning("Network context risk calculation failed", error=str(e))
            return 0.3, ["Network context analysis failed"]
    
    async def _calculate_historical_pattern_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk based on historical patterns"""
        risk_score = 0.0
        explanations = []
        
        try:
            historical_context = alert.get('enrichments', {}).get('historical_context', {})
            
            if not historical_context:
                return 0.3, ["No historical context available"]
            
            # Alert frequency analysis
            similar_24h = historical_context.get('similar_alerts_24h', 0)
            similar_7d = historical_context.get('similar_alerts_7d', 0)
            
            # Very frequent alerts might indicate ongoing campaign
            if similar_24h > 50:
                risk_score = max(risk_score, 0.7)
                explanations.append(f"Very high alert frequency: {similar_24h} in 24h")
            elif similar_24h > 20:
                risk_score = max(risk_score, 0.5)
                explanations.append(f"High alert frequency: {similar_24h} in 24h")
            
            # First-time occurrence
            if similar_7d <= 1:
                risk_score = max(risk_score, 0.4)
                explanations.append("First occurrence or very rare alert type")
            
            # Trend analysis
            trend = historical_context.get('trend', '').lower()
            if trend == 'spike':
                risk_score = max(risk_score, 0.8)
                explanations.append("Alert pattern shows suspicious spike")
            elif trend == 'increasing':
                risk_score = max(risk_score, 0.6)
                explanations.append("Alert frequency is increasing")
            
            # Related incidents
            related_incidents = historical_context.get('related_incidents', [])
            if related_incidents:
                risk_score = max(risk_score, 0.7)
                explanations.append(f"Related to {len(related_incidents)} previous incidents")
            
            # Frequency score
            frequency_score = historical_context.get('frequency_score', 0)
            if frequency_score > 8:
                risk_score = max(risk_score, 0.6)
                explanations.append("High frequency score indicates sustained activity")
            
            return min(risk_score, 1.0), explanations
            
        except Exception as e:
            logger.warning("Historical pattern risk calculation failed", error=str(e))
            return 0.3, ["Historical pattern analysis failed"]
    
    async def _calculate_alert_quality_risk(self, alert: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Calculate risk penalty based on alert quality (lower quality = higher uncertainty)"""
        quality_risk = 0.0
        explanations = []
        
        try:
            # Required field completeness
            required_fields = ['alert_id', 'timestamp', 'source', 'severity', 'alert_type']
            missing_required = sum(1 for field in required_fields if not alert.get(field))
            
            if missing_required > 0:
                quality_risk = missing_required / len(required_fields) * 0.5
                explanations.append(f"Missing {missing_required} required fields")
            
            # Enrichment quality
            enrichment_summary = alert.get('enrichment_summary', {})
            if enrichment_summary:
                success_rate = enrichment_summary.get('successful_enrichments', 0) / max(
                    enrichment_summary.get('total_enrichments', 1), 1
                )
                
                if success_rate < 0.5:
                    quality_risk = max(quality_risk, 0.3)
                    explanations.append(f"Low enrichment success rate: {success_rate:.2f}")
                elif success_rate < 0.8:
                    quality_risk = max(quality_risk, 0.1)
                    explanations.append("Moderate enrichment quality issues")
            
            # Source reliability (based on source type)
            source = alert.get('source', '').lower()
            unreliable_sources = ['syslog', 'generic', 'unknown']
            if any(unreliable in source for unreliable in unreliable_sources):
                quality_risk = max(quality_risk, 0.2)
                explanations.append("Alert from less reliable source type")
            
            # Processing issues
            if alert.get('processing_time_ms', 0) > 5000:  # 5 seconds
                quality_risk = max(quality_risk, 0.1)
                explanations.append("Extended processing time may indicate issues")
            
            return min(quality_risk, 1.0), explanations
            
        except Exception as e:
            logger.warning("Alert quality risk calculation failed", error=str(e))
            return 0.2, ["Alert quality analysis failed"]
    
    def _calculate_composite_score(self, risk_factors: Dict[str, float]) -> float:
        """Calculate weighted composite risk score"""
        try:
            total_weighted_score = 0.0
            total_weight = 0.0
            
            for factor, score in risk_factors.items():
                if factor in self.risk_weights:
                    weight = self.risk_weights[factor]
                    total_weighted_score += score * weight
                    total_weight += weight
            
            # Normalize by total weight
            if total_weight > 0:
                composite_score = total_weighted_score / total_weight
            else:
                composite_score = 0.5  # Default medium risk
            
            return min(1.0, max(0.0, composite_score))
            
        except Exception as e:
            logger.error("Composite score calculation failed", error=str(e))
            return 0.5
    
    def _calculate_confidence_score(self, alert: Dict[str, Any], risk_factors: Dict[str, float]) -> float:
        """Calculate confidence in the risk assessment"""
        try:
            confidence_components = {}
            
            # Data completeness confidence
            required_fields = ['alert_id', 'timestamp', 'source', 'severity', 'alert_type']
            optional_fields = ['description', 'signature', 'source_ip', 'destination_ip', 'user']
            
            required_completeness = sum(1 for field in required_fields if alert.get(field)) / len(required_fields)
            optional_completeness = sum(1 for field in optional_fields if alert.get(field)) / len(optional_fields)
            data_completeness = (required_completeness * 0.7) + (optional_completeness * 0.3)
            
            confidence_components['data_completeness'] = data_completeness
            
            # Source reliability confidence
            source = alert.get('source', '').lower()
            reliable_sources = ['splunk', 'qradar', 'crowdstrike', 'sentinelone']
            source_reliability = 0.9 if any(reliable in source for reliable in reliable_sources) else 0.5
            confidence_components['source_reliability'] = source_reliability
            
            # Enrichment quality confidence
            enrichment_summary = alert.get('enrichment_summary', {})
            if enrichment_summary and enrichment_summary.get('total_enrichments', 0) > 0:
                enrichment_quality = enrichment_summary.get('successful_enrichments', 0) / enrichment_summary.get('total_enrichments', 1)
            else:
                enrichment_quality = 0.3  # Low confidence without enrichment
            confidence_components['enrichment_quality'] = enrichment_quality
            
            # Temporal freshness confidence
            try:
                timestamp_str = alert.get('timestamp')
                if timestamp_str:
                    if isinstance(timestamp_str, str):
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        timestamp = timestamp_str
                    
                    age_hours = (datetime.now(timezone.utc) - timestamp).total_seconds() / 3600
                    temporal_freshness = max(0, 1 - (age_hours / 24))  # Decay over 24 hours
                else:
                    temporal_freshness = 0.5
            except:
                temporal_freshness = 0.5
            
            confidence_components['temporal_freshness'] = temporal_freshness
            
            # Calculate weighted confidence
            total_confidence = 0.0
            for component, score in confidence_components.items():
                if component in self.confidence_factors:
                    weight = self.confidence_factors[component]
                    total_confidence += score * weight
            
            return min(1.0, max(0.0, total_confidence))
            
        except Exception as e:
            logger.error("Confidence calculation failed", error=str(e))
            return 0.5
    
    def _determine_risk_level(self, composite_score: float) -> str:
        """Determine risk level category from composite score"""
        for level in ['critical', 'high', 'medium', 'low']:
            if composite_score >= self.risk_thresholds[level]:
                return level
        return 'informational'
    
    def _generate_mitigation_suggestions(
        self, 
        risk_factors: Dict[str, float], 
        alert: Dict[str, Any]
    ) -> List[str]:
        """Generate contextual mitigation suggestions"""
        suggestions = []
        
        # Threat intelligence based suggestions
        if risk_factors.get(RiskFactor.THREAT_INTELLIGENCE.value, 0) > 0.7:
            suggestions.extend([
                "Block malicious IPs at network perimeter",
                "Update threat intelligence feeds",
                "Isolate affected systems immediately"
            ])
        
        # Asset criticality based suggestions
        if risk_factors.get(RiskFactor.ASSET_CRITICALITY.value, 0) > 0.7:
            suggestions.extend([
                "Implement additional monitoring on critical assets",
                "Review access controls for sensitive systems",
                "Activate incident response team"
            ])
        
        # User risk based suggestions
        if risk_factors.get(RiskFactor.USER_RISK.value, 0) > 0.6:
            suggestions.extend([
                "Review user access permissions",
                "Require additional authentication",
                "Monitor user activity closely"
            ])
        
        # Behavioral anomaly suggestions
        if risk_factors.get(RiskFactor.BEHAVIORAL_ANOMALY.value, 0) > 0.6:
            suggestions.extend([
                "Investigate unusual behavior patterns",
                "Review baseline behavioral profiles",
                "Consider temporary access restrictions"
            ])
        
        # Network context suggestions
        if risk_factors.get(RiskFactor.NETWORK_CONTEXT.value, 0) > 0.5:
            suggestions.extend([
                "Review network segmentation",
                "Implement network access controls",
                "Monitor network traffic patterns"
            ])
        
        return list(set(suggestions))  # Remove duplicates
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is in private range (simplified)"""
        try:
            return (ip_address.startswith('10.') or 
                   ip_address.startswith('192.168.') or 
                   ip_address.startswith('172.') or
                   ip_address.startswith('127.'))
        except:
            return False
    
    def _initialize_baselines(self) -> Dict[str, Any]:
        """Initialize behavioral baselines (would load from historical data)"""
        return {
            'normal_login_hours': (8, 18),
            'typical_ports': [80, 443, 22, 25, 53],
            'common_countries': ['US', 'CA', 'UK', 'DE', 'FR'],
            'baseline_alert_frequency': 10  # alerts per hour
        }
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """Get risk scoring statistics"""
        return {
            'risk_weights': self.risk_weights,
            'risk_thresholds': self.risk_thresholds,
            'confidence_factors': self.confidence_factors,
            'cache_size': len(self.risk_cache),
            'assessments_processed': 0  # Would track in production
        }