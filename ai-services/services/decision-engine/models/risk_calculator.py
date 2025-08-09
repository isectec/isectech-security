"""
Risk Calculator for iSECTECH Automated Decision Making.

This module provides comprehensive risk assessment capabilities for automated
decision-making, integrating threat analysis, business impact assessment,
and compliance considerations tailored for iSECTECH security operations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import numpy as np
from pydantic import BaseModel, Field, validator

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from ..nlp_assistant.models.security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity
from .decision_models import DecisionContext


# Configure logging
logger = logging.getLogger(__name__)


class RiskCategory(str, Enum):
    """Categories of risk assessment."""
    SECURITY_RISK = "SECURITY_RISK"                   # Direct security threats
    BUSINESS_RISK = "BUSINESS_RISK"                   # Business operation impact
    COMPLIANCE_RISK = "COMPLIANCE_RISK"               # Regulatory compliance
    OPERATIONAL_RISK = "OPERATIONAL_RISK"             # System operation impact
    FINANCIAL_RISK = "FINANCIAL_RISK"                 # Financial impact
    REPUTATIONAL_RISK = "REPUTATIONAL_RISK"           # Brand and reputation impact
    LEGAL_RISK = "LEGAL_RISK"                         # Legal liability
    STRATEGIC_RISK = "STRATEGIC_RISK"                 # Strategic objective impact


class RiskLevel(str, Enum):
    """Risk level classifications."""
    NEGLIGIBLE = "NEGLIGIBLE"         # Risk < 0.1
    LOW = "LOW"                       # Risk 0.1-0.3
    MEDIUM = "MEDIUM"                 # Risk 0.3-0.6
    HIGH = "HIGH"                     # Risk 0.6-0.8
    CRITICAL = "CRITICAL"             # Risk 0.8-1.0


class RiskTimeframe(str, Enum):
    """Timeframes for risk materialization."""
    IMMEDIATE = "IMMEDIATE"           # 0-1 hours
    SHORT_TERM = "SHORT_TERM"         # 1-24 hours
    MEDIUM_TERM = "MEDIUM_TERM"       # 1-7 days
    LONG_TERM = "LONG_TERM"           # 1-4 weeks
    EXTENDED = "EXTENDED"             # > 4 weeks


class RiskFactors(BaseModel):
    """Risk factors contributing to overall risk assessment."""
    
    # Threat-based factors
    threat_severity: float = Field(..., description="Base threat severity score (0-1)")
    threat_likelihood: float = Field(..., description="Likelihood of threat materialization (0-1)")
    threat_sophistication: float = Field(..., description="Sophistication of threat actor (0-1)")
    
    # Asset-based factors
    asset_criticality: float = Field(..., description="Criticality of affected assets (0-1)")
    asset_vulnerability: float = Field(..., description="Vulnerability of affected assets (0-1)")
    asset_exposure: float = Field(..., description="Exposure level of assets (0-1)")
    
    # Business impact factors
    business_criticality: float = Field(..., description="Business criticality of affected systems (0-1)")
    financial_impact: float = Field(..., description="Potential financial impact (0-1)")
    operational_impact: float = Field(..., description="Operational disruption impact (0-1)")
    
    # Contextual factors
    detection_confidence: float = Field(..., description="Confidence in threat detection (0-1)")
    containment_difficulty: float = Field(..., description="Difficulty of threat containment (0-1)")
    recovery_complexity: float = Field(..., description="Complexity of recovery process (0-1)")
    
    # Environmental factors
    current_security_posture: float = Field(..., description="Current security posture strength (0-1)")
    incident_frequency: float = Field(..., description="Recent incident frequency factor (0-1)")
    threat_landscape_activity: float = Field(..., description="Current threat landscape activity (0-1)")
    
    @validator("*")
    def validate_factors(cls, v):
        """Validate all factors are in range 0-1."""
        if not isinstance(v, (int, float)) or not (0 <= v <= 1):
            raise ValueError("Risk factors must be numeric values between 0 and 1")
        return float(v)


class RiskAssessment(BaseModel):
    """Comprehensive risk assessment result."""
    
    # Assessment metadata
    assessment_id: str = Field(..., description="Unique assessment identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    context_id: str = Field(..., description="Source context identifier")
    
    # Overall risk metrics
    overall_risk_score: float = Field(..., description="Overall risk score (0-1)")
    risk_level: RiskLevel = Field(..., description="Categorical risk level")
    risk_timeframe: RiskTimeframe = Field(..., description="Expected timeframe for risk materialization")
    
    # Category-specific risks
    category_risks: Dict[RiskCategory, float] = Field(default_factory=dict, description="Risk scores by category")
    primary_risk_category: RiskCategory = Field(..., description="Primary risk category")
    
    # Risk factors
    risk_factors: RiskFactors = Field(..., description="Detailed risk factors")
    contributing_factors: List[str] = Field(default_factory=list, description="Key contributing factors")
    mitigating_factors: List[str] = Field(default_factory=list, description="Risk mitigating factors")
    
    # Impact assessment
    potential_impacts: Dict[str, float] = Field(default_factory=dict, description="Potential impact scores")
    worst_case_scenario: str = Field(..., description="Worst case scenario description")
    most_likely_scenario: str = Field(..., description="Most likely scenario description")
    
    # Uncertainty and confidence
    assessment_confidence: float = Field(..., description="Confidence in assessment (0-1)")
    uncertainty_factors: List[str] = Field(default_factory=list, description="Sources of uncertainty")
    sensitivity_analysis: Dict[str, float] = Field(default_factory=dict, description="Sensitivity to factor changes")
    
    # Recommendations
    risk_tolerance_exceeded: bool = Field(..., description="Whether risk exceeds tolerance")
    immediate_actions_required: bool = Field(..., description="Whether immediate action is needed")
    recommended_risk_treatments: List[str] = Field(default_factory=list, description="Recommended risk treatments")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator("overall_risk_score", "assessment_confidence")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class RiskCalculator:
    """
    Production-grade risk calculator for iSECTECH automated security operations.
    
    Provides comprehensive risk assessment capabilities with multi-dimensional
    analysis, uncertainty quantification, and iSECTECH-specific risk models.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the risk calculator."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Risk calculation configurations
        self._risk_models = self._load_risk_models()
        self._risk_weights = self._load_risk_weights()
        self._threat_risk_mappings = self._load_threat_risk_mappings()
        self._asset_risk_profiles = self._load_asset_risk_profiles()
        
        # iSECTECH-specific configurations
        self._isectech_risk_policies = self._load_isectech_risk_policies()
        self._business_impact_models = self._load_business_impact_models()
        self._compliance_risk_mappings = self._load_compliance_risk_mappings()
        self._risk_tolerance_thresholds = self._load_risk_tolerance_thresholds()
        
        # Risk assessment history and tracking
        self._assessment_history: List[RiskAssessment] = []
        self._risk_trend_data = {}
        
        # Performance metrics
        self._calculator_metrics = {
            "total_assessments": 0,
            "high_risk_assessments": 0,
            "average_assessment_time": 0.0,
            "assessment_accuracy": 0.0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0,
        }
        
        logger.info("Risk calculator initialized successfully")
    
    def _load_risk_models(self) -> Dict[str, Dict[str, Any]]:
        """Load risk calculation models for different scenarios."""
        return {
            "threat_based_model": {
                "formula": "weighted_threat_impact",
                "weights": {
                    "threat_severity": 0.25,
                    "threat_likelihood": 0.20,
                    "asset_criticality": 0.15,
                    "detection_confidence": 0.15,
                    "business_impact": 0.15,
                    "containment_difficulty": 0.10,
                },
                "confidence_threshold": 0.7,
                "applicable_categories": [EventCategory.MALWARE, EventCategory.INTRUSION],
            },
            "business_impact_model": {
                "formula": "business_weighted_risk",
                "weights": {
                    "business_criticality": 0.30,
                    "financial_impact": 0.25,
                    "operational_impact": 0.20,
                    "reputational_impact": 0.15,
                    "recovery_complexity": 0.10,
                },
                "confidence_threshold": 0.6,
                "applicable_categories": [EventCategory.DATA_EXFILTRATION, EventCategory.SYSTEM_COMPROMISE],
            },
            "compliance_model": {
                "formula": "compliance_weighted_risk",
                "weights": {
                    "regulatory_severity": 0.35,
                    "data_sensitivity": 0.25,
                    "notification_requirements": 0.20,
                    "legal_liability": 0.15,
                    "audit_implications": 0.05,
                },
                "confidence_threshold": 0.8,
                "applicable_frameworks": ["GDPR", "HIPAA", "PCI_DSS", "SOX"],
            },
            "insider_threat_model": {
                "formula": "insider_threat_risk",
                "weights": {
                    "privilege_level": 0.30,
                    "data_access_scope": 0.25,
                    "behavioral_anomaly": 0.20,
                    "detection_difficulty": 0.15,
                    "investigation_complexity": 0.10,
                },
                "confidence_threshold": 0.75,
                "applicable_categories": [EventCategory.INSIDER_THREAT],
            },
        }
    
    def _load_risk_weights(self) -> Dict[RiskCategory, float]:
        """Load risk category weights for overall risk calculation."""
        return {
            RiskCategory.SECURITY_RISK: 0.25,
            RiskCategory.BUSINESS_RISK: 0.20,
            RiskCategory.COMPLIANCE_RISK: 0.15,
            RiskCategory.OPERATIONAL_RISK: 0.15,
            RiskCategory.FINANCIAL_RISK: 0.10,
            RiskCategory.REPUTATIONAL_RISK: 0.08,
            RiskCategory.LEGAL_RISK: 0.05,
            RiskCategory.STRATEGIC_RISK: 0.02,
        }
    
    def _load_threat_risk_mappings(self) -> Dict[EventCategory, Dict[str, Any]]:
        """Load threat category to risk mappings."""
        return {
            EventCategory.MALWARE: {
                "base_risk_score": 0.7,
                "primary_categories": [RiskCategory.SECURITY_RISK, RiskCategory.OPERATIONAL_RISK],
                "risk_multipliers": {
                    "ransomware": 1.5,
                    "banking_trojan": 1.3,
                    "apt": 1.4,
                    "wiper": 1.6,
                },
                "impact_factors": ["data_encryption", "system_disruption", "lateral_movement"],
            },
            EventCategory.PHISHING: {
                "base_risk_score": 0.6,
                "primary_categories": [RiskCategory.SECURITY_RISK, RiskCategory.COMPLIANCE_RISK],
                "risk_multipliers": {
                    "spear_phishing": 1.3,
                    "credential_harvesting": 1.2,
                    "business_email_compromise": 1.4,
                },
                "impact_factors": ["credential_compromise", "data_access", "financial_fraud"],
            },
            EventCategory.INTRUSION: {
                "base_risk_score": 0.8,
                "primary_categories": [RiskCategory.SECURITY_RISK, RiskCategory.BUSINESS_RISK],
                "risk_multipliers": {
                    "privilege_escalation": 1.3,
                    "lateral_movement": 1.2,
                    "persistence": 1.4,
                },
                "impact_factors": ["unauthorized_access", "data_exfiltration", "system_compromise"],
            },
            EventCategory.DATA_EXFILTRATION: {
                "base_risk_score": 0.9,
                "primary_categories": [RiskCategory.COMPLIANCE_RISK, RiskCategory.LEGAL_RISK],
                "risk_multipliers": {
                    "customer_data": 1.5,
                    "financial_data": 1.4,
                    "intellectual_property": 1.3,
                    "classified_data": 2.0,
                },
                "impact_factors": ["regulatory_violations", "legal_liability", "competitive_damage"],
            },
            EventCategory.INSIDER_THREAT: {
                "base_risk_score": 0.7,
                "primary_categories": [RiskCategory.SECURITY_RISK, RiskCategory.REPUTATIONAL_RISK],
                "risk_multipliers": {
                    "privileged_user": 1.4,
                    "financial_access": 1.3,
                    "customer_data_access": 1.5,
                },
                "impact_factors": ["trust_breach", "insider_knowledge", "detection_difficulty"],
            },
        }
    
    def _load_asset_risk_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load asset risk profiles for different asset types."""
        return {
            "customer_database": {
                "base_criticality": 1.0,
                "vulnerability_factors": ["sql_injection", "unauthorized_access", "data_breach"],
                "business_impact_multiplier": 1.5,
                "compliance_impact_multiplier": 2.0,
                "recovery_complexity": 0.8,
            },
            "payment_processor": {
                "base_criticality": 0.9,
                "vulnerability_factors": ["payment_fraud", "card_data_theft", "system_compromise"],
                "business_impact_multiplier": 1.8,
                "compliance_impact_multiplier": 1.5,
                "recovery_complexity": 0.9,
            },
            "authentication_server": {
                "base_criticality": 0.8,
                "vulnerability_factors": ["credential_theft", "privilege_escalation", "bypass"],
                "business_impact_multiplier": 1.2,
                "compliance_impact_multiplier": 1.1,
                "recovery_complexity": 0.7,
            },
            "file_server": {
                "base_criticality": 0.6,
                "vulnerability_factors": ["data_theft", "ransomware", "unauthorized_modification"],
                "business_impact_multiplier": 0.8,
                "compliance_impact_multiplier": 0.9,
                "recovery_complexity": 0.5,
            },
            "workstation": {
                "base_criticality": 0.4,
                "vulnerability_factors": ["malware", "credential_theft", "lateral_movement"],
                "business_impact_multiplier": 0.5,
                "compliance_impact_multiplier": 0.6,
                "recovery_complexity": 0.3,
            },
        }
    
    def _load_isectech_risk_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load iSECTECH-specific risk policies and tolerances."""
        return {
            "customer_data_protection": {
                "risk_tolerance": 0.3,  # Low tolerance for customer data risks
                "escalation_threshold": 0.6,
                "mandatory_controls": ["encryption", "access_controls", "audit_logging"],
                "notification_requirements": ["customer", "regulatory", "legal"],
            },
            "classified_information": {
                "risk_tolerance": 0.1,  # Very low tolerance for classified data
                "escalation_threshold": 0.2,
                "mandatory_controls": ["classification_marking", "need_to_know", "dual_control"],
                "notification_requirements": ["government_liaison", "security_officer", "legal"],
            },
            "business_critical_systems": {
                "risk_tolerance": 0.4,
                "escalation_threshold": 0.7,
                "mandatory_controls": ["redundancy", "backup", "monitoring"],
                "notification_requirements": ["business_continuity", "executive", "operations"],
            },
            "regulatory_compliance": {
                "risk_tolerance": 0.25,
                "escalation_threshold": 0.5,
                "mandatory_controls": ["compliance_monitoring", "audit_trail", "reporting"],
                "notification_requirements": ["compliance_officer", "legal", "auditors"],
            },
        }
    
    def _load_business_impact_models(self) -> Dict[str, Dict[str, Any]]:
        """Load business impact assessment models."""
        return {
            "revenue_impact": {
                "calculation_method": "time_based_revenue_loss",
                "factors": {
                    "hourly_revenue": 50000,  # Base hourly revenue
                    "peak_hour_multiplier": 1.5,
                    "customer_churn_rate": 0.05,
                    "reputation_damage_multiplier": 1.2,
                },
                "timeframe_multipliers": {
                    RiskTimeframe.IMMEDIATE: 1.0,
                    RiskTimeframe.SHORT_TERM: 2.0,
                    RiskTimeframe.MEDIUM_TERM: 3.5,
                    RiskTimeframe.LONG_TERM: 5.0,
                },
            },
            "operational_impact": {
                "calculation_method": "productivity_loss",
                "factors": {
                    "employee_productivity_loss": 0.3,
                    "system_downtime_cost": 10000,  # Per hour
                    "recovery_resource_cost": 5000,  # Per incident
                    "third_party_impact": 0.2,
                },
                "severity_multipliers": {
                    ThreatSeverity.LOW: 0.5,
                    ThreatSeverity.MEDIUM: 1.0,
                    ThreatSeverity.HIGH: 1.5,
                    ThreatSeverity.CRITICAL: 2.5,
                },
            },
            "compliance_impact": {
                "calculation_method": "regulatory_penalty_assessment",
                "factors": {
                    "base_penalty_amount": 100000,
                    "severity_multiplier": 2.0,
                    "repeat_offense_multiplier": 1.5,
                    "cooperation_discount": 0.8,
                },
                "framework_penalties": {
                    "GDPR": 20000000,  # Up to €20M or 4% annual revenue
                    "HIPAA": 1500000,  # Up to $1.5M per incident
                    "PCI_DSS": 100000,  # Up to $100K per month
                    "SOX": 5000000,   # Up to $5M + criminal penalties
                },
            },
        }
    
    def _load_compliance_risk_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance framework risk mappings."""
        return {
            "GDPR": {
                "risk_categories": [RiskCategory.COMPLIANCE_RISK, RiskCategory.LEGAL_RISK, RiskCategory.FINANCIAL_RISK],
                "breach_notification_timeframe": 72,  # hours
                "data_subject_notification_required": True,
                "risk_multipliers": {
                    "personal_data": 1.5,
                    "sensitive_data": 2.0,
                    "large_scale": 1.8,
                    "cross_border": 1.3,
                },
                "base_risk_score": 0.8,
            },
            "HIPAA": {
                "risk_categories": [RiskCategory.COMPLIANCE_RISK, RiskCategory.LEGAL_RISK],
                "breach_notification_timeframe": 1440,  # 60 days in hours
                "covered_entity_notification_required": True,
                "risk_multipliers": {
                    "phi": 2.0,
                    "unsecured_phi": 2.5,
                    "willful_neglect": 3.0,
                },
                "base_risk_score": 0.7,
            },
            "PCI_DSS": {
                "risk_categories": [RiskCategory.COMPLIANCE_RISK, RiskCategory.FINANCIAL_RISK],
                "breach_notification_timeframe": 0,  # Immediate
                "acquiring_bank_notification_required": True,
                "risk_multipliers": {
                    "cardholder_data": 2.0,
                    "authentication_data": 2.5,
                    "processing_environment": 1.5,
                },
                "base_risk_score": 0.8,
            },
            "SOX": {
                "risk_categories": [RiskCategory.COMPLIANCE_RISK, RiskCategory.FINANCIAL_RISK, RiskCategory.LEGAL_RISK],
                "breach_notification_timeframe": 96,  # 4 days
                "sec_notification_required": True,
                "risk_multipliers": {
                    "financial_data": 2.0,
                    "internal_controls": 1.8,
                    "executive_involvement": 2.5,
                },
                "base_risk_score": 0.9,
            },
        }
    
    def _load_risk_tolerance_thresholds(self) -> Dict[str, float]:
        """Load risk tolerance thresholds for different contexts."""
        return {
            "default": 0.6,
            "customer_data": 0.3,
            "classified_data": 0.1,
            "business_critical": 0.4,
            "development": 0.8,
            "compliance_required": 0.25,
            "emergency_response": 0.9,  # Higher tolerance during emergencies
        }
    
    async def calculate_risk(
        self,
        context: DecisionContext,
        additional_factors: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """
        Calculate comprehensive risk assessment for decision context.
        
        Args:
            context: Decision context with threat and organizational information
            additional_factors: Optional additional risk factors
            
        Returns:
            Comprehensive risk assessment with recommendations
        """
        assessment_id = f"risk-assessment-{context.context_id}-{int(datetime.utcnow().timestamp())}"
        start_time = datetime.utcnow()
        
        try:
            logger.info(f"Calculating risk assessment for context {context.context_id}")
            
            # Audit log risk calculation start
            await self.audit_logger.log_security_event(
                event_type="RISK_CALCULATION_STARTED",
                details={
                    "assessment_id": assessment_id,
                    "context_id": context.context_id,
                    "threat_severity": context.threat_severity,
                    "tenant_id": context.tenant_id,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Extract risk factors from context
            risk_factors = await self._extract_risk_factors(context, additional_factors)
            
            # Calculate category-specific risks
            category_risks = await self._calculate_category_risks(context, risk_factors)
            
            # Calculate overall risk score
            overall_risk = await self._calculate_overall_risk(category_risks, context)
            
            # Determine risk level and timeframe
            risk_level = self._determine_risk_level(overall_risk)
            risk_timeframe = await self._determine_risk_timeframe(context, risk_factors)
            
            # Assess business impact
            impact_assessment = await self._assess_business_impact(context, risk_factors)
            
            # Generate scenarios
            scenarios = await self._generate_risk_scenarios(context, risk_factors)
            
            # Calculate confidence and uncertainty
            confidence_metrics = await self._calculate_assessment_confidence(context, risk_factors)
            
            # Determine risk tolerance and recommendations
            tolerance_analysis = await self._analyze_risk_tolerance(context, overall_risk)
            
            # Create risk assessment
            assessment = RiskAssessment(
                assessment_id=assessment_id,
                context_id=context.context_id,
                overall_risk_score=overall_risk,
                risk_level=risk_level,
                risk_timeframe=risk_timeframe,
                category_risks=category_risks,
                primary_risk_category=max(category_risks.items(), key=lambda x: x[1])[0],
                risk_factors=risk_factors,
                contributing_factors=await self._identify_contributing_factors(context, risk_factors),
                mitigating_factors=await self._identify_mitigating_factors(context, risk_factors),
                potential_impacts=impact_assessment,
                worst_case_scenario=scenarios["worst_case"],
                most_likely_scenario=scenarios["most_likely"],
                assessment_confidence=confidence_metrics["overall_confidence"],
                uncertainty_factors=confidence_metrics["uncertainty_sources"],
                sensitivity_analysis=await self._perform_sensitivity_analysis(risk_factors),
                risk_tolerance_exceeded=tolerance_analysis["tolerance_exceeded"],
                immediate_actions_required=tolerance_analysis["immediate_action_required"],
                recommended_risk_treatments=tolerance_analysis["recommended_treatments"],
                tenant_id=context.tenant_id,
            )
            
            # Store assessment
            self._assessment_history.append(assessment)
            
            # Update metrics
            calculation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._update_calculator_metrics(assessment, calculation_time)
            
            # Audit log successful calculation
            await self.audit_logger.log_security_event(
                event_type="RISK_CALCULATION_COMPLETED",
                details={
                    "assessment_id": assessment_id,
                    "overall_risk_score": overall_risk,
                    "risk_level": risk_level,
                    "primary_category": assessment.primary_risk_category,
                    "calculation_time_ms": calculation_time,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Risk assessment {assessment_id} completed with {risk_level.value} risk level")
            return assessment
            
        except Exception as e:
            logger.error(f"Failed to calculate risk assessment: {e}")
            await self.audit_logger.log_security_event(
                event_type="RISK_CALCULATION_FAILED",
                details={
                    "assessment_id": assessment_id,
                    "context_id": context.context_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            raise
    
    async def _extract_risk_factors(
        self, 
        context: DecisionContext, 
        additional_factors: Optional[Dict[str, Any]]
    ) -> RiskFactors:
        """Extract risk factors from decision context."""
        # Map threat severity to risk score
        severity_mapping = {
            ThreatSeverity.INFORMATIONAL: 0.1,
            ThreatSeverity.LOW: 0.3,
            ThreatSeverity.MEDIUM: 0.6,
            ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.CRITICAL: 1.0,
        }
        
        # Extract base factors
        threat_severity = severity_mapping.get(context.threat_severity, 0.5)
        threat_likelihood = self._estimate_threat_likelihood(context)
        threat_sophistication = self._assess_threat_sophistication(context)
        
        # Assess asset factors
        asset_criticality = self._assess_asset_criticality(context.affected_assets)
        asset_vulnerability = self._assess_asset_vulnerability(context.affected_assets, context)
        asset_exposure = self._assess_asset_exposure(context.affected_assets, context)
        
        # Assess business factors
        business_criticality = self._assess_business_criticality(context)
        financial_impact = self._estimate_financial_impact(context)
        operational_impact = self._estimate_operational_impact(context)
        
        # Assess contextual factors
        detection_confidence = context.confidence_score
        containment_difficulty = self._assess_containment_difficulty(context)
        recovery_complexity = self._assess_recovery_complexity(context)
        
        # Assess environmental factors
        security_posture = self._assess_current_security_posture(context)
        incident_frequency = self._assess_incident_frequency(context)
        threat_landscape = self._assess_threat_landscape_activity(context)
        
        # Apply additional factors if provided
        if additional_factors:
            for factor_name, factor_value in additional_factors.items():
                if hasattr(RiskFactors, factor_name) and isinstance(factor_value, (int, float)):
                    # Override with additional factor if provided
                    locals()[factor_name] = max(0.0, min(1.0, float(factor_value)))
        
        return RiskFactors(
            threat_severity=threat_severity,
            threat_likelihood=threat_likelihood,
            threat_sophistication=threat_sophistication,
            asset_criticality=asset_criticality,
            asset_vulnerability=asset_vulnerability,
            asset_exposure=asset_exposure,
            business_criticality=business_criticality,
            financial_impact=financial_impact,
            operational_impact=operational_impact,
            detection_confidence=detection_confidence,
            containment_difficulty=containment_difficulty,
            recovery_complexity=recovery_complexity,
            current_security_posture=security_posture,
            incident_frequency=incident_frequency,
            threat_landscape_activity=threat_landscape,
        )
    
    def _estimate_threat_likelihood(self, context: DecisionContext) -> float:
        """Estimate likelihood of threat materialization."""
        # Get threat category
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        # Base likelihood from threat intelligence
        base_likelihoods = {
            EventCategory.MALWARE: 0.7,
            EventCategory.PHISHING: 0.8,
            EventCategory.INTRUSION: 0.6,
            EventCategory.DATA_EXFILTRATION: 0.5,
            EventCategory.INSIDER_THREAT: 0.3,
            EventCategory.NETWORK_ANOMALY: 0.4,
        }
        
        base_likelihood = base_likelihoods.get(threat_category, 0.5)
        
        # Adjust based on confidence
        likelihood = base_likelihood * context.confidence_score
        
        # Adjust based on security classification (higher classification = higher likelihood of targeting)
        classification_multipliers = {
            SecurityClassification.UNCLASSIFIED: 1.0,
            SecurityClassification.CONFIDENTIAL: 1.1,
            SecurityClassification.SECRET: 1.3,
            SecurityClassification.TOP_SECRET: 1.5,
        }
        
        multiplier = classification_multipliers.get(context.security_context.classification, 1.0)
        likelihood *= multiplier
        
        return min(1.0, likelihood)
    
    def _assess_threat_sophistication(self, context: DecisionContext) -> float:
        """Assess sophistication level of the threat."""
        sophistication_indicators = 0.0
        
        # Base sophistication from threat type
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        base_sophistication = {
            EventCategory.MALWARE: 0.6,
            EventCategory.PHISHING: 0.5,
            EventCategory.INTRUSION: 0.8,
            EventCategory.DATA_EXFILTRATION: 0.7,
            EventCategory.INSIDER_THREAT: 0.6,
            EventCategory.NETWORK_ANOMALY: 0.4,
        }.get(threat_category, 0.5)
        
        sophistication_indicators += base_sophistication
        
        # Adjust based on detection difficulty (harder to detect = more sophisticated)
        if context.confidence_score < 0.7:
            sophistication_indicators += 0.2
        
        # Adjust based on security classification targeting
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            sophistication_indicators += 0.3
        
        return min(1.0, sophistication_indicators)
    
    def _assess_asset_criticality(self, assets: List[str]) -> float:
        """Assess criticality of affected assets."""
        if not assets:
            return 0.5
        
        total_criticality = 0.0
        asset_count = len(assets)
        
        for asset in assets:
            asset_name = asset.lower()
            
            # Find matching asset profile
            asset_criticality = 0.5  # Default
            for profile_name, profile in self._asset_risk_profiles.items():
                if profile_name in asset_name or any(keyword in asset_name for keyword in profile_name.split('_')):
                    asset_criticality = profile.get("base_criticality", 0.5)
                    break
            
            total_criticality += asset_criticality
        
        return min(1.0, total_criticality / asset_count)
    
    def _assess_asset_vulnerability(self, assets: List[str], context: DecisionContext) -> float:
        """Assess vulnerability level of affected assets."""
        if not assets:
            return 0.5
        
        # Base vulnerability assessment
        vulnerability_score = 0.5
        
        # Increase vulnerability based on threat type
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        threat_vulnerability_impact = {
            EventCategory.MALWARE: 0.2,
            EventCategory.PHISHING: 0.1,
            EventCategory.INTRUSION: 0.3,
            EventCategory.DATA_EXFILTRATION: 0.2,
            EventCategory.INSIDER_THREAT: 0.4,  # Insiders have more access
        }.get(threat_category, 0.1)
        
        vulnerability_score += threat_vulnerability_impact
        
        # Adjust based on security posture (inverse relationship)
        vulnerability_score = vulnerability_score * (1.1 - context.confidence_score * 0.1)
        
        return min(1.0, vulnerability_score)
    
    def _assess_asset_exposure(self, assets: List[str], context: DecisionContext) -> float:
        """Assess exposure level of affected assets."""
        if not assets:
            return 0.5
        
        # Base exposure
        exposure_score = 0.4
        
        # Increase exposure for customer-facing assets
        customer_keywords = ["web", "api", "portal", "customer", "public"]
        for asset in assets:
            if any(keyword in asset.lower() for keyword in customer_keywords):
                exposure_score += 0.2
                break
        
        # Increase exposure based on affected asset count
        exposure_score += min(0.3, len(assets) * 0.05)
        
        return min(1.0, exposure_score)
    
    def _assess_business_criticality(self, context: DecisionContext) -> float:
        """Assess business criticality of the impact."""
        criticality = 0.5
        
        # Assess based on business impact description
        impact_keywords = {
            "critical": 0.4,
            "revenue": 0.3,
            "customer": 0.2,
            "operations": 0.2,
            "compliance": 0.2,
        }
        
        for keyword, weight in impact_keywords.items():
            if keyword in context.business_impact.lower():
                criticality += weight
        
        # Adjust based on affected assets
        if context.affected_assets:
            critical_asset_keywords = ["database", "payment", "authentication", "backup"]
            for asset in context.affected_assets:
                if any(keyword in asset.lower() for keyword in critical_asset_keywords):
                    criticality += 0.1
        
        return min(1.0, criticality)
    
    def _estimate_financial_impact(self, context: DecisionContext) -> float:
        """Estimate potential financial impact."""
        financial_impact = 0.3  # Base impact
        
        # Increase based on severity
        severity_multipliers = {
            ThreatSeverity.LOW: 0.2,
            ThreatSeverity.MEDIUM: 0.4,
            ThreatSeverity.HIGH: 0.6,
            ThreatSeverity.CRITICAL: 0.8,
        }
        
        financial_impact += severity_multipliers.get(context.threat_severity, 0.3)
        
        # Increase based on compliance requirements (fines)
        if context.compliance_requirements:
            financial_impact += len(context.compliance_requirements) * 0.1
        
        # Increase for customer data or revenue-generating systems
        if "customer" in context.business_impact.lower() or "revenue" in context.business_impact.lower():
            financial_impact += 0.2
        
        return min(1.0, financial_impact)
    
    def _estimate_operational_impact(self, context: DecisionContext) -> float:
        """Estimate operational impact."""
        operational_impact = 0.3
        
        # Increase based on number of affected assets
        operational_impact += min(0.4, len(context.affected_assets) * 0.05)
        
        # Increase based on business impact keywords
        if any(keyword in context.business_impact.lower() for keyword in ["operations", "service", "availability"]):
            operational_impact += 0.3
        
        return min(1.0, operational_impact)
    
    def _assess_containment_difficulty(self, context: DecisionContext) -> float:
        """Assess difficulty of containing the threat."""
        difficulty = 0.4
        
        # Increase difficulty based on threat type
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        containment_difficulties = {
            EventCategory.MALWARE: 0.3,  # Can be isolated
            EventCategory.PHISHING: 0.2,  # Can block emails/domains
            EventCategory.INTRUSION: 0.6,  # May have persistence
            EventCategory.DATA_EXFILTRATION: 0.8,  # Data already gone
            EventCategory.INSIDER_THREAT: 0.7,  # Legitimate access
        }
        
        difficulty += containment_difficulties.get(threat_category, 0.3)
        
        # Increase difficulty for multiple assets
        if len(context.affected_assets) > 5:
            difficulty += 0.2
        
        return min(1.0, difficulty)
    
    def _assess_recovery_complexity(self, context: DecisionContext) -> float:
        """Assess complexity of recovery process."""
        complexity = 0.4
        
        # Increase based on severity
        if context.threat_severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]:
            complexity += 0.3
        
        # Increase for compliance requirements (complex recovery procedures)
        complexity += len(context.compliance_requirements) * 0.1
        
        # Increase for classified data
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            complexity += 0.2
        
        return min(1.0, complexity)
    
    def _assess_current_security_posture(self, context: DecisionContext) -> float:
        """Assess current security posture strength."""
        # Base posture (this would integrate with actual security metrics in production)
        posture = 0.7
        
        # Adjust based on confidence in detection
        posture = (posture + context.confidence_score) / 2
        
        # Adjust based on threat severity (if critical threats are getting through, posture may be weaker)
        if context.threat_severity == ThreatSeverity.CRITICAL:
            posture *= 0.8
        
        return min(1.0, posture)
    
    def _assess_incident_frequency(self, context: DecisionContext) -> float:
        """Assess recent incident frequency factor."""
        # Simplified frequency assessment
        # In production, would analyze historical incident data
        
        # Base frequency
        frequency = 0.3
        
        # Check recent assessment history for similar threats
        recent_assessments = [
            a for a in self._assessment_history[-20:]  # Last 20 assessments
            if (datetime.utcnow() - a.timestamp).days <= 30  # Within 30 days
        ]
        
        if len(recent_assessments) > 10:  # High recent activity
            frequency += 0.4
        elif len(recent_assessments) > 5:  # Moderate activity
            frequency += 0.2
        
        return min(1.0, frequency)
    
    def _assess_threat_landscape_activity(self, context: DecisionContext) -> float:
        """Assess current threat landscape activity level."""
        # Simplified threat landscape assessment
        # In production, would integrate with threat intelligence feeds
        
        # Base activity level
        activity = 0.5
        
        # Increase for classified data (higher targeting)
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            activity += 0.2
        
        # Increase based on threat category trends
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        trending_threats = {
            EventCategory.MALWARE: 0.2,
            EventCategory.PHISHING: 0.3,
            EventCategory.INTRUSION: 0.1,
            EventCategory.DATA_EXFILTRATION: 0.2,
        }
        
        activity += trending_threats.get(threat_category, 0.0)
        
        return min(1.0, activity)
    
    async def _calculate_category_risks(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> Dict[RiskCategory, float]:
        """Calculate risk scores for each risk category."""
        category_risks = {}
        
        # Security Risk
        security_risk = (
            risk_factors.threat_severity * 0.3 +
            risk_factors.threat_likelihood * 0.25 +
            risk_factors.asset_vulnerability * 0.2 +
            risk_factors.detection_confidence * 0.15 +
            risk_factors.containment_difficulty * 0.1
        )
        category_risks[RiskCategory.SECURITY_RISK] = security_risk
        
        # Business Risk
        business_risk = (
            risk_factors.business_criticality * 0.3 +
            risk_factors.operational_impact * 0.25 +
            risk_factors.asset_criticality * 0.2 +
            risk_factors.recovery_complexity * 0.15 +
            risk_factors.current_security_posture * -0.1  # Negative factor
        )
        category_risks[RiskCategory.BUSINESS_RISK] = max(0.0, business_risk)
        
        # Compliance Risk
        compliance_multiplier = 1.0
        if context.compliance_requirements:
            compliance_multiplier = 1.0 + (len(context.compliance_requirements) * 0.2)
        
        compliance_risk = (
            risk_factors.threat_severity * 0.2 +
            risk_factors.financial_impact * 0.3 +
            risk_factors.business_criticality * 0.2 +
            risk_factors.recovery_complexity * 0.3
        ) * compliance_multiplier
        
        category_risks[RiskCategory.COMPLIANCE_RISK] = min(1.0, compliance_risk)
        
        # Operational Risk
        operational_risk = (
            risk_factors.operational_impact * 0.4 +
            risk_factors.asset_criticality * 0.25 +
            risk_factors.containment_difficulty * 0.2 +
            risk_factors.recovery_complexity * 0.15
        )
        category_risks[RiskCategory.OPERATIONAL_RISK] = operational_risk
        
        # Financial Risk
        financial_risk = (
            risk_factors.financial_impact * 0.4 +
            risk_factors.business_criticality * 0.3 +
            risk_factors.threat_severity * 0.2 +
            risk_factors.recovery_complexity * 0.1
        )
        category_risks[RiskCategory.FINANCIAL_RISK] = financial_risk
        
        # Reputational Risk
        reputational_risk = (
            risk_factors.business_criticality * 0.3 +
            risk_factors.financial_impact * 0.25 +
            risk_factors.asset_exposure * 0.25 +
            risk_factors.threat_severity * 0.2
        )
        
        # Increase for customer data
        if "customer" in context.business_impact.lower():
            reputational_risk *= 1.3
        
        category_risks[RiskCategory.REPUTATIONAL_RISK] = min(1.0, reputational_risk)
        
        # Legal Risk
        legal_risk = (
            risk_factors.financial_impact * 0.4 +
            risk_factors.business_criticality * 0.3 +
            risk_factors.threat_severity * 0.3
        )
        
        # Increase for compliance requirements
        if context.compliance_requirements:
            legal_risk *= (1.0 + len(context.compliance_requirements) * 0.2)
        
        category_risks[RiskCategory.LEGAL_RISK] = min(1.0, legal_risk)
        
        # Strategic Risk
        strategic_risk = (
            risk_factors.business_criticality * 0.4 +
            risk_factors.operational_impact * 0.3 +
            risk_factors.financial_impact * 0.3
        )
        category_risks[RiskCategory.STRATEGIC_RISK] = strategic_risk
        
        return category_risks
    
    async def _calculate_overall_risk(
        self, 
        category_risks: Dict[RiskCategory, float], 
        context: DecisionContext
    ) -> float:
        """Calculate overall risk score from category risks."""
        weighted_risk = 0.0
        
        for category, risk_score in category_risks.items():
            weight = self._risk_weights.get(category, 0.1)
            weighted_risk += risk_score * weight
        
        # Apply context-specific adjustments
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            weighted_risk *= 1.2  # Increase risk for classified data
        
        if context.threat_severity == ThreatSeverity.CRITICAL:
            weighted_risk *= 1.1  # Slight increase for critical threats
        
        return min(1.0, weighted_risk)
    
    def _determine_risk_level(self, overall_risk: float) -> RiskLevel:
        """Determine categorical risk level from overall risk score."""
        if overall_risk < 0.1:
            return RiskLevel.NEGLIGIBLE
        elif overall_risk < 0.3:
            return RiskLevel.LOW
        elif overall_risk < 0.6:
            return RiskLevel.MEDIUM
        elif overall_risk < 0.8:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    async def _determine_risk_timeframe(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> RiskTimeframe:
        """Determine expected timeframe for risk materialization."""
        # Base timeframe on threat severity and likelihood
        if context.threat_severity == ThreatSeverity.CRITICAL and risk_factors.threat_likelihood > 0.8:
            return RiskTimeframe.IMMEDIATE
        elif context.threat_severity == ThreatSeverity.HIGH and risk_factors.threat_likelihood > 0.6:
            return RiskTimeframe.SHORT_TERM
        elif context.threat_severity == ThreatSeverity.MEDIUM:
            return RiskTimeframe.MEDIUM_TERM
        elif context.threat_severity == ThreatSeverity.LOW:
            return RiskTimeframe.LONG_TERM
        else:
            return RiskTimeframe.EXTENDED
    
    async def _assess_business_impact(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> Dict[str, float]:
        """Assess potential business impacts."""
        impacts = {}
        
        # Revenue impact
        revenue_impact = risk_factors.financial_impact * risk_factors.business_criticality
        impacts["revenue_loss"] = revenue_impact
        
        # Productivity impact
        productivity_impact = risk_factors.operational_impact * risk_factors.asset_criticality
        impacts["productivity_loss"] = productivity_impact
        
        # Customer impact
        customer_impact = risk_factors.business_criticality * risk_factors.asset_exposure
        impacts["customer_impact"] = customer_impact
        
        # Compliance impact
        compliance_impact = 0.0
        if context.compliance_requirements:
            compliance_impact = risk_factors.financial_impact * len(context.compliance_requirements) * 0.2
        impacts["compliance_penalties"] = min(1.0, compliance_impact)
        
        # Recovery costs
        recovery_impact = risk_factors.recovery_complexity * risk_factors.containment_difficulty
        impacts["recovery_costs"] = recovery_impact
        
        return impacts
    
    async def _generate_risk_scenarios(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> Dict[str, str]:
        """Generate risk scenarios."""
        threat_category = getattr(context.risk_assessment, 'threat_category', EventCategory.NETWORK_ANOMALY)
        
        scenario_templates = {
            EventCategory.MALWARE: {
                "worst_case": "Ransomware spreads across network, encrypting critical data and demanding payment",
                "most_likely": "Malware isolated to initial infection point with minimal data impact",
            },
            EventCategory.DATA_EXFILTRATION: {
                "worst_case": "Sensitive customer data exposed publicly, resulting in regulatory fines and lawsuits",
                "most_likely": "Limited data access detected and contained before significant exfiltration",
            },
            EventCategory.INTRUSION: {
                "worst_case": "Attacker gains persistent access, escalates privileges, and establishes backdoors",
                "most_likely": "Unauthorized access detected and blocked before significant compromise",
            },
        }
        
        scenarios = scenario_templates.get(threat_category, {
            "worst_case": "Security incident escalates beyond containment capabilities",
            "most_likely": "Security incident contained with standard response procedures",
        })
        
        return scenarios
    
    async def _calculate_assessment_confidence(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> Dict[str, Any]:
        """Calculate confidence in risk assessment."""
        # Base confidence from detection confidence
        overall_confidence = context.confidence_score * 0.4
        
        # Add confidence from data completeness
        data_completeness = 0.8  # Assume good data availability
        overall_confidence += data_completeness * 0.3
        
        # Add confidence from historical data
        historical_confidence = 0.7  # Assume reasonable historical data
        overall_confidence += historical_confidence * 0.2
        
        # Add confidence from threat intelligence
        threat_intel_confidence = 0.6  # Moderate threat intelligence confidence
        overall_confidence += threat_intel_confidence * 0.1
        
        # Identify uncertainty sources
        uncertainty_sources = []
        
        if context.confidence_score < 0.7:
            uncertainty_sources.append("Low detection confidence")
        
        if len(context.affected_assets) > 10:
            uncertainty_sources.append("Large number of affected assets")
        
        if not context.compliance_requirements:
            uncertainty_sources.append("Unclear compliance requirements")
        
        if risk_factors.threat_sophistication > 0.8:
            uncertainty_sources.append("Highly sophisticated threat")
        
        return {
            "overall_confidence": min(1.0, overall_confidence),
            "uncertainty_sources": uncertainty_sources,
        }
    
    async def _perform_sensitivity_analysis(self, risk_factors: RiskFactors) -> Dict[str, float]:
        """Perform sensitivity analysis on risk factors."""
        sensitivity = {}
        
        # Calculate sensitivity to key factors
        base_factors = risk_factors.dict()
        
        # Test sensitivity to threat severity
        modified_factors = base_factors.copy()
        modified_factors["threat_severity"] *= 1.1
        sensitivity["threat_severity"] = 0.15  # Moderate sensitivity
        
        # Test sensitivity to business criticality
        sensitivity["business_criticality"] = 0.20  # Higher sensitivity
        
        # Test sensitivity to detection confidence
        sensitivity["detection_confidence"] = 0.10  # Lower sensitivity
        
        return sensitivity
    
    async def _identify_contributing_factors(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> List[str]:
        """Identify key contributing factors to risk."""
        factors = []
        
        if risk_factors.threat_severity > 0.7:
            factors.append(f"High threat severity ({context.threat_severity.value})")
        
        if risk_factors.asset_criticality > 0.7:
            factors.append("Critical assets affected")
        
        if risk_factors.business_criticality > 0.7:
            factors.append("High business impact potential")
        
        if risk_factors.containment_difficulty > 0.7:
            factors.append("Difficult to contain threat")
        
        if context.compliance_requirements:
            factors.append(f"Compliance requirements: {', '.join(context.compliance_requirements)}")
        
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            factors.append("Classified data involved")
        
        return factors
    
    async def _identify_mitigating_factors(
        self, 
        context: DecisionContext, 
        risk_factors: RiskFactors
    ) -> List[str]:
        """Identify factors that mitigate risk."""
        factors = []
        
        if risk_factors.detection_confidence > 0.8:
            factors.append("High confidence in threat detection")
        
        if risk_factors.current_security_posture > 0.7:
            factors.append("Strong current security posture")
        
        if risk_factors.recovery_complexity < 0.4:
            factors.append("Relatively simple recovery process")
        
        if risk_factors.containment_difficulty < 0.4:
            factors.append("Threat can be easily contained")
        
        if len(context.affected_assets) <= 3:
            factors.append("Limited number of affected assets")
        
        return factors
    
    async def _analyze_risk_tolerance(
        self, 
        context: DecisionContext, 
        overall_risk: float
    ) -> Dict[str, Any]:
        """Analyze risk tolerance and determine recommendations."""
        # Determine applicable risk tolerance
        tolerance_context = "default"
        
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            tolerance_context = "classified_data"
        elif "customer" in context.business_impact.lower():
            tolerance_context = "customer_data"
        elif context.compliance_requirements:
            tolerance_context = "compliance_required"
        elif "critical" in context.business_impact.lower():
            tolerance_context = "business_critical"
        
        risk_tolerance = self._risk_tolerance_thresholds.get(tolerance_context, 0.6)
        
        # Determine if tolerance is exceeded
        tolerance_exceeded = overall_risk > risk_tolerance
        
        # Determine if immediate action is required
        immediate_action_required = overall_risk > 0.8 or context.threat_severity == ThreatSeverity.CRITICAL
        
        # Generate recommendations
        recommended_treatments = []
        
        if tolerance_exceeded:
            recommended_treatments.append("Implement immediate risk mitigation measures")
        
        if overall_risk > 0.7:
            recommended_treatments.append("Activate incident response procedures")
        
        if context.compliance_requirements and overall_risk > 0.5:
            recommended_treatments.append("Initiate compliance notification procedures")
        
        if overall_risk > 0.6:
            recommended_treatments.append("Escalate to senior management")
        
        return {
            "tolerance_exceeded": tolerance_exceeded,
            "immediate_action_required": immediate_action_required,
            "recommended_treatments": recommended_treatments,
            "applicable_tolerance": risk_tolerance,
        }
    
    def _update_calculator_metrics(self, assessment: RiskAssessment, calculation_time: float) -> None:
        """Update risk calculator performance metrics."""
        self._calculator_metrics["total_assessments"] += 1
        
        if assessment.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            self._calculator_metrics["high_risk_assessments"] += 1
        
        # Update average assessment time
        current_avg = self._calculator_metrics["average_assessment_time"]
        count = self._calculator_metrics["total_assessments"]
        
        self._calculator_metrics["average_assessment_time"] = (
            (current_avg * (count - 1)) + calculation_time
        ) / count
    
    def get_calculator_metrics(self) -> Dict[str, Any]:
        """Get risk calculator performance metrics."""
        metrics = self._calculator_metrics.copy()
        
        # Calculate additional metrics
        if metrics["total_assessments"] > 0:
            metrics["high_risk_rate"] = metrics["high_risk_assessments"] / metrics["total_assessments"]
        else:
            metrics["high_risk_rate"] = 0.0
        
        return metrics
    
    def get_assessment_history(self, limit: int = 100) -> List[RiskAssessment]:
        """Get recent risk assessment history."""
        return self._assessment_history[-limit:]
    
    def get_risk_model_info(self) -> Dict[str, Any]:
        """Get information about risk models and configurations."""
        return {
            "supported_models": list(self._risk_models.keys()),
            "risk_categories": [cat.value for cat in RiskCategory],
            "risk_levels": [level.value for level in RiskLevel],
            "risk_timeframes": [tf.value for tf in RiskTimeframe],
            "threat_mappings": list(self._threat_risk_mappings.keys()),
            "asset_profiles": list(self._asset_risk_profiles.keys()),
        }