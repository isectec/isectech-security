"""
Threat Explainer for iSECTECH Platform.

This module provides intelligent threat explanation capabilities that convert
complex security events into clear, actionable plain English explanations
tailored for security analysts and stakeholders.
"""

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import torch
from pydantic import BaseModel, Field, validator
from transformers import (
    AutoModelForSeq2SeqLM,
    AutoTokenizer,
    T5ForConditionalGeneration,
    pipeline,
)

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from .security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity


# Configure logging
logger = logging.getLogger(__name__)


class ExplanationStyle(str, Enum):
    """Explanation styles for different audiences."""
    TECHNICAL = "TECHNICAL"           # For security analysts and technical staff
    EXECUTIVE = "EXECUTIVE"           # For executives and management
    ANALYST = "ANALYST"               # For SOC analysts and investigators
    CUSTOMER = "CUSTOMER"             # For customer-facing reports
    COMPLIANCE = "COMPLIANCE"         # For compliance and audit purposes


class ExplanationComplexity(str, Enum):
    """Complexity levels for explanations."""
    SIMPLE = "SIMPLE"                 # Basic, high-level explanation
    DETAILED = "DETAILED"             # Comprehensive technical details
    SUMMARY = "SUMMARY"               # Executive summary format


class ThreatExplanation(BaseModel):
    """Container for threat explanation results."""
    
    # Explanation metadata
    explanation_id: str = Field(..., description="Unique explanation identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_id: str = Field(..., description="Source event identifier")
    
    # Content structure
    title: str = Field(..., description="Clear, concise threat title")
    summary: str = Field(..., description="Executive summary of the threat")
    detailed_explanation: str = Field(..., description="Comprehensive threat explanation")
    
    # Impact assessment
    impact_analysis: str = Field(..., description="Analysis of potential impact")
    business_context: str = Field(..., description="Business context and implications")
    risk_factors: List[str] = Field(default_factory=list, description="Key risk factors identified")
    
    # Technical details
    technical_details: Dict[str, Any] = Field(default_factory=dict, description="Technical analysis")
    indicators_explained: List[Dict[str, str]] = Field(default_factory=list, description="IOC explanations")
    mitre_context: Dict[str, str] = Field(default_factory=dict, description="MITRE ATT&CK context")
    
    # Recommendation sections
    immediate_actions: List[str] = Field(default_factory=list, description="Immediate response actions")
    investigation_steps: List[str] = Field(default_factory=list, description="Recommended investigation steps")
    prevention_measures: List[str] = Field(default_factory=list, description="Prevention recommendations")
    
    # Quality metrics
    confidence_score: float = Field(..., description="Explanation confidence (0-1)")
    completeness_score: float = Field(..., description="Explanation completeness (0-1)")
    clarity_score: float = Field(..., description="Explanation clarity (0-1)")
    
    # Customization
    style: ExplanationStyle = Field(..., description="Explanation style used")
    complexity: ExplanationComplexity = Field(..., description="Complexity level")
    audience_tailored: bool = Field(default=True, description="Whether content is audience-tailored")
    
    @validator("confidence_score", "completeness_score", "clarity_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class ThreatExplainer:
    """
    Production-grade threat explanation engine for iSECTECH.
    
    Converts complex security events and threat intelligence into clear,
    actionable explanations tailored for different audiences and use cases.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the threat explainer."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Model configuration
        self.device = torch.device("cuda" if torch.cuda.is_available() and self.settings.ml.enable_gpu else "cpu")
        self.max_length = self.settings.ml.max_sequence_length
        
        # Generation models
        self._explanation_model = None
        self._explanation_tokenizer = None
        self._summarization_pipeline = None
        self._generation_pipeline = None
        
        # Explanation templates and knowledge base
        self._explanation_templates = self._load_explanation_templates()
        self._threat_knowledge_base = self._load_threat_knowledge_base()
        self._mitigation_database = self._load_mitigation_database()
        self._business_impact_models = self._load_business_impact_models()
        
        # Performance tracking
        self._explanation_metrics = {
            "total_explanations": 0,
            "average_generation_time": 0.0,
            "style_distribution": {},
            "complexity_distribution": {},
        }
        
        # Initialize models
        asyncio.create_task(self._initialize_models())
    
    async def _initialize_models(self) -> None:
        """Initialize NLP models for explanation generation."""
        try:
            logger.info("Initializing threat explanation models...")
            
            # Load T5 model for text generation
            model_name = "t5-base"
            self._explanation_tokenizer = AutoTokenizer.from_pretrained(model_name)
            self._explanation_model = T5ForConditionalGeneration.from_pretrained(model_name).to(self.device)
            
            # Initialize summarization pipeline
            self._summarization_pipeline = pipeline(
                "summarization",
                model="facebook/bart-large-cnn",
                device=0 if self.device.type == "cuda" else -1,
                max_length=150,
                min_length=50,
            )
            
            # Initialize text generation pipeline
            self._generation_pipeline = pipeline(
                "text-generation",
                model="gpt2-medium",
                device=0 if self.device.type == "cuda" else -1,
                max_length=512,
                temperature=0.7,
                do_sample=True,
            )
            
            logger.info("Threat explanation models initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize explanation models: {e}")
            await self.audit_logger.log_security_event(
                event_type="EXPLANATION_MODEL_INIT_FAILED",
                details={"error": str(e)},
                severity="HIGH",
            )
            raise
    
    def _load_explanation_templates(self) -> Dict[str, Dict[str, str]]:
        """Load explanation templates for different styles and complexities."""
        return {
            "TECHNICAL": {
                "SIMPLE": """
                **Security Event Analysis**
                
                Event Type: {event_type}
                Severity: {severity}
                
                **What Happened:**
                {event_summary}
                
                **Technical Details:**
                {technical_details}
                
                **Immediate Actions Required:**
                {immediate_actions}
                """,
                "DETAILED": """
                **Comprehensive Security Analysis**
                
                **Event Classification:**
                - Type: {event_type}
                - Severity: {severity}
                - Confidence: {confidence}%
                
                **Threat Analysis:**
                {detailed_analysis}
                
                **Technical Indicators:**
                {technical_indicators}
                
                **MITRE ATT&CK Mapping:**
                {mitre_mapping}
                
                **Investigation Procedures:**
                {investigation_steps}
                
                **Mitigation Strategies:**
                {mitigation_strategies}
                """,
            },
            "EXECUTIVE": {
                "SUMMARY": """
                **Executive Security Brief**
                
                **Threat Summary:**
                {executive_summary}
                
                **Business Impact:**
                {business_impact}
                
                **Risk Level:** {risk_level}
                
                **Recommended Actions:**
                {executive_actions}
                
                **Resources Required:**
                {resources_needed}
                """,
            },
            "ANALYST": {
                "DETAILED": """
                **SOC Analyst Investigation Guide**
                
                **Alert Details:**
                {alert_details}
                
                **Investigation Workflow:**
                {investigation_workflow}
                
                **Key Evidence to Collect:**
                {evidence_collection}
                
                **Correlation Opportunities:**
                {correlation_points}
                
                **Escalation Criteria:**
                {escalation_criteria}
                """,
            },
        }
    
    def _load_threat_knowledge_base(self) -> Dict[str, Dict[str, Any]]:
        """Load threat intelligence knowledge base."""
        return {
            EventCategory.MALWARE: {
                "description": "Malicious software designed to damage, disrupt, or gain unauthorized access to systems",
                "common_indicators": ["suspicious files", "registry modifications", "network communications"],
                "typical_impacts": ["data theft", "system compromise", "operational disruption"],
                "investigation_focus": ["file analysis", "process monitoring", "network traffic"],
            },
            EventCategory.PHISHING: {
                "description": "Social engineering attack using deceptive communications to steal credentials or install malware",
                "common_indicators": ["suspicious emails", "fake domains", "credential harvesting"],
                "typical_impacts": ["credential compromise", "initial access", "data breach"],
                "investigation_focus": ["email analysis", "user education", "domain reputation"],
            },
            EventCategory.INTRUSION: {
                "description": "Unauthorized access to systems or networks by external or internal actors",
                "common_indicators": ["failed login attempts", "privilege escalation", "lateral movement"],
                "typical_impacts": ["data exfiltration", "system compromise", "persistent access"],
                "investigation_focus": ["access logs", "user behavior", "network analysis"],
            },
            EventCategory.DATA_EXFILTRATION: {
                "description": "Unauthorized transfer or copying of sensitive data from the organization",
                "common_indicators": ["large data transfers", "unusual access patterns", "external communications"],
                "typical_impacts": ["data breach", "regulatory violations", "competitive disadvantage"],
                "investigation_focus": ["data flow analysis", "access controls", "encryption status"],
            },
        }
    
    def _load_mitigation_database(self) -> Dict[str, List[str]]:
        """Load mitigation strategies database."""
        return {
            EventCategory.MALWARE: [
                "Isolate affected systems immediately",
                "Run comprehensive antimalware scans",
                "Update security signatures and definitions",
                "Implement application whitelisting",
                "Enhance email filtering and web protection",
            ],
            EventCategory.PHISHING: [
                "Block malicious domains and URLs",
                "Implement additional email security controls",
                "Conduct user awareness training",
                "Enable multi-factor authentication",
                "Review and update security policies",
            ],
            EventCategory.INTRUSION: [
                "Change all potentially compromised credentials",
                "Implement network segmentation",
                "Enhance monitoring and detection capabilities",
                "Review and update access controls",
                "Conduct thorough system hardening",
            ],
            EventCategory.DATA_EXFILTRATION: [
                "Implement data loss prevention (DLP) controls",
                "Enhance data encryption at rest and in transit",
                "Review and restrict data access permissions",
                "Implement data classification and labeling",
                "Enhance network monitoring for data flows",
            ],
        }
    
    def _load_business_impact_models(self) -> Dict[str, Dict[str, Any]]:
        """Load business impact assessment models."""
        return {
            ThreatSeverity.CRITICAL: {
                "impact_description": "Severe business disruption with potential for significant financial and reputational damage",
                "response_timeline": "Immediate (within 1 hour)",
                "stakeholder_notification": ["CISO", "CEO", "Board", "Legal", "PR"],
                "resource_allocation": "All available resources",
            },
            ThreatSeverity.HIGH: {
                "impact_description": "Significant business impact requiring urgent attention and resources",
                "response_timeline": "Urgent (within 4 hours)",
                "stakeholder_notification": ["CISO", "IT Leadership", "Business Units"],
                "resource_allocation": "Dedicated incident response team",
            },
            ThreatSeverity.MEDIUM: {
                "impact_description": "Moderate business impact requiring timely investigation and response",
                "response_timeline": "Priority (within 24 hours)",
                "stakeholder_notification": ["Security Team", "IT Operations"],
                "resource_allocation": "Standard incident response procedures",
            },
            ThreatSeverity.LOW: {
                "impact_description": "Limited business impact requiring monitoring and standard procedures",
                "response_timeline": "Standard (within 48 hours)",
                "stakeholder_notification": ["Security Operations"],
                "resource_allocation": "Standard monitoring and response",
            },
        }
    
    async def explain_threat(
        self,
        context: SecurityContext,
        processing_result: Optional[Dict[str, Any]] = None,
        style: ExplanationStyle = ExplanationStyle.ANALYST,
        complexity: ExplanationComplexity = ExplanationComplexity.DETAILED,
        customize_for_tenant: bool = True,
    ) -> ThreatExplanation:
        """
        Generate a comprehensive threat explanation.
        
        Args:
            context: Security context containing event details
            processing_result: Optional NLP processing results
            style: Explanation style for target audience
            complexity: Level of detail in explanation
            customize_for_tenant: Whether to customize for specific tenant
            
        Returns:
            Comprehensive threat explanation
        """
        start_time = datetime.utcnow()
        explanation_id = f"explain-{context.event_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Generating threat explanation for event {context.event_id}")
            
            # Audit log the explanation request
            await self.audit_logger.log_security_event(
                event_type="THREAT_EXPLANATION_STARTED",
                details={
                    "event_id": context.event_id,
                    "explanation_id": explanation_id,
                    "style": style,
                    "complexity": complexity,
                    "tenant_id": context.tenant_id,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Determine threat category and severity
            threat_category = self._determine_category(context, processing_result)
            threat_severity = self._determine_severity(context, processing_result)
            
            # Generate explanation components
            title = await self._generate_title(context, threat_category, threat_severity)
            summary = await self._generate_summary(context, threat_category, style)
            detailed_explanation = await self._generate_detailed_explanation(
                context, threat_category, complexity
            )
            
            # Generate impact analysis
            impact_analysis = await self._generate_impact_analysis(
                context, threat_severity, style
            )
            business_context = await self._generate_business_context(
                context, threat_severity, customize_for_tenant
            )
            
            # Extract and explain technical details
            technical_details = await self._generate_technical_details(context, processing_result)
            indicators_explained = await self._explain_indicators(context, processing_result)
            mitre_context = await self._generate_mitre_context(context)
            
            # Generate recommendations
            immediate_actions = await self._generate_immediate_actions(
                threat_category, threat_severity, style
            )
            investigation_steps = await self._generate_investigation_steps(
                context, threat_category, complexity
            )
            prevention_measures = await self._generate_prevention_measures(
                threat_category, style
            )
            
            # Assess explanation quality
            confidence_score = self._assess_confidence(context, processing_result)
            completeness_score = self._assess_completeness(
                context, technical_details, indicators_explained
            )
            clarity_score = self._assess_clarity(detailed_explanation, style)
            
            # Create explanation result
            explanation = ThreatExplanation(
                explanation_id=explanation_id,
                event_id=context.event_id,
                title=title,
                summary=summary,
                detailed_explanation=detailed_explanation,
                impact_analysis=impact_analysis,
                business_context=business_context,
                risk_factors=self._extract_risk_factors(context, threat_category),
                technical_details=technical_details,
                indicators_explained=indicators_explained,
                mitre_context=mitre_context,
                immediate_actions=immediate_actions,
                investigation_steps=investigation_steps,
                prevention_measures=prevention_measures,
                confidence_score=confidence_score,
                completeness_score=completeness_score,
                clarity_score=clarity_score,
                style=style,
                complexity=complexity,
            )
            
            # Update metrics
            self._update_explanation_metrics(style, complexity, start_time)
            
            # Audit log successful explanation
            await self.audit_logger.log_security_event(
                event_type="THREAT_EXPLANATION_COMPLETED",
                details={
                    "explanation_id": explanation_id,
                    "confidence_score": confidence_score,
                    "completeness_score": completeness_score,
                    "generation_time_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Generated threat explanation {explanation_id}")
            return explanation
            
        except Exception as e:
            logger.error(f"Failed to generate threat explanation: {e}")
            await self.audit_logger.log_security_event(
                event_type="THREAT_EXPLANATION_FAILED",
                details={
                    "explanation_id": explanation_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            raise
    
    def _determine_category(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> EventCategory:
        """Determine the threat category from context and processing results."""
        if processing_result and "event_category" in processing_result:
            return EventCategory(processing_result["event_category"])
        
        # Fallback to rule-based classification
        event_type = context.event_type.lower()
        if "malware" in event_type or "virus" in event_type:
            return EventCategory.MALWARE
        elif "phishing" in event_type or "social" in event_type:
            return EventCategory.PHISHING
        elif "intrusion" in event_type or "breach" in event_type:
            return EventCategory.INTRUSION
        elif "data" in event_type and "exfiltration" in event_type:
            return EventCategory.DATA_EXFILTRATION
        else:
            return EventCategory.NETWORK_ANOMALY
    
    def _determine_severity(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> ThreatSeverity:
        """Determine the threat severity from context and processing results."""
        if processing_result and "threat_severity" in processing_result:
            return ThreatSeverity(processing_result["threat_severity"])
        
        # Fallback severity assessment
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            return ThreatSeverity.HIGH
        
        return ThreatSeverity.MEDIUM
    
    async def _generate_title(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        severity: ThreatSeverity
    ) -> str:
        """Generate a clear, concise title for the threat."""
        category_name = category.value.replace("_", " ").title()
        severity_name = severity.value.title()
        
        return f"{severity_name} {category_name} Detected - Event {context.event_id}"
    
    async def _generate_summary(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        style: ExplanationStyle
    ) -> str:
        """Generate an executive summary of the threat."""
        try:
            knowledge = self._threat_knowledge_base.get(category, {})
            description = knowledge.get("description", "Security event detected")
            
            if style == ExplanationStyle.EXECUTIVE:
                return f"A {category.value.lower().replace('_', ' ')} has been detected on {context.source_system}. {description}. Immediate investigation and response is recommended."
            else:
                return f"Security event classified as {category.value.lower().replace('_', ' ')}. {description}. Event originated from {context.source_system} and requires analysis."
        
        except Exception as e:
            logger.warning(f"Summary generation failed: {e}")
            return f"Security event {context.event_id} detected and requires investigation."
    
    async def _generate_detailed_explanation(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        complexity: ExplanationComplexity
    ) -> str:
        """Generate detailed explanation of the threat."""
        try:
            knowledge = self._threat_knowledge_base.get(category, {})
            
            explanation_parts = [
                f"**Event Analysis:**",
                f"This security event has been classified as {category.value.lower().replace('_', ' ')}.",
                f"",
                f"**Description:**",
                knowledge.get("description", "Security event requiring investigation"),
                f"",
                f"**Event Details:**",
                f"- Source System: {context.source_system}",
                f"- Event Type: {context.event_type}",
                f"- Timestamp: {context.timestamp}",
                f"- Security Classification: {context.classification.value}",
            ]
            
            if context.threat_indicators:
                explanation_parts.extend([
                    f"",
                    f"**Threat Indicators:**",
                    *[f"- {indicator}" for indicator in context.threat_indicators[:5]],
                ])
            
            if context.mitre_tactics:
                explanation_parts.extend([
                    f"",
                    f"**MITRE ATT&CK Tactics:**",
                    *[f"- {tactic}" for tactic in context.mitre_tactics],
                ])
            
            if complexity == ExplanationComplexity.DETAILED:
                common_indicators = knowledge.get("common_indicators", [])
                if common_indicators:
                    explanation_parts.extend([
                        f"",
                        f"**Common Indicators for {category.value.title()}:**",
                        *[f"- {indicator}" for indicator in common_indicators],
                    ])
            
            return "\n".join(explanation_parts)
        
        except Exception as e:
            logger.warning(f"Detailed explanation generation failed: {e}")
            return f"Detailed analysis of security event {context.event_id} is in progress."
    
    async def _generate_impact_analysis(
        self, 
        context: SecurityContext, 
        severity: ThreatSeverity, 
        style: ExplanationStyle
    ) -> str:
        """Generate impact analysis for the threat."""
        try:
            impact_model = self._business_impact_models.get(severity, {})
            impact_desc = impact_model.get("impact_description", "Business impact assessment required")
            
            if style == ExplanationStyle.EXECUTIVE:
                return f"**Business Impact:** {impact_desc}\n\n**Response Timeline:** {impact_model.get('response_timeline', 'To be determined')}\n\n**Stakeholders to Notify:** {', '.join(impact_model.get('stakeholder_notification', []))}"
            else:
                return f"Impact Level: {severity.value}\n\nDescription: {impact_desc}\n\nRequired Response: {impact_model.get('resource_allocation', 'Standard procedures')}"
        
        except Exception as e:
            logger.warning(f"Impact analysis generation failed: {e}")
            return "Impact analysis in progress. Severity level indicates immediate attention required."
    
    async def _generate_business_context(
        self, 
        context: SecurityContext, 
        severity: ThreatSeverity, 
        customize_for_tenant: bool
    ) -> str:
        """Generate business context and implications."""
        try:
            context_parts = [
                f"This security event affects tenant {context.tenant_id} and may impact business operations.",
                f"Given the {severity.value.lower()} severity level, appropriate resources should be allocated for response.",
            ]
            
            if context.asset_info:
                context_parts.append(f"Affected assets may include critical business systems requiring immediate protection.")
            
            if customize_for_tenant:
                context_parts.append(f"Response procedures should align with tenant-specific security policies and compliance requirements.")
            
            return " ".join(context_parts)
        
        except Exception as e:
            logger.warning(f"Business context generation failed: {e}")
            return "Business context assessment required for comprehensive response planning."
    
    async def _generate_technical_details(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate technical details section."""
        technical = {
            "event_metadata": {
                "event_id": context.event_id,
                "source_system": context.source_system,
                "event_type": context.event_type,
                "timestamp": context.timestamp.isoformat(),
            },
            "structured_data": context.structured_data,
        }
        
        if processing_result:
            technical["nlp_analysis"] = {
                "confidence_score": processing_result.get("confidence_score", 0),
                "extracted_entities": processing_result.get("entities", {}),
                "keywords": processing_result.get("keywords", []),
                "urgency_score": processing_result.get("urgency_score", 0),
            }
        
        if context.asset_info:
            technical["asset_context"] = context.asset_info
        
        if context.network_context:
            technical["network_context"] = context.network_context
        
        return technical
    
    async def _explain_indicators(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Explain threat indicators and IOCs."""
        explained_indicators = []
        
        # Explain context indicators
        for indicator in context.threat_indicators:
            explanation = self._get_indicator_explanation(indicator)
            explained_indicators.append({
                "indicator": indicator,
                "explanation": explanation,
                "source": "context",
            })
        
        # Explain extracted indicators
        if processing_result and "indicators" in processing_result:
            for indicator in processing_result["indicators"]:
                if indicator not in context.threat_indicators:
                    explanation = self._get_indicator_explanation(indicator)
                    explained_indicators.append({
                        "indicator": indicator,
                        "explanation": explanation,
                        "source": "extracted",
                    })
        
        return explained_indicators
    
    def _get_indicator_explanation(self, indicator: str) -> str:
        """Get explanation for a specific indicator."""
        indicator_lower = indicator.lower()
        
        if "md5" in indicator_lower or "sha" in indicator_lower:
            return "File hash that can be used to identify specific malware samples or suspicious files"
        elif indicator_lower.count(".") == 3:  # IP address pattern
            return "IP address potentially associated with malicious activity or command and control infrastructure"
        elif "." in indicator and not indicator.startswith("http"):
            return "Domain name that may be used for malicious purposes including phishing or malware hosting"
        elif indicator.startswith("http"):
            return "URL potentially hosting malicious content or used in phishing attacks"
        else:
            return "Security indicator requiring further analysis and investigation"
    
    async def _generate_mitre_context(self, context: SecurityContext) -> Dict[str, str]:
        """Generate MITRE ATT&CK context mapping."""
        mitre_context = {}
        
        if context.mitre_tactics:
            mitre_context["tactics"] = ", ".join(context.mitre_tactics)
            mitre_context["tactics_explanation"] = "MITRE ATT&CK tactics represent the adversary's tactical goals"
        
        if context.mitre_techniques:
            mitre_context["techniques"] = ", ".join(context.mitre_techniques)
            mitre_context["techniques_explanation"] = "MITRE ATT&CK techniques describe how adversaries achieve tactical goals"
        
        return mitre_context
    
    async def _generate_immediate_actions(
        self, 
        category: EventCategory, 
        severity: ThreatSeverity, 
        style: ExplanationStyle
    ) -> List[str]:
        """Generate immediate action recommendations."""
        try:
            actions = []
            
            # Severity-based actions
            if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                actions.extend([
                    "Immediately isolate affected systems if confirmed malicious",
                    "Notify incident response team and key stakeholders",
                    "Preserve evidence and maintain chain of custody",
                ])
            
            # Category-specific actions
            category_actions = {
                EventCategory.MALWARE: [
                    "Run comprehensive antimalware scans on affected systems",
                    "Check for lateral movement and additional compromised systems",
                    "Update security signatures and definitions",
                ],
                EventCategory.PHISHING: [
                    "Block sender and malicious URLs/domains",
                    "Notify potentially affected users",
                    "Check for credential compromise",
                ],
                EventCategory.INTRUSION: [
                    "Change potentially compromised credentials",
                    "Review access logs for unauthorized activity",
                    "Implement additional access controls",
                ],
                EventCategory.DATA_EXFILTRATION: [
                    "Identify and secure data sources",
                    "Review data access permissions and logs",
                    "Implement data loss prevention controls",
                ],
            }
            
            actions.extend(category_actions.get(category, [
                "Begin immediate investigation and evidence collection",
                "Review system logs and security alerts",
                "Implement appropriate containment measures",
            ]))
            
            return actions
        
        except Exception as e:
            logger.warning(f"Immediate actions generation failed: {e}")
            return ["Begin immediate investigation and response procedures"]
    
    async def _generate_investigation_steps(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        complexity: ExplanationComplexity
    ) -> List[str]:
        """Generate investigation step recommendations."""
        try:
            knowledge = self._threat_knowledge_base.get(category, {})
            focus_areas = knowledge.get("investigation_focus", ["system analysis", "log review"])
            
            steps = [
                f"1. Analyze {context.source_system} logs and security events",
                f"2. Review user and system activity around {context.timestamp}",
                f"3. Check for related events and indicators across the environment",
            ]
            
            for i, focus in enumerate(focus_areas, 4):
                steps.append(f"{i}. Conduct detailed {focus} investigation")
            
            if complexity == ExplanationComplexity.DETAILED:
                steps.extend([
                    f"{len(steps) + 1}. Document findings and maintain evidence chain",
                    f"{len(steps) + 2}. Coordinate with stakeholders and update incident status",
                    f"{len(steps) + 3}. Prepare preliminary incident report",
                ])
            
            return steps
        
        except Exception as e:
            logger.warning(f"Investigation steps generation failed: {e}")
            return ["Conduct comprehensive investigation following standard procedures"]
    
    async def _generate_prevention_measures(
        self, 
        category: EventCategory, 
        style: ExplanationStyle
    ) -> List[str]:
        """Generate prevention measure recommendations."""
        try:
            measures = self._mitigation_database.get(category, [
                "Implement appropriate security controls",
                "Enhance monitoring and detection capabilities",
                "Conduct security awareness training",
            ])
            
            if style == ExplanationStyle.EXECUTIVE:
                # Add business-focused measures
                measures.extend([
                    "Review and update security policies and procedures",
                    "Consider additional security investments and technologies",
                    "Enhance business continuity and disaster recovery plans",
                ])
            
            return measures
        
        except Exception as e:
            logger.warning(f"Prevention measures generation failed: {e}")
            return ["Implement comprehensive security controls and monitoring"]
    
    def _extract_risk_factors(self, context: SecurityContext, category: EventCategory) -> List[str]:
        """Extract key risk factors from the event."""
        risk_factors = []
        
        # Classification-based risks
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            risk_factors.append("High-value target due to security classification")
        
        # Category-based risks
        knowledge = self._threat_knowledge_base.get(category, {})
        typical_impacts = knowledge.get("typical_impacts", [])
        risk_factors.extend([f"Risk of {impact}" for impact in typical_impacts])
        
        # Indicator-based risks
        if context.threat_indicators:
            risk_factors.append("Active threat indicators present")
        
        if context.mitre_tactics:
            risk_factors.append("Tactics align with advanced persistent threats")
        
        return risk_factors
    
    def _assess_confidence(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> float:
        """Assess confidence in the explanation."""
        confidence = 0.7  # Base confidence
        
        if processing_result:
            # Boost confidence if NLP analysis is available
            nlp_confidence = processing_result.get("confidence_score", 0.5)
            confidence = (confidence + nlp_confidence) / 2
        
        if context.threat_indicators:
            confidence += 0.1
        
        if context.mitre_tactics:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _assess_completeness(
        self, 
        context: SecurityContext, 
        technical_details: Dict[str, Any], 
        indicators_explained: List[Dict[str, str]]
    ) -> float:
        """Assess completeness of the explanation."""
        completeness = 0.6  # Base completeness
        
        if technical_details:
            completeness += 0.1
        
        if indicators_explained:
            completeness += 0.1
        
        if context.asset_info:
            completeness += 0.1
        
        if context.mitre_tactics or context.mitre_techniques:
            completeness += 0.1
        
        return min(1.0, completeness)
    
    def _assess_clarity(self, explanation: str, style: ExplanationStyle) -> float:
        """Assess clarity of the explanation."""
        # Simple heuristic based on explanation length and style
        if style == ExplanationStyle.EXECUTIVE and len(explanation) > 2000:
            return 0.7  # Too verbose for executive
        elif style == ExplanationStyle.TECHNICAL and len(explanation) < 500:
            return 0.7  # Too brief for technical
        else:
            return 0.9  # Good clarity
    
    def _update_explanation_metrics(
        self, 
        style: ExplanationStyle, 
        complexity: ExplanationComplexity, 
        start_time: datetime
    ) -> None:
        """Update explanation generation metrics."""
        self._explanation_metrics["total_explanations"] += 1
        
        # Update style distribution
        style_key = style.value
        if style_key not in self._explanation_metrics["style_distribution"]:
            self._explanation_metrics["style_distribution"][style_key] = 0
        self._explanation_metrics["style_distribution"][style_key] += 1
        
        # Update complexity distribution
        complexity_key = complexity.value
        if complexity_key not in self._explanation_metrics["complexity_distribution"]:
            self._explanation_metrics["complexity_distribution"][complexity_key] = 0
        self._explanation_metrics["complexity_distribution"][complexity_key] += 1
        
        # Update average generation time
        generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        current_avg = self._explanation_metrics["average_generation_time"]
        count = self._explanation_metrics["total_explanations"]
        
        self._explanation_metrics["average_generation_time"] = (
            (current_avg * (count - 1)) + generation_time
        ) / count
    
    def get_explanation_metrics(self) -> Dict[str, Any]:
        """Get explanation generation metrics."""
        return self._explanation_metrics.copy()