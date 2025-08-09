"""
Investigation Advisor for iSECTECH Platform.

This module provides intelligent investigation recommendations and guidance
for security analysts, delivering contextual analysis and step-by-step
investigation workflows tailored to specific threat scenarios.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from pydantic import BaseModel, Field, validator

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from .security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity


# Configure logging
logger = logging.getLogger(__name__)


class InvestigationPriority(str, Enum):
    """Investigation priority levels."""
    IMMEDIATE = "IMMEDIATE"       # Requires immediate attention (< 1 hour)
    URGENT = "URGENT"             # High priority (< 4 hours)
    HIGH = "HIGH"                 # Important (< 24 hours)
    MEDIUM = "MEDIUM"             # Standard priority (< 48 hours)
    LOW = "LOW"                   # Monitor and track (< 72 hours)


class InvestigationComplexity(str, Enum):
    """Investigation complexity levels."""
    SIMPLE = "SIMPLE"             # Basic log review and analysis
    MODERATE = "MODERATE"         # Multi-source correlation required
    COMPLEX = "COMPLEX"           # Advanced forensics and analysis
    ADVANCED = "ADVANCED"         # Specialized expertise required


class EvidenceType(str, Enum):
    """Types of evidence to collect."""
    SYSTEM_LOGS = "SYSTEM_LOGS"
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"
    FILE_ARTIFACTS = "FILE_ARTIFACTS"
    MEMORY_DUMPS = "MEMORY_DUMPS"
    REGISTRY_DATA = "REGISTRY_DATA"
    USER_ACTIVITY = "USER_ACTIVITY"
    DATABASE_LOGS = "DATABASE_LOGS"
    EMAIL_RECORDS = "EMAIL_RECORDS"
    AUTHENTICATION_LOGS = "AUTHENTICATION_LOGS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"


class InvestigationStep(BaseModel):
    """Individual investigation step with details."""
    
    step_number: int = Field(..., description="Step sequence number")
    title: str = Field(..., description="Step title")
    description: str = Field(..., description="Detailed step description")
    
    # Step execution details
    priority: InvestigationPriority = Field(..., description="Step priority level")
    estimated_time_minutes: int = Field(..., description="Estimated completion time")
    required_skills: List[str] = Field(default_factory=list, description="Required skills/expertise")
    
    # Evidence and data collection
    evidence_types: List[EvidenceType] = Field(default_factory=list, description="Evidence to collect")
    data_sources: List[str] = Field(default_factory=list, description="Specific data sources")
    collection_commands: List[str] = Field(default_factory=list, description="Commands or procedures")
    
    # Tools and techniques
    recommended_tools: List[str] = Field(default_factory=list, description="Recommended analysis tools")
    techniques: List[str] = Field(default_factory=list, description="Investigation techniques")
    
    # Dependencies and context
    prerequisites: List[int] = Field(default_factory=list, description="Prerequisite step numbers")
    parallel_steps: List[int] = Field(default_factory=list, description="Steps that can run in parallel")
    
    # Output and results
    expected_outputs: List[str] = Field(default_factory=list, description="Expected investigation outputs")
    success_criteria: List[str] = Field(default_factory=list, description="Criteria for step completion")
    
    # Risk and safety
    risk_level: str = Field(default="LOW", description="Risk level of executing this step")
    safety_considerations: List[str] = Field(default_factory=list, description="Safety considerations")
    
    @validator("step_number")
    def validate_step_number(cls, v):
        """Validate step number is positive."""
        if v <= 0:
            raise ValueError("Step number must be positive")
        return v
    
    @validator("estimated_time_minutes")
    def validate_time_estimate(cls, v):
        """Validate time estimate is reasonable."""
        if v <= 0 or v > 1440:  # Max 24 hours
            raise ValueError("Time estimate must be between 1 and 1440 minutes")
        return v


class InvestigationRecommendation(BaseModel):
    """Comprehensive investigation recommendation result."""
    
    # Recommendation metadata
    recommendation_id: str = Field(..., description="Unique recommendation identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_id: str = Field(..., description="Source event identifier")
    
    # Investigation overview
    investigation_title: str = Field(..., description="Investigation title")
    executive_summary: str = Field(..., description="Executive summary of recommended investigation")
    complexity: InvestigationComplexity = Field(..., description="Overall investigation complexity")
    priority: InvestigationPriority = Field(..., description="Investigation priority level")
    
    # Resource requirements
    estimated_total_hours: float = Field(..., description="Total estimated investigation time")
    required_expertise: List[str] = Field(default_factory=list, description="Required expertise areas")
    required_tools: List[str] = Field(default_factory=list, description="Required investigation tools")
    
    # Investigation workflow
    investigation_steps: List[InvestigationStep] = Field(default_factory=list, description="Detailed investigation steps")
    critical_path: List[int] = Field(default_factory=list, description="Critical path step numbers")
    parallel_workflows: List[List[int]] = Field(default_factory=list, description="Parallel workflow groups")
    
    # Evidence and data
    key_evidence_targets: List[str] = Field(default_factory=list, description="Key evidence targets")
    data_retention_requirements: Dict[str, int] = Field(default_factory=dict, description="Data retention needs (days)")
    chain_of_custody_requirements: List[str] = Field(default_factory=list, description="Chain of custody requirements")
    
    # Threat context
    threat_indicators: List[str] = Field(default_factory=list, description="Key threat indicators")
    attack_timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Estimated attack timeline")
    potential_impact_areas: List[str] = Field(default_factory=list, description="Potential impact areas")
    
    # Escalation and communication
    escalation_triggers: List[str] = Field(default_factory=list, description="Escalation triggers")
    stakeholder_communication: Dict[str, List[str]] = Field(default_factory=dict, description="Stakeholder communication plan")
    reporting_requirements: List[str] = Field(default_factory=list, description="Reporting requirements")
    
    # Quality and confidence
    confidence_score: float = Field(..., description="Recommendation confidence (0-1)")
    completeness_score: float = Field(..., description="Recommendation completeness (0-1)")
    risk_assessment: str = Field(..., description="Investigation risk assessment")
    
    # Success metrics
    success_indicators: List[str] = Field(default_factory=list, description="Investigation success indicators")
    completion_criteria: List[str] = Field(default_factory=list, description="Investigation completion criteria")
    
    @validator("confidence_score", "completeness_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class InvestigationAdvisor:
    """
    Production-grade investigation advisor for iSECTECH security operations.
    
    Provides intelligent, contextual investigation recommendations and workflows
    tailored to specific threat scenarios and organizational capabilities.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the investigation advisor."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Investigation knowledge bases
        self._investigation_playbooks = self._load_investigation_playbooks()
        self._evidence_collection_guides = self._load_evidence_collection_guides()
        self._tool_recommendations = self._load_tool_recommendations()
        self._escalation_procedures = self._load_escalation_procedures()
        self._compliance_requirements = self._load_compliance_requirements()
        
        # Investigation templates and workflows
        self._workflow_templates = self._load_workflow_templates()
        self._step_libraries = self._load_step_libraries()
        self._technique_mappings = self._load_technique_mappings()
        
        # Performance tracking
        self._advisory_metrics = {
            "total_recommendations": 0,
            "average_generation_time": 0.0,
            "complexity_distribution": {},
            "priority_distribution": {},
            "success_rate": 0.0,
        }
        
        logger.info("Investigation advisor initialized successfully")
    
    def _load_investigation_playbooks(self) -> Dict[EventCategory, Dict[str, Any]]:
        """Load investigation playbooks for different threat categories."""
        return {
            EventCategory.MALWARE: {
                "title": "Malware Investigation Playbook",
                "description": "Comprehensive malware analysis and containment procedures",
                "key_objectives": [
                    "Identify malware type and capabilities",
                    "Determine infection vector and scope",
                    "Assess data compromise and exfiltration",
                    "Implement containment and eradication",
                ],
                "critical_evidence": [
                    EvidenceType.FILE_ARTIFACTS,
                    EvidenceType.SYSTEM_LOGS,
                    EvidenceType.NETWORK_TRAFFIC,
                    EvidenceType.MEMORY_DUMPS,
                ],
                "typical_duration_hours": 8,
                "expertise_required": ["malware_analysis", "forensics", "incident_response"],
            },
            EventCategory.PHISHING: {
                "title": "Phishing Investigation Playbook",
                "description": "Email-based attack investigation and user impact assessment",
                "key_objectives": [
                    "Analyze phishing email and infrastructure",
                    "Identify affected users and systems",
                    "Assess credential compromise",
                    "Implement protective measures",
                ],
                "critical_evidence": [
                    EvidenceType.EMAIL_RECORDS,
                    EvidenceType.AUTHENTICATION_LOGS,
                    EvidenceType.USER_ACTIVITY,
                    EvidenceType.NETWORK_TRAFFIC,
                ],
                "typical_duration_hours": 4,
                "expertise_required": ["email_security", "user_behavior_analysis", "threat_intelligence"],
            },
            EventCategory.INTRUSION: {
                "title": "Intrusion Investigation Playbook",
                "description": "Unauthorized access investigation and lateral movement analysis",
                "key_objectives": [
                    "Identify attack vector and entry point",
                    "Map lateral movement and persistence",
                    "Assess data access and exfiltration",
                    "Implement access controls and monitoring",
                ],
                "critical_evidence": [
                    EvidenceType.AUTHENTICATION_LOGS,
                    EvidenceType.SYSTEM_LOGS,
                    EvidenceType.NETWORK_TRAFFIC,
                    EvidenceType.USER_ACTIVITY,
                ],
                "typical_duration_hours": 12,
                "expertise_required": ["network_forensics", "access_control", "incident_response"],
            },
            EventCategory.DATA_EXFILTRATION: {
                "title": "Data Exfiltration Investigation Playbook",
                "description": "Data breach investigation and impact assessment",
                "key_objectives": [
                    "Identify exfiltrated data and scope",
                    "Determine exfiltration methods and channels",
                    "Assess regulatory and legal implications",
                    "Implement data protection measures",
                ],
                "critical_evidence": [
                    EvidenceType.DATABASE_LOGS,
                    EvidenceType.NETWORK_TRAFFIC,
                    EvidenceType.USER_ACTIVITY,
                    EvidenceType.FILE_ARTIFACTS,
                ],
                "typical_duration_hours": 16,
                "expertise_required": ["data_forensics", "compliance", "legal", "incident_response"],
            },
        }
    
    def _load_evidence_collection_guides(self) -> Dict[EvidenceType, Dict[str, Any]]:
        """Load evidence collection guides for different evidence types."""
        return {
            EvidenceType.SYSTEM_LOGS: {
                "description": "Operating system and application logs",
                "collection_priority": "HIGH",
                "retention_period_days": 90,
                "tools": ["log_collectors", "syslog", "windows_event_logs"],
                "collection_steps": [
                    "Identify relevant log sources and time ranges",
                    "Preserve original logs before collection",
                    "Use appropriate tools to extract logs",
                    "Verify log integrity and completeness",
                    "Document collection procedures and timestamps",
                ],
                "analysis_techniques": ["timeline_analysis", "anomaly_detection", "correlation_analysis"],
            },
            EvidenceType.NETWORK_TRAFFIC: {
                "description": "Network packets and flow data",
                "collection_priority": "HIGH",
                "retention_period_days": 30,
                "tools": ["wireshark", "tcpdump", "network_monitors"],
                "collection_steps": [
                    "Identify network segments and interfaces",
                    "Configure packet capture with appropriate filters",
                    "Ensure sufficient storage for captures",
                    "Verify capture completeness and integrity",
                    "Secure captured data with encryption",
                ],
                "analysis_techniques": ["protocol_analysis", "traffic_flow_analysis", "malware_c2_detection"],
            },
            EvidenceType.FILE_ARTIFACTS: {
                "description": "Suspicious files and executable artifacts",
                "collection_priority": "CRITICAL",
                "retention_period_days": 365,
                "tools": ["file_carving", "hash_analysis", "sandbox_analysis"],
                "collection_steps": [
                    "Identify suspicious files and locations",
                    "Create forensic copies with hash verification",
                    "Preserve file metadata and timestamps",
                    "Isolate files to prevent execution",
                    "Conduct initial triage analysis",
                ],
                "analysis_techniques": ["static_analysis", "dynamic_analysis", "signature_matching"],
            },
            EvidenceType.MEMORY_DUMPS: {
                "description": "System memory snapshots for volatile data",
                "collection_priority": "HIGH",
                "retention_period_days": 60,
                "tools": ["volatility", "memory_acquisition", "rekall"],
                "collection_steps": [
                    "Acquire memory dump from affected systems",
                    "Verify dump integrity and completeness",
                    "Extract running processes and network connections",
                    "Identify injected code and rootkits",
                    "Correlate with other evidence sources",
                ],
                "analysis_techniques": ["process_analysis", "memory_forensics", "malware_detection"],
            },
        }
    
    def _load_tool_recommendations(self) -> Dict[str, Dict[str, Any]]:
        """Load tool recommendations for different investigation tasks."""
        return {
            "malware_analysis": {
                "primary_tools": ["IDA Pro", "Ghidra", "x64dbg", "OllyDbg"],
                "sandbox_tools": ["Cuckoo Sandbox", "Joe Sandbox", "Hybrid Analysis"],
                "static_analysis": ["PEiD", "Detect It Easy", "YARA"],
                "dynamic_analysis": ["Process Monitor", "Process Hacker", "API Monitor"],
            },
            "network_forensics": {
                "capture_tools": ["Wireshark", "tcpdump", "NetworkMiner"],
                "analysis_tools": ["Zeek", "Suricata", "Security Onion"],
                "flow_analysis": ["SiLK", "nfcapd", "Argus"],
                "protocol_analysis": ["Wireshark", "tcpflow", "Chaosreader"],
            },
            "log_analysis": {
                "collection_tools": ["Splunk", "ELK Stack", "Graylog"],
                "analysis_tools": ["Sigma", "YARA-L", "Custom Scripts"],
                "correlation_tools": ["SIEM Platforms", "LogRhythm", "QRadar"],
                "visualization": ["Kibana", "Grafana", "Splunk Dashboards"],
            },
            "forensics": {
                "disk_imaging": ["dd", "FTK Imager", "EnCase"],
                "file_analysis": ["Autopsy", "Sleuth Kit", "X-Ways"],
                "timeline_analysis": ["log2timeline", "Plaso", "Volatility"],
                "reporting": ["CaseFile", "Maltego", "Custom Reports"],
            },
        }
    
    def _load_escalation_procedures(self) -> Dict[ThreatSeverity, Dict[str, Any]]:
        """Load escalation procedures for different severity levels."""
        return {
            ThreatSeverity.CRITICAL: {
                "immediate_notifications": ["CISO", "CEO", "Legal", "PR"],
                "notification_timeframe": "15 minutes",
                "escalation_triggers": [
                    "Data breach confirmed",
                    "Critical systems compromised",
                    "Regulatory notification required",
                    "Media attention likely",
                ],
                "communication_channels": ["Phone", "Secure messaging", "Emergency broadcast"],
                "external_resources": ["Law enforcement", "Legal counsel", "PR firm", "Cyber insurance"],
            },
            ThreatSeverity.HIGH: {
                "immediate_notifications": ["CISO", "IT Leadership", "Security Team"],
                "notification_timeframe": "1 hour",
                "escalation_triggers": [
                    "Widespread impact confirmed",
                    "Advanced persistent threat detected",
                    "Business operations affected",
                ],
                "communication_channels": ["Phone", "Email", "Incident management system"],
                "external_resources": ["Incident response firm", "Technical experts"],
            },
            ThreatSeverity.MEDIUM: {
                "immediate_notifications": ["Security Operations", "IT Operations"],
                "notification_timeframe": "4 hours",
                "escalation_triggers": [
                    "Incident scope expanding",
                    "Technical expertise needed",
                    "Timeline objectives at risk",
                ],
                "communication_channels": ["Email", "Chat", "Incident management system"],
                "external_resources": ["Vendor support", "Technical consultants"],
            },
        }
    
    def _load_compliance_requirements(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance requirements for investigations."""
        return {
            "gdpr": {
                "notification_timeline": "72 hours to authorities, 30 days to individuals",
                "documentation_requirements": [
                    "Breach assessment and impact analysis",
                    "Timeline of events and response actions",
                    "Data subject impact assessment",
                    "Remediation measures implemented",
                ],
                "evidence_retention": "As long as processing is lawful",
            },
            "hipaa": {
                "notification_timeline": "60 days to authorities and individuals",
                "documentation_requirements": [
                    "Risk assessment and mitigation",
                    "Breach report and impact analysis",
                    "Corrective action plan",
                    "Business associate notifications",
                ],
                "evidence_retention": "6 years minimum",
            },
            "pci_dss": {
                "notification_timeline": "Immediately to card brands and acquirer",
                "documentation_requirements": [
                    "Incident response procedures followed",
                    "Forensic investigation results",
                    "Remediation and validation testing",
                    "Compliance restoration plan",
                ],
                "evidence_retention": "1 year minimum",
            },
        }
    
    def _load_workflow_templates(self) -> Dict[InvestigationComplexity, List[str]]:
        """Load investigation workflow templates by complexity."""
        return {
            InvestigationComplexity.SIMPLE: [
                "Initial triage and classification",
                "Basic log analysis and correlation",
                "Impact assessment and containment",
                "Documentation and reporting",
            ],
            InvestigationComplexity.MODERATE: [
                "Enhanced triage and threat assessment",
                "Multi-source evidence collection",
                "Advanced analysis and correlation",
                "Threat intelligence integration",
                "Comprehensive impact assessment",
                "Remediation and lessons learned",
            ],
            InvestigationComplexity.COMPLEX: [
                "Advanced forensic preparation",
                "Comprehensive evidence preservation",
                "Detailed timeline reconstruction",
                "Advanced threat actor analysis",
                "Attribution and intelligence gathering",
                "Legal and regulatory coordination",
                "Strategic remediation planning",
                "Post-incident security enhancement",
            ],
            InvestigationComplexity.ADVANCED: [
                "Specialized forensic environment setup",
                "Advanced persistent threat hunting",
                "Nation-state actor analysis",
                "Supply chain compromise investigation",
                "Advanced malware reverse engineering",
                "Geopolitical threat assessment",
                "International coordination",
                "Strategic security transformation",
            ],
        }
    
    def _load_step_libraries(self) -> Dict[str, InvestigationStep]:
        """Load reusable investigation step library."""
        return {
            "initial_triage": InvestigationStep(
                step_number=1,
                title="Initial Triage and Assessment",
                description="Conduct initial assessment to understand the scope and severity of the security incident",
                priority=InvestigationPriority.IMMEDIATE,
                estimated_time_minutes=60,
                required_skills=["incident_response", "threat_assessment"],
                evidence_types=[EvidenceType.SYSTEM_LOGS, EvidenceType.NETWORK_TRAFFIC],
                data_sources=["Security alerts", "System logs", "Network monitoring"],
                collection_commands=["Review SIEM alerts", "Check system status", "Analyze network flows"],
                recommended_tools=["SIEM", "Network monitoring", "Threat intelligence"],
                techniques=["Alert correlation", "Timeline analysis", "Threat classification"],
                expected_outputs=["Incident classification", "Initial scope assessment", "Priority determination"],
                success_criteria=["Threat type identified", "Scope bounded", "Priority assigned"],
                risk_level="LOW",
                safety_considerations=["Avoid alerting potential attackers", "Preserve evidence integrity"],
            ),
            "evidence_preservation": InvestigationStep(
                step_number=2,
                title="Evidence Preservation and Collection",
                description="Secure and preserve critical evidence before it can be lost or contaminated",
                priority=InvestigationPriority.URGENT,
                estimated_time_minutes=120,
                required_skills=["digital_forensics", "evidence_handling"],
                evidence_types=[EvidenceType.FILE_ARTIFACTS, EvidenceType.MEMORY_DUMPS, EvidenceType.SYSTEM_LOGS],
                data_sources=["Affected systems", "Network devices", "Log servers"],
                collection_commands=["Create disk images", "Acquire memory dumps", "Export logs"],
                recommended_tools=["FTK Imager", "Volatility", "Log exporters"],
                techniques=["Forensic imaging", "Memory acquisition", "Log preservation"],
                expected_outputs=["Forensic images", "Memory dumps", "Log archives"],
                success_criteria=["Evidence integrity verified", "Chain of custody established", "Data preserved"],
                risk_level="MEDIUM",
                safety_considerations=["Maintain chain of custody", "Avoid evidence contamination", "Secure storage"],
            ),
        }
    
    def _load_technique_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load investigation technique mappings."""
        return {
            "timeline_analysis": {
                "description": "Reconstruct chronological sequence of events",
                "applicable_evidence": [EvidenceType.SYSTEM_LOGS, EvidenceType.AUTHENTICATION_LOGS],
                "tools": ["log2timeline", "Plaso", "Splunk"],
                "complexity": "MODERATE",
                "estimated_time": 180,
            },
            "malware_analysis": {
                "description": "Analyze malicious software behavior and capabilities",
                "applicable_evidence": [EvidenceType.FILE_ARTIFACTS, EvidenceType.MEMORY_DUMPS],
                "tools": ["IDA Pro", "Cuckoo Sandbox", "Volatility"],
                "complexity": "COMPLEX",
                "estimated_time": 480,
            },
            "network_flow_analysis": {
                "description": "Analyze network communications and data flows",
                "applicable_evidence": [EvidenceType.NETWORK_TRAFFIC],
                "tools": ["Wireshark", "Zeek", "NetworkMiner"],
                "complexity": "MODERATE",
                "estimated_time": 240,
            },
        }
    
    async def generate_investigation_recommendation(
        self,
        context: SecurityContext,
        processing_result: Optional[Dict[str, Any]] = None,
        threat_explanation: Optional[Dict[str, Any]] = None,
        customize_for_organization: bool = True,
    ) -> InvestigationRecommendation:
        """
        Generate comprehensive investigation recommendations.
        
        Args:
            context: Security context containing event details
            processing_result: Optional NLP processing results
            threat_explanation: Optional threat explanation results
            customize_for_organization: Whether to customize for organization
            
        Returns:
            Comprehensive investigation recommendation
        """
        start_time = datetime.utcnow()
        recommendation_id = f"inv-rec-{context.event_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Generating investigation recommendation for event {context.event_id}")
            
            # Audit log the recommendation request
            await self.audit_logger.log_security_event(
                event_type="INVESTIGATION_RECOMMENDATION_STARTED",
                details={
                    "event_id": context.event_id,
                    "recommendation_id": recommendation_id,
                    "tenant_id": context.tenant_id,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Determine investigation parameters
            threat_category = self._determine_threat_category(context, processing_result)
            threat_severity = self._determine_threat_severity(context, processing_result)
            complexity = self._assess_investigation_complexity(context, threat_category, threat_severity)
            priority = self._determine_investigation_priority(threat_severity, context)
            
            # Generate investigation components
            title = self._generate_investigation_title(context, threat_category, threat_severity)
            summary = await self._generate_executive_summary(context, threat_category, threat_explanation)
            
            # Build investigation workflow
            investigation_steps = await self._build_investigation_workflow(
                context, threat_category, complexity, processing_result
            )
            
            # Determine resource requirements
            total_hours, expertise, tools = self._calculate_resource_requirements(investigation_steps)
            
            # Generate supporting information
            evidence_targets = self._identify_evidence_targets(threat_category, context)
            retention_requirements = self._determine_retention_requirements(threat_category, context)
            escalation_triggers = self._define_escalation_triggers(threat_severity, context)
            
            # Build recommendation
            recommendation = InvestigationRecommendation(
                recommendation_id=recommendation_id,
                event_id=context.event_id,
                investigation_title=title,
                executive_summary=summary,
                complexity=complexity,
                priority=priority,
                estimated_total_hours=total_hours,
                required_expertise=expertise,
                required_tools=tools,
                investigation_steps=investigation_steps,
                critical_path=self._identify_critical_path(investigation_steps),
                parallel_workflows=self._identify_parallel_workflows(investigation_steps),
                key_evidence_targets=evidence_targets,
                data_retention_requirements=retention_requirements,
                chain_of_custody_requirements=self._define_custody_requirements(threat_category),
                threat_indicators=context.threat_indicators,
                attack_timeline=await self._estimate_attack_timeline(context, processing_result),
                potential_impact_areas=self._identify_impact_areas(context, threat_category),
                escalation_triggers=escalation_triggers,
                stakeholder_communication=self._define_communication_plan(threat_severity),
                reporting_requirements=self._determine_reporting_requirements(context, threat_category),
                confidence_score=self._assess_recommendation_confidence(context, processing_result),
                completeness_score=self._assess_recommendation_completeness(investigation_steps, evidence_targets),
                risk_assessment=self._assess_investigation_risk(context, complexity),
                success_indicators=self._define_success_indicators(threat_category, complexity),
                completion_criteria=self._define_completion_criteria(threat_category, threat_severity),
            )
            
            # Update metrics
            self._update_advisory_metrics(complexity, priority, start_time)
            
            # Audit log successful recommendation
            await self.audit_logger.log_security_event(
                event_type="INVESTIGATION_RECOMMENDATION_COMPLETED",
                details={
                    "recommendation_id": recommendation_id,
                    "complexity": complexity,
                    "priority": priority,
                    "estimated_hours": total_hours,
                    "generation_time_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
                },
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Generated investigation recommendation {recommendation_id}")
            return recommendation
            
        except Exception as e:
            logger.error(f"Failed to generate investigation recommendation: {e}")
            await self.audit_logger.log_security_event(
                event_type="INVESTIGATION_RECOMMENDATION_FAILED",
                details={
                    "recommendation_id": recommendation_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.classification,
                tenant_id=context.tenant_id,
            )
            raise
    
    def _determine_threat_category(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> EventCategory:
        """Determine the threat category for investigation planning."""
        if processing_result and "event_category" in processing_result:
            return EventCategory(processing_result["event_category"])
        
        # Fallback based on context
        event_type = context.event_type.lower()
        if "malware" in event_type:
            return EventCategory.MALWARE
        elif "phishing" in event_type:
            return EventCategory.PHISHING
        elif "intrusion" in event_type or "breach" in event_type:
            return EventCategory.INTRUSION
        elif "data" in event_type and ("exfiltration" in event_type or "leak" in event_type):
            return EventCategory.DATA_EXFILTRATION
        else:
            return EventCategory.NETWORK_ANOMALY
    
    def _determine_threat_severity(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> ThreatSeverity:
        """Determine the threat severity for investigation planning."""
        if processing_result and "threat_severity" in processing_result:
            return ThreatSeverity(processing_result["threat_severity"])
        
        # Fallback severity assessment
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            return ThreatSeverity.HIGH
        elif context.threat_indicators and len(context.threat_indicators) > 3:
            return ThreatSeverity.MEDIUM
        else:
            return ThreatSeverity.LOW
    
    def _assess_investigation_complexity(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        severity: ThreatSeverity
    ) -> InvestigationComplexity:
        """Assess the complexity level of the investigation."""
        complexity_score = 0
        
        # Base complexity by category
        category_complexity = {
            EventCategory.MALWARE: 2,
            EventCategory.PHISHING: 1,
            EventCategory.INTRUSION: 3,
            EventCategory.DATA_EXFILTRATION: 3,
            EventCategory.NETWORK_ANOMALY: 1,
        }
        complexity_score += category_complexity.get(category, 1)
        
        # Severity adjustment
        severity_adjustment = {
            ThreatSeverity.CRITICAL: 2,
            ThreatSeverity.HIGH: 1,
            ThreatSeverity.MEDIUM: 0,
            ThreatSeverity.LOW: -1,
        }
        complexity_score += severity_adjustment.get(severity, 0)
        
        # Context factors
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            complexity_score += 1
        
        if context.mitre_tactics and len(context.mitre_tactics) > 2:
            complexity_score += 1
        
        if context.threat_indicators and len(context.threat_indicators) > 5:
            complexity_score += 1
        
        # Map to complexity levels
        if complexity_score >= 6:
            return InvestigationComplexity.ADVANCED
        elif complexity_score >= 4:
            return InvestigationComplexity.COMPLEX
        elif complexity_score >= 2:
            return InvestigationComplexity.MODERATE
        else:
            return InvestigationComplexity.SIMPLE
    
    def _determine_investigation_priority(
        self, 
        severity: ThreatSeverity, 
        context: SecurityContext
    ) -> InvestigationPriority:
        """Determine the investigation priority level."""
        # Base priority by severity
        severity_priority = {
            ThreatSeverity.CRITICAL: InvestigationPriority.IMMEDIATE,
            ThreatSeverity.HIGH: InvestigationPriority.URGENT,
            ThreatSeverity.MEDIUM: InvestigationPriority.HIGH,
            ThreatSeverity.LOW: InvestigationPriority.MEDIUM,
        }
        
        base_priority = severity_priority.get(severity, InvestigationPriority.MEDIUM)
        
        # Upgrade priority for high-classification data
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            if base_priority == InvestigationPriority.HIGH:
                return InvestigationPriority.URGENT
            elif base_priority == InvestigationPriority.MEDIUM:
                return InvestigationPriority.HIGH
        
        return base_priority
    
    def _generate_investigation_title(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        severity: ThreatSeverity
    ) -> str:
        """Generate a descriptive investigation title."""
        category_name = category.value.replace("_", " ").title()
        severity_name = severity.value.title()
        
        return f"{severity_name} {category_name} Investigation - Event {context.event_id}"
    
    async def _generate_executive_summary(
        self, 
        context: SecurityContext, 
        category: EventCategory, 
        threat_explanation: Optional[Dict[str, Any]]
    ) -> str:
        """Generate executive summary for the investigation."""
        try:
            playbook = self._investigation_playbooks.get(category, {})
            description = playbook.get("description", "Security incident investigation")
            
            summary_parts = [
                f"A {category.value.lower().replace('_', ' ')} has been detected requiring comprehensive investigation.",
                f"",
                f"**Investigation Objectives:**",
            ]
            
            objectives = playbook.get("key_objectives", [
                "Determine incident scope and impact",
                "Identify attack vectors and techniques",
                "Implement containment and remediation",
                "Prevent similar incidents",
            ])
            
            summary_parts.extend([f"- {obj}" for obj in objectives])
            
            if threat_explanation and "business_context" in threat_explanation:
                summary_parts.extend([
                    f"",
                    f"**Business Context:**",
                    threat_explanation["business_context"],
                ])
            
            return "\n".join(summary_parts)
        
        except Exception as e:
            logger.warning(f"Executive summary generation failed: {e}")
            return f"Investigation required for security event {context.event_id}. Comprehensive analysis and response procedures will be implemented."
    
    async def _build_investigation_workflow(
        self,
        context: SecurityContext,
        category: EventCategory,
        complexity: InvestigationComplexity,
        processing_result: Optional[Dict[str, Any]],
    ) -> List[InvestigationStep]:
        """Build detailed investigation workflow steps."""
        steps = []
        step_counter = 1
        
        try:
            # Get workflow template
            workflow_template = self._workflow_templates.get(complexity, [])
            playbook = self._investigation_playbooks.get(category, {})
            
            # Build core workflow steps
            for step_name in workflow_template:
                step = await self._create_investigation_step(
                    step_counter, step_name, category, complexity, context
                )
                steps.append(step)
                step_counter += 1
            
            # Add category-specific steps
            category_steps = await self._get_category_specific_steps(
                category, complexity, step_counter, context
            )
            steps.extend(category_steps)
            
            # Add compliance steps if required
            compliance_steps = await self._get_compliance_steps(
                context, step_counter + len(category_steps)
            )
            steps.extend(compliance_steps)
            
            return steps
        
        except Exception as e:
            logger.warning(f"Workflow building failed: {e}")
            # Return basic workflow as fallback
            return [
                InvestigationStep(
                    step_number=1,
                    title="Initial Investigation",
                    description="Conduct initial investigation and assessment",
                    priority=InvestigationPriority.URGENT,
                    estimated_time_minutes=120,
                    expected_outputs=["Initial findings", "Scope assessment"],
                    success_criteria=["Basic understanding achieved"],
                ),
            ]
    
    async def _create_investigation_step(
        self,
        step_number: int,
        step_name: str,
        category: EventCategory,
        complexity: InvestigationComplexity,
        context: SecurityContext,
    ) -> InvestigationStep:
        """Create a detailed investigation step."""
        # Map step names to detailed configurations
        step_configs = {
            "Initial triage and classification": {
                "title": "Initial Triage and Event Classification",
                "description": "Conduct rapid assessment to classify the incident and determine initial response priorities",
                "priority": InvestigationPriority.IMMEDIATE,
                "estimated_time": 60,
                "evidence_types": [EvidenceType.SYSTEM_LOGS, EvidenceType.NETWORK_TRAFFIC],
                "skills": ["incident_response", "threat_assessment"],
                "tools": ["SIEM", "Threat Intelligence Platform"],
            },
            "Basic log analysis and correlation": {
                "title": "Log Analysis and Event Correlation",
                "description": "Analyze system and security logs to understand the sequence of events and identify related activities",
                "priority": InvestigationPriority.URGENT,
                "estimated_time": 180,
                "evidence_types": [EvidenceType.SYSTEM_LOGS, EvidenceType.AUTHENTICATION_LOGS],
                "skills": ["log_analysis", "data_correlation"],
                "tools": ["Splunk", "ELK Stack", "Log analysis tools"],
            },
            "Impact assessment and containment": {
                "title": "Impact Assessment and Containment",
                "description": "Assess the scope of impact and implement appropriate containment measures",
                "priority": InvestigationPriority.HIGH,
                "estimated_time": 120,
                "evidence_types": [EvidenceType.USER_ACTIVITY, EvidenceType.NETWORK_TRAFFIC],
                "skills": ["impact_assessment", "incident_containment"],
                "tools": ["Network isolation tools", "Access control systems"],
            },
            "Documentation and reporting": {
                "title": "Documentation and Preliminary Reporting",
                "description": "Document findings and prepare preliminary incident report",
                "priority": InvestigationPriority.MEDIUM,
                "estimated_time": 90,
                "evidence_types": [],
                "skills": ["documentation", "report_writing"],
                "tools": ["Documentation templates", "Reporting tools"],
            },
        }
        
        config = step_configs.get(step_name, {
            "title": step_name.title(),
            "description": f"Execute {step_name} procedures",
            "priority": InvestigationPriority.MEDIUM,
            "estimated_time": 120,
            "evidence_types": [],
            "skills": ["general_investigation"],
            "tools": ["Standard investigation tools"],
        })
        
        return InvestigationStep(
            step_number=step_number,
            title=config["title"],
            description=config["description"],
            priority=config["priority"],
            estimated_time_minutes=config["estimated_time"],
            required_skills=config["skills"],
            evidence_types=config["evidence_types"],
            recommended_tools=config["tools"],
            expected_outputs=[f"Completed {step_name}"],
            success_criteria=[f"{step_name} objectives achieved"],
        )
    
    async def _get_category_specific_steps(
        self,
        category: EventCategory,
        complexity: InvestigationComplexity,
        start_step_number: int,
        context: SecurityContext,
    ) -> List[InvestigationStep]:
        """Get category-specific investigation steps."""
        steps = []
        
        if category == EventCategory.MALWARE:
            steps.append(InvestigationStep(
                step_number=start_step_number,
                title="Malware Analysis and Attribution",
                description="Conduct detailed malware analysis to understand capabilities and attribution",
                priority=InvestigationPriority.HIGH,
                estimated_time_minutes=240,
                required_skills=["malware_analysis", "reverse_engineering"],
                evidence_types=[EvidenceType.FILE_ARTIFACTS, EvidenceType.MEMORY_DUMPS],
                recommended_tools=["IDA Pro", "Cuckoo Sandbox", "Volatility"],
                expected_outputs=["Malware analysis report", "IOC extraction"],
                success_criteria=["Malware capabilities understood", "Attribution assessed"],
            ))
        
        elif category == EventCategory.PHISHING:
            steps.append(InvestigationStep(
                step_number=start_step_number,
                title="Email Infrastructure Analysis",
                description="Analyze phishing email infrastructure and identify affected users",
                priority=InvestigationPriority.HIGH,
                estimated_time_minutes=180,
                required_skills=["email_security", "threat_intelligence"],
                evidence_types=[EvidenceType.EMAIL_RECORDS, EvidenceType.AUTHENTICATION_LOGS],
                recommended_tools=["Email security tools", "Domain analysis tools"],
                expected_outputs=["Infrastructure mapping", "User impact assessment"],
                success_criteria=["Phishing infrastructure mapped", "Affected users identified"],
            ))
        
        return steps
    
    async def _get_compliance_steps(
        self, 
        context: SecurityContext, 
        start_step_number: int
    ) -> List[InvestigationStep]:
        """Get compliance-specific investigation steps."""
        steps = []
        
        # Determine applicable compliance frameworks
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            steps.append(InvestigationStep(
                step_number=start_step_number,
                title="Security Classification Compliance Review",
                description="Ensure investigation procedures comply with security classification requirements",
                priority=InvestigationPriority.HIGH,
                estimated_time_minutes=60,
                required_skills=["compliance", "security_clearance"],
                expected_outputs=["Compliance verification", "Classification review"],
                success_criteria=["Classification requirements met"],
            ))
        
        return steps
    
    def _calculate_resource_requirements(
        self, 
        steps: List[InvestigationStep]
    ) -> Tuple[float, List[str], List[str]]:
        """Calculate total resource requirements."""
        total_minutes = sum(step.estimated_time_minutes for step in steps)
        total_hours = total_minutes / 60.0
        
        # Collect unique skills and tools
        all_skills = set()
        all_tools = set()
        
        for step in steps:
            all_skills.update(step.required_skills)
            all_tools.update(step.recommended_tools)
        
        return total_hours, list(all_skills), list(all_tools)
    
    def _identify_evidence_targets(
        self, 
        category: EventCategory, 
        context: SecurityContext
    ) -> List[str]:
        """Identify key evidence targets for collection."""
        playbook = self._investigation_playbooks.get(category, {})
        critical_evidence = playbook.get("critical_evidence", [])
        
        targets = []
        for evidence_type in critical_evidence:
            guide = self._evidence_collection_guides.get(evidence_type, {})
            targets.append(f"{evidence_type.value}: {guide.get('description', 'Evidence collection required')}")
        
        return targets
    
    def _determine_retention_requirements(
        self, 
        category: EventCategory, 
        context: SecurityContext
    ) -> Dict[str, int]:
        """Determine data retention requirements."""
        requirements = {}
        
        playbook = self._investigation_playbooks.get(category, {})
        critical_evidence = playbook.get("critical_evidence", [])
        
        for evidence_type in critical_evidence:
            guide = self._evidence_collection_guides.get(evidence_type, {})
            retention_days = guide.get("retention_period_days", 90)
            requirements[evidence_type.value] = retention_days
        
        return requirements
    
    def _define_escalation_triggers(
        self, 
        severity: ThreatSeverity, 
        context: SecurityContext
    ) -> List[str]:
        """Define escalation triggers for the investigation."""
        escalation_config = self._escalation_procedures.get(severity, {})
        return escalation_config.get("escalation_triggers", [
            "Investigation timeline at risk",
            "Additional resources required",
            "External expertise needed",
        ])
    
    def _define_custody_requirements(self, category: EventCategory) -> List[str]:
        """Define chain of custody requirements."""
        return [
            "Maintain detailed evidence logs",
            "Document all access and handling",
            "Secure evidence storage with encryption",
            "Regular integrity verification",
            "Access control and audit trails",
        ]
    
    async def _estimate_attack_timeline(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Estimate attack timeline based on available information."""
        timeline = []
        
        # Add event timestamp as key point
        timeline.append({
            "timestamp": context.timestamp.isoformat(),
            "event": "Security event detected",
            "description": f"Event {context.event_id} detected by {context.source_system}",
            "confidence": "HIGH",
        })
        
        # Estimate potential earlier events
        estimated_start = context.timestamp - timedelta(hours=24)
        timeline.insert(0, {
            "timestamp": estimated_start.isoformat(),
            "event": "Potential attack initiation",
            "description": "Estimated time of initial compromise or attack start",
            "confidence": "LOW",
        })
        
        return timeline
    
    def _identify_impact_areas(
        self, 
        context: SecurityContext, 
        category: EventCategory
    ) -> List[str]:
        """Identify potential impact areas."""
        impact_areas = []
        
        # Base impact areas by category
        category_impacts = {
            EventCategory.MALWARE: ["System integrity", "Data confidentiality", "Operations"],
            EventCategory.PHISHING: ["User credentials", "Email security", "Trust relationships"],
            EventCategory.INTRUSION: ["System access", "Data exposure", "Network security"],
            EventCategory.DATA_EXFILTRATION: ["Data confidentiality", "Regulatory compliance", "Reputation"],
        }
        
        impact_areas.extend(category_impacts.get(category, ["General security posture"]))
        
        # Add context-specific impacts
        if context.asset_info:
            impact_areas.append("Critical asset compromise")
        
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            impact_areas.extend(["National security", "Classification spillage"])
        
        return impact_areas
    
    def _identify_critical_path(self, steps: List[InvestigationStep]) -> List[int]:
        """Identify the critical path through investigation steps."""
        # Simple implementation - in practice, this would use dependency analysis
        critical_steps = []
        
        for step in steps:
            if step.priority in [InvestigationPriority.IMMEDIATE, InvestigationPriority.URGENT]:
                critical_steps.append(step.step_number)
        
        return critical_steps
    
    def _identify_parallel_workflows(self, steps: List[InvestigationStep]) -> List[List[int]]:
        """Identify steps that can be executed in parallel."""
        # Group steps that don't have dependencies on each other
        parallel_groups = []
        
        # Simple grouping by priority - in practice, this would analyze dependencies
        priority_groups = {}
        for step in steps:
            priority = step.priority.value
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(step.step_number)
        
        # Return groups with more than one step
        for group in priority_groups.values():
            if len(group) > 1:
                parallel_groups.append(group)
        
        return parallel_groups
    
    def _define_communication_plan(self, severity: ThreatSeverity) -> Dict[str, List[str]]:
        """Define stakeholder communication plan."""
        escalation_config = self._escalation_procedures.get(severity, {})
        
        return {
            "immediate_notifications": escalation_config.get("immediate_notifications", ["Security Team"]),
            "regular_updates": ["Incident Commander", "Management"],
            "final_report": ["All stakeholders", "Compliance team"],
        }
    
    def _determine_reporting_requirements(
        self, 
        context: SecurityContext, 
        category: EventCategory
    ) -> List[str]:
        """Determine reporting requirements for the investigation."""
        requirements = [
            "Internal incident report",
            "Timeline of events",
            "Impact assessment",
            "Lessons learned document",
        ]
        
        # Add compliance-specific requirements
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            requirements.extend([
                "Security classification review",
                "Authority notification assessment",
            ])
        
        # Add category-specific requirements
        if category == EventCategory.DATA_EXFILTRATION:
            requirements.extend([
                "Data breach notification assessment",
                "Regulatory compliance review",
            ])
        
        return requirements
    
    def _assess_recommendation_confidence(
        self, 
        context: SecurityContext, 
        processing_result: Optional[Dict[str, Any]]
    ) -> float:
        """Assess confidence in the investigation recommendation."""
        confidence = 0.8  # Base confidence
        
        if processing_result:
            nlp_confidence = processing_result.get("confidence_score", 0.5)
            confidence = (confidence + nlp_confidence) / 2
        
        if context.threat_indicators:
            confidence += 0.1
        
        if context.mitre_tactics:
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _assess_recommendation_completeness(
        self, 
        steps: List[InvestigationStep], 
        evidence_targets: List[str]
    ) -> float:
        """Assess completeness of the investigation recommendation."""
        completeness = 0.7  # Base completeness
        
        if len(steps) >= 5:
            completeness += 0.1
        
        if evidence_targets:
            completeness += 0.1
        
        # Check for diverse step types
        step_priorities = {step.priority for step in steps}
        if len(step_priorities) >= 3:
            completeness += 0.1
        
        return min(1.0, completeness)
    
    def _assess_investigation_risk(
        self, 
        context: SecurityContext, 
        complexity: InvestigationComplexity
    ) -> str:
        """Assess risks associated with the investigation."""
        risk_factors = []
        
        if complexity in [InvestigationComplexity.COMPLEX, InvestigationComplexity.ADVANCED]:
            risk_factors.append("High complexity may require specialized expertise")
        
        if context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            risk_factors.append("Classified information handling requirements")
        
        if context.threat_indicators:
            risk_factors.append("Active threat indicators present")
        
        if not risk_factors:
            return "LOW - Standard investigation procedures applicable"
        else:
            return f"MODERATE - {'; '.join(risk_factors)}"
    
    def _define_success_indicators(
        self, 
        category: EventCategory, 
        complexity: InvestigationComplexity
    ) -> List[str]:
        """Define success indicators for the investigation."""
        indicators = [
            "Threat actor identification or attribution",
            "Complete timeline reconstruction",
            "Impact scope fully determined",
            "Containment measures effective",
            "Remediation plan implemented",
        ]
        
        if complexity in [InvestigationComplexity.COMPLEX, InvestigationComplexity.ADVANCED]:
            indicators.extend([
                "Advanced threat techniques identified",
                "Threat intelligence production",
                "Strategic security improvements identified",
            ])
        
        return indicators
    
    def _define_completion_criteria(
        self, 
        category: EventCategory, 
        severity: ThreatSeverity
    ) -> List[str]:
        """Define investigation completion criteria."""
        criteria = [
            "All investigation objectives achieved",
            "Evidence collection completed",
            "Impact assessment finalized",
            "Stakeholder notifications completed",
            "Final report submitted",
        ]
        
        if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            criteria.extend([
                "Regulatory compliance verified",
                "Lessons learned documented",
                "Security improvements implemented",
            ])
        
        return criteria
    
    def _update_advisory_metrics(
        self, 
        complexity: InvestigationComplexity, 
        priority: InvestigationPriority, 
        start_time: datetime
    ) -> None:
        """Update advisory performance metrics."""
        self._advisory_metrics["total_recommendations"] += 1
        
        # Update complexity distribution
        complexity_key = complexity.value
        if complexity_key not in self._advisory_metrics["complexity_distribution"]:
            self._advisory_metrics["complexity_distribution"][complexity_key] = 0
        self._advisory_metrics["complexity_distribution"][complexity_key] += 1
        
        # Update priority distribution
        priority_key = priority.value
        if priority_key not in self._advisory_metrics["priority_distribution"]:
            self._advisory_metrics["priority_distribution"][priority_key] = 0
        self._advisory_metrics["priority_distribution"][priority_key] += 1
        
        # Update average generation time
        generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        current_avg = self._advisory_metrics["average_generation_time"]
        count = self._advisory_metrics["total_recommendations"]
        
        self._advisory_metrics["average_generation_time"] = (
            (current_avg * (count - 1)) + generation_time
        ) / count
    
    def get_advisory_metrics(self) -> Dict[str, Any]:
        """Get investigation advisory metrics."""
        return self._advisory_metrics.copy()
    
    def get_investigation_templates(self) -> Dict[str, Any]:
        """Get available investigation templates and workflows."""
        return {
            "playbooks": list(self._investigation_playbooks.keys()),
            "complexity_levels": list(self._workflow_templates.keys()),
            "evidence_types": list(self._evidence_collection_guides.keys()),
            "escalation_procedures": list(self._escalation_procedures.keys()),
        }