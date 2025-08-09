"""
Response Selector for iSECTECH Automated Decision Making.

This module provides intelligent response selection capabilities that choose
appropriate security responses based on threat context, risk assessment,
and organizational policies tailored for iSECTECH operations.
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
from .decision_models import DecisionContext, DecisionUrgency, DecisionConfidence


# Configure logging
logger = logging.getLogger(__name__)


class ResponsePriority(str, Enum):
    """Priority levels for response actions."""
    CRITICAL = "CRITICAL"         # Execute immediately, highest priority
    HIGH = "HIGH"                 # Execute within minutes
    MEDIUM = "MEDIUM"             # Execute within hours
    LOW = "LOW"                   # Execute within days
    BACKGROUND = "BACKGROUND"     # Execute when resources available


class ResponseCategory(str, Enum):
    """Categories of security responses."""
    IMMEDIATE_CONTAINMENT = "IMMEDIATE_CONTAINMENT"     # Stop threat spread
    THREAT_NEUTRALIZATION = "THREAT_NEUTRALIZATION"    # Eliminate threat
    EVIDENCE_PRESERVATION = "EVIDENCE_PRESERVATION"    # Preserve for analysis
    SYSTEM_PROTECTION = "SYSTEM_PROTECTION"            # Protect critical systems
    USER_NOTIFICATION = "USER_NOTIFICATION"            # Inform stakeholders
    REGULATORY_COMPLIANCE = "REGULATORY_COMPLIANCE"    # Meet compliance requirements
    BUSINESS_CONTINUITY = "BUSINESS_CONTINUITY"        # Maintain operations
    INTELLIGENCE_GATHERING = "INTELLIGENCE_GATHERING"   # Collect threat intel


class ResponseComplexity(str, Enum):
    """Complexity levels for response execution."""
    SIMPLE = "SIMPLE"             # Single action, automated
    MODERATE = "MODERATE"         # Multiple coordinated actions
    COMPLEX = "COMPLEX"           # Multi-stage, may require human oversight
    ADVANCED = "ADVANCED"         # Requires specialized skills/tools


class ResponseAction(BaseModel):
    """Individual response action with execution details."""
    
    # Action metadata
    action_id: str = Field(..., description="Unique action identifier")
    name: str = Field(..., description="Human-readable action name")
    description: str = Field(..., description="Detailed action description")
    
    # Classification and priority
    category: ResponseCategory = Field(..., description="Response category")
    priority: ResponsePriority = Field(..., description="Execution priority")
    complexity: ResponseComplexity = Field(..., description="Execution complexity")
    
    # Execution parameters
    estimated_duration_minutes: int = Field(..., description="Estimated execution time")
    requires_approval: bool = Field(default=False, description="Requires manual approval")
    auto_executable: bool = Field(default=True, description="Can be executed automatically")
    
    # Dependencies and constraints
    prerequisites: List[str] = Field(default_factory=list, description="Required prerequisite actions")
    conflicts: List[str] = Field(default_factory=list, description="Conflicting actions")
    resource_requirements: List[str] = Field(default_factory=list, description="Required resources")
    
    # Impact assessment
    effectiveness_score: float = Field(..., description="Expected effectiveness (0-1)")
    risk_score: float = Field(..., description="Risk of negative impact (0-1)")
    business_impact_score: float = Field(..., description="Business disruption risk (0-1)")
    
    # Execution details
    execution_method: str = Field(..., description="How to execute the action")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Action parameters")
    rollback_procedure: str = Field(..., description="How to rollback if needed")
    
    # Validation and monitoring
    success_criteria: List[str] = Field(default_factory=list, description="Success indicators")
    monitoring_requirements: List[str] = Field(default_factory=list, description="What to monitor")
    validation_methods: List[str] = Field(default_factory=list, description="How to validate success")
    
    @validator("effectiveness_score", "risk_score", "business_impact_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v
    
    @validator("estimated_duration_minutes")
    def validate_duration(cls, v):
        """Validate duration is reasonable."""
        if v <= 0 or v > 2880:  # Max 48 hours
            raise ValueError("Duration must be between 1 and 2880 minutes")
        return v


class ResponsePlan(BaseModel):
    """Complete response plan with coordinated actions."""
    
    # Plan metadata
    plan_id: str = Field(..., description="Unique plan identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    context_id: str = Field(..., description="Source decision context ID")
    
    # Plan overview
    name: str = Field(..., description="Response plan name")
    description: str = Field(..., description="Plan description")
    objective: str = Field(..., description="Primary objective")
    
    # Actions and execution
    actions: List[ResponseAction] = Field(..., description="Ordered list of actions")
    execution_phases: List[List[str]] = Field(default_factory=list, description="Parallel execution phases")
    critical_path: List[str] = Field(default_factory=list, description="Critical path action IDs")
    
    # Timing and coordination
    total_estimated_duration: int = Field(..., description="Total estimated time in minutes")
    parallel_execution_possible: bool = Field(default=False, description="Can actions run in parallel")
    coordination_requirements: List[str] = Field(default_factory=list, description="Coordination needs")
    
    # Quality and assessment
    overall_effectiveness: float = Field(..., description="Overall plan effectiveness (0-1)")
    overall_risk: float = Field(..., description="Overall plan risk (0-1)")
    confidence_score: float = Field(..., description="Plan confidence (0-1)")
    
    # Approval and authorization
    requires_approval: bool = Field(..., description="Requires manual approval")
    approval_level: str = Field(..., description="Required approval level")
    auto_executable: bool = Field(..., description="Can be fully automated")
    
    # Contingency and fallback
    contingency_actions: List[ResponseAction] = Field(default_factory=list, description="Backup actions")
    escalation_triggers: List[str] = Field(default_factory=list, description="When to escalate")
    rollback_plan: str = Field(..., description="How to rollback the entire plan")
    
    # Monitoring and validation
    success_indicators: List[str] = Field(default_factory=list, description="Plan success indicators")
    monitoring_points: List[str] = Field(default_factory=list, description="What to monitor during execution")
    
    @validator("overall_effectiveness", "overall_risk", "confidence_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class ResponseSelector:
    """
    Production-grade response selector for iSECTECH automated security operations.
    
    Provides intelligent selection of security responses based on threat context,
    risk assessment, and organizational policies with coordination and optimization.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the response selector."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Response libraries and configurations
        self._response_library = self._load_response_library()
        self._response_templates = self._load_response_templates()
        self._coordination_rules = self._load_coordination_rules()
        self._optimization_strategies = self._load_optimization_strategies()
        
        # iSECTECH-specific configurations
        self._isectech_response_matrix = self._load_isectech_response_matrix()
        self._business_impact_models = self._load_business_impact_models()
        self._asset_protection_rules = self._load_asset_protection_rules()
        self._compliance_response_mappings = self._load_compliance_response_mappings()
        
        # Performance tracking
        self._selection_metrics = {
            "total_plans_generated": 0,
            "average_plan_effectiveness": 0.0,
            "average_generation_time": 0.0,
            "successful_executions": 0,
            "failed_executions": 0,
        }
        
        logger.info("Response selector initialized successfully")
    
    def _load_response_library(self) -> Dict[str, Dict[str, Any]]:
        """Load comprehensive response action library."""
        return {
            # Immediate containment responses
            "network_isolation": {
                "category": ResponseCategory.IMMEDIATE_CONTAINMENT,
                "priority": ResponsePriority.CRITICAL,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 5,
                "effectiveness": 0.9,
                "risk": 0.3,
                "business_impact": 0.6,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "network_acl_update",
                "success_criteria": ["network_connectivity_blocked", "traffic_analysis_confirms_isolation"],
                "rollback": "restore_network_access",
            },
            
            "system_quarantine": {
                "category": ResponseCategory.IMMEDIATE_CONTAINMENT,
                "priority": ResponsePriority.CRITICAL,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 3,
                "effectiveness": 0.85,
                "risk": 0.2,
                "business_impact": 0.4,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "endpoint_quarantine_api",
                "success_criteria": ["system_isolated", "no_network_communication"],
                "rollback": "remove_quarantine_status",
            },
            
            "account_lockout": {
                "category": ResponseCategory.IMMEDIATE_CONTAINMENT,
                "priority": ResponsePriority.HIGH,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 2,
                "effectiveness": 0.8,
                "risk": 0.1,
                "business_impact": 0.3,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "identity_management_api",
                "success_criteria": ["account_disabled", "authentication_blocked"],
                "rollback": "enable_account_with_mfa_reset",
            },
            
            # Threat neutralization responses
            "malware_removal": {
                "category": ResponseCategory.THREAT_NEUTRALIZATION,
                "priority": ResponsePriority.HIGH,
                "complexity": ResponseComplexity.MODERATE,
                "duration": 30,
                "effectiveness": 0.9,
                "risk": 0.3,
                "business_impact": 0.2,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "antimalware_scan_and_clean",
                "success_criteria": ["malware_removed", "system_clean_scan"],
                "rollback": "restore_from_backup_if_system_damage",
            },
            
            "threat_signature_update": {
                "category": ResponseCategory.THREAT_NEUTRALIZATION,
                "priority": ResponsePriority.MEDIUM,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 10,
                "effectiveness": 0.7,
                "risk": 0.1,
                "business_impact": 0.1,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "security_appliance_update",
                "success_criteria": ["signatures_updated", "threat_blocked"],
                "rollback": "revert_signature_update",
            },
            
            # Evidence preservation responses
            "memory_dump_collection": {
                "category": ResponseCategory.EVIDENCE_PRESERVATION,
                "priority": ResponsePriority.HIGH,
                "complexity": ResponseComplexity.MODERATE,
                "duration": 45,
                "effectiveness": 0.95,
                "risk": 0.1,
                "business_impact": 0.2,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "forensic_memory_acquisition",
                "success_criteria": ["memory_dump_created", "chain_of_custody_established"],
                "rollback": "no_rollback_needed",
            },
            
            "log_preservation": {
                "category": ResponseCategory.EVIDENCE_PRESERVATION,
                "priority": ResponsePriority.MEDIUM,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 15,
                "effectiveness": 0.85,
                "risk": 0.05,
                "business_impact": 0.1,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "log_export_and_archive",
                "success_criteria": ["logs_exported", "integrity_verified"],
                "rollback": "no_rollback_needed",
            },
            
            # System protection responses
            "backup_verification": {
                "category": ResponseCategory.SYSTEM_PROTECTION,
                "priority": ResponsePriority.MEDIUM,
                "complexity": ResponseComplexity.MODERATE,
                "duration": 60,
                "effectiveness": 0.8,
                "risk": 0.05,
                "business_impact": 0.1,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "backup_integrity_check",
                "success_criteria": ["backups_verified", "recovery_tested"],
                "rollback": "no_rollback_needed",
            },
            
            "patch_deployment": {
                "category": ResponseCategory.SYSTEM_PROTECTION,
                "priority": ResponsePriority.MEDIUM,
                "complexity": ResponseComplexity.COMPLEX,
                "duration": 120,
                "effectiveness": 0.9,
                "risk": 0.3,
                "business_impact": 0.4,
                "auto_executable": False,
                "requires_approval": True,
                "execution_method": "automated_patch_management",
                "success_criteria": ["patches_applied", "vulnerabilities_closed"],
                "rollback": "rollback_patches_if_issues",
            },
            
            # Notification responses
            "stakeholder_notification": {
                "category": ResponseCategory.USER_NOTIFICATION,
                "priority": ResponsePriority.HIGH,
                "complexity": ResponseComplexity.SIMPLE,
                "duration": 5,
                "effectiveness": 0.7,
                "risk": 0.05,
                "business_impact": 0.1,
                "auto_executable": True,
                "requires_approval": False,
                "execution_method": "notification_system_api",
                "success_criteria": ["notifications_sent", "delivery_confirmed"],
                "rollback": "send_all_clear_notification",
            },
            
            "regulatory_notification": {
                "category": ResponseCategory.REGULATORY_COMPLIANCE,
                "priority": ResponsePriority.HIGH,
                "complexity": ResponseComplexity.MODERATE,
                "duration": 30,
                "effectiveness": 0.95,
                "risk": 0.1,
                "business_impact": 0.2,
                "auto_executable": False,
                "requires_approval": True,
                "execution_method": "compliance_reporting_system",
                "success_criteria": ["authorities_notified", "compliance_documented"],
                "rollback": "no_rollback_possible",
            },
        }
    
    def _load_response_templates(self) -> Dict[EventCategory, List[str]]:
        """Load response templates for different threat categories."""
        return {
            EventCategory.MALWARE: [
                "system_quarantine",
                "malware_removal", 
                "network_isolation",
                "memory_dump_collection",
                "log_preservation",
                "stakeholder_notification",
                "threat_signature_update",
            ],
            EventCategory.PHISHING: [
                "account_lockout",
                "threat_signature_update",
                "stakeholder_notification",
                "log_preservation",
                "regulatory_notification",
            ],
            EventCategory.INTRUSION: [
                "account_lockout",
                "network_isolation",
                "memory_dump_collection",
                "log_preservation",
                "backup_verification",
                "stakeholder_notification",
                "patch_deployment",
            ],
            EventCategory.DATA_EXFILTRATION: [
                "network_isolation",
                "account_lockout",
                "memory_dump_collection",
                "log_preservation",
                "regulatory_notification",
                "stakeholder_notification",
                "backup_verification",
            ],
            EventCategory.INSIDER_THREAT: [
                "account_lockout",
                "log_preservation",
                "memory_dump_collection",
                "stakeholder_notification",
                "regulatory_notification",
            ],
        }
    
    def _load_coordination_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load coordination rules for action execution."""
        return {
            "sequential_requirements": {
                # Must execute log preservation before system modifications
                "log_preservation": {"before": ["system_quarantine", "malware_removal", "patch_deployment"]},
                "memory_dump_collection": {"before": ["system_quarantine", "malware_removal"]},
                "backup_verification": {"before": ["patch_deployment", "system_modifications"]},
            },
            "parallel_capabilities": {
                # These actions can run in parallel
                "notification_actions": ["stakeholder_notification", "regulatory_notification"],
                "preservation_actions": ["log_preservation", "memory_dump_collection"],
                "signature_updates": ["threat_signature_update", "patch_deployment"],
            },
            "mutual_exclusions": {
                # These actions cannot run together
                "network_isolation": ["patch_deployment"],  # Can't patch if isolated
                "system_quarantine": ["malware_removal"],   # Can't remove if quarantined
            },
            "resource_conflicts": {
                # Actions that compete for the same resources
                "high_cpu_actions": ["malware_removal", "patch_deployment", "backup_verification"],
                "network_intensive": ["memory_dump_collection", "log_preservation", "backup_verification"],
            },
        }
    
    def _load_optimization_strategies(self) -> Dict[str, Dict[str, Any]]:
        """Load optimization strategies for response planning."""
        return {
            "effectiveness_maximization": {
                "priority_weight": 0.4,
                "effectiveness_weight": 0.4,
                "risk_weight": -0.2,
                "description": "Maximize overall response effectiveness",
            },
            "risk_minimization": {
                "priority_weight": 0.3,
                "effectiveness_weight": 0.2,
                "risk_weight": -0.5,
                "description": "Minimize operational and business risk",
            },
            "speed_optimization": {
                "priority_weight": 0.5,
                "effectiveness_weight": 0.3,
                "risk_weight": -0.2,
                "description": "Minimize response time",
            },
            "business_continuity": {
                "priority_weight": 0.2,
                "effectiveness_weight": 0.3,
                "risk_weight": -0.1,
                "business_impact_weight": -0.4,
                "description": "Minimize business disruption",
            },
        }
    
    def _load_isectech_response_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Load iSECTECH-specific response matrix."""
        return {
            "customer_data_protection": {
                "priority_actions": [
                    "network_isolation",
                    "account_lockout", 
                    "regulatory_notification",
                    "log_preservation",
                ],
                "execution_order": "parallel_where_possible",
                "approval_required": False,
                "max_business_impact": 0.7,
            },
            "system_availability": {
                "priority_actions": [
                    "threat_signature_update",
                    "malware_removal",
                    "backup_verification",
                    "stakeholder_notification",
                ],
                "execution_order": "minimize_downtime",
                "approval_required": False,
                "max_business_impact": 0.5,
            },
            "regulatory_compliance": {
                "priority_actions": [
                    "log_preservation",
                    "memory_dump_collection",
                    "regulatory_notification",
                    "stakeholder_notification",
                ],
                "execution_order": "evidence_first",
                "approval_required": True,
                "max_business_impact": 0.3,
            },
            "classified_data_handling": {
                "priority_actions": [
                    "network_isolation",
                    "system_quarantine",
                    "memory_dump_collection",
                    "log_preservation",
                ],
                "execution_order": "containment_first",
                "approval_required": True,
                "max_business_impact": 0.8,
            },
        }
    
    def _load_business_impact_models(self) -> Dict[str, Dict[str, Any]]:
        """Load business impact assessment models."""
        return {
            "customer_impact": {
                "network_isolation": 0.6,
                "system_quarantine": 0.4,
                "account_lockout": 0.3,
                "malware_removal": 0.2,
                "patch_deployment": 0.5,
            },
            "revenue_impact": {
                "network_isolation": 0.8,
                "system_quarantine": 0.5,
                "patch_deployment": 0.6,
                "backup_verification": 0.3,
            },
            "operational_impact": {
                "network_isolation": 0.7,
                "system_quarantine": 0.6,
                "account_lockout": 0.4,
                "patch_deployment": 0.7,
                "malware_removal": 0.3,
            },
        }
    
    def _load_asset_protection_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load asset protection rules for different asset types."""
        return {
            "critical_databases": {
                "max_risk_threshold": 0.2,
                "required_actions": ["backup_verification", "log_preservation"],
                "prohibited_actions": ["system_quarantine"],
                "approval_required": True,
            },
            "customer_systems": {
                "max_risk_threshold": 0.3,
                "required_actions": ["stakeholder_notification", "regulatory_notification"],
                "prohibited_actions": [],
                "approval_required": False,
            },
            "development_systems": {
                "max_risk_threshold": 0.6,
                "required_actions": [],
                "prohibited_actions": [],
                "approval_required": False,
            },
            "backup_systems": {
                "max_risk_threshold": 0.1,
                "required_actions": ["network_isolation", "log_preservation"],
                "prohibited_actions": ["malware_removal"],
                "approval_required": True,
            },
        }
    
    def _load_compliance_response_mappings(self) -> Dict[str, List[str]]:
        """Load compliance framework response mappings."""
        return {
            "GDPR": [
                "log_preservation",
                "memory_dump_collection", 
                "regulatory_notification",
                "stakeholder_notification",
            ],
            "HIPAA": [
                "log_preservation",
                "regulatory_notification",
                "stakeholder_notification",
                "backup_verification",
            ],
            "PCI_DSS": [
                "network_isolation",
                "log_preservation",
                "regulatory_notification",
                "patch_deployment",
            ],
            "SOX": [
                "log_preservation",
                "backup_verification",
                "stakeholder_notification",
                "regulatory_notification",
            ],
        }
    
    async def select_response(
        self,
        context: DecisionContext,
        optimization_strategy: str = "effectiveness_maximization",
        custom_constraints: Optional[Dict[str, Any]] = None,
    ) -> ResponsePlan:
        """
        Select optimal response plan based on context and constraints.
        
        Args:
            context: Decision context with threat and organizational information
            optimization_strategy: Strategy for optimizing response selection
            custom_constraints: Optional custom constraints and requirements
            
        Returns:
            Complete response plan with coordinated actions
        """
        start_time = datetime.utcnow()
        plan_id = f"response-plan-{context.context_id}-{int(start_time.timestamp())}"
        
        try:
            logger.info(f"Selecting response plan for context {context.context_id}")
            
            # Audit log the selection request
            await self.audit_logger.log_security_event(
                event_type="RESPONSE_SELECTION_STARTED",
                details={
                    "context_id": context.context_id,
                    "plan_id": plan_id,
                    "optimization_strategy": optimization_strategy,
                    "tenant_id": context.tenant_id,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Determine threat category and applicable templates
            threat_category = self._determine_threat_category(context)
            candidate_actions = await self._get_candidate_actions(threat_category, context)
            
            # Apply constraints and filters
            filtered_actions = await self._apply_constraints(
                candidate_actions, context, custom_constraints
            )
            
            # Optimize action selection
            selected_actions = await self._optimize_selection(
                filtered_actions, context, optimization_strategy
            )
            
            # Create response actions
            response_actions = await self._create_response_actions(selected_actions, context)
            
            # Plan execution coordination
            execution_phases, critical_path = await self._plan_execution_coordination(
                response_actions, context
            )
            
            # Calculate plan metrics
            plan_metrics = await self._calculate_plan_metrics(response_actions, context)
            
            # Generate contingency and rollback plans
            contingency_actions = await self._generate_contingency_actions(
                response_actions, context
            )
            rollback_plan = await self._generate_rollback_plan(response_actions)
            
            # Create response plan
            plan = ResponsePlan(
                plan_id=plan_id,
                context_id=context.context_id,
                name=f"Response to {threat_category.value} - {context.threat_severity.value}",
                description=await self._generate_plan_description(response_actions, context),
                objective=await self._determine_plan_objective(threat_category, context),
                actions=response_actions,
                execution_phases=execution_phases,
                critical_path=critical_path,
                total_estimated_duration=plan_metrics["total_duration"],
                parallel_execution_possible=plan_metrics["parallel_possible"],
                coordination_requirements=await self._identify_coordination_requirements(response_actions),
                overall_effectiveness=plan_metrics["effectiveness"],
                overall_risk=plan_metrics["risk"],
                confidence_score=plan_metrics["confidence"],
                requires_approval=plan_metrics["requires_approval"],
                approval_level=await self._determine_approval_level(response_actions, context),
                auto_executable=plan_metrics["auto_executable"],
                contingency_actions=contingency_actions,
                escalation_triggers=await self._define_escalation_triggers(context, response_actions),
                rollback_plan=rollback_plan,
                success_indicators=await self._define_success_indicators(response_actions, context),
                monitoring_points=await self._define_monitoring_points(response_actions),
            )
            
            # Update metrics
            generation_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            self._update_selection_metrics(plan, generation_time)
            
            # Audit log successful selection
            await self.audit_logger.log_security_event(
                event_type="RESPONSE_SELECTION_COMPLETED",
                details={
                    "plan_id": plan_id,
                    "actions_count": len(response_actions),
                    "overall_effectiveness": plan.overall_effectiveness,
                    "requires_approval": plan.requires_approval,
                    "generation_time_ms": generation_time,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Response plan {plan_id} generated in {generation_time:.2f}ms")
            return plan
            
        except Exception as e:
            logger.error(f"Failed to select response plan: {e}")
            await self.audit_logger.log_security_event(
                event_type="RESPONSE_SELECTION_FAILED",
                details={
                    "plan_id": plan_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            raise
    
    def _determine_threat_category(self, context: DecisionContext) -> EventCategory:
        """Determine threat category from context."""
        # Try to get from risk assessment first
        if context.risk_assessment and hasattr(context.risk_assessment, 'threat_category'):
            return context.risk_assessment.threat_category
        
        # Fallback to event type analysis
        event_type = context.security_context.event_type.lower()
        
        if "malware" in event_type or "virus" in event_type:
            return EventCategory.MALWARE
        elif "phishing" in event_type or "social" in event_type:
            return EventCategory.PHISHING
        elif "intrusion" in event_type or "breach" in event_type:
            return EventCategory.INTRUSION
        elif "data" in event_type and ("exfiltration" in event_type or "leak" in event_type):
            return EventCategory.DATA_EXFILTRATION
        elif "insider" in event_type:
            return EventCategory.INSIDER_THREAT
        else:
            return EventCategory.NETWORK_ANOMALY
    
    async def _get_candidate_actions(
        self, 
        threat_category: EventCategory, 
        context: DecisionContext
    ) -> List[str]:
        """Get candidate actions for the threat category."""
        # Start with template actions
        template_actions = self._response_templates.get(threat_category, [])
        
        # Add iSECTECH-specific actions based on priority
        priorities = self._isectech_response_matrix
        
        # Determine primary concern
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            priority_key = "classified_data_handling"
        elif "customer" in context.business_impact.lower() or "client" in context.business_impact.lower():
            priority_key = "customer_data_protection"
        elif "compliance" in " ".join(context.compliance_requirements).lower():
            priority_key = "regulatory_compliance"
        else:
            priority_key = "system_availability"
        
        priority_actions = priorities.get(priority_key, {}).get("priority_actions", [])
        
        # Combine and deduplicate
        all_actions = list(set(template_actions + priority_actions))
        
        # Add compliance-specific actions
        for framework in context.compliance_requirements:
            compliance_actions = self._compliance_response_mappings.get(framework, [])
            all_actions.extend(compliance_actions)
        
        return list(set(all_actions))  # Remove duplicates
    
    async def _apply_constraints(
        self,
        candidate_actions: List[str],
        context: DecisionContext,
        custom_constraints: Optional[Dict[str, Any]],
    ) -> List[str]:
        """Apply constraints to filter candidate actions."""
        filtered_actions = []
        
        for action in candidate_actions:
            action_config = self._response_library.get(action)
            if not action_config:
                continue
            
            # Apply business impact constraints
            if action_config["business_impact"] > 0.8:
                # High business impact requires high threat severity
                if context.threat_severity not in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
                    continue
            
            # Apply asset protection rules
            if context.affected_assets:
                asset_type = self._classify_assets(context.affected_assets)
                protection_rules = self._asset_protection_rules.get(asset_type, {})
                
                if action in protection_rules.get("prohibited_actions", []):
                    continue
                
                if action_config["risk"] > protection_rules.get("max_risk_threshold", 1.0):
                    continue
            
            # Apply security classification constraints
            if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
                # Higher scrutiny for classified data
                if action_config["risk"] > 0.3 and not action_config.get("requires_approval", False):
                    continue
            
            # Apply custom constraints
            if custom_constraints:
                if custom_constraints.get("max_business_impact", 1.0) < action_config["business_impact"]:
                    continue
                
                if action in custom_constraints.get("prohibited_actions", []):
                    continue
                
                if custom_constraints.get("auto_only", False) and not action_config["auto_executable"]:
                    continue
            
            filtered_actions.append(action)
        
        return filtered_actions
    
    def _classify_assets(self, assets: List[str]) -> str:
        """Classify assets to determine protection rules."""
        # Simple classification based on naming patterns
        asset_str = " ".join(assets).lower()
        
        if any(keyword in asset_str for keyword in ["database", "db", "sql", "mongo"]):
            return "critical_databases"
        elif any(keyword in asset_str for keyword in ["customer", "client", "prod", "production"]):
            return "customer_systems"
        elif any(keyword in asset_str for keyword in ["backup", "archive", "recovery"]):
            return "backup_systems"
        elif any(keyword in asset_str for keyword in ["dev", "test", "staging"]):
            return "development_systems"
        else:
            return "customer_systems"  # Default to higher protection
    
    async def _optimize_selection(
        self,
        filtered_actions: List[str],
        context: DecisionContext,
        optimization_strategy: str,
    ) -> List[str]:
        """Optimize action selection based on strategy."""
        strategy_config = self._optimization_strategies.get(
            optimization_strategy, 
            self._optimization_strategies["effectiveness_maximization"]
        )
        
        # Score each action
        action_scores = []
        
        for action in filtered_actions:
            action_config = self._response_library.get(action, {})
            
            # Calculate weighted score
            score = 0.0
            
            # Priority component (urgency-based)
            priority_score = self._calculate_priority_score(action_config, context)
            score += strategy_config.get("priority_weight", 0.3) * priority_score
            
            # Effectiveness component
            effectiveness = action_config.get("effectiveness", 0.5)
            score += strategy_config.get("effectiveness_weight", 0.4) * effectiveness
            
            # Risk component (negative)
            risk = action_config.get("risk", 0.5)
            score += strategy_config.get("risk_weight", -0.2) * risk
            
            # Business impact component (negative)
            business_impact = action_config.get("business_impact", 0.5)
            score += strategy_config.get("business_impact_weight", -0.1) * business_impact
            
            action_scores.append((action, score))
        
        # Sort by score and select top actions
        action_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Select actions, avoiding conflicts
        selected_actions = []
        coordination_rules = self._coordination_rules
        
        for action, score in action_scores:
            # Check for conflicts with already selected actions
            conflicts = coordination_rules.get("mutual_exclusions", {}).get(action, [])
            if any(conflict in selected_actions for conflict in conflicts):
                continue
            
            selected_actions.append(action)
            
            # Limit to reasonable number of actions
            if len(selected_actions) >= 5:
                break
        
        return selected_actions
    
    def _calculate_priority_score(self, action_config: Dict[str, Any], context: DecisionContext) -> float:
        """Calculate priority score for an action."""
        base_priority = {
            ResponsePriority.CRITICAL: 1.0,
            ResponsePriority.HIGH: 0.8,
            ResponsePriority.MEDIUM: 0.6,
            ResponsePriority.LOW: 0.4,
            ResponsePriority.BACKGROUND: 0.2,
        }.get(ResponsePriority(action_config.get("priority", "MEDIUM")), 0.6)
        
        # Adjust based on threat severity
        severity_multiplier = {
            ThreatSeverity.CRITICAL: 1.2,
            ThreatSeverity.HIGH: 1.0,
            ThreatSeverity.MEDIUM: 0.8,
            ThreatSeverity.LOW: 0.6,
            ThreatSeverity.INFORMATIONAL: 0.4,
        }.get(context.threat_severity, 0.8)
        
        return min(1.0, base_priority * severity_multiplier)
    
    async def _create_response_actions(
        self, 
        selected_actions: List[str], 
        context: DecisionContext
    ) -> List[ResponseAction]:
        """Create detailed response action objects."""
        response_actions = []
        
        for i, action_name in enumerate(selected_actions):
            action_config = self._response_library.get(action_name, {})
            
            # Generate unique action ID
            action_id = f"action-{context.context_id}-{i+1}-{action_name}"
            
            # Create response action
            action = ResponseAction(
                action_id=action_id,
                name=action_name.replace("_", " ").title(),
                description=await self._generate_action_description(action_name, context),
                category=ResponseCategory(action_config.get("category", "SYSTEM_PROTECTION")),
                priority=ResponsePriority(action_config.get("priority", "MEDIUM")),
                complexity=ResponseComplexity(action_config.get("complexity", "MODERATE")),
                estimated_duration_minutes=action_config.get("duration", 30),
                requires_approval=action_config.get("requires_approval", False),
                auto_executable=action_config.get("auto_executable", True),
                prerequisites=await self._determine_prerequisites(action_name, selected_actions),
                conflicts=await self._determine_conflicts(action_name, selected_actions),
                resource_requirements=await self._determine_resource_requirements(action_name),
                effectiveness_score=action_config.get("effectiveness", 0.7),
                risk_score=action_config.get("risk", 0.3),
                business_impact_score=action_config.get("business_impact", 0.3),
                execution_method=action_config.get("execution_method", "manual_procedure"),
                parameters=await self._generate_action_parameters(action_name, context),
                rollback_procedure=action_config.get("rollback", "contact_administrator"),
                success_criteria=action_config.get("success_criteria", ["action_completed"]),
                monitoring_requirements=await self._determine_monitoring_requirements(action_name),
                validation_methods=await self._determine_validation_methods(action_name),
            )
            
            response_actions.append(action)
        
        return response_actions
    
    async def _generate_action_description(self, action_name: str, context: DecisionContext) -> str:
        """Generate detailed action description."""
        base_descriptions = {
            "network_isolation": f"Isolate affected systems from network to prevent threat propagation for {context.security_context.event_type}",
            "system_quarantine": f"Quarantine compromised system to contain threat and preserve evidence",
            "account_lockout": f"Disable user account associated with security incident to prevent further access",
            "malware_removal": f"Execute comprehensive malware scan and removal procedures on affected systems",
            "log_preservation": f"Preserve and export security logs for forensic analysis and compliance requirements",
            "stakeholder_notification": f"Notify relevant stakeholders about security incident per iSECTECH protocols",
            "regulatory_notification": f"Submit required notifications to regulatory authorities for compliance",
        }
        
        return base_descriptions.get(action_name, f"Execute {action_name.replace('_', ' ')} procedure")
    
    async def _determine_prerequisites(self, action_name: str, all_actions: List[str]) -> List[str]:
        """Determine prerequisites for an action."""
        coordination_rules = self._coordination_rules.get("sequential_requirements", {})
        prerequisites = []
        
        for prereq_action, rules in coordination_rules.items():
            if action_name in rules.get("before", []) and prereq_action in all_actions:
                prerequisites.append(prereq_action)
        
        return prerequisites
    
    async def _determine_conflicts(self, action_name: str, all_actions: List[str]) -> List[str]:
        """Determine conflicting actions."""
        conflicts = self._coordination_rules.get("mutual_exclusions", {}).get(action_name, [])
        return [conflict for conflict in conflicts if conflict in all_actions]
    
    async def _determine_resource_requirements(self, action_name: str) -> List[str]:
        """Determine resource requirements for an action."""
        resource_mapping = {
            "network_isolation": ["network_admin_access", "firewall_management"],
            "system_quarantine": ["endpoint_management_system", "admin_privileges"],
            "malware_removal": ["antimalware_tools", "system_admin_access"],
            "memory_dump_collection": ["forensic_tools", "storage_space"],
            "patch_deployment": ["patch_management_system", "maintenance_window"],
        }
        
        return resource_mapping.get(action_name, ["standard_admin_access"])
    
    async def _generate_action_parameters(self, action_name: str, context: DecisionContext) -> Dict[str, Any]:
        """Generate action-specific parameters."""
        base_params = {
            "tenant_id": context.tenant_id,
            "incident_id": context.context_id,
            "classification": context.security_context.classification.value,
        }
        
        # Action-specific parameters
        if action_name == "network_isolation":
            base_params.update({
                "target_systems": context.affected_assets[:10],  # Limit for performance
                "isolation_type": "full" if context.threat_severity == ThreatSeverity.CRITICAL else "partial",
            })
        elif action_name == "stakeholder_notification":
            base_params.update({
                "notification_level": context.threat_severity.value,
                "business_impact": context.business_impact,
                "urgency": "immediate" if context.threat_severity == ThreatSeverity.CRITICAL else "standard",
            })
        elif action_name == "regulatory_notification":
            base_params.update({
                "frameworks": context.compliance_requirements,
                "severity": context.threat_severity.value,
                "data_involved": bool(context.affected_assets),
            })
        
        return base_params
    
    async def _determine_monitoring_requirements(self, action_name: str) -> List[str]:
        """Determine monitoring requirements for an action."""
        monitoring_mapping = {
            "network_isolation": ["network_connectivity", "traffic_flows", "isolated_system_activity"],
            "system_quarantine": ["system_status", "quarantine_effectiveness", "lateral_movement_attempts"],
            "malware_removal": ["scan_progress", "threat_elimination", "system_integrity"],
            "patch_deployment": ["patch_installation", "system_stability", "vulnerability_status"],
        }
        
        return monitoring_mapping.get(action_name, ["execution_status", "completion_verification"])
    
    async def _determine_validation_methods(self, action_name: str) -> List[str]:
        """Determine validation methods for an action."""
        validation_mapping = {
            "network_isolation": ["connectivity_tests", "traffic_analysis", "isolation_verification"],
            "system_quarantine": ["quarantine_status_check", "communication_blocking_test"],
            "malware_removal": ["clean_scan_verification", "behavioral_analysis"],
            "account_lockout": ["authentication_test", "access_attempt_blocking"],
        }
        
        return validation_mapping.get(action_name, ["manual_verification", "log_analysis"])
    
    async def _plan_execution_coordination(
        self, 
        actions: List[ResponseAction], 
        context: DecisionContext
    ) -> Tuple[List[List[str]], List[str]]:
        """Plan execution coordination and determine critical path."""
        # Analyze dependencies to create execution phases
        phases = []
        remaining_actions = {action.action_id: action for action in actions}
        completed_actions = set()
        
        while remaining_actions:
            # Find actions with no unfulfilled prerequisites
            ready_actions = []
            for action_id, action in remaining_actions.items():
                unfulfilled_prereqs = [prereq for prereq in action.prerequisites 
                                     if prereq not in completed_actions]
                if not unfulfilled_prereqs:
                    ready_actions.append(action_id)
            
            if not ready_actions:
                # Break circular dependencies by taking the first remaining action
                ready_actions = [list(remaining_actions.keys())[0]]
            
            phases.append(ready_actions)
            
            # Mark actions as completed and remove from remaining
            for action_id in ready_actions:
                completed_actions.add(action_id)
                del remaining_actions[action_id]
        
        # Determine critical path (longest dependency chain)
        critical_path = self._find_critical_path(actions)
        
        return phases, critical_path
    
    def _find_critical_path(self, actions: List[ResponseAction]) -> List[str]:
        """Find the critical path through action dependencies."""
        # Simple implementation - in production would use more sophisticated algorithm
        action_dict = {action.action_id: action for action in actions}
        
        # Find actions with no dependencies
        starting_actions = [action for action in actions if not action.prerequisites]
        
        if not starting_actions:
            return [actions[0].action_id] if actions else []
        
        # Find longest path from each starting action
        longest_path = []
        
        for start_action in starting_actions:
            path = self._find_path_from_action(start_action, action_dict, [])
            if len(path) > len(longest_path):
                longest_path = path
        
        return longest_path
    
    def _find_path_from_action(
        self, 
        action: ResponseAction, 
        action_dict: Dict[str, ResponseAction], 
        visited: List[str]
    ) -> List[str]:
        """Find longest path from a specific action."""
        if action.action_id in visited:
            return []
        
        new_visited = visited + [action.action_id]
        
        # Find actions that depend on this action
        dependent_actions = [
            other_action for other_action in action_dict.values()
            if action.action_id in other_action.prerequisites
        ]
        
        if not dependent_actions:
            return [action.action_id]
        
        # Find longest path through dependents
        longest_dependent_path = []
        for dependent in dependent_actions:
            path = self._find_path_from_action(dependent, action_dict, new_visited)
            if len(path) > len(longest_dependent_path):
                longest_dependent_path = path
        
        return [action.action_id] + longest_dependent_path
    
    async def _calculate_plan_metrics(
        self, 
        actions: List[ResponseAction], 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Calculate overall plan metrics."""
        if not actions:
            return {
                "total_duration": 0,
                "effectiveness": 0.0,
                "risk": 1.0,
                "confidence": 0.0,
                "requires_approval": True,
                "auto_executable": False,
                "parallel_possible": False,
            }
        
        # Calculate total duration (considering parallel execution)
        max_duration_per_phase = []
        current_phase_actions = []
        
        for action in actions:
            if not action.prerequisites or all(
                prereq_id in [a.action_id for a in current_phase_actions] 
                for prereq_id in action.prerequisites
            ):
                current_phase_actions.append(action)
            else:
                # New phase needed
                if current_phase_actions:
                    max_duration_per_phase.append(
                        max(a.estimated_duration_minutes for a in current_phase_actions)
                    )
                current_phase_actions = [action]
        
        if current_phase_actions:
            max_duration_per_phase.append(
                max(a.estimated_duration_minutes for a in current_phase_actions)
            )
        
        total_duration = sum(max_duration_per_phase)
        
        # Calculate weighted effectiveness
        effectiveness_scores = [action.effectiveness_score for action in actions]
        weights = [1.0 / (i + 1) for i in range(len(actions))]  # Decreasing weights
        weighted_effectiveness = sum(e * w for e, w in zip(effectiveness_scores, weights)) / sum(weights)
        
        # Calculate overall risk (maximum risk among actions)
        overall_risk = max(action.risk_score for action in actions)
        
        # Calculate confidence (average of action effectiveness)
        confidence = sum(action.effectiveness_score for action in actions) / len(actions)
        
        # Determine approval and execution requirements
        requires_approval = any(action.requires_approval for action in actions)
        auto_executable = all(action.auto_executable for action in actions) and not requires_approval
        
        # Check if parallel execution is possible
        parallel_possible = len(max_duration_per_phase) > 1
        
        return {
            "total_duration": total_duration,
            "effectiveness": weighted_effectiveness,
            "risk": overall_risk,
            "confidence": confidence,
            "requires_approval": requires_approval,
            "auto_executable": auto_executable,
            "parallel_possible": parallel_possible,
        }
    
    async def _generate_contingency_actions(
        self, 
        primary_actions: List[ResponseAction], 
        context: DecisionContext
    ) -> List[ResponseAction]:
        """Generate contingency actions for plan failures."""
        contingency_names = [
            "escalate_to_human_analyst",
            "emergency_system_shutdown",
            "activate_incident_response_team",
            "engage_external_experts",
        ]
        
        contingency_actions = []
        
        for i, name in enumerate(contingency_names[:2]):  # Limit to 2 contingencies
            action_id = f"contingency-{context.context_id}-{i+1}"
            
            action = ResponseAction(
                action_id=action_id,
                name=name.replace("_", " ").title(),
                description=f"Contingency action: {name.replace('_', ' ')}",
                category=ResponseCategory.USER_NOTIFICATION,
                priority=ResponsePriority.HIGH,
                complexity=ResponseComplexity.SIMPLE,
                estimated_duration_minutes=15,
                requires_approval=True,
                auto_executable=False,
                effectiveness_score=0.8,
                risk_score=0.2,
                business_impact_score=0.3,
                execution_method="manual_escalation",
                parameters={"reason": "primary_plan_failure"},
                rollback_procedure="no_rollback_needed",
                success_criteria=["escalation_completed"],
                monitoring_requirements=["escalation_status"],
                validation_methods=["manual_confirmation"],
            )
            
            contingency_actions.append(action)
        
        return contingency_actions
    
    async def _generate_rollback_plan(self, actions: List[ResponseAction]) -> str:
        """Generate rollback plan for the response."""
        rollback_steps = []
        
        for action in reversed(actions):  # Rollback in reverse order
            rollback_steps.append(f"- {action.name}: {action.rollback_procedure}")
        
        plan_parts = [
            "**Response Plan Rollback Procedure**",
            "",
            "Execute the following steps in order if rollback is required:",
            "",
            *rollback_steps,
            "",
            "**Post-Rollback Actions:**",
            "- Verify system status and functionality",
            "- Document rollback reason and outcome", 
            "- Reassess threat and consider alternative responses",
            "- Notify stakeholders of rollback completion",
        ]
        
        return "\n".join(plan_parts)
    
    async def _generate_plan_description(
        self, 
        actions: List[ResponseAction], 
        context: DecisionContext
    ) -> str:
        """Generate human-readable plan description."""
        action_names = [action.name for action in actions]
        
        return (
            f"Coordinated response to {context.threat_severity.value} severity "
            f"{context.security_context.event_type} involving {len(actions)} actions: "
            f"{', '.join(action_names)}. Plan optimized for iSECTECH operational requirements "
            f"with consideration for business impact and regulatory compliance."
        )
    
    async def _determine_plan_objective(self, threat_category: EventCategory, context: DecisionContext) -> str:
        """Determine primary objective for the response plan."""
        objectives = {
            EventCategory.MALWARE: "Contain and eliminate malware threat while preserving evidence",
            EventCategory.PHISHING: "Block phishing attack and protect user credentials",
            EventCategory.INTRUSION: "Stop unauthorized access and secure compromised systems",
            EventCategory.DATA_EXFILTRATION: "Prevent data loss and ensure regulatory compliance",
            EventCategory.INSIDER_THREAT: "Contain insider threat and preserve investigation evidence",
        }
        
        base_objective = objectives.get(threat_category, "Mitigate security threat and restore normal operations")
        
        # Add context-specific objectives
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            base_objective += " with classified data protection protocols"
        
        if context.compliance_requirements:
            base_objective += f" while maintaining {', '.join(context.compliance_requirements)} compliance"
        
        return base_objective
    
    async def _identify_coordination_requirements(self, actions: List[ResponseAction]) -> List[str]:
        """Identify coordination requirements for plan execution."""
        requirements = []
        
        # Check for actions requiring simultaneous execution
        if any(action.category == ResponseCategory.IMMEDIATE_CONTAINMENT for action in actions):
            requirements.append("Coordinate containment actions to prevent gaps")
        
        # Check for resource conflicts
        resource_intensive_actions = [
            action for action in actions 
            if action.complexity in [ResponseComplexity.COMPLEX, ResponseComplexity.ADVANCED]
        ]
        
        if len(resource_intensive_actions) > 1:
            requirements.append("Manage resource allocation for complex actions")
        
        # Check for approval requirements
        approval_actions = [action for action in actions if action.requires_approval]
        if approval_actions:
            requirements.append(f"Obtain approvals for {len(approval_actions)} actions before execution")
        
        # Check for notification coordination
        notification_actions = [
            action for action in actions 
            if action.category == ResponseCategory.USER_NOTIFICATION
        ]
        
        if len(notification_actions) > 1:
            requirements.append("Coordinate stakeholder notifications to ensure consistent messaging")
        
        return requirements
    
    async def _determine_approval_level(
        self, 
        actions: List[ResponseAction], 
        context: DecisionContext
    ) -> str:
        """Determine required approval level for the plan."""
        # Check for high-risk actions
        high_risk_actions = [action for action in actions if action.risk_score > 0.6]
        
        # Check for high business impact
        high_impact_actions = [action for action in actions if action.business_impact_score > 0.6]
        
        # Check for classified data
        is_classified = context.security_context.classification in [
            SecurityClassification.SECRET, 
            SecurityClassification.TOP_SECRET
        ]
        
        # Determine approval level
        if is_classified or high_risk_actions:
            return "CISO"
        elif high_impact_actions or context.threat_severity == ThreatSeverity.CRITICAL:
            return "Security_Manager"
        elif any(action.requires_approval for action in actions):
            return "SOC_Lead"
        else:
            return "Automated"
    
    async def _define_escalation_triggers(
        self, 
        context: DecisionContext, 
        actions: List[ResponseAction]
    ) -> List[str]:
        """Define triggers for escalating the response."""
        triggers = [
            "Any action fails to achieve success criteria within expected timeframe",
            "Threat severity increases during response execution",
            "Additional systems become compromised during response",
        ]
        
        # Context-specific triggers
        if context.threat_severity == ThreatSeverity.CRITICAL:
            triggers.append("Any unexpected resistance or evolution of the threat")
        
        if context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            triggers.append("Any indication of classified data compromise")
        
        if context.compliance_requirements:
            triggers.append("Risk of regulatory violation or compliance breach")
        
        # Action-specific triggers
        high_risk_actions = [action for action in actions if action.risk_score > 0.5]
        if high_risk_actions:
            triggers.append("Unexpected side effects from high-risk actions")
        
        return triggers
    
    async def _define_success_indicators(
        self, 
        actions: List[ResponseAction], 
        context: DecisionContext
    ) -> List[str]:
        """Define success indicators for the response plan."""
        indicators = [
            "All primary actions completed successfully",
            "Threat contained and no longer spreading",
            "Affected systems secured and operational",
            "No additional compromise detected",
        ]
        
        # Add action-specific indicators
        action_categories = {action.category for action in actions}
        
        if ResponseCategory.IMMEDIATE_CONTAINMENT in action_categories:
            indicators.append("Threat containment verified through monitoring")
        
        if ResponseCategory.EVIDENCE_PRESERVATION in action_categories:
            indicators.append("Evidence preserved with chain of custody maintained")
        
        if ResponseCategory.REGULATORY_COMPLIANCE in action_categories:
            indicators.append("Regulatory notifications completed within required timeframes")
        
        # Context-specific indicators
        if context.compliance_requirements:
            indicators.append("Compliance requirements satisfied for all applicable frameworks")
        
        return indicators
    
    async def _define_monitoring_points(self, actions: List[ResponseAction]) -> List[str]:
        """Define monitoring points for plan execution."""
        monitoring_points = [
            "Overall plan execution progress",
            "Action completion status and timing",
            "System health and operational status",
            "Threat activity and evolution",
        ]
        
        # Add action-specific monitoring points
        for action in actions:
            monitoring_points.extend(action.monitoring_requirements)
        
        # Remove duplicates and sort
        return sorted(list(set(monitoring_points)))
    
    def _update_selection_metrics(self, plan: ResponsePlan, generation_time: float) -> None:
        """Update response selection performance metrics."""
        self._selection_metrics["total_plans_generated"] += 1
        
        # Update average effectiveness
        current_avg = self._selection_metrics["average_plan_effectiveness"]
        count = self._selection_metrics["total_plans_generated"]
        
        self._selection_metrics["average_plan_effectiveness"] = (
            (current_avg * (count - 1)) + plan.overall_effectiveness
        ) / count
        
        # Update average generation time
        current_time_avg = self._selection_metrics["average_generation_time"]
        self._selection_metrics["average_generation_time"] = (
            (current_time_avg * (count - 1)) + generation_time
        ) / count
    
    def get_selection_metrics(self) -> Dict[str, Any]:
        """Get response selection performance metrics."""
        return self._selection_metrics.copy()
    
    def get_response_library_info(self) -> Dict[str, Any]:
        """Get information about the response library."""
        return {
            "total_responses": len(self._response_library),
            "categories": list(set(
                response.get("category", "UNKNOWN") 
                for response in self._response_library.values()
            )),
            "complexity_levels": list(set(
                response.get("complexity", "MODERATE") 
                for response in self._response_library.values()
            )),
            "auto_executable": len([
                response for response in self._response_library.values()
                if response.get("auto_executable", False)
            ]),
            "requires_approval": len([
                response for response in self._response_library.values()
                if response.get("requires_approval", False)
            ]),
        }