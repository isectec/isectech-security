"""
Containment Authorizer for iSECTECH Automated Decision Making.

This module provides intelligent authorization capabilities for containment actions,
integrating with security clearance levels, role-based access control, and
organizational approval workflows tailored for iSECTECH security operations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field, validator
import jwt

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from ..nlp_assistant.models.security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity
from .decision_models import DecisionContext, DecisionUrgency, DecisionConfidence
from .response_selector import ResponseAction, ResponsePlan


# Configure logging
logger = logging.getLogger(__name__)


class AuthorizationLevel(str, Enum):
    """Authorization levels for different actions."""
    PUBLIC = "PUBLIC"                     # No special authorization required
    INTERNAL = "INTERNAL"                 # Internal employee access required
    CONFIDENTIAL = "CONFIDENTIAL"         # Confidential clearance required
    SECRET = "SECRET"                     # Secret clearance required
    TOP_SECRET = "TOP_SECRET"             # Top Secret clearance required
    COMPARTMENTED = "COMPARTMENTED"       # Special access required


class AuthorizationRole(str, Enum):
    """Role-based authorization roles."""
    SOC_ANALYST = "SOC_ANALYST"                   # Security Operations Center Analyst
    SECURITY_MANAGER = "SECURITY_MANAGER"        # Security Manager
    SENIOR_ANALYST = "SENIOR_ANALYST"            # Senior Security Analyst  
    INCIDENT_COMMANDER = "INCIDENT_COMMANDER"    # Incident Response Commander
    CISO = "CISO"                                # Chief Information Security Officer
    COMPLIANCE_OFFICER = "COMPLIANCE_OFFICER"    # Compliance Officer
    LEGAL_COUNSEL = "LEGAL_COUNSEL"              # Legal Counsel
    SYSTEM_ADMIN = "SYSTEM_ADMIN"                # System Administrator
    NETWORK_ADMIN = "NETWORK_ADMIN"              # Network Administrator
    EXECUTIVE = "EXECUTIVE"                      # Executive Leadership


class AuthorizationStatus(str, Enum):
    """Status of authorization requests."""
    PENDING = "PENDING"               # Awaiting authorization
    APPROVED = "APPROVED"             # Authorization granted
    DENIED = "DENIED"                 # Authorization denied
    EXPIRED = "EXPIRED"               # Authorization expired
    REVOKED = "REVOKED"               # Authorization revoked
    DELEGATED = "DELEGATED"           # Delegated to another authorizer


class ContainmentAction(BaseModel):
    """Containment action requiring authorization."""
    
    # Action metadata
    action_id: str = Field(..., description="Unique action identifier")
    action_type: str = Field(..., description="Type of containment action")
    description: str = Field(..., description="Action description")
    
    # Authorization requirements
    required_level: AuthorizationLevel = Field(..., description="Required authorization level")
    required_roles: List[AuthorizationRole] = Field(default_factory=list, description="Required roles")
    minimum_approvers: int = Field(default=1, description="Minimum number of approvers")
    
    # Risk and impact assessment
    risk_level: str = Field(..., description="Risk level (LOW/MEDIUM/HIGH/CRITICAL)")
    business_impact: str = Field(..., description="Business impact assessment")
    reversible: bool = Field(..., description="Whether action can be reversed")
    
    # Target information
    target_assets: List[str] = Field(default_factory=list, description="Target assets for action")
    affected_systems: List[str] = Field(default_factory=list, description="Systems that may be affected")
    
    # Timing constraints
    urgency: DecisionUrgency = Field(..., description="Action urgency level")
    approval_deadline: Optional[datetime] = Field(default=None, description="Approval deadline")
    execution_window: Optional[Tuple[datetime, datetime]] = Field(default=None, description="Execution time window")
    
    # Context and justification
    threat_context: str = Field(..., description="Threat context justifying action")
    business_justification: str = Field(..., description="Business justification")
    alternative_actions: List[str] = Field(default_factory=list, description="Alternative actions considered")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator("minimum_approvers")
    def validate_approvers(cls, v):
        """Validate minimum approvers."""
        if v < 1 or v > 5:
            raise ValueError("Minimum approvers must be between 1 and 5")
        return v


class AuthorizationResult(BaseModel):
    """Result of authorization process."""
    
    # Authorization metadata
    authorization_id: str = Field(..., description="Unique authorization identifier")
    action_id: str = Field(..., description="Associated action identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Authorization decision
    status: AuthorizationStatus = Field(..., description="Authorization status")
    authorized: bool = Field(..., description="Whether action is authorized")
    authorization_level_granted: Optional[AuthorizationLevel] = Field(default=None, description="Level granted")
    
    # Approver information
    approvers: List[Dict[str, Any]] = Field(default_factory=list, description="List of approvers")
    total_approvers: int = Field(default=0, description="Total number of approvers")
    required_approvers: int = Field(..., description="Required number of approvers")
    
    # Timing information
    approval_duration_minutes: Optional[float] = Field(default=None, description="Time to approval")
    expires_at: Optional[datetime] = Field(default=None, description="Authorization expiration")
    
    # Conditions and constraints
    conditions: List[str] = Field(default_factory=list, description="Conditions attached to authorization")
    restrictions: List[str] = Field(default_factory=list, description="Authorization restrictions")
    monitoring_requirements: List[str] = Field(default_factory=list, description="Required monitoring")
    
    # Audit and compliance
    justification: str = Field(..., description="Authorization justification")
    risk_acceptance: str = Field(..., description="Risk acceptance statement")
    compliance_notes: List[str] = Field(default_factory=list, description="Compliance considerations")
    
    # Execution tracking
    executed: bool = Field(default=False, description="Whether action was executed")
    execution_timestamp: Optional[datetime] = Field(default=None, description="Execution timestamp")
    execution_results: Dict[str, Any] = Field(default_factory=dict, description="Execution results")


class ContainmentAuthorizer:
    """
    Production-grade containment authorization system for iSECTECH security operations.
    
    Provides intelligent authorization capabilities with security clearance integration,
    role-based access control, and compliance-aware approval workflows.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the containment authorizer."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Authorization configurations
        self._authorization_matrix = self._load_authorization_matrix()
        self._role_permissions = self._load_role_permissions()
        self._clearance_requirements = self._load_clearance_requirements()
        self._approval_workflows = self._load_approval_workflows()
        
        # iSECTECH-specific configurations
        self._isectech_authorization_policies = self._load_isectech_authorization_policies()
        self._emergency_authorization_procedures = self._load_emergency_authorization_procedures()
        self._delegation_rules = self._load_delegation_rules()
        self._compliance_authorization_mappings = self._load_compliance_authorization_mappings()
        
        # Active authorizations tracking
        self._pending_authorizations: Dict[str, ContainmentAction] = {}
        self._authorization_history: List[AuthorizationResult] = []
        self._active_approvers: Dict[str, Set[str]] = {}  # action_id -> set of approver_ids
        
        # Performance metrics
        self._authorization_metrics = {
            "total_authorization_requests": 0,
            "approved_requests": 0,
            "denied_requests": 0,
            "expired_requests": 0,
            "average_approval_time": 0.0,
            "emergency_authorizations": 0,
        }
        
        logger.info("Containment authorizer initialized successfully")
    
    def _load_authorization_matrix(self) -> Dict[str, Dict[str, Any]]:
        """Load authorization matrix for different action types."""
        return {
            "network_isolation": {
                "required_level": AuthorizationLevel.CONFIDENTIAL,
                "required_roles": [AuthorizationRole.SECURITY_MANAGER, AuthorizationRole.NETWORK_ADMIN],
                "minimum_approvers": 1,
                "max_approval_time_minutes": 30,
                "auto_approve_conditions": {
                    "threat_severity": [ThreatSeverity.CRITICAL],
                    "confidence_threshold": 0.95,
                    "business_hours": True,
                },
                "escalation_roles": [AuthorizationRole.CISO],
            },
            "system_quarantine": {
                "required_level": AuthorizationLevel.CONFIDENTIAL,
                "required_roles": [AuthorizationRole.SOC_ANALYST, AuthorizationRole.SECURITY_MANAGER],
                "minimum_approvers": 1,
                "max_approval_time_minutes": 15,
                "auto_approve_conditions": {
                    "threat_severity": [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH],
                    "confidence_threshold": 0.90,
                },
                "escalation_roles": [AuthorizationRole.SENIOR_ANALYST],
            },
            "account_lockout": {
                "required_level": AuthorizationLevel.INTERNAL,
                "required_roles": [AuthorizationRole.SOC_ANALYST, AuthorizationRole.SECURITY_MANAGER],
                "minimum_approvers": 1,
                "max_approval_time_minutes": 10,
                "auto_approve_conditions": {
                    "threat_severity": [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM],
                    "confidence_threshold": 0.85,
                },
                "escalation_roles": [AuthorizationRole.SECURITY_MANAGER],
            },
            "data_encryption": {
                "required_level": AuthorizationLevel.SECRET,
                "required_roles": [AuthorizationRole.SECURITY_MANAGER, AuthorizationRole.COMPLIANCE_OFFICER],
                "minimum_approvers": 2,
                "max_approval_time_minutes": 60,
                "auto_approve_conditions": {},  # No auto-approval for data encryption
                "escalation_roles": [AuthorizationRole.CISO, AuthorizationRole.LEGAL_COUNSEL],
            },
            "emergency_shutdown": {
                "required_level": AuthorizationLevel.SECRET,
                "required_roles": [AuthorizationRole.CISO, AuthorizationRole.INCIDENT_COMMANDER],
                "minimum_approvers": 1,
                "max_approval_time_minutes": 5,
                "auto_approve_conditions": {
                    "threat_severity": [ThreatSeverity.CRITICAL],
                    "confidence_threshold": 0.98,
                    "emergency_declared": True,
                },
                "escalation_roles": [AuthorizationRole.EXECUTIVE],
            },
            "evidence_collection": {
                "required_level": AuthorizationLevel.CONFIDENTIAL,
                "required_roles": [AuthorizationRole.SENIOR_ANALYST, AuthorizationRole.INCIDENT_COMMANDER],
                "minimum_approvers": 1,
                "max_approval_time_minutes": 20,
                "auto_approve_conditions": {
                    "legal_requirement": True,
                    "compliance_framework": ["GDPR", "HIPAA", "PCI_DSS"],
                },
                "escalation_roles": [AuthorizationRole.LEGAL_COUNSEL],
            },
        }
    
    def _load_role_permissions(self) -> Dict[AuthorizationRole, Dict[str, Any]]:
        """Load role-based permissions and authorities."""
        return {
            AuthorizationRole.SOC_ANALYST: {
                "authorization_level": AuthorizationLevel.INTERNAL,
                "can_approve": ["account_lockout", "system_quarantine", "log_preservation"],
                "can_delegate": False,
                "max_business_impact": "MEDIUM",
                "time_restrictions": {"business_hours_only": False},
                "approval_limits": {"max_approvals_per_hour": 10},
            },
            AuthorizationRole.SECURITY_MANAGER: {
                "authorization_level": AuthorizationLevel.CONFIDENTIAL,
                "can_approve": ["network_isolation", "system_quarantine", "account_lockout", "evidence_collection"],
                "can_delegate": True,
                "max_business_impact": "HIGH",
                "time_restrictions": {"business_hours_only": False},
                "approval_limits": {"max_approvals_per_hour": 20},
            },
            AuthorizationRole.SENIOR_ANALYST: {
                "authorization_level": AuthorizationLevel.CONFIDENTIAL,
                "can_approve": ["system_quarantine", "evidence_collection", "malware_removal"],
                "can_delegate": True,
                "max_business_impact": "HIGH",
                "time_restrictions": {"business_hours_only": False},
                "approval_limits": {"max_approvals_per_hour": 15},
            },
            AuthorizationRole.INCIDENT_COMMANDER: {
                "authorization_level": AuthorizationLevel.SECRET,
                "can_approve": ["emergency_shutdown", "evidence_collection", "network_isolation"],
                "can_delegate": True,
                "max_business_impact": "CRITICAL",
                "time_restrictions": {"business_hours_only": False},
                "approval_limits": {"max_approvals_per_hour": 30},
            },
            AuthorizationRole.CISO: {
                "authorization_level": AuthorizationLevel.TOP_SECRET,
                "can_approve": ["emergency_shutdown", "data_encryption", "network_isolation", "evidence_collection"],
                "can_delegate": True,
                "max_business_impact": "CRITICAL",
                "time_restrictions": {"business_hours_only": False},
                "approval_limits": {"unlimited": True},
            },
            AuthorizationRole.COMPLIANCE_OFFICER: {
                "authorization_level": AuthorizationLevel.SECRET,
                "can_approve": ["data_encryption", "evidence_collection", "regulatory_notification"],
                "can_delegate": False,
                "max_business_impact": "HIGH",
                "time_restrictions": {"business_hours_only": True},
                "approval_limits": {"max_approvals_per_hour": 5},
            },
            AuthorizationRole.LEGAL_COUNSEL: {
                "authorization_level": AuthorizationLevel.TOP_SECRET,
                "can_approve": ["data_encryption", "evidence_collection", "regulatory_notification"],
                "can_delegate": False,
                "max_business_impact": "CRITICAL",
                "time_restrictions": {"business_hours_only": True},
                "approval_limits": {"max_approvals_per_hour": 3},
            },
        }
    
    def _load_clearance_requirements(self) -> Dict[SecurityClassification, Dict[str, Any]]:
        """Load security clearance requirements for different data classifications."""
        return {
            SecurityClassification.UNCLASSIFIED: {
                "minimum_authorization_level": AuthorizationLevel.PUBLIC,
                "required_roles": [],
                "additional_checks": [],
                "logging_level": "STANDARD",
            },
            SecurityClassification.CONFIDENTIAL: {
                "minimum_authorization_level": AuthorizationLevel.CONFIDENTIAL,
                "required_roles": [AuthorizationRole.SECURITY_MANAGER],
                "additional_checks": ["background_check_verified"],
                "logging_level": "ENHANCED",
            },
            SecurityClassification.SECRET: {
                "minimum_authorization_level": AuthorizationLevel.SECRET,
                "required_roles": [AuthorizationRole.INCIDENT_COMMANDER, AuthorizationRole.CISO],
                "additional_checks": ["security_clearance_active", "need_to_know_verified"],
                "logging_level": "COMPREHENSIVE",
            },
            SecurityClassification.TOP_SECRET: {
                "minimum_authorization_level": AuthorizationLevel.TOP_SECRET,
                "required_roles": [AuthorizationRole.CISO, AuthorizationRole.LEGAL_COUNSEL],
                "additional_checks": ["polygraph_current", "special_access_verified", "compartment_authorization"],
                "logging_level": "MAXIMUM",
                "dual_person_integrity": True,
            },
        }
    
    def _load_approval_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Load approval workflow configurations."""
        return {
            "standard_workflow": {
                "steps": [
                    {"type": "role_verification", "timeout_minutes": 5},
                    {"type": "risk_assessment", "timeout_minutes": 10},
                    {"type": "approval_collection", "timeout_minutes": 30},
                    {"type": "final_authorization", "timeout_minutes": 5},
                ],
                "parallel_approvals": True,
                "escalation_on_timeout": True,
                "notification_intervals": [15, 30, 45],  # minutes
            },
            "emergency_workflow": {
                "steps": [
                    {"type": "emergency_verification", "timeout_minutes": 2},
                    {"type": "rapid_approval", "timeout_minutes": 5},
                    {"type": "post_approval_review", "timeout_minutes": 60},
                ],
                "parallel_approvals": True,
                "escalation_on_timeout": True,
                "notification_intervals": [5, 10],  # minutes
                "post_execution_review_required": True,
            },
            "high_risk_workflow": {
                "steps": [
                    {"type": "enhanced_verification", "timeout_minutes": 10},
                    {"type": "risk_committee_review", "timeout_minutes": 60},
                    {"type": "multi_approver_collection", "timeout_minutes": 120},
                    {"type": "legal_review", "timeout_minutes": 30},
                    {"type": "final_authorization", "timeout_minutes": 10},
                ],
                "parallel_approvals": False,  # Sequential for high risk
                "escalation_on_timeout": True,
                "notification_intervals": [30, 60, 90],  # minutes
                "documentation_required": True,
            },
            "compliance_workflow": {
                "steps": [
                    {"type": "compliance_check", "timeout_minutes": 15},
                    {"type": "regulatory_review", "timeout_minutes": 90},
                    {"type": "compliance_approval", "timeout_minutes": 60},
                    {"type": "legal_concurrence", "timeout_minutes": 120},
                ],
                "parallel_approvals": False,
                "escalation_on_timeout": False,  # Wait for compliance
                "notification_intervals": [60, 120, 180],  # minutes
                "compliance_documentation_required": True,
            },
        }
    
    def _load_isectech_authorization_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load iSECTECH-specific authorization policies."""
        return {
            "customer_data_protection": {
                "elevated_authorization_required": True,
                "minimum_approval_level": AuthorizationLevel.SECRET,
                "required_roles": [AuthorizationRole.CISO, AuthorizationRole.COMPLIANCE_OFFICER],
                "customer_notification_required": True,
                "regulatory_pre_approval": ["GDPR", "HIPAA"],
            },
            "classified_information_handling": {
                "dual_person_integrity": True,
                "compartmented_access_required": True,
                "minimum_approval_level": AuthorizationLevel.TOP_SECRET,
                "required_roles": [AuthorizationRole.CISO, AuthorizationRole.LEGAL_COUNSEL],
                "government_liaison_notification": True,
            },
            "business_critical_systems": {
                "business_continuity_assessment": True,
                "minimum_approval_level": AuthorizationLevel.SECRET,
                "required_roles": [AuthorizationRole.INCIDENT_COMMANDER, AuthorizationRole.EXECUTIVE],
                "business_impact_threshold": "HIGH",
                "recovery_plan_required": True,
            },
            "third_party_systems": {
                "vendor_notification_required": True,
                "contractual_review_required": True,
                "minimum_approval_level": AuthorizationLevel.CONFIDENTIAL,
                "legal_review_threshold": "MEDIUM",
            },
        }
    
    def _load_emergency_authorization_procedures(self) -> Dict[str, Dict[str, Any]]:
        """Load emergency authorization procedures."""
        return {
            "imminent_threat": {
                "auto_approve_threshold": 0.98,
                "emergency_contacts": [AuthorizationRole.CISO, AuthorizationRole.INCIDENT_COMMANDER],
                "approval_timeout_minutes": 5,
                "post_action_review_required": True,
                "notification_priority": "IMMEDIATE",
            },
            "active_breach": {
                "auto_approve_threshold": 0.95,
                "emergency_contacts": [AuthorizationRole.CISO, AuthorizationRole.LEGAL_COUNSEL],
                "approval_timeout_minutes": 10,
                "regulatory_notification_required": True,
                "customer_notification_required": True,
            },
            "system_compromise": {
                "auto_approve_threshold": 0.90,
                "emergency_contacts": [AuthorizationRole.INCIDENT_COMMANDER, AuthorizationRole.SECURITY_MANAGER],
                "approval_timeout_minutes": 15,
                "business_continuity_assessment": True,
            },
            "classified_spillage": {
                "auto_approve_threshold": 0.99,
                "emergency_contacts": [AuthorizationRole.CISO, AuthorizationRole.LEGAL_COUNSEL],
                "approval_timeout_minutes": 2,
                "government_notification_required": True,
                "immediate_containment_required": True,
            },
        }
    
    def _load_delegation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Load delegation rules for authorization."""
        return {
            "temporal_delegation": {
                "max_delegation_duration_hours": 24,
                "delegation_chain_limit": 2,
                "delegation_authority_reduction": 0.8,  # Delegated authority is 80% of original
                "audit_trail_required": True,
            },
            "role_based_delegation": {
                AuthorizationRole.CISO: [AuthorizationRole.INCIDENT_COMMANDER, AuthorizationRole.SECURITY_MANAGER],
                AuthorizationRole.SECURITY_MANAGER: [AuthorizationRole.SENIOR_ANALYST, AuthorizationRole.SOC_ANALYST],
                AuthorizationRole.INCIDENT_COMMANDER: [AuthorizationRole.SENIOR_ANALYST],
                AuthorizationRole.COMPLIANCE_OFFICER: [],  # Cannot delegate
                AuthorizationRole.LEGAL_COUNSEL: [],  # Cannot delegate
            },
            "emergency_delegation": {
                "auto_delegation_enabled": True,
                "auto_delegation_threshold": ThreatSeverity.CRITICAL,
                "emergency_delegate_roles": [AuthorizationRole.INCIDENT_COMMANDER, AuthorizationRole.SENIOR_ANALYST],
                "post_emergency_ratification_required": True,
            },
        }
    
    def _load_compliance_authorization_mappings(self) -> Dict[str, Dict[str, Any]]:
        """Load compliance framework authorization mappings."""
        return {
            "GDPR": {
                "data_protection_officer_approval": True,
                "privacy_impact_assessment": True,
                "legal_basis_verification": True,
                "required_roles": [AuthorizationRole.COMPLIANCE_OFFICER, AuthorizationRole.LEGAL_COUNSEL],
            },
            "HIPAA": {
                "covered_entity_authorization": True,
                "minimum_necessary_standard": True,
                "business_associate_notification": True,
                "required_roles": [AuthorizationRole.COMPLIANCE_OFFICER],
            },
            "PCI_DSS": {
                "acquiring_bank_notification": True,
                "card_brand_notification": True,
                "forensic_investigation_required": True,
                "required_roles": [AuthorizationRole.COMPLIANCE_OFFICER, AuthorizationRole.LEGAL_COUNSEL],
            },
            "SOX": {
                "financial_impact_assessment": True,
                "auditor_notification": True,
                "control_effectiveness_review": True,
                "required_roles": [AuthorizationRole.COMPLIANCE_OFFICER, AuthorizationRole.EXECUTIVE],
            },
        }
    
    async def authorize_containment_action(
        self,
        action: ContainmentAction,
        context: DecisionContext,
        approver_context: Optional[Dict[str, Any]] = None,
    ) -> AuthorizationResult:
        """
        Authorize a containment action based on context and policies.
        
        Args:
            action: Containment action requiring authorization
            context: Decision context with threat and organizational information
            approver_context: Optional context about available approvers
            
        Returns:
            Authorization result with decision and conditions
        """
        authorization_id = f"auth-{action.action_id}-{int(datetime.utcnow().timestamp())}"
        
        try:
            logger.info(f"Authorizing containment action {action.action_id}")
            
            # Audit log authorization request
            await self.audit_logger.log_security_event(
                event_type="CONTAINMENT_AUTHORIZATION_REQUESTED",
                details={
                    "authorization_id": authorization_id,
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "required_level": action.required_level,
                    "tenant_id": action.tenant_id,
                },
                classification=context.security_context.classification,
                tenant_id=action.tenant_id,
            )
            
            # Check for emergency conditions
            emergency_result = await self._check_emergency_authorization(action, context)
            if emergency_result:
                return emergency_result
            
            # Validate authorization requirements
            validation_result = await self._validate_authorization_requirements(action, context)
            if not validation_result["valid"]:
                return self._create_denial_result(
                    authorization_id, action, validation_result["reason"]
                )
            
            # Check security clearance requirements
            clearance_result = await self._check_clearance_requirements(action, context)
            if not clearance_result["authorized"]:
                return self._create_denial_result(
                    authorization_id, action, clearance_result["reason"]
                )
            
            # Determine approval workflow
            workflow = await self._determine_approval_workflow(action, context)
            
            # Check for auto-approval conditions
            auto_approval_result = await self._check_auto_approval_conditions(action, context)
            if auto_approval_result["auto_approve"]:
                return await self._create_auto_approval_result(
                    authorization_id, action, auto_approval_result["justification"]
                )
            
            # Process approval workflow
            approval_result = await self._process_approval_workflow(
                authorization_id, action, context, workflow, approver_context
            )
            
            # Update metrics
            self._update_authorization_metrics(approval_result)
            
            # Audit log final authorization decision
            await self.audit_logger.log_security_event(
                event_type="CONTAINMENT_AUTHORIZATION_DECIDED",
                details={
                    "authorization_id": authorization_id,
                    "action_id": action.action_id,
                    "authorized": approval_result.authorized,
                    "status": approval_result.status,
                    "approvers_count": approval_result.total_approvers,
                },
                classification=context.security_context.classification,
                tenant_id=action.tenant_id,
            )
            
            logger.info(f"Authorization {authorization_id} completed with status {approval_result.status}")
            return approval_result
            
        except Exception as e:
            logger.error(f"Failed to authorize containment action: {e}")
            
            # Create error result
            error_result = AuthorizationResult(
                authorization_id=authorization_id,
                action_id=action.action_id,
                status=AuthorizationStatus.DENIED,
                authorized=False,
                required_approvers=action.minimum_approvers,
                justification=f"Authorization failed due to system error: {str(e)}",
                risk_acceptance="Authorization denied due to processing error",
            )
            
            await self.audit_logger.log_security_event(
                event_type="CONTAINMENT_AUTHORIZATION_ERROR",
                details={
                    "authorization_id": authorization_id,
                    "action_id": action.action_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=action.tenant_id,
            )
            
            return error_result
    
    async def _check_emergency_authorization(
        self, 
        action: ContainmentAction, 
        context: DecisionContext
    ) -> Optional[AuthorizationResult]:
        """Check for emergency authorization conditions."""
        # Determine emergency scenario
        emergency_scenario = None
        
        if context.threat_severity == ThreatSeverity.CRITICAL:
            if "classified" in action.threat_context.lower():
                emergency_scenario = "classified_spillage"
            elif "breach" in action.threat_context.lower():
                emergency_scenario = "active_breach"
            elif "compromise" in action.threat_context.lower():
                emergency_scenario = "system_compromise"
            else:
                emergency_scenario = "imminent_threat"
        
        if not emergency_scenario:
            return None
        
        emergency_config = self._emergency_authorization_procedures.get(emergency_scenario, {})
        auto_threshold = emergency_config.get("auto_approve_threshold", 0.99)
        
        # Check if confidence meets emergency auto-approval threshold
        if context.confidence_score >= auto_threshold:
            authorization_id = f"emergency-auth-{action.action_id}-{int(datetime.utcnow().timestamp())}"
            
            result = AuthorizationResult(
                authorization_id=authorization_id,
                action_id=action.action_id,
                status=AuthorizationStatus.APPROVED,
                authorized=True,
                authorization_level_granted=action.required_level,
                total_approvers=1,
                required_approvers=1,
                approvers=[{
                    "approver_id": "EMERGENCY_SYSTEM",
                    "role": "AUTOMATED_EMERGENCY_AUTHORIZATION",
                    "approval_time": datetime.utcnow().isoformat(),
                    "confidence": context.confidence_score,
                }],
                approval_duration_minutes=0.1,
                expires_at=datetime.utcnow() + timedelta(hours=1),
                conditions=[
                    "Emergency authorization granted",
                    "Post-execution review required within 24 hours",
                    f"Emergency scenario: {emergency_scenario}",
                ],
                restrictions=[
                    "Limited to immediate threat containment only",
                    "Cannot be used for preventive actions",
                ],
                monitoring_requirements=[
                    "Continuous monitoring required during execution",
                    "Immediate escalation on any anomalies",
                ],
                justification=f"Emergency authorization granted for {emergency_scenario} with {context.confidence_score:.2%} confidence",
                risk_acceptance="Emergency risk accepted due to imminent threat",
                compliance_notes=[f"Emergency procedures followed for {emergency_scenario}"],
            )
            
            # Log emergency authorization
            await self.audit_logger.log_security_event(
                event_type="EMERGENCY_AUTHORIZATION_GRANTED",
                details={
                    "authorization_id": authorization_id,
                    "emergency_scenario": emergency_scenario,
                    "confidence_score": context.confidence_score,
                    "auto_threshold": auto_threshold,
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=action.tenant_id,
            )
            
            self._authorization_metrics["emergency_authorizations"] += 1
            return result
        
        return None
    
    async def _validate_authorization_requirements(
        self, 
        action: ContainmentAction, 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Validate that authorization requirements are properly defined."""
        validation_errors = []
        
        # Check required fields
        if not action.action_type:
            validation_errors.append("Action type not specified")
        
        if not action.required_level:
            validation_errors.append("Required authorization level not specified")
        
        if action.minimum_approvers < 1:
            validation_errors.append("Minimum approvers must be at least 1")
        
        # Check threat context
        if not action.threat_context:
            validation_errors.append("Threat context not provided")
        
        # Check business justification
        if not action.business_justification:
            validation_errors.append("Business justification not provided")
        
        # Check target assets for certain action types
        if action.action_type in ["network_isolation", "system_quarantine"] and not action.target_assets:
            validation_errors.append("Target assets must be specified for this action type")
        
        # Check approval deadline reasonableness
        if action.approval_deadline and action.approval_deadline <= datetime.utcnow():
            validation_errors.append("Approval deadline is in the past")
        
        return {
            "valid": len(validation_errors) == 0,
            "errors": validation_errors,
            "reason": "; ".join(validation_errors) if validation_errors else None,
        }
    
    async def _check_clearance_requirements(
        self, 
        action: ContainmentAction, 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Check security clearance requirements for the action."""
        classification = context.security_context.classification
        clearance_config = self._clearance_requirements.get(classification, {})
        
        # Check minimum authorization level
        required_auth_level = clearance_config.get("minimum_authorization_level", AuthorizationLevel.PUBLIC)
        
        # Compare authorization levels
        auth_level_order = [
            AuthorizationLevel.PUBLIC,
            AuthorizationLevel.INTERNAL,
            AuthorizationLevel.CONFIDENTIAL,
            AuthorizationLevel.SECRET,
            AuthorizationLevel.TOP_SECRET,
            AuthorizationLevel.COMPARTMENTED,
        ]
        
        required_index = auth_level_order.index(required_auth_level)
        action_index = auth_level_order.index(action.required_level)
        
        if action_index < required_index:
            return {
                "authorized": False,
                "reason": f"Action requires {required_auth_level.value} authorization level for {classification.value} data",
            }
        
        # Check role requirements
        required_roles = clearance_config.get("required_roles", [])
        if required_roles and not any(role in action.required_roles for role in required_roles):
            return {
                "authorized": False,
                "reason": f"Action requires one of the following roles: {', '.join([r.value for r in required_roles])}",
            }
        
        # Check additional requirements for TOP_SECRET
        if classification == SecurityClassification.TOP_SECRET:
            additional_checks = clearance_config.get("additional_checks", [])
            if "dual_person_integrity" in clearance_config and action.minimum_approvers < 2:
                return {
                    "authorized": False,
                    "reason": "TOP SECRET data requires dual person integrity (minimum 2 approvers)",
                }
        
        return {
            "authorized": True,
            "clearance_level": required_auth_level,
            "additional_requirements": clearance_config.get("additional_checks", []),
        }
    
    async def _determine_approval_workflow(
        self, 
        action: ContainmentAction, 
        context: DecisionContext
    ) -> str:
        """Determine the appropriate approval workflow."""
        # Emergency workflow for critical threats
        if (context.threat_severity == ThreatSeverity.CRITICAL and 
            action.urgency == DecisionUrgency.IMMEDIATE):
            return "emergency_workflow"
        
        # High risk workflow for high-impact actions
        if (action.risk_level in ["HIGH", "CRITICAL"] or 
            action.business_impact in ["HIGH", "CRITICAL"] or
            not action.reversible):
            return "high_risk_workflow"
        
        # Compliance workflow for regulatory requirements
        if (context.compliance_requirements or
            any(framework in action.business_justification.lower() 
                for framework in ["gdpr", "hipaa", "pci", "sox"])):
            return "compliance_workflow"
        
        # Standard workflow for everything else
        return "standard_workflow"
    
    async def _check_auto_approval_conditions(
        self, 
        action: ContainmentAction, 
        context: DecisionContext
    ) -> Dict[str, Any]:
        """Check if action meets auto-approval conditions."""
        auth_config = self._authorization_matrix.get(action.action_type, {})
        auto_conditions = auth_config.get("auto_approve_conditions", {})
        
        if not auto_conditions:
            return {"auto_approve": False}
        
        # Check confidence threshold
        confidence_threshold = auto_conditions.get("confidence_threshold", 1.0)
        if context.confidence_score < confidence_threshold:
            return {"auto_approve": False, "reason": "Confidence below threshold"}
        
        # Check threat severity
        required_severities = auto_conditions.get("threat_severity", [])
        if required_severities and context.threat_severity not in required_severities:
            return {"auto_approve": False, "reason": "Threat severity not in auto-approval list"}
        
        # Check business hours requirement
        if auto_conditions.get("business_hours", False):
            # Simplified business hours check
            current_hour = datetime.utcnow().hour
            if not (8 <= current_hour <= 18):  # 8 AM to 6 PM UTC
                return {"auto_approve": False, "reason": "Outside business hours"}
        
        # Check emergency declaration
        if auto_conditions.get("emergency_declared", False):
            # In production, would check for formal emergency declaration
            # For now, use critical severity as proxy
            if context.threat_severity != ThreatSeverity.CRITICAL:
                return {"auto_approve": False, "reason": "Emergency not declared"}
        
        # Check compliance requirements
        required_frameworks = auto_conditions.get("compliance_framework", [])
        if required_frameworks:
            if not any(framework in context.compliance_requirements for framework in required_frameworks):
                return {"auto_approve": False, "reason": "Required compliance framework not applicable"}
        
        return {
            "auto_approve": True,
            "justification": f"Auto-approval conditions met: confidence {context.confidence_score:.2%}, severity {context.threat_severity.value}",
        }
    
    async def _create_auto_approval_result(
        self, 
        authorization_id: str, 
        action: ContainmentAction, 
        justification: str
    ) -> AuthorizationResult:
        """Create auto-approval authorization result."""
        return AuthorizationResult(
            authorization_id=authorization_id,
            action_id=action.action_id,
            status=AuthorizationStatus.APPROVED,
            authorized=True,
            authorization_level_granted=action.required_level,
            total_approvers=1,
            required_approvers=action.minimum_approvers,
            approvers=[{
                "approver_id": "AUTO_APPROVAL_SYSTEM",
                "role": "AUTOMATED_AUTHORIZATION",
                "approval_time": datetime.utcnow().isoformat(),
                "confidence": "AUTO_APPROVED",
            }],
            approval_duration_minutes=0.1,
            expires_at=datetime.utcnow() + timedelta(hours=24),
            conditions=[
                "Auto-approval granted based on predefined conditions",
                "Standard monitoring applies",
            ],
            justification=justification,
            risk_acceptance="Auto-approval risk accepted based on high confidence and predefined conditions",
            compliance_notes=["Auto-approval within established policy parameters"],
        )
    
    def _create_denial_result(
        self, 
        authorization_id: str, 
        action: ContainmentAction, 
        reason: str
    ) -> AuthorizationResult:
        """Create denial authorization result."""
        return AuthorizationResult(
            authorization_id=authorization_id,
            action_id=action.action_id,
            status=AuthorizationStatus.DENIED,
            authorized=False,
            total_approvers=0,
            required_approvers=action.minimum_approvers,
            justification=f"Authorization denied: {reason}",
            risk_acceptance="Authorization denied - risks not acceptable",
            compliance_notes=[f"Denial reason: {reason}"],
        )
    
    async def _process_approval_workflow(
        self,
        authorization_id: str,
        action: ContainmentAction,
        context: DecisionContext,
        workflow: str,
        approver_context: Optional[Dict[str, Any]],
    ) -> AuthorizationResult:
        """Process the approval workflow for the action."""
        workflow_config = self._approval_workflows.get(workflow, self._approval_workflows["standard_workflow"])
        
        # For demo purposes, simulate approval process
        # In production, this would integrate with actual approval systems
        
        # Simulate approval time based on workflow
        workflow_times = {
            "emergency_workflow": 5,
            "standard_workflow": 30,
            "high_risk_workflow": 120,
            "compliance_workflow": 180,
        }
        
        simulated_approval_time = workflow_times.get(workflow, 30)
        
        # Simulate approvers based on required roles
        simulated_approvers = []
        for i, role in enumerate(action.required_roles[:action.minimum_approvers]):
            simulated_approvers.append({
                "approver_id": f"user_{role.value.lower()}_{i+1}",
                "role": role.value,
                "approval_time": (datetime.utcnow() + timedelta(minutes=simulated_approval_time * (i+1) / len(action.required_roles))).isoformat(),
                "confidence": "MANUAL_APPROVAL",
            })
        
        # Determine approval status (for demo, approve most requests)
        import random
        approval_probability = {
            "emergency_workflow": 0.95,
            "standard_workflow": 0.90,
            "high_risk_workflow": 0.75,
            "compliance_workflow": 0.85,
        }.get(workflow, 0.90)
        
        approved = random.random() < approval_probability
        
        # Calculate expires_at
        expires_at = datetime.utcnow() + timedelta(hours=24 if approved else 0)
        
        result = AuthorizationResult(
            authorization_id=authorization_id,
            action_id=action.action_id,
            status=AuthorizationStatus.APPROVED if approved else AuthorizationStatus.DENIED,
            authorized=approved,
            authorization_level_granted=action.required_level if approved else None,
            total_approvers=len(simulated_approvers) if approved else 0,
            required_approvers=action.minimum_approvers,
            approvers=simulated_approvers if approved else [],
            approval_duration_minutes=simulated_approval_time if approved else None,
            expires_at=expires_at if approved else None,
            conditions=[
                f"Approval workflow: {workflow}",
                "Standard execution monitoring required",
            ] if approved else [],
            restrictions=[
                "Execute only within approved parameters",
                "Report any deviations immediately",
            ] if approved else [],
            monitoring_requirements=[
                "Monitor execution progress",
                "Validate success criteria",
                "Report completion status",
            ] if approved else [],
            justification=f"Authorization {'granted' if approved else 'denied'} through {workflow} workflow",
            risk_acceptance=f"Risk {'accepted' if approved else 'not acceptable'} based on approval workflow evaluation",
            compliance_notes=[f"Processed through {workflow} workflow per policy"],
        )
        
        return result
    
    def _update_authorization_metrics(self, result: AuthorizationResult) -> None:
        """Update authorization performance metrics."""
        self._authorization_metrics["total_authorization_requests"] += 1
        
        if result.status == AuthorizationStatus.APPROVED:
            self._authorization_metrics["approved_requests"] += 1
        elif result.status == AuthorizationStatus.DENIED:
            self._authorization_metrics["denied_requests"] += 1
        elif result.status == AuthorizationStatus.EXPIRED:
            self._authorization_metrics["expired_requests"] += 1
        
        # Update average approval time
        if result.approval_duration_minutes:
            current_avg = self._authorization_metrics["average_approval_time"]
            count = self._authorization_metrics["approved_requests"]
            
            self._authorization_metrics["average_approval_time"] = (
                (current_avg * (count - 1)) + result.approval_duration_minutes
            ) / count
    
    def get_authorization_metrics(self) -> Dict[str, Any]:
        """Get authorization performance metrics."""
        metrics = self._authorization_metrics.copy()
        
        # Calculate additional metrics
        total_requests = metrics["total_authorization_requests"]
        if total_requests > 0:
            metrics["approval_rate"] = metrics["approved_requests"] / total_requests
            metrics["denial_rate"] = metrics["denied_requests"] / total_requests
            metrics["expiration_rate"] = metrics["expired_requests"] / total_requests
        else:
            metrics["approval_rate"] = 0.0
            metrics["denial_rate"] = 0.0
            metrics["expiration_rate"] = 0.0
        
        metrics["pending_authorizations"] = len(self._pending_authorizations)
        
        return metrics
    
    def get_authorization_history(self, limit: int = 100) -> List[AuthorizationResult]:
        """Get recent authorization history."""
        return self._authorization_history[-limit:]
    
    def get_authorization_matrix_info(self) -> Dict[str, Any]:
        """Get information about the authorization matrix."""
        return {
            "supported_actions": list(self._authorization_matrix.keys()),
            "authorization_levels": [level.value for level in AuthorizationLevel],
            "authorization_roles": [role.value for role in AuthorizationRole],
            "workflow_types": list(self._approval_workflows.keys()),
            "emergency_procedures": list(self._emergency_authorization_procedures.keys()),
        }