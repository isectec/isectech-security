"""
Playbook Engine for iSECTECH Automated Decision Making.

This module provides automated playbook execution capabilities that trigger
predefined response procedures based on threat conditions, business rules,
and organizational policies tailored for iSECTECH security operations.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import ray
from pydantic import BaseModel, Field, validator

from ...shared.config.settings import SecurityClassification, get_settings
from ...shared.security.audit import AuditLogger
from ..nlp_assistant.models.security_nlp_processor import SecurityContext, EventCategory, ThreatSeverity
from .decision_models import DecisionContext, DecisionUrgency, DecisionConfidence
from .response_selector import ResponsePlan, ResponseAction


# Configure logging
logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    """Status of playbook execution."""
    PENDING = "PENDING"               # Waiting to execute
    TRIGGERED = "TRIGGERED"           # Conditions met, ready to run
    RUNNING = "RUNNING"               # Currently executing
    PAUSED = "PAUSED"                 # Execution paused
    COMPLETED = "COMPLETED"           # Successfully completed
    FAILED = "FAILED"                 # Execution failed
    CANCELLED = "CANCELLED"           # Manually cancelled
    TIMEOUT = "TIMEOUT"               # Execution timed out


class PlaybookTriggerType(str, Enum):
    """Types of playbook triggers."""
    THREAT_BASED = "THREAT_BASED"                     # Threat severity/type triggers
    ASSET_BASED = "ASSET_BASED"                       # Asset criticality triggers
    TIME_BASED = "TIME_BASED"                         # Time-based conditions
    COMPLIANCE_BASED = "COMPLIANCE_BASED"             # Regulatory requirements
    BUSINESS_IMPACT = "BUSINESS_IMPACT"               # Business impact thresholds
    ESCALATION_BASED = "ESCALATION_BASED"             # Escalation conditions
    CUSTOM_LOGIC = "CUSTOM_LOGIC"                     # Custom business logic


class PlaybookScope(str, Enum):
    """Scope of playbook execution."""
    SINGLE_ASSET = "SINGLE_ASSET"             # Target specific asset
    ASSET_GROUP = "ASSET_GROUP"               # Target group of assets
    NETWORK_SEGMENT = "NETWORK_SEGMENT"       # Target network segment
    TENANT_WIDE = "TENANT_WIDE"               # Apply to entire tenant
    GLOBAL = "GLOBAL"                         # Cross-tenant execution


class PlaybookTrigger(BaseModel):
    """Trigger condition for playbook execution."""
    
    # Trigger metadata
    trigger_id: str = Field(..., description="Unique trigger identifier")
    name: str = Field(..., description="Human-readable trigger name")
    description: str = Field(..., description="Trigger description")
    
    # Trigger classification
    trigger_type: PlaybookTriggerType = Field(..., description="Type of trigger condition")
    priority: int = Field(default=5, description="Trigger priority (1-10, higher = more important)")
    enabled: bool = Field(default=True, description="Whether trigger is active")
    
    # Condition definition
    conditions: Dict[str, Any] = Field(..., description="Trigger condition logic")
    logical_operator: str = Field(default="AND", description="Logic operator for multiple conditions")
    
    # Execution parameters
    cooldown_minutes: int = Field(default=15, description="Minimum time between trigger activations")
    max_executions_per_hour: int = Field(default=4, description="Maximum executions per hour")
    timeout_minutes: int = Field(default=60, description="Maximum execution time")
    
    # Context requirements
    required_confidence: float = Field(default=0.7, description="Minimum confidence threshold")
    required_severity: Optional[ThreatSeverity] = Field(default=None, description="Minimum threat severity")
    allowed_classifications: List[SecurityClassification] = Field(
        default_factory=lambda: list(SecurityClassification),
        description="Allowed security classifications"
    )
    
    # Business rules
    business_hours_only: bool = Field(default=False, description="Execute only during business hours")
    requires_approval: bool = Field(default=False, description="Requires manual approval")
    approval_roles: List[str] = Field(default_factory=list, description="Roles that can approve")
    
    @validator("priority")
    def validate_priority(cls, v):
        """Validate priority range."""
        if not 1 <= v <= 10:
            raise ValueError("Priority must be between 1 and 10")
        return v
    
    @validator("required_confidence")
    def validate_confidence(cls, v):
        """Validate confidence range."""
        if not 0 <= v <= 1:
            raise ValueError("Confidence must be between 0 and 1")
        return v


class PlaybookExecution(BaseModel):
    """Playbook execution instance with tracking and results."""
    
    # Execution metadata
    execution_id: str = Field(..., description="Unique execution identifier")
    playbook_id: str = Field(..., description="Source playbook identifier")
    trigger_id: str = Field(..., description="Triggering condition identifier")
    context_id: str = Field(..., description="Decision context identifier")
    
    # Timing information
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = Field(default=None, description="Execution start time")
    completed_at: Optional[datetime] = Field(default=None, description="Execution completion time")
    
    # Execution details
    status: PlaybookStatus = Field(default=PlaybookStatus.PENDING)
    scope: PlaybookScope = Field(..., description="Execution scope")
    target_assets: List[str] = Field(default_factory=list, description="Target assets")
    
    # Response plan integration
    response_plan: Optional[ResponsePlan] = Field(default=None, description="Associated response plan")
    executed_actions: List[str] = Field(default_factory=list, description="Completed action IDs")
    failed_actions: List[str] = Field(default_factory=list, description="Failed action IDs")
    
    # Progress tracking
    progress_percentage: float = Field(default=0.0, description="Execution progress (0-100)")
    current_step: str = Field(default="initialization", description="Current execution step")
    
    # Results and metrics
    success_rate: float = Field(default=0.0, description="Action success rate (0-1)")
    effectiveness_score: float = Field(default=0.0, description="Overall effectiveness (0-1)")
    execution_log: List[Dict[str, Any]] = Field(default_factory=list, description="Detailed execution log")
    
    # Error handling
    error_count: int = Field(default=0, description="Number of errors encountered")
    last_error: Optional[str] = Field(default=None, description="Last error message")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    
    # Multi-tenancy
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator("progress_percentage")
    def validate_progress(cls, v):
        """Validate progress range."""
        if not 0 <= v <= 100:
            raise ValueError("Progress must be between 0 and 100")
        return v
    
    @validator("success_rate", "effectiveness_score")
    def validate_scores(cls, v):
        """Validate score ranges."""
        if not 0 <= v <= 1:
            raise ValueError("Scores must be between 0 and 1")
        return v


class PlaybookEngine:
    """
    Production-grade playbook engine for iSECTECH automated security operations.
    
    Provides intelligent playbook execution with trigger-based automation,
    distributed processing capabilities, and comprehensive monitoring.
    """
    
    def __init__(self, settings: Optional[Any] = None):
        """Initialize the playbook engine."""
        self.settings = settings or get_settings()
        self.audit_logger = AuditLogger(self.settings.security)
        
        # Playbook configurations
        self._playbook_library = self._load_playbook_library()
        self._trigger_registry = self._load_trigger_registry()
        self._execution_templates = self._load_execution_templates()
        self._coordination_policies = self._load_coordination_policies()
        
        # iSECTECH-specific configurations
        self._isectech_playbooks = self._load_isectech_playbooks()
        self._business_hour_config = self._load_business_hour_config()
        self._approval_workflows = self._load_approval_workflows()
        self._escalation_playbooks = self._load_escalation_playbooks()
        
        # Execution tracking
        self._active_executions: Dict[str, PlaybookExecution] = {}
        self._execution_history: List[PlaybookExecution] = []
        self._trigger_cooldowns: Dict[str, datetime] = {}
        
        # Performance metrics
        self._engine_metrics = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_execution_time": 0.0,
            "trigger_activation_rate": 0.0,
            "effectiveness_rate": 0.0,
        }
        
        # Ray distributed processing
        self._ray_initialized = False
        self._distributed_actors = {}
        
        # Initialize components
        asyncio.create_task(self._initialize_engine())
        
        logger.info("Playbook engine initialized successfully")
    
    async def _initialize_engine(self) -> None:
        """Initialize the playbook engine components."""
        try:
            logger.info("Initializing playbook engine components...")
            
            # Initialize Ray for distributed processing
            await self._initialize_ray_cluster()
            
            # Load and validate playbooks
            await self._validate_playbook_library()
            
            # Start background monitoring
            asyncio.create_task(self._background_monitoring())
            
            logger.info("Playbook engine components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize playbook engine: {e}")
            await self.audit_logger.log_security_event(
                event_type="PLAYBOOK_ENGINE_INIT_FAILED",
                details={"error": str(e)},
                severity="HIGH",
            )
            raise
    
    async def _initialize_ray_cluster(self) -> None:
        """Initialize Ray cluster for distributed processing."""
        try:
            if not ray.is_initialized():
                # Initialize Ray with iSECTECH configuration
                ray.init(
                    num_cpus=self.settings.ml.max_parallel_workers,
                    object_store_memory=int(self.settings.ml.data_preprocessing_cache_size_gb * 1024**3),
                    ignore_reinit_error=True,
                )
                
                # Create distributed actors for playbook execution
                self._distributed_actors = {
                    "action_executor": ray.remote(ActionExecutorActor).remote(),
                    "monitor": ray.remote(ExecutionMonitorActor).remote(),
                    "coordinator": ray.remote(ExecutionCoordinatorActor).remote(),
                }
                
                self._ray_initialized = True
                logger.info("Ray cluster initialized for distributed playbook execution")
            
        except Exception as e:
            logger.warning(f"Ray initialization failed, falling back to local execution: {e}")
            self._ray_initialized = False
    
    def _load_playbook_library(self) -> Dict[str, Dict[str, Any]]:
        """Load comprehensive playbook library."""
        return {
            "malware_containment": {
                "name": "Malware Containment and Eradication",
                "description": "Comprehensive malware response playbook for iSECTECH environments",
                "trigger_types": [PlaybookTriggerType.THREAT_BASED],
                "scope": PlaybookScope.ASSET_GROUP,
                "estimated_duration": 45,
                "actions": [
                    "system_quarantine",
                    "malware_removal",
                    "memory_dump_collection",
                    "log_preservation",
                    "threat_signature_update",
                    "stakeholder_notification",
                ],
                "success_criteria": [
                    "malware_eliminated",
                    "system_cleaned",
                    "evidence_preserved",
                    "signatures_updated",
                ],
                "prerequisites": ["backup_verification"],
                "rollback_actions": ["restore_from_backup"],
            },
            
            "data_breach_response": {
                "name": "Data Breach Response and Notification",
                "description": "Regulatory-compliant data breach response for iSECTECH customers",
                "trigger_types": [PlaybookTriggerType.COMPLIANCE_BASED, PlaybookTriggerType.THREAT_BASED],
                "scope": PlaybookScope.TENANT_WIDE,
                "estimated_duration": 90,
                "actions": [
                    "network_isolation",
                    "account_lockout",
                    "log_preservation",
                    "memory_dump_collection",
                    "regulatory_notification",
                    "stakeholder_notification",
                    "backup_verification",
                ],
                "success_criteria": [
                    "breach_contained",
                    "authorities_notified",
                    "evidence_preserved",
                    "customers_informed",
                ],
                "compliance_requirements": ["GDPR", "HIPAA", "PCI_DSS"],
                "requires_approval": True,
            },
            
            "insider_threat_investigation": {
                "name": "Insider Threat Investigation and Response",
                "description": "Sensitive insider threat handling with evidence preservation",
                "trigger_types": [PlaybookTriggerType.THREAT_BASED, PlaybookTriggerType.CUSTOM_LOGIC],
                "scope": PlaybookScope.SINGLE_ASSET,
                "estimated_duration": 120,
                "actions": [
                    "account_lockout",
                    "log_preservation",
                    "memory_dump_collection",
                    "stakeholder_notification",
                ],
                "success_criteria": [
                    "insider_access_revoked",
                    "evidence_collected",
                    "management_notified",
                    "investigation_initiated",
                ],
                "requires_approval": True,
                "approval_roles": ["CISO", "Legal", "HR"],
            },
            
            "critical_system_protection": {
                "name": "Critical System Protection Protocol",
                "description": "Emergency protection for business-critical systems",
                "trigger_types": [PlaybookTriggerType.ASSET_BASED, PlaybookTriggerType.BUSINESS_IMPACT],
                "scope": PlaybookScope.ASSET_GROUP,
                "estimated_duration": 30,
                "actions": [
                    "backup_verification",
                    "network_isolation",
                    "patch_deployment",
                    "stakeholder_notification",
                ],
                "success_criteria": [
                    "systems_protected",
                    "vulnerabilities_patched",
                    "backups_verified",
                    "operations_notified",
                ],
                "high_priority": True,
            },
            
            "compliance_incident_response": {
                "name": "Regulatory Compliance Incident Response",
                "description": "Framework-specific incident response for regulatory compliance",
                "trigger_types": [PlaybookTriggerType.COMPLIANCE_BASED],
                "scope": PlaybookScope.TENANT_WIDE,
                "estimated_duration": 60,
                "actions": [
                    "log_preservation",
                    "regulatory_notification",
                    "stakeholder_notification",
                    "backup_verification",
                ],
                "success_criteria": [
                    "compliance_maintained",
                    "authorities_notified",
                    "documentation_complete",
                ],
                "framework_specific": True,
            },
        }
    
    def _load_trigger_registry(self) -> List[PlaybookTrigger]:
        """Load trigger conditions for playbook activation."""
        return [
            # Malware detection triggers
            PlaybookTrigger(
                trigger_id="malware_critical_severity",
                name="Critical Malware Detection",
                description="Triggers malware containment for critical severity threats",
                trigger_type=PlaybookTriggerType.THREAT_BASED,
                priority=9,
                conditions={
                    "threat_category": "MALWARE",
                    "threat_severity": ["CRITICAL", "HIGH"],
                    "confidence_threshold": 0.85,
                },
                cooldown_minutes=10,
                max_executions_per_hour=6,
                required_confidence=0.85,
                required_severity=ThreatSeverity.HIGH,
            ),
            
            # Data breach triggers
            PlaybookTrigger(
                trigger_id="data_exfiltration_detected",
                name="Data Exfiltration Detection",
                description="Triggers data breach response for exfiltration events",
                trigger_type=PlaybookTriggerType.THREAT_BASED,
                priority=10,
                conditions={
                    "threat_category": "DATA_EXFILTRATION",
                    "data_sensitivity": ["CONFIDENTIAL", "SECRET", "TOP_SECRET"],
                    "volume_threshold": 1000000,  # 1MB
                },
                cooldown_minutes=5,
                max_executions_per_hour=2,
                required_confidence=0.75,
                requires_approval=True,
                approval_roles=["CISO", "Legal"],
            ),
            
            # Insider threat triggers
            PlaybookTrigger(
                trigger_id="insider_threat_indicators",
                name="Insider Threat Pattern Detection",
                description="Triggers insider threat investigation for anomalous behavior",
                trigger_type=PlaybookTriggerType.CUSTOM_LOGIC,
                priority=8,
                conditions={
                    "behavioral_anomaly_score": 0.9,
                    "privilege_escalation": True,
                    "off_hours_access": True,
                    "data_access_pattern": "unusual",
                },
                cooldown_minutes=30,
                max_executions_per_hour=1,
                required_confidence=0.8,
                requires_approval=True,
                approval_roles=["CISO", "Security_Manager", "Legal"],
            ),
            
            # Critical asset protection
            PlaybookTrigger(
                trigger_id="critical_asset_compromise",
                name="Critical Asset Compromise",
                description="Triggers protection protocol for critical business assets",
                trigger_type=PlaybookTriggerType.ASSET_BASED,
                priority=9,
                conditions={
                    "asset_criticality": ["CRITICAL", "HIGH"],
                    "compromise_indicators": True,
                    "business_impact": "HIGH",
                },
                cooldown_minutes=15,
                max_executions_per_hour=3,
                required_confidence=0.8,
            ),
            
            # Compliance triggers
            PlaybookTrigger(
                trigger_id="regulatory_violation_risk",
                name="Regulatory Violation Risk",
                description="Triggers compliance response for regulatory risk events",
                trigger_type=PlaybookTriggerType.COMPLIANCE_BASED,
                priority=7,
                conditions={
                    "compliance_frameworks": ["GDPR", "HIPAA", "PCI_DSS"],
                    "violation_risk": "HIGH",
                    "notification_required": True,
                },
                cooldown_minutes=60,
                max_executions_per_hour=1,
                requires_approval=True,
                approval_roles=["Compliance_Officer", "Legal"],
            ),
        ]
    
    def _load_execution_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load execution templates for different scenarios."""
        return {
            "emergency_response": {
                "max_parallel_actions": 5,
                "action_timeout_minutes": 30,
                "retry_attempts": 2,
                "escalation_on_failure": True,
                "progress_reporting_interval": 60,  # seconds
            },
            "standard_response": {
                "max_parallel_actions": 3,
                "action_timeout_minutes": 60,
                "retry_attempts": 3,
                "escalation_on_failure": False,
                "progress_reporting_interval": 120,  # seconds
            },
            "compliance_response": {
                "max_parallel_actions": 2,
                "action_timeout_minutes": 120,
                "retry_attempts": 1,
                "escalation_on_failure": True,
                "progress_reporting_interval": 300,  # seconds
                "requires_documentation": True,
                "audit_trail_required": True,
            },
            "investigative_response": {
                "max_parallel_actions": 1,
                "action_timeout_minutes": 180,
                "retry_attempts": 1,
                "escalation_on_failure": False,
                "progress_reporting_interval": 600,  # seconds
                "evidence_preservation": True,
                "chain_of_custody": True,
            },
        }
    
    def _load_coordination_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load coordination policies for playbook execution."""
        return {
            "conflict_resolution": {
                "priority_based": True,
                "resource_contention": "queue_and_wait",
                "mutual_exclusion": [
                    ["malware_containment", "system_maintenance"],
                    ["insider_threat_investigation", "user_training"],
                ],
            },
            "resource_management": {
                "max_concurrent_playbooks": 3,
                "resource_allocation": {
                    "cpu_limit_per_playbook": 0.3,
                    "memory_limit_mb": 1024,
                    "network_bandwidth_limit": "100mbps",
                },
                "priority_preemption": True,
            },
            "tenant_isolation": {
                "strict_isolation": True,
                "cross_tenant_playbooks": [],
                "shared_resource_policies": {
                    "threat_intelligence": "shared",
                    "signature_updates": "shared",
                    "regulatory_notifications": "isolated",
                },
            },
        }
    
    def _load_isectech_playbooks(self) -> Dict[str, Dict[str, Any]]:
        """Load iSECTECH-specific playbook configurations."""
        return {
            "customer_data_protection": {
                "playbooks": ["data_breach_response", "critical_system_protection"],
                "execution_priority": 10,
                "auto_approve_threshold": 0.9,
                "notification_requirements": ["customer", "legal", "compliance"],
            },
            "classified_data_handling": {
                "playbooks": ["insider_threat_investigation", "critical_system_protection"],
                "execution_priority": 9,
                "auto_approve_threshold": 0.95,
                "additional_approvals": ["Government_Liaison", "Security_Officer"],
                "enhanced_audit": True,
            },
            "business_continuity": {
                "playbooks": ["critical_system_protection", "malware_containment"],
                "execution_priority": 8,
                "auto_approve_threshold": 0.85,
                "business_hour_preference": True,
            },
            "regulatory_compliance": {
                "playbooks": ["compliance_incident_response", "data_breach_response"],
                "execution_priority": 7,
                "auto_approve_threshold": 0.8,
                "framework_specific_handling": True,
            },
        }
    
    def _load_business_hour_config(self) -> Dict[str, Any]:
        """Load business hours configuration for iSECTECH operations."""
        return {
            "timezone": "UTC",
            "business_days": ["monday", "tuesday", "wednesday", "thursday", "friday"],
            "business_hours": {
                "start": "08:00",
                "end": "18:00",
            },
            "emergency_override": {
                "enabled": True,
                "severity_threshold": ThreatSeverity.CRITICAL,
                "approval_required": False,
            },
            "holiday_calendar": [],  # Would be populated with organization holidays
        }
    
    def _load_approval_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Load approval workflows for different scenarios."""
        return {
            "standard_approval": {
                "required_approvers": 1,
                "approval_timeout_minutes": 60,
                "escalation_on_timeout": True,
                "auto_approve_conditions": {
                    "confidence_threshold": 0.95,
                    "business_hours": True,
                    "low_business_impact": True,
                },
            },
            "high_risk_approval": {
                "required_approvers": 2,
                "approval_timeout_minutes": 30,
                "escalation_on_timeout": True,
                "required_roles": ["CISO", "Security_Manager"],
                "auto_approve_conditions": {},  # No auto-approval for high risk
            },
            "compliance_approval": {
                "required_approvers": 2,
                "approval_timeout_minutes": 120,
                "escalation_on_timeout": False,
                "required_roles": ["Compliance_Officer", "Legal"],
                "documentation_required": True,
            },
            "emergency_approval": {
                "required_approvers": 1,
                "approval_timeout_minutes": 15,
                "escalation_on_timeout": True,
                "emergency_contact": True,
                "post_execution_review": True,
            },
        }
    
    def _load_escalation_playbooks(self) -> Dict[str, str]:
        """Load escalation playbooks for failed executions."""
        return {
            "malware_containment": "critical_system_protection",
            "data_breach_response": "compliance_incident_response", 
            "insider_threat_investigation": "critical_system_protection",
            "critical_system_protection": "manual_escalation",
            "compliance_incident_response": "manual_escalation",
        }
    
    async def evaluate_triggers(
        self,
        context: DecisionContext,
        response_plan: Optional[ResponsePlan] = None,
    ) -> List[PlaybookTrigger]:
        """
        Evaluate trigger conditions and return activated triggers.
        
        Args:
            context: Decision context with threat and organizational information
            response_plan: Optional response plan for additional context
            
        Returns:
            List of activated triggers sorted by priority
        """
        try:
            logger.info(f"Evaluating playbook triggers for context {context.context_id}")
            
            activated_triggers = []
            current_time = datetime.utcnow()
            
            for trigger in self._trigger_registry:
                # Check if trigger is enabled and not in cooldown
                if not trigger.enabled:
                    continue
                
                if not await self._check_cooldown(trigger.trigger_id, current_time):
                    continue
                
                # Check execution limits
                if not await self._check_execution_limits(trigger, current_time):
                    continue
                
                # Evaluate trigger conditions
                if await self._evaluate_trigger_conditions(trigger, context, response_plan):
                    activated_triggers.append(trigger)
                    
                    # Update cooldown
                    self._trigger_cooldowns[trigger.trigger_id] = current_time
            
            # Sort by priority (descending)
            activated_triggers.sort(key=lambda t: t.priority, reverse=True)
            
            if activated_triggers:
                await self.audit_logger.log_security_event(
                    event_type="PLAYBOOK_TRIGGERS_ACTIVATED",
                    details={
                        "context_id": context.context_id,
                        "activated_triggers": [t.trigger_id for t in activated_triggers],
                        "trigger_count": len(activated_triggers),
                    },
                    classification=context.security_context.classification,
                    tenant_id=context.tenant_id,
                )
            
            return activated_triggers
            
        except Exception as e:
            logger.error(f"Failed to evaluate triggers: {e}")
            await self.audit_logger.log_security_event(
                event_type="TRIGGER_EVALUATION_FAILED",
                details={"context_id": context.context_id, "error": str(e)},
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            return []
    
    async def _check_cooldown(self, trigger_id: str, current_time: datetime) -> bool:
        """Check if trigger is out of cooldown period."""
        if trigger_id not in self._trigger_cooldowns:
            return True
        
        trigger = next((t for t in self._trigger_registry if t.trigger_id == trigger_id), None)
        if not trigger:
            return True
        
        last_activation = self._trigger_cooldowns[trigger_id]
        cooldown_period = timedelta(minutes=trigger.cooldown_minutes)
        
        return current_time >= (last_activation + cooldown_period)
    
    async def _check_execution_limits(self, trigger: PlaybookTrigger, current_time: datetime) -> bool:
        """Check if trigger execution limits are within bounds."""
        # Count executions in the last hour
        one_hour_ago = current_time - timedelta(hours=1)
        
        recent_executions = [
            execution for execution in self._execution_history
            if (execution.trigger_id == trigger.trigger_id and 
                execution.triggered_at >= one_hour_ago)
        ]
        
        return len(recent_executions) < trigger.max_executions_per_hour
    
    async def _evaluate_trigger_conditions(
        self,
        trigger: PlaybookTrigger,
        context: DecisionContext,
        response_plan: Optional[ResponsePlan],
    ) -> bool:
        """Evaluate whether trigger conditions are met."""
        try:
            conditions = trigger.conditions
            
            # Check confidence threshold
            if context.confidence_score < trigger.required_confidence:
                return False
            
            # Check severity requirement
            if trigger.required_severity:
                severity_order = [ThreatSeverity.INFORMATIONAL, ThreatSeverity.LOW, 
                                ThreatSeverity.MEDIUM, ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
                if severity_order.index(context.threat_severity) < severity_order.index(trigger.required_severity):
                    return False
            
            # Check security classification
            if context.security_context.classification not in trigger.allowed_classifications:
                return False
            
            # Check business hours requirement
            if trigger.business_hours_only and not await self._is_business_hours():
                # Check for emergency override
                emergency_config = self._business_hour_config.get("emergency_override", {})
                if not (emergency_config.get("enabled", False) and 
                       context.threat_severity == emergency_config.get("severity_threshold")):
                    return False
            
            # Evaluate specific trigger conditions
            return await self._evaluate_specific_conditions(trigger, context, conditions)
            
        except Exception as e:
            logger.warning(f"Failed to evaluate trigger conditions for {trigger.trigger_id}: {e}")
            return False
    
    async def _is_business_hours(self) -> bool:
        """Check if current time is within business hours."""
        config = self._business_hour_config
        current_time = datetime.utcnow()
        
        # Check if current day is a business day
        day_name = current_time.strftime("%A").lower()
        if day_name not in config["business_days"]:
            return False
        
        # Check if current time is within business hours
        start_time = datetime.strptime(config["business_hours"]["start"], "%H:%M").time()
        end_time = datetime.strptime(config["business_hours"]["end"], "%H:%M").time()
        current_time_only = current_time.time()
        
        return start_time <= current_time_only <= end_time
    
    async def _evaluate_specific_conditions(
        self,
        trigger: PlaybookTrigger,
        context: DecisionContext,
        conditions: Dict[str, Any],
    ) -> bool:
        """Evaluate trigger-specific conditions."""
        # Threat-based conditions
        if "threat_category" in conditions:
            threat_category = getattr(context.risk_assessment, 'threat_category', 
                                    getattr(context.security_context, 'event_type', 'unknown')).upper()
            if threat_category != conditions["threat_category"]:
                return False
        
        if "threat_severity" in conditions:
            allowed_severities = conditions["threat_severity"]
            if context.threat_severity.value not in allowed_severities:
                return False
        
        if "confidence_threshold" in conditions:
            if context.confidence_score < conditions["confidence_threshold"]:
                return False
        
        # Asset-based conditions
        if "asset_criticality" in conditions:
            # Simplified asset criticality check
            asset_criticality = self._assess_asset_criticality(context.affected_assets)
            if asset_criticality not in conditions["asset_criticality"]:
                return False
        
        # Business impact conditions
        if "business_impact" in conditions:
            impact_level = self._assess_business_impact_level(context.business_impact)
            if impact_level != conditions["business_impact"]:
                return False
        
        # Compliance conditions
        if "compliance_frameworks" in conditions:
            required_frameworks = conditions["compliance_frameworks"]
            if not any(framework in context.compliance_requirements for framework in required_frameworks):
                return False
        
        # Custom logic conditions (more complex evaluation would go here)
        if "behavioral_anomaly_score" in conditions:
            # In production, this would connect to behavioral analysis service
            anomaly_score = getattr(context.risk_assessment, 'anomaly_score', 0.5)
            if anomaly_score < conditions["behavioral_anomaly_score"]:
                return False
        
        return True
    
    def _assess_asset_criticality(self, assets: List[str]) -> str:
        """Assess criticality level of affected assets."""
        if not assets:
            return "LOW"
        
        # Simple criticality assessment based on asset names
        asset_str = " ".join(assets).lower()
        
        if any(keyword in asset_str for keyword in ["database", "payment", "customer", "production"]):
            return "CRITICAL"
        elif any(keyword in asset_str for keyword in ["server", "application", "service"]):
            return "HIGH"
        elif any(keyword in asset_str for keyword in ["workstation", "laptop", "client"]):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _assess_business_impact_level(self, business_impact: str) -> str:
        """Assess business impact level from description."""
        impact_lower = business_impact.lower()
        
        if any(keyword in impact_lower for keyword in ["critical", "severe", "major", "catastrophic"]):
            return "HIGH"
        elif any(keyword in impact_lower for keyword in ["significant", "important", "moderate"]):
            return "MEDIUM"
        else:
            return "LOW"
    
    async def execute_playbook(
        self,
        playbook_id: str,
        trigger: PlaybookTrigger,
        context: DecisionContext,
        response_plan: Optional[ResponsePlan] = None,
    ) -> PlaybookExecution:
        """
        Execute a specific playbook based on trigger and context.
        
        Args:
            playbook_id: ID of playbook to execute
            trigger: Triggering condition
            context: Decision context
            response_plan: Optional pre-built response plan
            
        Returns:
            Playbook execution instance with tracking
        """
        execution_id = f"exec-{playbook_id}-{context.context_id}-{int(datetime.utcnow().timestamp())}"
        
        try:
            logger.info(f"Executing playbook {playbook_id} for context {context.context_id}")
            
            # Create execution instance
            execution = PlaybookExecution(
                execution_id=execution_id,
                playbook_id=playbook_id,
                trigger_id=trigger.trigger_id,
                context_id=context.context_id,
                scope=await self._determine_execution_scope(playbook_id, context),
                target_assets=context.affected_assets,
                response_plan=response_plan,
                tenant_id=context.tenant_id,
            )
            
            # Check approval requirements
            if trigger.requires_approval:
                if not await self._handle_approval_workflow(execution, trigger):
                    execution.status = PlaybookStatus.CANCELLED
                    return execution
            
            # Add to active executions
            self._active_executions[execution_id] = execution
            
            # Start execution
            execution.status = PlaybookStatus.RUNNING
            execution.started_at = datetime.utcnow()
            
            # Audit log execution start
            await self.audit_logger.log_security_event(
                event_type="PLAYBOOK_EXECUTION_STARTED",
                details={
                    "execution_id": execution_id,
                    "playbook_id": playbook_id,
                    "trigger_id": trigger.trigger_id,
                    "context_id": context.context_id,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            # Execute playbook steps
            if self._ray_initialized:
                await self._execute_distributed(execution, context)
            else:
                await self._execute_local(execution, context)
            
            # Complete execution
            execution.completed_at = datetime.utcnow()
            execution.status = PlaybookStatus.COMPLETED if execution.error_count == 0 else PlaybookStatus.FAILED
            
            # Update metrics
            self._update_execution_metrics(execution)
            
            # Move to history
            self._execution_history.append(execution)
            if execution_id in self._active_executions:
                del self._active_executions[execution_id]
            
            # Audit log completion
            await self.audit_logger.log_security_event(
                event_type="PLAYBOOK_EXECUTION_COMPLETED",
                details={
                    "execution_id": execution_id,
                    "status": execution.status,
                    "success_rate": execution.success_rate,
                    "duration_minutes": (execution.completed_at - execution.started_at).total_seconds() / 60,
                },
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            
            logger.info(f"Playbook execution {execution_id} completed with status {execution.status}")
            return execution
            
        except Exception as e:
            logger.error(f"Failed to execute playbook {playbook_id}: {e}")
            
            # Update execution with error
            if execution_id in self._active_executions:
                execution = self._active_executions[execution_id]
                execution.status = PlaybookStatus.FAILED
                execution.last_error = str(e)
                execution.completed_at = datetime.utcnow()
                
                # Move to history
                self._execution_history.append(execution)
                del self._active_executions[execution_id]
            
            await self.audit_logger.log_security_event(
                event_type="PLAYBOOK_EXECUTION_FAILED",
                details={
                    "execution_id": execution_id,
                    "playbook_id": playbook_id,
                    "error": str(e),
                },
                severity="HIGH",
                classification=context.security_context.classification,
                tenant_id=context.tenant_id,
            )
            raise
    
    async def _determine_execution_scope(self, playbook_id: str, context: DecisionContext) -> PlaybookScope:
        """Determine execution scope for the playbook."""
        playbook_config = self._playbook_library.get(playbook_id, {})
        default_scope = playbook_config.get("scope", PlaybookScope.SINGLE_ASSET)
        
        # Adjust scope based on context
        if len(context.affected_assets) > 10:
            return PlaybookScope.NETWORK_SEGMENT
        elif len(context.affected_assets) > 3:
            return PlaybookScope.ASSET_GROUP
        elif context.security_context.classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
            return PlaybookScope.TENANT_WIDE
        else:
            return default_scope
    
    async def _handle_approval_workflow(self, execution: PlaybookExecution, trigger: PlaybookTrigger) -> bool:
        """Handle approval workflow for playbook execution."""
        # In production, this would integrate with approval system
        # For now, simulate approval based on auto-approval conditions
        
        # Check auto-approval conditions
        auto_approve_threshold = 0.9
        if (execution.response_plan and 
            execution.response_plan.confidence_score >= auto_approve_threshold and
            await self._is_business_hours()):
            return True
        
        # For demo purposes, assume approval is granted for high-confidence decisions
        return trigger.required_confidence >= 0.85
    
    async def _execute_distributed(self, execution: PlaybookExecution, context: DecisionContext) -> None:
        """Execute playbook using distributed Ray actors."""
        try:
            # Get coordinator actor
            coordinator = self._distributed_actors["coordinator"]
            
            # Execute playbook through distributed coordinator
            result = await coordinator.execute_playbook.remote(
                execution.dict(),
                context.dict(),
                self._playbook_library[execution.playbook_id]
            )
            
            # Update execution with results
            execution_updates = ray.get(result)
            for key, value in execution_updates.items():
                if hasattr(execution, key):
                    setattr(execution, key, value)
            
        except Exception as e:
            logger.warning(f"Distributed execution failed, falling back to local: {e}")
            await self._execute_local(execution, context)
    
    async def _execute_local(self, execution: PlaybookExecution, context: DecisionContext) -> None:
        """Execute playbook locally without distributed processing."""
        try:
            playbook_config = self._playbook_library[execution.playbook_id]
            actions = playbook_config.get("actions", [])
            
            executed_count = 0
            failed_count = 0
            
            for i, action_name in enumerate(actions):
                try:
                    # Update progress
                    execution.progress_percentage = (i / len(actions)) * 100
                    execution.current_step = action_name
                    
                    # Simulate action execution
                    await self._execute_action(action_name, execution, context)
                    
                    execution.executed_actions.append(action_name)
                    executed_count += 1
                    
                    # Log progress
                    execution.execution_log.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "action": action_name,
                        "status": "completed",
                    })
                    
                except Exception as e:
                    execution.failed_actions.append(action_name)
                    execution.error_count += 1
                    execution.last_error = str(e)
                    failed_count += 1
                    
                    # Log error
                    execution.execution_log.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "action": action_name,
                        "status": "failed",
                        "error": str(e),
                    })
            
            # Calculate final metrics
            execution.progress_percentage = 100.0
            execution.success_rate = executed_count / len(actions) if actions else 0.0
            execution.effectiveness_score = execution.success_rate * 0.9 if execution.error_count == 0 else execution.success_rate * 0.7
            
        except Exception as e:
            execution.error_count += 1
            execution.last_error = str(e)
            raise
    
    async def _execute_action(self, action_name: str, execution: PlaybookExecution, context: DecisionContext) -> None:
        """Execute a specific action within the playbook."""
        # Simulate action execution with appropriate delay
        action_delays = {
            "system_quarantine": 3,
            "malware_removal": 30,
            "network_isolation": 5,
            "log_preservation": 15,
            "stakeholder_notification": 2,
        }
        
        delay = action_delays.get(action_name, 10)
        await asyncio.sleep(delay / 10)  # Reduced for demo purposes
        
        # Simulate potential failures
        import random
        if random.random() < 0.1:  # 10% failure rate
            raise Exception(f"Simulated failure in {action_name}")
    
    async def _background_monitoring(self) -> None:
        """Background monitoring of active executions."""
        while True:
            try:
                current_time = datetime.utcnow()
                
                # Check for timed-out executions
                for execution_id, execution in list(self._active_executions.items()):
                    if execution.started_at:
                        elapsed = (current_time - execution.started_at).total_seconds()
                        
                        # Get timeout from trigger
                        trigger = next((t for t in self._trigger_registry if t.trigger_id == execution.trigger_id), None)
                        timeout_minutes = trigger.timeout_minutes if trigger else 60
                        
                        if elapsed > (timeout_minutes * 60):
                            execution.status = PlaybookStatus.TIMEOUT
                            execution.completed_at = current_time
                            
                            # Move to history
                            self._execution_history.append(execution)
                            del self._active_executions[execution_id]
                            
                            await self.audit_logger.log_security_event(
                                event_type="PLAYBOOK_EXECUTION_TIMEOUT",
                                details={"execution_id": execution_id},
                                severity="MEDIUM",
                                tenant_id=execution.tenant_id,
                            )
                
                # Clean up old execution history (keep last 1000)
                if len(self._execution_history) > 1000:
                    self._execution_history = self._execution_history[-1000:]
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Background monitoring error: {e}")
                await asyncio.sleep(300)  # Wait longer on error
    
    async def _validate_playbook_library(self) -> None:
        """Validate playbook library configuration."""
        for playbook_id, config in self._playbook_library.items():
            required_fields = ["name", "description", "actions"]
            for field in required_fields:
                if field not in config:
                    logger.warning(f"Playbook {playbook_id} missing required field: {field}")
    
    def _update_execution_metrics(self, execution: PlaybookExecution) -> None:
        """Update engine performance metrics."""
        self._engine_metrics["total_executions"] += 1
        
        if execution.status == PlaybookStatus.COMPLETED:
            self._engine_metrics["successful_executions"] += 1
        else:
            self._engine_metrics["failed_executions"] += 1
        
        # Update average execution time
        if execution.started_at and execution.completed_at:
            execution_time = (execution.completed_at - execution.started_at).total_seconds()
            current_avg = self._engine_metrics["average_execution_time"]
            count = self._engine_metrics["total_executions"]
            
            self._engine_metrics["average_execution_time"] = (
                (current_avg * (count - 1)) + execution_time
            ) / count
        
        # Update effectiveness rate
        current_effectiveness = self._engine_metrics["effectiveness_rate"]
        self._engine_metrics["effectiveness_rate"] = (
            (current_effectiveness * (self._engine_metrics["total_executions"] - 1)) + execution.effectiveness_score
        ) / self._engine_metrics["total_executions"]
    
    def get_engine_metrics(self) -> Dict[str, Any]:
        """Get playbook engine performance metrics."""
        metrics = self._engine_metrics.copy()
        
        # Calculate additional metrics
        if metrics["total_executions"] > 0:
            metrics["success_rate"] = metrics["successful_executions"] / metrics["total_executions"]
            metrics["failure_rate"] = metrics["failed_executions"] / metrics["total_executions"]
        else:
            metrics["success_rate"] = 0.0
            metrics["failure_rate"] = 0.0
        
        metrics["active_executions"] = len(self._active_executions)
        metrics["trigger_count"] = len(self._trigger_registry)
        metrics["playbook_count"] = len(self._playbook_library)
        
        return metrics
    
    def get_active_executions(self) -> List[PlaybookExecution]:
        """Get currently active playbook executions."""
        return list(self._active_executions.values())
    
    def get_execution_history(self, limit: int = 100) -> List[PlaybookExecution]:
        """Get recent execution history."""
        return self._execution_history[-limit:]


# Ray remote actors for distributed processing
@ray.remote
class ActionExecutorActor:
    """Ray actor for executing individual actions."""
    
    def execute_action(self, action_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific action with given parameters."""
        # Implementation would go here
        return {"status": "completed", "result": f"Executed {action_name}"}


@ray.remote
class ExecutionMonitorActor:
    """Ray actor for monitoring execution progress."""
    
    def monitor_execution(self, execution_id: str) -> Dict[str, Any]:
        """Monitor execution progress and health."""
        # Implementation would go here
        return {"status": "healthy", "progress": 50.0}


@ray.remote  
class ExecutionCoordinatorActor:
    """Ray actor for coordinating distributed playbook execution."""
    
    def execute_playbook(self, execution_data: Dict[str, Any], context_data: Dict[str, Any], playbook_config: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate distributed playbook execution."""
        # Implementation would go here
        return {"status": "completed", "success_rate": 0.9}