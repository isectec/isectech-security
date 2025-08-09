"""
API Models for Automated Decision Making and Response Service

Defines request/response models for:
- Risk-based decision making and response selection
- Automated playbook execution and orchestration
- Containment action authorization and security clearance
- Feedback learning from human overrides
- Response coordination and business impact assessment
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, validator


class DecisionInput(BaseModel):
    """Input data for decision making"""
    incident_id: str = Field(..., description="Incident identifier")
    threat_data: Dict[str, Any] = Field(..., description="Threat analysis data")
    context_data: Dict[str, Any] = Field(..., description="Additional context data")
    user_id: str = Field(..., description="User associated with incident")
    asset_criticality: str = Field(..., description="Asset criticality level")
    business_impact: str = Field(..., description="Potential business impact")
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator('asset_criticality')
    def validate_asset_criticality(cls, v):
        allowed_levels = ['low', 'medium', 'high', 'critical']
        if v.lower() not in allowed_levels:
            raise ValueError(f"Asset criticality must be one of: {allowed_levels}")
        return v.lower()
    
    @validator('business_impact')
    def validate_business_impact(cls, v):
        allowed_impacts = ['minimal', 'low', 'medium', 'high', 'severe']
        if v.lower() not in allowed_impacts:
            raise ValueError(f"Business impact must be one of: {allowed_impacts}")
        return v.lower()


class DecisionRequest(BaseModel):
    """Request for automated decision making"""
    decision_input: DecisionInput = Field(..., description="Decision input data")
    decision_type: str = Field(..., description="Type of decision requested")
    urgency_level: str = Field("medium", description="Decision urgency level")
    constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Decision constraints and parameters"
    )
    require_human_approval: bool = Field(False, description="Require human approval before execution")
    max_response_time_seconds: int = Field(300, description="Maximum response time in seconds")
    
    @validator('decision_type')
    def validate_decision_type(cls, v):
        allowed_types = ['containment', 'investigation', 'notification', 'remediation', 'escalation']
        if v not in allowed_types:
            raise ValueError(f"Decision type must be one of: {allowed_types}")
        return v
    
    @validator('urgency_level')
    def validate_urgency_level(cls, v):
        allowed_levels = ['low', 'medium', 'high', 'critical', 'emergency']
        if v.lower() not in allowed_levels:
            raise ValueError(f"Urgency level must be one of: {allowed_levels}")
        return v.lower()


class ResponseAction(BaseModel):
    """Individual response action"""
    action_id: str = Field(..., description="Unique action identifier")
    action_type: str = Field(..., description="Type of response action")
    action_name: str = Field(..., description="Human-readable action name")
    description: str = Field(..., description="Action description")
    parameters: Dict[str, Any] = Field(..., description="Action parameters")
    estimated_duration: str = Field(..., description="Estimated execution duration")
    required_approvals: List[str] = Field(..., description="Required approval levels")
    risk_level: str = Field(..., description="Risk level of executing action")
    reversible: bool = Field(..., description="Whether action is reversible")
    dependencies: List[str] = Field(..., description="Action dependencies")


class DecisionResult(BaseModel):
    """Result of automated decision making"""
    decision_id: str = Field(..., description="Unique decision identifier")
    incident_id: str = Field(..., description="Related incident identifier")
    decision_type: str = Field(..., description="Type of decision made")
    recommended_actions: List[ResponseAction] = Field(..., description="Recommended response actions")
    confidence_score: float = Field(..., description="Decision confidence (0-1)")
    reasoning: str = Field(..., description="Decision reasoning explanation")
    risk_assessment: Dict[str, Any] = Field(..., description="Risk assessment results")
    business_impact_analysis: Dict[str, Any] = Field(..., description="Business impact analysis")
    alternative_options: List[Dict[str, Any]] = Field(..., description="Alternative response options")
    execution_timeline: str = Field(..., description="Recommended execution timeline")
    monitoring_requirements: List[str] = Field(..., description="Monitoring requirements")
    success_criteria: List[str] = Field(..., description="Success criteria for actions")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Rollback plan if needed")
    timestamp: datetime = Field(..., description="Decision timestamp")


class PlaybookExecutionRequest(BaseModel):
    """Request for playbook execution"""
    playbook_name: str = Field(..., description="Name of playbook to execute")
    incident_id: str = Field(..., description="Incident identifier")
    trigger_data: Dict[str, Any] = Field(..., description="Playbook trigger data")
    execution_mode: str = Field("automatic", description="Execution mode")
    override_parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters to override in playbook"
    )
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator('execution_mode')
    def validate_execution_mode(cls, v):
        allowed_modes = ['automatic', 'semi_automatic', 'manual', 'simulation']
        if v not in allowed_modes:
            raise ValueError(f"Execution mode must be one of: {allowed_modes}")
        return v


class PlaybookStep(BaseModel):
    """Individual playbook execution step"""
    step_id: str = Field(..., description="Step identifier")
    step_name: str = Field(..., description="Step name")
    status: str = Field(..., description="Step execution status")
    started_at: Optional[datetime] = Field(None, description="Step start time")
    completed_at: Optional[datetime] = Field(None, description="Step completion time")
    duration_ms: Optional[float] = Field(None, description="Step duration in milliseconds")
    result: Optional[Dict[str, Any]] = Field(None, description="Step execution result")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    retry_count: int = Field(0, description="Number of retries attempted")


class PlaybookExecution(BaseModel):
    """Playbook execution status and results"""
    execution_id: str = Field(..., description="Unique execution identifier")
    playbook_name: str = Field(..., description="Executed playbook name")
    incident_id: str = Field(..., description="Related incident identifier")
    status: str = Field(..., description="Overall execution status")
    progress_percent: float = Field(..., description="Execution progress (0-100)")
    started_at: datetime = Field(..., description="Execution start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    completed_at: Optional[datetime] = Field(None, description="Actual completion time")
    steps: List[PlaybookStep] = Field(..., description="Execution steps")
    results: Dict[str, Any] = Field(..., description="Execution results")
    metrics: Dict[str, float] = Field(..., description="Execution metrics")
    logs: List[str] = Field(..., description="Execution logs")


class ContainmentRequest(BaseModel):
    """Request for containment action authorization"""
    action_type: str = Field(..., description="Type of containment action")
    target_assets: List[str] = Field(..., description="Target assets for containment")
    threat_level: str = Field(..., description="Assessed threat level")
    business_justification: str = Field(..., description="Business justification for action")
    requested_by: str = Field(..., description="User requesting containment")
    incident_id: str = Field(..., description="Related incident identifier")
    urgency: str = Field(..., description="Containment urgency level")
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator('action_type')
    def validate_action_type(cls, v):
        allowed_types = [
            'network_isolation', 'account_disable', 'system_shutdown',
            'process_termination', 'file_quarantine', 'traffic_blocking'
        ]
        if v not in allowed_types:
            raise ValueError(f"Action type must be one of: {allowed_types}")
        return v
    
    @validator('threat_level')
    def validate_threat_level(cls, v):
        allowed_levels = ['low', 'medium', 'high', 'critical']
        if v.lower() not in allowed_levels:
            raise ValueError(f"Threat level must be one of: {allowed_levels}")
        return v.lower()


class ContainmentAuthorization(BaseModel):
    """Containment action authorization result"""
    authorization_id: str = Field(..., description="Unique authorization identifier")
    incident_id: str = Field(..., description="Related incident identifier")
    action_type: str = Field(..., description="Authorized action type")
    authorization_status: str = Field(..., description="Authorization status")
    authorized_by: str = Field(..., description="Authorizing entity")
    clearance_level: str = Field(..., description="Required clearance level")
    conditions: List[str] = Field(..., description="Authorization conditions")
    expiration_time: datetime = Field(..., description="Authorization expiration")
    monitoring_requirements: List[str] = Field(..., description="Required monitoring")
    rollback_authority: str = Field(..., description="Entity authorized to rollback")
    justification: str = Field(..., description="Authorization justification")
    timestamp: datetime = Field(..., description="Authorization timestamp")


class FeedbackInput(BaseModel):
    """Human feedback input for learning"""
    decision_id: str = Field(..., description="Decision identifier being overridden")
    feedback_type: str = Field(..., description="Type of feedback")
    human_decision: str = Field(..., description="Human decision made")
    reasoning: str = Field(..., description="Human reasoning for override")
    outcome_assessment: str = Field(..., description="Assessment of decision outcome")
    suggested_improvements: List[str] = Field(..., description="Suggested improvements")
    confidence_in_override: float = Field(..., description="Confidence in human decision (0-1)")
    provided_by: str = Field(..., description="User providing feedback")
    tenant_id: str = Field(..., description="Tenant identifier")
    
    @validator('feedback_type')
    def validate_feedback_type(cls, v):
        allowed_types = ['override', 'modification', 'approval', 'rejection', 'improvement']
        if v not in allowed_types:
            raise ValueError(f"Feedback type must be one of: {allowed_types}")
        return v


class LearningResult(BaseModel):
    """Result of feedback learning process"""
    learning_id: str = Field(..., description="Unique learning identifier")
    feedback_processed: int = Field(..., description="Number of feedback items processed")
    patterns_identified: List[str] = Field(..., description="Identified patterns from feedback")
    model_adjustments: Dict[str, Any] = Field(..., description="Model adjustments made")
    confidence_improvements: Dict[str, float] = Field(..., description="Confidence improvements")
    bias_detections: List[str] = Field(..., description="Detected biases")
    recommendations: List[str] = Field(..., description="Recommendations for improvement")
    impact_assessment: Dict[str, Any] = Field(..., description="Impact assessment of changes")
    timestamp: datetime = Field(..., description="Learning process timestamp")


class RiskCalculationRequest(BaseModel):
    """Request for risk calculation"""
    incident_data: Dict[str, Any] = Field(..., description="Incident data for risk calculation")
    asset_information: Dict[str, Any] = Field(..., description="Asset information")
    threat_intelligence: Dict[str, Any] = Field(..., description="Threat intelligence data")
    business_context: Dict[str, Any] = Field(..., description="Business context information")
    historical_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Historical data for context"
    )
    tenant_id: str = Field(..., description="Tenant identifier")


class RiskScore(BaseModel):
    """Individual risk score component"""
    category: str = Field(..., description="Risk category")
    score: float = Field(..., description="Risk score (0-1)")
    confidence: float = Field(..., description="Confidence in score (0-1)")
    contributing_factors: List[str] = Field(..., description="Contributing risk factors")
    mitigation_suggestions: List[str] = Field(..., description="Risk mitigation suggestions")


class RiskAssessmentResult(BaseModel):
    """Comprehensive risk assessment result"""
    assessment_id: str = Field(..., description="Unique assessment identifier")
    overall_risk_score: float = Field(..., description="Overall risk score (0-1)")
    risk_level: str = Field(..., description="Risk level classification")
    risk_scores: List[RiskScore] = Field(..., description="Individual risk scores")
    risk_tolerance: str = Field(..., description="Risk tolerance assessment")
    recommended_actions: List[str] = Field(..., description="Recommended risk actions")
    monitoring_requirements: List[str] = Field(..., description="Risk monitoring requirements")
    escalation_thresholds: Dict[str, float] = Field(..., description="Risk escalation thresholds")
    business_impact_forecast: Dict[str, Any] = Field(..., description="Business impact forecast")
    timestamp: datetime = Field(..., description="Assessment timestamp")


class ServiceHealth(BaseModel):
    """Decision engine service health"""
    status: str = Field(..., description="Service health status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    models_loaded: int = Field(..., description="Number of models loaded")
    active_decisions: int = Field(..., description="Number of active decisions")
    playbook_queue_size: int = Field(..., description="Playbook execution queue size")
    decision_latency_ms: float = Field(..., description="Average decision latency")
    success_rate: float = Field(..., description="Decision success rate")
    last_error: Optional[str] = Field(None, description="Last error message")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")


class ModelPerformanceMetrics(BaseModel):
    """Model performance metrics"""
    model_name: str = Field(..., description="Model name")
    model_version: str = Field(..., description="Model version")
    accuracy: float = Field(..., description="Model accuracy")
    precision: float = Field(..., description="Model precision")
    recall: float = Field(..., description="Model recall")
    f1_score: float = Field(..., description="Model F1 score")
    decisions_made: int = Field(..., description="Total decisions made")
    successful_decisions: int = Field(..., description="Successful decisions")
    override_rate: float = Field(..., description="Human override rate")
    avg_confidence: float = Field(..., description="Average confidence score")
    last_updated: datetime = Field(..., description="Last metrics update")


class DecisionAuditLog(BaseModel):
    """Decision audit log entry"""
    log_id: str = Field(..., description="Log entry identifier")
    decision_id: str = Field(..., description="Related decision identifier")
    timestamp: datetime = Field(..., description="Log timestamp")
    action: str = Field(..., description="Action performed")
    actor: str = Field(..., description="Entity performing action")
    details: Dict[str, Any] = Field(..., description="Action details")
    outcome: str = Field(..., description="Action outcome")
    impact_assessment: Optional[str] = Field(None, description="Impact assessment")


# --- Alert triage models ---

class TriageAlert(BaseModel):
    """Incoming alert/event payload for triage."""
    alert_id: str = Field(..., description="Unique alert identifier")
    tenant_id: str = Field(..., description="Tenant identifier")
    source: str = Field(..., description="Source system (siem/ids/edr/app)")
    event_type: str = Field(..., description="Event type/category")
    severity_hint: Optional[str] = Field(None, description="Upstream severity hint (low/medium/high/critical)")
    message: Optional[str] = Field(None, description="Human-readable message")
    indicators: Dict[str, Any] = Field(default_factory=dict, description="IOC/telemetry fields")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context metadata")

class TriageRequest(BaseModel):
    """Request to triage one or more alerts."""
    alerts: List[TriageAlert] = Field(..., description="Alerts to triage")
    auto_actions_allowed: bool = Field(True, description="Permit auto-remediation if confidence high")

class TriageDecision(BaseModel):
    """Per-alert triage decision result."""
    alert_id: str = Field(...)
    priority: str = Field(..., description="routing priority: p1..p4")
    routed_to: str = Field(..., description="queue/destination (soar, analyst_l1, analyst_l2)")
    recommended_actions: List[str] = Field(default_factory=list)
    confidence: float = Field(..., ge=0.0, le=1.0)
    risk_score: float = Field(..., ge=0.0, le=1.0)
    auto_remediate: bool = Field(False)

class TriageResult(BaseModel):
    """Response for alert triage."""
    triage_id: str = Field(...)
    decisions: List[TriageDecision] = Field(...)
    processed_count: int = Field(...)
    timestamp: datetime = Field(default_factory=datetime.utcnow)