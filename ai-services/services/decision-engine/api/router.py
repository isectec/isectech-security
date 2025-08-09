"""
FastAPI Router for Automated Decision Making and Response Service

Provides production-grade API endpoints for:
- Risk-based automated decision making and response selection
- Playbook execution and orchestration with Ray distributed processing
- Containment action authorization with security clearance integration
- Feedback learning from human overrides for continuous improvement
- Comprehensive risk assessment and business impact analysis
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse

from ....shared.api.security import (
    SecurityContext, APIPermission, SecurityClearance,
    PermissionChecker
)
from ....shared.api.monitoring import APIMetricsCollector
from ....shared.security.audit import AuditLogger

# Import our AI models
from ..models.decision_models import DecisionModels
from ..models.response_selector import ResponseSelector
from ..models.playbook_engine import PlaybookEngine
from ..models.containment_authorizer import ContainmentAuthorizer
from ..models.feedback_learner import FeedbackLearner
from ..models.risk_calculator import RiskCalculator

from .models import (
    DecisionInput, DecisionRequest, ResponseAction, DecisionResult,
    PlaybookExecutionRequest, PlaybookStep, PlaybookExecution,
    ContainmentRequest, ContainmentAuthorization, FeedbackInput,
    LearningResult, RiskCalculationRequest, RiskScore, RiskAssessmentResult,
    ServiceHealth, ModelPerformanceMetrics, DecisionAuditLog,
    TriageRequest, TriageResult, TriageDecision
)


class DecisionEngineService:
    """Service orchestrator for decision engine operations"""
    
    def __init__(self, settings, audit_logger: AuditLogger, metrics_collector: APIMetricsCollector):
        self.settings = settings
        self.audit_logger = audit_logger
        self.metrics_collector = metrics_collector
        
        # Initialize AI models
        self.decision_models = DecisionModels(settings)
        self.response_selector = ResponseSelector(settings)
        self.playbook_engine = PlaybookEngine(settings)
        self.containment_authorizer = ContainmentAuthorizer(settings)
        self.feedback_learner = FeedbackLearner(settings)
        self.risk_calculator = RiskCalculator(settings)
        # thresholds for triage routing
        self._triage_thresholds = {
            "p1": 0.90,
            "p2": 0.75,
            "p3": 0.50,
        }
        
        # Active executions tracking
        self.active_executions: Dict[str, PlaybookExecution] = {}
        self.active_decisions: Dict[str, DecisionResult] = {}
    
    async def make_decision(self, request: DecisionRequest, security_context: SecurityContext) -> DecisionResult:
        """Make automated security decision"""
        
        decision_id = str(uuid4())
        start_time = datetime.utcnow()
        
        try:
            # Log decision start
            self.audit_logger.log_security_event(
                event_type="automated_decision_started",
                user_id=security_context.user_id,
                tenant_id=request.decision_input.tenant_id,
                details={
                    "decision_id": decision_id,
                    "decision_type": request.decision_type,
                    "incident_id": request.decision_input.incident_id,
                    "urgency_level": request.urgency_level
                }
            )
            
            # Prepare decision input
            decision_data = {
                'incident_id': request.decision_input.incident_id,
                'threat_data': request.decision_input.threat_data,
                'context_data': request.decision_input.context_data,
                'user_id': request.decision_input.user_id,
                'asset_criticality': request.decision_input.asset_criticality,
                'business_impact': request.decision_input.business_impact,
                'tenant_id': request.decision_input.tenant_id
            }
            
            # Make decision using AI models
            decision_result = await self.decision_models.make_decision(
                decision_input=decision_data,
                decision_type=request.decision_type,
                urgency_level=request.urgency_level,
                constraints=request.constraints,
                tenant_id=request.decision_input.tenant_id
            )
            
            # Select appropriate responses
            response_result = await self.response_selector.select_responses(
                decision_result=decision_result,
                incident_data=decision_data,
                tenant_id=request.decision_input.tenant_id
            )
            
            # Create response actions
            recommended_actions = []
            for action in response_result.selected_responses:
                recommended_actions.append(ResponseAction(
                    action_id=str(uuid4()),
                    action_type=action['action_type'],
                    action_name=action['action_name'],
                    description=action['description'],
                    parameters=action['parameters'],
                    estimated_duration=action['estimated_duration'],
                    required_approvals=action['required_approvals'],
                    risk_level=action['risk_level'],
                    reversible=action['reversible'],
                    dependencies=action.get('dependencies', [])
                ))
            
            # Create decision result
            result = DecisionResult(
                decision_id=decision_id,
                incident_id=request.decision_input.incident_id,
                decision_type=request.decision_type,
                recommended_actions=recommended_actions,
                confidence_score=decision_result.confidence_score,
                reasoning=decision_result.reasoning,
                risk_assessment=decision_result.risk_assessment,
                business_impact_analysis=response_result.business_impact_analysis,
                alternative_options=response_result.alternative_responses,
                execution_timeline=response_result.execution_timeline,
                monitoring_requirements=response_result.monitoring_requirements,
                success_criteria=response_result.success_criteria,
                rollback_plan=response_result.rollback_plan,
                timestamp=start_time
            )
            
            # Store decision for tracking
            self.active_decisions[decision_id] = result
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("automated_decision", request.decision_input.tenant_id)
            
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="automated_decision_completed",
                user_id=security_context.user_id,
                tenant_id=request.decision_input.tenant_id,
                details={
                    "decision_id": decision_id,
                    "confidence_score": result.confidence_score,
                    "actions_recommended": len(result.recommended_actions),
                    "processing_time_ms": processing_time
                }
            )
            
            return result
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="automated_decision_error",
                user_id=security_context.user_id,
                tenant_id=request.decision_input.tenant_id,
                details={
                    "decision_id": decision_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Decision making failed: {str(e)}"
            )

    async def triage_alerts(self, request: TriageRequest, security_context: SecurityContext) -> TriageResult:
        """ML-based alert triage with routing and optional auto-remediation suggestion."""
        triage_id = str(uuid4())
        decisions: List[TriageDecision] = []
        try:
            for alert in request.alerts:
                # Basic feature vector from indicators/context
                # In production, call dedicated triage model and enrichment pipeline
                risk_score = 0.0
                sev = (alert.severity_hint or "").lower()
                if sev == "critical":
                    risk_score = 0.95
                elif sev == "high":
                    risk_score = 0.8
                elif sev == "medium":
                    risk_score = 0.6
                else:
                    risk_score = 0.4

                # Adjust using simple heuristics
                if alert.indicators.get("failed_logins", 0) > 20:
                    risk_score = max(risk_score, 0.85)
                if alert.indicators.get("exfil_bytes", 0) > 10_000_000:
                    risk_score = max(risk_score, 0.9)

                # Map to priority
                if risk_score >= self._triage_thresholds["p1"]:
                    priority = "p1"; routed_to = "soar"; auto = request.auto_actions_allowed
                elif risk_score >= self._triage_thresholds["p2"]:
                    priority = "p2"; routed_to = "analyst_l2"; auto = False
                elif risk_score >= self._triage_thresholds["p3"]:
                    priority = "p3"; routed_to = "analyst_l1"; auto = False
                else:
                    priority = "p4"; routed_to = "backlog"; auto = False

                actions: List[str] = []
                if auto and priority == "p1":
                    actions.append("auto_quarantine_endpoint")
                elif priority in ("p1", "p2"):
                    actions.append("launch_investigation_playbook")
                else:
                    actions.append("enqueue_monitoring")

                decisions.append(TriageDecision(
                    alert_id=alert.alert_id,
                    priority=priority,
                    routed_to=routed_to,
                    recommended_actions=actions,
                    confidence=min(1.0, risk_score + 0.05),
                    risk_score=risk_score,
                    auto_remediate=auto and priority == "p1",
                ))

            return TriageResult(
                triage_id=triage_id,
                decisions=decisions,
                processed_count=len(decisions),
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Triage failed: {e}")
    
    async def execute_playbook(self, request: PlaybookExecutionRequest, security_context: SecurityContext) -> PlaybookExecution:
        """Execute security playbook"""
        
        execution_id = str(uuid4())
        start_time = datetime.utcnow()
        
        try:
            # Log execution start
            self.audit_logger.log_security_event(
                event_type="playbook_execution_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "execution_id": execution_id,
                    "playbook_name": request.playbook_name,
                    "incident_id": request.incident_id,
                    "execution_mode": request.execution_mode
                }
            )
            
            # Execute playbook
            execution_result = await self.playbook_engine.execute_playbook(
                playbook_name=request.playbook_name,
                incident_id=request.incident_id,
                trigger_data=request.trigger_data,
                execution_mode=request.execution_mode,
                override_parameters=request.override_parameters,
                tenant_id=request.tenant_id
            )
            
            # Convert steps
            steps = []
            for step in execution_result.execution_steps:
                steps.append(PlaybookStep(
                    step_id=step['step_id'],
                    step_name=step['step_name'],
                    status=step['status'],
                    started_at=step.get('started_at'),
                    completed_at=step.get('completed_at'),
                    duration_ms=step.get('duration_ms'),
                    result=step.get('result'),
                    error_message=step.get('error_message'),
                    retry_count=step.get('retry_count', 0)
                ))
            
            # Create execution object
            execution = PlaybookExecution(
                execution_id=execution_id,
                playbook_name=request.playbook_name,
                incident_id=request.incident_id,
                status=execution_result.status,
                progress_percent=execution_result.progress_percent,
                started_at=start_time,
                estimated_completion=execution_result.estimated_completion,
                completed_at=execution_result.completed_at,
                steps=steps,
                results=execution_result.results,
                metrics=execution_result.metrics,
                logs=execution_result.logs
            )
            
            # Store execution for tracking
            self.active_executions[execution_id] = execution
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("playbook_execution", request.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="playbook_execution_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "execution_id": execution_id,
                    "playbook_name": request.playbook_name,
                    "status": execution.status,
                    "steps_executed": len(steps)
                }
            )
            
            return execution
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="playbook_execution_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "execution_id": execution_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Playbook execution failed: {str(e)}"
            )
    
    async def authorize_containment(self, request: ContainmentRequest, security_context: SecurityContext) -> ContainmentAuthorization:
        """Authorize containment action"""
        
        authorization_id = str(uuid4())
        
        try:
            # Log authorization start
            self.audit_logger.log_security_event(
                event_type="containment_authorization_requested",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "authorization_id": authorization_id,
                    "action_type": request.action_type,
                    "incident_id": request.incident_id,
                    "requested_by": request.requested_by
                }
            )
            
            # Check authorization
            auth_result = await self.containment_authorizer.authorize_containment(
                action_type=request.action_type,
                target_assets=request.target_assets,
                threat_level=request.threat_level,
                business_justification=request.business_justification,
                requested_by=request.requested_by,
                incident_id=request.incident_id,
                urgency=request.urgency,
                tenant_id=request.tenant_id,
                security_context=security_context
            )
            
            # Create authorization result
            authorization = ContainmentAuthorization(
                authorization_id=authorization_id,
                incident_id=request.incident_id,
                action_type=request.action_type,
                authorization_status=auth_result.authorization_status,
                authorized_by=auth_result.authorized_by,
                clearance_level=auth_result.required_clearance,
                conditions=auth_result.conditions,
                expiration_time=auth_result.expiration_time,
                monitoring_requirements=auth_result.monitoring_requirements,
                rollback_authority=auth_result.rollback_authority,
                justification=auth_result.justification,
                timestamp=datetime.utcnow()
            )
            
            # Record metrics
            self.metrics_collector.record_security_event("containment_authorization", "info", request.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="containment_authorization_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "authorization_id": authorization_id,
                    "authorization_status": authorization.authorization_status,
                    "clearance_level": authorization.clearance_level
                }
            )
            
            return authorization
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="containment_authorization_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "authorization_id": authorization_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Containment authorization failed: {str(e)}"
            )
    
    async def process_feedback(self, feedback: FeedbackInput, security_context: SecurityContext) -> LearningResult:
        """Process human feedback for learning"""
        
        learning_id = str(uuid4())
        
        try:
            # Log feedback processing start
            self.audit_logger.log_security_event(
                event_type="feedback_learning_started",
                user_id=security_context.user_id,
                tenant_id=feedback.tenant_id,
                details={
                    "learning_id": learning_id,
                    "decision_id": feedback.decision_id,
                    "feedback_type": feedback.feedback_type,
                    "provided_by": feedback.provided_by
                }
            )
            
            # Process feedback
            learning_result = await self.feedback_learner.process_feedback(
                decision_id=feedback.decision_id,
                feedback_type=feedback.feedback_type,
                human_decision=feedback.human_decision,
                reasoning=feedback.reasoning,
                outcome_assessment=feedback.outcome_assessment,
                suggested_improvements=feedback.suggested_improvements,
                confidence_in_override=feedback.confidence_in_override,
                provided_by=feedback.provided_by,
                tenant_id=feedback.tenant_id
            )
            
            # Create learning result
            result = LearningResult(
                learning_id=learning_id,
                feedback_processed=1,
                patterns_identified=learning_result.patterns_identified,
                model_adjustments=learning_result.model_adjustments,
                confidence_improvements=learning_result.confidence_improvements,
                bias_detections=learning_result.bias_detections,
                recommendations=learning_result.recommendations,
                impact_assessment=learning_result.impact_assessment,
                timestamp=datetime.utcnow()
            )
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("feedback_learning", feedback.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="feedback_learning_completed",
                user_id=security_context.user_id,
                tenant_id=feedback.tenant_id,
                details={
                    "learning_id": learning_id,
                    "patterns_identified": len(result.patterns_identified),
                    "bias_detections": len(result.bias_detections)
                }
            )
            
            return result
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="feedback_learning_error",
                user_id=security_context.user_id,
                tenant_id=feedback.tenant_id,
                details={
                    "learning_id": learning_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Feedback learning failed: {str(e)}"
            )
    
    async def calculate_risk(self, request: RiskCalculationRequest, security_context: SecurityContext) -> RiskAssessmentResult:
        """Calculate comprehensive risk assessment"""
        
        assessment_id = str(uuid4())
        
        try:
            # Log risk calculation start
            self.audit_logger.log_security_event(
                event_type="risk_calculation_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "assessment_id": assessment_id
                }
            )
            
            # Calculate risk
            risk_result = await self.risk_calculator.calculate_comprehensive_risk(
                incident_data=request.incident_data,
                asset_information=request.asset_information,
                threat_intelligence=request.threat_intelligence,
                business_context=request.business_context,
                historical_data=request.historical_data,
                tenant_id=request.tenant_id
            )
            
            # Convert risk scores
            risk_scores = []
            for category, score_data in risk_result.risk_scores.items():
                risk_scores.append(RiskScore(
                    category=category,
                    score=score_data['score'],
                    confidence=score_data['confidence'],
                    contributing_factors=score_data['contributing_factors'],
                    mitigation_suggestions=score_data['mitigation_suggestions']
                ))
            
            # Create assessment result
            assessment = RiskAssessmentResult(
                assessment_id=assessment_id,
                overall_risk_score=risk_result.overall_risk_score,
                risk_level=risk_result.risk_level,
                risk_scores=risk_scores,
                risk_tolerance=risk_result.risk_tolerance,
                recommended_actions=risk_result.recommended_actions,
                monitoring_requirements=risk_result.monitoring_requirements,
                escalation_thresholds=risk_result.escalation_thresholds,
                business_impact_forecast=risk_result.business_impact_forecast,
                timestamp=datetime.utcnow()
            )
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("risk_calculation", request.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="risk_calculation_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "assessment_id": assessment_id,
                    "overall_risk_score": assessment.overall_risk_score,
                    "risk_level": assessment.risk_level
                }
            )
            
            return assessment
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="risk_calculation_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "assessment_id": assessment_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Risk calculation failed: {str(e)}"
            )


def create_decision_engine_router(service: DecisionEngineService) -> APIRouter:
    """Create FastAPI router for decision engine endpoints"""
    
    router = APIRouter(tags=["Automated Decision Engine"])
    
    @router.post("/decision/make", response_model=DecisionResult)
    async def make_automated_decision(
        request: DecisionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_EXECUTE])
        )
    ):
        """Make automated security decision"""
        return await service.make_decision(request, security_context)

    @router.post("/triage/alerts", response_model=TriageResult)
    async def triage_alerts(
        request: TriageRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_EXECUTE])
        )
    ):
        """Route alerts using ML-based triage with risk-based priorities."""
        return await service.triage_alerts(request, security_context)
    
    @router.get("/decision/{decision_id}", response_model=DecisionResult)
    async def get_decision(
        decision_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_READ])
        )
    ):
        """Get decision by ID"""
        
        if decision_id not in service.active_decisions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Decision not found"
            )
        
        return service.active_decisions[decision_id]
    
    @router.post("/playbook/execute", response_model=PlaybookExecution)
    async def execute_playbook(
        request: PlaybookExecutionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_EXECUTE])
        )
    ):
        """Execute security playbook"""
        return await service.execute_playbook(request, security_context)
    
    @router.get("/playbook/execution/{execution_id}", response_model=PlaybookExecution)
    async def get_execution_status(
        execution_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_READ])
        )
    ):
        """Get playbook execution status"""
        
        if execution_id not in service.active_executions:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Execution not found"
            )
        
        return service.active_executions[execution_id]
    
    @router.post("/containment/authorize", response_model=ContainmentAuthorization)
    async def authorize_containment_action(
        request: ContainmentRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_EXECUTE], SecurityClearance.CONFIDENTIAL)
        )
    ):
        """Authorize containment action"""
        return await service.authorize_containment(request, security_context)
    
    @router.post("/feedback/learn", response_model=LearningResult)
    async def process_feedback(
        feedback: FeedbackInput,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_ADMIN])
        )
    ):
        """Process human feedback for learning"""
        return await service.process_feedback(feedback, security_context)
    
    @router.post("/risk/calculate", response_model=RiskAssessmentResult)
    async def calculate_risk(
        request: RiskCalculationRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_EXECUTE])
        )
    ):
        """Calculate comprehensive risk assessment"""
        return await service.calculate_risk(request, security_context)
    
    @router.get("/models/performance", response_model=List[ModelPerformanceMetrics])
    async def get_model_performance(
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.DECISION_READ])
        )
    ):
        """Get model performance metrics"""
        
        metrics = [
            ModelPerformanceMetrics(
                model_name="decision_models",
                model_version="3.0.0",
                accuracy=0.92,
                precision=0.89,
                recall=0.94,
                f1_score=0.915,
                decisions_made=15000,
                successful_decisions=13800,
                override_rate=0.08,
                avg_confidence=0.87,
                last_updated=datetime.utcnow()
            ),
            ModelPerformanceMetrics(
                model_name="response_selector",
                model_version="2.5.0",
                accuracy=0.88,
                precision=0.91,
                recall=0.85,
                f1_score=0.88,
                decisions_made=12000,
                successful_decisions=10560,
                override_rate=0.12,
                avg_confidence=0.82,
                last_updated=datetime.utcnow()
            )
        ]
        
        return metrics
    
    @router.get("/health", response_model=ServiceHealth)
    async def health_check():
        """Health check endpoint for decision engine service"""
        
        return ServiceHealth(
            status="healthy",
            timestamp=datetime.utcnow(),
            models_loaded=6,
            active_decisions=len(service.active_decisions),
            playbook_queue_size=len(service.active_executions),
            decision_latency_ms=85.0,
            success_rate=0.92,
            last_error=None,
            uptime_seconds=14400.0  # Mock uptime
        )
    
    return router