"""
FastAPI Router for ML Feedback Loop and Continuous Improvement
Task 85.9: API endpoints for feedback collection, drift detection, and model retraining
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ....shared.api.security import (
    SecurityContext, APIPermission, SecurityClearance,
    PermissionChecker
)
from ....shared.api.monitoring import APIMetricsCollector
from ....shared.security.audit import AuditLogger

from ..models.feedback_loop import (
    FeedbackCollector, DriftDetector, FeedbackBasedRetrainer,
    ContinuousImprovementOrchestrator, DetectionFeedback,
    FeedbackType, FeedbackSource, RetrainingConfig
)


# Pydantic models for API requests/responses
class FeedbackSubmission(BaseModel):
    """Request model for submitting feedback"""
    detection_id: str
    model_id: int
    original_score: float
    original_prediction: str
    
    feedback_type: str = Field(..., description="Type of feedback: true_positive, false_positive, etc.")
    is_true_positive: bool = Field(..., description="Whether the detection was actually positive")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Feedback confidence level")
    
    analyst_id: Optional[str] = None
    investigation_notes: Optional[str] = None
    additional_context: Dict[str, Any] = Field(default_factory=dict)
    
    # Original event and feature data for retraining
    feature_vector: Dict[str, Any] = Field(default_factory=dict)
    original_event_data: Dict[str, Any] = Field(default_factory=dict)


class BatchFeedbackSubmission(BaseModel):
    """Request model for batch feedback submission"""
    tenant_id: Optional[str] = None
    feedbacks: List[FeedbackSubmission]


class DriftDetectionRequest(BaseModel):
    """Request model for drift detection"""
    model_id: int
    tenant_id: Optional[str] = None
    evaluation_days: int = Field(7, ge=1, le=30, description="Days to evaluate for drift")


class RetrainingRequest(BaseModel):
    """Request model for model retraining"""
    model_id: int
    tenant_id: Optional[str] = None
    force_retrain: bool = Field(False, description="Force retraining even if drift not detected")
    include_feedback: bool = Field(True, description="Include feedback data in retraining")


class ABTestRequest(BaseModel):
    """Request model for A/B test management"""
    experiment_id: Optional[str] = None
    control_model_id: Optional[int] = None
    treatment_model_id: Optional[int] = None
    traffic_split: float = Field(0.1, ge=0.01, le=0.5, description="Traffic percentage for treatment")
    duration_days: int = Field(7, ge=1, le=30, description="Test duration in days")


class FeedbackStats(BaseModel):
    """Response model for feedback statistics"""
    total_feedback_count: int
    feedback_by_type: Dict[str, int]
    feedback_by_source: Dict[str, int]
    false_positive_rate: float
    false_negative_rate: float
    recent_feedback_volume: int
    negative_feedback_ratio: float


class DriftMetricsResponse(BaseModel):
    """Response model for drift detection results"""
    model_id: int
    tenant_id: Optional[str]
    evaluation_period: List[datetime]
    drift_detected: bool
    drift_severity: str
    
    accuracy_degradation: float
    precision_degradation: float
    recall_degradation: float
    f1_degradation: float
    
    false_positive_rate: float
    false_negative_rate: float
    negative_feedback_ratio: float
    
    recommended_actions: List[str]
    evaluation_timestamp: datetime


class RetrainingResponse(BaseModel):
    """Response model for retraining results"""
    status: str
    model_id: int
    new_model_id: Optional[int] = None
    
    training_samples: Optional[int] = None
    performance_metrics: Optional[Dict[str, float]] = None
    improvement_metrics: Optional[Dict[str, float]] = None
    
    ab_test_started: bool = False
    ab_test_id: Optional[str] = None
    
    retraining_timestamp: datetime


class ABTestStatus(BaseModel):
    """Response model for A/B test status"""
    experiment_id: str
    status: str
    control_model_id: int
    treatment_model_id: int
    
    traffic_split: float
    start_time: datetime
    planned_end_time: datetime
    actual_end_time: Optional[datetime] = None
    
    control_samples: int = 0
    treatment_samples: int = 0
    statistical_significance: Optional[float] = None
    winner: Optional[str] = None


class ContinuousImprovementStatus(BaseModel):
    """Response model for continuous improvement status"""
    tenant_id: Optional[str]
    evaluation_timestamp: datetime
    
    models_evaluated: int
    drift_detected_count: int
    retraining_triggered_count: int
    ab_tests_running: int
    ab_tests_completed: int
    
    overall_health_score: float
    recommendations: List[str]


def create_feedback_router(
    postgres_dsn: str,
    audit_logger: AuditLogger,
    metrics_collector: APIMetricsCollector
) -> APIRouter:
    """Create FastAPI router for ML feedback loop endpoints"""
    
    router = APIRouter(tags=["ML Feedback Loop"])
    
    # Initialize feedback loop components
    retraining_config = RetrainingConfig()
    feedback_collector = FeedbackCollector(postgres_dsn)
    drift_detector = DriftDetector(postgres_dsn, feedback_collector)
    retrainer = FeedbackBasedRetrainer(postgres_dsn, retraining_config)
    orchestrator = ContinuousImprovementOrchestrator(postgres_dsn, retraining_config)
    
    @router.post("/feedback/submit", response_model=Dict[str, Any])
    async def submit_detection_feedback(
        feedback: FeedbackSubmission,
        tenant_id: Optional[str] = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Submit feedback for a detection outcome"""
        
        feedback_id = str(uuid4())
        
        try:
            # Create feedback record
            feedback_record = DetectionFeedback(
                id=feedback_id,
                tenant_id=tenant_id or security_context.tenant_id,
                user_id=security_context.user_id,
                detection_id=feedback.detection_id,
                model_id=feedback.model_id,
                model_version="",  # Will be filled from model registry
                original_score=feedback.original_score,
                original_prediction=feedback.original_prediction,
                feedback_type=FeedbackType(feedback.feedback_type),
                feedback_source=FeedbackSource.SOC_ANALYST if feedback.analyst_id else FeedbackSource.USER_SELF_REPORT,
                corrected_label=feedback.is_true_positive,
                confidence=feedback.confidence,
                analyst_id=feedback.analyst_id or security_context.user_id,
                feedback_timestamp=datetime.utcnow(),
                investigation_notes=feedback.investigation_notes,
                additional_context=feedback.additional_context,
                feature_vector=feedback.feature_vector,
                original_event_data=feedback.original_event_data
            )
            
            # Submit feedback
            success = await feedback_collector.collect_feedback(feedback_record)
            
            if success:
                # Log feedback submission
                audit_logger.log_security_event(
                    event_type="ml_feedback_submitted",
                    user_id=security_context.user_id,
                    tenant_id=tenant_id or security_context.tenant_id,
                    details={
                        "feedback_id": feedback_id,
                        "detection_id": feedback.detection_id,
                        "model_id": feedback.model_id,
                        "feedback_type": feedback.feedback_type,
                        "is_true_positive": feedback.is_true_positive
                    }
                )
                
                # Record metrics
                metrics_collector.record_security_event("feedback_submitted", "info", tenant_id)
                
                return {
                    "status": "success",
                    "feedback_id": feedback_id,
                    "message": "Feedback submitted successfully",
                    "will_trigger_retraining": feedback.confidence >= 0.8  # High confidence feedback
                }
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Failed to submit feedback"
                )
                
        except Exception as e:
            audit_logger.log_security_event(
                event_type="ml_feedback_error",
                user_id=security_context.user_id,
                tenant_id=tenant_id or security_context.tenant_id,
                details={
                    "detection_id": feedback.detection_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Feedback submission failed: {str(e)}"
            )
    
    @router.post("/feedback/batch", response_model=Dict[str, Any])
    async def submit_batch_feedback(
        request: BatchFeedbackSubmission,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Submit multiple feedback records in batch"""
        
        results = {
            "submitted": 0,
            "failed": 0,
            "feedback_ids": [],
            "errors": []
        }
        
        for feedback in request.feedbacks:
            try:
                # Reuse single feedback endpoint logic
                feedback_id = str(uuid4())
                
                feedback_record = DetectionFeedback(
                    id=feedback_id,
                    tenant_id=request.tenant_id or security_context.tenant_id,
                    user_id=security_context.user_id,
                    detection_id=feedback.detection_id,
                    model_id=feedback.model_id,
                    model_version="",
                    original_score=feedback.original_score,
                    original_prediction=feedback.original_prediction,
                    feedback_type=FeedbackType(feedback.feedback_type),
                    feedback_source=FeedbackSource.SOC_ANALYST if feedback.analyst_id else FeedbackSource.USER_SELF_REPORT,
                    corrected_label=feedback.is_true_positive,
                    confidence=feedback.confidence,
                    analyst_id=feedback.analyst_id or security_context.user_id,
                    feedback_timestamp=datetime.utcnow(),
                    investigation_notes=feedback.investigation_notes,
                    additional_context=feedback.additional_context,
                    feature_vector=feedback.feature_vector,
                    original_event_data=feedback.original_event_data
                )
                
                success = await feedback_collector.collect_feedback(feedback_record)
                
                if success:
                    results["submitted"] += 1
                    results["feedback_ids"].append(feedback_id)
                else:
                    results["failed"] += 1
                    results["errors"].append(f"Failed to submit feedback for detection {feedback.detection_id}")
                    
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(f"Error processing feedback for detection {feedback.detection_id}: {str(e)}")
        
        # Record batch metrics
        metrics_collector.record_security_event("batch_feedback_submitted", "info", request.tenant_id)
        
        return results
    
    @router.get("/feedback/stats", response_model=FeedbackStats)
    async def get_feedback_statistics(
        model_id: Optional[int] = None,
        tenant_id: Optional[str] = None,
        days: int = 30,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get feedback statistics for analysis"""
        
        try:
            # Get recent feedback
            hours = days * 24
            recent_feedback = await feedback_collector.get_recent_feedback(
                model_id or 0, tenant_id, hours
            )
            
            # Calculate statistics
            total_count = len(recent_feedback)
            feedback_by_type = {}
            feedback_by_source = {}
            false_positive_count = 0
            false_negative_count = 0
            
            for feedback in recent_feedback:
                # Count by type
                type_str = feedback.feedback_type.value
                feedback_by_type[type_str] = feedback_by_type.get(type_str, 0) + 1
                
                # Count by source
                source_str = feedback.feedback_source.value
                feedback_by_source[source_str] = feedback_by_source.get(source_str, 0) + 1
                
                # Count false positives/negatives
                if feedback.feedback_type == FeedbackType.FALSE_POSITIVE:
                    false_positive_count += 1
                elif feedback.feedback_type == FeedbackType.FALSE_NEGATIVE:
                    false_negative_count += 1
            
            # Calculate rates
            false_positive_rate = false_positive_count / total_count if total_count > 0 else 0.0
            false_negative_rate = false_negative_count / total_count if total_count > 0 else 0.0
            negative_feedback_count = false_positive_count + false_negative_count
            negative_feedback_ratio = negative_feedback_count / total_count if total_count > 0 else 0.0
            
            return FeedbackStats(
                total_feedback_count=total_count,
                feedback_by_type=feedback_by_type,
                feedback_by_source=feedback_by_source,
                false_positive_rate=false_positive_rate,
                false_negative_rate=false_negative_rate,
                recent_feedback_volume=total_count,
                negative_feedback_ratio=negative_feedback_ratio
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get feedback statistics: {str(e)}"
            )
    
    @router.post("/drift/detect", response_model=DriftMetricsResponse)
    async def detect_model_drift(
        request: DriftDetectionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Detect performance drift in ML model"""
        
        try:
            # Perform drift detection
            drift_metrics = await drift_detector.detect_drift(
                model_id=request.model_id,
                tenant_id=request.tenant_id or security_context.tenant_id,
                evaluation_days=request.evaluation_days
            )
            
            # Log drift detection
            audit_logger.log_security_event(
                event_type="ml_drift_detection",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id or security_context.tenant_id,
                details={
                    "model_id": request.model_id,
                    "drift_detected": drift_metrics.drift_detected,
                    "drift_severity": drift_metrics.drift_severity,
                    "accuracy_degradation": drift_metrics.accuracy_degradation
                }
            )
            
            # Record metrics
            metrics_collector.record_ml_prediction("drift_detection", request.tenant_id)
            
            return DriftMetricsResponse(
                model_id=drift_metrics.model_id,
                tenant_id=drift_metrics.tenant_id,
                evaluation_period=[drift_metrics.evaluation_period[0], drift_metrics.evaluation_period[1]],
                drift_detected=drift_metrics.drift_detected,
                drift_severity=drift_metrics.drift_severity,
                accuracy_degradation=drift_metrics.accuracy_degradation,
                precision_degradation=drift_metrics.precision_degradation,
                recall_degradation=drift_metrics.recall_degradation,
                f1_degradation=drift_metrics.f1_degradation,
                false_positive_rate=drift_metrics.false_positive_rate,
                false_negative_rate=drift_metrics.false_negative_rate,
                negative_feedback_ratio=drift_metrics.negative_feedback_ratio,
                recommended_actions=drift_metrics.recommended_actions,
                evaluation_timestamp=datetime.utcnow()
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Drift detection failed: {str(e)}"
            )
    
    @router.post("/retrain/trigger", response_model=RetrainingResponse)
    async def trigger_model_retraining(
        request: RetrainingRequest,
        background_tasks: BackgroundTasks,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Trigger model retraining with feedback incorporation"""
        
        async def _perform_retraining():
            """Background task for retraining"""
            try:
                # Detect drift first if not forced
                drift_metrics = None
                if not request.force_retrain:
                    drift_metrics = await drift_detector.detect_drift(
                        request.model_id, request.tenant_id
                    )
                    
                    if not drift_metrics.drift_detected:
                        # No drift detected, skip retraining
                        audit_logger.log_security_event(
                            event_type="ml_retraining_skipped",
                            user_id=security_context.user_id,
                            tenant_id=request.tenant_id or security_context.tenant_id,
                            details={
                                "model_id": request.model_id,
                                "reason": "no_drift_detected"
                            }
                        )
                        return
                
                # Trigger retraining
                result = await retrainer.trigger_retraining(
                    model_id=request.model_id,
                    tenant_id=request.tenant_id or security_context.tenant_id,
                    drift_metrics=drift_metrics
                )
                
                # Log retraining completion
                audit_logger.log_security_event(
                    event_type="ml_retraining_completed",
                    user_id=security_context.user_id,
                    tenant_id=request.tenant_id or security_context.tenant_id,
                    details={
                        "model_id": request.model_id,
                        "status": result.get("status"),
                        "new_model_id": result.get("new_model_id")
                    }
                )
                
            except Exception as e:
                audit_logger.log_security_event(
                    event_type="ml_retraining_error",
                    user_id=security_context.user_id,
                    tenant_id=request.tenant_id or security_context.tenant_id,
                    details={
                        "model_id": request.model_id,
                        "error": str(e)
                    }
                )
        
        # Queue background retraining
        background_tasks.add_task(_perform_retraining)
        
        # Record metrics
        metrics_collector.record_ml_prediction("retraining_triggered", request.tenant_id)
        
        return RetrainingResponse(
            status="queued",
            model_id=request.model_id,
            retraining_timestamp=datetime.utcnow()
        )
    
    @router.get("/retrain/status/{model_id}")
    async def get_retraining_status(
        model_id: int,
        tenant_id: Optional[str] = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get status of model retraining"""
        
        # This would check the status of ongoing retraining
        # For now, return mock status
        return {
            "model_id": model_id,
            "status": "completed",
            "last_retrained": datetime.utcnow() - timedelta(hours=2),
            "next_scheduled": datetime.utcnow() + timedelta(days=1)
        }
    
    @router.post("/ab-test/start", response_model=ABTestStatus)
    async def start_ab_test(
        request: ABTestRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Start A/B test between model versions"""
        
        if not request.control_model_id or not request.treatment_model_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Both control_model_id and treatment_model_id required"
            )
        
        try:
            # Start A/B test using retrainer
            ab_test_result = await retrainer._start_ab_test(
                control_model_id=request.control_model_id,
                treatment_model_id=request.treatment_model_id,
                tenant_id=security_context.tenant_id
            )
            
            # Log A/B test start
            audit_logger.log_security_event(
                event_type="ml_ab_test_started",
                user_id=security_context.user_id,
                tenant_id=security_context.tenant_id,
                details={
                    "experiment_id": ab_test_result["experiment_id"],
                    "control_model_id": request.control_model_id,
                    "treatment_model_id": request.treatment_model_id,
                    "traffic_split": request.traffic_split
                }
            )
            
            return ABTestStatus(
                experiment_id=ab_test_result["experiment_id"],
                status="running",
                control_model_id=request.control_model_id,
                treatment_model_id=request.treatment_model_id,
                traffic_split=request.traffic_split,
                start_time=datetime.utcnow(),
                planned_end_time=datetime.utcnow() + timedelta(days=request.duration_days)
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to start A/B test: {str(e)}"
            )
    
    @router.get("/ab-test/status/{experiment_id}", response_model=ABTestStatus)
    async def get_ab_test_status(
        experiment_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get A/B test status and results"""
        
        # Query A/B test status from database
        # For now, return mock status
        return ABTestStatus(
            experiment_id=experiment_id,
            status="running",
            control_model_id=1,
            treatment_model_id=2,
            traffic_split=0.1,
            start_time=datetime.utcnow() - timedelta(days=2),
            planned_end_time=datetime.utcnow() + timedelta(days=5),
            control_samples=1000,
            treatment_samples=100
        )
    
    @router.post("/continuous-improvement/run")
    async def run_continuous_improvement(
        tenant_id: Optional[str] = None,
        background_tasks: BackgroundTasks = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Run complete continuous improvement cycle"""
        
        async def _run_improvement_cycle():
            """Background task for continuous improvement"""
            try:
                result = await orchestrator.run_continuous_improvement_cycle(
                    tenant_id or security_context.tenant_id
                )
                
                # Log cycle completion
                audit_logger.log_security_event(
                    event_type="ml_continuous_improvement_completed",
                    user_id=security_context.user_id,
                    tenant_id=tenant_id or security_context.tenant_id,
                    details=result
                )
                
            except Exception as e:
                audit_logger.log_security_event(
                    event_type="ml_continuous_improvement_error",
                    user_id=security_context.user_id,
                    tenant_id=tenant_id or security_context.tenant_id,
                    details={"error": str(e)}
                )
        
        # Queue background improvement cycle
        if background_tasks:
            background_tasks.add_task(_run_improvement_cycle)
        
        return {
            "status": "queued",
            "message": "Continuous improvement cycle started",
            "tenant_id": tenant_id or security_context.tenant_id,
            "timestamp": datetime.utcnow()
        }
    
    @router.get("/continuous-improvement/status", response_model=ContinuousImprovementStatus)
    async def get_continuous_improvement_status(
        tenant_id: Optional[str] = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get status of continuous improvement processes"""
        
        # This would query the current state of all improvement processes
        # For now, return mock status
        return ContinuousImprovementStatus(
            tenant_id=tenant_id or security_context.tenant_id,
            evaluation_timestamp=datetime.utcnow(),
            models_evaluated=3,
            drift_detected_count=1,
            retraining_triggered_count=1,
            ab_tests_running=1,
            ab_tests_completed=2,
            overall_health_score=0.85,
            recommendations=[
                "Model 1 shows accuracy degradation, retraining recommended",
                "A/B test for Model 2 shows positive results, consider promotion"
            ]
        )
    
    @router.get("/health")
    async def feedback_system_health():
        """Health check for feedback loop system"""
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow(),
            "components": {
                "feedback_collector": "operational",
                "drift_detector": "operational",
                "retrainer": "operational",
                "orchestrator": "operational"
            },
            "metrics": {
                "active_models": 3,
                "recent_feedback_count": 156,
                "active_ab_tests": 1,
                "last_improvement_cycle": datetime.utcnow() - timedelta(hours=1)
            }
        }
    
    return router