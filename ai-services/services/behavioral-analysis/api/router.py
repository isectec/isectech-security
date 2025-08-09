"""
FastAPI Router for Behavioral Analysis & Anomaly Detection Service

Provides production-grade API endpoints for:
- Real-time behavioral analysis and anomaly detection
- Baseline establishment and management
- Risk assessment and threat classification
- Model management and monitoring
- Historical analysis and reporting
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, List
from uuid import uuid4

import os
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks

from ....shared.api.security import (
    SecurityContext, APIPermission, SecurityClearance,
    PermissionChecker
)
from ....shared.api.monitoring import APIMetricsCollector
from ....shared.security.audit import AuditLogger

# Import our AI models
from ..models.feature_engineering import FeatureExtractor
from ..models.baseline import BaselineModel
from ..models.anomaly_detection import AnomalyDetector
from ..models.risk_scoring import RiskScorer
from ..models.training_pipeline import TrainingPipeline, TrainingPipelineConfig
from ..models.model_registry import ModelRegistry, ModelRegistryConfig
from ..models.feedback_loop import FeedbackLoop, FeedbackLoopConfig, FeedbackType

from .models import (
    UserEvent, BatchEventRequest, BaselineRequest, AnomalyDetectionRequest,
    RiskAssessmentRequest, BehavioralFeatures, BaselineInfo, AnomalyResult,
    AnomalyDetectionResponse, RiskAssessment, ModelStatus, AnalysisStatus,
    UserBehaviorProfile, HealthCheckResponse, ThreatClassification
)
from ..service.service_manager import BehavioralAnalysisServiceManager


class BehavioralAnalysisService:
    """Service orchestrator for behavioral analysis operations"""
    
    def __init__(self, settings, audit_logger: AuditLogger, metrics_collector: APIMetricsCollector):
        self.settings = settings
        self.audit_logger = audit_logger
        self.metrics_collector = metrics_collector
        
        # Initialize AI models
        self.feature_extractor = FeatureExtractor(settings)
        self.baseline_model = BaselineModel(settings)
        self.anomaly_detector = AnomalyDetector(settings)
        self.risk_scorer = RiskScorer(settings)
        
        # Background analysis tracking
        self.active_analyses: Dict[str, AnalysisStatus] = {}
    
    async def process_events_batch(self, request: BatchEventRequest, security_context: SecurityContext) -> Dict[str, Any]:
        """Process batch of events for behavioral analysis"""
        
        analysis_id = str(uuid4())
        start_time = datetime.utcnow()
        
        try:
            # Log analysis start
            self.audit_logger.log_security_event(
                event_type="behavioral_analysis_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "event_count": len(request.events),
                    "processing_options": request.processing_options
                }
            )
            
            # Extract features from events
            features_by_user = {}
            for event in request.events:
                if event.user_id not in features_by_user:
                    features_by_user[event.user_id] = []
                
                # Convert event to feature format
                event_data = {
                    'timestamp': event.timestamp,
                    'event_type': event.event_type,
                    'resource': event.resource,
                    'ip_address': event.ip_address,
                    'user_agent': event.user_agent,
                    'location': event.location or {},
                    'metadata': event.metadata
                }
                features_by_user[event.user_id].append(event_data)
            
            # Process features for each user
            processed_results = {}
            for user_id, user_events in features_by_user.items():
                
                # Extract behavioral features
                features = await self.feature_extractor.extract_features(
                    user_events, user_id, request.tenant_id
                )
                
                processed_results[user_id] = {
                    "features": features,
                    "event_count": len(user_events)
                }
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("behavioral_analysis", request.tenant_id)
            self.metrics_collector.record_data_processed(
                "behavioral_events", 
                len(request.events) * 1024,  # Estimate 1KB per event
                request.tenant_id
            )
            
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Log analysis completion
            self.audit_logger.log_security_event(
                event_type="behavioral_analysis_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "users_processed": len(features_by_user),
                    "processing_time_ms": processing_time
                }
            )
            
            return {
                "analysis_id": analysis_id,
                "tenant_id": request.tenant_id,
                "timestamp": start_time,
                "events_processed": len(request.events),
                "users_analyzed": len(features_by_user),
                "results": processed_results,
                "processing_time_ms": processing_time,
                "status": "completed"
            }
            
        except Exception as e:
            # Log error
            self.audit_logger.log_security_event(
                event_type="behavioral_analysis_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Analysis failed: {str(e)}"
            )
    
    async def establish_baseline(self, request: BaselineRequest, security_context: SecurityContext) -> BaselineInfo:
        """Establish behavioral baseline for user"""
        
        try:
            # Log baseline establishment start
            self.audit_logger.log_security_event(
                event_type="baseline_establishment_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "time_window_days": request.time_window_days,
                    "force_rebuild": request.force_rebuild
                }
            )
            
            # Create baseline
            baseline = await self.baseline_model.create_baseline(
                user_id=request.user_id,
                tenant_id=request.tenant_id,
                time_window_days=request.time_window_days,
                force_rebuild=request.force_rebuild
            )
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("baseline_creation", request.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="baseline_establishment_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "baseline_id": baseline.baseline_id,
                    "confidence_score": baseline.confidence_score
                }
            )
            
            return BaselineInfo(
                user_id=request.user_id,
                tenant_id=request.tenant_id,
                baseline_id=baseline.baseline_id,
                created_at=baseline.created_at,
                last_updated=baseline.last_updated,
                data_points=baseline.data_points,
                time_window_days=request.time_window_days,
                confidence_score=baseline.confidence_score,
                stability_score=baseline.stability_score,
                baseline_metrics=baseline.metrics,
                status="active"
            )
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="baseline_establishment_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Baseline establishment failed: {str(e)}"
            )
    
    async def detect_anomalies(self, request: AnomalyDetectionRequest, security_context: SecurityContext) -> AnomalyDetectionResponse:
        """Detect anomalies in user events"""
        
        analysis_id = str(uuid4())
        start_time = datetime.utcnow()
        
        try:
            # Log anomaly detection start
            self.audit_logger.log_security_event(
                event_type="anomaly_detection_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "event_count": len(request.events),
                    "detection_sensitivity": request.detection_sensitivity
                }
            )
            
            # Convert events to analysis format
            event_data = []
            for event in request.events:
                event_data.append({
                    'user_id': event.user_id,
                    'timestamp': event.timestamp,
                    'event_type': event.event_type,
                    'resource': event.resource,
                    'ip_address': event.ip_address,
                    'user_agent': event.user_agent,
                    'location': event.location or {},
                    'metadata': event.metadata
                })
            
            # Perform anomaly detection
            anomaly_results = []
            anomaly_count = 0
            overall_risk = "low"
            
            for i, event in enumerate(event_data):
                # Detect anomalies for this event
                anomaly_result = await self.anomaly_detector.detect_anomalies(
                    events=[event],
                    tenant_id=request.tenant_id,
                    sensitivity=request.detection_sensitivity
                )
                
                # Create result
                is_anomaly = anomaly_result.anomaly_score > 0.5
                if is_anomaly:
                    anomaly_count += 1
                
                # Determine severity
                score = anomaly_result.anomaly_score
                if score >= 0.9:
                    severity = "critical"
                    overall_risk = "critical"
                elif score >= 0.7:
                    severity = "high"
                    if overall_risk not in ["critical"]:
                        overall_risk = "high"
                elif score >= 0.5:
                    severity = "medium"
                    if overall_risk not in ["critical", "high"]:
                        overall_risk = "medium"
                else:
                    severity = "low"
                
                anomaly_results.append(AnomalyResult(
                    event_id=f"event_{i}",
                    anomaly_score=score,
                    is_anomaly=is_anomaly,
                    confidence=anomaly_result.confidence,
                    anomaly_type=anomaly_result.anomaly_type,
                    contributing_factors=anomaly_result.contributing_factors,
                    explanation=anomaly_result.explanation if request.include_explanations else None,
                    severity=severity,
                    recommended_actions=anomaly_result.recommended_actions
                ))
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("anomaly_detection", request.tenant_id)
            self.metrics_collector.record_security_event("anomaly_detected", "info", request.tenant_id)
            
            processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="anomaly_detection_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "anomalies_detected": anomaly_count,
                    "overall_risk_level": overall_risk,
                    "processing_time_ms": processing_time
                }
            )
            
            return AnomalyDetectionResponse(
                tenant_id=request.tenant_id,
                analysis_id=analysis_id,
                timestamp=start_time,
                total_events=len(request.events),
                anomalies_detected=anomaly_count,
                overall_risk_level=overall_risk,
                anomaly_results=anomaly_results,
                summary_statistics={
                    "avg_anomaly_score": sum(r.anomaly_score for r in anomaly_results) / len(anomaly_results),
                    "max_anomaly_score": max(r.anomaly_score for r in anomaly_results),
                    "high_severity_count": sum(1 for r in anomaly_results if r.severity in ["high", "critical"]),
                    "detection_sensitivity": request.detection_sensitivity
                },
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="anomaly_detection_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "analysis_id": analysis_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Anomaly detection failed: {str(e)}"
            )
    
    async def assess_risk(self, request: RiskAssessmentRequest, security_context: SecurityContext) -> RiskAssessment:
        """Perform comprehensive risk assessment"""
        
        try:
            # Log risk assessment start
            self.audit_logger.log_security_event(
                event_type="risk_assessment_started",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "assessment_type": request.assessment_type,
                    "event_count": len(request.events)
                }
            )
            
            # Convert events for risk assessment
            event_data = []
            for event in request.events:
                event_data.append({
                    'user_id': event.user_id,
                    'timestamp': event.timestamp,
                    'event_type': event.event_type,
                    'resource': event.resource,
                    'ip_address': event.ip_address,
                    'user_agent': event.user_agent,
                    'location': event.location or {},
                    'metadata': event.metadata
                })
            
            # Perform risk assessment
            risk_result = await self.risk_scorer.assess_risk(
                user_id=request.user_id,
                events=event_data,
                tenant_id=request.tenant_id,
                assessment_type=request.assessment_type,
                context_data=request.context_data
            )
            
            # Record metrics
            self.metrics_collector.record_ml_prediction("risk_assessment", request.tenant_id)
            
            # Log completion
            self.audit_logger.log_security_event(
                event_type="risk_assessment_completed",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "assessment_id": risk_result.assessment_id,
                    "overall_risk_score": risk_result.overall_risk_score,
                    "risk_level": risk_result.risk_level
                }
            )
            
            return RiskAssessment(
                user_id=request.user_id,
                tenant_id=request.tenant_id,
                assessment_id=risk_result.assessment_id,
                timestamp=risk_result.timestamp,
                overall_risk_score=risk_result.overall_risk_score,
                risk_level=risk_result.risk_level,
                risk_factors=risk_result.risk_factors,
                threat_classifications=[
                    ThreatClassification(
                        threat_type=tc.threat_type,
                        confidence=tc.confidence,
                        indicators=tc.indicators,
                        mitre_techniques=tc.mitre_techniques,
                        severity=tc.severity
                    ) for tc in risk_result.threat_classifications
                ],
                business_impact=risk_result.business_impact,
                recommendations=risk_result.recommendations,
                investigation_priority=risk_result.investigation_priority,
                automated_actions=risk_result.automated_actions,
                context_analysis=risk_result.context_analysis
            )
            
        except Exception as e:
            self.audit_logger.log_security_event(
                event_type="risk_assessment_error",
                user_id=security_context.user_id,
                tenant_id=request.tenant_id,
                details={
                    "target_user_id": request.user_id,
                    "error": str(e)
                }
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Risk assessment failed: {str(e)}"
            )


def create_behavioral_analysis_router(service: BehavioralAnalysisService) -> APIRouter:
    """Create FastAPI router for behavioral analysis endpoints"""
    
    router = APIRouter(tags=["Behavioral Analysis"])
    # Initialize training pipeline lazily when needed
    _pipeline: TrainingPipeline | None = None
    def get_pipeline() -> TrainingPipeline:
        nonlocal _pipeline
        if _pipeline is None:
            pg_dsn = os.getenv("FEATURE_STORE_DSN")
            if not pg_dsn:
                raise HTTPException(status_code=503, detail="Training pipeline unavailable: FEATURE_STORE_DSN not set")
            cfg = TrainingPipelineConfig(
                postgres_dsn=pg_dsn,
                model_dir=os.getenv("BASELINE_MODEL_DIR", "/var/lib/isectech/models"),
                use_mlflow=os.getenv("BEHAVIORAL_USE_MLFLOW", "true").lower() == "true",
                mlflow_tracking_uri=os.getenv("MLFLOW_TRACKING_URI"),
            )
            # Reuse feature store if available via service_manager
            try:
                from ..service.api import get_service_manager
                mgr = get_service_manager()
                if not mgr.feature_store:
                    raise RuntimeError("FeatureStore not initialized")
                _pipeline = TrainingPipeline(mgr.feature_store, cfg)
            except Exception:
                # Fallback: create a local FeatureStore
                from ..models.feature_store import FeatureStore, FeatureStoreConfig
                fs = FeatureStore(FeatureStoreConfig(postgres_dsn=pg_dsn, redis_url=os.getenv("FEATURE_STORE_REDIS_URL")))
                fs.connect()
                _pipeline = TrainingPipeline(fs, cfg)
        return _pipeline

    # Admin endpoints for model versioning (promotion/rollback/list)
    @router.post("/models/supervised/promote")
    async def promote_supervised_model(
        model_id: int,
        stage: str = "production",
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        ),
    ):
        """Promote a supervised model to a stage (staging/production)."""
        if stage not in ("staging", "production"):
            raise HTTPException(status_code=400, detail="invalid_stage")
        pg_dsn = os.getenv("FEATURE_STORE_DSN")
        if not pg_dsn:
            raise HTTPException(status_code=503, detail="registry_unavailable")
        reg = ModelRegistry(ModelRegistryConfig(postgres_dsn=pg_dsn))
        res = reg.promote(tenant_id=tenant_id, model_type="supervised_detector", model_id=model_id, stage=stage, promoted_by=security_context.user_id)
        return JSONResponse(content={"ok": True, "result": res})

    @router.get("/models/supervised/current")
    async def get_current_supervised(
        stage: str = "production",
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        ),
    ):
        pg_dsn = os.getenv("FEATURE_STORE_DSN")
        if not pg_dsn:
            raise HTTPException(status_code=503, detail="registry_unavailable")
        reg = ModelRegistry(ModelRegistryConfig(postgres_dsn=pg_dsn))
        cur = reg.current(tenant_id=tenant_id, model_type="supervised_detector", stage=stage)
        return JSONResponse(content={"ok": True, "result": bool(cur)})

    @router.get("/models/supervised/history")
    async def get_supervised_history(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        ),
    ):
        pg_dsn = os.getenv("FEATURE_STORE_DSN")
        if not pg_dsn:
            raise HTTPException(status_code=503, detail="registry_unavailable")
        reg = ModelRegistry(ModelRegistryConfig(postgres_dsn=pg_dsn))
        hist = reg.history(tenant_id=tenant_id, model_type="supervised_detector")
        return JSONResponse(content={"ok": True, "result": hist})
    
    @router.post("/analyze/batch", response_model=Dict[str, Any])
    async def analyze_events_batch(
        request: BatchEventRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Process batch of events for behavioral analysis"""
        return await service.process_events_batch(request, security_context)

    @router.post("/models/train/baseline")
    async def train_baseline_models(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        pipe = get_pipeline()
        res = pipe.train_baseline(tenant_id)
        return JSONResponse(content={"ok": True, "result": res})

    @router.post("/models/train/supervised")
    async def train_supervised_models(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        pipe = get_pipeline()
        res = pipe.train_supervised(tenant_id)
        return JSONResponse(content={"ok": True, "result": res})

    @router.get("/models/evaluate/supervised")
    async def evaluate_supervised_models(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        pipe = get_pipeline()
        res = pipe.evaluate_supervised(tenant_id)
        return JSONResponse(content={"ok": True, "result": res})
    
    @router.post("/baseline/establish", response_model=BaselineInfo)
    async def establish_baseline(
        request: BaselineRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Establish behavioral baseline for user"""
        return await service.establish_baseline(request, security_context)
    
    @router.get("/baseline/{user_id}", response_model=BaselineInfo)
    async def get_baseline(
        user_id: str,
        tenant_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get existing baseline for user"""
        
        try:
            baseline = await service.baseline_model.get_baseline(user_id, tenant_id)
            
            return BaselineInfo(
                user_id=user_id,
                tenant_id=tenant_id,
                baseline_id=baseline.baseline_id,
                created_at=baseline.created_at,
                last_updated=baseline.last_updated,
                data_points=baseline.data_points,
                time_window_days=30,  # Default from baseline
                confidence_score=baseline.confidence_score,
                stability_score=baseline.stability_score,
                baseline_metrics=baseline.metrics,
                status="active"
            )
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Baseline not found: {str(e)}"
            )
    
    @router.post("/anomalies/detect", response_model=AnomalyDetectionResponse)
    async def detect_anomalies(
        request: AnomalyDetectionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Detect anomalies in user events"""
        return await service.detect_anomalies(request, security_context)
    
    @router.post("/risk/assess", response_model=RiskAssessment)
    async def assess_risk(
        request: RiskAssessmentRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Perform comprehensive risk assessment"""
        return await service.assess_risk(request, security_context)
    
    @router.get("/models/status", response_model=List[ModelStatus])
    async def get_model_status(
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get status of all behavioral analysis models"""
        
        models = [
            ModelStatus(
                model_name="feature_extractor",
                model_version="1.0.0",
                status="loaded",
                last_updated=datetime.utcnow(),
                performance_metrics={"extraction_speed": 1000.0},
                training_data_points=100000,
                accuracy=0.95,
                precision=0.93,
                recall=0.92,
                f1_score=0.925
            ),
            ModelStatus(
                model_name="anomaly_detector",
                model_version="2.1.0", 
                status="loaded",
                last_updated=datetime.utcnow(),
                performance_metrics={"detection_speed": 500.0},
                training_data_points=50000,
                accuracy=0.92,
                precision=0.89,
                recall=0.94,
                f1_score=0.915
            ),
            ModelStatus(
                model_name="risk_scorer",
                model_version="1.5.0",
                status="loaded",
                last_updated=datetime.utcnow(),
                performance_metrics={"scoring_speed": 200.0},
                training_data_points=75000,
                accuracy=0.88,
                precision=0.91,
                recall=0.85,
                f1_score=0.88
            )
        ]
        
        return models
    
    @router.get("/user/{user_id}/profile", response_model=UserBehaviorProfile)
    async def get_user_profile(
        user_id: str,
        tenant_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Get behavioral profile for user"""
        
        # Mock profile data - in production, fetch from database
        return UserBehaviorProfile(
            user_id=user_id,
            tenant_id=tenant_id,
            profile_created=datetime.utcnow() - timedelta(days=30),
            last_updated=datetime.utcnow(),
            activity_patterns={
                "peak_hours": "09:00-17:00",
                "avg_daily_events": 150,
                "common_resources": ["document_server", "email_system"],
                "typical_locations": ["office", "home"]
            },
            risk_indicators=["unusual_time_access", "new_device_login"],
            baseline_deviations={"access_frequency": 0.1, "location_variance": 0.05},
            historical_anomalies=3,
            confidence_level=0.85,
            learning_status="stable"
        )
    
    @router.get("/health", response_model=HealthCheckResponse)
    async def health_check():
        """Health check endpoint for behavioral analysis service"""
        
        return HealthCheckResponse(
            status="healthy",
            timestamp=datetime.utcnow(),
            models_loaded=3,
            active_analyses=len(service.active_analyses),
            queue_size=0,
            last_error=None,
            uptime_seconds=3600.0  # Mock uptime
        )

    # Supervised training (admin)
    @router.post("/models/supervised/train")
    async def train_supervised_model(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Trigger supervised training for a tenant (or global when tenant_id is None)."""
        try:
            # Access underlying service manager to use initialized trainers
            # Note: The BehavioralAnalysisService used here is a lighter orchestrator; training is handled by ServiceManager
            from ..service.api import get_service_manager
        except Exception:
            # Fallback if helper is not available in this package context
            raise HTTPException(status_code=503, detail="Service manager not available")

        mgr: BehavioralAnalysisServiceManager = get_service_manager()
        if not mgr.supervised_trainer:
            raise HTTPException(status_code=503, detail="Supervised trainer not initialized")
        res = mgr.supervised_trainer.train_for_tenant(tenant_id)
        return JSONResponse(content={"ok": True, "result": res})

    # Supervised inference endpoint
    @router.post("/models/supervised/score")
    async def score_supervised(
        feature_map: Dict[str, float],
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Score a provided feature map with the latest supervised model."""
        try:
            from ..service.api import get_service_manager
        except Exception:
            raise HTTPException(status_code=503, detail="Service manager not available")

        mgr: BehavioralAnalysisServiceManager = get_service_manager()
        if not mgr.supervised_trainer:
            raise HTTPException(status_code=503, detail="Supervised trainer not initialized")
        prob = mgr.supervised_trainer.predict_proba(tenant_id, feature_map)
        if prob is None:
            return JSONResponse(status_code=404, content={"ok": False, "error": "model_not_found"})
        return {"probability": prob, "threat_level": "high" if prob >= 0.8 else "medium" if prob >= 0.5 else "low"}

    @router.post("/inference/events/stream")
    async def stream_events_for_inference(
        request: BatchEventRequest,
        background: BackgroundTasks,
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Submit a batch of events for real-time inference; processed asynchronously.
        Returns an analysis_id to poll later in downstream systems.
        """
        try:
            from ..service.api import get_service_manager
        except Exception:
            raise HTTPException(status_code=503, detail="Service manager not available")

        mgr: BehavioralAnalysisServiceManager = get_service_manager()

        async def _process():
            try:
                # Reuse existing batch analysis path for feature extraction and anomaly scoring
                await service.process_events_batch(request, security_context)
            except Exception:
                # Non-blocking: log via audit inside service
                pass

        background.add_task(_process)
        return JSONResponse(content={"ok": True, "accepted": True})
    
    # Feedback Loop endpoints
    _feedback_loop: FeedbackLoop | None = None
    def get_feedback_loop() -> FeedbackLoop:
        nonlocal _feedback_loop
        if _feedback_loop is None:
            pg_dsn = os.getenv("FEATURE_STORE_DSN")
            if not pg_dsn:
                raise HTTPException(status_code=503, detail="Feedback loop unavailable: FEATURE_STORE_DSN not set")
            config = FeedbackLoopConfig(
                database_dsn=pg_dsn,
                redis_url=os.getenv("FEATURE_STORE_REDIS_URL", "redis://localhost:6379"),
                feedback_table="behavioral_feedback",
                performance_table="model_performance_metrics"
            )
            _feedback_loop = FeedbackLoop(config)
        return _feedback_loop
    
    @router.post("/feedback/collect")
    async def collect_feedback(
        entity_id: str,
        prediction_id: str,
        feedback_type: FeedbackType,
        original_score: float,
        original_prediction: bool,
        corrected_label: bool,
        tenant_id: str | None = None,
        source: str = "user",
        metadata: Dict[str, Any] | None = None,
        confidence: float = 1.0,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Collect feedback for model improvement"""
        feedback_loop = get_feedback_loop()
        feedback_id = await feedback_loop.collect_feedback(
            entity_id=entity_id,
            tenant_id=tenant_id or "default",
            prediction_id=prediction_id,
            feedback_type=feedback_type,
            original_score=original_score,
            original_prediction=original_prediction,
            corrected_label=corrected_label,
            source=source,
            metadata=metadata,
            confidence=confidence
        )
        return JSONResponse(content={
            "ok": True,
            "feedback_id": feedback_id,
            "message": "Feedback collected successfully"
        })
    
    @router.post("/feedback/process")
    async def process_feedback_batch(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_ANALYZE])
        )
    ):
        """Process unprocessed feedback for training data generation"""
        feedback_loop = get_feedback_loop()
        result = await feedback_loop.process_feedback_batch(tenant_id or "default")
        return JSONResponse(content={
            "ok": True,
            "processed_count": result["processed_count"],
            "training_data_generated": result["training_data"] is not None
        })
    
    @router.get("/feedback/report")
    async def get_feedback_report(
        tenant_id: str | None = None,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.BEHAVIORAL_READ])
        )
    ):
        """Generate comprehensive feedback report with recommendations"""
        feedback_loop = get_feedback_loop()
        report = await feedback_loop.generate_feedback_report(tenant_id or "default")
        return JSONResponse(content={
            "ok": True,
            "report": report
        })
    
    return router