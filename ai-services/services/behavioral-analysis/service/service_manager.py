"""
Service manager for behavioral analysis operations.

This module provides the main service orchestration and business logic
for the behavioral analysis and anomaly detection system.
"""

import asyncio
import pickle
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import structlog

from ....shared.config.settings import Settings
from ....shared.security.audit import get_audit_logger, AuditEventType, AuditSeverity
from ..config import BehavioralAnalysisConfig, get_behavioral_config
from ..models.feature_engineering import FeatureExtractor, BehavioralFeatures
from ..models.baseline import BaselineModel, BehavioralBaseline
from ..models.anomaly_detection import AnomalyDetector, AnomalyResult
from ..models.risk_scoring import RiskScorer, ThreatRiskAssessment
from ..models.feature_store import FeatureStore, FeatureStoreConfig
from ..models.baseline_trainer import BaselineTrainer, BaselineTrainerConfig
from ..models.supervised_trainer import SupervisedTrainer, SupervisedTrainerConfig
import os
from .models import (
    SecurityEventRequest, AnalysisRequest, AnomalyResponse, 
    ThreatAssessmentResponse, ComprehensiveAnalysisResponse,
    BaselineStatusResponse, ModelStatusResponse
)


class EventBuffer:
    """Buffer for real-time event processing."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_size))
        self.lock = asyncio.Lock()
    
    async def add_event(self, entity_id: str, event: SecurityEventRequest):
        """Add event to buffer."""
        async with self.lock:
            self.events[entity_id].append(event)
    
    async def get_events(self, entity_id: str, 
                        time_window: timedelta = None) -> List[SecurityEventRequest]:
        """Get events for entity within time window."""
        async with self.lock:
            events = list(self.events.get(entity_id, []))
            
            if time_window:
                cutoff_time = datetime.utcnow() - time_window
                events = [e for e in events if e.timestamp >= cutoff_time]
            
            return events
    
    async def get_entity_count(self) -> int:
        """Get number of entities in buffer."""
        async with self.lock:
            return len(self.events)
    
    async def cleanup_old_events(self, max_age: timedelta = timedelta(hours=24)):
        """Remove old events from buffer."""
        cutoff_time = datetime.utcnow() - max_age
        
        async with self.lock:
            for entity_id in list(self.events.keys()):
                events = self.events[entity_id]
                # Keep only recent events
                recent_events = deque(
                    [e for e in events if e.timestamp >= cutoff_time],
                    maxlen=self.max_size
                )
                
                if recent_events:
                    self.events[entity_id] = recent_events
                else:
                    del self.events[entity_id]


class ModelManager:
    """Manager for ML models and their lifecycle."""
    
    def __init__(self, config: BehavioralAnalysisConfig):
        self.config = config
        self.feature_extractor = FeatureExtractor()
        self.baseline_model = BaselineModel(self.feature_extractor)
        self.anomaly_detector = AnomalyDetector(self.baseline_model)
        self.risk_scorer = RiskScorer()
        
        # Model versioning and tracking
        self.model_versions = {
            "feature_extractor": "1.0.0",
            "baseline_model": "1.0.0",
            "anomaly_detector": "1.0.0",
            "risk_scorer": "1.0.0"
        }
        
        # Performance tracking
        self.performance_metrics = {
            "total_analyses": 0,
            "total_anomalies": 0,
            "avg_processing_time_ms": 0.0,
            "baseline_coverage": 0.0
        }
        
        self.logger = structlog.get_logger("model_manager")
    
    async def extract_features(self, events: List[SecurityEventRequest],
                             entity_id: str, entity_type: str,
                             time_window: timedelta) -> BehavioralFeatures:
        """Extract behavioral features from events."""
        # Convert events to DataFrame
        event_data = []
        for event in events:
            event_dict = {
                'timestamp': event.timestamp,
                'event_type': event.event_type,
                'resource': event.resource,
                'action': event.action,
                'source_ip': event.source_ip,
                'user_agent': event.user_agent,
                'success': event.success,
                'data_size': event.data_size,
                'location': event.location,
                'application': event.application,
                'security_classification': event.security_classification.value
            }
            event_data.append(event_dict)
        
        events_df = pd.DataFrame(event_data)
        
        # Extract features
        features = self.feature_extractor.extract_features(
            events_df, entity_id, entity_type, time_window
        )
        
        return features
    
    async def detect_anomalies(self, entity_id: str, 
                             features: BehavioralFeatures) -> AnomalyResult:
        """Detect anomalies in behavioral features."""
        result = self.anomaly_detector.detect_anomalies(entity_id, features)
        
        # Update performance metrics
        self.performance_metrics["total_analyses"] += 1
        if result.is_anomaly:
            self.performance_metrics["total_anomalies"] += 1
        
        return result
    
    async def assess_risk(self, entity_id: str, entity_type: str,
                        features: BehavioralFeatures,
                        anomaly_result: AnomalyResult) -> ThreatRiskAssessment:
        """Assess threat risk for entity."""
        baseline = self.baseline_model.get_baseline(entity_id)
        
        assessment = self.risk_scorer.assess_risk(
            entity_id, entity_type, features, anomaly_result, baseline
        )
        
        return assessment
    
    async def create_baseline(self, entity_id: str, entity_type: str,
                            historical_features: List[BehavioralFeatures]) -> BehavioralBaseline:
        """Create behavioral baseline for entity."""
        try:
            baseline = self.baseline_model.create_baseline(
                entity_id, entity_type, historical_features
            )
            
            self.logger.info(
                "Baseline created",
                entity_id=entity_id,
                entity_type=entity_type,
                sample_count=baseline.sample_count,
                confidence=baseline.confidence_score
            )
            
            return baseline
        
        except Exception as e:
            self.logger.error(
                "Baseline creation failed",
                entity_id=entity_id,
                entity_type=entity_type,
                error=str(e)
            )
            raise
    
    async def update_baseline(self, entity_id: str, 
                            features: BehavioralFeatures) -> bool:
        """Update baseline with new features."""
        return self.baseline_model.update_baseline(entity_id, features)
    
    async def get_baseline_status(self, entity_id: str) -> Optional[BehavioralBaseline]:
        """Get baseline status for entity."""
        return self.baseline_model.get_baseline(entity_id)
    
    async def train_ensemble_models(self, training_data: Dict[str, List[BehavioralFeatures]]):
        """Train ensemble anomaly detection models."""
        self.logger.info("Starting ensemble training", entities=len(training_data))
        
        try:
            self.anomaly_detector.train_ensemble(training_data)
            self.logger.info("Ensemble training completed successfully")
        except Exception as e:
            self.logger.error("Ensemble training failed", error=str(e))
            raise
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all models."""
        baseline_summary = self.baseline_model.get_baseline_summary()
        anomaly_stats = self.anomaly_detector.get_detection_statistics()
        
        return {
            "model_versions": self.model_versions,
            "baseline_summary": baseline_summary,
            "anomaly_detector_status": anomaly_stats,
            "performance_metrics": self.performance_metrics,
            "last_training_time": self.anomaly_detector.last_training_time.isoformat() 
                if self.anomaly_detector.last_training_time else None,
            "ensemble_trained": self.anomaly_detector.ensemble.is_trained
        }


class BehavioralAnalysisServiceManager:
    """Main service manager for behavioral analysis operations."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.config = get_behavioral_config()
        self.logger = structlog.get_logger("service_manager")
        self.audit_logger = get_audit_logger("behavioral-analysis")
        
        # Core components
        self.model_manager = ModelManager(self.config)
        self.event_buffer = EventBuffer(max_size=self.config.max_queue_size)
        self.feature_store: Optional[FeatureStore] = None
        self.baseline_trainer: Optional[BaselineTrainer] = None
        self.supervised_trainer: Optional[SupervisedTrainer] = None
        
        # Service state
        self.is_initialized = False
        self.start_time = datetime.utcnow()
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        self.should_stop = False
        
        # Processing statistics
        self.processing_stats = {
            "requests_processed_24h": 0,
            "anomalies_detected_24h": 0,
            "errors_24h": 0,
            "avg_response_time_ms": 0.0
        }
    
    async def initialize(self):
        """Initialize the service manager."""
        self.logger.info("Initializing behavioral analysis service")
        
        try:
            # Initialize model manager
            await self._initialize_models()

            # Initialize feature store if configured
            pg_dsn = os.getenv("FEATURE_STORE_DSN")
            redis_url = os.getenv("FEATURE_STORE_REDIS_URL")
            if pg_dsn:
                fs_cfg = FeatureStoreConfig(postgres_dsn=pg_dsn, redis_url=redis_url, cache_ttl_seconds=900)
                self.feature_store = FeatureStore(fs_cfg)
                self.feature_store.connect()
                self.logger.info("Feature store initialized", postgres_dsn="configured", redis=bool(redis_url))
            else:
                self.logger.warn("Feature store not configured (FEATURE_STORE_DSN missing) - skipping persistence")
            
            # Initialize baseline trainer if feature store configured
            if pg_dsn and self.feature_store:
                model_dir = os.getenv("BASELINE_MODEL_DIR", "/var/lib/isectech/models")
                contamination = float(os.getenv("BASELINE_IF_CONTAMINATION", "0.03"))
                min_samples = int(os.getenv("BASELINE_MIN_SAMPLES", "200"))
                window_hours = int(os.getenv("BASELINE_TRAIN_WINDOW_HOURS", str(24 * 14)))
                bt_cfg = BaselineTrainerConfig(
                    postgres_dsn=pg_dsn,
                    model_dir=model_dir,
                    contamination=contamination,
                    min_samples=min_samples,
                    train_window_hours=window_hours,
                )
                self.baseline_trainer = BaselineTrainer(self.feature_store, bt_cfg)
                self.logger.info("Baseline trainer initialized", model_dir=model_dir)

                # Initialize supervised trainer
                st_cfg = SupervisedTrainerConfig(
                    postgres_dsn=pg_dsn,
                    model_dir=os.getenv("SUPERVISED_MODEL_DIR", model_dir),
                    min_samples=int(os.getenv("SUPERVISED_MIN_SAMPLES", "500")),
                    train_window_hours=int(os.getenv("SUPERVISED_TRAIN_WINDOW_HOURS", str(24 * 30))),
                    test_size=float(os.getenv("SUPERVISED_TEST_SIZE", "0.2")),
                )
                self.supervised_trainer = SupervisedTrainer(self.feature_store, st_cfg)
                self.logger.info("Supervised trainer initialized", model_dir=st_cfg.model_dir)

            # Start background tasks
            await self._start_background_tasks()
            
            self.is_initialized = True
            self.logger.info("Service initialization completed successfully")
        
        except Exception as e:
            self.logger.error("Service initialization failed", error=str(e))
            raise
    
    async def shutdown(self):
        """Shutdown the service manager."""
        self.logger.info("Shutting down behavioral analysis service")
        
        self.should_stop = True
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        self.logger.info("Service shutdown completed")
    
    async def analyze_behavior(self, request: AnalysisRequest) -> ComprehensiveAnalysisResponse:
        """Perform comprehensive behavioral analysis."""
        start_time = time.time()
        
        try:
            self.logger.info(
                "Starting behavioral analysis",
                entity_id=request.entity_id,
                entity_type=request.entity_type,
                event_count=len(request.events)
            )
            
            # Extract features
            time_window = timedelta(hours=request.time_window_hours)
            features = await self.model_manager.extract_features(
                request.events, request.entity_id, request.entity_type, time_window
            )

            # Persist features to feature store if available
            try:
                if self.feature_store:
                    tenant_id = getattr(request, "tenant_id", None)
                    self.feature_store.save_features(request.entity_id, features, tenant_id=tenant_id)
            except Exception as e:
                # Do not fail the analysis path due to persistence error; log and continue
                self.logger.error("Feature store persistence failed", error=str(e))
            
            # Get baseline status
            baseline = await self.model_manager.get_baseline_status(request.entity_id)
            baseline_available = baseline is not None and baseline.is_stable()
            
            # Handle insufficient baseline
            if not baseline_available and not request.force_analysis:
                if request.include_baseline_creation and len(request.events) >= self.config.min_events_for_baseline:
                    # Create baseline from current events
                    historical_features = [features]  # Would typically use more historical data
                    baseline = await self.model_manager.create_baseline(
                        request.entity_id, request.entity_type, historical_features
                    )
                    baseline_available = True
                else:
                    # Return response indicating insufficient baseline
                    return ComprehensiveAnalysisResponse(
                        entity_id=request.entity_id,
                        entity_type=request.entity_type,
                        analysis_timestamp=datetime.utcnow(),
                        time_window_hours=request.time_window_hours,
                        extracted_features=features.features,
                        feature_metadata=features.metadata,
                        baseline_available=False,
                        anomaly_result=AnomalyResponse(
                            entity_id=request.entity_id,
                            anomaly_score=0.0,
                            is_anomaly=False,
                            confidence=0.1,
                            anomaly_type="insufficient_baseline",
                            detection_method="none",
                            timestamp=datetime.utcnow(),
                            baseline_available=False
                        ),
                        risk_assessment=ThreatAssessmentResponse(
                            assessment_id="no_assessment",
                            entity_id=request.entity_id,
                            entity_type=request.entity_type,
                            risk_score=0.0,
                            threat_level="low",
                            confidence_score=0.1,
                            investigation_priority=1,
                            false_positive_likelihood=0.9,
                            timestamp=datetime.utcnow()
                        ),
                        processing_time_ms=(time.time() - start_time) * 1000,
                        model_versions=self.model_manager.model_versions
                    )
            
            # Detect anomalies
            anomaly_result = await self.model_manager.detect_anomalies(request.entity_id, features)
            
            # Assess risk
            risk_assessment = await self.model_manager.assess_risk(
                request.entity_id, request.entity_type, features, anomaly_result
            )
            
            # Update baseline if available
            if baseline_available:
                await self.model_manager.update_baseline(request.entity_id, features)
            
            # Create response
            response = ComprehensiveAnalysisResponse(
                entity_id=request.entity_id,
                entity_type=request.entity_type,
                analysis_timestamp=datetime.utcnow(),
                time_window_hours=request.time_window_hours,
                extracted_features=features.features,
                feature_metadata=features.metadata,
                baseline_available=baseline_available,
                baseline_confidence=baseline.confidence_score if baseline else None,
                baseline_age_hours=(datetime.utcnow() - baseline.last_updated).total_seconds() / 3600 if baseline else None,
                baseline_deviations=anomaly_result.contributing_features,
                anomaly_result=AnomalyResponse(
                    entity_id=anomaly_result.entity_id,
                    anomaly_score=anomaly_result.anomaly_score,
                    is_anomaly=anomaly_result.is_anomaly,
                    confidence=anomaly_result.confidence,
                    anomaly_type=anomaly_result.anomaly_type,
                    contributing_features=anomaly_result.contributing_features,
                    detection_method=anomaly_result.detection_method,
                    timestamp=anomaly_result.timestamp,
                    baseline_available=baseline_available
                ),
                risk_assessment=ThreatAssessmentResponse(
                    assessment_id=risk_assessment.assessment_id,
                    entity_id=risk_assessment.entity_id,
                    entity_type=risk_assessment.entity_type,
                    risk_score=risk_assessment.risk_score,
                    threat_level=risk_assessment.threat_level.value,
                    confidence_score=risk_assessment.confidence_score,
                    risk_categories=[cat.value for cat in risk_assessment.risk_categories],
                    mitre_tactics=[tactic.value for tactic in risk_assessment.mitre_tactics],
                    potential_impact=risk_assessment.potential_impact,
                    recommendations=risk_assessment.recommendations,
                    investigation_priority=risk_assessment.investigation_priority,
                    false_positive_likelihood=risk_assessment.false_positive_likelihood,
                    timestamp=risk_assessment.timestamp
                ),
                processing_time_ms=(time.time() - start_time) * 1000,
                model_versions=self.model_manager.model_versions
            )
            
            # Log analysis completion
            self.audit_logger.log_model_event(
                event_type=AuditEventType.BEHAVIOR_ANALYZED,
                user_id="system",
                tenant_id="system",
                model_id="behavioral_analysis",
                model_type="ueba",
                prediction_confidence=anomaly_result.confidence
            )
            
            # Update statistics
            self.processing_stats["requests_processed_24h"] += 1
            if anomaly_result.is_anomaly:
                self.processing_stats["anomalies_detected_24h"] += 1
            
            processing_time_ms = (time.time() - start_time) * 1000
            self.processing_stats["avg_response_time_ms"] = (
                self.processing_stats["avg_response_time_ms"] * 0.9 + processing_time_ms * 0.1
            )
            
            self.logger.info(
                "Behavioral analysis completed",
                entity_id=request.entity_id,
                anomaly_detected=anomaly_result.is_anomaly,
                risk_score=risk_assessment.risk_score,
                processing_time_ms=processing_time_ms
            )
            
            return response
        
        except Exception as e:
            self.processing_stats["errors_24h"] += 1
            self.logger.error(
                "Behavioral analysis failed",
                entity_id=request.entity_id,
                error=str(e)
            )
            raise
    
    async def create_baseline(self, entity_id: str, entity_type: str,
                            historical_events: List[SecurityEventRequest]) -> BaselineStatusResponse:
        """Create baseline for entity."""
        try:
            # Extract features from historical events
            time_window = timedelta(hours=24)  # Default window
            historical_features = []
            
            # Group events by time windows and extract features
            events_df = pd.DataFrame([
                {
                    'timestamp': event.timestamp,
                    'event_type': event.event_type,
                    'resource': event.resource,
                    'action': event.action,
                    'source_ip': event.source_ip,
                    'user_agent': event.user_agent,
                    'success': event.success,
                    'data_size': event.data_size,
                    'location': event.location,
                    'application': event.application,
                    'security_classification': event.security_classification.value
                }
                for event in historical_events
            ])
            
            # Extract features for the entire period
            features = self.model_manager.feature_extractor.extract_features(
                events_df, entity_id, entity_type, time_window
            )
            historical_features.append(features)
            
            # Create baseline
            baseline = await self.model_manager.create_baseline(
                entity_id, entity_type, historical_features
            )
            
            return BaselineStatusResponse(
                entity_id=entity_id,
                entity_type=entity_type,
                baseline_exists=True,
                baseline_id=baseline.baseline_id,
                created_at=baseline.created_at,
                last_updated=baseline.last_updated,
                sample_count=baseline.sample_count,
                stability_score=baseline.stability_score,
                confidence_score=baseline.confidence_score,
                is_stable=baseline.is_stable(),
                feature_count=len(baseline.feature_names),
                next_update_due=baseline.last_updated + timedelta(hours=self.config.retrain_frequency_hours)
            )
        
        except Exception as e:
            self.logger.error(
                "Baseline creation failed",
                entity_id=entity_id,
                entity_type=entity_type,
                error=str(e)
            )
            raise
    
    async def get_baseline_status(self, entity_id: str) -> BaselineStatusResponse:
        """Get baseline status for entity."""
        baseline = await self.model_manager.get_baseline_status(entity_id)
        
        if baseline:
            return BaselineStatusResponse(
                entity_id=entity_id,
                entity_type=baseline.entity_type,
                baseline_exists=True,
                baseline_id=baseline.baseline_id,
                created_at=baseline.created_at,
                last_updated=baseline.last_updated,
                sample_count=baseline.sample_count,
                stability_score=baseline.stability_score,
                confidence_score=baseline.confidence_score,
                is_stable=baseline.is_stable(),
                feature_count=len(baseline.feature_names),
                next_update_due=baseline.last_updated + timedelta(hours=self.config.retrain_frequency_hours)
            )
        else:
            return BaselineStatusResponse(
                entity_id=entity_id,
                entity_type="unknown",
                baseline_exists=False
            )
    
    async def get_service_status(self) -> ModelStatusResponse:
        """Get comprehensive service status."""
        model_status = self.model_manager.get_model_status()
        
        return ModelStatusResponse(
            service_version="1.0.0",
            model_status=model_status,
            baseline_summary=model_status["baseline_summary"],
            anomaly_detector_status=model_status["anomaly_detector_status"],
            last_training_time=datetime.fromisoformat(model_status["last_training_time"]) 
                if model_status["last_training_time"] else None,
            next_training_due=datetime.utcnow() + timedelta(hours=self.config.retrain_frequency_hours),
            performance_metrics=self.processing_stats
        )
    
    async def _initialize_models(self):
        """Initialize ML models."""
        self.logger.info("Initializing ML models")
        
        # Models are initialized in ModelManager constructor
        # Additional initialization can be added here
        
        self.logger.info("ML models initialized successfully")
    
    async def _start_background_tasks(self):
        """Start background processing tasks."""
        self.logger.info("Starting background tasks")
        
        # Model maintenance task
        model_maintenance_task = asyncio.create_task(self._model_maintenance_loop())
        self.background_tasks.append(model_maintenance_task)
        
        # Event buffer cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.background_tasks.append(cleanup_task)
        
        # Statistics reset task
        stats_reset_task = asyncio.create_task(self._stats_reset_loop())
        self.background_tasks.append(stats_reset_task)

        # Baseline training task (optional)
        bt_interval_hours = int(os.getenv("BASELINE_TRAIN_INTERVAL_HOURS", "24"))
        if self.baseline_trainer:
            baseline_task = asyncio.create_task(self._baseline_training_loop(bt_interval_hours))
            self.background_tasks.append(baseline_task)

        # Supervised training task (optional)
        st_interval_hours = int(os.getenv("SUPERVISED_TRAIN_INTERVAL_HOURS", "24"))
        if self.supervised_trainer:
            supervised_task = asyncio.create_task(self._supervised_training_loop(st_interval_hours))
            self.background_tasks.append(supervised_task)
        
        self.logger.info("Background tasks started")
    
    async def _model_maintenance_loop(self):
        """Background task for model maintenance."""
        while not self.should_stop:
            try:
                # Check if retraining is needed
                if self.model_manager.anomaly_detector.should_retrain():
                    self.logger.info("Starting automatic model retraining")
                    
                    # Would collect training data here in production
                    # For now, skip automatic retraining
                    pass
                
                # Cleanup old baselines
                self.model_manager.baseline_model.cleanup_old_baselines()
                
                # Sleep for 1 hour
                await asyncio.sleep(3600)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Model maintenance error", error=str(e))
                await asyncio.sleep(300)  # Sleep 5 minutes on error
    
    async def _cleanup_loop(self):
        """Background task for cleaning up old events."""
        while not self.should_stop:
            try:
                await self.event_buffer.cleanup_old_events()
                await asyncio.sleep(1800)  # Clean up every 30 minutes
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Cleanup loop error", error=str(e))
                await asyncio.sleep(300)
    
    async def _stats_reset_loop(self):
        """Background task for resetting daily statistics."""
        while not self.should_stop:
            try:
                # Wait until next midnight
                now = datetime.utcnow()
                next_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                sleep_seconds = (next_midnight - now).total_seconds()
                
                await asyncio.sleep(sleep_seconds)
                
                # Reset daily statistics
                self.processing_stats.update({
                    "requests_processed_24h": 0,
                    "anomalies_detected_24h": 0,
                    "errors_24h": 0
                })
                
                self.logger.info("Daily statistics reset")
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Stats reset error", error=str(e))
                await asyncio.sleep(3600)  # Retry in 1 hour

    async def _baseline_training_loop(self, interval_hours: int):
        """Periodic baseline training for recent entities."""
        while not self.should_stop:
            try:
                tenant_id = None  # TODO: iterate per-tenant if needed
                limit = int(os.getenv("BASELINE_TRAIN_ENTITY_LIMIT", "200"))
                if self.baseline_trainer:
                    res = self.baseline_trainer.train_all_recent(tenant_id=tenant_id, limit=limit)
                    trained = len([1 for r in res.get("trained", [])])
                    skipped = len([1 for r in res.get("skipped", [])])
                    self.logger.info("Baseline training cycle completed", trained=trained, skipped=skipped)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Baseline training error", error=str(e))
            await asyncio.sleep(interval_hours * 3600)

    async def _supervised_training_loop(self, interval_hours: int):
        """Periodic supervised training for recent labeled data."""
        while not self.should_stop:
            try:
                if self.supervised_trainer:
                    tenant_id = None  # TODO: iterate per-tenant when labels exist per tenant
                    result = self.supervised_trainer.train_for_tenant(tenant_id)
                    status = result.get("status")
                    self.logger.info("Supervised training cycle", status=status, details=result)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Supervised training error", error=str(e))
            await asyncio.sleep(interval_hours * 3600)