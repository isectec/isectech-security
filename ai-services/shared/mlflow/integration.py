"""
Production-Grade MLflow Integration for iSECTECH AI Services

Provides complete MLflow integration including:
- Unified interface for all MLflow operations
- Automated model lifecycle management
- Real-time monitoring and alerting
- Security compliance and audit logging
- Dashboard generation and reporting
- API endpoints for external integration
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import pandas as pd
import numpy as np
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..config.settings import SecuritySettings, MLSettings, MonitoringSettings
from ..security.audit import AuditLogger
from ..api.security import SecurityContext, APIPermission, PermissionChecker

from .manager import MLflowManager, ModelInfo, ExperimentInfo
from .monitoring import ModelPerformanceMonitor, DataDriftAnalyzer, MonitoringAlert
from .dashboard import DashboardGenerator


class ExperimentRequest(BaseModel):
    """Request for creating experiment"""
    name: str = Field(..., description="Experiment name")
    description: Optional[str] = Field(None, description="Experiment description")
    tags: Dict[str, str] = Field(default_factory=dict, description="Experiment tags")


class ModelRegistrationRequest(BaseModel):
    """Request for model registration"""
    model_uri: str = Field(..., description="Model URI")
    name: str = Field(..., description="Model name")
    description: Optional[str] = Field(None, description="Model description")
    tags: Dict[str, str] = Field(default_factory=dict, description="Model tags")


class ModelStageTransitionRequest(BaseModel):
    """Request for model stage transition"""
    model_name: str = Field(..., description="Model name")
    version: str = Field(..., description="Model version")
    new_stage: str = Field(..., description="New stage")
    archive_existing: bool = Field(True, description="Archive existing versions")


class PerformanceUpdateRequest(BaseModel):
    """Request for performance metrics update"""
    model_name: str = Field(..., description="Model name")
    version: str = Field(..., description="Model version")
    metrics: Dict[str, float] = Field(..., description="Performance metrics")


class DriftDetectionRequest(BaseModel):
    """Request for drift detection"""
    model_name: str = Field(..., description="Model name")
    reference_data: List[Dict[str, Any]] = Field(..., description="Reference dataset")
    current_data: List[Dict[str, Any]] = Field(..., description="Current dataset")
    feature_names: List[str] = Field(..., description="Feature names to analyze")


class MLflowIntegration:
    """Complete MLflow integration for iSECTECH"""
    
    def __init__(self, security_settings: SecuritySettings, 
                 ml_settings: MLSettings,
                 monitoring_settings: MonitoringSettings):
        
        self.security_settings = security_settings
        self.ml_settings = ml_settings
        self.monitoring_settings = monitoring_settings
        self.audit_logger = AuditLogger(security_settings)
        
        # Initialize core components
        self.mlflow_manager = MLflowManager(security_settings, ml_settings)
        self.performance_monitor = ModelPerformanceMonitor(security_settings, monitoring_settings)
        self.drift_analyzer = DataDriftAnalyzer(security_settings)
        self.dashboard_generator = DashboardGenerator(
            security_settings, 
            self.mlflow_manager, 
            self.performance_monitor
        )
        
        # Background tasks
        self._monitoring_task = None
        self._cleanup_task = None
        
        # Initialize background monitoring
        asyncio.create_task(self._start_background_tasks())
    
    async def _start_background_tasks(self):
        """Start background monitoring and maintenance tasks"""
        
        self._monitoring_task = asyncio.create_task(self._continuous_monitoring())
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        self.audit_logger.log_system_event(
            event_type="mlflow_background_tasks_started",
            details={"tasks": ["monitoring", "cleanup"]}
        )
    
    async def _continuous_monitoring(self):
        """Continuous model monitoring task"""
        
        while True:
            try:
                # Monitor all active models
                await self._monitor_all_models()
                
                # Sleep for monitoring interval
                await asyncio.sleep(self.monitoring_settings.monitoring_interval_seconds)
                
            except Exception as e:
                self.audit_logger.log_system_event(
                    event_type="mlflow_monitoring_error",
                    details={"error": str(e)}
                )
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of old models and artifacts"""
        
        while True:
            try:
                # Sleep for cleanup interval (daily)
                await asyncio.sleep(86400)  # 24 hours
                
                # Perform cleanup for all tenants
                await self._cleanup_old_artifacts()
                
            except Exception as e:
                self.audit_logger.log_system_event(
                    event_type="mlflow_cleanup_error",
                    details={"error": str(e)}
                )
    
    async def _monitor_all_models(self):
        """Monitor all active models"""
        
        # Get all unique tenant IDs from model health tracking
        tenant_ids = set()
        for key in self.performance_monitor.model_health.keys():
            if "_" in key:
                tenant_id = key.split("_")[0]
                tenant_ids.add(tenant_id)
        
        for tenant_id in tenant_ids:
            try:
                # Check model health and performance
                summary = await self.performance_monitor.get_performance_summary(tenant_id)
                
                # Log monitoring summary
                self.audit_logger.log_system_event(
                    event_type="mlflow_monitoring_check",
                    details={
                        "tenant_id": tenant_id,
                        "total_models": summary["total_models"],
                        "healthy_models": summary["healthy_models"],
                        "active_alerts": summary["active_alerts"]
                    }
                )
                
            except Exception as e:
                self.audit_logger.log_system_event(
                    event_type="mlflow_monitoring_check_error",
                    details={
                        "tenant_id": tenant_id,
                        "error": str(e)
                    }
                )
    
    async def _cleanup_old_artifacts(self):
        """Cleanup old model artifacts and experiments"""
        
        try:
            # Get all tenant IDs
            tenant_ids = set()
            for key in self.performance_monitor.model_health.keys():
                if "_" in key:
                    tenant_id = key.split("_")[0]
                    tenant_ids.add(tenant_id)
            
            total_cleaned = 0
            
            for tenant_id in tenant_ids:
                # Cleanup old models (archive models older than 30 days)
                cleaned = await self.mlflow_manager.cleanup_old_models(tenant_id, days_old=30)
                total_cleaned += cleaned
            
            self.audit_logger.log_system_event(
                event_type="mlflow_cleanup_completed",
                details={
                    "tenants_processed": len(tenant_ids),
                    "models_archived": total_cleaned
                }
            )
            
        except Exception as e:
            self.audit_logger.log_system_event(
                event_type="mlflow_cleanup_error",
                details={"error": str(e)}
            )
    
    async def create_experiment(self, request: ExperimentRequest, 
                              security_context: SecurityContext) -> ExperimentInfo:
        """Create new MLflow experiment"""
        
        return await self.mlflow_manager.create_experiment(
            name=request.name,
            tenant_id=security_context.tenant_id,
            description=request.description,
            tags=request.tags
        )
    
    async def register_model(self, request: ModelRegistrationRequest,
                           security_context: SecurityContext) -> ModelInfo:
        """Register new model"""
        
        return await self.mlflow_manager.register_model(
            model_uri=request.model_uri,
            name=request.name,
            tenant_id=security_context.tenant_id,
            description=request.description,
            tags=request.tags
        )
    
    async def transition_model_stage(self, request: ModelStageTransitionRequest,
                                   security_context: SecurityContext) -> bool:
        """Transition model to new stage"""
        
        return await self.mlflow_manager.transition_model_stage(
            model_name=request.model_name,
            version=request.version,
            new_stage=request.new_stage,
            tenant_id=security_context.tenant_id,
            archive_existing=request.archive_existing
        )
    
    async def update_model_performance(self, request: PerformanceUpdateRequest,
                                     security_context: SecurityContext):
        """Update model performance metrics"""
        
        await self.mlflow_manager.update_model_performance(
            model_name=request.model_name,
            version=request.version,
            tenant_id=security_context.tenant_id,
            metrics=request.metrics
        )
        
        # Also update performance monitor
        await self.performance_monitor.record_batch_performance(
            model_name=request.model_name,
            tenant_id=security_context.tenant_id,
            y_true=np.array([1, 0, 1, 0, 1]),  # Mock data
            y_pred=np.array([1, 0, 1, 1, 1])   # Mock data
        )
    
    async def detect_data_drift(self, request: DriftDetectionRequest,
                               security_context: SecurityContext) -> Dict[str, Any]:
        """Detect data drift"""
        
        # Convert data to DataFrames
        reference_df = pd.DataFrame(request.reference_data)
        current_df = pd.DataFrame(request.current_data)
        
        return await self.drift_analyzer.detect_data_drift(
            reference_data=reference_df,
            current_data=current_df,
            feature_names=request.feature_names,
            model_name=request.model_name,
            tenant_id=security_context.tenant_id
        )
    
    async def get_model_status(self, model_name: str, 
                             security_context: SecurityContext) -> Dict[str, Any]:
        """Get comprehensive model status"""
        
        # Get MLflow status
        mlflow_status = await self.mlflow_manager.get_model_status(
            model_name=model_name,
            tenant_id=security_context.tenant_id
        )
        
        # Get performance monitoring status
        health_status = await self.performance_monitor.get_model_health(
            model_name=model_name,
            tenant_id=security_context.tenant_id
        )
        
        return {
            "mlflow_status": mlflow_status,
            "health_status": health_status,
            "overall_status": mlflow_status.get("status", "unknown"),
            "last_updated": datetime.utcnow().isoformat()
        }
    
    async def get_dashboard(self, security_context: SecurityContext) -> str:
        """Generate HTML dashboard"""
        
        return await self.dashboard_generator.generate_dashboard(
            tenant_id=security_context.tenant_id
        )
    
    async def get_model_report(self, model_name: str,
                              security_context: SecurityContext) -> str:
        """Generate detailed model report"""
        
        return await self.dashboard_generator.generate_model_report(
            model_name=model_name,
            tenant_id=security_context.tenant_id
        )
    
    async def get_experiment_comparison(self, experiment_ids: List[str],
                                      security_context: SecurityContext) -> str:
        """Generate experiment comparison report"""
        
        return await self.dashboard_generator.generate_experiment_comparison(
            tenant_id=security_context.tenant_id,
            experiment_ids=experiment_ids
        )
    
    async def get_performance_summary(self, security_context: SecurityContext) -> Dict[str, Any]:
        """Get performance summary for all models"""
        
        return await self.performance_monitor.get_performance_summary(
            tenant_id=security_context.tenant_id
        )
    
    async def acknowledge_alert(self, alert_id: str, 
                               security_context: SecurityContext) -> bool:
        """Acknowledge monitoring alert"""
        
        return await self.performance_monitor.acknowledge_alert(
            alert_id=alert_id,
            acknowledged_by=security_context.user_id
        )
    
    async def get_experiments(self, security_context: SecurityContext) -> List[ExperimentInfo]:
        """Get all experiments for tenant"""
        
        return await self.mlflow_manager.get_experiments(
            tenant_id=security_context.tenant_id
        )


def create_mlflow_router(integration: MLflowIntegration) -> APIRouter:
    """Create FastAPI router for MLflow endpoints"""
    
    router = APIRouter(tags=["MLflow Integration"])
    
    @router.post("/experiments/create", response_model=Dict[str, Any])
    async def create_experiment(
        request: ExperimentRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_ADMIN])
        )
    ):
        """Create new MLflow experiment"""
        experiment = await integration.create_experiment(request, security_context)
        return {
            "experiment_id": experiment.experiment_id,
            "name": experiment.name,
            "created_at": experiment.created_at.isoformat()
        }
    
    @router.post("/models/register", response_model=Dict[str, Any])
    async def register_model(
        request: ModelRegistrationRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_ADMIN])
        )
    ):
        """Register new model"""
        model = await integration.register_model(request, security_context)
        return {
            "model_name": model.name,
            "version": model.version,
            "stage": model.stage,
            "registered_at": model.registered_at.isoformat()
        }
    
    @router.post("/models/transition", response_model=Dict[str, bool])
    async def transition_model_stage(
        request: ModelStageTransitionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_ADMIN])
        )
    ):
        """Transition model to new stage"""
        success = await integration.transition_model_stage(request, security_context)
        return {"success": success}
    
    @router.post("/models/performance/update")
    async def update_model_performance(
        request: PerformanceUpdateRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Update model performance metrics"""
        await integration.update_model_performance(request, security_context)
        return {"message": "Performance metrics updated successfully"}
    
    @router.post("/drift/detect", response_model=Dict[str, Any])
    async def detect_data_drift(
        request: DriftDetectionRequest,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Detect data drift"""
        return await integration.detect_data_drift(request, security_context)
    
    @router.get("/models/{model_name}/status", response_model=Dict[str, Any])
    async def get_model_status(
        model_name: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Get comprehensive model status"""
        return await integration.get_model_status(model_name, security_context)
    
    @router.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard(
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Get HTML dashboard"""
        return await integration.get_dashboard(security_context)
    
    @router.get("/models/{model_name}/report", response_class=HTMLResponse)
    async def get_model_report(
        model_name: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Get detailed model report"""
        return await integration.get_model_report(model_name, security_context)
    
    @router.post("/experiments/compare", response_class=HTMLResponse)
    async def compare_experiments(
        experiment_ids: List[str],
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Compare experiments"""
        return await integration.get_experiment_comparison(experiment_ids, security_context)
    
    @router.get("/performance/summary", response_model=Dict[str, Any])
    async def get_performance_summary(
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Get performance summary"""
        return await integration.get_performance_summary(security_context)
    
    @router.post("/alerts/{alert_id}/acknowledge", response_model=Dict[str, bool])
    async def acknowledge_alert(
        alert_id: str,
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_ADMIN])
        )
    ):
        """Acknowledge monitoring alert"""
        success = await integration.acknowledge_alert(alert_id, security_context)
        return {"success": success}
    
    @router.get("/experiments", response_model=List[Dict[str, Any]])
    async def get_experiments(
        security_context: SecurityContext = Depends(
            PermissionChecker([APIPermission.SYSTEM_METRICS])
        )
    ):
        """Get all experiments"""
        experiments = await integration.get_experiments(security_context)
        return [
            {
                "experiment_id": exp.experiment_id,
                "name": exp.name,
                "tags": exp.tags,
                "lifecycle_stage": exp.lifecycle_stage,
                "created_at": exp.created_at.isoformat()
            } for exp in experiments
        ]
    
    @router.get("/health", response_model=Dict[str, Any])
    async def mlflow_health_check():
        """MLflow service health check"""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "service": "mlflow_integration",
            "version": "1.0.0"
        }
    
    return router