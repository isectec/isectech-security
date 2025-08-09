"""
API Models for Behavioral Analysis & Anomaly Detection Service

Defines request/response models for:
- Behavioral analysis and baseline learning
- Anomaly detection and risk assessment
- Real-time event processing
- Historical data analysis
- Model management and configuration
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, validator


class UserEvent(BaseModel):
    """Individual user event for behavioral analysis"""
    user_id: str = Field(..., description="User identifier")
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of event (login, file_access, etc.)")
    resource: Optional[str] = Field(None, description="Resource accessed")
    ip_address: str = Field(..., description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    location: Optional[Dict[str, Any]] = Field(None, description="Geographic location data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional event metadata")
    
    @validator('event_type')
    def validate_event_type(cls, v):
        allowed_types = [
            'login', 'logout', 'file_access', 'file_download', 'file_upload',
            'email_sent', 'email_received', 'admin_action', 'config_change',
            'api_call', 'database_query', 'system_access'
        ]
        if v not in allowed_types:
            raise ValueError(f"Event type must be one of: {allowed_types}")
        return v


class BatchEventRequest(BaseModel):
    """Request for batch event processing"""
    events: List[UserEvent] = Field(..., description="List of events to process")
    tenant_id: str = Field(..., description="Tenant identifier")
    processing_options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Processing configuration options"
    )
    
    @validator('events')
    def validate_events_count(cls, v):
        if len(v) > 1000:
            raise ValueError("Maximum 1000 events per batch")
        if len(v) == 0:
            raise ValueError("At least one event required")
        return v


class BaselineRequest(BaseModel):
    """Request for baseline establishment"""
    user_id: str = Field(..., description="User identifier for baseline")
    tenant_id: str = Field(..., description="Tenant identifier")
    time_window_days: int = Field(30, description="Historical data window in days")
    force_rebuild: bool = Field(False, description="Force baseline rebuild")
    baseline_options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Baseline configuration options"
    )


class AnomalyDetectionRequest(BaseModel):
    """Request for anomaly detection analysis"""
    events: List[UserEvent] = Field(..., description="Events to analyze for anomalies")
    tenant_id: str = Field(..., description="Tenant identifier")
    detection_sensitivity: float = Field(
        0.5,
        ge=0.0,
        le=1.0,
        description="Detection sensitivity (0=low, 1=high)"
    )
    include_explanations: bool = Field(True, description="Include anomaly explanations")
    detection_options: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detection configuration options"
    )


class RiskAssessmentRequest(BaseModel):
    """Request for risk assessment"""
    user_id: str = Field(..., description="User identifier")
    events: List[UserEvent] = Field(..., description="Events for risk assessment")
    tenant_id: str = Field(..., description="Tenant identifier")
    assessment_type: str = Field("comprehensive", description="Type of risk assessment")
    context_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context for risk assessment"
    )
    
    @validator('assessment_type')
    def validate_assessment_type(cls, v):
        allowed_types = ['comprehensive', 'insider_threat', 'account_compromise', 'data_exfiltration']
        if v not in allowed_types:
            raise ValueError(f"Assessment type must be one of: {allowed_types}")
        return v


class BehavioralFeatures(BaseModel):
    """Extracted behavioral features"""
    temporal_features: Dict[str, float] = Field(..., description="Time-based patterns")
    access_features: Dict[str, float] = Field(..., description="Access patterns")
    contextual_features: Dict[str, float] = Field(..., description="Contextual patterns")
    feature_importance: Dict[str, float] = Field(..., description="Feature importance scores")
    extraction_timestamp: datetime = Field(..., description="When features were extracted")


class BaselineInfo(BaseModel):
    """Baseline information and statistics"""
    user_id: str = Field(..., description="User identifier")
    tenant_id: str = Field(..., description="Tenant identifier")
    baseline_id: str = Field(..., description="Unique baseline identifier")
    created_at: datetime = Field(..., description="Baseline creation timestamp")
    last_updated: datetime = Field(..., description="Last update timestamp")
    data_points: int = Field(..., description="Number of data points used")
    time_window_days: int = Field(..., description="Historical window used")
    confidence_score: float = Field(..., description="Baseline confidence (0-1)")
    stability_score: float = Field(..., description="Baseline stability (0-1)")
    baseline_metrics: Dict[str, float] = Field(..., description="Baseline statistical metrics")
    status: str = Field(..., description="Baseline status (active, updating, insufficient_data)")


class AnomalyResult(BaseModel):
    """Individual anomaly detection result"""
    event_id: str = Field(..., description="Event identifier")
    anomaly_score: float = Field(..., description="Anomaly score (0-1)")
    is_anomaly: bool = Field(..., description="Whether event is considered anomalous")
    confidence: float = Field(..., description="Detection confidence (0-1)")
    anomaly_type: str = Field(..., description="Type of anomaly detected")
    contributing_factors: List[str] = Field(..., description="Factors contributing to anomaly")
    explanation: Optional[str] = Field(None, description="Human-readable explanation")
    severity: str = Field(..., description="Anomaly severity (low, medium, high, critical)")
    recommended_actions: List[str] = Field(..., description="Recommended response actions")


class AnomalyDetectionResponse(BaseModel):
    """Response for anomaly detection"""
    tenant_id: str = Field(..., description="Tenant identifier")
    analysis_id: str = Field(..., description="Unique analysis identifier")
    timestamp: datetime = Field(..., description="Analysis timestamp")
    total_events: int = Field(..., description="Total events analyzed")
    anomalies_detected: int = Field(..., description="Number of anomalies detected")
    overall_risk_level: str = Field(..., description="Overall risk level")
    anomaly_results: List[AnomalyResult] = Field(..., description="Individual anomaly results")
    summary_statistics: Dict[str, Any] = Field(..., description="Analysis summary statistics")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")


class ThreatClassification(BaseModel):
    """Threat classification result"""
    threat_type: str = Field(..., description="Type of threat identified")
    confidence: float = Field(..., description="Classification confidence (0-1)")
    indicators: List[str] = Field(..., description="Threat indicators")
    mitre_techniques: List[str] = Field(..., description="MITRE ATT&CK techniques")
    severity: str = Field(..., description="Threat severity")


class RiskAssessment(BaseModel):
    """Comprehensive risk assessment result"""
    user_id: str = Field(..., description="User identifier")
    tenant_id: str = Field(..., description="Tenant identifier")
    assessment_id: str = Field(..., description="Unique assessment identifier")
    timestamp: datetime = Field(..., description="Assessment timestamp")
    overall_risk_score: float = Field(..., description="Overall risk score (0-1)")
    risk_level: str = Field(..., description="Risk level (low, medium, high, critical)")
    risk_factors: Dict[str, float] = Field(..., description="Individual risk factor scores")
    threat_classifications: List[ThreatClassification] = Field(
        ..., description="Identified threats"
    )
    business_impact: Dict[str, Any] = Field(..., description="Business impact assessment")
    recommendations: List[str] = Field(..., description="Risk mitigation recommendations")
    investigation_priority: str = Field(..., description="Investigation priority level")
    automated_actions: List[str] = Field(..., description="Suggested automated actions")
    context_analysis: Dict[str, Any] = Field(..., description="Contextual risk analysis")


class ModelStatus(BaseModel):
    """ML model status information"""
    model_name: str = Field(..., description="Model name")
    model_version: str = Field(..., description="Model version")
    status: str = Field(..., description="Model status (loaded, loading, error)")
    last_updated: datetime = Field(..., description="Last update timestamp")
    performance_metrics: Dict[str, float] = Field(..., description="Model performance metrics")
    training_data_points: int = Field(..., description="Training data points")
    accuracy: Optional[float] = Field(None, description="Model accuracy")
    precision: Optional[float] = Field(None, description="Model precision")
    recall: Optional[float] = Field(None, description="Model recall")
    f1_score: Optional[float] = Field(None, description="Model F1 score")


class AnalysisStatus(BaseModel):
    """Background analysis status"""
    analysis_id: str = Field(..., description="Analysis identifier")
    status: str = Field(..., description="Analysis status (queued, processing, completed, failed)")
    progress: float = Field(..., description="Progress percentage (0-1)")
    started_at: datetime = Field(..., description="Analysis start time")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    result_url: Optional[str] = Field(None, description="URL to fetch results")
    error_message: Optional[str] = Field(None, description="Error message if failed")


class UserBehaviorProfile(BaseModel):
    """User behavioral profile summary"""
    user_id: str = Field(..., description="User identifier")
    tenant_id: str = Field(..., description="Tenant identifier")
    profile_created: datetime = Field(..., description="Profile creation timestamp")
    last_updated: datetime = Field(..., description="Last update timestamp")
    activity_patterns: Dict[str, Any] = Field(..., description="Activity pattern summary")
    risk_indicators: List[str] = Field(..., description="Known risk indicators")
    baseline_deviations: Dict[str, float] = Field(..., description="Current baseline deviations")
    historical_anomalies: int = Field(..., description="Count of historical anomalies")
    confidence_level: float = Field(..., description="Profile confidence level")
    learning_status: str = Field(..., description="Learning status (learning, stable, stale)")


class HealthCheckResponse(BaseModel):
    """Service health check response"""
    status: str = Field(..., description="Service health status")
    timestamp: datetime = Field(..., description="Health check timestamp")
    models_loaded: int = Field(..., description="Number of models loaded")
    active_analyses: int = Field(..., description="Number of active analyses")
    queue_size: int = Field(..., description="Processing queue size")
    last_error: Optional[str] = Field(None, description="Last error message")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")