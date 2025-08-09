"""
API request and response models for behavioral analysis service.

This module defines Pydantic models for API validation and serialization.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator

from ....shared.config.settings import SecurityClassification


class SecurityEventRequest(BaseModel):
    """Request model for security event data."""
    
    entity_id: str = Field(..., description="Unique identifier for the entity")
    entity_type: str = Field(default="user", description="Type of entity (user, device, etc.)")
    timestamp: datetime = Field(..., description="Event timestamp")
    event_type: str = Field(..., description="Type of security event")
    resource: Optional[str] = Field(None, description="Resource accessed")
    action: str = Field(..., description="Action performed")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    success: bool = Field(default=True, description="Whether the action was successful")
    data_size: Optional[int] = Field(None, description="Data size transferred (bytes)")
    location: Optional[str] = Field(None, description="Geographic location")
    application: Optional[str] = Field(None, description="Application used")
    security_classification: SecurityClassification = Field(
        default=SecurityClassification.UNCLASSIFIED,
        description="Security classification level"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional event metadata")

    @validator('timestamp')
    def validate_timestamp(cls, v):
        """Validate timestamp is not in the future."""
        if v > datetime.utcnow():
            raise ValueError("Timestamp cannot be in the future")
        return v

    @validator('entity_id')
    def validate_entity_id(cls, v):
        """Validate entity ID format."""
        if not v or len(v.strip()) == 0:
            raise ValueError("Entity ID cannot be empty")
        return v.strip()


class AnalysisRequest(BaseModel):
    """Request model for behavioral analysis."""
    
    entity_id: str = Field(..., description="Entity to analyze")
    entity_type: str = Field(default="user", description="Type of entity")
    events: List[SecurityEventRequest] = Field(..., description="Security events to analyze")
    time_window_hours: float = Field(default=24.0, description="Analysis time window in hours")
    include_baseline_creation: bool = Field(
        default=False, 
        description="Whether to create/update baseline if insufficient data"
    )
    force_analysis: bool = Field(
        default=False,
        description="Force analysis even with insufficient baseline"
    )

    @validator('events')
    def validate_events(cls, v):
        """Validate events list."""
        if not v:
            raise ValueError("Events list cannot be empty")
        if len(v) > 10000:
            raise ValueError("Too many events (max 10,000)")
        return v

    @validator('time_window_hours')
    def validate_time_window(cls, v):
        """Validate time window."""
        if v <= 0 or v > 168:  # Max 1 week
            raise ValueError("Time window must be between 0 and 168 hours")
        return v


class BatchAnalysisRequest(BaseModel):
    """Request model for batch analysis."""
    
    analyses: List[AnalysisRequest] = Field(..., description="List of analysis requests")
    parallel_processing: bool = Field(default=True, description="Enable parallel processing")

    @validator('analyses')
    def validate_analyses(cls, v):
        """Validate analyses list."""
        if not v:
            raise ValueError("Analyses list cannot be empty")
        if len(v) > 100:
            raise ValueError("Too many analyses (max 100)")
        return v


class BaselineCreationRequest(BaseModel):
    """Request model for baseline creation."""
    
    entity_id: str = Field(..., description="Entity to create baseline for")
    entity_type: str = Field(default="user", description="Type of entity")
    historical_events: List[SecurityEventRequest] = Field(..., description="Historical events for baseline")
    learning_rate: float = Field(default=0.1, description="Learning rate for adaptive updates")
    min_samples: int = Field(default=100, description="Minimum samples required for baseline")

    @validator('historical_events')
    def validate_historical_events(cls, v):
        """Validate historical events."""
        if len(v) < 50:
            raise ValueError("Need at least 50 historical events for baseline")
        if len(v) > 50000:
            raise ValueError("Too many historical events (max 50,000)")
        return v


class AnomalyResponse(BaseModel):
    """Response model for anomaly detection results."""
    
    entity_id: str
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score (0-1)")
    is_anomaly: bool = Field(..., description="Whether behavior is anomalous")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in detection (0-1)")
    anomaly_type: str = Field(..., description="Type of anomaly detected")
    contributing_features: Dict[str, float] = Field(
        default_factory=dict,
        description="Features contributing to anomaly"
    )
    detection_method: str = Field(..., description="Detection method used")
    timestamp: datetime = Field(..., description="Analysis timestamp")
    baseline_available: bool = Field(..., description="Whether baseline was available")


class ThreatAssessmentResponse(BaseModel):
    """Response model for threat risk assessment."""
    
    assessment_id: str = Field(..., description="Unique assessment ID")
    entity_id: str
    entity_type: str
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Overall risk score (0-1)")
    threat_level: str = Field(..., description="Threat level (low/medium/high/critical)")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Assessment confidence (0-1)")
    risk_categories: List[str] = Field(default_factory=list, description="Identified risk categories")
    mitre_tactics: List[str] = Field(default_factory=list, description="MITRE ATT&CK tactics")
    potential_impact: Dict[str, float] = Field(
        default_factory=dict,
        description="Potential impact scores"
    )
    recommendations: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Security recommendations"
    )
    investigation_priority: int = Field(..., ge=1, le=10, description="Investigation priority (1-10)")
    false_positive_likelihood: float = Field(
        ..., ge=0.0, le=1.0,
        description="Likelihood of false positive (0-1)"
    )
    timestamp: datetime = Field(..., description="Assessment timestamp")


class ComprehensiveAnalysisResponse(BaseModel):
    """Response model for comprehensive behavioral analysis."""
    
    entity_id: str
    entity_type: str
    analysis_timestamp: datetime
    time_window_hours: float
    
    # Feature analysis
    extracted_features: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extracted behavioral features"
    )
    feature_metadata: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Feature extraction metadata"
    )
    
    # Baseline analysis
    baseline_available: bool
    baseline_confidence: Optional[float] = None
    baseline_age_hours: Optional[float] = None
    baseline_deviations: Dict[str, float] = Field(default_factory=dict)
    
    # Anomaly detection
    anomaly_result: AnomalyResponse
    
    # Risk assessment
    risk_assessment: ThreatAssessmentResponse
    
    # Processing metadata
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")
    model_versions: Dict[str, str] = Field(default_factory=dict, description="Model versions used")


class BaselineStatusResponse(BaseModel):
    """Response model for baseline status."""
    
    entity_id: str
    entity_type: str
    baseline_exists: bool
    baseline_id: Optional[str] = None
    created_at: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    sample_count: int = 0
    stability_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    is_stable: bool = False
    feature_count: int = 0
    next_update_due: Optional[datetime] = None


class ModelStatusResponse(BaseModel):
    """Response model for model status."""
    
    service_name: str = "behavioral-analysis"
    service_version: str
    model_status: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Status of different models"
    )
    baseline_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Baseline model summary"
    )
    anomaly_detector_status: Dict[str, Any] = Field(
        default_factory=dict,
        description="Anomaly detector status"
    )
    last_training_time: Optional[datetime] = None
    next_training_due: Optional[datetime] = None
    performance_metrics: Dict[str, float] = Field(default_factory=dict)


class HealthCheckResponse(BaseModel):
    """Response model for health checks."""
    
    service: str = "behavioral-analysis"
    status: str = Field(..., description="Service status (healthy/degraded/unhealthy)")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    version: str
    uptime_seconds: float
    
    # Component health
    database_status: str = Field(..., description="Database connectivity status")
    model_status: str = Field(..., description="ML models status")
    memory_usage_percent: float = Field(..., ge=0.0, le=100.0)
    cpu_usage_percent: float = Field(..., ge=0.0, le=100.0)
    
    # Operational metrics
    requests_processed_24h: int = Field(default=0)
    anomalies_detected_24h: int = Field(default=0)
    avg_response_time_ms: float = Field(default=0.0)
    error_rate_percent: float = Field(default=0.0, ge=0.0, le=100.0)
    
    # Resource status
    active_baselines: int = Field(default=0)
    queue_size: int = Field(default=0)
    cache_hit_rate: float = Field(default=0.0, ge=0.0, le=1.0)


class ErrorResponse(BaseModel):
    """Response model for API errors."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = Field(None, description="Request tracking ID")
    suggestions: List[str] = Field(default_factory=list, description="Suggestions to fix the error")


class AnalysisMetrics(BaseModel):
    """Model for analysis metrics and statistics."""
    
    entity_id: Optional[str] = None
    time_window_hours: float = Field(default=24.0)
    
    # Detection metrics
    total_analyses: int = Field(default=0)
    anomalies_detected: int = Field(default=0)
    anomaly_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    avg_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Risk metrics
    critical_threats: int = Field(default=0)
    high_threats: int = Field(default=0)
    medium_threats: int = Field(default=0)
    low_threats: int = Field(default=0)
    avg_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Performance metrics
    avg_processing_time_ms: float = Field(default=0.0)
    baseline_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    false_positive_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    
    # Trend data
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ConfigUpdateRequest(BaseModel):
    """Request model for configuration updates."""
    
    anomaly_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    confidence_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    baseline_update_frequency_hours: Optional[float] = Field(None, gt=0.0)
    ensemble_weights: Optional[Dict[str, float]] = None
    risk_weights: Optional[Dict[str, float]] = None
    alert_settings: Optional[Dict[str, Any]] = None

    @validator('ensemble_weights')
    def validate_ensemble_weights(cls, v):
        """Validate ensemble weights sum to 1."""
        if v is not None:
            total = sum(v.values())
            if not (0.9 <= total <= 1.1):  # Allow small floating point errors
                raise ValueError("Ensemble weights must sum to approximately 1.0")
        return v

    @validator('risk_weights')
    def validate_risk_weights(cls, v):
        """Validate risk weights sum to 1."""
        if v is not None:
            total = sum(v.values())
            if not (0.9 <= total <= 1.1):  # Allow small floating point errors
                raise ValueError("Risk weights must sum to approximately 1.0")
        return v