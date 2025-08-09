"""
Configuration for the Behavioral Analysis & Anomaly Detection Service.

This module provides service-specific configuration for the UEBA system.
"""

from pydantic import BaseSettings, Field
from typing import Dict, List, Optional

from ...shared.config.settings import Settings


class BehavioralAnalysisConfig(BaseSettings):
    """Configuration specific to behavioral analysis service."""
    
    # Model configuration
    baseline_learning_days: int = Field(default=30, description="Days of data for baseline learning")
    min_events_for_baseline: int = Field(default=100, description="Minimum events needed for baseline")
    anomaly_detection_threshold: float = Field(default=0.95, description="Anomaly detection threshold")
    confidence_threshold: float = Field(default=0.8, description="Minimum confidence for alerts")
    
    # Behavioral features
    time_window_minutes: int = Field(default=60, description="Time window for behavioral analysis")
    activity_patterns_count: int = Field(default=10, description="Number of activity patterns to track")
    location_sensitivity: float = Field(default=0.1, description="Sensitivity for location-based anomalies")
    
    # Entity types to analyze
    entity_types: List[str] = Field(
        default=["user", "device", "application", "network"],
        description="Types of entities to analyze"
    )
    
    # Risk scoring
    risk_score_weights: Dict[str, float] = Field(
        default={
            "temporal_anomaly": 0.25,
            "access_anomaly": 0.30,
            "behavioral_anomaly": 0.25,
            "contextual_anomaly": 0.20
        },
        description="Weights for different anomaly types in risk scoring"
    )
    
    # ML model settings
    ensemble_model_count: int = Field(default=5, description="Number of models in ensemble")
    autoencoder_latent_dims: int = Field(default=32, description="Latent dimensions for autoencoder")
    lstm_sequence_length: int = Field(default=50, description="LSTM sequence length")
    isolation_forest_contamination: float = Field(default=0.1, description="Isolation forest contamination rate")
    
    # Feature engineering
    feature_selection_threshold: float = Field(default=0.01, description="Feature importance threshold")
    categorical_encoding_method: str = Field(default="target", description="Categorical encoding method")
    normalization_method: str = Field(default="robust", description="Data normalization method")
    
    # Real-time processing
    batch_size: int = Field(default=1000, description="Batch size for real-time processing")
    max_queue_size: int = Field(default=10000, description="Maximum queue size for events")
    processing_timeout_seconds: int = Field(default=30, description="Processing timeout for events")
    
    # Model retraining
    retrain_frequency_hours: int = Field(default=24, description="Model retraining frequency")
    model_drift_threshold: float = Field(default=0.1, description="Threshold for model drift detection")
    min_new_data_for_retrain: int = Field(default=1000, description="Minimum new data for retraining")
    
    # Alert configuration
    alert_cooldown_minutes: int = Field(default=60, description="Cooldown period between similar alerts")
    max_alerts_per_hour: int = Field(default=100, description="Maximum alerts per hour per entity")
    alert_aggregation_window_minutes: int = Field(default=15, description="Alert aggregation window")
    
    # Performance settings
    max_entities_in_memory: int = Field(default=10000, description="Maximum entities to keep in memory")
    cache_expiry_hours: int = Field(default=6, description="Cache expiry time for behavioral profiles")
    parallel_processing_workers: int = Field(default=4, description="Parallel processing workers")
    
    class Config:
        env_prefix = "BEHAVIORAL_ANALYSIS_"


def get_behavioral_config() -> BehavioralAnalysisConfig:
    """Get behavioral analysis configuration."""
    return BehavioralAnalysisConfig()


def create_service_settings() -> Settings:
    """Create complete settings for the behavioral analysis service."""
    base_settings = Settings(
        service_name="behavioral-analysis",
        service_version="1.0.0",
        port=8001
    )
    
    return base_settings