"""
Advanced AI/ML Threat Detection Models

Production-grade machine learning models for enhanced threat detection,
including behavioral analytics, anomaly detection, predictive threat
intelligence, and automated threat hunting.

This service leverages state-of-the-art ML frameworks and integrates
with the existing iSECTECH security infrastructure.
"""

__version__ = "1.0.0"
__author__ = "iSECTECH Security Team"

from .data_pipeline import DataCollectionPipeline, DataPreprocessor
from .models import (
    BehavioralAnalyticsModel,
    AnomalyDetectionModel,
    ThreatClassificationModel,
    ZeroDayDetectionModel,
    PredictiveThreatModel,
    ThreatHuntingModel
)
from .explainability import ExplainabilityEngine
from .integration import SIEMIntegrator, SOARIntegrator
from .monitoring import ModelMonitor, DriftDetector

__all__ = [
    "DataCollectionPipeline",
    "DataPreprocessor", 
    "BehavioralAnalyticsModel",
    "AnomalyDetectionModel",
    "ThreatClassificationModel",
    "ZeroDayDetectionModel",
    "PredictiveThreatModel",
    "ThreatHuntingModel",
    "ExplainabilityEngine",
    "SIEMIntegrator",
    "SOARIntegrator",
    "ModelMonitor",
    "DriftDetector"
]