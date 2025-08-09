"""
MLOps Pipeline for Automated Model Training and Deployment

This module provides production-grade MLOps capabilities including automated
model training, validation, deployment, and monitoring with full lifecycle
management for threat detection models.
"""

__version__ = '1.0.0'
__author__ = 'iSECTECH AI/ML Team'

from .model_training_pipeline import AutomatedModelTrainingPipeline
from .model_registry import ThreatDetectionModelRegistry
from .deployment_manager import ModelDeploymentManager
from .monitoring_system import ModelMonitoringSystem

__all__ = [
    'AutomatedModelTrainingPipeline',
    'ThreatDetectionModelRegistry',
    'ModelDeploymentManager',
    'ModelMonitoringSystem'
]