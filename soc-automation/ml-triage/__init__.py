"""
ML-Based Alert Triage System

This module provides intelligent alert triage using machine learning models
to automatically categorize and prioritize security alerts based on risk
assessment and pattern analysis.

Components:
- MLTriageEngine: Main triage orchestrator with ensemble models
- AlertFeatureExtractor: Advanced feature engineering from alert data
- RiskScorer: Multi-dimensional risk assessment engine  
- ModelTrainer: Continuous learning and model improvement

Usage:
    from soc_automation.ml_triage import MLTriageEngine
    
    # Initialize triage engine
    triage_engine = MLTriageEngine(config)
    await triage_engine.initialize()
    
    # Triage an alert
    result = await triage_engine.triage_alert(enriched_alert)
    
    print(f"Decision: {result.decision}")
    print(f"Confidence: {result.confidence}")
    print(f"Risk Score: {result.risk_score}")
"""

from .ml_triage_engine import MLTriageEngine, TriageResult, TriageDecision
from .feature_extractor import AlertFeatureExtractor
from .risk_scorer import RiskScorer, RiskAssessment, RiskFactor
from .model_trainer import ModelTrainer, TrainingResults, ModelPerformance

__version__ = "1.0.0"
__author__ = "iSECTECH SOC Team"

__all__ = [
    # Main classes
    "MLTriageEngine",
    "AlertFeatureExtractor", 
    "RiskScorer",
    "ModelTrainer",
    
    # Data classes
    "TriageResult",
    "TriageDecision",
    "RiskAssessment",
    "RiskFactor",
    "TrainingResults",
    "ModelPerformance",
]

# Module metadata
ML_TRIAGE_INFO = {
    "name": "ML-Based Alert Triage System",
    "version": __version__,
    "description": "Intelligent security alert triage using machine learning",
    "components": {
        "ml_triage_engine": "Main triage orchestrator with ensemble ML models",
        "feature_extractor": "Advanced feature engineering from security alerts",
        "risk_scorer": "Multi-dimensional risk assessment across 8 risk factors",
        "model_trainer": "Continuous learning and model improvement pipeline"
    },
    "capabilities": [
        "Real-time alert triage (<100ms processing)",
        "Multi-model ensemble predictions", 
        "Risk scoring across 8 dimensions",
        "Feature extraction (100+ features)",
        "Confidence scoring and explainability",
        "Continuous model training and improvement",
        "Performance monitoring and A/B testing"
    ],
    "integration": {
        "input": "Enriched alerts from alert-ingestion system",
        "output": "Triage decisions for SOC orchestration",
        "storage": "Elasticsearch for model performance tracking",
        "caching": "Redis for model deployment and results"
    }
}