"""
Automated Threat Hunting System for iSECTECH AI/ML Threat Detection

This module provides automated threat hunting capabilities with pattern recognition,
hypothesis generation, and continuous monitoring for advanced persistent threats (APTs),
insider threats, and zero-day attacks.
"""

__version__ = '1.0.0'
__author__ = 'iSECTECH AI/ML Team'

from .automated_threat_hunter import AutomatedThreatHunter
from .pattern_recognition_engine import PatternRecognitionEngine
from .hypothesis_generator import ThreatHypothesisGenerator
from .hunting_orchestrator import ThreatHuntingOrchestrator

__all__ = [
    'AutomatedThreatHunter',
    'PatternRecognitionEngine', 
    'ThreatHypothesisGenerator',
    'ThreatHuntingOrchestrator'
]