"""
Threat Pattern Knowledge Base for iSECTECH AI/ML Threat Detection

This module provides comprehensive threat pattern storage, analysis, and learning
capabilities with historical data management and pattern evolution tracking.
"""

__version__ = '1.0.0'
__author__ = 'iSECTECH AI/ML Team'

from .threat_pattern_database import ThreatPatternDatabase
from .historical_data_manager import HistoricalThreatDataManager
from .pattern_evolution_tracker import PatternEvolutionTracker
from .knowledge_base_manager import ThreatKnowledgeBaseManager

__all__ = [
    'ThreatPatternDatabase',
    'HistoricalThreatDataManager',
    'PatternEvolutionTracker',
    'ThreatKnowledgeBaseManager'
]