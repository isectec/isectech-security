"""
NLP Security Assistant Models Module.

This module contains the core NLP models for the iSECTECH security assistant,
providing threat explanation, investigation recommendations, and report generation.
"""

from .threat_explainer import ThreatExplainer, ThreatExplanation
from .investigation_advisor import InvestigationAdvisor, InvestigationRecommendation
from .report_generator import ReportGenerator, SecurityReport
from .security_nlp_processor import SecurityNLPProcessor, SecurityContext

__all__ = [
    "ThreatExplainer",
    "ThreatExplanation", 
    "InvestigationAdvisor",
    "InvestigationRecommendation",
    "ReportGenerator",
    "SecurityReport",
    "SecurityNLPProcessor",
    "SecurityContext",
]