"""
Trust Scoring API Module

Real-time trust scoring engine with FastAPI implementation.
"""

from .trust_scoring_engine import app, TrustScoreCalculationRequest, TrustScoreResponse

__all__ = ["app", "TrustScoreCalculationRequest", "TrustScoreResponse"]