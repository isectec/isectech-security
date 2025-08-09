"""
Behavioral Analysis Service API Layer

Production-grade FastAPI service for UEBA capabilities.
"""

from .api import create_app
from .models import *
from .endpoints import *

__all__ = ["create_app"]