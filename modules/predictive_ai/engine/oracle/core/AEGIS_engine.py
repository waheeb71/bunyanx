"""
Re-export AEGISEngine and AEGISResult from oracle_engine for compatibility.
"""
from modules.predictive_ai.engine.oracle.core.oracle_engine import (
    AEGISEngine,
    AEGISResult,
)

__all__ = ["AEGISEngine", "AEGISResult"]
