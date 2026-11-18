"""
PHANTOM — Online Continual Learner (OCL) Package
=================================================
Layer 4 of the PHANTOM framework.
"""

from .ocl_engine import OnlineContinualLearner, DriftStatus, MemoryEntry

__all__ = ["OnlineContinualLearner", "DriftStatus", "MemoryEntry"]
