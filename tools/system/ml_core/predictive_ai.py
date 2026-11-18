"""
system/ml_core/predictive_ai.py
================================
⚠️  DEPRECATED — هذا الملف تم نقله إلى:
    modules/predictive_ai/engine/correlator.py

هذا الملف مجرد compatibility shim يُعيد التوجيه للمكان الصحيح.
استورد مباشرة من:
    from modules.predictive_ai.engine.correlator import PredictiveCorrelationEngine
    from modules.predictive_ai.engine import ForecastGate, IntentPredictor
"""

import warnings

warnings.warn(
    "system.ml_core.predictive_ai is deprecated and will be removed. "
    "Import from modules.predictive_ai.engine.correlator instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export everything from the correct location
from modules.predictive_ai.engine.correlator import (  # noqa: F401, E402
    PredictiveCorrelationEngine,
    ForecastGate,
    IntentPredictor,
    IntentEntry,
    RLSafetyLayer,
    SafetyAuditEntry,
)
