"""
system/ml_core/anomaly_detector.py
=====================================
Compatibility shim — backward-compat import path for AnomalyDetector.

All callers MUST be migrated to import directly from:
    modules.ids_ips.engine.anomaly_detector

Remaining callers using this shim (Phase 6 audit):
  - tests/unit/test_anomaly_detector.py   → migrate when test refactored
  - tests/unit/test_ml_inference.py       → migrate when test refactored
  - tests/conftest.py                     → already aliased, OK

Once zero callers remain, this file can be deleted.
"""
from modules.ids_ips.engine.anomaly_detector import (  # noqa: F401
    AnomalyDetector, TrafficFeatures, AnomalyResult
)
