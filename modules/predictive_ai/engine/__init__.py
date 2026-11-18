"""
bunyanx NGFW — Predictive AI Engine  (AEGIS v3)
====================================================

Public API for the engine package. Import everything you need from here.

Quick-start
-----------
    # AEGIS v3 — Recommended: Two-Stage Proactive Defense
    from modules.predictive_ai.engine.AEGIS.core.AEGIS_engine import AEGISEngine
    from modules.predictive_ai.engine.tpe.pre_armed_adapter import TwoStageDefenseSystem

    AEGIS  = AEGISEngine()
    result  = AEGIS.process_event("10.0.0.5", "WAF_EXPLOIT")

    # Stage 1 only (pre-attack risk assessment)
    from modules.predictive_ai.engine.tpe.pre_armed_adapter import create_from_config
    system  = create_from_config(sector="BANKING", geo_zone="WAR_ZONE")
    directive = system.run_stage1()

    # Correlator / Legacy path
    from modules.predictive_ai.engine import (
        PredictiveCorrelationEngine,
        ForecastGate,
        IntentPredictor,
        RLSafetyLayer,
    )

Component overview (AEGIS v3)
-------------------------------
    AEGISEngine              — AEGIS Stage 2: adversarial closed-loop (ASE+AIS+CSO+DIE)
    TwoStageDefenseSystem     — AEGIS v3 full pipeline (Stage 1 TPE + Stage 2 AEGIS)
    ThreatProbabilityEngine   — Stage 1: pre-attack Bayesian risk scorer
    PredictiveCorrelationEngine — Event bridge: EventSink → AEGIS v3 pipeline
    ForecastGate              — RL risk budget + safety audit log
    IntentPredictor           — Per-IP attack intent state (kill-chain prediction)
    RLSafetyLayer             — RL budget tracker with human-review thresholds
    KillchainGraph            — Online Markov kill-chain graph
    AttackForecaster          — [legacy] time-series attack volume forecast
    RLAutoResponseAgent       — [legacy] Q-table response agent
    VulnerabilityPredictor    — [legacy] EPSS-based asset vulnerability scoring
    AIInspector               — [legacy] deep-learning traffic inspection plugin
"""

# ---------------------------------------------------------------------------
# Tier 1 — AEGIS v3: Two-Stage Proactive Defense (NEW — Recommended)
# ---------------------------------------------------------------------------
from modules.predictive_ai.engine.AEGIS.core.AEGIS_engine import (
    AEGISEngine,
    AEGISResult,
)
from modules.predictive_ai.engine.AEGIS import (
    BeliefState,
    CounterStrategy,
    DeceptionInjectionEngine,
    DecoyDirective,
    DecoyAsset,
)
from modules.predictive_ai.engine.tpe.pre_armed_adapter import (
    TwoStageDefenseSystem,
    PreArmDirective,
    create_from_config,
)
from modules.predictive_ai.engine.tpe.threat_probability_engine import (
    ThreatProbabilityEngine,
)

# ---------------------------------------------------------------------------
# Correlator layer — moved from system/ml_core/ (architectural fix)
# ---------------------------------------------------------------------------
from modules.predictive_ai.engine.correlator import (
    PredictiveCorrelationEngine,
    ForecastGate,
    IntentPredictor,
    IntentEntry,
    RLSafetyLayer,
    SafetyAuditEntry,
)

# ---------------------------------------------------------------------------
# Convenience re-exports
# ---------------------------------------------------------------------------
__all__ = [
    # AEGIS v3 — Stage 2
    "AEGISEngine",
    "AEGISResult",
    "BeliefState",
    "CounterStrategy",
    "DeceptionInjectionEngine",
    "DecoyDirective",
    "DecoyAsset",
    # AEGIS v3 — Stage 1
    "TwoStageDefenseSystem",
    "ThreatProbabilityEngine",
    "PreArmDirective",
    "create_from_config",
    # Correlator / Intent / Safety
    "PredictiveCorrelationEngine",
    "ForecastGate",
    "IntentPredictor",
    "IntentEntry",
    "RLSafetyLayer",
    "SafetyAuditEntry",
]
