"""
bunyanx NGFW — AEGIS Engine
================================

Public package API.  External code should import only from here:

    from modules.predictive_ai.engine.AEGIS import AEGISEngine, AEGISResult

All other modules inside this package are considered implementation
details and may change without notice.

Package layout
--------------
    AEGIS/
    ├── __init__.py                     ← this file (public API)
    ├── _constants.py                   ← all matrices & taxonomy (private)
    ├── belief_state.py                 ← BeliefState dataclass
    ├── adversarial_state_estimator.py  ← ASE (Layer 2)
    ├── adversarial_intent_simulator.py ← AIS (Layer 3)
    ├── counter_strategy_optimizer.py   ← CSO (Layer 4)
    ├── ueba_verifier.py               ← UEBA Verification Gate (Layer 4.5)
    ├── user_baseline.py               ← UEBA behavioral baselines
    ├── deception_injection_engine.py   ← DIE (Layer 5)
    └── AEGIS_engine.py                ← AEGISEngine orchestrator
"""

from modules.predictive_ai.engine.AEGIS.core.AEGIS_engine import (
    AEGISEngine,
    AEGISResult,
)
from modules.predictive_ai.engine.AEGIS.state.belief import BeliefState
from modules.predictive_ai.engine.AEGIS.intent.simulator import (
    TTPPrediction,
)
from modules.predictive_ai.engine.AEGIS.strategy.optimizer import (
    CounterStrategy,
)
from modules.predictive_ai.engine.AEGIS.deception.injector import (
    DeceptionInjectionEngine,
    DecoyDirective,
    DecoyAsset,
)
from modules.predictive_ai.engine.AEGIS.ueba.verifier import (
    UEBAVerifier,
    UEBADecision,
    UEBAVerdict,
)
from modules.predictive_ai.engine.AEGIS.ueba.profile import (
    UserBaseline,
    AnomalyScorer,
    AnomalyResult,
    SessionRecord,
    EntityType,
)
from modules.predictive_ai.engine.AEGIS.topology.gnn import (
    GNNLateralPredictor,
)
from modules.predictive_ai.engine.AEGIS.topology.graph import (
    NetworkTopology,
    NetworkNode,
    NetworkEdge,
    TopologyBuilder,
)
from modules.predictive_ai.engine.AEGIS.intent.attention_predictor import (
    TTPTransformerPredictor,
)

from modules.predictive_ai.engine.AEGIS.core.constants import (
    DEFENDER_ACTIONS,
    KILL_CHAIN_STAGES,
    TTP_NAMES,
)

OracleEngine = AEGISEngine
OracleResult = AEGISResult

__all__ = [
    # Engine
    "AEGISEngine",
    "AEGISResult",
    "OracleEngine",
    "OracleResult",
    # Data structures
    "BeliefState",
    "TTPPrediction",
    "CounterStrategy",
    # UEBA layer
    "UEBAVerifier",
    "UEBADecision",
    "UEBAVerdict",
    "UserBaseline",
    "AnomalyScorer",
    "AnomalyResult",
    "SessionRecord",
    "EntityType",
    # GNN layer
    "GNNLateralPredictor",
    "NetworkTopology",
    "NetworkNode",
    "NetworkEdge",
    "TopologyBuilder",
    # Transformer predictor
    "TTPTransformerPredictor",

    # Deception layer
    "DeceptionInjectionEngine",
    "DecoyDirective",
    "DecoyAsset",
    # Taxonomy constants (read-only)
    "DEFENDER_ACTIONS",
    "KILL_CHAIN_STAGES",
    "TTP_NAMES",
]
