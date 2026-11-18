"""
bunyanx NGFW — AEGIS Engine: Belief State Data Structures
=============================================================

Defines the probabilistic state representation used by the Adversarial
State Estimator (ASE) to track an attacker's position within the
MITRE ATT&CK Kill-Chain.

Design notes
------------
* BeliefState is intentionally a lightweight data class.  All Bayesian
  arithmetic lives in AdversarialStateEstimator; this class is pure data.
* `belief` is stored as a numpy array for numerical efficiency but the
  class handles serialisation gracefully via `to_dict()`.
* The entropy property provides a single scalar measure of certainty:
  - entropy ≈ 3.0  →  uniform belief (we know nothing about the attacker)
  - entropy ≈ 0.0  →  near-certain attacker position
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    KILL_CHAIN_STAGES,
    NUM_STAGES,
    ASE_UNIFORM_PRIOR,
)


# ---------------------------------------------------------------------------
# BeliefState
# ---------------------------------------------------------------------------

@dataclass
class BeliefState:
    """
    Probability distribution over MITRE ATT&CK Kill-Chain stages
    maintained for a single source IP.

    Attributes
    ----------
    src_ip : str
        The source IP whose attacker state is being tracked.
    belief : np.ndarray, shape (NUM_STAGES,)
        Probability mass across Kill-Chain stages. Always sums to 1.0.
    last_updated : float
        UNIX timestamp of the most recent Bayesian update.
    observation_count : int
        Number of security events observed for this IP.
    """

    src_ip: str
    belief: np.ndarray = field(
        default_factory=lambda: np.full(NUM_STAGES, ASE_UNIFORM_PRIOR, dtype=np.float64)
    )
    last_updated: float = field(default_factory=time.time)
    observation_count: int = 0

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def most_likely_stage(self) -> str:
        """Returns the name of the most probable Kill-Chain stage."""
        return KILL_CHAIN_STAGES[int(np.argmax(self.belief))]

    @property
    def most_likely_stage_idx(self) -> int:
        """Returns the index of the most probable Kill-Chain stage."""
        return int(np.argmax(self.belief))

    @property
    def stage_certainty(self) -> float:
        """
        P(most likely stage) — range [1/NUM_STAGES, 1.0].
        Useful as a scalar confidence signal.
        """
        return float(np.max(self.belief))

    @property
    def entropy(self) -> float:
        """
        Shannon entropy (bits) of the belief distribution.
        Range: [0, log2(NUM_STAGES)] = [0, 3.0] for 8 stages.

        Higher entropy → greater uncertainty about attacker position.
        """
        p = self.belief + 1e-12   # guard against log(0)
        return float(-np.sum(p * np.log2(p)))

    @property
    def normalised_certainty(self) -> float:
        """
        1 − H / H_max  ∈ [0, 1].
        0 = maximum uncertainty, 1 = perfect certainty.
        Suitable as a feature in the AEGIS composite score.
        """
        h_max = math.log2(NUM_STAGES)
        return 1.0 - (self.entropy / h_max)

    @property
    def is_stale(self) -> bool:
        """
        Returns True if belief has not been updated in >5 minutes.
        Staleness triggers a decay toward the uniform prior in ASE.
        """
        return (time.time() - self.last_updated) > 300.0

    # ------------------------------------------------------------------
    # Mutation helpers (called exclusively by AdversarialStateEstimator)
    # ------------------------------------------------------------------

    def reset_to_uniform(self) -> None:
        """Resets belief to the uninformative uniform prior."""
        self.belief = np.full(NUM_STAGES, ASE_UNIFORM_PRIOR, dtype=np.float64)
        self.last_updated = time.time()

    def touch(self) -> None:
        """Updates the last_updated timestamp and increments counter."""
        self.last_updated = time.time()
        self.observation_count += 1

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Returns a JSON-serialisable representation."""
        return {
            "src_ip":              self.src_ip,
            "most_likely_stage":   self.most_likely_stage,
            "stage_certainty":     round(self.stage_certainty, 4),
            "entropy":             round(self.entropy, 4),
            "normalised_certainty": round(self.normalised_certainty, 4),
            "belief":              {
                stage: round(float(prob), 4)
                for stage, prob in zip(KILL_CHAIN_STAGES, self.belief)
            },
            "observation_count":   self.observation_count,
            "last_updated":        self.last_updated,
            "is_stale":            self.is_stale,
        }

    def __repr__(self) -> str:
        return (
            f"BeliefState(ip={self.src_ip!r}, "
            f"stage={self.most_likely_stage!r}, "
            f"certainty={self.stage_certainty:.2%}, "
            f"H={self.entropy:.2f} bits)"
        )
