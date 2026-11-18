"""
bunyanx NGFW — AEGIS : Causal Anti-Poisoning Gate (CIAPG)
=============================================================

AEGIS Contribution C8

Problem Addressed
-----------------
Machine-learning-based threat detectors are vulnerable to adversarial data
poisoning.  A sophisticated attacker can inject crafted "observations"
(e.g., spoofed SCAN events from a clean IP immediately before an EXFIL
event) to corrupt the AIS Q-table and Transformer history, causing AEGIS
to *under-predict* the attacker's actual TTP sequence.

CIAPG applies the do-calculus (Pearl's interventional framework) to
distinguish:

    • Observational probability  P_obs(s_{t+1} | s_t, A_t=x)
      — what we empirically observed in the system

    • Interventional probability P_do(s_{t+1} | s_t, do(A_t=x))
      — what would happen if the TTP x were *forced* by the attacker
        (i.e., the causal effect, not merely correlation)

If these two distributions diverge beyond threshold ε_causal, the
observation is classified as a poisoning attempt and QUARANTINED — it is
not added to AIS history or Q-table, preventing model corruption.

Algorithm
---------
For each incoming observation (TTP=x, stage_from=s_t, stage_to=s_{t+1}):

  1. P_obs  = N(s_t, x, s_{t+1}) / max(1, Σ N(s_t, x, *))
              where N is the empirical count table.

  2. P_do   = Σ_z P(s_{t+1} | z, x) · P(z | s_t)  [backdoor adjustment]
              using MITRE TRANSITION_MODEL as the confounding-free prior.

  3. Γ(x)   = |P_obs − P_do|

  4. Decision:
       Γ(x) ≤ ε_causal  →  PASS  (observation is causally consistent)
       Γ(x) >  ε_causal  →  QUARANTINE  (causal anomaly detected)

  5. On PASS only: update N(s_t, x, s_{t+1}) += 1

Research Basis
--------------
  * Pearl, J., "Causality: Models, Reasoning, and Inference," Cambridge 2009.
  * Bareinboim, E. & Pearl, J., "Causal inference and the data-fusion problem,"
    PNAS 2016.
  * Kravchik, M. & Shabtai, A., "Detecting cyber attacks in industrial control
    systems using convolutional neural networks," CPS-SPC 2018.
  * AEGIS paper — bunyanx AI Division, April 2026, §IV.C Contribution C8.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from typing import Literal

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    KILL_CHAIN_STAGES,
    NUM_STAGES,
    STAGE_INDEX,
    TRANSITION_MODEL,
    TTP_NAMES,
    NUM_TTPS,
    TTP_INDEX,
)

_log = logging.getLogger(__name__)

# Type alias for gate decision
GateDecision = Literal["PASS", "QUARANTINE"]

# Pre-compute transition matrix as numpy array (for backdoor adjustment)
_T = np.array(TRANSITION_MODEL, dtype=np.float64)  # (8, 8)  P(s'|s)


class CausalAntiPoisoningGate:
    """
    AEGIS Contribution C8 — Causal Anti-Poisoning Gate.

    Filters adversarial data-poisoning attempts by comparing observed
    TTP→stage transitions against causally-corrected (backdoor-adjusted)
    expected transitions from MITRE ATT&CK priors.

    Thread Safety
    -------------
    All state mutations (count table updates) are protected by a threading
    lock — safe for concurrent calls from the event processing pipeline.

    Parameters
    ----------
    causal_threshold : float
        ε_causal — maximum allowed divergence Γ(x) before quarantine.
        Default: 0.30.
    min_observations : int
        Minimum number of observations for a (s_t, TTP) pair before
        the causal check is activated.  Below this, always PASS
        (insufficient data to detect poisoning).  Default: 10.
    """

    def __init__(
        self,
        causal_threshold:  float = 0.30,
        min_observations:  int   = 10,
    ) -> None:
        self._eps   = causal_threshold
        self._n_min = min_observations

        # Empirical count table: N[s_t_idx][ttp_idx][s_t1_idx] = count
        # Represented as a 3D numpy array: (8 stages, 9 TTPs, 8 stages)
        self._counts: np.ndarray = np.zeros(
            (NUM_STAGES, NUM_TTPS, NUM_STAGES), dtype=np.float64
        )

        # Total observations per (s_t, ttp) pair for normalisation
        self._pair_totals: np.ndarray = np.zeros(
            (NUM_STAGES, NUM_TTPS), dtype=np.float64
        )

        self._lock = threading.Lock()

        # Statistics
        self._total_checked:      int = 0
        self._total_quarantined:  int = 0

        _log.info(
            "CausalAntiPoisoningGate ready — ε_causal=%.2f min_obs=%d",
            causal_threshold, min_observations,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        ttp:        str,
        stage_from: str,
        stage_to:   str,
    ) -> tuple[GateDecision, float]:
        """
        Evaluate whether an observed TTP transition is causally consistent.

        Parameters
        ----------
        ttp : str
            Observed TTP name (e.g. "SCAN", "LATERAL").
        stage_from : str
            Kill-chain stage *before* the event.
        stage_to : str
            Kill-chain stage *after* the event (as estimated by ASE).

        Returns
        -------
        tuple[GateDecision, float]
            (decision, gamma) where:
              decision = "PASS" or "QUARANTINE"
              gamma    = Γ(x) = |P_obs − P_do| ∈ [0, 1]
        """
        ttp_u       = ttp.upper().strip()
        stage_from_u = stage_from.upper().strip()
        stage_to_u   = stage_to.upper().strip()

        ttp_idx  = TTP_INDEX.get(ttp_u)
        sf_idx   = STAGE_INDEX.get(stage_from_u)
        st_idx   = STAGE_INDEX.get(stage_to_u)

        # If any index is unknown, pass through (unknown events can't be evaluated)
        if ttp_idx is None or sf_idx is None or st_idx is None:
            return "PASS", 0.0

        with self._lock:
            self._total_checked += 1
            pair_total = self._pair_totals[sf_idx, ttp_idx]

            # Not enough data yet → pass through
            if pair_total < self._n_min:
                return "PASS", 0.0

            # Step 1: Observational probability P_obs(s_to | s_from, ttp)
            p_obs = self._counts[sf_idx, ttp_idx, st_idx] / pair_total

            # Step 2: Backdoor adjustment P_do(s_to | s_from, do(ttp))
            # P_do(s_{t+1} | s_t, do(A_t)) = Σ_z P(s_{t+1} | z, A_t) · P(z | s_t)
            # Using MITRE transition model as P(z | s_t):
            #   p_transition[s_t] → gives P(z | s_t)  (the "confounders" z)
            # Since we observe (s_from → s_to | ttp), and the causal model
            # says the TTP is driven by stage independently, we approximate:
            #   P_do(s_to | s_from, do(ttp)) ≈ P(s_to | s_from)  [from MITRE matrix]
            p_do = _T[sf_idx, st_idx]

            # Step 3: Causal divergence
            gamma = abs(p_obs - p_do)

        if gamma > self._eps:
            with self._lock:
                self._total_quarantined += 1
            _log.warning(
                "CIAPG QUARANTINE: ttp=%s s_from=%s s_to=%s γ=%.3f (ε=%.2f)",
                ttp_u, stage_from_u, stage_to_u, gamma, self._eps,
            )
            return "QUARANTINE", round(gamma, 4)

        _log.debug(
            "CIAPG PASS: ttp=%s s_from=%s→%s γ=%.3f",
            ttp_u, stage_from_u, stage_to_u, gamma,
        )
        return "PASS", round(gamma, 4)

    def observe(
        self,
        ttp:        str,
        stage_from: str,
        stage_to:   str,
    ) -> None:
        """
        Record a PASSED observation into the empirical count table.

        IMPORTANT: Call this ONLY after check() returns "PASS".
        Calling on quarantined observations would defeat the purpose.

        Parameters
        ----------
        ttp : str
            Observed TTP name.
        stage_from : str
            Kill-chain stage before the event.
        stage_to : str
            Kill-chain stage after the event.
        """
        ttp_u        = ttp.upper().strip()
        stage_from_u = stage_from.upper().strip()
        stage_to_u   = stage_to.upper().strip()

        ttp_idx = TTP_INDEX.get(ttp_u)
        sf_idx  = STAGE_INDEX.get(stage_from_u)
        st_idx  = STAGE_INDEX.get(stage_to_u)

        if ttp_idx is None or sf_idx is None or st_idx is None:
            return

        with self._lock:
            self._counts[sf_idx, ttp_idx, st_idx] += 1.0
            self._pair_totals[sf_idx, ttp_idx]    += 1.0

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return diagnostic statistics about the gate's operation."""
        with self._lock:
            quarantine_rate = (
                self._total_quarantined / max(1, self._total_checked)
            )
            total_obs = int(self._pair_totals.sum())
        return {
            "enabled":          True,
            "causal_threshold": self._eps,
            "min_observations": self._n_min,
            "total_checked":    self._total_checked,
            "total_quarantined": self._total_quarantined,
            "quarantine_rate_pct": round(quarantine_rate * 100, 2),
            "total_observations_recorded": total_obs,
        }

    def reset(self) -> None:
        """Reset all empirical counts (e.g., for unit testing)."""
        with self._lock:
            self._counts[:]       = 0.0
            self._pair_totals[:]  = 0.0
            self._total_checked   = 0
            self._total_quarantined = 0
        _log.info("CIAPG: state reset.")
