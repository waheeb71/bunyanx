"""
bunyanx NGFW — AEGIS Engine: Adversarial State Estimator (ASE)
==================================================================

Maintains a Bayesian belief distribution over MITRE ATT&CK Kill-Chain
stages for every active attacker IP observed on the network.

Algorithm (Bayesian Filter)
---------------------------

    B⁻(s') = Σ_s  P(s'|s) · B(s)               [prediction step]
    B(s')  ∝ P(event|s') · B⁻(s')               [update step]
    B(s')   = B(s') / Σ B(s')                   [normalisation]

where:
    B(s)        — current belief (prior probability of stage s)
    P(s'|s)     — Kill-Chain stage transition model (TRANSITION_MODEL)
    P(event|s') — likelihood of observing `event` in stage s' (EMISSION_MODEL)

Key properties
--------------
* Online — every incoming security event triggers an O(S) update.
* Stateless between IPs — each IP's BeliefState is independent.
* Memory-bounded — max_tracked_ips cap (+ LRU eviction) prevents unbounded growth.
* Thread-safe — per-IP locking (for future multi-thread integration).

Research reference
------------------
    B. Kordy et al., "Foundations of Attack Trees," FPS 2010.
    E. Milajerdi et al., "POIROT," CCS 2019 (provenance-based belief tracking).
    AEGIS paper — bunyanx AI Division, April 2026, §3 Layer 2 (ASE).
"""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from typing import Optional

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    EMISSION_MODEL,
    KILL_CHAIN_STAGES,
    NUM_STAGES,
    TRANSITION_MODEL,
    TTP_INDEX,
)
from modules.predictive_ai.engine.AEGIS.state.belief import BeliefState


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AdversarialStateEstimator
# ---------------------------------------------------------------------------

class AdversarialStateEstimator:
    """
    Bayesian Belief Filter over MITRE ATT&CK Kill-Chain stages.

    Maintains one BeliefState per tracked source IP.  On each call to
    ``observe(src_ip, event_type)``, the belief is updated in-place
    using the two-step Bayesian filter (predict → update).

    Parameters
    ----------
    max_tracked_ips : int
        Maximum number of IPs to track simultaneously.  When the limit
        is reached, the IP with the oldest ``last_updated`` timestamp
        is evicted (LRU policy).  Default: 4 096.
    decay_alpha : float
        Exponential decay rate applied to stale beliefs on observation.
        Belief is blended with the uniform prior at rate ``decay_alpha``
        if the IP has not been seen for >5 minutes.  Range: [0, 1].
        Default: 0.15 (15 % decay toward uniform per stale observation).
    """

    # Pre-computed numpy arrays (class-level, shared across instances)
    _T: np.ndarray = np.array(TRANSITION_MODEL, dtype=np.float64)          # (8, 8)
    _E: np.ndarray = np.array(EMISSION_MODEL,   dtype=np.float64)          # (9, 8)
    _uniform: np.ndarray = np.full(NUM_STAGES, 1.0 / NUM_STAGES, dtype=np.float64)

    # ------------------------------------------------------------------
    def __init__(
        self,
        max_tracked_ips: int = 4_096,
        decay_alpha: float = 0.15,
    ) -> None:
        self._max_tracked_ips = max_tracked_ips
        self._decay_alpha = decay_alpha

        # OrderedDict used as an LRU cache: oldest entry at the front.
        self._beliefs: OrderedDict[str, BeliefState] = OrderedDict()
        self._lock = threading.Lock()

        _log.info(
            "AdversarialStateEstimator ready — "
            "max_ips=%d  decay_alpha=%.2f",
            max_tracked_ips,
            decay_alpha,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def observe(self, src_ip: str, event_type: str) -> BeliefState:
        """
        Update the Bayesian belief for ``src_ip`` given a newly observed
        security event.

        Parameters
        ----------
        src_ip : str
            Source IP address of the suspected attacker.
        event_type : str
            Observed security event name (matched against TTP_NAMES).
            Case-insensitive.  Unknown events result in a prediction step
            only (no emission likelihood update).

        Returns
        -------
        BeliefState
            The updated belief state (same object mutated in-place).
        """
        event = event_type.upper().strip()

        with self._lock:
            belief = self._get_or_create(src_ip)

            # -- Optional: decay stale beliefs before the update -------
            if belief.is_stale and belief.observation_count > 0:
                self._apply_staleness_decay(belief)

            # -- Step 1: Prediction (time update) ----------------------
            predicted = self._T.T @ belief.belief   # shape (8,)

            # -- Step 2: Update (measurement update) -------------------
            emission_row = self._get_emission_vector(event)
            if emission_row is not None:
                updated = emission_row * predicted
            else:
                _log.debug(
                    "ASE: unknown event type '%s' — prediction step only", event
                )
                updated = predicted

            # -- Normalise ---------------------------------------------
            total = updated.sum()
            if total > 1e-10:
                belief.belief = updated / total
            else:
                _log.warning(
                    "ASE: normalisation near-zero for ip=%s event=%s — "
                    "resetting to uniform prior",
                    src_ip,
                    event,
                )
                belief.reset_to_uniform()

            belief.touch()

            _log.debug(
                "ASE update: ip=%s event=%s → stage=%s (p=%.2f, H=%.2f bits)",
                src_ip,
                event,
                belief.most_likely_stage,
                belief.stage_certainty,
                belief.entropy,
            )
            return belief

    def get_belief(self, src_ip: str) -> Optional[BeliefState]:
        """
        Return the current BeliefState for ``src_ip``, or ``None`` if the
        IP is not currently tracked.
        """
        with self._lock:
            return self._beliefs.get(src_ip)

    def get_or_create_belief(self, src_ip: str) -> BeliefState:
        """
        Return the current BeliefState for ``src_ip``, creating a fresh
        uniform-prior belief if the IP is not yet tracked.
        """
        with self._lock:
            return self._get_or_create(src_ip)

    def reset_ip(self, src_ip: str) -> None:
        """
        Reset the belief for ``src_ip`` to the uniform prior.
        Called after a successful mitigation — the attacker's position
        is no longer known.
        """
        with self._lock:
            if src_ip in self._beliefs:
                self._beliefs[src_ip].reset_to_uniform()
                _log.info("ASE: belief reset to uniform prior for ip=%s", src_ip)

    def evict_ip(self, src_ip: str) -> None:
        """Remove all tracking data for ``src_ip``."""
        with self._lock:
            self._beliefs.pop(src_ip, None)
            _log.debug("ASE: evicted ip=%s", src_ip)

    def active_ips(self) -> list[str]:
        """Return the list of IPs currently being tracked."""
        with self._lock:
            return list(self._beliefs.keys())

    def summary(self) -> dict:
        """Return a diagnostic summary of the estimator's current state."""
        with self._lock:
            return {
                "tracked_ips": len(self._beliefs),
                "max_capacity": self._max_tracked_ips,
                "utilisation_pct": round(
                    100.0 * len(self._beliefs) / self._max_tracked_ips, 1
                ),
                "top_threats": [
                    b.to_dict()
                    for b in sorted(
                        self._beliefs.values(),
                        key=lambda b: b.stage_certainty,
                        reverse=True,
                    )[:5]
                ],
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create(self, src_ip: str) -> BeliefState:
        """
        Retrieve an existing BeliefState or create a new one.
        Implements LRU eviction when capacity is reached.
        Must be called with ``self._lock`` held.
        """
        if src_ip in self._beliefs:
            # Move to end (most recently used)
            self._beliefs.move_to_end(src_ip)
            return self._beliefs[src_ip]

        # Evict oldest entry if at capacity
        if len(self._beliefs) >= self._max_tracked_ips:
            evicted_ip, _ = self._beliefs.popitem(last=False)
            _log.debug("ASE: LRU eviction of ip=%s", evicted_ip)

        belief = BeliefState(src_ip=src_ip)
        self._beliefs[src_ip] = belief
        _log.debug("ASE: tracking new ip=%s", src_ip)
        return belief

    @classmethod
    def _get_emission_vector(cls, event: str) -> Optional[np.ndarray]:
        """
        Return the emission likelihood vector P(event | stage) for `event`,
        or None if the event is unknown.

        `_E` rows are indexed by TTP_INDEX; shape (9, 8).
        """
        idx = TTP_INDEX.get(event)
        if idx is None:
            return None
        return cls._E[idx]   # shape (8,)

    def _apply_staleness_decay(self, belief: BeliefState) -> None:
        """
        Blend belief toward the uniform prior to account for elapsed time.
        Prevents stale beliefs from dominating future updates.
        """
        belief.belief = (
            (1.0 - self._decay_alpha) * belief.belief
            + self._decay_alpha * self._uniform
        )
        _log.debug(
            "ASE: staleness decay applied for ip=%s (α=%.2f)",
            belief.src_ip,
            self._decay_alpha,
        )
