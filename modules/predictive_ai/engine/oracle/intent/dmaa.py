"""
bunyanx NGFW — AEGIS : Dual-Model Adaptive Adversary (DMAA)
================================================================

AEGIS Contribution C7

Problem Addressed
-----------------
Standard AEGIS assumes the attacker is a static rational agent with a fixed
strategy.  Advanced Persistent Threats (APTs) actively profile the defender's
response pattern and *adapt* their TTP selection to evade detection.

DMAA models the attacker's second-order reasoning:
    "The defender has responded with BLOCK_IP three times — they are a
     Reactive-Blocker archetype.  Therefore, I should pivot to MALWARE
     delivery via a side channel, which this archetype rarely monitors."

Architecture
------------
Two interleaved Bayesian inference loops:

  Loop 1 — Defender Archetype Inference (attacker's belief about us):
    B_adv^(t)(θ_D) ∝ P(response_t | θ_D) · B_adv^(t-1)(θ_D)

    θ_D ∈ {Reactive-Blocker, Deceptive-Honeypot, MTD-Shuffler,
             Conservative-Monitor, Balanced-Nash}

  Loop 2 — Evasive TTP Selection (defender-aware attack strategy):
    DetRisk(a, B_adv) = Σ_θ B_adv(θ_D) · P(detected | a, θ_D)

    a_A* = argmax_{a ∈ A_A} [ Q_A(s, a) − λ_eva · DetRisk(a, B_adv) ]

    If DetRisk(a_A*) > PIVOT_THRESHOLD:
        PIVOT — select TTPs from a different attack sub-tree

DMAA output is used by the AIS to *adjust* its TTP probability distribution,
making the system model a smarter, defender-aware adversary.

Research Basis
--------------
  * Albanese, M. et al., "Automated adversary emulation," ACM CCS 2018.
  * Dasgupta, D. & Gonzalez, F., "Evolving adversaries in cybersecurity,"
    IEEE TSMCS 2020.
  * Hespanha, J., "Game theory and adversarial reasoning," Springer 2017.
  * AEGIS paper — bunyanx AI Division, April 2026, §IV.C Contribution C7.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    DEFENDER_ACTIONS,
    NUM_ACTIONS,
    TTP_NAMES,
    NUM_TTPS,
    TTP_INDEX,
    ESCALATION_RISK,
)

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Defender archetype definitions
# ---------------------------------------------------------------------------

ARCHETYPE_NAMES: tuple[str, ...] = (
    "Reactive-Blocker",      # 0 — responds with BLOCK_IP / EMERGENCY_ISOLATE
    "Deceptive-Honeypot",    # 1 — prefers HONEYPOT_REDIRECT / DECOY_TRAP
    "MTD-Shuffler",          # 2 — frequently changes FAKE_PATCH / DECOY_TRAP
    "Conservative-Monitor",  # 3 — stays on MONITOR / ALERT_ONLY
    "Balanced-Nash",         # 4 — follows Nash-optimal strategy (like AEGIS)
)

N_ARCHETYPES: int = len(ARCHETYPE_NAMES)
N_ACTIONS:    int = NUM_ACTIONS  # 12 defender actions

# Action-to-archetype affinity matrix P(observed_action | archetype)
# Shape: (N_ACTIONS=12, N_ARCHETYPES=5)
# Each column sums to 1 — probability that an archetype takes each action.
_ACTION_ARCHETYPE_LIKELIHOOD: np.ndarray = np.array([
    # Reactive  Deceptive  MTD-Shuf  Conserv  Nash
    [0.02,      0.08,      0.05,     0.40,    0.08],   # 0: MONITOR
    [0.02,      0.12,      0.18,     0.05,    0.08],   # 1: DECOY_TRAP
    [0.04,      0.05,      0.10,     0.08,    0.08],   # 2: ISOLATE_PARTIAL
    [0.01,      0.25,      0.08,     0.02,    0.10],   # 3: HONEYPOT_REDIRECT
    [0.06,      0.04,      0.06,     0.10,    0.07],   # 4: RATE_LIMIT
    [0.08,      0.04,      0.05,     0.04,    0.08],   # 5: KILL_SESSIONS
    [0.10,      0.04,      0.05,     0.04,    0.07],   # 6: ISOLATE_FULL
    [0.04,      0.05,      0.07,     0.06,    0.07],   # 7: CREDENTIAL_ROTATE
    [0.02,      0.08,      0.20,     0.04,    0.08],   # 8: FAKE_PATCH
    [0.01,      0.04,      0.03,     0.15,    0.08],   # 9: ALERT_ONLY
    [0.35,      0.10,      0.08,     0.01,    0.10],   # 10: BLOCK_IP
    [0.25,      0.11,      0.05,     0.01,    0.11],   # 11: EMERGENCY_ISOLATE
], dtype=np.float64)

# Normalise each column to be a valid probability distribution
_ACTION_ARCHETYPE_LIKELIHOOD /= _ACTION_ARCHETYPE_LIKELIHOOD.sum(axis=0, keepdims=True)

# Detection probability matrix P(detected | attacker_ttp, defender_archetype)
# Shape: (N_TTPS=9, N_ARCHETYPES=5)
# How likely each archetype is to detect each TTP (from attacker's perspective).
_TTP_DETECTION_PROB: np.ndarray = np.array([
    # Reactive  Deceptive  MTD-Shuf  Conserv  Nash
    [0.80,      0.30,      0.40,     0.60,    0.70],   # 0: SCAN
    [0.75,      0.55,      0.45,     0.40,    0.65],   # 1: WAF_EXPLOIT
    [0.70,      0.60,      0.50,     0.35,    0.65],   # 2: MALWARE
    [0.50,      0.45,      0.35,     0.25,    0.55],   # 3: DGA_C2
    [0.65,      0.40,      0.45,     0.30,    0.60],   # 4: PRIV_ESC
    [0.60,      0.55,      0.40,     0.25,    0.58],   # 5: LATERAL
    [0.55,      0.35,      0.30,     0.20,    0.52],   # 6: DLP_EXFIL
    [0.90,      0.50,      0.55,     0.40,    0.75],   # 7: RANSOMWARE
    [0.40,      0.30,      0.25,     0.15,    0.45],   # 8: PERSISTENCE
], dtype=np.float64)


# ---------------------------------------------------------------------------
# DualModelAdaptiveAdversary
# ---------------------------------------------------------------------------

class DualModelAdaptiveAdversary:
    """
    AEGIS Contribution C7 — Dual-Model Adaptive Adversary.

    Models an attacker who profiles the defender's archetype and selects
    TTPs that minimise detection risk while maximising attack progress.

    This component is consumed by the AdversarialIntentSimulator to *adjust*
    its TTP probability distribution to reflect a more realistic, evasion-aware
    adversary model.

    Parameters
    ----------
    lambda_eva : float
        Evasion weight — how strongly the attacker penalises detected TTPs.
        Range [0, 1].  Default: 0.40.
    pivot_threshold : float
        Detection-risk threshold above which attacker performs a strategy pivot.
        Default: 0.65.
    uniform_prior : bool
        If True, initialise belief over archetypes as uniform (equal weight).
        Default: True.
    """

    LAMBDA_EVA:      float = 0.40
    PIVOT_THRESHOLD: float = 0.65

    def __init__(
        self,
        lambda_eva:     float = 0.40,
        pivot_threshold: float = 0.65,
        uniform_prior:  bool  = True,
    ) -> None:
        self._lambda_eva     = lambda_eva
        self._pivot_threshold = pivot_threshold

        # B_adv — attacker's belief distribution over defender archetypes
        if uniform_prior:
            self._belief = np.ones(N_ARCHETYPES, dtype=np.float64) / N_ARCHETYPES
        else:
            # Slight bias toward Balanced-Nash (most rational defender prior)
            self._belief = np.array([0.15, 0.20, 0.15, 0.20, 0.30], dtype=np.float64)

        # Pivot counter for monitoring
        self._pivot_count: int = 0
        self._update_count: int = 0

        _log.info(
            "DualModelAdaptiveAdversary ready — λ_eva=%.2f pivot_thresh=%.2f",
            lambda_eva, pivot_threshold,
        )

    # ------------------------------------------------------------------
    # Loop 1 — Defender Archetype Inference
    # ------------------------------------------------------------------

    def update_belief(self, observed_defender_action: str) -> None:
        """
        Bayesian belief update upon observing a defender action.

        B_adv^(t)(θ_D) ∝ P(action | θ_D) · B_adv^(t-1)(θ_D)

        Parameters
        ----------
        observed_defender_action : str
            The defender action name observed (must be in DEFENDER_ACTIONS).
        """
        action_upper = observed_defender_action.upper().strip()

        try:
            action_idx = list(DEFENDER_ACTIONS).index(action_upper)
        except ValueError:
            _log.debug("DMAA: unknown defender action '%s', skipping update", action_upper)
            return

        # Likelihood P(action | θ_D) for each archetype
        likelihoods = _ACTION_ARCHETYPE_LIKELIHOOD[action_idx]  # shape (5,)

        # Bayesian update
        posterior = likelihoods * self._belief
        total     = posterior.sum()

        if total > 1e-12:
            self._belief = posterior / total
        else:
            # Numerical underflow — reset to uniform
            self._belief = np.ones(N_ARCHETYPES, dtype=np.float64) / N_ARCHETYPES
            _log.warning("DMAA: belief underflow — reset to uniform prior")

        self._update_count += 1

        _log.debug(
            "DMAA belief update: action=%s → top_archetype=%s (p=%.2f)",
            action_upper,
            ARCHETYPE_NAMES[int(np.argmax(self._belief))],
            float(np.max(self._belief)),
        )

    # ------------------------------------------------------------------
    # Loop 2 — Evasive TTP Selection
    # ------------------------------------------------------------------

    def compute_det_risk(self, ttp_idx: int) -> float:
        """
        Compute the detection risk for a TTP given the current archetype belief.

        DetRisk(a, B_adv) = Σ_θ B_adv(θ) · P(detected | a, θ)

        Parameters
        ----------
        ttp_idx : int
            Index of the attacker TTP in TTP_NAMES.

        Returns
        -------
        float
            Detection risk ∈ [0, 1].
        """
        if ttp_idx < 0 or ttp_idx >= NUM_TTPS:
            return 0.5  # unknown TTP — assume moderate risk
        return float(np.dot(_TTP_DETECTION_PROB[ttp_idx], self._belief))

    def get_evasion_adjusted_probs(
        self,
        base_probs:        dict[str, float],
        current_stage_idx: int,
    ) -> dict[str, float]:
        """
        Adjust base TTP probabilities to reflect attacker's evasion reasoning.

        For each TTP a:
            P_evasive(a) ∝ base_prob(a) · (1 − λ_eva · DetRisk(a, B_adv))

        Parameters
        ----------
        base_probs : dict[str, float]
            Base TTP probability distribution from AIS {ttp_name: prob}.
        current_stage_idx : int
            Current kill-chain stage index (0–7) for context.

        Returns
        -------
        dict[str, float]
            Evasion-adjusted TTP probability distribution.
        """
        if not base_probs:
            return base_probs

        adjusted: dict[str, float] = {}
        pivot_triggered = False

        for ttp_name, prob in base_probs.items():
            ttp_idx = TTP_INDEX.get(ttp_name.upper(), -1)
            det_risk = self.compute_det_risk(ttp_idx) if ttp_idx >= 0 else 0.5

            # Evasion-adjusted probability
            evasion_factor = max(0.0, 1.0 - self._lambda_eva * det_risk)
            adjusted[ttp_name] = prob * evasion_factor

            # Check if pivot should occur
            if det_risk > self._pivot_threshold and prob > 0.1:
                pivot_triggered = True

        if pivot_triggered:
            self._pivot_count += 1
            _log.info(
                "DMAA PIVOT triggered: stage=%d pivot_count=%d — "
                "attacker switching to lower-detection TTP cluster",
                current_stage_idx,
                self._pivot_count,
            )
            # On pivot: suppress all high-detection-risk TTPs further
            adjusted = self._apply_pivot_suppression(adjusted)

        # Renormalise
        total = sum(adjusted.values())
        if total > 1e-10:
            adjusted = {k: v / total for k, v in adjusted.items()}
        else:
            # Fallback to base probs if everything zeroed out
            adjusted = base_probs

        return adjusted

    def _apply_pivot_suppression(
        self, probs: dict[str, float]
    ) -> dict[str, float]:
        """
        Apply stronger suppression to detected-risk TTPs during a pivot.
        TTPs with DetRisk > 0.5 are suppressed to near-zero.
        """
        pivoted: dict[str, float] = {}
        for ttp_name, prob in probs.items():
            ttp_idx  = TTP_INDEX.get(ttp_name.upper(), -1)
            det_risk = self.compute_det_risk(ttp_idx) if ttp_idx >= 0 else 0.5

            if det_risk > 0.50:
                pivoted[ttp_name] = prob * 0.05  # near-zero
            else:
                pivoted[ttp_name] = prob * 1.50  # amplify low-risk TTPs
        return pivoted

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_belief_summary(self) -> dict:
        """Return the current defender archetype belief distribution."""
        top_idx = int(np.argmax(self._belief))
        return {
            "top_archetype":     ARCHETYPE_NAMES[top_idx],
            "top_archetype_prob": round(float(self._belief[top_idx]), 4),
            "belief": {
                ARCHETYPE_NAMES[i]: round(float(self._belief[i]), 4)
                for i in range(N_ARCHETYPES)
            },
            "pivot_count":   self._pivot_count,
            "update_count":  self._update_count,
            "lambda_eva":    self._lambda_eva,
            "pivot_threshold": self._pivot_threshold,
        }
