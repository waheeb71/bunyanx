"""
bunyanx NGFW — AEGIS : Calibrated Prediction Confidence Index (CPCI)
=========================================================================

AEGIS Contribution C11

Problem Addressed
-----------------
AEGIS's AIS produces a probability distribution over attacker TTPs.
Without formal uncertainty quantification, the system cannot reliably
distinguish:
  (a) High-confidence prediction: P(RANSOMWARE) = 0.92 ← act autonomously
  (b) Low-confidence prediction:  P(SCAN) = 0.16, P(WAF) = 0.14 ← need analyst

Prior work relies on thresholding a single softmax output, which:
  - Is poorly calibrated (softmax scores are known to be overconfident)
  - Provides no coverage guarantee

CPCI resolves this by applying *Conformal Prediction* (Vovk et al., 2005),
which provides a rigorous statistical guarantee:

    P(true TTP ∈ Prediction_Set_{1-α}(x)) ≥ 1 − α  for all distributions.

This is a model-agnostic, distribution-free coverage guarantee (not just
an asymptotic result), validated at 95% confidence (α = 0.05) by default.

Algorithm
---------
Phase 1 — Calibration (offline, runs once at startup):
  For each calibration sample (xⱼ, yⱼ):
    Compute nonconformity score: s(xⱼ, yⱼ) = 1 − π_A(yⱼ | xⱼ)
    where yⱼ = true TTP label, π_A = AIS probability for yⱼ

  Conformal quantile:
    q̂ = Quantile( {s(xⱼ, yⱼ)}_{j=1}^m, ⌈(m+1)(1−α)⌉ / m )

Phase 2 — Inference (online, per event):
  Prediction set:
    P_{1−α}(x) = { y ∈ A_A : 1 − π_A(y|x) ≤ q̂ }
              = { y : π_A(y|x) ≥ 1 − q̂ }

CPCI Score:
    CPCI = (1 − (|P| − 1)/|A_A|) · (1 − H(B^t)/log₂(K))

where:
    |P|    = size of the prediction set
    |A_A|  = number of TTP classes (9)
    H(B^t) = Shannon entropy of current belief state (bits)
    K      = number of kill-chain stages (8)
    log₂(K) = 3.0 bits = maximum entropy

Authorization Tiers:
    CPCI ≥ 0.75  AND  |P| = 1          →  AUTONOMOUS
    0.40 ≤ CPCI < 0.75  OR  2 ≤ |P| ≤ 3  →  HUMAN_REVIEW
    CPCI < 0.40  OR  |P| > 3            →  EMERGENCY_OVERRIDE

Research Basis
--------------
  * Vovk, V. et al., "Algorithmic Learning in a Random World," Springer 2005.
  * Angelopoulos, A. & Bates, S., "A Gentle Introduction to Conformal Prediction,"
    arXiv 2021.
  * Romano, Y. et al., "Classification with Valid Adaptive Coverage," NeurIPS 2020.
  * AEGIS paper — bunyanx AI Division, April 2026, §IV.C Contribution C11.
"""

from __future__ import annotations

import logging
import math
from typing import Literal, Optional

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    TTP_NAMES,
    NUM_TTPS,
    NUM_STAGES,
)

_log = logging.getLogger(__name__)

# Authorization tier type
AuthorizationTier = Literal["AUTONOMOUS", "HUMAN_REVIEW", "EMERGENCY_OVERRIDE"]

# CPCI thresholds
_AUTONOMOUS_CPCI_THRESHOLD:  float = 0.75
_REVIEW_CPCI_THRESHOLD:      float = 0.40
_AUTONOMOUS_SET_SIZE:        int   = 1
_REVIEW_MAX_SET_SIZE:        int   = 3

# Maximum belief entropy (log2 of NUM_STAGES)
_MAX_BELIEF_ENTROPY: float = math.log2(NUM_STAGES)  # ≈ 3.0 bits


class CalibratedPredictionConfidenceIndex:
    """
    AEGIS Contribution C11 — Calibrated Prediction Confidence Index.

    Provides a statistically rigorous, distribution-free confidence score
    for AEGIS's TTP predictions using Conformal Prediction theory.

    The CPCI score directly drives a 3-tier authorization framework:
      AUTONOMOUS        — system acts without human review
      HUMAN_REVIEW      — SOC analyst confirmation required
      EMERGENCY_OVERRIDE — revert to safest action (MONITOR)

    Parameters
    ----------
    alpha : float
        Conformal coverage level.  Default 0.05 → 95% coverage guarantee.
    auto_bootstrap : bool
        If True, automatically build a synthetic calibration set from
        MITRE ATT&CK stage-to-TTP emission patterns on first use.
        Default: True.
    """

    def __init__(
        self,
        alpha:          float = 0.05,
        auto_bootstrap: bool  = True,
    ) -> None:
        self._alpha          = alpha
        self._cal_scores:    list[float] = []
        self._quantile:      float       = 1.0 - alpha  # conservative default
        self._calibrated:    bool        = False

        # Metrics
        self._n_predictions:  int = 0
        self._n_autonomous:   int = 0
        self._n_review:       int = 0
        self._n_override:     int = 0

        if auto_bootstrap:
            self._bootstrap_from_mitre()

        _log.info(
            "CalibratedPredictionConfidenceIndex ready — α=%.2f calibrated=%s q̂=%.4f",
            alpha, self._calibrated, self._quantile,
        )

    # ------------------------------------------------------------------
    # Phase 1 — Calibration
    # ------------------------------------------------------------------

    def calibrate(
        self,
        probs_list:  list[dict[str, float]],
        true_labels: list[str],
    ) -> None:
        """
        Calibrate the conformal quantile from a held-out calibration set.

        Parameters
        ----------
        probs_list : list[dict[str, float]]
            Predicted TTP probability distributions: [{ttp_name: prob}, ...]
        true_labels : list[str]
            Corresponding true TTP names (ground truth).
        """
        if len(probs_list) != len(true_labels):
            raise ValueError("probs_list and true_labels must have equal length.")
        if not probs_list:
            _log.warning("CPCI calibration called with empty dataset — skipped.")
            return

        scores: list[float] = []
        for probs, true_ttp in zip(probs_list, true_labels):
            true_ttp_u = true_ttp.upper().strip()
            pi_true    = probs.get(true_ttp_u, 0.0)
            s          = 1.0 - pi_true  # nonconformity score
            scores.append(s)

        # Conformal quantile: ⌈(m+1)(1-α)⌉ / m
        m = len(scores)
        level = math.ceil((m + 1) * (1.0 - self._alpha)) / m
        level = min(1.0, level)
        self._quantile    = float(np.quantile(scores, level))
        self._cal_scores  = scores
        self._calibrated  = True

        _log.info(
            "CPCI calibrated: m=%d α=%.2f q̂=%.4f",
            m, self._alpha, self._quantile,
        )

    # ------------------------------------------------------------------
    # Phase 2 — Online Inference
    # ------------------------------------------------------------------

    def predict_set(self, probs: dict[str, float]) -> list[str]:
        """
        Compute the conformal prediction set for a given probability distribution.

        P_{1−α}(x) = { y ∈ A_A : π_A(y|x) ≥ 1 − q̂ }

        Parameters
        ----------
        probs : dict[str, float]
            TTP probability distribution {ttp_name: probability}.

        Returns
        -------
        list[str]
            Prediction set — guaranteed to contain the true TTP with
            probability ≥ 1−α (95% by default).  May be the full TTP
            space if the model is highly uncertain.
        """
        threshold = 1.0 - self._quantile

        pred_set = [
            ttp for ttp in TTP_NAMES
            if probs.get(ttp, probs.get(ttp.upper(), 0.0)) >= threshold
        ]

        # Safety: if prediction set is empty (very high quantile), include top-1
        if not pred_set:
            if probs:
                top_ttp = max(probs, key=probs.get)
                pred_set = [top_ttp.upper() if top_ttp.upper() in TTP_NAMES else top_ttp]
            else:
                pred_set = list(TTP_NAMES)  # full set — maximum uncertainty

        return pred_set

    def compute_cpci(
        self,
        prediction_set:  list[str],
        belief_entropy:  float,
    ) -> float:
        """
        Compute the CPCI score.

            CPCI = (1 − (|P| − 1)/|A_A|) · (1 − H(B^t)/log₂(K))

        Parameters
        ----------
        prediction_set : list[str]
            The conformal prediction set from predict_set().
        belief_entropy : float
            Shannon entropy (bits) of the current ASE belief state.
            Range: [0, log₂(K)] = [0, 3.0] for 8 kill-chain stages.

        Returns
        -------
        float
            CPCI ∈ [0.0, 1.0].  1.0 = maximum confidence.
        """
        # Set-size term: smaller set → higher confidence
        set_size    = len(prediction_set)
        set_factor  = 1.0 - (set_size - 1) / NUM_TTPS

        # Entropy term: lower belief entropy → higher confidence
        H_norm      = min(belief_entropy / _MAX_BELIEF_ENTROPY, 1.0)
        ent_factor  = 1.0 - H_norm

        cpci = set_factor * ent_factor
        return round(max(0.0, min(1.0, cpci)), 4)

    def get_authorization(
        self,
        cpci:          float,
        pred_set_size: int,
    ) -> AuthorizationTier:
        """
        Map CPCI score and prediction set size to an authorization tier.

        Tier logic:
          AUTONOMOUS        : CPCI ≥ 0.75  AND  |P| = 1
          HUMAN_REVIEW      : 0.40 ≤ CPCI < 0.75  OR  |P| ∈ {2, 3}
          EMERGENCY_OVERRIDE: CPCI < 0.40  OR  |P| > 3

        Parameters
        ----------
        cpci : float
            CPCI score from compute_cpci().
        pred_set_size : int
            Number of TTPs in the conformal prediction set.

        Returns
        -------
        AuthorizationTier
        """
        self._n_predictions += 1

        if cpci >= _AUTONOMOUS_CPCI_THRESHOLD and pred_set_size <= _AUTONOMOUS_SET_SIZE:
            self._n_autonomous += 1
            return "AUTONOMOUS"

        if cpci < _REVIEW_CPCI_THRESHOLD or pred_set_size > _REVIEW_MAX_SET_SIZE:
            self._n_override += 1
            return "EMERGENCY_OVERRIDE"

        self._n_review += 1
        return "HUMAN_REVIEW"

    def full_assessment(
        self,
        probs:          dict[str, float],
        belief_entropy: float,
    ) -> dict:
        """
        Run the full CPCI pipeline in a single call.

        Returns
        -------
        dict with keys: prediction_set, cpci, authorization, quantile.
        """
        pred_set  = self.predict_set(probs)
        cpci      = self.compute_cpci(pred_set, belief_entropy)
        auth      = self.get_authorization(cpci, len(pred_set))
        return {
            "prediction_set":  pred_set,
            "pred_set_size":   len(pred_set),
            "cpci":            cpci,
            "authorization":   auth,
            "quantile":        round(self._quantile, 4),
            "calibrated":      self._calibrated,
        }

    # ------------------------------------------------------------------
    # Bootstrap calibration from MITRE ATT&CK priors
    # ------------------------------------------------------------------

    def _bootstrap_from_mitre(self) -> None:
        """
        Build a synthetic calibration set from MITRE ATT&CK stage-TTP
        emission patterns.

        Each kill-chain stage "emits" TTPs with known likelihoods.
        We simulate 200 synthetic predictions and their true labels to
        produce an initial conformal quantile before any real traffic.

        This ensures the CPCI is usable from system startup without
        requiring a pre-collected labelled dataset.
        """
        from modules.predictive_ai.engine.AEGIS.core.constants import EMISSION_MODEL

        rng = np.random.default_rng(seed=42)

        # EMISSION_MODEL shape: (9 TTPs, 8 stages) — row=TTP, col=stage
        E = np.array(EMISSION_MODEL, dtype=np.float64)

        synthetic_probs:  list[dict[str, float]] = []
        synthetic_labels: list[str] = []

        n_synthetic = 300

        for _ in range(n_synthetic):
            # Sample a random stage
            stage_idx = rng.integers(0, NUM_STAGES)

            # True TTP is the most likely for this stage
            likelihoods = E[:, stage_idx]
            if likelihoods.sum() > 0:
                likelihoods = likelihoods / likelihoods.sum()

            true_ttp_idx = int(rng.choice(NUM_TTPS, p=likelihoods))
            true_ttp     = TTP_NAMES[true_ttp_idx]

            # Simulated AIS prediction: true TTP gets weight ∝ likelihood,
            # plus Dirichlet noise for diversity
            noisy_probs = rng.dirichlet(5.0 * likelihoods + 0.1)
            pred_dict   = {TTP_NAMES[i]: float(noisy_probs[i]) for i in range(NUM_TTPS)}

            synthetic_probs.append(pred_dict)
            synthetic_labels.append(true_ttp)

        self.calibrate(synthetic_probs, synthetic_labels)
        _log.info("CPCI: bootstrapped from %d synthetic MITRE scenarios.", n_synthetic)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return diagnostic statistics about CPCI operation."""
        total = max(1, self._n_predictions)
        return {
            "enabled":       True,
            "calibrated":    self._calibrated,
            "alpha":         self._alpha,
            "quantile":      round(self._quantile, 4),
            "n_cal_samples": len(self._cal_scores),
            "total_predictions": self._n_predictions,
            "autonomous_pct": round(100.0 * self._n_autonomous / total, 1),
            "review_pct":    round(100.0 * self._n_review    / total, 1),
            "override_pct":  round(100.0 * self._n_override  / total, 1),
        }
