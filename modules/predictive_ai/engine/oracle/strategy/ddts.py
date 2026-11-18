"""
bunyanx NGFW — AEGIS : Defensive Digital Twin Simulator (DDTS)
==================================================================

AEGIS Contribution C10

Problem Addressed
-----------------
The CSO selects the Nash-optimal action in a single-shot game against the
*current* TTP distribution.  However, security decisions have temporal
consequences — deploying HONEYPOT_REDIRECT now may expose the honeypot
in 2 time steps if the attacker escalates to LATERAL movement, rendering
the deception ineffective.

DDTS evaluates each candidate defender action through N=50 stochastic
k-step rollouts before committing.  This transforms the single-shot CSO
decision into a *k-step lookahead* commitment that is statistically robust.

Algorithm
---------
For each candidate action a_D ∈ A_D:

  1. Sample N i.i.d. trajectories {τᵢ}_{i=1}^N:
       For each step τ = 0, 1, ..., k−1:
         a. Sample attacker TTP: a_A^(τ) ~ Categorical(Π_A)
            (with Dirichlet noise for diversity: Π_A' = Dirichlet(α·Π_A, 100))
         b. Compute reward: r^(τ) = α·D[a_D, a_A^(τ)] − β·C[a_D] − λ·E[a_D]
         c. Evolve attacker distribution via MITRE transition kernel

  2. Compute discounted return per trajectory:
       G_i = Σ_{τ=0}^{k-1} γ^τ · r_i^(τ)

  3. Compute mean and 95% CI:
       μ(a_D) = (1/N) Σᵢ Gᵢ
       CI_95   = [μ − 1.96·σ/√N,  μ + 1.96·σ/√N]

  4. Commit decision:
       Commit to a_D* if CI_lower(a_D*) > CI_upper(a_D_{2nd})
       Otherwise: fallback to CSO Nash-optimal recommendation.

Research Basis
--------------
  * Sutton, R. & Barto, A., "Reinforcement Learning: An Introduction," MIT 2018.
  * Silver, D. et al., "Mastering the game of Go with deep RL," Nature 2016.
  * Shoham, Y. & Leyton-Brown, K., "Multiagent Systems," Cambridge 2009.
  * AEGIS paper — bunyanx AI Division, April 2026, §IV.C Contribution C10.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    DEFENDER_ACTIONS,
    NUM_ACTIONS,
    NUM_TTPS,
    TTP_INDEX,
    DISRUPTION_MATRIX,
    OPERATIONAL_COST,
    ESCALATION_RISK,
    DECEPTION_VALUE,
    TRANSITION_MODEL,
    NUM_STAGES,
    STAGE_INDEX,
    KILL_CHAIN_STAGES,
)

_log = logging.getLogger(__name__)

# Pre-computed matrices (class-level, loaded once at import)
_D = np.array(DISRUPTION_MATRIX,  dtype=np.float64)  # (12, 9)
_C = np.array(OPERATIONAL_COST,   dtype=np.float64)  # (12,)
_E_risk = np.array(ESCALATION_RISK, dtype=np.float64)  # (12,)
_G = np.array(DECEPTION_VALUE,    dtype=np.float64)  # (12,)
_T = np.array(TRANSITION_MODEL,   dtype=np.float64)  # (8, 8) P(s'|s)

# Default MITRE emission mapping: P(ttp_idx is active | stage_idx)
# Used to evolve TTP distribution over stages during rollout
# Simplified: each stage amplifies 2-3 "most characteristic" TTPs
_STAGE_TTP_AMPLIFICATION: np.ndarray = np.array([
    # SCAN  WAF   MAL   DGA   PRIV  LAT   EXFIL RANSOM PERS
    [0.9,   0.1,  0.05, 0.05, 0.02, 0.02, 0.02, 0.02, 0.02],  # RECON
    [0.05,  0.7,  0.15, 0.10, 0.10, 0.05, 0.02, 0.02, 0.10],  # INIT_ACCESS
    [0.02,  0.10, 0.65, 0.40, 0.25, 0.10, 0.05, 0.10, 0.35],  # EXECUTION
    [0.02,  0.05, 0.20, 0.30, 0.25, 0.20, 0.08, 0.05, 0.70],  # PERSISTENCE
    [0.01,  0.03, 0.10, 0.15, 0.70, 0.35, 0.10, 0.10, 0.20],  # PRIV_ESC
    [0.01,  0.02, 0.05, 0.25, 0.15, 0.75, 0.25, 0.15, 0.15],  # LATERAL
    [0.01,  0.02, 0.03, 0.10, 0.05, 0.10, 0.75, 0.35, 0.10],  # COLLECTION
    [0.01,  0.01, 0.03, 0.05, 0.03, 0.05, 0.90, 0.85, 0.05],  # EXFILTRATION
], dtype=np.float64)


class DefensiveDigitalTwinSimulator:
    """
    AEGIS Contribution C10 — Defensive Digital Twin Simulator.

    Validates CSO decisions through N stochastic k-step rollouts before
    committing.  Acts as a "sanity check" layer between the single-shot Nash
    optimizer and the final action commitment.

    Parameters
    ----------
    n_trajectories : int
        Number of Monte Carlo rollout trajectories per action.  Default: 50.
    k_steps : int
        Number of lookahead steps per trajectory.  Default: 3.
    gamma : float
        Discount factor for multi-step returns.  Default: 0.90.
    alpha : float
        Disruption weight in the reward function (mirrors CSO).  Default: 0.55.
    beta : float
        Operational cost weight.  Default: 0.20.
    lam : float
        Escalation risk penalty weight.  Default: 0.10.
    dirichlet_alpha_scale : float
        Dirichlet noise concentration for trajectory diversity.
        Higher = less noise.  Default: 10.0.
    require_ci_dominance : bool
        If True, commit DDTS choice only when CI_lower > CI_upper of runner-up.
        If False, always commit DDTS argmax.  Default: True.
    """

    def __init__(
        self,
        n_trajectories:      int   = 50,
        k_steps:             int   = 3,
        gamma:               float = 0.90,
        alpha:               float = 0.55,
        beta:                float = 0.20,
        lam:                 float = 0.10,
        dirichlet_alpha_scale: float = 10.0,
        require_ci_dominance: bool  = True,
    ) -> None:
        self._N       = n_trajectories
        self._K       = k_steps
        self._gamma   = gamma
        self._alpha   = alpha
        self._beta    = beta
        self._lam     = lam
        self._dir_scale = dirichlet_alpha_scale
        self._require_ci_dominance = require_ci_dominance

        # Runtime counters
        self._total_calls:     int = 0
        self._ci_commits:      int = 0
        self._fallback_count:  int = 0

        _log.info(
            "DefensiveDigitalTwinSimulator ready — "
            "N=%d k=%d γ=%.2f ci_dominance=%s",
            n_trajectories, k_steps, gamma, require_ci_dominance,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        nash_best_idx:      int,
        ttp_probs:          np.ndarray,
        current_stage_idx:  int = 0,
    ) -> tuple[int, dict]:
        """
        Evaluate candidate defender actions via Monte Carlo rollouts.

        Parameters
        ----------
        nash_best_idx : int
            The action index recommended by CSO (Nash-optimal baseline).
        ttp_probs : np.ndarray, shape (9,)
            Normalised TTP probability vector from AIS.
        current_stage_idx : int
            Current attacker kill-chain stage index (0–7).

        Returns
        -------
        tuple[int, dict]
            (committed_action_idx, evaluation_report)
              - committed_action_idx: final committed action (may differ from nash)
              - evaluation_report: statistics for logging/API response
        """
        self._total_calls += 1

        # Normalise TTP probs defensively
        ttp_probs = np.asarray(ttp_probs, dtype=np.float64)
        total = ttp_probs.sum()
        if total > 1e-10:
            ttp_probs = ttp_probs / total
        else:
            ttp_probs = np.ones(NUM_TTPS, dtype=np.float64) / NUM_TTPS

        # Evaluate all 12 actions
        means    = np.zeros(NUM_ACTIONS, dtype=np.float64)
        lowers   = np.zeros(NUM_ACTIONS, dtype=np.float64)
        uppers   = np.zeros(NUM_ACTIONS, dtype=np.float64)

        for a_idx in range(NUM_ACTIONS):
            scores = self._rollout_action(a_idx, ttp_probs, current_stage_idx)
            mu = scores.mean()
            ci_lo, ci_hi = self._confidence_interval_95(scores)
            means[a_idx]  = mu
            lowers[a_idx] = ci_lo
            uppers[a_idx] = ci_hi

        # Rank actions by mean return
        ranked_indices = np.argsort(means)[::-1]  # descending
        ddts_best_idx  = int(ranked_indices[0])
        runner_up_idx  = int(ranked_indices[1]) if NUM_ACTIONS > 1 else ddts_best_idx

        # Commit decision logic
        ci_dominant = bool(lowers[ddts_best_idx] > uppers[runner_up_idx])

        if self._require_ci_dominance and not ci_dominant:
            # Ambiguous — fallback to CSO Nash recommendation
            committed = nash_best_idx
            self._fallback_count += 1
            decision_source = "CSO_fallback"
        else:
            committed = ddts_best_idx
            self._ci_commits += 1
            decision_source = "DDTS_commit"

        report = {
            "decision_source":   decision_source,
            "committed_action":  DEFENDER_ACTIONS[committed],
            "nash_action":       DEFENDER_ACTIONS[nash_best_idx],
            "ddts_action":       DEFENDER_ACTIONS[ddts_best_idx],
            "ddts_mean":         round(float(means[ddts_best_idx]), 4),
            "ddts_ci_lower":     round(float(lowers[ddts_best_idx]), 4),
            "ddts_ci_upper":     round(float(uppers[ddts_best_idx]), 4),
            "runner_up_action":  DEFENDER_ACTIONS[runner_up_idx],
            "runner_up_ci_upper": round(float(uppers[runner_up_idx]), 4),
            "ci_dominance":      ci_dominant,
            "n_trajectories":    self._N,
            "k_steps":           self._K,
        }

        _log.info(
            "DDTS: %s → %s (μ=%.3f CI=[%.3f,%.3f]) [nash=%s]",
            decision_source,
            DEFENDER_ACTIONS[committed],
            means[committed],
            lowers[committed],
            uppers[committed],
            DEFENDER_ACTIONS[nash_best_idx],
        )

        return committed, report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _rollout_action(
        self,
        action_idx:        int,
        base_ttp_probs:    np.ndarray,
        current_stage_idx: int,
    ) -> np.ndarray:
        """
        Run N trajectories for a single defender action.

        Returns
        -------
        np.ndarray, shape (N,)
            Discounted cumulative return per trajectory.
        """
        returns = np.zeros(self._N, dtype=np.float64)

        for i in range(self._N):
            # Add Dirichlet noise for trajectory diversity
            alpha_vec = self._dir_scale * base_ttp_probs + 0.01
            ttp_probs = np.random.dirichlet(alpha_vec)

            stage_idx = current_stage_idx
            cumulative_return = 0.0

            for step in range(self._K):
                # Sample attacker TTP from current distribution
                a_A_idx = np.random.choice(NUM_TTPS, p=ttp_probs)

                # Compute per-step reward
                disruption = _D[action_idx, a_A_idx]
                cost       = _C[action_idx]
                esc_risk   = _E_risk[action_idx]
                reward     = (
                    self._alpha * disruption
                    - self._beta  * cost
                    - self._lam   * esc_risk
                )

                cumulative_return += (self._gamma ** step) * reward

                # Evolve attacker stage using MITRE transition
                stage_probs = _T[stage_idx]
                stage_idx   = int(np.random.choice(NUM_STAGES, p=stage_probs))

                # Update TTP distribution based on new stage
                stage_ttp_amp = _STAGE_TTP_AMPLIFICATION[stage_idx]
                new_probs     = ttp_probs * stage_ttp_amp
                total         = new_probs.sum()
                if total > 1e-10:
                    ttp_probs = new_probs / total
                # else: keep previous probs

            returns[i] = cumulative_return

        return returns

    @staticmethod
    def _confidence_interval_95(scores: np.ndarray) -> tuple[float, float]:
        """
        Compute 95% confidence interval using t-approximation.

        Returns
        -------
        tuple[float, float]
            (lower, upper) bounds of the 95% CI.
        """
        n    = len(scores)
        mu   = float(scores.mean())
        std  = float(scores.std(ddof=1)) if n > 1 else 0.0
        se   = std / (n ** 0.5) if n > 0 else 0.0
        margin = 1.96 * se  # z = 1.96 for 95% CI (large N approximation)
        return mu - margin, mu + margin

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return cumulative statistics about DDTS operation."""
        total = max(1, self._total_calls)
        return {
            "n_trajectories":    self._N,
            "k_steps":           self._K,
            "gamma":             self._gamma,
            "total_calls":       self._total_calls,
            "ci_commits":        self._ci_commits,
            "cso_fallbacks":     self._fallback_count,
            "commit_rate_pct":   round(100.0 * self._ci_commits / total, 1),
            "fallback_rate_pct": round(100.0 * self._fallback_count / total, 1),
        }
