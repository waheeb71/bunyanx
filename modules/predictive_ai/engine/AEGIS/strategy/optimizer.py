"""
bunyanx NGFW — AEGIS Engine: Counter-Strategy Optimizer (CSO)
=================================================================

Selects the Nash-optimal defender action against the full attacker TTP
distribution produced by the Adversarial Intent Simulator (AIS).

Objective (distribution-aware Minimax)
---------------------------------------

    π_D* = argmax_{a_D ∈ A_D}
              α · E[DisruptionScore(a_D, a_A)]   (disruption)
            − β · OperationalCost(a_D)            (ops cost)
            + γ · DeceptionValue(a_D)             (strategic shaping)
            − λ · EscalationRisk(a_D, Π_A)        (escalation penalty)

where E[·] is taken over the *full* attacker TTP distribution Π_A,
not just the most likely TTP.  This is a key design choice:

    ❌  "Block the most likely TTP" — myopic; fails if attacker pivots.
    ✅  "Minimise expected attacker utility across Π_A,
         penalising actions that alert the attacker (escalation)."

EscalationRisk(a_D, Π_A)
    = Σ_a  Π_A(a) · P(escalate | a_D, a) · danger_multiplier

    danger_multiplier  = 1 + Σ_{dangerous TTPs} Π_A(a)
    dangerous TTPs     = PRIV_ESC, LATERAL, DLP_EXFIL, RANSOMWARE

This means a BLOCK_IP action when the attacker distribution is heavy
on RANSOMWARE is penalised more than when they are in RECON.

Constraints (optional, applied per `optimize()` call)
------------------------------------------------------
* Operational risk budget: OperationalCost(a_D) ≤ budget
* Escalation cap:          EscalationRisk(a_D)   ≤ max_escalation
* Critical asset flag:     additional penalty on isolating/blocking

Research reference
------------------
    J. Nash, "Equilibrium Points in n-Person Games," PNAS 1950.
    D. Silver et al., "Mastering Chess and Shogi by Self-Play," arXiv 2017.
    AEGIS paper — bunyanx AI Division, April 2026, §3 Layer 4 (CSO).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import NamedTuple

import numpy as np

from modules.predictive_ai.engine.AEGIS.core.constants import (
    CSO_ALPHA,
    CSO_BETA,
    CSO_GAMMA,
    CSO_LAMBDA,
    DECEPTION_VALUE,
    DEFENDER_ACTIONS,
    DISRUPTION_MATRIX,
    ESCALATION_RISK,
    NUM_ACTIONS,
    NUM_TTPS,
    OPERATIONAL_COST,
    TTP_INDEX,
    TTP_NAMES,
)
from modules.predictive_ai.engine.AEGIS.intent.simulator import (
    TTPPrediction,
)


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pre-computed class-level numpy arrays (computed once at import time)
# ---------------------------------------------------------------------------

class _Matrices:
    """Namespace for pre-computed CSO matrices."""
    D = np.array(DISRUPTION_MATRIX, dtype=np.float64)   # (12, 9)
    C = np.array(OPERATIONAL_COST,  dtype=np.float64)   # (12,)
    G = np.array(DECEPTION_VALUE,   dtype=np.float64)   # (12,)
    E = np.array(ESCALATION_RISK,   dtype=np.float64)   # (12,)

    # Indices of "dangerous" TTPs (amplify escalation risk)
    _dangerous_ttp_names = {"PRIV_ESC", "LATERAL", "DLP_EXFIL", "RANSOMWARE"}
    DANGEROUS_TTP_INDICES: frozenset[int] = frozenset(
        TTP_INDEX[t] for t in _dangerous_ttp_names if t in TTP_INDEX
    )


# ---------------------------------------------------------------------------
# Output type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CounterStrategy:
    """
    The result of a single CSO optimisation call.

    Attributes
    ----------
    action : str
        Selected defender action name.
    action_idx : int
        Index of the action in DEFENDER_ACTIONS.
    net_value : float
        Raw optimisation score (higher = better).
    expected_disruption : float
        E[DisruptionScore] against the full TTP distribution.
    operational_cost : float
        Estimated operational cost of the action (0–1).
    escalation_risk : float
        Estimated probability the action triggers attacker escalation.
    deception_value : float
        Strategic shaping value of the action (0–1).
    ttp_distribution : tuple[TTPPrediction, ...]
        The attacker TTP distribution used for this decision.
    explanation : str
        Human-readable, ATT&CK-attributed explanation for the action.
    """

    action:               str
    action_idx:           int
    net_value:            float
    expected_disruption:  float
    operational_cost:     float
    escalation_risk:      float
    deception_value:      float
    ttp_distribution:     tuple[TTPPrediction, ...]
    explanation:          str

    def to_dict(self) -> dict:
        return {
            "action":              self.action,
            "action_idx":          self.action_idx,
            "net_value":           round(self.net_value, 4),
            "expected_disruption": round(self.expected_disruption, 4),
            "operational_cost":    round(self.operational_cost, 4),
            "escalation_risk":     round(self.escalation_risk, 4),
            "deception_value":     round(self.deception_value, 4),
            "explanation":         self.explanation,
            "top_predicted_ttps":  [
                {"ttp": p.ttp, "probability": round(p.probability, 4)}
                for p in self.ttp_distribution[:3]
            ],
        }


# ---------------------------------------------------------------------------
# CounterStrategyOptimizer
# ---------------------------------------------------------------------------

class CounterStrategyOptimizer:
    """
    Counter-Strategy Optimiser with EscalationRisk penalty.

    Selects the defender action that maximises:
        α·DisruptionScore − β·OpsCost + γ·DeceptionValue − λ·EscalationRisk

    evaluated over the *full* attacker TTP distribution Π_A.

    Solver Method
    -------------
    Exhaustive enumeration (brute-force argmax) over all |A_D|=12 defender
    actions.  Because the action space is finite and small, this is
    computationally equivalent to the *exact* solution of the formulated
    single-defender optimization problem — no approximation, sampling, or
    heuristic is introduced at the solver level.

    The term "Nash-optimal" in the paper refers to the defender's best
    response against the predicted attacker distribution Π_A (a Nash
    equilibrium concept in the single-shot two-player setting where the
    attacker's mixed strategy is taken as given from the AIS prediction).

    Parameters
    ----------
    alpha, beta, gamma, lam : float
        Objective function weights (default from _constants.py).
        Must satisfy alpha + beta + gamma + lam > 0.
    """

    SOLVER_METHOD = "exhaustive_argmax"  # exact for |A_D|=12

    def __init__(
        self,
        alpha: float  = CSO_ALPHA,
        beta:  float  = CSO_BETA,
        gamma: float  = CSO_GAMMA,
        lam:   float  = CSO_LAMBDA,
    ) -> None:
        if not all(w >= 0 for w in (alpha, beta, gamma, lam)):
            raise ValueError("All CSO weights must be non-negative.")

        self.alpha = alpha
        self.beta  = beta
        self.gamma = gamma
        self.lam   = lam

        _log.info(
            "CounterStrategyOptimizer ready — "
            "α=%.2f β=%.2f γ=%.2f λ=%.2f",
            alpha, beta, gamma, lam,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def optimize(
        self,
        ttp_distribution: list[TTPPrediction],
        *,
        is_critical_asset: bool = False,
        operational_budget: float = 1.0,
        max_escalation: float = 1.0,
        tpe_score: float = 0.0,
        attention_explanation: dict = None,
    ) -> CounterStrategy:
        """
        Find the optimal defender action against the attacker TTP distribution.

        Parameters
        ----------
        ttp_distribution : list[TTPPrediction]
            Full attacker TTP probability distribution from AIS.
            Must be non-empty.
        is_critical_asset : bool
            If True, applies heavy penalty to ISOLATE_FULL, BLOCK_IP,
            and EMERGENCY_ISOLATE to protect service availability.
        operational_budget : float
            Maximum allowed operational cost (0–1).  Actions exceeding
            this budget are excluded from consideration.
        max_escalation : float
            Maximum allowed escalation risk (0–1).  Actions exceeding
            this cap are excluded from consideration.

        Returns
        -------
        CounterStrategy
            Fully populated strategy object including explanation.
        """
        if not ttp_distribution:
            raise ValueError("ttp_distribution must contain at least one entry.")

        # -- Build normalised TTP probability vector (9,) -----------------
        ttp_probs = self._build_ttp_vector(ttp_distribution)

        # -- Expected disruption score per defender action (12,) ----------
        # E[Disruption(a_D)] = D @ ttp_probs       shape (12,)
        expected_disruption = _Matrices.D @ ttp_probs

        # -- Danger multiplier for escalation risk ------------------------
        # More dangerous TTP distribution → escalation of any overt action
        # is more consequential.
        danger_mass = sum(
            ttp_probs[i] for i in _Matrices.DANGEROUS_TTP_INDICES
        )
        danger_multiplier = 1.0 + danger_mass
        escalation = _Matrices.E * danger_multiplier    # shape (12,)

        # -- Operational cost (with critical asset adjustments) -----------
        cost = _Matrices.C.copy()
        if is_critical_asset:
            cost[6]  += 0.50    # ISOLATE_FULL
            cost[10] += 0.40    # BLOCK_IP
            cost[11] += 0.80    # EMERGENCY_ISOLATE

        # -- tpe_score-aware lambda scaling --------------------------------
        # When TPE pre-arm score is high, the attacker is already in a
        # dangerous posture → amplify the escalation penalty so we prefer
        # covert responses (HONEYPOT, DECOY) over overt ones (BLOCK_IP).
        # λ_effective = λ · (1 + 0.5 · tpe_score)
        lam_effective = self.lam * (1.0 + 0.5 * max(0.0, min(1.0, tpe_score)))

        # -- Full objective function ---------------------------------------
        net_values = (
              self.alpha * expected_disruption
            - self.beta  * cost
            + self.gamma * _Matrices.G
            - lam_effective * escalation
        )

        # -- Apply hard constraints (mask out infeasible actions) ---------
        feasible_mask = (cost <= operational_budget) & (escalation <= max_escalation)
        if not feasible_mask.any():
            _log.warning(
                "CSO: no feasible action within budget=%.2f / max_esc=%.2f "
                "— relaxing constraints to single safest option",
                operational_budget, max_escalation,
            )
            # Fallback: lowest escalation action (MONITOR or ALERT_ONLY)
            best_idx = int(np.argmin(escalation))
        else:
            masked_values = np.where(feasible_mask, net_values, -np.inf)
            best_idx = int(np.argmax(masked_values))

        best_action = DEFENDER_ACTIONS[best_idx]

        # -- Build explanation --------------------------------------------
        explanation = self._build_explanation(
            best_action,
            ttp_distribution[:3],
            expected_disruption[best_idx],
            escalation[best_idx],
            net_values[best_idx],
        )

        strategy = CounterStrategy(
            action=best_action,
            action_idx=best_idx,
            net_value=float(net_values[best_idx]),
            expected_disruption=float(expected_disruption[best_idx]),
            operational_cost=float(cost[best_idx]),
            escalation_risk=float(escalation[best_idx]),
            deception_value=float(_Matrices.G[best_idx]),
            ttp_distribution=tuple(ttp_distribution),
            explanation=explanation,
        )

        _log.info(
            "CSO decision: action=%s  disruption=%.3f  escalation=%.3f  "
            "net=%.3f  [top_ttp=%s p=%.2f]",
            best_action,
            strategy.expected_disruption,
            strategy.escalation_risk,
            strategy.net_value,
            ttp_distribution[0].ttp,
            ttp_distribution[0].probability,
        )

        return strategy

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_ttp_vector(distribution: list[TTPPrediction]) -> np.ndarray:
        """
        Convert a list of TTPPrediction into a normalised numpy vector
        aligned with TTP_NAMES ordering.
        """
        vec = np.zeros(NUM_TTPS, dtype=np.float64)
        for pred in distribution:
            idx = TTP_INDEX.get(pred.ttp.upper())
            if idx is not None:
                vec[idx] = pred.probability
        total = vec.sum()
        if total > 1e-10:
            vec /= total
        else:
            vec = np.full(NUM_TTPS, 1.0 / NUM_TTPS)
        return vec

    @staticmethod
    def _build_explanation(
        action: str,
        top_ttps: list[TTPPrediction],
        disruption: float,
        escalation: float,
        net_value: float,
    ) -> str:
        ttp_summary = ", ".join(
            f"{p.ttp}({p.probability:.0%})" for p in top_ttps
        )
        return (
            f"AEGIS → {action} | "
            f"Predicted TTPs: [{ttp_summary}] | "
            f"E[Disruption]={disruption:.3f}  "
            f"EscalationRisk={escalation:.3f}  "
            f"NetValue={net_value:.3f}"
        )
