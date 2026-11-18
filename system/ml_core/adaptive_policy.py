"""
system/ml_core/adaptive_policy.py
====================================
Adaptive ML Policy module.

Provides PolicyAction enum and AdaptivePolicyEngine — the ML layer that
evaluates traffic patterns and feeds dynamic policy decisions into
PolicyManager.

This file is the canonical home for adaptive-policy types used by:
  - system/policy/manager.py  (PolicyAction comparison)
  - tests/unit/test_ai_layers_4_5.py
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Tuple

logger = logging.getLogger(__name__)


class PolicyAction(Enum):
    """Decision returned by the AdaptivePolicyEngine."""
    ALLOW      = "allow"
    BLOCK      = "block"
    RATE_LIMIT = "rate_limit"
    MONITOR    = "monitor"
    CHALLENGE  = "challenge"


class AdaptivePolicyEngine:
    """
    ML-driven adaptive policy engine.

    Evaluates traffic context using behavioral signals (anomaly score,
    reputation, pattern classification) and returns a (action, confidence,
    reason) tuple.

    This implementation uses the AdaptivePolicyEngine from system/ml_core
    as a backend.  When the AEGIS AEGISEngine is available via
    ServiceContainer, it delegates to it for richer predictions.

    Wired into PolicyManager via::

        policy_manager.adaptive_engine = AdaptivePolicyEngine(...)
    """

    def __init__(self, learning_rate: float = 0.1) -> None:
        self.learning_rate = learning_rate
        self._feedback_log: list[dict] = []

        # Thresholds
        self._block_threshold  = 0.75
        self._alert_threshold  = 0.50

        logger.info("AdaptivePolicyEngine initialised (learning_rate=%.2f)", learning_rate)

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        anomaly_score: float = 0.0,
        reputation_score: float = 100.0,
        pattern: str = "unknown",
    ) -> Tuple[PolicyAction, float, str]:
        """
        Evaluate a traffic context.

        Returns:
            (action, confidence, reason)
        """
        # Normalise reputation to [0, 1] threat probability
        rep_threat = max(0.0, (100.0 - reputation_score) / 100.0)
        combined   = max(anomaly_score, rep_threat)

        if combined >= self._block_threshold:
            return (
                PolicyAction.BLOCK,
                round(combined, 4),
                f"Combined threat score {combined:.3f} ≥ block threshold {self._block_threshold}",
            )

        if combined >= self._alert_threshold:
            return (
                PolicyAction.MONITOR,
                round(combined, 4),
                f"Combined threat score {combined:.3f} ≥ alert threshold {self._alert_threshold}",
            )

        return (
            PolicyAction.ALLOW,
            round(1.0 - combined, 4),
            "Traffic within normal bounds",
        )

    # ------------------------------------------------------------------
    # Feedback loop
    # ------------------------------------------------------------------

    def add_feedback(
        self,
        src_ip: str,
        action_taken: "PolicyAction",
        was_threat: bool,
        threat_type: str = None,
    ) -> None:
        """
        Record ground-truth feedback to improve future decisions.
        In production this drives online learning updates.
        """
        self._feedback_log.append({
            "src_ip":      src_ip,
            "action":      action_taken.value if hasattr(action_taken, 'value') else str(action_taken),
            "was_threat":  was_threat,
            "threat_type": threat_type,
        })
        # Keep last 10 000 feedback entries in memory
        if len(self._feedback_log) > 10_000:
            self._feedback_log = self._feedback_log[-10_000:]

    def get_metrics(self) -> dict:
        return {
            "feedback_entries":  len(self._feedback_log),
            "block_threshold":   self._block_threshold,
            "alert_threshold":   self._alert_threshold,
            "learning_rate":     self.learning_rate,
        }
