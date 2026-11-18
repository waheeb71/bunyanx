"""
bunyanx NGFW — AEGIS Engine: UEBA Verification Gate
========================================================

Second-pass behavioral verification layer that intercepts high-risk
defensive actions BEFORE execution to reduce false positive rates.

Problem Solved
--------------
The AEGIS framework's CSO + DIE pipeline achieves 90.9% disruption
precision, but suffers a 20% False Isolation Rate (1/5 benign enterprise
scenarios incorrectly disrupted). The root cause: a large scheduled
backup transfer (500GB over SMB) was semantically indistinguishable from
data exfiltration at the L4-L7 metadata level.

Solution: UEBA Verification Gate
---------------------------------
Inserted between CSO and DIE, this gate performs a multi-modal behavioral
check whenever the CSO selects an action with BaseRisk >= 0.35 (i.e., a
disruptive action). It evaluates the traffic against the user/entity's
historical behavioral baseline and returns one of three verdicts:

    CONFIRM   — anomaly confirmed; proceed with defensive action
    OVERRIDE  — false positive detected; downgrade to MONITOR
    ESCALATE  — anomaly confirmed AND behavioral red flags; increase severity

Decision Logic (Thresholds)
---------------------------
    anomaly_score < 0.25  →  OVERRIDE (very normal behavior)
    anomaly_score < 0.55  →  further checks required:
        - is_scheduled_match=True  →  OVERRIDE
        - entity_type=SERVER_BACKUP →  OVERRIDE
        - otherwise               →  CONFIRM (borderline, err on safe side)
    anomaly_score >= 0.55 →  CONFIRM (clearly anomalous)
    anomaly_score >= 0.85 →  ESCALATE (extreme deviation)

Integration Point
-----------------
    AEGIS_engine.py:  process_event()
        ...
        CSO decision
        ↓
        UEBA gate (if BaseRisk >= 0.35)
        ↓
        DIE execution

Research Reference
------------------
    AEGIS Paper — §IV.B Layer 4.5 (UEBA Verification Gate)
    Target: Reduce FPR from 20% to < 5%
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from modules.predictive_ai.engine.AEGIS.ueba.profile import (
    AnomalyResult,
    AnomalyScorer,
    BaselineBuilder,
    EntityType,
    SessionRecord,
    UserBaseline,
)
from modules.predictive_ai.engine.AEGIS.strategy.optimizer import (
    CounterStrategy,
)
from modules.predictive_ai.engine.AEGIS.core.constants import (
    ESCALATION_RISK,
    DEFENDER_ACTIONS,
)


# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# UEBA Decision Verdicts
# ---------------------------------------------------------------------------

class UEBAVerdict(Enum):
    """Possible outcomes of the UEBA verification gate."""
    CONFIRM  = "confirm"    # Anomaly confirmed → proceed with CSO action
    OVERRIDE = "override"   # False positive → downgrade to MONITOR
    ESCALATE = "escalate"   # Extreme anomaly → upgrade severity


# ---------------------------------------------------------------------------
# UEBA Decision Result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UEBADecision:
    """
    Result of a UEBA verification check.

    Attributes
    ----------
    verdict : UEBAVerdict
        The verification outcome.
    original_action : str
        The CSO-selected defender action before UEBA check.
    final_action : str
        The action to actually execute (may be changed by OVERRIDE).
    anomaly_result : AnomalyResult | None
        Detailed anomaly scoring breakdown (None if no baseline exists).
    reason : str
        Human-readable explanation of the UEBA decision.
    entity_type : EntityType
        Detected entity type.
    had_baseline : bool
        True if a historical baseline existed for this entity.
    """

    verdict:         UEBAVerdict
    original_action: str
    final_action:    str
    anomaly_result:  Optional[AnomalyResult]
    reason:          str
    entity_type:     EntityType
    had_baseline:    bool

    def to_dict(self) -> dict:
        return {
            "verdict":         self.verdict.value,
            "original_action": self.original_action,
            "final_action":    self.final_action,
            "anomaly_result":  self.anomaly_result.to_dict() if self.anomaly_result else None,
            "reason":          self.reason,
            "entity_type":     self.entity_type.value,
            "had_baseline":    self.had_baseline,
        }


# ---------------------------------------------------------------------------
# UEBAVerifier — Main UEBA Gate
# ---------------------------------------------------------------------------

class UEBAVerifier:
    """
    UEBA Multi-modal Verification Gate for AEGIS false positive reduction.

    Architecture
    ------------
    The verifier maintains an internal BaselineBuilder and a library of
    pre-built baselines per entity IP. When the CSO selects a disruptive
    action, the verifier:

      1. Looks up the source entity's baseline.
      2. Runs multi-dimensional anomaly scoring.
      3. Returns CONFIRM / OVERRIDE / ESCALATE.

    If no baseline exists for an entity, the verifier defaults to CONFIRM
    (fail-open for security: don't suppress a legitimate alert just because
    we lack behavioral history).

    Parameters
    ----------
    base_risk_threshold : float
        Minimum BaseRisk of the CSO action to trigger UEBA check.
        Actions below this threshold bypass UEBA entirely.
        Default: 0.35 (ISOLATE_PARTIAL and above).
    override_threshold : float
        Maximum anomaly score for OVERRIDE verdict.
        Default: 0.25.
    escalate_threshold : float
        Minimum anomaly score for ESCALATE verdict.
        Default: 0.85.
    confirm_threshold : float
        Anomaly score above which CONFIRM is issued without further checks.
        Default: 0.55.
    """

    def __init__(
        self,
        base_risk_threshold:  float = 0.35,
        override_threshold:   float = 0.25,
        escalate_threshold:   float = 0.85,
        confirm_threshold:    float = 0.55,
    ) -> None:
        self._base_risk_threshold = base_risk_threshold
        self._override_threshold  = override_threshold
        self._escalate_threshold  = escalate_threshold
        self._confirm_threshold   = confirm_threshold

        # Internal components
        self._scorer   = AnomalyScorer()
        self._builder  = BaselineBuilder()
        self._baselines: dict[str, UserBaseline] = {}

        # Metrics
        self._total_checks    = 0
        self._override_count  = 0
        self._confirm_count   = 0
        self._escalate_count  = 0
        self._bypass_count    = 0   # actions below base_risk_threshold

        _log.info(
            "UEBAVerifier initialized | base_risk_thresh=%.2f | "
            "override_thresh=%.2f | escalate_thresh=%.2f",
            base_risk_threshold,
            override_threshold,
            escalate_threshold,
        )

    # ------------------------------------------------------------------
    # Baseline Management
    # ------------------------------------------------------------------

    def register_baseline(self, baseline: UserBaseline) -> None:
        """Register a pre-built baseline for an entity."""
        self._baselines[baseline.entity_ip] = baseline
        _log.info(
            "UEBA: registered baseline for ip=%s (type=%s, sessions=%d)",
            baseline.entity_ip,
            baseline.entity_type.value,
            baseline.session_count,
        )

    def build_baseline_from_sessions(
        self,
        entity_ip: str,
        sessions: list[SessionRecord],
    ) -> Optional[UserBaseline]:
        """
        Build and register a baseline from historical session records.

        Returns the built baseline, or None if insufficient data.
        """
        self._builder.add_sessions(sessions)
        baseline = self._builder.build(entity_ip)
        if baseline:
            self._baselines[entity_ip] = baseline
        return baseline

    def get_baseline(self, entity_ip: str) -> Optional[UserBaseline]:
        """Look up the stored baseline for an entity."""
        return self._baselines.get(entity_ip)

    # ------------------------------------------------------------------
    # Main Verification API
    # ------------------------------------------------------------------

    def verify(
        self,
        counter_strategy: CounterStrategy,
        src_ip:           str,
        bytes_transferred: int    = 0,
        hour_of_day:      int     = -1,
        day_of_week:      int     = -1,
        dst_ip:           str     = "",
        protocol:         str     = "",
    ) -> UEBADecision:
        """
        Perform UEBA verification on a CSO decision.

        Parameters
        ----------
        counter_strategy : CounterStrategy
            The CSO-selected defender action.
        src_ip : str
            Source IP of the entity being evaluated.
        bytes_transferred : int
            Bytes moved in the current session (for volume analysis).
        hour_of_day : int
            Hour of day (0–23). Auto-detected from current time if -1.
        day_of_week : int
            Day of week (0=Mon, 6=Sun). Auto-detected if -1.
        dst_ip : str
            Destination IP of the current traffic.
        protocol : str
            Protocol used (SMB, HTTPS, etc.).

        Returns
        -------
        UEBADecision
            Verification result with verdict and explanation.
        """
        action = counter_strategy.action
        action_idx = counter_strategy.action_idx

        # Auto-detect time if not provided
        if hour_of_day < 0 or day_of_week < 0:
            now = time.localtime()
            if hour_of_day < 0:
                hour_of_day = now.tm_hour
            if day_of_week < 0:
                day_of_week = now.tm_wday

        # ── Gate: Only check if action is disruptive enough ───────────
        base_risk = ESCALATION_RISK[action_idx] if action_idx < len(ESCALATION_RISK) else 0.0
        if base_risk < self._base_risk_threshold:
            self._bypass_count += 1
            return UEBADecision(
                verdict=UEBAVerdict.CONFIRM,
                original_action=action,
                final_action=action,
                anomaly_result=None,
                reason=f"UEBA bypass: action={action} BaseRisk={base_risk:.2f} "
                       f"< threshold={self._base_risk_threshold:.2f}",
                entity_type=EntityType.UNKNOWN,
                had_baseline=False,
            )

        self._total_checks += 1

        # ── Look up entity baseline ───────────────────────────────────
        baseline = self._baselines.get(src_ip)

        if baseline is None:
            # No baseline → CONFIRM (fail-open for security)
            self._confirm_count += 1
            return UEBADecision(
                verdict=UEBAVerdict.CONFIRM,
                original_action=action,
                final_action=action,
                anomaly_result=None,
                reason=f"UEBA: no baseline for ip={src_ip} — fail-open CONFIRM",
                entity_type=EntityType.UNKNOWN,
                had_baseline=False,
            )

        # ── Run anomaly scoring ───────────────────────────────────────
        anomaly = self._scorer.score(
            baseline=baseline,
            bytes_transferred=bytes_transferred,
            hour_of_day=hour_of_day,
            day_of_week=day_of_week,
            dst_ip=dst_ip,
            protocol=protocol,
        )

        # ── Decision logic ────────────────────────────────────────────
        verdict, final_action, reason = self._decide(
            action=action,
            anomaly=anomaly,
            baseline=baseline,
        )

        if verdict == UEBAVerdict.OVERRIDE:
            self._override_count += 1
        elif verdict == UEBAVerdict.ESCALATE:
            self._escalate_count += 1
        else:
            self._confirm_count += 1

        decision = UEBADecision(
            verdict=verdict,
            original_action=action,
            final_action=final_action,
            anomaly_result=anomaly,
            reason=reason,
            entity_type=baseline.entity_type,
            had_baseline=True,
        )

        _log.info(
            "UEBA: ip=%s action=%s → verdict=%s (anomaly=%.3f, type=%s) "
            "| %s",
            src_ip, action, verdict.value, anomaly.composite_score,
            baseline.entity_type.value, reason,
        )

        return decision

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return diagnostic metrics for the /health endpoint."""
        total = self._total_checks
        return {
            "total_checks":     total,
            "override_count":   self._override_count,
            "confirm_count":    self._confirm_count,
            "escalate_count":   self._escalate_count,
            "bypass_count":     self._bypass_count,
            "override_rate":    round(self._override_count / total, 4) if total else 0.0,
            "baselines_loaded": len(self._baselines),
            "thresholds": {
                "base_risk":  self._base_risk_threshold,
                "override":   self._override_threshold,
                "confirm":    self._confirm_threshold,
                "escalate":   self._escalate_threshold,
            },
        }

    @property
    def false_positive_reduction_rate(self) -> float:
        """
        Estimated FPR reduction: what fraction of disruptive actions
        were identified as false positives and overridden.
        """
        total = self._total_checks
        if total == 0:
            return 0.0
        return self._override_count / total

    # ------------------------------------------------------------------
    # Private decision logic
    # ------------------------------------------------------------------

    def _decide(
        self,
        action:   str,
        anomaly:  AnomalyResult,
        baseline: UserBaseline,
    ) -> tuple[UEBAVerdict, str, str]:
        """
        Core decision function.

        Returns (verdict, final_action, reason).
        """
        score = anomaly.composite_score

        # ── ESCALATE: extreme anomaly confirmed ───────────────────────
        if score >= self._escalate_threshold:
            return (
                UEBAVerdict.ESCALATE,
                self._escalate_action(action),
                f"EXTREME anomaly (score={score:.3f} ≥ {self._escalate_threshold}). "
                f"Entity type={baseline.entity_type.value}. "
                f"All behavioral dimensions deviate significantly from baseline.",
            )

        # ── OVERRIDE: clearly normal behavior ─────────────────────────
        if score < self._override_threshold:
            return (
                UEBAVerdict.OVERRIDE,
                "MONITOR",   # Downgrade to passive monitoring
                f"NORMAL behavior detected (score={score:.3f} "
                f"< {self._override_threshold}). "
                f"Volume/timing/destination all within baseline norms. "
                f"Entity type={baseline.entity_type.value}. "
                f"Original action '{action}' downgraded to MONITOR.",
            )

        # ── BORDERLINE zone (override_threshold ≤ score < confirm_threshold)
        if score < self._confirm_threshold:
            # Additional contextual checks for borderline cases
            if anomaly.is_scheduled_match:
                return (
                    UEBAVerdict.OVERRIDE,
                    "MONITOR",
                    f"SCHEDULED JOB match (score={score:.3f}, "
                    f"pattern='{baseline.schedule_pattern}'). "
                    f"Activity matches known periodic schedule — overriding "
                    f"'{action}' to MONITOR.",
                )

            if baseline.entity_type == EntityType.SERVER_BACKUP:
                return (
                    UEBAVerdict.OVERRIDE,
                    "MONITOR",
                    f"BACKUP SERVER recognized (score={score:.3f}). "
                    f"Entity type=SERVER_BACKUP with established behavioral "
                    f"pattern. Large data transfer is expected — overriding "
                    f"'{action}' to MONITOR.",
                )

            if baseline.entity_type == EntityType.SERVER_DB:
                return (
                    UEBAVerdict.OVERRIDE,
                    "MONITOR",
                    f"DATABASE SERVER recognized (score={score:.3f}). "
                    f"Entity type=SERVER_DB. Replication/backup traffic is "
                    f"expected — overriding '{action}' to MONITOR.",
                )

            # Borderline but no mitigating context → CONFIRM (err on safe side)
            return (
                UEBAVerdict.CONFIRM,
                action,
                f"BORDERLINE anomaly (score={score:.3f}). "
                f"No matching schedule or known server type. "
                f"Proceeding with '{action}' as precaution.",
            )

        # ── CONFIRM: clearly anomalous ────────────────────────────────
        return (
            UEBAVerdict.CONFIRM,
            action,
            f"ANOMALY CONFIRMED (score={score:.3f} "
            f"≥ {self._confirm_threshold}). "
            f"Entity type={baseline.entity_type.value}. "
            f"Behavioral deviation supports defensive action '{action}'.",
        )

    @staticmethod
    def _escalate_action(current_action: str) -> str:
        """
        Upgrade a defensive action to a more aggressive level.
        Used when UEBA detects extreme behavioral anomaly.
        """
        _ESCALATION_MAP = {
            "MONITOR":           "ISOLATE_PARTIAL",
            "DECOY_TRAP":        "ISOLATE_PARTIAL",
            "ISOLATE_PARTIAL":   "ISOLATE_FULL",
            "HONEYPOT_REDIRECT": "KILL_SESSIONS",
            "RATE_LIMIT":        "KILL_SESSIONS",
            "KILL_SESSIONS":     "ISOLATE_FULL",
            "CREDENTIAL_ROTATE": "ISOLATE_PARTIAL",
            "FAKE_PATCH":        "KILL_SESSIONS",
            "ALERT_ONLY":        "ISOLATE_PARTIAL",
            "ISOLATE_FULL":      "EMERGENCY_ISOLATE",
            "BLOCK_IP":          "EMERGENCY_ISOLATE",
            "EMERGENCY_ISOLATE": "EMERGENCY_ISOLATE",
        }
        return _ESCALATION_MAP.get(current_action, current_action)
