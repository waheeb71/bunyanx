"""
bunyanx NGFW — AEGIS v3: Pre-Armed Adapter
===============================================

The bridge between Stage 1 (TPE) and Stage 2 (AEGIS).

Responsibilities:
    1. Run TPE assessment for the organization.
    2. If risk_level == HIGH:
       - Lower AEGIS disruption threshold (pre-armed mode).
       - Pre-deploy honeypots targeted at predicted threat actor TTPs.
    3. Expose a unified `TwoStageDefenseSystem` wrapper for the entire
       AEGIS v3 pipeline (TPE → AEGIS).

Integration with AEGIS (Stage 2):
    The AEGISEngine's internal disruption threshold is normally 0.55.
    In pre-armed mode (TPE score ≥ 0.65), it is lowered to 0.40 so that
    AEGIS acts more aggressively during the early kill-chain stages —
    catching threats that would otherwise wait for more evidence.

    ┌────────────────────────────────────────────────────────────────┐
    │  TPE (Stage 1)  → AttackLikelihoodReport                      │
    │     ↓ (if HIGH → pre_arm=True)                                │
    │  AEGISEngine.set_sensitivity(mode="HIGH")                    │
    │     disruption_threshold: 0.55 → 0.40                         │
    │     deception_boost:      1.0  → 1.3  (more honeypots)        │
    │     ↓                                                          │
    │  AEGISEngine (Stage 2) processes live events as usual        │
    └────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from modules.predictive_ai.engine.tpe import (
    AttackLikelihoodReport,
    GeopoliticalZone,
    HistoricalBreachRecord,
    OrganizationProfile,
    OrgSector,
    OrgSize,
    RiskLevel,
    ThreatProbabilityEngine,
    VulnerabilityContext,
)
from modules.predictive_ai.engine.tpe.gtatm import GeopoliticalTemporalModel

_log = logging.getLogger(__name__)

# Sensitivity mode thresholds
_NORMAL_THRESHOLD  = 0.55    # Default AEGIS disruption threshold
_PREARMED_THRESHOLD = 0.40   # Lowered when TPE says HIGH
_DECEPTION_BOOST   = 1.30    # Honeypot reward multiplier in HIGH mode


# ---------------------------------------------------------------------------
# Pre-Armed Mode Result
# ---------------------------------------------------------------------------

@dataclass
class PreArmDirective:
    """
    Directive sent from TPE (Stage 1) to AEGIS (Stage 2).

    Applied automatically by TwoStageDefenseSystem.apply_to_AEGIS().
    """
    pre_armed:             bool
    deploy_honeypots:      bool
    disruption_threshold:  float     # what to set AEGIS's threshold to
    deception_boost:       float     # multiplier on CSO deception reward
    threat_score:          float
    risk_level:            str
    most_likely_vector:    str
    most_likely_actor:     str
    expected_ttps:         list[str]
    recommendations:       list[str]


# ---------------------------------------------------------------------------
# TwoStageDefenseSystem
# ---------------------------------------------------------------------------

class TwoStageDefenseSystem:
    """
    Unified AEGIS v3 pipeline: Stage 1 (TPE) + Stage 2 (AEGIS).

    Usage:
        # At system startup or when org profile changes:
        system = TwoStageDefenseSystem(org_profile)
        directive = system.run_stage1()   # TPE assessment
        system.apply_to_AEGIS(AEGIS_engine, directive)

        # Then AEGIS processes live events as usual (Stage 2).

    Parameters
    ----------
    profile : OrganizationProfile
        The organization's risk profile (sector, geo, vulns, history).
    tpe : ThreatProbabilityEngine | None
        TPE engine instance. Defaults to a fresh instance with default weights.
    """

    def __init__(
        self,
        profile: OrganizationProfile,
        tpe: Optional[ThreatProbabilityEngine] = None,
        adv_tz_offset: float = 0.0,
    ) -> None:
        self.profile = profile
        self._tpe    = tpe or ThreatProbabilityEngine()
        self._gtatm  = GeopoliticalTemporalModel()   # C9 — temporal P₂ adjustment
        self._adv_tz = adv_tz_offset
        self._last_report: Optional[AttackLikelihoodReport] = None
        _log.info(
            "TwoStageDefenseSystem ready | org=%s sector=%s geo=%s tz_offset=%.1fh",
            profile.name, profile.sector.value, profile.geo_zone.value, adv_tz_offset,
        )

    # ------------------------------------------------------------------
    # Stage 1: TPE Assessment
    # ------------------------------------------------------------------

    def run_stage1(self) -> PreArmDirective:
        """
        Run the Stage 1 (TPE) assessment and return a directive for AEGIS.

        Returns
        -------
        PreArmDirective
            Contains sensitivity settings to apply to AEGISEngine.
        """
        report = self._tpe.assess(self.profile)
        self._last_report = report

        # C9 — GTATM: apply temporal adjustment to P₂ (geopolitical factor)
        # The raw threat_score already includes P₂ from TPE.
        # We recalculate the geo-factor portion using the temporal model.
        raw_score = report.threat_score
        if hasattr(report, 'p_geo') and report.p_geo is not None:
            base_p2      = report.p_geo
            p2_temporal  = self._gtatm.compute_p2_temporal(
                base_p2=base_p2,
                adv_tz_offset=self._adv_tz,
            )
            # Delta: difference between temporal P₂ and base P₂
            # Apply proportional adjustment to the overall score
            p2_delta  = p2_temporal - base_p2
            # Weight P₂ in TPE is approximately alpha_2 (index 1 in alpha_weights)
            alpha_geo = (
                report.alpha_weights[1]
                if hasattr(report, 'alpha_weights') and len(report.alpha_weights) > 1
                else 0.20
            )
            score_adjusted = min(1.0, max(0.0, raw_score + alpha_geo * p2_delta))
            _log.info(
                "GTATM adjustment: base_p2=%.3f temporal_p2=%.3f delta=%.4f "
                "score: %.4f → %.4f",
                base_p2, p2_temporal, p2_delta, raw_score, score_adjusted,
            )
        else:
            score_adjusted = raw_score

        if score_adjusted >= 0.65:
            threshold       = _PREARMED_THRESHOLD
            deception_boost = _DECEPTION_BOOST
            _log.warning(
                "TPE+GTATM PRE-ARM TRIGGERED: score=%.3f→%.3f level=%s | "
                "AEGIS threshold %.2f → %.2f | DeceptionBoost=%.1fx",
                raw_score, score_adjusted, report.risk_level.value,
                _NORMAL_THRESHOLD, threshold, deception_boost,
            )
        elif report.pre_arm_AEGIS:
            threshold       = _PREARMED_THRESHOLD
            deception_boost = _DECEPTION_BOOST
        else:
            threshold       = _NORMAL_THRESHOLD
            deception_boost = 1.0

        return PreArmDirective(
            pre_armed            = (score_adjusted >= 0.65) or report.pre_arm_AEGIS,
            deploy_honeypots     = report.deploy_honeypots,
            disruption_threshold = threshold,
            deception_boost      = deception_boost,
            threat_score         = score_adjusted,
            risk_level           = report.risk_level.value,
            most_likely_vector   = report.most_likely_vector.value,
            most_likely_actor    = report.most_likely_actor,
            expected_ttps        = report.expected_ttps,
            recommendations      = report.recommendations,
        )

    # ------------------------------------------------------------------
    # Stage 2: Apply directive to AEGISEngine
    # ------------------------------------------------------------------

    def apply_to_AEGIS(self, AEGIS_engine, directive: PreArmDirective) -> None:
        """
        Apply the TPE pre-arm directive to the live AEGISEngine instance.

        Changes applied:
          - Lowers AEGISEvaluator disruption threshold if pre_armed.
          - Sets CSO deception boost multiplier.
          - Logs pre-emptive honeypot deployment directive.

        Parameters
        ----------
        AEGIS_engine : AEGISEngine
            The live AEGIS Stage 2 engine.
        directive : PreArmDirective
            Output from run_stage1().
        """
        if AEGIS_engine is None:
            _log.warning("apply_to_AEGIS: AEGISEngine not available — skipping")
            return

        # Set sensitivity mode on AEGIS engine
        try:
            if hasattr(AEGIS_engine, 'set_sensitivity'):
                AEGIS_engine.set_sensitivity(
                    disruption_threshold = directive.disruption_threshold,
                    deception_boost      = directive.deception_boost,
                )
            else:
                # Fallback: directly patch internal evaluator threshold
                # (works with current AEGISEngine implementation)
                if hasattr(AEGIS_engine, '_disruption_threshold'):
                    AEGIS_engine._disruption_threshold = directive.disruption_threshold
                _log.info(
                    "AEGIS sensitivity set: threshold=%.2f boost=%.1f",
                    directive.disruption_threshold, directive.deception_boost,
                )
        except Exception as exc:
            _log.warning("Failed to apply pre-arm to AEGIS: %s", exc)

        # Log pre-emptive honeypot directive
        if directive.deploy_honeypots:
            _log.warning(
                "PRE-EMPTIVE HONEYPOT DIRECTIVE: Deploy decoys targeting "
                "actor=%s vector=%s TTPs=%s",
                directive.most_likely_actor,
                directive.most_likely_vector,
                directive.expected_ttps,
            )

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def last_report(self) -> Optional[AttackLikelihoodReport]:
        """The last TPE assessment report."""
        return self._last_report

    # ------------------------------------------------------------------
    # C9 — GTATM: Geopolitical event registration
    # ------------------------------------------------------------------

    def add_geopolitical_event(
        self,
        weight: float,
        description: str,
        beta_override: Optional[float] = None,
    ) -> None:
        """
        Register a geopolitical shock event that elevates the temporal
        threat score.  Events decay exponentially with a 72-hour half-life.

        Parameters
        ----------
        weight : float
            Event severity ∈ [0, 1].  1.0 = maximum (armed conflict escalation).
        description : str
            Human-readable event description.
        beta_override : float | None
            Optional per-event decay rate override (h⁻¹).
        """
        import time as _t
        self._gtatm.add_geopolitical_event(
            timestamp=_t.time(),
            weight=weight,
            description=description,
            beta_override=beta_override,
        )

    def get_temporal_summary(self) -> dict:
        """Return GTATM temporal snapshot (Φ_TZ, Ψ_shock, active events)."""
        return self._gtatm.get_temporal_summary(self._adv_tz)

    def to_dict(self) -> dict:
        """Serializable summary for API and logging."""
        if self._last_report is None:
            return {"status": "not_assessed"}
        r = self._last_report
        return {
            "org_name":           r.org_name,
            "sector":             r.sector,
            "geo_zone":           r.geo_zone,
            "threat_score":       r.threat_score,
            "risk_level":         r.risk_level.value,
            "most_likely_vector": r.most_likely_vector.value,
            "most_likely_actor":  r.most_likely_actor,
            "expected_ttps":      r.expected_ttps,
            "pre_arm_AEGIS":     r.pre_arm_AEGIS,
            "deploy_honeypots":   r.deploy_honeypots,
            "recommendations":    r.recommendations,
            "component_scores": {
                "P_sector":  r.p_sector,
                "P_geo":     r.p_geo,
                "P_vuln":    r.p_vuln,
                "P_cti":     r.p_cti,
                "P_history": r.p_history,
            },
            "alpha_weights": list(r.alpha_weights),
        }


# ---------------------------------------------------------------------------
# Quick-start factory
# ---------------------------------------------------------------------------

def create_from_config(
    sector:        str,
    geo_zone:      str,
    size:          str          = "ENTERPRISE",
    avg_epss:      float        = 0.10,
    max_cvss:      float        = 6.0,
    critical_vulns: int         = 0,
    exposed_assets: int         = 20,
    patch_days:    int          = 30,
    breaches_12m:  int          = 0,
    ransomware:    bool         = False,
    has_ot:        bool         = False,
    is_critical:   bool         = False,
    org_name:      str          = "Organization",
) -> TwoStageDefenseSystem:
    """
    Factory function — create TwoStageDefenseSystem from simple params.
    Used by the REST API endpoint and system initialization.

    Parameters match the POST /api/v1/ai/threat-assessment body schema.
    """
    profile = OrganizationProfile(
        name    = org_name,
        sector  = OrgSector(sector.upper()),
        geo_zone= GeopoliticalZone(geo_zone.upper()),
        size    = OrgSize(size.upper()),
        vuln_context = VulnerabilityContext(
            avg_epss               = avg_epss,
            max_cvss               = max_cvss,
            num_critical_vulns     = critical_vulns,
            internet_exposed_assets= exposed_assets,
            days_since_last_patch  = patch_days,
        ),
        breach_history = HistoricalBreachRecord(
            breaches_last_12m  = breaches_12m,
            ransomware_history = ransomware,
        ),
        has_ot_environment         = has_ot,
        is_critical_infrastructure = is_critical,
    )
    return TwoStageDefenseSystem(profile)
