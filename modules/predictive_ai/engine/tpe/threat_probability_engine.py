"""
bunyanx NGFW — AEGIS v3: Threat Probability Engine (TPE)
============================================================

Stage 1 — Pre-attack Risk Scoring Engine.

Algorithm:  Bayesian Weighted Scorer (linear combination of risk factors).
This is a purely static feature extraction engine that generates a contextual risk
prior based on fixed organizational parameters and CTI inputs.

Core Formula (per paper §III.A):

    ThreatScore = Σ αᵢ · Pᵢ

where:
    P₁ = P(attack | sector)          — sector base rate (DBIR 2024)
    P₂ = P(attack | geo_zone)        — geopolitical multiplied base
    P₃ = f(EPSS, CVSS, n_vulns)      — technical vulnerability exposure
    P₄ = CTI campaign intensity       — active threat intel signal
    P₅ = P(attack | breach_history)  — historical breach prior

Default weights:
    α₁=0.25, α₂=0.30, α₃=0.20, α₄=0.15, α₅=0.10

References:
    [1] A. Ganin et al., "Multicriteria decision making approach to cybersecurity
        risk assessment," Reliab. Eng. Sys. Safety, 2017.
    [2] P. Manadhata & J. Wing, "An Attack Surface Metric," IEEE TSE, 2011.
    [3] FIRST EPSS Model — https://www.first.org/epss/model
    [4] Verizon DBIR 2024, IBM X-Force 2024, Mandiant M-Trends 2024.
"""

from __future__ import annotations

import logging
import math
from typing import Optional

from modules.predictive_ai.engine.tpe.risk_context import (
    AttackLikelihoodReport,
    AttackVector,
    GeopoliticalZone,
    HistoricalBreachRecord,
    OrganizationProfile,
    OrgSector,
    RiskLevel,
    ThreatIntelFeedProtocol,
    VulnerabilityContext,
)
from modules.predictive_ai.engine.tpe.sector_profiles import (
    GEO_MULTIPLIERS,
    SECTOR_PROFILES,
    SIZE_MODIFIERS,
)
from modules.predictive_ai.engine.tpe.threat_intel_feed import StaticCTIFeed

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default alpha weights (tuned on DBIR historical data)
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS = (0.25, 0.30, 0.20, 0.15, 0.10)

# Extended weights for 6 factors (with sentiment P₆)
DEFAULT_WEIGHTS_6 = (0.22, 0.27, 0.18, 0.13, 0.09, 0.11)

# Pre-arm threshold: AEGIS switches to "high-sensitivity" mode
PRE_ARM_THRESHOLD    = 0.65
# Pre-emptive honeypot deployment threshold
HONEYPOT_THRESHOLD   = 0.80

# Risk level thresholds
LEVEL_HIGH_THRESHOLD   = 0.75
LEVEL_MEDIUM_THRESHOLD = 0.50


# ---------------------------------------------------------------------------
# ThreatProbabilityEngine
# ---------------------------------------------------------------------------

class ThreatProbabilityEngine:
    """
    Pre-attack Threat Probability Engine (Stage 1 of AEGIS v3).

    Computes a quantitative attack likelihood score for an organization
    BEFORE any attack is observed, enabling proactive posture adjustment.

    This addresses the key gap identified by academic reviewers:
    most IDS/IPS systems react *after* an attack begins.
    TPE provides the "over-the-horizon" threat signal.

    Parameters
    ----------
    weights : tuple[float, ...]
        Alpha weights (α₁..α₅) for the 5 risk factors.
        Must sum to 1.0. Default: (0.25, 0.30, 0.20, 0.15, 0.10).
    cti_feed : ThreatIntelFeedProtocol | None
        CTI feed implementation. Defaults to StaticCTIFeed.
    """

    def __init__(
        self,
        weights:                 tuple[float, ...] = DEFAULT_WEIGHTS,
        cti_feed:                Optional[ThreatIntelFeedProtocol] = None,
    ) -> None:
        if len(weights) not in (5, 6):
            raise ValueError("weights must have 5 or 6 elements")
        total = sum(weights)
        if abs(total - 1.0) > 0.01:
            raise ValueError(f"weights must sum to 1.0, got {total:.3f}")

        self._weights  = list(weights)
        self._cti_feed = cti_feed  # injected later if None

        _log.info(
            "ThreatProbabilityEngine initialized | "
            "weights=%s",
            self._weights,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess(self, profile: OrganizationProfile) -> AttackLikelihoodReport:
        """
        Compute the pre-attack threat likelihood for the given organization.

        Parameters
        ----------
        profile : OrganizationProfile
            Full organizational risk profile (sector, geo, vulnerabilities, etc.)

        Returns
        -------
        AttackLikelihoodReport
            Complete threat assessment including score, level,
            predicted vector, threat actor, and tactical recommendations.
        """
        sector  = profile.sector
        geo     = profile.geo_zone
        vuln    = profile.vuln_context
        history = profile.breach_history

        # Resolve CTI feed
        cti = self._resolve_cti(geo)

        # ── Compute individual P factors ──────────────────────────────
        p1 = self._p_sector(sector, profile)
        p2 = self._p_geo(geo, sector)
        p3 = self._p_vulnerability(vuln)
        p4 = self._p_cti(sector, cti)
        p5 = self._p_history(history)

        factors = [p1, p2, p3, p4, p5]

        # ── P₆: Sentiment CTI (if 6-factor mode) ─────────────────────
        p6 = 0.0
        if len(self._weights) == 6:
            try:
                from modules.predictive_ai.engine.tpe.sentiment_cti_feed import (
                    SentimentAugmentedCTIFeed,
                )
                if isinstance(cti, SentimentAugmentedCTIFeed):
                    p6 = cti.get_sentiment_index(sector)
                else:
                    p6 = 0.0
            except ImportError:
                p6 = 0.0
            factors.append(p6)

        w = tuple(self._weights[:len(factors)])

        # ── Weighted combination ──────────────────────────────────────
        raw_score = sum(wi * pi for wi, pi in zip(w, factors))
        raw_score = max(0.0, min(1.0, raw_score))   # clamp

        # Apply size modifier
        size_mod  = SIZE_MODIFIERS.get(profile.size.value, 1.0)
        score     = max(0.0, min(1.0, raw_score * size_mod))

        # OT / Critical infrastructure boost
        if profile.has_ot_environment:
            score = min(1.0, score * 1.15)
        if profile.is_critical_infrastructure:
            score = min(1.0, score * 1.20)

        # ── Risk level classification ─────────────────────────────────
        level = self._classify_level(score)

        # ── Prediction outputs ────────────────────────────────────────
        vector, actor, expected_ttps = self._predict_vector_and_actor(sector, cti)

        # ── Recommendations ───────────────────────────────────────────
        recommendations = self._build_recommendations(level, score, vuln, sector, profile)

        # ── Pre-arm / Honeypot directives ─────────────────────────────
        pre_arm          = score >= PRE_ARM_THRESHOLD
        deploy_honeypots = score >= HONEYPOT_THRESHOLD

        report = AttackLikelihoodReport(
            threat_score       = round(score, 4),
            risk_level         = level,
            most_likely_vector = vector,
            most_likely_actor  = actor,
            expected_ttps      = expected_ttps,
            p_sector           = round(p1, 4),
            p_geo              = round(p2, 4),
            p_vuln             = round(p3, 4),
            p_cti              = round(p4, 4),
            p_history          = round(p5, 4),
            alpha_weights      = w,
            recommendations    = recommendations,
            pre_arm_AEGIS     = pre_arm,
            deploy_honeypots   = deploy_honeypots,
            org_name           = profile.name,
            sector             = sector.value,
            geo_zone           = geo.value,
        )

        _log.info("TPE assessment: %s", report)
        return report

    # ------------------------------------------------------------------
    # Private factor computations
    # ------------------------------------------------------------------

    def _p_sector(self, sector: OrgSector, profile: OrganizationProfile) -> float:
        """P₁ — base attack rate for the sector (DBIR 2024 calibrated)."""
        prof = SECTOR_PROFILES.get(sector, {})
        base = prof.get("base_attack_rate", 0.25)
        weight = prof.get("risk_weight", 0.70)
        return base * weight

    def _p_geo(self, geo: GeopoliticalZone, sector: OrgSector) -> float:
        """
        P₂ — geopolitical risk probability.
        Scales the sector base rate by geopolitical multiplier,
        then normalizes to [0,1].
        """
        mult   = GEO_MULTIPLIERS.get(geo.value, 1.0)
        base   = SECTOR_PROFILES.get(sector, {}).get("base_attack_rate", 0.25)
        # P₂ = saturating function: 1 - e^(-k · base · mult)
        k      = 2.0
        p      = 1.0 - math.exp(-k * base * mult)
        return min(1.0, p)

    def _p_vulnerability(self, vuln: VulnerabilityContext) -> float:
        """
        P₃ — technical exposure probability.

        Components:
          - EPSS avg score (primary — direct exploit probability)
          - CVSS normalization (0-10 → 0-1)
          - Critical vuln count penalty
          - Patch currency penalty (days since last patch)
        """
        # EPSS is already [0,1] and direct probability of exploitation
        epss_component = vuln.avg_epss

        # CVSS contribution (normalize to 0-1)
        cvss_norm = vuln.max_cvss / 10.0

        # Critical vulns add direct risk
        crit_penalty = min(0.3, vuln.num_critical_vulns * 0.05)

        # Patch delay: each 30 days of no patching adds 3% risk
        patch_penalty = min(0.20, (vuln.days_since_last_patch / 30) * 0.03)

        # Exposure surface: large exposed surface = more attack opportunities
        exposure = min(0.15, vuln.internet_exposed_assets * 0.005)

        p3 = epss_component + 0.3 * cvss_norm + crit_penalty + patch_penalty + exposure
        return min(1.0, p3)

    def _p_cti(self, sector: OrgSector, cti: object) -> float:
        """P₄ — CTI campaign intensity for the sector."""
        try:
            return cti.get_campaign_intensity(sector)
        except Exception:
            return 0.0

    def _p_history(self, history: HistoricalBreachRecord) -> float:
        """
        P₅ — historical breach prior.

        Monthly breach rate (bounded to [0, 1]):
            P₅ = breaches_last_12m / 12  (continuous)
        Plus ransomware recidivism premium: +0.15
        Plus dwell time signal: long dwell → poor detection → higher risk
        """
        monthly_rate = min(0.7, history.breaches_last_12m / 12.0)

        ransomware_premium = 0.15 if history.ransomware_history else 0.0

        # Dwell time: normalize by industry average (204 days, IBM 2024)
        dwell_signal = min(0.15, (history.avg_dwell_days / 204.0) * 0.15)

        return min(1.0, monthly_rate + ransomware_premium + dwell_signal)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _classify_level(self, score: float) -> RiskLevel:
        if score >= LEVEL_HIGH_THRESHOLD:
            return RiskLevel.HIGH
        if score >= LEVEL_MEDIUM_THRESHOLD:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _resolve_cti(self, geo: GeopoliticalZone):
        """Return injected CTI feed or default StaticCTIFeed."""
        if self._cti_feed is not None:
            return self._cti_feed
        mult = GEO_MULTIPLIERS.get(geo.value, 1.0)
        return StaticCTIFeed(geopolitical_multiplier=mult)

    def _predict_vector_and_actor(
        self,
        sector: OrgSector,
        cti: object,
    ) -> tuple[AttackVector, str, list[str]]:
        """
        Predict most likely initial access vector, threat actor, and TTPs.
        Prefers CTI dominant campaign; falls back to sector profile default.
        """
        # Try CTI dominant campaign first
        try:
            dominant = cti.get_dominant_campaign(sector)
            if dominant:
                return (
                    dominant["vector"],
                    dominant["actor"],
                    dominant["ttps"],
                )
        except Exception:
            pass

        # Fall back to sector profile
        prof    = SECTOR_PROFILES.get(sector, {})
        vectors = prof.get("primary_vectors", [AttackVector.PHISHING])
        actor   = prof.get("top_threat_actors", "Unknown")
        ttps    = prof.get("top_ttps", [])
        return vectors[0], actor, ttps

    def _build_recommendations(
        self,
        level:   RiskLevel,
        score:   float,
        vuln:    VulnerabilityContext,
        sector:  OrgSector,
        profile: OrganizationProfile,
    ) -> list[str]:
        """Generate prioritized tactical recommendations."""
        recs: list[str] = []

        if level == RiskLevel.HIGH:
            recs.append("CRITICAL: Pre-arm AEGIS — lower detection thresholds immediately")
            recs.append("Deploy sector-specific honeypots targeted at predicted threat actor TTPs")
            recs.append("Activate 24/7 SOC monitoring with escalation protocol")

        if level in (RiskLevel.HIGH, RiskLevel.MEDIUM):
            recs.append("Update threat signatures for predicted TTPs and attack vectors")
            recs.append("Review and tighten external-facing firewall rules")

        if vuln.num_critical_vulns > 0:
            recs.append(
                f"URGENT: Patch {vuln.num_critical_vulns} critical "
                "vulnerability(ies) — appear on likely attack path"
            )

        if vuln.days_since_last_patch > 60:
            recs.append(
                f"Accelerate patch cycle: {vuln.days_since_last_patch} days "
                "since last patch (industry threshold: 30 days)"
            )

        if vuln.avg_epss > 0.3:
            recs.append(
                f"High EPSS score ({vuln.avg_epss:.0%}) — internet-facing "
                "assets under active exploitation risk"
            )

        if profile.has_ot_environment:
            recs.append("Segment OT/ICS network — nation-state OT attacks predicted for this sector")

        if not recs:
            recs.append("Maintain current security posture — continue routine monitoring")

        return recs
