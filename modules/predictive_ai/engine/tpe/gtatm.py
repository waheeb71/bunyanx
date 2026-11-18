"""
bunyanx NGFW — AEGIS : Geopolitical Temporal Attack Timing Model (GTATM)
=============================================================================

AEGIS Contribution C9

Problem Addressed
-----------------
TPE's geopolitical factor P₂ is computed once per assessment cycle (daily/
hourly) using a static multiplier μ(g).  Nation-state adversaries are
empirically known to mount coordinated operations aligned with:
  1. Business-hours of their own time zone (staffed C2 operators).
  2. Sudden geopolitical shock events (sanctions, diplomatic crises, conflict
     escalation) that trigger opportunistic campaigns.

A static P₂ completely misses these within-day and event-driven surges,
leading to under-alerting during peak attack windows.

GTATM replaces the static multiplier with a time-aware function:

    P₂_GTATM(t) = min(1.0,  μ(g) · Φ_TZ(t, TZ_adv) · Ψ_shock(t, E))

where:

    Φ_TZ(t, TZ_adv) = 1 + κ · max(0, cos(2π · ((t_UTC + TZ_adv) mod 24 - h_peak) / 24))

        κ       = amplitude of timezone-rhythm modulation (default 0.40)
        TZ_adv  = adversary timezone offset in hours (e.g. +3 for Moscow)
        h_peak  = hour of peak activity in adversary local time (default 13:00)

    Ψ_shock(t, E) = min(2.0, 1 + Σ_{e∈E} wₑ · exp(−βₑ · max(0, t − tₑ)))

        E    = list of registered geopolitical shock events
        wₑ   = event severity weight ∈ [0, 1]
        βₑ   = decay rate (default 0.042 h⁻¹ → half-life ≈ 72 h ≈ 3 days)
        tₑ   = event UNIX timestamp

Research Basis
--------------
  * Rid, T. & Buchanan, B., "Attributing Cyber Attacks," J. Strategic Studies 2015.
  * FireEye / Mandiant M-Trends 2024 — working-hours distribution of APT activity.
  * Verizon DBIR 2024 — temporal attack density by industry.
  * AEGIS paper — bunyanx AI Division, April 2026, §IV.C Contribution C9.
"""

from __future__ import annotations

import logging
import math
import time as _time_module
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Default hyper-parameters
# ---------------------------------------------------------------------------

_DEFAULT_KAPPA:     float = 0.40   # timezone rhythm amplitude
_DEFAULT_H_PEAK:    float = 13.0   # local peak hour (1 PM business hours)
_DEFAULT_BETA:      float = 0.042  # shock decay rate h⁻¹  (half-life ≈ 72 h)
_DEFAULT_MAX_PSI:   float = 2.0    # cap on shock multiplier
_DEFAULT_MAX_PHI:   float = 1.40   # cap on timezone multiplier (1 + κ)


# ---------------------------------------------------------------------------
# Shock event data structure
# ---------------------------------------------------------------------------

@dataclass
class GeopoliticalShockEvent:
    """
    A registered geopolitical shock event that elevates attack probability.

    Parameters
    ----------
    timestamp : float
        UNIX timestamp of event occurrence.
    weight : float
        Severity weight ∈ [0, 1].  1.0 = maximum severity (armed conflict
        escalation, major sanctions).  0.3 = moderate (diplomatic expulsion).
    description : str
        Human-readable label for logging and reporting.
    beta_override : float | None
        Optional per-event decay rate override.  If None, uses default β.
    """
    timestamp:     float
    weight:        float
    description:   str
    beta_override: Optional[float] = None

    def psi_contribution(self, current_time: float, default_beta: float) -> float:
        """Compute this event's additive contribution to Ψ_shock at time t."""
        elapsed_h = max(0.0, (current_time - self.timestamp) / 3600.0)
        beta = self.beta_override if self.beta_override is not None else default_beta
        return self.weight * math.exp(-beta * elapsed_h)


# ---------------------------------------------------------------------------
# GeopoliticalTemporalModel — Main class
# ---------------------------------------------------------------------------

class GeopoliticalTemporalModel:
    """
    AEGIS Contribution C9 — Geopolitical Temporal Attack Timing Model.

    Converts the static TPE P₂ factor into a time-aware, event-driven signal
    that reflects the adversary's operational rhythm and geopolitical triggers.

    Thread Safety
    -------------
    Shock events are appended via ``add_geopolitical_event()`` which may be
    called from an external feed thread.  The internal list uses simple append
    semantics; Python's GIL guarantees atomicity of list.append(), so no
    additional lock is required for correctness (reads during write will see
    a consistent state).

    Parameters
    ----------
    kappa : float
        Timezone-rhythm amplitude.  Range [0, 1].  Default: 0.40.
    h_peak : float
        Hour of peak adversary activity in *their local time* (0–24).
        Default: 13.0 (1 PM).
    beta : float
        Shock event decay rate in h⁻¹.  Default: 0.042 (72 h half-life).
    max_events : int
        Maximum number of shock events retained.  Oldest are pruned.
        Default: 100.
    """

    def __init__(
        self,
        kappa:      float = _DEFAULT_KAPPA,
        h_peak:     float = _DEFAULT_H_PEAK,
        beta:       float = _DEFAULT_BETA,
        max_events: int   = 100,
    ) -> None:
        self._kappa      = kappa
        self._h_peak     = h_peak
        self._beta       = beta
        self._max_events = max_events
        self._events:    list[GeopoliticalShockEvent] = []

        _log.info(
            "GeopoliticalTemporalModel ready — κ=%.2f h_peak=%.1f β=%.4f",
            kappa, h_peak, beta,
        )

    # ------------------------------------------------------------------
    # Event registration
    # ------------------------------------------------------------------

    def add_geopolitical_event(
        self,
        timestamp:     float,
        weight:        float,
        description:   str,
        beta_override: Optional[float] = None,
    ) -> None:
        """
        Register a new geopolitical shock event.

        Parameters
        ----------
        timestamp : float
            UNIX timestamp of the event.
        weight : float
            Severity weight ∈ [0, 1].
        description : str
            Human-readable event description.
        beta_override : float | None
            Per-event decay rate override (optional).
        """
        weight = max(0.0, min(1.0, weight))
        event = GeopoliticalShockEvent(
            timestamp=timestamp,
            weight=weight,
            description=description,
            beta_override=beta_override,
        )
        self._events.append(event)

        # Prune oldest events if over capacity
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]

        _log.info(
            "GTATM: registered shock event '%s' weight=%.2f",
            description, weight,
        )

    def clear_events(self) -> None:
        """Remove all registered shock events."""
        self._events.clear()
        _log.info("GTATM: all shock events cleared.")

    # ------------------------------------------------------------------
    # Core computation
    # ------------------------------------------------------------------

    def compute_phi_tz(
        self,
        t_unix: float,
        adv_tz_offset: float = 0.0,
    ) -> float:
        """
        Compute the timezone-rhythm factor Φ_TZ.

            Φ_TZ(t, TZ_adv) = 1 + κ · max(0, cos(2π · (local_h - h_peak) / 24))

        where local_h = (t_UTC_hour + TZ_adv) mod 24.

        Parameters
        ----------
        t_unix : float
            Current UNIX timestamp.
        adv_tz_offset : float
            Adversary timezone offset in hours.  E.g. +3 for Moscow, +8 for Beijing.

        Returns
        -------
        float
            Φ_TZ ∈ [1.0, 1 + κ].
        """
        import datetime
        utc_hour = (t_unix % 86400) / 3600.0  # fractional UTC hour
        local_h  = (utc_hour + adv_tz_offset) % 24.0
        cosine   = math.cos(2.0 * math.pi * (local_h - self._h_peak) / 24.0)
        phi      = 1.0 + self._kappa * max(0.0, cosine)
        return min(_DEFAULT_MAX_PHI, phi)

    def compute_psi_shock(self, t_unix: float) -> float:
        """
        Compute the geopolitical shock multiplier Ψ_shock.

            Ψ_shock(t, E) = min(2.0, 1 + Σ wₑ · exp(−β · max(0, t − tₑ)) / 3600)

        Parameters
        ----------
        t_unix : float
            Current UNIX timestamp.

        Returns
        -------
        float
            Ψ_shock ∈ [1.0, 2.0].
        """
        if not self._events:
            return 1.0

        total = sum(e.psi_contribution(t_unix, self._beta) for e in self._events)
        psi   = 1.0 + total
        return min(_DEFAULT_MAX_PSI, psi)

    def compute_p2_temporal(
        self,
        base_p2:       float,
        adv_tz_offset: float = 0.0,
        current_time:  Optional[float] = None,
    ) -> float:
        """
        Compute the temporally-adjusted geopolitical probability P₂_GTATM.

            P₂_GTATM(t) = min(1.0, base_p2 · Φ_TZ(t, TZ_adv) · Ψ_shock(t, E))

        Parameters
        ----------
        base_p2 : float
            The static geopolitical factor P₂ from TPE._p_geo().
        adv_tz_offset : float
            Adversary timezone offset in hours.
        current_time : float | None
            UNIX timestamp to evaluate at.  Uses time.time() if None.

        Returns
        -------
        float
            Adjusted P₂ ∈ [0.0, 1.0].
        """
        t = current_time if current_time is not None else _time_module.time()

        phi_tz  = self.compute_phi_tz(t, adv_tz_offset)
        psi_shk = self.compute_psi_shock(t)

        p2_adjusted = base_p2 * phi_tz * psi_shk
        p2_clamped  = max(0.0, min(1.0, p2_adjusted))

        _log.debug(
            "GTATM: base_p2=%.3f × Φ_TZ=%.3f × Ψ_shock=%.3f → P₂*=%.3f",
            base_p2, phi_tz, psi_shk, p2_clamped,
        )
        return round(p2_clamped, 6)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def get_temporal_summary(self, adv_tz_offset: float = 0.0) -> dict:
        """
        Return a diagnostic snapshot of the current temporal state.

        Returns
        -------
        dict
            Keys: phi_tz, psi_shock, n_active_events, recent_events.
        """
        t = _time_module.time()
        return {
            "phi_tz":        round(self.compute_phi_tz(t, adv_tz_offset), 4),
            "psi_shock":     round(self.compute_psi_shock(t), 4),
            "n_active_events": len(self._events),
            "adv_tz_offset": adv_tz_offset,
            "recent_events": [
                {
                    "description": e.description,
                    "weight":      e.weight,
                    "hours_ago":   round((t - e.timestamp) / 3600.0, 1),
                }
                for e in self._events[-5:]
            ],
        }
