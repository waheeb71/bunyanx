"""
Enterprise bunyanx — UBA User Profiler (Adaptive Baseline Engine)

Central coordinator for the UBA pipeline:

  1. Load or create a UBAUserProfile from the database.
  2. Run all 5 detectors on the incoming event.
  3. Aggregate scores → RiskAggregator.
  4. Update the profile baseline (EMA / histogram / known lists).
  5. Persist the UBAEvent and updated UBAUserProfile.

Peer-group stats are computed over all profiles sharing the same peer_group.
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class UBAAnalysisResult:
    """Result of a single event analysis."""
    __slots__ = (
        "username", "anomaly_score", "risk_contribution",
        "risk_score", "risk_level", "action",
        "detectors_triggered", "details",
    )

    def __init__(self):
        self.username: str = ""
        self.anomaly_score: float = 0.0
        self.risk_contribution: float = 0.0
        self.risk_score: float = 0.0
        self.risk_level: str = "low"
        self.action: str = "allow"
        self.detectors_triggered: List[str] = []
        self.details: Dict = {}

    def to_dict(self) -> dict:
        return {
            "username":            self.username,
            "anomaly_score":       round(self.anomaly_score, 4),
            "risk_contribution":   round(self.risk_contribution, 2),
            "risk_score":          round(self.risk_score, 2),
            "risk_level":          self.risk_level,
            "action":              self.action,
            "detectors_triggered": self.detectors_triggered,
            "details":             self.details,
        }


class UBAConfigHolder:
    """Detached helper object to hold config attributes without database session binding."""
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


class UserProfiler:
    """
    Adaptive behavioral profiler that orchestrates:
      - Profile load / create
      - Detector pipeline
      - EMA baseline update
      - DB persistence

    Usage:
        profiler = UserProfiler(db_manager=db, config=uba_cfg)
        result = profiler.analyze(event_data)
    """

    def __init__(self, db_manager=None, config=None, logger=None):
        self.db = db_manager
        self.cfg = config         # UBAConfig DB row (or dict if not yet persisted)
        self.logger = logger or logging.getLogger(self.__class__.__name__)
        self._peer_cache: Dict[str, dict] = {}    # peer_group → stats
        self._peer_cache_ts: float = 0.0
        self._lock = threading.RLock()

        # Import detectors here to avoid circular imports at module level
        from modules.uba.engine.detectors.time_detector      import TimeAnomalyDetector
        from modules.uba.engine.detectors.location_detector  import LocationAnomalyDetector
        from modules.uba.engine.detectors.exfil_detector     import ExfilDetector
        from modules.uba.engine.detectors.privilege_detector import PrivilegeDetector
        from modules.uba.engine.detectors.peer_detector      import PeerGroupDetector
        from modules.uba.engine.core.risk_aggregator         import RiskAggregator
        from modules.uba.engine.core.uba_deception           import UBAHoneytokenEngine

        privileged_svcs = None
        if config and hasattr(config, 'privileged_services'):
            privileged_svcs = config.privileged_services or []

        weights    = (config.detector_weights if config else None) or {}
        thresholds = (config.thresholds        if config else None) or {}
        alpha      = float(config.ema_alpha    if config else 0.10)

        self.time_det      = TimeAnomalyDetector()
        self.location_det  = LocationAnomalyDetector()
        self.exfil_det     = ExfilDetector()
        self.privilege_det = PrivilegeDetector(privileged_svcs)
        self.peer_det      = PeerGroupDetector()
        self.aggregator    = RiskAggregator(
            weights=weights or None,
            thresholds=thresholds or None,
            ema_alpha=alpha,
        )
        self.deception_engine = UBAHoneytokenEngine()

    def refresh_config(self):
        """Reload configuration dynamically from database to support hot-reloading."""
        if not self.db:
            return
        try:
            from system.database.database import UBAConfig
            with self.db.sync_session() as session:
                cfg = session.query(UBAConfig).first()
                if cfg:
                    self.cfg = UBAConfigHolder(
                        enabled=cfg.enabled,
                        deception_enabled=getattr(cfg, 'deception_enabled', True),
                        mode=cfg.mode,
                        baseline_min_events=cfg.baseline_min_events,
                        max_known_ips=cfg.max_known_ips,
                        max_known_services=cfg.max_known_services,
                        ema_alpha=cfg.ema_alpha,
                        detector_weights=dict(cfg.detector_weights or {}),
                        thresholds=dict(cfg.thresholds or {}),
                        alert_on_risk_level=cfg.alert_on_risk_level,
                        privileged_services=list(cfg.privileged_services or []),
                    )
                    # Update active sub-detectors and aggregator parameters
                    if hasattr(self, 'privilege_det'):
                        from modules.uba.engine.detectors.privilege_detector import DEFAULT_PRIVILEGED
                        self.privilege_det._privileged = DEFAULT_PRIVILEGED | frozenset(
                            s.lower() for s in (self.cfg.privileged_services or [])
                        )
                    if hasattr(self, 'aggregator'):
                        self.aggregator.weights = self.cfg.detector_weights or self.aggregator.weights
                        self.aggregator.thresholds = self.cfg.thresholds or self.aggregator.thresholds
                        self.aggregator.ema_alpha = float(self.cfg.ema_alpha or 0.10)
        except Exception as exc:
            self.logger.warning("Failed to refresh UBA config in UserProfiler: %s", exc)

    # ── Public interface ──────────────────────────────────────────────────────

    def analyze(
        self,
        username: str,
        source_ip: str,
        target_service: str,
        bytes_transferred: float,
        session_duration: float = 0.0,
        event_time: Optional[float] = None,
        peer_group: Optional[str] = None,
        groups: Optional[List[str]] = None,
        department: Optional[str] = None,
    ) -> "UBAAnalysisResult":
        """
        Full pipeline: load profile → run detectors → aggregate → update → persist.

        Parameters
        ----------
        username     : canonical login name (from ICE / LDAP)
        source_ip    : client IP address
        target_service : e.g. "HTTP:80" or "SMTP:25"
        bytes_transferred : bytes in this event
        session_duration  : seconds
        event_time   : Unix timestamp (defaults to now)
        peer_group   : explicit peer group override
        groups       : AD/LDAP groups (from ICE) — used to derive peer_group
        department   : AD department (from ICE) — preferred peer_group source

        Returns UBAAnalysisResult.
        """
        self.refresh_config()
        ts = event_time or time.time()
        result = UBAAnalysisResult()
        result.username = username

        if not username:
            return result

        # Derive peer_group from AD identity (if not explicitly provided)
        if not peer_group:
            peer_group = (
                department
                or (groups[0] if groups else "")
            )

        # 1. Load / create profile
        profile = self._get_or_create_profile(username, peer_group, department=department)

        # Query cumulative bytes transferred in last 24 hours (excluding current event)
        cumulative_24h_bytes = 0.0
        if self.db:
            try:
                from system.database.database import UBAEvent
                from sqlalchemy import func
                cutoff = datetime.now(timezone.utc) - timedelta(days=1)
                with self.db.sync_session() as session:
                    res = (
                        session.query(func.sum(UBAEvent.bytes_transferred))
                        .filter(UBAEvent.username == username)
                        .filter(UBAEvent.event_time >= cutoff)
                        .scalar()
                    )
                    cumulative_24h_bytes = float(res or 0.0)
            except Exception as exc:
                self.logger.warning("Failed to query 24h cumulative bytes: %s", exc)

        total_24h_bytes = cumulative_24h_bytes + bytes_transferred

        # 2. Run detectors
        t_score, t_flags = self.time_det.analyze(profile, ts)
        l_score, l_flags = self.location_det.analyze(profile, source_ip)
        e_score, e_flags = self.exfil_det.analyze(profile, bytes_transferred, target_service, total_24h_bytes)
        p_score, p_flags = self.privilege_det.analyze(profile, target_service)

        peer_stats = self._get_peer_stats(peer_group or profile.peer_group or "")
        pe_score, pe_flags = self.peer_det.analyze(bytes_transferred, session_duration, peer_stats)

        all_flags = t_flags + l_flags + e_flags + p_flags + pe_flags

        # 3. Aggregate
        raw_score, risk_contribution = self.aggregator.aggregate({
            "time":      t_score,
            "location":  l_score,
            "exfil":     e_score,
            "privilege": p_score,
            "peer":      pe_score,
        })

        new_risk, risk_level = self.aggregator.update_profile_risk(
            profile.risk_score or 0.0, risk_contribution
        )

        # 4. Determine action
        mode = "monitor"
        deception_enabled = True
        if self.cfg:
            mode = getattr(self.cfg, 'mode', 'monitor')
            deception_enabled = getattr(self.cfg, 'deception_enabled', True)
            
        action = "allow"
        bait = None
        
        if mode == "enforce" and risk_level in ("critical", "high"):
            action = "block" if risk_level == "critical" else "alert"
        elif all_flags:
            action = "alert"
            
        # Deception injection: Suspected malicious intent (high risk but not critical)
        if deception_enabled and risk_level == "high" and mode == "enforce":
            bait = self.deception_engine.generate_contextual_bait(username, source_ip, target_service)
            action = "inject_bait"

        result.anomaly_score       = round(raw_score, 4)
        result.risk_contribution   = round(risk_contribution, 2)
        result.risk_score          = round(new_risk, 2)
        result.risk_level          = risk_level
        result.action              = action
        result.detectors_triggered = all_flags
        result.details             = {
            "scores": {
                "time": round(t_score, 3),
                "location": round(l_score, 3),
                "exfil": round(e_score, 3),
                "privilege": round(p_score, 3),
                "peer": round(pe_score, 3),
            }
        }
        
        if bait:
            result.details["deception_bait"] = bait

        # 5. Update profile baseline (skip learning if event is high/critical risk to prevent poisoning)
        skip_learning = (risk_level in ("high", "critical"))
        self._update_profile(
            profile, source_ip, target_service, bytes_transferred,
            session_duration, ts, new_risk, risk_level, skip_learning=skip_learning,
            cumulative_24h_bytes=cumulative_24h_bytes
        )

        # 6. Persist event to DB
        self._persist_event(
            username=username,
            source_ip=source_ip,
            target_service=target_service,
            bytes_transferred=bytes_transferred,
            session_duration=session_duration,
            event_time=datetime.fromtimestamp(ts, tz=timezone.utc),
            result=result,
            peer_group=peer_group or profile.peer_group,
        )

        self.logger.debug(
            "UBA [%s] score=%.3f risk=%s action=%s flags=%s",
            username, raw_score, risk_level, action, all_flags or "none",
        )

        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _get_or_create_profile(self, username: str, peer_group: Optional[str] = None, department: Optional[str] = None):
        if self.db is None:
            return _MemoryProfile(username, peer_group)

        from system.database.database import UBAUserProfile
        try:
            with self.db.sync_session() as session:
                profile = session.query(UBAUserProfile).filter_by(username=username).first()
                if profile is None:
                    cfg_min = 50
                    if self.cfg:
                        cfg_min = getattr(self.cfg, 'baseline_min_events', 50)
                    profile = UBAUserProfile(
                        username=username,
                        peer_group=peer_group or "",
                        baseline_min_events=cfg_min,
                    )
                    session.add(profile)
                    session.commit()
                    session.refresh(profile)
                else:
                    # Update peer_group if we now have one from ICE but didn't before
                    if peer_group and not profile.peer_group:
                        profile.peer_group = peer_group
                        session.commit()
                # Detach so we can read attrs outside the session
                session.expunge(profile)
                return profile
        except Exception as exc:
            self.logger.warning("UBA profile load failed: %s — using in-memory fallback", exc)
            return _MemoryProfile(username, peer_group)

    def _update_profile(
        self, profile, source_ip, target_service, bytes_transferred,
        session_duration, ts, new_risk, risk_level, skip_learning: bool = False,
        cumulative_24h_bytes: float = 0.0
    ):
        if self.db is None:
            return  # in-memory profile, nothing to persist

        from system.database.database import UBAUserProfile

        try:
            cfg_max_ips  = 30
            cfg_max_svcs = 100
            alpha        = 0.10
            if self.cfg:
                cfg_max_ips  = getattr(self.cfg, 'max_known_ips',     30)
                cfg_max_svcs = getattr(self.cfg, 'max_known_services', 100)
                alpha        = float(getattr(self.cfg, 'ema_alpha',    0.10))

            with self.db.sync_session() as session:
                p = session.query(UBAUserProfile).filter_by(username=profile.username).first()
                if p is None:
                    return

                if not skip_learning:
                    # Hour histogram
                    p.hour_histogram = self.time_det.update_histogram(
                        p.hour_histogram or {}, ts
                    )

                    # Known IPs
                    p.known_ips = self.location_det.update_known_ips(
                        p.known_ips or [], source_ip, cfg_max_ips
                    )

                    # Known services
                    p.known_services = self.privilege_det.update_known_services(
                        p.known_services or [], target_service, cfg_max_svcs
                    )

                    # Volume EMA (updated on day transition to store true daily volume average)
                    day_changed = False
                    if p.last_seen:
                        last_seen_date = p.last_seen.date()
                        now_date = datetime.now(timezone.utc).date()
                        if now_date != last_seen_date:
                            day_changed = True
                    else:
                        day_changed = True

                    if day_changed and cumulative_24h_bytes > 0:
                        p.avg_daily_bytes, p.daily_bytes_stddev, p.max_observed_bytes = (
                            self.exfil_det.update_baseline(p, cumulative_24h_bytes, alpha)
                        )
                    elif p.avg_daily_bytes == 0.0 and bytes_transferred > 0:
                        p.avg_daily_bytes, p.daily_bytes_stddev, p.max_observed_bytes = (
                            self.exfil_det.update_baseline(p, bytes_transferred, alpha)
                        )

                    # Session EMA (simple)
                    if session_duration > 0:
                        prev = p.avg_session_duration or session_duration
                        p.avg_session_duration = alpha * session_duration + (1 - alpha) * prev

                    # Learning state
                    p.event_count    = (p.event_count or 0) + 1
                    cfg_min = getattr(self.cfg, 'baseline_min_events', 50) if self.cfg else 50
                    if not p.baseline_locked and p.event_count >= cfg_min:
                        p.baseline_locked = True
                        self.logger.info("UBA baseline locked for user: %s", profile.username)

                # Risk state (always updated)
                p.risk_score  = new_risk
                p.risk_level  = risk_level

                p.last_seen  = datetime.now(timezone.utc)
                p.updated_at = datetime.now(timezone.utc)
                session.commit()

        except Exception as exc:
            self.logger.warning("UBA profile update failed: %s", exc)

    def _persist_event(self, *, username, source_ip, target_service,
                       bytes_transferred, session_duration, event_time,
                       result, peer_group):
        if self.db is None:
            return
        from system.database.database import UBAEvent
        try:
            with self.db.sync_session() as session:
                ev = UBAEvent(
                    username=username,
                    source_ip=source_ip,
                    target_service=target_service,
                    bytes_transferred=bytes_transferred,
                    session_duration=session_duration,
                    event_time=event_time,
                    anomaly_score=result.anomaly_score,
                    risk_contribution=result.risk_contribution,
                    detectors_triggered=result.detectors_triggered,
                    action_taken=result.action,
                    details=result.details,
                    peer_group=peer_group,
                )
                session.add(ev)
                session.commit()
        except Exception as exc:
            self.logger.warning("UBA event persist failed: %s", exc)

    def _get_peer_stats(self, peer_group: str) -> dict:
        """Return cached peer stats; refresh every 5 minutes."""
        if not peer_group or self.db is None:
            return {}
        now = time.time()
        if now - self._peer_cache_ts < 300 and peer_group in self._peer_cache:
            return self._peer_cache[peer_group]
        
        with self._lock:
            # Recheck after acquiring lock
            if now - self._peer_cache_ts < 300 and peer_group in self._peer_cache:
                return self._peer_cache[peer_group]
            try:
                from system.database.database import UBAUserProfile
                from sqlalchemy import func
                with self.db.sync_session() as session:
                    rows = (
                        session.query(
                            func.avg(UBAUserProfile.avg_daily_bytes).label("avg_bytes"),
                            func.avg(UBAUserProfile.daily_bytes_stddev).label("stddev_bytes"),
                            func.avg(UBAUserProfile.avg_session_duration).label("avg_session"),
                            func.count(UBAUserProfile.id).label("count"),
                        )
                        .filter(
                            UBAUserProfile.peer_group == peer_group,
                            UBAUserProfile.baseline_locked == True,
                        )
                        .one()
                    )
                    stats = {
                        "avg_daily_bytes":        float(rows.avg_bytes or 0),
                        "daily_bytes_stddev":     float(rows.stddev_bytes or 1),
                        "avg_session_duration":   float(rows.avg_session or 0),
                        "session_duration_stddev": float(rows.avg_session or 1) * 0.3,
                        "count":                  int(rows.count or 0),
                    }
                    self._peer_cache[peer_group] = stats
                    self._peer_cache_ts = now
                    return stats
            except Exception as exc:
                self.logger.debug("Peer stats query failed: %s", exc)
                return {}


# ── In-memory fallback (no DB) ────────────────────────────────────────────────

class _MemoryProfile:
    """Simple dict-based fallback profile when DB is unavailable."""

    def __init__(self, username: str, peer_group: Optional[str] = None):
        self.username = username
        self.peer_group = peer_group or ""
        self.typical_hours_start = 0
        self.typical_hours_end = 23
        self.hour_histogram = {}
        self.known_ips = []
        self.known_services = []
        self.avg_daily_bytes = 0.0
        self.daily_bytes_stddev = 0.0
        self.max_observed_bytes = 0.0
        self.avg_session_duration = 0.0
        self.avg_failed_logins = 0.0
        self.risk_score = 0.0
        self.risk_level = "low"
        self.event_count = 0
        self.baseline_locked = False
        self.baseline_min_events = 50
        self.last_seen = None
