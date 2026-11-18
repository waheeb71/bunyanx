"""
Enterprise bunyanx — UBA REST API
================================
Prefix: /api/v1/uba

Endpoints:
  GET    /status                        — Module status + live stats
  GET    /config                        — Read UBA config
  PUT    /config                        — Update UBA thresholds / mode
  GET    /users                         — List all user profiles
  GET    /users/{username}              — Single user profile + risk
  DELETE /users/{username}/reset        — Clear user baseline
  GET    /users/{username}/events       — Events for one user
  GET    /events                        — All events (paginated, filterable)
  GET    /alerts                        — High/critical events only
  POST   /events                        — Manually submit an event for analysis
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, Field, field_validator

from api.core.auth import require_admin, make_permission_checker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/uba", tags=["UBA"])

require_uba = make_permission_checker("uba")

# ── Security: Input Validation ────────────────────────────────────────────────
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_@.\-]{1,64}$")


def _validate_username(username: str) -> str:
    """Sanitize and validate username to prevent injection attacks."""
    if not username or not _USERNAME_RE.match(username):
        raise HTTPException(
            status_code=422,
            detail="Invalid username format. Allowed: alphanumeric, _, @, ., - (max 64 chars)"
        )
    return username


# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class DetectorWeights(BaseModel):
    time: Optional[float] = None
    exfil: Optional[float] = None
    location: Optional[float] = None
    peer: Optional[float] = None
    privilege: Optional[float] = None


class UBAConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    deception_enabled: Optional[bool] = None
    enable_auto_quarantine: Optional[bool] = None
    auto_quarantine_risk_score: Optional[int] = Field(None, ge=50, le=100)
    mode: Optional[str] = Field(None, description="monitor|enforce|learning")
    baseline_min_events: Optional[int] = Field(None, ge=10, le=1000)
    ema_alpha: Optional[float] = Field(None, ge=0.01, le=1.0)
    alert_on_risk_level: Optional[str] = None
    detector_weights: Optional[DetectorWeights] = None
    thresholds: Optional[Dict[str, float]] = None

    @field_validator("detector_weights")
    @classmethod
    def validate_weights_sum(cls, v):
        if v is not None:
            # v is now a DetectorWeights instance
            d = v.model_dump(exclude_none=True)
            total = sum(d.values())
            if total > 1.05:  # small tolerance for float math
                raise ValueError(f"detector_weights sum ({total:.2f}) must be ≤ 1.0")
            if any(w < 0 for w in d.values()):
                raise ValueError("detector_weights must be non-negative")
        return v

    @field_validator("alert_on_risk_level")
    @classmethod
    def validate_risk_level(cls, v):
        if v is not None and v not in ("low", "medium", "high", "critical"):
            raise ValueError("alert_on_risk_level must be one of: low, medium, high, critical")
        return v


class UBAEventSubmit(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    source_ip: str = ""
    target_service: str = ""
    bytes_transferred: float = Field(0.0, ge=0.0)
    session_duration: float = Field(0.0, ge=0.0)
    peer_group: Optional[str] = None
    event_time: Optional[datetime] = None

    @field_validator("username")
    @classmethod
    def validate_username_format(cls, v):
        if not _USERNAME_RE.match(v):
            raise ValueError("Invalid username format")
        return v


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db(request: Request = None):
    if request:
        bunyanx = getattr(request.app.state, "bunyanx", None) or getattr(request.app.state, "bunyanx_app", None)
        if bunyanx and hasattr(bunyanx, "db") and bunyanx.db:
            return bunyanx.db
    from system.database.database import _db_manager_ref, _ensure_db_manager
    return _db_manager_ref or _ensure_db_manager()


def _get_or_create_uba_config(db):
    from system.database.database import UBAConfig
    with db.sync_session() as session:
        cfg = session.query(UBAConfig).first()
        if cfg is None:
            cfg = UBAConfig()
            session.add(cfg)
            session.commit()
            session.refresh(cfg)
        return cfg


def _config_to_dict(cfg) -> dict:
    return {
        "enabled":                    cfg.enabled,
        "deception_enabled":          getattr(cfg, "deception_enabled", True),
        "enable_auto_quarantine":     getattr(cfg, "enable_auto_quarantine", True),
        "auto_quarantine_risk_score": getattr(cfg, "auto_quarantine_risk_score", 85),
        "mode":                       cfg.mode,
        "baseline_min_events":        cfg.baseline_min_events,
        "max_known_ips":              cfg.max_known_ips,
        "max_known_services":         cfg.max_known_services,
        "ema_alpha":                  cfg.ema_alpha,
        "detector_weights":           cfg.detector_weights or {},
        "thresholds":                 cfg.thresholds or {},
        "alert_on_risk_level":        cfg.alert_on_risk_level,
        "privileged_services":        cfg.privileged_services or [],
    }

def _profile_to_dict(p) -> dict:
    return {
        "username":              p.username,
        "peer_group":            p.peer_group,
        "risk_score":            p.risk_score,
        "risk_level":            p.risk_level,
        "event_count":           p.event_count,
        "baseline_locked":       p.baseline_locked,
        "known_ips_count":       len(p.known_ips or []),
        "known_services_count":  len(p.known_services or []),
        "avg_daily_bytes":       p.avg_daily_bytes,
        "avg_session_duration":  p.avg_session_duration,
        "typical_hours":         f"{p.typical_hours_start}:00–{p.typical_hours_end}:00",
        "last_seen":             p.last_seen.isoformat() if p.last_seen else None,
        "created_at":            p.created_at.isoformat() if p.created_at else None,
    }


def _get_profiler(request: Request = None):
    """Return a UserProfiler wired to the live DB+ config."""
    db = _get_db(request)
    from modules.uba.engine.core.user_profiler import UserProfiler
    try:
        cfg = _get_or_create_uba_config(db) if db else None
    except Exception:
        cfg = None
    return UserProfiler(db_manager=db, config=cfg)


# ── Endpoints ────────────────────────────────────────────────────────────────
@router.get("/status")
async def get_status(request: Request, token: dict = Depends(require_uba)):
    """Return live UBA module status."""
    try:
        db = _get_db(request)
        from system.database.database import UBAUserProfile, UBAEvent, UBAConfig
        with db.sync_session() as session:
            profile_count = session.query(UBAUserProfile).count()
            event_count   = session.query(UBAEvent).count()
            high_risk     = session.query(UBAUserProfile).filter(
                UBAUserProfile.risk_level.in_(["high", "critical"])
            ).count()
            cfg = session.query(UBAConfig).first()
            mode    = cfg.mode if cfg else "monitor"
            enabled = cfg.enabled if cfg else True
        return {
            "module":         "uba",
            "status":         "active" if enabled else "disabled",
            "mode":           mode,
            "version":        "2.0.0",
            "profiles_total": profile_count,
            "events_total":   event_count,
            "high_risk_users": high_risk,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("UBA status endpoint failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/config")
async def get_config(request: Request, token: dict = Depends(require_uba)):
    db = _get_db(request)
    cfg = _get_or_create_uba_config(db)
    return _config_to_dict(cfg)


@router.put("/config")
async def update_config(
    request: Request,
    update: UBAConfigUpdate,
    token: dict = Depends(require_admin),
):
    from system.database.database import UBAConfig
    db = _get_db(request)
    with db.sync_session() as session:
        cfg = session.query(UBAConfig).first()
        if cfg is None:
            cfg = UBAConfig()
            session.add(cfg)

        data = update.dict(exclude_none=True)
        valid_modes = ("monitor", "enforce", "learning")
        if "mode" in data and data["mode"] not in valid_modes:
            raise HTTPException(status_code=422, detail=f"mode must be one of {valid_modes}")

        for field, val in data.items():
            if hasattr(cfg, field):
                if isinstance(val, dict) and isinstance(getattr(cfg, field, None), dict):
                    merged = dict(getattr(cfg, field) or {})
                    merged.update(val)
                    setattr(cfg, field, merged)
                else:
                    setattr(cfg, field, val)

        session.commit()
        session.refresh(cfg)
        return {"status": "success", "config": _config_to_dict(cfg)}


@router.get("/users")
async def list_users(
    request: Request,
    username: Optional[str] = Query(None, description="Filter by username search query"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    peer_group: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAUserProfile
    db = _get_db(request)
    with db.sync_session() as session:
        q = session.query(UBAUserProfile)
        if username:
            q = q.filter(UBAUserProfile.username.ilike(f"%{username}%"))
        if risk_level:
            q = q.filter(UBAUserProfile.risk_level == risk_level)
        if peer_group:
            q = q.filter(UBAUserProfile.peer_group == peer_group)
        total = q.count()
        profiles = q.order_by(UBAUserProfile.risk_score.desc()).offset(offset).limit(limit).all()
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "users": [_profile_to_dict(p) for p in profiles],
        }


@router.get("/users/{username}")
async def get_user(
    request: Request,
    username: str,
    token: dict = Depends(require_uba),
):
    _validate_username(username)
    from system.database.database import UBAUserProfile, UBAEvent
    from api.services.dashboard.geoip_service import GeoIPService
    db = _get_db(request)
    with db.sync_session() as session:
        p = session.query(UBAUserProfile).filter_by(username=username).first()
        if p is None:
            raise HTTPException(status_code=404, detail=f"No UBA profile for '{username}'")
        
        # Query recent events for this user to get latest IP and accurate detector activity
        recent_events = (
            session.query(UBAEvent)
            .filter(UBAEvent.username == username)
            .order_by(UBAEvent.event_time.desc())
            .limit(100)
            .all()
        )

        user_ip = (
            recent_events[0].source_ip
            if recent_events and recent_events[0].source_ip
            else (p.known_ips[-1] if p.known_ips else "127.0.0.1")
        )

        # Resolve real GeoIP location using GeoLite2-City.mmdb
        geoip_info = GeoIPService.get_instance().resolve_ip_location(user_ip)

        # Calculate detector trigger breakdown and failed attempts
        detector_counts = {"time": 0, "location": 0, "exfil": 0, "privilege": 0, "peer": 0}
        failed_count = 0
        for ev in recent_events:
            if ev.action_taken in ("block", "quarantine", 7, 6) or (ev.anomaly_score or 0) > 0.7:
                failed_count += 1
            triggers = ev.detectors_triggered or []
            if isinstance(triggers, str):
                try:
                    import json
                    triggers = json.loads(triggers)
                except Exception:
                    triggers = [triggers]
            for t in triggers:
                t_str = str(t).lower()
                for k in detector_counts:
                    if k in t_str:
                        detector_counts[k] += 1

        total_trig = sum(detector_counts.values())

        result = _profile_to_dict(p)
        result["known_ips"]      = p.known_ips or []
        result["known_services"] = p.known_services or []
        result["hour_histogram"] = p.hour_histogram or {}
        result["ip"]             = user_ip
        result["failed_attempts"] = failed_count if recent_events else (int(p.event_count * 0.05) if p.event_count else 0)

        # Metrics for the profile radar chart
        if total_trig > 0:
            result["metrics"] = {
                "time_anomaly": round(min((detector_counts["time"] / total_trig) * 0.8 + (p.risk_score / 200.0), 1.0), 2),
                "location_drift": round(min((detector_counts["location"] / total_trig) * 0.8 + (p.risk_score / 200.0), 1.0), 2),
                "data_exfil": round(min((detector_counts["exfil"] / total_trig) * 0.8 + (p.risk_score / 200.0), 1.0), 2),
                "privilege_escalation": round(min((detector_counts["privilege"] / total_trig) * 0.8 + (p.risk_score / 200.0), 1.0), 2),
                "peer_deviation": round(min((detector_counts["peer"] / total_trig) * 0.8 + (p.risk_score / 200.0), 1.0), 2),
            }
        else:
            base_factor = min(p.risk_score / 100.0, 1.0)
            result["metrics"] = {
                "time_anomaly": round(base_factor * 0.3, 2),
                "location_drift": round(base_factor * 0.25, 2),
                "data_exfil": round(base_factor * 0.45, 2),
                "privilege_escalation": round(base_factor * 0.35, 2),
                "peer_deviation": round(base_factor * 0.2, 2),
            }

        result["geoip"] = geoip_info
        return result



@router.delete("/users/{username}/reset", status_code=status.HTTP_200_OK)
async def reset_user(
    request: Request,
    username: str,
    token: dict = Depends(require_admin),
):
    """Clear a user's behavioral baseline (admin only)."""
    _validate_username(username)
    from system.database.database import UBAUserProfile
    db = _get_db(request)
    with db.sync_session() as session:
        p = session.query(UBAUserProfile).filter_by(username=username).first()
        if p is None:
            raise HTTPException(status_code=404, detail=f"No UBA profile for '{username}'")
        session.delete(p)
        session.commit()
    admin_id = token.get("sub", "unknown_admin")
    logger.info("UBA profile reset for user: %s by admin: %s", username, admin_id)
    return {"status": "success", "message": f"Baseline reset for '{username}'"}



@router.get("/users/{username}/events")
async def get_user_events(
    request: Request,
    username: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    token: dict = Depends(require_uba),
):
    _validate_username(username)
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.sync_session() as session:
        q = (
            session.query(UBAEvent)
            .filter(UBAEvent.username == username)
            .filter(UBAEvent.anomaly_score >= min_score)
            .order_by(UBAEvent.event_time.desc())
        )
        total = q.count()
        events = q.offset(offset).limit(limit).all()
        return {
            "username": username,
            "total": total,
            "events": [e.to_dict() for e in events],
        }


@router.get("/events")
async def get_events(
    request: Request,
    min_score: float = Query(0.0, ge=0.0, le=1.0, description="Min anomaly score"),
    risk_level: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    token: dict = Depends(require_uba),
):
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.sync_session() as session:
        q = session.query(UBAEvent).filter(UBAEvent.anomaly_score >= min_score)
        if username:
            q = q.filter(UBAEvent.username == username)
        total = q.count()
        events = q.order_by(UBAEvent.event_time.desc()).offset(offset).limit(limit).all()
        return {"total": total, "events": [e.to_dict() for e in events]}


@router.get("/alerts")
async def get_alerts(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    token: dict = Depends(require_uba),
):
    """Return high/critical-risk events."""
    from system.database.database import UBAEvent
    db = _get_db(request)
    with db.sync_session() as session:
        events = (
            session.query(UBAEvent)
            .filter(UBAEvent.anomaly_score >= 0.5)
            .order_by(UBAEvent.event_time.desc())
            .limit(limit)
            .all()
        )
        return {"total": len(events), "alerts": [e.to_dict() for e in events]}


@router.post("/events", status_code=status.HTTP_200_OK)
async def submit_event(
    request: Request,
    event: UBAEventSubmit,
    token: dict = Depends(require_admin),
):
    """Manually submit a behavioral event for UBA analysis (admin only)."""
    try:
        profiler = _get_profiler(request)
        result = profiler.analyze(
            username=event.username,
            source_ip=event.source_ip,
            target_service=event.target_service,
            bytes_transferred=event.bytes_transferred,
            session_duration=event.session_duration,
            event_time=event.event_time.timestamp() if event.event_time else None,
            peer_group=event.peer_group,
        )
        return {"status": "analyzed", "result": result.to_dict()}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("UBA event submission failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ── Demo Endpoints for UBA Deception (Patent PoC) ─────────────────────────────

class UBADemoAccess(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    target_service: str
    simulated_risk_score: float = Field(0.6, ge=0.0, le=1.0)

    @field_validator("username")
    @classmethod
    def validate_demo_username(cls, v):
        if not _USERNAME_RE.match(v):
            raise ValueError("Invalid username format")
        return v

@router.post("/demo/file_access")
async def demo_file_access(
    request: Request,
    data: UBADemoAccess,
    token: dict = Depends(require_admin),
):
    """
    Simulates a high-risk access attempt that triggers the Honeytoken bait.
    Requires admin authentication.
    """
    from modules.uba.engine.core.uba_deception import UBAHoneytokenEngine
    db = _get_db(request)
    cfg = _get_or_create_uba_config(db)
    
    if not getattr(cfg, "deception_enabled", True):
        return {"access": "granted", "files": ["Public_Policy.pdf", "Holiday_Calendar.pdf"], "status": "Normal Access"}

    # Simulate UBA Profiler analysis where score > threshold
    if data.simulated_risk_score >= 0.4:
        engine = UBAHoneytokenEngine()
        bait_payload = engine.generate_contextual_bait(
            username=data.username, 
            source_ip="10.0.0.99", 
            target_service=data.target_service
        )
        return {
            "access": "granted_with_monitoring",
            "message": f"Anomalous access detected (Score: {data.simulated_risk_score}). Injecting bait.",
            "response_data": bait_payload
        }
    
    return {"access": "granted", "files": ["Public_Policy.pdf"], "status": "Normal Access"}

@router.post("/demo/open_honeytoken")
async def demo_open_honeytoken(
    token_payload: dict,
    token: dict = Depends(require_admin),
):
    """
    Simulates the attacker interacting with the generated Honeytoken.
    Requires admin authentication.
    """
    from modules.uba.engine.core.uba_deception import UBAHoneytokenEngine
    engine = UBAHoneytokenEngine()
    
    # Check if the payload matches an active honeytoken
    payload_str = str(token_payload)
    is_accessed, evidence = engine.verify_honeytoken_access(payload_str)
    
    if is_accessed:
        return {
            "uba_action": "ACCOUNT_LOCKED",
            "threat_score": 1.0,
            "reason": evidence
        }
    return {"uba_action": "IGNORE", "message": "No honeytoken detected in payload."}
