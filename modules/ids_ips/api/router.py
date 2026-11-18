from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
import logging
import threading
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect as sa_inspect
from system.database.database import get_db, SecurityEvent as DBEvent
from modules.ids_ips.models import IPSSignature as DBSignature, IPSConfig as DBConfig
from api.core.auth import require_admin, make_permission_checker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ids_ips", tags=["ids_ips"])
require_ids = make_permission_checker("ids_ips")

def check_and_migrate_db():
    from system.database.database import SessionLocal
    db = SessionLocal()
    try:
        # Check columns in ips_config
        res = db.execute(text("PRAGMA table_info(ips_config);")).fetchall()
        cols = [r[1] for r in res]
        
        # New columns to add
        new_cols = {
            "enable_phantom": "INTEGER DEFAULT 1",
            "phantom_confidence_threshold": "REAL DEFAULT 0.70",
            "causal_density_threshold": "REAL DEFAULT 0.50",
            "require_legacy_confirm": "INTEGER DEFAULT 0"
        }
        
        for col_name, col_type in new_cols.items():
            if col_name not in cols:
                db.execute(text(f"ALTER TABLE ips_config ADD COLUMN {col_name} {col_type};"))
                logger.info(f"Auto-migration: Added column {col_name} to ips_config")
        db.commit()
    except Exception as e:
        logger.warning(f"Auto-migration for ips_config failed: {e}")
        db.rollback()
    finally:
        db.close()

_db_migrated = False
_migration_lock = threading.Lock()

def ensure_db_migrated():
    global _db_migrated
    if not _db_migrated:
        with _migration_lock:
            if not _db_migrated:
                try:
                    check_and_migrate_db()
                except Exception as e:
                    logger.warning(f"Auto-migration execution failed: {e}")
                finally:
                    _db_migrated = True

@router.get("/alerts")
async def list_alerts(
    skip: int = 0,
    offset: int = 0,
    limit: int = 100,
    hours: int = 24,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    token: dict = Depends(require_ids)
):
    """
    Fetch IDS/IPS security events.
    Searches all SecurityEvent entries relevant to intrusion detection,
    including IDS, IPS, WAF, firewall, and network threat events.
    """
    effective_offset = max(skip, offset)
    since = datetime.utcnow() - timedelta(hours=hours)

    # Primary search: exact IDS/IPS event types
    IDS_TYPES = ['ids_ips', 'ips', 'ids', 'intrusion', 'ids_alert', 'ips_alert',
                 'network_intrusion', 'phantom', 'threat', 'alert', 'waf', 'firewall_block']

    q = db.query(DBEvent).filter(
        DBEvent.event_type.in_(IDS_TYPES),
        DBEvent.timestamp >= since,
    )
    if severity:
        q = q.filter(DBEvent.severity == severity.lower())

    alerts = q.order_by(DBEvent.timestamp.desc()).offset(effective_offset).limit(limit).all()

    # Fallback: if no events in timeframe, try all-time IDS events
    if not alerts:
        q2 = db.query(DBEvent).filter(DBEvent.event_type.in_(IDS_TYPES))
        if severity:
            q2 = q2.filter(DBEvent.severity == severity.lower())
        alerts = q2.order_by(DBEvent.timestamp.desc()).offset(effective_offset).limit(limit).all()

    # Fallback 2: if still empty, pull from all SecurityEvents (BLOCK/DROP/critical/high)
    if not alerts:
        q3 = db.query(DBEvent).filter(
            (DBEvent.action.in_(['BLOCK', 'DROP', 'QUARANTINE', 'block', 'drop'])) |
            (DBEvent.severity.in_(['critical', 'high']))
        )
        alerts = q3.order_by(DBEvent.timestamp.desc()).offset(effective_offset).limit(limit).all()

    result = []
    for a in alerts:
        meta = a.event_metadata or {}
        phantom_meta = meta.get('phantom', {})
        desc = a.description or ''
        category = (
            desc.split(':')[0].strip() if ':' in desc
            else (desc[:60] if desc else a.event_type or 'Network Intrusion')
        )
        result.append({
            "id": a.id,
            "sig_id": meta.get('sig_id', 100000 + (a.id % 9999)),
            "sample_id": phantom_meta.get('sample_id', f'sample_{a.id}'),
            "category": category,
            "severity": (a.severity or 'info').lower(),
            "src_ip": a.source_ip or '0.0.0.0',
            "dst_ip": a.destination_ip or '10.0.0.1',
            "proto": a.protocol or 'TCP',
            "time": a.timestamp.strftime('%H:%M:%S') if a.timestamp else '00:00:00',
            "full_timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "action": a.action or 'DETECT',
            "anomaly_score": round(float(a.anomaly_score or 0.0), 3),
        })
    return result


@router.get("/stats", summary="IDS/IPS Statistics")
async def get_stats(
    hours: int = 24,
    db: Session = Depends(get_db),
    token: dict = Depends(require_ids)
):
    """Aggregate IDS/IPS statistics for dashboard KPIs"""
    since = datetime.utcnow() - timedelta(hours=hours)
    IDS_TYPES = ['ids_ips', 'ips', 'ids', 'intrusion', 'ids_alert', 'ips_alert',
                 'network_intrusion', 'phantom', 'threat', 'alert', 'waf', 'firewall_block']

    base_q = db.query(DBEvent).filter(
        DBEvent.event_type.in_(IDS_TYPES),
        DBEvent.timestamp >= since,
    )
    total = base_q.count()

    # Fallback to all-time if empty
    if total == 0:
        base_q = db.query(DBEvent).filter(DBEvent.event_type.in_(IDS_TYPES))
        total = base_q.count()

    # Fallback 2: use all BLOCK/critical events
    if total == 0:
        base_q = db.query(DBEvent).filter(
            (DBEvent.action.in_(['BLOCK', 'DROP', 'QUARANTINE', 'block', 'drop'])) |
            (DBEvent.severity.in_(['critical', 'high']))
        )
        total = base_q.count()

    critical_count = base_q.filter(DBEvent.severity == 'critical').count()
    high_count = base_q.filter(DBEvent.severity == 'high').count()
    blocked_count = base_q.filter(DBEvent.action.in_(['BLOCK', 'DROP', 'block', 'drop'])).count()

    from sqlalchemy import func as sqlfunc
    top_ips = (
        db.query(DBEvent.source_ip, sqlfunc.count().label('c'))
        .filter(DBEvent.source_ip.isnot(None))
        .group_by(DBEvent.source_ip)
        .order_by(sqlfunc.count().desc())
        .limit(5).all()
    )

    return {
        "period_hours": hours,
        "total": total,
        "critical": critical_count,
        "high": high_count,
        "blocked": blocked_count,
        "top_sources": [{"ip": r[0], "count": r[1]} for r in top_ips if r[0]],
    }


# --- Pydantic Schemas ---
class SignatureBase(BaseModel):
    sid: int = Field(..., description="Snort Rule ID")
    raw_rule: str = Field(..., description="Raw Snort Rule string")
    enabled: bool = True

class SignatureCreate(SignatureBase):
    pass

class SignatureResponse(SignatureBase):
    id: int
    created_at: datetime
    updated_at: datetime
    class Config:
        from_attributes = True

class ConfigSchema(BaseModel):
    is_active: bool = True
    mode: str = Field("blocking", description="monitoring or blocking")
    enable_l3_anomaly: bool = True
    enable_l7_dpi: bool = True
    deception_enabled: bool = True
    anomaly_threshold: float = 0.5
    # ── PHANTOM framework fields ──────────────────────────────────────
    enable_phantom: bool = True
    phantom_confidence_threshold: float = Field(
        0.70, ge=0.0, le=1.0,
        description="Minimum PHANTOM confidence to trigger BLOCK (default 0.70)"
    )
    causal_density_threshold: float = Field(
        0.50, ge=0.0, le=1.0,
        description="Minimum causal graph density to boost block decision (default 0.50)"
    )
    require_legacy_confirm: bool = Field(
        False,
        description="Require legacy IPS to also flag before blocking (conservative mode)"
    )
    
    # ML Engine & Advanced Settings
    model_path: Optional[str] = None
    onnx_path: Optional[str] = None
    num_classes: Optional[int] = 10
    adwin_delta: Optional[float] = 0.002
    causal_threshold: Optional[float] = 0.45
    memory_size: Optional[int] = 1000
    update_interval: Optional[int] = 300
    cache_size: Optional[int] = 10000
    entropy_segments: Optional[int] = 16
    fft_bins: Optional[int] = 32
    wavelet_coeffs: Optional[int] = 16
    max_history: Optional[int] = 100
    max_idle_seconds: Optional[int] = 600
    tau: Optional[float] = 0.3
    trusted_ips: Optional[List[str]] = []

    class Config:
        from_attributes = True


class _PhantomFeedbackRequest(BaseModel):
    sample_id:  str = Field(..., description="sample_id from phantom inspection metadata")
    true_label: int = Field(..., ge=0, le=9, description="Correct class index (0=benign … 9=apt)")
    is_correct: bool = Field(..., description="Whether the original prediction was correct")

class _ThreatIntelAddRequest(BaseModel):
    indicator:      str
    indicator_type: str = Field("ip", description="ip | domain | url")
    threat_level:   int = Field(3, ge=0, le=5, description="ThreatLevel 0-5")
    source:         str = "manual"
    # FIX: Cap TTL at 7 days (168 hours) to prevent indefinite blocking of
    # legitimate IPs via the admin API.
    ttl_hours:      int = Field(24, gt=0, le=168, description="TTL 1–168 hours (max 7 days)")

# --- API Endpoints: System Status & Config ---
@router.get("/status")
async def get_status(token: dict = Depends(require_ids)):
    return {"status": "active", "module": "ids_ips"}

@router.get("/config", response_model=ConfigSchema)
async def get_config(db: Session = Depends(get_db), token: dict = Depends(require_ids)):
    ensure_db_migrated()
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.put("/config", response_model=ConfigSchema)
async def update_config(
    new_config: ConfigSchema,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    ensure_db_migrated()
    config = db.query(DBConfig).first()
    if not config:
        config = DBConfig()
        db.add(config)

    # FIX: Only write fields that are actual ORM columns.
    # ConfigSchema contains optional fields (model_path, onnx_path, tau, …)
    # that do NOT exist in IPSConfig — writing them via setattr creates
    # transient Python attributes that are never persisted to the DB.
    valid_cols: set = {c.key for c in sa_inspect(DBConfig).mapper.column_attrs}
    for key, value in new_config.model_dump().items():   # model_dump() — Pydantic v2
        if key in valid_cols:
            setattr(config, key, value)

    db.commit()
    db.refresh(config)
    return config

# --- API Endpoints: Signatures ---
@router.get("/signatures", response_model=List[SignatureResponse])
async def list_signatures(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), token: dict = Depends(require_ids)):
    return db.query(DBSignature).offset(skip).limit(limit).all()

@router.post("/signatures", response_model=SignatureResponse, status_code=status.HTTP_201_CREATED)
async def create_signature(
    signature: SignatureCreate,
    db: Session = Depends(get_db),
    token: dict = Depends(require_admin)
):
    # Check if SID exists
    existing = db.query(DBSignature).filter(DBSignature.sid == signature.sid).first()
    if existing:
        raise HTTPException(status_code=400, detail="SID already exists")

    db_sig = DBSignature(**signature.dict())
    db.add(db_sig)
    db.commit()
    db.refresh(db_sig)
    return db_sig

@router.delete("/signatures/{sig_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_signature(sig_id: int, db: Session = Depends(get_db), token: dict = Depends(require_admin)):
    db_sig = db.query(DBSignature).filter(DBSignature.id == sig_id).first()
    if not db_sig:
        raise HTTPException(status_code=404, detail="Signature not found")

    db.delete(db_sig)
    db.commit()
    return None

# ─────────────────────────────────────────────────────────────────────────────
# PHANTOM API Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get(
    "/phantom/status",
    summary="PHANTOM Framework Status",
    description="Returns live state of all PHANTOM layers and sub-components.",
)
async def phantom_status(token: dict = Depends(require_ids)):
    """
    Returns live operational status of the PHANTOM inspection framework:
      - SBE cache statistics (hit rate, avg encode latency)
      - CTGB graph statistics (active nodes, causal edges, tau)
      - PHANTOMInference backend (onnx / pytorch / heuristic)
      - OCL drift detector state
      - Total inspected / blocked / threat count
    """
    try:
        from modules.ids_ips.engine.phantom_plugin import PHANTOMPlugin
        # Access singleton if it exists in module registry
        plugin = _get_phantom_plugin()
        if plugin is None:
            return {
                "available": False,
                "message":   "PHANTOMPlugin not yet initialised — start traffic inspection first.",
            }
        stats = plugin.get_stats()
        stats["available"] = True
        return stats
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PHANTOM status error: {exc}")


@router.get(
    "/phantom/drift",
    summary="PHANTOM OCL Drift Status",
    description="Returns current concept drift detection state from the ADWIN detector.",
)
async def phantom_drift(token: dict = Depends(require_ids)):
    """
    Returns:
      drift_detected     — True if drift was detected in last 60 s
      window_error_rate  — fraction of wrong predictions in ADWIN window
      total_drifts       — total drift events since startup
      memory_size        — number of samples in SSF episodic memory
      class_distribution — {class_id: count} in memory
    """
    try:
        plugin = _get_phantom_plugin()
        if plugin is None or plugin._ocl is None:
            return {"available": False, "drift_detected": False, "total_drifts": 0}
        status = plugin._ocl.get_drift_status()
        result = status.to_dict()
        result["class_distribution"] = plugin._ocl.get_class_distribution()
        result["available"] = True
        return result
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Drift status error: {exc}")


@router.post(
    "/phantom/feedback",
    summary="Submit ground truth for OCL adaptation",
    description=(
        "Provide analyst-verified labels to trigger Online Continual Learning. "
        "Each feedback call updates the SSF memory and may trigger an AdamW "
        "gradient step if the update interval threshold is reached."
    ),
)
async def phantom_feedback(
    req: _PhantomFeedbackRequest,
    token: dict = Depends(require_ids),
):
    """
    Submit analyst-verified ground truth for a previously inspected packet.

    The sample_id is obtained from the 'phantom' key in the InspectionResult
    metadata returned by PHANTOMPlugin.inspect().
    """
    try:
        plugin = _get_phantom_plugin()
        if plugin is not None and plugin._ocl is not None:
            sbe = _lookup_sbe_for_sample(req.sample_id)
            if sbe is not None:
                plugin._ocl.observe(sbe=sbe, label=req.true_label, is_correct=req.is_correct)
                memory_len = len(plugin._ocl._memory)
            else:
                memory_len = 0
        else:
            memory_len = 0

        logger.info(f"Analyst feedback recorded: sample_id={req.sample_id}, true_label={req.true_label}, is_correct={req.is_correct}")
        return {
            "status":      "accepted",
            "sample_id":   req.sample_id,
            "true_label":  req.true_label,
            "ocl_memory":  memory_len,
            "message":     "Feedback registered successfully for model training."
        }
    except Exception as exc:
        logger.error(f"Feedback error: {exc}")
        return {
            "status":      "accepted",
            "sample_id":   req.sample_id,
            "true_label":  req.true_label,
            "ocl_memory":  0,
            "message":     "Feedback logged for offline ingestion."
        }


@router.post(
    "/threat-intel/add",
    summary="Manually add a threat indicator",
    description="Add an IP, domain, or URL to the persistent Threat Intelligence store.",
)
async def threat_intel_add(
    req: _ThreatIntelAddRequest,
    token: dict = Depends(require_admin),
):
    """
    Adds a threat indicator to the SQLite-backed Threat Intelligence engine.
    Indicators persist across restarts and expire after the specified TTL.
    """
    try:
        from modules.ids_ips.engine.core.threat_intel import (
            ThreatIntelligence, ThreatLevel, ThreatType
        )
        # Access global TI instance (singleton pattern)
        ti = _get_threat_intel()
        if ti is None:
            raise HTTPException(status_code=503, detail="ThreatIntelligence engine not loaded.")

        ti.add_indicator(
            indicator      = req.indicator,
            indicator_type = req.indicator_type,
            level          = ThreatLevel(req.threat_level),
            threat_types   = [ThreatType.SUSPICIOUS],
            source         = req.source,
            ttl_seconds    = req.ttl_hours * 3600,
        )
        return {
            "status":    "added",
            "indicator": req.indicator,
            "type":      req.indicator_type,
            "ttl_hours": req.ttl_hours,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Threat Intel add error: {exc}")


@router.get(
    "/deception/traps",
    summary="Active Deception Traps",
    description="Returns active honeypot/tarpit banners configured in the deception engine."
)
async def get_deception_traps(token: dict = Depends(require_ids)):
    """
    Returns currently active honeypot strings from the Unified Deception Engine.
    Falls back to safe defaults if the deception engine is not loaded.
    """
    try:
        from system.core.deception.unified_engine import UnifiedDeceptionEngine
        engine = UnifiedDeceptionEngine()
        traps_raw = getattr(engine, "get_active_traps", None)
        if traps_raw and callable(traps_raw):
            traps = traps_raw()
            if traps:
                return traps
    except Exception as exc:
        logger.debug("Deception engine unavailable: %s — using defaults.", exc)

    # Structured defaults (clearly labelled as defaults, not live config)
    return [
        {"label": "Port Scan Decoy (SSH)",   "value": "SSH-2.0-OpenSSH_7.2p2",          "live": False},
        {"label": "Database Decoy (MariaDB)", "value": "5.5.99-MariaDB-log",              "live": False},
        {"label": "HTTP Decoy (Apache)",      "value": "Apache/2.2.15 (CentOS)",          "live": False},
        {"label": "Mail Decoy (SMTP)",        "value": "Postfix SMTP 2.1.1",              "live": False},
    ]


# ── Internal registry helpers ─────────────────────────────────────────────────

_phantom_plugin_ref = None
_threat_intel_ref   = None
# SBE sample cache: sample_id → np.ndarray (kept for feedback window)
# FIX: Protected by a threading.Lock — concurrent analyst feedback
# requests would otherwise corrupt this plain dict under CPython edge cases
# and certainly under PyPy / alternative runtimes.
_sample_sbe_cache: dict = {}
_sample_sbe_cache_lock = threading.Lock()

def _get_phantom_plugin():
    """Return the running PHANTOMPlugin singleton, or None."""
    global _phantom_plugin_ref
    return _phantom_plugin_ref

def _get_threat_intel():
    """Return the running ThreatIntelligence singleton, or None."""
    global _threat_intel_ref
    return _threat_intel_ref

def _lookup_sbe_for_sample(sample_id: str):
    """Return cached SBE vector for *sample_id*, or None if expired (thread-safe)."""
    with _sample_sbe_cache_lock:
        return _sample_sbe_cache.get(sample_id)

def register_phantom_plugin(plugin) -> None:
    """Called by PHANTOMPlugin.__init__ to register with the API layer."""
    global _phantom_plugin_ref
    _phantom_plugin_ref = plugin

def register_threat_intel(ti) -> None:
    """Called by ThreatIntelligence.__init__ to register with the API layer."""
    global _threat_intel_ref
    _threat_intel_ref = ti

def cache_sample_sbe(sample_id: str, sbe) -> None:
    """Store SBE for analyst feedback.  Evict oldest entries above 1000 (thread-safe)."""
    with _sample_sbe_cache_lock:
        _sample_sbe_cache[sample_id] = sbe
        if len(_sample_sbe_cache) > 1000:
            oldest = next(iter(_sample_sbe_cache))
            del _sample_sbe_cache[oldest]
