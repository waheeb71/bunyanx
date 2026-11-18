"""
Enterprise bunyanx WAF — API Router

─── GNN Model ──────────────────────────────────────────────
  GET  /api/v1/waf/gnn/status           - GNN model status and config
  GET  /api/v1/waf/gnn/logs             - Session logs metadata + preview
  POST /api/v1/waf/gnn/logs/flush       - Force-flush log buffer to CSV
  POST /api/v1/waf/gnn/train            - Start background GNN training
  GET  /api/v1/waf/gnn/train/status     - Training job progress
  PUT  /api/v1/waf/gnn/activate         - Hot-swap newly trained model
  PUT  /api/v1/waf/gnn/toggle           - Enable/disable GNN at runtime

─── Core Status ────────────────────────────────────────────
  GET  /api/v1/waf/status               - WAF module status + feature flags
  GET  /api/v1/waf/settings             - Full snapshot of all settings
  POST /api/v1/waf/settings/reload      - Reload settings from YAML
  PUT  /api/v1/waf/settings/master      - Enable/disable WAF (master switch)
  PUT  /api/v1/waf/settings/mode        - Set mode: enforce | monitor | learning

─── AI Model Control ───────────────────────────────────────
  PUT  /api/v1/waf/models/{model}/toggle  - Toggle any model on/off
  PUT  /api/v1/waf/models/{model}/config  - Set threshold + weight (nlp/gaf/temporal/gnn/anomaly)
  PUT  /api/v1/waf/bot/config             - Bot detection: action, threshold, weight

─── Risk & Scoring ─────────────────────────────────────────
  PUT  /api/v1/waf/risk_thresholds      - Update allow/challenge/block thresholds

─── Defense Config ─────────────────────────────────────────
  PUT  /api/v1/waf/threat_intel/config  - Toggle threat intel feeds
  PUT  /api/v1/waf/honeypot/config      - Honeypot: score_boost, TTL, paths
  PUT  /api/v1/waf/deception/config     - Deception engine: threshold, TTL
  PUT  /api/v1/waf/ato/config           - ATO protector: limits and window
  PUT  /api/v1/waf/graphql/config       - GraphQL inspector: depth, batch, introspection
  PUT  /api/v1/waf/preprocessing/config - Decoder chain toggles
  PUT  /api/v1/waf/waap/rate_limiter/config  - Rate limiter params
  PUT  /api/v1/waf/waap/toggle/{feature}     - Toggle WAAP features
  PUT  /api/v1/waf/dynamic_amplifiers/config - Risk scoring dynamic multipliers

─── IP Access Lists ────────────────────────────────────────
  PUT  /api/v1/waf/ip/whitelist         - Replace whitelist
  POST /api/v1/waf/ip/whitelist/add     - Append to whitelist
  PUT  /api/v1/waf/ip/blacklist         - Replace blacklist
  POST /api/v1/waf/ip/blacklist/add     - Append to blacklist

─── WAAP & Shadow Mode ─────────────────────────────────────
  POST /api/v1/waf/waap/api_schema/upload      - Upload OpenAPI schema
  POST /api/v1/waf/waap/shadow_mode/start      - Start shadow learning
  POST /api/v1/waf/waap/shadow_mode/stop       - Stop shadow learning
  GET  /api/v1/waf/waap/shadow_mode/status     - Shadow mode progress
  GET  /api/v1/waf/waap/shadow_mode/export     - Export learned schema
"""
import logging
import os
import jwt
import asyncio
from typing import Optional, Dict, Any
from fastapi import APIRouter, BackgroundTasks, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query
from pydantic import BaseModel

from api.core.auth import require_admin, make_permission_checker, SECRET_KEY, ALGORITHM
from modules.waf.api.live_monitor import waf_dispatcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/waf", tags=["WAF"])

# ── Resource permission shorthand ────────────────────
# Admins pass automatically. Any other user needs a DB rule: resource="waf"
require_waf = make_permission_checker("waf")


# ── Request / Response models ───────────────────────

class TrainRequest(BaseModel):
    epochs:      int  = 30
    n_synthetic: int  = 500    # fallback synthetic sessions if no real logs

class ToggleRequest(BaseModel):
    enabled: bool

class ActivateRequest(BaseModel):
    model_path: Optional[str] = None   # if None, auto-detect latest

class RateLimitConfigRequest(BaseModel):
    global_rate_limit: int
    ip_rate_limit: int
    user_rate_limit: int
    adaptive_ratelimit: bool

class APISchemaUploadRequest(BaseModel):
    endpoint: str
    schema_definition: Dict[str, Any]

class ShadowModeStartRequest(BaseModel):
    hours: int = 72

# ── Lazy imports (avoid circular imports) ───────────

def _get_waf_settings():
    from modules.waf.engine.core.settings import get_waf_settings
    return get_waf_settings()

def _get_collector():
    """Retrieve the global SessionLogCollector, if initialized."""
    try:
        from modules.waf.engine.waf_inspector import _gnn_log_collector
        return _gnn_log_collector
    except (ImportError, AttributeError):
        return None

def _get_gnn_inference():
    """Retrieve the live GNN inference instance, if available."""
    try:
        from modules.waf.engine.waf_inspector import _live_gnn_model
        return _live_gnn_model
    except (ImportError, AttributeError):
        return None

def _get_shadow_autopilot():
    """Retrieve the global Shadow Autopilot instance."""
    try:
        from modules.waf.engine.waf_inspector import _live_shadow_autopilot
        return _live_shadow_autopilot
    except (ImportError, AttributeError):
        return None

# ── WAF Core Endpoints ─────────────────────────────

@router.get("/status")
async def waf_status(token: dict = Depends(require_waf)):
    """Overall WAF module status and active feature flags."""
    try:
        cfg = _get_waf_settings()
        stats = {"inspected": 0, "detected": 0, "blocked": 0, "challenged": 0}
        try:
            from system.core.framework.pipeline import _global_pipeline
            for plugin in _global_pipeline.get_plugins():
                if plugin.name == "waf_ai_inspector":
                    stats["inspected"] = getattr(plugin, "_inspected_count", 0)
                    stats["detected"] = getattr(plugin, "_detected_count", 0)
                    stats["blocked"] = getattr(plugin, "_blocked_count", 0)
                    stats["challenged"] = getattr(plugin, "_challenged_count", 0)
                    break
        except ImportError:
            pass
        except Exception as e:
            logger.warning("Failed to retrieve WAF stats from pipeline: %s", e)

        return {
            "waf_enabled":     cfg.enabled,
            "mode":            cfg.mode,
            "monitored_ports": cfg.monitored_ports,
            "stats":           stats,
            "features": {
                "preprocessing":  cfg.preprocessing.enabled,
                "nlp":            cfg.nlp.enabled,
                "bot_detection":  cfg.bot.enabled,
                "gnn":            cfg.gnn.enabled,
                "anomaly":        cfg.anomaly.enabled,
                "threat_intel":   cfg.threat_intel.enabled,
                "honeypot":       cfg.honeypot.enabled,
                "waap_api_schema": cfg.api_schema.enabled,
                "waap_fingerprint": cfg.fingerprint.enabled,
                "waap_ato":       cfg.ato_protector.enabled,
                "waap_rate_limit": cfg.rate_limiter.enabled,
                "waap_graphql":   cfg.graphql_inspector.enabled,
                "xai_explainer":  cfg.xai_explainer.enabled,
                "self_learning":  getattr(cfg, 'self_learning', None) and cfg.self_learning.enabled,
                "deception_engine": getattr(cfg, 'deception_engine', None) and cfg.deception_engine.enabled,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── WAF Events & Feed Query ────────────────────────
@router.get("/events")
async def get_waf_events(
    limit: int = 50,
    offset: int = 0,
    token: dict = Depends(require_waf)
):
    """Return recent and persistent WAF security events."""
    try:
        from modules.waf.api.live_monitor import waf_dispatcher
        mem_events = waf_dispatcher.get_recent_events()
        
        db_events = []
        try:
            from system.database.database import _ensure_db_manager, SecurityEvent
            db = _ensure_db_manager()
            if db:
                with db.sync_session() as session:
                    rows = (
                        session.query(SecurityEvent)
                        .filter(SecurityEvent.event_type.in_(["waf", "waap", "WAF", "WAAP"]))
                        .order_by(SecurityEvent.timestamp.desc())
                        .limit(limit)
                        .all()
                    )
                    for r in rows:
                        meta = r.event_metadata or {}
                        db_events.append({
                            "id": meta.get("id") or r.id,
                            "time": r.timestamp.strftime("%H:%M:%S") if r.timestamp else "00:00:00",
                            "ip": r.source_ip or "0.0.0.0",
                            "path": meta.get("path", "/"),
                            "action": r.action or "BLOCK",
                            "risk": f"{r.anomaly_score:.2f}" if r.anomaly_score is not None else "0.85",
                            "cause": r.description or "هجوم WAF تم صده",
                            "severity": (r.severity or "HIGH").upper(),
                            "method": meta.get("method", "POST"),
                        })
        except Exception as _e:
            logger.debug("DB WAF events query error: %s", _e)

        combined = []
        seen = set()
        for ev in (mem_events + db_events):
            key = f"{ev.get('ip')}_{ev.get('time')}_{ev.get('path')}"
            if key not in seen:
                seen.add(key)
                combined.append(ev)

        return {
            "total": len(combined),
            "events": combined[offset : offset + limit]
        }
    except Exception as e:
        logger.error("Failed fetching WAF events: %s", e)
        return {"total": 0, "events": []}


@router.post("/demo/simulate_attack")
async def simulate_waf_attack(
    attack_type: str = "sqli",
    token: dict = Depends(require_admin)
):
    """Simulate an anomalous/attack request to verify WAF detection & WebSocket feed."""
    import time
    from modules.waf.api.live_monitor import waf_dispatcher
    
    samples = {
        "sqli": {
            "src_ip": "198.51.100.42",
            "path": "/api/v1/users?id=1' UNION SELECT username,password_hash FROM users--",
            "method": "GET",
            "action": "BLOCK",
            "risk_score": 0.96,
            "triggers": ["SQL_INJECTION", "UNION_SELECT_PATTERN", "HEURISTIC_SCORE_HIGH"],
            "severity": "HIGH",
            "description": "SQL Injection pattern detected in query parameter 'id'",
            "xai_explanation": "تم اكتشاف عبارة حقن قواعد بيانات SQL مشبوهة تستهدف استخراج جداول المستخدمين",
        },
        "xss": {
            "src_ip": "203.0.113.88",
            "path": "/api/v1/comments",
            "method": "POST",
            "action": "BLOCK",
            "risk_score": 0.91,
            "triggers": ["XSS_ATTACK", "SCRIPT_TAG_INJECTION"],
            "severity": "HIGH",
            "description": "Cross-Site Scripting (XSS) payload in comment body: <script>alert(1)</script>",
            "xai_explanation": "تم اكتشاف وسم برمجيات نصية خبيثة (XSS) في جسم الطلب",
        },
        "path_traversal": {
            "src_ip": "192.0.2.115",
            "path": "/download?file=../../../../etc/passwd",
            "method": "GET",
            "action": "BLOCK",
            "risk_score": 0.94,
            "triggers": ["PATH_TRAVERSAL", "DIR_TRAVERSAL_DOTDOT"],
            "severity": "HIGH",
            "description": "Directory Traversal attempt attempting to access /etc/passwd",
            "xai_explanation": "تم اعتراض محاولة تسلل للملفات الجذرية للنظام عبر متوالية ../",
        },
        "bot": {
            "src_ip": "45.33.32.156",
            "path": "/login",
            "method": "POST",
            "action": "CHALLENGE",
            "risk_score": 0.78,
            "triggers": ["BOT_ABUSE", "CREDENTIAL_STUFFING", "ANOMALOUS_FINGERPRINT"],
            "severity": "MEDIUM",
            "description": "Automated bot activity detected on /login endpoint (Fingerprint mismatch)",
            "xai_explanation": "تم رصد محاولات تسجيل دخول آلية سريعة وتم إرسال تحدي أمني CAPTCHA",
        },
        "bola": {
            "src_ip": "185.220.101.5",
            "path": "/api/v1/accounts/acc_99999/transfer",
            "method": "POST",
            "action": "BLOCK",
            "risk_score": 0.98,
            "triggers": ["BOLA_API_ABUSE", "UNAUTHORIZED_OBJECT_ACCESS", "DECEPTION_TRIP"],
            "severity": "CRITICAL",
            "description": "Broken Object Level Authorization (BOLA/IDOR) on account transfer",
            "xai_explanation": "محاولة وصول غير مصرح لمعرف كائن حساب بنكي أطلقت فخ الخداع الدفاعي",
        },
    }

    selected = samples.get(attack_type.lower(), samples["sqli"])
    event_payload = {
        "id": int(time.time() * 1000),
        "timestamp": time.time(),
        **selected
    }

    await waf_dispatcher.broadcast(event_payload)
    return {
        "status": "simulated",
        "attack_type": attack_type,
        "event": waf_dispatcher._normalize_event(event_payload),
    }


# ── Live WebSocket Dashboard ───────────────────────

@router.websocket("/live")
async def live_dashboard_websocket(websocket: WebSocket, token: Optional[str] = Query(None)):
    """
    Real-time WAF Event Feed.
    Secured via Query Parameter or Message-Based Authentication.
    Accepts: /api/v1/waf/live?token=... or first message: {"type": "auth", "token": "ey..."}
    """
    await websocket.accept()

    auth_token = token
    if not auth_token:
        # Wait for the first message (authentication) within a 3.0 second timeout
        try:
            auth_msg = await asyncio.wait_for(websocket.receive_json(), timeout=3.0)
            if isinstance(auth_msg, dict) and auth_msg.get("type") == "auth":
                auth_token = auth_msg.get("token")
        except asyncio.TimeoutError:
            logger.warning("WebSocket auth timed out")
            try:
                await websocket.close(code=1008, reason="Authentication timeout")
            except Exception:
                pass
            return
        except Exception as e:
            logger.warning("WebSocket auth message read failed: %s", e)
            try:
                await websocket.close(code=1008, reason=f"Auth message error: {str(e)}")
            except Exception:
                pass
            return

    if not auth_token:
        try:
            await websocket.close(code=1008, reason="Token not provided")
        except Exception:
            pass
        return

    # Decode and validate JWT
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=[ALGORITHM])
        role = payload.get("role", "")
        if role not in ("admin", "waf", "viewer"):
            await websocket.close(code=1008, reason="Insufficient privileges")
            return
    except Exception as e:
        logger.warning("WebSocket authentication failed: %s", e)
        try:
            await websocket.close(code=1008, reason=f"Authentication failed: {str(e)}")
        except Exception:
            pass
        return

    # Client authenticated successfully! Add to dispatcher.
    await waf_dispatcher.connect(websocket)

    try:
        while True:
            # Keep connection alive, wait for client ping / disconnect
            await websocket.receive_text()
    except WebSocketDisconnect:
        waf_dispatcher.disconnect(websocket)
    except Exception as e:
        logger.debug("WebSocket error: %s", e)
        waf_dispatcher.disconnect(websocket)

# ── WAAP Controls ──────────────────────────────────


# ── GNN Status ─────────────────────────────────────

@router.get("/gnn/status")
async def gnn_status(token: dict = Depends(require_waf)):
    """GNN model status: enabled flag, model loaded, log collection stats."""
    try:
        cfg       = _get_waf_settings()
        collector = _get_collector()
        gnn_inf   = _get_gnn_inference()

        model_path    = cfg.gnn.model_path
        model_exists  = os.path.exists(model_path) if model_path else False
        model_loaded  = gnn_inf.is_loaded() if gnn_inf else False

        log_path      = cfg.gnn.logs_path
        log_exists    = os.path.exists(log_path) if log_path else False
        log_size_mb   = round(os.path.getsize(log_path) / 1024 / 1024, 2) if log_exists else 0

        return {
            "gnn_enabled":         cfg.gnn.enabled,
            "log_sessions":        cfg.gnn.log_sessions,
            "model_configured":    model_path,
            "model_file_exists":   model_exists,
            "model_loaded_in_waf": model_loaded,
            "detection_threshold": cfg.gnn.detection_threshold,
            "weight_in_risk":      cfg.gnn.weight,
            "session_log": {
                "path":          log_path,
                "file_exists":   log_exists,
                "file_size_mb":  log_size_mb,
                "buffer_count":  collector.get_record_count() if collector else 0,
                "total_flushed": collector.get_total_flushed() if collector else 0,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Session Logs ───────────────────────────────────

@router.get("/gnn/logs")
async def get_session_logs(preview_lines: int = 10, token: dict = Depends(require_waf)):
    """
    Return session log file metadata and an optional CSV preview.
    Use ?preview_lines=0 to skip preview (faster for large files).
    """
    try:
        cfg = _get_waf_settings()
        log_path = cfg.gnn.logs_path

        if not log_path or not os.path.exists(log_path):
            return {
                "status": "no_logs",
                "message": "No session_logs.csv found yet. Enable GNN logging and run traffic.",
                "log_path": log_path,
            }

        file_size = os.path.getsize(log_path)
        preview = []
        if preview_lines > 0:
            with open(log_path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= preview_lines + 1:   # +1 for header
                        break
                    preview.append(line.rstrip())

        return {
            "status":        "available",
            "log_path":      log_path,
            "file_size_mb":  round(file_size / 1024 / 1024, 2),
            "preview_lines": preview,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gnn/logs/flush")
async def flush_session_logs(token: dict = Depends(require_admin)): # Admin-only destructive op
    """Force-flush in-memory session log buffer to CSV immediately."""
    collector = _get_collector()
    if not collector:
        return {"status": "no_collector", "message": "Log collector not initialized yet."}
    flushed = collector.flush()
    return {"status": "ok", "records_flushed": flushed}


# ── Training Control ───────────────────────────────

@router.post("/gnn/train")
async def start_gnn_training(request: TrainRequest, token: dict = Depends(require_admin)):
    """
    Start GNN model training as a background job.
    Uses real session_logs.csv if available, otherwise synthetic data.
    Returns immediately — poll /gnn/train/status for progress.
    """
    from modules.waf.engine.core.models.gnn_trainer import GNNTrainingJob, TrainingState

    if GNNTrainingJob.is_running():
        raise HTTPException(
            status_code=409,
            detail="A training job is already running. Check /gnn/train/status."
        )

    cfg = _get_waf_settings()
    logs_path  = cfg.gnn.logs_path or "modules/waf/ml_training/waf_gnn/datasets/session_logs.csv"
    output_dir = os.path.dirname(cfg.gnn.model_path or "ml/models/waf/gnn_model.pt")

    job = GNNTrainingJob(
        logs_path   = logs_path,
        output_dir  = output_dir,
        epochs      = request.epochs,
        n_synthetic = request.n_synthetic,
    )
    job.start()

    return {
        "status":  "started",
        "epochs":  request.epochs,
        "logs_path": logs_path,
        "message": "Training started. Poll GET /api/v1/waf/gnn/train/status for updates.",
    }


@router.get("/gnn/train/status")
async def get_training_status(token: dict = Depends(require_waf)):
    """Return the current GNN training job progress and results."""
    from modules.waf.engine.core.models.gnn_trainer import GNNTrainingJob

    with GNNTrainingJob._instance_lock:
        job = GNNTrainingJob._active_job

    if job is None:
        return {
            "state":   "idle",
            "message": "No training job has been run in this session.",
        }

    return job.status().to_dict()


# ── Model Activation ───────────────────────────────

@router.put("/gnn/activate")
async def activate_gnn_model(request: ActivateRequest, token: dict = Depends(require_admin)):
    """
    Load a trained GNN model into the live WAF (no restart required).
    If model_path is not specified, the path from waf.yaml is used.
    """
    try:
        cfg = _get_waf_settings()
        model_path = request.model_path or cfg.gnn.model_path

        if not model_path or not os.path.exists(model_path):
            raise HTTPException(
                status_code=404,
                detail=f"Model file not found: {model_path}. Train first via POST /gnn/train"
            )

        from modules.waf.ml_training.waf_gnn.model import WAFGNNInference

        # Reload inference object
        try:
            import modules.waf.engine.waf_inspector as waf_mod
            waf_mod._live_gnn_model = WAFGNNInference(model_path=model_path)
            logger.info("GNN model activated from %s", model_path)
        except AttributeError:
            pass

        return {
            "status":     "activated",
            "model_path": model_path,
            "message":    "GNN model loaded into live WAF successfully.",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Runtime Toggle ─────────────────────────────────

@router.put("/gnn/toggle")
async def toggle_gnn(request: ToggleRequest, token: dict = Depends(require_admin)):
    """Enable or disable GNN guard at runtime without restarting the WAF."""
    try:
        cfg = _get_waf_settings()
        cfg.gnn.enabled = request.enabled
        cfg.save()  # Persist change
        logger.info("GNN runtime toggle → %s (Persisted)", "ENABLED" if request.enabled else "DISABLED")
        return {
            "status":      "ok",
            "gnn_enabled": cfg.gnn.enabled,
            "message":     f"GNN {'enabled' if request.enabled else 'disabled'} (runtime, no restart needed).",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── WAAP Config Endpoints ──────────────────────────

@router.put("/waap/rate_limiter/config")
async def apply_rate_limit_config(request: RateLimitConfigRequest, token: dict = Depends(require_admin)):
    """Dynamically update Rate Limiting parameters."""
    cfg = _get_waf_settings()
    cfg.rate_limiter.global_rate_limit = request.global_rate_limit
    cfg.rate_limiter.ip_rate_limit = request.ip_rate_limit
    cfg.rate_limiter.user_rate_limit = request.user_rate_limit
    cfg.rate_limiter.adaptive_ratelimit = request.adaptive_ratelimit
    cfg.save()  # Persist change
    logger.info("WAAP Rate Limits dynamically updated and persisted")
    return {"status": "ok", "message": "Rate limits updated successfully"}

@router.put("/waap/toggle/{feature}")
async def toggle_waap_feature(feature: str, request: ToggleRequest, token: dict = Depends(require_admin)):
    """Toggle specific WAAP features (api_schema, fingerprint, ato, rate_limit, xai, graphql, self_learning)."""
    cfg = _get_waf_settings()
    if feature in ("api_schema", "waap_api_schema"):
        cfg.api_schema.enabled = request.enabled
    elif feature in ("fingerprint", "waap_fingerprint"):
        cfg.fingerprint.enabled = request.enabled
    elif feature in ("ato", "waap_ato"):
        cfg.ato_protector.enabled = request.enabled
    elif feature in ("rate_limit", "waap_rate_limit"):
        cfg.rate_limiter.enabled = request.enabled
    elif feature in ("xai", "xai_explainer"):
        cfg.xai_explainer.enabled = request.enabled
    elif feature in ("graphql", "waap_graphql"):
        cfg.graphql_inspector.enabled = request.enabled
    elif feature == "self_learning":
        cfg.self_learning.enabled = request.enabled
    elif feature == "deception_engine":
        cfg.deception_engine.enabled = request.enabled
    else:
        raise HTTPException(status_code=400, detail=f"Unknown WAAP feature: {feature}")
        
    cfg.save()  # Persist change
    logger.info("WAAP feature '%s' toggled to %s (Persisted)", feature, request.enabled)
    return {"status": "ok", "feature": feature, "enabled": request.enabled}


@router.post("/waap/api_schema/upload")
async def upload_api_schema(request: APISchemaUploadRequest, token: dict = Depends(require_admin)):
    """
    Upload an OpenAPI/Swagger JSON schema for a specific endpoint.
    Crucial for Multi-Tenant WAF-as-a-Service environments.
    """
    try:
        from modules.waf.engine.core.defenses.api_schema_validator import APISchemaValidator
        
        # 1. Update/Save schema persistently
        validator = APISchemaValidator()
        validator.load_schema(request.endpoint, request.schema_definition, persist=True)

        # 2. Hot-inject into active pipeline plugin instances
        injected = False
        try:
            from system.core.framework.pipeline import _global_pipeline
            for plugin in _global_pipeline.get_plugins():
                if plugin.name == "waf_ai_inspector" and hasattr(plugin, 'api_validator'):
                    plugin.api_validator.load_schema(request.endpoint, request.schema_definition, persist=False)
                    injected = True
        except Exception as e:
            logger.debug("Active WAF plugin lookup failed: %s", e)

        msg = f"Schema accepted and saved for {request.endpoint}."
        if injected:
            msg += " Hot-injected into running WAF inspector."
        else:
            msg += " Will be loaded on next WAF startup."

        return {"status": "ok", "message": msg}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── Shadow Autopilot Endpoints ─────────────────────

@router.post("/waap/shadow_mode/start")
async def start_shadow_mode(request: ShadowModeStartRequest, token: dict = Depends(require_admin)):
    """
    Start the Shadow Autopilot learning mode.
    The WAF will observe traffic to build a structural profile.
    """
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        raise HTTPException(status_code=500, detail="Shadow Autopilot is not initialized.")
        
    cfg = _get_waf_settings()
    cfg.shadow_mode.enabled = True
    cfg.shadow_mode.observation_window_hours = request.hours
    cfg.save()  # Persist toggle to prevent state loss
    
    autopilot.start_learning(hours=request.hours)
    logger.info(f"Shadow Autopilot activated for {request.hours} hours.")
    
    return {
        "status": "started", 
        "hours": request.hours, 
        "message": "Shadow Autopilot is now silently observing traffic to build the API Schema."
    }

@router.post("/waap/shadow_mode/stop")
async def stop_shadow_mode(token: dict = Depends(require_admin)):
    """
    Forcefully stop the Shadow Autopilot learning phase.
    Collected profile data is preserved — you can still export it.
    """
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        raise HTTPException(status_code=500, detail="Shadow Autopilot is not initialized.")
    
    autopilot.stop_learning()
    
    cfg = _get_waf_settings()
    cfg.shadow_mode.enabled = False
    cfg.save()
    
    endpoints_learned = len(autopilot.profiles)
    logger.info("Shadow Autopilot stopped manually. Endpoints profiled: %s", endpoints_learned)
    return {
        "status": "stopped",
        "endpoints_learned": endpoints_learned,
        "message": "Autopilot stopped. You can still export the schema."
    }

@router.get("/waap/shadow_mode/status")
async def shadow_mode_status(token: dict = Depends(require_waf)):
    """Get the live status and progress of the Shadow Autopilot."""
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        return {"status": "not_initialized"}
        
    res = autopilot.get_progress()
    if "endpoints_learned" in res:
        res["endpoints_profiled"] = res["endpoints_learned"]
    return res

@router.get("/waap/shadow_mode/export")
async def export_shadow_schema(token: dict = Depends(require_admin)):
    """
    Export the synthesized JSON Schema learned by the Autopilot.
    This can be reviewed and Enforced manually using the standard Schema Validator.
    """
    autopilot = _get_shadow_autopilot()
    if not autopilot:
        raise HTTPException(status_code=500, detail="Shadow Autopilot is not initialized.")
        
    generated_schema = autopilot.generate_schema()
    
    # Automatically disable learning if it's done or being exported
    cfg = _get_waf_settings()
    if not autopilot.is_learning() and cfg.shadow_mode.enabled:
        cfg.shadow_mode.enabled = False
        cfg.save()
        
    endpoints_count = len(generated_schema.get("paths", {}))
    return {
        "status": "success",
        "endpoints_learned": endpoints_count,
        "endpoints_profiled": endpoints_count,
        "schema": generated_schema,
        "message": "Schema perfectly tailored to your application's traffic!"
    }


# ── Patent PoC Demo Endpoints ──────────────────────
from fastapi import Request

@router.post("/waap/demo/bola_target")
@router.get("/waap/demo/bola_target")
async def demo_bola_deception(request: Request):
    """
    Demo endpoint to showcase the 'Intent-Proving Deceptive Object Graph WAAP'.
    Send an anomalous request to this endpoint to receive a Deceptive Canary.
    Then send the canary back in a second request to prove malicious intent.
    """
    # Simulate a generic backend response
    response_data = {
        "status": "success",
        "data": {
            "account_id": "acc_12345",
            "balance": "$5,000"
        }
    }
    
    # In a real setup, a middleware would pull 'waf_decoy_payload' from the InspectionResult metadata
    # For this PoC, we check the global active plugin just for demonstration
    try:
        from system.core.framework.pipeline import _global_pipeline
        # A contrived way to fish out the decoy just for the demo 
        # (Assuming the WAF inspector left a decoy in its engine state for this IP)
        import modules.waf.engine.waf_inspector as waf_mod
        for p in _global_pipeline.get_plugins():
            if isinstance(p, waf_mod.WAFInspectorPlugin) and p.deception_engine:
                # Let's peek into the engine's generated canaries for this IP
                # This is normally securely injected by the proxy, not the app itself.
                client_ip = request.client.host if request.client else "unknown"
                for canary_val, record in list(p.deception_engine.canaries.items()):
                    if record.ip_address == client_ip:
                        # We found a trap set for this IP! Inject it into the response.
                        response_data["_metadata"] = p.deception_engine.generate_decoy(
                            session_id="demo_session", 
                            ip_address=client_ip, 
                            attack_surface=record.canary_type.split('_')[0]
                        )
                        break
    except Exception as e:
        logger.error(f"Demo Decoy Injection Error: {e}")


    return response_data


# ═══════════════════════════════════════════════════
#  WAF Settings Control API
#  Full API control for every setting in settings.py
# ═══════════════════════════════════════════════════

# ── Additional Pydantic request models ───────────────

class WAFModeRequest(BaseModel):
    mode: str  # "enforce" | "monitor" | "learning"

class ModelConfigRequest(BaseModel):
    enabled:             Optional[bool]  = None
    detection_threshold: Optional[float] = None
    weight:              Optional[float] = None
    session_window_requests: Optional[int] = None
    max_log_records:         Optional[int] = None

class BotConfigRequest(BaseModel):
    enabled:             Optional[bool]  = None
    detection_threshold: Optional[float] = None
    weight:              Optional[float] = None
    bot_action:          Optional[str]   = None  # "challenge" | "block"

class RiskThresholdsRequest(BaseModel):
    allow:      Optional[float] = None
    challenge:  Optional[float] = None
    soft_block: Optional[float] = None
    block:      Optional[float] = None

class ThreatIntelConfigRequest(BaseModel):
    enabled:           Optional[bool]  = None
    weight:            Optional[float] = None
    cache_ttl_seconds: Optional[int]   = None
    abuseipdb_enabled: Optional[bool]  = None
    abuseipdb_key:     Optional[str]   = None
    abuseipdb_max_age: Optional[int]   = None
    otx_enabled:       Optional[bool]  = None
    otx_key:           Optional[str]   = None
    spamhaus_enabled:  Optional[bool]  = None
    feodo_enabled:     Optional[bool]  = None
    feodo_update_hours: Optional[int]  = None

class SelfLearningConfigRequest(BaseModel):
    enabled:        Optional[bool] = None
    log_blocked:    Optional[bool] = None
    log_challenged: Optional[bool] = None
    log_allowed:    Optional[bool] = None
    max_records:    Optional[int]  = None

class LoggingConfigRequest(BaseModel):
    enabled:         Optional[bool] = None
    log_blocked:     Optional[bool] = None
    log_challenged:  Optional[bool] = None
    log_allowed:     Optional[bool] = None
    include_payload: Optional[bool] = None
    log_file:        Optional[str]  = None
    alert_threshold: Optional[float] = None

class XAIExplainerConfigRequest(BaseModel):
    enabled:        Optional[bool] = None
    explainer_type: Optional[str]  = None

class HoneypotConfigRequest(BaseModel):
    enabled:               Optional[bool]  = None
    score_boost:           Optional[float] = None
    blacklist_ttl_seconds: Optional[int]   = None
    custom_paths:          Optional[list]  = None

class DeceptionConfigRequest(BaseModel):
    enabled:             Optional[bool]  = None
    injection_threshold: Optional[float] = None
    ttl_seconds:         Optional[int]   = None

class PerformanceConfigRequest(BaseModel):
    max_inspection_time_ms:    Optional[int]  = None
    fail_open:                 Optional[bool] = None
    max_payload_inspect_bytes: Optional[int]  = None

class ATOConfigRequest(BaseModel):
    enabled:               Optional[bool] = None
    max_attempts_per_ip:   Optional[int]  = None
    max_attempts_per_user: Optional[int]  = None
    time_window_seconds:   Optional[int]  = None

class GraphQLConfigRequest(BaseModel):
    enabled:              Optional[bool] = None
    max_depth:            Optional[int]  = None
    max_batched_queries:  Optional[int]  = None
    detect_introspection: Optional[bool] = None

class IPListRequest(BaseModel):
    ips:   Optional[list] = None
    cidrs: Optional[list] = None

class PreprocessingConfigRequest(BaseModel):
    enabled:           Optional[bool] = None
    max_iterations:    Optional[int]  = None
    url_decode:        Optional[bool] = None
    html_entity:       Optional[bool] = None
    hex_decode:        Optional[bool] = None
    base64_detect:     Optional[bool] = None
    unicode_normalize: Optional[bool] = None
    sql_comment_strip: Optional[bool] = None
    xml_json_flatten:  Optional[bool] = None

class DynamicAmplifierConfigRequest(BaseModel):
    enabled:                             Optional[bool]  = None
    reputation_boost:                    Optional[float] = None
    reputation_threshold:                Optional[float] = None
    bot_boost:                           Optional[float] = None
    bot_threshold:                       Optional[float] = None
    bot_reputation_dependency_threshold: Optional[float] = None
    high_confidence_override:            Optional[float] = None
    high_confidence_nlp_threshold:       Optional[float] = None
    high_confidence_gaf_threshold:       Optional[float] = None
    gnn_override_weight:                 Optional[float] = None
    fingerprint_boost_weight:            Optional[float] = None



def _apply_fields(target, request_obj):
    """Apply all non-None Pydantic fields onto a settings dataclass."""
    for field_name, value in request_obj.model_dump(exclude_none=True).items():
        if hasattr(target, field_name):
            setattr(target, field_name, value)


# ── 1. Full settings snapshot ─────────────────────────

@router.get("/settings")
async def get_waf_settings_snapshot(token: dict = Depends(require_waf)):
    """Return a full snapshot of all current WAF settings for admin dashboards."""
    cfg = _get_waf_settings()
    return {
        "waf_enabled": cfg.enabled,
        "mode":        cfg.mode,
        "monitored_ports": cfg.monitored_ports,
        "ai_models": {
            "nlp":      {"enabled": cfg.nlp.enabled,      "threshold": cfg.nlp.detection_threshold,      "weight": cfg.nlp.weight},
            "gaf":      {"enabled": cfg.gaf.enabled,      "threshold": cfg.gaf.detection_threshold,      "weight": cfg.gaf.weight},
            "temporal": {"enabled": cfg.temporal.enabled, "threshold": cfg.temporal.detection_threshold, "weight": cfg.temporal.weight},
            "bot":      {"enabled": cfg.bot.enabled,      "threshold": cfg.bot.detection_threshold,      "weight": cfg.bot.weight, "bot_action": cfg.bot.bot_action},
            "gnn":      {"enabled": cfg.gnn.enabled,      "threshold": cfg.gnn.detection_threshold,      "weight": cfg.gnn.weight, "session_window": cfg.gnn.session_window_requests},
            "anomaly":  {"enabled": cfg.anomaly.enabled,  "weight": cfg.anomaly.weight},
        },
        "defenses": {
            "threat_intel":  {"enabled": cfg.threat_intel.enabled,  "weight": cfg.threat_intel.weight, "abuseipdb": cfg.threat_intel.abuseipdb_enabled, "otx": cfg.threat_intel.otx_enabled, "spamhaus": cfg.threat_intel.spamhaus_enabled, "feodo": cfg.threat_intel.feodo_enabled},
            "honeypot":      {"enabled": cfg.honeypot.enabled,      "score_boost": cfg.honeypot.score_boost, "blacklist_ttl": cfg.honeypot.blacklist_ttl_seconds, "custom_paths": cfg.honeypot.custom_paths},
            "fingerprint":   {"enabled": cfg.fingerprint.enabled,   "check_ja3": cfg.fingerprint.check_ja3, "check_headers": cfg.fingerprint.check_headers},
            "ato_protector": {"enabled": cfg.ato_protector.enabled, "max_per_ip": cfg.ato_protector.max_attempts_per_ip, "max_per_user": cfg.ato_protector.max_attempts_per_user, "window_s": cfg.ato_protector.time_window_seconds},
            "rate_limiter":  {"enabled": cfg.rate_limiter.enabled,  "global": cfg.rate_limiter.global_rate_limit, "per_ip": cfg.rate_limiter.ip_rate_limit, "per_user": cfg.rate_limiter.user_rate_limit, "adaptive": cfg.rate_limiter.adaptive_ratelimit},
            "api_schema":    {"enabled": cfg.api_schema.enabled,    "max_payload_size": cfg.api_schema.max_payload_size},
            "graphql":       {"enabled": cfg.graphql_inspector.enabled, "max_depth": cfg.graphql_inspector.max_depth, "max_batched": cfg.graphql_inspector.max_batched_queries, "detect_introspection": cfg.graphql_inspector.detect_introspection},
            "deception":     {"enabled": cfg.deception_engine.enabled, "injection_threshold": cfg.deception_engine.injection_threshold, "ttl_s": cfg.deception_engine.ttl_seconds},
        },
        "intelligence": {
            "xai":          {"enabled": cfg.xai_explainer.enabled, "type": cfg.xai_explainer.explainer_type},
            "self_learning": {"enabled": cfg.self_learning.enabled},
            "shadow_mode":  {"enabled": cfg.shadow_mode.enabled, "window_hours": cfg.shadow_mode.observation_window_hours},
            "dynamic_amplifiers": {
                "enabled": cfg.dynamic_amplifiers.enabled,
                "reputation_boost": cfg.dynamic_amplifiers.reputation_boost,
                "reputation_threshold": cfg.dynamic_amplifiers.reputation_threshold,
                "bot_boost": cfg.dynamic_amplifiers.bot_boost,
                "bot_threshold": cfg.dynamic_amplifiers.bot_threshold,
                "bot_reputation_dependency_threshold": cfg.dynamic_amplifiers.bot_reputation_dependency_threshold,
                "high_confidence_override": cfg.dynamic_amplifiers.high_confidence_override,
                "high_confidence_nlp_threshold": cfg.dynamic_amplifiers.high_confidence_nlp_threshold,
                "high_confidence_gaf_threshold": cfg.dynamic_amplifiers.high_confidence_gaf_threshold,
                "gnn_override_weight": cfg.dynamic_amplifiers.gnn_override_weight,
                "fingerprint_boost_weight": cfg.dynamic_amplifiers.fingerprint_boost_weight
            }
        },
        "risk_scoring": {
            "enabled":   cfg.risk_scoring.enabled,
            "allow":     cfg.risk_scoring.thresholds.allow,
            "challenge": cfg.risk_scoring.thresholds.challenge,
            "block":     cfg.risk_scoring.thresholds.block,
        },
        "performance": {
            "max_inspection_ms":   cfg.performance.max_inspection_time_ms,
            "fail_open":           cfg.performance.fail_open,
            "max_payload_inspect": cfg.performance.max_payload_inspect_bytes,
        },
        "access_lists": {
            "whitelist": {"enabled": cfg.whitelist.enabled, "ips": cfg.whitelist.ips, "cidrs": cfg.whitelist.cidrs},
            "blacklist": {"enabled": cfg.blacklist.enabled, "ips": cfg.blacklist.ips, "cidrs": cfg.blacklist.cidrs},
        },
    }


# ── 2. Reload settings from YAML ─────────────────────

@router.post("/settings/reload")
async def reload_waf_settings(token: dict = Depends(require_admin)):
    """Re-read waf.yaml + waf.local.yaml and apply changes in-place. No restart required."""
    cfg = _get_waf_settings()
    cfg.reload()
    logger.info("WAF settings reloaded via API")
    return {"status": "ok", "message": "WAF settings reloaded from YAML"}


# ── 3. Master WAF switch ──────────────────────────────

@router.put("/settings/master")
async def toggle_waf_master(request: ToggleRequest, token: dict = Depends(require_admin)):
    """Enable or disable the entire WAF (master switch). Persisted to waf.local.yaml."""
    cfg = _get_waf_settings()
    cfg.set_enabled(request.enabled)
    cfg.save()
    return {"status": "ok", "waf_enabled": request.enabled}


# ── 4. WAF mode ───────────────────────────────────────

@router.put("/settings/mode")
async def set_waf_mode(request: WAFModeRequest, token: dict = Depends(require_admin)):
    """
    Switch WAF operation mode:
    - **enforce** — block/challenge threats (production)
    - **monitor** — log only, no blocking (staging/testing)
    - **learning** — observe and self-learn (alias for monitor)
    """
    cfg = _get_waf_settings()
    try:
        cfg.set_mode(request.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    cfg.save()
    return {"status": "ok", "mode": request.mode}


# ── 5. Generic AI model toggle ────────────────────────

@router.put("/models/{model}/toggle")
async def toggle_model_endpoint(model: str, request: ToggleRequest, token: dict = Depends(require_admin)):
    """
    Enable or disable any WAF model or defense at runtime (no restart).

    **model** values: `nlp` `gaf` `temporal` `bot` `gnn` `anomaly`
    `threat_intel` `fingerprint` `ato` `rate_limiter` `honeypot`
    `api_schema` `graphql` `xai` `deception` `self_learning`
    """
    cfg = _get_waf_settings()
    try:
        cfg.toggle_model(model, request.enabled)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    cfg.save()
    return {"status": "ok", "model": model, "enabled": request.enabled}


# ── 6. Per-model threshold + weight config ────────────

@router.put("/models/{model}/config")
async def configure_model_endpoint(model: str, request: ModelConfigRequest, token: dict = Depends(require_admin)):
    """
    Update detection_threshold and/or weight for an AI model.

    **model** values: `nlp` `gaf` `temporal` `gnn` `anomaly`
    (use `/bot/config` for bot, `/threat_intel/config` for threat intel)
    """
    cfg = _get_waf_settings()
    target_map = {
        "nlp":      cfg.nlp,
        "gaf":      cfg.gaf,
        "temporal": cfg.temporal,
        "gnn":      cfg.gnn,
        "anomaly":  cfg.anomaly,
    }
    if model not in target_map:
        raise HTTPException(status_code=400, detail=f"Model '{model}' not configurable here. Valid: {list(target_map.keys())}")
    _apply_fields(target_map[model], request)
    cfg.save()
    logger.info("Model [%s] config updated: %s", model, request.model_dump(exclude_none=True))
    return {"status": "ok", "model": model, "applied": request.model_dump(exclude_none=True)}


# ── 7. Bot Detection config ───────────────────────────

@router.put("/bot/config")
async def configure_bot(request: BotConfigRequest, token: dict = Depends(require_admin)):
    """
    Configure Bot Detection XGBoost.

    - **bot_action**: `"challenge"` (CAPTCHA) or `"block"` (hard block)
    - **detection_threshold**: 0.0–1.0 (default 0.65)
    - **weight**: contribution to risk score (default 0.20)
    """
    cfg = _get_waf_settings()
    _apply_fields(cfg.bot, request)
    cfg.save()
    return {"status": "ok", "bot": {"enabled": cfg.bot.enabled, "threshold": cfg.bot.detection_threshold, "weight": cfg.bot.weight, "action": cfg.bot.bot_action}}


# ── 8. Risk scoring thresholds ───────────────────────

@router.put("/risk_thresholds")
async def update_risk_thresholds(request: RiskThresholdsRequest, token: dict = Depends(require_admin)):
    """
    Update WAF risk score decision boundaries.

    - **allow** — below this → ALLOW (default 0.30)
    - **challenge** — below this → CHALLENGE/CAPTCHA (default 0.60)
    - **block** — above this → BLOCK (default 0.80)
    """
    cfg = _get_waf_settings()
    _apply_fields(cfg.risk_scoring.thresholds, request)
    cfg.save()
    t = cfg.risk_scoring.thresholds
    return {"status": "ok", "thresholds": {"allow": t.allow, "challenge": t.challenge, "soft_block": t.soft_block, "block": t.block}}


# ── 9. Threat Intelligence config ────────────────────

@router.put("/threat_intel/config")
async def configure_threat_intel(request: ThreatIntelConfigRequest, token: dict = Depends(require_admin)):
    """
    Toggle individual threat intel feeds (no restart needed).

    Feeds: `abuseipdb_enabled` `otx_enabled` `spamhaus_enabled` `feodo_enabled`
    """
    cfg = _get_waf_settings()
    _apply_fields(cfg.threat_intel, request)
    cfg.save()
    return {"status": "ok", "threat_intel": {"enabled": cfg.threat_intel.enabled, "abuseipdb": cfg.threat_intel.abuseipdb_enabled, "otx": cfg.threat_intel.otx_enabled, "spamhaus": cfg.threat_intel.spamhaus_enabled, "feodo": cfg.threat_intel.feodo_enabled}}


# ── 10. Honeypot config ───────────────────────────────

@router.put("/honeypot/config")
async def configure_honeypot(request: HoneypotConfigRequest, token: dict = Depends(require_admin)):
    """Configure Honeypot Guard: score_boost, blacklist TTL, and custom trap paths."""
    cfg = _get_waf_settings()
    _apply_fields(cfg.honeypot, request)
    cfg.save()
    return {"status": "ok", "honeypot": {"enabled": cfg.honeypot.enabled, "score_boost": cfg.honeypot.score_boost, "blacklist_ttl": cfg.honeypot.blacklist_ttl_seconds, "custom_paths": cfg.honeypot.custom_paths}}


# ── 11. Deception Engine config ───────────────────────

@router.put("/deception/config")
async def configure_deception(request: DeceptionConfigRequest, token: dict = Depends(require_admin)):
    """
    Configure the Intent-Proving Deception Engine.

    - **injection_threshold**: risk score above which a decoy is injected (default 0.40)
    - **ttl_seconds**: canary trap lifetime (default 3600 = 1h)
    """
    cfg = _get_waf_settings()
    _apply_fields(cfg.deception_engine, request)
    cfg.save()
    return {"status": "ok", "deception": {"enabled": cfg.deception_engine.enabled, "injection_threshold": cfg.deception_engine.injection_threshold, "ttl_seconds": cfg.deception_engine.ttl_seconds}}


# ── 12. Performance config ────────────────────────────

@router.put("/performance/config")
async def configure_performance(request: PerformanceConfigRequest, token: dict = Depends(require_admin)):
    """Configure WAF performance limits: inspection timeout, fail-open, max payload size."""
    cfg = _get_waf_settings()
    _apply_fields(cfg.performance, request)
    cfg.save()
    return {"status": "ok", "performance": {"max_inspection_ms": cfg.performance.max_inspection_time_ms, "fail_open": cfg.performance.fail_open, "max_payload_inspect": cfg.performance.max_payload_inspect_bytes}}


# ── 13. ATO Protector config ──────────────────────────

@router.put("/ato/config")
async def configure_ato(request: ATOConfigRequest, token: dict = Depends(require_admin)):
    """
    Configure Account Takeover (ATO) Protector.

    - **max_attempts_per_ip**: brute-force limit per IP (default 10)
    - **max_attempts_per_user**: credential-stuffing limit per username (default 3)
    - **time_window_seconds**: rolling window (default 300s)
    """
    cfg = _get_waf_settings()
    _apply_fields(cfg.ato_protector, request)
    cfg.save()
    return {"status": "ok", "ato": {"enabled": cfg.ato_protector.enabled, "max_per_ip": cfg.ato_protector.max_attempts_per_ip, "max_per_user": cfg.ato_protector.max_attempts_per_user, "window_seconds": cfg.ato_protector.time_window_seconds}}


# ── 14. GraphQL Inspector config ──────────────────────

@router.put("/graphql/config")
async def configure_graphql(request: GraphQLConfigRequest, token: dict = Depends(require_admin)):
    """Configure GraphQL Inspector: max depth, batch limit, introspection detection."""
    cfg = _get_waf_settings()
    _apply_fields(cfg.graphql_inspector, request)
    cfg.save()
    return {"status": "ok", "graphql": {"enabled": cfg.graphql_inspector.enabled, "max_depth": cfg.graphql_inspector.max_depth, "max_batched_queries": cfg.graphql_inspector.max_batched_queries, "detect_introspection": cfg.graphql_inspector.detect_introspection}}


# ── 15. Preprocessing config ──────────────────────────

@router.put("/preprocessing/config")
async def configure_preprocessing(request: PreprocessingConfigRequest, token: dict = Depends(require_admin)):
    """Configure preprocessing decoders."""
    cfg = _get_waf_settings()
    _apply_fields(cfg.preprocessing, request)
    cfg.save()
    return {"status": "ok"}

@router.put("/self_learning/config")
async def configure_self_learning(request: SelfLearningConfigRequest, token: dict = Depends(require_admin)):
    cfg = _get_waf_settings()
    _apply_fields(cfg.self_learning, request)
    cfg.save()
    return {"status": "ok"}

@router.put("/logging/config")
async def configure_logging(request: LoggingConfigRequest, token: dict = Depends(require_admin)):
    cfg = _get_waf_settings()
    _apply_fields(cfg.logging, request)
    cfg.save()
    return {"status": "ok"}

@router.put("/xai_explainer/config")
async def configure_xai(request: XAIExplainerConfigRequest, token: dict = Depends(require_admin)):
    cfg = _get_waf_settings()
    _apply_fields(cfg.xai_explainer, request)
    cfg.save()
    return {"status": "ok"}


# ── 16. IP Whitelist / Blacklist management ───────────

@router.put("/ip/whitelist")
async def update_whitelist(request: IPListRequest, token: dict = Depends(require_admin)):
    """Replace the entire IP whitelist. Sends full replacement list."""
    cfg = _get_waf_settings()
    if request.ips is not None:
        cfg.whitelist.ips = request.ips
    if request.cidrs is not None:
        cfg.whitelist.cidrs = request.cidrs
    cfg.save()
    return {"status": "ok", "whitelist": {"ips": cfg.whitelist.ips, "cidrs": cfg.whitelist.cidrs}}


@router.post("/ip/whitelist/add")
async def add_to_whitelist(request: IPListRequest, token: dict = Depends(require_admin)):
    """Append IPs/CIDRs to the whitelist without replacing existing entries."""
    cfg = _get_waf_settings()
    for ip in (request.ips or []):
        if ip not in cfg.whitelist.ips:
            cfg.whitelist.ips.append(ip)
    for cidr in (request.cidrs or []):
        if cidr not in cfg.whitelist.cidrs:
            cfg.whitelist.cidrs.append(cidr)
    cfg.save()
    return {"status": "ok", "whitelist": {"ips": cfg.whitelist.ips, "cidrs": cfg.whitelist.cidrs}}


@router.put("/ip/blacklist")
async def update_blacklist(request: IPListRequest, token: dict = Depends(require_admin)):
    """Replace the static IP blacklist."""
    cfg = _get_waf_settings()
    if request.ips is not None:
        cfg.blacklist.ips = request.ips
    if request.cidrs is not None:
        cfg.blacklist.cidrs = request.cidrs
    cfg.save()
    return {"status": "ok", "blacklist": {"ips": cfg.blacklist.ips, "cidrs": cfg.blacklist.cidrs}}


@router.post("/ip/blacklist/add")
async def add_to_blacklist(request: IPListRequest, token: dict = Depends(require_admin)):
    """Append IPs/CIDRs to the blacklist without replacing existing entries."""
    cfg = _get_waf_settings()
    for ip in (request.ips or []):
        if ip not in cfg.blacklist.ips:
            cfg.blacklist.ips.append(ip)
    for cidr in (request.cidrs or []):
        if cidr not in cfg.blacklist.cidrs:
            cfg.blacklist.cidrs.append(cidr)
    cfg.save()
    return {"status": "ok", "blacklist": {"ips": cfg.blacklist.ips, "cidrs": cfg.blacklist.cidrs}}
@router.put("/dynamic_amplifiers/config")
async def apply_dynamic_amplifiers_config(request: DynamicAmplifierConfigRequest, token: dict = Depends(require_admin)):
    """Dynamically update risk multiplier heuristics."""
    cfg = _get_waf_settings()
    _apply_fields(cfg.dynamic_amplifiers, request)
    cfg.save()
    logger.info("Dynamic multipliers dynamically updated and persisted")
    return {"status": "ok", "message": "Dynamic multipliers updated successfully"}


@router.post("/ip/session/clear")
async def clear_ip_session(
    ip: str = Query(..., description="IP address to clear GNN + temporal session for"),
    token: dict = Depends(require_admin),
):
    """
    Manually flush the GNN session graph and temporal tracker history for a
    specific IP address.

    Use this after a pen-test or authorized scan so the tested IP can resume
    normal browsing without inheriting the attack session history.

    This does NOT affect the model weights or block history in the blocklist.
    """
    cleared = []

    gnn = _get_gnn_inference()
    if gnn:
        gnn.clear_session(ip)
        cleared.append("gnn_session")

    try:
        from modules.waf.engine.waf_inspector import _live_temporal_tracker
        if _live_temporal_tracker:
            _live_temporal_tracker.clear_ip(ip)
            cleared.append("temporal_history")
    except (ImportError, AttributeError):
        pass

    if not cleared:
        raise HTTPException(status_code=503, detail="WAF session models not loaded")

    logger.info("Admin cleared session state for IP=%s (cleared=%s)", ip, cleared)
    return {
        "status": "ok",
        "ip": ip,
        "cleared": cleared,
        "message": f"Session history for {ip} has been reset. Next request starts with a clean slate.",
    }

