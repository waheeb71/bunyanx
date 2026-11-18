"""
Enterprise bunyanx - System Status & Health Endpoints
GET  /api/v1/status          — Full system status  (operator+)
GET  /health                 — Liveness probe (public)
GET  /api/v1/health/liveness — Kubernetes liveness (public)
GET  /api/v1/health/readiness
GET  /api/v1/health/detailed — Component detail (operator+)
GET  /metrics                — Prometheus metrics (public)
"""
from datetime import datetime
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from api.core.auth import verify_token, require_operator

router = APIRouter(tags=["Health & Status"])


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class SystemStatus(BaseModel):
    status: str
    uptime_seconds: float
    cpu_usage: float
    memory_usage: float
    active_connections: int
    rules_count: int
    ml_models_loaded: bool
    ha_state: str = Field("UNKNOWN")
    ha_peer: Optional[str] = None
    ha_priority: int = 0


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/health")
async def health_check():
    """Public liveness heartbeat (no auth). Used by load balancers."""
    return {"status": "healthy", "timestamp": datetime.utcnow()}


@router.get("/api/v1/health/liveness")
async def liveness_probe(request: Request):
    """Kubernetes liveness probe (no auth)."""
    try:
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and hasattr(bunyanx, "health_checker"):
            alive = await bunyanx.health_checker.liveness_probe()
            if not alive:
                return JSONResponse(status_code=503, content={"status": "dead"})
        return {"status": "alive", "timestamp": datetime.utcnow()}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})


@router.get("/api/v1/health/readiness")
async def readiness_probe(request: Request):
    """Kubernetes readiness probe (no auth)."""
    try:
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and hasattr(bunyanx, "health_checker"):
            ready = await bunyanx.health_checker.readiness_probe()
            if not ready:
                return JSONResponse(status_code=503, content={"status": "not_ready"})
            return {"status": "ready", "timestamp": datetime.utcnow()}
        return JSONResponse(status_code=503, content={"status": "not_ready", "reason": "Health checker missing"})
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "error", "detail": str(e)})


@router.get("/api/v1/health/detailed")
async def detailed_health(request: Request, token: dict = Depends(verify_token)):
    """Detailed per-component health check (authenticated users)."""
    bunyanx = getattr(request.app.state, "bunyanx", None)
    if bunyanx and hasattr(bunyanx, "health_checker"):
        return await bunyanx.health_checker.check_all_components()
    return {"overall_status": "unknown", "message": "Health checker not available"}


@router.get("/api/v1/status", response_model=SystemStatus)
async def get_status(request: Request, token: dict = Depends(require_operator)):
    """Full system metrics — operators and admins only."""
    import psutil
    from sqlalchemy.future import select
    from sqlalchemy import func
    from system.database.database import Rule

    bunyanx = getattr(request.app.state, "bunyanx", None)
    ha_state, ha_peer, ha_priority, uptime = "MASTER", None, 100, 0.0
    active_connections = 0
    rules_count = 0
    ml_loaded = False

    if bunyanx:
        uptime = bunyanx.get_uptime() if hasattr(bunyanx, "get_uptime") else 0.0
        if getattr(bunyanx, "ha_manager", None):
            ha_state = bunyanx.ha_manager.state.name
            ha_peer = getattr(bunyanx.ha_manager, "peer_ip", None)
            ha_priority = getattr(bunyanx.ha_manager, "priority", 100)
        # Live rules count from DB
        try:
            async with bunyanx.db.session() as session:
                result = await session.execute(select(func.count(Rule.id)).where(Rule.enabled == True))
                rules_count = result.scalar() or 0
        except Exception:
            pass
        # Active connections from flow tracker
        try:
            if getattr(bunyanx, "flow_tracker", None):
                flows = bunyanx.flow_tracker.get_active_flows()
                active_connections = len(flows) if flows else 0
        except Exception:
            pass
        # ML models loaded check
        ml_loaded = (
            getattr(bunyanx, "anomaly_detector", None) is not None
            or getattr(bunyanx, "AEGIS_engine", None) is not None
        )

    return SystemStatus(
        status="operational",
        uptime_seconds=uptime,
        cpu_usage=psutil.cpu_percent(),
        memory_usage=psutil.virtual_memory().percent,
        active_connections=active_connections,
        rules_count=rules_count,
        ml_models_loaded=ml_loaded,
        ha_state=ha_state,
        ha_peer=ha_peer,
        ha_priority=ha_priority,
    )


# NOTE: /metrics is registered in api/main.py — removed duplicate here to avoid shadowing.
