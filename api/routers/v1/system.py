"""
Enterprise bunyanx — System & Engine Endpoints
==================================================
Combines Engine controls, System scripts, Health probes, and Circuit Breakers.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel

from api.core.auth import require_admin
from api.services import system_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/system", tags=["System Health"])

# ── Health & Circuit Breakers ────────────────────────────────────────────────

@router.get("/health")
async def health_basic():
    """Quick liveness probe for load balancers."""
    return {"status": "ok", "service": "bunyanx NGFW"}


@router.get("/health/detailed")
async def health_detailed(request: Request):
    """
    Returns circuit breaker state and plugin statistics for every registered module.
    """
    ctrl = getattr(request.app.state, 'bunyanx', None)
    health_data = await system_service.get_detailed_health(ctrl)

    plugins = []
    if ctrl and hasattr(ctrl, "inspection_pipeline"):
        for plugin in ctrl.inspection_pipeline.get_plugins():
            plugins.append({
                "name": plugin.name,
                "enabled": plugin.enabled,
                "priority": getattr(plugin, "priority", 50),
                "statistics": plugin.get_statistics() if hasattr(plugin, "get_statistics") else {}
            })

    health_data["plugins"] = plugins
    return health_data


@router.post("/health/reset/{module_name}")
async def reset_breaker(module_name: str, token: dict = Depends(require_admin)):
    """Admin endpoint: manually reset a module's circuit breaker to CLOSED."""
    try:
        return await system_service.reset_circuit_breaker(module_name)
    except ValueError as e:
        return {"error": str(e)}


@router.get("/features")
async def get_features(token: dict = Depends(require_admin)):
    """Return the current feature flag state (from features.yaml)."""
    return await system_service.get_system_features()


@router.post("/features/reload")
async def reload_features(token: dict = Depends(require_admin)):
    """Force hot-reload of features.yaml without restart."""
    return await system_service.reload_system_features()


# ── Engine Controls & Daemon ─────────────────────────────────────────────────

@router.get("/daemon/status")
async def daemon_status(request: Request, token: dict = Depends(require_admin)):
    """Get the current status of the Daemon and Engine via internal main state"""
    ctrl = getattr(request.app.state, 'bunyanx', None)
    engine_running = getattr(ctrl, 'engine_running', False) if ctrl else False
    uptime = ctrl.get_uptime() if ctrl and hasattr(ctrl, 'get_uptime') else 0.0

    if ctrl is None:
        daemon_status_str = "offline"
    elif not engine_running:
        daemon_status_str = "degraded"
    else:
        daemon_status_str = "online"

    return {
        "daemon": daemon_status_str,
        "engine_running": engine_running,
        "uptime_seconds": uptime,
    }

@router.post("/engine/start")
async def start_engine(request: Request, token: dict = Depends(require_admin)):
    """Start the main.py bunyanx Engine Inspection Components"""
    ctrl = getattr(request.app.state, 'bunyanx', None)
    try:
        return await system_service.start_firewall_engine(ctrl)
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/engine/stop")
async def stop_engine(request: Request, token: dict = Depends(require_admin)):
    """Stop the main.py bunyanx Engine Inspection Components natively"""
    ctrl = getattr(request.app.state, 'bunyanx', None)
    try:
        return await system_service.stop_firewall_engine(ctrl)
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ── System Scripts ───────────────────────────────────────────────────────────

class ScriptRequest(BaseModel):
    script_name: str
    args: list[str] = []

@router.post("/scripts")
async def run_system_script(request_body: ScriptRequest, token: dict = Depends(require_admin)):
    """Execute permitted bash scripts from the scripts directory"""
    try:
        return await system_service.execute_system_script(request_body.script_name, request_body.args)
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except FileNotFoundError as fe:
        raise HTTPException(status_code=404, detail=str(fe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

from system.database.database import AuditLog
from sqlalchemy.future import select

@router.get("/audit/logs")
async def list_audit_logs(request: Request, token: dict = Depends(require_admin)):
    """Retrieve system administrative audit logs (real data)."""
    if not hasattr(request.app.state, "bunyanx") or not request.app.state.bunyanx:
        raise HTTPException(status_code=503, detail="bunyanx not initialized")
    db = request.app.state.bunyanx.db
    async with db.session() as session:
        result = await session.execute(select(AuditLog).order_by(AuditLog.timestamp.desc()))
        logs = result.scalars().all()
        formatted_logs = []
        for log in logs:
            resource_lower = (log.resource or "system").lower()
            category = "system"
            if any(k in resource_lower for k in ["auth", "login", "user", "session"]):
                category = "auth"
            elif any(k in resource_lower for k in ["waf", "ids", "ips", "security", "threat", "av"]):
                category = "security"
            elif any(k in resource_lower for k in ["policy", "rule", "filter"]):
                category = "policy"
            elif any(k in resource_lower for k in ["config", "setting", "feature"]):
                category = "config"
            elif any(k in resource_lower for k in ["vpn", "net", "interface"]):
                category = "network"

            action_lower = (log.action or "").lower()
            severity = "info"
            if any(k in action_lower for k in ["fail", "error", "block", "deny"]):
                severity = "error"
            elif any(k in action_lower for k in ["warn", "alert", "change"]):
                severity = "warning"
            elif any(k in action_lower for k in ["success", "create", "start", "enable"]):
                severity = "success"

            formatted_logs.append({
                "id": f"EVT-{log.id:05d}",
                "timestamp": log.timestamp.isoformat() + 'Z' if log.timestamp else None,
                "category": category,
                "message": log.action,
                "severity": severity,
                "actor": log.username,
                "ip": log.ip_address or "127.0.0.1",
                "result": "نجاح" if severity != "error" else "فشل",
                "details": log.details
            })
        return formatted_logs
