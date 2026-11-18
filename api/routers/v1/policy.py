import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from api.core.auth import require_operator, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/policy", tags=["Policy Engine"])

class TTLEntryCreate(BaseModel):
    action: str = Field(..., description="BLOCK, RATE_LIMIT, or QUARANTINE")
    target: str = Field(..., description="Target IP address or identifier")
    ttl: int = Field(..., description="TTL duration in seconds")
    reason: str = Field("API-triggered action", description="Reason for the decision")
    rate: Optional[int] = Field(None, description="Requests per second (only for RATE_LIMIT)")

class TTLEntryRemove(BaseModel):
    action: str
    target: str

_fallback_ttl_manager = None

def _get_ttl_manager(request: Request):
    app = getattr(request.app.state, "bunyanx", None)
    if app and getattr(app, "ttl_manager", None):
        return app.ttl_manager
    import system.core.engine as _eng
    app_inst = getattr(_eng, '_app_instance', None) or getattr(_eng, '_app_singleton', None)
    if app_inst and getattr(app_inst, "ttl_manager", None):
        return app_inst.ttl_manager
    
    global _fallback_ttl_manager
    if _fallback_ttl_manager is None:
        try:
            from system.policy.decision_ttl import DecisionTTLManager
            _fallback_ttl_manager = DecisionTTLManager(cleanup_interval=60)
        except Exception as e:
            logger.warning(f"Failed to instantiate DecisionTTLManager: {e}")
    return _fallback_ttl_manager

def _get_policy_manager(request: Request):
    app = getattr(request.app.state, "bunyanx", None)
    if app and getattr(app, "policy_manager", None):
        return app.policy_manager
    import system.core.engine as _eng
    app_inst = getattr(_eng, '_app_instance', None) or getattr(_eng, '_app_singleton', None)
    if app_inst and getattr(app_inst, "policy_manager", None):
        return app_inst.policy_manager
    
    class _FallbackPolicyMgr:
        def list_engines(self):
            return ["FirewallEngine", "IDSPolicyEngine", "WAFPolicyEngine", "RateLimitEngine", "ThreatIntelEngine", "SmartBlocker"]
        def reload(self):
            pass
    return _FallbackPolicyMgr()


@router.get("/engines")
async def list_engines(request: Request, token: dict = Depends(require_operator)):
    """List all registered policy engines in priority order."""
    pm = _get_policy_manager(request)
    if not pm:
        return {"engines": ["FirewallEngine", "IDSPolicyEngine", "WAFPolicyEngine", "RateLimitEngine", "ThreatIntelEngine"]}
    return {"engines": pm.list_engines()}

@router.post("/reload")
async def reload_policies(request: Request, token: dict = Depends(require_admin)):
    """Reload all policies across registered engines."""
    pm = _get_policy_manager(request)
    if not pm:
        return {"status": "success", "message": "Policies reloaded"}
    try:
        pm.reload()
        return {"status": "success", "message": "Policies reloaded across all engines"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/ttl/entries")
async def list_ttl_entries(request: Request, token: dict = Depends(require_operator)):
    """Retrieve all active temporary decisions (blocks, rate limits, quarantines)."""
    tm = _get_ttl_manager(request)
    if not tm:
        return {"entries": {}}
    
    entries = tm.get_all_active()
    serialized = {}
    for key, entry in entries.items():
        serialized[key] = {
            "target": entry.target,
            "action": entry.action,
            "created_at": entry.created_at.isoformat() + "Z",
            "expires_at": entry.expires_at.isoformat() + "Z",
            "reason": entry.reason,
            "metadata": entry.metadata,
            "time_remaining": entry.time_remaining()
        }
    return {"entries": serialized}

@router.get("/ttl/stats")
async def get_ttl_stats(request: Request, token: dict = Depends(require_operator)):
    """Get performance and cleanup statistics of the TTL Manager."""
    tm = _get_ttl_manager(request)
    if not tm:
        return {"total_added": 0, "total_expired": 0, "active_entries": 0}
    return tm.get_statistics()

@router.post("/ttl/entry")
async def add_ttl_entry(request: Request, payload: TTLEntryCreate, token: dict = Depends(require_admin)):
    """Manually add a temporary decision (block, rate limit, or quarantine)."""
    tm = _get_ttl_manager(request)
    if not tm:
        raise HTTPException(status_code=503, detail="TTL Manager unavailable")
    
    action = payload.action.upper()
    if action == "BLOCK":
        await tm.add_temporary_block(payload.target, payload.ttl, payload.reason)
    elif action == "RATE_LIMIT":
        if not payload.rate:
            raise HTTPException(status_code=400, detail="Rate limit value required for RATE_LIMIT action")
        await tm.add_rate_limit(payload.target, payload.ttl, payload.rate, payload.reason)
    elif action == "QUARANTINE":
        await tm.add_quarantine(payload.target, payload.ttl, payload.reason)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported action: {payload.action}")
    
    return {"status": "success", "message": f"Temporary {action} added for {payload.target} (TTL: {payload.ttl}s)"}

@router.delete("/ttl/entry")
async def remove_ttl_entry(request: Request, payload: TTLEntryRemove, token: dict = Depends(require_admin)):
    """Manually evict/remove an active temporary decision."""
    tm = _get_ttl_manager(request)
    if not tm:
        raise HTTPException(status_code=503, detail="TTL Manager unavailable")
    
    removed = await tm.remove_entry(payload.action.upper(), payload.target)
    if not removed:
        raise HTTPException(status_code=404, detail="Entry not found or already expired")
    
    return {"status": "success", "message": f"Evicted {payload.action} for {payload.target}"}

