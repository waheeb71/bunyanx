from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Dict, Any
from api.core.auth import require_operator, require_admin

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])

@router.get("/stats")
async def get_threat_intel_stats(token: dict = Depends(require_operator)) -> Dict[str, Any]:
    """Retrieve cache size, enabled state, and last refresh timestamp of the CTI manager."""
    from system.threat_intel.intel_manager import ThreatIntelManager
    manager = ThreatIntelManager.instance()
    return manager.get_stats()

@router.get("/lookup/{ip}")
async def lookup_ip_reputation(ip: str, token: dict = Depends(require_operator)) -> Dict[str, Any]:
    """Perform a reputation lookup for a given IP."""
    from system.threat_intel.intel_manager import ThreatIntelManager
    manager = ThreatIntelManager.instance()
    
    # Validate IP format
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
        
    result = await manager.lookup_ip(ip)
    return {
        "ip": result.ip,
        "score": result.score,
        "is_malicious": result.is_malicious,
        "source": result.source,
        "reason": result.reason,
        "last_seen_epoch": result.last_seen
    }

@router.post("/refresh")
async def force_threat_intel_refresh(token: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Force manual reload and refresh of threat intelligence feeds."""
    from system.threat_intel.intel_manager import ThreatIntelManager
    manager = ThreatIntelManager.instance()
    
    if not manager._flags or not manager._flags.current.threat_intel.enabled:
        raise HTTPException(status_code=400, detail="Threat Intelligence is disabled in configurations")
        
    try:
        await manager._do_refresh()
        return {"status": "success", "message": "Manual refresh of Threat Intelligence feeds completed successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Refresh failed: {str(e)}")
