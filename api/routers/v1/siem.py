from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime
from api.core.auth import require_admin, require_operator

router = APIRouter(prefix="/api/v1/siem", tags=["SIEM Integration"])

@router.get("/status")
async def get_siem_status(request: Request, token: dict = Depends(require_operator)):
    """Retrieve status, connector configuration details, and delivery stats."""
    app = getattr(request.app.state, "bunyanx", None)
    if not app or not getattr(app, "siem_connector", None):
        return {
            "enabled": False,
            "status": "disabled",
            "type": None,
            "stats": {"sent": 0, "failed": 0, "buffered": 0}
        }
    
    connector = app.siem_connector
    config_details = {
        "server": getattr(connector, "server", None),
        "port": getattr(connector, "port", None),
        "protocol": getattr(connector, "protocol", None),
        "hosts": getattr(connector, "hosts", None),
        "url": getattr(connector, "url", None),
        "buffer_size": connector._buffer_size,
        "flush_interval": connector._flush_interval,
    }
    
    return {
        "enabled": True,
        "status": "active" if connector._running else "stopped",
        "type": connector.__class__.__name__.replace("Connector", "").lower(),
        "config": config_details,
        "stats": connector.stats
    }

@router.post("/test")
async def test_siem_connection(request: Request, token: dict = Depends(require_admin)):
    """Inject a dummy SIEMEvent and flush buffer to test SIEM connectivity."""
    app = getattr(request.app.state, "bunyanx", None)
    if not app or not getattr(app, "siem_connector", None):
        raise HTTPException(status_code=503, detail="SIEM connector is not enabled or configured")
    
    from system.siem.siem_connector import SIEMEvent
    
    test_event = SIEMEvent(
        timestamp=datetime.utcnow().isoformat() + "Z",
        severity="info",
        event_type="test_probe",
        source_ip="127.0.0.1",
        destination_ip="127.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        action="allow",
        description="NGFW API Connection Test Event",
        metadata={"test": True}
    )
    
    try:
        await app.siem_connector.send(test_event)
        await app.siem_connector.flush()
        return {"status": "success", "message": "Test event sent and flushed to SIEM target successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SIEM test failed: {str(e)}")
