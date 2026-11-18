"""
Enterprise bunyanx - Response Orchestrator Configuration & Central Incident Hub
GET    /api/v1/response/blocks -> List current hardware IP blocks
DELETE /api/v1/response/blocks/{ip} -> Unblock an IP from eBPF
GET    /api/v1/response/incidents -> List all security incidents (real system data)
GET    /api/v1/response/incidents/{id} -> Incident details & timeline
PUT    /api/v1/response/incidents/{id}/status -> Update status (open, investigating, contained, closed)
POST   /api/v1/response/incidents/{id}/action -> Trigger mitigation action
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from api.core.auth import make_permission_checker
from api.services.response.incident_service import IncidentService
from api.services.response.mitigation_service import MitigationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/response", tags=["Response Orchestration"])


class StatusUpdate(BaseModel):
    status: str


class ActionRequest(BaseModel):
    action: str
    label: Optional[str] = None
    ip: Optional[str] = None
    reason: Optional[str] = None
    duration: Optional[str] = None


@router.get("/blocks")
async def list_blocks(
    request: Request,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Retrieve all IPs currently blocked by the eBPF engine and hardware orchestrator."""
    return await MitigationService.list_blocks(request, token)


@router.delete("/blocks/{ip}")
async def remove_block(
    request: Request,
    ip: str,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Remove a hardware mitigation / eBPF kernel block for a specific IP."""
    return await MitigationService.remove_block(request, ip, token)


@router.get("/incidents")
async def list_incidents(
    request: Request,
    limit: int = 100,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Retrieve all logged security incidents (real data)."""
    return await IncidentService.list_incidents(request, token)


@router.get("/incidents/{incident_id}")
async def get_incident(
    request: Request,
    incident_id: str,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Get single incident detail with full security timeline."""
    return await IncidentService.get_incident_detail(request, incident_id, token)


@router.put("/incidents/{incident_id}/status")
async def update_incident_status(
    request: Request,
    incident_id: str,
    payload: StatusUpdate,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Update incident lifecycle status (open, investigating, contained, closed)."""
    return await IncidentService.update_incident_status(request, incident_id, payload.status, token)


@router.post("/incidents/{incident_id}/action")
async def trigger_incident_action(
    request: Request,
    incident_id: str,
    payload: ActionRequest,
    token: dict = Depends(make_permission_checker("firewall")),
):
    """Execute mitigation action on the incident (real data integration)."""
    return await MitigationService.trigger_incident_action(
        request,
        incident_id,
        payload.action,
        payload.label or payload.action,
        token,
        ip=payload.ip,
        reason=payload.reason,
        duration=payload.duration,
    )
