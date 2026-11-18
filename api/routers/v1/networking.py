"""
Enterprise bunyanx - Hardware Network Interface Endpoints
============================================================
Admin-only REST API for managing physical NIC assignments.

Endpoints:
  GET  /api/v1/system/networking/interfaces         → List all NICs with roles
  PUT  /api/v1/system/networking/interfaces         → Assign roles (triggers apply + rollback timer)
  POST /api/v1/system/networking/interfaces/confirm → Commit pending change (cancels rollback)
  POST /api/v1/system/networking/transparent-proxy  → Enable/disable transparent proxy
  GET  /api/v1/system/networking/status             → Legacy iptables status (now nftables)
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field

from api.core.auth import require_admin
from api.services import network_service

router = APIRouter(prefix="/api/v1/system/networking", tags=["Networking"])
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────

class InterfaceRoleAssignment(BaseModel):
    mac: str = Field(..., description="MAC address of the physical NIC")
    role: str = Field(..., description="Role: wan | lan | dmz | unassigned")
    mode: Optional[str] = Field("dhcp", description="IP mode: dhcp | static")
    address: Optional[str] = Field(None, description="Static IP in CIDR format, e.g. 10.0.0.1/24")
    gateway: Optional[str] = Field(None, description="Default gateway for WAN static mode")
    dns: Optional[str] = Field("1.1.1.1", description="DNS server for static mode")

class InterfacesUpdatePayload(BaseModel):
    assignments: list[InterfaceRoleAssignment]

class TransparentProxyToggle(BaseModel):
    enable: bool

# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@router.get("/interfaces")
async def list_interfaces(token: dict = Depends(require_admin)):
    """
    Returns all physical NICs discovered on this appliance,
    enriched with their current role assignment and lock status.
    """
    try:
        nics = await network_service.get_all_interfaces()
        return {"interfaces": nics}
    except Exception as e:
        logger.error(f"Failed to list interfaces: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/interfaces")
async def assign_interfaces(
    payload: InterfacesUpdatePayload,
    token: dict = Depends(require_admin)
):
    """
    Assigns roles to physical NICs by MAC address.
    Triggers a 30-second rollback timer — UI must call /confirm to lock in.
    MGMT interface cannot be reassigned via this endpoint.
    """
    try:
        return await network_service.assign_interfaces_roles(payload.assignments)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except RuntimeError as re:
        raise HTTPException(status_code=500, detail=str(re))
    except Exception as e:
        logger.error(f"Interface assignment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/interfaces/confirm")
async def confirm_interface_change(token: dict = Depends(require_admin)):
    """
    Confirms and commits the pending network configuration change.
    Cancels the automatic rollback timer.
    Must be called within 30 seconds of PUT /interfaces.
    """
    try:
        return await network_service.confirm_changes()
    except Exception as e:
        logger.error(f"Confirm failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/status")
async def networking_status(token: dict = Depends(require_admin)):
    """Return current nftables status and active interface roles."""
    try:
        return await network_service.get_networking_status()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/transparent-proxy")
async def toggle_transparent_proxy(
    request: Request,
    payload: TransparentProxyToggle,
    token: dict = Depends(require_admin)
):
    """Enable or disable transparent proxy rules (nftables NAT)."""
    try:
        return await network_service.toggle_transparent_proxy_mode(payload.enable)
    except Exception as e:
        logger.error(f"Transparent proxy toggle error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
