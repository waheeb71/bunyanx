from fastapi import APIRouter, WebSocket
import uuid
import logging

from api.websocket.handler import handle_websocket

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSockets Live Feed"])

@router.websocket("/api/v1/ws/live")
async def siem_websocket_endpoint(websocket: WebSocket):
    """SIEM Unified Live Feed (Stats, Alerts, Traffic)"""
    client_id = str(uuid.uuid4())
    await handle_websocket(websocket, client_id)
