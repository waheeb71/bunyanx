"""
Enterprise bunyanx - WebSocket Handler
===================================================
Handles the WebSocket connection logic and message parsing.
"""

import json
import logging
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.websockets import WebSocketState

from api.websocket.manager import manager
from api.websocket.background import send_live_stats

logger = logging.getLogger(__name__)

async def handle_websocket(websocket: WebSocket, client_id: str):
    """
    Main WebSocket handler
    
    Message format:
    {
        "type": "subscribe|unsubscribe|ping|request",
        "room": "stats|alerts|traffic|anomalies",
        "data": {...}
    }
    """
    token = websocket.query_params.get('token')
    
    connected = await manager.connect(websocket, client_id, token)
    
    if not connected:
        if websocket.application_state != WebSocketState.DISCONNECTED:
            try:
                await websocket.close(code=1008, reason="Authentication failed")
            except Exception:
                pass
        return
    
    try:
        while True:
            try:
                data = await websocket.receive_text()
            except RuntimeError as e:
                logger.warning(f"WebSocket client {client_id} disconnected unexpectedly: {e}")
                break
            
            try:
                message = json.loads(data)
                msg_type = message.get('type')
                
                if msg_type == 'subscribe':
                    room = message.get('room')
                    if room:
                        success = manager.subscribe(client_id, room)
                        await manager.send_personal_message(
                            {
                                'type': 'subscription',
                                'status': 'success' if success else 'failed',
                                'room': room
                            },
                            client_id
                        )
                
                elif msg_type == 'unsubscribe':
                    room = message.get('room')
                    if room:
                        success = manager.unsubscribe(client_id, room)
                        await manager.send_personal_message(
                            {
                                'type': 'unsubscription',
                                'status': 'success' if success else 'failed',
                                'room': room
                            },
                            client_id
                        )
                
                elif msg_type == 'ping':
                    await manager.send_personal_message(
                        {'type': 'pong', 'timestamp': datetime.now().isoformat()},
                        client_id
                    )
                
                elif msg_type == 'request':
                    request_type = message.get('request')
                    if request_type == 'stats':
                        await send_live_stats(client_id)
                    elif request_type == 'connections':
                        stats = manager.get_stats()
                        await manager.send_personal_message(
                            {'type': 'connections_stats', 'data': stats},
                            client_id
                        )
                
                else:
                    await manager.send_personal_message(
                        {'type': 'error', 'message': f'Unknown message type: {msg_type}'},
                        client_id
                    )
            
            except json.JSONDecodeError:
                await manager.send_personal_message(
                    {'type': 'error', 'message': 'Invalid JSON'},
                    client_id
                )
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected normally")
    
    except Exception as e:
        logger.error(f"WebSocket error for {client_id}: {e}", exc_info=True)
        manager.disconnect(client_id)
