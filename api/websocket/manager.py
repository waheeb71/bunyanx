"""
Enterprise bunyanx - WebSocket Connection Manager
======================================================
Manages WebSocket connections, subscriptions, and broadcasting.
"""

import logging
from typing import Set, Dict, Any, Optional
from datetime import datetime
from fastapi import WebSocket
from fastapi.websockets import WebSocketState
import jwt

from api.core.auth import SECRET_KEY, ALGORITHM

logger = logging.getLogger(__name__)

class ConnectionManager:
    """
    Manage WebSocket connections and broadcasts
    
    Features:
    - Connection management
    - Room-based subscriptions
    - Broadcast to all/specific clients
    - Authentication via JWT
    """
    
    def __init__(self):
        # Active connections by client ID
        self.active_connections: Dict[str, WebSocket] = {}
        
        # Subscription rooms
        self.subscriptions: Dict[str, Set[str]] = {
            'stats': set(),       # Live statistics
            'alerts': set(),      # Alert notifications
            'traffic': set(),     # Live traffic flows
            'anomalies': set()    # Anomaly detections
        }
        
        # Client metadata
        self.client_metadata: Dict[str, Dict] = {}
        
        logger.info("ConnectionManager initialized")
    
    async def connect(
        self,
        websocket: WebSocket,
        client_id: str,
        token: Optional[str] = None
    ) -> bool:
        """Accept new WebSocket connection.

        Uses application_state (server-side) not client_state (client-side)
        to determine whether accept() needs to be called.  client_state can
        already be CONNECTED in some FastAPI versions even before accept(),
        which caused 'WebSocket is not connected. Need to call accept first.'
        """
        try:
            # application_state tracks the SERVER side:
            #   NOT_CONNECTED → accept() → CONNECTED → close() → DISCONNECTED
            # Always call accept() unless we already did.
            if websocket.application_state != WebSocketState.CONNECTED:
                await websocket.accept()
        except Exception as e:
            logger.error(f"Failed to accept WebSocket from {client_id}: {e}")
            return False

        # ── JWT authentication ──────────────────────────────────────────────
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                username = payload.get("sub")
                role = payload.get("role", "guest")
            except jwt.PyJWTError as e:
                logger.warning(f"Invalid token for client {client_id}: {e}")
                # accept() already called — close gracefully before returning
                try:
                    await websocket.close(code=1008, reason="Authentication failed")
                except Exception:
                    pass
                return False
        else:
            username = "anonymous"
            role = "guest"

        self.active_connections[client_id] = websocket
        self.client_metadata[client_id] = {
            'username': username,
            'role': role,
            'connected_at': datetime.now().isoformat(),
            'subscriptions': set()
        }

        logger.info(f"Client {client_id} ({username}) connected")

        try:
            await self.send_personal_message(
                {
                    'type': 'connection',
                    'status': 'connected',
                    'client_id': client_id,
                    'message': f'Welcome {username}!'
                },
                client_id
            )
        except Exception:
            pass

        return True
    
    def disconnect(self, client_id: str):
        """Disconnect client and cleanup"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        for room in self.subscriptions.values():
            room.discard(client_id)
        
        if client_id in self.client_metadata:
            del self.client_metadata[client_id]
        
        logger.info(f"Client {client_id} disconnected")
    
    async def send_personal_message(self, message: Dict[str, Any], client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to {client_id}: {e}")
                self.disconnect(client_id)
    
    async def broadcast(self, message: Dict[str, Any], room: Optional[str] = None):
        """Broadcast message to all clients or specific room"""
        if room and room in self.subscriptions:
            # Snapshot the set → prevents "Set changed size during iteration"
            # if a client disconnects mid-broadcast.
            clients = list(self.subscriptions[room])
        else:
            clients = list(self.active_connections.keys())

        disconnected = []

        for client_id in clients:
            if client_id in self.active_connections:
                websocket = self.active_connections[client_id]
                try:
                    await websocket.send_json(message)
                except (RuntimeError, ConnectionResetError, OSError, Exception) as e:
                    # FIX-WS: Client disconnected during broadcast — this is normal,
                    # not an error. Happens when the browser tab closes or connection resets.
                    logger.debug("Client %s disconnected during broadcast: %s", client_id, e)
                    disconnected.append(client_id)

        for client_id in disconnected:
            self.disconnect(client_id)

    
    def subscribe(self, client_id: str, room: str) -> bool:
        """Subscribe client to a room"""
        if room not in self.subscriptions:
            logger.warning(f"Invalid room: {room}")
            return False
        
        self.subscriptions[room].add(client_id)
        
        if client_id in self.client_metadata:
            self.client_metadata[client_id]['subscriptions'].add(room)
        
        logger.info(f"Client {client_id} subscribed to {room}")
        return True
    
    def unsubscribe(self, client_id: str, room: str) -> bool:
        """Unsubscribe client from a room"""
        if room not in self.subscriptions:
            return False
        
        self.subscriptions[room].discard(client_id)
        
        if client_id in self.client_metadata:
            self.client_metadata[client_id]['subscriptions'].discard(room)
        
        logger.info(f"Client {client_id} unsubscribed from {room}")
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'total_connections': len(self.active_connections),
            'subscriptions': {
                room: len(clients)
                for room, clients in self.subscriptions.items()
            },
            'clients': [
                {
                    'client_id': client_id,
                    'username': meta['username'],
                    'role': meta['role'],
                    'subscriptions': list(meta['subscriptions'])
                }
                for client_id, meta in self.client_metadata.items()
            ]
        }

# Global connection manager
manager = ConnectionManager()
