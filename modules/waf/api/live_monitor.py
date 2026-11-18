import asyncio
import collections
import datetime
import logging
import time
from typing import List, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger(__name__)

class WAFEventDispatcher:
    """
    Manages active WebSocket connections for the WAF Live Dashboard.
    Broadcasts WAF inspection events (Blocks, Challenges, and high-risk Allows)
    to all connected clients in real-time and maintains a recent events buffer.
    """
    
    def __init__(self):
        self._active_connections: List[WebSocket] = []
        self._recent_events = collections.deque(maxlen=100)
        self._listening = False
        logger.info("WAF Event Dispatcher initialized")

    async def start_listening(self):
        if self._listening: return
        self._listening = True
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics
            bus = await EventBus.instance()
            async def _on_waf_event(event: dict):
                # EventBus delivers the payload dict directly as the handler argument
                await self.broadcast(event)
            await bus.subscribe(Topics.WAF_BLOCK, _on_waf_event)
            await bus.subscribe(Topics.WAF_ALERT, _on_waf_event)
            logger.info("WAF Event Dispatcher subscribed to global EventBus")
        except Exception as e:
            logger.error(f"Failed to subscribe WAF Dispatcher: {e}")

    async def connect(self, websocket: WebSocket):
        """Register an already-accepted WebSocket connection."""
        await self.start_listening()
        self._active_connections.append(websocket)
        logger.debug("Live Dashboard Client connected. Total: %d", len(self._active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self._active_connections:
            self._active_connections.remove(websocket)
            logger.debug("Live Dashboard Client disconnected. Total: %d", len(self._active_connections))

    def get_recent_events(self) -> List[Dict[str, Any]]:
        """Return a copy of recent in-memory WAF events."""
        return list(self._recent_events)

    def _normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        ts = event.get("timestamp") or time.time()
        time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        risk_val = event.get("risk_score")
        if isinstance(risk_val, (int, float)):
            risk_str = f"{risk_val:.2f}"
        else:
            risk_str = str(risk_val or "0.85")

        triggers = event.get("triggers", [])
        if isinstance(triggers, list) and triggers:
            cause_str = ", ".join(str(t) for t in triggers)
        else:
            cause_str = event.get("xai_explanation") or event.get("description") or "فحص وتدقيق أمني"

        return {
            "id": event.get("id") or ts,
            "time": event.get("time") or time_str,
            "ip": event.get("src_ip") or event.get("ip") or "0.0.0.0",
            "path": event.get("path") or "/",
            "action": (event.get("action") or "BLOCK").upper(),
            "risk": risk_str,
            "cause": cause_str,
            "severity": event.get("severity") or "HIGH",
            "method": event.get("method") or "POST",
        }

    async def broadcast(self, event: Dict[str, Any]):
        """Non-blocking broadcast to all connected WebSocket clients and save to recent buffer."""
        norm_event = self._normalize_event(event)
        self._recent_events.appendleft(norm_event)

        # Persist to database if available
        try:
            from system.database.database import _ensure_db_manager, SecurityEvent
            db = _ensure_db_manager()
            if db:
                with db.sync_session() as session:
                    sec_ev = SecurityEvent(
                        timestamp=datetime.datetime.utcnow(),
                        event_type="waf",
                        severity=norm_event["severity"].lower(),
                        source_ip=norm_event["ip"],
                        destination_ip="10.0.0.1",
                        action=norm_event["action"],
                        description=norm_event["cause"],
                        anomaly_score=float(norm_event["risk"]) if norm_event["risk"].replace(".", "", 1).isdigit() else 0.85,
                        event_metadata={"path": norm_event["path"], "id": norm_event["id"], "method": norm_event["method"]},
                    )
                    session.add(sec_ev)
                    session.commit()
        except Exception as _db_err:
            logger.debug("WAF event DB save skipped: %s", _db_err)

        if not self._active_connections:
            return  # Nobody listening
            
        disconnected = []
        for connection in self._active_connections:
            try:
                await connection.send_json(event)
            except Exception as e:
                logger.debug("Failed sending WebSocket event: %s", e)
                disconnected.append(connection)
                
        # Clean up dead connections
        for dead in disconnected:
            self.disconnect(dead)

# Global singleton dispatcher used by the router and the inspector
waf_dispatcher = WAFEventDispatcher()

