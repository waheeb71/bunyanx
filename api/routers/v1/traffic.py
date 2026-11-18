"""
Enterprise bunyanx - Traffic Statistics & Anomaly Endpoints
GET  /api/v1/statistics          — Live traffic stats
GET  /api/v1/anomalies           — Recent anomaly detections
GET  /api/v1/profiles/{ip}       — IP behavioral profile

FIX (2026-06-21):
  - Corrected state key: bunyanx_controller → bunyanx
  - Corrected SecurityEvent field names: detected_at→timestamp, src_ip→source_ip, confidence→anomaly_score
  - Switched anomaly query from sync 'with session' to async 'async with session'
  - Removed meaningless total_bytes = packets * 850 estimate comment
"""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime
from api.core.auth import verify_token

router = APIRouter(prefix="/api/v1", tags=["traffic"])


class TrafficStats(BaseModel):
    timestamp: datetime
    total_packets: int
    total_bytes: int
    blocked_packets: int
    allowed_packets: int
    unique_sources: int
    unique_destinations: int
    top_protocols: Dict[str, int]


class AnomalyReport(BaseModel):
    timestamp: datetime
    src_ip: str
    anomaly_score: float
    is_anomaly: bool
    reason: str
    confidence: float


@router.get("/statistics", response_model=TrafficStats)
async def get_traffic_statistics(
    request: Request,
    time_window: int = 300,
    token: dict = Depends(verify_token),
):
    """Get traffic statistics from live pipeline and flow tracker if available."""
    # ── Use correct state key ──────────────────────────────────────────────────
    bunyanx = getattr(request.app.state, "bunyanx", None)

    total_packets = 0
    blocked_packets = 0
    allowed_packets = 0
    unique_sources = 0
    unique_destinations = 0
    top_protocols: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0}

    if bunyanx and hasattr(bunyanx, "inspection_pipeline"):
        stats = bunyanx.inspection_pipeline.get_statistics()
        total_packets = stats.get("total_inspections", 0)
        blocked_packets = stats.get("total_blocks", 0)
        allowed_packets = total_packets - blocked_packets

    # Pull unique source/destination counts from flow tracker if available
    total_bytes = 0
    if bunyanx and getattr(bunyanx, "flow_tracker", None):
        try:
            flows = bunyanx.flow_tracker.get_active_flows()
            if flows:
                unique_sources = len({f.get("src_ip") for f in flows if f.get("src_ip")})
                unique_destinations = len({f.get("dst_ip") for f in flows if f.get("dst_ip")})
                proto_count: Dict[str, int] = {}
                for f in flows:
                    p = str(f.get("protocol", "OTHER")).upper()
                    proto_count[p] = proto_count.get(p, 0) + 1
                    total_bytes += (f.get("bytes_sent", 0) + f.get("bytes_received", 0))
                top_protocols = proto_count
        except Exception:
            pass

    return TrafficStats(
        timestamp=datetime.now(),
        total_packets=total_packets,
        total_bytes=total_bytes,
        blocked_packets=blocked_packets,
        allowed_packets=allowed_packets,
        unique_sources=unique_sources,
        unique_destinations=unique_destinations,
        top_protocols=top_protocols,
    )


@router.get("/anomalies", response_model=List[AnomalyReport])
async def get_anomalies(
    request: Request,
    limit: int = 100,
    token: dict = Depends(verify_token),
):
    """Get recent anomaly detections from the active Database."""
    # ── Use correct state key ──────────────────────────────────────────────────
    bunyanx = getattr(request.app.state, "bunyanx", None)
    if not bunyanx or not hasattr(bunyanx, "db"):
        return []

    try:
        from system.database.database import SecurityEvent
        from sqlalchemy.future import select

        # ── async with, correct field names ────────────────────────────────────
        async with bunyanx.db.session() as session:
            result = await session.execute(
                select(SecurityEvent)
                .order_by(SecurityEvent.timestamp.desc())   # was detected_at (wrong)
                .limit(limit)
            )
            recent_events = result.scalars().all()

        reports = []
        for ev in recent_events:
            reports.append(AnomalyReport(
                timestamp=ev.timestamp,                        # was detected_at
                src_ip=ev.source_ip or "Unknown",             # was src_ip (wrong)
                anomaly_score=ev.anomaly_score or 0.0,        # was confidence (wrong)
                is_anomaly=True,
                reason=f"{ev.event_type} - {ev.severity}",
                confidence=ev.anomaly_score or 0.0,           # was confidence (wrong)
            ))
        return reports

    except Exception as e:
        return []


@router.get("/profiles/{ip_address}")
async def get_ip_profile(
    request: Request,
    ip_address: str,
    token: dict = Depends(verify_token),
):
    """Get behavioral profile for an IP address via real UBA logic if loaded."""
    # ── Use correct state key ──────────────────────────────────────────────────
    bunyanx = getattr(request.app.state, "bunyanx", None)

    if bunyanx and getattr(bunyanx, "uba", None):
        try:
            profile = bunyanx.uba.get_profile(ip_address)
            if profile:
                return profile
        except Exception:
            pass

    return {
        "ip": ip_address,
        "reputation_score": 100.0,
        "total_connections": 0,
        "patterns_detected": [],
        "first_seen": datetime.now(),
        "last_seen": datetime.now(),
    }
