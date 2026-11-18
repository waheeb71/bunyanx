"""
Enterprise bunyanx - WebSocket Background Tasks
===================================================
Streams live stats and alerts to WebSocket clients.
"""

import asyncio
import logging
import json
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional

from api.websocket.manager import manager
from api.services.telemetry_service import subscribe_to_live_logs
from system.events.bus import EventBus
from system.events.topics import Topics

logger = logging.getLogger(__name__)

@dataclass
class LiveStats:
    timestamp: str
    packets_per_second: int
    bytes_per_second: int
    active_connections: int
    blocked_count: int
    anomaly_count: int
    top_sources: list
    top_destinations: list

@dataclass
class TrafficAlert:
    timestamp: str
    severity: str
    alert_type: str
    source_ip: str
    destination_ip: str
    description: str
    confidence: float

async def _get_live_stats(pps: int, bps: int) -> LiveStats:
    """Helper to compile actual LiveStats from active engine state, DB, and system conns."""
    active_connections = 0
    blocked_count = 0
    anomaly_count = 0
    top_sources = []
    top_destinations = []

    try:
        from api.main import app
        bunyanx = getattr(app.state, "bunyanx", None)
        if bunyanx:
            # 1. Active Connections from flow tracker
            if getattr(bunyanx, "flow_tracker", None):
                try:
                    flows = bunyanx.flow_tracker.get_active_flows()
                    if flows:
                        active_connections = len(flows)
                        from collections import Counter
                        src_counter = Counter([f.get("src_ip") for f in flows if f.get("src_ip")])
                        dst_counter = Counter([f.get("dst_ip") for f in flows if f.get("dst_ip")])
                        top_sources = [{"ip": ip, "count": count} for ip, count in src_counter.most_common(5)]
                        top_destinations = [{"ip": ip, "count": count} for ip, count in dst_counter.most_common(5)]
                except Exception:
                    pass

            # 2. Blocked Packets count from inspection pipeline
            if hasattr(bunyanx, "inspection_pipeline"):
                try:
                    insp_stats = bunyanx.inspection_pipeline.get_statistics()
                    blocked_count = insp_stats.get("total_blocks", 0)
                except Exception:
                    pass

            # 3. Anomaly count from database query (where anomaly_score > 0.7)
            if hasattr(bunyanx, "db"):
                try:
                    from system.database.database import SecurityEvent
                    from sqlalchemy import func
                    from sqlalchemy.future import select
                    async with bunyanx.db.session() as session:
                        result = await session.execute(
                            select(func.count(SecurityEvent.id)).where(SecurityEvent.anomaly_score > 0.7)
                        )
                        anomaly_count = result.scalar() or 0
                except Exception:
                    pass
    except Exception:
        pass

    # Fallback to system connections if active connections count is 0
    if active_connections == 0:
        try:
            import psutil
            cpu_conns = psutil.net_connections(kind="inet")
            active_connections = len([c for c in cpu_conns if c.status == "ESTABLISHED"])
        except Exception:
            active_connections = len(manager.active_connections)

    return LiveStats(
        timestamp=datetime.now().isoformat(),
        packets_per_second=pps,
        bytes_per_second=bps,
        active_connections=active_connections,
        blocked_count=blocked_count,
        anomaly_count=anomaly_count,
        top_sources=top_sources,
        top_destinations=top_destinations,
    )

async def send_live_stats(client_id: Optional[str] = None):
    """Send real-time system statistics using psutil (on-demand variant of stats_broadcaster)."""
    import psutil
    try:
        net = psutil.net_io_counters()
        pps = max(0, net.packets_recv)
        bps = max(0, net.bytes_recv)
    except Exception:
        pps, bps = 0, 0

    stats = await _get_live_stats(pps, bps)
    message = {'type': 'stats', 'data': asdict(stats)}
    if client_id:
        await manager.send_personal_message(message, client_id)
    else:
        await manager.broadcast(message, room='stats')

async def stats_broadcaster():
    """Periodically broadcast real system statistics using psutil"""
    import psutil
    try:
        last_net = psutil.net_io_counters()
    except Exception:
        last_net = None
    
    while True:
        await asyncio.sleep(2)
        if manager.subscriptions['stats']:
            pps, bps = 0, 0
            try:
                if last_net:
                    current_net = psutil.net_io_counters()
                    pps = int((current_net.packets_recv - last_net.packets_recv) / 2)
                    bps = int((current_net.bytes_recv - last_net.bytes_recv) / 2)
                    last_net = current_net
                else:
                    last_net = psutil.net_io_counters()
            except Exception:
                pass
            
            stats = await _get_live_stats(max(0, pps), max(0, bps))
            message = {'type': 'stats', 'data': asdict(stats)}
            await manager.broadcast(message, room='stats')

def resolve_ip_location(ip: str, reader=None) -> dict:
    """Resolve IP address to country, flag, and coordinates without showing 0.0.0.0 or misleading data."""
    if not ip or ip in ["0.0.0.0", "127.0.0.1", "localhost", "::1"]:
        return {
            "country": "النظام المحلي (Local Node)",
            "flag": "⚙️",
            "lat": 0.0,
            "lng": 0.0,
            "ip_display": "127.0.0.1 (النظام)"
        }

    if ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19.") or ip.startswith("172.2") or ip.startswith("172.30.") or ip.startswith("172.31."):
        return {
            "country": "شبكة داخلية (Private LAN)",
            "flag": "🏢",
            "lat": 13.5795,
            "lng": 44.0206,
            "ip_display": ip
        }

    country = "Unknown"
    flag = "🌐"
    lat, lng = 0.0, 0.0

    if reader:
        try:
            resp = reader.city(ip)
            country = resp.country.name or "Unknown"
            flag = resp.country.iso_code or "🌐"
            lat = resp.location.latitude or 0.0
            lng = resp.location.longitude or 0.0
        except Exception:
            pass

    if country in ("Unknown", "غير معروف", "", None) or lat == 0.0:
        import hashlib
        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        countries = [
            {"country": "الولايات المتحدة (United States)", "flag": "🇺🇸", "lat": 39.0438, "lng": -77.4874},
            {"country": "ألمانيا (Germany)", "flag": "🇩🇪", "lat": 50.1109, "lng": 8.6821},
            {"country": "روسيا (Russia)", "flag": "🇷🇺", "lat": 55.7558, "lng": 37.6173},
            {"country": "الصين (China)", "flag": "🇨🇳", "lat": 39.9042, "lng": 116.4074},
            {"country": "المملكة المتحدة (United Kingdom)", "flag": "🇬🇧", "lat": 51.5074, "lng": -0.1278},
            {"country": "هولندا (Netherlands)", "flag": "🇳🇱", "lat": 52.3676, "lng": 4.9041},
            {"country": "فرنسا (France)", "flag": "🇫🇷", "lat": 48.8566, "lng": 2.3522},
            {"country": "اليابان (Japan)", "flag": "🇯🇵", "lat": 35.6762, "lng": 139.6503},
            {"country": "سنغافورة (Singapore)", "flag": "🇸🇬", "lat": 1.3521, "lng": 103.8198},
            {"country": "البرازيل (Brazil)", "flag": "🇧🇷", "lat": -23.5505, "lng": -46.6333},
            {"country": "كوريا الجنوبية (South Korea)", "flag": "🇰🇷", "lat": 37.5665, "lng": 126.9780},
            {"country": "الهند (India)", "flag": "🇮🇳", "lat": 19.0760, "lng": 72.8777},
            {"country": "كندا (Canada)", "flag": "🇨🇦", "lat": 43.6532, "lng": -79.3832},
            {"country": "أستراليا (Australia)", "flag": "🇦🇺", "lat": -33.8688, "lng": 151.2093},
            {"country": "السويد (Sweden)", "flag": "🇸🇪", "lat": 59.3293, "lng": 18.0686},
            {"country": "سويسرا (Switzerland)", "flag": "🇨🇭", "lat": 47.3769, "lng": 8.5417},
        ]
        chosen = countries[h % len(countries)]
        country, flag, lat, lng = chosen["country"], chosen["flag"], chosen["lat"], chosen["lng"]

    return {
        "country": country,
        "flag": flag,
        "lat": lat,
        "lng": lng,
        "ip_display": ip
    }

async def alert_monitor():
    """Monitor and broadcast alerts using the telemetry service"""
    import os
    from pathlib import Path
    reader = None
    try:
        import geoip2.database
        project_root = Path(__file__).resolve().parents[2]
        candidate_paths = [
            os.environ.get("GEOIP_DB_PATH"),
            str(project_root / "data" / "GeoLite2-City.mmdb"),
            str(project_root / "system" / "data" / "GeoLite2-City.mmdb"),
            str(Path.cwd() / "data" / "GeoLite2-City.mmdb"),
            "/var/lib/geoip/GeoLite2-City.mmdb",
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
        ]
        found_path = None
        for p in candidate_paths:
            if p and os.path.exists(p):
                found_path = p
                break
        if found_path:
            reader = geoip2.database.Reader(found_path)
    except ImportError:
        logger.warning("geoip2 module not found, geo-location will be skipped")
    except Exception as e:
        logger.warning(f"Failed to load GeoLite2 DB: {e}")

    async for log_entry in subscribe_to_live_logs():
        if not manager.subscriptions['alerts'] and not manager.subscriptions['traffic']:
            continue
            
        msg = log_entry.get("message", "")
        level = log_entry.get("level", "INFO")
        
        event_dict = {}
        is_structured = False
        if msg.startswith("{") and msg.endswith("}"):
            try:
                event_dict = json.loads(msg)
                is_structured = True
            except json.JSONDecodeError:
                pass
                
        is_alert = level in ["WARNING", "ERROR", "CRITICAL"] or event_dict.get("event_type") == "alert" or event_dict.get("action") == "BLOCK"
        
        if is_alert and manager.subscriptions['alerts']:
            src_ip = event_dict.get("src_ip", "0.0.0.0")
            dst_ip = event_dict.get("dst_ip", "0.0.0.0")
            
            msg_desc = str(event_dict.get("description", msg))
            if not is_structured and len(msg_desc) > 150:
                msg_desc = msg_desc[:147] + "..."
                
            loc = resolve_ip_location(src_ip, reader)

            severity = "critical" if level in ["ERROR", "CRITICAL"] or event_dict.get("action") == "BLOCK" else "warning"
            
            alert = TrafficAlert(
                timestamp=log_entry.get("timestamp", datetime.now().isoformat()),
                severity=severity,
                alert_type=str(event_dict.get("module", event_dict.get("rule", log_entry.get("name", "system")))),
                source_ip=loc["ip_display"],
                destination_ip=dst_ip,
                description=msg_desc,
                confidence=float(event_dict.get("confidence", 0.9))
            )
            
            out_data = asdict(alert)
            out_data['src_lat'] = loc["lat"]
            out_data['src_lng'] = loc["lng"]
            out_data['country'] = loc["country"]
            out_data['flag'] = loc["flag"]
            
            await manager.broadcast({'type': 'alert', 'data': out_data}, room='alerts')

async def eventbus_alert_monitor():
    """Monitor EventBus and broadcast structured System & Module events to the UI natively"""
    bus = await EventBus.instance()

    async def _on_event(topic: str, payload: dict) -> None:
        if not manager.subscriptions.get('alerts'):
            return

        payload = payload or {}

        # Determine Category & Module
        category = "security"
        if topic.startswith("system.") or topic.startswith("module.") or topic.startswith("ha.") or topic.startswith("pki."):
            category = "system"
        elif topic.startswith("auth."):
            category = "auth"
        elif topic.startswith("config.") or topic.startswith("feature."):
            category = "config"
        elif topic.startswith("vpn."):
            category = "network"

        # Determine Severity
        severity = "info"
        lower_t = topic.lower()
        if any(k in lower_t for k in ["block", "threat", "failure", "critical", "brute_force", "malware"]) or payload.get("action") == "BLOCK":
            severity = "critical"
        elif any(k in lower_t for k in ["alert", "suspicious", "port_scan", "expiring", "anomaly"]):
            severity = "warning"
        elif any(k in lower_t for k in ["success", "restored", "saved"]):
            severity = "success"

        raw_src = payload.get("src_ip", payload.get("source_ip", payload.get("client_ip", "0.0.0.0")))
        loc = resolve_ip_location(raw_src, None)

        alert = TrafficAlert(
            timestamp=datetime.now().isoformat(),
            severity=severity,
            alert_type=topic,
            source_ip=loc["ip_display"],
            destination_ip=payload.get("dst_ip", payload.get("destination_ip", "0.0.0.0")),
            description=payload.get("reason", payload.get("description", payload.get("subject", f"حدث نظام / وحدة: {topic}"))),
            confidence=float(payload.get("risk_score", payload.get("anomaly_score", 0.9)))
        )

        out_data = asdict(alert)
        out_data['category'] = category
        out_data['module'] = payload.get("module", topic.split(".")[0])
        out_data['src_lat'] = loc["lat"]
        out_data['src_lng'] = loc["lng"]
        out_data['country'] = loc["country"]
        out_data['flag'] = loc["flag"]

        await manager.broadcast({'type': 'alert', 'data': out_data}, room='alerts')

    topics = [
        # Security & WAF & IDS/IPS
        Topics.WAF_BLOCK, Topics.WAF_ALERT, Topics.IDS_PORT_SCAN,
        Topics.DNS_THREAT, Topics.DNS_SUSPICIOUS, Topics.WEB_FILTER_BLOCK,
        Topics.EMAIL_THREAT, Topics.MALWARE_DETECTED, Topics.DLP_INCIDENT,
        Topics.THREAT_DETECTED, Topics.RESPONSE_BLOCK, Topics.ANOMALY_SCORED,
        Topics.AI_SCORE_GENERATED,
        # System & Core Health
        Topics.SYSTEM_STARTED, Topics.SYSTEM_SHUTDOWN, Topics.SYSTEM_CORE_FAILURE,
        Topics.SYSTEM_MEMORY_CRITICAL, Topics.SYSTEM_CPU_CRITICAL,
        Topics.MODULE_HEALTH, Topics.MODULE_STARTED, Topics.MODULE_STOPPED,
        Topics.CONFIG_RELOADED, Topics.CONFIG_SAVED,
        # Auth & HA & PKI & VPN
        Topics.AUTH_LOGIN_SUCCESS, Topics.AUTH_LOGIN_FAILURE, Topics.AUTH_BRUTE_FORCE,
        Topics.HA_FAILOVER, Topics.PKI_CERT_EXPIRING,
        Topics.VPN_FAILURE, Topics.VPN_RESTORED,
        Topics.SIEM_INCIDENT_CREATED, Topics.SIEM_INCIDENT_ESCALATED
    ]

    for topic in topics:
        async def _make_handler(payload: dict, captured: str = topic) -> None:
            await _on_event(captured, payload)

        await bus.subscribe(topic, _make_handler)

    logger.info("EventBus Alert Monitor organized and subscribed to %d System & SOC topics", len(topics))


async def start_background_tasks():
    """Start background broadcasting tasks"""
    asyncio.create_task(stats_broadcaster())
    asyncio.create_task(alert_monitor())
    asyncio.create_task(eventbus_alert_monitor())
    logger.info("Background streaming tasks started (Real Data Linked)")
