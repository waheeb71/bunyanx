from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import StreamingResponse
import json
import asyncio
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from modules.log_manager.engine.log_controller import LogControllerManager, global_memory_handler
from modules.log_manager.config.loader import get_log_settings, save_log_settings

import logging

logger = logging.getLogger(__name__)

class LogManagerConfigSchema(BaseModel):
    enabled: Optional[bool] = None
    default_level: Optional[str] = None
    primary_log_dir: Optional[str] = None
    main_log_file: Optional[str] = None
    max_file_size_bytes: Optional[int] = None
    backup_count: Optional[int] = None
    
    # Nested dictionaries for advanced config
    security_logging: Optional[Dict[str, Any]] = None
    flow_logging: Optional[Dict[str, Any]] = None
    event_sink: Optional[Dict[str, Any]] = None

router = APIRouter(prefix="/api/log_manager", tags=["Log Manager"])

@router.get("/config")
async def get_config():
    """Get log manager configuration."""
    cfg = get_log_settings()
    return {
        "status": "success",
        "data": cfg
    }

@router.put("/config")
async def update_config(request: LogManagerConfigSchema):
    """Update log manager configuration."""
    cfg = get_log_settings()
    dump = request.model_dump(exclude_none=True)
    for k, v in dump.items():
        if isinstance(v, dict) and k in cfg:
            if isinstance(cfg[k], dict):
                cfg[k].update(v)
            else:
                cfg[k] = v
        else:
            cfg[k] = v
    save_log_settings(cfg)
    
    try:
        LogControllerManager.get_instance(cfg)
    except Exception as e:
        logger.error(f"Failed to apply dynamic configuration update: {e}")
        raise HTTPException(status_code=500, detail=f"Configuration saved but active reload failed: {e}")
        
    return {"status": "success"}

@router.get("/logs/stream")
async def stream_logs():
    """Streams logs in real-time as Server-Sent Events (SSE)."""
    async def log_generator():
        async for log_entry in global_memory_handler.subscribe():
            yield f"data: {json.dumps(log_entry)}\n\n"
            
    return StreamingResponse(log_generator(), media_type="text/event-stream")

class ClearLogsRequest(BaseModel):
    file_name: Optional[str] = None

@router.get("/logs/search")
async def search_logs(
    level: Optional[str] = Query(None, description="Log level filter: INFO, WARNING, ERROR"),
    keyword: Optional[str] = Query(None, description="Keyword filter"),
    file_name: Optional[str] = Query(None, description="Specific log file filter"),
    limit: int = Query(200, description="Max result count")
):
    """Searches and parses content from actual .log/.json files on disk."""
    controller = LogControllerManager.get_instance()
    loop = asyncio.get_running_loop()
    try:
        results = await loop.run_in_executor(
            None, controller.search_logs, file_name, level, keyword, limit
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error during log search: {e}")
        raise HTTPException(status_code=500, detail=f"Log search failed: {e}")

    return {
        "status": "success",
        "count": len(results),
        "data": results
    }

@router.post("/logs/clear")
async def clear_logs(request: ClearLogsRequest):
    """Truncates log files (warning: unrecoverable)."""
    controller = LogControllerManager.get_instance()
    loop = asyncio.get_running_loop()
    try:
        cleared = await loop.run_in_executor(None, controller.clear_logs, request.file_name)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        raise HTTPException(status_code=500, detail=f"Log clear failed: {e}")

    return {
        "status": "success",
        "cleared_files": cleared
    }

@router.get("/logs/stats")
async def get_log_stats():
    """Retrieve statistics about log usage and file sizes."""
    controller = LogControllerManager.get_instance()
    loop = asyncio.get_running_loop()
    stats_data = await loop.run_in_executor(None, controller.get_stats)

    blocked = stats_data.get("blocked_count", 0) if isinstance(stats_data, dict) else 0
    total   = stats_data.get("total_events",  0) if isinstance(stats_data, dict) else 0

    return {
        "status": "success",
        "blocked_count": blocked,
        "total_blocked": blocked,
        "total_events": total,
        "data": stats_data
    }

@router.get("/logs/files")
async def list_log_files():
    """Get a list of all existing log files."""
    controller = LogControllerManager.get_instance()
    loop = asyncio.get_running_loop()
    files_data = await loop.run_in_executor(None, controller.list_log_files)
    return {
        "status": "success",
        "data": files_data
    }

@router.get("/events/search")
async def search_events(
    src_ip: Optional[str] = Query(None, description="Source IP to filter by"),
    verdict: Optional[str] = Query(None, description="Verdict filter (allow, drop, etc.)"),
    category: Optional[str] = Query(None, description="Category filter (e.g. WEB_FILTER)"),
    module: Optional[str] = Query(None, description="Module filter (e.g. web_filter)"),
    limit: int = Query(100, description="Max results")
):
    """Search structured security events (Visitor Tracking / SIEM)."""
    controller = LogControllerManager.get_instance()
    results = await controller.query_events(src_ip=src_ip, verdict=verdict, category=category or module, limit=limit)
    
    # Enrich and normalize module and rule/reason attributes
    for ev in results:
        if not ev.get("module"):
            ev["module"] = (
                ev.get("category")
                or ev.get("service")
                or ev.get("event_type")
                or ev.get("source")
                or ev.get("type")
                or "NGFW Guard"
            )
        if not ev.get("rule"):
            ev["rule"] = (
                ev.get("reason")
                or ev.get("signature")
                or ev.get("rule_id")
                or ev.get("description")
                or (f"Rule Check: {ev.get('verdict', 'INSPECT')}")
            )

    return {
        "status": "success",
        "count": len(results),
        "data": results,
        "events": results
    }


@router.get("/visitors")
async def get_visitors(limit: int = 50):
    """Visitor Tracking aggregated view by unique source IP with multi-source telemetry & GeoIP enrichment."""
    controller = LogControllerManager.get_instance()
    events = await controller.query_events(limit=limit * 10)
    
    # Supplementary query to EventsRepository to ensure no recent attack telemetry is missed
    try:
        from api.services.dashboard.events_repository import EventsRepository
        repo_rows = await EventsRepository.fetch_recent_events(limit=limit * 10)
        for row in repo_rows:
            if len(row) >= 5 and row[2]:
                events.append({
                    "event_id": row[0],
                    "timestamp": str(row[1]) if row[1] else None,
                    "src_ip": str(row[2]),
                    "dst_ip": str(row[3]) if len(row) > 3 else None,
                    "verdict": str(row[4]) if len(row) > 4 else "ALLOW",
                    "action": str(row[4]) if len(row) > 4 else "ALLOW",
                    "reason": str(row[5]) if len(row) > 5 else "Security Inspection",
                })
    except Exception as e:
        logger.debug(f"EventsRepository query in get_visitors: {e}")

    visitors_map: Dict[str, Dict[str, Any]] = {}
    for evt in events:
        ip = evt.get("src_ip") or evt.get("source_ip")
        if not ip or ip == "0.0.0.0":
            continue

        if ip not in visitors_map:
            is_lan = ip.startswith(("10.", "172.", "127.", "fe80:"))
            country = evt.get("country") or ("شبكة محلية (LAN)" if is_lan else "موقع خارجي")
            flag = evt.get("flag") or ("🏠" if is_lan else "🌐")
            city = evt.get("city") or ""

            visitors_map[ip] = {
                "src_ip": ip,
                "total_events": 0,
                "blocked_count": 0,
                "allowed_count": 0,
                "last_action": str(evt.get("action") or evt.get("verdict") or "ALLOW").upper(),
                "last_seen": str(evt.get("timestamp") or evt.get("time") or ""),
                "latest_event_id": evt.get("event_id"),
                "country": country,
                "flag": flag,
                "city": city,
                "src_lat": evt.get("src_lat"),
                "src_lng": evt.get("src_lng"),
            }
        v = visitors_map[ip]
        v["total_events"] += 1
        verdict_str = str(evt.get("verdict") or evt.get("action") or "").upper()
        if verdict_str in ["DROP", "BLOCK", "DENY", "REJECT", "CRITICAL", "HIGH"]:
            v["blocked_count"] += 1
        else:
            v["allowed_count"] += 1

    visitors_list = list(visitors_map.values())[:limit]
    return {
        "status": "success",
        "count": len(visitors_list),
        "data": visitors_list
    }

