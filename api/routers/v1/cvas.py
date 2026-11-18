"""
bunyanx NGFW — bunyanx Voice Alert Service (CVAS) API Router
================================================================
FastAPI router mounted under /api/v1/cvas

Provides complete commercial management for CVAS spoken alert subsystem.
Endpoints:
  GET    /api/v1/cvas/status          — Subsystem runtime status
  GET    /api/v1/cvas/health          — Subsystem health state
  GET    /api/v1/cvas/statistics      — Subsystem speech & queue metrics
  GET    /api/v1/cvas/voices          — Available TTS voices on host system
  GET    /api/v1/cvas/languages       — Supported spoken languages
  GET    /api/v1/cvas/events          — Event coverage matrix & phrase library
  GET    /api/v1/cvas/history         — Spoken alert history ring buffer
  GET    /api/v1/cvas/configuration   — Current YAML configuration
  PUT    /api/v1/cvas/configuration   — Update configuration
  POST   /api/v1/cvas/test            — Trigger test spoken alert
  POST   /api/v1/cvas/speak           — Synthesize custom spoken text
  POST   /api/v1/cvas/reload          — Reload YAML config & JSON phrase library
  POST   /api/v1/cvas/clear_queue     — Flush pending items from priority queue
  POST   /api/v1/cvas/preview         — Preview phrase template with dynamic parameters
  POST   /api/v1/cvas/enable          — Enable voice alert service
  POST   /api/v1/cvas/disable         — Disable voice alert service
  POST   /api/v1/cvas/mute            — Mute spoken alerts
  POST   /api/v1/cvas/unmute          — Unmute spoken alerts
  POST   /api/v1/cvas/reset           — Reset statistics counters
  DELETE /api/v1/cvas/history         — Clear spoken alert history log
"""

import logging
import yaml
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from system.cvas.cvas_service import CVASService
from system.audio.native_player import NativePlayer
from api.core.auth import verify_token, require_operator, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cvas", tags=["bunyanx Voice Alert Service (CVAS)"])


def get_cvas() -> CVASService:
    service = CVASService.instance()
    if not service.running and service.enabled:
        # Lazy initialization if service not started yet.
        # FIX: use get_running_loop() — get_event_loop() is deprecated in Python 3.10+
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                asyncio.create_task(service.start())
        except RuntimeError:
            pass  # No running event loop — service will start via lifespan
    return service


# ── Request / Response Pydantic Schemas ────────────────────────────────────────

class CVASConfigUpdate(BaseModel):
    """
    All fields are optional (PATCH semantics).
    Constraints are applied manually in the endpoint to avoid Pydantic v2 strict
    float validation issues (e.g. HTML sliders producing 1.0000000000000002).
    """
    enabled:                Optional[bool]  = None
    language:               Optional[str]   = None
    voice_gender:           Optional[str]   = None
    speed_wpm:              Optional[float] = None   # stored as int, float accepted for slider safety
    volume:                 Optional[float] = None
    pitch:                  Optional[float] = None
    speech_mode:            Optional[str]   = None
    tts_engine:             Optional[str]   = None
    audio_effect:           Optional[str]   = None
    auto_language:          Optional[bool]  = None
    rate_limit_per_min:     Optional[float] = None   # stored as int, float accepted for slider safety
    deduplication_window_s: Optional[float] = None
    ip_cooldown_s:          Optional[float] = None
    window_seconds:         Optional[float] = None
    min_burst_count:        Optional[float] = None
    allow_critical_interrupt: Optional[bool] = None


class SpeakRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=500)
    verbosity: str = Field(default="level1_critical", description="level1_critical, level2_high, level3_medium")
    topic: str = Field(default="manual.alert")


class PreviewRequest(BaseModel):
    topic: str = Field(..., description="Event topic key, e.g. threat.detected")
    verbosity_level: str = Field(default="level1_critical", description="level1_critical | level2_high | level3_medium")
    language: str = Field(default="ar-SA")
    payload: Dict[str, Any] = Field(default_factory=dict)


# ── Status & Health ─────────────────────────────────────────────────────────────

@router.get("/status", summary="Get CVAS service status")
async def get_status(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    return cvas.status()


@router.get("/health", summary="Get CVAS health check")
async def get_health(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    return {
        "status": "healthy" if cvas.running else "degraded",
        "running": cvas.running,
        "enabled": cvas.enabled,
        "muted": cvas.muted,
        "worker_alive": cvas.tts_worker.is_alive() if cvas.tts_worker else False,
        "queue_size": cvas.priority_engine._queue.qsize() if cvas.priority_engine else 0,
    }


@router.get("/statistics", summary="Get CVAS subsystem statistics")
async def get_statistics(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    return cvas.statistics()


# ── Voices & Languages ──────────────────────────────────────────────────────────

@router.get("/voices", summary="List available TTS voices")
async def list_voices(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    return {"count": len(cvas.get_available_voices()), "voices": cvas.get_available_voices()}


@router.get("/languages", summary="List supported spoken languages")
async def list_languages(token: dict = Depends(verify_token)):
    return {
        "default": "ar-SA",
        "languages": [
            {"code": "ar-SA", "name": "العربية (السعودية) - Arabic", "flag": "🇸🇦"},
            {"code": "en-US", "name": "English (United States)", "flag": "🇺🇸"},
        ]
    }


# ── Coverage & Events ───────────────────────────────────────────────────────────

@router.get("/events", summary="Get event coverage matrix and templates")
async def get_events(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    templates = cvas.phrase_engine.get_supported_events() if cvas.phrase_engine else {}
    from system.cvas.subscriber import CVAS_SUBSCRIBED_TOPICS
    
    matrix = []
    for topic in CVAS_SUBSCRIBED_TOPICS:
        entry = templates.get(topic, {})
        handled = topic in templates
        matrix.append({
            "topic": topic,
            "handled": handled,
            "title": entry.get("title", topic),
            "description": entry.get("description", "System event"),
            "variables": entry.get("variables", []),
            "has_arabic": "ar-SA" in str(entry),
            "has_english": "en-US" in str(entry),
        })
    return {"total_subscribed": len(CVAS_SUBSCRIBED_TOPICS), "handled_count": len([m for m in matrix if m["handled"]]), "events": matrix}


# ── Spoken History ──────────────────────────────────────────────────────────────

@router.get("/history", summary="Get spoken alert history")
async def get_history(limit: int = Query(default=100, ge=1, le=500), token: dict = Depends(verify_token)):
    cvas = get_cvas()
    items = list(cvas.history)[:limit]
    return {"count": len(items), "history": items}


@router.delete("/history", summary="Clear spoken alert history")
async def clear_history(token: dict = Depends(require_operator)):
    cvas = get_cvas()
    cvas.history.clear()
    return {"success": True, "message": "Spoken alert history cleared."}


# ── Configuration Management ────────────────────────────────────────────────────

@router.get("/configuration", summary="Get current CVAS configuration")
async def get_configuration(token: dict = Depends(verify_token)):
    cvas = get_cvas()
    return cvas.config


@router.put("/configuration", summary="Update CVAS configuration")
async def update_configuration(body: CVASConfigUpdate, token: dict = Depends(require_operator)):
    cvas = get_cvas()
    cvas_conf = cvas.config.get("cvas", {})

    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No configuration fields provided for update.")

    # Manual clamping replaces Pydantic ge/le constraints.
    # This avoids 422 errors from floating-point edge cases (e.g. slider at max
    # producing 1.0000000000000002 which fails le=1.0).
    if "speed_wpm" in updates and updates["speed_wpm"] is not None:
        updates["speed_wpm"] = int(max(100, min(300, updates["speed_wpm"])))
    if "volume" in updates and updates["volume"] is not None:
        updates["volume"] = round(max(0.0, min(1.0, updates["volume"])), 4)
    if "pitch" in updates and updates["pitch"] is not None:
        updates["pitch"] = round(max(0.5, min(2.0, updates["pitch"])), 4)
    if "rate_limit_per_min" in updates and updates["rate_limit_per_min"] is not None:
        updates["rate_limit_per_min"] = int(max(1, min(60, updates["rate_limit_per_min"])))
    if "deduplication_window_s" in updates and updates["deduplication_window_s"] is not None:
        updates["deduplication_window_s"] = max(5.0, min(300.0, updates["deduplication_window_s"]))
    if "ip_cooldown_s" in updates and updates["ip_cooldown_s"] is not None:
        updates["ip_cooldown_s"] = max(5.0, min(300.0, updates["ip_cooldown_s"]))

    if "window_seconds" in updates and updates["window_seconds"] is not None:
        updates["window_seconds"] = max(5.0, min(300.0, updates["window_seconds"]))
    if "min_burst_count" in updates and updates["min_burst_count"] is not None:
        updates["min_burst_count"] = int(max(2, min(50, updates["min_burst_count"])))

    for k, v in updates.items():
        if k in ("rate_limit_per_min", "deduplication_window_s", "ip_cooldown_s"):
            cvas_conf.setdefault("cooldown", {})[k] = v
        elif k in ("window_seconds", "min_burst_count"):
            cvas_conf.setdefault("aggregation", {})[k] = v
        elif k == "allow_critical_interrupt":
            cvas_conf.setdefault("priority_override", {})["allow_critical_interrupt"] = v
        else:
            cvas_conf[k] = v

    cvas.config["cvas"] = cvas_conf

    # Save to yaml file
    try:
        with open(cvas.config_path, "w", encoding="utf-8") as f:
            yaml.dump(cvas.config, f, allow_unicode=True, default_flow_style=False)
    except Exception as e:
        logger.warning(f"[CVAS:API] Failed to write updated config to file: {e}")

    await cvas.reload()
    return {"success": True, "message": "CVAS configuration updated.", "config": cvas.config}


# ── Service Control & Actions ───────────────────────────────────────────────────

@router.post("/test", summary="Trigger test voice alert")
async def test_alert(topic: Optional[str] = "malware.detected", token: dict = Depends(require_operator)):
    cvas = get_cvas()
    test_payload = {
        "src_ip": "185.220.101.5",
        "dst_ip": "10.0.4.15",
        "country": "Germany",
        "city": "Frankfurt",
        "module": "Malware & AV Inspection Engine",
        "threat_type": "Trojan.Win32.Ransomware",
        "action": "Blocked & Quarantined",
    }
    await cvas.process_event_async(topic, test_payload)
    return {"success": True, "message": f"Test voice alert dispatched for topic '{topic}'"}


@router.post("/speak", summary="Synthesize custom spoken phrase")
async def speak_phrase(body: SpeakRequest, token: dict = Depends(require_operator)):
    cvas = get_cvas()
    success = cvas.speak_manual_phrase(text=body.text, verbosity=body.verbosity, topic=body.topic)
    return {"success": success, "text": body.text, "message": "Phrase enqueued for speech synthesis" if success else "Speech dropped or muted"}


@router.post("/reload", summary="Reload configuration and templates")
async def reload_service(token: dict = Depends(require_operator)):
    cvas = get_cvas()
    await cvas.reload()
    return {"success": True, "message": "CVAS configuration & phrase templates reloaded from disk."}


@router.post("/clear_queue", summary="Clear active priority queue")
async def clear_queue(token: dict = Depends(require_operator)):
    cvas = get_cvas()
    cleared = cvas.priority_engine.clear_queue() if cvas.priority_engine else 0
    return {"success": True, "cleared_count": cleared, "message": f"Cleared {cleared} pending items from priority queue."}


@router.post("/preview", summary="Preview spoken text template synthesis")
async def preview_template(body: PreviewRequest, token: dict = Depends(verify_token)):
    cvas = get_cvas()
    if not cvas.phrase_engine:
        raise HTTPException(status_code=500, detail="Phrase engine not initialized.")

    spoken_text, template_used = cvas.phrase_engine.generate_spoken_text(
        topic=body.topic,
        payload=body.payload,
        verbosity_level=body.verbosity_level,
        language=body.language
    )
    return {
        "topic": body.topic,
        "language": body.language,
        "template_used": template_used,
        "spoken_text": spoken_text,
    }


@router.post("/enable", summary="Enable CVAS service")
async def enable_cvas(token: dict = Depends(require_admin)):
    cvas = get_cvas()
    cvas.enabled = True
    if not cvas.running:
        await cvas.start()
    return {"success": True, "enabled": True, "message": "bunyanx Voice Alert Service enabled."}


@router.post("/disable", summary="Disable CVAS service")
async def disable_cvas(token: dict = Depends(require_admin)):
    cvas = get_cvas()
    cvas.enabled = False
    if cvas.running:
        await cvas.stop()
    return {"success": True, "enabled": False, "message": "bunyanx Voice Alert Service disabled."}


@router.post("/mute", summary="Mute CVAS voice alerts")
async def mute_cvas(token: dict = Depends(require_operator)):
    cvas = get_cvas()
    cvas.muted = True
    return {"success": True, "muted": True, "message": "bunyanx Voice Alerts muted."}


@router.post("/unmute", summary="Unmute CVAS voice alerts")
async def unmute_cvas(token: dict = Depends(require_operator)):
    cvas = get_cvas()
    cvas.muted = False
    return {"success": True, "muted": False, "message": "bunyanx Voice Alerts unmuted."}


# ── Alert Tones Control (NativePlayer) ─────────────────────────────────────────

@router.get("/tones/status", summary="Get alert tones on/off state")
async def get_tones_status(token: dict = Depends(verify_token)):
    """
    Returns whether alert tone sounds (NativePlayer MP3 files) are currently
    enabled.  CVAS TTS speech is a separate toggle and is unaffected.
    """
    return {
        "tones_enabled": NativePlayer.get_tones_enabled(),
        "message": (
            "نغمات التنبيه مفعلة — تعمل بجانب الناطق." if NativePlayer.get_tones_enabled()
            else "نغمات التنبيه متوقفة — الناطق يعمل وحده."
        ),
    }


@router.post("/tones/enable", summary="Enable alert tone sounds")
async def enable_tones(token: dict = Depends(require_operator)):
    """Enable NativePlayer alert tone sounds. Speech (TTS) is unaffected."""
    NativePlayer.set_tones_enabled(True)
    return {"success": True, "tones_enabled": True, "message": "تم تفعيل نغمات التنبيه الصوتية."}


@router.post("/tones/disable", summary="Disable alert tone sounds")
async def disable_tones(token: dict = Depends(require_operator)):
    """
    Disable NativePlayer alert tone sounds.
    CVAS TTS speech continues working normally — only the MP3 alert tones stop.
    """
    NativePlayer.set_tones_enabled(False)
    return {"success": True, "tones_enabled": False, "message": "تم إيقاف نغمات التنبيه — الناطق يعمل وحده."}


@router.post("/reset", summary="Reset statistics counters")
async def reset_cvas(token: dict = Depends(require_admin)):
    cvas = get_cvas()
    if cvas.priority_engine:
        cvas.priority_engine.stats = {
            "enqueued": 0,
            "spoken": 0,
            "dropped_full": 0,
            "dropped_rate_limit": 0,
            "cleared": 0,
        }
    cvas.history.clear()
    return {"success": True, "message": "CVAS statistics and history reset."}
