"""
bunyanx NGFW — Audio Alert System: REST API Router
======================================================
FastAPI router mounted at /api/audio/

Endpoints:
  GET    /api/audio/settings          — Get current audio settings
  PUT    /api/audio/settings          — Update settings
  POST   /api/audio/mute              — Mute (optionally timed)
  POST   /api/audio/unmute            — Unmute
  GET    /api/audio/profiles          — List sound profiles
  POST   /api/audio/test/{sound_id}   — Test a sound
  GET    /api/audio/history           — Recent audio event history
  GET    /api/audio/events/stream     — SSE live event stream
  GET    /api/audio/event-map         — Full event → sound mapping
  PUT    /api/audio/event-map/{topic} — Override event sound mapping
  DELETE /api/audio/event-map/{topic} — Remove override
  GET    /api/audio/stats             — System stats
"""

import asyncio
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends, status, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import jwt

from system.audio.audio_manager import AudioManager
from api.core.auth import verify_token, require_operator, SECRET_KEY, ALGORITHM

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/audio", tags=["Audio Alert System"])


# ── SSE Token Verification Dependency ─────────────────────────────────
async def verify_sse_token(
    request: Request,
    token: Optional[str] = Query(None)
) -> dict:
    """
    Authenticate Server-Sent Events (SSE) connections.
    Accepts token from query parameters (since browsers can't set headers on EventSource)
    or fall back to Authorization header.
    """
    actual_token = token
    if not actual_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            actual_token = auth_header[7:]

    if not actual_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is required for event stream"
        )

    try:
        payload = jwt.decode(actual_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check blacklist
        bunyanx = getattr(request.app.state, "bunyanx", None)
        if bunyanx and bunyanx.db:
            from sqlalchemy.future import select
            from system.database.database import TokenBlacklist
            async with bunyanx.db.session() as session:
                res = await session.execute(select(TokenBlacklist).filter_by(token=actual_token))
                if res.scalars().first():
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token has been revoked"
                    )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


# ──────────────────────────────────────────────────────────────────────
# Request / Response Models
# ──────────────────────────────────────────────────────────────────────

class SettingsUpdate(BaseModel):
    enabled:              Optional[bool]  = None
    volume:               Optional[float] = Field(None, ge=0.0, le=1.0)
    muted:                Optional[bool]  = None
    profile:              Optional[str]   = Field(None, pattern="^(default|night|silent)$")
    auto_switch_enabled:  Optional[bool]  = None
    day_start_hour:       Optional[int]   = Field(None, ge=0, le=23)
    night_start_hour:     Optional[int]   = Field(None, ge=0, le=23)
    native_playback_enabled: Optional[bool] = None  # تفعيل/تعطيل التشغيل المحلي على السيرفر


class MuteRequest(BaseModel):
    duration_minutes: Optional[int] = Field(
        None, ge=1, le=1440,
        description="Duration in minutes. Omit for permanent mute."
    )


class EventOverrideRequest(BaseModel):
    sound_profile: dict = Field(
        ..., description="Full SoundProfile dict (tones, repeat, gap_ms, etc.)"
    )


# ──────────────────────────────────────────────────────────────────────
# Dependency: lazy AudioManager accessor
# ──────────────────────────────────────────────────────────────────────

async def _mgr() -> AudioManager:
    """
    Returns the AudioManager singleton, ensuring it is started.
    This guarantees EventSubscriber is subscribed even when the API
    is accessed before or without start_firewall_components().
    """
    mgr = await AudioManager.instance()
    if not mgr._started:
        import logging
        logging.getLogger(__name__).info(
            "[AudioAPI] AudioManager not started — starting now (lazy init)"
        )
        await mgr.start()
    return mgr


# ──────────────────────────────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────────────────────────────

@router.get("/settings", summary="Get audio alert settings")
async def get_settings(token: dict = Depends(verify_token)):
    """Return current Audio Alert System settings."""
    mgr = await _mgr()
    settings = await mgr.get_settings()
    return settings.to_dict()


@router.put("/settings", summary="Update audio alert settings")
async def update_settings(body: SettingsUpdate, token: dict = Depends(require_operator)):
    """Update one or more audio alert settings fields."""
    mgr = await _mgr()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    settings = await mgr.update_settings(updates)
    return {"success": True, "settings": settings.to_dict()}


# ──────────────────────────────────────────────────────────────────────
# Mute Control
# ──────────────────────────────────────────────────────────────────────

@router.post("/mute", summary="Mute audio alerts")
async def mute_audio(body: MuteRequest, token: dict = Depends(require_operator)):
    """
    Mute audio alerts.
    Optionally provide duration_minutes for a timed mute.
    Emergency (Level 6) events bypass mute.
    """
    mgr = await _mgr()
    await mgr.mute(body.duration_minutes)
    msg = (f"Muted for {body.duration_minutes} minutes"
           if body.duration_minutes else "Muted permanently")
    return {"success": True, "message": msg}


@router.post("/unmute", summary="Unmute audio alerts")
async def unmute_audio(token: dict = Depends(require_operator)):
    """Remove any active mute and resume audio alerts."""
    mgr = await _mgr()
    await mgr.unmute()
    return {"success": True, "message": "Audio alerts unmuted"}


# ──────────────────────────────────────────────────────────────────────
# Profiles
# ──────────────────────────────────────────────────────────────────────

@router.get("/profiles", summary="List available sound profiles")
async def list_profiles(token: dict = Depends(verify_token)):
    """Return available sound profile names and descriptions."""
    return {
        "profiles": [
            {
                "id": "default",
                "name": "الافتراضي",
                "description": "أصوات كاملة لنوبات العمل العادية",
                "icon": "🔊",
            },
            {
                "id": "night",
                "name": "الوضع الليلي",
                "description": "أصوات أهدأ مناسبة لنوبات الليل",
                "icon": "🌙",
            },
            {
                "id": "silent",
                "name": "صامت",
                "description": "إشعارات بصرية فقط — بدون أصوات (ما عدا الطوارئ)",
                "icon": "🔕",
            },
        ]
    }


# ──────────────────────────────────────────────────────────────────────
# Sound Testing
# ──────────────────────────────────────────────────────────────────────

@router.post("/test/{sound_id}", summary="Test a specific sound")
async def test_sound(sound_id: str, token: dict = Depends(require_operator)):
    """
    Trigger a test sound by sound_id.
    Bypasses mute and cooldown — plays immediately:
      1) On the server's native speakers (if native_playback_enabled=True)
      2) Broadcasts SSE notification to all connected browser clients
    Example: POST /api/audio/test/threat_detected
    """
    mgr = await _mgr()
    notification = await mgr.test_sound(sound_id)
    settings = await mgr.get_settings()
    return {
        "success": True,
        "notification_id": notification.notification_id,
        "sound_id": notification.sound_id,
        "priority": notification.priority,
        "priority_name": notification.priority_name,
        "native_played": settings.native_playback_enabled,
        "message": f"Test sound '{sound_id}' triggered",
    }


@router.post("/test-native/{sound_id}", summary="Test native server-side sound playback")
async def test_native_sound(sound_id: str, token: dict = Depends(require_operator)):
    """
    Play a sound directly on the firewall server's speakers (PowerShell MediaPlayer).
    Does NOT require a connected browser — works even when no SSE clients are active.
    Useful for verifying that server-side audio hardware and files are working.
    Example: POST /api/audio/test-native/threat_detected
    """
    from system.audio.native_player import NativePlayer
    import asyncio

    mgr = await _mgr()
    settings = await mgr.get_settings()
    volume = settings.volume

    # Run in executor to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None,
        NativePlayer.play_sound,
        sound_id,
        5,       # Default to priority 5 (Critical) for test purposes
        volume,
    )

    return {
        "success": True,
        "sound_id": sound_id,
        "volume": volume,
        "message": f"Native playback triggered for '{sound_id}' on server speakers",
    }


# ──────────────────────────────────────────────────────────────────────
# History
# ──────────────────────────────────────────────────────────────────────

@router.get("/history", summary="Get recent audio event history")
async def get_history(limit: int = Query(default=100, ge=1, le=500), token: dict = Depends(verify_token)):
    """Return the most recent audio notification history (ring buffer)."""
    mgr = await _mgr()
    history = await mgr.get_history(limit)
    return {"count": len(history), "events": history}


# ──────────────────────────────────────────────────────────────────────
# SSE Live Stream
# ──────────────────────────────────────────────────────────────────────

@router.get("/events/stream", summary="SSE live audio event stream")
async def audio_event_stream(token: dict = Depends(verify_sse_token)):
    """
    Server-Sent Events stream for live audio notifications.

    Connect with:
        const es = new EventSource('/api/audio/events/stream');
        es.onmessage = (e) => playSound(JSON.parse(e.data));

    The stream sends:
      - Initial 'connected' event
      - AudioNotification JSON for each sound event
      - Keepalive comment every 25 seconds
    """
    mgr = await _mgr()
    q   = await mgr.notification_ctrl.connect()

    return StreamingResponse(
        mgr.notification_ctrl.stream(q),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",   # Disable nginx buffering
            "Connection":        "keep-alive",
        },
    )


# ──────────────────────────────────────────────────────────────────────
# Event → Sound Mapping
# ──────────────────────────────────────────────────────────────────────

@router.get("/event-map", summary="Get full event → sound mapping")
async def get_event_map(token: dict = Depends(verify_token)):
    """Return the complete event topic → sound profile mapping."""
    mgr = await _mgr()
    mapping = mgr.get_event_map()
    return {"count": len(mapping), "mapping": mapping}


@router.put("/event-map/{topic:path}", summary="Override event sound mapping")
async def set_event_override(topic: str, body: EventOverrideRequest, token: dict = Depends(require_operator)):
    """
    Override the sound profile for a specific event topic.
    Example topic: 'threat.detected'
    """
    mgr = await _mgr()
    mgr.set_event_override(topic, body.sound_profile)
    return {"success": True, "topic": topic, "message": "Override applied"}


@router.delete("/event-map/{topic:path}", summary="Remove event sound override")
async def clear_event_override(topic: str, token: dict = Depends(require_operator)):
    """Remove a per-topic sound override and revert to profile default."""
    mgr = await _mgr()
    mgr.clear_event_override(topic)
    return {"success": True, "topic": topic, "message": "Override removed"}


# ──────────────────────────────────────────────────────────────────────
# Native Player: Status + File Management
# ──────────────────────────────────────────────────────────────────────

@router.get("/native-status", summary="Native player diagnostics")
async def get_native_status(token: dict = Depends(require_operator)):
    """
    Return diagnostic info for the server-side NativePlayer:
      - alerts directory path and existence
      - manifest load status and entry count
      - list of all MP3 files found on disk
    """
    from system.audio.native_player import NativePlayer
    return NativePlayer.get_status()


@router.get("/files", summary="List audio alert files on server")
async def list_audio_files(token: dict = Depends(verify_token)):
    """
    List all MP3/WAV audio files stored in var/audio/alerts/
    along with their manifest mappings.
    """
    from system.audio.native_player import NativePlayer, ALERTS_DIR
    import os

    status = NativePlayer.get_status()
    files = []
    if ALERTS_DIR.exists():
        for f in sorted(ALERTS_DIR.iterdir()):
            if f.is_file() and f.suffix.lower() in (".mp3", ".wav", ".ogg"):
                files.append({
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "size_kb": round(f.stat().st_size / 1024, 1),
                })

    return {
        "alerts_dir": status["alerts_dir"],
        "manifest_entries": status["manifest_entries"],
        "file_count": len(files),
        "files": files,
    }


@router.post("/files/reload-manifest", summary="Reload audio manifest from disk")
async def reload_manifest(token: dict = Depends(require_operator)):
    """
    Force-reload manifest.json from var/audio/alerts/manifest.json.
    Call this after manually adding or removing audio files on the server.
    """
    from system.audio.native_player import NativePlayer
    NativePlayer.reload_manifest()
    status = NativePlayer.get_status()
    return {
        "success": True,
        "manifest_entries": status["manifest_entries"],
        "mp3_count": status["mp3_count"],
        "message": "Manifest reloaded from disk",
    }


# ──────────────────────────────────────────────────────────────────────
# Stats
# ──────────────────────────────────────────────────────────────────────

@router.get("/stats", summary="Audio system statistics")
async def get_stats(token: dict = Depends(require_operator)):
    """Return runtime statistics for the Audio Alert System."""
    mgr = await _mgr()
    from system.audio.native_player import NativePlayer
    stats = mgr.stats
    stats["native_player"] = NativePlayer.get_status()
    return stats
