"""
audio_pipeline_check.py — bunyanx NGFW Audio Pipeline Diagnostic
"""

import asyncio
import sys
import os
import logging
import io

# Force UTF-8 stdout (fixes Windows cp1256 encoding errors)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

sys.path.insert(0, "F:/enterprise_ngfw")

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("audio_check")
logger.setLevel(logging.DEBUG)

PASS = "[OK] "
FAIL = "[ERR]"
WARN = "[WRN]"

results = []

def check(label, ok, detail=""):
    icon = PASS if ok else FAIL
    msg = f"  {icon} {label}"
    if detail:
        msg += f" — {detail}"
    print(msg)
    results.append((label, ok))
    return ok


async def run():
    print("\n" + "="*60)
    print("  bunyanx NGFW — Audio Pipeline Diagnostic")
    print("="*60 + "\n")

    # ── 1. Feature Flags ──────────────────────────────────────────
    print("[1] Feature Flags")
    try:
        from system.config.feature_flags import FeatureFlagManager
        flags = FeatureFlagManager.instance()
        eb_flags = flags.current.event_bus
        check("FeatureFlagManager loaded", True)
        eb_enabled = eb_flags.enabled
        check("event_bus.enabled", eb_enabled, f"backend={eb_flags.backend}" if eb_enabled else "DISABLED → النظام لن يرسل أحداث!")
    except Exception as e:
        check("FeatureFlagManager", False, str(e))
        eb_enabled = False

    # ── 2. EventBus ───────────────────────────────────────────────
    print("\n[2] EventBus")
    try:
        from system.events.bus import EventBus, NullBackend, MemoryBackend
        bus = await EventBus.instance()
        backend_type = type(bus._backend).__name__
        check("EventBus.instance() created", True, f"backend={backend_type}")
        check("Not NullBackend", not isinstance(bus._backend, NullBackend),
              "NullBackend → كل الأحداث تُتجاهل!" if isinstance(bus._backend, NullBackend) else "OK")
        if isinstance(bus._backend, MemoryBackend):
            subs = dict(bus._backend._subscriptions)
            check("MemoryBackend has subscriptions", len(subs) > 0,
                  f"{len(subs)} topics subscribed" if subs else "لا subscriptions — EventSubscriber لم يُسجَّل!")
            print(f"\n     Topics subscribed ({len(subs)}):")
            for t in sorted(subs.keys()):
                print(f"       - {t} ({len(subs[t])} handler(s))")
    except Exception as e:
        check("EventBus", False, str(e))

    # ── 3. AudioManager ───────────────────────────────────────────
    print("\n[3] AudioManager")
    try:
        from system.audio.audio_manager import AudioManager
        mgr = await AudioManager.instance()
        check("AudioManager.instance() created", True)
        check("AudioManager._started", mgr._started,
              "started=True" if mgr._started else "NEVER STARTED → EventSubscriber لم يشترك!")

        if not mgr._started:
            print(f"\n     {WARN} AudioManager لم يبدأ! جارٍ تشغيله الآن...")
            await mgr.start()
            check("AudioManager.start() called manually", mgr._started)

        sub = mgr.event_subscriber
        check("EventSubscriber._subscribed", sub._subscribed,
              "subscribed=True" if sub._subscribed else "لم يشترك في EventBus!")
        check("History buffer initialized", True, f"maxlen={mgr._history.maxlen}")
    except Exception as e:
        check("AudioManager", False, str(e))

    # ── 4. NativePlayer ───────────────────────────────────────────
    print("\n[4] NativePlayer")
    try:
        from system.audio.native_player import NativePlayer, ALERTS_DIR
        status = NativePlayer.get_status()
        check("ALERTS_DIR exists", status["alerts_dir_exists"], f"path={status['alerts_dir']}")
        check("manifest.json loaded", status["manifest_loaded"],
              f"{status['manifest_entries']} entries" if status["manifest_loaded"] else "MISSING manifest.json!")
        check("MP3 files present", status["mp3_count"] > 0, f"{status['mp3_count']} MP3 files")

        # اختبار resolve لـ threat.detected
        fp = NativePlayer._resolve_filepath("threat_detected", 4)
        check("threat_detected resolves to file", fp is not None,
              str(fp) if fp else "لم يجد الملف!")
    except Exception as e:
        check("NativePlayer", False, str(e))

    # ── 5. MuteController ─────────────────────────────────────────
    print("\n[5] MuteController (هل الصوت مكتوم؟)")
    try:
        from system.audio.audio_manager import AudioManager
        mgr = await AudioManager.instance()
        settings = await mgr.mute_controller.get_settings()
        is_muted = await mgr.mute_controller.is_muted()
        check("native_playback_enabled", settings.native_playback_enabled,
              "enabled" if settings.native_playback_enabled else "DISABLED → الصوت معطَّل!")
        check("Not globally muted", not is_muted,
              "OK" if not is_muted else "MUTED → الصوت مكتوم!")
        check("Volume > 0", settings.volume > 0, f"volume={settings.volume:.0%}")
        print(f"     Profile: {settings.profile}")
    except Exception as e:
        check("MuteController", False, str(e))

    # ── 6. اختبار End-to-End: نشر حدث + مراقبة ────────────────────
    print("\n[6] End-to-End Test: publish threat.detected → AudioManager")
    received = {"ok": False, "topic": None}

    try:
        from system.events.bus import EventBus
        from system.events.topics import Topics

        # Subscribe a test handler BEFORE publishing
        bus = await EventBus.instance()
        async def _test_handler(payload: dict):
            received["ok"] = True
            received["topic"] = "threat.detected"
            logger.info(f"[TEST] ✅ Event received: threat.detected payload={payload.get('test_marker')}")

        await bus.subscribe(Topics.THREAT_DETECTED, _test_handler)

        # Publish test event
        await bus.publish(Topics.THREAT_DETECTED, {
            "test_marker": "audio_pipeline_check",
            "src_ip": "10.0.0.1",
            "threat_type": "port_scan",
            "severity": "high",
        })

        # Wait for async processing
        await asyncio.sleep(1.5)
        check("Test event received by handler", received["ok"],
              "Event propagated correctly" if received["ok"] else "Event NOT received — EventBus broken!")

    except Exception as e:
        check("End-to-End publish", False, str(e))

    # ── 7. Sound Router ───────────────────────────────────────────
    print("\n[7] SoundRouter — topic → sound_id")
    try:
        from system.audio.audio_manager import AudioManager
        mgr = await AudioManager.instance()
        test_topics = [
            ("threat.detected", 4),
            ("malware.detected", 5),
            ("ids.port_scan", 4),
            ("auth.brute_force", 5),
            ("system.core_failure", 6),
        ]
        for topic, priority in test_topics:
            profile = mgr.sound_router.route(topic, priority)
            sound_id = profile.get("sound_id", "?")
            check(f"  {topic}", True, f"→ {sound_id} (priority={priority})")
    except Exception as e:
        check("SoundRouter", False, str(e))

    # ── Summary ───────────────────────────────────────────────────
    print("\n" + "="*60)
    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"  النتيجة: {passed}/{total} فحص ناجح")
    if passed == total:
        print(f"  {PASS} كل شيء يعمل بشكل صحيح!")
    else:
        failed = [label for label, ok in results if not ok]
        print(f"  {FAIL} مشاكل في: {', '.join(failed)}")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(run())
