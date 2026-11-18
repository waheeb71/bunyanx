"""
bunyanx Voice Alert Service (CVAS) - Main Service Orchestrator
=================================================================
Core service lifecycle manager for CVAS.
Orchestrates GeoIP enrichment, Event Aggregation, Phrase Synthesis, Priority Queueing,
History Ring Buffer, and pyttsx3/PulseAudio Background Speech rendering.

DESIGN RULES:
  - Every runtime setting is read from cvas_config.yaml (no silent Python defaults).
  - Payload dicts are COPIED before mutation to prevent EventBus side-effects.
  - Singleton creation is protected by a threading.Lock.
  - Watchdog monitors TTS worker and restarts it if it dies unexpectedly.
"""

import asyncio
import logging
import threading
import yaml
import time
from collections import deque
from pathlib import Path
from typing import Dict, Any, Optional, List

from .geo_enricher import GeoEnricher
from .aggregator import EventAggregator
from .phrase_engine import PhraseEngine
from .priority_engine import PriorityEngine
from .tts_worker import CVASWorkerThread, PYTTSX3_AVAILABLE
from .subscriber import CVASSubscriber

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Path resolution — no hardcoded drive letters
# ---------------------------------------------------------------------------
_HERE = Path(__file__).parent  # system/cvas/
_DEFAULT_CONFIG = _HERE / "config" / "cvas_config.yaml"


class CVASService:
    """
    bunyanx Voice Alert Service (CVAS) Main Service Instance.
    Thread-safe Singleton / Lifecycle orchestrator.
    """

    _instance: Optional["CVASService"] = None
    _instance_lock: threading.Lock = threading.Lock()

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else _DEFAULT_CONFIG
        self.config: Dict[str, Any] = {}
        self.enabled = True
        self.muted = False
        self.running = False

        # Spoken Alerts History Ring Buffer (Max 500 items)
        self.history: deque = deque(maxlen=500)

        # Components
        self.geo_enricher: Optional[GeoEnricher] = None
        self.aggregator: Optional[EventAggregator] = None
        self.phrase_engine: Optional[PhraseEngine] = None
        self.priority_engine: Optional[PriorityEngine] = None
        self.tts_worker: Optional[CVASWorkerThread] = None
        self.subscriber: Optional[CVASSubscriber] = None
        self._flush_task: Optional[asyncio.Task] = None
        self._watchdog_task: Optional[asyncio.Task] = None

        self._load_config()

    @classmethod
    def instance(cls) -> "CVASService":
        """Thread-safe singleton accessor (FIX: BUG-04)."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Config ──────────────────────────────────────────────────────────────

    def _load_config(self) -> None:
        """Load cvas_config.yaml. Uses __file__-relative path — no CWD dependency."""
        if not self.config_path.exists():
            logger.warning(
                f"[CVAS:Service] Config not found at {self.config_path}. "
                "Operating with built-in defaults."
            )
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.config = yaml.safe_load(f) or {}
            logger.info(f"[CVAS:Service] Loaded configuration from {self.config_path}")
        except Exception as e:
            logger.warning(f"[CVAS:Service] Failed to load yaml config: {e}. Using defaults.")

        cvas_conf = self.config.get("cvas", {})
        self.enabled = cvas_conf.get("enabled", True)

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def initialize_components(self) -> None:
        """Instantiate all sub-components. Settings come from cvas_config.yaml."""
        cvas_conf = self.config.get("cvas", {})
        language = cvas_conf.get("language", "ar-SA")

        # 1. GeoIP Enricher
        geoip_conf = cvas_conf.get("geoip", {})
        db_path = geoip_conf.get("database_path") if geoip_conf.get("enabled", True) else None
        # Resolve relative path relative to project root (two levels up from system/cvas/)
        if db_path:
            db_path_obj = Path(db_path)
            if not db_path_obj.is_absolute():
                db_path_obj = _HERE.parent.parent / db_path
            db_path = str(db_path_obj) if db_path_obj.exists() else None
        self.geo_enricher = GeoEnricher(db_path=db_path)

        # 2. Event Aggregator (FIX: CONTRADICTION-04 — honour aggregation.enabled)
        agg_conf = cvas_conf.get("aggregation", {})
        agg_enabled = agg_conf.get("enabled", True)
        if agg_enabled:
            window_s = float(agg_conf.get("window_seconds", 30))
            min_burst = int(agg_conf.get("min_burst_count", 3))
            cooldown_conf = cvas_conf.get("cooldown", {})
            dedup_window_s = float(cooldown_conf.get("deduplication_window_s", 45))
            ip_cooldown_s = float(cooldown_conf.get("ip_cooldown_s", 60))
            self.aggregator = EventAggregator(
                window_seconds=window_s,
                min_burst_count=min_burst,
                deduplication_window_s=dedup_window_s,
                ip_cooldown_s=ip_cooldown_s,
            )
        else:
            self.aggregator = None
            logger.info("[CVAS:Service] Event aggregation disabled by config.")

        # 3. Phrase Engine
        self.phrase_engine = PhraseEngine(default_language=language)

        # 4. Priority Engine
        cooldown_conf = cvas_conf.get("cooldown", {})
        queue_size = int(cvas_conf.get("queue", {}).get("max_size", 100))
        rate_limit = int(cooldown_conf.get("rate_limit_per_min", 10))
        self.priority_engine = PriorityEngine(max_queue_size=queue_size, rate_limit_per_min=rate_limit)

        # 5. Worker Thread (pass full config so worker can read cvas sub-dict)
        self.tts_worker = CVASWorkerThread(priority_engine=self.priority_engine, config=self.config)

        # 6. Subscriber
        self.subscriber = CVASSubscriber(orchestrator=self)

    async def start(self) -> None:
        """Starts CVAS service and background workers."""
        if self.running or not self.enabled:
            return

        logger.info("[CVAS:Service] Starting bunyanx Voice Alert Service...")
        self.initialize_components()

        # Start TTS worker thread
        if self.tts_worker:
            self.tts_worker.start()

        # Subscribe to EventBus
        if self.subscriber:
            await self.subscriber.subscribe_all()

        # Start periodic aggregation flush loop
        self._flush_task = asyncio.create_task(
            self._periodic_flush_loop(), name="cvas_flush_loop"
        )

        # Start watchdog (FIX: ARCH-05)
        cvas_conf = self.config.get("cvas", {})
        if cvas_conf.get("watchdog", {}).get("enabled", True):
            self._watchdog_task = asyncio.create_task(
                self._watchdog_loop(), name="cvas_watchdog"
            )

        self.running = True
        logger.info("=========================================================")
        logger.info("   bunyanx Voice Alert Service (CVAS) Initialized ✓   ")
        logger.info("=========================================================")

    async def stop(self) -> None:
        """Stops CVAS service gracefully."""
        if not self.running:
            return

        logger.info("[CVAS:Service] Stopping CVAS service...")
        self.running = False

        for task in (self._flush_task, self._watchdog_task):
            if task:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        if self.tts_worker:
            self.tts_worker.stop()

        if self.geo_enricher:
            self.geo_enricher.close()

        logger.info("[CVAS:Service] CVAS service stopped.")

    async def reload(self) -> None:
        """Hot-reload: re-reads cvas_config.yaml and propagates all live settings."""
        self._load_config()
        cvas_conf = self.config.get("cvas", {})
        new_language = cvas_conf.get("language", "ar-SA")

        # Reload phrase library AND sync language
        if self.phrase_engine:
            self.phrase_engine._load_phrase_library()
            self.phrase_engine.default_language = new_language

        # Propagate the refreshed cvas sub-dict to TTS worker (atomic replace)
        if self.tts_worker:
            self.tts_worker.config = cvas_conf   # dict replace is GIL-atomic in CPython

        # Propagate rate-limit changes to the priority engine
        if self.priority_engine:
            self.priority_engine.rate_limit_per_min = (
                cvas_conf.get("cooldown", {}).get("rate_limit_per_min", 10)
            )

        logger.info(
            f"[CVAS:Service] Reloaded — language={new_language} "
            f"speed={cvas_conf.get('speed_wpm', 175)} wpm "
            f"volume={cvas_conf.get('volume', 0.9)} "
            f"tts_engine={cvas_conf.get('tts_engine', 'auto')} "
            f"audio_effect={cvas_conf.get('audio_effect', 'none')}"
        )

    # ── Background loops ─────────────────────────────────────────────────────

    async def _periodic_flush_loop(self) -> None:
        """Flushes expired burst aggregation buckets every 5 seconds."""
        while self.running:
            try:
                await asyncio.sleep(5.0)
                if self.aggregator:
                    burst_summaries = self.aggregator.flush_expired_buckets()
                    for burst_payload in burst_summaries:
                        await self._process_single_payload("threat.detected", burst_payload)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CVAS:Service] Aggregation flush loop error: {e}")

    async def _watchdog_loop(self) -> None:
        """
        Watchdog: monitors TTS worker thread health and restarts it if dead.
        (FIX: ARCH-05) Settings from cvas_config.yaml watchdog section.
        """
        cvas_conf = self.config.get("cvas", {})
        wd_conf = cvas_conf.get("watchdog", {})
        check_interval = float(wd_conf.get("check_interval_s", 30))
        max_restarts = int(wd_conf.get("max_restart_attempts", 5))
        restart_count = 0

        while self.running:
            try:
                await asyncio.sleep(check_interval)
                if not self.running:
                    break

                if self.tts_worker and not self.tts_worker.is_alive():
                    if restart_count >= max_restarts:
                        logger.error(
                            f"[CVAS:Watchdog] TTS worker died {restart_count} times — "
                            "giving up. Check system audio configuration."
                        )
                        break

                    restart_count += 1
                    logger.warning(
                        f"[CVAS:Watchdog] TTS worker thread died unexpectedly "
                        f"(attempt {restart_count}/{max_restarts}). Restarting..."
                    )
                    try:
                        # Re-create and start fresh worker
                        self.tts_worker = CVASWorkerThread(
                            priority_engine=self.priority_engine,
                            config=self.config,
                        )
                        self.tts_worker.start()
                        logger.info("[CVAS:Watchdog] TTS worker restarted successfully.")
                    except Exception as exc:
                        logger.error(f"[CVAS:Watchdog] Failed to restart TTS worker: {exc}")
                else:
                    # Worker is alive — reset counter
                    restart_count = 0

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CVAS:Watchdog] Watchdog loop error: {e}")

    # ── Event processing pipeline ────────────────────────────────────────────

    def map_severity_to_verbosity(self, topic: str, payload: Dict[str, Any]) -> str:
        """
        Maps topic and payload severity to CVAS verbosity level.
        Returns one of: level1_critical | level2_high | level3_medium | level4_low_info
        """
        severity = (payload.get("severity") or payload.get("priority") or "").lower()

        if (
            topic in (
                "system.core_failure", "ha.failover", "siem.incident_escalated",
                "pki.cert_invalid", "system.memory_critical", "system.cpu_critical",
            )
            or severity == "critical"
        ):
            return "level1_critical"

        if (
            topic in (
                "malware.detected", "threat.detected", "waf.block", "waf.alert",
                "auth.brute_force", "dlp.incident", "dns.threat", "email.threat",
                "ids.port_scan", "vpn.failure", "correlation.triggered",
                "response.block", "response.quarantine", "ai.score_generated",
            )
            or severity == "high"
        ):
            return "level1_critical" if topic in ("malware.detected", "response.block") else "level2_high"

        if (
            topic in (
                "web_filter.block", "dns.suspicious", "vpn.restored", "anomaly.scored",
                "pki.cert_expiring", "auth.login_failure", "system.shutdown",
                "captive_portal.login", "captive_portal.logout",
            )
            or severity == "medium"
        ):
            return "level3_medium"

        return "level4_low_info"

    async def process_event_async(self, topic: str, payload: Dict[str, Any]) -> None:
        """
        Main non-blocking processing pipeline for an incoming event.
        """
        if not self.running or not self.enabled or self.muted:
            return

        try:
            # Step 1: Burst Event Aggregation & Deduplication
            if self.aggregator:
                processed_payload = self.aggregator.process_event(topic, payload)
                if processed_payload is None:
                    return
                payload = processed_payload

            await self._process_single_payload(topic, payload)
        except Exception as e:
            logger.error(f"[CVAS:Service] Error in process_event_async for {topic}: {e}")

    async def _process_single_payload(self, topic: str, payload: Dict[str, Any]) -> None:
        # FIX (BUG-05): copy payload before mutation to avoid EventBus side-effects
        payload = dict(payload)

        # Step 2: GeoIP Enrichment
        src_ip = payload.get("src_ip", "")
        if src_ip and self.geo_enricher:
            geo_info = self.geo_enricher.lookup(src_ip)
            payload["country"] = geo_info.get("country", "")
            payload["city"] = geo_info.get("city", "")

        # Step 3: Verbosity level check
        verbosity_level = self.map_severity_to_verbosity(topic, payload)

        # FIX (CONTRADICTION-02): read verbosity_levels from YAML to decide silence
        cvas_conf = self.config.get("cvas", {})
        vl_conf = cvas_conf.get("verbosity_levels", {})
        resolved_level = vl_conf.get(verbosity_level, verbosity_level)

        if resolved_level in ("silent_ui_only", "level4_low_info") or verbosity_level == "level4_low_info":
            return

        speech_mode = cvas_conf.get("speech_mode", "natural")

        # FIX (CONTRADICTION-03): auto_language — use payload locale if present
        language = cvas_conf.get("language", "ar-SA")
        if cvas_conf.get("auto_language", False):
            language = payload.get("operator_language") or payload.get("session_language") or language

        # speech_mode="critical_only" suppresses non-critical spoken alerts
        if speech_mode == "critical_only" and verbosity_level != "level1_critical":
            logger.debug(f"[CVAS:Service] Suppressed {topic} ({verbosity_level}) due to speech_mode=critical_only")
            return

        # Check IP-level voice cooldown
        if src_ip and not payload.get("is_burst") and verbosity_level != "level1_critical":
            if self.aggregator and self.aggregator.is_ip_in_cooldown(src_ip):
                logger.debug(f"[CVAS:Service] Suppressed alert for IP in voice cooldown: {src_ip}")
                return

        if self.phrase_engine:
            spoken_text, level_used = self.phrase_engine.generate_spoken_text(
                topic=topic,
                payload=payload,
                verbosity_level=verbosity_level,
                language=language,
            )

            if not spoken_text:
                return

            # Check duplicate phrase suppression
            if self.aggregator and self.aggregator.is_duplicate_phrase(spoken_text):
                logger.debug(f"[CVAS:Service] Suppressed duplicate phrase: {spoken_text}")
                return

            # Step 4: Emergency Interrupt check for Level 1 CRITICAL
            allow_interrupt = cvas_conf.get("priority_override", {}).get("allow_critical_interrupt", True)
            if verbosity_level == "level1_critical" and allow_interrupt and self.tts_worker:
                self.tts_worker.interrupt_for_critical()

            # Record in Spoken History
            self.record_history_item(
                topic=topic, spoken_text=spoken_text,
                verbosity_level=verbosity_level, payload=payload,
            )

            # Step 5: Enqueue into Priority Queue
            if self.priority_engine:
                self.priority_engine.enqueue_alert(
                    topic=topic,
                    spoken_text=spoken_text,
                    verbosity_level=verbosity_level,
                    payload=payload,
                )

    def record_history_item(
        self, topic: str, spoken_text: str, verbosity_level: str, payload: Dict[str, Any]
    ) -> None:
        self.history.appendleft({
            "timestamp": time.time(),
            "datetime": time.strftime("%Y-%m-%d %H:%M:%S"),
            "topic": topic,
            "spoken_text": spoken_text,
            "verbosity_level": verbosity_level,
            "src_ip": payload.get("src_ip", ""),
            "country": payload.get("country", ""),
            "module": payload.get("module", payload.get("source_module", "core")),
        })

    def speak_manual_phrase(
        self, text: str, verbosity: str = "level1_critical", topic: str = "manual.alert"
    ) -> bool:
        """Enqueues a manual voice alert directly into queue."""
        if not self.enabled or self.muted or not self.priority_engine:
            return False
        # Sanitize: strip braces to prevent format injection
        safe_text = text.replace("{", "").replace("}", "")
        if verbosity == "level1_critical" and self.tts_worker:
            self.tts_worker.interrupt_for_critical()
        payload = {"source": "manual_api", "text": safe_text}
        self.record_history_item(
            topic=topic, spoken_text=safe_text, verbosity_level=verbosity, payload=payload
        )
        return self.priority_engine.enqueue_alert(
            topic=topic, spoken_text=safe_text, verbosity_level=verbosity, payload=payload
        )

    def get_available_voices(self) -> List[Dict[str, Any]]:
        """Returns installed TTS voices on host system (Piper ONNX + OS voices)."""
        voices_list = []

        # 1. Scan filesystem for downloaded Piper ONNX models
        search_dirs = [
            Path(__file__).parent / "voices",
            Path("/usr/share/piper-voices"),
            Path("/usr/local/share/piper-voices"),
            Path.home() / ".local" / "share" / "piper-voices",
        ]
        import glob as _glob
        for home_dir in _glob.glob("/home/*/.local/share/piper-voices"):
            p_dir = Path(home_dir)
            if p_dir not in search_dirs:
                search_dirs.append(p_dir)

        detected_ids: set = set()
        for d in search_dirs:
            if d.exists() and d.is_dir():
                for onnx_file in d.glob("*.onnx"):
                    stem = onnx_file.stem
                    if stem in detected_ids:
                        continue
                    detected_ids.add(stem)

                    is_ar = "ar" in stem.lower() or "arabic" in stem.lower()
                    is_female = any(
                        w in stem.lower()
                        for w in ("female", "karimah", "hafsa", "lessac")
                    )
                    lang = "ar-SA" if is_ar else "en-US"
                    gender = "female" if is_female else "male"

                    voices_list.append({
                        "id": stem,
                        "name": f"{stem} (Piper Neural ONNX)",
                        "languages": [lang],
                        "gender": gender,
                        "engine": "Piper Neural TTS",
                        "path": str(onnx_file),
                    })

        # 2. Check pyttsx3 fallback voices
        if self.tts_worker and self.tts_worker.engine:
            try:
                for v in self.tts_worker.engine.getProperty("voices") or []:
                    v_id = getattr(v, "id", "default")
                    if v_id not in detected_ids:
                        voices_list.append({
                            "id": v_id,
                            "name": getattr(v, "name", "Default OS Voice"),
                            "languages": getattr(v, "languages", ["ar-SA", "en-US"]),
                            "gender": getattr(v, "gender", "female"),
                            "engine": "OS System Voice",
                        })
            except Exception:
                pass

        if not voices_list:
            voices_list = [
                {"id": "ar_female",          "name": "Arabic Enterprise Female (Voice Engine)", "languages": ["ar-SA"], "gender": "female"},
                {"id": "en_US_female",        "name": "English Enterprise Female (Voice Engine)", "languages": ["en-US"], "gender": "female"},
                {"id": "ar_JO-kareem-medium", "name": "Arabic Kareem Male (Voice Engine)",        "languages": ["ar-SA"], "gender": "male"},
            ]

        return voices_list

    def status(self) -> Dict[str, Any]:
        """Returns current subsystem operational status."""
        cvas_conf = self.config.get("cvas", {})
        return {
            "subsystem":          "bunyanx Voice Alert Service (CVAS)",
            "enabled":            self.enabled,
            "muted":              self.muted,
            "running":            self.running,
            "language":           cvas_conf.get("language", "ar-SA"),
            "voice_gender":       cvas_conf.get("voice_gender", "female"),
            "speed_wpm":          cvas_conf.get("speed_wpm", 175),
            "volume":             cvas_conf.get("volume", 0.9),
            "pitch":              cvas_conf.get("pitch", 1.0),
            "tts_engine":         cvas_conf.get("tts_engine", "auto"),
            "audio_effect":       cvas_conf.get("audio_effect", "none"),
            "speech_mode":        cvas_conf.get("speech_mode", "natural"),
            "auto_language":      cvas_conf.get("auto_language", False),
            "aggregation_enabled": bool(self.aggregator),
            "pyttsx3_available":  PYTTSX3_AVAILABLE,
            "geo_enricher_active": self.geo_enricher._initialized if self.geo_enricher else False,
            "tts_worker_alive":   self.tts_worker.is_alive() if self.tts_worker else False,
            "queue_size":         self.priority_engine._queue.qsize() if self.priority_engine else 0,
            "history_count":      len(self.history),
        }

    def statistics(self) -> Dict[str, Any]:
        """Returns detailed statistics counters."""
        priority_stats = self.priority_engine.stats if self.priority_engine else {}
        return {
            "enqueued":           priority_stats.get("enqueued", 0),
            "spoken":             priority_stats.get("spoken", 0),
            "dropped_full":       priority_stats.get("dropped_full", 0),
            "dropped_rate_limit": priority_stats.get("dropped_rate_limit", 0),
            "cleared":            priority_stats.get("cleared", 0),
            "total_history":      len(self.history),
            "queue_current":      self.priority_engine._queue.qsize() if self.priority_engine else 0,
        }
