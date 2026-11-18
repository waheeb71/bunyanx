"""
bunyanx NGFW — Event Bus ↔ Acceleration Bridge
====================================================
Connects the Phase 7 EventBus to the acceleration layer (XDP/eBPF engine).

This is the KEY integration point between:
  - EventBus (threat.detected, response.block events)
  - XDP Engine (kernel-level IP blocking via eBPF maps)
  - Threat Intel Manager (reputation-based blocking)

Architecture:
  EventBus "threat.detected" → AccelerationBridge → XDP.add_blocked_ip()
  EventBus "response.block"  → AccelerationBridge → XDP.add_blocked_ip()
  Feature flag: data_plane.ebpf_acceleration = true (to use XDP)
              : data_plane.ebpf_acceleration = false (software blocking only)

Usage (in app startup):
    bridge = AccelerationBridge()
    await bridge.start()

    # Now all threat events automatically propagate to XDP kernel layer
"""

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class AccelerationBridge:
    """
    Subscription bridge between EventBus and the XDP acceleration engine.

    Wires these flows:
      1. threat.detected → XDP blocklist (if confidence ≥ threshold)
      2. response.block  → XDP blocklist + StateSyncManager (cluster-wide)
      3. ai.score_generated → XDP blocklist (if inline_blocking=true)
      4. XDP stats → EventBus metrics.packet_stats (upstream metrics)

    Completely optional: if ebpf_acceleration=false, XDP calls silently no-op.
    """

    def __init__(self, xdp_engine=None):
        self._xdp = xdp_engine
        self._bus = None
        self._flags = None
        self._running = False
        # Phase 3: Conntrack Garbage Collector
        self._conntrack_mgr = None
        # Phase 4: ML Reputation Updater (runs in sync)
        self._rep_update_task = None
        # Phase 5: L4 Load Balancer Manager
        self._lb_manager = None

    async def start(self) -> None:
        """Wire all subscriptions. Call once at system startup."""
        from system.config.feature_flags import FeatureFlagManager
        from system.events.bus import EventBus
        from system.events.topics import Topics

        self._flags = FeatureFlagManager.instance()
        self._bus = await EventBus.instance()

        # Load XDP engine only if not provided by the core engine
        if self._xdp is None:
            await self._init_xdp()

        # Wire bus → XDP
        await self._bus.subscribe(Topics.THREAT_DETECTED, self._on_threat_detected)
        await self._bus.subscribe(Topics.RESPONSE_BLOCK, self._on_response_block)
        await self._bus.subscribe(Topics.AI_SCORE_GENERATED, self._on_ai_score)

        # ── Phase 1: Wire Ring Buffer Consumer critical events ───────────────────
        await self._wire_ring_buffer_consumer()

        # ── Phase 3: Start Conntrack Garbage Collector ───────────────────────────
        if self._flags.current.data_plane.ebpf_conntrack:
            await self._start_conntrack_manager()

        # ── Phase 5: Start L4 LB Manager ─────────────────────────────────────────
        if self._flags.current.data_plane.ebpf_l4_lb:
            self._start_lb_manager()

        self._running = True
        logger.info("[AccelBridge] Started ✓ — XDP bridge active")

    async def stop(self) -> None:
        self._running = False
        # Stop Phase 3 Conntrack GC
        if self._conntrack_mgr:
            await self._conntrack_mgr.stop()
            self._conntrack_mgr = None
        # Stop Phase 5 LB Manager
        if self._lb_manager:
            await self._lb_manager.stop()
            self._lb_manager = None
        # Stop Phase 4 rep update task
        if self._rep_update_task:
            self._rep_update_task.cancel()
        # Stop XDP engine
        if self._xdp:
            await self._xdp.stop()

    # ── Event Handlers ─────────────────────────────────────────────

    async def _on_threat_detected(self, event: dict) -> None:
        """
        threat.detected → auto-block IP in XDP if confidence is HIGH.
        Threshold from features.ai_engine.confidence_threshold.
        """
        if not self._running:
            return

        src_ip = event.get("src_ip", "")
        confidence = float(event.get("confidence", 0.0))
        module = event.get("module", "unknown")

        if not src_ip or src_ip in ("", "0.0.0.0"):
            return

        threshold = self._flags.current.ai_engine.confidence_threshold

        if confidence >= threshold:
            logger.warning(
                f"[AccelBridge] High-confidence threat from {src_ip} "
                f"(module={module}, conf={confidence:.2f}) → XDP block"
            )
            await self._xdp_block(src_ip, reason=f"threat.detected by {module}")

            # Also sync to cluster-wide state
            await self._cluster_block(src_ip, f"threat:{module}")

    async def _on_response_block(self, event: dict) -> None:
        """response.block → immediate XDP kernel block."""
        if not self._running:
            return

        src_ip = event.get("src_ip", "")
        reason = event.get("reason", "response.block event")
        duration_s = int(event.get("duration_s", 3600))

        if not src_ip:
            return

        logger.info(f"[AccelBridge] Block order for {src_ip}: {reason}")
        await self._xdp_block(src_ip, reason=reason)
        await self._cluster_block(src_ip, reason, duration_s)

    async def _on_ai_score(self, event: dict) -> None:
        """
        ai.score_generated → block if inline_blocking=true and score ≥ threshold.
        This implements the AI fast-path for inline blocking mode.
        """
        if not self._running:
            return

        ai_flags = self._flags.current.ai_engine
        if not (ai_flags.mode == "inline" and ai_flags.inline_blocking):
            return

        score = float(event.get("score", 0.0))
        if score >= ai_flags.confidence_threshold:
            session_id = event.get("session_id", "")
            logger.warning(
                f"[AccelBridge] AI inline block: session={session_id} "
                f"score={score:.2f} ≥ {ai_flags.confidence_threshold}"
            )
            # Note: we don't have src_ip in AI score events — that's by design
            # The pipeline will block the specific session via its return value

    # ── XDP Integration ────────────────────────────────────────────

    async def _xdp_block(self, ip: str, reason: str = "") -> None:
        """Push an IP block to the XDP kernel map (if eBPF is active).
        Falls back to DynamicBlocklist (software pipeline block) when eBPF
        is disabled so that block orders are still enforced at the proxy layer.
        """
        if self._xdp and self._flags.current.data_plane.ebpf_acceleration:
            await self._xdp.add_blocked_ip(ip)
        else:
            # Software fallback: add to the in-memory DynamicBlocklist so the
            # inspection pipeline drops future packets from this IP before
            # any plugin runs (zero-cost path in pipeline Phase 1.5).
            try:
                from modules.ids_ips.engine.blocklist.dynamic_blocklist import (
                    DynamicBlocklist,
                )
                bl = DynamicBlocklist.instance()
                bl.add_src_ip(ip, reason=reason or "accel_bridge_software_block")
                logger.info(
                    "[AccelBridge] Software block applied for %s via DynamicBlocklist (%s)",
                    ip, reason,
                )
            except Exception as exc:
                logger.warning(
                    "[AccelBridge] Software block fallback failed for %s: %s", ip, exc
                )



    async def _cluster_block(self, ip: str, reason: str, duration_s: int = 3600) -> None:
        """Replicate IP block across HA cluster via StateSyncManager."""
        try:
            from system.ha.state_sync import StateSyncManager
            await StateSyncManager.instance().sync_blocked_ip(ip, reason, duration_s)
        except Exception as exc:
            logger.debug(f"[AccelBridge] Cluster sync failed: {exc}")

    async def _wire_ring_buffer_consumer(self) -> None:
        """
        Phase 1: ربط RingBufConsumer بـ AccelerationBridge.
        يضبط custom handlers في consumer النواة
        حتى تصل الأحداث فورياً لهذا البريج بدلاً من انتظار 5 ثوانٍ.
        """
        if not self._flags.current.data_plane.ebpf_ring_buffers:
            return
        if not (self._xdp and hasattr(self._xdp, 'ring_buf_consumer')
                and self._xdp.ring_buf_consumer):
            return

        consumer = self._xdp.ring_buf_consumer

        # Override critical handler — الأحداث الحرجية تصل لهذا الفصل فوراً
        async def _bridge_critical_handler(evt) -> None:
            from acceleration.ebpf.ring_buffer_consumer import EventType
            src_ip = evt.src_ip

            if not src_ip or src_ip in ("0.0.0.0", ""):
                return

            # ML anomaly → block immediately (no 5s poll wait)
            if evt.event_type in (EventType.ML_ANOMALY, EventType.SYN_FLOOD):
                logger.warning(
                    f"[AccelBridge][RingBuf] ⚨ {evt.event_type.name} from {src_ip} "
                    f"(pkts={evt.pkt_count}) → instant XDP block"
                )
                await self._xdp_block(src_ip, reason=f"ringbuf.{evt.event_type.name}")
                await self._cluster_block(src_ip, f"ringbuf:{evt.event_type.name}")

            # Already-blocked IP still getting traffic → log for SIEM
            elif evt.event_type == EventType.BLOCKED_IP:
                logger.debug(f"[AccelBridge][RingBuf] Blocked IP {src_ip} still sending traffic")

        # Override warning handler — تسجيل للـ SIEM
        async def _bridge_warning_handler(evt) -> None:
            from acceleration.ebpf.ring_buffer_consumer import EventType
            if evt.event_type == EventType.RATE_LIMITED:
                # إذا تجاوز IP الحد كثيراً → ارفع التقرير لـ EventBus
                if self._bus:
                    from system.events.topics import Topics
                    await self._bus.publish(
                        Topics.THREAT_DETECTED,
                        {
                            "src_ip":     evt.src_ip,
                            "module":     "xdp.rate_limiter",
                            "confidence": 0.70,
                            "pkt_count":  evt.pkt_count,
                        }
                    )

        # تسجيل الـ handlers في الـ consumer
        consumer._on_critical = _bridge_critical_handler
        consumer._on_warning  = _bridge_warning_handler
        logger.info("[AccelBridge] Ring Buffer Consumer handlers wired ✓")

    async def _start_conntrack_manager(self) -> None:
        """Phase 3 — يُشغّل Conntrack Garbage Collector."""
        try:
            if not (self._xdp and hasattr(self._xdp, 'pipeline_loader')
                    and self._xdp.pipeline_loader):
                logger.info("[AccelBridge] Conntrack: Pipeline not in pipeline mode — GC skipped")
                return

            from acceleration.ebpf.conntrack_manager import ConntrackManager
            from system.config.config_manager import ConfigManager
            config = ConfigManager.instance().get_all()

            self._conntrack_mgr = ConntrackManager(
                pipeline_loader=self._xdp.pipeline_loader,
                config=config,
            )
            await self._conntrack_mgr.start()
            logger.info("[AccelBridge] Conntrack GC started ✓")

        except Exception as exc:
            logger.error(f"[AccelBridge] Conntrack manager init failed: {exc}")

    def _start_lb_manager(self) -> None:
        """Phase 5 — يُشغّل L4 LB Manager."""
        try:
            if not (self._xdp and hasattr(self._xdp, 'pipeline_loader')
                    and self._xdp.pipeline_loader):
                logger.info("[AccelBridge] LB: Pipeline not in pipeline mode — LBManager skipped")
                return

            from acceleration.ebpf.lb_manager import LBManager
            from system.config.config_manager import ConfigManager
            config = ConfigManager.instance().get_all()

            self._lb_manager = LBManager(
                pipeline_loader=self._xdp.pipeline_loader,
                config=config,
            )
            self._lb_manager.start()
            logger.info("[AccelBridge] LB Manager started ✓")

        except Exception as exc:
            logger.error(f"[AccelBridge] LB manager init failed: {exc}")

    async def _init_xdp(self) -> None:
        """Lazily initialize XDP engine from acceleration module."""
        try:
            from system.config.config_manager import ConfigManager
            config = ConfigManager.instance().get_all()

            from acceleration.ebpf.xdp_engine import create_xdp_engine
            self._xdp = create_xdp_engine(config, event_sink=None)

            if self._flags.current.data_plane.ebpf_acceleration:
                await self._xdp.start()
                logger.info("[AccelBridge] XDP engine started ✓")
            else:
                logger.info("[AccelBridge] eBPF disabled in feature flags — XDP in mock mode")

        except ImportError as exc:
            logger.warning(f"[AccelBridge] Could not load XDP engine: {exc} — software-only mode")
            self._xdp = _SoftwareBlocklist()
        except Exception as exc:
            logger.error(f"[AccelBridge] XDP init failed: {exc} — software-only mode")
            self._xdp = _SoftwareBlocklist()


class _SoftwareBlocklist:
    """
    Pure Python fallback when eBPF/BCC is unavailable.
    Maintains an in-memory LRU blocklist used by the pipeline for pre-check.
    Max capacity: 50,000 IPs.
    """
    def __init__(self):
        import threading
        from collections import OrderedDict
        self.max_ips = 50000
        self._blocked = OrderedDict()
        self._lock = threading.RLock()

    async def add_blocked_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked[ip] = True
            self._blocked.move_to_end(ip)
            if len(self._blocked) > self.max_ips:
                self._blocked.popitem(last=False)
        logger.info(f"[SoftwareBlocklist] Blocked {ip} (LRU mode)")

    async def remove_blocked_ip(self, ip: str) -> None:
        with self._lock:
            if ip in self._blocked:
                del self._blocked[ip]

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked:
                self._blocked.move_to_end(ip)
                return True
            return False

    def get_statistics(self) -> dict:
        with self._lock:
            return {"total_packets": 0, "blocked_ips_count": len(self._blocked)}
