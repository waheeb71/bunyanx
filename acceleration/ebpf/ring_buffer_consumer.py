"""
bunyanx NGFW — eBPF Ring Buffer Consumer
=============================================
يُحوّل نظام الأحداث من Polling (كل 5 ثوانٍ) إلى Push فوري مُدرَّج بـ 3 مستويات.

المستويات:
  🔴 Critical  → BPF_RB_FORCE_WAKEUP  → Python يستيقظ خلال < 1ms
  🟡 Warning   → BPF_RB_NO_WAKEUP    → batch كل 100ms
  🟢 Info      → BPF_RB_NO_WAKEUP    → polling كل 5 ثوانٍ (مثل السابق)

التكامل:
  XDPEngine.start() → RingBufConsumer.start()   (إذا ebpf_ring_buffers=true)
  AccelerationBridge._on_critical_event()       (يتصرف فوراً)

الأمان:
  - كل event له NMI-safe fallback (lost_events_counter)
  - Buffer overflow لا يوقف النواة — يُسجَّل فقط
  - Consumer crash لا يوقف packet processing
"""
from __future__ import annotations

import asyncio
import ctypes
import logging
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from acceleration.ebpf.xdp_engine import XDPEngine

logger = logging.getLogger(__name__)


# ── Event Schema (يجب أن يتطابق مع هيكل C في xdp_engine.py) ────────────────

class EventType(IntEnum):
    BLOCKED_IP    = 0
    RATE_LIMITED  = 1
    SYN_FLOOD     = 2
    ML_ANOMALY    = 3
    CONNTRACK_NEW = 4
    CONNTRACK_ERR = 5
    L4_LB_MISS    = 6
    STATS_SUMMARY = 7


class EventSeverity(IntEnum):
    INFO     = 0
    WARNING  = 1
    CRITICAL = 2


# هيكل C: struct security_event { u64 ts; u32 src_ip; u32 dst_ip;
#          u16 src_port; u16 dst_port; u8 type; u8 severity; u16 proto;
#          u32 pkt_count; char reason[32]; }
_EVENT_FORMAT = "<QIIHHBBHI32s"
_EVENT_SIZE   = struct.calcsize(_EVENT_FORMAT)   # = 64 bytes


@dataclass
class SecurityEvent:
    """حدث أمني موحّد من النواة."""
    timestamp_ns:  int
    src_ip:        str
    dst_ip:        str
    src_port:      int
    dst_port:      int
    event_type:    EventType
    severity:      EventSeverity
    protocol:      int
    pkt_count:     int
    reason:        str

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SecurityEvent":
        ts, sip, dip, sp, dp, etype, sev, proto, cnt, reason_b = struct.unpack(
            _EVENT_FORMAT, raw[:_EVENT_SIZE]
        )
        return cls(
            timestamp_ns = ts,
            src_ip       = _int_to_ip(sip),
            dst_ip       = _int_to_ip(dip),
            src_port     = sp,
            dst_port     = dp,
            event_type   = EventType(etype)     if etype < len(EventType)    else EventType.STATS_SUMMARY,
            severity     = EventSeverity(sev)   if sev   < len(EventSeverity) else EventSeverity.INFO,
            protocol     = proto,
            pkt_count    = cnt,
            reason       = reason_b.rstrip(b"\x00").decode("utf-8", errors="replace"),
        )


def _int_to_ip(n: int) -> str:
    return f"{n & 0xFF}.{(n >> 8) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 24) & 0xFF}"


# ── Ring Buffer Consumer ──────────────────────────────────────────────────────

class RingBufConsumer:
    """
    يستبدل `_feedback_loop` في XDPEngine بمعمارية Event-Driven 3 طبقات.

    الاستخدام:
        consumer = RingBufConsumer(bpf=engine.bpf, engine=engine)
        await consumer.start()
        # ...
        await consumer.stop()
    """

    def __init__(
        self,
        bpf,                                          # BCC BPF object
        engine:       "XDPEngine",
        on_critical:  Optional[Callable] = None,      # callback فوري
        on_warning:   Optional[Callable] = None,
        on_info:      Optional[Callable] = None,
        warning_poll_ms:  int = 100,
        info_poll_sec:    int = 5,
    ):
        self._bpf            = bpf
        self._engine         = engine
        self._on_critical    = on_critical  or self._default_critical_handler
        self._on_warning     = on_warning   or self._default_warning_handler
        self._on_info        = on_info      or self._default_info_handler
        self._warning_poll   = warning_poll_ms / 1000.0
        self._info_poll      = info_poll_sec
        self._tasks: list    = []
        self._running        = False
        self._lost_events    = 0    # عداد الأحداث المفقودة من NMI overflow

    async def start(self) -> None:
        """يشغّل 3 consumer tasks منفصلة."""
        self._running = True
        self._tasks = [
            asyncio.create_task(self._consume_critical(), name="rb-critical"),
            asyncio.create_task(self._consume_warning(),  name="rb-warning"),
            asyncio.create_task(self._consume_info(),     name="rb-info"),
        ]
        logger.info("[RingBuf] Consumer started — 3-tier event pipeline active")

    async def stop(self) -> None:
        """يوقف جميع الـ consumer tasks."""
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info(f"[RingBuf] Stopped. Total lost events (NMI overflow): {self._lost_events}")

    # ── Critical Path (< 1ms) ─────────────────────────────────────────────────

    async def _consume_critical(self) -> None:
        """
        يعمل في loop مستمر بـ poll timeout=0.
        BPF_RB_FORCE_WAKEUP يُيقظه فور وصول حدث critical من النواة.
        """
        try:
            rb = self._bpf["critical_events"]
            rb.open_ring_buffer(self._on_raw_critical)
            while self._running:
                self._bpf.ring_buffer_poll(rb, timeout=1)  # 1ms max wait
                await asyncio.sleep(0.005)  # yield للـ event loop and prevent 100% CPU burn
        except Exception as e:
            logger.error(f"[RingBuf] Critical consumer crashed: {e}")

    def _on_raw_critical(self, ctx, data, size) -> int:
        """Callback مباشر من BCC — لا await هنا (C context)."""
        try:
            if size != _EVENT_SIZE:
                logger.error(f"[RingBuf] Critical event size mismatch: expected {_EVENT_SIZE}, got {size}")
                return 0
            raw = bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_char * size)).contents)
            evt = SecurityEvent.from_bytes(raw)
            # نجدول الـ coroutine في الـ event loop بدلاً من await مباشر
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(
                    lambda e=evt: asyncio.ensure_future(self._on_critical(e))
                )
        except Exception as e:
            logger.error(f"[RingBuf] Failed to parse critical event: {e}")
        return 0

    # ── Warning Path (batch كل 100ms) ─────────────────────────────────────────

    async def _consume_warning(self) -> None:
        try:
            rb = self._bpf["warning_events"]
            rb.open_ring_buffer(self._on_raw_warning)
            while self._running:
                await asyncio.sleep(self._warning_poll)
                self._bpf.ring_buffer_poll(rb, timeout=0)
        except Exception as e:
            logger.error(f"[RingBuf] Warning consumer crashed: {e}")

    def _on_raw_warning(self, ctx, data, size) -> int:
        try:
            if size != _EVENT_SIZE:
                return 0
            raw = bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_char * size)).contents)
            evt = SecurityEvent.from_bytes(raw)
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(
                    lambda e=evt: asyncio.ensure_future(self._on_warning(e))
                )
        except Exception as e:
            logger.debug(f"[RingBuf] Failed to parse warning event: {e}")
        return 0

    # ── Info Path (polling كل N ثوانٍ — كالسابق) ─────────────────────────────

    async def _consume_info(self) -> None:
        try:
            rb = self._bpf["info_events"]
            rb.open_ring_buffer(self._on_raw_info)
            while self._running:
                await asyncio.sleep(self._info_poll)
                self._bpf.ring_buffer_poll(rb, timeout=0)
                await self._check_lost_events()
        except Exception as e:
            logger.error(f"[RingBuf] Info consumer crashed: {e}")

    def _on_raw_info(self, ctx, data, size) -> int:
        try:
            if size != _EVENT_SIZE:
                return 0
            raw = bytes(ctypes.cast(data, ctypes.POINTER(ctypes.c_char * size)).contents)
            evt = SecurityEvent.from_bytes(raw)
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(
                    lambda e=evt: asyncio.ensure_future(self._on_info(e))
                )
        except Exception as e:
            logger.debug(f"[RingBuf] Failed to parse info event: {e}")
        return 0

    # ── Lost Events Counter (NMI overflow fallback) ────────────────────────────

    async def _check_lost_events(self) -> None:
        """
        يتحقق من عداد الأحداث المفقودة بسبب NMI contention.
        إذا ارتفع → نُحذَّر (يعني الـ buffer صغير أو الـ consumer بطيء).
        """
        try:
            counter = self._bpf["lost_events_counter"]
            lost = counter[0].value
            if lost > self._lost_events:
                new_lost = lost - self._lost_events
                self._lost_events = lost
                logger.warning(
                    f"[RingBuf] ⚠ {new_lost} events lost due to NMI overflow. "
                    f"Consider increasing ring buffer size in base.yaml"
                )
        except Exception:
            pass  # الـ map غير موجود في بعض الأوضاع — تجاهل

    # ── Default Handlers ───────────────────────────────────────────────────────

    async def _default_critical_handler(self, evt: SecurityEvent) -> None:
        """
        المعالج الافتراضي للأحداث الحرجة.
        يُستبدَل من AccelerationBridge بمعالج أكثر ذكاءً.
        """
        logger.warning(
            f"[RingBuf][CRITICAL] type={evt.event_type.name} "
            f"src={evt.src_ip}:{evt.src_port} "
            f"pkts={evt.pkt_count} reason={evt.reason!r}"
        )
        # الاستجابة الفورية: حجب IP في النواة + تنبيه صوتي معزول
        if evt.event_type in (EventType.ML_ANOMALY, EventType.SYN_FLOOD):
            try:
                from acceleration.ebpf.ebpf_audio_notifier import get_ebpf_audio_notifier
                get_ebpf_audio_notifier().trigger_alert(
                    src_ip=evt.src_ip,
                    event_type=evt.event_type.name,
                    reason=evt.reason
                )
            except Exception:
                pass

            if hasattr(self._engine, "add_blocked_ip"):
                await self._engine.add_blocked_ip(evt.src_ip)

    async def _default_warning_handler(self, evt: SecurityEvent) -> None:
        logger.warning(
            f"[RingBuf][WARNING] type={evt.event_type.name} "
            f"src={evt.src_ip} pkts={evt.pkt_count}"
        )
        if evt.event_type == EventType.RATE_LIMITED:
            try:
                from acceleration.ebpf.ebpf_audio_notifier import get_ebpf_audio_notifier
                get_ebpf_audio_notifier().trigger_alert(
                    src_ip=evt.src_ip,
                    event_type="RATE_LIMITED",
                    reason="eBPF Rate Limit Exceeded"
                )
            except Exception:
                pass

            if hasattr(self._engine, "add_blocked_ip"):
                await self._engine.add_blocked_ip(evt.src_ip)

    async def _default_info_handler(self, evt: SecurityEvent) -> None:
        logger.debug(
            f"[RingBuf][INFO] type={evt.event_type.name} "
            f"src={evt.src_ip} pkts={evt.pkt_count}"
        )

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "running":           self._running,
            "active_tasks":      sum(not t.done() for t in self._tasks),
            "total_lost_events": self._lost_events,
            "warning_poll_ms":   int(self._warning_poll * 1000),
            "info_poll_sec":     self._info_poll,
        }
