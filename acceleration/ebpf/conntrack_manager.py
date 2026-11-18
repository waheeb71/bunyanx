"""
bunyanx NGFW — Conntrack Userspace Manager
==============================================
يُدير جدول الاتصالات من الـ userspace:
  - كتابة timeouts للـ kernel عند البداية
  - Garbage Collector: يحذف الـ entries المنتهية كل N ثانية
  - إحصائيات في الوقت الفعلي
  - ربط مع AccelerationBridge للأحداث

لماذا يجب أن يعمل في userspace؟
  - Garbage Collection تحتاج loop على كل الـ entries → ممنوع في kernel
  - bpf_map_delete_elem يمكن استدعاؤه من userspace بأمان
  - LRU يتولى الـ overflow تلقائياً — لكن userspace يُسرّع التنظيف
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from acceleration.ebpf.pipeline.pipeline_loader import PipelineLoader

logger = logging.getLogger(__name__)


# ── TCP States (يتطابق مع #define في stage_conntrack.c) ──────────────────────

class TCPState(IntEnum):
    NEW         = 1
    SYN_RECV    = 2
    ESTABLISHED = 3
    FIN_WAIT    = 4
    CLOSE_WAIT  = 5
    CLOSED      = 6


@dataclass
class ConnEntry:
    """تمثيل Python لـ conn_value من الـ kernel."""
    src_ip:       str
    dst_ip:       str
    src_port:     int
    dst_port:     int
    state:        TCPState
    pkt_count:    int
    last_seen_ns: int
    timeout_s:    int

    @property
    def age_s(self) -> float:
        return (time.monotonic_ns() - self.last_seen_ns) / 1e9

    @property
    def is_expired(self) -> bool:
        return self.age_s > self.timeout_s


class ConntrackManager:
    """
    Garbage Collector وإدارة الـ conntrack table من الـ userspace.

    الاستخدام:
        mgr = ConntrackManager(pipeline_loader=loader, config=cfg)
        await mgr.start()
        # ...
        await mgr.stop()
        mgr.get_stats()
    """

    # struct conn_key format (يتطابق مع stage_conntrack.c)
    _KEY_FORMAT = "=IIHH3B"         # src_ip, dst_ip, src_port, dst_port, proto, pad[3]
    _KEY_SIZE   = struct.calcsize(_KEY_FORMAT)   # 16 bytes

    # struct conn_value format
    _VAL_FORMAT = "=QIIB3BII"       # last_seen_ns, pkt_count, byte_count, state, flags, pad, timeout_s, reserved
    _VAL_SIZE   = struct.calcsize(_VAL_FORMAT)   # 32 bytes

    def __init__(
        self,
        pipeline_loader: "PipelineLoader",
        config: dict,
    ):
        self._loader    = pipeline_loader
        self._config    = config
        self._running   = False
        self._task: Optional[asyncio.Task] = None

        ct_cfg = config.get("ebpf", {}).get("conntrack", {})
        self._cleanup_interval = ct_cfg.get("cleanup_interval", 30)    # ثانية
        self._timeout_est      = ct_cfg.get("tcp_timeout_established", 300)
        self._timeout_syn      = ct_cfg.get("tcp_timeout_syn", 10)
        self._timeout_fin      = ct_cfg.get("tcp_timeout_fin", 30)
        self._max_entries      = ct_cfg.get("max_entries", 1_000_000)

        # إحصائيات داخلية (userspace)
        self._total_cleaned    = 0
        self._last_table_size  = 0

    # ── Public API ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """يُشغّل Garbage Collector وينقل الـ timeouts للـ kernel."""
        if not self._loader or not self._loader._bpf:
            logger.warning("[Conntrack] Pipeline not ready — manager disabled")
            return

        await self._write_timeouts_to_kernel()
        self._running = True
        self._task    = asyncio.create_task(self._gc_loop(), name="conntrack-gc")
        logger.info(
            f"[Conntrack] Manager started — cleanup every {self._cleanup_interval}s "
            f"| est={self._timeout_est}s syn={self._timeout_syn}s fin={self._timeout_fin}s"
        )

    async def stop(self) -> None:
        """يوقف الـ Garbage Collector."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info(
            f"[Conntrack] Manager stopped — "
            f"total cleaned entries: {self._total_cleaned}"
        )

    def get_stats(self) -> dict:
        """يرجع إحصائيات من kernel + userspace."""
        if not self._loader or not self._loader._bpf:
            return {}
        try:
            stats_map = self._loader._bpf["ct_stats"]
            return {
                "new_connections":    stats_map[stats_map.Key(0)].value,
                "established":        stats_map[stats_map.Key(1)].value,
                "dropped_no_state":   stats_map[stats_map.Key(2)].value,
                "fin_closed":         stats_map[stats_map.Key(3)].value,
                "rst_dropped":        stats_map[stats_map.Key(4)].value,
                "fast_table_full":    stats_map[stats_map.Key(5)].value,
                "global_table_full":  stats_map[stats_map.Key(6)].value,
                "timeout_dropped":    stats_map[stats_map.Key(7)].value,
                "userspace_cleaned":  self._total_cleaned,
                "last_table_size":    self._last_table_size,
            }
        except Exception as exc:
            logger.debug(f"[Conntrack] Stats read error: {exc}")
            return {}

    def get_active_connections(self, limit: int = 100) -> list:
        """يرجع قائمة بالاتصالات النشطة (للـ API/Dashboard)."""
        if not self._loader or not self._loader._bpf:
            return []
        entries = []
        try:
            ct_global = self._loader._bpf["ct_global"]
            count = 0
            for k, v in ct_global.items():
                if count >= limit:
                    break
                entry = self._parse_entry(k, v)
                if entry and not entry.is_expired:
                    entries.append({
                        "src": f"{entry.src_ip}:{entry.src_port}",
                        "dst": f"{entry.dst_ip}:{entry.dst_port}",
                        "state": entry.state.name,
                        "pkts":  entry.pkt_count,
                        "age_s": round(entry.age_s, 1),
                    })
                    count += 1
        except Exception as exc:
            logger.debug(f"[Conntrack] Active conn read error: {exc}")
        return entries

    # ── Garbage Collector Loop ────────────────────────────────────────────────

    async def _gc_loop(self) -> None:
        """
        Garbage Collector الرئيسي.
        يعمل كل N ثانية (cleanup_interval في base.yaml).
        """
        logger.info("[Conntrack] GC loop started")
        while self._running:
            await asyncio.sleep(self._cleanup_interval)
            try:
                await self._run_gc_cycle()
            except Exception as exc:
                logger.error(f"[Conntrack] GC cycle error: {exc}")

    async def _run_gc_cycle(self) -> None:
        """دورة تنظيف واحدة — يُنفَّذ في loop منفصلة لتجنب blocking."""
        if not self._loader or not self._loader._bpf:
            return

        to_delete = []
        table_size = 0

        try:
            ct_global = self._loader._bpf["ct_global"]

            for k, v in ct_global.items():
                table_size += 1
                entry = self._parse_entry(k, v)
                if entry and entry.is_expired:
                    to_delete.append(k)
                # نعطي الـ event loop فرصة للتنفس كل 1000 entry
                if table_size % 1000 == 0:
                    await asyncio.sleep(0)

            self._last_table_size = table_size

            # حذف الـ entries المنتهية
            deleted = 0
            for key in to_delete:
                try:
                    del ct_global[key]
                    deleted += 1
                except Exception:
                    pass

            self._total_cleaned += deleted

            if deleted > 0:
                logger.info(
                    f"[Conntrack] GC: cleaned {deleted}/{table_size} entries "
                    f"(total={self._total_cleaned})"
                )
            else:
                logger.debug(f"[Conntrack] GC: table_size={table_size}, nothing to clean")

        except Exception as exc:
            logger.error(f"[Conntrack] GC cycle internal error: {exc}")

    # ── Kernel Initialization ─────────────────────────────────────────────────

    async def _write_timeouts_to_kernel(self) -> None:
        """
        يكتب قيم الـ timeouts في ct_timeouts kernel map.
        يُستدعى مرة واحدة عند البداية.
        """
        try:
            bpf  = self._loader._bpf
            tmap = bpf["ct_timeouts"]
            tmap[tmap.Key(0)] = tmap.Leaf(self._timeout_est)   # established
            tmap[tmap.Key(1)] = tmap.Leaf(self._timeout_syn)   # syn
            tmap[tmap.Key(2)] = tmap.Leaf(self._timeout_fin)   # fin
            logger.info(
                f"[Conntrack] Timeouts written to kernel: "
                f"est={self._timeout_est}s syn={self._timeout_syn}s "
                f"fin={self._timeout_fin}s"
            )
        except Exception as exc:
            logger.error(f"[Conntrack] Failed to write timeouts: {exc}")

    # ── Parsing Helpers ───────────────────────────────────────────────────────

    def _parse_entry(self, key, val) -> Optional[ConnEntry]:
        """يُحوّل BCC key/val لـ ConnEntry Python."""
        try:
            import socket, struct
            # Fix Endianness: BCC reads as little-endian u32, convert back to string
            src_ip   = socket.inet_ntoa(struct.pack("<I", key.src_ip))
            dst_ip   = socket.inet_ntoa(struct.pack("<I", key.dst_ip))
            src_port = key.src_port
            dst_port = key.dst_port

            # Val: last_seen_ns, pkt_count, byte_count, state, ...
            last_seen = val.last_seen_ns
            pkt_count = val.pkt_count
            state_int = val.state
            timeout   = val.timeout_s

            state = TCPState(state_int) if 1 <= state_int <= 6 else TCPState.NEW

            return ConnEntry(
                src_ip       = src_ip,
                dst_ip       = dst_ip,
                src_port     = src_port,
                dst_port     = dst_port,
                state        = state,
                pkt_count    = pkt_count,
                last_seen_ns = last_seen,
                timeout_s    = timeout,
            )
        except Exception:
            return None

    # ── Hot Reload Support ────────────────────────────────────────────────────

    def reload_config(self, new_config: dict) -> None:
        """يطبّق تغييرات config الجديدة (hot-reload)."""
        ct_cfg = new_config.get("ebpf", {}).get("conntrack", {})
        self._cleanup_interval = ct_cfg.get("cleanup_interval", 30)
        self._timeout_est      = ct_cfg.get("tcp_timeout_established", 300)
        self._timeout_syn      = ct_cfg.get("tcp_timeout_syn", 10)
        self._timeout_fin      = ct_cfg.get("tcp_timeout_fin", 30)

        # كتابة الـ timeouts الجديدة في kernel
        import asyncio as _asyncio
        loop = _asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(self._write_timeouts_to_kernel())
        logger.info("[Conntrack] Config hot-reloaded")
