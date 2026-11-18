"""
bunyanx NGFW — L4 Load Balancer Manager
=============================================
الجسر بين reverse_proxy.py وكود C في XDP.

المسؤوليات:
  1. قراءة backends من proxy.vips في base.yaml  
  2. ترجمة health_state من reverse_proxy → healthy_backends_map
  3. كتابة القائمة الصحية لـ kernel عند كل تغيير
  4. Session map cleanup (يعمل بجانب Conntrack GC)

مبدأ الفصل الحاسم:
  health checks → reverse_proxy.py (Python)
  قرار LB       → stage_l4_lb.c (Kernel)
  Kernel لا يكتب المaps إلا بأمر صريح من هنا
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from acceleration.ebpf.pipeline.pipeline_loader import PipelineLoader

logger = logging.getLogger(__name__)


@dataclass
class BackendInfo:
    """يتطابق مع struct backend_info في stage_l4_lb.c"""
    ip:      str
    port:    int
    healthy: bool  = True
    weight:  int   = 1

    def to_kernel_struct(self) -> bytes:
        """
        يُحوّل لـ binary للكتابة في BPF map.
        struct: { u32 ip; u16 port; u8 healthy; u8 weight; }
        """
        ip_int = int(ipaddress.IPv4Address(self.ip))
        return struct.pack("=IHBBxx",
                           ip_int,
                           self.port,
                           1 if self.healthy else 0,
                           self.weight & 0xFF)


class LBManager:
    """
    يُزامن قائمة الـ healthy backends بين reverse_proxy.py وكرنل XDP.

    الاستخدام:
        mgr = LBManager(pipeline_loader=loader, config=cfg)
        mgr.start()
        # عند تغيير health state في reverse_proxy:
        mgr.sync_backends_to_kernel(healthy_list)
        # ...
        await mgr.stop()
    """

    def __init__(
        self,
        pipeline_loader: "PipelineLoader",
        config: dict,
    ):
        self._loader   = pipeline_loader
        self._config   = config
        self._running  = False
        self._backends: List[BackendInfo] = []
        self._healthy:  List[BackendInfo] = []

        lb_cfg = config.get("ebpf", {}).get("l4_lb", {})
        self._max_backends   = lb_cfg.get("max_backends", 64)
        self._algorithm      = lb_cfg.get("algorithm", "hash")
        self._session_map_sz = lb_cfg.get("session_map_size", 500_000)

        # إحصائيات Python-side
        self._sync_count = 0
        self._last_healthy_count = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """يُهيئ الـ backends من config ويكتب للـ kernel."""
        if not self._loader or not self._loader._bpf:
            logger.warning("[LBManager] Pipeline not ready — LB disabled")
            return

        self._backends = self._load_backends_from_config()
        # في البداية: كل الـ backends صحية (حتى يبدأ health checker)
        self.sync_backends_to_kernel(self._backends)
        self._running = True
        logger.info(
            f"[LBManager] Started — {len(self._backends)} backends loaded "
            f"| algorithm={self._algorithm}"
        )

    async def stop(self) -> None:
        """يوقف الـ manager ويمسح kernel maps."""
        self._running = False
        try:
            # مسح الـ healthy list من kernel عند الإيقاف
            if self._loader and self._loader._bpf:
                num_map = self._loader._bpf["num_healthy_backends"]
                num_map[num_map.Key(0)] = num_map.Leaf(0)
        except Exception:
            pass
        logger.info(f"[LBManager] Stopped (synced {self._sync_count} times)")

    def sync_backends_to_kernel(self, healthy_backends: List[BackendInfo]) -> None:
        """
        يكتب قائمة الـ healthy backends لـ kernel (الدالة الرئيسية).
        تُستدعى من reverse_proxy.py._health_check_loop() عند كل تغيير.

        ⚠️ يجب أن تعمل بسرعة (لا I/O، لا sleep)
        """
        if not self._loader or not self._loader._bpf:
            return
        if len(healthy_backends) > self._max_backends:
            healthy_backends = healthy_backends[:self._max_backends]
            logger.warning(
                f"[LBManager] Truncated to {self._max_backends} backends "
                f"(max_backends in base.yaml)"
            )

        try:
            bpf            = self._loader._bpf
            backends_map   = bpf["healthy_backends_map"]
            num_map        = bpf["num_healthy_backends"]

            # كتابة الـ backends
            for idx, b in enumerate(healthy_backends):
                key  = backends_map.Key(idx)
                data = b.to_kernel_struct()
                backends_map[key] = backends_map.Leaf.from_buffer_copy(data)

            # تحديث العدد (atomic write)
            num_map[num_map.Key(0)] = num_map.Leaf(len(healthy_backends))

            self._healthy     = healthy_backends
            self._sync_count += 1
            self._last_healthy_count = len(healthy_backends)

            logger.info(
                f"[LBManager] Kernel synced: {len(healthy_backends)} healthy backends "
                f"| sync#{self._sync_count}"
            )

        except Exception as exc:
            logger.error(f"[LBManager] Kernel sync failed: {exc}")

    def mark_backend_down(self, ip: str, port: int) -> bool:
        """
        يُعطّل backend محدد (يُستدعى من health checker مباشرة).
        يُزيله من الـ healthy list ويُزامن مع kernel.
        """
        healthy = [
            b for b in self._healthy
            if not (b.ip == ip and b.port == port)
        ]
        if len(healthy) == len(self._healthy):
            return False  # لم يُجد

        logger.warning(f"[LBManager] Backend {ip}:{port} marked DOWN")
        self.sync_backends_to_kernel(healthy)
        return True

    def mark_backend_up(self, ip: str, port: int) -> bool:
        """يُعيد backend للـ rotation."""
        # ابحث عن الـ backend في القائمة الكاملة
        backend = next((b for b in self._backends if b.ip == ip and b.port == port), None)
        if not backend:
            return False

        backend.healthy = True
        if backend not in self._healthy:
            self._healthy.append(backend)
            logger.info(f"[LBManager] Backend {ip}:{port} marked UP")
            self.sync_backends_to_kernel(self._healthy)
        return True

    def get_stats(self) -> dict:
        """يرجع إحصائيات الـ LB من kernel + Python."""
        result = {
            "total_backends":   len(self._backends),
            "healthy_backends": self._last_healthy_count,
            "algorithm":        self._algorithm,
            "sync_count":       self._sync_count,
        }
        if self._loader and self._loader._bpf:
            try:
                stats = self._loader._bpf["lb_stats"]
                result.update({
                    "kernel_total_balanced": stats[stats.Key(0)].value,
                    "kernel_no_backends":    stats[stats.Key(1)].value,
                    "kernel_dnat_applied":   stats[stats.Key(2)].value,
                    "kernel_session_reuse":  stats[stats.Key(3)].value,
                    "kernel_new_sessions":   stats[stats.Key(5)].value,
                })
            except Exception:
                pass
        return result

    def get_healthy_backends(self) -> list:
        """للـ API/Dashboard."""
        return [{"ip": b.ip, "port": b.port, "weight": b.weight}
                for b in self._healthy]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_backends_from_config(self) -> List[BackendInfo]:
        """
        يقرأ backends من proxy.vips في base.yaml.
        لا تكرار للإعدادات — نقرأ من نفس مصدر reverse_proxy.
        """
        vips = self._config.get("proxy", {}).get("vips", [])
        backends = []
        for vip in vips:
            ip   = vip.get("internal_ip", "")
            port = int(vip.get("internal_port", 80))
            if ip:
                backends.append(BackendInfo(ip=ip, port=port))

        # إذا لم تكن هناك vips → قرأ من ebpf.l4_lb.backends (override)
        lb_backends = self._config.get("ebpf", {}).get("l4_lb", {}).get("backends", [])
        for b in lb_backends:
            backends.append(BackendInfo(
                ip=b.get("ip", ""),
                port=int(b.get("port", 80)),
                weight=int(b.get("weight", 1))
            ))

        if not backends:
            logger.warning("[LBManager] No backends found in proxy.vips or ebpf.l4_lb.backends")
        return backends

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        import asyncio as _asyncio
        loop = _asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(self.stop())
