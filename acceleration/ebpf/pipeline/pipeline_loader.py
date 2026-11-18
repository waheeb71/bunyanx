"""
bunyanx NGFW — XDP Pipeline Loader
=======================================
يُحمّل الـ Modular XDP Pipeline ويديره من Python.

المهام:
  1. تحميل dispatcher.c + كل stage مُفعَّل
  2. ربط stages في PROG_ARRAY
  3. تحديث pipeline bitmask في kernel
  4. تفعيل/إيقاف stages في وقت التشغيل

التصميم:
  - Userspace يقرر ما يُفعِّل — Kernel ينفّذ فقط
  - كل stage مستقل قابل للتحميل/التفريغ بدون restart
  - PROG_ARRAY index = PipelineStage enum value

الحد الحرج:
  Max tail call depth = 33 (Linux 5.2+)
  يعني: Dispatcher + 32 stage كحد أقصى — نحن نستخدم 4 فقط
"""
from __future__ import annotations

import logging
import os
from enum import IntEnum
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    pass  # BCC imported lazily to avoid errors on non-Linux

logger = logging.getLogger(__name__)

# ── Stage Indices (يتطابق مع #define في dispatcher.c) ────────────────────────

class PipelineStage(IntEnum):
    BLACKLIST  = 0   # Phase 1: IP Blocklist + Rate Limit (دائماً مفعّل)
    CONNTRACK  = 1   # Phase 3: Stateful TCP
    SYN_PROXY  = 2   # Phase 4: SYN Cookie
    L4_LB      = 3   # Phase 5: L4 Load Balancer


# Feature Bitmask bits (يتطابق مع #define في dispatcher.c)
class PipelineFlags(IntEnum):
    BLACKLIST  = 1 << 4   # 0b00010000
    CONNTRACK  = 1 << 5   # 0b00100000
    SYN_PROXY  = 1 << 6   # 0b01000000
    L4_LB      = 1 << 7   # 0b10000000


_STAGE_TO_FLAG: Dict[PipelineStage, PipelineFlags] = {
    PipelineStage.BLACKLIST: PipelineFlags.BLACKLIST,
    PipelineStage.CONNTRACK: PipelineFlags.CONNTRACK,
    PipelineStage.SYN_PROXY: PipelineFlags.SYN_PROXY,
    PipelineStage.L4_LB:     PipelineFlags.L4_LB,
}

_DISPATCHER_C = Path(__file__).parent / "dispatcher.c"


class PipelineLoader:
    """
    يُحمّل XDP Dispatcher + يُدير stages في runtime.

    الاستخدام:
        loader = PipelineLoader(bpf=bpf, iface="eth0", config=cfg)
        loader.load()
        loader.enable_stage(PipelineStage.CONNTRACK)
        # ...
        loader.disable_stage(PipelineStage.CONNTRACK)
        loader.unload()
    """

    def __init__(
        self,
        iface: str,
        config: dict,
        xdp_flags: int = 0,           # XDP_FLAGS_DRV_MODE=0, SKB=2
    ):
        self._iface      = iface
        self._config     = config
        self._xdp_flags  = xdp_flags
        self._bpf        = None        # BCC BPF object (لازم Linux)
        self._loaded_stages: Dict[PipelineStage, object] = {}
        self._current_bitmask: int = int(PipelineFlags.BLACKLIST)  # Default
        self._attached   = False

        # قراءة الـ bitmask الأولي من base.yaml
        pipeline_cfg = config.get("ebpf", {}).get("pipeline", {})
        cfg_bitmask  = pipeline_cfg.get("bitmask", int(PipelineFlags.BLACKLIST))
        self._current_bitmask = int(cfg_bitmask)

    # ── Public API ────────────────────────────────────────────────────────────

    def load(self) -> bool:
        """
        يُحمّل dispatcher.c (= ملف واحد يحتوي كل الـ stages).
        يُسجّل Blacklist stage افتراضياً.
        يرجع True عند النجاح.

        لماذا ملف واحد؟
          BCC يُنشئ BPF object مستقل لكل BPF(text=...) call.
          PROG_ARRAY يجب أن يكون في نفس الـ object حتى تعمل Tail Calls.
          → كل الـ stages مُجمَّعة في dispatcher.c واحد.
        """
        try:
            from bcc import BPF
        except ImportError:
            logger.warning("[Pipeline] BCC not available — pipeline disabled")
            return False

        if not _DISPATCHER_C.exists():
            logger.error(f"[Pipeline] dispatcher.c not found: {_DISPATCHER_C}")
            return False

        try:
            logger.info(f"[Pipeline] Compiling unified pipeline → {self._iface}")

            src = _DISPATCHER_C.read_text(encoding="utf-8")
            self._bpf = BPF(text=src)

            # تحميل الـ dispatcher function وربطه بالـ interface
            dispatcher_fn = self._bpf.load_func("xdp_dispatcher", BPF.XDP)
            self._bpf.attach_xdp(self._iface, dispatcher_fn, self._xdp_flags)
            self._attached = True

            # تسجيل Stage 0 (Blacklist) افتراضياً — دائماً يعمل
            self._register_stage_fn(PipelineStage.BLACKLIST, "stage_blacklist")

            # كتابة bitmask الأولي في kernel map
            self._write_bitmask(self._current_bitmask)

            logger.info(
                f"[Pipeline] \u2705 Dispatcher loaded on {self._iface} "
                f"| stages=1 | bitmask=0b{self._current_bitmask:08b}"
            )
            return True

        except Exception as exc:
            logger.error(f"[Pipeline] Load failed: {exc}", exc_info=True)
            return False

    def unload(self) -> None:
        """يفصل XDP من الـ interface ويُحرّر الموارد."""
        if not self._bpf or not self._attached:
            return
        try:
            self._bpf.remove_xdp(self._iface)
            self._attached = False
            self._loaded_stages.clear()
            logger.info(f"[Pipeline] Detached from {self._iface}")
        except Exception as exc:
            logger.warning(f"[Pipeline] Unload error: {exc}")

    def enable_stage(self, stage: PipelineStage) -> bool:
        """
        يُفعّل stage في الـ PROG_ARRAY ويُحدّث bitmask.
        آمن للاستدعاء أثناء التشغيل (hot-enable).

        الشرط: stage function يجب أن يكون موجوداً في نفس BPF object
               (مُجمَّع مع dispatcher.c في ملف واحد).
        """
        if not self._bpf:
            return False

        func_name = f"stage_{stage.name.lower()}"
        if not self._register_stage_fn(stage, func_name):
            return False

        flag = int(_STAGE_TO_FLAG[stage])
        self._current_bitmask |= flag
        self._write_bitmask(self._current_bitmask)

        logger.info(
            f"[Pipeline] \u2705 Stage {stage.name} enabled "
            f"| bitmask=0b{self._current_bitmask:08b}"
        )
        return True

    def disable_stage(self, stage: PipelineStage) -> bool:
        """
        يُوقف stage في الـ Pipeline:
          1. يزيل function من PROG_ARRAY (يُقيم NULL)
          2. يُحدّث bitmask
        لا يُمكن إيقاف BLACKLIST (الأساس الأمني).
        """
        if stage == PipelineStage.BLACKLIST:
            logger.warning("[Pipeline] Cannot disable BLACKLIST stage — security requirement")
            return False

        if not self._bpf:
            return False

        try:
            prog_array = self._bpf["xdp_pipeline"]
            # إزالة الـ mapping من PROG_ARRAY
            try:
                del prog_array[prog_array.Key(int(stage))]
            except Exception:
                pass
            self._loaded_stages.pop(stage, None)
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to unregister stage {stage.name}: {exc}")
            return False

        # تحديث bitmask
        flag = int(_STAGE_TO_FLAG[stage])
        self._current_bitmask &= ~flag
        self._write_bitmask(self._current_bitmask)

        logger.info(
            f"[Pipeline] Stage {stage.name} disabled "
            f"| bitmask=0b{self._current_bitmask:08b}"
        )
        return True

    def get_bitmask(self) -> int:
        """يرجع الـ bitmask الحالي (Python side)."""
        return self._current_bitmask

    def get_active_stages(self) -> list:
        """يرجع قائمة الـ stages المُفعَّلة حالياً."""
        return [s.name for s in self._loaded_stages]

    def get_stats(self) -> dict:
        """يرجع إحصائيات الـ dispatcher من kernel."""
        if not self._bpf:
            return {}
        try:
            stats = self._bpf["dispatcher_stats"]
            return {
                "total_dispatched":   stats[stats.Key(0)].value,
                "tail_call_missed":   stats[stats.Key(1)].value,
                "meta_alloc_failed":  stats[stats.Key(2)].value,
                "active_stages":      self.get_active_stages(),
                "bitmask":            self._current_bitmask,
            }
        except Exception as exc:
            logger.debug(f"[Pipeline] Stats read error: {exc}")
            return {}

    def sync_from_config(self) -> None:
        """
        يزامن حالة الـ stages مع base.yaml (للـ hot-reload).
        يُستدعى من feature flag watcher.
        """
        try:
            from system.config.feature_flags import FeatureFlagManager
            flags = FeatureFlagManager.instance().current.data_plane

            # Phase 3: Conntrack
            if flags.ebpf_conntrack:
                self.enable_stage(PipelineStage.CONNTRACK)
            else:
                self.disable_stage(PipelineStage.CONNTRACK)

            # Phase 4: SYN Proxy
            if flags.ebpf_syn_proxy:
                self.enable_stage(PipelineStage.SYN_PROXY)
            else:
                self.disable_stage(PipelineStage.SYN_PROXY)

            # Phase 5: L4 LB
            if flags.ebpf_l4_lb:
                self.enable_stage(PipelineStage.L4_LB)
            else:
                self.disable_stage(PipelineStage.L4_LB)

        except Exception as exc:
            logger.error(f"[Pipeline] sync_from_config failed: {exc}")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _register_stage_fn(self, stage: PipelineStage, func_name: str) -> bool:
        """
        يُحمّل XDP function من نفس الـ BPF object ويُسجّله في PROG_ARRAY.

        ملاحظة: `load_func()` من BCC يُحمّل الـ function من نفس الـ object
        المُجمَّع في `load()` — لا يتطلب ملف C منفصل.
        BCC API: prog_array[Key(idx)] = Leaf(fn.fd)
        """
        try:
            from bcc import BPF
            fn         = self._bpf.load_func(func_name, BPF.XDP)
            prog_array = self._bpf["xdp_pipeline"]
            key        = prog_array.Key(int(stage))
            prog_array[key] = prog_array.Leaf(fn.fd)
            self._loaded_stages[stage] = fn
            logger.debug(f"[Pipeline] Registered {func_name} → PROG_ARRAY[{int(stage)}]")
            return True
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to register {func_name}: {exc}")
            return False

    def _write_bitmask(self, bitmask: int) -> None:
        """يكتب pipeline bitmask في kernel map بشكل atomic."""
        if not self._bpf:
            return
        try:
            cfg = self._bpf["pipeline_config"]
            cfg[cfg.Key(0)] = cfg.Leaf(bitmask)
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to write bitmask: {exc}")

    # ── Context Manager ───────────────────────────────────────────────────────

    def __enter__(self):
        self.load()
        return self

    def __exit__(self, *_):
        self.unload()
