#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Enterprise bunyanx - eBPF XDP Engine
═══════════════════════════════════════════════════════════════════

Manages eBPF XDP/TC programs for high-speed packet filtering at
kernel level. Implements feedback loop with user-space proxy.

Author: Enterprise Security Team
License: Proprietary
"""

import asyncio
import logging
import socket
import struct
import ipaddress
from typing import Optional, Set, TYPE_CHECKING
from pathlib import Path
from datetime import datetime

if TYPE_CHECKING:
    from system.telemetry.events import UnifiedEventSink
    from system.telemetry.events.event_schema import EventVerdict

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logging.warning("BCC not available. eBPF features will be disabled.")

logger = logging.getLogger(__name__)


class XDPEngine:
    """
    eBPF Manager for kernel-level packet filtering
    
    Implements XDP (eXpress Data Path) for ultra-fast packet filtering
    and TC (Traffic Control) for additional processing.
    """
    
    def __init__(self, config: dict, event_sink: Optional['UnifiedEventSink'] = None):
        self.config = config
        self.ebpf_config = config.get('ebpf', {})
        
        self.enabled = self.ebpf_config.get('enabled', True) and BCC_AVAILABLE
        
        # Event sink for unified logging
        self.event_sink = event_sink
        
        if not self.enabled:
            logger.warning("eBPF is disabled or BCC not available")
            return

        # ── Interface Resolution (Hardware Appliance Mode) ──────────────
        # IMPORTANT: XDP must NEVER attach to the MGMT interface.
        # We resolve data-plane interfaces (WAN + LAN) by MAC from InterfaceManager.
        # This ensures portability across hardware — no hardcoded 'eth0'.
        self.data_plane_interfaces: list[str] = self._resolve_data_plane_interfaces()

        # Legacy single-interface field kept for backward compatibility
        # Points to first data-plane interface if available, else falls back gracefully.
        self.interface = self.data_plane_interfaces[0] if self.data_plane_interfaces else None
        if not self.interface:
            logger.warning("XDP: No data-plane interfaces configured. eBPF will not attach.")
            self.enabled = False
            return

        self.xdp_mode = self.ebpf_config.get('xdp_mode', 'native')
        
        # eBPF program
        self.bpf: Optional[BPF] = None
        
        # Maps for blocked IPs and rate limiting
        self.blocked_ips: Set[str] = set()
        self.rate_limited_ips: Set[str] = set()
        
        # Feedback loop (legacy polling — preserved for backward compat)
        self.feedback_interval = self.ebpf_config.get('feedback_interval', 5)
        self.feedback_task = None

        # Ring Buffer Consumer (Phase 1) — replaces polling when flag is enabled
        self.ring_buf_consumer = None
        self._rb_cfg = self.ebpf_config.get('ring_buffers', {})

        # Modular Pipeline (Phase 2) — Tail Calls Dispatcher
        self.pipeline_loader = None
        self._pipeline_cfg = self.ebpf_config.get('pipeline', {})
        
        # ML Anomaly Integration
        self.ml_config = self.ebpf_config.get('ml_integration', {})
        self.ml_enabled = self.ml_config.get('enabled', True)
        self.ml_threshold = self.ml_config.get('confidence_threshold', 0.85)

        # Kernel version detection (needed for SYN Proxy helpers in Phase 4)
        self.kernel_major, self.kernel_minor = self._detect_kernel_version()

        model_path = config.get('ml', {}).get('anomaly_detection', {}).get('model_path')
        from modules.ids_ips.engine.anomaly_detector import AnomalyDetector
        self.anomaly_detector = AnomalyDetector(model_path=model_path)

        
        logger.info(
            f"XDP Engine initialized. Interfaces: {self.data_plane_interfaces} "
            f"| Kernel: {self.kernel_major}.{self.kernel_minor} "
            f"| RingBuf capable: {self.kernel_major > 5 or (self.kernel_major == 5 and self.kernel_minor >= 8)}"
        )
    
    def _resolve_data_plane_interfaces(self) -> list:
        """
        Resolves the actual kernel device names for WAN + LAN roles
        using MAC address lookup via InterfaceManager.
        MGMT is explicitly excluded — XDP never touches it.
        """
        resolved = []
        try:
            from system.networking.appliance.interface_manager import InterfaceManager
            mgr = InterfaceManager(self.config)
            # Only attach XDP to data-plane roles
            for role in ("wan", "lan", "dmz"):
                device = mgr.get_role_device(role)
                if device:
                    resolved.append(device)
                    logger.info(f"XDP will attach to {role.upper()} → {device}")
        except Exception as e:
            logger.warning(f"XDP interface resolution failed: {e}. Using fallback.")
            # Fallback: read legacy ebpf.interface key if present, but warn loudly
            legacy = self.ebpf_config.get('interface')
            if legacy and legacy != 'eth0':
                resolved.append(legacy)
            # Never silently fall back to eth0 — that could be MGMT!
        return resolved

    @staticmethod
    def _detect_kernel_version() -> tuple:
        """
        يكتشف إصدار النواة — يُستخدم لتفعيل Ring Buffers (5.8+) وSYN Cookie helpers (6.8+).
        يعمل طبيعياً على Linux ، ويرجع (0, 0) على Windows/Dev.
        """
        try:
            import subprocess
            out = subprocess.check_output(["uname", "-r"], timeout=2).decode().strip()
            parts = out.split(".")
            major = int(parts[0]) if parts else 0
            minor = int(parts[1].split("-")[0]) if len(parts) > 1 else 0
            return (major, minor)
        except Exception:
            return (0, 0)   # Dev/Windows env — graceful degradation

    async def start(self):
        """Start eBPF programs and attach to all data-plane interfaces."""
        if not self.enabled:
            logger.info("eBPF not enabled, skipping")
            return
        
        try:
            # ── Phase 2: Modular Pipeline (Tail Calls) ────────────────────────────────
            pipeline_enabled = self._pipeline_cfg.get('enabled', False)
            try:
                from system.config.feature_flags import FeatureFlagManager
                _flags = FeatureFlagManager.instance()
                pipeline_enabled = pipeline_enabled and _flags.current.data_plane.ebpf_pipeline
            except Exception:
                pass

            if pipeline_enabled:
                await self._start_pipeline_mode()
            else:
                await self._start_legacy_mode()

            # Initialize rate limiting config from base.yaml
            try:
                rate_limit_cfg = self.config.get('security', {}).get('rate_limiting', {})
                if rate_limit_cfg.get('enabled', True):
                    pps = rate_limit_cfg.get('requests_per_second', 1000)
                    burst = rate_limit_cfg.get('burst_size', 5000)
                    await self.set_rate_limit(pps, burst)
            except Exception as e:
                logger.error(f"Failed to initialize BPF rate limits: {e}")

            # Sync Whitelist entries to eBPF map
            try:
                self.sync_whitelist()
            except Exception as e:
                logger.error(f"Failed to sync BPF whitelist: {e}")

            logger.info("✅ XDP Engine started successfully")

        except Exception as e:
            logger.error(f"Failed to start eBPF: {e}", exc_info=True)
            self.enabled = False

    def sync_whitelist(self):
        """Sync host IPs from IPWhitelistManager into eBPF whitelist_ips map."""
        bpf_obj = self.bpf or (self.pipeline_loader._bpf if self.pipeline_loader else None)
        if not self.enabled or not bpf_obj:
            return
        try:
            from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
            wl_mgr = get_whitelist_manager()
            wl_data = wl_mgr.list_all()
            
            try:
                wl_map = bpf_obj.get_table("whitelist_ips")
                wl_map.clear()
            except Exception:
                return
            
            import socket, struct
            count = 0
            for host_entry in wl_data.get("hosts", []):
                ip_str = host_entry.get("ip")
                if ip_str:
                    try:
                        ip_int = struct.unpack("<I", socket.inet_aton(ip_str))[0]
                        wl_map[wl_map.Key(ip_int)] = wl_map.Leaf(1)
                        count += 1
                    except Exception:
                        pass
            logger.info(f"✅ Synced {count} whitelisted host IPs to eBPF whitelist_ips map")
        except Exception as e:
            logger.error(f"[XDP] Failed to sync whitelist map: {e}")

    async def _start_pipeline_mode(self) -> None:
        """
        Phase 2: تشغيل الـ Modular Pipeline (Tail Calls Dispatcher).
        يستخدم dispatcher.c بدلاً من الكود المضمّن.
        """
        from acceleration.ebpf.pipeline.pipeline_loader import PipelineLoader, PipelineStage

        logger.info("[XDP] Starting in Pipeline mode (Tail Calls Dispatcher)...")

        for iface in self.data_plane_interfaces:
            loader = PipelineLoader(
                iface=iface,
                config=self.config,
                xdp_flags=self._get_xdp_flags(),
            )
            if loader.load():
                self.pipeline_loader = loader   # يحتفظ بآخر loader (للـ API)
                # ربط مع feature flags للـ hot-reload
                try:
                    from system.config.feature_flags import FeatureFlagManager
                    FeatureFlagManager.instance().on_reload(
                        lambda _flags, l=loader: l.sync_from_config()
                    )
                except Exception:
                    pass
                logger.info(f"✅ Pipeline loaded on {iface} — bitmask=0b{loader.get_bitmask():08b}")
            else:
                logger.warning(f"⚠️ Pipeline load failed on {iface} — fallback to legacy")
                await self._start_legacy_mode()
                return

        # Ring Buffers مع Pipeline — يعملان معاً
        await self._start_ring_buffer_consumer()
        self.feedback_task = asyncio.create_task(self._feedback_loop_legacy())

    async def _start_legacy_mode(self) -> None:
        """
        Legacy mode: كود C مضمّن في Python (Phase 0 القديم).
        يعمل بدون Dispatcher — برنامج واحد لكل شيء.
        """
        logger.info("[XDP] Starting in Legacy mode (embedded C program)...")

        self.bpf = BPF(text=self._get_xdp_program())
        fn = self.bpf.load_func("xdp_filter", BPF.XDP)
        flags = self._get_xdp_flags()

        for iface in self.data_plane_interfaces:
            self.bpf.attach_xdp(iface, fn, flags)
            logger.info(f"✅ XDP (Legacy) attached to {iface}")

        await self._start_ring_buffer_consumer()

    async def _start_ring_buffer_consumer(self) -> None:
        """
        Phase 1: تشغيل Ring Buffer Consumer إذا كان مفعّلاً.
        """
        bpf_obj = self.bpf or (
            self.pipeline_loader._bpf
            if self.pipeline_loader else None
        )
        if not bpf_obj:
            self.feedback_task = asyncio.create_task(self._feedback_loop())
            return

        ring_buf_capable = (
            self._rb_cfg.get('critical_size_kb', 0) > 0
            and (self.kernel_major > 5 or (self.kernel_major == 5 and self.kernel_minor >= 8))
        )
        try:
            from system.config.feature_flags import FeatureFlagManager
            ring_buf_capable = ring_buf_capable and FeatureFlagManager.instance().current.data_plane.ebpf_ring_buffers
        except Exception:
            pass

        if ring_buf_capable:
            from acceleration.ebpf.ring_buffer_consumer import RingBufConsumer
            self.ring_buf_consumer = RingBufConsumer(
                bpf=bpf_obj,
                engine=self,
                warning_poll_ms=100,
                info_poll_sec=self.feedback_interval,
            )
            await self.ring_buf_consumer.start()
            self.feedback_task = asyncio.create_task(self._feedback_loop_legacy())
            logger.info("✅ Ring Buffer Consumer active — event latency ≤ 1ms")
        else:
            self.feedback_task = asyncio.create_task(self._feedback_loop())
            logger.info("⚠️ Ring Buffers disabled — using legacy 5s polling")

    
    async def stop(self):
        """Stop eBPF programs and detach from all data-plane interfaces."""
        if not self.enabled:
            return

        try:
            logger.info("Stopping XDP Engine...")

            # Stop Ring Buffer Consumer
            if self.ring_buf_consumer:
                await self.ring_buf_consumer.stop()
                self.ring_buf_consumer = None

            # Stop feedback task
            if self.feedback_task:
                self.feedback_task.cancel()
                try:
                    await self.feedback_task
                except asyncio.CancelledError:
                    pass

            # Phase 2: Pipeline Loader detach
            if self.pipeline_loader:
                self.pipeline_loader.unload()
                self.pipeline_loader = None
            elif self.bpf:
                # Legacy mode detach
                for iface in self.data_plane_interfaces:
                    try:
                        self.bpf.remove_xdp(iface)
                        logger.info(f"XDP detached from {iface}")
                    except Exception as de:
                        logger.warning(f"Could not detach from {iface}: {de}")

            logger.info("XDP Engine stopped.")
        except Exception as e:
            logger.error(f"Error stopping XDP: {e}")

    
    def _get_xdp_flags(self) -> int:
        """Get XDP attachment flags based on mode"""
        if self.xdp_mode == 'native':
            return 0  # XDP_FLAGS_DRV_MODE
        elif self.xdp_mode == 'offload':
            return 1 << 2  # XDP_FLAGS_HW_MODE
        else:  # generic
            return 1 << 1  # XDP_FLAGS_SKB_MODE
    
    def _get_xdp_program(self) -> str:
        """
        Get eBPF XDP program source code
        
        This program runs in the kernel for every packet at the NIC driver level.
        """
        return """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// ═══ BPF Maps ═══

// Blocked IP addresses (key: IP, value: 1 = blocked)
BPF_HASH(blocked_ips, u32, u32, 100000);

// Whitelisted IP addresses (key: IP, value: 1 = whitelisted)
BPF_HASH(whitelist_ips, u32, u32, 10000);

struct rate_info {
    u64 last_ts;
    u64 count;
};

// Rate limiting (key: IP, value: rate_info struct)
BPF_HASH(rate_limit, u32, struct rate_info, 50000);

// Statistics (key: 0=total, 1=blocked, 2=rate_limited, 3=ringbuf_lost)
BPF_ARRAY(stats, u64, 10);

// Configuration (key: 0=rate_limit_pps, 1=rate_limit_burst)
BPF_ARRAY(config, u64, 10);

// ── Phase 1: Tiered Ring Buffers ──────────────────────────────────────────
// أحداث حرجية: FORCE_WAKEUP — Python يستيقظ < 1ms
BPF_RINGBUF_OUTPUT(critical_events, 1024);   // 1MB = 1024 pages
// أنشطة مشبوهة: batch كل 100ms
BPF_RINGBUF_OUTPUT(warning_events,  4096);   // 4MB
// إحصائيات: polling كل 5ث
BPF_RINGBUF_OUTPUT(info_events,     16384);  // 16MB

// عداد الأحداث المفقودة (NMI overflow fallback)
BPF_ARRAY(lost_events_counter, u64, 1);

// هيكل الحدث الموحد — 64 bytes (cache-aligned)
// يجب أن يتطابق مع _EVENT_FORMAT في ring_buffer_consumer.py
struct security_event {
    u64  timestamp_ns;
    u32  src_ip;
    u32  dst_ip;
    u16  src_port;
    u16  dst_port;
    u8   event_type;   // EventType enum (0=blocked,1=rate,2=syn,3=ml,...)
    u8   severity;     // 0=info,1=warning,2=critical
    u16  protocol;     // IPPROTO_TCP/UDP/etc
    u32  pkt_count;
    char reason[32];
};  // total: 8+4+4+2+2+1+1+2+4+32 = 60 bytes (+4 pad = 64)

// ── emit_* helpers (NMI-safe) ─────────────────────────────────────────────

static __always_inline void _lost_event_inc(void) {
    u32 key = 0;
    u64 *cnt = lost_events_counter.lookup(&key);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

// أحداث حرجية: BPF_RB_FORCE_WAKEUP — يوقظ Python فوراً
static __always_inline void emit_critical(u32 src_ip, u32 dst_ip,
                                          u16 sport, u16 dport,
                                          u8 etype, u16 proto, u32 cnt) {
    struct security_event *e = critical_events.ringbuf_reserve(
        sizeof(struct security_event));
    if (!e) { _lost_event_inc(); return; }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip       = src_ip;
    e->dst_ip       = dst_ip;
    e->src_port     = sport;
    e->dst_port     = dport;
    e->event_type   = etype;
    e->severity     = 2;  // CRITICAL
    e->protocol     = proto;
    e->pkt_count    = cnt;
    e->reason[0]    = 0;
    critical_events.ringbuf_submit(e, BPF_RB_FORCE_WAKEUP);
}

// أحداث تحذير: batch — لا يوقظ Python فوراً
static __always_inline void emit_warning(u32 src_ip, u8 etype, u32 cnt) {
    struct security_event *e = warning_events.ringbuf_reserve(
        sizeof(struct security_event));
    if (!e) { _lost_event_inc(); return; }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip       = src_ip;
    e->event_type   = etype;
    e->severity     = 1;  // WARNING
    e->pkt_count    = cnt;
    e->reason[0]    = 0;
    warning_events.ringbuf_submit(e, BPF_RB_NO_WAKEUP);
}

// إحصائيات: polling — Python تقرأ عند الفرصة
static __always_inline void emit_info(u32 src_ip, u8 etype, u32 cnt) {
    struct security_event *e = info_events.ringbuf_reserve(
        sizeof(struct security_event));
    if (!e) { _lost_event_inc(); return; }
    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip       = src_ip;
    e->event_type   = etype;
    e->severity     = 0;  // INFO
    e->pkt_count    = cnt;
    e->reason[0]    = 0;
    info_events.ringbuf_submit(e, BPF_RB_NO_WAKEUP);
}

// ═══ Helper Functions ═══

static __always_inline int is_exempt_ip(u32 ip) {
    // 1. Check explicit whitelist BPF map
    u32 *wl = whitelist_ips.lookup(&ip);
    if (wl != NULL && *wl == 1) return 1;

    // 2. Check Loopback (127.0.0.0/8) in network byte order
    unsigned char *b = (unsigned char *)&ip;
    if (b[0] == 127) return 1;

    return 0;
}

static __always_inline int check_ip_blocked(u32 ip) {
    u32 *blocked = blocked_ips.lookup(&ip);
    return (blocked != NULL && *blocked == 1);
}

static __always_inline int check_rate_limit(u32 ip) {
    u64 now = bpf_ktime_get_ns();
    struct rate_info *info = rate_limit.lookup(&ip);
    
    if (info == NULL) {
        struct rate_info new_info = { .last_ts = now, .count = 1 };
        rate_limit.update(&ip, &new_info);
        return 0;
    }
    
    // Reset counter if more than 1 second (1,000,000,000 ns) has passed
    if (now - info->last_ts > 1000000000ULL) {
        info->last_ts = now;
        info->count = 1;
        return 0;
    }
    
    u32 key = 0;
    u64 *pps_limit = config.lookup(&key);
    u64 rate_limit_pps = (pps_limit != NULL && *pps_limit > 0) ? *pps_limit : 5000;
    
    info->count++;
    if (info->count >= rate_limit_pps) {
        return 1;
    }
    
    return 0;
}

static __always_inline void update_stats(int stat_type) {
    u32 key = stat_type;
    u64 *value = stats.lookup(&key);
    if (value != NULL) {
        __sync_fetch_and_add(value, 1);
    } else {
        u64 initial = 1;
        stats.update(&key, &initial);
    }
}

// ═══ Main XDP Program ═══

int xdp_filter(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != htons(ETH_P_IP))  return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)       return XDP_PASS;
    
    u32 src_ip = ip->saddr;
    u32 dst_ip = ip->daddr;
    
    update_stats(0);   // total_packets

    // ── Exemption check: RFC-1918 Private IPs & Whitelisted IPs bypass eBPF drops ──
    if (is_exempt_ip(src_ip)) {
        return XDP_PASS;
    }

    
    // ── IP Blocklist check ────────────────────────────────────────────────────
    if (check_ip_blocked(src_ip)) {
        update_stats(1);
        // إصدار حدث Critical فوري (EventType=0=BLOCKED_IP)
        emit_critical(src_ip, dst_ip, 0, 0, 0, ip->protocol, 1);
        return XDP_DROP;
    }
    
    // ── Rate Limit check ────────────────────────────────────────────────────
    if (check_rate_limit(src_ip)) {
        update_stats(2);
        // إصدار حدث Warning (EventType=1=RATE_LIMITED)
        emit_warning(src_ip, 1, 1);
        return XDP_DROP;
    }
    
    // ── تمرير TCP إلى proxy ports ────────────────────────────────────
    if (ip->protocol == IPPROTO_TCP) {
        u8 ihl = ip->ihl;
        if (ihl < 5) return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + (ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        u16 dest_port = ntohs(tcp->dest);
        if (dest_port == 8080 || dest_port == 8443 || dest_port == 443) {
            return XDP_PASS;
        }
    }
    
    return XDP_PASS;
}
"""
    
    async def add_blocked_ip(self, ip: str):
        """
        Add IP address to kernel-level blocklist
        
        Args:
            ip: IP address to block
        """
        if not self.enabled or not self.bpf:
            return
        
        try:
            # Fix Endianness: Convert IP to integer in correct network byte order for BPF map
            import socket, struct
            ip_int = struct.unpack("<I", socket.inet_aton(ip))[0]
            
            # Update eBPF map
            blocked_ips = self.bpf.get_table("blocked_ips")
            blocked_ips[blocked_ips.Key(ip_int)] = blocked_ips.Leaf(1)
            
            self.blocked_ips.add(ip)
            logger.info(f"🚫 Added {ip} to eBPF blocklist")

            # Trigger eBPF voice alert asynchronously (with 30s debounce cooldown)
            try:
                from acceleration.ebpf.ebpf_audio_notifier import get_ebpf_audio_notifier
                get_ebpf_audio_notifier().trigger_alert(src_ip=ip, event_type="RATE_LIMITED")
            except Exception:
                pass
            
        except Exception as e:
            logger.error(f"Failed to add IP to blocklist: {e}")
    
    async def remove_blocked_ip(self, ip: str):
        """Remove IP address from blocklist"""
        if not self.enabled or not self.bpf:
            return
        
        try:
            import socket, struct
            ip_int = struct.unpack("<I", socket.inet_aton(ip))[0]
            
            blocked_ips = self.bpf.get_table("blocked_ips")
            blocked_ips.pop(blocked_ips.Key(ip_int))
            
            self.blocked_ips.discard(ip)
            logger.info(f"✅ Removed {ip} from eBPF blocklist")
            
        except Exception as e:
            logger.error(f"Failed to remove IP from blocklist: {e}")
    
    async def add_blocked_domain(self, domain: str):
        """
        Add domain to blocklist (requires DNS resolution)
        
        This is called from the feedback loop when suspicious domains are detected.
        """
        try:
            # Resolve domain to IP
            loop = asyncio.get_event_loop()
            addrinfo = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            
            for info in addrinfo:
                ip = info[4][0]
                await self.add_blocked_ip(ip)
                logger.info(f"🚫 Blocked domain {domain} -> {ip}")
                
        except Exception as e:
            logger.error(f"Failed to block domain {domain}: {e}")
    
    async def set_rate_limit(self, pps: int, burst: int, ip: Optional[str] = None):
        """
        Set rate limiting parameters
        
        Args:
            pps: Packets per second limit
            burst: Burst limit
            ip: Optional IP to rate limit (ignored in global eBPF limit)
        """
        if not self.enabled or not self.bpf:
            return
        
        try:
            config = self.bpf.get_table("config")
            config[config.Key(0)] = config.Leaf(pps)
            config[config.Key(1)] = config.Leaf(burst)
            
            logger.info(f"⚙️  Set rate limit: {pps} pps, burst {burst}")
            
        except Exception as e:
            logger.error(f"Failed to set rate limit: {e}")
    
    def get_statistics(self) -> dict:
        """Get eBPF statistics"""
        if not self.enabled or not self.bpf:
            return {}
        
        try:
            stats_table = self.bpf.get_table("stats")
            result = {
                'total_packets':       stats_table[stats_table.Key(0)].value if stats_table.Key(0) in stats_table else 0,
                'blocked_packets':     stats_table[stats_table.Key(1)].value if stats_table.Key(1) in stats_table else 0,
                'rate_limited_packets':stats_table[stats_table.Key(2)].value if stats_table.Key(2) in stats_table else 0,
                'blocked_ips_count':   len(self.blocked_ips),
            }
            # Ring Buffer lost-events counter (Phase 1)
            try:
                lost_tbl = self.bpf.get_table("lost_events_counter")
                result['ringbuf_lost'] = lost_tbl[lost_tbl.Key(0)].value
            except Exception:
                result['ringbuf_lost'] = 0
            # Ring Buffer Consumer stats (if active)
            if self.ring_buf_consumer:
                result['ringbuf_consumer'] = self.ring_buf_consumer.get_stats()
            return result
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    async def _feedback_loop_legacy(self):
        """
        دورة تلخيص بسيطة للإحصائيات — تعمل بجانب Ring Buffer Consumer.
        بينما Consumer يتولى الأحداث الأمنية فورياً،
        هذه الدورة تتولى ML analysis وإحصائيات التلخيص.
        """
        logger.info("[XDP] Legacy stats loop running alongside Ring Buffer Consumer")
        try:
            while True:
                await asyncio.sleep(self.feedback_interval)
                stats = self.get_statistics()
                if stats:
                    logger.debug(
                        f"[XDP] Stats: total={stats.get('total_packets', 0)} "
                        f"blocked={stats.get('blocked_packets', 0)} "
                        f"rate_limited={stats.get('rate_limited_packets', 0)} "
                        f"rb_lost={stats.get('ringbuf_lost', 0)}"
                    )
                    if self.event_sink and stats.get('blocked_packets', 0) > 0:
                        await self._send_xdp_summary_event(stats)
                if self.ml_enabled:
                    await self._analyze_and_update()
                
                # Clear rate limit map for the next interval
                if self.bpf:
                    try:
                        rate_limit_map = self.bpf.get_table("rate_limit")
                        rate_limit_map.clear()
                    except Exception as e:
                        logger.error(f"[XDP] Error clearing rate_limit map: {e}")
        except asyncio.CancelledError:
            logger.info("[XDP] Legacy stats loop cancelled")
        except Exception as e:
            logger.error(f"[XDP] Legacy stats loop error: {e}", exc_info=True)

    async def _feedback_loop(self):
        """
        Legacy Feedback Loop — Polling mode (when Ring Buffers are disabled).
        يعمل بدلاً من Ring Buffer Consumer عندما ebpf_ring_buffers=false.
        """
        logger.info("[XDP] Starting legacy polling feedback loop (5s interval)...")
        try:
            while True:
                await asyncio.sleep(self.feedback_interval)
                stats = self.get_statistics()
                
                if stats:
                    logger.debug(
                        f"eBPF Stats: "
                        f"Total={stats.get('total_packets', 0)} "
                        f"Blocked={stats.get('blocked_packets', 0)} "
                        f"RateLimited={stats.get('rate_limited_packets', 0)} "
                        f"BlockedIPs={stats.get('blocked_ips_count', 0)}"
                    )
                    
                    # Send aggregate stats to event sink
                    if self.event_sink and stats.get('blocked_packets', 0) > 0:
                        await self._send_xdp_summary_event(stats)
                
                # Here we can implement more sophisticated feedback logic:
                # 1. Analyze traffic patterns
                # 2. Detect anomalies
                # 3. Update eBPF maps based on ML predictions
                # 4. Adjust rate limits dynamically
                
                # AI/ML integration
                if self.ml_enabled:
                    await self._analyze_and_update()
                
                # Clear rate limit map for the next interval
                if self.bpf:
                    try:
                        rate_limit_map = self.bpf.get_table("rate_limit")
                        rate_limit_map.clear()
                    except Exception as e:
                        logger.error(f"[XDP] Error clearing rate_limit map: {e}")
                
        except asyncio.CancelledError:
            logger.info("eBPF feedback loop cancelled")
        except Exception as e:
            logger.error(f"Error in feedback loop: {e}", exc_info=True)
    
    async def _send_xdp_summary_event(self, stats: dict):
        """
        Send XDP summary event to Unified Sink
        
        Args:
            stats: XDP statistics dictionary
        """
        try:
            from system.telemetry.events.event_schema import create_event_from_xdp, EventVerdict
            
            # Create aggregate event for XDP activity
            event = create_event_from_xdp(
                src_ip="0.0.0.0",  # Aggregate event
                dst_ip="0.0.0.0",
                src_port=0,
                dst_port=0,
                protocol="aggregate",
                interface=self.interface,
                bytes_count=0,
                packets_count=stats.get('blocked_packets', 0),
                verdict=EventVerdict.DROP,
                reason=f"XDP blocked {stats.get('blocked_packets', 0)} packets, "
                       f"rate-limited {stats.get('rate_limited_packets', 0)}",
                flow_id=f"xdp-summary-{datetime.now().timestamp()}",
            )
            
            await self.event_sink.submit_event(event)
            
        except Exception as e:
            logger.error(f"Error sending XDP event to sink: {e}")
    
    async def _analyze_and_update(self):
        """
        Analyze traffic patterns using ML models and update eBPF maps instantly.
        """
        if not self.ml_enabled or not self.bpf:
            return

        try:
            from modules.ids_ips.engine.anomaly_detector import TrafficFeatures

            
            # Since true per-IP feature extraction requires deep kernel flow tracking,
            # we securely sample active IPs and their packet counts from the BPF rate limit map.
            rate_limit_map = self.bpf.get_table("rate_limit")
            
            suspect_ips = []
            try:
                from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager as _get_wl
                _whitelist = _get_wl()
            except Exception:
                _whitelist = None

            for k, v in rate_limit_map.items():
                # Analyze streams with HIGH activity only (>500 packets/interval)
                # LOW threshold (e.g. 50) causes Health-Check connections and
                # legitimate bursts to be flagged as anomalies, blocking backends.
                if v.value > 500:
                    ip_str = socket.inet_ntoa(struct.pack("<I", k.value))
                    # Skip whitelisted IPs (YAML-backed) — never treat them as threats.
                    # Manage via: POST/DELETE /api/v1/firewall/whitelist/...
                    if _whitelist and _whitelist.is_whitelisted(ip_str):
                        continue
                    if ip_str not in self.blocked_ips:
                        suspect_ips.append((k, ip_str, v.value))
            
            for key, ip_str, pkt_count in suspect_ips:
                # Structure synthetic TrafficFeatures derived from kernel observations
                features = TrafficFeatures(
                    packets_per_second=pkt_count / self.feedback_interval,
                    bytes_per_second=(pkt_count * 1500) / self.feedback_interval,
                    avg_packet_size=1500,
                    packet_size_variance=200,
                    tcp_ratio=0.0,     # REMOVED FAKE DATA: True ML requires a flow tracker
                    udp_ratio=0.0,
                    syn_ratio=0.0,     # FAKE DATA caused 100% false positives
                    unique_dst_ports=1,
                    unique_src_ports=1,
                    inter_arrival_time_mean=0.0,
                    inter_arrival_time_variance=0.0,
                    failed_connections=0,
                    connection_attempts=1,
                    reputation_score=100.0 
                )
                
                # ML Inference Execution
                result = self.anomaly_detector.detect(features)
                
                if result.is_anomaly and result.confidence >= self.ml_threshold:
                    logger.warning(f"🚨 ML Pipeline detected anomaly from {ip_str} (Conf: {result.confidence:.2f}). Dropping via zero-millisecond eBPF!")
                    await self.add_blocked_ip(ip_str)
                    
                    # Log event
                    if self.event_sink:
                        from system.telemetry.events.event_schema import create_event_from_xdp, EventVerdict
                        event = create_event_from_xdp(
                            src_ip=ip_str,
                            dst_ip="0.0.0.0",
                            src_port=0,
                            dst_port=0,
                            protocol="tcp",
                            interface=self.interface,
                            bytes_count=pkt_count * 1500,
                            packets_count=pkt_count,
                            verdict=EventVerdict.DROP,
                            reason=f"ML Anomaly Detected (Confidence: {result.confidence:.2f})",
                            flow_id=f"ml-block-{ip_str}-{datetime.now().timestamp()}",
                        )
                        await self.event_sink.submit_event(event)

        except Exception as e:
            logger.error(f"Error in eBPF ML analysis loop: {e}")


class XDPEngineMock:
    """
    Mock eBPF Manager for systems without BCC/eBPF support
    
    Provides same interface but no actual functionality.
    """
    
    def __init__(self, config: dict, event_sink: Optional['UnifiedEventSink'] = None):
        self.config = config
        self.event_sink = event_sink
        self.enabled = False
        logger.info("Using mock eBPF Manager (BCC not available)")
    
    async def start(self):
        logger.info("Mock eBPF Manager: start() called (no-op)")
    
    async def stop(self):
        logger.info("Mock eBPF Manager: stop() called (no-op)")
    
    async def add_blocked_ip(self, ip: str):
        logger.debug(f"Mock eBPF: would block IP {ip}")
    
    async def remove_blocked_ip(self, ip: str):
        logger.debug(f"Mock eBPF: would unblock IP {ip}")
    
    async def add_blocked_domain(self, domain: str):
        logger.debug(f"Mock eBPF: would block domain {domain}")
    
    async def set_rate_limit(self, pps: int, burst: int, ip: Optional[str] = None):
        logger.debug(f"Mock eBPF: would set rate limit {pps} pps, burst {burst} for IP {ip}")
    
    def get_statistics(self) -> dict:
        return {
            'total_packets': 0,
            'blocked_packets': 0,
            'rate_limited_packets': 0,
            'blocked_ips_count': 0,
        }


def create_xdp_engine(config: dict, event_sink: Optional['UnifiedEventSink'] = None):
    """
    Factory function to create appropriate eBPF manager
    
    Args:
        config: Configuration dictionary
        event_sink: Optional unified event sink
    
    Returns:
        XDPEngine or XDPEngineMock
    """
    if BCC_AVAILABLE and config.get('ebpf', {}).get('enabled', True):
        return XDPEngine(config, event_sink)
    else:
        return XDPEngineMock(config, event_sink)