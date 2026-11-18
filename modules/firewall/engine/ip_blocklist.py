"""
Enterprise bunyanx — IP Blocklist Manager
==========================================
Manages the runtime IP blocklist that is enforced at two layers:
  1. eBPF/XDP kernel level — ultra-fast zero-copy drops via xdp_engine.
  2. Software fallback  — in-memory set used when BCC/eBPF is unavailable.

The blocklist is persisted to a JSON file so entries survive restarts.

API Endpoints (registered in modules/firewall/api/router.py):
  GET    /api/v1/block/ips            — list all blocked IPs
  POST   /api/v1/block/{ip}           — block an IP
  DELETE /api/v1/block/{ip}           — unblock an IP
  DELETE /api/v1/block/all            — clear all blocked IPs (admin only)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import threading
import time
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from acceleration.ebpf.xdp_engine import XDPEngine

logger = logging.getLogger(__name__)

# Persistent storage location for blocked IPs
_DEFAULT_STORE = Path(__file__).parent.parent.parent.parent / "system" / "data" / "blocked_ips.json"


class BlockedEntry:
    """Represents a single blocked IP entry with metadata."""

    def __init__(self, ip: str, reason: str = "Manual block", blocked_by: str = "admin",
                 expires_at: Optional[float] = None):
        self.ip = ip
        self.reason = reason
        self.blocked_by = blocked_by
        self.blocked_at = time.time()
        self.expires_at = expires_at   # None = permanent

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BlockedEntry":
        entry = cls(
            ip=data["ip"],
            reason=data.get("reason", "Restored from disk"),
            blocked_by=data.get("blocked_by", "system"),
            expires_at=data.get("expires_at"),
        )
        entry.blocked_at = data.get("blocked_at", time.time())
        return entry


class IPBlocklistManager:
    """
    Central IP Blocklist Manager.

    Thread-safe via threading.RLock. Backed by eBPF when available,
    falls back to a pure Python in-memory set that integrates with
    the inspection pipeline.
    """

    def __init__(self, xdp_engine: Optional["XDPEngine"] = None,
                 store_path: Path = _DEFAULT_STORE):
        self._xdp: Optional["XDPEngine"] = xdp_engine
        self._entries: Dict[str, BlockedEntry] = {}
        self._store_path = store_path
        # Thread safety: single lock protects _entries for both sync and async callers.
        # RLock is used because _save_to_disk may be called while lock is held.
        self._lock = threading.RLock()
        self._load_from_disk()
        logger.info(f"IPBlocklistManager initialized — {len(self._entries)} entries loaded")
        self._subscribe_to_event_bus()

    def block_ip_sync(
        self,
        ip: str,
        reason: str = "Auto block",
        blocked_by: str = "security_module",
        duration_seconds: Optional[int] = None
    ) -> dict:
        """Synchronous IP/Domain block helper for event bus listeners and internal callers."""
        is_ip_addr = True
        try:
            target = str(ipaddress.ip_address(ip))
        except ValueError:
            is_ip_addr = False
            target = str(ip).strip()
            if not target:
                return {"status": "error", "message": "Target IP or domain cannot be empty"}

        expires_at = None if duration_seconds is None else time.time() + duration_seconds

        with self._lock:
            # Idempotency check: If IP/domain is already blocked and not expired, return immediately
            if target in self._entries and not self._entries[target].is_expired():
                return {"status": "already_blocked", **self._entries[target].to_dict()}

            entry = BlockedEntry(target, reason, blocked_by, expires_at)
            self._entries[target] = entry
            if is_ip_addr:
                self._enforce_kernel_ip_drop(target)
            logger.info(f"🚫 [AutoBlock] Blocked {target}: {reason} (by {blocked_by})")
            self._save_to_disk()

            # If blocked due to DDoS / rate limiting, trigger eBPF audio notification (with cooldown)
            if is_ip_addr and any(k in str(reason).lower() or k in str(blocked_by).lower() for k in ["ddos", "flood", "rate_limit", "syn_flood", "anti_ddos"]):
                try:
                    from acceleration.ebpf.ebpf_audio_notifier import get_ebpf_audio_notifier
                    get_ebpf_audio_notifier().trigger_alert(src_ip=target, event_type="RATE_LIMITED", reason=reason)
                except Exception:
                    pass

            return {"status": "blocked", **entry.to_dict()}

    def _enforce_kernel_ip_drop(self, ip: str) -> None:
        """Insert OS kernel & eBPF/XDP drop rule for instant NIC/kernel hardware packet drop."""
        # 1. Push to eBPF / XDP hardware drop map if eBPF acceleration is available
        try:
            from acceleration.ebpf.xdp_engine import XDPEngine
            xdp = XDPEngine.get_instance()
            if xdp and hasattr(xdp, 'add_blocked_ip'):
                xdp.add_blocked_ip(ip)
        except Exception as _xdp_err:
            logger.debug("[IPBlocklistManager] XDP drop map registration: %s", _xdp_err)

        import os, subprocess, shutil
        if os.name != "posix":
            return
        try:
            # 2. Add raw PREROUTING drop (drops before connection tracking & socket creation)
            if shutil.which("iptables"):
                subprocess.run(
                    ["iptables", "-t", "raw", "-I", "PREROUTING", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=2
                )
                subprocess.run(
                    ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True, timeout=2
                )
            elif shutil.which("nft"):
                subprocess.run(
                    ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                    capture_output=True, timeout=2
                )
        except Exception as exc:
            logger.debug("[IPBlocklistManager] Kernel IP drop rule error for %s: %s", ip, exc)

    def _remove_kernel_ip_drop(self, ip: str) -> None:
        """Remove OS kernel & eBPF/XDP drop rule completely."""
        try:
            from acceleration.ebpf.xdp_engine import XDPEngine
            xdp = XDPEngine.get_instance()
            if xdp and hasattr(xdp, 'remove_blocked_ip'):
                xdp.remove_blocked_ip(ip)
        except Exception:
            pass

        import os, subprocess, shutil
        if os.name != "posix":
            return
        try:
            if shutil.which("iptables"):
                # Loop to purge all duplicate raw PREROUTING and INPUT rules for this IP
                for _ in range(10):
                    res1 = subprocess.run(
                        ["iptables", "-t", "raw", "-D", "PREROUTING", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=2
                    )
                    res2 = subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True, timeout=2
                    )
                    if res1.returncode != 0 and res2.returncode != 0:
                        break
            if shutil.which("nft"):
                subprocess.run(
                    ["nft", "delete", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"],
                    capture_output=True, timeout=2
                )
        except Exception as exc:
            logger.debug("[IPBlocklistManager] Kernel unblock error for %s: %s", ip, exc)

    def _subscribe_to_event_bus(self):
        """Auto-subscribe to EventBus topics so module blocks register automatically in IPBlocklist."""
        try:
            from system.events.bus import EventBus
            from system.events.topics import Topics

            def _handle_block_event(payload: dict, topic_name: str):
                try:
                    if not isinstance(payload, dict):
                        return
                    ip = payload.get("src_ip") or payload.get("client_ip") or payload.get("ip")
                    if not ip:
                        return

                    # ── SAFEGUARD 1: Never auto-block whitelisted or internal network IPs ──
                    try:
                        from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
                        if get_whitelist_manager().is_whitelisted(str(ip)):
                            logger.debug(
                                "[IPBlocklistManager] AutoBlock skipped for Whitelisted IP %s (topic=%s)",
                                ip, topic_name
                            )
                            return
                    except Exception:
                        pass

                    # ── SAFEGUARD 2: Never auto-block protected infrastructure IPs ──
                    import ipaddress as _ipmod
                    try:
                        _ip_obj = _ipmod.ip_address(str(ip))
                        if _ip_obj.is_loopback or str(ip) in ("10.10.0.1", "10.10.0.50", "127.0.0.1"):
                            logger.debug(
                                "[IPBlocklistManager] AutoBlock skipped for Protected System/WAN IP %s (topic=%s)",
                                ip, topic_name
                            )
                            return
                    except ValueError:
                        pass

                    # ── DLP Block Enforcement: Auto-block when DLP decision is BLOCK ──
                    if topic_name == Topics.DLP_INCIDENT:
                        _act = str(payload.get("action") or payload.get("action_taken") or "").upper()
                        if _act not in ("BLOCK", "REJECT", "DROP"):
                            logger.debug("[IPBlocklistManager] AutoBlock skipped for non-BLOCK DLP event on %s (action=%s)", ip, _act)
                            return

                    # General check: Skip auto-blocking for events where action is ALLOW or LOG_ONLY
                    _evt_act = str(payload.get("action") or payload.get("action_taken") or "").upper()
                    if _evt_act in ("ALLOW", "LOG_ONLY", "LOG", "PASSTHROUGH"):
                        logger.debug("[IPBlocklistManager] AutoBlock skipped for %s event on %s", _evt_act, ip)
                        return

                    # FIX-FP-05: Gate THREAT_DETECTED on a minimum confidence level.
                    if topic_name == Topics.THREAT_DETECTED:
                        confidence = float(payload.get("confidence", 1.0))
                        min_conf = float(self._config.get("auto_block_min_confidence", 0.65)
                                         if hasattr(self, "_config") else 0.65)
                        if confidence < min_conf:
                            logger.debug(
                                "[IPBlocklistManager] THREAT_DETECTED skipped (conf=%.3f < min=%.2f) for %s",
                                confidence, min_conf, ip,
                            )
                            return

                    # ── Attack Threshold Guard: Require 3 attempts within 60s for routine single-event blocks ──
                    # High-confidence confirmed threats (conf >= 0.85) or THREAT_DETECTED trigger immediately.
                    _conf = float(payload.get("confidence", 1.0))
                    if _conf < 0.85 and topic_name != Topics.THREAT_DETECTED:
                        now_ts = time.time()
                        if not hasattr(self, "_event_hit_tracker"):
                            self._event_hit_tracker = {}
                        hits = [t for t in self._event_hit_tracker.get(str(ip), []) if now_ts - t <= 60]
                        hits.append(now_ts)
                        self._event_hit_tracker[str(ip)] = hits
                        if len(hits) < 3:
                            logger.debug(
                                "[IPBlocklistManager] Single event logged per-request block (%d/3 hits in 60s) for %s",
                                len(hits), ip
                            )
                            return

                    reason = (
                        payload.get("reason")
                        or payload.get("description")
                        or payload.get("category")
                        or f"Blocked by {topic_name}"
                    )

                    module = payload.get("module") or topic_name.split(".")[0]
                    formatted_reason = f"[{module}] {reason}"

                    # FIX-FP-05b: Auto-blocks from events should be time-limited (10 min),
                    # not permanent. Permanent blocks are for manual admin actions only.
                    _AUTO_BLOCK_TTL = 10 * 60  # 10 minutes
                    self.block_ip_sync(
                        ip=str(ip),
                        reason=formatted_reason,
                        blocked_by=module,
                        duration_seconds=_AUTO_BLOCK_TTL,
                    )
                except Exception as exc:
                    logger.debug("[IPBlocklistManager] Event handle error: %s", exc)

            EventBus.subscribe_from_thread(Topics.WEB_FILTER_BLOCK, lambda p: _handle_block_event(p, Topics.WEB_FILTER_BLOCK))
            EventBus.subscribe_from_thread(Topics.WAF_BLOCK, lambda p: _handle_block_event(p, Topics.WAF_BLOCK))
            EventBus.subscribe_from_thread(Topics.DLP_INCIDENT, lambda p: _handle_block_event(p, Topics.DLP_INCIDENT))
            EventBus.subscribe_from_thread(Topics.RESPONSE_BLOCK, lambda p: _handle_block_event(p, Topics.RESPONSE_BLOCK))
            EventBus.subscribe_from_thread(Topics.THREAT_DETECTED, lambda p: _handle_block_event(p, Topics.THREAT_DETECTED))

            logger.info("[IPBlocklistManager] Auto-subscribed to EventBus security block topics.")
        except Exception as exc:
            logger.warning("[IPBlocklistManager] EventBus subscription skipped: %s", exc)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def block_ip(self, ip: str, reason: str = "Manual block",
                       blocked_by: str = "admin",
                       duration_seconds: Optional[int] = None) -> dict:
        """
        Block an IP address or domain.

        Args:
            ip: IPv4/IPv6 address or domain/target string.
            reason: Human-readable reason for the block.
            blocked_by: Username or system component that initiated the block.
            duration_seconds: Block duration. None = permanent.

        Returns:
            dict with status and entry info.
        """
        is_ip_addr = True
        try:
            target = str(ipaddress.ip_address(ip))
        except ValueError:
            is_ip_addr = False
            target = str(ip).strip()
            if not target:
                raise ValueError("Target IP or domain cannot be empty")

        expires_at = None if duration_seconds is None else time.time() + duration_seconds

        with self._lock:
            entry = BlockedEntry(target, reason, blocked_by, expires_at)
            self._entries[target] = entry

            if is_ip_addr:
                # Kernel-level enforcement
                self._enforce_kernel_ip_drop(target)
                if self._xdp and self._xdp.enabled:
                    await self._xdp.add_blocked_ip(target)
                    logger.info(f"🚫 [eBPF] Blocked {target}: {reason}")
                else:
                    logger.info(f"🚫 [Kernel+Soft] Blocked {target}: {reason}")
            else:
                logger.info(f"🚫 [Domain] Blocked {target}: {reason}")

            result = {"status": "blocked", **entry.to_dict()}

        asyncio.create_task(asyncio.to_thread(self._save_to_disk))
        return result

    async def unblock_ip(self, ip: str) -> dict:
        """
        Remove an IP or domain from the blocklist.

        Args:
            ip: IP address or domain to unblock.

        Returns:
            dict with status.
        """
        if self._xdp is None:
            try:
                from system.core.service_container import ServiceContainer
                self._xdp = ServiceContainer.instance().get_optional('xdp_engine')
            except Exception:
                pass

        is_ip_addr = True
        try:
            target = str(ipaddress.ip_address(ip))
        except ValueError:
            is_ip_addr = False
            target = str(ip).strip()
            if not target:
                raise ValueError("Target IP or domain cannot be empty")

        with self._lock:
            exists_local = target in self._entries
            exists_xdp = bool(is_ip_addr and self._xdp and hasattr(self._xdp, 'blocked_ips') and target in self._xdp.blocked_ips)

            blocked_by = "unknown"
            blocked_at = time.time()

            if exists_local:
                entry = self._entries.pop(target)
                blocked_by = entry.blocked_by
                blocked_at = entry.blocked_at
            elif exists_xdp:
                self._xdp.blocked_ips.discard(target)

            if is_ip_addr:
                # Remove from OS kernel & eBPF/XDP hardware drop tables
                self._remove_kernel_ip_drop(target)
                if self._xdp and self._xdp.enabled:
                    await self._xdp.remove_blocked_ip(target)
                    logger.info(f"✅ [eBPF+Kernel] Unblocked {target}")
                else:
                    logger.info(f"✅ [Kernel+Soft] Unblocked {target}")
            else:
                logger.info(f"✅ [Domain] Unblocked {target}")

            # Synchronize unblock with module blacklists (e.g. WAF, DynamicBlocklist)
            self._sync_unblock_modules(target)

            result = {"status": "unblocked", "ip": target,
                      "was_blocked_by": blocked_by,
                      "was_blocked_at": blocked_at}

        asyncio.create_task(asyncio.to_thread(self._save_to_disk))
        return result

    def unblock_ip_sync(self, ip: str) -> dict:
        """Synchronous IP/domain unblock helper for event bus listeners, CLI, and sync callers."""
        is_ip_addr = True
        try:
            target = str(ipaddress.ip_address(ip))
        except ValueError:
            is_ip_addr = False
            target = str(ip).strip()
            if not target:
                return {"status": "error", "message": "Target IP or domain cannot be empty"}

        with self._lock:
            exists_local = target in self._entries
            exists_xdp = bool(is_ip_addr and self._xdp and hasattr(self._xdp, 'blocked_ips') and target in self._xdp.blocked_ips)

            blocked_by = "unknown"
            blocked_at = time.time()

            if exists_local:
                entry = self._entries.pop(target)
                blocked_by = entry.blocked_by
                blocked_at = entry.blocked_at
            elif exists_xdp:
                self._xdp.blocked_ips.discard(target)

            if is_ip_addr:
                self._remove_kernel_ip_drop(target)
            self._sync_unblock_modules(target)
            logger.info(f"✅ [Kernel+Sync] Unblocked {target}")
            self._save_to_disk()

            return {"status": "unblocked", "ip": target, "was_blocked_by": blocked_by, "was_blocked_at": blocked_at}

    async def unblock_all(self) -> dict:
        """Clear the entire blocklist."""
        if self._xdp is None:
            try:
                from system.core.service_container import ServiceContainer
                self._xdp = ServiceContainer.instance().get_optional('xdp_engine')
            except Exception:
                pass

        with self._lock:
            ips = list(self._entries.keys())
            for target in ips:
                self._entries.pop(target)
                try:
                    ipaddress.ip_address(target)
                    self._remove_kernel_ip_drop(target)
                except ValueError:
                    pass
                if self._xdp and self._xdp.enabled:
                    await self._xdp.remove_blocked_ip(target)
            
            if self._xdp and hasattr(self._xdp, 'blocked_ips') and self._xdp.blocked_ips:
                xdp_ips = list(self._xdp.blocked_ips)
                for ip in xdp_ips:
                    self._xdp.blocked_ips.discard(ip)
                    self._remove_kernel_ip_drop(ip)
                    if self._xdp.enabled:
                        await self._xdp.remove_blocked_ip(ip)

            self._sync_unblock_modules(ip=None)

        asyncio.create_task(asyncio.to_thread(self._save_to_disk))
        logger.warning(f"⚠️  Cleared entire blocklist and purged kernel drop rules")
        return {"status": "cleared", "count": len(ips)}

    def _sync_unblock_modules(self, ip: Optional[str] = None):
        """Synchronize unblocking an IP or domain across subsystem module blacklists (e.g. WAF, DynamicBlocklist)."""
        try:
            from system.core.service_container import ServiceContainer
            waf_plugin = ServiceContainer.instance().get_optional('waf_inspector')
            if waf_plugin and hasattr(waf_plugin, 'cfg'):
                if ip:
                    waf_plugin.cfg.unblacklist_ip(ip)
                else:
                    waf_plugin.cfg.clear_blacklist()
        except Exception as exc:
            logger.debug("[IPBlocklistManager] WAF unblock sync skipped: %s", exc)

        try:
            from modules.ids_ips.engine.blocklist.dynamic_blocklist import DynamicBlocklist
            bl = DynamicBlocklist.instance()
            if ip:
                bl.unblock(ip)
                bl.add_whitelisted_domain(ip)
            else:
                with bl._rw_lock:
                    bl._blocked.clear()
                    bl._counter.clear()
                    bl._save_locked()
        except Exception as exc:
            logger.debug("[IPBlocklistManager] DynamicBlocklist unblock sync skipped: %s", exc)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked (used by software inspection pipeline).
        
        Thread-safe: acquires _lock to prevent read-during-mutation races.
        """
        with self._lock:
            entry = self._entries.get(ip)
            if entry is None:
                if self._xdp and hasattr(self._xdp, 'blocked_ips') and ip in self._xdp.blocked_ips:
                    return True
                return False
            if entry.is_expired():
                # Synchronous cleanup — remove expired entry under lock
                self._entries.pop(ip, None)
                # Schedule async disk save if event loop is running
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(asyncio.to_thread(self._save_to_disk))
                except RuntimeError:
                    pass  # No event loop — disk save will happen on next write
                return False
            return True

    def get_all(self) -> list:
        """Return a list of all currently blocked IPs with their metadata.
        
        Thread-safe: acquires _lock to prevent iteration-during-mutation.
        """
        if self._xdp is None:
            try:
                from system.core.service_container import ServiceContainer
                self._xdp = ServiceContainer.instance().get_optional('xdp_engine')
            except Exception:
                pass

        with self._lock:
            entries = {e.ip: e.to_dict() for e in self._entries.values() if not e.is_expired()}
            
            if self._xdp and hasattr(self._xdp, 'blocked_ips') and self._xdp.blocked_ips:
                for ip in self._xdp.blocked_ips:
                    if ip not in entries:
                        entries[ip] = {
                            "ip": ip,
                            "reason": "حظر تلقائي (eBPF/ML)",
                            "blocked_by": "kernel",
                            "blocked_at": time.time(),
                            "expires_at": None,
                        }

            try:
                from modules.ids_ips.engine.blocklist.dynamic_blocklist import DynamicBlocklist
                for b in DynamicBlocklist.instance().blocked_entries():
                    target = b.get("domain") or b.get("target") or b.get("ip")
                    if target and target not in entries:
                        entries[target] = {
                            "ip": target,
                            "reason": f"DynamicBlocklist ({b.get('hits', 0)} hits)",
                            "blocked_by": "dynamic_blocklist",
                            "blocked_at": time.time(),
                            "expires_at": b.get("expiry"),
                        }
            except Exception:
                pass

            return list(entries.values())

    def get_stats(self) -> dict:
        if self._xdp is None:
            try:
                from system.core.service_container import ServiceContainer
                self._xdp = ServiceContainer.instance().get_optional('xdp_engine')
            except Exception:
                pass

        total = len(self.get_all())
        return {
            "total_blocked": total,
            "ebpf_active": bool(self._xdp and self._xdp.enabled),
            "store_path": str(self._store_path),
        }

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _purge_expired(self):
        with self._lock:
            expired = [ip for ip, e in self._entries.items() if e.is_expired()]
            for ip in expired:
                self._entries.pop(ip)
                self._remove_kernel_ip_drop(ip)
                logger.info(f"🕒 Auto-expired block for {ip} (kernel drop purged)")
        if expired:
            self._save_to_disk()

    def _save_to_disk(self):
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                snapshot = [e.to_dict() for e in self._entries.values()]
            with open(self._store_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save blocklist to disk: {e}")

    def _load_from_disk(self):
        if not self._store_path.exists():
            return
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data:
                entry = BlockedEntry.from_dict(item)
                if not entry.is_expired():
                    self._entries[entry.ip] = entry
            logger.info(f"Loaded {len(self._entries)} blocked IPs from disk")
        except Exception as e:
            logger.error(f"Failed to load blocklist from disk: {e}")


# ── Module-level singleton ────────────────────────────────────────────────────

_instance: Optional[IPBlocklistManager] = None
_singleton_lock = threading.Lock()


def get_blocklist_manager() -> IPBlocklistManager:
    """Return or create the singleton IPBlocklistManager."""
    global _instance
    if _instance is None:
        with _singleton_lock:
            if _instance is None:
                _instance = IPBlocklistManager()
    return _instance


def init_blocklist_manager(xdp_engine=None) -> IPBlocklistManager:
    """Initialize the singleton with an eBPF engine (called at app startup)."""
    global _instance
    with _singleton_lock:
        _instance = IPBlocklistManager(xdp_engine=xdp_engine)
    return _instance

