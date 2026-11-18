"""
BunyanX NGFW -- IP Whitelist Manager
======================================
Manages a persistent YAML-backed whitelist of IPs/CIDRs that are exempt
from auto-blocking by inspection_bridge and xdp_engine.

Key guarantees:
  - Thread-safe via RLock
  - Every mutation is written to disk immediately (no data loss on crash)
  - The YAML file is the single source of truth -- not reset on restart
  - Singleton: use get_whitelist_manager() everywhere

Usage:
    from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager

    mgr = get_whitelist_manager()
    if mgr.is_whitelisted("10.10.0.50"):
        # skip auto-block
        pass
"""

import ipaddress
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import yaml

logger = logging.getLogger(__name__)

# Default path -- matches the config directory used by the firewall module
_DEFAULT_YAML = Path(__file__).parent.parent / "config" / "ip_whitelist.yaml"


class IPWhitelistManager:
    """
    Thread-safe, YAML-backed manager for auto-block exemptions.

    Stores two categories:
      - networks : list of ipaddress.ip_network objects (CIDR ranges)
      - hosts    : set of ipaddress.ip_address objects  (single IPs)

    Both are loaded from ip_whitelist.yaml at startup and kept in memory
    for fast O(n) lookups. Every add/remove is immediately persisted.
    """

    def __init__(self, yaml_path: Path = _DEFAULT_YAML):
        self._path = Path(yaml_path)
        self._lock = threading.RLock()
        # In-memory store: list of (network_obj, meta_dict)
        self._networks: List[tuple] = []   # [(ip_network, {cidr,label,...}), ...]
        self._hosts: dict = {}             # {ip_str: meta_dict}
        self._load()

    # ── Public query API ──────────────────────────────────────────────────────

    def is_whitelisted(self, ip: str) -> bool:
        """
        Return True if `ip` is covered by any whitelist entry.
        Checks hosts first (O(1)), then networks (O(n)).
        Returns False for malformed IPs.
        """
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            logger.debug("[Whitelist] Malformed IP skipped: %r", ip)
            return False

        with self._lock:
            # 1. Exact host match
            if ip in self._hosts:
                return True
            # 2. Network match
            for net, _ in self._networks:
                if addr in net:
                    return True
        return False

    def list_all(self) -> dict:
        """Return full whitelist as a serialisable dict (for API GET)."""
        with self._lock:
            return {
                "networks": [meta for _, meta in self._networks],
                "hosts":    list(self._hosts.values()),
            }

    # ── Network (CIDR) mutation API ───────────────────────────────────────────

    def add_network(
        self,
        cidr: str,
        label: str = "",
        reason: str = "",
        added_by: str = "api",
    ) -> dict:
        """
        Add a CIDR range to the whitelist.
        Raises ValueError if cidr is invalid or already present.
        Persists to YAML immediately.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{cidr}': {exc}") from exc

        canonical = str(net)  # normalise e.g. 10.0.0.1/8 -> 10.0.0.0/8

        with self._lock:
            for existing_net, _ in self._networks:
                if existing_net == net:
                    raise ValueError(f"Network '{canonical}' already in whitelist")

            meta = {
                "cidr":      canonical,
                "label":     label,
                "reason":    reason,
                "added_by":  added_by,
                "added_at":  datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            self._networks.append((net, meta))
            self._save()
            logger.info("[Whitelist] Added network %s (%s) by %s", canonical, label, added_by)
            return meta

    def remove_network(self, cidr: str) -> bool:
        """
        Remove a CIDR range from the whitelist.
        Returns True if removed, False if not found.
        Persists to YAML immediately.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{cidr}': {exc}") from exc

        with self._lock:
            before = len(self._networks)
            self._networks = [(n, m) for n, m in self._networks if n != net]
            removed = len(self._networks) < before
            if removed:
                self._save()
                logger.info("[Whitelist] Removed network %s", str(net))
            return removed

    # ── Host (single IP) mutation API ─────────────────────────────────────────

    def add_host(
        self,
        ip: str,
        label: str = "",
        reason: str = "",
        added_by: str = "api",
    ) -> dict:
        """
        Add a single IP to the whitelist.
        Raises ValueError if IP is invalid or already present.
        Persists to YAML immediately.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP '{ip}': {exc}") from exc

        canonical = str(addr)

        with self._lock:
            if canonical in self._hosts:
                raise ValueError(f"Host '{canonical}' already in whitelist")

            meta = {
                "ip":       canonical,
                "label":    label,
                "reason":   reason,
                "added_by": added_by,
                "added_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            self._hosts[canonical] = meta
            self._save()
            logger.info("[Whitelist] Added host %s (%s) by %s", canonical, label, added_by)
            return meta

    def remove_host(self, ip: str) -> bool:
        """
        Remove a single IP from the whitelist.
        Returns True if removed, False if not found.
        Persists to YAML immediately.
        """
        try:
            canonical = str(ipaddress.ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP '{ip}': {exc}") from exc

        with self._lock:
            if canonical not in self._hosts:
                return False
            del self._hosts[canonical]
            self._save()
            logger.info("[Whitelist] Removed host %s", canonical)
            return True

    # ── Reload ────────────────────────────────────────────────────────────────

    def reload(self) -> dict:
        """
        Re-read ip_whitelist.yaml from disk without restarting the process.
        Called by POST /api/v1/firewall/whitelist/reload.
        Returns summary dict.
        """
        with self._lock:
            self._load()
            self._notify_ebpf()
        summary = {"networks": len(self._networks), "hosts": len(self._hosts)}
        logger.info("[Whitelist] Reloaded from disk: %s", summary)
        return summary

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load(self) -> None:
        """Parse YAML and populate in-memory structures. Called on init and reload."""
        self._networks = []
        self._hosts = {}

        if not self._path.exists():
            logger.warning(
                "[Whitelist] %s not found — whitelist is empty. "
                "Create the file or call add_network/add_host.",
                self._path,
            )
            return

        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        except Exception as exc:
            logger.error("[Whitelist] Failed to read %s: %s", self._path, exc)
            return

        wl = data.get("ip_whitelist", {})

        # Parse networks
        for entry in wl.get("networks", []) or []:
            cidr = entry.get("cidr", "")
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                self._networks.append((net, entry))
            except ValueError:
                logger.warning("[Whitelist] Skipping invalid CIDR '%s'", cidr)

        # Parse hosts
        for entry in wl.get("hosts", []) or []:
            ip_str = entry.get("ip", "")
            try:
                canonical = str(ipaddress.ip_address(ip_str))
                self._hosts[canonical] = entry
            except ValueError:
                logger.warning("[Whitelist] Skipping invalid host IP '%s'", ip_str)

        logger.info(
            "[Whitelist] Loaded %d networks, %d hosts from %s",
            len(self._networks), len(self._hosts), self._path,
        )

    def _save(self) -> None:
        """Serialise current state to YAML. Must be called while holding self._lock."""
        data = {
            "ip_whitelist": {
                "networks": [meta for _, meta in self._networks],
                "hosts":    list(self._hosts.values()),
            }
        }
        header = (
            "# ==============================================================================\n"
            "#  IP / CIDR Whitelist -- Auto-Block Exemptions\n"
            "#  AUTO-GENERATED by IPWhitelistManager -- do not edit while system is running.\n"
            "#  To add/remove entries use the API or edit this file then call /reload.\n"
            "# ==============================================================================\n\n"
        )
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".yaml.tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(header)
                yaml.dump(data, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
            tmp.replace(self._path)   # atomic rename
            self._notify_ebpf()
        except Exception as exc:
            logger.error("[Whitelist] Failed to save %s: %s", self._path, exc)

    def _notify_ebpf(self) -> None:
        """Helper to sync eBPF map if XDPEngine is running."""
        try:
            from system.core.framework.orchestrator import AppOrchestrator
            orch = AppOrchestrator.instance()
            if hasattr(orch, "xdp_engine") and orch.xdp_engine:
                orch.xdp_engine.sync_whitelist()
        except Exception:
            pass


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance: Optional[IPWhitelistManager] = None
_instance_lock = threading.Lock()


def get_whitelist_manager(yaml_path: Path = _DEFAULT_YAML) -> IPWhitelistManager:
    """Return (or create) the process-wide IPWhitelistManager singleton."""
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = IPWhitelistManager(yaml_path=yaml_path)
    return _instance
