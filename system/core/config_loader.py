"""
BunyanX NGFW — Unified Config Loader
======================================
Single interface for reading shared settings from system/config/settings.yaml.

Modules MUST use this class instead of hardcoding values or reading base.yaml
directly. This ensures all shared values come from one source of truth.

Usage:
    from system.core.config_loader import ConfigLoader

    # Get internal networks as ipaddress.ip_network objects
    nets = ConfigLoader.get_internal_networks()

    # Get inspection settings dict
    settings = ConfigLoader.get_inspection_settings()
    threshold = settings["internal_block_threshold"]  # 0.80

    # Check if an IP is internal
    if ConfigLoader.is_internal(src_ip):
        ...

Design:
  - Lazy loading: settings.yaml is loaded on first access, then cached.
  - Thread-safe: uses a module-level lock for initialization.
  - Graceful fallback: if settings.yaml is missing, hardcoded defaults apply.
  - ConfigLoader also merges base.yaml values for backward compatibility.
"""

import ipaddress
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# ── Module-level cache ────────────────────────────────────────────────────────
_lock = threading.Lock()
_cache: Optional[Dict[str, Any]] = None

# Resolved path to settings.yaml
_SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.yaml"

# ── Defaults (used if settings.yaml is missing or incomplete) ─────────────────
_DEFAULTS = {
    "ngfw": {
        "name": "BunyanX Enterprise NGFW",
        "version": "3.0",
        "environment": "production",
    },
    "network": {
        "wan_ip": "",
        "lan_ip": "",
        "internal_networks": [
            "10.0.0.0/8",
            "172.16.0.0/12",
        ],
        "trusted_ips": [],
    },
    "inspection": {
        "fail_open": False,
        "max_pipeline_time_ms": 500,
        "internal_block_threshold": 0.80,
        "fast_path_on_block": True,
    },
}


def _load() -> Dict[str, Any]:
    """Load settings.yaml with defaults fallback. Not thread-safe — caller locks."""
    global _cache
    if _cache is not None:
        return _cache

    result: Dict[str, Any] = _deep_merge({}, _DEFAULTS)

    if _SETTINGS_PATH.exists():
        try:
            with open(_SETTINGS_PATH, "r", encoding="utf-8") as f:
                from_file = yaml.safe_load(f) or {}
            result = _deep_merge(result, from_file)
            logger.info("[ConfigLoader] Loaded settings from %s", _SETTINGS_PATH)
        except Exception as exc:
            logger.warning(
                "[ConfigLoader] Could not load %s: %s — using defaults",
                _SETTINGS_PATH, exc,
            )
    else:
        logger.info(
            "[ConfigLoader] %s not found — using built-in defaults", _SETTINGS_PATH
        )

    _cache = result
    return result


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base. Override wins on conflicts."""
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _get() -> Dict[str, Any]:
    """Thread-safe singleton loader."""
    global _cache
    if _cache is None:
        with _lock:
            if _cache is None:
                _load()
    return _cache


class ConfigLoader:
    """
    Static interface for reading shared BunyanX settings.

    All methods are class methods — no instantiation needed.
    """

    @classmethod
    def reload(cls) -> None:
        """Force reload from disk (useful after config changes or in tests)."""
        global _cache
        with _lock:
            _cache = None
        _get()
        logger.info("[ConfigLoader] Settings reloaded from %s", _SETTINGS_PATH)

    # ── Network ───────────────────────────────────────────────────────────────

    @classmethod
    def get_internal_networks(cls) -> List[ipaddress.IPv4Network]:
        """
        Return internal networks as ipaddress.ip_network objects.

        Used by:
          - ContextBuilder (tag "internal")
          - PHANTOM/IDS-IPS (apply internal_block_threshold)
          - Firewall (allow internal traffic)
        """
        raw = _get().get("network", {}).get("internal_networks", [])
        nets = []
        for entry in raw:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                logger.warning("[ConfigLoader] Invalid network %r: %s", entry, exc)
        return nets

    @classmethod
    def get_internal_networks_raw(cls) -> List[str]:
        """Return internal networks as raw CIDR strings."""
        return list(_get().get("network", {}).get("internal_networks", []))

    @classmethod
    def get_trusted_ips(cls) -> List[str]:
        """Return list of trusted IP strings."""
        return list(_get().get("network", {}).get("trusted_ips", []))

    @classmethod
    def is_internal(cls, ip: str) -> bool:
        """Return True if ip falls within any internal network."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in cls.get_internal_networks())
        except ValueError:
            return False

    @classmethod
    def is_trusted(cls, ip: str) -> bool:
        """Return True if ip is in the trusted_ips list."""
        return ip in cls.get_trusted_ips()

    # ── Inspection ────────────────────────────────────────────────────────────

    @classmethod
    def get_inspection_settings(cls) -> Dict[str, Any]:
        """
        Return inspection policy settings dict.

        Keys:
          fail_open (bool):                  Allow on pipeline error?
          max_pipeline_time_ms (int):        Max total inspection time
          internal_block_threshold (float):  Confidence needed to block internal
          fast_path_on_block (bool):         Break pipeline on first BLOCK?

        Used by:
          - InspectionBridge (fail_open)
          - InspectionPipeline (max_pipeline_time_ms)
          - PHANTOM/IDS-IPS (internal_block_threshold)
          - UBA (internal_block_threshold)
        """
        defaults = _DEFAULTS["inspection"]
        raw = _get().get("inspection", {})
        return {**defaults, **raw}

    @classmethod
    def get_internal_block_threshold(cls) -> float:
        """Return the confidence threshold for blocking internal sources."""
        return float(
            cls.get_inspection_settings().get("internal_block_threshold", 0.80)
        )

    @classmethod
    def get_fail_open(cls) -> bool:
        """Return True if pipeline should allow traffic on errors."""
        return bool(cls.get_inspection_settings().get("fail_open", False))

    @classmethod
    def get_max_pipeline_time_ms(cls) -> int:
        """Return max inspection pipeline time in milliseconds (supports both max_pipeline_time_ms and max_processing_time_ms)."""
        settings = cls.get_inspection_settings()
        val = settings.get("max_pipeline_time_ms") or settings.get("max_processing_time_ms") or 5000
        return int(val)

    @classmethod
    def get_fast_path_on_block(cls) -> bool:
        """Return True if pipeline should break on first BLOCK verdict."""
        return bool(cls.get_inspection_settings().get("fast_path_on_block", True))

    # ── General ───────────────────────────────────────────────────────────────

    @classmethod
    def get_ngfw_info(cls) -> Dict[str, str]:
        """Return ngfw name, version, environment."""
        return dict(_get().get("ngfw", {}))

    @classmethod
    def get_raw(cls) -> Dict[str, Any]:
        """Return the full settings dict (read-only copy)."""
        return dict(_get())
