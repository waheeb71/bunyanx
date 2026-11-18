"""
bunyanx NGFW — DLP Settings Loader
======================================
REM-11 FIX: settings.yaml was present in the repository but never imported
or read by any Python module. This loader:

  1. Reads ``modules/dlp/config/settings.yaml`` at import time.
  2. Resolves ``${ENV_VAR}`` placeholders using os.environ.
  3. Exposes ``get_dlp_settings()`` for diagnostic endpoints.
  4. Exposes individual helpers used by the DLP engine to honour
     ``max_payload_bytes`` and ``log_rotation_days`` from the file
     rather than burying them as magic numbers in code.

Design decision
---------------
Database-driven values (weights, thresholds, enabled flags) remain in the
DB and take precedence over YAML.  The YAML governs **deployment-time**
values that shouldn't change per-request:

  - model_path, training_log, feedback_db paths
  - max_payload_bytes (hard limit on regex/BEFP input)
  - log_rotation_days
  - mode (monitor | enforce)
"""

from __future__ import annotations

import os
import re
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Path to the YAML file (relative to this loader)
_SETTINGS_PATH = Path(__file__).parent / "settings.yaml"

# Regex to match ${VAR_NAME} placeholders
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")


def _resolve_env(value: str) -> str:
    """Replace ${ENV_VAR} tokens with their os.environ values."""
    def _replace(m: re.Match) -> str:
        var = m.group(1)
        resolved = os.environ.get(var, "")
        if not resolved:
            logger.warning(
                "[DLP][Settings] Env var '%s' referenced in settings.yaml is not set.", var
            )
        return resolved
    return _ENV_PLACEHOLDER.sub(_replace, value)


def _resolve_dict(d: Any) -> Any:
    """Recursively resolve ${} placeholders in all string values of a dict."""
    if isinstance(d, dict):
        return {k: _resolve_dict(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_resolve_dict(i) for i in d]
    if isinstance(d, str):
        return _resolve_env(d)
    return d


@lru_cache(maxsize=1)
def _load_raw() -> Dict[str, Any]:
    """
    Load and parse settings.yaml exactly once (cached).
    Falls back to safe defaults if the file is missing or unparseable.
    """
    defaults: Dict[str, Any] = {
        "dlp": {
            "enabled": True,
            "mode": "enforce",
            "model_path": "",
            "training_log": "",
            "feedback_db": "",
            "weights_config": "",
            "max_payload_bytes": 65536,
            "max_scan_chunk_bytes": 102400,
            "max_extracted_text_bytes": 2097152,
            "log_rotation_days": 30,
        }
    }

    if not _SETTINGS_PATH.exists():
        logger.warning(
            "[DLP][Settings] settings.yaml not found at %s — using built-in defaults.",
            _SETTINGS_PATH,
        )
        return defaults

    try:
        import yaml   # PyYAML — standard dep in most Python environments
    except ImportError:
        logger.error(
            "[DLP][Settings] PyYAML not installed. Cannot load settings.yaml. "
            "Install with: pip install pyyaml"
        )
        return defaults

    try:
        with open(_SETTINGS_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        # Merge defaults with file content (file wins)
        merged = {**defaults}
        if "dlp" in raw:
            merged["dlp"] = {**defaults["dlp"], **raw["dlp"]}
        resolved = _resolve_dict(merged)
        logger.info("[DLP][Settings] Loaded settings.yaml from %s", _SETTINGS_PATH)
        return resolved
    except Exception as e:
        logger.error(
            "[DLP][Settings] Failed to parse settings.yaml: %s — using defaults.", e
        )
        return defaults


def get_dlp_settings() -> Dict[str, Any]:
    """Return the fully resolved DLP settings dict (cached after first load)."""
    return _load_raw().get("dlp", {})


def get_max_payload_bytes() -> int:
    """Hard upper limit on DLP regex/BEFP input size (bytes)."""
    return int(get_dlp_settings().get("max_payload_bytes", 65536))


def get_max_scan_chunk_bytes() -> int:
    """Maximum chunk size (bytes) for regex scanning."""
    return int(get_dlp_settings().get("max_scan_chunk_bytes", 102400))


def get_max_extracted_text_bytes() -> int:
    """Maximum text size (bytes) extracted per payload."""
    return int(get_dlp_settings().get("max_extracted_text_bytes", 2097152))


def get_log_rotation_days() -> int:
    """Number of days before log files are rotated/archived."""
    return int(get_dlp_settings().get("log_rotation_days", 30))


def get_dlp_mode() -> str:
    """Operational mode: 'monitor' (alert only) or 'enforce' (block)."""
    return str(get_dlp_settings().get("mode", "enforce")).lower()

