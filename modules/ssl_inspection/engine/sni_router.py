#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SNI Router - Server Name Indication Parser & Router
═══════════════════════════════════════════════════════════════════

Extracts SNI (Server Name Indication) from TLS ClientHello packets
and provides domain-based routing decisions.

Improvements:
- Validates decoded hostname (no empty strings / control chars).
- Logs malformed packets at WARNING (not only DEBUG) for visibility.
- `get_backend_for_sni` uses pre-compiled wildcard matching.

Author: Enterprise Security Team
"""

import re
import struct
import logging
from typing import Optional, Pattern, Dict, Tuple

# ── Single implementation lives in system/networking/sni_utils.py ──────────
# Imported here for backward-compatibility so callers using
# `from modules.ssl_inspection.engine.sni_router import extract_sni`
# continue to work without changes.
try:
    from system.networking.sni_utils import extract_sni, _parse_sni_extension  # noqa: F401
except ImportError:
    # Fallback implementation if system module is unavailable
    def extract_sni(data: bytes) -> Optional[str]:
        """
        Extract Server Name Indication (SNI) from a raw TLS ClientHello record.
        """
        try:
            if len(data) < 5 or data[0] != 0x16:
                return None
            pos = 5
            if len(data) < pos + 4 or data[pos] != 0x01:
                return None
            pos += 4
            if len(data) < pos + 34:  # client_version(2) + random(32)
                return None
            pos += 34
            if len(data) < pos + 1:
                return None
            pos += 1 + data[pos]  # session_id
            if len(data) < pos + 2:
                return None
            cs_len = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += 2 + cs_len  # cipher_suites
            if len(data) < pos + 1:
                return None
            pos += 1 + data[pos]  # compression_methods
            if len(data) < pos + 2:
                return None
            ext_total_len = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_total_len
            while pos < ext_end and pos < len(data):
                if len(data) < pos + 4:
                    break
                ext_type = struct.unpack('>H', data[pos:pos + 2])[0]
                ext_length = struct.unpack('>H', data[pos + 2:pos + 4])[0]
                pos += 4
                if ext_type == 0:  # SNI extension
                    if len(data) < pos + ext_length:
                        break
                    return _parse_sni_extension(data[pos:pos + ext_length])
                pos += ext_length
            return None
        except Exception as exc:
            logger.warning("SNI parse error — malformed ClientHello: %s", exc)
            return None

logger = logging.getLogger(__name__)

# RFC 1035 / 5891 — basic hostname character set
_VALID_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9\-.*]+$")
_MAX_SNI_LEN = 253



def _parse_sni_extension(sni_data: bytes) -> Optional[str]:
    """
    Parse the SNI extension payload (RFC 6066 §3).

    Structure:
        ServerNameList length (2)
        NameType (1)  — 0 = host_name
        HostName length (2)
        HostName bytes
    """
    if len(sni_data) < 5:
        return None

    # sni_list_length (2) — we parse only the first name entry
    sni_pos = 2
    name_type = sni_data[sni_pos]

    if name_type != 0:               # Only host_name (0) is defined
        return None

    sni_pos += 1
    if len(sni_data) < sni_pos + 2:
        return None

    name_len = struct.unpack('>H', sni_data[sni_pos:sni_pos + 2])[0]
    sni_pos += 2

    if len(sni_data) < sni_pos + name_len:
        return None

    raw_hostname = sni_data[sni_pos:sni_pos + name_len]

    try:
        hostname = raw_hostname.decode('ascii').strip().lower()
    except UnicodeDecodeError:
        logger.warning("SNI hostname contained non-ASCII bytes — rejected")
        return None

    # Validate decoded hostname
    if not hostname:
        return None
    if len(hostname) > _MAX_SNI_LEN:
        logger.warning("SNI hostname exceeds max length (%d chars) — rejected", len(hostname))
        return None
    if not _VALID_HOSTNAME_RE.match(hostname):
        logger.warning("SNI hostname has invalid characters — rejected: %r", hostname)
        return None

    return hostname


# ---------------------------------------------------------------------------
# SNI-based router
# ---------------------------------------------------------------------------
class SNIRouter:
    """
    Routes connections to different backends based on SNI hostname.

    Routing rules are sourced from config['sni_routing'] and support
    exact matches and wildcard patterns (e.g., '*.example.com').
    """

    def __init__(self, config: dict):
        self.config = config
        raw_rules: Dict[str, dict] = config.get('sni_routing', {})

        # Pre-compile wildcard patterns for O(n) linear scan
        # Each entry: (compiled_pattern, original_key, backend_dict)
        self._rules: list = []
        for pattern, backend in raw_rules.items():
            try:
                escaped   = re.escape(pattern)
                safe_re   = escaped.replace(r"\*", r"[^.]*")
                compiled  = re.compile(f"^{safe_re}$", re.IGNORECASE)
                self._rules.append((compiled, pattern, backend))
            except re.error as exc:
                logger.warning("Invalid SNI routing pattern %r — skipping: %s", pattern, exc)

        logger.info("SNI Router initialized with %d rules", len(self._rules))

    def get_backend_for_sni(self, sni: str) -> Optional[dict]:
        """
        Return the backend configuration dict for the given SNI hostname.

        Matching priority:
          1. Exact match
          2. First matching wildcard pattern

        Args:
            sni: Decoded hostname from the ClientHello.

        Returns:
            Backend config dict, or None if no rule matches.
        """
        sni_lower = sni.lower()
        for compiled, _original, backend in self._rules:
            if compiled.match(sni_lower):
                return backend
        return None
