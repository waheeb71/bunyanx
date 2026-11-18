#!/usr/bin/env python3
"""
system/networking/sni_utils.py
================================
Pure networking utility: extract the Server Name Indication (SNI) from a raw
TLS ClientHello record without any dependency on the ssl_inspection module.

This function belongs here (system/networking) rather than in
modules/ssl_inspection because core system routing must be able to parse SNI
regardless of whether the ssl_inspection module is enabled or installed.

Architecture note
-----------------
system/core/router/utils.py uses this function to make routing decisions.
modules/ssl_inspection/engine/sni_router.py now imports from here so there
is a single implementation. All callers should use this path:

    from system.networking.sni_utils import extract_sni
"""

import re
import struct
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# RFC 1035 / 5891 — basic hostname character set
_VALID_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9\-.*]+$")
_MAX_SNI_LEN = 253


def extract_sni(data: bytes) -> Optional[str]:
    """
    Extract Server Name Indication (SNI) from a raw TLS ClientHello record.

    Args:
        data: Raw bytes starting from the first byte of the TLS record.

    Returns:
        Decoded hostname string, or None if not present / unparseable.
    """
    try:
        # ── TLS record header: content_type(1) + version(2) + length(2) ──
        if len(data) < 5:
            return None
        if data[0] != 0x16:          # Not a Handshake record
            return None

        pos = 5

        # ── Handshake header: msg_type(1) + length(3) ─────────────────
        if len(data) < pos + 4:
            return None
        if data[pos] != 0x01:        # Not a ClientHello
            return None
        pos += 4

        # ── ClientHello body ───────────────────────────────────────────
        # client_version (2)
        if len(data) < pos + 2:
            return None
        pos += 2

        # random (32)
        if len(data) < pos + 32:
            return None
        pos += 32

        # session_id length (1) + session_id
        if len(data) < pos + 1:
            return None
        pos += 1 + data[pos]

        # cipher_suites length (2) + cipher_suites
        if len(data) < pos + 2:
            return None
        cs_len = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2 + cs_len

        # compression_methods length (1) + methods
        if len(data) < pos + 1:
            return None
        pos += 1 + data[pos]

        # ── Extensions ────────────────────────────────────────────────
        if len(data) < pos + 2:
            return None
        ext_total_len = struct.unpack('>H', data[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total_len

        while pos < ext_end and pos < len(data):
            if len(data) < pos + 4:
                break

            ext_type   = struct.unpack('>H', data[pos:pos + 2])[0]
            ext_length = struct.unpack('>H', data[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0:        # SNI extension
                if len(data) < pos + ext_length:
                    break

                sni_data = data[pos:pos + ext_length]
                hostname = _parse_sni_extension(sni_data)
                if hostname:
                    return hostname

            pos += ext_length

        return None

    except Exception as exc:
        logger.warning("SNI parse error — malformed ClientHello: %s", exc)
        return None


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
    pos = 2
    name_type = sni_data[pos]
    if name_type != 0:               # Only host_name (0) is defined
        return None
    pos += 1

    if len(sni_data) < pos + 2:
        return None
    name_len = struct.unpack('>H', sni_data[pos:pos + 2])[0]
    pos += 2

    if len(sni_data) < pos + name_len:
        return None

    try:
        hostname = sni_data[pos:pos + name_len].decode('ascii').strip().lower()
    except (UnicodeDecodeError, ValueError):
        return None

    if not hostname or len(hostname) > _MAX_SNI_LEN:
        return None
    if not _VALID_HOSTNAME_RE.match(hostname):
        logger.warning("SNI contains invalid characters — discarding: %r", hostname)
        return None

    return hostname
