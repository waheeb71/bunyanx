#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSL/TLS Inspection Engine Package
══════════════════════════════════
Exports:
    CAPoolManager   — PKI / certificate authority management
    SSLInspector    — TLS interception engine
    SSLPolicyEngine — Bypass / inspect / block decision logic
    SSLAction       — Enum of possible policy outcomes
    extract_sni     — Parse SNI from raw TLS ClientHello bytes
    SNIRouter       — Route connections based on SNI

Author: Enterprise Security Team
"""

from .ca_pool       import CAPoolManager
from .inspector     import SSLInspector
from .policy_engine import SSLPolicyEngine, SSLAction
from .sni_router    import extract_sni, SNIRouter

__all__ = [
    "CAPoolManager",
    "SSLInspector",
    "SSLPolicyEngine",
    "SSLAction",
    "extract_sni",
    "SNIRouter",
]
