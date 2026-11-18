#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backward-compatible facade for transparent proxy.

The full implementation has been split into focused modules under
  modules/proxy/engine/proxy_modes/transparent/

  _types.py            → ConnectionStats dataclass
  _tls_layer.py        → TLSInterceptor + _VIPSSLReader + _VIPSSLWriter
  _security_mixin.py   → _check_security_policy, _match_domain_pattern
  _relay_mixin.py      → _perform_mitm, _relay_data, _relay_http, …
  _connection_mixin.py → handle_connection, handle_http_connection, …
  _proxy_core.py       → MITMProxy (slim orchestrator)
  __init__.py          → re-exports MITMProxy

Any existing code that does:
    from modules.proxy.engine.proxy_modes.transparent_proxy import MITMProxy
continues to work without modification.
"""
from modules.proxy.engine.proxy_modes.transparent._proxy_core import MITMProxy  # noqa: F401
from modules.proxy.engine.proxy_modes.transparent._tls_layer import (  # noqa: F401
    TLSInterceptor,
    _VIPSSLReader,
    _VIPSSLWriter,
)
from modules.proxy.engine.proxy_modes.transparent._types import ConnectionStats  # noqa: F401

__all__ = [
    'MITMProxy',
    'TLSInterceptor',
    '_VIPSSLReader',
    '_VIPSSLWriter',
    'ConnectionStats',
]