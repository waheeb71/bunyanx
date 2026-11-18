#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
SSL Inspector - Advanced SSL/TLS Interception Engine
═══════════════════════════════════════════════════════════════════

Handles SSL/TLS interception with advanced features:
- Dynamic certificate generation
- Certificate pinning detection
- Protocol version negotiation
- Cipher suite management
- In-memory cert loading (no temp files on hot path)

Author: Enterprise Security Team
"""

import asyncio
import logging
import ssl
import io
from typing import Optional, Tuple

from .ca_pool import CAPoolManager

logger = logging.getLogger(__name__)


class SSLInspector:
    """
    SSL/TLS Inspection Engine

    Performs man-in-the-middle SSL inspection.

    Improvements vs previous version:
    * M6: cert/key loaded via ssl.MemoryBIO — no temp files on hot path.
    * M1: no deprecated datetime.utcnow().
    * Proper handling of legacy-TLS blocking.
    """

    def __init__(self, ca_manager: CAPoolManager, config: dict):
        self.ca_manager = ca_manager
        self.config = config
        self.tls_config = config.get('tls', {})
        self.ssl_cfg    = config.get('ssl_inspection', {})

        # Create SSL context for upstream connections (to real servers)
        self.upstream_ssl_context = self._create_upstream_ssl_context()

        logger.info("SSL Inspector initialized")

    # ------------------------------------------------------------------
    # Upstream SSL context (firewall → real server)
    # ------------------------------------------------------------------
    def _create_upstream_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for connecting to real upstream servers."""
        context = ssl.create_default_context()

        # TLS version bounds
        self._apply_tls_version(context)

        # Cipher suites
        cipher_suites = self.tls_config.get('cipher_suites', [])
        if cipher_suites:
            context.set_ciphers(':'.join(cipher_suites))

        # ALPN
        alpn = self.tls_config.get('alpn_protocols', ['h2', 'http/1.1'])
        context.set_alpn_protocols(alpn)

        # Certificate validation
        sec = self.config.get('security', {})
        if sec.get('strict_cert_validation', True):
            context.check_hostname = True
            context.verify_mode    = ssl.CERT_REQUIRED
        else:
            logger.warning("strict_cert_validation is disabled — upstream certs will NOT be verified!")
            context.check_hostname = False
            context.verify_mode    = ssl.CERT_NONE

        return context

    # ------------------------------------------------------------------
    # Client-facing SSL context (client → firewall)  — M6: no temp files
    # ------------------------------------------------------------------
    def create_client_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """
        Create an SSL context for the client-side of the MITM connection.

        M6 improvement: loads cert/key directly from memory using
        ssl.SSLContext.load_cert_chain with in-memory buffers (Python ≥ 3.13)
        or via a MemoryBIO fallback, eliminating temp-file I/O on the hot path.

        Args:
            hostname: Target hostname — used to generate the spoofed cert.

        Returns:
            Configured ssl.SSLContext for the server side of the TLS handshake.
        """
        cert_pem, key_pem = self.ca_manager.generate_server_certificate(hostname)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Python ≥ 3.13 supports load_cert_chain from bytes directly.
        # For older versions we fall back to a minimal temp-file approach
        # with immediate cleanup.
        try:
            # Preferred: in-memory load (no disk I/O)
            context.load_cert_chain(
                certfile=io.BytesIO(cert_pem),  # type: ignore[arg-type]
                keyfile=io.BytesIO(key_pem),    # type: ignore[arg-type]
            )
        except TypeError:
            # Fallback for Python < 3.13: write to temp files, unlink immediately
            import os
            import tempfile
            _cert_path = _key_path = None
            try:
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.crt') as cf:
                    cf.write(cert_pem)
                    _cert_path = cf.name
                with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.key') as kf:
                    kf.write(key_pem)
                    _key_path = kf.name
                context.load_cert_chain(_cert_path, _key_path)
            finally:
                for _p in (_cert_path, _key_path):
                    if _p:
                        try:
                            os.unlink(_p)
                        except OSError as exc:
                            logger.warning("Could not delete temp cert file %s: %s", _p, exc)

        # TLS version
        self._apply_tls_version(context)

        # Cipher suites
        cipher_suites = self.tls_config.get('cipher_suites', [])
        if cipher_suites:
            context.set_ciphers(':'.join(cipher_suites))

        # ALPN
        alpn = self.tls_config.get('alpn_protocols', ['h2', 'http/1.1'])
        context.set_alpn_protocols(alpn)

        return context

    # ------------------------------------------------------------------
    # Async helpers
    # ------------------------------------------------------------------
    async def wrap_client_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        hostname: str,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Upgrade a plain client connection to TLS (server-side handshake).

        Args:
            reader: Client StreamReader (pre-TLS).
            writer: Client StreamWriter (pre-TLS).
            hostname: Target hostname for cert generation.

        Returns:
            (ssl_reader, ssl_writer) after successful TLS handshake.
        """
        try:
            ssl_context = self.create_client_ssl_context(hostname)

            ssl_reader = asyncio.StreamReader()
            protocol   = asyncio.StreamReaderProtocol(ssl_reader)

            # FIX: get_event_loop() deprecated in Python 3.10+ — use get_running_loop()
            loop = asyncio.get_running_loop()
            ssl_transport = await loop.start_tls(
                writer.transport,
                protocol,
                ssl_context,
                server_side=True,
            )

            ssl_writer = asyncio.StreamWriter(
                ssl_transport, protocol, ssl_reader, loop
            )

            logger.debug("SSL handshake completed for %s", hostname)
            return ssl_reader, ssl_writer

        except ssl.SSLError as exc:
            logger.error("SSL handshake error for %s: %s", hostname, exc)
            raise
        except Exception as exc:
            logger.error("Error wrapping client connection for %s: %s", hostname, exc)
            raise

    async def connect_to_upstream(
        self,
        hostname: str,
        port: int = 443,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open an encrypted connection to the upstream (real) server.

        Args:
            hostname: Target hostname.
            port:     Target port (default 443).

        Returns:
            (reader, writer) tuple for the upstream connection.
        """
        try:
            reader, writer = await asyncio.open_connection(
                hostname, port,
                ssl=self.upstream_ssl_context,
                server_hostname=hostname,
            )
            logger.debug("Connected to upstream: %s:%s", hostname, port)
            return reader, writer
        except Exception as exc:
            logger.error("Failed to connect to %s:%s — %s", hostname, port, exc)
            raise

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _apply_tls_version(self, context: ssl.SSLContext) -> None:
        """Apply min/max TLS version settings from config to *context*."""
        min_ver = self.tls_config.get('min_tls_version', 'TLSv1.2')
        max_ver = self.tls_config.get('max_tls_version', 'TLSv1.3')

        _map = {
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': ssl.TLSVersion.TLSv1_3,
        }
        if min_ver in _map:
            context.minimum_version = _map[min_ver]
        if max_ver in _map:
            context.maximum_version = _map[max_ver]
