#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS layer components:
  - TLSInterceptor  : creates SSL contexts for MITM and reverse-proxy modes.
  - _VIPSSLReader   : asyncio.StreamReader-compatible MemoryBIO decryption wrapper.
  - _VIPSSLWriter   : asyncio.StreamWriter-compatible MemoryBIO encryption wrapper.

These are kept separate so the heavy TLS logic can be read and tested in isolation,
without loading the entire MITMProxy class graph.
"""
import ssl
import asyncio
import logging

from modules.ssl_inspection.engine.ca_pool import CAPoolManager
from modules.ssl_inspection.engine.inspector import SSLInspector
from system.core.path_manager import resolve_path

logger = logging.getLogger(__name__)


# ── TLS Interceptor ───────────────────────────────────────────────────────────

class TLSInterceptor:
    """
    TLS/HTTPS Interceptor

    Handles SSL/TLS handshake interception, certificate generation,
    and delegates to SSLInspector to avoid temp files on the hot path.
    """

    def __init__(self, ca_manager: CAPoolManager, config: dict):
        self.ca_manager = ca_manager
        self.config = config
        self.tls_config = config.get('tls', {})
        self.inspector = SSLInspector(ca_manager, config)
        self.upstream_ssl_context = self.inspector.upstream_ssl_context

    def create_client_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """
        Create SSL context for client connection with dynamically generated certificate.

        Args:
            hostname: Target hostname for certificate generation

        Returns:
            SSL context with MITM certificate
        """
        if self.config["proxy"].get("mode") == "reverse_proxy":
            logger.info(f"Reverse proxy mode active - using server cert for {hostname}")
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                certfile=self.tls_config.get("server_cert"),
                keyfile=self.tls_config.get("server_key")
            )
            if self.tls_config.get("cert_chain"):
                context.load_verify_locations(self.tls_config.get("cert_chain"))
            context.set_alpn_protocols(self.tls_config.get('alpn_protocols', ['h2', 'http/1.1']))
            if self.tls_config.get('min_tls_version', 'TLSv1.2') == 'TLSv1.2':
                context.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            return context

        return self.inspector.create_client_ssl_context(hostname)


# ── VIP MemoryBIO stream wrappers ─────────────────────────────────────────────
# After TLS termination via MemoryBIO, these wrappers expose a plain-text
# asyncio API so _perform_mitm (and its full inspection pipeline: WAF, IDS,
# DLP …) sees decrypted HTTP as if the connection had arrived on a plain port.
# Without these, raw relay skips inspection → WAF cannot block injections.


class _VIPSSLReader:
    """
    asyncio.StreamReader-compatible wrapper backed by ssl.MemoryBIO.

    Decrypts incoming TLS bytes on-demand so callers can use the same
    readline / read / readuntil API as a plain asyncio.StreamReader.
    """
    __slots__ = ('_raw', '_ssl', '_in', '_buf', '_eof', '_ssl_mod')

    def __init__(self, raw_reader, ssl_obj, in_bio):
        self._raw    = raw_reader
        self._ssl    = ssl_obj
        self._in     = in_bio
        self._buf    = bytearray()
        self._eof    = False
        self._ssl_mod = ssl

    # -- internal helper -------------------------------------------------
    async def _fill(self):
        """Decrypt whatever is already in the BIO; fetch more if needed."""
        # 1. Drain already-decryptable data
        while True:
            try:
                chunk = self._ssl.read(65536)
                if chunk:
                    self._buf.extend(chunk)
                    return
                break
            except self._ssl_mod.SSLWantReadError:
                break
        if self._eof:
            return
        # 2. Fetch more encrypted bytes from network
        try:
            enc = await asyncio.wait_for(self._raw.read(65536), timeout=300)
        except asyncio.TimeoutError:
            self._eof = True
            return
        if not enc:
            self._eof = True
            return
        self._in.write(enc)
        # 3. Retry decryption
        while True:
            try:
                chunk = self._ssl.read(65536)
                if chunk:
                    self._buf.extend(chunk)
                else:
                    break
            except self._ssl_mod.SSLWantReadError:
                break

    # -- public API (asyncio.StreamReader-compatible) --------------------
    async def readline(self) -> bytes:
        while b'\n' not in self._buf and not self._eof:
            await self._fill()
        if not self._buf:
            return b''
        idx = self._buf.find(b'\n')
        if idx == -1:
            line, self._buf = bytes(self._buf), bytearray()
        else:
            line = bytes(self._buf[:idx + 1])
            del self._buf[:idx + 1]
        return line

    async def read(self, n: int = -1) -> bytes:
        if n == -1:
            # Read-all mode: drain until EOF
            while not self._eof:
                await self._fill()
            data, self._buf = bytes(self._buf), bytearray()
            return data
        # ── Partial-read mode (standard asyncio.StreamReader.read(n) semantics) ──
        # Return as soon as ANY data is available (up to n bytes).
        # DO NOT wait until self._buf >= n — that causes a deadlock because:
        #   - HTTP GET request ≈ 500 bytes, but caller often requests n=65536
        #   - Browser doesn't send more data until it gets a response
        #   - So waiting for 65536 bytes blocks forever
        if not self._buf and not self._eof:
            await self._fill()          # one fill — get whatever arrived
        if not self._buf:
            return b''
        take = min(n, len(self._buf))
        data = bytes(self._buf[:take])
        del self._buf[:take]
        return data


    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n and not self._eof:
            await self._fill()
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    async def readuntil(self, sep: bytes = b'\n') -> bytes:
        while sep not in self._buf and not self._eof:
            await self._fill()
        idx = self._buf.find(sep)
        if idx == -1:
            data, self._buf = bytes(self._buf), bytearray()
        else:
            end = idx + len(sep)
            data = bytes(self._buf[:end])
            del self._buf[:end]
        return data

    def at_eof(self) -> bool:
        return self._eof and not self._buf

    def feed_data(self, data: bytes):
        """Legacy compat used by some internal callers."""
        self._in.write(data)


class _VIPSSLWriter:
    """
    asyncio.StreamWriter-compatible wrapper backed by ssl.MemoryBIO.

    Encrypts outgoing plaintext bytes transparently before handing them
    to the underlying raw asyncio writer.
    """
    __slots__ = ('_raw', '_ssl', '_out')

    def __init__(self, raw_writer, ssl_obj, out_bio):
        self._raw = raw_writer
        self._ssl = ssl_obj
        self._out = out_bio

    def write(self, data: bytes):
        if data:
            self._ssl.write(data)
            enc = self._out.read()
            if enc:
                self._raw.write(enc)

    async def drain(self):
        await self._raw.drain()

    def is_closing(self) -> bool:
        return self._raw.is_closing()

    def close(self):
        self._raw.close()

    async def wait_closed(self):
        await self._raw.wait_closed()

    def get_extra_info(self, name, default=None):
        return self._raw.get_extra_info(name, default)

    @property
    def transport(self):
        return self._raw.transport
