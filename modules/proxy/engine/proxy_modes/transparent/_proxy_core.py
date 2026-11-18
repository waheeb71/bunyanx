#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MITMProxy core — thin orchestrator class.

Inherits behaviour from:
  RelayMixin      → _perform_mitm, _relay_data, _relay_http, …
  ConnectionMixin → handle_connection, handle_http_connection, …
  SecurityMixin   → _check_security_policy, _match_domain_pattern

This file is intentionally small (~220 lines).  All business logic lives in
the respective mixin modules.
"""
import ssl
import asyncio
import logging
from typing import Optional, Dict

from modules.ssl_inspection.engine.ca_pool import CAPoolManager
from system.core.framework.pipeline import InspectionPipeline
from system.core.utils.http_cloaker import HTTPCloaker
from system.core.path_manager import resolve_path
from modules.proxy.engine.context_builder import ContextBuilder
from modules.proxy.engine.inspection_bridge import InspectionBridge

from modules.proxy.engine.proxy_modes.transparent._types import ConnectionStats
from modules.proxy.engine.proxy_modes.transparent._tls_layer import TLSInterceptor
from modules.proxy.engine.proxy_modes.transparent._security_mixin import SecurityMixin
from modules.proxy.engine.proxy_modes.transparent._relay_mixin import RelayMixin
from modules.proxy.engine.proxy_modes.transparent._connection_mixin import ConnectionMixin

logger = logging.getLogger(__name__)


class MITMProxy(RelayMixin, ConnectionMixin, SecurityMixin):
    """
    Enterprise MITM Transparent Proxy.

    Composes RelayMixin, ConnectionMixin, SecurityMixin via multiple inheritance.
    MRO (left-to-right) ensures predictable method resolution with no conflicts.

    Lifecycle:
        proxy = MITMProxy(config, ca_manager, ...)
        await proxy.start()   # blocks until stop() is called
        await proxy.stop()
    """

    def __init__(
        self,
        config: dict,
        ca_manager: CAPoolManager,
        ebpf_manager=None,
        event_sink=None,
        inspection_pipeline: Optional[InspectionPipeline] = None,
    ):
        self.config           = config
        self.ca_manager       = ca_manager
        self.ebpf_manager     = ebpf_manager
        self.event_sink       = event_sink
        self.inspection_pipeline = inspection_pipeline

        from modules.ssl_inspection.engine.policy_engine import SSLPolicyEngine
        self.ssl_policy = SSLPolicyEngine(config, ebpf_manager, event_sink)

        self.proxy_config    = config.get('proxy', {})
        self.security_config = config.get('security', {})

        self.listen_host = self.proxy_config.get('listen_host', '0.0.0.0')
        self.listen_port = self.proxy_config.get('listen_port', 8443)
        self.http_port   = self.proxy_config.get('http_port', 8080)

        self.tls_interceptor   = TLSInterceptor(ca_manager, config)
        self.server_ssl_context = None
        self.vip_ssl_context    = None   # http/1.1-only ALPN — set below

        self.vips = self.proxy_config.get("vips", [])
        self.vips_table: Dict[tuple, dict] = {}

        for vip in self.vips:
            key = (vip.get("external_ip"), vip.get("external_port"))
            self.vips_table[key] = vip
            logger.info(
                "🛡️ VIP Registered: %s (%s:%s -> %s:%s)",
                vip.get('name'),
                vip.get('external_ip'), vip.get('external_port'),
                vip.get('internal_ip'), vip.get('internal_port'),
            )

        if self.config.get('proxy', {}).get('mode') == 'reverse_proxy' or self.vips:
            self.server_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls = self.config.get('tls', {})
            server_cert = resolve_path(tls.get('server_cert'))
            server_key  = resolve_path(tls.get('server_key'))
            cert_chain  = resolve_path(tls.get('cert_chain')) if tls.get('cert_chain') else None

            if server_cert and server_cert.exists():
                try:
                    self.server_ssl_context.load_cert_chain(str(server_cert), str(server_key))
                    if cert_chain and cert_chain.exists():
                        self.server_ssl_context.load_verify_locations(str(cert_chain))
                        logger.info("✅ Loaded certificate chain: %s", cert_chain)
                    self.server_ssl_context.set_alpn_protocols(
                        tls.get('alpn_protocols', ['h2', 'http/1.1'])
                    )
                    logger.info("✅ SSL Termination configured using %s", server_cert)

                    # VIP-specific context: forces http/1.1 ALPN only
                    # VIP backends (e.g., uvicorn) are HTTP/1.1-only.
                    # If server_ssl_context advertises h2, Chrome/Firefox negotiate
                    # HTTP/2 and send the PRI * HTTP/2.0 preface → 404 from backend.
                    self.vip_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    self.vip_ssl_context.load_cert_chain(str(server_cert), str(server_key))
                    if cert_chain and cert_chain.exists():
                        self.vip_ssl_context.load_verify_locations(str(cert_chain))
                    self.vip_ssl_context.set_alpn_protocols(['http/1.1'])
                    logger.info("✅ VIP SSL context ready (ALPN: http/1.1 only)")

                except Exception as e:
                    logger.error("❌ Failed to load SSL certificate chain: %s", e)
            else:
                logger.warning(
                    "⚠️ SSL server certificate not found at %s; "
                    "reverse proxy mode may exhibit limited TLS support.", server_cert,
                )

        # Hardening
        self.http_cloaker = HTTPCloaker(config)

        # Statistics
        self.stats: Dict[str, ConnectionStats] = {}
        self.total_connections  = 0
        self.active_connections = 0
        self.bytes_sent         = 0
        self.bytes_received     = 0

        # Running state
        self.running = False
        self.servers = []

        # Connection limiter — prevents DDoS exhaustion
        _max = self.proxy_config.get('max_connections', 10000)
        self._conn_semaphore = asyncio.Semaphore(_max)
        self._max_stats = 50000
        self._expired_hosts_cache: set = set()
        self.category_engine = None

        # Phase 10: unified context building and inspection bridge
        self._ctx_builder = ContextBuilder(config)
        _fail_open    = config.get("inspection", {}).get("fail_open", True)
        _auto_block_ttl = config.get("inspection", {}).get("auto_block_ttl", 10 * 60)
        self._inspection_bridge = (
            InspectionBridge(
                pipeline=inspection_pipeline,
                fail_open=_fail_open,
                event_sink=event_sink,
                auto_block_ttl=_auto_block_ttl,
            )
            if inspection_pipeline else None
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self):
        """Start HTTPS and HTTP proxy listeners."""
        logger.info("Starting Enterprise MITM Proxy...")
        self.running = True

        # HTTPS proxy
        https_server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
            ssl=self.server_ssl_context,
        )
        self.servers.append(https_server)
        addrs = ', '.join(str(sock.getsockname()) for sock in https_server.sockets)
        logger.info("🔒 HTTPS Proxy listening on %s", addrs)

        # HTTP proxy
        http_server = await asyncio.start_server(
            self.handle_http_connection,
            self.listen_host,
            self.http_port,
        )
        self.servers.append(http_server)
        addrs = ', '.join(str(sock.getsockname()) for sock in http_server.sockets)
        logger.info(" HTTP Proxy listening on %s", addrs)

        logger.info("✅ Enterprise MITM Proxy started successfully")
        logger.info(" Max connections: %s", self.proxy_config.get('max_connections', 10000))

        # Silence asyncio TLS noise and handle EMFILE/ENFILE open file descriptor limits
        from system.core.resource_limits import handle_emfile_resource_exhaustion

        def _loop_exception_handler(loop, context):
            exc = context.get("exception")
            msg = context.get("message", "")
            if exc or msg:
                handle_emfile_resource_exhaustion(exc or Exception(msg), "Transparent Proxy accept loop")
            if isinstance(exc, (ConnectionResetError, asyncio.IncompleteReadError)):
                logger.debug("[asyncio] TLS client reset (normal): %s", msg or exc)
                return
            if isinstance(exc, ssl.SSLError) and "HTTP_REQUEST" in str(exc):
                logger.debug("[asyncio] Plain HTTP request sent to SSL port: %s", msg or exc)
                return
            if "Task was destroyed" in msg or "Task was destroyed" in str(context):
                logger.debug("[asyncio] Pending task destroyed (normal on teardown): %s", msg)
                return
            if "eof_received" in msg or "handshake" in msg.lower() or "ssl protocol" in msg.lower():
                logger.debug("[asyncio] TLS handshake/protocol noise suppressed: %s", msg or exc)
                return
            loop.default_exception_handler(context)

        try:
            asyncio.get_event_loop().set_exception_handler(_loop_exception_handler)
        except Exception:
            pass

        for srv in self.servers:
            await srv.start_serving()
        logger.info("✅ All proxy listeners active — awaiting connections")

        await asyncio.gather(
            *[srv.serve_forever() for srv in self.servers],
            return_exceptions=True,
        )

    async def stop(self):
        """Stop proxy servers and cancel in-flight connection tasks."""
        logger.info("Stopping proxy servers...")
        self.running = False

        current = asyncio.current_task()
        pending = [
            t for t in asyncio.all_tasks()
            if t is not current
            and not t.done()
            and any(
                name in str(t)
                for name in (
                    "handle_connection", "handle_http_connection",
                    "_perform_mitm", "_guarded",
                )
            )
        ]
        if pending:
            logger.info("Cancelling %d in-flight proxy tasks before shutdown...", len(pending))
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            logger.info("In-flight proxy tasks cancelled.")

        for server in self.servers:
            server.close()
            await server.wait_closed()

        logger.info("Proxy servers stopped")

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_statistics(self) -> dict:
        """Return proxy statistics snapshot."""
        return {
            'total_connections':  self.total_connections,
            'active_connections': self.active_connections,
            'bytes_sent':         self.bytes_sent,
            'bytes_received':     self.bytes_received,
            'cached_certificates': len(self.ca_manager.cert_cache.cache),
        }
