#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Reverse Proxy - Web Application Protection Mode
═══════════════════════════════════════════════════════════════════

Reverse proxy mode for protecting web servers/applications.
Features:
- SSL termination at proxy
- Load balancing (future)
- Web Application Firewall (WAF) integration
- DDoS protection

Author: Enterprise Security Team
"""

import asyncio
import logging
import ssl
import ipaddress
from typing import Optional, List
from .base_proxy import BaseProxy, ProxyConnection
from system.core.path_manager import resolve_path

logger = logging.getLogger(__name__)

# ── Lazy inspection helpers ─────────────────────────────────────────────────

def _build_inspection_ctx(client_ip: str, client_port: int,
                          backend_host: str, backend_port: int,
                          protocol: str, raw_data: bytes = b"",
                          vip_name: str = ""):
    """Build an InspectionContext for a reverse-proxy connection."""
    import uuid
    try:
        from system.core.inspection_context import InspectionContext
        from modules.proxy.engine.http_parser import HttpRequestParser

        flow_id = f"rev-{client_ip}-{client_port}-{uuid.uuid4().hex[:8]}"
        ctx = InspectionContext(
            src_ip=client_ip,
            src_port=client_port,
            dst_ip=backend_host,
            dst_port=backend_port,
            protocol=protocol,
            direction="inbound",
            flow_id=flow_id,
        )
        ctx.metadata = {"vip_name": vip_name, "proxy_mode": "reverse"}

        # Enrich with HTTP details if we have payload
        if raw_data:
            try:
                scheme = "https" if protocol == "HTTPS" else "http"
                parser = HttpRequestParser()
                http_info = parser.parse_from_bytes(raw_data, scheme=scheme)
                if http_info:
                    ctx.http = http_info
            except Exception:
                pass
        return ctx
    except Exception:
        return None


async def _run_pipeline_check(pipeline, ctx, client_writer) -> bool:
    """
    Run the inspection pipeline on *ctx*.
    Returns True if traffic is ALLOWED, False if BLOCKED/DROPPED.
    Sends a 403 response to the client writer when blocked.
    """
    if pipeline is None or ctx is None:
        return True
    try:
        from system.core.framework.pipeline import InspectionAction
        result = await pipeline.inspect_async(ctx, b"")
        if result.action in (InspectionAction.BLOCK, InspectionAction.DROP):
            logger.warning(
                "[ReverseProxy] BLOCKED %s → %s:%s | action=%s | findings=%d | plugins: %s",
                ctx.src_ip, ctx.dst_ip, ctx.dst_port,
                result.action.name,
                len(result.findings),
                ", ".join(f.plugin_name for f in result.findings[:3]),
            )
            try:
                block_resp = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 63\r\n"
                    b"Connection: close\r\n\r\n"
                    b"<html><body><h1>403 Forbidden</h1><p>Blocked by NGFW.</p></body></html>"
                )
                client_writer.write(block_resp)
                await client_writer.drain()
            except Exception:
                pass
            return False
        if result.action in (InspectionAction.REDIRECT_DECOY, InspectionAction.QUARANTINE):
            logger.info("[ReverseProxy] DECEPTION/QUARANTINE triggered -> Blocking connection with 403 Decoy")
            try:
                block_resp = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 72\r\n"
                    b"Connection: close\r\n\r\n"
                    b"<html><body><h1>403 Access Denied</h1><p>Honeytoken Triggered.</p></body></html>"
                )
                client_writer.write(block_resp)
                await client_writer.drain()
            except Exception:
                pass
            return False
        return True
    except Exception as exc:
        logger.warning("[ReverseProxy] pipeline check failed (fail-open): %s", exc)
        return True  # fail-open




class ReverseProxy(BaseProxy):
    """
    Reverse Proxy Implementation

    Terminates SSL at proxy and forwards to backend servers.
    Supports VIP routing: reads proxy.vips from config and routes
    each incoming connection to the correct internal backend based
    on SO_ORIGINAL_DST (original destination before nftables redirect).
    """

    # Linux kernel constant — retrieve original dst from iptables/nftables REDIRECT
    SO_ORIGINAL_DST = 80

    def __init__(self, config: dict, ca_manager, flow_tracker=None, event_sink=None, inspection_pipeline=None):
        super().__init__(config, inspection_pipeline=inspection_pipeline, event_sink=event_sink)
        self.ca_manager = ca_manager
        self.flow_tracker = flow_tracker

        self.listen_host = self.proxy_config.get('reverse_listen_host', '0.0.0.0')
        self.listen_port = self.proxy_config.get('reverse_listen_port', 443)
        self.http_port   = self.proxy_config.get('reverse_http_port', 80)
        self.http_enabled = self.proxy_config.get('reverse_http_enabled', True)

        # Connection limiter — prevents DDoS exhaustion
        max_conns = self.proxy_config.get('max_connections', 10000)
        self._conn_semaphore = asyncio.Semaphore(max_conns)
        self._active_conn_count = 0   # explicit counter (avoid private ._value)
        self._max_connections = max_conns

        # ── VIP routing table (external_ip, external_port) → vip_config ──────
        # Populated from proxy.vips in base.yaml.
        # When a connection arrives, SO_ORIGINAL_DST is read to get the
        # original destination before nftables redirect, then matched here.
        self.vips_table: dict = {}
        for vip in self.proxy_config.get('vips', []):
            key = (vip.get('external_ip'), int(vip.get('external_port', 80)))
            self.vips_table[key] = vip
            logger.info(
                "🛡️ ReverseProxy VIP: %s  %s:%s → %s:%s",
                vip.get('name', ''), key[0], key[1],
                vip.get('internal_ip'), vip.get('internal_port'),
            )

        # ── Generic backend pool (used when no VIP matches) ──────────────────
        raw_backends = self.proxy_config.get('backends', [])
        # Auto-derive backends from VIPs if no explicit backends list
        if not raw_backends and self.vips_table:
            raw_backends = [
                {'host': v.get('internal_ip'), 'port': int(v.get('internal_port', 8080)),
                 'ssl': v.get('use_tls_upstream', False)}
                for v in self.proxy_config.get('vips', [])
            ]
        self.backends = raw_backends or [{'host': 'localhost', 'port': 8080}]
        self.current_backend = 0

        # Health tracking per backend
        self.health_state: dict = {i: True for i in range(len(self.backends))}
        self.active_conns: dict = {i: 0     for i in range(len(self.backends))}
        self._health_task = None
        self._health_interval = self.proxy_config.get('health_check_interval', 10)
        self._health_timeout  = self.proxy_config.get('health_check_timeout',  6)

        # SSL context for client connections
        self.ssl_context = self._create_ssl_context()

        # Whether to verify backend TLS certificates (default: True for security)
        self._verify_backend_tls = self.proxy_config.get('verify_backend_tls', True)

        logger.info(
            "Reverse Proxy configured — %s:%s (HTTP:%s) | %d VIPs | %d backends | max_conns=%d",
            self.listen_host, self.listen_port,
            self.http_port if self.http_enabled else 'off',
            len(self.vips_table), len(self.backends), max_conns,
        )
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for accepting client connections"""
        tls_config = self.config.get('tls', {})
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load server certificate
        cert_file = str(resolve_path(tls_config.get('server_cert', 'certs/server.crt')))
        key_file = str(resolve_path(tls_config.get('server_key', 'certs/server.key')))
        
        try:
            context.load_cert_chain(cert_file, key_file)
            logger.info(f"Loaded SSL certificate: {cert_file}")
        except (FileNotFoundError, ssl.SSLError) as e:
            logger.warning(f"SSL certificate not found or invalid: {e}")
            logger.warning("Auto-generating self-signed certificate for testing...")
            self._generate_self_signed_cert(cert_file, key_file)
            try:
                context.load_cert_chain(cert_file, key_file)
                logger.info("✅ Self-signed certificate loaded")
            except Exception as e2:
                logger.error(f"Failed to load generated cert: {e2}")
        
        # Configure TLS versions
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # ALPN: only http/1.1 — we relay raw TCP, not HTTP/2 frames
        context.set_alpn_protocols(['http/1.1'])
        
        return context
    
    def _generate_self_signed_cert(self, cert_file: str, key_file: str):
        """Generate a self-signed certificate for testing.
        Includes all VIP external_ips in the SANs so browsers don't
        reject with ERR_SSL_PROTOCOL_ERROR due to IP mismatch.
        """
        import os, ipaddress as _ipmod
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        # Create directories if needed
        os.makedirs(os.path.dirname(cert_file), exist_ok=True)
        os.makedirs(os.path.dirname(key_file), exist_ok=True)

        # Generate key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Generate cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "bunyanx NGFW Reverse Proxy"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enterprise bunyanx NGFW"),
        ])

        # ── Collect all VIP external IPs + well-known defaults ──────────────
        _ip_set: list[x509.IPAddress] = []
        _seen: set = set()
        _defaults = ["127.0.0.1", "192.168.10.1", "192.168.20.1"]

        # Add every VIP external IP from config
        for _vip in self.proxy_config.get("vips", []):
            _ext_ip = _vip.get("external_ip", "")
            if _ext_ip and _ext_ip not in _seen:
                try:
                    _ip_set.append(x509.IPAddress(_ipmod.IPv4Address(_ext_ip)))
                    _seen.add(_ext_ip)
                except ValueError:
                    pass

        # Fallback defaults
        for _ip in _defaults:
            if _ip not in _seen:
                try:
                    _ip_set.append(x509.IPAddress(_ipmod.IPv4Address(_ip)))
                    _seen.add(_ip)
                except ValueError:
                    pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=730)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"), x509.DNSName("bunyanx.local")]
                    + _ip_set
                ),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )

        # Write key
        with open(key_file, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Write cert
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        logger.info(
            "Generated self-signed cert: %s | IP SANs: %s",
            cert_file, [str(i) for i in _seen]
        )
    
    async def start(self):
        """Start reverse proxy server"""
        logger.info("Starting Reverse Proxy...")
        self.running = True

        # Launch background health-check loop before serving traffic
        self._health_task = asyncio.create_task(
            self._health_check_loop(),
            name="reverse-proxy-health-check"
        )

        # Start HTTPS server
        server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port,
            ssl=self.ssl_context
        )
        self.servers.append(server)

        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info("Reverse Proxy (HTTPS) listening on %s", addrs)

        # Start HTTP server if enabled
        if self.http_enabled:
            http_server = await asyncio.start_server(
                self.handle_http_connection,
                self.listen_host,
                self.http_port
            )
            self.servers.append(http_server)
            addrs_http = ', '.join(str(sock.getsockname()) for sock in http_server.sockets)
            logger.info("Reverse Proxy (HTTP) listening on %s", addrs_http)

        # serve_forever() calls start_serving() internally — no need to call it separately.
        logger.info("✅ Reverse Proxy listeners active")
        await asyncio.gather(
            *[srv.serve_forever() for srv in self.servers],
            return_exceptions=True
        )
    
    async def stop(self):
        """Stop reverse proxy server"""
        logger.info("Stopping Reverse Proxy...")
        self.running = False

        if self._health_task and not self._health_task.done():
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        for server in self.servers:
            server.close()
            await server.wait_closed()

        logger.info("Reverse Proxy stopped")
    
    def _get_original_dst(self, sock) -> tuple:
        """Read the original destination IP:port before nftables REDIRECT."""
        import struct, socket as _socket
        try:
            dst = sock.getsockopt(_socket.SOL_IP, self.SO_ORIGINAL_DST, 16)
            port = struct.unpack('!H', dst[2:4])[0]
            addr = _socket.inet_ntoa(dst[4:8])
            if addr not in ('127.0.0.1', '0.0.0.0'):
                return addr, port
        except Exception:
            pass
        return None, 0

    def _resolve_backend_for_connection(self, sock) -> dict:
        """
        Determine the correct backend for an incoming connection.
        Priority:
          1. VIP match via SO_ORIGINAL_DST
          2. Generic least-connections backend pool
        Returns a backend dict: {'host':..., 'port':..., 'ssl':..., 'vip_name':...}
        """
        if self.vips_table and sock is not None:
            orig_addr, orig_port = self._get_original_dst(sock)
            if orig_addr:
                vip = self.vips_table.get((orig_addr, orig_port))
                if vip:
                    logger.info(
                        "🛡️ VIP match: %s (%s:%s → %s:%s)",
                        vip.get('name', ''), orig_addr, orig_port,
                        vip.get('internal_ip'), vip.get('internal_port'),
                    )
                    return {
                        'host':     vip.get('internal_ip'),
                        'port':     int(vip.get('internal_port', 8080)),
                        'ssl':      vip.get('use_tls_upstream', False),
                        'vip_name': vip.get('name', ''),
                    }
        return self._select_backend()

    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming HTTPS client connection.
        SSL is already terminated by the server.
        """
        client_addr = client_writer.get_extra_info('peername')
        if self._active_conn_count >= self._max_connections:
            logger.warning("Max connections reached, rejecting %s", client_addr)
            client_writer.close()
            return
        async with self._conn_semaphore:
            self._active_conn_count += 1
            try:
                await self._handle_reverse_connection(client_reader, client_writer, client_addr)
            finally:
                self._active_conn_count -= 1


    async def _handle_reverse_connection(self, client_reader, client_writer, client_addr):
        """Inner handler — VIP-aware backend selection + relay."""
        logger.debug("Reverse proxy connection from %s", client_addr)

        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1

        server_reader = None
        server_writer = None
        backend = None
        conn_id = None

        try:
            # ── VIP-aware backend selection ───────────────────────────────
            sock = client_writer.get_extra_info('socket')
            backend = self._resolve_backend_for_connection(sock)

            # ── Inspection Pipeline (PHANTOMPlugin, WAF, DLP, etc.) ───────
            # Read the first chunk of data so we can enrich the context
            # before the pipeline runs. We then forward it on to the backend.
            first_chunk = b""
            try:
                first_chunk = await asyncio.wait_for(
                    client_reader.read(8192), timeout=2.0
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass

            vip_name = backend.get('vip_name', '')
            ctx = _build_inspection_ctx(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                backend_host=backend['host'],
                backend_port=backend['port'],
                protocol="HTTPS",
                raw_data=first_chunk,
                vip_name=vip_name,
            )
            allowed = await _run_pipeline_check(
                self.inspection_pipeline, ctx, client_writer
            )
            if not allowed:
                return

            logger.info(f"🔄 Reverse proxying {client_addr[0]} → {backend['host']}:{backend['port']}")

            # Connect to backend
            # Check if backend uses SSL
            use_ssl = backend.get('ssl', False)
            if isinstance(use_ssl, str):
                use_ssl = use_ssl.lower() in ('true', '1', 'yes', 'on')
            if backend['port'] == 80 and use_ssl:
                logger.warning(
                    "Disabling SSL for port 80 backend %s", backend['host']
                )
                use_ssl = False
            
            logger.info(
                "Connecting to backend %s:%s (SSL=%s)",
                backend['host'], backend['port'], use_ssl,
            )
            
            if use_ssl:
                backend_ssl = ssl.create_default_context()
                if not self._verify_backend_tls:
                    # Only disable verification when explicitly configured
                    backend_ssl.check_hostname = False
                    backend_ssl.verify_mode = ssl.CERT_NONE
                    logger.debug("Backend TLS verification DISABLED (config override)")
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'], backend['port'],
                    ssl=backend_ssl,
                    server_hostname=backend['host'],
                )
            else:
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'], backend['port'],
                )
            
            # Create connection object
            conn_id = self._generate_connection_id(
                client_addr,
                backend['host'],
                backend['port']
            )
            
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=backend['host'],
                target_port=backend['port'],
                protocol="HTTPS",
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer
            )
            self.active_sessions[conn_id] = connection

            # Send the first chunk we already read before forwarding the stream
            if first_chunk:
                server_writer.write(first_chunk)
                await server_writer.drain()

            # Relay data bidirectionally
            await asyncio.gather(
                self.relay_data(client_reader, server_writer, connection, 'client->server'),
                self.relay_data(server_reader, client_writer, connection, 'server->client'),
                return_exceptions=True
            )
            
            self._log_allowed_connection(connection, "HTTPS", "Reverse HTTPS connection completed")
            logger.info(f"✅ Connection closed: {backend['host']} (↑{connection.bytes_sent}B ↓{connection.bytes_received}B)")
            
        except Exception as e:
            logger.error("Error in reverse proxy: %s", e, exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            if conn_id:
                self.active_sessions.pop(conn_id, None)
            if backend is not None:
                self._release_backend(backend)
            
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()
            
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def handle_http_connection(self,
                                    client_reader: asyncio.StreamReader,
                                    client_writer: asyncio.StreamWriter):
        """
        Handle incoming HTTP client connection (non-SSL).
        Uses VIP routing table first, then falls back to generic backends.
        """
        client_addr = client_writer.get_extra_info('peername')
        if self._active_conn_count >= self._max_connections:
            logger.warning("Max HTTP connections reached, rejecting %s", client_addr)
            client_writer.close()
            return
        async with self._conn_semaphore:
            self._active_conn_count += 1
            try:
                await self._handle_http_reverse_connection(client_reader, client_writer, client_addr)
            finally:
                self._active_conn_count -= 1

    async def _handle_http_reverse_connection(self, client_reader, client_writer, client_addr):
        """Inner handler for HTTP connections with semaphore protection."""
        logger.debug("Reverse proxy HTTP connection from %s", client_addr)

        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1

        server_reader = None
        server_writer = None
        backend = None
        conn_id = None

        try:
            # ── VIP-aware backend selection ───────────────────────────────
            sock = client_writer.get_extra_info('socket')
            backend = self._resolve_backend_for_connection(sock)

            # ── Inspection Pipeline (PHANTOMPlugin, WAF, DLP, etc.) ───────
            first_chunk = b""
            try:
                first_chunk = await asyncio.wait_for(
                    client_reader.read(8192), timeout=2.0
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass

            vip_name = backend.get('vip_name', '')
            ctx = _build_inspection_ctx(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                backend_host=backend['host'],
                backend_port=backend['port'],
                protocol="HTTP",
                raw_data=first_chunk,
                vip_name=vip_name,
            )
            allowed = await _run_pipeline_check(
                self.inspection_pipeline, ctx, client_writer
            )
            if not allowed:
                return

            logger.info(f"🔄 Reverse proxying (HTTP) {client_addr[0]} → {backend['host']}:{backend['port']}")

            
            # Connect to backend (usually HTTP plain text)
            # If backend requires SSL, we can use ssl context here too
            use_ssl = backend.get('ssl', False)
            if isinstance(use_ssl, str):
                use_ssl = use_ssl.lower() in ('true', '1', 'yes', 'on')
            if backend['port'] == 80 and use_ssl:
                use_ssl = False
            
            logger.info(
                "Connecting (HTTP) to backend %s:%s (SSL=%s)",
                backend['host'], backend['port'], use_ssl,
            )
            
            if use_ssl:
                backend_ssl = ssl.create_default_context()
                if not self._verify_backend_tls:
                    backend_ssl.check_hostname = False
                    backend_ssl.verify_mode = ssl.CERT_NONE
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'], backend['port'],
                    ssl=backend_ssl,
                    server_hostname=backend['host'],
                )
            else:
                server_reader, server_writer = await asyncio.open_connection(
                    backend['host'], backend['port'],
                )
            
            # Create connection object
            conn_id = self._generate_connection_id(
                client_addr,
                backend['host'],
                backend['port']
            )
            
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=backend['host'],
                target_port=backend['port'],
                protocol="HTTP",
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer
            )
            self.active_sessions[conn_id] = connection

            # Forward the chunk we already read
            if first_chunk:
                server_writer.write(first_chunk)
                await server_writer.drain()

            # Relay data bidirectionally
            await asyncio.gather(
                self.relay_data(client_reader, server_writer, connection, 'client->server'),
                self.relay_data(server_reader, client_writer, connection, 'server->client'),
                return_exceptions=True
            )
            
            self._log_allowed_connection(connection, "HTTP", "Reverse HTTP connection completed")
            logger.info(f"✅ Connection closed: {backend['host']} (↑{connection.bytes_sent}B ↓{connection.bytes_received}B)")
            
        except Exception as e:
            logger.error("Error in reverse proxy HTTP: %s", e, exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            if conn_id:
                self.active_sessions.pop(conn_id, None)
            if backend is not None:
                self._release_backend(backend)
            
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()
            
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()

    def _select_backend(self) -> dict:
        """
        Select backend — Least-Connections with Health-Aware filtering.

        Algorithm:
          1. Filter to healthy backends only (health_state[i] == True)
          2. Among healthy backends, pick the one with fewest active connections
          3. Fallback: if ALL backends are unhealthy, round-robin over all
             (prevents total service blackout; let errors surface naturally)
        """
        if not self.backends:
            raise ValueError("No backend servers configured")

        # Healthy candidates
        candidates = [
            (i, b) for i, b in enumerate(self.backends)
            if self.health_state.get(i, True)
        ]

        if not candidates:
            # All backends degraded — fallback to round-robin over all
            logger.warning(
                "All reverse-proxy backends are unhealthy! "
                "Falling back to round-robin over all backends."
            )
            idx = self.current_backend
            self.current_backend = (idx + 1) % len(self.backends)
            return self.backends[idx]

        # Least-connections selection
        best_idx, best_backend = min(
            candidates,
            key=lambda pair: self.active_conns.get(pair[0], 0)
        )
        self.active_conns[best_idx] = self.active_conns.get(best_idx, 0) + 1
        logger.debug(
            "Backend selected: %s:%s (conns=%d, healthy=%d/%d)",
            best_backend['host'], best_backend['port'],
            self.active_conns[best_idx],
            len(candidates), len(self.backends)
        )
        return best_backend

    def _release_backend(self, backend: dict):
        """Decrement active-connection counter when a connection closes."""
        for i, b in enumerate(self.backends):
            if b['host'] == backend['host'] and b['port'] == backend['port']:
                self.active_conns[i] = max(0, self.active_conns.get(i, 0) - 1)
                break

    async def _health_check_loop(self):
        """
        Periodic TCP health-check for each configured backend.

        Opens a raw TCP connection to each backend every `health_check_interval`
        seconds. On success → marks healthy. On failure → marks unhealthy and
        logs a WARNING so operators can act.

        Uses asyncio.wait_for() with `health_check_timeout` to avoid hanging
        on unreachable hosts.
        """
        logger.info(
            "Reverse Proxy health-check loop started "
            "(interval=%ds timeout=%ds)",
            self._health_interval, self._health_timeout
        )
        try:
            while True:
                await asyncio.sleep(self._health_interval)
                for i, backend in enumerate(self.backends):
                    host = backend['host']
                    port = backend['port']
                    try:
                        _r, _w = await asyncio.wait_for(
                            asyncio.open_connection(host, port),
                            timeout=self._health_timeout
                        )
                        _w.close()
                        await _w.wait_closed()
                        if not self.health_state.get(i, True):
                            logger.info(
                                "Backend RECOVERED: %s:%s", host, port
                            )
                        self.health_state[i] = True
                    except Exception as _hc_err:
                        if self.health_state.get(i, True):
                            logger.warning(
                                "Backend UNHEALTHY: %s:%s — %s",
                                host, port, _hc_err
                            )
                        self.health_state[i] = False
        except asyncio.CancelledError:
            logger.info("Reverse Proxy health-check loop stopped")
