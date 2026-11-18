#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
═══════════════════════════════════════════════════════════════════
Forward Proxy - Explicit Proxy Mode
═══════════════════════════════════════════════════════════════════

Forward proxy mode where clients explicitly configure proxy settings.
Supports:
- HTTP CONNECT method
- SOCKS5 protocol (future)
- Proxy authentication
- PAC (Proxy Auto-Configuration) files

Author: Enterprise Security Team
"""
import asyncio
import logging
from typing import Optional, Tuple
from .base_proxy import BaseProxy, ProxyConnection

logger = logging.getLogger(__name__)
class ForwardProxy(BaseProxy):
    """
    Forward Proxy Implementation
    Clients explicitly configure proxy settings to use this proxy.
    """
    def __init__(self, config: dict, ca_manager, flow_tracker=None, event_sink=None, inspection_pipeline=None):
        super().__init__(config, inspection_pipeline=inspection_pipeline, event_sink=event_sink)
        self.ca_manager = ca_manager
        self.flow_tracker = flow_tracker
        
        self.listen_host = self.proxy_config.get('forward_listen_host', '0.0.0.0')
        # Port 3128 is the standard explicit/forward proxy port.
        # DO NOT use 8080 here — that port is reserved for TransparentProxy HTTP interception.
        self.listen_port = self.proxy_config.get('forward_listen_port', 3128)
        
        logger.info(
            "Forward Proxy configured on %s:%s",
            self.listen_host, self.listen_port,
        )
    
    async def start(self):
        """Start forward proxy server"""
        logger.info("Starting Forward Proxy...")
        self.running = True
        
        server = await asyncio.start_server(
            self.handle_connection,
            self.listen_host,
            self.listen_port
        )
        self.servers.append(server)

        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logger.info("Forward Proxy listening on %s", addrs)
        # serve_forever() calls start_serving() internally — no need to call it separately.
        await server.serve_forever()
    
    async def stop(self):
        """Stop forward proxy server"""
        logger.info("Stopping Forward Proxy...")
        self.running = False
        
        for server in self.servers:
            server.close()
            await server.wait_closed()
        
        logger.info("Forward Proxy stopped")
    
    async def handle_connection(self,
                               client_reader: asyncio.StreamReader,
                               client_writer: asyncio.StreamWriter):
        """
        Handle incoming client connection
        
        Expects HTTP CONNECT or regular HTTP request
        """
        client_addr = client_writer.get_extra_info('peername')
        logger.debug(f"Forward proxy connection from {client_addr}")
        
        self.stats['total_connections'] += 1
        self.stats['active_connections'] += 1
        
        try:
            # Read first line to determine request type
            first_line = await asyncio.wait_for(
                client_reader.readline(),
                timeout=10.0
            )
            
            if not first_line:
                return
            
            # Parse request
            line = first_line.decode('latin-1').strip()
            parts = line.split()
            
            if len(parts) < 2:
                logger.warning(f"Invalid request from {client_addr}")
                return
            
            method = parts[0]
            target = parts[1]
            
            # Handle CONNECT method (for HTTPS)
            if method == 'CONNECT':
                await self._handle_connect(
                    client_reader, client_writer,
                    target, client_addr
                )
            else:
                # Handle regular HTTP request
                await self._handle_http(
                    client_reader, client_writer,
                    first_line, method, target, client_addr
                )
                
        except asyncio.TimeoutError:
            logger.debug(f"Connection timeout from {client_addr}")
        except Exception as e:
            logger.error(f"Error handling forward proxy connection: {e}", exc_info=True)
        finally:
            self.stats['active_connections'] -= 1
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
    
    async def _handle_connect(self,
                             client_reader: asyncio.StreamReader,
                             client_writer: asyncio.StreamWriter,
                             target: str,
                             client_addr: tuple):
        """
        Handle HTTP CONNECT -- Full MITM TLS Interception

        Previous implementation was a blind passthrough (no DPI).
        Now performs proper MITM:
          1. Acknowledge CONNECT (client sends TLS ClientHello)
          2. Generate dynamic certificate via CAPoolManager
          3. Terminate TLS with client using generated cert
          4. Connect to real upstream with validated TLS
          5. Relay every chunk through InspectionPipeline

        Graceful Degradation: if TLS handshake fails (cert pinning / legacy)
        falls back to blind passthrough rather than dropping the connection.
        """
        import ssl as _ssl
        import tempfile as _tmpfile
        import os as _os
        upstream_reader = upstream_writer = None
        conn_id = None
        try:
            target_parts = target.split(':')
            target_host = target_parts[0]
            target_port = int(target_parts[1]) if len(target_parts) > 1 else 443

            logger.info(
                "CONNECT MITM %s:%s from %s",
                target_host, target_port, client_addr[0]
            )

            # Destination SSRF Validation Check
            if not await self._validate_destination_async(target_host):
                logger.warning(
                    "Block SSRF/restricted target connection to %s:%s from %s",
                    target_host, target_port, client_addr[0]
                )
                client_writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 22\r\n\r\nBlocked by bunyanx")
                await client_writer.drain()
                return

            # Drain remaining CONNECT request headers
            while True:
                line = await client_reader.readline()
                if line in (b'\r\n', b'\n', b''):
                    break

            # Acknowledge CONNECT -- client will now send TLS ClientHello
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()

            # ── Step 1: terminate TLS with the client side ─────────────────
            try:
                cert_pem, key_pem = self.ca_manager.generate_server_certificate(target_host)
                client_ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)

                # Write cert+key to separate tempfiles then unlink immediately (no leak)
                _cert_path = _key_path = None
                try:
                    with _tmpfile.NamedTemporaryFile(
                            mode='wb', delete=False, suffix='.crt') as _cf:
                        _cf.write(cert_pem)
                        _cert_path = _cf.name
                    with _tmpfile.NamedTemporaryFile(
                            mode='wb', delete=False, suffix='.key') as _kf:
                        _kf.write(key_pem)
                        _key_path = _kf.name
                    client_ssl_ctx.load_cert_chain(_cert_path, _key_path)
                finally:
                    for _p in (_cert_path, _key_path):
                        if _p:
                            try:
                                _os.unlink(_p)
                            except OSError:
                                pass

                client_ssl_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
                client_ssl_ctx.set_alpn_protocols(['http/1.1'])

                transport = client_writer.transport
                transport.pause_reading()
                ssl_reader = asyncio.StreamReader()
                protocol   = asyncio.StreamReaderProtocol(ssl_reader)
                # FIX P-FW2: use get_running_loop() — get_event_loop() deprecated in 3.10+
                _loop = asyncio.get_running_loop()
                ssl_transport = await _loop.start_tls(
                    transport, protocol, client_ssl_ctx, server_side=True
                )
                # FIX P-FW3: pass running loop to StreamWriter
                ssl_writer = asyncio.StreamWriter(
                    ssl_transport, protocol, ssl_reader, _loop
                )
                logger.debug("Forward MITM TLS handshake OK with %s", client_addr[0])

            except _ssl.SSLError as _tls_err:
                # Cert pinning or client rejection -- graceful degradation to passthrough
                logger.warning(
                    "Forward MITM TLS failed (%s): %s -- passthrough (no inspection)",
                    target_host, _tls_err
                )
                upstream_reader, upstream_writer = await self.connect_to_upstream(
                    target_host, target_port
                )
                conn_id = self._generate_connection_id(client_addr, target_host, target_port)
                connection = ProxyConnection(
                    connection_id=conn_id,
                    client_ip=client_addr[0], client_port=client_addr[1],
                    target_host=target_host, target_port=target_port,
                    protocol="HTTPS-PASSTHROUGH"
                )
                self.active_sessions[conn_id] = connection
                await asyncio.gather(
                    self.relay_data(client_reader, upstream_writer, connection,
                                    'client->server'),
                    self.relay_data(upstream_reader, client_writer, connection,
                                    'server->client'),
                    return_exceptions=True
                )
                self._log_allowed_connection(connection, "HTTPS-PASSTHROUGH", "HTTPS blind passthrough completed")
                return

            # ── Step 2: connect to real upstream with validated TLS ────────
            upstream_ssl_ctx = _ssl.create_default_context()
            upstream_ssl_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
            upstream_reader, upstream_writer = await asyncio.open_connection(
                target_host, target_port,
                ssl=upstream_ssl_ctx, server_hostname=target_host
            )
            logger.debug(
                "Forward MITM upstream TLS connected to %s:%s",
                target_host, target_port
            )

            # ── Step 3: relay through InspectionPipeline on every chunk ───
            conn_id = self._generate_connection_id(client_addr, target_host, target_port)
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0], client_port=client_addr[1],
                target_host=target_host, target_port=target_port,
                protocol="HTTPS",
                client_reader=ssl_reader, client_writer=ssl_writer,
                server_reader=upstream_reader, server_writer=upstream_writer
            )
            self.active_sessions[conn_id] = connection

            logger.info(
                "Forward MITM relay: %s -- %s:%s",
                client_addr[0], target_host, target_port
            )
            await asyncio.gather(
                self.relay_data(ssl_reader, upstream_writer, connection, 'client->server'),
                self.relay_data(upstream_reader, ssl_writer, connection, 'server->client'),
                return_exceptions=True
            )
            logger.info(
                "Forward MITM closed: %s (sent=%dB recv=%dB)",
                target_host, connection.bytes_sent, connection.bytes_received
            )
            self._log_allowed_connection(connection, "HTTPS", "Forward MITM connection completed")

        except Exception as e:
            logger.error("Error in Forward CONNECT MITM for %s: %s", target, e, exc_info=True)
        finally:
            if conn_id:
                self.active_sessions.pop(conn_id, None)
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _handle_http(self,
                           client_reader: asyncio.StreamReader,
                           client_writer: asyncio.StreamWriter,
                           first_line: bytes,
                           method: str,
                           url: str,
                           client_addr: tuple):
        """
        Handle regular HTTP request (non-CONNECT)
        """
        conn_id = None
        server_writer = None
        try:
            # Parse URL to extract host
            if url.startswith('http://'):
                url = url[7:]
            
            # Extract host and path
            if '/' in url:
                host_part, path = url.split('/', 1)
                path = '/' + path
            else:
                host_part = url
                path = '/'
            
            # Extract host and port
            if ':' in host_part:
                target_host, port_str = host_part.split(':', 1)
                target_port = int(port_str)
            else:
                target_host = host_part
                target_port = 80
            
            logger.info(f"📄 HTTP {method} {target_host}{path} from {client_addr[0]}")

            # Destination SSRF Validation Check
            if not await self._validate_destination_async(target_host):
                logger.warning(
                    "Block HTTP SSRF/restricted target connection to %s:%s from %s",
                    target_host, target_port, client_addr[0]
                )
                client_writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 22\r\n\r\nBlocked by bunyanx")
                await client_writer.drain()
                return
            
            # Connect to upstream
            server_reader, server_writer = await self.connect_to_upstream(
                target_host, target_port
            )
            
            # Forward request
            # Reconstruct request without full URL
            new_first_line = f"{method} {path} HTTP/1.1\r\n".encode()
            server_writer.write(new_first_line)
            
            # Forward remaining headers
            while True:
                line = await client_reader.readline()
                server_writer.write(line)
                if line == b'\r\n' or line == b'\n' or not line:
                    break
            
            await server_writer.drain()
            
            # Create connection object for tracking
            conn_id = self._generate_connection_id(client_addr, target_host, target_port)
            connection = ProxyConnection(
                connection_id=conn_id,
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port,
                protocol="HTTP",
                client_reader=client_reader,
                client_writer=client_writer,
                server_reader=server_reader,
                server_writer=server_writer
            )
            self.active_sessions[conn_id] = connection
            
            # Relay data bidirectionally
            await asyncio.gather(
                self.relay_data(client_reader, server_writer, connection, 'client->server'),
                self.relay_data(server_reader, client_writer, connection, 'server->client'),
                return_exceptions=True
            )
            self._log_allowed_connection(connection, "HTTP", "Forward HTTP connection completed")
            
        except Exception as e:
            logger.error("Error in HTTP handler: %s", e, exc_info=True)
        finally:
            if conn_id:
                self.active_sessions.pop(conn_id, None)
            if server_writer and not server_writer.is_closing():
                server_writer.close()
                await server_writer.wait_closed()

    async def _validate_destination_async(self, target_host: str) -> bool:
        """
        Validates if target host is a public/allowed destination.
        Returns False if the destination resolves to a private, loopback, 
        or link-local address (preventing SSRF/proxy bouncing).
        """
        import ipaddress
        import socket
        try:
            # Whitelist override check
            allowed_hosts = self.proxy_config.get('allowed_ssrf_hosts', [])
            if target_host in allowed_hosts:
                return True

            try:
                ip = ipaddress.ip_address(target_host)
                if ip.is_loopback or ip.is_private or ip.is_link_local:
                    return False
                return True
            except ValueError:
                if target_host.lower() in ('localhost', 'localhost.localdomain'):
                    return False
                # Resolve host via executor (non-blocking DNS)
                # FIX P-FW4: use get_running_loop() here too
                loop = asyncio.get_running_loop()
                resolved_ip_str = await loop.run_in_executor(
                    None,
                    lambda: socket.gethostbyname(target_host)
                )
                ip = ipaddress.ip_address(resolved_ip_str)
                if ip.is_loopback or ip.is_private or ip.is_link_local:
                    return False
                return True
        except Exception as e:
            logger.warning("SSRF validation failed for host %s: %s", target_host, e)
            return False

