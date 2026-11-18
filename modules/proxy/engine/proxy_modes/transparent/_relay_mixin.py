#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Relay mixin — bidirectional data relay with inspection, DLP, and malware scanning.

Contains:
  - RelayMixin              : _perform_mitm, _perform_reverse_proxy,
                              _perform_passthrough, _relay_data, _relay_http
  - _send_dlp_block_response: module-level helper for HTTP 549 DLP block responses

Consumed by MITMProxy via multiple inheritance.
Depends on self attributes set in MITMProxy.__init__:
  _inspection_bridge, _ctx_builder, http_cloaker, tls_interceptor,
  stats, event_sink, config, proxy_config, vips_table, qos_manager (optional)
"""
import asyncio
import ssl
import logging
from datetime import datetime
from typing import Optional

from system.core.framework.pipeline import InspectionAction
from system.telemetry.events.event_schema import create_event_from_proxy, EventVerdict
from modules.proxy.engine.inspection_bridge import InspectionBridge

from modules.proxy.engine.proxy_modes.transparent._types import ConnectionStats

logger = logging.getLogger(__name__)


# ── Module-level helper ───────────────────────────────────────────────────────

async def _send_dlp_block_response(
    writer: asyncio.StreamWriter,
    reasons: list,
    protocol: str,
) -> None:
    """
    Send an HTTP 549 DLP Block response to a client writer and close the stream.

    549 is an unofficial status code used by some enterprise proxies for
    content-policy violations. We follow that convention here so that
    client-side tooling can distinguish DLP blocks from generic 403s.

    Args:
        writer:   The client-facing asyncio StreamWriter to write the response to.
        reasons:  List of human-readable block reasons (from DLP findings).
        protocol: "HTTP" or "HTTPS" (for Content-Type logging only).
    """
    try:
        body_lines = ["DLP Policy Violation: Sensitive data transfer blocked."]
        for r in reasons[:5]:
            body_lines.append(f"  - {r}")
        body = "\r\n".join(body_lines).encode("utf-8")

        response = (
            b"HTTP/1.1 549 DLP Block\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Connection: close\r\n"
            b"X-Block-Reason: DLP-Egress\r\n"
            b"Cache-Control: no-store\r\n"
            + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            + b"\r\n"
            + body
        )
        writer.write(response)
        await writer.drain()
    except Exception as _exc:
        logger.debug("[DLP-RSP] Failed to send 549 block response: %s", _exc)
    finally:
        if not writer.is_closing():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ── Relay Mixin ───────────────────────────────────────────────────────────────

class RelayMixin:
    """
    Relay methods for MITMProxy.

    All methods access `self` attributes set in MITMProxy.__init__.
    """

    def _is_self_loop(self, target_host: str, target_port: int, client_writer) -> bool:
        """
        Check if a target (host, port) resolves back to the proxy's own IP and listening port,
        which would cause a recursive infinite proxy loop and Denial of Service.
        """
        if not target_host or not target_port:
            return False

        target_host_lower = str(target_host).strip().lower()
        _local_ips = {"127.0.0.1", "localhost", "0.0.0.0"}

        if client_writer:
            try:
                sock = client_writer.get_extra_info('socket')
                if sock:
                    _local_ips.add(sock.getsockname()[0])
            except Exception:
                pass

        try:
            import socket as _sock_mod
            hostname = _sock_mod.gethostname()
            _local_ips.add(hostname.lower())
            _local_ips.add(_sock_mod.gethostbyname(hostname))
        except Exception:
            pass

        _proxy_ports = {
            getattr(self, "listen_port", 8443),
            getattr(self, "http_port", 8080),
            getattr(self, "forward_listen_port", 3128),
            getattr(self, "reverse_listen_port", 443),
            getattr(self, "reverse_http_port", 80),
        }

        try:
            p_cfg = getattr(self, "config", {}).get('proxy', {})
            for key in ("listen_port", "http_port", "forward_listen_port", "reverse_listen_port", "reverse_http_port"):
                val = p_cfg.get(key)
                if val:
                    _proxy_ports.add(int(val))
        except Exception:
            pass

        return (target_host_lower in _local_ips) and (int(target_port) in _proxy_ports)

    async def _perform_mitm(
        self,
        client_reader,
        client_writer,
        target_host: str,
        target_port: int,
        client_addr: tuple,
        is_vip: bool = False,
        vip_config: dict = None,
    ):
        """
        Perform MITM interception or Reverse Proxy.

        Args:
            is_vip:     If True, this is a mapped Virtual IP connection.
            vip_config: The specific VIP configuration for this flow.
        """
        if not is_vip and self._is_self_loop(target_host, target_port, client_writer):
            logger.warning(
                "🚫 MITM Relay blocked: Self-loop detected (%s requested %s:%s)",
                client_addr[0] if client_addr else "unknown", target_host, target_port,
            )
            client_writer.write(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 38\r\nConnection: close\r\n\r\n"
                b"Error: Proxy self-loop request blocked."
            )
            await client_writer.drain()
            return

        mode = self.config.get('proxy', {}).get('mode', 'transparent')
        if mode == 'reverse_proxy' or is_vip:
            await self._perform_reverse_proxy(
                client_reader, client_writer,
                target_host, target_port, is_vip, vip_config,
            )
            return


        upstream_reader = None
        upstream_writer = None
        conn_id = None

        try:
            # Step 1: Create SSL context for client with generated certificate
            logger.debug(f"Generating certificate for {target_host}")
            client_ssl_context = self.tls_interceptor.create_client_ssl_context(target_host)

            # Wrap client connection with SSL
            client_ssl_reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(client_ssl_reader)
            transport = client_writer.transport

            ssl_transport = await asyncio.get_running_loop().start_tls(
                transport,
                protocol,
                client_ssl_context,
                server_side=True,
            )

            client_ssl_writer = asyncio.StreamWriter(
                ssl_transport,
                protocol,
                client_ssl_reader,
                asyncio.get_event_loop(),
            )

            logger.debug("✅ SSL handshake completed with client")

            # Step 2: Connect to upstream server
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        target_host, target_port,
                        ssl=self.tls_interceptor.upstream_ssl_context,
                        server_hostname=target_host,
                    ),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as conn_err:
                logger.warning(
                    "⚠️ HTTPS Upstream connection failed: %s:%d (%s)",
                    target_host, target_port, conn_err,
                )
                return

            # Create statistics
            conn_id = f"{client_addr[0]}:{client_addr[1]}->{target_host}:{target_port}"
            stats = ConnectionStats(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port,
            )
            self.stats[conn_id] = stats

            # Enrich TLS context after handshake
            _tls_version = None
            try:
                _ssl_obj = ssl_transport.get_extra_info("ssl_object")
                if _ssl_obj:
                    _tls_version = _ssl_obj.version()
            except Exception:
                pass

            _mitm_tls_ctx = self._ctx_builder.enrich_tls(
                self._ctx_builder.build_network_context(
                    client_addr, target_host, target_port, "HTTPS",
                    direction="inbound",
                ),
                sni=target_host,
                version=_tls_version,
                is_decrypted=True,
            )
            if is_vip:
                self._ctx_builder.tag_vip(
                    _mitm_tls_ctx, vip_config.get('name', '') if vip_config else ''
                )

            # Step 3: Relay data bidirectionally
            logger.info(
                "🔄 MITM Relay (decrypted): %s ↔ %s:%s",
                client_addr[0], target_host, target_port,
            )

            await asyncio.gather(
                self._relay_data(
                    client_ssl_reader, upstream_writer, stats,
                    'client->server', client_ssl_writer, is_vip=is_vip,
                ),
                self._relay_data(
                    upstream_reader, client_ssl_writer, stats,
                    'server->client', is_vip=is_vip,
                    request_url=f"https://{stats.target_host}",
                ),
                return_exceptions=True,
            )

            stats.end_time = datetime.now()
            duration = (stats.end_time - stats.start_time).total_seconds()
            logger.info(
                "✅ Connection closed: %s (↑%dB ↓%dB %.2fs)",
                target_host, stats.bytes_sent, stats.bytes_received, duration,
            )

            if getattr(self, 'event_sink', None):
                try:
                    evt = create_event_from_proxy(
                        src_ip=stats.client_ip, dst_ip=stats.target_host,
                        src_port=stats.client_port, dst_port=stats.target_port,
                        protocol="HTTPS",
                        bytes_count=stats.bytes_sent + stats.bytes_received,
                        packets_count=(stats.bytes_sent + stats.bytes_received) // 1400,
                        verdict=EventVerdict.ALLOW, reason="MITM proxy completed",
                    )
                    asyncio.create_task(self.event_sink.submit_event(evt))
                except Exception as e:
                    logger.debug("Event sink push failed: %s", e)

        except ssl.SSLError as e:
            logger.error("SSL error during MITM: %s", e)
            if "expired" in str(e).lower() and target_host:
                if not hasattr(self, '_expired_hosts_cache'):
                    self._expired_hosts_cache = set()
                self._expired_hosts_cache.add(target_host)
        except ConnectionResetError:
            logger.debug("Connection reset by peer during MITM for %s", target_host)
        except TypeError as e:
            if "_abort() takes 1 positional argument" in str(e):
                logger.debug(
                    "Connection reset by peer during MITM handshake "
                    "(Python 3.11 asyncio bug handled) for %s", target_host,
                )
            else:
                logger.error("Error during MITM: %s", e, exc_info=True)
        except Exception as e:
            logger.error("Error during MITM: %s", e, exc_info=True)
        finally:
            if conn_id:
                self.http_cloaker.clear_flow(conn_id)
                self.stats.pop(conn_id, None)
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _perform_reverse_proxy(
        self,
        client_reader,
        client_writer,
        target_host,
        target_port,
        is_vip: bool = False,
        vip_config: dict = None,
    ):
        """
        Relay between client and backend in reverse proxy mode.
        TLS already terminated at server side. Backend connection may use TLS.
        """
        upstream_reader = upstream_writer = None
        conn_id = None
        current_addr = client_writer.get_extra_info('peername')

        try:
            if is_vip and vip_config:
                use_tls    = vip_config.get('use_tls_upstream', True)
                backend_host = vip_config.get('internal_ip', target_host)
                backend_port = vip_config.get('internal_port', target_port)
            else:
                backend = self.config.get('backend', {})
                use_tls    = backend.get('use_tls', True)
                backend_host = backend.get('target_host', target_host)
                backend_port = backend.get('target_port', target_port)

            logger.debug("Connecting to backend %s:%s (TLS: %s)", backend_host, backend_port, use_tls)

            if use_tls:
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    backend_host, backend_port,
                    ssl=self.tls_interceptor.upstream_ssl_context,
                    server_hostname=backend_host,
                )
            else:
                upstream_reader, upstream_writer = await asyncio.open_connection(
                    backend_host, backend_port,
                )

            stats = ConnectionStats(
                client_ip=current_addr[0],
                client_port=current_addr[1],
                target_host=backend_host,
                target_port=backend_port,
            )
            conn_id = f"{stats.client_ip}:{stats.client_port}->{backend_host}:{backend_port}"
            self.stats[conn_id] = stats

            await asyncio.gather(
                self._relay_data(
                    client_reader, upstream_writer, stats,
                    'client->server', client_writer, is_vip=is_vip,
                ),
                self._relay_data(
                    upstream_reader, client_writer, stats,
                    'server->client', is_vip=is_vip,
                ),
                return_exceptions=True,
            )

            stats.end_time = datetime.now()
            duration = (stats.end_time - stats.start_time).total_seconds()
            logger.info("✅ VIP Relay closed: %s (duration: %.2fs)", backend_host, duration)

            if getattr(self, 'event_sink', None):
                try:
                    evt = create_event_from_proxy(
                        src_ip=stats.client_ip, dst_ip=stats.target_host,
                        src_port=stats.client_port, dst_port=stats.target_port,
                        protocol="TCP/TLS",
                        bytes_count=stats.bytes_sent + stats.bytes_received,
                        packets_count=(stats.bytes_sent + stats.bytes_received) // 1400,
                        verdict=EventVerdict.ALLOW, reason="VIP reverse proxy completed",
                    )
                    asyncio.create_task(self.event_sink.submit_event(evt))
                except Exception as e:
                    logger.debug("Event sink push failed: %s", e)

        except OSError as e:
            logger.warning("Backend unreachable (VIP): %s", e)
        except Exception as e:
            logger.error("Reverse proxy error: %s", e, exc_info=True)
        finally:
            if conn_id:
                self.http_cloaker.clear_flow(conn_id)
                self.stats.pop(conn_id, None)
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _perform_passthrough(
        self,
        client_reader,
        client_writer,
        target_host,
        target_port,
    ):
        """Pure TCP fast-forward for Bypassed domains (no TLS decryption)."""
        upstream_reader = None
        upstream_writer = None
        conn_id = None
        current_addr = client_writer.get_extra_info('peername')
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                target_host, target_port,
            )
            stats = ConnectionStats(
                client_ip=current_addr[0], client_port=current_addr[1],
                target_host=target_host, target_port=target_port,
            )
            conn_id = f"{stats.client_ip}:{stats.client_port}->{target_host}:{target_port}"
            self.stats[conn_id] = stats

            await asyncio.gather(
                self._relay_data(client_reader, upstream_writer, stats, 'client->server', client_writer),
                self._relay_data(upstream_reader, client_writer, stats, 'server->client'),
                return_exceptions=True,
            )

            stats.end_time = datetime.now()
            duration = (stats.end_time - stats.start_time).total_seconds()
            logger.info(
                "✅ Fast-forward Passthrough closed: %s (duration: %.2fs)",
                target_host, duration,
            )
        except Exception as e:
            logger.debug("Passthrough error for %s: %s", target_host, e)
        finally:
            if conn_id:
                self.http_cloaker.clear_flow(conn_id)
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _relay_data(
        self,
        reader,
        writer,
        stats: ConnectionStats,
        direction: str,
        opposite_writer=None,
        is_vip: bool = False,
        request_url: str = "",
    ):
        """
        Relay data between two streams with unified InspectionBridge inspection.

        Phase 10 changes:
          - context is built via ContextBuilder (typed, not metadata dict)
          - For client→server: HTTP body goes into context.http.body
            (data is PLAINTEXT after TLS decryption by _perform_mitm)
          - Inspection via InspectionBridge.check() instead of inline pipeline call
          - 403 response sent by InspectionBridge.send_block_403()
          - Event publishing delegated to InspectionBridge

        DLP Egress Guard (server→client):
          - Every server response chunk is scanned by DLPInspectorPlugin.inspect_response()
            BEFORE being forwarded to the client.
          - Any confirmed content match (CC, SSN, source code, etc.) immediately
            terminates the relay and sends a 549 DLP Block to the client.
        """
        # ── Lazy DLP & Malware/AV plugin references for response inspection ──
        _dlp_plugin = None
        _mav_plugin = None
        if direction == 'server->client' and self._inspection_bridge:
            try:
                from modules.dlp.engine.dlp_inspector import DLPInspectorPlugin
                _pipeline = getattr(self._inspection_bridge, '_pipeline', None)
                if _pipeline:
                    _dlp_plugin = _pipeline._plugins_by_name.get('dlp_inspector')
                    if _dlp_plugin and not isinstance(_dlp_plugin, DLPInspectorPlugin):
                        _dlp_plugin = None
                    _mav_plugin = _pipeline._plugins_by_name.get('malware_av')
            except Exception as _rsp_init_exc:
                logger.debug("[RSP-GUARD] Plugin lookup failed: %s", _rsp_init_exc)

        _accumulated_stream = b""
        # ── Per-connection inspection gate ─────────────────────────────────────
        # InspectionBridge.check() must run ONCE per connection (on the first chunk
        # that contains the HTTP request line + headers), NOT on every relay chunk.
        #
        # Running it on every chunk causes:
        #   - 700ms+ latency per chunk × N chunks = browser spinning indefinitely
        #   - Redundant ML inference on body fragments that don't contain attack patterns
        #
        # After the first check returns ALLOW, remaining chunks are forwarded directly.
        # If the first check returns BLOCK, the connection is terminated immediately.
        _inspection_done = False

        try:
            buffer_size = self.proxy_config.get('buffer_size', 65536)

            while True:
                data = await reader.read(buffer_size)
                if not data:
                    break

                # Throttle based on QoS policies
                if getattr(self, 'qos_manager', None):
                    await self.qos_manager.throttle(stats.client_ip, len(data))

                # Update statistics
                if direction == 'client->server':
                    stats.bytes_sent += len(data)
                    self.bytes_sent += len(data)
                    _accumulated_stream += data
                    if len(_accumulated_stream) > 35_000_000 and _inspection_done:
                        _accumulated_stream = _accumulated_stream[-1_000_000:]
                else:
                    flow_id = (
                        f"{stats.client_ip}:{stats.client_port}"
                        f"->{stats.target_host}:{stats.target_port}"
                    )
                    data = self.http_cloaker.process_data(data, direction, flow_id)
                    stats.bytes_received += len(data)
                    self.bytes_received += len(data)

                # ── Phase 10: Inspect via InspectionBridge (client→server, complete request) ──
                if self._inspection_bridge and direction == 'client->server' and not _inspection_done:
                    try:
                        _dir = 'inbound' if is_vip else 'outbound'
                        _is_email = stats.target_port in (25, 587, 465, 143, 993, 110, 995)
                        _proto = (
                            "SMTP" if stats.target_port in (25, 587, 465)
                            else ("HTTP" if stats.target_port == 80 else "HTTPS")
                        )
                        ctx = self._ctx_builder.build_network_context(
                            (stats.client_ip, stats.client_port),
                            stats.target_host, stats.target_port,
                            _proto, direction=_dir,
                        )
                        if _is_email:
                            ctx.metadata["raw_email_bytes"] = _accumulated_stream
                        else:
                            self._ctx_builder.enrich_tls(
                                ctx, sni=stats.target_host, is_decrypted=True,
                            )
                            # Pass accumulated stream so full HTTP headers + decrypted POST payload are parsed
                            self._ctx_builder.enrich_http(ctx, _accumulated_stream, scheme=_proto.lower())

                        # For POST/PUT requests or SMTP streams, buffer full body before inspection
                        _is_post_put = ctx.http and ctx.http.method in ("POST", "PUT", "PATCH")
                        _has_headers = b"\r\n\r\n" in _accumulated_stream or b"\n\n" in _accumulated_stream
                        _need_more_body = False

                        if _is_email:
                            _smtp_done = (
                                b"\r\n.\r\n" in _accumulated_stream or 
                                b"\n.\n" in _accumulated_stream or 
                                b"QUIT\r\n" in _accumulated_stream or
                                b"QUIT\n" in _accumulated_stream
                            )
                            if not _smtp_done:
                                # For interactive SMTP: forward command chunk immediately so SMTP server responds (220, 250, 354),
                                # while continuing to accumulate the stream until \r\n.\r\n
                                writer.write(data)
                                await writer.drain()
                                continue
                            ctx.metadata["raw_email_bytes"] = _accumulated_stream
                        elif not _has_headers and len(_accumulated_stream) < 65536:
                            _need_more_body = True
                        elif _is_post_put and _has_headers:
                            _content_length = (ctx.http.headers or {}).get("content-length")
                            if _content_length and _content_length.isdigit():
                                _expected_len = min(int(_content_length), 30 * 1024 * 1024)
                                if len(ctx.http.body) < _expected_len and len(_accumulated_stream) < 30 * 1024 * 1024:
                                    _need_more_body = True

                        if _need_more_body:
                            # Keep buffering more chunks before checking or forwarding
                            continue

                        result = await self._inspection_bridge.check(ctx)
                        _inspection_done = True   # ← mark done; skip on all subsequent chunks

                        if result.is_blocked:
                            logger.warning(
                                "🚫 Relay BLOCK [%s]: %s → %s (action=%s)",
                                direction, stats.client_ip, stats.target_host,
                                result.action.name,
                            )
                            if opposite_writer and not opposite_writer.is_closing():
                                reasons = [
                                    f"[{f.plugin_name}] {f.description}"
                                    for f in result.findings
                                ]
                                await InspectionBridge.send_block_403(
                                    opposite_writer, reasons, _proto,
                                )
                            raise ConnectionAbortedError("Blocked by InspectionBridge")

                        # Inspection passed (ALLOW) -> Flush buffered accumulated stream to server!
                        if not _is_email:
                            writer.write(_accumulated_stream)
                            await writer.drain()
                        else:
                            writer.write(data)
                            await writer.drain()
                        continue

                    except ConnectionAbortedError:
                        raise
                    except Exception as exc:
                        _inspection_done = True   # don't retry on error either
                        logger.error("Relay inspection error: %s", exc)
                        # On error, flush accumulated stream to avoid stall
                        writer.write(_accumulated_stream)
                        await writer.drain()
                        continue


                # ── DLP Egress Guard ──────────────────────────────────────────
                elif direction == 'server->client' and _dlp_plugin is not None:
                    try:
                        _proto = "HTTPS" if stats.target_port in (443, 8443) else "HTTP"
                        dlp_result = _dlp_plugin.inspect_response(
                            raw_chunk=data,
                            src_ip=stats.client_ip,
                            dst_ip=stats.target_host,
                            src_port=stats.client_port,
                            dst_port=stats.target_port,
                            protocol=_proto,
                            url=request_url,
                        )
                        if dlp_result.is_blocked:
                            reasons = [
                                f"[{f.plugin_name}] {f.description}"
                                for f in dlp_result.findings
                            ]
                            logger.warning(
                                "🚫 DLP Egress BLOCK [server→client]: %s → %s | %s",
                                stats.target_host, stats.client_ip,
                                " | ".join(reasons[:3]),
                            )
                            target_w = (
                                opposite_writer
                                if (opposite_writer and not opposite_writer.is_closing())
                                else writer
                            )
                            if not target_w.is_closing():
                                await _send_dlp_block_response(target_w, reasons, _proto)
                            raise ConnectionAbortedError("DLP Egress Block")
                    except ConnectionAbortedError:
                        raise
                    except Exception as dlp_exc:
                        logger.error("[DLP-RSP] Response inspection error (skipping): %s", dlp_exc)

                # ── Malware AV Egress Guard ───────────────────────────────────
                if direction == 'server->client' and _mav_plugin is not None and len(data) >= 4:
                    try:
                        _proto = "HTTPS" if stats.target_port in (443, 8443) else "HTTP"
                        _rsp_ctx = self._ctx_builder.build_network_context(
                            (stats.client_ip, stats.client_port),
                            stats.target_host, stats.target_port,
                            _proto,
                            direction='inbound' if is_vip else 'outbound',
                        )
                        mav_result = await _mav_plugin.inspect_async(_rsp_ctx, data)
                        if mav_result.is_blocked:
                            reasons = [
                                f"[{f.plugin_name}] {f.description}"
                                for f in mav_result.findings
                            ]
                            logger.warning(
                                "🚫 Malware AV Egress BLOCK [server→client]: %s → %s | %s",
                                stats.target_host, stats.client_ip, " | ".join(reasons[:3]),
                            )
                            target_w = (
                                opposite_writer
                                if (opposite_writer and not opposite_writer.is_closing())
                                else writer
                            )
                            if not target_w.is_closing():
                                await _send_dlp_block_response(target_w, reasons, _proto)
                            raise ConnectionAbortedError("Malware AV Egress Block")
                    except ConnectionAbortedError:
                        raise
                    except Exception as mav_exc:
                        logger.debug("[MAV-RSP] Response inspection error: %s", mav_exc)

                writer.write(data)
                await writer.drain()

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug("Relay ended (%s): %s", direction, e)
        finally:
            if not writer.is_closing():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def _relay_http(
        self,
        client_reader,
        client_writer,
        first_line: bytes,
    ):
        """
        Relay plain HTTP connection to the destination server.

        Extracts the Host header from the request, connects to the
        target server, forwards the full request, and relays the response.
        """
        upstream_writer = None
        try:
            # Read remaining headers
            headers_raw = b''
            while True:
                line = await asyncio.wait_for(client_reader.readline(), timeout=10.0)
                headers_raw += line
                if line in (b'\r\n', b'\n') or not line:
                    break

            # Extract Host header to determine target
            target_host = None
            target_port = 80
            for hdr_line in headers_raw.decode('latin-1', errors='replace').split('\r\n'):
                if hdr_line.lower().startswith('host:'):
                    host_val = hdr_line.split(':', 1)[1].strip()
                    if ':' in host_val:
                        target_host, port_str = host_val.rsplit(':', 1)
                        try:
                            target_port = int(port_str)
                        except ValueError:
                            target_host = host_val
                    else:
                        target_host = host_val
                    break

            if not target_host:
                req_parts = first_line.decode('latin-1').strip().split()
                if len(req_parts) >= 2 and req_parts[1].startswith('http://'):
                    from urllib.parse import urlparse
                    parsed = urlparse(req_parts[1])
                    target_host = parsed.hostname
                    target_port = parsed.port or 80

            if not target_host:
                logger.warning("HTTP relay: could not determine target host")
                client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                await client_writer.drain()
                return

            # VIP rewrite
            if (target_host, target_port) in self.vips_table:
                vip_cfg = self.vips_table[(target_host, target_port)]
                target_host = vip_cfg.get("internal_ip")
                target_port = vip_cfg.get("internal_port")

            # Self-loop protection guard
            if self._is_self_loop(target_host, target_port, client_writer):
                client_addr = client_writer.get_extra_info('peername')
                logger.warning(
                    "🚫 Proxy Self-Loop Blocked: %s requested %s:%s (proxy listener)",
                    client_addr[0] if client_addr else "unknown", target_host, target_port,
                )
                client_writer.write(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: 38\r\nConnection: close\r\n\r\n"
                    b"Error: Proxy self-loop request blocked."
                )
                await client_writer.drain()
                return

            # Fast response for OS connectivity probes

            _KNOWN_PROBES = (
                "detectportal.firefox.com",
                "www.msftconnecttest.com",
                "connectivitycheck.gstatic.com",
            )
            if target_host in _KNOWN_PROBES:
                logger.debug("🌐 Fast-response for OS Connectivity Check: %s", target_host)
                resp = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: 7\r\nConnection: close\r\n\r\nsuccess"
                )
                client_writer.write(resp)
                await client_writer.drain()
                return

            # Security policy
            client_addr = client_writer.get_extra_info('peername')
            if not self._check_security_policy(client_addr[0], target_host):
                logger.warning("🚫 HTTP blocked: %s → %s", client_addr[0], target_host)
                client_writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 21\r\n\r\n"
                    b"Blocked by bunyanx policy"
                )
                await client_writer.drain()
                return

            logger.info("🔄 HTTP relay: %s → %s:%s", client_addr[0], target_host, target_port)

            # Phase 10: Run inspection via InspectionBridge BEFORE opening upstream
            req_data = first_line + headers_raw
            if self._inspection_bridge:
                ctx = self._ctx_builder.build_network_context(
                    client_addr, target_host, target_port,
                    "HTTP", direction="outbound",
                )
                self._ctx_builder.enrich_http(ctx, req_data, scheme="http")
                result = await self._inspection_bridge.check(ctx, client_writer)
                if result.is_blocked:
                    logger.warning(
                        "🚫 HTTP Blocked [InspectionBridge]: %s → %s (action=%s)",
                        client_addr[0], target_host, result.action.name,
                    )
                    return  # 403 already sent by bridge; upstream never opened

            # Connect to upstream
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=10.0,
                )
            except (OSError, asyncio.TimeoutError) as conn_err:
                logger.warning(
                    "⚠️ HTTP Upstream connection failed: %s:%d (%s)",
                    target_host, target_port, conn_err,
                )
                if client_writer and not client_writer.is_closing():
                    body = (
                        f"HTTP 504 Gateway Timeout\r\n"
                        f"Unable to connect to upstream server {target_host}:{target_port}: {conn_err}\r\n"
                    ).encode()
                    resp = (
                        b"HTTP/1.1 504 Gateway Timeout\r\n"
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Connection: close\r\n"
                        + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
                        + body
                    )
                    try:
                        client_writer.write(resp)
                        await client_writer.drain()
                    except Exception:
                        pass
                return

            # Forward original request
            upstream_writer.write(req_data)
            await upstream_writer.drain()

            stats = ConnectionStats(
                client_ip=client_addr[0],
                client_port=client_addr[1],
                target_host=target_host,
                target_port=target_port,
            )

            _req_parts = first_line.decode('latin-1', errors='replace').strip().split()
            _req_url = (
                f"http://{target_host}:{target_port}{_req_parts[1]}"
                if len(_req_parts) >= 2 and _req_parts[1].startswith('/')
                else (_req_parts[1] if len(_req_parts) >= 2 else "")
            )

            await asyncio.gather(
                self._relay_data(client_reader, upstream_writer, stats, 'client->server', client_writer),
                self._relay_data(upstream_reader, client_writer, stats, 'server->client', request_url=_req_url),
                return_exceptions=True,
            )

            logger.info(
                "✅ HTTP closed: %s (↑%dB ↓%dB)",
                target_host, stats.bytes_sent, stats.bytes_received,
            )

            if getattr(self, 'event_sink', None):
                try:
                    evt = create_event_from_proxy(
                        src_ip=stats.client_ip, dst_ip=stats.target_host,
                        src_port=stats.client_port, dst_port=stats.target_port,
                        protocol="HTTP",
                        bytes_count=stats.bytes_sent + stats.bytes_received,
                        packets_count=(stats.bytes_sent + stats.bytes_received) // 1400,
                        verdict=EventVerdict.ALLOW, reason="HTTP relay completed",
                    )
                    asyncio.create_task(self.event_sink.submit_event(evt))
                except Exception as e:
                    logger.debug("Event sink push failed: %s", e)

        except asyncio.TimeoutError:
            logger.warning("HTTP relay: timeout reading headers")
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as conn_err:
            logger.debug("HTTP relay connection closed: %s", conn_err)
        except Exception as e:
            logger.error("HTTP relay error: %s", e, exc_info=True)
        finally:
            if upstream_writer and not upstream_writer.is_closing():
                upstream_writer.close()
                await upstream_writer.wait_closed()
