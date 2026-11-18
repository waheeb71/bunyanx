#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Connection handling mixin — entry points for inbound HTTPS and HTTP connections.

Contains:
  - ConnectionMixin.handle_connection      : HTTPS transparent proxy (port 8443)
  - ConnectionMixin.handle_http_connection : HTTP proxy + VIP routing (port 8080)
  - ConnectionMixin._handle_vip_https      : MemoryBIO TLS termination for HTTPS VIPs
  - ConnectionMixin._get_original_dst      : SO_ORIGINAL_DST via getsockopt
  - ConnectionMixin._extract_target        : target extraction fallback
  - ConnectionMixin._parse_sni_from_client_hello : TLS ClientHello SNI parser

Consumed by MITMProxy via multiple inheritance (ConnectionMixin).
"""
import asyncio
import ssl
import socket
import struct
import logging
from typing import Optional, Tuple

from modules.proxy.engine.proxy_modes.transparent._tls_layer import (
    _VIPSSLReader,
    _VIPSSLWriter,
)

logger = logging.getLogger(__name__)


class ConnectionMixin:
    """Connection entry-point methods for MITMProxy."""

    # Linux kernel constant for retrieving original destination from iptables REDIRECT
    SO_ORIGINAL_DST = 80

    # ── SO_ORIGINAL_DST ───────────────────────────────────────────────────────

    def _get_original_dst(self, sock_wrapper) -> Tuple[Optional[str], int]:
        """
        Get the original destination IP:port from iptables REDIRECT.

        When iptables PREROUTING redirects traffic (e.g., port 443 → 8443),
        the original destination is stored in the socket and can be retrieved
        via getsockopt(SOL_IP, SO_ORIGINAL_DST).

        This is the standard technique used by transparent proxies
        (mitmproxy, squid, etc.) on Linux.
        """
        try:
            dst = sock_wrapper.getsockopt(socket.SOL_IP, self.SO_ORIGINAL_DST, 16)
            port = struct.unpack('!H', dst[2:4])[0]
            addr = socket.inet_ntoa(dst[4:8])
            if addr in ('127.0.0.1', '0.0.0.0'):
                return None, 0
            logger.debug("SO_ORIGINAL_DST: %s:%s", addr, port)
            return addr, port
        except Exception as e:
            logger.debug("SO_ORIGINAL_DST failed: %s", e)
            return None, 0

    # ── HTTPS connection handler (port 8443) ──────────────────────────────────

    async def handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        """
        Handle incoming client connection (HTTPS).

        Target extraction strategy (in order):
        1. SNI peek (MSG_PEEK) — for domain-based HTTPS (e.g., https://example.com)
        2. SO_ORIGINAL_DST     — for IP-based HTTPS via iptables REDIRECT
        3. Stream read fallback — for HTTP CONNECT tunnels
        """
        client_addr = client_writer.get_extra_info('peername')
        if not client_addr:
            client_writer.close()
            return

        # FAST PRE-FILTER: Instantly drop connections from blocked/DDoS IPs silently
        try:
            from modules.firewall.engine.ip_blocklist import get_blocklist_manager
            if get_blocklist_manager().is_blocked(str(client_addr[0])):
                if not client_writer.is_closing():
                    client_writer.close()
                return
        except Exception:
            pass

        logger.debug("New connection from %s", client_addr)

        if not self._conn_semaphore._value:
            logger.warning("Max connections reached, rejecting %s", client_addr)
            client_writer.close()
            return

        self.total_connections += 1
        self.active_connections += 1

        # Publish connection event for real-time Port Scan detection in CorrelationEngine
        if client_addr and len(client_addr) >= 2:
            try:
                from system.events.bus import EventBus
                from system.events.topics import Topics
                sock_wrapper = client_writer.get_extra_info('socket')
                orig_addr, orig_port = (None, 8443)
                if sock_wrapper is not None:
                    orig_addr, orig_port = self._get_original_dst(sock_wrapper)
                EventBus.publish_from_thread(Topics.PACKET_INSPECTED, {
                    "src_ip": str(client_addr[0]),
                    "src_port": int(client_addr[1]),
                    "dst_port": int(orig_port or 8443),
                    "dst_ip": str(orig_addr or "10.10.0.50"),
                    "protocol": "TCP",
                })
            except Exception:
                pass

        try:
            async with self._conn_semaphore:
                transport = client_writer.transport
                transport.pause_reading()

                target_host = None
                target_port = 443
                sock_wrapper = transport.get_extra_info('socket')
                is_vip = False
                vip_config = None

                # Strategy 0: VIP Mapping
                cached_orig_addr, cached_orig_port = None, 0
                if sock_wrapper is not None:
                    cached_orig_addr, cached_orig_port = self._get_original_dst(sock_wrapper)

                if (cached_orig_addr, cached_orig_port) in self.vips_table:
                    vip_config = self.vips_table[(cached_orig_addr, cached_orig_port)]
                    target_host = vip_config.get("internal_ip")
                    target_port = vip_config.get("internal_port")
                    is_vip = True
                    logger.info(
                        "VIP Match: %s -> %s:%s",
                        vip_config.get('name'), target_host, target_port,
                    )

                # Strategy 1: SNI Peek
                tls_version = None
                if not is_vip and sock_wrapper is not None:
                    try:
                        fd = sock_wrapper.fileno()
                        dup_sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
                        try:
                            dup_sock.settimeout(5.0)
                            loop = asyncio.get_event_loop()
                            peek_data = await loop.run_in_executor(
                                None,
                                lambda: dup_sock.recv(4096, socket.MSG_PEEK),
                            )
                            if peek_data and len(peek_data) > 5 and peek_data[0] == 0x16:
                                target_host = self._parse_sni_from_client_hello(peek_data)
                                if target_host:
                                    logger.info("SNI: %s", target_host)
                                if len(peek_data) >= 11:
                                    ver_bytes = peek_data[9:11]
                                    if ver_bytes == b'\x03\x04':
                                        tls_version = "TLSv1.3"
                                    elif ver_bytes == b'\x03\x03':
                                        tls_version = "TLSv1.2"
                                    elif ver_bytes == b'\x03\x02':
                                        tls_version = "TLSv1.1"
                                    elif ver_bytes == b'\x03\x01':
                                        tls_version = "TLSv1.0"
                                    elif ver_bytes == b'\x03\x00':
                                        tls_version = "SSLv3"
                        finally:
                            dup_sock.close()
                    except Exception as e:
                        logger.debug("SNI peek failed: %s", e)

                # Strategy 2: SO_ORIGINAL_DST (cached)
                if not is_vip and not target_host and cached_orig_addr:
                    target_host = cached_orig_addr
                    target_port = cached_orig_port
                    logger.info(
                        "Original destination (nftables REDIRECT): %s:%s",
                        target_host, target_port,
                    )

                # Strategy 3: Stream read fallback (CONNECT)
                if not target_host:
                    transport.resume_reading()
                    target_host, target_port = await self._extract_target(
                        client_reader, client_writer,
                    )

                if not target_host:
                    transport.resume_reading()
                    logger.warning("Could not extract target from %s", client_addr)
                    return

                logger.info(
                    "%s%s -> %s:%s",
                    "[VIP] " if is_vip else "", client_addr[0], target_host, target_port,
                )

                # Security policy check
                if not self._check_security_policy(client_addr[0], target_host):
                    logger.warning(
                        "Blocked by security policy: %s -> %s", client_addr[0], target_host,
                    )
                    transport.resume_reading()
                    client_writer.close()
                    await client_writer.wait_closed()
                    return

                # SSL Policy Engine (Inspect / Bypass / Block)
                if not is_vip:
                    from modules.ssl_inspection.engine.policy_engine import SSLAction

                    category = None
                    if target_host:
                        if getattr(self, 'category_engine', None) is None:
                            try:
                                from modules.web_filter.policy.category import CategoryEngine
                                self.category_engine = CategoryEngine()
                            except Exception as ce_exc:
                                logger.debug("Could not instantiate CategoryEngine: %s", ce_exc)
                                self.category_engine = False

                        if self.category_engine:
                            try:
                                match = self.category_engine.categorize(target_host)
                                if match and match.categories:
                                    category = match.categories[0]
                            except Exception as cat_exc:
                                logger.debug("Failed to categorize %s: %s", target_host, cat_exc)

                    cert_expired = target_host in getattr(self, '_expired_hosts_cache', set())
                    ssl_action = self.ssl_policy.decide(
                        client_addr[0], target_host, target_port,
                        tls_version=tls_version,
                        category=category,
                        username=None,
                        cert_expired=cert_expired,
                    )

                    if ssl_action == SSLAction.BLOCK:
                        logger.warning("SSL Policy BLOCKED: %s -> %s", client_addr[0], target_host)
                        transport.resume_reading()
                        client_writer.close()
                        await client_writer.wait_closed()
                        return
                    elif ssl_action == SSLAction.BYPASS:
                        logger.info("SSL Policy BYPASSED MITM: %s", target_host)
                        transport.resume_reading()
                        await self._perform_passthrough(
                            client_reader, client_writer, target_host, target_port,
                        )
                        return

                # MITM or VIP Reverse Proxy
                await self._perform_mitm(
                    client_reader, client_writer,
                    target_host, target_port,
                    client_addr,
                    is_vip=is_vip,
                    vip_config=vip_config,
                )

        except ssl.SSLError as ssl_exc:
            err_str = str(ssl_exc)
            if 'HTTP_REQUEST' in err_str or 'WRONG_VERSION' in err_str:
                logger.debug(
                    "Plain HTTP sent to TLS port from %s — connection rejected", client_addr,
                )
            else:
                logger.warning("SSL error from %s: %s", client_addr, ssl_exc)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            logger.debug("Connection reset during handshake from %s (suppressed)", client_addr)
        except Exception as e:
            logger.error("Error handling connection from %s: %s", client_addr, e, exc_info=True)
        finally:
            self.active_connections -= 1
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()

    # ── HTTP connection handler (port 8080) ───────────────────────────────────

    async def handle_http_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        """Handle HTTP (non-TLS) connections — includes VIP routing and HTTPS VIP termination."""
        client_addr = client_writer.get_extra_info('peername')
        if not client_addr:
            client_writer.close()
            return

        # FAST PRE-FILTER: Instantly drop connections from blocked/DDoS IPs silently
        try:
            from modules.firewall.engine.ip_blocklist import get_blocklist_manager
            if get_blocklist_manager().is_blocked(str(client_addr[0])):
                if not client_writer.is_closing():
                    client_writer.close()
                return
        except Exception:
            pass

        logger.debug("New HTTP connection from %s", client_addr)

        # Publish connection event for real-time Port Scan detection in CorrelationEngine
        if client_addr and len(client_addr) >= 2:
            try:
                from system.events.bus import EventBus
                from system.events.topics import Topics
                sock_wrapper = client_writer.get_extra_info('socket')
                orig_addr, orig_port = (None, 8080)
                if sock_wrapper is not None:
                    orig_addr, orig_port = self._get_original_dst(sock_wrapper)
                EventBus.publish_from_thread(Topics.PACKET_INSPECTED, {
                    "src_ip": str(client_addr[0]),
                    "src_port": int(client_addr[1]),
                    "dst_port": int(orig_port or 8080),
                    "dst_ip": str(orig_addr or "10.10.0.50"),
                    "protocol": "TCP",
                })
            except Exception:
                pass

        is_vip = False
        vip_config = None
        target_host = None
        target_port = 80

        try:
            # Check VIP table using SO_ORIGINAL_DST
            sock_wrapper = client_writer.get_extra_info('socket')
            if sock_wrapper is not None:
                orig_addr, orig_port = self._get_original_dst(sock_wrapper)
                if (orig_addr, orig_port) in self.vips_table:
                    vip_config = self.vips_table[(orig_addr, orig_port)]
                    target_host = vip_config.get("internal_ip")
                    target_port = vip_config.get("internal_port")
                    is_vip = True
                    logger.info(
                        "🛡️ HTTP VIP Match: %s → %s:%s (from %s)",
                        vip_config.get('name'), target_host, target_port, client_addr,
                    )

            if is_vip:
                # Phase 10: VIP IP-level inspection via InspectionBridge
                if self._inspection_bridge:
                    try:
                        ctx = self._ctx_builder.build_network_context(
                            client_addr, target_host, target_port, "TCP",
                            direction="inbound",
                        )
                        self._ctx_builder.tag_vip(ctx, vip_name=vip_config.get('name', ''))

                        # SSL-Aware: tag context when this VIP serves HTTPS traffic
                        _ext_port  = vip_config.get('external_port', 80)
                        _https_ports = {443, 8443}
                        try:
                            _rp = self.config.get('proxy', {}).get('reverse_listen_port', 443)
                            _https_ports.add(int(_rp))
                        except Exception:
                            pass
                        if int(_ext_port) in _https_ports:
                            self._ctx_builder.enrich_tls(
                                ctx,
                                sni=vip_config.get('external_ip', ''),
                                version='TLSv1.3',
                                is_decrypted=True,
                            )
                            logger.debug(
                                '[VIP][SSL-Aware] ctx.tls.is_decrypted=True set '
                                'for HTTPS VIP %s (port %s)',
                                vip_config.get('name', ''), _ext_port,
                            )

                        ctx.metadata.update({
                            "external_ip":   vip_config.get('external_ip', ''),
                            "external_port": vip_config.get('external_port', 80),
                        })
                        result = await self._inspection_bridge.check_ip_level(ctx, client_writer)
                        if result.is_blocked:
                            logger.warning(
                                "🛑 VIP blocked by InspectionBridge: %s → %s:%s",
                                client_addr[0], target_host, target_port,
                            )
                            if not client_writer.is_closing():
                                client_writer.close()
                                await client_writer.wait_closed()
                            return
                    except Exception as pipe_exc:
                        logger.debug("VIP inspection bridge error: %s", pipe_exc)

                # Delegate to HTTPS VIP handler if external port is HTTPS
                _ext_port_int = int(vip_config.get('external_port', 80))
                _https_vip_ports: set = {443, 8443}
                try:
                    _rvp = self.config.get('proxy', {}).get('reverse_listen_port', 443)
                    _https_vip_ports.add(int(_rvp))
                except Exception:
                    pass

                if _ext_port_int in _https_vip_ports and self.vip_ssl_context is not None:
                    await self._handle_vip_https(
                        client_reader, client_writer,
                        target_host, target_port,
                        client_addr, vip_config,
                    )
                    return

                # Non-HTTPS VIP: plain relay
                await self._perform_mitm(
                    client_reader, client_writer,
                    target_host, target_port,
                    client_addr,
                    is_vip=True,
                    vip_config=vip_config,
                )
                return

            # Regular HTTP request (non-VIP)
            request_line = await client_reader.readline()
            if not request_line:
                return

            parts = request_line.decode('latin-1').strip().split()
            if len(parts) < 2:
                return

            method = parts[0]
            url    = parts[1]

            if method == 'CONNECT':
                target = url.split(':')
                target_host = target[0]
                target_port = int(target[1]) if len(target) > 1 else 443
                logger.info("🔐 CONNECT %s:%s from %s", target_host, target_port, client_addr[0])
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_writer.drain()
                await self._perform_mitm(
                    client_reader, client_writer,
                    target_host, target_port, client_addr,
                )
            else:
                logger.info("📄 HTTP %s %s from %s", method, url, client_addr[0])
                await self._relay_http(client_reader, client_writer, request_line)

        except (ConnectionResetError, asyncio.IncompleteReadError, BrokenPipeError) as e:
            logger.debug("HTTP connection closed/reset by peer (%s): %s", client_addr[0], e)
        except OSError as e:
            if getattr(e, 'errno', None) in (104, 32, 111, 10054):
                logger.debug("HTTP socket reset by peer (%s): %s", client_addr[0], e)
            else:
                logger.error("Error handling HTTP connection from %s: %s", client_addr[0], e, exc_info=True)
        except Exception as e:
            logger.error("Error handling HTTP connection from %s: %s", client_addr[0], e, exc_info=True)
        finally:
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()

    # ── HTTPS VIP MemoryBIO TLS termination ──────────────────────────────────

    async def _handle_vip_https(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
        client_addr: tuple,
        vip_config: dict,
    ):
        """
        Terminate TLS for an HTTPS VIP connection using ssl.MemoryBIO.

        nftables redirects :443 → :8080 (HTTP handler). The client sends a TLS
        ClientHello which asyncio pre-reads into client_reader._buffer before we
        reach this point.  We use MemoryBIO (not start_tls) to avoid asyncio-
        internal timing issues with the pre-buffered bytes.

        After handshake, wraps streams in _VIPSSLReader/_VIPSSLWriter so that
        _perform_mitm sees plain-text HTTP and can run the full WAF/IDS/DLP
        inspection pipeline on the decrypted content.
        """
        import ssl as _ssl_mod
        try:
            _loop   = asyncio.get_running_loop()
            _in_bio  = _ssl_mod.MemoryBIO()
            _out_bio = _ssl_mod.MemoryBIO()
            _ssl_obj = self.vip_ssl_context.wrap_bio(
                _in_bio, _out_bio, server_side=True,
            )

            # Pre-feed ClientHello already buffered by asyncio transport
            _pre_buf = bytes(getattr(client_reader, '_buffer', b'') or b'')
            if _pre_buf:
                if hasattr(client_reader, '_buffer'):
                    client_reader._buffer.clear()
                _in_bio.write(_pre_buf)
                logger.info(
                    '[VIP][TLS] Pre-fed %d bytes → SSL engine (ClientHello)',
                    len(_pre_buf),
                )
            else:
                logger.info('[VIP][TLS] No pre-buffered data — waiting for ClientHello')

            # Handshake loop (≤15 s)
            _hs_deadline = _loop.time() + 15
            while True:
                if _loop.time() > _hs_deadline:
                    raise asyncio.TimeoutError('VIP TLS handshake timeout (15 s)')
                try:
                    _ssl_obj.do_handshake()
                    break  # ✅ handshake complete
                except _ssl_mod.SSLWantReadError:
                    pass
                except _ssl_mod.SSLWantWriteError:
                    pass

                # Flush outgoing SSL data to client
                _out = _out_bio.read()
                if _out:
                    client_writer.write(_out)
                    await client_writer.drain()

                # Read next encrypted chunk from client
                try:
                    _new = await asyncio.wait_for(
                        client_reader.read(16384), timeout=10,
                    )
                except asyncio.TimeoutError:
                    raise asyncio.TimeoutError('VIP TLS: client silent during handshake')
                if not _new:
                    return  # client closed before handshake
                _in_bio.write(_new)

            # Final flush (TLS Finished / session tickets)
            _out = _out_bio.read()
            if _out:
                client_writer.write(_out)
                await client_writer.drain()

            logger.info(
                '[VIP][TLS] ✅ Handshake OK: %s → %s:%s',
                client_addr[0], target_host, target_port,
            )

            # Wrap decrypted stream → full inspection via _perform_mitm
            # Wrapper objects make _perform_mitm see plain-text HTTP so
            # WAF / IDS / DLP all run on the actual request content.
            _ssl_reader = _VIPSSLReader(client_reader, _ssl_obj, _in_bio)
            _ssl_writer = _VIPSSLWriter(client_writer, _ssl_obj, _out_bio)
            await self._perform_mitm(
                _ssl_reader, _ssl_writer,
                target_host, target_port,
                client_addr,
                is_vip=True,
                vip_config=vip_config,
            )

        except (_ssl_mod.SSLError, ConnectionResetError) as _tls_err:
            logger.warning('[VIP][TLS] SSL error from %s: %s', client_addr[0], _tls_err)
        except asyncio.TimeoutError as _tls_err:
            logger.warning('[VIP][TLS] Timeout from %s: %s', client_addr[0], _tls_err)
        except Exception as _tls_err:
            logger.warning(
                '[VIP][TLS] Unexpected error from %s: %s',
                client_addr[0], _tls_err, exc_info=True,
            )

    # ── Target extraction helpers ─────────────────────────────────────────────

    async def _extract_target(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> Tuple[Optional[str], int]:
        """
        Extract target hostname and port from connection.

        Returns:
            (hostname, port) or (None, 0) if extraction fails
        """
        try:
            transport = client_writer.transport
            sock_wrapper = transport.get_extra_info('socket')
            if sock_wrapper is not None:
                try:
                    fd = sock_wrapper.fileno()
                    dup_sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        dup_sock.settimeout(2.0)
                        loop = asyncio.get_event_loop()
                        peek_data = await loop.run_in_executor(
                            None,
                            lambda: dup_sock.recv(1024, socket.MSG_PEEK),
                        )
                        if peek_data and len(peek_data) > 0 and peek_data[0] == 0x16:
                            hostname = self._parse_sni_from_client_hello(peek_data)
                            if hostname:
                                return hostname, 443
                            return None, 0
                    finally:
                        dup_sock.close()
                except Exception as e:
                    logger.debug("Socket peek in _extract_target failed: %s", e)

            data = await asyncio.wait_for(client_reader.read(1024), timeout=5.0)
            if not data:
                return None, 0

            if data[0] == 0x16 and len(data) > 5:
                hostname = self._parse_sni_from_client_hello(data)
                if hostname:
                    return hostname, 443

            if data.startswith(b'CONNECT'):
                line = data.split(b'\r\n')[0].decode('latin-1')
                parts = line.split()
                if len(parts) >= 2:
                    target = parts[1].split(':')
                    hostname = target[0]
                    port = int(target[1]) if len(target) > 1 else 443
                    return hostname, port

            return None, 0

        except asyncio.TimeoutError:
            logger.warning("Timeout reading target information")
            return None, 0
        except Exception as e:
            logger.error("Error extracting target: %s", e)
            return None, 0

    def _parse_sni_from_client_hello(self, data: bytes) -> Optional[str]:
        """
        Parse Server Name Indication (SNI) from TLS ClientHello.

        Args:
            data: Raw TLS ClientHello data

        Returns:
            Hostname or None if not found
        """
        try:
            if len(data) < 5:
                return None

            pos = 5      # skip TLS record header: type(1) + version(2) + length(2)
            if len(data) < pos + 4:
                return None
            pos += 4     # skip handshake header: type(1) + length(3)
            pos += 2     # client version
            pos += 32    # random

            if len(data) < pos + 1:
                return None
            session_id_length = data[pos]
            pos += 1 + session_id_length

            if len(data) < pos + 2:
                return None
            cipher_suites_length = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += 2 + cipher_suites_length

            if len(data) < pos + 1:
                return None
            compression_length = data[pos]
            pos += 1 + compression_length

            if len(data) < pos + 2:
                return None
            extensions_length = struct.unpack('>H', data[pos:pos + 2])[0]
            pos += 2

            extensions_end = pos + extensions_length
            while pos < extensions_end and pos < len(data):
                if len(data) < pos + 4:
                    break
                ext_type   = struct.unpack('>H', data[pos:pos + 2])[0]
                ext_length = struct.unpack('>H', data[pos + 2:pos + 4])[0]
                pos += 4

                if ext_type == 0:  # SNI extension
                    if len(data) < pos + ext_length:
                        break
                    sni_data = data[pos:pos + ext_length]
                    if len(sni_data) >= 5:
                        sni_pos = 2  # skip list length
                        if sni_data[sni_pos] == 0:  # hostname type
                            sni_pos += 1
                            name_length = struct.unpack('>H', sni_data[sni_pos:sni_pos + 2])[0]
                            sni_pos += 2
                            return sni_data[sni_pos:sni_pos + name_length].decode('ascii')

                pos += ext_length

            return None

        except Exception as e:
            logger.debug("Error parsing SNI: %s", e)
            return None
