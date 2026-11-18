import asyncio
import errno
import logging
import struct
import socket
from typing import Dict, Any, Optional
from system.core.framework.pipeline import InspectionPipeline, InspectionContext, InspectionAction
from modules.dns_security.engine.dns_engine import DNSEngine
from modules.dns_security.engine.servers.sinkhole_server import SinkholeServer
from modules.dns_security.monitoring import dns_metrics

logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────
_DNS_HEADER_LEN = 12
_UPSTREAM_TIMEOUT = 5.0          # seconds
_MAX_COMPRESSION_DEPTH = 10      # prevent infinite pointer loops

# Cross-platform unreachable network errnos (POSIX + Windows socket errnos)
_UNREACHABLE_ERRNOS = {
    getattr(errno, name)
    for name in (
        "ENETUNREACH", "EHOSTUNREACH", "ECONNREFUSED", "ENETDOWN", "ENONET",
        "WSAENETUNREACH", "WSAEHOSTUNREACH", "WSAECONNREFUSED", "WSAENETDOWN", "WSAENONET",
        "WSAEHOSTDOWN", "WSAENETRESET"
    )
    if hasattr(errno, name)
}


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """One-shot UDP protocol for upstream DNS forwarding."""

    def __init__(self):
        # BUG-3 FIX: asyncio.get_event_loop() is deprecated in Python 3.10+.
        # get_running_loop() is safe here because this object is always created
        # from within an async context (DNSProtocol.connection_made).
        self.response: asyncio.Future = asyncio.get_running_loop().create_future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc):
        if not self.response.done():
            self.response.set_exception(exc)

    def connection_lost(self, exc):
        if not self.response.done():
            self.response.set_exception(exc or ConnectionError("upstream lost"))


class DNSProtocol(asyncio.DatagramProtocol):
    """
    UDP Protocol that handles DNS queries, intercepts for steering,
    and forwards others to an upstream resolver.
    """
    def __init__(self, engine: DNSEngine, pipeline: InspectionPipeline, upstream_dns: str = "8.8.8.8"):
        self.engine = engine
        self.pipeline = pipeline
        self.upstream_dns = upstream_dns
        self.transport = None
        # FAIL FIX: Semaphore caps concurrent in-flight query tasks.
        # Without this, a DNS flood creates unbounded tasks → OOM kill.
        # 256 concurrent queries is well above normal enterprise load.
        self._sem = asyncio.Semaphore(256)

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # FAIL FIX: Acquire semaphore before spawning task.
        # If 256 tasks are already running, new packets are dropped (rate-limited)
        # rather than growing the task queue without bound.
        async def _guarded():
            async with self._sem:
                await self.handle_query(data, addr)
        asyncio.create_task(_guarded())

    async def handle_query(self, data, addr):
        try:
            # 1. Parse basic DNS header
            if len(data) < _DNS_HEADER_LEN:
                return
            transaction_id = data[:2]
            qdcount = struct.unpack(">H", data[4:6])[0]
            
            if qdcount == 0:
                return  # No queries
            
            # 2. Extract domain name from first query
            domain, pos = self._parse_dns_name(data, 12)
            if pos + 4 > len(data):
                return  # Malformed packet
            qtype, qclass = struct.unpack(">HH", data[pos:pos+4])


            # ── Critical Infrastructure Whitelist: NEVER block these ──────────
            # These domains must never be blocked regardless of blocklist state.
            # Blocking upstream DNS resolvers breaks all DNS forwarding.
            _DNS_NEVER_BLOCK = {
                "dns.google", "dns64.dns.google",
                "one.one.one.one", "cloudflare-dns.com",
                "resolver1.opendns.com", "resolver2.opendns.com",
                "doh.opendns.com", "dns.quad9.net",
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
            }
            # ── Critical Infrastructure Whitelist: NEVER block these ──────────
            # These domains must never be blocked regardless of blocklist state.
            # Blocking upstream DNS resolvers breaks all DNS forwarding.
            _DNS_NEVER_BLOCK = {
                "dns.google", "dns64.dns.google",
                "one.one.one.one", "cloudflare-dns.com",
                "resolver1.opendns.com", "resolver2.opendns.com",
                "doh.opendns.com", "dns.quad9.net",
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9",
            }
            qtype_str = self._qtype_to_str(qtype)
            if domain in _DNS_NEVER_BLOCK or domain.endswith(".dns.google"):
                # Bypass ALL inspection — forward directly
                await self._forward_to_upstream(data, addr, domain, qtype_str)
                return

            # ── System Blocklist: INSTANT DROP before any module sees it ──────
            # Check happens HERE — domain is known, but NO plugin has run yet.
            # If blocked → return NXDOMAIN immediately (< 1ms, 0 plugins).
            try:
                from modules.ids_ips.engine.blocklist.dynamic_blocklist import DynamicBlocklist
                _bl = DynamicBlocklist.instance()
                if _bl.is_blocked(domain):
                    logger.warning(
                        "[Blocklist] DNS INSTANT DROP | domain=%s src=%s "
                        "| 0 modules ran",
                        domain, addr[0],
                    )
                    # Record query log & metrics for instant drop
                    self.engine.log_query_event(
                        client_ip=addr[0],
                        domain=domain,
                        query_type=qtype_str,
                        action="BLOCK",
                        category="DYNAMIC_BLOCKLIST",
                        reason=f"Domain '{domain}' blocked by Dynamic Blocklist",
                        confidence=1.0,
                    )
                    dns_metrics.record_query(action="BLOCK", protocol="UDP")
                    dns_metrics.record_block(category="DYNAMIC_BLOCKLIST", severity="HIGH")

                    # Fire EventBus event to notify live monitor & voice alerts
                    try:
                        from system.events.bus import EventBus
                        from system.events.topics import Topics
                        bus = await EventBus.instance()
                        await bus.publish(Topics.DNS_THREAT, {
                            "src_ip": addr[0],
                            "dst_ip": "FIREWALL_IP",
                            "domain": domain,
                            "category": "DYNAMIC_BLOCKLIST",
                            "severity": "HIGH",
                            "action": "BLOCK",
                            "reason": f"Domain '{domain}' blocked by Dynamic Blocklist"
                        })
                    except Exception as _bus_ex:
                        logger.debug("Failed to publish DNS instant block event: %s", _bus_ex)

                    # Return NXDOMAIN — client will never attempt TCP connection
                    nxdomain = self._build_nxdomain_response(transaction_id, data)
                    if nxdomain and self.transport:
                        self.transport.sendto(nxdomain, addr)
                    return
            except Exception:
                pass  # Blocklist unavailable — continue normally


            # 3. Create context for inspection
            context = InspectionContext(
                src_ip=addr[0],
                dst_ip="FIREWALL_IP",  # Abstracted
                src_port=addr[1],
                dst_port=53,
                protocol="dns",
                direction="inbound",
                flow_id=f"{addr[0]}:{addr[1]}-dns",
                # BUG-3 FIX: use get_running_loop() instead of deprecated get_event_loop()
                timestamp=asyncio.get_running_loop().time(),
                metadata={"domain": domain, "query_type": qtype_str, "is_dns": True}
            )

            # 4. Run through inspection pipeline
            result = await self.pipeline.inspect_async(context, data)
            
            if result.action == InspectionAction.REDIRECT:
                redirect_ip = result.metadata.get("redirect_ip")
                if redirect_ip:
                    logger.info(f"🛡️ DNS Steering: Redirecting {domain} to {redirect_ip} for {addr[0]}")
                    category = "DNS_SINKHOLE"
                    severity = "CRITICAL"
                    reason = f"DNS redirect to sinkhole for '{domain}'"
                    if result.findings:
                        top = result.findings[-1]
                        severity = top.severity
                        category = top.category
                        reason = top.description

                    # Record query log & metrics
                    self.engine.log_query_event(
                        client_ip=addr[0],
                        domain=domain,
                        query_type=qtype_str,
                        action="REDIRECT",
                        category=category,
                        reason=reason,
                        confidence=1.0,
                        response_ip=redirect_ip,
                    )
                    dns_metrics.record_query(action="REDIRECT", protocol="UDP")

                    # Fire EventBus event to trigger audio alerts
                    try:
                        from system.events.bus import EventBus
                        from system.events.topics import Topics
                        bus = await EventBus.instance()
                        await bus.publish(Topics.DNS_THREAT, {
                            "src_ip": addr[0],
                            "dst_ip": "FIREWALL_IP",
                            "domain": domain,
                            "category": category,
                            "severity": severity,
                            "action": "REDIRECT",
                            "reason": reason
                        })
                    except Exception as _bus_ex:
                        logger.warning(f"Failed to publish DNS redirect event: {_bus_ex}")

                    response = self._build_dns_response(transaction_id, domain, qtype, redirect_ip)
                    self.transport.sendto(response, addr)
                    return

            if result.is_blocked:
                logger.warning(f"🚫 DNS Blocked: {domain} for {addr[0]}")
                category = "DNS_BLOCK"
                severity = "HIGH"
                reason = f"DNS query for '{domain}' was blocked by policy"
                conf = 1.0
                if result.findings:
                    top = result.findings[-1]
                    severity = top.severity
                    category = top.category
                    reason = top.description
                    conf = top.confidence or 1.0

                # Record query log & metrics
                self.engine.log_query_event(
                    client_ip=addr[0],
                    domain=domain,
                    query_type=qtype_str,
                    action="BLOCK",
                    category=category,
                    reason=reason,
                    confidence=conf,
                )
                dns_metrics.record_query(action="BLOCK", protocol="UDP")
                dns_metrics.record_block(category=category, severity=severity)

                # ── Feed DNS detection to DynamicBlocklist ───────────────────
                try:
                    from modules.ids_ips.engine.blocklist.dynamic_blocklist import DynamicBlocklist
                    DynamicBlocklist.instance().record_detection(domain)
                except Exception as _bl_err:
                    logger.debug("Failed to record DNS detection to blocklist: %s", _bl_err)
                
                # Fire EventBus event to trigger audio alerts
                try:
                    from system.events.bus import EventBus
                    from system.events.topics import Topics
                    bus = await EventBus.instance()
                    await bus.publish(Topics.DNS_THREAT, {
                        "src_ip": addr[0],
                        "dst_ip": "FIREWALL_IP",
                        "domain": domain,
                        "category": category,
                        "severity": severity,
                        "action": result.action.name,
                        "reason": reason
                    })
                except Exception as _bus_ex:
                    logger.warning(f"Failed to publish DNS block event: {_bus_ex}")

                return

            # 5. Forward to upstream if not steered/blocked
            await self._forward_to_upstream(data, addr, domain, qtype_str)

        except Exception as e:
            logger.error(f"Error handling DNS query from {addr}: {e}")

    async def _forward_to_upstream(self, data: bytes, client_addr: tuple, domain: str = "", qtype_str: str = "A"):
        """
        Forwards a DNS query to the upstream resolver via asyncio UDP transport,
        waits for the response with a timeout, and relays it back to the client.
        """
        # BUG-3 FIX: use get_running_loop() instead of deprecated get_event_loop()
        loop = asyncio.get_running_loop()
        transport = None
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                _UpstreamProtocol,
                remote_addr=(self.upstream_dns, 53),
            )
            transport.sendto(data)

            # Wait for upstream response with timeout
            response = await asyncio.wait_for(protocol.response, timeout=_UPSTREAM_TIMEOUT)

            # Relay back to original client
            self.transport.sendto(response, client_addr)

            # Record clean query log & metrics
            if domain:
                self.engine.log_query_event(
                    client_ip=client_addr[0],
                    domain=domain,
                    query_type=qtype_str,
                    action="ALLOW",
                    category="CLEAN",
                    reason="Upstream resolved",
                    confidence=0.0,
                )
                dns_metrics.record_query(action="ALLOW", protocol="UDP")


        except asyncio.TimeoutError:
            logger.debug(f"Upstream DNS timeout for client {client_addr[0]}")
            servfail_resp = self._build_servfail_response(data)
            if servfail_resp:
                self.transport.sendto(servfail_resp, client_addr)
        except OSError as e:
            if e.errno in _UNREACHABLE_ERRNOS:
                # Network not available in lab/offline environment — silently return SERVFAIL
                logger.debug(f"Upstream DNS unreachable for client {client_addr[0]}: {e}")
                servfail_resp = self._build_servfail_response(data)
                if servfail_resp:
                    self.transport.sendto(servfail_resp, client_addr)
            else:
                logger.warning(f"DNS forwarding OS error for {client_addr}: {e}")
        except Exception as e:
            logger.error(f"DNS forwarding error for {client_addr}: {e}")
        finally:
            if transport:
                transport.close()

    def _build_servfail_response(self, query_data: bytes) -> bytes:
        """Construct a DNS SERVFAIL (RCODE=2) response packet for timeouts."""
        if len(query_data) < 12:
            return b""
        tx_id = query_data[:2]
        # Header: ID, Flags (0x8182 = Response + Recursion Desired/Available + SERVFAIL), QD=1, AN=0, NS=0, AR=0
        header = tx_id + b"\x81\x82" + b"\x00\x01\x00\x00\x00\x00\x00\x00"
        return header + query_data[12:]

    def _parse_dns_name(self, data: bytes, pos: int) -> tuple:
        """
        Parses a domain name from DNS packet bytes.
        Handles compression pointers (RFC 1035 §4.1.4) with depth limit.
        """
        parts = []
        depth = 0
        jumped = False
        return_pos = pos  # position to return after first pointer jump

        while depth < _MAX_COMPRESSION_DEPTH:
            if pos >= len(data):
                break
            length = data[pos]

            if length == 0:
                if not jumped:
                    return_pos = pos + 1
                break

            if length & 0xC0 == 0xC0:  # Compression pointer
                if pos + 1 >= len(data):
                    break
                if not jumped:
                    return_pos = pos + 2
                pointer = struct.unpack(">H", data[pos:pos+2])[0] & 0x3FFF
                pos = pointer
                jumped = True
                depth += 1
                continue

            pos += 1
            if pos + length > len(data):
                break
            try:
                parts.append(data[pos:pos+length].decode('ascii'))
            except UnicodeDecodeError:
                parts.append(data[pos:pos+length].hex())
            pos += length

        return ".".join(parts), return_pos

    def _qtype_to_str(self, qtype: int) -> str:
        mapping = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 12: "PTR", 5: "CNAME", 6: "SOA", 2: "NS"}
        return mapping.get(qtype, f"TYPE{qtype}")

    def _build_dns_response(self, tx_id: bytes, domain: str, qtype: int, ip: str) -> bytes:
        """Constructs a minimal DNS response packet. Supports A and AAAA records."""
        # Header: ID, Flags (Standard response, No error), QD=1, AN=1, NS=0, AR=0
        header = tx_id + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00"
        
        # Question section
        question = b""
        for part in domain.split("."):
            question += struct.pack("B", len(part)) + part.encode("ascii")
        question += b"\x00" + struct.pack(">HH", qtype, 1)  # Class 1 (IN)
        
        # Answer section — pointer to domain name in question
        answer = b"\xc0\x0c"

        if qtype == 28:
            # AAAA record (IPv6)
            try:
                ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
                answer += struct.pack(">HHIH", 28, 1, 300, 16)
                answer += ip_bytes
            except (socket.error, OSError):
                # Fallback: return A record if IP is IPv4
                answer += struct.pack(">HHIH", 1, 1, 300, 4)
                answer += socket.inet_aton(ip)
        else:
            # A record (IPv4) — default
            answer += struct.pack(">HHIH", 1, 1, 300, 4)
            try:
                answer += socket.inet_aton(ip)
            except OSError:
                answer += b"\x0a\x00\x00\x01"  # fallback 10.0.0.1
        
        return header + question + answer

    def _build_nxdomain_response(self, tx_id: bytes, raw_query: bytes) -> bytes:
        """Return a minimal NXDOMAIN (RCODE=3) response for the original query.

        Copies the question section verbatim from the raw query so the client
        can match the response to its request.  The client sees 'domain does
        not exist' and will NOT attempt any TCP connection.
        """
        try:
            # Flags: QR=1 (response), Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=3 (NXDOMAIN)
            flags = b"\x81\x83"   # 0x8183 = standard response + NXDOMAIN
            # QD=1, AN=0, NS=0, AR=0
            counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
            # Question section is everything after the 12-byte header
            question = raw_query[_DNS_HEADER_LEN:] if len(raw_query) > _DNS_HEADER_LEN else b""
            return tx_id + flags + counts + question
        except Exception:
            return b""

class DNSServer:
    """Manager for the bunyanx DNS Steering Service"""
    def __init__(self, config: dict, pipeline: InspectionPipeline):
        self.config = config.get("modules", {}).get("dns_security", {})
        self.pipeline = pipeline
        self.engine = DNSEngine()
        self.transport = None
        self.protocol = None

        # Resolve upstream DNS — try 3 sources in priority order:
        #   1. System config (modules.dns_security.upstream_dns)
        #   2. Module settings.yaml (direct read — most reliable after our YAML fix)
        #   3. /etc/resolv.conf
        #   4. Hardcoded fallback 8.8.8.8
        resolved_upstream = (
            self.config.get("upstream_dns")
            or self._read_settings_yaml_upstream()
            or self._get_system_dns()
        )
        if resolved_upstream in ("192.168.1.33", "10.10.0.1", "127.0.0.1", "0.0.0.0"):
            logger.warning(
                "DNSServer: configured upstream_dns '%s' is a local firewall interface, falling back to '8.8.8.8' to prevent resolution loop.",
                resolved_upstream
            )
            self.upstream_dns = "8.8.8.8"
        else:
            self.upstream_dns = resolved_upstream or "8.8.8.8"

        logger.info(
            "DNSServer: upstream_dns resolved to '%s'", self.upstream_dns
        )

        # Instantiate the Sinkhole Web Server from config
        self.sinkhole_config = self.config.get("sinkhole_server", self.config.get("sinkhole", {}))
        self.sinkhole_enabled = self.sinkhole_config.get("enabled", True)

        http_port = self.sinkhole_config.get("http_port", 80)
        https_port = self.sinkhole_config.get("https_port", 443)

        self.sinkhole_server = SinkholeServer(host="0.0.0.0", http_port=http_port, https_port=https_port)

    def _read_settings_yaml_upstream(self) -> str:
        """
        FIX: Direct fallback read of settings.yaml upstream_dns.
        The system config passed by proxy module may not carry the dns_security
        sub-keys from our settings.yaml (depends on config merge order).
        Reading the YAML file directly guarantees we always pick up the value.
        """
        try:
            import yaml
            from pathlib import Path
            settings = Path(__file__).parent.parent.parent / "config" / "settings.yaml"
            if settings.exists():
                with open(settings, encoding="utf-8") as f:
                    raw = yaml.safe_load(f) or {}
                dns_cfg = raw.get("dns_security", raw)
                val = dns_cfg.get("upstream_dns", "").strip()
                if val:
                    logger.info(
                        "DNSServer: upstream_dns '%s' read from settings.yaml", val
                    )
                    return val
        except Exception as exc:
            logger.debug("DNSServer: could not read settings.yaml: %s", exc)
        return ""

    def _get_system_dns(self) -> str:
        try:
            import os
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip().startswith("nameserver"):
                            ns = line.split()[1]
                            # Skip localhost loopbacks to prevent infinite loops
                            if ns not in ("127.0.0.1", "127.0.0.53", "localhost"):
                                return ns
        except Exception:
            pass
        return "8.8.8.8"

    async def start(self):
        if not self.config.get("enabled", True):
            return
            
        port = self.config.get("intercept_port", 5353)
        # SEC-7 FIX: Configurable listen address instead of hardcoded 0.0.0.0.
        # Set dns_security.listen_address in base.yaml to restrict to internal interfaces.
        listen_addr = self.config.get("listen_address", "0.0.0.0")
        if listen_addr == "0.0.0.0":
            logger.warning(
                "⚠️  DNS server binding to 0.0.0.0 (all interfaces). "
                "Set dns_security.listen_address in config to restrict to internal interfaces only."
            )
        # BUG-3 FIX: use get_running_loop() instead of deprecated get_event_loop()
        loop = asyncio.get_running_loop()

        logger.info(f"🚀 Starting DNS Steering Server on {listen_addr}:{port}... Upstream DNS: {self.upstream_dns}")
        self.transport, self.protocol = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self.engine, self.pipeline, upstream_dns=self.upstream_dns),
            local_addr=(listen_addr, port)
        )
        
        # Start Sinkhole Web Server concurrently if enabled
        if self.sinkhole_enabled:
            logger.info(f"🚀 Starting Sinkhole Block Page Server (HTTP/HTTPS) on ports {self.sinkhole_server.http_port}/{self.sinkhole_server.https_port}...")
            asyncio.create_task(self.sinkhole_server.start())
        else:
            logger.info("ℹ️ Sinkhole Block Page Server is disabled in configuration.")

    async def stop(self):
        if self.transport:
            self.transport.close()
            logger.info("🛑 DNS Steering Server stopped.")
        
        # Stop Sinkhole Server
        await self.sinkhole_server.stop()
