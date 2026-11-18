"""
BunyanX NGFW — Inspection Context Builder
==========================================
Builds unified InspectionContext objects for every connection type.

Responsibilities:
  - Build network-level context from socket info
  - Enrich with HTTP info (via HttpRequestParser)
  - Enrich with TLS info (populated by proxy after TLS handshake)
  - Tag context: "internal", "vip", "trusted", "encrypted", "decrypted"
  - Populate legacy metadata dict (for backward-compatible modules)

TLS / HTTPS Flow:
  transparent_proxy._perform_mitm() handles TLS termination.
  After decryption, it calls:
    ctx = builder.build_network_context(...)
    ctx.tls = TlsInfo(sni=..., version=..., is_decrypted=True)
    ctx = builder.enrich_http(ctx, decrypted_bytes, scheme="https")
  This ensures context.tls carries the original TLS metadata AND
  context.http carries the decrypted plaintext content.

Usage:
    builder = ContextBuilder(config=system_config)
    ctx = builder.build_network_context(client_addr, target_host, target_port, "HTTP")
    ctx.tls = TlsInfo(sni="example.com", version="TLSv1.3", is_decrypted=True)
    ctx = builder.enrich_http(ctx, raw_request_bytes, scheme="https")
"""

import ipaddress
import logging
import time
from typing import Optional, Tuple

from system.core.inspection_context import (
    InspectionContext,
    HttpInfo,
    TlsInfo,
    DnsInfo,
    SmtpInfo,
)
from modules.proxy.engine.http_parser import HttpRequestParser

# Identity resolution — imported lazily to avoid circular imports at module load.
# resolve_identity() is called once per connection (O(1) dict lookup).
def _resolve_identity_safe(src_ip: str):
    """Resolve IP → IdentityContext without raising."""
    try:
        from system.auth.identity_engine import resolve_identity
        return resolve_identity(src_ip)
    except Exception:
        from system.core.inspection_context import IdentityContext
        return IdentityContext()

logger = logging.getLogger(__name__)


class ContextBuilder:
    """
    Builds and enriches InspectionContext objects.

    Instantiate once per proxy instance and reuse (thread/coroutine safe).
    """

    def __init__(self, config: dict):
        """
        Args:
            config: Full system config dict (from base.yaml / settings.yaml)
        """
        self._config = config
        self._http_parser = HttpRequestParser()

        from system.core.config_loader import ConfigLoader
        network_cfg = config.get("network", {})
        raw_nets = network_cfg.get("internal_networks") or ConfigLoader.get_internal_networks_raw()
        raw_trusted = network_cfg.get("trusted_ips") or ConfigLoader.get_trusted_ips()

        self._internal_networks = self._parse_networks(raw_nets)
        self._trusted_ips = set(raw_trusted)
        logger.debug(
            "[ContextBuilder] Initialized with %d internal networks, %d trusted IPs",
            len(self._internal_networks),
            len(self._trusted_ips),
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def build_network_context(
        self,
        client_addr: Tuple[str, int],
        target_host: str,
        target_port: int,
        protocol: str,
        direction: str = "inbound",
    ) -> InspectionContext:
        """
        Build a network-level InspectionContext (no application data yet).

        This is the FIRST step for any connection. Call enrich_http() or
        enrich_tls() afterwards when more info becomes available.

        Args:
            client_addr: (client_ip, client_port) tuple
            target_host: Destination IP or hostname
            target_port: Destination port
            protocol:    "TCP", "UDP", "HTTP", "HTTPS", "DNS", "SMTP"
            direction:   "inbound" | "outbound"

        Returns:
            InspectionContext with network fields populated and tags set.
        """
        client_ip, client_port = client_addr[0], client_addr[1]
        flow_id = f"{client_ip}:{client_port}->{target_host}:{target_port}"

        ctx = InspectionContext(
            src_ip=client_ip,
            dst_ip=target_host,
            src_port=client_port,
            dst_port=target_port,
            protocol=protocol,
            direction=direction,
            flow_id=flow_id,
            timestamp=time.time(),
        )

        # Tag: internal, trusted
        self._apply_network_tags(ctx)

        # ── Identity injection ─────────────────────────────────────────────
        # Resolve IP → user identity from IdentityCorrelationEngine.
        # O(1) cache lookup — negligible latency per packet.
        # anonymous IdentityContext is returned when IP is unknown.
        ctx.identity = _resolve_identity_safe(client_ip)

        # Populate legacy metadata immediately for backward compat
        ctx.metadata = ctx.to_legacy_metadata()

        return ctx

    def enrich_http(
        self,
        ctx: InspectionContext,
        raw_bytes: bytes,
        scheme: str = "http",
    ) -> InspectionContext:
        """
        Parse raw HTTP bytes and attach HttpInfo to the context.

        Works for both HTTP and HTTPS (scheme differentiates them).
        For HTTPS, call this AFTER setting ctx.tls (so scheme="https").

        Args:
            ctx:       Existing context (from build_network_context)
            raw_bytes: Raw plaintext HTTP request bytes
            scheme:    "http" or "https"

        Returns:
            The same context object (mutated in place), with ctx.http set.
        """
        if not raw_bytes:
            return ctx

        http_info = self._http_parser.parse_from_bytes(raw_bytes, scheme=scheme)
        if http_info:
            ctx.http = http_info
            # Update protocol to reflect application layer
            ctx.protocol = "HTTPS" if scheme == "https" else "HTTP"
            # Refresh legacy metadata now that http is available
            ctx.metadata = ctx.to_legacy_metadata()
            logger.debug(
                "[ContextBuilder] HTTP enriched: %s %s (body=%d bytes)",
                http_info.method, http_info.path, len(http_info.body)
            )
        else:
            logger.debug("[ContextBuilder] HTTP parse failed — context has no http info")

        return ctx

    def enrich_http_from_parts(
        self,
        ctx: InspectionContext,
        first_line: bytes,
        headers_raw: bytes,
        scheme: str = "http",
    ) -> InspectionContext:
        """
        Parse HTTP from already-split first_line + headers (no body yet).
        Body remains b"" until available.

        Used in the relay path where proxy reads line-by-line.
        """
        http_info = self._http_parser.parse_from_first_line_and_headers(
            first_line, headers_raw, scheme=scheme
        )
        if http_info:
            ctx.http = http_info
            ctx.protocol = "HTTPS" if scheme == "https" else "HTTP"
            ctx.metadata = ctx.to_legacy_metadata()
        return ctx

    def enrich_tls(
        self,
        ctx: InspectionContext,
        sni: Optional[str] = None,
        version: Optional[str] = None,
        cipher: Optional[str] = None,
        is_decrypted: bool = False,
        bypass_reason: Optional[str] = None,
    ) -> InspectionContext:
        """
        Attach TLS session metadata to context.

        Call this BEFORE enrich_http() for HTTPS connections so that
        the TLS info is available during HTTP parsing (e.g., scheme).

        For MITM-decrypted connections: is_decrypted=True
        For bypassed connections:       is_decrypted=False + bypass_reason

        Args:
            ctx:           Existing context
            sni:           Server Name Indication (hostname from ClientHello)
            version:       TLS version string ("TLSv1.2", "TLSv1.3", ...)
            cipher:        Negotiated cipher suite
            is_decrypted:  True if MITM decryption was performed
            bypass_reason: Reason MITM was not performed (e.g., "banking")

        Returns:
            The same context (mutated), with ctx.tls set.
        """
        ctx.tls = TlsInfo(
            sni=sni,
            version=version,
            cipher=cipher,
            is_decrypted=is_decrypted,
            bypass_reason=bypass_reason,
        )
        # Add tags
        ctx.tags.add("encrypted")
        if is_decrypted:
            ctx.tags.add("decrypted")

        # Update dst_ip with SNI if we only had an IP before
        if sni and not ctx.dst_ip:
            ctx.dst_ip = sni

        # Refresh legacy metadata
        ctx.metadata = ctx.to_legacy_metadata()

        logger.debug(
            "[ContextBuilder] TLS enriched: sni=%s version=%s decrypted=%s",
            sni, version, is_decrypted
        )
        return ctx

    def tag_vip(self, ctx: InspectionContext, vip_name: str = "") -> InspectionContext:
        """Mark context as a VIP-mapped connection."""
        ctx.tags.add("vip")
        if vip_name:
            ctx.metadata["vip_name"] = vip_name
        ctx.metadata["vip"] = True
        return ctx

    # ── Private helpers ───────────────────────────────────────────────────────

    def _apply_network_tags(self, ctx: InspectionContext) -> None:
        """Add 'internal' and 'trusted' tags based on src_ip."""
        from system.core.config_loader import ConfigLoader
        if ConfigLoader.is_internal(ctx.src_ip):
            ctx.tags.add("internal")

        if ConfigLoader.is_trusted(ctx.src_ip):
            ctx.tags.add("trusted")

    def _parse_networks(self, raw_list: list) -> list:
        """Parse list of CIDR strings into ipaddress.ip_network objects."""
        nets = []
        for entry in raw_list:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                logger.warning("[ContextBuilder] Invalid network: %s — %s", entry, exc)
        return nets
