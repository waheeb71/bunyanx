"""
BunyanX NGFW — Inspection Bridge
==================================
Single bridge between the Proxy layer and the InspectionPipeline.

This replaces the 3 scattered inline inspection calls in transparent_proxy:
  ① VIP pre-flight  (L548)  → was: pipeline.inspect_async(ctx, b"")
  ② Relay path      (L1094) → was: pipeline.inspect_async(ctx, data)
  ③ HTTP relay      (L1245) → was: pipeline.inspect_async(ctx, req_data)

After this bridge:
  ALL calls go through: bridge.check(ctx) → InspectionResult

Key guarantees:
  - Context MUST have body in ctx.http.body BEFORE calling bridge.check()
  - Bridge never raises — all exceptions are caught and fail-open applied
  - Block responses are sent by bridge._send_block_response() — not by proxy
  - Event sink publishing happens here, not scattered across proxy methods

TLS note:
  ctx.tls.is_decrypted == True means body is plaintext (MITM happened).
  ctx.tls.is_decrypted == False means body is still encrypted (bypass).
  In bypass mode, bridge skips application-layer plugins (WAF, DLP)
  since they can't inspect ciphertext. IP-level checks still run.
"""

import asyncio
import logging
from typing import Optional

from system.core.framework.pipeline import InspectionPipeline
from system.core.framework.plugin_base import InspectionResult, InspectionAction
from system.core.inspection_context import InspectionContext

logger = logging.getLogger(__name__)


class InspectionBridge:
    """
    Proxy-to-Pipeline bridge.

    Instantiate once per proxy instance.
    All three proxy paths (VIP, relay, HTTP) call bridge.check().
    """

    def __init__(
        self,
        pipeline: InspectionPipeline,
        fail_open: bool = True,
        event_sink=None,
        auto_block_ttl: int = 10 * 60,
    ):
        """
        Args:
            pipeline:       The InspectionPipeline singleton
            fail_open:      If True, allow traffic when pipeline errors occur.
                            If False (strict security), block on errors.
            event_sink:     Optional event bus sink for telemetry
            auto_block_ttl: TTL for auto-blocked IPs in seconds (default 10*60 = 600s)
        """
        self._pipeline = pipeline
        self._fail_open = fail_open
        self._event_sink = event_sink
        self._auto_block_ttl = int(auto_block_ttl) if auto_block_ttl else 10 * 60
        self._last_drop_telemetry_ts: dict[str, float] = {}

    # ── Main inspection entrypoint ────────────────────────────────────────────

    async def check(
        self,
        ctx: InspectionContext,
        writer: Optional[asyncio.StreamWriter] = None,
    ) -> InspectionResult:
        """
        Run the full inspection pipeline on the context.

        The context MUST have ctx.http.body populated BEFORE calling this
        if you want WAF/DLP to inspect the body. For TCP-only flows with no
        HTTP data, ctx.http will be None — application plugins will skip.

        TLS bypass:
          If ctx.tls is set but ctx.tls.is_decrypted is False, body is
          ciphertext — application plugins (WAF, DLP) will return ALLOW
          naturally since ctx.http is None. IP-level plugins still run.

        Args:
            ctx:    Fully built InspectionContext
            writer: Optional — if provided and result is BLOCK, sends 403.

        Returns:
            InspectionResult (never raises)
        """
        if self._pipeline is None:
            return _allow()

        try:
            result = await self._pipeline.run_async(ctx)
        except Exception as exc:
            logger.error("[InspectionBridge] Pipeline exception: %s", exc, exc_info=True)
            if self._fail_open:
                return _allow()
            else:
                return _block_on_error(str(exc))

        if result.is_blocked:
            try:
                from modules.firewall.engine.ip_whitelist_manager import get_whitelist_manager
                _src = ctx.src_ip or ""
                # Check YAML-backed whitelist — never auto-block exempt IPs.
                # Only auto-block if actual NEW threat findings exist and not already a blocklist hit
                is_already_blocked = result.metadata.get("blocklist_hit") or result.metadata.get("src_ip_blocked")
                if _src and not is_already_blocked and not get_whitelist_manager().is_whitelisted(_src):    
                    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
                    reason = (
                        " | ".join(f"[{f.plugin_name}] {f.description}" for f in result.findings)
                        if result.findings
                        else "Security Threat Detected"
                    )
                    _AUTO_BLOCK_TTL = self._auto_block_ttl  # 10 * 60 (10 minutes)
                    get_blocklist_manager().block_ip_sync(
                        ip=_src,
                        reason=reason,
                        blocked_by="inspection_bridge",
                        duration_seconds=_AUTO_BLOCK_TTL,
                    )
            except Exception as exc:
                logger.debug("[InspectionBridge] Blocklist sync warning: %s", exc)

            if writer and not writer.is_closing():
                await self._send_block_response(writer, result, ctx)

        # Publish event asynchronously (rate-limited for blocklist drops to protect SQLite from lock storms)
        if self._event_sink:
            should_publish = True
            if result.is_blocked and (result.metadata.get("blocklist_hit") or result.metadata.get("src_ip_blocked")):
                import time as _t
                _now = _t.monotonic()
                _last = self._last_drop_telemetry_ts.get(ctx.src_ip, 0.0)
                if _now - _last < 5.0:
                    should_publish = False
                else:
                    self._last_drop_telemetry_ts[ctx.src_ip] = _now

            if should_publish:
                asyncio.create_task(self._publish_event(ctx, result))

        return result

    async def check_ip_level(
        self,
        ctx: InspectionContext,
        writer: Optional[asyncio.StreamWriter] = None,
    ) -> InspectionResult:
        """
        Run IP-level inspection only (for VIP pre-flight or early reject).

        Identical to check() but explicitly signals that no HTTP body is
        available. Sets ctx.http = None before running to prevent application
        plugins from firing (they will return ALLOW when ctx.http is None).

        Use this BEFORE reading the HTTP request body (e.g., VIP path).
        """
        # Temporarily ensure http is None so app-layer plugins skip
        saved_http = ctx.http
        ctx.http = None

        try:
            result = await self.check(ctx, writer)
        finally:
            ctx.http = saved_http  # restore in case caller needs it

        return result

    # ── Response helpers ──────────────────────────────────────────────────────

    @staticmethod
    async def send_block_403(
        writer: asyncio.StreamWriter,
        reasons: list = None,
        protocol: str = "HTTP",
    ) -> None:
        """
        Send a block response (HTTP 403 or SMTP 550) for blocked connections.
        Safe to call even if writer is closing.
        """
        if writer.is_closing():
            return
        try:
            reason_text = " | ".join(reasons) if reasons else "Blocked by BunyanX NGFW"
            if protocol and protocol.upper() == "SMTP":
                response = f"550 5.7.1 Security policy violation: {reason_text}\r\n".encode()
            else:
                body = (
                    f"Blocked by BunyanX NGFW\r\n{reason_text}"
                ).encode()
                response = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: close\r\n"
                    b"Server: BunyanX-NGFW\r\n"
                    + b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    + b"\r\n"
                    + body
                )
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as exc:
            logger.debug("[InspectionBridge] Block response send failed: %s", exc)

    # ── Private ───────────────────────────────────────────────────────────────

    async def _send_block_response(
        self,
        writer: asyncio.StreamWriter,
        result: InspectionResult,
        ctx: InspectionContext,
    ) -> None:
        reasons = [
            f"[{f.plugin_name}] {f.description}"
            for f in result.findings
        ]
        await self.send_block_403(writer, reasons, protocol=ctx.protocol)

    async def _publish_event(
        self,
        ctx: InspectionContext,
        result: InspectionResult,
    ) -> None:
        """Fire-and-forget telemetry event publishing."""
        try:
            from system.telemetry.events.event_schema import (
                create_event_from_proxy,
                EventVerdict,
            )
            verdict = EventVerdict.DROP if result.is_blocked else EventVerdict.ALLOW
            reason = (
                " | ".join(f"[{f.plugin_name}] {f.description}" for f in result.findings)
                if result.findings
                else ("blocked" if result.is_blocked else "allowed")
            )
            # Estimate bytes from body if available
            body_len = len(ctx.http.body) if ctx.http else 0
            evt = create_event_from_proxy(
                src_ip=ctx.src_ip,
                dst_ip=ctx.dst_ip,
                src_port=ctx.src_port,
                dst_port=ctx.dst_port,
                protocol=ctx.protocol,
                bytes_count=body_len,
                packets_count=max(1, body_len // 1400),
                verdict=verdict,
                reason=reason,
            )
            await self._event_sink.submit_event(evt)
        except Exception as exc:
            logger.debug("[InspectionBridge] Event publish failed: %s", exc)


# ── Module-level helpers ──────────────────────────────────────────────────────

def _allow() -> InspectionResult:
    return InspectionResult(action=InspectionAction.ALLOW)


def _block_on_error(reason: str) -> InspectionResult:
    from system.core.framework.plugin_base import InspectionFinding
    result = InspectionResult(action=InspectionAction.BLOCK)
    result.findings.append(InspectionFinding(
        plugin_name="inspection_bridge",
        severity="CRITICAL",
        category="pipeline_error",
        description=f"Pipeline error (fail-closed): {reason}",
        confidence=1.0,
    ))
    return result
