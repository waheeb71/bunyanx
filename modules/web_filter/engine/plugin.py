"""
Enterprise bunyanx NGFW — Web Filter Plugin
==============================================

Integrates WebFilterEngine (HoloFilter v2 + CategoryEngine + SafeSearch)
into the InspectionPipeline so every HTTP/HTTPS request is evaluated.

Integration path
----------------
  engine.py → InspectionPipeline.register_plugin(WebFilterPlugin())
  ↓
  BaseProxy.relay_data() → inspection_pipeline.inspect_async()
  ↓
  WebFilterPlugin.inspect() → WebFilterEngine.evaluate(url, domain)
  ↓
  InspectionResult(BLOCK / ALLOW / LOG_ONLY)

Fail behaviour
--------------
  Any exception inside evaluate() → ALLOW (Fail-Open by design, see
  WEB_FILTER_DOCUMENTATION.md §10.3).
"""

import logging
import asyncio
from typing import Optional

from system.events.bus import EventBus
from system.events.topics import Topics

from system.core.framework.plugin_base import (
    InspectorPlugin, InspectionContext, InspectionFinding,
    InspectionResult, InspectionAction, PluginPriority,
)
from system.policy.schema import Action

logger = logging.getLogger(__name__)

class WebFilterPlugin(InspectorPlugin):
    """
    Web Filter Inspection Plugin (HoloFilter v2 + CategoryEngine + SafeSearch).

    Priority: HIGH (25) — runs after ThreatIntel, before DPI/DLP.
    Fail-Open: any exception inside evaluate() returns ALLOW so that a DB
    outage never takes down legitimate web traffic.
    """

    # Ports considered web traffic (HTTP / HTTPS variants)
    _WEB_PORTS = frozenset({80, 443, 8080, 8443, 3128})

    def __init__(self, block_on_match: bool = True):
        super().__init__(name="web_filter", priority=PluginPriority.HIGH)
        self.block_on_match = block_on_match
        self._engine: Optional[object] = None   # lazy — avoids DB hit at import
        self._init_failed: bool = False

    # ------------------------------------------------------------------
    # Lazy engine accessor
    # ------------------------------------------------------------------
    def _get_engine(self):
        if self._engine is not None:
            return self._engine
        if self._init_failed:
            return None
        try:
            from modules.web_filter.policy.engine import WebFilterEngine
            self._engine = WebFilterEngine()
            self.logger.info("[WebFilterPlugin] WebFilterEngine initialised ✅")
        except Exception as exc:
            self._init_failed = True
            self.logger.error(
                "[WebFilterPlugin] WebFilterEngine init failed: %s "
                "— running in pass-through (fail-open) mode.", exc
            )
        return self._engine

    # ------------------------------------------------------------------
    # InspectorPlugin interface
    # ------------------------------------------------------------------
    def can_inspect(self, context: InspectionContext) -> bool:
        """
        Inspect outbound HTTP/HTTPS flows by:
          1) protocol string (set by SSL inspector: 'HTTP', 'HTTPS')
          2) destination port (80/443/8080/8443/3128)
          3) presence of typed http/tls fields or legacy metadata keys
        """
        proto = (context.protocol or "").upper()
        if proto in ("HTTP", "HTTPS"):
            return True
        if context.dst_port in self._WEB_PORTS:
            return True
        # Typed fields (Phase 10)
        if context.http and (context.http.host or context.http.url):
            return True
        if context.tls and context.tls.sni:
            return True
        # Legacy metadata fallback
        if context.metadata and (
            "host" in context.metadata
            or "url" in context.metadata
            or "sni" in context.metadata
        ):
            return True
        return False

    def inspect(self, context: InspectionContext, data: bytes = b"") -> InspectionResult:
        findings = []
        pipeline_action = InspectionAction.ALLOW
        metadata_additions = {}

        engine = self._get_engine()
        if engine is None:
            return InspectionResult(action=pipeline_action, findings=findings,
                                    metadata=metadata_additions)

        # ── 1. Extract hostname and URL path ───────────────────────────────
        host_str = ""
        if context.http and context.http.host:
            host_str = context.http.host
        elif context.tls and context.tls.sni:
            host_str = context.tls.sni
        else:
            host_str = (
                (context.metadata or {}).get("host")
                or (context.metadata or {}).get("sni")
                or ""
            )

        url_str = ""
        if context.http and context.http.url:
            url_str = context.http.url
        else:
            url_str = (context.metadata or {}).get("url") or ""

        # Fallback from raw bytes if missing
        if data and (not host_str or not url_str):
            try:
                head = data[:512].decode("utf-8", errors="ignore")
                lines = head.split("\r\n") if "\r\n" in head else head.split("\n")
                if not url_str and lines and any(lines[0].startswith(m) for m in ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ")):
                    parts = lines[0].split(" ")
                    if len(parts) >= 2:
                        url_str = parts[1]
                if not host_str:
                    for line in lines:
                        if line.lower().startswith("host:"):
                            host_str = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass

        if not host_str:
            host_str = context.dst_ip or ""

        if not host_str and not url_str:
            return InspectionResult(action=pipeline_action, findings=findings,
                                    metadata=metadata_additions)

        # ── 2. Normalise domain and target_url ──────────────────────────────
        if url_str.startswith("http://") or url_str.startswith("https://"):
            target_url = url_str
            from urllib.parse import urlparse
            try:
                parsed = urlparse(target_url)
                domain = parsed.netloc.lower().split(":")[0]
            except Exception:
                domain = host_str.lower().split(":")[0]
        else:
            domain = host_str.lower().split(":")[0]
            scheme = "https" if context.dst_port in (443, 8443) else "http"
            path = url_str if url_str.startswith("/") else (f"/{url_str}" if url_str else "/")
            target_url = f"{scheme}://{host_str}{path}"

        if domain.startswith("www."):
            domain = domain[4:]

        # ── 2b. Bypass RFC-1918 / Private LAN IP addresses & Localhost ─────
        # Web Filter is designed for public internet sites (malware, adult, gambling, etc.).
        # Internal LAN IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x, 127.x.x.x, localhost)
        # must NEVER be evaluated by WebFilter or categorized as blocked.
        import ipaddress as _ipmod
        try:
            _target_ip = _ipmod.ip_address(domain)
            if _target_ip.is_private or _target_ip.is_loopback or _target_ip.is_link_local:
                return InspectionResult(action=InspectionAction.ALLOW, findings=[], metadata={})
        except ValueError:
            if domain in ("localhost", "127.0.0.1", "0.0.0.0"):
                return InspectionResult(action=InspectionAction.ALLOW, findings=[], metadata={})

        # ── 3. Evaluate (Fail-Open) ──────────────────────────────────────────
        try:
            result_action, modified_url = engine.evaluate(url=target_url, domain=domain)
        except Exception as exc:
            self.logger.warning(
                "[WebFilterPlugin] evaluate() raised %s for '%s' — allowing (fail-open).",
                exc, domain,
            )
            return InspectionResult(action=InspectionAction.ALLOW, findings=[],
                                    metadata={})

        if result_action in (Action.BLOCK, Action.REJECT):
            findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="HIGH",
                category="WEB_FILTER",
                description=f"Domain '{domain}' blocked by Web Filter policy (HoloFilter / Category).",
                confidence=0.95,
                recommends_block=True,
                metadata={"target": target_url, "domain": domain, "action": result_action.name},
            ))
            if self.block_on_match:
                pipeline_action = InspectionAction.BLOCK
            self.logger.info("[WebFilterPlugin] 🔴 BLOCK domain='%s' src=%s",
                             domain, context.src_ip)
            
            # Fire global event for Audio/SSE and cross-process dispatchers
            import uuid
            from datetime import datetime, timezone
            payload = {
                "event_id": f"evt-{uuid.uuid4()}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module": "web_filter",
                "event_type": Topics.WEB_FILTER_BLOCK,
                "severity": "HIGH",
                "confidence": 0.95,
                "domain": domain,
                "src_ip": context.src_ip,
                "dst_ip": context.dst_ip,
                "action": result_action.name,
                "target": target_url,
                "category": "WEB_FILTER"
            }
            try:
                EventBus.publish_from_thread(Topics.WEB_FILTER_BLOCK, payload)

                # ── IMPORTANT: Only auto-block src_ip if it is NOT a private RFC-1918 IP ──
                # Auto-blocking RFC-1918 private IPs (e.g. 10.10.0.50 or user PCs) on a Web Filter
                # match isolates the entire internal server/device at the firewall IP layer.
                _is_src_private = False
                if context.src_ip:
                    try:
                        _is_src_private = _ipmod.ip_address(context.src_ip).is_private
                    except ValueError:
                        pass
                if not _is_src_private:
                    from modules.firewall.engine.ip_blocklist import get_blocklist_manager
                    get_blocklist_manager().block_ip_sync(
                        ip=context.src_ip,
                        reason=f"[web_filter] Domain '{domain}' blocked by Web Filter policy (HoloFilter / Category).",
                        blocked_by="web_filter",
                    )
            except Exception as e:
                self.logger.debug("Failed to dispatch WebFilter event/block: %s", e)


        elif result_action == Action.MONITOR:
            findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="INFO",
                category="WEB_FILTER",
                description=f"Domain '{domain}' in monitor mode (logged, not blocked).",
                confidence=1.0,
                metadata={"target": target_url, "domain": domain},
            ))
            pipeline_action = InspectionAction.LOG_ONLY

        # ── 5. SafeSearch URL rewrite notification ───────────────────────────
        if modified_url:
            metadata_additions["rewrite_url"] = modified_url
            metadata_additions["proxy_action"] = "rewrite"
            findings.append(InspectionFinding(
                plugin_name=self.name,
                severity="INFO",
                category="SAFE_SEARCH",
                description="SafeSearch parameter appended to URL.",
                confidence=1.0,
                metadata={"original": target_url, "rewritten": modified_url},
            ))

        return InspectionResult(
            action=pipeline_action,
            findings=findings,
            metadata=metadata_additions,
        )
